"""Runtime packs: archive format, packaging, fetch and the attempt's setup.

A runtime pack is one project's application runtime for the agent's
workspace (`r2t.agents.runtime_pack`): the project's interpreters, build tools,
dependencies and services, run through the pack's own runner in a nested
bubblewrap sandbox.  Its release `runtime-<project>-v<version>` holds

    pack.json       the pack's record: project, manifest_sha256, leak audit
    pack.tar.zst    every directory, regular file and link of the pack except
                    the top-level pack.json, split into `.part-NN` pieces
                    over 1.9 GiB like every other release archive
    SHA256SUMS      every asset and the reassembled archive

**Archive format.**  A PAX tar compressed with `zstd`, members sorted by
path, so every directory comes before what it holds.  Directories are members
of their own, empty ones included; links are links (`l` members keep their
target and are never followed, also when the target dangles on the host, as
the in-sandbox targets of a pack do); permission bits are kept (`mode &
0o777`: the set-id and sticky bits do nothing in an unprivileged sandbox);
owners are 0, names empty, times 0.  Nothing else (a fifo, a device, a hard
link member) is accepted on either side.

**Extractor.**  `extract_archive` writes each member only directly inside a
directory an earlier member of the same archive created, creates files with
`O_CREAT | O_EXCL | O_NOFOLLOW` and links with `symlink`, so no member is ever
written through a link and none replaces another.  Directory modes are set
after their contents are written.

**Identity.**  A pack's identity is its `manifest_sha256`
(`r2t.agents.runtime_pack.manifest_sha256`: files and links, not modes or
directories).  `fetch` installs a pack only when its pack.json records the
manifest `req2test.kits.RUNTIME_PACKS` pins and the extracted tree has that
manifest, and only after `runtime_pack.load_pack` admits it (leak audit
passed, an `rt/` to bind).  `runtime setup` refuses an installed pack whose
pack.json records another manifest.

**Attempt setup.**  `req2test runtime setup` is the attempt setup the
leaderboard's runs used, run by `runtime_pack` itself: `init_attempt` (repairs, remainder,
state and instance file, in that order) and `sandbox_binds`.  It prints the
binds the user's sandbox must make, the entries to link into the agent's home
(a pack's `rt/home/`), the pack identity a row records, and the binds as
`docker run` options for an agent that runs in a container.

**Runtime preflight.**  `req2test runtime preflight` sets up a probe attempt
the same way, for the project's first eval instance unless `--instance` names
another, in a new directory under the directory that will hold the
workspaces.  It runs the project's probe (`runtime_pack.PROBES`) through the
pack's runner in a reference bubblewrap sandbox that makes the printed binds,
and removes the attempt.
"""
from __future__ import annotations

import argparse
import json
import os
import posixpath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

from . import kits
from .kits import KitError, SUMS

PACK_JSON = "pack.json"
PACK_ARCHIVE = "pack.tar.zst"
#: The files every runtime release lists in its SHA256SUMS (the archive under
#: its reassembled name).
PACK_FILES = (PACK_JSON, PACK_ARCHIVE)


def _runtime_pack():
    """The engine's runtime-pack module (`r2t.agents.runtime_pack`)."""
    from .execute import ensure_engine_path
    ensure_engine_path()
    from r2t.agents import runtime_pack
    return runtime_pack


def _refused(fn, *args):
    """`fn(*args)`, with the engine's `SystemExit("REFUSED: ...")` raised
    as the `KitError` `req2test.cli` prints."""
    try:
        return fn(*args)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            raise KitError(exc.code) from None
        raise


# --------------------------------------------------------------------------
# Archive format


def _entries(src: Path) -> list:
    """`(rel, kind, path, st)` of every directory (`d`), regular file (`f`)
    and link (`l`) under `src`, sorted by `rel`; the top-level pack.json is
    left out.  A link to a directory is a link and is not descended into."""
    out = []
    for dirpath, dirnames, filenames in os.walk(src):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, src).replace(os.sep, "/")
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                kind = "l"
            elif stat.S_ISDIR(st.st_mode):
                kind = "d"
            elif stat.S_ISREG(st.st_mode):
                if rel == PACK_JSON:
                    continue
                kind = "f"
            else:
                raise KitError(f"{path} is not a directory, regular file or "
                               f"link; a runtime pack holds only those")
            out.append((rel, kind, path, st))
    return sorted(out)


def write_archive(src, archive, *, level: int = 3) -> int:
    """Pack the pack directory `src` into `archive` (`.tar.zst`); the
    number of members."""
    count = 0
    with kits._Zstd(archive, "w", level=level, long=True) as z:
        with tarfile.open(fileobj=z.stream, mode="w|",
                          format=tarfile.PAX_FORMAT) as tar:
            for rel, kind, path, st in _entries(Path(src)):
                kits._check_member_name(rel)
                info = tarfile.TarInfo(rel)
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = stat.S_IMODE(st.st_mode) & 0o777
                if kind == "d":
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                elif kind == "l":
                    info.type = tarfile.SYMTYPE
                    info.mode = 0o777
                    info.linkname = os.readlink(path)
                    tar.addfile(info)
                else:
                    info.size = st.st_size
                    with open(path, "rb") as fh:
                        reader = kits._HashingReader(fh)
                        tar.addfile(info, reader)
                    if reader.bytes != st.st_size:
                        raise KitError(f"{path}: changed while packing")
                count += 1
    return count


def extract_archive(archive, dest) -> int:
    """Extract a pack archive into the existing empty directory `dest`;
    the number of members.

    Every member must lie directly inside `dest` or inside a directory an
    earlier member created, so no member is written through a link, and no
    member may name a path another one already wrote.
    """
    archive, dest = Path(archive), Path(dest)
    dirs, modes, count = {""}, [], 0
    try:
        with kits._Zstd(archive, "r") as z:
            with tarfile.open(fileobj=z.stream, mode="r|") as tar:
                for member in tar:
                    name = member.name
                    kits._check_member_name(name)
                    if posixpath.dirname(name) not in dirs:
                        raise KitError(
                            f"{archive.name}: {name} is not inside a "
                            f"directory the archive made before it; a pack "
                            f"is never extracted through a link")
                    target = os.path.join(dest, name)
                    mode = member.mode & 0o777
                    if member.isdir():
                        os.mkdir(target, 0o700)
                        dirs.add(name)
                        modes.append((target, mode))
                    elif member.issym():
                        os.symlink(member.linkname, target)
                    elif member.isreg():
                        fd = os.open(target, os.O_WRONLY | os.O_CREAT
                                     | os.O_EXCL | os.O_NOFOLLOW
                                     | os.O_CLOEXEC, 0o600)
                        with os.fdopen(fd, "wb") as out:
                            shutil.copyfileobj(tar.extractfile(member), out,
                                               kits._CHUNK)
                            os.fchmod(out.fileno(), mode)
                    else:
                        raise KitError(
                            f"{archive.name}: {name} is not a directory, "
                            f"regular file or link")
                    count += 1
    except FileExistsError as exc:
        raise KitError(f"{archive.name}: {exc.filename} is written twice") \
            from None
    except (tarfile.TarError, EOFError) as exc:
        raise KitError(f"{archive} is damaged ({exc}); re-fetch the pack") \
            from None
    # Deepest first, so a directory that becomes read-only is already full.
    for target, mode in reversed(modes):
        os.chmod(target, mode)
    return count


def pack_runtime(src, out, *, project: str,
                 part_bytes: int = kits.PART_BYTES, level: int = 3) -> dict:
    """Package the runtime pack directory `src` as the release assets of
    `runtime-<project>-v<version>` in `out` (maintainers).

    Refused unless `src/pack.json` names `project` and records the manifest
    `src` has (`runtime_pack.manifest_sha256`).  Returns `{asset: sha256}`
    of `out/SHA256SUMS`.
    """
    rp = _runtime_pack()
    src, out = Path(src), Path(out)
    doc = json.loads((src / PACK_JSON).read_text(encoding="utf-8"))
    if doc.get("project") != project:
        raise KitError(f"{src / PACK_JSON} names project "
                       f"{doc.get('project')!r}, not {project!r}")
    actual = rp.manifest_sha256(str(src))
    if doc.get("manifest_sha256") != actual:
        raise KitError(f"{src}: manifest {actual}, but {PACK_JSON} records "
                       f"{doc.get('manifest_sha256')}")
    out.mkdir(parents=True, exist_ok=True)
    archive = out / PACK_ARCHIVE
    write_archive(src, archive, level=level)
    sums = {PACK_JSON: kits._copy_hashed(src / PACK_JSON, out / PACK_JSON)}
    return kits._finish_release(out, [archive], part_bytes, sums)


# --------------------------------------------------------------------------
# Fetch and install


def _install(source, project: str, home: Path) -> tuple:
    """Extract, check and move one downloaded pack into place; its
    directory and the number of archive members."""
    rp = _runtime_pack()
    _version, pinned = kits.RUNTIME_PACKS[project]
    root = kits.packs_root(home)
    final = root / project
    # `<stage_root>/<project>` is a packs root of its own, so `load_pack`
    # admits the pack before it is moved into place.
    stage_root = root / f".partial-{os.getpid()}"
    stage = stage_root / project
    joindir = home / "tmp" / f"join-{os.getpid()}"
    kits._remove_stale(root, ".partial-*")
    kits._remove_stale(joindir.parent, "join-*")
    rp.remove_state(str(stage_root))
    stage.mkdir(parents=True)
    try:
        path = source.open_archive(PACK_ARCHIVE, joindir)
        count = extract_archive(path, stage)
        if path.parent == joindir:
            path.unlink()
        digest = kits._copy_hashed(source.dir / PACK_JSON, stage / PACK_JSON)
        if digest != source.sums[PACK_JSON]:
            raise KitError(f"{source.tag}: installed {PACK_JSON} has sha256 "
                           f"{digest}, not the listed "
                           f"{source.sums[PACK_JSON]}")
        doc = json.loads((stage / PACK_JSON).read_text(encoding="utf-8"))
        if doc.get("project") != project \
                or doc.get("manifest_sha256") != pinned:
            raise KitError(
                f"{source.tag}: {PACK_JSON} names project "
                f"{doc.get('project')!r} and manifest "
                f"{doc.get('manifest_sha256')}; this req2test pins {project} "
                f"{pinned}")
        actual = rp.manifest_sha256(str(stage))
        if actual != pinned:
            raise KitError(f"{source.tag}: the extracted pack has manifest "
                           f"{actual}, not the pinned {pinned}")
        _refused(rp.load_pack, str(stage_root), project)
        if final.exists():
            raise KitError(f"{final} appeared during the install; not "
                           f"overwriting it")
        os.rename(stage, final)
    finally:
        rp.remove_state(str(stage_root))
        shutil.rmtree(joindir, ignore_errors=True)
    return final, count


def fetch_packs(projects=None, remote: Optional[kits.Remote] = None, *,
                home=None, from_dir=None, download_dir=None,
                download_only: bool = False, jobs: int = 4,
                keep_downloads: bool = False) -> list:
    """Download, verify and install the pinned runtime packs of `projects`
    (default: all eight) at `$REQ2TEST_HOME/runtime-packs/<project>`.

    Files come from the release folders `releases/runtime-<project>-v<version>/`
    of `remote` (default: `kits.Remote()`), or from `from_dir/<tag>/` or
    `from_dir/releases/<tag>/`, each checked against the release's pinned
    `SHA256SUMS`.  An installed
    pack with the same pack.json is kept; any other is an error.  Returns the
    installed directories, or with `download_only` one download record per
    release.
    """
    home = Path(home or kits.req2test_home())
    projects = kits._select_projects(projects)
    from_dir = Path(from_dir) if from_dir else None
    workdir = Path(download_dir) if download_dir else home / "downloads"
    remote = remote or kits.Remote()
    plan, download = {}, []
    for project in projects:
        source = kits._Source(kits.pack_tag(project), remote, workdir,
                              from_dir)
        source.get([])
        missing = [n for n in PACK_FILES if n not in source.sums]
        if missing:
            raise KitError(f"{source.tag}: {SUMS} does not list {missing}")
        final = kits.packs_root(home) / project
        state = "absent" if download_only else kits._installed_state(
            final, PACK_JSON, source.sums[PACK_JSON])
        if state == "different":
            raise KitError(f"{final} holds another runtime pack; not "
                           f"overwriting it (remove the directory to "
                           f"reinstall)")
        if state == "same":
            kits._log(f"{source.tag}: already installed at {final}")
            source.cleanup(keep_downloads)
            continue
        names = [PACK_JSON] + source.archive_assets(PACK_ARCHIVE)
        plan[project] = (source, names)
        download += source.download_jobs(names)
    if plan:
        kits._log(kits._plan_line(from_dir, "runtime pack release(s)",
                                  list(plan.values())))
    kits._run_jobs(download, jobs)
    for source, names in plan.values():
        source.get(names)
    if download_only:
        return [kits._downloaded(source, names)
                for source, names in plan.values()]
    for project, (source, _names) in plan.items():
        final, count = _install(source, project, home)
        kits._log(f"{source.tag}: installed {count} entries at {final}, "
                  f"manifest {kits.RUNTIME_PACKS[project][1][:12]} as pinned")
        source.cleanup(keep_downloads)
    return [kits.packs_root(home) / p for p in projects]


# --------------------------------------------------------------------------
# `req2test runtime setup`


def _pinned_pack(project: str, packs_dir=None):
    """The installed pack of `project`, admitted by `load_pack` and refused
    unless it records the manifest this req2test pins."""
    root = Path(packs_dir).expanduser() if packs_dir else kits.packs_root()
    pack = _refused(_runtime_pack().load_pack, str(root), project)
    _version, pinned = kits.RUNTIME_PACKS[project]
    if pack.manifest_sha256 != pinned:
        raise KitError(
            f"the {project} runtime pack at {pack.dir} records manifest "
            f"{pack.manifest_sha256}; this req2test pins {pinned} "
            f"({kits.pack_tag(project)}). Remove it and run `req2test fetch "
            f"--packs-only --project {project}`")
    return pack


def setup_attempt(project: str, instance_id: str, workspace,
                  state=None, packs_dir=None) -> dict:
    """Set up one execution-enabled attempt in `workspace` (which holds the
    materialized TH view at `repo/`) from the installed pinned pack.

    `state` (default `<workspace>.rt`) must not
    exist.  Returns the binds the agent's sandbox makes (the workspace at
    its own path, then the pack's binds), the `PATH` entry it puts first,
    the links to make in the agent's home (`home_links`: each entry of the
    pack's `rt/home/` by its in-sandbox path; none for a pack without one),
    the pack identity a row records (`metadata.runtime_pack`), and the
    same binds as `docker run` options for an agent that runs in a container
    (`docker_args`).
    """
    if project not in kits.RUNTIME_PACKS:
        raise ValueError(f"unknown project {project!r}")
    if not instance_id.startswith(project + "/"):
        raise ValueError(f"{instance_id!r} is not a {project} instance")
    rp = _runtime_pack()
    pack = _pinned_pack(project, packs_dir)
    ws = os.path.abspath(workspace)
    state = os.path.abspath(state) if state else ws + ".rt"
    if os.path.lexists(state):
        raise ValueError(f"{state} already exists; every attempt starts "
                         f"from a new state directory")
    added, repaired, instance_file = _refused(
        rp.init_attempt, pack, ws, state, instance_id)
    binds = _refused(rp.sandbox_binds, pack, ws, state)
    home = os.path.join(pack.dir, rp.RUNTIME_DIR, rp.HOME_DIR)
    home_links = [{"name": name,
                   "target": posixpath.join(rp.PACK_MOUNT, rp.HOME_DIR, name)}
                  for name in (sorted(os.listdir(home))
                               if os.path.isdir(home) else ())]
    setup = {
        "project": project, "instance_id": instance_id, "workspace": ws,
        "repo": os.path.join(ws, "repo"), "state": state,
        # The workspace at its own path first: attempt.env names it, and
        # the pack's runner binds it again in its nested sandbox.
        "binds": [{"source": ws, "target": ws, "writable": True}]
                 + [{"source": src, "target": dst, "writable": rw}
                    for src, dst, rw in binds],
        "path_prepend": rp.PACK_MOUNT + "/bin",
        "home_links": home_links,
        "remainder_added": len(added),
        "runtime_pack": {"project": pack.project,
                         "manifest_sha256": pack.manifest_sha256,
                         "pack_json_sha256": pack.pack_json_sha256,
                         "repaired": repaired,
                         "instance_file": instance_file},
    }
    setup["docker_args"] = docker_args(setup)
    return setup


# --------------------------------------------------------------------------
# Containers

#: What a container needs for the runner's nested bubblewrap: Docker's
#: default seccomp profile refuses its user namespace, and its default
#: AppArmor profile and masked `/proc` paths refuse its mounts.
DOCKER_SECURITY = ("--security-opt", "seccomp=unconfined",
                   "--security-opt", "apparmor=unconfined",
                   "--security-opt", "systempaths=unconfined")
#: Docker's default `PATH`, after the pack's wrappers.
DOCKER_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def docker_args(setup: dict) -> list:
    """The `docker run` options that give a container the attempt's
    runtime: the binds at the same paths, the wrappers first on `PATH`, the
    workspace as the working directory, and `DOCKER_SECURITY`."""
    args = list(DOCKER_SECURITY)
    for bind in setup["binds"]:
        args += ["-v", f"{bind['source']}:{bind['target']}"
                 + ("" if bind["writable"] else ":ro")]
    return args + ["-w", setup["workspace"],
                   "-e", f"PATH={setup['path_prepend']}:{DOCKER_PATH}"]


def docker_user() -> list:
    """`--user UID:GID` on a rootful Docker daemon, so the files a container
    writes in the workspace stay yours; nothing on a rootless one, whose
    root already is you."""
    done = subprocess.run(["docker", "info", "--format",
                           "{{json .SecurityOptions}}"],
                          capture_output=True, text=True)
    # Without a daemon, `docker info --format` prints null and exits 0.
    if done.returncode != 0 or done.stdout.strip() == "null":
        raise ValueError(f"docker info failed: {done.stderr.strip()}")
    if "rootless" in done.stdout:
        return []
    return ["--user", f"{os.getuid()}:{os.getgid()}"]


def unprivileged(user: list) -> list:
    """The prefix of a container's command that runs it as you rather than
    as root on a rootless Docker daemon (`user`, from `docker_user`, is
    empty): an unprivileged user of a user namespace of its own, with your
    IDs, mapped to the container's root, which on the host is you.  The
    packs' PostgreSQL and MySQL refuse to run as root.  Nothing on a rootful
    daemon, where `user` already runs the container as you."""
    if user:
        return []
    return ["bwrap", "--die-with-parent", "--unshare-user", "--uid", str(os.getuid()),
            "--gid", str(os.getgid()), "--dev-bind", "/", "/", "--"]


# --------------------------------------------------------------------------
# `req2test runtime preflight`

#: What the preflight's sandbox binds of the host, read-only, besides the
#: attempt's binds: the system set of the leaderboard runs' agent sandbox, a
#: merged-`/usr` link as the link it is.
PREFLIGHT_SYSTEM = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/ssl",
                    "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf")
PREFLIGHT_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def bwrap_base(system=PREFLIGHT_SYSTEM, bwrap: str = "bwrap") -> list:
    """A bubblewrap sandbox with loopback only and a private `/tmp`, which
    binds the host's `system` set read-only, a merged-`/usr` link as the
    link it is."""
    argv = [bwrap, "--die-with-parent", "--unshare-pid", "--unshare-ipc",
            "--unshare-net", "--unshare-uts", "--new-session",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for path in system:
        if os.path.islink(path) and path.count("/") == 1:
            argv += ["--symlink", os.readlink(path), path]
        elif os.path.exists(path):
            argv += ["--ro-bind", path, path]
    return argv


def _preflight_argv(setup: dict, command: str) -> list:
    """A bubblewrap sandbox (`bwrap_base`) with `setup`'s binds, running
    `command` from the workspace."""
    argv = bwrap_base()
    for bind in setup["binds"]:
        argv += ["--bind" if bind["writable"] else "--ro-bind",
                 bind["source"], bind["target"]]
    path = f"{setup['path_prepend']}:{PREFLIGHT_PATH}"
    return argv + ["--chdir", setup["workspace"], "--clearenv",
                   "--setenv", "PATH", path,
                   "--setenv", "HOME", setup["workspace"],
                   "/bin/sh", "-c", command]


def _docker_preflight_argv(setup: dict, image: str, user: list,
                           command: str) -> list:
    """A container of `image` with the attempt's `docker_args`, running
    `command` from the workspace as you (`unprivileged`)."""
    return (["docker", "run", "--rm"] + setup["docker_args"] + user
            + ["-e", f"HOME={setup['workspace']}", image] + unprivileged(user)
            + ["/bin/sh", "-c", command])


def preflight_runtime(project: str, workspace_root, instance_id=None,
                      packs_dir=None, docker: Optional[str] = None) -> dict:
    """Probe the installed pinned pack in a probe attempt under
    `workspace_root`, the directory that will hold the attempts' workspaces.
    With `docker`, an image, the probe runs in a container of that image
    instead of the reference bubblewrap sandbox.

    The attempt is set up for `instance_id`, by default the project's first
    eval instance, as `setup_attempt` sets one up, with an empty `repo/`.
    The probe runs through the pack's wrapper and runner
    (`runtime_pack.run_probe`), and the attempt is removed.  Returns the
    probe's record (`ok`, `cause`, `probe`, `exit`, `stderr_tail`, ...), the
    instance and the pack identity.
    """
    root = Path(workspace_root).expanduser()
    if not root.is_dir():
        raise ValueError(f"--workspace-root {root} is not a directory")
    if instance_id is None:
        from . import dataset
        from .layout import data_dir
        instance_id = next(dataset.iter_instances("eval", project, data_dir()),
                           {}).get("instance_id")
        if instance_id is None:
            raise ValueError(f"the eval split has no {project} instance")
    rp = _runtime_pack()
    ws = tempfile.mkdtemp(prefix="r2t-preflight-", dir=os.path.abspath(root))
    state = ws + ".rt"
    try:
        os.mkdir(os.path.join(ws, "repo"))
        setup = setup_attempt(project, instance_id, ws, state=state,
                              packs_dir=packs_dir)
        if docker:
            user = docker_user()
            argv = lambda command: _docker_preflight_argv(  # noqa: E731
                setup, docker, user, command)
        else:
            argv = lambda command: _preflight_argv(setup, command)  # noqa: E731
        record = rp.run_probe(_pinned_pack(project, packs_dir), ws, state, argv)
    finally:
        shutil.rmtree(ws, ignore_errors=True)
        rp.remove_state(state)
    return dict(record, project=project, instance_id=instance_id,
                runtime_pack=setup["runtime_pack"], docker=docker)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """The `runtime` verb's actions, on the `req2test runtime` subparser."""
    sub = parser.add_subparsers(dest="action", metavar="ACTION")
    sub.required = True
    setup = sub.add_parser(
        "setup", help="set up one attempt's runtime",
        description="Apply the installed runtime pack to a workspace whose "
                    "repo/ holds the instance's materialized TH view: "
                    "repairs, remainder, state and instance file, in that "
                    "order. Prints the sandbox binds as JSON.")
    setup.add_argument("--project", required=True,
                       choices=sorted(kits.RUNTIME_PACKS))
    setup.add_argument("--instance", required=True, help="instance_id")
    setup.add_argument("--workspace", required=True,
                       help="the workspace; its repo/ is the view")
    setup.add_argument("--state", default=None,
                       help="new per-attempt state directory "
                            "(default <workspace>.rt)")
    setup.add_argument("--packs-dir", default=None,
                       help="default $REQ2TEST_HOME/runtime-packs")
    preflight = sub.add_parser(
        "preflight", help="check that the runtime pack runs where the "
                          "workspaces will be",
        description="Set up a probe attempt in a new directory under "
                    "--workspace-root as `runtime setup` would, run the "
                    "project's runtime probe through the pack's runner in a "
                    "bubblewrap sandbox that makes the attempt's binds, and "
                    "remove the attempt. Prints the probe's record as JSON; "
                    "exits 1 when the runtime cannot run there.")
    preflight.add_argument("--project", required=True,
                           choices=sorted(kits.RUNTIME_PACKS))
    preflight.add_argument("--workspace-root", required=True,
                           help="the existing directory that will hold the "
                                "attempts' workspaces")
    preflight.add_argument("--instance", default=None,
                           help="the instance_id to set up (default: the "
                                "project's first eval instance)")
    preflight.add_argument("--packs-dir", default=None,
                           help="default $REQ2TEST_HOME/runtime-packs")
    preflight.add_argument("--docker", default=None, metavar="IMAGE",
                           help="run the probe in a container of IMAGE, "
                                "with the attempt's docker_args, instead of "
                                "a bubblewrap sandbox")


def main(args: argparse.Namespace) -> int:
    """`req2test runtime setup` and `preflight`; errors propagate to
    `req2test.cli.main`."""
    if args.action == "preflight":
        record = preflight_runtime(args.project, args.workspace_root,
                                   args.instance, packs_dir=args.packs_dir,
                                   docker=args.docker)
        print(json.dumps(record, indent=1, sort_keys=True))
        if not record["ok"]:
            print(f"req2test runtime preflight: FAILED: {record['cause']}",
                  file=sys.stderr)
        return 0 if record["ok"] else 1
    result = setup_attempt(args.project, args.instance, args.workspace,
                           state=args.state, packs_dir=args.packs_dir)
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0
