"""Runtime packs: the runnable workspace of the `c2r` condition.

EXECUTION_ENABLED_TH_SENSITIVITY_SPEC.md section 3.  Per project, the
pack's runtime (`RUNTIME_DIR`) is bound read-only into the agent's own sandbox
at `PACK_MOUNT`, a per-attempt writable state directory at `STATE_MOUNT`, and
the agent's `PATH` starts with `PACK_MOUNT/bin`.  The runtime holds the
evaluation image's curated userland (`rootfs/`), one small wrapper per command
a developer would type (`bin/`), the runner those wrappers call
(`libexec/run`, which executes the real command in a nested bubblewrap on the
agent's own workspace and appends one JSON line per run to
`STATE_MOUNT/runs.jsonl`) and the runtime's environment (`env`).  A runtime
whose configuration names an absolute application directory (Sylius's
`/var/www/html`) names it in `workdir_alias`: the runner binds the agent's
`./repo` there as well, and so does the agent's own sandbox, so a path the
runtime prints opens in the agent's shell.  A runtime may also ship what a
developer's home holds for its tools (`home/`, Kapua's and Algorand SDK's
`.m2` in benchmark 2.0): the agent driver links each entry into the home it
makes for the agent's CLI.  Beside the runtime, outside the
sandbox, are the non-implementation files a checkout has and the view lacks
(`remainder/`, copied into the workspace), the compile repairs of views that
hiding left unable to build or load (`repairs/`, section 3.4, applied to
the workspace), the per-instance files a runtime reads (`instances/`, the
attempt's one copied into its state), the attempt's initial state
(`state-template/`, copied into the state directory), the build record, and
`pack.json`: recipe, provenance and the leak audit's result.  Only the
runtime is bound: the record and the audit describe the hidden bodies they
were checked against, and the agent must not read them.

This module is the harness's side of a pack, and nothing more: its identity
(`manifest_sha256`), its admission (`load_pack`), the attempt's setup
(`init_attempt`) and binds (`sandbox_binds`), the read-back of the
runner's log (`collect_runs`, `past_setup`) and the runtime probe
(`run_probe`), which the launcher's preflight (`agents.runtime_preflight`)
and `req2test runtime preflight` run in a probe attempt of their own.  It
builds no sandbox; the adapter binds the
pack through `agent_sandbox_command(extra_binds=...)`.  The pack is NOT
passed through the source-view mount audit: its leak audit is its own,
recorded in `pack.json`, and `load_pack` admits only a pack whose audit
passed.

`python -m r2t.agents.runtime_pack manifest DIR` prints a pack's manifest
digest; `verify DIR` recomputes it and compares it with `pack.json`.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass

#: Where the pack and the attempt's state are mounted inside the sandbox.
#: Fixed, because the wrappers and the runner name them literally.
PACK_MOUNT = "/r2t-rt"
STATE_MOUNT = "/r2t-state"

#: The part of a pack that is bound at `PACK_MOUNT`; nothing else of it is.
RUNTIME_DIR = "rt"

#: The operator setting naming the directory that holds one pack per project;
#: unset, `$R2T_DATA_ROOT/runtime-packs`.
PACKS_ENV = "R2T_RUNTIME_PACKS"

#: The pack's compile repairs: `index.json` lists `{path, th_sha256,
#: repaired_sha256, rule}`, and `blobs/<repaired_sha256>` holds the bytes.
REPAIRS_DIR = "repairs"

#: Per-instance files a runtime reads, `instances/<sha256(instance id)>.json`
#: (the Behat projects' suite and retained contexts), and the one name the
#: attempt's own file has in its state, whatever the project.
INSTANCES_DIR = "instances"
INSTANCE_FILE = "instance.json"

#: In the runtime: one absolute path at which `./repo` is also bound.
WORKDIR_ALIAS = "workdir_alias"
#: In the runtime: entries for the agent's home.  The Codex and Claude Code
#: drivers name `PACK_MOUNT/HOME_DIR` themselves (`RUNTIME_HOME`): this
#: module is not in their sandbox.
HOME_DIR = "home"
#: Top-level names an alias may not be at or under: the agent sandbox's own
#: system binds, its `/proc`, `/dev` and `/tmp`, and the two mounts above.
#: `lib*` covers `/lib`, `/lib64`, `/lib32` and `/libx32`.
SYSTEM_TOPS = ("usr", "bin", "sbin", "lib*", "etc", "proc", "dev", "tmp",
               PACK_MOUNT.lstrip("/"), STATE_MOUNT.lstrip("/"))

#: The runner's log in the attempt's state, and its copy in the trajectory.
RUNS_LOG = "runs.jsonl"
TRAJECTORY_LOG = "runtime_runs.jsonl"

#: A logged run whose nested sandbox was never set up: bubblewrap exits 1
#: when it cannot build the namespace, and `timeout` exits 125-127 when it
#: cannot start bubblewrap.  Such a run usually ends within milliseconds:
#: 2,586 of the 2,588 runs of the seven GPT-6.1 Sol 2.0 cells other than
#: PrestaShop, all of them setup failures, ended within 0.108 s (the other
#: two took 0.96 s and 7.0 s).  A real run also exits 1 when a test or a
#: compile fails, as most test runs on a TH view do (two Kapua baseline
#: attempts ran only `javac` compiles that failed in 0.43 s and 0.44 s), so a
#: run counts as past setup when it exits otherwise or lasts at least
#: SETUP_SECONDS (`past_setup`).
SETUP_FAILURE_EXITS = (1, 125, 126, 127)
SETUP_SECONDS = 0.25

#: Each project's runtime probe: a command every pack of the project has in
#: `rt/bin`, asking the runtime for its version, so it exits 0 whatever the
#: view hides.  `run_probe` types it as an agent would, from `./repo`.
PROBES = {
    "python-docx": ("python3", "--version"),
    "algorand-sdk": ("java", "-version"),
    "kapua": ("java", "-version"),
    "coddy-agent": ("go", "version"),
    "coreshop": ("php", "--version"),
    "sylius": ("php", "--version"),
    "prestashop": ("php", "--version"),
    "e-petitions": ("ruby", "--version"),
}
#: The probe's envelope: a pack with services starts its database first,
#: and its `services` script waits up to 120 s for it.
PROBE_SECONDS = 300


@dataclass(frozen=True)
class RuntimePack:
    """One admitted pack: where it is, the two digests a row records, its
    repairs as `(path, th_sha256, repaired_sha256)` and its workdir alias."""

    dir: str
    project: str
    manifest_sha256: str
    pack_json_sha256: str
    repairs: frozenset = frozenset()
    workdir_alias: str | None = None


def packs_root() -> str:
    """`R2T_RUNTIME_PACKS`, else `$R2T_DATA_ROOT/runtime-packs`."""
    from ..core.paths import data_path
    return os.path.abspath(os.environ.get(PACKS_ENV)
                           or os.fspath(data_path("runtime-packs")))


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def manifest_sha256(pack_dir: str) -> str:
    """sha256 over the sorted lines `<kind> <sha256-or-link-target> <relpath>`.

    One line per regular file (`f`, its content's sha256) and per symlink
    (`l`, its target, never followed) under `pack_dir`, `pack.json` excepted
    because it records this digest.  Directories are implied by the paths
    they hold; nothing else (a fifo, a device node) is content.  Bytes
    throughout, so a file name that is not UTF-8 is hashed as it is on disk.
    """
    return manifest_digest(manifest_lines(pack_dir))


def manifest_digest(lines) -> str:
    """`manifest_sha256` of a pack whose manifest lines are `lines`."""
    return hashlib.sha256(b"".join(line + b"\n" for line in lines)).hexdigest()


def manifest_lines(pack_dir: str) -> list:
    """The sorted lines `manifest_sha256` digests, as bytes without the
    newline, so that two builds of a pack can be compared line by line."""
    root = os.fsencode(os.path.abspath(pack_dir))
    lines = []
    for dirpath, dirnames, filenames in os.walk(root):
        # A symlink to a directory is listed with the directories and not
        # descended into; it is recorded as the link it is.
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                lines.append(b"l " + os.readlink(path) + b" " + rel)
            elif stat.S_ISREG(mode) and rel != b"pack.json":
                lines.append(b"f " + _file_sha256(path).encode() + b" " + rel)
    return sorted(lines)


def load_pack(root: str, project: str) -> RuntimePack:
    """The pack at `<root>/<project>`, admitted on its own `pack.json`.

    Refused unless it names `project`, its leak audit says `passed: true`,
    and it has an `rt/` to bind, its repairs, if any, repair each view
    file one way only, and its workdir alias, if any, is one absolute path
    outside the sandbox's system paths.  The manifest digest it records is
    read, not
    recomputed (the adapter compares it with the protocol's pin):
    hashing a whole userland per launch would buy nothing `verify` does not
    already give the operator before the run.
    """
    directory = os.path.join(os.path.abspath(root), project)
    path = os.path.join(directory, "pack.json")
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        doc = json.loads(raw)
    except (OSError, ValueError) as e:
        raise SystemExit(
            f"REFUSED: no readable runtime pack for {project} at {path} "
            f"({e}). Set {PACKS_ENV} to the directory holding the packs.")
    audit = doc.get("audit") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or doc.get("project") != project:
        raise SystemExit(f"REFUSED: {path} is not the runtime pack of {project}")
    if not isinstance(audit, dict) or audit.get("passed") is not True:
        raise SystemExit(f"REFUSED: {path} records no passed leak audit")
    digest = doc.get("manifest_sha256")
    if not os.path.isdir(os.path.join(directory, RUNTIME_DIR)):
        raise SystemExit(f"REFUSED: {directory} has no {RUNTIME_DIR}/ to bind")
    return RuntimePack(directory, project, digest,
                       hashlib.sha256(raw).hexdigest(), _read_repairs(directory),
                       _read_alias(directory))


def _read_alias(directory: str) -> str | None:
    """`rt/workdir_alias`, refused unless it is one normalized absolute path
    whose first component is none of `SYSTEM_TOPS`.

    The agent sandbox binds `./repo` at it, so at or under a system path it
    would shadow the sandbox's own binds (or fail to mount under a read-only
    one), and `/` would shadow all of them.
    """
    path = os.path.join(directory, RUNTIME_DIR, WORKDIR_ALIAS)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        alias = fh.read().strip()
    top = alias.split("/")[1] if alias.startswith("/") else ""
    if (not os.path.isabs(alias) or os.path.normpath(alias) != alias
            or any(c.isspace() for c in alias) or not top
            or any(fnmatch.fnmatchcase(top, t) for t in SYSTEM_TOPS)):
        raise SystemExit(
            f"REFUSED: {path} names {alias!r}, not one absolute path outside "
            f"the sandbox's system paths (/{', /'.join(SYSTEM_TOPS)})")
    return alias


def _read_repairs(directory: str) -> frozenset:
    """The pack's repairs, refused if one view file is repaired two ways.

    A view file is identified by its path and its sha256 (null: absent from
    the view), so two entries with one identity and different bytes leave
    the attempt's file to chance.  Identical entries are one repair.
    """
    path = os.path.join(directory, REPAIRS_DIR, "index.json")
    if not os.path.exists(path):
        return frozenset()
    try:
        with open(path, encoding="utf-8") as fh:
            repairs = frozenset((e["path"], e["th_sha256"], e["repaired_sha256"])
                                for e in json.load(fh))
    except (OSError, ValueError, TypeError, KeyError) as e:
        raise SystemExit(f"REFUSED: {path} is not a list of repairs ({e!r})")
    keys = [(p, th) for p, th, _ in repairs]
    if len(keys) != len(set(keys)):
        raise SystemExit(f"REFUSED: {path} repairs one view file two ways")
    return repairs


def init_attempt(pack: RuntimePack, ws: str, state: str,
                 instance_id: str) -> tuple:
    """Set up one attempt: the repairs and the remainder in `ws/repo`, the
    state from its template and the instance's own file.

    A repair applies where the view, as materialized, has its path with its
    `th_sha256`, or lacks the path when that is null: it writes the repaired
    bytes, keeping the file's mode (0644 for a file it adds).  Every other
    repair is another instance's.  The remainder is then copied file by file
    and never over a file the view already has (view files win);
    `state-template/` is copied whole into `state`, with `state/home` beside
    it, and `state/attempt.env` names the workspace and the repository for
    the runner.  A pack with `instances/` holds one file per instance,
    `<sha256(instance_id)>.json`, copied to `state/instance.json`; an
    instance it has no file for is refused before anything is written.
    Returns the repository-relative paths the remainder added and those the
    repairs wrote, so the caller can seed both like view files (unchanged,
    they are not the agent's edits), and whether an instance file was
    copied.
    """
    ws = os.path.abspath(ws)
    repo = os.path.join(ws, "repo")
    if not os.path.isdir(repo):
        raise SystemExit(f"REFUSED: no materialized view at {repo}")
    instances = os.path.join(pack.dir, INSTANCES_DIR)
    instance = None
    if os.path.isdir(instances):
        instance = os.path.join(instances, hashlib.sha256(
            instance_id.encode("utf-8")).hexdigest() + ".json")
        if not os.path.isfile(instance):
            raise SystemExit(
                f"REFUSED: the {pack.project} runtime pack has {INSTANCES_DIR}/ "
                f"but no file for {instance_id} ({os.path.basename(instance)}); "
                f"its runtime cannot run this instance's Scenario.")
    # Matched against the view before any repair is written, so a repair
    # never applies to another's output.
    found = {}
    for rel, _th, _sha in pack.repairs:
        if rel not in found:
            path = os.path.join(repo, rel)
            found[rel] = (_file_sha256(path) if os.path.isfile(path)
                          else "" if os.path.lexists(path) else None)
    repaired = []
    for rel, th, sha in pack.repairs:
        if found[rel] == th:
            path = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            shutil.copyfile(os.path.join(pack.dir, REPAIRS_DIR, "blobs", sha), path)
            if th is None:
                os.chmod(path, 0o644)
            repaired.append(rel)
    added = []
    remainder = os.path.join(pack.dir, "remainder")
    for dirpath, dirnames, filenames in os.walk(remainder):
        rel_dir = os.path.relpath(dirpath, remainder)
        os.makedirs(os.path.normpath(os.path.join(repo, rel_dir)), exist_ok=True)
        for name in filenames + [d for d in dirnames
                                 if os.path.islink(os.path.join(dirpath, d))]:
            src = os.path.join(dirpath, name)
            rel = os.path.normpath(os.path.join(rel_dir, name))
            dst = os.path.join(repo, rel)
            if os.path.lexists(dst):
                continue
            if os.path.islink(src):
                os.symlink(os.readlink(src), dst)
            else:
                shutil.copy2(src, dst)
            added.append(rel.replace(os.sep, "/"))
    os.makedirs(state)
    template = os.path.join(pack.dir, "state-template")
    if os.path.isdir(template):
        # Without the template's timestamps: Go trims cache entries whose
        # mtime is more than five days old, which would empty a seeded GOCACHE
        # in every attempt once the pack is a week old.
        subprocess.run(["cp", "-dR", "--preserve=mode,links", "--reflink=auto",
                        template + "/.", state], check=True)
    os.makedirs(os.path.join(state, "home"), exist_ok=True)
    if instance is not None:
        shutil.copyfile(instance, os.path.join(state, INSTANCE_FILE))
    with open(os.path.join(state, "attempt.env"), "w", encoding="utf-8") as fh:
        fh.write(f"WS={ws}\nREPO={repo}\n")
    return sorted(added), sorted(repaired), instance is not None


def sandbox_binds(pack: RuntimePack, ws: str, state: str) -> tuple:
    """The attempt's `extra_binds`: the runtime read-only at `PACK_MOUNT`,
    the state read-write at `STATE_MOUNT` and, when the pack has a workdir
    alias, `ws/repo` read-write at the alias.

    The alias must not be, contain or lie inside the workspace, which the
    sandbox binds at its own path: one of the two binds would shadow the
    other.
    """
    binds = ((os.path.join(pack.dir, RUNTIME_DIR), PACK_MOUNT, False),
             (state, STATE_MOUNT, True))
    alias = pack.workdir_alias
    if alias is None:
        return binds
    ws = os.path.abspath(ws)
    if (alias + "/").startswith(ws + "/") or (ws + "/").startswith(alias + "/"):
        raise SystemExit(f"REFUSED: the {pack.project} runtime pack's workdir "
                         f"alias {alias} collides with the workspace {ws}")
    return binds + ((os.path.join(ws, "repo"), alias, True),)


def remove_state(state: str) -> None:
    """Remove an attempt's state, unreadable and read-only directories included.

    A Go module cache is read-only by design, and the agent can leave a
    directory it made unreadable; `rmtree` alone would leave either behind.
    Never raises: it runs after the row is assembled.  `chmod -R` changes a
    directory before it reads it and never follows a link.
    """
    if os.path.isdir(state):
        subprocess.run(["chmod", "-R", "u+rwX", state],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(state, ignore_errors=True)


def collect_runs(state: str, trajectory_dir) -> dict:
    """Copy the runner's log into the trajectory and count what it records.

    `n_runs` runs, `run_seconds` spent in them, `n_nonzero` that exited
    non-zero.  A line that does not parse is skipped rather than refused: the
    last one is cut short when the sandbox ends mid-run, and the copy keeps
    the raw bytes for anyone who needs more than the counts.

    The agent can write both the state and the trajectory directory, so it
    can put a link at either path, as `harvest` already assumes of the
    workspace.  The log is read without following one and only if it is a
    regular file, and the copy is created as a new file without following
    one; anything else is recorded under `error`, never followed.
    """
    raw, record = b"", {}
    try:
        fd = os.open(os.path.join(state, RUNS_LOG),
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        fd = None
    except OSError as e:
        fd, record["error"] = None, f"runs log not read: {e.strerror}"
    if fd is not None:
        with os.fdopen(fd, "rb") as fh:
            if stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                raw = fh.read()
            else:
                record["error"] = "runs log is not a regular file"
    if raw and trajectory_dir:
        try:
            out = os.open(os.path.join(trajectory_dir, TRAJECTORY_LOG),
                          os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                          | os.O_CLOEXEC, 0o644)
        except OSError as e:
            record["error"] = f"runs log not copied: {e.strerror}"
        else:
            with os.fdopen(out, "wb") as fh:
                fh.write(raw)
    runs = parse_runs(raw)
    seconds = [r.get("seconds") for r in runs]
    return {"n_runs": len(runs),
            "run_seconds": round(sum(s for s in seconds
                                     if isinstance(s, (int, float))), 3),
            "n_nonzero": sum(1 for r in runs if r.get("exit") != 0),
            **record}


def parse_runs(raw: bytes) -> list:
    """The entries of a runner's log; a line that does not parse is skipped
    (the last one is cut short when the sandbox ends mid-run)."""
    runs = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            runs.append(entry)
    return runs


def trajectory_runs(trajectory_dir: str) -> list:
    """The runs an attempt's trajectory records (`TRAJECTORY_LOG`); none
    when it has no log, which `collect_runs` copies only when it is not
    empty."""
    try:
        with open(os.path.join(trajectory_dir, TRAJECTORY_LOG), "rb") as fh:
            return parse_runs(fh.read())
    except FileNotFoundError:
        return []


def past_setup(run: dict) -> bool:
    """Whether one logged run got past the runner's sandbox setup: it exited
    other than `SETUP_FAILURE_EXITS`, or ran at least `SETUP_SECONDS`.  Not
    "exited 0": a test run on a TH view usually fails, because the hidden
    bodies throw."""
    code, seconds = run.get("exit"), run.get("seconds")
    if not isinstance(code, int) or isinstance(code, bool):
        return False
    return code not in SETUP_FAILURE_EXITS or (
        isinstance(seconds, (int, float)) and seconds >= SETUP_SECONDS)


def run_probe(pack: RuntimePack, ws: str, state: str, sandbox_argv,
              probe=None, timeout: float = PROBE_SECONDS) -> dict:
    """Run the project's probe (`PROBES`) in an attempt set up at `ws` and
    `state`, and say whether the runtime works there.

    `sandbox_argv(command)` is the argv that runs the shell `command` in the
    attempt's sandbox; the probe types its command from `./repo` through the
    pack's wrapper, as an agent would.  It passes when the sandbox exits 0
    and the runner logged the probe's run with exit 0, so a wrapper that
    reached no runner fails too.  The record names the cause, and, for a
    workspace under a top-level directory that the pack's userland also has,
    why the runner could not bind it.  The caller removes the attempt.
    """
    probe = tuple(probe or PROBES[pack.project])
    command = "cd repo && exec " + " ".join(shlex.quote(a) for a in probe)
    started = time.monotonic()
    try:
        done = subprocess.run(sandbox_argv(command), stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=timeout)
        code, out, err = done.returncode, done.stdout, done.stderr
    except subprocess.TimeoutExpired as e:
        code, out, err = None, e.stdout or b"", e.stderr or b""
    try:
        with open(os.path.join(state, RUNS_LOG), "rb") as fh:
            runs = parse_runs(fh.read())
    except OSError:
        runs = []
    err = err.decode("utf-8", errors="replace")
    cause = None
    if code is None:
        cause = f"the probe did not finish within {timeout:g} s"
    elif code != 0:
        cause = f"the probe exited {code}"
    elif not runs or any(r.get("exit") != 0 for r in runs):
        cause = "the probe exited 0 but the runner logged no successful run"
    # bubblewrap says "Can't mkdir parents for <ws>" when the userland lacks
    # the workspace's parent, and "Can't mkdir <ws>" when it has it (/var/tmp).
    top = ws.split("/")[1]
    if cause and "Can't mkdir" in err and os.path.lexists(
            os.path.join(pack.dir, RUNTIME_DIR, "rootfs", top)):
        cause += (f"; the workspace is under /{top}, which the pack's userland"
                  f" also has (rt/rootfs/{top}), and the runner binds that"
                  f" read-only before the workspace")
    return {"ok": cause is None, "cause": cause, "probe": list(probe),
            "workspace": ws, "state": state, "exit": code,
            "seconds": round(time.monotonic() - started, 3), "runs": runs,
            "stdout_tail": out.decode("utf-8", errors="replace")[-2000:],
            "stderr_tail": err[-2000:]}


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] not in ("manifest", "verify"):
        print("usage: python -m r2t.agents.runtime_pack {manifest|verify} DIR",
              file=sys.stderr)
        return 2
    command, pack_dir = args
    digest = manifest_sha256(pack_dir)
    if command == "manifest":
        print(digest)
        return 0
    with open(os.path.join(pack_dir, "pack.json"), encoding="utf-8") as fh:
        recorded = json.load(fh).get("manifest_sha256")
    if recorded != digest:
        print(f"MISMATCH: pack.json records {recorded}, the pack is {digest}")
        return 1
    print(f"OK {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
