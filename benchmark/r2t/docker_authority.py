"""Verified Docker execution authority and workload binding evidence.

This module is deliberately Linux/rootless-specific at its capture edge.  The
rest of the benchmark consumes only a closed, revalidated authority artifact;
it never treats a socket route, Docker context, or ambient environment as
authority.  Structural JSON schemas live in ``benchmark/schemas``.  The
cross-field and live joins that JSON Schema cannot express are enforced here.
"""
from __future__ import annotations

import datetime as _datetime
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from typing import Callable, Iterable, Mapping, Optional


AUTHORITY_SCHEMA = "r2t.docker-execution-authority/v1"
BINDING_SCHEMA = "r2t.docker-execution-binding/v1"
POOL_SCHEMA = "r2t.docker-execution-pool/v1"
ADAPTER_SCHEMA = "r2t.docker-authority-adapter/linux-rootless-v1"
VERIFIER_NAME = "r2t.docker_authority"
VERIFIER_VERSION = "1.0"
#: Why this module stayed at the package root while the rest of `core`
#: moved into `core/`: this path is recorded in every authority and pool
#: attestation ever captured, and `_verifier_git_identity` refuses a
#: module that is not at it.
VERIFIER_SOURCE_PATH = "benchmark/r2t/docker_authority.py"

ENDPOINT_ADDRESS_DOMAIN = "r2t.docker-endpoint-address/v1"
EMPTY_CONFIG_DOMAIN = "r2t.docker-client-config/empty-v1"
DAEMON_FINGERPRINT_DOMAIN = "r2t.docker-daemon-fingerprint/v1"

AMBIENT_DOCKER_KEYS = (
    "DOCKER_API_VERSION",
    "DOCKER_CERT_PATH",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_DEFAULT_PLATFORM",
    "DOCKER_HOST",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OBJECT_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_MODE_RE = re.compile(r"[0-7]{4}\Z")
_SOCKET_PATH_RE = re.compile(r"/[A-Za-z0-9._/-]+\Z")
_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class DockerAuthorityRefused(RuntimeError):
    """The requested authority/binding cannot authorize live Docker work."""


def _refuse(message: str) -> DockerAuthorityRefused:
    return DockerAuthorityRefused("REFUSED: " + message)


def _unique_object(items):
    out = {}
    for key, value in items:
        if key in out:
            raise _refuse(f"JSON object repeats key {key!r}")
        out[key] = value
    return out


def loads_exact_json(raw: bytes | str, *, label: str = "JSON") -> object:
    """Decode UTF-8 JSON while rejecting duplicate keys and non-finite floats."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _refuse(f"{label} is not UTF-8") from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise _refuse(f"{label} bytes have invalid type {type(raw).__name__}")

    def bad_constant(value: str):
        raise _refuse(f"{label} contains non-finite number {value}")

    try:
        return json.loads(text, object_pairs_hook=_unique_object,
                          parse_constant=bad_constant)
    except DockerAuthorityRefused:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise _refuse(f"{label} is not exact JSON: {exc}") from exc


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _refuse(f"evidence is not canonical-JSON encodable: {exc}") from exc


def domain_digest(domain: str, value: object) -> str:
    if not isinstance(domain, str) or not domain:
        raise _refuse("digest domain is empty")
    return hashlib.sha256(
        domain.encode("utf-8") + b"\0" + _canonical_bytes(value)).hexdigest()


def semantic_digest(document: Mapping[str, object],
                    *, domain: Optional[str] = None) -> str:
    """Digest a closed evidence object with only its top-level digest omitted."""
    if not isinstance(document, Mapping):
        raise _refuse("semantic digest input is not an object")
    schema = domain if domain is not None else document.get("schema")
    if not isinstance(schema, str) or not schema:
        raise _refuse("semantic digest input has no schema/domain")
    projected = dict(document)
    projected.pop("digest", None)
    return domain_digest(schema, projected)


def daemon_fingerprint(daemon: Mapping[str, object]) -> str:
    """Hash the daemon projection with only fingerprint_sha256 omitted."""
    if not isinstance(daemon, Mapping):
        raise _refuse("daemon fingerprint input is not an object")
    projected = dict(daemon)
    projected.pop("fingerprint_sha256", None)
    return domain_digest(DAEMON_FINGERPRINT_DOMAIN, projected)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError as exc:
        raise _refuse(f"cannot hash evidence file {path}: {exc}") from exc
    return h.hexdigest()


def _exact_keys(value: object, expected: Iterable[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise _refuse(f"{label} is not an object")
    wanted = set(expected)
    actual = set(value)
    if actual != wanted:
        raise _refuse(
            f"{label} fields differ; missing={sorted(wanted - actual)}, "
            f"unknown={sorted(actual - wanted)}")
    return value


def _string(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise _refuse(f"{label} must be a "
                      + ("string" if allow_empty else "nonempty string"))
    if "\x00" in value or "\r" in value or "\n" in value:
        raise _refuse(f"{label} contains a control separator")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise _refuse(f"{label} must be an integer >= {minimum}")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise _refuse(f"{label} must be boolean")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise _refuse(f"{label} is not a lower-case full SHA-256")
    return value


def _object_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _OBJECT_ID_RE.fullmatch(value) is None:
        raise _refuse(f"{label} is not a 64-hex Docker object ID")
    return value


def _image_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _IMAGE_ID_RE.fullmatch(value) is None:
        raise _refuse(f"{label} is not an immutable sha256: Docker image ID")
    return value


def _mode(value: object, label: str, *, owner_only: bool = False) -> str:
    if not isinstance(value, str) or _MODE_RE.fullmatch(value) is None:
        raise _refuse(f"{label} is not a four-digit octal mode")
    if owner_only and int(value, 8) & 0o077:
        raise _refuse(f"{label} grants group/other permissions")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise _refuse(f"{label} is not exact UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = _datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise _refuse(f"{label} is not a real UTC calendar instant") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise _refuse(f"{label} is not canonical UTC")
    return value


def utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def canonical_absolute_path(value: object, label: str, *,
                            socket_path: bool = False) -> str:
    path = _string(value, label)
    if not os.path.isabs(path) or os.path.normpath(path) != path \
            or "//" in path[1:]:
        raise _refuse(f"{label} is not a normalized absolute path")
    if socket_path and (_SOCKET_PATH_RE.fullmatch(path) is None
                        or any(part in (".", "..")
                               for part in path.split("/"))):
        raise _refuse(f"{label} is not an unambiguous Unix-socket path")
    return path


def refuse_ambient_docker(environ: Optional[Mapping[str, str]] = None) -> None:
    selected = os.environ if environ is None else environ
    present = [name for name in AMBIENT_DOCKER_KEYS if name in selected]
    if present:
        raise _refuse("ambient Docker selector variables are present ("
                      + ", ".join(present) + "); values were not read")


def endpoint_address(socket_path: str) -> str:
    return "unix://" + canonical_absolute_path(
        socket_path, "Docker socket path", socket_path=True)


def endpoint_address_digest(address: str) -> str:
    return hashlib.sha256(
        ENDPOINT_ADDRESS_DOMAIN.encode("utf-8") + b"\0"
        + address.encode("utf-8")).hexdigest()


def empty_config_digest() -> str:
    return hashlib.sha256(
        EMPTY_CONFIG_DOMAIN.encode("utf-8") + b"\0").hexdigest()


def _mode_text(mode: int) -> str:
    return f"{stat.S_IMODE(mode):04o}"


def _acl_absent(path: str, *, directory: bool = False) -> bool:
    names = ("system.posix_acl_access",)
    if directory:
        names += ("system.posix_acl_default",)
    try:
        present = set(os.listxattr(path, follow_symlinks=False))
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP,
                         getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}:
            return True
        raise _refuse(f"cannot inspect ACL metadata for {path}") from exc
    return not any(name in present for name in names)


def _path_components(path: str, *, include_leaf: bool) -> list[str]:
    path = canonical_absolute_path(path, "path")
    end = path if include_leaf else os.path.dirname(path)
    if end == "/":
        return ["/"]
    parts = end.split(os.sep)[1:]
    out = ["/"]
    cursor = ""
    for part in parts:
        cursor += "/" + part
        out.append(cursor)
    return out


def _secure_directory_chain(path: str, *, include_leaf: bool = False) -> None:
    trusted_uids = {0, os.geteuid()}
    for component in _path_components(path, include_leaf=include_leaf):
        try:
            info = os.lstat(component)
        except OSError as exc:
            raise _refuse(f"path component is unavailable: {component}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise _refuse(f"path component is not a non-symlink directory: "
                          f"{component}")
        mode = stat.S_IMODE(info.st_mode)
        peer_writable = bool(mode & 0o022)
        sticky_root_exception = (
            info.st_uid == 0 and bool(mode & stat.S_ISVTX)
            and bool(mode & 0o002))
        if info.st_uid not in trusted_uids:
            raise _refuse(f"path component is owned by a peer: {component}")
        if peer_writable and not sticky_root_exception:
            raise _refuse(f"path component is replaceable by a peer: {component}")


def assert_trusted_file(path: str, *, label: str = "evidence") -> os.stat_result:
    path = canonical_absolute_path(path, f"{label} path")
    _secure_directory_chain(path)
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise _refuse(f"{label} file is unavailable: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise _refuse(f"{label} is not a non-symlink regular file: {path}")
    if info.st_nlink != 1:
        raise _refuse(f"{label} has multiple hard-link names: {path}")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise _refuse(f"{label} is not current-UID owned and non-writable by peers")
    if not _acl_absent(path):
        raise _refuse(f"{label} carries an access ACL")
    if os.path.realpath(path) != path:
        raise _refuse(f"{label} path does not equal realpath")
    return info


def _read_trusted_bytes(path: str, label: str) -> bytes:
    before = assert_trusted_file(path, label=label)
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise _refuse(f"cannot read {label}: {path}") from exc
    after = assert_trusted_file(path, label=label)
    identity_before = (before.st_dev, before.st_ino, before.st_size,
                       before.st_mtime_ns, before.st_ctime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size,
                      after.st_mtime_ns, after.st_ctime_ns)
    if identity_before != identity_after or len(raw) != after.st_size:
        raise _refuse(f"{label} changed while it was read: {path}")
    return raw


def _git(args: list[str], *, cwd: str) -> bytes:
    try:
        cp = subprocess.run(["git", "-C", cwd, *args], capture_output=True,
                            timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _refuse("cannot establish verifier Git identity") from exc
    if cp.returncode != 0:
        raise _refuse("cannot establish verifier Git identity")
    return cp.stdout


def _verifier_git_root() -> str:
    module_path = os.path.realpath(__file__)
    root = _git(
        ["rev-parse", "--show-toplevel"],
        cwd=os.path.dirname(module_path)).decode("utf-8", "strict").strip()
    return canonical_absolute_path(root, "Git worktree root")


def _refuse_authority_output_in_verifier_worktree(path: str) -> str:
    """Keep a newly minted authority from invalidating its own clean pin."""
    output = canonical_absolute_path(
        os.path.abspath(path), "authority evidence output path")
    root = _verifier_git_root()
    if output == root or output.startswith(root + "/"):
        raise _refuse(
            "authority output must be outside the verifier Git worktree; "
            "otherwise the new evidence would invalidate its clean source "
            "identity before first use")
    return output


def _verifier_git_identity() -> dict:
    module_path = os.path.realpath(__file__)
    root = _verifier_git_root()
    expected = os.path.join(root, VERIFIER_SOURCE_PATH)
    if os.path.realpath(expected) != module_path:
        raise _refuse("verifier module is not at its fixed repository path")
    status = _git(["status", "--porcelain=v1", "--untracked-files=all"],
                  cwd=root)
    if status:
        raise _refuse("verifier worktree is not clean; capture from a reviewed tag")
    commit = _git(["rev-parse", "HEAD"], cwd=root).decode(
        "ascii", "strict").strip()
    if _COMMIT_RE.fullmatch(commit) is None:
        raise _refuse("verifier Git commit is not a full lower-case SHA-1")
    committed = _git(["show", f"{commit}:{VERIFIER_SOURCE_PATH}"], cwd=root)
    with open(module_path, "rb") as fh:
        raw = fh.read()
    if raw != committed:
        raise _refuse("verifier module bytes differ from the recorded commit")
    return {
        "name": VERIFIER_NAME,
        "version": VERIFIER_VERSION,
        "source_path": VERIFIER_SOURCE_PATH,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "git_commit": commit,
        "git_tree_clean": True,
    }


def _validate_reference(value: object, label: str) -> dict:
    ref = _exact_keys(value, ("path", "file_sha256", "digest"), label)
    canonical_absolute_path(ref["path"], f"{label}.path")
    _sha256(ref["file_sha256"], f"{label}.file_sha256")
    _sha256(ref["digest"], f"{label}.digest")
    return ref


def evidence_reference(path: str, *, expected_schema: Optional[str] = None,
                       validator: Optional[Callable[[object], object]] = None,
                       label: str = "evidence") -> tuple[dict, dict]:
    path = canonical_absolute_path(os.path.abspath(path), f"{label} path")
    raw = _read_trusted_bytes(path, label)
    document = loads_exact_json(raw, label=label)
    if not isinstance(document, dict):
        raise _refuse(f"{label} document is not an object")
    if expected_schema is not None and document.get("schema") != expected_schema:
        raise _refuse(f"{label} has unsupported schema {document.get('schema')!r}")
    if validator is not None:
        validator(document)
    digest = document.get("digest")
    _sha256(digest, f"{label}.digest")
    if semantic_digest(document) != digest:
        raise _refuse(f"{label} semantic digest does not recompute")
    return document, {
        "path": path,
        "file_sha256": hashlib.sha256(raw).hexdigest(),
        "digest": digest,
    }


def load_reference(reference: object, *, expected_schema: str,
                   validator: Callable[[object], object],
                   label: str) -> dict:
    ref = _validate_reference(reference, label + " reference")
    document, actual = evidence_reference(
        ref["path"], expected_schema=expected_schema, validator=validator,
        label=label)
    if actual != ref:
        raise _refuse(f"{label} reference does not match target bytes/digest")
    return document


#: Drift pairs already reported, so a command that validates the same
#: authority three times says it once.  Output hygiene, not a check.
_DISCLOSED_DRIFT: set = set()


def _disclose_verifier_drift(recorded: str, live: str) -> None:
    """Say, once, that this tree is not the tree that recorded the document.

    There is nothing to decide here, so this is deliberately not a check.  It
    exists because the difference between the commit that recorded an
    authority and the commit consuming it is exactly the kind of fact a reader
    should meet at the moment it happens, rather than reconstruct afterwards
    by joining a run row's `harness_commit` against the authority file.

    It goes to stderr because `worker provision` prints its preflight report
    as the whole of stdout and runbooks parse that stream (see `cli.cmd_worker`
    and commit 094671e, which moved provision's own progress lines off stdout
    for exactly this reason).  A note on stdout would break the parse in the
    one case this disclosure exists to allow: provisioning a pool from a
    drifted authority.
    """
    key = (recorded, live)
    if key in _DISCLOSED_DRIFT:
        return
    _DISCLOSED_DRIFT.add(key)
    print(f"note: Docker authority recorded at {recorded[:12]}, executing at "
          f"{live[:12]}; environment and contract pins still enforced",
          file=sys.stderr, flush=True)


def _validate_verifier(value: object, *, current_source: bool) -> dict:
    fields = ("name", "version", "source_path", "source_sha256",
              "git_commit", "git_tree_clean")
    doc = _exact_keys(value, fields, "authority.verifier")
    if doc["name"] != VERIFIER_NAME or doc["version"] != VERIFIER_VERSION \
            or doc["source_path"] != VERIFIER_SOURCE_PATH \
            or doc["git_tree_clean"] is not True:
        raise _refuse("authority verifier identity is unsupported")
    _sha256(doc["source_sha256"], "authority.verifier.source_sha256")
    if not isinstance(doc["git_commit"], str) \
            or _COMMIT_RE.fullmatch(doc["git_commit"]) is None:
        raise _refuse("authority verifier git_commit is not full lower-case SHA-1")
    if current_source:
        # The call below is retained deliberately, and that is the point of it:
        # it establishes the self-integrity facts about the tree running right
        # now -- the worktree is clean, this module sits at its fixed path, and
        # its bytes match the commit they claim.  Those still hold and are
        # still enforced.
        #
        # What is no longer treated as fatal is provenance DRIFT: the commit
        # running now differing from the commit that recorded this document.  A
        # worker pool names one document by path and digest, so that equality
        # made a pool usable only from its own recording commit -- a
        # comment-only edit invalidated every pool, and for the
        # database-backed project that meant a full bring-up.  The equality
        # bought no compatibility protection that is not bought elsewhere: the
        # pool separately pins `container_image_digest` (the execution
        # environment) and `harness_version` (the harness/pool contract, see
        # `validate.HARNESS_VERSION`), and this module's own contract is pinned
        # by the VERIFIER_VERSION equality checked above.  Comparable
        # benchmarks pin the subject commit and the environment image, not the
        # evaluating harness's commit.  So drift is DISCLOSED rather than
        # fatal, and every run row still carries `harness_commit`, so a reader
        # can always join the two.  Owner decision, 2026-08-29.
        live = _verifier_git_identity()
        if doc["git_commit"] != live["git_commit"]:
            _disclose_verifier_drift(doc["git_commit"], live["git_commit"])
    return doc


def _validate_endpoint(value: object) -> dict:
    fields = ("selection_source", "selection_identity", "transport",
              "address", "address_sha256", "ambient_keys_checked",
              "ambient_keys_present", "client_config_mode",
              "client_config_sha256")
    doc = _exact_keys(value, fields, "authority.endpoint")
    if doc["selection_source"] != "explicit_cli" \
            or doc["transport"] != "unix" \
            or doc["client_config_mode"] != "isolated_empty":
        raise _refuse("authority endpoint selection mode is unsupported")
    address = _string(doc["address"], "authority.endpoint.address")
    if not address.startswith("unix://"):
        raise _refuse("authority endpoint is not a Unix URI")
    path = canonical_absolute_path(address[len("unix://"):],
                                   "authority endpoint socket",
                                   socket_path=True)
    if address != endpoint_address(path) \
            or doc["selection_identity"] != "host:" + address:
        raise _refuse("authority endpoint address/identity join failed")
    if doc["address_sha256"] != endpoint_address_digest(address):
        raise _refuse("authority endpoint address digest does not recompute")
    if doc["ambient_keys_checked"] != list(AMBIENT_DOCKER_KEYS) \
            or doc["ambient_keys_present"] != []:
        raise _refuse("authority did not prove every ambient selector absent")
    if doc["client_config_sha256"] != empty_config_digest():
        raise _refuse("authority empty-client-config digest does not recompute")
    return doc


def _validate_client(value: object, invoking_uid: int,
                     invoking_gid: int) -> dict:
    fields = (
        "selected_executable", "resolved_executable", "executable_sha256",
        "selected_executable_kind", "selected_executable_uid",
        "selected_executable_gid", "selected_executable_mode",
        "resolved_executable_uid", "resolved_executable_gid",
        "resolved_executable_mode", "path_chain_secure", "version",
        "api_version", "operating_system", "architecture")
    doc = _exact_keys(value, fields, "authority.client")
    selected = canonical_absolute_path(
        doc["selected_executable"], "authority.client.selected_executable")
    resolved = canonical_absolute_path(
        doc["resolved_executable"], "authority.client.resolved_executable")
    if doc["selected_executable_kind"] not in {"regular", "symlink"}:
        raise _refuse("authority client selected kind is unsupported")
    for key in ("selected_executable_uid", "selected_executable_gid",
                "resolved_executable_uid", "resolved_executable_gid"):
        _integer(doc[key], f"authority.client.{key}")
    if doc["selected_executable_uid"] not in {0, invoking_uid} \
            or doc["resolved_executable_uid"] not in {0, invoking_uid}:
        raise _refuse("Docker client is not owned by root or the invoking UID")
    selected_mode = _mode(doc["selected_executable_mode"],
                          "authority.client.selected_executable_mode")
    resolved_mode = _mode(doc["resolved_executable_mode"],
                          "authority.client.resolved_executable_mode")
    if doc["selected_executable_kind"] == "regular" \
            and int(selected_mode, 8) & 0o022:
        raise _refuse("selected Docker client is peer-writable")
    if int(resolved_mode, 8) & 0o022:
        raise _refuse("resolved Docker client is peer-writable")
    if doc["selected_executable_kind"] == "regular":
        if selected != resolved:
            raise _refuse(
                "regular selected Docker client does not equal resolved path")
        if any(doc[selected_key] != doc[resolved_key]
               for selected_key, resolved_key in (
                   ("selected_executable_uid", "resolved_executable_uid"),
                   ("selected_executable_gid", "resolved_executable_gid"),
                   ("selected_executable_mode", "resolved_executable_mode"))):
            raise _refuse(
                "regular selected/resolved Docker client facts disagree")
    elif selected == resolved:
        raise _refuse(
            "symlink-selected Docker client does not name a distinct target")
    resolved_bits = int(resolved_mode, 8)
    if doc["resolved_executable_uid"] == invoking_uid:
        executable = bool(resolved_bits & stat.S_IXUSR)
    elif doc["resolved_executable_gid"] == invoking_gid:
        executable = bool(resolved_bits & stat.S_IXGRP)
    else:
        executable = bool(resolved_bits & stat.S_IXOTH)
    if not executable:
        raise _refuse("resolved Docker client is not executable by invoking UID")
    if doc["path_chain_secure"] is not True:
        raise _refuse("Docker client path-chain proof is false")
    _sha256(doc["executable_sha256"], "authority.client.executable_sha256")
    for key in ("version", "api_version", "operating_system", "architecture"):
        _string(doc[key], f"authority.client.{key}")
    return doc


def _validate_daemon(value: object) -> dict:
    fields = (
        "id", "fingerprint_sha256", "server_version", "api_version",
        "minimum_api_version", "os_type", "operating_system",
        "architecture", "kernel", "security_options", "isolation",
        "rootless", "userns_remap", "storage_driver", "docker_root_dir",
        "cgroup_driver", "cgroup_version", "default_runtime")
    doc = _exact_keys(value, fields, "authority.daemon")
    for key in ("id", "server_version", "api_version", "minimum_api_version",
                "operating_system", "architecture", "kernel",
                "storage_driver"):
        _string(doc[key], f"authority.daemon.{key}")
    if doc["os_type"] != "linux" or doc["rootless"] is not True:
        raise _refuse("authority v1 requires a Linux rootless daemon")
    _boolean(doc["userns_remap"], "authority.daemon.userns_remap")
    options = doc["security_options"]
    if not isinstance(options, list) or any(not isinstance(v, str) or not v
                                            for v in options) \
            or options != sorted(set(options)) \
            or "name=rootless" not in options:
        raise _refuse("daemon security options are not sorted/unique rootless proof")
    observed_userns = any(
        value == "name=userns" or value.startswith("name=userns,")
        for value in options)
    if doc["userns_remap"] is not observed_userns:
        raise _refuse("daemon userns_remap does not match security options")
    for key in ("isolation", "cgroup_driver", "cgroup_version",
                "default_runtime"):
        if doc[key] is not None:
            _string(doc[key], f"authority.daemon.{key}")
    canonical_absolute_path(doc["docker_root_dir"],
                            "authority.daemon.docker_root_dir")
    expected = daemon_fingerprint(doc)
    if doc["fingerprint_sha256"] != expected:
        raise _refuse("daemon fingerprint does not recompute")
    return doc


def _validate_adapter(value: object, *, endpoint: dict, daemon: dict) -> dict:
    fields = (
        "schema", "invoking_uid", "invoking_gid", "selected_socket_path",
        "resolved_socket_path", "socket_uid", "socket_gid", "socket_mode",
        "socket_acl", "private_parent_path", "private_parent_uid",
        "private_parent_gid", "private_parent_mode", "private_parent_acl",
        "docker_root_resolved_path", "docker_root_uid", "docker_root_gid",
        "docker_root_mode", "docker_root_acl", "rootless_security_option",
        "socket_exclusive", "data_root_owned_by_invoking_uid")
    doc = _exact_keys(value, fields, "authority.adapter")
    if doc["schema"] != ADAPTER_SCHEMA:
        raise _refuse("authority adapter schema is unsupported")
    uid = _integer(doc["invoking_uid"], "authority.adapter.invoking_uid",
                   minimum=1)
    _integer(doc["invoking_gid"], "authority.adapter.invoking_gid")
    for key in ("socket_uid", "socket_gid", "private_parent_uid",
                "private_parent_gid", "docker_root_uid", "docker_root_gid"):
        _integer(doc[key], f"authority.adapter.{key}")
    selected = canonical_absolute_path(
        doc["selected_socket_path"], "authority.adapter.selected_socket_path",
        socket_path=True)
    resolved = canonical_absolute_path(
        doc["resolved_socket_path"], "authority.adapter.resolved_socket_path",
        socket_path=True)
    parent = canonical_absolute_path(
        doc["private_parent_path"], "authority.adapter.private_parent_path")
    root = canonical_absolute_path(
        doc["docker_root_resolved_path"],
        "authority.adapter.docker_root_resolved_path")
    if selected != resolved \
            or endpoint["address"] != "unix://" + selected \
            or daemon["docker_root_dir"] != root:
        raise _refuse("authority endpoint/socket/data-root join failed")
    if any(doc[key] != uid for key in
           ("socket_uid", "private_parent_uid", "docker_root_uid")):
        raise _refuse("authority adapter resources are not invoking-UID owned")
    for key in ("socket_mode", "private_parent_mode", "docker_root_mode"):
        _mode(doc[key], f"authority.adapter.{key}", owner_only=True)
    for key in ("socket_acl", "private_parent_acl", "docker_root_acl"):
        if doc[key] != "absent":
            raise _refuse(f"authority.adapter.{key} does not prove ACL absence")
    if doc["rootless_security_option"] != "name=rootless" \
            or doc["rootless_security_option"] not in daemon["security_options"]:
        raise _refuse("authority rootless option join failed")
    if doc["socket_exclusive"] is not True \
            or doc["data_root_owned_by_invoking_uid"] is not True:
        raise _refuse("authority adapter isolation proof is false")
    if parent != os.path.dirname(selected) and not selected.startswith(parent + "/"):
        raise _refuse("authority private parent does not contain the socket")
    return doc


def validate_authority_document(value: object, *,
                                current_source: bool = True) -> dict:
    fields = (
        "schema", "captured_at_utc", "verifier", "authority_class",
        "tenant_scope", "canonical_eligible", "refusal_reasons", "endpoint",
        "client", "daemon", "adapter", "digest")
    doc = _exact_keys(value, fields, "Docker authority")
    if doc["schema"] != AUTHORITY_SCHEMA \
            or doc["authority_class"] != "rootless_current_user" \
            or doc["tenant_scope"] != "current_user" \
            or doc["canonical_eligible"] is not True \
            or doc["refusal_reasons"] != []:
        raise _refuse("authority v1 is not exact eligible current-user rootless")
    _timestamp(doc["captured_at_utc"], "authority.captured_at_utc")
    _validate_verifier(doc["verifier"], current_source=current_source)
    endpoint = _validate_endpoint(doc["endpoint"])
    adapter_shape = _exact_keys(doc["adapter"], (
        "schema", "invoking_uid", "invoking_gid", "selected_socket_path",
        "resolved_socket_path", "socket_uid", "socket_gid", "socket_mode",
        "socket_acl", "private_parent_path", "private_parent_uid",
        "private_parent_gid", "private_parent_mode", "private_parent_acl",
        "docker_root_resolved_path", "docker_root_uid", "docker_root_gid",
        "docker_root_mode", "docker_root_acl", "rootless_security_option",
        "socket_exclusive", "data_root_owned_by_invoking_uid"),
        "authority.adapter")
    invoking_uid = _integer(adapter_shape["invoking_uid"],
                            "authority.adapter.invoking_uid", minimum=1)
    invoking_gid = _integer(adapter_shape["invoking_gid"],
                            "authority.adapter.invoking_gid")
    _validate_client(doc["client"], invoking_uid, invoking_gid)
    daemon = _validate_daemon(doc["daemon"])
    _validate_adapter(doc["adapter"], endpoint=endpoint, daemon=daemon)
    _sha256(doc["digest"], "authority.digest")
    if semantic_digest(doc) != doc["digest"]:
        raise _refuse("authority semantic digest does not recompute")
    return doc


def validate_pool_document(value: object, *, verify_files: bool = False) -> dict:
    doc = _exact_keys(value, ("schema", "workers", "database", "network",
                              "digest"), "execution pool")
    if doc["schema"] != POOL_SCHEMA:
        raise _refuse("execution pool schema is unsupported")
    workers = doc["workers"]
    if not isinstance(workers, list) or not workers:
        raise _refuse("execution pool has no workers")
    paths, hashes, names = set(), set(), set()
    for expected_index, item in enumerate(workers):
        worker = _exact_keys(item, ("index", "worker_spec_path",
                                    "worker_spec_sha256", "container_name"),
                             f"execution pool worker {expected_index}")
        actual_index = _integer(
            worker["index"], f"execution pool worker {expected_index}.index")
        if actual_index != expected_index:
            raise _refuse("execution pool worker indices are not contiguous/order")
        path = canonical_absolute_path(worker["worker_spec_path"],
                                       "pool worker spec path")
        digest = _sha256(worker["worker_spec_sha256"],
                         "pool worker spec SHA-256")
        name = _string(worker["container_name"], "pool worker container name")
        if path in paths or digest in hashes or name in names:
            raise _refuse("execution pool worker paths/hashes/names are not unique")
        paths.add(path)
        hashes.add(digest)
        names.add(name)
        if verify_files:
            raw = _read_trusted_bytes(path, "worker spec")
            if hashlib.sha256(raw).hexdigest() != digest:
                raise _refuse("pool worker spec raw hash does not recompute")
            loads_exact_json(raw, label="worker spec")
    database = doc["database"]
    if database is not None:
        db = _exact_keys(database, ("role", "container_name"), "pool database")
        if db["role"] != "database":
            raise _refuse("pool database role is invalid")
        db_name = _string(db["container_name"], "pool database container name")
        if db_name in names:
            raise _refuse("pool database shares a worker container name")
    network = _exact_keys(doc["network"], ("mode", "name"), "pool network")
    if database is None:
        if network != {"mode": "none", "name": "none"}:
            raise _refuse("no-database persistent pool must use network none")
    elif network["mode"] != "dedicated_internal" \
            or not isinstance(network["name"], str) or not network["name"]:
        raise _refuse("database persistent pool requires named internal network")
    _sha256(doc["digest"], "pool.digest")
    if semantic_digest(doc) != doc["digest"]:
        raise _refuse("execution pool digest does not recompute")
    return doc


def _validate_attachment(value: object, label: str) -> dict:
    doc = _exact_keys(value, ("name", "id"), label)
    _string(doc["name"], label + ".name")
    _object_id(doc["id"], label + ".id")
    return doc


def _validate_container(value: object, label: str) -> dict:
    fields = ("name", "id", "image_id", "running", "host_network_mode",
              "network_attachments")
    doc = _exact_keys(value, fields, label)
    _string(doc["name"], label + ".name")
    _object_id(doc["id"], label + ".id")
    _image_id(doc["image_id"], label + ".image_id")
    if doc["running"] is not True:
        raise _refuse(f"{label} is not running")
    _string(doc["host_network_mode"], label + ".host_network_mode")
    attachments = doc["network_attachments"]
    if not isinstance(attachments, list) or len(attachments) != 1:
        raise _refuse(f"{label} does not have exactly one raw attachment")
    _validate_attachment(attachments[0], label + ".network_attachments[0]")
    return doc


def _member_sort_key(member: dict):
    index = member["worker_index"]
    return (member["role"], -1 if index is None else index,
            member["name"], member["id"])


def _validate_member(value: object, label: str) -> dict:
    fields = ("role", "worker_index", "name", "id", "image_id", "running",
              "host_network_mode", "network_attachments")
    doc = _exact_keys(value, fields, label)
    if doc["role"] not in {"worker", "database"}:
        raise _refuse(f"{label} role is invalid")
    if doc["role"] == "worker":
        _integer(doc["worker_index"], label + ".worker_index")
    elif doc["worker_index"] is not None:
        raise _refuse(f"{label} database worker_index is not null")
    _validate_container({key: doc[key] for key in (
        "name", "id", "image_id", "running", "host_network_mode",
        "network_attachments")}, label)
    return doc


def validate_binding_document(value: object) -> dict:
    fields = ("schema", "captured_at_utc", "authority", "pool",
              "worker_index", "worker_spec_sha256", "container",
              "network_policy", "egress_probe", "digest")
    doc = _exact_keys(value, fields, "execution binding")
    if doc["schema"] != BINDING_SCHEMA:
        raise _refuse("execution binding schema is unsupported")
    _timestamp(doc["captured_at_utc"], "binding.captured_at_utc")
    _validate_reference(doc["authority"], "binding.authority")
    pool = validate_pool_document(doc["pool"])
    index = _integer(doc["worker_index"], "binding.worker_index")
    if index >= len(pool["workers"]):
        raise _refuse("binding worker index is outside its pool")
    pool_worker = pool["workers"][index]
    if doc["worker_spec_sha256"] != pool_worker["worker_spec_sha256"]:
        raise _refuse("binding worker spec hash differs from pool entry")
    container = _validate_container(doc["container"], "binding.container")
    if container["name"] != pool_worker["container_name"]:
        raise _refuse("binding container differs from pool entry")
    policy = doc["network_policy"]
    if not isinstance(policy, dict) or policy.get("mode") not in {
            "none", "dedicated_internal"}:
        raise _refuse("binding network policy mode is unsupported")
    common = ("mode", "name", "id", "driver", "scope", "internal",
              "ingress", "attachable", "expected_members",
              "observed_members")
    policy = _exact_keys(policy, common, "binding.network_policy")
    network_id = _object_id(policy["id"], "binding.network_policy.id")
    for field in ("internal", "ingress", "attachable"):
        _boolean(policy[field], f"binding.network_policy.{field}")
    probe = _exact_keys(doc["egress_probe"],
                        ("required", "status", "target", "evidence_sha256"),
                        "binding.egress_probe")
    _boolean(probe["required"], "binding.egress_probe.required")
    if probe != {"required": False, "status": "not_required", "target": None,
                 "evidence_sha256": None}:
        raise _refuse("binding egress-probe record is not exact not_required")
    if policy["mode"] == "none":
        expected_policy = {
            "mode": "none", "name": "none", "id": network_id,
            "driver": "null", "scope": "local", "internal": False,
            "ingress": False, "attachable": False,
            "expected_members": [], "observed_members": []}
        if policy != expected_policy \
                or pool["network"] != {"mode": "none", "name": "none"} \
                or container["host_network_mode"] != "none" \
                or container["network_attachments"] != [
                    {"name": "none", "id": network_id}]:
            raise _refuse("binding none-network raw projection is incoherent")
    else:
        name = _string(policy["name"], "binding.network_policy.name")
        if pool["network"] != {"mode": "dedicated_internal", "name": name} \
                or policy["driver"] != "bridge" \
                or policy["scope"] != "local" \
                or policy["internal"] is not True \
                or policy["ingress"] is not False \
                or policy["attachable"] is not False:
            raise _refuse("binding dedicated network adapter facts are invalid")
        expected = policy["expected_members"]
        observed = policy["observed_members"]
        if not isinstance(expected, list) or not expected \
                or expected != observed:
            raise _refuse("binding expected/observed membership is not exact")
        for pos, member in enumerate(expected):
            _validate_member(member, f"binding member {pos}")
            if member["host_network_mode"] != name \
                    or member["network_attachments"] != [
                        {"name": name, "id": network_id}]:
                raise _refuse("binding member network join failed")
        if expected != sorted(expected, key=_member_sort_key):
            raise _refuse("binding members are not canonically sorted")
        if len({_member_sort_key(member) for member in expected}) != len(expected):
            raise _refuse("binding members are not unique")
        worker_member_rows = [m for m in expected if m["role"] == "worker"]
        if len(worker_member_rows) != len(pool["workers"]) \
                or len({m["worker_index"] for m in worker_member_rows}) \
                != len(worker_member_rows) \
                or len({m["name"] for m in expected}) != len(expected) \
                or len({m["id"] for m in expected}) != len(expected):
            raise _refuse(
                "binding members do not have unique pool indices/names/ids")
        worker_members = {m["worker_index"]: m for m in worker_member_rows}
        database_members = [m for m in expected if m["role"] == "database"]
        if set(worker_members) != set(range(len(pool["workers"]))) \
                or len(database_members) != (1 if pool["database"] else 0):
            raise _refuse("binding members do not cover the complete pool")
        for worker_index, worker in enumerate(pool["workers"]):
            if worker_members[worker_index]["name"] != worker["container_name"]:
                raise _refuse("binding member name differs from pool worker")
        if pool["database"] and database_members[0]["name"] \
                != pool["database"]["container_name"]:
            raise _refuse("binding database member differs from pool")
        current_member = worker_members[index]
        if any(container[key] != current_member[key] for key in (
                "name", "id", "image_id", "running", "host_network_mode",
                "network_attachments")):
            raise _refuse("binding top container differs from pool member snapshot")
    _sha256(doc["digest"], "binding.digest")
    if semantic_digest(doc) != doc["digest"]:
        raise _refuse("execution binding digest does not recompute")
    return doc


def _selected_client_facts(path: str) -> dict:
    selected = canonical_absolute_path(path, "selected Docker executable")
    _secure_directory_chain(selected)
    try:
        selected_info = os.lstat(selected)
    except OSError as exc:
        raise _refuse("selected Docker executable is unavailable") from exc
    if stat.S_ISREG(selected_info.st_mode):
        kind = "regular"
        resolved = selected
    elif stat.S_ISLNK(selected_info.st_mode):
        kind = "symlink"
        cursor = selected
        seen = set()
        for _depth in range(40):
            if cursor in seen:
                raise _refuse("Docker executable symlink chain loops")
            seen.add(cursor)
            _secure_directory_chain(cursor)
            try:
                link_info = os.lstat(cursor)
            except OSError as exc:
                raise _refuse("Docker executable symlink target is unavailable") from exc
            if not stat.S_ISLNK(link_info.st_mode):
                break
            if link_info.st_uid not in {0, os.geteuid()}:
                raise _refuse("Docker executable symlink is not root/current-UID owned")
            target = os.readlink(cursor)
            if not os.path.isabs(target):
                target = os.path.join(os.path.dirname(cursor), target)
            cursor = canonical_absolute_path(
                os.path.normpath(target), "Docker executable symlink target")
        else:
            raise _refuse("Docker executable symlink chain is too deep")
        resolved = cursor
        if os.path.realpath(selected) != resolved:
            raise _refuse("Docker executable symlink resolution is unstable")
        _secure_directory_chain(resolved)
    else:
        raise _refuse("selected Docker executable is not regular or a symlink")
    try:
        resolved_info = os.lstat(resolved)
    except OSError as exc:
        raise _refuse("resolved Docker executable is unavailable") from exc
    if stat.S_ISLNK(resolved_info.st_mode) or not stat.S_ISREG(resolved_info.st_mode):
        raise _refuse("resolved Docker executable is not a regular file")
    uid = os.geteuid()
    gid = os.getegid()
    if selected_info.st_uid not in {0, uid} or resolved_info.st_uid not in {0, uid}:
        raise _refuse("Docker executable is not root/current-UID owned")
    if kind == "regular" and stat.S_IMODE(selected_info.st_mode) & 0o022:
        raise _refuse("selected Docker executable is peer-writable")
    if stat.S_IMODE(resolved_info.st_mode) & 0o022:
        raise _refuse("resolved Docker executable is peer-writable")
    if resolved_info.st_uid == uid and resolved_info.st_nlink != 1:
        raise _refuse(
            "current-UID Docker executable has multiple hard-link names")
    resolved_bits = stat.S_IMODE(resolved_info.st_mode)
    if resolved_info.st_uid == uid:
        executable = bool(resolved_bits & stat.S_IXUSR)
    elif resolved_info.st_gid == gid:
        executable = bool(resolved_bits & stat.S_IXGRP)
    else:
        executable = bool(resolved_bits & stat.S_IXOTH)
    if not executable:
        raise _refuse(
            "resolved Docker executable is not executable by the invoking "
            "UID under the v1 owner/primary-group/other rule")
    return {
        "selected_executable": selected,
        "resolved_executable": resolved,
        "executable_sha256": sha256_file(resolved),
        "selected_executable_kind": kind,
        "selected_executable_uid": selected_info.st_uid,
        "selected_executable_gid": selected_info.st_gid,
        "selected_executable_mode": _mode_text(selected_info.st_mode),
        "resolved_executable_uid": resolved_info.st_uid,
        "resolved_executable_gid": resolved_info.st_gid,
        "resolved_executable_mode": _mode_text(resolved_info.st_mode),
        "path_chain_secure": True,
    }


def _socket_and_parent_facts(path: str) -> dict:
    selected = canonical_absolute_path(path, "selected Docker socket",
                                       socket_path=True)
    _secure_directory_chain(selected)
    try:
        info = os.lstat(selected)
    except OSError as exc:
        raise _refuse("selected Docker socket is unavailable") from exc
    uid = os.geteuid()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode) \
            or info.st_nlink != 1 or os.path.realpath(selected) != selected:
        raise _refuse("selected Docker endpoint is not a non-symlink socket")
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077 \
            or not _acl_absent(selected):
        raise _refuse("selected Docker socket is not current-UID private")
    parent = os.path.dirname(selected)
    private = None
    while True:
        parent_info = os.lstat(parent)
        if parent_info.st_uid == uid \
                and not stat.S_IMODE(parent_info.st_mode) & 0o077 \
                and _acl_absent(parent, directory=True):
            private = (parent, parent_info)
            break
        if parent == "/":
            break
        parent = os.path.dirname(parent)
    if private is None:
        raise _refuse("Docker socket has no current-UID private ancestor")
    return {
        "selected_socket_path": selected,
        "resolved_socket_path": selected,
        "socket_uid": info.st_uid,
        "socket_gid": info.st_gid,
        "socket_mode": _mode_text(info.st_mode),
        "socket_acl": "absent",
        "private_parent_path": private[0],
        "private_parent_uid": private[1].st_uid,
        "private_parent_gid": private[1].st_gid,
        "private_parent_mode": _mode_text(private[1].st_mode),
        "private_parent_acl": "absent",
    }


def _docker_root_facts(path: str) -> dict:
    reported = canonical_absolute_path(path, "Docker root directory")
    resolved = canonical_absolute_path(os.path.realpath(reported),
                                       "resolved Docker root directory")
    _secure_directory_chain(resolved)
    try:
        info = os.lstat(resolved)
    except OSError as exc:
        raise _refuse("Docker root directory is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) \
            or info.st_uid != os.geteuid() \
            or stat.S_IMODE(info.st_mode) & 0o077 \
            or not _acl_absent(resolved, directory=True):
        raise _refuse("Docker root directory is not current-UID private")
    return {
        "docker_root_resolved_path": resolved,
        "docker_root_uid": info.st_uid,
        "docker_root_gid": info.st_gid,
        "docker_root_mode": _mode_text(info.st_mode),
        "docker_root_acl": "absent",
    }


def _docker_json(client: str, address: str, config_dir: str,
                 argv: list[str]) -> dict:
    if os.listdir(config_dir):
        raise _refuse("isolated Docker client configuration is no longer empty")
    command = [client, "--config", config_dir, "--host", address,
               *argv, "--format", "{{json .}}"]
    clean_env = dict(os.environ)
    for key in AMBIENT_DOCKER_KEYS:
        clean_env.pop(key, None)
    try:
        cp = subprocess.run(command, capture_output=True, timeout=60,
                            check=False, env=clean_env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _refuse(f"Docker read-only {argv[0]} probe failed") from exc
    if cp.returncode != 0:
        raise _refuse(f"Docker read-only {argv[0]} probe returned "
                      f"status {cp.returncode}")
    value = loads_exact_json(cp.stdout, label=f"Docker {argv[0]} probe")
    if not isinstance(value, dict):
        raise _refuse(f"Docker {argv[0]} probe did not return an object")
    return value


def _pick(mapping: Mapping[str, object], names: Iterable[str], label: str,
          *, nullable: bool = False) -> Optional[str]:
    for name in names:
        value = mapping.get(name)
        if isinstance(value, str) and value:
            return value
    if nullable:
        return None
    raise _refuse(f"Docker probe omitted stable field {label}")


def _probe_docker(client_path: str, address: str) -> tuple[dict, dict]:
    with tempfile.TemporaryDirectory(prefix="r2t-docker-config.") as cfg:
        os.chmod(cfg, 0o700)
        version = _docker_json(client_path, address, cfg, ["version"])
        info = _docker_json(client_path, address, cfg, ["info"])
    client = version.get("Client")
    server = version.get("Server")
    if not isinstance(client, dict) or not isinstance(server, dict):
        raise _refuse("Docker version probe omitted Client/Server objects")
    client_fields = {
        "version": _pick(client, ("Version",), "client version"),
        "api_version": _pick(client, ("ApiVersion",), "client API version"),
        "operating_system": _pick(client, ("Os", "OS"), "client OS"),
        "architecture": _pick(client, ("Arch",), "client architecture"),
    }
    security = info.get("SecurityOptions")
    if not isinstance(security, list) or any(not isinstance(v, str) or not v
                                             for v in security):
        raise _refuse("Docker info omitted exact SecurityOptions")
    security = sorted(set(security))
    rootless = "name=rootless" in security
    daemon = {
        "id": _pick(info, ("ID", "Id"), "daemon ID"),
        "fingerprint_sha256": "0" * 64,
        "server_version": _pick(server, ("Version",), "server version"),
        "api_version": _pick(server, ("ApiVersion",), "server API version"),
        "minimum_api_version": _pick(
            server, ("MinAPIVersion",), "minimum server API version"),
        "os_type": _pick(info, ("OSType",), "daemon OS type"),
        "operating_system": _pick(
            info, ("OperatingSystem",), "daemon operating system"),
        "architecture": _pick(info, ("Architecture",), "daemon architecture"),
        "kernel": _pick(info, ("KernelVersion",), "daemon kernel"),
        "security_options": security,
        "isolation": _pick(info, ("Isolation",), "daemon isolation",
                           nullable=True),
        "rootless": rootless,
        "userns_remap": any(v == "name=userns" or v.startswith("name=userns,")
                            for v in security),
        "storage_driver": _pick(info, ("Driver",), "storage driver"),
        "docker_root_dir": canonical_absolute_path(
            os.path.realpath(_pick(info, ("DockerRootDir",), "Docker root")),
            "Docker root directory"),
        "cgroup_driver": _pick(info, ("CgroupDriver",), "cgroup driver",
                               nullable=True),
        "cgroup_version": _pick(info, ("CgroupVersion",), "cgroup version",
                                nullable=True),
        "default_runtime": _pick(info, ("DefaultRuntime",), "default runtime",
                                 nullable=True),
    }
    daemon["fingerprint_sha256"] = daemon_fingerprint(daemon)
    return client_fields, daemon


def _current_adapter(authority: dict) -> None:
    refuse_ambient_docker()
    adapter = authority["adapter"]
    if os.geteuid() != adapter["invoking_uid"] \
            or os.getegid() != adapter["invoking_gid"]:
        raise _refuse("authority belongs to another invoking UID/GID")
    socket_facts = _socket_and_parent_facts(adapter["selected_socket_path"])
    for key, value in socket_facts.items():
        if adapter[key] != value:
            raise _refuse(f"live socket fact changed: {key}")
    root_facts = _docker_root_facts(adapter["docker_root_resolved_path"])
    for key, value in root_facts.items():
        if adapter[key] != value:
            raise _refuse(f"live Docker-root fact changed: {key}")
    client_facts = _selected_client_facts(
        authority["client"]["selected_executable"])
    for key, value in client_facts.items():
        if authority["client"][key] != value:
            raise _refuse(f"live Docker-client fact changed: {key}")


def load_authority(path: str, *, live: bool = False) -> dict:
    document, reference = evidence_reference(
        os.path.abspath(path), expected_schema=AUTHORITY_SCHEMA,
        validator=lambda value: validate_authority_document(
            value, current_source=True), label="Docker authority")
    _current_adapter(document)
    if live:
        client_fields, daemon = _probe_docker(
            document["client"]["selected_executable"],
            document["endpoint"]["address"])
        for key, value in client_fields.items():
            if document["client"][key] != value:
                raise _refuse(f"Docker client probe changed: {key}")
        if document["daemon"] != daemon:
            raise _refuse("Docker daemon fingerprint/facts changed")
        # Re-read the trust anchor after the live probe to close simple races.
        _document2, reference2 = evidence_reference(
            reference["path"], expected_schema=AUTHORITY_SCHEMA,
            validator=lambda value: validate_authority_document(
                value, current_source=True), label="Docker authority")
        if reference2 != reference:
            raise _refuse("Docker authority changed during live revalidation")
    return document


def authority_reference(path: str, *, live: bool = False) -> tuple[dict, dict]:
    document = load_authority(path, live=live)
    document2, reference = evidence_reference(
        os.path.abspath(path), expected_schema=AUTHORITY_SCHEMA,
        validator=lambda value: validate_authority_document(
            value, current_source=True), label="Docker authority")
    if document2 != document:
        raise _refuse("Docker authority changed while its reference was built")
    return document2, reference


def capture_authority(*, docker_host: str, docker_cli: str, out: str) -> dict:
    """Inspect one explicit Linux rootless endpoint and mint eligible v1."""
    refuse_ambient_docker()
    out = _refuse_authority_output_in_verifier_worktree(out)
    out = _preflight_evidence_output_target(out)
    if os.geteuid() == 0:
        raise _refuse("authority v1 requires a non-root invoking UID")
    # Source review and the immutable output destination are preconditions,
    # not facts to discover after contacting a daemon.  Keep both ahead of
    # even the read-only version/info eligibility probes.
    verifier = _verifier_git_identity()
    if docker_host.startswith("unix://"):
        socket_path = docker_host[len("unix://"):]
    else:
        socket_path = docker_host
    socket_facts = _socket_and_parent_facts(socket_path)
    client_facts = _selected_client_facts(docker_cli)
    address = endpoint_address(socket_facts["selected_socket_path"])
    client_probe, daemon = _probe_docker(
        client_facts["selected_executable"], address)
    if daemon["os_type"] != "linux" or daemon["rootless"] is not True \
            or "name=rootless" not in daemon["security_options"]:
        raise _refuse("selected daemon is not exact Linux current-user rootless")
    root_facts = _docker_root_facts(daemon["docker_root_dir"])
    adapter = {
        "schema": ADAPTER_SCHEMA,
        "invoking_uid": os.geteuid(),
        "invoking_gid": os.getegid(),
        **socket_facts,
        **root_facts,
        "rootless_security_option": "name=rootless",
        "socket_exclusive": True,
        "data_root_owned_by_invoking_uid": True,
    }
    document = {
        "schema": AUTHORITY_SCHEMA,
        "captured_at_utc": utc_now(),
        "verifier": verifier,
        "authority_class": "rootless_current_user",
        "tenant_scope": "current_user",
        "canonical_eligible": True,
        "refusal_reasons": [],
        "endpoint": {
            "selection_source": "explicit_cli",
            "selection_identity": "host:" + address,
            "transport": "unix",
            "address": address,
            "address_sha256": endpoint_address_digest(address),
            "ambient_keys_checked": list(AMBIENT_DOCKER_KEYS),
            "ambient_keys_present": [],
            "client_config_mode": "isolated_empty",
            "client_config_sha256": empty_config_digest(),
        },
        "client": {**client_facts, **client_probe},
        "daemon": daemon,
        "adapter": adapter,
        "digest": "0" * 64,
    }
    document["digest"] = semantic_digest(document)
    validate_authority_document(document, current_source=True)
    _current_adapter(document)
    write_evidence_no_clobber(out, document)
    return document


def _preflight_evidence_output_target(path: str) -> str:
    """Prove a new evidence target is private and currently unoccupied."""
    path = canonical_absolute_path(path, "evidence output path")
    if os.path.lexists(path):
        raise _refuse(f"evidence output already exists: {path}")
    _secure_directory_chain(os.path.dirname(path), include_leaf=True)
    return path


def write_evidence_no_clobber(path: str, document: dict) -> None:
    """Durably create one owner-private JSON file without replacing a target."""
    path = _preflight_evidence_output_target(path)
    parent = os.path.dirname(path)
    payload = json.dumps(document, indent=1, sort_keys=True,
                         ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"
    fd = -1
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".r2t-evidence.", dir=parent)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as fh:
            fd = -1
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.link(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as exc:
        raise _refuse(f"evidence output already exists: {path}") from exc
    except OSError as exc:
        raise _refuse(f"cannot create evidence output {path}: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _fixture_authority() -> dict:
    uid = 1001
    address = "unix:///run/user/1001/r2t/docker.sock"
    daemon = {
        "id": "fixture-daemon", "fingerprint_sha256": "0" * 64,
        "server_version": "1", "api_version": "1.1",
        "minimum_api_version": "1.0", "os_type": "linux",
        "operating_system": "Fixture Linux", "architecture": "amd64",
        "kernel": "6.0", "security_options": ["name=rootless"],
        "isolation": None, "rootless": True, "userns_remap": False,
        "storage_driver": "overlay2", "docker_root_dir": "/private/docker",
        "cgroup_driver": "systemd", "cgroup_version": "2",
        "default_runtime": "runc"}
    daemon["fingerprint_sha256"] = daemon_fingerprint(daemon)
    doc = {
        "schema": AUTHORITY_SCHEMA, "captured_at_utc": "2026-08-06T00:00:00Z",
        "verifier": {"name": VERIFIER_NAME, "version": VERIFIER_VERSION,
                     "source_path": VERIFIER_SOURCE_PATH,
                     "source_sha256": "1" * 64, "git_commit": "2" * 40,
                     "git_tree_clean": True},
        "authority_class": "rootless_current_user",
        "tenant_scope": "current_user", "canonical_eligible": True,
        "refusal_reasons": [],
        "endpoint": {"selection_source": "explicit_cli",
                     "selection_identity": "host:" + address,
                     "transport": "unix", "address": address,
                     "address_sha256": endpoint_address_digest(address),
                     "ambient_keys_checked": list(AMBIENT_DOCKER_KEYS),
                     "ambient_keys_present": [],
                     "client_config_mode": "isolated_empty",
                     "client_config_sha256": empty_config_digest()},
        "client": {"selected_executable": "/usr/bin/docker",
                   "resolved_executable": "/usr/bin/docker",
                   "executable_sha256": "3" * 64,
                   "selected_executable_kind": "regular",
                   "selected_executable_uid": 0, "selected_executable_gid": 0,
                   "selected_executable_mode": "0755",
                   "resolved_executable_uid": 0, "resolved_executable_gid": 0,
                   "resolved_executable_mode": "0755",
                   "path_chain_secure": True, "version": "1",
                   "api_version": "1.1", "operating_system": "linux",
                   "architecture": "amd64"},
        "daemon": daemon,
        "adapter": {"schema": ADAPTER_SCHEMA, "invoking_uid": uid,
                    "invoking_gid": uid,
                    "selected_socket_path": "/run/user/1001/r2t/docker.sock",
                    "resolved_socket_path": "/run/user/1001/r2t/docker.sock",
                    "socket_uid": uid, "socket_gid": uid,
                    "socket_mode": "0600", "socket_acl": "absent",
                    "private_parent_path": "/run/user/1001/r2t",
                    "private_parent_uid": uid, "private_parent_gid": uid,
                    "private_parent_mode": "0700",
                    "private_parent_acl": "absent",
                    "docker_root_resolved_path": "/private/docker",
                    "docker_root_uid": uid, "docker_root_gid": uid,
                    "docker_root_mode": "0700", "docker_root_acl": "absent",
                    "rootless_security_option": "name=rootless",
                    "socket_exclusive": True,
                    "data_root_owned_by_invoking_uid": True},
        "digest": "0" * 64}
    doc["digest"] = semantic_digest(doc)
    return doc


def _fixture_pool(*, database: bool = False) -> dict:
    doc = {
        "schema": POOL_SCHEMA,
        "workers": [{"index": 0, "worker_spec_path": "/private/worker0.json",
                     "worker_spec_sha256": "4" * 64,
                     "container_name": "worker0"}],
        "database": ({"role": "database", "container_name": "database"}
                     if database else None),
        "network": ({"mode": "dedicated_internal", "name": "r2t-internal"}
                    if database else {"mode": "none", "name": "none"}),
        "digest": "0" * 64}
    doc["digest"] = semantic_digest(doc)
    return doc


def _fixture_binding(*, database: bool = False) -> dict:
    pool = _fixture_pool(database=database)
    authority = {"path": "/private/authority.json",
                 "file_sha256": "a" * 64, "digest": "b" * 64}
    worker_id = "5" * 64
    worker_image = "sha256:" + "6" * 64
    network_id = "7" * 64
    if database:
        attachment = [{"name": "r2t-internal", "id": network_id}]
        database_member = {
            "role": "database", "worker_index": None, "name": "database",
            "id": "8" * 64, "image_id": "sha256:" + "9" * 64,
            "running": True, "host_network_mode": "r2t-internal",
            "network_attachments": attachment}
        worker_member = {
            "role": "worker", "worker_index": 0, "name": "worker0",
            "id": worker_id, "image_id": worker_image, "running": True,
            "host_network_mode": "r2t-internal",
            "network_attachments": attachment}
        members = [database_member, worker_member]
        policy = {
            "mode": "dedicated_internal", "name": "r2t-internal",
            "id": network_id, "driver": "bridge", "scope": "local",
            "internal": True, "ingress": False, "attachable": False,
            "expected_members": members, "observed_members": members}
        host_mode = "r2t-internal"
        attachments = attachment
    else:
        policy = {
            "mode": "none", "name": "none", "id": network_id,
            "driver": "null", "scope": "local", "internal": False,
            "ingress": False, "attachable": False,
            "expected_members": [], "observed_members": []}
        host_mode = "none"
        attachments = [{"name": "none", "id": network_id}]
    doc = {
        "schema": BINDING_SCHEMA, "captured_at_utc": "2026-08-06T00:00:00Z",
        "authority": authority, "pool": pool, "worker_index": 0,
        "worker_spec_sha256": "4" * 64,
        "container": {"name": "worker0", "id": worker_id,
                      "image_id": worker_image, "running": True,
                      "host_network_mode": host_mode,
                      "network_attachments": attachments},
        "network_policy": policy,
        "egress_probe": {"required": False, "status": "not_required",
                         "target": None, "evidence_sha256": None},
        "digest": "0" * 64}
    doc["digest"] = semantic_digest(doc)
    return doc


def selftest() -> int:
    import contextlib
    import io
    from unittest.mock import patch

    failures = []

    def check(name, condition):
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}")
        if not condition:
            failures.append(name)

    def refused(fn) -> bool:
        try:
            fn()
        except DockerAuthorityRefused:
            return True
        return False

    vector = {"schema": "r2t.example/v1", "value": "\N{SNOWMAN}",
              "digest": "ignored"}
    check("semantic digest golden vector",
          semantic_digest(vector)
          == "ea793c5038e281646274162f7dd5dbcd7961d7e58b9a44dd6076b6500a111ef6")
    check("duplicate JSON keys refuse",
          refused(lambda: loads_exact_json('{"a":1,"a":2}')))
    check("socket URI metacharacters refuse",
          all(refused(lambda value=value: endpoint_address(value))
              for value in ("/tmp/a?b", "/tmp/a#b", "/tmp/a%b", "/tmp/a b")))
    authority = _fixture_authority()
    check("closed authority fixture validates",
          validate_authority_document(authority, current_source=False)
          is authority)
    # Only transport is mocked: exercise real temporary allocation, empty
    # config admission, explicit endpoint argv, and response interpretation.
    with tempfile.TemporaryDirectory(prefix="authority-tmp.") as config_root, \
            patch.dict(os.environ, {"TMPDIR": config_root}), \
            patch.object(tempfile, "tempdir", None):
        probe_dirs = []
        probe_argv = []
        private_configs = []
        client = authority["client"]
        daemon = authority["daemon"]
        version = {"Client": {"Version": client["version"],
                              "ApiVersion": client["api_version"],
                              "Os": client["operating_system"],
                              "Arch": client["architecture"]},
                   "Server": {"Version": daemon["server_version"],
                              "ApiVersion": daemon["api_version"],
                              "MinAPIVersion": daemon["minimum_api_version"]}}
        info = {name: daemon[key] for name, key in (
            ("ID", "id"), ("OSType", "os_type"), ("OperatingSystem", "operating_system"),
            ("Architecture", "architecture"), ("KernelVersion", "kernel"),
            ("SecurityOptions", "security_options"), ("Isolation", "isolation"),
            ("Driver", "storage_driver"), ("DockerRootDir", "docker_root_dir"),
            ("CgroupDriver", "cgroup_driver"), ("CgroupVersion", "cgroup_version"),
            ("DefaultRuntime", "default_runtime"))}

        def fixture_probe(command, **_kwargs):
            cfg = command[2]
            probe_dirs.append(cfg)
            probe_argv.append(command)
            facts = os.stat(cfg)
            private_configs.append(os.path.dirname(cfg) == config_root
                                   and stat.S_IMODE(facts.st_mode) == 0o700
                                   and facts.st_uid == os.geteuid()
                                   and os.listdir(cfg) == [])
            return subprocess.CompletedProcess(command, 0, json.dumps(
                version if command[5] == "version" else info).encode(), b"")

        with patch.object(subprocess, "run", side_effect=fixture_probe):
            got_client, got_daemon = _probe_docker(
                "/usr/bin/docker", authority["endpoint"]["address"])
        check("authority probes honor TMPDIR with one private empty config and unchanged identity",
              len(probe_dirs) == 2 and probe_dirs[0] == probe_dirs[1]
              and all(private_configs) and not os.path.exists(probe_dirs[0])
              and probe_argv == [["/usr/bin/docker", "--config", probe_dirs[0],
                                 "--host", authority["endpoint"]["address"], action,
                                 "--format", "{{json .}}"] for action in ("version", "info")]
              and got_daemon == daemon
              and all(got_client[key] == client[key] for key in got_client))
        with open(os.path.join(config_root, "config.json"), "w") as handle:
            handle.write("{}")
        check("probe refuses a nonempty configured client directory before transport",
              refused(lambda: _docker_json("/usr/bin/docker",
                                          authority["endpoint"]["address"], config_root, ["info"])))
    # `worker provision` prints its preflight report as the whole of stdout and
    # runbooks parse that stream, so the drift disclosure must not land there.
    drift_out, drift_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(drift_out), \
            contextlib.redirect_stderr(drift_err):
        _disclose_verifier_drift("a" * 40, "b" * 40)
    check("verifier drift is disclosed on stderr, leaving stdout parseable",
          drift_out.getvalue() == ""
          and drift_err.getvalue().startswith(
              "note: Docker authority recorded at aaaaaaaaaaaa, "
              "executing at bbbbbbbbbbbb;"))
    regular_fact_chimera = json.loads(json.dumps(authority))
    regular_fact_chimera["client"]["selected_executable_uid"] = 1001
    regular_fact_chimera["digest"] = semantic_digest(regular_fact_chimera)
    no_execute_client = json.loads(json.dumps(authority))
    no_execute_client["client"]["selected_executable_mode"] = "0644"
    no_execute_client["client"]["resolved_executable_mode"] = "0644"
    no_execute_client["digest"] = semantic_digest(no_execute_client)
    collapsed_symlink = json.loads(json.dumps(authority))
    collapsed_symlink["client"]["selected_executable_kind"] = "symlink"
    collapsed_symlink["digest"] = semantic_digest(collapsed_symlink)
    check("Docker client kind/fact/execute joins refuse chimeras",
          refused(lambda: validate_authority_document(
              regular_fact_chimera, current_source=False))
          and refused(lambda: validate_authority_document(
              no_execute_client, current_source=False))
          and refused(lambda: validate_authority_document(
              collapsed_symlink, current_source=False)))
    userns_chimera = json.loads(json.dumps(authority))
    userns_chimera["daemon"]["userns_remap"] = True
    userns_chimera["daemon"]["fingerprint_sha256"] = daemon_fingerprint(
        userns_chimera["daemon"])
    userns_chimera["digest"] = semantic_digest(userns_chimera)
    check("daemon userns fact must derive from security options",
          refused(lambda: validate_authority_document(
              userns_chimera, current_source=False)))
    chimera = json.loads(json.dumps(authority))
    chimera["endpoint"]["address"] = "unix:///run/user/1001/other.sock"
    chimera["digest"] = semantic_digest(chimera)
    check("endpoint/socket chimera refuses",
          refused(lambda: validate_authority_document(
              chimera, current_source=False)))
    pool = _fixture_pool()
    check("no-database pool fixture validates",
          validate_pool_document(pool) is pool)
    boolean_index = json.loads(json.dumps(pool))
    boolean_index["workers"][0]["index"] = False
    boolean_index["digest"] = semantic_digest(boolean_index)
    check("pool worker booleans cannot impersonate integer indices",
          refused(lambda: validate_pool_document(boolean_index)))
    bad_pool = json.loads(json.dumps(pool))
    bad_pool["network"] = {"mode": "dedicated_internal", "name": "wrong"}
    bad_pool["digest"] = semantic_digest(bad_pool)
    check("no-database internal persistent pool refuses",
          refused(lambda: validate_pool_document(bad_pool)))
    none_binding = _fixture_binding()
    internal_binding = _fixture_binding(database=True)
    check("none binding golden fixture validates",
          validate_binding_document(none_binding) is none_binding)
    check("dedicated internal binding golden fixture validates",
          validate_binding_document(internal_binding) is internal_binding)
    bool_chimeras = []
    for field in ("internal", "ingress", "attachable"):
        candidate = json.loads(json.dumps(none_binding))
        candidate["network_policy"][field] = 0
        candidate["digest"] = semantic_digest(candidate)
        bool_chimeras.append(candidate)
    candidate = json.loads(json.dumps(none_binding))
    candidate["egress_probe"]["required"] = 0
    candidate["digest"] = semantic_digest(candidate)
    bool_chimeras.append(candidate)
    check("JSON integers cannot impersonate binding booleans",
          all(refused(lambda candidate=candidate:
                      validate_binding_document(candidate))
              for candidate in bool_chimeras))
    custom_driver = json.loads(json.dumps(internal_binding))
    custom_driver["network_policy"]["driver"] = "overlay"
    custom_driver["digest"] = semantic_digest(custom_driver)
    check("custom network driver refuses",
          refused(lambda: validate_binding_document(custom_driver)))
    mixed_mode = json.loads(json.dumps(internal_binding))
    mixed_mode["network_policy"]["expected_members"][1][
        "host_network_mode"] = "bridge"
    mixed_mode["network_policy"]["observed_members"][1][
        "host_network_mode"] = "bridge"
    mixed_mode["digest"] = semantic_digest(mixed_mode)
    check("dedicated attachment/mode chimera refuses",
          refused(lambda: validate_binding_document(mixed_mode)))
    duplicate_member = json.loads(json.dumps(internal_binding))
    extra = json.loads(json.dumps(
        duplicate_member["network_policy"]["expected_members"][1]))
    extra["name"] = "a-worker"
    extra["id"] = "1" * 64
    members = duplicate_member["network_policy"]["expected_members"]
    members.append(extra)
    members.sort(key=_member_sort_key)
    duplicate_member["network_policy"]["observed_members"] = \
        json.loads(json.dumps(members))
    duplicate_member["digest"] = semantic_digest(duplicate_member)
    check("dedicated membership cannot collapse two rows onto one worker "
          "index", refused(lambda: validate_binding_document(
              duplicate_member)))
    git_root = _verifier_git_root()
    check("authority output inside the verifier worktree refuses before "
          "minting while an external path remains eligible",
          refused(lambda: _refuse_authority_output_in_verifier_worktree(
              os.path.join(git_root, "authority.json")))
          and _refuse_authority_output_in_verifier_worktree(
              "/tmp/r2t-authority.json") == "/tmp/r2t-authority.json")
    with tempfile.TemporaryDirectory(
            prefix="r2t-authority-link-selftest.") as link_root:
        linked = os.path.join(link_root, "evidence.json")
        alias = os.path.join(link_root, "workspace-alias.json")
        with open(linked, "wb") as fh:
            fh.write(b"fixture")
        os.chmod(linked, 0o600)
        os.link(linked, alias)
        check("trusted evidence refuses an aliasing hard link",
              refused(lambda: assert_trusted_file(linked)))
    import socket as _socket
    # Short prefix on purpose: this directory holds a BOUND AF_UNIX socket,
    # whose path is capped at 107 bytes, and `TMPDIR` is now a per-module
    # directory under the self-test run root rather than `/tmp`.
    with tempfile.TemporaryDirectory(prefix="r2t-authority-sock.") \
            as link_root:
        executable = os.path.join(link_root, "docker")
        executable_alias = os.path.join(link_root, "docker-alias")
        with open(executable, "wb") as fh:
            fh.write(b"#!/bin/sh\nexit 0\n")
        os.chmod(executable, 0o700)
        os.link(executable, executable_alias)
        socket_path = os.path.join(link_root, "docker.sock")
        socket_alias = os.path.join(link_root, "socket-alias")
        fixture_socket = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        fixture_socket.bind(socket_path)
        os.link(socket_path, socket_alias)
        try:
            check("current-UID client and socket hard-link aliases refuse",
                  refused(lambda: _selected_client_facts(executable))
                  and refused(lambda: _socket_and_parent_facts(socket_path)))
        finally:
            fixture_socket.close()

    # Capture's filesystem/source prerequisites are deliberately tested with
    # spies: neither failure may cross the Docker probe boundary.
    real_probe = globals()["_probe_docker"]
    real_identity = globals()["_verifier_git_identity"]
    real_ambient = globals()["refuse_ambient_docker"]
    real_geteuid = os.geteuid
    probe_calls = []
    identity_calls = []

    def forbidden_probe(*_args, **_kwargs):
        probe_calls.append(True)
        raise AssertionError("Docker probe crossed a static refusal")

    def dirty_identity():
        identity_calls.append(True)
        raise _refuse("forced dirty verifier fixture")

    with tempfile.TemporaryDirectory(
            prefix="r2t-authority-capture-selftest.") as capture_root:
        occupied = os.path.join(capture_root, "occupied.json")
        with open(occupied, "wb") as fh:
            fh.write(b"occupied")
        clean_target = os.path.join(capture_root, "clean-target.json")
        globals()["_probe_docker"] = forbidden_probe
        globals()["_verifier_git_identity"] = dirty_identity
        globals()["refuse_ambient_docker"] = lambda *_args, **_kwargs: None
        os.geteuid = lambda: real_geteuid() or 1
        try:
            collision_refused = refused(lambda: capture_authority(
                docker_host="/private/docker.sock",
                docker_cli="/private/docker", out=occupied))
            collision_preceded_identity = identity_calls == []
            source_refused = refused(lambda: capture_authority(
                docker_host="/private/docker.sock",
                docker_cli="/private/docker", out=clean_target))
        finally:
            globals()["_probe_docker"] = real_probe
            globals()["_verifier_git_identity"] = real_identity
            globals()["refuse_ambient_docker"] = real_ambient
            os.geteuid = real_geteuid
    check("output collision and dirty verifier refuse before Docker contact",
          collision_refused and collision_preceded_identity
          and source_refused and len(identity_calls) == 1
          and probe_calls == [])

    schemas = os.path.join(os.path.dirname(os.path.dirname(__file__)), "schemas")
    expected = {
        "docker-execution-authority-v1.schema.json": AUTHORITY_SCHEMA,
        "docker-execution-binding-v1.schema.json": BINDING_SCHEMA,
        "worker-runtime-v3.schema.json": "r2t.worker-runtime/v3",
    }
    schema_ok = True
    for filename, identity in expected.items():
        try:
            raw = open(os.path.join(schemas, filename), "rb").read()
            schema_doc = loads_exact_json(raw, label=filename)
            schema_ok = schema_ok and isinstance(schema_doc, dict) \
                and schema_doc.get("type") == "object" \
                and schema_doc.get("additionalProperties") is False \
                and schema_doc.get("properties", {}).get("schema", {}).get(
                    "const") == identity
        except (OSError, DockerAuthorityRefused):
            schema_ok = False
    check("all authority schemas are closed and identity-pinned", schema_ok)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(selftest())
