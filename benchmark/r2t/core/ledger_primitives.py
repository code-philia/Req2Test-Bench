"""The result ledger's primitive layer, staged into the confined backend.

Everything here is what `result_ledger_v2` and `agent_wire_transport` need
from `result_ledger` when they run INSIDE the agent sandbox: exact JSON and
its digests, schema validation, trusted reads, durable no-clobber writes,
path containment and the small value helpers, all raising through one
`ResultLedgerRefused`.  `result_ledger` re-exports every name below, so its
importers see one module; this one exists so that the file the backend
tree stages -- and whose bytes every staged shared module is checked
against at launch -- is the layer the sandbox executes and not the whole
verifier.  Nothing here imports beyond the standard library at module
scope; `jsonschema`, `yaml` and `docker_authority` are function-local and
never reached in a sandbox.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import math
import os
import posixpath
import re
import secrets
import stat
from typing import Callable, Iterable, Mapping, Optional

CHECKPOINT_SCHEMA = "r2t.result-checkpoint/v1"
RECEIPT_SCHEMA = "r2t.result-ledger/v1"
BUNDLE_INDEX_SCHEMA = "r2t.publication-bundle-index/v1"
ORDERED_IDS_DOMAIN = "r2t.ordered-item-ids/v1"

_HERE = os.path.dirname(os.path.abspath(__file__))
_BENCHMARK = os.path.dirname(os.path.dirname(_HERE))
_SCHEMA_DIR = os.path.join(_BENCHMARK, "schemas")
_SCHEMA_FILES = {
    CHECKPOINT_SCHEMA: "result-checkpoint-v1.schema.json",
    RECEIPT_SCHEMA: "result-ledger-v1.schema.json",
    BUNDLE_INDEX_SCHEMA: "publication-bundle-index-v1.schema.json",
    "r2t.worker-runtime/v3": "worker-runtime-v3.schema.json",
    "r2t.worker-runtime/v4": "worker-runtime-v4.schema.json",
    # The agent-producer amendment's two additional documents.  They are
    # registered HERE, in the one registry, rather than beside their own
    # module: a second schema loader would be a second answer to "which
    # bytes is this identity", and the v1 identities above would no longer
    # be the whole list a reader has to check.
    "r2t.result-checkpoint/v2": "result-checkpoint-v2.schema.json",
    "r2t.result-ledger/v2": "result-ledger-v2.schema.json",
}
_SCHEMA_CACHE: dict[str, object] = {}
_VALIDATOR_CACHE: dict[str, object] = {}

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_HEX16_RE = re.compile(r"[0-9a-f]{16}\Z")


class ResultLedgerRefused(RuntimeError):
    """Evidence did not satisfy the complete I1 verifier contract."""


def _refuse(message: str) -> ResultLedgerRefused:
    if message.startswith("REFUSED: "):
        return ResultLedgerRefused(message)
    return ResultLedgerRefused("REFUSED: " + message)


def _raise_from(exc: BaseException, label: str) -> None:
    text = str(exc)
    if text.startswith("REFUSED: "):
        raise _refuse(text) from exc
    raise _refuse(f"{label}: {text}") from exc


# ---------------------------------------------------------------- exact JSON
def loads_exact_json(raw: bytes | str, *, label: str = "JSON") -> object:
    """Parse UTF-8 JSON, rejecting duplicate keys and every non-finite value.

    json.loads(parse_constant=...) does not catch exponent overflow:
    1e999 becomes positive infinity before a caller sees it.  The finite
    parse_float hook is therefore part of the exact parser rather than a
    later schema check.
    """
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _refuse(f"{label} is not UTF-8") from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise _refuse(
            f"{label} bytes have invalid type {type(raw).__name__}")

    def unique_object(items):
        out = {}
        for key, value in items:
            if key in out:
                raise _refuse(f"{label} repeats JSON object key {key!r}")
            out[key] = value
        return out

    def bad_constant(value: str):
        raise _refuse(f"{label} contains non-finite number {value}")

    def finite_float(value: str):
        try:
            parsed = float(value)
        except ValueError as exc:
            raise _refuse(f"{label} contains malformed number {value}") from exc
        if not math.isfinite(parsed):
            raise _refuse(f"{label} contains non-finite number {value}")
        return parsed

    try:
        return json.loads(
            text, object_pairs_hook=unique_object,
            parse_constant=bad_constant, parse_float=finite_float)
    except ResultLedgerRefused:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise _refuse(f"{label} is not exact JSON: {exc}") from exc


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _refuse(f"value is not canonical-JSON encodable: {exc}") from exc


def _same_json_value(left: object, right: object) -> bool:
    """JSON-value equality that cannot collapse booleans into integers."""
    return canonical_json_bytes(left) == canonical_json_bytes(right)


def _require_same_json(left: object, right: object, message: str) -> None:
    if not _same_json_value(left, right):
        raise _refuse(message)


def domain_digest(domain: str, value: object) -> str:
    """Authority-compatible domain-separated canonical digest."""
    if not isinstance(domain, str) or not domain:
        raise _refuse("digest domain is empty")
    return hashlib.sha256(
        domain.encode("utf-8") + b"\0" + canonical_json_bytes(value)
    ).hexdigest()


def semantic_digest(document: Mapping[str, object],
                    *, domain: Optional[str] = None) -> str:
    """Authority-compatible digest omitting only this object's top digest."""
    if not isinstance(document, Mapping):
        raise _refuse("semantic digest input is not an object")
    schema = domain if domain is not None else document.get("schema")
    if not isinstance(schema, str) or not schema:
        raise _refuse("semantic digest input has no schema/domain")
    projected = dict(document)
    projected.pop("digest", None)
    return domain_digest(schema, projected)


def ordered_item_ids_digest(item_ids: Iterable[str]) -> str:
    values = list(item_ids)
    if any(not isinstance(value, str) or not value for value in values):
        raise _refuse("ordered workset contains an empty or non-string item ID")
    if len(values) != len(set(values)):
        raise _refuse("ordered workset contains duplicate item IDs")
    return domain_digest(ORDERED_IDS_DOMAIN, values)


def raw_sha256(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        raise _refuse("raw SHA-256 input is not bytes")
    return hashlib.sha256(raw).hexdigest()


# -------------------------------------------------------------- JSON Schema
def _schema(schema_name: str):
    if schema_name not in _SCHEMA_FILES:
        raise _refuse(f"unsupported JSON Schema identity {schema_name!r}")
    cached = _SCHEMA_CACHE.get(schema_name)
    if cached is not None:
        return cached
    path = os.path.join(_SCHEMA_DIR, _SCHEMA_FILES[schema_name])
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise _refuse(f"cannot read bundled JSON Schema {path}: {exc}") from exc
    value = loads_exact_json(raw, label=f"bundled schema {schema_name}")
    if not isinstance(value, dict):
        raise _refuse(f"bundled schema {schema_name} is not an object")
    try:
        from jsonschema import Draft202012Validator
        Draft202012Validator.check_schema(value)
    except ImportError as exc:
        raise _refuse(
            "jsonschema dependency is unavailable; install "
            "benchmark/requirements-ci.txt") from exc
    except Exception as exc:  # jsonschema exposes several schema exceptions
        raise _refuse(f"bundled schema {schema_name} is invalid: {exc}") from exc
    _SCHEMA_CACHE[schema_name] = value
    return value


def _validator(schema_name: str):
    cached = _VALIDATOR_CACHE.get(schema_name)
    if cached is not None:
        return cached
    try:
        from jsonschema import Draft202012Validator
        value = Draft202012Validator(_schema(schema_name))
    except ImportError as exc:
        raise _refuse(
            "jsonschema dependency is unavailable; install "
            "benchmark/requirements-ci.txt") from exc
    _VALIDATOR_CACHE[schema_name] = value
    return value


def _json_path(parts) -> str:
    out = "$"
    for part in parts:
        out += f"[{part}]" if isinstance(part, int) else f".{part}"
    return out


def validate_json_schema(document: object, schema_name: str,
                         *, label: str = "evidence") -> None:
    errors = sorted(
        _validator(schema_name).iter_errors(document),
        key=lambda error: (tuple(str(v) for v in error.absolute_path),
                           error.message))
    if errors:
        error = errors[0]
        raise _refuse(
            f"{label} fails {schema_name} at "
            f"{_json_path(error.absolute_path)}: {error.message}")
    # The proposed schemas contain no number-valued field whose JSON type is
    # number. JSON Schema intentionally considers 1.0 an integer, while the
    # contract requires incorrectly typed fields to refuse. Enforce the
    # lexical-model distinction Python retained after parsing.
    def reject_float(value: object, path: tuple = ()):
        if isinstance(value, float):
            raise _refuse(
                f"{label} field {_json_path(path)} is a floating-point value; "
                "v1 evidence numeric fields are exact integers")
        if isinstance(value, dict):
            for key, child in value.items():
                reject_float(child, path + (key,))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                reject_float(child, path + (index,))
    reject_float(document)


def validate_checkpoint_schema(document: object) -> None:
    validate_json_schema(document, CHECKPOINT_SCHEMA, label="result checkpoint")


def validate_receipt_schema(document: object) -> None:
    validate_json_schema(document, RECEIPT_SCHEMA, label="result receipt")


def validate_bundle_index_schema(document: object) -> None:
    validate_json_schema(
        document, BUNDLE_INDEX_SCHEMA, label="publication bundle index")


# ---------------------------------------------------------- paths and reads
def canonical_absolute_path(value: object, label: str, *,
                            live: bool = True) -> str:
    """Validate the S0 canonical absolute spelling without normalizing it."""
    if not isinstance(value, str) or not value:
        raise _refuse(f"{label} is not a nonempty string")
    if any(mark in value for mark in ("\x00", "\r", "\n")):
        raise _refuse(f"{label} contains a control separator")
    if not value.startswith("/") or value.startswith("//"):
        raise _refuse(f"{label} is not an absolute path with one leading slash")
    if value != "/" and value.endswith("/"):
        raise _refuse(f"{label} has a trailing separator")
    if "//" in value:
        raise _refuse(f"{label} contains a repeated separator")
    parts = [] if value == "/" else value.split("/")[1:]
    if any(part in ("", ".", "..") for part in parts):
        raise _refuse(f"{label} contains an empty, dot, or dot-dot component")
    if posixpath.normpath(value) != value:
        raise _refuse(f"{label} is not lexically normalized")
    if live and os.path.realpath(value) != value:
        raise _refuse(f"{label} does not equal its live filesystem realpath")
    return value


def _require_workspace_separation(workspace: str, paths: Iterable[str],
                                  label: str) -> None:
    """Replay runtime-v3's two-way static containment invariant offline."""
    workspace_real = os.path.realpath(workspace).rstrip("/") or "/"
    for path in dict.fromkeys(paths):
        if not isinstance(path, str) or not os.path.isabs(path):
            raise _refuse(f"{label} protected path is not absolute")
        protected_real = os.path.realpath(path).rstrip("/") or "/"
        workspace_contains = protected_real == workspace_real \
            or workspace_real == "/" \
            or protected_real.startswith(workspace_real + "/")
        protected_contains = workspace_real == protected_real \
            or protected_real == "/" \
            or workspace_real.startswith(protected_real + "/")
        if workspace_contains or protected_contains:
            raise _refuse(
                f"{label} is reachable from the worker workspace: {path}")


def _path_components(path: str, *, include_leaf: bool) -> list[str]:
    path = canonical_absolute_path(path, "path")
    end = path if include_leaf else os.path.dirname(path)
    if end == "/":
        return ["/"]
    out = ["/"]
    cursor = ""
    for part in end.split("/")[1:]:
        cursor += "/" + part
        out.append(cursor)
    return out


# Linux stores a POSIX ACL xattr as a little-endian u32 version (2) and then
# 8-byte entries: u16 tag, u16 permissions, u32 id.  Owner (0x01), owning
# group (0x04) and other (0x20) entries only restate the mode bits; a named
# user (0x02), named group (0x08) or mask (0x10) entry in a DEFAULT ACL gives
# every file created under it an access ACL.
_ACL_MODE_BIT_TAGS = frozenset({0x01, 0x04, 0x20})


def _default_acl_gives_files_access_acl(directory: str) -> bool:
    try:
        raw = os.getxattr(directory, "system.posix_acl_default",
                          follow_symlinks=False)
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP,
                         getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}:
            return False
        raise _refuse(f"cannot inspect default ACL for {directory}") from exc
    if len(raw) < 4 or (len(raw) - 4) % 8 \
            or int.from_bytes(raw[:4], "little") != 2:
        raise _refuse(f"cannot parse default ACL for {directory}")
    tags = {int.from_bytes(raw[offset:offset + 2], "little")
            for offset in range(4, len(raw), 8)}
    return not tags <= _ACL_MODE_BIT_TAGS


def _secure_directory_chain(path: str, *, include_leaf: bool = False) -> None:
    """Refuse a replaceable or ACL-widened directory above ``path``.

    An access ACL refuses on every component.  A default ACL grants nothing
    on the directory that carries it; it only shapes what is created inside.
    So it is checked on the last component alone, the directory that holds or
    receives the file, and refuses there only when files created in it would
    get an access ACL: before anything is written, not at the readback.
    """
    from .. import docker_authority as authority
    trusted_uids = {0, os.geteuid()}
    components = _path_components(path, include_leaf=include_leaf)
    for component in components:
        try:
            info = os.lstat(component)
        except OSError as exc:
            raise _refuse(f"path component is unavailable: {component}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise _refuse(
                f"path component is not a non-symlink directory: {component}")
        mode = stat.S_IMODE(info.st_mode)
        sticky_root_exception = (
            info.st_uid == 0 and bool(mode & stat.S_ISVTX)
            and bool(mode & 0o002))
        if info.st_uid not in trusted_uids:
            raise _refuse(f"path component is owned by a peer: {component}")
        if mode & 0o022 and not sticky_root_exception:
            raise _refuse(f"path component is replaceable by a peer: {component}")
        try:
            acl_absent = authority._acl_absent(component)
        except authority.DockerAuthorityRefused as exc:
            _raise_from(exc, "directory ACL check")
        if not acl_absent:
            raise _refuse(f"path component carries an access ACL: {component}")
    if _default_acl_gives_files_access_acl(components[-1]):
        raise _refuse("path component's default ACL gives files created in "
                      f"it an access ACL: {components[-1]}")


def _trusted_leaf(path: str, label: str) -> os.stat_result:
    from .. import docker_authority as authority
    path = canonical_absolute_path(path, f"{label} path")
    _secure_directory_chain(path)
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise _refuse(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise _refuse(f"{label} is not a non-symlink regular file: {path}")
    if info.st_nlink != 1:
        raise _refuse(f"{label} has multiple hard-link names: {path}")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise _refuse(
            f"{label} is not current-UID owned and non-writable by peers")
    try:
        acl_absent = authority._acl_absent(path)
    except authority.DockerAuthorityRefused as exc:
        _raise_from(exc, "file ACL check")
    if not acl_absent:
        raise _refuse(f"{label} carries an access ACL")
    if os.path.realpath(path) != path:
        raise _refuse(f"{label} path does not equal realpath")
    return info


def _stat_identity(info: os.stat_result) -> tuple:
    return (
        info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid,
        info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size,
    )


def _read_trusted_snapshot(path: str, *, label: str) -> tuple[bytes, tuple]:
    """Return bytes plus the stable full identity of their file object."""
    before = _trusted_leaf(path, label)
    if not hasattr(os, "O_NOFOLLOW"):
        raise _refuse("platform lacks O_NOFOLLOW required for trusted reads")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _refuse(f"cannot open {label} without following links: {path}") from exc
    try:
        fd_before = os.fstat(fd)
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        fd_after = os.fstat(fd)
    except OSError as exc:
        raise _refuse(f"cannot read {label}: {path}") from exc
    finally:
        os.close(fd)
    after = _trusted_leaf(path, label)
    raw = b"".join(chunks)
    identities = {
        _stat_identity(before), _stat_identity(fd_before),
        _stat_identity(fd_after), _stat_identity(after),
    }
    if len(identities) != 1 or len(raw) != after.st_size:
        raise _refuse(f"{label} changed while it was read: {path}")
    return raw, _stat_identity(after)


def read_trusted_bytes(path: str, *, label: str = "evidence") -> bytes:
    """Read through a no-follow fd and prove the full file identity stayed put."""
    return _read_trusted_snapshot(path, label=label)[0]


class _LiveReader:
    """One stable snapshot per path, followed by an end-of-verification reread."""

    def __init__(self):
        self.raw_by_path: dict[str, bytes] = {}
        self.labels: dict[str, str] = {}
        self.identity_by_path: dict[str, tuple] = {}
        self.absent_paths: dict[str, str] = {}

    def read(self, path: str, label: str) -> bytes:
        path = canonical_absolute_path(path, f"{label} path")
        if path in self.raw_by_path:
            return self.raw_by_path[path]
        raw, identity = _read_trusted_snapshot(path, label=label)
        self.raw_by_path[path] = raw
        self.labels[path] = label
        self.identity_by_path[path] = identity
        return raw

    def require_absent(self, path: str, label: str) -> None:
        path = canonical_absolute_path(path, f"{label} path")
        _secure_directory_chain(path)
        if os.path.lexists(path):
            raise _refuse(f"{label} must be absent: {path}")
        self.absent_paths[path] = label

    def confirm(self) -> None:
        for path in sorted(self.raw_by_path):
            current, identity = _read_trusted_snapshot(
                path, label=self.labels[path])
            if current != self.raw_by_path[path] \
                    or identity != self.identity_by_path[path]:
                raise _refuse(
                    f"{self.labels[path]} bytes or file identity changed "
                    f"during verification: {path}")
        for path in sorted(self.absent_paths):
            _secure_directory_chain(path)
            if os.path.lexists(path):
                raise _refuse(
                    f"{self.absent_paths[path]} appeared during verification: "
                    f"{path}")


# --------------------------------------------------------- durable creation
_RENAME_NOREPLACE = 1


def _fault(fault: Optional[Callable[[str], None]], event: str) -> None:
    """Deterministic producer crash seam; production callers pass ``None``."""
    if fault is not None:
        fault(event)


def _open_directory_nofollow(path: str, label: str) -> int:
    """Open an absolute directory without following any component."""
    canonical_absolute_path(path, label)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open("/", flags)
    try:
        for component in (part for part in path.split("/") if part):
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        current = os.fstat(fd)
        if not stat.S_ISDIR(current.st_mode):
            raise _refuse(f"{label} is not a directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _rename_noreplace(parent_fd: int, source: str, destination: str,
                      label: str) -> None:
    """Commit a staged leaf without a check/replace race."""
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise _refuse(
            "renameat2(RENAME_NOREPLACE) is unavailable; durable "
            f"{label} creation refuses") from exc
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(parent_fd, os.fsencode(source), parent_fd,
                 os.fsencode(destination), _RENAME_NOREPLACE) == 0:
        return
    value = ctypes.get_errno()
    if value == errno.EEXIST:
        raise _refuse(f"{label} already exists")
    if value in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
        raise _refuse(
            "filesystem lacks atomic RENAME_NOREPLACE; durable "
            f"{label} creation refuses")
    raise _refuse(
        f"atomic {label} no-clobber commit failed: {os.strerror(value)}")


def _write_all(fd: int, payload: bytes, label: str) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise _refuse(f"short write while staging {label}")
        view = view[written:]


def durable_create_bytes_no_clobber(
        path: str, payload: bytes, *, label: str,
        fault: Optional[Callable[[str], None]] = None) -> None:
    """Durably create exact owner-private bytes with a kernel no-clobber.

    Parents are deliberately never created here.  Publication paths are
    authenticated resources, not conveniences to be normalised or repaired.
    """
    if not isinstance(payload, bytes):
        raise _refuse(f"{label} payload is not bytes")
    path = canonical_absolute_path(path, f"{label} path", live=False)
    parent, name = os.path.dirname(path), os.path.basename(path)
    _secure_directory_chain(path)
    if os.path.realpath(parent) != parent:
        raise _refuse(f"{label} parent path does not equal realpath")
    parent_fd = _open_directory_nofollow(parent, f"{label} parent")
    temporary = None
    fd = -1
    published = False
    try:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise _refuse(f"{label} already exists: {path}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        for _attempt in range(32):
            candidate = ".r2t-ledger-stage-" + secrets.token_hex(16)
            try:
                fd = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
                temporary = candidate
                break
            except FileExistsError:
                continue
        if fd < 0 or temporary is None:
            raise _refuse(f"cannot reserve private {label} staging file")
        _write_all(fd, payload, label)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        _fault(fault, label + ":stage_fsync")
        _rename_noreplace(parent_fd, temporary, name, label)
        temporary = None
        published = True
        _fault(fault, label + ":commit")
        os.fsync(parent_fd)
        _fault(fault, label + ":directory_fsync")
    except ResultLedgerRefused:
        raise
    except OSError as exc:
        state = " after publication" if published else ""
        raise _refuse(
            f"cannot durably create {label}{state}: {path}: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                pass
        os.close(parent_fd)
    current = read_trusted_bytes(path, label=label)
    if current != payload:
        raise _refuse(f"durable {label} failed exact readback")


def durable_replace_bytes(
        path: str, payload: bytes, *, label: str,
        fault: Optional[Callable[[str], None]] = None) -> None:
    """Durably replace an existing trusted mutable file with exact bytes."""
    if not isinstance(payload, bytes):
        raise _refuse(f"{label} payload is not bytes")
    path = canonical_absolute_path(path, f"{label} path")
    before = _trusted_leaf(path, label)
    parent, name = os.path.dirname(path), os.path.basename(path)
    parent_fd = _open_directory_nofollow(parent, f"{label} parent")
    temporary = None
    fd = -1
    replaced = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        for _attempt in range(32):
            candidate = ".r2t-ledger-stage-" + secrets.token_hex(16)
            try:
                fd = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
                temporary = candidate
                break
            except FileExistsError:
                continue
        if fd < 0 or temporary is None:
            raise _refuse(f"cannot reserve private {label} staging file")
        _write_all(fd, payload, label)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        _fault(fault, label + ":stage_fsync")
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _stat_identity(current) != _stat_identity(before):
            raise _refuse(f"{label} changed before atomic replacement")
        os.replace(temporary, name, src_dir_fd=parent_fd,
                   dst_dir_fd=parent_fd)
        temporary = None
        replaced = True
        _fault(fault, label + ":replace")
        os.fsync(parent_fd)
        _fault(fault, label + ":directory_fsync")
    except ResultLedgerRefused:
        raise
    except OSError as exc:
        state = " after replacement" if replaced else ""
        raise _refuse(
            f"cannot durably replace {label}{state}: {path}: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                pass
        os.close(parent_fd)
    current = read_trusted_bytes(path, label=label)
    if current != payload:
        raise _refuse(f"durable {label} replacement failed exact readback")


# --------------------------------------------------------------- primitives
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


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise _refuse(f"{label} is not a lowercase full SHA-256")
    return value


def _hex16(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX16_RE.fullmatch(value) is None:
        raise _refuse(f"{label} is not 16 lowercase hex characters")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise _refuse(f"{label} must be an integer >= {minimum}")
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or not value.strip():
        raise _refuse(f"{label} must be a non-whitespace string")
    if any(mark in value for mark in ("\x00", "\r", "\n")):
        raise _refuse(f"{label} contains a control separator")
    return value


def _safe_relative(value: object, label: str) -> str:
    path = _nonempty(value, label)
    if path.startswith("/") or "\\" in path or "//" in path \
            or path.endswith("/"):
        raise _refuse(f"{label} is not a canonical relative POSIX path")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts) \
            or posixpath.normpath(path) != path:
        raise _refuse(f"{label} is not a safe relative POSIX path")
    if any(mark in path for mark in ("\x00", "\r", "\n")):
        raise _refuse(f"{label} contains a control separator")
    return path


def _contained_path(root: str, relative: str, label: str) -> str:
    root = canonical_absolute_path(root, label + " root")
    relative = _safe_relative(relative, label + " relative path")
    candidate = root + "/" + relative
    canonical_absolute_path(candidate, label)
    if candidate != root and not candidate.startswith(root + "/"):
        raise _refuse(f"{label} escapes its declared root")
    return candidate


def _verify_digest(document: Mapping[str, object], *, label: str,
                   domain: Optional[str] = None) -> str:
    claimed = _sha256(document.get("digest"), label + ".digest")
    actual = semantic_digest(document, domain=domain)
    if claimed != actual:
        raise _refuse(f"{label} semantic digest does not recompute")
    return claimed


def _verify_raw_reference(reader: _LiveReader, reference: object, label: str,
                          *, byte_length: Optional[int] = None) -> bytes:
    ref = _exact_keys(reference, ("path", "file_sha256"), label + " reference")
    path = canonical_absolute_path(ref["path"], label + " reference.path")
    claimed = _sha256(ref["file_sha256"], label + " reference.file_sha256")
    raw = reader.read(path, label)
    if raw_sha256(raw) != claimed:
        raise _refuse(f"{label} raw SHA-256 does not match its reference")
    if byte_length is not None and len(raw) != byte_length:
        raise _refuse(f"{label} byte length does not match its reference")
    return raw


def _verify_semantic_reference(
        reader: _LiveReader, reference: object, label: str, *,
        expected_schema: str, validator) -> tuple[dict, bytes]:
    ref = _exact_keys(
        reference, ("path", "file_sha256", "digest"), label + " reference")
    path = canonical_absolute_path(ref["path"], label + " reference.path")
    _sha256(ref["file_sha256"], label + " reference.file_sha256")
    _sha256(ref["digest"], label + " reference.digest")
    raw = reader.read(path, label)
    if raw_sha256(raw) != ref["file_sha256"]:
        raise _refuse(f"{label} raw SHA-256 does not match its reference")
    document = loads_exact_json(raw, label=label)
    if not isinstance(document, dict) or document.get("schema") != expected_schema:
        raise _refuse(f"{label} has unsupported schema")
    try:
        validator(document)
    except ResultLedgerRefused:
        raise
    except BaseException as exc:
        _raise_from(exc, label)
    if semantic_digest(document) != ref["digest"]:
        raise _refuse(f"{label} semantic digest differs from its reference")
    return document, raw


def _json_lines(raw: bytes, label: str) -> list[dict]:
    if not raw:
        return []
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _refuse(f"{label} begins with a UTF-8 BOM")
    if b"\r" in raw:
        raise _refuse(f"{label} contains CR or CRLF bytes")
    if not raw.endswith(b"\n"):
        raise _refuse(f"{label} does not end at an LF-terminated record")
    out = []
    for line_number, line in enumerate(raw.split(b"\n")[:-1], 1):
        if not line or not line.strip():
            raise _refuse(f"{label} contains blank physical line {line_number}")
        row = loads_exact_json(line, label=f"{label} line {line_number}")
        if not isinstance(row, dict):
            raise _refuse(f"{label} line {line_number} is not a JSON object")
        out.append(row)
    return out


def _parse_json_object(raw: bytes, label: str) -> dict:
    value = loads_exact_json(raw, label=label)
    if not isinstance(value, dict):
        raise _refuse(f"{label} is not a JSON object")
    return value


def _parse_yaml(raw: bytes, label: str):
    try:
        import yaml
        value = yaml.safe_load(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise _refuse(f"{label} is not valid UTF-8 YAML: {exc}") from exc
    except Exception as exc:
        raise _refuse(f"{label} is not valid YAML: {exc}") from exc

    def finite(child: object, path: str = "$"):
        if isinstance(child, float) and not math.isfinite(child):
            raise _refuse(f"{label} contains a non-finite value at {path}")
        if isinstance(child, dict):
            for key, item in child.items():
                finite(item, f"{path}.{key}")
        elif isinstance(child, list):
            for index, item in enumerate(child):
                finite(item, f"{path}[{index}]")
    finite(value)
    return value


def _named_canonical_values(value: object, label: str, *,
                            expected_names: Optional[set[str]] = None) -> dict:
    if not isinstance(value, list):
        raise _refuse(f"{label} is not a list")
    names = []
    out = {}
    for index, item in enumerate(value):
        row = _exact_keys(item, ("name", "value_json"),
                          f"{label}[{index}]")
        name = _nonempty(row["name"], f"{label}[{index}].name")
        encoded = _nonempty(row["value_json"],
                            f"{label}[{index}].value_json")
        if any(mark in encoded for mark in ("\r", "\n")):
            raise _refuse(f"{label}[{index}].value_json is not one line")
        decoded = loads_exact_json(
            encoded, label=f"{label}[{index}].value_json")
        if canonical_json_bytes(decoded).decode("utf-8") != encoded:
            raise _refuse(
                f"{label}[{index}].value_json is not exact canonical JSON")
        if name in out:
            raise _refuse(f"{label} repeats name {name!r}")
        names.append(name)
        out[name] = decoded
    if names != sorted(names):
        raise _refuse(f"{label} is not sorted by name")
    if expected_names is not None and set(names) != expected_names:
        raise _refuse(
            f"{label} names differ; missing="
            f"{sorted(expected_names - set(names))}, "
            f"unknown={sorted(set(names) - expected_names)}")
    return out
