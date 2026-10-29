"""Deterministic, source-only producers for the J0 JVM cost probe.

This module implements Phase A of :mod:`benchmark/J0_JVM_TIMING_PROTOCOL.md`:
it authenticates the three immutable Git trees, composes Algorand's vendored
test workspace without network access, parses features through the exact
Cucumber-version Gherkin parsers, and freezes the candidate-blind scalar and
Examples inputs.  It deliberately contains no Maven, Docker, timing, recorder,
or mutation execution path.

The public functions fail closed with :class:`J0Error`.  Generated JSON is
canonical UTF-8 with a single terminal LF; validators reject duplicate keys,
floats, noncanonical bytes, unknown keys, unsafe paths, and identity drift.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


class J0Error(ValueError):
    """A controlled Phase-A refusal."""


HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TAG = re.compile(r"@[A-Za-z0-9_.-]+\Z")
GHERKIN_TAG = re.compile(r"@[^\s@]+\Z")

TREE_DOMAIN = "r2t-j0-tree/1"
TREE_PREFIX = b"r2t-j0-tree/1\0"
SOURCE_SCHEMA = "r2t.java-j0-source-archive/1"
COMPOSITION_SCHEMA = "r2t.java-j0-algorand-composition/1"
PARSER_AST_SCHEMA = "r2t.j0-bridge-ast/1"
CENSUS_SCHEMA = "r2t.java-j0-census/1"
SCALAR_SELECTION_SCHEMA = "r2t.java-j0-scalar-selection/1"
EXAMPLES_SELECTION_SCHEMA = "r2t.java-j0-examples-selection/1"
EXAMPLES_OVERLAY_SCHEMA = "r2t.java-j0-examples-overlay/1"
PHASE_A_SCHEMA = "r2t.java-j0-phase-a/1"
ITEMS_SHA256 = "621ae1f109f888e291359bba1a526dc9dcf0c5b065036b03ca61c43262a3b5de"
GIT_EXECUTABLE = "/usr/bin/git"
JAVA_EXECUTABLE = "/usr/bin/java"
JAVAC_EXECUTABLE = "/usr/bin/javac"
UNIT_TAGS_SHA256 = "0ca6a881c86db58172740a500ea7dbf5a5400726832feada06699a3725f54845"

PINNED_REPOSITORIES: dict[str, dict[str, str]] = {
    "epubcheck": {
        "commit": "82b174ec319ea3e6c9d2488f84155fa4a9171fc2",
        "git_tree": "993e9df95278da08b8c6ebe68dfb44f777ddfbea",
        "upstream": "https://github.com/w3c/epubcheck.git",
    },
    "algorand-sdk": {
        "commit": "4e38dadc4eec827ed8742c8bb272e0545c801932",
        "git_tree": "6b896a9e6a64ca846ebe8a6c59e32056fba13b43",
        "upstream": "https://github.com/algorand/java-algorand-sdk.git",
    },
    # benchmark/config/corpora.yml historically has pinned_commit: null for
    # this repository.  J0 does not inherit that omission: the protocol pin
    # and tree below are unconditional source authority.
    "algorand-sdk-testing": {
        "commit": "7c67284b52675257e66c017cc3606bcd4803f4c6",
        "git_tree": "f6c4984d2e9ae5256bfee89df155900f28801d48",
        "upstream": "https://github.com/algorand/algorand-sdk-testing.git",
    },
}

PINNED_SOURCE_ARCHIVE_FACTS: dict[str, dict[str, Any]] = {
    "epubcheck": {
        "archive_tree_sha256":
            "2a6f37ae3bb5d9c373e6b0f83982053dd645f87049dc36dee4fbfc930c5dc7d9",
        "file_count": 3753,
        "manifest_sha256":
            "fa05687396f47a71caf08fff1462f1595b3240235781d8776420c1a9d3d33db4",
        "total_bytes": 9356666,
    },
    "algorand-sdk": {
        "archive_tree_sha256":
            "120c79cf5d99274faca46abdd09355e11bc3675f57c5023a3aef339ff8871559",
        "file_count": 443,
        "manifest_sha256":
            "5916f90edef78e21d2022505a02a7199796c95c52530d5d7769d151afcdb0d67",
        "total_bytes": 1856882,
    },
    "algorand-sdk-testing": {
        "archive_tree_sha256":
            "e9fdc199385ddee3ae6a04ab3d839f10e378d45ebf71f0acd673ea2567609a54",
        "file_count": 270,
        "manifest_sha256":
            "c039afa20a0182eb09d1ce68db99aa31e1859da62da38fc4e0968240fef5d4fb",
        "total_bytes": 16603351,
    },
}

PARSER_STACKS: dict[str, dict[str, Any]] = {
    "kapua": {
        "adapter": "cucumber-6.11.0/gherkin-18.1.1/r2t-phase-a-1",
        # The shaded Gherkin 18 API retains the measured protobuf interface
        # used by mode 15. Reuse it without changing existing bridge identities.
        "bridge_mode": "15",
        "cucumber_version": "6.11.0",
        "gherkin_version": "18.1.1",
        "artifacts": (
            {
                "coordinate": "io.cucumber:cucumber-gherkin-messages:6.11.0",
                "sha256": "085e7aeeecc0496e0feebbf3116393267fee7699f86f77a315aa4603fb584cd7",
            },
            {
                "coordinate": "io.cucumber:messages:15.0.0",
                "sha256": "f9d06d6d9d079577660e1a3d6f4a77fb0b8a0d01ea800a95bfb81d0b41d87a16",
            },
            {
                "coordinate": "io.cucumber:tag-expressions:3.0.1",
                "sha256": "3fdc20beaf5165d0b72f998458445ee65a7fb48e82d1b09b8fa8c05661c577af",
            },
        ),
    },
    "algorand-sdk": {
        "adapter": "cucumber-6.6.0/gherkin-15.0.2/r2t-phase-a-1",
        "bridge_mode": "15",
        "cucumber_version": "6.6.0",
        "gherkin_version": "15.0.2",
        "artifacts": (
            {
                "coordinate": "io.cucumber:cucumber-gherkin-messages:6.6.0",
                "sha256": "17f4a71c4a099ba1032a374fd14d5dcb68f44add74a170680f4316e0baecfbd8",
            },
            {
                "coordinate": "io.cucumber:messages:13.0.1",
                "sha256": "db96b0bfe832bcc399da35a293f350a58eaaf4be6f772873da5289ab42beae45",
            },
            {
                "coordinate": "io.cucumber:tag-expressions:3.0.0",
                "sha256": "432ce7ed32ed36007e8373e4743b84d64eac8ec99f17790d18f9c7c656beeabb",
            },
        ),
    },
    "epubcheck": {
        "adapter": "cucumber-7.8.0/gherkin-24.0.0/r2t-phase-a-1",
        "bridge_mode": "24",
        "cucumber_version": "7.8.0",
        "gherkin_version": "24.0.0",
        "artifacts": (
            {
                "coordinate": "io.cucumber:gherkin:24.0.0",
                "sha256": "f1ad566279099c0fdb8c03992e702f25a87c6283289fb26225310502dc4e656f",
            },
            {
                "coordinate": "io.cucumber:messages:19.1.2",
                "sha256": "2409fdda68e2c2afbc90dfb9ba94a74874efd34e5127eb0f363757235cbddcad",
            },
            {
                "coordinate": "io.cucumber:tag-expressions:4.1.0",
                "sha256": "11f6196b20373afd088889d860985e25b04d2ece49621c61ef8f9fbc450fa6dc",
            },
        ),
    },
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _raw_sha256(path: os.PathLike[str] | str) -> str:
    raw, _ = _read_absolute_regular_nofollow(path)
    return _sha256(raw)


def _validate_json_value(value: Any, where: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise J0Error(f"{where}: string is not valid UTF-8") from exc
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        raise J0Error(f"{where}: floats are forbidden")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{where}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise J0Error(f"{where}: JSON object key is not a string")
            _validate_json_value(key, f"{where}.<key>")
            _validate_json_value(item, f"{where}.{key}")
        return
    raise J0Error(f"{where}: unsupported JSON type {type(value).__name__}")


def canonical_json_bytes(value: Any, *, terminal_lf: bool = True) -> bytes:
    """Return the one J0 canonical JSON serialization."""
    _validate_json_value(value)
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise J0Error(f"cannot serialize canonical JSON: {exc}") from exc
    return raw + (b"\n" if terminal_lf else b"")


def _reject_float(token: str) -> Any:
    raise J0Error(f"float JSON token is forbidden: {token}")


def _reject_constant(token: str) -> Any:
    raise J0Error(f"non-finite JSON token is forbidden: {token}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise J0Error(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def load_canonical_json_bytes(raw: bytes, *, where: str = "document") -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise J0Error(f"{where}: not strict UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except J0Error:
        raise
    except json.JSONDecodeError as exc:
        raise J0Error(f"{where}: invalid JSON: {exc}") from exc
    _validate_json_value(value)
    if raw != canonical_json_bytes(value):
        raise J0Error(f"{where}: JSON bytes are not canonical")
    return value


def load_canonical_json(path: os.PathLike[str] | str) -> Any:
    with open(path, "rb") as handle:
        return load_canonical_json_bytes(handle.read(), where=str(path))


def _closed(obj: Any, keys: set[str], where: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise J0Error(f"{where}: expected object")
    actual = set(obj)
    if actual != keys:
        raise J0Error(
            f"{where}: closed schema keys differ; missing={sorted(keys - actual)!r} "
            f"unknown={sorted(actual - keys)!r}"
        )
    return obj


def _string(value: Any, where: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise J0Error(f"{where}: expected {'nonempty ' if nonempty else ''}string")
    return value


def _integer(value: Any, where: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise J0Error(f"{where}: expected integer >= {minimum}")
    return value


def _hex(value: Any, length: int, where: str) -> str:
    value = _string(value, where)
    pattern = HEX40 if length == 40 else HEX64
    if not pattern.fullmatch(value):
        raise J0Error(f"{where}: expected lowercase {length}-hex")
    return value


def validate_posix_path(value: Any, *, where: str = "path") -> str:
    value = _string(value, where)
    if "\x00" in value or "\\" in value:
        raise J0Error(f"{where}: NUL and backslash are forbidden")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise J0Error(f"{where}: not valid UTF-8") from exc
    if not raw or value.startswith("/"):
        raise J0Error(f"{where}: must be a nonempty relative POSIX path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise J0Error(f"{where}: empty, '.' and '..' components are forbidden")
    if str(PurePosixPath(value)) != value:
        raise J0Error(f"{where}: is not a normalized relative POSIX path")
    return value


def validate_path_set(paths: Iterable[str], *, where: str = "paths") -> list[str]:
    values = [validate_posix_path(path, where=f"{where}[{index}]")
              for index, path in enumerate(paths)]
    if values != sorted(values, key=lambda item: item.encode("utf-8")):
        raise J0Error(f"{where}: paths are not sorted by UTF-8 bytes")
    if len(values) != len(set(values)):
        raise J0Error(f"{where}: duplicate path")
    nfc: dict[str, str] = {}
    for path in values:
        normalized = unicodedata.normalize("NFC", path)
        if normalized in nfc:
            raise J0Error(
                f"{where}: NFC collision between {nfc[normalized]!r} and {path!r}"
            )
        nfc[normalized] = path
    return values


def framed_tree_sha256(files: Iterable[tuple[str, bytes]]) -> str:
    """Hash normalized files with the exact ``r2t-j0-tree/1`` frame."""
    entries = list(files)
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    validate_path_set((path for path, _ in entries), where="tree.paths")
    digest = hashlib.sha256()
    digest.update(TREE_PREFIX)
    for path, content in entries:
        if not isinstance(content, bytes):
            raise J0Error(f"tree[{path!r}]: content is not bytes")
        path_bytes = path.encode("utf-8")
        if len(path_bytes) > 2**64 - 1 or len(content) > 2**64 - 1:
            raise J0Error("tree frame length exceeds u64")
        digest.update(struct.pack(">Q", len(path_bytes)))
        digest.update(path_bytes)
        digest.update(b"\0" + b"100644" + b"\0")
        digest.update(struct.pack(">Q", len(content)))
        digest.update(content)
    return digest.hexdigest()


def _safe_join(root: Path, rel: str) -> Path:
    validate_posix_path(rel)
    target = root.joinpath(*rel.split("/"))
    # Lexical containment is enough after the path validator; individual
    # components are lstat-checked before reading/writing.
    if target == root or root not in target.parents:
        raise J0Error(f"path escapes root: {rel!r}")
    return target


def _require_no_symlink_components(root: Path, rel: str) -> Path:
    target = _safe_join(root, rel)
    current = root
    for part in rel.split("/"):
        current = current / part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            raise J0Error(f"missing source path: {rel}") from None
        if stat.S_ISLNK(mode):
            raise J0Error(f"symlink source path refused: {rel}")
    return target


def _stable_stat(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _directory_open_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise J0Error("platform lacks O_DIRECTORY/O_NOFOLLOW for authenticated reads")
    return (os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)


def _file_open_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise J0Error("platform lacks O_NOFOLLOW for authenticated reads")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW


def _read_from_directory_fd(root_fd: int, parts: Sequence[str], where: str) \
        -> tuple[bytes, os.stat_result]:
    if not parts:
        raise J0Error(f"{where}: empty file path")
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                child = os.open(part, _directory_open_flags(), dir_fd=current)
            except OSError as exc:
                raise J0Error(f"{where}: unsafe directory component {part!r}: {exc}") from exc
            os.close(current)
            current = child
        name = parts[-1]
        try:
            fd = os.open(name, _file_open_flags(), dir_fd=current)
        except OSError as exc:
            raise J0Error(f"{where}: cannot securely open file: {exc}") from exc
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise J0Error(f"{where}: path is not a regular file")
            chunks: list[bytes] = []
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                chunks.append(block)
            after = os.fstat(fd)
            try:
                reachable = os.stat(name, dir_fd=current, follow_symlinks=False)
            except OSError as exc:
                raise J0Error(f"{where}: file disappeared during authenticated read") from exc
            if _stable_stat(before) != _stable_stat(after) \
                    or before.st_dev != reachable.st_dev \
                    or before.st_ino != reachable.st_ino \
                    or not stat.S_ISREG(reachable.st_mode):
                raise J0Error(f"{where}: file changed during authenticated read")
            raw = b"".join(chunks)
            if len(raw) != before.st_size:
                raise J0Error(f"{where}: short authenticated read")
            return raw, after
        finally:
            os.close(fd)
    finally:
        os.close(current)


def _read_absolute_regular_nofollow(path: os.PathLike[str] | str) \
        -> tuple[bytes, os.stat_result]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if not absolute.is_absolute() or not parts or parts[0] != os.sep:
        raise J0Error(f"authenticated file path is not absolute: {path}")
    root_fd = os.open(os.sep, _directory_open_flags())
    try:
        return _read_from_directory_fd(
            root_fd, list(parts[1:]), f"authenticated file {absolute}")
    finally:
        os.close(root_fd)


def _read_relative_regular_nofollow(
    root: os.PathLike[str] | str,
    rel: str,
) -> tuple[bytes, os.stat_result]:
    validate_posix_path(rel, where="authenticated relative path")
    root_path = Path(os.path.abspath(os.fspath(root)))
    target = _safe_join(root_path, rel)
    return _read_absolute_regular_nofollow(target)


def _closed_process_environment(*, java: bool = False, git: bool = False) \
        -> dict[str, str]:
    if java and git:
        raise J0Error("process environment cannot be both Java and Git")
    env = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8" if java else "C",
        "LC_ALL": "C.UTF-8" if java else "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }
    if git:
        env.update({
            "GIT_ASKPASS": "/bin/false",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "SSH_ASKPASS": "/bin/false",
            "XDG_CONFIG_HOME": "/nonexistent",
        })
    return env


def _git(root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    command = [
        GIT_EXECUTABLE,
        "-c", "core.hooksPath=/dev/null",
        "-c", "credential.helper=",
        "-c", "protocol.allow=never",
        "-c", "core.fsmonitor=false",
        "-C", str(root), *args,
    ]
    try:
        proc = subprocess.run(
            command,
            check=False,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_closed_process_environment(git=True),
        )
    except OSError as exc:
        raise J0Error(f"cannot execute git for source authentication: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise J0Error(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout


def _git_blob_sha1(content: bytes) -> str:
    framed = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    return hashlib.sha1(framed).hexdigest()  # nosec - Git SHA-1 object identity


def _assert_git_objects_present(
    root: Path,
    commit: str,
    tree: str,
    tracked: Mapping[str, tuple[str, str]],
) -> None:
    expected: dict[str, str] = {commit: "commit", tree: "tree"}
    for _path, (_mode, oid) in tracked.items():
        expected[oid] = "blob"
    ordered = sorted(expected, key=lambda value: value.encode("ascii"))
    queries = b"".join(oid.encode("ascii") + b"\n" for oid in ordered)
    raw = _git(
        root, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        input_bytes=queries,
    )
    try:
        lines = raw.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise J0Error("Git object inventory is not ASCII") from exc
    if len(lines) != len(ordered):
        raise J0Error("Git object inventory cardinality mismatch")
    for requested, line in zip(ordered, lines):
        fields = line.split(" ")
        if len(fields) != 3 or fields[0] != requested \
                or fields[1] != expected[requested] or not fields[2].isdigit():
            raise J0Error(
                f"Git object is missing/substituted under no-lazy-fetch: {requested}"
            )


def _walk_checkout(root: Path) -> dict[str, os.stat_result]:
    if not root.is_dir() or root.is_symlink():
        raise J0Error(f"source root is not a real directory: {root}")
    out: dict[str, os.stat_result] = {}
    directories: set[str] = set()
    nfc: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        kept: list[str] = []
        for name in dirnames:
            candidate = current / name
            if current == root and name == ".git":
                continue
            mode = os.lstat(candidate).st_mode
            rel = candidate.relative_to(root).as_posix()
            validate_posix_path(rel, where="checkout.directory")
            if stat.S_ISLNK(mode):
                raise J0Error(f"symlink directory refused: {rel}")
            if not stat.S_ISDIR(mode):
                raise J0Error(f"non-directory tree entry refused: {rel}")
            kept.append(name)
            directories.add(rel)
        dirnames[:] = kept
        for name in filenames:
            candidate = current / name
            rel = candidate.relative_to(root).as_posix()
            validate_posix_path(rel, where="checkout.file")
            mode = os.lstat(candidate).st_mode
            if not stat.S_ISREG(mode):
                kind = "symlink" if stat.S_ISLNK(mode) else "non-regular"
                raise J0Error(f"{kind} source entry refused: {rel}")
            normalized = unicodedata.normalize("NFC", rel)
            if normalized in nfc:
                raise J0Error(
                    f"checkout NFC collision: {nfc[normalized]!r} and {rel!r}"
                )
            nfc[normalized] = rel
            out[rel] = os.lstat(candidate)
    implied: set[str] = set()
    for path in out:
        parent = PurePosixPath(path).parent
        while parent != PurePosixPath("."):
            implied.add(parent.as_posix())
            parent = parent.parent
    if directories != implied:
        extra = sorted(directories - implied, key=lambda item: item.encode("utf-8"))
        missing = sorted(implied - directories, key=lambda item: item.encode("utf-8"))
        raise J0Error(
            f"physical directory set is not implied by files; "
            f"extra={extra[:8]!r} missing={missing[:8]!r}"
        )
    return out


def build_source_archive_manifest(project: str, root: os.PathLike[str] | str) -> dict[str, Any]:
    """Authenticate a clean checkout and bind every tracked path/mode/byte."""
    if project not in PINNED_REPOSITORIES:
        raise J0Error(f"unknown J0 source project: {project}")
    spec = PINNED_REPOSITORIES[project]
    root = Path(root)
    head = _git(root, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
    tree = _git(root, "rev-parse", "--verify", "HEAD^{tree}").decode("ascii").strip()
    object_format = _git(root, "rev-parse", "--show-object-format").decode("ascii").strip()
    if head != spec["commit"]:
        raise J0Error(f"{project}: wrong HEAD {head}; expected {spec['commit']}")
    if tree != spec["git_tree"]:
        raise J0Error(f"{project}: wrong Git tree {tree}; expected {spec['git_tree']}")
    if object_format != "sha1":
        raise J0Error(f"{project}: unsupported Git object format {object_format!r}")

    raw_entries = _git(root, "ls-tree", "-rz", "--full-tree", spec["commit"])
    tracked: dict[str, tuple[str, str]] = {}
    for index, raw in enumerate(raw_entries.split(b"\0")):
        if not raw:
            continue
        try:
            header, path_raw = raw.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw = header.split(b" ", 2)
            path = path_raw.decode("utf-8", errors="strict")
            mode = mode_raw.decode("ascii")
            kind = kind_raw.decode("ascii")
            oid = oid_raw.decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise J0Error(f"{project}: malformed ls-tree entry {index}") from exc
        validate_posix_path(path, where=f"{project}.ls_tree[{index}].path")
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise J0Error(f"{project}: unsupported Git entry {mode} {kind} {path}")
        if not HEX40.fullmatch(oid):
            raise J0Error(f"{project}: malformed Git blob id for {path}")
        if path in tracked:
            raise J0Error(f"{project}: duplicate Git path {path}")
        tracked[path] = (mode, oid)

    _assert_git_objects_present(root, spec["commit"], spec["git_tree"], tracked)

    physical = _walk_checkout(root)
    if set(physical) != set(tracked):
        missing = sorted(set(tracked) - set(physical), key=lambda p: p.encode("utf-8"))
        extra = sorted(set(physical) - set(tracked), key=lambda p: p.encode("utf-8"))
        raise J0Error(
            f"{project}: checkout is dirty; missing={missing[:8]!r} extra={extra[:8]!r}"
        )

    files: list[dict[str, Any]] = []
    tree_inputs: list[tuple[str, bytes]] = []
    total_bytes = 0
    for path in sorted(tracked, key=lambda item: item.encode("utf-8")):
        git_mode, git_blob = tracked[path]
        content, authenticated_stat = _read_relative_regular_nofollow(root, path)
        mode = authenticated_stat.st_mode
        if not stat.S_ISREG(mode):
            raise J0Error(f"{project}: non-regular tracked path {path}")
        executable = bool(mode & 0o111)
        if executable != (git_mode == "100755"):
            raise J0Error(
                f"{project}: dirty executable mode for {path}; Git has {git_mode}"
            )
        actual_blob = _git_blob_sha1(content)
        if actual_blob != git_blob:
            raise J0Error(f"{project}: dirty bytes for {path}")
        total_bytes += len(content)
        files.append({
            "bytes": len(content),
            "git_blob_sha1": git_blob,
            "git_mode": git_mode,
            "path": path,
            "raw_file_sha256": _sha256(content),
        })
        tree_inputs.append((path, content))

    manifest = {
        "archive_tree_digest_domain": TREE_DOMAIN,
        "archive_tree_sha256": framed_tree_sha256(tree_inputs),
        "commit": spec["commit"],
        "file_count": len(files),
        "files": files,
        "git_object_format": object_format,
        "git_tree": spec["git_tree"],
        "project": project,
        "schema": SOURCE_SCHEMA,
        "total_bytes": total_bytes,
        "upstream": spec["upstream"],
    }
    validate_source_archive_manifest(manifest)
    return manifest


def validate_source_archive_manifest(manifest: Any) -> dict[str, Any]:
    obj = _closed(manifest, {
        "archive_tree_digest_domain", "archive_tree_sha256", "commit",
        "file_count", "files", "git_object_format", "git_tree", "project",
        "schema", "total_bytes", "upstream",
    }, "source_archive")
    if obj["schema"] != SOURCE_SCHEMA:
        raise J0Error("source_archive.schema: wrong schema")
    project = _string(obj["project"], "source_archive.project")
    if project not in PINNED_REPOSITORIES:
        raise J0Error("source_archive.project: unknown project")
    spec = PINNED_REPOSITORIES[project]
    if obj["commit"] != spec["commit"] or obj["git_tree"] != spec["git_tree"]:
        raise J0Error(f"source_archive: {project} pin/tree mismatch")
    if obj["upstream"] != spec["upstream"]:
        raise J0Error("source_archive.upstream: mismatch")
    if obj["git_object_format"] != "sha1":
        raise J0Error("source_archive.git_object_format: must be sha1")
    if obj["archive_tree_digest_domain"] != TREE_DOMAIN:
        raise J0Error("source_archive.archive_tree_digest_domain: mismatch")
    _hex(obj["archive_tree_sha256"], 64, "source_archive.archive_tree_sha256")
    if not isinstance(obj["files"], list):
        raise J0Error("source_archive.files: expected array")
    paths: list[str] = []
    total = 0
    for index, value in enumerate(obj["files"]):
        entry = _closed(value, {
            "bytes", "git_blob_sha1", "git_mode", "path", "raw_file_sha256",
        }, f"source_archive.files[{index}]")
        paths.append(validate_posix_path(
            entry["path"], where=f"source_archive.files[{index}].path"))
        total += _integer(entry["bytes"], f"source_archive.files[{index}].bytes")
        _hex(entry["git_blob_sha1"], 40,
             f"source_archive.files[{index}].git_blob_sha1")
        _hex(entry["raw_file_sha256"], 64,
             f"source_archive.files[{index}].raw_file_sha256")
        if entry["git_mode"] not in {"100644", "100755"}:
            raise J0Error(f"source_archive.files[{index}].git_mode: invalid")
    validate_path_set(paths, where="source_archive.files.paths")
    if obj["file_count"] != len(obj["files"]):
        raise J0Error("source_archive.file_count: mismatch")
    if obj["total_bytes"] != total:
        raise J0Error("source_archive.total_bytes: mismatch")
    _integer(obj["file_count"], "source_archive.file_count")
    _integer(obj["total_bytes"], "source_archive.total_bytes")
    pinned = PINNED_SOURCE_ARCHIVE_FACTS.get(project)
    if pinned is not None:
        for key in ("archive_tree_sha256", "file_count", "total_bytes"):
            if obj[key] != pinned[key]:
                raise J0Error(f"source_archive.{key}: pinned {project} fact mismatch")
        if _sha256(canonical_json_bytes(obj)) != pinned["manifest_sha256"]:
            raise J0Error(f"source_archive: pinned {project} manifest identity mismatch")
    return obj


def validate_source_checkout(
    project: str,
    root: os.PathLike[str] | str,
    manifest: Mapping[str, Any],
) -> None:
    """Rebuild and byte-compare the complete source authority."""
    validate_source_archive_manifest(manifest)
    rebuilt = build_source_archive_manifest(project, root)
    if canonical_json_bytes(rebuilt) != canonical_json_bytes(dict(manifest)):
        raise J0Error(f"{project}: source archive manifest no longer matches checkout")


def _validate_manifest_tree(
    root: os.PathLike[str] | str,
    manifest: Mapping[str, Any],
) -> None:
    validate_source_archive_manifest(manifest)
    root_path = Path(root)
    physical = _walk_checkout(root_path)
    expected = {entry["path"]: entry for entry in manifest["files"]}
    if set(physical) != set(expected):
        raise J0Error(f"{manifest['project']}: authenticated snapshot path-set mismatch")
    framed: list[tuple[str, bytes]] = []
    for rel in sorted(expected, key=lambda value: value.encode("utf-8")):
        entry = expected[rel]
        raw, snapshot_stat = _read_relative_regular_nofollow(root_path, rel)
        expected_mode = 0o755 if entry["git_mode"] == "100755" else 0o644
        if stat.S_IMODE(snapshot_stat.st_mode) != expected_mode:
            raise J0Error(f"{manifest['project']}: snapshot mode mismatch: {rel}")
        if len(raw) != entry["bytes"] \
                or _sha256(raw) != entry["raw_file_sha256"] \
                or _git_blob_sha1(raw) != entry["git_blob_sha1"]:
            raise J0Error(f"{manifest['project']}: snapshot bytes mismatch: {rel}")
        framed.append((rel, raw))
    if framed_tree_sha256(framed) != manifest["archive_tree_sha256"]:
        raise J0Error(f"{manifest['project']}: snapshot framed-tree mismatch")


def _snapshot_source_checkout(
    source_root: os.PathLike[str] | str,
    manifest: Mapping[str, Any],
    destination: os.PathLike[str] | str,
) -> None:
    validate_source_archive_manifest(manifest)
    destination_path = Path(destination)
    _require_new_empty_directory(destination_path)
    for entry in manifest["files"]:
        raw, source_stat = _read_relative_regular_nofollow(
            source_root, entry["path"])
        executable = entry["git_mode"] == "100755"
        if bool(source_stat.st_mode & 0o111) != executable \
                or len(raw) != entry["bytes"] \
                or _sha256(raw) != entry["raw_file_sha256"] \
                or _git_blob_sha1(raw) != entry["git_blob_sha1"]:
            raise J0Error(
                f"{manifest['project']}: source changed while snapshotting "
                f"{entry['path']}"
            )
        target = _safe_join(destination_path, entry["path"])
        _write_new_file(target, raw)
        if executable:
            os.chmod(target, 0o755)
    _validate_manifest_tree(destination_path, manifest)


def _mkdir_normalized(path: Path) -> None:
    path.mkdir(mode=0o755)
    os.chmod(path, 0o755)


def _write_new_file(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise J0Error(f"refusing existing output path: {path}")
    _mkdir_parents(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        try:
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(path, 0o644)
    except OSError as exc:
        raise J0Error(f"cannot create output {path}: {exc}") from exc


def _mkdir_parents(path: Path) -> None:
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            raise J0Error(f"cannot find existing output ancestor for {path}")
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise J0Error(f"output ancestor is not a real directory: {current}")
    for item in reversed(missing):
        _mkdir_normalized(item)


def write_canonical_json_new(path: os.PathLike[str] | str, value: Any) -> str:
    raw = canonical_json_bytes(value)
    _write_new_file(Path(path), raw)
    return _sha256(raw)


def _require_new_empty_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise J0Error(f"output is not a real directory: {path}")
        if any(path.iterdir()):
            raise J0Error(f"output directory is not empty: {path}")
        os.chmod(path, 0o755)
    else:
        _mkdir_parents(path.parent)
        _mkdir_normalized(path)


def _manifest_file_map(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    validate_source_archive_manifest(manifest)
    return {entry["path"]: entry for entry in manifest["files"]}


def _derive_composition_policy(
    sdk_manifest: Mapping[str, Any],
    testing_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    sdk_files = _manifest_file_map(sdk_manifest)
    testing_files = _manifest_file_map(testing_manifest)
    if sdk_manifest["project"] != "algorand-sdk" \
            or testing_manifest["project"] != "algorand-sdk-testing":
        raise J0Error("composer policy: wrong bound source projects")
    removed_prefixes = (
        "src/test/resources/com/algorand/algosdk/unit/",
        "src/test/resources/com/algorand/algosdk/integration/",
    )
    mappings: list[dict[str, Any]] = []
    destinations: dict[str, tuple[int, str]] = {}
    excluded: list[str] = []

    def install(project: str, source_path: str, destination_path: str) -> None:
        entries = sdk_files if project == "algorand-sdk" else testing_files
        entry = entries[source_path]
        pair = (entry["bytes"], entry["raw_file_sha256"])
        previous = destinations.get(destination_path)
        if previous is not None and previous != pair:
            raise J0Error(
                f"composer policy: non-identical collision at {destination_path}"
            )
        destinations[destination_path] = pair
        mappings.append({
            "bytes": entry["bytes"],
            "destination_path": destination_path,
            "raw_file_sha256": entry["raw_file_sha256"],
            "source_path": source_path,
            "source_project": project,
        })

    for path in sorted(sdk_files, key=lambda value: value.encode("utf-8")):
        if path.startswith(removed_prefixes):
            excluded.append(path)
        else:
            install("algorand-sdk", path, path)
    for path in sorted(testing_files, key=lambda value: value.encode("utf-8")):
        destination_path: str | None = None
        if path.startswith("features/unit/"):
            suffix = path[len("features/unit/"):]
            if suffix:
                destination_path = (
                    "src/test/resources/com/algorand/algosdk/integration/offline.feature"
                    if path == "features/unit/offline.feature"
                    else "src/test/resources/com/algorand/algosdk/unit/" + suffix
                )
        elif path.startswith("features/integration/"):
            suffix = path[len("features/integration/"):]
            if suffix:
                destination_path = (
                    "src/test/resources/com/algorand/algosdk/integration/" + suffix)
        elif path.startswith("features/resources/"):
            suffix = path[len("features/resources/"):]
            if suffix:
                destination_path = "src/test/resources/" + suffix
        if destination_path is not None:
            install("algorand-sdk-testing", path, destination_path)
    mappings.sort(key=lambda item: (
        item["destination_path"].encode("utf-8"),
        item["source_project"].encode("utf-8"),
        item["source_path"].encode("utf-8"),
    ))
    return {
        "destination_file_count": len(destinations),
        "destination_total_bytes": sum(size for size, _digest in destinations.values()),
        "excluded_sdk_paths": excluded,
        "mappings": mappings,
    }


def compose_algorand_offline(
    sdk_root: os.PathLike[str] | str,
    testing_root: os.PathLike[str] | str,
    sdk_manifest: Mapping[str, Any],
    testing_manifest: Mapping[str, Any],
    output: os.PathLike[str] | str,
) -> dict[str, Any]:
    """Compose the exact two pinned Algorand trees into an empty directory.

    This function never invokes Git or any external process.  Callers must
    authenticate manifests/checkouts first; every read here is rechecked
    against the manifest's size and raw SHA-256.
    """
    sdk_root = Path(sdk_root)
    testing_root = Path(testing_root)
    output = Path(output)
    _require_new_empty_directory(output)
    sdk_files = _manifest_file_map(sdk_manifest)
    testing_files = _manifest_file_map(testing_manifest)
    if sdk_manifest["project"] != "algorand-sdk":
        raise J0Error("composer: wrong SDK source manifest")
    if testing_manifest["project"] != "algorand-sdk-testing":
        raise J0Error("composer: wrong testing source manifest")

    source_roots = {
        "algorand-sdk": sdk_root,
        "algorand-sdk-testing": testing_root,
    }
    source_entries = {
        "algorand-sdk": sdk_files,
        "algorand-sdk-testing": testing_files,
    }

    def read_source(repo: str, rel: str) -> bytes:
        entry = source_entries[repo].get(rel)
        if entry is None:
            raise J0Error(f"composer: source path absent from manifest: {repo}:{rel}")
        raw, source_stat = _read_relative_regular_nofollow(source_roots[repo], rel)
        mode = source_stat.st_mode
        if not stat.S_ISREG(mode):
            raise J0Error(f"composer: non-regular source {repo}:{rel}")
        if len(raw) != entry["bytes"] or _sha256(raw) != entry["raw_file_sha256"]:
            raise J0Error(f"composer: source bytes drifted: {repo}:{rel}")
        return raw

    removed_prefixes = (
        "src/test/resources/com/algorand/algosdk/unit/",
        "src/test/resources/com/algorand/algosdk/integration/",
    )
    destination: dict[str, bytes] = {}
    mappings: list[dict[str, Any]] = []
    excluded_sdk_paths: list[str] = []

    def install(repo: str, source_path: str, destination_path: str) -> None:
        validate_posix_path(destination_path, where="composer.destination_path")
        raw = read_source(repo, source_path)
        previous = destination.get(destination_path)
        if previous is not None and previous != raw:
            raise J0Error(
                f"composer: non-identical destination collision at {destination_path}"
            )
        destination[destination_path] = raw
        mappings.append({
            "bytes": len(raw),
            "destination_path": destination_path,
            "raw_file_sha256": _sha256(raw),
            "source_path": source_path,
            "source_project": repo,
        })

    for path in sorted(sdk_files, key=lambda item: item.encode("utf-8")):
        if any(path.startswith(prefix) for prefix in removed_prefixes):
            excluded_sdk_paths.append(path)
            continue
        install("algorand-sdk", path, path)

    for path in sorted(testing_files, key=lambda item: item.encode("utf-8")):
        if path.startswith("features/unit/"):
            suffix = path[len("features/unit/"):]
            if not suffix:
                continue
            if path == "features/unit/offline.feature":
                dest = ("src/test/resources/com/algorand/algosdk/"
                        "integration/offline.feature")
            else:
                dest = "src/test/resources/com/algorand/algosdk/unit/" + suffix
            install("algorand-sdk-testing", path, dest)
        elif path.startswith("features/integration/"):
            suffix = path[len("features/integration/"):]
            if suffix:
                install(
                    "algorand-sdk-testing", path,
                    "src/test/resources/com/algorand/algosdk/integration/" + suffix,
                )
        elif path.startswith("features/resources/"):
            suffix = path[len("features/resources/"):]
            if suffix:
                install(
                    "algorand-sdk-testing", path,
                    "src/test/resources/" + suffix,
                )

    mappings.sort(key=lambda item: (
        item["destination_path"].encode("utf-8"),
        item["source_project"].encode("utf-8"),
        item["source_path"].encode("utf-8"),
    ))
    tree_inputs = sorted(destination.items(), key=lambda item: item[0].encode("utf-8"))
    for rel, raw in tree_inputs:
        _write_new_file(_safe_join(output, rel), raw)
    # Normalize all directories after materialization, including an existing
    # caller-created root whose umask might differ.
    for dirpath, dirnames, filenames in os.walk(output):
        del dirnames, filenames
        os.chmod(dirpath, 0o755)

    module_source, _ = _read_absolute_regular_nofollow(Path(__file__))
    manifest = {
        "composer_source_sha256": _sha256(module_source),
        "destination_file_count": len(destination),
        "destination_total_bytes": sum(len(raw) for raw in destination.values()),
        "destination_tree_digest_domain": TREE_DOMAIN,
        "destination_tree_sha256": framed_tree_sha256(tree_inputs),
        "excluded_sdk_paths": excluded_sdk_paths,
        "mappings": mappings,
        "schema": COMPOSITION_SCHEMA,
        "sources": [
            {
                "commit": sdk_manifest["commit"],
                "git_tree": sdk_manifest["git_tree"],
                "project": "algorand-sdk",
                "source_archive_manifest_sha256": _sha256(
                    canonical_json_bytes(dict(sdk_manifest))),
            },
            {
                "commit": testing_manifest["commit"],
                "git_tree": testing_manifest["git_tree"],
                "project": "algorand-sdk-testing",
                "source_archive_manifest_sha256": _sha256(
                    canonical_json_bytes(dict(testing_manifest))),
            },
        ],
    }
    validate_composition_manifest(manifest, sdk_manifest, testing_manifest)
    return manifest


def validate_composition_manifest(
    manifest: Any,
    sdk_manifest: Mapping[str, Any] | None = None,
    testing_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    obj = _closed(manifest, {
        "composer_source_sha256", "destination_file_count",
        "destination_total_bytes", "destination_tree_digest_domain",
        "destination_tree_sha256", "excluded_sdk_paths", "mappings", "schema",
        "sources",
    }, "composition")
    if obj["schema"] != COMPOSITION_SCHEMA:
        raise J0Error("composition.schema: wrong schema")
    _hex(obj["composer_source_sha256"], 64, "composition.composer_source_sha256")
    if obj["composer_source_sha256"] != _raw_sha256(Path(__file__)):
        raise J0Error("composition.composer_source_sha256: implementation drift")
    if obj["destination_tree_digest_domain"] != TREE_DOMAIN:
        raise J0Error("composition.destination_tree_digest_domain: mismatch")
    _hex(obj["destination_tree_sha256"], 64, "composition.destination_tree_sha256")
    _integer(obj["destination_file_count"], "composition.destination_file_count")
    _integer(obj["destination_total_bytes"], "composition.destination_total_bytes")
    if not isinstance(obj["excluded_sdk_paths"], list):
        raise J0Error("composition.excluded_sdk_paths: expected array")
    excluded = validate_path_set(obj["excluded_sdk_paths"],
                                 where="composition.excluded_sdk_paths")
    for path in excluded:
        if not path.startswith((
            "src/test/resources/com/algorand/algosdk/unit/",
            "src/test/resources/com/algorand/algosdk/integration/",
        )):
            raise J0Error("composition.excluded_sdk_paths: outside removed trees")
    if not isinstance(obj["sources"], list) or len(obj["sources"]) != 2:
        raise J0Error("composition.sources: expected two entries")
    expected_projects = ["algorand-sdk", "algorand-sdk-testing"]
    for index, source in enumerate(obj["sources"]):
        source = _closed(source, {
            "commit", "git_tree", "project", "source_archive_manifest_sha256",
        }, f"composition.sources[{index}]")
        project = expected_projects[index]
        if source["project"] != project:
            raise J0Error("composition.sources: wrong order/project")
        if source["commit"] != PINNED_REPOSITORIES[project]["commit"]:
            raise J0Error("composition.sources: wrong commit")
        if source["git_tree"] != PINNED_REPOSITORIES[project]["git_tree"]:
            raise J0Error("composition.sources: wrong tree")
        _hex(source["source_archive_manifest_sha256"], 64,
             f"composition.sources[{index}].source_archive_manifest_sha256")
    if not isinstance(obj["mappings"], list):
        raise J0Error("composition.mappings: expected array")
    destination_unique: dict[str, str] = {}
    last_sort: tuple[bytes, bytes, bytes] | None = None
    destinations: dict[str, tuple[int, str]] = {}
    for index, value in enumerate(obj["mappings"]):
        entry = _closed(value, {
            "bytes", "destination_path", "raw_file_sha256", "source_path",
            "source_project",
        }, f"composition.mappings[{index}]")
        dest = validate_posix_path(
            entry["destination_path"],
            where=f"composition.mappings[{index}].destination_path")
        source_path = validate_posix_path(
            entry["source_path"],
            where=f"composition.mappings[{index}].source_path")
        project = entry["source_project"]
        if project not in expected_projects:
            raise J0Error(f"composition.mappings[{index}].source_project: invalid")
        size = _integer(entry["bytes"], f"composition.mappings[{index}].bytes")
        digest = _hex(entry["raw_file_sha256"], 64,
                      f"composition.mappings[{index}].raw_file_sha256")
        key = (dest.encode("utf-8"), project.encode("utf-8"),
               source_path.encode("utf-8"))
        if last_sort is not None and key <= last_sort:
            raise J0Error("composition.mappings: not strictly canonical sorted")
        last_sort = key
        if dest in destinations and destinations[dest] != (size, digest):
            raise J0Error("composition.mappings: non-identical collision")
        destinations[dest] = (size, digest)
        normalized = unicodedata.normalize("NFC", dest)
        if normalized in destination_unique and destination_unique[normalized] != dest:
            raise J0Error("composition.mappings: destination NFC collision")
        destination_unique[normalized] = dest
    if obj["destination_file_count"] != len(destinations):
        raise J0Error("composition.destination_file_count: mismatch")
    if obj["destination_total_bytes"] != sum(size for size, _ in destinations.values()):
        raise J0Error("composition.destination_total_bytes: mismatch")
    if sdk_manifest is None or testing_manifest is None:
        raise J0Error(
            "composition: both pinned source manifests are required for exact policy")
    policy = _derive_composition_policy(sdk_manifest, testing_manifest)
    for key in (
            "destination_file_count", "destination_total_bytes",
            "excluded_sdk_paths", "mappings"):
        if obj[key] != policy[key]:
            raise J0Error(f"composition.{key}: derived source policy mismatch")
    expected_sources = [
        {
            "commit": sdk_manifest["commit"],
            "git_tree": sdk_manifest["git_tree"],
            "project": "algorand-sdk",
            "source_archive_manifest_sha256": _sha256(
                canonical_json_bytes(dict(sdk_manifest))),
        },
        {
            "commit": testing_manifest["commit"],
            "git_tree": testing_manifest["git_tree"],
            "project": "algorand-sdk-testing",
            "source_archive_manifest_sha256": _sha256(
                canonical_json_bytes(dict(testing_manifest))),
        },
    ]
    if obj["sources"] != expected_sources:
        raise J0Error("composition.sources: bound source-manifest mismatch")
    return obj


def validate_composed_tree(
    workspace: os.PathLike[str] | str,
    manifest: Mapping[str, Any],
    sdk_manifest: Mapping[str, Any] | None = None,
    testing_manifest: Mapping[str, Any] | None = None,
) -> None:
    validate_composition_manifest(manifest, sdk_manifest, testing_manifest)
    workspace = Path(workspace)
    physical = _walk_checkout(workspace)
    # _walk_checkout excludes a top-level .git; a composed workspace may not
    # contain one at all, so catch it explicitly rather than silently pruning.
    if (workspace / ".git").exists() or (workspace / ".git").is_symlink():
        raise J0Error("composed workspace unexpectedly contains .git")
    expected: dict[str, tuple[int, str]] = {}
    for entry in manifest["mappings"]:
        expected[entry["destination_path"]] = (
            entry["bytes"], entry["raw_file_sha256"])
    if set(physical) != set(expected):
        raise J0Error("composed workspace path set mismatch")
    tree_inputs: list[tuple[str, bytes]] = []
    for path in sorted(expected, key=lambda item: item.encode("utf-8")):
        raw, target_stat = _read_relative_regular_nofollow(workspace, path)
        mode = stat.S_IMODE(target_stat.st_mode)
        if mode != 0o644:
            raise J0Error(f"composed workspace file mode is not 0644: {path}")
        size, digest = expected[path]
        if len(raw) != size or _sha256(raw) != digest:
            raise J0Error(f"composed workspace bytes mismatch: {path}")
        tree_inputs.append((path, raw))
    for dirpath, dirnames, filenames in os.walk(workspace):
        del dirnames, filenames
        mode = stat.S_IMODE(os.lstat(dirpath).st_mode)
        if mode != 0o755:
            raise J0Error(f"composed workspace directory mode is not 0755: {dirpath}")
    actual_tree = framed_tree_sha256(tree_inputs)
    if actual_tree != manifest["destination_tree_sha256"]:
        raise J0Error("composed workspace framed tree digest mismatch")


def _parser_source_path() -> Path:
    return Path(__file__).with_name("J0GherkinBridge.java")


def _protocol_path() -> Path:
    return Path(__file__).resolve().parents[2] / "J0_JVM_TIMING_PROTOCOL.md"


def _authenticate_parser_inputs(
    project: str,
    artifact_paths: Sequence[os.PathLike[str] | str],
) -> tuple[dict[str, Any], list[bytes], bytes]:
    if project not in PARSER_STACKS:
        raise J0Error(f"no Phase-A parser stack for {project}")
    spec = PARSER_STACKS[project]
    if len(artifact_paths) != len(spec["artifacts"]):
        raise J0Error(
            f"{project}: parser requires {len(spec['artifacts'])} exact artifacts"
        )
    artifacts: list[dict[str, Any]] = []
    artifact_bytes: list[bytes] = []
    for index, (provided, expected) in enumerate(zip(artifact_paths, spec["artifacts"])):
        try:
            raw, artifact_stat = _read_absolute_regular_nofollow(provided)
        except (OSError, J0Error) as exc:
            raise J0Error(f"{project}: parser artifact {index} unavailable: {exc}") from exc
        if not stat.S_ISREG(artifact_stat.st_mode):
            raise J0Error(f"{project}: parser artifact {index} is not a regular file")
        actual = _sha256(raw)
        if actual != expected["sha256"]:
            raise J0Error(
                f"{project}: wrong parser artifact {expected['coordinate']} digest "
                f"{actual}; expected {expected['sha256']}"
            )
        artifacts.append({
            "bytes": len(raw),
            "coordinate": expected["coordinate"],
            "raw_file_sha256": actual,
        })
        artifact_bytes.append(raw)
    bridge_source = _parser_source_path()
    bridge_raw, bridge_stat = _read_absolute_regular_nofollow(bridge_source)
    if not stat.S_ISREG(bridge_stat.st_mode):
        raise J0Error("J0 Gherkin bridge source is unavailable or non-regular")
    identity = {
        "adapter": spec["adapter"],
        "artifacts": artifacts,
        "bridge_source_sha256": _sha256(bridge_raw),
        "cucumber_version": spec["cucumber_version"],
        "gherkin_version": spec["gherkin_version"],
    }
    validate_parser_identity(identity, project)
    return identity, artifact_bytes, bridge_raw


def parser_identity(
    project: str,
    artifact_paths: Sequence[os.PathLike[str] | str],
) -> dict[str, Any]:
    identity, _artifacts, _bridge = _authenticate_parser_inputs(
        project, artifact_paths)
    return identity


def validate_parser_identity(identity: Any, project: str) -> dict[str, Any]:
    obj = _closed(identity, {
        "adapter", "artifacts", "bridge_source_sha256", "cucumber_version",
        "gherkin_version",
    }, "parser_identity")
    if project not in PARSER_STACKS:
        raise J0Error("parser_identity: unknown project")
    spec = PARSER_STACKS[project]
    for key in ("adapter", "cucumber_version", "gherkin_version"):
        if obj[key] != spec[key]:
            raise J0Error(f"parser_identity.{key}: mismatch")
    _hex(obj["bridge_source_sha256"], 64, "parser_identity.bridge_source_sha256")
    if obj["bridge_source_sha256"] != _raw_sha256(_parser_source_path()):
        raise J0Error("parser_identity.bridge_source_sha256: implementation drift")
    if not isinstance(obj["artifacts"], list) \
            or len(obj["artifacts"]) != len(spec["artifacts"]):
        raise J0Error("parser_identity.artifacts: wrong cardinality")
    for index, (value, expected) in enumerate(zip(obj["artifacts"], spec["artifacts"])):
        entry = _closed(value, {"bytes", "coordinate", "raw_file_sha256"},
                        f"parser_identity.artifacts[{index}]")
        if entry["coordinate"] != expected["coordinate"] \
                or entry["raw_file_sha256"] != expected["sha256"]:
            raise J0Error(f"parser_identity.artifacts[{index}]: pin mismatch")
        _integer(entry["bytes"], f"parser_identity.artifacts[{index}].bytes", minimum=1)
        _hex(entry["raw_file_sha256"], 64,
             f"parser_identity.artifacts[{index}].raw_file_sha256")
    return obj


def _compile_parser_bridge(destination: Path, source_snapshot: Path) -> None:
    _require_new_empty_directory(destination)
    command = [
        JAVAC_EXECUTABLE, "-encoding", "UTF-8", "-d", str(destination),
        str(source_snapshot),
    ]
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=False,
                              env=_closed_process_environment(java=True))
    except OSError as exc:
        raise J0Error(f"cannot execute javac for pinned Gherkin bridge: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace")
        raise J0Error(f"J0 Gherkin bridge compilation failed: {detail.strip()}")
    produced: list[str] = []
    for path in destination.rglob("*"):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise J0Error("javac produced a symlink/non-regular bridge entry")
        if path.is_file():
            produced.append(path.relative_to(destination).as_posix())
    produced.sort(key=lambda value: value.encode("utf-8"))
    if produced != ["J0GherkinBridge$Parsed.class", "J0GherkinBridge.class"]:
        raise J0Error(f"javac produced unexpected bridge classes: {produced!r}")


class GherkinParserBridge:
    """One temporary no-Maven compiler/runtime for both pinned adapters."""

    def __init__(self) -> None:
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._root: Path | None = None
        self.classes: Path | None = None
        self._bridge_source_bytes: bytes | None = None
        self._artifact_inputs: dict[str, tuple[str, ...]] = {}
        self._artifact_snapshots: dict[str, tuple[Path, ...]] = {}
        self._identities: dict[str, dict[str, Any]] = {}
        self._source_counter = 0

    def __enter__(self) -> "GherkinParserBridge":
        if self._temporary is not None:
            raise J0Error("GherkinParserBridge cannot be entered twice")
        self._temporary = tempfile.TemporaryDirectory(prefix="r2t-j0-gherkin-")
        self._root = Path(self._temporary.name)
        bridge_raw, _ = _read_absolute_regular_nofollow(_parser_source_path())
        source_snapshot = self._root / "source" / "J0GherkinBridge.java"
        _write_new_file(source_snapshot, bridge_raw)
        snapshot_raw, _ = _read_absolute_regular_nofollow(source_snapshot)
        if snapshot_raw != bridge_raw:
            raise J0Error("Gherkin bridge source snapshot changed")
        self._bridge_source_bytes = bridge_raw
        self.classes = self._root / "classes"
        _compile_parser_bridge(self.classes, source_snapshot)
        final_bridge, _ = _read_absolute_regular_nofollow(_parser_source_path())
        if final_bridge != bridge_raw:
            raise J0Error("Gherkin bridge source changed during compilation")
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            if exc_type is None:
                self.revalidate_inputs()
        finally:
            if self._temporary is not None:
                self._temporary.cleanup()
            self._temporary = None
            self._root = None
            self.classes = None
            self._bridge_source_bytes = None
            self._artifact_inputs.clear()
            self._artifact_snapshots.clear()
            self._identities.clear()

    def _prepare_stack(
        self,
        project: str,
        artifact_paths: Sequence[os.PathLike[str] | str],
    ) -> tuple[dict[str, Any], tuple[Path, ...]]:
        if self._root is None or self.classes is None:
            raise J0Error("GherkinParserBridge is not active")
        normalized = tuple(os.path.abspath(os.fspath(path)) for path in artifact_paths)
        if project in self._identities:
            if normalized != self._artifact_inputs[project]:
                raise J0Error(f"{project}: parser artifact pathname set changed")
            return self._identities[project], self._artifact_snapshots[project]
        identity, raw_artifacts, bridge_raw = _authenticate_parser_inputs(
            project, artifact_paths)
        if bridge_raw != self._bridge_source_bytes:
            raise J0Error("Gherkin bridge source identity changed before parser setup")
        jar_root = self._root / "jars" / project
        _require_new_empty_directory(jar_root)
        snapshots: list[Path] = []
        for index, (raw, expected) in enumerate(zip(
                raw_artifacts, PARSER_STACKS[project]["artifacts"])):
            snapshot = jar_root / f"{index:02d}.jar"
            _write_new_file(snapshot, raw)
            copied, _ = _read_absolute_regular_nofollow(snapshot)
            if copied != raw or _sha256(copied) != expected["sha256"]:
                raise J0Error(f"{project}: parser JAR snapshot changed")
            snapshots.append(snapshot)
        self._artifact_inputs[project] = normalized
        self._artifact_snapshots[project] = tuple(snapshots)
        self._identities[project] = identity
        return identity, tuple(snapshots)

    def identity(
        self,
        project: str,
        artifact_paths: Sequence[os.PathLike[str] | str],
    ) -> dict[str, Any]:
        identity, _snapshots = self._prepare_stack(project, artifact_paths)
        return dict(identity)

    def revalidate_inputs(self) -> None:
        if self._bridge_source_bytes is not None:
            current, _ = _read_absolute_regular_nofollow(_parser_source_path())
            if current != self._bridge_source_bytes:
                raise J0Error("Gherkin bridge source changed during parser session")
        for project, original_paths in self._artifact_inputs.items():
            if parser_identity(project, original_paths) != self._identities[project]:
                raise J0Error(f"{project}: original parser artifacts changed")
            for snapshot, expected in zip(
                    self._artifact_snapshots[project],
                    PARSER_STACKS[project]["artifacts"]):
                raw, _ = _read_absolute_regular_nofollow(snapshot)
                if _sha256(raw) != expected["sha256"]:
                    raise J0Error(f"{project}: parser artifact snapshot changed")

    def parse(
        self,
        project: str,
        source_path: os.PathLike[str] | str,
        source_uri: str,
        artifact_paths: Sequence[os.PathLike[str] | str],
    ) -> dict[str, Any]:
        if self.classes is None:
            raise J0Error("GherkinParserBridge is not active")
        validate_posix_path(source_uri, where="parser.source_uri")
        _identity, snapshot_artifacts = self._prepare_stack(project, artifact_paths)
        try:
            raw, source_stat = _read_absolute_regular_nofollow(source_path)
        except (OSError, J0Error) as exc:
            raise J0Error(f"cannot authenticate Gherkin source {source_uri}: {exc}") from exc
        if not stat.S_ISREG(source_stat.st_mode):
            raise J0Error(f"Gherkin source is not regular: {source_uri}")
        try:
            raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise J0Error(f"Gherkin source is not strict UTF-8: {source_uri}") from exc
        if b"\r" in raw:
            raise J0Error(f"Gherkin source must use LF, not CR: {source_uri}")
        if self._root is None:
            raise J0Error("GherkinParserBridge lost its private root")
        parse_snapshot = self._root / "parse-sources" / f"{self._source_counter:06d}.feature"
        self._source_counter += 1
        _write_new_file(parse_snapshot, raw)
        stack = PARSER_STACKS[project]
        classpath = os.pathsep.join(
            [str(self.classes), *(str(path) for path in snapshot_artifacts)]
        )
        command = [
            JAVA_EXECUTABLE, "-Dfile.encoding=UTF-8", "-cp", classpath,
            "J0GherkinBridge", stack["bridge_mode"], source_uri, str(parse_snapshot),
        ]
        try:
            proc = subprocess.run(command, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, check=False,
                                  env=_closed_process_environment(java=True))
        except OSError as exc:
            raise J0Error(f"cannot execute Java Gherkin bridge: {exc}") from exc
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", errors="replace").strip()
            raise J0Error(f"pinned Gherkin parser refused {source_uri}: {detail}")
        if proc.stderr:
            raise J0Error(f"pinned Gherkin parser wrote unexpected stderr: {source_uri}")
        ast = load_canonical_json_bytes(proc.stdout, where=f"AST {source_uri}")
        validate_bridge_ast(ast, source_uri)
        after_source, _ = _read_absolute_regular_nofollow(source_path)
        snapshot_source, _ = _read_absolute_regular_nofollow(parse_snapshot)
        if after_source != raw or snapshot_source != raw:
            raise J0Error(f"Gherkin source changed during parse: {source_uri}")
        return ast

    def evaluate_tag_expression(
        self,
        project: str,
        expression: str,
        tags: Sequence[str],
        artifact_paths: Sequence[os.PathLike[str] | str],
    ) -> bool:
        """Evaluate through the project Cucumber version's pinned tag JAR."""
        if self.classes is None:
            raise J0Error("GherkinParserBridge is not active")
        _string(expression, "tag_expression")
        for index, tag in enumerate(tags):
            if not GHERKIN_TAG.fullmatch(tag):
                raise J0Error(f"tag_expression.tags[{index}]: invalid Gherkin tag")
        _identity, snapshot_artifacts = self._prepare_stack(project, artifact_paths)
        classpath = os.pathsep.join(
            [str(self.classes), *(str(path) for path in snapshot_artifacts)]
        )
        command = [
            JAVA_EXECUTABLE, "-Dfile.encoding=UTF-8", "-cp", classpath,
            "J0GherkinBridge", "tag", expression, *tags,
        ]
        try:
            proc = subprocess.run(command, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, check=False,
                                  env=_closed_process_environment(java=True))
        except OSError as exc:
            raise J0Error(f"cannot execute pinned tag-expression adapter: {exc}") from exc
        if proc.returncode != 0 or proc.stderr or proc.stdout not in {b"true\n", b"false\n"}:
            detail = proc.stderr.decode("utf-8", errors="replace").strip()
            raise J0Error(f"pinned tag-expression adapter refused: {detail}")
        return proc.stdout == b"true\n"

    def qualify_generated_or(
        self,
        project: str,
        expression: str,
        atoms: Sequence[str],
        artifact_paths: Sequence[os.PathLike[str] | str],
    ) -> dict[str, Any]:
        """Bind the restricted OR evaluator to Cucumber's exact implementation.

        Phase A generates only ``(tag) or (tag)`` expressions.  The Python
        census can therefore use set intersection after the pinned parser has
        accepted the full expression and agreed on empty, foreign, endpoint,
        and all-atom witnesses.
        """
        if not atoms:
            raise J0Error("tag-expression qualification requires atoms")
        cases = [
            {"expected": False, "tags": []},
            {"expected": False, "tags": ["@r2t.phase_a.foreign"]},
            {"expected": True, "tags": [atoms[0]]},
            {"expected": True, "tags": [atoms[-1]]},
            {"expected": True, "tags": list(atoms)},
        ]
        for case in cases:
            actual = self.evaluate_tag_expression(
                project, expression, case["tags"], artifact_paths)
            if actual != case["expected"]:
                raise J0Error(
                    "pinned Cucumber tag-expression semantics disagree with "
                    "the generated-OR evaluator")
        evidence = {
            "cases": cases,
            "evaluator": "cucumber-generated-or-membership/r2t-1",
            "expression": expression,
            "schema": "r2t.java-j0-tag-expression-qualification/1",
        }
        validate_tag_expression_qualification(evidence)
        return evidence


def _validate_location(value: Any, where: str) -> dict[str, Any]:
    obj = _closed(value, {"column", "line"}, where)
    _integer(obj["line"], f"{where}.line", minimum=1)
    _integer(obj["column"], f"{where}.column", minimum=1)
    return obj


def _validate_ast_tags(value: Any, where: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise J0Error(f"{where}: expected array")
    out: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        obj = _closed(item, {"location", "name"}, f"{where}[{index}]")
        _validate_location(obj["location"], f"{where}[{index}].location")
        name = _string(obj["name"], f"{where}[{index}].name")
        if not GHERKIN_TAG.fullmatch(name):
            raise J0Error(f"{where}[{index}].name: invalid tag")
        out.append(obj)
    return out


def _validate_ast_step(value: Any, where: str) -> dict[str, Any]:
    obj = _closed(value, {"keyword", "location", "text"}, where)
    _string(obj["keyword"], f"{where}.keyword")
    _string(obj["text"], f"{where}.text", nonempty=False)
    _validate_location(obj["location"], f"{where}.location")
    return obj


def _validate_ast_row(value: Any, where: str) -> dict[str, Any]:
    obj = _closed(value, {"cells", "location"}, where)
    _validate_location(obj["location"], f"{where}.location")
    if not isinstance(obj["cells"], list) or not obj["cells"]:
        raise J0Error(f"{where}.cells: expected nonempty array")
    for index, value in enumerate(obj["cells"]):
        cell = _closed(value, {"location", "value"}, f"{where}.cells[{index}]")
        _validate_location(cell["location"], f"{where}.cells[{index}].location")
        _string(cell["value"], f"{where}.cells[{index}].value", nonempty=False)
    return obj


def _validate_ast_examples(value: Any, where: str) -> dict[str, Any]:
    obj = _closed(value, {
        "description", "keyword", "location", "name", "table_body",
        "table_header", "tags", "type",
    }, where)
    if obj["type"] != "examples":
        raise J0Error(f"{where}.type: expected examples")
    for key in ("description", "keyword", "name"):
        _string(obj[key], f"{where}.{key}", nonempty=(key == "keyword"))
    _validate_location(obj["location"], f"{where}.location")
    _validate_ast_tags(obj["tags"], f"{where}.tags")
    if obj["table_header"] is None:
        if obj["table_body"]:
            raise J0Error(f"{where}: body without header")
    else:
        _validate_ast_row(obj["table_header"], f"{where}.table_header")
    if not isinstance(obj["table_body"], list):
        raise J0Error(f"{where}.table_body: expected array")
    for index, row in enumerate(obj["table_body"]):
        _validate_ast_row(row, f"{where}.table_body[{index}]")
    return obj


def _validate_ast_scenario(value: Any, where: str) -> dict[str, Any]:
    obj = _closed(value, {
        "description", "examples", "keyword", "location", "name", "steps",
        "tags", "type",
    }, where)
    if obj["type"] != "scenario":
        raise J0Error(f"{where}.type: expected scenario")
    for key in ("description", "keyword", "name"):
        _string(obj[key], f"{where}.{key}", nonempty=(key == "keyword"))
    _validate_location(obj["location"], f"{where}.location")
    _validate_ast_tags(obj["tags"], f"{where}.tags")
    if not isinstance(obj["steps"], list):
        raise J0Error(f"{where}.steps: expected array")
    for index, step in enumerate(obj["steps"]):
        _validate_ast_step(step, f"{where}.steps[{index}]")
    if not isinstance(obj["examples"], list):
        raise J0Error(f"{where}.examples: expected array")
    for index, examples in enumerate(obj["examples"]):
        _validate_ast_examples(examples, f"{where}.examples[{index}]")
    return obj


def _validate_ast_background(value: Any, where: str) -> dict[str, Any]:
    obj = _closed(value, {
        "description", "keyword", "location", "name", "steps", "type",
    }, where)
    if obj["type"] != "background":
        raise J0Error(f"{where}.type: expected background")
    for key in ("description", "keyword", "name"):
        _string(obj[key], f"{where}.{key}", nonempty=(key == "keyword"))
    _validate_location(obj["location"], f"{where}.location")
    if not isinstance(obj["steps"], list):
        raise J0Error(f"{where}.steps: expected array")
    for index, step in enumerate(obj["steps"]):
        _validate_ast_step(step, f"{where}.steps[{index}]")
    return obj


def _validate_ast_rule(value: Any, where: str) -> dict[str, Any]:
    obj = _closed(value, {
        "children", "description", "keyword", "location", "name", "tags", "type",
    }, where)
    if obj["type"] != "rule":
        raise J0Error(f"{where}.type: expected rule")
    for key in ("description", "keyword", "name"):
        _string(obj[key], f"{where}.{key}", nonempty=(key == "keyword"))
    _validate_location(obj["location"], f"{where}.location")
    _validate_ast_tags(obj["tags"], f"{where}.tags")
    if not isinstance(obj["children"], list):
        raise J0Error(f"{where}.children: expected array")
    for index, child in enumerate(obj["children"]):
        if not isinstance(child, dict):
            raise J0Error(f"{where}.children[{index}]: expected object")
        if child.get("type") == "scenario":
            _validate_ast_scenario(child, f"{where}.children[{index}]")
        elif child.get("type") == "background":
            _validate_ast_background(child, f"{where}.children[{index}]")
        else:
            raise J0Error(f"{where}.children[{index}]: invalid RuleChild")
    return obj


def _validate_bridge_pickle(value: Any, where: str) -> dict[str, Any]:
    obj = _closed(value, {
        "ast_node_refs", "effective_tags", "language", "name",
    }, where)
    _string(obj["language"], f"{where}.language")
    _string(obj["name"], f"{where}.name", nonempty=False)
    _validate_tags_array(obj["effective_tags"], f"{where}.effective_tags")
    if not isinstance(obj["ast_node_refs"], list):
        raise J0Error(f"{where}.ast_node_refs: expected array")
    kinds: list[str] = []
    encoded: list[bytes] = []
    for index, value in enumerate(obj["ast_node_refs"]):
        ref = _closed(value, {"kind", "location"},
                      f"{where}.ast_node_refs[{index}]")
        if ref["kind"] not in {"Scenario", "ExamplesRow"}:
            raise J0Error(f"{where}.ast_node_refs[{index}].kind: invalid Pickle ref")
        _validate_location(ref["location"],
                           f"{where}.ast_node_refs[{index}].location")
        kinds.append(ref["kind"])
        encoded.append(canonical_json_bytes(ref, terminal_lf=False))
    if kinds.count("Scenario") != 1 or kinds.count("ExamplesRow") > 1 \
            or len(kinds) not in {1, 2}:
        raise J0Error(f"{where}.ast_node_refs: expected Scenario plus optional row")
    if encoded != sorted(encoded) or len(encoded) != len(set(encoded)):
        raise J0Error(f"{where}.ast_node_refs: not unique canonical sorted")
    return obj


def validate_bridge_ast(ast: Any, source_uri: str) -> dict[str, Any]:
    obj = _closed(ast, {"feature", "pickles", "schema", "uri"}, "bridge_ast")
    if obj["schema"] != PARSER_AST_SCHEMA:
        raise J0Error("bridge_ast.schema: mismatch")
    if obj["uri"] != source_uri:
        raise J0Error("bridge_ast.uri: mismatch")
    feature = _closed(obj["feature"], {
        "children", "description", "keyword", "language", "location", "name",
        "tags", "type",
    }, "bridge_ast.feature")
    if feature["type"] != "feature":
        raise J0Error("bridge_ast.feature.type: expected feature")
    for key in ("description", "keyword", "language", "name"):
        _string(feature[key], f"bridge_ast.feature.{key}",
                nonempty=(key in {"keyword", "language"}))
    _validate_location(feature["location"], "bridge_ast.feature.location")
    _validate_ast_tags(feature["tags"], "bridge_ast.feature.tags")
    if not isinstance(feature["children"], list):
        raise J0Error("bridge_ast.feature.children: expected array")
    for index, child in enumerate(feature["children"]):
        if not isinstance(child, dict):
            raise J0Error(f"bridge_ast.feature.children[{index}]: expected object")
        child_type = child.get("type")
        if child_type == "scenario":
            _validate_ast_scenario(child, f"bridge_ast.feature.children[{index}]")
        elif child_type == "background":
            _validate_ast_background(child, f"bridge_ast.feature.children[{index}]")
        elif child_type == "rule":
            _validate_ast_rule(child, f"bridge_ast.feature.children[{index}]")
        else:
            raise J0Error(f"bridge_ast.feature.children[{index}]: invalid FeatureChild")
    if not isinstance(obj["pickles"], list):
        raise J0Error("bridge_ast.pickles: expected array")
    encoded_pickles: list[bytes] = []
    for index, pickle in enumerate(obj["pickles"]):
        _validate_bridge_pickle(pickle, f"bridge_ast.pickles[{index}]")
        encoded_pickles.append(canonical_json_bytes(pickle, terminal_lf=False))
    if encoded_pickles != sorted(encoded_pickles):
        raise J0Error("bridge_ast.pickles: not canonical sorted")
    return obj


def _parse_unit_tags_bytes(raw: bytes) -> tuple[list[str], str]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise J0Error("Algorand unit.tags is not strict UTF-8") from exc
    if "\r" in text or (text and not text.endswith("\n")):
        raise J0Error("Algorand unit.tags must use LF and end in LF")
    tags: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        if not TAG.fullmatch(line):
            raise J0Error(f"Algorand unit.tags line {line_number}: invalid tag")
        if line in tags:
            raise J0Error(f"Algorand unit.tags line {line_number}: duplicate tag")
        tags.append(line)
    if not tags:
        raise J0Error("Algorand unit.tags contains no tags")
    tags.sort(key=lambda item: item.encode("utf-8"))
    expression = "(" + ") or (".join(tags) + ")"
    return tags, expression


def read_unit_tags(sdk_root: os.PathLike[str] | str) -> tuple[list[str], str, str]:
    raw, _ = _read_relative_regular_nofollow(sdk_root, "src/test/unit.tags")
    digest = _sha256(raw)
    if digest != UNIT_TAGS_SHA256:
        raise J0Error(
            f"Algorand unit.tags digest {digest}; expected {UNIT_TAGS_SHA256}")
    tags, expression = _parse_unit_tags_bytes(raw)
    return tags, expression, digest


def validate_tag_expression_qualification(value: Any) -> dict[str, Any]:
    obj = _closed(value, {"cases", "evaluator", "expression", "schema"},
                  "tag_expression_qualification")
    if obj["schema"] != "r2t.java-j0-tag-expression-qualification/1" \
            or obj["evaluator"] != "cucumber-generated-or-membership/r2t-1":
        raise J0Error("tag_expression_qualification: wrong schema/evaluator")
    expression = _string(obj["expression"],
                         "tag_expression_qualification.expression")
    if not expression.startswith("(") or not expression.endswith(")"):
        raise J0Error("tag_expression_qualification.expression: malformed")
    atoms = expression[1:-1].split(") or (")
    if not atoms or any(not TAG.fullmatch(atom) for atom in atoms) \
            or atoms != sorted(atoms, key=lambda item: item.encode("utf-8")) \
            or len(atoms) != len(set(atoms)):
        raise J0Error("tag_expression_qualification.expression: invalid atoms")
    expected = [
        {"expected": False, "tags": []},
        {"expected": False, "tags": ["@r2t.phase_a.foreign"]},
        {"expected": True, "tags": [atoms[0]]},
        {"expected": True, "tags": [atoms[-1]]},
        {"expected": True, "tags": atoms},
    ]
    if not isinstance(obj["cases"], list):
        raise J0Error("tag_expression_qualification.cases: expected array")
    for index, case in enumerate(obj["cases"]):
        entry = _closed(case, {"expected", "tags"},
                        f"tag_expression_qualification.cases[{index}]")
        if not isinstance(entry["expected"], bool) or not isinstance(entry["tags"], list):
            raise J0Error(f"tag_expression_qualification.cases[{index}]: wrong types")
        for tag_index, tag in enumerate(entry["tags"]):
            if not isinstance(tag, str) or not GHERKIN_TAG.fullmatch(tag):
                raise J0Error(
                    f"tag_expression_qualification.cases[{index}].tags[{tag_index}]: invalid")
    if obj["cases"] != expected:
        raise J0Error("tag_expression_qualification.cases: witness set mismatch")
    return obj


def _tag_names(node: Mapping[str, Any]) -> list[str]:
    return [tag["name"] for tag in node.get("tags", [])]


def _sorted_unique_strings(values: Iterable[str]) -> list[str]:
    return sorted(set(values), key=lambda item: item.encode("utf-8"))


def _structural_key(
    source_uri: str,
    kind: str,
    location: Mapping[str, int],
    parent: list[Any] | None,
    ordinal: int,
) -> list[Any]:
    return [source_uri, kind, location["line"], location["column"], parent, ordinal]


def _scenario_form(node: Mapping[str, Any]) -> str:
    keyword = node["keyword"].strip()
    if node["examples"] or keyword in {"Scenario Outline", "Scenario Template"}:
        return "outline"
    if keyword in {"Scenario", "Example"}:
        return "plain"
    raise J0Error(f"unsupported English scenario keyword: {keyword!r}")


def _flatten_scenarios(
    ast: Mapping[str, Any],
    source_uri: str,
    runtime_uri: str,
    admitted_tags: set[str] | None,
) -> list[dict[str, Any]]:
    feature = ast["feature"]
    feature_key = _structural_key(
        source_uri, "Feature", feature["location"], None, 0)
    feature_tags = _tag_names(feature)
    results: list[dict[str, Any]] = []

    def visit(children: Sequence[Mapping[str, Any]], parent_key: list[Any],
              inherited_tags: list[str]) -> None:
        same_kind: dict[str, int] = {}
        for child in children:
            if child["type"] == "background":
                kind = "Background"
            elif child["type"] == "rule":
                kind = "Rule"
            elif child["type"] == "scenario":
                kind = "ScenarioOutline" if _scenario_form(child) == "outline" else "Scenario"
            else:  # already rejected by AST validator
                raise J0Error(f"unknown AST child type: {child['type']}")
            ordinal = same_kind.get(kind, 0)
            same_kind[kind] = ordinal + 1
            key = _structural_key(source_uri, kind, child["location"],
                                  parent_key, ordinal)
            if child["type"] == "background":
                continue
            if child["type"] == "rule":
                visit(child["children"], key,
                      inherited_tags + _tag_names(child))
                continue

            form = _scenario_form(child)
            scenario_tags = _sorted_unique_strings(
                inherited_tags + _tag_names(child))
            steps: list[dict[str, Any]] = []
            for step_ordinal, step in enumerate(child["steps"]):
                step_key = _structural_key(
                    source_uri, "Step", step["location"], key, step_ordinal)
                steps.append({
                    "column": step["location"]["column"],
                    "keyword": step["keyword"],
                    "line": step["location"]["line"],
                    "structural_key": step_key,
                    "text": step["text"],
                })
            rows: list[dict[str, Any]] = []
            for examples_ordinal, examples in enumerate(child["examples"]):
                examples_key = _structural_key(
                    source_uri, "Examples", examples["location"], key,
                    examples_ordinal)
                effective = _sorted_unique_strings(
                    scenario_tags + _tag_names(examples))
                header = examples["table_header"]
                if header is None and examples["table_body"]:
                    raise J0Error(f"{source_uri}: Examples body without header")
                if header is not None:
                    width = len(header["cells"])
                    if width == 0:
                        raise J0Error(f"{source_uri}: empty Examples header")
                    for row_ordinal, row in enumerate(examples["table_body"]):
                        if len(row["cells"]) != width:
                            raise J0Error(
                                f"{source_uri}:{row['location']['line']}: ragged Examples row"
                            )
                        row_key = _structural_key(
                            source_uri, "ExamplesRow", row["location"],
                            examples_key, row_ordinal)
                        admitted = admitted_tags is None or bool(
                            admitted_tags.intersection(effective))
                        rows.append({
                            "admitted": admitted,
                            "case_key": [runtime_uri, key, row_key],
                            "column": row["location"]["column"],
                            "effective_tags": effective,
                            "examples_key": examples_key,
                            "examples_keyword": examples["keyword"],
                            "examples_name": examples["name"],
                            "exclusion_reason": None if admitted else "tag_expression_no_match",
                            "line": row["location"]["line"],
                            "raw_cells": [cell["value"] for cell in row["cells"]],
                            "row_ordinal": row_ordinal,
                            "structural_key": row_key,
                        })
            if form == "plain":
                admitted = admitted_tags is None or bool(
                    admitted_tags.intersection(scenario_tags))
                case_keys = [[runtime_uri, key, None]] if admitted else []
            else:
                admitted = any(row["admitted"] for row in rows)
                case_keys = [row["case_key"] for row in rows if row["admitted"]]
            results.append({
                "admitted": admitted,
                "case_keys": case_keys,
                "column": child["location"]["column"],
                "effective_tags": scenario_tags,
                "exclusion_reason": None if admitted else (
                    "tag_expression_no_match" if admitted_tags is not None
                    else "outline_has_no_examples_rows"),
                "form": form,
                "item_id": None,
                "keyword": child["keyword"],
                "line": child["location"]["line"],
                "name": child["name"],
                "rows": rows,
                "runtime_uri": runtime_uri,
                "source_uri": source_uri,
                "steps": steps,
                "structural_key": key,
            })

    visit(feature["children"], feature_key, feature_tags)
    return results


def load_frozen_java_items(items_path: os.PathLike[str] | str) \
        -> tuple[dict[str, list[dict[str, Any]]], str]:
    try:
        raw, items_stat = _read_absolute_regular_nofollow(items_path)
    except (OSError, J0Error) as exc:
        raise J0Error(f"cannot read frozen items.jsonl: {exc}") from exc
    if not stat.S_ISREG(items_stat.st_mode):
        raise J0Error("frozen items.jsonl is not a regular file")
    digest = _sha256(raw)
    if digest != ITEMS_SHA256:
        raise J0Error(f"wrong items.jsonl SHA-256 {digest}; expected {ITEMS_SHA256}")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise J0Error("items.jsonl is not strict UTF-8") from exc
    if "\r" in text or not text.endswith("\n"):
        raise J0Error("items.jsonl must use LF and end in LF")
    by_project: dict[str, list[dict[str, Any]]] = {
        "epubcheck": [], "algorand-sdk": [],
    }
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            raise J0Error(f"items.jsonl:{line_number}: blank line")
        try:
            item = json.loads(
                line,
                object_pairs_hook=_unique_object,
                parse_float=_reject_float,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, J0Error) as exc:
            raise J0Error(f"items.jsonl:{line_number}: invalid row: {exc}") from exc
        _validate_json_value(item, f"items.jsonl[{line_number}]")
        if not isinstance(item, dict):
            raise J0Error(f"items.jsonl:{line_number}: row is not object")
        if item.get("project") not in by_project \
                or item.get("task") != "criterion_to_test" \
                or item.get("language") != "java" \
                or item.get("framework") != "cucumber":
            continue
        item_id = _string(item.get("item_id"), f"items.jsonl:{line_number}.item_id")
        if item_id in seen:
            raise J0Error(f"items.jsonl:{line_number}: duplicate item_id {item_id}")
        seen.add(item_id)
        provenance = item.get("provenance")
        if not isinstance(provenance, dict):
            raise J0Error(f"items.jsonl:{line_number}: missing provenance")
        source_uri = validate_posix_path(
            provenance.get("file_path"),
            where=f"items.jsonl:{line_number}.provenance.file_path")
        source_line = _integer(
            provenance.get("line"),
            f"items.jsonl:{line_number}.provenance.line", minimum=1)
        expected_id = f"{item['project']}/{source_uri}:{source_line}"
        if item_id != expected_id:
            raise J0Error(
                f"items.jsonl:{line_number}: item_id/provenance mismatch "
                f"{item_id!r} != {expected_id!r}"
            )
        expected_commit = PINNED_REPOSITORIES[
            "epubcheck" if item["project"] == "epubcheck"
            else "algorand-sdk-testing"]["commit"]
        if provenance.get("commit") != expected_commit:
            raise J0Error(f"items.jsonl:{line_number}: provenance commit mismatch")
        by_project[item["project"]].append(item)
    for project in by_project:
        by_project[project].sort(key=lambda item: item["item_id"].encode("utf-8"))
    return by_project, digest


def _composition_runtime_map(
    composition: Mapping[str, Any],
    sdk_manifest: Mapping[str, Any],
    testing_manifest: Mapping[str, Any],
) -> dict[str, str]:
    validate_composition_manifest(composition, sdk_manifest, testing_manifest)
    out: dict[str, str] = {}
    prefix = "src/test/resources/"
    for mapping in composition["mappings"]:
        if mapping["source_project"] != "algorand-sdk-testing" \
                or not mapping["source_path"].endswith(".feature"):
            continue
        dest = mapping["destination_path"]
        if not dest.startswith(prefix):
            raise J0Error("composition feature destination outside test resources")
        runtime = dest[len(prefix):]
        prior = out.get(mapping["source_path"])
        if prior is not None and prior != runtime:
            raise J0Error("composition source feature has multiple runtime paths")
        out[mapping["source_path"]] = runtime
    return out


def _feature_paths_from_manifest(
    source_manifest: Mapping[str, Any], prefix: str,
) -> list[str]:
    paths = [entry["path"] for entry in source_manifest["files"]
             if entry["path"].startswith(prefix) and entry["path"].endswith(".feature")]
    return sorted(paths, key=lambda item: item.encode("utf-8"))


def _census_totals(items: Sequence[Mapping[str, Any]], integration_items: int) \
        -> dict[str, int]:
    raw_plain = sum(item["form"] == "plain" for item in items)
    raw_outline = sum(item["form"] == "outline" for item in items)
    admitted_plain = sum(item["form"] == "plain" and item["admitted"] for item in items)
    admitted_outline = sum(item["form"] == "outline" and item["admitted"] for item in items)
    raw_rows = sum(len(item["rows"]) for item in items)
    admitted_rows = sum(
        row["admitted"] for item in items for row in item["rows"])
    return {
        "admitted_examples_rows": admitted_rows,
        "admitted_items": admitted_plain + admitted_outline,
        "admitted_outline_items": admitted_outline,
        "admitted_pickles": admitted_plain + admitted_rows,
        "admitted_plain_items": admitted_plain,
        "integration_items": integration_items,
        "raw_examples_rows": raw_rows,
        "raw_items": len(items),
        "raw_outline_items": raw_outline,
        "raw_plain_items": raw_plain,
    }


def build_census(
    project: str,
    source_root: os.PathLike[str] | str,
    source_manifest: Mapping[str, Any],
    frozen_items: Sequence[Mapping[str, Any]],
    items_sha256: str,
    bridge: GherkinParserBridge,
    parser_artifacts: Sequence[os.PathLike[str] | str],
    *,
    composition_manifest: Mapping[str, Any] | None = None,
    sdk_root: os.PathLike[str] | str | None = None,
    sdk_source_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if project not in {"epubcheck", "algorand-sdk"}:
        raise J0Error(f"unsupported census project: {project}")
    expected_source_project = (
        "epubcheck" if project == "epubcheck" else "algorand-sdk-testing")
    validate_source_archive_manifest(source_manifest)
    if source_manifest["project"] != expected_source_project:
        raise J0Error(f"{project}: wrong source archive manifest")
    _hex(items_sha256, 64, "census.items_file_sha256")
    if items_sha256 != ITEMS_SHA256:
        raise J0Error("census: wrong frozen items identity")
    source_root = Path(source_root)
    identity = bridge.identity(project, parser_artifacts)

    if project == "epubcheck":
        if composition_manifest is not None or sdk_root is not None \
                or sdk_source_manifest is not None:
            raise J0Error("epubcheck census cannot receive Algorand composition inputs")
        feature_paths = sorted(
            {item["provenance"]["file_path"] for item in frozen_items},
            key=lambda item: item.encode("utf-8"),
        )
        runtime_map = {
            path: path[len("src/test/resources/"):]
            for path in feature_paths
            if path.startswith("src/test/resources/")
        }
        if len(runtime_map) != len(feature_paths):
            raise J0Error("epubcheck item feature outside src/test/resources")
        admitted_tags: set[str] | None = None
        tag_expression = None
        tag_file_sha256 = None
        tag_expression_qualification = None
        integration_paths: list[str] = []
        composition_sha = None
    else:
        if composition_manifest is None or sdk_root is None \
                or sdk_source_manifest is None:
            raise J0Error("Algorand census requires composition manifest and SDK root")
        validate_composition_manifest(
            composition_manifest, sdk_source_manifest, source_manifest)
        runtime_map = _composition_runtime_map(
            composition_manifest, sdk_source_manifest, source_manifest)
        feature_paths = _feature_paths_from_manifest(source_manifest, "features/unit/")
        integration_paths = _feature_paths_from_manifest(
            source_manifest, "features/integration/")
        if set(feature_paths) - set(runtime_map):
            raise J0Error("Algorand composition omits a unit feature")
        tags, tag_expression, tag_file_sha256 = read_unit_tags(sdk_root)
        admitted_tags = set(tags)
        tag_expression_qualification = bridge.qualify_generated_or(
            project, tag_expression, tags, parser_artifacts)
        composition_sha = _sha256(canonical_json_bytes(dict(composition_manifest)))

    item_lookup: dict[tuple[str, int], Mapping[str, Any]] = {}
    for item in frozen_items:
        provenance = item["provenance"]
        key = (provenance["file_path"], provenance["line"])
        if key in item_lookup:
            raise J0Error(f"{project}: duplicate frozen item provenance {key}")
        item_lookup[key] = item

    census_items: list[dict[str, Any]] = []
    feature_records: list[dict[str, Any]] = []
    seen_item_keys: set[tuple[str, int]] = set()
    for source_uri in feature_paths:
        entry = _manifest_file_map(source_manifest).get(source_uri)
        if entry is None:
            raise J0Error(f"{project}: feature absent from source archive: {source_uri}")
        source_path = _safe_join(source_root, source_uri)
        source_raw, _ = _read_relative_regular_nofollow(source_root, source_uri)
        if len(source_raw) != entry["bytes"] \
                or _sha256(source_raw) != entry["raw_file_sha256"]:
            raise J0Error(f"{project}: feature bytes differ from source manifest")
        ast = bridge.parse(project, source_path, source_uri, parser_artifacts)
        ast_sha = _sha256(canonical_json_bytes(ast))
        flattened = _flatten_scenarios(
            ast, source_uri, runtime_map[source_uri], admitted_tags)
        runtime_pickles = _normalize_runtime_pickles(
            ast, source_uri, runtime_map[source_uri])
        if _runtime_pickle_structure(runtime_pickles) \
                != _expected_runtime_pickle_structure(flattened):
            raise J0Error(
                f"{project}: official Pickle multiset disagrees with AST cases: "
                f"{source_uri}")
        feature_records.append({
            "ast_canonical_sha256": ast_sha,
            "raw_file_sha256": entry["raw_file_sha256"],
            "runtime_pickle_count": len(runtime_pickles),
            "runtime_pickle_multiset_sha256": _sha256(
                canonical_json_bytes(runtime_pickles)),
            "runtime_pickles": runtime_pickles,
            "runtime_uri": runtime_map[source_uri],
            "source_uri": source_uri,
        })
        for census_item in flattened:
            key = (source_uri, census_item["line"])
            item = item_lookup.get(key)
            if item is None:
                raise J0Error(f"{project}: AST scenario has no frozen item: {key}")
            census_item["item_id"] = item["item_id"]
            seen_item_keys.add(key)
            census_items.append(census_item)
    missing_items = set(item_lookup) - seen_item_keys
    if project == "algorand-sdk":
        # J0 intentionally excludes the 51 integration items.  All remaining
        # missing items must be exactly those paths, never a lost unit item.
        bad = [key for key in missing_items if not key[0].startswith("features/integration/")]
        if bad:
            raise J0Error(f"Algorand unit census missed frozen items: {bad[:8]!r}")
    elif missing_items:
        raise J0Error(f"epubcheck census missed frozen items: {sorted(missing_items)[:8]!r}")

    integration_count = 0
    if project == "algorand-sdk":
        for source_uri in integration_paths:
            ast = bridge.parse(
                project,
                _safe_join(source_root, source_uri),
                source_uri,
                parser_artifacts,
            )
            # Integration source/runtime translation is still authenticated by
            # composition, but integration cases are not serialized into J0's
            # executable item census.
            integration_items = _flatten_scenarios(
                ast, source_uri, runtime_map[source_uri], None)
            integration_pickles = _normalize_runtime_pickles(
                ast, source_uri, runtime_map[source_uri])
            if _runtime_pickle_structure(integration_pickles) \
                    != _expected_runtime_pickle_structure(integration_items):
                raise J0Error(
                    "Algorand integration Pickle multiset disagrees with AST cases")
            integration_count += len(integration_items)

    census_items.sort(key=lambda item: item["item_id"].encode("utf-8"))
    totals = _census_totals(census_items, integration_count)
    if project == "algorand-sdk":
        expected = {
            "raw_items": 132,
            "raw_plain_items": 7,
            "raw_outline_items": 125,
            "raw_examples_rows": 527,
            "admitted_items": 125,
            "admitted_plain_items": 4,
            "admitted_outline_items": 121,
            "admitted_examples_rows": 471,
            "admitted_pickles": 475,
            "integration_items": 51,
        }
        if totals != expected:
            raise J0Error(f"Algorand pinned census totals mismatch: {totals!r}")
        excluded = sorted(
            f"{item['source_uri']}:{item['line']}"
            for item in census_items if not item["admitted"])
        expected_excluded = sorted([
            "features/unit/atomic_transaction_composer.feature:181",
            "features/unit/client-no-headers.feature:10",
            "features/unit/client-no-headers.feature:22",
            "features/unit/sourcemap.feature:38",
            "features/unit/sourcemap.feature:43",
            "features/unit/sourcemap.feature:65",
            "features/unit/v2algodclient_paths.feature:128",
        ])
        if excluded != expected_excluded:
            raise J0Error(f"Algorand excluded item lines mismatch: {excluded!r}")
        offline = [item for item in census_items
                   if item["source_uri"] == "features/unit/offline.feature"
                   and item["admitted"]]
        if len(offline) != 9 or any("@unit.offline" not in item["effective_tags"]
                                    for item in offline):
            raise J0Error("Algorand offline.feature admission mismatch")
        responses = next((item for item in census_items
                          if item["source_uri"] == "features/unit/responses.feature"
                          and item["line"] == 4), None)
        if responses is None or len(responses["rows"]) != 167 \
                or sum(row["admitted"] for row in responses["rows"]) != 156:
            raise J0Error("Algorand responses.feature pinned row totals mismatch")

    source_runtime_map = [
        {"runtime_uri": runtime_map[source], "source_uri": source}
        for source in sorted(
            set(feature_paths + integration_paths),
            key=lambda item: item.encode("utf-8"),
        )
    ]
    source_runtime_map.sort(key=lambda item: canonical_json_bytes(item, terminal_lf=False))
    census = {
        "composition_manifest_sha256": composition_sha,
        "features": feature_records,
        "items": census_items,
        "items_file_sha256": items_sha256,
        "parser": identity,
        "project": project,
        "schema": CENSUS_SCHEMA,
        "source_archive_manifest_sha256": _sha256(
            canonical_json_bytes(dict(source_manifest))),
        "source_runtime_map": source_runtime_map,
        "tag_expression": tag_expression,
        "tag_expression_qualification": tag_expression_qualification,
        "tag_file_sha256": tag_file_sha256,
        "totals": totals,
    }
    validate_census(census)
    return census


def _validate_tags_array(value: Any, where: str) -> list[str]:
    if not isinstance(value, list):
        raise J0Error(f"{where}: expected array")
    tags: list[str] = []
    for index, tag in enumerate(value):
        tag = _string(tag, f"{where}[{index}]")
        if not GHERKIN_TAG.fullmatch(tag):
            raise J0Error(f"{where}[{index}]: invalid tag")
        tags.append(tag)
    if tags != _sorted_unique_strings(tags):
        raise J0Error(f"{where}: tags must be unique and UTF-8 sorted")
    return tags


def _validate_structural_key(
    value: Any,
    where: str,
    *,
    source_uri: str | None = None,
) -> list[Any]:
    if not isinstance(value, list) or len(value) != 6:
        raise J0Error(f"{where}: expected six-element structural key")
    uri = validate_posix_path(value[0], where=f"{where}[0]")
    if source_uri is not None and uri != source_uri:
        raise J0Error(f"{where}: structural source URI mismatch")
    if value[1] not in {
        "Feature", "Rule", "Background", "Scenario", "ScenarioOutline",
        "Examples", "ExamplesRow", "Step",
    }:
        raise J0Error(f"{where}[1]: invalid AST kind")
    _integer(value[2], f"{where}[2]", minimum=1)
    _integer(value[3], f"{where}[3]", minimum=1)
    if value[4] is not None:
        _validate_structural_key(value[4], f"{where}[4]", source_uri=uri)
    elif value[1] != "Feature":
        raise J0Error(f"{where}: only Feature may have null parent")
    _integer(value[5], f"{where}[5]")
    return value


def _validate_case_key(
    value: Any,
    where: str,
    *,
    runtime_uri: str,
    scenario_key: list[Any],
) -> list[Any]:
    if not isinstance(value, list) or len(value) != 3:
        raise J0Error(f"{where}: expected three-element case key")
    if value[0] != runtime_uri or value[1] != scenario_key:
        raise J0Error(f"{where}: runtime/scenario authority mismatch")
    if value[2] is not None:
        row_key = _validate_structural_key(value[2], f"{where}[2]",
                                           source_uri=scenario_key[0])
        if row_key[1] != "ExamplesRow":
            raise J0Error(f"{where}[2]: expected ExamplesRow key")
    return value


def _validate_census_structure(census: Any) -> dict[str, Any]:
    obj = _closed(census, {
        "composition_manifest_sha256", "features", "items", "items_file_sha256",
        "parser", "project", "schema", "source_archive_manifest_sha256",
        "source_runtime_map", "tag_expression", "tag_expression_qualification",
        "tag_file_sha256", "totals",
    }, "census")
    if obj["schema"] != CENSUS_SCHEMA:
        raise J0Error("census.schema: wrong schema")
    project = obj["project"]
    if project not in {"epubcheck", "algorand-sdk"}:
        raise J0Error("census.project: invalid")
    _hex(obj["items_file_sha256"], 64, "census.items_file_sha256")
    if obj["items_file_sha256"] != ITEMS_SHA256:
        raise J0Error("census.items_file_sha256: not frozen J0 items")
    _hex(obj["source_archive_manifest_sha256"], 64,
         "census.source_archive_manifest_sha256")
    validate_parser_identity(obj["parser"], project)
    if project == "epubcheck":
        if any(obj[key] is not None for key in (
                "composition_manifest_sha256", "tag_expression",
                "tag_expression_qualification", "tag_file_sha256")):
            raise J0Error("census: epubcheck has unexpected Algorand fields")
    else:
        _hex(obj["composition_manifest_sha256"], 64,
             "census.composition_manifest_sha256")
        _hex(obj["tag_file_sha256"], 64, "census.tag_file_sha256")
        expression = _string(obj["tag_expression"], "census.tag_expression")
        if not expression.startswith("(") or not expression.endswith(")"):
            raise J0Error("census.tag_expression: malformed generated expression")
        expression_tags = expression[1:-1].split(") or (")
        if not expression_tags or any(not TAG.fullmatch(tag) for tag in expression_tags):
            raise J0Error("census.tag_expression: outside generated OR grammar")
        if expression_tags != sorted(expression_tags, key=lambda x: x.encode("utf-8")) \
                or len(expression_tags) != len(set(expression_tags)):
            raise J0Error("census.tag_expression: tags not unique/sorted")
        qualification = validate_tag_expression_qualification(
            obj["tag_expression_qualification"])
        if qualification["expression"] != expression:
            raise J0Error("census.tag_expression_qualification: expression mismatch")

    if not isinstance(obj["source_runtime_map"], list):
        raise J0Error("census.source_runtime_map: expected array")
    maps: list[dict[str, Any]] = []
    for index, value in enumerate(obj["source_runtime_map"]):
        entry = _closed(value, {"runtime_uri", "source_uri"},
                        f"census.source_runtime_map[{index}]")
        validate_posix_path(entry["runtime_uri"],
                            where=f"census.source_runtime_map[{index}].runtime_uri")
        validate_posix_path(entry["source_uri"],
                            where=f"census.source_runtime_map[{index}].source_uri")
        maps.append(entry)
    expected_map_sort = sorted(
        maps, key=lambda item: canonical_json_bytes(item, terminal_lf=False))
    if maps != expected_map_sort or len({entry["source_uri"] for entry in maps}) != len(maps) \
            or len({entry["runtime_uri"] for entry in maps}) != len(maps):
        raise J0Error("census.source_runtime_map: not unique canonical-byte sorted")
    runtime_by_source = {entry["source_uri"]: entry["runtime_uri"] for entry in maps}

    if not isinstance(obj["features"], list):
        raise J0Error("census.features: expected array")
    feature_sources: list[str] = []
    runtime_pickles_by_source: dict[str, list[dict[str, Any]]] = {}
    for index, value in enumerate(obj["features"]):
        entry = _closed(value, {
            "ast_canonical_sha256", "raw_file_sha256", "runtime_pickle_count",
            "runtime_pickle_multiset_sha256", "runtime_pickles", "runtime_uri",
            "source_uri",
        }, f"census.features[{index}]")
        source = validate_posix_path(
            entry["source_uri"], where=f"census.features[{index}].source_uri")
        runtime = validate_posix_path(
            entry["runtime_uri"], where=f"census.features[{index}].runtime_uri")
        if runtime_by_source.get(source) != runtime:
            raise J0Error(f"census.features[{index}]: source/runtime map mismatch")
        _hex(entry["raw_file_sha256"], 64,
             f"census.features[{index}].raw_file_sha256")
        _hex(entry["ast_canonical_sha256"], 64,
             f"census.features[{index}].ast_canonical_sha256")
        if not isinstance(entry["runtime_pickles"], list):
            raise J0Error(f"census.features[{index}].runtime_pickles: expected array")
        pickle_records: list[dict[str, Any]] = []
        encoded_pickles: list[bytes] = []
        for pickle_index, pickle_value in enumerate(entry["runtime_pickles"]):
            pickle_where = (
                f"census.features[{index}].runtime_pickles[{pickle_index}]")
            pickle = _closed(pickle_value, {
                "effective_tags", "language", "name", "row_key", "runtime_uri",
                "scenario_key",
            }, pickle_where)
            if pickle["runtime_uri"] != runtime:
                raise J0Error(f"{pickle_where}.runtime_uri: feature mismatch")
            _string(pickle["language"], f"{pickle_where}.language")
            _string(pickle["name"], f"{pickle_where}.name", nonempty=False)
            _validate_tags_array(pickle["effective_tags"],
                                 f"{pickle_where}.effective_tags")
            scenario_key = _validate_structural_key(
                pickle["scenario_key"], f"{pickle_where}.scenario_key",
                source_uri=source)
            if scenario_key[1] not in {"Scenario", "ScenarioOutline"}:
                raise J0Error(f"{pickle_where}.scenario_key: wrong kind")
            if pickle["row_key"] is not None:
                row_key = _validate_structural_key(
                    pickle["row_key"], f"{pickle_where}.row_key", source_uri=source)
                if row_key[1] != "ExamplesRow" or row_key[4] is None \
                        or row_key[4][4] != scenario_key:
                    raise J0Error(f"{pickle_where}.row_key: parent mismatch")
            pickle_records.append(pickle)
            encoded_pickles.append(canonical_json_bytes(
                pickle, terminal_lf=False))
        if encoded_pickles != sorted(encoded_pickles):
            raise J0Error(
                f"census.features[{index}].runtime_pickles: not canonical sorted")
        if entry["runtime_pickle_count"] != len(pickle_records):
            raise J0Error(f"census.features[{index}].runtime_pickle_count: mismatch")
        _integer(entry["runtime_pickle_count"],
                 f"census.features[{index}].runtime_pickle_count")
        _hex(entry["runtime_pickle_multiset_sha256"], 64,
             f"census.features[{index}].runtime_pickle_multiset_sha256")
        if entry["runtime_pickle_multiset_sha256"] != _sha256(
                canonical_json_bytes(pickle_records)):
            raise J0Error(
                f"census.features[{index}].runtime_pickle_multiset_sha256: mismatch")
        runtime_pickles_by_source[source] = pickle_records
        feature_sources.append(source)
    if feature_sources != sorted(feature_sources, key=lambda x: x.encode("utf-8")) \
            or len(feature_sources) != len(set(feature_sources)):
        raise J0Error("census.features: paths not unique UTF-8 sorted")

    if not isinstance(obj["items"], list):
        raise J0Error("census.items: expected array")
    item_ids: list[str] = []
    for index, value in enumerate(obj["items"]):
        where = f"census.items[{index}]"
        item = _closed(value, {
            "admitted", "case_keys", "column", "effective_tags",
            "exclusion_reason", "form", "item_id", "keyword", "line", "name",
            "rows", "runtime_uri", "source_uri", "steps", "structural_key",
        }, where)
        if not isinstance(item["admitted"], bool):
            raise J0Error(f"{where}.admitted: expected boolean")
        source = validate_posix_path(item["source_uri"], where=f"{where}.source_uri")
        runtime = validate_posix_path(item["runtime_uri"], where=f"{where}.runtime_uri")
        if runtime_by_source.get(source) != runtime:
            raise J0Error(f"{where}: source/runtime map mismatch")
        line = _integer(item["line"], f"{where}.line", minimum=1)
        _integer(item["column"], f"{where}.column", minimum=1)
        item_id = _string(item["item_id"], f"{where}.item_id")
        if item_id != f"{project}/{source}:{line}":
            raise J0Error(f"{where}.item_id: source/line mismatch")
        item_ids.append(item_id)
        if item["form"] not in {"plain", "outline"}:
            raise J0Error(f"{where}.form: invalid")
        _string(item["keyword"], f"{where}.keyword")
        _string(item["name"], f"{where}.name", nonempty=False)
        tags = _validate_tags_array(item["effective_tags"], f"{where}.effective_tags")
        del tags
        if item["admitted"]:
            if item["exclusion_reason"] is not None:
                raise J0Error(f"{where}: admitted item has exclusion reason")
        elif item["exclusion_reason"] not in {
                "tag_expression_no_match", "outline_has_no_examples_rows"}:
            raise J0Error(f"{where}: excluded item has invalid reason")
        scenario_key = _validate_structural_key(
            item["structural_key"], f"{where}.structural_key", source_uri=source)
        expected_kind = "Scenario" if item["form"] == "plain" else "ScenarioOutline"
        if scenario_key[1] != expected_kind or scenario_key[2] != line \
                or scenario_key[3] != item["column"]:
            raise J0Error(f"{where}.structural_key: item classification/location mismatch")

        if not isinstance(item["steps"], list):
            raise J0Error(f"{where}.steps: expected array")
        for step_index, value in enumerate(item["steps"]):
            step_where = f"{where}.steps[{step_index}]"
            step = _closed(value, {
                "column", "keyword", "line", "structural_key", "text",
            }, step_where)
            _integer(step["line"], f"{step_where}.line", minimum=1)
            _integer(step["column"], f"{step_where}.column", minimum=1)
            _string(step["keyword"], f"{step_where}.keyword")
            _string(step["text"], f"{step_where}.text", nonempty=False)
            step_key = _validate_structural_key(
                step["structural_key"], f"{step_where}.structural_key",
                source_uri=source)
            if step_key[1] != "Step" or step_key[4] != scenario_key \
                    or step_key[5] != step_index:
                raise J0Error(f"{step_where}.structural_key: mismatch")

        if not isinstance(item["rows"], list):
            raise J0Error(f"{where}.rows: expected array")
        admitted_row_keys: list[list[Any]] = []
        examples_ordinals: dict[bytes, list[int]] = {}
        for row_index, value in enumerate(item["rows"]):
            row_where = f"{where}.rows[{row_index}]"
            row = _closed(value, {
                "admitted", "case_key", "column", "effective_tags", "examples_key",
                "examples_keyword", "examples_name", "exclusion_reason", "line",
                "raw_cells", "row_ordinal", "structural_key",
            }, row_where)
            if not isinstance(row["admitted"], bool):
                raise J0Error(f"{row_where}.admitted: expected boolean")
            _integer(row["line"], f"{row_where}.line", minimum=1)
            _integer(row["column"], f"{row_where}.column", minimum=1)
            ordinal = _integer(row["row_ordinal"], f"{row_where}.row_ordinal")
            _string(row["examples_keyword"], f"{row_where}.examples_keyword")
            _string(row["examples_name"], f"{row_where}.examples_name", nonempty=False)
            _validate_tags_array(row["effective_tags"], f"{row_where}.effective_tags")
            if not isinstance(row["raw_cells"], list) or not row["raw_cells"]:
                raise J0Error(f"{row_where}.raw_cells: expected nonempty array")
            for cell_index, cell in enumerate(row["raw_cells"]):
                _string(cell, f"{row_where}.raw_cells[{cell_index}]", nonempty=False)
            examples_key = _validate_structural_key(
                row["examples_key"], f"{row_where}.examples_key", source_uri=source)
            row_key = _validate_structural_key(
                row["structural_key"], f"{row_where}.structural_key", source_uri=source)
            if examples_key[1] != "Examples" or examples_key[4] != scenario_key \
                    or row_key[1] != "ExamplesRow" or row_key[4] != examples_key \
                    or row_key[5] != ordinal:
                raise J0Error(f"{row_where}: structural parent/ordinal mismatch")
            encoded_examples = canonical_json_bytes(examples_key, terminal_lf=False)
            examples_ordinals.setdefault(encoded_examples, []).append(ordinal)
            _validate_case_key(row["case_key"], f"{row_where}.case_key",
                               runtime_uri=runtime, scenario_key=scenario_key)
            if row["case_key"][2] != row_key:
                raise J0Error(f"{row_where}.case_key: row key mismatch")
            if row["admitted"]:
                if row["exclusion_reason"] is not None:
                    raise J0Error(f"{row_where}: admitted row has exclusion reason")
                admitted_row_keys.append(row["case_key"])
            elif row["exclusion_reason"] != "tag_expression_no_match":
                raise J0Error(f"{row_where}: wrong exclusion reason")
        for ordinals in examples_ordinals.values():
            if ordinals != list(range(len(ordinals))):
                raise J0Error(f"{where}.rows: Examples row ordinals not contiguous")
        if item["form"] == "plain" and item["rows"]:
            raise J0Error(f"{where}: plain Scenario has Examples rows")
        expected_cases = (
            [[runtime, scenario_key, None]] if item["form"] == "plain"
            and item["admitted"] else admitted_row_keys)
        if not isinstance(item["case_keys"], list) or item["case_keys"] != expected_cases:
            raise J0Error(f"{where}.case_keys: admitted case multiset mismatch")
        for case_index, case_key in enumerate(item["case_keys"]):
            _validate_case_key(case_key, f"{where}.case_keys[{case_index}]",
                               runtime_uri=runtime, scenario_key=scenario_key)
    if item_ids != sorted(item_ids, key=lambda x: x.encode("utf-8")) \
            or len(item_ids) != len(set(item_ids)):
        raise J0Error("census.items: item ids not unique UTF-8 sorted")

    items_by_source: dict[str, list[Mapping[str, Any]]] = {}
    for item in obj["items"]:
        items_by_source.setdefault(item["source_uri"], []).append(item)
    for source in feature_sources:
        if _runtime_pickle_structure(runtime_pickles_by_source[source]) \
                != _expected_runtime_pickle_structure(items_by_source.get(source, [])):
            raise J0Error(
                f"census.features: official Pickle structural multiset mismatch: {source}")

    totals = _closed(obj["totals"], {
        "admitted_examples_rows", "admitted_items", "admitted_outline_items",
        "admitted_pickles", "admitted_plain_items", "integration_items",
        "raw_examples_rows", "raw_items", "raw_outline_items", "raw_plain_items",
    }, "census.totals")
    for key, value in totals.items():
        _integer(value, f"census.totals.{key}")
    recomputed = _census_totals(obj["items"], totals["integration_items"])
    if totals != recomputed:
        raise J0Error(f"census.totals: arithmetic mismatch {totals!r} != {recomputed!r}")
    return obj


def _enforce_pinned_census_semantics(obj: Mapping[str, Any]) -> None:
    project = obj["project"]
    expected_source = PINNED_SOURCE_ARCHIVE_FACTS[
        "epubcheck" if project == "epubcheck" else "algorand-sdk-testing"
    ]["manifest_sha256"]
    if obj["source_archive_manifest_sha256"] != expected_source:
        raise J0Error("census.source_archive_manifest_sha256: pinned source mismatch")
    if project == "epubcheck":
        expected_totals = {
            "admitted_examples_rows": 106,
            "admitted_items": 1041,
            "admitted_outline_items": 11,
            "admitted_pickles": 1136,
            "admitted_plain_items": 1030,
            "integration_items": 0,
            "raw_examples_rows": 106,
            "raw_items": 1041,
            "raw_outline_items": 11,
            "raw_plain_items": 1030,
        }
        if obj["totals"] != expected_totals \
                or len(obj["features"]) != 47 \
                or len(obj["source_runtime_map"]) != 47:
            raise J0Error("EPUBCheck pinned census semantic facts mismatch")
        return

    expected_totals = {
        "admitted_examples_rows": 471,
        "admitted_items": 125,
        "admitted_outline_items": 121,
        "admitted_pickles": 475,
        "admitted_plain_items": 4,
        "integration_items": 51,
        "raw_examples_rows": 527,
        "raw_items": 132,
        "raw_outline_items": 125,
        "raw_plain_items": 7,
    }
    if obj["totals"] != expected_totals \
            or len(obj["features"]) != 16 \
            or len(obj["source_runtime_map"]) != 27:
        raise J0Error("Algorand pinned census totals/path cardinalities mismatch")
    if obj["tag_file_sha256"] != UNIT_TAGS_SHA256:
        raise J0Error("Algorand pinned unit.tags SHA-256 mismatch")
    excluded = sorted(
        f"{item['source_uri']}:{item['line']}"
        for item in obj["items"] if not item["admitted"])
    expected_excluded = sorted([
        "features/unit/atomic_transaction_composer.feature:181",
        "features/unit/client-no-headers.feature:10",
        "features/unit/client-no-headers.feature:22",
        "features/unit/sourcemap.feature:38",
        "features/unit/sourcemap.feature:43",
        "features/unit/sourcemap.feature:65",
        "features/unit/v2algodclient_paths.feature:128",
    ])
    if excluded != expected_excluded:
        raise J0Error("Algorand pinned exclusion set mismatch")
    offline = sorted([
        {
            "admitted": item["admitted"],
            "effective_tags": item["effective_tags"],
            "form": item["form"],
            "line": item["line"],
            "row_lines": [row["line"] for row in item["rows"]],
            "runtime_uri": item["runtime_uri"],
        }
        for item in obj["items"]
        if item["source_uri"] == "features/unit/offline.feature"
    ], key=lambda item: item["line"])
    expected_offline = [
        {"admitted": True, "effective_tags": ["@unit", "@unit.offline"],
         "form": "plain", "line": 4, "row_lines": [],
         "runtime_uri": "com/algorand/algosdk/integration/offline.feature"},
        {"admitted": True, "effective_tags": ["@unit", "@unit.offline"],
         "form": "outline", "line": 10, "row_lines": [17],
         "runtime_uri": "com/algorand/algosdk/integration/offline.feature"},
        {"admitted": True, "effective_tags": ["@unit", "@unit.offline"],
         "form": "outline", "line": 19, "row_lines": [26],
         "runtime_uri": "com/algorand/algosdk/integration/offline.feature"},
        {"admitted": True, "effective_tags": ["@unit", "@unit.offline"],
         "form": "outline", "line": 28, "row_lines": [37],
         "runtime_uri": "com/algorand/algosdk/integration/offline.feature"},
        {"admitted": True, "effective_tags": ["@unit", "@unit.offline"],
         "form": "outline", "line": 39, "row_lines": [45],
         "runtime_uri": "com/algorand/algosdk/integration/offline.feature"},
        {"admitted": True, "effective_tags": ["@unit", "@unit.offline"],
         "form": "outline", "line": 47, "row_lines": [57],
         "runtime_uri": "com/algorand/algosdk/integration/offline.feature"},
        {"admitted": True, "effective_tags": ["@unit", "@unit.offline"],
         "form": "outline", "line": 59, "row_lines": [67],
         "runtime_uri": "com/algorand/algosdk/integration/offline.feature"},
        {"admitted": True, "effective_tags": ["@unit", "@unit.offline"],
         "form": "outline", "line": 69, "row_lines": [76],
         "runtime_uri": "com/algorand/algosdk/integration/offline.feature"},
        {"admitted": True, "effective_tags": ["@unit", "@unit.offline"],
         "form": "outline", "line": 78,
         "row_lines": [84, 85, 86, 87, 88, 89],
         "runtime_uri": "com/algorand/algosdk/integration/offline.feature"},
    ]
    if offline != expected_offline:
        raise J0Error("Algorand pinned offline.feature facts mismatch")
    responses = [
        item for item in obj["items"]
        if item["source_uri"] == "features/unit/responses.feature"
        and item["line"] == 4
    ]
    if len(responses) != 1:
        raise J0Error("Algorand pinned responses.feature outline missing")
    response = responses[0]
    rejected_rows = [row["line"] for row in response["rows"] if not row["admitted"]]
    if len(response["rows"]) != 167 \
            or sum(row["admitted"] for row in response["rows"]) != 156 \
            or rejected_rows != [146, 185, 233, 234, 235, 240, 245, 246, 247, 248, 249]:
        raise J0Error("Algorand pinned responses.feature row facts mismatch")
    expression = obj["tag_expression"]
    if _sha256(expression.encode("utf-8")) \
            != "784f8ac5eeaddd29c663af98ca5eda3ba3aaf64483b0456c6969c8fcb39645bc":
        raise J0Error("Algorand pinned tag expression mismatch")


def validate_census(census: Any) -> dict[str, Any]:
    obj = _validate_census_structure(census)
    _enforce_pinned_census_semantics(obj)
    return obj


def _salted_sha(prefix: bytes, *parts: str) -> bytes:
    digest = hashlib.sha256()
    digest.update(prefix)
    for index, part in enumerate(parts):
        if index:
            digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return digest.digest()


def _eligible_census_items(census: Mapping[str, Any]) -> list[dict[str, Any]]:
    _validate_census_structure(census)
    return [dict(item) for item in census["items"] if item["admitted"]]


def _select_scalar_items(census: Mapping[str, Any]) -> tuple[list[dict[str, Any]], int, int]:
    eligible = _eligible_census_items(census)
    if len(eligible) < 12:
        raise J0Error("scalar selection requires at least 12 eligible criterion items")

    def item_order(item: Mapping[str, Any]) -> tuple[bytes, bytes]:
        return (
            _salted_sha(b"r2t-j0-scalar/1\0", item["item_id"]),
            item["item_id"].encode("utf-8"),
        )

    def feature_order(path: str) -> tuple[bytes, bytes]:
        return (
            _salted_sha(b"r2t-j0-feature/1\0", path),
            path.encode("utf-8"),
        )

    selected: dict[str, list[dict[str, Any]]] = {"plain": [], "outline": []}
    globals_by_form: dict[str, list[dict[str, Any]]] = {}
    for form in ("plain", "outline"):
        population = sorted(
            [item for item in eligible if item["form"] == form], key=item_order)
        globals_by_form[form] = population
        by_feature: dict[str, list[dict[str, Any]]] = {}
        for item in population:
            by_feature.setdefault(item["source_uri"], []).append(item)
        for feature in sorted(by_feature, key=feature_order):
            if len(selected[form]) == 6:
                break
            selected[form].append(by_feature[feature][0])
        for item in population:
            if len(selected[form]) == 6:
                break
            if item not in selected[form]:
                selected[form].append(item)

    initial_plain = len(selected["plain"])
    initial_outline = len(selected["outline"])
    if initial_plain < 6:
        deficit = 6 - initial_plain
        for item in globals_by_form["outline"]:
            if deficit == 0:
                break
            if item not in selected["outline"]:
                selected["outline"].append(item)
                deficit -= 1
        if deficit:
            raise J0Error("scalar selection cannot transfer plain deficit")
    if initial_outline < 6:
        deficit = 6 - initial_outline
        for item in globals_by_form["plain"]:
            if deficit == 0:
                break
            if item not in selected["plain"]:
                selected["plain"].append(item)
                deficit -= 1
        if deficit:
            raise J0Error("scalar selection cannot transfer outline deficit")
    ordered = selected["plain"] + selected["outline"]
    if len(ordered) != 12 or len({item["item_id"] for item in ordered}) != 12:
        raise J0Error("scalar selection did not produce 12 unique items")
    return ordered, initial_plain, initial_outline


def build_scalar_selection(census: Mapping[str, Any]) -> dict[str, Any]:
    _validate_census_structure(census)
    ordered, initial_plain, initial_outline = _select_scalar_items(census)
    records: list[dict[str, Any]] = []
    for ordinal, item in enumerate(ordered):
        records.append({
            "case_keys": item["case_keys"],
            "column": item["column"],
            "form": item["form"],
            "item_id": item["item_id"],
            "line": item["line"],
            "ordinal": ordinal,
            "pickle_count": len(item["case_keys"]),
            "runtime_uri": item["runtime_uri"],
            "source_uri": item["source_uri"],
            "structural_key": item["structural_key"],
        })
    manifest = {
        "algorithm": "r2t-j0-scalar/1",
        "census_manifest_sha256": _sha256(canonical_json_bytes(dict(census))),
        "initial_outline_seats": initial_outline,
        "initial_plain_seats": initial_plain,
        "items": records,
        "items_file_sha256": census["items_file_sha256"],
        "project": census["project"],
        "schema": SCALAR_SELECTION_SCHEMA,
        "target_item_count": 12,
        "target_outline_seats": 6,
        "target_plain_seats": 6,
    }
    validate_scalar_selection(manifest, census)
    return manifest


def validate_scalar_selection(
    selection: Any,
    census: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    obj = _closed(selection, {
        "algorithm", "census_manifest_sha256", "initial_outline_seats",
        "initial_plain_seats", "items", "items_file_sha256", "project", "schema",
        "target_item_count", "target_outline_seats", "target_plain_seats",
    }, "scalar_selection")
    if obj["schema"] != SCALAR_SELECTION_SCHEMA \
            or obj["algorithm"] != "r2t-j0-scalar/1":
        raise J0Error("scalar_selection: wrong schema/algorithm")
    if obj["project"] not in {"epubcheck", "algorand-sdk"}:
        raise J0Error("scalar_selection.project: invalid")
    _hex(obj["census_manifest_sha256"], 64,
         "scalar_selection.census_manifest_sha256")
    _hex(obj["items_file_sha256"], 64, "scalar_selection.items_file_sha256")
    for key, expected in (
        ("target_item_count", 12), ("target_outline_seats", 6),
        ("target_plain_seats", 6),
    ):
        if obj[key] != expected:
            raise J0Error(f"scalar_selection.{key}: must be {expected}")
    for key in ("initial_plain_seats", "initial_outline_seats"):
        value = _integer(obj[key], f"scalar_selection.{key}")
        if value > 6:
            raise J0Error(f"scalar_selection.{key}: exceeds six")
    if not isinstance(obj["items"], list) or len(obj["items"]) != 12:
        raise J0Error("scalar_selection.items: expected 12 entries")
    ids: list[str] = []
    for index, value in enumerate(obj["items"]):
        where = f"scalar_selection.items[{index}]"
        item = _closed(value, {
            "case_keys", "column", "form", "item_id", "line", "ordinal",
            "pickle_count", "runtime_uri", "source_uri", "structural_key",
        }, where)
        if item["ordinal"] != index:
            raise J0Error(f"{where}.ordinal: not contiguous")
        if item["form"] not in {"plain", "outline"}:
            raise J0Error(f"{where}.form: invalid")
        item_id = _string(item["item_id"], f"{where}.item_id")
        source = validate_posix_path(item["source_uri"], where=f"{where}.source_uri")
        runtime = validate_posix_path(item["runtime_uri"], where=f"{where}.runtime_uri")
        line = _integer(item["line"], f"{where}.line", minimum=1)
        column = _integer(item["column"], f"{where}.column", minimum=1)
        if item_id != f"{obj['project']}/{source}:{line}":
            raise J0Error(f"{where}.item_id: source/line mismatch")
        key = _validate_structural_key(item["structural_key"],
                                       f"{where}.structural_key", source_uri=source)
        if key[2] != line or key[3] != column:
            raise J0Error(f"{where}.structural_key: location mismatch")
        if not isinstance(item["case_keys"], list):
            raise J0Error(f"{where}.case_keys: expected array")
        for case_index, case in enumerate(item["case_keys"]):
            _validate_case_key(case, f"{where}.case_keys[{case_index}]",
                               runtime_uri=runtime, scenario_key=key)
        if item["pickle_count"] != len(item["case_keys"]) \
                or item["pickle_count"] < 1:
            raise J0Error(f"{where}.pickle_count: mismatch/empty")
        ids.append(item_id)
    if len(ids) != len(set(ids)):
        raise J0Error("scalar_selection.items: duplicate item")
    plain_prefix = [item["form"] for item in obj["items"]]
    if plain_prefix != sorted(plain_prefix, key=lambda form: 0 if form == "plain" else 1):
        raise J0Error("scalar_selection.items: plain items must precede outlines")
    if census is not None:
        _validate_census_structure(census)
        if obj["project"] != census["project"] \
                or obj["items_file_sha256"] != census["items_file_sha256"] \
                or obj["census_manifest_sha256"] != _sha256(
                    canonical_json_bytes(dict(census))):
            raise J0Error("scalar_selection: census identity mismatch")
        rebuilt, initial_plain, initial_outline = _select_scalar_items(census)
        expected_ids = [item["item_id"] for item in rebuilt]
        if ids != expected_ids or obj["initial_plain_seats"] != initial_plain \
                or obj["initial_outline_seats"] != initial_outline:
            raise J0Error("scalar_selection: algorithm reconstruction mismatch")
        by_id = {item["item_id"]: item for item in census["items"]}
        for record in obj["items"]:
            source = by_id[record["item_id"]]
            expected = {
                "case_keys": source["case_keys"],
                "column": source["column"],
                "form": source["form"],
                "item_id": source["item_id"],
                "line": source["line"],
                "ordinal": record["ordinal"],
                "pickle_count": len(source["case_keys"]),
                "runtime_uri": source["runtime_uri"],
                "source_uri": source["source_uri"],
                "structural_key": source["structural_key"],
            }
            if record != expected:
                raise J0Error("scalar_selection: item facts drifted from census")
    return obj


def _select_examples_item(census: Mapping[str, Any]) \
        -> tuple[dict[str, Any], list[dict[str, Any]]]:
    outlines: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for item in _eligible_census_items(census):
        if item["form"] != "outline":
            continue
        admitted_rows = [row for row in item["rows"] if row["admitted"]]
        if admitted_rows:
            outlines.append((item, admitted_rows))
    if not outlines:
        raise J0Error("Examples selection has no admitted outline")
    outlines.sort(key=lambda pair: (
        -len(pair[1]),
        _salted_sha(b"r2t-j0-scalar/1\0", pair[0]["item_id"]),
        pair[0]["item_id"].encode("utf-8"),
    ))
    item, rows = outlines[0]
    if len(rows) < 2:
        raise J0Error("largest admitted outline has fewer than two rows")
    k = min(len(rows), 16)
    selected = sorted(rows, key=lambda row: (
        _salted_sha(
            b"r2t-j0-examples/1\0", item["item_id"], str(row["line"])),
        row["line"],
    ))[:k]
    selected.sort(key=lambda row: row["line"])
    return item, selected


def build_examples_selection(census: Mapping[str, Any]) -> dict[str, Any]:
    _validate_census_structure(census)
    item, selected = _select_examples_item(census)
    selected_keys = {canonical_json_bytes(row["structural_key"], terminal_lf=False)
                     for row in selected}
    rows: list[dict[str, Any]] = []
    for ordinal, row in enumerate(selected):
        rows.append({
            "case_key": row["case_key"],
            "effective_tags": row["effective_tags"],
            "examples_key": row["examples_key"],
            "line": row["line"],
            "ordinal": ordinal,
            "raw_cells": row["raw_cells"],
            "structural_key": row["structural_key"],
        })
    manifest = {
        "admitted_row_count": sum(row["admitted"] for row in item["rows"]),
        "algorithm": "r2t-j0-examples/1",
        "census_manifest_sha256": _sha256(canonical_json_bytes(dict(census))),
        "item_id": item["item_id"],
        "items_file_sha256": census["items_file_sha256"],
        "project": census["project"],
        "raw_row_count": len(item["rows"]),
        "rejected_row_lines": [
            row["line"] for row in item["rows"]
            if canonical_json_bytes(row["structural_key"], terminal_lf=False)
            not in selected_keys
        ],
        "rows": rows,
        "schema": EXAMPLES_SELECTION_SCHEMA,
        "selected_item": {
            "column": item["column"],
            "line": item["line"],
            "runtime_uri": item["runtime_uri"],
            "source_uri": item["source_uri"],
            "structural_key": item["structural_key"],
        },
        "selected_row_count": len(rows),
    }
    validate_examples_selection(manifest)
    return manifest


def validate_examples_selection(
    selection: Any,
    census: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    obj = _closed(selection, {
        "admitted_row_count", "algorithm", "census_manifest_sha256", "item_id",
        "items_file_sha256", "project", "raw_row_count", "rejected_row_lines",
        "rows", "schema", "selected_item", "selected_row_count",
    }, "examples_selection")
    if obj["schema"] != EXAMPLES_SELECTION_SCHEMA \
            or obj["algorithm"] != "r2t-j0-examples/1":
        raise J0Error("examples_selection: wrong schema/algorithm")
    if obj["project"] not in {"epubcheck", "algorand-sdk"}:
        raise J0Error("examples_selection.project: invalid")
    _hex(obj["census_manifest_sha256"], 64,
         "examples_selection.census_manifest_sha256")
    _hex(obj["items_file_sha256"], 64, "examples_selection.items_file_sha256")
    item_id = _string(obj["item_id"], "examples_selection.item_id")
    selected_item = _closed(obj["selected_item"], {
        "column", "line", "runtime_uri", "source_uri", "structural_key",
    }, "examples_selection.selected_item")
    source = validate_posix_path(selected_item["source_uri"],
                                 where="examples_selection.selected_item.source_uri")
    runtime = validate_posix_path(selected_item["runtime_uri"],
                                  where="examples_selection.selected_item.runtime_uri")
    line = _integer(selected_item["line"],
                    "examples_selection.selected_item.line", minimum=1)
    column = _integer(selected_item["column"],
                      "examples_selection.selected_item.column", minimum=1)
    scenario_key = _validate_structural_key(
        selected_item["structural_key"],
        "examples_selection.selected_item.structural_key", source_uri=source)
    if scenario_key[1] != "ScenarioOutline" or scenario_key[2] != line \
            or scenario_key[3] != column:
        raise J0Error("examples_selection.selected_item: not the bound outline")
    if item_id != f"{obj['project']}/{source}:{line}":
        raise J0Error("examples_selection.item_id: source/line mismatch")
    raw_count = _integer(obj["raw_row_count"], "examples_selection.raw_row_count")
    admitted_count = _integer(obj["admitted_row_count"],
                              "examples_selection.admitted_row_count", minimum=2)
    selected_count = _integer(obj["selected_row_count"],
                              "examples_selection.selected_row_count", minimum=2)
    if selected_count != min(admitted_count, 16):
        raise J0Error("examples_selection.selected_row_count: k mismatch")
    if not isinstance(obj["rows"], list) or len(obj["rows"]) != selected_count:
        raise J0Error("examples_selection.rows: count mismatch")
    row_lines: list[int] = []
    row_keys: set[bytes] = set()
    for index, value in enumerate(obj["rows"]):
        where = f"examples_selection.rows[{index}]"
        row = _closed(value, {
            "case_key", "effective_tags", "examples_key", "line", "ordinal",
            "raw_cells", "structural_key",
        }, where)
        if row["ordinal"] != index:
            raise J0Error(f"{where}.ordinal: not contiguous")
        row_line = _integer(row["line"], f"{where}.line", minimum=1)
        row_lines.append(row_line)
        _validate_tags_array(row["effective_tags"], f"{where}.effective_tags")
        if not isinstance(row["raw_cells"], list) or not row["raw_cells"]:
            raise J0Error(f"{where}.raw_cells: expected nonempty array")
        for cell_index, cell in enumerate(row["raw_cells"]):
            _string(cell, f"{where}.raw_cells[{cell_index}]", nonempty=False)
        examples_key = _validate_structural_key(
            row["examples_key"], f"{where}.examples_key", source_uri=source)
        key = _validate_structural_key(
            row["structural_key"], f"{where}.structural_key", source_uri=source)
        if examples_key[1] != "Examples" or examples_key[4] != scenario_key \
                or key[1] != "ExamplesRow" or key[4] != examples_key \
                or key[2] != row_line:
            raise J0Error(f"{where}: structural key mismatch")
        _validate_case_key(row["case_key"], f"{where}.case_key",
                           runtime_uri=runtime, scenario_key=scenario_key)
        if row["case_key"][2] != key:
            raise J0Error(f"{where}.case_key: row mismatch")
        encoded = canonical_json_bytes(key, terminal_lf=False)
        if encoded in row_keys:
            raise J0Error("examples_selection.rows: duplicate row key")
        row_keys.add(encoded)
    if row_lines != sorted(row_lines) or len(row_lines) != len(set(row_lines)):
        raise J0Error("examples_selection.rows: not restored to unique source order")
    if not isinstance(obj["rejected_row_lines"], list):
        raise J0Error("examples_selection.rejected_row_lines: expected array")
    rejected: list[int] = []
    for index, value in enumerate(obj["rejected_row_lines"]):
        rejected.append(_integer(value,
                                 f"examples_selection.rejected_row_lines[{index}]",
                                 minimum=1))
    if rejected != sorted(rejected) or len(rejected) != len(set(rejected)):
        raise J0Error("examples_selection.rejected_row_lines: not unique sorted")
    if len(rejected) + selected_count != raw_count:
        raise J0Error("examples_selection: selected/rejected/raw arithmetic mismatch")
    if set(rejected).intersection(row_lines):
        raise J0Error("examples_selection: selected/rejected row overlap")
    if census is not None:
        _validate_census_structure(census)
        if obj["project"] != census["project"] \
                or obj["items_file_sha256"] != census["items_file_sha256"] \
                or obj["census_manifest_sha256"] != _sha256(
                    canonical_json_bytes(dict(census))):
            raise J0Error("examples_selection: census identity mismatch")
        rebuilt = build_examples_selection(census)
        if canonical_json_bytes(obj) != canonical_json_bytes(rebuilt):
            raise J0Error("examples_selection: algorithm reconstruction mismatch")
    return obj


def _node_start_line(node: Mapping[str, Any]) -> int:
    lines = [node["location"]["line"]]
    lines.extend(tag["location"]["line"] for tag in node.get("tags", []))
    return min(lines)


def _child_span(
    children: Sequence[Mapping[str, Any]],
    index: int,
    parent_end: int,
) -> tuple[int, int]:
    start = _node_start_line(children[index])
    end = (_node_start_line(children[index + 1]) - 1
           if index + 1 < len(children) else parent_end)
    if end < start:
        raise J0Error("Gherkin AST child spans overlap")
    return start, end


def _find_scenario_context(
    ast: Mapping[str, Any], line: int,
) -> tuple[Mapping[str, Any], Mapping[str, Any] | None, int, int]:
    """Return scenario, parent Rule-or-null, child index, parent index."""
    feature = ast["feature"]
    for feature_index, child in enumerate(feature["children"]):
        if child["type"] == "scenario" and child["location"]["line"] == line:
            return child, None, feature_index, feature_index
        if child["type"] == "rule":
            for rule_index, nested in enumerate(child["children"]):
                if nested["type"] == "scenario" \
                        and nested["location"]["line"] == line:
                    return nested, child, rule_index, feature_index
    raise J0Error(f"selected outline line {line} is absent from parser AST")


def _index_structural_keys(ast: Mapping[str, Any], source_uri: str) \
        -> dict[tuple[str, int, int], list[Any]]:
    """Reconstruct every stable AST key without reading generated node ids."""
    feature = ast["feature"]
    feature_key = _structural_key(
        source_uri, "Feature", feature["location"], None, 0)
    out: dict[tuple[str, int, int], list[Any]] = {
        ("Feature", feature["location"]["line"], feature["location"]["column"]):
            feature_key,
    }

    def add_children(children: Sequence[Mapping[str, Any]], parent: list[Any]) -> None:
        ordinals: dict[str, int] = {}
        for child in children:
            if child["type"] == "background":
                kind = "Background"
            elif child["type"] == "rule":
                kind = "Rule"
            else:
                kind = "ScenarioOutline" if _scenario_form(child) == "outline" \
                    else "Scenario"
            ordinal = ordinals.get(kind, 0)
            ordinals[kind] = ordinal + 1
            key = _structural_key(source_uri, kind, child["location"], parent, ordinal)
            locator = (kind, child["location"]["line"], child["location"]["column"])
            if locator in out:
                raise J0Error(f"duplicate AST structural locator: {locator!r}")
            out[locator] = key
            if child["type"] == "rule":
                add_children(child["children"], key)
            elif child["type"] in {"background", "scenario"}:
                for step_ordinal, step in enumerate(child["steps"]):
                    step_key = _structural_key(
                        source_uri, "Step", step["location"], key, step_ordinal)
                    locator = ("Step", step["location"]["line"],
                               step["location"]["column"])
                    if locator in out:
                        raise J0Error(f"duplicate AST step locator: {locator!r}")
                    out[locator] = step_key
            if child["type"] == "scenario":
                for examples_ordinal, examples in enumerate(child["examples"]):
                    examples_key = _structural_key(
                        source_uri, "Examples", examples["location"], key,
                        examples_ordinal)
                    locator = ("Examples", examples["location"]["line"],
                               examples["location"]["column"])
                    if locator in out:
                        raise J0Error(f"duplicate AST Examples locator: {locator!r}")
                    out[locator] = examples_key
                    for row_ordinal, row in enumerate(examples["table_body"]):
                        row_key = _structural_key(
                            source_uri, "ExamplesRow", row["location"],
                            examples_key, row_ordinal)
                        locator = ("ExamplesRow", row["location"]["line"],
                                   row["location"]["column"])
                        if locator in out:
                            raise J0Error(f"duplicate AST row locator: {locator!r}")
                        out[locator] = row_key

    add_children(feature["children"], feature_key)
    return out


def _index_structural_spans(
    ast: Mapping[str, Any],
    source_uri: str,
    total_lines: int,
) -> dict[bytes, list[int]]:
    if total_lines < 1:
        raise J0Error("cannot index structural spans for an empty source")
    keys = _index_structural_keys(ast, source_uri)
    feature = ast["feature"]
    spans: dict[bytes, list[int]] = {}

    def record(kind: str, node: Mapping[str, Any], start: int, end: int) -> None:
        locator = (kind, node["location"]["line"], node["location"]["column"])
        key = keys.get(locator)
        if key is None or start < 1 or end < start or end > total_lines:
            raise J0Error(f"invalid structural span for {locator!r}: {start}:{end}")
        encoded = canonical_json_bytes(key, terminal_lf=False)
        if encoded in spans:
            raise J0Error(f"duplicate structural span key: {locator!r}")
        spans[encoded] = [start, end]

    def add_steps(
        owner: Mapping[str, Any],
        owner_end: int,
        following_start: int | None,
    ) -> None:
        steps = owner["steps"]
        for index, step in enumerate(steps):
            end = (step["location"]["line"] if index + 1 >= len(steps)
                   else steps[index + 1]["location"]["line"] - 1)
            if index + 1 >= len(steps):
                end = ((following_start - 1) if following_start is not None
                       else owner_end)
            record("Step", step, step["location"]["line"], end)

    def add_children(
        children: Sequence[Mapping[str, Any]],
        parent_end: int,
    ) -> None:
        for index, child in enumerate(children):
            child_start, child_end = _child_span(children, index, parent_end)
            if child["type"] == "rule":
                nested = child["children"]
                own_end = (_node_start_line(nested[0]) - 1 if nested else child_end)
                record("Rule", child, child_start, own_end)
                add_children(nested, child_end)
                continue
            if child["type"] == "background":
                steps = child["steps"]
                own_end = (steps[0]["location"]["line"] - 1
                           if steps else child_end)
                record("Background", child, child_start, own_end)
                add_steps(child, child_end, None)
                continue
            kind = "ScenarioOutline" if _scenario_form(child) == "outline" \
                else "Scenario"
            nested_starts = [step["location"]["line"] for step in child["steps"]]
            nested_starts.extend(_node_start_line(block) for block in child["examples"])
            own_end = min(nested_starts) - 1 if nested_starts else child_end
            record(kind, child, child_start, own_end)
            first_examples = (_node_start_line(child["examples"][0])
                              if child["examples"] else None)
            add_steps(child, child_end, first_examples)
            for block_index, block in enumerate(child["examples"]):
                block_start = _node_start_line(block)
                block_end = (_node_start_line(child["examples"][block_index + 1]) - 1
                             if block_index + 1 < len(child["examples"])
                             else child_end)
                rows = block["table_body"]
                own_block_end = (rows[0]["location"]["line"] - 1
                                 if rows else block_end)
                record("Examples", block, block_start, own_block_end)
                for row in rows:
                    line = row["location"]["line"]
                    record("ExamplesRow", row, line, line)

    children = feature["children"]
    feature_end = (_node_start_line(children[0]) - 1 if children else total_lines)
    record("Feature", feature, 1, feature_end)
    add_children(children, total_lines)
    return spans


def _build_structural_span_mappings(
    source_ast: Mapping[str, Any],
    source_uri: str,
    source_total_lines: int,
    output_ast: Mapping[str, Any],
    output_uri: str,
    output_total_lines: int,
    source_line_by_output_line: Sequence[int],
) -> tuple[list[dict[str, Any]], list[dict[str, int]]]:
    if len(source_line_by_output_line) != output_total_lines:
        raise J0Error("slicer line authority does not cover every output line")
    if list(source_line_by_output_line) != sorted(source_line_by_output_line) \
            or len(set(source_line_by_output_line)) != len(source_line_by_output_line):
        raise J0Error("slicer source lines are not a strict ordered subsequence")
    source_keys = _index_structural_keys(source_ast, source_uri)
    output_keys = _index_structural_keys(output_ast, output_uri)
    source_spans = _index_structural_spans(
        source_ast, source_uri, source_total_lines)
    output_spans = _index_structural_spans(
        output_ast, output_uri, output_total_lines)
    source_to_output = {
        source_line: output_line
        for output_line, source_line in enumerate(source_line_by_output_line, 1)
    }
    expected_source_keys: set[bytes] = set()
    for encoded_key, source_span in source_spans.items():
        output_lines = [
            source_to_output.get(line)
            for line in range(source_span[0], source_span[1] + 1)
        ]
        if all(line is not None for line in output_lines) \
                and output_lines == list(range(
                    output_lines[0], output_lines[0] + len(output_lines))):
            expected_source_keys.add(encoded_key)
    mappings: list[dict[str, Any]] = []
    for (kind, output_line, column), output_key in output_keys.items():
        source_line = source_line_by_output_line[output_line - 1]
        source_key = source_keys.get((kind, source_line, column))
        if source_key is None:
            raise J0Error(
                f"output structural key lacks verbatim source peer: "
                f"{kind}:{output_line}:{column}")
        source_span = source_spans[canonical_json_bytes(
            source_key, terminal_lf=False)]
        output_span = output_spans[canonical_json_bytes(
            output_key, terminal_lf=False)]
        mapped_lines = list(source_line_by_output_line[
            output_span[0] - 1:output_span[1]])
        if mapped_lines != list(range(source_span[0], source_span[1] + 1)):
            raise J0Error(
                f"structural span is not an exact verbatim mapping: {kind}")
        mappings.append({
            "kind": kind,
            "output_key": output_key,
            "output_span": output_span,
            "source_key": source_key,
            "source_span": source_span,
        })
    mapped_source_keys = {
        canonical_json_bytes(mapping["source_key"], terminal_lf=False)
        for mapping in mappings
    }
    if mapped_source_keys != expected_source_keys:
        raise J0Error(
            "output structural inventory is not the complete preserved source inventory")
    mappings.sort(key=lambda item: canonical_json_bytes(item, terminal_lf=False))
    line_mappings = [
        {"output_line": index, "source_line": source_line}
        for index, source_line in enumerate(source_line_by_output_line, 1)
    ]
    return mappings, line_mappings


def _normalize_runtime_pickles(
    ast: Mapping[str, Any],
    source_uri: str,
    runtime_uri: str,
) -> list[dict[str, Any]]:
    validate_bridge_ast(ast, source_uri)
    validate_posix_path(runtime_uri, where="runtime_pickle.runtime_uri")
    keys = _index_structural_keys(ast, source_uri)
    records: list[dict[str, Any]] = []
    for index, value in enumerate(ast["pickles"]):
        pickle = _validate_bridge_pickle(value, f"bridge_ast.pickles[{index}]")
        scenario_key: list[Any] | None = None
        row_key: list[Any] | None = None
        for ref in pickle["ast_node_refs"]:
            line = ref["location"]["line"]
            column = ref["location"]["column"]
            if ref["kind"] == "Scenario":
                candidates = [
                    keys[locator] for locator in (
                        ("Scenario", line, column),
                        ("ScenarioOutline", line, column),
                    ) if locator in keys
                ]
                if len(candidates) != 1:
                    raise J0Error("Pickle Scenario ref has no unique structural key")
                scenario_key = candidates[0]
            else:
                locator = ("ExamplesRow", line, column)
                if locator not in keys:
                    raise J0Error("Pickle ExamplesRow ref has no structural key")
                row_key = keys[locator]
        if scenario_key is None:
            raise J0Error("Pickle lacks Scenario structural identity")
        if row_key is not None:
            examples_key = row_key[4]
            if examples_key is None or examples_key[4] != scenario_key:
                raise J0Error("Pickle row/scenario structural identity mismatch")
        records.append({
            "effective_tags": pickle["effective_tags"],
            "language": pickle["language"],
            "name": pickle["name"],
            "row_key": row_key,
            "runtime_uri": runtime_uri,
            "scenario_key": scenario_key,
        })
    records.sort(key=lambda item: canonical_json_bytes(item, terminal_lf=False))
    return records


def _runtime_pickle_structure(
    records: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return sorted([
        {
            "effective_tags": record["effective_tags"],
            "row_key": record["row_key"],
            "scenario_key": record["scenario_key"],
        }
        for record in records
    ], key=lambda item: canonical_json_bytes(item, terminal_lf=False))


def _require_equal_runtime_pickle_multisets(
    source_records: Sequence[Mapping[str, Any]],
    sliced_records: Sequence[Mapping[str, Any]],
    expected_count: int,
) -> None:
    if len(source_records) != expected_count \
            or len(sliced_records) != expected_count \
            or canonical_json_bytes(list(source_records)) \
            != canonical_json_bytes(list(sliced_records)):
        raise J0Error(
            "official source-selected and sliced runtime Pickle multisets differ")


def _expected_runtime_pickle_structure(
    items: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    expected: list[dict[str, Any]] = []
    for item in items:
        if item["form"] == "plain":
            expected.append({
                "effective_tags": item["effective_tags"],
                "row_key": None,
                "scenario_key": item["structural_key"],
            })
        else:
            for row in item["rows"]:
                expected.append({
                    "effective_tags": row["effective_tags"],
                    "row_key": row["structural_key"],
                    "scenario_key": item["structural_key"],
                })
    expected.sort(key=lambda item: canonical_json_bytes(item, terminal_lf=False))
    return expected


def _slice_examples_bytes(
    raw: bytes,
    ast: Mapping[str, Any],
    scenario_line: int,
    selected_row_lines: set[int],
) -> tuple[bytes, dict[str, Any]]:
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise J0Error("slicer input is not strict UTF-8") from exc
    if b"\r" in raw:
        raise J0Error("slicer input must use LF, not CR")
    lines = raw.splitlines(keepends=True)
    if not lines:
        raise J0Error("slicer input is empty")
    feature = ast["feature"]
    scenario, rule, scenario_index, feature_index = _find_scenario_context(
        ast, scenario_line)
    if _scenario_form(scenario) != "outline" or not scenario["examples"]:
        raise J0Error("slicer target is not an outline with Examples")
    total_lines = len(lines)
    feature_children = feature["children"]
    first_child_start = (_node_start_line(feature_children[0])
                         if feature_children else total_lines + 1)
    chunks: list[bytes] = []
    source_line_by_output_line: list[int] = []

    def append_range(start: int, end: int) -> None:
        if start < 1 or end > total_lines or end < start:
            raise J0Error(f"invalid source span {start}:{end}")
        for line_number in range(start, end + 1):
            chunks.append(lines[line_number - 1])
            source_line_by_output_line.append(line_number)

    # Language header, Feature tags/header/name/narrative are one verbatim
    # prefix.  No semantic field is rendered back into text.
    append_range(1, first_child_start - 1)

    # Feature Background applies to scenarios both directly and under Rule.
    preserved_background_spans: list[list[int]] = []
    for index, child in enumerate(feature_children):
        if child["type"] == "background":
            start, end = _child_span(feature_children, index, total_lines)
            append_range(start, end)
            preserved_background_spans.append([start, end])

    if rule is None:
        scenario_end = _child_span(
            feature_children, scenario_index, total_lines)[1]
        rule_span = None
    else:
        rule_start, rule_end = _child_span(
            feature_children, feature_index, total_lines)
        rule_children = rule["children"]
        if not rule_children:
            raise J0Error("selected Rule has no children")
        rule_header_end = _node_start_line(rule_children[0]) - 1
        append_range(rule_start, rule_header_end)
        for index, child in enumerate(rule_children):
            if child["type"] == "background":
                start, end = _child_span(rule_children, index, rule_end)
                append_range(start, end)
                preserved_background_spans.append([start, end])
        scenario_end = _child_span(rule_children, scenario_index, rule_end)[1]
        rule_span = [rule_start, rule_end]

    examples = scenario["examples"]
    scenario_start = _node_start_line(scenario)
    first_examples_start = _node_start_line(examples[0])
    append_range(scenario_start, first_examples_start - 1)
    selected_blocks: list[dict[str, Any]] = []
    all_body_lines: set[int] = set()
    for block in examples:
        all_body_lines.update(row["location"]["line"] for row in block["table_body"])
    if not selected_row_lines.issubset(all_body_lines):
        raise J0Error("selected row line is absent from target outline")

    for index, block in enumerate(examples):
        block_rows = {row["location"]["line"] for row in block["table_body"]}
        keep = sorted(block_rows.intersection(selected_row_lines))
        if not keep:
            continue
        start = _node_start_line(block)
        end = (_node_start_line(examples[index + 1]) - 1
               if index + 1 < len(examples) else scenario_end)
        for line_number in range(start, end + 1):
            if line_number not in block_rows or line_number in selected_row_lines:
                chunks.append(lines[line_number - 1])
                source_line_by_output_line.append(line_number)
        selected_blocks.append({
            "source_span": [start, end],
            "selected_row_lines": keep,
        })
    if not selected_blocks:
        raise J0Error("slicer selected no Examples block")
    output = b"".join(chunks)
    if not output:
        raise J0Error("slicer produced empty output")
    evidence = {
        "preserved_background_spans": preserved_background_spans,
        "rule_span": rule_span,
        "scenario_span": [scenario_start, scenario_end],
        "selected_blocks": selected_blocks,
        "source_line_by_output_line": source_line_by_output_line,
    }
    return output, evidence


def build_examples_overlay(
    census: Mapping[str, Any],
    selection: Mapping[str, Any],
    source_root: os.PathLike[str] | str,
    bridge: GherkinParserBridge,
    parser_artifacts: Sequence[os.PathLike[str] | str],
    output_tree: os.PathLike[str] | str,
) -> dict[str, Any]:
    validate_census(census)
    validate_examples_selection(selection, census)
    if census["project"] != selection["project"]:
        raise J0Error("overlay project mismatch")
    project = census["project"]
    selected_item = selection["selected_item"]
    source_uri = selected_item["source_uri"]
    source_path = _safe_join(Path(source_root), source_uri)
    raw, _ = _read_relative_regular_nofollow(source_root, source_uri)
    try:
        source_text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise J0Error("overlay input feature is not strict UTF-8") from exc
    feature_entry = next((entry for entry in census["features"]
                          if entry["source_uri"] == source_uri), None)
    if feature_entry is None or _sha256(raw) != feature_entry["raw_file_sha256"]:
        raise J0Error("overlay input feature does not match census")
    source_ast = bridge.parse(
        project, source_path, source_uri, parser_artifacts)
    if _sha256(canonical_json_bytes(source_ast)) != feature_entry["ast_canonical_sha256"]:
        raise J0Error("overlay input AST does not match census")
    selected_lines = {row["line"] for row in selection["rows"]}
    output_raw, slicing = _slice_examples_bytes(
        raw, source_ast, selected_item["line"], selected_lines)

    output_tree = Path(output_tree)
    _require_new_empty_directory(output_tree)
    output_path = "src/test/resources/r2t-j0/examples.feature"
    output_file = _safe_join(output_tree, output_path)
    _write_new_file(output_file, output_raw)
    output_ast = bridge.parse(
        project, output_file, output_path, parser_artifacts)
    structural_span_mappings, source_output_line_map = (
        _build_structural_span_mappings(
            source_ast, source_uri, len(raw.splitlines()),
            output_ast, output_path, len(output_raw.splitlines()),
            slicing["source_line_by_output_line"],
        )
    )
    admitted_tags: set[str] | None = None
    if project == "algorand-sdk":
        expression = census["tag_expression"]
        admitted_tags = set(expression[1:-1].split(") or ("))
    projected = _flatten_scenarios(
        output_ast, output_path, "r2t-j0/examples.feature", admitted_tags)
    if len(projected) != 1 or projected[0]["form"] != "outline" \
            or not projected[0]["admitted"]:
        raise J0Error("Examples overlay did not reparse to one admitted outline")
    output_item = projected[0]
    output_rows = [row for row in output_item["rows"] if row["admitted"]]
    if len(output_rows) != len(selection["rows"]):
        raise J0Error("Examples overlay pickle count differs from selection")
    row_mappings: list[dict[str, Any]] = []
    for source_row, output_row in zip(selection["rows"], output_rows):
        if source_row["raw_cells"] != output_row["raw_cells"] \
                or source_row["effective_tags"] != output_row["effective_tags"]:
            raise J0Error("Examples overlay changed selected row values/effective tags")
        row_mappings.append({
            "effective_tags": source_row["effective_tags"],
            "output_examples_key": output_row["examples_key"],
            "output_line": output_row["line"],
            "output_span": [output_row["line"], output_row["line"]],
            "output_structural_key": output_row["structural_key"],
            "source_examples_key": source_row["examples_key"],
            "source_line": source_row["line"],
            "source_span": [source_row["line"], source_row["line"]],
            "source_structural_key": source_row["structural_key"],
        })

    source_keys = _index_structural_keys(source_ast, source_uri)
    output_keys = _index_structural_keys(output_ast, output_path)
    unique_source_keys = {
        canonical_json_bytes(mapping["source_key"], terminal_lf=False):
            mapping["source_key"]
        for mapping in structural_span_mappings
    }
    preserved_source_keys = [
        unique_source_keys[key] for key in sorted(unique_source_keys)
    ]

    output_step_keys = [
        output_keys[("Step", step["line"], step["column"])]
        for step in output_item["steps"]
    ]
    preserved_output_by_bytes = {
        canonical_json_bytes(mapping["output_key"], terminal_lf=False):
            mapping["output_key"]
        for mapping in structural_span_mappings
    }
    preserved_output_keys = [
        preserved_output_by_bytes[key] for key in sorted(preserved_output_by_bytes)
    ]
    output_to_source = {
        canonical_json_bytes(mapping["output_key"], terminal_lf=False):
            mapping["source_key"]
        for mapping in structural_span_mappings
    }
    selected_row_keys = {
        canonical_json_bytes(row["structural_key"], terminal_lf=False)
        for row in selection["rows"]
    }
    source_runtime_pickles = _normalize_runtime_pickles(
        source_ast, source_uri, selected_item["runtime_uri"])
    source_selected_runtime_pickles = sorted([
        {
            "effective_tags": record["effective_tags"],
            "language": record["language"],
            "name": record["name"],
            "source_row_key": record["row_key"],
            "source_scenario_key": record["scenario_key"],
        }
        for record in source_runtime_pickles
        if record["scenario_key"] == selected_item["structural_key"]
        and record["row_key"] is not None
        and canonical_json_bytes(record["row_key"], terminal_lf=False)
        in selected_row_keys
    ], key=lambda item: canonical_json_bytes(item, terminal_lf=False))
    sliced_runtime_pickles: list[dict[str, Any]] = []
    for record in _normalize_runtime_pickles(
            output_ast, output_path, "r2t-j0/examples.feature"):
        scenario = output_to_source.get(canonical_json_bytes(
            record["scenario_key"], terminal_lf=False))
        row = (None if record["row_key"] is None else output_to_source.get(
            canonical_json_bytes(record["row_key"], terminal_lf=False)))
        if scenario is None or row is None:
            raise J0Error("sliced runtime Pickle lacks source structural mapping")
        sliced_runtime_pickles.append({
            "effective_tags": record["effective_tags"],
            "language": record["language"],
            "name": record["name"],
            "source_row_key": row,
            "source_scenario_key": scenario,
        })
    sliced_runtime_pickles.sort(
        key=lambda item: canonical_json_bytes(item, terminal_lf=False))
    _require_equal_runtime_pickle_multisets(
        source_selected_runtime_pickles, sliced_runtime_pickles,
        selection["selected_row_count"])
    parser = bridge.identity(project, parser_artifacts)
    manifest = {
        "input_feature": {
            "raw_file_sha256": _sha256(raw),
            "raw_utf8": source_text,
            "runtime_uri": selected_item["runtime_uri"],
            "source_uri": source_uri,
        },
        "output_ast": output_ast,
        "output_outline_line": output_item["line"],
        "output_path": output_path,
        "output_raw_file_sha256": _sha256(output_raw),
        "output_scenario_key": output_item["structural_key"],
        "output_step_keys": output_step_keys,
        "overlay_tree_digest_domain": TREE_DOMAIN,
        "overlay_tree_sha256": framed_tree_sha256([(output_path, output_raw)]),
        "parser": parser,
        "preserved_output_keys": preserved_output_keys,
        "preserved_source_keys": preserved_source_keys,
        "project": project,
        "rejected_row_lines": selection["rejected_row_lines"],
        "row_mappings": row_mappings,
        "runtime_selector": (
            f"classpath:r2t-j0/examples.feature:{output_item['line']}"),
        "runtime_pickle_multiset_sha256": _sha256(canonical_json_bytes(
            source_selected_runtime_pickles)),
        "schema": EXAMPLES_OVERLAY_SCHEMA,
        "selection_manifest_sha256": _sha256(
            canonical_json_bytes(dict(selection))),
        "slicer_source_sha256": _raw_sha256(Path(__file__)),
        "sliced_runtime_pickles": sliced_runtime_pickles,
        "source_output_line_map": source_output_line_map,
        "source_scenario_span": slicing["scenario_span"],
        "source_ast": source_ast,
        "source_selected_runtime_pickles": source_selected_runtime_pickles,
        "structural_span_mappings": structural_span_mappings,
    }
    validate_examples_overlay(manifest, selection, census)
    return manifest


def _validate_span(value: Any, where: str) -> list[int]:
    if not isinstance(value, list) or len(value) != 2:
        raise J0Error(f"{where}: expected [start,end]")
    start = _integer(value[0], f"{where}[0]", minimum=1)
    end = _integer(value[1], f"{where}[1]", minimum=1)
    if end < start:
        raise J0Error(f"{where}: reversed span")
    return value


def validate_examples_overlay(
    overlay: Any,
    selection: Mapping[str, Any] | None = None,
    census: Mapping[str, Any] | None = None,
    output_tree: os.PathLike[str] | str | None = None,
) -> dict[str, Any]:
    obj = _closed(overlay, {
        "input_feature", "output_outline_line", "output_path",
        "output_ast", "output_raw_file_sha256", "output_scenario_key",
        "output_step_keys",
        "overlay_tree_digest_domain", "overlay_tree_sha256", "parser",
        "preserved_output_keys", "preserved_source_keys", "project",
        "rejected_row_lines", "row_mappings",
        "runtime_pickle_multiset_sha256", "runtime_selector", "schema",
        "selection_manifest_sha256", "slicer_source_sha256",
        "sliced_runtime_pickles", "source_output_line_map",
        "source_ast", "source_scenario_span", "source_selected_runtime_pickles",
        "structural_span_mappings",
    }, "examples_overlay")
    if obj["schema"] != EXAMPLES_OVERLAY_SCHEMA:
        raise J0Error("examples_overlay.schema: wrong schema")
    project = obj["project"]
    if project not in {"epubcheck", "algorand-sdk"}:
        raise J0Error("examples_overlay.project: invalid")
    if selection is None or census is None:
        raise J0Error(
            "examples_overlay: selection and pinned census are required")
    validate_census(census)
    validate_examples_selection(selection, census)
    if census["project"] != project or selection["project"] != project:
        raise J0Error("examples_overlay: project authority mismatch")
    validate_parser_identity(obj["parser"], project)
    _hex(obj["selection_manifest_sha256"], 64,
         "examples_overlay.selection_manifest_sha256")
    _hex(obj["slicer_source_sha256"], 64,
         "examples_overlay.slicer_source_sha256")
    if obj["slicer_source_sha256"] != _raw_sha256(Path(__file__)):
        raise J0Error("examples_overlay.slicer_source_sha256: implementation drift")
    input_feature = _closed(obj["input_feature"], {
        "raw_file_sha256", "raw_utf8", "runtime_uri", "source_uri",
    }, "examples_overlay.input_feature")
    _hex(input_feature["raw_file_sha256"], 64,
         "examples_overlay.input_feature.raw_file_sha256")
    source_uri = validate_posix_path(
        input_feature["source_uri"],
        where="examples_overlay.input_feature.source_uri")
    source_text = _string(
        input_feature["raw_utf8"], "examples_overlay.input_feature.raw_utf8")
    source_raw = source_text.encode("utf-8")
    if _sha256(source_raw) != input_feature["raw_file_sha256"]:
        raise J0Error("examples_overlay.input_feature.raw_utf8: digest mismatch")
    validate_posix_path(input_feature["runtime_uri"],
                        where="examples_overlay.input_feature.runtime_uri")
    output_path = validate_posix_path(obj["output_path"],
                                      where="examples_overlay.output_path")
    if output_path != "src/test/resources/r2t-j0/examples.feature":
        raise J0Error("examples_overlay.output_path: protocol path mismatch")
    source_ast = validate_bridge_ast(obj["source_ast"], source_uri)
    output_ast = validate_bridge_ast(obj["output_ast"], output_path)
    feature_record = next((
        entry for entry in census["features"]
        if entry["source_uri"] == source_uri
    ), None)
    if feature_record is None \
            or feature_record["raw_file_sha256"] != _sha256(source_raw) \
            or feature_record["ast_canonical_sha256"] != _sha256(
                canonical_json_bytes(source_ast)):
        raise J0Error(
            "examples_overlay source bytes/AST do not match the pinned census")
    selected_item = selection["selected_item"]
    expected_output_raw, expected_slicing = _slice_examples_bytes(
        source_raw, source_ast, selected_item["line"],
        {row["line"] for row in selection["rows"]},
    )
    output_line = _integer(obj["output_outline_line"],
                           "examples_overlay.output_outline_line", minimum=1)
    _hex(obj["output_raw_file_sha256"], 64,
         "examples_overlay.output_raw_file_sha256")
    if obj["output_raw_file_sha256"] != _sha256(expected_output_raw):
        raise J0Error("examples_overlay.output_raw_file_sha256: slice mismatch")
    if obj["overlay_tree_digest_domain"] != TREE_DOMAIN:
        raise J0Error("examples_overlay.overlay_tree_digest_domain: mismatch")
    _hex(obj["overlay_tree_sha256"], 64,
         "examples_overlay.overlay_tree_sha256")
    if obj["overlay_tree_sha256"] != framed_tree_sha256(
            [(output_path, expected_output_raw)]):
        raise J0Error("examples_overlay.overlay_tree_sha256: slice mismatch")
    if obj["runtime_selector"] != f"classpath:r2t-j0/examples.feature:{output_line}":
        raise J0Error("examples_overlay.runtime_selector: mismatch")
    output_scenario = _validate_structural_key(
        obj["output_scenario_key"], "examples_overlay.output_scenario_key",
        source_uri=output_path)
    if output_scenario[1] != "ScenarioOutline" or output_scenario[2] != output_line:
        raise J0Error("examples_overlay.output_scenario_key: mismatch")
    source_span = _validate_span(obj["source_scenario_span"],
                                 "examples_overlay.source_scenario_span")
    if source_span != expected_slicing["scenario_span"]:
        raise J0Error("examples_overlay.source_scenario_span: slicer mismatch")

    if not isinstance(obj["source_output_line_map"], list) \
            or not obj["source_output_line_map"]:
        raise J0Error("examples_overlay.source_output_line_map: expected nonempty array")
    mapped_source_lines: list[int] = []
    for index, value in enumerate(obj["source_output_line_map"]):
        where = f"examples_overlay.source_output_line_map[{index}]"
        mapping = _closed(value, {"output_line", "source_line"}, where)
        if mapping["output_line"] != index + 1:
            raise J0Error(f"{where}.output_line: not contiguous")
        mapped_source_lines.append(_integer(
            mapping["source_line"], f"{where}.source_line", minimum=1))
    if mapped_source_lines != sorted(mapped_source_lines) \
            or len(mapped_source_lines) != len(set(mapped_source_lines)):
        raise J0Error(
            "examples_overlay.source_output_line_map: source lines not strict ordered")
    expected_line_map = [
        {"output_line": index, "source_line": source_line}
        for index, source_line in enumerate(
            expected_slicing["source_line_by_output_line"], 1)
    ]
    if obj["source_output_line_map"] != expected_line_map:
        raise J0Error(
            "examples_overlay.source_output_line_map: exact slicer mismatch")

    if not isinstance(obj["output_step_keys"], list):
        raise J0Error("examples_overlay.output_step_keys: expected array")
    for index, key in enumerate(obj["output_step_keys"]):
        step = _validate_structural_key(
            key, f"examples_overlay.output_step_keys[{index}]",
            source_uri=output_path)
        if step[1] != "Step" or step[4] != output_scenario or step[5] != index:
            raise J0Error("examples_overlay.output_step_keys: parent/order mismatch")

    if not isinstance(obj["preserved_source_keys"], list) \
            or not obj["preserved_source_keys"]:
        raise J0Error("examples_overlay.preserved_source_keys: expected nonempty array")
    encoded_keys: list[bytes] = []
    for index, key in enumerate(obj["preserved_source_keys"]):
        _validate_structural_key(
            key, f"examples_overlay.preserved_source_keys[{index}]",
            source_uri=source_uri)
        encoded_keys.append(canonical_json_bytes(key, terminal_lf=False))
    if encoded_keys != sorted(encoded_keys) or len(encoded_keys) != len(set(encoded_keys)):
        raise J0Error("examples_overlay.preserved_source_keys: not unique canonical sorted")
    if not isinstance(obj["preserved_output_keys"], list) \
            or not obj["preserved_output_keys"]:
        raise J0Error("examples_overlay.preserved_output_keys: expected nonempty array")
    encoded_output_keys: list[bytes] = []
    for index, key in enumerate(obj["preserved_output_keys"]):
        _validate_structural_key(
            key, f"examples_overlay.preserved_output_keys[{index}]",
            source_uri=output_path)
        encoded_output_keys.append(canonical_json_bytes(key, terminal_lf=False))
    if encoded_output_keys != sorted(encoded_output_keys) \
            or len(encoded_output_keys) != len(set(encoded_output_keys)):
        raise J0Error("examples_overlay.preserved_output_keys: not unique canonical sorted")
    if canonical_json_bytes(output_scenario, terminal_lf=False) \
            not in set(encoded_output_keys):
        raise J0Error("examples_overlay.preserved_output_keys: missing output outline")
    output_key_set = set(encoded_output_keys)
    source_key_set = set(encoded_keys)
    if any(canonical_json_bytes(key, terminal_lf=False) not in output_key_set
           for key in obj["output_step_keys"]):
        raise J0Error("examples_overlay.preserved_output_keys: missing output step")

    if not isinstance(obj["structural_span_mappings"], list) \
            or not obj["structural_span_mappings"]:
        raise J0Error("examples_overlay.structural_span_mappings: expected array")
    structural_encoded: list[bytes] = []
    mapped_source_keys: set[bytes] = set()
    mapped_output_keys: set[bytes] = set()
    for index, value in enumerate(obj["structural_span_mappings"]):
        where = f"examples_overlay.structural_span_mappings[{index}]"
        mapping = _closed(value, {
            "kind", "output_key", "output_span", "source_key", "source_span",
        }, where)
        kind = _string(mapping["kind"], f"{where}.kind")
        source_key = _validate_structural_key(
            mapping["source_key"], f"{where}.source_key", source_uri=source_uri)
        output_key = _validate_structural_key(
            mapping["output_key"], f"{where}.output_key", source_uri=output_path)
        if source_key[1] != kind or output_key[1] != kind:
            raise J0Error(f"{where}.kind: structural-key mismatch")
        source_node_span = _validate_span(mapping["source_span"],
                                          f"{where}.source_span")
        output_node_span = _validate_span(mapping["output_span"],
                                          f"{where}.output_span")
        if not (source_node_span[0] <= source_key[2] <= source_node_span[1]) \
                or not (output_node_span[0] <= output_key[2] <= output_node_span[1]):
            raise J0Error(f"{where}: node location outside its span")
        mapped = mapped_source_lines[
            output_node_span[0] - 1:output_node_span[1]]
        if mapped != list(range(source_node_span[0], source_node_span[1] + 1)):
            raise J0Error(f"{where}: span is not exact in line map")
        source_encoded = canonical_json_bytes(source_key, terminal_lf=False)
        output_encoded = canonical_json_bytes(output_key, terminal_lf=False)
        if source_encoded in mapped_source_keys or output_encoded in mapped_output_keys:
            raise J0Error(f"{where}: duplicate structural mapping")
        mapped_source_keys.add(source_encoded)
        mapped_output_keys.add(output_encoded)
        structural_encoded.append(canonical_json_bytes(mapping, terminal_lf=False))
    if structural_encoded != sorted(structural_encoded):
        raise J0Error("examples_overlay.structural_span_mappings: not canonical sorted")
    expected_structural_mappings, rebuilt_line_map = (
        _build_structural_span_mappings(
            source_ast, source_uri, len(source_raw.splitlines()),
            output_ast, output_path, len(expected_output_raw.splitlines()),
            expected_slicing["source_line_by_output_line"],
        )
    )
    if rebuilt_line_map != expected_line_map \
            or obj["structural_span_mappings"] != expected_structural_mappings:
        raise J0Error(
            "examples_overlay.structural_span_mappings: exact AST/slicer mismatch")
    if mapped_source_keys != source_key_set or mapped_output_keys != output_key_set:
        raise J0Error(
            "examples_overlay.structural_span_mappings: preserved-key coverage mismatch")

    def validate_runtime_pickles(value: Any, where: str) -> list[dict[str, Any]]:
        if not isinstance(value, list) or len(value) < 2:
            raise J0Error(f"{where}: expected at least two Pickles")
        records: list[dict[str, Any]] = []
        encoded: list[bytes] = []
        for index, raw_record in enumerate(value):
            item_where = f"{where}[{index}]"
            record = _closed(raw_record, {
                "effective_tags", "language", "name", "source_row_key",
                "source_scenario_key",
            }, item_where)
            _validate_tags_array(record["effective_tags"],
                                 f"{item_where}.effective_tags")
            _string(record["language"], f"{item_where}.language")
            _string(record["name"], f"{item_where}.name", nonempty=False)
            scenario = _validate_structural_key(
                record["source_scenario_key"],
                f"{item_where}.source_scenario_key", source_uri=source_uri)
            row = _validate_structural_key(
                record["source_row_key"], f"{item_where}.source_row_key",
                source_uri=source_uri)
            if scenario[1] != "ScenarioOutline" or row[1] != "ExamplesRow" \
                    or row[4] is None or row[4][4] != scenario:
                raise J0Error(f"{item_where}: Pickle structural parent mismatch")
            records.append(record)
            encoded.append(canonical_json_bytes(record, terminal_lf=False))
        if encoded != sorted(encoded):
            raise J0Error(f"{where}: not canonical sorted")
        return records

    source_runtime_pickles = validate_runtime_pickles(
        obj["source_selected_runtime_pickles"],
        "examples_overlay.source_selected_runtime_pickles")
    sliced_runtime_pickles = validate_runtime_pickles(
        obj["sliced_runtime_pickles"],
        "examples_overlay.sliced_runtime_pickles")
    if source_runtime_pickles != sliced_runtime_pickles:
        raise J0Error("examples_overlay: source/sliced runtime Pickle multiset mismatch")
    selected_row_key_set = {
        canonical_json_bytes(row["structural_key"], terminal_lf=False)
        for row in selection["rows"]
    }
    expected_source_runtime_pickles = sorted([
        {
            "effective_tags": record["effective_tags"],
            "language": record["language"],
            "name": record["name"],
            "source_row_key": record["row_key"],
            "source_scenario_key": record["scenario_key"],
        }
        for record in _normalize_runtime_pickles(
            source_ast, source_uri, selected_item["runtime_uri"])
        if record["scenario_key"] == selected_item["structural_key"]
        and record["row_key"] is not None
        and canonical_json_bytes(record["row_key"], terminal_lf=False)
        in selected_row_key_set
    ], key=lambda item: canonical_json_bytes(item, terminal_lf=False))
    expected_output_to_source = {
        canonical_json_bytes(mapping["output_key"], terminal_lf=False):
            mapping["source_key"]
        for mapping in expected_structural_mappings
    }
    expected_sliced_runtime_pickles: list[dict[str, Any]] = []
    for record in _normalize_runtime_pickles(
            output_ast, output_path, "r2t-j0/examples.feature"):
        scenario_key = expected_output_to_source.get(canonical_json_bytes(
            record["scenario_key"], terminal_lf=False))
        row_key = (None if record["row_key"] is None else
                   expected_output_to_source.get(canonical_json_bytes(
                       record["row_key"], terminal_lf=False)))
        if scenario_key is None or row_key is None:
            raise J0Error(
                "examples_overlay.output_ast Pickle lacks exact source mapping")
        expected_sliced_runtime_pickles.append({
            "effective_tags": record["effective_tags"],
            "language": record["language"],
            "name": record["name"],
            "source_row_key": row_key,
            "source_scenario_key": scenario_key,
        })
    expected_sliced_runtime_pickles.sort(
        key=lambda item: canonical_json_bytes(item, terminal_lf=False))
    if source_runtime_pickles != expected_source_runtime_pickles \
            or sliced_runtime_pickles != expected_sliced_runtime_pickles:
        raise J0Error(
            "examples_overlay runtime Pickles differ from embedded exact-stack ASTs")
    _hex(obj["runtime_pickle_multiset_sha256"], 64,
         "examples_overlay.runtime_pickle_multiset_sha256")
    if obj["runtime_pickle_multiset_sha256"] != _sha256(
            canonical_json_bytes(source_runtime_pickles)):
        raise J0Error("examples_overlay.runtime_pickle_multiset_sha256: mismatch")

    if not isinstance(obj["rejected_row_lines"], list):
        raise J0Error("examples_overlay.rejected_row_lines: expected array")
    rejected = [
        _integer(value, f"examples_overlay.rejected_row_lines[{index}]", minimum=1)
        for index, value in enumerate(obj["rejected_row_lines"])
    ]
    if rejected != sorted(rejected) or len(rejected) != len(set(rejected)):
        raise J0Error("examples_overlay.rejected_row_lines: not unique sorted")

    if not isinstance(obj["row_mappings"], list) or len(obj["row_mappings"]) < 2:
        raise J0Error("examples_overlay.row_mappings: expected at least two rows")
    source_lines: list[int] = []
    output_lines: list[int] = []
    for index, value in enumerate(obj["row_mappings"]):
        where = f"examples_overlay.row_mappings[{index}]"
        mapping = _closed(value, {
            "effective_tags", "output_examples_key", "output_line", "output_span",
            "output_structural_key", "source_examples_key", "source_line",
            "source_span", "source_structural_key",
        }, where)
        _validate_tags_array(mapping["effective_tags"], f"{where}.effective_tags")
        source_line = _integer(mapping["source_line"], f"{where}.source_line", minimum=1)
        output_row_line = _integer(mapping["output_line"],
                                   f"{where}.output_line", minimum=1)
        source_lines.append(source_line)
        output_lines.append(output_row_line)
        if _validate_span(mapping["source_span"], f"{where}.source_span") \
                != [source_line, source_line]:
            raise J0Error(f"{where}.source_span: row span mismatch")
        if _validate_span(mapping["output_span"], f"{where}.output_span") \
                != [output_row_line, output_row_line]:
            raise J0Error(f"{where}.output_span: row span mismatch")
        source_examples = _validate_structural_key(
            mapping["source_examples_key"], f"{where}.source_examples_key",
            source_uri=source_uri)
        source_key = _validate_structural_key(
            mapping["source_structural_key"], f"{where}.source_structural_key",
            source_uri=source_uri)
        output_examples = _validate_structural_key(
            mapping["output_examples_key"], f"{where}.output_examples_key",
            source_uri=output_path)
        output_key = _validate_structural_key(
            mapping["output_structural_key"], f"{where}.output_structural_key",
            source_uri=output_path)
        if source_examples[1] != "Examples" or source_key[1] != "ExamplesRow" \
                or source_key[4] != source_examples or source_key[2] != source_line:
            raise J0Error(f"{where}: source structural mismatch")
        if output_examples[1] != "Examples" or output_examples[4] != output_scenario \
                or output_key[1] != "ExamplesRow" or output_key[4] != output_examples \
                or output_key[2] != output_row_line:
            raise J0Error(f"{where}: output structural mismatch")
        if canonical_json_bytes(source_examples, terminal_lf=False) not in source_key_set \
                or canonical_json_bytes(source_key, terminal_lf=False) not in source_key_set:
            raise J0Error(f"{where}: source keys absent from preserved key set")
        if canonical_json_bytes(output_examples, terminal_lf=False) not in output_key_set \
                or canonical_json_bytes(output_key, terminal_lf=False) not in output_key_set:
            raise J0Error(f"{where}: output keys absent from preserved key set")
    if source_lines != sorted(source_lines) or len(source_lines) != len(set(source_lines)):
        raise J0Error("examples_overlay.row_mappings: source order mismatch")
    if output_lines != sorted(output_lines) or len(output_lines) != len(set(output_lines)):
        raise J0Error("examples_overlay.row_mappings: output order mismatch")

    if selection is not None:
        validate_examples_selection(selection, census)
        if obj["selection_manifest_sha256"] != _sha256(
                canonical_json_bytes(dict(selection))) \
                or project != selection["project"]:
            raise J0Error("examples_overlay: selection identity mismatch")
        selected = selection["selected_item"]
        if input_feature["source_uri"] != selected["source_uri"] \
                or input_feature["runtime_uri"] != selected["runtime_uri"]:
            raise J0Error("examples_overlay.input_feature: selection mismatch")
        if not (source_span[0] <= selected["line"] <= source_span[1]):
            raise J0Error("examples_overlay.source_scenario_span: misses outline line")
        if rejected != selection["rejected_row_lines"]:
            raise J0Error("examples_overlay.rejected_row_lines: selection mismatch")
        if len(obj["row_mappings"]) != selection["selected_row_count"]:
            raise J0Error("examples_overlay.row_mappings: selection count mismatch")
        for mapping, row in zip(obj["row_mappings"], selection["rows"]):
            if mapping["source_line"] != row["line"] \
                    or mapping["source_structural_key"] != row["structural_key"] \
                    or mapping["source_examples_key"] != row["examples_key"] \
                    or mapping["effective_tags"] != row["effective_tags"]:
                raise J0Error("examples_overlay.row_mappings: source selection drift")
        selected_row_keys = sorted([
            canonical_json_bytes(row["structural_key"], terminal_lf=False)
            for row in selection["rows"]
        ])
        runtime_row_keys = sorted([
            canonical_json_bytes(record["source_row_key"], terminal_lf=False)
            for record in source_runtime_pickles
        ])
        if runtime_row_keys != selected_row_keys \
                or any(record["source_scenario_key"] != selected["structural_key"]
                       for record in source_runtime_pickles):
            raise J0Error(
                "examples_overlay runtime Pickles do not equal selected structural cases")
        if canonical_json_bytes(selected["structural_key"], terminal_lf=False) \
                not in set(encoded_keys):
            raise J0Error("examples_overlay.preserved_source_keys: missing outline key")
    if census is not None:
        validate_census(census)
        if census["project"] != project:
            raise J0Error("examples_overlay: census project mismatch")
        feature = next((entry for entry in census["features"]
                        if entry["source_uri"] == source_uri), None)
        if feature is None or feature["raw_file_sha256"] != input_feature["raw_file_sha256"]:
            raise J0Error("examples_overlay.input_feature: census mismatch")

    if output_tree is not None:
        root = Path(output_tree)
        physical = _walk_checkout(root)
        if set(physical) != {output_path} or (root / ".git").exists():
            raise J0Error("examples_overlay tree has foreign/missing paths")
        raw, output_stat = _read_relative_regular_nofollow(root, output_path)
        if stat.S_IMODE(output_stat.st_mode) != 0o644:
            raise J0Error("examples_overlay output mode is not 0644")
        if len(raw.splitlines()) != len(obj["source_output_line_map"]):
            raise J0Error("examples_overlay source/output line-map length mismatch")
        if raw != expected_output_raw:
            raise J0Error("examples_overlay output bytes differ from exact source slice")
        if _sha256(raw) != obj["output_raw_file_sha256"]:
            raise J0Error("examples_overlay output raw digest mismatch")
        if framed_tree_sha256([(output_path, raw)]) != obj["overlay_tree_sha256"]:
            raise J0Error("examples_overlay framed tree digest mismatch")
    return obj


def _output_artifacts(root: Path, *, exclude: set[str] | None = None) \
        -> list[dict[str, Any]]:
    exclude = exclude or set()
    physical = _walk_checkout(root)
    if (root / ".git").exists() or (root / ".git").is_symlink():
        raise J0Error("Phase-A output may not contain .git")
    artifacts: list[dict[str, Any]] = []
    for path in sorted(physical, key=lambda item: item.encode("utf-8")):
        if path in exclude:
            continue
        raw, target_stat = _read_relative_regular_nofollow(root, path)
        mode = stat.S_IMODE(target_stat.st_mode)
        if mode != 0o644:
            raise J0Error(f"Phase-A artifact mode is not 0644: {path}")
        artifacts.append({
            "bytes": len(raw),
            "path": path,
            "raw_file_sha256": _sha256(raw),
        })
    return artifacts


def _phase_tree_digest(root: Path, artifacts: Sequence[Mapping[str, Any]]) -> str:
    inputs: list[tuple[str, bytes]] = []
    for entry in artifacts:
        raw, _ = _read_relative_regular_nofollow(root, entry["path"])
        inputs.append((entry["path"], raw))
    return framed_tree_sha256(inputs)


def _artifact_digest(root: Path, rel: str) -> str:
    return _raw_sha256(_require_no_symlink_components(root, rel))


def generate_phase_a(
    *,
    output: os.PathLike[str] | str,
    epubcheck_root: os.PathLike[str] | str,
    algorand_sdk_root: os.PathLike[str] | str,
    algorand_testing_root: os.PathLike[str] | str,
    items_path: os.PathLike[str] | str,
    epubcheck_parser_artifacts: Sequence[os.PathLike[str] | str],
    algorand_parser_artifacts: Sequence[os.PathLike[str] | str],
) -> dict[str, Any]:
    """Authenticate mutable inputs, snapshot them privately, then generate."""
    original_roots = {
        "epubcheck": Path(epubcheck_root),
        "algorand-sdk": Path(algorand_sdk_root),
        "algorand-sdk-testing": Path(algorand_testing_root),
    }
    source_manifests = {
        project: build_source_archive_manifest(project, root)
        for project, root in original_roots.items()
    }
    items_raw, _ = _read_absolute_regular_nofollow(items_path)
    if _sha256(items_raw) != ITEMS_SHA256:
        raise J0Error("wrong frozen items identity before source snapshot")
    with tempfile.TemporaryDirectory(prefix="r2t-j0-authenticated-inputs-") as temporary:
        private_root = Path(temporary)
        snapshot_roots: dict[str, Path] = {}
        for project, original in original_roots.items():
            snapshot = private_root / "sources" / project
            _snapshot_source_checkout(
                original, source_manifests[project], snapshot)
            validate_source_checkout(project, original, source_manifests[project])
            snapshot_roots[project] = snapshot
        items_snapshot = private_root / "inputs" / "items.jsonl"
        _write_new_file(items_snapshot, items_raw)
        result = _generate_phase_a_from_snapshots(
            output=output,
            roots=snapshot_roots,
            source_manifests=source_manifests,
            items_path=items_snapshot,
            epubcheck_parser_artifacts=epubcheck_parser_artifacts,
            algorand_parser_artifacts=algorand_parser_artifacts,
        )
        for project, original in original_roots.items():
            _validate_manifest_tree(snapshot_roots[project], source_manifests[project])
            validate_source_checkout(project, original, source_manifests[project])
        final_items, _ = _read_absolute_regular_nofollow(items_path)
        if final_items != items_raw:
            raise J0Error("frozen items changed during Phase-A generation")
        validate_phase_a_output(output)
        return result


def _generate_phase_a_from_snapshots(
    *,
    output: os.PathLike[str] | str,
    roots: Mapping[str, Path],
    source_manifests: Mapping[str, Mapping[str, Any]],
    items_path: os.PathLike[str] | str,
    epubcheck_parser_artifacts: Sequence[os.PathLike[str] | str],
    algorand_parser_artifacts: Sequence[os.PathLike[str] | str],
) -> dict[str, Any]:
    """Generate only from already authenticated, private source snapshots."""
    output = Path(output)
    _require_new_empty_directory(output)
    for project, manifest in source_manifests.items():
        _validate_manifest_tree(roots[project], manifest)
        write_canonical_json_new(
            output / "sources" / f"{project}.json", manifest)

    composition_manifests: list[dict[str, Any]] = []
    for label in ("a", "b"):
        base = output / f"algorand-composition-{label}"
        _mkdir_parents(base.parent)
        _mkdir_normalized(base)
        workspace = base / "workspace"
        manifest = compose_algorand_offline(
            roots["algorand-sdk"], roots["algorand-sdk-testing"],
            source_manifests["algorand-sdk"],
            source_manifests["algorand-sdk-testing"], workspace,
        )
        validate_composed_tree(
            workspace, manifest,
            source_manifests["algorand-sdk"],
            source_manifests["algorand-sdk-testing"],
        )
        write_canonical_json_new(base / "manifest.json", manifest)
        composition_manifests.append(manifest)
    if canonical_json_bytes(composition_manifests[0]) \
            != canonical_json_bytes(composition_manifests[1]):
        raise J0Error("Algorand second composition did not reproduce manifest bytes")
    if _output_artifacts(output / "algorand-composition-a" / "workspace") \
            != _output_artifacts(output / "algorand-composition-b" / "workspace"):
        raise J0Error("Algorand second composition did not reproduce workspace bytes")

    frozen_items, items_digest = load_frozen_java_items(items_path)
    censuses: dict[str, dict[str, Any]] = {}
    scalars: dict[str, dict[str, Any]] = {}
    examples: dict[str, dict[str, Any]] = {}
    overlays: dict[str, list[dict[str, Any]]] = {}
    artifact_args = {
        "epubcheck": epubcheck_parser_artifacts,
        "algorand-sdk": algorand_parser_artifacts,
    }
    source_args = {
        "epubcheck": (roots["epubcheck"], source_manifests["epubcheck"]),
        "algorand-sdk": (
            roots["algorand-sdk-testing"],
            source_manifests["algorand-sdk-testing"],
        ),
    }
    with GherkinParserBridge() as bridge:
        for project in ("epubcheck", "algorand-sdk"):
            source_root, source_manifest = source_args[project]
            census = build_census(
                project, source_root, source_manifest, frozen_items[project],
                items_digest, bridge, artifact_args[project],
                composition_manifest=(composition_manifests[0]
                                      if project == "algorand-sdk" else None),
                sdk_root=(roots["algorand-sdk"]
                          if project == "algorand-sdk" else None),
                sdk_source_manifest=(source_manifests["algorand-sdk"]
                                     if project == "algorand-sdk" else None),
            )
            scalar = build_scalar_selection(census)
            examples_selection = build_examples_selection(census)
            validate_scalar_selection(scalar, census)
            validate_examples_selection(examples_selection, census)
            project_root = output / "projects" / project
            write_canonical_json_new(project_root / "census.json", census)
            write_canonical_json_new(project_root / "scalar-selection.json", scalar)
            write_canonical_json_new(
                project_root / "examples-selection.json", examples_selection)
            overlay_manifests: list[dict[str, Any]] = []
            for label in ("a", "b"):
                overlay_root = project_root / f"examples-overlay-{label}"
                _mkdir_parents(overlay_root.parent)
                _mkdir_normalized(overlay_root)
                tree_root = overlay_root / "tree"
                overlay = build_examples_overlay(
                    census, examples_selection, source_root, bridge,
                    artifact_args[project], tree_root,
                )
                validate_examples_overlay(
                    overlay, examples_selection, census, tree_root)
                write_canonical_json_new(overlay_root / "manifest.json", overlay)
                overlay_manifests.append(overlay)
            if canonical_json_bytes(overlay_manifests[0]) \
                    != canonical_json_bytes(overlay_manifests[1]):
                raise J0Error(f"{project}: second slice did not reproduce manifest bytes")
            if _output_artifacts(project_root / "examples-overlay-a" / "tree") \
                    != _output_artifacts(project_root / "examples-overlay-b" / "tree"):
                raise J0Error(f"{project}: second slice did not reproduce feature bytes")
            censuses[project] = census
            scalars[project] = scalar
            examples[project] = examples_selection
            overlays[project] = overlay_manifests

        bridge.revalidate_inputs()

    artifacts = _output_artifacts(output, exclude={"phase-a.json"})
    index = {
        "artifact_count": len(artifacts),
        "artifact_total_bytes": sum(entry["bytes"] for entry in artifacts),
        "artifact_tree_digest_domain": TREE_DOMAIN,
        "artifact_tree_sha256": _phase_tree_digest(output, artifacts),
        "artifacts": artifacts,
        "items_file_sha256": items_digest,
        "producer_source_sha256": _raw_sha256(Path(__file__)),
        "protocol_raw_file_sha256": _raw_sha256(_protocol_path()),
        "projects": {
            project: {
                "census_manifest_sha256": _artifact_digest(
                    output, f"projects/{project}/census.json"),
                "examples_overlay_manifest_sha256": _artifact_digest(
                    output, f"projects/{project}/examples-overlay-a/manifest.json"),
                "examples_overlay_tree_sha256": overlays[project][0][
                    "overlay_tree_sha256"],
                "examples_selection_manifest_sha256": _artifact_digest(
                    output, f"projects/{project}/examples-selection.json"),
                "scalar_selection_manifest_sha256": _artifact_digest(
                    output, f"projects/{project}/scalar-selection.json"),
            }
            for project in ("algorand-sdk", "epubcheck")
        },
        "reproducible_algorand_composition_manifest_sha256": _artifact_digest(
            output, "algorand-composition-a/manifest.json"),
        "schema": PHASE_A_SCHEMA,
        "source_archive_manifest_sha256": {
            project: _artifact_digest(output, f"sources/{project}.json")
            for project in (
                "algorand-sdk", "algorand-sdk-testing", "epubcheck")
        },
    }
    validate_phase_a_index(index, output)
    write_canonical_json_new(output / "phase-a.json", index)
    validate_phase_a_output(output)
    return index


def validate_phase_a_index(
    index: Any,
    output: os.PathLike[str] | str | None = None,
) -> dict[str, Any]:
    obj = _closed(index, {
        "artifact_count", "artifact_total_bytes", "artifact_tree_digest_domain",
        "artifact_tree_sha256", "artifacts", "items_file_sha256", "producer_source_sha256",
        "projects", "protocol_raw_file_sha256",
        "reproducible_algorand_composition_manifest_sha256", "schema",
        "source_archive_manifest_sha256",
    }, "phase_a")
    if obj["schema"] != PHASE_A_SCHEMA:
        raise J0Error("phase_a.schema: wrong schema")
    if obj["artifact_tree_digest_domain"] != TREE_DOMAIN:
        raise J0Error("phase_a.artifact_tree_digest_domain: mismatch")
    _hex(obj["artifact_tree_sha256"], 64, "phase_a.artifact_tree_sha256")
    _hex(obj["items_file_sha256"], 64, "phase_a.items_file_sha256")
    if obj["items_file_sha256"] != ITEMS_SHA256:
        raise J0Error("phase_a.items_file_sha256: wrong frozen input")
    _hex(obj["producer_source_sha256"], 64, "phase_a.producer_source_sha256")
    if obj["producer_source_sha256"] != _raw_sha256(Path(__file__)):
        raise J0Error("phase_a.producer_source_sha256: implementation drift")
    _hex(obj["protocol_raw_file_sha256"], 64,
         "phase_a.protocol_raw_file_sha256")
    if obj["protocol_raw_file_sha256"] != _raw_sha256(_protocol_path()):
        raise J0Error("phase_a.protocol_raw_file_sha256: methodology drift")
    _hex(obj["reproducible_algorand_composition_manifest_sha256"], 64,
         "phase_a.reproducible_algorand_composition_manifest_sha256")
    if not isinstance(obj["artifacts"], list):
        raise J0Error("phase_a.artifacts: expected array")
    paths: list[str] = []
    total = 0
    for position, value in enumerate(obj["artifacts"]):
        entry = _closed(value, {"bytes", "path", "raw_file_sha256"},
                        f"phase_a.artifacts[{position}]")
        path = validate_posix_path(entry["path"],
                                   where=f"phase_a.artifacts[{position}].path")
        if path == "phase-a.json":
            raise J0Error("phase_a.artifacts: self-index is forbidden")
        paths.append(path)
        total += _integer(entry["bytes"], f"phase_a.artifacts[{position}].bytes")
        _hex(entry["raw_file_sha256"], 64,
             f"phase_a.artifacts[{position}].raw_file_sha256")
    validate_path_set(paths, where="phase_a.artifacts.paths")
    if obj["artifact_count"] != len(obj["artifacts"]):
        raise J0Error("phase_a.artifact_count: mismatch")
    if obj["artifact_total_bytes"] != total:
        raise J0Error("phase_a.artifact_total_bytes: mismatch")
    _integer(obj["artifact_count"], "phase_a.artifact_count")
    _integer(obj["artifact_total_bytes"], "phase_a.artifact_total_bytes")
    sources = _closed(obj["source_archive_manifest_sha256"], {
        "algorand-sdk", "algorand-sdk-testing", "epubcheck",
    }, "phase_a.source_archive_manifest_sha256")
    for project, digest in sources.items():
        _hex(digest, 64, f"phase_a.source_archive_manifest_sha256.{project}")
        if digest != PINNED_SOURCE_ARCHIVE_FACTS[project]["manifest_sha256"]:
            raise J0Error(
                f"phase_a.source_archive_manifest_sha256.{project}: pinned mismatch")
    projects = _closed(obj["projects"], {"algorand-sdk", "epubcheck"},
                       "phase_a.projects")
    project_keys = {
        "census_manifest_sha256", "examples_overlay_manifest_sha256",
        "examples_overlay_tree_sha256", "examples_selection_manifest_sha256",
        "scalar_selection_manifest_sha256",
    }
    for project, value in projects.items():
        entry = _closed(value, project_keys, f"phase_a.projects.{project}")
        for key, digest in entry.items():
            _hex(digest, 64, f"phase_a.projects.{project}.{key}")
    if output is not None:
        root = Path(output)
        actual = _output_artifacts(root, exclude={"phase-a.json"})
        if actual != obj["artifacts"]:
            raise J0Error("phase_a.artifacts: output path/byte set mismatch")
        if _phase_tree_digest(root, actual) != obj["artifact_tree_sha256"]:
            raise J0Error("phase_a.artifact_tree_sha256: output mismatch")
        expected_files = {entry["path"]: entry["raw_file_sha256"] for entry in actual}
        bindings = {
            "algorand-composition-a/manifest.json":
                obj["reproducible_algorand_composition_manifest_sha256"],
            **{
                f"sources/{project}.json": digest
                for project, digest in sources.items()
            },
        }
        for project, entry in projects.items():
            bindings.update({
                f"projects/{project}/census.json": entry["census_manifest_sha256"],
                f"projects/{project}/examples-overlay-a/manifest.json":
                    entry["examples_overlay_manifest_sha256"],
                f"projects/{project}/examples-selection.json":
                    entry["examples_selection_manifest_sha256"],
                f"projects/{project}/scalar-selection.json":
                    entry["scalar_selection_manifest_sha256"],
            })
        for path, digest in bindings.items():
            if expected_files.get(path) != digest:
                raise J0Error(f"phase_a binding mismatch: {path}")
    return obj


def validate_phase_a_output(output: os.PathLike[str] | str) -> dict[str, Any]:
    root = Path(output)
    index = load_canonical_json(root / "phase-a.json")
    validate_phase_a_index(index, root)
    source_manifests = {
        project: load_canonical_json(root / "sources" / f"{project}.json")
        for project in ("algorand-sdk", "algorand-sdk-testing", "epubcheck")
    }
    for manifest in source_manifests.values():
        validate_source_archive_manifest(manifest)
    compositions = [
        load_canonical_json(root / f"algorand-composition-{label}" / "manifest.json")
        for label in ("a", "b")
    ]
    for label, manifest in zip(("a", "b"), compositions):
        validate_composition_manifest(
            manifest,
            source_manifests["algorand-sdk"],
            source_manifests["algorand-sdk-testing"],
        )
        validate_composed_tree(
            root / f"algorand-composition-{label}" / "workspace", manifest,
            source_manifests["algorand-sdk"],
            source_manifests["algorand-sdk-testing"],
        )
    if canonical_json_bytes(compositions[0]) != canonical_json_bytes(compositions[1]):
        raise J0Error("Phase-A Algorand composition reproductions differ")
    source_manifest_digests = {
        project: _sha256(canonical_json_bytes(manifest))
        for project, manifest in source_manifests.items()
    }
    expected_composition_sources = {
        entry["project"]: entry["source_archive_manifest_sha256"]
        for entry in compositions[0]["sources"]
    }
    for project in ("algorand-sdk", "algorand-sdk-testing"):
        if expected_composition_sources.get(project) != source_manifest_digests[project]:
            raise J0Error(
                f"Phase-A composition/source archive binding mismatch: {project}")
    for project in ("algorand-sdk", "epubcheck"):
        base = root / "projects" / project
        census = load_canonical_json(base / "census.json")
        scalar = load_canonical_json(base / "scalar-selection.json")
        examples = load_canonical_json(base / "examples-selection.json")
        validate_census(census)
        expected_source_project = (
            "algorand-sdk-testing" if project == "algorand-sdk" else "epubcheck")
        if census["source_archive_manifest_sha256"] \
                != source_manifest_digests[expected_source_project]:
            raise J0Error(f"Phase-A {project} census/source binding mismatch")
        expected_composition = (_sha256(canonical_json_bytes(compositions[0]))
                                if project == "algorand-sdk" else None)
        if census["composition_manifest_sha256"] != expected_composition:
            raise J0Error(f"Phase-A {project} census/composition binding mismatch")
        source_files = {
            entry["path"]: entry
            for entry in source_manifests[expected_source_project]["files"]
        }
        for feature in census["features"]:
            source_entry = source_files.get(feature["source_uri"])
            if source_entry is None \
                    or source_entry["raw_file_sha256"] != feature["raw_file_sha256"]:
                raise J0Error(f"Phase-A {project} census feature/source mismatch")
        census_runtime = {
            entry["source_uri"]: entry["runtime_uri"]
            for entry in census["source_runtime_map"]
        }
        if project == "algorand-sdk":
            expected_runtime = _composition_runtime_map(
                compositions[0], source_manifests["algorand-sdk"],
                source_manifests["algorand-sdk-testing"])
            expected_runtime = {
                source: runtime for source, runtime in expected_runtime.items()
                if source.startswith(("features/unit/", "features/integration/"))
            }
        else:
            expected_runtime = {
                feature["source_uri"]:
                    feature["source_uri"][len("src/test/resources/"):]
                for feature in census["features"]
            }
        if census_runtime != expected_runtime:
            raise J0Error(f"Phase-A {project} source/runtime map mismatch")
        validate_scalar_selection(scalar, census)
        validate_examples_selection(examples, census)
        overlay_documents: list[dict[str, Any]] = []
        for label in ("a", "b"):
            overlay = load_canonical_json(
                base / f"examples-overlay-{label}" / "manifest.json")
            validate_examples_overlay(
                overlay, examples, census,
                base / f"examples-overlay-{label}" / "tree")
            overlay_documents.append(overlay)
        if canonical_json_bytes(overlay_documents[0]) \
                != canonical_json_bytes(overlay_documents[1]):
            raise J0Error(f"Phase-A {project} slice reproductions differ")
    for dirpath, dirnames, filenames in os.walk(root):
        del dirnames, filenames
        if stat.S_IMODE(os.lstat(dirpath).st_mode) != 0o755:
            raise J0Error(f"Phase-A output directory mode is not 0755: {dirpath}")
    return index


def check_phase_a_reproduction(**kwargs: Any) -> dict[str, Any]:
    """Regenerate into a fresh temporary root and byte-compare everything."""
    existing = Path(kwargs["output"])
    validate_phase_a_output(existing)
    with tempfile.TemporaryDirectory(prefix="r2t-j0-phase-a-check-") as temporary:
        replay = Path(temporary) / "replay"
        replay_kwargs = dict(kwargs)
        replay_kwargs["output"] = replay
        generate_phase_a(**replay_kwargs)
        left = _output_artifacts(existing)
        right = _output_artifacts(replay)
        if left != right:
            left_map = {entry["path"]: entry for entry in left}
            right_map = {entry["path"]: entry for entry in right}
            changed = sorted(
                path for path in set(left_map).union(right_map)
                if left_map.get(path) != right_map.get(path)
            )
            raise J0Error(
                f"Phase-A --check reproduction differs at {changed[:12]!r}")
    return validate_phase_a_output(existing)


def _default_items_path() -> str:
    return str(Path(__file__).resolve().parents[2] / "items.jsonl")


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate or reproduce-check source-only J0 Phase-A artifacts")
    parser.add_argument("--output", required=True,
                        help="new empty output directory (existing artifacts for --check)")
    parser.add_argument("--epubcheck-root", required=True)
    parser.add_argument("--algorand-sdk-root", required=True)
    parser.add_argument("--algorand-testing-root", required=True)
    parser.add_argument("--items", default=_default_items_path())
    parser.add_argument(
        "--epubcheck-parser-artifact", action="append", required=True,
        help=("repeat in exact order: gherkin-24.0.0.jar, messages-19.1.2.jar, "
              "tag-expressions-4.1.0.jar"))
    parser.add_argument(
        "--algorand-parser-artifact", action="append", required=True,
        help=("repeat in exact order: cucumber-gherkin-messages-6.6.0.jar, "
              "messages-13.0.1.jar, tag-expressions-3.0.0.jar"))
    parser.add_argument(
        "--check", action="store_true",
        help="validate existing output and regenerate into a fresh root byte-for-byte")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    kwargs = {
        "output": args.output,
        "epubcheck_root": args.epubcheck_root,
        "algorand_sdk_root": args.algorand_sdk_root,
        "algorand_testing_root": args.algorand_testing_root,
        "items_path": args.items,
        "epubcheck_parser_artifacts": args.epubcheck_parser_artifact,
        "algorand_parser_artifacts": args.algorand_parser_artifact,
    }
    try:
        index = (check_phase_a_reproduction(**kwargs) if args.check
                 else generate_phase_a(**kwargs))
    except J0Error as exc:
        print(f"J0 Phase A REFUSED: {exc}", file=sys.stderr)
        return 2
    action = "REPRODUCED" if args.check else "GENERATED"
    print(
        f"J0 Phase A {action}: artifacts={index['artifact_count']} "
        f"tree={index['artifact_tree_sha256']}")
    return 0


def selftest() -> int:
    """Network-free adversarial checks for every Phase-A source boundary."""
    import copy

    ok = True

    def check(name: str, condition: Any, detail: str = "") -> None:
        nonlocal ok
        passed = bool(condition)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not passed else ""))
        ok = ok and passed

    def refused(callable_: Any) -> bool:
        try:
            callable_()
        except J0Error:
            return True
        return False

    def refusal_mentions(callable_: Any, phrase: str) -> bool:
        try:
            callable_()
        except J0Error as exc:
            return phrase in str(exc)
        return False

    # Canonical JSON and path domains.
    unicode_doc = {"z": 1, "é": [True, None, "雪"]}
    encoded = canonical_json_bytes(unicode_doc)
    check("canonical JSON is UTF-8, compact, sorted, and LF terminated",
          encoded.endswith(b"\n") and b"\\u" not in encoded
          and load_canonical_json_bytes(encoded) == unicode_doc, repr(encoded))
    check("floats are forbidden recursively",
          refused(lambda: canonical_json_bytes({"x": [1.0]})))
    check("duplicate JSON keys are refused",
          refused(lambda: load_canonical_json_bytes(b'{"a":1,"a":2}\n')))
    check("noncanonical JSON bytes are refused",
          refused(lambda: load_canonical_json_bytes(b'{"a": 1}\n')))
    check("non-finite JSON is refused",
          refused(lambda: load_canonical_json_bytes(b'{"a":NaN}\n')))
    check("missing terminal LF is refused",
          refused(lambda: load_canonical_json_bytes(b'{"a":1}')))
    bad_paths = ["/absolute", "a//b", "a/./b", "a/../b", "a\\b", "a\x00b"]
    check("unsafe POSIX paths are refused",
          all(refused(lambda path=path: validate_posix_path(path))
              for path in bad_paths))
    check("NFC-equivalent path aliases are refused",
          refused(lambda: validate_path_set(["e\u0301", "é"])))
    frame_a = framed_tree_sha256([("b", b"2"), ("a", b"1")])
    frame_b = framed_tree_sha256([("a", b"1"), ("b", b"2")])
    check("r2t-j0-tree/1 order is UTF-8 canonical", frame_a == frame_b)
    check("tree framing separates path and content domains",
          frame_a != framed_tree_sha256([("a", b"1"), ("b", b"22")]))
    with tempfile.TemporaryDirectory(prefix="r2t-j0-empty-dir-test-") as temporary:
        root = Path(temporary)
        _write_new_file(root / "kept.txt", b"kept\n")
        (root / "foreign-empty").mkdir()
        check("Phase-A and overlay inventories refuse foreign empty directories",
              refused(lambda: _output_artifacts(root)))

    # Exact tag-file grammar and generated expression semantics.
    tags, expression = _parse_unit_tags_bytes(b"@unit.z\n\n@unit.a\n")
    check("unit.tags are sorted and form the exact OR expression",
          tags == ["@unit.a", "@unit.z"]
          and expression == "(@unit.a) or (@unit.z)")
    check("unit.tags duplicate is refused",
          refused(lambda: _parse_unit_tags_bytes(b"@a\n@a\n")))
    check("unit.tags CRLF is refused",
          refused(lambda: _parse_unit_tags_bytes(b"@a\r\n")))
    check("unit.tags arbitrary expression is refused",
          refused(lambda: _parse_unit_tags_bytes(b"@a or @b\n")))
    tag_qualification = {
        "cases": [
            {"expected": False, "tags": []},
            {"expected": False, "tags": ["@r2t.phase_a.foreign"]},
            {"expected": True, "tags": ["@a"]},
            {"expected": True, "tags": ["@z"]},
            {"expected": True, "tags": ["@a", "@z"]},
        ],
        "evaluator": "cucumber-generated-or-membership/r2t-1",
        "expression": "(@a) or (@z)",
        "schema": "r2t.java-j0-tag-expression-qualification/1",
    }
    validate_tag_expression_qualification(tag_qualification)
    tampered_qualification = copy.deepcopy(tag_qualification)
    tampered_qualification["cases"][1]["expected"] = True
    check("tag-expression qualification has an exact closed witness set",
          refused(lambda: validate_tag_expression_qualification(
              tampered_qualification)))

    alg_totals = {
        "admitted_examples_rows": 471, "admitted_items": 125,
        "admitted_outline_items": 121, "admitted_pickles": 475,
        "admitted_plain_items": 4, "integration_items": 51,
        "raw_examples_rows": 527, "raw_items": 132,
        "raw_outline_items": 125, "raw_plain_items": 7,
    }
    excluded_pairs = [
        ("features/unit/atomic_transaction_composer.feature", 181),
        ("features/unit/client-no-headers.feature", 10),
        ("features/unit/client-no-headers.feature", 22),
        ("features/unit/sourcemap.feature", 38),
        ("features/unit/sourcemap.feature", 43),
        ("features/unit/sourcemap.feature", 65),
        ("features/unit/v2algodclient_paths.feature", 128),
    ]
    semantic_items: list[dict[str, Any]] = [
        {"admitted": False, "line": line, "source_uri": source}
        for source, line in excluded_pairs
    ]
    for line, form, rows in (
        (4, "plain", []), (10, "outline", [17]),
        (19, "outline", [26]), (28, "outline", [37]),
        (39, "outline", [45]), (47, "outline", [57]),
        (59, "outline", [67]), (69, "outline", [76]),
        (78, "outline", [84, 85, 86, 87, 88, 89]),
    ):
        semantic_items.append({
            "admitted": True, "effective_tags": ["@unit", "@unit.offline"],
            "form": form, "line": line,
            "rows": [{"line": row_line} for row_line in rows],
            "runtime_uri": "com/algorand/algosdk/integration/offline.feature",
            "source_uri": "features/unit/offline.feature",
        })
    rejected_response_rows = {
        146, 185, 233, 234, 235, 240, 245, 246, 247, 248, 249,
    }
    semantic_items.append({
        "admitted": True, "line": 4,
        "rows": [{"admitted": line not in rejected_response_rows, "line": line}
                 for line in range(100, 267)],
        "source_uri": "features/unit/responses.feature",
    })
    semantic_stub: dict[str, Any] = {
        "features": [{} for _ in range(16)], "items": semantic_items,
        "project": "algorand-sdk",
        "source_archive_manifest_sha256":
            PINNED_SOURCE_ARCHIVE_FACTS["algorand-sdk-testing"]["manifest_sha256"],
        "source_runtime_map": [{} for _ in range(27)],
        "tag_expression": "invalid-only-after-earlier-semantic-gates",
        "tag_file_sha256": UNIT_TAGS_SHA256, "totals": alg_totals,
    }
    wrong_tag = copy.deepcopy(semantic_stub)
    wrong_tag["tag_file_sha256"] = "0" * 64
    check("pinned census validator refuses a forged unit.tags digest",
          refusal_mentions(lambda: _enforce_pinned_census_semantics(wrong_tag),
                           "unit.tags"))
    wrong_totals = copy.deepcopy(semantic_stub)
    wrong_totals["totals"]["raw_items"] = 131
    check("pinned census validator refuses recomputed 131-item arithmetic",
          refusal_mentions(lambda: _enforce_pinned_census_semantics(wrong_totals),
                           "totals"))
    missing_exclusion = copy.deepcopy(semantic_stub)
    missing_exclusion["items"] = [
        item for item in missing_exclusion["items"]
        if not (item["source_uri"] == "features/unit/sourcemap.feature"
                and item["line"] == 38)
    ]
    check("pinned census validator refuses removal of sourcemap.feature:38",
          refusal_mentions(
              lambda: _enforce_pinned_census_semantics(missing_exclusion),
              "exclusion"))
    wrong_offline = copy.deepcopy(semantic_stub)
    next(item for item in wrong_offline["items"]
         if item["source_uri"] == "features/unit/offline.feature")[
             "runtime_uri"] = "forged/offline.feature"
    check("pinned census validator refuses offline move/admission drift",
          refusal_mentions(lambda: _enforce_pinned_census_semantics(wrong_offline),
                           "offline.feature"))
    wrong_responses = copy.deepcopy(semantic_stub)
    response_stub = next(item for item in wrong_responses["items"]
                         if item["source_uri"] == "features/unit/responses.feature")
    next(row for row in response_stub["rows"] if row["line"] == 248)[
        "admitted"] = True
    check("pinned census validator refuses responses.feature row drift",
          refusal_mentions(
              lambda: _enforce_pinned_census_semantics(wrong_responses),
              "responses.feature"))

    def git_run(root: Path, *args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(root), *args], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"},
        )
        if proc.returncode:
            raise AssertionError(proc.stderr.decode("utf-8", errors="replace"))
        return proc.stdout.decode("ascii").strip()

    # A local Git fixture proves pin/tree/blob/mode enforcement without any
    # network or dependence on the external corpus checkouts.
    with tempfile.TemporaryDirectory(prefix="r2t-j0-git-test-") as temporary:
        repo = Path(temporary) / "repo"
        repo.mkdir()
        git_run(repo, "init", "-q")
        git_run(repo, "config", "user.email", "r2t@example.invalid")
        git_run(repo, "config", "user.name", "R2T Selftest")
        (repo / "a.txt").write_bytes(b"alpha\n")
        (repo / "bin.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
        os.chmod(repo / "a.txt", 0o644)
        os.chmod(repo / "bin.sh", 0o755)
        git_run(repo, "add", "a.txt", "bin.sh")
        git_run(repo, "commit", "-q", "-m", "fixture")
        commit = git_run(repo, "rev-parse", "HEAD")
        tree = git_run(repo, "rev-parse", "HEAD^{tree}")
        PINNED_REPOSITORIES["fixture"] = {
            "commit": commit, "git_tree": tree,
            "upstream": "https://example.invalid/fixture.git",
        }
        try:
            manifest = build_source_archive_manifest("fixture", repo)
            check("source archive binds every Git path/mode/blob/byte",
                  manifest["file_count"] == 2
                  and [entry["git_mode"] for entry in manifest["files"]]
                  == ["100644", "100755"])
            snapshot = Path(temporary) / "authenticated-snapshot"
            _snapshot_source_checkout(repo, manifest, snapshot)
            (repo / "a.txt").write_bytes(b"path-raced\n")
            snapshot_still_exact = True
            try:
                _validate_manifest_tree(snapshot, manifest)
            except J0Error:
                snapshot_still_exact = False
            check("private source snapshot is immutable from later pathname mutation",
                  snapshot_still_exact
                  and refused(lambda: validate_source_checkout("fixture", repo, manifest)))
            (repo / "a.txt").write_bytes(b"alpha\n")
            mutated = copy.deepcopy(manifest)
            mutated["unknown"] = 1
            check("source archive closed schema refuses unknown keys",
                  refused(lambda: validate_source_archive_manifest(mutated)))
            original_pin = PINNED_REPOSITORIES["fixture"]["commit"]
            PINNED_REPOSITORIES["fixture"]["commit"] = "0" * 40
            check("wrong source commit pin is refused",
                  refused(lambda: build_source_archive_manifest("fixture", repo)))
            PINNED_REPOSITORIES["fixture"]["commit"] = original_pin
            original_tree = PINNED_REPOSITORIES["fixture"]["git_tree"]
            PINNED_REPOSITORIES["fixture"]["git_tree"] = "0" * 40
            check("wrong source Git tree pin is refused",
                  refused(lambda: build_source_archive_manifest("fixture", repo)))
            PINNED_REPOSITORIES["fixture"]["git_tree"] = original_tree
            (repo / "a.txt").write_bytes(b"dirty\n")
            check("dirty tracked bytes are refused",
                  refused(lambda: build_source_archive_manifest("fixture", repo)))
            (repo / "a.txt").write_bytes(b"alpha\n")
            (repo / "untracked").write_bytes(b"foreign")
            check("untracked and ignored-like checkout bytes are refused",
                  refused(lambda: build_source_archive_manifest("fixture", repo)))
            (repo / "untracked").unlink()
            (repo / "unaccounted-empty").mkdir()
            check("source validation refuses a physical empty directory",
                  refused(lambda: build_source_archive_manifest("fixture", repo)))
            os.rmdir(repo / "unaccounted-empty")
            os.symlink("a.txt", repo / "link")
            check("source symlinks are refused",
                  refused(lambda: build_source_archive_manifest("fixture", repo)))
            (repo / "link").unlink()
            os.chmod(repo / "a.txt", 0o755)
            check("dirty executable mode is refused",
                  refused(lambda: build_source_archive_manifest("fixture", repo)))
            os.chmod(repo / "a.txt", 0o644)
            validate_source_checkout("fixture", repo, manifest)
            check("clean source checkout revalidates byte-for-byte", True)
            blob = next(entry["git_blob_sha1"] for entry in manifest["files"]
                        if entry["path"] == "a.txt")
            loose = repo / ".git" / "objects" / blob[:2] / blob[2:]
            if not loose.is_file():
                raise J0Error("selftest expected a loose Git blob")
            loose.unlink()
            check("missing promisor-style Git object refuses without lazy fetch",
                  refused(lambda: build_source_archive_manifest("fixture", repo)))
        finally:
            PINNED_REPOSITORIES.pop("fixture", None)

    with tempfile.TemporaryDirectory(prefix="r2t-j0-parser-pin-test-") as temporary:
        fake = Path(temporary) / "fake.jar"
        fake.write_bytes(b"not a pinned parser")
        check("unavailable/substituted parser artifacts are refused by raw SHA-256",
              refused(lambda: parser_identity("epubcheck", [fake, fake, fake])))
        authenticated, _ = _read_absolute_regular_nofollow(fake)
        private_copy = Path(temporary) / "private" / "00.jar"
        _write_new_file(private_copy, authenticated)
        fake.write_bytes(b"mutated after authentication")
        copied, _ = _read_absolute_regular_nofollow(private_copy)
        check("private JAR snapshot is detached from its mutable input pathname",
              copied == authenticated and copied != fake.read_bytes())

    git_env = _closed_process_environment(git=True)
    java_env = _closed_process_environment(java=True)
    check("Git subprocess environment disables lazy fetch, prompts and helpers",
          git_env.get("GIT_NO_LAZY_FETCH") == "1"
          and git_env.get("GIT_TERMINAL_PROMPT") == "0"
          and git_env.get("GIT_ASKPASS") == "/bin/false"
          and "GIT_CONFIG_COUNT" not in git_env)
    check("Java subprocess environment drops all option-injection variables",
          all(name not in java_env for name in (
              "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH")))

    def fixture_source_manifest(project: str, root: Path) -> dict[str, Any]:
        paths = sorted(
            [path.relative_to(root).as_posix() for path in root.rglob("*")
             if path.is_file() and not path.is_symlink()],
            key=lambda item: item.encode("utf-8"),
        )
        files: list[dict[str, Any]] = []
        framed: list[tuple[str, bytes]] = []
        for path in paths:
            raw = _safe_join(root, path).read_bytes()
            files.append({
                "bytes": len(raw), "git_blob_sha1": _git_blob_sha1(raw),
                "git_mode": "100644", "path": path,
                "raw_file_sha256": _sha256(raw),
            })
            framed.append((path, raw))
        result = {
            "archive_tree_digest_domain": TREE_DOMAIN,
            "archive_tree_sha256": framed_tree_sha256(framed),
            "commit": PINNED_REPOSITORIES[project]["commit"],
            "file_count": len(files), "files": files,
            "git_object_format": "sha1",
            "git_tree": PINNED_REPOSITORIES[project]["git_tree"],
            "project": project, "schema": SOURCE_SCHEMA,
            "total_bytes": sum(entry["bytes"] for entry in files),
            "upstream": PINNED_REPOSITORIES[project]["upstream"],
        }
        validate_source_archive_manifest(result)
        return result

    # The tiny composer fixture deliberately uses the two production project
    # labels while carrying only a handful of files.  Temporarily remove the
    # full-corpus archive facts; production validation never takes this path.
    saved_archive_facts = {
        project: PINNED_SOURCE_ARCHIVE_FACTS.pop(project)
        for project in ("algorand-sdk", "algorand-sdk-testing")
    }
    with tempfile.TemporaryDirectory(prefix="r2t-j0-compose-test-") as temporary:
        base = Path(temporary)
        sdk = base / "sdk"
        testing = base / "testing"
        sdk.mkdir()
        testing.mkdir()

        def put(root: Path, rel: str, raw: bytes) -> None:
            target = _safe_join(root, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)

        put(sdk, "pom.xml", b"<project/>\n")
        put(sdk, "src/test/resources/com/algorand/algosdk/unit/stale.feature",
            b"Feature: stale\n")
        put(sdk, "src/test/resources/shared.txt", b"same\n")
        put(testing, "features/unit/a.feature", b"Feature: unit\n")
        put(testing, "features/unit/offline.feature", b"Feature: offline\n")
        put(testing, "features/integration/i.feature", b"Feature: integration\n")
        put(testing, "features/resources/shared.txt", b"same\n")
        put(testing, "features/resources/data.bin", b"\x00\xff")
        sdk_manifest = fixture_source_manifest("algorand-sdk", sdk)
        testing_manifest = fixture_source_manifest("algorand-sdk-testing", testing)
        first = base / "first"
        second = base / "second"
        composed_a = compose_algorand_offline(
            sdk, testing, sdk_manifest, testing_manifest, first)
        composed_b = compose_algorand_offline(
            sdk, testing, sdk_manifest, testing_manifest, second)
        check("offline composition is byte/manifest reproducible",
              canonical_json_bytes(composed_a) == canonical_json_bytes(composed_b)
              and _output_artifacts(first) == _output_artifacts(second))
        check("offline feature is physically moved, not copied to unit",
              (first / "src/test/resources/com/algorand/algosdk/integration/offline.feature").is_file()
              and not (first / "src/test/resources/com/algorand/algosdk/unit/offline.feature").exists())
        check("preexisting SDK unit tree is removed",
              not (first / "src/test/resources/com/algorand/algosdk/unit/stale.feature").exists())
        check("identical resource collision is accepted once",
              (first / "src/test/resources/shared.txt").read_bytes() == b"same\n")
        forged_policy = copy.deepcopy(composed_a)
        pom_mapping = next(mapping for mapping in forged_policy["mappings"]
                           if mapping["destination_path"] == "pom.xml")
        forged_policy["mappings"].remove(pom_mapping)
        forged_policy["destination_file_count"] -= 1
        forged_policy["destination_total_bytes"] -= pom_mapping["bytes"]
        check("composer validator independently derives every mapping including pom.xml",
              refused(lambda: validate_composition_manifest(
                  forged_policy, sdk_manifest, testing_manifest)))
        check("composer validator cannot bypass exact policy without source manifests",
              refused(lambda: validate_composition_manifest(forged_policy)))
        (first / "unaccounted-empty").mkdir()
        check("composed-tree validation refuses a physical empty directory",
              refused(lambda: validate_composed_tree(
                  first, composed_a, sdk_manifest, testing_manifest)))
        os.rmdir(first / "unaccounted-empty")
        (first / "pom.xml").write_bytes(b"drift")
        check("post-composition byte drift is refused",
              refused(lambda: validate_composed_tree(
                  first, composed_a, sdk_manifest, testing_manifest)))
        put(testing, "features/resources/shared.txt", b"different\n")
        testing_drift = fixture_source_manifest("algorand-sdk-testing", testing)
        check("non-identical resource collision is refused",
              refused(lambda: compose_algorand_offline(
                  sdk, testing, sdk_manifest, testing_drift, base / "collision")))
    PINNED_SOURCE_ARCHIVE_FACTS.update(saved_archive_facts)

    # A normalized AST fixture exercises inherited tags, aliases, Rules,
    # multiple Examples blocks, duplicate titles, and lossless slicing.
    feature_raw = (
        b"# language: en\n"
        b"@feature\n"
        b"Feature: F\n"
        b"  narrative\n"
        b"\n"
        b"  Background:\n"
        b"    Given feature background\n"
        b"\n"
        b"  @rule\n"
        b"  Rule: R\n"
        b"    rule narrative\n"
        b"\n"
        b"    Background:\n"
        b"      Given rule background\n"
        b"\n"
        b"    @outline\n"
        b"    Scenario Template: duplicate\n"
        b"      Given <v>\n"
        b"\n"
        b"      @keep\n"
        b"      Scenarios: first\n"
        b"        | v |\n"
        b"        | one |\n"
        b"        | two |\n"
        b"\n"
        b"      @drop\n"
        b"      Examples: second\n"
        b"        | v |\n"
        b"        | three |\n"
        b"        | four |\n"
        b"\n"
        b"    Example: duplicate\n"
        b"      Given other\n"
    )

    def loc(line: int, column: int = 1) -> dict[str, int]:
        return {"column": column, "line": line}

    def tag(name: str, line: int, column: int = 1) -> dict[str, Any]:
        return {"location": loc(line, column), "name": name}

    def step(keyword: str, text: str, line: int, column: int = 1) -> dict[str, Any]:
        return {"keyword": keyword, "location": loc(line, column), "text": text}

    def row(value: str, line: int) -> dict[str, Any]:
        return {"cells": [{"location": loc(line, 9), "value": value}],
                "location": loc(line, 9)}

    ast = {
        "feature": {
            "children": [
                {"description": "", "keyword": "Background", "location": loc(6, 3),
                 "name": "", "steps": [step("Given ", "feature background", 7, 5)],
                 "type": "background"},
                {"children": [
                    {"description": "", "keyword": "Background", "location": loc(13, 5),
                     "name": "", "steps": [step("Given ", "rule background", 14, 7)],
                     "type": "background"},
                    {"description": "", "examples": [
                        {"description": "", "keyword": "Scenarios", "location": loc(21, 7),
                         "name": "first", "table_body": [row("one", 23), row("two", 24)],
                         "table_header": row("v", 22), "tags": [tag("@keep", 20, 7)],
                         "type": "examples"},
                        {"description": "", "keyword": "Examples", "location": loc(27, 7),
                         "name": "second", "table_body": [row("three", 29), row("four", 30)],
                         "table_header": row("v", 28), "tags": [tag("@drop", 26, 7)],
                         "type": "examples"},
                    ], "keyword": "Scenario Template", "location": loc(17, 5),
                     "name": "duplicate", "steps": [step("Given ", "<v>", 18, 7)],
                     "tags": [tag("@outline", 16, 5)], "type": "scenario"},
                    {"description": "", "examples": [], "keyword": "Example",
                     "location": loc(32, 5), "name": "duplicate",
                     "steps": [step("Given ", "other", 33, 7)], "tags": [],
                     "type": "scenario"},
                ], "description": "rule narrative", "keyword": "Rule",
                 "location": loc(10, 3), "name": "R", "tags": [tag("@rule", 9, 3)],
                 "type": "rule"},
            ], "description": "  narrative", "keyword": "Feature", "language": "en",
            "location": loc(3), "name": "F", "tags": [tag("@feature", 2)],
            "type": "feature"},
        "pickles": [], "schema": PARSER_AST_SCHEMA, "uri": "features/f.feature",
    }
    for scenario_line, row_line, tags in (
        (17, 23, ["@feature", "@keep", "@outline", "@rule"]),
        (17, 24, ["@feature", "@keep", "@outline", "@rule"]),
        (17, 29, ["@drop", "@feature", "@outline", "@rule"]),
        (17, 30, ["@drop", "@feature", "@outline", "@rule"]),
        (32, None, ["@feature", "@rule"]),
    ):
        refs = [{"kind": "Scenario", "location": loc(scenario_line, 5)}]
        if row_line is not None:
            refs.append({"kind": "ExamplesRow", "location": loc(row_line, 9)})
        refs.sort(key=lambda item: canonical_json_bytes(item, terminal_lf=False))
        ast["pickles"].append({
            "ast_node_refs": refs, "effective_tags": tags,
            "language": "en", "name": "duplicate",
        })
    ast["pickles"].sort(
        key=lambda item: canonical_json_bytes(item, terminal_lf=False))
    validate_bridge_ast(ast, "features/f.feature")
    flattened = _flatten_scenarios(
        ast, "features/f.feature", "runtime/f.feature", {"@keep"})
    runtime_pickles = _normalize_runtime_pickles(
        ast, "features/f.feature", "runtime/f.feature")
    check("official Pickles carry stable scenario/row identity and effective tags",
          len(runtime_pickles) == 5
          and _runtime_pickle_structure(runtime_pickles)
          == _expected_runtime_pickle_structure(flattened))
    missing_pickles = copy.deepcopy(ast)
    missing_pickles.pop("pickles")
    check("bridge AST refuses adapters that omit official Pickle generation",
          refused(lambda: validate_bridge_ast(
              missing_pickles, "features/f.feature")))
    changed_runtime = copy.deepcopy(runtime_pickles)
    changed_runtime[0]["effective_tags"] = ["@forged"]
    check("source/sliced runtime Pickle multiset drift is refused",
          refused(lambda: _require_equal_runtime_pickle_multisets(
              runtime_pickles, changed_runtime, len(runtime_pickles))))
    check("AST aliases classify outline/plain independent of duplicate title",
          [item["form"] for item in flattened] == ["outline", "plain"]
          and flattened[0]["structural_key"] != flattened[1]["structural_key"])
    check("Feature/Rule/Scenario/Examples tags are inherited per row",
          flattened[0]["rows"][0]["effective_tags"]
          == ["@feature", "@keep", "@outline", "@rule"]
          and flattened[0]["rows"][2]["effective_tags"]
          == ["@drop", "@feature", "@outline", "@rule"])
    check("exact generated tag expression admits only matching Examples block",
          [row["admitted"] for row in flattened[0]["rows"]]
          == [True, True, False, False])
    sliced, slice_evidence = _slice_examples_bytes(feature_raw, ast, 17, {23, 30})
    check("slicer keeps language/Feature/Rule and both Backgrounds verbatim",
          sliced.startswith(b"# language: en\n@feature\nFeature: F\n")
          and b"feature background" in sliced and b"rule background" in sliced)
    check("slicer preserves separate tagged Examples aliases and selected raw rows",
          b"Scenarios: first" in sliced and b"Examples: second" in sliced
          and b"| one |" in sliced and b"| four |" in sliced)
    check("slicer drops rejected rows and foreign duplicate-title scenario",
          b"| two |" not in sliced and b"| three |" not in sliced
          and b"Given other" not in sliced)
    check("slicer records two Background and two Examples source spans",
          len(slice_evidence["preserved_background_spans"]) == 2
          and len(slice_evidence["selected_blocks"]) == 2)
    identity_output_ast = copy.deepcopy(ast)
    identity_output_ast["uri"] = "r2t-j0/examples.feature"
    full_line_map = list(range(1, len(feature_raw.splitlines()) + 1))
    full_span_map, full_lines = _build_structural_span_mappings(
        ast, "features/f.feature", len(full_line_map),
        identity_output_ast, "r2t-j0/examples.feature", len(full_line_map),
        full_line_map,
    )
    check("span evidence covers full Feature/Rule/Background/scenario/step/Examples/row keys",
          {entry["kind"] for entry in full_span_map}
          == {"Feature", "Rule", "Background", "Scenario", "ScenarioOutline",
              "Step", "Examples", "ExamplesRow"}
          and len(full_lines) == len(full_line_map))
    forged_line_map = list(full_line_map)
    forged_line_map[10] = forged_line_map[9]
    check("non-exact source/output structural span mapping is refused",
          refused(lambda: _build_structural_span_mappings(
              ast, "features/f.feature", len(full_line_map),
              identity_output_ast, "r2t-j0/examples.feature", len(full_line_map),
              forged_line_map)))
    incomplete_output_ast = copy.deepcopy(identity_output_ast)
    incomplete_output_ast["feature"]["children"].pop(0)
    check("structural mapping refuses an output AST that drops a preserved node",
          refused(lambda: _build_structural_span_mappings(
              ast, "features/f.feature", len(full_line_map),
              incomplete_output_ast, "r2t-j0/examples.feature", len(full_line_map),
              full_line_map)))
    bad_ast = copy.deepcopy(ast)
    bad_ast["feature"]["children"][1]["children"][1]["generated_id"] = "random"
    check("AST generated/unknown ids cannot enter authority",
          refused(lambda: validate_bridge_ast(bad_ast, "features/f.feature")))

    def synthetic_item(index: int, form: str, row_count: int) -> dict[str, Any]:
        source = f"features/f{index:02d}.feature"
        runtime = f"runtime/f{index:02d}.feature"
        feature_key = [source, "Feature", 1, 1, None, 0]
        kind = "Scenario" if form == "plain" else "ScenarioOutline"
        scenario_key = [source, kind, 3, 3, feature_key, 0]
        rows: list[dict[str, Any]] = []
        if form == "outline":
            examples_key = [source, "Examples", 5, 5, scenario_key, 0]
            for ordinal in range(row_count):
                line = 7 + ordinal
                row_key = [source, "ExamplesRow", line, 7, examples_key, ordinal]
                rows.append({
                    "admitted": True, "case_key": [runtime, scenario_key, row_key],
                    "column": 7, "effective_tags": [], "examples_key": examples_key,
                    "examples_keyword": "Examples", "examples_name": "",
                    "exclusion_reason": None, "line": line,
                    "raw_cells": [str(ordinal)], "row_ordinal": ordinal,
                    "structural_key": row_key,
                })
            case_keys = [row["case_key"] for row in rows]
        else:
            case_keys = [[runtime, scenario_key, None]]
        return {
            "admitted": True, "case_keys": case_keys, "column": 3,
            "effective_tags": [], "exclusion_reason": None, "form": form,
            "item_id": f"epubcheck/{source}:3", "keyword": (
                "Example" if form == "plain" else "Scenario Template"),
            "line": 3, "name": "duplicate", "rows": rows,
            "runtime_uri": runtime, "source_uri": source, "steps": [],
            "structural_key": scenario_key,
        }

    synthetic_items = [synthetic_item(i, "plain" if i < 4 else "outline",
                                      20 if i == 13 else 2)
                       for i in range(14)]
    synthetic_items.sort(key=lambda item: item["item_id"].encode("utf-8"))

    def synthetic_runtime_pickles(item: Mapping[str, Any]) -> list[dict[str, Any]]:
        row_keys = ([None] if item["form"] == "plain"
                    else [row["structural_key"] for row in item["rows"]])
        records = [{
            "effective_tags": ([] if row_key is None else next(
                row["effective_tags"] for row in item["rows"]
                if row["structural_key"] == row_key)),
            "language": "en", "name": item["name"], "row_key": row_key,
            "runtime_uri": item["runtime_uri"],
            "scenario_key": item["structural_key"],
        } for row_key in row_keys]
        records.sort(key=lambda value: canonical_json_bytes(
            value, terminal_lf=False))
        return records

    synthetic_census = {
        "composition_manifest_sha256": None,
        "features": [{
            "ast_canonical_sha256": "1" * 64, "raw_file_sha256": "2" * 64,
            "runtime_pickle_count": len(synthetic_runtime_pickles(item)),
            "runtime_pickle_multiset_sha256": _sha256(canonical_json_bytes(
                synthetic_runtime_pickles(item))),
            "runtime_pickles": synthetic_runtime_pickles(item),
            "runtime_uri": item["runtime_uri"], "source_uri": item["source_uri"],
        } for item in synthetic_items],
        "items": synthetic_items, "items_file_sha256": ITEMS_SHA256,
        "parser": {
            "adapter": PARSER_STACKS["epubcheck"]["adapter"],
            "artifacts": [{
                "bytes": 1, "coordinate": expected["coordinate"],
                "raw_file_sha256": expected["sha256"],
            } for expected in PARSER_STACKS["epubcheck"]["artifacts"]],
            "bridge_source_sha256": _raw_sha256(_parser_source_path()),
            "cucumber_version": "7.8.0", "gherkin_version": "24.0.0",
        },
        "project": "epubcheck", "schema": CENSUS_SCHEMA,
        "source_archive_manifest_sha256": "3" * 64,
        "source_runtime_map": sorted([
            {"runtime_uri": item["runtime_uri"], "source_uri": item["source_uri"]}
            for item in synthetic_items
        ], key=lambda item: canonical_json_bytes(item, terminal_lf=False)),
        "tag_expression": None, "tag_expression_qualification": None,
        "tag_file_sha256": None,
        "totals": _census_totals(synthetic_items, 0),
    }
    _validate_census_structure(synthetic_census)
    scalar = build_scalar_selection(synthetic_census)
    check("scalar selection transfers the exact four-plain deficit to outline",
          scalar["initial_plain_seats"] == 4
          and scalar["initial_outline_seats"] == 6
          and [item["form"] for item in scalar["items"]]
          == ["plain"] * 4 + ["outline"] * 8)
    check("scalar duplicate titles remain 12 unique structural item identities",
          len({item["item_id"] for item in scalar["items"]}) == 12)
    examples_selection = build_examples_selection(synthetic_census)
    check("Examples selection chooses largest outline, k=16, then restores source order",
          examples_selection["item_id"] == "epubcheck/features/f13.feature:3"
          and examples_selection["selected_row_count"] == 16
          and [row["line"] for row in examples_selection["rows"]]
          == sorted(row["line"] for row in examples_selection["rows"]))
    tampered_selection = copy.deepcopy(examples_selection)
    tampered_selection["rows"][0]["line"] += 1
    check("Examples selection source-line tampering is refused",
          refused(lambda: validate_examples_selection(
              tampered_selection, synthetic_census)))
    unknown_census = copy.deepcopy(synthetic_census)
    unknown_census["items"][0]["uuid"] = "random"
    check("census closed schema refuses generated UUID authority",
          refused(lambda: validate_census(unknown_census)))

    print("\n" + ("ALL PASS (java.j0)" if ok else "FAILURES (java.j0)"))
    return 0 if ok else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        raise SystemExit(selftest())
    raise SystemExit(main())
