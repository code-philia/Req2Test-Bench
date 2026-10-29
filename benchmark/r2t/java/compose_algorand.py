"""Compose the two pinned Algorand Java trees without the upstream harness.

The source checkouts must already exist locally.  Authentication uses J0's
reviewed source-manifest primitive, but this module owns the post-J0 scope
delta: ``test-harness.sh`` is excluded and the result is pinned by one exact
destination-tree digest.  No Maven, Docker, algod, kmd, or network path exists
here.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import j0
from .algorand import (OFFLINE_SOURCE, OFFLINE_WORKSPACE,
                       source_to_workspace_feature,
                       workspace_to_source_feature)


SCHEMA = "r2t.java-algorand-composition/1"

SDK_PROJECT = "algorand-sdk"
TESTING_PROJECT = "algorand-sdk-testing"
SDK_COMMIT = "4e38dadc4eec827ed8742c8bb272e0545c801932"
SDK_GIT_TREE = "6b896a9e6a64ca846ebe8a6c59e32056fba13b43"
SDK_SOURCE_MANIFEST_SHA256 = \
    "5916f90edef78e21d2022505a02a7199796c95c52530d5d7769d151afcdb0d67"
TESTING_COMMIT = "7c67284b52675257e66c017cc3606bcd4803f4c6"
TESTING_GIT_TREE = "f6c4984d2e9ae5256bfee89df155900f28801d48"
TESTING_SOURCE_MANIFEST_SHA256 = \
    "c039afa20a0182eb09d1ce68db99aa31e1859da62da38fc4e0968240fef5d4fb"

EXPECTED_FILE_COUNT = 697
EXPECTED_TOTAL_BYTES = 18_267_756
EXPECTED_TREE_SHA256 = \
    "a00cc2551054804e1376b37a612b6f9b74d1cdc8bfb7425d34e744455cb84b77"

HARNESS_PATH = "test-harness.sh"
STALE_RESOURCE_PREFIXES = (
    "src/test/resources/com/algorand/algosdk/unit/",
    "src/test/resources/com/algorand/algosdk/integration/",
)

_MANIFEST_KEYS = {
    "composer_source_sha256", "destination_file_count",
    "destination_total_bytes", "destination_tree_digest_domain",
    "destination_tree_sha256", "excluded_sdk_paths", "schema", "sources",
}


class CompositionError(j0.J0Error):
    """A controlled refusal of an Algorand composition."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _source_manifest(project: str, root: os.PathLike[str] | str) -> dict[str, Any]:
    manifest = j0.build_source_archive_manifest(project, root)
    expected = {
        SDK_PROJECT: SDK_SOURCE_MANIFEST_SHA256,
        TESTING_PROJECT: TESTING_SOURCE_MANIFEST_SHA256,
    }[project]
    if _sha256(j0.canonical_json_bytes(manifest)) != expected:
        raise CompositionError(f"{project}: frozen source-manifest mismatch")
    return manifest


def _file_map(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {entry["path"]: entry for entry in manifest["files"]}


def _plan(
    sdk_manifest: Mapping[str, Any],
    testing_manifest: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Return the unique destination plan and explicit SDK exclusions."""
    files = {
        SDK_PROJECT: _file_map(sdk_manifest),
        TESTING_PROJECT: _file_map(testing_manifest),
    }
    destinations: dict[str, dict[str, Any]] = {}
    excluded: list[str] = []

    def add(project: str, source: str, destination: str) -> None:
        j0.validate_posix_path(destination, where="composition destination")
        entry = files[project][source]
        planned = {
            "bytes": entry["bytes"],
            "destination": destination,
            "sha256": entry["raw_file_sha256"],
            "source": source,
            "source_project": project,
        }
        previous = destinations.get(destination)
        if previous is not None:
            if (previous["bytes"], previous["sha256"]) \
                    != (planned["bytes"], planned["sha256"]):
                raise CompositionError(
                    f"non-identical destination collision: {destination}")
            return
        destinations[destination] = planned

    for path in sorted(files[SDK_PROJECT], key=lambda value: value.encode("utf-8")):
        if path == HARNESS_PATH or path.startswith(STALE_RESOURCE_PREFIXES):
            excluded.append(path)
        else:
            add(SDK_PROJECT, path, path)

    for path in sorted(files[TESTING_PROJECT],
                       key=lambda value: value.encode("utf-8")):
        destination: str | None = None
        if path.startswith(("features/unit/", "features/integration/")):
            destination = source_to_workspace_feature(path)
        elif path.startswith("features/resources/"):
            suffix = path[len("features/resources/"):]
            if suffix:
                destination = "src/test/resources/" + suffix
        if destination is not None:
            add(TESTING_PROJECT, path, destination)

    plan = sorted(destinations.values(),
                  key=lambda entry: entry["destination"].encode("utf-8"))
    excluded.sort(key=lambda value: value.encode("utf-8"))
    return plan, excluded


def _prepare_empty_directory(path: Path) -> None:
    if path.is_symlink():
        raise CompositionError(f"output is a symlink: {path}")
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise CompositionError(f"output is not an empty directory: {path}")
    else:
        path.mkdir(parents=True)
    path.chmod(0o755)


def _materialize(
    sdk_root: os.PathLike[str] | str,
    testing_root: os.PathLike[str] | str,
    workspace: Path,
    plan: Sequence[Mapping[str, Any]],
) -> str:
    roots = {SDK_PROJECT: Path(sdk_root), TESTING_PROJECT: Path(testing_root)}
    _prepare_empty_directory(workspace)
    tree: list[tuple[str, bytes]] = []
    for entry in plan:
        raw = roots[entry["source_project"]].joinpath(
            *entry["source"].split("/")).read_bytes()
        if len(raw) != entry["bytes"] or _sha256(raw) != entry["sha256"]:
            raise CompositionError(
                f"source bytes changed: {entry['source_project']}:{entry['source']}")
        target = workspace.joinpath(*entry["destination"].split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o644)
        tree.append((entry["destination"], raw))
    for directory, _dirnames, _filenames in os.walk(workspace):
        Path(directory).chmod(0o755)
    return j0.framed_tree_sha256(tree)


def _source_identities(
    sdk_manifest: Mapping[str, Any],
    testing_manifest: Mapping[str, Any],
) -> list[dict[str, str]]:
    return [
        {
            "commit": SDK_COMMIT,
            "git_tree": SDK_GIT_TREE,
            "project": SDK_PROJECT,
            "source_archive_manifest_sha256":
                _sha256(j0.canonical_json_bytes(dict(sdk_manifest))),
        },
        {
            "commit": TESTING_COMMIT,
            "git_tree": TESTING_GIT_TREE,
            "project": TESTING_PROJECT,
            "source_archive_manifest_sha256":
                _sha256(j0.canonical_json_bytes(dict(testing_manifest))),
        },
    ]


def _expected_sources() -> list[dict[str, str]]:
    return [
        {
            "commit": SDK_COMMIT,
            "git_tree": SDK_GIT_TREE,
            "project": SDK_PROJECT,
            "source_archive_manifest_sha256": SDK_SOURCE_MANIFEST_SHA256,
        },
        {
            "commit": TESTING_COMMIT,
            "git_tree": TESTING_GIT_TREE,
            "project": TESTING_PROJECT,
            "source_archive_manifest_sha256": TESTING_SOURCE_MANIFEST_SHA256,
        },
    ]


def _workspace_tree(workspace: Path) -> tuple[list[tuple[str, bytes]], set[str]]:
    if not workspace.is_dir() or workspace.is_symlink():
        raise CompositionError("workspace is not a real directory")
    files: list[tuple[str, bytes]] = []
    physical_dirs: set[str] = set()
    for directory, dirnames, filenames in os.walk(workspace, followlinks=False):
        current = Path(directory)
        if stat.S_IMODE(current.stat().st_mode) != 0o755:
            raise CompositionError(f"workspace directory mode is not 0755: {current}")
        for name in dirnames:
            child = current / name
            if child.is_symlink():
                raise CompositionError(f"workspace contains symlink: {child}")
            physical_dirs.add(child.relative_to(workspace).as_posix())
        for name in filenames:
            path = current / name
            if path.is_symlink() or not path.is_file():
                raise CompositionError(f"workspace contains non-regular file: {path}")
            if stat.S_IMODE(path.stat().st_mode) != 0o644:
                raise CompositionError(f"workspace file mode is not 0644: {path}")
            files.append((path.relative_to(workspace).as_posix(), path.read_bytes()))
    files.sort(key=lambda item: item[0].encode("utf-8"))
    implied_dirs: set[str] = set()
    for path, _raw in files:
        parent = Path(path).parent
        while parent != Path("."):
            implied_dirs.add(parent.as_posix())
            parent = parent.parent
    if physical_dirs != implied_dirs:
        raise CompositionError("workspace contains an unexpected empty directory")
    return files, physical_dirs


def compose(
    sdk_root: os.PathLike[str] | str,
    testing_root: os.PathLike[str] | str,
    output: os.PathLike[str] | str,
) -> dict[str, Any]:
    """Authenticate the pins and create ``workspace/`` plus ``manifest.json``."""
    sdk_manifest = _source_manifest(SDK_PROJECT, sdk_root)
    testing_manifest = _source_manifest(TESTING_PROJECT, testing_root)
    plan, excluded = _plan(sdk_manifest, testing_manifest)
    if excluded != [HARNESS_PATH]:
        raise CompositionError(f"unexpected SDK exclusions: {excluded!r}")
    if len(plan) != EXPECTED_FILE_COUNT \
            or sum(entry["bytes"] for entry in plan) != EXPECTED_TOTAL_BYTES:
        raise CompositionError("composition census differs from the frozen pins")

    output_path = Path(output)
    _prepare_empty_directory(output_path)
    tree_sha256 = _materialize(
        sdk_root, testing_root, output_path / "workspace", plan)
    if tree_sha256 != EXPECTED_TREE_SHA256:
        raise CompositionError("composition tree differs from the frozen mapping")
    manifest = {
        "composer_source_sha256": _sha256(Path(__file__).read_bytes()),
        "destination_file_count": EXPECTED_FILE_COUNT,
        "destination_total_bytes": EXPECTED_TOTAL_BYTES,
        "destination_tree_digest_domain": j0.TREE_DOMAIN,
        "destination_tree_sha256": EXPECTED_TREE_SHA256,
        "excluded_sdk_paths": [HARNESS_PATH],
        "schema": SCHEMA,
        "sources": _source_identities(sdk_manifest, testing_manifest),
    }
    j0.write_canonical_json_new(output_path / "manifest.json", manifest)
    return validate(output_path)


def validate(output: os.PathLike[str] | str) -> dict[str, Any]:
    """Validate the exact composed output without reopening either source."""
    output_path = Path(output)
    if not output_path.is_dir() or output_path.is_symlink():
        raise CompositionError("output is not a real directory")
    if stat.S_IMODE(output_path.stat().st_mode) != 0o755:
        raise CompositionError("output mode is not 0755")
    if sorted(path.name for path in output_path.iterdir()) \
            != ["manifest.json", "workspace"]:
        raise CompositionError("output must contain only manifest.json and workspace")

    manifest_path = output_path / "manifest.json"
    if stat.S_IMODE(manifest_path.stat().st_mode) != 0o644:
        raise CompositionError("manifest mode is not 0644")
    manifest = j0.load_canonical_json(manifest_path)
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEYS:
        raise CompositionError("manifest has the wrong shape")
    expected = {
        "composer_source_sha256": _sha256(Path(__file__).read_bytes()),
        "destination_file_count": EXPECTED_FILE_COUNT,
        "destination_total_bytes": EXPECTED_TOTAL_BYTES,
        "destination_tree_digest_domain": j0.TREE_DOMAIN,
        "destination_tree_sha256": EXPECTED_TREE_SHA256,
        "excluded_sdk_paths": [HARNESS_PATH],
        "schema": SCHEMA,
        "sources": _expected_sources(),
    }
    if manifest != expected:
        raise CompositionError("manifest differs from the frozen composition")

    files, _directories = _workspace_tree(output_path / "workspace")
    if len(files) != EXPECTED_FILE_COUNT \
            or sum(len(raw) for _path, raw in files) != EXPECTED_TOTAL_BYTES:
        raise CompositionError("workspace census differs from the frozen composition")
    if j0.framed_tree_sha256(files) != EXPECTED_TREE_SHA256:
        raise CompositionError("workspace tree digest differs from the frozen composition")
    paths = {path for path, _raw in files}
    if HARNESS_PATH in paths:
        raise CompositionError("upstream test-harness.sh entered the workspace")
    if "src/test/resources/com/algorand/algosdk/unit/offline.feature" in paths \
            or OFFLINE_WORKSPACE not in paths:
        raise CompositionError("offline.feature is not at its integration destination")
    return manifest


def selftest() -> int:
    """Exercise the Algorand-only mapping delta without external processes."""
    ok = True

    def check(name: str, condition: object) -> None:
        nonlocal ok
        passed = bool(condition)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed

    def put(root: Path, relative: str, raw: bytes) -> None:
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def fixture(root: Path) -> dict[str, Any]:
        entries = []
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            raw = path.read_bytes()
            entries.append({
                "bytes": len(raw),
                "path": path.relative_to(root).as_posix(),
                "raw_file_sha256": _sha256(raw),
            })
        return {"files": entries}

    check("frozen destination census is explicit",
          (EXPECTED_FILE_COUNT, EXPECTED_TOTAL_BYTES)
          == (697, 18_267_756))
    check("frozen destination tree is explicit",
          EXPECTED_TREE_SHA256
          == "a00cc2551054804e1376b37a612b6f9b74d1cdc8bfb7425d34e744455cb84b77")
    mapped = source_to_workspace_feature("features/unit/nested/a.feature")
    check("feature mapping preserves nested suffixes and round-trips",
          mapped.endswith("/unit/nested/a.feature")
          and workspace_to_source_feature(mapped)
          == "features/unit/nested/a.feature"
          and workspace_to_source_feature(OFFLINE_WORKSPACE)
          == OFFLINE_SOURCE)

    with tempfile.TemporaryDirectory(prefix="r2t-compose-algorand-") as temporary:
        base = Path(temporary)
        sdk, testing = base / "sdk", base / "testing"
        sdk.mkdir()
        testing.mkdir()
        put(sdk, "pom.xml", b"<project/>\n")
        put(sdk, HARNESS_PATH, b"git clone forbidden\n")
        put(sdk, "src/main/java/Example.java", b"class Example {}\n")
        put(sdk, "src/test/resources/com/algorand/algosdk/unit/stale.feature",
            b"Feature: stale\n")
        put(sdk, "src/test/resources/shared.txt", b"same\n")
        put(testing, "features/unit/a.feature", b"Feature: unit\n")
        put(testing, "features/unit/offline.feature", b"Feature: offline\n")
        put(testing, "features/integration/i.feature", b"Feature: integration\n")
        put(testing, "features/resources/shared.txt", b"same\n")
        put(testing, "features/resources/data.bin", b"\x00\xff")

        plan, excluded = _plan(fixture(sdk), fixture(testing))
        first, second = base / "first", base / "second"
        first_sha = _materialize(sdk, testing, first, plan)
        second_sha = _materialize(sdk, testing, second, plan)
        first_files, first_dirs = _workspace_tree(first)
        second_files, second_dirs = _workspace_tree(second)
        check("fixture composition is byte-and-mode reproducible",
              first_sha == second_sha and first_files == second_files
              and first_dirs == second_dirs)
        check("network harness is excluded",
              HARNESS_PATH in excluded and not (first / HARNESS_PATH).exists())
        check("stale SDK resource tree is replaced",
              not (first / "src/test/resources/com/algorand/algosdk/unit/stale.feature").exists())
        check("offline.feature is relocated",
              first.joinpath(*OFFLINE_WORKSPACE.split("/")).is_file()
              and not (first / "src/test/resources/com/algorand/algosdk/unit/offline.feature").exists())
        check("identical collision is one destination",
              (first / "src/test/resources/shared.txt").read_bytes() == b"same\n")

        put(testing, "features/resources/shared.txt", b"different\n")
        try:
            _plan(fixture(sdk), fixture(testing))
        except CompositionError:
            collision_refused = True
        else:
            collision_refused = False
        check("non-identical collision is refused", collision_refused)

    print("Algorand composer selftest: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compose the exact source-only Algorand Java workspace")
    parser.add_argument("--sdk-root")
    parser.add_argument("--testing-root")
    parser.add_argument("--output")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        if args.sdk_root or args.testing_root or args.output:
            parser.error("--selftest takes no composition paths")
        return selftest()
    if not all((args.sdk_root, args.testing_root, args.output)):
        parser.error("composition requires --sdk-root, --testing-root, and --output")
    try:
        manifest = compose(args.sdk_root, args.testing_root, args.output)
    except (j0.J0Error, OSError) as exc:
        print(f"Algorand composition REFUSED: {exc}", file=sys.stderr)
        return 2
    print(
        "Algorand composition GENERATED: "
        f"files={manifest['destination_file_count']} "
        f"bytes={manifest['destination_total_bytes']} "
        f"tree={manifest['destination_tree_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
