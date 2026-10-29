"""The ``r2t-mutate-java`` 1.0 binding.

``java/Mutate.java`` is one offline JDK-only program with enumerate and apply
modes.  This module supplies the language-neutral mutation spine with that
program's identity, validates its complete envelope, and binds Cucumber's
population/map CLI to the exact final-reviewed release, canonical image,
Surefire classpath and worker source pool.  Campaign execution remains at the
existing mutation-run seam.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
import json
import hashlib
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import zipfile
from typing import Iterable, Optional
import xml.etree.ElementTree as ET

from ..data import mutation as M
from ..java import kapua as K

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JAVA_ENGINE_DIR = os.path.join(HERE, "java")
JAVA_SOURCE = os.path.join(JAVA_ENGINE_DIR, "Mutate.java")
#: Concurrent audit trees, each with its own session container.  The owner's
#: number (2026-08-12): "parallelize k=16 if possible ... set a large k for
#: the sake of efficiency".  It deliberately oversubscribes a 40-core box
#: whose per-mutant container was measured at ~291% CPU (PROVENANCE §A30).
DEFAULT_AUDIT_WORKERS = 16


def _source_constant(name: str) -> str:
    """Read a Java producer constant so Python cannot mint a parallel id space."""
    with open(JAVA_SOURCE, encoding="utf-8") as fh:
        source = fh.read()
    match = re.search(
        r"public\s+static\s+final\s+String\s+" + re.escape(name)
        + r"\s*=\s*(?:\n\s*)?\"([^\"]+)\"\s*;", source)
    if match is None:
        raise RuntimeError(f"Java mutation source has no simple {name} constant")
    return match.group(1)


ENGINE = _source_constant("ENGINE")
ENGINE_VERSION = _source_constant("ENGINE_VERSION")
ENUMERATOR_REV = _source_constant("ENUMERATOR_REV")
ANALYSIS_SCHEMA = "r2t.java-analysis-recipe/1"
MODULE_ANALYSIS_SCHEMA = "r2t.kapua-java-module-analysis/1"
_ANALYSIS_KEYS = frozenset({
    "schema", "classpath", "sourcepath", "module_path", "digest",
})
_ANALYSIS_ENTRY_KEYS = frozenset({"path", "kind", "sha256"})
_MODULE_ANALYSIS_KEYS = frozenset({
    "schema", "project", "modules", "digest",
})
_MODULE_ANALYSIS_ROW_KEYS = frozenset({
    "module", "source_root", "source_files", "compiler", "recipe", "digest",
})
_MODULE_COMPILER_KEYS = frozenset({
    "java_home", "parser", "encoding", "source", "target", "release",
    "runtime_executable_sha256", "compiler_executable_sha256",
    "tools_jar_sha256",
})
_MODULE_JAVA_HOMES = frozenset({
    "/opt/java/openjdk", "/opt/java/openjdk8",
})
_KAPUA_ABSENT_MANIFEST_CLASSPATHS = {
    "var/bench_java_analysis/m2/com/sun/xml/bind/jaxb-core/2.3.0.1/"
    "jaxb-core-2.3.0.1.jar": ("jaxb-api.jar",),
    "var/bench_java_analysis/m2/org/glassfish/jaxb/jaxb-runtime/2.3.1/"
    "jaxb-runtime-2.3.1.jar": (
        "jaxb-api-2.3.1.jar", "txw2-2.3.1.jar",
        "istack-commons-runtime-3.0.7.jar", "stax-ex-1.8.jar",
        "FastInfoset-1.2.15.jar", "javax.activation-api-1.2.0.jar"),
}
_EMPTY_PATH_NAMES = {
    "classpath": ".r2t-java-empty-classpath",
    "sourcepath": ".r2t-java-empty-sourcepath",
}

# Java launchers and javac consume these variables before the mutation engine
# sees its explicit argv.  In particular, JAVA_TOOL_OPTIONS can append an
# arbitrary host JAR to the boot class path, silently making an undeclared
# dependency visible even though the analysis recipe supplies exact
# classpath/sourcepath/module-path arguments.  Every trusted Java subprocess
# uses ``sanitised_java_env``; the Docker sidecar also overrides these keys in
# case the worker image declares them in Config.Env.
AMBIENT_JAVA_ENV_KEYS: tuple[str, ...] = (
    "_JAVA_OPTIONS",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "JDK_JAVAC_OPTIONS",
    "CLASSPATH",
)
TOOLCHAIN_JAVAC_MARKER = "R2T_JAVAC_IDENTITY"
TOOLCHAIN_JAVA_MARKER = "R2T_JAVA_PROPERTIES"
TOOLCHAIN_JAVA_SHA_MARKER = "R2T_JAVA_EXECUTABLE_SHA256"
TOOLCHAIN_JAVAC_SHA_MARKER = "R2T_JAVAC_EXECUTABLE_SHA256"
TOOLCHAIN_TOOLS_JAR_SHA_MARKER = "R2T_TOOLS_JAR_SHA256"

# These repeat the source-side traversal exclusions in manifest vocabulary.
# Like the PHP/Python twins, the source enumerator matches these names as path
# segments while mutation.is_excluded applies manifest entries as prefixes.
EXCLUDED_PREFIXES: tuple[str, ...] = (
    "vendor/", "var/", ".git/", ".gradle/", "target/", "build/", "out/",
    "generated-sources/",
)

SOURCEPATH = "src/main/java"
DEFAULT_PATHS: tuple[str, ...] = (SOURCEPATH,)
MUTATION_AUTHORITY_DIR = "java-mutation-authority"
_AUTHORITY_FILES = frozenset({
    "canonical-transcript.json", "m2-manifest.json",
    "reality-manifest.json", "reality-transcript.json",
})
_RELEVANT_REALITY_RUNS = {
    "kapua": tuple(
        name for suite in K.SUITES
        for name in (suite.runner_package + "." + suite.upstream_runner_class + "-ordinary",
                     suite.runner_package + "." + suite.upstream_runner_class + "-unstripped-dry-run")),
    "epubcheck": ("full-suite", "unstripped-dry-run"),
    "algorand-sdk": (
        "unit-ordinary", "unit-unstripped-dry-run",
        "offline-ordinary", "offline-unstripped-dry-run"),
}
_REALITY_WORKSPACE_CLASSPATH = (
    "/work/target/test-classes", "/work/target/classes")
_MAX_AUTHORITY_JSON = 64 * 1024 * 1024
_MAX_SUREFIRE_XML = 64 * 1024 * 1024
_PRODUCTION_COMPILE_WORKERS = 4


def _canonical_sha256(value) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sanitised_java_env(base=None) -> dict[str, str]:
    """Copy an environment without launcher-controlled Java inputs."""
    env = dict(os.environ if base is None else base)
    for key in AMBIENT_JAVA_ENV_KEYS:
        env.pop(key, None)
    return env


def _regular_bytes(path: str, label: str, *, maximum: int) -> bytes:
    try:
        info = os.lstat(path)
        if os.path.islink(path) or not stat.S_ISREG(info.st_mode) \
                or os.path.realpath(path) != os.path.abspath(path) \
                or info.st_size > maximum:
            raise ValueError
        with open(path, "rb") as handle:
            raw = handle.read(maximum + 1)
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"REFUSED: Java {label} is not a bounded canonical regular file") \
            from exc
    if len(raw) > maximum or len(raw) != info.st_size:
        raise ValueError(f"REFUSED: Java {label} changed while being read")
    return raw


def _json_object(path: str, label: str) -> tuple[dict, bytes]:
    raw = _regular_bytes(path, label, maximum=_MAX_AUTHORITY_JSON)
    from .. import docker_authority as D
    try:
        value = D.loads_exact_json(raw, label=f"Java {label}")
    except D.DockerAuthorityRefused as exc:
        raise ValueError(str(exc)) from exc
    if not isinstance(value, dict):
        raise ValueError(f"REFUSED: Java {label} is not an object")
    return value, raw


def _validate_m2_manifest(document: dict) -> dict[str, dict]:
    """Read the existing research-minimal Maven inventory, without widening it."""
    from ..java import research_minimal as R
    if set(document) != {"schema", "files", "totals"} \
            or document.get("schema") != R.MANIFEST_SCHEMA \
            or not isinstance(document.get("files"), list) \
            or not isinstance(document.get("totals"), dict) \
            or set(document["totals"]) != {"files", "bytes"}:
        raise ValueError("REFUSED: Java Maven authority manifest has another shape")
    by_path = {}
    ordered = []
    total = 0
    for index, row in enumerate(document["files"]):
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise ValueError(
                f"REFUSED: Java Maven authority row #{index} fields differ")
        rel = _canonical_relative(row.get("path"), "Maven manifest")
        size = row.get("bytes")
        digest = row.get("sha256")
        if rel in by_path or not isinstance(size, int) \
                or isinstance(size, bool) or size < 0 or not _is_sha256(digest):
            raise ValueError(
                f"REFUSED: Java Maven authority row #{index} is malformed")
        by_path[rel] = row
        ordered.append(rel)
        total += size
    if ordered != sorted(ordered, key=lambda value: value.encode("utf-8")) \
            or document["totals"] != {"files": len(ordered), "bytes": total}:
        raise ValueError("REFUSED: Java Maven authority inventory is not canonical")
    return by_path


def validate_population_release(
        release_root: str, *, project: str, approval_path: str,
        approved_digest: str) -> dict:
    """Authenticate the exact final-review release before opening controls."""
    if project == "kapua":
        from ..java.kapua_population import validate_release
        return validate_release(release_root, approval_path=approval_path,
                                approved_digest=approved_digest)
    from ..java import release_validation as V

    root = os.path.abspath(release_root)
    if os.path.islink(root) or not os.path.isdir(root) \
            or os.path.realpath(root) != root:
        raise ValueError(
            "REFUSED: Java --artifacts must be the canonical final release "
            "root")
    approval = V._approval(
        project, "release", approval_path, approved_digest)
    manifest_path = os.path.join(
        os.path.dirname(root), "release-manifest.json")
    document = V._validate_release_file_manifest(
        root, manifest_path, approval.release_manifest_sha256,
        approval.release_tree_sha256)
    items_path = os.path.join(root, "items.jsonl")
    item_refs = [row for row in document["files"]
                 if row.get("path") == "items.jsonl"]
    closure_refs = [
        row for row in document["files"]
        if row.get("path") == "control-artifacts/closures.json"]
    if len(item_refs) != 1 or len(closure_refs) != 1:
        raise ValueError(
            "REFUSED: Java final release lacks unique item/closure records")
    items_raw = _regular_bytes(
        items_path, "final release items", maximum=_MAX_AUTHORITY_JSON)
    items_sha256 = hashlib.sha256(items_raw).hexdigest()
    if item_refs[0].get("bytes") != len(items_raw) \
            or item_refs[0].get("sha256") != items_sha256:
        raise ValueError(
            "REFUSED: Java final release items differ from reviewed manifest")
    from ..bench import result_ledger as L
    try:
        item_rows = L._json_lines(items_raw, "Java final release items")
    except L.ResultLedgerRefused as exc:
        raise ValueError(str(exc)) from exc
    release_ids = set()
    for number, row in enumerate(item_rows, 1):
        item_id = row.get("item_id")
        if not isinstance(item_id, str) or not item_id:
            raise ValueError(
                f"REFUSED: Java final release row {number} has no item_id")
        if item_id in release_ids:
            raise ValueError(
                f"REFUSED: Java final release repeats item_id {item_id!r}")
        release_ids.add(item_id)
    recorded = document.get("released_item_ids")
    if document.get("project") != project \
            or document.get("tree_sha256") != approval.release_tree_sha256 \
            or not isinstance(recorded, list) \
            or any(not isinstance(item_id, str) or not item_id
                   for item_id in recorded) \
            or len(recorded) != len(set(recorded)) \
            or set(recorded) != release_ids:
        raise ValueError(
            "REFUSED: Java final release population differs from approval")
    return {
        "root": root, "manifest_path": manifest_path,
        "items_path": items_path, "released_item_ids": release_ids,
        "item_rows": item_rows,
        "items_sha256": items_sha256,
        "closures_sha256": closure_refs[0]["sha256"],
        "manifest_sha256": approval.release_manifest_sha256,
        "tree_sha256": approval.release_tree_sha256,
    }


def _surefire_classpath(raw: bytes, label: str) -> str:
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError(f"REFUSED: Java {label} contains an XML declaration")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"REFUSED: Java {label} is malformed XML") from exc
    values = [
        node.get("value") for node in root.iter()
        if node.tag.rsplit("}", 1)[-1] == "property"
        and node.get("name") == "java.class.path"]
    if len(values) != 1 or not isinstance(values[0], str) or not values[0]:
        raise ValueError(
            f"REFUSED: Java {label} has no unique nonempty java.class.path")
    return values[0]


def reality_classpath_entries(value: str) -> list[str]:
    """Split one recorded reality `java.class.path` into its usable entries.

    Separated from `load_population_authority` so the rule can be probed on
    the exact production bytes it governs.  It had been inline, and the only
    thing that ever exercised it was a hand-written three-entry fixture -- so
    the first real Surefire report the benchmark ever showed it was refused.

    ONE TRAILING SEPARATOR IS TOLERATED, AND ONLY ONE.  Surefire 3.0.0-M5 --
    the version `algorand-sdk`'s pom pins -- writes the test classpath into
    the report's properties with a trailing `:`, so `split` yields a final
    empty element.  That element is the join's punctuation, not a directory:
    the same report's `surefire.real.class.path` shows the fork ran off a
    generated booter jar (`target/surefire/surefirebooter*.jar`), so nothing
    was ever loaded from it.  The measured string is stable -- byte-identical
    (sha256 `21649431b4a4...`) across all four non-stripped runs of three
    independent reality chains built on three different canonical images --
    and is pinned as this module's selftest fixture.

    An empty element ANYWHERE ELSE stays refused, because there it means `.`:
    the current directory, a real classpath entry whose contents depend on
    where the JVM was started and which no manifest can pin.  A SECOND
    trailing one stays refused too -- `a::` trims once to `a:` and is then
    refused on the empty that remains -- and so does a classpath that is
    nothing but separators.
    """
    entries = value.split(":")
    if len(entries) > 1 and entries[-1] == "":
        entries = entries[:-1]
    if any(not entry or not entry.startswith("/")
           or os.path.normpath(entry) != entry or "\x00" in entry
           or "\n" in entry or "\r" in entry for entry in entries) \
            or len(entries) != len(set(entries)):
        raise ValueError(
            "REFUSED: Java reality classpath is empty, relative, or repeated")
    if tuple(entries[:2]) != _REALITY_WORKSPACE_CLASSPATH \
            or any(entry.startswith("/work/") for entry in entries[2:]):
        raise ValueError(
            "REFUSED: Java reality classpath workspace entries differ from "
            "the two discarded target directories")
    return entries


def load_population_authority(
        release_root: str, *, project: str, repo_roots: Iterable[str],
        runtime: dict, approval_path: str, approved_digest: str) -> dict:
    """Authenticate the released source/image/Maven/Surefire analysis subset."""
    if project == "kapua":
        from ..java.kapua_population import load_population_authority as load_kapua
        return load_kapua(release_root, repo_roots=repo_roots, runtime=runtime,
                          approval_path=approval_path, approved_digest=approved_digest)
    if project not in _RELEVANT_REALITY_RUNS:
        raise ValueError(f"REFUSED: no Java population authority for {project!r}")
    release = validate_population_release(
        release_root, project=project, approval_path=approval_path,
        approved_digest=approved_digest)
    authority = os.path.join(
        release["root"], "control-artifacts", MUTATION_AUTHORITY_DIR)
    if os.path.islink(authority) or not os.path.isdir(authority) \
            or os.path.realpath(authority) != authority:
        raise ValueError(
            "REFUSED: release control artifacts have no canonical Java "
            "mutation authority")
    reality, _reality_raw = _json_object(
        os.path.join(authority, "reality-transcript.json"),
        "reality transcript")
    canonical, canonical_raw = _json_object(
        os.path.join(authority, "canonical-transcript.json"),
        "canonical transcript")
    reality_manifest, reality_manifest_raw = _json_object(
        os.path.join(authority, "reality-manifest.json"),
        "reality manifest")
    m2_manifest, m2_raw = _json_object(
        os.path.join(authority, "m2-manifest.json"), "Maven manifest")

    from ..java import research_minimal as R
    if reality.get("schema") != R.REALITY_SCHEMA \
            or reality.get("path") != R.PATH \
            or reality.get("project") != project \
            or reality.get("status") != "complete" \
            or reality.get("network") != "none" \
            or reality.get("pull") != "never":
        raise ValueError("REFUSED: Java mutation reality transcript differs")
    if canonical.get("schema") != R.IMAGE_SCHEMA \
            or canonical.get("path") != R.PATH \
            or canonical.get("project") != project \
            or canonical.get("phase") != "canonical" \
            or canonical.get("status") != "complete":
        raise ValueError("REFUSED: Java mutation canonical transcript differs")
    if hashlib.sha256(canonical_raw).hexdigest() \
            != reality.get("canonical_transcript_sha256") \
            or canonical.get("source") != reality.get("source") \
            or canonical.get("authority") != reality.get("authority") \
            or canonical.get("base") != reality.get("base"):
        raise ValueError(
            "REFUSED: Java mutation reality/canonical chain is not exact")
    result = canonical.get("result") if isinstance(canonical, dict) else None
    if not isinstance(result, dict) \
            or result.get("candidate_image_id") != reality.get("image_id") \
            or hashlib.sha256(m2_raw).hexdigest() \
            != result.get("m2_manifest_sha256"):
        raise ValueError("REFUSED: Java mutation image/Maven chain differs")

    selected = runtime.get("selected") if isinstance(runtime, dict) else None
    if not isinstance(selected, dict):
        raise ValueError("REFUSED: Java population has no validated live worker")
    worker_runtime = selected.get("runtime")
    worker_authority = selected.get("authority")
    recorded_authority = reality.get("authority")
    if not isinstance(worker_runtime, dict) \
            or not isinstance(worker_authority, dict) \
            or not isinstance(recorded_authority, dict) \
            or worker_runtime.get("container_image_digest") \
            != reality.get("image_id") \
            or worker_runtime.get("docker_execution_authority") \
            != recorded_authority.get("reference") \
            or (worker_authority.get("daemon") or {}).get(
                "fingerprint_sha256") \
            != recorded_authority.get("daemon_fingerprint"):
        raise ValueError(
            "REFUSED: live Java worker differs from reviewed image/authority")

    manifest_ref = reality.get("manifest")
    if not isinstance(manifest_ref, dict) \
            or manifest_ref.get("path") != "manifest.json" \
            or manifest_ref.get("bytes") != len(reality_manifest_raw) \
            or manifest_ref.get("sha256") \
            != hashlib.sha256(reality_manifest_raw).hexdigest() \
            or reality_manifest.get("schema") \
            != "r2t.java-research-minimal-reality-manifest/1" \
            or set(reality_manifest) != {"schema", "files"} \
            or not isinstance(reality_manifest.get("files"), list):
        raise ValueError("REFUSED: Java mutation reality manifest differs")
    refs = {}
    for ref in reality_manifest["files"]:
        if not isinstance(ref, dict) \
                or set(ref) != {"path", "bytes", "sha256"} \
                or not isinstance(ref.get("path"), str) \
                or ref["path"] in refs \
                or not isinstance(ref.get("bytes"), int) \
                or isinstance(ref.get("bytes"), bool) \
                or ref["bytes"] < 0 or not _is_sha256(ref.get("sha256")):
            raise ValueError(
                "REFUSED: Java mutation reality file inventory is malformed")
        refs[ref["path"]] = ref

    runs = reality.get("runs")
    if not isinstance(runs, list):
        raise ValueError("REFUSED: Java mutation reality has no run ledger")
    relevant = tuple(
        row.get("name") for row in runs
        if isinstance(row, dict) and row.get("stripped") is False)
    if relevant != _RELEVANT_REALITY_RUNS[project]:
        raise ValueError(
            "REFUSED: Java mutation reality non-stripped run set differs")
    xml_paths = []
    classpaths = []
    for run_name in relevant:
        prefix = f"runs/{run_name}/artifacts/surefire/"
        selected_xml = sorted(
            rel for rel in refs
            if rel.startswith(prefix) and rel.endswith(".xml"))
        if not selected_xml:
            raise ValueError(
                f"REFUSED: Java mutation reality run {run_name} has no XML")
        for rel in selected_xml:
            path = os.path.join(authority, "reality", *rel.split("/"))
            raw = _regular_bytes(path, f"Surefire report {rel}",
                                 maximum=_MAX_SUREFIRE_XML)
            ref = refs[rel]
            if len(raw) != ref["bytes"] \
                    or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
                raise ValueError(
                    f"REFUSED: Java mutation Surefire report changed: {rel}")
            xml_paths.append("reality/" + rel)
            classpaths.append(_surefire_classpath(raw, f"Surefire report {rel}"))
    if not classpaths or any(value.encode("utf-8") != classpaths[0].encode(
            "utf-8") for value in classpaths[1:]):
        raise ValueError(
            "REFUSED: Java reality reports disagree on java.class.path bytes")

    entries = reality_classpath_entries(classpaths[0])
    m2_by_path = _validate_m2_manifest(m2_manifest)
    jars = []
    for absolute in entries[2:]:
        if not absolute.startswith("/opt/m2/") or not absolute.endswith(".jar"):
            raise ValueError(
                f"REFUSED: Java reality classpath has a foreign entry: {absolute}")
        rel = absolute[len("/opt/m2/"):]
        if rel not in m2_by_path:
            raise ValueError(
                f"REFUSED: Java reality classpath JAR is absent from M2: {rel}")
        jars.append({"image_path": absolute, **m2_by_path[rel]})
    if not jars:
        raise ValueError("REFUSED: Java reality classpath has no Maven JARs")

    source_authority = os.path.join(authority, "source")
    source_kind, source_digest = _input_content(
        source_authority, SOURCEPATH, "sourcepath")
    if source_kind != "tree":
        raise ValueError("REFUSED: Java source authority is not one tree")
    roots = [os.path.abspath(root) for root in repo_roots]
    if not roots:
        raise ValueError("REFUSED: Java population has no worker pool roots")
    for root in roots:
        kind, digest = _input_content(root, SOURCEPATH, "sourcepath")
        if kind != "tree" or digest != source_digest:
            raise ValueError(
                "REFUSED: Java worker source differs from reviewed "
                f"src/main/java: {root}")

    try:
        actual_files = sorted(R._tree_files(authority))
    except RuntimeError as exc:
        raise ValueError(str(exc)) from exc
    source_files = [name for name in actual_files
                    if name.startswith("source/src/main/java/")]
    expected_files = sorted([*_AUTHORITY_FILES, *source_files, *xml_paths])
    if actual_files != expected_files:
        raise ValueError(
            "REFUSED: Java mutation authority subset is not exact; "
            f"missing={sorted(set(expected_files)-set(actual_files))[:3]}, "
            f"extra={sorted(set(actual_files)-set(expected_files))[:3]}")
    return {"root": authority, "release": release, "jars": jars,
            "sourcepath_sha256": source_digest,
            "image_id": reality["image_id"]}


def private_java_scratch(prefix: str, *forbidden_roots: str) -> str:
    """Create canonical host scratch outside every submitted workspace.

    This deliberately ignores TMPDIR/TEMP/TMP.  A candidate-controlled temp
    setting may point back into its own RW tree, where a lingering submitted
    process could replace an authenticated snapshot or compiled applier.
    """
    parent = "/tmp"
    if os.path.islink(parent) or not os.path.isdir(parent) \
            or os.path.realpath(parent) != parent:
        raise RuntimeError(
            "REFUSED: /tmp is not a canonical host-private scratch parent")
    roots = [os.path.realpath(os.path.abspath(root))
             for root in forbidden_roots]
    for root in roots:
        try:
            parent_contained = os.path.commonpath((root, parent)) == root
        except ValueError:
            parent_contained = False
        if parent_contained:
            raise RuntimeError(
                "REFUSED: host-private Java scratch parent is inside a "
                f"submitted workspace: {root}")
    scratch = tempfile.mkdtemp(prefix=prefix, dir=parent)
    try:
        if os.path.islink(scratch) or not os.path.isdir(scratch) \
                or os.path.realpath(scratch) != scratch:
            raise RuntimeError(
                "REFUSED: Java scratch directory is not canonical")
        for root in roots:
            try:
                contained = os.path.commonpath((root, scratch)) == root
            except ValueError:
                contained = False
            if contained:
                raise RuntimeError(
                    "REFUSED: Java scratch directory is inside a submitted "
                    f"workspace: {root}")
        return scratch
    except BaseException:                                  # noqa: BLE001
        shutil.rmtree(scratch, ignore_errors=True)
        raise


def _is_sha256(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _canonical_relative(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"REFUSED: Java {label} entry is not a path")
    normal = M.normalise_path(value)
    components = normal.split("/")
    if value != normal or value in {".", ".."} or value.startswith("/") \
            or value.startswith("../") or os.pathsep in value \
            or any(component in {"", ".", ".."}
                   for component in components):
        raise ValueError(
            f"REFUSED: Java {label} entry must be one canonical, "
            f"project-relative path without a path-list separator: {value!r}")
    return normal


def _open_input_fd(root: str, rel: str) -> int:
    """Open a contained input component-by-component with no symlink hop."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) \
        | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    fd = os.open(root, flags | directory | nofollow)
    try:
        components = rel.split("/")
        for index, component in enumerate(components):
            child_flags = flags | nofollow
            if index + 1 < len(components):
                child_flags |= directory
            child = os.open(component, child_flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def _hash_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _manifest_class_path(fd: int, label: str) -> tuple[str, ...]:
    """Read the JAR main section's ordered Class-Path tokens."""
    os.lseek(fd, 0, os.SEEK_SET)
    duplicate = os.dup(fd)
    try:
        with os.fdopen(duplicate, "rb") as raw:
            duplicate = -1
            try:
                with zipfile.ZipFile(raw) as archive:
                    # java.util.jar.JarFile accepts the conventional manifest
                    # path case-insensitively (including on a case-sensitive
                    # host filesystem).  Matching more narrowly would let a
                    # carrier JAR activate an undeclared Class-Path while our
                    # recipe validator believed none existed.
                    manifests = [info for info in archive.infolist()
                                 if info.filename.lower()
                                 == "meta-inf/manifest.mf"]
                    if not manifests:
                        return ()
                    if len(manifests) != 1:
                        raise ValueError(
                            f"REFUSED: Java {label} JAR has duplicate "
                            "META-INF/MANIFEST.MF entries")
                    info = manifests[0]
                    if info.file_size > (1 << 20):
                        raise ValueError(
                            f"REFUSED: Java {label} JAR manifest is too large")
                    payload = archive.read(info)
            except zipfile.BadZipFile:
                return ()
            except (OSError, RuntimeError, zipfile.LargeZipFile) as exc:
                raise ValueError(
                    f"REFUSED: Java {label} JAR manifest is unreadable: "
                    f"{exc}") from exc
    finally:
        if duplicate >= 0:
            os.close(duplicate)
    # Manifest continuation lines begin with one space.  Only the main
    # section controls a JAR's Class-Path expansion.
    logical: list[bytes] = []
    for line in payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n"):
        if not line:
            break
        if line.startswith(b" ") and logical:
            logical[-1] += line[1:]
        else:
            logical.append(line)
    values = []
    for line in logical:
        key, separator, value = line.partition(b":")
        if separator and key.strip().lower() == b"class-path" \
                and value.strip():
            try:
                values.append(value.strip().decode("ascii"))
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"REFUSED: Java {label} JAR manifest Class-Path is not "
                    "ASCII") from exc
    if len(values) > 1:
        raise ValueError(
            f"REFUSED: Java {label} JAR has multiple Class-Path fields")
    return tuple(values[0].split()) if values else ()


def _manifest_has_class_path(fd: int, label: str) -> bool:
    return bool(_manifest_class_path(fd, label))


def _allow_kapua_absent_manifest_classpath(
        root: str, rel: str, tokens: tuple[str, ...]) -> None:
    expected = _KAPUA_ABSENT_MANIFEST_CLASSPATHS.get(rel)
    if expected is None or tokens != expected:
        raise ValueError(
            f"REFUSED: Kapua Java classpath JAR {rel!r} has an unsupported "
            "manifest Class-Path")
    parent = os.path.dirname(rel)
    for token in tokens:
        if "/" in token or "\\" in token or ":" in token \
                or token in {"", ".", ".."}:
            raise ValueError(
                "REFUSED: Kapua JAXB manifest Class-Path token differs from "
                "the measured adjacent-name form")
        target = f"{parent}/{token}"
        _canonical_relative(target, "manifest Class-Path target")
        if os.path.lexists(os.path.join(root, target)):
            raise ValueError(
                f"REFUSED: measured-absent Kapua manifest Class-Path target "
                f"exists: {target}")


def _tree_rows(fd: int, label: str, prefix: str = "") -> list[dict]:
    rows: list[dict] = []
    try:
        names = sorted(os.listdir(fd))
    except OSError as exc:
        raise ValueError(
            f"REFUSED: cannot list Java {label} input tree: {exc}") from exc
    for name in names:
        child_rel = f"{prefix}/{name}" if prefix else name
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) \
            | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_NONBLOCK", 0)
        try:
            child = os.open(name, flags, dir_fd=fd)
        except OSError as exc:
            raise ValueError(
                f"REFUSED: Java {label} tree entry cannot be opened without "
                f"following a link: {child_rel}: {exc}") from exc
        try:
            current = os.fstat(child)
            if stat.S_ISDIR(current.st_mode):
                rows.extend(_tree_rows(child, label, child_rel))
            elif stat.S_ISREG(current.st_mode):
                rows.append({"path": child_rel, "sha256": _hash_fd(child)})
            else:
                raise ValueError(
                    f"REFUSED: Java {label} tree contains a non-regular "
                    f"entry: {child_rel}")
        finally:
            os.close(child)
    return rows


def _input_content(root: str, rel: str, label: str, *,
                   allow_kapua_absent_manifest_classpath: bool = False
                   ) -> tuple[str, str]:
    """Return ``(file|tree, digest)`` through descriptor-relative opens."""
    try:
        fd = _open_input_fd(root, rel)
    except OSError as exc:
        raise ValueError(
            f"REFUSED: Java {label} input cannot be opened without symlink "
            f"or path escape: {rel}: {exc}") from exc
    try:
        current = os.fstat(fd)
        if stat.S_ISREG(current.st_mode):
            if label == "classpath":
                manifest_classpath = _manifest_class_path(fd, label)
                if manifest_classpath:
                    if not allow_kapua_absent_manifest_classpath:
                        raise ValueError(
                            f"REFUSED: Java classpath JAR {rel!r} has a "
                            "manifest Class-Path that would load "
                            "unauthenticated inputs")
                    _allow_kapua_absent_manifest_classpath(
                        root, rel, manifest_classpath)
            return "file", _hash_fd(fd)
        if stat.S_ISDIR(current.st_mode):
            return "tree", _canonical_sha256(_tree_rows(fd, label))
        raise ValueError(
            f"REFUSED: Java {label} input is not a regular file/tree: {rel}")
    finally:
        os.close(fd)


def empty_analysis_recipe() -> dict:
    """The one authenticated spelling of three intentionally empty paths."""
    recipe = {"schema": ANALYSIS_SCHEMA, "classpath": [],
              "sourcepath": [], "module_path": []}
    recipe["digest"] = _canonical_sha256(recipe)
    return recipe


def make_analysis_recipe(repo_root: str, *,
                         classpath: Iterable[str] = (),
                         sourcepath: Iterable[str] = (),
                         module_path: Iterable[str] = (),
                         _allow_kapua_absent_manifest_classpath: bool = False
                         ) -> dict:
    """Bind project-relative javac inputs to their exact current content.

    Absolute host paths and opaque ``os.pathsep`` strings are deliberately
    not an API.  A recipe survives relocation because it names only paths
    below the project root; every consumer resolves and re-hashes those paths
    before launching javac.
    """
    root = os.path.abspath(repo_root)
    if os.path.islink(root) or not os.path.isdir(root) \
            or os.path.realpath(root) != root:
        raise ValueError(
            "REFUSED: Java analysis root must be a canonical non-symlink "
            "directory")
    recipe = {"schema": ANALYSIS_SCHEMA}
    for key, values in (("classpath", classpath),
                        ("sourcepath", sourcepath),
                        ("module_path", module_path)):
        rows = []
        seen = set()
        for raw in values:
            rel = _canonical_relative(raw, key)
            if rel in seen:
                raise ValueError(
                    f"REFUSED: Java {key} repeats project input {rel!r}")
            seen.add(rel)
            kind, digest = _input_content(
                root, rel, key,
                allow_kapua_absent_manifest_classpath=(
                    _allow_kapua_absent_manifest_classpath
                    and key == "classpath"))
            rows.append({"path": rel, "kind": kind, "sha256": digest})
        recipe[key] = rows
    recipe["digest"] = _canonical_sha256(recipe)
    return recipe


def make_module_analysis_child_recipe(
        repo_root: str, module: str, *, classpath: Iterable[str],
        module_path: Iterable[str] = ()) -> dict:
    """Build one composite-only child, including measured-absent JAXB links."""
    module = _canonical_relative(module, "module")
    return make_analysis_recipe(
        repo_root, classpath=classpath,
        sourcepath=(f"{module}/src/main/java",), module_path=module_path,
        _allow_kapua_absent_manifest_classpath=True)


def make_module_analysis_recipe(repo_root: str, modules: Iterable[dict]) -> dict:
    """Bind Kapua's complete production tree to owning-module javac recipes."""
    rows = []
    for raw in modules:
        if not isinstance(raw, dict) or set(raw) != {
                "module", "source_root", "source_files", "compiler", "recipe"}:
            raise ValueError(
                "REFUSED: Kapua Java module analysis input fields differ")
        row = dict(raw)
        row["source_files"] = list(raw["source_files"])
        row["compiler"] = dict(raw["compiler"])
        row["digest"] = _canonical_sha256(row)
        rows.append(row)
    authority = {
        "schema": MODULE_ANALYSIS_SCHEMA,
        "project": "kapua",
        "modules": rows,
    }
    authority["digest"] = _canonical_sha256(authority)
    return validate_analysis_recipe(authority, repo_root)


def stage_classpath_bundle(
        repo_root: str, sources: Iterable[str], *,
        bundle_rel: str = "var/bench_java_analysis/classpath") -> list[str]:
    """Materialise host/Maven jars as immutable project-relative inputs.

    A Maven cache location such as ``/opt/m2`` is runtime plumbing, not
    portable population identity.  This preparation seam copies selected
    regular files into an excluded project-local bundle named by order and
    content.  Only the returned relative names enter ``make_analysis_recipe``;
    the original absolute cache paths never do.  Existing exact files are
    reusable, while a conflicting byte sequence fails closed.
    """
    root = os.path.abspath(repo_root)
    if os.path.islink(root) or not os.path.isdir(root) \
            or os.path.realpath(root) != root:
        raise ValueError(
            "REFUSED: Java analysis root must be a canonical non-symlink "
            "directory")
    bundle_rel = _canonical_relative(bundle_rel, "bundle")
    if bundle_rel != "var/bench_java_analysis/classpath":
        raise ValueError(
            "REFUSED: Java analysis bundle has one benchmark-owned path: "
            "var/bench_java_analysis/classpath")
    source_list = list(sources)
    if not source_list:
        raise ValueError("REFUSED: Java classpath bundle has no inputs")

    # Authenticate every input before creating benchmark scratch.  The second
    # digest at the destination closes a source change during the copy.
    prepared = []
    seen_sources = set()
    for index, source in enumerate(source_list):
        source = os.path.abspath(source)
        if os.path.islink(source) or not os.path.isfile(source) \
                or os.path.realpath(source) != source:
            raise ValueError(
                f"REFUSED: Java classpath bundle source is not a canonical "
                f"regular file: {source}")
        if source in seen_sources:
            raise ValueError(
                f"REFUSED: Java classpath bundle repeats source: {source}")
        seen_sources.add(source)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) \
            | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_NONBLOCK", 0)
        try:
            source_fd = os.open(source, flags)
        except OSError as exc:
            raise ValueError(
                f"REFUSED: Java classpath bundle source cannot be opened "
                f"without following a link: {source}: {exc}") from exc
        try:
            if not stat.S_ISREG(os.fstat(source_fd).st_mode):
                raise ValueError(
                    "REFUSED: Java classpath bundle source changed file type")
            if _manifest_has_class_path(source_fd, "classpath bundle"):
                raise ValueError(
                    "REFUSED: Java classpath bundle source has a manifest "
                    "Class-Path that would load unauthenticated inputs")
            digest = _hash_fd(source_fd)
        finally:
            os.close(source_fd)
        basename = re.sub(r"[^A-Za-z0-9_.-]+", "_",
                          os.path.basename(source)) or "dependency.jar"
        name = f"{index:04d}-{digest[:16]}-{basename}"
        prepared.append((source, digest, name))

    # Build one component at a time so a repository-supplied `var` symlink is
    # refused before mkdir can create anything through it.
    current = root
    for component in bundle_rel.split("/"):
        current = os.path.join(current, component)
        if os.path.lexists(current):
            if os.path.islink(current) or not os.path.isdir(current) \
                    or os.path.realpath(current) != current:
                raise ValueError(
                    "REFUSED: Java analysis bundle parent is not a canonical "
                    f"directory: {current}")
        else:
            try:
                os.mkdir(current, 0o700)
            except OSError as exc:
                raise ValueError(
                    f"REFUSED: cannot create Java analysis bundle directory "
                    f"{current}: {exc}") from exc
            if os.path.islink(current) or not os.path.isdir(current) \
                    or os.path.realpath(current) != current:
                raise ValueError(
                    "REFUSED: created Java analysis bundle path is not "
                    f"canonical: {current}")
    bundle = current

    staged = []
    created = []
    try:
        for source, digest, name in prepared:
            destination = os.path.join(bundle, name)
            destination_rel = f"{bundle_rel}/{name}"
            if os.path.lexists(destination):
                try:
                    kind, actual = _input_content(
                        root, destination_rel, "classpath")
                except ValueError:
                    kind, actual = None, None
                if kind != "file" or actual != digest:
                    raise ValueError(
                        "REFUSED: Java analysis bundle destination "
                        f"conflicts: {bundle_rel}/{name}")
            else:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(destination, flags, 0o600)
                created.append(destination)
                try:
                    with open(source, "rb") as src, os.fdopen(fd, "wb") as dst:
                        fd = -1
                        shutil.copyfileobj(src, dst)
                        dst.flush()
                        os.fsync(dst.fileno())
                finally:
                    if fd >= 0:
                        os.close(fd)
                kind, actual = _input_content(
                    root, destination_rel, "classpath")
                if kind != "file" or actual != digest:
                    raise ValueError(
                        "REFUSED: staged Java classpath bundle bytes changed")
            staged.append(destination_rel)
        return staged
    except Exception:
        # A failed multi-input preparation is transactional for files this
        # invocation created.  Pre-existing authenticated bundles are never
        # removed, and cleanup never widens beyond the fixed benchmark path.
        for destination in reversed(created):
            try:
                os.unlink(destination)
            except OSError:
                pass
        for rel in ("var/bench_java_analysis/classpath",
                    "var/bench_java_analysis"):
            try:
                os.rmdir(os.path.join(root, rel))
            except OSError:
                pass
        raise


def cleanup_classpath_bundle(repo_root: str, recipe: dict) -> list[str]:
    """Remove only authenticated benchmark-owned bundle files.

    Cleanup first re-hashes the complete recipe.  A changed dependency is
    failure evidence and is never silently deleted.  Paths outside the narrow
    bundle prefix are ignored; no recursive deletion exists here.
    """
    root = os.path.abspath(repo_root)
    validate_analysis_recipe(recipe, root)
    if recipe["schema"] != ANALYSIS_SCHEMA:
        raise ValueError(
            "REFUSED: shared Kapua analysis inputs require their owning "
            "authority cleanup")
    prefix = "var/bench_java_analysis/classpath/"
    entries = [entry for entry in recipe["classpath"]
               if entry["path"].startswith(prefix)]
    removed = []
    for entry in entries:
        full = os.path.join(root, entry["path"])
        if os.path.islink(full) or not os.path.isfile(full) \
                or os.path.realpath(full) != full:
            raise ValueError(
                f"REFUSED: Java analysis cleanup target is not the exact "
                f"regular bundle file: {entry['path']}")
        os.unlink(full)
        removed.append(entry["path"])
    # Remove only now-empty benchmark-owned directories, never `var` itself.
    for rel in ("var/bench_java_analysis/classpath",
                "var/bench_java_analysis"):
        directory = os.path.join(root, rel)
        try:
            os.rmdir(directory)
        except FileNotFoundError:
            pass
        except OSError:
            # Another explicitly staged bundle entry may remain.  Leaving the
            # directory is safer than widening cleanup.
            pass
    return removed


def _validate_single_analysis_recipe(recipe: dict,
                                     repo_root: Optional[str] = None, *,
                                     allow_kapua_absent_manifest_classpath:
                                     bool = False) -> dict:
    """Validate structure/digest and, when rooted, every input's live bytes."""
    if not isinstance(recipe, dict) or set(recipe) != _ANALYSIS_KEYS:
        missing = sorted(_ANALYSIS_KEYS - set(recipe or {})) \
            if isinstance(recipe, dict) else sorted(_ANALYSIS_KEYS)
        unknown = sorted(set(recipe) - _ANALYSIS_KEYS) \
            if isinstance(recipe, dict) else []
        raise ValueError(
            f"REFUSED: Java analysis recipe fields differ; missing={missing}, "
            f"unknown={unknown}")
    if recipe.get("schema") != ANALYSIS_SCHEMA:
        raise ValueError("REFUSED: unsupported Java analysis recipe schema")
    if not _is_sha256(recipe.get("digest")) \
            or recipe["digest"] != _canonical_sha256(
                {key: value for key, value in recipe.items()
                 if key != "digest"}):
        raise ValueError("REFUSED: Java analysis recipe digest does not recompute")
    root = None
    if repo_root is not None:
        root = os.path.abspath(repo_root)
        if os.path.islink(root) or not os.path.isdir(root) \
                or os.path.realpath(root) != root:
            raise ValueError(
                "REFUSED: Java analysis root must be a canonical non-symlink "
                "directory")
    for key in ("classpath", "sourcepath", "module_path"):
        entries = recipe[key]
        if not isinstance(entries, list):
            raise ValueError(f"REFUSED: Java analysis {key} is not an array")
        seen = set()
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) \
                    or set(entry) != _ANALYSIS_ENTRY_KEYS:
                raise ValueError(
                    f"REFUSED: Java analysis {key} entry #{index} fields differ")
            rel = _canonical_relative(entry.get("path"), key)
            if rel in seen:
                raise ValueError(
                    f"REFUSED: Java analysis {key} repeats input {rel!r}")
            seen.add(rel)
            if entry.get("kind") not in {"file", "tree"} \
                    or not _is_sha256(entry.get("sha256")):
                raise ValueError(
                    f"REFUSED: Java analysis {key} entry #{index} has invalid "
                    "kind/digest")
            if root is not None:
                kind, digest = _input_content(
                    root, rel, key,
                    allow_kapua_absent_manifest_classpath=(
                        allow_kapua_absent_manifest_classpath
                        and key == "classpath"))
                if kind != entry["kind"] or digest != entry["sha256"]:
                    raise ValueError(
                        f"REFUSED: Java analysis {key} input {rel!r} is stale: "
                        f"live {kind}/{digest}, recipe "
                        f"{entry['kind']}/{entry['sha256']}")
    return recipe


def _validate_module_analysis_recipe(recipe: dict,
                                     repo_root: Optional[str] = None) -> dict:
    if not isinstance(recipe, dict) or set(recipe) != _MODULE_ANALYSIS_KEYS:
        missing = sorted(_MODULE_ANALYSIS_KEYS - set(recipe or {})) \
            if isinstance(recipe, dict) else sorted(_MODULE_ANALYSIS_KEYS)
        unknown = sorted(set(recipe) - _MODULE_ANALYSIS_KEYS) \
            if isinstance(recipe, dict) else []
        raise ValueError(
            "REFUSED: Kapua Java module analysis fields differ; "
            f"missing={missing}, unknown={unknown}")
    if recipe.get("schema") != MODULE_ANALYSIS_SCHEMA \
            or recipe.get("project") != "kapua":
        raise ValueError("REFUSED: unsupported Kapua Java module authority")
    if not _is_sha256(recipe.get("digest")) \
            or recipe["digest"] != _canonical_sha256(
                {key: value for key, value in recipe.items()
                 if key != "digest"}):
        raise ValueError(
            "REFUSED: Kapua Java module authority digest does not recompute")
    rows = recipe.get("modules")
    if not isinstance(rows, list) or not rows:
        raise ValueError(
            "REFUSED: Kapua Java module authority has no module rows")
    roots = []
    modules = set()
    files = set()
    inputs: dict[str, tuple[str, str]] = {}
    compilers: dict[str, tuple] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) \
                or set(row) != _MODULE_ANALYSIS_ROW_KEYS:
            raise ValueError(
                f"REFUSED: Kapua Java module row #{index} fields differ")
        if not _is_sha256(row.get("digest")) \
                or row["digest"] != _canonical_sha256(
                    {key: value for key, value in row.items()
                     if key != "digest"}):
            raise ValueError(
                f"REFUSED: Kapua Java module row #{index} digest does not "
                "recompute")
        module = _canonical_relative(row.get("module"), "module")
        source_root = _canonical_relative(
            row.get("source_root"), "module source root")
        if source_root != f"{module}/src/main/java":
            raise ValueError(
                f"REFUSED: Kapua Java module {module!r} has another "
                "production source root")
        if module in modules or source_root in roots:
            raise ValueError(
                f"REFUSED: Kapua Java module authority repeats {module!r}")
        modules.add(module)
        roots.append(source_root)
        source_files = row.get("source_files")
        if not isinstance(source_files, list) or not source_files \
                or source_files != sorted(source_files) \
                or len(set(source_files)) != len(source_files):
            raise ValueError(
                f"REFUSED: Kapua Java module {module!r} source files are "
                "empty, repeated, or not sorted")
        for raw in source_files:
            rel = _canonical_relative(raw, "module source file")
            if not rel.endswith(".java") \
                    or not rel.startswith(source_root + "/"):
                raise ValueError(
                    f"REFUSED: Kapua Java source {rel!r} is outside its "
                    "owning production root")
            if rel in files:
                raise ValueError(
                    f"REFUSED: Kapua Java source has multiple owners: {rel}")
            files.add(rel)
        compiler = row.get("compiler")
        if not isinstance(compiler, dict) \
                or set(compiler) != _MODULE_COMPILER_KEYS \
                or compiler.get("java_home") not in _MODULE_JAVA_HOMES \
                or not isinstance(compiler.get("parser"), str) \
                or not compiler["parser"].strip() \
                or compiler.get("encoding") != "UTF-8":
            raise ValueError(
                f"REFUSED: Kapua Java module {module!r} compiler binding "
                "is incomplete or unsupported")
        source = compiler.get("source")
        target = compiler.get("target")
        release = compiler.get("release")
        level = re.compile(r"[1-9][0-9]*(?:\.[0-9]+)*\Z")
        source_target = (isinstance(source, str) and level.fullmatch(source)
                         and isinstance(target, str)
                         and level.fullmatch(target) and release is None)
        release_only = (source is None and target is None
                        and isinstance(release, str)
                        and level.fullmatch(release))
        if not source_target and not release_only:
            raise ValueError(
                f"REFUSED: Kapua Java module {module!r} must bind exactly "
                "source/target or release")
        if compiler["java_home"] == "/opt/java/openjdk8" \
                and release is not None:
            raise ValueError(
                "REFUSED: Kapua JDK 8 compiler cannot accept --release")
        for key in ("runtime_executable_sha256",
                    "compiler_executable_sha256"):
            if not _is_sha256(compiler.get(key)):
                raise ValueError(
                    f"REFUSED: Kapua Java module {module!r} has no exact "
                    f"{key}")
        tools_digest = compiler.get("tools_jar_sha256")
        if tools_digest is not None and not _is_sha256(tools_digest):
            raise ValueError(
                f"REFUSED: Kapua Java module {module!r} has invalid "
                "tools.jar identity")
        if (compiler["java_home"] == "/opt/java/openjdk8") \
                != (tools_digest is not None):
            raise ValueError(
                f"REFUSED: Kapua Java module {module!r} tools.jar binding "
                "does not match its supported toolchain")
        toolchain = tuple(compiler[key] for key in (
            "parser", "runtime_executable_sha256",
            "compiler_executable_sha256", "tools_jar_sha256"))
        previous_compiler = compilers.setdefault(
            compiler["java_home"], toolchain)
        if previous_compiler != toolchain:
            raise ValueError(
                f"REFUSED: Kapua Java home {compiler['java_home']!r} has "
                "conflicting compiler identities")
        child = _validate_single_analysis_recipe(
            row.get("recipe"), repo_root,
            allow_kapua_absent_manifest_classpath=True)
        expected_sourcepath = [{
            "path": source_root,
            "kind": "tree",
            "sha256": child["sourcepath"][0]["sha256"],
        }] if len(child["sourcepath"]) == 1 else None
        if child["sourcepath"] != expected_sourcepath:
            raise ValueError(
                f"REFUSED: Kapua Java module {module!r} sourcepath is not "
                "its one owning production root")
        expected_output = f"{module}/target/classes"
        if not child["classpath"] \
                or child["classpath"][0].get("path") != expected_output \
                or child["classpath"][0].get("kind") != "tree":
            raise ValueError(
                f"REFUSED: Kapua Java module {module!r} classpath does not "
                "start with its compiled output")
        for key in ("classpath", "sourcepath", "module_path"):
            for entry in child[key]:
                identity = (entry["kind"], entry["sha256"])
                previous = inputs.setdefault(entry["path"], identity)
                if previous != identity:
                    raise ValueError(
                        "REFUSED: Kapua Java modules bind conflicting bytes "
                        f"for {entry['path']!r}")
        if repo_root is not None:
            root = os.path.abspath(repo_root)
            fd = _open_input_fd(root, source_root)
            try:
                actual = sorted(
                    f"{source_root}/{entry['path']}"
                    for entry in _tree_rows(fd, "module source root")
                    if entry["path"].endswith(".java"))
            finally:
                os.close(fd)
            if actual != source_files:
                raise ValueError(
                    f"REFUSED: Kapua Java module {module!r} source-file "
                    "membership differs from live original sources")
    if roots != sorted(roots):
        raise ValueError(
            "REFUSED: Kapua Java module rows are not ordered by source root")
    return recipe


def validate_analysis_recipe(recipe: dict, repo_root: Optional[str] = None
                             ) -> dict:
    """Validate one javac recipe or Kapua's per-module composite authority."""
    if isinstance(recipe, dict) \
            and recipe.get("schema") == MODULE_ANALYSIS_SCHEMA:
        return _validate_module_analysis_recipe(recipe, repo_root)
    return _validate_single_analysis_recipe(recipe, repo_root)



def validate_module_analysis_sources(repo_root: str, authority: dict) -> None:
    """Bind a mutation worker's original sources to the captured compiler tree.

    Kapua runtime class trees contain worker settings and need not equal the
    compiler capture. Only original production sources must agree on both
    roots; all compiler inputs are authenticated separately by the recipe.
    """
    validate_analysis_recipe(authority)
    if authority["schema"] != MODULE_ANALYSIS_SCHEMA:
        raise ValueError("REFUSED: separate Java analysis root requires Kapua module authority")
    root = os.path.abspath(repo_root)
    if os.path.realpath(root) != root or not os.path.isdir(root):
        raise ValueError("REFUSED: Java worker source root is not canonical")
    for row in authority["modules"]:
        for entry in row["recipe"]["sourcepath"]:
            if _input_content(root, entry["path"], "sourcepath") != (
                    entry["kind"], entry["sha256"]):
                raise ValueError(
                    "REFUSED: worker production source differs from Java analysis "
                    "authority: " + entry["path"])


def analysis_recipe_for_path(authority: dict, source_path: str) -> dict:
    """Return the one javac recipe that owns an original source file."""
    validate_analysis_recipe(authority)
    rel = _canonical_relative(source_path, "analysis source")
    if authority["schema"] == ANALYSIS_SCHEMA:
        if not analysis_path_covers(authority, rel):
            raise ValueError(
                f"REFUSED: Java source {rel!r} is outside analysis authority")
        return authority
    matches = [row["recipe"] for row in authority["modules"]
               if rel in row["source_files"]]
    if len(matches) != 1:
        raise ValueError(
            f"REFUSED: Java source {rel!r} has {len(matches)} module recipes")
    return matches[0]


def analysis_compiler_for_path(authority: dict, source_path: str
                              ) -> Optional[dict]:
    """Return Kapua's exact compiler binding; legacy recipes need no selector."""
    validate_analysis_recipe(authority)
    if authority["schema"] == ANALYSIS_SCHEMA:
        return None
    rel = _canonical_relative(source_path, "analysis source")
    matches = [row["compiler"] for row in authority["modules"]
               if rel in row["source_files"]]
    if len(matches) != 1:
        raise ValueError(
            f"REFUSED: Java source {rel!r} has {len(matches)} compilers")
    return matches[0]


def module_engine_toolchain(authority: dict) -> dict:
    """Select the engine compiler shared by enumeration and audit evidence.

    JDK 8 engine classes also run on the newer module JVMs. When the authority
    contains only JDK 17, that is the engine compiler too. Module parsing still
    uses each source file's own compiler and language-level flags.
    """
    _validate_module_analysis_recipe(authority)
    toolchains = {row["compiler"]["java_home"]: row["compiler"]
                  for row in authority["modules"]}
    home = ("/opt/java/openjdk8" if "/opt/java/openjdk8" in toolchains
            else "/opt/java/openjdk")
    return toolchains[home]


def module_analysis_parser(authority: dict) -> str:
    """Stable manifest parser identity for a heterogeneous Kapua authority."""
    validate_analysis_recipe(authority)
    if authority["schema"] != MODULE_ANALYSIS_SCHEMA:
        raise ValueError("REFUSED: Java authority is not a Kapua module map")
    return f"kapua-module-javac/1 sha256:{authority['digest']}"


def analysis_compiler_argv(authority: dict, source_path: str) -> list[str]:
    """Return only the measured language-level flags accepted by Mutate.java."""
    compiler = analysis_compiler_for_path(authority, source_path)
    if compiler is None:
        return []
    if compiler["release"] is not None:
        return ["--release-level", compiler["release"]]
    return ["--source-level", compiler["source"],
            "--target-level", compiler["target"]]


def _validated_compiler_argv(values: Iterable[str]) -> list[str]:
    argv = list(values)
    level = r"[1-9][0-9]*(?:\.[0-9]+)*"
    if argv and not (
            (len(argv) == 2 and argv[0] == "--release-level"
             and re.fullmatch(level, argv[1]))
            or (len(argv) == 4 and argv[0] == "--source-level"
                and argv[2] == "--target-level"
                and re.fullmatch(level, argv[1])
                and re.fullmatch(level, argv[3]))):
        raise ValueError("REFUSED: unsupported Java compiler option binding")
    return argv


def analysis_binding_for_path(authority: dict, source_path: str) -> dict:
    """Validate once and return one source's recipe, compiler and safe flags."""
    validate_analysis_recipe(authority)
    rel = _canonical_relative(source_path, "analysis source")
    if authority["schema"] == ANALYSIS_SCHEMA:
        if not analysis_path_covers(authority, rel):
            raise ValueError(
                f"REFUSED: Java source {rel!r} is outside analysis authority")
        return {"recipe": authority, "compiler": None, "compiler_argv": [],
                "allow_kapua_absent_manifest_classpath": False}
    rows = [row for row in authority["modules"]
            if rel in row["source_files"]]
    if len(rows) != 1:
        raise ValueError(
            f"REFUSED: Java source {rel!r} has {len(rows)} module bindings")
    compiler = rows[0]["compiler"]
    compiler_argv = (["--release-level", compiler["release"]]
                     if compiler["release"] is not None else
                     ["--source-level", compiler["source"],
                      "--target-level", compiler["target"]])
    return {"recipe": rows[0]["recipe"], "compiler": compiler,
            "compiler_argv": compiler_argv,
            "allow_kapua_absent_manifest_classpath": True}


def module_analysis_bindings(authority: dict) -> dict[str, dict]:
    """Validate once and index every original Kapua source for hot paths."""
    validate_analysis_recipe(authority)
    if authority["schema"] != MODULE_ANALYSIS_SCHEMA:
        raise ValueError("REFUSED: Java authority is not a Kapua module map")
    bindings = {}
    for row in authority["modules"]:
        compiler = row["compiler"]
        compiler_argv = (["--release-level", compiler["release"]]
                         if compiler["release"] is not None else
                         ["--source-level", compiler["source"],
                          "--target-level", compiler["target"]])
        binding = {"recipe": row["recipe"], "compiler": compiler,
                   "compiler_argv": compiler_argv,
                   "allow_kapua_absent_manifest_classpath": True}
        for source in row["source_files"]:
            bindings[source] = binding
    return bindings


def _analysis_recipes(authority: dict) -> list[dict]:
    validate_analysis_recipe(authority)
    if authority["schema"] == ANALYSIS_SCHEMA:
        return [authority]
    return [row["recipe"] for row in authority["modules"]]


def _copy_regular_fd(source_fd: int, destination: str) -> None:
    os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    out = os.open(destination, flags, 0o600)
    try:
        os.lseek(source_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source_fd, 1 << 20)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(out, view)
                view = view[written:]
        os.fsync(out)
    finally:
        os.close(out)


def _copy_tree_fd(source_fd: int, destination: str, label: str) -> None:
    os.makedirs(destination, mode=0o700, exist_ok=True)
    try:
        names = sorted(os.listdir(source_fd))
    except OSError as exc:
        raise ValueError(
            f"REFUSED: cannot snapshot Java {label} tree: {exc}") from exc
    for name in names:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) \
            | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_NONBLOCK", 0)
        try:
            child = os.open(name, flags, dir_fd=source_fd)
        except OSError as exc:
            raise ValueError(
                f"REFUSED: cannot snapshot Java {label} entry {name!r} "
                f"without following a link: {exc}") from exc
        try:
            current = os.fstat(child)
            target = os.path.join(destination, name)
            if stat.S_ISDIR(current.st_mode):
                _copy_tree_fd(child, target, label)
            elif stat.S_ISREG(current.st_mode):
                _copy_regular_fd(child, target)
            else:
                raise ValueError(
                    f"REFUSED: Java {label} snapshot encountered a "
                    f"non-regular entry {name!r}")
        finally:
            os.close(child)


def _copy_analysis_entry(root: str, entry: dict, destination: str,
                         label: str) -> None:
    try:
        source = _open_input_fd(root, entry["path"])
    except OSError as exc:
        raise ValueError(
            f"REFUSED: cannot snapshot Java {label} input "
            f"{entry['path']!r}: {exc}") from exc
    try:
        current = os.fstat(source)
        if entry["kind"] == "file" and stat.S_ISREG(current.st_mode):
            _copy_regular_fd(source, destination)
        elif entry["kind"] == "tree" and stat.S_ISDIR(current.st_mode):
            _copy_tree_fd(source, destination, label)
        else:
            raise ValueError(
                f"REFUSED: Java {label} input {entry['path']!r} changed "
                "file/tree kind while snapshotting")
    finally:
        os.close(source)


def _require_snapshot_sources(snapshot: str, recipe: dict,
                              required_sources: Iterable[str]) -> None:
    """Prove each mutant target is a regular member of the copied authority."""
    seen = set()
    for raw in required_sources:
        rel = _canonical_relative(raw, "mutant source")
        if rel in seen:
            continue
        seen.add(rel)
        if not rel.lower().endswith(".java") \
                or not analysis_path_covers(recipe, rel):
            raise ValueError(
                f"REFUSED: Java mutant file {rel!r} is outside its "
                "authenticated sourcepath or is not a .java source")
        try:
            fd = _open_input_fd(snapshot, rel)
        except OSError as exc:
            raise ValueError(
                f"REFUSED: Java mutant file {rel!r} is not present in its "
                f"authenticated sourcepath snapshot: {exc}") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError(
                    f"REFUSED: Java mutant file {rel!r} is not a regular "
                    "member of its authenticated sourcepath snapshot")
        finally:
            os.close(fd)


@contextmanager
def analysis_snapshot(repo_root: str, recipe: dict, *,
                      required_sources: Iterable[str] = ()):
    """Yield a host-private byte-authenticated root used by javac.

    Pre/post pathname hashes cannot exclude an ABA dependency swap.  Every
    consumer therefore receives private copies outside the submitted
    workspace, and those copies are re-hashed both before and after use.  A
    Docker campaign exposes this root only to a short-lived analysis container
    through a read-only bind mount; it is never projected into the persistent
    candidate container's read-write workspace.
    """
    root = os.path.abspath(repo_root)
    validate_analysis_recipe(recipe)
    if os.path.islink(root) or not os.path.isdir(root) \
            or os.path.realpath(root) != root:
        raise ValueError(
            "REFUSED: Java analysis root must be a canonical non-symlink "
            "directory")
    scratch = private_java_scratch("r2t_java_analysis_", root)
    snapshot = os.path.join(scratch, "root")
    os.mkdir(snapshot, 0o700)
    try:
        # Parent entries first make overlapping authorities deterministic; a
        # child already copied by its parent is authenticated independently by
        # the final recipe validation.
        entries: list[tuple[str, dict]] = []
        for child in _analysis_recipes(recipe):
            for key in ("classpath", "sourcepath", "module_path"):
                entries.extend((key, entry) for entry in child[key])
        entries.sort(key=lambda item: (
            len(item[1]["path"].split("/")), item[1]["path"], item[0]))
        for key, entry in entries:
            destination = os.path.join(snapshot, entry["path"])
            if os.path.lexists(destination):
                continue
            _copy_analysis_entry(root, entry, destination, key)
        validate_analysis_recipe(recipe, snapshot)
        _require_snapshot_sources(snapshot, recipe, required_sources)
        yield snapshot
        # javac must be a reader of the authority, never its next producer.
        validate_analysis_recipe(recipe, snapshot)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def analysis_path_covers(recipe: dict, rel: str) -> bool:
    """Whether an enumerated source path lives in authenticated sourcepath."""
    rel = _canonical_relative(rel, "enumeration")
    if recipe.get("schema") == MODULE_ANALYSIS_SCHEMA:
        return sum(rel in row["source_files"]
                   for row in recipe["modules"]) == 1
    for entry in recipe["sourcepath"]:
        base = entry["path"]
        if rel == base or (entry["kind"] == "tree"
                           and rel.startswith(base + "/")):
            return True
    return False


def resolve_analysis_inputs(repo_root: str, recipe: dict, *,
                            runtime_root: Optional[str] = None,
                            source_path: Optional[str] = None
                            ) -> dict[str, str]:
    """Authenticate then resolve the exact three javac path-list values."""
    root = os.path.abspath(repo_root)
    validate_analysis_recipe(recipe, root)
    if recipe["schema"] == MODULE_ANALYSIS_SCHEMA:
        if source_path is None:
            raise ValueError(
                "REFUSED: Kapua Java analysis requires an owning source path")
        recipe = analysis_recipe_for_path(recipe, source_path)
    runtime = os.path.abspath(runtime_root) if runtime_root is not None else root
    resolved = {}
    for key in ("classpath", "sourcepath", "module_path"):
        paths = [os.path.join(runtime, entry["path"])
                 for entry in recipe[key]]
        if not paths and key in _EMPTY_PATH_NAMES:
            host_empty = os.path.join(root, _EMPTY_PATH_NAMES[key])
            if os.path.lexists(host_empty):
                raise ValueError(
                    f"REFUSED: Java empty-{key} sentinel exists: "
                    f"{_EMPTY_PATH_NAMES[key]}")
            paths = [os.path.join(runtime, _EMPTY_PATH_NAMES[key])]
        resolved[key] = os.pathsep.join(paths)
    return resolved


def snapshot_analysis_inputs(snapshot_root: str, recipe: dict, *,
                             runtime_root: Optional[str] = None,
                             source_path: Optional[str] = None,
                             allow_kapua_absent_manifest_classpath: bool = False
                             ) -> dict[str, str]:
    """Resolve a root already yielded by ``analysis_snapshot``.

    The context authenticates the full tree before yielding and again on
    exit.  Re-hashing that same private tree for every mutant would turn one
    shard into O(mutants × dependency-bytes) I/O without adding a new
    authority boundary.
    """
    if allow_kapua_absent_manifest_classpath:
        _validate_single_analysis_recipe(
            recipe, allow_kapua_absent_manifest_classpath=True)
    else:
        validate_analysis_recipe(recipe)
    if recipe["schema"] == MODULE_ANALYSIS_SCHEMA:
        if source_path is None:
            raise ValueError(
                "REFUSED: Kapua Java analysis requires an owning source path")
        recipe = analysis_recipe_for_path(recipe, source_path)
    root = os.path.abspath(snapshot_root)
    if os.path.islink(root) or not os.path.isdir(root) \
            or os.path.realpath(root) != root:
        raise ValueError(
            "REFUSED: Java analysis snapshot root is not canonical")
    runtime = os.path.abspath(runtime_root) if runtime_root is not None else root
    resolved = {}
    for key in ("classpath", "sourcepath", "module_path"):
        paths = [os.path.join(runtime, entry["path"])
                 for entry in recipe[key]]
        if not paths and key in _EMPTY_PATH_NAMES:
            host_empty = os.path.join(root, _EMPTY_PATH_NAMES[key])
            if os.path.lexists(host_empty):
                raise ValueError(
                    f"REFUSED: Java empty-{key} sentinel exists in snapshot")
            paths = [os.path.join(runtime, _EMPTY_PATH_NAMES[key])]
        resolved[key] = os.pathsep.join(paths)
    return resolved


def analysis_argv(repo_root: str, recipe: dict, *,
                  runtime_root: Optional[str] = None,
                  source_path: Optional[str] = None) -> list[str]:
    resolved = resolve_analysis_inputs(
        repo_root, recipe, runtime_root=runtime_root,
        source_path=source_path)
    return ["--classpath", resolved["classpath"],
            "--sourcepath", resolved["sourcepath"],
            "--module-path", resolved["module_path"]]


def revalidate_analysis_inputs(repo_root: str, authority: dict) -> dict:
    """Re-hash a whole authority and preserve empty-path sentinel refusal."""
    root = os.path.abspath(repo_root)
    validate_analysis_recipe(authority, root)
    if authority["schema"] == ANALYSIS_SCHEMA:
        resolve_analysis_inputs(root, authority)
        return authority
    children = _analysis_recipes(authority)
    for key, sentinel in _EMPTY_PATH_NAMES.items():
        if any(not child[key] for child in children) \
                and os.path.lexists(os.path.join(root, sentinel)):
            raise ValueError(
                f"REFUSED: Java empty-{key} sentinel exists: {sentinel}")
    return authority


def applier():
    """The Java source applier at the established campaign seam."""
    from ..bench.mutation_run import Applier
    return Applier(
        source="Mutate.java",
        rel="var/bench_mutate/Mutate.java",
        interpreter="java",
        entrypoint="Mutate",
        classes_rel="var/bench_mutate/classes",
    )


def _tool(name: str, explicit: Optional[str] = None) -> str:
    value = explicit or shutil.which(name)
    if not value:
        raise RuntimeError(f"REFUSED: {name} is required for Java mutation")
    return os.path.abspath(value)


def _tools_jar(javac: str) -> Optional[str]:
    """Return JDK 8's tools.jar when present (modular JDKs need no entry)."""
    candidate = os.path.normpath(
        os.path.join(os.path.dirname(os.path.realpath(javac)), "..", "lib",
                     "tools.jar"))
    return candidate if os.path.isfile(candidate) else None


def compile_engine(classes: str, *, source: str = JAVA_SOURCE,
                   javac: Optional[str] = None) -> tuple[str, Optional[str]]:
    """Compile the dependency-free producer and return ``(javac, tools.jar)``.

    Some vendor JDK 8 launchers do not implicitly expose ``tools.jar`` while
    compiling code that imports ``com.sun.source``.  Supplying their own jar is
    deterministic and still entirely in-JDK; modular JDK 9+ simply omits it.
    """
    javac_bin = _tool("javac", javac)
    tools_jar = _tools_jar(javac_bin)
    os.makedirs(classes, exist_ok=True)
    argv = [javac_bin]
    if tools_jar:
        argv += ["-classpath", tools_jar]
    argv += ["-proc:none", "-d", classes, source]
    cp = subprocess.run(
        argv, capture_output=True, text=True, timeout=180,
        env=sanitised_java_env())
    if cp.returncode != 0:
        raise RuntimeError(
            "REFUSED: compiling r2t-mutate-java failed "
            f"(rc={cp.returncode}):\n{(cp.stderr or cp.stdout)[-2000:]}")
    return javac_bin, tools_jar


def _runtime_classpath(classes: str, tools_jar: Optional[str]) -> str:
    return classes + ((os.pathsep + tools_jar) if tools_jar else "")


def java_sidecar_shell_prefix(workspace_runtime: str, *,
                              java_home: Optional[str] = None) -> str:
    """Validate and select image-owned Java tools before mounting RW input."""
    workspace = os.path.normpath(workspace_runtime)
    if not os.path.isabs(workspace) or workspace == "/" \
            or "\n" in workspace or "\r" in workspace:
        raise ValueError(
            "REFUSED: Java sidecar workspace runtime must be a safe absolute "
            "non-root path")
    if java_home is not None and java_home not in _MODULE_JAVA_HOMES:
        raise ValueError("REFUSED: unsupported image-owned Java home")
    return (
        "set -eu; "
        "unset " + " ".join(AMBIENT_JAVA_ENV_KEYS) + "; "
        + (("JAVA_HOME=" + shlex.quote(java_home) + "; export JAVA_HOME; ")
           if java_home is not None else "")
        + "r2t_workspace=" + shlex.quote(workspace) + "; "
        "case \"${JAVA_HOME:-}\" in /*) ;; *) "
        "echo 'REFUSED: JAVA_HOME is not absolute' >&2; exit 96;; esac; "
        "if ! r2t_java_home=$(CDPATH= cd \"$JAVA_HOME\" 2>/dev/null "
        "&& pwd -P); then echo 'REFUSED: JAVA_HOME is unavailable' >&2; "
        "exit 96; fi; "
        "if [ \"$r2t_java_home\" != \"$JAVA_HOME\" ]; then "
        "echo 'REFUSED: JAVA_HOME is not canonical' >&2; exit 96; fi; "
        "case \"$JAVA_HOME/\" in \"$r2t_workspace/\"*) "
        "echo 'REFUSED: JAVA_HOME overlaps the RW workspace' >&2; "
        "exit 96;; esac; "
        "case \"$r2t_workspace/\" in \"$JAVA_HOME/\"*) "
        "echo 'REFUSED: RW workspace overlaps JAVA_HOME' >&2; "
        "exit 96;; esac; "
        "if ! r2t_java_bin=$(CDPATH= cd \"$JAVA_HOME/bin\" 2>/dev/null "
        "&& pwd -P); then echo 'REFUSED: JAVA_HOME/bin is unavailable' >&2; "
        "exit 96; fi; "
        "if [ \"$r2t_java_bin\" != \"$JAVA_HOME/bin\" ]; then "
        "echo 'REFUSED: JAVA_HOME/bin is not canonical' >&2; exit 96; fi; "
        "for r2t_java_tool in java javac; do "
        "r2t_java_path=\"$r2t_java_bin/$r2t_java_tool\"; "
        "if [ ! -f \"$r2t_java_path\" ] || [ ! -x \"$r2t_java_path\" ] "
        "|| [ -L \"$r2t_java_path\" ]; then "
        "echo \"REFUSED: $r2t_java_tool is not a canonical image-owned "
        "executable\" >&2; exit 96; fi; done; ")


def toolchain_probe_command(workspace_runtime: str, *,
                            java_home: Optional[str] = None) -> str:
    """Identify and hash the image-owned Java tools in one sidecar."""
    return (
        java_sidecar_shell_prefix(workspace_runtime, java_home=java_home)
        + f"printf '%s\\n' {TOOLCHAIN_JAVAC_MARKER}; "
        "\"$JAVA_HOME/bin/javac\" -version 2>&1; "
        f"printf '%s\\n' {TOOLCHAIN_JAVA_MARKER}; "
        "\"$JAVA_HOME/bin/java\" -XshowSettings:properties -version 2>&1; "
        + "if ! command -v sha256sum >/dev/null 2>&1; then "
        "echo 'REFUSED: image has no sha256sum' >&2; exit 96; fi; "
        f"printf '%s\\n' {TOOLCHAIN_JAVA_SHA_MARKER}; "
        "sha256sum \"$JAVA_HOME/bin/java\"; "
        f"printf '%s\\n' {TOOLCHAIN_JAVAC_SHA_MARKER}; "
        "sha256sum \"$JAVA_HOME/bin/javac\"; "
        f"printf '%s\\n' {TOOLCHAIN_TOOLS_JAR_SHA_MARKER}; "
        "if [ -f \"$JAVA_HOME/lib/tools.jar\" ] "
        "&& [ ! -L \"$JAVA_HOME/lib/tools.jar\" ]; then "
        "sha256sum \"$JAVA_HOME/lib/tools.jar\"; else printf 'none\\n'; fi")


def parse_toolchain_hash_probe(output: str) -> dict[str, Optional[str]]:
    """Read the three fixed hash records emitted by the image sidecar."""
    def digest(marker: str, label: str, *, optional=False) -> Optional[str]:
        match = re.search(
            r"(?m)^" + re.escape(marker)
            + r"\r?\n(none|[0-9a-f]{64}\s+\S+)\r?$", output)
        if output.count(marker) != 1 or match is None \
                or (match.group(1) == "none" and not optional):
            raise RuntimeError(
                f"REFUSED: isolated Java {label} hash is malformed")
        return (None if match.group(1) == "none"
                else match.group(1).split()[0])

    return {
        "runtime_executable_sha256": digest(
            TOOLCHAIN_JAVA_SHA_MARKER, "runtime"),
        "compiler_executable_sha256": digest(
            TOOLCHAIN_JAVAC_SHA_MARKER, "compiler"),
        "tools_jar_sha256": digest(
            TOOLCHAIN_TOOLS_JAR_SHA_MARKER, "tools.jar", optional=True),
    }


def validate_module_toolchains(authority: dict, runner, *,
                               timeout: int = 120) -> dict[str, dict]:
    """Probe each compiler selected by a Kapua authority in its pinned image."""
    validate_analysis_recipe(authority)
    if authority["schema"] != MODULE_ANALYSIS_SCHEMA:
        raise ValueError("REFUSED: Java authority is not a Kapua module map")
    probe = getattr(runner, "probe_isolated_java_toolchain", None)
    if not callable(probe):
        raise ValueError(
            "REFUSED: Kapua Java authority requires isolated toolchain probes")
    observed = {}
    for row in authority["modules"]:
        compiler = row["compiler"]
        home = compiler["java_home"]
        toolchain = {key: compiler[key] for key in (
            "java_home", "parser", "runtime_executable_sha256",
            "compiler_executable_sha256", "tools_jar_sha256")}
        if home in observed:
            if observed[home] != toolchain:
                raise ValueError(
                    f"REFUSED: Kapua Java home {home!r} has conflicting "
                    "compiler bindings")
            continue
        cp = probe(timeout=timeout, java_home=home)
        if cp.returncode != 0:
            raise ValueError(
                f"REFUSED: Kapua Java toolchain probe failed for {home!r} "
                f"(rc={cp.returncode}): "
                f"{(cp.stderr or cp.stdout or '')[-500:]}")
        output = (cp.stdout or "") + "\n" + (cp.stderr or "")
        parser = parse_toolchain_probe(
            output, expected_parser=compiler["parser"])
        hashes = parse_toolchain_hash_probe(output)
        expected_hashes = {key: compiler[key] for key in hashes}
        if hashes != expected_hashes:
            raise ValueError(
                f"REFUSED: Kapua Java toolchain bytes differ for {home!r}")
        observed[home] = dict(toolchain, parser=parser)
    return observed


def _parser_identity_from_settings(text: str) -> str:
    def prop(name: str) -> Optional[str]:
        match = re.search(r"(?m)^\s*" + re.escape(name)
                          + r"\s*=\s*(.*?)\s*$", text)
        return match.group(1) if match else None

    version = prop("java.version")
    vendor = prop("java.vendor")
    runtime = prop("java.runtime.version")
    if not version or not vendor or not runtime:
        raise RuntimeError(
            "REFUSED: cannot identify the Java runtime that will host javac")
    return f"javac {version} [{vendor}; runtime={runtime}]"


def parse_toolchain_probe(output: str, *, expected_parser: Optional[str] = None
                          ) -> str:
    """Validate one image's javac/java agreement and optional manifest pin."""
    if not isinstance(output, str) \
            or output.count(TOOLCHAIN_JAVAC_MARKER) != 1 \
            or output.count(TOOLCHAIN_JAVA_MARKER) != 1:
        raise RuntimeError(
            "REFUSED: isolated Java toolchain probe markers differ")
    _prefix, _separator, rest = output.partition(TOOLCHAIN_JAVAC_MARKER)
    compiler_text, separator, runtime_text = rest.partition(
        TOOLCHAIN_JAVA_MARKER)
    if not separator:
        raise RuntimeError(
            "REFUSED: isolated Java toolchain probe order differs")
    compiler = " ".join(compiler_text.split())
    if re.fullmatch(r"javac\s+\S+", compiler) is None:
        raise RuntimeError(
            "REFUSED: isolated Java compiler identity is malformed: "
            + repr(compiler))
    runtime = _parser_identity_from_settings(runtime_text)
    if not runtime.startswith(compiler + " ["):
        raise RuntimeError(
            "REFUSED: isolated Java javac/runtime identities differ: "
            f"{compiler!r} / {runtime!r}")
    if expected_parser is not None and runtime != expected_parser:
        raise RuntimeError(
            "REFUSED: isolated Java campaign runtime is "
            f"{runtime!r}, manifest requires {expected_parser!r}")
    return runtime


def probe_parser_version(*, java: Optional[str] = None) -> str:
    """Independently identify the runtime whose javac API produces spans."""
    java_bin = _tool("java", java)
    cp = subprocess.run(
        [java_bin, "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, timeout=30,
        env=sanitised_java_env())
    text = (cp.stdout or "") + "\n" + (cp.stderr or "")
    if cp.returncode != 0:
        raise RuntimeError(
            "REFUSED: cannot identify the Java runtime that will host javac")
    return _parser_identity_from_settings(text)


def enumerate_local(repo_root: str, paths: Iterable[str], *,
                    analysis_recipe: dict,
                    compiler_argv: Iterable[str] = (),
                    javac: Optional[str] = None, java: Optional[str] = None,
                    compile_workers: int = 1,
                    record_enumerator_rev: bool = True,
                    expected_enumerator_sha256: Optional[str] = None,
                    timeout: int = 3600) -> dict:
    """Compile and run the offline enumerator, then validate its full envelope.

    ``repo_root`` is never written.  The producer, classes, and raw envelope
    live under a fresh host scratch directory.  A production revision-bearing
    call must authenticate the exact staged source bytes; focused diagnostic
    gates may omit the pin only when they explicitly disable revision output.
    """
    if not isinstance(compile_workers, int) or isinstance(compile_workers, bool) \
            or compile_workers < 1:
        raise ValueError("compile_workers must be a positive integer")
    compiler_args = _validated_compiler_argv(compiler_argv)
    if record_enumerator_rev and expected_enumerator_sha256 is None:
        raise ValueError(
            "recording Java enumerator provenance requires the pinned staged "
            "producer SHA-256")
    root = os.path.realpath(repo_root)
    if not os.path.isdir(root) or os.path.islink(repo_root):
        raise RuntimeError("REFUSED: Java enumeration root must be a canonical "
                           "non-symlink directory")
    path_list = [_canonical_relative(path, "enumeration") for path in paths]
    if not path_list or any(not analysis_path_covers(analysis_recipe, path)
                            for path in path_list):
        raise ValueError(
            "REFUSED: every Java enumeration path must be contained in the "
            "digest-bound sourcepath recipe")
    # javac and the source enumerator both run over one immutable authenticated
    # snapshot.  Live pathname pre/post hashes alone cannot exclude ABA swaps.
    with analysis_snapshot(root, analysis_recipe) as analysis_root:
        analysis_args = (analysis_argv(analysis_root, analysis_recipe)
                         + compiler_args)
        scratch = private_java_scratch("r2t_javamutate_", root)
        try:
            staged = os.path.join(scratch, "Mutate.java")
            if expected_enumerator_sha256 is None:
                shutil.copyfile(JAVA_SOURCE, staged)
            else:
                from ..data import mutation_attestation as A
                from . import mutation_audit as AUDIT
                AUDIT.stage_preserved_file(
                    JAVA_SOURCE, staged, expected_enumerator_sha256,
                    label="Java enumerator")
            classes = os.path.join(scratch, "classes")
            _javac, tools_jar = compile_engine(
                classes, source=staged, javac=javac)
            java_bin = _tool("java", java)
            raw = os.path.join(scratch, "raw.json")
            argv = [java_bin, "-cp", _runtime_classpath(classes, tools_jar),
                    "Mutate", "--root", analysis_root, "--compile-workers",
                    str(compile_workers), "--out", raw]
            for path in path_list:
                argv += ["--path", path]
            argv += analysis_args
            if record_enumerator_rev:
                argv.append("--record-enumerator-rev")
            cp = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout,
                env=sanitised_java_env())
            if cp.returncode != 0 or not os.path.isfile(raw):
                raise RuntimeError(
                    "REFUSED: Java enumerator failed "
                    f"(rc={cp.returncode}):\n"
                    f"{(cp.stderr or cp.stdout)[-2000:]}")
            with open(raw, encoding="utf-8") as fh:
                document = json.load(fh)
            document["analysis_recipe"] = analysis_recipe
            return validate_envelope(
                document, expected_parser=probe_parser_version(java=java_bin),
                require_revision=record_enumerator_rev)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


@contextmanager
def image_classpath_export(runner, jars: Iterable[dict], *,
                           forbidden_roots: Iterable[str] = ()):
    """Copy only the reviewed Surefire JAR set out of the exact worker image."""
    if runner.workdir != "/work":
        raise RuntimeError(
            "REFUSED: Java population worker must mount at /work, the exact "
            "path recorded by the reality classpath")
    rows = list(jars)
    if not rows:
        raise ValueError("REFUSED: Java image classpath export is empty")
    scratch = private_java_scratch(
        "r2t_java_classpath_", *tuple(forbidden_roots))
    workspace = os.path.join(scratch, "export")
    unused_analysis = os.path.join(scratch, "unused-analysis")
    unused_classes = os.path.join(scratch, "unused-classes")
    os.mkdir(workspace, 0o700)
    os.mkdir(unused_analysis, 0o700)
    os.mkdir(unused_classes, 0o700)
    exported = []
    commands = ["umask 077"]
    try:
        for index, row in enumerate(rows):
            source = row.get("image_path")
            digest = row.get("sha256")
            size = row.get("bytes")
            if not isinstance(source, str) or not source.startswith("/opt/m2/") \
                    or os.path.normpath(source) != source \
                    or not source.endswith(".jar") or not _is_sha256(digest) \
                    or not isinstance(size, int) or isinstance(size, bool) \
                    or size < 0:
                raise ValueError(
                    f"REFUSED: Java image classpath row #{index} is malformed")
            basename = re.sub(r"[^A-Za-z0-9_.-]+", "_",
                              os.path.basename(source)) or "dependency.jar"
            name = f"{index:04d}-{basename}"
            destination = os.path.join(workspace, name)
            runtime_destination = f"/work/{name}"
            commands.extend((
                f"test -f {shlex.quote(source)}",
                f"test ! -L {shlex.quote(source)}",
                f"test ! -e {shlex.quote(runtime_destination)}",
                f"cp {shlex.quote(source)} {shlex.quote(runtime_destination)}",
                f"chmod 600 {shlex.quote(runtime_destination)}"))
            exported.append((destination, row))
        cp = runner.run_isolated_java(
            " && ".join(commands), workspace_host=workspace,
            analysis_host=unused_analysis, classes_host=unused_classes,
            analysis_runtime="/opt/r2t-unused-analysis",
            classes_runtime="/opt/r2t-unused-classes", timeout=1800)
        if cp.returncode != 0:
            raise RuntimeError(
                "REFUSED: canonical Java image classpath export failed "
                f"(rc={cp.returncode}): "
                f"{(cp.stderr or cp.stdout or '')[-1000:]}")
        if sorted(os.listdir(workspace)) \
                != sorted(os.path.basename(path) for path, _row in exported):
            raise RuntimeError(
                "REFUSED: canonical Java image classpath export files differ")
        paths = []
        for path, row in exported:
            raw = _regular_bytes(
                path, "exported Maven JAR",
                maximum=max(row["bytes"], 1) + 1)
            if len(raw) != row["bytes"] \
                    or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise RuntimeError(
                    "REFUSED: canonical image JAR differs from approved M2 "
                    f"manifest: {row['path']}")
            paths.append(path)
        yield paths
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def stage_population_analysis(
        repo_roots: Iterable[str], classpath_sources: Iterable[str], *,
        sourcepath_sha256: str) -> dict:
    """Install one deterministic excluded recipe in every authenticated worker."""
    roots = [os.path.abspath(root) for root in repo_roots]
    sources = list(classpath_sources)
    if not roots or not sources or not _is_sha256(sourcepath_sha256):
        raise ValueError("REFUSED: Java population analysis inputs are incomplete")
    recipes = []
    for root in roots:
        staged = stage_classpath_bundle(root, sources)
        recipe = make_analysis_recipe(
            root, classpath=staged, sourcepath=(SOURCEPATH,))
        if len(recipe["sourcepath"]) != 1 \
                or recipe["sourcepath"][0] != {
                    "path": SOURCEPATH, "kind": "tree",
                    "sha256": sourcepath_sha256}:
            raise ValueError(
                "REFUSED: staged Java sourcepath differs from release authority")
        bundle = os.path.join(root, "var/bench_java_analysis/classpath")
        actual = sorted(os.path.join(
            "var/bench_java_analysis/classpath", name).replace(os.sep, "/")
                        for name in os.listdir(bundle))
        if actual != staged:
            raise ValueError(
                "REFUSED: Java analysis bundle contains an unselected input")
        recipes.append(recipe)
    if any(recipe != recipes[0] for recipe in recipes[1:]):
        raise ValueError(
            "REFUSED: authenticated Java workers staged different recipes")
    return recipes[0]


def enumerate_in_image(
        repo_root: str, paths: Iterable[str], *, analysis_recipe: dict,
        runner, expected_image_id: str, expected_enumerator_sha256: str,
        compile_workers: int = _PRODUCTION_COMPILE_WORKERS,
        timeout: int = 7200) -> dict:
    """Enumerate under the exact authority-bound canonical worker image."""
    root = os.path.realpath(repo_root)
    path_list = [_canonical_relative(path, "enumeration") for path in paths]
    if not path_list or any(not analysis_path_covers(analysis_recipe, path)
                            for path in path_list):
        raise ValueError(
            "REFUSED: every Java enumeration path must be under src/main/java")
    if not isinstance(compile_workers, int) \
            or isinstance(compile_workers, bool) or compile_workers < 1:
        raise ValueError("compile_workers must be a positive integer")
    if runner._image_for_isolated_run() != expected_image_id:
        raise RuntimeError(
            "REFUSED: isolated Java enumeration resolved another image")
    probe = runner.probe_isolated_java_toolchain(timeout=120)
    if probe.returncode != 0:
        raise RuntimeError(
            "REFUSED: isolated Java population toolchain probe failed "
            f"(rc={probe.returncode}): "
            f"{(probe.stderr or probe.stdout or '')[-500:]}")
    parser = parse_toolchain_probe(
        (probe.stdout or "") + "\n" + (probe.stderr or ""))

    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT
    with analysis_snapshot(root, analysis_recipe) as analysis_root:
        scratch = private_java_scratch(
            "r2t_javamutate_image_", root, analysis_root)
        try:
            source_dir = os.path.join(scratch, "source")
            classes = os.path.join(scratch, "classes")
            output = os.path.join(scratch, "output")
            os.mkdir(source_dir, 0o700)
            os.mkdir(classes, 0o700)
            os.mkdir(output, 0o700)
            staged_source = os.path.join(source_dir, "Mutate.java")
            AUDIT.stage_preserved_file(
                JAVA_SOURCE, staged_source, expected_enumerator_sha256,
                label="Java enumerator")
            compiled = runner.prepare_isolated_java_applier(
                staged_source, classes, timeout=300)
            if compiled.returncode != 0:
                raise RuntimeError(
                    "REFUSED: compiling Java population engine in canonical "
                    f"image failed (rc={compiled.returncode}): "
                    f"{(compiled.stderr or compiled.stdout or '')[-1000:]}")
            analysis_runtime = "/opt/r2t-analysis"
            classes_runtime = "/opt/r2t-engine-classes"
            resolved = snapshot_analysis_inputs(
                analysis_root, analysis_recipe,
                runtime_root=analysis_runtime)
            raw_runtime = "/work/raw.json"
            engine_args = [
                "-cp", classes_runtime + ":$JAVA_HOME/lib/tools.jar",
                "Mutate", "--root", analysis_runtime, "--compile-workers",
                str(compile_workers), "--out", raw_runtime]
            for path in path_list:
                engine_args += ["--path", path]
            engine_args += [
                "--classpath", resolved["classpath"],
                "--sourcepath", resolved["sourcepath"],
                "--module-path", resolved["module_path"],
                "--record-enumerator-rev"]
            # Quote every token, then deliberately restore expansion only in
            # the image-owned tools.jar component of the runtime classpath.
            quoted = [shlex.quote(value) for value in engine_args]
            quoted[1] = (shlex.quote(classes_runtime)
                         + ":\"$JAVA_HOME/lib/tools.jar\"")
            inner = "\"$JAVA_HOME/bin/java\" " + " ".join(quoted)
            cp = runner.run_isolated_java(
                inner, workspace_host=output, analysis_host=analysis_root,
                classes_host=classes, analysis_runtime=analysis_runtime,
                classes_runtime=classes_runtime, timeout=timeout)
            raw_path = os.path.join(output, "raw.json")
            if cp.returncode != 0 or not os.path.isfile(raw_path):
                raise RuntimeError(
                    "REFUSED: Java enumerator failed in canonical image "
                    f"(rc={cp.returncode}):\n"
                    f"{(cp.stderr or cp.stdout or '')[-2000:]}")
            document, _raw = _json_object(raw_path, "enumerator output")
            document["analysis_recipe"] = analysis_recipe
            return validate_envelope(
                document, expected_parser=parser, require_revision=True)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


def enumerate_modules_in_image(
        repo_root: str, authority: dict, *, runner,
        expected_image_id: str, expected_enumerator_sha256: str,
        compile_workers: int = _PRODUCTION_COMPILE_WORKERS,
        timeout: int = 7200) -> dict:
    """Enumerate each Kapua source root under its own captured compiler."""
    root = os.path.realpath(repo_root)
    validate_analysis_recipe(authority, root)
    if authority["schema"] != MODULE_ANALYSIS_SCHEMA:
        raise ValueError("REFUSED: Kapua module enumeration needs a module map")
    if not isinstance(compile_workers, int) \
            or isinstance(compile_workers, bool) or compile_workers < 1:
        raise ValueError("compile_workers must be a positive integer")
    if runner._image_for_isolated_run() != expected_image_id:
        raise RuntimeError(
            "REFUSED: isolated Kapua enumeration resolved another image")
    validate_module_toolchains(authority, runner, timeout=120)
    engine_java_home = module_engine_toolchain(authority)["java_home"]

    from . import mutation_audit as AUDIT
    with analysis_snapshot(root, authority) as analysis_root:
        scratch = private_java_scratch(
            "r2t_javamutate_modules_", root, analysis_root)
        try:
            source_dir = os.path.join(scratch, "source")
            classes = os.path.join(scratch, "classes")
            outputs = os.path.join(scratch, "outputs")
            os.mkdir(source_dir, 0o700)
            os.mkdir(classes, 0o700)
            os.mkdir(outputs, 0o700)
            staged_source = os.path.join(source_dir, "Mutate.java")
            AUDIT.stage_preserved_file(
                JAVA_SOURCE, staged_source, expected_enumerator_sha256,
                label="Java enumerator")
            compiled = runner.prepare_isolated_java_applier(
                staged_source, classes, timeout=300,
                java_home=engine_java_home)
            if compiled.returncode != 0:
                raise RuntimeError(
                    "REFUSED: compiling the Kapua population engine failed "
                    f"(rc={compiled.returncode}): "
                    f"{(compiled.stderr or compiled.stdout or '')[-1000:]}")
            analysis_runtime = "/opt/r2t-analysis"
            classes_runtime = "/opt/r2t-engine-classes"
            supplied = []
            for index, row in enumerate(authority["modules"]):
                output = os.path.join(outputs, f"{index:04d}")
                os.mkdir(output, 0o700)
                raw_runtime = "/work/raw.json"
                binding = analysis_binding_for_path(
                    authority, row["source_files"][0])
                resolved = snapshot_analysis_inputs(
                    analysis_root, binding["recipe"],
                    runtime_root=analysis_runtime,
                    allow_kapua_absent_manifest_classpath=binding[
                        "allow_kapua_absent_manifest_classpath"])
                compiler = binding["compiler"]
                java_home = compiler["java_home"]
                engine_args = [
                    "-cp", classes_runtime + ":"
                    + java_home + "/lib/tools.jar",
                    "Mutate", "--root", analysis_runtime,
                    "--compile-workers", str(compile_workers),
                    "--out", raw_runtime, "--path", row["source_root"],
                    "--classpath", resolved["classpath"],
                    "--sourcepath", resolved["sourcepath"],
                    "--module-path", resolved["module_path"],
                    *binding["compiler_argv"],
                    "--record-enumerator-rev"]
                inner = (shlex.quote(java_home + "/bin/java") + " "
                         + " ".join(shlex.quote(value)
                                    for value in engine_args))
                cp = runner.run_isolated_java(
                    inner, workspace_host=output,
                    analysis_host=analysis_root, classes_host=classes,
                    analysis_runtime=analysis_runtime,
                    classes_runtime=classes_runtime, timeout=timeout)
                raw_path = os.path.join(output, "raw.json")
                if cp.returncode != 0 or not os.path.isfile(raw_path):
                    raise RuntimeError(
                        "REFUSED: Kapua Java module enumeration failed for "
                        f"{row['module']!r} (rc={cp.returncode}):\n"
                        f"{(cp.stderr or cp.stdout or '')[-2000:]}")
                document, _raw = _json_object(
                    raw_path, f"{row['module']} enumerator output")
                document["analysis_recipe"] = row["recipe"]
                supplied.append({"module": row["module"], "envelope":
                                 validate_envelope(
                                     document,
                                     expected_parser=compiler["parser"],
                                     require_revision=True,
                                     _allow_kapua_absent_manifest_classpath=
                                     True)})
            return merge_module_envelopes(authority, supplied)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


def validate_envelope(document: dict, *, expected_parser: Optional[str] = None,
                      require_revision: bool = True,
                      _allow_kapua_absent_manifest_classpath: bool = False
                      ) -> dict:
    """Validate header, errors witness, optional metadata, and every row."""
    from ..data import mutation_attestation as A
    checked = A.validate_enumerator_envelope(
        document, expected_engine=ENGINE,
        expected_engine_version=ENGINE_VERSION,
        expected_parser_version=expected_parser,
        expected_enumerator_rev=ENUMERATOR_REV if require_revision else None)
    if _allow_kapua_absent_manifest_classpath:
        _validate_single_analysis_recipe(
            checked.get("analysis_recipe"),
            allow_kapua_absent_manifest_classpath=True)
    else:
        validate_analysis_recipe(checked.get("analysis_recipe"))
    if checked["analysis_recipe"]["schema"] == MODULE_ANALYSIS_SCHEMA \
            and checked["parser"] != module_analysis_parser(
                checked["analysis_recipe"]):
        raise ValueError(
            "REFUSED: Kapua module envelope parser identity differs from "
            "its composite authority")
    # build_manifest is the authoritative row validator: exact field set,
    # v2 operator vocabulary, 1-based coordinates, no-ops/deletions, duplicate
    # ids, sorting, and digest construction. Discard the result here; callers
    # wanting a manifest go through build_population below with the same args.
    rows = checked["mutants"]
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"REFUSED: Java mutant #{index} is not an object")
        for field in ("end_line", "end_col"):
            value = row.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(
                    f"REFUSED: Java mutant #{index} has invalid {field}")
        if (row["end_line"], row["end_col"]) \
                < (row.get("start_line", 0), row.get("start_col", 0)):
            raise ValueError(
                f"REFUSED: Java mutant #{index} has a reversed byte span")
        for field in ("class", "method"):
            if field in row and (not isinstance(row[field], str)
                                 or not row[field].strip()):
                raise ValueError(
                    f"REFUSED: Java mutant #{index} has invalid {field}")
        path = row.get("file")
        if not isinstance(path, str) or path != M.normalise_path(path) \
                or path.startswith("/") or path == ".." \
                or path.startswith("../"):
            raise ValueError(
                f"REFUSED: Java mutant #{index} has non-canonical file path")
    order = lambda row: (row["file"], row["start_line"], row["start_col"],
                         row["end_line"], row["end_col"], row["operator"])
    if rows != sorted(rows, key=order):
        raise ValueError("REFUSED: Java enumerator rows are not canonically sorted")
    manifest = build_population(
        checked["mutants"], parser_version=checked["parser"],
        n_invalid=checked.get("n_invalid"),
        enumerator_rev=checked.get("enumerator_rev"),
        analysis_recipe=checked["analysis_recipe"],
        _allow_kapua_absent_manifest_classpath=
        _allow_kapua_absent_manifest_classpath)
    if manifest["n"] != len(rows) or manifest["n_excluded"]:
        raise ValueError(
            "REFUSED: Java envelope contains a row excluded from its declared "
            "source policy")
    distinct_files = {row["file"] for row in rows}
    if checked["files"] < len(distinct_files):
        raise ValueError(
            "REFUSED: Java envelope files count is smaller than its row files")
    return checked


def merge_module_envelopes(authority: dict, envelopes: Iterable[dict]) -> dict:
    """Merge complete per-module enumerations without merging classpaths."""
    validate_analysis_recipe(authority)
    if authority["schema"] != MODULE_ANALYSIS_SCHEMA:
        raise ValueError("REFUSED: Java envelope merge requires a module map")
    supplied = list(envelopes)
    if len(supplied) != len(authority["modules"]):
        raise ValueError(
            "REFUSED: Kapua Java enumeration has missing or extra modules")
    mutants = []
    total_files = 0
    total_invalid = 0
    for index, (module_row, supplied_row) in enumerate(
            zip(authority["modules"], supplied)):
        if not isinstance(supplied_row, dict) \
                or set(supplied_row) != {"module", "envelope"} \
                or supplied_row.get("module") != module_row["module"]:
            raise ValueError(
                f"REFUSED: Kapua Java enumeration row #{index} does not "
                "match authority order")
        checked = validate_envelope(
            supplied_row.get("envelope"),
            expected_parser=module_row["compiler"]["parser"],
            require_revision=True,
            _allow_kapua_absent_manifest_classpath=True)
        if checked["analysis_recipe"] != module_row["recipe"]:
            raise ValueError(
                f"REFUSED: Kapua Java module {module_row['module']!r} "
                "enumerated under another compiler recipe")
        if checked["files"] != len(module_row["source_files"]):
            raise ValueError(
                f"REFUSED: Kapua Java module {module_row['module']!r} "
                "did not process every original source file")
        total_files += checked["files"]
        total_invalid += checked.get("n_invalid", 0)
        mutants.extend(checked["mutants"])
    order = lambda row: (row["file"], row["start_line"], row["start_col"],
                         row["end_line"], row["end_col"], row["operator"])
    merged = {
        "engine": ENGINE,
        "engine_version": ENGINE_VERSION,
        "parser": module_analysis_parser(authority),
        "files": total_files,
        "errors": {},
        "mutants": sorted(mutants, key=order),
        "enumerator_rev": ENUMERATOR_REV,
        "analysis_recipe": authority,
    }
    if total_invalid:
        merged["n_invalid"] = total_invalid
    return validate_envelope(
        merged, expected_parser=merged["parser"], require_revision=True)


def load_raw_doc(document: dict) -> list[dict]:
    """Return rows only after the complete Java envelope validates."""
    return validate_envelope(document)["mutants"]


def load_raw(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return load_raw_doc(json.load(fh))


def build_population(raw: list[dict], *, parser_version: str,
                     exclusions: Iterable[str] = EXCLUDED_PREFIXES,
                     sample: Optional[int] = None, seed=None,
                     n_invalid: Optional[int] = None,
                     enumerator_rev: Optional[str] = None,
                     analysis_recipe: Optional[dict] = None,
                     _allow_kapua_absent_manifest_classpath: bool = False
                     ) -> dict:
    """Build a v2-only manifest in the Java engine's disjoint id space."""
    if _allow_kapua_absent_manifest_classpath:
        _validate_single_analysis_recipe(
            analysis_recipe, allow_kapua_absent_manifest_classpath=True)
    else:
        validate_analysis_recipe(analysis_recipe)
    for index, row in enumerate(raw):
        path = row.get("file") if isinstance(row, dict) else None
        if not isinstance(path, str) \
                or not analysis_path_covers(analysis_recipe, path):
            raise ValueError(
                f"REFUSED: Java mutant #{index} file {path!r} is outside "
                "its authenticated sourcepath")
    manifest = M.build_manifest(
        raw, parser_version=parser_version, operators=M.OPERATORS,
        exclusions=exclusions, engine=ENGINE, engine_version=ENGINE_VERSION,
        sample=sample, seed=seed, n_invalid=n_invalid,
        enumerator_rev=enumerator_rev)
    # The generic builder intentionally knows nothing Java-specific.  Add the
    # already validated recipe before recomputing the generic manifest digest;
    # every campaign/audit later authenticates this exact object through that
    # digest before resolving any project path.
    manifest["analysis_recipe"] = analysis_recipe
    manifest["digest"] = M.manifest_digest(manifest)
    return manifest


def population_for(document: dict, *, expected_parser: Optional[str] = None,
                   sample: Optional[int] = None, seed=None) -> dict:
    """Validate one current envelope and turn it into its digest-covered manifest."""
    checked = validate_envelope(document, expected_parser=expected_parser,
                                require_revision=True)
    return build_population(
        checked["mutants"], parser_version=checked["parser"],
        sample=sample, seed=seed, n_invalid=checked.get("n_invalid"),
        enumerator_rev=checked["enumerator_rev"],
        analysis_recipe=checked["analysis_recipe"])


def strict_gold_coverage(
        coverage_run: str, release_ids: set[str]) -> tuple[dict, str]:
    """Load one complete gold+coverage campaign and its parsed-byte digest."""
    from ..bench import campaign as C
    from ..bench import result_ledger as L

    raw = _regular_bytes(
        os.path.abspath(coverage_run), "gold coverage run",
        maximum=1 << 30)
    rows_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        rows = L._json_lines(raw, "Java gold coverage run")
    except L.ResultLedgerRefused as exc:
        raise ValueError(str(exc)) from exc
    side_path = os.path.abspath(coverage_run) + ".campaign.json"
    side, _side_raw = _json_object(
        side_path, "gold coverage campaign sidecar")
    side_fields = {
        "campaign", "campaign_digest", "workers", "n", "rows_path",
        "rows_digest",
    }
    if set(side) != side_fields or not isinstance(side.get("campaign"), dict) \
            or not isinstance(side.get("workers"), list) \
            or side.get("rows_path") != os.path.basename(coverage_run) \
            or side.get("n") != len(rows) \
            or side.get("rows_digest") != rows_sha256[:16]:
        raise ValueError(
            "REFUSED: Java gold coverage campaign sidecar does not bind rows")
    try:
        digest = C.campaign_digest(side["campaign"])
    except SystemExit as exc:
        raise ValueError(str(exc)) from exc
    campaign = side["campaign"]
    if side.get("campaign_digest") != digest \
            or campaign.get("coverage") is not True \
            or campaign.get("trial_budget") != 0 \
            or campaign.get("condition") is not None \
            or campaign.get("model") is not None \
            or campaign.get("agent_system") is not None:
        raise ValueError(
            "REFUSED: Java coverage input is not one gold control campaign")
    by_item = {}
    for number, row in enumerate(rows, 1):
        item_id = row.get("item_id")
        if not isinstance(item_id, str) or not item_id or item_id in by_item:
            raise ValueError(
                "REFUSED: Java gold coverage repeats or omits an item_id")
        shard = row.get("shard")
        if not isinstance(shard, int) or isinstance(shard, bool):
            raise ValueError(
                f"REFUSED: Java gold coverage row {number} has no shard")
        problems = C._crosscheck_row(campaign, row, shard)
        coverage = row.get("coverage_lines")
        metadata = row.get("metadata")
        if problems or row.get("campaign_digest") != digest \
                or row.get("adapter") != "gold" \
                or not isinstance(metadata, dict) \
                or metadata.get("source") != "gold" \
                or type(row.get("repeats")) is not int \
                or row.get("repeats") != 1 \
                or row.get("coverage") is not True \
                or row.get("coverage_requested") is not True \
                or row.get("coverage_collected") is not True \
                or row.get("outcome") != "passed" \
                or row.get("coverage_mismatch") != [] \
                or not isinstance(coverage, dict):
            raise ValueError(
                f"REFUSED: Java gold coverage row {number} is not one "
                "successful measured gold observation"
                + (f": {problems[0]}" if problems else ""))
        clean = {}
        for path, lines in coverage.items():
            if not isinstance(path, str) or path != M.normalise_path(path) \
                    or not path.startswith(SOURCEPATH + "/") \
                    or not isinstance(lines, list) \
                    or any(not isinstance(line, int) or isinstance(line, bool)
                           or line < 1 for line in lines) \
                    or lines != sorted(set(lines)):
                raise ValueError(
                    f"REFUSED: Java gold coverage row {number} has malformed "
                    "production line coverage")
            clean[path] = lines
        by_item[item_id] = clean
    if set(by_item) != release_ids:
        raise ValueError(
            "REFUSED: Java gold coverage is not the complete released item "
            f"set; missing={sorted(release_ids-set(by_item))[:3]}, "
            f"extra={sorted(set(by_item)-release_ids)[:3]}")
    return by_item, rows_sha256


def _build_population_map(
        manifest: dict, coverage_run: str, *, release_ids: set[str],
        release_sha256: str, kapua_release=None, boundary_path=None,
        items_path=None) -> tuple[dict, dict]:
    """Bind a map to the exact coverage and reviewed-release snapshots."""
    from ..data import mutation_attestation as A

    if kapua_release is not None:
        from ..java.kapua_population import load_gold_coverage
        from ..java import kapua_gold_coverage as G
        if os.path.lexists(G.projection_path(coverage_run)):
            coverage, coverage_sha256 = G.load_projection(
                coverage_run, items_path, boundary_path, release=kapua_release)
        else:
            coverage, coverage_sha256 = load_gold_coverage(
                coverage_run, kapua_release, boundary_path=boundary_path)
    else:
        coverage, coverage_sha256 = strict_gold_coverage(coverage_run, release_ids)
    by_mutant, uncovered = M.map_mutants_to_items(manifest, coverage)
    payload = A.build_map_artifact(
        manifest, by_mutant, uncovered,
        coverage_sha256=coverage_sha256,
        release_sha256=release_sha256)
    A.validate_map(
        payload, manifest, release_ids=release_ids,
        coverage_by_item=coverage)
    return payload, coverage


def _copy_audit_roots(root: str, scratch: str, count: int,
                      recipe: dict) -> list[str]:
    """Make `count` further disposable audit trees from the marked original.

    Each copy is held to everything the original had to prove: the exact
    disposable marker bytes, and the SAME analysis recipe validated against
    its own files.  `audit_population` then refuses unless every tree's
    bounded source set is digest-identical to the primary's, so a copy that
    silently lost or gained a byte cannot become an audited tree.
    """
    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT

    copies = []
    for index in range(count):
        destination = os.path.join(scratch, f"audit-root-{index + 1:03d}")
        shutil.copytree(root, destination, symlinks=True)
        marker = os.path.join(destination, A.DISPOSABLE_MARKER)
        if os.path.islink(destination) or not os.path.isdir(destination) \
                or os.path.realpath(destination) != destination \
                or os.path.islink(marker) or not os.path.isfile(marker):
            raise ValueError(
                "REFUSED: parallel Java audit copy is not a marked canonical "
                "disposable workspace")
        with open(marker, encoding="utf-8") as handle:
            if handle.read() != AUDIT.DISPOSABLE_MARKER_CONTENT:
                raise ValueError(
                    "REFUSED: parallel Java audit copy marker bytes differ")
        validate_analysis_recipe(recipe, destination)
        copies.append(destination)
    return copies


@contextmanager
def _java_audit_sessions(open_session, worker_roots: list, *,
                         analysis_host: str, classes_host: str,
                         timeout: int):
    """Open one session per audited tree; close and prove ALL of them absent.

    The single-session close protocol does not weaken as k grows: whatever
    goes wrong -- a session that fails to open, a worker that refuses, a
    timeout mid-walk -- every container this function opened is force-removed
    and proved absent before the exception leaves it.  A tree left mounted
    read-write by a surviving container is exactly the hazard the audit's
    restoration evidence exists to exclude.
    """
    from ..bench import mutation_run as RUN

    sessions: dict[str, object] = {}
    try:
        for worker_root in worker_roots:
            sessions[worker_root] = open_session(
                workspace_host=worker_root, analysis_host=analysis_host,
                classes_host=classes_host,
                analysis_runtime=RUN.JAVA_ANALYSIS_RUNTIME,
                classes_runtime=RUN.JAVA_APPLIER_RUNTIME,
                timeout=timeout)
        yield sessions
    finally:
        problems = []
        for worker_root, session in sessions.items():
            try:
                session.close()
            except BaseException as exc:                     # noqa: BLE001
                problems.append(
                    f"{worker_root}: {type(exc).__name__}: {exc}")
        if problems:
            raise RuntimeError(
                "REFUSED: Java audit session containers could not all be "
                "proved absent: " + "; ".join(problems))


def audit_population_in_image(manifest: dict, source_root: str, *, runner,
                              expected_image_id: str,
                              timeout: int = 300,
                              workers: int = 1) -> dict:
    """Apply, parse and restore the full Java population in its frozen image.

    TRANSPORT: ONE long-lived container per worker, one `docker exec` per
    mutant (owner rulings, 2026-08-12).  The first shape ran one `docker run`
    sidecar per mutant and measured 0.6-1.8 mutants/min on Algorand's 7,766
    (PROVENANCE §A27 step 5).  The session transport removed that: the first
    live run measured **0.33 s of transport against 12.11 s of compute** per
    mutant, driver at 0.4% CPU, and 26.8 h projected for the population
    (§A30 step 5).  Twelve seconds is two fresh JVMs -- apply, then parse --
    each launched against a 53-jar classpath, and no transport change can
    remove it.

    PARALLELISM (`workers`, owner ruling: "parallelize k=16 if possible",
    default 16 at the CLI).  Each worker owns ONE session container and ONE
    disposable tree: this function copies the operator's marked audit root
    into `workers - 1` further private copies, validates each against the
    same analysis recipe, and hands the set to `audit_population`, which
    refuses unless all of them are digest-identical.  k trees are not a
    convenience -- a mutant is materialised INTO the audited tree and the
    collateral check asserts nothing else moved, so two live mutations in one
    tree would make that assertion false.

    SATURATION, so the measured rate stays interpretable: one mutant's
    container was measured at ~291% CPU (the `java` process inside it at
    451%).  On this 40-core box that saturates near ~13 fully-parallel
    mutants, so k=16 deliberately OVERSUBSCRIBES -- the owner's explicit
    call, and the right one, because the extra workers fill the gaps while
    others are in JVM startup or in the driver's own snapshot/restore work
    rather than on CPU.  Expect the walk to approach, not exceed, a ~13x
    speedup over the sequential 26.8 h.

    Everything else is what it was: the same image, mounts and isolation, the
    same per-mutant apply/parse commands, the same evidence, refusals and
    digests.  With `workers=1` there is one tree, one session and one
    attestation byte-identical to the sequential walk's.
    """
    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT
    from ..bench import mutation_run as RUN

    A.validate_manifest(manifest, expected_engine=ENGINE)
    root = os.path.abspath(source_root)
    marker = os.path.join(root, A.DISPOSABLE_MARKER)
    if os.path.islink(root) or not os.path.isdir(root) \
            or os.path.realpath(root) != root \
            or os.path.islink(marker) or not os.path.isfile(marker):
        raise ValueError(
            "REFUSED: Java audit root is not a marked canonical disposable "
            "workspace")
    with open(marker, encoding="utf-8") as handle:
        if handle.read() != AUDIT.DISPOSABLE_MARKER_CONTENT:
            raise ValueError(
                "REFUSED: Java audit disposable marker bytes differ")
    if runner._image_for_isolated_run() != expected_image_id:
        raise ValueError(
            "REFUSED: Java audit sidecar image differs from reviewed reality")
    open_session = getattr(runner, "open_isolated_java_session", None)
    if not callable(open_session):
        raise ValueError(
            "REFUSED: Java audit requires a runner with a long-lived "
            "isolated Java session")
    validate_analysis_recipe(manifest["analysis_recipe"], root)
    engine_dir, bound_applier = RUN.binding_for(manifest["engine"])
    if bound_applier != applier() or RUN.operator_profile_for(
            manifest["operators"]) != "v2":
        raise ValueError(
            "REFUSED: Java audit manifest has another applier/operator profile")
    if isinstance(workers, bool) or not isinstance(workers, int) \
            or workers < 1:
        raise ValueError(
            "REFUSED: Java audit worker count must be an integer >= 1")
    engine_source = os.path.join(engine_dir, bound_applier.source)
    engine_source_sha256 = A.sha256_file(engine_source)
    harness = type("JavaAuditHarness", (), {})()
    harness.root = root
    harness.runner = runner
    scratch_rel = os.path.dirname(bound_applier.rel)
    scratch = AUDIT.create_private_scratch(root, scratch_rel)
    parse_rel = (scratch_rel + "/parse.json").replace(os.sep, "/")
    cached_parse = {}
    runtime_reports = set()
    local = threading.local()
    copies_scratch = None
    try:
        module_authority = manifest["analysis_recipe"].get("schema") \
            == MODULE_ANALYSIS_SCHEMA
        if module_authority:
            module_bindings = module_analysis_bindings(
                manifest["analysis_recipe"])
            toolchains = validate_module_toolchains(
                manifest["analysis_recipe"], runner, timeout=timeout)
            engine_java_home = module_engine_toolchain(
                manifest["analysis_recipe"])["java_home"]
            engine_toolchain = toolchains[engine_java_home]
            runtime_identity = engine_toolchain["parser"]
            tool_hashes = {key: engine_toolchain[key] for key in (
                "runtime_executable_sha256", "compiler_executable_sha256",
                "tools_jar_sha256")}
        else:
            module_bindings = None
            probe = runner.probe_isolated_java_toolchain(timeout=timeout)
            if probe.returncode != 0:
                raise ValueError(
                    "REFUSED: isolated Java toolchain probe failed "
                    f"(rc={probe.returncode}): "
                    f"{(probe.stderr or probe.stdout or '')[-500:]}")
            probe_output = (probe.stdout or "") + "\n" + (probe.stderr or "")
            runtime_identity = parse_toolchain_probe(
                probe_output, expected_parser=manifest["parser"])
            tool_hashes = parse_toolchain_hash_probe(probe_output)
        required_sources = [row["file"] for row in manifest["mutants"]]
        worker_roots = [root]
        if workers > 1:
            copies_scratch = private_java_scratch(
                "r2t_java_audit_roots_", root)
            worker_roots.extend(_copy_audit_roots(
                root, copies_scratch, workers - 1,
                manifest["analysis_recipe"]))
        with analysis_snapshot(
                root, manifest["analysis_recipe"],
                required_sources=required_sources) as analysis_root, \
                RUN._isolated_java_applier(
                    harness, engine_dir, bound_applier,
                    expected_sha256=engine_source_sha256,
                    java_home=(engine_java_home
                               if module_authority else None)) as classes_root, \
                _java_audit_sessions(
                    open_session, worker_roots,
                    analysis_host=analysis_root, classes_host=classes_root,
                    timeout=timeout) as sessions:
            initial_classes_sha256 = AUDIT._compiled_tree_sha256(classes_root)

            def worker_bind(worker_root: str) -> None:
                """Bind THIS thread to its own tree, session and evidence."""
                local.session = sessions[worker_root]
                local.parse_path = os.path.join(
                    worker_root, *parse_rel.split("/"))

            def apply_one(mutant: dict, _target: str) -> None:
                parse_path = local.parse_path
                if os.path.exists(parse_path):
                    os.unlink(parse_path)
                rel = mutant["file"]
                binding = (module_bindings[rel]
                           if module_bindings is not None else
                           analysis_binding_for_path(
                               manifest["analysis_recipe"], rel))
                resolved = snapshot_analysis_inputs(
                    analysis_root, binding["recipe"],
                    runtime_root=RUN.JAVA_ANALYSIS_RUNTIME,
                    allow_kapua_absent_manifest_classpath=binding[
                        "allow_kapua_absent_manifest_classpath"])
                compiler_args = binding["compiler_argv"]
                analysis_suffix = (
                    " --classpath " + shlex.quote(resolved["classpath"])
                    + " --sourcepath " + shlex.quote(resolved["sourcepath"])
                    + " --module-path " + shlex.quote(resolved["module_path"])
                    + "".join(" " + shlex.quote(value)
                              for value in compiler_args))
                compiler = binding["compiler"]
                if compiler is None:
                    java = ("\"$JAVA_HOME/bin/java\" -cp \""
                            + RUN.JAVA_APPLIER_RUNTIME
                            + ":$JAVA_HOME/lib/tools.jar\" "
                            + shlex.quote(bound_applier.entrypoint))
                    expected_parser = manifest["parser"]
                else:
                    java_home = compiler["java_home"]
                    java = (shlex.quote(java_home + "/bin/java")
                            + " -cp " + shlex.quote(
                                RUN.JAVA_APPLIER_RUNTIME + ":"
                                + java_home + "/lib/tools.jar") + " "
                            + shlex.quote(bound_applier.entrypoint))
                    expected_parser = compiler["parser"]
                apply_command = (
                    f"{java} --root {RUN.JAVA_ANALYSIS_RUNTIME} "
                    f"--write-root {shlex.quote(runner.workdir)} "
                    "--operator-profile v2 "
                    f"--apply-file {shlex.quote(rel)} "
                    f"--start-line {int(mutant['start_line'])} "
                    f"--start-col {int(mutant['start_col'])} "
                    f"--operator {shlex.quote(mutant['operator'])} "
                    f"--original {shlex.quote(mutant['original'])} "
                    f"--mutated {shlex.quote(mutant['mutated'])} "
                    f"--out {shlex.quote(rel)}{analysis_suffix}")
                parse_command = (
                    f"{java} --root {shlex.quote(runner.workdir)} "
                    "--operator-profile v2 "
                    f"--path {shlex.quote(rel)} "
                    f"--out {shlex.quote(parse_rel)}{analysis_suffix}")
                cp = local.session.run(
                    apply_command + " && " + parse_command, timeout=timeout)
                if cp.returncode != 0:
                    raise A.MutationAssetRefused(
                        "REFUSED: image-owned Java apply/parse failed for "
                        f"{mutant['id']} (rc={cp.returncode}): "
                        f"{(cp.stderr or cp.stdout or '')[-500:]}")
                document, _raw = _json_object(
                    parse_path, "materialisation parse evidence")
                cached_parse[mutant["id"]] = (document, expected_parser)

            def parse_one(mutant: dict, _target: str) -> None:
                cached = cached_parse.pop(mutant["id"], None)
                if not isinstance(cached, tuple) or len(cached) != 2:
                    document, expected_parser = None, None
                else:
                    document, expected_parser = cached
                if not isinstance(document, dict) or document.get("errors") \
                        or document.get("parser") != expected_parser:
                    raise A.MutationAssetRefused(
                        "REFUSED: image-owned parser rejected materialised "
                        f"mutant {mutant['id']}")
                runtime_reports.add(document["parser"])

            compiled = {
                "schema": "r2t.compiled-applier/2",
                "source_sha256": engine_source_sha256,
                "interpreter": bound_applier.interpreter,
                "entrypoint": bound_applier.entrypoint,
                "classes_rel": bound_applier.classes_rel.replace(os.sep, "/"),
                "classes_sha256": initial_classes_sha256,
                "compiler_identity": runtime_identity.split(" [", 1)[0],
                **tool_hashes,
                "runtime_identity": runtime_identity,
                "analysis_recipe_digest": manifest["analysis_recipe"][
                    "digest"],
            }

            def operator_gate() -> dict:
                return {
                    "mode": "real_engine",
                    "disposable_marker": A.DISPOSABLE_MARKER,
                    "engine_source_sha256": engine_source_sha256,
                    "runtime_parser_identity": manifest["parser"],
                    "runtime_parser_reported": (
                        module_analysis_parser(manifest["analysis_recipe"])
                        if module_authority and runtime_reports == {
                            row["compiler"]["parser"] for row in
                            manifest["analysis_recipe"]["modules"]
                            if any(mutant["file"] in row["source_files"]
                                   for mutant in manifest["mutants"])}
                        else (next(iter(runtime_reports))
                              if len(runtime_reports) == 1 else None)),
                    "compiled_applier": compiled,
                }

            try:
                report = AUDIT.audit_population(
                    manifest, root, apply_one, parse_one,
                    parallel_roots=worker_roots[1:],
                    worker_bind=worker_bind)
            except A.MaterialisationAuditRefused as exc:
                exc.report["operator_gate"] = operator_gate()
                exc.report["digest"] = A.audit_digest(exc.report)
                raise
            A.validate_preserved_file(
                engine_source, engine_source_sha256,
                label="Java audit engine source")
            if AUDIT._compiled_tree_sha256(classes_root) \
                    != initial_classes_sha256:
                raise ValueError(
                    "REFUSED: isolated Java audit classes changed")
            report["operator_gate"] = operator_gate()
            report["digest"] = A.audit_digest(report)
            return report
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        if copies_scratch is not None:
            shutil.rmtree(copies_scratch, ignore_errors=True)


def build_asset_index(project: str, *, manifest: dict, manifest_path: str,
                      mapping: dict, coverage_path: str, release_path: str,
                      boundary_path: str, audit: dict) -> dict:
    """Derive the existing frozen mutation index from exact Java evidence.

    The construction moved WHOLE into `toolkit.mutation_asset_index` when a
    Behat/PHP population needed the same entry and had no way to mint one.
    Every line of it was project-general except two -- the expected engine
    name and the engine source whose bytes the entry binds -- and both are
    arguments there.  Java enumerates inside the production boundary, so its
    raw catalogue IS its scored population: one manifest, one path.  That
    module's self-test and this one both pin the resulting bytes.
    """
    from . import mutation_asset_index as ASSETS

    return ASSETS.build_asset_index(
        project, engine=ENGINE, engine_source_path=JAVA_SOURCE,
        raw_manifest=manifest, raw_manifest_path=manifest_path,
        scored_manifest=manifest, mapping=mapping,
        coverage_path=coverage_path, release_path=release_path,
        boundary_path=boundary_path, audit=audit)


def _map_release_inputs(release, items_path, coverage_run, *, kapua=False):
    """Census files retain the original complete release's approval authority."""
    if kapua:
        from ..java import kapua_gold_coverage as G
        if os.path.lexists(G.projection_path(coverage_run)):
            from ..data import mutation_attestation as A
            # The builder below revalidates the full projection before output creation.
            return A.load_release_ids(items_path), A.sha256_file(items_path)
    if os.path.abspath(items_path) != release["items_path"]:
        raise ValueError("REFUSED: Java mutation map/audit release is not the exact reviewed final release items.jsonl")
    return release["released_item_ids"], release["items_sha256"]


def cmd_mutants(args) -> int:
    """Cucumber's authority-bound ``mutants build|map`` implementation."""
    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT
    from ..core.boundary import load_boundary

    boundary = load_boundary(args.boundary, repo_root=args.repo)
    if boundary.project not in _RELEVANT_REALITY_RUNS:
        raise SystemExit(
            f"REFUSED: Java mutation project {boundary.project!r} is not "
            "released")

    if args.action == "map":
        try:
            if not args.release:
                raise ValueError(
                    "REFUSED: Java mutants map requires the final release "
                    "items.jsonl")
            input_paths = (args.manifest, args.coverage_run, args.release,
                           args.boundary, args.coverage_run + ".campaign.json",
                           getattr(args, "approval", None), args.artifacts)
            if boundary.project != "kapua":
                out_fd = AUDIT.reserve_output(args.out, input_paths=input_paths)
            release = validate_population_release(
                args.artifacts, project=boundary.project,
                approval_path=getattr(args, "approval", None),
                approved_digest=getattr(args, "approved_digest", None))
            map_ids, map_release_sha256 = _map_release_inputs(
                release, args.release, args.coverage_run, kapua=boundary.project == "kapua")
            with open(args.manifest, encoding="utf-8") as handle:
                manifest = json.load(handle)
            A.validate_manifest(manifest, expected_engine=ENGINE)
            payload, coverage = _build_population_map(
                manifest, args.coverage_run,
                release_ids=map_ids,
                release_sha256=map_release_sha256,
                kapua_release=release if boundary.project == "kapua" else None,
                boundary_path=args.boundary, items_path=args.release)
            if boundary.project == "kapua":
                # Receipt/source/worker/row refusals precede even output creation.
                out_fd = AUDIT.reserve_output(args.out, input_paths=input_paths)
            AUDIT.write_reserved_json(out_fd, payload)
        except (A.MutationAssetRefused, OSError, ValueError,
                json.JSONDecodeError, TypeError) as exc:
            message = str(exc)
            raise SystemExit(message if message.startswith("REFUSED:")
                             else "REFUSED: " + message) from exc
        print(json.dumps({
            "out": args.out, "mutants": manifest["n"],
            "covered": payload["n_mapped"],
            "uncovered": payload["n_uncovered"],
            "items_with_coverage": len(coverage)}, indent=1))
        return 0

    if args.action != "build":
        raise SystemExit(f"REFUSED: Java mutants action {args.action!r} is closed")
    if getattr(args, "operator_profile", "v2") != "v2":
        raise SystemExit(
            "REFUSED: r2t-mutate-java has no historical v1 operator profile")
    try:
        enumerator = A.pinned_enumerator_identity("r2t/java/Mutate.java")
        outputs = [args.out] + ([args.raw_out]
                                if getattr(args, "raw_out", None) else [])
        fds = AUDIT.reserve_outputs(
            outputs, input_paths=(args.boundary, args.artifacts,
                                  getattr(args, "approval", None)))
        # The operator-reviewed release tree is a pre-Docker gate.  Authority
        # parsing below repeats this join before it opens the retained subset.
        reviewed_release = validate_population_release(
            args.artifacts, project=boundary.project,
            approval_path=getattr(args, "approval", None),
            approved_digest=getattr(args, "approved_digest", None))
        args._publication_protected_paths = tuple(
            getattr(args, "_publication_protected_paths", ())) + (
                getattr(args, "approval", None),
                reviewed_release["manifest_path"])
    except (A.MutationAssetRefused, OSError, RuntimeError, ValueError,
            TypeError, json.JSONDecodeError) as exc:
        message = str(exc)
        raise SystemExit(message if message.startswith("REFUSED:")
                         else "REFUSED: " + message) from exc
    from ..bench.cli import _require_bound_live_worker
    runtime = _require_bound_live_worker(args)
    roots = [spec.workspace for spec in runtime["pool_specs"]]
    try:
        authority = load_population_authority(
            args.artifacts, project=boundary.project, repo_roots=roots,
            runtime=runtime, approval_path=getattr(args, "approval", None),
            approved_digest=getattr(args, "approved_digest", None))
        from ..bench.harness import DockerRunner
        runner = DockerRunner(args.container, workdir=args.workdir)
        if boundary.project == "kapua":
            from ..java.kapua_population import stage_population_analysis as stage_kapua
            wanted = [row["source_root"] for row in authority["analysis_recipe"]["modules"]]
            if args.path and list(args.path) != wanted:
                raise ValueError("REFUSED: Kapua population requires every owning production root")
            recipe = stage_kapua(roots, authority)
            document = enumerate_modules_in_image(
                args.repo, recipe, runner=runner,
                expected_image_id=authority["image_id"],
                expected_enumerator_sha256=enumerator["sha256"])
        else:
            with image_classpath_export(
                    runner, authority["jars"],
                    forbidden_roots=(*roots, authority["root"])) as exported:
                recipe = stage_population_analysis(
                    roots, exported,
                    sourcepath_sha256=authority["sourcepath_sha256"])
            paths = list(args.path or DEFAULT_PATHS)
            document = enumerate_in_image(
                args.repo, paths, analysis_recipe=recipe, runner=runner,
                expected_image_id=authority["image_id"],
                expected_enumerator_sha256=enumerator["sha256"])
        manifest = population_for(
            document, sample=args.sample, seed=args.seed)
        AUDIT.write_reserved_json(fds[0], manifest)
        if getattr(args, "raw_out", None):
            AUDIT.write_reserved_json(fds[1], manifest)
    except (A.MutationAssetRefused, OSError, RuntimeError, ValueError,
            TypeError, json.JSONDecodeError) as exc:
        message = str(exc)
        raise SystemExit(message if message.startswith("REFUSED:")
                         else "REFUSED: " + message) from exc
    per_operator = {}
    for mutant in manifest["mutants"]:
        name = mutant["operator"]
        per_operator[name] = per_operator.get(name, 0) + 1
    print(json.dumps({
        "out": args.out, "n": manifest["n"],
        "n_excluded": manifest["n_excluded"],
        "files": document["files"], "digest": manifest["digest"],
        "engine": manifest["engine"], "parser": manifest["parser"],
        "analysis_recipe": manifest["analysis_recipe"]["digest"],
        "per_operator": dict(sorted(per_operator.items()))}, indent=1))
    return 0


def cmd_audit_assets(args) -> int:
    """Create one full image-owned audit and its mechanically derived index."""
    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT
    from ..core.boundary import load_boundary
    from ..data.profile import load_profile

    boundary = load_boundary(args.boundary, repo_root=args.audit_root)
    profile = load_profile(args.profile)
    if boundary.project not in _RELEVANT_REALITY_RUNS \
            or profile.project != boundary.project \
            or profile.framework != "cucumber":
        raise SystemExit(
            "REFUSED: Java audit boundary/profile names another stack")
    try:
        release = validate_population_release(
            args.artifacts, project=boundary.project,
            approval_path=args.approval,
            approved_digest=args.approved_digest)
        map_ids, map_release_sha256 = _map_release_inputs(
            release, args.release, args.coverage_run, kapua=boundary.project == "kapua")
        manifest, _manifest_raw = _json_object(
            args.manifest, "mutation population")
        mapping, _map_raw = _json_object(args.map, "mutation map")
        expected_map, coverage = _build_population_map(
            manifest, args.coverage_run,
            release_ids=map_ids,
            release_sha256=map_release_sha256,
            kapua_release=release if boundary.project == "kapua" else None,
            boundary_path=args.boundary, items_path=args.release)
        if mapping != expected_map:
            raise ValueError(
                "REFUSED: Java audit map does not rederive from gold coverage")
        validate_analysis_recipe(manifest["analysis_recipe"], args.audit_root)
        outputs = AUDIT.reserve_outputs(
            (args.audit_out, args.asset_index_out),
            input_paths=(args.manifest, args.map, args.coverage_run,
                         args.release, args.boundary, args.profile,
                         args.approval, args.docker_authority))
    except (A.MutationAssetRefused, OSError, RuntimeError, TypeError,
            ValueError, json.JSONDecodeError) as exc:
        message = str(exc)
        raise SystemExit(message if message.startswith("REFUSED:")
                         else "REFUSED: " + message) from exc

    from ..bench import cli
    from ..core.docker_cli import DockerEndpointRefused, configure
    args.cmd = "mutants"
    args.repo = None
    args.container = None
    args.workdir = None
    args.gold = os.path.join(args.artifacts, "reference-gold")
    args.out = args.audit_out
    args._publication_protected_paths = (
        args.approval, release["manifest_path"], args.manifest, args.map,
        args.coverage_run, args.release, args.audit_root,
        args.asset_index_out)
    try:
        configure(authority_path=args.docker_authority)
        cli._apply_worker(args)
        runtime = cli._require_bound_live_worker(args)
        roots = [spec.workspace for spec in runtime["pool_specs"]]
        authority = load_population_authority(
            args.artifacts, project=boundary.project,
            repo_roots=[args.audit_root, *roots], runtime=runtime,
            approval_path=args.approval,
            approved_digest=args.approved_digest)
        from ..bench.harness import DockerRunner
        runner = DockerRunner(args.container, workdir=args.workdir)
        audit = audit_population_in_image(
            manifest, args.audit_root, runner=runner,
            expected_image_id=authority["image_id"], timeout=args.timeout,
            workers=args.audit_workers)
        index = build_asset_index(
            boundary.project, manifest=manifest,
            manifest_path=args.manifest, mapping=mapping,
            coverage_path=args.coverage_run, release_path=args.release,
            boundary_path=args.boundary, audit=audit)
        A.validate_index_binding(
            index, boundary.project, raw_manifest=manifest,
            scored_manifest=manifest, mapping=mapping,
            boundary_path=args.boundary,
            coverage_path=args.coverage_run,
            release_path=args.release,
            engine_source_path=JAVA_SOURCE,
            raw_manifest_path=args.manifest,
            audit_attestation=audit,
            require_release_ready=True)
        AUDIT.write_reserved_json(outputs[0], audit)
        AUDIT.write_reserved_json(outputs[1], index)
    except (A.MaterialisationAuditRefused, A.MutationAssetRefused,
            DockerEndpointRefused, OSError, RuntimeError, SystemExit,
            TypeError, ValueError, json.JSONDecodeError) as exc:
        message = str(exc)
        raise SystemExit(message if message.startswith("REFUSED:")
                         else "REFUSED: " + message) from exc
    print(json.dumps({
        "project": boundary.project,
        "mutants": manifest["n"],
        "mapped": expected_map["n_mapped"],
        "coverage_items": len(coverage),
        "audit": os.path.abspath(args.audit_out),
        "audit_digest": audit["digest"],
        "asset_index": os.path.abspath(args.asset_index_out),
        "image_id": authority["image_id"],
    }, indent=1, sort_keys=True))
    return 0


def operator_main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m r2t.toolkit.mutation_java")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser(
        "audit-assets",
        help="audit one complete Java population in its reviewed image")
    for name in ("boundary", "profile", "artifacts", "approval",
                 "approved-digest", "worker", "docker-authority",
                 "manifest", "map", "coverage-run", "release",
                 "audit-root", "audit-out", "asset-index-out"):
        audit.add_argument("--" + name, required=True)
    audit.add_argument("--timeout", type=int, default=300)
    audit.add_argument(
        "--audit-workers", type=int, default=DEFAULT_AUDIT_WORKERS,
        help="concurrent audit trees/session containers (owner ruling: 16)")
    args = parser.parse_args(argv)
    if args.audit_workers < 1:
        raise SystemExit(
            "REFUSED: --audit-workers must be an integer >= 1")
    return cmd_audit_assets(args)


#: The EXACT `java.class.path` Surefire 3.0.0-M5 recorded for `algorand-sdk`,
#: read out of `runs/unit-ordinary/.../TEST-…R2TBenchCucumberTest.xml` in
#: reality attempt-5 and byte-identical in all four non-stripped runs of the
#: v11, v12 and v13 releases -- three reality chains, three canonical images.
#: It is the fixture `reality_classpath_entries` is probed on, because the
#: synthetic three-entry string below is exactly what let its trailing-
#: separator behaviour go untested until the first live `mutants build`.
#: 56 `split(":")` elements, of which the 56th is empty.
_REALITY_CLASSPATH_ALGORAND = (
    "/work/target/test-classes:"
    "/work/target/classes:"
    "/opt/m2/com/fasterxml/jackson/core/jackson-annotations/2.18.6/jackson-annotations-2.18.6.jar:"
    "/opt/m2/com/fasterxml/jackson/core/jackson-core/2.18.6/jackson-core-2.18.6.jar:"
    "/opt/m2/com/fasterxml/jackson/core/jackson-databind/2.18.6/jackson-databind-2.18.6.jar:"
    "/opt/m2/com/google/code/gson/gson/2.8.9/gson-2.8.9.jar:"
    "/opt/m2/com/squareup/okhttp/logging-interceptor/2.7.5/logging-interceptor-2.7.5.jar:"
    "/opt/m2/com/squareup/okhttp/okhttp/2.7.5/okhttp-2.7.5.jar:"
    "/opt/m2/com/squareup/okio/okio/1.17.6/okio-1.17.6.jar:"
    "/opt/m2/commons-codec/commons-codec/1.19.0/commons-codec-1.19.0.jar:"
    "/opt/m2/io/gsonfire/gson-fire/1.8.0/gson-fire-1.8.0.jar:"
    "/opt/m2/io/swagger/swagger-annotations/1.5.18/swagger-annotations-1.5.18.jar:"
    "/opt/m2/org/apache/commons/commons-lang3/3.18.0/commons-lang3-3.18.0.jar:"
    "/opt/m2/org/bouncycastle/bcprov-jdk15to18/1.78/bcprov-jdk15to18-1.78.jar:"
    "/opt/m2/org/msgpack/jackson-dataformat-msgpack/0.9.9/jackson-dataformat-msgpack-0.9.9.jar:"
    "/opt/m2/org/msgpack/msgpack-core/0.9.9/msgpack-core-0.9.9.jar:"
    "/opt/m2/org/threeten/threetenbp/1.3.5/threetenbp-1.3.5.jar:"
    "/opt/m2/com/google/guava/guava/32.0.1-android/guava-32.0.1-android.jar:"
    "/opt/m2/com/google/guava/failureaccess/1.0.1/failureaccess-1.0.1.jar:"
    "/opt/m2/com/google/guava/listenablefuture/9999.0-empty-to-avoid-conflict-with-guava/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar:"
    "/opt/m2/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar:"
    "/opt/m2/org/checkerframework/checker-qual/3.33.0/checker-qual-3.33.0.jar:"
    "/opt/m2/com/google/errorprone/error_prone_annotations/2.18.0/error_prone_annotations-2.18.0.jar:"
    "/opt/m2/com/google/j2objc/j2objc-annotations/2.8/j2objc-annotations-2.8.jar:"
    "/opt/m2/org/assertj/assertj-core/3.27.7/assertj-core-3.27.7.jar:"
    "/opt/m2/net/bytebuddy/byte-buddy/1.18.3/byte-buddy-1.18.3.jar:"
    "/opt/m2/org/junit/jupiter/junit-jupiter/5.6.2/junit-jupiter-5.6.2.jar:"
    "/opt/m2/org/junit/jupiter/junit-jupiter-engine/5.6.2/junit-jupiter-engine-5.6.2.jar:"
    "/opt/m2/org/junit/jupiter/junit-jupiter-api/5.6.2/junit-jupiter-api-5.6.2.jar:"
    "/opt/m2/org/apiguardian/apiguardian-api/1.1.0/apiguardian-api-1.1.0.jar:"
    "/opt/m2/org/opentest4j/opentest4j/1.2.0/opentest4j-1.2.0.jar:"
    "/opt/m2/org/junit/platform/junit-platform-commons/1.6.2/junit-platform-commons-1.6.2.jar:"
    "/opt/m2/org/junit/vintage/junit-vintage-engine/5.6.2/junit-vintage-engine-5.6.2.jar:"
    "/opt/m2/org/junit/platform/junit-platform-engine/1.6.2/junit-platform-engine-1.6.2.jar:"
    "/opt/m2/junit/junit/4.13/junit-4.13.jar:"
    "/opt/m2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar:"
    "/opt/m2/org/junit/jupiter/junit-jupiter-params/5.6.2/junit-jupiter-params-5.6.2.jar:"
    "/opt/m2/org/mockito/mockito-core/3.5.7/mockito-core-3.5.7.jar:"
    "/opt/m2/net/bytebuddy/byte-buddy-agent/1.10.13/byte-buddy-agent-1.10.13.jar:"
    "/opt/m2/org/objenesis/objenesis/3.1/objenesis-3.1.jar:"
    "/opt/m2/io/cucumber/cucumber-java/6.6.0/cucumber-java-6.6.0.jar:"
    "/opt/m2/io/cucumber/cucumber-core/6.6.0/cucumber-core-6.6.0.jar:"
    "/opt/m2/io/cucumber/cucumber-gherkin/6.6.0/cucumber-gherkin-6.6.0.jar:"
    "/opt/m2/io/cucumber/cucumber-gherkin-messages/6.6.0/cucumber-gherkin-messages-6.6.0.jar:"
    "/opt/m2/io/cucumber/messages/13.0.1/messages-13.0.1.jar:"
    "/opt/m2/io/cucumber/tag-expressions/3.0.0/tag-expressions-3.0.0.jar:"
    "/opt/m2/io/cucumber/cucumber-expressions/10.3.0/cucumber-expressions-10.3.0.jar:"
    "/opt/m2/io/cucumber/datatable/3.4.0/datatable-3.4.0.jar:"
    "/opt/m2/io/cucumber/cucumber-plugin/6.6.0/cucumber-plugin-6.6.0.jar:"
    "/opt/m2/io/cucumber/docstring/6.6.0/docstring-6.6.0.jar:"
    "/opt/m2/io/cucumber/html-formatter/9.0.0/html-formatter-9.0.0.jar:"
    "/opt/m2/io/cucumber/create-meta/2.0.1/create-meta-2.0.1.jar:"
    "/opt/m2/io/cucumber/cucumber-junit/6.6.0/cucumber-junit-6.6.0.jar:"
    "/opt/m2/io/cucumber/cucumber-picocontainer/6.6.0/cucumber-picocontainer-6.6.0.jar:"
    "/opt/m2/org/picocontainer/picocontainer/2.15/picocontainer-2.15.jar:")
_REALITY_CLASSPATH_ALGORAND_SHA256 = (
    "21649431b4a4aa85b8440ad2cd43995b6ffba2cf71e0effbf958c8b301e8c2ba")


def module_analysis_selftest(scratch_parent: Optional[str] = None) -> bool:
    """Exercise two owning compiler contexts without running javac or Docker."""
    with tempfile.TemporaryDirectory(
            prefix="r2t-java-modules-", dir=scratch_parent) as root:
        paths = {
            "a-module/src/main/java/a/A.java": "package a; class A {}\n",
            "a-module/src/main/java/a/Empty.java":
                "package a; class Empty {}\n",
            "b-module/src/main/java/b/B.java": "package b; class B {}\n",
            "b-module/target/generated-sources/annotations/b/BMapperImpl.java":
                "package b; class BMapperImpl {}\n",
        }
        for rel, content in paths.items():
            destination = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with open(destination, "w", encoding="utf-8") as handle:
                handle.write(content)
        for rel in ("a-module/target/classes", "b-module/target/classes",
                    "deps/shared", "deps/a", "deps/b"):
            os.makedirs(os.path.join(root, *rel.split("/")), exist_ok=True)
        manifest_jars = (
            "var/bench_java_analysis/m2/com/sun/xml/bind/jaxb-core/"
            "2.3.0.1/jaxb-core-2.3.0.1.jar",
            "var/bench_java_analysis/m2/org/glassfish/jaxb/jaxb-runtime/"
            "2.3.1/jaxb-runtime-2.3.1.jar",
        )
        manifest_paths = []
        for manifest_jar in manifest_jars:
            manifest_path = os.path.join(root, *manifest_jar.split("/"))
            manifest_paths.append(manifest_path)
            os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
            expected = _KAPUA_ABSENT_MANIFEST_CLASSPATHS[manifest_jar]
            with zipfile.ZipFile(manifest_path, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nClass-Path: "
                    + " ".join(expected) + "\n\n")
        a_recipe = make_analysis_recipe(
            root,
            classpath=("a-module/target/classes", "deps/shared", "deps/a"),
            sourcepath=("a-module/src/main/java",))
        b_recipe = make_module_analysis_child_recipe(
            root, "b-module",
            classpath=("b-module/target/classes", "deps/b", "deps/shared",
                       *manifest_jars))
        compiler8 = {
            "java_home": "/opt/java/openjdk8",
            "parser": "javac 1.8 [Fixture; runtime=1.8]",
            "encoding": "UTF-8",
            "source": "1.6", "target": "1.6", "release": None,
            "runtime_executable_sha256": "1" * 64,
            "compiler_executable_sha256": "2" * 64,
            "tools_jar_sha256": "3" * 64,
        }
        compiler17 = {
            "java_home": "/opt/java/openjdk",
            "parser": "javac 17 [Fixture; runtime=17]",
            "encoding": "UTF-8",
            "source": "11", "target": "11", "release": None,
            "runtime_executable_sha256": "4" * 64,
            "compiler_executable_sha256": "5" * 64,
            "tools_jar_sha256": None,
        }
        module_rows = [
            {"module": "a-module", "source_root":
             "a-module/src/main/java", "source_files": sorted(
                 rel for rel in paths if rel.startswith(
                     "a-module/src/main/java/")),
             "compiler": compiler8, "recipe": a_recipe},
            {"module": "b-module", "source_root":
             "b-module/src/main/java", "source_files": sorted(
                 rel for rel in paths if rel.startswith(
                     "b-module/src/main/java/")),
             "compiler": compiler17, "recipe": b_recipe},
        ]
        authority = make_module_analysis_recipe(root, module_rows)
        legacy_manifest_refused = False
        try:
            make_analysis_recipe(
                root, classpath=manifest_jars,
                sourcepath=("b-module/src/main/java",))
        except ValueError as exc:
            legacy_manifest_refused = "manifest Class-Path" in str(exc)

        def row(file_name: str) -> dict:
            return {"file": file_name, "start_line": 1, "start_col": 1,
                    "end_line": 1, "end_col": 7,
                    "operator": "ReturnValue", "original": "package",
                    "mutated": "return null;", "class": "Fixture",
                    "method": "fixture"}

        envelopes = []
        for module_row, mutants, files in (
                (authority["modules"][0], [row(
                    "a-module/src/main/java/a/A.java")], 2),
                (authority["modules"][1], [row(
                    "b-module/src/main/java/b/B.java")], 1)):
            envelopes.append({"module": module_row["module"], "envelope": {
                "engine": ENGINE, "engine_version": ENGINE_VERSION,
                "parser": module_row["compiler"]["parser"],
                "files": files, "errors": {}, "mutants": mutants,
                "enumerator_rev": ENUMERATOR_REV,
                "analysis_recipe": module_row["recipe"],
            }})
        merged = merge_module_envelopes(authority, envelopes)
        population = population_for(
            merged, expected_parser=module_analysis_parser(authority))

        def refused(callable_, needle: str) -> bool:
            try:
                callable_()
            except ValueError as exc:
                return needle in str(exc)
            return False

        from ..bench.cli import _mutation_java_analysis_root
        from types import SimpleNamespace
        root_args = SimpleNamespace(java_analysis_root=root)
        manifest = {"engine": ENGINE, "analysis_recipe": authority}
        assert _mutation_java_analysis_root(root_args, manifest, [root]) == root
        with tempfile.TemporaryDirectory(prefix="r2t-java-worker-") as worker:
            for rel, content in paths.items():
                destination = os.path.join(worker, rel)
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                with open(destination, "w", encoding="utf-8") as handle:
                    handle.write(content)
            assert _mutation_java_analysis_root(root_args, manifest, [root, worker]) == root
            with open(os.path.join(worker, "a-module/src/main/java/a/A.java"), "a") as handle:
                handle.write("// changed original source\n")
            try:
                _mutation_java_analysis_root(root_args, manifest, [root, worker])
            except SystemExit as exc:
                assert "worker production source differs" in str(exc)
            else:
                raise AssertionError("second worker's source drift accepted")
        changed_input = os.path.join(root, "deps/a/changed.class")
        with open(changed_input, "wb") as handle:
            handle.write(b"changed captured dependency")
        try:
            _mutation_java_analysis_root(root_args, manifest, [root])
        except SystemExit as exc:
            assert "is stale" in str(exc)
        else:
            raise AssertionError("changed compiler capture accepted")
        finally:
            os.unlink(changed_input)

        changed_recipe = make_analysis_recipe(
            root,
            classpath=("b-module/target/classes", "deps/shared", "deps/b"),
            sourcepath=("b-module/src/main/java",))
        changed_rows = [dict(module_rows[0]),
                        dict(module_rows[1], recipe=changed_recipe)]
        changed_authority = make_module_analysis_recipe(root, changed_rows)
        missing_source = [dict(module_rows[0], source_files=[
            "a-module/src/main/java/a/A.java"]), module_rows[1]]

        class ProbeRunner:
            def __init__(self):
                self.homes = []

            def probe_isolated_java_toolchain(self, *, timeout, java_home):
                del timeout
                self.homes.append(java_home)
                compiler = (compiler8 if java_home.endswith("openjdk8")
                            else compiler17)
                version = "1.8" if java_home.endswith("openjdk8") else "17"
                tools = (compiler["tools_jar_sha256"] + "  tools.jar"
                         if compiler["tools_jar_sha256"] else "none")
                output = (
                    f"{TOOLCHAIN_JAVAC_MARKER}\njavac {version}\n"
                    f"{TOOLCHAIN_JAVA_MARKER}\n"
                    f"java.version = {version}\njava.vendor = Fixture\n"
                    f"java.runtime.version = {version}\n"
                    f"{TOOLCHAIN_JAVA_SHA_MARKER}\n"
                    f"{compiler['runtime_executable_sha256']}  java\n"
                    f"{TOOLCHAIN_JAVAC_SHA_MARKER}\n"
                    f"{compiler['compiler_executable_sha256']}  javac\n"
                    f"{TOOLCHAIN_TOOLS_JAR_SHA_MARKER}\n{tools}\n")
                return subprocess.CompletedProcess([], 0, output, "")

        probe_runner = ProbeRunner()
        observed = validate_module_toolchains(authority, probe_runner)
        bad_compiler = dict(
            compiler8, runtime_executable_sha256="6" * 64)
        bad_tool_rows = [dict(module_rows[0], compiler=bad_compiler),
                         module_rows[1]]
        bad_tool_authority = make_module_analysis_recipe(root, bad_tool_rows)
        present_target_refused = []
        for manifest_path, target_name in zip(
                manifest_paths, ("jaxb-api.jar", "jaxb-api-2.3.1.jar")):
            absent_target = os.path.join(
                os.path.dirname(manifest_path), target_name)
            with open(absent_target, "wb") as handle:
                handle.write(b"unexpected adjacent bytes")
            present_target_refused.append(refused(
                lambda: validate_analysis_recipe(authority, root),
                "measured-absent"))
            os.unlink(absent_target)
        return (
            validate_analysis_recipe(authority, root) is authority
            and analysis_recipe_for_path(
                authority, "a-module/src/main/java/a/A.java") == a_recipe
            and analysis_recipe_for_path(
                authority, "b-module/src/main/java/b/B.java") == b_recipe
            and analysis_compiler_argv(
                authority, "a-module/src/main/java/a/A.java")
                == ["--source-level", "1.6", "--target-level", "1.6"]
            and merged["files"] == 3 and len(merged["mutants"]) == 2
            and population["n"] == 2
            and population["analysis_recipe"] == authority
            and not analysis_path_covers(authority,
                "b-module/target/generated-sources/annotations/b/BMapperImpl.java")
            and changed_authority["digest"] != authority["digest"]
            and refused(lambda: analysis_recipe_for_path(
                authority, "b-module/src/main/java/b/Missing.java"),
                "0 module recipes")
            and refused(lambda: make_module_analysis_recipe(
                root, missing_source), "membership differs")
            and refused(lambda: merge_module_envelopes(
                authority, envelopes[:1]), "missing or extra modules")
            and sorted(observed) == sorted(_MODULE_JAVA_HOMES)
            and sorted(probe_runner.homes) == sorted(_MODULE_JAVA_HOMES)
            and legacy_manifest_refused and all(present_target_refused)
            and refused(lambda: validate_module_toolchains(
                bad_tool_authority, ProbeRunner()), "bytes differ")
            and analysis_compiler_for_path(a_recipe,
                "a-module/src/main/java/a/A.java") is None)


def module_analysis_compiled_selftest() -> bool:
    """Compile, enumerate and apply against two incompatible module contexts."""
    java = _tool("java", os.environ.get("R2T_JAVA"))
    javac = _tool("javac", os.environ.get("R2T_JAVAC"))
    parser = probe_parser_version(java=java)
    if not parser.startswith("javac 17"):
        raise RuntimeError(
            "REFUSED: composite compiler fixture requires the checked JDK 17")
    with tempfile.TemporaryDirectory(prefix="r2t-java-module-compiled-") as base:
        root = os.path.join(base, "analysis")
        os.mkdir(root)

        def write(rel: str, content: str) -> None:
            destination = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with open(destination, "w", encoding="utf-8") as handle:
                handle.write(content)

        write("a-module/src/main/java/a/A.java",
              "package a; class A { String f() { return dep.Api.value(); } }\n")
        write("b-module/src/main/java/b/B.java",
              "package b; class B { int f() { return dep.Api.value(); } }\n")
        write("deps/a-src/dep/Api.java",
              "package dep; public class Api { public static String value() "
              "{ return \"a\"; } }\n")
        write("deps/b-src/dep/Api.java",
              "package dep; public class Api { public static int value() "
              "{ return 1; } }\n")
        for rel in ("a-module/target/classes", "b-module/target/classes",
                    "deps/a", "deps/b"):
            os.makedirs(os.path.join(root, *rel.split("/")), exist_ok=True)
        for source, output in (("deps/a-src/dep/Api.java", "deps/a"),
                               ("deps/b-src/dep/Api.java", "deps/b")):
            cp = subprocess.run(
                [javac, "-proc:none", "-d", os.path.join(root, output),
                 os.path.join(root, source)], capture_output=True, text=True,
                env=sanitised_java_env(), timeout=60)
            if cp.returncode != 0:
                raise RuntimeError(
                    "REFUSED: compiling module fixture dependency failed: "
                    + (cp.stderr or cp.stdout)[-500:])
        settings = "a-module/target/classes/kapua-environment-setting.properties"
        write(settings, "fixture.mode=compiler-capture\n")
        a_recipe = make_analysis_recipe(
            root, classpath=("a-module/target/classes", "deps/a"),
            sourcepath=("a-module/src/main/java",))
        b_recipe = make_analysis_recipe(
            root, classpath=("b-module/target/classes", "deps/b"),
            sourcepath=("b-module/src/main/java",))
        with open(java, "rb") as handle:
            java_hash = hashlib.sha256(handle.read()).hexdigest()
        with open(javac, "rb") as handle:
            javac_hash = hashlib.sha256(handle.read()).hexdigest()
        compiler = {
            "java_home": "/opt/java/openjdk", "parser": parser,
            "encoding": "UTF-8", "source": "8", "target": "8",
            "release": None, "runtime_executable_sha256": java_hash,
            "compiler_executable_sha256": javac_hash,
            "tools_jar_sha256": None,
        }
        compiler_release = dict(
            compiler, source=None, target=None, release="11")
        authority = make_module_analysis_recipe(root, (
            {"module": "a-module", "source_root":
             "a-module/src/main/java", "source_files": [
                 "a-module/src/main/java/a/A.java"],
             "compiler": compiler, "recipe": a_recipe},
            {"module": "b-module", "source_root":
             "b-module/src/main/java", "source_files": [
                 "b-module/src/main/java/b/B.java"],
             "compiler": compiler_release, "recipe": b_recipe},
        ))
        with open(JAVA_SOURCE, "rb") as handle:
            source_sha = hashlib.sha256(handle.read()).hexdigest()
        supplied = []
        for row in authority["modules"]:
            binding = analysis_binding_for_path(
                authority, row["source_files"][0])
            document = enumerate_local(
                root, [row["source_root"]],
                analysis_recipe=binding["recipe"],
                compiler_argv=binding["compiler_argv"], javac=javac,
                java=java, expected_enumerator_sha256=source_sha)
            supplied.append({"module": row["module"], "envelope": document})
        merged = merge_module_envelopes(authority, supplied)
        if merged["files"] != 2 or not merged["mutants"]:
            return False

        wrong_b = make_analysis_recipe(
            root, classpath=("b-module/target/classes", "deps/a"),
            sourcepath=("b-module/src/main/java",))
        wrong_rejected = False
        try:
            enumerate_local(
                root, ["b-module/src/main/java"],
                analysis_recipe=wrong_b,
                compiler_argv=("--release-level", "11"), javac=javac,
                java=java, expected_enumerator_sha256=source_sha)
        except ValueError as exc:
            wrong_rejected = "failed files" in str(exc)

        engine_classes = os.path.join(base, "engine")
        _compiled_javac, tools = compile_engine(
            engine_classes, javac=javac)
        engine_cp = _runtime_classpath(engine_classes, tools)

        def apply_one(source: str, *, wrong_recipe=None) -> bool:
            binding = analysis_binding_for_path(authority, source)
            candidate = next(row for row in merged["mutants"]
                             if row["file"] == source)
            write_root = os.path.join(
                base, "write-" + source.split("/", 1)[0]
                + ("-wrong" if wrong_recipe else ""))
            shutil.copytree(root, write_root)
            # The real Kapua worker lacks compiler dependencies and carries
            # its own settings in a captured classpath tree. Neither may be
            # replaced merely to make the immutable compiler recipe usable.
            shutil.rmtree(os.path.join(write_root, "deps"))
            worker_settings = os.path.join(write_root, settings)
            with open(worker_settings, "w", encoding="utf-8") as handle:
                handle.write("fixture.mode=worker-runtime\n")
            validate_module_analysis_sources(write_root, authority)
            recipe = wrong_recipe or binding["recipe"]
            with open(os.path.join(root, source), "rb") as handle:
                before = handle.read()
            with analysis_snapshot(root, authority, required_sources=[source]) as snapshot:
                argv = [java, "-cp", engine_cp, "Mutate", "--root", snapshot,
                        "--write-root", write_root, "--operator-profile", "v2",
                        "--apply-file", source,
                        "--start-line", str(candidate["start_line"]),
                        "--start-col", str(candidate["start_col"]),
                        "--operator", candidate["operator"],
                        "--original", candidate["original"],
                        "--mutated", candidate["mutated"], "--out", source,
                        *analysis_argv(snapshot, recipe),
                        *binding["compiler_argv"]]
                cp = subprocess.run(
                    argv, capture_output=True, text=True,
                    env=sanitised_java_env(), timeout=120)
            target = os.path.join(write_root, source)
            with open(target, "rb") as handle:
                after = handle.read()
            if cp.returncode == 0 and before != after:
                try:
                    validate_module_analysis_sources(write_root, authority)
                except ValueError as exc:
                    assert "worker production source differs" in str(exc)
                else:
                    raise AssertionError("mutated worker source accepted as original")
            with open(target, "wb") as handle:
                handle.write(before)
            validate_module_analysis_sources(write_root, authority)
            revalidate_analysis_inputs(root, authority)
            with open(worker_settings, encoding="utf-8") as handle:
                assert handle.read() == "fixture.mode=worker-runtime\n"
            assert not os.path.exists(os.path.join(write_root, "deps"))
            return cp.returncode == 0 and before != after

        return (wrong_rejected
                and apply_one("a-module/src/main/java/a/A.java")
                and apply_one("b-module/src/main/java/b/B.java")
                and not apply_one(
                    "b-module/src/main/java/b/B.java", wrong_recipe=wrong_b))


def selftest() -> int:
    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    def raises(fn, needle=""):
        try:
            fn()
        except Exception as exc:                         # noqa: BLE001
            return needle in str(exc)
        return False

    check("identity is read from the Java producer",
          ENGINE == "r2t-mutate-java" and ENGINE_VERSION == "1.0"
          and ENUMERATOR_REV.startswith(ENGINE + "/"))
    check("Java ids occupy neither existing engine's namespace",
          ENGINE not in {M.ENGINE, "r2t-mutate-py"})
    check("the current producer revision has one authenticated registry pin",
          A.pinned_enumerator_revision("r2t/java/Mutate.java")
          == ENUMERATOR_REV)
    ap = applier()
    check("the Java applier is staged under var and launched as a compiled class",
          ap.source == "Mutate.java" and ap.rel.startswith("var/")
          and ap.interpreter == "java" and ap.entrypoint == "Mutate"
          and ap.classes_rel == "var/bench_mutate/classes")
    check("Kapua module authority routes two distinct compiler contexts, "
          "preserves zero-mutant files, and refuses incomplete membership",
          module_analysis_selftest())
    check("Kapua module enumeration and application use incompatible owning "
          "dependencies under distinct Java 8-source and Java 11-release "
          "contexts",
          module_analysis_compiled_selftest())

    row = {"file": "src/main/java/p/C.java",
           "start_line": 2, "start_col": 4, "end_line": 2, "end_col": 8,
           "operator": "ReturnValue", "original": "return x;",
           "mutated": "return null;", "class": "C", "method": "f"}
    fixture_recipe = {"schema": ANALYSIS_SCHEMA, "classpath": [],
                      "sourcepath": [{"path": "src/main/java",
                                      "kind": "tree", "sha256": "a" * 64}],
                      "module_path": []}
    fixture_recipe["digest"] = _canonical_sha256(fixture_recipe)
    envelope = {"engine": ENGINE, "engine_version": ENGINE_VERSION,
                "parser": "javac fixture", "files": 1, "errors": {},
                "mutants": [row], "n_invalid": 2,
                "enumerator_rev": ENUMERATOR_REV,
                "analysis_recipe": fixture_recipe}
    manifest = population_for(envelope, expected_parser="javac fixture")
    check("the complete envelope reaches a v2 Java manifest",
          manifest["engine"] == ENGINE
          and manifest["operators"] == list(M.OPERATORS)
          and manifest["n_invalid"] == 2
          and manifest["enumerator_rev"] == ENUMERATOR_REV
          and manifest["analysis_recipe"]["digest"]
          == envelope["analysis_recipe"]["digest"])
    check("unknown envelope fields and producer errors fail closed",
          raises(lambda: validate_envelope(dict(envelope, surprise=True)),
                 "fields differ")
          and raises(lambda: validate_envelope(dict(envelope,
                                                    errors={"C.java": "bad"})),
                     "failed files"))
    check("a foreign engine and a missing revision cannot mint Java ids",
          raises(lambda: validate_envelope(dict(envelope,
                                                engine="r2t-mutate-py")),
                 "expected")
          and raises(lambda: validate_envelope(
              {k: v for k, v in envelope.items() if k != "enumerator_rev"}),
                     "expected"))
    forged_recipe = json.loads(json.dumps(envelope))
    forged_recipe["analysis_recipe"]["digest"] = "0" * 64
    check("a missing or re-digested Java analysis authority fails closed",
          raises(lambda: validate_envelope(
              {k: v for k, v in envelope.items()
               if k != "analysis_recipe"}), "analysis recipe")
          and raises(lambda: validate_envelope(forged_recipe),
                     "digest does not recompute"))
    outside_recipe = dict(envelope, analysis_recipe=empty_analysis_recipe())
    outside_manifest = json.loads(json.dumps(manifest))
    outside_manifest["analysis_recipe"] = empty_analysis_recipe()
    outside_manifest["digest"] = M.manifest_digest(outside_manifest)
    check("every Java row must live under authenticated sourcepath authority",
          raises(lambda: validate_envelope(outside_recipe),
                 "outside its authenticated sourcepath")
          and raises(lambda: build_population(
              [row], parser_version="javac fixture",
              enumerator_rev=ENUMERATOR_REV,
              analysis_recipe=empty_analysis_recipe()),
                     "outside its authenticated sourcepath")
          and raises(lambda: A.validate_manifest(outside_manifest),
                     "outside its authenticated sourcepath"))
    check("zero invalid metadata has one encoding: absence",
          raises(lambda: validate_envelope(dict(envelope, n_invalid=0)),
                 "omitted"))
    classpath_value = (
        "/work/target/test-classes:/work/target/classes:"
        "/opt/m2/org/example/dep.jar")
    report = (
        '<testsuite><properties><property name="java.class.path" value="'
        + classpath_value + '"/></properties></testsuite>').encode("utf-8")
    check("Surefire authority exposes one exact classpath and rejects XML "
          "with duplicate classpath facts",
          _surefire_classpath(report, "selftest") == classpath_value
          and raises(lambda: _surefire_classpath(
              report.replace(b"</properties>", report.split(
                  b"<properties>", 1)[1].split(b"</properties>", 1)[0]
                  + b"</properties>"), "selftest"),
                     "unique nonempty"))

    # ---- the reality classpath rule, probed on PRODUCTION bytes ----------
    #
    # The synthetic string above is retained (it is a legitimate shape and
    # `_surefire_classpath` is still checked against it), but it is not the
    # witness for anything below: every check here runs on the exact bytes
    # Surefire wrote for `algorand-sdk`.
    real = _REALITY_CLASSPATH_ALGORAND
    check("the pinned Algorand reality classpath is the measured production "
          "string and not an edited copy of it",
          hashlib.sha256(real.encode("utf-8")).hexdigest()
          == _REALITY_CLASSPATH_ALGORAND_SHA256)
    # ANTI-VACUITY.  If the fixture were ever "fixed" by deleting its trailing
    # separator, the acceptance below would pass without the tolerance ever
    # running.  These two say the fixture still exercises it.
    check("the pinned production classpath really does carry the trailing "
          "empty element the rule tolerates",
          real.endswith(":") and "" in real.split(":")
          and len(real.split(":")) == 56)
    entries = reality_classpath_entries(real)
    check("the production classpath is ACCEPTED, and the tolerance consumes "
          "exactly the trailing element",
          len(entries) == 55 and "" not in entries
          and tuple(entries[:2]) == _REALITY_WORKSPACE_CLASSPATH
          and all(entry.startswith("/opt/m2/") and entry.endswith(".jar")
                  for entry in entries[2:]))
    head = ":".join(_REALITY_WORKSPACE_CLASSPATH)
    check("an empty element anywhere but the end is still refused -- there it "
          "is `.`, not punctuation",
          raises(lambda: reality_classpath_entries(
              head + "::/opt/m2/org/example/dep.jar"),
                 "empty, relative, or repeated")
          and raises(lambda: reality_classpath_entries(
              head + ":/opt/m2/org/example/dep.jar::"),
                     "empty, relative, or repeated")
          and raises(lambda: reality_classpath_entries(":"),
                     "empty, relative, or repeated")
          and raises(lambda: reality_classpath_entries(""),
                     "empty, relative, or repeated"))
    check("tolerating the trailing separator weakens nothing else: relative, "
          "repeated and workspace-shaped entries still refuse",
          raises(lambda: reality_classpath_entries(
              head + ":opt/m2/org/example/dep.jar:"),
                 "empty, relative, or repeated")
          and raises(lambda: reality_classpath_entries(
              head + ":/opt/m2/org/example/dep.jar:"
              "/opt/m2/org/example/dep.jar:"),
                     "empty, relative, or repeated")
          and raises(lambda: reality_classpath_entries(
              head + ":/work/target/extra:"),
                     "workspace entries differ"))
    # EPUBCheck is NOT covered by this change and this check says so on its
    # own bytes.  Its pom pins Surefire 2.18.1, which dumps the MAVEN
    # process's system properties into the report, so the recorded
    # `java.class.path` is Maven's launcher jar and the project's test
    # classpath is absent from the retained evidence entirely.  That is an
    # open decision item (RECONCILIATION, 2026-08-12), not something this
    # commit may paper over -- so the refusal is pinned rather than relaxed.
    check("EPUBCheck's recorded reality classpath is still REFUSED, at the "
          "workspace-head check, and this change does not touch that",
          raises(lambda: reality_classpath_entries(
              "/usr/share/maven/boot/plexus-classworlds-2.7.0.jar"),
                 "workspace entries differ"))

    jar_raw = b"selftest dependency bytes"
    jar_row = {
        "image_path": "/opt/m2/org/example/dep.jar",
        "path": "org/example/dep.jar", "bytes": len(jar_raw),
        "sha256": hashlib.sha256(jar_raw).hexdigest(),
    }

    class ExportRunner:
        workdir = "/work"

        def __init__(self, payload):
            self.payload = payload

        def run_isolated_java(self, _command, **kwargs):
            with open(os.path.join(
                    kwargs["workspace_host"], "0000-dep.jar"), "wb") as fh:
                fh.write(self.payload)
            return subprocess.CompletedProcess([], 0, "", "")

    def changed_export():
        with image_classpath_export(ExportRunner(b"changed"), [jar_row]):
            pass

    check("canonical-image JAR export re-hashes copied bytes",
          raises(changed_export, "differs from approved M2"))

    parser_identity = "javac 17.0.1 [Fixture Vendor; runtime=17.0.1+1]"
    tool_hash_output = (
        TOOLCHAIN_JAVA_SHA_MARKER + "\n" + "1" * 64 + "  /java\n"
        + TOOLCHAIN_JAVAC_SHA_MARKER + "\n" + "2" * 64 + "  /javac\n"
        + TOOLCHAIN_TOOLS_JAR_SHA_MARKER + "\nnone\n")

    with tempfile.TemporaryDirectory(prefix="r2t-java-image-audit-") \
            as audit_root:
        source_path = os.path.join(
            audit_root, "src", "main", "java", "p", "C.java")
        os.makedirs(os.path.dirname(source_path))
        original_source = b"package p;\n   return x;\n"
        with open(source_path, "wb") as handle:
            handle.write(original_source)
        with open(os.path.join(audit_root, A.DISPOSABLE_MARKER), "w",
                  encoding="utf-8") as handle:
            handle.write(AUDIT.DISPOSABLE_MARKER_CONTENT)
        audit_recipe = make_analysis_recipe(
            audit_root, sourcepath=[SOURCEPATH])
        audit_row = {
            "file": "src/main/java/p/C.java",
            "start_line": 2, "start_col": 4,
            "end_line": 2, "end_col": 12,
            "operator": "ReturnValue", "original": "return x;",
            "mutated": "return null;", "class": "C", "method": "f",
        }
        audit_manifest = build_population(
            [audit_row], parser_version=parser_identity,
            enumerator_rev=ENUMERATOR_REV,
            analysis_recipe=audit_recipe)
        expected_image = "sha256:" + "3" * 64

        class AuditSession:
            """The exec transport's fixture seam: apply/parse, then close."""

            def __init__(self, owner, workspace_host, work):
                self.owner = owner
                self.workspace_host = workspace_host
                self.work = work
                self.execs = 0
                self.closed = False

            def run(self, command, *, timeout=None):
                if self.closed:
                    raise AssertionError("exec on a closed session")
                self.execs += 1
                self.owner.runs += 1
                if " --apply-file " not in command \
                        or " && " not in command or " --path " not in command:
                    return subprocess.CompletedProcess(
                        [], 2, "", "missing combined apply/parse")
                if not self.work:
                    return subprocess.CompletedProcess([], 0, "", "")
                argv = shlex.split(command)
                rel = argv[argv.index("--apply-file") + 1]
                binding = analysis_binding_for_path(
                    self.owner.manifest["analysis_recipe"], rel)
                compiler = binding["compiler"]
                parser = compiler["parser"] if compiler else parser_identity
                if compiler is not None:
                    assert argv[0] == compiler["java_home"] + "/bin/java"
                    assert argv[argv.index("&&") + 1] == argv[0]
                    self.owner.applied_compilers.append((rel, argv[0]))
                target = os.path.join(self.workspace_host, *rel.split("/"))
                with open(target, "rb") as handle:
                    raw = handle.read()
                with open(target, "wb") as handle:
                    handle.write(raw.replace(
                        b"return x;", b"return null;", 1))
                parse_path = os.path.join(
                    self.workspace_host, "var", "bench_mutate", "parse.json")
                with open(parse_path, "w", encoding="utf-8") as handle:
                    json.dump({"parser": parser, "errors": {}},
                              handle)
                return subprocess.CompletedProcess([], 0, "", "")

            def close(self):
                self.closed = True

        class AuditRunner:
            workdir = "/work"

            def __init__(self, work=True, *, manifest=None,
                         toolchain_probes=None):
                self.runs = 0
                self.work = work
                self.sessions = []
                self.manifest = manifest or audit_manifest
                self.toolchain_probes = toolchain_probes
                self.compiled_homes = []
                self.applied_compilers = []

            def open_isolated_java_session(self, *, workspace_host,
                                           analysis_host, classes_host,
                                           analysis_runtime, classes_runtime,
                                           timeout=300):
                session = AuditSession(self, workspace_host, self.work)
                self.sessions.append(session)
                return session

            def _image_for_isolated_run(self):
                return expected_image

            def probe_isolated_java_toolchain(self, **_kwargs):
                if self.toolchain_probes is not None:
                    return subprocess.CompletedProcess(
                        [], 0, self.toolchain_probes[_kwargs["java_home"]], "")
                output = (
                    TOOLCHAIN_JAVAC_MARKER + "\n"
                    "javac 17.0.1\n" + TOOLCHAIN_JAVA_MARKER + "\n"
                    "java.version = 17.0.1\n"
                    "java.vendor = Fixture Vendor\n"
                    "java.runtime.version = 17.0.1+1\n"
                    + tool_hash_output)
                return subprocess.CompletedProcess([], 0, output, "")

            def prepare_isolated_java_applier(
                    self, _source, classes, **_kwargs):
                self.compiled_homes.append(_kwargs.get("java_home"))
                with open(os.path.join(classes, "Mutate.class"), "wb") \
                        as handle:
                    handle.write(b"fixture compiled class")
                return subprocess.CompletedProcess([], 0, "", "")

        audit_runner = AuditRunner()
        image_audit = audit_population_in_image(
            audit_manifest, audit_root, runner=audit_runner,
            expected_image_id=expected_image)
        compiled = image_audit["operator_gate"]["compiled_applier"]
        check("canonical-image audit compiles/snapshots once, opens ONE "
              "long-lived session, execs one apply+parse per mutant, closes "
              "it, and restores exact source",
              image_audit["status"] == "complete"
              and image_audit["n_applied"] == audit_manifest["n"]
              and image_audit["n_parse_valid"] == audit_manifest["n"]
              and len(audit_runner.sessions) == 1
              and audit_runner.sessions[0].execs == audit_manifest["n"]
              and audit_runner.sessions[0].closed
              and audit_runner.runs == audit_manifest["n"]
              and open(source_path, "rb").read() == original_source
              and not os.path.exists(os.path.join(
                  audit_root, "var", "bench_mutate")))
        # Anti-vacuity: the walk is only evidence because a session that
        # returns success WITHOUT applying and parsing is refused, and
        # because a runner that cannot open a session never walks at all.
        idle_runner = AuditRunner(work=False)
        check("a session that answers success without materialising anything "
              "is refused, and its container is still closed",
              raises(lambda: audit_population_in_image(
                  audit_manifest, audit_root, runner=idle_runner,
                  expected_image_id=expected_image),
                  "materialisation parse evidence")
              and len(idle_runner.sessions) == 1
              and idle_runner.sessions[0].closed
              and idle_runner.sessions[0].execs == 1
              and open(source_path, "rb").read() == original_source)

        class SessionlessRunner(AuditRunner):
            open_isolated_java_session = None

        check("a runner without the long-lived session transport cannot walk "
              "a Java population",
              raises(lambda: audit_population_in_image(
                  audit_manifest, audit_root, runner=SessionlessRunner(),
                  expected_image_id=expected_image),
                  "long-lived isolated Java session"))

        check("canonical-image audit emits the existing compiled-applier/2 "
              "tool and recipe binding",
              compiled["schema"] == "r2t.compiled-applier/2"
              and compiled["runtime_identity"] == parser_identity
              and compiled["runtime_executable_sha256"] == "1" * 64
              and compiled["compiler_executable_sha256"] == "2" * 64
              and compiled["analysis_recipe_digest"]
              == audit_recipe["digest"])
        manifest_path = os.path.join(audit_root, "population.json")
        release_path = os.path.join(audit_root, "release.jsonl")
        coverage_path = os.path.join(audit_root, "coverage.jsonl")
        boundary_path = os.path.abspath(os.path.join(
            HERE, "..", "config", "boundary_epubcheck.yml"))
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(audit_manifest, handle, sort_keys=True)
            handle.write("\n")
        with open(release_path, "w", encoding="utf-8") as handle:
            handle.write('{"item_id":"java-item"}\n')
        coverage_rows = [{
            "item_id": "java-item",
            "coverage_lines": {"src/main/java/p/C.java": [2]},
        }]
        with open(coverage_path, "w", encoding="utf-8") as handle:
            for coverage_row in coverage_rows:
                handle.write(json.dumps(coverage_row, sort_keys=True) + "\n")
        by_mutant, uncovered = M.map_mutants_to_items(
            audit_manifest, {"java-item": coverage_rows[0]["coverage_lines"]})
        audit_map = A.build_map_artifact(
            audit_manifest, by_mutant, uncovered,
            coverage_sha256=A.sha256_file(coverage_path),
            release_sha256=A.sha256_file(release_path))
        asset_index = build_asset_index(
            "epubcheck", manifest=audit_manifest,
            manifest_path=manifest_path, mapping=audit_map,
            coverage_path=coverage_path, release_path=release_path,
            boundary_path=boundary_path, audit=image_audit)
        check("Java mutation asset index is derived as raw-equals-scored and "
              "binds the complete audit",
              asset_index["projects"]["epubcheck"]["raw_population"]["n"]
              == audit_manifest["n"]
              and asset_index["projects"]["epubcheck"]
              ["materialisation_audit"]["attestation_digest"]
              == image_audit["digest"])
        # The construction now lives in `toolkit.mutation_asset_index` and is
        # shared with the Behat/PHP mint.  This is the pre-refactor entry,
        # written out here field for field from the same fixture: if the
        # shared function ever derives one value differently, Java's index
        # changes, and Java's index is a FROZEN artifact.  Written inline
        # rather than pinned as a digest because every field below is a
        # function of the fixture, and a digest would have to be re-earned by
        # hand each time the fixture moves.
        audit_facts = A.validate_manifest(audit_manifest,
                                          expected_engine=ENGINE)
        audit_map_facts = A.validate_map(
            audit_map, audit_manifest,
            release_ids=A.load_release_ids(release_path),
            coverage_by_item=A.coverage_from_rows(
                A.load_jsonl(coverage_path)))
        image_gate = image_audit["operator_gate"]
        pre_refactor = {
            "schema": A.ASSET_INDEX_SCHEMA,
            "version": 1,
            "projects": {"epubcheck": {
                "engine": audit_manifest["engine"],
                "engine_version": audit_manifest["engine_version"],
                "parser": audit_manifest["parser"],
                "raw_population": {
                    "role": "pre_boundary_catalogue",
                    "n": audit_manifest["n"],
                    "manifest_digest": audit_manifest["digest"],
                    "canonical_sha256": audit_facts["canonical_sha256"],
                    "preserved_file_sha256": A.sha256_file(manifest_path),
                },
                "scored_population": {
                    "role": "raw_equals_scored",
                    "n": audit_manifest["n"],
                    "manifest_digest": audit_manifest["digest"],
                    "canonical_sha256": audit_facts["canonical_sha256"],
                    "raw_manifest_digest": audit_manifest["digest"],
                    "n_non_production_excluded": 0,
                },
                "boundary": {
                    "config": os.path.basename(boundary_path),
                    "classification": "production",
                    "sha256": A.sha256_file(boundary_path),
                },
                "mutation_map": {
                    "manifest_role": "scored_population",
                    "n_mutants": audit_map_facts["n_mutants"],
                    "n_mapped": audit_map_facts["n_mapped"],
                    "n_uncovered": audit_map_facts["n_uncovered"],
                    "n_pairs": audit_map_facts["n_pairs"],
                    "digest": audit_map_facts["digest"],
                    "canonical_sha256": audit_map_facts["canonical_sha256"],
                    "coverage_sha256": A.sha256_file(coverage_path),
                    "release_sha256": A.sha256_file(release_path),
                },
                "coverage_oracle": {
                    "rows": len(coverage_rows),
                    "sha256": A.sha256_file(coverage_path)},
                "release": {
                    "items": 1, "sha256": A.sha256_file(release_path)},
                "engine_source": {"sha256": A.sha256_file(JAVA_SOURCE)},
                "materialisation_audit": {
                    "expected_mutants": audit_manifest["n"],
                    "status": "complete",
                    "attestation_digest": image_audit["digest"],
                    "release_blocker": None,
                    "bounded_roots": image_audit["bounded_roots"],
                    "n_source_files": image_audit["n_source_files"],
                    "source_set_sha256":
                        image_audit["source_set_sha256_before"],
                    "runtime_parser_identity":
                        image_gate["runtime_parser_identity"],
                    "engine_source_sha256":
                        image_gate["engine_source_sha256"],
                },
            }},
        }
        def entry_difference(actual, expected):
            """Differing keys, one level into the entry's nested blocks."""
            differing = []
            for key in sorted(set(actual) | set(expected)):
                left, right = actual.get(key), expected.get(key)
                if left == right:
                    continue
                if isinstance(left, dict) and isinstance(right, dict):
                    differing += [f"{key}.{inner}" for inner
                                  in entry_difference(left, right)]
                else:
                    differing.append(key)
            return differing

        check("the shared mint reproduces the pre-refactor Java index byte "
              "for byte",
              A.canonical_bytes(asset_index)
              == A.canonical_bytes(pre_refactor),
              detail=str(entry_difference(
                  asset_index["projects"]["epubcheck"],
                  pre_refactor["projects"]["epubcheck"])))

    # Use the actual audit producer and index/reader join; only the image
    # transport is the fixture above. The population's composite parser is
    # distinct from the single JDK compiling the shared mutation engine.
    for mixed in (True, False):
        with tempfile.TemporaryDirectory(prefix="r2t-module-audit-") as root:
            probes, compilers = {}, {}
            for version, home, hashes in (
                    ("1.8", "/opt/java/openjdk8", ("1", "2", "3")),
                    ("17", "/opt/java/openjdk", ("4", "5", None))):
                runtime_hash, compiler_hash, tools_hash = (
                    value * 64 if value else None for value in hashes)
                output = (
                    f"{TOOLCHAIN_JAVAC_MARKER}\njavac {version}\n"
                    f"{TOOLCHAIN_JAVA_MARKER}\njava.version = {version}\n"
                    f"java.vendor = Fixture\njava.runtime.version = {version}\n"
                    f"{TOOLCHAIN_JAVA_SHA_MARKER}\n{runtime_hash}  /java\n"
                    f"{TOOLCHAIN_JAVAC_SHA_MARKER}\n{compiler_hash}  /javac\n"
                    f"{TOOLCHAIN_TOOLS_JAR_SHA_MARKER}\n"
                    + (tools_hash + "  /tools.jar" if tools_hash else "none")
                    + "\n")
                probes[home] = output
                compilers[home] = {
                    "java_home": home, "parser": parse_toolchain_probe(output),
                    "encoding": "UTF-8", "source": "8", "target": "8",
                    "release": None, "runtime_executable_sha256": runtime_hash,
                    "compiler_executable_sha256": compiler_hash,
                    "tools_jar_sha256": tools_hash,
                }
            module_rows, mutants = [], []
            for module, home in (
                    ("a-module", "/opt/java/openjdk8" if mixed else
                     "/opt/java/openjdk"), ("b-module", "/opt/java/openjdk")):
                source = f"{module}/src/main/java/p/C.java"
                path = os.path.join(root, source)
                os.makedirs(os.path.dirname(path))
                with open(path, "wb") as handle:
                    handle.write(original_source)
                classes = f"{module}/target/classes"
                os.makedirs(os.path.join(root, classes))
                module_rows.append({
                    "module": module, "source_root": f"{module}/src/main/java",
                    "source_files": [source], "compiler": compilers[home],
                    "recipe": make_module_analysis_child_recipe(
                        root, module, classpath=[classes]),
                })
                mutants.append(dict(audit_row, file=source))
            with open(os.path.join(root, A.DISPOSABLE_MARKER), "w") as handle:
                handle.write(AUDIT.DISPOSABLE_MARKER_CONTENT)
            authority = make_module_analysis_recipe(root, module_rows)
            manifest = build_population(
                mutants, parser_version=module_analysis_parser(authority),
                enumerator_rev=ENUMERATOR_REV, analysis_recipe=authority)
            runner = AuditRunner(manifest=manifest, toolchain_probes=probes)
            report = audit_population_in_image(
                manifest, root, runner=runner, expected_image_id=expected_image)
            engine = compilers["/opt/java/openjdk8" if mixed else
                               "/opt/java/openjdk"]
            gate = report["operator_gate"]
            check(f"module audit ({'8/17' if mixed else '17 only'}) compiles "
                  "one selected engine while each mutant uses its module JVM",
                  runner.compiled_homes == [engine["java_home"]]
                  and runner.applied_compilers == [
                      (row["source_files"][0],
                       row["compiler"]["java_home"] + "/bin/java")
                      for row in authority["modules"]]
                  and gate["compiled_applier"]["runtime_identity"]
                  == engine["parser"]
                  and gate["compiled_applier"]["compiler_identity"]
                  == engine["parser"].split(" [", 1)[0]
                  and gate["runtime_parser_identity"] == manifest["parser"]
                  and gate["runtime_parser_reported"] == manifest["parser"])

            def write_document(name, document):
                path = os.path.join(root, name)
                with open(path, "w") as handle:
                    handle.write(json.dumps(document) + "\n")
                return path

            manifest_path = write_document("manifest.json", manifest)
            release_path = write_document("release.jsonl", {"item_id": "java-item"})
            coverage = {row["file"]: [2] for row in mutants}
            coverage_path = write_document("coverage.jsonl", {
                "item_id": "java-item", "coverage_lines": coverage})
            boundary_path = os.path.abspath(os.path.join(
                HERE, "..", "config", "boundary_kapua.yml"))
            by_mutant, uncovered = M.map_mutants_to_items(
                manifest, {"java-item": coverage})
            mapping = A.build_map_artifact(
                manifest, by_mutant, uncovered,
                coverage_sha256=A.sha256_file(coverage_path),
                release_sha256=A.sha256_file(release_path))

            def admit(audit):
                index = build_asset_index(
                    "kapua", manifest=manifest, manifest_path=manifest_path,
                    mapping=mapping, coverage_path=coverage_path,
                    release_path=release_path, boundary_path=boundary_path,
                    audit=audit)
                return A.validate_index_binding(
                    index, "kapua", raw_manifest=manifest,
                    scored_manifest=manifest, mapping=mapping,
                    boundary_path=boundary_path, coverage_path=coverage_path,
                    release_path=release_path, engine_source_path=JAVA_SOURCE,
                    raw_manifest_path=manifest_path, audit_attestation=audit,
                    require_release_ready=True)

            check("module audit producer -> asset index -> release-ready "
                  "consumer accepts the selected engine witness", bool(admit(report)))
            alternatives = [
                ("compiler_identity", "javac wrong"),
                ("runtime_identity", manifest["parser"]),
                ("analysis_recipe_digest", "0" * 64),
                *((key, "0" * 64) for key in (
                    "runtime_executable_sha256", "compiler_executable_sha256",
                    "tools_jar_sha256")),
            ]
            for key, value in alternatives:
                changed = json.loads(json.dumps(report))
                changed["operator_gate"]["compiled_applier"][key] = value
                changed["digest"] = A.audit_digest(changed)
                check(f"module audit refuses wrong compiled {key}",
                      raises(lambda: admit(changed), "pristine full population"))
            other_engine = compilers["/opt/java/openjdk" if mixed else
                                     "/opt/java/openjdk8"]
            changed = json.loads(json.dumps(report))
            changed["operator_gate"]["compiled_applier"].update({
                **{key: other_engine[key] for key in (
                    "runtime_executable_sha256", "compiler_executable_sha256",
                    "tools_jar_sha256")},
                "runtime_identity": other_engine["parser"],
                "compiler_identity": other_engine["parser"].split(" [", 1)[0],
            })
            changed["digest"] = A.audit_digest(changed)
            check("module audit refuses an internally consistent wrong engine",
                  raises(lambda: admit(changed), "pristine full population"))
            for key in ("runtime_parser_identity", "runtime_parser_reported"):
                changed = json.loads(json.dumps(report))
                changed["operator_gate"][key] = engine["parser"]
                changed["digest"] = A.audit_digest(changed)
                expected_refusal = ("audit parser identity differs"
                                    if key == "runtime_parser_identity" else
                                    "pristine full population")
                check(f"module audit keeps composite {key} exact",
                      raises(lambda: admit(changed), expected_refusal))

    # -- the k-way pool (owner ruling, 2026-08-12: k=16 by default).  One
    #    session container and one disposable tree per worker; the collector
    #    is order-preserving; any failure closes every container.
    with tempfile.TemporaryDirectory(prefix="r2t-java-pool-audit-") \
            as pool_root:
        pool_files = [f"src/main/java/p/C{index}.java" for index in range(6)]
        pool_source = b"package p;\n   return x;\n"
        for rel in pool_files:
            path = os.path.join(pool_root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(pool_source)
        with open(os.path.join(pool_root, A.DISPOSABLE_MARKER), "w",
                  encoding="utf-8") as handle:
            handle.write(AUDIT.DISPOSABLE_MARKER_CONTENT)
        pool_recipe = make_analysis_recipe(pool_root, sourcepath=[SOURCEPATH])
        pool_manifest = build_population(
            [{"file": rel, "start_line": 2, "start_col": 4,
              "end_line": 2, "end_col": 12, "operator": "ReturnValue",
              "original": "return x;", "mutated": "return null;",
              "class": "C", "method": "f"} for rel in pool_files],
            parser_version=parser_identity, enumerator_rev=ENUMERATOR_REV,
            analysis_recipe=pool_recipe)
        pool_image = "sha256:" + "4" * 64
        pool_ids = {row["file"]: row["id"] for row in pool_manifest["mutants"]}

        class PoolSession:
            """One fixture session per tree: it only ever writes ITS tree."""

            def __init__(self, owner, workspace_host):
                self.owner = owner
                self.workspace_host = workspace_host
                self.execs = 0
                self.closed = False

            def run(self, command, *, timeout=None):
                if self.closed:
                    raise AssertionError("exec on a closed session")
                self.execs += 1
                tokens = shlex.split(command)
                rel = tokens[tokens.index("--apply-file") + 1]
                self.owner.note(self, rel)
                gate = self.owner.gates.get(rel)
                if gate is not None:
                    gate()
                if rel in self.owner.fail_files:
                    return subprocess.CompletedProcess(
                        [], 3, "", f"fixture refused {rel}")
                target = os.path.join(self.workspace_host, *rel.split("/"))
                with open(target, "rb") as handle:
                    raw = handle.read()
                with open(target, "wb") as handle:
                    handle.write(raw.replace(
                        b"return x;", b"return null;", 1))
                parse_path = os.path.join(
                    self.workspace_host, "var", "bench_mutate", "parse.json")
                with open(parse_path, "w", encoding="utf-8") as handle:
                    json.dump({"parser": parser_identity, "errors": {}},
                              handle)
                return subprocess.CompletedProcess([], 0, "", "")

            def close(self):
                self.closed = True

        class PoolRunner(AuditRunner):
            def __init__(self, *, fail_files=(), gates=None):
                super().__init__()
                self.fail_files = set(fail_files)
                self.gates = dict(gates or {})
                self.by_worker = {}
                self.lock = threading.Lock()

            def _image_for_isolated_run(self):
                return pool_image

            def note(self, session, rel):
                with self.lock:
                    self.by_worker.setdefault(
                        session.workspace_host, []).append(rel)

            def open_isolated_java_session(self, *, workspace_host, **_kw):
                session = PoolSession(self, workspace_host)
                with self.lock:
                    self.sessions.append(session)
                return session

        def walk(runner, workers):
            return audit_population_in_image(
                pool_manifest, pool_root, runner=runner,
                expected_image_id=pool_image, workers=workers)

        sequential_runner = PoolRunner()
        sequential = walk(sequential_runner, 1)
        pool_runner = PoolRunner()
        parallel = walk(pool_runner, 3)
        stripped = {key: value for key, value in parallel.items()
                    if key != "parallel_audit"}
        stripped["digest"] = A.audit_digest(stripped)
        check("k workers open k sessions over k disposable trees, close every "
              "one, and walk the whole population exactly once",
              len(pool_runner.sessions) == 3
              and all(session.closed for session in pool_runner.sessions)
              and sum(session.execs for session in pool_runner.sessions)
              == pool_manifest["n"]
              # A queue can legitimately leave a session idle. Verify distinct
              # session trees and exact work coverage independently.
              and len({session.workspace_host
                       for session in pool_runner.sessions}) == 3
              and sorted(rel for files in pool_runner.by_worker.values()
                         for rel in files) == sorted(pool_files)
              and parallel["status"] == "complete"
              and parallel["n_restored"] == pool_manifest["n"]
              and parallel["parallel_audit"]["n_roots"] == 3
              and sum(parallel["parallel_audit"]["mutants_by_root"])
              == pool_manifest["n"]
              and all(open(os.path.join(pool_root, *rel.split("/")),
                           "rb").read() == pool_source
                      for rel in pool_files),
              json.dumps(parallel.get("parallel_audit")))
        check("k=1 is the sequential walk it always was: ONE session, ONE "
              "tree, and an attestation byte-identical to the pool's once "
              "the disclosed parallel block is removed",
              len(sequential_runner.sessions) == 1
              and sequential_runner.sessions[0].execs == pool_manifest["n"]
              and "parallel_audit" not in sequential
              and stripped == sequential)

        # Anti-vacuity for the collector: the LATER mutant is made to fail
        # FIRST in wall-clock time, deterministically.  An implementation
        # that reported whichever thread raised first would name C4 here.
        early_running = threading.Event()
        late_failed = threading.Event()

        def early_gate():
            early_running.set()
            late_failed.wait(timeout=10)

        def late_gate():
            early_running.wait(timeout=10)

        ordered_runner = PoolRunner(
            fail_files=("src/main/java/p/C1.java",
                        "src/main/java/p/C4.java"),
            gates={"src/main/java/p/C1.java": early_gate,
                   "src/main/java/p/C4.java": late_gate})

        ordered_failure = {}
        try:
            walk(ordered_runner, 3)
        except A.MaterialisationAuditRefused as exc:
            ordered_failure = exc.report
        late_failed.set()
        check("the collector reports the EARLIEST FAILING MUTANT IN MANIFEST "
              "ORDER, not the first worker to raise",
              ordered_failure.get("status") == "failed"
              and ordered_failure.get("failing_mutant_id")
              == pool_ids["src/main/java/p/C1.java"]
              and ordered_failure.get("failure_stage") == "apply"
              and "fixture refused src/main/java/p/C1.java"
              in (ordered_failure.get("failure") or ""),
              repr(ordered_failure.get("failing_mutant_id")))
        check("a worker failure closes EVERY session container and leaves "
              "every audited tree restored",
              len(ordered_runner.sessions) == 3
              and all(session.closed
                      for session in ordered_runner.sessions)
              and all(open(os.path.join(pool_root, *rel.split("/")),
                           "rb").read() == pool_source
                      for rel in pool_files))

        class UnclosableRunner(PoolRunner):
            def open_isolated_java_session(self, **kwargs):
                session = super().open_isolated_java_session(**kwargs)

                def refuse_close():
                    raise RuntimeError("fixture container is still there")

                session.close = refuse_close
                return session

        check("a session container that cannot be proved absent refuses the "
              "whole audit, however many workers there were",
              raises(lambda: walk(UnclosableRunner(), 3),
                     "could not all be proved absent"))

    from ..bench import campaign as C
    gold_campaign = C.campaign_fingerprint(
        campaign_id="java-gold-map", k_workers=1,
        shard_rule=C.SHARD_RULE, trial_budget=0, condition=None,
        coverage=True, harness_version="selftest",
        config_digest="0123456789abcdef", model=None,
        container_image_digest="sha256:" + "1" * 64,
        workspace_seed_digest="2" * 64,
        database_dump_digest=C.NO_DATABASE,
        protocol_version=None, protocol_digest=None, agent_system=None)
    gold_digest = C.campaign_digest(gold_campaign)
    gold_row = {
        "item_id": "java-item-1", "shard": 0,
        "campaign_digest": gold_digest, "adapter": "gold",
        "metadata": {"source": "gold"}, "repeats": 1,
        "coverage": True, "coverage_requested": True,
        "coverage_collected": True, "coverage_mismatch": [],
        "coverage_lines": {}, "outcome": "passed",
    }
    with tempfile.TemporaryDirectory(prefix="r2t_java_gold_") as scratch:
        release_ids = {"java-item-1"}
        case_number = 0

        def gold_case(**changes):
            nonlocal case_number
            case_number += 1
            row = {**gold_row, **changes}
            path = os.path.join(scratch, f"gold-{case_number}.jsonl")
            payload = (json.dumps(row, sort_keys=True) + "\n").encode("utf-8")
            with open(path, "wb") as handle:
                handle.write(payload)
            side = {
                "campaign": gold_campaign, "campaign_digest": gold_digest,
                "workers": [], "n": 1, "rows_path": os.path.basename(path),
                "rows_digest": hashlib.sha256(payload).hexdigest()[:16],
            }
            with open(path + ".campaign.json", "w", encoding="utf-8") \
                    as handle:
                json.dump(side, handle, sort_keys=True)
                handle.write("\n")
            return path, payload

        def load_gold(**changes):
            path, payload = gold_case(**changes)
            return path, payload, strict_gold_coverage(path, release_ids)

        gold_path, gold_raw, loaded_gold = load_gold()
        check("strict Java map admits complete gold even when one item covers "
              "zero production lines",
              loaded_gold == ({"java-item-1": {}},
                              hashlib.sha256(gold_raw).hexdigest()))
        check("strict Java map refuses a non-gold source, repeated draw, or "
              "any non-empty/wrong-typed mismatch witness",
              raises(lambda: load_gold(metadata={"source": "candidate"}),
                     "successful measured gold")
              and raises(lambda: load_gold(repeats=2),
                         "successful measured gold")
              and raises(lambda: load_gold(
                  coverage_mismatch=["src/main/java/p/C.java"]),
                         "successful measured gold")
              and raises(lambda: load_gold(coverage_mismatch={}),
                         "successful measured gold"))

        original_mapper = M.map_mutants_to_items

        def mutate_after_read(*args, **kwargs):
            with open(gold_path, "wb") as handle:
                handle.write(b"{}\n")
            return original_mapper(*args, **kwargs)

        M.map_mutants_to_items = mutate_after_read
        try:
            mapped, _coverage = _build_population_map(
                manifest, gold_path, release_ids=release_ids,
                release_sha256="b" * 64)
        finally:
            M.map_mutants_to_items = original_mapper
        check("map identity hashes the coverage snapshot it parsed, not a "
              "path changed before binding",
              mapped["coverage_sha256"]
              == hashlib.sha256(gold_raw).hexdigest()
              and mapped["release_sha256"] == "b" * 64
              and mapped["coverage_sha256"]
              != hashlib.sha256(b"{}\n").hexdigest())
    print("\n" + ("ALL PASS (mutation_java)" if ok
                   else "FAILURES (mutation_java)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(operator_main(sys.argv[1:]) if len(sys.argv) > 1
                     else selftest())
