"""Research-minimal Java image and offline-reality source path.

This module implements the deliberately small ``java-research-minimal/v1``
path.  It does not import the retired EPUBCheck forensic producer.  Live
execution stays closed without an exact external reviewed phase approval.
The public CLI and ``LiveResearchRunner`` reuse the authority-bound bounded
Docker client from :mod:`r2t.toolkit.epubcheck_image`; the private ``_execute_*`` seams
remain deterministic fake-runner test seams.

The runner boundary is intentionally narrow: revalidate one already-selected
Docker authority, execute an exact inner argv once, and safely enumerate one
directory in an immutable image.  Registry observers, gateways, helper
containers, tags, name/ID resolution ceremonies, and active egress probes are
not part of this path.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field, fields
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Optional, Protocol, Sequence
import xml.etree.ElementTree as ET


PATH = "java-research-minimal/v1"
IMAGE_SCHEMA = "r2t.java-research-minimal-image/1"
REALITY_SCHEMA = "r2t.java-research-minimal-reality/1"
MANIFEST_SCHEMA = "r2t.java-research-minimal-m2-manifest/1"
PREPARATION_SCHEMA = "r2t.java-research-minimal-workspace/1"
APPROVAL_SCHEMA = "r2t.java-research-minimal-phase-approval/1"
CENSUS_SCHEMA = "r2t.java-research-minimal-census/1"
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_M2_FILES = 32_768
MAX_M2_BYTES = 4 * 1024 * 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SAFE_ARTIFACT = re.compile(r"[A-Za-z0-9_.+/-]+\Z")
_TRANSIENT = re.compile(
    r"(?:^|/)(?:[^/]*\.lastUpdated|[^/]*\.(?:part|tmp|error)|"
    r"resolver-status\.properties)\Z")


class MinimalJavaRefused(RuntimeError):
    """A missing approval or a source/runtime invariant stopped the path."""


def _refuse(message: str) -> MinimalJavaRefused:
    if message.startswith("REFUSED: "):
        message = message[len("REFUSED: "):]
    return MinimalJavaRefused("REFUSED: " + message)


@dataclass(frozen=True)
class ProjectConfig:
    project: str
    jdk_major: int
    base_name: str
    source_commits: tuple[tuple[str, str], ...]
    source_tree: str
    extracted_items: int
    criterion_items: int
    requirement_items: int


PROJECTS: dict[str, ProjectConfig] = {
    "epubcheck": ProjectConfig(
        project="epubcheck",
        jdk_major=8,
        base_name="docker.io/library/maven:3.9.6-eclipse-temurin-8",
        source_commits=((
            "w3c/epubcheck",
            "82b174ec319ea3e6c9d2488f84155fa4a9171fc2"),),
        source_tree="993e9df95278da08b8c6ebe68dfb44f777ddfbea",
        extracted_items=1088, criterion_items=1041, requirement_items=47),
    "algorand-sdk": ProjectConfig(
        project="algorand-sdk",
        jdk_major=11,
        base_name="docker.io/library/maven:3.9.6-eclipse-temurin-11",
        source_commits=(
            ("algorand/java-algorand-sdk",
             "4e38dadc4eec827ed8742c8bb272e0545c801932"),
            ("algorand/algorand-sdk-testing",
             "7c67284b52675257e66c017cc3606bcd4803f4c6")),
        source_tree=
            "a00cc2551054804e1376b37a612b6f9b74d1cdc8bfb7425d34e744455cb84b77",
        extracted_items=210, criterion_items=183, requirement_items=27),
}


MAVEN_DISCOVERY_PREFIX = (
    "mvn", "-B", "--no-transfer-progress", "-Dstyle.color=never",
    "-Dmaven.repo.local=/opt/m2", "-DreuseForks=false",
    "-DfailIfNoTests=true", "-Dsurefire.failIfNoSpecifiedTests=true")
MAVEN_OFFLINE_PREFIX = (
    "mvn", "--offline", "--no-transfer-progress", "-Dstyle.color=never",
    "-Dmaven.repo.local=/opt/m2", "-DreuseForks=false",
    "-DfailIfNoTests=true", "-Dsurefire.failIfNoSpecifiedTests=true")

EPUB_RUNNER = "org.w3c.epubcheck.RunCucumberTest"
ALGORAND_UNIT_RUNNER = \
    "com.algorand.algosdk.unit.R2TBenchCucumberTest"
ALGORAND_OFFLINE_RUNNER = \
    "com.algorand.algosdk.integration.R2TBenchCucumberTest"
ALGORAND_OFFLINE_FEATURE = \
    "classpath:com/algorand/algosdk/integration/offline.feature"

_REALITY_WORKSPACE_KINDS = {
    "epubcheck": ("suite", "unstripped", "stripped"),
    "algorand-sdk": (
        "unit-ordinary", "unit-unstripped", "unit-stripped",
        "offline-ordinary", "offline-unstripped", "offline-stripped"),
}

CENTRAL_SETTINGS = b"""<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <localRepository>/opt/m2</localRepository>
  <mirrors>
    <mirror>
      <id>r2t-central-only</id>
      <mirrorOf>*</mirrorOf>
      <url>https://repo.maven.apache.org/maven2/</url>
    </mirror>
  </mirrors>
</settings>
"""

# The offline settings must name the SAME mirror id the payload was cached
# under.  Maven Resolver records, per artifact, which remote repository id it
# came from (`_remote.repositories`), and offline it will not serve a cached
# artifact for a repository id that record does not list -- it reports the
# artifact as "present, but unavailable".  Discovery caches everything under
# `r2t-central-only`, so canonical and reality must ask under that id too.
# `<offline>true</offline>` still forbids every fetch; the mirror is an
# identity here, not a route, and the phases that use these settings run with
# `--network none`.
OFFLINE_SETTINGS = b"""<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <localRepository>/opt/m2</localRepository>
  <offline>true</offline>
  <mirrors>
    <mirror>
      <id>r2t-central-only</id>
      <mirrorOf>*</mirrorOf>
      <url>https://repo.maven.apache.org/maven2/</url>
    </mirror>
  </mirrors>
</settings>
"""


@dataclass(frozen=True)
class Approval:
    project: str
    phase: str
    execution_identity: Optional[str] = None
    base_digest: Optional[str] = None
    base_config_id: Optional[str] = None
    predecessor_transcript_sha256: Optional[str] = None
    m2_manifest_sha256: Optional[str] = None
    m2_tree_sha256: Optional[str] = None
    image_id: Optional[str] = None
    source_manifest_sha256: Optional[str] = None
    preparation_manifest_sha256: Optional[str] = None
    preparation_manifests_sha256: Optional[dict[str, str]] = None
    census_sha256: Optional[str] = None
    reality_manifest_sha256: Optional[str] = None
    closures_sha256: Optional[str] = None
    quality_sha256: Optional[str] = None
    boundary_sha256: Optional[str] = None
    profile_sha256: Optional[str] = None
    strip_manifest_sha256: Optional[str] = None
    gold_tree_sha256: Optional[str] = None
    validation_manifest_sha256: Optional[str] = None
    validation_ledger_sha256: Optional[str] = None
    release_manifest_sha256: Optional[str] = None
    release_tree_sha256: Optional[str] = None
    authority_reference: Optional[dict] = None
    daemon_fingerprint: Optional[str] = None


_PHASE_APPROVAL_FIELDS = {
    "base": ("execution_identity", "base_digest", "authority_reference",
             "daemon_fingerprint"),
    "discovery": ("execution_identity", "base_digest", "base_config_id",
                  "predecessor_transcript_sha256", "authority_reference",
                  "daemon_fingerprint", "source_manifest_sha256",
                  "preparation_manifest_sha256"),
    "canonical": ("execution_identity", "base_digest", "base_config_id",
                  "predecessor_transcript_sha256", "m2_manifest_sha256",
                  "m2_tree_sha256", "authority_reference",
                  "daemon_fingerprint"),
    "reality": ("execution_identity", "base_digest", "base_config_id",
                "predecessor_transcript_sha256", "m2_manifest_sha256",
                "m2_tree_sha256", "image_id", "authority_reference",
                "daemon_fingerprint", "source_manifest_sha256",
                "preparation_manifests_sha256", "census_sha256"),
    # The N=3 phase starts only after the exact reality and complete
    # closure/quality/strip bundle have been reviewed.  Its output is still
    # pending review; the source-only ``release`` phase below is the separate
    # stopped decision that can mark the generated pool provided.
    "validation": (
        "execution_identity", "base_digest", "base_config_id",
        "predecessor_transcript_sha256", "m2_manifest_sha256",
        "m2_tree_sha256", "image_id", "authority_reference",
        "daemon_fingerprint", "source_manifest_sha256",
        "preparation_manifest_sha256", "census_sha256",
        "reality_manifest_sha256", "closures_sha256", "quality_sha256",
        "boundary_sha256", "profile_sha256", "strip_manifest_sha256",
        "gold_tree_sha256"),
    "release": (
        "execution_identity", "predecessor_transcript_sha256",
        "validation_manifest_sha256", "validation_ledger_sha256",
        "release_manifest_sha256", "release_tree_sha256"),
}


def require_source_approval(project: str, phase: str, *, approval_path: str | None,
                            approved_digest: str | None) -> Approval:
    """Load one external reviewed approval, avoiding a source/authority cycle."""
    if project not in PROJECTS or phase not in _PHASE_APPROVAL_FIELDS:
        raise _refuse(f"unknown project/phase {project!r}/{phase!r}")
    if approval_path is None or approved_digest is None:
        raise _refuse(
            f"{project} {phase} external reviewed phase approval is absent")
    from .. import docker_authority
    try:
        path = docker_authority.canonical_absolute_path(
            approval_path, "Java phase approval")
        docker_authority.assert_trusted_file(path, label="Java phase approval")
        raw = Path(path).read_bytes()
        document = docker_authority.loads_exact_json(
            raw, label="Java phase approval")
    except (docker_authority.DockerAuthorityRefused, OSError) as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    expected_top = {"schema", "path", "project", "phase", "approval",
                    "digest"}
    expected_approval = {item.name for item in fields(Approval)}
    if not isinstance(document, dict) or set(document) != expected_top \
            or document.get("schema") != APPROVAL_SCHEMA \
            or document.get("path") != PATH \
            or document.get("project") != project \
            or document.get("phase") != phase \
            or not isinstance(document.get("approval"), dict) \
            or set(document["approval"]) != expected_approval:
        raise _refuse("external phase approval has another schema/path/phase")
    recorded = document.get("digest")
    if not isinstance(recorded, str) or _SHA256.fullmatch(recorded) is None \
            or approved_digest != recorded:
        raise _refuse("external phase approval digest is not operator-approved")
    try:
        computed = docker_authority.semantic_digest(
            document, domain=APPROVAL_SCHEMA)
    except docker_authority.DockerAuthorityRefused as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    if computed != recorded:
        raise _refuse("external phase approval semantic digest is stale")
    try:
        approval = Approval(**document["approval"])
    except TypeError as exc:
        raise _refuse("external phase approval fields are malformed") from exc
    return _validate_approval(approval, project, phase)


def phase_approval_document(approval: Approval) -> dict:
    """Render a draft external approval; the operator separately approves its digest."""
    from .. import docker_authority
    document = {
        "schema": APPROVAL_SCHEMA, "path": PATH,
        "project": approval.project, "phase": approval.phase,
        "approval": asdict(approval), "digest": "0" * 64,
    }
    document["digest"] = docker_authority.semantic_digest(
        document, domain=APPROVAL_SCHEMA)
    return document


def _validate_approval(value: Approval, project: str, phase: str) -> Approval:
    if value.project != project or value.phase != phase:
        raise _refuse("approval belongs to another project/phase")
    for name in _PHASE_APPROVAL_FIELDS[phase]:
        selected = getattr(value, name)
        valid = isinstance(selected, str) and bool(selected)
        if name == "authority_reference":
            valid = isinstance(selected, dict)
        elif name == "preparation_manifests_sha256":
            expected = (set(_REALITY_WORKSPACE_KINDS[project])
                        if project in _REALITY_WORKSPACE_KINDS else set())
            valid = isinstance(selected, dict) and set(selected) == expected \
                and all(isinstance(digest, str)
                        and _SHA256.fullmatch(digest) is not None
                        for digest in selected.values())
        elif name in {"base_digest", "base_config_id", "image_id"}:
            valid = valid and _IMAGE_ID.fullmatch(selected) is not None
        elif name.endswith("sha256") or name == "daemon_fingerprint":
            valid = valid and _SHA256.fullmatch(selected) is not None
        if not valid:
            raise _refuse(f"approval {name} is malformed")
    return value


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    overflowed: bool = False
    artifacts: Mapping[str, bytes] = field(default_factory=dict)
    facts: Mapping[str, Any] = field(default_factory=dict)


class Runner(Protocol):
    def revalidate_authority(self) -> Mapping[str, Any]: ...

    def run(self, argv: Sequence[str], *, timeout: int,
            build: bool = False) -> CommandResult: ...

    def capture_files(self, image_id: str, path: str, *, timeout: int) \
            -> Mapping[str, bytes]: ...


def _live_bind(value: str, target: str, *, readonly: bool = False) -> str:
    suffix = ",readonly" if readonly else ""
    marker = f",target={target}{suffix}"
    if not value.startswith("type=bind,source=") or not value.endswith(marker):
        raise _refuse(f"live Docker mount is not exact for {target}")
    source = value[len("type=bind,source="):-len(marker)]
    if not source or "," in source:
        raise _refuse("live Docker bind source is empty/ambiguous")
    return _absolute(source, "live Docker bind source")


def _validate_live_maven(value: tuple[str, ...]) -> None:
    prefix = None
    for candidate in (MAVEN_DISCOVERY_PREFIX, MAVEN_OFFLINE_PREFIX):
        if value[:len(candidate)] == candidate:
            prefix = candidate
            break
    if prefix is None:
        raise _refuse("live Maven argv has another reviewed prefix")
    tail = value[len(prefix):]
    if tail in {
            ("test-compile",),
            ("org.jacoco:jacoco-maven-plugin:0.8.11:help",)}:
        return
    if not tail or tail[-1] != "test":
        raise _refuse("live Maven argv has another goal")
    properties = tail[:-1]
    fixed = {
        "-Djacoco.skip=true", "-Dcucumber.execution.dry-run=true",
        "-Dcucumber.publish.quiet=true",
        "-Dcucumber.plugin=json:/work/target/r2t-cucumber.json",
        "-Dtest=RunCucumberTest",
        f"-Dtest={ALGORAND_UNIT_RUNNER}",
        f"-Dtest={ALGORAND_OFFLINE_RUNNER}",
        f"-Dcucumber.features={ALGORAND_OFFLINE_FEATURE}",
    }
    dynamic = [item for item in properties
               if item.startswith("-Dcucumber.filter.tags=")
               and 0 < len(item.removeprefix("-Dcucumber.filter.tags=")) <= 4096]
    algorand = any(item in properties for item in {
        f"-Dtest={ALGORAND_UNIT_RUNNER}",
        f"-Dtest={ALGORAND_OFFLINE_RUNNER}"})
    expected_plugins = 0 if algorand else 1
    if len(properties) != len(set(properties)) \
            or any(item not in fixed and item not in dynamic
                   for item in properties) \
            or properties.count(
                "-Dcucumber.plugin=json:/work/target/r2t-cucumber.json") \
            != expected_plugins:
        raise _refuse("live Maven test properties differ from reviewed shapes")


def validate_live_docker_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Closed Docker vocabulary for the concrete research-minimal runner."""
    try:
        value = tuple(argv)
    except TypeError as exc:
        raise _refuse("live Docker argv is not a sequence") from exc
    if not value or any(not isinstance(token, str) or not token
                        or "\x00" in token for token in value):
        raise _refuse("live Docker argv is malformed")
    if value[:2] == ("image", "pull"):
        valid = len(value) == 5 \
            and value[2:4] == ("--platform", "linux/amd64") \
            and any(value[4].startswith(cfg.base_name + "@sha256:")
                    for cfg in PROJECTS.values()) \
            and _IMAGE_ID.fullmatch(value[4].rsplit("@", 1)[-1]) is not None
        if not valid:
            raise _refuse("live base pull differs from the digest-only shape")
        return value
    if value[:2] == ("image", "inspect") and len(value) == 3:
        operand = value[2]
        if _IMAGE_ID.fullmatch(operand) is None and not any(
                operand.startswith(cfg.base_name + "@sha256:")
                and _IMAGE_ID.fullmatch(operand.rsplit("@", 1)[-1])
                for cfg in PROJECTS.values()):
            raise _refuse("live image inspection is not immutable")
        return value
    if value[0] == "build":
        if len(value) != 9 or value[1:4] != (
                "--pull=false", "--network", "none") \
                or value[4] != "--iidfile" or value[6] != "--file":
            raise _refuse("live canonical build differs from reviewed shape")
        iidfile = _absolute(value[5], "live canonical iidfile")
        dockerfile = _absolute(value[7], "live canonical Dockerfile")
        context = _absolute(value[8], "live canonical context")
        # The exact producer currently emits nine tokens.  Keeping the length
        # check explicit prevents a tag or second context operand.
        if os.path.dirname(dockerfile) != context \
                or os.path.dirname(iidfile) != os.path.dirname(context) \
                or os.path.basename(dockerfile) != "Dockerfile" \
                or os.path.basename(iidfile) != "canonical.iid":
            raise _refuse("live canonical build paths do not share one output")
        return value
    if len(value) < 5 \
            or value[:5] != (
                "run", "--rm", "--network", value[3], "--pull=never") \
            or value[3] not in {"none", "bridge"}:
        raise _refuse("live Docker command is outside the closed vocabulary")
    if value[5:7] == ("--entrypoint", "java") \
            and value[3] == "none" and len(value) == 9 \
            and _IMAGE_ID.fullmatch(value[7]) and value[8:] == ("-version",):
        return value
    if value[5:7] == ("--entrypoint", "/bin/tar") \
            and value[3] == "none" and len(value) == 13 \
            and _IMAGE_ID.fullmatch(value[7]) \
            and value[8:] == ("-C", "/opt", "-cf", "-", "m2"):
        return value
    if value[5:7] == ("--entrypoint", "/bin/sh") \
            and value[3] == "none" and len(value) == 10 \
            and _IMAGE_ID.fullmatch(value[7]) and value[8] == "-c" \
            and value[9] == (
                "set -eu; test -z \"$(find /work -mindepth 1 -print -quit)\"; "
                "test ! -e /pom.xml; test ! -e /src; test ! -e /.git; "
                "grep -q '<offline>true</offline>' /root/.m2/settings.xml; "
                "java -version; mvn --version; printf 'R2T-QUALIFIED\\n'"):
        return value
    if value[3] == "bridge":
        if len(value) < 15 or value[5] != "--mount" \
                or value[7] != "--mount" or value[9] != "--mount" \
                or value[11:13] != ("--workdir", "/work") \
                or _IMAGE_ID.fullmatch(value[13]) is None:
            raise _refuse("live discovery container shape differs")
        _live_bind(value[6], "/work")
        _live_bind(value[8], "/opt/m2")
        _live_bind(value[10], "/root/.m2/settings.xml", readonly=True)
        maven = value[14:]
    else:
        if len(value) < 11 or value[5] != "--mount" \
                or value[7:9] != ("--workdir", "/work") \
                or _IMAGE_ID.fullmatch(value[9]) is None:
            raise _refuse("live offline container shape differs")
        _live_bind(value[6], "/work")
        maven = value[10:]
    _validate_live_maven(maven)
    return value


def _collect_reality_artifacts(argv: tuple[str, ...]) -> dict[str, bytes]:
    mounts = [argv[index + 1] for index, token in enumerate(argv[:-1])
              if token == "--mount" and argv[index + 1].endswith(
                  ",target=/work")]
    if len(mounts) != 1:
        raise _refuse("offline run has no unique /work mount")
    workspace = _live_bind(mounts[0], "/work")
    root = os.path.realpath(workspace)

    def regular(path: str, label: str) -> bytes:
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise _refuse(f"offline run retained no {label}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) \
                or not os.path.realpath(path).startswith(root + os.sep) \
                or info.st_size > MAX_LOG_BYTES:
            raise _refuse(f"offline {label} is linked/special/oversized")
        return Path(path).read_bytes()

    cucumber_raw = regular(
        os.path.join(root, "target", "r2t-cucumber.json"),
        "Cucumber JSON")
    try:
        document = json.loads(cucumber_raw)
        from ..stacks.cucumber import records_from_json
        rows, _voids = records_from_json(document)
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError,
            TypeError, ValueError) as exc:
        raise _refuse("offline Cucumber JSON cannot be folded") from exc
    artifacts = {
        "cucumber.json": cucumber_raw,
        "cucumber.records.jsonl": b"".join(
            _canonical_json(row) for row in rows),
    }
    xml_bytes = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if any(Path(dirpath, name).is_symlink() for name in dirnames):
            raise _refuse("offline workspace gained a linked directory")
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        if not rel_dir.endswith("target/surefire-reports"):
            continue
        for name in sorted(filenames):
            if not name.startswith("TEST-") or not name.endswith(".xml"):
                continue
            path = os.path.join(dirpath, name)
            raw = regular(path, "Surefire XML")
            xml_bytes += len(raw)
            if xml_bytes > MAX_LOG_BYTES:
                raise _refuse("offline Surefire XML exceeds its byte ceiling")
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            artifacts["surefire/" + rel] = raw
    if len(artifacts) == 2:
        raise _refuse("offline run retained no Surefire XML")
    return artifacts


class LiveResearchRunner:
    """Concrete protocol adapter over the existing bounded Docker runner."""

    def __init__(self, authority_reference: Mapping[str, object], *,
                 scratch_root: str):
        from ..toolkit.epubcheck_image import LiveDockerRunner
        self._scratch_root = _absolute(
            scratch_root, "research-minimal capture scratch")
        self._runner = LiveDockerRunner(
            authority_reference, argv_validator=validate_live_docker_argv,
            mutation_predicate=lambda argv: tuple(argv)[:2] in {
                ("image", "pull"), ("run", "--rm")}
            or tuple(argv)[:1] == ("build",))

    def revalidate_authority(self) -> Mapping[str, Any]:
        return self._runner.revalidate_authority()

    def run(self, argv: Sequence[str], *, timeout: int,
            build: bool = False) -> CommandResult:
        result = self._runner.run(argv, timeout=timeout, build=build)
        inner = tuple(result.argv)
        artifacts = {}
        collectable_exit = result.returncode == 0 or (
            result.returncode == 1
            and "-Dcucumber.execution.dry-run=true" in inner)
        if collectable_exit and not result.timed_out \
                and not result.overflowed and len(inner) >= 5 \
                and inner[:3] == ("run", "--rm", "--network") \
                and inner[4] == "--pull=never" and "mvn" in inner \
                and ("-Dcucumber.plugin=json:/work/target/r2t-cucumber.json"
                     in inner or any(token.startswith("-Dtest=")
                                     and "R2TBenchCucumberTest" in token
                                     for token in inner)):
            artifacts = _collect_reality_artifacts(inner)
        return CommandResult(
            inner, result.returncode, result.stdout, result.stderr,
            result.timed_out, result.overflowed, artifacts)

    def capture_files(self, image_id: str, path: str, *, timeout: int) \
            -> Mapping[str, bytes]:
        return self._runner.capture_files(
            image_id, path, timeout=timeout,
            maximum_files=MAX_M2_FILES, maximum_bytes=MAX_M2_BYTES,
            scratch_root=self._scratch_root)


def _config(project: str) -> ProjectConfig:
    try:
        return PROJECTS[project]
    except KeyError as exc:
        raise _refuse(f"unknown Java project {project!r}") from exc


def _jsonl_rows(path: os.PathLike[str] | str) -> tuple[list[dict], bytes]:
    raw = Path(path).read_bytes()
    rows = []
    try:
        for line in raw.splitlines():
            if line:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("row is not an object")
                rows.append(value)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _refuse(f"items file {path} is not valid JSONL") from exc
    return rows, raw


def precontact_admission(project: str,
                         items_path: os.PathLike[str] | str) -> dict:
    """Authenticate fixed source counts and exclusions before any contact."""
    cfg = _config(project)
    rows, raw = _jsonl_rows(items_path)
    project_rows = [row for row in rows if row.get("project") == project]
    criteria = [row for row in project_rows
                if row.get("task") == "criterion_to_test"]
    requirements = [row for row in project_rows
                    if row.get("task") == "requirement_to_test"]
    ids = [row.get("item_id") for row in project_rows]
    if any(not isinstance(item_id, str) or not item_id for item_id in ids) \
            or len(ids) != len(set(ids)) \
            or (len(project_rows), len(criteria), len(requirements)) != (
                cfg.extracted_items, cfg.criterion_items,
                cfg.requirement_items):
        raise _refuse(f"{project} source item census differs from its pin")

    blocked: list[str] = []
    candidate_ids = [row["item_id"] for row in criteria]
    policy_identity = None
    admitted_ids = candidate_ids
    if project == "algorand-sdk":
        from .algorand import load_exclusion_policy
        policy = load_exclusion_policy(items_path)
        blocked = list(policy["item_ids"])
        policy_identity = policy["sorted_item_ids_sha256"]
        admitted_ids = [item_id for item_id in candidate_ids
                        if item_id not in set(blocked)]
        if len(admitted_ids) != 132:
            raise _refuse("Algorand pre-contact criterion count is not 132")

    return {
        "items_file_sha256": hashlib.sha256(raw).hexdigest(),
        "source_items": len(project_rows),
        "criterion_items": len(criteria),
        "requirement_items": len(requirements),
        "precontact_excluded": len(blocked),
        "precontact_excluded_item_ids": blocked,
        "precontact_exclusion_sha256": policy_identity,
        "admitted_criterion_items": len(admitted_ids),
        "criterion_item_ids": candidate_ids,
        "admitted_item_ids": admitted_ids,
    }


def _algorand_tag_expression(snapshot: "SourceSnapshot") -> tuple[str, str]:
    from . import j0
    raw = snapshot.files.get("src/test/unit.tags")
    if not isinstance(raw, bytes):
        raise _refuse("authenticated Algorand composition has no unit.tags")
    try:
        _tags, expression = j0._parse_unit_tags_bytes(raw)
    except j0.J0Error as exc:
        raise _refuse(str(exc)) from exc
    digest = hashlib.sha256(raw).hexdigest()
    return expression, digest


def _capture_pickle_ids(result: CommandResult, label: str,
                        project: str) -> list[str]:
    from .closure_java import LOCATED, ClosureJavaError, parse_dry_run
    from ..stacks.cucumber import CucumberStackRefused, records_from_json
    if not isinstance(result.artifacts, Mapping) or set(result.artifacts) < {
            "cucumber.json", "cucumber.records.jsonl"}:
        raise _refuse(f"{label} retained no Cucumber census artifacts")
    try:
        document = json.loads(result.artifacts["cucumber.json"])
        # Discovery's only workspace is the UNSTRIPPED preparation
        # (`_execute_discovery` validates it with `stripped=False`), and only
        # `--dry-run` captures reach here, so the per-leg state is known.
        dry = parse_dry_run(document, "src/test/resources", project=project,
                            dry_run=True, expect_state=LOCATED)
        folded, voids = records_from_json(document)
        retained = _artifact_rows(
            result.artifacts["cucumber.records.jsonl"], label)
    except (json.JSONDecodeError, UnicodeDecodeError, ClosureJavaError,
            CucumberStackRefused, KeyError, TypeError, ValueError) as exc:
        raise _refuse(f"{label} Cucumber census artifacts are malformed") \
            from exc
    if not dry.cases or voids or retained != folded:
        raise _refuse(f"{label} raw/folded Cucumber census disagrees")
    values = sorted(f"{uri}:{line}" for uri, line in dry.cases)
    if len(values) != len(set(values)):
        raise _refuse(f"{label} repeats a Cucumber pickle identity")
    return values


def _source_item_pickles(project: str, snapshot: "SourceSnapshot",
                         row: Mapping[str, Any]) -> list[str]:
    from ..core.gherkin import parse_feature_file
    from ..toolkit.pystep_index import (CUCUMBER_DIALECT, StepResolutionError,
                                examples_rows)
    from .algorand import runtime_feature_path
    provenance = row.get("provenance")
    if not isinstance(provenance, dict):
        raise _refuse("criterion item has no provenance")
    source = provenance.get("file_path")
    line = provenance.get("line")
    if not isinstance(source, str) or not isinstance(line, int) \
            or isinstance(line, bool):
        raise _refuse("criterion provenance path/line is malformed")
    runtime = runtime_feature_path(project, source)
    raw = snapshot.files.get(runtime)
    if not isinstance(raw, bytes):
        raise _refuse(f"criterion feature is absent from source: {runtime}")
    try:
        feature = parse_feature_file(runtime, text=raw.decode("utf-8"))
        scenario = feature.scenario_at(line)
        if scenario is None:
            raise ValueError("scenario line is absent")
        rows = examples_rows(feature, scenario, dialect=CUCUMBER_DIALECT)
    except (UnicodeDecodeError, StepResolutionError, ValueError) as exc:
        raise _refuse(f"criterion cannot be joined to source: {source}:{line}") \
            from exc
    lines = ([row_line for row_line, _values in rows]
             if scenario.kind.startswith("Scenario Outline") else [line])
    return [f"{runtime}:{pickle_line}" for pickle_line in lines]


def _partial_selection(project: str, snapshot: "SourceSnapshot",
                       row: Mapping[str, Any], expected: list[str],
                       selected: set) -> dict:
    """Prove a partial selection fell on `Examples:` block boundaries.

    Returns the record the census carries so a partly admitted item is never
    admitted SILENTLY: which blocks went in, which stayed out, each named by
    its own tags and `Examples:` line, with its pickle count.
    """
    item_id = row["item_id"]
    blocks = _source_item_blocks(project, snapshot, row)
    if not blocks:
        raise _refuse(
            f"{item_id}: dry run selected part of an item that has no "
            f"Examples blocks to cut on")
    chosen: list[dict] = []
    omitted: list[dict] = []
    for block in blocks:
        ids = set(block["pickle_ids"])
        inside = ids & selected
        if inside == ids:
            chosen.append(block)
        elif not inside:
            omitted.append(block)
        else:
            raise _refuse(
                f"{item_id}: dry run selected {len(inside)} of the "
                f"{len(ids)} pickles of the Examples block at line "
                f"{block['examples_line']}; a tag admits a whole block or "
                f"none of it, so a cut through one is not a tag filter")
    if not chosen or not omitted:
        raise _refuse(f"{item_id}: partial selection has no block boundary")

    def record(items):
        return [{"examples_line": block["examples_line"],
                 "tags": list(block["tags"]),
                 "pickles": len(block["pickle_ids"])} for block in items]

    return {
        "expected_pickles": len(expected),
        "selected_pickles": len(selected),
        "selected_blocks": record(chosen),
        "omitted_blocks": record(omitted),
    }


def selected_block_pickles(project: str, snapshot: "SourceSnapshot",
                           row: Mapping[str, Any],
                           record: Mapping[str, Any]) -> tuple[list, list]:
    """Re-derive `(selected, every)` pickle ids for a partly admitted item.

    `_partial_selection` WRITES the census record when discovery admits part
    of an item; this READS one back and holds it against the source, which is
    what every later phase needs and what `produce_source_artifacts` had no
    way to do while it asserted whole-item equality.

    The rule is the one the block ruling states: the item's `Examples:` blocks
    must be exactly the recorded selected + omitted blocks -- same lines, same
    tags, same row counts, nothing extra on either side -- and the selection
    is then the recorded selected blocks' rows.  A cut THROUGH a block cannot
    survive it: no union of whole blocks equals a part of one, so the caller's
    comparison against the census's admitted pickles refuses.

    Returns both the selected ids and every id of the whole scenario, so the
    caller can state the two facts it cares about separately -- what the item
    IS, and what the source says it could have been.
    """
    item_id = row["item_id"]
    blocks = _source_item_blocks(project, snapshot, row)
    if not blocks:
        raise _refuse(
            f"{item_id}: the census records a partial selection of an item "
            f"with no Examples blocks to cut on")

    def described(entries):
        return sorted((int(entry["examples_line"]), tuple(entry["tags"]),
                       int(entry["pickles"])) for entry in entries)

    source = sorted((block["examples_line"], tuple(block["tags"]),
                     len(block["pickle_ids"])) for block in blocks)
    recorded = sorted(described(record["selected_blocks"])
                      + described(record["omitted_blocks"]))
    if recorded != source:
        raise _refuse(
            f"{item_id}: the census partial record names blocks "
            f"{recorded!r}, the source has {source!r}")
    chosen = {int(entry["examples_line"])
              for entry in record["selected_blocks"]}
    return (sorted(value for block in blocks
                   if block["examples_line"] in chosen
                   for value in block["pickle_ids"]),
            sorted(value for block in blocks
                   for value in block["pickle_ids"]))


def _source_item_blocks(project: str, snapshot: "SourceSnapshot",
                        row: Mapping[str, Any]) -> list[dict]:
    """This criterion's `Examples:` blocks, each with its own tags and rows.

    An `Examples:` block carries its OWN tags in Gherkin, so one outline can
    be half inside the suite's tag filter and half outside it -- which is
    exactly what `unit/responses.feature:4` is.  The block, not the item, is
    therefore the unit at which the filter may cut, and this returns the
    blocks so `_build_discovery_census` can prove the cut fell on block
    boundaries rather than through the middle of one.

    A plain `Scenario` has no blocks and returns `[]`: nothing can partially
    select a single pickle, so there is no boundary to check.
    """
    from ..core.gherkin import parse_feature_file
    from ..toolkit.pystep_index import (CUCUMBER_DIALECT, StepResolutionError,
                                examples_rows)
    from .algorand import runtime_feature_path

    provenance = row.get("provenance")
    if not isinstance(provenance, dict):
        raise _refuse("criterion item has no provenance")
    source = provenance.get("file_path")
    line = provenance.get("line")
    if not isinstance(source, str) or not isinstance(line, int) \
            or isinstance(line, bool):
        raise _refuse("criterion provenance path/line is malformed")
    runtime = runtime_feature_path(project, source)
    raw = snapshot.files.get(runtime)
    if not isinstance(raw, bytes):
        raise _refuse(f"criterion feature is absent from source: {runtime}")
    try:
        feature = parse_feature_file(runtime, text=raw.decode("utf-8"))
        scenario = feature.scenario_at(line)
        if scenario is None:
            raise ValueError("scenario line is absent")
        if not scenario.kind.startswith("Scenario Outline"):
            return []
        rows = examples_rows(feature, scenario, dialect=CUCUMBER_DIALECT)
    except (UnicodeDecodeError, StepResolutionError, ValueError) as exc:
        raise _refuse(f"criterion cannot be joined to source: {source}:{line}") \
            from exc

    by_line = {row_line for row_line, _values in rows}
    blocks: list[dict] = []
    for start, end in scenario.examples_lines:
        member = sorted(
            value for value in by_line if start < value <= end)
        # The block's tags are the contiguous `@` lines directly above its
        # `Examples:` keyword -- Gherkin's own placement.
        tags: list[str] = []
        index = start - 1
        while index >= 0:
            text = feature.lines[index].strip()
            if not text:
                index -= 1
                continue
            if not text.startswith("@"):
                break
            tags = text.split() + tags
            index -= 1
        blocks.append({
            "examples_line": start + 1, "tags": tags,
            "pickle_ids": [f"{runtime}:{value}" for value in member],
        })
    if sorted(value for block in blocks
              for value in block["pickle_ids"]) != sorted(
                  f"{runtime}:{value}" for value in by_line):
        raise _refuse(
            f"{source}:{line}: Examples rows do not partition into blocks")
    return blocks


def _build_discovery_census(project: str, items_path: str,
                            snapshot: "SourceSnapshot", admission: dict,
                            dry_results: Sequence[tuple[str, CommandResult]],
                            *, tag_expression: str | None,
                            tag_file_sha256: str | None) -> dict:
    actual: set[str] = set()
    for label, result in dry_results:
        selected = set(_capture_pickle_ids(result, label, project))
        if actual & selected:
            raise _refuse("discovery dry-run captures overlap")
        actual.update(selected)
    rows, _raw = _jsonl_rows(items_path)
    criteria = [row for row in rows if row.get("project") == project
                and row.get("task") == "criterion_to_test"]
    blocked = set(admission["precontact_excluded_item_ids"])
    candidates = [row for row in criteria if row["item_id"] not in blocked]
    if [row["item_id"] for row in candidates] != admission["admitted_item_ids"]:
        raise _refuse("discovery source item population changed")
    claimed: set[str] = set()
    census_rows = []
    for row in candidates:
        expected = _source_item_pickles(project, snapshot, row)
        selected = sorted(set(expected) & actual)
        partial = None
        if selected and selected != sorted(expected):
            # An `Examples:` block carries its own tags, so the suite's tag
            # filter may legitimately take some of an outline's blocks and
            # leave others -- but it can only ever cut on a BLOCK boundary,
            # because a tag admits a whole block or none of it.  A cut THROUGH
            # a block is the shape the old all-or-nothing rule existed to
            # catch (a truncated or doctored capture), and it still refuses.
            partial = _partial_selection(
                project, snapshot, row, expected, set(selected))
        admitted = bool(selected)
        if project == "epubcheck" and not admitted:
            raise _refuse(f"{row['item_id']}: EPUB criterion is absent from dry run")
        claimed.update(selected)
        census_rows.append({
            "item_id": row["item_id"], "admitted": admitted,
            "exclusion_reason": None if admitted else "tag_expression_excluded",
            "pickle_ids": selected,
            "partial_selection": partial,
        })
    if claimed != actual:
        raise _refuse("discovery dry run selected a foreign source pickle")
    admitted_rows = [row for row in census_rows if row["admitted"]]
    pickle_count = sum(len(row["pickle_ids"]) for row in admitted_rows)
    if project == "algorand-sdk" and (len(admitted_rows), pickle_count) \
            != (125, 475):
        raise _refuse("Algorand discovery census is not the frozen 125/475")
    if project == "epubcheck" and len(admitted_rows) != 1041:
        raise _refuse("EPUB discovery census does not represent all 1,041 criteria")
    return {
        "schema": CENSUS_SCHEMA, "path": PATH, "project": project,
        "source": dict(snapshot.identity),
        "items_file_sha256": admission["items_file_sha256"],
        "tag_expression": tag_expression,
        "tag_file_sha256": tag_file_sha256,
        "precontact_excluded_item_ids":
            admission["precontact_excluded_item_ids"],
        "items": census_rows,
        "totals": {"source_criteria": admission["criterion_items"],
                   "post_precontact_items": len(candidates),
                   "admitted_items": len(admitted_rows),
                   "admitted_pickles": pickle_count},
    }


def _valid_partial_record(row: Mapping[str, Any]) -> bool:
    """A census item's `partial_selection`: absent, or an exact block record."""
    record = row["partial_selection"]
    if record is None:
        return True
    if not row["admitted"] or not isinstance(record, dict) \
            or set(record) != {"expected_pickles", "selected_pickles",
                               "selected_blocks", "omitted_blocks"}:
        return False
    counts = []
    for key in ("selected_blocks", "omitted_blocks"):
        blocks = record[key]
        if not isinstance(blocks, list) or not blocks:
            return False
        for block in blocks:
            if not isinstance(block, dict) \
                    or set(block) != {"examples_line", "tags", "pickles"} \
                    or not isinstance(block["examples_line"], int) \
                    or isinstance(block["examples_line"], bool) \
                    or block["examples_line"] < 1 \
                    or not isinstance(block["pickles"], int) \
                    or isinstance(block["pickles"], bool) \
                    or block["pickles"] < 1 \
                    or not isinstance(block["tags"], list) \
                    or any(not isinstance(tag, str) or not tag.startswith("@")
                           for tag in block["tags"]):
                return False
        counts.append(sum(block["pickles"] for block in blocks))
    selected, omitted = counts
    return (record["selected_pickles"] == selected == len(row["pickle_ids"])
            and record["expected_pickles"] == selected + omitted)


def validate_research_census(project: str, census_path: str, *,
                             expected_sha256: str,
                             snapshot: "SourceSnapshot",
                             admission: dict) -> dict:
    raw = Path(_absolute(census_path, "research-minimal census")).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise _refuse("research-minimal census differs from review")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("research-minimal census is not JSON") from exc
    expected_keys = {
        "schema", "path", "project", "source", "items_file_sha256",
        "tag_expression", "tag_file_sha256", "precontact_excluded_item_ids",
        "items", "totals"}
    if not isinstance(document, dict) or set(document) != expected_keys \
            or document.get("schema") != CENSUS_SCHEMA \
            or document.get("path") != PATH \
            or document.get("project") != project \
            or document.get("source") != dict(snapshot.identity) \
            or document.get("items_file_sha256") \
            != admission["items_file_sha256"] \
            or document.get("precontact_excluded_item_ids") \
            != admission["precontact_excluded_item_ids"]:
        raise _refuse("research-minimal census has another identity/population")
    rows = document.get("items")
    expected_ids = admission["admitted_item_ids"]
    if not isinstance(rows, list) or [row.get("item_id") for row in rows
                                      if isinstance(row, dict)] != expected_ids:
        raise _refuse("research-minimal census is not the post-precontact set")
    pickles: list[str] = []
    admitted_ids = []
    item_pickles = {}
    exclusions = {}
    for row in rows:
        if set(row) != {"item_id", "admitted", "exclusion_reason",
                       "pickle_ids", "partial_selection"} \
                or not isinstance(row["admitted"], bool) \
                or not isinstance(row["pickle_ids"], list) \
                or any(not isinstance(value, str) or not value
                       for value in row["pickle_ids"]) \
                or row["pickle_ids"] != sorted(set(row["pickle_ids"])):
            raise _refuse("research-minimal census item is malformed")
        # A partly selected item is admitted, never silently: the record says
        # which Examples blocks went in and which stayed out, and it must
        # agree with the pickle count beside it.
        if not _valid_partial_record(row):
            raise _refuse("research-minimal census partial record is malformed")
        if row["admitted"]:
            if row["exclusion_reason"] is not None or not row["pickle_ids"]:
                raise _refuse("admitted census item is empty/reasoned")
            admitted_ids.append(row["item_id"])
            item_pickles[row["item_id"]] = row["pickle_ids"]
            pickles.extend(row["pickle_ids"])
        elif row["exclusion_reason"] != "tag_expression_excluded" \
                or row["pickle_ids"]:
            raise _refuse("excluded census item has another disposition")
        else:
            exclusions[row["item_id"]] = row["exclusion_reason"]
    if len(pickles) != len(set(pickles)):
        raise _refuse("research-minimal census repeats pickle identities")
    expected_totals = {
        "source_criteria": admission["criterion_items"],
        "post_precontact_items": len(expected_ids),
        "admitted_items": len(admitted_ids),
        "admitted_pickles": len(pickles),
    }
    if document["totals"] != expected_totals \
            or project == "algorand-sdk" and (
                len(admitted_ids), len(pickles)) != (125, 475) \
            or project == "epubcheck" and len(admitted_ids) != 1041:
        raise _refuse("research-minimal census totals differ from the gate")
    return {
        **admission,
        "admitted_criterion_items": len(admitted_ids),
        "admitted_item_ids": admitted_ids,
        "tag_exclusions": exclusions,
        "admitted_pickle_ids": sorted(pickles),
        "admitted_item_pickle_ids": item_pickles,
        "tag_census": {
            "file_sha256": expected_sha256,
            "tag_expression": document["tag_expression"],
            "tag_file_sha256": document["tag_file_sha256"],
            "admitted_items": len(admitted_ids),
            "admitted_pickles": len(pickles),
        },
    }


def _authority(runner: Runner, approval: Approval) -> dict:
    value = runner.revalidate_authority()
    if not isinstance(value, Mapping):
        raise _refuse("runner returned no Docker authority record")
    record = dict(value)
    if set(record) != {"reference", "daemon_fingerprint"} \
            or record["reference"] != approval.authority_reference \
            or record["daemon_fingerprint"] != approval.daemon_fingerprint:
        raise _refuse("Docker authority differs from the phase approval")
    return record


def _checked(runner: Runner, argv: Sequence[str], *, timeout: int,
             build: bool = False,
             accepted_returncodes: tuple[int, ...] = (0,)) -> CommandResult:
    exact = tuple(argv)
    result = runner.run(exact, timeout=timeout, build=build)
    if result.argv != exact:
        raise _refuse("runner reported an argv different from the request")
    if not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes) \
            or len(result.stdout) > MAX_LOG_BYTES \
            or len(result.stderr) > MAX_LOG_BYTES:
        raise _refuse("command log is not bounded bytes")
    if not accepted_returncodes \
            or any(not isinstance(code, int) or isinstance(code, bool)
                   for code in accepted_returncodes):
        raise _refuse("accepted command return-code set is malformed")
    if result.timed_out or result.overflowed \
            or result.returncode not in accepted_returncodes:
        raise _refuse(
            f"command failed without retry: {exact[:3]!r} "
            f"(exit {result.returncode})")
    return result


def _absolute(path: os.PathLike[str] | str, label: str) -> str:
    value = os.fspath(path)
    if not os.path.isabs(value) or os.path.normpath(value) != value \
            or "\x00" in value:
        raise _refuse(f"{label} must be one normalized absolute path")
    return value


def _create_output(path: os.PathLike[str] | str) -> str:
    value = _absolute(path, "phase output")
    if os.path.lexists(value):
        raise _refuse("phase output must be absent; resume/overwrite is forbidden")
    os.mkdir(value, 0o700)
    return value


def _write(path: str, raw: bytes, *, mode: int = 0o600) -> dict:
    if not isinstance(raw, bytes):
        raise _refuse("artifact is not bytes")
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path, "xb") as handle:
        handle.write(raw)
    os.chmod(path, mode)
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"))
            + "\n").encode("utf-8")


def _read_document(path: str, *, expected_sha256: str,
                   phase: str, project: str) -> dict:
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise _refuse(f"approved {phase} transcript bytes changed")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse(f"{phase} transcript is not JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != IMAGE_SCHEMA \
            or value.get("path") != PATH or value.get("project") != project \
            or value.get("phase") != phase or value.get("status") != "complete":
        raise _refuse(f"predecessor is not one complete {phase} transcript")
    return value


def _transcript(out: str, document: dict) -> dict:
    path = os.path.join(out, "transcript.json")
    _write(path, _canonical_json(document))
    return document


def _inspect(stdout: bytes, expected_id: str | None = None) -> dict:
    try:
        value = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("Docker inspect output is not JSON") from exc
    if not isinstance(value, list) or len(value) != 1 \
            or not isinstance(value[0], dict):
        raise _refuse("Docker inspect output is not one object")
    image_id = value[0].get("Id")
    if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None \
            or expected_id is not None and image_id != expected_id:
        raise _refuse("Docker inspect returned another/malformed config ID")
    return value[0]


def _artifacts(out: str, names: Sequence[str]) -> list[dict]:
    return [{"path": rel, "bytes": len(raw),
             "sha256": hashlib.sha256(raw).hexdigest()}
            for rel in sorted(names) for raw in [Path(out, rel).read_bytes()]]


def _java_banner_matches(raw: bytes, major: int) -> bool:
    text = raw.decode("utf-8", "replace")
    pattern = r'\bversion "1\.8(?:[."_])' if major == 8 \
        else rf'\bversion "{major}(?:[."_])'
    return re.search(pattern, text) is not None


def canonical_dockerfile(config: ProjectConfig, base_digest: str) -> bytes:
    if _IMAGE_ID.fullmatch(base_digest) is None:
        raise _refuse("canonical Dockerfile base digest is malformed")
    reference = f"{config.base_name}@{base_digest}"
    return (
        f"FROM {reference} AS payloads\n"
        "COPY approved-m2/ /opt/m2/\n\n"
        f"FROM {reference}\n"
        "COPY --from=payloads /opt/m2/ /opt/m2/\n"
        "COPY offline-settings.xml /root/.m2/settings.xml\n"
        "ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC\n"
        "WORKDIR /work\n"
        "ENTRYPOINT []\n"
        "CMD [\"tail\",\"-f\",\"/dev/null\"]\n").encode("utf-8")


def _manifest(files: Mapping[str, bytes]) -> tuple[dict, str]:
    entries = []
    total = 0
    for path in sorted(files, key=lambda value: value.encode("utf-8")):
        raw = files[path]
        if not isinstance(path, str) or not path or path.startswith("/") \
                or Path(path).as_posix() != path or ".." in Path(path).parts \
                or not isinstance(raw, bytes):
            raise _refuse("captured Maven repository has an unsafe path/value")
        if _TRANSIENT.search(path):
            raise _refuse(f"Maven repository retains transient marker {path}")
        total += len(raw)
        entries.append({"path": path, "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest()})
    if not entries or len(entries) > MAX_M2_FILES or total > MAX_M2_BYTES:
        raise _refuse("Maven repository is empty or exceeds its source ceiling")
    from .j0 import framed_tree_sha256
    return ({"schema": MANIFEST_SCHEMA, "files": entries,
             "totals": {"files": len(entries), "bytes": total}},
            framed_tree_sha256(files.items()))


def _tree_paths(root: str) -> list[str]:
    """Every regular file under `root`, relative and in traversal order.

    One traversal with one set of guards, shared by `_tree_files` and the
    transient purge, so the two can never disagree about what is in a tree.
    """
    root = _absolute(root, "tree root")
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            if Path(dirpath, name).is_symlink():
                raise _refuse("tree contains a linked/special directory")
        for name in filenames:
            path = Path(dirpath, name)
            if path.is_symlink() or not path.is_file():
                raise _refuse("tree contains a link or special file")
            found.append(path.relative_to(root).as_posix())
    return found


def _tree_files(root: str) -> dict[str, bytes]:
    root = _absolute(root, "tree root")
    return {rel: Path(root, *rel.split("/")).read_bytes()
            for rel in _tree_paths(root)}


def _purge_transient(root: str) -> list[str]:
    """Delete exactly the resolver bookkeeping `_manifest` refuses, no more.

    `io.cucumber:html-formatter` and `io.cucumber:gherkin` declare a version
    RANGE `[19.0.0,20.0.0)` on `io.cucumber:messages`, so Maven must fetch that
    artifact's `maven-metadata.xml` and Maven Resolver writes
    `resolver-status.properties` beside it recording a host wall-clock.  That
    timestamp is bookkeeping about a fetch, never a payload artifact, and
    keeping it would make the canonical image's `/opt/m2` irreproducible.  The
    metadata itself stays: offline range resolution reads it.
    """
    root = _absolute(root, "Maven repository root")
    removed = [rel for rel in _tree_paths(root) if _TRANSIENT.search(rel)]
    for rel in removed:
        os.remove(os.path.join(root, *rel.split("/")))
    if any(_TRANSIENT.search(rel) for rel in _tree_paths(root)):
        raise _refuse("Maven repository still retains a transient marker")
    return removed


@dataclass(frozen=True)
class SourceSnapshot:
    root: str
    identity: Mapping[str, Any]
    files: Mapping[str, bytes]
    modes: Mapping[str, int]


@dataclass(frozen=True)
class PreparedWorkspace:
    root: str
    workspace: str
    gold: str
    document: Mapping[str, Any]
    boundary: Any
    strip_manifest: Any


def _tree_identity(files: Mapping[str, bytes]) -> dict:
    from .j0 import framed_tree_sha256
    return {
        "files": len(files),
        "bytes": sum(len(raw) for raw in files.values()),
        "tree_sha256": framed_tree_sha256(files.items()),
    }


def _authenticate_source(project: str, source_root: str,
                         source_manifest: str,
                         expected_sha256: str) -> SourceSnapshot:
    """Authenticate the raw pin/composition and return its exact file map."""
    root = _absolute(source_root, "raw source workspace")
    manifest_path = _absolute(source_manifest, "source/composition manifest")
    raw = Path(manifest_path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise _refuse("source/composition manifest differs from review")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("source/composition manifest is not JSON") from exc

    if project == "epubcheck":
        from . import j0
        try:
            manifest = j0.validate_source_archive_manifest(document)
            j0.validate_source_checkout(project, root, manifest)
        except (j0.J0Error, OSError) as exc:
            raise _refuse(f"EPUBCheck source checkout is not its pin: {exc}") \
                from exc
        if manifest["git_tree"] != PROJECTS[project].source_tree:
            raise _refuse("EPUBCheck Git tree differs from the reviewed pin")
        files = {entry["path"]: Path(root, *entry["path"].split("/")).read_bytes()
                 for entry in manifest["files"]}
        modes = {entry["path"]: (0o755 if entry["git_mode"] == "100755"
                                 else 0o644)
                 for entry in manifest["files"]}
        identity = {
            "kind": "source-archive",
            "manifest_sha256": expected_sha256,
            "commit": manifest["commit"],
            "git_tree": manifest["git_tree"],
            "archive_tree_sha256": manifest["archive_tree_sha256"],
        }
    else:
        from . import compose_algorand
        output = os.path.dirname(manifest_path)
        if os.path.realpath(root) != os.path.realpath(
                os.path.join(output, "workspace")):
            raise _refuse("Algorand source root is not the reviewed composition")
        try:
            manifest = compose_algorand.validate(output)
        except (compose_algorand.CompositionError, OSError) as exc:
            raise _refuse(f"Algorand composition is not exact: {exc}") from exc
        if manifest["destination_tree_sha256"] != PROJECTS[project].source_tree:
            raise _refuse("Algorand composition tree differs from the reviewed pin")
        files = _tree_files(root)
        modes = {rel: 0o644 for rel in files}
        identity = {
            "kind": "algorand-composition",
            "manifest_sha256": expected_sha256,
            "destination_tree_sha256": manifest["destination_tree_sha256"],
            "sources": manifest["sources"],
        }
    return SourceSnapshot(root, identity, files, modes)


def _boundary_path(project: str) -> str:
    name = "boundary_epubcheck.yml" if project == "epubcheck" \
        else "boundary_algorand.yml"
    return str(Path(__file__).resolve().parents[2] / "config" / name)


def _materialize_snapshot(snapshot: SourceSnapshot, destination: str) -> None:
    os.mkdir(destination, 0o755)
    for rel, raw in snapshot.files.items():
        target = os.path.join(destination, *rel.split("/"))
        os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
        _write(target, raw, mode=snapshot.modes.get(rel, 0o644))
    for directory, _dirnames, _filenames in os.walk(destination):
        os.chmod(directory, 0o755)


def _prepare_runtime_from_snapshot(project: str, snapshot: SourceSnapshot,
                                   out: str, *, stripped: bool) -> dict:
    """Apply the existing Cucumber strip/preparation to one fresh snapshot."""
    from ..core.boundary import load_boundary
    from ..bench import repo
    from ..stacks.cucumber import (CucumberStackRefused, integrity_baseline,
                                   strip_repo_cucumber)

    output = _create_output(out)
    workspace = os.path.join(output, "workspace")
    gold = os.path.join(output, "gold")
    _materialize_snapshot(snapshot, workspace)
    os.mkdir(gold, 0o700)
    boundary_path = _boundary_path(project)
    boundary = load_boundary(boundary_path, repo_root=workspace)
    try:
        manifest = strip_repo_cucumber(
            boundary, gold, stripped=stripped)
        integrity_baseline(
            manifest, boundary, os.path.join(gold, "strip_manifest.json"),
            stripped=stripped)
    except (CucumberStackRefused, SystemExit, OSError) as exc:
        raise _refuse(f"deterministic Cucumber preparation failed: {exc}") \
            from exc
    if not stripped:
        repo.restore(manifest, manifest.moved + manifest.moved_config)

    strip_raw = Path(gold, "strip_manifest.json").read_bytes()
    workspace_identity = _tree_identity(_tree_files(workspace))
    boundary_raw = Path(boundary_path).read_bytes()
    document = {
        "schema": PREPARATION_SCHEMA,
        "path": PATH,
        "project": project,
        "mode": "stripped" if stripped else "unstripped",
        "source": dict(snapshot.identity),
        "boundary_sha256": hashlib.sha256(boundary_raw).hexdigest(),
        "strip_manifest_sha256": hashlib.sha256(strip_raw).hexdigest(),
        "workspace": workspace_identity,
    }
    _write(os.path.join(output, "preparation.json"), _canonical_json(document))
    return document


def prepare_runtime_workspace(project: str, *, source_root: str,
                              source_manifest: str, out: str,
                              stripped: bool) -> dict:
    """Create a reviewable derived workspace; it performs no Maven/Docker IO."""
    raw = Path(_absolute(source_manifest, "source/composition manifest")).read_bytes()
    snapshot = _authenticate_source(
        project, source_root, source_manifest,
        hashlib.sha256(raw).hexdigest())
    return _prepare_runtime_from_snapshot(project, snapshot, out,
                                          stripped=stripped)


def _under_prefix(path: str, prefix: str) -> bool:
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


#: ALGORAND_BUNDLE_V1_SPEC.md section 13 (PROPOSED 2026-08-19): recorded
#: collection-time runner bytes for the pinned wave-5 Algorand stripped
#: preparation, keyed by its `preparation.json` SHA-256.  That preparation
#: (manifest `69fad45f…`, workspace tree `610ed127…`, 680 files,
#: 18,077,179 bytes, strip manifest `6173c01e…`) was byte-exact under
#: collection-day code `48fc7ec` (2026-08-11).  Commit `5554d47`
#: (2026-08-17) widened the stripped-mode offline runner's `extraGlue` to
#: also scan `com.algorand.algosdk.unit`, so a fresh derivation with
#: current code emits a 790-byte wide runner (`f8af1941…`) where the frozen
#: tree — and every executed and released wave-5 artifact — carries the
#: 759-byte narrow one (`87d6af45…`).  Validating THIS preparation against
#: a fresh derivation would therefore refuse the true frozen bytes;
#: validation of a pinned preparation compares against these recorded
#: bytes instead.  Every check around the runner comparison — manifest
#: hash, workspace tree identity, strip-manifest digests, substrate
#: verification — is unchanged, so tampering with the pinned workspace
#: still refuses, and every preparation NOT keyed here still validates
#: against the current derivation.
_COLLECTION_TIME_RUNNERS: dict[str, dict[str, bytes]] = {
    "69fad45f57da8916cf5cda6d45e1891bafb8e3b6bb4243b160bdc03999e189bb": {
        # sha256 7ffd166454f8329f3dad334b86a6429ab95ef7d07bbba3b7490b0f60
        # dc7f1ff2, 752 bytes.
        "src/test/java/com/algorand/algosdk/unit/R2TBenchCucumberTest.java":
            b"""\
package com.algorand.algosdk.unit;

import org.junit.runner.RunWith;

import io.cucumber.junit.Cucumber;
import io.cucumber.junit.CucumberOptions;

/**
 * Written by r2t's cucumber strip (r2t/stacks/cucumber.py) and hashed into
 * the substrate baseline; editing it during a run is a tampering abort.
 *
 * It exists so that the JSON plugin the harness folds is declared HERE and
 * never on the command line: algorand-sdk's own runner is retained
 * byte-for-byte, and a `-Dcucumber.plugin` flag would collide with any
 * runner that already holds STDOUT.
 */
@RunWith(Cucumber.class)
@CucumberOptions(extraGlue = "com.algorand.algosdk.cucumber.shared", \
strict = true, plugin = {"json:target/r2t-cucumber.json"})
public class R2TBenchCucumberTest
{
}
""",
        # sha256 87d6af457399ab4c066e276e5a593e420ca76dbd35a4b189d370e993
        # 8b1f1ffe, 759 bytes.  Differs from today's stripped-mode
        # derivation only in `extraGlue`.
        "src/test/java/com/algorand/algosdk/integration/"
        "R2TBenchCucumberTest.java":
            b"""\
package com.algorand.algosdk.integration;

import org.junit.runner.RunWith;

import io.cucumber.junit.Cucumber;
import io.cucumber.junit.CucumberOptions;

/**
 * Written by r2t's cucumber strip (r2t/stacks/cucumber.py) and hashed into
 * the substrate baseline; editing it during a run is a tampering abort.
 *
 * It exists so that the JSON plugin the harness folds is declared HERE and
 * never on the command line: algorand-sdk's own runner is retained
 * byte-for-byte, and a `-Dcucumber.plugin` flag would collide with any
 * runner that already holds STDOUT.
 */
@RunWith(Cucumber.class)
@CucumberOptions(extraGlue = "com.algorand.algosdk.cucumber.shared", \
strict = true, plugin = {"json:target/r2t-cucumber.json"})
public class R2TBenchCucumberTest
{
}
""",
    },
}


def _validate_preparation(project: str, snapshot: SourceSnapshot,
                          preparation_manifest: str, expected_sha256: str,
                          *, stripped: bool) -> PreparedWorkspace:
    """Verify the reviewed manifest and the executable derived tree."""
    from ..core.boundary import REMOVABLE, load_boundary
    from ..bench import repo
    from ..stacks.cucumber import (CucumberStackRefused, installed_sources_for,
                                   pom_with_coverage, runner_variants_for)

    path = _absolute(preparation_manifest, "workspace preparation manifest")
    raw = Path(path).read_bytes()
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    if manifest_sha256 != expected_sha256:
        raise _refuse("workspace preparation manifest differs from review")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("workspace preparation manifest is not JSON") from exc
    if not isinstance(document, dict) or set(document) != {
            "schema", "path", "project", "mode", "source",
            "boundary_sha256", "strip_manifest_sha256", "workspace"} \
            or document["schema"] != PREPARATION_SCHEMA \
            or document["path"] != PATH or document["project"] != project \
            or document["mode"] != ("stripped" if stripped else "unstripped") \
            or document["source"] != dict(snapshot.identity):
        raise _refuse("workspace preparation manifest has another identity")

    root = os.path.dirname(path)
    workspace = os.path.join(root, "workspace")
    gold = os.path.join(root, "gold")
    if sorted(os.listdir(root)) != ["gold", "preparation.json", "workspace"]:
        raise _refuse("workspace preparation has an unexpected top-level path")
    boundary_path = _boundary_path(project)
    boundary_raw = Path(boundary_path).read_bytes()
    if document["boundary_sha256"] != hashlib.sha256(boundary_raw).hexdigest():
        raise _refuse("workspace preparation names another boundary")
    boundary = load_boundary(boundary_path, repo_root=workspace)
    strip_path = os.path.join(gold, "strip_manifest.json")
    strip_raw = Path(strip_path).read_bytes()
    if document["strip_manifest_sha256"] != hashlib.sha256(strip_raw).hexdigest():
        raise _refuse("workspace strip manifest bytes changed")
    try:
        manifest = repo.load_manifest(strip_path)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _refuse("workspace strip manifest is malformed") from exc
    if os.path.realpath(manifest.repo_root) != os.path.realpath(workspace) \
            or os.path.realpath(manifest.gold_root) != os.path.realpath(gold) \
            or manifest.boundary_version != boundary.version:
        raise _refuse("strip manifest belongs to another workspace/boundary")

    variants = runner_variants_for(project, stripped=stripped)
    expected = dict(snapshot.files)
    removable = [rel for rel in expected
                 if boundary.classify(rel) == REMOVABLE]
    config = [rel for rel in removable
              if any(_under_prefix(rel, prefix)
                     for prefix in boundary.removable_config)]
    moved = sorted(set(removable) - set(config))
    config.sort()
    if stripped:
        for rel in removable:
            expected.pop(rel, None)
    try:
        expected["pom.xml"] = pom_with_coverage(
            snapshot.files["pom.xml"].decode("utf-8")).encode("utf-8")
    except (KeyError, UnicodeDecodeError, CucumberStackRefused) as exc:
        raise _refuse(f"pinned POM cannot receive reviewed runtime patch: {exc}") \
            from exc
    # The runners plus, beside each runner whose fork carries the direct-call
    # agent, the step-tag listener its `plugin` element names.  A PINNED
    # preparation predates the listener: its recorded bytes are the two
    # runners and nothing else, and its workspace holds no listener.
    installed = installed_sources_for(project, stripped=stripped)
    recorded = _COLLECTION_TIME_RUNNERS.get(manifest_sha256)
    if recorded is None:
        installed_rels = sorted(installed)
        for rel, text in installed.items():
            expected[rel] = text.encode("utf-8")
    elif set(recorded) not in ({variant.runner_rel for variant in variants},
                               set(installed)):
        raise _refuse("recorded collection-time runners do not cover this "
                      "preparation's runner set")
    else:
        # The pin names every harness-owned source that preparation installed.
        # A preparation made before the step-tag listener existed names the
        # runners and nothing else, and its workspace holds nothing else.
        installed_rels = sorted(recorded)
        expected.update(recorded)

    actual = _tree_files(workspace)
    if actual != expected or document["workspace"] != _tree_identity(actual):
        raise _refuse("derived workspace bytes differ from source/strip policy")
    if sorted(manifest.moved) != moved \
            or sorted(manifest.moved_config) != config \
            or manifest.patched != ["pom.xml"] \
            or sorted(manifest.installed) != installed_rels \
            or manifest.roots() != repo.CUCUMBER_SUBSTRATE_ROOTS \
            or manifest.volatile() != repo.CUCUMBER_SUBSTRATE_VOLATILE \
            or manifest.bytecode_roots != [] \
            or manifest.build_roots != list(repo.CUCUMBER_BUILD_ROOTS) \
            or not manifest.digests:
        raise _refuse("strip manifest differs from deterministic preparation")
    for rel in removable:
        gold_file = os.path.join(gold, *rel.split("/"))
        if not os.path.isfile(gold_file) \
                or Path(gold_file).read_bytes() != snapshot.files[rel]:
            raise _refuse("strip gold does not retain exact source glue")
    report = repo.verify_substrate(manifest, boundary)
    if report["changed"] or report["missing"] or report["added"]:
        raise _refuse("derived workspace changed outside the strip boundary")
    return PreparedWorkspace(root, workspace, gold, document, boundary, manifest)


def _copy_regular_tree(source: str, destination: str) -> None:
    """Copy a payload tree at modes that do not depend on the invoking umask.

    This builds the canonical image's build context, so every mode here is
    COPYed into the image and read back by `capture_tar_repository`, which
    requires 0755 for every directory and 0644 for every file.  `os.makedirs`
    applies its `mode` only to the FINAL component -- every ancestor it creates
    gets `0o777 & ~umask` -- so the explicit walk below is the directory
    counterpart of the explicit file mode `_write` is given, exactly as
    `_materialize_snapshot` already does for a prepared workspace.
    """
    files = _tree_files(source)
    os.mkdir(destination, 0o755)
    for rel, raw in files.items():
        target = os.path.join(destination, *rel.split("/"))
        os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
        _write(target, raw, mode=0o644)
    for directory, _dirnames, _filenames in os.walk(destination):
        os.chmod(directory, 0o755)


def _base_reference(config: ProjectConfig, approval: Approval) -> str:
    return f"{config.base_name}@{approval.base_digest}"


def run_base_phase(project: str, *, items_path: str, out: str,
                   runner: Runner, approval_path: str | None = None,
                   approved_digest: str | None = None) -> dict:
    return _execute_base(project, items_path=items_path, out=out, runner=runner,
                         approval=require_source_approval(
                             project, "base", approval_path=approval_path,
                             approved_digest=approved_digest))


def _execute_base(project: str, *, items_path: str, out: str,
                  runner: Runner, approval: Approval) -> dict:
    cfg = _config(project)
    _validate_approval(approval, project, "base")
    # This deliberately precedes both authority revalidation and the pull.
    admission = precontact_admission(project, items_path)
    output = _create_output(out)
    authority = _authority(runner, approval)
    reference = _base_reference(cfg, approval)

    pull_argv = ("image", "pull", "--platform", "linux/amd64", reference)
    pull = _checked(runner, pull_argv, timeout=3600)
    _write(os.path.join(output, "pull.stdout"), pull.stdout)
    _write(os.path.join(output, "pull.stderr"), pull.stderr)

    first = _checked(runner, ("image", "inspect", reference), timeout=120)
    resolved = _inspect(first.stdout)
    image_id = resolved["Id"]
    second = _checked(runner, ("image", "inspect", image_id), timeout=120)
    inspected = _inspect(second.stdout, image_id)
    repo_digests = inspected.get("RepoDigests")
    if inspected.get("Os") != "linux" or inspected.get("Architecture") != "amd64" \
            or not isinstance(repo_digests, list) or not any(
                isinstance(value, str)
                and value.endswith("@" + approval.base_digest)
                and value.split("@", 1)[0] in {"maven", "docker.io/library/maven"}
                for value in repo_digests):
        raise _refuse("base inspection disagrees on digest/platform")
    java = _checked(runner, (
        "run", "--rm", "--network", "none", "--pull=never",
        "--entrypoint", "java", image_id, "-version"), timeout=120)
    if not _java_banner_matches(java.stdout + java.stderr, cfg.jdk_major):
        raise _refuse(f"base image is not JDK {cfg.jdk_major}")
    _write(os.path.join(output, "inspect.json"), second.stdout)
    _write(os.path.join(output, "java-version.stdout"), java.stdout)
    _write(os.path.join(output, "java-version.stderr"), java.stderr)

    names = ["inspect.json", "java-version.stderr", "java-version.stdout",
             "pull.stderr", "pull.stdout"]
    document = {
        "schema": IMAGE_SCHEMA, "path": PATH, "project": project,
        "phase": "base", "status": "complete",
        "execution_identity": approval.execution_identity,
        "authority": authority, "admission": admission,
        "commands": [list(pull_argv), list(first.argv), list(second.argv),
                     list(java.argv)],
        "result": {"base_reference": reference, "base_config_id": image_id,
                   "platform": "linux/amd64", "jdk_major": cfg.jdk_major,
                   "cleanup": {"base_retained": True,
                               "leftover_containers": []}},
        "artifacts": _artifacts(output, names),
    }
    return _transcript(output, document)


def _epub_commands(prefix: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    return (
        prefix + ("-Dcucumber.plugin=json:/work/target/r2t-cucumber.json",
                  "-Dcucumber.publish.quiet=true", "test"),
        prefix + ("-Djacoco.skip=true", "-Dtest=RunCucumberTest",
                  "-Dcucumber.execution.dry-run=true",
                  "-Dcucumber.plugin=json:/work/target/r2t-cucumber.json",
                  "-Dcucumber.publish.quiet=true", "test"),
        prefix + ("test-compile",),
        prefix + ("org.jacoco:jacoco-maven-plugin:0.8.11:help",),
    )


def _algorand_commands(prefix: tuple[str, ...], tag_expression: str,
                       *, dry_only: bool = False) -> tuple[tuple[str, ...], ...]:
    def target(runner: str, feature: str | None, dry: bool) -> tuple[str, ...]:
        values = prefix + ("-Djacoco.skip=true", f"-Dtest={runner}")
        if feature is not None:
            values += (f"-Dcucumber.features={feature}",)
        values += (f"-Dcucumber.filter.tags={tag_expression}",
                   "-Dcucumber.publish.quiet=true")
        if dry:
            values += ("-Dcucumber.execution.dry-run=true",)
        return values + ("test",)

    targets = (
        target(ALGORAND_UNIT_RUNNER, None, False),
        target(ALGORAND_UNIT_RUNNER, None, True),
        target(ALGORAND_OFFLINE_RUNNER, ALGORAND_OFFLINE_FEATURE, False),
        target(ALGORAND_OFFLINE_RUNNER, ALGORAND_OFFLINE_FEATURE, True),
    )
    return targets if dry_only else targets + (
        prefix + ("test-compile",),
        prefix + ("org.jacoco:jacoco-maven-plugin:0.8.11:help",))


def discovery_commands(project: str, *, tag_expression: str | None = None) \
        -> tuple[tuple[str, ...], ...]:
    _config(project)
    if project == "epubcheck":
        if tag_expression is not None:
            raise _refuse("EPUBCheck discovery has no tag expression")
        return _epub_commands(MAVEN_DISCOVERY_PREFIX)
    if not isinstance(tag_expression, str) or not tag_expression:
        raise _refuse("Algorand discovery requires the pinned tag expression")
    commands = _algorand_commands(MAVEN_DISCOVERY_PREFIX, tag_expression)
    _validate_algorand_commands(commands)
    return commands


def _validate_algorand_commands(commands: Sequence[Sequence[str]]) -> None:
    joined = "\n".join("\0".join(command) for command in commands)
    if "RunCucumberIntegrationTest" in joined \
            or "features/integration/" in joined \
            or "src/test/resources/com/algorand/algosdk/integration/" in joined \
            or joined.count(ALGORAND_OFFLINE_FEATURE) > 2:
        raise _refuse("Algorand command set admits an upstream integration suite")
    selectors = [value for command in commands for value in command
                 if value.startswith("-Dtest=")]
    if any(value not in {f"-Dtest={ALGORAND_UNIT_RUNNER}",
                         f"-Dtest={ALGORAND_OFFLINE_RUNNER}"}
           for value in selectors):
        raise _refuse("Algorand command set names a foreign runner")


def run_discovery_phase(project: str, *, items_path: str,
                        base_transcript: str, source_root: str,
                        source_manifest: str,
                        preparation_manifest: str,
                        out: str, runner: Runner,
                        approval_path: str | None = None,
                        approved_digest: str | None = None) -> dict:
    return _execute_discovery(
        project, items_path=items_path,
        base_transcript=base_transcript, source_root=source_root,
        source_manifest=source_manifest,
        preparation_manifest=preparation_manifest, out=out, runner=runner,
        approval=require_source_approval(
            project, "discovery", approval_path=approval_path,
            approved_digest=approved_digest))


def _execute_discovery(project: str, *, items_path: str,
                       base_transcript: str, source_root: str,
                       source_manifest: str,
                       preparation_manifest: str,
                       out: str, runner: Runner, approval: Approval) -> dict:
    cfg = _config(project)
    _validate_approval(approval, project, "discovery")
    admission = precontact_admission(project, items_path)
    predecessor = _read_document(
        _absolute(base_transcript, "base transcript"),
        expected_sha256=approval.predecessor_transcript_sha256 or "",
        phase="base", project=project)
    expected_authority = {
        "reference": approval.authority_reference,
        "daemon_fingerprint": approval.daemon_fingerprint,
    }
    if predecessor.get("authority") != expected_authority \
            or predecessor["result"].get("base_config_id") \
            != approval.base_config_id \
            or predecessor["result"].get("base_reference") \
            != _base_reference(cfg, approval):
        raise _refuse(
            "base transcript digest/config/authority differs from "
            "discovery approval")
    snapshot = _authenticate_source(
        project, source_root, source_manifest,
        approval.source_manifest_sha256 or "")
    prepared = _validate_preparation(
        project, snapshot, preparation_manifest,
        approval.preparation_manifest_sha256 or "", stripped=False)
    workspace = prepared.workspace
    tag_expression = tag_file_sha256 = None
    if project == "algorand-sdk":
        tag_expression, tag_file_sha256 = _algorand_tag_expression(snapshot)
    output = _create_output(out)
    m2 = os.path.join(output, "m2")
    os.mkdir(m2, 0o700)
    settings = os.path.join(output, "central-settings.xml")
    _write(settings, CENTRAL_SETTINGS)
    authority = _authority(runner, approval)
    commands = discovery_commands(
        project, tag_expression=tag_expression)

    log_names = ["central-settings.xml"]
    command_records = []
    dry_results: list[tuple[str, CommandResult]] = []
    for index, maven in enumerate(commands, 1):
        argv = (
            "run", "--rm", "--network", "bridge", "--pull=never",
            "--mount", f"type=bind,source={workspace},target=/work",
            "--mount", f"type=bind,source={m2},target=/opt/m2",
            "--mount", (f"type=bind,source={settings},"
                        "target=/root/.m2/settings.xml,readonly"),
            "--workdir", "/work", approval.base_config_id, *maven)
        result = _checked(runner, argv, timeout=7200)
        stdout_name = f"logs/{index:02d}.stdout"
        stderr_name = f"logs/{index:02d}.stderr"
        _write(os.path.join(output, stdout_name), result.stdout)
        _write(os.path.join(output, stderr_name), result.stderr)
        log_names += [stdout_name, stderr_name]
        artifact_refs = []
        for rel, raw in sorted(result.artifacts.items()):
            if not isinstance(rel, str) or _SAFE_ARTIFACT.fullmatch(rel) is None \
                    or rel.startswith("/") or ".." in Path(rel).parts \
                    or not isinstance(raw, bytes):
                raise _refuse("discovery runner returned an unsafe artifact")
            retained = f"runs/{index:02d}/artifacts/{rel}"
            _write(os.path.join(output, retained), raw)
            log_names.append(retained)
            artifact_refs.append(retained)
        if "-Dcucumber.execution.dry-run=true" in maven:
            dry_results.append((f"discovery command {index}", result))
        command_records.append({"index": index, "maven_argv": list(maven),
                                "docker_argv": list(argv), "exit_code": 0,
                                "artifacts": artifact_refs})

    expected_dry = 1 if project == "epubcheck" else 2
    if len(dry_results) != expected_dry:
        raise _refuse("discovery did not retain every exact dry-run capture")
    census_document = _build_discovery_census(
        project, items_path, snapshot, admission, dry_results,
        tag_expression=tag_expression,
        tag_file_sha256=tag_file_sha256)
    census_raw = _canonical_json(census_document)
    census_identity = _write(os.path.join(output, "census.json"), census_raw)
    log_names.append("census.json")

    from ..bench import repo
    substrate = repo.verify_substrate(
        prepared.strip_manifest, prepared.boundary)
    if substrate["changed"] or substrate["missing"] or substrate["added"]:
        raise _refuse("discovery changed source outside the strip boundary")
    # The networked resolution is over; what it left behind about WHEN it ran
    # is not part of the payload the canonical image is built from.
    purged = _purge_transient(m2)
    manifest, tree_sha = _manifest(_tree_files(m2))
    manifest_raw = _canonical_json(manifest)
    manifest_name = "m2-manifest.json"
    manifest_identity = _write(
        os.path.join(output, manifest_name), manifest_raw)
    log_names.append(manifest_name)
    document = {
        "schema": IMAGE_SCHEMA, "path": PATH, "project": project,
        "phase": "discovery", "status": "complete",
        "execution_identity": approval.execution_identity,
        "authority": authority, "admission": admission,
        "predecessor_transcript_sha256":
            approval.predecessor_transcript_sha256,
        "base": {"repository_digest": approval.base_digest,
                 "config_id": approval.base_config_id},
        "source": dict(snapshot.identity),
        "census": {"path": "census.json", **census_identity,
                   "admitted_items":
                       census_document["totals"]["admitted_items"],
                   "admitted_pickles":
                       census_document["totals"]["admitted_pickles"]},
        "preparation": {
            "manifest_sha256": approval.preparation_manifest_sha256,
            "mode": "unstripped",
            "workspace": prepared.document["workspace"],
            "strip_manifest_sha256":
                prepared.document["strip_manifest_sha256"],
        },
        "network": "bridge", "commands": command_records,
        "result": {"m2_manifest_sha256": manifest_identity["sha256"],
                   "m2_tree_sha256": tree_sha,
                   "files": manifest["totals"]["files"],
                   "bytes": manifest["totals"]["bytes"],
                   "purged_transient": purged},
        "artifacts": _artifacts(output, log_names),
    }
    return _transcript(output, document)


def run_canonical_phase(project: str, *, items_path: str,
                        discovery_transcript: str, out: str,
                        runner: Runner, approval_path: str | None = None,
                        approved_digest: str | None = None) -> dict:
    return _execute_canonical(
        project, items_path=items_path,
        discovery_transcript=discovery_transcript, out=out, runner=runner,
        approval=require_source_approval(
            project, "canonical", approval_path=approval_path,
            approved_digest=approved_digest))


def _execute_canonical(project: str, *, items_path: str,
                       discovery_transcript: str, out: str,
                       runner: Runner, approval: Approval) -> dict:
    cfg = _config(project)
    _validate_approval(approval, project, "canonical")
    admission = precontact_admission(project, items_path)
    transcript_path = _absolute(discovery_transcript, "discovery transcript")
    predecessor = _read_document(
        transcript_path,
        expected_sha256=approval.predecessor_transcript_sha256 or "",
        phase="discovery", project=project)
    expected_authority = {
        "reference": approval.authority_reference,
        "daemon_fingerprint": approval.daemon_fingerprint,
    }
    expected_base = {"repository_digest": approval.base_digest,
                     "config_id": approval.base_config_id}
    if predecessor.get("base") != expected_base \
            or predecessor.get("authority") != expected_authority:
        raise _refuse(
            "discovery base/config/authority differs from canonical approval")
    result = predecessor.get("result") or {}
    if result.get("m2_manifest_sha256") != approval.m2_manifest_sha256 \
            or result.get("m2_tree_sha256") != approval.m2_tree_sha256:
        raise _refuse("discovery payload differs from canonical approval")
    if not isinstance(predecessor.get("source"), dict) \
            or predecessor["source"].get("manifest_sha256") is None \
            or not isinstance(predecessor.get("preparation"), dict) \
            or not isinstance(predecessor.get("census"), dict) \
            or predecessor["census"].get("path") != "census.json" \
            or _SHA256.fullmatch(predecessor["census"].get("sha256", "")) \
            is None:
        raise _refuse(
            "discovery transcript lacks source/preparation/census identity")
    discovery_root = os.path.dirname(transcript_path)
    source_m2 = os.path.join(discovery_root, "m2")
    current_manifest, current_tree = _manifest(_tree_files(source_m2))
    current_raw = _canonical_json(current_manifest)
    if hashlib.sha256(current_raw).hexdigest() != approval.m2_manifest_sha256 \
            or current_tree != approval.m2_tree_sha256:
        raise _refuse("retained discovery payload changed after review")

    # Revalidate the current daemon before creating the build context, and
    # require it to be the same authority the predecessor recorded.  The
    # reviewed approval is the bridge: a transcript cannot silently move a
    # Maven payload from one base/daemon chain onto another canonical build.
    authority = _authority(runner, approval)
    if authority != predecessor["authority"]:
        raise _refuse("canonical current authority differs from discovery")

    output = _create_output(out)
    context = os.path.join(output, "context")
    os.mkdir(context, 0o700)
    approved_m2 = os.path.join(context, "approved-m2")
    _copy_regular_tree(source_m2, approved_m2)
    dockerfile = canonical_dockerfile(cfg, approval.base_digest or "")
    dockerfile_path = os.path.join(context, "Dockerfile")
    settings_path = os.path.join(context, "offline-settings.xml")
    _write(dockerfile_path, dockerfile)
    _write(settings_path, OFFLINE_SETTINGS)
    if sorted(os.listdir(context)) != [
            "Dockerfile", "approved-m2", "offline-settings.xml"]:
        raise _refuse("canonical context contains a source/non-payload path")
    copied_manifest, copied_tree = _manifest(_tree_files(approved_m2))
    if copied_manifest != current_manifest or copied_tree != current_tree:
        raise _refuse("canonical context payload differs from approval")

    iidfile = os.path.join(output, "canonical.iid")
    argv = ("build", "--pull=false", "--network", "none",
            "--iidfile", iidfile, "--file", dockerfile_path, context)
    build = _checked(runner, argv, timeout=7200, build=True)
    _write(os.path.join(output, "build.stdout"), build.stdout)
    _write(os.path.join(output, "build.stderr"), build.stderr)
    try:
        image_id = Path(iidfile).read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise _refuse("canonical build wrote no readable iidfile") from exc
    if _IMAGE_ID.fullmatch(image_id) is None:
        raise _refuse("canonical iidfile is not one immutable config ID")

    inspect_result = _checked(
        runner, ("image", "inspect", image_id), timeout=120)
    inspected = _inspect(inspect_result.stdout, image_id)
    config = inspected.get("Config")
    if not isinstance(config, dict) or config.get("WorkingDir") != "/work" \
            or config.get("Entrypoint") not in (None, []) \
            or config.get("Cmd") != ["tail", "-f", "/dev/null"]:
        raise _refuse("canonical config does not clear entrypoint/set /work")
    env = set(config.get("Env") or [])
    if not {"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"} <= env:
        raise _refuse("canonical UTF-8/UTC environment differs")
    _write(os.path.join(output, "inspect.json"), inspect_result.stdout)

    probe_argv = (
        "run", "--rm", "--network", "none", "--pull=never",
        "--entrypoint", "/bin/sh", image_id, "-c",
        "set -eu; test -z \"$(find /work -mindepth 1 -print -quit)\"; "
        "test ! -e /pom.xml; test ! -e /src; test ! -e /.git; "
        "grep -q '<offline>true</offline>' /root/.m2/settings.xml; "
        "java -version; mvn --version; printf 'R2T-QUALIFIED\\n'")
    probe = _checked(runner, probe_argv, timeout=300)
    banner = probe.stdout + probe.stderr
    if b"R2T-QUALIFIED\n" not in probe.stdout \
            or b"Apache Maven 3.9.6" not in banner \
            or not _java_banner_matches(banner, cfg.jdk_major):
        raise _refuse("canonical source-free/JDK/Maven qualification failed")
    _write(os.path.join(output, "qualification.stdout"), probe.stdout)
    _write(os.path.join(output, "qualification.stderr"), probe.stderr)
    captured_manifest, captured_tree = _manifest(dict(
        runner.capture_files(image_id, "/opt/m2", timeout=7200)))
    if captured_manifest != current_manifest or captured_tree != current_tree:
        raise _refuse("canonical image /opt/m2 differs from approved payload")
    if any(token in argv for token in ("-t", "--tag")):
        raise _refuse("canonical build attempted a forbidden image tag")

    names = ["build.stderr", "build.stdout", "inspect.json",
             "qualification.stderr", "qualification.stdout"]
    document = {
        "schema": IMAGE_SCHEMA, "path": PATH, "project": project,
        "phase": "canonical", "status": "complete",
        "execution_identity": approval.execution_identity,
        "authority": authority, "admission": admission,
        "predecessor_transcript_sha256":
            approval.predecessor_transcript_sha256,
        "base": predecessor["base"],
        "source": predecessor["source"],
        "discovery_preparation": predecessor["preparation"],
        "discovery_census": predecessor["census"],
        "definition": {"bytes": len(dockerfile),
                       "sha256": hashlib.sha256(dockerfile).hexdigest()},
        "build_argv": list(argv), "network": "none", "tag": None,
        "result": {"candidate_image_id": image_id,
                   "base_config_id": approval.base_config_id,
                   "m2_manifest_sha256": approval.m2_manifest_sha256,
                   "m2_tree_sha256": approval.m2_tree_sha256,
                   "source_free": True, "jdk_major": cfg.jdk_major,
                   "maven_version": "3.9.6"},
        "artifacts": _artifacts(output, names),
    }
    return _transcript(output, document)


@dataclass(frozen=True)
class RealityRun:
    name: str
    target: str
    workspace_kind: str
    maven_argv: tuple[str, ...]
    dry_run: bool
    stripped: bool


#: Maven's exit code for a STRIPPED dry-run leg, per pinned cucumber version.
#: What such a leg REPORTS is a cucumber-version fact and the two pinned
#: versions disagree, so the exit code they produce disagrees with them.
#:
#: 7.8.0: `DRY_RUN.execute` invokes the match, the removed glue comes back
#: `undefined`, surefire records those as test failures and Maven exits 1
#: (measured on EPUBCheck: 1136 undefined steps, exit 1).
#:
#: 6.6.0: `DRY_RUN.execute` returns SKIPPED without consulting the match, so
#: the stripped tree reports every step `skipped`, surefire sees no failure
#: and Maven exits 0 (measured on Algorand with this phase's own image and
#: argv: BUILD SUCCESS, Tests run 461, Failures 0, Errors 0, Skipped 461,
#: 1779 steps all skipped and all locationless).
#:
#: Exactly ONE code is accepted on either contract: this DISPATCHES the
#: expectation, it does not widen it.  What the dispatch costs is the strip
#: witness the exit code used to carry, and that witness has already moved:
#: under 6.6.0 the exit code separates nothing, so `_artifact_facts` reads
#: the BINDINGS instead -- `parse_dry_run` is given expect_state=LOCATIONLESS
#: for a stripped leg and LOCATED for an unstripped one, and a stripped leg
#: that projects any binding into removable glue is refused.  That is a
#: stronger witness than an exit code, because it reads the glue itself.
STRIPPED_DRY_RUN_EXIT: dict[str, int] = {"7.8.0": 1, "6.6.0": 0, "6.11.0": 1}


def _dry_run_contract(project: str) -> str:
    """`project`'s pinned cucumber dry-run contract, as a phase refusal.

    The version authority is `closure_java.dry_run_contract`, i.e.
    `j0.PARSER_STACKS[project]["cucumber_version"]` -- the same closed
    per-project record the dry-run DOCUMENT contract already dispatches on,
    never a second copy of the version kept here.  An unpinned project
    refuses there; this only restates that refusal in this module's class.
    """
    from .closure_java import ClosureJavaError, dry_run_contract

    try:
        return dry_run_contract(project)
    except ClosureJavaError as exc:
        raise _refuse(str(exc)) from exc


def stripped_dry_run_exit(project: str) -> int:
    """The ONLY Maven exit code `project`'s stripped dry-run legs may have."""
    contract = _dry_run_contract(project)
    if contract not in STRIPPED_DRY_RUN_EXIT:
        raise _refuse(
            f"{project!r}: cucumber {contract} has no reviewed stripped "
            f"dry-run exit contract")
    return STRIPPED_DRY_RUN_EXIT[contract]


def reality_runs(project: str, *, tag_expression: str | None = None) \
        -> tuple[RealityRun, ...]:
    if project == "kapua":
        # Shared native plans, consumed by Kapua's own capture binding.
        # This does not admit Kapua to the legacy image/preparation chain.
        from .kapua import SUITES
        from ..stacks.cucumber import suite_capture_argv

        if tag_expression is not None:
            raise _refuse("Kapua reality uses its fixed native tag selection")
        runs = []
        for suite in SUITES:
            target = suite.runner_package + "." + suite.upstream_runner_class
            ordinary = tuple(suite_capture_argv(
                project, source_feature=suite.features[0]))
            dry = tuple(suite_capture_argv(
                project, source_feature=suite.features[0], dry_run=True))
            runs.extend((
                RealityRun(target + "-ordinary", target, "pinned", ordinary,
                           False, False),
                RealityRun(target + "-unstripped-dry-run", target, "pinned", dry,
                           True, False),
                RealityRun(target + "-stripped-dry-run", target, "stripped", dry,
                           True, True),
            ))
        return tuple(runs)
    _config(project)
    if project == "epubcheck":
        ordinary, dry, _compile, _jacoco = _epub_commands(MAVEN_OFFLINE_PREFIX)
        return (
            RealityRun("full-suite", EPUB_RUNNER, "suite", ordinary,
                       False, False),
            RealityRun("unstripped-dry-run", EPUB_RUNNER, "unstripped", dry,
                       True, False),
            RealityRun("stripped-dry-run", EPUB_RUNNER, "stripped", dry,
                       True, True),
        )
    if not isinstance(tag_expression, str) or not tag_expression:
        raise _refuse("Algorand reality requires the pinned tag expression")
    commands = _algorand_commands(
        MAVEN_OFFLINE_PREFIX, tag_expression, dry_only=True)
    _validate_algorand_commands(commands)
    unit, unit_dry, offline, offline_dry = commands
    return (
        RealityRun("unit-ordinary", ALGORAND_UNIT_RUNNER, "unit-ordinary", unit,
                   False, False),
        RealityRun("unit-unstripped-dry-run", ALGORAND_UNIT_RUNNER,
                   "unit-unstripped", unit_dry, True, False),
        RealityRun("unit-stripped-dry-run", ALGORAND_UNIT_RUNNER,
                   "unit-stripped", unit_dry, True, True),
        RealityRun("offline-ordinary", ALGORAND_OFFLINE_RUNNER,
                   "offline-ordinary", offline, False, False),
        RealityRun("offline-unstripped-dry-run", ALGORAND_OFFLINE_RUNNER,
                   "offline-unstripped", offline_dry, True, False),
        RealityRun("offline-stripped-dry-run", ALGORAND_OFFLINE_RUNNER,
                   "offline-stripped", offline_dry, True, True),
    )


def run_reality(project: str, *, items_path: str, census_path: str | None,
                canonical_transcript: str,
                source_root: str, source_manifest: str,
                preparation_manifests: Mapping[str, str], out: str,
                runner: Runner, approval_path: str | None = None,
                approved_digest: str | None = None) -> dict:
    return _execute_reality(
        project, items_path=items_path, census_path=census_path,
        canonical_transcript=canonical_transcript, source_root=source_root,
        source_manifest=source_manifest,
        preparation_manifests=preparation_manifests,
        out=out, runner=runner,
        approval=require_source_approval(
            project, "reality", approval_path=approval_path,
            approved_digest=approved_digest))


def _artifact_rows(raw: bytes, label: str) -> list[dict]:
    rows = []
    try:
        for line in raw.splitlines():
            if line:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("folded row is not an object")
                rows.append(value)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise _refuse(f"{label} folded Cucumber records are malformed") from exc
    return rows


def _runner_name_matches(value: str, target: str) -> bool:
    simple = target.rsplit(".", 1)[-1]
    return value in {target, simple} or value.endswith("." + simple)


def _surefire_facts(artifacts: Mapping[str, bytes], target: str,
                    minimum_tests: int, run_name: str, *,
                    expected_test_failure: bool = False) -> dict:
    reports = [(rel, raw) for rel, raw in artifacts.items()
               if rel.startswith("surefire/") and rel.endswith(".xml")]
    if not reports:
        raise _refuse(f"{run_name} retained no Surefire XML")
    target_seen = False
    target_simple = target.rsplit(".", 1)[-1]
    classes: set[str] = set()
    tests = failures = errors = 0
    for rel, raw in reports:
        target_seen |= target_simple in os.path.basename(rel)
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise _refuse(f"{run_name} Surefire XML is malformed: {rel}") from exc
        suites = ([root] if root.tag.rsplit("}", 1)[-1] == "testsuite"
                  else [node for node in root.iter()
                        if node.tag.rsplit("}", 1)[-1] == "testsuite"])
        if not suites:
            raise _refuse(f"{run_name} Surefire XML contains no testsuite")
        for suite in suites:
            name = suite.get("name") or ""
            target_seen |= _runner_name_matches(name, target)
            cases = [node for node in suite
                     if node.tag.rsplit("}", 1)[-1] == "testcase"]
            try:
                tests += int(suite.get("tests", str(len(cases))))
                failures += int(suite.get("failures", "0"))
                errors += int(suite.get("errors", "0"))
            except ValueError as exc:
                raise _refuse(f"{run_name} Surefire counts are malformed") from exc
            for case in cases:
                classname = case.get("classname") or ""
                name = case.get("name") or ""
                if classname:
                    classes.add(classname)
                target_seen |= _runner_name_matches(classname, target) \
                    or _runner_name_matches(name, target)
    observed_failures = failures + errors
    if not target_seen or tests < minimum_tests \
            or expected_test_failure and observed_failures <= 0 \
            or not expected_test_failure and observed_failures:
        raise _refuse(
            f"{run_name} Surefire does not prove the exact runner outcome")
    return {"reports": len(reports), "tests": tests,
            "failures": failures, "errors": errors,
            "test_classes": sorted(classes), "target": target}


def _artifact_facts(result: CommandResult, run: RealityRun,
                    expected_pickle_ids: list[str], boundary: Any,
                    type_index: dict, project: str) -> dict:
    """Derive every reality claim from retained Cucumber/Surefire bytes."""
    from .closure_java import (ClosureJavaError, LOCATED, LOCATIONLESS,
                               UNDEFINED, dry_run_problems, parse_dry_run,
                               unstripped_bindings)
    from ..stacks.cucumber import (CucumberStackRefused,
                                   records_from_json)

    contract = _dry_run_contract(project)
    feature_root = "src/test/resources"
    if project == "kapua":
        from .kapua import SUITES
        selected = [suite for suite in SUITES
                    if suite.runner_package + "." + suite.upstream_runner_class == run.target]
        if len(selected) != 1:
            raise _refuse(f"{run.name} has no admitted Kapua native runner")
        feature_root = selected[0].module + "/src/test/resources"
    invoking_dry_run = contract in {"7.8.0", "6.11.0"}
    artifacts = result.artifacts
    if not isinstance(artifacts, Mapping) or set(artifacts) < {
            "cucumber.json", "cucumber.records.jsonl"}:
        raise _refuse(f"{run.name} lacks raw and folded Cucumber evidence")
    for rel, raw in artifacts.items():
        if not isinstance(rel, str) or not rel \
                or _SAFE_ARTIFACT.fullmatch(rel) is None \
                or rel.startswith("/") or ".." in Path(rel).parts \
                or not isinstance(raw, bytes):
            raise _refuse(f"{run.name} returned an unsafe artifact")
    try:
        document = json.loads(artifacts["cucumber.json"])
        # `RealityRun` declares both halves of the leg, so this site asserts
        # the EXPECTED state rather than mere uniformity.
        dry = parse_dry_run(
            document, feature_root, project=project,
            dry_run=run.dry_run,
            expect_state=(LOCATIONLESS if run.stripped else LOCATED)
            if run.dry_run else None)
        folded, voids = records_from_json(document)
    except (json.JSONDecodeError, UnicodeDecodeError, ClosureJavaError,
            CucumberStackRefused, KeyError, TypeError, ValueError) as exc:
        raise _refuse(f"{run.name} Cucumber evidence cannot be parsed: {exc}") \
            from exc
    retained_fold = _artifact_rows(
        artifacts["cucumber.records.jsonl"], run.name)
    if not dry.cases or voids or retained_fold != folded \
            or len(folded) != len(dry.cases):
        raise _refuse(f"{run.name} raw/folded Cucumber evidence disagrees")
    pickle_ids = sorted(f"{uri}:{line}" for uri, line in dry.cases)
    if pickle_ids != expected_pickle_ids:
        raise _refuse(f"{run.name} Cucumber pickles differ from census")

    uris = dry.uris()
    offline_uri = ("src/test/resources/com/algorand/algosdk/"
                   "integration/offline.feature")
    if project == "algorand-sdk":
        if run.target == ALGORAND_UNIT_RUNNER \
                and any("/integration/" in uri for uri in uris):
            raise _refuse(f"{run.name} selected a foreign integration feature")
        if run.target == ALGORAND_OFFLINE_RUNNER and uris != [offline_uri]:
            raise _refuse(f"{run.name} did not select only relocated offline.feature")

    # Whether a stripped dry run FAILS TESTS is the same cucumber-version
    # fact as its exit code (`STRIPPED_DRY_RUN_EXIT`): under 7.8.0 the
    # removed glue comes back `undefined` and surefire records failures,
    # Kapua 6.11.0 has the same invoking/failure contract as 7.8.0;
    # under 6.6.0 the whole tree is `skipped` and surefire records none
    # (measured: tests 461, failures 0, errors 0, skipped 461).  Passing
    # `expected_test_failure=False` on the 6.6.0 leg is not a weaker check --
    # `_surefire_facts` then REFUSES any failure or error, which is exactly
    # what that leg's contract says it must have.
    surefire = _surefire_facts(
        artifacts, run.target, len(pickle_ids), run.name,
        expected_test_failure=run.stripped and invoking_dry_run)
    ordinary = (not run.dry_run and bool(folded))
    if ordinary and project == "epubcheck":
        ordinary = any(not _runner_name_matches(name, run.target)
                       for name in surefire["test_classes"])
    if not run.dry_run and not ordinary:
        raise _refuse(f"{run.name} ordinary tests are not represented")

    bindings = (unstripped_bindings(dry, boundary, type_index)
                if run.dry_run else [])
    undefined_steps = sum(
        step.status == UNDEFINED for case in dry.cases.values()
        for _origin, step in case.all_steps)
    if run.dry_run and run.stripped and bindings:
        raise _refuse(f"{run.name} retained removable glue bindings")
    # How the strip SHOWS UP in the steps is the third face of the same
    # version fact.  7.8.0 names the removed glue `undefined`, so a stripped
    # leg reporting none of it did not strip anything; 6.11.0 has the
    # same measured contract.  6.6.0 never emits
    # `undefined` in dry-run mode at all (`parse_dry_run` refuses any step
    # there that is not `skipped`), so the only admissible count is 0 and a
    # non-zero one is a document from another execution model; the strip
    # witness on that contract is the LOCATIONLESS state asserted above plus
    # the empty binding set refused just above.  `dry_run_problems` is
    # version-neutral -- a non-passed before-hook or an out-of-vocabulary
    # status is a defect on both contracts -- so it stays outside the
    # dispatch.
    expected_undefined = (undefined_steps > 0 if invoking_dry_run
                          else undefined_steps == 0)
    if run.dry_run and run.stripped \
            and (not expected_undefined or dry_run_problems(dry)):
        raise _refuse(
            f"{run.name} does not prove the expected stripped dry-run state")
    if run.dry_run and not run.stripped and not bindings:
        raise _refuse(f"{run.name} projects no binding to removable glue")
    return {
        "pickle_ids": pickle_ids,
        "bindings": bindings,
        "features": uris,
        "folded_records": len(folded),
        "surefire": surefire,
        "undefined_steps": undefined_steps,
        "ordinary_tests_represented": ordinary,
    }


def _execute_reality(project: str, *, items_path: str,
                     census_path: str | None, canonical_transcript: str,
                     source_root: str, source_manifest: str,
                     preparation_manifests: Mapping[str, str], out: str,
                     runner: Runner, approval: Approval) -> dict:
    _validate_approval(approval, project, "reality")
    if census_path is None:
        raise _refuse("reality requires the reviewed discovery census")
    admission = precontact_admission(project, items_path)
    predecessor = _read_document(
        _absolute(canonical_transcript, "canonical transcript"),
        expected_sha256=approval.predecessor_transcript_sha256 or "",
        phase="canonical", project=project)
    image_id = predecessor.get("result", {}).get("candidate_image_id")
    expected_authority = {
        "reference": approval.authority_reference,
        "daemon_fingerprint": approval.daemon_fingerprint,
    }
    expected_base = {"repository_digest": approval.base_digest,
                     "config_id": approval.base_config_id}
    if predecessor.get("authority") != expected_authority \
            or predecessor.get("base") != expected_base \
            or image_id != approval.image_id \
            or predecessor.get("result", {}).get("m2_manifest_sha256") \
            != approval.m2_manifest_sha256 \
            or predecessor.get("result", {}).get("m2_tree_sha256") \
            != approval.m2_tree_sha256:
        raise _refuse("canonical transcript differs from reality approval")
    snapshot = _authenticate_source(
        project, source_root, source_manifest,
        approval.source_manifest_sha256 or "")
    if predecessor.get("source") != dict(snapshot.identity):
        raise _refuse("reality source differs from canonical source identity")
    admission = validate_research_census(
        project, census_path, expected_sha256=approval.census_sha256 or "",
        snapshot=snapshot, admission=admission)
    census = admission["tag_census"]
    canonical_census = predecessor.get("discovery_census")
    if not isinstance(canonical_census, dict) \
            or canonical_census.get("sha256") != approval.census_sha256:
        raise _refuse("canonical transcript names another discovery census")
    plans = reality_runs(project, tag_expression=census["tag_expression"])
    expected_workspaces = {plan.workspace_kind for plan in plans}
    if set(preparation_manifests) != expected_workspaces:
        raise _refuse("reality preparations differ from the exact run plan")
    reviewed = approval.preparation_manifests_sha256 or {}
    prepared = {
        plan.workspace_kind: _validate_preparation(
            project, snapshot, preparation_manifests[plan.workspace_kind],
            reviewed[plan.workspace_kind], stripped=plan.stripped)
        for plan in plans
    }
    physical = [(os.path.realpath(value.workspace),
                 os.stat(value.workspace, follow_symlinks=False).st_dev,
                 os.stat(value.workspace, follow_symlinks=False).st_ino)
                for value in prepared.values()]
    if len({path for path, _dev, _ino in physical}) != len(plans) \
            or len({(dev, ino) for _path, dev, ino in physical}) != len(plans):
        raise _refuse("every reality Maven process needs a fresh workspace")

    from .closure_java import build_type_index
    stripped_exit = stripped_dry_run_exit(project)
    index_workspace = prepared[
        "unstripped" if project == "epubcheck" else "unit-unstripped"]
    type_index = build_type_index(
        index_workspace.workspace, ("src/main/java", "src/test/java"))
    output = _create_output(out)
    authority = _authority(runner, approval)

    before_manifest, before_tree = _manifest(dict(
        runner.capture_files(image_id, "/opt/m2", timeout=7200)))
    if hashlib.sha256(_canonical_json(before_manifest)).hexdigest() \
            != approval.m2_manifest_sha256 or before_tree != approval.m2_tree_sha256:
        raise _refuse("reality image starts with another /opt/m2")

    observations: dict[str, dict] = {}
    artifact_names: list[str] = []
    records = []
    for plan in plans:
        selected = prepared[plan.workspace_kind]
        workspace = selected.workspace
        argv = (
            "run", "--rm", "--network", "none", "--pull=never",
            "--mount", f"type=bind,source={workspace},target=/work",
            "--workdir", "/work", image_id, *plan.maven_argv)
        result = _checked(
            runner, argv, timeout=7200,
            # A stripped dry run's exit code is a cucumber-version fact, so
            # it is dispatched on the pinned version rather than fixed:
            # 7.8.0 reports the removed glue `undefined`, surefire records
            # test failures and Maven exits 1; 6.6.0 reports the same tree
            # wholly `skipped`, surefire records no failure and Maven exits
            # 0.  Exactly ONE code is accepted either way -- see
            # `STRIPPED_DRY_RUN_EXIT`, which also states why the strip
            # witness now lives in the bindings.  Every leg's retained
            # JSON/XML is semantically checked below before admission.
            accepted_returncodes=((stripped_exit,) if plan.stripped
                                  else (0,)))
        all_pickles = admission["admitted_pickle_ids"]
        if project == "algorand-sdk":
            marker = ("src/test/resources/com/algorand/algosdk/"
                      "integration/offline.feature:")
            expected_pickles = sorted(
                item for item in all_pickles
                if item.startswith(marker)
                == (plan.target == ALGORAND_OFFLINE_RUNNER))
        else:
            expected_pickles = list(all_pickles)
        facts = _artifact_facts(
            result, plan, expected_pickles, selected.boundary,
            type_index, project)
        observations[plan.name] = facts
        prefix = f"runs/{plan.name}"
        for suffix, raw in (("stdout", result.stdout),
                            ("stderr", result.stderr)):
            rel = f"{prefix}/{suffix}"
            _write(os.path.join(output, rel), raw)
            artifact_names.append(rel)
        for rel, raw in sorted(result.artifacts.items()):
            name = f"{prefix}/artifacts/{rel}"
            _write(os.path.join(output, name), raw)
            artifact_names.append(name)
        from ..bench import repo
        substrate = repo.verify_substrate(
            selected.strip_manifest, selected.boundary)
        if substrate["changed"] or substrate["missing"] or substrate["added"]:
            raise _refuse(f"{plan.name} changed source outside strip boundary")
        records.append({"name": plan.name, "target": plan.target,
                        "dry_run": plan.dry_run, "stripped": plan.stripped,
                        "exit_code": result.returncode,
                        "docker_argv": list(argv),
                        "maven_argv": list(plan.maven_argv),
                        "pickle_ids": facts["pickle_ids"],
                        "features": facts["features"],
                        "bindings": facts["bindings"],
                        "undefined_steps": facts["undefined_steps"],
                        "folded_records": facts["folded_records"],
                        "surefire": facts["surefire"],
                        "preparation_manifest_sha256":
                            reviewed[plan.workspace_kind],
                        "strip_manifest_sha256":
                            selected.document["strip_manifest_sha256"]})

    if project == "epubcheck":
        if observations["unstripped-dry-run"]["pickle_ids"] \
                != observations["stripped-dry-run"]["pickle_ids"]:
            raise _refuse("EPUBCheck dry-run pickle sets differ after strip")
    else:
        for target in ("unit", "offline"):
            ordinary = observations[f"{target}-ordinary"]["pickle_ids"]
            unstripped = observations[
                f"{target}-unstripped-dry-run"]["pickle_ids"]
            stripped = observations[f"{target}-stripped-dry-run"]["pickle_ids"]
            if ordinary != unstripped or unstripped != stripped:
                raise _refuse(f"Algorand {target} pickle set changed across capture")
        combined = set(observations["unit-ordinary"]["pickle_ids"]) \
            | set(observations["offline-ordinary"]["pickle_ids"])
        if combined != set(admission["admitted_pickle_ids"]):
            raise _refuse("Algorand reality differs from admitted census")

    after_manifest, after_tree = _manifest(dict(
        runner.capture_files(image_id, "/opt/m2", timeout=7200)))
    if after_manifest != before_manifest or after_tree != before_tree:
        raise _refuse("reality changed canonical /opt/m2 bytes")

    file_manifest = {
        "schema": "r2t.java-research-minimal-reality-manifest/1",
        "files": _artifacts(output, artifact_names),
    }
    manifest_raw = _canonical_json(file_manifest)
    manifest_identity = _write(
        os.path.join(output, "manifest.json"), manifest_raw)
    document = {
        "schema": REALITY_SCHEMA, "path": PATH, "project": project,
        "status": "complete", "execution_identity": approval.execution_identity,
        "authority": authority, "admission": admission,
        "base": predecessor["base"],
        "source": dict(snapshot.identity),
        "census": {"path": _absolute(census_path, "research-minimal census"),
                   "sha256": approval.census_sha256},
        "canonical_transcript_sha256":
            approval.predecessor_transcript_sha256,
        "image_id": image_id, "network": "none", "pull": "never",
        "runs": records,
        "manifest": {"path": "manifest.json", **manifest_identity},
        "result": {"runs": len(records), "offline_repository_unchanged": True,
                   "substrate_unchanged": True,
                   "pickle_sets_stable": True,
                   "stripped_bindings_empty": True},
    }
    return _transcript(output, document)


def _cli_live_runner(args: argparse.Namespace, phase: str) \
        -> LiveResearchRunner:
    approval = require_source_approval(
        args.project, phase, approval_path=args.approval,
        approved_digest=args.approved_digest)
    expected = (approval.authority_reference or {}).get("path")
    authority_path = _absolute(args.docker_authority, "Docker authority")
    if expected != authority_path:
        raise _refuse("CLI Docker authority differs from phase approval")
    from ..core import docker_cli
    docker_cli.configure(authority_path=authority_path)
    return LiveResearchRunner(
        approval.authority_reference or {}, scratch_root=args.out)


def write_epub_source_manifest(*, source_root: str, out: str) -> dict:
    """Write the pure pinned-checkout manifest without running a J0 plan."""
    from .j0 import J0Error, build_source_archive_manifest
    target = _absolute(out, "EPUB source manifest output")
    if os.path.lexists(target):
        raise _refuse("EPUB source manifest output must be absent")
    try:
        document = build_source_archive_manifest(
            "epubcheck", _absolute(source_root, "EPUB source checkout"))
    except (J0Error, OSError) as exc:
        raise _refuse(f"EPUB source manifest cannot be built: {exc}") from exc
    _write(target, _canonical_json(document))
    return document


def write_approval_draft(*, fields_path: str, out: str) -> dict:
    """Digest exact operator-supplied fields; infer no phase identity."""
    source = _absolute(fields_path, "approval draft fields")
    target = _absolute(out, "approval draft output")
    if os.path.lexists(target):
        raise _refuse("approval draft output must be absent")
    try:
        info = os.lstat(source)
        value = json.loads(Path(source).read_bytes())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("approval draft fields are not readable JSON") from exc
    expected = {item.name for item in fields(Approval)}
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) \
            or not isinstance(value, dict) or set(value) != expected:
        raise _refuse("approval draft fields are not one exact regular object")
    try:
        approval = Approval(**value)
    except TypeError as exc:
        raise _refuse("approval draft fields are malformed") from exc
    _config(approval.project)
    if approval.phase not in _PHASE_APPROVAL_FIELDS:
        raise _refuse("approval draft phase is unknown")
    _validate_approval(approval, approval.project, approval.phase)
    document = phase_approval_document(approval)
    _write(target, _canonical_json(document))
    return document


def _preparation_arguments(values: Sequence[str]) -> dict[str, str]:
    out = {}
    for value in values:
        if not isinstance(value, str) or value.count("=") != 1:
            raise _refuse("--preparation must be KIND=/absolute/path")
        kind, path = value.split("=", 1)
        if not kind or kind in out:
            raise _refuse("--preparation repeats/omits its workspace kind")
        out[kind] = _absolute(path, "workspace preparation manifest")
    return out


def _phase_parser(subparsers: Any, name: str) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(name)
    parser.add_argument("--project", required=True, choices=sorted(PROJECTS))
    parser.add_argument("--items", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--approved-digest", required=True)
    parser.add_argument("--docker-authority", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Execute one approved phase through the concrete authority-bound runner."""
    parser = argparse.ArgumentParser(prog="python -m benchmark.r2t.java.research_minimal")
    subparsers = parser.add_subparsers(dest="command", required=True)
    source_manifest = subparsers.add_parser("source-manifest")
    source_manifest.add_argument("--source-root", required=True)
    source_manifest.add_argument("--out", required=True)
    approval_draft = subparsers.add_parser("approval-draft")
    approval_draft.add_argument("--fields", required=True)
    approval_draft.add_argument("--out", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--project", required=True, choices=sorted(PROJECTS))
    prepare.add_argument("--source-root", required=True)
    prepare.add_argument("--source-manifest", required=True)
    prepare.add_argument("--out", required=True)
    prepare.add_argument("--mode", required=True,
                         choices=("stripped", "unstripped"))

    base = _phase_parser(subparsers, "base")
    discovery = _phase_parser(subparsers, "discovery")
    discovery.add_argument("--base-transcript", required=True)
    discovery.add_argument("--source-root", required=True)
    discovery.add_argument("--source-manifest", required=True)
    discovery.add_argument("--preparation-manifest", required=True)
    canonical = _phase_parser(subparsers, "canonical")
    canonical.add_argument("--discovery-transcript", required=True)
    reality = _phase_parser(subparsers, "reality")
    reality.add_argument("--census", required=True)
    reality.add_argument("--canonical-transcript", required=True)
    reality.add_argument("--source-root", required=True)
    reality.add_argument("--source-manifest", required=True)
    reality.add_argument("--preparation", action="append", default=[],
                         metavar="KIND=/ABSOLUTE/PREPARATION.JSON")
    args = parser.parse_args(argv)

    if args.command == "source-manifest":
        document = write_epub_source_manifest(
            source_root=args.source_root, out=args.out)
    elif args.command == "approval-draft":
        document = write_approval_draft(
            fields_path=args.fields, out=args.out)
    elif args.command == "prepare":
        document = prepare_runtime_workspace(
            args.project, source_root=args.source_root,
            source_manifest=args.source_manifest, out=args.out,
            stripped=(args.mode == "stripped"))
    elif args.command == "base":
        document = run_base_phase(
            args.project, items_path=args.items, out=args.out,
            runner=_cli_live_runner(args, "base"),
            approval_path=args.approval,
            approved_digest=args.approved_digest)
    elif args.command == "discovery":
        document = run_discovery_phase(
            args.project, items_path=args.items,
            base_transcript=args.base_transcript,
            source_root=args.source_root, source_manifest=args.source_manifest,
            preparation_manifest=args.preparation_manifest, out=args.out,
            runner=_cli_live_runner(args, "discovery"),
            approval_path=args.approval,
            approved_digest=args.approved_digest)
    elif args.command == "canonical":
        document = run_canonical_phase(
            args.project, items_path=args.items,
            discovery_transcript=args.discovery_transcript, out=args.out,
            runner=_cli_live_runner(args, "canonical"),
            approval_path=args.approval,
            approved_digest=args.approved_digest)
    else:
        document = run_reality(
            args.project, items_path=args.items, census_path=args.census,
            canonical_transcript=args.canonical_transcript,
            source_root=args.source_root, source_manifest=args.source_manifest,
            preparation_manifests=_preparation_arguments(args.preparation),
            out=args.out, runner=_cli_live_runner(args, "reality"),
            approval_path=args.approval,
            approved_digest=args.approved_digest)
    print(json.dumps(document, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
