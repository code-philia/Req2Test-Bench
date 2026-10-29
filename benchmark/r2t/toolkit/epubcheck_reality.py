"""Closed, offline capture path for the EPUBCheck reality spike.

The public entry point remains inert until two source constants below are
filled by a later exact review.  Its only live input is an already validated
canonical-image transcript; the image, Maven argv, corpus pin, network mode,
and artifact names are all derived from reviewed source.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import time
from typing import Callable, Mapping, Optional, Protocol, Sequence
import xml.etree.ElementTree as ET

from ..core import docker_cli
from . import epubcheck_image as _image
from ..core.paths import BENCHMARK_ROOT


class EPUBCheckRealityRefused(RuntimeError):
    """A closed gate, malformed input, or failed capture invariant."""


SCHEMA = "r2t.epubcheck-reality/v1"
PROJECT = "epubcheck"
FEATURE_ROOT = "src/test/resources"
MAX_ARTIFACT_BYTES = _image.MAX_RAW_LOG_BYTES
TRANSCRIPT_MAX_BYTES = 16 * 1024 * 1024
SUITE_TIMEOUT_SECONDS = 7200
DRY_RUN_TIMEOUT_SECONDS = 7200

# Source review opens implementation, never execution.  The exact canonical
# transcript does not exist yet, so neither of its later execution gates can
# honestly be filled in this source head.
REALITY_SPIKE_IMPLEMENTED = True
APPROVED_EPUBCHECK_REALITY_EXECUTION_IDENTITY: Optional[str] = None
APPROVED_EPUBCHECK_REALITY_CANONICAL_TRANSCRIPT_SHA256: Optional[str] = None

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SUREFIRE_NAME = re.compile(r"[A-Za-z0-9_.-]+\.xml\Z")


@dataclass(frozen=True)
class RealityGates:
    implemented: bool
    execution_identity: Optional[str]
    canonical_transcript_sha256: Optional[str]


@dataclass(frozen=True)
class CanonicalImage:
    transcript_path: str
    transcript_sha256: str
    image_id: str
    authority_reference: dict
    daemon_fingerprint: str


@dataclass(frozen=True)
class PreparedWorkspaces:
    root: str
    suite: str
    unstripped: str
    stripped: str
    baselines: Mapping[str, dict]
    boundary: object
    type_index: dict


class Runner(Protocol):
    def run(self, argv: Sequence[str], *, timeout: int) -> _image.CommandResult: ...


def _refuse(message: str) -> EPUBCheckRealityRefused:
    if message.startswith("REFUSED: "):
        message = message[len("REFUSED: "):]
    return EPUBCheckRealityRefused("REFUSED: " + message)


def _absolute(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value \
            or not os.path.isabs(value) or os.path.normpath(value) != value:
        raise _refuse(f"{label} must be one normalized absolute path")
    return value


def _printable_identity(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 512 and all(
        0x21 <= ord(character) <= 0x7e for character in value)


def source_gates() -> RealityGates:
    """Project the only production gate values; callers cannot fill them."""
    return RealityGates(
        REALITY_SPIKE_IMPLEMENTED,
        APPROVED_EPUBCHECK_REALITY_EXECUTION_IDENTITY,
        APPROVED_EPUBCHECK_REALITY_CANONICAL_TRANSCRIPT_SHA256)


def require_source_gates(
        gates: Optional[RealityGates] = None) -> RealityGates:
    selected = source_gates() if gates is None else gates
    findings = []
    if selected.implemented is not True:
        findings.append("implementation is not complete")
    if not _printable_identity(selected.execution_identity):
        findings.append("exact execution identity is absent/malformed")
    if not isinstance(selected.canonical_transcript_sha256, str) \
            or _SHA256.fullmatch(
                selected.canonical_transcript_sha256) is None:
        findings.append("approved canonical transcript SHA-256 is absent/malformed")
    if findings:
        raise _refuse("reality-spike source authority is closed.\n  - "
                      + "\n  - ".join(findings))
    return selected


def _exact_json(raw: bytes, label: str) -> object:
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _refuse(f"{label} is not exact UTF-8 JSON") from exc


def load_canonical_image(path: str, gates: RealityGates) -> CanonicalImage:
    """Authenticate one complete canonical transcript without Docker."""
    path = _absolute(path, "--image-transcript")
    try:
        stable = _image.stable_read(path, max_bytes=TRANSCRIPT_MAX_BYTES)
    except _image.EPUBCheckImageRefused as exc:
        raise _refuse(str(exc)) from exc
    if stable.sha256 != gates.canonical_transcript_sha256:
        raise _refuse("canonical transcript differs from the source-approved SHA-256")
    value = _exact_json(stable.data, "canonical transcript")
    try:
        document = _image.validate_transcript(value)
    except _image.EPUBCheckImageRefused as exc:
        raise _refuse(str(exc)) from exc
    if document["phase"] != "canonical" or document["status"] != "complete":
        raise _refuse("image transcript is not one complete canonical phase")
    image_id = document["result"].get("candidate_image_id")
    if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
        raise _refuse("canonical transcript has no immutable candidate image ID")
    reference = document["authority"].get("reference")
    fingerprint = document["authority"].get("daemon_fingerprint")
    if not isinstance(reference, dict) or not isinstance(fingerprint, str) \
            or _SHA256.fullmatch(fingerprint) is None:
        raise _refuse("canonical transcript authority projection is malformed")
    return CanonicalImage(path, stable.sha256, image_id,
                          dict(reference), fingerprint)


def _maven_argv(*, dry_run: bool) -> tuple[str, ...]:
    from ..stacks.cucumber import suite_capture_argv
    return suite_capture_argv(PROJECT, dry_run=dry_run)


def docker_run_argv(*, name: str, phase: str, workspace: str,
                    image_id: str, maven_argv: Sequence[str]) -> tuple[str, ...]:
    """One source-owned, offline container invocation."""
    if not re.fullmatch(r"r2t-epubcheck-reality-[0-9a-f]{16}-[a-z-]+", name):
        raise _refuse("reality container name is malformed")
    if phase not in {"full-suite", "unstripped-dry-run",
                     "stripped-dry-run"}:
        raise _refuse("reality run phase is malformed")
    workspace = _absolute(workspace, "reality workspace")
    if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
        raise _refuse("reality run image is not one immutable ID")
    return (
        "run", "--rm", "--name", name,
        "--label", "r2t.project=epubcheck",
        "--label", f"r2t.phase={phase}",
        "--network", "none", "--pull=never", "--cpus=4",
        "--mount", f"type=bind,source={workspace},target=/work",
        "--workdir", "/work", image_id, *tuple(maven_argv))


class _LiveRunner:
    """Small bridge from closed inner argv to the selected Docker authority."""

    def run(self, argv: Sequence[str], *, timeout: int) -> _image.CommandResult:
        inner = tuple(argv)
        environment = _image.clean_subprocess_environment()
        outer = docker_cli.docker_command(inner, environ=environment)
        result = _image._bounded_process(
            outer, timeout=timeout, environ=environment)
        return _image.CommandResult(
            inner, result.returncode, result.stdout, result.stderr,
            result.timed_out, result.overflowed)


class RealityOutput:
    """One absent owner-private directory with a small fixed artifact surface."""

    _FIXED = {
        "full-suite.stdout", "full-suite.stderr",
        "cucumber_suite_epubcheck.json",
        "cucumber_suite_epubcheck.records.jsonl",
        "cucumber_suite_epubcheck.timings.json",
        "unstripped-dry-run.stdout", "unstripped-dry-run.stderr",
        "cucumber_dry_run_epubcheck.json",
        "stripped-dry-run.stdout", "stripped-dry-run.stderr",
        "cucumber_dry_run_epubcheck_stripped.json",
    }

    def __init__(self, path: str):
        self.path = _absolute(path, "--out")
        self.artifacts: list[dict] = []

    def create(self) -> None:
        if os.path.lexists(self.path):
            raise _refuse("--out must be absent; resume/overwrite is unsupported")
        os.mkdir(self.path, 0o700)
        info = os.lstat(self.path)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) \
                or info.st_uid != os.getuid() \
                or stat.S_IMODE(info.st_mode) != 0o700:
            raise _refuse("--out is not one owner-private 0700 directory")

    def write(self, rel: str, raw: bytes) -> dict:
        if rel not in self._FIXED:
            if not rel.startswith("surefire/") \
                    or _SUREFIRE_NAME.fullmatch(rel[len("surefire/"):]) is None:
                raise _refuse(f"reality artifact name is not admitted: {rel}")
        if not isinstance(raw, bytes) or len(raw) > MAX_ARTIFACT_BYTES:
            raise _refuse(f"reality artifact exceeds the byte ceiling: {rel}")
        parent = self.path
        name = rel
        if rel.startswith("surefire/"):
            parent = os.path.join(self.path, "surefire")
            name = rel[len("surefire/"):]
            if not os.path.lexists(parent):
                os.mkdir(parent, 0o700)
        path = os.path.join(parent, name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        artifact = {"path": rel, "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest()}
        self.artifacts.append(artifact)
        return artifact

    def finalize(self, manifest: dict) -> dict:
        document = dict(manifest)
        document["artifacts"] = sorted(
            self.artifacts, key=lambda item: item["path"])
        raw = (json.dumps(document, sort_keys=True, separators=(",", ":"))
               + "\n").encode("utf-8")
        path = os.path.join(self.path, "manifest.json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_CLOEXEC", 0)
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(self.path,
                            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return document


def _artifact_json(path: str, label: str) -> tuple[bytes, object]:
    stable = _image.stable_read(path, max_bytes=MAX_ARTIFACT_BYTES)
    return stable.data, _exact_json(stable.data, label)


def _source_unchanged(workspace: str, expected: dict) -> None:
    try:
        observed = _image._workspace_source_inventory(workspace)
    except _image.EPUBCheckImageRefused as exc:
        raise _refuse(str(exc)) from exc
    if observed != expected:
        raise _refuse("Maven run changed the authenticated pom/src workspace")


def _inspect_candidate(canonical: CanonicalImage, runner: Runner,
                       revalidate: Callable[[], object]) -> None:
    revalidate()
    result = runner.run(("image", "inspect", canonical.image_id,
                         "--format", "{{json .}}"), timeout=30)
    if result.timed_out or result.overflowed or result.returncode != 0:
        raise _refuse("canonical candidate image is not inspectable by immutable ID")
    value = _exact_json(result.stdout, "canonical candidate inspect")
    if not isinstance(value, dict) or value.get("Id") != canonical.image_id:
        raise _refuse("canonical candidate inspect differs from transcript image ID")


def _cleanup_failed_run(name: str, runner: Runner,
                        revalidate: Callable[[], object]) -> None:
    """Remove only the named AutoRemove container if a client window failed."""
    revalidate()
    inspected = runner.run(("container", "inspect", name), timeout=30)
    if inspected.returncode == 1 and not inspected.timed_out \
            and not inspected.overflowed:
        return
    if inspected.returncode != 0 or inspected.timed_out or inspected.overflowed:
        raise _refuse("failed reality container presence could not be determined")
    revalidate()
    removed = runner.run(("container", "rm", "--force", name), timeout=60)
    if removed.returncode != 0 or removed.timed_out or removed.overflowed:
        raise _refuse("failed reality container could not be removed")


def _execute_run(*, phase: str, workspace: str, image_id: str,
                 maven_argv: Sequence[str], timeout: int, output: RealityOutput,
                 runner: Runner, revalidate: Callable[[], object],
                 attempt: str, monotonic: Callable[[], float]) -> dict:
    name = f"r2t-epubcheck-reality-{attempt}-{phase}"
    argv = docker_run_argv(name=name, phase=phase, workspace=workspace,
                           image_id=image_id, maven_argv=maven_argv)
    revalidate()
    started = monotonic()
    try:
        result = runner.run(argv, timeout=timeout)
    except Exception:
        _cleanup_failed_run(name, runner, revalidate)
        raise
    elapsed = monotonic() - started
    stdout_name = phase + ".stdout"
    stderr_name = phase + ".stderr"
    stdout = output.write(stdout_name, result.stdout)
    stderr = output.write(stderr_name, result.stderr)
    if result.argv != argv:
        raise _refuse("runner result argv differs from requested inner argv")
    if result.timed_out or result.overflowed or result.returncode != 0:
        _cleanup_failed_run(name, runner, revalidate)
        raise _refuse(f"{phase} Maven run did not complete successfully")
    return {
        "phase": phase, "argv": list(argv),
        "maven_argv": list(maven_argv),
        "timeout_seconds": timeout, "returncode": result.returncode,
        "timed_out": result.timed_out, "overflowed": result.overflowed,
        "wall_seconds": elapsed, "stdout": stdout, "stderr": stderr,
    }


def _suite_artifacts(workspace: str, output: RealityOutput) -> None:
    from ..stacks.cucumber import (CucumberStackRefused, records_from_json,
                                  scenario_timings_from_json)

    raw, document = _artifact_json(
        os.path.join(workspace, "target", "r2t-cucumber.json"),
        "full-suite cucumber document")
    if not isinstance(document, list):
        raise _refuse("full-suite cucumber document is not an array")
    try:
        records, voids = records_from_json(document)
        timings = scenario_timings_from_json(document)
    except (KeyError, TypeError, CucumberStackRefused) as exc:
        raise _refuse(f"full-suite cucumber fold failed: {exc}") from exc
    if not records or voids or len(timings) != len(records):
        raise _refuse("full-suite cucumber document has no usable pickle records")
    output.write("cucumber_suite_epubcheck.json", raw)
    records_raw = b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        .encode("utf-8") for record in records)
    output.write("cucumber_suite_epubcheck.records.jsonl", records_raw)
    timings_raw = (json.dumps(timings, sort_keys=True, separators=(",", ":"))
                   + "\n").encode("utf-8")
    output.write("cucumber_suite_epubcheck.timings.json", timings_raw)

    reports = os.path.join(workspace, "target", "surefire-reports")
    try:
        names = sorted(name for name in os.listdir(reports)
                       if _SUREFIRE_NAME.fullmatch(name))
    except OSError as exc:
        raise _refuse("full suite produced no readable Surefire report directory") from exc
    if not names:
        raise _refuse("full suite produced no Surefire XML")
    for name in names:
        report = _image.stable_read(
            os.path.join(reports, name), max_bytes=MAX_ARTIFACT_BYTES)
        try:
            ET.fromstring(report.data)
        except ET.ParseError as exc:
            raise _refuse(f"Surefire report is not XML: {name}") from exc
        output.write("surefire/" + name, report.data)


def _dry_run_artifact(workspace: str, output: RealityOutput,
                      output_name: str):
    from ..java.closure_java import (ClosureJavaError, dry_run_problems,
                                    parse_dry_run)
    raw, document = _artifact_json(
        os.path.join(workspace, "target", "r2t-cucumber-dry-run.json"),
        output_name)
    try:
        # EPUBCheck is the 7.8.0 contract, whose branch is unchanged and
        # reads neither `dry_run` nor `expect_state`; this pipeline captures
        # both stripped and unstripped trees through one helper, so no leg
        # state is asserted.
        dry_run = parse_dry_run(document, FEATURE_ROOT, project="epubcheck")
        problems = dry_run_problems(dry_run)
    except ClosureJavaError as exc:
        raise _refuse(f"{output_name} is not admitted dry-run JSON: {exc}") from exc
    if problems:
        raise _refuse(f"{output_name} has blocking dry-run findings: {problems[0]}")
    output.write(output_name, raw)
    return dry_run


def _closure_gate(unstripped, stripped, prepared: PreparedWorkspaces) -> None:
    from ..java.closure_java import unstripped_bindings
    if not unstripped.cases or set(unstripped.cases) != set(stripped.cases):
        raise _refuse("unstripped and stripped dry runs cover different pickles")
    before = unstripped_bindings(
        unstripped, prepared.boundary, prepared.type_index)
    after = unstripped_bindings(
        stripped, prepared.boundary, prepared.type_index)
    if not before:
        raise _refuse("unstripped dry run names no removable binding")
    if after:
        raise _refuse("stripped dry run still names removable glue")


def _capture_with_runner(*, canonical: CanonicalImage,
                         prepared: PreparedWorkspaces, out: str,
                         gates: RealityGates, source_commit: str,
                         runner: Runner,
                         revalidate: Callable[[], object],
                         attempt: str = "0000000000000000",
                         monotonic: Callable[[], float] = time.monotonic) -> dict:
    """Internal deterministic seam; production supplies every dependency."""
    gates = require_source_gates(gates)
    if re.fullmatch(r"[0-9a-f]{16}", attempt) is None:
        raise _refuse("reality attempt identity is malformed")
    output = RealityOutput(out)
    _inspect_candidate(canonical, runner, revalidate)
    output.create()
    suite_argv = _maven_argv(dry_run=False)
    dry_argv = _maven_argv(dry_run=True)
    runs = []
    runs.append(_execute_run(
        phase="full-suite", workspace=prepared.suite,
        image_id=canonical.image_id, maven_argv=suite_argv,
        timeout=SUITE_TIMEOUT_SECONDS, output=output, runner=runner,
        revalidate=revalidate, attempt=attempt, monotonic=monotonic))
    _source_unchanged(prepared.suite, prepared.baselines["suite"])
    _suite_artifacts(prepared.suite, output)

    runs.append(_execute_run(
        phase="unstripped-dry-run", workspace=prepared.unstripped,
        image_id=canonical.image_id, maven_argv=dry_argv,
        timeout=DRY_RUN_TIMEOUT_SECONDS, output=output, runner=runner,
        revalidate=revalidate, attempt=attempt, monotonic=monotonic))
    _source_unchanged(
        prepared.unstripped, prepared.baselines["unstripped"])
    unstripped = _dry_run_artifact(
        prepared.unstripped, output, "cucumber_dry_run_epubcheck.json")

    runs.append(_execute_run(
        phase="stripped-dry-run", workspace=prepared.stripped,
        image_id=canonical.image_id, maven_argv=dry_argv,
        timeout=DRY_RUN_TIMEOUT_SECONDS, output=output, runner=runner,
        revalidate=revalidate, attempt=attempt, monotonic=monotonic))
    _source_unchanged(prepared.stripped, prepared.baselines["stripped"])
    stripped = _dry_run_artifact(
        prepared.stripped, output,
        "cucumber_dry_run_epubcheck_stripped.json")
    _closure_gate(unstripped, stripped, prepared)
    revalidate()
    return output.finalize({
        "schema": SCHEMA, "project": PROJECT, "status": "complete",
        "source": {"commit": source_commit,
                   "corpus_commit": _image.CORPUS_COMMIT},
        "gate": {"execution_identity": gates.execution_identity},
        "authority": {"reference": canonical.authority_reference,
                      "daemon_fingerprint": canonical.daemon_fingerprint},
        "image_transcript": {"path": canonical.transcript_path,
                             "sha256": canonical.transcript_sha256},
        "image_id": canonical.image_id,
        "runs": runs,
        "diagnostic_timing": {
            "artifact": "cucumber_suite_epubcheck.timings.json",
            "method": "cucumber raw per-pickle duration sum",
            "not_n3_measurement": True,
        },
        "artifacts": [],
    })


def _prepare_workspaces() -> PreparedWorkspaces:
    """Build three private workspaces from the authenticated pinned blobs."""
    from ..core.boundary import load_boundary
    from ..java.closure_java import build_type_index
    from ..stacks.cucumber import strip_repo_cucumber

    parent = os.lstat(_image.ATTEMPT_PARENT)
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode) \
            or parent.st_uid != os.getuid() \
            or stat.S_IMODE(parent.st_mode) != 0o700:
        raise _refuse("fixed reality attempt parent is not owner-private 0700")
    root = tempfile.mkdtemp(
        prefix="r2t-epubcheck-reality-", dir=_image.ATTEMPT_PARENT)
    os.chmod(root, 0o700)
    paths = {name: os.path.join(root, name) for name in (
        "suite", "unstripped", "stripped", "gold")}
    try:
        for path in paths.values():
            os.mkdir(path, 0o700)
        suite = _image._source_snapshot(
            _image.CORPUS_ROOT, paths["suite"], coverage_patch=True)
        unstripped = _image._source_snapshot(
            _image.CORPUS_ROOT, paths["unstripped"], coverage_patch=True)
        _image._source_snapshot(
            _image.CORPUS_ROOT, paths["stripped"], coverage_patch=False)
        repo_root = BENCHMARK_ROOT
        boundary_path = os.path.join(
            repo_root, "config", "boundary_epubcheck.yml")
        strip_boundary = load_boundary(
            boundary_path, repo_root=paths["stripped"])
        strip_repo_cucumber(strip_boundary, paths["gold"])
        stripped = _image._workspace_source_inventory(paths["stripped"])
        boundary = load_boundary(
            boundary_path, repo_root=paths["unstripped"])
        type_index = build_type_index(
            paths["unstripped"], ("src/main/java", "src/test/java"))
        return PreparedWorkspaces(
            root, paths["suite"], paths["unstripped"], paths["stripped"],
            {"suite": {"paths": suite["paths"],
                       "tree_sha256": suite["tree_sha256"]},
             "unstripped": {"paths": unstripped["paths"],
                            "tree_sha256": unstripped["tree_sha256"]},
             "stripped": stripped}, boundary, type_index)
    except Exception:
        shutil.rmtree(root)
        raise


def _dispose_workspaces(prepared: PreparedWorkspaces) -> None:
    root = _absolute(prepared.root, "reality attempt root")
    if os.path.dirname(root) != _image.ATTEMPT_PARENT \
            or not os.path.basename(root).startswith("r2t-epubcheck-reality-"):
        raise _refuse("reality attempt cleanup target is outside its fixed prefix")
    if os.path.lexists(root):
        shutil.rmtree(root)


def capture_epubcheck_reality(*, image_transcript: str, out: str) -> dict:
    """Production entry: remain closed until exact later source approval."""
    image_transcript = _absolute(image_transcript, "--image-transcript")
    out = _absolute(out, "--out")
    if os.path.lexists(out):
        raise _refuse("--out must be absent")
    try:
        _image.refuse_ambient(os.environ)
    except _image.EPUBCheckImageRefused as exc:
        raise _refuse(str(exc)) from exc
    configured = docker_cli.configured_authority_path()
    if configured is None or not os.path.isabs(configured):
        raise _refuse("reality spike requires one absolute --docker-authority")
    gates = require_source_gates()
    canonical = load_canonical_image(image_transcript, gates)
    docker_cli.require_authority_reference(
        canonical.authority_reference, live=False)

    source_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))
    try:
        source_commit = _image._source_commit(source_root)
    except _image.EPUBCheckImageRefused as exc:
        raise _refuse(str(exc)) from exc

    docker_cli.reset_phase()
    authority, reference = docker_cli.begin_phase()
    if reference != canonical.authority_reference \
            or authority.get("daemon", {}).get("fingerprint_sha256") \
            != canonical.daemon_fingerprint:
        raise _refuse("live Docker authority differs from canonical transcript")

    def revalidate():
        docker_cli.reset_phase()
        current, current_reference = docker_cli.begin_phase()
        if current_reference != canonical.authority_reference \
                or current.get("daemon", {}).get("fingerprint_sha256") \
                != canonical.daemon_fingerprint:
            raise _refuse("Docker authority changed during reality spike")
        return current

    try:
        prepared = _prepare_workspaces()
    except _image.EPUBCheckImageRefused as exc:
        raise _refuse(str(exc)) from exc
    try:
        return _capture_with_runner(
            canonical=canonical, prepared=prepared, out=out, gates=gates,
            source_commit=source_commit, runner=_LiveRunner(),
            revalidate=revalidate, attempt=secrets.token_hex(8))
    except _image.EPUBCheckImageRefused as exc:
        raise _refuse(str(exc)) from exc
    finally:
        _dispose_workspaces(prepared)
