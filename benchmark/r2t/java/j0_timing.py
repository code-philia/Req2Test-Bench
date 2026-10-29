"""Inert controller and durability core for the J0 JVM timing protocol.

This module deliberately stops before execution.  It freezes and validates
the protocol's blocked N=3 cell order, derives the exact number of atomic
processes and timeout for every cell, assigns the sole ``attempt-0001``
evidence locations, decides whether an append-only campaign may advance, and
publishes already-validated canonical evidence with a durable kernel
no-clobber rename.

There is intentionally no CLI and no subprocess, Docker, Maven, Java, socket,
network-observer, or timing backend here.  In particular, this module cannot
turn a schedule into an execution.  The missing Phase-B adapters and runtime
gates in :mod:`benchmark/J0_JVM_TIMING_PROTOCOL.md` must land and qualify
separately before any canonical timing can start.
"""
from __future__ import annotations

import copy
import ctypes
import errno
import os
import secrets
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import j0


class J0TimingError(j0.J0Error):
    """A controlled refusal in the inert J0 timing controller."""


SCHEDULE_SCHEMA = "r2t.java-j0-timing-schedule/1"
PROJECTS = ("epubcheck", "algorand-sdk")
SCALAR_ITEM_COUNT = 12
PREPARATION_TIMEOUT_SECONDS = 600

DIRECT_ORDER: dict[int, tuple[str, ...]] = {
    1: (
        "full", "scalar_maven", "scalar_direct",
        "examples_aggregate", "examples_scalar",
    ),
    2: (
        "examples_scalar", "examples_aggregate", "full",
        "scalar_direct", "scalar_maven",
    ),
    3: (
        "scalar_maven", "scalar_direct", "examples_aggregate",
        "examples_scalar", "full",
    ),
}

NO_DIRECT_ORDER: dict[int, tuple[str, ...]] = {
    1: ("scalar_maven", "full", "examples_aggregate", "examples_scalar"),
    2: ("examples_scalar", "examples_aggregate", "full", "scalar_maven"),
    3: ("examples_aggregate", "examples_scalar", "scalar_maven", "full"),
}

PROJECT_ORDER: dict[int, tuple[str, str]] = {
    1: ("epubcheck", "algorand-sdk"),
    2: ("algorand-sdk", "epubcheck"),
    3: ("epubcheck", "algorand-sdk"),
}

CELL_TIMEOUT_SECONDS = {
    "full": 7200,
    "scalar_maven": 7200,
    "scalar_direct": 7200,
    "examples_aggregate": 3600,
    "examples_scalar": 3600,
}

_DIRECT_STATUSES = {"qualified", "rejected"}
_CELL_STATES = {"unstarted", "success", "direct_rejected", "failure", "torn"}
_INDEX_STATES = {"absent", "complete", "aborted"}
_RENAME_NOREPLACE = 1


def _closed(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise J0TimingError(f"{where}: expected object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        raise J0TimingError(
            f"{where}: closed schema mismatch; missing={missing!r}, extra={extra!r}")
    return value


def _integer(value: Any, where: str, *, minimum: int = 0,
             maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise J0TimingError(f"{where}: expected integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise J0TimingError(f"{where}: expected integer <= {maximum}")
    return value


def _hex64(value: Any, where: str) -> str:
    if not isinstance(value, str) or j0.HEX64.fullmatch(value) is None:
        raise J0TimingError(f"{where}: expected lowercase 64-hex digest")
    return value


def _validated_document_sha256(value: Any) -> str:
    """Hash the exact canonical object bytes that the caller validated.

    Reopening a pathname after validation would let a concurrent replacement
    split the validated identity from the recorded digest.  J0's canonical
    loader guarantees that these reconstructed bytes are exactly the loaded
    file bytes.
    """
    return j0._sha256(j0.canonical_json_bytes(value))


def _project_facts(value: Any, project: str) -> dict[str, Any]:
    facts = _closed(value, {
        "direct_qualification_sha256", "direct_status",
        "examples_row_count", "examples_selection_manifest_sha256",
        "scalar_selection_manifest_sha256",
    }, f"projects.{project}")
    if facts["direct_status"] not in _DIRECT_STATUSES:
        raise J0TimingError(
            f"projects.{project}.direct_status: expected qualified or rejected")
    _hex64(facts["direct_qualification_sha256"],
           f"projects.{project}.direct_qualification_sha256")
    _hex64(facts["examples_selection_manifest_sha256"],
           f"projects.{project}.examples_selection_manifest_sha256")
    _hex64(facts["scalar_selection_manifest_sha256"],
           f"projects.{project}.scalar_selection_manifest_sha256")
    _integer(facts["examples_row_count"],
             f"projects.{project}.examples_row_count", minimum=2, maximum=16)
    return facts


def _atomic_count(leg: str, examples_row_count: int) -> int:
    if leg in ("full", "examples_aggregate"):
        return 1
    if leg in ("scalar_maven", "scalar_direct"):
        return SCALAR_ITEM_COUNT
    if leg == "examples_scalar":
        return examples_row_count
    raise J0TimingError(f"unknown timing leg: {leg!r}")


def _make_schedule(
    phase_a_index_sha256: str,
    projects: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    _hex64(phase_a_index_sha256, "phase_a_index_sha256")
    projects_obj = _closed(dict(projects), set(PROJECTS), "projects")
    normalized_projects = {
        project: copy.deepcopy(_project_facts(projects_obj[project], project))
        for project in PROJECTS
    }

    cells: list[dict[str, Any]] = []
    for replicate in (1, 2, 3):
        for project in PROJECT_ORDER[replicate]:
            facts = normalized_projects[project]
            order = (DIRECT_ORDER if facts["direct_status"] == "qualified"
                     else NO_DIRECT_ORDER)[replicate]
            for position, leg in enumerate(order, start=1):
                cells.append({
                    "atomic_count": _atomic_count(
                        leg, facts["examples_row_count"]),
                    "cell_ordinal": len(cells),
                    "leg": leg,
                    "position": position,
                    "project": project,
                    "replicate": replicate,
                    "timeout_seconds": CELL_TIMEOUT_SECONDS[leg],
                })

    return {
        "cells": cells,
        "phase_a_index_sha256": phase_a_index_sha256,
        "projects": normalized_projects,
        "schema": SCHEDULE_SCHEMA,
    }


def _phase_a_schedule_facts(output: os.PathLike[str] | str) \
        -> tuple[str, dict[str, dict[str, Any]]]:
    """Read only Phase-A-authenticated, candidate-blind selection facts."""
    root = Path(output)
    index = j0.validate_phase_a_output(root)
    phase_a_digest = _validated_document_sha256(index)
    projects: dict[str, dict[str, Any]] = {}
    for project in PROJECTS:
        census = j0.load_canonical_json(root / "projects" / project / "census.json")
        selection = j0.load_canonical_json(
            root / "projects" / project / "examples-selection.json")
        scalar = j0.load_canonical_json(
            root / "projects" / project / "scalar-selection.json")
        j0.validate_census(census)
        j0.validate_examples_selection(selection, census)
        j0.validate_scalar_selection(scalar, census)
        if len(scalar["items"]) != SCALAR_ITEM_COUNT:
            raise J0TimingError(
                f"{project}: Phase-A scalar selection is not 12 items")
        bound = index["projects"][project]
        census_digest = _validated_document_sha256(census)
        selection_digest = _validated_document_sha256(selection)
        scalar_digest = _validated_document_sha256(scalar)
        if census_digest != bound["census_manifest_sha256"] \
                or selection_digest != bound["examples_selection_manifest_sha256"] \
                or scalar_digest != bound["scalar_selection_manifest_sha256"]:
            raise J0TimingError(
                f"{project}: loaded Phase-A document bytes drift from index")
        projects[project] = {
            # Filled only by build_timing_schedule after functional
            # qualification.  These sentinels never enter a schedule.
            "direct_qualification_sha256": None,
            "direct_status": None,
            "examples_row_count": selection["selected_row_count"],
            "examples_selection_manifest_sha256": selection_digest,
            "scalar_selection_manifest_sha256": scalar_digest,
        }
    return phase_a_digest, projects


def build_timing_schedule(
    phase_a_output: os.PathLike[str] | str,
    direct_qualifications: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Build the exact inert N=3 schedule from authenticated Phase A.

    ``direct_qualifications`` has exactly the two project keys.  Each value
    has ``status`` (``qualified`` or ``rejected``) and ``evidence_sha256``.
    A rejected direct launcher therefore remains an authenticated frozen
    choice of the four-position matrix; it is never deleted after timings.
    """
    phase_a_digest, projects = _phase_a_schedule_facts(phase_a_output)
    qualifications = _closed(
        dict(direct_qualifications), set(PROJECTS), "direct_qualifications")
    for project in PROJECTS:
        qualification = _closed(qualifications[project], {
            "evidence_sha256", "status",
        }, f"direct_qualifications.{project}")
        if qualification["status"] not in _DIRECT_STATUSES:
            raise J0TimingError(
                f"direct_qualifications.{project}.status: invalid")
        _hex64(qualification["evidence_sha256"],
               f"direct_qualifications.{project}.evidence_sha256")
        projects[project]["direct_status"] = qualification["status"]
        projects[project]["direct_qualification_sha256"] = \
            qualification["evidence_sha256"]
    return _make_schedule(phase_a_digest, projects)


def validate_timing_schedule(
    schedule: Any,
    *,
    phase_a_output: os.PathLike[str] | str | None = None,
) -> dict[str, Any]:
    """Validate a schedule and optionally rebind it to its Phase-A tree."""
    obj = _closed(schedule, {
        "cells", "phase_a_index_sha256", "projects", "schema",
    }, "schedule")
    if obj["schema"] != SCHEDULE_SCHEMA:
        raise J0TimingError("schedule.schema: wrong schema")
    phase_a_digest = _hex64(
        obj["phase_a_index_sha256"], "schedule.phase_a_index_sha256")
    projects_obj = _closed(obj["projects"], set(PROJECTS), "schedule.projects")
    facts = {
        project: _project_facts(projects_obj[project], project)
        for project in PROJECTS
    }
    if not isinstance(obj["cells"], list):
        raise J0TimingError("schedule.cells: expected array")
    expected = _make_schedule(phase_a_digest, facts)
    if j0.canonical_json_bytes(obj) != j0.canonical_json_bytes(expected):
        raise J0TimingError(
            "schedule: matrix/order/atomic-count/timeout does not match protocol")

    if phase_a_output is not None:
        actual_digest, actual_facts = _phase_a_schedule_facts(phase_a_output)
        if actual_digest != phase_a_digest:
            raise J0TimingError("schedule: wrong Phase-A index bytes")
        for project in PROJECTS:
            for key in (
                "examples_row_count", "examples_selection_manifest_sha256",
                "scalar_selection_manifest_sha256",
            ):
                if facts[project][key] != actual_facts[project][key]:
                    raise J0TimingError(
                        f"schedule.projects.{project}.{key}: Phase-A mismatch")
    return obj


def timing_schedule_sha256(schedule: Any) -> str:
    """Return the canonical file digest of a validated timing schedule."""
    obj = validate_timing_schedule(schedule)
    return j0._sha256(j0.canonical_json_bytes(obj))


def expected_attempt_layout(schedule: Any) -> list[dict[str, Any]]:
    """Return every predetermined cell and atomic ``attempt-0001`` path."""
    obj = validate_timing_schedule(schedule)
    layout: list[dict[str, Any]] = []
    for cell in obj["cells"]:
        cell_root = f"cells/cell-{cell['cell_ordinal']:04d}"
        layout.append({
            "atomic_ordinal": None,
            "cell_ordinal": cell["cell_ordinal"],
            "kind": "cell",
            "relative_path": f"{cell_root}/attempt-0001",
        })
        for atomic_ordinal in range(cell["atomic_count"]):
            layout.append({
                "atomic_ordinal": atomic_ordinal,
                "cell_ordinal": cell["cell_ordinal"],
                "kind": "atomic",
                "relative_path": (
                    f"{cell_root}/atomics/atomic-{atomic_ordinal:04d}/"
                    "attempt-0001"),
            })
    layout.sort(key=lambda entry: entry["relative_path"].encode("utf-8"))
    paths = [entry["relative_path"] for entry in layout]
    j0.validate_path_set(paths, where="attempt_layout.paths")
    return layout


def next_campaign_action(
    schedule: Any,
    cell_states: Sequence[str],
    *,
    index_state: str = "absent",
) -> dict[str, Any]:
    """Apply J0's no-retry/torn-attempt resume state machine.

    This is a decision function only.  It cannot start a process or write an
    index.  ``direct_rejected`` is a terminal cell state permitted only for
    the exploratory direct leg; all core legs require ``success``.
    """
    obj = validate_timing_schedule(schedule)
    if isinstance(cell_states, (str, bytes)) or not isinstance(
            cell_states, Sequence):
        raise J0TimingError("cell_states: expected sequence")
    states = list(cell_states)
    if len(states) != len(obj["cells"]):
        raise J0TimingError("cell_states: wrong matrix cardinality")
    if index_state not in _INDEX_STATES:
        raise J0TimingError("index_state: invalid")
    for ordinal, state in enumerate(states):
        if state not in _CELL_STATES:
            raise J0TimingError(f"cell_states[{ordinal}]: invalid")
        if state == "direct_rejected" \
                and obj["cells"][ordinal]["leg"] != "scalar_direct":
            raise J0TimingError(
                f"cell_states[{ordinal}]: direct rejection on a core leg")

    first_nonterminal = next((
        index for index, state in enumerate(states)
        if state in {"unstarted", "failure", "torn"}
    ), len(states))
    for ordinal in range(first_nonterminal + 1, len(states)):
        if states[ordinal] != "unstarted":
            raise J0TimingError(
                "cell_states: a later cell exists after the first missing/failed/torn cell")

    if index_state == "complete":
        if first_nonterminal != len(states):
            raise J0TimingError("complete index cannot cover an incomplete matrix")
        return {"action": "complete", "cell": None}
    if index_state == "aborted":
        if first_nonterminal == len(states) \
                or states[first_nonterminal] != "torn":
            raise J0TimingError("ABORTED index requires the first incomplete cell to be torn")
        return {"action": "aborted", "cell": None}

    if first_nonterminal == len(states):
        return {"action": "write_final_index", "cell": None}
    state = states[first_nonterminal]
    cell = copy.deepcopy(obj["cells"][first_nonterminal])
    if state == "unstarted":
        return {"action": "next_cell", "cell": cell}
    if state == "failure":
        return {"action": "closed_failure", "cell": cell}
    if state == "torn":
        return {"action": "write_aborted", "cell": cell}
    raise AssertionError("unreachable campaign state")


def _normalized_absolute_path(path: os.PathLike[str] | str) -> Path:
    """Validate raw spelling before ``Path`` can erase unsafe aliases."""
    raw = os.fspath(path)
    if not isinstance(raw, str):
        raise J0TimingError("evidence path must be a Unicode string")
    try:
        raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise J0TimingError("evidence path is not strict UTF-8") from exc
    if "\x00" in raw or not raw.startswith("/"):
        raise J0TimingError("evidence path must be a normalized absolute path")
    # The first split component is the leading root.  Every later component
    # must be literal and nonempty: this rejects //, /./, /../ and a trailing
    # slash before pathlib or normpath can collapse them.
    if any(component in ("", ".", "..") for component in raw.split("/")[1:]):
        raise J0TimingError("evidence path contains a non-normal component")
    if os.path.normpath(raw) != raw:
        raise J0TimingError("evidence path must be normalized")
    return Path(raw)


def _open_directory_nofollow(path: Path) -> int:
    """Open one absolute directory without following any path component."""
    raw = os.fspath(path)
    components = [part for part in raw.split(os.sep) if part]
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(os.sep, flags)
    try:
        for component in components:
            if component in (".", "..") or "\x00" in component:
                raise J0TimingError("unsafe evidence parent component")
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        current = os.fstat(fd)
        if not stat.S_ISDIR(current.st_mode):
            raise J0TimingError("evidence parent is not a directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    """Use Linux renameat2 so staging publication cannot clobber a winner."""
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise J0TimingError(
            "renameat2(RENAME_NOREPLACE) is unavailable; durable publication refuses") \
            from exc
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        value = ctypes.get_errno()
        if value in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
            raise J0TimingError(
                "filesystem lacks atomic RENAME_NOREPLACE; publication refuses")
        if value == errno.EEXIST:
            raise J0TimingError(
                f"evidence target already exists: {destination}")
        raise J0TimingError(
            f"atomic evidence rename failed: {os.strerror(value)}")


def durable_publish_new_json(
    path: os.PathLike[str] | str,
    value: Any,
) -> str:
    """Durably publish canonical JSON exactly once, without creating parents.

    The caller supplies an already semantically validated evidence object.
    This function owns only canonical bytes and the durability/no-clobber
    boundary: private same-directory staging, file fsync, atomic
    ``RENAME_NOREPLACE``, directory fsync, and exact read-back.  It never
    overwrites or repairs evidence.
    """
    destination = _normalized_absolute_path(path)
    name = destination.name
    if not name or name in (".", "..") or os.sep in name or "\x00" in name:
        raise J0TimingError("unsafe evidence filename")
    payload = j0.canonical_json_bytes(value)
    parent_fd = _open_directory_nofollow(destination.parent)
    temporary: str | None = None
    fd = -1
    published = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        for _attempt in range(32):
            candidate = ".r2t-j0-stage-" + secrets.token_hex(16)
            try:
                fd = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
                temporary = candidate
                break
            except FileExistsError:
                continue
        if fd < 0 or temporary is None:
            raise J0TimingError("cannot reserve private J0 staging file")
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise J0TimingError("short write while staging J0 evidence")
            view = view[written:]
        os.fchmod(fd, 0o644)
        os.fsync(fd)
        _rename_noreplace(parent_fd, temporary, name)
        temporary = None
        published = True
        os.fsync(parent_fd)
        os.close(fd)
        fd = -1

        read_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_CLOEXEC", 0)
        read_fd = os.open(name, read_flags, dir_fd=parent_fd)
        try:
            current = os.fstat(read_fd)
            if not stat.S_ISREG(current.st_mode) \
                    or stat.S_IMODE(current.st_mode) != 0o644:
                raise J0TimingError("published J0 evidence has wrong file type/mode")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(read_fd, 1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
            if b"".join(chunks) != payload:
                raise J0TimingError("published J0 evidence failed exact read-back")
        finally:
            os.close(read_fd)
        return j0._sha256(payload)
    except OSError as exc:
        state = " after publication" if published else ""
        raise J0TimingError(
            f"durable J0 evidence write failed{state}: {exc}") from exc
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


def selftest() -> int:
    import ast
    import hashlib

    ok = True

    def check(name: str, condition: bool) -> None:
        nonlocal ok
        print(("PASS" if condition else "FAIL") + ": " + name)
        ok &= condition

    def refused(callable_) -> bool:
        try:
            callable_()
        except (J0TimingError, j0.J0Error, OSError):
            return True
        return False

    digest = lambda text: hashlib.sha256(text.encode("ascii")).hexdigest()

    with tempfile.TemporaryDirectory(prefix="r2t-j0-timing-swap-") as temporary:
        authority_path = Path(temporary) / "authority.json"
        authority_a = {"authority": "a"}
        authority_b = {"authority": "b"}
        authority_path.write_bytes(j0.canonical_json_bytes(authority_a))
        validated_authority = j0.load_canonical_json(authority_path)
        authority_path.write_bytes(j0.canonical_json_bytes(authority_b))
        check("validated document digest cannot be split by a pathname swap",
              _validated_document_sha256(validated_authority)
              == j0._sha256(j0.canonical_json_bytes(authority_a))
              and _validated_document_sha256(validated_authority)
              != j0._sha256(authority_path.read_bytes()))

    project_facts = {
        "epubcheck": {
            "direct_qualification_sha256": digest("epub-direct"),
            "direct_status": "qualified",
            "examples_row_count": 16,
            "examples_selection_manifest_sha256": digest("epub-examples"),
            "scalar_selection_manifest_sha256": digest("epub-scalar"),
        },
        "algorand-sdk": {
            "direct_qualification_sha256": digest("algo-direct"),
            "direct_status": "qualified",
            "examples_row_count": 5,
            "examples_selection_manifest_sha256": digest("algo-examples"),
            "scalar_selection_manifest_sha256": digest("algo-scalar"),
        },
    }
    schedule = _make_schedule(digest("phase-a"), project_facts)
    validate_timing_schedule(schedule)
    check("qualified-direct matrix has exactly 30 cells",
          len(schedule["cells"]) == 30)
    check("project blocks alternate EPUB/Algorand by frozen replicate",
          [(cell["replicate"], cell["project"])
           for cell in schedule["cells"] if cell["position"] == 1]
          == [(1, "epubcheck"), (1, "algorand-sdk"),
              (2, "algorand-sdk"), (2, "epubcheck"),
              (3, "epubcheck"), (3, "algorand-sdk")])
    epub_r1 = [cell["leg"] for cell in schedule["cells"]
               if cell["project"] == "epubcheck" and cell["replicate"] == 1]
    check("five-position order is byte-for-leg exact", epub_r1 == list(DIRECT_ORDER[1]))
    check("scalar and Examples atomic cardinalities are not pickle-pooled",
          [(cell["leg"], cell["atomic_count"])
           for cell in schedule["cells"]
           if cell["project"] == "epubcheck" and cell["replicate"] == 1]
          == [("full", 1), ("scalar_maven", 12), ("scalar_direct", 12),
              ("examples_aggregate", 1), ("examples_scalar", 16)])
    check("core/scalar and Examples timeout envelopes are exact",
          {cell["timeout_seconds"] for cell in schedule["cells"]
           if cell["leg"] in {"full", "scalar_maven", "scalar_direct"}}
          == {7200}
          and {cell["timeout_seconds"] for cell in schedule["cells"]
               if cell["leg"].startswith("examples_")} == {3600}
          and PREPARATION_TIMEOUT_SECONDS == 600)

    rejected_facts = copy.deepcopy(project_facts)
    rejected_facts["epubcheck"]["direct_status"] = "rejected"
    rejected_facts["algorand-sdk"]["direct_status"] = "rejected"
    no_direct = _make_schedule(digest("phase-a"), rejected_facts)
    check("rejected-direct matrix uses exact 24-cell four-position order",
          len(no_direct["cells"]) == 24
          and [cell["leg"] for cell in no_direct["cells"]
               if cell["project"] == "algorand-sdk" and cell["replicate"] == 2]
          == list(NO_DIRECT_ORDER[2])
          and not any(cell["leg"] == "scalar_direct" for cell in no_direct["cells"]))
    mixed_facts = copy.deepcopy(project_facts)
    mixed_facts["algorand-sdk"]["direct_status"] = "rejected"
    mixed = _make_schedule(digest("phase-a"), mixed_facts)
    check("direct qualification is frozen independently per project",
          len(mixed["cells"]) == 27
          and sum(cell["leg"] == "scalar_direct" for cell in mixed["cells"]) == 3
          and all(cell["project"] == "epubcheck" for cell in mixed["cells"]
                  if cell["leg"] == "scalar_direct"))

    layout = expected_attempt_layout(schedule)
    check("cell and every atomic process receive one unique attempt-0001",
          len(layout) == 249
          and len({entry["relative_path"] for entry in layout}) == len(layout)
          and all(entry["relative_path"].endswith("attempt-0001") for entry in layout)
          and not any("attempt-0002" in entry["relative_path"] for entry in layout))

    tampered_timeout = copy.deepcopy(schedule)
    tampered_timeout["cells"][0]["timeout_seconds"] = 7199
    check("schedule validator refuses timeout relaxation",
          refused(lambda: validate_timing_schedule(tampered_timeout)))
    tampered_order = copy.deepcopy(schedule)
    tampered_order["cells"][0], tampered_order["cells"][1] = \
        tampered_order["cells"][1], tampered_order["cells"][0]
    check("schedule validator refuses post-observation reordering",
          refused(lambda: validate_timing_schedule(tampered_order)))
    tampered_atomic = copy.deepcopy(schedule)
    tampered_atomic["cells"][1]["atomic_count"] = 1
    check("schedule validator refuses scalar invocation pooling",
          refused(lambda: validate_timing_schedule(tampered_atomic)))
    injected_fork_policy = copy.deepcopy(schedule)
    injected_fork_policy["projects"]["epubcheck"]["reuseForks"] = True
    check("closed schedule cannot smuggle unapproved fork reuse",
          refused(lambda: validate_timing_schedule(injected_fork_policy)))
    missing_evidence = copy.deepcopy(project_facts)
    missing_evidence["epubcheck"]["direct_qualification_sha256"] = None
    check("four-position fallback still requires frozen rejection evidence",
          refused(lambda: _make_schedule(digest("phase-a"), missing_evidence)))

    states = ["unstarted"] * len(schedule["cells"])
    action = next_campaign_action(schedule, states)
    check("fresh campaign may address only the first frozen cell",
          action["action"] == "next_cell" and action["cell"]["cell_ordinal"] == 0)
    states[0] = "success"
    check("resume advances by exactly one successful prefix cell",
          next_campaign_action(schedule, states)["cell"]["cell_ordinal"] == 1)
    gap = list(states)
    gap[2] = "success"
    check("resume refuses a terminal cell after an unstarted gap",
          refused(lambda: next_campaign_action(schedule, gap)))
    failed = ["success"] + ["unstarted"] * (len(states) - 1)
    failed[1] = "failure"
    check("terminal core failure is closed and never retryable",
          next_campaign_action(schedule, failed)["action"] == "closed_failure")
    torn = ["success"] + ["unstarted"] * (len(states) - 1)
    torn[1] = "torn"
    check("torn attempt requires ABORTED rather than repeat",
          next_campaign_action(schedule, torn)["action"] == "write_aborted"
          and next_campaign_action(schedule, torn, index_state="aborted")["action"]
          == "aborted")
    illegal_direct = ["unstarted"] * len(states)
    illegal_direct[0] = "direct_rejected"
    check("direct semantic exception cannot launder a core leg",
          refused(lambda: next_campaign_action(schedule, illegal_direct)))
    all_success = ["success"] * len(states)
    direct_cell = next(index for index, cell in enumerate(schedule["cells"])
                       if cell["leg"] == "scalar_direct")
    all_success[direct_cell] = "direct_rejected"
    check("qualified direct mismatch may close direct while core matrix completes",
          next_campaign_action(schedule, all_success)["action"] == "write_final_index"
          and next_campaign_action(
              schedule, all_success, index_state="complete")["action"] == "complete")
    check("final index cannot cover a partial matrix",
          refused(lambda: next_campaign_action(
              schedule, states, index_state="complete")))

    with tempfile.TemporaryDirectory(prefix="r2t-j0-timing-durable-") as temporary:
        root = Path(temporary)
        destination = root / "schedule.json"
        digest_value = durable_publish_new_json(destination, schedule)
        check("durable publication writes exact canonical bytes and digest",
              destination.read_bytes() == j0.canonical_json_bytes(schedule)
              and digest_value == timing_schedule_sha256(schedule)
              and stat.S_IMODE(destination.stat().st_mode) == 0o644)
        preserved = destination.read_bytes()
        check("durable publication is kernel no-clobber",
              refused(lambda: durable_publish_new_json(destination, {"winner": False}))
              and destination.read_bytes() == preserved)
        outside = root / "outside.json"
        outside.write_bytes(b"outside\n")
        linked = root / "linked.json"
        linked.symlink_to(outside)
        check("existing symlink target cannot redirect evidence publication",
              refused(lambda: durable_publish_new_json(linked, {"unsafe": True}))
              and outside.read_bytes() == b"outside\n")
        real_parent = root / "real-parent"
        real_parent.mkdir()
        symlink_parent = root / "linked-parent"
        symlink_parent.symlink_to(real_parent, target_is_directory=True)
        check("symlinked parent component is refused",
              refused(lambda: durable_publish_new_json(
                  symlink_parent / "evidence.json", {"unsafe": True}))
              and not (real_parent / "evidence.json").exists())
        dot_alias = os.fspath(root) + "/./dot-alias.json"
        double_slash_alias = "/" + os.fspath(root) + "/double-alias.json"
        check("raw dot and double-slash aliases refuse before Path normalization",
              refused(lambda: durable_publish_new_json(
                  dot_alias, {"unsafe": True}))
              and refused(lambda: durable_publish_new_json(
                  double_slash_alias, {"unsafe": True}))
              and not (root / "dot-alias.json").exists()
              and not (root / "double-alias.json").exists())
        check("byte-string evidence paths cannot bypass strict UTF-8 authority",
              refused(lambda: durable_publish_new_json(
                  os.fsencode(root / "bytes.json"), {"unsafe": True}))
              and not (root / "bytes.json").exists())

    source_tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(source_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(source_tree)
        if isinstance(node, ast.ImportFrom) and node.level == 0
    }
    functions = {
        node.name for node in ast.walk(source_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    check("controller remains inert with no execution/network imports or CLI",
          not ({"subprocess", "socket", "urllib"} & imported_roots)
          and "main" not in functions)

    print("\n" + ("ALL PASS (java.j0_timing)" if ok
                   else "FAILURES (java.j0_timing)"))
    return 0 if ok else 1
