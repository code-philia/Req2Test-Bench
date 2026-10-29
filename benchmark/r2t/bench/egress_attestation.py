"""Content-addressed evidence for the prospective confined egress gate.

The ordinary egress command prints a useful verdict, but terminal output is
not release evidence: it neither binds the run bytes nor the trajectory bytes
that were inspected.  This module closes that gap.  An attestation commits to
the candidate run, every regular file below every attempt directory actually
read by :mod:`r2t.egress`, the detector's gate version and rules digest, the
recorded detector and scanner source identity, policy, aggregate verdicts,
exit status, and printed-output bytes.

Schema /3 joins the retained trajectory detector to the coordinator proxy's
per-item zero-body-403 journal.  Historical /1 and /2 documents retain their
original validation and are never rescored under the prospective rule.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
from typing import Iterable, Optional

from .. import egress
from ..core.constants import JOURNAL_RELATIVE, JOURNAL_SCHEMA
from ..core.paths import RELEASE_DIR
from ..data import versions


SCHEMA = "r2t.egress-attestation/3"
V2_SCHEMA = "r2t.egress-attestation/2"

#: The one sealed /1 document this repository still carries:
#: `release/legacy_consistency/cell1_coreshop_aider.egress.json`, the published
#: CoreShop Cell 1 aider arm.  It is accepted UNCHANGED -- historical evidence
#: is labelled `legacy_consistency`, never given provenance fields retroactively
#: as though they were present at collection.  /1 meant "sealed only when
#: clean", so a /1 document that validates carries exactly the guarantee its
#: bytes claimed when it was written.
LEGACY_SCHEMA = "r2t.egress-attestation/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EgressAttestationRefused(RuntimeError):
    """The evidence is incomplete, inconsistent, or mutable while read."""


def _refuse(message: str):
    raise EgressAttestationRefused("REFUSED: " + message)


# --- the egress proxy's journal ---------------------------------------------
#
# Written by the coordinator-side proxy (`agents/egress_proxy.py`) after one
# item process exits, read back here by `_read_proxy_journal`.  The builder
# and the validator live with the READER: the proxy imports them back, so a
# checkout without the agent component can still validate the journals an
# attestation names.


class EgressRefused(Exception):
    """A CONNECT target outside the single admitted endpoint."""


def journal_document(attempts) -> dict:
    """Return the closed journal for rejected CONNECT targets.

    An entry is appended only in `_serve`'s off-allowlist branch, before that
    branch writes its zero-length 403 and returns without opening upstream.
    Repeated targets remain repeated because the collection reports attempts,
    not merely distinct destinations.
    """
    entries = []
    for index, attempt in enumerate(attempts):
        if not isinstance(attempt, dict) or set(attempt) != {"host", "port"}:
            raise EgressRefused(
                f"journal attempt {index} is not a closed host/port object")
        host, port = attempt["host"], attempt["port"]
        if not isinstance(host, str) or not host:
            raise EgressRefused(f"journal attempt {index} has no host")
        if type(port) is not int or not 1 <= port <= 65535:
            raise EgressRefused(f"journal attempt {index} has an invalid port")
        entries.append({"host": host, "port": port})
    return {
        "schema": JOURNAL_SCHEMA,
        "n_attempts": len(entries),
        "attempts": entries,
    }


def validate_journal(document) -> dict:
    """Validate one exact `/1` proxy journal document."""
    if not isinstance(document, dict) \
            or set(document) != {"schema", "n_attempts", "attempts"}:
        raise EgressRefused("proxy journal is not the closed /1 document")
    if document.get("schema") != JOURNAL_SCHEMA:
        raise EgressRefused("proxy journal has another schema")
    attempts = document.get("attempts")
    if not isinstance(attempts, list):
        raise EgressRefused("proxy journal attempts is not a list")
    rebuilt = journal_document(attempts)
    if type(document.get("n_attempts")) is not int \
            or document["n_attempts"] != rebuilt["n_attempts"]:
        raise EgressRefused("proxy journal count differs from its attempts")
    return rebuilt


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def canonical_sha256(value) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _exact_keys(value, expected: set[str], where: str) -> None:
    if not isinstance(value, dict):
        _refuse(f"{where} is not an object")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        _refuse(f"{where} keys differ; missing={missing}, extra={extra}")


def _is_sha256(value) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _file_fact(path: str, *, label: str) -> dict:
    """Hash one stable, non-symlink regular file through a no-follow fd."""
    absolute = os.path.abspath(path)
    try:
        before = os.lstat(absolute)
    except OSError as exc:
        _refuse(f"cannot stat {label}: {exc}")
    if not stat.S_ISREG(before.st_mode):
        _refuse(f"{label} is not a non-symlink regular file: {absolute}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) \
        | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(absolute, flags)
    except OSError as exc:
        _refuse(f"cannot open {label} without following links: {exc}")
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) \
                or (opened.st_dev, opened.st_ino) \
                != (before.st_dev, before.st_ino):
            _refuse(f"{label} changed identity while it was opened")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after_fd = os.fstat(fd)
    finally:
        os.close(fd)
    try:
        after_path = os.lstat(absolute)
    except OSError as exc:
        _refuse(f"cannot re-stat {label}: {exc}")
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns",
                     "st_ctime_ns")
    if any(getattr(before, key) != getattr(after_fd, key)
           or getattr(before, key) != getattr(after_path, key)
           for key in stable_fields) or size != before.st_size:
        _refuse(f"{label} changed while it was hashed")
    return {"bytes": size, "sha256": digest.hexdigest()}


def _tree_inventory(root: str, attempt_dirs: Iterable[str]) -> dict:
    """Digest exactly the attempt subtrees the detector reported reading."""
    root_abs = os.path.abspath(root)
    root_real = os.path.realpath(root_abs)
    if os.path.islink(root_abs) or not os.path.isdir(root_abs):
        _refuse("trajectory root is not a non-symlink directory")
    attempts: list[tuple[str, str]] = []
    for raw in sorted(set(os.path.abspath(path) for path in attempt_dirs)):
        real = os.path.realpath(raw)
        try:
            inside = os.path.commonpath((root_real, real)) == root_real
        except ValueError:
            inside = False
        if not inside or real == root_real:
            _refuse(f"attempt directory escapes trajectory root: {raw}")
        if raw != real or os.path.islink(raw) or not os.path.isdir(raw):
            _refuse(f"attempt directory is not a stable real directory: {raw}")
        attempts.append((os.path.relpath(real, root_real).replace(os.sep, "/"),
                         real))
    if not attempts:
        _refuse("no attempt directory was available to attest")

    records = []
    seen = set()
    for _attempt_rel, attempt in attempts:
        for dirpath, dirnames, filenames in os.walk(
                attempt, topdown=True, followlinks=False):
            dirnames.sort()
            filenames.sort()
            for name in dirnames:
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    _refuse("trajectory inventory contains a symlink directory: "
                            + os.path.relpath(path, root_real))
                try:
                    mode = os.lstat(path).st_mode
                except OSError as exc:
                    _refuse(f"cannot stat trajectory directory {path}: {exc}")
                if not stat.S_ISDIR(mode):
                    _refuse(f"trajectory path is not a directory: {path}")
            for name in filenames:
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, root_real).replace(os.sep, "/")
                if rel in seen:
                    _refuse(f"trajectory file was inventoried twice: {rel}")
                seen.add(rel)
                fact = _file_fact(path, label=f"trajectory file {rel}")
                records.append({"path": rel, **fact})
    records.sort(key=lambda row: row["path"])
    attempt_names = [item[0] for item in attempts]
    return {
        "n_attempt_dirs": len(attempt_names),
        "attempt_dirs_sha256": canonical_sha256(attempt_names),
        "n_files": len(records),
        "bytes": sum(row["bytes"] for row in records),
        "records_sha256": canonical_sha256(records),
    }


def _source_authority() -> dict:
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    benchmark_root = os.path.dirname(package_root)
    egress_path = os.path.join(package_root, "egress.py")
    detector = {
        "path": "benchmark/r2t/egress.py",
        **_file_fact(egress_path, label="egress detector source"),
    }
    scanner_root = os.path.join(package_root, "agents", "scanners")
    scanner_records = []
    for dirpath, dirnames, filenames in os.walk(scanner_root):
        dirnames.sort()
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, benchmark_root).replace(os.sep, "/")
            scanner_records.append({
                "path": "benchmark/" + rel,
                **_file_fact(path, label=f"native scanner source {rel}"),
            })
    if not scanner_records:
        _refuse("native scanner source inventory is empty")
    return {
        "egress_detector": detector,
        "native_scanners": {
            "n_files": len(scanner_records),
            "records_sha256": canonical_sha256(scanner_records),
            "files": scanner_records,
        },
    }


def _result(verdicts: dict, exit_code: int, stdout: str, *,
            n_egress_attempts: Optional[int] = None,
            n_egress_retrieved: Optional[int] = None) -> dict:
    entries = list(verdicts.values())
    attempts = [attempt for entry in entries for attempt in entry["attempts"]]
    n_raw = sum(entry["n_raw_suspects"] for entry in entries)
    n_suspects = sum(entry["n_suspects"] for entry in entries)
    result = {
        "exit_code": exit_code,
        "clean": exit_code == 0,
        "n_items": len(entries),
        "n_assessed": sum(not entry["unassessable"] for entry in entries),
        "n_unassessable": sum(entry["unassessable"] for entry in entries),
        "n_no_trajectory": sum(entry["no_trajectory"] for entry in entries),
        "n_contaminated": sum(entry["contaminated"] for entry in entries),
        "n_strict_suspects": n_suspects - n_raw,
        "n_raw_suspects": n_raw,
        "n_attempt_dirs": len(attempts),
        "n_events": sum(attempt["n_events"] for attempt in attempts),
        "n_unrecognized_files": sum(
            len(attempt["unrecognized"]) for attempt in attempts),
        "stdout_bytes": len(stdout.encode("utf-8")),
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
    }
    if n_egress_attempts is not None:
        result["n_egress_attempts"] = n_egress_attempts
        result["n_egress_retrieved"] = n_egress_retrieved
    return result


def _candidate_proxy_counts(run_path: str) -> dict[str, int]:
    """The row-side count each coordinator journal must equal."""
    counts = {}
    try:
        with open(run_path, encoding="utf-8") as handle:
            lines = list(handle)
    except OSError as exc:
        _refuse(f"cannot read candidate run proxy counts: {exc}")
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            _refuse(f"candidate run line {number} is not JSON: {exc}")
        if not isinstance(row, dict) or not isinstance(row.get("item_id"), str) \
                or not row["item_id"]:
            _refuse(f"candidate run line {number} has no item_id")
        item_id = row["item_id"]
        if item_id in counts:
            _refuse(f"candidate run repeats item_id {item_id!r}")
        metadata = row.get("metadata")
        count = metadata.get("egress_blocked_attempts") \
            if isinstance(metadata, dict) else None
        if type(count) is not int or count < 0:
            _refuse(
                f"candidate row {item_id!r} has no valid "
                "egress_blocked_attempts count")
        counts[item_id] = count
    return counts


def _read_proxy_journal(attempt_dir: str) -> dict:
    path = os.path.join(attempt_dir, JOURNAL_RELATIVE)
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        _refuse(f"cannot read required proxy journal {path}: {exc}")
    try:
        return validate_journal(document)
    except EgressRefused as exc:
        _refuse(f"invalid proxy journal {path}: {exc}")


def _affirmative_transfer(hit: dict) -> bool:
    """Whether an attributed response itself proves off-host bytes arrived."""
    return hit.get("kind") == "response" \
        and isinstance(hit.get("host"), str) \
        and hit.get("affirmative_transfer") is True


def _join_proxy_journals(run_path: str, verdicts: dict) -> tuple:
    """Join row counts to journals and remove journal-proven blocked hits.

    The existing detector remains the affirmative-retrieval check.  A
    A journal-matched nonaffirmative hit is a disclosed blocked attempt. An
    affirmative response remains contamination even for the same host. Any
    other off-allowlist hit is unresolved rather than silently promoted to a
    retrieval: the item becomes unassessable and cannot seal.
    """
    row_counts = _candidate_proxy_counts(run_path)
    if set(row_counts) != set(verdicts):
        _refuse("candidate rows and egress verdict items differ")
    adjusted = copy.deepcopy(verdicts)
    by_item = {}
    attempted_items = []
    for item_id, entry in adjusted.items():
        item_attempts = []
        attempts_by_dir = {}
        for attempt in entry["attempts"]:
            journal = _read_proxy_journal(attempt["real"])
            attempts_by_dir[attempt["real"]] = journal["attempts"]
            item_attempts.extend(journal["attempts"])
        if row_counts[item_id] != len(item_attempts):
            _refuse(
                f"candidate row {item_id!r} records "
                f"{row_counts[item_id]} blocked attempts but its proxy "
                f"journal records {len(item_attempts)}")
        by_item[item_id] = item_attempts
        if item_attempts:
            attempted_items.append(item_id)

        retrieved_hosts = set()
        retrieved_count = 0
        unresolved_hosts = set()
        for attempt in entry["attempts"]:
            blocked_hosts = {
                blocked["host"].lower()
                for blocked in attempts_by_dir[attempt["real"]]}
            affirmative_hosts = {
                hit["host"].lower() for hit in attempt["hits"]
                if hit.get("verdict") == egress.VIOLATION
                and isinstance(hit.get("host"), str)
                and _affirmative_transfer(hit)}
            hits = []
            attempt_retrieved = 0
            for raw_hit in attempt["hits"]:
                hit = dict(raw_hit)
                host = hit.get("host")
                if hit.get("verdict") == egress.VIOLATION:
                    normalized = host.lower() if isinstance(host, str) else None
                    if _affirmative_transfer(hit):
                        attempt_retrieved += 1
                        if normalized is not None:
                            retrieved_hosts.add(host)
                    elif normalized in affirmative_hosts:
                        hit["verdict"] = "affirmed_context"
                    elif normalized in blocked_hosts:
                        hit["verdict"] = "blocked"
                    else:
                        hit["verdict"] = "unresolved"
                        if normalized is not None:
                            unresolved_hosts.add(host)
                hits.append(hit)
            attempt["hits"] = hits
            attempt["n_violations"] = attempt_retrieved
            attempt["verdicts"][egress.VIOLATION] = attempt_retrieved
            attempt["violation_hosts"] = sorted({
                hit["host"] for hit in hits
                if hit.get("verdict") == egress.VIOLATION
                and isinstance(hit.get("host"), str)})
            attempt["contaminated"] = bool(attempt_retrieved)
            retrieved_count += attempt_retrieved
        entry["n_violations"] = retrieved_count
        entry["violation_hosts"] = sorted(retrieved_hosts)
        entry["contaminated"] = bool(retrieved_count)
        if unresolved_hosts:
            entry["unassessable"] = True
            entry["unassessable_reasons"] = list(
                entry["unassessable_reasons"]) + [
                    "off-allowlist evidence for "
                    + ", ".join(sorted(unresolved_hosts))
                    + " is neither an affirmative transfer nor joined to "
                      "a proxy refusal"]
    return adjusted, by_item, sorted(attempted_items)


def _retrieved_count(verdicts: dict) -> int:
    """Count affirmative transfer responses that remain violations."""
    return sum(
        hit.get("verdict") == egress.VIOLATION
        and _affirmative_transfer(hit)
        for entry in verdicts.values()
        for attempt in entry["attempts"]
        for hit in attempt["hits"])


def build_attestation(run_path: str, trajectory_root: str, *,
                      allowed_hosts: Iterable[str],
                      condition: Optional[str] = None) -> dict:
    """Run prospective gate 5 and return its sealed clean/contaminated result."""
    run_abs = os.path.abspath(run_path)
    root_abs = os.path.abspath(trajectory_root)
    hosts = sorted(set(allowed_hosts))
    if not hosts or not all(isinstance(host, str) and host for host in hosts):
        _refuse("a non-empty explicit allowed-host set is required")
    # `strict_suspect=False` is the /2 change, and it narrows what QUARANTINES,
    # not what is detected.  A SUSPECT is the documented verdict for a call
    # whose host could not be read; under `True` it was indistinguishable from
    # a resolved-host VIOLATION, so an agent probe spelling `pip install` in a
    # `||` branch that never ran destroyed a campaign while a real `git clone`
    # of the SDK under test sat unnoticed in another shard.  Suspects are still
    # counted, still printed, and still sealed below.
    policy = egress.Policy(allow=frozenset(hosts), strict_suspect=False)
    scanned = egress.scan_run(run_abs, root_abs, policy, condition=condition)
    verdicts, proxy_attempts, attempted_items = \
        _join_proxy_journals(run_abs, scanned)
    output = io.StringIO()
    exit_code = egress.gate(
        run_abs, root_abs, policy, condition=condition, out=output,
        allow_unassessed=False, precomputed=verdicts,
        proxy_attempts=proxy_attempts)
    result = _result(
        verdicts, exit_code, output.getvalue(),
        n_egress_attempts=sum(len(value) for value in proxy_attempts.values()),
        n_egress_retrieved=_retrieved_count(verdicts))
    # Unreadable evidence still refuses: "not scored is not zero" applied to
    # the gate's own reading.  A row it could not assess is not a row it
    # cleared, and sealing it would claim knowledge the gate does not have.
    if result["n_unassessable"] or result["n_no_trajectory"]:
        _refuse("strict egress gate could not assess every row: "
                + json.dumps(result, sort_keys=True))
    contaminated = sorted(item for item, entry in verdicts.items()
                          if entry["contaminated"])
    attempt_dirs = [attempt["real"] for entry in verdicts.values()
                    for attempt in entry["attempts"]]
    inventory = _tree_inventory(root_abs, attempt_dirs)
    if inventory["n_attempt_dirs"] != result["n_attempt_dirs"]:
        _refuse("detector attempt count and inventoried attempt roots differ")
    document = {
        "schema": SCHEMA,
        "status": "contaminated" if contaminated else "clean",
        # Named, not counted: a reader deciding whether to publish needs to
        # know WHICH rows, and the scorer needs the same list to refuse them a
        # pass without deleting them from the denominator.
        "contaminated_items": contaminated,
        "attempted_items": attempted_items,
        "gate": {
            "version": egress.EGRESS_GATE_VERSION,
            "strict_suspect": False,
            "allow_unassessed": False,
            "allowed_hosts": hosts,
            "condition": condition,
            "detection_not_prevention": False,
        },
        "analysis_authority": _source_authority(),
        "inputs": {
            "candidate_run": {
                "path": run_abs,
                **_file_fact(run_abs, label="candidate run"),
            },
            "trajectory_root": {"path": root_abs, **inventory},
        },
        "result": result,
    }
    document["attestation_sha256"] = canonical_sha256(document)
    validate_attestation(document)
    return document


def validate_attestation(document: dict) -> dict:
    """Validate the closed schema and every internal digest/equation."""
    schema = document.get("schema") if isinstance(document, dict) else None
    legacy = schema == LEGACY_SCHEMA
    v2 = schema == V2_SCHEMA
    current = schema == SCHEMA
    if not (legacy or v2 or current):
        _refuse("egress attestation schema is not /1, /2, or /3")
    _exact_keys(document, {"schema", "status", "gate", "analysis_authority",
                           "inputs", "result", "attestation_sha256"}
                | (set() if legacy else {"contaminated_items"})
                | ({"attempted_items"} if current else set()),
                "egress attestation")
    if legacy:
        if document["status"] != "clean":
            _refuse("a /1 attestation exists only in its clean form")
        items: list = []
        attempted: list = []
    else:
        if document["status"] not in ("clean", "contaminated"):
            _refuse("egress attestation status is invalid")
        items = document["contaminated_items"]
        if not isinstance(items, list) or items != sorted(set(items)) \
                or not all(isinstance(item, str) and item for item in items):
            _refuse("contaminated_items is not a sorted unique string list")
        if bool(items) != (document["status"] == "contaminated"):
            _refuse("status and contaminated_items disagree")
        attempted = document["attempted_items"] if current else []
        if current and (not isinstance(attempted, list)
                        or attempted != sorted(set(attempted))
                        or not all(isinstance(item, str) and item
                                   for item in attempted)):
            _refuse("attempted_items is not a sorted unique string list")
    gate = document["gate"]
    _exact_keys(gate, {"version", "strict_suspect", "allow_unassessed",
                       "allowed_hosts", "condition",
                       "detection_not_prevention"}, "gate")
    expected_gate = 5 if current else 4
    expected_detection_only = not current
    if type(gate["version"]) is not int \
            or gate["version"] != expected_gate \
            or gate["strict_suspect"] is not (True if legacy else False) \
            or gate["allow_unassessed"] is not False \
            or gate["detection_not_prevention"] is not expected_detection_only \
            or gate["condition"] is not None:
        _refuse(
            f"gate is not the canonical version-{expected_gate} policy")
    hosts = gate["allowed_hosts"]
    if not isinstance(hosts, list) or not hosts \
            or hosts != sorted(set(hosts)) \
            or not all(isinstance(host, str) and host for host in hosts):
        _refuse("gate allowed-host set is invalid")

    authority = document["analysis_authority"]
    _exact_keys(authority, {"egress_detector", "native_scanners"},
                "analysis authority")
    detector = authority["egress_detector"]
    _exact_keys(detector, {"path", "bytes", "sha256"}, "egress detector")
    if detector["path"] != "benchmark/r2t/egress.py" \
            or type(detector["bytes"]) is not int or detector["bytes"] <= 0 \
            or not _is_sha256(detector["sha256"]):
        _refuse("egress detector authority is invalid")
    scanners = authority["native_scanners"]
    _exact_keys(scanners, {"n_files", "records_sha256", "files"},
                "native scanners")
    files = scanners["files"]
    if type(scanners["n_files"]) is not int or scanners["n_files"] <= 0 \
            or not isinstance(files, list) \
            or scanners["n_files"] != len(files) \
            or not _is_sha256(scanners["records_sha256"]) \
            or canonical_sha256(files) != scanners["records_sha256"]:
        _refuse("native scanner inventory digest/count differs")
    paths = []
    for index, row in enumerate(files):
        _exact_keys(row, {"path", "bytes", "sha256"},
                    f"native scanner file {index}")
        if not isinstance(row["path"], str) \
                or not row["path"].startswith("benchmark/r2t/agents/scanners/") \
                or type(row["bytes"]) is not int or row["bytes"] <= 0 \
                or not _is_sha256(row["sha256"]):
            _refuse(f"native scanner file {index} is invalid")
        paths.append(row["path"])
    if paths != sorted(set(paths)):
        _refuse("native scanner paths are not unique canonical order")

    inputs = document["inputs"]
    _exact_keys(inputs, {"candidate_run", "trajectory_root"}, "inputs")
    run = inputs["candidate_run"]
    _exact_keys(run, {"path", "bytes", "sha256"}, "candidate run")
    if not os.path.isabs(run["path"]) or type(run["bytes"]) is not int \
            or run["bytes"] <= 0 or not _is_sha256(run["sha256"]):
        _refuse("candidate-run content address is invalid")
    tree = inputs["trajectory_root"]
    _exact_keys(tree, {"path", "n_attempt_dirs", "attempt_dirs_sha256",
                       "n_files", "bytes", "records_sha256"},
                "trajectory root")
    if not os.path.isabs(tree["path"]):
        _refuse("trajectory root path is not absolute")
    for key in ("n_attempt_dirs", "n_files", "bytes"):
        if type(tree[key]) is not int or tree[key] <= 0:
            _refuse(f"trajectory root {key} is invalid")
    for key in ("attempt_dirs_sha256", "records_sha256"):
        if not _is_sha256(tree[key]):
            _refuse(f"trajectory root {key} is invalid")

    result = document["result"]
    _exact_keys(result, {"exit_code", "clean", "n_items", "n_assessed",
                         "n_unassessable", "n_no_trajectory",
                         "n_contaminated", "n_strict_suspects",
                         "n_raw_suspects", "n_attempt_dirs", "n_events",
                         "n_unrecognized_files", "stdout_bytes",
                         "stdout_sha256"}
                | ({"n_egress_attempts", "n_egress_retrieved"}
                   if current else set()), "result")
    integer_fields = set(result) - {"clean", "stdout_sha256"}
    if any(type(result[key]) is not int or result[key] < 0
           for key in integer_fields):
        _refuse("result contains an invalid count")
    # Completeness is still absolute; cleanliness is now recorded rather than
    # required.  `n_contaminated` must equal the named list, so a document
    # cannot claim a count its item list does not carry.
    if result["n_items"] <= 0 \
            or result["n_assessed"] != result["n_items"] \
            or result["n_unassessable"] != 0 \
            or result["n_no_trajectory"] != 0 \
            or result["n_attempt_dirs"] != tree["n_attempt_dirs"] \
            or result["stdout_bytes"] <= 0 \
            or not _is_sha256(result["stdout_sha256"]):
        _refuse("result does not prove a complete strict run")
    if legacy:
        # /1 sealed only when nothing was found at all, suspects included.
        if result["exit_code"] != 0 or result["clean"] is not True \
                or result["n_contaminated"] != 0 \
                or result["n_strict_suspects"] != 0:
            _refuse("a /1 attestation does not prove a clean strict run")
    elif result["n_contaminated"] != len(items) \
            or result["clean"] is not (not items) \
            or (result["exit_code"] == 0) is not (not items):
        _refuse("result counts disagree with the named contaminated items")
    if current:
        if result["n_egress_attempts"] < len(attempted) \
                or bool(result["n_egress_attempts"]) != bool(attempted) \
                or bool(result["n_egress_retrieved"]) != bool(items) \
                or result["n_egress_retrieved"] < len(items) \
                or len(attempted) > result["n_items"]:
            _refuse(
                "proxy attempt/retrieval counts disagree with named items")
    sealed = dict(document)
    claimed = sealed.pop("attestation_sha256")
    if not _is_sha256(claimed) or canonical_sha256(sealed) != claimed:
        _refuse("attestation self-digest differs")
    return {
        "schema": document["schema"],
        "status": document["status"],
        "contaminated_items": list(items),
        "attempted_items": list(attempted),
        "n_egress_attempts": (result["n_egress_attempts"] if current else 0),
        "n_egress_retrieved": (
            result["n_egress_retrieved"] if current else 0),
        "attestation_sha256": claimed,
        "candidate_run_sha256": run["sha256"],
        "trajectory_records_sha256": tree["records_sha256"],
        "n_items": result["n_items"],
        "n_events": result["n_events"],
    }


def _replay_historical_external_bytes(document: dict) -> None:
    """Re-bind /1-/2 candidate and tree bytes without rescoring their gate."""
    run = document["inputs"]["candidate_run"]
    if _file_fact(run["path"], label="historical candidate run") \
            != {"bytes": run["bytes"], "sha256": run["sha256"]}:
        _refuse("historical candidate run bytes differ from attestation")

    root = document["inputs"]["trajectory_root"]
    attempts = []
    try:
        with open(run["path"], encoding="utf-8") as handle:
            lines = list(handle)
    except OSError as exc:
        _refuse(f"cannot read historical candidate run: {exc}")
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            _refuse(f"historical candidate line {number} is not JSON: {exc}")
        if not isinstance(row, dict) or not isinstance(row.get("item_id"), str) \
                or not row["item_id"]:
            _refuse(f"historical candidate line {number} has no item_id")
        metadata = row.get("metadata")
        trajectory = metadata.get("trajectory") \
            if isinstance(metadata, dict) else None
        recorded = trajectory.get("dir") \
            if isinstance(trajectory, dict) \
            and isinstance(trajectory.get("dir"), str) else None
        condition = row.get("condition") \
            if isinstance(row.get("condition"), str) else None
        attempts.extend(egress.trajectory_dirs(
            row["item_id"], root["path"], condition, recorded))
    inventory = _tree_inventory(root["path"], attempts)
    expected = {name: root[name] for name in inventory}
    if inventory != expected:
        _refuse("historical trajectory inventory differs from attestation")


#: Recorded/live authority pairs already reported, so a command that replays
#: the same document several times says it once.  Output hygiene, not a check.
_DISCLOSED_DRIFT: set = set()


def _disclose_detector_drift(recorded: dict, live: dict) -> None:
    """Say, once, that the verifying tree is not the tree that sealed this.

    Nothing is decided here: the recorded block is provenance a reader can
    join, and what makes the verdict trustworthy is the rebuild against the
    live detector under the enforced gate version and rules digest.  stderr,
    because `scripts/build_egress_attestation.py --check` and `verify-receipt`
    print their summaries on stdout and runbooks parse that stream.
    """
    key = (recorded["egress_detector"]["sha256"],
           live["egress_detector"]["sha256"],
           recorded["native_scanners"]["records_sha256"],
           live["native_scanners"]["records_sha256"])
    if key in _DISCLOSED_DRIFT:
        return
    _DISCLOSED_DRIFT.add(key)
    recorded_files = {row["path"]: (row["bytes"], row["sha256"])
                      for row in recorded["native_scanners"]["files"]}
    live_files = {row["path"]: (row["bytes"], row["sha256"])
                  for row in live["native_scanners"]["files"]}
    n_scanners = sum(recorded_files.get(path) != live_files.get(path)
                     for path in set(recorded_files) | set(live_files))
    print(f"note: egress detector recorded at {key[0][:12]}, verifying at "
          f"{key[1][:12]} ({n_scanners} scanner file(s) also differ); gate "
          f"version {egress.EGRESS_GATE_VERSION} and detection rules "
          f"{egress.DETECTION_RULES_DIGEST[:12]} still enforced",
          file=sys.stderr, flush=True)


def _enforce_detection_rules() -> None:
    """The live detector must apply the reviewed rule set, or no replay of it
    means anything.  Live-versus-reviewed: no /3 document carries a rules
    digest, so this proves the verifying tree runs the pinned rules, not that
    it runs the rules that produced the document."""
    pinned = versions.component("egress_gate").get("detection_rules_digest")
    if egress.DETECTION_RULES_DIGEST != pinned:
        _refuse(f"live egress detection rules digest "
                f"{egress.DETECTION_RULES_DIGEST} differs from the reviewed "
                f"VERSIONS.yml pin {pinned}")


def replay_attestation(document: dict) -> dict:
    """Replay /3 against the live detector's rules; retain /1 and /2
    validation without prospective rescoring.  The recorded detector and
    scanner bytes are provenance: drift from the verifying tree is disclosed,
    not refused."""
    summary = validate_attestation(document)
    if document["schema"] != SCHEMA:
        # The approved rule is prospective.  Rebuilding an old document with
        # required proxy journals it could never have recorded would relabel
        # history, not validate it.  Result-ledger verification separately
        # binds its candidate and trajectory bytes to the preserved document.
        _replay_historical_external_bytes(document)
        return summary
    _enforce_detection_rules()
    rebuilt = build_attestation(
        document["inputs"]["candidate_run"]["path"],
        document["inputs"]["trajectory_root"]["path"],
        allowed_hosts=document["gate"]["allowed_hosts"],
        condition=document["gate"]["condition"])
    recorded = document["analysis_authority"]
    if rebuilt["analysis_authority"] != recorded:
        _disclose_detector_drift(recorded, rebuilt["analysis_authority"])
        rebuilt["analysis_authority"] = recorded
        rebuilt.pop("attestation_sha256")
        rebuilt["attestation_sha256"] = canonical_sha256(rebuilt)
    if rebuilt != document:
        _refuse("replayed strict egress evidence differs from attestation")
    return validate_attestation(rebuilt)


def selftest() -> int:
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail else ""))
        ok = ok and bool(condition)

    def refused(fn, needle="REFUSED:"):
        try:
            fn()
        except EgressAttestationRefused as exc:
            return needle in str(exc)
        return False

    with tempfile.TemporaryDirectory(prefix="r2t_egress_attest_") as root:
        attempt = os.path.join(root, "c3", "item")
        os.makedirs(os.path.join(attempt, "events"))
        event = os.path.join(attempt, "events", "one.json")
        with open(event, "w", encoding="utf-8") as handle:
            handle.write("{}\n")
        inventory = _tree_inventory(root, [attempt])
        check("trajectory inventory is deterministic and content-addressed",
              inventory["n_attempt_dirs"] == 1
              and inventory["n_files"] == 1
              and inventory["bytes"] == 3
              and _is_sha256(inventory["records_sha256"]))
        inventory2 = _tree_inventory(root, [attempt, attempt])
        check("duplicate detector roots do not double-count evidence",
              inventory2 == inventory)
        link = os.path.join(attempt, "linked.json")
        os.symlink(event, link)
        check("a symlink in preserved evidence is refused",
              refused(lambda: _tree_inventory(root, [attempt]), "symlink"))

    def prospective_fixture(root: str, item_id: str, *, journal,
                            row_count: int, host: str = "github.com",
                            output: str = "fatal: unable to access remote: "
                                          "HTTP 403 Forbidden",
                            extra_outputs: tuple = ()) -> tuple:
        trajectory_root = os.path.join(root, "items")
        attempt = os.path.join(trajectory_root, item_id, "trajectory")
        conversation = os.path.join(attempt, "conv")
        os.makedirs(conversation)
        outputs = (output,) + extra_outputs
        for index, response in enumerate(outputs):
            egress._terminal(
                conversation, 1 + 2 * index,
                f"git clone https://{host}/owner/repo.git checkout-{index}",
                response)
        if journal is not None:
            with open(os.path.join(attempt, JOURNAL_RELATIVE),
                      "w", encoding="utf-8") as handle:
                json.dump(journal, handle, sort_keys=True)
        run_path = os.path.join(root, "run.jsonl")
        row = {
            "item_id": item_id,
            "metadata": {
                "egress_blocked_attempts": row_count,
                "trajectory": {
                    "present": True,
                    "dir": attempt,
                    "n_events": 2 * len(outputs),
                    "conversations": ["conv"],
                },
            },
        }
        with open(run_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
        return run_path, trajectory_root

    # /3's five prospective facts: empty/non-empty journals are required,
    # blocked attempts remain clean and counted, the row count must join, and
    # an unaccounted affirmative retrieval remains contamination.
    with tempfile.TemporaryDirectory(prefix="r2t_egress_v3_") as root:
        blocked_id = "blocked-item"
        blocked = journal_document(
            [{"host": "github.com", "port": 443}])
        run_path, trajectory_root = prospective_fixture(
            root, blocked_id, journal=blocked, row_count=1)
        document = build_attestation(
            run_path, trajectory_root, allowed_hosts=["api.deepseek.com"])
        summary = validate_attestation(document)
        check("a journaled zero-body 403 is clean but disclosed",
              document["schema"] == SCHEMA
              and document["status"] == "clean"
              and document["gate"]["detection_not_prevention"] is False
              and summary["attempted_items"] == [blocked_id]
              and summary["n_egress_attempts"] == 1
              and summary["n_egress_retrieved"] == 0)
        detection_only = copy.deepcopy(document)
        detection_only["gate"]["detection_not_prevention"] = True
        detection_only.pop("attestation_sha256")
        detection_only["attestation_sha256"] = \
            canonical_sha256(detection_only)
        check("a /3 attestation cannot claim detection instead of proxy "
              "prevention",
              refused(lambda: validate_attestation(detection_only),
                      "canonical version-5 policy"))

        policy = egress.Policy(allow=frozenset({"api.deepseek.com"}))
        scanned = egress.scan_run(run_path, trajectory_root, policy)
        adjusted, attempts, _items = _join_proxy_journals(run_path, scanned)
        output = io.StringIO()
        egress.gate(run_path, trajectory_root, policy, out=output,
                    precomputed=adjusted, proxy_attempts=attempts)
        check("gate output reports the blocked target and attempt count",
              "proxy blocks : 1 rejected CONNECT attempt(s)" in output.getvalue()
              and "github.com:443 x1" in output.getvalue())

        # Replay after the section-17 amendment: the gate version and the
        # rules digest are enforced, every scored field is an exact equality
        # against the rebuild, and the recorded detector/scanner bytes are
        # provenance whose drift is said once on stderr.
        def replayed(doc):
            captured = io.StringIO()
            with contextlib.redirect_stderr(captured):
                summary = replay_attestation(doc)
            return summary, captured.getvalue()

        def resealed(doc):
            doc.pop("attestation_sha256")
            doc["attestation_sha256"] = canonical_sha256(doc)
            return doc

        summary, note = replayed(document)
        check("a /3 document sealed by the verifying tree replays silently",
              summary["schema"] == SCHEMA and note == "")
        drifted = copy.deepcopy(document)
        drifted["analysis_authority"]["egress_detector"]["bytes"] += 787
        drifted["analysis_authority"]["egress_detector"]["sha256"] = "1" * 64
        resealed(drifted)
        summary, note = replayed(drifted)
        expected_tail = (
            f"(0 scanner file(s) also differ); gate version "
            f"{egress.EGRESS_GATE_VERSION} and detection rules "
            f"{egress.DETECTION_RULES_DIGEST[:12]} still enforced\n")
        check("a recorded detector differing from the live tree replays with "
              "exactly one stderr note",
              summary["status"] == "clean"
              and note.startswith("note: egress detector recorded at "
                                  "111111111111, verifying at ")
              and note.endswith(expected_tail)
              and note.count("\n") == 1, repr(note))
        _summary, note = replayed(drifted)
        check("replaying the same drifted document again says nothing",
              note == "", repr(note))
        scanner_drift = copy.deepcopy(document)
        scanners = scanner_drift["analysis_authority"]["native_scanners"]
        scanners["files"][0]["bytes"] += 5
        scanners["files"][0]["sha256"] = "2" * 64
        scanners["records_sha256"] = canonical_sha256(scanners["files"])
        resealed(scanner_drift)
        summary, note = replayed(scanner_drift)
        check("a recorded scanner file differing from the live tree replays "
              "with a note that counts it",
              summary["status"] == "clean"
              and "(1 scanner file(s) also differ)" in note
              and note.count("\n") == 1, repr(note))

        live_digest = egress.DETECTION_RULES_DIGEST
        altered_rules = tuple(
            (name, value + ("host.invalid",)) if name == "_LOOPBACK"
            else (name, value) for name, value in egress.DETECTION_RULES)
        egress.DETECTION_RULES_DIGEST = \
            egress.detection_rules_digest(altered_rules)
        try:
            check("a live rule table differing from the reviewed pin refuses "
                  "and names the rules digest",
                  egress.DETECTION_RULES_DIGEST != live_digest
                  and refused(lambda: replay_attestation(document),
                              egress.DETECTION_RULES_DIGEST))
        finally:
            egress.DETECTION_RULES_DIGEST = live_digest

        differs = "replayed strict egress evidence differs from attestation"
        moved_stdout = copy.deepcopy(document)
        moved_stdout["result"]["stdout_sha256"] = "3" * 64
        moved_count = copy.deepcopy(document)
        moved_count["result"]["n_events"] += 1
        moved_items = copy.deepcopy(document)
        moved_items["status"] = "contaminated"
        moved_items["contaminated_items"] = [blocked_id]
        moved_items["result"].update(
            n_contaminated=1, n_egress_retrieved=1, exit_code=1, clean=False)
        check("a /3 document whose printed output, a count, or the named "
              "items differ from the rebuild still refuses",
              all(refused(lambda doc=doc: replay_attestation(resealed(doc)),
                          differs)
                  for doc in (moved_stdout, moved_count, moved_items)))
        old_gate = copy.deepcopy(document)
        old_gate["gate"]["version"] = egress.EGRESS_GATE_VERSION - 1
        check("a /3 document not sealed under the live gate version refuses "
              "at replay",
              refused(lambda: replay_attestation(resealed(old_gate)),
                      "canonical version-5 policy"))

        historical = copy.deepcopy(document)
        historical["schema"] = V2_SCHEMA
        historical.pop("attempted_items")
        historical["gate"]["version"] = 4
        historical["gate"]["detection_not_prevention"] = True
        historical["result"].pop("n_egress_attempts")
        historical["result"].pop("n_egress_retrieved")
        historical.pop("attestation_sha256")
        historical["attestation_sha256"] = canonical_sha256(historical)
        check("a /2 replay re-binds external bytes without prospective "
              "rescoring",
              replay_attestation(historical)["schema"] == V2_SCHEMA)
        preventive_v2 = copy.deepcopy(historical)
        preventive_v2["gate"]["detection_not_prevention"] = False
        preventive_v2.pop("attestation_sha256")
        preventive_v2["attestation_sha256"] = canonical_sha256(preventive_v2)
        check("a historical /2 attestation cannot claim proxy prevention",
              refused(lambda: validate_attestation(preventive_v2),
                      "canonical version-4 policy"))
        absent = copy.deepcopy(historical)
        absent["inputs"]["candidate_run"]["path"] = \
            os.path.join(root, "absent.jsonl")
        absent["inputs"]["trajectory_root"]["path"] = \
            os.path.join(root, "absent-trajectories")
        absent.pop("attestation_sha256")
        absent["attestation_sha256"] = canonical_sha256(absent)
        check("a self-consistent /2 document cannot point at absent external "
              "evidence",
              refused(lambda: replay_attestation(absent),
                      "cannot stat historical candidate run"))

    with tempfile.TemporaryDirectory(prefix="r2t_egress_v3_empty_") as root:
        run_path, trajectory_root = prospective_fixture(
            root, "retrieved-item",
            journal=journal_document([]), row_count=0,
            output="Cloning into 'checkout'...\n"
                   "Receiving objects: 100% (2/2)",
            extra_outputs=("remote: Enumerating objects: 3\n"
                           "Receiving objects: 100% (3/3)",))
        document = build_attestation(
            run_path, trajectory_root, allowed_hosts=["api.deepseek.com"])
        check("affirmative retrieval not accounted by a proxy refusal remains "
              "contamination",
              document["status"] == "contaminated"
              and document["contaminated_items"] == ["retrieved-item"]
              and document["attempted_items"] == []
              and document["result"]["n_egress_retrieved"] == 2)
        zero_retrieved = copy.deepcopy(document)
        zero_retrieved["result"]["n_egress_retrieved"] = 0
        zero_retrieved.pop("attestation_sha256")
        zero_retrieved["attestation_sha256"] = \
            canonical_sha256(zero_retrieved)
        check("a /3 contaminated item cannot claim zero retrieved responses",
              refused(lambda: validate_attestation(zero_retrieved),
                      "counts disagree"))

    with tempfile.TemporaryDirectory(prefix="r2t_egress_v3_unjoined_") as root:
        run_path, trajectory_root = prospective_fixture(
            root, "unjoined-failure",
            journal=journal_document([]), row_count=0)
        check("an unjournaled nonaffirmative violation is unassessable, not "
              "contamination",
              refused(lambda: build_attestation(
                  run_path, trajectory_root,
                  allowed_hosts=["api.deepseek.com"]),
                  "could not assess every row"))

    with tempfile.TemporaryDirectory(prefix="r2t_egress_v3_conflict_") as root:
        run_path, trajectory_root = prospective_fixture(
            root, "same-host-retrieval",
            journal=journal_document(
                [{"host": "github.com", "port": 443}]), row_count=1,
            output="Cloning into 'checkout'...\n"
                   "Receiving objects: 100% (2/2)")
        document = build_attestation(
            run_path, trajectory_root, allowed_hosts=["api.deepseek.com"])
        check("a journal cannot launder affirmative retrieval from the same "
              "host",
              document["status"] == "contaminated"
              and document["attempted_items"] == ["same-host-retrieval"]
              and document["contaminated_items"]
              == ["same-host-retrieval"]
              and document["result"]["n_egress_retrieved"] == 1)

    with tempfile.TemporaryDirectory(prefix="r2t_egress_v3_join_") as root:
        run_path, trajectory_root = prospective_fixture(
            root, "count-mismatch",
            journal=journal_document(
                [{"host": "github.com", "port": 443}]), row_count=0)
        check("a row count inconsistent with its journal refuses",
              refused(lambda: build_attestation(
                  run_path, trajectory_root,
                  allowed_hosts=["api.deepseek.com"]), "records 0"))

    with tempfile.TemporaryDirectory(prefix="r2t_egress_v3_missing_") as root:
        run_path, trajectory_root = prospective_fixture(
            root, "missing-journal", journal=None, row_count=0)
        check("a missing required journal is unassessable and refuses",
              refused(lambda: build_attestation(
                  run_path, trajectory_root,
                  allowed_hosts=["api.deepseek.com"]),
                  "required proxy journal"))

    with tempfile.TemporaryDirectory(prefix="r2t_egress_v3_bad_") as root:
        run_path, trajectory_root = prospective_fixture(
            root, "malformed-journal",
            journal={"schema": JOURNAL_SCHEMA,
                     "n_attempts": 1, "attempts": []}, row_count=1)
        check("a malformed journal is unassessable and refuses",
              refused(lambda: build_attestation(
                  run_path, trajectory_root,
                  allowed_hosts=["api.deepseek.com"]),
                  "count differs"))

    # /2's own invariants. These are checked before the structural ones, so a
    # skeleton document reaches them; the point is that a status and the items
    # it names can never drift apart, which is the whole basis on which a
    # contaminated row is refused a pass without being deleted.
    def skeleton(**over):
        doc = {"schema": V2_SCHEMA, "status": "clean",
               "contaminated_items": [],
               "gate": {}, "analysis_authority": {}, "inputs": {},
               "result": {}, "attestation_sha256": "0" * 64}
        doc.update(over)
        return doc

    def legacy_skeleton(**over):
        doc = {k: v for k, v in skeleton().items()
               if k != "contaminated_items"}
        doc["schema"] = LEGACY_SCHEMA
        doc.update(over)
        return doc

    check("a /1 document claiming contamination is refused outright",
          refused(lambda: validate_attestation(
              legacy_skeleton(status="contaminated")),
              "only in its clean form"))
    check("an unknown schema is not read as either version",
          refused(lambda: validate_attestation(
              skeleton(schema="r2t.egress-attestation/4")),
              "not /1, /2, or /3"))
    check("a document without the item list is refused, not defaulted",
          refused(lambda: validate_attestation(
              {k: v for k, v in skeleton().items()
               if k != "contaminated_items"}), "differ"))
    check("claiming contamination without naming a row refuses",
          refused(lambda: validate_attestation(skeleton(
              status="contaminated")), "disagree"))
    check("naming a row without claiming contamination refuses",
          refused(lambda: validate_attestation(skeleton(
              contaminated_items=["a"])), "disagree"))
    check("an unsorted or duplicated item list refuses",
          refused(lambda: validate_attestation(skeleton(
              status="contaminated", contaminated_items=["b", "a"])),
              "sorted unique")
          and refused(lambda: validate_attestation(skeleton(
              status="contaminated", contaminated_items=["a", "a"])),
              "sorted unique"))
    check("an unknown status is refused",
          refused(lambda: validate_attestation(skeleton(status="dirty")),
                  "status is invalid"))

    # The one real /1 document in the tree, validated as itself. `/2` changed
    # what SEALS; it must not change what an already-published arm's evidence
    # means, and this is the artifact that would notice.
    legacy_path = os.path.join(RELEASE_DIR, "legacy_consistency", "cell1_coreshop_aider.egress.json")
    if os.path.isfile(legacy_path):
        with open(legacy_path, encoding="utf-8") as handle:
            legacy_doc = json.load(handle)
        summary = validate_attestation(legacy_doc)
        check("the published /1 arm's sealed evidence still validates as /1",
              legacy_doc["schema"] == LEGACY_SCHEMA
              and summary["schema"] == LEGACY_SCHEMA
              and summary["status"] == "clean"
              and summary["contaminated_items"] == [])
        check("a /1 document may not carry /2's item list",
              refused(lambda: validate_attestation(
                  {**legacy_doc, "contaminated_items": []}), "differ"))
        preventive_v1 = copy.deepcopy(legacy_doc)
        preventive_v1["gate"]["detection_not_prevention"] = False
        preventive_v1.pop("attestation_sha256")
        preventive_v1["attestation_sha256"] = canonical_sha256(preventive_v1)
        check("a historical /1 attestation cannot claim proxy prevention",
              refused(lambda: validate_attestation(preventive_v1),
                      "canonical version-4 policy"))
    else:
        check("the published /1 arm's sealed evidence is present", False,
              legacy_path)

    authority = _source_authority()
    check("analysis authority records detector and scanner source bytes",
          _is_sha256(authority["egress_detector"]["sha256"])
          and authority["native_scanners"]["n_files"] >= 2)
    print("\n" + ("ALL PASS (egress_attestation)" if ok
                   else "FAILURES (egress_attestation)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
