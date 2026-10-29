"""Materialisation audits and validation reports for mutation assets.

The writer half of `data/mutation_attestation.py` (wave M5): the private
scratch and staged-copy discipline a producer runs under, the reserved
output files it may write, the apply/parse/restore audit of a population
against a real engine, and the legacy and native validation reports.
Every join it validates against -- the manifest, map, index, binding and
saved-report validators -- stays in `data/mutation_attestation.py`, which this
module imports; nothing there imports this.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from typing import Callable, Iterable, Optional

from ..data import mutation as M
from ..data.mutation_attestation import (AUDIT_SCHEMA, DISPOSABLE_MARKER,
                                   MaterialisationAuditRefused,
                                   MutationAssetRefused, REPOSITORY_ROOT,
                                   _audit_roots, _offline_git_env,
                                   _read_json_object, _refuse, audit_digest,
                                   build_map_artifact, canonical_sha256,
                                   coverage_from_rows,
                                   derive_boundary_scored_manifest,
                                   derive_raw_equals_scored_manifest,
                                   expected_runtime_parser,
                                   legacy_consistency,
                                   legacy_engine_source_bindings, load_jsonl,
                                   load_release_ids, sha256_file,
                                   validate_asset_index,
                                   validate_index_binding,
                                   validate_legacy_engine_source_bindings,
                                   validate_manifest, validate_map,
                                   validate_preserved_file)
DISPOSABLE_MARKER_CONTENT = "r2t disposable mutation audit\n"

#: The document `php/mutate_argv.php` reads, and the file name it is written
#: under inside the audit's own private scratch.  It exists because the
#: owner's Docker authority refuses an EMPTY argv token and a deletion-shaped
#: mutant (`RemoveNegation`: `!` -> ``) has one; see that shim's header.
APPLIER_ARGV_SCHEMA = "r2t.mutation-applier-argv/1"
APPLIER_ARGV_BASENAME = "argv.json"
APPLIER_SHIM_BASENAME = "mutate_argv.php"


def create_private_scratch(root: str, relative: str) -> str:
    """Create a fresh scratch directory without traversing symlink parents."""
    root = os.path.abspath(root)
    if os.path.islink(root) or not os.path.isdir(root) \
            or os.path.realpath(root) != root:
        _refuse("scratch root must be a canonical non-symlink directory")
    relative = os.path.normpath(relative)
    if os.path.isabs(relative) or relative in {"", ".", ".."} \
            or relative.startswith(".." + os.sep):
        _refuse(f"scratch path must be a contained relative directory: "
                f"{relative!r}")
    current = root
    parts = relative.split(os.sep)
    for index, component in enumerate(parts):
        current = os.path.join(current, component)
        final = index == len(parts) - 1
        if os.path.lexists(current):
            if final:
                _refuse(f"scratch already exists: {current}")
            if os.path.islink(current) or not os.path.isdir(current) \
                    or os.path.realpath(current) != current:
                _refuse(f"scratch parent is not a canonical directory: "
                        f"{current}")
            continue
        try:
            os.mkdir(current, 0o700)
        except OSError as exc:
            _refuse(f"cannot create scratch directory {current}: {exc}")
        if os.path.islink(current) or not os.path.isdir(current) \
                or os.path.realpath(current) != current:
            _refuse(f"created scratch path is not canonical: {current}")
    return current


def stage_preserved_file(source: str, destination: str,
                         expected_sha256: str, *,
                         label: str = "producer") -> str:
    """Copy one authenticated file to a fresh path and re-authenticate it.

    Producers run from staged copies.  Checking only the live source leaves a
    check/copy race in which different bytes can reach the runtime while the
    resulting envelope still repeats the pinned revision constant.  The
    destination is created exclusively (and never through a symlink), then
    hashed against the same authority digest before it can be executed.
    """
    source = os.path.abspath(source)
    if os.path.realpath(source) != source:
        _refuse(f"{label} source is reached through a symlink: {source}")
    validate_preserved_file(source, expected_sha256,
                            label=f"{label} source")
    destination = os.path.abspath(destination)
    parent = os.path.dirname(destination)
    if os.path.islink(parent) or not os.path.isdir(parent) \
            or os.path.realpath(parent) != parent:
        _refuse(f"staged {label} parent must be a canonical non-symlink "
                f"directory: {parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(destination, flags, 0o600)
    except OSError as exc:
        _refuse(f"cannot reserve fresh staged {label} {destination}: {exc}")
    try:
        with open(source, "rb") as src, os.fdopen(fd, "wb") as dst:
            fd = -1
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        actual = validate_preserved_file(
            destination, expected_sha256, label=f"staged {label}")
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(destination)
        except OSError:
            pass
        raise
    return actual


def _check_output_destination(path: str,
                              input_paths: Iterable[str]) -> str:
    if not isinstance(path, str) or not path:
        _refuse("an output path is required")
    absolute = os.path.abspath(path)
    parent = os.path.dirname(absolute)
    if not os.path.isdir(parent):
        _refuse(f"output parent does not exist: {parent}")
    if os.path.realpath(parent) != parent:
        _refuse(f"output path traverses a symlinked parent: {path}")
    if os.path.lexists(absolute):
        _refuse(f"output already exists and will not be replaced: {path}")
    output_real = os.path.realpath(absolute)
    for input_path in input_paths:
        if not input_path:
            continue
        input_absolute = os.path.abspath(input_path)
        input_real = os.path.realpath(input_absolute)
        if absolute == input_absolute or output_real == input_real:
            _refuse(f"output aliases an input: {path}")
    return absolute


def _open_reserved_output(path: str, absolute: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(absolute, flags, 0o600)
    except FileExistsError:
        _refuse(f"output appeared while being reserved: {path}")
    except OSError as exc:
        _refuse(f"cannot reserve output {path}: {exc}")


def reserve_output(path: str, *, input_paths: Iterable[str] = ()) -> int:
    """Exclusively reserve a fresh, non-aliased regular output path.

    The returned descriptor stays owned by the caller until
    :func:`write_reserved_json` writes and closes it.  Refusing pre-existing
    paths is intentional: validation evidence is immutable and a typo must
    never replace an input or an earlier report.
    """
    absolute = _check_output_destination(path, input_paths)
    return _open_reserved_output(path, absolute)


def reserve_outputs(paths: Iterable[str], *,
                    input_paths: Iterable[str] = ()) -> list[int]:
    """Preflight every output before reserving any of a related set."""
    outputs = list(paths)
    if not outputs:
        _refuse("at least one output path is required")
    all_inputs = list(input_paths)
    absolutes: list[str] = []
    for index, path in enumerate(outputs):
        other_outputs = outputs[:index] + outputs[index + 1:]
        absolutes.append(_check_output_destination(
            path, all_inputs + other_outputs))
    # O_EXCL still closes the race after the all-target preflight.  A race can
    # leave an earlier zero-byte reservation, but can never overwrite data.
    descriptors: list[int] = []
    for path, absolute in zip(outputs, absolutes):
        descriptors.append(_open_reserved_output(path, absolute))
    return descriptors


def write_reserved_json(fd: int, value: dict) -> None:
    """Write one JSON document to an already exclusively reserved output."""
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(value, fh, indent=1, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())


def _line_offset(data: bytes, line: int, column: int) -> int:
    starts = [0]
    starts.extend(index + 1 for index, value in enumerate(data) if value == 10)
    if line < 1 or line > len(starts) or column < 1:
        _refuse(f"source position {line}:{column} is outside the file")
    offset = starts[line - 1] + column - 1
    if offset > len(data):
        _refuse(f"source position {line}:{column} is outside the file")
    return offset


def _source_set_digest(files: dict[str, bytes]) -> str:
    return canonical_sha256([
        {"file": path, "sha256": hashlib.sha256(data).hexdigest()}
        for path, data in sorted(files.items())])


def _snapshot_tree(root: str, bounded_roots: Iterable[str]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for rel_root in bounded_roots:
        rel_root = M.normalise_path(rel_root).rstrip("/")
        full_root = os.path.abspath(os.path.join(root, rel_root))
        if os.path.commonpath((root, full_root)) != root:
            _refuse(f"audit source root escapes workspace: {rel_root}")
        if not os.path.isdir(full_root):
            _refuse(f"bounded audit source root does not exist: {rel_root}")
        for directory, dirnames, filenames in os.walk(full_root):
            dirnames.sort()
            filenames.sort()
            for name in dirnames:
                full = os.path.join(directory, name)
                if os.path.islink(full):
                    rel = os.path.relpath(full, root).replace(os.sep, "/")
                    _refuse(f"bounded source set contains symlink {rel}")
            for name in filenames:
                full = os.path.join(directory, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if os.path.islink(full):
                    _refuse(f"bounded source set contains symlink {rel}")
                if not os.path.isfile(full):
                    _refuse(f"bounded source set contains non-file {rel}")
                with open(full, "rb") as fh:
                    files[rel] = fh.read()
    return files


def _tree_stats(root: str, bounded_roots: Iterable[str]) -> dict[str, tuple]:
    """Relevant lstat identity, intentionally excluding volatile timestamps."""
    stats: dict[str, tuple] = {}
    for rel_root in bounded_roots:
        full_root = os.path.join(root, rel_root)
        if not os.path.isdir(full_root):
            continue
        for directory, dirnames, filenames in os.walk(full_root):
            dirnames.sort()
            filenames.sort()
            for name in dirnames:
                full = os.path.join(directory, name)
                if os.path.islink(full):
                    rel = os.path.relpath(full, root).replace(os.sep, "/")
                    stats[rel] = ("symlink",)
            for name in filenames:
                full = os.path.join(directory, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                st = os.lstat(full)
                stats[rel] = (st.st_mode, st.st_uid, st.st_gid)
    return stats


def _source_lstat_digest(stats: dict[str, tuple]) -> str:
    rows = []
    for rel, value in sorted(stats.items()):
        if len(value) != 3 or not all(type(part) is int for part in value):
            _refuse(f"bounded source set has non-regular lstat entry {rel}")
        rows.append({"file": rel, "mode": value[0], "uid": value[1],
                     "gid": value[2]})
    return canonical_sha256(rows)


def _restore_audit_target(path: str, data: bytes,
                          wanted: tuple[int, int, int]) -> None:
    """Restore one target's bytes plus mode/uid/gid without following links."""
    if len(wanted) != 3 or not stat.S_ISREG(wanted[0]):
        _refuse(f"invalid pristine lstat authority for {path}")
    try:
        from ..bench.mutation_run import MutationAborted, _restore_bytes_and_lstat
        _restore_bytes_and_lstat(
            path, data,
            {"mode": wanted[0], "uid": wanted[1], "gid": wanted[2]},
            "materialisation audit cleanup")
    except MutationAborted as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))


def _overlapping_paths(left: str, right: str) -> bool:
    """True when either directory contains the other, or they are the same.

    Two audited trees that overlap are one tree wearing two names, and one
    worker's live mutation would then be another worker's collateral change.
    """
    try:
        common = os.path.commonpath((left, right))
    except ValueError:
        return False
    return common in (left, right)


def _collateral_changes(root: str, bounded_roots: Iterable[str],
                        pristine: dict[str, bytes],
                        pristine_stats: dict[str, tuple]) -> dict:
    now = _tree_stats(root, bounded_roots)
    added = sorted(set(now) - set(pristine))
    deleted = sorted(set(pristine) - set(now))
    changed: list[str] = []
    for rel in sorted(set(now) & set(pristine)):
        full = os.path.join(root, rel)
        if os.path.islink(full) or not os.path.isfile(full):
            changed.append(rel)
            continue
        with open(full, "rb") as fh:
            if (now[rel] != pristine_stats.get(rel)
                    or fh.read() != pristine[rel]):
                changed.append(rel)
    return {"added": added, "changed": changed, "deleted": deleted}


# Each checker process owns a read-only pristine image. Passing it once at
# process startup avoids serializing the complete source tree for every
# mutant. Mutation/apply/restore still belongs to the owning audit thread.
_COLLATERAL_PRISTINE = None
_COLLATERAL_STATS = None


def _init_collateral_checker(pristine, pristine_stats):
    global _COLLATERAL_PRISTINE, _COLLATERAL_STATS
    _COLLATERAL_PRISTINE = pristine
    _COLLATERAL_STATS = pristine_stats


def _check_collateral_in_process(root, roots):
    return _collateral_changes(root, roots, _COLLATERAL_PRISTINE,
                               _COLLATERAL_STATS)


def audit_population(manifest: dict, source_root: str,
                     apply_one: Callable[[dict, str], None],
                     parse_one: Callable[[dict, str], None],
                     *, parallel_roots: Iterable[str] = (),
                     worker_bind: Optional[Callable[[str], None]] = None
                     ) -> dict:
    """Apply, parse and restore every mutant using injected real operations.

    THE AUDITED SOURCE SET IS A FUNCTION OF THE MANIFEST.  An operator-
    supplied `bounded_roots` override used to sit here and is deliberately
    gone (review correction 10; plan §3 PR R2 item 3, second arm): every
    widening path is a path by which a completed attestation can name a
    source set the attested population does not live in, and the reader that
    has to catch that -- `validate_completed_audit_binding` -- can only
    recompute the roots when nothing but the manifest decides them.  The
    private helpers below still take a `roots` argument; it is always
    `_audit_roots(manifest)`.

    PARALLELISM (owner ruling, 2026-08-12: "parallelize k=16 if possible").
    One mutant at a time is not a stylistic choice here: a mutant is
    materialised INTO the audited tree and the collateral check after it
    asserts that NOTHING ELSE in the bounded source set moved.  Two live
    mutations in one tree make that assertion false, so k concurrent mutants
    require k trees.  `parallel_roots` names the additional disposable roots;
    each worker owns exactly one root for its whole life, and the walk
    REFUSES unless every root's pristine source set and lstat set are
    digest-identical to the primary's -- which is what keeps the single
    `source_set_sha256_before/after` pair literally true of every tree that
    was audited.  Every per-mutant check is the same code (`audit_one`) on
    both paths, and with no `parallel_roots` this is the sequential walk it
    always was, byte for byte.

    What parallelism DOES change, disclosed rather than hidden: (1) the
    document carries a `parallel_audit` block naming the root count and the
    mutants each root took -- absent entirely when k == 1; (2) the cumulative
    apply/restore chain any one tree survives is n/k long instead of n; and
    (3) IN A FAILED report the counters include work other workers had
    already started, where the sequential walk stops dead.  The failing
    mutant itself is always the EARLIEST FAILURE IN MANIFEST ORDER, never
    the first one to fail in wall-clock time.
    """
    facts = validate_manifest(manifest)
    root = os.path.abspath(source_root)
    roots = _audit_roots(manifest)
    pristine = _snapshot_tree(root, roots)
    pristine_stats = _tree_stats(root, roots)
    mutant_files = {M.normalise_path(m["file"]) for m in manifest["mutants"]}
    missing_files = sorted(mutant_files - set(pristine))
    if missing_files:
        _refuse(f"mutant files are outside the bounded source set: "
                f"{missing_files[:3]}")
    before_digest = _source_set_digest(pristine)
    before_lstat_digest = _source_lstat_digest(pristine_stats)
    worker_roots = [root]
    for value in parallel_roots:
        extra = os.path.abspath(value)
        if os.path.islink(extra) or not os.path.isdir(extra) \
                or os.path.realpath(extra) != extra:
            _refuse(f"parallel audit root is not a canonical directory: "
                    f"{extra}")
        if any(_overlapping_paths(extra, taken) for taken in worker_roots):
            _refuse(f"parallel audit root overlaps another audited tree: "
                    f"{extra}")
        if _source_set_digest(_snapshot_tree(extra, roots)) != before_digest \
                or _source_lstat_digest(_tree_stats(extra, roots)) \
                != before_lstat_digest:
            _refuse("parallel audit roots are not byte-identical trees")
        worker_roots.append(extra)
    n_roots = len(worker_roots)
    counters = {"attempted": 0, "applied": 0, "parse_valid": 0, "restored": 0}
    per_root = [0] * n_roots
    tally = threading.Lock()

    def report(status: str, *, failing_id=None, stage=None, error=None,
               collateral=None, after_root=None) -> dict:
        observed = after_root or root
        try:
            after_files = _snapshot_tree(observed, roots)
            after_digest = _source_set_digest(after_files)
            after_lstat_digest = _source_lstat_digest(
                _tree_stats(observed, roots))
        except MutationAssetRefused:
            after_digest = None
            after_lstat_digest = None
        document = {
            "schema": AUDIT_SCHEMA,
            "status": status,
            "manifest_digest": manifest["digest"],
            "engine": facts["engine"],
            "engine_version": facts["engine_version"],
            "parser": facts["parser"],
            "n_mutants": manifest["n"],
            "n_attempted": counters["attempted"],
            "n_applied": counters["applied"],
            "n_parse_valid": counters["parse_valid"],
            "n_restored": counters["restored"],
            "n_source_files": len(pristine),
            "bounded_roots": roots,
            "source_set_sha256_before": before_digest,
            "source_set_sha256_after": after_digest,
            "source_lstat_sha256_before": before_lstat_digest,
            "source_lstat_sha256_after": after_lstat_digest,
            "failing_mutant_id": failing_id,
            "failure_stage": stage,
            "failure": error,
            "collateral": collateral or {
                "added": [], "changed": [], "deleted": []},
        }
        if n_roots > 1:
            document["parallel_audit"] = {
                "n_roots": n_roots,
                "mutants_by_root": list(per_root),
            }
        document["digest"] = audit_digest(document)
        return document

    collateral_executor = None

    def audit_one(mutant: dict, worker_root: str, slot: int):
        """One mutant's whole cycle, in one tree.  The only auditing body."""
        with tally:
            counters["attempted"] += 1
            per_root[slot] += 1
        rel = M.normalise_path(mutant["file"])
        target = os.path.join(worker_root, rel)
        original_file = pristine[rel]
        original_lstat = pristine_stats[rel]
        problem: Optional[BaseException] = None
        stage = "precondition"
        try:
            with open(target, "rb") as fh:
                current = fh.read()
            if current != original_file:
                _refuse(f"{rel} is not pristine before mutant {mutant['id']}")
            current_stat = os.lstat(target)
            if (current_stat.st_mode, current_stat.st_uid,
                    current_stat.st_gid) != original_lstat:
                _refuse(f"{rel} mode/uid/gid is not pristine before mutant "
                        f"{mutant['id']}")
            offset = _line_offset(current, mutant["start_line"],
                                  mutant["start_col"])
            original = mutant["original"].encode("utf-8")
            mutated = mutant["mutated"].encode("utf-8")
            if current[offset:offset + len(original)] != original:
                _refuse(f"mutant {mutant['id']} original bytes do not match")
            expected = (current[:offset] + mutated
                        + current[offset + len(original):])
            stage = "apply"
            apply_one(mutant, target)
            with tally:
                counters["applied"] += 1
            stage = "materialised_bytes"
            with open(target, "rb") as fh:
                materialised = fh.read()
            if materialised != expected or materialised == current:
                _refuse(f"mutant {mutant['id']} is not its exact non-identity "
                        "byte splice")
            stage = "materialised_lstat"
            materialised_stat = os.lstat(target)
            if (materialised_stat.st_mode, materialised_stat.st_uid,
                    materialised_stat.st_gid) != original_lstat:
                _refuse(f"mutant {mutant['id']} changed target mode/uid/gid")
            stage = "parse"
            parse_one(mutant, target)
            with tally:
                counters["parse_valid"] += 1
        except BaseException as exc:
            problem = exc
        finally:
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                _restore_audit_target(target, original_file, original_lstat)
                with open(target, "rb") as fh:
                    restored = fh.read()
                if restored != original_file:
                    raise MutationAssetRefused(
                        f"REFUSED: {rel} did not restore")
                with tally:
                    counters["restored"] += 1
            except BaseException as restore_exc:
                problem = restore_exc
                stage = "restore"
        if collateral_executor is None:
            collateral = _collateral_changes(
                worker_root, roots, pristine, pristine_stats)
        else:
            # Await this exact root's full scan before its thread can claim
            # another mutant. Every per-mutant byte/lstat check is retained.
            collateral = collateral_executor.submit(
                _check_collateral_in_process, worker_root, roots).result()
        if any(collateral.values()) and problem is None:
            problem = MutationAssetRefused(
                "REFUSED: materialisation changed files outside its target")
            stage = "collateral"
        return problem, stage, collateral

    def refuse_mutant(mutant, stage, problem, collateral, worker_root):
        message = (str(problem) if isinstance(problem, MutationAssetRefused)
                   else f"REFUSED: {type(problem).__name__}: {problem}")
        failed = report("failed", failing_id=mutant["id"], stage=stage,
                        error=message, collateral=collateral,
                        after_root=worker_root)
        raise MaterialisationAuditRefused(message, failed) from None

    if n_roots == 1:
        if worker_bind is not None:
            worker_bind(root)
        for mutant in manifest["mutants"]:
            problem, stage, collateral = audit_one(mutant, root, 0)
            if problem is not None:
                refuse_mutant(mutant, stage, problem, collateral, root)
    else:
        import concurrent.futures
        import multiprocessing
        # Python threads contend heavily on the many small filesystem calls
        # in the complete collateral scan. Independent interpreters keep the
        # same scanner while allowing the already-isolated roots to progress.
        # Spawn avoids forking a live Docker/session thread or inherited locks.
        with concurrent.futures.ProcessPoolExecutor(
                max_workers=n_roots,
                mp_context=multiprocessing.get_context("spawn"),
                initializer=_init_collateral_checker,
                initargs=(pristine, pristine_stats)) as executor:
            collateral_executor = executor
            _audit_population_in_parallel(
                manifest, worker_roots, audit_one, refuse_mutant, worker_bind)

    collateral = {"added": [], "changed": [], "deleted": []}
    for worker_root in worker_roots:
        found = _collateral_changes(worker_root, roots, pristine,
                                    pristine_stats)
        for key in collateral:
            collateral[key] = sorted(set(collateral[key]) | set(found[key]))
    completed = report("complete", collateral=collateral)
    residue = [worker_root for worker_root in worker_roots[1:]
               if _source_set_digest(_snapshot_tree(worker_root, roots))
               != before_digest
               or _source_lstat_digest(_tree_stats(worker_root, roots))
               != before_lstat_digest]
    if any(collateral.values()) or residue \
            or completed["source_set_sha256_after"] != before_digest \
            or completed["source_lstat_sha256_after"] \
            != before_lstat_digest:
        message = "REFUSED: bounded source set differs after audit"
        completed["status"] = "failed"
        completed["failure_stage"] = "final_source_set"
        completed["failure"] = message
        completed["digest"] = audit_digest(completed)
        raise MaterialisationAuditRefused(message, completed)
    return completed


def _audit_population_in_parallel(manifest: dict, worker_roots: list,
                                  audit_one, refuse_mutant,
                                  worker_bind) -> None:
    """Deal the manifest to one worker per tree, collect in manifest order.

    The collector is what makes this an audit rather than a race.  Work is
    handed out in manifest order, and the failure the attestation reports is
    the earliest failing INDEX, not the first thread to raise -- so the same
    population and the same defect produce the same attestation whatever the
    machine's scheduling did that day.  A worker never abandons a mutant it
    started: `audit_one` restores in its own `finally`, and only then does
    the worker stop, so no tree is left dirty by the stop itself.
    """
    mutants = manifest["mutants"]
    state = {"next": 0, "failure": None, "error": None}
    dealer = threading.Lock()

    def claim():
        with dealer:
            failure = state["failure"]
            if state["error"] is not None \
                    or (failure is not None and state["next"] > failure[0]) \
                    or state["next"] >= len(mutants):
                return None
            index = state["next"]
            state["next"] += 1
            return index

    def record_failure(index, facts):
        with dealer:
            if state["failure"] is None or index < state["failure"][0]:
                state["failure"] = (index, facts)

    def record_error(exc):
        with dealer:
            if state["error"] is None:
                state["error"] = exc

    def work(slot: int, worker_root: str):
        try:
            if worker_bind is not None:
                worker_bind(worker_root)
            while True:
                index = claim()
                if index is None:
                    return
                mutant = mutants[index]
                problem, stage, collateral = audit_one(
                    mutant, worker_root, slot)
                if problem is not None:
                    record_failure(
                        index, (mutant, stage, problem, collateral,
                                worker_root))
                    return
        except BaseException as exc:                         # noqa: BLE001
            record_error(exc)

    threads = [
        threading.Thread(target=work, args=(slot, worker_root),
                         name=f"r2t-audit-{slot}", daemon=False)
        for slot, worker_root in enumerate(worker_roots)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    # An unexpected exception -- a tampered tree, an interrupt -- is never
    # shadowed by the routine mutant refusal another worker may also have
    # recorded: it means the walk stopped in a way the attestation cannot
    # describe, and it must reach the operator as itself.
    if state["error"] is not None:
        raise state["error"]
    if state["failure"] is not None:
        refuse_mutant(*state["failure"][1])


def _compiled_tree_sha256(classes: str) -> str:
    """Digest a javac output tree, rejecting links and non-regular entries."""
    rows = []
    for directory, dirnames, filenames in os.walk(classes):
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            full = os.path.join(directory, name)
            if os.path.islink(full) or not os.path.isdir(full):
                _refuse(f"compiled applier output contains unsafe directory "
                        f"{full}")
        for name in filenames:
            full = os.path.join(directory, name)
            if os.path.islink(full) or not os.path.isfile(full) \
                    or os.path.realpath(full) != full:
                _refuse(f"compiled applier output contains unsafe file {full}")
            rows.append({
                "file": os.path.relpath(full, classes).replace(os.sep, "/"),
                "sha256": sha256_file(full),
            })
    if not rows:
        _refuse("compiled applier produced no class files")
    return canonical_sha256(rows)


def _tool_identity(argv: list[str], what: str, *, timeout: int,
                   env: dict) -> str:
    cp = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                        env=env)
    identity = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
    if cp.returncode != 0 or not identity:
        _refuse(f"cannot identify compiled-applier {what}: "
                f"{identity[-400:]}")
    return " ".join(identity.split())


def _copy_disposable_roots(root: str, count: int) -> tuple[str, list[str]]:
    """Make ``count`` further disposable audit trees BESIDE the operator's.

    Beside, not in a host temp directory, and the substrate is the reason:
    track S's Sylius audit root is 341 MB on a tmpfs the operator sized for
    this, and 24 further copies of it are the 8.5 GB that tmpfs was sized
    for.  A copy made under TMPDIR would land on another filesystem, spend
    the host's disk instead, and then be audited at that filesystem's speed.
    Copying inside the root's own parent keeps a tmpfs copy on tmpfs.

    Each copy carries everything the walk needs because the copies are made
    AFTER the engine and the shim are staged: `vendor/`, `composer.lock`, the
    disposable marker and the audit's own private scratch all travel with the
    tree.  What makes a copy an AUDITABLE tree is `audit_population`, which
    refuses unless every one of them is a canonical, non-overlapping
    directory whose bounded source set and lstat set are digest-identical to
    the primary's -- the check that keeps the single
    `source_set_sha256_before/after` pair literally true of every tree.
    """
    scratch = tempfile.mkdtemp(prefix="r2t_php_audit_roots_",
                               dir=os.path.dirname(root))
    try:
        copies = []
        for index in range(count):
            destination = os.path.join(scratch, f"audit-root-{index + 1:03d}")
            shutil.copytree(root, destination, symlinks=True)
            copies.append(destination)
        return scratch, copies
    except BaseException:                                   # noqa: BLE001
        shutil.rmtree(scratch, ignore_errors=True)
        raise


@contextlib.contextmanager
def _php_audit_sessions(runner, worker_roots: list, *, interpreter: str,
                        timeout: int):
    """Open one session per audited tree; close and prove ALL of them absent.

    The single-session close protocol does not weaken as k grows (the Java
    route's `_java_audit_sessions` makes the same argument): whatever goes
    wrong -- a session that fails to open, an applier that refuses, a timeout
    mid-walk -- every container this function opened is force-removed and
    proved absent before the exception leaves it.  A tree left mounted
    read-write by a surviving container is exactly the hazard the audit's
    restoration evidence exists to exclude.
    """
    sessions: dict[str, object] = {}
    try:
        for worker_root in worker_roots:
            sessions[worker_root] = runner.open_isolated_php_session(
                workspace_host=worker_root, interpreter=interpreter,
                timeout=timeout)
        yield sessions
    finally:
        problems = []
        for worker_root, session in sessions.items():
            try:
                session.close()
            except BaseException as exc:                    # noqa: BLE001
                problems.append(
                    f"{worker_root}: {type(exc).__name__}: {exc}")
        if problems:
            raise RuntimeError(
                "REFUSED: PHP audit session containers could not all be "
                "proved absent: " + "; ".join(problems))


def audit_with_engine(manifest: dict, source_root: str,
                      *, timeout: int = 300,
                      engine_source_path: Optional[str] = None,
                      historical_engine_source: Optional[dict] = None,
                      runner=None,
                      expected_image_id: Optional[str] = None,
                      workers: int = 1) -> dict:
    """Run the real engine, gated to an explicitly marked disposable copy.

    WHERE THE ENGINE RUNS.  With no ``runner`` this is what it has always
    been: the applier is a HOST subprocess, and the host must therefore carry
    the interpreter the population was enumerated with.  No sprint host does
    for PHP -- server-nus has neither `php` nor `composer` -- so a Behat
    population could be built and mapped on the marshal host and then not be
    audited there at all, while the pool image three metres away has the
    exact interpreter the manifest names.

    ``runner`` closes that: the applier and the interpreter probe run INSIDE
    the pool's image, with the disposable copy bind-mounted at
    ``runner.workdir``, exactly as `mutation_java.audit_population_in_image`
    already does for Cucumber.  Every path the applier is TOLD about is
    rebuilt from ``workdir``; every path this process reads back afterwards
    -- the snapshots, the collateral check, the parse evidence, the lock
    re-authentication -- stays the host's, because the bind mount is the same
    directory.  So the report's fields keep their meanings and their
    producer: `bounded_roots`, `n_source_files` and
    `source_set_sha256_before/after` come from the same host walk, and
    `operator_gate.runtime_parser_identity` is still `composer.lock`'s.

    HOW THE APPLIER IS CARRIED, and how many trees.  Through a runner the
    applier is not a container per invocation: one long-lived session
    container is opened per audited tree and every invocation is a
    `docker exec` into it.  Track S measured the per-invocation shape at
    ~2.5 s per mutant in the Sylius image -- TWO container starts, the apply
    and the parse -- which is about 30 h for that population's 43,670
    mutants; an exec into a running container is 0.1-0.3 s.  ``workers``
    then does for this route what it already does for Java: k disposable
    copies of the one audit root, one session container each, the manifest
    dealt out so every mutant is attempted exactly once, and ONE report whose
    failure is the EARLIEST failing mutant in manifest order (see
    `audit_population`, which owns both semantics).  ``workers=1`` is one
    tree, one session, and the report the sequential walk wrote.

    ``historical_engine_source`` is the canonical historical-producer seam;
    it must be one exact Git binding from ``VERSIONS.yml`` and is materialised
    into a private temporary file before ordinary staging.  The lower-level
    ``engine_source_path`` seam is retained for independently preserved
    producer bytes and tests.  Frozen
    v1 populations bind a Git-attested producer blob while ``binding_for``
    necessarily resolves the current applier protocol.  The protocol facts
    still come from that closed engine binding, but the exact source staged
    and revalidated here may be the preserved historical blob supplied to
    the validation CLI.  Without this seam ``--engine-source`` affected only
    index validation while the audit silently executed the live producer,
    making a truthful release-ready audit of an archived population
    impossible after the enumerator evolved.
    """
    if engine_source_path is not None and historical_engine_source is not None:
        _refuse("audit accepts either preserved engine bytes or a Git-bound "
                "historical producer, never both")
    if historical_engine_source is not None:
        with tempfile.TemporaryDirectory(
                prefix="r2t_historical_mutator_") as producer_dir:
            producer_path = os.path.join(
                producer_dir,
                os.path.basename(str(historical_engine_source.get("path"))))
            materialise_legacy_engine_source(
                historical_engine_source, producer_path)
            return audit_with_engine(
                manifest, source_root, timeout=timeout,
                engine_source_path=producer_path, runner=runner,
                expected_image_id=expected_image_id, workers=workers)

    # Resolve every manifest-controlled execution choice before touching the
    # disposable tree.  In particular, an otherwise well-formed manifest can
    # name an operator list which is neither of the two executable profiles;
    # discovering that only after creating ``var/bench_mutate`` poisoned all
    # retries with a stale scratch directory.
    from ..bench.mutation_run import binding_for, operator_profile_for
    validate_manifest(manifest)
    try:
        operator_profile = operator_profile_for(manifest["operators"])
    except (KeyError, ValueError) as exc:
        _refuse(str(exc))
    runtime_parser_required = expected_runtime_parser(manifest)
    try:
        engine_dir, applier = binding_for(manifest.get("engine"))
    except Exception as exc:
        _refuse(str(exc))
    if (applier.entrypoint is None) != (applier.classes_rel is None):
        _refuse("compiled audit applier must declare both entrypoint and "
                "classes_rel")
    compiled_applier = applier.entrypoint is not None
    if runner is not None:
        # The Behat/PHP route only.  Cucumber has its own in-image audit
        # (`mutation_java.audit_population_in_image`), which additionally
        # compiles the engine and mounts an authenticated analysis snapshot;
        # routing a compiled applier through this transport would run it
        # without either.
        if manifest["engine"] != M.ENGINE or compiled_applier:
            _refuse(
                f"this in-image materialisation audit is {M.ENGINE}'s "
                f"(Behat/PHP); it cannot run a {manifest['engine']!r} "
                "population's applier")
        if not isinstance(expected_image_id, str) or re.fullmatch(
                r"sha256:[0-9a-f]{64}", expected_image_id) is None:
            _refuse(
                "an in-image materialisation audit needs the pool's "
                "immutable image ID (sha256:<64 hex>); a mutable tag names "
                f"a different image tomorrow: {expected_image_id!r}")
        missing = [name for name in ("probe_isolated_php_toolchain",
                                     "open_isolated_php_session",
                                     "_image_for_isolated_run")
                   if not callable(getattr(runner, name, None))]
        if missing:
            _refuse(f"the audit runner has no {missing}; an in-image PHP "
                    "audit needs the isolated-PHP transport")
        if runner._image_for_isolated_run() != expected_image_id:
            _refuse(
                "in-image audit sidecar image differs from the bound pool "
                "image: the runner would run the applier under "
                f"{runner._image_for_isolated_run()!r}, the caller bound "
                f"{expected_image_id!r}")
    elif expected_image_id is not None:
        _refuse("expected_image_id names an image but no runner was given")
    if isinstance(workers, bool) or not isinstance(workers, int) \
            or workers < 1:
        _refuse("materialisation audit worker count must be an integer >= 1")
    if workers > 1 and runner is None:
        _refuse(
            "a k-way materialisation audit walks k disposable copies with one "
            "session container each, and the host route walks the one tree it "
            "was given: bind the pool that has the interpreter -- `r2t "
            "--worker <spec> mutants validate --audit-root <copy> "
            "--audit-workers k`")
    if compiled_applier and re.fullmatch(
            r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*",
            applier.entrypoint) is None:
        _refuse(f"compiled audit applier entrypoint is not a Java class: "
                f"{applier.entrypoint!r}")
    if engine_source_path is not None \
            and (not isinstance(engine_source_path, str)
                 or not engine_source_path):
        _refuse("audit engine source override must be a nonempty path")
    engine_source = (os.path.abspath(engine_source_path)
                     if engine_source_path is not None
                     else os.path.join(engine_dir, applier.source))
    if os.path.basename(engine_source) != applier.source \
            or os.path.islink(engine_source) \
            or not os.path.isfile(engine_source) \
            or os.path.realpath(engine_source) != engine_source:
        _refuse("audit engine source must be a canonical non-symlink regular "
                f"file named {applier.source!r}")
    try:
        engine_source_sha256 = sha256_file(engine_source)
    except OSError as exc:
        _refuse(f"cannot hash audit engine source {engine_source}: {exc}")
    logical_engine_source = os.path.relpath(
        os.path.join(engine_dir, applier.source),
        REPOSITORY_ROOT).replace(os.sep, "/")
    historical_binding = legacy_engine_source_bindings().get(
        logical_engine_source)
    historical_v1_cli = bool(
        historical_binding is not None
        and historical_binding["sha256"] == engine_source_sha256)
    if historical_v1_cli and operator_profile != "v1":
        _refuse("a Git-bound historical producer may execute only the exact "
                "v1 operator profile it predates")
    # The archived producers predate the explicit profile selector; their
    # closed default is exactly the shared-eight v1 profile.  A source digest
    # has to resolve through the Git-bound historical registry before that
    # old command grammar is admitted.  Every current or unknown producer
    # must accept the explicit profile argument.
    operator_profile_argv = ([] if historical_v1_cli else
                             ["--operator-profile", operator_profile])

    # A preserved copy of the bundled engine has the same protocol regardless
    # of its pathname. Older or historical producer bytes keep their original
    # enumeration protocol; never send a new flag to an unknown producer.
    parse_only_argv = (["--parse-only"] if manifest["engine"] == M.ENGINE
                       and engine_source_sha256 == sha256_file(
                           os.path.join(engine_dir, applier.source)) else [])

    root = os.path.abspath(source_root)
    if os.path.islink(root) or not os.path.isdir(root) \
            or os.path.realpath(root) != root:
        _refuse("full audit root must be a non-symlink directory reached "
                "without symlinked parents")
    marker = os.path.join(root, DISPOSABLE_MARKER)
    if os.path.islink(marker) or not os.path.isfile(marker):
        _refuse(f"full audit requires a non-symlink marker at {marker}")
    try:
        with open(marker, encoding="utf-8") as fh:
            marker_text = fh.read()
    except OSError:
        _refuse(f"full audit requires {marker} with the exact disposable-copy "
                "marker; live workspaces must not be touched")
    if marker_text != DISPOSABLE_MARKER_CONTENT:
        _refuse(f"{marker} does not contain the disposable-copy marker")

    resolved_analysis_authority: Optional[dict[str, str]] = None
    if compiled_applier:
        try:
            from . import mutation_java as JAVA
            if manifest["analysis_recipe"].get("schema") \
                    == JAVA.MODULE_ANALYSIS_SCHEMA:
                _refuse("Kapua module Java authority requires the canonical "
                        "image audit route")
            resolved_analysis_authority = JAVA.resolve_analysis_inputs(
                root, manifest["analysis_recipe"])
        except (TypeError, ValueError) as exc:
            _refuse(str(exc).removeprefix("REFUSED: "))

    engine_env = dict(os.environ)
    if compiled_applier:
        # Exact Java analysis arguments are not sufficient if a launcher
        # option inherited from the host can append an undeclared boot JAR.
        # Use the same ambient-input boundary as enumeration and campaigns.
        engine_env = JAVA.sanitised_java_env(engine_env)
    if runner is None and not compiled_applier \
            and shutil.which(applier.interpreter,
                             path=engine_env.get("PATH")) is None:
        _refuse(
            f"this host has no {applier.interpreter!r} on PATH, so a "
            f"{manifest['engine']} materialisation audit cannot run the "
            "applier here. Either install it, or bind the pool that already "
            "has it -- `r2t --worker <spec> mutants validate --audit-root "
            "<disposable copy>` runs the applier inside the pool's image")

    # WHERE THE APPLIER SEES THE TREE.  On the host route the disposable copy
    # is at `root` and nothing translates.  Through a runner the same copy is
    # bind-mounted at `runner.workdir`, so every path the applier is TOLD
    # about is rebuilt from there -- while every path this process reads back
    # stays the host's, because it is the same directory.
    runtime_root = root if runner is None else runner.workdir
    runtime_staged = (
        os.path.join(root, applier.rel) if runner is None else
        runtime_root.rstrip("/") + "/" + applier.rel.replace(os.sep, "/"))
    # The two constant tokens the in-image route actually hands Docker, and
    # the file that carries everything else.  Both sit in the audit's own
    # private scratch -- inside the one mount, outside the bounded source set
    # the collateral check walks -- and go away with it.
    applier_scratch_rel = os.path.dirname(applier.rel)
    shim_host = os.path.join(root, applier_scratch_rel,
                             APPLIER_SHIM_BASENAME)
    runtime_scratch = (runtime_root.rstrip("/") + "/"
                       + applier_scratch_rel.replace(os.sep, "/"))
    runtime_shim = runtime_scratch + "/" + APPLIER_SHIM_BASENAME
    runtime_descriptor = runtime_scratch + "/" + APPLIER_ARGV_BASENAME
    runtime_autoload = None
    runtime_autoload_sha256 = None
    runtime_parser_identity = manifest["parser"]
    if manifest["engine"] == M.ENGINE:
        runtime_autoload = os.path.join(root, "vendor", "autoload.php")
        if os.path.islink(runtime_autoload) \
                or not os.path.isfile(runtime_autoload) \
                or os.path.realpath(runtime_autoload) != runtime_autoload:
            _refuse("PHP materialisation audit requires the disposable "
                    "root's canonical non-symlink vendor/autoload.php")
        try:
            locked_parser = M.read_parser_version(
                os.path.join(root, "composer.lock"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            _refuse(f"cannot authenticate audit parser lock: {exc}")
        if locked_parser != manifest["parser"]:
            _refuse(f"audit root parser identity is {locked_parser!r}, "
                    f"manifest requires {manifest['parser']!r}")
        runtime_autoload_sha256 = sha256_file(runtime_autoload)
        engine_env["R2T_PHP_AUTOLOAD"] = (
            runtime_autoload if runner is None else
            runtime_root.rstrip("/") + "/vendor/autoload.php")
    else:
        # An inherited PHP override is not an input to a Python/Java audit and
        # must not become accidental ambient provenance.
        engine_env.pop("R2T_PHP_AUTOLOAD", None)
    scratch_relative = os.path.dirname(applier.rel)
    scratch = os.path.join(root, scratch_relative)
    staged = os.path.join(root, applier.rel)
    parse_out_rel = os.path.join(os.path.dirname(applier.rel), "parse.json")
    runtime_parsers_reported: set[str] = set()
    invocation_prefix: list[str] = [applier.interpreter, runtime_staged]
    analysis_invocation: list[str] = []
    compiled_provenance: Optional[dict] = None
    classes_abs: Optional[str] = None
    initial_classes_sha256: Optional[str] = None
    analysis_snapshot_context = None
    analysis_snapshot_entered = False

    # WHICH TREE THIS THREAD IS AUDITING.  With k > 1 each worker owns one
    # disposable copy for its whole life, and everything that is per-tree --
    # the session container it execs into, the descriptor it writes, the
    # parse evidence it reads back -- follows from that one binding.  With
    # k == 1 there is one tree and this is the primary, before and during the
    # walk alike.
    local = threading.local()
    sessions: dict[str, object] = {}
    #: Every tree this audit will walk.  Bound before `verify_runtime_binding`
    #: is defined because that check has to cover all of them, and extended
    #: below once the copies exist.
    worker_roots = [root]

    def worker_bind(worker_root: str) -> None:
        local.root = worker_root
        if runner is not None:
            local.session = sessions[worker_root]

    def worker_root() -> str:
        return getattr(local, "root", root)

    def run(argv: list[str], what: str) -> None:
        if runner is None:
            cp = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout,
                env=engine_env)
        else:
            # NO MUTANT TEXT IN A CONTAINER ARGUMENT.  The vector goes into
            # the descriptor the staged shim reads; what Docker is handed is
            # the interpreter and two constant paths.  `docker_argv` refuses
            # an empty token, and a deletion-shaped mutant has one.
            # `argv[1:]`, and the slice is the whole contract: the
            # descriptor carries PHP's `$argv`, whose element 0 is the
            # SCRIPT, not the interpreter.  `mutate.php` opens with
            # `array_slice($argv, 1)` to drop the script name, so a vector
            # that still carried "php" would leave the staged script path in
            # argument position and the engine would exit 2 on
            # `unknown argument /work/var/bench_mutate/mutate.php`.
            # The descriptor is written into THIS worker's own tree, which
            # is the tree its session container has bind-mounted at
            # `workdir` -- so the two constant container paths below name
            # this worker's descriptor and no other's.
            with open(os.path.join(worker_root(), applier_scratch_rel,
                                   APPLIER_ARGV_BASENAME),
                      "w", encoding="utf-8") as descriptor:
                json.dump({"schema": APPLIER_ARGV_SCHEMA, "argv": argv[1:]},
                          descriptor)
                descriptor.flush()
                os.fsync(descriptor.fileno())
            # The container's own environment is the image's, not this
            # host's, so only the one variable the applier protocol defines
            # crosses the boundary.
            cp = local.session.run(
                [applier.interpreter, runtime_shim, runtime_descriptor],
                env={"R2T_PHP_AUTOLOAD": engine_env["R2T_PHP_AUTOLOAD"]},
                timeout=timeout)
        if cp.returncode != 0:
            raise MutationAssetRefused(
                f"REFUSED: {what} exited {cp.returncode}: "
                f"{(cp.stderr or cp.stdout or '')[-800:]}")

    def apply_one(mutant: dict, _target: str) -> None:
        # Java enumerates from the immutable analysis snapshot and therefore
        # has a separate authenticated write root.  The established PHP and
        # Python applier protocols enumerate and write in the same disposable
        # root and intentionally have no ``--write-root`` option.  Passing
        # the Java-only flag to them made every historical script-engine
        # audit fail before its first mutant.
        write_root = (["--write-root", root] if compiled_applier else [])
        run(invocation_prefix + ["--root", runtime_root] + write_root
            + operator_profile_argv + [
             "--apply-file", mutant["file"],
             "--start-line", str(mutant["start_line"]),
             "--start-col", str(mutant["start_col"]),
             "--operator", mutant["operator"],
             "--original", mutant["original"],
             "--mutated", mutant["mutated"],
             "--out", mutant["file"]] + analysis_invocation,
            f"applying {mutant['id']}")

    def parse_one(mutant: dict, _target: str) -> None:
        parse_out = os.path.join(worker_root(), parse_out_rel)
        if os.path.exists(parse_out):
            os.unlink(parse_out)
        run(invocation_prefix + ["--root", runtime_root]
            + operator_profile_argv
            + parse_only_argv
            + ["--path", mutant["file"], "--out", parse_out_rel]
            + analysis_invocation,
            f"parsing {mutant['id']}")
        try:
            with open(parse_out, encoding="utf-8") as fh:
                document = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise MutationAssetRefused(
                f"REFUSED: parser produced no readable evidence for "
                f"{mutant['id']}: {exc}") from None
        if document.get("errors"):
            raise MutationAssetRefused(
                f"REFUSED: materialised mutant {mutant['id']} does not parse: "
                f"{document['errors']}")
        if document.get("parser") != runtime_parser_required:
            raise MutationAssetRefused(
                f"REFUSED: runtime parser is {document.get('parser')!r}, "
                f"manifest requires {runtime_parser_required!r}")
        runtime_parsers_reported.add(document["parser"])

    def operator_gate() -> dict:
        reported = (next(iter(runtime_parsers_reported))
                    if len(runtime_parsers_reported) == 1 else None)
        gate = {
            "mode": "real_engine",
            "disposable_marker": DISPOSABLE_MARKER,
            "engine_source_sha256": engine_source_sha256,
            # Keep the complete identity (including the PHP lock reference).
            # The shorter value is separately the parser's runtime report.
            "runtime_parser_identity": runtime_parser_identity,
            "runtime_parser_reported": reported,
        }
        if compiled_provenance is not None:
            gate["compiled_applier"] = compiled_provenance
        return gate

    def verify_runtime_binding() -> None:
        validate_preserved_file(
            engine_source, engine_source_sha256,
            label="audit engine source")
        if runtime_autoload is not None:
            # EVERY audited tree, not just the primary.  With k > 1 the other
            # workers ran the applier against THEIR copy's autoloader over
            # their own read-write mount, and `audit_population`'s residue and
            # collateral checks see only the bounded source set -- which
            # `vendor/` and `composer.lock` are deliberately outside.
            for audited_root in worker_roots:
                validate_preserved_file(
                    os.path.join(audited_root, "vendor", "autoload.php"),
                    runtime_autoload_sha256,
                    label="audit project autoloader")
                try:
                    final_parser = M.read_parser_version(
                        os.path.join(audited_root, "composer.lock"))
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    _refuse(
                        f"cannot re-authenticate audit parser lock: {exc}")
                if final_parser != runtime_parser_identity:
                    _refuse("audit parser lock identity changed during "
                            f"materialisation: {audited_root}")
        if compiled_applier:
            try:
                from . import mutation_java as JAVA
                JAVA.resolve_analysis_inputs(
                    root, manifest["analysis_recipe"])
            except (TypeError, ValueError) as exc:
                _refuse(str(exc).removeprefix("REFUSED: "))
            validate_preserved_file(
                staged, engine_source_sha256,
                label="staged compiled audit engine")
            if classes_abs is None or initial_classes_sha256 is None \
                    or _compiled_tree_sha256(classes_abs) \
                    != initial_classes_sha256:
                _refuse("compiled audit applier classes changed during "
                        "materialisation")
    scratch_created = False
    copies_scratch = None
    try:
        if runner is not None:
            probe = runner.probe_isolated_php_toolchain(
                interpreter=applier.interpreter, timeout=timeout)
            identity = ((probe.stdout or "") + "\n"
                        + (probe.stderr or "")).strip()
            if probe.returncode != 0 or not identity:
                _refuse(
                    f"isolated {applier.interpreter} toolchain probe failed "
                    f"in {expected_image_id} (rc={probe.returncode}): "
                    f"{identity[-400:]}")
        if compiled_applier:
            # The compiler consumes only a private authenticated snapshot.
            # Live pre/post hashes remain a staleness witness but are not the
            # authority passed through javac's pathname API.
            analysis_snapshot_context = JAVA.analysis_snapshot(
                root, manifest["analysis_recipe"],
                required_sources=[row["file"]
                                  for row in manifest["mutants"]])
            analysis_snapshot_root = analysis_snapshot_context.__enter__()
            analysis_snapshot_entered = True
            resolved_analysis_authority = JAVA.resolve_analysis_inputs(
                analysis_snapshot_root, manifest["analysis_recipe"])
        scratch = create_private_scratch(root, scratch_relative)
        scratch_created = True
        stage_preserved_file(
            engine_source, staged, engine_source_sha256,
            label="audit engine")
        if runner is not None:
            shim_source = os.path.join(engine_dir, APPLIER_SHIM_BASENAME)
            stage_preserved_file(
                shim_source, shim_host, sha256_file(shim_source),
                label="audit applier argv shim")
        if compiled_applier:
            classes_rel = os.path.normpath(applier.classes_rel)
            classes_abs = os.path.abspath(os.path.join(root, classes_rel))
            try:
                contained = os.path.commonpath((root, classes_abs)) == root
            except ValueError:
                contained = False
            if not contained or os.path.dirname(classes_abs) != scratch \
                    or os.path.lexists(classes_abs):
                _refuse("compiled audit classes path must be a fresh direct "
                        "child of the private engine scratch")
            try:
                os.mkdir(classes_abs, 0o700)
            except OSError as exc:
                _refuse(f"cannot create compiled audit classes directory: "
                        f"{exc}")
            if os.path.islink(classes_abs) or not os.path.isdir(classes_abs) \
                    or os.path.realpath(classes_abs) != classes_abs:
                _refuse("compiled audit classes directory is not canonical")

            java_bin = shutil.which(applier.interpreter,
                                    path=engine_env.get("PATH"))
            javac_bin = shutil.which("javac", path=engine_env.get("PATH"))
            if java_bin is None or javac_bin is None:
                _refuse("compiled audit requires both java and javac")
            java_bin = os.path.realpath(java_bin)
            javac_bin = os.path.realpath(javac_bin)
            from . import mutation_java as JAVA
            if resolved_analysis_authority is None:
                _refuse("compiled audit lost its resolved analysis authority")
            resolved_analysis = resolved_analysis_authority
            analysis_invocation = [
                "--classpath", resolved_analysis["classpath"],
                "--sourcepath", resolved_analysis["sourcepath"],
                "--module-path", resolved_analysis["module_path"],
            ]
            runtime_identity = JAVA.probe_parser_version(java=java_bin)
            compiler_identity = _tool_identity(
                [javac_bin, "-version"], "compiler", timeout=timeout,
                env=engine_env)
            if runtime_identity != runtime_parser_required:
                _refuse(f"compiled audit runtime is {runtime_identity!r}, "
                        f"manifest requires {runtime_parser_required!r}")
            if not runtime_identity.startswith(compiler_identity + " ["):
                _refuse(f"compiled audit javac/runtime identities differ: "
                        f"{compiler_identity!r} / {runtime_identity!r}")
            tools_jar = JAVA._tools_jar(javac_bin)
            compile_argv = [javac_bin]
            if tools_jar is not None:
                compile_argv += ["-classpath", tools_jar]
            compile_argv += ["-proc:none", "-d", classes_abs, staged]
            run(compile_argv, "compiling staged Java audit applier")
            main_class = os.path.join(
                classes_abs, *applier.entrypoint.split(".")) + ".class"
            if os.path.islink(main_class) or not os.path.isfile(main_class) \
                    or os.path.realpath(main_class) != main_class:
                _refuse("javac did not produce the declared audit entrypoint")
            initial_classes_sha256 = _compiled_tree_sha256(classes_abs)
            classpath = classes_abs + (
                os.pathsep + tools_jar if tools_jar is not None else "")
            invocation_prefix = [java_bin, "-cp", classpath,
                                 applier.entrypoint]
            compiled_provenance = {
                "schema": "r2t.compiled-applier/2",
                "source_sha256": engine_source_sha256,
                "interpreter": applier.interpreter,
                "entrypoint": applier.entrypoint,
                "classes_rel": applier.classes_rel.replace(os.sep, "/"),
                "classes_sha256": initial_classes_sha256,
                "compiler_identity": compiler_identity,
                "compiler_executable_sha256": sha256_file(javac_bin),
                "runtime_identity": runtime_identity,
                "runtime_executable_sha256": sha256_file(java_bin),
                "tools_jar_sha256": (sha256_file(tools_jar)
                                     if tools_jar is not None else None),
                "analysis_recipe_digest":
                    manifest["analysis_recipe"]["digest"],
            }
        # The copies are made HERE, after staging, so each one carries the
        # authenticated engine and shim rather than staging k times into k
        # trees and having to prove the k stagings agreed.
        if workers > 1:
            copies_scratch, copies = _copy_disposable_roots(
                root, workers - 1)
            worker_roots.extend(copies)
        with contextlib.ExitStack() as transport:
            if runner is not None:
                sessions.update(transport.enter_context(_php_audit_sessions(
                    runner, worker_roots, interpreter=applier.interpreter,
                    timeout=timeout)))
            try:
                report = audit_population(
                    manifest, root, apply_one, parse_one,
                    parallel_roots=worker_roots[1:], worker_bind=worker_bind)
            except MaterialisationAuditRefused as exc:
                verify_runtime_binding()
                exc.report["operator_gate"] = operator_gate()
                exc.report["digest"] = audit_digest(exc.report)
                raise
            verify_runtime_binding()
            report["operator_gate"] = operator_gate()
            report["digest"] = audit_digest(report)
            return report
    finally:
        if scratch_created:
            shutil.rmtree(scratch, ignore_errors=True)
        if copies_scratch is not None:
            shutil.rmtree(copies_scratch, ignore_errors=True)
        if analysis_snapshot_entered:
            analysis_snapshot_context.__exit__(None, None, None)


def materialise_legacy_engine_source(binding: dict, destination: str) -> None:
    """Write one reviewed historical producer blob to ``destination``.

    The v1 producers live in the Git object store, not in the working tree:
    `asset_pin_expectations` already treats the blob as the pin's subject
    because the live enumerators have moved on.  Both consumers of those
    bytes need them as a FILE -- the operator-gated audit stages one into a
    disposable workspace, and the bundle producer stages one as the
    `engine_source` role -- so the resolution, the SHA-256 check and the
    no-follow exclusive write live here once.
    """
    if not isinstance(binding, dict) or set(binding) != {
            "commit", "path", "git_blob", "sha256"}:
        _refuse("historical engine producer has invalid fields")
    checked = validate_legacy_engine_source_bindings().get(binding["path"])
    if checked != binding:
        _refuse("historical engine producer is not the exact reviewed "
                "commit:path/blob binding")
    cp = subprocess.run(
        ["git", "-C", REPOSITORY_ROOT, "cat-file", "blob",
         binding["git_blob"]], capture_output=True, timeout=30,
        env=_offline_git_env())
    if cp.returncode != 0 \
            or hashlib.sha256(cp.stdout).hexdigest() != binding["sha256"]:
        _refuse("historical engine producer blob is unavailable or differs "
                "from its reviewed SHA-256")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(cp.stdout)
        fh.flush()
        os.fsync(fh.fileno())
    validate_preserved_file(destination, binding["sha256"],
                            label="materialised historical engine producer")


def build_legacy_validation_report(*, project: str, paths: dict[str, str],
                                   references: dict[str, str],
                                   relative_to_report: str) -> dict:
    """Build one portable saved report from preserved legacy evidence.

    ``paths`` names the bytes being validated on this machine;
    ``references`` names where the same bytes live below the extracted bundle
    root.  Keeping those two concerns separate lets a bundle carry historical
    rows without retaining the development host's absolute paths.
    """
    required = {
        "raw_manifest", "map", "coverage_run", "release", "asset_index",
        "boundary", "engine_source", "candidate_run", "gold_baseline",
        "candidate_results", "gold_results",
    }
    optional = {"audit_attestation"}
    missing = sorted(required - set(paths))
    unknown = sorted(set(paths) - required - optional)
    if missing or unknown or set(references) != set(paths):
        _refuse(f"portable legacy report inputs differ; missing={missing}, "
                f"unknown={unknown}, references_match="
                f"{set(references) == set(paths)}")
    if not isinstance(relative_to_report, str) or not relative_to_report \
            or os.path.isabs(relative_to_report):
        _refuse("portable legacy report root is not relative to its report")
    for label, reference in references.items():
        normal = os.path.normpath(reference)
        if not isinstance(reference, str) or not reference \
                or os.path.isabs(reference) or normal == ".." \
                or normal.startswith(".." + os.sep):
            _refuse(f"portable legacy input {label} is not root-relative")

    index = _read_json_object(paths["asset_index"], "bundle asset index")
    validate_asset_index(index)
    entry = index["projects"].get(project)
    if entry is None:
        _refuse(f"bundle asset index has no project {project!r}")
    raw_manifest = _read_json_object(
        paths["raw_manifest"], "bundle raw manifest")
    raw_facts = validate_manifest(raw_manifest)
    legacy_map = _read_json_object(paths["map"], "bundle legacy map")
    release_ids = load_release_ids(paths["release"])
    coverage = coverage_from_rows(load_jsonl(paths["coverage_run"]))
    raw_map_facts = validate_map(
        legacy_map, raw_manifest, release_ids=release_ids,
        coverage_by_item=coverage, allow_legacy=True)

    from ..core.boundary import load_boundary
    boundary = load_boundary(paths["boundary"], repo_root=".")
    boundary_sha256 = sha256_file(paths["boundary"])
    role = entry["scored_population"]["role"]
    if role == "boundary_scored":
        scored_manifest = derive_boundary_scored_manifest(
            raw_manifest, boundary, paths["boundary"], boundary_sha256)
    elif role == "raw_equals_scored":
        scored_manifest = derive_raw_equals_scored_manifest(
            raw_manifest, boundary, paths["boundary"], boundary_sha256)
    else:
        _refuse(f"bundle asset index has unsupported scored role {role!r}")
    scored_facts = validate_manifest(
        scored_manifest,
        raw_manifest=(raw_manifest if raw_manifest["digest"]
                      != scored_manifest["digest"] else None))
    by_mutant, uncovered = M.map_mutants_to_items(scored_manifest, coverage)
    strict_mapping = build_map_artifact(
        scored_manifest, by_mutant, uncovered,
        coverage_sha256=sha256_file(paths["coverage_run"]),
        release_sha256=sha256_file(paths["release"]))
    map_facts = validate_map(
        strict_mapping, scored_manifest, release_ids=release_ids,
        coverage_by_item=coverage)
    evidence = legacy_consistency(
        scored_manifest=scored_manifest, mapping=legacy_map,
        raw_manifest=(raw_manifest if raw_manifest["digest"]
                      != scored_manifest["digest"] else None),
        release_ids=release_ids,
        candidate_run_rows=load_jsonl(paths["candidate_run"]),
        gold_baseline_rows=load_jsonl(paths["gold_baseline"]),
        candidate_result_rows=load_jsonl(paths["candidate_results"]),
        gold_result_rows=load_jsonl(paths["gold_results"]))

    audit_path = paths.get("audit_attestation")
    if audit_path:
        audit_document = _read_json_object(
            audit_path, "bundle materialisation audit")
        audit = audit_document.get("materialisation_audit", audit_document)
    else:
        audit = {
            "status": "not_run",
            "reason": "operator-gated disposable workspace required",
            "expected_mutants": raw_manifest["n"],
        }
    index_facts = validate_index_binding(
        index, project, raw_manifest=raw_manifest,
        scored_manifest=scored_manifest, mapping=strict_mapping,
        boundary_path=paths["boundary"],
        coverage_path=paths["coverage_run"],
        release_path=paths["release"],
        engine_source_path=paths["engine_source"],
        raw_manifest_path=paths["raw_manifest"],
        audit_attestation=(audit if audit_path else None),
        require_release_ready=False)

    inputs = {
        label: {"path": references[label].replace(os.sep, "/"),
                "sha256": sha256_file(path)}
        for label, path in sorted(paths.items())
    }
    report = {
        "schema": "r2t.mutation-validation/1",
        "status": "valid",
        "path_base": {
            "kind": "repository_root",
            "relative_to_report": relative_to_report.replace(os.sep, "/"),
        },
        "raw_manifest": raw_facts,
        "scored_manifest": scored_facts,
        "map": map_facts,
        "legacy_raw_map": raw_map_facts,
        "evidence": evidence,
        "asset_index": index_facts,
        "materialisation_audit": audit,
        "inputs": inputs,
    }
    return {"report": report, "scored_manifest": scored_manifest,
            "mutation_map": strict_mapping}


def build_native_validation_report(*, project: str, paths: dict[str, str],
                                   references: dict[str, str],
                                   relative_to_report: str) -> dict:
    """Build the native campaign gate over already-derived bundle assets."""
    required = {
        "raw_manifest", "manifest", "map", "coverage_run", "release",
        "asset_index", "boundary", "engine_source",
    }
    optional = {"audit_attestation"}
    missing = sorted(required - set(paths))
    unknown = sorted(set(paths) - required - optional)
    if missing or unknown or set(references) != set(paths):
        _refuse(f"portable native report inputs differ; missing={missing}, "
                f"unknown={unknown}, references_match="
                f"{set(references) == set(paths)}")
    if not isinstance(relative_to_report, str) or not relative_to_report \
            or os.path.isabs(relative_to_report):
        _refuse("portable native report root is not relative to its report")
    for label, reference in references.items():
        normal = os.path.normpath(reference)
        if not isinstance(reference, str) or not reference \
                or os.path.isabs(reference) or normal == ".." \
                or normal.startswith(".." + os.sep):
            _refuse(f"portable native input {label} is not root-relative")

    index = _read_json_object(paths["asset_index"], "bundle asset index")
    raw_manifest = _read_json_object(
        paths["raw_manifest"], "bundle raw manifest")
    manifest = _read_json_object(paths["manifest"], "bundle scored manifest")
    mapping = _read_json_object(paths["map"], "bundle mutation map")
    raw_facts = validate_manifest(raw_manifest)
    manifest_facts = validate_manifest(
        manifest, raw_manifest=(raw_manifest if raw_manifest["digest"]
                                != manifest["digest"] else None))
    release_ids = load_release_ids(paths["release"])
    coverage = coverage_from_rows(load_jsonl(paths["coverage_run"]))
    map_facts = validate_map(
        mapping, manifest, release_ids=release_ids,
        coverage_by_item=coverage)
    audit_path = paths.get("audit_attestation")
    if audit_path:
        audit_document = _read_json_object(
            audit_path, "bundle materialisation audit")
        audit = audit_document.get("materialisation_audit", audit_document)
    else:
        audit = {
            "status": "not_run",
            "reason": "operator-gated disposable workspace required",
            "expected_mutants": raw_manifest["n"],
        }
    index_facts = validate_index_binding(
        index, project, raw_manifest=raw_manifest,
        scored_manifest=manifest, mapping=mapping,
        boundary_path=paths["boundary"],
        coverage_path=paths["coverage_run"],
        release_path=paths["release"],
        engine_source_path=paths["engine_source"],
        raw_manifest_path=paths["raw_manifest"],
        audit_attestation=(audit if audit_path else None),
        require_release_ready=False)
    inputs = {
        label: {"path": references[label].replace(os.sep, "/"),
                "sha256": sha256_file(path)}
        for label, path in sorted(paths.items())
    }
    return {
        "schema": "r2t.mutation-validation/1",
        "status": "valid",
        "path_base": {
            "kind": "repository_root",
            "relative_to_report": relative_to_report.replace(os.sep, "/"),
        },
        "raw_manifest": raw_facts,
        "scored_manifest": manifest_facts,
        "map": map_facts,
        "legacy_raw_map": None,
        "evidence": {"validation_class": "native"},
        "asset_index": index_facts,
        "materialisation_audit": audit,
        "inputs": inputs,
    }

def selftest() -> int:
    import ast
    import contextlib
    import inspect
    import io
    import shlex
    import sys
    import tempfile
    import time
    from ..core.boundary import Boundary
    from ..core.paths import BENCHMARK_ROOT
    from ..data.mutation_attestation import (ASSET_INDEX_SCHEMA, AUDIT_SCHEMA_V1,
                                       _gold_files, _is_sha256,
                                       _mutants_outside_roots,
                                       _normalised_roots, _passed_files,
                                       _saved_report_paths,
                                       load_validated_legacy_scoring_inputs,
                                       load_validated_saved_report,
                                       pinned_enumerator_identity,
                                       require_index_release_ready,
                                       solution_digest,
                                       validate_campaign_asset_inputs,
                                       validate_completed_audit_binding,
                                       validate_saved_validation_report)

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    def refused(fn, contains="REFUSED"):
        try:
            fn()
        except (MutationAssetRefused, ValueError) as exc:
            return contains in str(exc)
        return False

    raw_records = [
        {"file": "src/app.py", "operator": "ArithmeticOperator",
         "start_line": 1, "start_col": 3, "original": "+", "mutated": "-"},
        {"file": "tests/helper.py", "operator": "TrueValue",
         "start_line": 1, "start_col": 1, "original": "True",
         "mutated": "False"},
    ]
    raw = M.build_manifest(raw_records, parser_version="fixture-parser",
                           exclusions=())
    boundary = Boundary(version=1, project="fixture", repo_root=".",
                        retained=[("tests/", "test support")])
    scored = derive_boundary_scored_manifest(
        raw, boundary, "boundary_fixture.yml", "a" * 64)

    try:
        pinned_php_identity = pinned_enumerator_identity(
            "r2t/php/mutate.php")
        pinned_php_rev = pinned_php_identity["enumerator_rev"]
    except MutationAssetRefused as exc:
        pinned_php_identity = {}
        pinned_php_rev = f"refused: {exc}"
    with tempfile.TemporaryDirectory() as stage_root:
        stage_path = os.path.join(stage_root, "mutate.php")
        php_source = os.path.join(
            BENCHMARK_ROOT, "r2t", "php", "mutate.php")
        staged = False
        if pinned_php_identity:
            staged = stage_preserved_file(
                php_source, stage_path, pinned_php_identity["sha256"],
                label="selftest enumerator") == pinned_php_identity["sha256"]
        check("a producer executes only from a fresh staged copy that "
              "rehashes to its authority digest",
              staged and refused(lambda: stage_preserved_file(
                  php_source, stage_path, pinned_php_identity["sha256"],
                  label="selftest enumerator"), "fresh staged"))
        with tempfile.TemporaryDirectory() as outside:
            linked_parent = os.path.join(stage_root, "linked")
            os.symlink(outside, linked_parent)
            check("staging refuses a symlinked parent before writing outside "
                  "its scratch tree",
                  refused(lambda: stage_preserved_file(
                      php_source, os.path.join(linked_parent, "mutate.php"),
                      pinned_php_identity["sha256"],
                      label="selftest enumerator"), "parent must be")
                  and not os.path.lexists(
                      os.path.join(outside, "mutate.php")))

    with tempfile.TemporaryDirectory() as output_dir:
        input_path = os.path.join(output_dir, "input.json")
        with open(input_path, "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        fresh_path = os.path.join(output_dir, "fresh.json")
        fd = reserve_output(fresh_path, input_paths=[input_path])
        write_reserved_json(fd, {"status": "fresh"})
        check("fresh output reservation writes exactly once",
              json.load(open(fresh_path, encoding="utf-8"))["status"]
              == "fresh")
        check("an existing output is never replaced",
              refused(lambda: reserve_output(fresh_path), "already exists"))
        check("an output equal to an input is refused before opening",
              refused(lambda: reserve_output(
                  input_path, input_paths=[input_path]), "already exists"))
        symlink_path = os.path.join(output_dir, "output-link.json")
        os.symlink(input_path, symlink_path)
        check("a symlink output is never followed",
              refused(lambda: reserve_output(symlink_path), "already exists"))
        hardlink_path = os.path.join(output_dir, "output-hard.json")
        os.link(input_path, hardlink_path)
        check("a hard-link output is never replaced",
              refused(lambda: reserve_output(hardlink_path), "already exists"))
        real_parent = os.path.join(output_dir, "real-parent")
        os.mkdir(real_parent)
        linked_parent = os.path.join(output_dir, "linked-parent")
        os.symlink(real_parent, linked_parent)
        check("an output through a symlinked parent is refused",
              refused(lambda: reserve_output(
                  os.path.join(linked_parent, "report.json")),
                  "symlinked parent"))
        first_build = os.path.join(output_dir, "build.json")
        check("aliased build --out/--raw-out refuse before reservation",
              refused(lambda: reserve_outputs(
                  [first_build, first_build]), "aliases an input")
              and not os.path.exists(first_build))
        second_existing = os.path.join(output_dir, "raw-existing.json")
        with open(second_existing, "w", encoding="utf-8") as fh:
            fh.write("preserved\n")
        check("an existing raw-out refuses before reserving build out",
              refused(lambda: reserve_outputs(
                  [first_build, second_existing]), "already exists")
              and not os.path.exists(first_build))

        saved_shape = {
            "schema": "r2t.mutation-validation/1",
            "status": "valid",
            "path_base": {"kind": "repository_root",
                          "relative_to_report": "."},
            "raw_manifest": {}, "scored_manifest": {}, "map": {},
            "legacy_raw_map": {},
            "evidence": {"validation_class": "legacy_consistency"},
            "asset_index": {"project": "fixture",
                            "index_binding": "unbound"},
            "materialisation_audit": {}, "inputs": {},
        }

        def saved_copy(name, mutate):
            document = json.loads(json.dumps(saved_shape))
            mutate(document)
            path = os.path.join(output_dir, name)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(document, fh)
            return path

        missing_index_report = saved_copy(
            "missing-index.json", lambda doc: doc.pop("asset_index"))
        check("saved-report reader refuses a missing asset_index claim",
              refused(lambda: validate_saved_validation_report(
                  missing_index_report), "missing"))
        missing_status_report = saved_copy(
            "missing-status.json", lambda doc: doc.pop("status"))
        check("saved-report reader refuses a missing completion status",
              refused(lambda: validate_saved_validation_report(
                  missing_status_report), "missing"))
        unbound_report = saved_copy("unbound-index.json", lambda _doc: None)
        check("saved-report reader refuses an unbound asset_index claim",
              refused(lambda: validate_saved_validation_report(
                  unbound_report), "no valid frozen asset-index binding"))
        failed_status_report = saved_copy(
            "failed-status.json",
            lambda doc: doc.__setitem__("status", "failed"))
        check("saved-report reader refuses a non-valid status",
              refused(lambda: validate_saved_validation_report(
                  failed_status_report), "not a completed valid report"))
        synthetic_bound_report = saved_copy(
            "synthetic-bound.json",
            lambda doc: doc["asset_index"].__setitem__(
                "index_binding", "valid"))
        check("shape-valid synthetic saved JSON cannot replace input bytes",
              refused(lambda: validate_saved_validation_report(
                  synthetic_bound_report), "inputs differ"))
        evidence_file = os.path.join(output_dir, "evidence.json")
        with open(evidence_file, "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        evidence_link = os.path.join(output_dir, "evidence-link.json")
        os.symlink(evidence_file, evidence_link)
        path_report = {
            "path_base": {"kind": "repository_root",
                          "relative_to_report": "."},
            "inputs": {"evidence": {
                "path": "evidence-link.json",
                "sha256": sha256_file(evidence_file),
            }},
        }
        check("saved-report inputs cannot be mutable symlink indirections",
              refused(lambda: _saved_report_paths(
                  path_report, synthetic_bound_report),
                      "non-symlink regular file"))

    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, "src", "app.py")
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as fh:
            fh.write(b"a + b\n")
        os.chmod(path, 0o640)
        with open(os.path.join(root, "src", "untouched.py"), "wb") as fh:
            fh.write(b"UNCHANGED = True\n")

        def apply_exact(mutant, target):
            with open(target, "rb") as fh:
                data = fh.read()
            offset = _line_offset(data, mutant["start_line"],
                                  mutant["start_col"])
            with open(target, "wb") as fh:
                fh.write(data[:offset] + mutant["mutated"].encode()
                         + data[offset + len(mutant["original"]):])

        def parse_python(_mutant, target):
            with open(target, encoding="utf-8") as fh:
                ast.parse(fh.read())

        audit = audit_population(scored, root, apply_exact, parse_python)
        with open(path, "rb") as fh:
            restored = fh.read()
        check("complete audit applies, parses and restores every mutant",
              audit["n_applied"] == scored["n"] and restored == b"a + b\n"
              and audit["n_source_files"] == 2
              and audit["status"] == "complete"
              and audit["source_lstat_sha256_before"]
              == audit["source_lstat_sha256_after"]
              and stat.S_IMODE(os.lstat(path).st_mode) == 0o640
              and audit["digest"] == audit_digest(audit))

        # k concurrent mutants need k trees: one mutant is materialised INTO
        # the audited tree and the collateral check says nothing else moved.
        with tempfile.TemporaryDirectory() as parallel_home:
            twin = os.path.join(parallel_home, "twin")
            shutil.copytree(root, twin)
            bound_workers = []
            parallel_audit = audit_population(
                scored, root, apply_exact, parse_python,
                parallel_roots=[twin],
                worker_bind=bound_workers.append)
            stripped = {key: value for key, value in parallel_audit.items()
                        if key != "parallel_audit"}
            stripped["digest"] = audit_digest(stripped)
            check("a parallel audit walks k byte-identical trees, binds one "
                  "worker to each, accounts for every mutant, and is "
                  "otherwise the sequential attestation exactly",
                  parallel_audit["status"] == "complete"
                  and parallel_audit["parallel_audit"] == {
                      "n_roots": 2,
                      "mutants_by_root": parallel_audit["parallel_audit"][
                          "mutants_by_root"]}
                  and sum(parallel_audit["parallel_audit"]["mutants_by_root"])
                  == scored["n"]
                  and sorted(bound_workers) == sorted([root, twin])
                  and open(path, "rb").read() == b"a + b\n"
                  and open(os.path.join(twin, "src", "app.py"),
                           "rb").read() == b"a + b\n"
                  and stripped == audit)
            # Process transport retains the exact scanner: same-byte-size
            # edits, metadata, additions, deletions and symlink substitutions
            # must all produce the same facts as the synchronous call.
            import concurrent.futures
            import multiprocessing
            bounds = _audit_roots(scored)
            baseline = _snapshot_tree(twin, bounds)
            baseline_stats = _tree_stats(twin, bounds)
            other = os.path.join(twin, "src", "untouched.py")
            extra = os.path.join(twin, "src", "extra.py")
            with concurrent.futures.ProcessPoolExecutor(max_workers=1,
                    mp_context=multiprocessing.get_context("spawn"),
                    initializer=_init_collateral_checker,
                    initargs=(baseline, baseline_stats)) as checker:
                def same_check(label, expected):
                    remote = checker.submit(_check_collateral_in_process,
                                            twin, bounds).result()
                    check(label, remote == expected == _collateral_changes(
                        twin, bounds, baseline, baseline_stats), str(remote))
                empty = {"added": [], "changed": [], "deleted": []}
                same_check("process collateral scan accepts pristine bytes", empty)
                with open(other, "wb") as fh:
                    fh.write(b"UNCHANGED = Nope\n")
                same_check("process scanner detects same-size byte edits",
                           dict(empty, changed=["src/untouched.py"]))
                with open(other, "wb") as fh:
                    fh.write(baseline["src/untouched.py"])
                os.chmod(other, 0o600)
                same_check("process scanner detects mode changes",
                           dict(empty, changed=["src/untouched.py"]))
                os.chmod(other, stat.S_IMODE(baseline_stats["src/untouched.py"][0]))
                with open(extra, "w") as fh:
                    fh.write("added")
                same_check("process scanner detects added paths",
                           dict(empty, added=["src/extra.py"]))
                os.unlink(extra)
                os.unlink(other)
                same_check("process scanner detects deleted paths",
                           dict(empty, deleted=["src/untouched.py"]))
                os.symlink("app.py", other)
                same_check("process scanner rejects substituted symlinks",
                           dict(empty, changed=["src/untouched.py"]))
                os.unlink(other)
                with open(other, "wb") as fh:
                    fh.write(baseline["src/untouched.py"])
                os.chmod(other, stat.S_IMODE(baseline_stats["src/untouched.py"][0]))
                same_check("process scanner observes restoration", empty)
            drifted = os.path.join(parallel_home, "drifted")
            shutil.copytree(root, drifted)
            with open(os.path.join(drifted, "src", "untouched.py"),
                      "ab") as fh:
                fh.write(b"# one byte of drift\n")
            check("a parallel root that is not a byte-identical tree cannot "
                  "be audited under one source-set digest",
                  refused(lambda: audit_population(
                      scored, root, apply_exact, parse_python,
                      parallel_roots=[drifted]),
                      "byte-identical trees"))
            check("two audited trees may not overlap -- that is one tree "
                  "wearing two names",
                  refused(lambda: audit_population(
                      scored, root, apply_exact, parse_python,
                      parallel_roots=[os.path.join(root, "src")]),
                      "overlaps another audited tree")
                  and refused(lambda: audit_population(
                      scored, root, apply_exact, parse_python,
                      parallel_roots=[root]),
                      "overlaps another audited tree"))

        def apply_and_chmod(mutant, target):
            apply_exact(mutant, target)
            os.chmod(target, 0o600)

        metadata_failure = None
        try:
            audit_population(scored, root, apply_and_chmod, parse_python)
        except MaterialisationAuditRefused as exc:
            metadata_failure = exc.report
        check("audit detects a metadata-changing applier and still restores "
              "the exact original mode/uid/gid",
              metadata_failure is not None
              and metadata_failure["failure_stage"] == "materialised_lstat"
              and stat.S_IMODE(os.lstat(path).st_mode) == 0o640
              and metadata_failure["source_lstat_sha256_before"]
              == metadata_failure["source_lstat_sha256_after"])

        os.chmod(path, 0o444)
        readonly_stat = os.lstat(path)
        readonly_wanted = (readonly_stat.st_mode, readonly_stat.st_uid,
                           readonly_stat.st_gid)
        readonly_mutant = os.path.join(root, "src", ".readonly-mutant")
        with open(readonly_mutant, "wb") as fh:
            fh.write(b"a - b\n")
        os.chmod(readonly_mutant, 0o444)
        os.replace(readonly_mutant, path)
        _restore_audit_target(path, b"a + b\n", readonly_wanted)
        check("audit restoration handles an exact read-only source mode",
              open(path, "rb").read() == b"a + b\n"
              and (os.lstat(path).st_mode, os.lstat(path).st_uid,
                   os.lstat(path).st_gid) == readonly_wanted)
        os.chmod(path, 0o640)
        check("an injected audit without the real-engine gate cannot bind",
              refused(lambda: validate_completed_audit_binding(
                  {"status": "complete",
                   "attestation_digest": audit["digest"],
                   "bounded_roots": audit["bounded_roots"],
                   "n_source_files": audit["n_source_files"],
                   "source_set_sha256": audit["source_set_sha256_before"],
                   "runtime_parser_identity": scored["parser"],
                   "engine_source_sha256": "d" * 64},
                  audit, scored,
                  {"engine": scored["engine"],
                   "engine_version": scored["engine_version"],
                   "parser": scored["parser"],
                   "engine_source": {"sha256": "d" * 64}}),
                  "fields differ"))
        gated_audit = json.loads(json.dumps(audit))
        gated_audit["operator_gate"] = {
            "mode": "real_engine",
            "disposable_marker": DISPOSABLE_MARKER,
            "engine_source_sha256": "d" * 64,
            "runtime_parser_identity": scored["parser"],
            "runtime_parser_reported": expected_runtime_parser(scored),
        }
        gated_audit["digest"] = audit_digest(gated_audit)
        complete_entry = {
            "status": "complete",
            "attestation_digest": gated_audit["digest"],
            "bounded_roots": gated_audit["bounded_roots"],
            "n_source_files": gated_audit["n_source_files"],
            "source_set_sha256": gated_audit["source_set_sha256_before"],
            "runtime_parser_identity": scored["parser"],
            "engine_source_sha256": "d" * 64,
        }
        project_entry = {
            "engine": scored["engine"],
            "engine_version": scored["engine_version"],
            "parser": scored["parser"],
            "engine_source": {"sha256": "d" * 64},
        }
        validate_completed_audit_binding(
            complete_entry, gated_audit, scored, project_entry)
        legacy_audit = json.loads(json.dumps(gated_audit))
        legacy_audit["schema"] = AUDIT_SCHEMA_V1
        legacy_audit.pop("source_lstat_sha256_before")
        legacy_audit.pop("source_lstat_sha256_after")
        legacy_audit["digest"] = audit_digest(legacy_audit)
        legacy_entry = dict(
            complete_entry, attestation_digest=legacy_audit["digest"])
        validate_completed_audit_binding(
            legacy_entry, legacy_audit, scored, project_entry)
        check("archived noncompiled /1 audits remain readable while new /2 "
              "audits attest mode/uid/gid", True)
        parallel_bound = json.loads(json.dumps(gated_audit))
        parallel_bound["parallel_audit"] = {
            "n_roots": 2,
            "mutants_by_root": [gated_audit["n_attempted"] - 1, 1],
        }
        parallel_bound["digest"] = audit_digest(parallel_bound)
        validate_completed_audit_binding(
            dict(complete_entry, attestation_digest=parallel_bound["digest"]),
            parallel_bound, scored, project_entry)

        def rebound(block):
            document = json.loads(json.dumps(gated_audit))
            document["parallel_audit"] = block
            document["digest"] = audit_digest(document)
            return validate_completed_audit_binding(
                dict(complete_entry,
                     attestation_digest=document["digest"]),
                document, scored, project_entry)

        check("a parallel audit block binds only when it accounts for every "
              "tree and every attempted mutant",
              refused(lambda: rebound(
                  {"n_roots": 2, "mutants_by_root": [1, 1]}),
                  "every audited tree")
              and refused(lambda: rebound(
                  {"n_roots": 1,
                   "mutants_by_root": [gated_audit["n_attempted"]]}),
                  "every audited tree")
              and refused(lambda: rebound(
                  {"n_roots": 2,
                   "mutants_by_root": [gated_audit["n_attempted"]]}),
                  "every audited tree"))
        legacy_parallel = json.loads(json.dumps(gated_audit))
        legacy_parallel["schema"] = AUDIT_SCHEMA_V1
        legacy_parallel.pop("source_lstat_sha256_before")
        legacy_parallel.pop("source_lstat_sha256_after")
        legacy_parallel["parallel_audit"] = {
            "n_roots": 2, "mutants_by_root": [1, 1]}
        legacy_parallel["digest"] = audit_digest(legacy_parallel)
        check("an archived /1 attestation cannot acquire multi-root "
              "semantics after the fact",
              refused(lambda: validate_completed_audit_binding(
                  dict(complete_entry,
                       attestation_digest=legacy_parallel["digest"]),
                  legacy_parallel, scored, project_entry)))
        changed_metadata = json.loads(json.dumps(gated_audit))
        changed_metadata["source_lstat_sha256_after"] = "f" * 64
        changed_metadata["digest"] = audit_digest(changed_metadata)
        changed_metadata_entry = dict(
            complete_entry, attestation_digest=changed_metadata["digest"])
        check("a v2 audit with changed source metadata cannot bind",
              refused(lambda: validate_completed_audit_binding(
                  changed_metadata_entry, changed_metadata, scored,
                  project_entry), "pristine"))
        tainted_audit = json.loads(json.dumps(gated_audit))
        tainted_audit["collateral"]["added"] = ["src/forged.py"]
        tainted_audit["digest"] = audit_digest(tainted_audit)
        tainted_entry = dict(complete_entry,
                             attestation_digest=tainted_audit["digest"])
        check("a self-consistently re-digested collateral audit cannot bind",
              refused(lambda: validate_completed_audit_binding(
                  tainted_entry, tainted_audit, scored, project_entry),
                  "collateral"))
        null_hash_audit = json.loads(json.dumps(gated_audit))
        null_hash_audit["source_set_sha256_before"] = None
        null_hash_audit["source_set_sha256_after"] = None
        null_hash_audit["digest"] = audit_digest(null_hash_audit)
        null_hash_entry = dict(
            complete_entry, attestation_digest=null_hash_audit["digest"])
        check("equal null source hashes cannot bind",
              refused(lambda: validate_completed_audit_binding(
                  null_hash_entry, null_hash_audit, scored, project_entry),
                  "pristine"))
        stripped_parser = json.loads(json.dumps(gated_audit))
        stripped_parser["operator_gate"]["runtime_parser_identity"] = \
            "reported-parser-without-lock-identity"
        stripped_parser["digest"] = audit_digest(stripped_parser)
        stripped_entry = dict(
            complete_entry, attestation_digest=stripped_parser["digest"])
        check("runtime parser identity cannot strip its lock/ref identity",
              refused(lambda: validate_completed_audit_binding(
                  stripped_entry, stripped_parser, scored, project_entry),
                  "pristine"))
        # MA5 -- the world join.  `audit_population` no longer takes a
        # `bounded_roots` override, so every one of these fabricates the
        # divergence the removed parameter used to make reachable, by
        # tampering with the ATTESTATION and the INDEX ENTRY instead.
        def rooted(audit_roots, entry_roots=None):
            """A re-digested attestation + matching entry, roots swapped."""
            forged = json.loads(json.dumps(gated_audit))
            forged["bounded_roots"] = audit_roots
            forged["digest"] = audit_digest(forged)
            entry = dict(complete_entry,
                         attestation_digest=forged["digest"],
                         bounded_roots=(entry_roots if entry_roots is not None
                                        else audit_roots))
            return forged, entry

        wrong_roots, wrong_roots_entry = rooted(["src", "tests"])
        check("MA5: extra attested roots the manifest does not define refuse",
              refused(lambda: validate_completed_audit_binding(
                  wrong_roots_entry, wrong_roots, scored, project_entry),
                  "not the roots this manifest defines"))
        fabricated, fabricated_entry = rooted(["docs"])
        check("MA5: a wholly fabricated `docs` root refuses -- the review's "
              "own world-inconsistent attestation probe",
              refused(lambda: validate_completed_audit_binding(
                  fabricated_entry, fabricated, scored, project_entry),
                  "not the roots this manifest defines"))
        missing_root, missing_root_entry = rooted([])
        check("MA5: an attestation naming no bounded root at all refuses",
              refused(lambda: validate_completed_audit_binding(
                  missing_root_entry, missing_root, scored, project_entry),
                  "names no bounded source roots"))
        skewed, skewed_entry = rooted(["src"], entry_roots=["src", "docs"])
        check("MA5: attestation and frozen index must agree with the "
              "manifest AND with each other",
              refused(lambda: validate_completed_audit_binding(
                  skewed_entry, skewed, scored, project_entry),
                  "not the roots this manifest defines"))
        # The `src2` prefix trap: a population whose only file is `src2/...`
        # derives root `src2`, so an attestation over `src` is a different
        # tree.  A `startswith(root)` implementation accepts this; the
        # `root + "/"` rule does not.
        prefix_records = [{"file": "src2/app.py",
                           "operator": "ArithmeticOperator",
                           "start_line": 1, "start_col": 3,
                           "original": "+", "mutated": "-"}]
        prefix_raw = M.build_manifest(prefix_records,
                                      parser_version="fixture-parser",
                                      exclusions=())
        # A forged keep policy: the rows say `src2`, the policy says `src`.
        # Re-digested, so nothing but the root join can catch it.
        prefix_raw["exclusions"] = ["!src"]
        prefix_raw["digest"] = M.manifest_digest(prefix_raw)
        prefix_audit = json.loads(json.dumps(gated_audit))
        prefix_audit["manifest_digest"] = prefix_raw["digest"]
        prefix_audit["n_mutants"] = prefix_raw["n"]
        prefix_audit["digest"] = audit_digest(prefix_audit)
        prefix_entry = dict(complete_entry,
                            attestation_digest=prefix_audit["digest"])
        check("MA5: `src2` never satisfies bounded root `src`",
              _audit_roots(prefix_raw) == ["src"]
              and _mutants_outside_roots(prefix_raw, ["src"])
              == ["src2/app.py"]
              and refused(lambda: validate_completed_audit_binding(
                  prefix_entry, prefix_audit, prefix_raw, project_entry),
                  "lie outside the attested bounded source roots"))
        check("MA5: a bounded root is matched exactly or as a directory "
              "prefix, and both really match",
              _mutants_outside_roots(prefix_raw, ["src2"]) == []
              and _mutants_outside_roots(prefix_raw, ["src2/app.py"]) == []
              and _mutants_outside_roots(prefix_raw, ["src2/app"])
              == ["src2/app.py"])
        check("MA5: bounded roots are compared normalised, not as spellings",
              _normalised_roots(["./src/", "src"], "fixture") == ["src"]
              and refused(lambda: _normalised_roots(["../src"], "fixture"),
                          "repository-relative"))
        check("audit roots are derived from the manifest, and "
              "`audit_population` accepts no operator override",
              "bounded_roots" not in inspect.signature(
                  audit_population).parameters
              and audit["bounded_roots"] == _audit_roots(scored))

        invalid_raw = M.build_manifest([
            {"file": "src/app.py", "operator": "ArithmeticOperator",
             "start_line": 1, "start_col": 3, "original": "+",
             "mutated": "("}],
            parser_version="fixture-parser", exclusions=())
        invalid_scored = derive_boundary_scored_manifest(
            invalid_raw, boundary, "boundary_fixture.yml", "a" * 64)
        failed_report = None
        try:
            audit_population(invalid_scored, root, apply_exact, parse_python)
        except MaterialisationAuditRefused as exc:
            failed_report = exc.report
        check("invalid syntax leaves durable failing-ID/count evidence",
              failed_report is not None
              and failed_report["status"] == "failed"
              and failed_report["failing_mutant_id"]
              == invalid_scored["mutants"][0]["id"]
              and failed_report["n_attempted"] == 1
              and failed_report["n_restored"] == 1
              and failed_report["digest"] == audit_digest(failed_report))
        with open(path, "rb") as fh:
            restored_after_failure = fh.read()
        check("parse failure still restores pristine source",
              restored_after_failure == b"a + b\n")

        no_op_report = None
        try:
            audit_population(scored, root, lambda _m, _t: None, parse_python)
        except MaterialisationAuditRefused as exc:
            no_op_report = exc.report
        check("a no-op applier cannot manufacture a complete audit",
              no_op_report is not None
              and no_op_report["failure_stage"] == "materialised_bytes")

        def apply_with_collateral(mutant, target):
            apply_exact(mutant, target)
            with open(os.path.join(root, "src", "collateral.py"), "wb") as fh:
                fh.write(b"COLLATERAL = True\n")

        collateral_report = None
        try:
            audit_population(scored, root, apply_with_collateral, parse_python)
        except MaterialisationAuditRefused as exc:
            collateral_report = exc.report
        check("complete bounded source set catches collateral additions",
              collateral_report is not None
              and collateral_report["failure_stage"] == "collateral"
              and collateral_report["collateral"]["added"]
              == ["src/collateral.py"])
        os.unlink(os.path.join(root, "src", "collateral.py"))
        check("full real-engine audit refuses an unmarked workspace",
              refused(lambda: audit_with_engine(scored, root),
                      "full audit requires"))
        with open(os.path.join(root, DISPOSABLE_MARKER), "w",
                  encoding="utf-8") as fh:
            fh.write(DISPOSABLE_MARKER_CONTENT)
        from ..py import mutate as PY_MUTATE

        @contextlib.contextmanager
        def this_interpreter_as_python3():
            # The host route runs the Python applier as whichever `python3`
            # PATH finds first, and refuses unless it reports the manifest's
            # parser.  These fixtures name the parser of the interpreter
            # running this test, so where PATH finds another `python3` first
            # -- Anaconda ahead of a coordinator built from /usr/bin/python3
            # -- they would refuse for the host's reason, not the change's
            # (#244).  A `python3` that execs this interpreter makes the
            # fixture's claim true; the production route is unchanged.
            with tempfile.TemporaryDirectory() as shim_dir:
                shim = os.path.join(shim_dir, "python3")
                with open(shim, "w", encoding="utf-8") as fh:
                    fh.write("#!/bin/sh\nexec "
                             f"{shlex.quote(sys.executable)} \"$@\"\n")
                os.chmod(shim, 0o700)
                saved = os.environ.get("PATH", os.defpath)
                os.environ["PATH"] = shim_dir + os.pathsep + saved
                try:
                    yield
                finally:
                    os.environ["PATH"] = saved

        python_manifest = M.build_manifest(
            [raw_records[0]], parser_version=PY_MUTATE.parser_version(),
            operators=M.OPERATORS_V1, exclusions=(),
            engine=PY_MUTATE.ENGINE,
            engine_version=PY_MUTATE.ENGINE_VERSION)
        with tempfile.TemporaryDirectory() as preserved_engine_dir, \
                this_interpreter_as_python3():
            current_python_engine = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "py", "mutate.py")
            preserved_python_engine = os.path.join(
                preserved_engine_dir, "mutate.py")
            shutil.copyfile(current_python_engine, preserved_python_engine)
            preserved_audit = audit_with_engine(
                python_manifest, root,
                engine_source_path=preserved_python_engine)
            check("an explicit preserved producer is the exact source staged "
                  "and attested by a real audit",
                  preserved_audit["status"] == "complete"
                  and preserved_audit["n_applied"] == 1
                  and preserved_audit["operator_gate"][
                      "engine_source_sha256"]
                  == sha256_file(preserved_python_engine))
            wrong_name = os.path.join(preserved_engine_dir, "producer.py")
            shutil.copyfile(current_python_engine, wrong_name)
            check("the historical producer seam cannot substitute a source "
                  "under another applier filename",
                  refused(lambda: audit_with_engine(
                      python_manifest, root, engine_source_path=wrong_name),
                      "canonical non-symlink regular file named 'mutate.py'"))
            historical = legacy_engine_source_bindings()[
                "benchmark/r2t/py/mutate.py"]
            historical_dir = os.path.join(
                preserved_engine_dir, "historical")
            os.mkdir(historical_dir)
            historical_python_engine = os.path.join(
                historical_dir, "mutate.py")
            # Through the same validated seam the production path and the
            # bundle producer use, not an ad-hoc read.  This blob is reachable
            # only through full history, and the ad-hoc `cat-file` here ignored
            # its exit status: on a shallow clone it wrote a zero-byte producer
            # and the self-test then died at "mutant ... is not its exact
            # non-identity byte splice", blaming the mutation engine for a
            # clone-shape problem.
            materialise_legacy_engine_source(
                historical, historical_python_engine)
            historical_audit = audit_with_engine(
                python_manifest, root,
                engine_source_path=historical_python_engine)
            check("the Git-bound pre-profile producer executes its exact v1 "
                  "default grammar without accepting a generic downgrade",
                  sha256_file(historical_python_engine)
                  == historical["sha256"]
                  and historical_audit["status"] == "complete"
                  and historical_audit["operator_gate"][
                      "engine_source_sha256"] == historical["sha256"])
            python_v2_manifest = M.build_manifest(
                [raw_records[0]], parser_version=PY_MUTATE.parser_version(),
                operators=M.OPERATORS, exclusions=(),
                engine=PY_MUTATE.ENGINE,
                engine_version=PY_MUTATE.ENGINE_VERSION)
            check("a historical producer digest cannot be relabelled as the "
                  "new v2 operator grammar",
                  refused(lambda: audit_with_engine(
                      python_v2_manifest, root,
                      engine_source_path=historical_python_engine),
                      "only the exact v1 operator profile"))
        # ``create_private_scratch`` intentionally preserves a parent it had
        # to create; remove that empty fixture-only parent before the next
        # symlink-parent attack constructs the same path.
        os.rmdir(os.path.join(root, "var"))
        unknown_profile = json.loads(json.dumps(scored))
        unknown_profile["operators"].append("UnknownOperator")
        unknown_profile["digest"] = M.manifest_digest(unknown_profile)
        from ..bench.mutation_run import binding_for
        _engine_dir, applier = binding_for(unknown_profile["engine"])
        scratch = os.path.join(root, os.path.dirname(applier.rel))
        check("an unexecutable operator profile refuses before creating "
              "audit scratch",
              refused(lambda: audit_with_engine(unknown_profile, root),
                      "neither the exact ordered v1 profile nor")
              and not os.path.exists(scratch))
        missing_parser = json.loads(json.dumps(scored))
        del missing_parser["parser"]
        missing_parser["digest"] = M.manifest_digest(missing_parser)
        check("a malformed manifest refuses before creating audit scratch",
              refused(lambda: audit_with_engine(missing_parser, root),
                      "missing ['parser']")
              and not os.path.exists(scratch))
        with tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(root, "var"))
            python_manifest = M.build_manifest(
                raw_records[:1], parser_version="cpython fixture",
                exclusions=(), engine="r2t-mutate-py",
                engine_version="1.0")
            check("full audit refuses a symlinked scratch parent before "
                  "creating or executing outside the disposable root",
                  refused(lambda: audit_with_engine(python_manifest, root),
                          "scratch parent")
                  and not os.path.lexists(
                      os.path.join(outside, "bench_mutate")))
            os.unlink(os.path.join(root, "var"))

    # Compiled-engine path: this is intentionally a REAL javac/java audit,
    # not the command-shape fake in mutation_run.selftest. It proves staging,
    # exact class invocation, enumerate/apply symmetry, parse evidence,
    # restoration, and the toolchain/source/entrypoint provenance join.
    with tempfile.TemporaryDirectory() as java_root:
        from . import mutation_java as JAVA
        java_file = os.path.join(java_root, "src", "demo", "Audit.java")
        os.makedirs(os.path.dirname(java_file))
        with open(java_file, "w", encoding="utf-8") as fh:
            fh.write("package demo;\nimport ext.External;\n"
                     "public class Audit {\n"
                     "  External dependency;\n"
                     "  int value() { return 1; }\n}\n")
        external_source = os.path.join(
            java_root, "deps-src", "ext", "External.java")
        external_classes = os.path.join(java_root, "deps", "classes")
        os.makedirs(os.path.dirname(external_source))
        os.makedirs(external_classes)
        with open(external_source, "w", encoding="utf-8") as fh:
            fh.write("package ext; public final class External {}\n")
        javac_for_fixture = shutil.which("javac")
        if javac_for_fixture is None:
            raise RuntimeError("mutation_attestation selftest requires javac")
        external_cp = subprocess.run(
            [javac_for_fixture, "-proc:none", "-d", external_classes,
             external_source], capture_output=True, text=True, timeout=60,
            env=JAVA.sanitised_java_env())
        if external_cp.returncode != 0:
            raise RuntimeError(
                "external Java audit dependency did not compile: "
                + (external_cp.stderr or external_cp.stdout)[-800:])
        with open(os.path.join(java_root, DISPOSABLE_MARKER), "w",
                  encoding="utf-8") as fh:
            fh.write(DISPOSABLE_MARKER_CONTENT)
        java_source_sha = sha256_file(JAVA.JAVA_SOURCE)
        java_recipe = JAVA.make_analysis_recipe(
            java_root, classpath=["deps/classes"], sourcepath=["src"])
        java_envelope = JAVA.enumerate_local(
            java_root, ["src"], analysis_recipe=java_recipe,
            compile_workers=1,
            record_enumerator_rev=True,
            expected_enumerator_sha256=java_source_sha,
            timeout=180)
        java_manifest = JAVA.population_for(
            java_envelope, expected_parser=java_envelope["parser"])
        java_audit = audit_with_engine(java_manifest, java_root, timeout=180)
        java_gate = java_audit["operator_gate"]
        compiled = java_gate.get("compiled_applier") or {}
        check("compiled Java materialisation audit runs every real mutant "
              "through javac-tree apply/parse and restores the source",
              java_audit["status"] == "complete"
              and java_audit["n_applied"] == java_manifest["n"]
              and java_audit["n_parse_valid"] == java_manifest["n"]
              and open(java_file, encoding="utf-8").read()
              == "package demo;\nimport ext.External;\n"
                 "public class Audit {\n"
                 "  External dependency;\n"
                 "  int value() { return 1; }\n}\n"
              and not os.path.exists(os.path.join(
                  java_root, "var", "bench_mutate")))
        check("compiled audit provenance binds exact source, class entrypoint, "
              "toolchain identities and compiled bytes",
              compiled.get("schema") == "r2t.compiled-applier/2"
              and compiled.get("source_sha256") == java_source_sha
              and compiled.get("entrypoint") == "Mutate"
              and compiled.get("classes_rel")
              == "var/bench_mutate/classes"
              and _is_sha256(compiled.get("classes_sha256"))
              and compiled.get("runtime_identity")
              == java_manifest["parser"]
              and compiled.get("analysis_recipe_digest")
              == java_recipe["digest"]
              and java_manifest["parser"].startswith(
                  compiled.get("compiler_identity", "") + " ["),
              str(compiled))
        java_entry = {
            "status": "complete",
            "attestation_digest": java_audit["digest"],
            "bounded_roots": java_audit["bounded_roots"],
            "n_source_files": java_audit["n_source_files"],
            "source_set_sha256": java_audit["source_set_sha256_before"],
            "runtime_parser_identity": java_manifest["parser"],
            "engine_source_sha256": java_source_sha,
        }
        java_project = {
            "engine": JAVA.ENGINE,
            "engine_version": JAVA.ENGINE_VERSION,
            "parser": java_manifest["parser"],
            "engine_source": {"sha256": java_source_sha},
        }
        validate_completed_audit_binding(
            java_entry, java_audit, java_manifest, java_project)
        external_class_path = os.path.join(
            external_classes, "ext", "External.class")
        with open(external_class_path, "rb") as fh:
            external_class_bytes = fh.read()
        with open(external_class_path, "ab") as fh:
            fh.write(b"stale")
        try:
            stale_refused = refused(
                lambda: audit_with_engine(
                    java_manifest, java_root, timeout=180), "is stale")
        finally:
            with open(external_class_path, "wb") as fh:
                fh.write(external_class_bytes)
        check("compiled audit refuses stale classpath authority before "
              "creating engine scratch",
              stale_refused and not os.path.exists(os.path.join(
                  java_root, "var", "bench_mutate")))
        forged_java_audit = json.loads(json.dumps(java_audit))
        forged_java_audit["operator_gate"]["compiled_applier"][
            "entrypoint"] = "ForgedMain"
        forged_java_audit["digest"] = audit_digest(forged_java_audit)
        forged_java_entry = dict(
            java_entry, attestation_digest=forged_java_audit["digest"])
        check("a self-consistent compiled audit cannot forge its entrypoint",
              refused(lambda: validate_completed_audit_binding(
                  forged_java_entry, forged_java_audit, java_manifest,
                  java_project), "pristine full population"))

    # --------------------------------------------------------- MA3/MA4/MA6
    # ONE COMPLETE FIXTURE WORLD, DRIVEN THROUGH THE REAL VERB.  Nothing
    # below hand-writes a validation report: every report read back is one
    # the real `r2t mutants validate` producer wrote, and every read goes
    # through the real saved-report loader at `require_release_ready=True`.
    # That is the only arrangement in which review caveat AC1 (the legacy
    # branch was traced by reading only) can be settled by execution.
    with tempfile.TemporaryDirectory() as world:
        from .. import cli as C
        from . import mutation_py as MP

        def wpath(name):
            return os.path.join(world, name)

        def write_json(name, value):
            path = wpath(name)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(value, fh, indent=1, sort_keys=True)
            return path

        def write_jsonl(name, rows):
            path = wpath(name)
            with open(path, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
            return path

        def produce(argv):
            """Run the real verb; keep its report summary out of this log."""
            with contextlib.redirect_stdout(io.StringIO()):
                return C.main(argv)

        def exit_refused(argv, contains):
            try:
                produce(argv)
            except SystemExit as exc:
                return contains in str(exc)
            return False

        # (1) A real source tree and the population the PYTHON engine's
        #     identity mints over it.  The engine source is this repository's
        #     own `r2t/py/mutate.py`, so the frozen index below pins the same
        #     bytes the asset-pin validator rehashes.
        engine_source_path = os.path.join(MP.PY_ENGINE_DIR, "mutate.py")
        source_root = wpath("workspace")
        os.makedirs(os.path.join(source_root, "src"))
        with open(os.path.join(source_root, "src", "app.py"), "wb") as fh:
            fh.write(b"a + b\n")
        world_manifest = M.build_manifest(
            [{"file": "src/app.py", "operator": "ArithmeticOperator",
              "start_line": 1, "start_col": 3, "original": "+",
              "mutated": "-"}],
            parser_version="fixture-python", exclusions=(),
            engine=MP.ENGINE, engine_version=MP.ENGINE_VERSION)
        world_facts = validate_manifest(world_manifest)
        manifest_path = write_json("mutants.json", world_manifest)

        boundary_path = wpath("boundary_fixture.yml")
        with open(boundary_path, "w", encoding="utf-8") as fh:
            fh.write("version: 1\n"
                     "project: fixture\n"
                     f"repo_root: {source_root}\n"
                     "removable: []\n"
                     "removable_config: []\n"
                     "retained: []\n"
                     "retained_contexts: []\n")

        world_mutant = world_manifest["mutants"][0]
        release_path = write_jsonl("release.jsonl", [{"item_id": "item-1"}])
        # The gold baseline IS the coverage run, exactly as the preserved
        # Slice 1 legacy report names one file for both.
        gold_rows = [{"item_id": "item-1", "outcome": "passed",
                      "coverage_lines": {"src/app.py": [1]},
                      "produced_files": [{"file_path": "gold.py",
                                          "code": "assert reference"}]}]
        coverage_path = write_jsonl("gold_baseline.jsonl", gold_rows)
        candidate_rows = [{"item_id": "item-1", "outcome": "passed",
                           "produced_files": [{"file_path": "steps.py",
                                               "code": "assert value"}]}]
        candidate_path = write_jsonl("candidate_run.jsonl", candidate_rows)
        world_coverage = coverage_from_rows(gold_rows)

        def world_result_row(files):
            return {"mutant_id": world_mutant["id"], "item_id": "item-1",
                    "file": world_mutant["file"],
                    "operator": world_mutant["operator"],
                    "start_line": world_mutant["start_line"],
                    "outcome": "failed",
                    "engine": world_manifest["engine"],
                    "engine_version": world_manifest["engine_version"],
                    "manifest_digest": None,
                    "candidate_digest": solution_digest(files)}

        candidate_results_path = write_jsonl(
            "candidate_results.jsonl",
            [world_result_row(_passed_files(candidate_rows))])
        gold_results_path = write_jsonl(
            "gold_results.jsonl",
            [world_result_row(_gold_files(gold_rows, {"item-1"}))])

        world_by, world_uncovered = M.map_mutants_to_items(
            world_manifest, world_coverage)
        world_map = build_map_artifact(
            world_manifest, world_by, world_uncovered,
            coverage_sha256=sha256_file(coverage_path),
            release_sha256=sha256_file(release_path))
        map_path = write_json("map.json", world_map)
        world_map_facts = validate_map(
            world_map, world_manifest, release_ids={"item-1"},
            coverage_by_item=world_coverage)

        # (2) A REAL completed audit over that tree, then the operator gate
        #     the two-party ceremony records on it.
        world_audit = audit_population(
            world_manifest, source_root, apply_exact, parse_python)
        engine_source_sha256 = sha256_file(engine_source_path)
        world_audit["operator_gate"] = {
            "mode": "real_engine",
            "disposable_marker": DISPOSABLE_MARKER,
            "engine_source_sha256": engine_source_sha256,
            "runtime_parser_identity": world_manifest["parser"],
            "runtime_parser_reported": expected_runtime_parser(world_manifest),
        }
        world_audit["digest"] = audit_digest(world_audit)
        audit_path = write_json("audit_attestation.json", world_audit)

        population_identity = {
            "n": world_facts["n"],
            "manifest_digest": world_facts["digest"],
            "canonical_sha256": world_facts["canonical_sha256"],
        }
        world_index = {
            "schema": ASSET_INDEX_SCHEMA,
            "version": 1,
            "projects": {"fixture": {
                "engine": world_manifest["engine"],
                "engine_version": world_manifest["engine_version"],
                "parser": world_manifest["parser"],
                "raw_population": dict(
                    population_identity, role="pre_boundary_catalogue",
                    preserved_file_sha256=sha256_file(manifest_path)),
                "scored_population": dict(
                    population_identity, role="raw_equals_scored",
                    raw_manifest_digest=world_facts["digest"],
                    n_non_production_excluded=0),
                "boundary": {"config": "boundary_fixture.yml",
                             "classification": "production",
                             "sha256": sha256_file(boundary_path)},
                "mutation_map": {
                    "manifest_role": "scored_population",
                    "n_mutants": world_map_facts["n_mutants"],
                    "n_mapped": world_map_facts["n_mapped"],
                    "n_uncovered": world_map_facts["n_uncovered"],
                    "n_pairs": world_map_facts["n_pairs"],
                    "digest": world_map_facts["digest"],
                    "canonical_sha256": world_map_facts["canonical_sha256"],
                    "coverage_sha256": sha256_file(coverage_path),
                    "release_sha256": sha256_file(release_path)},
                "coverage_oracle": {"rows": 1,
                                    "sha256": sha256_file(coverage_path)},
                "release": {"items": 1, "sha256": sha256_file(release_path)},
                "engine_source": {"sha256": engine_source_sha256},
                "materialisation_audit": {
                    "expected_mutants": world_facts["n"],
                    "status": "complete",
                    "attestation_digest": world_audit["digest"],
                    "release_blocker": None,
                    "bounded_roots": world_audit["bounded_roots"],
                    "n_source_files": world_audit["n_source_files"],
                    "source_set_sha256":
                        world_audit["source_set_sha256_before"],
                    "runtime_parser_identity": world_manifest["parser"],
                    "engine_source_sha256": engine_source_sha256},
            }},
        }
        world_index_path = write_json("asset_index.json", world_index)
        check("MA3: the fixture world's frozen index is a COMPLETE one -- "
              "the state that used to deadlock the legacy class",
              validate_asset_index(world_index)["projects"] == ["fixture"]
              and require_index_release_ready(world_index, "fixture") is None)
        forged_historical = dict(legacy_engine_source_bindings()[
            "benchmark/r2t/py/mutate.py"])
        forged_historical["sha256"] = "0" * 64
        check("MA3: an arbitrary engine-source digest cannot bypass hashing "
              "by posing as historical provenance",
              refused(lambda: validate_index_binding(
                  world_index, "fixture", raw_manifest=world_manifest,
                  scored_manifest=world_manifest, mapping=world_map,
                  boundary_path=boundary_path, coverage_path=coverage_path,
                  release_path=release_path,
                  engine_source_path=engine_source_path,
                  historical_engine_source=forged_historical,
                  raw_manifest_path=manifest_path,
                  audit_attestation=world_audit),
                  "not the reviewed"))

        # The bundle producer validates local source paths, then records the
        # locations those same bytes have after extraction.  Exercise that
        # rebase through the real saved-report reader rather than inspecting
        # the JSON in memory.
        portable_engine = wpath("mutate.py")
        shutil.copyfile(engine_source_path, portable_engine)
        portable_paths = {
            "raw_manifest": manifest_path,
            "map": map_path,
            "coverage_run": coverage_path,
            "release": release_path,
            "asset_index": world_index_path,
            "boundary": boundary_path,
            "engine_source": portable_engine,
            "candidate_run": candidate_path,
            "gold_baseline": coverage_path,
            "candidate_results": candidate_results_path,
            "gold_results": gold_results_path,
            "audit_attestation": audit_path,
        }
        portable = build_legacy_validation_report(
            project="fixture", paths=portable_paths,
            references={key: os.path.basename(path)
                        for key, path in portable_paths.items()},
            relative_to_report=".")
        portable_report_path = write_json(
            "portable.validation.json", portable["report"])
        portable_facts = validate_saved_validation_report(
            portable_report_path,
            expected_validation_class="legacy_consistency",
            require_release_ready=True)
        check("MA6: a portable legacy report re-loads from its rebased input "
              "paths without promoting historical provenance",
              portable_facts["release_ready"] is True
              and portable["report"]["evidence"]["native_provenance"] is False
              and all(not os.path.isabs(item["path"])
                      for item in portable["report"]["inputs"].values()))

        # Recollection adds recorder evidence without changing coverage or
        # solution bytes. The map still binds the entire new baseline file.
        import copy
        from . import bundle_build as BB
        recollected_rows = [dict(row, direct_calls=[]) for row in gold_rows]
        recollected_path = write_jsonl("gold_recollected.jsonl", recollected_rows)
        recollected_map = build_map_artifact(
            world_manifest, world_by, world_uncovered,
            coverage_sha256=sha256_file(recollected_path),
            release_sha256=sha256_file(release_path))
        recollected_facts = validate_map(
            recollected_map, world_manifest, release_ids={"item-1"},
            coverage_by_item=coverage_from_rows(recollected_rows))
        recollected_index = copy.deepcopy(world_index)
        recollected_entry = recollected_index["projects"]["fixture"]
        for key in ("digest", "canonical_sha256", "n_mutants", "n_mapped",
                    "n_uncovered", "n_pairs"):
            recollected_entry["mutation_map"][key] = recollected_facts[key]
        recollected_entry["mutation_map"]["coverage_sha256"] = sha256_file(
            recollected_path)
        recollected_entry["coverage_oracle"] = {
            "rows": len(recollected_rows), "sha256": sha256_file(recollected_path)}
        recollected_index_path = write_json("recollected_index.json", recollected_index)
        recollected_paths = dict(portable_paths, coverage_run=recollected_path,
                                 gold_baseline=recollected_path)

        def recollected_ceremony():
            return build_legacy_validation_report(
                project="fixture", paths=recollected_paths,
                references={key: os.path.basename(path)
                            for key, path in recollected_paths.items()},
                relative_to_report=".")

        check("recollection refuses stale index pins even with identical coverage",
              refused(recollected_ceremony, "map"))
        recollected_paths["asset_index"] = recollected_index_path
        recollected = recollected_ceremony()
        recollected_report_path = write_json(
            "recollected.validation.json", recollected["report"])
        selected = BB._historical_report("fixture", recollected_report_path)
        for label, path in recollected_paths.items():
            BB._match_historical(selected, label, path)
        check("a rerun ceremony binds the new baseline and map while keeping "
              "the historical population, audit and non-native evidence",
              recollected["mutation_map"] == recollected_map
              and recollected_map["digest"] != world_map["digest"]
              and recollected["report"]["evidence"] == portable["report"]["evidence"]
              and recollected["scored_manifest"] == portable["scored_manifest"]
              and recollected["report"]["materialisation_audit"] == world_audit
              and validate_saved_validation_report(
                  recollected_report_path,
                  expected_validation_class="legacy_consistency",
                  require_release_ready=True)["release_ready"])

        common_argv = [
            "--boundary", boundary_path,
            "mutants", "validate",
            "--map", map_path,
            "--coverage-run", coverage_path,
            "--release", release_path,
            "--asset-index", world_index_path,
            "--asset-project", "fixture",
            "--engine-source", engine_source_path,
        ]
        legacy_argv = [
            "--legacy-consistency",
            "--candidate-run", candidate_path,
            "--gold-baseline", coverage_path,
            "--candidate-results", candidate_results_path,
            "--gold-results", gold_results_path,
        ]

        # (3) MA3 native: producer -> saved report -> release-ready reader.
        native_out = wpath("native.validation.json")
        native_rc = produce(common_argv + [
            "--out", native_out, "--manifest", manifest_path,
            "--audit-attestation", audit_path, "--require-release-ready"])
        native_facts = validate_saved_validation_report(
            native_out, expected_validation_class="native",
            require_release_ready=True)
        check("MA3: a NATIVE report the real producer wrote reads back "
              "release-ready through the real loader",
              native_rc == 0
              and native_facts["status"] == "valid"
              and native_facts["validation_class"] == "native"
              and native_facts["release_ready"] is True,
              str(native_facts))

        # Preserve the producer's report, including its absolute locations.
        # The installed files supply locations only; the real native reader
        # still derives the population, map and completed audit from them.
        with tempfile.TemporaryDirectory() as installed:
            from unittest.mock import patch
            from ..data import mutation_attestation as A

            _, native_report, native_paths = load_validated_saved_report(
                native_out, expected_validation_class="native",
                require_release_ready=True)
            installed_report = os.path.join(installed, "report.json")
            shutil.copyfile(native_out, installed_report)
            installed_inputs = {}
            for label, source in native_paths.items():
                directory = os.path.join(installed, label)
                os.mkdir(directory)
                target = os.path.join(directory, os.path.basename(source))
                shutil.copyfile(source, target)
                installed_inputs[label] = target
            preserved_report_sha = sha256_file(native_out)
            producer_paths = {os.path.abspath(path)
                              for path in (*native_paths.values(), native_out)}
            real_open = open

            def installed_open(path, *args, **kwargs):
                if isinstance(path, (str, bytes, os.PathLike)) \
                        and os.path.abspath(path) in producer_paths:
                    raise AssertionError(f"producer input was reopened: {path}")
                return real_open(path, *args, **kwargs)

            def read_installed(**kwargs):
                return validate_saved_validation_report(
                    installed_report, expected_validation_class="native",
                    require_release_ready=True,
                    input_paths=kwargs.get("input_paths", installed_inputs))

            with patch("builtins.open", side_effect=installed_open), \
                    patch.object(A, "_legacy_catalogue_overrides",
                                 side_effect=AssertionError("legacy catalogue read")):
                loaded_facts, loaded_report, loaded_paths = \
                    load_validated_saved_report(
                        installed_report, expected_validation_class="native",
                        require_release_ready=True, input_paths=installed_inputs)
                assets = validate_campaign_asset_inputs(
                    installed_report,
                    manifest_path=installed_inputs.get(
                        "manifest", installed_inputs["raw_manifest"]),
                    map_path=installed_inputs["map"],
                    release_path=installed_inputs["release"],
                    input_paths=installed_inputs)
            check("native report and campaign validation use relocated exact "
                  "inputs without producer paths or historical candidates",
                  loaded_facts == native_facts
                  and loaded_report == native_report
                  and loaded_paths == installed_inputs
                  and assets["manifest"] == world_manifest
                  and assets["map"] == world_map
                  and assets["validation_sha256"] == preserved_report_sha
                  and sha256_file(installed_report) == preserved_report_sha
                  and not {"candidate_run", "candidate_results", "gold_results"}
                      & set(installed_inputs))
            incomplete = dict(installed_inputs)
            del incomplete["audit_attestation"]
            check("explicit native locations are complete: no omitted audit "
                  "or added candidate input can fall back to producer paths",
                  refused(lambda: read_installed(input_paths=incomplete),
                          "relocated native report inputs")
                  and refused(lambda: read_installed(input_paths={
                      **installed_inputs, "candidate_run": candidate_path}),
                      "relocated native report inputs"))
            check("a missing relocated file or location refuses even while "
                  "the original producer file remains readable",
                  refused(lambda: read_installed(input_paths={
                      **installed_inputs, "map": os.path.join(installed, "missing")}),
                      "regular file")
                  and refused(lambda: read_installed(input_paths={
                      **installed_inputs, "map": None}), "has no path"))
            with open(installed_inputs["map"], "rb") as handle:
                map_bytes = handle.read()
            with open(installed_inputs["map"], "ab") as handle:
                handle.write(b"\n")
            check("relocation retains the original exact-byte input pins",
                  refused(read_installed, "SHA-256"))
            with open(installed_inputs["map"], "wb") as handle:
                handle.write(map_bytes)
            false_report = copy.deepcopy(native_report)
            false_report["map"]["n_pairs"] += 1
            false_report_path = os.path.join(installed, "false-report.json")
            with open(false_report_path, "w", encoding="utf-8") as handle:
                json.dump(false_report, handle)
            check("relocated input hashes do not replace native rederivation",
                  refused(lambda: validate_saved_validation_report(
                      false_report_path, expected_validation_class="native",
                      require_release_ready=True, input_paths=installed_inputs),
                      "differs from re-derived"))
            wrong_boundary = os.path.join(installed, "boundary.yml")
            shutil.copyfile(installed_inputs["boundary"], wrong_boundary)
            check("relocation retains the indexed boundary filename rule",
                  refused(lambda: read_installed(input_paths={
                      **installed_inputs, "boundary": wrong_boundary})))

            # The actual frozen v1 bytes can be shipped without their producer
            # Git checkout. The original logical path remains in the report.
            logical_engine, binding = next(iter(
                legacy_engine_source_bindings().items()))
            preserved_engine = os.path.join(installed, "preserved-engine")
            materialise_legacy_engine_source(binding, preserved_engine)
            engine_report = {
                "path_base": native_report["path_base"],
                "evidence": {"validation_class": "native"},
                "inputs": {"engine_source": {
                    "path": logical_engine, "sha256": binding["sha256"]}}}
            with patch.object(A, "validate_legacy_engine_source_bindings",
                              side_effect=AssertionError("producer Git read")):
                _, engine_paths = _saved_report_paths(
                    engine_report, installed_report,
                    input_paths={"engine_source": preserved_engine})
            check("a relocated native enumerator is validated from preserved "
                  "bytes at its original report pin without producer Git",
                  engine_paths == {"engine_source": preserved_engine}
                  and sha256_file(preserved_engine) == binding["sha256"])

        # (4) MA3 legacy -- review correction 9 / finding 6.  The producer
        #     refuses `--require-release-ready` for a legacy class (it is not
        #     native and never becomes native), and the frozen index being
        #     COMPLETE forces it to record `audit_attestation` anyway.  The
        #     reader must therefore accept that key for this class, or
        #     `require_release_ready=True` is unsatisfiable forever.
        legacy_out = wpath("legacy.validation.json")
        legacy_rc = produce(common_argv + legacy_argv + [
            "--out", legacy_out, "--manifest", manifest_path,
            "--audit-attestation", audit_path])
        legacy_facts = validate_saved_validation_report(
            legacy_out, expected_validation_class="legacy_consistency",
            require_release_ready=True)
        _, _, legacy_paths = load_validated_saved_report(legacy_out)
        check("explicit native locations do not change the historical reader",
              refused(lambda: validate_saved_validation_report(
                  legacy_out, input_paths=legacy_paths), "require native evidence"))
        with open(legacy_out, encoding="utf-8") as fh:
            legacy_report = json.load(fh)
        legacy_evidence = legacy_report["evidence"]
        check("MA3: a LEGACY_CONSISTENCY report with its audit attestation "
              "reads back release-ready -- the §8.2 deadlock is broken",
              legacy_rc == 0
              and legacy_facts["validation_class"] == "legacy_consistency"
              and legacy_facts["release_ready"] is True
              and "audit_attestation" in legacy_report["inputs"],
              str(legacy_facts))
        check("MA3: and admitting that key PROMOTES NOTHING -- the legacy "
              "evidence stays explicitly non-native (caveat AC1, by "
              "execution rather than by reading)",
              legacy_evidence["validation_class"] == "legacy_consistency"
              and legacy_evidence["native_provenance"] is False
              and legacy_evidence["historical_manifest_digest_present"]
              is False
              and legacy_report["legacy_raw_map"] is not None
              and legacy_report["materialisation_audit"] == world_audit
              and refused(lambda: validate_saved_validation_report(
                  legacy_out, expected_validation_class="native",
                  require_release_ready=True), "expected 'native'"))
        check("MA6: the real saved-report LOADER returns revalidated facts, "
              "the exact report and its re-hashed input paths",
              all(loaded[0]["release_ready"] is True
                  and loaded[1]["status"] == "valid"
                  and os.path.isfile(loaded[2]["audit_attestation"])
                  and loaded[2]["asset_index"] == world_index_path
                  for loaded in (
                      load_validated_saved_report(
                          native_out, expected_validation_class="native",
                          require_release_ready=True),
                      load_validated_saved_report(
                          legacy_out,
                          expected_validation_class="legacy_consistency",
                          require_release_ready=True))))
        check("MA6: and the legacy SCORING loader -- which hard-codes "
              "require_release_ready=True -- reconstructs the same world",
              load_validated_legacy_scoring_inputs(
                  legacy_out)["expected_pairs"]
              == {("item-1", world_mutant["id"])})
        # Caveat AC1, settled by execution rather than by reading.
        for label, target in (("map", map_path),
                              ("raw_manifest", manifest_path),
                              ("asset_index", world_index_path)):
            with open(target, "rb") as fh:
                original_bytes = fh.read()
            with open(target, "ab") as fh:
                fh.write(b"\n")
            rehashed = refused(
                lambda: validate_saved_validation_report(
                    legacy_out, require_release_ready=True),
                f"saved report input {label} SHA-256")
            with open(target, "wb") as fh:
                fh.write(original_bytes)
            check(f"AC1 leg 1: the legacy reader re-hashes its {label} input "
                  "-- a post-hoc edit of those bytes refuses",
                  rehashed and validate_saved_validation_report(
                      legacy_out, require_release_ready=True)["status"]
                  == "valid")
        check("AC1 leg 2: the legacy binding reports engine identity from "
              "the PRESERVED manifest and the frozen index, not from a "
              "current runtime probe",
              legacy_report["asset_index"]["raw_manifest"]["engine"]
              == world_manifest["engine"]
              == world_index["projects"]["fixture"]["engine"]
              and legacy_report["asset_index"]["raw_manifest"]["parser"]
              == world_manifest["parser"]
              and legacy_report["evidence"]["manifest_digest"]
              == world_manifest["digest"])

        # (4b) THE SUBSET-MODE POPULATION JOIN, through the real campaign
        #     asset gate.  Under C5 the Slice-3 seam hands `release_path` a
        #     PAID VIEW of the population the map was built over; the
        #     report's release pin keeps naming the population document and
        #     must be verified against those exact bytes -- never skipped,
        #     never retargeted at the view.
        campaign_args = dict(
            manifest_path=manifest_path, map_path=map_path,
            release_path=release_path, require_release_ready=True)
        baseline_assets = validate_campaign_asset_inputs(
            native_out, **campaign_args)
        check("CA1: the existing single-document caller shape is unchanged "
              "-- population handed as release_path, default mode, admitted",
              baseline_assets["asset_project"] == "fixture"
              and baseline_assets["release_items"] == 1)
        paid_view_path = write_jsonl(
            "paid_view.jsonl", [{"item_id": "item-1", "paid_view": True}])
        check("CA2: a paid view with view-specific bytes is REFUSED in "
              "default mode on the release byte pin -- the pin still binds "
              "every caller that hands the population itself",
              refused(lambda: validate_campaign_asset_inputs(
                  native_out, manifest_path=manifest_path,
                  map_path=map_path, release_path=paid_view_path,
                  require_release_ready=True),
                      "campaign release input SHA-256"))
        subset_assets = validate_campaign_asset_inputs(
            native_out, manifest_path=manifest_path, map_path=map_path,
            release_path=paid_view_path, require_release_ready=True,
            paid_view_subset=True)
        check("CA3: subset mode ADMITS the same view because the pin is "
              "verified against the population document the report names, "
              "resolved from its own validated inputs",
              subset_assets["asset_project"] == "fixture"
              and subset_assets["map"] == world_map
              and subset_assets["release_items"] == 1)
        check("CA4: subset mode still refuses a view naming an item no "
              "mutant covers -- the surviving containment direction",
              refused(lambda: validate_campaign_asset_inputs(
                  native_out, manifest_path=manifest_path,
                  map_path=map_path,
                  release_path=write_jsonl(
                      "paid_view_uncovered.jsonl",
                      [{"item_id": "item-1"}, {"item_id": "item-9"}]),
                  require_release_ready=True, paid_view_subset=True),
                      "item-9"))
        with open(release_path, "rb") as fh:
            population_bytes = fh.read()
        with open(release_path, "ab") as fh:
            fh.write(b"\n")
        population_changed = refused(
            lambda: validate_campaign_asset_inputs(
                native_out, manifest_path=manifest_path, map_path=map_path,
                release_path=paid_view_path, require_release_ready=True,
                paid_view_subset=True),
            "release SHA-256")
        with open(release_path, "wb") as fh:
            fh.write(population_bytes)
        os.replace(release_path, release_path + ".moved")
        try:
            population_absent = refused(
                lambda: validate_campaign_asset_inputs(
                    native_out, manifest_path=manifest_path,
                    map_path=map_path, release_path=paid_view_path,
                    require_release_ready=True, paid_view_subset=True),
                "regular file")
        finally:
            os.replace(release_path + ".moved", release_path)
        check("CA5: a population document whose bytes moved after pinning "
              "REFUSES on the sha -- subset mode never relaxes the pin",
              population_changed)
        check("CA6: an absent population document REFUSES -- fail closed, "
              "no skip-the-pin fallback",
              population_absent)
        check("CA7: after restoration both modes admit again, so the "
              "probes mutated nothing",
              validate_campaign_asset_inputs(
                  native_out, **campaign_args)["release_items"] == 1
              and validate_campaign_asset_inputs(
                  native_out, manifest_path=manifest_path,
                  map_path=map_path, release_path=paid_view_path,
                  require_release_ready=True,
                  paid_view_subset=True)["release_items"] == 1)
        check("CA8: subset mode handed the population document itself "
              "(byte-equal to the pin) collapses to the strict default "
              "semantics -- identical facts, so a scoring caller may key "
              "the flag on bound-observation evidence without moving any "
              "population-handing campaign's answer",
              validate_campaign_asset_inputs(
                  native_out, manifest_path=manifest_path,
                  map_path=map_path, release_path=release_path,
                  require_release_ready=True, paid_view_subset=True)
              == baseline_assets)

        # (4c) THE BUDGETED DERIVED MAP against a report this producer
        #      actually wrote.  What the restriction means, and that the map
        #      handed back is the budget's, are proved in `data.subsets` and
        #      `bench.cli` over a population that HAS more than one mutant
        #      per item; this world has one, so what it can prove is the
        #      other half: which parent the sidecar is checked against, and
        #      that a caller without a sidecar is exactly where it was.
        from ..data import subsets as SUB
        from . import subset_writer as SW
        recollected_map_path = write_json("recollected_map.json",
                                          recollected_map)
        stranger = SUB.budgeted_sample(release_path, recollected_map_path,
                                       manifest_path, 1, 1)
        stranger_map, stranger_sidecar = SW.write_budgeted_sample(
            stranger, wpath("stranger_sample"))
        check("CB1: a sidecar drawn from ANOTHER parent map is refused "
              "against the parent THIS campaign's report pins -- the map a "
              "budget is checked against is never the one handed in",
              refused(lambda: validate_campaign_asset_inputs(
                  native_out, manifest_path=manifest_path,
                  map_path=stranger_map, release_path=release_path,
                  require_release_ready=True,
                  budgeted_sidecar=stranger_sidecar),
                  "different population"))
        check("CB2: and with no sidecar the gate returns exactly what it "
              "returned before a budget existed -- same value, same key "
              "set, no basis key for a reader to find",
              validate_campaign_asset_inputs(native_out, **campaign_args)
              == baseline_assets
              and set(baseline_assets) == {
                  "validation_class", "validation_sha256",
                  "asset_index_sha256", "asset_project",
                  "n_non_production_excluded", "manifest", "map",
                  "release_items"})

        # (5) MA4: a complete index without the attestation refuses, at the
        #     producer and at the reader.
        check("MA4: the producer refuses to bind a COMPLETE index when no "
              "audit attestation is supplied",
              exit_refused(common_argv + [
                  "--out", wpath("no-audit.validation.json"),
                  "--manifest", manifest_path, "--require-release-ready"],
                  "attestation was not supplied"))
        check("MA4: ...for the legacy class too, which is what forces the "
              "producer to record the key at all",
              exit_refused(common_argv + legacy_argv + [
                  "--out", wpath("no-audit-legacy.validation.json"),
                  "--manifest", manifest_path],
                  "attestation was not supplied"))
        for label, produced in (("native", native_out),
                                ("legacy", legacy_out)):
            with open(produced, encoding="utf-8") as fh:
                stripped_report = json.load(fh)
            stripped_report["inputs"].pop("audit_attestation")
            stripped_path = write_json(
                f"{label}-no-audit-input.json", stripped_report)
            check(f"MA4: a saved {label} report that drops its audit input "
                  "under a complete index refuses at the reader",
                  refused(lambda path=stripped_path:
                          validate_saved_validation_report(
                              path, require_release_ready=True),
                          "omits its audit attestation"))
            with open(produced, encoding="utf-8") as fh:
                widened_report = json.load(fh)
            widened_report["inputs"]["surprise"] = {
                "path": map_path, "sha256": sha256_file(map_path)}
            widened_path = write_json(f"{label}-unknown-input.json",
                                      widened_report)
            check(f"MA4: admitting `audit_attestation` for the {label} class "
                  "widened nothing else -- an unknown input still refuses",
                  refused(lambda path=widened_path:
                          validate_saved_validation_report(
                              path, require_release_ready=True),
                          "unknown=['surprise']"))
            # The attestation's OWN bytes, execution-proven like its three
            # siblings above: requiring the input is worth nothing if the
            # document it names could be swapped after the report was
            # written.
            with open(audit_path, "rb") as fh:
                attestation_bytes = fh.read()
            with open(audit_path, "ab") as fh:
                fh.write(b"\n")
            attestation_rehashed = refused(
                lambda path=produced: validate_saved_validation_report(
                    path, require_release_ready=True),
                "saved report input audit_attestation SHA-256")
            with open(audit_path, "wb") as fh:
                fh.write(attestation_bytes)
            check(f"MA4: the {label} reader re-hashes the ATTESTATION's own "
                  "bytes -- appending one byte to it refuses the read",
                  attestation_rehashed
                  and validate_saved_validation_report(
                      produced, require_release_ready=True)["status"]
                  == "valid")
    # -- the Behat/PHP audit, run INSIDE the pool's image ------------------
    #
    # The host route needs the interpreter the population was enumerated
    # with.  No sprint host has `php`, and the pool image that does is the
    # one the manifest's parser identity came from.  A fake runner stands in
    # for `DockerRunner` below: it RECORDS the transport it is handed and
    # then does what the applier would have done, so these checks are about
    # container paths, the one environment variable and the image binding --
    # never about `mutate.php`, which is not executed anywhere here.
    from types import SimpleNamespace
    from unittest.mock import patch
    from ..bench.mutation_run import binding_for as bound_engine

    php_engine_dir, php_applier = bound_engine(M.ENGINE)
    php_engine_source = os.path.join(php_engine_dir, php_applier.source)
    php_parser = "nikic/php-parser v5.3.1@0d1a1c1fixture"

    #: The PHP argument protocol, including valueless flags.
    applier_value_flags = (
        "--root", "--path", "--out", "--apply-file", "--start-line",
        "--start-col", "--operator", "--original", "--mutated",
        "--operator-profile")
    applier_boolean_flags = ("--record-enumerator-rev", "--validity-probe",
                             "--parse-only")

    #: Two `mutated` texts no enumerator can produce, so a k-way fixture
    #: walk can be given a population that fails at KNOWN manifest indices --
    #: and, with the earlier one slow, one whose earliest failure in manifest
    #: order is deliberately NOT the first failure in wall-clock time.
    FIXTURE_APPLIER_REFUSES = "\x01fixture-applier-refuses\x01"
    FIXTURE_APPLIER_REFUSES_SLOWLY = "\x01fixture-applier-refuses-slowly\x01"

    def fake_applier(php_argv, host_root):
        """`mutate.php`'s own argument loop, then what it would have done.

        `php_argv` is the interpreter's `$argv`, whose element 0 is the
        SCRIPT.  Modelling `array_slice($argv, 1)` and the `default:` arm of
        `mutate.php:149-165` exactly is the point of this function: a vector
        one token out of step leaves a path where a flag belongs, and the
        engine exits 2 rather than mutating anything.  A fake that scanned
        for `--` tokens instead could not see that, and did not.
        """
        arguments = list(php_argv[1:])
        options, index = {}, 0
        while index < len(arguments):
            token = arguments[index]
            if token in applier_value_flags:
                if index + 1 >= len(arguments):
                    return SimpleNamespace(
                        returncode=2, stdout="",
                        stderr=f"argument {token} needs a value\n")
                options[token[2:]] = arguments[index + 1]
                index += 2
            elif token in applier_boolean_flags:
                options[token[2:]] = True
                index += 1
            else:
                return SimpleNamespace(returncode=2, stdout="",
                                       stderr=f"unknown argument {token}\n")
        # Two fixture sentinels, so a k-way walk can be given a population
        # that fails at a KNOWN index and one that breaks the transport
        # itself.  Neither is reachable from a real mutant: a `mutated` text
        # is source, and these are not.
        if options.get("mutated") in (FIXTURE_APPLIER_REFUSES,
                                      FIXTURE_APPLIER_REFUSES_SLOWLY):
            if options["mutated"] == FIXTURE_APPLIER_REFUSES_SLOWLY:
                time.sleep(0.2)
            return SimpleNamespace(returncode=7, stdout="",
                                   stderr="fixture applier refuses\n")
        if "apply-file" in options:
            target = os.path.join(host_root, options["apply-file"])
            with open(target, "rb") as handle:
                data = handle.read()
            offset = _line_offset(data, int(options["start-line"]),
                                  int(options["start-col"]))
            original = options["original"].encode()
            assert data[offset:offset + len(original)] == original, (
                "fixture mutant does not name the bytes it replaces")
            with open(os.path.join(host_root, options["out"]), "wb") as handle:
                handle.write(data[:offset] + options["mutated"].encode()
                             + data[offset + len(original):])
        else:
            with open(os.path.join(host_root, options["out"]), "w",
                      encoding="utf-8") as handle:
                json.dump({"parser": php_reported, "errors": []}, handle)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    class FakePoolSession:
        """`IsolatedPhpSession`'s surface: ONE container, one exec per call."""

        def __init__(self, pool, *, name, workspace_host):
            self.pool = pool
            self.name = name
            self.workspace_host = workspace_host
            self.opened = True

        def _host(self, runtime_path):
            """The host path a container path names, through the one mount."""
            assert runtime_path.startswith(self.pool.workdir + "/"), \
                runtime_path
            return os.path.join(
                self.workspace_host,
                runtime_path[len(self.pool.workdir):].lstrip("/"))

        def run(self, argv, *, env=None, timeout=900):
            assert self.opened, "exec into a closed session"
            # A worker executing against ITS OWN copy's parser lock, and
            # rewriting it -- which nothing outside that copy can see.
            if self.pool.tamper_copy_lock \
                    and self.workspace_host != self.pool.host_root:
                self.pool.tamper_copy_lock = False
                with open(os.path.join(self.workspace_host, "composer.lock"),
                          "w", encoding="utf-8") as handle:
                    json.dump({"packages": [{
                        "name": "nikic/php-parser", "version": "v4.19.4",
                        "dist": {"reference": "tampered"}}]}, handle)
            with self.pool.ledger:
                self.pool.calls.append(("exec", self.name, list(argv),
                                        dict(env or {}), self.workspace_host))
            # THE AUTHORITY'S OWN RULE, applied to what Docker would be
            # handed: `core.docker_cli.docker_argv` refuses an empty or
            # NUL-bearing token.  A deletion-shaped mutant has an empty one,
            # which is why the vector travels in a file.
            assert all(isinstance(part, str) and part and "\0" not in part
                       for part in argv), argv
            assert len(argv) == 3 \
                and argv[1].startswith(self.pool.workdir + "/") \
                and argv[2].startswith(self.pool.workdir + "/"), argv
            assert self.workspace_host not in " ".join(argv), argv
            with open(self._host(argv[2]), encoding="utf-8") as handle:
                descriptor = json.load(handle)
            assert descriptor["schema"] == APPLIER_ARGV_SCHEMA, descriptor
            with self.pool.ledger:
                self.pool.vectors.append((self.name,
                                          list(descriptor["argv"])))
            return fake_applier(descriptor["argv"], self.workspace_host)

        def close(self):
            if not self.opened:
                return
            self.opened = False
            with self.pool.ledger:
                self.pool.calls.append(("close", self.name))

    class FakePoolRunner:
        """`DockerRunner`'s isolated-PHP surface, and nothing else."""

        def __init__(self, host_root, *, image, probe_rc=0,
                     probe_text="PHP 8.3.6 (cli) (built: fixture)",
                     sessions_before_failure=None,
                     tamper_copy_lock=False):
            self.workdir = "/work"
            self.host_root = host_root
            self.image = image
            self.probe_rc = probe_rc
            self.probe_text = probe_text
            self.sessions_before_failure = sessions_before_failure
            self.tamper_copy_lock = tamper_copy_lock
            self.calls = []
            self.sessions = []
            self.vectors = []
            self.ledger = threading.Lock()

        def _image_for_isolated_run(self):
            return self.image

        def probe_isolated_php_toolchain(self, *, interpreter="php",
                                         timeout=120):
            self.calls.append(("probe", interpreter))
            return SimpleNamespace(returncode=self.probe_rc,
                                   stdout=self.probe_text, stderr="")

        def open_isolated_php_session(self, *, workspace_host,
                                      interpreter="php", timeout=300):
            if self.sessions_before_failure is not None \
                    and len(self.sessions) >= self.sessions_before_failure:
                raise RuntimeError(
                    "REFUSED: the isolated PHP audit session container did "
                    "not start (fixture)")
            assert os.path.isdir(workspace_host), workspace_host
            name = f"r2t-php-session-fixture-{len(self.sessions):03d}"
            session = FakePoolSession(self, name=name,
                                      workspace_host=workspace_host)
            self.sessions.append(session)
            self.calls.append(("open", name, interpreter, workspace_host))
            return session

    with tempfile.TemporaryDirectory(prefix="r2t-php-in-image-") as php_temp:
        # One level below the fixture's temporary directory ON PURPOSE: a
        # k-way audit copies the root BESIDE itself, and if the root's parent
        # were TMPDIR a copy made under TMPDIR instead would be
        # indistinguishable from a copy made beside the root.
        php_root = os.path.join(os.path.realpath(php_temp), "audit-copy")
        os.makedirs(os.path.join(php_root, "src"))
        os.makedirs(os.path.join(php_root, "vendor"))
        with open(os.path.join(php_root, "src", "Money.php"), "wb") as handle:
            handle.write(b"<?php\nreturn $a + $b;\n"
                         b"if (!$c) { return 0; }\n$d = 'x';\n")
        # Eight identical mutable sites on eight lines: a population long
        # enough to be dealt across shards, and one whose fifth member can be
        # made to fail at a KNOWN manifest index.
        with open(os.path.join(php_root, "src", "Batch.php"), "wb") as handle:
            handle.write(b"<?php\n" + b"$x = 1 + 1;\n" * 8)
        with open(os.path.join(php_root, "vendor", "autoload.php"),
                  "w", encoding="utf-8") as handle:
            handle.write("<?php // fixture autoloader\n")
        with open(os.path.join(php_root, "composer.lock"), "w",
                  encoding="utf-8") as handle:
            json.dump({"packages": [{
                "name": "nikic/php-parser", "version": "v5.3.1",
                "dist": {"reference": "0d1a1c1fixture"}}]}, handle)
        with open(os.path.join(php_root, DISPOSABLE_MARKER), "w",
                  encoding="utf-8") as handle:
            handle.write(DISPOSABLE_MARKER_CONTENT)
        # Three mutants, and two of them are the reason this route needed a
        # descriptor at all: a DELETION (`RemoveNegation` mutates `!` to the
        # empty string -- 930 of them in the Sylius population, and the first
        # one killed the live audit at mutant 183) and one carrying quotes, a
        # newline, `$`, backticks and a leading `-`.
        hostile = "-x $a `b` \"q\" 'r'\nnewline"
        php_manifest = M.build_manifest(
            [{"file": "src/Money.php", "operator": "ArithmeticOperator",
              "start_line": 2, "start_col": 11,
              "original": "+", "mutated": "-"},
             {"file": "src/Money.php", "operator": "RemoveNegation",
              "start_line": 3, "start_col": 5,
              "original": "!", "mutated": ""},
             {"file": "src/Money.php", "operator": "ConstantReplacement",
              "start_line": 4, "start_col": 6,
              "original": "'x'", "mutated": hostile}],
            parser_version=php_parser, operators=M.OPERATORS,
            exclusions=("!src", "vendor/"))
        php_reported = expected_runtime_parser(php_manifest)
        assert M.read_parser_version(
            os.path.join(php_root, "composer.lock")) == php_parser

        image_id = "sha256:" + "b" * 64
        pool = FakePoolRunner(php_root, image=image_id)
        in_image = audit_with_engine(php_manifest, php_root, runner=pool,
                                     expected_image_id=image_id)
        gate = in_image["operator_gate"]
        check("a Behat/PHP population audits completely inside the pool "
              "image -- deletion-shaped and hostile-text mutants included",
              in_image["status"] == "complete"
              and in_image["n_mutants"] == in_image["n_attempted"]
              == in_image["n_applied"] == in_image["n_parse_valid"]
              == in_image["n_restored"] == 3
              and in_image["bounded_roots"] == ["src"]
              and in_image["n_source_files"] == 2
              and in_image["source_set_sha256_before"]
              == in_image["source_set_sha256_after"]
              and in_image["digest"] == audit_digest(in_image)
              and gate["mode"] == "real_engine"
              and gate["runtime_parser_identity"] == php_parser
              and gate["runtime_parser_reported"] == php_reported
              and gate["engine_source_sha256"]
              == sha256_file(php_engine_source),
              str(in_image.get("failure")))
        check("bundled PHP audit parses the materialized file without "
              "enumerating its sibling mutants",
              all(("--parse-only" in vector) == ("--path" in vector)
                  for _name, vector in pool.vectors))
        with tempfile.TemporaryDirectory(prefix="r2t_preserved_php_") as preserved:
            preserved_engine = os.path.join(preserved, "mutate.php")
            shutil.copyfile(php_engine_source, preserved_engine)
            preserved_pool = FakePoolRunner(php_root, image=image_id)
            preserved_report = audit_with_engine(
                php_manifest, php_root, engine_source_path=preserved_engine,
                runner=preserved_pool, expected_image_id=image_id)
            check("an explicitly preserved copy of current PHP bytes uses "
                  "parse-only too",
                  preserved_report["status"] == "complete"
                  and any("--parse-only" in vector
                          for _name, vector in preserved_pool.vectors))
            # A separately preserved producer may predate parse-only. The
            # old enumeration protocol remains the supported fallback.
            with open(preserved_engine, "a", encoding="utf-8") as handle:
                handle.write("\n// separately preserved producer\n")
            older_pool = FakePoolRunner(php_root, image=image_id)
            older_report = audit_with_engine(
                php_manifest, php_root, engine_source_path=preserved_engine,
                runner=older_pool, expected_image_id=image_id)
            check("unknown preserved PHP bytes retain their original "
                  "enumeration protocol",
                  older_report["status"] == "complete"
                  and all("--parse-only" not in vector
                          for _name, vector in older_pool.vectors))
        execs = [call for call in pool.calls if call[0] == "exec"]
        opens = [call for call in pool.calls if call[0] == "open"]
        scratch_rel = os.path.dirname(php_applier.rel).replace(os.sep, "/")
        check("Docker is handed the interpreter and two constant paths -- "
              "never a mutant's text, and never an empty token",
              [call for call in pool.calls if call[0] == "probe"]
              == [("probe", php_applier.interpreter)]
              and len(execs) == 6
              and all(argv == [php_applier.interpreter,
                               f"/work/{scratch_rel}/{APPLIER_SHIM_BASENAME}",
                               f"/work/{scratch_rel}/{APPLIER_ARGV_BASENAME}"]
                      and env == {"R2T_PHP_AUTOLOAD":
                                  "/work/vendor/autoload.php"}
                      and workspace == php_root
                      for _kind, _name, argv, env, workspace in execs),
              str(execs[:1]))
        # THE COST THIS ROUTE EXISTS TO REMOVE.  Track S measured the
        # per-invocation shape at ~2.5 s per mutant in the Sylius image --
        # two container starts each, 43,670 mutants, about 30 h.  A whole
        # audit now starts ONE container per audited tree and drives it with
        # execs.
        check("the audit starts one container per disposable copy, not two "
              "per mutant",
              len(opens) == 1 and len(execs) == 2 * php_manifest["n"]
              and [call[0] for call in pool.calls][:2] == ["probe", "open"]
              and pool.calls[-1] == ("close", opens[0][1])
              and opens[0][2] == php_applier.interpreter
              and opens[0][3] == php_root
              and all(not session.opened for session in pool.sessions),
              str([call[0] for call in pool.calls]))
        # The rule that made the descriptor necessary, stated over the exact
        # vectors this population produces: as bare Docker arguments the
        # deletion mutant is an EMPTY token, which the authority refuses.
        deletion = [row for row in php_manifest["mutants"]
                    if row["operator"] == "RemoveNegation"][0]
        bare_argv = [php_applier.interpreter, "/work/x/mutate.php",
                     "--root", "/work", "--apply-file", deletion["file"],
                     "--operator", deletion["operator"],
                     "--original", deletion["original"],
                     "--mutated", deletion["mutated"]]
        check("as bare Docker arguments this population WOULD be refused: "
              "the authority's own token rule rejects the deletion mutant",
              deletion["mutated"] == ""
              and any(not token for token in bare_argv)
              and not any(not token for call in execs for token in call[2]))
        check("the descriptor lives in the audit's own private scratch -- "
              "inside the one mount, outside the bounded source set, and "
              "gone with the scratch",
              scratch_rel.split("/")[0] not in in_image["bounded_roots"]
              and not os.path.exists(os.path.join(
                  php_root, scratch_rel, APPLIER_ARGV_BASENAME))
              and not os.path.exists(os.path.join(
                  php_root, scratch_rel, APPLIER_SHIM_BASENAME))
              and not os.path.isdir(os.path.join(php_root, scratch_rel))
              and in_image["collateral"] == {
                  "added": [], "changed": [], "deleted": []},
              str(in_image["bounded_roots"]))

        # The host route, byte for byte.  `php` is absent here, so the
        # interpreter lookup and the subprocess are both stood in for -- the
        # POINT is the argv and env they are handed, which must still be the
        # host's paths, and the report, which must be identical.
        host_calls = []

        def host_subprocess(argv, **kwargs):
            host_calls.append((list(argv), dict(kwargs.get("env") or {})))
            # What the OS hands PHP: the interpreter is consumed, `$argv[0]`
            # is the script.  The same vector the descriptor now carries.
            return fake_applier(argv[1:], php_root)

        with patch.object(shutil, "which", lambda *a, **k: "/usr/bin/php"), \
                patch.object(subprocess, "run", host_subprocess):
            host_report = audit_with_engine(php_manifest, php_root)
        host_argv, host_env = host_calls[0]
        check("with no runner the host route is unchanged: host paths in the "
              "argv, the host autoloader in the env, the same report -- and "
              "the mutant's own text still travels as a bare argument there",
              len(host_calls) == 6
              and any(not token for token in
                      [part for argv, _env in host_calls for part in argv])
              and host_argv[0] == php_applier.interpreter
              and host_argv[1] == os.path.join(php_root, php_applier.rel)
              and host_argv[host_argv.index("--root") + 1] == php_root
              and host_env["R2T_PHP_AUTOLOAD"]
              == os.path.join(php_root, "vendor", "autoload.php")
              and host_env.get("PATH") == os.environ.get("PATH")
              and host_report == in_image,
              str(host_argv[:4]))

        check("a host with no interpreter refuses by name, and names the "
              "worker binding that does have one",
              refused(lambda: audit_with_engine(php_manifest, php_root),
                      "mutants validate --audit-root")
              and refused(lambda: audit_with_engine(php_manifest, php_root),
                          "has no 'php' on PATH"))
        check("an audit runner pointed at another image is refused",
              refused(lambda: audit_with_engine(
                  php_manifest, php_root,
                  runner=FakePoolRunner(php_root,
                                        image="sha256:" + "c" * 64),
                  expected_image_id=image_id),
                  "sidecar image differs from the bound pool image"))
        check("a mutable tag is not an image binding",
              refused(lambda: audit_with_engine(
                  php_manifest, php_root, runner=pool,
                  expected_image_id="sylius-pool:latest"),
                  "immutable image ID"))
        check("an image id without a runner is refused rather than ignored",
              refused(lambda: audit_with_engine(
                  php_manifest, php_root, expected_image_id=image_id),
                  "no runner was given"))
        probe_failed = FakePoolRunner(php_root, image=image_id, probe_rc=127,
                                      probe_text="php: not found")
        check("a failing interpreter probe refuses BEFORE the population "
              "walk, so a whole audit does not die one mutant at a time",
              refused(lambda: audit_with_engine(
                  php_manifest, php_root, runner=probe_failed,
                  expected_image_id=image_id),
                  "toolchain probe failed")
              and probe_failed.calls == [("probe", php_applier.interpreter)])
        check("this transport refuses a population whose applier is not the "
              "one it knows how to run",
              refused(lambda: audit_with_engine(
                  java_manifest, java_root, runner=pool,
                  expected_image_id=image_id),
                  "cannot run a 'r2t-mutate-java' population's applier"))

        # THE TWO ASSUMPTIONS THE SHIM RESTS ON, and neither is executable
        # here -- this host has no `php`, which is the whole reason the
        # in-image route exists.  Both are statements about source bytes, and
        # both would otherwise fail LIVE, one mutant at a time: the engine
        # reads the global `$argv` (a move to `getopt()` would read the real
        # command line and silently see no arguments at all), and the shim
        # names the schema the audit writes.
        with open(php_engine_source, encoding="utf-8") as handle:
            engine_text = handle.read()
        with open(os.path.join(php_engine_dir, APPLIER_SHIM_BASENAME),
                  encoding="utf-8") as handle:
            shim_text = handle.read()
        check("the engine still reads the global $argv the shim replaces, "
              "and does not read the real command line behind its back",
              "array_slice($argv, 1)" in engine_text
              and "getopt(" not in engine_text
              and "$_SERVER['argv']" not in engine_text)
        check("the shim requires the engine staged beside it and admits only "
              "the descriptor schema the audit writes",
              f"'{APPLIER_ARGV_SCHEMA}'" in shim_text
              and "require __DIR__ . '/" + php_applier.source + "'"
              in shim_text)

        # -- the k-way walk, the whole point of the session transport ------
        #
        # Ported from the Java route, and its semantics are NOT reimplemented
        # here: `audit_population` deals the manifest so every mutant is
        # attempted exactly once, reports the EARLIEST failing mutant in
        # manifest order whatever shard reached it first, and discloses the
        # tree count in an additive `parallel_audit` block that
        # `validate_completed_audit_binding` already knows.  What W12 adds is
        # the transport underneath it: k copies of the one `--audit-root`,
        # one session container each.
        batch_rows = [{"file": "src/Batch.php",
                       "operator": "ArithmeticOperator",
                       "start_line": line, "start_col": 8,
                       "original": "+", "mutated": "-"}
                      for line in range(2, 10)]
        batch_manifest = M.build_manifest(
            batch_rows, parser_version=php_parser, operators=M.OPERATORS,
            exclusions=("!src", "vendor/"))
        # Index 4 fails SLOWLY and index 6 fails at once, so with k = 3 the
        # first failure in wall-clock time is NOT the earliest failure in
        # manifest order.  The report must name index 4 either way.
        failing_rows = [dict(row) for row in batch_rows]
        failing_rows[4]["mutated"] = FIXTURE_APPLIER_REFUSES_SLOWLY
        failing_rows[6]["mutated"] = FIXTURE_APPLIER_REFUSES
        failing_manifest = M.build_manifest(
            failing_rows, parser_version=php_parser, operators=M.OPERATORS,
            exclusions=("!src", "vendor/"))

        sequential_pool = FakePoolRunner(php_root, image=image_id)
        sequential = audit_with_engine(
            batch_manifest, php_root, runner=sequential_pool,
            expected_image_id=image_id)
        with patch.object(shutil, "which", lambda *a, **k: "/usr/bin/php"), \
                patch.object(subprocess, "run", host_subprocess):
            batch_on_host = audit_with_engine(batch_manifest, php_root)
        check("k=1 in-image is the sequential route, byte for byte: the same "
              "population and the same root produce the report the host "
              "walk produces",
              canonical_sha256(sequential) == canonical_sha256(batch_on_host)
              and "parallel_audit" not in sequential
              and sequential["status"] == "complete"
              and sequential["n_attempted"] == batch_manifest["n"] == 8,
              str(sequential.get("failure")))

        kway_pool = FakePoolRunner(php_root, image=image_id)
        kway = audit_with_engine(
            batch_manifest, php_root, runner=kway_pool,
            expected_image_id=image_id, workers=3)
        kway_opens = [call for call in kway_pool.calls if call[0] == "open"]
        kway_execs = [call for call in kway_pool.calls if call[0] == "exec"]
        kway_roots = [call[3] for call in kway_opens]
        copies = kway_roots[1:]
        check("k copies of the ONE audit root, one session container each -- "
              "and a container start per copy, not two per mutant",
              len(kway_opens) == 3 and len(kway_execs) == 16
              and len(set(kway_roots)) == 3 and kway_roots[0] == php_root
              and all(os.path.dirname(os.path.dirname(copy))
                      == os.path.dirname(php_root) for copy in copies)
              and all(call[4] in kway_roots for call in kway_execs)
              and all(not session.opened for session in kway_pool.sessions)
              and len([call for call in kway_pool.calls
                       if call[0] == "close"]) == 3,
              str(kway_roots))
        check("the copies live beside the root -- a tmpfs audit root's "
              "copies stay on tmpfs -- and are gone with the audit",
              copies and not any(os.path.exists(copy) for copy in copies)
              and not any(os.path.exists(os.path.dirname(copy))
                          for copy in copies)
              and sorted(os.listdir(os.path.join(php_root, "src")))
              == ["Batch.php", "Money.php"],
              str(copies))
        applied = sorted(int(vector[vector.index("--start-line") + 1])
                         for _name, vector in kway_pool.vectors
                         if "--apply-file" in vector)
        check("every mutant is attempted exactly once across the shards, and "
              "the report accounts for every audited tree",
              applied == list(range(2, 10))
              and kway["parallel_audit"]["n_roots"] == 3
              and sum(kway["parallel_audit"]["mutants_by_root"])
              == kway["n_attempted"] == 8
              and len(kway_pool.vectors) == 16,
              str(applied))
        check("...and the k-way report IS the sequential report plus that "
              "one disclosure: no other field of the document moves",
              set(kway) - set(sequential) == {"parallel_audit"}
              and {key: value for key, value in kway.items()
                   if key not in ("parallel_audit", "digest")}
              == {key: value for key, value in sequential.items()
                  if key != "digest"}
              and kway["digest"] == audit_digest(kway),
              str(sorted(set(kway) - set(sequential))))

        # THE FAILURE SEMANTICS, reproduced from `audit_population`: the
        # failing mutant is the earliest in MANIFEST order, not the first to
        # fail in wall-clock time; and a failed k-way report's counters
        # include work other workers had already started, which its docstring
        # discloses rather than hides.
        def audit_failure(pool, manifest, **kwargs):
            try:
                audit_with_engine(manifest, php_root, runner=pool,
                                  expected_image_id=image_id, **kwargs)
            except MaterialisationAuditRefused as exc:
                return exc.report
            return None

        seq_fail_pool = FakePoolRunner(php_root, image=image_id)
        seq_fail = audit_failure(seq_fail_pool, failing_manifest)
        kway_fail_pool = FakePoolRunner(php_root, image=image_id)
        kway_fail = audit_failure(kway_fail_pool, failing_manifest, workers=3)
        fifth = failing_manifest["mutants"][4]["id"]
        check("a k-way walk reports the EARLIEST failing mutant in manifest "
              "order -- index 4, which fails SLOWLY, rather than index 6, "
              "which a later shard has already reported by then",
              seq_fail is not None and kway_fail is not None
              and seq_fail["failing_mutant_id"]
              == kway_fail["failing_mutant_id"] == fifth
              and seq_fail["failure_stage"] == kway_fail["failure_stage"]
              == "apply"
              and seq_fail["n_attempted"] == 5 and seq_fail["n_applied"] == 4,
              str((seq_fail or {}).get("failing_mutant_id")))
        check("...and the counters of a FAILED k-way report are the "
              "disclosed ones: work other workers had already started, every "
              "tree accounted for, nothing beyond the population",
              5 <= kway_fail["n_attempted"] <= failing_manifest["n"]
              and kway_fail["n_applied"] < kway_fail["n_attempted"]
              and sum(kway_fail["parallel_audit"]["mutants_by_root"])
              == kway_fail["n_attempted"]
              and kway_fail["n_restored"] == kway_fail["n_attempted"],
              str(kway_fail["n_attempted"]))
        check("every session container is closed on a failing mutant too, "
              "and no copy is left behind",
              all(not session.opened
                  for pool in (seq_fail_pool, kway_fail_pool)
                  for session in pool.sessions)
              and len([call for call in kway_fail_pool.calls
                       if call[0] == "close"]) == 3
              and not any(os.path.exists(call[3])
                          for call in kway_fail_pool.calls
                          if call[0] == "open" and call[3] != php_root))

        # An exception the walk cannot describe as a mutant refusal must
        # still leave no container holding a tree's read-write mount.
        exploded_pool = FakePoolRunner(php_root, image=image_id)

        def exploding_walk(*_args, **_kwargs):
            raise RuntimeError("fixture walk exploded mid-population")

        exploded = False
        with patch.object(sys.modules[__name__], "audit_population",
                          exploding_walk):
            try:
                audit_with_engine(batch_manifest, php_root,
                                  runner=exploded_pool,
                                  expected_image_id=image_id, workers=3)
            except RuntimeError as exc:
                exploded = "exploded mid-population" in str(exc)
        check("an exception mid-walk closes every session container the "
              "audit opened, and takes the copies with it",
              exploded and len(exploded_pool.sessions) == 3
              and all(not session.opened
                      for session in exploded_pool.sessions)
              and not any(os.path.exists(call[3])
                          for call in exploded_pool.calls
                          if call[0] == "open" and call[3] != php_root))

        half_open_pool = FakePoolRunner(php_root, image=image_id,
                                        sessions_before_failure=2)
        half_open = False
        try:
            audit_with_engine(batch_manifest, php_root,
                              runner=half_open_pool,
                              expected_image_id=image_id, workers=3)
        except RuntimeError as exc:
            half_open = "session container did not start" in str(exc)
        check("a session that fails to open closes the ones that did",
              half_open and len(half_open_pool.sessions) == 2
              and all(not session.opened
                      for session in half_open_pool.sessions))

        # THE TREES THE PRIMARY CANNOT SPEAK FOR.  Each worker ran the
        # applier against its OWN copy's autoloader and parser lock, over its
        # own read-write mount, and `vendor/` and `composer.lock` sit outside
        # the bounded source set the residue and collateral checks walk.
        tamper_pool = FakePoolRunner(php_root, image=image_id,
                                     tamper_copy_lock=True)
        check("a copy whose parser lock is rewritten mid-walk is caught: the "
              "post-walk re-authentication covers every audited tree, not "
              "just the primary",
              refused(lambda: audit_with_engine(
                  batch_manifest, php_root, runner=tamper_pool,
                  expected_image_id=image_id, workers=3),
                  "audit parser lock identity changed during materialisation")
              and not tamper_pool.tamper_copy_lock
              and all(not session.opened
                      for session in tamper_pool.sessions))

        check("k > 1 on the host route is refused by name, not silently "
              "walked in one tree",
              refused(lambda: audit_with_engine(
                  batch_manifest, php_root, workers=3),
                  "--audit-workers k")
              and refused(lambda: audit_with_engine(
                  batch_manifest, php_root, runner=pool,
                  expected_image_id=image_id, workers=0),
                  "worker count must be an integer >= 1"))

        # The deliverable: what W8's mint does with this report.
        from . import mutation_asset_index as ASSETS
        from ..data.mutation_attestation import canonical_bytes
        release_path = os.path.join(php_root, "release.jsonl")
        coverage_path = os.path.join(php_root, "gold.jsonl")
        with open(release_path, "w", encoding="utf-8") as handle:
            handle.write('{"item_id":"item-a"}\n')
        coverage_rows = [{"item_id": "item-a",
                          "coverage_lines": {"src/Money.php": [2]}}]
        with open(coverage_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(coverage_rows[0], sort_keys=True) + "\n")
        boundary_path = os.path.join(php_root, "boundary_fixture.yml")
        with open(boundary_path, "w", encoding="utf-8") as handle:
            handle.write("version: 1\nproject: fixture\n"
                         "repo_root: /nonexistent/fixture\n"
                         "removable:\n  - path: tests/\n"
                         "    why: the fixture's test code\nretained: []\n")
        manifest_path = os.path.join(php_root, "population.json")
        with open(manifest_path, "wb") as handle:
            handle.write(canonical_bytes(php_manifest) + b"\n")
        audit_path = os.path.join(php_root, "materialisation_audit.json")
        with open(audit_path, "wb") as handle:
            handle.write(canonical_bytes(in_image) + b"\n")
        by_mutant, uncovered = M.map_mutants_to_items(
            php_manifest, {"item-a": coverage_rows[0]["coverage_lines"]})
        map_path = os.path.join(php_root, "mutant_map.json")
        with open(map_path, "wb") as handle:
            handle.write(canonical_bytes(build_map_artifact(
                php_manifest, by_mutant, uncovered,
                coverage_sha256=sha256_file(coverage_path),
                release_sha256=sha256_file(release_path))) + b"\n")
        minted = os.path.join(php_root, "minted")
        os.mkdir(minted)
        answer = ASSETS.mint(
            "fixture", raw_manifest_path=manifest_path,
            scored_manifest_path=manifest_path, map_path=map_path,
            coverage_path=coverage_path, release_path=release_path,
            boundary_path=boundary_path, audit_path=audit_path,
            asset_index_out=os.path.join(minted, "asset_index.json"),
            validation_out=os.path.join(minted, "mutation_validation.json"))
        check("the in-image report is one the asset-index mint accepts, "
              "unchanged, as a completed materialisation audit",
              answer["audit_digest"] == in_image["digest"]
              and answer["scored_role"] == "raw_equals_scored"
              and answer["raw_n"] == 3)

        # ...and so is the k-way one: the `parallel_audit` block is additive
        # and already part of the attestation the frozen index binds.
        batch_coverage = [{"item_id": "item-a",
                           "coverage_lines": {"src/Batch.php":
                                              list(range(2, 10))}}]
        batch_coverage_path = os.path.join(php_root, "gold_batch.jsonl")
        with open(batch_coverage_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(batch_coverage[0], sort_keys=True) + "\n")
        batch_manifest_path = os.path.join(php_root, "population_batch.json")
        with open(batch_manifest_path, "wb") as handle:
            handle.write(canonical_bytes(batch_manifest) + b"\n")
        batch_audit_path = os.path.join(php_root, "audit_batch.json")
        with open(batch_audit_path, "wb") as handle:
            handle.write(canonical_bytes(kway) + b"\n")
        batch_by_mutant, batch_uncovered = M.map_mutants_to_items(
            batch_manifest, {"item-a": batch_coverage[0]["coverage_lines"]})
        batch_map_path = os.path.join(php_root, "mutant_map_batch.json")
        with open(batch_map_path, "wb") as handle:
            handle.write(canonical_bytes(build_map_artifact(
                batch_manifest, batch_by_mutant, batch_uncovered,
                coverage_sha256=sha256_file(batch_coverage_path),
                release_sha256=sha256_file(release_path))) + b"\n")
        batch_minted = os.path.join(php_root, "minted-batch")
        os.mkdir(batch_minted)
        batch_answer = ASSETS.mint(
            "fixture", raw_manifest_path=batch_manifest_path,
            scored_manifest_path=batch_manifest_path,
            map_path=batch_map_path, coverage_path=batch_coverage_path,
            release_path=release_path, boundary_path=boundary_path,
            audit_path=batch_audit_path,
            asset_index_out=os.path.join(batch_minted, "asset_index.json"),
            validation_out=os.path.join(batch_minted,
                                        "mutation_validation.json"))
        check("the k-way in-image report is one the mint accepts too, with "
              "its parallel-audit disclosure intact",
              batch_answer["audit_digest"] == kway["digest"]
              and batch_answer["raw_n"] == 8
              and _read_json_object(
                  os.path.join(batch_minted, "mutation_validation.json"),
                  "minted k-way validation report"
              )["materialisation_audit"]["parallel_audit"]["n_roots"] == 3)

    print("\n" + ("ALL PASS (mutation_audit)" if ok
                    else "FAILURES (mutation_audit)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
