"""Remote Go execution copy with host-held integrity and proved child cleanup.

The caller serializes the existing worker and owns seed/manifest verification,
context selection and trusted transforms. No container, mount, host source scan,
or baseline from observed candidate bytes is created here. GO_STACK_SPEC §6 and
GO_SUBSTRATE_SEED_DEPENDENCY_AMENDMENT own this lifecycle.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import math
import json
import stat
from pathlib import Path
import re
import shlex
import subprocess
import time

from ..bench.repo import (GO_SUBSTRATE_ROOTS, GO_SUBSTRATE_VOLATILE,
                          compare_substrate_inventory)
from .context import validate_suite_context

ORIGINAL_ROOT = "/work"
COPY_ROOT = "/r2t-go/run/work"
RUN_ROOT = "/r2t-go/run"
COMMAND_TIMEOUT = 600
# Retirement removes /r2t-go/run and /r2t-go/tmp after the command. A test that
# spins probing fresh names until its deadline leaves the kernel ~10^8 negative
# directory entries under its temporary tree, and removing that tree then took
# longer than the 30 s housekeeping bound (coddy full-gold supplement 2,
# 2026-09-30). This is housekeeping after the verdict, never test time.
RETIRE_TIMEOUT = 900
_COORDINATION = GO_SUBSTRATE_VOLATILE | {".r2t-exec.lock"}
_SUPPORT = Path(__file__).with_name("execution_support.sh").read_text()


class ExecutionRefused(RuntimeError):
    """An unproved lifecycle or integrity condition; never a scored answer."""


class ExecutionIntegrityError(ExecutionRefused):
    """Observed inventory differences, retaining phase and report objects."""

    def __init__(self, message, *, phase, scope, reports):
        super().__init__(message)
        self.phase, self.scope = phase, scope
        self.reports = copy.deepcopy(reports)


class ExecutionTimeout(subprocess.TimeoutExpired):
    """Deadline/monitor proof stays distinct from a transport timeout.

    The caller must also require successful cleanup/integrity and retirement;
    this exception alone never declares a scored timeout.
    """

    def __init__(self, cmd, *, basis, output=None, stderr=None):
        super().__init__(cmd, COMMAND_TIMEOUT, output=output, stderr=stderr)
        self.basis = basis


def _path(value):
    if (not isinstance(value, str) or not value or value.startswith("/")
            or "\\" in value or any(ord(c) < 32 for c in value)
            or any(p in {"", ".", ".."} for p in value.split("/"))):
        raise ExecutionRefused("REFUSED: invalid remote relative path")
    return value


def _digests(value):
    result = dict(value)
    for path, digest in result.items():
        _path(path)
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
            raise ExecutionRefused("REFUSED: invalid host-held inventory digest")
    return result


def _payload(text, kind):
    lines = text.splitlines()
    if (len(lines) != 3 or lines[0] != f"R2T_{kind}/1"
            or lines[2] != f"R2T_{kind}_END"):
        raise ExecutionRefused("REFUSED: incomplete remote " + kind.lower())
    try:
        return base64.b64decode(lines[1], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ExecutionRefused("REFUSED: corrupt remote " + kind.lower()) from error


def parse_inventory(text):
    """Parse a complete framed NUL inventory; no partial scan can be a baseline."""
    raw = _payload(text, "INVENTORY")
    if raw and not raw.endswith(b"\0"):
        raise ExecutionRefused("REFUSED: unterminated inventory")
    result = {}
    for row in raw.split(b"\0")[:-1]:
        if not re.fullmatch(b"[0-9a-f]{64}  \\./[^\\0]+", row):
            raise ExecutionRefused("REFUSED: malformed inventory entry")
        try:
            path = _path(row[68:].decode("utf-8"))
        except UnicodeError as error:
            raise ExecutionRefused("REFUSED: non-UTF-8 inventory path") from error
        if path in result:
            raise ExecutionRefused("REFUSED: duplicate inventory entry")
        result[path] = row[:64].decode("ascii")
    return result


def _clean(report):
    return not any(report[k] for k in ("changed", "missing", "added"))


class ExecutionCopy:
    """One serialized existing worker; integrity failure permanently quarantines it
    (``retire_unscorable`` is the one ruled exception).

    ``original_inventory`` is the complete independently verified stripped seed
    inventory, not a scan taken from a candidate-bearing remote workspace.
    The original manifest's protected inventory is a second, independent guard.
    A preparation admits one already-installed answer and exact trusted changes.
    The caller exports outputs after execute and calls retire before the next item.
    """

    def __init__(self, runner, *, original_inventory, boundary, original_manifest):
        self.runner = runner
        self.original_boundary = copy.deepcopy(boundary)
        self.copy_boundary = copy.deepcopy(boundary)
        self.copy_boundary.repo_root = COPY_ROOT
        self.original_manifest = copy.deepcopy(original_manifest)
        self.original_inventory = _digests(original_inventory)
        self.quarantined = False
        self.process_evidence = None
        self.mutation_evidence = None
        self.command_evidence = []
        self._state = "idle"
        self._context = None
        self._answer_paths = ()
        self._generated = set()
        self._expected = None
        self._deadline = None
        self._mutation_baseline = None
        self._expected_mutations = {}
        self._mutation_metadata = {}
        self._mutation_attempted = False
        self._mutation_reference_retired = False
        manifest = self.original_manifest
        if (tuple(manifest.substrate_roots) != GO_SUBSTRATE_ROOTS
                or frozenset(manifest.substrate_volatile) != GO_SUBSTRATE_VOLATILE
                or manifest.bytecode_roots or manifest.build_roots
                or not manifest.digests or boundary.project != "coddy-agent"):
            raise ExecutionRefused("REFUSED: missing or non-Go original manifest policy")
        self._original_baseline = {p: d for p, d in _digests(manifest.digests).items()
                                   if p not in GO_SUBSTRATE_VOLATILE}
        if not _clean(compare_substrate_inventory(
                self._original_baseline,
                self._protected(self.original_inventory, original=True))):
            raise ExecutionRefused("REFUSED: original manifest and verified seed differ")

    def _available(self):
        if self.quarantined:
            raise ExecutionRefused("REFUSED: Go worker is quarantined")

    def _refuse(self, message, *, scope=None, reports=None):
        self.quarantined = True
        message = "REFUSED: Go execution copy: " + message
        if reports is not None:
            raise ExecutionIntegrityError(message, phase=self._state,
                                          scope=scope, reports=reports)
        raise ExecutionRefused(message)

    def _call(self, verb, *args, timeout=30, input=None):
        command = ("exec /bin/bash -c " + shlex.quote(_SUPPORT)
                   + " r2t-execution " + shlex.join([verb, *args]))
        kwargs = {} if input is None else {"input": input}
        return self.runner.run(command, timeout=timeout, **kwargs)

    def _checked(self, verb, *args, timeout=30, input=None):
        try:
            result = self._call(verb, *args, timeout=timeout, input=input)
            if result.returncode:
                self._refuse(f"{verb} helper failed (rc={result.returncode})")
            return result.stdout
        except BaseException:
            self.quarantined = True
            raise

    def inventory(self, *, original=False, forward=False):
        """Complete regular-file inventory over the existing remote transport."""
        return self._inventory(original=original, forward=forward)

    def _inventory(self, *, original=False, forward=False):
        self._available()
        timeout = min(30, self._remaining(["inventory"])) if forward else 30
        try:
            inventory = parse_inventory(self._checked(
                "inventory", ORIGINAL_ROOT if original else COPY_ROOT, timeout=timeout))
        except BaseException:
            self.quarantined = True
            raise
        if forward:
            self._remaining(["inventory"])
        return inventory

    def read(self, path, *, output=False):
        """Exact bytes from the copy or run outputs, never a host path alias."""
        return self._read(path, output=output, optional=False)

    def read_optional_output(self, path):
        """None only when the trusted transport proves this output is absent.

        A compiler failure may never create native.jsonl. Nonregular files and
        malformed or failed transport still quarantine, just as ordinary reads.
        """
        return self._read(path, output=True, optional=True)

    @property
    def diagnostics_ready(self):
        """Output retrieval is housekeeping only after proved command cleanup."""
        if self.quarantined or not self.command_evidence or (self._state not in {"planned", "executed"}
                and not (self._state == "ready" and self.command_evidence[-1]["phase"] == "mutation")):
            return False
        evidence = self.command_evidence[-1]
        processes, integrity = evidence["processes"], evidence["integrity"]
        return (processes is not None
                and processes["cleanup"] == "R2T_CLEANUP/1\ncomplete\nR2T_CLEANUP_END\n"
                and integrity is not None and all(_clean(report) for report in integrity.values()))

    def read_diagnostic_output(self, path):
        """Preserve failed-command output after its forward deadline, before retire.

        Only proved quiescent copies permit this existing bounded housekeeping
        read. It adds no command time, retry, or timeout-success inference.
        """
        self._available()
        if not self.diagnostics_ready:
            raise ExecutionRefused("REFUSED: diagnostic output requires proved cleanup and integrity")
        return self._read(path, output=True, optional=True, forward=False)

    def _read(self, path, *, output, optional, forward=None):
        self._available()
        _path(path)
        if forward is None:
            forward = self._deadline is not None and self._state in {"prepared", "planned", "ready"}
        timeout = min(30, self._remaining(["read", path])) if forward else 30
        try:
            result = self._checked("read-optional" if optional else "read",
                                   RUN_ROOT if output else COPY_ROOT, path, timeout=timeout)
            raw = (None if optional and result == "R2T_ABSENT/1\nR2T_ABSENT_END\n"
                   else _payload(result, "BYTES"))
        except BaseException:
            self.quarantined = True
            raise
        if forward:
            try:
                self._remaining(["read", path])
            except ExecutionTimeout as error:
                # Preserve bytes already observed before the post-read cutoff.
                error.output_path, error.output = path, raw
                raise
        return raw

    def _protected(self, inventory, *, original=False):
        boundary = self.original_boundary if original else self.copy_boundary
        return {p: d for p, d in inventory.items()
                if p not in GO_SUBSTRATE_VOLATILE
                and ((not original and p in self._generated)
                     or (any(p == r or p.startswith(r + "/")
                             for r in GO_SUBSTRATE_ROOTS)
                         and boundary.classify(p) != "removable"))}

    def prepare(self, context, installed_answers, trusted_transforms, *,
                allowed_paths, coordination_inputs=None, deadline=None):
        """Fresh copy of verified original plus this answer and trusted transforms.

        ``context`` is the canonical go_suite from the caller's admitted table.
        ``allowed_paths`` is the immutable witnessed answer set from that table,
        or a coordinator-derived original file set during bootstrap discovery.
        ``installed_answers`` supplies exact bytes for every allowed file; None
        requires every allowed answer path to be absent in the original worker.
        The caller supplies known current bytes (or absence) for only the existing
        lock and exported record in ``coordination_inputs``. Nothing is inferred
        from arbitrary observed remote contents. Trusted additions are protected;
        transformed selected glue retains its documented removable classification.

        Bootstrap discovery may supply one absolute monotonic ``deadline`` for
        all its fresh compilation attempts. It bounds preparation as well as
        planning and cannot extend the existing 600-second ceiling. Ordinary
        item calls retain their clock starting at the first planner.
        """
        self._available()
        if self._state != "idle":
            self._refuse("previous invocation was not retired")
        context = validate_suite_context(context)
        self._context = copy.deepcopy(context)
        if not isinstance(allowed_paths, (list, tuple)) or not allowed_paths:
            self._refuse("missing witnessed answer paths")
        paths = tuple(_path(path) for path in allowed_paths)
        self._answer_paths = paths
        if len(paths) != len(set(paths)) or context["glue_path"] not in paths:
            self._refuse("duplicate answer path or missing primary glue")
        if any(self.original_boundary.classify(path) != "removable" for path in paths):
            self._refuse("selected answer is not removable")
        if installed_answers is None:
            answers = dict.fromkeys(paths)
        else:
            if not isinstance(installed_answers, dict):
                raise TypeError("installed_answers must be a path-to-bytes dict or None")
            answers = dict(installed_answers)
            if set(answers) != set(paths):
                self._refuse("installed answer paths differ from witnessed set")
            if any(not isinstance(raw, bytes) for raw in answers.values()):
                raise TypeError("installed answers must contain exact bytes")
        transforms = dict(trusted_transforms)
        coordination = dict(coordination_inputs or {})
        if set(coordination) - _COORDINATION:
            raise ExecutionRefused("REFUSED: undeclared coordination input")
        for path, raw in {**transforms, **coordination}.items():
            _path(path)
            if not isinstance(raw, bytes) and not (path in coordination and raw is None):
                raise TypeError("trusted transforms must contain exact bytes")
        if set(transforms) & _COORDINATION:
            raise ExecutionRefused("REFUSED: coordination paths are not source transforms")
        self._prepare_verified(answers, transforms, coordination, deadline)

    def prepare_bootstrap(self, trusted_inputs, *, deadline):
        """Stage the source-only native parser before suite contexts exist.

        This fixed Go preparation has no answer files or scenario selection.
        The worker must still be the exact independently verified stripped seed.
        Native parsing imports Godog only; subject wrappers never execute here.
        """
        self._available()
        if self._state != "idle":
            self._refuse("previous invocation was not retired")
        required = {"_bench/go/support/bootstrap_select.go", "_bench/go/bootstrap-request.json"}
        if (not isinstance(trusted_inputs, dict) or set(trusted_inputs) != required
                or any(not isinstance(raw, bytes) for raw in trusted_inputs.values())
                or any(self.original_boundary.classify(path) == "removable"
                       for path in self.original_inventory)):
            raise ExecutionRefused("REFUSED: bootstrap requires its fixed parser inputs and stripped seed")
        self._context = None
        self._answer_paths = ()
        self._prepare_verified({}, dict(trusted_inputs), {}, deadline)

    def _prepare_verified(self, answers, transforms, coordination, deadline):
        """Shared original/copy guards after the caller validates its inputs."""
        if deadline is not None and (type(deadline) not in (int, float)
                or not math.isfinite(deadline)
                or deadline > time.monotonic() + COMMAND_TIMEOUT):
            raise ValueError("discovery deadline must be a finite cutoff within 600 seconds")
        expected_original = dict(self.original_inventory)
        for path, raw in {**coordination, **answers}.items():
            if raw is None:
                expected_original.pop(path, None)
            else:
                expected_original[path] = hashlib.sha256(raw).hexdigest()
        self._deadline = deadline
        self.mutation_evidence = None
        self._mutation_baseline = None
        self._expected_mutations = {}
        self._mutation_metadata = {}
        self._mutation_attempted = False
        self._mutation_reference_retired = False
        self.command_evidence = []
        forward = deadline is not None
        try:
            current = self._inventory(original=True, forward=forward)
            if current != expected_original:
                self._refuse("original bytes differ from verified inputs/current answer",
                    scope="original_inputs", reports={"original": compare_substrate_inventory(
                        expected_original, current)})
            if not _clean(compare_substrate_inventory(
                    self._original_baseline, self._protected(current, original=True))):
                self._refuse("original manifest check failed before preparation")
            self._expected = dict(expected_original)
            self._generated = set()
            timeout = min(30, self._remaining(["prepare"])) if forward else 30
            self._checked("prepare", timeout=timeout)
            # A completed copy can be verified and retired even if its caller's
            # discovery cutoff passed while the transport was returning.
            self._state = "prepared"
            if forward:
                self._remaining(["prepare"])
            for path, raw in transforms.items():
                timeout = min(30, self._remaining(["write", path])) if forward else 30
                if path not in self._expected:
                    self._generated.add(path)
                self._expected[path] = hashlib.sha256(raw).hexdigest()
                self._checked("write", COPY_ROOT, path,
                              input=base64.b64encode(raw).decode("ascii"), timeout=timeout)
                if forward:
                    self._remaining(["write", path])
            if self._inventory(forward=forward) != self._expected:
                self._refuse("copy differs from host-held preparation expectation")
        except subprocess.TimeoutExpired:
            if not self.quarantined:
                if self._state == "prepared":
                    # No forward work follows expiry. Prove exactly the writes
                    # that completed, then perform mandatory retirement.
                    if self.inventory() != self._expected:
                        self._refuse("expired preparation differs from completed writes")
                    self.retire()
                else:
                    self._deadline = None
            raise

    def finalize(self, trusted_transforms):
        """Apply planner-returned exact bytes without making another source copy.

        Only a completed trusted planner can enter this phase. Its copy must
        still exactly match the host-held map, including removable answer bytes.
        No observed remote contents become a new baseline.
        """
        self._available()
        if self._state != "planned":
            self._refuse("finalize requires a completed planner, before candidate execution")
        transforms = dict(trusted_transforms)
        for path, raw in transforms.items():
            _path(path)
            if not isinstance(raw, bytes):
                raise TypeError("trusted transforms must contain exact bytes")
        if set(transforms) & _COORDINATION:
            raise ExecutionRefused("REFUSED: coordination paths are not source transforms")
        self._remaining(["finalize"])
        try:
            self._verify(forward=True)
            for path, raw in transforms.items():
                digest = hashlib.sha256(raw).hexdigest()
                encoded = base64.b64encode(raw).decode("ascii")
                timeout = min(30, self._remaining(["write", path]))
                # Advance authority only for this exact trusted write. If the
                # deadline passes after it completes, later unattempted writes
                # must not make verified retirement impossible.
                if path not in self._expected:
                    self._generated.add(path)
                self._expected[path] = digest
                self._checked("write", COPY_ROOT, path, input=encoded, timeout=timeout)
                self._remaining(["write", path])
            if self._inventory(forward=True) != self._expected:
                self._refuse("finalized copy differs from host-held transformation expectation")
            self._remaining(["finalize"])
        except subprocess.TimeoutExpired:
            # These mandatory guards are allowed after the forward deadline.
            # A transport timeout instead quarantines: its helper exit is not
            # proved, so it cannot claim a clean reusable copy.
            if not self.quarantined:
                self.verify()
            raise
        self._state = "ready"

    @property
    def pre_mutation_inventory(self):
        return copy.deepcopy(self._mutation_baseline)

    @property
    def expected_mutations(self):
        return dict(self._expected_mutations)

    def begin_mutation(self):
        """Freeze known finalized bytes before observing the candidate copy."""
        self._available()
        if self._state != "ready" or self._mutation_baseline is not None:
            self._refuse("mutation requires one finalized, previously unmutated copy")
        if "_bench/go/measure/recorder.go" in self._expected:
            self._refuse("API/coverage measurement is unsupported in mutation copies")
        self._remaining(["mutation-baseline"])
        self._mutation_baseline = dict(self._expected)
        observed = self.inventory(forward=True)
        if observed != self._mutation_baseline:
            self._refuse("prepared copy differs from independently constructed mutation PRE",
                scope="mutation_pre", reports={"copy": compare_substrate_inventory(self._mutation_baseline, observed)})
        self._verify(forward=True)
        return self.pre_mutation_inventory

    def read_metadata(self, path, *, original=False, forward=True):
        """Read the existing regular-file mode/uid/gid contract remotely."""
        self._available(); _path(path)
        timeout = min(30, self._remaining(["metadata", path])) if forward else 30
        try:
            raw = self._checked("metadata", ORIGINAL_ROOT if original else COPY_ROOT, path, timeout=timeout)
            value = json.loads(_payload(raw, "METADATA"))
            if (not isinstance(value, dict) or set(value) != {"mode", "uid", "gid"}
                    or any(type(value[k]) is not int or value[k] < 0 for k in value)
                    or not stat.S_ISREG(value["mode"])):
                self._refuse("invalid remote regular-file metadata")
        except BaseException:
            self.quarantined = True
            raise
        if forward:
            self._remaining(["metadata", path])
        return value

    def run_mutation_applier(self, trusted_argv):
        """One reference-engine invocation after finalization, on the same clock.

        It must not mutate the candidate copy. The Go mutation module verifies
        reference output before transferring the one exact production delta.
        This is not another planner or another finalization.
        """
        self._available()
        if self._state != "ready" or self._mutation_baseline is None or self._mutation_attempted:
            self._refuse("mutation applier requires the frozen PRE and a fresh attempt")
        self._mutation_attempted = True
        return self._run_command(trusted_argv, planner=False, mutation=True)

    def install_mutation(self, path, pristine, changed, metadata):
        """Transfer an engine-verified splice; PRE is never advanced."""
        self._available(); _path(path)
        if (self._state != "ready" or self._mutation_baseline is None or not self._mutation_attempted
                or self._expected_mutations or self.copy_boundary.classify(path) != "production"
                or not path.endswith(".go") or path.endswith("_test.go")
                or not any(path.startswith(root + "/") for root in ("cmd", "internal", "external"))):
            self._refuse("invalid mutation target or lifecycle")
        if (not isinstance(pristine, bytes) or not isinstance(changed, bytes) or pristine == changed
                or hashlib.sha256(pristine).hexdigest() != self._mutation_baseline.get(path)):
            self._refuse("mutation target lacks its authoritative pristine bytes")
        self._verify(forward=True)
        if self.read(path) != pristine or self.read_metadata(path) != metadata:
            self._refuse("candidate mutation target changed before transfer")
        self._checked("write", COPY_ROOT, path, input=base64.b64encode(changed).decode("ascii"),
                      timeout=min(30, self._remaining(["mutation-write", path])))
        if self.read(path) != changed or self.read_metadata(path) != metadata:
            self._refuse("mutation transfer bytes or metadata differ")
        self._expected_mutations = {path: hashlib.sha256(changed).hexdigest()}
        self._mutation_metadata = {path: dict(metadata)}
        self._verify(forward=True)

    def _remaining(self, argv):
        remaining = (COMMAND_TIMEOUT if self._deadline is None
                     else self._deadline - time.monotonic())
        if remaining <= 0:
            raise ExecutionTimeout(list(argv), basis="deadline")
        return remaining

    def run_planner(self, trusted_argv):
        """Run the pinned read-only planner once, inside this verified copy.

        The caller supplies coordinator-owned compiler/planner arguments, never
        a candidate-selected command. The first planner starts the single 600s
        clock covering cold planning, host plan folding/finalization and testing.
        A bootstrap deadline supplied to prepare is preserved across this call.
        Read its exact output bytes, then call finalize with trusted transforms.
        """
        self._available()
        if self._state != "prepared":
            self._refuse("planner requires the initial prepared copy")
        if self._deadline is None:
            self._deadline = time.monotonic() + COMMAND_TIMEOUT
        return self._run_command(trusted_argv, planner=True)

    def run_audit_operation(self, trusted_argv, *, timeout=300):
        """Run one standalone audit operation under its existing command budget.

        A population audit applies/parses/restores many descriptors in one
        private original tree. Its command clock is separate from an item’s
        single planner/test clock. Only the fixed immutable audit driver can use
        this path; candidate execution cannot renew its deadline here.
        """
        self._available()
        helpers = ('_bench/go/support/mutation_audit.go',
                   '_bench/go/support/mutation_audit_support.go')
        prefix = ['/usr/local/go/bin/go', 'run', '-p=1',
                  *[ORIGINAL_ROOT+'/'+path for path in helpers]]
        argv = list(trusted_argv)
        if (self._state not in {'prepared', 'planned'}
                or self._mutation_baseline is not None
                or not set(helpers).issubset(self.original_inventory)
                or argv[:len(prefix)] != prefix
                or len(argv) not in {len(prefix)+1, len(prefix)+2}
                or argv[len(prefix)] not in {'setup', 'apply', 'parse', 'restore', 'retire'}
                or (len(argv) == len(prefix)+2 and not re.fullmatch(r'0|[1-9][0-9]*', argv[-1]))):
            raise ExecutionRefused('REFUSED: standalone audit requires its trusted operation driver')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= COMMAND_TIMEOUT:
            raise ValueError('audit operation timeout must be finite and within 600 seconds')
        self._deadline = time.monotonic() + timeout
        return self._run_command(argv, planner=True)

    def _processes(self):
        timeout = min(30, self._remaining(["processes"]))
        lines = self._checked("processes", timeout=timeout).splitlines()
        self._remaining(["processes"])
        if (len(lines) < 3 or lines[0] != "R2T_PROCESSES/1"
                or lines[-1] != "R2T_PROCESSES_END"):
            self._refuse("incomplete process census")
        pids = set()
        for line in lines[1:-1]:
            if not re.fullmatch(r"[1-9][0-9]* [0-9]+ [0-9]+ [0-9]+ [0-9]+", line):
                self._refuse("corrupt process census")
            pid = line.split()[0]
            if pid in pids:
                self._refuse("duplicate process identity")
            pids.add(pid)
        return base64.b64encode(("\n".join(lines[1:-1]) + "\n").encode()).decode()

    def execute(self, argv):
        """Run the final test once, using what remains of the shared 600s budget.

        Without a planner the command still gets exactly 600 seconds. Command
        failures return CompletedProcess. A deadline or client interruption is
        propagated only after cleanup and both integrity guards succeed.
        """
        self._available()
        if self._state not in {"prepared", "ready"}:
            self._refuse("execute requires preparation and any planner finalization")
        if self._mutation_baseline is not None and (len(self._expected_mutations) != 1 or not self._mutation_reference_retired):
            self._refuse("mutation execution needs a verified target and retired reference analysis")
        return self._run_command(argv, planner=False)

    def _run_command(self, argv, *, planner, mutation=False):
        if (not isinstance(argv, (list, tuple)) or not argv
                or any(not isinstance(a, str) or "\0" in a for a in argv)):
            raise ValueError("execution requires an argument array")
        evidence = {"phase": "mutation" if mutation else ("planner" if planner else "execution"), "argv": list(argv),
                    "returncode": None, "stdout": None, "seconds": None,
                    "transport_stdout": None, "transport_stderr": None,
                    "timeout_basis": None, "timeout_log": None,
                    "processes": None, "integrity": None}
        self.command_evidence.append(evidence)
        try:
            # Refuse expired planning before launching another remote command.
            self._remaining(argv)
            self.process_evidence = None
            baseline = self._processes()
            self.process_evidence = {"baseline": base64.b64decode(baseline).decode(), "cleanup": None}
            evidence["processes"] = self.process_evidence
            self._state = "running"
            try:
                remaining = self._remaining(argv)
                started = time.monotonic()
                try:
                    result = self._call("execute", str(remaining), *argv, timeout=remaining + 15)
                    evidence.update(returncode=result.returncode,
                                    transport_stdout=result.stdout, transport_stderr=result.stderr)
                except subprocess.TimeoutExpired as error:
                    evidence.update(transport_stdout=error.output, transport_stderr=error.stderr)
                    raise ExecutionTimeout(list(argv), basis="transport",
                                           output=error.output, stderr=error.stderr) from error
                finally:
                    evidence["seconds"] = time.monotonic() - started
            finally:
                try:
                    cleanup = self._checked("cleanup", baseline, timeout=15)
                    self.process_evidence["cleanup"] = cleanup
                    if cleanup != "R2T_CLEANUP/1\ncomplete\nR2T_CLEANUP_END\n":
                        self._refuse("process cleanup was not proved")
                    self._state = "ready" if mutation else ("planned" if planner else "executed")
                    evidence["integrity"] = self.verify()
                except BaseException:
                    self.quarantined = True
                    raise
            output = self.read("stdout.log", output=True).decode("utf-8", errors="replace")
            evidence["stdout"] = output  # Child stderr is merged here by the existing transport.
            timeout_log = self.read("timeout.log", output=True)
            evidence["timeout_log"] = timeout_log.decode("utf-8", errors="replace")
            if b"timeout: sending signal TERM to command" in timeout_log:
                raise ExecutionTimeout(list(argv), basis="monitor", output=output)
            if planner:
                self._remaining(argv)
            return subprocess.CompletedProcess(list(argv), result.returncode, output, "")
        except ExecutionTimeout as error:
            evidence["timeout_basis"] = error.basis
            if getattr(error, "output_path", None) == "stdout.log" and error.output is not None:
                evidence["stdout"] = error.output.decode("utf-8", errors="replace")
            raise
        except ExecutionIntegrityError as error:
            evidence["integrity"] = copy.deepcopy(error.reports)
            raise

    def verify(self):
        """Check both guards after cleanup, even after the command deadline."""
        return self._verify()

    def _verify(self, *, forward=False):
        self._available()
        if self._state not in {"prepared", "planned", "ready", "executed"}:
            self._refuse("verification requires a quiescent prepared copy")
        copy_inventory = self._inventory(forward=forward)
        if self._state == "planned" and copy_inventory != self._expected:
            self._refuse("read-only planner copy differs from host-held expectation",
                scope="planner_copy", reports={"copy": compare_substrate_inventory(
                    self._expected, copy_inventory)})
        baseline = self._expected if self._mutation_baseline is None else self._mutation_baseline
        reports = {
            "copy": compare_substrate_inventory(self._protected(baseline),
                                                  self._protected(copy_inventory), self._expected_mutations),
            "original": compare_substrate_inventory(
                self._original_baseline, self._protected(self._inventory(original=True, forward=forward),
                                                         original=True)),
        }
        for path, expected in self._mutation_metadata.items():
            if self.read_metadata(path, forward=forward) != expected:
                reports["metadata"] = {"changed": [path], "missing": [], "added": []}
                self._refuse("mutation target metadata changed", scope="mutation_metadata", reports=reports)
        if not all(_clean(report) for report in reports.values()):
            self._refuse("protected substrate changed: " + str(reports),
                         scope="protected_substrate", reports=reports)
        return reports

    def retire(self):
        """Recheck both guards and discard run state; refused workers cannot recycle."""
        self._available()
        if self._state not in {"prepared", "planned", "ready", "executed"}:
            self._refuse("retire requires a quiescent invocation")
        self.verify()
        self._checked("retire", timeout=RETIRE_TIMEOUT)
        self._reset()

    def retire_unscorable(self):
        """Owner ruling 2026-09-30: retire a mutant copy its test only added files to.

        Only this quarantine qualifies: the executed mutant test's own check
        after proved cleanup, with the original clean, no metadata report and
        a copy report of protected additions alone, honouring exactly the
        transferred mutation. The whole copy is then retired and the original
        rechecked before the quarantine clears; the scoped reports are returned
        as the pair's evidence. Anything else returns None and stays quarantined.
        """
        evidence = self.command_evidence[-1] if self.command_evidence else {}
        reports = evidence.get("integrity") or {}
        if not (self.quarantined and self._state == "executed" and self._expected_mutations
                and evidence["phase"] == "execution"
                and evidence["processes"]["cleanup"] == "R2T_CLEANUP/1\ncomplete\nR2T_CLEANUP_END\n"
                and set(reports) == {"copy", "original"} and _clean(reports["original"])
                and not reports["copy"]["changed"] and not reports["copy"]["missing"]
                and reports["copy"]["added"]
                and reports["copy"]["mutated"] == sorted(self._expected_mutations)):
            return None
        self._checked("retire", timeout=RETIRE_TIMEOUT)
        current = parse_inventory(self._checked("inventory", ORIGINAL_ROOT))
        if not _clean(compare_substrate_inventory(
                self._original_baseline, self._protected(current, original=True))):
            self._refuse("original changed while retiring an unscorable mutant copy")
        self._reset()
        self.quarantined = False
        return copy.deepcopy(reports)

    def _reset(self):
        self._state = "idle"
        self._context = None
        self._answer_paths = ()
        self._expected = None
        self._generated = set()
        self._deadline = None
        self._mutation_baseline = None
        self._expected_mutations = {}
        self._mutation_metadata = {}
        self._mutation_attempted = False
        self._mutation_reference_retired = False
