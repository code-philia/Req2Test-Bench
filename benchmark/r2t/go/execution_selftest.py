"""Network-free lifecycle/refusal tests; real transport proof is an operator gate."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile
from unittest.mock import patch

from ..bench.repo import GO_SUBSTRATE_ROOTS, GO_SUBSTRATE_VOLATILE, StripManifest
from ..core.boundary import Boundary
from .context import canonical_item
from .execution import (COPY_ROOT, ExecutionCopy, ExecutionRefused, ExecutionIntegrityError, ExecutionTimeout,
                        ORIGINAL_ROOT, RETIRE_TIMEOUT, _SUPPORT, parse_inventory)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _frame(raw, kind):
    return f"R2T_{kind}/1\n{base64.b64encode(raw).decode()}\nR2T_{kind}_END\n"


def _inventory(files):
    return _frame(b"".join(_hash(raw).encode() + b"  ./" + p.encode() + b"\0"
                           for p, raw in sorted(files.items())), "INVENTORY")


class Remote:
    """Fault injection at the existing runner transport, without Docker emulation."""

    def __init__(self, files):
        self.original = dict(files)
        self.copy = None
        self.outputs = {}
        self.calls = []
        self.effect = None
        self.fault = None
        self.fault_output = None
        self.copy_tamper = None
        self.durations = []
        self.after_call = None
        self.transport = []

    def run(self, command, timeout, input=None):
        words = shlex.split(command)
        verb, *args = words[5:]
        self.calls.append(verb)
        self.transport.append((verb, timeout, input))
        if self.fault == verb:
            if self.fault_output is not None:
                return subprocess.CompletedProcess(command, 0, self.fault_output, "")
            return subprocess.CompletedProcess(command, 70, "", "injected failure")
        result, code = "", 0
        if verb == "inventory":
            result = _inventory(self.original if args[0] == ORIGINAL_ROOT else self.copy)
        elif verb == "prepare":
            self.copy = dict(self.original)
            self.outputs = {}
            if self.copy_tamper:
                self.copy_tamper(self.copy)
        elif verb == "write":
            assert args[0] == COPY_ROOT and len(args) == 2
            assert isinstance(input, str)
            self.copy[args[1]] = base64.b64decode(input, validate=True)
        elif verb in {"read", "read-optional"}:
            source = self.copy if args[0] == COPY_ROOT else self.outputs
            result = ("R2T_ABSENT/1\nR2T_ABSENT_END\n"
                      if verb == "read-optional" and args[1] not in source
                      else _frame(source[args[1]], "BYTES"))
        elif verb == "processes":
            result = "R2T_PROCESSES/1\n1 0 1 1 101\nR2T_PROCESSES_END\n"
        elif verb == "cleanup":
            result = "R2T_CLEANUP/1\ncomplete\nR2T_CLEANUP_END\n"
        elif verb == "execute":
            duration = float(args[0])
            assert 0 < duration <= 600 and timeout == duration + 15
            self.durations.append(duration)
            self.outputs = {"stdout.log": b"actual stdout\n", "timeout.log": b""}
            if self.effect:
                code = self.effect(self) or 0
        elif verb == "retire":
            self.copy = None
            self.outputs = {}
        else:
            raise AssertionError(verb)
        if self.after_call:
            self.after_call(verb)
        return subprocess.CompletedProcess(command, code, result, "")


def fixture(extra_answers=()):
    context = canonical_item()["go_suite"]
    glue = context["glue_path"]
    files = {"go.mod": b"module fixture\n", "go.sum": b"",
             "internal/pkg/source.go": b"package pkg\n", context["feature_path"]: b"Feature: f\n",
             "external/httpserver/retained_test.go": b"package httpserver\n",
             "_bench/go/support/trusted.go": b"package support\n"}
    boundary = Boundary(1, "coddy-agent", ORIGINAL_ROOT,
                        removable=[*( (p, "helper answer") for p in extra_answers),
                                   (glue, "answer"),
                                   ("external/httpserver/zz_r2t_harness_test.go", "reserved test")])
    digests = {p: _hash(raw) for p, raw in files.items()}
    manifest = StripManifest(ORIGINAL_ROOT, "/unused", digests=digests,
                             substrate_roots=list(GO_SUBSTRATE_ROOTS),
                             substrate_volatile=sorted(GO_SUBSTRATE_VOLATILE))
    remote = Remote(files)
    adapter = ExecutionCopy(remote, original_inventory=digests,
                            boundary=boundary, original_manifest=manifest)
    return adapter, remote, context


def selftest():
    count = 0

    def check(name, run):
        nonlocal count
        run()
        count += 1
        print("  [PASS] " + name)

    def refused(fn):
        try:
            fn()
        except ExecutionRefused:
            return
        raise AssertionError("expected ExecutionRefused")

    def toolchain_survives_login_shell():
        # DockerRunner's sh -lc loses the image's inherited Go PATH. Run the
        # actual support shell through that route, using the real local Go
        # executable and mapping only its image directory and private roots.
        go = shutil.which("go")
        timeout = shutil.which("timeout")
        assert go is not None and timeout is not None
        expected = subprocess.check_output([go, "version"], text=True)
        with tempfile.TemporaryDirectory(prefix="go-support-path-") as td:
            root = Path(td)
            limited_bin = root / "without-go"; limited_bin.mkdir()
            (limited_bin / "timeout").symlink_to(timeout)
            private = root / "worker"
            for relative in ("run/work", "tmp", "cache"):
                (private / relative).mkdir(parents=True)
            support = _SUPPORT.replace("/r2t-go", str(private)).replace(
                "/usr/local/go/bin", str(Path(go).resolve().parent))
            # Restrict PATH after the real login shell has read its profiles,
            # so this reproduces the observed missing-Go environment on every
            # host, even one with Go installed in a system binary directory.
            child = "go version; /bin/sh -c 'go version'"
            inner = ("export PATH=" + shlex.quote(str(limited_bin)) + "; "
                     "exec /bin/bash -c " + shlex.quote(support)
                     + " r2t-execution execute 15 /bin/bash -e -c "
                     + shlex.quote(child))
            completed = subprocess.run(["/bin/sh", "-lc", inner],
                                       capture_output=True, text=True, timeout=30)
            actual = (private / "run/stdout.log").read_text()
            assert completed.returncode == 0, (completed.returncode, actual, completed.stderr)
            assert actual == expected * 2, actual
            assert (private / "run/exit-code.txt").read_text() == "0\n"
    check("real support shell restores Go after login PATH loss for parent and child", toolchain_survives_login_shell)

    def optional_outputs():
        # Run the exact shell branch on real files, including a dangling link.
        with tempfile.TemporaryDirectory(prefix="go-optional-output-") as td:
            root = Path(td)
            (root / 'native.jsonl').write_bytes(b'raw native\n')
            (root / 'empty.jsonl').write_bytes(b'')
            (root / 'directory').mkdir()
            (root / 'link').symlink_to(root / 'absent')
            def run(verb, name):
                return subprocess.run(['/bin/bash', '-c', _SUPPORT, 'r2t-execution',
                                       verb, td, name], capture_output=True, text=True, timeout=10)
            for name, expected in [('native.jsonl', b'raw native\n'), ('empty.jsonl', b'')]:
                result = run('read-optional', name)
                assert result.returncode == 0 and result.stdout == _frame(expected, 'BYTES')
            absent = run('read-optional', 'absent')
            assert absent.returncode == 0 and absent.stdout == 'R2T_ABSENT/1\nR2T_ABSENT_END\n'
            assert run('read', 'absent').returncode != 0
            for name in ('directory', 'link'):
                assert run('read-optional', name).returncode != 0
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context['glue_path'],))
        adapter.execute(['go', 'test'])
        assert adapter.read_optional_output('native.jsonl') is None
        remote.outputs['native.jsonl'] = b'actual native'
        assert adapter.read_optional_output('native.jsonl') == b'actual native'
        adapter.retire()
        for malformed in (None, 'R2T_ABSENT/1\n', 'R2T_BYTES/1\n!\nR2T_BYTES_END\n'):
            adapter, remote, context = fixture()
            adapter.prepare(context, None, {}, allowed_paths=(context['glue_path'],))
            remote.fault, remote.fault_output = 'read-optional', malformed
            refused(lambda: adapter.read_optional_output('native.jsonl'))
            assert adapter.quarantined
    check('actual optional output shell proves present/absent; nonregular and broken reads refuse', optional_outputs)

    def command_facts():
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context['glue_path'],))
        remote.effect = lambda r: r.outputs.update({'stdout.log': b'compiler diagnostic\n'}) or 127
        completed = adapter.run_planner(['go', 'run', 'planner.go'])
        evidence = adapter.command_evidence[-1]
        assert completed.returncode == evidence['returncode'] == 127
        assert completed.stdout == evidence['stdout'] == 'compiler diagnostic\n'
        assert evidence['phase'] == 'planner' and evidence['timeout_basis'] is None
        assert evidence['seconds'] >= 0 and evidence['transport_stderr'] == ''
        assert evidence['processes']['cleanup'] == 'R2T_CLEANUP/1\ncomplete\nR2T_CLEANUP_END\n'
        assert all(not report[key] for report in evidence['integrity'].values()
                   for key in ('changed','missing','added'))
        adapter.retire()
        assert adapter.command_evidence[-1] is evidence
        adapter.prepare(context, None, {}, allowed_paths=(context['glue_path'],))
        assert adapter.command_evidence == []
        def transport_timeout(r):
            raise subprocess.TimeoutExpired('transport', 615, output=b'partial transport', stderr=b'connection')
        remote.effect = transport_timeout
        try:
            adapter.execute(['go','test'])
        except ExecutionTimeout as error:
            assert error.basis == 'transport' and error.output == b'partial transport'
        else: raise AssertionError('transport timeout was scored as normal exit')
        evidence = adapter.command_evidence[-1]
        assert evidence['timeout_basis'] == 'transport' and evidence['returncode'] is None
        assert evidence['transport_stderr'] == b'connection' and evidence['stdout'] is None
        assert not adapter.quarantined
        adapter.retire()
    check('command facts survive retirement and distinguish unknown transport timeout from exit127', command_facts)

    def diagnostic_reads():
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context['glue_path'],))
        assert not adapter.diagnostics_ready
        refused(lambda: adapter.read_diagnostic_output('stdout.log'))
        clock = [0.0]
        with patch('r2t.go.execution.time.monotonic', side_effect=lambda: clock[0]):
            def expired(r):
                clock[0] = 601.0
                r.outputs['stdout.log'] = b'compiler prefix before deadline\n'
                r.outputs['native.jsonl'] = b'partial native\n'
                r.outputs['timeout.log'] = b'timeout: sending signal TERM to command /bin/bash\n'
                return 124
            remote.effect = expired
            try: adapter.run_planner(['go','run','planner.go'])
            except ExecutionTimeout as error: assert error.basis == 'deadline'
            else: raise AssertionError('expired planner returned')
            assert adapter.diagnostics_ready and not adapter.quarantined
            before = len(remote.calls)
            try: adapter.read_optional_output('stdout.log')
            except ExecutionTimeout: pass
            else: raise AssertionError('ordinary optional read bypassed expired forward clock')
            assert len(remote.calls) == before
            assert adapter.read_diagnostic_output('stdout.log') == b'compiler prefix before deadline\n'
            assert adapter.read_diagnostic_output('native.jsonl') == b'partial native\n'
            assert adapter.read_diagnostic_output('absent') is None
            assert remote.transport[-1][:2] == ('read-optional', 30)
            assert remote.calls.count('execute') == 1
            adapter.retire()
            assert not adapter.diagnostics_ready
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context['glue_path'],))
        remote.effect = lambda r: r.copy.update({'internal/pkg/source.go':b'changed'})
        refused(lambda: adapter.execute(['go','test']))
        assert not adapter.diagnostics_ready
        calls = list(remote.calls)
        refused(lambda: adapter.read_diagnostic_output('stdout.log'))
        assert remote.calls == calls
    check('expired diagnostics require proved cleanup/integrity and never extend command time', diagnostic_reads)

    def cycle():
        adapter, remote, context = fixture()
        glue = context["glue_path"]
        scaffold = context["package_dir"] + "/zz_r2t_harness_test.go"
        for number in range(2):
            answer = f"package httpserver // answer {number}\n".encode()
            remote.original[glue] = answer
            remote.original[".r2t-exec.lock"] = b"lock owned by coordinator\n"
            inputs = {".r2t-exec.lock": remote.original[".r2t-exec.lock"]}
            if number:
                inputs["_bench/run_record.jsonl"] = b'{"trusted":true}\n'
            adapter.prepare(context, {context["glue_path"]: answer}, {scaffold: b"package httpserver\n"},
                            coordination_inputs=inputs, allowed_paths=(context["glue_path"],))
            assert adapter.read(glue) == answer
            assert adapter.execute(["go", "test"]).returncode == 0
            assert adapter.read("stdout.log", output=True) == b"actual stdout\n"
            remote.original["_bench/run_record.jsonl"] = b'{"trusted":true}\n'
            adapter.retire()
            assert remote.copy is None and not adapter.quarantined
        assert adapter.copy_boundary.repo_root == COPY_ROOT
    check("two item answers, lock and exported record reuse", cycle)

    def multi_file_cycle():
        helper = "external/httpserver/bdd_helpers_test.go"
        adapter, remote, context = fixture((helper,))
        glue = context["glue_path"]
        allowed = (glue, helper)
        protected = dict(remote.original)
        for number in range(2):
            answer = {glue: f"primary-{number}".encode(),
                      helper: f"helper-{number}".encode()}
            remote.original.update(answer)
            adapter.prepare(context, answer, {}, allowed_paths=allowed)
            assert all(adapter.read(path) == raw for path, raw in answer.items())
            adapter.run_planner(["trusted-planner"])
            adapter.finalize({glue: b"interposed primary"})
            assert adapter.read(glue) == b"interposed primary"
            assert adapter.read(helper) == answer[helper]
            assert adapter.execute(["go", "test"]).returncode == 0
            assert all(remote.original[path] == raw for path, raw in answer.items())
            assert all(remote.original[path] == raw for path, raw in protected.items())
            adapter.retire()
        for path in allowed:
            remote.original.pop(path)
        adapter.prepare(context, None, {}, allowed_paths=allowed)
        assert all(path not in remote.copy for path in allowed)
        adapter.execute(["go", "test"])
        adapter.retire()
        assert not adapter.quarantined
    check("two multi-file answers preserve helper bytes and then require complete absence", multi_file_cycle)

    def multi_file_refusals():
        helper = "external/httpserver/bdd_helpers_test.go"
        foreign = "external/httpserver/bdd_foreign_test.go"
        for defect in ("missing", "extra", "stale", "duplicate", "retained", "missing-primary"):
            adapter, remote, context = fixture((helper, foreign))
            glue = context["glue_path"]
            answer = {glue: b"primary", helper: b"helper"}
            remote.original.update(answer)
            allowed = (glue, helper)
            if defect == "missing":
                answer.pop(helper)
            elif defect == "extra":
                answer[foreign] = b"foreign"
            elif defect == "stale":
                remote.original[helper] = b"stale installed bytes"
            elif defect == "duplicate":
                allowed = (glue, helper, helper)
            elif defect == "retained":
                allowed = (glue, "external/httpserver/retained_test.go")
            else:
                allowed = (helper,)
            refused(lambda: adapter.prepare(context, answer, {}, allowed_paths=allowed))
            assert "prepare" not in remote.calls and "write" not in remote.calls
        adapter, remote, context = fixture((helper,))
        remote.original[helper] = b"leftover from previous item"
        refused(lambda: adapter.prepare(context, None, {},
                                        allowed_paths=(context["glue_path"], helper)))
        assert "prepare" not in remote.calls
    check("missing/extra/stale/duplicate/retained files refuse before preparation", multi_file_refusals)

    def multi_file_planner_integrity():
        helper = "external/httpserver/bdd_helpers_test.go"
        adapter, remote, context = fixture((helper,))
        glue = context["glue_path"]
        answer = {glue: b"primary", helper: b"helper"}
        remote.original.update(answer)
        adapter.prepare(context, answer, {}, allowed_paths=(glue, helper))
        remote.effect = lambda r: r.copy.__setitem__(helper, b"planner changed helper")
        refused(lambda: adapter.run_planner(["trusted-planner"]))
        assert adapter.quarantined and remote.calls.count("cleanup") == 1
    check("read-only planner integrity includes secondary answer files", multi_file_planner_integrity)

    def integrity(path, mode, original=False):
        adapter, remote, context = fixture()
        scaffold = context["package_dir"] + "/zz_r2t_harness_test.go"
        adapter.prepare(context, None, {scaffold: b"trusted scaffold"}, allowed_paths=(context["glue_path"],))
        def alter(r):
            files = r.original if original else r.copy
            if mode == "missing":
                files.pop(path)
            else:
                files[path] = b"changed"
        remote.effect = alter
        try:
            adapter.execute(["go", "test"])
        except ExecutionIntegrityError as error:
            assert error.phase == 'executed' and error.scope == 'protected_substrate'
            assert path in error.reports['original' if original else 'copy'][mode]
            assert adapter.command_evidence[-1]['integrity'] == error.reports
        else:
            raise AssertionError('missing structured protected-substrate refusal')
        assert adapter.quarantined
        assert remote.calls.index("cleanup") < len(remote.calls) - 1
        before = list(remote.calls)
        refused(adapter.retire)
        assert remote.calls == before
    for mode in ("changed", "missing"):
        check("protected production " + mode,
              lambda m=mode: integrity("internal/pkg/source.go", m))
    check("protected source added", lambda: integrity("internal/pkg/extra.go", "added"))
    check("reserved generated scaffold stays protected in removable territory",
          lambda: integrity("external/httpserver/zz_r2t_harness_test.go", "changed"))
    check("original manifest independently rejects tampering",
          lambda: integrity("go.mod", "changed", original=True))
    check("exact volatile sibling remains protected",
          lambda: integrity("_bench/run_record.jsonl.sibling", "added"))

    def removable():
        adapter, remote, context = fixture()
        glue = context["glue_path"]
        remote.original[glue] = b"answer"
        adapter.prepare(context, {context["glue_path"]: b"answer"}, {glue: b"interposed"}, allowed_paths=(context["glue_path"],))
        def change(r):
            r.copy[glue] = b"candidate-writable"
            r.copy["_bench/run_record.jsonl"] = b"volatile"
            r.original["_bench/run_record.jsonl"] = b"volatile"
        remote.effect = change
        adapter.execute(["go", "test"])
        adapter.retire()
        assert not adapter.quarantined
    check("exact selected answer remains removable; only exact record is volatile", removable)

    def prepare_tamper():
        adapter, remote, context = fixture()
        remote.copy_tamper = lambda files: files.update({"go.mod": b"altered before baseline"})
        refused(lambda: adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],)))
        assert adapter.quarantined and "execute" not in remote.calls
    check("copy baseline cannot adopt arbitrary prepared bytes", prepare_tamper)

    def original_tamper():
        adapter, remote, context = fixture()
        remote.original["go.mod"] = b"changed"
        refused(lambda: adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],)))
        assert remote.calls == ["inventory"]
    check("original input refuses before copy side effects", original_tamper)

    def corrupt():
        good = _inventory({"go.mod": b"fixture"})
        row = base64.b64decode(good.splitlines()[1])
        bads = [good.replace("R2T_INVENTORY_END", ""),
                "R2T_INVENTORY/1\n!!!\nR2T_INVENTORY_END\n",
                _frame(row + row, "INVENTORY"), _frame(row[:-1], "INVENTORY"),
                _frame(b"a" * 64 + b"  ./../escape\0", "INVENTORY")]
        for bad in bads:
            refused(lambda text=bad: parse_inventory(text))
        adapter, remote, context = fixture()
        remote.fault, remote.fault_output = "inventory", bads[0]
        refused(lambda: adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],)))
        assert adapter.quarantined
    check("malformed, partial, duplicate and escaping inventory refusal", corrupt)

    def cleanup_failure():
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
        remote.fault = "cleanup"
        start = len(remote.calls)
        refused(lambda: adapter.execute(["go", "test"]))
        assert remote.calls[start:] == ["processes", "execute", "cleanup"]
        assert adapter.quarantined
    check("unproved cleanup quarantines before postinventory or retire", cleanup_failure)

    def interrupted():
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
        def interrupt(r):
            raise KeyboardInterrupt()
        remote.effect = interrupt
        try:
            adapter.execute(["go", "test"])
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError("interruption swallowed")
        assert remote.calls[-3:] == ["cleanup", "inventory", "inventory"]
        adapter.retire()
        assert not adapter.quarantined
    check("interruption cleans and verifies before propagation", interrupted)

    def deadline():
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
        remote.effect = lambda r: 124
        assert adapter.execute(["go", "test"]).returncode == 124
        adapter.retire()
        adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
        def expired(r):
            r.outputs["timeout.log"] = b'timeout: sending signal TERM to command /bin/bash\n'
            return 124
        remote.effect = expired
        try:
            adapter.execute(["go", "test"])
        except subprocess.TimeoutExpired as error:
            assert error.timeout == 600 and error.output == "actual stdout\n"
            assert isinstance(error, ExecutionTimeout) and error.basis == 'monitor'
            assert adapter.command_evidence[-1]['timeout_basis'] == 'monitor'
            assert adapter.command_evidence[-1]['returncode'] == 124
        else:
            raise AssertionError("deadline was not classified")
        adapter.retire()
    check("timeout evidence distinguishes normal exit124 and retains600 budget", deadline)

    def slow_retire_after_deadline():
        # A mutant spinning over fresh names until its deadline left a tree
        # whose removal outlasted the 30 s housekeeping bound; the timed-out
        # command's verdict stands and retirement still completes.
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
        def expired(r):
            r.outputs["timeout.log"] = b'timeout: sending signal TERM to command /bin/bash\n'
            return 124
        remote.effect = expired
        run = remote.run
        def slow(command, timeout, input=None):
            if shlex.split(command)[5] == "retire" and timeout < 120:
                raise subprocess.TimeoutExpired(command, timeout)
            return run(command, timeout, input)
        remote.run = slow
        try:
            adapter.execute(["go", "test"])
        except ExecutionTimeout as error:
            assert error.basis == 'monitor'
        else:
            raise AssertionError("deadline was not classified")
        adapter.retire()
        assert not adapter.quarantined and remote.transport[-1] == ("retire", RETIRE_TIMEOUT, None)
        assert all(timeout <= 30 for verb, timeout, _ in remote.transport if verb not in {"retire", "execute"})
    check("retirement after a deadline has its own bound, reads keep 30 s", slow_retire_after_deadline)

    def retire_failure():
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
        remote.fault = "retire"
        refused(adapter.retire)
        assert adapter.quarantined
    check("retirement failure quarantines the worker", retire_failure)

    def policy():
        adapter, remote, context = fixture()
        manifest = adapter.original_manifest
        for field, value in (("substrate_roots", []), ("substrate_volatile", []),
                             ("digests", {}), ("build_roots", ["target"])):
            import copy
            bad = copy.deepcopy(manifest)
            setattr(bad, field, value)
            refused(lambda: ExecutionCopy(remote,
                    original_inventory=adapter.original_inventory,
                    boundary=adapter.original_boundary, original_manifest=bad))
        refused(lambda: adapter.prepare(context, None, {},
                coordination_inputs={"internal/pkg/source.go": b"tamper"}, allowed_paths=(context["glue_path"],)))
        assert not remote.calls
    check("Go policy cannot fall back; coordination cannot alter protected inputs", policy)

    def helper_failure():
        adapter, remote, context = fixture()
        remote.fault = "inventory"
        refused(lambda: adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],)))
        assert adapter.quarantined and remote.calls == ["inventory"]
    check("nonzero inventory helper refuses without adopting partial output", helper_failure)
    def two_phase():
        adapter, remote, context = fixture()
        glue = context["glue_path"]
        remote.original[glue] = b"cold candidate"
        clock = [100.0]
        with patch("r2t.go.execution.time.monotonic", side_effect=lambda: clock[0]):
            adapter.prepare(context, {context["glue_path"]: b"cold candidate"}, {}, allowed_paths=(context["glue_path"],))
            def planning(r):
                r.outputs["plan.json"] = b'{"trusted_plan":true}\n'
                clock[0] += 125
            remote.effect = planning
            assert adapter.run_planner(["trusted-runplan", "--output", "plan.json"]).returncode == 0
            assert adapter.read("plan.json", output=True) == b'{"trusted_plan":true}\n'
            clock[0] += 5  # host folding and validation are part of this budget
            scaffold = context["package_dir"] + "/zz_r2t_harness_test.go"
            adapter.finalize({glue: b"interposed candidate", scaffold: b"trusted helper"})
            assert adapter.read(glue) == b"interposed candidate"
            remote.effect = None
            clock[0] += 10
            adapter.execute(["go", "test"])
            assert remote.durations == [600, 460]
            assert remote.calls.count("prepare") == 1
            count_before = len(remote.calls)
            refused(lambda: adapter.finalize({}))
            assert adapter.quarantined and len(remote.calls) == count_before
    check("cold planning, host fold and final test share600 without recopy; late finalize refuses",
          two_phase)

    def expired_plan():
        adapter, remote, context = fixture()
        clock = [0.0]
        with patch("r2t.go.execution.time.monotonic", side_effect=lambda: clock[0]):
            adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
            adapter.run_planner(["trusted-runplan"])
            clock[0] = 601
            previous = list(remote.calls)
            try:
                adapter.finalize({"internal/pkg/source.go": b"trusted"})
            except subprocess.TimeoutExpired as error:
                assert error.timeout == 600
            else:
                raise AssertionError("expired planning budget admitted writes")
            assert remote.calls == previous and not adapter.quarantined
            adapter.retire()
    check("expired planning refuses finalization effects without renewing deadline", expired_plan)

    def planner_mutation():
        adapter, remote, context = fixture()
        glue = context["glue_path"]
        remote.original[glue] = b"answer"
        adapter.prepare(context, {context["glue_path"]: b"answer"}, {}, allowed_paths=(context["glue_path"],))
        remote.effect = lambda r: r.copy.update({glue: b"unexpected planner edit"})
        refused(lambda: adapter.run_planner(["trusted-runplan"]))
        assert adapter.quarantined and "cleanup" in remote.calls
    check("read-only planner cannot alter removable answer before finalization", planner_mutation)

    def unfinalized():
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
        adapter.run_planner(["trusted-runplan"])
        previous = list(remote.calls)
        refused(lambda: adapter.execute(["go", "test"]))
        assert remote.calls == previous
    check("planned copy cannot execute until trusted finalization", unfinalized)

    def finalize_write():
        adapter, remote, context = fixture()
        adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
        adapter.run_planner(["trusted-runplan"])
        remote.fault, remote.fault_output = "write", ""
        refused(lambda: adapter.finalize({"internal/pkg/source.go": b"trusted rewrite"}))
        assert adapter.quarantined
    check("finalization requires exact remote transformed byte inventory", finalize_write)

    def expired_test():
        adapter, remote, context = fixture()
        clock = [0.0]
        with patch("r2t.go.execution.time.monotonic", side_effect=lambda: clock[0]):
            adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
            adapter.run_planner(["trusted-runplan"])
            adapter.finalize({})
            clock[0] = 601
            previous = list(remote.calls)
            try:
                adapter.execute(["go", "test"])
            except subprocess.TimeoutExpired as error:
                assert error.timeout == 600
            else:
                raise AssertionError("expired shared budget launched candidate")
            assert remote.calls == previous
            adapter.retire()
    check("late final test gets no additional600 and launches no process", expired_test)
    def large_transform():
        adapter, remote, context = fixture()
        # Matches the real admitted openapi.go size; native qualification uses
        # the exact pinned source bytes, not this network-free synthetic body.
        raw = (b"// large source fixture\n" * 8000)[:165124]
        adapter.prepare(context, None, {"external/httpserver/openapi.go": raw}, allowed_paths=(context["glue_path"],))
        assert adapter.read("external/httpserver/openapi.go") == raw
        writes = [entry for entry in remote.transport if entry[0] == "write"]
        assert len(writes) == 1 and len(writes[0][2]) == 220168
        adapter.retire()
    check("165124-byte transform uses stdin with exact readback", large_transform)

    def finalize_expiry():
        adapter, remote, context = fixture()
        clock = [0.0]
        with patch("r2t.go.execution.time.monotonic", side_effect=lambda: clock[0]):
            adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
            adapter.run_planner(["trusted-runplan"])
            clock[0] = 599.0
            remote.after_call = lambda verb: clock.__setitem__(0, 601.0) if verb == "write" else None
            try:
                adapter.finalize({"internal/pkg/source.go": b"trusted first",
                                  "internal/pkg/unattempted.go": b"trusted second"})
            except subprocess.TimeoutExpired as error:
                assert error.timeout == 600
            else:
                raise AssertionError("finalize succeeded after its first write exceeded deadline")
            assert remote.copy["internal/pkg/source.go"] == b"trusted first"
            assert "internal/pkg/unattempted.go" not in remote.copy
            assert [x[1] for x in remote.transport if x[0] == "write"] == [1.0]
            assert remote.calls[-2:] == ["inventory", "inventory"]
            assert not adapter.quarantined
            adapter.retire()
            assert remote.copy is None
    check("expiry during finalize stops later writes and still guards/retires completed writes", finalize_expiry)

    def read_expiry():
        adapter, remote, context = fixture()
        clock = [0.0]
        with patch("r2t.go.execution.time.monotonic", side_effect=lambda: clock[0]):
            adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
            adapter.run_planner(["trusted-runplan"])
            clock[0] = 599.0
            remote.after_call = lambda verb: clock.__setitem__(0, 601.0) if verb == "read" else None
            try:
                adapter.read("stdout.log", output=True)
            except subprocess.TimeoutExpired as error:
                assert error.timeout == 600
            else:
                raise AssertionError("planner output read succeeded after expiry")
            assert remote.transport[-1][:2] == ("read", 1.0)
            assert not adapter.quarantined
            before = list(remote.calls)
            try:
                adapter.read("stdout.log", output=True)
            except subprocess.TimeoutExpired:
                pass
            else:
                raise AssertionError("expired planner read launched a helper")
            assert remote.calls == before
            adapter.retire()
    check("planner output reads are bounded and rechecked but expiry permits retirement", read_expiry)

    def planner_return_expiry():
        adapter, remote, context = fixture()
        clock = [0.0]
        with patch("r2t.go.execution.time.monotonic", side_effect=lambda: clock[0]):
            adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
            remote.after_call = lambda verb: clock.__setitem__(0, 601.0) if verb == "read" else None
            try:
                adapter.run_planner(["trusted-runplan"])
            except subprocess.TimeoutExpired as error:
                assert error.timeout == 600
            else:
                raise AssertionError("run_planner returned success after output read expiry")
            assert "cleanup" in remote.calls and not adapter.quarantined
            adapter.retire()
    check("run_planner cannot return success when its output read consumes deadline", planner_return_expiry)
    def discovery_attempts_share_deadline():
        adapter, remote, context = fixture()
        clock = [0.0]
        with patch("r2t.go.execution.time.monotonic", side_effect=lambda: clock[0]):
            def preparation_time(verb):
                if verb in {"inventory", "prepare", "write"}:
                    clock[0] += 3.0
            remote.after_call = preparation_time
            remote.effect = lambda r: clock.__setitem__(0, clock[0] + 100.0)
            for _ in range(2):
                adapter.prepare(context, None, {"_bench/discovery.txt": b"trusted"},
                                allowed_paths=(context["glue_path"],), deadline=600.0)
                assert adapter.run_planner(["go", "list"]).returncode == 0
                adapter.retire()
            assert remote.durations == [588.0, 464.0], remote.durations
            assert remote.calls.count("prepare") == remote.calls.count("cleanup") == 2
            assert remote.copy is None and not adapter.quarantined
    check("fresh discovery copies share one cutoff including preparation and cleanup time", discovery_attempts_share_deadline)

    def standalone_audit_command_clocks():
        adapter, remote, context = fixture()
        names=('_bench/go/support/mutation_audit.go', '_bench/go/support/mutation_audit_support.go')
        prefix=['/usr/local/go/bin/go','run','-p=1',*[ORIGINAL_ROOT+'/'+p for p in names]]
        for name in names:
            adapter.original_inventory[name]=_hash(b'trusted fixture')
            adapter._original_baseline[name]=_hash(b'trusted fixture')
            remote.original[name]=b'trusted fixture'
        clock=[0.0]
        with patch('r2t.go.execution.time.monotonic',side_effect=lambda:clock[0]):
            adapter.prepare(context,None,{},
                            allowed_paths=(context['glue_path'],),deadline=600.0)
            remote.effect=lambda r:clock.__setitem__(0,clock[0]+100.0)
            for action in ('setup','apply','parse'):
                assert adapter.run_audit_operation(prefix+[action]).returncode == 0
            assert remote.durations == [300.0,300.0,300.0],remote.durations
            assert remote.calls.count('cleanup') == 3 and adapter._state == 'planned'
            calls=len(remote.calls)
            refused(lambda:adapter.run_audit_operation(['go','test']))
            assert len(remote.calls) == calls
            adapter.retire()
        adapter,remote,context=fixture()
        adapter.prepare(context,None,{},allowed_paths=(context['glue_path'],))
        refused(lambda:adapter.run_audit_operation(prefix+['setup']))
        assert 'execute' not in remote.calls
        adapter.retire()
    check('standalone audit renews only its fixed trusted operation clock and retains cleanup', standalone_audit_command_clocks)

    def discovery_preparation_expiry():
        for phase in ("before", "prepare", "write"):
            adapter, remote, context = fixture()
            clock = [600.0 if phase == "before" else 599.0]
            with patch("r2t.go.execution.time.monotonic", side_effect=lambda: clock[0]):
                remote.after_call = lambda verb: clock.__setitem__(0, 601.0) if verb == phase else None
                try:
                    adapter.prepare(context, None,
                                    {"_bench/first.txt": b"first", "_bench/second.txt": b"second"},
                                    allowed_paths=(context["glue_path"],), deadline=600.0)
                except subprocess.TimeoutExpired:
                    pass
                else:
                    raise AssertionError("expired discovery preparation returned success")
                assert "execute" not in remote.calls and not adapter.quarantined
                assert remote.calls.count("write") == (1 if phase == "write" else 0)
                assert remote.calls.count("retire") == (0 if phase == "before" else 1)
                assert remote.copy is None
                if phase == "before":
                    assert remote.calls == []
                # No stale discovery deadline may affect the next ordinary item.
                remote.after_call = None
                adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],))
                adapter.execute(["go", "test"])
                adapter.retire()
                assert remote.durations == [600.0]
    check("preparation expiry stops unattempted writes and retires proved completed copies", discovery_preparation_expiry)

    def discovery_preparation_transport_timeout():
        adapter, remote, context = fixture()
        real_run = remote.run
        def timed_out(command, timeout, input=None):
            if shlex.split(command)[5] == "prepare":
                raise subprocess.TimeoutExpired(command, timeout)
            return real_run(command, timeout, input)
        remote.run = timed_out
        with patch("r2t.go.execution.time.monotonic", return_value=0.0):
            try:
                adapter.prepare(context, None, {},
                                allowed_paths=(context["glue_path"],), deadline=600.0)
            except subprocess.TimeoutExpired:
                pass
            else:
                raise AssertionError("uncertain preparation transport was accepted")
        assert adapter.quarantined and "retire" not in remote.calls
    check("uncertain preparation transport quarantines instead of claiming cleanup", discovery_preparation_transport_timeout)

    def discovery_process_census_expiry():
        adapter, remote, context = fixture()
        clock = [599.0]
        with patch("r2t.go.execution.time.monotonic", side_effect=lambda: clock[0]):
            adapter.prepare(context, None, {}, allowed_paths=(context["glue_path"],), deadline=600.0)
            remote.after_call = lambda verb: clock.__setitem__(0, 601.0) if verb == "processes" else None
            try:
                adapter.run_planner(["go", "list"])
            except subprocess.TimeoutExpired:
                pass
            else:
                raise AssertionError("expired process census launched the compiler")
            assert "execute" not in remote.calls
            assert [timeout for verb, timeout, _ in remote.transport if verb == "processes"] == [1.0]
            adapter.retire()
            assert not adapter.quarantined
    check("process census consumes the remaining discovery budget before compiler launch", discovery_process_census_expiry)

    print(f"  {count} Go execution-copy checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
