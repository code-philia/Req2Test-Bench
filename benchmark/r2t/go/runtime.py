"""Go outcomes and measurements using the shared benchmark runtime contract.

Candidate bytes cannot select control preparation or mutation authority.
"""
from __future__ import annotations

import copy
import bisect
import hashlib
from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import re
import time

from ..bench.harness import RECORD_REL, SERVICES_FRAGMENT_NAME, RunResult, Solution
from ..bench import repo
from .context import ContextRefused
from .controls import PreparedControl, helper_source, prepare_control, verify_witness
from .execution import COMMAND_TIMEOUT, ExecutionIntegrityError, ExecutionTimeout
from .registry import (GodogRefused, NativeCaptureError, capture_execution,
                       read_crash_prefix, read_runtime_native, source_selection,
                       support_files)

DIAGNOSTIC_START = 'R2T_GO_PLANNER_DIAGNOSTIC/1'
DIAGNOSTIC_END = 'R2T_GO_PLANNER_DIAGNOSTIC_END'


class RuntimeRefused(RuntimeError):
    """Unattributed or unproved execution; never a candidate result."""
    def __init__(self, message, capture=None):
        super().__init__(message)
        self.capture = capture


@dataclass
class _Attempt:
    run: RunResult
    index_errors: dict = field(default_factory=dict)
    diagnostic: object = None
    control_preparation: dict | None = None
    control_witness: dict | None = None
    mutation_evidence: dict | None = None


def _options(timeout, repeats=1, task='criterion_to_test'):
    if type(timeout) is not int or timeout != COMMAND_TIMEOUT:
        raise ValueError('Go runtime requires the shared 600-second timeout')
    if type(repeats) is not int:
        raise ValueError('Go repeats must be an integer')
    if task != 'criterion_to_test':
        raise ContextRefused('Go runtime supports only witnessed criterion_to_test items')
    return max(1, repeats)


def _context(harness, feature=None, scenario=None):
    root = Path(harness.root).resolve()
    if feature is None:
        selected = harness._selected
        if selected is None:
            raise ContextRefused('select a witnessed Go context before execution')
        context = harness.contexts.context_for(selected['feature_path'], selected['scenario_line'])
        if context != selected:
            raise ContextRefused('selected Go context differs from its immutable table')
    else:
        try:
            path = Path(feature.path).resolve().relative_to(root).as_posix()
        except (ValueError, TypeError) as error:
            raise ContextRefused('Go feature is outside its workspace') from error
        context = harness.contexts.context_for(path, scenario.line)
    return context


def _source(harness, context):
    root = Path(harness.root).resolve()
    target = root / context['feature_path']
    if not target.resolve().is_relative_to(root):
        raise ContextRefused('original Go feature escapes its workspace')
    source = target.read_text(encoding='utf-8')
    return source, source_selection(context, source)[3]


def _reset_record(harness, context):
    harness.clear_registration()
    harness.select(context['feature_path'], context['scenario_line'])


def _export(harness, records):
    root = Path(harness.root).resolve(); path = root / RECORD_REL
    if not path.resolve().is_relative_to(root):
        raise RuntimeRefused('Go exported record escapes its workspace')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(row) + '\n' for row in records), encoding='utf-8')


def _project_records(capture, witness, *, coverage):
    from .measurement import project
    return project(capture, witness, coverage=coverage)


def _diagnostic_sources(harness, context, installed):
    """Retain source bytes against existing authority before the copy starts."""
    root = Path(harness.root).resolve(); result = {}
    for path, expected in harness.copy.original_inventory.items():
        if Path(path).parent.as_posix() != context['package_dir'] or not path.endswith('.go'):
            continue
        target = root/path
        if not target.resolve().is_relative_to(root):
            raise RuntimeRefused('diagnostic source escapes its verified workspace')
        raw = target.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise RuntimeRefused('diagnostic source differs from the verified seed before capture')
        result[path] = raw
    result.update(installed)
    return result


def _candidate_diagnostic(stdout, context, *, sources=None):
    """Consume the trusted frame; compile positions bind to pre-capture bytes."""
    lines = stdout.splitlines()
    if not lines or lines[0] != DIAGNOSTIC_START:
        return None
    try:
        if len(lines) < 3 or lines[2] != DIAGNOSTIC_END:
            raise ValueError('incomplete frame')
        row = json.loads(lines[1])
        fields = {'schema', 'attribution', 'stage', 'file', 'message'}
        if (row['schema'] != 'r2t.go-planner-diagnostic/1' or row['attribution'] != 'candidate'
                or row['file'] != context['glue_path'] or not isinstance(row['message'], str)
                or not row['message']):
            raise ValueError('invalid diagnostic identity')
        if row['stage'] in ('parse','scaffold'):
            if set(row) != fields:
                raise ValueError('invalid primary diagnostic fields')
            return {row['file']: {'kind': row['stage'], 'message': row['message']}}
        if (row['stage'] != 'compile' or set(row) != fields | {'package_dir','package_name','sources','diagnostics'}
                or row['package_dir'] != context['package_dir'] or row['package_name'] != context['package_name']
                or not isinstance(row['sources'], dict) or not row['sources'] or not isinstance(sources, dict)
                or context['glue_path'] not in row['sources']):
            raise ValueError('compile diagnostic lacks its authenticated selected package')
        for path, digest in row['sources'].items():
            if (path not in sources or Path(path).parent.as_posix() != context['package_dir']
                    or hashlib.sha256(sources[path]).hexdigest() != digest):
                raise ValueError('compile source differs from pre-capture inputs')
        if not isinstance(row['diagnostics'], list) or not row['diagnostics']:
            raise ValueError('compile diagnostic is empty')
        errors = {}
        for error in row['diagnostics']:
            if (set(error) != {'file','line','column','offset','message','kind','soft'}
                    or error['file'] not in row['sources'] or error['kind'] not in ('types.Error','scanner.Error')
                    or type(error['soft']) is not bool or not isinstance(error['message'], str)
                    or not error['message'] or any(type(error[k]) is not int for k in ('line','column','offset'))):
                raise ValueError('invalid typed diagnostic')
            raw = sources[error['file']]; offset = error['offset']
            if not 0 <= offset <= len(raw):
                raise ValueError('typed diagnostic offset outside original source')
            starts = [0] + [i+1 for i, value in enumerate(raw) if value == 10 and i+1 < len(raw)]
            line = bisect.bisect_right(starts, offset)
            if error['line'] != line or error['column'] != offset-starts[line-1]+1:
                raise ValueError('typed diagnostic lost its physical source position')
            errors.setdefault(error['file'], {'kind':'compile', 'diagnostics':[]})['diagnostics'].append(copy.deepcopy(error))
        return errors
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise RuntimeRefused('malformed or unauthenticated Go planner diagnostic') from error


def _violation(reports):
    return {key: sorted({path for report in reports.values() for path in report.get(key, [])})
            for key in ('changed', 'missing', 'added')}


def _host_postcondition(harness):
    report = repo.verify_substrate(harness.man, harness.boundary,
                                  expected=harness.expected_mutations)
    if report['baseline'] and any(report[key] for key in ('changed', 'missing', 'added')):
        harness.copy.quarantined = True
        raise repo.SubstrateTampered(report)


def _timeout(harness, error, *, context, rows, started, deadline, capture=None):
    if (not isinstance(error, ExecutionTimeout) or error.basis not in ('deadline', 'monitor')
            or time.monotonic() < deadline or harness.copy.quarantined
            or harness.copy._state != 'idle'):
        raise RuntimeRefused('Go timeout lacks deadline and clean-retirement proof', capture) from error
    commands = capture.commands if capture is not None else harness.copy.command_evidence
    for command in commands:
        if command['seconds'] is None:
            continue  # Expiry before a command started needs no process cleanup.
        processes, integrity = command['processes'], command['integrity']
        if (processes is None or processes['cleanup'] != 'R2T_CLEANUP/1\ncomplete\nR2T_CLEANUP_END\n'
                or integrity is None or any(any(report[key] for key in ('changed','missing','added'))
                                           for report in integrity.values())):
            raise RuntimeRefused('Go timeout cleanup or integrity is unproved', capture) from error
    output = next((row['stdout'] for row in reversed(commands) if row.get('stdout') is not None), '')
    cleanup = 'killed' if any(row['seconds'] is not None for row in commands) else 'no_pid'
    return _Attempt(RunResult(-1, output, time.monotonic()-started, timed_out=True,
        expected_line=context['scenario_line'], expected_lines=rows, timeout_cleanup=cleanup,
        error_markers=()), mutation_evidence=(None if capture is None else copy.deepcopy(capture.mutation_evidence)))


#: Go 1.25 may print `gp=... m=...` between the id and the status.
_GOROUTINE = re.compile(r'goroutine \d+ [^\[]*\[')
_PACKAGE_FAIL = re.compile(r'FAIL\t(\S+)\t\d+(?:\.\d+)?s$')
#: Runtime resource exhaustion names the host, not the mutant.
_RESOURCE_EXHAUSTION = ('out of memory', 'failed to create new OS thread',
                        'newosproc', 'cannot allocate memory')
#: How `go test` reports a test binary that SIGKILL ended: the wait status,
#: appended to the binary's last output, then the package FAIL result.
_KILLED = 'signal: killed'
#: Go's testing package writes `cleanup panicked with <value>` with no
#: newline before it repanics, so the runtime's `panic: ` starts mid-line.
_CLEANUP_PANIC = re.compile(r'^(\s*cleanup panicked with [^\n]*?)((?:panic|fatal error): )', re.M)
#: What Go prints when a step called FailNow on the outer test.
_PARENT_FAILNOW = ('test executed panic(nil) or runtime.Goexit: '
                   'subtest may have called FailNow on a parent test')


def _go_crash(completed, context):
    """Classify a mutant's Go test-process crash, with route B's two readings.

    `_go_trace_crash` decides first. Only an exit it classifies as no crash
    is read again, so no exit it already classifies changes:

    - the streams with a `cleanup panicked with ...` line split before its
      `panic: ` or `fatal error: `, read by `_go_trace_crash` again; every
      other condition of the crash rule applies unchanged;
    - `go test` exit 1 with the line `_PARENT_FAILNOW`, the selected
      package's FAIL result and no `panic: `/`fatal error: ` line in either
      stream is ('kill', 'go_parent_failnow'): a step called FailNow on the
      outer test, which ends it through runtime.Goexit (owner ruling
      2026-10-01: a kill).

    Either kill still needs the native prefix that `read_crash_prefix`
    admits (`_capture_attempt`). Ported from the research repository's
    experiments/coddy-agent-v2/completion-operators/route_b.py
    `crash_readings`, which the paper's coddy candidate scoring installed
    over this module (CODDY_AGENT_FULL282_MUTATION_SPEC.md section 2,
    amended 2026-10-01). Patch P2 in engine/UPSTREAM.json.
    """
    crash = _go_trace_crash(completed, context)
    if crash is not None:
        return crash
    split = copy.copy(completed)
    for name in ('stdout', 'stderr'):
        setattr(split, name, _CLEANUP_PANIC.sub(r'\1\n\2', getattr(completed, name) or ''))
    if (split.stdout, split.stderr) != (completed.stdout or '', completed.stderr or ''):
        crash = _go_trace_crash(split, context)
        if crash is not None:
            return crash
    lines = split.stdout.splitlines()
    traced = any(line.startswith(('panic: ', 'fatal error: '))
                 for text in (split.stdout, split.stderr) for line in text.splitlines())
    if (completed.returncode == 1 and not traced
            and any(line.strip().endswith(_PARENT_FAILNOW) for line in lines)
            and any(_selected_fail(line, context) for line in lines)):
        return 'kill', 'go_parent_failnow'
    return None


def _go_trace_crash(completed, context):
    """Classify a Go runtime crash of the selected test binary.

    `go test` reports a test binary that died of a runtime panic or fatal
    error with exit 1 (2 is admitted too; it is also the go command's
    build-failure status, which never prints the result line required
    below). The runtime's own trace is required in order: a `panic: ` or
    `fatal error: ` line, the crashing goroutine's header, then the go
    command's timed FAIL result for the selected package.

    Returns None when that is absent or is not the mutant's crash, so the
    existing handling applies: the test binary's own `panic: test timed out`,
    and a crash raised in benchmark support code, i.e. whose innermost
    non-runtime frame lies under `_bench/` or in the recorder helper the
    planner installs as `zz_r2t_harness_test.go` (its recorder panics on
    write errors). Runtime resource exhaustion returns
    ('infrastructure', line); any other crash returns ('kill', label).

    A test binary that the kernel's OOM killer ended leaves no Go trace:
    SIGKILL cannot be caught, so `go test` prints only `signal: killed` and
    the selected package's timed FAIL result. That is resource exhaustion
    too, so it returns ('infrastructure', 'signal: killed') when neither
    stream has a `panic: ` or `fatal error: ` line. Any other sender of
    SIGKILL is likewise not a mutant verdict. The harness's own deadline is
    an ExecutionTimeout before this is read, and go test's own kill
    (-timeout plus one minute) comes after that deadline.
    CODDY_AGENT_FULL282_MUTATION_SPEC.md section 2, amended 2026-09-28.
    """
    if completed.returncode not in (1, 2):
        return None
    traced = False
    for text in (completed.stdout, completed.stderr):
        lines = (text or '').splitlines()
        start = next((i for i, line in enumerate(lines)
                      if line.startswith(('panic: ', 'fatal error: '))), None)
        if start is None:
            continue
        traced = True
        if lines[start].startswith('panic: test timed out after '):
            return None
        trace = next((i for i in range(start+1, len(lines)) if _GOROUTINE.match(lines[i])), None)
        if trace is None:
            continue
        if not any(_selected_fail(line, context) for line in lines[trace+1:]):
            continue
        cause = start
        while cause and lines[cause-1].startswith('runtime: '):
            cause -= 1
        if any(marker in line for line in lines[cause:start+1] for marker in _RESOURCE_EXHAUSTION):
            return 'infrastructure', lines[start]
        if _support_frame(lines, trace):
            return None
        return 'kill', ('go_panic' if lines[start].startswith('panic: ') else 'go_fatal_error')
    lines = (completed.stdout or '').splitlines()
    if not traced and any(lines[i-1].endswith(_KILLED) and _selected_fail(lines[i], context)
                          for i in range(1, len(lines))):
        return 'infrastructure', _KILLED
    return None


def _selected_fail(line, context):
    """Whether `line` is the go command's timed FAIL result for our package."""
    match = _PACKAGE_FAIL.match(line)
    return match is not None and (match[1] == context['package_dir']
                                  or match[1].endswith('/'+context['package_dir']))


def _support_frame(lines, trace):
    """Whether the crashing goroutine's innermost non-runtime frame is ours.

    Its traceback lists frames innermost first, each a function line then a
    tab-indented location, up to `created by` (where it was started, not
    where it crashed). A panic that `testing.tRunner` recovered and raised
    again (the recorder runs on a `t.Run` goroutine) shows tRunner's frames
    above a `panic(` frame; the frame that raised it lies just below the
    innermost `panic(` frame, so the search starts there.
    """
    frames = []
    i = trace + 1
    while i + 1 < len(lines) and lines[i] and not lines[i].startswith('created by '):
        function, location = lines[i], lines[i+1]
        if location.startswith('\t') and not function.startswith('\t'):
            frames.append((function, location))
            i += 2
        else:
            i += 1
    raised = next((n for n, (function, _) in enumerate(frames) if function.startswith('panic(')), -1)
    for function, location in frames[raised+1:]:
        if not function.startswith(('runtime.', 'internal/runtime/', 'panic(')):
            return '/_bench/' in location or '/zz_r2t_harness_test.go:' in location
    return False


def _crash_attempt(captured, completed, context, rows, crash, elapsed):
    """The verdict on a mutant attempt whose Go test process crashed.

    The native stream never completed, so no record is projected from it. A
    crash kill (owner ruling 2026-09-28) is a measurement: RunResult reads
    its label as the literal `failed` and exports it. Resource exhaustion is
    infrastructure: its crash line (or `signal: killed`) marks the run
    `container_error`, which takes the existing single retry and is then
    excluded.
    """
    kind, value = crash
    return _Attempt(RunResult(completed.returncode, completed.stdout, elapsed, records=[],
        expected_line=context['scenario_line'], expected_lines=rows,
        error_markers=(value,) if kind == 'infrastructure' else (),
        crash=value if kind == 'kill' else None),
        mutation_evidence=copy.deepcopy(captured.mutation_evidence))


def _retained_helpers(harness, context, installed):
    """Harness-owned helper files for one candidate, and what they supply.

    Every ordinary execution receives each retained-test helper its answer
    files do not declare (harness 25; specifications/EVALUATOR_CORRECTIONS_
    20261015_AMENDMENT.md). Gold declares them all and receives nothing. The
    files go into the disposable execution copy alone; retiring the copy
    removes them. Prepared controls never reach this.
    """
    from .sensitivity import overlay
    return overlay(context, installed, harness.manifest.gold_root)


def _capture_attempt(harness, context, source, rows, *, installed, prepared,
                     closure, coverage, started, deadline, mutation=None, evidence_dir=None,
                     overlay=None):
    paths = harness.contexts.files_for(context['feature_path'], context['scenario_line'])
    initial = support_files(); helper = None; helper_path = '_bench/go/support/harness.go'
    overlay = overlay or {}
    if prepared is None:
        original = installed[context['glue_path']]
        initial.update(overlay)
    else:
        original = prepared.files[context['glue_path']]
        initial.update(prepared.files)
        helper = helper_source(); helper_path = '_bench/go/support/control_harness.go'
        initial[helper_path] = helper
    diagnostic_sources = (_diagnostic_sources(harness, context, {**installed, **overlay})
                          if prepared is None else None)
    try:
        captured = capture_execution(harness.copy, context=context, feature_source=source,
            installed=installed, paths=paths, original=original, initial=initial,
            coordination_inputs=harness.coordination_inputs(), deadline=deadline,
            helper_path=helper_path, helper_template=helper,
            measurement=coverage, control=prepared is not None, runtime_diagnostics=True, mutation=mutation,
            **({} if evidence_dir is None else {"evidence_dir":evidence_dir}))
    except NativeCaptureError as error:
        cause = error.cause
        if (isinstance(cause, ExecutionIntegrityError) and cause.phase == 'executed'
                and cause.scope == 'protected_substrate' and prepared is None):
            raise repo.SubstrateTampered(_violation(cause.reports)) from error
        if isinstance(cause, ExecutionTimeout):
            return _timeout(harness, cause, context=context, rows=rows, started=started,
                            deadline=deadline, capture=error.capture)
        raise RuntimeRefused('Go capture failed before a trustworthy native outcome', error.capture) from error
    elapsed = time.monotonic()-started
    if captured.planner.returncode:
        errors = _candidate_diagnostic(captured.planner.stdout, context, sources=diagnostic_sources) if prepared is None else None
        if errors is None:
            raise RuntimeRefused('Go planner failure is not attributed by a trusted candidate diagnostic', captured)
        return _Attempt(RunResult(captured.planner.returncode, captured.planner.stdout, elapsed,
            expected_line=context['scenario_line'], expected_lines=rows, error_markers=()), errors,
            mutation_evidence=copy.deepcopy(captured.mutation_evidence))
    completed = captured.completed
    # Only a coordinator mutation attempt classifies a test-process crash.
    crash = (_go_crash(completed, context)
             if mutation is not None and completed is not None else None)
    if completed is None or (completed.returncode not in (0, 1) and crash is None):
        raise RuntimeRefused('Go execution has no supported test exit', captured)
    control_witness = None
    if captured.native in (None, b''):
        if prepared is not None:
            raise RuntimeRefused('Go control is missing its required native witness', captured)
        if crash is not None:
            return _crash_attempt(captured, completed, context, rows, crash, elapsed)
        # Match the shared empty-recorder rule after successful planning and
        # proved capture cleanup, including candidate init/setup failures.
        # The wrapper opens the recorder before rejecting a suite with nil
        # Options, so that ordinary early failure leaves an empty file.
        # Nonempty streams still require the complete native witness.
        records, diagnostic = [], None
    else:
        try:
            # A mutant can make a scenario's Before hook fail (full282 section 2):
            # Godog's complete record of that is the literal failure, a kill.
            witness = read_runtime_native(captured.native, context=context, feature_source=source,
                                          source_map=captured.source_map, exit_code=completed.returncode,
                                          hook_failure=mutation is not None and prepared is None)
            if prepared is not None:
                verified = verify_witness({'native': captured.native, 'witness': witness},
                                          prepared.mode, closure)
                control_witness = copy.deepcopy(verified['control_witness'])
        except GodogRefused as error:
            if crash is not None:
                try:
                    read_crash_prefix(captured.native, context=context, feature_source=source,
                                      source_map=captured.source_map,
                                      hook_failure=mutation is not None and prepared is None)
                except GodogRefused:
                    pass
                else:
                    return _crash_attempt(captured, completed, context, rows, crash, elapsed)
            raise RuntimeRefused('native Go status/control witness is incomplete or inconsistent', captured) from error
        records, diagnostic = _project_records(captured, witness, coverage=coverage)
    return _Attempt(RunResult(completed.returncode, completed.stdout, elapsed, records=records,
        expected_line=context['scenario_line'], expected_lines=rows, error_markers=()),
        diagnostic=diagnostic, control_witness=control_witness,
        mutation_evidence=copy.deepcopy(captured.mutation_evidence))


def _installed(harness, context):
    root = Path(harness.root).resolve(); paths = harness.contexts.files_for(context['feature_path'], context['scenario_line'])
    result = {}
    for path in paths:
        target = root / path
        if not target.resolve().is_relative_to(root) or not target.is_file() or target.is_symlink():
            raise RuntimeRefused('Go execution needs the complete installed regular-file answer set')
        result[path] = target.read_bytes()
    return result


def execute(harness, coverage=False, timeout=600, expected_line=None, expected_lines=None):
    """One ordinary candidate invocation; no control authority is accepted here."""
    _options(timeout); context = _context(harness)
    harness.verify_substrate(); source, rows = _source(harness, context)
    if ((expected_line is not None and expected_line != context['scenario_line'])
            or (expected_lines is not None and list(expected_lines) != rows)):
        raise ContextRefused('Go result selection differs from the witnessed scenario/Examples')
    _reset_record(harness, context); installed = _installed(harness, context)
    overlay, _ = _retained_helpers(harness, context, installed)
    started = time.monotonic()
    try:
        attempt = _capture_attempt(harness, context, source, rows, installed=installed,
            prepared=None, closure=None, coverage=coverage, started=started,
            deadline=started+COMMAND_TIMEOUT, overlay=overlay)
    finally:
        _host_postcondition(harness)
    _export(harness, attempt.run.records)
    return attempt.run


def _answer_errors(harness, solution, paths):
    rejected = []; encoded = {}; root = Path(harness.root).resolve()
    if solution.services_fragment:
        rejected.append({'file_path': SERVICES_FRAGMENT_NAME, 'why': 'no_wiring_channel:godog'})
    for answer in solution.files:
        path, code = answer.file_path, answer.code
        why = None
        if not isinstance(path, str) or path not in paths:
            why = 'not_in_witnessed_closure'
        elif path in encoded:
            why = 'duplicate_answer_path'
        elif not (root/path).resolve().is_relative_to(root):
            why = 'path_escape'
        elif not isinstance(code, str):
            why = 'code_must_be_text'
        else:
            try: encoded[path] = code.encode('utf-8')
            except UnicodeError: why = 'code_must_be_utf8'
        if why:
            rejected.append({'file_path': path, 'why': why})
    missing = sorted(set(paths)-set(encoded))
    errors = ({'answer_files': {'message': 'requires the complete witnessed Go answer set',
                              'missing': missing}} if missing else {})
    return rejected, errors


def _envelope(written, rejected, errors, attempts, violation=None, keep_stdout=False,
              supplied=None):
    runs = []
    for attempt in attempts:
        run = attempt.run.to_json(keep_stdout=keep_stdout)
        if attempt.control_preparation is not None:
            run['control_preparation'] = copy.deepcopy(attempt.control_preparation)
        if attempt.control_witness is not None:
            run['control_witness'] = copy.deepcopy(attempt.control_witness)
        if attempt.mutation_evidence is not None:
            run['go_mutation'] = copy.deepcopy(attempt.mutation_evidence)
        runs.append(run)
    envelope = {'substrate_violation': violation, 'written_files': written, 'rejected_files': rejected,
        'feature_from_solution': False, 'index_errors': errors, 'registered_contexts': sorted(written),
        'runs': runs,
        'outcomes': [a.run.outcome for a in attempts],
        'collection_complete': bool(attempts) and all(a.run.records and all(
            row.get('coverage') is not None and row.get('direct_calls') is not None
            for row in a.run.records) for a in attempts),
        'go_diagnostics': [a.diagnostic for a in attempts if a.diagnostic is not None]}
    if supplied is not None:
        # Which retained-test helpers the harness added, by gold file; {} when none.
        envelope['supplied_helpers'] = copy.deepcopy(supplied)
    return envelope


def run_solution(harness, feature, scenario, solution: Solution, coverage=False,
                 timeout=600, repeats=1, task='criterion_to_test', keep_stdout=False, *, mutation=None, evidence_dir=None):
    """Install one whole candidate set and run fresh copies with the shared fold.

    Only the coordinator mutation adapter supplies the independently bound
    mutation request; ordinary candidate submissions cannot set it.
    """
    if mutation is not None and coverage:
        raise RuntimeRefused('Go mutation attempts do not collect API/coverage')
    repeats = _options(timeout, repeats, task); context = _context(harness, feature, scenario)
    if evidence_dir is not None:
        evidence_dir = Path(evidence_dir).resolve()
        if (not evidence_dir.is_dir() or any(evidence_dir.iterdir())
                or evidence_dir.is_relative_to(Path(harness.root).resolve())):
            raise RuntimeRefused('Go capture evidence needs a new empty directory outside the workspace')
    harness.verify_substrate(); repo.clean_workspace(harness.man, harness.boundary)
    _reset_record(harness, context); source, rows = _source(harness, context)
    paths = harness.contexts.files_for(context['feature_path'], context['scenario_line'])
    rejected, errors = _answer_errors(harness, solution, paths)
    if rejected or errors:
        _host_postcondition(harness)
        return _envelope([], rejected, errors, [], keep_stdout=keep_stdout, supplied={})
    attempts = []; violation = None; written = []; supplied = {}; unscorable = None
    try:
        written = harness.install_solution(solution, task)
        overlay, supplied = _retained_helpers(harness, context, _installed(harness, context))
        for number in range(repeats):
            _reset_record(harness, context)
            capture_dir = None
            if evidence_dir is not None:
                capture_dir = evidence_dir / str(number + 1)
                capture_dir.mkdir()
            started = time.monotonic()
            attempt = _capture_attempt(harness, context, source, rows, installed=_installed(harness, context),
                prepared=None, closure=None, coverage=coverage, started=started,
                deadline=started+COMMAND_TIMEOUT, mutation=mutation, evidence_dir=capture_dir,
                overlay=overlay)
            attempts.append(attempt); errors.update(attempt.index_errors)
            _export(harness, attempt.run.records)
    except repo.SubstrateTampered as error:
        violation = {k: list(error.report.get(k, [])) for k in ('changed','missing','added')}
        # Owner ruling 2026-09-30: a mutant test that only added files to its
        # disposable copy leaves an unscorable pair, not a quarantined worker.
        unscorable = harness.copy.retire_unscorable() if mutation is not None else None
    except BaseException:
        _host_postcondition(harness)
        raise
    try: _host_postcondition(harness)
    except repo.SubstrateTampered as error:
        violation = _violation({'capture': violation or {}, 'host': error.report}); unscorable = None
    envelope = _envelope(written, rejected, errors, attempts, violation, keep_stdout, supplied)
    if unscorable is not None:
        # The merged violation stays for any reader that does not know the ruling.
        envelope['unscorable_substrate'] = unscorable
    return envelope


def _gold(harness, paths):
    root = Path(harness.manifest.gold_root).resolve(); originals = {}
    for path in paths:
        target = root/path
        if not target.resolve().is_relative_to(root) or not target.is_file():
            raise RuntimeRefused('Go control original is absent or escapes preserved gold')
        originals[path] = target.read_bytes()
    return originals


def _prepared(value, context, mode, paths):
    if (not isinstance(value, PreparedControl) or value.context != context or value.mode != mode
            or not isinstance(value.files, dict) or set(value.files) != set(paths) or not all(isinstance(v, bytes) for v in value.files.values())):
        raise RuntimeRefused('Go control preparation differs from the trusted mode/context/whole-file set')


def run_control(harness, feature, scenario, *, mode, closure, prepared=None, deadline=None,
                coverage=False, timeout=600, repeats=1, task='criterion_to_test', keep_stdout=False):
    """Only the explicit coordinator route can read gold and prepare controls."""
    repeats = _options(timeout, repeats, task); context = _context(harness, feature, scenario)
    harness.check_context(closure)
    if mode not in ('empty','noop') or closure['go_suite'] != context:
        raise RuntimeRefused('Go control mode or closure differs from selected context')
    paths = harness.contexts.files_for(context['feature_path'], context['scenario_line'])
    if prepared is not None:
        _prepared(prepared, context, mode, paths)
        if deadline is None:
            raise RuntimeRefused('prepared control requires its original deadline')
    if deadline is not None and (type(deadline) not in (int,float) or not math.isfinite(deadline)
                                 or deadline > time.monotonic()+COMMAND_TIMEOUT):
        raise ValueError('Go control deadline must preserve a finite cutoff within600 seconds')
    harness.verify_substrate(); repo.clean_workspace(harness.man, harness.boundary)
    _reset_record(harness, context); source, rows = _source(harness, context)
    originals = _gold(harness, paths); attempts = []; first_files = None
    try:
        for number in range(repeats):
            _reset_record(harness, context)
            cutoff = deadline if number == 0 and deadline is not None else time.monotonic()+COMMAND_TIMEOUT
            started = cutoff-COMMAND_TIMEOUT
            current = prepared if number == 0 else None
            try:
                if time.monotonic() >= cutoff:
                    raise ExecutionTimeout(['control'], basis='deadline')
                if current is None:
                    current = prepare_control(harness.copy, context=context, original_answers=originals,
                        allowed_paths=paths, mode=mode, closure=closure, deadline=cutoff,
                        coordination_inputs=harness.coordination_inputs())
                _prepared(current, context, mode, paths)
                if first_files is None: first_files = dict(current.files)
                elif current.files != first_files:
                    raise RuntimeRefused('Go control preparation changed across stability repeats')
                attempt = _capture_attempt(harness, context, source, rows, installed=None,
                    prepared=current, closure=closure, coverage=coverage, started=started, deadline=cutoff)
            except ExecutionTimeout as error:
                attempt = _timeout(harness, error, context=context, rows=rows,
                                   started=started, deadline=cutoff)
            if current is not None:
                attempt.control_preparation = copy.deepcopy(current.plan)
            attempts.append(attempt); _export(harness, attempt.run.records)
    finally:
        _host_postcondition(harness)
    return _envelope(list(paths) if mode == 'noop' else [], [], {}, attempts, keep_stdout=keep_stdout)
