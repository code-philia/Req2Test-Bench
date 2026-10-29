"""Godog's native Defined witness and fail-closed, uncollected status records.

No expression is matched here. Godog chooses each registration; go/types supplies
its original declaration span. Coverage/direct_calls remain null, never zero.
"""
from __future__ import annotations

import json
import base64
import copy
import hashlib
import time
from contextlib import contextmanager
import math
import posixpath
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..core.gherkin import parse_feature_file
from ..toolkit.pystep_index import CUCUMBER_DIALECT, examples_rows


class GodogRefused(ValueError):
    pass


def _require(value, reason):
    if not value:
        raise GodogRefused("REFUSED: godog: " + reason)


def _context(value):
    from .context import validate_suite_context
    return validate_suite_context(value)


def source_selection(context, source: str):
    """Keep original line identity, Background, tags, and every Examples block."""
    context = _context(context)
    feature = parse_feature_file(context['feature_path'], source)
    scenario = feature.scenario_at(context['scenario_line'])
    _require(scenario is not None and scenario.steps, 'missing or empty selected scenario')
    lines = source.splitlines(keepends=True)
    for other in feature.scenarios:
        if other.line == scenario.line:
            continue
        following = [s.start_line - 1 for s in feature.scenarios if s.start_line > other.start_line]
        end = min([other.end_line, len(lines)] + following)
        for i in range(other.start_line - 1, end):
            lines[i] = '\r\n' if lines[i].endswith('\r\n') else '\n'
    rows = ([line for line, _ in examples_rows(feature, scenario,
                                              dialect=CUCUMBER_DIALECT)]
            if scenario.examples_lines else [scenario.line])
    _require(rows, 'Outline contains no Examples rows')
    return ''.join(lines), feature, scenario, rows


def command(context):
    context = _context(context)
    argv = ['go', 'test', '-v', '-count=1', '-p=1', '-timeout=600s',
            '-run', '^' + context['test_name'] + '$']
    if context['go_build_tags']:
        argv += ['-tags', ','.join(context['go_build_tags'])]
    return argv + ['./' + context['package_dir']]


def planner_command(context, *, root='/r2t-go/run/work',
                    helper_path='_bench/go/support/harness.go', runtime_diagnostics=False):
    context = _context(context)
    argv = ['go', 'run', './_bench/go/support/interpose.go', '-root', root,
            '-package', context['package_dir'], '-file', context['glue_path'],
            '-test', context['test_name'], '-helper',
            root + '/' + helper_path]
    if context['go_build_tags']:
        argv += ['-tags', ','.join(context['go_build_tags'])]
    if runtime_diagnostics:
        argv.append('-runtime-diagnostics')
    return argv


def support_files():
    root = Path(__file__).with_name('support')
    files = {'_bench/go/support/' + name: (root / name).read_bytes()
             for name in ('interpose.go', 'harness.go', 'mutation_audit.go',
                          'mutation_audit_support.go')}
    # The source applier is immutable input to every worker seed. Campaigns
    # never stage or remove it in a candidate-bearing original workspace.
    files['_bench/go/support/mutate.go'] = (root.parent / 'mutate.go').read_bytes()
    return files


def checked_plan(raw, context, original: bytes, *, helper_template=None):
    """Host reconstruction binds trusted edits to the exact current answer."""
    import hashlib
    context = _context(context)
    try:
        plan = json.loads(raw)
        mapping = plan['map']
        transformed = plan['transformed_source'].encode('utf-8')
        helper = plan['helper_source'].encode('utf-8')
        start, end = mapping['start_byte'], mapping['end_byte']
        _require(type(start) is int and type(end) is int
                 and 0 <= start < end <= len(original), 'invalid Run span')
        _require(mapping['file'] == context['glue_path']
                 and mapping['test_name'] == context['test_name']
                 and mapping['package_name'] == context['package_name']
                 and mapping['resolved_method'] == 'github.com/cucumber/godog.TestSuite.Run',
                 'planner resolved a foreign wrapper')
        _require(hashlib.sha256(original).hexdigest() == mapping['original_sha256'],
                 'planner original bytes differ')
        _require(transformed == original[:start] + mapping['replacement'].encode() + original[end:]
                 and hashlib.sha256(transformed).hexdigest() == mapping['transformed_sha256'],
                 'planner replacement does not reconstruct')
        _require(mapping['line_delta'] == 0 and transformed.count(b'\n') == original.count(b'\n'),
                 'planner moved original source lines')
        expected_helper = (support_files()['_bench/go/support/harness.go']
                           if helper_template is None else helper_template).replace(
            b'package r2tbench', ('package ' + context['package_name']).encode(), 1)
        _require(helper == expected_helper, 'planner changed trusted helper')
        return mapping, {context['glue_path']: transformed,
                         context['package_dir'] + '/zz_r2t_harness_test.go': helper}
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise GodogRefused('REFUSED: malformed native preparation plan') from exc


@dataclass
class NativeWitness:
    context: dict
    records: list[dict]
    bindings: list[dict]
    source_dependencies: list[str]
    native_exit: int


def read_native(raw: bytes, *, context, feature_source: str, source_map: dict,
                exit_code: int) -> NativeWitness:
    """Read one selected item's complete native stream, including all Outline rows.

    This is a precollection witness. Records use r2t.record/1 fields, with null
    uncollected channels. They must never be scored as complete execution.
    """
    return _decode_native(raw, context=context, feature_source=feature_source,
                          source_map=source_map, exit_code=exit_code, runtime=False)


def read_runtime_native(raw: bytes, *, context, feature_source: str, source_map: dict,
                        exit_code: int, hook_failure: bool = False) -> NativeWitness:
    """Same complete witness, allowing Go failure after native Godog success.

    The caller retains the outer exit for RunResult's passed_but_nonzero_exit.
    No records or measurement channels are invented for absent/truncated output.

    `hook_failure` (a coordinator mutation attempt only) also admits Godog's
    complete record of a scenario whose Before hook failed: Godog fails the
    scenario's first step before it matches a definition, so that step has a
    `failed` status carrying the error and no Defined event, and every later
    step is defined and `skipped`. The step is recorded failed, unbound.
    """
    return _decode_native(raw, context=context, feature_source=feature_source,
                          source_map=source_map, exit_code=exit_code, runtime=True,
                          hook_failure=hook_failure)


def _decode_native(raw, *, context, feature_source, source_map, exit_code, runtime,
                   hook_failure=False):
    context = _context(context)
    _require(type(exit_code) is int and exit_code in (0, 1), 'non-test exit status')
    _, feature, scenario, expected_rows = source_selection(context, feature_source)
    _require(raw and raw.endswith(b'\n'), 'empty or truncated native stream')
    try:
        events = [json.loads(line) for line in raw.splitlines()]
        return _read_events(events, context, feature, scenario, expected_rows,
                            source_map, exit_code, runtime=runtime, hook_failure=hook_failure)
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        if isinstance(exc, GodogRefused):
            raise
        raise GodogRefused('REFUSED: malformed native stream: ' + str(exc)) from exc


def _read_events(events, context, feature, scenario, expected_rows, source_map, exit_code, *,
                 runtime=False, hook_failure=False):
    allowed = {'interposed', 'run_started', 'feature', 'pickle', 'defined', 'status', 'summary', 'exit'}
    _require(all(isinstance(e, dict) and e.get('event') in allowed for e in events),
             'unknown native event')
    _require(events[0]['event'] == 'interposed' and events[-1]['event'] == 'exit',
             'missing Run start or terminal exit')
    for kind in ('interposed', 'run_started', 'feature', 'summary', 'exit'):
        _require(sum(e['event'] == kind for e in events) == 1, 'duplicate/missing ' + kind)
    _require(events[-2]['event'] == 'summary', 'events after native summary')
    _require(events[0]['test'] == context['test_name'], 'foreign wrapper')
    end = events[-1]
    _require(end['code'] in (0, 1) and type(end['code']) is int,
             'native run did not execute scenarios')
    _require(end['serial'] == 1 and end['testing_t'] is True
             and end['frozen_tags'] == context['godog_tags'], 'runtime context differs')
    expected_path = posixpath.relpath(context['feature_path'], context['package_dir'])
    _require(end['frozen_paths'] == [expected_path], 'runtime feature path differs')
    decl, steps, bg_lines, pickles, defined, statuses = _agreeing_events(
        events, context, feature, scenario, expected_rows, source_map, hook_failure=hook_failure)
    _require(sorted(line for _, line in pickles.values()) == sorted(expected_rows),
             'missing or repeated Examples/scenario execution')
    expected_keys = {(pid, s['id']) for pid, (p, _) in pickles.items() for s in p['steps']}
    hooked = set(statuses) - set(defined)
    for pid, step_id in hooked:
        # Only the whole shape of a failed Before hook: the first step alone
        # failed without a definition, and nothing after it ran.
        p = pickles[pid][0]
        _require(p['steps'][0]['id'] == step_id
                 and all(statuses.get((pid, s['id']), {}).get('status') == 'skipped'
                         for s in p['steps'][1:]), 'status lacks its Defined event')
    _require(expected_keys and set(statuses) == expected_keys
             and set(defined) == expected_keys - hooked,
             'empty, missing or truncated native step status stream')
    records, bindings = [], []
    for pid, (p, row_line) in pickles.items():
        record_steps = []
        for step, original_step in zip(p['steps'], steps):
            key = pid, step['id']; event, status = defined.get(key), statuses[key]
            result = 'failed' if event is None else _step_result(event, status)
            definition = None
            if event is not None and event['matched']:
                d = _registration(event, decl)
                definition = {'file': d['registration']['file'], 'class': context['package_name'],
                    'method': d.get('handler', {}).get('name', ''), 'kind': 'step',
                    'pattern': event['expression'], 'go': {
                        'registration': d['registration'], 'handler': d.get('handler'),
                        'arguments': event['native_arguments'], 'keyword': event['keyword'],
                        'handler_type': event['handler_type'],
                        'pickle': {'scenario_line': scenario.line, 'example_line': row_line,
                                   'step_line': original_step.line}}}
            bindings.append({'text': step['text'], 'origin': 'background' if original_step.line in bg_lines else 'scenario',
                             'keyword': original_step.resolved, 'definition': definition})
            record_steps.append({'line': original_step.line, 'keyword': original_step.keyword,
                'text': step['text'], 'result': result, 'seconds': status['seconds'],
                'exception': ({'class': 'godog.' + status['status'], 'message': status['error']}
                              if 'error' in status else None)})
        passed = all(s['result'] == 'passed' for s in record_steps)
        records.append({'feature_file': context['feature_path'], 'feature_title': feature.title,
            'scenario_title': p['name'], 'scenario_line': row_line, 'suite': context['test_name'],
            'steps': record_steps, 'coverage': None, 'direct_calls': None,
            'seconds': sum(s['seconds'] for s in record_steps),
            'scenario_result': 'passed' if passed else 'not-passed'})
    native_failure = any(s['result'] in ('failed', 'undefined', 'pending')
                         for r in records for s in r['steps'])
    _require((end['code'] != 0) == native_failure
             and ((exit_code != 0) == native_failure
                  or (runtime and end['code'] == 0 and exit_code == 1)),
             'native statuses and native/Go exits disagree')
    return NativeWitness(context, records, bindings, source_map.get('source_dependencies', []), end['code'])


def _agreeing_events(events, context, feature, scenario, expected_rows, source_map, *,
                     hook_failure=False):
    """Per-event agreement shared by the complete witness and a crash prefix.

    Every feature, pickle, Defined and status event must belong to the
    selected feature, scenario/Examples rows and original steps. Nothing here
    requires completeness; each caller states what else its stream must hold.
    """
    doc = next((e for e in events if e['event'] == 'feature'), None)
    positions = {}
    if doc is not None:
        _require(posixpath.normpath(posixpath.join(context['package_dir'], doc['path']))
                 == context['feature_path'], 'foreign feature document')
        def walk(value):
            if isinstance(value, dict):
                if 'id' in value and 'location' in value:
                    positions[value['id']] = value['location']['line']
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
        walk(doc['document'])
    decl = {}
    for d in source_map['registration_declarations']:
        r = d.get('runtime_registration', d['registration'])
        key = (r['file'].removeprefix('/r2t-go/run/work/'), r['line'])
        _require(key not in decl, 'multiple registrations on one physical line cannot be disambiguated')
        decl[key] = d
    _require(source_map['file'] == context['glue_path'] and
             source_map['test_name'] == context['test_name'], 'foreign physical map')
    steps = ([] if feature.background is None else feature.background.steps) + scenario.steps
    step_lines = [s.line for s in steps]
    bg_lines = {s.line for s in feature.background.steps} if feature.background else set()
    pickles, defined, statuses = {}, {}, {}
    for event in events:
        kind = event['event']
        if kind == 'pickle':
            p = event['pickle']
            _require(p['id'] not in pickles and p['steps'], 'duplicate/empty pickle')
            _require(posixpath.normpath(posixpath.join(context['package_dir'], p['uri']))
                     == context['feature_path'], 'foreign pickle path')
            header = positions[p['astNodeIds'][0]]
            row_line = positions[p['astNodeIds'][-1]]
            _require(header == scenario.line and row_line in expected_rows, 'foreign scenario/Examples row')
            actual = [positions[s['astNodeIds'][0]] for s in p['steps']]
            _require(actual == step_lines, 'native steps differ from original Background/scenario')
            pickles[p['id']] = (p, row_line)
        elif kind == 'defined':
            key = event['pickle_id'], event['step']['id']
            _require(key[0] in pickles and key not in defined and key not in statuses,
                     'foreign/duplicate Defined')
            p = pickles[key[0]][0]
            _require(event['step'] in p['steps'] and event['uri'] == p['uri'], 'foreign Defined step')
            _require(type(event['matched']) is bool, 'invalid matching witness')
            defined[key] = event
        elif kind == 'status':
            key = event['pickle_id'], event['step_id']
            if hook_failure and key not in defined and key not in statuses:
                # Godog reports a failed Before hook on the step it never matched.
                _require(key[0] in pickles and event['status'] == 'failed'
                         and isinstance(event.get('error'), str) and event['error']
                         and any(s['id'] == key[1] for s in pickles[key[0]][0]['steps']),
                         'foreign/duplicate status')
            else:
                _require(key in defined and key not in statuses, 'foreign/duplicate status')
            _require(event['status'] in {'passed', 'failed', 'undefined', 'pending', 'skipped', 'ambiguous'},
                     'unknown native status')
            seconds = event['seconds']
            _require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0,
                     'invalid native duration')
            statuses[key] = event
    return decl, steps, bg_lines, pickles, defined, statuses


def _step_result(event, status):
    """One status's result, which must agree with its Defined registration."""
    result = 'failed' if status['status'] == 'ambiguous' else status['status']
    _require(event['matched'] or result in ('undefined', 'failed'), 'status lacks native registration')
    _require(not (result == 'undefined' and event['matched']), 'undefined step claims a match')
    return result


def _registration(event, decl):
    """The typed original declaration behind a matched Defined event."""
    file = event['registration_file'].removeprefix('/r2t-go/run/work/')
    d = decl.get((file, event['registration_line']))
    _require(d is not None, 'native registration lacks original typed origin')
    return d


def read_crash_prefix(raw, *, context, feature_source: str, source_map: dict,
                      hook_failure: bool = False) -> int:
    """Admit what a crashed test process left in its native stream.

    Only the Go runtime's mutation crash rule reads this, after the process
    exited with a runtime crash trace. The recorder is absent or empty (the
    crash preceded the first event), or it holds whole events, in the order
    the wrapper and Godog write them, that the complete reader's per-event
    rules accept: its own wrapper start, the selected feature, pickles,
    steps, typed registrations and statuses up to the truncation point. It
    never holds the terminal exit event, which only a complete stream read by
    read_runtime_native has. With `hook_failure` (as for read_runtime_native)
    a scenario's first step may carry the failed Before hook's status without
    a Defined event; whatever followed it in that scenario was skipped. A partial or unparsable final record refuses.
    Nothing is completed, projected or recorded; returns the number of
    events admitted.
    """
    context = _context(context)
    if not raw:
        return 0
    _, feature, scenario, expected_rows = source_selection(context, feature_source)
    _require(raw.endswith(b'\n'), 'crash prefix ends inside a native event')
    try:
        events = [json.loads(line) for line in raw.splitlines()]
        _require(all(isinstance(e, dict) for e in events), 'non-object native event')
        kinds = [e.get('event') for e in events]
        header = ['interposed', 'run_started', 'feature']
        _require(kinds[:3] == header[:len(kinds[:3])]
                 and all(kind in ('pickle', 'defined', 'status') for kind in kinds[3:-1])
                 and (len(kinds) <= 3 or kinds[-1] in ('pickle', 'defined', 'status', 'summary')),
                 'crash prefix events are unknown, terminal or out of order')
        _require(events[0]['test'] == context['test_name'], 'foreign wrapper')
        decl, _, _, pickles, defined, statuses = _agreeing_events(
            events, context, feature, scenario, expected_rows, source_map, hook_failure=hook_failure)
        rows = [line for _, line in pickles.values()]
        _require(len(rows) == len(set(rows)), 'repeated Examples/scenario execution')
        hooked = set(statuses) - set(defined)
        for pid, step_id in hooked:
            p = pickles[pid][0]
            _require(p['steps'][0]['id'] == step_id
                     and all(statuses[(pid, s['id'])]['status'] == 'skipped'
                             for s in p['steps'][1:] if (pid, s['id']) in statuses),
                     'status lacks its Defined event')
        if kinds[-1] == 'summary':
            # Godog finished: only the wrapper's exit event may be missing.
            expected_keys = {(pid, s['id']) for pid, (p, _) in pickles.items() for s in p['steps']}
            _require(sorted(rows) == sorted(expected_rows)
                     and set(statuses) == expected_keys and set(defined) == expected_keys - hooked,
                     'summarized crash prefix lacks executed steps')
        for key, event in defined.items():
            if event['matched']:
                _registration(event, decl)
            if key in statuses:
                _step_result(event, statuses[key])
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        if isinstance(exc, GodogRefused):
            raise
        raise GodogRefused('REFUSED: malformed native crash prefix: ' + str(exc)) from exc
    return len(events)


def collection_config(context):
    return {'Paths': [posixpath.relpath(context['feature_path'], context['package_dir'])],
            'Tags': context['godog_tags'], 'Output': '/r2t-go/run/native.jsonl',
            'TestName': context['test_name'], 'go_suite': context}


def native_copy_inventory(receipt, context, originals, feature_source, plan):
    """Expected native copy from an already verified compiler receipt and pin."""
    seed = receipt['attempts'][0]['result']['inventory_before']
    removable = set(receipt['inventory']['removable_paths'])
    expected = {path: digest for path, digest in seed.items() if path not in removable}
    transforms = dict(originals)
    transforms[context['feature_path']] = source_selection(context, feature_source)[0].encode('utf-8')
    _, rewritten = checked_plan(plan, context, originals[context['glue_path']])
    transforms.update(rewritten)
    transforms['_bench/go/context.json'] = json.dumps(collection_config(context)).encode('utf-8')
    expected.update({path: hashlib.sha256(raw).hexdigest() for path, raw in transforms.items()})
    return expected


def capture_native(execution_copy, *, context, feature_source, installed_answers,
                   allowed_paths, empty=False, coordination_inputs=None, evidence_dir=None,
                   control_originals=None):
    """Shared precollection operation; context comes from coordinator authority.

    Bootstrap validates an annotated item before this call. Runtime obtains the
    same closed context and allowed_paths from its immutable witnessed ContextTable.
    installed_answers contains every current answer file; only the primary Run is
    transformed. Bootstrap supplies its separately verified compiler preparation
    set; the native witness remains distinct from that preparation receipt.
    """
    from .closure import empty_scaffold
    from .context import _path
    if control_originals is not None:
        _require(empty and installed_answers is None,
                 'declaration support is confined to an explicit absent-answer control')
        from .controls import capture_control
        return capture_control(execution_copy, context=context, feature_source=feature_source,
            original_answers=control_originals, allowed_paths=allowed_paths, mode='empty',
            coordination_inputs=coordination_inputs, evidence_dir=evidence_dir)
    context = _context(context)
    _require(isinstance(allowed_paths, (tuple, list)) and allowed_paths,
             'native collection requires explicit witnessed answer paths')
    paths = tuple(_path(path, 'answer path') for path in allowed_paths)
    _require(len(paths) == len(set(paths)) and context['glue_path'] in paths,
             'duplicate answer path or missing primary glue')
    if empty:
        _require(len(paths) == 1,
                 'multi-file empty control requires preserved original declarations')
        _require(installed_answers is None, 'empty control requires all answers actually absent')
        original = empty_scaffold(context).encode('utf-8')
        installed = None
    else:
        _require(isinstance(installed_answers, dict) and set(installed_answers) == set(paths)
                 and all(isinstance(raw, bytes) for raw in installed_answers.values()),
                 'native collection requires exact bytes for every witnessed answer file')
        installed = dict(installed_answers)
        original = installed[context['glue_path']]
    initial = support_files()
    if empty:
        initial[context['glue_path']] = original
    return _capture(execution_copy, context=context, feature_source=feature_source,
        installed=installed, paths=paths, original=original, initial=initial,
        coordination_inputs=coordination_inputs, evidence_dir=evidence_dir)


@dataclass
class NativeCapture:
    """Observed invocation facts, possibly partial; never completed measurements."""
    context: dict
    phase: str = 'prepare'
    planner: subprocess.CompletedProcess | None = None
    completed: subprocess.CompletedProcess | None = None
    source_map: dict | None = None
    native: bytes | None = None
    measurement: bytes | None = None
    measurement_owner: bytes | None = None
    measurement_plan: dict | None = None
    mutation_evidence: dict | None = None
    commands: list[dict] = field(default_factory=list)
    retired: bool = False


class NativeCaptureError(RuntimeError):
    """A raw capture failed; retain facts and the typed underlying cause."""
    def __init__(self, capture, cause):
        super().__init__(str(cause))
        self.capture, self.cause = capture, cause


def _capture(execution_copy, **kwargs):
    """Strict admission/control wrapper over the same raw execution lifecycle."""
    try:
        captured = capture_execution(execution_copy, **kwargs)
    except NativeCaptureError as error:
        raise error.cause from None
    if captured.planner.returncode != 0:
        detail = captured.planner.stderr or captured.planner.stdout
        raise GodogRefused('REFUSED: typed native preparation failed for '
                          + captured.context['glue_path'] + ': ' + detail)
    witness = read_native(captured.native, context=captured.context,
        feature_source=kwargs['feature_source'], source_map=captured.source_map,
        exit_code=captured.completed.returncode)
    return {'witness': witness, 'native': captured.native, 'plan': captured.planner.stdout,
            'stdout': captured.completed.stdout, 'stderr': captured.completed.stderr,
            'exit_code': captured.completed.returncode, 'collection_complete': False}


def capture_execution(execution_copy, *, context, feature_source, installed, paths, original,
                      initial, coordination_inputs=None, evidence_dir=None, deadline=None,
                      helper_path='_bench/go/support/harness.go', helper_template=None,
                      measurement=False, control=False, runtime_diagnostics=False, mutation=None):
    """Capture raw facts using the existing trusted preparation/finalization seam.

    Inputs have the same coordinator authority as _capture: exact candidate or
    explicitly prepared control bytes, immutable context and witnessed paths.
    A failed planner returns its facts without launching a test. Other failures
    raise NativeCaptureError with partial observations and the original typed
    cause. Runtime decoding is separate; strict admission uses _capture above.
    """
    from .execution import ExecutionTimeout
    context = _context(context)
    if mutation is not None:
        _require(not measurement and not control, 'mutation capture cannot collect measurements or repair controls')
        _require(isinstance(mutation, dict) and set(mutation) == {
            'descriptor', 'reference_files', 'engine_request', 'engine_sha256'},
            'mutation capture requires complete coordinator reference authority')
    selected, _, _, _ = source_selection(context, feature_source)
    captured = NativeCapture(copy.deepcopy(context))
    evidence = None if evidence_dir is None else Path(evidence_dir)
    if evidence is not None:
        _require(evidence.is_dir(), 'native evidence directory must already exist')
        (evidence / 'context.json').write_text(json.dumps(context, indent=2) + '\n')
        (evidence / 'feature.feature').write_text(feature_source, encoding='utf-8')
        (evidence / 'answer.go').write_bytes(original)
        for path, raw in (installed or {}).items():
            saved = evidence / 'original_answers' / path
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(raw)
    def save():
        captured.commands = copy.deepcopy(execution_copy.command_evidence)
        if mutation is not None:
            captured.mutation_evidence = copy.deepcopy(getattr(execution_copy, 'mutation_evidence', None))
        if evidence is None:
            return
        for completed, stdout, stderr in ((captured.planner, 'plan.json', 'planner.stderr.txt'),
                                          (captured.completed, 'stdout.txt', 'stderr.txt')):
            if completed is not None:
                (evidence / stdout).write_text(completed.stdout, encoding='utf-8')
                (evidence / stderr).write_text(completed.stderr, encoding='utf-8')
        if captured.native is not None:
            (evidence / 'native.jsonl').write_bytes(captured.native)
        for name, raw in (('measurement.json', captured.measurement),
                          ('measurement-owner.pid', captured.measurement_owner)):
            if raw is not None:
                (evidence / name).write_bytes(raw)
        def result(value):
            return (None if value is None else {'argv': value.args, 'returncode': value.returncode,
                                                'stdout': value.stdout, 'stderr': value.stderr})
        row = {'phase': captured.phase, 'planner': result(captured.planner),
               'execution': result(captured.completed), 'commands': captured.commands,
               'native_present': captured.native is not None, 'retired': captured.retired,
               'collection_complete': False}
        if captured.mutation_evidence is not None:
            row['mutation_evidence'] = captured.mutation_evidence
        # A timed-out transport may supply bytes rather than decoded text.
        (evidence / 'capture.json').write_text(json.dumps(row, indent=2,
            default=lambda raw: {'base64': base64.b64encode(raw).decode('ascii')}) + '\n')
    initial = dict(initial)
    if measurement:
        from . import measurement as collector
        initial.update(collector.initial_files(control=control))
        helper_path, helper_template = collector.HELPER, initial[collector.HELPER]
    initial[context['feature_path']] = selected.encode('utf-8')
    options = {} if deadline is None else {'deadline': deadline}
    try:
        execution_copy.prepare(context, installed, initial, allowed_paths=paths,
                               coordination_inputs=coordination_inputs, **options)
        try:
            captured.phase = 'planner'
            argv = (collector.planner_command(context, runtime_diagnostics=runtime_diagnostics) if measurement else
                    planner_command(context, helper_path=helper_path, runtime_diagnostics=runtime_diagnostics))
            captured.planner = execution_copy.run_planner(argv)
            save()
            if captured.planner.returncode != 0:
                return captured
            if measurement:
                captured.source_map, transforms, captured.measurement_plan = collector.checked_plan(
                    captured.planner.stdout, context=context, original=original,
                    expected_inventory=execution_copy._expected, boundary=execution_copy.copy_boundary,
                    helper_template=helper_template)
            else:
                captured.source_map, transforms = checked_plan(captured.planner.stdout, context, original,
                                                               helper_template=helper_template)
            transforms['_bench/go/context.json'] = json.dumps(collection_config(context)).encode('utf-8')
            captured.phase = 'finalize'
            execution_copy.finalize(transforms)
            if mutation is not None:
                from .mutation_copy import apply_mutation
                captured.phase = 'mutation'
                apply_mutation(execution_copy, **mutation, measurement=False)
                save()
            if evidence is not None:
                before = execution_copy.inventory(forward=True)
                (evidence / 'copy_inventory_before.json').write_text(json.dumps(before, indent=2) + '\n')
            captured.phase = 'execution'
            captured.completed = execution_copy.execute(command(context))
            if evidence is not None:
                after = execution_copy.inventory()
                (evidence / 'copy_inventory_after.json').write_text(json.dumps(after, indent=2) + '\n')
            captured.native = execution_copy.read_optional_output('native.jsonl')
            if measurement:
                captured.measurement = execution_copy.read_optional_output('measurement.json')
                captured.measurement_owner = execution_copy.read_optional_output('measurement-owner.pid')
            captured.phase = 'captured'
            return captured
        except ExecutionTimeout:
            if execution_copy.diagnostics_ready:
                command_evidence = execution_copy.command_evidence[-1]
                for path, field_name in (('stdout.log', 'stdout'), ('timeout.log', 'timeout_log')):
                    raw = execution_copy.read_diagnostic_output(path)
                    if raw is not None:
                        command_evidence[field_name] = raw.decode('utf-8', errors='replace')
                if captured.phase == 'execution':
                    captured.native = execution_copy.read_diagnostic_output('native.jsonl')
                    if measurement:
                        captured.measurement = execution_copy.read_diagnostic_output('measurement.json')
                        captured.measurement_owner = execution_copy.read_diagnostic_output('measurement-owner.pid')
            raise
        finally:
            try:
                save()  # Preserve observed bytes before retirement removes outputs.
            finally:
                if not execution_copy.quarantined:
                    execution_copy.retire()
                    captured.retired = True
    except Exception as error:
        raise NativeCaptureError(captured, error) from error
    finally:
        save()


@contextmanager
def _installed_originals(root, source_root, paths, execution_copy, *, deadline=None):
    """Install one exact answer set in the existing worker's host-backed root."""
    targets = {path: root / path for path in paths}
    _require(all(target.resolve().is_relative_to(root) and not target.exists()
                 for target in targets.values()), 'answer set is not absent inside workspace')
    def forward():
        if deadline is not None and time.monotonic() >= deadline:
            from .closure_plan import PreparationInfrastructureError
            raise PreparationInfrastructureError('shared closure preparation deadline expired')
    installed = {}
    for path in paths:
        forward()
        installed[path] = (source_root / path).read_bytes()
    forward()
    written = []
    try:
        for path, target in targets.items():
            forward()
            target.parent.mkdir(parents=True, exist_ok=True)
            forward()
            written.append(target); target.write_bytes(installed[path])
        forward()
        yield installed
    finally:
        if not execution_copy.quarantined:
            for target in written:
                target.unlink()


def index_items(items, *, execution_copy, boundary, source_root, output_dir,
                go, compiler=None, inventory_provider=None):
    """Derive preparation once per compile context, then witness every item.

    The optional compiler callback exposes guarded compiler observations to
    focused tests/operators; a supplied map is never answer-set authority.
    Preparation and failed native evidence survive, but incomplete collections
    never publish final indexes. No controls or retries run here.
    """
    from .coddy import candidate_census, assert_candidate_items
    from .context import validate_context
    from .closure_plan import (compile_context, source_inventory, derive_file_plan,
                               verify_file_plan, PreparationInfrastructureError)
    from .closure import extract_closure, removable_census, gold_sidecar
    from .execution import COPY_ROOT, COMMAND_TIMEOUT
    items = sorted(items, key=lambda item: item['item_id'])
    assert_candidate_items(items, candidate_census(source_root))
    contexts = [validate_context(item, boundary=boundary) for item in items]
    source_root = Path(source_root).resolve(); root = Path(boundary.repo_root).resolve()
    output = Path(output_dir).resolve()
    _require(root != source_root and source_root not in root.parents,
             'registry requires a disposable stripped workspace')
    _require(root != output and source_root != output and root not in output.parents and source_root not in output.parents,
             'registry artifacts must remain outside source/workspace')
    _require(not output.exists(), 'registry output must be a fresh directory')
    _require(not any(boundary.classify(p) == 'removable' for p in execution_copy.original_inventory),
             'registry requires the independently verified stripped seed')
    _require(execution_copy.inventory(original=True) == execution_copy.original_inventory,
             'registry workspace differs before any installation')
    output.mkdir(parents=True)
    def save(path, value):
        path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    def compile_copy(paths, *, context, argv, deadline):
        with _installed_originals(root, source_root, paths, execution_copy, deadline=deadline) as answers:
            execution_copy.prepare(context, answers, {}, allowed_paths=paths, deadline=deadline)
            try:
                before = execution_copy.inventory(forward=True)
                result = execution_copy.run_planner(argv)
                after = execution_copy.inventory()
                return {'returncode': result.returncode, 'stdout': result.stdout,
                        'stderr': result.stderr, 'work_root': COPY_ROOT,
                        'inventory_before': before, 'inventory_after': after,
                        'cleanup_baseline_restored': True, 'timeout': False}
            finally:
                if not execution_copy.quarantined:
                    execution_copy.retire()
    compiler = compiler or compile_copy
    inventory_provider = inventory_provider or source_inventory
    plans = {}
    for context in contexts:
        key = json.dumps(compile_context(context), sort_keys=True)
        if key in plans:
            continue
        case = output / 'preparations' / str(len(plans)); case.mkdir(parents=True)
        save(case / 'context.json', context)
        deadline = time.monotonic() + COMMAND_TIMEOUT
        def recorded_compile(paths, **kwargs):
            record = {'files': list(paths), 'argv': list(kwargs['argv'])}
            try:
                record['result'] = compiler(paths, **kwargs)
                return record['result']
            except BaseException as exc:
                record['error'] = type(exc).__name__ + ': ' + str(exc)
                raise
            finally:
                with (case / 'attempts.jsonl').open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(record) + '\n')
        try:
            inventory = inventory_provider(context, source_root=source_root, boundary=boundary,
                                           go=go, deadline=deadline)
            save(case / 'inventory.json', inventory)
            receipt = derive_file_plan(context, source_root=source_root, boundary=boundary,
                                       inventory=inventory, compiler=recorded_compile, deadline=deadline)
            save(case / 'receipt.json', receipt)
            paths = verify_file_plan(receipt, context=context, source_root=source_root,
                                     boundary=boundary)
            if time.monotonic() >= deadline:
                raise PreparationInfrastructureError('shared closure preparation deadline expired')
            plans[key] = (paths, str((case / 'receipt.json').relative_to(output)), receipt)
        except BaseException as exc:
            save(case / 'failure.json', {'error': type(exc).__name__, 'message': str(exc)})
            raise
    index, closures = {}, []
    for number, (item, context) in enumerate(zip(items, contexts)):
        paths, receipt_path, receipt = plans[json.dumps(compile_context(context), sort_keys=True)]
        case = output / str(number); case.mkdir()
        feature = (source_root / context['feature_path']).read_text(encoding='utf-8')
        try:
            with _installed_originals(root, source_root, paths, execution_copy) as answers:
                captured = capture_native(execution_copy, context=context, feature_source=feature,
                                          installed_answers=answers, allowed_paths=paths, evidence_dir=case)
            expected = native_copy_inventory(receipt, context, answers, feature, captured['plan'])
            for name in ('copy_inventory_before.json', 'copy_inventory_after.json'):
                _require(json.loads((case / name).read_text()) == expected,
                         'native gold copy differs from pinned inputs and trusted transforms')
            closure = extract_closure(captured['witness'], boundary, verified_files=paths)
            save(case / 'closure.json', closure.to_json())
            _require(not closure.problems and captured['witness'].native_exit == 0
                     and all(row['scenario_result'] == 'passed' for row in captured['witness'].records),
                     'blocked gold closure: ' + item['item_id'] + ': ' + repr(closure.problems))
            closures.append(closure)
            index[item['item_id']] = {'native': str(number) + '/native.jsonl',
                'plan': str(number) + '/plan.json', 'exit_code': captured['exit_code'],
                'preparation': receipt_path, 'feature': str(number) + '/feature.feature',
                'answers': {path: str(number) + '/original_answers/' + path for path in paths},
                'copy_before': str(number) + '/copy_inventory_before.json',
                'copy_after': str(number) + '/copy_inventory_after.json'}
        except BaseException as exc:
            save(case / 'failure.json', {'error': type(exc).__name__, 'message': str(exc)})
            raise
    for name, value in [('witnesses.json', index),
                        ('closures.json', [c.to_json() for c in closures]),
                        ('gold-sidecars.json', [gold_sidecar(c.to_json()) for c in closures]),
                        ('go_closure_census.json', removable_census(closures, boundary))]:
        save(output / name, value)
    return index
