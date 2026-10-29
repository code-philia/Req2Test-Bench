"""Approved declaration-only Go sanity controls; never candidate repair.

The coordinator supplies preserved original files. Planning and execution use
separate disposable copies under one deadline, while the original worker must
have every answer absent. The parent-process witness proves that no inert helper
was invoked; it makes no claim about child API calls or coverage.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import time

from .context import answer_paths, validate_context
from .execution import COPY_ROOT, COMMAND_TIMEOUT
from .registry import GodogRefused, _context, _require

CHECKS = {'original_function_bodies_absent', 'original_variable_initializers_absent',
          'only_reviewed_empty_string_constant', 'helper_bodies_exact_witness_plus_zero_returns'}


def registrations(closure):
    """Use native Defined patterns and reflected handler types, never rematching."""
    found = {}
    for step in closure['steps']:
        definition = step['definition']
        _require(definition is not None, 'noop control requires matched original steps')
        metadata = definition['go']
        keyword = metadata['keyword']
        _require(type(keyword) is int and keyword in (0, 1, 2, 3),
                 'unknown native registration keyword')
        signature = metadata.get('handler_type')
        match = re.fullmatch(r'func\(([^()]*)\) error', signature or '')
        _require(match is not None, 'unsupported native noop handler signature')
        types = [] if not match[1] else match[1].split(', ')
        args = metadata['arguments'] or []
        _require(len(types) == len(args), 'native noop argument count differs')
        parameters = []
        for typ, arg in zip(types, args):
            if typ in ('string', 'int', 'float64'):
                _require(isinstance(arg, str), 'native scalar capture is not string')
            elif typ == '*messages.PickleTable':
                _require(isinstance(arg, dict) and set(arg) == {'dataTable'},
                         'native table capture differs')
                typ = '*r2tControlGodog.Table'
            elif typ == '*messages.PickleDocString':
                _require(isinstance(arg, dict) and set(arg) == {'docString'},
                         'native docstring capture differs')
                typ = '*r2tControlGodog.DocString'
            else:
                raise GodogRefused('REFUSED: unsupported native noop parameter ' + typ)
            parameters.append('_ ' + typ)
        key = (keyword, definition['pattern'])
        _require(key not in found or found[key] == parameters,
                 'Outline changes one native registration signature')
        found[key] = parameters
    _require(found, 'empty noop is not an arity control')
    return [(key, parameters) for key, parameters in found.items()]


def wrapper(context, mode, closure=None):
    _require(mode in ('empty', 'noop'), 'unknown Go sanity control')
    lines = []
    if mode == 'noop':
        _require(closure is not None and not closure.get('problems'),
                 'noop requires an unblocked witnessed closure')
        _require(validate_context(closure) == context,
                 'noop closure context differs')
        for (keyword, pattern), parameters in registrations(closure):
            method = ('Given', 'When', 'Then', 'Step')[keyword]
            key = json.dumps(str(keyword) + ':' + pattern, ensure_ascii=False)
            lines.append('sc.' + method + '(' + json.dumps(pattern, ensure_ascii=False)
                         + ', func(' + ', '.join(parameters) + ') error {'
                         + 'r2tControlNoopCalls = append(r2tControlNoopCalls, ' + key
                         + '); return nil })')
    return ('package ' + context['package_name'] + '\n'
        'import (r2tControlTesting "testing"; r2tControlGodog "github.com/cucumber/godog")\n'
        'var r2tControlHelperCalls []string\n'
        'var r2tControlNoopCalls []string\n'
        'var r2tControlCheck func() map[string]any\n'
        'func r2tControlWitness(name string) { r2tControlHelperCalls = append(r2tControlHelperCalls, name) }\n'
        'func ' + context['test_name'] + '(t *r2tControlTesting.T) {\n'
        'r2tControlCheck = func() map[string]any { return map[string]any{'
        '"mode":' + json.dumps(mode) + ', "original_helper_calls":append([]string{}, r2tControlHelperCalls...), '
        '"noop_handler_calls":append([]string{}, r2tControlNoopCalls...)}}\n'
        'if len(r2tControlHelperCalls) != 0 { t.Fatal("inert helpers invoked before suite") }\n'
        'suite := r2tControlGodog.TestSuite{Name:"r2t-inert-control", '
        'Options:&r2tControlGodog.Options{TestingT:t, Strict:true}, '
        'ScenarioInitializer:func(sc *r2tControlGodog.ScenarioContext) {\n'
        + '\n'.join(lines) + '\n}}\n'
        'if suite.Run() != 0 { t.Fail() }\n'
        'if len(r2tControlHelperCalls) != 0 { t.Fatal("inert helpers invoked by suite") }\n}\n')


def planner_context(context, paths, control_wrapper, *, root=COPY_ROOT):
    return {'root': root, 'package_dir': context['package_dir'],
            'package_name': context['package_name'], 'files': list(paths),
            'primary': context['glue_path'], 'test_name': context['test_name'],
            'go_build_tags': context['go_build_tags'], 'feature_path': context['feature_path'],
            'godog_tags': context['godog_tags'], 'wrapper': control_wrapper}


@dataclass
class PreparedControl:
    context: dict
    mode: str
    files: dict[str, bytes]
    plan: dict
    planner_result: dict | None = None


def checked_plan(raw, context, originals, mode, closure=None, *, root=COPY_ROOT):
    """Bind trusted planner output to exact original files and selected control."""
    paths = tuple(sorted(originals))
    expected = planner_context(context, paths, wrapper(context, mode, closure), root=root)
    try:
        plan = json.loads(raw)
        _require(plan['context'] == expected, 'control planner changed context or wrapper')
        _require(plan['checks'] == dict.fromkeys(CHECKS, True), 'incomplete control declaration audit')
        _require([row['path'] for row in plan['files']] == list(paths),
                 'control planner changed answer paths')
        files = {}
        for row in plan['files']:
            path = row['path']; data = row['source'].encode('utf-8')
            _require(row['original_sha256'] == hashlib.sha256(originals[path]).hexdigest()
                     and row['sha256'] == hashlib.sha256(data).hexdigest(),
                     'control planner source bytes differ')
            for constant in row['required_constants'] or []:
                _require(path == 'internal/agent/bdd_loop_guard_test.go'
                         and constant['name'] == 'bddLoopedSentence'
                         and constant['control_value'] == '""',
                         'unreviewed control constant')
            files[path] = data
        return PreparedControl(json.loads(json.dumps(context)), mode, files, plan)
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise GodogRefused('REFUSED: malformed control declaration plan') from error


def prepare_control(execution_copy, *, context, original_answers, allowed_paths,
                    mode, closure=None, coordination_inputs=None, deadline=None,
                    evidence_dir=None):
    """Read preserved originals in a disposable copy; emit no original helper logic."""
    context = _context(context)
    paths = answer_paths({'item_id': 'coddy-agent/' + context['feature_path'] + ':'
                          + str(context['scenario_line']), 'go_suite': context,
                          'feature_file': context['feature_path'],
                          'scenario_line': context['scenario_line'], 'files': list(allowed_paths)})
    _require(isinstance(original_answers, dict) and set(original_answers) == set(paths)
             and all(isinstance(raw, bytes) for raw in original_answers.values()),
             'control preparation requires exact preserved original answer files')
    if closure is not None:
        _require(answer_paths(closure) == paths, 'control closure file set differs')
    generated = wrapper(context, mode, closure)
    trusted = planner_context(context, paths, generated)
    inputs = dict(original_answers)
    inputs['_bench/go/support/controls.go'] = Path(__file__).with_name('support').joinpath('controls.go').read_bytes()
    inputs['_bench/go/control-context.json'] = json.dumps(trusted).encode('utf-8')
    deadline = time.monotonic() + COMMAND_TIMEOUT if deadline is None else deadline
    evidence = None if evidence_dir is None else Path(evidence_dir)
    if evidence is not None:
        _require(evidence.is_dir(), 'control evidence directory must already exist')
        for path, raw in original_answers.items():
            saved = evidence / 'control_originals' / path
            saved.parent.mkdir(parents=True, exist_ok=True); saved.write_bytes(raw)
    execution_copy.prepare(context, None, inputs, allowed_paths=paths,
                           coordination_inputs=coordination_inputs, deadline=deadline)
    try:
        if evidence is not None:
            before = execution_copy.inventory(forward=True)
            (evidence / 'control_inventory_before.json').write_text(json.dumps(before, indent=2) + '\n')
        result = execution_copy.run_planner(['go', 'run', '-p=1',
            './_bench/go/support/controls.go', '-context', './_bench/go/control-context.json'])
        if evidence is not None:
            after = execution_copy.inventory(forward=True)
            (evidence / 'control_inventory_after.json').write_text(json.dumps(after, indent=2) + '\n')
            (evidence / 'control-plan.json').write_text(result.stdout, encoding='utf-8')
            (evidence / 'control-planner.stderr.txt').write_text(result.stderr, encoding='utf-8')
        _require(result.returncode == 0, 'control declaration preparation failed: '
                 + (result.stderr or result.stdout))
        prepared = checked_plan(result.stdout, context, original_answers, mode, closure)
        prepared.planner_result = {'returncode': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr}
        return prepared
    finally:
        if not execution_copy.quarantined:
            execution_copy.retire()


def helper_source():
    """The existing native recorder plus the explicit parent control witness."""
    from .registry import support_files
    source = support_files()['_bench/go/support/harness.go']
    old = b'"testing_t": opts.TestingT == t'
    _require(source.count(old) == 1, 'native recorder control extension point changed')
    return source.replace(old, old + b', "control_witness": r2tControlCheck()')


def verify_witness(captured, mode, closure=None):
    """Require native undefined/noop behavior and empty parent helper calls."""
    report = json.loads(captured['native'].splitlines()[-1]).get('control_witness')
    _require(isinstance(report, dict) and set(report) == {
        'mode', 'original_helper_calls', 'noop_handler_calls'} and report['mode'] == mode
        and report['original_helper_calls'] == [], 'missing or nonempty parent control witness')
    witness = captured['witness']
    statuses = [step['result'] for record in witness.records for step in record['steps']]
    _require(statuses and all(status == ('undefined' if mode == 'empty' else 'passed')
                             for status in statuses), 'unexpected native control statuses')
    _require(all((binding['definition'] is not None) == (mode == 'noop')
                 for binding in witness.bindings), 'native control registrations differ')
    calls = report['noop_handler_calls']
    _require(isinstance(calls, list) and all(isinstance(call, str) for call in calls),
             'invalid noop invocation witness')
    expected = Counter()
    if mode == 'noop':
        for step in closure['steps']:
            definition = step['definition']
            expected[str(definition['go']['keyword']) + ':' + definition['pattern']] += 1
    _require(Counter(calls) == expected, 'noop handler invocation counts differ from original bindings')
    captured['control_witness'] = report
    return captured


def capture_control(execution_copy, *, context, feature_source, original_answers,
                    allowed_paths, mode, closure=None, coordination_inputs=None,
                    evidence_dir=None):
    """Explicit coordinator control route; candidate capture cannot request repairs."""
    from .registry import source_selection
    source_selection(context, feature_source)
    deadline = time.monotonic() + COMMAND_TIMEOUT
    prepared = prepare_control(execution_copy, context=context, original_answers=original_answers,
        allowed_paths=allowed_paths, mode=mode, closure=closure,
        coordination_inputs=coordination_inputs, deadline=deadline, evidence_dir=evidence_dir)
    return capture_prepared_control(execution_copy, prepared=prepared,
        feature_source=feature_source, closure=closure, deadline=deadline,
        coordination_inputs=coordination_inputs, evidence_dir=evidence_dir)


def capture_prepared_control(execution_copy, *, prepared, feature_source, deadline,
                             closure=None, coordination_inputs=None, evidence_dir=None):
    """Finish a coordinator preparation without refreshing its shared deadline."""
    from .registry import _capture, support_files
    _require(isinstance(prepared, PreparedControl), 'missing typed control preparation')
    context = _context(prepared.context)
    _require(prepared.mode in ('empty', 'noop') and isinstance(prepared.files, dict)
             and context['glue_path'] in prepared.files
             and all(isinstance(raw, bytes) for raw in prepared.files.values()),
             'invalid prepared control mode or files')
    _require(closure is not None or prepared.mode == 'empty',
             'noop capture requires its witnessed closure')
    if closure is not None:
        _require(validate_context(closure) == context
                 and answer_paths(closure) == tuple(sorted(prepared.files)),
                 'prepared control differs from its witnessed closure')
    _require(deadline is not None, 'prepared control requires its original deadline')
    supports = support_files()
    helper = helper_source()
    helper_path = '_bench/go/support/control_harness.go'
    supports[helper_path] = helper
    captured = _capture(execution_copy, context=prepared.context, feature_source=feature_source,
        installed=None, paths=tuple(sorted(prepared.files)), original=prepared.files[context['glue_path']],
        initial={**supports, **prepared.files}, coordination_inputs=coordination_inputs,
        evidence_dir=evidence_dir, deadline=deadline, helper_path=helper_path, helper_template=helper)
    captured['control_preparation'] = prepared.plan
    return verify_witness(captured, prepared.mode, closure)
