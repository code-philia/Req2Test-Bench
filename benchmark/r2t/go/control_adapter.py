"""Coordinator-owned empty/noop requests; generated JSON never grants control access.

Shared wiring must dispatch only these actual adapter instances to run_control;
all other adapters, including replay, use candidate run_solution. The future
GodogHarness.run_control seam receives feature/scenario and keyword arguments
mode, closure, prepared, deadline plus ordinary run options. It must consume the
first preparation under that unchanged deadline, use fresh 600-second budgets
for later repeats, preserve the parent witness, and retain the normal runtime
capability gate. This module neither runs native tests nor supplies measurements.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import time

from ..bench.fixtures import Adapter
from ..toolkit.strip import load_closures
from .closure import stub_solution
from .context import validate_context
from .controls import PreparedControl, prepare_control
from .execution import COMMAND_TIMEOUT, ExecutionRefused
from .registry import _require


@dataclass
class _Invocation:
    closure: dict
    prepared: PreparedControl | None
    deadline: float | None
    files: tuple[tuple[str, str], ...]


class GoControlAdapter(Adapter):
    """One worker's trusted fixture; no control authorization travels in files."""

    def __init__(self, *, harness, closures_path, mode, go_control_plans_root=None):
        _require(mode in ('empty', 'noop'), 'unknown coordinator Go control')
        self._harness, self._mode = harness, mode
        self._closures = deepcopy(load_closures(closures_path))
        for closure in self._closures.values():
            harness.check_context(closure)
        self._gold = Path(harness.manifest.gold_root).resolve()
        self._pending = None
        self._plans_root = go_control_plans_root
        super().__init__('empty' if mode == 'empty' else 'stub', self._produce,
                         {'closures': str(closures_path)})

    def _produce(self, task):
        self._pending = None
        self._harness.check_context(task)
        _require(task.get('item_id') in self._closures, 'missing Go control closure')
        closure = deepcopy(self._closures[task['item_id']])
        self._harness.check_context(closure)
        context = validate_context(closure)
        prepared = deadline = None
        if self._mode == 'empty':
            produced = {'files': [], 'metadata': {}}
        else:
            deadline = time.monotonic() + COMMAND_TIMEOUT
            _require(self._gold == Path(self._harness.manifest.gold_root).resolve(),
                     'Go control gold root changed after construction')
            paths = self._harness.contexts.files_for(
                context['feature_path'], context['scenario_line'])
            originals = {}
            for path in paths:
                target = self._gold / path
                _require(target.resolve().is_relative_to(self._gold) and target.is_file(),
                         'control original is absent or escapes preserved gold')
                originals[path] = target.read_bytes()
            prepared = prepare_control(self._harness.copy, context=context,
                original_answers=originals, allowed_paths=paths, mode='noop',
                closure=closure, deadline=deadline,
                coordination_inputs=self._harness.coordination_inputs())
            if self._plans_root is not None:
                save_control_plan(self._plans_root, role='stub', closure=closure,
                                  originals=originals, prepared=prepared)
            produced = stub_solution(task, closure, prepared_control=prepared)
        self._pending = _Invocation(closure, deepcopy(prepared), deadline,
            tuple((row['file_path'], row['code']) for row in produced['files']))
        return produced

    def run_control(self, harness, feature, scenario, solution, **run_options):
        """Consume only this adapter's exact output at the final execution call.

        No call falls back to candidate execution. The harness owns native
        execution and its result contract; this adapter grants no API/coverage
        claim. Failed or consumed invocations cannot authorize another call.
        """
        pending, self._pending = self._pending, None
        _require(harness is self._harness and pending is not None,
                 'Go control invocation is missing, consumed, or belongs to another harness')
        harness.check_context(pending.closure)
        context = validate_context(pending.closure)
        expected_feature = Path(harness.root) / context['feature_path']
        _require(Path(feature.path).resolve() == expected_feature.resolve()
                 and scenario.line == context['scenario_line'],
                 'Go control execution differs from its selected feature/header')
        _require(not solution.services_fragment and
                 tuple((f.file_path, f.code) for f in solution.files) == pending.files,
                 'Go control execution differs from its prepared solution bytes')
        if pending.deadline is not None and time.monotonic() >= pending.deadline:
            raise ExecutionRefused('REFUSED: Go control preparation deadline expired')
        return harness.run_control(feature, scenario, mode=self._mode,
            closure=pending.closure, prepared=pending.prepared,
            deadline=pending.deadline, **run_options)


def make_empty_adapter(*, harness, closures_path):
    return GoControlAdapter(harness=harness, closures_path=closures_path, mode='empty')


def make_stub_adapter(closures_path, *, harness, go_control_plans_root=None):
    return GoControlAdapter(harness=harness, closures_path=closures_path, mode='noop',
                            go_control_plans_root=go_control_plans_root)


PLAN_SCHEMA = 'r2t.go-control-plan/1'


def plan_member(role, closure):
    """Portable member name; native context validation owns safe relative paths."""
    _require(role in ('stripped_gold', 'stub'), 'unknown saved Go control role')
    context = validate_context(closure)
    return Path(role) / context['feature_path'] / (str(context['scenario_line']) + '.json')


def _plan_binding(role, closure, originals, selection):
    import hashlib
    from .context import answer_paths
    from . import assertion_strip, controls
    _require(not closure.get('problems') and tuple(sorted(originals)) == answer_paths(closure),
             'saved Go control requires exact unblocked original answers')
    context = validate_context(closure)
    if role == 'stripped_gold':
        handlers = assertion_strip.selected_handlers(closure, assertion_selection=selection)
        assertion_strip.validate_selected_source(closure, originals, selection)
        request = {'handlers': [assertion_strip._handler_request(h) for h in handlers]}
        helper = 'assertion_strip.go'
    else:
        _require(role == 'stub' and selection is None, 'invalid saved Go control selection')
        request = controls.planner_context(context, tuple(sorted(originals)),
                                           controls.wrapper(context, 'noop', closure))
        helper = 'controls.go'
    return {'schema': PLAN_SCHEMA, 'role': role, 'closure': deepcopy(closure),
            'original_answers': {p: raw.decode('utf-8') for p, raw in originals.items()},
            'assertion_selection': selection,
            'planner_sha256': hashlib.sha256(Path(__file__).with_name('support').joinpath(helper).read_bytes()).hexdigest(),
            'request': request}


def save_control_plan(root, *, role, closure, originals, prepared, assertion_selection=None):
    """Persist native preparation, outside closed run/tests trees, without restamping."""
    import json
    from . import assertion_strip, controls
    expected_type = assertion_strip.PreparedStrip if role == 'stripped_gold' else controls.PreparedControl
    _require(isinstance(prepared, expected_type) and prepared.planner_result is not None,
             'saved Go control requires live native planner evidence')
    record = _plan_binding(role, closure, originals, assertion_selection)
    record['result'] = prepared.planner_result
    _require(record['result']['returncode'] == 0, 'cannot save failed Go planner')
    path = Path(root) / plan_member(role, closure)
    _require(path.resolve().is_relative_to(Path(root).resolve()), 'Go plan escapes input tree')
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        _require(json.loads(path.read_text(encoding='utf-8')) == record,
                 'existing Go plan differs; use a new collection output')
    else:
        with path.open('x', encoding='utf-8') as handle:
            json.dump(record, handle, sort_keys=True, indent=2)
            handle.write('\n')


def make_replay_adapter(*, role, gold_root, closures_path, go_control_plans_root,
                        control_policy=None):
    """Rederive from admitted native inputs only; no execution transport exists here."""
    import json
    from ..toolkit.assertion_selection import reviewed_assertion_selection
    from ..toolkit.strip import StripRefused
    from .context import answer_paths, compare_context, ContextRefused
    from .registry import GodogRefused
    from . import assertion_strip, controls
    if go_control_plans_root is None:
        raise StripRefused('REFUSED: Coddy controls require go_control_plans_root')
    closures = deepcopy(load_closures(closures_path))
    gold, plans = Path(gold_root).resolve(), Path(go_control_plans_root).resolve()

    def run(task):
        try:
            closure = closures[task['item_id']]
            compare_context(task, closure)
            originals = {}
            for p in answer_paths(closure):
                target = gold / p
                _require(target.resolve().is_relative_to(gold), 'Go original escapes gold')
                originals[p] = target.read_bytes()
            selection = reviewed_assertion_selection(closure, policy=control_policy) if role == 'stripped_gold' else None
            expected = _plan_binding(role, closure, originals, selection)
            path = plans / plan_member(role, closure)
            _require(path.resolve().is_relative_to(plans), 'Go plan escapes admitted tree')
            saved = json.loads(path.read_text(encoding='utf-8'))
            _require(isinstance(saved, dict) and set(saved) == set(expected) | {'result'}
                     and {k: saved[k] for k in expected} == expected,
                     'saved Go planner source/closure/context/request authority differs')
            result = saved['result']
            _require(isinstance(result, dict) and set(result) == {'returncode', 'stdout', 'stderr'}
                     and type(result['returncode']) is int and result['returncode'] == 0
                     and isinstance(result['stdout'], str) and isinstance(result['stderr'], str),
                     'saved Go planner did not succeed')
            if role == 'stripped_gold':
                prepared = assertion_strip.checked_plan(result['stdout'], context=validate_context(closure),
                    handlers=assertion_strip.selected_handlers(closure, assertion_selection=selection), originals=originals)
                return assertion_strip.stripped_solution(closure, prepared, assertion_selection=selection)
            prepared = controls.checked_plan(result['stdout'], validate_context(closure), originals, 'noop', closure)
            return stub_solution(task, closure, prepared_control=prepared)
        except (OSError, KeyError, TypeError, ValueError, GodogRefused, ContextRefused) as exc:
            raise StripRefused('REFUSED: saved Go control replay: ' + str(exc)) from exc

    return Adapter('stripped-gold' if role == 'stripped_gold' else 'stub', run,
                   {'gold': str(gold), 'closures': str(closures_path),
                    'go_control_plans_root': str(plans), 'control_policy': control_policy})
