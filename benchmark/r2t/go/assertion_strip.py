"""Native-selected Go Then bodies become successful, inert bodies.

The shared Then-only policy is unchanged unless the operator selects the
reviewed Coddy singleton disposition. Native handler spans identify the
actual declarations, including methods registered from another file; Go types
identify imports whose last use disappeared. They become blank imports so
package initialization and every non-Then body keep their original behavior.
Only preserved gold enters this planner. Candidate execution never calls it.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time

from ..toolkit.strip import StripRefused, load_closures, then_definitions
from .context import answer_paths, validate_context
from .execution import COPY_ROOT, COMMAND_TIMEOUT

SCHEMA = 'r2t.go-assertion-strip/1'
HELPER = '_bench/go/support/assertion_strip.go'
REQUEST = '_bench/go/assertion-strip-request.json'


def _require(ok, message):
    if not ok:
        raise StripRefused('REFUSED: Go assertion stripping: ' + message)


def selected_handlers(closure, *, assertion_selection=None):
    """Project native physical handler identities into the universal selector.

    The common definition.file is the registration file and its class is the
    package, so that triple cannot distinguish same-name receiver methods or
    identify a handler declared in another file. No Gherkin is parsed here.
    """
    projected = deepcopy(closure)
    identities = {}
    files = set(closure.get('files') or [])
    for step in projected.get('steps') or []:
        definition = step.get('definition')
        handler = definition.get('go', {}).get('handler') if definition else None
        _require(isinstance(handler, dict) and isinstance(handler.get('file'), str),
                 'missing native handler declaration')
        start, end = handler.get('start_byte'), handler.get('end_byte')
        _require(type(start) is int and type(end) is int and 0 <= start < end,
                 'invalid physical handler span')
        _require(handler.get('kind') in ('function_or_method', 'function_literal')
                 and isinstance(handler.get('name'), str) and handler['name']
                 and isinstance(handler.get('signature'), str) and handler['signature'],
                 'missing native handler kind/name/signature')
        key = (handler['file'], 'go-handler', f'{start}:{end}')
        _require(key not in identities or identities[key] == handler,
                 'one native handler span has conflicting identities')
        identities[key] = handler
        definition.update(file=key[0], **{'class': key[1]}, method=key[2])
        # Registration ownership does not determine handler ownership.
        step['side'] = 'removable' if handler['file'] in files else 'retained'
    if assertion_selection is not None:
        from ..toolkit.assertion_selection import validate_assertion_selection
        return [identities[key] for key in validate_assertion_selection(closure, assertion_selection)]
    return [identities[key] for key in then_definitions(projected)]


def planner_command(context):
    argv = ['go', 'run', '-p=1', './' + HELPER, '-root', COPY_ROOT,
            '-package', context['package_dir'], '-file', context['glue_path'],
            '-request', COPY_ROOT + '/' + REQUEST]
    if context['go_build_tags']:
        argv += ['-tags', ','.join(context['go_build_tags'])]
    return argv


def _handler_request(handler):
    return {key: handler[key] for key in
            ('file', 'start_byte', 'end_byte', 'name', 'kind', 'signature')}


@dataclass(frozen=True)
class PreparedStrip:
    context: dict
    handlers: list[dict]
    files: dict[str, bytes]
    plan: dict
    planner_result: dict | None = None


def checked_plan(raw, *, context, handlers, originals, root=COPY_ROOT):
    """Reconstruct only typed Then body and preserving blank-import edits."""
    try:
        plan = json.loads(raw)
        _require(plan['schema'] == SCHEMA and plan['root'] == root
                 and plan['package_dir'] == context['package_dir']
                 and plan['glue_path'] == context['glue_path']
                 and plan['go_build_tags'] == ','.join(context['go_build_tags'])
                 and plan['handlers'] == [_handler_request(h) for h in handlers],
                 'typed planner context or selected handlers differ')
        _require([row['file'] for row in plan['files']]
                 == sorted({h['file'] for h in handlers}),
                 'typed planner changed handler file ownership')
        files = dict(originals)
        seen = set()
        for row in plan['files']:
            path = row['file']
            _require(path in originals, 'planner edits a non-answer file')
            source = originals[path]
            output, previous = b'', 0
            for edit in row['edits']:
                start, end = edit['start_byte'], edit['end_byte']
                replacement = edit['replacement'].encode('utf-8')
                _require(type(start) is int and type(end) is int
                         and previous <= start < end <= len(source),
                         'overlapping or invalid edit span')
                _require(replacement.count(b'\n') == source[start:end].count(b'\n'),
                         'edit moved original source lines')
                if edit['kind'] == 'then_body':
                    owners = [i for i, h in enumerate(handlers) if h['file'] == path
                              and h['start_byte'] <= start < end <= h['end_byte']]
                    _require(len(owners) == 1 and owners[0] not in seen,
                             'body edit does not belong to one selected handler')
                    seen.add(owners[0])
                    _require(source[start:start+1] == b'{' and source[end-1:end] == b'}'
                             and replacement in (b'{' + b'\n' * replacement.count(b'\n') + b'}',
                                 b'{' + b'\n' * replacement.count(b'\n') + b'return nil}'),
                             'body edit is not a successful inert body')
                else:
                    _require(edit['kind'] == 'blank_import'
                             and replacement.lstrip().startswith((b'_ ', b'import _ ')),
                             'unexpected edit outside a Then body')
                output += source[previous:start] + replacement
                previous = end
            files[path] = output + source[previous:]
        _require(seen == set(range(len(handlers))), 'missing selected Then body edit')
        return PreparedStrip(deepcopy(context), deepcopy(handlers), files, plan)
    except (KeyError, TypeError, AttributeError, UnicodeError, json.JSONDecodeError) as exc:
        raise StripRefused('REFUSED: malformed Go assertion-strip plan') from exc


def prepare_stripped(execution_copy, *, closure, original_answers, allowed_paths,
                     coordination_inputs=None, deadline=None, evidence_dir=None,
                     assertion_selection=None):
    """Read preserved gold in one verified disposable compiler copy.

    Every answer must be absent in the original worker. Gold is added only as a
    trusted copy input. No original worker installation, handler execution, or
    generated-candidate repair occurs here.
    """
    context = validate_context(closure)
    paths = answer_paths(closure)
    _require(not closure.get('problems'), 'blocked reference closure')
    _require(tuple(sorted(allowed_paths)) == paths
             and len(allowed_paths) == len(paths), 'immutable answer paths differ')
    _require(isinstance(original_answers, dict) and set(original_answers) == set(paths)
             and all(isinstance(raw, bytes) for raw in original_answers.values()),
             'requires exact preserved original answer files')
    handlers = selected_handlers(closure, assertion_selection=assertion_selection)
    validate_selected_source(closure, original_answers, assertion_selection)
    inputs = dict(original_answers)
    inputs[HELPER] = Path(__file__).with_name('support').joinpath('assertion_strip.go').read_bytes()
    inputs[REQUEST] = json.dumps({'handlers': [_handler_request(h) for h in handlers]}).encode()
    deadline = time.monotonic() + COMMAND_TIMEOUT if deadline is None else deadline
    evidence = None if evidence_dir is None else Path(evidence_dir)
    if evidence is not None:
        _require(evidence.is_dir(), 'evidence directory must already exist')
        for path, raw in original_answers.items():
            saved = evidence / 'originals' / path
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(raw)
    execution_copy.prepare(context, None, inputs, allowed_paths=paths,
                           coordination_inputs=coordination_inputs, deadline=deadline)
    try:
        result = execution_copy.run_planner(planner_command(context))
        if evidence is not None:
            (evidence / 'plan.json').write_text(result.stdout, encoding='utf-8')
            (evidence / 'planner.stderr.txt').write_text(result.stderr, encoding='utf-8')
        _require(result.returncode == 0, 'typed planner failed: ' + (result.stderr or result.stdout))
        from dataclasses import replace
        return replace(checked_plan(result.stdout, context=context, handlers=handlers,
                            originals=original_answers), planner_result={
            'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
    finally:
        if not execution_copy.quarantined:
            execution_copy.retire()


def validate_selected_source(closure, originals, selection):
    if selection is not None:
        from ..toolkit.assertion_selection import (
            GO_REVIEWED_HANDLERS, GO_REVIEWED_SOURCES, validate_assertion_selection)
        validate_assertion_selection(closure, selection)
        item = closure['item_id']
        for handler, source in zip(GO_REVIEWED_HANDLERS[item], GO_REVIEWED_SOURCES[item]):
            raw = originals.get(handler['file'], b'')
            _require(raw[handler['start_byte']:handler['end_byte']] == source.encode()
                     and raw[:handler['start_byte']].count(b'\n') + 1 == handler['line'],
                     'reviewed handler source/receiver/line differs')


def stripped_solution(closure, prepared, *, assertion_selection=None):
    """Return the ordinary files/metadata payload from completed preparation."""
    context = validate_context(closure)
    handlers = selected_handlers(closure, assertion_selection=assertion_selection)
    _require(isinstance(prepared, PreparedStrip) and prepared.context == context
             and prepared.handlers == handlers and tuple(sorted(prepared.files)) == answer_paths(closure),
             'prepared reference differs from immutable closure')
    identities = [_handler_request(h) for h in handlers]
    result = {'files': [{'file_path': path, 'code': prepared.files[path].decode('utf-8')}
                      for path in sorted(prepared.files)],
            'metadata': {'source': 'stripped_gold', 'stripped_gold': True,
                         'item_id': closure['item_id'], 'n_then_definitions': len(handlers),
                         'then_definitions': identities,
                         'definition_identity_sha256': hashlib.sha256(json.dumps(
                             identities, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}}

    if assertion_selection is not None:
        result['metadata'] = {'source': 'stripped_gold', 'stripped_gold': True,
            'item_id': closure['item_id'], 'assertion_selection': assertion_selection}
    return result


def make_strip_adapter(gold_root, closures_path, *, harness, control_policy=None,
                       go_control_plans_root=None):
    """Use the runtime's immutable context and trusted preserved gold directory."""
    from ..bench.adapters import Adapter
    from .context import ContextRefused
    closures = deepcopy(load_closures(closures_path))
    root = Path(gold_root).resolve()
    _require(root == Path(harness.manifest.gold_root).resolve(),
             'gold directory differs from the harness manifest')
    for closure in closures.values():
        harness.check_context(closure)

    def run(task):
        item_id = task.get('item_id')
        try:
            _require(item_id in closures, 'no reference closure for ' + str(item_id))
            closure = closures[item_id]
            harness.check_context(task)
            harness.check_context(closure)
            paths = harness.contexts.files_for(closure['feature_file'], closure['scenario_line'])
            originals = {}
            for path in paths:
                target = root / path
                _require(target.resolve().is_relative_to(root), 'gold file escapes trusted root')
                originals[path] = target.read_bytes()
            from ..toolkit.assertion_selection import reviewed_assertion_selection
            selection = reviewed_assertion_selection(closure, policy=control_policy)
            prepared = prepare_stripped(harness.copy, closure=closure,
                                        original_answers=originals, allowed_paths=paths,
                                        coordination_inputs=harness.coordination_inputs(),
                                        assertion_selection=selection)
            if go_control_plans_root is not None:
                from .control_adapter import save_control_plan
                save_control_plan(go_control_plans_root, role='stripped_gold',
                    closure=closure, originals=originals, prepared=prepared,
                    assertion_selection=selection)
            return stripped_solution(closure, prepared, assertion_selection=selection)
        except (StripRefused, ContextRefused, OSError) as exc:
            return {'files': [], 'metadata': {'adapter_error': str(exc), 'strip_refusal': True,
                    'source': 'stripped_gold', 'stripped_gold': True, 'item_id': item_id}}

    return Adapter('stripped-gold', run, {'gold': str(root), 'closures': str(closures_path),
        'control_policy': control_policy, 'adapter_version': 1})
