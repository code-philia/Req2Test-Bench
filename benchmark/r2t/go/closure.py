"""File-granular Go gold closures from native registry witnesses."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import json

from ..core.boundary import PRODUCTION, REMOVABLE, RETAINED
from ..toolkit.closure import ItemClosure, StepBinding
from .registry import GodogRefused, NativeWitness, _context, _require


@dataclass
class GoItemClosure(ItemClosure):
    go_suite: dict = field(default_factory=dict)

    def to_json(self):
        doc = super().to_json()
        doc['go_suite'] = json.loads(json.dumps(self.go_suite))
        # Keep the existing binding list, including every expanded Examples row.
        for raw, binding in zip(doc['steps'], self.steps):
            if binding.definition is not None:
                raw['definition']['go'] = binding.definition['go']
        return doc


def extract_closure(witness: NativeWitness, boundary, *, verified_files) -> GoItemClosure:
    context = _context(witness.context)
    glue = context['glue_path']
    _require(boundary.project == 'coddy-agent' and boundary.classify(glue) == REMOVABLE,
             'closure original glue is not removable')
    from .context import _answer_paths
    files = _answer_paths({'files': list(verified_files)}, context,
                          boundary=boundary, project='coddy-agent')
    out = GoItemClosure(item_id=f"coddy-agent/{context['feature_path']}:{context['scenario_line']}",
        feature_file=context['feature_path'], scenario_line=context['scenario_line'],
        go_suite=context, files=list(files))
    retained, production, problems = set(), set(), set()
    def dependency(path):
        side = boundary.classify(path)
        if side == REMOVABLE and path not in files:
            problems.add('removable dependency outside verified preparation: ' + path)
        elif side == RETAINED:
            retained.add(path)
        elif side == PRODUCTION:
            production.add(path)
    for raw in witness.bindings:
        d = raw['definition'];side = None if d is None else boundary.classify(d['file'])
        out.steps.append(StepBinding(raw['text'], raw['origin'], raw['keyword'], d, side))
        if d is None:
            problems.add('native step has no matching registration: ' + raw['text'])
            continue
        dependency(d['file'])
        handler = d['go']['handler']
        if not handler:
            problems.add('native handler has no resolved declaration: ' + raw['text'])
        else:
            dependency(handler['file'])
    for path in witness.source_dependencies:
        dependency(path)
    out.retained_files, out.production_deps = sorted(retained), sorted(production)
    if out.answered_entirely_by_retained:
        problems.add('no removable native step registration')
    out.problems = sorted(problems)
    return out


def removable_census(closures, boundary):
    counts = Counter(path for closure in closures for path in closure.files)
    exact = [path for path, _ in boundary.removable]
    _require(len(exact) == len(set(exact)) and all(
        p.startswith(('cmd/', 'internal/', 'external/')) and p.endswith('_test.go')
        and not any(c in p for c in '*?[') and not p.endswith('/') for p in exact),
        'Go boundary requires exact original removable files')
    _require(not set(counts) - set(exact), 'closure escaped removable census')
    return {path: counts[path] for path in sorted(exact)}


def empty_scaffold(context):
    """Actual empty initializer; selection still reaches native undefined steps."""
    return _scaffold(_context(context), [])


def _scaffold(context, registrations):
    tags = context['go_build_expression']
    source = ('//go:build ' + tags + '\n\n') if tags else ''
    source += 'package ' + context['package_name'] + '\n\n'
    source += 'import ("testing"; "github.com/cucumber/godog")\n\n'
    source += 'func ' + context['test_name'] + '(t *testing.T) {\n'
    source += 'suite := godog.TestSuite{Name: "r2t-scaffold", Options: &godog.Options{TestingT:t, Strict:true}, ScenarioInitializer: func(sc *godog.ScenarioContext) {\n'
    source += '\n'.join(registrations)
    source += '\n}}\nif suite.Run() != 0 {t.Fatal("godog scenario did not pass")}\n}\n'
    return source


def stub_solution(item: dict, closure: dict | None, *, prepared_control=None) -> dict:
    """Typed no-op control; declaration preparation is explicit and coordinator-owned."""
    from .context import answer_paths, compare_context
    from .controls import PreparedControl, registrations
    _require(closure is not None, 'stub requires its witnessed gold closure')
    context = compare_context(item, closure)
    _require(not closure.get('problems'), 'stub refuses a blocked gold closure')
    paths = answer_paths(closure)
    if prepared_control is not None:
        _require(isinstance(prepared_control, PreparedControl)
                 and prepared_control.mode == 'noop' and prepared_control.context == context
                 and set(prepared_control.files) == set(paths),
                 'stub declaration preparation differs from its witnessed closure')
        files = prepared_control.files
    else:
        _require(paths == (context['glue_path'],),
                 'multi-file stub requires prepared control declarations')
        lines = []
        for (keyword, pattern), parameters in registrations(closure):
            method = ('Given', 'When', 'Then', 'Step')[keyword]
            parameters = [parameter.replace('r2tControlGodog.', 'godog.')
                          for parameter in parameters]
            lines.append('sc.' + method + '(' + json.dumps(pattern, ensure_ascii=False)
                         + ', func(' + ', '.join(parameters) + ') error { return nil })')
        files = {context['glue_path']: _scaffold(context, lines).encode('utf-8')}
    return {'files': [{'file_path': path, 'code': files[path].decode('utf-8')}
                      for path in sorted(files)],
            'metadata': {'control': 'syntax-only-arity-correct-stub'}}


def gold_sidecar(closure):
    """Existing gold sidecar fields plus this stack's closed suite carrier."""
    from ..toolkit.closure_py import gold_sidecar as common_sidecar
    from .context import validate_context
    context = validate_context(closure)
    return dict(common_sidecar(closure), go_suite=context)


def recompute(items, witnesses, *, boundary, repo_root, artifacts, source_root):
    """The S3 gate: reconstruct saved native closures without another run."""
    from .coddy import candidate_census, assert_candidate_items
    assert_candidate_items(items, candidate_census(source_root))
    from .closure_plan import verify_file_plan
    from pathlib import Path
    from .context import validate_context
    from .registry import checked_plan, read_native, native_copy_inventory
    root = Path(source_root).resolve(); artifacts = Path(artifacts).resolve()
    def artifact(path):
        candidate = (artifacts / path).resolve()
        if not candidate.is_relative_to(artifacts):
            raise GodogRefused('REFUSED: witness path escapes its artifact directory')
        return candidate.read_bytes()
    contexts = {}
    for item in items:
        if item.get('project') != 'coddy-agent' or item.get('task') != 'criterion_to_test':
            raise GodogRefused('REFUSED: Go S3 requires the exact S2 Go criterion set')
        context = validate_context(item, boundary=boundary)
        if item['item_id'] in contexts:
            raise GodogRefused('REFUSED: duplicate S2 item')
        contexts[item['item_id']] = context
    if not contexts or set(contexts) != set(witnesses):
        raise GodogRefused('REFUSED: native witnesses differ from the full supplied S2 item set')
    closures = []
    for item_id, context in sorted(contexts.items()):
        witness = witnesses[item_id]
        receipt = json.loads(artifact(witness['preparation']))
        files = verify_file_plan(receipt, context=context, source_root=root, boundary=boundary)
        if set(witness['answers']) != set(files):
            raise GodogRefused('REFUSED: saved original answers differ from verified preparation')
        originals = {path: (root / path).read_bytes() for path in files}
        if any(artifact(witness['answers'][path]) != raw for path, raw in originals.items()):
            raise GodogRefused('REFUSED: saved answer differs from clean pinned original')
        feature = (root / context['feature_path']).read_text(encoding='utf-8')
        if artifact(witness['feature']) != feature.encode('utf-8'):
            raise GodogRefused('REFUSED: saved feature differs from clean pinned original')
        plan = artifact(witness['plan'])
        mapping, _ = checked_plan(plan, context, originals[context['glue_path']])
        expected = native_copy_inventory(receipt, context, originals, feature, plan)
        if any(json.loads(artifact(witness[key])) != expected for key in ('copy_before', 'copy_after')):
            raise GodogRefused('REFUSED: native copy differs from pinned originals and trusted transforms')
        native = read_native(artifact(witness['native']), context=context,
            feature_source=feature,
            source_map=mapping, exit_code=witness['exit_code'])
        closure = extract_closure(native, boundary, verified_files=files)
        if (closure.problems or native.native_exit != 0
                or not all(row['scenario_result'] == 'passed' for row in native.records)):
            raise GodogRefused('REFUSED: blocked gold closure ' + item_id + ': ' + repr(closure.problems))
        closures.append(closure)
    return [c.to_json() for c in closures], removable_census(closures, boundary)
