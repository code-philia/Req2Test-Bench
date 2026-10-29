"""Replayable coddy-agent census of exact native step-handler sets.

Selection is finer than closure file sets; uncertainty still uses the latter.
See CODDY_AGENT_V2_EVALUATION_AMENDMENT.md. No source or test code executes.
"""
from __future__ import annotations

import json
import os
from pathlib import PurePosixPath

from . import subsets as S
from ..go.context import ContextRefused, handler_identity, validate_context

SCHEMA = 'r2t.step-definition-census/1'
CONTEXT_FIELDS = ('package_dir', 'package_name', 'glue_path', 'test_name',
                  'suite_line', 'go_build_expression', 'go_build_tags', 'godog_tags')
SELECTION_UNIT = 'step_definition_set'
INFERENCE_UNIT = 'closure_file_set'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _read(path):
    try:
        with open(path, 'rb') as handle:
            raw = handle.read()
        return raw, json.loads(raw)
    except (OSError, ValueError) as exc:
        raise S._refuse(f'cannot read census input {path!r}: {exc}') from exc


def _item_key(item, closure):
    iid = item['item_id']
    try:
        context = validate_context(item, project='coddy-agent')
        if validate_context(closure, project='coddy-agent') != context \
                or sorted(item['files']) != sorted(closure['files']):
            raise ValueError('closure context or answer files differ from released item')
        if closure.get('problems') != []:
            raise ValueError('closure is blocked or lacks its extraction problem list')
        steps = closure.get('steps')
        if not isinstance(steps, list) or not steps:
            raise ValueError('closure has no native step bindings')
        handlers = {}
        for step in steps:
            if step.get('origin') not in ('background', 'scenario') \
                    or step.get('side') not in ('removable', 'retained'):
                raise ValueError('step has no admitted origin or definition side')
            handler = handler_identity(step['definition']['go']['handler'])
            path = PurePosixPath(handler['file'])
            if path.is_absolute() or '..' in path.parts or '\\' in handler['file']:
                raise ValueError('handler does not name original repository-relative source')
            handlers[_canonical(handler)] = handler
        return {'context': {key: context[key] for key in CONTEXT_FIELDS},
                'handlers': [handlers[key] for key in sorted(handlers)]}
    except (ContextRefused, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise S._refuse(f'{iid}: invalid native implementation binding: {exc}') from exc


def census(items_path: str, closures_path: str) -> dict:
    """One lexicographically first released item per context/handler set."""
    items = S.read_items(items_path)
    source_lines = dict(items)
    raw, closures = _read(closures_path)
    if not isinstance(closures, list):
        raise S._refuse('native closures input must be the extraction ledger array')
    by_id = {}
    for closure in closures:
        if not isinstance(closure, dict):
            raise S._refuse('native closure ledger contains a non-object record')
        iid = closure.get('item_id')
        if iid not in source_lines:
            continue
        if iid in by_id:
            raise S._refuse(f'{iid}: duplicate native closure')
        by_id[iid] = closure
    clusters = S._closure_clusters(os.path.dirname(os.path.abspath(items_path)))
    groups, source_identities = {}, set()
    for iid, line in items:
        if iid not in by_id:
            raise S._refuse(f'{iid}: no preserved native closure')
        if iid not in clusters:
            raise S._refuse(f'{iid}: no original closure-file correlation group')
        item = json.loads(line)
        provenance = item.get('provenance') or {}
        source = (provenance.get('repo_url'), provenance.get('commit'))
        if not all(isinstance(value, str) and value for value in source):
            raise S._refuse(f'{iid}: missing original source revision identity')
        source_identities.add(source)
        key = _item_key(item, by_id[iid])
        group = groups.setdefault(_canonical(key), dict(key, members=[]))
        group['members'].append(iid)
    if len(source_identities) != 1:
        raise S._refuse('implementation census spans different original source revisions')
    ordered = []
    for key in sorted(groups):
        group = groups[key]
        group['members'].sort()
        group['representative'] = group['members'][0]
        ordered.append(group)
    chosen = sorted(group['representative'] for group in ordered)
    lines = [source_lines[iid] for iid in chosen]
    represented = len({clusters[iid] for iid in chosen})
    repo, commit = next(iter(source_identities))
    provenance = {
        'schema': SCHEMA, 'algorithm_version': 1, 'reconstructed': False,
        'selection_unit': SELECTION_UNIT, 'inference_unit': INFERENCE_UNIT,
        'representative_rule': 'lexicographically_first_item_id',
        'census': True, 'census_unit': SELECTION_UNIT,
        'n': len(chosen), 'population_n': len(items), 'groups': ordered,
        'source_items': os.path.basename(items_path),
        'source_items_sha256': S.sha256_file(items_path),
        'source_closures': os.path.basename(closures_path),
        'source_closures_sha256': S.sha256_bytes(raw),
        'source_revision': {'repo_url': repo, 'commit': commit},
        'closure_map_sha256': S._closure_map_digest(clusters),
        'correlation_clusters': {'represented': represented,
                                 'total': len({clusters[iid] for iid, _ in items})},
        'inference_valid': True,
        'allow_cluster_siblings': represented < len(chosen),
        'item_id_list_digest': S.id_list_digest(chosen),
        'content_sha256': S.sha256_bytes(''.join(lines).encode('utf-8')),
        'generated_by': 'scripts/sample_subset.py --mode step_definition_census',
    }
    return {'item_ids': chosen, 'lines': lines, 'provenance': provenance,
            'replay_context': {'items': os.path.abspath(items_path),
                               'closures': os.path.abspath(closures_path),
                               'clusters': clusters}}


def replay(subset_path: str, doc: dict) -> dict:
    """Recompute membership, source bindings and inference facts after installation."""
    parent = os.path.dirname(os.path.abspath(subset_path))
    inputs = {}
    for field in ('source_items', 'source_closures'):
        name = doc.get(field)
        if not isinstance(name, str) or not name or name in ('.', '..') \
                or os.path.basename(name) != name:
            raise S._refuse(f'implementation census has invalid {field}')
        inputs[field] = os.path.join(parent, name)
    expected = census(inputs['source_items'], inputs['source_closures'])
    if doc != expected['provenance']:
        raise S._refuse('implementation census provenance differs from replayed native bindings')
    try:
        with open(subset_path, 'rb') as handle:
            actual = handle.read()
    except OSError as exc:
        raise S._refuse(f'cannot read implementation census: {exc}') from exc
    if actual != ''.join(expected['lines']).encode('utf-8'):
        raise S._refuse('implementation census bytes differ from replayed representatives')
    return {key: doc[key] for key in ('inference_valid', 'allow_cluster_siblings',
                                      'selection_unit', 'inference_unit')}


def selftest():
    import copy
    import subprocess
    import sys
    import tempfile
    from pathlib import Path
    from types import SimpleNamespace
    from ..bench.cli import _compare_impl
    from ..toolkit.subset_writer import write_subset

    def check(value, label):
        if not value:
            raise AssertionError(label)
        print('[PASS] ' + label)

    def refused(fn, fragment):
        try:
            fn()
        except S.SubsetRefused as exc:
            check(fragment in str(exc), 'refusal: ' + fragment)
        else:
            raise AssertionError('expected refusal: ' + fragment)

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        pool, ledger = root/'items.jsonl', root/'closures.json'
        context = {'schema': 'r2t.go-suite-context/1',
                   'feature_path': 'features/probe.feature', 'scenario_line': 1,
                   'glue_path': 'internal/probe/bdd_probe_test.go',
                   'package_dir': 'internal/probe', 'package_name': 'probe',
                   'test_name': 'TestProbe', 'suite_line': 90,
                   'go_build_expression': '', 'go_build_tags': [], 'godog_tags': '',
                   'godog_tags_origin': {'kind': 'default', 'line': 90}}
        handlers = [{'file': context['glue_path'], 'line': i,
                     'start_byte': i*10, 'end_byte': i*10+9,
                     'name': 'handler'+str(i), 'kind': 'function_literal',
                     'signature': 'func(string) error'} for i in range(1, 4)]
        items, closures = [], []
        # 1 and 2 use the same functions; 3 differs within the same file;
        # 4 differs only in the suite entrypoint; 5 differs in Background.
        for i, indices in enumerate(([0, 1], [1, 0, 1], [0, 2], [0, 1], [2, 1]), 1):
            c = dict(context, scenario_line=i)
            if i == 4:
                c['test_name'] = 'TestOther'
            iid = f'coddy-agent/features/probe.feature:{i}'
            item = {'item_id': iid, 'project': 'coddy-agent', 'language': 'go',
                    'framework': 'godog', 'task': 'criterion_to_test', 'go_suite': c,
                    'files': [context['glue_path']],
                    'provenance': {'repo_url': 'https://example.org/coddy-agent',
                                   'commit': 'a'*40, 'file_path': c['feature_path'], 'line': i}}
            items.append(item)
            steps = [{'origin': 'background' if j == 0 else 'scenario',
                      'side': 'removable', 'text': f'argument {i}',
                      'definition': {'go': {'handler': handlers[index],
                                             'registration': {'line': i*100+j},
                                             'arguments': [i]}}}
                     for j, index in enumerate(indices)]
            closures.append({'item_id': iid, 'feature_file': c['feature_path'],
                             'scenario_line': i, 'go_suite': c, 'files': item['files'],
                             'problems': [], 'steps': steps})
        # A distinct Background implementation, without changing the scenario handler.
        closures[4]['steps'][0]['definition']['go']['handler'] = dict(handlers[0], name='otherBackground', start_byte=100, end_byte=109)
        pool.write_text(''.join(json.dumps(row)+'\n' for row in items))
        ledger.write_text(json.dumps(closures))
        (root/'closure_clusters.json').write_text(json.dumps({i['item_id']: 'shared-file' for i in items}))
        result = census(str(pool), str(ledger))
        check(result['item_ids'] == [items[i]['item_id'] for i in (0, 2, 3, 4)],
              'same handler sets merge despite values/order/repetition/registration sites')
        check(result['provenance']['correlation_clusters']['represented'] == 1
              and result['provenance']['n'] == 4,
              'distinct implementations do not become independent file clusters')
        check(census(str(pool), str(ledger)) == result, 'census rederives deterministically')
        target = root/'installed'/'eval_step_definition_census.jsonl'
        write_subset(result, str(target))
        identity = S.identify_for_inference(str(target))
        check(identity['selection_unit'] == SELECTION_UNIT
              and identity['inference_unit'] == INFERENCE_UNIT
              and identity['allow_cluster_siblings'], 'installed census replays native bindings')
        check(S.verify_release_subsets(str(target.parent)) == [], 'release gate accepts replayable census')
        runs = []
        for name in ('a', 'b'):
            run = root/(name+'.jsonl')
            run.write_text(''.join(json.dumps({'item_id': iid, 'outcome': 'passed',
                                               'n_files': 1, 'condition': 'c2',
                                               'comparison_class': 'fixed_model_scaffold'})+'\n'
                                   for iid in result['item_ids']))
            runs.append(str(run))
        try:
            _compare_impl(SimpleNamespace(run=runs, items=str(target),
                                          gold_dir=str(target.parent), metric='pass'))
        except SystemExit as exc:
            check('20' in str(exc) and 'cluster' in str(exc)
                  and 'descriptive-only' not in str(exc),
                  'compare accepts census identity but applies the original file-cluster floor')
        else:
            raise AssertionError('one original file cluster cannot support inference')
        cli_out = root/'cli'/'eval_step_definition_census.jsonl'
        command = [sys.executable, str(Path(__file__).resolve().parents[2]/'scripts/sample_subset.py'),
                   '--mode', 'step_definition_census', '--items', str(pool),
                   '--closures', str(ledger), '--out', str(cli_out)]
        proc = subprocess.run(command, capture_output=True, text=True)
        check(proc.returncode == 0 and cli_out.read_bytes() == target.read_bytes(),
              'CLI selects and ships the replayable native census')
        proc = subprocess.run(command+['--seed', '1'], capture_output=True, text=True)
        check(proc.returncode == 2 and 'does not use --seed' in proc.stderr,
              'census CLI refuses a random-draw knob it cannot honor')
        sidecar = target.with_suffix('.provenance.json')
        doc = json.loads(sidecar.read_text())
        doc['groups'][0]['representative'] = 'invented'
        sidecar.write_text(json.dumps(doc))
        refused(lambda: S.identify_for_inference(str(target)), 'differs from replayed')
        sidecar.write_text(json.dumps(result['provenance']))
        # Every selected Outline row contributes bindings; union does not pick only row one.
        modified = copy.deepcopy(closures)
        modified[1]['steps'].append(copy.deepcopy(closures[2]['steps'][1]))
        ledger.write_text(json.dumps(modified))
        check(census(str(pool), str(ledger))['provenance']['n'] == 5,
              'an additional Outline handler changes implementation membership')
        for mutation, fragment in ((lambda x: x.pop(0), 'no preserved native closure'),
                                   (lambda x: x.append(x[0]), 'duplicate native closure'),
                                   (lambda x: x[0]['steps'][0]['definition']['go'].pop('handler'), 'invalid native implementation binding'),
                                   (lambda x: x[0]['problems'].append('unmatched'), 'closure is blocked'),
                                   (lambda x: x[0]['go_suite'].update(test_name='TestWrong'), 'context or answer files differ')):
            changed = copy.deepcopy(closures)
            mutation(changed)
            ledger.write_text(json.dumps(changed))
            refused(lambda: census(str(pool), str(ledger)), fragment)
    print('step-definition census: all checks passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(selftest())
