"""Source-bound primary suite contexts before witnessed answer-file discovery.

The AST helper reads syntax only. A caller-owned native transport runs the
pinned Godog RetrieveFeatures helper; no Python tag matcher or subject wrapper
is used. The result carries no answer files and claims no item admission.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from ..core.gherkin import parse_feature_file
from ..toolkit.extract import extract_project
from ..toolkit.pystep_index import CUCUMBER_DIALECT, examples_rows
from .coddy import (PINNED_COMMIT, FEATURE_EXCLUSIONS, candidate_census,
                    select_candidates, assert_candidate_items)
from .context import FIELDS, validate_suite_context
from .closure_plan import _snapshot, _remaining, PreparationInfrastructureError


class BootstrapRefused(ValueError):
    pass


def _require(value, message):
    if not value:
        raise BootstrapRefused('REFUSED: Go suite bootstrap: ' + message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _helper(name):
    return Path(__file__).with_name('support') / name


def inspect_suites(source_root, *, go, deadline):
    """Parse original suite/options/build syntax at the exact clean source pin."""
    source = _snapshot(source_root)
    files = sorted(path for path in source if Path(path).name.startswith('bdd_')
                   and path.endswith('_test.go'))
    _require(len(files) == 61, 'original removable census differs')
    _require(Path(go).is_absolute() and Path(go).is_file(), 'explicit Go executable required')
    request = {'root': str(Path(source_root).resolve()), 'files': files}
    helper = _helper('bootstrap.go')
    env = dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', GOWORK='off')
    try:
        completed = subprocess.run([str(go), 'run', str(helper)],
                                   input=json.dumps(request), text=True, capture_output=True,
                                   timeout=_remaining(deadline), env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreparationInfrastructureError('Go bootstrap AST transport failed') from exc
    _remaining(deadline)
    _require(completed.returncode == 0, 'AST discovery failed: ' + completed.stderr)
    try:
        ast = json.loads(completed.stdout)
    except ValueError as exc:
        raise BootstrapRefused('malformed Go bootstrap AST output') from exc
    verify_suites(ast, source)
    return {'source_commit': PINNED_COMMIT, 'ast_helper_sha256': _sha(helper.read_bytes()),
            'ast': ast}


def verify_suites(ast, source):
    """Bind every recorded source coordinate to the unchanged original bytes."""
    _require(ast['schema'] == 'r2t.go-bootstrap-ast/1' and ast['toolchain'] == 'go1.25.0',
             'AST helper identity differs')
    _require(ast['inactive_files'] == ['external/ui/bdd_spawn_agent_test.go',
                                     'internal/update/bdd_update_windows_test.go'],
             'Linux Go build dispositions differ')
    _require(len(ast['suites']) == 64, 'Linux-buildable original suite census differs')
    keys = set()
    for suite in ast['suites']:
        key = suite['glue_path'], suite['test_name']
        _require(key not in keys, 'duplicate original suite'); keys.add(key)
        for row in suite['source'].values():
            raw = source.get(row['file']); a, b = row['start'], row['end']
            _require(raw is not None and type(a) is int and type(b) is int
                     and 0 <= a < b <= len(raw) and raw[a:b].decode() == row['text']
                     and raw[:a].count(b'\n') + 1 == row['line'], 'original source span differs')
        proof = suite['source']
        _require(all(proof[name]['file'] == suite['glue_path'] for name in ('test', 'suite', 'options', 'path'))
                 and proof['test']['start'] <= proof['suite']['start'] < proof['suite']['end'] <= proof['test']['end']
                 and proof['test']['start'] <= proof['options']['start'] < proof['options']['end'] <= proof['test']['end']
                 and proof['options']['start'] <= proof['path']['start'] < proof['path']['end'] <= proof['options']['end']
                 and proof['suite']['line'] == suite['suite_line'], 'suite/options source joins differ')
        origin = suite['godog_tags_origin']
        expected = proof['options'] if origin['kind'] == 'default' else proof['tags']
        _require(origin['line'] == expected['line'] and expected['file'] == suite['glue_path'],
                 'tag origin source join differs')
        if origin['kind'] == 'linux_ansi_override':
            _require(suite['glue_path'] == 'internal/session/bdd_attachment_encoding_test.go'
                     and suite['godog_tags'] == '~@windows' and origin['line'] == 209
                     and proof['linux_decoder']['file'] == 'internal/platform/output_other.go',
                     'reviewed Linux override differs')
        _require(suite['feature_path'] in source, 'original feature is missing')
        context = {key: suite[key] for key in FIELDS - {'schema', 'scenario_line'}}
        validate_suite_context(dict(context, schema='r2t.go-suite-context/1', scenario_line=1))
    return ast


def selection_request(ast, source):
    """Project only original paths and filters; all selection remains native."""
    suites = [row for row in ast['suites'] if row['feature_path'] not in FEATURE_EXCLUSIONS]
    _require(len(suites) == 63, 'post-exclusion original wrapper census differs')
    request = {'features': {row['feature_path']: source[row['feature_path']].decode('utf-8') for row in suites},
               'suites': [{key: row[key] for key in ('glue_path', 'test_name', 'feature_path', 'godog_tags')}
                          for row in suites]}
    return request


def _native_rows(result, request):
    """Recheck native AST/pickle IDs against original header/Examples positions.

    Tags are retained as native evidence. This does not evaluate tag grammar or
    reconstruct pickle inheritance in Python.
    """
    _require(result['schema'] == 'r2t.go-bootstrap-selection/1'
             and result['toolchain'] == 'go1.25.0' and result['godog_version'] == 'v0.15.1',
             'native parser identity differs')
    _require(len(result['selections']) == len(request['suites']), 'native suite result census differs')
    rows = []
    for selected, suite in zip(result['selections'], request['suites']):
        source = request['features'][suite['feature_path']]
        _require(selected['suite'] == suite and selected['feature_sha256'] == _sha(source.encode()),
                 'native source/context identity differs')
        feature = parse_feature_file(suite['feature_path'], source)
        document = selected['document']; pickles = selected['pickles']
        if not pickles:
            _require(document is None, 'empty native selection has a document')
            rows.append([]); continue
        _require(document['uri'] == suite['feature_path'], 'native document URI differs')
        scenarios, examples = {}, {}
        def visit(children):
            for child in children:
                if child.get('rule'):
                    visit(child['rule']['children'])
                if not child.get('scenario'):
                    continue
                scenario = child['scenario']; line = scenario['location']['line']
                original = feature.scenario_at(line)
                _require(original is not None and original.title == scenario['name']
                         and scenario['id'] not in scenarios, 'native scenario/source header join differs')
                scenarios[scenario['id']] = original
                for example in scenario.get('examples', []):
                    for row in example.get('tableBody', []):
                        _require(row['id'] not in examples, 'duplicate native Examples row ID')
                        examples[row['id']] = (scenario['id'], row['location']['line'])
        visit(document['feature']['children'])
        _require({s.line for s in scenarios.values()} == {s.line for s in feature.scenarios},
                 'native document headers differ from original feature')
        selected_rows = []; seen = set()
        for pickle in pickles:
            ids = pickle['ast_node_ids']
            _require(len(ids) in (1, 2) and ids[0] in scenarios, 'native pickle lacks a scenario AST join')
            scenario = scenarios[ids[0]]
            _require(pickle['header_line'] == scenario.line, 'native pickle header differs')
            row_line = scenario.line
            if len(ids) == 2:
                _require(ids[1] in examples and examples[ids[1]][0] == ids[0], 'native pickle Examples AST join differs')
                row_line = examples[ids[1]][1]
            possible = ([line for line, _ in examples_rows(feature, scenario, dialect=CUCUMBER_DIALECT)]
                        if scenario.examples_lines else [scenario.line])
            _require(row_line in possible and pickle['row_line'] == row_line,
                     'native selected row is outside original scenario/Examples')
            steps = ([] if feature.background is None else feature.background.steps) + scenario.steps
            _require(pickle['step_lines'] == [s.line for s in steps], 'native Background/scenario step mapping differs')
            key = scenario.line, row_line
            _require(key not in seen, 'duplicate native row'); seen.add(key)
            selected_rows.append(key)
        rows.append(selected_rows)
    return rows


def assemble_items(raw_items, census, inspection, request, native):
    """Attach one context per original header; refuse zero or multiple matches."""
    items = deepcopy(select_candidates(raw_items, census))
    suites = {(s['glue_path'], s['test_name']): s for s in inspection['ast']['suites']}
    selected = {}
    for suite, rows in zip(request['suites'], _native_rows(native, request)):
        origin = suites[(suite['glue_path'], suite['test_name'])]
        for header in sorted({header for header, _ in rows}):
            key = suite['feature_path'], header
            _require(key not in selected, 'multiple original suite contexts select one candidate header')
            context = {key: origin[key] for key in FIELDS - {'schema', 'scenario_line'}}
            selected[key] = validate_suite_context(dict(context, schema='r2t.go-suite-context/1', scenario_line=header))
    _require(set(selected) == set(census['candidate_keys']), 'native selected headers differ from exact candidate census')
    for item in items:
        _require('files' not in item and 'go_suite' not in item, 'raw items already contain runtime context/answer paths')
        item['go_suite'] = selected[(item['provenance']['file_path'], item['provenance']['line'])]
    assert_candidate_items(items, census)
    return sorted(items, key=lambda item: item['item_id'])


def bootstrap_items(source_root, *, go, selector, deadline=None):
    """Return canonical 282 items and preparation proof, with no answer files.

    selector(request, *, helper, deadline) must run the supplied native helper
    in the qualified pinned image, with original go.mod/go.sum, and retain
    exact request/response, command, image and process/copy evidence. It returns returncode/stdout/stderr,
    timeout=False and cleanup_baseline_restored=True. This callback is transport,
    not a supplied context map; native source/AST joins are checked here.
    """
    deadline = time.monotonic() + 600 if deadline is None else deadline
    _remaining(deadline)
    inspection = inspect_suites(source_root, go=go, deadline=deadline)
    source = _snapshot(source_root)
    verify_suites(inspection['ast'], source)
    request = selection_request(inspection['ast'], source)
    helper = _helper('bootstrap_select.go')
    observed = selector(deepcopy(request), helper=str(helper), deadline=deadline)
    _remaining(deadline)
    if (observed.get('timeout') is not False or observed.get('cleanup_baseline_restored') is not True
            or type(observed.get('returncode')) is not int or observed['returncode'] in (124, 126, 127, 137)):
        raise PreparationInfrastructureError('native Go bootstrap transport/cleanup failed')
    _require(observed['returncode'] == 0, 'native feature selection failed: ' + observed.get('stderr', ''))
    try:
        native = json.loads(observed['stdout'])
    except ValueError as exc:
        raise BootstrapRefused('malformed native feature selection output') from exc
    raw, counts = extract_project('coddy-agent', str(source_root), subdir='features', language='go', framework='godog')
    _require(len(raw) == 354 and counts == {'features': 61, 'skipped': []}, 'raw original extraction differs')
    census = candidate_census(source_root)
    items = assemble_items(raw, census, inspection, request, native)
    _remaining(deadline)
    return {'items': items, 'proof': {'source_commit': PINNED_COMMIT, 'inspection': inspection,
            'selection_helper_sha256': _sha(helper.read_bytes()), 'request': request,
            'observed': deepcopy(observed), 'candidate_census': census,
            'closure_qualified': False, 'admitted': False}}
