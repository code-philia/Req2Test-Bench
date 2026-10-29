"""Original-source, cached-export Go attribution; no subject code executes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from .context import (ContextTable, ContextRefused, HANDLER_FIELDS,
                      handler_identity as native_handler_identity, validate_suite_context)
from .prod_index import GO_PROD_PATHS, GoIndexRefused, _inputs, _removables, _compilation_view, _run
from .prod_index_entry import source_inventory

SCHEMA = 'r2t.go-interface-attribution/1'
COMPILE_FIELDS = ('package_dir', 'package_name', 'glue_path', 'go_build_expression', 'go_build_tags')


def handler_identity(handler):
    """Use the native handler, not its distinct registration-site coordinates."""
    try:
        return native_handler_identity(handler)
    except ContextRefused as exc:
        raise GoIndexRefused(str(exc)) from exc


def member_key(handler):
    h = handler_identity(handler)
    return tuple(h[k] for k in HANDLER_FIELDS)


def partitions(closures, prod_index):
    """Group identical compiler contexts; retain each exact item membership."""
    table = ContextTable(closures, boundary=None, project='coddy-agent')
    if prod_index.get('schema') != 'r2t.go_prod_index/1':
        raise GoIndexRefused('Go interfaces requires the reviewed Go production index')
    memberships = {}
    for row in prod_index.get('contexts', []):
        context = validate_suite_context(row['go_suite'])
        key = context['feature_path'], context['scenario_line']
        if key in memberships:
            raise GoIndexRefused('duplicate Go production-index context')
        memberships[key] = row
    if set(memberships) != {(c['feature_file'],c['scenario_line']) for c in closures}:
        raise GoIndexRefused('Go interface closure/index populations differ')
    groups, contexts = [], []
    by_key = {}
    for closure in closures:
        context = table.context_for(closure['feature_file'], closure['scenario_line'])
        answers = table.files_for(closure['feature_file'], closure['scenario_line'])
        row = memberships[closure['feature_file'], closure['scenario_line']]
        if row['go_suite'] != context or row.get('answer_files') != list(answers) \
                or any(p not in prod_index['files'] for p in row['files']):
            raise GoIndexRefused('Go interface context/answers differ from production index')
        key = json.dumps([*[context[k] for k in COMPILE_FIELDS], answers], sort_keys=True)
        if key not in by_key:
            by_key[key] = len(groups)
            groups.append({'context':context, 'files':list(answers), 'handlers':[], 'production_files':row['files']})
        partition = by_key[key]; group = groups[partition]
        if row['files'] != group['production_files']:
            raise GoIndexRefused('same Go build context has inconsistent production membership')
        for step in closure.get('steps', []):
            if step.get('side') != 'removable':
                continue
            handler = handler_identity((step.get('definition') or {}).get('go',{}).get('handler'))
            if handler['file'] not in answers or step.get('origin') not in ('scenario','background'):
                raise GoIndexRefused('native Go handler lies outside its closure or origin')
            if handler not in group['handlers']:
                group['handlers'].append(handler)
        contexts.append({'go_suite':context, 'answer_files':list(answers), 'files':row['files'], 'partition':partition})
    return groups, contexts


def attribute_sources(source_root, closures, prod_index, *, go, go_scratch, removable_paths):
    """Fresh original compile views, one cached-export query per exact group."""
    groups, contexts = partitions(closures, prod_index)
    root, scratch, _, env, observed = _inputs(source_root, go, go_scratch, GO_PROD_PATHS)
    removable = _removables(root, removable_paths, [g['context'] for g in groups])
    inventory = source_inventory(root)
    facts = []
    helper_source = Path(__file__).with_name('interfaces.go')
    with tempfile.TemporaryDirectory(prefix='interfaces-', dir=scratch) as directory:
        support = Path(directory)
        helper = support/'interfaces.go'; helper.write_bytes(helper_source.read_bytes())
        binary = support/'interfaces'
        _run([go,'build','-p=1','-o',str(binary),str(helper)],cwd=support,env=env)
        for i, group in enumerate(groups):
            view = support/('view-'+str(i))
            _compilation_view(root, view, removable-set(group['files']))
            c = group['context']
            query = {'label':str(i), 'package_dir':c['package_dir'], 'package_name':c['package_name'],
                     'glue_path':c['glue_path'], 'go_build_tags':c['go_build_tags'],
                     'files':group['files'], 'handlers':group['handlers']}
            raw = _run([str(binary)],cwd=support,env=env,input=json.dumps({'Root':str(view),'Go':go,'Queries':[query]}).encode())
            result = json.loads(raw)
            if result.get('schema') != SCHEMA or result.get('toolchain') != observed['GOVERSION'] \
                    or len(result.get('queries',[])) != 1:
                raise GoIndexRefused('invalid Go interface attribution output')
            fact = result['queries'][0]
            for path,digest in fact['source_files'].items():
                if inventory.get(path) != {'sha256':digest}:
                    raise GoIndexRefused('Go attribution changed original source identity: '+path)
            facts.append(fact)
            shutil.rmtree(view)
    if source_inventory(root) != inventory:
        raise GoIndexRefused('original Go source changed during interface attribution')
    return {'schema':SCHEMA,'source_root':str(root),'source_inventory':inventory,
            'contexts':contexts,'partitions':facts,'runtime':observed,
            'helper_sha256':hashlib.sha256(helper_source.read_bytes()).hexdigest()}
