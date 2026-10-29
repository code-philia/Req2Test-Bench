"""Original Go production declarations under explicit admitted suite contexts.

Only compilation of cached export data and trusted analysis occurs. No package
initialization, tests, coverage, API events or interface extraction runs here.
The union retains each canonical context's active production-file membership.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path, PurePosixPath
import subprocess
import tempfile

from .context import ContextRefused, ContextTable, validate_suite_context

SCHEMA = 'r2t.go_prod_index/1'
GO_PROD_PATHS = ('cmd', 'internal', 'external')


class GoIndexRefused(ValueError):
    """Missing original inputs or incomplete attribution; never partial success."""


def _run(argv, *, cwd, env, input=None):
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, input=input, capture_output=True)
    except OSError as exc:
        raise GoIndexRefused(f'cannot launch Go analysis: {exc}') from exc
    if result.returncode:
        raise GoIndexRefused('Go analysis failed: ' + result.stderr.decode('utf-8', errors='replace'))
    return result.stdout


def _packages(raw):
    decoder = json.JSONDecoder()
    text, rows = raw.decode('utf-8'), []
    try:
        while text.strip():
            row, end = decoder.raw_decode(text.lstrip())
            text = text.lstrip()[end:]
            rows.append(row)
    except ValueError as exc:
        raise GoIndexRefused('invalid go list package output') from exc
    return rows


def _inputs(repo_root, go, go_scratch, paths):
    root = Path(repo_root).resolve()
    if not root.is_dir() or not (root / 'go.mod').is_file():
        raise GoIndexRefused('Go index requires an original module root with go.mod')
    if not isinstance(go, str) or not Path(go).is_absolute():
        raise GoIndexRefused('Go index requires an explicit absolute go executable')
    if not isinstance(go_scratch, str) or not Path(go_scratch).is_absolute():
        raise GoIndexRefused('Go index requires explicit absolute trusted scratch')
    scratch = Path(go_scratch).resolve()
    if scratch == root or root in scratch.parents or scratch in root.parents \
            or scratch == Path('/work') or Path('/work') in scratch.parents:
        raise GoIndexRefused('Go analysis scratch must be disjoint from source and outside /work')
    paths = tuple(paths)
    if not paths or len(paths) != len(set(paths)) or any(
            not isinstance(path, str) or str(PurePosixPath(path)) != path
            or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts
            or path in ('', '.') for path in paths):
        raise GoIndexRefused('Go production roots must be unique relative source paths')
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / 'tmp').mkdir(exist_ok=True)
    # Keep the image's predownloaded module cache; a synthetic stdlib fixture
    # without one uses empty private support rather than the operator's home.
    modules = os.environ.get('GOMODCACHE', str(scratch / 'modules'))
    if not Path(modules).is_absolute():
        raise GoIndexRefused('GOMODCACHE must be an absolute qualified cache path')
    env = {key: value for key, value in os.environ.items() if not key.startswith('GO')}
    env.update(GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOENV='off',
               GOFLAGS='-mod=readonly', GO111MODULE='on', GOSUMDB='sum.golang.org',
               GOPATH=str(scratch / 'gopath'), GOMODCACHE=modules,
               GOCACHE=str(scratch / 'cache'), GOTMPDIR=str(scratch / 'tmp'),
               TMPDIR=str(scratch / 'tmp'))
    observed = json.loads(_run([go, 'env', '-json', 'GOVERSION', 'GOOS', 'GOARCH', 'CGO_ENABLED'],
                               cwd=root, env=env))
    if observed['GOVERSION'] != 'go1.25.0' or observed['GOOS'] != 'linux':
        raise GoIndexRefused('Go index requires qualified Go 1.25.0 on Linux')
    return root, scratch, paths, env, observed


def _removables(root, removable_paths, contexts):
    if not isinstance(removable_paths, (list, tuple)) or not removable_paths:
        raise GoIndexRefused('Go index requires explicit reviewed removable file paths')
    if any(not isinstance(path, str) or str(PurePosixPath(path)) != path
           or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts
           or path in ('', '.') or not (root / path).is_file()
           for path in removable_paths) or len(set(removable_paths)) != len(removable_paths):
        raise GoIndexRefused('Go removable paths must be unique exact existing relative files')
    if any(context['glue_path'] not in removable_paths for context in contexts):
        raise GoIndexRefused('selected Go glue is absent from the reviewed removable paths')
    return set(removable_paths)


def _compilation_view(root, destination, omitted):
    def ignore(directory, names):
        return [name for name in names
                if (Path(directory) == root and name == '.git')
                or (Path(directory) / name).relative_to(root).as_posix() in omitted]
    # Preserve supplied fixture links. A reviewed prepared snapshot already
    # carries its project-specific link dispositions; infer no other omissions.
    shutil.copytree(root, destination, symlinks=True, ignore=ignore)


def build_prod_index(repo_root: str, *, go: str, go_contexts, go_scratch: str,
                     removable_paths, go_closures,
                     paths=GO_PROD_PATHS) -> dict:
    """Union independently resolved contexts; never infer an untagged default.

    ``classes``/``methods`` use the existing production-index consumer shape.
    ``removable_paths`` is the reviewed boundary's exact file sequence. Each
    distinct compiler/helper input compiles an isolated copy with exactly its
    witnessed closure files, retaining ordinary tests/resources; original source
    is never stripped. Equal inputs reuse that result within this call while
    every canonical context keeps its own membership row.
    ``go_closures`` uses the existing witnessed closure-record format and must
    bind every supplied canonical context, without extra or missing records.
    A retained test depending on an unselected removable file still refuses.
    Type owners have ``decl`` only in their own TypeSpec's file; a receiver
    method declared in another file still has its original owner's name.
    Methods include private declarations, with declaration-name publicness.
    Body spans include braces; ``decl`` always names the physical func token.
    """
    if not isinstance(go_contexts, (list, tuple)) or not go_contexts:
        raise GoIndexRefused('Go production index requires explicit admitted suite contexts')
    if not isinstance(go_closures, (list, tuple)) or not go_closures:
        raise GoIndexRefused('Go production index requires witnessed closure records')
    try:
        contexts = [validate_suite_context(context) for context in go_contexts]
        table = ContextTable(go_closures, boundary=None, project='coddy-agent')
        if len(contexts) != len(go_closures):
            raise GoIndexRefused('Go contexts and witnessed closures differ')
        for context in contexts:
            if context != table.context_for(context['feature_path'], context['scenario_line']):
                raise GoIndexRefused('Go context differs from its witnessed closure')
    except ContextRefused as exc:
        raise GoIndexRefused(str(exc)) from exc
    keys = [(context['feature_path'], context['scenario_line']) for context in contexts]
    if len(keys) != len(set(keys)):
        raise GoIndexRefused('duplicate original item key in Go index contexts')
    contexts.sort(key=lambda context: (context['feature_path'], context['scenario_line']))
    root, scratch, paths, env, observed = _inputs(repo_root, go, go_scratch, paths)
    removable = _removables(root, removable_paths, contexts)
    answer_sets = [table.files_for(context['feature_path'], context['scenario_line'])
                   for context in contexts]
    if any(not set(answers) <= removable for answers in answer_sets):
        raise GoIndexRefused('Go answer files must be exact reviewed removable paths')
    files, memberships, runtime = {}, [], None
    resolved = {}
    with tempfile.TemporaryDirectory(prefix='prod-index-', dir=scratch) as directory:
        support = Path(directory)
        helper = support / 'prod_index.go'
        helper.write_bytes(Path(__file__).with_suffix('.go').read_bytes())
        (support / 'go.mod').write_text('module r2t.local/production-index\n\ngo 1.25.0\n')
        binary = support / 'prod-index'
        _run([go, 'build', '-o', str(binary), str(helper)], cwd=support, env=env)
        for index, (context, answers) in enumerate(zip(contexts, answer_sets)):
            key = (context['package_dir'], context['package_name'], context['glue_path'],
                   tuple(context['go_build_tags']), answers)
            fresh = key not in resolved
            if fresh:
                view = support / ('view-' + str(index))
                _compilation_view(root, view, removable - set(answers))
                argv = [go, 'list', '-p=1', '-deps', '-export', '-test', '-json']
                if context['go_build_tags']:
                    argv.append('-tags=' + ','.join(context['go_build_tags']))
                argv.append('./' + context['package_dir'])
                packages = _packages(_run(argv, cwd=view, env=env))
                request = {'root': str(view), 'original_root': str(root), 'paths': paths, 'packages': packages,
                           'package_dir': context['package_dir'], 'package_name': context['package_name'],
                           'glue_path': context['glue_path']}
                output = _run([str(binary)], cwd=support, env=env,
                              input=json.dumps(request).encode('utf-8'))
                try:
                    result = json.loads(output)
                except ValueError as exc:
                    raise GoIndexRefused('invalid Go declaration output') from exc
            else:
                result = resolved[key]
            facts = result['runtime']
            if (facts['toolchain'], facts['goos'], facts['goarch'], facts['cgo_enabled']) != (
                    observed['GOVERSION'], observed['GOOS'], observed['GOARCH'], observed['CGO_ENABLED'] == '1'):
                raise GoIndexRefused('Go analysis runtime differs from the qualified compiler')
            if runtime is not None and runtime != facts:
                raise GoIndexRefused('Go runtime changed between explicit index contexts')
            runtime = facts
            for path, row in result['files'].items():
                if path in files and files[path] != row:
                    raise GoIndexRefused(f'original declarations differ between Go contexts: {path}')
                files[path] = row
            memberships.append({'go_suite': context, 'answer_files': list(answers),
                                'files': sorted(result['files'])})
            if fresh:
                shutil.rmtree(view)
                resolved[key] = result
    ordered = {path: files[path] for path in sorted(files)}
    methods = [method for row in ordered.values() for cls in row['classes'] for method in cls['methods']]
    return {'schema': SCHEMA, 'root': str(root), 'paths': list(paths), 'files': ordered,
            'contexts': memberships, 'runtime': runtime,
            'counts': {'files': len(ordered), 'contexts': len(contexts), 'methods': len(methods),
                       'public_methods': sum(method['public'] for method in methods)}}


def build_context_index(repo_root: str, *, go: str, go_context: dict,
                        go_scratch: str, removable_paths, go_closure, paths=GO_PROD_PATHS) -> dict:
    """The same primitive with exactly one explicit canonical context."""
    return build_prod_index(repo_root, go=go, go_contexts=[go_context],
                            go_scratch=go_scratch, removable_paths=removable_paths,
                            go_closures=[go_closure], paths=paths)
