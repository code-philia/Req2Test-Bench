"""Compiler preparation evidence, deliberately distinct from a native closure.

The caller owns guarded compiler copies and one absolute deadline. No Docker,
subject handlers, placeholder controls, or population admission runs here.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
import time

from .coddy import PINNED_COMMIT, candidate_census
from .context import validate_suite_context, _path

SCHEMA = 'r2t.go-closure-preparation/1'


class ClosurePlanRefused(ValueError):
    """Unsupported/ambiguous source or ordinary compiler refusal."""


class PreparationInfrastructureError(RuntimeError):
    """Transport, deadline or copy-integrity failure; never a compiler finding."""


def _require(condition, message):
    if not condition:
        raise ClosurePlanRefused('REFUSED: Go closure preparation: ' + message)


def _remaining(deadline):
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
        raise PreparationInfrastructureError('an absolute finite deadline is required')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise PreparationInfrastructureError('shared closure preparation deadline expired')
    return remaining


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _snapshot(source_root):
    """Read the full clean pin using the already reviewed Go copy policy."""
    root = Path(source_root).resolve()
    candidate_census(root)  # includes clean/full/pin identity, not closure evidence
    listed = subprocess.check_output(['git', '-C', str(root), 'ls-tree', '-rz',
                                      '--name-only', PINNED_COMMIT])
    files = {}
    for raw in listed.split(b'\0'):
        if not raw:
            continue
        rel = raw.decode('utf-8'); _path(rel, 'tracked source path')
        path = root / rel
        if path.is_symlink() and not path.exists():
            continue  # pinned six dangling UI links; never copy a dangling link
        _require(path.resolve().is_relative_to(root) and path.is_file(),
                 'tracked source must resolve to an in-root regular file: ' + rel)
        files[rel] = path.read_bytes()
    return files


def _removable(boundary, source):
    _require(boundary.project == 'coddy-agent', 'wrong boundary project')
    paths = [path for path, _ in boundary.removable]
    _require(paths and len(paths) == len(set(paths)), 'empty/duplicate removable census')
    for path in paths:
        _path(path, 'removable path')
        _require(path in source and path.startswith(('cmd/', 'internal/', 'external/'))
                 and PurePosixPath(path).name.startswith('bdd_') and path.endswith('_test.go')
                 and not any(c in path for c in '*?[]') and boundary.classify(path) == 'removable',
                 'removable census must contain exact original BDD files')
    return tuple(sorted(paths))


def compile_context(context):
    """Shared compilation key; native feature/header/test/tag selection stays separate."""
    context = validate_suite_context(context)
    return {key: context[key] for key in ('glue_path', 'package_dir', 'package_name',
                                          'go_build_expression', 'go_build_tags')}


def _helper():
    return Path(__file__).with_name('support') / 'closure_plan.go'


def _seed_files(inventory, removable):
    # Exact effects of Godog strip + sanitise_repo on tracked source. Git is
    # already absent from the prepared tracked-file snapshot. The Go strip
    # supplies no bytecode/build roots to the shared sanitizer.
    from ..bench.repo import _EXTRACTION_ARTIFACTS
    from .registry import support_files
    omitted = {'_bench/' + name for name in _EXTRACTION_ARTIFACTS}
    omitted.add('_bench/strip_manifest.json')
    source = inventory['source_files']
    supports = support_files()
    _require(not set(source) & set(supports), 'source occupies reserved Go support paths')
    expected = {p: h for p, h in source.items() if p not in removable and p not in omitted
                and not p.startswith(('var/cache/', 'var/log/'))}
    expected.update({p: _sha(raw) for p, raw in supports.items()})
    return expected


def source_inventory(context, *, source_root, boundary, go, deadline):
    """Fresh stdlib AST/build inventory; owners are not claimed type-resolved.

    The Go executable must be the explicit pinned host tool. This helper parses
    source only, matches Linux/amd64 build files, and never imports the subject.
    """
    context = validate_suite_context(context); _remaining(deadline)
    source = _snapshot(source_root); removable = _removable(boundary, source)
    _require(context['glue_path'] in removable, 'primary is outside removable census')
    _require(Path(go).is_absolute() and Path(go).is_file(), 'explicit Go executable required')
    request = {'root': str(Path(source_root).resolve()), 'package_dir': context['package_dir'],
               'package_name': context['package_name'], 'tags': context['go_build_tags'],
               'files': sorted(source)}
    helper = _helper()
    try:
        result = subprocess.run([str(go), 'run', str(helper)], input=json.dumps(request),
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=_remaining(deadline), check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreparationInfrastructureError('source inventory tool failed') from exc
    _remaining(deadline)
    _require(result.returncode == 0, 'source inventory refused: ' + result.stderr)
    try:
        ast = json.loads(result.stdout)
    except ValueError as exc:
        raise ClosurePlanRefused('malformed source inventory output') from exc
    inventory = {'source_commit': PINNED_COMMIT, 'compile_context': compile_context(context),
                 'inventory_helper_sha256': _sha(helper.read_bytes()),
                 'source_files': {p: _sha(b) for p, b in source.items()},
                 'removable_paths': list(removable), 'ast': ast}
    _validate_inventory(inventory, context, boundary, source)
    return inventory


def _validate_inventory(inventory, context, boundary, source):
    _require(inventory['source_commit'] == PINNED_COMMIT
             and inventory['compile_context'] == compile_context(context)
             and inventory['inventory_helper_sha256'] == _sha(_helper().read_bytes()),
             'inventory source/context identity differs')
    _require(inventory['source_files'] == {p: _sha(b) for p, b in source.items()},
             'inventory differs from exact original source bytes')
    removable = _removable(boundary, source)
    _require(inventory['removable_paths'] == list(removable), 'inventory boundary differs')
    ast = inventory['ast']
    _require(ast['toolchain'] == 'go1.25.0', 'inventory has wrong Go toolchain')
    active = ast['active_files']
    _require(active == sorted(set(active)) and context['glue_path'] in active
             and all(p in source and str(PurePosixPath(p).parent) == context['package_dir'] for p in active),
             'invalid active package file inventory')
    def span(value):
        raw = source.get(value['file']); a, b = value['start'], value['end']
        _require(raw is not None and type(a) is int and type(b) is int and 0 <= a < b <= len(raw)
                 and raw[a:b].decode('utf-8') == value['text']
                 and raw[:a].count(b'\n') + 1 == value['line'], 'declaration/source span differs')
    for owner in ast['owners']:
        _require(owner['declaration']['file'] in active and owner['kind'] in ('func', 'type', 'var', 'const')
                 and isinstance(owner['name'], str) and owner['name'], 'invalid declaration owner')
        span(owner['declaration']); span(owner['identifier'])
        declaration, identifier = owner['declaration'], owner['identifier']
        _require(identifier['text'] == owner['name'] and identifier['file'] == declaration['file']
                 and declaration['start'] <= identifier['start'] < identifier['end'] <= declaration['end'],
                 'owner identifier/declaration join differs')
    for edge in ast['runtime_edges']:
        for key in ('caller', 'handler', 'selector', 'owner'):
            span(edge[key])
        _require(edge['caller']['file'] in active and edge['owner']['file'] in removable
                 and edge['owner']['file'] in active and edge['name'] == 'TestHelperHook'
                 and json.loads(edge['selector']['text']) == '-test.run=^TestHelperHook$',
                 'unsupported runtime helper edge')
        handler, selector = edge['handler'], edge['selector']
        _require(selector['file'] == handler['file']
                 and handler['start'] <= selector['start'] < selector['end'] <= handler['end']
                 and any(row['name'] == edge['name'] and row['kind'] == 'func'
                         and row['declaration'] == edge['owner'] for row in ast['owners']),
                 'runtime selector/Handler/declaration joins differ')
    return removable


def verify_inventory(record, *, source_root, context, boundary):
    """Bind raw AST evidence to the clean pin and physical declaration/helper joins.

    This rechecks source bytes and evidence structure, not a subject compiler run.
    The successful compiler test-variant output separately closes active-file
    membership when a preparation receipt is replayed.
    """
    context = validate_suite_context(context)
    _validate_inventory(record, context, boundary, _snapshot(source_root))
    return json.loads(json.dumps(record))


def compiler_argv(context):
    context = validate_suite_context(context)
    argv = ['go', 'list', '-deps', '-export', '-test', '-json', '-p=1']
    if context['go_build_tags']:
        argv += ['-tags', ','.join(context['go_build_tags'])]
    return tuple(argv + ['./' + context['package_dir']])


def _checked_attempt(result, *, files, context, inventory, removable):
    """Compare actual callback observations to independently derived copy bytes."""
    if (result.get('timeout') is not False or result.get('cleanup_baseline_restored') is not True
            or type(result.get('returncode')) is not int or result['returncode'] < 0
            or result['returncode'] in (124, 126, 127, 137)):
        raise PreparationInfrastructureError('compiler timeout/transport/cleanup failure')
    expected = _seed_files(inventory, removable)
    expected.update({p: inventory['source_files'][p] for p in files})
    if result.get('inventory_before') != expected or result.get('inventory_after') != expected:
        raise PreparationInfrastructureError('compiler copy inventories differ from exact Go stripped seed plus answers')
    _require(isinstance(result.get('stdout'), str) and isinstance(result.get('stderr'), str),
             'compiler result requires both raw output streams')
    work = result.get('work_root')
    _require(isinstance(work, str) and work.startswith('/') and work.rstrip('/') == work,
             'compiler result lacks its concrete work root')
    if result['returncode'] == 0:
        packages = []; text = result['stdout']; decoder = json.JSONDecoder()
        try:
            while text.strip():
                value, end = decoder.raw_decode(text.lstrip()); packages.append(value); text = text.lstrip()[end:]
        except ValueError as exc:
            raise ClosurePlanRefused('successful compiler output is not complete go list JSON') from exc
        wanted = {PurePosixPath(p).name for p in inventory['ast']['active_files']
                  if p not in removable or p in files}
        variants = [p for p in packages if p.get('Dir') == work + '/' + context['package_dir']
                    and p.get('Name') == context['package_name']
                    and {PurePosixPath(f).name for f in p.get('GoFiles', [])} == wanted]
        _require(variants, 'compiler success lacks the exact restored test variant')
    return result


_DIAGNOSTIC = re.compile(r'^(.*\.go):(\d+):(\d+): (.*)$', re.MULTILINE)
_UNDEFINED = re.compile(r'undefined: ([A-Za-z_][A-Za-z_0-9]*)$')
# A missing embedded type also hides its promoted fields (observed in the
# pinned hooks-subagents first compile). This supplies no declaration owner.
_MISSING_MEMBER = re.compile(
    r'[A-Za-z_][A-Za-z_0-9]*\.([A-Za-z_][A-Za-z_0-9]*) undefined '
    r'\(type \*?[A-Za-z_][A-Za-z_0-9]* has no field or method \1\)$')


def _additions(result, files, context, inventory, removable):
    owners = {}
    for row in inventory['ast']['owners']:
        owners.setdefault(row['name'], set()).add(row['declaration']['file'])
    additions = set(); reasons = []
    # ExecutionCopy's real transport merges stderr into stdout. Neither stream
    # is a framework match source; these are compiler diagnostics only.
    for file, line, column, message in _DIAGNOSTIC.findall(result['stdout'] + '\n' + result['stderr']):
        name = _UNDEFINED.fullmatch(message)
        if message == 'too many errors':
            continue
        path = file.removeprefix(result['work_root'] + '/').removeprefix('./')
        _require(path in inventory['ast']['active_files'] and (path not in removable or path in files),
                 'compiler diagnostic is outside the actual selected package')
        if _MISSING_MEMBER.fullmatch(message):
            # Raw text remains in the attempt. Only the bare undefined names
            # below can justify growth/deletion, and they must add new files.
            continue
        _require(name is not None, 'unsupported compiler diagnostic: ' + message)
        targets = owners.get(name[1], set())
        _require(len(targets) == 1 and next(iter(targets)) in removable,
                 'ambiguous/non-removable undefined symbol: ' + name[1])
        target = next(iter(targets)); additions.add(target)
        reasons.append({'file': path, 'line': int(line), 'column': int(column),
                        'symbol': name[1], 'owner': target})
    additions -= files
    _require(additions, 'compiler refusal made no supported dependency progress')
    return additions, reasons


def _logic(context, inventory, removable, attempt):
    selected = {context['glue_path']}; dependencies = []
    def grow():
        nonlocal selected
        while True:
            result = attempt(tuple(sorted(selected)), 'grow')
            if result['returncode'] == 0:
                return
            additions, reasons = _additions(result, selected, context, inventory, removable)
            dependencies.extend(reasons); selected |= additions
    grow()
    while True:
        deleted = False; deletions = {}
        for path in sorted(selected - {context['glue_path']}):
            result = attempt(tuple(sorted(selected - {path})), 'delete')
            if result['returncode'] == 0:
                selected.remove(path); deleted = True; break
            # Failed deletion must demonstrate supported missing declarations,
            # not silently count a random compiler failure as necessity.
            _additions(result, selected - {path}, context, inventory, removable)
            deletions[path] = True
        if not deleted:
            break
    minimal = sorted(selected); runtime = []
    while True:
        additions = set()
        for edge in inventory['ast']['runtime_edges']:
            if edge['caller']['file'] in selected and edge['owner']['file'] not in selected:
                additions.add(edge['owner']['file']); runtime.append(edge)
        if not additions:
            break
        selected |= additions
        grow()  # added whole helper files may themselves require declarations
    return {'files': sorted(selected), 'compiler_minimal_files': minimal,
            'compiler_dependencies': dependencies, 'runtime_dependencies': runtime,
            'deletion_witness_files': sorted(deletions)}


def derive_file_plan(context, *, source_root, boundary, inventory, compiler, deadline):
    """Produce preparation evidence using injected guarded compiler observations.

    compiler(files, *, context, argv, deadline) returns returncode/stdout/stderr,
    work_root, full inventory_before/inventory_after, timeout and
    cleanup_baseline_restored. It must preserve the supplied absolute deadline
    across fresh attempts. No native result or closure is manufactured here.
    """
    context = validate_suite_context(context); _remaining(deadline)
    source = _snapshot(source_root); removable = _validate_inventory(inventory, context, boundary, source)
    attempts = []; argv = compiler_argv(context)
    def attempt(files, phase):
        _remaining(deadline)
        result = compiler(files, context=context, argv=argv, deadline=deadline)
        _remaining(deadline)
        result = _checked_attempt(result, files=files, context=context, inventory=inventory, removable=removable)
        attempts.append({'files': list(files), 'phase': phase, 'argv': list(argv),
                         'result': json.loads(json.dumps(result))})
        return result
    derived = _logic(context, inventory, removable, attempt)
    _remaining(deadline)
    return {'schema': SCHEMA, 'source_commit': PINNED_COMMIT,
            'compile_context': compile_context(context),
            'inventory': json.loads(json.dumps(inventory)),
            'attempts': attempts, **derived, 'native_qualified': False}


def verify_file_plan(receipt, *, context, source_root, boundary, inventory=None):
    """Read-only replay of source-bound preparation evidence; no compiler runs.

    Raw inventory evidence is independently bound to the clean pin and original
    physical spans. The final claimed file list is then recomputed from compiler
    diagnostics, exact copy/test-variant inventories, and runtime-helper edges.
    """
    context = validate_suite_context(context)
    inventory = verify_inventory(receipt['inventory'] if inventory is None else inventory,
                                 source_root=source_root, context=context, boundary=boundary)
    removable = tuple(inventory['removable_paths'])
    _require(receipt['schema'] == SCHEMA and receipt['source_commit'] == PINNED_COMMIT
             and receipt['compile_context'] == compile_context(context)
             and receipt['inventory'] == inventory and receipt['native_qualified'] is False,
             'preparation receipt identity/claim differs')
    attempts = iter(receipt['attempts']); argv = compiler_argv(context)
    def attempt(files, phase):
        record = next(attempts, None)
        _require(record is not None and record['files'] == list(files) and record['phase'] == phase
                 and record['argv'] == list(argv), 'compiler attempt sequence differs')
        return _checked_attempt(record['result'], files=files, context=context,
                                inventory=inventory, removable=removable)
    derived = _logic(context, inventory, removable, attempt)
    _require(next(attempts, None) is None and all(receipt.get(k) == v for k, v in derived.items()),
             'claimed final plan differs from compiler/runtime evidence replay')
    return tuple(derived['files'])
