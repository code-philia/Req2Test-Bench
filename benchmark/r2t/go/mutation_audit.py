"""Standalone Go population audit in an existing authenticated worker.

The host audit root supplies authenticated original inputs. A separate private
image tree survives each apply/parse/restore walk; only actual restoration
of its full PRE earns the shared restored counter. No subject code executes.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
from pathlib import Path
import stat
import shutil
import tempfile
import threading
import time

from ..data import mutation_attestation as A
from ..toolkit import mutation_audit as shared
from ..toolkit import mutation_go as M
from .execution import ORIGINAL_ROOT
from .mutation_runtime import prepare_original
from .prod_index_entry import source_inventory

SUPPORT = ('mutation_audit.go', 'mutation_audit_support.go')
REQUEST = '_bench/go/mutation-audit-request.json'
PREFIX = ['/usr/local/go/bin/go', 'run', '-p=1',
          *[ORIGINAL_ROOT+'/_bench/go/support/'+name for name in SUPPORT]]


def _require(value, message):
    if not value:
        raise A.MutationAssetRefused('REFUSED: Go materialisation audit: '+message)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _bounded(files, roots):
    return {p:raw for p,raw in files.items()
            if any(p == root or p.startswith(root+'/') for root in roots)}


def _facts(value, expected=None):
    _require(isinstance(value, dict) and bool(value), 'missing complete native source snapshot')
    for path, fact in value.items():
        _require(isinstance(fact, dict) and set(fact) == {'sha256', 'metadata'}, 'invalid source snapshot entry')
        digest, metadata = fact['sha256'], fact['metadata']
        _require(isinstance(digest, str) and len(digest) == 64
                 and all(c in '0123456789abcdef' for c in digest), 'invalid source digest')
        _require(isinstance(metadata, dict) and set(metadata) == {'mode', 'uid', 'gid'}
                 and all(type(v) is int and v >= 0 for v in metadata.values())
                 and stat.S_ISREG(metadata['mode']), 'invalid native source metadata')
    if expected is not None:
        _require(value == expected, 'complete source bytes or mode/uid/gid differ from PRE')
    return value


def _snapshot_digests(facts, roots):
    if facts is None:
        return None, None
    selected = _bounded(facts, roots)
    return (A.canonical_sha256([{'file':p, 'sha256':f['sha256']} for p,f in sorted(selected.items())]),
            shared._source_lstat_digest({p:tuple(f['metadata'][k] for k in ('mode','uid','gid'))
                                         for p,f in selected.items()}))


def _collateral(before, after):
    if before is None or after is None:
        return {'added':[], 'changed':[], 'deleted':[]}
    return {'added':sorted(set(after)-set(before)), 'deleted':sorted(set(before)-set(after)),
            'changed':sorted(p for p in set(before)&set(after) if before[p] != after[p])}


def _parse_result(document, raw, parser):
    _require(isinstance(document, dict) and set(document) == {'parser','sha256','valid','errors'}
             and document['parser'] == parser and document['sha256'] == _hash(raw)
             and type(document['valid']) is bool and isinstance(document['errors'], list),
             'actual changed-file parser identity or bytes differ')
    starts = [0]+[i+1 for i,b in enumerate(raw) if b == 10 and i+1 < len(raw)]
    for error in document['errors']:
        _require(isinstance(error, dict) and set(error) == {'offset','line','column','message'},
                 'malformed physical parse diagnostic')
        offset = error['offset']
        _require(type(offset) is int and 0 <= offset <= len(raw), 'parse diagnostic offset differs')
        line = sum(start <= offset for start in starts)
        _require(error['line'] == line and error['column'] == offset-starts[line-1]+1
                 and isinstance(error['message'], str) and bool(error['message']),
                 'parse diagnostic does not use physical source coordinates')
    _require(document['valid'] is True and document['errors'] == [], 'materialised target does not parse')


def _inputs(manifest, audit_root, harness, artifacts, evidence_dir, engine_source_path):
    root = Path(audit_root)
    _require(root.is_absolute() and root.resolve() == root and root.is_dir(),
             'audit root must be a canonical absolute directory')
    marker = root/A.DISPOSABLE_MARKER
    _require(marker.is_file() and not marker.is_symlink()
             and marker.read_text() == shared.DISPOSABLE_MARKER_CONTENT, 'missing exact disposable audit marker')
    image = getattr(harness, 'image_id', None)
    authority = prepare_original(harness, manifest, artifacts, image_id=image)
    workspace, gold = Path(harness.root).resolve(), Path(harness.manifest.gold_root).resolve()
    evidence = Path(evidence_dir).resolve()
    paths = (root, workspace, gold, Path(artifacts).resolve())
    for i,p in enumerate(paths):
        for q in paths[i+1:]:
            _require(not (p.is_relative_to(q) or q.is_relative_to(p)),
                     'audit root, worker, gold and artifacts must be disjoint')
    # A fresh evidence directory may sit beside the three immutable artifact
    # inputs. It must remain outside every source tree whose bytes we audit.
    for protected in (root,workspace,gold):
        _require(not (evidence.is_relative_to(protected) or protected.is_relative_to(evidence)),
                 'audit evidence and source trees must be disjoint')
    inventory = source_inventory(root)
    _require(all(set(f) != {'link'} for f in inventory.values()), 'audit input has a source symlink')
    hashes = {p:f['sha256'] for p,f in inventory.items() if set(f) == {'sha256'} and p != A.DISPOSABLE_MARKER}
    _require(hashes == dict(authority.source_hashes), 'audit source set differs from complete original authority')
    files = dict(authority.reference_files)
    _require(set(files) == set(hashes), 'original authority lacks full source bytes')
    _require(shared._snapshot_tree(str(root), A._audit_roots(manifest))
             == _bounded(files, A._audit_roots(manifest)),
             'manifest-bounded audit source set differs from original authority')
    modes = {}
    for p,raw in files.items():
        _require((root/p).read_bytes() == raw, 'audit input bytes differ: '+p)
        modes[p] = (root/p).stat().st_mode
    engine = Path(engine_source_path) if engine_source_path is not None else M.GO_SOURCE
    _require(engine.is_absolute() and engine.resolve() == engine and engine.is_file()
             and engine.name == 'mutate.go' and _hash(engine.read_bytes()) == authority.engine_sha256,
             'audit engine source differs from the immutable worker implementation')
    for name in SUPPORT:
        relative = '_bench/go/support/'+name
        raw = Path(__file__).with_name('support').joinpath(name).read_bytes()
        _require(harness.copy.original_inventory.get(relative) == _hash(raw)
                 and (workspace/relative).read_bytes() == raw, 'audit helper differs from immutable seed: '+name)
    groups = []
    for encoded, answers, production in authority.contexts.values():
        c = json.loads(encoded)
        row = {'package_dir':c['package_dir'], 'package_name':c['package_name'], 'glue_path':c['glue_path'],
               'go_build_tags':c['go_build_tags'], 'answers':list(answers), 'production_files':list(production)}
        if row not in groups:
            groups.append(row)
    request = {'files':{p:{'sha256':hashes[p], 'data':base64.b64encode(raw).decode('ascii'),
                              'mode':modes[p], 'removable':harness.boundary.classify(p) == 'removable'}
                         for p,raw in files.items()},
               'contexts':groups, 'mutants':deepcopy(manifest['mutants'])}
    for descriptor in manifest['mutants']:
        M.splice(files[descriptor['file']], {k:v for k,v in descriptor.items() if k != 'id'})
    _require(not evidence.exists() or (evidence.is_dir() and not any(evidence.iterdir())),
             'audit evidence output must be fresh')
    return authority, root, evidence, request, files, modes, inventory


def _audit_session(manifest, prepared, *, timeout, queue=None, slot=0):
    """One private full request; partial session counters are never attestations."""
    authority, root, evidence, request, files, modes, host_before = prepared
    harness = authority.harness
    roots = A._audit_roots(manifest)
    original_digest = shared._source_set_digest(_bounded(files, roots))
    evidence.mkdir(parents=True, exist_ok=True)
    def save(name, value):
        with (evidence/name).open('x',encoding='utf-8') as stream:
            json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')
    save('request.json',request)
    save('binding.json',{'manifest_digest':manifest['digest'], 'original_root':authority.original_root,
        'image_id':authority.image_id, 'engine_sha256':authority.engine_sha256,
        'audit_root':str(root), 'timeout_per_operation':timeout})
    copy = harness.copy
    pre = after = None
    runtime_parser = None
    owned = False
    counts = dict(attempted=0,applied=0,parse_valid=0,restored=0)
    failing_id = problem = None
    stage = 'prepare'
    operation_number = 0
    def invoke(action,index=None,*,housekeeping=False):
        nonlocal operation_number, owned, after
        number = operation_number;operation_number += 1
        argv = PREFIX+[action]+([] if index is None else [str(index)])
        try:
            completed = copy.run_audit_operation(argv,timeout=30 if housekeeping else timeout)
            save(f'{number:06d}-{action}-command.json',deepcopy(copy.command_evidence[-1]))
            _require(completed.returncode == 0, 'audit operation helper failed: '+action)
            document = json.loads(completed.stdout)
            _require(isinstance(document,dict) and document.get('operation') == action
                     and type(document.get('ok')) is bool, 'incomplete audit operation response')
            save(f'{number:06d}-{action}.json',document)
            if action == 'setup' and document.get('owned') is True:
                owned = True
            if document.get('after') is not None:
                after = _facts(document['after'])
            elif document.get('before') is not None:
                after = _facts(document['before'])
            _require(document['ok'], 'audit '+action+' failed: '+str(document.get('error')))
            return document
        except BaseException:
            if copy.command_evidence and not (evidence/f'{number:06d}-{action}-command.json').exists():
                save(f'{number:06d}-{action}-command.json',deepcopy(copy.command_evidence[-1]))
            raise
    try:
        encoded, answers, _ = next(iter(authority.contexts.values()))
        copy.prepare(json.loads(encoded),None,{REQUEST:(json.dumps(request,sort_keys=True)+'\n').encode()},
                     allowed_paths=answers,deadline=time.monotonic()+timeout)
        stage = 'setup'
        setup = invoke('setup')
        pre = _facts(setup['before'])
        _require(set(pre) == set(files) and all(pre[p]['sha256'] == _hash(raw)
                 and pre[p]['metadata']['mode'] == modes[p] for p,raw in files.items()),
                 'staged native PRE differs from independently held original source')
        runtime_parser = setup['runtime_parser']
        _require(runtime_parser == manifest['parser'], 'independent image Go version differs from manifest')
        if queue is not None:
            queue.ready(pre)
        indices = range(len(manifest['mutants'])) if queue is None else queue.indices(slot)
        for index in indices:
            descriptor = manifest['mutants'][index]
            failing_id = descriptor['id'];target = descriptor['file']
            counts['attempted'] += 1
            changed = M.splice(files[target],{k:v for k,v in descriptor.items() if k != 'id'})
            expected = deepcopy(pre);expected[target]['sha256'] = _hash(changed)
            iteration_problem = None
            try:
                stage = 'apply'
                applied = invoke('apply',index)
                counts['applied'] += 1
                stage = 'materialised_bytes'
                _facts(applied['before'],pre);_facts(applied['after'],expected)
                _require(base64.b64decode(applied['target'],validate=True) == changed, 'applier wrote a different splice')
                engine = json.loads(applied['engine_stdout'])
                _require(set(engine) == {'file','applied','original_sha256','mutated_sha256','metadata'}
                         and engine == {'file':target,'applied':True,'original_sha256':pre[target]['sha256'],
                                        'mutated_sha256':_hash(changed),'metadata':pre[target]['metadata']},
                         'source engine response differs from actual bytes/metadata')
                stage = 'parse'
                parsed = invoke('parse',index)
                _facts(parsed['before'],expected);_facts(parsed['after'],expected)
                _require(base64.b64decode(parsed['target'],validate=True) == changed, 'parsed target differs from splice')
                _parse_result(parsed['parse'],changed,runtime_parser)
                counts['parse_valid'] += 1
            except BaseException as error:
                iteration_problem = error
                if queue is not None:
                    queue.stop()
            finally:
                if not copy.quarantined:
                    try:
                        restored = invoke('restore',index,housekeeping=True)
                        _facts(restored['after'],pre)
                        _require(base64.b64decode(restored['target'],validate=True) == files[target],
                                 'actual target did not restore original bytes')
                        counts['restored'] += 1
                    except BaseException as error:
                        stage = 'restore';iteration_problem = error;copy.quarantined = True
            if iteration_problem is not None:
                raise iteration_problem
        failing_id = None
        stage = 'final_source_set'
        _facts(after,pre)
    except BaseException as error:
        problem = error
        if queue is not None:
            queue.stop()
    finally:
        if owned and not copy.quarantined:
            try:
                retired = invoke('retire',housekeeping=True)
                _facts(retired['before'],pre)
                _require(retired.get('private_analysis_removed') is True,'private source/cache/tmp removal unproved')
                owned = False
            except BaseException as error:
                stage = 'retire';problem = error;copy.quarantined = True
        elif not owned and stage == 'setup' and problem is not None:
            # An interrupted setup cannot certify whether its private gold was
            # created. Its container must be discarded, never quietly reused.
            copy.quarantined = True
        if not copy.quarantined and copy._state in {'prepared','planned','ready','executed'}:
            try:copy.retire()
            except BaseException as error:stage='retire';problem=error;copy.quarantined=True
        try:
            _require(source_inventory(root) == host_before, 'host original audit inputs changed')
            harness.verify_substrate()
        except BaseException as error:
            if problem is None:stage='final_source_set';problem=error
        if problem is not None and queue is not None:
            queue.stop()
        save('commands.json',deepcopy(copy.command_evidence))
    before_source,before_lstat = _snapshot_digests(pre,roots)
    after_source,after_lstat = _snapshot_digests(after,roots)
    report = {'schema':A.AUDIT_SCHEMA, 'status':'failed' if problem else 'complete',
        'manifest_digest':manifest['digest'], 'engine':manifest['engine'],
        'engine_version':manifest['engine_version'], 'parser':manifest['parser'], 'n_mutants':manifest['n'],
        **{'n_'+key:value for key,value in counts.items()}, 'n_source_files':len(_bounded(files,roots)),
        'bounded_roots':roots,'source_set_sha256_before':before_source or original_digest,
        'source_set_sha256_after':after_source,'source_lstat_sha256_before':before_lstat,
        'source_lstat_sha256_after':after_lstat,'failing_mutant_id':failing_id,
        'failure_stage':stage if problem else None,'failure':str(problem) if problem else None,
        'collateral':_collateral(pre,after),
        'operator_gate':{'mode':'real_engine','disposable_marker':A.DISPOSABLE_MARKER,
            'engine_source_sha256':authority.engine_sha256, 'runtime_parser_identity':manifest['parser'],
            'runtime_parser_reported':runtime_parser}}
    return report


def _finish_report(report, manifest, evidence):
    report['digest'] = A.audit_digest(report)
    if report['status'] == 'complete':
        audit_entry = {'status':'complete','attestation_digest':report['digest'],
            'n_source_files':report['n_source_files'],'bounded_roots':report['bounded_roots'],
            'source_set_sha256':report['source_set_sha256_before'],
            'engine_source_sha256':report['operator_gate']['engine_source_sha256'],
            'runtime_parser_identity':report['parser']}
        project_entry = {k:manifest[k] for k in ('engine','engine_version','parser')}
        project_entry['engine_source'] = {'sha256':report['operator_gate']['engine_source_sha256']}
        try:
            A.validate_completed_audit_binding(audit_entry,report,manifest,project_entry)
        except BaseException as error:
            report.update(status='failed',failure_stage='completed_binding',failure=str(error))
            report['digest'] = A.audit_digest(report)
    with (evidence/'report.json').open('x',encoding='utf-8') as stream:
        json.dump(report,stream,indent=2,sort_keys=True);stream.write('\n')
    if report['status'] != 'complete':
        raise A.MaterialisationAuditRefused(report['failure'],report)
    return report


class _AuditQueue:
    """Do not dispatch until every isolated worker has the same native PRE."""
    def __init__(self, count, workers):
        self.count = count
        self.next = 0
        self.lock = threading.Lock()
        self.stopped = False
        self.pre = None
        self.barrier = threading.Barrier(workers)
        self.assigned = [[] for _ in range(workers)]

    def ready(self, pre):
        with self.lock:
            if self.pre is None:
                self.pre = deepcopy(pre)
            _require(pre == self.pre, 'parallel native PRE bytes or metadata differ')
        try:
            self.barrier.wait()
        except threading.BrokenBarrierError:
            # The failing worker owns the refusal; peers retire without work.
            _require(self.stopped, 'parallel readiness barrier broke unexpectedly')

    def indices(self, slot):
        while True:
            with self.lock:
                if self.stopped or self.next == self.count:
                    return
                index = self.next
                self.next += 1
                self.assigned[slot].append(index)
            yield index

    def stop(self):
        with self.lock:
            self.stopped = True
        self.barrier.abort()


def audit_population_in_image(manifest, audit_root, *, harness, artifacts, evidence_dir,
                              timeout=300, engine_source_path=None, parallel_workers=()):
    """Audit one full population using isolated, already authenticated workers.

    ``parallel_workers`` contains additional (harness, artifacts) pairs from the
    same live pool. Every worker gets the complete request; only descriptor
    indices are shared. The unchanged serial route retains its evidence layout.
    """
    _require(type(timeout) in (int,float) and math.isfinite(timeout) and 0 < timeout <= 600,
             'operation timeout must be positive and at most 600 seconds')
    workers = [(harness, artifacts), *parallel_workers]
    evidence = Path(evidence_dir).resolve()
    if len(workers) == 1:
        prepared = _inputs(manifest,audit_root,harness,artifacts,evidence,engine_source_path)
        return _finish_report(_audit_session(manifest,prepared,timeout=timeout),manifest,evidence)
    roots = [Path(worker.root).resolve() for worker,_ in workers]
    _require(len({id(worker.copy) for worker,_ in workers}) == len(workers),
             'parallel workers share an execution copy')
    for index, root in enumerate(roots):
        for other in roots[index+1:]:
            _require(not (root.is_relative_to(other) or other.is_relative_to(root)),
                     'parallel worker source trees overlap')
    _require(not evidence.exists() or (evidence.is_dir() and not any(evidence.iterdir())),
             'audit evidence output must be fresh')
    # Authenticate the supplied root before creating any disposable replicas.
    first = _inputs(manifest,audit_root,harness,artifacts,evidence/'worker-0',engine_source_path)
    with tempfile.TemporaryDirectory(prefix='go-parallel-audit-',dir=Path(audit_root).parent) as scratch:
        prepared = [first]
        for slot,(worker,worker_artifacts) in enumerate(workers[1:],1):
            root = Path(scratch)/str(slot)
            shutil.copytree(audit_root,root)
            item = _inputs(manifest,str(root),worker,worker_artifacts,
                           evidence/f'worker-{slot}',engine_source_path)
            _require(item[3] == first[3] and item[0].image_id == first[0].image_id
                     and item[0].engine_sha256 == first[0].engine_sha256,
                     'parallel original inputs or engine/image identities differ')
            prepared.append(item)
        evidence.mkdir(parents=True,exist_ok=True)
        queue = _AuditQueue(len(manifest['mutants']),len(workers))
        def run(slot, item):
            try:
                return _audit_session(manifest,item,timeout=timeout,queue=queue,slot=slot)
            except BaseException:
                queue.stop()
                raise
        with ThreadPoolExecutor(max_workers=len(workers)) as executor:
            try:
                futures = [executor.submit(run,slot,item)
                           for slot,item in enumerate(prepared)]
                reports = [future.result() for future in futures]
            except BaseException:
                queue.stop()
                raise
        failures = [report for report in reports if report['status'] != 'complete']
        report = deepcopy(failures[0] if failures else reports[0])
        for field in ('n_attempted','n_applied','n_parse_valid','n_restored'):
            report[field] = sum(item[field] for item in reports)
        report['parallel_audit'] = {'n_roots':len(workers),
                                   'mutants_by_root':[item['n_attempted'] for item in reports]}
        assigned = [index for group in queue.assigned for index in group]
        if not failures and sorted(assigned) != list(range(len(manifest['mutants']))):
            report.update(status='failed',failure_stage='parallel_coverage',
                          failure='parallel audit did not cover every descriptor exactly once')
        return _finish_report(report,manifest,evidence)


def audit_bound_pool(args, manifest, *, audit_root, evidence_dir, engine_source_path=None):
    """Run a full raw audit independently of mapping, using the owning live pool.

    The shared CLI and population operator use this same authentication path.
    The namespace supplies the ordinary worker/harness arguments and audit_workers.
    """
    import argparse
    import os
    from ..bench.cli import _harness, _worker_spec
    from ..bench.worker import validate_live_worker_runtime, WorkerRefused
    from ..bench.validate import HARNESS_VERSION
    A.validate_manifest(manifest, expected_engine=M.ENGINE)
    harness, _, _ = _harness(args)
    live = validate_live_worker_runtime(
        args.worker, _worker_spec(args), HARNESS_VERSION,
        needs_database=False,
        answer_paths=(args.gold,args.artifacts,audit_root),
        expected_runtime={key:harness._worker_runtime[key] for key in (
            "harness_version","container_image_digest",
            "workspace_seed_digest","database_dump_digest")})
    harness.runner.container = live["selected"]["binding"]["container"]["id"]
    go_workers = [(harness, args.artifacts)]
    if args.audit_workers < 1:
        raise WorkerRefused("REFUSED: --audit-workers must be positive")
    if args.audit_workers > 1:
        from ..bench.worker import validate_offline_worker_runtime_pool
        if args.audit_workers > len(live["pool_paths"]):
            raise WorkerRefused(
                "REFUSED: --audit-workers exceeds the authenticated Go pool")
        bound_pool = validate_offline_worker_runtime_pool(list(live["pool_paths"]))
        go_workers = []
        identity_keys = ("harness_version", "container_image_digest",
                         "workspace_seed_digest", "database_dump_digest")
        for path, bound in zip(live["pool_paths"], bound_pool):
            if len(go_workers) == args.audit_workers:
                break
            worker = bound["worker"]
            if bound["binding"]["pool"]["digest"] != live["docker_execution_pool_digest"] \
                    or any(bound["runtime"][key] != harness._worker_runtime[key]
                           for key in identity_keys):
                raise WorkerRefused("REFUSED: parallel Go worker pool/runtime differs")
            if os.path.abspath(path) == os.path.abspath(args.worker):
                current = harness
            else:
                worker_args = argparse.Namespace(**vars(args))
                worker_args.worker = path
                worker_args.repo = worker.workspace
                worker_args.container = worker.container
                worker_args.workdir = worker.workdir
                worker_args.artifacts = worker.artifacts_root
                current, _, _ = _harness(worker_args)
            current.runner.container = bound["binding"]["container"]["id"]
            go_workers.append((current, worker.artifacts_root))
    primary, primary_artifacts = go_workers[0]
    return audit_population_in_image(
        manifest,audit_root,harness=primary,
        artifacts=primary_artifacts,evidence_dir=evidence_dir,
        engine_source_path=engine_source_path,parallel_workers=go_workers[1:])
