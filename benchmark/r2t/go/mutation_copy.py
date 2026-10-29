"""Reference-validated mutation transfer into one already finalized remote copy.

The coordinator supplies original/reference bytes and their exact engine request.
Gold source and request are staged only in a private analysis area, removed
before candidate execution. The applier's Go build cache is per worker, outside
that area, so it keeps compiled packages (original answers included) between
attempts; see REFERENCE_CACHE. This module changes no scoring or population rules.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import re
import stat

from ..toolkit.mutation_go import splice, ENGINE, ENGINE_VERSION, ENUMERATOR_REV
from .execution import COPY_ROOT, ORIGINAL_ROOT, RUN_ROOT, ExecutionRefused, ExecutionTimeout, _path, _payload, parse_inventory

ENGINE_PATH = '_bench/go/support/mutate.go'
REFERENCE_ROOT = RUN_ROOT + '/mutation-reference'
REFERENCE_SOURCE = REFERENCE_ROOT + '/source'
REQUEST_PATH = REFERENCE_ROOT + '/context.json'
# Per-worker Go build cache for the reference applier, beside the execution
# phase's own /r2t-go/cache and outside RUN_ROOT, which `prepare`/`retire`
# recreate for every copy, so consecutive attempts on one worker reuse it.
# Go keys every cache entry by a hash of its complete inputs (source bytes,
# flags, toolchain, dependency outputs and, outside GOROOT, the package
# directory, here under the fixed REFERENCE_SOURCE) and stores each output
# under its content hash, so a hit returns what a cold rebuild would produce:
# the applier's typed enumeration and splice cannot change. The host still
# verifies the exact spliced bytes, metadata and reference inventory each time.
# GOTMPDIR/TMPDIR stay per attempt inside REFERENCE_ROOT and are retired with it.
REFERENCE_CACHE = '/r2t-go/mutation-cache'


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(copy, root, path, *, kind='BYTES', forward=True):
    _path(path)
    timeout = min(30, copy._remaining(['mutation-read',path])) if forward else 30
    try:
        verb='metadata' if kind=='METADATA' else 'read'
        raw=_payload(copy._checked(verb,root,path,timeout=timeout),kind)
        if kind=='METADATA':
            value=json.loads(raw)
            if (not isinstance(value,dict) or set(value)!={'mode','uid','gid'}
                    or any(type(value[k]) is not int or value[k]<0 for k in value)
                    or not stat.S_ISREG(value['mode'])):
                copy._refuse('invalid reference metadata response')
        else:value=raw
    except BaseException:
        copy.quarantined=True
        raise
    if forward:copy._remaining(['mutation-read',path])
    return value


def _inventory(copy, root, *, forward=True):
    timeout=min(30,copy._remaining(['mutation-reference-inventory'])) if forward else 30
    try:
        result=parse_inventory(copy._checked('inventory',root,timeout=timeout))
    except BaseException:
        copy.quarantined=True
        raise
    if forward:copy._remaining(['mutation-reference-inventory'])
    return result


def _write(copy, root, path, raw):
    _path(path)
    copy._checked('write',root,path,input=base64.b64encode(raw).decode('ascii'),
                  timeout=min(30,copy._remaining(['mutation-reference-write',path])))
    copy._remaining(['mutation-reference-write',path])


def apply_mutation(copy, descriptor, *, reference_files, engine_request,
                   engine_sha256, measurement=False):
    """Apply one source-bound descriptor after the existing single finalize.

    `reference_files` is the independently authenticated original compile view:
    production/retained sources/resources and only the original answers required
    by this item's reference context. It must not come from candidate imports.
    The request uses the existing engine schema and this module's fixed private
    REFERENCE_SOURCE root; no implicit tags or fallback context is accepted.
    """
    copy._available()
    if measurement is not False:
        raise ExecutionRefused('Go mutation execution does not collect API/coverage')
    context=copy._context
    if context is None:
        raise ExecutionRefused('mutation needs the selected original suite context')
    files=dict(reference_files)
    if not files or any(not isinstance(raw,bytes) for raw in files.values()):
        raise ExecutionRefused('mutation reference requires complete original bytes')
    for path in files:_path(path)
    request=deepcopy(engine_request)
    expected_context={'root':REFERENCE_SOURCE,'package_dir':context['package_dir'],
        'package_name':context['package_name'],'glue_path':context['glue_path'],
        'go_build_tags':context['go_build_tags']}
    reference_pre={p:_hash(raw) for p,raw in files.items()}
    reference_answers={p for p in files if copy.original_boundary.classify(p)=='removable'}
    if reference_answers!=set(copy._answer_paths):
        raise ExecutionRefused('reference analysis must contain exactly this original answer set')
    if any(copy.original_inventory.get(p)!=digest for p,digest in reference_pre.items() if p not in reference_answers):
        raise ExecutionRefused('reference production/retained bytes differ from the verified original seed')
    if (not isinstance(request,dict) or set(request)!={'contexts','source_files'}
            or request['contexts']!=[expected_context] or request['source_files']!=reference_pre
            or context['glue_path'] not in files):
        raise ExecutionRefused('reference request differs from authenticated original context/files')
    target=descriptor['file'];_path(target)
    if (target not in files or copy.copy_boundary.classify(target)!='production'
            or not isinstance(engine_sha256,str) or not re.fullmatch('[0-9a-f]{64}',engine_sha256)
            or copy.original_inventory.get(ENGINE_PATH)!=engine_sha256):
        raise ExecutionRefused('mutation target or immutable engine lacks original authority')
    changed=splice(files[target],{k:v for k,v in descriptor.items() if k!='id'})
    pre=copy.begin_mutation()
    if pre.get(target)!=reference_pre[target]:
        copy._refuse('candidate production target differs from reference original')
    original=copy.read(target);metadata=copy.read_metadata(target)
    if original!=files[target]:copy._refuse('candidate target is not the authenticated original')
    engine=_read(copy,ORIGINAL_ROOT,ENGINE_PATH)
    if _hash(engine)!=engine_sha256:copy._refuse('immutable original engine differs from authority')
    proof={'descriptor':deepcopy(descriptor),'pre_mutation_inventory':pre,
        'reference_pre':reference_pre,'candidate_before_sha256':_hash(original),
        'candidate_metadata':metadata,'engine_sha256':engine_sha256,
        'engine':ENGINE,'engine_version':ENGINE_VERSION,'enumerator_rev':ENUMERATOR_REV,
        'reference_retired':False,'candidate_transfer':None}
    copy.mutation_evidence=proof
    owned=False
    try:
        copy._checked('prepare-reference',timeout=min(30,copy._remaining(['prepare-reference'])))
        owned=True
        # Copy only independently authenticated original nonremovable paths.
        # Candidate answers/coordination never enter the reference analysis.
        original_paths=sorted(set(files)-reference_answers)
        names=b''.join(path.encode('utf-8')+b'\0' for path in original_paths)
        copy._checked('copy-reference',input=base64.b64encode(names).decode('ascii'),
                      timeout=min(30,copy._remaining(['copy-reference'])))
        copy._remaining(['copy-reference'])
        proof['reference_original_paths']=original_paths
        for path in sorted(reference_answers):_write(copy,REFERENCE_SOURCE,path,files[path])
        request_bytes=(json.dumps(request,sort_keys=True)+'\n').encode()
        _write(copy,REFERENCE_ROOT,'context.json',request_bytes)
        if _inventory(copy,REFERENCE_SOURCE)!=reference_pre:
            copy._refuse('reference view differs from independently constructed original input')
        reference_metadata=_read(copy,REFERENCE_SOURCE,target,kind='METADATA')
        proof['reference_metadata']=reference_metadata
        row={k:v for k,v in descriptor.items() if k!='id'}
        argv=['/usr/bin/env','GOCACHE='+REFERENCE_CACHE,'GOTMPDIR='+REFERENCE_ROOT+'/tmp',
            'TMPDIR='+REFERENCE_ROOT+'/tmp','/usr/local/go/bin/go','run','-p=1',
            ORIGINAL_ROOT+'/'+ENGINE_PATH,'--operator-profile','v2','--root',REFERENCE_SOURCE,
            '--build-contexts',REQUEST_PATH,'--apply-file',target,'--start-line',str(row['start_line']),
            '--start-col',str(row['start_col']),'--operator',row['operator'],
            '--original',row['original'],'--mutated',row['mutated'],'--out',target]
        completed=copy.run_mutation_applier(argv)
        proof['reference_engine']={'argv':list(argv),'returncode':completed.returncode,
                                   'stdout':completed.stdout,'stderr':completed.stderr}
        if completed.returncode:
            raise ExecutionRefused('original reference engine refused the mutation descriptor')
        try:response=json.loads(completed.stdout)
        except (ValueError,TypeError):
            copy._refuse('malformed reference engine response')
        if not isinstance(response,dict) or set(response)!={'file','applied','original_sha256','mutated_sha256','metadata'}:
            copy._refuse('reference engine response fields differ')
        materialized=_read(copy,REFERENCE_SOURCE,target)
        observed_metadata=_read(copy,REFERENCE_SOURCE,target,kind='METADATA')
        expected_reference=dict(reference_pre);expected_reference[target]=_hash(changed)
        if (materialized!=changed or observed_metadata!=reference_metadata
                or response.get('file')!=target or response.get('applied') is not True
                or response.get('original_sha256')!=reference_pre[target]
                or response.get('mutated_sha256')!=_hash(changed) or response.get('metadata')!=reference_metadata
                or _inventory(copy,REFERENCE_SOURCE)!=expected_reference):
            copy._refuse('reference engine result/bytes/metadata differs from the exact host splice')
        proof['reference_applied_sha256']=_hash(materialized)
        copy.install_mutation(target,original,materialized,metadata)
        proof['candidate_transfer']={'sha256':_hash(materialized),'metadata':copy.read_metadata(target),
            'expected_mutations':copy.expected_mutations,'verified':True}
    except BaseException as error:
        if isinstance(error, ExecutionTimeout) and copy.diagnostics_ready:
            evidence=copy.command_evidence[-1]
            for name,key in (('stdout.log','stdout'),('timeout.log','timeout_log')):
                raw=copy.read_diagnostic_output(name)
                if raw is not None:evidence[key]=raw.decode('utf-8',errors='replace')
        proof['failure']={'type':type(error).__name__,'message':str(error),
                          'commands':deepcopy(copy.command_evidence)}
        raise
    finally:
        # Original answer source, request and temporary build files must
        # disappear before any candidate test can execute, including failures.
        # REFERENCE_CACHE is deliberately outside this root and persists.
        if owned and not copy.quarantined:
            copy._checked('retire-reference',timeout=30)
            copy._mutation_reference_retired=True
            proof['reference_retired']=True
    if not copy._mutation_reference_retired:copy._refuse('reference analysis retirement was not proved')
    return deepcopy(proof)


@contextmanager
def mutation_attempt(copy, descriptor, **kwargs):
    """One shared apply/execute/read/discard scope for future runtime and audit."""
    try:
        proof=apply_mutation(copy,descriptor,**kwargs)
        yield proof
    finally:
        if not copy.quarantined and copy._state in {'prepared','planned','ready','executed'}:
            copy.retire()
