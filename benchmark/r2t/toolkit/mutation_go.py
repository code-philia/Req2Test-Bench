"""Go generation-two source mutations; compilation precedes manifest emission.

The source applier is for an already prepared disposable copy. This module does
not implement the benchmark worker's expected_mutations or per-attempt lifecycle.
Mutation executions keep API/coverage instrumentation disabled.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from ..data import mutation as M
from ..go.context import ContextTable
from ..go.interfaces_attribution import partitions
from ..go.prod_index import GO_PROD_PATHS, _inputs, _compilation_view, _removables
from ..go.prod_index_entry import source_inventory

GO_ENGINE_DIR = str(Path(__file__).resolve().parents[1] / 'go')
GO_SOURCE = Path(GO_ENGINE_DIR) / 'mutate.go'
EXCLUDED_PREFIXES = ('!cmd', '!external', '!internal')
DEFAULT_PATHS = GO_PROD_PATHS


def _constant(name):
    match = re.search(r'^const '+re.escape(name)+r' = "([^"]+)"$',GO_SOURCE.read_text(),re.M)
    if not match:
        raise RuntimeError('Go mutation source lacks constant '+name)
    return match[1]


ENGINE = _constant('ENGINE')
ENGINE_VERSION = _constant('ENGINE_VERSION')
ENUMERATOR_REV = _constant('ENUMERATOR_REV')
if tuple(_constant('OPERATOR_ORDER').split(',')) != M.OPERATORS:
    raise RuntimeError('Go mutation operator catalogue differs from the shared order')


class GoMutationRefused(RuntimeError):
    pass


def _require(condition, reason):
    if not condition:
        raise GoMutationRefused('REFUSED: Go mutation: '+reason)


def applier():
    from ..bench.mutation_run import Applier
    return Applier(source='mutate.go',rel='_bench/go/support/mutate.go',interpreter='go run')


def _path(path):
    _require(isinstance(path,str) and path and path==M.normalise_path(path)
             and path not in ('.','') and Path(path).as_posix()==path and not Path(path).is_absolute()
             and '..' not in Path(path).parts and all(ord(c)>=32 for c in path),
             'noncanonical source path')
    return path


def validate_build_contexts(contexts):
    """Validate the closed, digest-covered Go manifest extension."""
    _require(isinstance(contexts,list) and contexts,'missing go_build_contexts')
    previous=None
    for row in contexts:
        _require(isinstance(row,dict) and set(row)=={'package_dir','go_build_tags','production_files'},'build context fields differ')
        _path(row['package_dir'])
        _require(row['go_build_tags'] in ([],['http'],['cli']),'unqualified build tags')
        files=row['production_files']
        _require(isinstance(files,list) and files==sorted(set(files)),'production files must be sorted unique')
        for path in files:
            _path(path)
            _require(path.endswith('.go') and not path.endswith('_test.go') and not M.is_excluded(path,EXCLUDED_PREFIXES),'context contains nonproduction Go source')
        key=(row['package_dir'],tuple(row['go_build_tags']),tuple(files))
        _require(previous is None or previous<key,'build contexts must be sorted unique')
        previous=key
    return contexts


def _context_union(rows):
    # This deduplicates context authority only; raw descriptors never pass here.
    unique={json.dumps(r,sort_keys=True):r for r in rows}
    return validate_build_contexts(sorted(unique.values(),key=lambda r:(r['package_dir'],tuple(r['go_build_tags']),tuple(r['production_files']))))


def _row(row):
    checked=M._validate(row,M.OPERATORS,0)
    _require(set(checked)==set(M.REQUIRED_FIELDS)|{'end_line','end_col'},'Go descriptor fields differ')
    _path(checked['file'])
    _require(not checked['file'].endswith('_test.go') and not M.is_excluded(checked['file'],EXCLUDED_PREFIXES),'nonproduction Go descriptor')
    _require(all(type(checked[k]) is int and checked[k]>0 for k in ('end_line','end_col')) and
             (checked['end_line'],checked['end_col']) >= (checked['start_line'],checked['start_col']),'invalid inclusive physical end')
    return checked


def splice(raw,row):
    """Independent physical UTF-8 byte splice, including both inclusive ends."""
    row=_row(row);lines=raw.splitlines(keepends=True)
    def offset(line,column):
        _require(1<=line<=len(lines) and 1<=column<=len(lines[line-1]),'byte coordinate outside source line')
        return sum(map(len,lines[:line-1]))+column-1
    start=offset(row['start_line'],row['start_col']);end=offset(row['end_line'],row['end_col'])+1
    _require(start<end and raw[start:end]==row['original'].encode(),'original physical source span differs')
    return raw[:start]+row['mutated'].encode()+raw[end:]


def validate_envelope(document, *, expected_parser=None):
    from ..data import mutation_attestation as A
    _require(isinstance(document,dict) and 'go_build_contexts' in document,'Go enumerator lacks build context authority')
    contexts=validate_build_contexts(document['go_build_contexts'])
    A.validate_enumerator_envelope(document,expected_engine=ENGINE,expected_engine_version=ENGINE_VERSION,
        expected_parser_version=expected_parser,expected_enumerator_rev=ENUMERATOR_REV)
    manifest=build_population(document['mutants'],parser_version=document['parser'],go_build_contexts=contexts,
                              n_invalid=document.get('n_invalid'),enumerator_rev=document['enumerator_rev'])
    _require(manifest['n']==len(document['mutants']) and not manifest['n_excluded'],'excluded or duplicate Go raw rows')
    _require(document['files']>=len({m['file'] for m in document['mutants']}),'file census smaller than mutant files')
    return document


def build_population(raw, *, parser_version, go_build_contexts, sample=None, seed=None,
                     n_invalid=None, enumerator_rev=None, exclusions=EXCLUDED_PREFIXES):
    contexts=validate_build_contexts(go_build_contexts)
    files={p for c in contexts for p in c['production_files']}
    for row in raw:
        _row(row);_require(row['file'] in files,'descriptor outside compiled context inventory')
    _require(enumerator_rev==ENUMERATOR_REV,'unverified Go enumerator revision')
    manifest=M.build_manifest(raw,parser_version=parser_version,operators=M.OPERATORS,exclusions=exclusions,
        engine=ENGINE,engine_version=ENGINE_VERSION,sample=sample,seed=seed,n_invalid=n_invalid,enumerator_rev=enumerator_rev)
    manifest['go_build_contexts']=contexts
    manifest['digest']=M.manifest_digest(manifest)
    return manifest


def validate_manifest(manifest):
    """Apply Go descriptor rules alongside complete shared artifact validation."""
    from ..data import mutation_attestation as A
    _require(isinstance(manifest,dict) and manifest.get('digest')==M.manifest_digest(manifest),'manifest digest differs')
    contexts=validate_build_contexts(manifest.get('go_build_contexts'))
    _require(manifest.get('engine')==ENGINE and manifest.get('engine_version')==ENGINE_VERSION
             and manifest.get('operators')==list(M.OPERATORS) and manifest.get('enumerator_rev')==ENUMERATOR_REV,'Go engine/catalogue/revision differs')
    A.validate_manifest(manifest,expected_engine=ENGINE)
    files={p for c in contexts for p in c['production_files']}
    for row in manifest['mutants']:
        _row({k:v for k,v in row.items() if k!='id'});_require(row['file'] in files,'manifest row outside compiled contexts')
    return manifest


def population_for(document, *, expected_parser=None, sample=None, seed=None):
    doc=validate_envelope(document,expected_parser=expected_parser)
    return build_population(doc['mutants'],parser_version=doc['parser'],go_build_contexts=doc['go_build_contexts'],
        sample=sample,seed=seed,n_invalid=doc.get('n_invalid'),enumerator_rev=doc['enumerator_rev'])


def boundary_population_for(document, boundary, boundary_config, boundary_sha256, *,
                            expected_parser=None, sample=None, seed=None):
    """Use shared production-boundary derivation with complete Go authority."""
    from ..data import mutation_attestation as A
    raw=population_for(document,expected_parser=expected_parser)
    return A.derive_boundary_scored_manifest(raw,boundary,boundary_config,boundary_sha256,sample=sample,seed=seed)


def production_only(raw,boundary):
    kept=[r for r in raw if boundary.classify(r['file'])=='production']
    return kept,len(raw)-len(kept)


def _save(path,document):
    Path(path).write_text(json.dumps(document,sort_keys=True,indent=2)+'\n')


def _invoke(argv, *, cwd, env, evidence):
    """Record complete compiler output; unknown failures are never invalid rows."""
    evidence=Path(evidence)
    _save(evidence.with_suffix('.command.json'),{'argv':list(argv),'cwd':str(cwd)})
    try:
        result=subprocess.run(argv,cwd=cwd,env=env,capture_output=True)
    except BaseException as error:
        _save(evidence.with_suffix('.failure.json'),{'error':repr(error)})
        raise
    evidence.with_suffix('.stdout').write_bytes(result.stdout)
    evidence.with_suffix('.stderr').write_bytes(result.stderr)
    _save(evidence.with_suffix('.result.json'),{'returncode':result.returncode})
    return result


def _metadata(path):
    current=Path(path).lstat()
    _require(stat.S_ISREG(current.st_mode),'mutation target must be a regular file')
    return {'mode':current.st_mode,'uid':current.st_uid,'gid':current.st_gid}


def _restore(path,raw,metadata):
    """Existing shared restoration/metadata contract on a host-visible copy only."""
    from ..bench.mutation_run import _restore_bytes_and_lstat
    _restore_bytes_and_lstat(str(path),raw,metadata,'Go disposable-copy mutation restoration')


def _evidence_path(evidence_dir, source_root):
    evidence=Path(evidence_dir).resolve()
    source=Path(source_root).resolve()
    _require(not evidence.is_relative_to(source) and not source.is_relative_to(evidence),
             'evidence directory must be disjoint from protected source/copy')
    return evidence


def _enumerate_source_copy(source_root, *, go, go_scratch, closures, prod_index, removable_paths,
                           original_inventory, evidence_dir, compile_workers=1):
    """Pure producer machinery; caller supplies independently pinned source authority."""
    from ..go.mutation_entry import enumerate_copy
    evidence=_evidence_path(evidence_dir,source_root)
    try:
        result=enumerate_copy(source_root,go=go,go_scratch=go_scratch,closures=closures,
            prod_index=prod_index,removable_paths=removable_paths,original_inventory=original_inventory,
            evidence_dir=evidence,engine_source=GO_SOURCE,
            expected_engine_sha256=hashlib.sha256(GO_SOURCE.read_bytes()).hexdigest(),
            compile_workers=compile_workers)
    except ValueError as error:
        raise GoMutationRefused(str(error)) from error
    parser_version=result['parser'];report=result['typed_candidates'];envelope=result['envelope']
    _require(report.get('schema')=='r2t.go-mutation-candidates/1' and report.get('engine')==ENGINE
             and report.get('engine_version')==ENGINE_VERSION and report.get('enumerator_rev')==ENUMERATOR_REV
             and report.get('parser')==parser_version and report.get('operators')==list(M.OPERATORS),'typed engine identity differs')
    M.build_manifest(report['candidates'],parser_version=parser_version,engine=ENGINE,engine_version=ENGINE_VERSION,
                     operators=M.OPERATORS,exclusions=EXCLUDED_PREFIXES)
    validate_envelope(envelope,expected_parser=parser_version)
    _require(envelope['go_build_contexts']==_context_union(report['contexts']),'final build contexts differ')
    return envelope


def enumerate_local(repo_root, *, go, go_scratch, closures, prod_index, boundary, evidence_dir,
                    expected_enumerator_sha256):
    """Enumerate the clean pinned original coddy source, never a candidate tree."""
    from ..go.closure_plan import _snapshot
    _snapshot(repo_root)  # existing full/clean source pin and copy policy
    _require(hashlib.sha256(GO_SOURCE.read_bytes()).hexdigest()==expected_enumerator_sha256,'staged enumerator differs from pinned authority')
    _require(Path(prod_index['root']).resolve()==Path(repo_root).resolve(),'production index names a different original source')
    _require(boundary.project=='coddy-agent','wrong Go project boundary')
    ContextTable(closures,boundary=boundary,project=boundary.project)
    return _enumerate_source_copy(repo_root,go=go,go_scratch=go_scratch,closures=closures,prod_index=prod_index,
        removable_paths=[p for p,_ in boundary.removable],original_inventory=source_inventory(repo_root),evidence_dir=evidence_dir)


@contextmanager
def applied_in_copy(copy_root, row, *, go, go_scratch, contexts, original_inventory, evidence_dir):
    """Re-enumerate, apply, verify and finally restore a HOST-VISIBLE owned copy.

    This is the materialisation fixture seam. Container-only benchmark attempts
    must use remote readback/metadata/PRE guards and their own discard lifecycle.
    """
    row=_row({k:v for k,v in row.items() if k!='id'})
    root=Path(copy_root).resolve();target=root/row['file']
    out=_evidence_path(evidence_dir,root)
    _require(all(Path(c['root']).resolve()==root for c in contexts),'local apply contexts must use this copy')
    _require(source_inventory(root)==original_inventory,'applier copy does not match original authority')
    before=target.read_bytes();metadata=_metadata(target);expected=splice(before,row)
    root,scratch,_,env,_=_inputs(str(root),go,go_scratch,GO_PROD_PATHS)
    out.mkdir(parents=True,exist_ok=False)
    request={'contexts':contexts,'source_files':{p:r['sha256'] for p,r in original_inventory.items() if 'sha256' in r}}
    with tempfile.TemporaryDirectory(prefix='go-apply-',dir=scratch) as directory:
        support=Path(directory);helper=support/'mutate.go';helper.write_bytes(GO_SOURCE.read_bytes())
        request_path=support/'contexts.json';_save(request_path,request)
        argv=[go,'run','-p=1',str(helper),'--operator-profile','v2','--root',str(root),'--build-contexts',str(request_path),
              '--apply-file',row['file'],'--start-line',str(row['start_line']),'--start-col',str(row['start_col']),
              '--operator',row['operator'],'--original',row['original'],'--mutated',row['mutated'],'--out',row['file']]
        try:
            result=_invoke(argv,cwd=root,env=env,evidence=out/'apply')
            _require(result.returncode==0,'source applier refused exact descriptor')
            observed=json.loads(result.stdout)
            _require(observed.get('metadata')==metadata and observed.get('original_sha256')==hashlib.sha256(before).hexdigest()
                     and observed.get('mutated_sha256')==hashlib.sha256(expected).hexdigest(),'applier response/readback identity differs')
            _require(target.read_bytes()==expected and _metadata(target)==metadata,'applier bytes/metadata differ')
            expected_inventory=dict(original_inventory);expected_inventory[row['file']]={'sha256':hashlib.sha256(expected).hexdigest()}
            _require(source_inventory(root)==expected_inventory,'applier changed unrelated source')
            yield {'file':row['file'],'digest':hashlib.sha256(expected).hexdigest(),'original':before,'lstat':metadata}
        finally:
            _restore(target,before,metadata)
            _require(source_inventory(root)==original_inventory and _metadata(target)==metadata,'copy restoration failed')
