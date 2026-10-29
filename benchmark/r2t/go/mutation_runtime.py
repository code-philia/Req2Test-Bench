"""Coordinator authority for Go mutation attempts; the shared reader stays final.

Preparation reads existing campaign/index/attribution inputs before output. Each
attempt passes original reference bytes to the normal single-copy runtime. This
module neither publishes a population nor alters retries, scoring, or controls.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import json
import posixpath
from pathlib import Path
import re
import tarfile
from types import MappingProxyType

from ..bench import seed as S
from ..data import mutation_attestation as A
from ..toolkit import mutation_go as M
from . import runtime
from .execution import _path
from .interfaces_attribution import SCHEMA, partitions
from .mutation_copy import ENGINE_PATH, REFERENCE_SOURCE


class MutationRuntimeRefused(RuntimeError):
    pass


def _require(value, message):
    if not value:
        raise MutationRuntimeRefused('REFUSED: Go mutation runtime: '+message)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def _read(root, path):
    _path(path)
    target = root/path
    _require(target.resolve().is_relative_to(root) and target.is_file(),
             'original input is absent or escapes its root: '+path)
    return target.read_bytes()


def applier_sha256(raw):
    """Admit runtime applier bytes and return their identity.

    Workers run the mutate.go their seed installed. This checkout's mutate.go
    is the catalogue builder, pinned separately by VERSIONS.yml; the two may
    differ in construction code, but never in the identity constants that
    every manifest and descriptor id carries.
    """
    text = raw.decode('utf-8', 'replace')
    differs = [name for name in ('ENGINE', 'ENGINE_VERSION', 'ENUMERATOR_REV')
               if not re.search('^const '+name+' = "'+re.escape(getattr(M, name))+'"$', text, re.M)]
    _require(not differs, 'runtime applier differs from this checkout in '+', '.join(differs))
    return _hash(raw)


def seed_applier(seed_dir):
    """Exact applier bytes installed in an already verified Go worker seed."""
    with tarfile.open(Path(seed_dir)/S.WORKSPACE_TAR, 'r:*') as archive:
        try:
            member = archive.getmember(ENGINE_PATH)
        except KeyError:
            member = None
        _require(member is not None and member.isfile(), 'worker seed installs no Go applier')
        raw = archive.extractfile(member).read()
    applier_sha256(raw)
    return raw


def installed_applier_sha256(harness):
    """Identity of the applier this worker runs: its unchanged seed copy."""
    engine_sha = applier_sha256(_read(Path(harness.root).resolve(), ENGINE_PATH))
    _require(harness.copy.original_inventory.get(ENGINE_PATH) == engine_sha,
             'immutable workspace applier differs from its seed')
    return engine_sha


def _original_hashes(inventory):
    """Use saved source identity, including links flattened by the Go seed."""
    _require(isinstance(inventory, dict) and inventory, 'missing original source inventory')
    for path in inventory:_path(path)
    def resolve(path, seen):
        _require(path not in seen, 'cyclic original source link')
        fact = inventory.get(path)
        if fact is None:
            return None  # Preserved dangling links have no materialized seed file.
        if set(fact) == {'sha256'}:
            _require(isinstance(fact['sha256'],str) and len(fact['sha256']) == 64
                     and all(c in '0123456789abcdef' for c in fact['sha256']), 'invalid original source hash')
            return fact['sha256']
        if set(fact) == {'directory'} and fact['directory'] is True:
            return None
        _require(set(fact) == {'link'} and isinstance(fact['link'],str), 'invalid original inventory entry')
        target = posixpath.normpath(posixpath.join(posixpath.dirname(path),fact['link']))
        _path(target)
        return resolve(target, seen | {path})
    return {path:digest for path in inventory if (digest := resolve(path,set())) is not None}


@dataclass(frozen=True)
class OriginalAuthority:
    """Original source/compile authority, independent of any campaign rows."""
    harness: object
    execution_copy: object
    manifest: str
    original_root: str
    source_hashes: object
    reference_files: object
    contexts: object
    engine_sha256: str
    image_id: str


@dataclass(frozen=True)
class CampaignAuthority:
    """In-memory binding to already supplied artifacts; no new provenance row."""
    harness: object
    execution_copy: object
    manifest: str
    identity: str
    original_root: str
    source_hashes: object
    reference_files: object
    contexts: object
    engine_sha256: str


def validate_campaign(manifest, identity):
    """Shared complete-manifest/identity checks, also safe for completed resume."""
    A.validate_manifest(manifest, expected_engine=M.ENGINE)
    from ..bench.mutation_run import _validate_campaign_identity
    _validate_campaign_identity(identity)
    _require(manifest['digest'] == identity['manifest_digest']
             and manifest['engine_version'] == identity['engine_version'] == M.ENGINE_VERSION
             and manifest['engine'] == identity['engine'] == M.ENGINE
             and manifest['parser'] == identity['parser'] == 'go version go1.25.0 linux/amd64'
             and manifest.get('enumerator_rev') == M.ENUMERATOR_REV
             and tuple(manifest['operators']) == M.M.OPERATORS
             and identity['asset_project'] == 'coddy-agent'
             and identity['timeout_seconds'] == 600, 'campaign engine/parser/digest/project differs')
    M.validate_build_contexts(manifest.get('go_build_contexts'))


def prepare_original(harness, manifest, artifacts, *, image_id, engine_sha256=None):
    """Join preserved originals to an already authenticated worker/image.

    Saved index roots identify the historical producer; current source bytes
    come only from the bound stripped workspace and its preserved gold.
    No candidate, campaign identity, or result row is constructed here.
    """
    A.validate_manifest(manifest, expected_engine=M.ENGINE)
    _require(manifest['engine_version'] == M.ENGINE_VERSION
             and manifest['parser'] == 'go version go1.25.0 linux/amd64'
             and manifest.get('enumerator_rev') == M.ENUMERATOR_REV
             and tuple(manifest['operators']) == M.M.OPERATORS,
             'original manifest engine/parser/revision differs')
    M.validate_build_contexts(manifest.get('go_build_contexts'))
    return _prepare_original(harness, manifest, artifacts, image_id=image_id,
                             engine_sha256=engine_sha256)


def original_source_metadata(closures, index, attribution, manifest, boundary, *, image_id):
    """Join saved original identities without a compiler or producer filesystem.

    Bundle admission and live preparation share this metadata contract. Callers
    still verify every returned source hash against preserved seed/gold bytes.
    """
    _require(boundary.project == 'coddy-agent', 'original source belongs to another project')
    _require(isinstance(image_id, str) and image_id.startswith('sha256:')
             and len(image_id) == 71 and all(c in '0123456789abcdef' for c in image_id[7:]),
             'missing authenticated original worker image')
    groups, contexts = partitions(closures, index)
    _require(attribution.get('schema') == SCHEMA and attribution.get('contexts') == contexts
             and len(attribution.get('partitions', [])) == len(groups),
             'original attribution and closure/index contexts differ')
    original_root = attribution['source_root']
    _require(isinstance(original_root,str) and original_root
             and index['root'] == attribution.get('root',original_root) == original_root
             and index.get('image_id') == attribution.get('image_id') == image_id,
             'preserved original source/image identities differ')
    hashes = _original_hashes(attribution['source_inventory'])
    records = {}; builds = []
    for context_row in contexts:
        context = context_row['go_suite']; answers = tuple(context_row['answer_files'])
        production = tuple(context_row['files'])
        _require(list(production) == sorted(set(production)) and all(
            path in hashes and boundary.classify(path) == 'production' for path in production),
            'original index production membership differs from source/boundary')
        fact = attribution['partitions'][context_row['partition']]
        _require(fact.get('compiled_package_name') == context['package_name']
                 and isinstance(fact.get('source_files'), dict) and fact['source_files'],
                 'original attribution lacks its selected compiled sources')
        for path, digest in fact['source_files'].items():
            _require(hashes.get(path) == digest, 'typed attribution source differs: '+path)
        _require(all(path in hashes and boundary.classify(path) == 'removable'
                     for path in answers), 'selected answer lacks complete original gold authority')
        records[(context['feature_path'],context['scenario_line'])] = (_canonical(context),answers,production)
        builds.append({'package_dir':context['package_dir'], 'go_build_tags':context['go_build_tags'],
                       'production_files':list(production)})
    _require(M._context_union(builds) == manifest['go_build_contexts'],
             'manifest build contexts differ from complete original index membership')
    return original_root, hashes, records


def _prepare_original(harness, manifest, artifacts, *, image_id, engine_sha256):
    harness.verify_substrate()
    _require(not harness.expected_mutations and harness.copy._state == 'idle',
             'original workspace must remain unmutated and copy idle')
    artifacts = Path(artifacts).resolve()
    documents = {}
    for name in ('closures.json','go_prod_index.json','go_interface_attribution.json'):
        documents[name] = json.loads(_read(artifacts, name))
    closures, index, attribution = (documents[name] for name in
        ('closures.json','go_prod_index.json','go_interface_attribution.json'))
    original_root, hashes, records = original_source_metadata(
        closures, index, attribution, manifest, harness.boundary, image_id=image_id)
    for closure in closures:
        harness.check_context(closure)
    workspace = Path(harness.root).resolve()
    seed = harness.copy.original_inventory
    files = {}
    gold = Path(harness.manifest.gold_root).resolve()
    for path, digest in hashes.items():
        if harness.boundary.classify(path) == 'removable':
            raw = _read(gold, path)
            _require(path in harness.manifest.moved and _hash(raw) == digest,
                     'original answer differs from preserved strip/gold: '+path)
            files[path] = raw
        else:
            _require(seed.get(path) == digest, 'reference nonremovable source differs from original seed: '+path)
            raw = _read(workspace,path)
            _require(_hash(raw) == digest, 'current original workspace changed: '+path)
            files[path] = raw
    engine_sha = installed_applier_sha256(harness)
    _require(engine_sha256 is None or engine_sha256 == engine_sha,
             'seed-installed applier differs from the campaign applier identity')
    return OriginalAuthority(harness,harness.copy,_canonical(manifest),original_root,
        MappingProxyType(hashes),MappingProxyType(files),MappingProxyType(records),engine_sha,image_id)


def prepare_campaign(harness, manifest, identity, artifacts):
    """Bind the original join to the existing campaign identity before output."""
    validate_campaign(manifest, identity)
    _require(harness.boundary.project == identity['asset_project'], 'campaign belongs to another project')
    original = _prepare_original(harness, manifest, artifacts,
        image_id=identity['container_image_digest'], engine_sha256=identity['applier_sha256'])
    return CampaignAuthority(harness,harness.copy,original.manifest,_canonical(identity),
        original.original_root,original.source_hashes,original.reference_files,
        original.contexts,original.engine_sha256)


def run_solution(harness, feature, scenario, solution, *, mutant, manifest, identity,
                 authority, evidence_dir, timeout=600, keep_stdout=False):
    """One existing permitted attempt, with fresh reference application inside."""
    _require(isinstance(authority, CampaignAuthority) and authority.harness is harness
             and authority.execution_copy is harness.copy, 'campaign authority belongs to another harness/copy')
    _require(_canonical(manifest) == authority.manifest and _canonical(identity) == authority.identity,
             'campaign authority changed after validation')
    _require(timeout == identity['timeout_seconds'] and type(timeout) is int and timeout == 600,
             'mutation attempt must retain the shared timeout')
    matches = [row for row in manifest['mutants'] if row.get('id') == mutant.get('id')]
    _require(matches == [mutant], 'selected descriptor differs from complete validated manifest')
    context = runtime._context(harness, feature, scenario)
    key = context['feature_path'], context['scenario_line']
    _require(key in authority.contexts, 'selected item lacks original mutation context')
    encoded, answers, production = authority.contexts[key]
    _require(_canonical(context) == encoded and tuple(harness.contexts.files_for(*key)) == answers
             and mutant['file'] in production, 'selected item/target differs from original index context')
    workspace = Path(harness.root).resolve()
    for path, raw in authority.reference_files.items():
        if harness.boundary.classify(path) != 'removable':
            _require(harness.copy.original_inventory.get(path) == authority.source_hashes[path]
                     and _read(workspace,path) == raw, 'current original source changed after preparation: '+path)
    gold = Path(harness.manifest.gold_root).resolve()
    for path in answers:
        _require(_read(gold,path) == authority.reference_files[path], 'preserved original answer changed: '+path)
    reference = {path:raw for path,raw in authority.reference_files.items()
                 if harness.boundary.classify(path) != 'removable' or path in answers}
    descriptor = deepcopy(mutant)
    M.splice(reference[descriptor['file']], {k:v for k,v in descriptor.items() if k != 'id'})
    request = {'descriptor':descriptor, 'reference_files':reference, 'engine_sha256':authority.engine_sha256,
        'engine_request':{'contexts':[{'root':REFERENCE_SOURCE, 'package_dir':context['package_dir'],
            'package_name':context['package_name'], 'glue_path':context['glue_path'],
            'go_build_tags':context['go_build_tags']}],
            'source_files':{path:_hash(raw) for path,raw in reference.items()}}}
    evidence = Path(evidence_dir).resolve()
    for protected in (workspace,gold):
        _require(not evidence.is_relative_to(protected) and not protected.is_relative_to(evidence),
                 'attempt evidence and protected original/gold must be disjoint')
    if evidence.exists():
        _require(evidence.is_dir() and not any(evidence.iterdir()), 'attempt evidence directory is not empty')
    else:
        evidence.mkdir(parents=True)
    def save(name, document):
        with (evidence/name).open('x',encoding='utf-8') as stream:
            json.dump(document,stream,indent=2,sort_keys=True);stream.write('\n')
    save('request.json', {'manifest_digest':manifest['digest'],'campaign_identity':identity,
        'descriptor':descriptor,'go_suite':context,'engine_request':request['engine_request'],
        'engine_sha256':authority.engine_sha256,'original_root':authority.original_root})
    save('solution.json',asdict(solution))
    native = evidence/'native'
    native.mkdir()
    try:
        result = runtime.run_solution(harness,feature,scenario,solution,coverage=False,timeout=timeout,
            repeats=1,task='criterion_to_test',keep_stdout=keep_stdout,mutation=request,
            evidence_dir=native)
    except BaseException as error:
        save('failure.json', {'type':type(error).__name__,'message':str(error),
            'commands':deepcopy(getattr(harness.copy,'command_evidence',[])),
            'mutation':deepcopy(getattr(harness.copy,'mutation_evidence',None))})
        raise
    save('result.json',result)
    return result
