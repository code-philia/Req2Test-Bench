"""Resolve reviewed target declarations to the shared source-view builder.

Input maps are operator artifacts, kept separate from implementation PRs.
They record principal/delegation decisions; the interface extractor does not
make those decisions. This module resolves named bodies, never guesses them.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path

from ..core.ledger_primitives import domain_digest, loads_exact_json, ordered_item_ids_digest
from ..core.source_view import (
    ContractFile, ItemSelection, RepairEntry, Selection, SourceSeed, TargetMap, ViewPolicy,
    ViewRefused, build_agent_view, parse_generated_operation_judgments, parse_repair_set,
    parse_zero_body_treatment, plan_agent_view, qualify_source_seed,
)

MAP_SCHEMA = 'r2t.target-body-map/v1'
#: v2: target-hidden views carry the reviewed repairs pinned below
#: (BENCHMARK_V2_SPEC section 3.3).  Benchmark 1.x views were built by
#: `r2t.target-source-view/v1`, at the tag `FSE-2027-submission`.
TRANSFORMER = 'r2t.target-source-view/v2'
#: The sha256 of each project's reviewed repair index,
#: `maps/<project>/th-view-repairs/index.json` (BENCHMARK_V2_SPEC sections 3.1
#: and 3.2).  The pins are part of `TRANSFORMER`: changing repair data needs a
#: reviewed change here and a new transformer version (section 8.3).
REPAIR_INDEX_SHA256 = {
    'algorand-sdk': '836c832be3bc745abd83c087a09d881f89970d0138b0969816d3eea4698f5a23',
    'coddy-agent': 'bfc5ff472ee171cb70d4aeb1c9ba73af5bf258d5307c2b5add149e926d587609',
    'coreshop': '4bd4acc2b28bbc327a705725205f722e67a9fcb5e9019f24ba5a3b7c4706292c',
    'e-petitions': '007dd585a4f2ee27e8ddc47677aba6f0370c39f8ba7e77914fd044abdb155da3',
}
#: The repair sets are found here, by project, whatever map path a build is
#: given (Algorand SDK's map comes from a release, PrestaShop's from a kit).
REPAIRS_ROOT = Path(__file__).resolve().parents[3] / 'maps'
REPAIRS_DIR = 'th-view-repairs'


def load_repairs(project):
    """`(index sha256, entries)` of the project's pinned repair set, or
    `(None, ())` for a project without one.

    Refused: a pinned set that is missing, an index whose sha256 is not the
    pinned value, an index for a project with no pin, and every defect
    `parse_repair_set` refuses (a blob whose sha256 is not its name, two
    entries for one view file).
    """
    directory = REPAIRS_ROOT / project / REPAIRS_DIR
    index = directory / 'index.json'
    pinned = REPAIR_INDEX_SHA256.get(project)
    if pinned is None:
        if os.path.lexists(index):
            raise ViewRefused(f'{index}: no pinned sha256 for {project} repairs')
        return None, ()
    try:
        raw = index.read_bytes()
    except OSError as exc:
        raise ViewRefused(f'{project}: pinned repair index unreadable: {exc}') from exc
    digest = hashlib.sha256(raw).hexdigest()
    if digest != pinned:
        raise ViewRefused(f'{index}: sha256 {digest} is not the pinned {pinned}')

    def blob(sha):
        try:
            return (directory / 'blobs' / sha).read_bytes()
        except OSError as exc:
            raise ViewRefused(f'{project}: repair blob {sha} unreadable: {exc}') from exc
    return digest, parse_repair_set(loads_exact_json(raw, label='repair index'), blob)


#: Per map schema: the item key carrying the interface annotation, and the
#: domain its digest is taken under.  Two schemas, one loader, because the v1
#: maps stay resolvable for the identities their recorded rows and manifests
#: already carry (TARGET_INTERFACES_V2_SPEC section 7a); everything else in a
#: map -- subjects, bodies, principals, delegation, judgments, contracts -- is
#: the same artifact under both, so this is one branch, not a second reader.
MAP_SCHEMAS = {MAP_SCHEMA: ('target_interfaces', 'r2t.visibility-interfaces/v1'),
               'r2t.target-body-map/v2': ('checked_interfaces',
                                          'r2t.visibility-interfaces/v2')}


def _closed(value, keys, where, optional=()):
    if not isinstance(value, dict) or not set(keys) <= set(value) <= set(keys) | set(optional):
        raise ViewRefused(f'{where}: expected exactly {sorted(keys)}')
    return value


def _annotation(field, item, where):
    """Validate one item's interface annotation and return it.

    The v2 annotation is checked by the PROMPT's own renderer -- the single
    function the released row must survive -- so a map and a row cannot
    disagree about shape, order or the empty-list reason while both pass.  The
    v1 branch keeps the two-string-list check it has always applied: those
    maps are reviewed artifacts whose recorded manifests were derived under
    exactly this rule, and the renderer's extra sorted/disjoint requirements
    would be a new refusal against bytes that are already evidence.
    """
    value = item[field]
    if field == 'target_interfaces':
        annotation = _closed(value, ('behaviour', 'setup'), 'target interfaces')
        if any(not isinstance(v, list) or any(not isinstance(s, str) for s in v)
               for v in annotation.values()):
            raise ViewRefused('target annotations must be two string lists')
        return annotation
    from types import SimpleNamespace
    from ..data.profile import ProfileError
    from ..data.prompt import ANNOTATION_BLOCKS
    try:
        ANNOTATION_BLOCKS[field](item, SimpleNamespace(path=where))
    except ProfileError as exc:
        # `ProfileError` exits a process; a map defect is a view refusal.
        raise ViewRefused(f'{field} annotation the prompt would refuse: {exc}') from exc
    return value


def _java_tools(java, javac):
    if any(not isinstance(tool, str) or not Path(tool).is_absolute()
           for tool in (java, javac)):
        raise ViewRefused('Java source views require explicit absolute java/javac paths')
    return {'java': java, 'javac': javac}


def java_tools_from_environment():
    """Ordinary launch input; library callers pass their explicit pair instead."""
    import os
    home = os.environ.get('JAVA_HOME')
    if not home or not Path(home).is_absolute():
        raise ViewRefused('Java source views require an explicit absolute JAVA_HOME')
    return {'java': str(Path(home) / 'bin/java'), 'javac': str(Path(home) / 'bin/javac')}


def go_tools_for_release(release_rows, scratch, go=None):
    """Bind the existing Go parser to explicit coordinator tools and released contexts."""
    import os
    go = go if go is not None else os.environ.get('R2T_SOURCE_VIEW_GO')
    if not isinstance(go, str) or not Path(go).is_absolute():
        raise ViewRefused('Go source views require an absolute R2T_SOURCE_VIEW_GO or --go')
    from ..go.source_view import _context
    contexts = {}
    for row in release_rows:
        item_id = row['item_id']
        if item_id in contexts:
            raise ViewRefused(f'duplicate Go release item: {item_id}')
        contexts[item_id] = _context(row.get('go_suite'))
    if not contexts:
        raise ViewRefused('Go source views require a nonempty selected release')
    return {'go': go, 'go_contexts': contexts, 'go_scratch': scratch}


def source_bodies(path: str, raw: bytes, *, java=None, javac=None,
                  go=None, go_context=None, go_scratch=None):
    if path.endswith('.go'):
        from ..go.source_view import source_bodies as bodies
        return bodies(path, raw, go=go, go_context=go_context, go_scratch=go_scratch)
    if path.endswith('.java'):
        from ..java.source_view import source_bodies as bodies
        return bodies(path, raw, **_java_tools(java, javac))
    if path.endswith('.py'):
        from ..py.source_view import source_bodies as bodies
    elif path.endswith('.php'):
        from ..php.source_view import source_bodies as bodies
    elif path.endswith('.rb'):
        from ..ruby.source_view import source_bodies as bodies
    else:
        raise ViewRefused(f'no body parser for {path}; use reviewed contract_only omission')
    return bodies(path, raw)


def parse_source(path: str, raw: bytes, *, java=None, javac=None,
                 go=None, go_context=None, go_scratch=None):
    if path.endswith('.go'):
        from ..go.source_view import parse_source as parse
        return parse(path, raw, go=go, go_context=go_context, go_scratch=go_scratch)
    if path.endswith('.java'):
        from ..java.source_view import parse_source as parse
        return parse(path, raw, **_java_tools(java, javac))
    if path.endswith('.py'):
        from ..py.source_view import parse_source as parse
    elif path.endswith('.php'):
        from ..php.source_view import parse_source as parse
    elif path.endswith('.rb'):
        from ..ruby.source_view import parse_source as parse
    else:
        raise ViewRefused(f'no source parser for transformed file: {path}')
    return parse(path, raw)


@dataclass(frozen=True)
class PreparedView:
    seed: SourceSeed
    mapping: TargetMap
    policy: ViewPolicy
    annotations: dict
    #: The task field these annotations ARE: the map schema decides whether a
    #: row is admitted on its v1 `target_interfaces` or its v2
    #: `checked_interfaces`, and nothing may compare one to the other.
    annotation_field: str
    map_file_sha256: str
    java: str | None = None
    javac: str | None = None
    go: str | None = None
    go_contexts: dict | None = None
    go_scratch: str | None = None
    #: The project's pinned repair set (`load_repairs`), applied to
    #: target-hidden views only.
    repair_index_sha256: str | None = None
    repairs: tuple[RepairEntry, ...] = ()

    @property
    def identity(self):
        return {'schema': 'r2t.visibility-run/v1',
                'source_files_digest': self.seed.files_digest,
                'runtime_seed_digest': self.seed.runtime_seed_digest,
                'map_digest': self.mapping.digest,
                'map_file_sha256': self.map_file_sha256,
                'policy_digest': self.policy.digest,
                'population_digest': self.mapping.population_digest,
                'interfaces_digest': self.mapping.interfaces_digest,
                'scope': self.policy.scope, 'feedback': self.policy.feedback}

    def plan(self, task):
        item_id = task.get('item_id')
        if item_id not in self.annotations \
                or task.get(self.annotation_field) != self.annotations[item_id]:
            raise ViewRefused(f'task interfaces differ from the reviewed map: {item_id}')
        if self.go_contexts is not None:
            from ..go.source_view import _context
            if _context(task.get('go_suite')) != self.go_contexts.get(item_id):
                raise ViewRefused(f'task Go context differs from the reviewed map: {item_id}')
        return plan_agent_view(source_seed=self.seed, item_id=item_id,
                               policy=self.policy, target_map=self.mapping,
                               repairs=_scope_repairs(self.policy.scope, self.repairs))

    def materialize(self, task, destination, applied=None):
        """Build the task's view and parse its transformed files.  With
        `applied`, the repair entries that applied are appended to it."""
        plan = self.plan(task)
        if self.go_scratch is not None:
            _outside_go_scratch(self.go_scratch, destination)
        manifest = build_agent_view(plan, destination=destination, applied=applied)
        # Check precisely the capability promised for transformed source.
        paths = sorted({e.body.path for e in plan.selection.bodies})
        java_sources = {path: (Path(destination) / path).read_bytes()
                        for path in paths if path.endswith('.java')}
        if java_sources:
            from ..java.source_view import parse_sources
            parse_sources(java_sources, **_java_tools(self.java, self.javac))
        for path in paths:
            if path not in java_sources:
                parse_source(path, (Path(destination) / path).read_bytes(),
                             java=self.java, javac=self.javac, go=self.go,
                             go_context=(self.go_contexts or {}).get(task.get('item_id')),
                             go_scratch=self.go_scratch)
        return manifest


def _scope_repairs(scope, repairs):
    """Repairs belong to target-hidden views; `full` and `all_hidden` get none."""
    return repairs if scope == 'target_hidden' else ()


def _outside_go_scratch(scratch, readable_root):
    if not isinstance(scratch, str) or not Path(scratch).is_absolute():
        raise ViewRefused('Go source views require explicit absolute trusted scratch')
    root, support = Path(readable_root).resolve(), Path(scratch).resolve()
    if root == support or root in support.parents or support in root.parents:
        raise ViewRefused('Go helper scratch and readable source/view must be disjoint')


def prepare_view(*, source_root: str, readable_paths: tuple[str, ...],
                 project: str, runtime_seed_digest: str, map_path: str,
                 scope: str, profile_digest: str, protocol_digest: str,
                 boundary_digest: str, java: str | None = None,
                 javac: str | None = None, go: str | None = None,
                 go_contexts: dict | None = None, go_scratch: str | None = None) -> PreparedView:
    if project not in ('coreshop', 'python-docx', 'algorand-sdk', 'sylius', 'kapua',
                       'prestashop', 'e-petitions', 'coddy-agent'):
        raise ViewRefused(f'{project}: target localization/source-view admission is not implemented')
    if project in ('algorand-sdk', 'kapua'):
        _java_tools(java, javac)  # required even for full or omission-only maps
    repair_index_sha256, repairs = load_repairs(project)
    seed = qualify_source_seed(root=source_root, project=project,
                               runtime_seed_digest=runtime_seed_digest,
                               readable_paths=readable_paths)
    raw = Path(map_path).read_bytes()
    doc = _closed(loads_exact_json(raw, label='target body map'),
                  ('schema', 'project', 'runtime_seed_digest', 'source_files_digest',
                   'subject_paths', 'items', 'contracts', 'all_file_rules'), 'target body map')
    if doc['schema'] not in MAP_SCHEMAS or doc['project'] != project \
            or doc['runtime_seed_digest'] != runtime_seed_digest \
            or doc['source_files_digest'] != seed.files_digest:
        raise ViewRefused('target body map is not bound to this runtime/source/project')
    annotation_field, interfaces_domain = MAP_SCHEMAS[doc['schema']]
    if not isinstance(doc['subject_paths'], list) or not isinstance(doc['items'], list) \
            or not isinstance(doc['contracts'], list) \
            or (doc['all_file_rules'] is not None and not isinstance(doc['all_file_rules'], list)):
        raise ViewRefused('target body map inventories must be lists, or null for all_file_rules')
    subjects = set(doc['subject_paths'])
    if len(subjects) != len(doc['subject_paths']):
        raise ViewRefused('duplicate subject path')
    files = {f.path for f in seed.files}
    if not subjects <= files:
        raise ViewRefused('subject inventory contains absent files')
    has_go = any(path.endswith('.go') for path in subjects)
    contexts = None
    if not has_go and go_contexts is not None:
        raise ViewRefused('released Go contexts supplied without Go source-map subjects')
    if has_go:
        from ..go.source_view import _context, _tools
        if not isinstance(go_contexts, dict) or not go_contexts:
            raise ViewRefused('Go source maps require released per-item suite contexts')
        contexts = {item_id: _context(context) for item_id, context in go_contexts.items()}
        _outside_go_scratch(go_scratch, source_root)
        _tools(go, go_scratch)
    parsed = {}
    annotations = {}
    items = []
    for item in doc['items']:
        _closed(item, ('item_id', annotation_field, 'principals', 'bodies',
                       'omitted_paths', 'delegation', 'generated_operation_judgments'),
                'target body map item', optional=('zero_body_treatment',))
        item_id = item['item_id']
        if not isinstance(item_id, str) or not item_id or item_id in annotations:
            raise ViewRefused('empty or duplicate visibility item ID')
        context = None
        if has_go:
            context = contexts.get(item_id)
            if context is None:
                raise ViewRefused(f'map item lacks its released Go context: {item_id}')
        annotation = _annotation(annotation_field, item, map_path)
        for key in ('principals', 'bodies', 'omitted_paths', 'delegation'):
            if not isinstance(item[key], list):
                raise ViewRefused(f'item {key} must be a list')
        if not item['principals'] or any(not isinstance(p, str) or not p for p in item['principals']):
            raise ViewRefused(f'principal localization is unresolved: {item_id}')
        for edge in item['delegation']:
            _closed(edge, ('from', 'to', 'evidence', 'decision'), 'delegation edge')
            if any(not isinstance(v, str) or not v for v in edge.values()):
                raise ViewRefused('delegation decisions require nonempty source evidence')
        judgments = parse_generated_operation_judgments(item['generated_operation_judgments'])
        zero_body_treatment = (parse_zero_body_treatment(item['zero_body_treatment'])
                               if 'zero_body_treatment' in item else None)
        if zero_body_treatment is not None and not item['delegation']:
            raise ViewRefused('zero-body treatment requires reviewed delegation evidence')
        edits = []
        for body in item['bodies']:
            _closed(body, ('path', 'declaration_id', 'kind'), 'target body')
            path = body['path']
            if path not in subjects:
                raise ViewRefused(f'target body is outside subject inventory: {path}')
            if path.endswith('.go'):
                # No path-only cache: every item resolves its actual qualified
                # bytes with its own explicit context and toolchain.
                from ..core.source_view import _source_bytes
                record = next(record for record in seed.files if record.path == path)
                resolved = source_bodies(path, _source_bytes(seed, record),
                    go=go, go_context=context, go_scratch=go_scratch)
            else:
                if path not in parsed:
                    parsed[path] = source_bodies(path, (Path(source_root) / path).read_bytes(),
                                                 java=java, javac=javac)
                resolved = parsed[path]
            matches = [e for e in resolved
                       if e.body.declaration_id == body['declaration_id'] and e.body.kind == body['kind']]
            if len(matches) != 1:
                raise ViewRefused(f'no unique concrete body: {path}: {body["declaration_id"]} ({body["kind"]})')
            edits.append(matches[0])
        if not edits and not item['omitted_paths'] and zero_body_treatment is None:
            raise ViewRefused(f'target body localization is empty: {item_id}')
        annotations[item_id] = annotation
        items.append(ItemSelection(item_id, tuple(item['principals']),
                                   Selection(tuple(edits), tuple(item['omitted_paths'])), judgments,
                                   zero_body_treatment))
    if contexts is not None and set(contexts) != set(annotations):
        raise ViewRefused('released Go contexts must exactly cover the source-map items')
    # Derived from the resolved map, never copied from it: a digest the file
    # carries and the code recomputes states the same fact twice, and the map
    # is a reviewed artifact whose bytes this run already hashes.
    population_digest = ordered_item_ids_digest(i.item_id for i in items)
    interfaces_digest = domain_digest(interfaces_domain,
        [{'item_id': i.item_id, annotation_field: annotations[i.item_id]} for i in items])
    contracts = []
    for contract in doc['contracts']:
        _closed(contract, ('path', 'content', 'sources'), 'contract supplement')
        if not isinstance(contract['content'], str) or not isinstance(contract['sources'], list) \
                or not contract['sources'] or any(not isinstance(s, str) or not s for s in contract['sources']):
            raise ViewRefused('contract supplement needs text and source citations')
        contracts.append(ContractFile(contract['path'], contract['content'].encode('utf-8')))
    if 'TARGET_CONTRACTS.md' not in {contract.path for contract in contracts}:
        raise ViewRefused('source-view profile requires the common TARGET_CONTRACTS.md supplement')
    mapping = TargetMap(project, seed.files_digest, population_digest,
                        interfaces_digest, tuple(items), tuple(contracts))
    policy = ViewPolicy(project, scope, profile_digest, protocol_digest,
                        boundary_digest, tuple(doc['subject_paths']), TRANSFORMER)
    if doc['all_file_rules'] is not None:
        # `null` means all-hidden is unavailable for this map and never
        # resolves a body; a list -- `[]` included -- approves it and every
        # subject path either names its contract-only omission here or is
        # resolved by the shared body parser.
        from .source_view_all import ProductionFileRule, select_all_production
        from .source_view_all import TRANSFORMER as all_transformer
        rules = []
        for rule in doc['all_file_rules']:
            _closed(rule, ('path', 'contract_paths'), 'all-production file rule')
            if not isinstance(rule['path'], str) or not isinstance(rule['contract_paths'], list) \
                    or any(not isinstance(path, str) for path in rule['contract_paths']):
                raise ViewRefused('all-production file rules require a path and contract paths')
            rules.append(ProductionFileRule(rule['path'], tuple(rule['contract_paths'])))
        # Go all-production inventory is independent of active membership:
        # one validated suite context suffices because no Go file is filtered.
        # Resolve once for every scope. The common map/annotations/contracts
        # keep one identity; only the selected scope changes the materialization.
        mapping = replace(mapping, all_selection=select_all_production(
            source_seed=seed, policy=policy, file_rules=tuple(rules), contracts=tuple(contracts),
            java=java, javac=javac, go=go,
            go_context=next(iter(contexts.values())) if contexts else None,
            go_scratch=go_scratch))
        policy = replace(policy, transformer=TRANSFORMER + '+' + all_transformer)
    prepared = PreparedView(seed, mapping, policy, annotations, annotation_field,
                            hashlib.sha256(raw).hexdigest(),
                            java, javac, go, contexts, go_scratch,
                            repair_index_sha256, repairs)
    # Resolve all declared items before generation, never turn admission errors
    # into per-item model failures. Full also validates the shared target map.
    for item in items:
        for candidate_scope in set((scope, 'target_hidden')):
            plan_agent_view(source_seed=seed, item_id=item.item_id,
                            policy=replace(policy, scope=candidate_scope), target_map=mapping,
                            repairs=_scope_repairs(candidate_scope, repairs))
    return prepared


def main(argv=None):
    """Materialize one reviewed view without an agent or execution service."""
    import argparse
    import json
    from ..bench import protocol_file, worker
    from ..data.profile import load_profile
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ('source-root', 'map', 'profile', 'protocol', 'seed', 'item', 'out', 'manifest'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--release', help='selected release JSONL; required for Go views')
    parser.add_argument('--go', help='absolute qualified coordinator Go executable')
    parser.add_argument('--go-scratch', help='absolute trusted scratch outside source and view')
    args = parser.parse_args(argv)
    profile = load_profile(args.profile)
    protocol = protocol_file.load(args.protocol)
    if profile.source_visibility is None or protocol.get('visibility') != profile.raw.get('visibility') \
            or protocol['prompt_profile']['prompt_digest'] != profile.prompt_digest \
            or protocol['condition'] not in ('c2', 'c2r') or protocol.get('trials') != 0:
        raise ViewRefused('profile/protocol do not agree on final-only source visibility')
    manifest_path = Path(args.manifest).absolute()
    out = Path(args.out).absolute()
    if manifest_path.exists() or manifest_path == out or out in manifest_path.parents:
        raise ViewRefused('manifest must be absent and outside the agent view')
    tools = java_tools_from_environment() if profile.project in ('algorand-sdk', 'kapua') else {}
    release_rows = None
    if profile.project == 'coddy-agent':
        if not args.release or not args.go_scratch:
            raise ViewRefused('Go source-view CLI requires --release and --go-scratch')
        from ..bench.runner import _load_release
        release_rows = _load_release(args.release)
        tools = go_tools_for_release(release_rows, args.go_scratch, args.go)
    runtime = worker.verified_seed_identity(args.seed, profile.needs_database)
    prepared = prepare_view(source_root=args.source_root, readable_paths=profile.readable_paths,
        project=profile.project, runtime_seed_digest=runtime['workspace_seed_digest'],
        map_path=args.map, scope=profile.source_visibility, profile_digest=profile.digest,
        protocol_digest=hashlib.sha256(Path(protocol_file.path_for(args.protocol)).read_bytes()).hexdigest(),
        boundary_digest=hashlib.sha256(Path(profile.boundary_path).read_bytes()).hexdigest(), **tools)
    task = {'item_id': args.item,
            prepared.annotation_field: prepared.annotations.get(args.item)}
    if release_rows is not None:
        if [i.item_id for i in prepared.mapping.items] != [r['item_id'] for r in release_rows]:
            raise ViewRefused('visibility map does not cover the complete selected release in order')
        for row in release_rows:
            prepared.plan(row)
        task = next((row for row in release_rows if row['item_id'] == args.item), None)
        if task is None:
            raise ViewRefused('requested item is absent from selected release')
    manifest = prepared.materialize(task, str(out))
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open('x') as stream:
        json.dump(manifest, stream, sort_keys=True, indent=1)
        stream.write('\n')
    print(json.dumps({'item_id': args.item, 'scope': profile.source_visibility,
                      'view': str(out), 'manifest': str(manifest_path), 'digest': manifest['digest']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
