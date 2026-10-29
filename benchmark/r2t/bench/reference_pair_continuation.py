"""Reader of the delivered Sylius319 reference continuation aggregates.

The three Sylius319 reference observations (pull request #879) were each
collected as an interrupted 16-worker parent plus a pending-pair suffix and
delivered as one typed aggregate per role: `reference-continuation.json`,
`plan.json`, `claim.json`, `parent/` and `suffix/`.  The original rows are
immutable and the suffix is incomplete on its own; only this aggregate joins
it to the original logical observation.

Ported from the harness-21 collector line (`c5317664`, `becd09c1`,
`0d51049c`; tag `sylius319-stub-gate-waived-gold-killed-h21-v1-20260928`) for
scoring at harness 25 (EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md section 5
step 3).  Only the portable reader is here: planning, execution and assembly
of a continuation stay on that line, so a continued root opens only through
`reference_controls.load_preserved_observation`, which never reads a
producer-host path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import mutation_run as R, mutation_continuation as M
from .worker import _seed_verification_scope

SCHEMA = 'r2t.sylius319-stripped-pair-continuation/1'
CLAIM_SCHEMA = 'r2t.sylius319-stripped-pair-claim/1'
AGGREGATE_SCHEMA = 'r2t.sylius319-stripped-pair-aggregate/1'
# Historical stripped schemas remain byte-for-byte unchanged.
ROLE_SCHEMAS = {
    'stripped_gold': (SCHEMA, CLAIM_SCHEMA, AGGREGATE_SCHEMA),
    'stub': ('r2t.sylius319-stub-pair-continuation/1',
             'r2t.sylius319-stub-pair-claim/1',
             'r2t.sylius319-stub-pair-aggregate/1'),
    'full_gold': ('r2t.sylius319-full-gold-pair-continuation/1',
                  'r2t.sylius319-full-gold-pair-claim/1',
                  'r2t.sylius319-full-gold-pair-aggregate/1'),
}
ROLE_BINDINGS = {'stub': ('stub-control', 'candidate'),
                 'stripped_gold': ('assertion-stripped-gold', 'candidate'),
                 'full_gold': ('full-gold', 'gold')}
MARKER = 'reference-continuation.json'
FIELD = 'reference_pair_continuation_sha256'
PARENTS, CHILDREN, PAIRS = 16, 32, 256324
SEGMENT = {'shard', 'of', 'expected_pairs', 'expected_pairs_sha256',
           'worker_resources_sha256', FIELD}
PLAN_FIELDS = {'schema', 'plan_path', 'arguments', 'input_refs', 'scope',
    'parent_root', 'parent_plan', 'parents', 'parent_identity',
    'logical_observation_id', 'mutant_order', 'full_pairs_sha256',
    'completed_pairs', 'completed_pairs_sha256', 'partitions', 'workers',
    'worker_resources', 'collector', 'output_root'}


def require(ok, reason):
    if not ok:
        raise R.MutationAborted('REFUSED: Sylius reference continuation ' + reason)


def read(path):
    return M._read(str(path))


def ref(path):
    return M._reference(str(path))


def core(identity):
    return {k: v for k, v in identity.items() if k not in SEGMENT}


def partitions(pairs, role='stripped_gold'):
    if role == 'stub':
        from .test_quality import shard_d4_confirmation_pairs
        count = min(PARENTS, len({mid for _, mid in pairs}))
        require(count > 0, 'parent already complete; no continuation needed')
        return shard_d4_confirmation_pairs(pairs, count)
    ordered = sorted(pairs, key=lambda p: (p[1], p[0]))
    result = [set(ordered[i::CHILDREN]) for i in range(CHILDREN)]
    require(all(result), 'pending universe leaves empty child partitions')
    return result


def identity_role(identity):
    for role, (reference_role, side) in ROLE_BINDINGS.items():
        if (identity.get('reference_control_role'), identity.get('side')) == (reference_role, side):
            return role
    require(False, 'role/side is not full-gold/gold or stripped/candidate')


def plan_role(plan):
    role = identity_role(plan['parent_identity'])
    require(plan['schema'] == ROLE_SCHEMAS[role][0], 'plan schema and role differ')
    return role


def parent_identity(identity):
    R._validate_campaign_identity(identity)
    identity_role(identity)
    require(identity['schema'] == R.MUTATION_IDENTITY_SCHEMA_V5
        and identity['asset_project'] == 'sylius'
        and identity['kind'] == 'mutation-run'
        and identity['of'] == PARENTS and identity['timeout_seconds'] == 600
        and identity['sample'] is None and identity['sample_seed'] is None
        and identity['generation_provenance_class'] == R.GENERATION_PROVENANCE_REFERENCE_CONTROL
        and not set(identity) & {FIELD, 'continuation_plan_sha256', 'population_basis'},
        'requires an ordinary unsampled Sylius reference 16-worker parent')


def _check_projection(plan):
    count = len(plan['partitions'])
    require(len(plan['qualification_workers']) == PARENTS
        and len(plan['qualification_resources']) == PARENTS
        and plan['worker_mapping'] == list(range(count))
        and all(type(i) is int for i in plan['worker_mapping'])
        and plan['workers'] == plan['qualification_workers'][:count]
        and plan['worker_resources'] == plan['qualification_resources'][:count],
        'stub child projection differs from original qualification')
    require([r.get('index') for r in plan['qualification_resources']] == list(range(PARENTS)),
            'original qualification indices differ')


def _structural(plan):
    require(isinstance(plan, dict), 'plan must be an object')
    stub = plan.get('schema') == ROLE_SCHEMAS['stub'][0]
    fields = PLAN_FIELDS | ({'qualification_workers', 'qualification_resources', 'worker_mapping'} if stub else set())
    require(set(plan) == fields and plan['schema'] in {s[0] for s in ROLE_SCHEMAS.values()}, 'plan fields differ')
    parent_identity(plan['parent_identity'])
    plan_role(plan)
    count = len(plan['partitions'])
    require(len(plan['parents']) == PARENTS and len(plan['workers']) == count
        and (1 <= count <= PARENTS if stub else count == CHILDREN), 'worker counts differ')
    if stub:
        _check_projection(plan)
    require(isinstance(plan['collector'], dict) and set(plan['collector']) == {'tag', 'commit', 'tree'}, 'collector binding differs')
    require(all(isinstance(plan['collector'][key], str) and len(plan['collector'][key]) == 40
                and all(c in '0123456789abcdef' for c in plan['collector'][key])
                for key in ('commit', 'tree')), 'collector commit/tree malformed')
    require(isinstance(plan['collector']['tag'], str) and plan['collector']['tag']
            and not any(c.isspace() for c in plan['collector']['tag']), 'collector tag malformed')


def _read_segment(paths, expected, *, complete, field=None, plan_digest=None):
    """Validate preserved rows without inventing a homogeneous prefix+suffix."""
    from . import reference_controls as RC, test_quality as TQ
    root = Path(paths[0]).parent
    require(root.is_dir() and not root.is_symlink(), 'segment root is linked or absent')
    require(all(Path(p).is_file() and not Path(p).is_symlink() for p in paths), 'segment rows are linked or absent')
    outcomes, identities, facts, rows_all = {}, [], [], []
    observation = None
    for number, path in enumerate(paths):
        side = read(R.provenance_path(path)); identity = side['campaign_identity']
        R._validate_campaign_identity(identity)
        require(identity['shard'] == number and identity['of'] == len(paths), 'segment shard set differs')
        require(side['status'] in ({'complete'} if complete else {'interrupted', 'complete'}), 'parent/child is live or failed')
        require(identity.get(FIELD) == plan_digest, 'segment continuation binding differs')
        if field is None:
            parent_identity(identity)
        RC._portable_worker_preimage(side, identity)
        done = R.completed_pairs(path, identity, expected_pairs=expected[number], require_complete=complete or side['status'] == 'complete')
        require(not set(outcomes) & done, 'segment pairs overlap')
        rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
        rows_all.extend(rows)
        for row in rows:
            pair = (row['item_id'], row['mutant_id'])
            RC._excluded_terminal_outcome(row['outcome'], identity_role(identity))
            outcomes[pair] = row['outcome']
        current = R.validate_observation_id(side.get('observation_id'))
        if observation is None:
            observation = current
        require(current == observation, 'mixed segment observation IDs')
        identities.append(identity)
        facts.append({'rows_sha256': R.sha256_file(path),
                      'sidecar_sha256': R.sha256_file(R.provenance_path(path))})
    require(all(core(i) == core(identities[0]) and
        i['worker_resources_sha256'] == identities[0]['worker_resources_sha256'] for i in identities),
        'mixed segment identities')
    parent_plan = read(Path(paths[0]).parent / R.MUTATION_OUTPUT_PLAN)
    require(R._validate_standalone_output_plan(parent_plan, identities[0]) == observation, 'segment plan observation differs')
    R.validate_standalone_output_directory(paths, identities[0])
    TQ.validate_native_retry_evidence(rows_all, where='Sylius pair continuation segment')
    return {'outcomes': outcomes, 'identities': identities, 'observation_id': observation, 'files': facts}


def _expected_parents(order, universe):
    require(len(order) == len(set(order)) and set(order) == {m for _, m in universe}, 'mutant order differs from universe')
    by_mutant = {}
    for iid, mid in universe:
        by_mutant.setdefault(mid, set()).add((iid, mid))
    return [set().union(*(by_mutant[m] for m in order[i::PARENTS])) for i in range(PARENTS)]


def _check_partition(plan, universe, segment):
    require(plan['parent_identity'] == segment['identities'][0]
        and plan['logical_observation_id'] == segment['observation_id'], 'parent identity changed')
    done = set(segment['outcomes'])
    require(done <= universe and len(universe) == PAIRS and R.pair_set_digest(universe) == plan['full_pairs_sha256'], 'universe differs')
    require(len(done) == plan['completed_pairs'] and R.pair_set_digest(done) == plan['completed_pairs_sha256'], 'completed prefix differs')
    require(plan['partitions'] == [sorted(map(list, p)) for p in partitions(universe - done, plan_role(plan))], 'pending partition differs')


def validate_identity(binding, identity):
    plan = binding['plan']
    require(core(identity) == core(plan['parent_identity']) and identity['of'] == len(binding['partitions']),
        'child changes stable campaign identity')
    require(identity.get(FIELD, binding['digest']) == binding['digest'], 'child plan digest differs')
    require(identity['worker_resources_sha256'] == R.content_digest(plan['worker_resources']), 'child pool differs')
    require(type(identity.get('shard')) is int and 0 <= identity['shard'] < len(binding['partitions']), 'child shard index differs')
    expected = binding['partitions'][identity['shard']]
    require(identity['expected_pairs'] == len(expected) and identity['expected_pairs_sha256'] == R.pair_set_digest(expected), 'child pair assignment differs')
    result = {**identity, FIELD: binding['digest']}
    R._validate_campaign_identity(result)
    return result


def _resolve_local(root, entry, local):
    path = Path(root) / local
    require(not path.is_symlink() and path.is_file() and R.sha256_file(path) == entry['sha256'], 'preserved bytes differ: ' + local)
    return str(path)


@_seed_verification_scope()
def aggregate(root, *, scope, role):
    """Reopen one relocated aggregate: both segments, never a producer path."""
    from . import reference_controls as RC
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), 'aggregate root is linked or absent')
    descriptor = read(root / MARKER)
    require(set(descriptor) == {'schema', 'plan_sha256', 'claim_sha256'} and descriptor['schema'] in {s[2] for s in ROLE_SCHEMAS.values()}, 'aggregate fields differ')
    require(set(os.listdir(root)) == {MARKER, 'plan.json', 'claim.json', 'parent', 'suffix'}, 'aggregate inventory differs')
    require(R.sha256_file(root / 'plan.json') == descriptor['plan_sha256'] and
        R.sha256_file(root / 'claim.json') == descriptor['claim_sha256'], 'aggregate plan/claim changed')
    plan = read(root / 'plan.json'); _structural(plan)
    require(role == plan_role(plan), 'requested role differs from aggregate')
    _, claim_schema, aggregate_schema = ROLE_SCHEMAS[role]
    require(descriptor['schema'] == aggregate_schema, 'aggregate schema and role differ')
    side = ROLE_BINDINGS[role][1]
    require(read(root / 'claim.json') == {'schema': claim_schema, 'plan': {'path': plan['plan_path'], 'sha256': descriptor['plan_sha256']}}, 'preserved parent claim differs')
    require(getattr(scope, '_evaluation_scope', None) == plan['scope'], 'aggregate scope differs')
    universe = scope.expected_pairs
    paths = []
    for i, entry in enumerate(plan['parents']):
        p = _resolve_local(root, entry['rows'], f'parent/{side}.w{i}.jsonl')
        _resolve_local(root, entry['sidecar'], f'parent/{side}.w{i}.jsonl.provenance.json'); paths.append(p)
    _resolve_local(root, plan['parent_plan'], 'parent/' + R.MUTATION_OUTPUT_PLAN)
    parent = _read_segment(paths, _expected_parents(plan['mutant_order'], universe), complete=False)
    RC._role_check(parent['identities'][0], role, scope)
    _check_partition(plan, universe, parent)
    if role == 'stub':
        require(read(R.provenance_path(paths[0]))['worker_resources'] == plan['qualification_resources'],
                'preserved original qualification preimage differs')
    paths = [str(root / 'suffix' / f'{side}.w{i}.jsonl') for i in range(len(plan['partitions']))]
    suffix = _read_segment(paths, [set(map(tuple, p)) for p in plan['partitions']],
        complete=True, field=FIELD, plan_digest=descriptor['plan_sha256'])
    binding = {'plan': plan, 'digest': descriptor['plan_sha256'], 'partitions': [set(map(tuple, p)) for p in plan['partitions']]}
    for identity in suffix['identities']:
        validate_identity(binding, identity)
    outcomes = dict(parent['outcomes'])
    require(not set(outcomes) & set(suffix['outcomes']), 'prefix and suffix overlap')
    outcomes.update(suffix['outcomes']); require(set(outcomes) == universe, 'aggregate pair set incomplete')
    facts = {'observation_id': plan['logical_observation_id'],
        'continuation_schema': aggregate_schema, 'continuation_plan_sha256': descriptor['plan_sha256'],
        'collector': plan['collector'], 'segments': [
            {'observation_id': s['observation_id'], 'campaign_identities': s['identities'],
             'files': s['files'], 'n_pairs': len(s['outcomes'])} for s in (parent, suffix)],
        'n_rows': len(outcomes), 'n_pairs': len(outcomes), 'pairs_sha256': R.pair_set_digest(outcomes)}
    # identity is the actual immutable parent anchor, never a restamped fake
    # homogeneous campaign; facts explicitly preserve both segment identities.
    value = {'identity': plan['parent_identity'], 'outcomes': outcomes, 'facts': facts}
    return RC._seal_observation(value,
        root=str(root), portable=True, role=role, expected_pairs=universe,
        plan_path=str(root / MARKER), scope=scope)
