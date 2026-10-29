"""Native row/sidecar fixtures for the portable Sylius319 continuation reader.

The fixture builder is the harness-21 line's (`reference_pair_continuation_
selftest.py` at `987e6d4e`): a 16-shard interrupted parent, a pending-pair
suffix partitioned as the collector did, and the aggregate directory the
delivery packed.  Only the reader is exercised: collection stays on that
line.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import tempfile
from unittest.mock import patch

from . import reference_pair_continuation as P, mutation_run as R
from . import reference_controls as RC, reference_loader as RL


def write(path, doc):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, sort_keys=True) + '\n')
    return str(path)


def refused(call, needle=None):
    try:
        call()
    except (R.MutationAborted, RC.ReferenceControlsRefused) as exc:
        assert needle is None or needle in str(exc), str(exc)
    else:
        raise AssertionError('accepted invalid continuation')


def identity(pairs, shard, of, resources, role='stripped_gold'):
    return R.build_campaign_identity(asset_index_sha256='a'*64, asset_project='sylius',
        mutation_validation_sha256='b'*64, mutation_validation_class='native',
        manifest_sha256='c'*64, manifest_digest='d'*64, map_sha256='e'*64,
        release_sha256='f'*64, candidate_run_sha256='1'*64,
        candidate_generated_tests_sha256='2'*64, solution_generated_tests_sha256='2'*64,
        substrate_baseline_sha256='3'*64, worker_resources_sha256=R.content_digest(resources),
        harness_version=21, container_image_digest='sha256:'+'4'*64,
        workspace_seed_digest='5'*64, database_dump_digest='6'*64,
        applier_sha256='7'*64, expected_pairs=pairs, engine='r2t-mutate',
        engine_version='1.0', parser='fixture-parser', side=RC.ROLE_SIDE[role],
        shard=shard, of=of, timeout=600,
        generation_provenance_class=R.GENERATION_PROVENANCE_REFERENCE_CONTROL,
        reference_control_role=RC.IDENTITY_REFERENCE_ROLE[role],
        reference_source_tag='original-reference-freeze', reference_workload_digest='8'*64)


def rows_file(root, ident, pairs, resources, observation, status, outcome='passed'):
    path = str(Path(root)/f'{ident["side"]}.w{ident["shard"]}.jsonl')
    R.prepare_standalone_output_directory(path, ident, observation)
    with open(path, 'w') as f:
        for iid, mid in sorted(pairs):
            f.write(json.dumps({**R.row_identity_stamp(ident), 'item_id':iid,
                'mutant_id':mid, 'outcome':outcome, 'attempt':1,
                'retried_infrastructure':False})+'\n')
    R.write_shard_provenance(path, ident, 'running', provenance={'worker_resources':resources})
    R.write_shard_provenance(path, ident, status, provenance={'worker_resources':resources})
    return path


def fixture(root, role='stripped_gold', outcome=None):
    schema, claim_schema, aggregate_schema = P.ROLE_SCHEMAS[role]
    observation = {'stripped_gold':'a','full_gold':'d','stub':'c'}[role] * 32
    suffix_observation = {'stripped_gold':'b','full_gold':'e','stub':'f'}[role] * 32
    outcome = outcome or ('failed' if role == 'full_gold' else 'passed')
    order = [f'm{i:02}' for i in range(32)]
    universe = {(f'i{j}', mid) for mid in order for j in range(3)}
    resources = [{'index':i,'workspace':f'/parent/{i}'} for i in range(16)]
    count = 16 if role == 'stub' else 32
    child_resources = resources if role == 'stub' else [{'index':i,'workspace':f'/child/{i}'} for i in range(count)]
    parent = root/'original-parent'; child=root/'original-suffix'; out=root/'aggregate'
    expected=P._expected_parents(order,universe);done=set();paths=[];identities=[]
    for i, want in enumerate(expected):
        ident=identity(want,i,16,resources,role);identities.append(ident)
        actual=set(sorted(want)[:2]);done.update(actual)
        paths.append(rows_file(parent,ident,actual,resources,observation,'interrupted',outcome))
    parts=P.partitions(universe-done, role)
    workload={'candidate_run_sha256':'1'*64,'generated_tests_sha256':'2'*64,
        'reference_source_tag':'original-reference-freeze','reference_workload_digest':'8'*64}
    population={'id':'sylius-v2','asset_index_sha256':'a'*64,'asset_project':'sylius',
        'manifest_sha256':'c'*64,'manifest_digest':'d'*64,'map_sha256':'e'*64,
        'release_sha256':'f'*64,'engine':'r2t-mutate','engine_version':'1.0','parser':'fixture-parser'}
    scope=RC.ReferenceScope(population=population,authority={},expected_pairs=frozenset(universe),
        workloads={r:dict(workload) for r in RC.ROLES},seal=RC._SCOPE_SEAL)
    scope._evaluation_scope={'fixture':'authenticated declared scope'}
    plan_path=root/'native-plan.json'
    plan={'schema':schema,'plan_path':str(plan_path),'arguments':{'role':role},'input_refs':[],
        'scope':scope._evaluation_scope,'parent_root':str(parent),
        'parent_plan':P.ref(parent/R.MUTATION_OUTPUT_PLAN),
        'parents':[{'rows':P.ref(p),'sidecar':P.ref(R.provenance_path(p))} for p in paths],
        'parent_identity':identities[0],'logical_observation_id':observation,'mutant_order':order,
        'full_pairs_sha256':R.pair_set_digest(universe),'completed_pairs':len(done),
        'completed_pairs_sha256':R.pair_set_digest(done),
        'partitions':[sorted(map(list,p)) for p in parts], 'workers':[{'spec':{'path':f'/qualified/worker{i}.json'}} for i in range(count)],
        'worker_resources':child_resources,'collector':{'tag':'new-executor','commit':'9'*40,'tree':'0'*40},
        'output_root':str(child)}
    if role == 'stub':
        plan.update(qualification_workers=plan['workers'], qualification_resources=resources,
                    worker_mapping=list(range(count)))
    write(plan_path,plan);claim=P.M.claim_path(str(parent));write(claim,{'schema':claim_schema,'plan':P.ref(plan_path)})
    binding={'plan':plan,'digest':R.sha256_file(plan_path),'partitions':parts}
    for i,want in enumerate(parts):
        ident=P.validate_identity(binding,identity(want,i,count,child_resources,role))
        rows_file(child,ident,want,child_resources,suffix_observation,'complete',outcome)
    out.mkdir();shutil.copyfile(plan_path,out/'plan.json');shutil.copyfile(claim,out/'claim.json')
    shutil.copytree(parent,out/'parent');shutil.copytree(child,out/'suffix')
    write(out/P.MARKER,{'schema':aggregate_schema,'plan_sha256':binding['digest'],
        'claim_sha256':R.sha256_file(out/'claim.json')})
    return out,scope,plan,binding


def single_role(root):
    """One continued stripped role: what the portable reader returns and refuses."""
    out,scope,plan,binding=fixture(root)
    # Producer paths gone: the reader opens only the relocated aggregate.
    moved=root/'moved';shutil.copytree(out,moved)
    shutil.rmtree(root/'original-parent');shutil.rmtree(root/'original-suffix');(root/'native-plan.json').unlink()
    got=RC.load_preserved_observation(str(moved),role='stripped_gold',scope=scope)
    assert len(got['outcomes'])==96 and got['facts']['observation_id']=='a'*32
    assert got['identity']==plan['parent_identity']
    assert [x['n_pairs'] for x in got['facts']['segments']]==[32,64]
    assert [x['observation_id'] for x in got['facts']['segments']]==['a'*32,'b'*32]
    assert got['facts']['continuation_schema']==P.AGGREGATE_SCHEMA
    assert got['facts']['collector']['tag']=='new-executor'
    assert got['identity']['reference_source_tag']=='original-reference-freeze'
    print('  [PASS] a relocated continued role reopens as its parent identity, logical ID and both segments, without producer paths')
    assert RL._native_role_source('stripped_gold',str(moved))[1]==plan['parent_identity']
    for wrong in ('full_gold','stub'):
        refused(lambda:RC.load_preserved_observation(str(moved),role=wrong,scope=scope))
        try:
            RL._native_role_source(wrong,str(moved))
        except RC.ReferenceControlsRefused as exc:
            assert 'continued reference role differs' in str(exc), str(exc)
        else:
            raise AssertionError('binding discovery read another role')
    refused(lambda:RC.load_native_observation(str(moved),role='stripped_gold',scope=scope),'preserved reader')
    print('  [PASS] binding discovery reads the plan parent; another role and the producer-side reader refuse')
    child=str(moved/'suffix/candidate.w0.jsonl')
    refused(lambda:R.validate_native_shards([child]),'aggregate')
    refused(lambda:R.validate_publishable_generation(P.read(R.provenance_path(child))['campaign_identity'],
                                                     reference_roles={'assertion-stripped-gold'}),'aggregate')
    print('  [PASS] a suffix shard alone is never a reference observation')
    # A hash-consistent but short terminal-complete parent is not a resumable
    # prefix: the segment reader refuses it directly.
    paths=[str(moved/'parent'/f'candidate.w{i}.jsonl') for i in range(16)]
    side=Path(R.provenance_path(paths[0]));saved=side.read_bytes();doc=json.loads(saved)
    doc['status']='complete';write(side,doc)
    refused(lambda:P._read_segment(paths,P._expected_parents(plan['mutant_order'],scope.expected_pairs),
        complete=False),'missing')
    side.write_bytes(saved)
    # Byte corruption, an active or failed parent, a forged suffix identity,
    # a missing suffix row, extra evidence and a claim conflict refuse.
    parent=moved/'parent/candidate.w0.jsonl';original=parent.read_bytes();parent.write_bytes(original+b'{}\n')
    refused(lambda:RC.load_preserved_observation(str(moved),role='stripped_gold',scope=scope),'bytes differ');parent.write_bytes(original)
    for status in ('running','failed'):
        side=moved/'parent/candidate.w0.jsonl.provenance.json';old=side.read_bytes();doc=json.loads(old);doc['status']=status;write(side,doc)
        refused(lambda:RC.load_preserved_observation(str(moved),role='stripped_gold',scope=scope));side.write_bytes(old)
    side=moved/'suffix/candidate.w0.jsonl.provenance.json';old=side.read_bytes();doc=json.loads(old);doc['campaign_identity']['reference_workload_digest']='0'*64;write(side,doc)
    refused(lambda:RC.load_preserved_observation(str(moved),role='stripped_gold',scope=scope));side.write_bytes(old)
    path=moved/'suffix/candidate.w0.jsonl';old=path.read_bytes();path.write_bytes(b'')
    refused(lambda:RC.load_preserved_observation(str(moved),role='stripped_gold',scope=scope));path.write_bytes(old)
    extra=moved/'suffix/foreign';extra.write_text('x')
    refused(lambda:RC.load_preserved_observation(str(moved),role='stripped_gold',scope=scope));extra.unlink()
    claim=moved/'claim.json';old=claim.read_bytes();write(claim,{'schema':P.CLAIM_SCHEMA,'plan':{'path':'wrong','sha256':binding['digest']}})
    refused(lambda:RC.load_preserved_observation(str(moved),role='stripped_gold',scope=scope));claim.write_bytes(old)
    other=copy.copy(scope);other._evaluation_scope={'fixture':'another scope'}
    refused(lambda:RC.load_preserved_observation(str(moved),role='stripped_gold',scope=other),'scope differs')
    assert dict(RC.load_preserved_observation(str(moved),role='stripped_gold',scope=scope))==dict(got)
    print('  [PASS] corrupted, live, forged, short, extended, reclaimed or rescoped aggregates refuse')
    for key,value in [('timeout_seconds',300),('harness_version',23),('candidate_run_sha256','9'*64)]:
        ident=identity(binding['partitions'][0],0,32,plan['worker_resources']);ident[key]=value
        refused(lambda:P.validate_identity(binding,ident),'stable')
    bad=copy.deepcopy(plan);bad['partitions'][0].append(bad['partitions'][1][0])
    segment={'identities':[plan['parent_identity']],'observation_id':'a'*32,
        'outcomes':{p:'passed' for p in scope.expected_pairs-set().union(*binding['partitions'])}}
    refused(lambda:P._check_partition(bad,scope.expected_pairs,segment),'partition')
    parts=P.partitions({(f'i{i}', 'one-mutant') for i in range(65)})
    assert sorted(map(len,parts))==[2]*31+[3]
    refused(lambda:P.partitions({('i','m')}),'empty')
    print('  [PASS] a suffix identity or partition that departs from the plan refuses')


def three_roles(root):
    """All three roles continued, as the delivered #879 components are."""
    root.mkdir()
    roles = root / 'roles'; roles.mkdir()
    originals = {}; common_scope = None
    # Full gold kills every pair, and neither stripped gold nor the stub kills
    # one, so G = H = every pair; the waived gate itself is
    # reference_controls' own test.
    for role, outcome in (('full_gold', 'failed'), ('stripped_gold', 'passed'),
                          ('stub', 'passed')):
        out, scope, plan, _binding = fixture(root / role, role, outcome)
        common_scope = scope
        originals[role] = plan
        shutil.copytree(out, roles / role)
    for plan in originals.values():
        shutil.rmtree(plan['parent_root']); shutil.rmtree(plan['output_root'])
        Path(plan['plan_path']).unlink()
    observations = {role: RC.load_preserved_observation(str(roles/role), role=role, scope=common_scope)
                    for role in RC.ROLES}
    for role in RC.ROLES:
        assert observations[role]['facts']['observation_id'] == originals[role]['logical_observation_id']
        assert observations[role]['identity'] == originals[role]['parent_identity']
    workloads, identities = RL._native_role_sources(str(roles))
    assert identities == {role: originals[role]['parent_identity'] for role in RC.ROLES}
    controls = RC.sensitivity_reference_controls(
        common_scope, **observations, sensitivity='sylius_stub_gate_waived_v1',
        allow_excluded_pairs=False)
    sets = RC.reference_sets(controls)
    assert controls['pairs']['count'] == 96 and controls['sensitivity'] == 'sylius_stub_gate_waived_v1'
    assert controls['stub_gate']['eligible'] is True
    assert all(len(sets.full_gold_kills[f'i{j}']) == 32 and sets.hard_subset[f'i{j}'] == sets.full_gold_kills[f'i{j}']
               for j in range(3))
    assert {role: record['observation_id'] for role, record in controls['observations'].items()} \
        == {role: originals[role]['logical_observation_id'] for role in RC.ROLES}
    print('  [PASS] three relocated continued roles join under the labelled basis with their logical IDs')
    plan = originals['stub']
    for key, value in [('worker_mapping', [1]*16),
                       ('qualification_resources', plan['qualification_resources'][:-1])]:
        bad = copy.deepcopy(plan); bad[key] = value
        refused(lambda: P._structural(bad), 'projection')
    bad = copy.deepcopy(originals['full_gold']); bad['schema'] = P.SCHEMA
    refused(lambda: P._structural(bad), 'schema and role')
    # A small pending set maps deterministically onto original indices 0..K-1;
    # a remaining mutant is never split or chosen by its recorded outcomes.
    pairs = {('i'+str(i), 'heavy') for i in range(9)} | {('x','light')}
    parts = P.partitions(pairs, 'stub')
    assert len(parts) == 2 and sorted(map(len, parts)) == [1, 9]
    assert parts == P.partitions(set(reversed(sorted(pairs))), 'stub')
    refused(lambda: P.partitions(set(), 'stub'), 'already complete')
    print('  [PASS] the stub projection and plan schema are checked as on the collector line')


def selftest():
    with tempfile.TemporaryDirectory(prefix='r2t-reference-continuation-') as tmp, \
            patch.object(P, 'PAIRS', 96):
        root = Path(tmp)
        single_role(root / 'single')
        three_roles(root / 'triple')
    print('ALL PASS (reference_pair_continuation_selftest)')
    return 0


if __name__ == '__main__':
    raise SystemExit(selftest())
