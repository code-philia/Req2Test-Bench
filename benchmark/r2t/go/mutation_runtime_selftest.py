"""Coordinator joins and real shared Go metadata validation with local fixtures.

No native subject execution, canonical rows or completed mutation leg is claimed.
"""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ..bench import mutation_run as MR
from ..bench.harness import Solution
from ..core.boundary import Boundary
from ..core.gherkin import parse_feature_file
from ..data import mutation as D
from ..data import mutation_attestation as A
from . import mutation_runtime as R
from . import mutation_copy as C
from .context import ContextTable
from .interfaces_attribution import SCHEMA, partitions
from .prod_index_selftest import suite, closure
from .prod_index_entry import source_inventory


class MutationRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='go-mutation-runtime-');self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.root=self.base/'worker';self.gold=self.base/'gold';self.artifacts=self.base/'artifacts'
        for path in (self.root,self.gold,self.artifacts):path.mkdir()
        self.contexts=[suite('first'),suite('second',glue='bdd_second_test.go')]
        self.helper='internal/check/bdd_helper_test.go';self.target='internal/lib/value.go'
        self.closures=[closure(c,sorted([c['glue_path'],self.helper])) for c in self.contexts]
        self.answers={p for row in self.closures for p in row['files']}
        self.originals={'go.mod':b'module fixture\n','go.sum':b'',self.target:b'package lib\nfunc Value() bool { return true }\n',
            'internal/lib/data/value.txt':b'required embedded resource\n','internal/check/retained_test.go':b'package check\n'}
        for c in self.contexts:
            self.originals[c['feature_path']]=b'Feature: fixture\n\nScenario: selected\n Given fixture\n'
            self.originals[c['glue_path']]=b'package check\n// original imports lib\n'
        self.originals[self.helper]=b'package check\n// original shared helper\n'
        source=self.base/'producer';source.mkdir()
        for p,raw in self.originals.items():self.write(source/p,raw)
        inventory=source_inventory(source)
        # Persist historical absolute producer identity; actual directory goes away.
        for p,raw in self.originals.items():self.write((self.gold if p in self.answers else self.root)/p,raw)
        self.engine=R.M.GO_SOURCE.read_bytes();self.write(self.root/C.ENGINE_PATH,self.engine)
        self.seed={p:R._hash(raw) for p,raw in self.originals.items() if p not in self.answers};self.seed[C.ENGINE_PATH]=R._hash(self.engine)
        self.boundary=Boundary(1,'coddy-agent',str(self.root),removable=[(p,'answer') for p in sorted(self.answers)],
            retained=[('internal/check/retained_test.go','retained')])
        table=ContextTable(self.closures,boundary=self.boundary,project='coddy-agent')
        self.harness=SimpleNamespace(root=str(self.root),boundary=self.boundary,contexts=table,
            expected_mutations={},manifest=SimpleNamespace(gold_root=str(self.gold),moved=sorted(self.answers)),
            copy=SimpleNamespace(original_inventory=deepcopy(self.seed),_state='idle'),
            check_context=table.check_context,verify_substrate=Mock())
        image='sha256:'+'7'*64;historical='/retired-producer/source'
        self.index={'schema':'r2t.go_prod_index/1','root':historical,'image_id':image,
            'files':{self.target:{'classes':[]}},'contexts':[{'go_suite':c,'answer_files':row['files'],'files':[self.target]}
                for c,row in zip(self.contexts,self.closures)]}
        groups,contexts=partitions(self.closures,self.index)
        self.attribution={'schema':SCHEMA,'root':historical,'source_root':historical,'image_id':image,
            'source_inventory':inventory,'contexts':contexts,'partitions':[{'compiled_package_name':'check',
                'source_files':{p:R._hash(self.originals[p]) for p in group['files']}} for group in groups]}
        raw=self.originals[self.target];offset=raw.index(b'true');col=offset-raw.rfind(b'\n',0,offset)
        row={'file':self.target,'start_line':2,'start_col':col,'end_line':2,'end_col':col+3,
            'operator':'TrueValue','original':'true','mutated':'false'}
        self.manifest=D.build_manifest([row],parser_version='go version go1.25.0 linux/amd64',
            engine=R.M.ENGINE,engine_version=R.M.ENGINE_VERSION,exclusions=R.M.EXCLUDED_PREFIXES)
        self.manifest['enumerator_rev']=R.M.ENUMERATOR_REV
        self.manifest['go_build_contexts']=[{'package_dir':'internal/check','go_build_tags':[],'production_files':[self.target]}]
        self.manifest['digest']=D.manifest_digest(self.manifest)
        self.mutant=self.manifest['mutants'][0]
        self.evidence_number=0
        self.identity=MR.build_campaign_identity(asset_index_sha256='0'*64,asset_project='coddy-agent',
            mutation_validation_sha256='1'*64,mutation_validation_class='native',manifest_sha256='2'*64,
            map_sha256='3'*64,release_sha256='4'*64,candidate_run_sha256='5'*64,
            solution_generated_tests_sha256='6'*64,candidate_generated_tests_sha256='6'*64,substrate_baseline_sha256='8'*64,worker_resources_sha256='9'*64,
            harness_version=1,container_image_digest=image,workspace_seed_digest='a'*64,database_dump_digest='no_database',
            expected_pairs=[(row['item_id'],self.mutant['id']) for row in self.closures],engine=R.M.ENGINE,
            engine_version=R.M.ENGINE_VERSION,parser=self.manifest['parser'],side='candidate',shard=0,of=1,timeout=600,
            generation_provenance_class=MR.GENERATION_PROVENANCE_FIXTURE,generation_campaign_digest='0123456789abcdef',manifest_digest=self.manifest['digest'],
            applier_sha256=R._hash(self.engine))
        self.save_artifacts()

    def write(self,path,raw):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)

    def save_artifacts(self):
        for name,doc in [('closures.json',self.closures),('go_prod_index.json',self.index),('go_interface_attribution.json',self.attribution)]:
            self.write(self.artifacts/name,(json.dumps(doc)+'\n').encode())

    def prepare(self):
        return R.prepare_campaign(self.harness,self.manifest,self.identity,self.artifacts)

    def invoke(self,authority,number=0,**kwargs):
        self.evidence_number+=1
        kwargs.setdefault('evidence_dir',self.base/('attempt-'+str(self.evidence_number)))
        c=self.contexts[number];feature=parse_feature_file(str(self.root/c['feature_path']))
        solution=Solution.from_json({'files':[{'file_path':p,'code':'package check\n// candidate drops original import\n'} for p in self.closures[number]['files']]})
        return R.run_solution(self.harness,feature,feature.scenario_at(c['scenario_line']),solution,
            mutant=self.mutant,manifest=self.manifest,identity=self.identity,authority=authority,**kwargs)

    def test_shared_reader_requires_go_contexts_before_effects(self):
        self.assertEqual(A.validate_manifest(self.manifest)['digest'],self.manifest['digest'])
        missing=deepcopy(self.manifest);missing.pop('go_build_contexts')
        missing['digest']=D.manifest_digest(missing)
        with self.assertRaisesRegex(A.MutationAssetRefused,'go_build_contexts'):
            R.prepare_campaign(self.harness,missing,self.identity,self.artifacts)
        self.harness.verify_substrate.assert_not_called()

    def test_shared_go_metadata_is_closed_and_digest_covered(self):
        def envelope(manifest):
            return {'engine':manifest['engine'],'engine_version':manifest['engine_version'],
                'parser':manifest['parser'],'files':1,'errors':{},'enumerator_rev':R.M.ENUMERATOR_REV,
                'mutants':[{k:v for k,v in row.items() if k!='id'} for row in manifest['mutants']],
                'go_build_contexts':deepcopy(manifest['go_build_contexts'])}
        def read(doc):
            return A.validate_enumerator_envelope(doc,expected_engine=doc['engine'],
                expected_engine_version=doc['engine_version'])
        doc=envelope(self.manifest);self.assertIs(read(doc),doc)
        for invalid in ([],None,[{'package_dir':'internal/check','go_build_tags':['windows'],'production_files':[self.target]}],
                        [{'package_dir':'internal/check','go_build_tags':[],'production_files':['internal/lib/other.go']}],
                        [dict(self.manifest['go_build_contexts'][0],unknown=True)]):
            bad=deepcopy(self.manifest);bad['go_build_contexts']=invalid;bad['digest']=D.manifest_digest(bad)
            with self.subTest(context=invalid),self.assertRaises(A.MutationAssetRefused):A.validate_manifest(bad)
            bad_envelope=envelope(bad)
            with self.assertRaises(A.MutationAssetRefused):read(bad_envelope)
        missing=envelope(self.manifest);missing.pop('go_build_contexts')
        with self.assertRaises(A.MutationAssetRefused):read(missing)
        changed=deepcopy(self.manifest);changed['go_build_contexts'][0]['go_build_tags']=['http']
        with self.assertRaisesRegex(A.MutationAssetRefused,'digest'):A.validate_manifest(changed)
        for engine in ('r2t-mutate','r2t-mutate-py','r2t-mutate-java','r2t-mutate-rb'):
            foreign=D.build_manifest([],parser_version='fixture',engine=engine,engine_version='1')
            foreign['go_build_contexts']=deepcopy(self.manifest['go_build_contexts'])
            foreign['digest']=D.manifest_digest(foreign)
            with self.subTest(engine=engine),self.assertRaisesRegex(A.MutationAssetRefused,'non-Go'):A.validate_manifest(foreign)
            with self.assertRaises(A.MutationAssetRefused):read(envelope(foreign))
        scored=A.derive_boundary_scored_manifest(self.manifest,self.boundary,'boundary.yml','a'*64)
        self.assertEqual(scored['go_build_contexts'],self.manifest['go_build_contexts'])
        A.validate_manifest(scored,raw_manifest=self.manifest)
        scored['go_build_contexts'][0]['go_build_tags']=['http'];scored['digest']=D.manifest_digest(scored)
        with self.assertRaisesRegex(A.MutationAssetRefused,'changes raw enumerator go_build_contexts'):
            A.validate_manifest(scored,raw_manifest=self.manifest)

    def test_portable_two_items_retry_and_full_reference_resource(self):
        authority=self.prepare();observed=[]
        def capture(harness,feature,scenario,solution,**options):
            self.assertIs(harness,self.harness);self.assertFalse(options['coverage']);self.assertEqual(options['repeats'],1)
            self.assertTrue(options['evidence_dir'].is_dir(), 'runtime requires an existing evidence directory')
            self.assertEqual(list(options['evidence_dir'].iterdir()), [])
            request=options['mutation'];observed.append(deepcopy(request))
            answers=set(self.closures[0 if len(observed)<3 else 1]['files'])
            self.assertEqual(set(request['reference_files'])&self.answers,answers)
            self.assertIn('internal/lib/data/value.txt',request['reference_files'])
            self.assertIn('internal/check/retained_test.go',request['reference_files'])
            self.assertNotIn(C.ENGINE_PATH,request['reference_files'])
            self.assertEqual(request['engine_request']['contexts'][0]['root'],C.REFERENCE_SOURCE)
            self.assertEqual(request['descriptor'],self.mutant)
            return {'outcomes':['passed'],'runs':[{'go_mutation':{'fixture':True}}]}
        with patch.object(R.runtime,'run_solution',side_effect=capture):
            for number in (0,0,1):self.assertEqual(self.invoke(authority,number)['outcomes'],['passed'])
        self.assertEqual(observed[0],observed[1]);self.assertNotEqual(observed[1]['reference_files'],observed[2]['reference_files'])
        self.assertEqual(self.harness.expected_mutations,{})
        self.assertEqual(authority.original_root,'/retired-producer/source')

    def test_context_gold_seed_engine_and_image_fail_before_runtime(self):
        changes=[lambda:self.index['contexts'][0]['go_suite']['go_build_tags'].append('http'),
            lambda:self.manifest['go_build_contexts'][0]['production_files'].clear(),
            lambda:self.write(self.gold/self.helper,b'changed gold'),
            lambda:self.write(self.root/'internal/lib/data/value.txt',b'changed resource'),
            lambda:self.harness.copy.original_inventory.__setitem__(self.target,'f'*64),
            lambda:self.identity.__setitem__('applier_sha256','f'*64),
            lambda:self.index.__setitem__('image_id','sha256:'+'f'*64)]
        for number,change in enumerate(changes):
            with self.subTest(number=number):
                self.setUp();change();self.save_artifacts()
                with patch.object(R.runtime,'run_solution') as capture:
                    with self.assertRaises((R.MutationRuntimeRefused,ValueError,R.M.GoMutationRefused)):self.prepare()
                capture.assert_not_called()

    def test_changed_inputs_descriptor_and_foreign_authority_refuse(self):
        for change in ('gold','resource','descriptor','identity','copy','timeout'):
            with self.subTest(change=change):
                self.setUp();authority=self.prepare();options={}
                if change=='gold':self.write(self.gold/self.helper,b'changed')
                elif change=='resource':self.write(self.root/'internal/lib/data/value.txt',b'changed')
                elif change=='descriptor':self.mutant=dict(self.mutant,mutated='true')
                elif change=='identity':self.identity['manifest_digest']='f'*64
                elif change=='copy':self.harness.copy=deepcopy(self.harness.copy)
                else:options={'timeout':60}
                with patch.object(R.runtime,'run_solution') as capture:
                    with self.assertRaises(R.MutationRuntimeRefused):self.invoke(authority,**options)
                capture.assert_not_called()

    def test_fresh_evidence_preserves_complete_result_and_failure(self):
        authority=self.prepare();folder=self.base/'evidence';folder.mkdir()
        result={'runs':[{'go_mutation':{'fullproof':True}}],'outcomes':['passed']}
        with patch.object(R.runtime,'run_solution',return_value=result) as capture:
            self.invoke(authority,evidence_dir=folder)
            self.assertEqual(capture.call_args.kwargs['evidence_dir'],folder/'native')
            self.assertEqual(json.loads((folder/'result.json').read_text()),result)
            with self.assertRaises(R.MutationRuntimeRefused):self.invoke(authority,evidence_dir=folder)
            self.assertEqual(capture.call_count,1)
        with patch.object(R.runtime,'run_solution',side_effect=RuntimeError('capture failed')):
            with self.assertRaisesRegex(RuntimeError,'capture failed'):self.invoke(authority,evidence_dir=self.base/'failed')
        self.assertEqual(json.loads((self.base/'failed/failure.json').read_text())['message'],'capture failed')
        for target in (self.root/'evidence',self.gold/'evidence'):
            with self.assertRaises(R.MutationRuntimeRefused):self.invoke(authority,evidence_dir=target)
            self.assertFalse(target.exists())

    def test_saved_in_root_link_identity_uses_verified_current_bytes(self):
        raw=self.originals['internal/lib/data/value.txt'];path='internal/lib/data/alias.txt'
        self.attribution['source_inventory'][path]={'link':'value.txt'}
        self.attribution['source_inventory']['internal/lib/data/dangling.txt']={'link':'missing.txt'}
        self.write(self.root/path,raw);self.harness.copy.original_inventory[path]=R._hash(raw);self.save_artifacts()
        authority=self.prepare();self.assertEqual(authority.reference_files[path],raw)
        self.assertNotIn('internal/lib/data/dangling.txt',authority.reference_files)
        self.attribution['source_inventory'][path]={'link':'../../../../outside'};self.save_artifacts()
        with self.assertRaises(C.ExecutionRefused):self.prepare()

    def test_original_authority_needs_no_campaign_and_keeps_full_gold_set(self):
        extra='internal/check/bdd_unselected_test.go';raw=b'package check\n// original unselected answer\n'
        self.originals[extra]=raw
        self.attribution['source_inventory'][extra]={'sha256':R._hash(raw)}
        self.boundary.removable.append((extra,'answer'))
        self.harness.manifest.moved.append(extra)
        self.write(self.gold/extra,raw);self.save_artifacts()
        authority=R.prepare_original(self.harness,self.manifest,self.artifacts,
            image_id=self.identity['container_image_digest'])
        self.assertIsInstance(authority,R.OriginalAuthority)
        self.assertFalse(hasattr(authority,'identity'))
        self.assertEqual(authority.reference_files[extra],raw)
        self.assertEqual(authority.original_root,'/retired-producer/source')
        self.assertEqual(authority.image_id,self.identity['container_image_digest'])
        with self.assertRaisesRegex(R.MutationRuntimeRefused,'image'):
            R.prepare_original(self.harness,self.manifest,self.artifacts,image_id='sha256:'+'f'*64)
        self.write(self.gold/extra,b'changed unselected gold')
        with self.assertRaisesRegex(R.MutationRuntimeRefused,'gold'):
            R.prepare_original(self.harness,self.manifest,self.artifacts,
                image_id=self.identity['container_image_digest'])

    def use_seed_applier(self, raw, *, campaign=None):
        """Model a worker seed whose applier another mutate.go revision installed."""
        self.write(self.root/C.ENGINE_PATH, raw)
        self.harness.copy.original_inventory[C.ENGINE_PATH] = R._hash(raw)
        self.identity['applier_sha256'] = R._hash(raw if campaign is None else campaign)

    def seed_archive(self, raw):
        seed = self.base/'seed';seed.mkdir()
        with tarfile.open(seed/'workspace.tar','w') as archive:
            member = tarfile.TarInfo(C.ENGINE_PATH);member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        return seed

    def test_seed_applier_differing_from_checkout_builder_is_the_campaign_applier(self):
        # The existing Coddy seed: a builder change moved only construction code.
        raw = self.engine + b'\n// construction-only change of an older builder\n'
        self.assertNotEqual(R._hash(raw), R._hash(R.M.GO_SOURCE.read_bytes()))
        self.use_seed_applier(raw)
        authority = self.prepare()
        self.assertEqual(authority.engine_sha256, R._hash(raw))
        self.assertEqual(R.prepare_original(self.harness, self.manifest, self.artifacts,
            image_id=self.identity['container_image_digest']).engine_sha256, R._hash(raw))
        seed = self.seed_archive(raw)
        self.assertEqual(R.seed_applier(seed), raw)
        self.assertEqual(MR.runtime_applier_sha256(R.M.ENGINE, str(seed)), R._hash(raw))
        with patch.object(R.runtime, 'run_solution', return_value={'outcomes':['passed'],'runs':[]}) as capture:
            self.invoke(authority)
        # Every application still checks these bytes and the host splice.
        self.assertEqual(capture.call_args.kwargs['mutation']['engine_sha256'], R._hash(raw))

    def test_seed_applier_other_than_campaign_identity_refuses(self):
        raw = self.engine + b'\n// construction-only change of an older builder\n'
        self.use_seed_applier(raw, campaign=self.engine)
        with patch.object(R.runtime, 'run_solution') as capture:
            with self.assertRaisesRegex(R.MutationRuntimeRefused, 'campaign applier identity'):
                self.prepare()
            self.use_seed_applier(raw)
            self.write(self.root/C.ENGINE_PATH, self.engine)
            with self.assertRaisesRegex(R.MutationRuntimeRefused, 'differs from its seed'):
                self.prepare()
        capture.assert_not_called()

    def test_seed_applier_from_other_enumerator_revision_refuses(self):
        current = ('const ENUMERATOR_REV = "'+R.M.ENUMERATOR_REV+'"').encode()
        self.assertIn(current, self.engine)
        raw = self.engine.replace(current, b'const ENUMERATOR_REV = "r2t-mutate-go/other-revision"')
        self.use_seed_applier(raw)
        with patch.object(R.runtime, 'run_solution') as capture:
            with self.assertRaisesRegex(R.MutationRuntimeRefused, 'ENUMERATOR_REV'):
                self.prepare()
            with self.assertRaisesRegex(R.MutationRuntimeRefused, 'ENUMERATOR_REV'):
                R.prepare_original(self.harness, self.manifest, self.artifacts,
                                   image_id=self.identity['container_image_digest'])
        capture.assert_not_called()
        seed = self.seed_archive(raw)
        with self.assertRaisesRegex(MR.MutationAborted, 'ENUMERATOR_REV'):
            MR.runtime_applier_sha256(R.M.ENGINE, str(seed))

    def test_cheap_validation_has_no_source_or_harness_dependency(self):
        self.assertIsNone(R.validate_campaign(self.manifest,self.identity))
        bad=deepcopy(self.identity);bad['engine_version']='wrong'
        with self.assertRaises(R.MutationRuntimeRefused):R.validate_campaign(self.manifest,bad)
        self.harness.verify_substrate.assert_not_called()


def selftest():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MutationRuntimeTests))
    return 0 if result.wasSuccessful() else 1

if __name__=='__main__':raise SystemExit(selftest())
