"""Real stdlib Go audit driver plus coordinator fault-injection contracts."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ..bench import mutation_run as MR
from ..data import mutation_attestation as A
from ..toolkit import mutation_audit as shared
from . import mutation_audit as G
from .mutation_runtime_selftest import MutationRuntimeTests


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = MutationRuntimeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f=self.fixture
        self.root=f.base/'audit';self.root.mkdir()
        for p,raw in f.originals.items():f.write(self.root/p,raw)
        for p in A._audit_roots(f.manifest):(self.root/p).mkdir(parents=True,exist_ok=True)
        (self.root/A.DISPOSABLE_MARKER).write_text(shared.DISPOSABLE_MARKER_CONTENT)
        f.harness.image_id=f.identity['container_image_digest']
        for name in G.SUPPORT:
            relative='_bench/go/support/'+name;raw=Path(G.__file__).with_name('support').joinpath(name).read_bytes()
            f.write(f.root/relative,raw);f.harness.copy.original_inventory[relative]=G._hash(raw)
        self.evidence=f.base/'audit-evidence'

    def invoke(self, mode=None):
        f=self.fixture;old=f.harness.copy
        copy=MockAuditCopy(old,f,mode);f.harness.copy=copy
        return G.audit_population_in_image(f.manifest,str(self.root),harness=f.harness,
            artifacts=f.artifacts,evidence_dir=self.evidence)

    def test_shared_report_counts_actual_operations_and_full_roots(self):
        report=self.invoke();copy=self.fixture.harness.copy
        self.assertEqual(report['status'],'complete')
        for name in ('n_mutants','n_attempted','n_applied','n_parse_valid','n_restored'):
            self.assertEqual(report[name],1)
        self.assertEqual(copy.actions,['setup','apply','parse','restore','retire'])
        self.assertEqual(copy.budgets,[300,300,300,30,30])
        self.assertEqual(report['digest'],A.audit_digest(report))
        self.assertEqual(report['n_source_files'],len(G._bounded(self.fixture.originals,report['bounded_roots'])))
        self.assertEqual(report['source_lstat_sha256_before'],report['source_lstat_sha256_after'])
        self.assertFalse(copy.quarantined);self.assertEqual(copy._state,'idle')
        self.assertEqual(json.loads((self.evidence/'report.json').read_text()),report)

    def test_evidence_can_live_beside_artifact_inputs(self):
        self.evidence=self.fixture.artifacts/'validation.json.go-audit-evidence'
        originals={p:p.read_bytes() for p in self.fixture.artifacts.iterdir()}
        self.assertEqual(self.invoke()['status'],'complete')
        self.assertTrue((self.evidence/'report.json').is_file())
        self.assertEqual({p:p.read_bytes() for p in originals},originals)

    def test_bound_raw_audit_does_not_require_mapping(self):
        from ..bench import cli as B, worker as W
        from ..bench.validate import HARNESS_VERSION
        f = self.fixture
        f.harness.copy = MockAuditCopy(f.harness.copy, f, None)
        f.harness._worker_runtime = {'harness_version': HARNESS_VERSION,
            'container_image_digest': f.harness.image_id, 'workspace_seed_digest': 'a'*64,
            'database_dump_digest': 'no_database'}
        f.harness.runner = SimpleNamespace(container='worker')
        args = SimpleNamespace(worker='/fixture/worker.json', gold=str(f.gold),
                               artifacts=str(f.artifacts), audit_workers=1)
        live = {'selected': {'binding': {'container': {'id': 'b'*64}}}}
        with patch.object(B, '_worker_spec', return_value=object()), \
                patch.object(B, '_harness', return_value=(f.harness, f.boundary, f.harness.manifest)), \
                patch.object(W, 'validate_live_worker_runtime', return_value=live):
            report = G.audit_bound_pool(args, f.manifest, audit_root=str(self.root), evidence_dir=str(self.evidence))
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(report['n_restored'], f.manifest['n'])
        self.assertFalse(hasattr(args, 'map'))
        self.assertEqual(f.harness.runner.container, 'b'*64)

    def test_shared_cli_audit_binds_the_live_go_worker(self):
        from .. import cli
        from ..bench import cli as B,worker as W
        from ..bench.validate import HARNESS_VERSION
        f=self.fixture;report=self.invoke()
        manifest_path=f.artifacts/'mutants.json';manifest_path.write_text(json.dumps(f.manifest))
        mapping=A.build_map_artifact(f.manifest,{},[f.mutant['id']],coverage_sha256='a'*64,release_sha256='b'*64)
        map_path=f.artifacts/'map.json';map_path.write_text(json.dumps(mapping))
        boundary_path=f.base/'boundary.yml';boundary_path.write_text('project: coddy-agent\n')
        output=f.artifacts/'validation.json'
        spec=SimpleNamespace(workspace=str(f.root),container='go-worker',workdir='/work',index=0,out_path=None)
        f.harness._worker_runtime={'harness_version':HARNESS_VERSION,'container_image_digest':f.harness.image_id,
            'workspace_seed_digest':'a'*64,'database_dump_digest':'no_database'}
        f.harness.runner=SimpleNamespace(container='go-worker')
        live={'selected':{'binding':{'container':{'id':'b'*64}}}}
        with patch.object(B,'_worker_spec',return_value=spec),patch.object(B,'_harness',return_value=(f.harness,f.boundary,f.harness.manifest)), \
                patch.object(W,'validate_live_worker_runtime',return_value=live) as validate, \
                patch.object(G,'audit_population_in_image',return_value=report) as audit, \
                patch.object(shared,'audit_with_engine',side_effect=AssertionError('Go used host audit')):
            result=cli.main(['--worker',str(f.base/'worker.json'),'--container','go-worker',
                '--boundary',str(boundary_path),'--gold',str(f.gold),'--artifacts',str(f.artifacts),
                'mutants','validate','--manifest',str(manifest_path),'--map',str(map_path),
                '--audit-root',str(self.root),'--out',str(output)])
        self.assertEqual(result,0)
        self.assertEqual(validate.call_args.kwargs['expected_runtime'],f.harness._worker_runtime)
        self.assertFalse(validate.call_args.kwargs['needs_database'])
        self.assertEqual(f.harness.runner.container,'b'*64)
        self.assertEqual(audit.call_args.kwargs['evidence_dir'],str(output)+'.go-audit-evidence')
        self.assertIs(audit.call_args.kwargs['harness'],f.harness)
        saved=json.loads(output.read_text())
        self.assertEqual(saved['materialisation_audit'],report)
        self.assertEqual(saved['status'],'valid')
        # The existing option selects the first k authenticated pool members,
        # even when the global worker selects a later pool member.
        peer = self.peer_harness()
        peer.root = str(f.base/'worker-1')
        spec.artifacts_root = str(f.artifacts)
        peer_spec = SimpleNamespace(workspace=peer.root,container='go-worker-1',workdir='/work',
                                    index=1,artifacts_root=str(f.base/'artifacts-1'))
        paths = [str(f.base/'worker.json'),str(f.base/'worker1.json')]
        live.update(pool_paths=paths,pool_specs=(spec,peer_spec),docker_execution_pool_digest='c'*64)
        bound_pool = [dict(worker=worker,runtime=dict(f.harness._worker_runtime),binding={
            'pool':{'digest':'c'*64},'container':{'id':str(i+1)*64}})
            for i,worker in enumerate((spec,peer_spec))]
        parallel_output = f.artifacts/'parallel-validation.json'
        def make(current):
            picked = peer if current.worker == paths[1] else f.harness
            return picked,f.boundary,f.harness.manifest
        with patch.object(B,'_worker_spec',return_value=peer_spec),patch.object(B,'_harness',side_effect=make) as make_harness, \
                patch.object(W,'validate_live_worker_runtime',return_value=live) as validate, \
                patch.object(W,'validate_offline_worker_runtime_pool',return_value=bound_pool), \
                patch.object(G,'audit_population_in_image',return_value=report) as audit:
            result=cli.main(['--worker',paths[1],'--container','go-worker-1',
                '--boundary',str(boundary_path),'--gold',str(f.gold),'--artifacts',str(f.artifacts),
                'mutants','validate','--manifest',str(manifest_path),'--map',str(map_path),
                '--audit-root',str(self.root),'--audit-workers','2','--out',str(parallel_output)])
        self.assertEqual(result,0)
        self.assertEqual(validate.call_count,1)
        self.assertIs(audit.call_args.kwargs['harness'],f.harness)
        self.assertEqual(audit.call_args.kwargs['parallel_workers'],[(peer,peer_spec.artifacts_root)])
        self.assertEqual((f.harness.runner.container,peer.runner.container),('1'*64,'2'*64))
        self.assertEqual(make_harness.call_args.args[0].repo,spec.workspace)
        for kind in ('short-pool','different-seed'):
            invalid = deepcopy(bound_pool)
            if kind == 'different-seed':invalid[0]['runtime']['workspace_seed_digest']='f'*64
            target = f.artifacts/(kind+'-parallel-refused.json')
            with patch.object(B,'_worker_spec',return_value=spec),patch.object(B,'_harness',side_effect=make), \
                    patch.object(W,'validate_live_worker_runtime',return_value=live), \
                    patch.object(W,'validate_offline_worker_runtime_pool',return_value=invalid), \
                    patch.object(G,'audit_population_in_image') as audit,self.assertRaisesRegex(SystemExit,'durable refusal evidence'):
                cli.main(['--worker',paths[0],'--container','go-worker',
                    '--boundary',str(boundary_path),'--gold',str(f.gold),'--artifacts',str(f.artifacts),
                    'mutants','validate','--manifest',str(manifest_path),'--map',str(map_path),
                    '--audit-root',str(self.root),'--audit-workers','3' if kind=='short-pool' else '2',
                    '--out',str(target)])
            audit.assert_not_called()
            self.assertEqual(json.loads(target.read_text())['status'],'refused')
        from .mutation_runtime import MutationRuntimeRefused
        from ..bench.repo import SubstrateTampered
        refusals=[('worker',W.WorkerRefused('fixture worker refused')),
                  ('source',MutationRuntimeRefused('fixture source refused')),
                  ('substrate',SubstrateTampered({'changed':['go.mod'],'missing':[],'added':[]}))]
        for kind,error in refusals:
            target=f.artifacts/(kind+'-refused.json')
            with patch.object(B,'_worker_spec',return_value=spec), \
                    patch.object(B,'_harness',side_effect=error if kind=='substrate' else None,
                                 return_value=(f.harness,f.boundary,f.harness.manifest)), \
                    patch.object(W,'validate_live_worker_runtime',side_effect=error if kind=='worker' else None,return_value=live), \
                    patch.object(G,'audit_population_in_image',side_effect=error if kind=='source' else None,return_value=report), \
                    self.assertRaisesRegex(SystemExit,'durable refusal evidence'):
                cli.main(['--worker',str(f.base/'worker.json'),'--container','go-worker',
                    '--boundary',str(boundary_path),'--gold',str(f.gold),'--artifacts',str(f.artifacts),
                    'mutants','validate','--manifest',str(manifest_path),'--map',str(map_path),
                    '--audit-root',str(self.root),'--out',str(target)])
            saved=json.loads(target.read_text())
            self.assertEqual(saved['status'],'refused')
            self.assertIn(str(error),saved['failure'])

    def test_failed_parse_restores_before_failed_report(self):
        with self.assertRaises(A.MaterialisationAuditRefused) as caught:self.invoke('parse')
        report=caught.exception.report
        self.assertEqual((report['n_applied'],report['n_parse_valid'],report['n_restored']),(1,0,1))
        self.assertEqual(report['failure_stage'],'parse')
        self.assertEqual(self.fixture.harness.copy.actions[-2:],['restore','retire'])
        self.assertEqual(report['source_set_sha256_before'],report['source_set_sha256_after'])

    def test_timeout_restores_and_preserves_failed_operation_evidence(self):
        with self.assertRaises(A.MaterialisationAuditRefused) as caught:self.invoke('timeout')
        report=caught.exception.report
        self.assertEqual((report['n_attempted'],report['n_applied'],report['n_parse_valid'],report['n_restored']),(1,0,0,1))
        self.assertEqual(report['failure_stage'],'apply')
        self.assertFalse(self.fixture.harness.copy.quarantined)
        restored=json.loads((self.evidence/'000002-restore.json').read_text())
        self.assertEqual(restored['prior_engine_stdout'],'partial source engine output')

    def test_disposal_or_collateral_cannot_earn_restoration(self):
        for mode in ('restore','collateral'):
            with self.subTest(mode=mode):
                self.setUp()
                with self.assertRaises(A.MaterialisationAuditRefused) as caught:self.invoke(mode)
                report=caught.exception.report
                self.assertEqual(report['n_restored'],0)
                self.assertEqual(report['failure_stage'],'restore')
                self.assertTrue(self.fixture.harness.copy.quarantined)
                self.assertNotIn('retire',self.fixture.harness.copy.actions)

    def test_missing_marker_changed_source_and_wrong_image_refuse_without_effects(self):
        for mode in ('marker','source','image','helper'):
            with self.subTest(mode=mode):
                self.setUp();f=self.fixture
                if mode=='marker':(self.root/A.DISPOSABLE_MARKER).unlink()
                elif mode=='source':(self.root/f.target).write_bytes(b'changed')
                elif mode=='image':f.harness.image_id='sha256:'+'f'*64
                else:(f.root/'_bench/go/support'/G.SUPPORT[0]).write_bytes(b'changed helper')
                with self.assertRaises((A.MutationAssetRefused,RuntimeError)):
                    G.audit_population_in_image(f.manifest,str(self.root),harness=f.harness,
                        artifacts=f.artifacts,evidence_dir=self.evidence)
                self.assertFalse(self.evidence.exists())

    def peer_harness(self):
        current = self.fixture.harness
        peer = SimpleNamespace(**vars(current))
        peer.copy = SimpleNamespace(original_inventory=deepcopy(current.copy.original_inventory),_state='idle')
        peer.runner = SimpleNamespace(container='go-worker-1')
        peer.verify_substrate = Mock()
        return peer

    def population(self, count=4):
        from ..data import mutation as D
        f = self.fixture
        raw = b'package lib\n' + b''.join(
            f'func Value{i}() bool {{ return true }}\n'.encode() for i in range(count))
        f.originals[f.target] = raw
        f.write(f.root/f.target,raw);f.write(self.root/f.target,raw)
        f.harness.copy.original_inventory[f.target] = G._hash(raw)
        f.attribution['source_inventory'][f.target] = {'sha256':G._hash(raw)}
        for part in f.attribution['partitions']:
            if f.target in part['source_files']:
                part['source_files'][f.target] = G._hash(raw)
        rows = []
        for number,line in enumerate(raw.splitlines(),1):
            if b'true' in line:
                col = line.index(b'true')+1
                rows.append(dict(file=f.target,start_line=number,start_col=col,end_line=number,
                                 end_col=col+3,operator='TrueValue',original='true',mutated='false'))
        manifest = D.build_manifest(rows,parser_version=f.manifest['parser'],engine=G.M.ENGINE,
                                    engine_version=G.M.ENGINE_VERSION,exclusions=G.M.EXCLUDED_PREFIXES)
        manifest.update(enumerator_rev=f.manifest['enumerator_rev'],
                        go_build_contexts=f.manifest['go_build_contexts'])
        manifest['digest'] = D.manifest_digest(manifest)
        f.manifest = manifest;f.save_artifacts()

    def parallel(self, mode=None, *, hooks=None):
        f = self.fixture
        peer = self.peer_harness()
        peer.root = str(f.base/'worker-1')
        shutil.copytree(f.root,peer.root)
        f.harness.copy = MockAuditCopy(f.harness.copy,f,mode)
        peer.copy = MockAuditCopy(peer.copy,f,None)
        if hooks:
            f.harness.copy.apply_hook,peer.copy.apply_hook = hooks
        self.peer = peer
        return G.audit_population_in_image(f.manifest,str(self.root),harness=f.harness,
            artifacts=f.artifacts,evidence_dir=self.evidence,parallel_workers=[(peer,f.artifacts)])

    def test_parallel_full_population_matches_serial_and_uses_both_workers(self):
        self.population()
        serial = self.invoke()
        self.evidence = self.fixture.base/'parallel-evidence'
        barrier = threading.Barrier(2)
        def together(copy):
            if copy.actions.count('apply') == 1:
                barrier.wait(timeout=10)
        report = self.parallel(hooks=(together,together))
        self.assertEqual({k:v for k,v in report.items() if k not in ('digest','parallel_audit')},
                         {k:v for k,v in serial.items() if k != 'digest'})
        self.assertEqual(report['parallel_audit']['n_roots'],2)
        self.assertTrue(all(n > 0 for n in report['parallel_audit']['mutants_by_root']))
        indices = []
        for slot,copy in enumerate((self.fixture.harness.copy,self.peer.copy)):
            indices.extend(int(row['argv'][-1]) for row in copy.command_evidence
                           if row['argv'][len(G.PREFIX)] == 'apply')
            saved = json.loads((self.evidence/f'worker-{slot}'/'request.json').read_text())
            self.assertEqual(saved['mutants'],self.fixture.manifest['mutants'])
            self.assertEqual(copy._state,'idle');self.assertFalse(copy.quarantined)
            self.assertFalse((self.evidence/f'worker-{slot}'/'report.json').exists())
        self.assertEqual(sorted(indices),list(range(4)))
        self.assertEqual(json.loads((self.evidence/'report.json').read_text()),report)

    def test_parallel_failure_stops_dispatch_and_active_worker_restores(self):
        self.population(6)
        together = threading.Barrier(2)
        stopped = threading.Event()
        real_stop = G._AuditQueue.stop
        def stop(queue):
            real_stop(queue);stopped.set()
        def failing(copy):
            together.wait(timeout=10)
        def active(copy):
            together.wait(timeout=10)
            self.assertTrue(stopped.wait(timeout=10))
        with patch.object(G._AuditQueue,'stop',stop),self.assertRaises(A.MaterialisationAuditRefused) as caught:
            self.parallel('parse',hooks=(failing,active))
        report = caught.exception.report
        self.assertEqual((report['n_attempted'],report['n_applied'],report['n_restored']),(2,2,2))
        self.assertEqual(report['n_parse_valid'],1)
        for copy in (self.fixture.harness.copy,self.peer.copy):
            self.assertEqual(copy.actions[-2:],['restore','retire'])
            self.assertEqual(copy._state,'idle');self.assertFalse(copy.quarantined)
        self.assertEqual(json.loads((self.evidence/'report.json').read_text()),report)

    def test_interrupted_submission_releases_prepared_workers_for_cleanup(self):
        self.population()
        real_submit = G.ThreadPoolExecutor.submit
        submissions = []
        def submit(executor, *args, **kwargs):
            if submissions:
                raise KeyboardInterrupt('interrupted worker startup')
            future = real_submit(executor,*args,**kwargs)
            submissions.append(future)
            return future
        with patch.object(G.ThreadPoolExecutor,'submit',submit),self.assertRaises(KeyboardInterrupt):
            self.parallel()
        copy = self.fixture.harness.copy
        self.assertEqual(copy.actions,['setup','retire'])
        self.assertEqual(copy._state,'idle');self.assertFalse(copy.quarantined)
        self.assertEqual(self.peer.copy.actions,[])
        self.assertTrue((self.evidence/'worker-0'/'commands.json').is_file())
        self.assertFalse((self.evidence/'report.json').exists())

    def test_parallel_native_metadata_mismatch_starts_no_mutant(self):
        self.population()
        with self.assertRaises(A.MaterialisationAuditRefused):
            self.parallel('metadata')
        for copy in (self.fixture.harness.copy,self.peer.copy):
            self.assertNotIn('apply',copy.actions)
            self.assertEqual(copy.actions[-1],'retire')

    def test_parallel_overlapping_workers_refuse_before_output(self):
        f = self.fixture
        with self.assertRaisesRegex(A.MutationAssetRefused,'share an execution copy'):
            G.audit_population_in_image(f.manifest,str(self.root),harness=f.harness,
                artifacts=f.artifacts,evidence_dir=self.evidence,parallel_workers=[(f.harness,f.artifacts)])
        self.assertFalse(self.evidence.exists())
        peer = self.peer_harness()
        with self.assertRaisesRegex(A.MutationAssetRefused,'source trees overlap'):
            G.audit_population_in_image(f.manifest,str(self.root),harness=f.harness,
                artifacts=f.artifacts,evidence_dir=self.evidence,parallel_workers=[(peer,f.artifacts)])
        self.assertFalse(self.evidence.exists())

    def test_real_go_driver_apply_parse_restore_and_syntax_failure(self):
        go=shutil.which('go');self.assertIsNotNone(go)
        with tempfile.TemporaryDirectory(prefix='go-audit-driver-') as directory:
            root=Path(directory);original=root/'work';run=root/'run';work=run/'work'
            for p in (original,work):p.mkdir(parents=True)
            source=b'package version\nfunc Value() bool { return true }\n'
            files={'go.mod':b'module auditfixture\n\ngo 1.25.0\n','go.sum':b'',
                'internal/version/version.go':source,'internal/version/version_test.go':b'package version\n'}
            for rel,raw in files.items():
                p=original/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
            engine=original/'_bench/go/support/mutate.go';engine.parent.mkdir(parents=True);engine.write_bytes(G.M.GO_SOURCE.read_bytes())
            target='internal/version/version.go';offset=source.index(b'true');column=offset-source.rfind(b'\n',0,offset)
            d={'id':'fixture','file':target,'operator':'TrueValue','start_line':2,'start_col':column,
               'end_line':2,'end_col':column+3,'original':'true','mutated':'false'}
            req={'files':{p:{'sha256':G._hash(raw),'data':base64.b64encode(raw).decode(),
                'mode':(original/p).stat().st_mode,'removable':False} for p,raw in files.items()},
                'contexts':[{'package_dir':'internal/version','package_name':'version','glue_path':'internal/version/version_test.go',
                    'go_build_tags':[],'answers':[],'production_files':[target]}],'mutants':[d]}
            request=work/G.REQUEST;request.parent.mkdir(parents=True);request.write_text(json.dumps(req))
            support=Path(G.__file__).with_name('support')
            driver=(support/G.SUPPORT[0]).read_text().replace('/r2t-go/run',str(run)).replace('const auditEngine = "/work/', 'const auditEngine = "'+str(original)+'/').replace('path("/work",relative)','path('+json.dumps(str(original))+',relative)').replace('/usr/local/go/bin/go',go)
            (root/'driver.go').write_text(driver);(root/'support.go').write_bytes((support/G.SUPPORT[1]).read_bytes())
            env=dict(os.environ,GOTOOLCHAIN='local',GOPROXY='off',GOWORK='off',GOFLAGS='-mod=readonly')
            binary=root/'audit'
            subprocess.run([go,'build','-p=1','-o',str(binary),str(root/'driver.go'),str(root/'support.go')],env=env,check=True,capture_output=True,timeout=60)
            def call(action):
                result=subprocess.run([str(binary),action]+([] if action in ('setup','retire') else ['0']),
                    env=env,capture_output=True,text=True,timeout=60,check=True)
                doc=json.loads(result.stdout);self.assertTrue(doc['ok'],doc);return doc
            setup=call('setup');pre=setup['before']
            apply=call('apply');changed=G.M.splice(source,{k:v for k,v in d.items() if k!='id'})
            self.assertEqual(base64.b64decode(apply['target']),changed)
            parsed=call('parse');G._parse_result(parsed['parse'],changed,setup['runtime_parser'])
            restored=call('restore');self.assertEqual(restored['after'],pre)
            native_target=run/'mutation-audit/original'/target
            native_target.write_bytes(source+b'\n//line imaginary.go:900\nfunc broken( {\n');native_target.chmod(0o600)
            invalid=call('parse');self.assertFalse(invalid['parse']['valid']);self.assertTrue(invalid['parse']['errors'])
            restored=call('restore');self.assertEqual(restored['after'],pre)
            retired=call('retire');self.assertTrue(retired['private_analysis_removed']);self.assertFalse((run/'mutation-audit').exists())


class MockAuditCopy:
    """Coordinator fault injection; real parser/restorer exercised separately."""
    def __init__(self,old,fixture,mode):
        self.original_inventory=old.original_inventory;self._state='idle';self.quarantined=False
        self.command_evidence=[];self.actions=[];self.budgets=[];self.f=fixture;self.mode=mode
    def prepare(self,context,answers,transforms,**kwargs):
        self._state='prepared';self.request=json.loads(transforms[G.REQUEST]);self.pre={
            p:{'sha256':r['sha256'],'metadata':{'mode':r['mode'],'uid':0,'gid':0}} for p,r in self.request['files'].items()}
        if self.mode == 'metadata':
            for fact in self.pre.values():fact['metadata']['uid'] = 1
        self.current=deepcopy(self.pre)
    def run_audit_operation(self,argv,*,timeout):
        action=argv[len(G.PREFIX)];self.actions.append(action);self.budgets.append(timeout);self._state='planned'
        result={'operation':action,'ok':True,'owned':action=='setup','before':deepcopy(self.current)}
        index = int(argv[-1]) if action not in ('setup','retire') else 0
        d=self.request['mutants'][index];p=d['file'];source=base64.b64decode(self.request['files'][p]['data'])
        changed=G.M.splice(source,{k:v for k,v in d.items() if k!='id'})
        if action=='setup':result['runtime_parser']=self.f.manifest['parser']
        elif action=='apply':
            if hasattr(self,'apply_hook'):self.apply_hook(self)
            self.current[p]['sha256']=G._hash(changed);result['target']=base64.b64encode(changed).decode()
            result['engine_stdout']=json.dumps({'file':p,'applied':True,'original_sha256':G._hash(source),
                'mutated_sha256':G._hash(changed),'metadata':self.pre[p]['metadata']})
        elif action=='parse':
            result['target']=base64.b64encode(changed).decode();result['parse']={'parser':self.f.manifest['parser'],
                'sha256':G._hash(changed),'valid':self.mode!='parse','errors':[]}
        elif action=='restore':
            if self.mode=='timeout':result['prior_engine_stdout']='partial source engine output'
            self.current=deepcopy(self.pre);result['target']=base64.b64encode(source).decode()
            if self.mode=='restore':result.update(ok=False,error='restoration unproved')
            if self.mode=='collateral':self.current['internal/extra.go']={'sha256':'0'*64,'metadata':self.pre[p]['metadata']}
        elif action=='retire':result['private_analysis_removed']=True
        result['after']=deepcopy(self.current)
        completed=subprocess.CompletedProcess(argv,0,json.dumps(result),'')
        self.command_evidence.append({'argv':argv,'stdout':completed.stdout,'returncode':0})
        if action=='apply' and self.mode=='timeout':raise subprocess.TimeoutExpired(argv,300)
        return completed
    def retire(self):self._state='idle'


def selftest():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AuditTests))
    return 0 if result.wasSuccessful() else 1

if __name__=='__main__':raise SystemExit(selftest())
