"""Remote mutation state/guard tests plus the actual shell metadata transport."""
import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import unittest

from ..bench.repo import compare_substrate_inventory
from .execution import COPY_ROOT, ORIGINAL_ROOT, RUN_ROOT, ExecutionCopy, ExecutionRefused, ExecutionIntegrityError, ExecutionTimeout, _SUPPORT, _payload
from .execution_selftest import Remote, fixture, _frame, _inventory
from . import mutation_copy as M


def digest(raw):return hashlib.sha256(raw).hexdigest()
META={'mode':0o100644,'uid':1000,'gid':1000}


class MutationRemote(Remote):
    def __init__(self,files):
        super().__init__(files);self.reference=None;self.reference_other={};self.meta={};self.executables=[]
        self.break_reference=False;self.corrupt_transfer=False;self.fail_retire=False

    def run(self,command,timeout,input=None):
        words=shlex.split(command);verb,*args=words[5:]
        if verb=='execute':self.executables.append(args[1:])
        if verb=='metadata':
            self.calls.append(verb)
            if args[0]==M.REFERENCE_SOURCE:exists=args[1] in (self.reference or {})
            else:exists=args[1] in (self.original if args[0]==ORIGINAL_ROOT else self.copy)
            return subprocess.CompletedProcess(command,0 if exists else 1,
                _frame(json.dumps(self.meta.get((args[0],args[1]),META)).encode(),'METADATA') if exists else '', '')
        if verb=='prepare-reference':
            self.calls.append(verb);assert self.reference is None
            self.reference={};self.reference_other={};return subprocess.CompletedProcess(command,0,'','')
        if verb=='copy-reference':
            self.calls.append(verb)
            paths=base64.b64decode(input,validate=True).decode().rstrip('\0').split('\0')
            self.copied_reference_paths=paths
            for path in paths:self.reference[path]=self.original[path]
            return subprocess.CompletedProcess(command,0,'','')
        if verb=='retire-reference':
            self.calls.append(verb)
            if self.fail_retire:return subprocess.CompletedProcess(command,70,'','refusal')
            self.reference=None;self.reference_other={};return subprocess.CompletedProcess(command,0,'','')
        if args and args[0] in (M.REFERENCE_SOURCE,M.REFERENCE_ROOT):
            self.calls.append(verb);tree=self.reference if args[0]==M.REFERENCE_SOURCE else self.reference_other
            if verb=='write':tree[args[1]]=base64.b64decode(input,validate=True);output=''
            elif verb=='read':output=_frame(tree[args[1]],'BYTES')
            elif verb=='inventory':output=_inventory(tree)
            else:raise AssertionError(verb)
            return subprocess.CompletedProcess(command,0,output,'')
        if verb=='read' and args[0]==ORIGINAL_ROOT:
            self.calls.append(verb);return subprocess.CompletedProcess(command,0,_frame(self.original[args[1]],'BYTES'),'')
        result=super().run(command,timeout,input)
        if verb=='write' and args[0]==COPY_ROOT and self.corrupt_transfer:
            self.copy[args[1]]+=b'bad'
        return result


def prepared():
    old,remote,context=fixture()
    target='internal/pkg/source.go';raw=b'package pkg\nfunc Value() bool { return true }\n'
    files=dict(remote.original);files[target]=raw;files[M.ENGINE_PATH]=b'qualified immutable engine source\n'
    remote=MutationRemote(files)
    manifest=deepcopy(old.original_manifest);manifest.digests={p:digest(b) for p,b in files.items()}
    copy=ExecutionCopy(remote,original_inventory=manifest.digests,boundary=old.original_boundary,original_manifest=manifest)
    candidate=b'package httpserver\n// candidate does not import the target package\n'
    remote.original[context['glue_path']]=candidate
    copy.prepare(context,{context['glue_path']:candidate},{},allowed_paths=(context['glue_path'],))
    copy.run_planner(['trusted-interposer']);copy.finalize({'external/httpserver/zz_r2t_harness_test.go':b'package httpserver\n'})
    offset=raw.index(b'true');column=offset-raw.rfind(b'\n',0,offset)
    row={'file':target,'operator':'TrueValue','start_line':2,'start_col':column,'end_line':2,'end_col':column+3,'original':'true','mutated':'false'}
    reference=dict(files);reference.pop(M.ENGINE_PATH)
    reference[context['glue_path']]=b'package httpserver\nimport _ "fixture/internal/pkg"\n'
    request={'contexts':[{'root':M.REFERENCE_SOURCE,'package_dir':context['package_dir'],'package_name':context['package_name'],
        'glue_path':context['glue_path'],'go_build_tags':context['go_build_tags']}],
        'source_files':{p:digest(raw) for p,raw in reference.items()}}
    kwargs={'reference_files':reference,'engine_request':request,'engine_sha256':digest(files[M.ENGINE_PATH])}
    def engine(r):
        argv=r.executables[-1]
        assert ORIGINAL_ROOT+'/'+M.ENGINE_PATH in argv
        assert 'GOCACHE='+M.REFERENCE_CACHE in argv and 'GOTMPDIR='+M.REFERENCE_ROOT+'/tmp' in argv
        assert r.copy[context['glue_path']]==candidate
        assert b'fixture/internal/pkg' in r.reference[context['glue_path']]
        assert json.loads(r.reference_other['context.json'])==request
        changed=M.splice(r.reference[target],row);r.reference[target]=changed
        if r.break_reference:r.reference['go.mod']+=b'unexpected'
        r.outputs['stdout.log']=json.dumps({'file':target,'applied':True,'original_sha256':digest(raw),'mutated_sha256':digest(changed),'metadata':META}).encode()
        return 0
    remote.effect=engine
    return copy,remote,context,row,kwargs,candidate


class MutationCopyTests(unittest.TestCase):
    def test_exact_transfer_original_analysis_and_same_copy_execution(self):
        copy,remote,context,row,kwargs,candidate=prepared();expected=deepcopy(copy._expected)
        with M.mutation_attempt(copy,row,**kwargs) as proof:
            self.assertEqual(copy.pre_mutation_inventory,expected)
            self.assertEqual(copy._expected,expected)
            self.assertEqual(copy.expected_mutations,{row['file']:digest(remote.copy[row['file']])})
            self.assertTrue(proof['reference_retired']);self.assertIsNone(remote.reference)
            self.assertEqual(remote.calls.count('copy-reference'),1)
            self.assertNotIn(context['glue_path'],remote.copied_reference_paths)
            self.assertNotIn(M.ENGINE_PATH,remote.copied_reference_paths)
            self.assertEqual(remote.copy[context['glue_path']],candidate)
            self.assertEqual(copy.read_metadata(row['file']),META)
            protected=copy.verify();self.assertEqual(protected['copy']['mutated'],[row['file']])
            self.assertEqual(protected['original']['mutated'],[])
            before_copy=remote.copy
            def candidate_effect(r):
                self.assertIsNone(r.reference);self.assertIs(r.copy,before_copy)
                self.assertIn(b'return false',r.copy[row['file']]);return 0
            remote.effect=candidate_effect;copy.execute(['selected-test'])
            self.assertEqual([r['phase'] for r in copy.command_evidence],['planner','mutation','execution'])
        self.assertEqual(copy._state,'idle');self.assertIsNone(remote.copy)
        self.assertIsNone(copy.pre_mutation_inventory);self.assertEqual(copy.expected_mutations,{})
        self.assertIn(b'return true',remote.original[row['file']])

    def test_reference_build_cache_persists_outside_retired_and_protected_roots(self):
        cache=M.REFERENCE_CACHE
        for root in (M.REFERENCE_ROOT,RUN_ROOT,COPY_ROOT,ORIGINAL_ROOT):
            self.assertFalse(cache==root or cache.startswith(root+'/'),root)
        self.assertNotEqual(cache,'/r2t-go/cache')  # the execution phase's own GOCACHE
        copy,remote,context,row,kwargs,candidate=prepared();engine=remote.effect;seen=[]
        def observed(r):
            seen.append([a for a in r.executables[-1] if a.split('=')[0] in ('GOCACHE','GOTMPDIR','TMPDIR')])
            return engine(r)
        for attempt in range(2):
            if attempt:
                remote.effect=None
                copy.prepare(context,{context['glue_path']:candidate},{},allowed_paths=(context['glue_path'],))
                copy.run_planner(['trusted-interposer'])
                copy.finalize({'external/httpserver/zz_r2t_harness_test.go':b'package httpserver\n'})
            remote.effect=observed
            with M.mutation_attempt(copy,row,**kwargs) as proof:
                self.assertTrue(proof['reference_retired']);self.assertIsNone(remote.reference)
        per_attempt=['GOCACHE='+cache,'GOTMPDIR='+M.REFERENCE_ROOT+'/tmp','TMPDIR='+M.REFERENCE_ROOT+'/tmp']
        self.assertEqual(seen,[per_attempt,per_attempt])
        self.assertEqual([c for c in remote.calls if c.endswith('-reference')],
                         ['prepare-reference','copy-reference','retire-reference']*2)

    def test_unexpected_reference_or_candidate_edit_quarantines(self):
        for which in ('reference','transfer','post-execution'):
            with self.subTest(which=which):
                copy,remote,context,row,kwargs,_=prepared()
                if which=='reference':remote.break_reference=True
                if which=='transfer':remote.corrupt_transfer=True
                with self.assertRaises(ExecutionRefused):
                    with M.mutation_attempt(copy,row,**kwargs):
                        remote.effect=lambda r:r.copy.update({'go.mod':b'tampered'}) or 0
                        copy.execute(['selected-test'])
                self.assertTrue(copy.quarantined)
                self.assertEqual(copy._mutation_baseline[row['file']],digest(kwargs['reference_files'][row['file']]))

    def test_metadata_change_and_reference_cleanup_failure_quarantine(self):
        copy,remote,context,row,kwargs,_=prepared()
        M.apply_mutation(copy,row,**kwargs)
        remote.meta[(COPY_ROOT,row['file'])]=dict(META,mode=0o100600)
        with self.assertRaises(ExecutionIntegrityError):copy.verify()
        self.assertTrue(copy.quarantined)
        copy,remote,context,row,kwargs,_=prepared();remote.fail_retire=True
        with self.assertRaises(ExecutionRefused):M.apply_mutation(copy,row,**kwargs)
        self.assertTrue(copy.quarantined)
        with self.assertRaises(ExecutionRefused):copy.execute(['selected-test'])

    def test_only_added_files_after_a_mutant_test_retire_as_unscorable(self):
        # Owner ruling 2026-09-30: the one shape that frees a quarantined copy.
        added='external/httpserver/config.yaml';target='internal/pkg/source.go'
        def mutant_test(effect):
            copy,remote,context,row,kwargs,candidate=prepared()
            M.apply_mutation(copy,row,**kwargs)
            def execute(r):
                effect(r);return 0
            remote.effect=execute
            with self.assertRaises(ExecutionIntegrityError) as caught:copy.execute(['selected-test'])
            return copy,remote,context,candidate,caught.exception
        copy,remote,context,candidate,error=mutant_test(lambda r:r.copy.update({added:b'test output\n'}))
        self.assertEqual((error.phase,error.scope),('executed','protected_substrate'))
        reports=copy.retire_unscorable()
        self.assertEqual(reports,error.reports);self.assertEqual(set(reports),{'copy','original'})
        self.assertEqual((reports['copy']['added'],reports['copy']['mutated']),([added],[target]))
        self.assertFalse(copy.quarantined);self.assertEqual(copy._state,'idle');self.assertIsNone(remote.copy)
        self.assertEqual(copy.expected_mutations,{});self.assertIsNone(copy.pre_mutation_inventory)
        self.assertEqual(remote.calls[-2:],['retire','inventory'])
        remote.effect=None  # the worker takes its next pair on a fresh copy
        copy.prepare(context,{context['glue_path']:candidate},{},allowed_paths=(context['glue_path'],))
        copy.run_planner(['trusted-interposer']);copy.finalize({'external/httpserver/zz_r2t_harness_test.go':b'package httpserver\n'})
        self.assertEqual(copy.execute(['selected-test']).returncode,0);copy.retire()
        # Every other violation after the mutant test keeps today's quarantine.
        for label,effect in {
                'changed':lambda r:r.copy.update({added:b'x','go.mod':b'changed'}),
                'missing':lambda r:(r.copy.update({added:b'x'}),r.copy.pop('go.sum')),
                'unmutated':lambda r:r.copy.update({added:b'x',target:r.original[target]}),
                'original':lambda r:(r.copy.update({added:b'x'}),r.original.update({'internal/pkg/extra.go':b'x'})),
                'metadata':lambda r:(r.copy.update({added:b'x'}),r.meta.update({(COPY_ROOT,target):dict(META,mode=0o100600)}))}.items():
            with self.subTest(label=label):
                copy,remote,*_=mutant_test(effect);calls=list(remote.calls)
                self.assertIsNone(copy.retire_unscorable())
                self.assertTrue(copy.quarantined);self.assertEqual(remote.calls,calls);self.assertIn(added,remote.copy)
        # The same addition outside the executed mutant test: the unmutated
        # (gold baseline) test, the planner, the mutation applier, and a test
        # whose child cleanup was not proved.
        def adds(r):
            r.copy[added]=b'x';return 0
        baseline,remote,context=fixture()
        baseline.prepare(context,None,{},allowed_paths=(context['glue_path'],));remote.effect=adds
        with self.assertRaises(ExecutionIntegrityError):baseline.execute(['go','test'])
        planner,remote,context=fixture()
        planner.prepare(context,None,{},allowed_paths=(context['glue_path'],));remote.effect=adds
        with self.assertRaises(ExecutionIntegrityError) as caught:planner.run_planner(['trusted-interposer'])
        self.assertEqual(caught.exception.scope,'planner_copy')
        applier,remote,context,row,kwargs,_=prepared();engine=remote.effect
        remote.effect=lambda r:engine(r) or adds(r)
        with self.assertRaises(ExecutionIntegrityError) as caught:M.apply_mutation(applier,row,**kwargs)
        self.assertEqual(caught.exception.phase,'ready')
        unproved,remote,context,row,kwargs,_=prepared();M.apply_mutation(unproved,row,**kwargs)
        remote.effect=adds;remote.fault='cleanup'
        with self.assertRaises(ExecutionRefused):unproved.execute(['selected-test'])
        for copy in (baseline,planner,applier,unproved):
            calls=list(copy.runner.calls)
            self.assertIsNone(copy.retire_unscorable());self.assertTrue(copy.quarantined)
            self.assertEqual(copy.runner.calls,calls)
        # A failed retirement or an original changed meanwhile stays quarantined.
        copy,remote,*_=mutant_test(adds);remote.fault='retire'
        with self.assertRaises(ExecutionRefused):copy.retire_unscorable()
        self.assertTrue(copy.quarantined)
        copy,remote,*_=mutant_test(adds)
        remote.after_call=lambda verb:verb=='retire' and remote.original.update({'go.mod':b'changed'})
        with self.assertRaisesRegex(ExecutionRefused,'original changed'):copy.retire_unscorable()
        self.assertTrue(copy.quarantined)

    def test_malformed_engine_response_quarantines_before_transfer(self):
        copy,remote,context,row,kwargs,_=prepared();engine=remote.effect
        before=remote.copy[row['file']]
        def malformed(r):
            engine(r);r.outputs['stdout.log']=b'[]';return 0
        remote.effect=malformed
        with self.assertRaises(ExecutionRefused):M.apply_mutation(copy,row,**kwargs)
        self.assertTrue(copy.quarantined)
        self.assertEqual(remote.copy[row['file']],before)
        self.assertEqual(copy.expected_mutations,{})

    def test_refused_engine_retires_without_running_unmutated_candidate(self):
        copy,remote,context,row,kwargs,_=prepared()
        remote.effect=lambda r:r.outputs.update({'stdout.log':b'reference descriptor refused'}) or 1
        with self.assertRaises(ExecutionRefused):
            with M.mutation_attempt(copy,row,**kwargs):self.fail('refusal accepted')
        self.assertFalse(copy.quarantined);self.assertEqual(copy._state,'idle');self.assertIsNone(remote.reference)
        self.assertEqual([r['phase'] for r in copy.command_evidence],['planner','mutation'])

    def test_no_measurement_no_observed_pre_and_no_context_guessing(self):
        copy,remote,context,row,kwargs,_=prepared();calls=len(remote.calls)
        with self.assertRaises(ExecutionRefused):M.apply_mutation(copy,row,measurement=True,**kwargs)
        self.assertEqual(len(remote.calls),calls)
        bad=deepcopy(kwargs);bad['engine_request']['contexts'][0]['go_build_tags']=['cli']
        with self.assertRaises(ExecutionRefused):M.apply_mutation(copy,row,**bad)
        self.assertEqual(len(remote.calls),calls)
        forged=deepcopy(kwargs);forged['reference_files']['go.mod']+=b'changed'
        forged['engine_request']['source_files']['go.mod']=digest(forged['reference_files']['go.mod'])
        with self.assertRaises(ExecutionRefused):M.apply_mutation(copy,row,**forged)
        self.assertEqual(len(remote.calls),calls)
        expected_mod=copy._expected['go.mod']
        remote.copy['go.mod']+=b'changed-before-baseline'
        with self.assertRaises(ExecutionIntegrityError):M.apply_mutation(copy,row,**kwargs)
        self.assertEqual(copy.pre_mutation_inventory['go.mod'],expected_mod)
        self.assertNotEqual(copy.pre_mutation_inventory['go.mod'],digest(remote.copy['go.mod']))
        self.assertTrue(copy.quarantined)

    def test_callback_and_timeout_paths_discard_reference_and_candidate(self):
        copy,remote,context,row,kwargs,_=prepared()
        with self.assertRaisesRegex(RuntimeError,'callback'):
            with M.mutation_attempt(copy,row,**kwargs):raise RuntimeError('callback')
        self.assertEqual(copy._state,'idle');self.assertIsNone(remote.reference);self.assertFalse(copy.quarantined)
        for phase in ('reference','candidate'):
            with self.subTest(phase=phase):
                copy,remote,context,row,kwargs,_=prepared()
                engine=remote.effect
                def expire(r):
                    if phase=='reference':engine(r)
                    r.outputs['stdout.log']=b'actual expired command output'
                    r.outputs['timeout.log']=b'timeout: sending signal TERM to command\n'
                    copy._deadline=time.monotonic()-1
                    return 124
                if phase=='reference':remote.effect=expire
                with self.assertRaises(ExecutionTimeout):
                    with M.mutation_attempt(copy,row,**kwargs):
                        remote.effect=expire;copy.execute(['selected-test'])
                self.assertEqual(copy._state,'idle');self.assertIsNone(remote.reference)
                self.assertFalse(copy.quarantined);self.assertEqual(copy.expected_mutations,{})
                self.assertEqual(copy.command_evidence[-1]['stdout'],'actual expired command output')

    def test_real_shell_metadata_and_reference_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='mutation-metadata-') as directory:
            root=Path(directory);target=root/'source.go';target.write_bytes(b'package fixture\n');target.chmod(0o640)
            command=['/bin/bash','-c',_SUPPORT,'r2t-execution','metadata',str(root),'source.go']
            result=subprocess.run(command,capture_output=True,text=True,check=True)
            observed=json.loads(_payload(result.stdout,'METADATA'));info=target.stat()
            self.assertEqual(observed,{'mode':info.st_mode,'uid':info.st_uid,'gid':info.st_gid})
            (root/'link.go').symlink_to(target)
            self.assertNotEqual(subprocess.run(command[:-1]+['link.go'],capture_output=True).returncode,0)
            original=root/'original';original.mkdir();(original/'source.go').write_bytes(target.read_bytes());(original/'source.go').chmod(0o640)
            (original/'candidate_answer.go').write_text('do not copy')
            (original/'resource.txt').write_text('embedded resource')
            support=_SUPPORT.replace('/r2t-go',str(root/'worker')).replace('/work/',str(original)+'/');(root/'worker/run').mkdir(parents=True)
            subprocess.run(['/bin/bash','-c',support,'r2t-execution','prepare-reference'],check=True)
            reference=root/'worker/run/mutation-reference'
            cache=root/'worker'/M.REFERENCE_CACHE.removeprefix('/r2t-go/')
            self.assertEqual(sorted(p.name for p in reference.iterdir()),['tmp'])
            self.assertTrue(cache.is_dir());self.assertEqual(list(cache.iterdir()),[])
            names=base64.b64encode(b'source.go\0resource.txt\0')
            subprocess.run(['/bin/bash','-c',support,'r2t-execution','copy-reference'],input=names,check=True)
            self.assertEqual(sorted(p.name for p in (reference/'source').iterdir()),['resource.txt','source.go'])
            self.assertEqual((reference/'source/source.go').read_bytes(),target.read_bytes())
            before=(original/'source.go').stat();after=(reference/'source/source.go').stat()
            self.assertEqual((before.st_mode,before.st_uid,before.st_gid),(after.st_mode,after.st_uid,after.st_gid))
            (reference/'source/gold.go').write_text('original answer')
            (reference/'tmp/export').write_text('original answer temporary build file')
            (cache/'00').mkdir();(cache/'00/entry-d').write_text('content-addressed build output')
            subprocess.run(['/bin/bash','-c',support,'r2t-execution','retire-reference'],check=True)
            self.assertFalse(reference.exists())
            # The next copy's retire/prepare recreate the run root, never the
            # worker's reference cache; the next reference root starts empty.
            subprocess.run(['/bin/bash','-c',support,'r2t-execution','retire'],check=True)
            self.assertFalse((root/'worker/run').exists());(root/'worker/run').mkdir()
            subprocess.run(['/bin/bash','-c',support,'r2t-execution','prepare-reference'],check=True)
            self.assertEqual(sorted(p.name for p in reference.iterdir()),['tmp'])
            self.assertEqual(list((reference/'tmp').iterdir()),[])
            self.assertEqual((cache/'00/entry-d').read_text(),'content-addressed build output')
            subprocess.run(['/bin/bash','-c',support,'r2t-execution','retire-reference'],check=True)
            self.assertFalse(reference.exists());self.assertTrue((cache/'00/entry-d').is_file())


def selftest():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MutationCopyTests))
    return 0 if result.wasSuccessful() else 1

if __name__=='__main__':raise SystemExit(selftest())
