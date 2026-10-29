"""Runtime envelopes over real bound seed inputs and preserved native streams.

The remote transport is replayed; these tests claim no new native qualification.
Control orchestration tests stop at its capture seam, leaving native witness and
placeholder semantics to their existing focused/native qualifications.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ..bench.harness import RunResult, Solution
from ..bench import repo
from ..core.gherkin import parse_feature_file
from ..stacks import godog
from . import runtime
from .controls import PreparedControl
from .execution import ExecutionCopy, ExecutionIntegrityError
from .execution_selftest import Remote
from .registry import (NativeCapture, NativeCaptureError, command, planner_command,
                       read_runtime_native, source_selection)
from .closure import extract_closure
from .workspace_selftest import _fixture


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='go-runtime-')
        self.addCleanup(self.temp.cleanup)
        self.fixture = _fixture(Path(self.temp.name))
        self.harness, _, _ = godog.make_harness(self.fixture.args)
        self.context = self.fixture.context
        self.feature = parse_feature_file(str(self.fixture.workspace/self.context['feature_path']))
        self.scenario = self.feature.scenario_at(self.context['scenario_line'])
        self.native_dir = Path(__file__).with_name('fixtures')/'native'
        self.native = (self.native_dir/'native.jsonl').read_bytes()
        self.plan = (self.native_dir/'plan.json').read_bytes()
        self.solution = Solution.from_json({'files':[{'file_path':path,
            'code':(self.fixture.gold/path).read_text()} for path in self.fixture.answers]})
        self.closure = json.loads(self.fixture.closures.read_text())[0]
        root = self.fixture.workspace
        class WorkspaceTransport(Remote):
            def run(remote, source, timeout, input=None):
                remote.original = {p.relative_to(root).as_posix():p.read_bytes()
                                   for p in root.rglob('*') if p.is_file()}
                words = shlex.split(source)
                if words[5] == 'execute': remote.argv = words[7:]
                return super().run(source, timeout, input)
        self.remote = WorkspaceTransport({})
        self.harness.copy = ExecutionCopy(self.remote,
            original_inventory=self.harness.copy.original_inventory,
            boundary=self.harness.boundary, original_manifest=self.harness.manifest)
        self.queue = []
        def effect(remote):
            self.assertTrue(self.queue, 'unexpected native invocation')
            expected, result = self.queue.pop(0)
            self.assertEqual(remote.argv, expected)
            return result(remote)
        self.remote.effect = effect

    def capture(self, raw=None, code=0, *, effect=None):
        self.queue.append((planner_command(self.context, runtime_diagnostics=True),
            lambda r: r.outputs.update({'stdout.log':self.plan}) or 0))
        def execute(r):
            r.outputs['stdout.log'] = b'fixture native output\n'
            if raw is not None: r.outputs['native.jsonl'] = raw
            if effect is not None: return effect(r)
            return code
        self.queue.append((command(self.context),execute))

    def run_candidate(self, **options):
        return self.harness.run_solution(self.feature, self.scenario,
                                         self.solution, **options)

    def test_multifile_repeats_fold_and_public_facade(self):
        self.capture(self.native); self.capture(self.native,1)
        # Actual coordinator lock bytes must reach every original-copy guard.
        lock=self.fixture.workspace/'.r2t-exec.lock';lock.write_text(f'{os.getpid()}\n')
        result=self.run_candidate(repeats=2, coverage=False, keep_stdout=True)
        self.assertEqual(result['written_files'],self.fixture.answers)
        self.assertEqual(result['outcomes'],['passed','passed_but_nonzero_exit'])
        self.assertEqual(result['runs'][0]['expected_lines'],[20,21,25,26])
        self.assertEqual(len(result['runs'][0]['records']),4)
        self.assertTrue(all(r['coverage'] is None and r['direct_calls'] is None
                            for run in result['runs'] for r in run['records']))
        self.assertFalse(result['collection_complete'])
        self.assertTrue(all('control_preparation' not in run and 'control_witness' not in run
                            for run in result['runs']))
        self.assertEqual(self.remote.calls.count('prepare'),2)
        self.assertEqual(self.remote.calls.count('retire'),2)
        self.assertFalse(self.queue)
        self.assertTrue((self.fixture.workspace/'_bench/run_record.jsonl').is_file())
        self.assertIs(godog.GodogHarness.run_solution,runtime.run_solution)
        self.assertIs(godog.GodogHarness.run_control,runtime.run_control)

    def test_runtime_preserves_raw_capture_for_each_attempt(self):
        evidence = Path(self.temp.name)/'native-evidence'
        evidence.mkdir()
        self.capture(self.native); self.capture(self.native)
        result=self.run_candidate(evidence_dir=evidence,repeats=2)
        self.assertEqual(result['outcomes'],['passed','passed'])
        for number in ('1','2'):
            folder=evidence/number
            self.assertEqual((folder/'native.jsonl').read_bytes(),self.native)
            capture=json.loads((folder/'capture.json').read_text())
            self.assertTrue(capture['retired'])
            self.assertEqual(len(capture['commands']),2)
            self.assertEqual((folder/'original_answers'/self.context['glue_path']).read_bytes(),
                             self.solution.files[0].code.encode())
        with self.assertRaises(runtime.RuntimeRefused):
            self.run_candidate(evidence_dir=evidence)
        self.assertFalse(self.queue)

    def test_coordinator_mutation_request_and_per_attempt_proof(self):
        authority = {'descriptor': {'file':'internal/r2tfixture/api.go'},
                     'reference_files': {}, 'engine_request': {}, 'engine_sha256':'a'*64}
        proofs = []
        def capture(copy_, **kwargs):
            self.assertIs(copy_,self.harness.copy)
            self.assertIs(kwargs['mutation'],authority)
            self.assertFalse(kwargs['measurement'])
            self.assertFalse(kwargs['control'])
            proof = {'attempt': len(proofs)+1, 'reference_retired':True}
            proofs.append(proof)
            return NativeCapture(self.context, phase='captured',
                planner=subprocess.CompletedProcess([],0,self.plan.decode(),''),
                completed=subprocess.CompletedProcess([],0,'mutated fixture',''),
                source_map=json.loads(self.plan)['map'],native=self.native,
                mutation_evidence=proof,retired=True)
        with patch('r2t.go.runtime.capture_execution',side_effect=capture) as observed:
            result=self.run_candidate(mutation=authority,repeats=2)
            self.assertEqual(observed.call_count,2)
        self.assertEqual(result['outcomes'],['passed','passed'])
        self.assertEqual([r['go_mutation'] for r in result['runs']],proofs)
        self.assertEqual(self.harness.expected_mutations,{})
        self.assertFalse(result['collection_complete'])
        proofs[0]['reference_retired']=False
        self.assertTrue(result['runs'][0]['go_mutation']['reference_retired'])
        with patch('r2t.go.runtime.capture_execution') as observed:
            with self.assertRaises(runtime.RuntimeRefused):
                self.run_candidate(mutation=authority,coverage=True)
            observed.assert_not_called()

    def _crashed(self, native, code, stdout, *, mutation=True):
        """One attempt whose proved capture ended as `stdout` describes."""
        authority = {'descriptor': {'file':'internal/r2tfixture/api.go'},
                     'reference_files': {}, 'engine_request': {}, 'engine_sha256':'a'*64}
        def capture(copy_, **kwargs):
            self.assertIs(kwargs['mutation'], authority if mutation else None)
            return NativeCapture(self.context, phase='captured',
                planner=subprocess.CompletedProcess([],0,self.plan.decode(),''),
                completed=subprocess.CompletedProcess([],code,stdout,''),
                source_map=json.loads(self.plan)['map'],native=native,
                mutation_evidence={'reference_retired':True} if mutation else None,retired=True)
        with patch('r2t.go.runtime.capture_execution',side_effect=capture):
            return self.run_candidate(**({'mutation':authority} if mutation else {}))

    def _output(self, name):
        """Real `go test` bytes, with its package result naming this fixture's."""
        text = (self.native_dir.with_name('crash')/name).read_text()
        self.assertIn('\tgithub.com/EvilFreelancer/coddy-agent/external/cli\t', text)
        return text.replace('github.com/EvilFreelancer/coddy-agent/external/cli',
                            'fixture/'+self.context['package_dir'])

    def test_mutant_crash_with_consistent_prefix_is_a_disclosed_kill(self):
        lines = self.native.splitlines(keepends=True)
        truncated = b''.join(lines[:7])
        self.assertEqual(json.loads(lines[6])['event'], 'defined')
        cases = [(truncated, 1, 'stdout-hw2.txt', 'go_panic'), (truncated, 1, 'stdout-hw3.txt', 'go_panic'),
                 (b''.join(lines[:-1]), 1, 'stdout-hw4.txt', 'go_panic'),
                 (b'', 1, 'stdout-hw2.txt', 'go_panic'), (None, 1, 'stdout-hw2.txt', 'go_panic'),
                 (truncated, 1, 'go125-production-panic-subtest.txt', 'go_panic'),
                 (truncated, 1, 'go125-deadlock.txt', 'go_fatal_error'),
                 (truncated, 2, 'go125-deadlock.txt', 'go_fatal_error')]
        for native, code, name, label in cases:
            with self.subTest(native=native and len(native), code=code, name=name):
                result = self._crashed(native, code, self._output(name))
                run = result['runs'][0]
                self.assertEqual(result['outcomes'], ['failed'])
                self.assertEqual((run['outcome'], run['crash'], run['exit_code'], run['records']),
                                 ('failed', label, code, []))
                self.assertEqual(run['go_mutation'], {'reference_retired': True})
                self.assertFalse(result['collection_complete'])
                from ..bench.runner import _record
                row = _record('i', {}, {'files': []}, 0.0, result)
                self.assertEqual((row['outcome'], row['crash']), ('failed', label))
                from ..bench.mutation_run import INFRASTRUCTURE_OUTCOMES
                self.assertNotIn(row['outcome'], INFRASTRUCTURE_OUTCOMES)

    def test_mutant_failed_before_hook_is_the_literal_failure(self):
        """Godog's complete record of a failed Before hook, as reference attempt 4's supplement met it."""
        events = [json.loads(line) for line in self.native.splitlines()]
        first = {e['pickle']['id']: e['pickle']['steps'][0]['id'] for e in events if e['event'] == 'pickle'}
        events = [e for e in events if not (e['event'] == 'defined' and first[e['pickle_id']] == e['step']['id'])]
        for e in events:
            if e['event'] == 'status':
                if first[e['pickle_id']] == e['step_id']:
                    e.update(status='failed', error='runtime error: invalid memory address or nil pointer dereference')
                else:
                    e['status'] = 'skipped'
            if e['event'] == 'exit':
                e['code'] = 1
        hooked = ('\n'.join(json.dumps(e) for e in events) + '\n').encode()
        stdout = '--- FAIL: TestFixture (0.00s)\nFAIL\nFAIL\tfixture/internal/r2tfixture\t0.017s\nFAIL\n'
        result = self._crashed(hooked, 1, stdout)
        run = result['runs'][0]
        self.assertEqual(result['outcomes'], ['failed'])
        self.assertNotIn('crash', run)
        self.assertEqual(run['go_mutation'], {'reference_retired': True})
        from ..bench.runner import _record
        from ..bench.mutation_run import INFRASTRUCTURE_OUTCOMES
        row = _record('i', {}, {'files': []}, 0.0, result)
        self.assertEqual(row['outcome'], 'failed')
        self.assertNotIn(row['outcome'], INFRASTRUCTURE_OUTCOMES)
        # Without a mutation the same stream is still an inconsistent witness,
        # and a mutation attempt keeps refusing a native/Go exit disagreement.
        with self.assertRaises(runtime.RuntimeRefused):
            self._crashed(hooked, 1, stdout, mutation=False)
        with self.assertRaises(runtime.RuntimeRefused):
            self._crashed(hooked, 0, stdout)

    def test_crash_rule_keeps_every_other_refusal_and_verdict(self):
        lines = self.native.splitlines(keepends=True)
        truncated = b''.join(lines[:7])
        panic = self._output('stdout-hw2.txt')
        refused = [('no crash signature', truncated, 1, 'FAIL\tfixture/internal/r2tfixture\t0.1s\nFAIL\n', True),
                   ('non-test exit', truncated, 3, panic, True),
                   ('successful exit', truncated, 0, panic, True),
                   ('partial final record', truncated[:-1], 1, panic, True),
                   ('foreign event', truncated + b'{"event": "other"}\n', 1, panic, True),
                   ('complete stream with exit 2', self.native, 2, panic, True),
                   ('harness support panic', truncated, 1, self._output('go125-support-panic.txt'), True),
                   ('recorder panic under t.Run', truncated, 1,
                    self._output('go125-recorder-panic-subtest.txt'), True),
                   ('go test timeout', truncated, 1, self._output('go125-test-timeout.txt'), True),
                   ('ordinary candidate run', truncated, 1, panic, False)]
        for label, native, code, stdout, mutation in refused:
            with self.subTest(label):
                with self.assertRaises(runtime.RuntimeRefused):
                    self._crashed(native, code, stdout, mutation=mutation)
        # An empty recorder keeps today's infrastructure outcome when the crash
        # is not the mutant's or no mutation was applied.
        for stdout, mutation in ((self._output('go125-support-panic.txt'), True), (panic, False)):
            result = self._crashed(b'', 1, stdout, mutation=mutation)
            self.assertEqual(result['outcomes'], ['no_scenario_ran'])
            self.assertNotIn('crash', result['runs'][0])
        # A complete witness keeps its own native verdict.
        result = self._crashed(self.native, 1, panic)
        self.assertEqual(result['outcomes'], ['passed_but_nonzero_exit'])
        self.assertNotIn('crash', result['runs'][0])

    def test_runtime_resource_exhaustion_is_retried_infrastructure(self):
        lines = self.native.splitlines(keepends=True)
        oom = self._output('go125-out-of-memory.txt')
        from ..bench.mutation_run import INFRASTRUCTURE_OUTCOMES as RETRIED
        from ..data.mutation import INFRASTRUCTURE_OUTCOMES as EXCLUDED
        for native in (b''.join(lines[:7]), b''):
            result = self._crashed(native, 1, oom)
            self.assertEqual(result['outcomes'], ['container_error'])
            self.assertNotIn('crash', result['runs'][0])
            self.assertIn('container_error', RETRIED & EXCLUDED)
        with self.assertRaises(runtime.RuntimeRefused):
            self._crashed(b''.join(lines[:7])[:-1], 1, oom)

    def test_sigkilled_test_binary_is_retried_infrastructure(self):
        # Real `go test` output of two OOM-killed attempts (KilledTestBinaryTests).
        lines = self.native.splitlines(keepends=True)
        truncated = b''.join(lines[:7])
        for name in ('oom-hw3-stdout.txt', 'oom-hw9-stdout.txt'):
            killed = self._output(name)
            for native in (truncated, b'', None):
                with self.subTest(name=name, native=native and len(native)):
                    result = self._crashed(native, 1, killed)
                    run = result['runs'][0]
                    self.assertEqual((result['outcomes'], run['records']), (['container_error'], []))
                    self.assertNotIn('crash', run)
                    self.assertEqual(run['go_mutation'], {'reference_retired': True})
            with self.subTest(name=name, case='partial final record'):
                with self.assertRaises(runtime.RuntimeRefused):
                    self._crashed(truncated[:-1], 1, killed)
            # An ordinary candidate run classifies no test-process crash.
            with self.subTest(name=name, case='ordinary candidate run'):
                with self.assertRaises(runtime.RuntimeRefused):
                    self._crashed(truncated, 1, killed, mutation=False)
                result = self._crashed(b'', 1, killed, mutation=False)
                self.assertEqual(result['outcomes'], ['no_scenario_ran'])

    def test_route_b_crash_readings_are_disclosed_kills(self):
        """Patch P2: the two candidate crashes route B read as kills (CrashSignatureTests)."""
        lines = self.native.splitlines(keepends=True)
        truncated = b''.join(lines[:7])
        from ..bench.runner import _record
        from ..bench.mutation_run import INFRASTRUCTURE_OUTCOMES
        for name, label in (('cleanup-panic-hw3-stdout.txt', 'go_panic'),
                            ('parent-failnow-hw9-stdout.txt', 'go_parent_failnow')):
            stdout = self._output(name)
            for native in (truncated, b'', None):
                with self.subTest(name=name, native=native and len(native)):
                    result = self._crashed(native, 1, stdout)
                    run = result['runs'][0]
                    self.assertEqual(result['outcomes'], ['failed'])
                    self.assertEqual((run['outcome'], run['crash'], run['exit_code'], run['records']),
                                     ('failed', label, 1, []))
                    row = _record('i', {}, {'files': []}, 0.0, result)
                    self.assertEqual((row['outcome'], row['crash']), ('failed', label))
                    self.assertNotIn(row['outcome'], INFRASTRUCTURE_OUTCOMES)
            with self.subTest(name=name, case='partial final record'):
                with self.assertRaises(runtime.RuntimeRefused):
                    self._crashed(truncated[:-1], 1, stdout)
            with self.subTest(name=name, case='ordinary candidate run'):
                with self.assertRaises(runtime.RuntimeRefused):
                    self._crashed(truncated, 1, stdout, mutation=False)
            with self.subTest(name=name, case='complete witness'):
                result = self._crashed(self.native, 1, stdout)
                self.assertEqual(result['outcomes'], ['passed_but_nonzero_exit'])
                self.assertNotIn('crash', result['runs'][0])

    def test_measured_capture_uses_shared_projection(self):
        from .measurement_selftest import projection_fixture
        captured, _, _ = projection_fixture()
        captured.mutation_evidence = None
        captured.planner = subprocess.CompletedProcess([],0,self.plan.decode(),'')
        captured.source_map = json.loads(self.plan)['map']
        captured.completed = subprocess.CompletedProcess([],0,'measurement fixture','')
        def capture(copy_, **kwargs):
            self.assertIs(copy_,self.harness.copy)
            self.assertTrue(kwargs['measurement'])
            self.assertFalse(kwargs['control'])
            self.assertEqual(kwargs['context'],self.context)
            return captured
        with patch('r2t.go.runtime.capture_execution',side_effect=capture):
            result=self.run_candidate(coverage=True)
        self.assertEqual(result['outcomes'],['passed'])
        self.assertTrue(result['collection_complete'])
        self.assertTrue(all(r['coverage'] is not None and r['direct_calls'] is not None
                            for r in result['runs'][0]['records']))

    def test_execute_and_current_candidate_bytes_keep_original_selection(self):
        self.harness.select(self.context['feature_path'],self.context['scenario_line'])
        self.harness.install_solution(self.solution,'criterion_to_test')
        self.capture(self.native)
        result=runtime.execute(self.harness,expected_line=6,expected_lines=[20,21,25,26])
        self.assertEqual(result.outcome,'passed')
        self.assertEqual(result.error_markers,())
        class Observed(Exception): pass
        changed=copy.deepcopy(self.solution)
        changed.files[0].code='\n\n'+changed.files[0].code
        def observe(copy_,**kwargs):
            self.assertIs(copy_,self.harness.copy)
            self.assertEqual(kwargs['context'],self.context)
            self.assertEqual(kwargs['original'],changed.files[0].code.encode())
            self.assertEqual(kwargs['installed'],{f.file_path:f.code.encode() for f in changed.files})
            raise Observed()
        with patch('r2t.go.runtime.capture_execution',side_effect=observe),self.assertRaises(Observed):
            runtime.run_solution(self.harness,self.feature,self.scenario,changed)

    def _helper_candidate(self):
        """Gold helper file declaring two helpers; the candidate declares one."""
        helper='internal/r2tfixture/bdd_helper_test.go'
        (self.fixture.gold/helper).write_text('package fixture\n\nimport "strings"\n\n'
            '// shout is support for retained tests.\n'
            'func shout(s string) string { return strings.ToUpper(s) }\n\n'
            'const quiet = "q"\n')
        candidate=copy.deepcopy(self.solution)
        next(f for f in candidate.files if f.file_path==helper).code=\
            'package fixture\n\nconst quiet = "mine"\n'
        return helper,candidate,{helper:('shout','quiet')}

    def test_every_candidate_receives_missing_gold_helpers_in_the_copy_only(self):
        from . import sensitivity
        helper,candidate,table=self._helper_candidate()
        target='internal/r2tfixture/zz_r2t_retained_helpers_bdd_helper_test.go'
        seen=[]
        def observe(remote):
            seen.append(remote.copy.get(target))
            return 0
        # No label and no option: harness 25 supplies the helpers by default.
        with patch.dict(sensitivity.RETAINED_HELPERS,table,clear=True):
            self.capture(self.native,effect=observe);self.capture(self.native,effect=observe)
            result=self.harness.run_solution(self.feature,self.scenario,candidate,repeats=2)
        self.assertEqual(result['outcomes'],['passed','passed'])
        self.assertEqual(result['supplied_helpers'],{helper:['shout']})
        self.assertEqual(seen[0],seen[1])
        self.assertEqual(seen[0].decode(),'// Supplied by the harness from '
            'internal/r2tfixture/bdd_helper_test.go for the retained tests.\n\npackage fixture\n\n'
            'import (\n\t"strings"\n)\n\n// shout is support for retained tests.\n'
            'func shout(s string) string { return strings.ToUpper(s) }\n')
        # The overlay exists only in the retired execution copy; the
        # candidate's bytes and the original workspace are untouched.
        self.assertFalse((self.fixture.workspace/target).exists())
        self.assertEqual((self.fixture.workspace/helper).read_text(),
                         'package fixture\n\nconst quiet = "mine"\n')
        # Gold declares every helper, so gold receives nothing and records so.
        gold=copy.deepcopy(self.solution)
        next(f for f in gold.files if f.file_path==helper).code=\
            (self.fixture.gold/helper).read_text()
        with patch.dict(sensitivity.RETAINED_HELPERS,table,clear=True):
            self.capture(self.native,effect=observe)
            result=self.harness.run_solution(self.feature,self.scenario,gold)
        self.assertIsNone(seen[-1])
        self.assertEqual(result['supplied_helpers'],{})
        self.assertFalse(self.queue)

    def test_a_mutation_attempt_receives_the_same_helpers(self):
        # A candidate scored under mutants runs with the helpers its baseline
        # ran with; otherwise every mutant would "kill" a compile error.
        from . import sensitivity
        helper,candidate,table=self._helper_candidate()
        target='internal/r2tfixture/zz_r2t_retained_helpers_bdd_helper_test.go'
        authority = {'descriptor': {'file':'internal/r2tfixture/api.go'},
                     'reference_files': {}, 'engine_request': {}, 'engine_sha256':'a'*64}
        supplied=[]
        def capture(copy_, **kwargs):
            self.assertIs(kwargs['mutation'],authority)
            supplied.append(sorted(p for p in kwargs['initial'] if 'zz_r2t_' in p))
            return NativeCapture(self.context, phase='captured',
                planner=subprocess.CompletedProcess([],0,self.plan.decode(),''),
                completed=subprocess.CompletedProcess([],0,'mutated fixture',''),
                source_map=json.loads(self.plan)['map'],native=self.native,
                mutation_evidence={'attempt':1},retired=True)
        with patch.dict(sensitivity.RETAINED_HELPERS,table,clear=True), \
                patch('r2t.go.runtime.capture_execution',side_effect=capture):
            result=self.harness.run_solution(self.feature,self.scenario,candidate,
                                             mutation=authority)
        self.assertEqual(supplied,[[target]])
        self.assertEqual(result['supplied_helpers'],{helper:['shout']})

    def test_a_compile_error_inside_the_supplied_helpers_is_attributed(self):
        from . import sensitivity
        helper,candidate,table=self._helper_candidate()
        target='internal/r2tfixture/zz_r2t_retained_helpers_bdd_helper_test.go'
        glue=self.context['glue_path']
        def planner(remote):
            row={'schema':'r2t.go-planner-diagnostic/1','attribution':'candidate','stage':'compile',
                 'file':glue,'message':'selected Go package does not type-check',
                 'package_dir':self.context['package_dir'],'package_name':self.context['package_name'],
                 'sources':{p:hashlib.sha256(remote.copy[p]).hexdigest() for p in (glue,target)},
                 'diagnostics':[{'file':target,'line':1,'column':1,'offset':0,
                                 'message':'shout redeclared in this block',
                                 'kind':'types.Error','soft':False}]}
            remote.outputs['stdout.log']=(runtime.DIAGNOSTIC_START+'\n'+json.dumps(row)+'\n'
                                          +runtime.DIAGNOSTIC_END+'\n').encode()
            return 1
        self.queue.append((planner_command(self.context,runtime_diagnostics=True),planner))
        with patch.dict(sensitivity.RETAINED_HELPERS,table,clear=True):
            result=self.harness.run_solution(self.feature,self.scenario,candidate)
        self.assertEqual(list(result['index_errors']),[target])
        self.assertEqual(result['supplied_helpers'],{helper:['shout']})
        self.assertFalse(self.queue)

    def test_a_gold_helper_it_cannot_find_refuses_the_attempt(self):
        from . import sensitivity
        helper,candidate,_=self._helper_candidate()
        with patch.dict(sensitivity.RETAINED_HELPERS,{helper:('absent',)},clear=True), \
                self.assertRaises(sensitivity.SensitivityRefused):
            self.harness.run_solution(self.feature,self.scenario,candidate)
        self.assertNotIn('execute',self.remote.calls)

    def test_the_retired_label_is_no_longer_a_run_option(self):
        # Harness 25 supplies the helpers on every candidate execution, so a
        # labelled replay would be a primary run under another name.
        import contextlib, io
        from ..bench import cli
        with contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as refused:
            cli.main(['run', '--adapter', 'replay', '--sensitivity', 'coddy_retained_helpers_v1'])
        self.assertEqual(refused.exception.code, 2)
        self.assertIn("invalid choice: 'coddy_retained_helpers_v1'", err.getvalue())

    def test_whole_file_and_wiring_rejections_make_no_write_or_control(self):
        cases=[]
        missing=copy.deepcopy(self.solution);missing.files.pop();cases.append(missing)
        duplicate=copy.deepcopy(self.solution);duplicate.files.append(duplicate.files[0]);cases.append(duplicate)
        foreign=copy.deepcopy(self.solution);foreign.files[0].file_path='../escape.go';cases.append(foreign)
        feature=copy.deepcopy(self.solution);feature.files[0].file_path=self.context['feature_path'];cases.append(feature)
        bad_code=copy.deepcopy(self.solution);bad_code.files[0].code=None;cases.append(bad_code)
        invalid_utf8=copy.deepcopy(self.solution);invalid_utf8.files[0].code='\ud800';cases.append(invalid_utf8)
        wiring=copy.deepcopy(self.solution);wiring.services_fragment={'service':{}};cases.append(wiring)
        empty=Solution(metadata={'mode':'empty','control':'noop'});cases.append(empty)
        with patch('r2t.go.runtime.prepare_control',side_effect=AssertionError('candidate repair')):
            for solution in cases:
                with self.subTest(solution=solution):
                    result=runtime.run_solution(self.harness,self.feature,self.scenario,solution)
                    self.assertEqual(result['written_files'],[])
                    self.assertEqual(result['runs'],[])
                    self.assertTrue(result['rejected_files'] or result['index_errors'])
                    # Nothing ran, so nothing was supplied: empty, not absent.
                    self.assertEqual(result['supplied_helpers'],{})
                    self.assertTrue(all(not (self.fixture.workspace/p).exists() for p in self.fixture.answers))
        self.assertEqual(self.remote.calls,[])

    def test_missing_native_and_unattributed_failures(self):
        # A nil-Options candidate reaches the wrapper, which creates the
        # recorder and then fails before its first event. Empty and absent
        # recorder outputs both mean no scenario ran, never a fabricated pass.
        for raw in (None,b''):
            for code in (0,1):
                with self.subTest(raw=raw,code=code):
                    self.capture(raw,code=code)
                    result=self.run_candidate()
                    self.assertEqual(result['outcomes'],['no_scenario_ran'])
                    self.assertEqual(result['runs'][0]['exit_code'],code)
                    self.assertEqual(result['runs'][0]['records'],[])
                    self.assertFalse(result['collection_complete'])
        self.capture(self.native[:-1],1)
        with self.assertRaises(runtime.RuntimeRefused):self.run_candidate()
        self.queue.append((planner_command(self.context, runtime_diagnostics=True),lambda r:r.outputs.update(
            {'stdout.log':b'undefined: ordinary compiler output without trusted attribution'}) or 1))
        with self.assertRaises(runtime.RuntimeRefused):self.run_candidate()
        self.assertFalse(self.queue)

    def test_structured_candidate_diagnostic_reaches_common_envelope(self):
        row={'schema':'r2t.go-planner-diagnostic/1','attribution':'candidate','stage':'parse',
             'file':self.context['glue_path'],'message':'actual parser diagnostic'}
        raw=(runtime.DIAGNOSTIC_START+'\n'+json.dumps(row)+'\n'+runtime.DIAGNOSTIC_END+'\nexit status 1\n').encode()
        self.queue.append((planner_command(self.context, runtime_diagnostics=True),lambda r:r.outputs.update({'stdout.log':raw}) or 1))
        result=self.run_candidate()
        self.assertIn(self.context['glue_path'],result['index_errors'])
        self.assertEqual(result['runs'][0]['exit_code'],1)
        self.assertEqual(self.remote.calls.count('execute'),1)
        row['file']='internal/foreign.go'
        with self.assertRaises(runtime.RuntimeRefused):
            runtime._candidate_diagnostic(runtime.DIAGNOSTIC_START+'\n'+json.dumps(row)+'\n'+runtime.DIAGNOSTIC_END,self.context)

    def test_compile_frame_authenticates_retained_sources_before_attribution(self):
        primary=self.context['glue_path'];retained='internal/r2tfixture/retained_test.go'
        sources={primary:self.solution.files[0].code.encode(),retained:(self.fixture.workspace/retained).read_bytes()}
        row={'schema':'r2t.go-planner-diagnostic/1','attribution':'candidate','stage':'compile',
             'file':primary,'message':'typed failure','package_dir':self.context['package_dir'],
             'package_name':self.context['package_name'],
             'sources':{p:hashlib.sha256(raw).hexdigest() for p,raw in sources.items()},
             'diagnostics':[{'file':retained,'line':1,'column':1,'offset':0,'message':'typed failure',
                             'kind':'types.Error','soft':False}]}
        def frame(value):return runtime.DIAGNOSTIC_START+'\n'+json.dumps(value)+'\n'+runtime.DIAGNOSTIC_END+'\n'
        self.assertIn(retained,runtime._candidate_diagnostic(frame(row),self.context,sources=sources))
        for change in ('foreign-file','wrong-offset','wrong-package','wrong-hash'):
            invalid=copy.deepcopy(row)
            if change=='foreign-file':invalid['diagnostics'][0]['file']='outside.go'
            elif change=='wrong-offset':invalid['diagnostics'][0]['offset']=1
            elif change=='wrong-package':invalid['package_name']='other'
            else:invalid['sources'][retained]='0'*64
            with self.assertRaises(runtime.RuntimeRefused):
                runtime._candidate_diagnostic(frame(invalid),self.context,sources=sources)

    def test_complete_undefined_and_incomplete_outline(self):
        events=[json.loads(line) for line in self.native.splitlines()]
        for e in events:
            if e['event']=='defined':e['matched']=False
            if e['event']=='status':e['status']='undefined'
            if e['event']=='exit':e['code']=1
        raw=('\n'.join(json.dumps(e) for e in events)+'\n').encode()
        self.capture(raw,1)
        result=self.run_candidate()
        self.assertEqual(result['outcomes'],['undefined_steps'])
        self.assertEqual(len(result['runs'][0]['records']),4)
        events.remove(next(e for e in events if e['event']=='status'))
        self.capture(('\n'.join(json.dumps(e) for e in events)+'\n').encode(),1)
        with self.assertRaises(runtime.RuntimeRefused):self.run_candidate()

    def test_candidate_substrate_violation_quarantines_without_repeat(self):
        def changed(remote):
            remote.copy['internal/r2tfixture/prod.go']=b'package fixture\n// changed\n'
            return 0
        self.capture(self.native,effect=changed)
        result=self.run_candidate(repeats=3)
        self.assertEqual(result['substrate_violation']['changed'],['internal/r2tfixture/prod.go'])
        self.assertTrue(self.harness.copy.quarantined)
        self.assertEqual(self.remote.calls.count('execute'),2)
        self.assertEqual(result['runs'],[])

    def test_mutant_added_files_are_unscorable_only_for_a_mutation_attempt(self):
        # Owner ruling 2026-09-30. The copy decides whether its quarantine is
        # the ruled shape (mutation_copy_selftest); the runtime asks only for a
        # mutation attempt, returns both scoped reports beside the merged
        # violation, and withdraws them when the host postcondition fails.
        added='internal/r2tfixture/config.yaml'
        def adds(remote):
            remote.copy[added]=b'written by the test\n'
            return 0
        self.capture(self.native,effect=adds)
        with patch.object(self.harness.copy,'retire_unscorable',
                          wraps=self.harness.copy.retire_unscorable) as asked:
            result=self.run_candidate()
        asked.assert_not_called()
        self.assertEqual(result['substrate_violation']['added'],[added])
        self.assertNotIn('unscorable_substrate',result)
        self.assertTrue(self.harness.copy.quarantined)
        authority={'descriptor': {'file':'internal/r2tfixture/api.go'},
                   'reference_files': {}, 'engine_request': {}, 'engine_sha256':'a'*64}
        clean={'baseline':True,'checked':1,'changed':[],'missing':[],'added':[],'mutated':[]}
        scoped={'copy':{**clean,'added':[added],'mutated':['internal/r2tfixture/api.go']},'original':clean}
        for recovered,host in ((True,False),(False,False),(True,True)):
            with self.subTest(recovered=recovered,host=host):
                self.setUp()
                def violated(copy_,**kwargs):
                    if host:(self.fixture.workspace/'internal/r2tfixture/extra.go').write_text('package fixture\n')
                    raise NativeCaptureError(NativeCapture(self.context),ExecutionIntegrityError(
                        'added',phase='executed',scope='protected_substrate',reports=scoped))
                with patch('r2t.go.runtime.capture_execution',side_effect=violated), \
                        patch.object(self.harness.copy,'retire_unscorable',
                                     return_value=copy.deepcopy(scoped) if recovered else None) as asked:
                    result=self.run_candidate(mutation=authority)
                asked.assert_called_once_with()
                self.assertEqual(result['runs'],[])
                self.assertEqual(result['substrate_violation']['added'],
                                 [added,'internal/r2tfixture/extra.go'] if host else [added])
                if recovered and not host:
                    self.assertEqual(result['unscorable_substrate'],scoped)
                    self.assertFalse(self.harness.copy.quarantined)
                else:
                    self.assertNotIn('unscorable_substrate',result)
                    self.assertEqual(self.harness.copy.quarantined,host)

    def test_preexisting_context_and_substrate_failures_escape(self):
        bad=copy.copy(self.scenario);bad.line=999
        with self.assertRaises(ValueError):
            runtime.run_solution(self.harness,self.feature,bad,self.solution)
        (self.fixture.workspace/'internal/r2tfixture/prod.go').write_text('changed before candidate')
        with self.assertRaises(repo.SubstrateTampered):self.run_candidate()
        self.assertEqual(self.remote.calls,[])

    def test_proved_timeout_and_transport_timeout_remain_distinct(self):
        clock=[10.0]
        def expired(remote):
            clock[0]=611.0
            remote.outputs['timeout.log']=b'timeout: sending signal TERM to command /bin/bash\n'
            return 124
        self.capture(self.native[:-8],effect=expired)
        with patch('time.monotonic',side_effect=lambda:clock[0]):result=self.run_candidate()
        self.assertEqual(result['outcomes'],['timeout'])
        self.assertTrue(result['runs'][0]['timed_out'])
        self.assertEqual(result['runs'][0]['records'],[])
        self.assertEqual(result['runs'][0]['timeout_cleanup'],'killed')
        self.assertFalse(self.harness.copy.quarantined)
        def uncertain(remote):raise subprocess.TimeoutExpired('transport',615)
        self.capture(effect=uncertain)
        with self.assertRaises(runtime.RuntimeRefused):self.run_candidate()

    def test_control_preparation_and_verified_parent_witness_survive_envelope(self):
        # Control/status metadata fixture: retain the real native stream's
        # complete Examples identities, and exercise the actual verifier. No
        # execution or measurement qualification is claimed by this replay.
        mapping=json.loads(self.plan)['map']
        source=self.feature.text if hasattr(self.feature,'text') else (
            self.fixture.workspace/self.context['feature_path']).read_text()
        witness=read_runtime_native(self.native,context=self.context,feature_source=source,
                                    source_map=mapping,exit_code=0)
        closure=extract_closure(witness,self.harness.boundary,
                               verified_files=tuple(self.fixture.answers)).to_json()
        files={p:(self.fixture.gold/p).read_bytes() for p in self.fixture.answers}
        for mode in ('empty','noop'):
            with self.subTest(mode=mode):
                events=[json.loads(line) for line in self.native.splitlines()]
                expected={'mode':mode,'original_helper_calls':[], 'noop_handler_calls':[]}
                if mode=='noop':
                    expected['noop_handler_calls']=[str(step['definition']['go']['keyword'])+':'+
                        step['definition']['pattern'] for step in closure['steps']]
                else:
                    for event in events:
                        if event['event']=='defined':event['matched']=False
                        if event['event']=='status':event['status']='undefined'
                        if event['event']=='exit':event['code']=1
                events[-1]['control_witness']=copy.deepcopy(expected)
                raw=('\n'.join(json.dumps(event) for event in events)+'\n').encode()
                plan={'mode':mode,'files':list(files),'held_metadata':{'value':'original'}}
                prepared=PreparedControl(copy.deepcopy(self.context),mode,copy.deepcopy(files),plan)
                captured=NativeCapture(copy.deepcopy(self.context),phase='captured',
                    planner=subprocess.CompletedProcess([],0,self.plan.decode(),''),
                    completed=subprocess.CompletedProcess([],int(mode=='empty'),'fixture control output',''),
                    source_map=mapping,native=raw,retired=True)
                with patch('r2t.go.runtime.capture_execution',return_value=captured):
                    result=runtime.run_control(self.harness,self.feature,self.scenario,mode=mode,
                        closure=closure,prepared=prepared,deadline=runtime.time.monotonic()+600)
                run=result['runs'][0]
                self.assertEqual(run['control_preparation'],plan)
                self.assertEqual(run['control_witness'],expected)
                self.assertEqual(run['outcome'],'undefined_steps' if mode=='empty' else 'passed')
                plan['held_metadata']['value']='changed later'
                expected['original_helper_calls'].append('changed later')
                self.assertEqual(run['control_preparation']['held_metadata']['value'],'original')
                self.assertEqual(run['control_witness']['original_helper_calls'],[])
                for missing_native in (None,b''):
                    with self.subTest(mode=mode,native=missing_native):
                        incomplete=copy.deepcopy(captured)
                        incomplete.native=missing_native
                        with patch('r2t.go.runtime.capture_execution',return_value=incomplete):
                            with self.assertRaisesRegex(runtime.RuntimeRefused,'missing its required native witness'):
                                runtime.run_control(self.harness,self.feature,self.scenario,mode=mode,
                                    closure=closure,prepared=prepared,deadline=runtime.time.monotonic()+600)

    def test_control_first_preparation_and_repeat_deadlines(self):
        # Orchestration only: stop at the trusted native capture seam. The
        # existing control tests own actual placeholder/native witness checks.
        original={p:(self.fixture.gold/p).read_bytes() for p in self.fixture.answers}
        first=PreparedControl(copy.deepcopy(self.context),'noop',copy.deepcopy(original),{})
        clock=[100.0];calls=[]
        def prepare(copy_, **kwargs):
            self.assertIs(copy_,self.harness.copy)
            self.assertEqual(kwargs['original_answers'],original)
            self.assertEqual(kwargs['deadline'],800.0)
            calls.append(('prepare',kwargs['deadline']))
            return copy.deepcopy(first)
        def capture(harness,context,source,rows,**kwargs):
            self.assertIsNone(kwargs['installed'])
            self.assertEqual(kwargs['prepared'].files,original)
            calls.append(('capture',kwargs['deadline']))
            clock[0]=200.0
            return runtime._Attempt(RunResult(0,'capture boundary only',0.0,records=[],
                expected_line=6,expected_lines=rows,error_markers=()))
        with patch('time.monotonic',side_effect=lambda:clock[0]), \
                patch('r2t.go.runtime.prepare_control',side_effect=prepare), \
                patch('r2t.go.runtime._capture_attempt',side_effect=capture):
            result=runtime.run_control(self.harness,self.feature,self.scenario,mode='noop',
                closure=self.closure,prepared=first,deadline=650.0,repeats=2)
        self.assertEqual(calls,[('capture',650.0),('prepare',800.0),('capture',800.0)])
        self.assertEqual(len(result['runs']),2)
        self.assertTrue(all(not (self.fixture.workspace/p).exists() for p in self.fixture.answers))
        for bad in ({'files':{}},PreparedControl(self.context,'empty',original,{})):
            with self.assertRaises(runtime.RuntimeRefused):
                runtime.run_control(self.harness,self.feature,self.scenario,mode='noop',
                    closure=self.closure,prepared=bad,deadline=650.0)


_GOLD_HELPERS = '''//go:build check

package check

import (
\t"fmt"
\t"strings"
\tstr "strconv"
)

// shout is support for the retained tests.
// It spans two comment lines.
func shout(s string) string { return strings.ToUpper(s) }

const greeting = "hi"

type probe struct{ n int }

func unrelated() string { return str.Itoa(1) }

// hit counts.
func (p *probe) hit() { p.n++ }

func (probe) label() string {
\treturn fmt.Sprint("probe")
}
'''


class CrashSignatureTests(unittest.TestCase):
    """`_go_crash` over real `go test` output (fixtures/crash; see registry_selftest)."""
    def setUp(self):
        self.crash = Path(__file__).with_name('fixtures')/'crash'
        self.context = json.loads((self.crash/'context.json').read_text())

    def classify(self, text, code=1, context=None):
        return runtime._go_crash(subprocess.CompletedProcess([], code, text, ''), context or self.context)

    def test_real_crashes_and_their_boundaries(self):
        read = lambda name: (self.crash/name).read_text()
        for name in ('stdout-hw2.txt', 'stdout-hw3.txt', 'stdout-hw4.txt'):
            for code in (1, 2):
                self.assertEqual(self.classify(read(name), code), ('kill', 'go_panic'))
            for code in (0, 3, 124):
                self.assertIsNone(self.classify(read(name), code))
        self.assertEqual(self.classify(read('go125-deadlock.txt')), ('kill', 'go_fatal_error'))
        self.assertEqual(runtime._go_crash(subprocess.CompletedProcess([], 1, '', read('stdout-hw2.txt')),
                                           self.context), ('kill', 'go_panic'))
        self.assertIsNone(self.classify(read('go125-test-timeout.txt')))
        self.assertIsNone(self.classify(read('go125-support-panic.txt')))
        self.assertIsNone(self.classify(read('stdout-hw2.txt'), context=dict(self.context, package_dir='external/other')))
        hw2 = read('stdout-hw2.txt')
        self.assertIsNone(self.classify(hw2.replace('0.104s', '[build failed]')))
        self.assertIsNone(self.classify(hw2.replace('goroutine 67 [running]:', 'no trace')))
        self.assertIsNone(self.classify(hw2.replace('panic: runtime error', 'error: runtime error')))
        # Only the innermost non-runtime frame decides support-code origin.
        self.assertIsNone(self.classify(hw2.replace('\t<autogenerated>:1 +0x24',
            '\t/r2t-go/run/work/_bench/go/support/harness.go:33 +0x24')))
        self.assertIsNone(self.classify(hw2.replace('\t<autogenerated>:1 +0x24',
            '\t/r2t-go/run/work/external/cli/zz_r2t_harness_test.go:33 +0x24')))
        self.assertEqual(self.classify(hw2.replace('/r2t-go/run/work/external/cli/tui/mainscreen.go:70 +0xb9',
            '/r2t-go/run/work/external/cli/zz_r2t_harness_test.go:33 +0xb9')), ('kill', 'go_panic'))
        support = read('go125-support-panic.txt')
        self.assertEqual(self.classify(support.replace('github.com/EvilFreelancer/coddy-agent/external/cli.r2tRecord()',
            'panic({0x4e4f60?, 0xc000012345?})\n\t/usr/local/go/src/runtime/panic.go:791 +0x132\n'
            'github.com/EvilFreelancer/coddy-agent/external/cli.r2tRecord()')), None)
        self.assertEqual(self.classify(support.replace('zz_r2t_harness_test.go:6', 'crash_test.go:6')),
                         ('kill', 'go_panic'))

    def test_panics_recovered_and_raised_again_by_t_run(self):
        # The recorder runs on a t.Run goroutine: testing.tRunner recovers its
        # panic and raises it again, so tRunner's frames sit above `panic(`.
        recorder = (self.crash/'go125-recorder-panic-subtest.txt').read_text()
        production = (self.crash/'go125-production-panic-subtest.txt').read_text()
        self.assertIn('[recovered, repanicked]', recorder)
        self.assertIn('testing.tRunner.func1.2(', recorder)
        self.assertIsNone(self.classify(recorder))
        self.assertEqual(self.classify(production), ('kill', 'go_panic'))
        # Go 1.18's spelling of the same shape (`[recovered]`) is read alike.
        self.assertIsNone(self.classify(recorder.replace('[recovered, repanicked]', '[recovered]')))
        # Below the raising frame, only the innermost non-runtime frame decides.
        self.assertEqual(self.classify(recorder.replace('external/cli/zz_r2t_harness_test.go:12',
                                                        'external/cli/render.go:12')), ('kill', 'go_panic'))

    def test_resource_exhaustion_is_infrastructure(self):
        oom = (self.crash/'go125-out-of-memory.txt').read_text()
        self.assertEqual(self.classify(oom), ('infrastructure', 'fatal error: out of memory'))
        # The runtime's other exhaustion spellings, in the real trace's place.
        deadlock = (self.crash/'go125-deadlock.txt').read_text()
        crash_line = 'fatal error: all goroutines are asleep - deadlock!'
        for cause in ('runtime: failed to create new OS thread (have 7 already; errno=11)\n'
                      'runtime: may need to increase max user processes (ulimit -u)\nfatal error: newosproc',
                      'fatal error: runtime: cannot allocate memory',
                      'fatal error: runtime: out of memory'):
            self.assertEqual(self.classify(deadlock.replace(crash_line, cause))[0], 'infrastructure', cause)

    def test_sigkilled_test_binary_is_infrastructure(self):
        for host in ('hw3', 'hw9'):
            killed = (self.crash/f'oom-{host}-stdout.txt').read_text()
            context = json.loads((self.crash/f'oom-{host}-context.json').read_text())
            classify = lambda text, code=1, ctx=context: self.classify(text, code, ctx)
            for code in (1, 2):
                self.assertEqual(classify(killed, code), ('infrastructure', 'signal: killed'))
            for code in (0, 3, 137):
                self.assertIsNone(classify(killed, code))
            # go test appends the wait status to an unterminated last line.
            self.assertEqual(classify(killed.replace('\nsignal: killed', '\npartial outputsignal: killed')),
                             ('infrastructure', 'signal: killed'))
            # Only the go command's report for the selected package, right
            # after the wait status, reads as a killed test binary.
            self.assertIsNone(classify(killed, ctx=dict(context, package_dir='external/other')))
            self.assertIsNone(classify(killed.replace('signal: killed', 'exit status 1')))
            self.assertIsNone(classify(killed.replace('signal: killed\n', 'signal: killed\nlater\n')))
            self.assertIsNone(classify(re.sub(r'\t[0-9.]+s\n', '\t[build failed]\n', killed)))
            # Any runtime crash line keeps the existing crash rule instead.
            for line in ('panic: boom', 'fatal error: boom', 'fatal error: out of memory'):
                self.assertIsNone(classify(killed.replace('signal: killed', line + '\nsignal: killed')), line)
            self.assertIsNone(runtime._go_crash(subprocess.CompletedProcess([], 1, killed, 'panic: boom\n'),
                                                context))

    def test_cleanup_panic_is_read_split(self):
        # Patch P2. Real stdout of a refused coddy candidate pair (2026-10-01;
        # hw3 cdy-luna-th-shard-2 worker 6, mutant cdfee1cbb72f2550), from the
        # research route B's test material: Go wrote `cleanup panicked with
        # <value>` and the repanic's `panic: ` on one line.
        text = (self.crash/'cleanup-panic-hw3-stdout.txt').read_text()
        self.assertIn('dereferencepanic: runtime error', text)
        self.assertIsNone(runtime._go_trace_crash(subprocess.CompletedProcess([], 1, text, ''), self.context))
        for code in (1, 2):
            self.assertEqual(self.classify(text, code), ('kill', 'go_panic'))
        self.assertEqual(runtime._go_crash(subprocess.CompletedProcess([], 1, '', text), self.context),
                         ('kill', 'go_panic'))
        # The split changes nothing else: support-code origin, the selected
        # package and the exit code still decide.
        self.assertIsNone(self.classify(text.replace('/r2t-go/run/work/external/cli/app.go:396',
                                                     '/r2t-go/run/work/_bench/go/support/harness.go:396')))
        self.assertIsNone(self.classify(text, context=dict(self.context, package_dir='external/other')))
        for code in (0, 3):
            self.assertIsNone(self.classify(text, code))
        self.assertEqual(self.classify(text.replace('dereferencepanic: ', 'dereferencefatal error: ')),
                         ('kill', 'go_fatal_error'))

    def test_parent_failnow_is_a_labelled_kill(self):
        # Patch P2. Real stdout of a refused coddy candidate pair (2026-10-01;
        # hw9 openhands-target_hidden-r3 worker 4, mutant 5ee4e14b480f9563):
        # a step called t.Fatalf on the outer test. Owner ruling 2026-10-01:
        # a kill, labelled go_parent_failnow.
        text = (self.crash/'parent-failnow-hw9-stdout.txt').read_text()
        self.assertIsNone(runtime._go_trace_crash(subprocess.CompletedProcess([], 1, text, ''), self.context))
        self.assertEqual(self.classify(text), ('kill', 'go_parent_failnow'))
        # Only that exact shape: exit 1, the selected package's timed FAIL,
        # the whole Go line, and no runtime trace line in either stream.
        for code in (0, 2, 3):
            self.assertIsNone(self.classify(text, code))
        self.assertIsNone(self.classify(text, context=dict(self.context, package_dir='external/tui')))
        self.assertIsNone(self.classify(text.replace('parent test', 'parent')))
        self.assertIsNone(self.classify(re.sub(r'\t[0-9.]+s\n', '\t[build failed]\n', text)))
        self.assertIsNone(self.classify(text.replace('    testing.go:1811: ', 'panic: ')))
        self.assertIsNone(runtime._go_crash(subprocess.CompletedProcess([], 1, text, 'panic: boom\n'),
                                            self.context))

    def test_readings_never_change_a_classified_exit(self):
        cleanup = (self.crash/'cleanup-panic-hw3-stdout.txt').read_text()
        calls = []
        def trace(completed, context):
            calls.append(completed.stdout)
            return 'infrastructure', 'signal: killed'
        with patch.object(runtime, '_go_trace_crash', side_effect=trace):
            self.assertEqual(self.classify(cleanup), ('infrastructure', 'signal: killed'))
        self.assertEqual(calls, [cleanup])  # classified on the first read, never split
        calls.clear()
        with patch.object(runtime, '_go_trace_crash', side_effect=lambda c, ctx: calls.append(c.stdout)):
            self.assertIsNone(self.classify('--- FAIL: TestX\nFAIL\n'))
        self.assertEqual(len(calls), 1)  # nothing to split: one read


class KilledTestBinaryTests(unittest.TestCase):
    """A mutant test binary the kernel OOM killer ended, from real bytes.

    fixtures/crash/oom-hw3-* and oom-hw9-* are two coddy full-gold reference
    attempts at tag coddy-agent-fullgold-attempt2-v1-20260928 (H24) that
    refused, from each host's
    reference/observations/full_gold/<host>/gold.w<i>.jsonl.go-evidence:
    huawei3 w1 9faf921abc01a545.1.rrbneodr and huawei9 w18
    a3449fb879e24c71.1.bjtnte9i. Each keeps the attempt's stdout, native
    stream and context; the source map is the planner map reduced to the keys
    the reader consumes and the declarations its events name. huawei9's
    feature is crash/feature.feature byte for byte. Both captures proved
    cleanup and integrity; the operator saw State.OOMKilled on the containers,
    which set no memory limit.
    """
    CASES = (('hw3', 'oom-hw3-feature.feature'), ('hw9', 'feature.feature'))

    def setUp(self):
        self.crash = Path(__file__).with_name('fixtures')/'crash'
        temp = tempfile.TemporaryDirectory(prefix='go-killed-')
        self.addCleanup(temp.cleanup)
        self.root = temp.name

    def load(self, host, feature):
        read = lambda name: (self.crash/name).read_bytes()
        return (json.loads(read(f'oom-{host}-context.json')), read(feature).decode(),
                read(f'oom-{host}-native.jsonl'), json.loads(read(f'oom-{host}-source_map.json')),
                read(f'oom-{host}-stdout.txt').decode())

    def attempt(self, context, source, native, source_map, stdout, *, mutation=True):
        """`_capture_attempt` over one proved capture holding these bytes."""
        authority = {'descriptor': {'file': 'external/cli/tui/markdown.go'},
                     'reference_files': {}, 'engine_request': {}, 'engine_sha256': 'a'*64}
        harness = SimpleNamespace(root=self.root, copy=SimpleNamespace(original_inventory={}),
            contexts=SimpleNamespace(files_for=lambda feature, line: [context['glue_path']]),
            coordination_inputs=lambda: None)
        captured = NativeCapture(context, phase='captured',
            planner=subprocess.CompletedProcess([], 0, '', ''),
            completed=subprocess.CompletedProcess([], 1, stdout, ''), source_map=source_map,
            native=native, mutation_evidence={'reference_retired': True} if mutation else None,
            retired=True)
        started = time.monotonic()
        with patch('r2t.go.runtime.capture_execution', return_value=captured) as capture:
            attempt = runtime._capture_attempt(harness, context, source, source_selection(context, source)[3],
                installed={context['glue_path']: b'package cli\n'}, prepared=None, closure=None,
                coverage=False, started=started, deadline=started+600,
                mutation=authority if mutation else None)
        self.assertIs(capture.call_args.kwargs['mutation'], authority if mutation else None)
        return attempt

    def test_real_oom_kills_are_retried_then_excluded_infrastructure(self):
        from ..bench.runner import _record
        from ..bench.mutation_run import INFRASTRUCTURE_OUTCOMES as RETRIED
        from ..data.mutation import classify_outcome
        for host, feature in self.CASES:
            context, source, native, source_map, stdout = self.load(host, feature)
            self.assertEqual(json.loads(native.splitlines()[-1])['event'], 'defined')
            for recorded in (native, b''):
                with self.subTest(host=host, native=len(recorded)):
                    attempt = self.attempt(context, source, recorded, source_map, stdout)
                    run = attempt.run.to_json()
                    self.assertEqual((run['outcome'], run['exit_code'], run['records']),
                                     ('container_error', 1, []))
                    self.assertNotIn('crash', run)
                    self.assertIn('\nsignal: killed\nFAIL\t', run['stdout_tail'])
                    row = _record('i', {}, {'files': []}, 0.0, runtime._envelope([], [], {}, [attempt]))
                    self.assertEqual(row['outcome'], 'container_error')
                    self.assertNotIn('crash', row)
                    # run_slice retries a first attempt with this outcome once
                    # (mutation_run.selftest); a second one is excluded.
                    self.assertIn(row['outcome'], RETRIED)
                    self.assertEqual(classify_outcome('passed', row['outcome']), 'infrastructure')

    def test_real_oom_kill_refusals(self):
        for host, feature in self.CASES:
            context, source, native, source_map, stdout = self.load(host, feature)
            refused = [('partial final record', native[:-1], True),
                       ('partial record after whole events', native + b'{"event": "status"', True),
                       ('foreign event', native + b'{"event": "other"}\n', True),
                       ('ordinary candidate run', native, False)]
            for label, recorded, mutation in refused:
                with self.subTest(host=host, case=label):
                    with self.assertRaises(runtime.RuntimeRefused):
                        self.attempt(context, source, recorded, source_map, stdout, mutation=mutation)


class SensitivityOverlayTests(unittest.TestCase):
    """Which gold declarations a candidate execution receives (harness 25)."""

    def test_declared_names_follow_go_declarations_not_comments_or_literals(self):
        from .sensitivity import declared_names, declarations
        source = ('package check\n\nimport (\n\t"fmt"\n\tstr "strings"\n)\n\n'
                  '/* func notReal() {} */\nvar raw = `\nfunc alsoNotReal() {}\n`\n'
                  'const (\n\talpha, beta = 1, 2\n\tgamma\n)\n'
                  'var (\n\tdelta int\n\tepsilon = fmt.Sprint(\n\t\t"func fake() {}",\n\t)\n'
                  '\tzed = alpha +\n\t\tomicron\n)\n'
                  'type (\n\tzeta struct{ a int }\n\teta = zeta\n)\n'
                  'type theta[T any] struct{ v T }\n'
                  'const sum = 1 +\n\t2\n'
                  "var r = '}'\n"
                  'func (z *zeta) shout() string { return str.ToUpper("x") }\n'
                  'func (theta[T]) spin() {}\n'
                  'func omega[T any](v T) T { return v }\n'
                  'var _ = 1\n')
        self.assertEqual(declared_names(source), {'raw', 'alpha', 'beta', 'gamma', 'delta',
            'epsilon', 'zed', 'zeta', 'eta', 'theta', 'sum', 'r', 'omega'})
        receivers = [d.receiver for d in declarations(source) if d.receiver]
        self.assertEqual(receivers, ['zeta', 'theta'])

    def test_helper_source_copies_declarations_methods_constraint_and_used_imports(self):
        from .sensitivity import helper_source
        self.assertEqual(helper_source(_GOLD_HELPERS, 'internal/check/bdd_helpers_test.go',
                                       ['shout', 'probe']),
            '//go:build check\n\n'
            '// Supplied by the harness from '
            'internal/check/bdd_helpers_test.go for the retained tests.\n\n'
            'package check\n\n'
            'import (\n\t"fmt"\n\t"strings"\n)\n\n'
            '// shout is support for the retained tests.\n// It spans two comment lines.\n'
            'func shout(s string) string { return strings.ToUpper(s) }\n\n'
            'type probe struct{ n int }\n\n'
            '// hit counts.\nfunc (p *probe) hit() { p.n++ }\n\n'
            'func (probe) label() string {\n\treturn fmt.Sprint("probe")\n}\n')

    def test_helper_source_refuses_what_it_cannot_copy_whole(self):
        from .sensitivity import SensitivityRefused, helper_source
        for gold, name in ((_GOLD_HELPERS, 'absent'),
                           ('package check\n\nvar shared = 1\n', 'shared'),
                           ('package check\n\nconst (\n\tone = 1\n\ttwo = 2\n)\n', 'one')):
            with self.subTest(name=name), self.assertRaises(SensitivityRefused):
                helper_source(gold, 'internal/check/bdd_helpers_test.go', [name])

    def test_real_compiler_accepts_every_supplied_combination(self):
        from .sensitivity import overlay
        go = shutil.which('go'); self.assertIsNotNone(go)
        env = dict(os.environ, GOPROXY='off', GOWORK='off', GOTOOLCHAIN='local',
                   GOFLAGS='-mod=readonly -p=1')
        helper = 'internal/check/bdd_helpers_test.go'
        glue = 'internal/check/bdd_glue_test.go'
        table = {helper: ('shout', 'greeting', 'probe'),
                 'internal/other/bdd_other_test.go': ('elsewhere',)}
        retained = ('//go:build check\n\npackage check\n\nimport "testing"\n\n'
                    'func TestRetained(t *testing.T) {\n\tp := &probe{}\n\tp.hit()\n'
                    '\tif shout(greeting) != "HI" || p.label() != "probe" {\n\t\tt.Fatal()\n\t}\n}\n')
        placeholder = '//go:build check\n\npackage check\n'
        world = placeholder + '\ntype world struct{}\n\n// A method named like a helper.\nfunc (world) shout() {}\n'
        own = placeholder + ('\ntype probe struct{}\n\nfunc (*probe) hit() {}\n\n'
                             'func (probe) label() string { return "probe" }\n\n'
                             'const (\n\tgreeting = "hi"\n)\n')
        cases = [({helper: placeholder, glue: world}, {helper: ['shout', 'greeting', 'probe']}),
                 ({helper: own, glue: placeholder}, {helper: ['shout']}),
                 ({helper: _GOLD_HELPERS, glue: placeholder}, {})]
        with tempfile.TemporaryDirectory(prefix='go-sensitivity-') as td:
            gold = Path(td) / 'gold'; (gold / helper).parent.mkdir(parents=True)
            (gold / helper).write_text(_GOLD_HELPERS)
            for number, (answers, supplied) in enumerate(cases):
                root = Path(td) / str(number); package = root / 'internal/check'
                package.mkdir(parents=True)
                (root / 'go.mod').write_text('module example.test/sensitivity\n\ngo 1.22\n')
                (package / 'prod.go').write_text('package check\n\nfunc Product() int { return 1 }\n')
                (package / 'retained_test.go').write_text(retained)
                installed = {path: code.encode() for path, code in answers.items()}
                for path, raw in installed.items():
                    (root / path).write_bytes(raw)
                build = [go, 'test', '-c', '-tags', 'check', '-o', os.devnull, './internal/check']
                if supplied:
                    missing = subprocess.run(build, cwd=root, env=env, capture_output=True, text=True)
                    self.assertNotEqual(missing.returncode, 0)
                    self.assertIn('undefined: shout', missing.stdout + missing.stderr)
                files, got = overlay({'package_dir': 'internal/check'}, installed, gold, table)
                self.assertEqual(got, supplied)
                self.assertEqual(list(files), ['internal/check/zz_r2t_retained_helpers_bdd_helpers_test.go']
                                 if supplied else [])
                for path, raw in files.items():
                    (root / path).write_bytes(raw)
                built = subprocess.run(build, cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)


class DiagnosticProducerTests(unittest.TestCase):
    def test_real_parser_scaffold_frames_and_unattributed_compiler_failure(self):
        go=shutil.which('go');self.assertIsNotNone(go)
        env=dict(os.environ,GOPROXY='off',GOWORK='off',GOTOOLCHAIN='local',GOFLAGS='-mod=readonly -p=1')
        with tempfile.TemporaryDirectory(prefix='go-runtime-diagnostic-') as td:
            root=Path(td);package=root/'internal/check';package.mkdir(parents=True)
            (root/'go.mod').write_text('module example.test/diagnostic\n\ngo 1.25.0\n')
            binary=root/'planner';subprocess.run([go,'build','-p=1','-o',str(binary),
                str(Path(__file__).with_name('support')/'interpose.go')],env=env,check=True,capture_output=True)
            path=package/'bdd_fixture_test.go';relative='internal/check/bdd_fixture_test.go'
            context={'glue_path':relative,'package_dir':'internal/check','package_name':'check'}
            args=[str(binary),'-root',td,'-package','internal/check','-file',relative,'-test','TestFixture']
            for raw,stage in [('package check\nfunc broken(\n','parse'),('package check\nfunc Other() {}\n','scaffold')]:
                path.write_text(raw)
                enabled=subprocess.run(args+['-runtime-diagnostics'],env=env,capture_output=True,text=True)
                self.assertEqual(enabled.returncode,1)
                parsed=runtime._candidate_diagnostic(enabled.stdout,context)
                self.assertEqual(parsed[relative]['kind'],stage)
                default=subprocess.run(args,env=env,capture_output=True,text=True)
                self.assertNotEqual(default.returncode,0)
                self.assertEqual(default.stdout,'')
            retained=package/'retained_test.go'
            retained.write_text('package check\nfunc retained(value CandidateState) string { return value.Label }\n')
            (package/'prod.go').write_text('package check\nfunc Product() int { return 1 }\n')
            extra=package/'extra_candidate_test.go'
            extra.write_text('package check\nfunc extra() int { return 1 }\n')
            template='package check\nimport (%s)\ntype CandidateState struct { Label %s }\nfunc TestFixture(t *testing.T) { %s }\n'
            cases=[('undefined','"testing"','string','missingDependency()',path),
                   ('unused-local','"testing"','string','abs := 1',path),
                   ('unused-import','"testing"; "fmt"','string','',path),
                   ('retained','"testing"','int','',retained)]
            for label,imports,field,body,error_file in cases:
                with self.subTest(label=label):
                    path.write_text(template%(imports,field,body))
                    failed=subprocess.run(args+['-runtime-diagnostics'],env=env,capture_output=True,text=True)
                    self.assertEqual(failed.returncode,1,failed.stderr)
                    sources={p.relative_to(root).as_posix():p.read_bytes() for p in package.glob('*.go')}
                    errors=runtime._candidate_diagnostic(failed.stdout,context,sources=sources)
                    key=error_file.relative_to(root).as_posix()
                    self.assertEqual(errors[key]['kind'],'compile')
                    self.assertTrue(errors[key]['diagnostics'])
                    default=subprocess.run(args,env=env,capture_output=True,text=True)
                    self.assertNotEqual(default.returncode,0)
                    self.assertEqual(default.stdout,'')
                    changed=dict(sources);changed[key]+=b'changed'
                    with self.assertRaises(runtime.RuntimeRefused):
                        runtime._candidate_diagnostic(failed.stdout,context,sources=changed)
            path.write_text(template%('"testing"','string',''))
            extra.write_text('package check\n//line imaginary.go:900\nfunc extra() int { return ) }\n')
            failed=subprocess.run(args+['-runtime-diagnostics'],env=env,capture_output=True,text=True)
            sources={p.relative_to(root).as_posix():p.read_bytes() for p in package.glob('*.go')}
            errors=runtime._candidate_diagnostic(failed.stdout,context,sources=sources)
            errors=errors[extra.relative_to(root).as_posix()]['diagnostics']
            self.assertTrue(all(e['line']==3 and e['file'].endswith('extra_candidate_test.go') for e in errors))
            extra.write_text('package check\nfunc extra() int { return 1 }\n')
            path.write_text(template%('"testing"; _ "example.invalid/missing"','string',''))
            missing=subprocess.run(args+['-runtime-diagnostics'],env=env,capture_output=True,text=True)
            self.assertNotEqual(missing.returncode,0)
            self.assertIsNone(runtime._candidate_diagnostic(missing.stdout,context))
            # Compile the actual tracking importer into a tiny local test;
            # corruption occurs after a successful real file open.
            (root/'interpose.go').write_bytes((Path(__file__).with_name('support')/'interpose.go').read_bytes())
            (root/'corrupt.a').write_bytes(b'not an export archive\n')
            (root/'importer_test.go').write_text(r'''package main
import ("go/importer"; "go/token"; "go/types"; "io"; "os"; "testing")
func TestImporterFailures(t *testing.T) {
 for _, name := range []string{"absent.a", "corrupt.a"} {
  opened := false
  base := importer.ForCompiler(token.NewFileSet(), "gc", func(path string)(io.ReadCloser,error) {
   f, err := os.Open(name); if err == nil { opened = true }; return f, err
  })
  tracked := &trackingImporter{base:base}
  var from types.ImporterFrom = tracked
  if _, err := from.ImportFrom("example.test/export", "", 0); err == nil || len(tracked.failures) != 1 {
   t.Fatal("full importer failure not tracked", err, tracked.failures)
  }
  if opened != (name == "corrupt.a") { t.Fatal("post-open corruption not exercised", name) }
 }
}
''')
            checked=subprocess.run([go,'test','-count=1','-p=1','-run','^TestImporterFailures$','.'],
                cwd=root,env=env,capture_output=True,text=True)
            self.assertEqual(checked.returncode,0,checked.stdout+checked.stderr)


def selftest():
    suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(cls)
                             for cls in (RuntimeTests,CrashSignatureTests,KilledTestBinaryTests,
                                         SensitivityOverlayTests,DiagnosticProducerTests)])
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':
    raise SystemExit(selftest())
