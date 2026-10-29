"""Collector reconstruction/projection tests; native writer qualification is separate."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from ..bench.harness import RunResult
from ..core.boundary import Boundary
from . import measurement as M
from .registry import checked_plan, read_native, support_files

FIXTURE = Path(__file__).with_name('fixtures') / 'native'
PROD = 'internal/example/prod.go'


def fixture():
    context = json.loads((FIXTURE/'context.json').read_text())
    plan = json.loads((FIXTURE/'plan.json').read_text())
    original = (FIXTURE/'bdd_fixture_test.go').read_bytes()
    source = (FIXTURE/'shape.feature').read_text()
    mapping, _ = checked_plan(json.dumps(plan), context, original)
    raw = (FIXTURE/'native.jsonl').read_bytes()
    witness = read_native(raw, context=context, feature_source=source,
                          source_map=mapping, exit_code=0)
    return context, plan, original, raw, witness


def projection_fixture():
    context, _, _, raw, witness = fixture()
    native = [json.loads(line) for line in raw.splitlines()]
    # Explicit test-only adaptation to the new driver field. The original
    # fixture remains unchanged; this does not claim a new native execution.
    native[0]['measurement_pid'] = 42
    # Every entry names the step that made it, or null for one made outside
    # any step (TARGET_INTERFACES_V2_SPEC section 4); each of the fixture's
    # four Examples records runs the same five steps, and 0 is the Background's.
    event = {'callee_file':PROD, 'callee_line':2, 'callee':'F',
             'caller_file':context['glue_path'], 'step':0}
    plan = {'production_files':[PROD], 'production_plans':[
        {'file':PROD, 'original_source':'package example\nfunc F() {\n return\n}\n',
         'declarations':[{'Name':'F','Line':2}]}]}
    document = {'schema':M.SCHEMA, 'complete':True, 'pid':42, 'exit':0,
        'window':M.WINDOW, 'failures':[], 'direct_calls':[event],
        'coverage':[{'File':PROD,'Counts':[1],'Positions':[2,4,2<<16|10],'Statements':[1]}]}
    capture = SimpleNamespace(measurement=json.dumps(document).encode(),
        measurement_owner=b'42\n', measurement_plan=plan,
        native=('\n'.join(json.dumps(row) for row in native)+'\n').encode(),
        completed=SimpleNamespace(returncode=0))
    return capture, witness, document


class MeasurementTests(unittest.TestCase):
    def test_native_outline_keeps_identity_and_complete_union(self):
        capture, witness, _ = projection_fixture()
        rows, diagnostic = M.project(capture,witness)
        self.assertIsNone(diagnostic)
        self.assertEqual([r['scenario_line'] for r in rows], [r['scenario_line'] for r in witness.records])
        self.assertEqual([r['steps'] for r in rows], [r['steps'] for r in witness.records])
        self.assertTrue(all(r['coverage']=={'files':{PROD:3},'units':[PROD+'::L2',PROD+'::L3',PROD+'::L4']} for r in rows))
        result = RunResult(0,'',0,records=rows,expected_lines=[r['scenario_line'] for r in rows])
        self.assertEqual(result.outcome,'passed')
        self.assertEqual(len(result.direct_calls),1)

    def test_every_entry_names_a_step_of_its_own_record(self):
        # The step is part of the entry's identity, so the same call from two
        # steps is two entries; one made outside a step carries null and sorts
        # first. The index is a position in the record's own step list -- the
        # Background's steps, then the scenario's -- so a shared process
        # window can only name steps every record of it actually ran.
        capture, witness, doc = projection_fixture()
        call = doc['direct_calls'][0]
        doc['direct_calls'] = [dict(call, step=step) for step in (None, 0, 4)]
        capture.measurement = json.dumps(doc).encode()
        rows, diagnostic = M.project(capture, witness)
        self.assertIsNone(diagnostic)
        self.assertEqual([len(r['steps']) for r in rows], [5, 5, 5, 5])
        self.assertTrue(all([e['step'] for e in r['direct_calls']] == [None, 0, 4]
                            for r in rows))
        for label, events in (
                ('unsorted', [dict(call, step=step) for step in (0, None)]),
                ('duplicate', [dict(call, step=0), dict(call, step=0)]),
                ('absent', [{k: v for k, v in call.items() if k != 'step'}]),
                ('beyond the record', [dict(call, step=5)]),
                ('negative', [dict(call, step=-1)]),
                ('not an index', [dict(call, step='0')])):
            with self.subTest(label=label):
                capture, witness, doc = projection_fixture()
                doc['direct_calls'] = events
                capture.measurement = json.dumps(doc).encode()
                rows, diagnostic = M.project(capture, witness)
                self.assertTrue(diagnostic)
                self.assertTrue(all(r['direct_calls'] is r['coverage'] is None for r in rows))

    def test_complete_empty_is_distinct_from_disabled_or_missing(self):
        capture,witness,doc = projection_fixture()
        doc['direct_calls']=[];doc['coverage'][0]['Counts']=[0]
        capture.measurement=json.dumps(doc).encode()
        rows,diagnostic=M.project(capture,witness)
        self.assertIsNone(diagnostic)
        self.assertTrue(all(r['direct_calls']==[] and r['coverage']=={'files':{},'units':[]} for r in rows))
        capture.measurement=None
        rows,diagnostic=M.project(capture,witness)
        self.assertTrue(diagnostic)
        self.assertTrue(all(r['direct_calls'] is r['coverage'] is None for r in rows))
        self.assertEqual(M.project(capture,witness,coverage=False),(witness.records,None))

    def test_invalid_finalization_never_becomes_empty_success(self):
        for label,mutate in (
            ('wrong-parent',lambda d:d.update(pid=43)),
            ('incomplete',lambda d:d.update(complete=False)),
            ('failed-collector',lambda d:d.update(failures=['bad frame'])),
            ('missing-file',lambda d:d.update(coverage=[])),
            ('partial-counters',lambda d:d['coverage'][0].update(Positions=[])),
            ('shifted-lines',lambda d:d['coverage'][0].update(Positions=[20,40,2<<16|10])),
            ('unmapped-callee',lambda d:d['direct_calls'][0].update(callee_line=10)),
        ):
            with self.subTest(label=label):
                capture,witness,doc=projection_fixture();mutate(doc)
                capture.measurement=json.dumps(doc).encode()
                rows,diagnostic=M.project(capture,witness)
                self.assertTrue(diagnostic)
                self.assertTrue(all(r['direct_calls'] is r['coverage'] is None for r in rows))
        capture,witness,_=projection_fixture();capture.measurement=b'{'
        self.assertTrue(M.project(capture,witness)[1])

    def test_helper_extension_preserves_admission_and_control_witness(self):
        original=support_files()['_bench/go/support/harness.go']
        for control in (False,True):
            files=M.initial_files(control=control)
            helper=files[M.HELPER]
            self.assertIn(b'FinalizeAndExit(m.Run())',helper)
            self.assertIn(b'"measurement_pid": os.Getpid()',helper)
            # The harness registers godog's step hooks in every build; only a
            # measured one has a recorder to receive the step.
            self.assertIn(b'r2tSetStep = r2tmeasure.SetStep',helper)
            self.assertIn(b'sc.StepContext().Before(',helper)
            # godog runs both step-hook lists forward in registration order, so
            # the harness brackets the candidate's hooks: the clearing
            # after-step hook is registered before the candidate initializer
            # runs and the two setters after it, which is what makes a call
            # from a candidate hook on either side carry a null step.
            after=helper.index(b'sc.StepContext().After(')
            call=helper.index(b'original(sc)')
            self.assertLess(after,call)
            self.assertLess(call,helper.index(b'sc.Before('))
            self.assertLess(call,helper.index(b'sc.StepContext().Before('))
            self.assertNotIn(b'r2tmeasure.SetStep',original)
            self.assertEqual(b'r2tControlCheck()' in helper,control)
        self.assertEqual(original,support_files()['_bench/go/support/harness.go'])
        context,*_=fixture();context['go_build_tags']=['http']
        argv=M.planner_command(context)
        self.assertEqual(argv[:4],['go','run','-p=1','./'+M.PLANNER])
        self.assertEqual(argv[argv.index('-tags')+1],'http')

    def test_exact_splice_same_offset_and_original_baseline(self):
        context,interposition,original,_,_=fixture()
        source=b'package example\nfunc F() {}\n'
        counter='R2TGoCover0';hook='r2tmeasurehook'
        native=(f'//line {M.COPY_ROOT}/{PROD}:1:1\npackage example; import _cover_atomic_ "sync/atomic"\n'
            f'func F() {{_cover_atomic_.AddUint32(&{counter}.Count[0], 1);}}\n'
            f'var {counter} = struct {{ Count [1]uint32; Pos [3]uint32; NumStmt [1]uint16 }} {{}}\n').encode()
        at=native.index(b'_cover_atomic_.AddUint32');end=native.index(b';}',at)
        increment={'Start':at,'End':end,'Text':f'{hook}.Hit(&{counter}.Count[0])'}
        after_name=native.index(b'package example')+len(b'package example')
        edits=[{'Start':after_name,'End':after_name,'Text':'; import '+hook+' "example.test/m/_bench/go/measure"'},
               {'Start':at,'End':at,'Text':f' {hook}.Enter("{PROD}",2,"F");'},increment]
        suffix='\nvar _ = _cover_atomic_.AddUint32;func init(){}\n'
        rebuilt=native
        for e in reversed(edits):rebuilt=rebuilt[:e['Start']]+e['Text'].encode()+rebuilt[e['End']:]
        rebuilt+=suffix.encode()
        digest=hashlib.sha256(source).hexdigest()
        row={'file':PROD,'original_source':source.decode(),'original_sha256':digest,
             'native_covered_source':native.decode(),'counter_name':counter,'hook_name':hook,
             'edits':edits,'counter_edits':[increment],'declarations':[{'Name':'F','Line':2}],
             'suffix':suffix,'transformed_source':rebuilt.decode()}
        plan={'module_path':'example.test/m','recorder_import':'example.test/m/_bench/go/measure',
              'interposition':interposition,'production_files':[PROD],'production_plans':[row],
              'coverage_order':'native-original-coverage-before-api-entry-hooks'}
        boundary=Boundary(1,'coddy-agent','/unused',removable=[(context['glue_path'],'answer')])
        def check(p=plan,inventory=None):
            return M.checked_plan(json.dumps(p),context=context,original=original,
                expected_inventory=inventory or {PROD:digest},boundary=boundary,
                helper_template=support_files()['_bench/go/support/harness.go'])
        self.assertEqual(check()[1][PROD],rebuilt)
        with self.assertRaises(M.MeasurementRefused):check(inventory={PROD:'0'*64})
        altered=deepcopy(plan);altered['production_plans'][0]['transformed_source']+='unexpected'
        with self.assertRaises(M.MeasurementRefused):check(altered)
        altered=deepcopy(plan);altered['production_plans'][0]['counter_edits'][0]['Text']=hook+'.Hit(&foreign)'
        with self.assertRaises(M.MeasurementRefused):check(altered)


#: The recorder's own compiled behaviour, driven directly: what it writes is
#: what `project` above is given. The absolute run paths are the container's,
#: so the driver substitutes a temporary root exactly as the mutation audit
#: self-test does, and the module has no dependency to fetch.
DRIVER = '''package probe

import (
\t"testing"

\tr2tmeasure "r2tprobe.test/m/_bench/go/measure"
)

const file = "internal/probe/probe_test.go"

func alpha() { r2tmeasure.Enter(file, 11, "alpha") }
func beta()  { r2tmeasure.Enter(file, 12, "beta") }

func TestEntries(t *testing.T) {
\talpha()
\tr2tmeasure.SetStep(0)
\talpha()
\tbeta()
\tr2tmeasure.SetStep(1)
\talpha()
\tr2tmeasure.SetStep(-1)
\tbeta()
}

func TestMain(m *testing.M) { r2tmeasure.FinalizeAndExit(m.Run()) }
'''


class RecorderTests(unittest.TestCase):
    def test_step_splits_an_entry_and_orders_last(self):
        go = shutil.which('go')
        self.assertIsNotNone(go, 'the Go recorder driver requires Go 1.25.0')
        with tempfile.TemporaryDirectory(prefix='go-recorder-') as td:
            run = Path(td) / 'run'
            work = run / 'work'
            (work / '_bench/go/measure').mkdir(parents=True)
            (work / 'internal/probe').mkdir(parents=True)
            source = (Path(__file__).with_name('support') / 'measurement_recorder.go').read_bytes()
            self.assertIn(b'/r2t-go/run', source)
            (work / '_bench/go/measure/recorder.go').write_bytes(
                source.replace(b'/r2t-go/run', str(run).encode()))
            (work / 'go.mod').write_text('module r2tprobe.test/m\n\ngo 1.25.0\n')
            (work / 'internal/probe/probe_test.go').write_text(DRIVER)
            result = subprocess.run(
                [go, 'test', '-count=1', '-p=1', './internal/probe'], cwd=work,
                env=dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', GOWORK='off',
                         GOFLAGS='-mod=readonly -p=1'),
                capture_output=True, text=True, timeout=300)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            document = json.loads((run / 'measurement.json').read_text())
        self.assertEqual(document['schema'], M.SCHEMA)
        self.assertEqual(document['failures'], None)
        # One call from two steps is two entries and keeps the step it was
        # made in; one made outside a step carries null and sorts first.
        self.assertEqual(document['direct_calls'], [
            {'callee_file': file, 'callee_line': line, 'callee': name,
             'caller_file': file, 'step': step}
            for file in ['internal/probe/probe_test.go']
            for line, name, step in ((11, 'alpha', None), (11, 'alpha', 0), (11, 'alpha', 1),
                                     (12, 'beta', None), (12, 'beta', 0))])


def selftest():
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite([loader.loadTestsFromTestCase(MeasurementTests),
                                loader.loadTestsFromTestCase(RecorderTests)])
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':
    raise SystemExit(selftest())
