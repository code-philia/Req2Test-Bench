"""Actual compiler fixtures and preserved native Then-strip evidence; no Docker."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from .assertion_strip import (COPY_ROOT, HELPER, SCHEMA, StripRefused, _handler_request,
    checked_plan, make_strip_adapter, prepare_stripped, selected_handlers,
    stripped_solution)
from .context import ContextTable
from .registry import read_native

FIXTURE = Path(__file__).with_name('fixtures') / 'assertion_strip'


def native_fixture(*, bdd_paths=False):
    context = json.loads((FIXTURE / 'context.json').read_text())
    mapping = json.loads((FIXTURE / 'original-planner-stdout.txt').read_text())['map']
    witness = read_native((FIXTURE / 'original-native.jsonl').read_bytes(), context=context,
        feature_source=(FIXTURE / 'strip.feature').read_text(), source_map=mapping, exit_code=1)
    originals = {p.relative_to(FIXTURE / 'source').as_posix(): p.read_bytes()
                 for p in (FIXTURE / 'source/internal/stripfixture').glob('*.go')}
    closure = {'item_id': 'coddy-agent/features/strip.feature:2',
        'feature_file': context['feature_path'], 'scenario_line': context['scenario_line'],
        'go_suite': context, 'files': sorted(originals), 'steps': witness.bindings, 'problems': []}
    plan = json.loads((FIXTURE / 'strip-plan-stdout.txt').read_text())
    if bdd_paths:
        renamed = {p: p if Path(p).name.startswith('bdd_') else
                   str(Path(p).with_name('bdd_' + Path(p).name)) for p in originals}
        originals = {renamed[p]: raw for p, raw in originals.items()}
        closure['files'] = sorted(originals)
        for step in closure['steps']:
            d = step['definition']
            d['file'] = renamed[d['file']]
            for value in (d['go']['registration'], d['go']['handler']):
                value['file'] = renamed[value['file']]
        for record in plan['files']:
            record['file'] = renamed[record['file']]
    handlers = selected_handlers(closure)
    plan.update(schema=SCHEMA, root=COPY_ROOT, package_dir=context['package_dir'],
                glue_path=context['glue_path'], go_build_tags='',
                handlers=[_handler_request(h) for h in handlers])
    return closure, originals, plan


class PlanningReplay:
    """Transport composition only; compiler and native behavior are checked separately."""
    quarantined = False

    def __init__(self, plan, code=0):
        self.plan, self.code, self.calls = plan, code, []

    def prepare(self, context, installed, inputs, **kwargs):
        assert installed is None
        self.calls.append(('prepare', deepcopy(inputs), kwargs))

    def run_planner(self, argv):
        self.calls.append(('plan', argv))
        return SimpleNamespace(returncode=self.code, stdout=json.dumps(self.plan), stderr='')

    def retire(self):
        self.calls.append(('retire',))


def singleton_fixture():
    """Small standard-library Go source with the exact reviewed singleton span."""
    from ..toolkit.assertion_selection import GO_ITEM, GO_HANDLER, GO_SOURCE
    context = json.loads((FIXTURE / 'context.json').read_text())
    context.update(feature_path='features/cli_tui.feature', scenario_line=165,
        glue_path=GO_HANDLER['file'], package_dir='external/cli', package_name='cli')
    closure = {'item_id': GO_ITEM, 'feature_file': context['feature_path'],
        'scenario_line': 165, 'go_suite': context, 'files': [GO_HANDLER['file']],
        'problems': [], 'steps': [{'keyword': keyword, 'side': 'removable',
            'definition': {'file': GO_HANDLER['file'], 'class': 'cli', 'method': 'footerShowsUsage',
                'go': {'handler': dict(GO_HANDLER)}}} for keyword in ('When', 'Then')]}
    prefix = ('package cli\nimport ("time"; "errors"; "testing")\n'
        'type cliTUIState struct {}\n'
        'func (s *cliTUIState) waitScreen(text string, d time.Duration) error {return errors.New(text)}\n'
        'func TestStripFixture(t *testing.T) {if err:=new(cliTUIState).footerShowsUsage("check");err!=nil {t.Fatal(err)}}\n')
    prefix += '\n' * (449 - prefix.count('\n'))
    prefix += '//' + ' ' * (14003 - len(prefix.encode()) - 3) + '\n'
    raw = (prefix + GO_SOURCE + '\n').encode()
    assert len(prefix.encode()) == 14003
    originals = {GO_HANDLER['file']: raw}
    return closure, originals


def thumbnail_fixture():
    """The pinned state-bearing/check/action spans in a standalone real Go package."""
    from ..toolkit.assertion_selection import GO_THUMBNAIL_ITEM, GO_THUMBNAIL_HANDLERS
    path = GO_THUMBNAIL_HANDLERS[0]['file']
    context = json.loads((FIXTURE / 'context.json').read_text())
    context.update(feature_path='features/remote_api.feature', scenario_line=51,
        glue_path=path, package_dir='external/httpserver', package_name='httpserver')
    prefix = ('package httpserver\nimport ("fmt"; "strings"; "testing"; "net/http")\n'
        'type remoteFeatureState struct {previewURL, contentType, rawBody string; status int; body map[string]interface{}}\n'
        'func (s *remoteFeatureState) requestMessages() error {return nil}\n'
        'func (s *remoteFeatureState) get(url string) error {return nil}\n'
        'func errStatus(message string, status int, body string) error {return fmt.Errorf("%s %d %s",message,status,body)}\n'
        'func TestThumbnail(t *testing.T) {s:=&remoteFeatureState{status:200,contentType:"image/png",rawBody:"\\x89PNG\\r\\n\\x1a\\n",body:map[string]interface{}{"messages":[]interface{}{map[string]interface{}{"files":[]interface{}{map[string]interface{}{"preview_url":"/thumbnail"}}}}}}; '
        'if err:=s.transcriptExposesPersistedThumbnail();err!=nil {t.Fatal(err)}; '
        'if err:=s.requestPersistedThumbnail();err!=nil {t.Fatal(err)}; '
        'if err:=s.responseIsPNG();err!=nil {t.Fatal(err)}; if err:=s.succeeds();err!=nil {t.Fatal(err)}}\n'
        'func TestRetainedMissingThumbnail(t *testing.T) {if (&remoteFeatureState{}).transcriptExposesPersistedThumbnail()==nil {t.Fatal("missing-thumbnail check removed")}}\n')
    prefix += '\n' * (281 - prefix.count('\n'))
    prefix += '//' + ' ' * (8612 - len(prefix.encode()) - 3) + '\n'
    source = (
        'func (s *remoteFeatureState) transcriptExposesPersistedThumbnail() error {\n'
        '\tif err := s.requestMessages(); err != nil {\n'
        '\t\treturn err\n'
        '\t}\n'
        '\tif err := s.succeeds(); err != nil {\n'
        '\t\treturn err\n'
        '\t}\n'
        '\tmessages, _ := s.body["messages"].([]interface{})\n'
        '\tfor _, rawMessage := range messages {\n'
        '\t\tmessage, _ := rawMessage.(map[string]interface{})\n'
        '\t\tfiles, _ := message["files"].([]interface{})\n'
        '\t\tfor _, rawFile := range files {\n'
        '\t\t\tfile, _ := rawFile.(map[string]interface{})\n'
        '\t\t\tif preview, _ := file["preview_url"].(string); preview != "" {\n'
        '\t\t\t\ts.previewURL = preview\n'
        '\t\t\t\treturn nil\n'
        '\t\t\t}\n'
        '\t\t}\n'
        '\t}\n'
        '\treturn errStatus("transcript missing persisted thumbnail", s.status, s.rawBody)\n'
        '}\n'
        '\n'
        'func (s *remoteFeatureState) requestPersistedThumbnail() error {\n'
        '\tif s.previewURL == "" {\n'
        '\t\treturn fmt.Errorf("persisted thumbnail URL is empty")\n'
        '\t}\n'
        '\treturn s.get(s.previewURL)\n'
        '}\n'
        '\n'
        'func (s *remoteFeatureState) responseIsPNG() error {\n'
        '\tif s.contentType != "image/png" || !strings.HasPrefix(s.rawBody, "\\x89PNG\\r\\n\\x1a\\n") {\n'
        '\t\treturn errStatus("response is not a PNG thumbnail", s.status, s.rawBody)\n'
        '\t}\n'
        '\treturn nil\n'
        '}\n'
        '\n'
        '// ---- assertions ----\n'
        '\n'
        'func (s *remoteFeatureState) unauthorized() error {\n'
        '\tif s.status != http.StatusUnauthorized {\n'
        '\t\treturn errStatus("want 401", s.status, s.rawBody)\n'
        '\t}\n'
        '\treturn nil\n'
        '}\n'
        '\n'
        'func (s *remoteFeatureState) succeeds() error {\n'
        '\tif s.status < 200 || s.status >= 300 {\n'
        '\t\treturn errStatus("want 2xx", s.status, s.rawBody)\n'
        '\t}\n'
        '\treturn nil\n'
        '}'
    )
    raw = (prefix + source + '\n').encode()
    handlers = [dict(file=path, line=283, start_byte=8612, end_byte=9274,
        name='transcriptExposesPersistedThumbnail', kind='function_or_method', signature='func() error'),
        dict(file=path, line=305, start_byte=9276, end_byte=9454,
        name='requestPersistedThumbnail', kind='function_or_method', signature='func() error'),
        *GO_THUMBNAIL_HANDLERS]
    closure = dict(item_id=GO_THUMBNAIL_ITEM, feature_file=context['feature_path'],
        scenario_line=51, go_suite=context, files=[path], problems=[], steps=[
            dict(keyword='When' if h['name']=='requestPersistedThumbnail' else 'Then',
                side='removable', definition=dict(file=path, **{'class':'httpserver'},
                method=h['name'], go={'handler': dict(h)})) for h in handlers])
    return closure, {path: raw}


def control_sources_fixture(root, *, asset_index_sha256, stripped_control_policy):
    """Reusable actual-planner inputs and synthetic baselines for bundle fixtures.

    Collection never calls this helper. Only preparation runs a local compiler;
    consumers can relocate the result and forbid all process launches on replay.
    """
    from . import controls
    from .control_adapter import save_control_plan
    from .closure import stub_solution
    from ..bench.reference_workloads import reference_recipe
    from ..bench.mutation_run import sha256_file
    from ..toolkit.assertion_selection import POLICY, reviewed_assertion_selection
    from ..data.release import _write_gold_fixture
    from ..bench.fixtures import make_gold_adapter
    assert stripped_control_policy == POLICY, 'singleton fixture requires the reviewed policy'
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    closure, originals = singleton_fixture()
    # Reflection facts for the fixture's single string argument registration.
    for step in closure['steps']:
        step['origin'] = 'scenario'
        step['text'] = 'check "value"'
        step['definition']['pattern'] = '^check "([^"]*)"$'
        step['definition']['go'].update(keyword=3, handler_type='func(string) error', arguments=['value'])
    gold = root / 'gold'; context = closure['go_suite']
    for p, raw in originals.items():
        target = gold / p; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
    (gold / 'go.mod').write_text('module fixture\n\ngo 1.25.0\n')
    feature_root = root / 'feature-source'
    feature = feature_root / context['feature_path']; feature.parent.mkdir(parents=True)
    feature.write_text('Feature: singleton\n' + '\n' * 163 +
        '  Scenario: check\n    When check "value"\n    Then check "value"\n')
    item = dict(closure, project='coddy-agent', framework='godog', language='go')
    release = root / 'release/items.jsonl'; release.parent.mkdir()
    release.write_text(json.dumps(item) + '\n')
    closures_path = root / 'closures.json'; closures_path.write_text(json.dumps([closure]))
    release_gold = release.parent / 'gold'
    _write_gold_fixture(str(release_gold), {item['item_id']: closure['files']})
    manifest = json.loads((release_gold / 'manifest.json').read_text())
    (release_gold / manifest[item['item_id']]).write_text(json.dumps(closure))
    go = shutil.which('go'); assert go, 'fixture needs the pinned native Go compiler'
    env = dict(os.environ, GOFLAGS='-mod=readonly -p=1', GOTOOLCHAIN='local', GOPROXY='off', GOWORK='off')
    binaries = {}
    for stem in ('assertion_strip', 'controls'):
        binaries[stem] = str(root / (stem + '-planner'))
        subprocess.run([go, 'build', '-o', binaries[stem],
            str(Path(__file__).with_name('support') / (stem + '.go'))],
            env=env, capture_output=True, check=True)
    class NativeCopy:
        quarantined = False
        def prepare(self, ctx, installed, inputs, **kwargs): self.inputs = inputs
        def retire(self): pass
        def run_planner(self, argv):
            stripping = HELPER in ' '.join(argv)
            request = root / 'native-request.json'
            if stripping:
                request.write_bytes(self.inputs['_bench/go/assertion-strip-request.json'])
                command = [binaries['assertion_strip'], '-root', str(gold),
                    '-package', context['package_dir'], '-file', context['glue_path'], '-request', str(request)]
            else:
                payload = json.loads(self.inputs['_bench/go/control-context.json'])
                payload['root'] = str(gold); request.write_text(json.dumps(payload))
                command = [binaries['controls'], '-context', str(request)]
            result = subprocess.run(command, cwd=gold, env=env, capture_output=True, text=True)
            assert result.returncode == 0, result.stderr
            plan = json.loads(result.stdout)
            (plan if stripping else plan['context'])['root'] = COPY_ROOT
            result.stdout = json.dumps(plan)
            return result
    selection = reviewed_assertion_selection(closure, policy=POLICY)
    prepared = {
        'stripped_gold': prepare_stripped(NativeCopy(), closure=closure,
            original_answers=originals, allowed_paths=closure['files'], assertion_selection=selection),
        'stub': controls.prepare_control(NativeCopy(), context=context, original_answers=originals,
            allowed_paths=closure['files'], mode='noop', closure=closure)}
    result = dict(execution_release_path=str(release), gold_root=str(gold),
        release_gold_root=str(release_gold), closures_path=str(closures_path),
        feature_root=str(feature_root), go_control_plans_root=str(root / 'go-control-plans'),
        run_paths={}, recipe_paths={})
    for role in ('full_gold', 'stripped_gold', 'stub'):
        policy = POLICY if role == 'stripped_gold' else None
        if role == 'full_gold':
            payload = make_gold_adapter(str(release.parent), str(gold))(item)
        else:
            save_control_plan(result['go_control_plans_root'], role=role, closure=closure,
                originals=originals, prepared=prepared[role],
                assertion_selection=selection if role == 'stripped_gold' else None)
            payload = (stripped_solution(closure, prepared[role], assertion_selection=selection)
                if role == 'stripped_gold' else stub_solution(item, closure, prepared_control=prepared[role]))
        recipe = reference_recipe(role=role, adapter_version=1, release_sha256=sha256_file(str(release)),
            asset_index_sha256=asset_index_sha256, control_policy=policy)
        row = dict(item_id=item['item_id'], adapter=recipe['adapter'], outcome='passed',
            produced_files=payload['files'], metadata=payload['metadata'],
            reference_derivation={k: v for k, v in recipe.items() if k != 'asset_index_sha256'},
            reference_source_tag='fixture-reviewed-native-control')
        run = root / (role + '.jsonl'); run.write_text(json.dumps(row) + '\n')
        recipe_path = root / (role + '.recipe.json'); recipe_path.write_text(json.dumps(recipe))
        result['run_paths'][role], result['recipe_paths'][role] = str(run), str(recipe_path)
    return result


def saved_plan_roundtrip(closure, originals, prepared, *, role, policy=None):
    """Use the reference validator after relocation with all process launch forbidden."""
    from unittest.mock import patch
    from .control_adapter import save_control_plan, plan_member
    from ..toolkit.assertion_selection import reviewed_assertion_selection
    from ..bench.reference_workloads import validate_control_input, reference_recipe, ReferenceWorkloadRefused
    from ..bench.mutation_run import sha256_file
    from .closure import stub_solution
    selection = reviewed_assertion_selection(closure, policy=policy) if role == 'stripped_gold' else None
    produced = (stripped_solution(closure, prepared, assertion_selection=selection)
        if role == 'stripped_gold' else stub_solution(closure, closure, prepared_control=prepared))
    with tempfile.TemporaryDirectory(prefix='go-saved-replay-') as directory:
        root = Path(directory) / 'producer'; root.mkdir()
        for p, raw in originals.items():
            target = root / 'gold' / p
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        (root / 'closures.json').write_text(json.dumps([closure]))
        task = dict(closure, project='coddy-agent')
        (root / 'items.jsonl').write_text(json.dumps(task) + '\n')
        recipe = reference_recipe(role=role, adapter_version=1,
            release_sha256=sha256_file(str(root / 'items.jsonl')),
            asset_index_sha256='b' * 64, control_policy=policy)
        (root / 'recipe.json').write_text(json.dumps(recipe))
        row = {'item_id': closure['item_id'], 'adapter': recipe['adapter'], 'outcome': 'passed',
            'produced_files': produced['files'], 'metadata': produced['metadata'],
            'reference_derivation': {k: v for k, v in recipe.items() if k != 'asset_index_sha256'},
            'reference_source_tag': 'fixture-reviewed-native-control'}
        (root / 'run.jsonl').write_text(json.dumps(row) + '\n')
        save_control_plan(root / 'go-control-plans', role=role, closure=closure,
            originals=originals, prepared=prepared, assertion_selection=selection)
        relocated = Path(directory) / 'installed'; root.rename(relocated); root = relocated
        args = dict(project='coddy-agent', role=role, run_path=str(root / 'run.jsonl'),
            recipe_path=str(root / 'recipe.json'), execution_release_path=str(root / 'items.jsonl'),
            gold_root=str(root / 'gold'), release_gold_root=str(root / 'release/gold'),
            closures_path=str(root / 'closures.json'), go_control_plans_root=str(root / 'go-control-plans'))
        member = root / 'go-control-plans' / plan_member(role, closure)
        original_record = json.loads(member.read_text())
        def refuses(call):
            try: call()
            except (ReferenceWorkloadRefused, StripRefused): pass
            else: raise AssertionError('changed saved authority accepted')
        with patch('subprocess.run', side_effect=AssertionError('offline compiler/executor call')), \
             patch('subprocess.Popen', side_effect=AssertionError('offline process call')):
            validated = validate_control_input(**args)
            assert validated['files_by_item'] == {closure['item_id']: produced['files']}
            refuses(lambda: validate_control_input(**dict(args, go_control_plans_root=None)))
            for key in ('closure', 'original_answers', 'request', 'planner_sha256', 'assertion_selection'):
                bad = deepcopy(original_record); bad[key] = 'changed'
                member.write_text(json.dumps(bad)); refuses(lambda: validate_control_input(**args))
            for key, value in (('returncode', 1), ('stdout', '{}')):
                bad = deepcopy(original_record); bad['result'][key] = value
                member.write_text(json.dumps(bad)); refuses(lambda: validate_control_input(**args))
            member.write_text(json.dumps(original_record))
            first = root / 'gold' / next(iter(originals)); raw = first.read_bytes()
            first.write_bytes(raw + b'\n'); refuses(lambda: validate_control_input(**args)); first.write_bytes(raw)
            altered = deepcopy(closure); altered['go_suite']['godog_tags'] = '@changed'
            (root / 'closures.json').write_text(json.dumps([altered]))
            refuses(lambda: validate_control_input(**args))
            (root / 'closures.json').write_text(json.dumps([closure]))
            if selection:
                badrow = deepcopy(row); badrow['metadata']['n_then_definitions'] = 1
                (root / 'run.jsonl').write_text(json.dumps(badrow) + '\n')
                refuses(lambda: validate_control_input(**args))
                (root / 'run.jsonl').write_text(json.dumps(row) + '\n')
            member.unlink(); refuses(lambda: validate_control_input(**args))


class AssertionStripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.go = shutil.which('go')
        if cls.go is None:
            raise RuntimeError('Go assertion fixtures require qualified Go 1.25.0')
        cls.support = tempfile.TemporaryDirectory(prefix='go-assertion-support-')
        cls.binary = str(Path(cls.support.name) / 'strip')
        cls.env = dict(os.environ, GOFLAGS='-mod=readonly -p=1', GOTOOLCHAIN='local',
                       GOPROXY='off', GOWORK='off')
        subprocess.run([cls.go, 'build', '-p=1', '-o', cls.binary,
            str(Path(__file__).with_name('support') / 'assertion_strip.go')],
            env=cls.env, capture_output=True, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.support.cleanup()

    def test_reviewed_singleton_live_factory_and_offline_replay(self):
        from ..toolkit.assertion_selection import GO_ITEM, GO_HANDLER, GO_SOURCE, POLICY, reviewed_assertion_selection
        from ..bench.fixtures import _build_stripped_gold
        # The exact reviewed source span/line is exercised in a small real Go package.
        closure, originals = singleton_fixture()
        context = closure['go_suite']
        raw = originals[GO_HANDLER['file']]
        selection = reviewed_assertion_selection(closure, policy=POLICY)
        self.assertEqual(len(selected_handlers(closure, assertion_selection=selection)), 1)
        with self.assertRaises(StripRefused): selected_handlers(closure)
        for kind in ('missing', 'handler', 'span', 'signature', 'retained'):
            bad = deepcopy(closure)
            if kind == 'missing': bad['steps'] = []
            elif kind == 'handler':
                for step in bad['steps']: step['definition']['go']['handler'] = None
            elif kind == 'retained': bad['steps'][0]['side'] = 'retained'
            else: bad['steps'][0]['definition']['go']['handler'][
                'start_byte' if kind == 'span' else 'signature'] = 1 if kind == 'span' else 'func() error'
            with self.subTest(kind=kind), self.assertRaises(StripRefused):
                reviewed_assertion_selection(bad, policy=POLICY)
        with tempfile.TemporaryDirectory(prefix='go-singleton-') as directory:
            root = Path(directory); target = root / GO_HANDLER['file']
            target.parent.mkdir(parents=True); target.write_bytes(raw)
            (root / 'go.mod').write_text('module fixture\n\ngo 1.25.0\n')
            (root / 'closures.json').write_text(json.dumps([closure]))
            table = ContextTable([closure], boundary=SimpleNamespace(project='coddy-agent',
                classify=lambda p: 'removable'), project='coddy-agent')
            testcase = self
            class NativeCopy:
                quarantined = False
                def prepare(self, ctx, installed, inputs, **kwargs):
                    self.inputs = inputs
                def run_planner(self, argv):
                    request = root / 'request.json'; request.write_bytes(self.inputs['_bench/go/assertion-strip-request.json'])
                    result = subprocess.run([testcase.binary, '-root', str(root), '-package', 'external/cli',
                        '-file', GO_HANDLER['file'], '-request', str(request)], cwd=root,
                        env=testcase.env, capture_output=True, text=True)
                    testcase.assertEqual(result.returncode, 0, result.stderr)
                    # The production transport mounts its disposable copy at COPY_ROOT.
                    plan = json.loads(result.stdout); plan['root'] = COPY_ROOT
                    result.stdout = json.dumps(plan)
                    return result
                def retire(self): pass
            harness = SimpleNamespace(manifest=SimpleNamespace(gold_root=str(root)), contexts=table,
                check_context=table.check_context, copy=NativeCopy(), coordination_inputs=lambda: {})
            args = SimpleNamespace(gold=str(root), artifacts=str(root),
                profile=str(Path(__file__).resolve().parents[2] / 'config/profile_coddy_agent.yml'),
                assertion_selection_policy=POLICY)
            adapter = _build_stripped_gold(args, harness)
            payload = adapter(closure)
            self.assertTrue(payload['files'], payload)
            self.assertEqual(payload['metadata']['assertion_selection'], selection)
            self.assertNotIn('n_then_definitions', payload['metadata'])
            prepared = prepare_stripped(harness.copy, closure=closure, original_answers=originals,
                allowed_paths=closure['files'], assertion_selection=selection)
            saved_plan_roundtrip(closure, originals, prepared, role='stripped_gold', policy=POLICY)
            self.assertEqual(target.read_bytes(), raw)
            target.write_bytes(prepared.files[GO_HANDLER['file']])
            run = subprocess.run([self.go, 'test', '-count=1', './external/cli'], cwd=root,
                                 env=self.env, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn(b'func (s *cliTUIState) waitScreen', target.read_bytes())
            bad = dict(originals); bad[GO_HANDLER['file']] = raw.replace(b'3*time.Second', b'4*time.Second')
            with self.assertRaises(StripRefused):
                prepare_stripped(harness.copy, closure=closure, original_answers=bad,
                    allowed_paths=closure['files'], assertion_selection=selection)

    def test_thumbnail_partial_strip_preserves_state_and_saved_replay(self):
        from ..toolkit.assertion_selection import POLICY, reviewed_assertion_selection
        closure, originals = thumbnail_fixture()
        selection = reviewed_assertion_selection(closure, policy=POLICY)
        self.assertEqual([h['name'] for h in selection['handlers']], ['responseIsPNG', 'succeeds'])
        self.assertEqual(len(selected_handlers(closure)), 3)
        for kind in ('missing', 'span', 'signature', 'retained'):
            bad = deepcopy(closure)
            if kind == 'missing': bad['steps'].pop()
            elif kind == 'retained': bad['steps'][-1]['side'] = 'retained'
            else: bad['steps'][-1]['definition']['go']['handler'][
                'start_byte' if kind == 'span' else 'signature'] = 0 if kind == 'span' else 'func(int) error'
            with self.subTest(kind=kind), self.assertRaises(StripRefused):
                reviewed_assertion_selection(bad, policy=POLICY)
        with tempfile.TemporaryDirectory(prefix='go-thumbnail-') as directory:
            root = Path(directory); path, raw = next(iter(originals.items()))
            target = root / path; target.parent.mkdir(parents=True); target.write_bytes(raw)
            (root / 'go.mod').write_text('module fixture\n\ngo 1.25.0\n')
            testcase = self
            class NativeCopy:
                quarantined = False
                def prepare(self, ctx, installed, inputs, **kwargs): self.inputs = inputs
                def retire(self): pass
                def run_planner(self, argv):
                    request = root / 'request.json'
                    request.write_bytes(self.inputs['_bench/go/assertion-strip-request.json'])
                    result = subprocess.run([testcase.binary, '-root', str(root),
                        '-package', 'external/httpserver', '-file', path, '-request', str(request)],
                        cwd=root, env=testcase.env, capture_output=True, text=True)
                    testcase.assertEqual(result.returncode, 0, result.stderr)
                    plan = json.loads(result.stdout); plan['root'] = COPY_ROOT
                    result.stdout = json.dumps(plan)
                    return result
            def execute():
                return subprocess.run([self.go, 'test', '-count=1', './external/httpserver'],
                    cwd=root, env=self.env, capture_output=True, text=True)
            self.assertEqual(execute().returncode, 0)
            automatic = prepare_stripped(NativeCopy(), closure=closure,
                original_answers=originals, allowed_paths=closure['files'])
            target.write_bytes(automatic.files[path])
            failed = execute()
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn('persisted thumbnail URL is empty', failed.stdout)
            target.write_bytes(raw)
            prepared = prepare_stripped(NativeCopy(), closure=closure,
                original_answers=originals, allowed_paths=closure['files'], assertion_selection=selection)
            payload = stripped_solution(closure, prepared, assertion_selection=selection)
            self.assertEqual(payload['metadata']['assertion_selection'], selection)
            self.assertNotIn('n_then_definitions', payload['metadata'])
            self.assertIn(raw[8612:9274], prepared.files[path])
            self.assertIn(raw[9276:9454], prepared.files[path])
            saved_plan_roundtrip(closure, originals, prepared, role='stripped_gold', policy=POLICY)
            target.write_bytes(prepared.files[path])
            passed = execute()
            self.assertEqual(passed.returncode, 0, passed.stdout + passed.stderr)
            for old, new in ((b'if s.status < 200', b'if s.status < 201'),
                             (b'*remoteFeatureState) succeeds', b'*changedFeatureType) succeeds')):
                bad = {path: raw.replace(old, new)}
                with self.assertRaises(StripRefused):
                    prepare_stripped(NativeCopy(), closure=closure, original_answers=bad,
                        allowed_paths=closure['files'], assertion_selection=selection)

    def test_reusable_reference_fixture(self):
        from unittest.mock import patch
        from ..bench.reference_workloads import fixture_control_sources, validate_control_input
        from ..toolkit.assertion_selection import POLICY
        with tempfile.TemporaryDirectory(prefix='go-reference-inputs-') as directory:
            fixture = fixture_control_sources(directory, project='coddy-agent', stripped_control_policy=POLICY)
            with patch('subprocess.Popen', side_effect=AssertionError('replay launched compiler')):
                for role in ('full_gold', 'stripped_gold', 'stub'):
                    result = validate_control_input(project='coddy-agent', role=role,
                        run_path=fixture['run_paths'][role], recipe_path=fixture['recipe_paths'][role],
                        **{k: v for k, v in fixture.items() if k not in ('run_paths', 'recipe_paths')})
                    self.assertEqual(len(result['files_by_item']), 1)

    def test_actual_native_evidence_and_original_import_init(self):
        closure, originals, plan = native_fixture()
        prepared = checked_plan(json.dumps(plan), context=closure['go_suite'],
                                handlers=selected_handlers(closure), originals=originals)
        source = prepared.files['internal/stripfixture/assertions_test.go']
        self.assertIn(b'_ "github.com/EvilFreelancer/coddy-agent/internal/stripinit"', source)
        self.assertNotIn(b'REMOVED ', source)
        for p in originals.keys() - {'internal/stripfixture/assertions_test.go'}:
            self.assertEqual(prepared.files[p], originals[p])
        mapping = json.loads((FIXTURE / 'stripped-planner-stdout.txt').read_text())['map']
        witness = read_native((FIXTURE / 'stripped-native.jsonl').read_bytes(),
            context=closure['go_suite'], feature_source=(FIXTURE / 'strip.feature').read_text(),
            source_map=mapping, exit_code=0)
        self.assertEqual([s['result'] for s in witness.records[0]['steps']], ['passed'] * 4)
        markers = lambda name: [line for line in (FIXTURE / name).read_text().splitlines()
                               if line.startswith('PRESERVED ')]
        self.assertEqual(markers('original-native-stdout.txt'), markers('stripped-native-stdout.txt'))
        self.assertEqual(len(markers('stripped-native-stdout.txt')), 9)
        self.assertEqual(markers('stripped-native-stdout.txt')[0], 'PRESERVED imported package init')

    def test_native_ownership_and_universal_refusals(self):
        closure, _, _ = native_fixture()
        selected = selected_handlers(closure)
        self.assertEqual(len(selected), 2)
        self.assertEqual({h['kind'] for h in selected}, {'function_or_method', 'function_literal'})
        self.assertNotEqual(closure['steps'][0]['definition']['go']['handler']['file'], selected[0]['file'])
        for kind in ('shared', 'retained', 'missing', 'conflicting'):
            bad = deepcopy(closure)
            if kind == 'shared':
                bad['steps'][0]['definition']['go']['handler'] = deepcopy(selected[0])
            elif kind == 'retained':
                bad['files'].remove(selected[0]['file'])
            elif kind == 'missing':
                bad['steps'][0]['definition']['go']['handler'] = None
            else:
                duplicate = deepcopy(bad['steps'][2])
                duplicate['definition']['go']['handler']['signature'] = 'func() int'
                bad['steps'].append(duplicate)
            with self.subTest(kind=kind), self.assertRaises(StripRefused):
                selected_handlers(bad)

    def test_context_preflight_original_only_adapter_and_retirement(self):
        closure, originals, plan = native_fixture(bdd_paths=True)
        boundary = SimpleNamespace(project='coddy-agent', classify=lambda p:
                                   'removable' if p in originals else 'retained')
        table = ContextTable([closure], boundary=boundary, project='coddy-agent')
        copy = PlanningReplay(plan)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for p, raw in originals.items():
                (root / p).parent.mkdir(parents=True, exist_ok=True)
                (root / p).write_bytes(raw)
            closures = root / 'closures.json'
            closures.write_text(json.dumps([closure]))
            harness = SimpleNamespace(manifest=SimpleNamespace(gold_root=str(root)),
                contexts=table, check_context=table.check_context, copy=copy,
                coordination_inputs=lambda: {'.r2t-exec.lock': b'123\n'})
            from unittest.mock import patch
            from .. import stacks
            from ..bench.fixtures import _build_stripped_gold
            profile = Path(__file__).resolve().parents[2] / 'config/profile_coddy_agent.yml'
            args = SimpleNamespace(gold=str(root), artifacts=str(root), profile=str(profile))
            # The complete-stack gate owns production registration. Exercise
            # its normal shared factory now with the real, checked Go profile.
            with patch.dict(stacks.KNOWN_FRAMEWORKS, {'godog': 'godog'}):
                adapter = _build_stripped_gold(args, harness)
            bad = deepcopy(closure); bad['go_suite']['godog_tags'] = '@foreign'
            self.assertTrue(adapter(bad)['metadata']['strip_refusal'])
            self.assertEqual(copy.calls, [])
            bad = deepcopy(closure); bad['files'].pop()
            self.assertTrue(adapter(bad)['metadata']['strip_refusal'])
            self.assertEqual(copy.calls, [])
            task = deepcopy(closure); task['candidate_source'] = 'must never be read as gold'
            result = adapter(task)
            self.assertEqual({f['file_path'] for f in result['files']}, set(originals))
            self.assertTrue(result['metadata']['stripped_gold'])
            self.assertEqual([c[0] for c in copy.calls], ['prepare', 'plan', 'retire'])
            self.assertEqual({p: copy.calls[0][1][p] for p in originals}, originals)
            self.assertIn(HELPER, copy.calls[0][1])
            self.assertIsNotNone(copy.calls[0][2]['deadline'])
            self.assertEqual(copy.calls[0][2]['coordination_inputs'],
                             {'.r2t-exec.lock': b'123\n'})
            self.assertEqual({p: (root / p).read_bytes() for p in originals}, originals)
        for overrides in ({'original_answers': {}}, {'allowed_paths': closure['files'][:-1]}):
            copy = PlanningReplay(plan)
            args = dict(closure=closure, original_answers=originals, allowed_paths=closure['files'])
            args.update(overrides)
            with self.assertRaises(StripRefused):
                prepare_stripped(copy, **args)
            self.assertEqual(copy.calls, [])
        copy = PlanningReplay(plan, code=1)
        with self.assertRaises(StripRefused):
            prepare_stripped(copy, closure=closure, original_answers=originals,
                             allowed_paths=closure['files'])
        self.assertEqual(copy.calls[-1], ('retire',))

    def test_actual_compiler_methods_literals_blank_imports_and_init(self):
        closure, _, _ = native_fixture(bdd_paths=True)
        primary = closure['go_suite']['glue_path']
        helper = 'internal/stripfixture/bdd_helpers_test.go'
        assertions = 'internal/stripfixture/bdd_assertions_test.go'
        sources = {primary: b'''package stripfixture
import "testing"
func TestStripFixture(t *testing.T) {
 s:=&setupState{}; if s.Assert()!=nil {t.Fatal("setup")}
 a:=&assertionState{originalHelper(s.value)}
 if err:=a.Assert();err!=nil {t.Error(err)}
 if err:=literal();err!=nil {t.Error(err)}
}
''', helper: (FIXTURE / 'source/internal/stripfixture/helpers_test.go').read_bytes(),
            assertions: b'''package stripfixture
import ("errors"; "fmt"; "fixture/internal/stripinit")
type assertionState struct {value int}
func (s *assertionState) Assert() error {
 if s.value != 43 {return fmt.Errorf("wrong value")}
 fmt.Println("REMOVED method"); return nil
}
var literal=func() error {
 sideeffect.AssertionMarker(); return errors.New("EXPECTED false")
}
func unsupported() int {return 1}
'''}
        def handler(path, marker, kind, name, signature='func() error'):
            raw = sources[path]; start = raw.index(marker)
            end = raw.index(b'\n}', start) + 2 if b'\n}' in raw[start:] else raw.index(b'\n', start)
            return dict(file=path, start_byte=start, end_byte=end, kind=kind,
                        name=name if name else 'func@' + str(start), signature=signature)
        handlers = [handler(assertions, b'func (s *assertionState)', 'function_or_method', 'Assert'),
                    handler(assertions, b'func() error', 'function_literal', None)]
        with tempfile.TemporaryDirectory(prefix='go-assertion-compiler-') as directory:
            root = Path(directory)
            all_sources = dict(sources)
            all_sources['internal/stripinit/marker.go'] = (FIXTURE / 'source/internal/stripinit/marker.go').read_bytes()
            for p, raw in all_sources.items():
                (root / p).parent.mkdir(parents=True, exist_ok=True); (root / p).write_bytes(raw)
            (root / 'go.mod').write_text('module fixture\n\ngo 1.25.0\n')
            request = root / 'request.json'; request.write_text(json.dumps({'handlers': handlers}))
            def run(argv):
                return subprocess.run(argv, cwd=root, env=self.env, capture_output=True, text=True)
            argv = [self.binary, '-root', str(root), '-package', 'internal/stripfixture',
                    '-file', primary, '-request', str(request)]
            original = run([self.go, 'test', '-v', '-count=1', './internal/stripfixture'])
            self.assertEqual(original.returncode, 1, original.stdout + original.stderr)
            planned = run(argv)
            self.assertEqual(planned.returncode, 0, planned.stderr)
            self.assertEqual({p: (root / p).read_bytes() for p in all_sources}, all_sources)
            prepared = checked_plan(planned.stdout, context=closure['go_suite'], handlers=handlers,
                                    originals=sources, root=str(root))
            portable_plan = json.loads(planned.stdout); portable_plan['root'] = COPY_ROOT
            portable = prepare_stripped(PlanningReplay(portable_plan),
                closure=dict(closure, steps=[{'keyword': 'Then', 'side': 'removable',
                    'definition': {'go': {'handler': h}}} for h in handlers]),
                original_answers=sources, allowed_paths=list(sources))
            saved_plan_roundtrip(dict(closure, steps=[{'keyword': 'Then', 'side': 'removable',
                'definition': {'go': {'handler': h}}} for h in handlers]),
                sources, portable, role='stripped_gold')
            self.assertEqual(prepared.files[primary], sources[primary])
            self.assertEqual(prepared.files[helper], sources[helper])
            for p, raw in prepared.files.items():
                (root / p).write_bytes(raw)
            stripped = run([self.go, 'test', '-v', '-count=1', './internal/stripfixture'])
            self.assertEqual(stripped.returncode, 0, stripped.stdout + stripped.stderr)
            self.assertIn('PRESERVED imported package init', original.stdout)
            self.assertIn('PRESERVED imported package init', stripped.stdout)
            self.assertIn('PRESERVED original helper 42', stripped.stdout)
            self.assertIn('REMOVED method', original.stdout)
            self.assertNotIn('REMOVED ', stripped.stdout)
            for p, raw in sources.items():
                (root / p).write_bytes(raw)
            unsupported = handler(assertions, b'func unsupported', 'function_or_method', 'unsupported', 'func() int')
            request.write_text(json.dumps({'handlers': [unsupported]}))
            refused = run(argv)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('unsupported native handler return signature', refused.stderr)
            self.assertEqual({p: (root / p).read_bytes() for p in sources}, sources)


def selftest():
    return 0 if unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(AssertionStripTests)).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(selftest())
