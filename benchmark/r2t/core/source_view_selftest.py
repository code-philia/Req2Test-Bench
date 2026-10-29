"""Network-free causal checks of actual source-view materialization."""
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from .ledger_primitives import semantic_digest
from .paths import RECORDED_ROOTS_ENV
from .source_view import (
    BodyEdit, BodyRef, ContractFile, GeneratedOperationJudgment, ItemSelection, RepairEntry, Selection,
    TargetMap, ViewPolicy, ViewRefused, ZeroBodyTreatment, build_agent_view, file_tree_digest, inventory,
    parse_generated_operation_judgments, parse_repair_set, parse_zero_body_treatment, plan_agent_view,
    qualify_source_seed, validate_view_manifest, verify_agent_view, verify_recorded_view,
    verify_view_bindings,
)


class SourceViewTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.raw = (b'class API:\n    def target(self, x=3):\n'
                    b'        return x * 7  # implementation secret\n'
                    b'    def helper(self):\n        return "surrounding"\n')
        (self.source / 'api.py').write_bytes(self.raw)
        (self.source / 'ui.js').write_text('function target() { return 7; }\n')
        self.seed = qualify_source_seed(root=str(self.source), project='fixture',
                                       runtime_seed_digest='a' * 64)
        start = self.raw.index(b'return x')
        end = self.raw.index(b'\n    def helper')
        edit = BodyEdit(BodyRef('api.py', 'API.target', 'method', start, end),
                        b'raise NotImplementedError("implementation hidden")')
        selection = Selection((edit,), ('ui.js',))
        self.mapping = TargetMap('fixture', self.seed.files_digest, 'b' * 64,
                                 'c' * 64,
                                 (ItemSelection('item-1', ('API.target',), selection),
                                  ItemSelection('item-2', ('API.helper',), Selection())),
                                 (ContractFile('TARGET_CONTRACTS.md', b'API target takes x=3.\n'),),
                                 selection)
        self.policy = ViewPolicy('fixture', 'target_hidden', 'd' * 64, 'e' * 64,
                                 'f' * 64, ('api.py', 'ui.js'), 'fixture/v1')

    def plan(self, **changes):
        args = dict(source_seed=self.seed, item_id='item-1', policy=self.policy,
                    target_map=self.mapping)
        args.update(changes)
        return plan_agent_view(**args)

    def test_actual_body_and_surrounding_contract(self):
        plan = self.plan()
        out = self.root / 'view'
        manifest = build_agent_view(plan, destination=str(out))
        actual = (out / 'api.py').read_bytes()
        self.assertNotIn(b'x * 7', actual)
        self.assertNotIn(b'implementation secret', actual)
        self.assertIn(b'def target(self, x=3):', actual)
        self.assertIn(b'def helper(self):\n        return "surrounding"', actual)
        compile(actual, 'api.py', 'exec')  # syntax only; never import the subject
        self.assertFalse((out / 'ui.js').exists())
        self.assertEqual((out / 'TARGET_CONTRACTS.md').read_bytes(),
                         self.mapping.contracts[0].content)
        self.assertEqual((self.source / 'api.py').read_bytes(), self.raw)
        self.assertEqual(inventory(str(self.source)), self.seed.files)
        verify_agent_view(str(out), manifest)
        verify_view_bindings(manifest, plan)
        self.assertEqual(manifest['files_digest'], file_tree_digest(manifest['files']))
        self.assertIsNone(manifest['zero_body_treatment'])

    def test_scope_and_item_are_part_of_actual_evidence(self):
        manifests = []
        for scope in ('full', 'target_hidden', 'all_hidden'):
            plan = self.plan(policy=replace(self.policy, scope=scope))
            out = self.root / scope
            manifests.append(build_agent_view(plan, destination=str(out)))
            self.assertEqual(b'x * 7' in (out / 'api.py').read_bytes(), scope == 'full')
            self.assertEqual((out / 'TARGET_CONTRACTS.md').read_bytes(),
                             self.mapping.contracts[0].content)
        self.assertEqual(len({m['digest'] for m in manifests}), 3)
        with self.assertRaisesRegex(ViewRefused, 'another'):
            verify_view_bindings(manifests[1], self.plan(item_id='item-2'))
        with self.assertRaisesRegex(ViewRefused, 'another'):
            verify_view_bindings(manifests[1], self.plan(policy=replace(self.policy, scope='full')))

    def test_item_judgments_survive_equal_trees_in_every_scope(self):
        judgments = (
            (GeneratedOperationJudgment('API.generated', True, 'Hide the caller.',
                                        'The generated operation realizes this item.'),),
            (GeneratedOperationJudgment('API.generated', False, 'Retain the declaration.',
                                        'The operation is only setup for this item.'),),
            (),
        )
        items = tuple(ItemSelection(f'item-{index}', ('API',),
                                    self.mapping.items[0].selection, evidence)
                      for index, evidence in enumerate(judgments))
        mapping = replace(self.mapping, items=items)
        for scope in ('full', 'target_hidden', 'all_hidden'):
            manifests = []
            for item in items:
                plan = self.plan(item_id=item.item_id, target_map=mapping,
                                 policy=replace(self.policy, scope=scope))
                self.assertEqual(plan.generated_operation_judgments,
                                 item.generated_operation_judgments)
                out = self.root / f'{scope}-{item.item_id}'
                manifest = build_agent_view(plan, destination=str(out))
                self.assertEqual(manifest['generated_operation_judgments'],
                                 [asdict(j) for j in item.generated_operation_judgments])
                verify_view_bindings(manifest, plan)
                changed = {**manifest, 'generated_operation_judgments':
                           [asdict(j) for j in judgments[1 if item.item_id == 'item-0' else 0]]}
                with self.assertRaisesRegex(ViewRefused, 'another'):
                    verify_view_bindings(changed, plan)
                self.assertNotIn(b'generated_operation_judgments',
                                 b''.join((out / record['path']).read_bytes()
                                          for record in manifest['files']))
                manifests.append(manifest)
            self.assertEqual(len({m['files_digest'] for m in manifests}), 1)
            self.assertEqual(len({m['digest'] for m in manifests}), len(items))
        changed_item = replace(items[0], generated_operation_judgments=())
        self.assertNotEqual(mapping.digest, replace(mapping, items=(changed_item, *items[1:])).digest)

    def test_judgment_records_require_reviewed_fields(self):
        record = {'operation': 'API.generated', 'realizes_target_behavior': True,
                  'treatment': 'Hide the caller.', 'reason': 'It realizes this requirement.'}
        self.assertEqual(parse_generated_operation_judgments([record]),
                         (GeneratedOperationJudgment(**record),))
        self.assertEqual(parse_generated_operation_judgments([]), ())
        for records in (None, [{**record, 'realizes_target_behavior': 'yes'}],
                        [{**record, 'reason': ''}], [{k: v for k, v in record.items() if k != 'treatment'}]):
            with self.subTest(records=records), self.assertRaises(ViewRefused):
                parse_generated_operation_judgments(records)

    def test_zero_body_treatment_stays_with_item_in_every_scope(self):
        item_id = 'coreshop/features/domain/category/create_category.feature:19'
        treatment = ZeroBodyTreatment('unchanged_target_hidden',
            'The hierarchy is framework-owned; no eligible first-party body exists.')
        seed = replace(self.seed, project='coreshop')
        item = ItemSelection(item_id, ('Pimcore\\Model\\DataObject\\AbstractObject::getParent',),
                             Selection(), zero_body_treatment=treatment)
        mapping = replace(self.mapping, project='coreshop', items=(item,))
        manifests = []
        for scope in ('full', 'target_hidden', 'all_hidden'):
            policy = replace(self.policy, project='coreshop', scope=scope)
            plan = self.plan(source_seed=seed, item_id=item_id, target_map=mapping, policy=policy)
            self.assertEqual(plan.zero_body_treatment, treatment)
            out = self.root / ('zero-' + scope)
            manifest = build_agent_view(plan, destination=str(out))
            self.assertEqual(manifest['zero_body_treatment'], asdict(treatment))
            self.assertEqual(b'x * 7' in (out / 'api.py').read_bytes(), scope != 'all_hidden')
            self.assertEqual((out / 'ui.js').exists(), scope != 'all_hidden')
            self.assertNotIn(treatment.reason.encode(),
                b''.join((out / record['path']).read_bytes() for record in manifest['files']))
            verify_view_bindings(manifest, plan)
            changed = {**manifest, 'zero_body_treatment': None}
            with self.assertRaisesRegex(ViewRefused, 'another'):
                verify_view_bindings(changed, plan)
            manifests.append(manifest)
        self.assertEqual(manifests[0]['files_digest'], manifests[1]['files_digest'])
        self.assertNotEqual(manifests[1]['files_digest'], manifests[2]['files_digest'])
        self.assertEqual((self.source / 'api.py').read_bytes(), self.raw)
        changed = replace(item, zero_body_treatment=replace(treatment, reason='Another reviewed reason.'))
        self.assertNotEqual(mapping.digest, replace(mapping, items=(changed,)).digest)
        for changes in ({'item_id': 'coreshop/features/domain/category/create_category.feature:20'},
                        {'project': 'python-docx'},
                        {'hidden_bodies': [asdict(self.mapping.all_selection.bodies[0].body)]},
                        {'zero_body_treatment': {'decision': treatment.decision, 'reason': ''}}):
            invalid = {**manifests[1], **changes}
            invalid['digest'] = semantic_digest(invalid)
            with self.subTest(changes=changes), self.assertRaises(ViewRefused):
                validate_view_manifest(invalid)

    def test_zero_body_record_requires_the_approved_decision_and_reason(self):
        record = {'decision': 'unchanged_target_hidden', 'reason': 'No eligible first-party body.'}
        self.assertEqual(parse_zero_body_treatment(record), ZeroBodyTreatment(**record))
        for invalid in (None, {}, {**record, 'decision': 'allow_empty'},
                        {**record, 'reason': ''}, {**record, 'reason': '  '},
                        {**record, 'reason': False}, {**record, 'operation': 'duplicate metadata'}):
            with self.subTest(record=invalid), self.assertRaises(ViewRefused):
                parse_zero_body_treatment(invalid)

    def test_stale_input_fails_before_materialization(self):
        plan = self.plan()
        (self.source / 'api.py').write_bytes(self.raw.replace(b'x * 7', b'x * 9'))
        out = self.root / 'view'
        with self.assertRaisesRegex(ViewRefused, 'source changed'):
            build_agent_view(plan, destination=str(out))
        self.assertFalse(out.exists())
        with self.assertRaisesRegex(ViewRefused, 'different source'):
            self.plan(target_map=replace(self.mapping, source_files_digest='0' * 64))

    def test_no_clobber_or_source_writes(self):
        for destination in (self.source, self.source / 'view'):
            with self.assertRaises(ViewRefused):
                build_agent_view(self.plan(), destination=str(destination))
        out = self.root / 'occupied'
        out.mkdir()
        (out / 'mine').write_text('belongs to someone else')
        with self.assertRaisesRegex(ViewRefused, 'already exists'):
            build_agent_view(self.plan(), destination=str(out))
        self.assertEqual((out / 'mine').read_text(), 'belongs to someone else')

    def test_workspace_verification_rejects_changed_and_unexpected_bytes(self):
        out = self.root / 'view'
        manifest = build_agent_view(self.plan(), destination=str(out))
        (out / 'extra.txt').write_bytes(b'extra implementation')
        with self.assertRaisesRegex(ViewRefused, 'inventory'):
            verify_agent_view(str(out), manifest)
        (out / 'extra.txt').unlink()
        (out / 'api.py').write_bytes(self.raw)
        with self.assertRaisesRegex(ViewRefused, 'inventory'):
            verify_agent_view(str(out), manifest)

    def test_alias_refusals(self):
        (self.source / 'link.py').symlink_to(self.source / 'api.py')
        with self.assertRaisesRegex(ViewRefused, 'non-regular'):
            qualify_source_seed(root=str(self.source), project='fixture', runtime_seed_digest='a' * 64)
        (self.source / 'link.py').unlink()
        (self.source / 'api.py').unlink()
        (self.root / 'elsewhere').write_bytes(b'class API: pass  # swapped after qualification\n')
        (self.source / 'api.py').symlink_to(self.root / 'elsewhere')
        with self.assertRaisesRegex(ViewRefused, 'source changed since qualification'):
            build_agent_view(self.plan(), destination=str(self.root / 'view'))

    def test_unsupported_and_incomplete_inputs_refuse(self):
        for policy in (replace(self.policy, feedback='trial'),
                       replace(self.policy, subject_paths=('absent.py',)),
                       replace(self.policy, project='wrong')):
            with self.assertRaises(ViewRefused):
                self.plan(policy=policy)
        with self.assertRaisesRegex(ViewRefused, 'unique item'):
            self.plan(item_id='missing')
        with self.assertRaisesRegex(ViewRefused, 'all-production'):
            self.plan(policy=replace(self.policy, scope='all_hidden'),
                      target_map=replace(self.mapping, all_selection=None))
        with self.assertRaisesRegex(ViewRefused, 'overwrites'):
            self.plan(target_map=replace(self.mapping, contracts=(ContractFile('api.py', b'x'),)))
        with self.assertRaisesRegex(ViewRefused, 'collision'):
            self.plan(target_map=replace(self.mapping, contracts=(ContractFile('api.py/x', b'x'),)))

    def test_overlapping_and_nested_selection(self):
        parent = self.mapping.items[0].selection.bodies[0]
        nested = BodyEdit(replace(parent.body, declaration_id='nested',
                                 start_byte=parent.body.start_byte + 2,
                                 end_byte=parent.body.end_byte - 1), b'...')
        def mapping(edits):
            return replace(self.mapping, items=(ItemSelection('item-1', ('API',), Selection(edits)),))
        plan = self.plan(target_map=mapping((parent, nested)))
        self.assertEqual(plan.selection.bodies, (parent,))
        plan = self.plan(target_map=mapping((parent, parent)))
        self.assertEqual(plan.selection.bodies, (parent,))
        with self.assertRaisesRegex(ViewRefused, 'conflicting'):
            self.plan(target_map=mapping((parent, replace(parent, replacement=b'...'))))
        crossing = replace(nested, body=replace(nested.body, end_byte=len(self.raw)))
        with self.assertRaisesRegex(ViewRefused, 'overlapping'):
            self.plan(target_map=mapping((parent, crossing)))

    def test_recorded_view_is_read_through_an_explicit_recorded_root(self):
        """Released rows name the collection host's manifest path.

        R2T_RECORDED_ROOTS says where that directory is here; it changes where
        the manifest is read and nothing that is checked about it.
        """
        manifest = build_agent_view(self.plan(), destination=str(self.root / 'view'))
        recorded = self.root / 'collection'
        evidence = recorded / 'generations/rows/cell.jsonl.agent-views/view.json'
        evidence.parent.mkdir(parents=True)
        raw = (json.dumps(manifest, sort_keys=True, indent=1) + '\n').encode()
        evidence.write_bytes(raw)
        keys = ('source_files_digest', 'runtime_seed_digest', 'map_digest', 'policy_digest',
                'population_digest', 'interfaces_digest', 'scope', 'feedback')
        row = {'item_id': 'item-1', 'produced_files': [],
               'visibility': {'schema': 'r2t.visibility-run/v1',
                              **{key: manifest[key] for key in keys}},
               'metadata': {'agent_view': {'path': str(evidence),
                                           'file_sha256': hashlib.sha256(raw).hexdigest(),
                                           'digest': manifest['digest']}}}
        local = self.root / 'recipient'
        mapping = {RECORDED_ROOTS_ENV: f'{recorded}={local}'}
        with patch.dict(os.environ, mapping):
            self.assertEqual(verify_recorded_view(row), {})  # the recorded path wins
        recorded.rename(local)
        with patch.dict(os.environ):
            os.environ.pop(RECORDED_ROOTS_ENV, None)
            with self.assertRaisesRegex(ViewRefused, 'cannot read recorded'):
                verify_recorded_view(row)
        with patch.dict(os.environ, mapping):
            self.assertEqual(verify_recorded_view(row), {str(recorded): str(local)})
            self.assertEqual(row['metadata']['agent_view']['path'], str(evidence))
            moved = local / evidence.relative_to(recorded)
            moved.write_bytes(raw.replace(b'"item-1"', b'"item-2"'))
            with self.assertRaisesRegex(ViewRefused, 'bytes changed'):
                verify_recorded_view(row)
            moved.unlink()
            with self.assertRaisesRegex(ViewRefused, 'cannot read recorded'):
                verify_recorded_view(row)
        for malformed in (str(recorded), f'{recorded}=relative', f'{recorded}={local}:'):
            with patch.dict(os.environ, {RECORDED_ROOTS_ENV: malformed}):
                with self.assertRaisesRegex(ViewRefused, RECORDED_ROOTS_ENV):
                    verify_recorded_view(row)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def repair(path, th, content, rule):
    """A repair entry for the view bytes `th` (None: a view lacking `path`)."""
    return RepairEntry(path, None if th is None else sha256(th), sha256(content), rule, content)


#: Synthetic files of the four repaired languages (BENCHMARK_V2_SPEC section
#: 3.1): a Java constructor whose hidden body called `super`, a Go file whose
#: imports only the hidden body used, a Ruby block that runs while its file
#: loads, and a Go file and a YAML configuration file the map omits.
JAVA = (b'package p;\npublic class Child extends Base {\n'
        b'    public Child(int x) {\n        super(x, "secret");\n    }\n}\n')
GO = (b'package pkg\n\nimport (\n\t"fmt"\n\t"strings"\n)\n\n'
      b'func API(x string) string {\n\treturn fmt.Sprint(strings.ToUpper(x))\n}\n')
RUBY = (b'module TitleHelper\n  %w[a b].each do |name|\n'
        b'    define_method(name) { name }\n  end\nend\n')
SOURCES = {'src/main/java/p/Child.java': JAVA, 'pkg/api.go': GO,
           'app/helpers/title_helper.rb': RUBY,
           'pkg/omitted.go': b'package pkg\n\nfunc Helper() string { return "secret" }\n',
           'config/workflow.yml': b'workflow:\n  places: [new, paid]\n'}


def hidden_body(raw, start, end, replacement):
    """The edit that replaces `raw[start-marker:end-marker]` with `replacement`."""
    first, last = raw.index(start), raw.index(end, raw.index(start)) + len(end)
    return first, last, replacement


class RepairTests(unittest.TestCase):
    """Reviewed repairs applied by `build_agent_view` (BENCHMARK_V2_SPEC section 3.2)."""

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        source = self.root / 'source'
        for rel, raw in SOURCES.items():
            (source / rel).parent.mkdir(parents=True, exist_ok=True)
            (source / rel).write_bytes(raw)
        self.seed = qualify_source_seed(root=str(source), project='fixture',
                                       runtime_seed_digest='a' * 64)
        edits = []
        for rel, start, end, replacement in (
                ('src/main/java/p/Child.java', b'{\n        super', b'}\n}',
                 b'{ throw new UnsupportedOperationException("implementation hidden"); }\n}'),
                ('pkg/api.go', b'{\n\treturn', b'}\n', b'{ panic("implementation hidden") }\n'),
                ('app/helpers/title_helper.rb', b'\n    define_method', b'}\n',
                 b' raise "implementation hidden"; \n')):
            first, last, text = hidden_body(SOURCES[rel], start, end, replacement)
            edits.append(BodyEdit(BodyRef(rel, rel + '#body', 'body', first, last), text))
        selection = Selection(tuple(edits), ('config/workflow.yml', 'pkg/omitted.go'))
        self.mapping = TargetMap('fixture', self.seed.files_digest, 'b' * 64, 'c' * 64,
                                 (ItemSelection('item', ('API',), selection),),
                                 (ContractFile('TARGET_CONTRACTS.md', b'Contracts.\n'),), selection)
        self.policy = ViewPolicy('fixture', 'target_hidden', 'd' * 64, 'e' * 64, 'f' * 64,
                                 tuple(SOURCES), 'fixture/v2')
        # The view as transformed, before any repair: what the entries match.
        self.th = self.build('unrepaired')[1]
        self.entries = (
            repair('src/main/java/p/Child.java', self.th['src/main/java/p/Child.java'],
                   self.th['src/main/java/p/Child.java'].replace(
                       b'{ throw', b'{ super(0, null); throw'), 'ctor_super'),
            repair('pkg/api.go', self.th['pkg/api.go'],
                   self.th['pkg/api.go'].replace(b'\t"fmt"\n\t"strings"',
                                                 b'\t_ "fmt"\n\t_ "strings"'),
                   'go-blank-unused-import'),
            repair('pkg/omitted.go', None,
                   b'package pkg\n\nfunc Helper() string { panic("implementation hidden") }\n',
                   'go-omitted-file-stub'),
            repair('app/helpers/title_helper.rb', self.th['app/helpers/title_helper.rb'],
                   self.th['app/helpers/title_helper.rb'].replace(
                       b' raise "implementation hidden"; ', b' '), 'ruby_load_time_body_empty'),
            repair('config/workflow.yml', None, b'# implementation hidden\n',
                   'yaml-omitted-config-empty-document'))

    def build(self, name, repairs=(), scope='target_hidden'):
        plan = plan_agent_view(source_seed=self.seed, item_id='item',
                               policy=replace(self.policy, scope=scope),
                               target_map=self.mapping, repairs=repairs)
        applied = []
        out = self.root / name
        manifest = build_agent_view(plan, destination=str(out), applied=applied)
        return manifest, {p.relative_to(out).as_posix(): p.read_bytes()
                          for p in sorted(out.rglob('*')) if p.is_file()}, applied

    def test_each_language_is_repaired_after_the_transformation(self):
        manifest, view, applied = self.build('repaired', self.entries)
        self.assertEqual(applied, list(self.entries))
        self.assertEqual({rel: view[rel] for rel in SOURCES},
                         {e.path: e.content for e in self.entries})
        self.assertNotIn(b'secret', b''.join(view.values()))
        self.assertIn(b'super(0, null); throw', view['src/main/java/p/Child.java'])
        self.assertIn(b'_ "fmt"', view['pkg/api.go'])
        # The manifest describes the repaired bytes, and still says what the map
        # hid: an added file is in both `files` and `omitted_paths`.
        self.assertEqual(manifest['files'], [{'path': rel, 'byte_length': len(raw),
                                              'file_sha256': sha256(raw)}
                                             for rel, raw in sorted(view.items())])
        self.assertEqual(manifest['omitted_paths'], ['config/workflow.yml', 'pkg/omitted.go'])
        self.assertEqual(len(manifest['hidden_bodies']), 3)
        validate_view_manifest(manifest)
        verify_agent_view(str(self.root / 'repaired'), manifest)
        unrepaired = self.build('again')[0]
        self.assertNotEqual(manifest['files_digest'], unrepaired['files_digest'])
        self.assertEqual({k: v for k, v in manifest.items() if k not in ('files', 'files_digest', 'digest')},
                         {k: v for k, v in unrepaired.items() if k not in ('files', 'files_digest', 'digest')})

    def test_entries_of_other_instances_do_nothing(self):
        others = (repair('pkg/api.go', b'another view of the file\n', b'not this one\n', 'rule'),
                  repair('pkg/absent.go', b'another view\n', b'not this one\n', 'rule'),
                  # A view that has the path, as a file or a directory, gets no addition.
                  repair('pkg/api.go', None, b'not over a view file\n', 'rule'),
                  repair('pkg', None, b'not over a directory\n', 'rule'))
        manifest, view, applied = self.build('others', others)
        self.assertEqual((applied, view), ([], self.th))

    def test_entries_match_the_view_before_any_is_written(self):
        first = self.entries[1]
        chained = repair('pkg/api.go', first.content, b'chained\n', 'rule')
        for order in ((first, chained), (chained, first)):
            _, view, applied = self.build('chain-' + str(order.index(first)), order)
            self.assertEqual((applied, view['pkg/api.go']), ([first], first.content))

    def test_repairs_refused_outside_target_hidden_and_below_a_file(self):
        for scope in ('full', 'all_hidden'):
            with self.assertRaisesRegex(ViewRefused, 'target-hidden views only'):
                self.build(scope, self.entries, scope)
            self.assertEqual(self.build(scope + '-plain', (), scope)[2], [])
        with self.assertRaisesRegex(ViewRefused, 'below a view file'):
            self.build('below', (repair('pkg/api.go/x', None, b'x\n', 'rule'),))
        self.assertFalse((self.root / 'below').exists())

    def test_repair_index_refusals(self):
        blobs = {e.repaired_sha256: e.content for e in self.entries}
        records = [{'path': e.path, 'th_sha256': e.th_sha256,
                    'repaired_sha256': e.repaired_sha256, 'rule': e.rule} for e in self.entries]
        self.assertEqual(parse_repair_set(records, blobs.__getitem__), self.entries)
        self.assertEqual(parse_repair_set([], blobs.__getitem__), ())
        record = records[0]
        for label, index, blob in (
                ('not a list', {'entries': records}, blobs.__getitem__),
                ('two entries for one view file', records + [{**record, 'rule': 'again'}],
                 blobs.__getitem__),
                ('a blob with other bytes', records, lambda sha: blobs[sha] + b' '),
                ('an extra field', [{**record, 'note': 'x'}], blobs.__getitem__),
                ('a missing field', [{k: v for k, v in record.items() if k != 'rule'}],
                 blobs.__getitem__),
                ('an empty rule', [{**record, 'rule': ''}], blobs.__getitem__),
                ('an absolute path', [{**record, 'path': '/etc/passwd'}], blobs.__getitem__),
                ('a parent path', [{**record, 'path': 'pkg/../x'}], blobs.__getitem__),
                ('a short th digest', [{**record, 'th_sha256': 'ab'}], blobs.__getitem__),
                ('an upper-case digest', [{**record, 'repaired_sha256': record['repaired_sha256'].upper()}],
                 blobs.__getitem__)):
            with self.subTest(case=label), self.assertRaises(ViewRefused):
                parse_repair_set(index, blob)


def selftest():
    suite = unittest.TestSuite()
    for case in (SourceViewTests, RepairTests):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(selftest())
