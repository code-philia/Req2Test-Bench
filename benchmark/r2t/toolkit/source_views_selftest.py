"""Parser-to-view checks: actual bodies hidden, public contracts preserved."""
from dataclasses import asdict, replace
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ..core.source_view import (
    ItemSelection, Selection, TargetMap, ViewPolicy, ViewRefused,
    build_agent_view, plan_agent_view, qualify_source_seed,
)
from . import source_views
from .source_views import prepare_view, source_bodies, parse_source


def write_repair_set(root, project, entries):
    """A synthetic `<root>/<project>/th-view-repairs/` from `(path, view
    bytes or None, repaired bytes, rule)` entries; returns the index sha256."""
    directory = Path(root) / project / source_views.REPAIRS_DIR
    (directory / 'blobs').mkdir(parents=True)
    index = []
    for path, th, content, rule in entries:
        sha = hashlib.sha256(content).hexdigest()
        (directory / 'blobs' / sha).write_bytes(content)
        index.append({'path': path, 'repaired_sha256': sha, 'rule': rule,
                      'th_sha256': None if th is None else hashlib.sha256(th).hexdigest()})
    raw = json.dumps(index, indent=1).encode()
    (directory / 'index.json').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def repair_data(root, pins):
    """Read repair sets from `root` under `pins` instead of the repository's
    (a synthetic project fixture must not receive a real project's repairs)."""
    return patch.multiple(source_views, REPAIRS_ROOT=Path(root),
                          REPAIR_INDEX_SHA256=dict(pins))


def fixture_map(root, project='python-docx'):
    """Small named-delegation fixture using the same artifact reader as a run."""
    root = Path(root)
    (root / 'src').mkdir()
    (root / 'src/api.py').write_text(
        'class Checker:\n    def valid(self, value: int = 3) -> bool:\n'
        '        """Whether the documented value is valid."""\n'
        '        # hidden checker algorithm\n        return value > 0\n'
        'class Validator:\n    def valid(self, value):\n'
        '        return Checker().valid(value)\n'
        '    def setup(self):\n        return 7\n')
    seed = qualify_source_seed(root=str(root), project=project, runtime_seed_digest='a' * 64,
                               readable_paths=('src',))
    item = {'item_id': 'fixture/example.feature:1',
            'target_interfaces': {'behaviour': ['api.Validator'], 'setup': []},
            'principals': ['api.Validator.valid'],
            'bodies': [{'path': 'src/api.py', 'declaration_id': 'api.' + name, 'kind': 'method'}
                       for name in ('Validator.valid', 'Checker.valid')],
            'omitted_paths': [], 'generated_operation_judgments': [],
            'delegation': [{'from': 'api.Validator.valid', 'to': 'api.Checker.valid',
                            'evidence': 'src/api.py:8', 'decision': 'hide behavior-bearing checker'}]}
    items = [item]
    return {'schema': 'r2t.target-body-map/v1', 'project': project,
            'runtime_seed_digest': 'a' * 64, 'source_files_digest': seed.files_digest,
            'subject_paths': ['src/api.py'], 'items': items, 'all_file_rules': [],
            'contracts': [{'path': 'TARGET_CONTRACTS.md', 'content': 'Use Validator.valid(value).',
                           'sources': ['src/api.py public declaration']}]}


def php_fixture_map(root, project='sylius'):
    """The same named-delegation fixture in PHP, for the PHP projects."""
    root = Path(root)
    (root / 'src').mkdir()
    (root / 'src/Api.php').write_text(
        '<?php\n'
        'namespace Api;\n'
        'class Checker\n{\n'
        '    /** Whether the documented value is valid. */\n'
        '    public function valid(int $value = 3): bool\n    {\n'
        '        // hidden checker algorithm\n        return $value > 0;\n    }\n}\n'
        'class Validator\n{\n'
        '    public function valid(int $value): bool\n    {\n'
        '        return (new Checker())->valid($value);\n    }\n'
        '    public function setup(): int\n    {\n        return 7;\n    }\n}\n')
    seed = qualify_source_seed(root=str(root), project=project, runtime_seed_digest='a' * 64,
                               readable_paths=('src',))
    item = {'item_id': 'fixture/example.feature:1',
            'target_interfaces': {'behaviour': ['Api\\Validator'], 'setup': []},
            'principals': ['Api\\Validator::valid'],
            'bodies': [{'path': 'src/Api.php', 'declaration_id': 'Api\\' + name, 'kind': 'method'}
                       for name in ('Validator::valid', 'Checker::valid')],
            'omitted_paths': [], 'generated_operation_judgments': [],
            'delegation': [{'from': 'Api\\Validator::valid', 'to': 'Api\\Checker::valid',
                            'evidence': 'src/Api.php:14', 'decision': 'hide behavior-bearing checker'}]}
    return {'schema': 'r2t.target-body-map/v1', 'project': project,
            'runtime_seed_digest': 'a' * 64, 'source_files_digest': seed.files_digest,
            'subject_paths': ['src/Api.php'], 'items': [item], 'all_file_rules': [],
            'contracts': [{'path': 'TARGET_CONTRACTS.md', 'content': 'Use Validator::valid($value).',
                           'sources': ['src/Api.php public declaration']}]}


def v2_fixture_map(doc):
    """The same map under `r2t.target-body-map/v2`: only the annotation moves.

    Every other key -- subjects, bodies, principals, delegation, judgments,
    contracts -- is the v1 map's own value, which is what makes the identity
    comparison below a statement about the annotation alone.
    """
    checked = {'checked': [{'key': ['api.Validator', 'valid'],
                            'declaration': 'def valid(self, value):'}],
               'empty_reason': None}
    items = [{**{k: v for k, v in item.items() if k != 'target_interfaces'},
              'checked_interfaces': checked} for item in doc['items']]
    return {**doc, 'schema': 'r2t.target-body-map/v2', 'items': items}


def zero_body_fixture_map(root):
    """Synthetic source with the three approved IDs; not project admission."""
    doc = fixture_map(root, project='coreshop')
    original = doc['items'][0]
    cases = (
        ('coreshop/features/domain/category/create_category.feature:13',
         'Pimcore.GeneratedProduct::getCategories', 'Generated relation access has no eligible first-party body.'),
        ('coreshop/features/domain/category/create_category.feature:19',
         'Pimcore.AbstractObject::getParent', 'Inherited framework hierarchy has no eligible first-party body.'),
        ('coreshop/features/domain/product/adding_product_category.feature:6',
         'Pimcore.GeneratedProduct::setCategories', 'Generated membership has no eligible first-party caller.'),
    )
    doc['items'] = []
    for item_id, principal, reason in cases:
        generated = [] if item_id.endswith(':19') else [{
            'operation': principal, 'realizes_target_behavior': True,
            'treatment': 'Retain the generated declaration outside this source projection.',
            'reason': 'The generated relation realizes this fixture criterion.'}]
        doc['items'].append({**original, 'item_id': item_id, 'principals': [principal],
            'bodies': [], 'omitted_paths': [], 'generated_operation_judgments': generated,
            'delegation': [{'from': item_id, 'to': principal,
                            'evidence': 'Synthetic excluded framework declaration.', 'decision': reason}],
            'zero_body_treatment': {'decision': 'unchanged_target_hidden', 'reason': reason}})
    return doc, original


class ParserViewTests(unittest.TestCase):
    def transform(self, path, raw, names=None):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / 'source'
            (root / path).parent.mkdir(parents=True)
            (root / path).write_bytes(raw)
            seed = qualify_source_seed(root=str(root), project='fixture', runtime_seed_digest='a' * 64)
            edits = source_bodies(path, raw)
            if names is not None:
                edits = tuple(e for e in edits if e.body.declaration_id in names)
                self.assertEqual(len(edits), len(names))
            mapping = TargetMap('fixture', seed.files_digest, 'b' * 64, 'c' * 64,
                                (ItemSelection('item', ('API',), Selection(edits)),))
            policy = ViewPolicy('fixture', 'target_hidden', 'd' * 64, 'e' * 64,
                                'f' * 64, (path,), 'parser-test')
            plan = plan_agent_view(source_seed=seed, item_id='item', policy=policy, target_map=mapping)
            out = Path(scratch) / 'view'
            build_agent_view(plan, destination=str(out))
            result = (out / path).read_bytes()
            parse_source(path, result)
            self.assertEqual((root / path).read_bytes(), raw)
            return result

    def test_python_multiline_properties_and_nonascii(self):
        raw = b'''# coding: utf-8
from typing import Optional
DEFAULT = 3
class API:
    @property
    def value(self) -> Optional[int]:
        """Public documentation remains."""
        # hidden local comment
        return self._secret
    @value.setter
    def value(self, x: int = DEFAULT): self._secret = x  # secret setter
    async def invoke(
        self,
        arg: dict[str, int] = {"x": 1},
    ) -> int:
        """A multiline
        documented contract.
        """
        local = "\xc3\xa9"
        def helper(): return local
        return helper()
    def surrounding(self): return "keep these bytes"
'''
        names = {'api.API.value', 'api.API.value.setter', 'api.API.invoke'}
        result = self.transform('src/api.py', raw, names)
        for absent in (b'_secret', b'secret setter', b'local =', b'def helper', b'hidden local comment'):
            self.assertNotIn(absent, result)
        for kept in (b'@value.setter', b'Public documentation remains', b'arg: dict[str, int] = {"x": 1}',
                     b'documented contract.', b'def surrounding(self): return "keep these bytes"'):
            self.assertIn(kept, result)

    def test_python_suite_forms_and_dynamic_contracts(self):
        raw = b'''from elsewhere import Document
ALIAS = 1
class XML:
    add_r: "Callable[[], Run]"
    r = ZeroOrMore("w:r")
    def plain(self): "contract"; return "secret"
    def outer(self):
        def nested(): return "secret"
        return nested()
callback = lambda x: x * 123
'''
        result = self.transform('src/api.py', raw)
        self.assertNotIn(b'secret', result)
        self.assertNotIn(b'x * 123', result)
        for kept in (b'from elsewhere import Document', b'ALIAS = 1', b'add_r: "Callable[[], Run]"',
                     b'r = ZeroOrMore("w:r")', b'"contract"'):
            self.assertIn(kept, result)

    def test_python_form_feed_inside_a_string_is_not_a_line_break(self):
        """`str.splitlines` breaks where `ast` and `tokenize` do not."""
        raw = ('HEADER = """page one\fpage two"""\n'
               'class API:\n'
               '    def target(self):\n'
               '        return "hidden"\n'
               'TRAILER = "keep"\n').encode()
        result = self.transform('src/api.py', raw, {'api.API.target'})
        self.assertNotIn(b'return "hidden"', result)
        self.assertTrue(result.startswith(raw[:raw.index(b'\n        return')]), result)
        self.assertTrue(result.endswith(b'\nTRAILER = "keep"\n'), result)

    def test_php_realistic_structure(self):
        raw = b'''<?php
namespace Example;
interface Contract { public function valid(array $configuration): bool; }
trait Helpers { protected function check($x) { return $x > 8; } }
final class Checker implements Contract {
    use Helpers { check as private originalCheck; }
    public const DEFAULT_ID = 'quantity';
    /** Public documented semantics. */
    public function __construct(private readonly int $value = 2) {}
    #[Marker('}')]
    public function valid(array $configuration): bool {
        // hidden branch implementation
        $text = <<<LABEL
not a closing brace }
LABEL;
        return $this->originalCheck($configuration['minQuantity']);
    }
    public function surrounding() { return 'unchanged'; }
}
namespace Other { function helper($x = ['}']) { return $x; } }
'''
        names = {'Example\\Checker::valid', 'Example\\Checker::__construct', 'Example\\Helpers::check'}
        result = self.transform('src/Example.php', raw, names)
        self.assertNotIn(b'hidden branch', result)
        self.assertNotIn(b'$x > 8', result)
        self.assertNotIn(b'<<<LABEL', result)
        for kept in (b'private readonly int $value = 2', b"public const DEFAULT_ID = 'quantity'",
                     b'/** Public documented semantics. */', b"#[Marker('}')]"):
            self.assertIn(kept, result)
        self.assertIn(b"public function surrounding() { return 'unchanged'; }", result)
        self.assertIn(b"function helper($x = ['}']) { return $x; }", result)

    def test_malformed_sources_refuse(self):
        for path, raw in [('a.py', b'def broken('), ('a.php', b'<?php function broken( {')]:
            with self.assertRaises(ViewRefused):
                source_bodies(path, raw)
        with self.assertRaises(ViewRefused):
            source_bodies('a.java', b'class A {}')

    def test_php_implicit_public_readonly_promotion(self):
        raw = b'''<?php
class Repository {
    public function __construct(private readonly Manager $manager, readonly Metadata $class) {
        parent::__construct($manager, $class);
    }
}
'''
        result = self.transform('Repository.php', raw)
        self.assertIn(b'readonly Metadata $class', result)
        self.assertNotIn(b'parent::__construct', result)
        with self.assertRaises(ViewRefused):
            source_bodies('bad.php', b'<?php function bad(readonly Metadata $class) {}')

    def test_python_overloads_are_preserved_declarations(self):
        raw = b'''from typing import overload
class Rows:
    @overload
    def __getitem__(self, index: int) -> "Row": ...
    @overload
    def __getitem__(self, index: slice) -> list["Row"]: ...
    def __getitem__(self, index):
        return list(self._rows)[index]
'''
        edits = source_bodies('src/api.py', raw)
        self.assertEqual(len(edits), 1)
        result = self.transform('src/api.py', raw, {'api.Rows.__getitem__'})
        self.assertEqual(result.count(b'@overload'), 2)
        self.assertIn(b'index: slice) -> list["Row"]: ...', result)
        self.assertNotIn(b'list(self._rows)[index]', result)

    def test_outdented_following_documentation_is_not_a_body(self):
        raw = b'''class Prior:
    def target(self):
        return "hidden"
        # local implementation comment

# Public contract of Following, not an implementation comment.
class Following:
    def __str__(self): return "documented value"
'''
        result = self.transform('src/api.py', raw, {'api.Prior.target'})
        self.assertNotIn(b'local implementation', result)
        self.assertIn(raw[raw.index(b'# Public contract'):], result)

    def test_map_preparation_preserves_per_item_judgments(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / 'source'
            root.mkdir()
            doc = fixture_map(root)
            judgment = {'operation': 'api.Validator.generated', 'realizes_target_behavior': True,
                        'treatment': 'Hide the caller; retain the declaration.',
                        'reason': 'The generated operation realizes this requirement.'}
            doc['items'] = [{**doc['items'][0], 'generated_operation_judgments': [judgment]},
                            {**doc['items'][0], 'item_id': 'fixture/example.feature:2'}]
            mapping = Path(scratch) / 'map.json'
            mapping.write_text(json.dumps(doc))
            options = dict(source_root=str(root), readable_paths=('src',), project='python-docx',
                           runtime_seed_digest='a' * 64, map_path=str(mapping),
                           profile_digest='d' * 64, protocol_digest='e' * 64, boundary_digest='f' * 64)
            for scope in ('full', 'target_hidden'):
                prepared = prepare_view(scope=scope, **options)
                manifests = []
                for index, task in enumerate(doc['items']):
                    expected = task['generated_operation_judgments']
                    resolved = prepared.mapping.items[index]
                    self.assertEqual([asdict(j) for j in resolved.generated_operation_judgments], expected)
                    manifest = prepared.materialize(task, str(Path(scratch) / f'{scope}-{index}'))
                    self.assertEqual(manifest['generated_operation_judgments'], expected)
                    self.assertIsNone(manifest['zero_body_treatment'])
                    manifests.append(manifest)
                self.assertEqual(manifests[0]['files_digest'], manifests[1]['files_digest'])
                self.assertNotEqual(manifests[0]['digest'], manifests[1]['digest'])
            del doc['items'][1]['generated_operation_judgments']
            mapping.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ViewRefused, 'target body map item: expected exactly'):
                prepare_view(scope='full', **options)

    def test_three_zero_body_items_keep_full_target_bytes_and_all_hidden_removal(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / 'source'
            root.mkdir()
            doc, _ = zero_body_fixture_map(root)
            original = (root / 'src/api.py').read_bytes()
            mapping = Path(scratch) / 'map.json'
            mapping.write_text(json.dumps(doc))
            identities, files_by_scope = [], {}
            for scope in ('full', 'target_hidden', 'all_hidden'):
                # CoreShop's reviewed repairs add omitted YAML files, which this
                # synthetic source lacks; the claim here is about the map alone.
                with repair_data(scratch, {}):
                    prepared = prepare_view(source_root=str(root), readable_paths=('src',),
                        project='coreshop', runtime_seed_digest='a' * 64, map_path=str(mapping),
                        scope=scope, profile_digest='d' * 64, protocol_digest='e' * 64,
                        boundary_digest='f' * 64)
                manifests = []
                for index, item in enumerate(doc['items']):
                    treatment = item['zero_body_treatment']
                    self.assertEqual(asdict(prepared.mapping.items[index].zero_body_treatment), treatment)
                    self.assertEqual(asdict(prepared.plan(item).zero_body_treatment), treatment)
                    out = Path(scratch) / f'{scope}-{index}'
                    manifest = prepared.materialize(item, str(out))
                    self.assertEqual(manifest['zero_body_treatment'], treatment)
                    self.assertEqual(manifest['generated_operation_judgments'],
                                     item['generated_operation_judgments'])
                    actual = (out / 'src/api.py').read_bytes()
                    self.assertEqual(b'return value > 0' in actual, scope != 'all_hidden')
                    self.assertEqual(b'return 7' in actual, scope != 'all_hidden')
                    self.assertEqual(bool(manifest['hidden_bodies']), scope == 'all_hidden')
                    if scope != 'all_hidden':
                        self.assertEqual(actual, original)
                    self.assertEqual(set(p.relative_to(out).as_posix() for p in out.rglob('*')
                                         if p.is_file()), {'src/api.py', 'TARGET_CONTRACTS.md'})
                    for record in manifest['files']:
                        self.assertNotIn(treatment['reason'].encode(), (out / record['path']).read_bytes())
                    manifests.append(manifest)
                self.assertEqual(len({m['files_digest'] for m in manifests}), 1)
                self.assertEqual(len({m['digest'] for m in manifests}), 3)
                files_by_scope[scope] = manifests[0]['files_digest']
                identities.append((manifests[0]['map_digest'], manifests[0]['population_digest'],
                                   manifests[0]['interfaces_digest']))
            self.assertEqual(files_by_scope['full'], files_by_scope['target_hidden'])
            self.assertNotEqual(files_by_scope['target_hidden'], files_by_scope['all_hidden'])
            self.assertEqual(len(set(identities)), 1)
            self.assertEqual((root / 'src/api.py').read_bytes(), original)

    def test_zero_body_record_never_admits_other_or_unresolved_localization(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / 'source'
            root.mkdir()
            base, original = zero_body_fixture_map(root)
            mapping = Path(scratch) / 'map.json'
            record = base['items'][0]['zero_body_treatment']
            cases = (
                ('missing record', lambda d: d['items'][0].pop('zero_body_treatment')),
                ('null record', lambda d: d['items'][0].update(zero_body_treatment=None)),
                ('empty record', lambda d: d['items'][0].update(zero_body_treatment={})),
                ('wrong decision', lambda d: d['items'][0].update(
                    zero_body_treatment={**record, 'decision': 'allow_empty'})),
                ('empty reason', lambda d: d['items'][0].update(
                    zero_body_treatment={**record, 'reason': ''})),
                ('extra field', lambda d: d['items'][0].update(
                    zero_body_treatment={**record, 'approved': True})),
                ('foreign item', lambda d: d['items'][0].update(
                    item_id='coreshop/features/domain/category/create_category.feature:20')),
                ('foreign project', lambda d: d.update(project='python-docx')),
                ('nonempty bodies', lambda d: d['items'][0].update(bodies=original['bodies'])),
                ('nonempty omissions', lambda d: d['items'][0].update(omitted_paths=['src/api.py'])),
                ('unresolved principal', lambda d: d['items'][0].update(principals=[])),
                ('missing delegation', lambda d: d['items'][0].update(delegation=[])),
                ('unresolved delegation', lambda d: d['items'][0]['delegation'][0].update(decision='')),
            )
            for label, change in cases:
                doc = deepcopy(base)
                change(doc)
                mapping.write_text(json.dumps(doc))
                for scope in ('full', 'target_hidden', 'all_hidden'):
                    with self.subTest(case=label, scope=scope), self.assertRaises(ViewRefused):
                        prepare_view(source_root=str(root), readable_paths=('src',),
                            project=doc['project'], runtime_seed_digest='a' * 64, map_path=str(mapping),
                            scope=scope, profile_digest='d' * 64, protocol_digest='e' * 64,
                            boundary_digest='f' * 64)

    def test_named_map_resolves_delegation_and_task_binding(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / 'source'
            root.mkdir()
            doc = fixture_map(root)
            mapping = Path(scratch) / 'map.json'
            mapping.write_text(json.dumps(doc))
            options = dict(source_root=str(root), readable_paths=('src',), project='python-docx',
                           runtime_seed_digest='a' * 64, map_path=str(mapping),
                           scope='target_hidden', profile_digest='d' * 64,
                           protocol_digest='e' * 64, boundary_digest='f' * 64)
            prepared = prepare_view(**options)
            task = doc['items'][0]
            out = Path(scratch) / 'view'
            manifest = prepared.materialize(task, str(out))
            self.assertEqual(len(manifest['hidden_bodies']), 2)
            self.assertNotIn(b'return value > 0', (out / 'src/api.py').read_bytes())
            self.assertIn(b'return 7', (out / 'src/api.py').read_bytes())
            with self.assertRaisesRegex(ViewRefused, 'interfaces differ'):
                prepared.plan({**task, 'target_interfaces': {'behaviour': [], 'setup': []}})
            # The population and interface identities are computed here, so a
            # map that still states one is carrying an unexpected field.
            mapping.write_text(json.dumps({**doc, 'population_digest': 'a' * 64}))
            with self.assertRaisesRegex(ViewRefused, 'target body map: expected exactly'):
                prepare_view(**options)
            doc['items'][0]['bodies'][0]['declaration_id'] = 'missing'
            mapping.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ViewRefused, 'unique concrete body'):
                prepare_view(**options)

    def test_v2_map_annotation_is_a_second_schema_not_a_second_shape(self):
        """A v2 map admits `checked_interfaces` rows under its own digest domain.

        The two schemas share one loader, so the risk is that they share a
        field: a map that accepted either annotation, or a digest that did not
        move with the annotation, would let a v2 row be admitted against a v1
        identity.  Every case below is that confusion refused.
        """
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / 'source'
            root.mkdir()
            v1 = fixture_map(root)
            v2 = v2_fixture_map(v1)
            v1_annotation = v1['items'][0]['target_interfaces']
            v2_annotation = v2['items'][0]['checked_interfaces']
            mapping = Path(scratch) / 'map.json'
            options = dict(source_root=str(root), readable_paths=('src',), project='python-docx',
                           runtime_seed_digest='a' * 64, map_path=str(mapping),
                           scope='target_hidden', profile_digest='d' * 64,
                           protocol_digest='e' * 64, boundary_digest='f' * 64)
            manifests = {}
            for name, doc, field, drift in (
                    ('v1', v1, 'target_interfaces', {'behaviour': [], 'setup': []}),
                    ('v2', v2, 'checked_interfaces',
                     {'checked': [], 'empty_reason': 'no_action_or_check_call'})):
                mapping.write_text(json.dumps(doc))
                prepared = prepare_view(**options)
                self.assertEqual(prepared.annotation_field, field)
                task = doc['items'][0]
                manifests[name] = prepared.materialize(task, str(Path(scratch) / name))
                # A row whose own field drifted from the map is refused, and so
                # is one carrying the OTHER schema's field and nothing else.
                for bad in ({**task, field: drift},
                            {'item_id': task['item_id'],
                             'target_interfaces' if name == 'v2' else 'checked_interfaces':
                                 v1_annotation if name == 'v2' else v2_annotation}):
                    with self.assertRaisesRegex(ViewRefused, 'interfaces differ'):
                        prepared.plan(bad)
            # The annotation is the ONLY thing that moved: the hidden bodies,
            # the omissions and the view bytes are the same artifact.
            for key in ('hidden_bodies', 'omitted_paths', 'files', 'files_digest'):
                self.assertEqual(manifests['v1'][key], manifests['v2'][key])
            for key in ('interfaces_digest', 'map_digest', 'digest'):
                self.assertNotEqual(manifests['v1'][key], manifests['v2'][key])

            def item(doc, **changes):
                return {**doc, 'items': [{**doc['items'][0], **changes}]}

            for label, doc in (
                    ('the v1 annotation under the v2 schema',
                     item(v2, checked_interfaces=v1_annotation)),
                    ('the v1 KEY under the v2 schema',
                     {**v2, 'items': [{**{k: v for k, v in v2['items'][0].items()
                                          if k != 'checked_interfaces'},
                                       'target_interfaces': v1_annotation}]}),
                    ('the v2 annotation under the v1 schema',
                     item(v1, target_interfaces=v2_annotation)),
                    ('the v2 KEY under the v1 schema',
                     {**v1, 'items': [{**{k: v for k, v in v1['items'][0].items()
                                          if k != 'target_interfaces'},
                                       'checked_interfaces': v2_annotation}]}),
                    ('an unknown map schema', {**v1, 'schema': 'r2t.target-body-map/v3'}),
                    # The prompt renderer's own rules, reached through the map:
                    # a `ProfileError` exits a process, so these also prove the
                    # loader turns one into a view refusal.
                    ('an unsorted v2 list', item(v2, checked_interfaces={
                        'checked': [{'key': ['api.Validator', 'valid'], 'declaration': 'd'},
                                    {'key': ['api.Validator', 'setup'], 'declaration': 'd'}],
                        'empty_reason': None})),
                    ('an empty v2 list with no reason',
                     item(v2, checked_interfaces={'checked': [], 'empty_reason': None})),
                    ('an unknown v2 empty reason', item(v2, checked_interfaces={
                        'checked': [], 'empty_reason': 'looked_empty_to_me'}))):
                mapping.write_text(json.dumps(doc))
                with self.subTest(case=label), self.assertRaises(ViewRefused):
                    prepare_view(**options)

    def test_php_project_admission_resolves_bodies_in_every_scope(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / 'source'
            root.mkdir()
            doc = php_fixture_map(root)
            mapping = Path(scratch) / 'map.json'
            mapping.write_text(json.dumps(doc))
            options = dict(source_root=str(root), readable_paths=('src',), project='sylius',
                           runtime_seed_digest='a' * 64, map_path=str(mapping),
                           profile_digest='d' * 64, protocol_digest='e' * 64,
                           boundary_digest='f' * 64)
            for scope in ('full', 'target_hidden', 'all_hidden'):
                prepared = prepare_view(scope=scope, **options)
                out = Path(scratch) / scope
                prepared.materialize(doc['items'][0], str(out))
                actual = (out / 'src/Api.php').read_bytes()
                # The delegated checker is a target body; `setup` is not, so
                # only the all-production walk reaches it.
                self.assertEqual(b'return $value > 0' in actual, scope == 'full')
                self.assertEqual(b'return 7' in actual, scope != 'all_hidden')
                self.assertIn(b'Whether the documented value is valid.', actual)
            with self.assertRaisesRegex(ViewRefused, 'admission is not implemented'):
                prepare_view(**{**options, 'project': 'not-a-project', 'scope': 'full'})


class RepairSetTests(unittest.TestCase):
    """The reviewed repair sets in the TH plan (BENCHMARK_V2_SPEC sections 3.2-3.3)."""

    def test_project_repair_sets_are_the_pinned_reviewed_data(self):
        """Section 3.1's table, read through the pins: a data change without a
        reviewed pin change (and a new transformer) fails here."""
        expected = {
            'algorand-sdk': (70, 49, 0, {'ctor_super': 53, 'null_primitive': 9, 'blank_final': 8}),
            'coddy-agent': (247, 135, 21, {'go-blank-unused-import': 226,
                                           'go-omitted-file-stub': 19, 'embed-placeholder': 2}),
            'e-petitions': (1, 1, 0, {'ruby_load_time_body_empty': 1}),
            'coreshop': (14, 14, 14, {'yaml-omitted-config-empty-document': 14}),
        }
        self.assertEqual(set(source_views.REPAIR_INDEX_SHA256), set(expected))
        for project in ('algorand-sdk', 'coddy-agent', 'coreshop', 'e-petitions', 'kapua',
                        'prestashop', 'python-docx', 'sylius'):
            digest, entries = source_views.load_repairs(project)
            with self.subTest(project=project):
                if project not in expected:
                    self.assertEqual((digest, entries), (None, ()))
                    continue
                self.assertEqual(digest, source_views.REPAIR_INDEX_SHA256[project])
                self.assertEqual((len(entries), len({e.path for e in entries}),
                                  sum(e.th_sha256 is None for e in entries),
                                  dict(Counter(e.rule.split(':')[0] for e in entries))),
                                 expected[project])
        self.assertEqual(sum(len(source_views.load_repairs(p)[1]) for p in expected), 332)
        self.assertEqual(source_views.TRANSFORMER, 'r2t.target-source-view/v2')

    def test_repair_set_refusals(self):
        with tempfile.TemporaryDirectory() as scratch:
            entry = ('src/api.py', b'view\n', b'repaired\n', 'fixture')
            pin = write_repair_set(scratch, 'python-docx', [entry])
            directory = Path(scratch) / 'python-docx' / source_views.REPAIRS_DIR
            with repair_data(scratch, {'python-docx': pin}):
                self.assertEqual(len(source_views.load_repairs('python-docx')[1]), 1)
            for label, pins, error in (
                    ('an index with another sha256', {'python-docx': '0' * 64}, 'not the pinned'),
                    ('an index with no pin', {}, 'no pinned sha256'),
                    ('a pinned set that is missing', {'python-docx': pin, 'sylius': pin},
                     'pinned repair index unreadable')):
                project = 'sylius' if 'missing' in label else 'python-docx'
                with self.subTest(case=label), repair_data(scratch, pins), \
                        self.assertRaisesRegex(ViewRefused, error):
                    source_views.load_repairs(project)
            blob = next((directory / 'blobs').iterdir())
            blob.write_bytes(b'other bytes\n')
            with repair_data(scratch, {'python-docx': pin}), \
                    self.assertRaisesRegex(ViewRefused, 'holds other bytes'):
                source_views.load_repairs('python-docx')
            blob.unlink()
            with repair_data(scratch, {'python-docx': pin}), \
                    self.assertRaisesRegex(ViewRefused, 'unreadable'):
                source_views.load_repairs('python-docx')
        with tempfile.TemporaryDirectory() as scratch:
            pin = write_repair_set(scratch, 'python-docx', [entry, entry[:3] + ('again',)])
            with repair_data(scratch, {'python-docx': pin}), \
                    self.assertRaisesRegex(ViewRefused, 'two repairs for one view file'):
                source_views.load_repairs('python-docx')

    def test_target_hidden_views_carry_the_repairs(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / 'source'
            root.mkdir()
            doc = fixture_map(root)
            (root / 'src/data.json').write_text('{"secret": 1}\n')
            doc.update(subject_paths=['src/api.py', 'src/data.json'],
                       source_files_digest=qualify_source_seed(
                           root=str(root), project='python-docx', runtime_seed_digest='a' * 64,
                           readable_paths=('src',)).files_digest)
            doc['items'][0]['omitted_paths'] = ['src/data.json']
            doc['all_file_rules'] = [{'path': 'src/data.json',
                                      'contract_paths': ['TARGET_CONTRACTS.md']}]
            mapping = Path(scratch) / 'map.json'
            mapping.write_text(json.dumps(doc))
            options = dict(source_root=str(root), readable_paths=('src',), project='python-docx',
                           runtime_seed_digest='a' * 64, map_path=str(mapping),
                           profile_digest='d' * 64, protocol_digest='e' * 64, boundary_digest='f' * 64)
            task = doc['items'][0]
            data = Path(scratch) / 'data'
            with repair_data(data, {}):
                unrepaired = prepare_view(scope='target_hidden', **options).materialize(
                    task, str(Path(scratch) / 'unrepaired'))
            th = (Path(scratch) / 'unrepaired/src/api.py').read_bytes()
            repaired = th + b'REPAIRED = True\n'
            pin = write_repair_set(data, 'python-docx', [
                ('src/api.py', th, repaired, 'fixture-replace'),
                ('src/data.json', None, b'{}\n', 'fixture-add'),
                ('src/api.py', b'another instance\n', b'not this one\n', 'fixture-other')])
            with repair_data(data, {'python-docx': pin}):
                for scope in ('full', 'target_hidden', 'all_hidden'):
                    prepared = prepare_view(scope=scope, **options)
                    self.assertEqual((prepared.repair_index_sha256, len(prepared.repairs)), (pin, 3))
                    self.assertEqual(prepared.policy.transformer,
                                     'r2t.target-source-view/v2+r2t.all-production-source-view/v1')
                    out = Path(scratch) / scope
                    applied = []
                    manifest = prepared.materialize(task, str(out), applied=applied)
                    self.assertEqual([(e.path, e.rule) for e in applied],
                                     [('src/api.py', 'fixture-replace'), ('src/data.json', 'fixture-add')]
                                     if scope == 'target_hidden' else [])
                    self.assertEqual(b'REPAIRED' in (out / 'src/api.py').read_bytes(),
                                     scope == 'target_hidden')
                    if scope == 'target_hidden':
                        self.assertEqual((out / 'src/data.json').read_bytes(), b'{}\n')
                        self.assertEqual(manifest['omitted_paths'], ['src/data.json'])
                        self.assertIn('src/data.json', {f['path'] for f in manifest['files']})
                        self.assertNotEqual(manifest['files_digest'], unrepaired['files_digest'])
                        self.assertEqual(manifest['hidden_bodies'], unrepaired['hidden_bodies'])
                # A repaired file goes through the same parse check as a hidden one.
                broken = Path(scratch) / 'broken'
                pin = write_repair_set(broken, 'python-docx', [
                    ('src/api.py', th, b'def broken(\n', 'fixture-broken')])
            with repair_data(broken, {'python-docx': pin}), self.assertRaises(ViewRefused):
                prepare_view(scope='target_hidden', **options).materialize(
                    task, str(Path(scratch) / 'broken-view'))


def selftest():
    suite = unittest.TestSuite()
    for case in (ParserViewTests, RepairSetTests):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(selftest())
