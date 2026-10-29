"""Real Go parser and shared-builder checks, without subject execution."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from ..core.source_view import (
    ContractFile, ItemSelection, Selection, TargetMap, ViewPolicy, ViewRefused,
    build_agent_view, plan_agent_view, qualify_source_seed,
)
from ..toolkit.source_view_all import ProductionFileRule, resolve_all_bodies, select_all_production
from ..toolkit.source_views import parse_source, prepare_view, source_bodies
from .source_view import source_inventory


def context(tags=()):
    return {'schema': 'r2t.go-suite-context/1', 'feature_path': 'features/fixture.feature',
            'scenario_line': 3, 'glue_path': 'internal/example/bdd_fixture_test.go',
            'package_dir': 'internal/example', 'package_name': 'p', 'test_name': 'TestFixture',
            'suite_line': 4, 'go_build_expression': ' || '.join(tags),
            'go_build_tags': list(tags), 'godog_tags': '~@skip',
            'godog_tags_origin': {'kind': 'literal', 'line': 8}}


class GoSourceViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.go = shutil.which('go')
        if cls.go is None:
            raise RuntimeError('Go source-view fixtures require qualified Go 1.25.0')
        cls.support = tempfile.TemporaryDirectory(prefix='go-source-view-support-')
        cls.tools = {'go': cls.go, 'go_context': context(), 'go_scratch': cls.support.name}

    @classmethod
    def tearDownClass(cls):
        cls.support.cleanup()

    def transform(self, sources, *, names=None, all_hidden=False, rules=(), tools=None):
        tools = tools or self.tools
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            for path, raw in sources.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_bytes(raw)
            seed = qualify_source_seed(root=str(root), project='fixture', runtime_seed_digest='a'*64)
            contracts = (ContractFile('TARGET_CONTRACTS.md', b'Reviewed fixture contract.'),)
            policy = ViewPolicy('fixture', 'all_hidden' if all_hidden else 'target_hidden',
                                'b'*64, 'c'*64, 'd'*64, tuple(sources), 'go-fixture')
            if all_hidden:
                selected = select_all_production(source_seed=seed, policy=policy,
                    file_rules=rules, contracts=contracts, **tools)
            else:
                edits = tuple(edit for path, raw in sources.items()
                              for edit in source_bodies(path, raw, **tools)
                              if names is None or edit.body.declaration_id in names)
                selected = Selection(edits)
            mapping = TargetMap('fixture', seed.files_digest, 'e'*64, 'f'*64,
                (ItemSelection('item', ('p#API',), selected),), contracts,
                all_selection=selected if all_hidden else None)
            plan = plan_agent_view(source_seed=seed, item_id='item', policy=policy, target_map=mapping)
            destination = Path(directory) / 'view'
            manifest = build_agent_view(plan, destination=str(destination))
            output = {path.relative_to(destination).as_posix(): path.read_bytes()
                      for path in destination.rglob('*') if path.is_file()}
            for path in {edit.body.path for edit in plan.selection.bodies}:
                parse_source(path, output[path], **tools)
            for path, raw in sources.items():
                self.assertEqual((root / path).read_bytes(), raw)
            return output, manifest

    def test_physical_bytes_generics_receivers_and_nested_bodies(self):
        raw = ('//go:build !windows\r\n\r\npackage p\r\n'
               '//line pretend.go:900\r\n// Public café.\r\n'
               'type Store[T interface { ~int | ~int64 }] struct { Value T `json:"v"` }\r\n'
               'type Reader[T any] interface { Read(...T) (T, error) }\r\n'
               'func (s *Store[T]) Get(v ...T) (T, error) { /* 秘密 */ '
               'nested := func() T { return s.Value }; _ = `raw { }`; return nested(), nil }\r\n'
               'func (s Store[T]) Copy() T { return s.Value }\r\n'
               'func Parse[T any](v T) T { return v }\r\n'
               'func init() { hiddenInit() }\r\n').encode()
        inventory = source_inventory('internal/api.go', raw, **self.tools)
        self.assertFalse(inventory.contract_only_reasons)
        ids = {edit.body.declaration_id for edit in inventory.bodies}
        self.assertTrue({'p#(*Store[T]).Get', 'p#(Store[T]).Copy', 'p#Parse'} <= ids)
        self.assertIn('p#init@'+str(raw.index(b'func init')), ids)
        self.assertIn('p#func_literal@'+str(raw.index(b'func()')), ids)
        method = next(row for row in inventory.declarations if row['declaration_id'] == 'p#(*Store[T]).Get')
        self.assertEqual(method['declaration_line'], 8)
        output, manifest = self.transform({'internal/api.go': raw}, all_hidden=True)
        actual = output['internal/api.go']
        for secret in ('秘密'.encode(), b'nested :=', b'raw { }', b'return ', b'hiddenInit'):
            self.assertNotIn(secret, actual)
        expected = raw
        # Shared builder collapses the nested literal underneath its method.
        outer = [edit for edit in inventory.bodies if edit.body.kind != 'lambda']
        for edit in sorted(outer, key=lambda edit: edit.body.start_byte, reverse=True):
            expected = expected[:edit.body.start_byte] + edit.replacement + expected[edit.body.end_byte:]
        self.assertEqual(actual, expected)
        self.assertEqual(set(output), {'internal/api.go', 'TARGET_CONTRACTS.md'})
        self.assertEqual(len(manifest['hidden_bodies']), 4)

    def test_targeted_literal_and_untargeted_initializer(self):
        raw = b'package p\nvar computed = make([]int, 4)\nfunc API() int { f := func() int { return 987 }; return f() }\n'
        inventory = source_inventory('api.go', raw, **self.tools)
        self.assertEqual(inventory.contract_only_reasons[0]['reason'], 'computed_var_initializer')
        literal = next(edit for edit in inventory.bodies if edit.body.kind == 'lambda')
        output, _ = self.transform({'api.go': raw}, names={literal.body.declaration_id})
        self.assertEqual(output['api.go'], raw[:literal.body.start_byte] + literal.replacement + raw[literal.body.end_byte:])
        self.assertIn(b'make([]int, 4)', output['api.go'])
        with self.assertRaisesRegex(ViewRefused, 'computed_var_initializer'):
            resolve_all_bodies('api.go', raw, **self.tools)

    def test_closed_declaration_allowlist(self):
        raw = b'''package p
import alias "elsewhere"
type Alias = alias.Value
type Matrix [1+2]int
type API[T interface { ~int | ~int64 }] struct { Value T; Reader interface { Read() T }; F func(...T) (T,error); C <-chan T; M map[string][]*T }
const (A = iota; B; C = ^(A+1); D = !false)
var (a int; b, c = -2, alias.Value; d = (+3); callback = func(v int) int { return v+666 }; other = callback)
func APIValue[T any](v T) T { return v }
'''
        result = source_inventory('api.go', raw, **self.tools)
        self.assertEqual(result.contract_only_reasons, ())
        output, _ = self.transform({'api.go': raw}, all_hidden=True)
        self.assertIn(b'var (a int; b, c = -2, alias.Value;', output['api.go'])
        self.assertNotIn(b'666', output['api.go'])

    def test_refusals_report_physical_line_and_kind(self):
        cases = [(b'var x = make([]int, 2)', 'computed_var_initializer', '*ast.CallExpr'),
                 (b'var x = []string{"secret"}', 'compound_var_initializer', '*ast.CompositeLit'),
                 (b'var x = &y', 'computed_var_initializer', '*ast.UnaryExpr'),
                 (b'var x = xs[0]', 'computed_var_initializer', '*ast.IndexExpr'),
                 (b'var x = <-ch', 'computed_var_initializer', '*ast.UnaryExpr'),
                 (b'const x = int(4)', 'unsupported_const_expression', '*ast.CallExpr'),
                 (b'func external()', 'bodyless_function', '*ast.FuncDecl'),
                 (b'import "C"', 'cgo_import', '*ast.ImportSpec'),
                 (b'//go:embed hidden.md\nvar text string', 'unreviewed_go_directive', '*ast.Comment'),
                 (b'type T [call()]int', 'unsupported_type', '*ast.TypeSpec')]
        for declaration, reason, node in cases:
            with self.subTest(declaration=declaration):
                raw = b'package p\n//line false.go:777\n'+declaration+b'\n'
                issues = source_inventory('api.go', raw, **self.tools).contract_only_reasons
                self.assertEqual((issues[0]['path'], issues[0]['line'], issues[0]['reason'], issues[0]['node']),
                                 ('api.go', 3, reason, node))
                with self.assertRaisesRegex(ViewRefused, reason):
                    resolve_all_bodies('api.go', raw, **self.tools)

    def test_context_and_actual_bytes_never_share_path_resolution(self):
        path = 'internal/http.go'
        raw = b'//go:build http && !windows\n\npackage p\nfunc API() { secret() }\n'
        http = {**self.tools, 'go_context': context(['http'])}
        self.assertTrue(source_inventory(path, raw, **http).active)
        with self.assertRaisesRegex(ViewRefused, 'inactive'):
            source_bodies(path, raw, **self.tools)
        self.assertEqual(len(resolve_all_bodies(path, raw, **self.tools).bodies), 1)
        changed = raw.replace(b'API()', b'NewAPI()')
        self.assertEqual(source_bodies(path, changed, **http)[0].body.declaration_id, 'p#NewAPI')
        self.assertFalse(source_inventory('api_windows.go', b'package p\nfunc Win() {}', **http).active)
        self.assertEqual(len(resolve_all_bodies('api_windows.go', b'package p\nfunc Win() {}', **http).bodies), 1)
        self.assertTrue(source_inventory('api.go', b'// +build http\n\npackage p\n', **http).active)
        self.assertFalse(source_inventory('api.go', b'// +build http\n\npackage p\n', **self.tools).active)
        self.assertFalse(source_inventory('api.go', b'//go:build !http\n\npackage p\n', **http).active)

    def test_all_hidden_inactive_and_contract_only_resource(self):
        sources = {'api.go': b'package p\nfunc API() { activeSecret() }\n',
                   'api_windows.go': b'package p\nfunc Win() { windowsSecret() }\n',
                   'embedded.go': b'package p\n//go:embed hidden.md\nvar hidden string\n',
                   'hidden.md': b'SECRET PROMPT'}
        rules = tuple(ProductionFileRule(path, ('TARGET_CONTRACTS.md',)) for path in ('embedded.go', 'hidden.md'))
        output, _ = self.transform(sources, all_hidden=True, rules=rules)
        self.assertEqual(set(output), {'api.go', 'api_windows.go', 'TARGET_CONTRACTS.md'})
        self.assertNotIn(b'windowsSecret', output['api_windows.go'])
        with self.assertRaisesRegex(ViewRefused, 'Go resource needs'):
            resolve_all_bodies('hidden.md', sources['hidden.md'], **self.tools)
        with self.assertRaisesRegex(ViewRefused, 'contract supplement'):
            self.transform(sources, all_hidden=True, rules=(ProductionFileRule('embedded.go', ('missing.md',)),))

    def test_malformed_and_explicit_tool_context_requirements(self):
        for raw in (b'package p\nfunc broken( {', b'package p\nfunc API() {\xff}'):
            with self.assertRaises(ViewRefused):
                source_bodies('api.go', raw, **self.tools)
        with self.assertRaisesRegex(ViewRefused, r'api.go:3: parse_error'):
            parse_source('api.go', b'package p\n//line fake.go:700\nfunc broken( {', **self.tools)
        for change in ({'go': 'go'}, {'go_scratch': '/work/support'}, {'go_context': None},
                       {'go_context': {**context(), 'go_build_tags': ['ui']}}):
            with self.assertRaises(ViewRefused):
                source_bodies('api.go', b'package p\nfunc API() {}', **{**self.tools, **change})

    def test_prepare_and_materialize_bind_released_context_without_map_schema(self):
        # Synthetic v2 coddy fixture; real project maps still require qualification.
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'; source.mkdir()
            raw = b'package p\nfunc API() { secret() }\n'
            (source / 'api.go').write_bytes(raw)
            seed = qualify_source_seed(root=str(source), project='coddy-agent', runtime_seed_digest='a'*64)
            item = {'item_id': 'fixture:3', 'checked_interfaces': {'checked': [{'key': ['p', 'API'], 'declaration': 'func API()'}], 'empty_reason': None},
                    'principals': ['p#API'], 'bodies': [{'path': 'api.go', 'declaration_id': 'p#API', 'kind': 'function'}],
                    'omitted_paths': [], 'delegation': [], 'generated_operation_judgments': []}
            doc = {'schema': 'r2t.target-body-map/v2', 'project': 'coddy-agent', 'runtime_seed_digest': 'a'*64,
                   'source_files_digest': seed.files_digest, 'subject_paths': ['api.go'], 'items': [item],
                   'all_file_rules': [], 'contracts': [{'path': 'TARGET_CONTRACTS.md', 'content': 'API contract', 'sources': ['api.go']}]}
            map_path = Path(directory) / 'map.json'; map_path.write_text(json.dumps(doc))
            options = dict(source_root=str(source), readable_paths=('api.go',), project='coddy-agent',
                           runtime_seed_digest='a'*64, map_path=str(map_path), scope='all_hidden',
                           profile_digest='b'*64, protocol_digest='c'*64, boundary_digest='d'*64,
                           go=self.go, go_scratch=self.support.name, go_contexts={'fixture:3': context()})
            prepared = prepare_view(**options)
            task = {**item, 'go_suite': context()}
            prepared.materialize(task, str(Path(directory) / 'view'))
            self.assertEqual((Path(directory) / 'view/api.go').read_bytes(), b'package p\nfunc API() { panic("implementation hidden") }\n')
            for scope in ('full', 'target_hidden'):
                other = prepare_view(**{**options, 'scope': scope})
                output = Path(directory) / scope
                other.materialize(task, str(output))
                expected = raw if scope == 'full' else b'package p\nfunc API() { panic("implementation hidden") }\n'
                self.assertEqual((output / 'api.go').read_bytes(), expected)
            with self.assertRaisesRegex(ViewRefused, 'context differs'):
                prepared.plan({**task, 'go_suite': context(['http'])})
            with self.assertRaisesRegex(ViewRefused, 'closed go_suite'):
                prepared.plan(item)
            for contexts in ({}, {'wrong': context()}, {'fixture:3': context(), 'extra': context()}):
                with self.assertRaises(ViewRefused):
                    prepare_view(**{**options, 'go_contexts': contexts})
            with self.assertRaisesRegex(ViewRefused, 'disjoint'):
                prepare_view(**{**options, 'go_scratch': str(source / 'support')})


def selftest():
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(GoSourceViewTests))
    if not result.wasSuccessful():
        raise AssertionError('Go source-view selftest failed')


if __name__ == '__main__':
    selftest()
