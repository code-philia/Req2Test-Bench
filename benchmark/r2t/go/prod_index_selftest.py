"""Real Go compilation/type attribution; never run fixture initialization/tests."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from .prod_index import GoIndexRefused, build_context_index, build_prod_index


def suite(feature, package='internal/check', name='check', tags=(), glue='bdd_fixture_test.go'):
    return {'schema': 'r2t.go-suite-context/1', 'feature_path': 'features/'+feature+'.feature',
            'scenario_line': 3, 'glue_path': package+'/'+glue, 'package_dir': package,
            'package_name': name, 'test_name': 'TestFixture', 'suite_line': 4,
            'go_build_expression': '', 'go_build_tags': list(tags), 'godog_tags': '',
            'godog_tags_origin': {'kind': 'default', 'line': 4}}


def closure(context, files=None):
    return {'item_id': f"coddy-agent/{context['feature_path']}:{context['scenario_line']}",
            'feature_file': context['feature_path'], 'scenario_line': context['scenario_line'],
            'go_suite': context, 'files': list(files or [context['glue_path']])}


class GoProductionIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.go = shutil.which('go')
        if cls.go is None:
            raise RuntimeError('Go production-index fixtures require Go 1.25.0')
        cls.directory = tempfile.TemporaryDirectory(prefix='go-prod-index-fixtures-')
        cls.base = Path(cls.directory.name)
        cls.source = cls.base / 'source'; cls.source.mkdir()
        cls.scratch = str(cls.base / 'support')
        cls.originals = {
            'go.mod': b'module example.test/index\n\ngo 1.25.0\n',
            'internal/lib/api.go': (
                'package lib\r\nimport "os"\r\n//line fictional.go:900\r\n'
                '// API café\r\ntype hidden struct{}\r\n'
                'type Alias = hidden\r\ntype Box[T any] struct { Value T }\r\n'
                'type Embedded struct { hidden }\r\ntype API interface { Abstract() }\r\n'
                'func (hidden) Exported() int { return 7 }\r\n'
                'func (hidden) private() int { return 2 }\r\n'
                'func (Alias) AliasMethod() {}\r\n'
                'func (b *Box[T]) Get() T { return b.Value }\r\n'
                'func Factory() hidden { return hidden{} }\r\n'
                'func Generic[T any](v T) T { return v }\r\n'
                'var callback = func() int { return 99 }\r\n'
                'func init() { _ = os.WriteFile("INIT_EXECUTED", nil, 0600) }\r\n').encode(),
            'internal/lib/other.go': b'package lib\nfunc (b Box[T]) Other() T { return b.Value }\n',
            'internal/lib/mode.go': b'//go:build !http && !cli\n\npackage lib\nfunc DefaultOnly() {}\n',
            'internal/lib/mode_http.go': b'//go:build http\n\npackage lib\nfunc HTTPOnly() {}\n',
            'internal/lib/mode_cli.go': b'//go:build cli\n\npackage lib\nfunc CLIOnly() {}\n',
            'internal/lib/platform_windows.go': b'package lib\nfunc WindowsOnly() {}\n',
            'internal/check/bdd_fixture_test.go': b'''package check
import ("os"; "testing"; "example.test/index/internal/lib")
func TestFixture(t *testing.T) { _ = os.WriteFile("TEST_EXECUTED", nil, 0600); _ = lib.Factory().Exported(); _ = lib.Generic(3); _ = (lib.Embedded{}).Exported() }
''',
            'internal/lib/bdd_external_test.go': b'''package lib_test
import ("testing"; "example.test/index/internal/lib")
func TestFixture(t *testing.T) { _ = lib.Factory().Exported() }
''',
            'internal/lib/bdd_internal_test.go': b'''package lib
import "testing"
func TestInternal(t *testing.T) { _ = (hidden{}).private() }
''',
            'cmd/check/main.go': b'package main\nimport "example.test/index/internal/lib"\nfunc main() { _ = lib.Factory() }\n',
            'cmd/check/bdd_fixture_test.go': b'package main\nimport "testing"\nfunc TestFixture(t *testing.T) { main() }\n',
            'internal/check/bdd_other_test.go': b'package check\nimport (_ "example.test/index/internal/otheronly"; "testing")\nfunc TestOther(t *testing.T) {}\n',
            'internal/check/ordinary_test.go': b'package check\nimport _ "example.test/index/internal/retainedonly"\n',
            'internal/otheronly/api.go': b'package otheronly\nfunc OtherSuiteOnly() {}\n',
            'internal/retainedonly/api.go': b'package retainedonly\nfunc RetainedTestOnly() {}\n',
            'internal/unrelated/api.go': b'package unrelated\nfunc NotCompiled() {}\n',
        }
        for name, raw in cls.originals.items():
            path = cls.source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        cls.removable = ['internal/check/bdd_fixture_test.go', 'internal/check/bdd_other_test.go',
                         'internal/lib/bdd_external_test.go', 'internal/lib/bdd_internal_test.go',
                         'cmd/check/bdd_fixture_test.go']
        cls.contexts = [suite('default'), suite('http', tags=['http']), suite('cli', tags=['cli']),
                        suite('external', 'internal/lib', 'lib_test', glue='bdd_external_test.go'),
                        suite('main', 'cmd/check', 'main'),
                        suite('other', glue='bdd_other_test.go')]
        cls.index = build_prod_index(str(cls.source), go=cls.go, go_contexts=cls.contexts, go_closures=[closure(c) for c in cls.contexts],
                                    go_scratch=cls.scratch, removable_paths=cls.removable)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_union_retains_exact_context_membership(self):
        self.assertEqual(self.index['schema'], 'r2t.go_prod_index/1')
        self.assertEqual(self.index['counts']['contexts'], 6)
        memberships = {row['go_suite']['feature_path']: row for row in self.index['contexts']}
        for context in self.contexts:
            row = memberships[context['feature_path']]
            self.assertEqual(row['go_suite'], context)
            self.assertEqual(row['answer_files'], [context['glue_path']])
            expected = 'mode_http.go' if context['go_build_tags'] == ['http'] else (
                'mode_cli.go' if context['go_build_tags'] == ['cli'] else 'mode.go')
            expected_modes = set() if context['feature_path']=='features/other.feature' else {'internal/lib/'+expected}
            self.assertEqual({path for path in row['files'] if '/mode' in path}, expected_modes)
        for path in self.index['files']:
            self.assertFalse(path.endswith('_test.go'))
            self.assertNotIn('windows', path)
            self.assertNotIn('unrelated', path)
        self.assertIn('cmd/check/main.go', self.index['files'])
        self.assertNotIn('cmd/check/main.go', memberships['features/default.feature']['files'])

    def test_only_selected_removable_imports_but_ordinary_tests_remain(self):
        rows = {row['go_suite']['feature_path']: row['files'] for row in self.index['contexts']}
        self.assertNotIn('internal/otheronly/api.go', rows['features/default.feature'])
        self.assertIn('internal/otheronly/api.go', rows['features/other.feature'])
        self.assertIn('internal/retainedonly/api.go', rows['features/default.feature'])
        self.assertIn('internal/retainedonly/api.go', rows['features/other.feature'])
        self.assertEqual(self.index['root'], str(self.source))

    def test_equal_compiler_inputs_reuse_work_and_preserve_complete_artifact(self):
        from unittest.mock import patch
        from . import prod_index
        contexts = []
        for context in self.contexts:
            contexts.extend([context, {**context, 'scenario_line': 23,
                                       'godog_tags': '@another-scenario'}])
        calls = []
        run = prod_index._run
        def observe(argv, **kwargs):
            calls.append(argv)
            return run(argv, **kwargs)
        with patch.object(prod_index, '_run', side_effect=observe):
            got = build_prod_index(str(self.source), go=self.go, go_contexts=contexts,
                go_closures=[closure(c) for c in contexts], go_scratch=self.scratch,
                removable_paths=self.removable)
        # setUpClass resolves each distinct input once, exactly as the prior
        # implementation did. Add only the other item identities/membership
        # rows it would repeat; compare every byte-level artifact field.
        expected = deepcopy(self.index)
        by_feature = {row['go_suite']['feature_path']: row for row in expected['contexts']}
        expected['contexts'] = [{**deepcopy(by_feature[c['feature_path']]), 'go_suite': c}
                                for c in sorted(contexts, key=lambda c: (c['feature_path'], c['scenario_line']))]
        expected['counts']['contexts'] = len(contexts)
        self.assertEqual(got, expected)
        self.assertEqual(sum(len(a)>1 and a[1]=='list' for a in calls), len(self.contexts))
        self.assertEqual(sum(len(a)==1 for a in calls), len(self.contexts))
        self.assertEqual(got['counts']['contexts'], 12)

    def test_distinct_answers_and_glue_are_not_reused(self):
        from unittest.mock import patch
        from . import prod_index
        single, multi, other = suite('a-single'), suite('b-multi'), suite('c-other', glue='bdd_other_test.go')
        both = [single['glue_path'], other['glue_path']]
        calls = []
        run = prod_index._run
        def observe(argv, **kwargs):
            calls.append(argv)
            return run(argv, **kwargs)
        with patch.object(prod_index, '_run', side_effect=observe):
            got = build_prod_index(str(self.source), go=self.go,
                go_contexts=[single, multi, other],
                go_closures=[closure(single), closure(multi, both), closure(other, list(reversed(both)))],
                go_scratch=self.scratch, removable_paths=self.removable)
        self.assertEqual(sum(len(a)>1 and a[1]=='list' for a in calls), 3)
        self.assertEqual(sum(len(a)==1 for a in calls), 3)
        rows = got['contexts']
        self.assertNotIn('internal/otheronly/api.go', rows[0]['files'])
        self.assertIn('internal/otheronly/api.go', rows[1]['files'])
        self.assertEqual(rows[1]['files'], rows[2]['files'])
        self.assertEqual(rows[1]['answer_files'], rows[2]['answer_files'])

    def test_distinct_package_name_still_resolves_and_refuses(self):
        from unittest.mock import patch
        from . import prod_index
        good = suite('a-external', 'internal/lib', 'lib_test', glue='bdd_external_test.go')
        wrong = {**good, 'feature_path': 'features/b-wrong.feature', 'package_name': 'lib'}
        calls = []
        run = prod_index._run
        def observe(argv, **kwargs):
            calls.append(argv)
            return run(argv, **kwargs)
        with patch.object(prod_index, '_run', side_effect=observe):
            with self.assertRaisesRegex(GoIndexRefused, 'selected glue/package'):
                build_prod_index(str(self.source), go=self.go, go_contexts=[good, wrong],
                    go_closures=[closure(good), closure(wrong)],
                    go_scratch=self.scratch, removable_paths=self.removable)
        self.assertEqual(sum(len(a)>1 and a[1]=='list' for a in calls), 2)
        self.assertEqual(sum(len(a)==1 for a in calls), 2)

    def test_every_context_is_validated_before_reuse(self):
        from unittest.mock import patch
        from . import prod_index
        first = suite('a-first')
        second = {**first, 'scenario_line': 23}
        changed = {**second, 'godog_tags': '@different'}
        with patch.object(prod_index, '_run', side_effect=AssertionError('compile before context validation')):
            with self.assertRaisesRegex(GoIndexRefused, 'differs from its witnessed closure'):
                build_prod_index(str(self.source), go=self.go, go_contexts=[first, second],
                    go_closures=[closure(first), closure(changed)],
                    go_scratch=self.scratch, removable_paths=self.removable)

    def test_missing_or_inexact_removal_boundary_refuses(self):
        for paths in (None, [], ['internal/check/'], ['missing.go'],
                      self.removable + self.removable, ['internal/check/bdd_other_test.go']):
            with self.assertRaises(GoIndexRefused):
                build_context_index(str(self.source), go=self.go, go_context=suite('default'), go_closure=closure(suite('default')),
                                    go_scratch=self.scratch, removable_paths=paths)

    def test_retained_dependency_on_unselected_glue_refuses(self):
        with tempfile.TemporaryDirectory(dir=self.base) as directory:
            root = Path(directory)/'source'; shutil.copytree(self.source, root)
            (root/'internal/check/bdd_other_test.go').write_text('package check\ntype OtherHelper struct{}\n')
            (root/'internal/check/ordinary_test.go').write_text('package check\nvar retained = OtherHelper{}\n')
            with self.assertRaisesRegex(GoIndexRefused, 'undefined: OtherHelper'):
                build_context_index(str(root), go=self.go, go_context=suite('default'), go_closure=closure(suite('default')),
                                    go_scratch=self.scratch, removable_paths=self.removable)

    def test_witnessed_multifile_restores_helpers_and_only_their_imports(self):
        context = suite('multi')
        helper = 'internal/check/bdd_other_test.go'
        with tempfile.TemporaryDirectory(dir=self.base) as directory:
            root = Path(directory)/'source'; shutil.copytree(self.source, root)
            (root/helper).write_text('package check\nimport _ "example.test/index/internal/otheronly"\ntype OtherHelper struct{}\n')
            (root/'internal/check/ordinary_test.go').write_text(
                'package check\nimport _ "example.test/index/internal/retainedonly"\nvar retained = OtherHelper{}\n')
            before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with self.assertRaisesRegex(GoIndexRefused, 'undefined: OtherHelper'):
                build_context_index(str(root), go=self.go, go_context=context,
                    go_closure=closure(context), go_scratch=self.scratch, removable_paths=self.removable)
            index = build_context_index(str(root), go=self.go, go_context=context,
                go_closure=closure(context, [helper, context['glue_path']]),
                go_scratch=self.scratch, removable_paths=self.removable)
            self.assertEqual(index['contexts'][0]['answer_files'], sorted([helper, context['glue_path']]))
            self.assertIn('internal/otheronly/api.go', index['files'])
            self.assertIn('internal/retainedonly/api.go', index['files'])
            self.assertNotIn('internal/unrelated/api.go', index['files'])
            self.assertTrue(all(not p.endswith('_test.go') for p in index['files']))
            self.assertEqual(before, {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()})
            hidden = next(c for c in index['files']['internal/lib/api.go']['classes']
                          if c['name'].endswith('.hidden'))
            self.assertEqual(next(m for m in hidden['methods'] if m['name']=='Exported')['decl'], 10)

    def test_multifile_binding_changes_membership_for_same_suite(self):
        context = suite('multi')
        helper = 'internal/check/bdd_other_test.go'
        index = build_context_index(str(self.source), go=self.go, go_context=context,
            go_closure=closure(context, [context['glue_path'], helper]),
            go_scratch=self.scratch, removable_paths=self.removable)
        self.assertIn('internal/otheronly/api.go', index['files'])
        single = next(row for row in self.index['contexts'] if row['go_suite']['feature_path']=='features/default.feature')
        self.assertNotIn('internal/otheronly/api.go', single['files'])

    def test_missing_stale_or_foreign_witnessed_paths_refuse(self):
        context = suite('default')
        wrong = {**context, 'godog_tags': '@changed'}
        cases = [None, [], [closure(wrong)], [closure(context), closure(suite('extra'))],
                 [closure(context, [context['glue_path'], context['glue_path']])],
                 [closure(context, [context['glue_path'], 'internal/check/ordinary_test.go'])],
                 [closure(context, [context['glue_path'], 'internal/check/bdd_unapproved_test.go'])]]
        for records in cases:
            with self.subTest(records=records), self.assertRaises(GoIndexRefused):
                build_prod_index(str(self.source), go=self.go, go_contexts=[context],
                    go_closures=records, go_scratch=self.scratch, removable_paths=self.removable)

    def test_physical_identity_publicness_and_original_receiver(self):
        classes = {row['name']: row for row in self.index['files']['internal/lib/api.go']['classes']}
        hidden = classes['example.test/index/internal/lib.hidden']
        methods = {row['name']: row for row in hidden['methods']}
        self.assertTrue(methods['Exported']['public'])
        self.assertFalse(methods['private']['public'])
        self.assertEqual(methods['Exported']['decl'], 10)
        self.assertEqual((methods['Exported']['start'], methods['Exported']['end']), (10, 10))
        self.assertIn('AliasMethod', methods)
        self.assertEqual(classes['example.test/index/internal/lib.Embedded']['methods'], [])
        self.assertEqual(classes['example.test/index/internal/lib.API']['methods'], [])
        self.assertTrue(classes['example.test/index/internal/lib.Alias']['alias'])
        box = classes['example.test/index/internal/lib.Box']
        self.assertEqual([method['name'] for method in box['methods']], ['Get'])
        other = self.index['files']['internal/lib/other.go']['classes'][0]
        self.assertEqual(other['name'], 'example.test/index/internal/lib.Box')
        self.assertNotIn('decl', other)  # this file does not declare the type
        self.assertEqual(other['methods'][0]['decl'], 2)
        free = classes['example.test/index/internal/lib']
        self.assertEqual({method['name'] for method in free['methods']}, {'Factory', 'Generic'})
        self.assertNotIn('init', str(free))
        self.assertNotIn('callback', str(free))

    def test_no_source_initialization_or_tests_and_no_source_changes(self):
        self.assertFalse(list(self.source.rglob('*EXECUTED')))
        actual = {path.relative_to(self.source).as_posix(): path.read_bytes()
                  for path in self.source.rglob('*') if path.is_file()}
        self.assertEqual(actual, self.originals)
        self.assertEqual(self.index['runtime']['toolchain'], 'go1.25.0')
        self.assertEqual(self.index['runtime']['goos'], 'linux')

    def test_existing_method_loader_shape(self):
        from ..bench.metrics import load_prod_index
        path = self.base / 'index.json'; path.write_text(json.dumps(self.index))
        loaded = load_prod_index(str(path))
        methods = loaded['internal/lib/api.go']
        exported = next(method for method in methods if method.name == 'Exported')
        self.assertEqual(exported.key, ('example.test/index/internal/lib.hidden', 'Exported'))
        self.assertEqual(exported.decl, 10)
        self.assertTrue(exported.public)

    def test_missing_duplicate_and_mismatched_context_refuse(self):
        for contexts in ([], [None], [suite('same'), suite('same')]):
            with self.assertRaises(GoIndexRefused):
                build_prod_index(str(self.source), go=self.go, go_contexts=contexts, go_closures=[closure(suite("same"))], go_scratch=self.scratch, removable_paths=self.removable)
        wrong = suite('wrong', 'internal/lib', 'lib', glue='bdd_external_test.go')
        with self.assertRaisesRegex(GoIndexRefused, 'selected glue/package'):
            build_context_index(str(self.source), go=self.go, go_context=wrong, go_closure=closure(wrong), go_scratch=self.scratch, removable_paths=self.removable)
        with self.assertRaisesRegex(GoIndexRefused, 'absolute go'):
            build_context_index(str(self.source), go='go', go_context=suite('default'), go_closure=closure(suite('default')), go_scratch=self.scratch, removable_paths=self.removable)
        with self.assertRaisesRegex(GoIndexRefused, 'disjoint'):
            build_context_index(str(self.source), go=self.go, go_context=suite('default'), go_closure=closure(suite('default')), go_scratch=str(self.source/'support'), removable_paths=self.removable)

    def test_source_declaration_drift_between_contexts_refuses(self):
        from unittest.mock import patch
        from . import prod_index
        with tempfile.TemporaryDirectory(dir=self.base) as directory:
            root = Path(directory)/'source'; shutil.copytree(self.source, root)
            original_run = prod_index._run
            lists = 0

            def change_source_between_real_compilations(argv, **kwargs):
                nonlocal lists
                if len(argv) > 1 and argv[1] == 'list':
                    lists += 1
                    if lists == 2:
                        path = root/'internal/lib/other.go'
                        path.write_bytes(path.read_bytes() + b'func ChangedDeclaration() {}\n')
                return original_run(argv, **kwargs)

            with patch.object(prod_index, '_run', side_effect=change_source_between_real_compilations):
                with self.assertRaisesRegex(GoIndexRefused, 'compiled Go source differs from original'):
                    # Different build inputs still perform a second real
                    # compilation, where this fixture injects source drift.
                    build_prod_index(str(root), go=self.go, go_contexts=[suite('a'), suite('b', tags=['http'])],
                                     go_closures=[closure(suite('a')), closure(suite('b', tags=['http']))],
                                     go_scratch=self.scratch, removable_paths=self.removable)

    def test_unresolved_production_types_refuse_without_partial_index(self):
        with tempfile.TemporaryDirectory(dir=self.base) as directory:
            root = Path(directory)/'source'; shutil.copytree(self.source, root)
            (root/'internal/lib/invalid.go').write_text('package lib\nfunc Broken() missingType { return nil }\n')
            with self.assertRaisesRegex(GoIndexRefused, 'undefined: missingType'):
                build_context_index(str(root), go=self.go, go_context=suite('default'), go_closure=closure(suite('default')), go_scratch=self.scratch, removable_paths=self.removable)


def selftest():
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(GoProductionIndexTests))
    if not result.wasSuccessful():
        raise AssertionError('Go production-index selftest failed')


if __name__ == '__main__':
    selftest()
