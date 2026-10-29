"""Source-only Ruby production index, qualified against native TracePoint bindings."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from ..core.paths import BENCHMARK_ROOT
from .mutation_rb import DEFAULT_IMAGE, PARSER_VERSION

SOURCE = str(Path(BENCHMARK_ROOT) / 'r2t/ruby/prod_index.rb')
COLLECTOR = str(Path(BENCHMARK_ROOT) / 'r2t/ruby/direct_calls.rb')
#: The marker the collector above stamps on a recording made NOW, which is
#: what this module's selftest records.  It moved to `/2` when every event
#: gained the step that made it (TARGET_INTERFACES_V2_SPEC section 4);
#: `metrics.RUBY_DIRECT_CALLS_SCHEMA` stays `/1`, the shape of the rows
#: already collected, and `RUBY_DIRECT_CALLS_SCHEMAS` scores both.
COLLECTOR_SCHEMA = 'r2t.ruby_direct_calls/2'
PROD_PATHS = ('app', 'lib')


def build_prod_index(root, paths=None, *, image=DEFAULT_IMAGE, ruby=None):
    paths = list(paths or PROD_PATHS)
    if ruby:
        argv = [ruby, SOURCE, '--root', str(root)]
    else:
        from ..core.docker_cli import docker_argv
        argv = docker_argv(['run', '--rm', '--network', 'none', '--pull=never',
                           '--entrypoint', 'ruby', '-v', f'{os.path.abspath(root)}:/work:ro',
                           '-v', f'{SOURCE}:/r2t-prod-index.rb:ro', image,
                           '/r2t-prod-index.rb', '--root', '/work'])
    for path in paths:
        argv += ['--path', path]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
    try:
        doc = json.loads(result.stdout)
    except ValueError as exc:
        raise ValueError(f'Ruby index failed ({result.returncode}): {result.stderr[-2000:]}') from exc
    if result.returncode or doc.get('errors'):
        raise ValueError(f'Ruby index refused files: {doc.get("errors")!r}; {result.stderr[-1000:]}')
    if not ruby:
        if doc.get('parser') != PARSER_VERSION:
            raise ValueError('Ruby production index parser differs from the reviewed runtime')
        doc['image_id'] = image
    return doc


def selftest():
    from ..bench import harness, metrics
    from ..core.boundary import PRODUCTION, REMOVABLE, RETAINED
    ruby = os.environ.get('R2T_RUBY') or shutil.which('ruby')
    if not ruby:
        print('[FAIL] Ruby >=3.0 required (or R2T_RUBY)')
        return 1
    with tempfile.TemporaryDirectory(prefix='r2t-ruby-api-') as temp:
        root = Path(temp)
        for directory in ('app/models', 'app/views', 'lib', 'features/step_definitions', 'features/support'):
            (root / directory).mkdir(parents=True)
        production = '''module Included
  def supplied; :included; end
end
class Parent
  def self.to_s; raise 'subject owner display invoked'; end
  def self.singleton_class; raise 'subject singleton lookup invoked'; end
  def self.instance_method(*); raise 'subject method lookup invoked'; end
  attr_accessor :value, :other
  attr_reader(
    :reader
  )
  attr_writer :writer
  def initialize; @value = 1; end
  def foo; :foo; end
  private
  def hidden; :hidden; end
  public
  def indirect; foo; end
  def render_indirect(renderer); renderer.render; end
  def self.foo; :singleton; end
  class << self
    def scoped; :scoped; end
  end
end
class Child < Parent
  include Included
  alias private_alias foo
  private :private_alias
  alias_method :public_alias, :hidden
  public :public_alias
  alias_method :renamed_value, :value
  define_method(:empty) {}; define_method(:generated) { :generated }
  define_method(:multiline)
  do
    :multiline
  end
end
module Nested
  class Parent
    def original; :nested; end
  end
  class Child < Parent
    alias_method :inherited_alias, :original
  end
end
class VisibilityOrder
  def before; :before; end
  private :before
  alias_method :copied_private, :before
  public :before
  alias copied_public before
  private :before
end
def Parent.outside; :outside; end
FeedbackSignature = Struct.new(:value)
DynamicType = Object
'''
        # A newline before do is not Ruby's inline-block grammar; the block
        # opener may instead follow the closing parenthesis on a later line.
        production = production.replace('define_method(:multiline)\n  do', 'define_method(\n    :multiline\n  ) do')
        (root / 'app/models/fixture.rb').write_text(production)
        (root / 'features/support/helper.rb').write_text('def retained_call(obj); obj.foo; end\n')
        (root / 'lib/unsupported.rb').write_text("kind = :computed\nattr_reader kind\ndefine_method(kind) {}\nalias_method :changed, kind\ndefine_method(:external, &factory)\n")
        doc = build_prod_index(root, ruby=ruby)
        assert doc['files']['lib/unsupported.rb']['classes'] == []
        declarations = doc['files']['app/models/fixture.rb']['declarations']
        declared = [(row['name'], row['kind']) for row in declarations]
        assert ('Parent', 'class') in declared and ('Child', 'class') in declared
        assert ('Nested::Child', 'class') in declared
        assert ('FeedbackSignature', 'struct') in declared
        assert not any(name == 'DynamicType' for name, _kind in declared)
        assert {'dynamic_accessor', 'dynamic_define_method', 'dynamic_alias'} <= {row['reason'] for row in doc['unsupported']}

        index_path = root / 'index.json'
        index_path.write_text(json.dumps(doc))
        index = metrics.load_prod_index(str(index_path))
        script = '''require ENV.fetch('R2T_COLLECTOR')
require_relative '../../app/models/fixture'
require_relative '../support/helper'
obj = Child.new
R2T::DirectCalls.start
obj.value = 3
obj.value
obj.other = 4
obj.other
obj.reader
obj.writer = 5
obj.foo
obj.supplied
obj.send(:private_alias)
obj.public_alias
obj.renamed_value
obj.empty
obj.generated
obj.multiline
Parent.foo
Child.foo
Child.scoped
Parent.outside
Nested::Child.new.inherited_alias
ordered = VisibilityOrder.new
ordered.send(:copied_private)
ordered.copied_public
retained_call(obj)
obj.indirect
anonymous = Class.new
def anonymous.to_s; raise 'anonymous display invoked'; end
anonymous.class_eval("def render; :generated; end", File.join(ENV.fetch('BENCH_REPO_ROOT'), 'app/views/generated.erb'), 0)
anonymous.new.render
obj.render_indirect(anonymous.new)
first = R2T::DirectCalls.finish
R2T::DirectCalls.start
empty = R2T::DirectCalls.finish
puts JSON.generate(calls: first, empty: empty)
'''
        script_path = root / 'features/step_definitions/probe.rb'
        script_path.write_text("require 'json'\n" + script)
        env = dict(os.environ, BENCH_REPO_ROOT=str(root), R2T_COLLECTOR=COLLECTOR)
        cp = subprocess.run([ruby, str(script_path)], capture_output=True, text=True, env=env, timeout=60)
        if cp.returncode:
            raise AssertionError(cp.stderr)
        captured = json.loads(cp.stdout)
        # No Cucumber formatter here, so nothing set a step: the field is
        # present on every event and null, never absent.
        assert all('step' in event and event['step'] is None for event in captured['calls']), captured['calls'][:1]
        record = dict(direct_calls=captured['calls'], direct_calls_schema=COLLECTOR_SCHEMA)

        class Boundary:
            def classify(self, file):
                return PRODUCTION if file.startswith(('app/', 'lib/')) else (REMOVABLE if file.startswith('features/step_definitions/') else RETAINED)

        boundary = Boundary()
        assert metrics.direct_record_issue(record, index) is None
        methods, gaps = metrics.direct_methods(record, boundary, index)
        expected = {
            ('Parent', 'instance', name) for name in ('value', 'value=', 'other', 'other=', 'reader', 'writer=', 'foo', 'indirect', 'render_indirect')
        } | {('Included', 'instance', 'supplied'), ('Child', 'instance', 'public_alias'),
             ('Child', 'instance', 'renamed_value'), ('Child', 'instance', 'generated'),
             ('Child', 'instance', 'empty'), ('Child', 'instance', 'multiline'), ('Parent', 'singleton', 'foo'), ('Parent', 'singleton', 'scoped'),
             ('Parent', 'singleton', 'outside'), ('Nested::Child', 'instance', 'inherited_alias'),
             ('VisibilityOrder', 'instance', 'copied_public')}
        assert methods == expected, (methods ^ expected, doc['unsupported'], captured)
        assert gaps == 1, (gaps, doc, captured)
        assert captured['empty'] == []
        generated = [event for event in captured['calls'] if event['ruby_binding_issue'] == 'generated_method']
        assert all('#<Class:0x' in event['callee'] for event in generated)
        assert len(generated) == 2 and {event['caller_file'] for event in generated} == {'features/step_definitions/probe.rb', 'app/models/fixture.rb'}
        assert any(event['caller_file'] == 'features/support/helper.rb' for event in captured['calls'])
        assert any(event['caller_file'] == 'app/models/fixture.rb' for event in captured['calls'])
        assert any(event['ruby_binding_issue'] == 'generated_method' and event['callee_line'] == 0 for event in captured['calls'])
        assert ('Parent', 'instance', 'foo') in methods and ('Parent', 'singleton', 'foo') in methods
        for event in captured['calls']:
            binding = event['ruby_binding']
            if binding:
                key = tuple(binding[k] for k in ('declaring_file', 'declaring_line', 'owner', 'method_kind', 'method_name'))
                assert key in index.ruby_bindings, (key, doc['unsupported'])
        private_alias = [method for methods in index.values() for method in methods if method.name == 'private_alias']
        assert len(private_alias) == 1 and not private_alias[0].public
        print('[PASS] Native exact joins: same-line accessor operations, aliases/visibility, included/inherited and singleton owners, inline define_method')
        print('[PASS] Immediate source callers, generated direct diagnostic, per-window reset and no subject reflection overrides')
        for broken in (dict(record, direct_calls_schema=None), dict(record, direct_calls=[{}]),
                       dict(record, direct_calls=[dict(captured['calls'][0], ruby_binding_issue='bad')])):
            assert metrics.direct_record_issue(broken, index) == 'before_api_amendment_3'
        assert metrics.direct_methods(dict(record, direct_calls=[]), boundary, index) == (set(), 0)
        assert metrics.direct_methods(dict(record, direct_calls=None), boundary, index) is None
        rows = [dict(record, scenario_line=10), dict(record, scenario_line=11, direct_calls=[])]
        assert harness.fold_direct_calls_schema(rows, 9, [9, 10, 11]) == COLLECTOR_SCHEMA
        assert harness.fold_direct_calls_schema([rows[0], dict(rows[1], direct_calls_schema='r2t.python_direct_calls/2')], 9, [9, 10, 11]) is None
        assert len(harness.fold_direct_calls(rows, 9, [9, 10, 11])) == len(captured['calls'])
        result = harness.RunResult(exit_code=0, stdout='', wall_seconds=0, records=rows,
                                   expected_line=9, expected_lines=[9, 10, 11])
        assert result.direct_calls_schema == COLLECTOR_SCHEMA
        assert result.direct_calls == harness.fold_direct_calls(rows, 9, [9, 10, 11])
        scored = dict(record, item_id='ruby', coverage_lines={'app/models/fixture.rb': [1]})
        same = metrics.compare(scored, scored, index, boundary)
        assert same['counts']['gold_methods'] == len(expected) and same['api']['f1'] == 1.0
        old = metrics.compare(scored, dict(scored, direct_calls_schema=None), index, boundary)
        assert old['coverage']['recall'] == 1.0 and old['api_excluded']
        assert old['api_undefined_reason'] == 'run_before_api_amendment_3'
        assert metrics.summarise([old])['api_excluded']['run_before_api_amendment_3'] == 1
        null_union = harness.RunResult(exit_code=0, stdout='', wall_seconds=0,
                                       records=[dict(rows[0], direct_calls=[None]), rows[1]],
                                       expected_line=9, expected_lines=[9, 10, 11])
        assert null_union.direct_calls == [None]
        valid_event = next(event for event in captured['calls'] if event['ruby_binding'])
        malformed = [None, {}, dict(valid_event, callee_line=[]),
                     dict(valid_event, callee_file=7), dict(valid_event, ruby_binding=['wrong']),
                     dict(valid_event, ruby_binding=dict(valid_event['ruby_binding'], declaring_line='wrong'))]
        for bad in malformed:
            bad_rows = [dict(rows[0], direct_calls=[valid_event, bad]), rows[1]]
            folded = harness.RunResult(exit_code=0, stdout='', wall_seconds=0, records=bad_rows,
                                       expected_line=9, expected_lines=[9, 10, 11])
            events = folded.direct_calls
            assert len(events) == 2 and bad in events
            invalid_record = dict(scored, direct_calls=events, direct_calls_schema=folded.direct_calls_schema)
            assert metrics.direct_record_issue(invalid_record, index) == 'before_api_amendment_3'
            invalid_pair = metrics.compare(scored, invalid_record, index, boundary)
            assert invalid_pair['api_excluded'] and invalid_pair['api'] is None
            assert invalid_pair['api_undefined_reason'] == 'run_before_api_amendment_3'
        print('[PASS] Malformed Ruby outline events survive RunResult union without crashes or partial API credit')
        print('[PASS] Ruby invalid evidence, null/empty distinction, marker-preserving outline union and mixed-marker refusal')
        duplicate = json.loads(index_path.read_text())
        cls = next(cls for file in duplicate['files'].values() for cls in file['classes'] if cls['methods'])
        cls['methods'].append(cls['methods'][0])
        index_path.write_text(json.dumps(duplicate))
        try:
            metrics.load_prod_index(str(index_path))
        except metrics.MetricsInputError:
            pass
        else:
            raise AssertionError('duplicate exact Ruby binding accepted')
        print('[PASS] Duplicate exact index bindings refuse')
    return 0


if __name__ == '__main__':
    raise SystemExit(selftest())
