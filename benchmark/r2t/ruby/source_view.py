"""Structural Ruby callable bodies, without loading or executing the subject.

Source identities are syntax/declaration positions, independent of runtime API
bindings. The shared source-view builder owns edits, containment and output.
"""
from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version

from ..core.source_view import BodyEdit, BodyRef, ViewRefused

PARSER_PACKAGES = {'tree-sitter': '0.25.2', 'tree-sitter-ruby': '0.23.1'}
_METHODS = {'method', 'singleton_method'}
_BLOCKS = {'block', 'do_block'}
_PLACEHOLDER = b'raise "implementation hidden"'


def _position(path, raw, offset):
    prefix = raw[:offset]
    line = prefix.count(b'\n') + 1
    column = len(prefix.rsplit(b'\n', 1)[-1]) + 1
    return f'{path}:{line}:{column}'


def parse_source(path: str, raw: bytes):
    """Return the pinned tree or a positioned prerequisite; never normalize."""
    try:
        raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ViewRefused(f'{_position(path, raw, exc.start)}: unsupported Ruby encoding; UTF-8 required') from exc
    # Ruby coding comments can override UTF-8 interpretation even when these
    # bytes happen to decode. Inspect only the language's first two lines.
    for match in re.finditer(rb'(?m)^[ \t]*#[^\r\n]*?\b(?:coding|encoding)\s*[:=]\s*([-\w]+)',
                             b'\n'.join(raw.split(b'\n')[:2])):
        if match[1].lower() not in (b'utf-8', b'utf8'):
            raise ViewRefused(f'{_position(path, raw, match.start())}: unsupported Ruby encoding declaration')
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_ruby
        for package, expected in PARSER_PACKAGES.items():
            if version(package) != expected:
                raise ViewRefused(f'{path}:1:1: Ruby source views require {package}=={expected}')
    except (ImportError, PackageNotFoundError) as exc:
        raise ViewRefused(f'{path}:1:1: Ruby source views require benchmark/requirements-coordinator.txt') from exc
    tree = Parser(Language(tree_sitter_ruby.language())).parse(raw)
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.is_error or node.is_missing:
            raise ViewRefused(f'{path}:{node.start_point.row + 1}:{node.start_point.column + 1}: '
                              f'Ruby parse error/missing {node.type}')
        pending.extend(reversed(node.children))
    return tree


def source_bodies(path: str, raw: bytes) -> tuple[BodyEdit, ...]:
    tree = parse_source(path, raw)
    edits = []

    def text(node):
        return raw[node.start_byte:node.end_byte].decode('utf-8')

    def descendants(node):
        yield node
        for child in node.named_children:
            yield from descendants(child)

    def refuse(node, reason):
        raise ViewRefused(f'{path}:{node.start_point.row + 1}:{node.start_point.column + 1}: {reason}')

    def interior(node):
        body = node.child_by_field_name('body')
        if body is None:
            return None  # A comment-only/empty callable has no invented body.
        if node.type in _METHODS and any(c.type == '=' for c in node.children):
            begin, end = body.start_byte, body.end_byte
            openings = [n for n in descendants(body) if n.type == 'heredoc_beginning']
            if openings:
                # The grammar places endless-method heredoc bodies after the
                # method as siblings. Consume precisely those bodies; consuming
                # another declaration/statement would be a noncontiguous edit.
                siblings = list(node.parent.named_children)
                index = siblings.index(node) + 1
                for _opening in openings:
                    if index >= len(siblings) or siblings[index].type != 'heredoc_body':
                        refuse(node, 'endless heredoc has no contiguous complete body binding')
                    end = siblings[index].end_byte
                    index += 1
            return begin, end, b'(' + _PLACEHOLDER + b')'
        closing = node.children[-1]
        expected = '}' if node.type == 'block' else 'end'
        if closing.type != expected:
            refuse(node, 'callable has no closing delimiter')
        parameters = node.child_by_field_name('parameters')
        header = parameters or (node.child_by_field_name('name') if node.type in _METHODS else node.children[0])
        if header is None:
            refuse(node, 'callable has no complete signature boundary')
        if any(n.type == 'heredoc_beginning' for n in descendants(header)):
            refuse(header, 'heredoc parameter overlaps callable interior; reviewed transformation required')
        # Include leading interior comments, which the grammar sometimes places
        # beside (not inside) body_statement, and the complete rescue/ensure tail.
        return header.end_byte, closing.start_byte, b'; ' + _PLACEHOLDER + b'; '

    def walk(node, lambda_wrapper=False):
        if node.type == 'lambda':
            wrapper = node.child_by_field_name('body')
            if wrapper is None or wrapper.type not in _BLOCKS:
                refuse(node, 'lambda has no supported block delimiter')
            span = interior(wrapper)
            if span is not None:
                begin, end, replacement = span
                identity = f'ruby:lambda:{node.start_byte}:<lambda>'
                edits.append(BodyEdit(BodyRef(path, identity, 'lambda', begin, end), replacement))
            # Inventory defaults and nested callables, but not a duplicate edit
            # for the lambda's own block wrapper.
            for child in node.named_children:
                walk(child, child == wrapper)
            return
        if node.type in _METHODS | _BLOCKS and not lambda_wrapper:
            span = interior(node)
            if span is not None:
                name = node.child_by_field_name('name')
                local = text(name) if name else '<block>'
                receiver = node.child_by_field_name('object')
                if receiver is not None:
                    local = text(receiver) + '.' + local
                kind = node.type
                begin, end, replacement = span
                identity = f'ruby:{kind}:{node.start_byte}:{local}'
                edits.append(BodyEdit(BodyRef(path, identity, kind, begin, end), replacement))
        for child in node.named_children:
            walk(child)

    walk(tree.root_node)
    return tuple(edits)


def selftest() -> int:
    """Real parser-to-shared-builder fixtures; no Ruby runtime is required."""
    from pathlib import Path
    import tempfile
    from ..core.source_view import (
        ItemSelection, Selection, TargetMap, ViewPolicy, build_agent_view,
        plan_agent_view, qualify_source_seed,
    )
    from ..toolkit.source_views import source_bodies as dispatch_bodies
    from ..toolkit.source_views import parse_source as dispatch_parse
    from ..toolkit.source_view_all import (
        _ruby_declaration_diagnostics, resolve_all_bodies, select_all_production,
    )
    ok = True

    def check(name, condition):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}")
        ok = ok and bool(condition)

    def refused(fn, needle=''):
        try:
            fn()
        except ViewRefused as exc:
            return needle in str(exc)
        return False

    def transform(raw, names=None):
        with tempfile.TemporaryDirectory(prefix='ruby-source-view-') as directory:
            root = Path(directory) / 'source'
            root.mkdir()
            (root / 'api.rb').write_bytes(raw)
            seed = qualify_source_seed(root=str(root), project='fixture',
                                       runtime_seed_digest='a' * 64)
            edits = dispatch_bodies('api.rb', raw)
            if names is not None:
                edits = tuple(e for e in edits if e.body.declaration_id in names)
            mapping = TargetMap('fixture', seed.files_digest, 'b' * 64, 'c' * 64,
                                (ItemSelection('item', ('API',), Selection(edits)),))
            policy = ViewPolicy('fixture', 'target_hidden', 'd' * 64, 'e' * 64,
                                'f' * 64, ('api.rb',), 'ruby-fixture')
            plan = plan_agent_view(source_seed=seed, item_id='item', policy=policy,
                                   target_map=mapping)
            out = Path(directory) / 'view'
            build_agent_view(plan, destination=str(out))
            result = (out / 'api.rb').read_bytes()
            dispatch_parse('api.rb', result)
            # Every gap outside the shared normalized edits remains identical.
            cursor = 0
            pieces = []
            for edit in plan.selection.bodies:
                pieces += [raw[cursor:edit.body.start_byte], edit.replacement]
                cursor = edit.body.end_byte
            pieces.append(raw[cursor:])
            check('shared writer preserves every unselected byte and pristine source',
                  result == b''.join(pieces) and (root / 'api.rb').read_bytes() == raw)
            return result, edits, plan.selection.bodies

    fixture = '''# encoding: UTF-8
require_relative "contract"
module Namespace
 class API < ::Base
  include ::Contract
  extend Contract
  attr_reader :value, "other_value"
  private
  def café(x, y = -1, *rest, label: "λ", enabled: true, required:, **kw, &block)
   # hidden algorithm
   text = "def/end are data"
   def nested(arg = [])
    secret_nested
   end
   implicit_secret
  rescue Error
   rescue_secret
  else
   else_secret
  ensure
   ensure_secret
  end
  def self.build = compute_secret
  class << self
   def ready?
    readiness_secret
   end
  end
  def empty; end
 end
 class API
  def café(x); reopened_secret; end
 end
end
'''
    for newline in ('\n', '\r\n'):
        raw = fixture.replace('\n', newline).encode()
        result, edits, selected = transform(raw)
        ids = [e.body.declaration_id for e in edits]
        check(f'original byte identities distinguish nested/reopened/singleton methods {newline!r}',
              len(ids) == len(set(ids)) == 5
              and sum(i.endswith(':café') for i in ids) == 2
              and any(':singleton_method:' in i and i.endswith(':self.build') for i in ids)
              and any(i.endswith(':nested') for i in ids)
              and len(selected) == 4)
        check(f'complete bodies hide implicit returns, comments, rescue/else/ensure {newline!r}',
              all(word not in result for word in (b'secret', b'hidden algorithm', b'def nested', b'rescue Error'))
              and b'def empty; end' in result and b'attr_reader :value, "other_value"' in result
              and b'y = -1' in result and b'required:' in result
              and b'# encoding: UTF-8' + newline.encode() in result)
        check('frozen declarations inspect defaults outside, skip nested defaults inside hidden body',
              _ruby_declaration_diagnostics('api.rb', raw) == ())
        narrow = next(e for e in edits if e.body.declaration_id.endswith(':nested'))
        narrow_result, _, narrow_selected = transform(raw, {narrow.body.declaration_id})
        check('a narrow nested target preserves its outer implementation',
              len(narrow_selected) == 1 and b'secret_nested' not in narrow_result
              and b'implicit_secret' in narrow_result and b'def nested(arg = [])' in narrow_result)

    callbacks = b'''scope :active, ->(x = 1) { by_name(x) }
callback = proc do |x|
  before
rescue Error
  recover
ensure
  finish
end
register do
 def nested; inside; end
 call { nested_call }
end
'''
    result, edits, selected = transform(callbacks)
    check('lambda/default, proc and declaration blocks have distinct complete bodies',
          [e.body.kind for e in edits] == ['lambda', 'do_block', 'do_block', 'method', 'block']
          and b'->(x = 1)' in result and b'|x|' in result
          and all(word not in result for word in (b'by_name', b'recover', b'finish', b'def nested'))
          and len(selected) == 3)
    check('body inventory never admits retained Rails callbacks or assigned closures',
          refused(lambda: resolve_all_bodies('api.rb', callbacks), 'unapproved_call:scope'))
    for raw in (b'def f\n <<~TEXT\n secret\nTEXT\nend\n',
                b'def f = <<~TEXT\n secret\nTEXT\n',
                b'def f = combine(<<A, <<B)\n one\nA\n two\nB\n'):
        for data in (raw, raw.replace(b'\n', b'\r\n')):
            result, _, _ = transform(data)
            check('heredoc body/terminator removed; final physical newline retained',
                  b'secret' not in result and b'one' not in result and b'two' not in result
                  and b'<<' not in result and result.endswith(b'\r\n' if b'\r\n' in data else b'\n'))
    check('noncontiguous endless heredoc and parameter-heredoc overlap visibly refuse',
          refused(lambda: source_bodies('api.rb', b'def f = <<A; other\nsecret\nA\n'), 'contiguous')
          and refused(lambda: source_bodies('api.rb', b'def f(x = <<A)\nsecret\nA\n x\nend\n'), 'heredoc parameter'))
    check('empty/comment-only methods and blocks invent no body',
          source_bodies('api.rb', b'def f; end\ndef self.g\n # contract\nend\n-> {}\nf do\n# contract\nend\n') == ())
    check('missing/error nodes and unsupported encodings refuse with positions',
          refused(lambda: parse_source('api.rb', b'def f(\n'), 'api.rb:')
          and refused(lambda: parse_source('api.rb', b'"\xff"'), 'api.rb:1:2')
          and refused(lambda: parse_source('api.rb', b'# coding: latin-1\ntrue\n'), 'encoding declaration'))
    allowed = (
        b'require "x"\nrequire_relative "x"\n',
        b'class ::A::B < ::Parent\ninclude X, ::Y::Z\nextend X\nprivate :a, "[]"\npublic\nprotected()\nattr_writer :name\nattr_accessor "value"\nend\n',
        b'class << self\ndef +(other); other; end\ndef self.make(x=1, y=-2.0, z=:key, **kw); x; end\nend\n',
        b'def f((a,b), *rest, **kw, &block); a; end\ndef forward(...); target(...); end\n',
    )
    for raw in allowed:
        check(f'closed static declaration predicate {raw[:35]!r}',
              _ruby_declaration_diagnostics('api.rb', raw) == ())
    denied = (
        (b'VALUE = 1\n', 'value_assignment:assignment'),
        (b'alias second first\n', 'unapproved_declaration:alias'),
        (b'alias_method :second, :first\n', 'unapproved_call:alias_method'),
        (b'extend self\n', 'unapproved_call_shape:extend'),
        (b'module_function\n', 'unapproved_declaration:identifier'),
        (b'attribute :x\n', 'unapproved_call:attribute'),
        (b'attr_reader :"bad-name"\n', 'unapproved_call_shape:attr_reader'),
        (b'attr_reader "a\\x62"\n', 'unapproved_call_shape:attr_reader'),
        (b'require "#{computed}"\n', 'unapproved_call_shape:require'),
        (b'private def f; 1; end\n', 'unapproved_call_shape:private'),
        (b'def f(x=[]); x; end\n', 'non_scalar_default:array'),
        (b'def f(x={}); x; end\n', 'non_scalar_default:hash'),
        (b'def f(x=DEFAULT); x; end\n', 'non_scalar_default:constant'),
        (b'def f(x=compute); x; end\n', 'non_scalar_default:identifier'),
        (b'class A < build(Base); end\n', 'dynamic_or_unsupported_superclass'),
        (b'def (factory).f; 1; end\n', 'dynamic_singleton_method_receiver'),
    )
    for raw, reason in denied:
        diagnostics = _ruby_declaration_diagnostics('api.rb', raw)
        check(f'closed refusal {reason}', bool(diagnostics) and diagnostics[0]['reason'] == reason
              and refused(lambda: resolve_all_bodies('api.rb', raw), reason))
    with tempfile.TemporaryDirectory(prefix='ruby-all-view-') as directory:
        root = Path(directory)
        (root / 'target.rb').write_bytes(b'def f; 1; end\n')
        (root / 'untargeted.rb').write_bytes(b'VALUE = 1\n')
        seed = qualify_source_seed(root=directory, project='fixture', runtime_seed_digest='a' * 64)
        policy = ViewPolicy('fixture', 'all_hidden', 'b' * 64, 'c' * 64, 'd' * 64,
                            ('target.rb', 'untargeted.rb'), 'ruby-fixture')
        check('all-production inspects untargeted files independently of named maps',
              refused(lambda: select_all_production(source_seed=seed, policy=policy,
                                                     file_rules=(), contracts=()), 'untargeted.rb'))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(selftest())
