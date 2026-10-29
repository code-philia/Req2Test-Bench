"""Complete all-production selection for the shared source-view builder.

The reviewed file rules account for every subject file in ViewPolicy. The
shared language resolver supplies *all* bodies for each transformed file;
target annotations and per-item target selections never limit this walk.
This module does not parse or rewrite a language, materialize workspaces,
or admit a project/backend for evaluation.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import PurePosixPath

from r2t.core import source_view
from r2t.core.source_view import (
    ContractFile,
    Selection,
    SourceSeed,
    ViewPolicy,
    ViewRefused,
)

TRANSFORMER = "r2t.all-production-source-view/v1"

# Non-code production data in the pinned python-docx source projection.
# Keep this explicit: archives elsewhere are not automatically dependency data.
_DOCX_DATA_PATHS = {
    'src/docx/py.typed',
    'src/docx/templates/default.docx',
    'src/docx/templates/default-docx-template/docProps/thumbnail.jpeg',
    'src/docx/templates/default-docx-template/_rels/.rels',
    'src/docx/templates/default-docx-template/customXml/_rels/item1.xml.rels',
    'src/docx/templates/default-docx-template/word/_rels/document.xml.rels',
}


# Declarative python-docx callees whose calls may stand in place as an
# assignment value (xmlchemy/typing descriptors) or a bare statement
# (element-class registration), reviewed in spec #418 section 3.
_ALLOWED_VALUE_CALLEES = {
    'TypeVar', 'ZeroOrOne', 'ZeroOrMore', 'OneAndOnlyOne', 'OneOrMore',
    'OptionalAttribute', 'RequiredAttribute',
}
_ALLOWED_STATEMENT_CALLEES = {'register_element_cls'}


def _python_declarations(path: str, raw: bytes) -> None:
    """Reject executable initialization outside the suites the parser hides."""
    tree = ast.parse(raw, filename=path)

    def refuse(node, detail):
        raise ViewRefused(
            f"{path}:{node.lineno}: {detail}; reviewed declarative replacement required"
        )

    def data(node):
        if node is None or isinstance(node, (ast.Constant, ast.Name)):
            return True
        if isinstance(node, ast.Attribute):
            return data(node.value)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return all(data(value) for value in node.elts)
        if isinstance(node, ast.Dict):
            return all(key is not None and data(key) and data(value)
                       for key, value in zip(node.keys, node.values))
        return (isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub))
                and isinstance(node.operand, ast.Constant)
                and type(node.operand.value) in (int, float, complex))

    def dotted_name(node):
        if isinstance(node, ast.Name):
            return True
        return isinstance(node, ast.Attribute) and dotted_name(node.value)

    def declarative_argument(node):
        if isinstance(node, ast.Constant) or dotted_name(node):
            return True
        if isinstance(node, ast.Tuple):
            return all(isinstance(value, ast.Constant) or dotted_name(value)
                       for value in node.elts)
        return False

    def declarative_call(node, callees):
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in callees
                and not any(isinstance(arg, ast.Starred) for arg in node.args)
                and all(declarative_argument(arg) for arg in node.args)
                and all(keyword.arg is not None and declarative_argument(keyword.value)
                       for keyword in node.keywords))

    def annotation(node):
        if data(node):
            return True
        if isinstance(node, ast.Subscript):
            return annotation(node.value) and annotation(node.slice)
        if isinstance(node, (ast.Tuple, ast.List)):
            return all(annotation(value) for value in node.elts)
        return (isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr)
                and annotation(node.left) and annotation(node.right))

    def suite(nodes):
        for node in nodes:
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.Pass)):
                continue
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, str):
                continue  # declaration and enum-member documentation
            if isinstance(node, ast.Expr) \
                    and declarative_call(node.value, _ALLOWED_STATEMENT_CALLEES):
                continue  # reviewed element-class registration
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if any(not isinstance(value, (ast.Name, ast.Attribute)) or not data(value)
                       for value in node.decorator_list):
                    refuse(node, "computed decorator")
                if isinstance(node, ast.ClassDef):
                    if any(not annotation(value) for value in node.bases) \
                            or any(value.arg is None or not annotation(value.value)
                                   for value in node.keywords):
                        refuse(node, "computed base or metaclass")
                    suite(node.body)
                else:
                    args = node.args
                    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
                    parameters += [arg for arg in (args.vararg, args.kwarg) if arg is not None]
                    if any(not data(value) for value in (*args.defaults, *args.kw_defaults)):
                        refuse(node, "computed parameter default")
                    if not annotation(node.returns) \
                            or any(not annotation(arg.annotation) for arg in parameters):
                        refuse(node, "computed annotation")
                    # The shared parser removes the entire callable suite,
                    # including nested definitions and executable expressions.
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(not isinstance(target, ast.Name) for target in targets):
                    refuse(node, "registration or attribute/subscript assignment")
                if isinstance(node, ast.AnnAssign) and not annotation(node.annotation):
                    refuse(node, "computed annotation")
                if not data(node.value) \
                        and not declarative_call(node.value, _ALLOWED_VALUE_CALLEES):
                    refuse(node, "computed value or generated descriptor/type declaration")
                continue
            if isinstance(node, ast.If) and isinstance(node.test, ast.Name) \
                    and node.test.id == 'TYPE_CHECKING' and not node.orelse \
                    and all(isinstance(child, (ast.Import, ast.ImportFrom)) for child in node.body):
                continue
            refuse(node, f"executable {type(node).__name__} outside callable bodies")

    suite(tree.body)


def _php_declarations(path: str, raw: bytes) -> None:
    """Use the shared PHP syntax tree to account for every surviving node."""
    from r2t.php.source_view import parse_source

    tree = parse_source(path, raw)
    # Declaration/header and constant-expression forms in the pinned PHP
    # trees. Unknown forms are prerequisites, never an implicit retention rule.
    declarations = {
        'program', 'php_tag', 'comment', 'declare_statement', 'declare_directive',
        'namespace_definition', 'namespace_name', 'namespace_use_declaration',
        'namespace_use_clause', 'name', 'qualified_name', 'relative_scope',
        'class_declaration', 'interface_declaration', 'trait_declaration',
        'enum_declaration', 'declaration_list', 'enum_declaration_list', 'enum_case',
        'base_clause', 'class_interface_clause', 'use_declaration', 'use_list', 'use_as_clause',
        'abstract_modifier', 'final_modifier', 'static_modifier', 'visibility_modifier',
        'readonly_modifier', 'reference_modifier', 'formal_parameters',
        'simple_parameter', 'variadic_parameter', 'property_promotion_parameter',
        'primitive_type', 'bottom_type', 'named_type', 'optional_type', 'union_type', 'intersection_type',
        'property_declaration', 'property_element', 'const_declaration', 'const_element',
        'attribute_list', 'attribute_group', 'attribute', 'arguments', 'argument',
        'array_creation_expression', 'array_element_initializer',
        'class_constant_access_expression', 'variable_name', 'null', 'boolean',
        'integer', 'float', 'string', 'string_content', 'encapsed_string', 'escape_sequence',
        'binary_expression', 'unary_op_expression', 'compound_statement',
    }
    callables = {'method_declaration', 'function_definition', 'anonymous_function', 'arrow_function'}

    def walk(node):
        if node.type == 'return_statement' and len(node.named_children) == 1 \
                and node.named_children[0].type in ('anonymous_function', 'arrow_function'):
            # PHP's configuration-file calling convention exports a closure;
            # its implementation is selected by the same common body parser.
            walk(node.named_children[0])
            return
        if node.type not in declarations | callables:
            raise ViewRefused(
                f"{path}:{node.start_point.row + 1}: unsupported PHP {node.type} outside "
                "callable bodies; reviewed declarative replacement required"
            )
        for index, child in enumerate(node.children):
            if child.is_named and not (
                node.type in callables and node.field_name_for_child(index) == 'body'
            ):
                walk(child)

    walk(tree.root_node)


def _ruby_declaration_diagnostics(path: str, raw: bytes) -> tuple[dict, ...]:
    """Frozen B0 predicates; collect maximal refused subtrees for census review."""
    from collections import Counter
    import re
    from ..ruby.source_view import parse_source

    tree = parse_source(path, raw)
    METHODS = {'method', 'singleton_method'}
    VIS = {'public', 'private', 'protected'}
    ATTR = {'attr_reader', 'attr_writer', 'attr_accessor'}
    ALLOW_CALLS = VIS | ATTR | {'require', 'require_relative', 'include', 'extend'}
    def src(n):
        return raw[n.start_byte:n.end_byte].decode('utf-8')
    def pos(n):
        return dict(path=path, kind=n.type, start_byte=n.start_byte, end_byte=n.end_byte,
                    line=n.start_point.row + 1, column_byte=n.start_point.column + 1,
                    end_line=n.end_point.row + 1, end_column_byte=n.end_point.column + 1,
                    snippet=src(n)[:240])
    def named(n):
        return [c for c in n.named_children if c.type != 'comment']
    def field_shape(n, allowed):
        return all(not c.is_named or c.type == 'comment' or n.field_name_for_child(i) in allowed
                   for i, c in enumerate(n.children))
    def static_constant(n):
        if n is None:
            return False
        if n.type == 'constant':
            return not n.named_children
        if n.type != 'scope_resolution' or not field_shape(n, {'scope', 'name'}):
            return False
        name, scope = n.child_by_field_name('name'), n.child_by_field_name('scope')
        return name is not None and name.type == 'constant' and (scope is None or static_constant(scope))
    def plain_string(n):
        return n is not None and n.type == 'string' and all(c.type in {'string_content', 'escape_sequence'} for c in n.named_children)
    def scalar(n):
        if n is None:
            return False
        if n.type in {'nil', 'true', 'false', 'integer', 'float', 'simple_symbol'}:
            return not n.named_children
        if plain_string(n):
            return True
        if n.type == 'unary' and field_shape(n, {'operator', 'operand'}):
            op, operand = n.child_by_field_name('operator'), n.child_by_field_name('operand')
            return op is not None and src(op) in {'+', '-'} and operand is not None and operand.type in {'integer', 'float'} and not operand.named_children
        return False

    def static_method_name(n):
        # No interpolation/evaluation, including Ruby operator method names.
        return n is not None and (n.type == 'simple_symbol' or plain_string(n))
    def static_attribute_name(n):
        if n.type == 'simple_symbol':
            value = src(n)[1:]
        elif plain_string(n) and not any(c.type == 'escape_sequence' for c in n.named_children):
            value = ''.join(src(c) for c in n.named_children)
        else:
            return False
        return re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value) is not None

    def parameter(n, diagnostics):
        if n.type == 'identifier' and not n.named_children:
            return
        if n.type in {'splat_parameter', 'hash_splat_parameter', 'block_parameter'} and field_shape(n, {'name'}):
            name = n.child_by_field_name('name')
            if name is None or (name.type == 'identifier' and not name.named_children):
                return
        if n.type == 'forward_parameter' and not n.named_children and src(n) == '...':
            return
        if n.type == 'destructured_parameter':
            for c in named(n):
                parameter(c, diagnostics)
            return
        if n.type in {'optional_parameter', 'keyword_parameter'} and field_shape(n, {'name', 'value'}):
            name, value = n.child_by_field_name('name'), n.child_by_field_name('value')
            if name is None or name.type != 'identifier' or name.named_children:
                refuse(n, 'unsupported_parameter_name', diagnostics)
            elif value is None and n.type == 'keyword_parameter':
                return
            elif not scalar(value):
                refuse(value if value is not None else n, 'non_scalar_default:' + (value.type if value else '<missing>'), diagnostics)
            return
        refuse(n, 'unsupported_parameter:' + n.type, diagnostics)

    def refuse(n, reason, diagnostics):
        diagnostics.append(dict(pos(n), reason=reason))

    def declaration(n, diagnostics, accepted_shapes):
        if n.type in {'program', 'body_statement'}:
            for c in named(n):
                declaration(c, diagnostics, accepted_shapes)
            return
        if n.type == 'comment' or plain_string(n):
            accepted_shapes[n.type] += 1
            return
        if n.type in {'class', 'module'}:
            name = n.child_by_field_name('name')
            superclass = n.child_by_field_name('superclass')
            if not field_shape(n, {'name', 'superclass', 'body'}) or not static_constant(name):
                refuse(n, 'dynamic_or_unsupported_scope_header', diagnostics)
                return
            if superclass is not None and (superclass.type != 'superclass' or len(named(superclass)) != 1 or not static_constant(named(superclass)[0])):
                refuse(n, 'dynamic_or_unsupported_superclass', diagnostics)
                return
            accepted_shapes[n.type] += 1
            body = n.child_by_field_name('body')
            if body is not None:
                if body.type != 'body_statement':
                    refuse(body, 'unsupported_scope_body:' + body.type, diagnostics)
                else:
                    declaration(body, diagnostics, accepted_shapes)
            return
        if n.type == 'singleton_class':
            value = n.child_by_field_name('value')
            if not field_shape(n, {'value', 'body'}) or value is None or value.type != 'self':
                refuse(n, 'dynamic_or_unsupported_singleton_class', diagnostics)
                return
            accepted_shapes[n.type] += 1
            body = n.child_by_field_name('body')
            if body is not None:
                if body.type != 'body_statement':
                    refuse(body, 'unsupported_scope_body:' + body.type, diagnostics)
                else:
                    declaration(body, diagnostics, accepted_shapes)
            return
        if n.type in METHODS:
            name = n.child_by_field_name('name')
            obj = n.child_by_field_name('object')
            if not field_shape(n, {'name', 'object', 'parameters', 'body'}) or name is None or name.type not in {'identifier', 'operator', 'constant', 'setter'}:
                refuse(n, 'unsupported_method_header', diagnostics)
                return
            if n.type == 'singleton_method' and (obj is None or (obj.type != 'self' and not static_constant(obj))):
                refuse(n, 'dynamic_singleton_method_receiver', diagnostics)
                return
            before = len(diagnostics)
            params = n.child_by_field_name('parameters')
            if params is not None:
                if params.type != 'method_parameters':
                    refuse(params, 'unsupported_method_parameters', diagnostics)
                else:
                    for c in named(params):
                        parameter(c, diagnostics)
            if len(diagnostics) == before:
                accepted_shapes[n.type] += 1
            # COMPLETE body field is intentionally opaque, including rescue/ensure.
            # Empty no-body-field and endless-expression forms are inventoried, not transformed.
            return
        if n.type == 'identifier' and src(n) in VIS:
            accepted_shapes['visibility_bare:' + src(n)] += 1
            return
        if n.type == 'call':
            method = n.child_by_field_name('method')
            name = src(method) if method is not None else '<missing>'
            args = n.child_by_field_name('arguments')
            children = named(args) if args is not None else []
            shape = (method is not None and method.type == 'identifier' and
                     field_shape(n, {'method', 'arguments'}) and
                     (args is None or args.type == 'argument_list'))
            approved = False
            if shape and name in {'require', 'require_relative'}:
                approved = len(children) == 1 and plain_string(children[0])
            elif shape and name in {'include', 'extend'}:
                approved = bool(children) and all(static_constant(c) for c in children)
            elif shape and name in VIS:
                approved = all(static_method_name(c) for c in children)
            elif shape and name in ATTR:
                approved = bool(children) and all(static_attribute_name(c) for c in children)
            if approved:
                accepted_shapes['call:' + name] += 1
            else:
                refuse(n, ('unapproved_call_shape:' if name in ALLOW_CALLS else 'unapproved_call:') + name, diagnostics)
            return
        if n.type in {'assignment', 'operator_assignment', 'multiple_assignment'}:
            refuse(n, 'value_assignment:' + n.type, diagnostics)
            return
        refuse(n, 'unapproved_declaration:' + n.type, diagnostics)
    diagnostics = []
    declaration(tree.root_node, diagnostics, Counter())
    return tuple(diagnostics)


def _ruby_declarations(path: str, raw: bytes) -> None:
    diagnostics = _ruby_declaration_diagnostics(path, raw)
    if diagnostics:
        first = diagnostics[0]
        raise ViewRefused(
            f"{path}:{first['line']}:{first['column_byte']}: {first['reason']}; "
            f"{len(diagnostics)} unsupported Ruby declarations outside callable bodies; "
            "reviewed declarative replacement required")


def _go_declarations(path: str, raw: bytes, *, go, go_context, go_scratch):
    """Closed declaration policy, including every inactive readable Go file."""
    from ..go.source_view import source_inventory
    inventory = source_inventory(path, raw, go=go, go_context=go_context,
                                 go_scratch=go_scratch)
    if inventory.contract_only_reasons:
        reasons = '; '.join(f'{issue["path"]}:{issue["line"]}: {issue["node"]}: '
                            f'{issue["reason"]} ({issue["declaration"]})'
                            for issue in inventory.contract_only_reasons)
        raise ViewRefused(f'{path}: use reviewed contract_only omission: {reasons}')
    return inventory.bodies


def resolve_all_bodies(path: str, raw: bytes, *, java=None, javac=None,
                       go=None, go_context=None, go_scratch=None) -> Selection:
    """Common callable spans plus all-scope executable-initialization checks.

    This deliberately refuses unresolved dynamic contracts. The map must
    supply a reviewed representation before those files can be admitted.
    No missing prerequisite is converted into an item failure or exclusion.
    """
    from .source_views import source_bodies

    suffix = PurePosixPath(path).suffix
    if suffix == '.go':
        edits = _go_declarations(path, raw, go=go, go_context=go_context, go_scratch=go_scratch)
    elif suffix == '.py':
        edits = source_bodies(path, raw)
        _python_declarations(path, raw)
    elif suffix == '.java':
        # J1 inventories callable bodies and executable field/block initializers.
        # Its public entry point refuses unsupported contract shapes.
        edits = source_bodies(path, raw, java=java, javac=javac)
    elif suffix == '.php':
        edits = source_bodies(path, raw)
        _php_declarations(path, raw)
    elif suffix == '.rb':
        _ruby_declarations(path, raw)
        edits = source_bodies(path, raw)
    elif go_context is not None:
        # Go embed/resource bytes need explicit reviewed dispositions; the
        # older language profiles' extension allowlist is not Go admission.
        raise ViewRefused(f'{path}: Go resource needs a reviewed contract-only rule')
    elif path in _DOCX_DATA_PATHS or suffix in ('.json', '.yml', '.yaml', '.xml', '.toml', '.neon', '.md'):
        return Selection()  # reviewed non-code configuration/documentation
    else:
        raise ViewRefused(
            f"{path}: unsupported executable resource/language; "
            "reviewed contract-only rule or shared parser required"
        )
    return Selection(edits)


@dataclass(frozen=True)
class ProductionFileRule:
    """A reviewed contract-only omission for one subject file.

    Every subject path not named here goes through ``resolve_all_bodies``.
    ``contract_paths`` names the non-empty supplement(s) that replace the
    omitted source, supplied identically across visibility scopes in
    TargetMap.contracts.
    """

    path: str
    contract_paths: tuple[str, ...]


def select_all_production(
    *,
    source_seed: SourceSeed,
    policy: ViewPolicy,
    file_rules: tuple[ProductionFileRule, ...],
    contracts: tuple[ContractFile, ...],
    java: str | None = None,
    javac: str | None = None,
    go: str | None = None,
    go_context: dict | None = None,
    go_scratch: str | None = None,
) -> Selection:
    """Resolve every subject file into TargetMap.all_selection.

    ``file_rules`` names only the contract-only omissions; every other
    subject path is resolved by ``resolve_all_bodies``, the common
    language/inventory resolver. It returns all BodyEdits for a file, an
    empty Selection for declarations/data with no executable bodies, or
    raises ViewRefused with a concrete unsupported-form prerequisite.

    Complete path accounting cannot prove a parser's semantic completeness.
    Parser feature tests and independent checks of the resulting view are
    required by IMPLEMENTATION_VISIBILITY_SPEC and ALL_PRODUCTION_VIEW_CASES.
    The shared planner validates spans and collapses nested selected bodies.
    """
    subjects = set(policy.subject_paths)
    records = {record.path: record for record in source_seed.files}
    rules = {rule.path: rule for rule in file_rules}
    if len(rules) != len(file_rules):
        raise ViewRefused("duplicate all-production file rule")
    extra = rules.keys() - subjects
    if extra:
        raise ViewRefused(f"all-production file rule outside_subject: {sorted(extra)}")
    supplements = {contract.path: contract.content for contract in contracts}
    if len(supplements) != len(contracts):
        raise ViewRefused("duplicate all-production contract supplement")

    java_sources = {
        path: source_view._source_bytes(source_seed, records[path])
        for path in sorted(subjects) if path.endswith('.java') and path not in rules
    }
    java_inventories = {}
    if java_sources:
        from .source_views import _java_tools
        from ..java.source_view import source_inventories
        java_inventories = source_inventories(java_sources, **_java_tools(java, javac))
    bodies = []
    omissions = []
    for path in sorted(subjects):
        rule = rules.get(path)
        if rule is not None:
            if not rule.contract_paths or any(
                not supplements.get(contract_path) for contract_path in rule.contract_paths
            ):
                raise ViewRefused(f"{path}: contract-only resource needs its contract supplement")
            omissions.append(path)
            continue
        # Use the common qualified-source reader; never parse or omit a stale
        # source file and then bind its edits to a different source identity.
        try:
            if path in java_inventories:
                inventory = java_inventories[path]
                if inventory.contract_only_reasons:
                    raise ViewRefused(f'{path}: use reviewed contract_only omission: ' +
                                      '; '.join(inventory.contract_only_reasons))
                resolved = Selection(inventory.bodies)
            else:
                raw = source_view._source_bytes(source_seed, records[path])
                resolved = resolve_all_bodies(path, raw, java=java, javac=javac,
                    go=go, go_context=go_context, go_scratch=go_scratch)
        except ViewRefused as exc:
            raise ViewRefused(f"{source_seed.project}/{path}: {exc}") from exc
        bodies.extend(resolved.bodies)

    return Selection(tuple(bodies), tuple(omissions))
