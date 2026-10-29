"""Python callable body spans and syntax-preserving declaration placeholders."""
from __future__ import annotations

import ast
import io
import tokenize

from ..core.source_view import BodyEdit, BodyRef, ViewRefused
from .prod_index import module_name, _decorator_names, _PROPERTY_DECORATORS


def source_bodies(path: str, raw: bytes) -> tuple[BodyEdit, ...]:
    """Inventory callable bodies without importing or executing the subject.

    Module/class initialization is a separate inventory obligation of the
    all-production selector. A callable inventory alone never claims 'all'.
    """
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding)
        tree = ast.parse(raw, filename=path)
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (SyntaxError, UnicodeError, LookupError, tokenize.TokenError) as exc:
        raise ViewRefused(f"cannot parse Python source {path}: {exc}") from exc
    codec = 'utf-8' if encoding == 'utf-8-sig' else encoding
    prefix = len(raw) - len(text.encode(codec))
    # The tokenizer's own line model, which `generate_tokens` reads above.
    # `str.splitlines` also breaks on form feed, VT, NEL and U+2028/9, so one
    # form feed inside a string literal shifted every later span by a line --
    # and left a body visible in output that still parsed.
    lines = list(io.StringIO(text))
    starts = [prefix]
    for line in lines:
        starts.append(starts[-1] + len(line.encode(codec)))

    def offset(position):
        row, col = position
        if row > len(lines):
            return len(raw)
        return starts[row - 1] + len(lines[row - 1][:col].encode(codec))

    def ast_offset(row, byte_col):
        col = len(lines[row - 1].encode('utf-8')[:byte_col].decode('utf-8'))
        return offset((row, col))

    def callable_edit(node, qualified, kind):
        start = ast_offset(node.lineno, node.col_offset)
        candidates = [i for i, t in enumerate(tokens) if offset(t.start) >= start]
        depth = 0
        colon = None
        for index in candidates:
            t = tokens[index]
            if t.type == tokenize.OP:
                if t.string in ('(', '[', '{'):
                    depth += 1
                elif t.string in (')', ']', '}'):
                    depth -= 1
                elif t.string == ':' and depth == 0:
                    colon = index
                    break
        first = colon + 1
        while tokens[first].type in (tokenize.COMMENT, tokenize.NL):
            first += 1
        doc = b''
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) \
                and isinstance(node.body[0].value.value, str):
            d = node.body[0]
            doc = raw[ast_offset(d.lineno, d.col_offset):ast_offset(d.end_lineno, d.end_col_offset)]
        begin = offset(tokens[colon].end)
        stub = b'raise NotImplementedError("implementation hidden")'
        if tokens[first].type != tokenize.NEWLINE:
            newline = next(t for t in tokens[first:] if t.type == tokenize.NEWLINE)
            end = offset(newline.start)
            replacement = b' ' + (doc + b'; ' if doc else b'') + stub
        else:
            indent_index = next(i for i in range(first + 1, len(tokens))
                                if tokens[i].type == tokenize.INDENT)
            indent = tokens[indent_index].string.encode(codec)
            # Comments outdented from the suite document a following
            # class/property: they belong to the surrounding contract and must
            # remain byte-exact, so the suite ends at the first line that is
            # neither blank nor a comment indented at least as far as it.
            end = offset((node.end_lineno + 1, 0))
            suite_width = len(tokens[indent_index].string.expandtabs(8))
            for row in range(node.end_lineno + 1, len(lines) + 1):
                line = lines[row - 1]
                stripped = line.lstrip(' \t\f')
                if not stripped.strip():
                    continue
                width = len(line[:len(line) - len(stripped)].expandtabs(8))
                if stripped.startswith('#') and width >= suite_width:
                    end = offset((row + 1, 0))
                else:
                    break
            newline = b'\r\n' if tokens[first].string == '\r\n' else b'\n'
            replacement = newline + (indent + doc + newline if doc else b'') + indent + stub + newline
        return BodyEdit(BodyRef(path, qualified, kind, begin, end), replacement)

    edits = []

    def walk(node, parents=(), in_class=False):
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                walk(child, (*parents, node.name), True)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators = _decorator_names(node)
            if any(name.rsplit('.', 1)[-1] == 'overload' for name in decorators):
                # typing overload suites declare signatures; they are not
                # additional implementations of __getitem__ (real docx API).
                declarations = (ast.Pass,)
                if any(not isinstance(statement, declarations)
                       and not (isinstance(statement, ast.Expr)
                                and isinstance(statement.value, ast.Constant)
                                and (statement.value.value is Ellipsis
                                     or isinstance(statement.value.value, str)))
                       for statement in node.body):
                    raise ViewRefused('overload declaration contains executable implementation')
                return
            kind = 'method' if in_class else 'function'
            suffix = ''
            if any(name in _PROPERTY_DECORATORS for name in decorators):
                kind = 'getter'
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name) and decorator.id == 'property':
                    kind = 'getter'
                if isinstance(decorator, ast.Attribute) and decorator.attr in ('getter', 'setter', 'deleter'):
                    kind = decorator.attr
                    if kind != 'getter':
                        suffix = '.' + kind
            name = '.'.join((module_name(path), *parents, node.name)) + suffix
            edits.append(callable_edit(node, name, kind))
            for child in node.body:
                walk(child, (*parents, node.name, '<locals>'), False)
            return
        if isinstance(node, ast.Lambda):
            expr = node.body
            begin = ast_offset(expr.lineno, expr.col_offset)
            end = ast_offset(expr.end_lineno, expr.end_col_offset)
            name = '.'.join((module_name(path), *parents, f'<lambda@{begin}>'))
            edits.append(BodyEdit(BodyRef(path, name, 'lambda', begin, end), b'None'))
        for child in ast.iter_child_nodes(node):
            walk(child, parents, in_class)

    walk(tree)
    return tuple(edits)


def parse_source(path: str, raw: bytes) -> None:
    try:
        ast.parse(raw, filename=path)
    except (SyntaxError, ValueError) as exc:
        raise ViewRefused(f"transformed Python source does not parse: {path}: {exc}") from exc
