"""Structural PHP source positions; never invoke a subject's PHP code."""
from __future__ import annotations

from ..core.source_view import BodyEdit, BodyRef, ViewRefused


def parse_source(path: str, raw: bytes):
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_php
    except ImportError as exc:
        raise ViewRefused('PHP source views require benchmark/requirements-coordinator.txt') from exc
    parser = Parser(Language(tree_sitter_php.language_php()))
    tree = parser.parse(raw)
    if tree.root_node.has_error:
        # The pinned CoreShop EntityRepository constructor uses implicit-public
        # readonly promotion. PHP permits it; grammar 0.24.1 requires visibility.
        # Normalize ONLY that recognized constructor-modifier error for parsing,
        # at identical byte width. All edits/contracts still use original raw
        # bytes, preserving readonly exactly. This is not source rewriting.
        # https://www.php.net/manual/en/language.oop5.properties.php
        errors = []
        def collect(node):
            if node.is_error or node.is_missing:
                errors.append(node)
            for child in node.children:
                collect(child)
        collect(tree.root_node)
        normalized = bytearray(raw)
        for error in errors:
            parameters = error.parent
            method = parameters.parent if parameters else None
            name = method.child_by_field_name('name') if method else None
            if raw[error.start_byte:error.end_byte] != b'readonly' \
                    or parameters.type != 'formal_parameters' \
                    or method.type != 'method_declaration' or name is None \
                    or raw[name.start_byte:name.end_byte].lower() != b'__construct':
                break
            normalized[error.start_byte:error.end_byte] = b'public  '
        else:
            tree = parser.parse(bytes(normalized))
    if tree.root_node.has_error:
        raise ViewRefused(f'PHP source does not parse: {path}')
    return tree


def source_bodies(path: str, raw: bytes) -> tuple[BodyEdit, ...]:
    tree = parse_source(path, raw)
    edits = []

    def name(node):
        return raw[node.start_byte:node.end_byte].decode('utf-8')

    def walk(node, namespace='', owner=''):
        if node.type in ('program', 'compound_statement'):
            current = namespace
            for child in node.named_children:
                if child.type == 'namespace_definition' and child.child_by_field_name('body') is None:
                    field = child.child_by_field_name('name')
                    current = name(field) if field else ''
                else:
                    walk(child, current, owner)
            return
        if node.type == 'namespace_definition':
            field = node.child_by_field_name('name')
            current = name(field) if field else ''
            body = node.child_by_field_name('body')
            if body:
                walk(body, current, '')
            return
        if node.type in ('class_declaration', 'interface_declaration', 'trait_declaration',
                         'enum_declaration', 'anonymous_class'):
            field = node.child_by_field_name('name')
            local = name(field) if field else f'<anonymous@{node.start_byte}>'
            owner = '\\'.join(p for p in (namespace, local) if p)
        if node.type in ('method_declaration', 'function_definition', 'anonymous_function',
                         'arrow_function'):
            body = node.child_by_field_name('body')
            if body is not None:
                field = node.child_by_field_name('name')
                local = name(field) if field else f'<closure@{node.start_byte}>'
                qualified = (owner + '::' + local if owner else
                             '\\'.join(p for p in (namespace, local) if p))
                kind = 'method' if node.type == 'method_declaration' else 'function'
                if body.type == 'compound_statement':
                    begin, end = body.start_byte + 1, body.end_byte - 1
                    replacement = b' throw new \\LogicException("implementation hidden"); '
                else:
                    begin, end = body.start_byte, body.end_byte
                    replacement = b'throw new \\LogicException("implementation hidden")'
                edits.append(BodyEdit(BodyRef(path, qualified, kind, begin, end), replacement))
        for child in node.named_children:
            walk(child, namespace, owner)

    walk(tree.root_node)
    return tuple(edits)
