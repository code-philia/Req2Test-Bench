"""Retained-test helpers that every coddy-agent candidate execution receives.

Retained ordinary tests in five coddy-agent packages use 20 helper
declarations that exist only in removed gold ``bdd_*_test.go`` files. Every
candidate execution is supplied each of them that the candidate's own answer
files do not declare, copied from the preserved gold into one harness-owned
file per gold source. The file exists only in the disposable execution copy,
so the original workspace never holds it and retiring the copy removes it.
Candidate bytes are never edited, and the choice depends on the candidate's
declarations alone, never on compiler output. Gold declares every helper, so
gold receives nothing.

This was the labelled post-hoc sensitivity ``coddy_retained_helpers_v1``
(specifications/CODDY_RETAINED_HELPERS_SENSITIVITY_SPEC.md), which is why the
module keeps its name. Harness 25 made it the default and retired the label
(specifications/EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md).

A small Go lexer is enough here: it finds top-level declarations and the
imports a declaration uses. It does not type-check; the compiler does that.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re

#: Gold file -> the retained-test helpers it declares (20 in all; audit
#: 2026-09-26). Each is a top-level func, type or const; a type brings every
#: method declared on it in the same file.
RETAINED_HELPERS = {
    'external/cli/bdd_cli_tui_test.go': ('bddTerminal',),
    'external/httpserver/bdd_compaction_http_test.go': ('cannedSummaryProvider',),
    'internal/agent/bdd_compaction_test.go': ('compactionUsageSender', 'transcriptText'),
    'internal/agent/bdd_loop_guard_test.go': ('bddLoopProvider', 'bddLoopedSentence',
                                              'bddLoopedThought'),
    'internal/agent/bdd_subagents_test.go': ('answerStep', 'commandCall', 'recordingClient',
                                             'scriptStep', 'scriptedProvider', 'spawnCall',
                                             'toolStep'),
    'internal/tools/shell/bdd_background_test.go': ('sleepCommand',),
    'internal/tools/shell/bdd_foreground_timeout_test.go': ('complainCommand',
                                                            'lastingChildCommand'),
    'internal/tools/shell/bdd_special_characters_test.go': ('printCommand',),
    'internal/update/bdd_update_test.go': ('tarGzArchive', 'zipArchive'),
}
OVERLAY_PREFIX = 'zz_r2t_retained_helpers_'


class SensitivityRefused(ValueError):
    pass


_TOKEN = re.compile(r'''
    (?P<nl>\n)
  | (?P<space>[ \t\r\f\v]+)
  | (?P<line>//[^\n]*)
  | (?P<block>/\*.*?\*/)
  | (?P<lit>`[^`]*`|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])+'|\.?\d[\w.]*)
  | (?P<ident>[^\W\d]\w*)
  | (?P<punct>.)
''', re.S | re.X)
_KEYWORDS = frozenset('break case chan const continue default defer else fallthrough for func '
                      'go goto if import interface map package range return select struct '
                      'switch type var'.split())
# Go inserts a semicolon at a newline after these (spec, "Semicolons").
_ENDS_STATEMENT = frozenset({')', ']', '}'})
_OPEN, _CLOSE = '([{', ')]}'


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str
    start: int
    end: int


@dataclass
class Declaration:
    keyword: str
    names: list
    receiver: str | None
    grouped: bool
    start: int
    end: int
    specs: list


def _tokens(source):
    tokens = []
    for match in _TOKEN.finditer(source):
        kind, text = match.lastgroup, match.group()
        if kind in ('space', 'line'):
            continue
        if kind == 'block':
            if '\n' not in text:
                continue
            kind = 'nl'  # a general comment spanning lines acts like a newline
        tokens.append(_Token(kind, text, match.start(), match.end()))
    return tokens


def _terminates(token):
    """True when a newline after this token ends a statement."""
    return (token is not None
            and (token.kind == 'lit' or token.text in _ENDS_STATEMENT
                 or (token.kind == 'ident' and (token.text not in _KEYWORDS or token.text in
                                               ('break', 'continue', 'fallthrough', 'return')))))


def _matching(tokens, index):
    depth = 0
    for position in range(index, len(tokens)):
        text = tokens[position].text
        if tokens[position].kind == 'punct' and text in _OPEN:
            depth += 1
        elif tokens[position].kind == 'punct' and text in _CLOSE:
            depth -= 1
            if depth == 0:
                return position
    return len(tokens) - 1


def _statement_end(tokens, index):
    """Index of the last token of the top-level statement starting at index."""
    depth, previous = 0, None
    for position in range(index, len(tokens)):
        token = tokens[position]
        if depth == 0 and (token.text == ';' or (token.kind == 'nl' and _terminates(previous))):
            return position - 1
        if token.kind == 'punct' and token.text in _OPEN:
            depth += 1
        elif token.kind == 'punct' and token.text in _CLOSE:
            depth -= 1
        if token.kind != 'nl':
            previous = token
    return len(tokens) - 1


def _specs(tokens, first, last, keyword):
    """Split a spec list into (names, first token, last token) rows."""
    rows, position = [], first
    while position <= last:
        token = tokens[position]
        if token.kind == 'nl' or token.text == ';':
            position += 1
            continue
        end = min(_statement_end(tokens, position), last)
        names = []
        if keyword == 'import':
            pass
        elif token.kind == 'ident':
            names.append(token.text)
            if keyword in ('var', 'const'):
                cursor = position + 1
                while (cursor + 1 <= end and tokens[cursor].text == ','
                       and tokens[cursor + 1].kind == 'ident'):
                    names.append(tokens[cursor + 1].text)
                    cursor += 2
        rows.append((names, position, end))
        position = end + 1
    return rows


def declarations(source):
    """Top-level declarations of one Go file, in source order."""
    tokens, result, position = _tokens(source), [], 0
    while position < len(tokens):
        token = tokens[position]
        if token.kind != 'ident' or token.text not in ('func', 'type', 'var', 'const', 'import'):
            position += 1
            continue
        end = _statement_end(tokens, position)
        keyword, cursor, receiver, grouped, specs = token.text, position + 1, None, False, []
        if keyword == 'func':
            names = []
            if cursor <= end and tokens[cursor].text == '(':
                close, depth, idents = _matching(tokens, cursor), 0, []
                for inner in tokens[cursor + 1:close]:
                    depth += inner.text == '[' and inner.kind == 'punct'
                    depth -= inner.text == ']' and inner.kind == 'punct'
                    if depth == 0 and inner.kind == 'ident':
                        idents.append(inner.text)
                receiver = idents[-1] if idents else None
            elif cursor <= end and tokens[cursor].kind == 'ident':
                names = [tokens[cursor].text]
        elif cursor <= end and tokens[cursor].text == '(':
            grouped, close = True, _matching(tokens, cursor)
            specs = _specs(tokens, cursor + 1, close - 1, keyword)
            names = [name for row in specs for name in row[0]]
        else:
            specs = _specs(tokens, cursor, end, keyword)
            names = [name for row in specs for name in row[0]]
        result.append(Declaration(keyword, names, receiver, grouped, token.start,
                                  tokens[end].end, [(names_, tokens[a].start, tokens[b].end)
                                                    for names_, a, b in specs]))
        position = end + 1
    return result


def declared_names(source):
    """Package-level names a file declares; methods declare none."""
    return {name for declaration in declarations(source) if declaration.keyword != 'import'
            for name in declaration.names} - {'_'}


def _imports(source):
    """(local name, spec text) for every import of the file."""
    result = []
    for declaration in declarations(source):
        if declaration.keyword != 'import':
            continue
        for _, start, end in declaration.specs:
            spec = source[start:end]
            match = re.fullmatch(r'(?:([^\W\d]\w*|\.|_)\s+)?"([^"]+)"', spec.strip())
            if match is None:
                raise SensitivityRefused(f'REFUSED: unsupported import spec {spec!r}')
            result.append((match.group(1) or match.group(2).rsplit('/', 1)[-1], spec.strip()))
    return result


def _with_doc(source, start):
    """Move start up over the comment lines directly above a declaration."""
    line = source.rfind('\n', 0, start) + 1
    while line > 0:
        previous = source.rfind('\n', 0, line - 1) + 1
        text = source[previous:line - 1].strip()
        if not text.startswith('//') or text.startswith('//go:build'):
            break
        line = previous
    return line


def helper_source(gold, source_path, names):
    """A compilable test file holding exactly these gold declarations."""
    found = declarations(gold)
    chosen = []
    for name in names:
        owners = [d for d in found if name in d.names]
        if (len(owners) != 1 or owners[0].keyword not in ('func', 'type', 'const')
                or owners[0].grouped or owners[0].names != [name]):
            raise SensitivityRefused(f'REFUSED: {source_path} does not declare {name} '
                                     'alone as one top-level func, type or const')
        chosen.append(owners[0])
        if owners[0].keyword == 'type':
            chosen.extend(d for d in found if d.keyword == 'func' and d.receiver == name)
    body = '\n\n'.join(gold[_with_doc(gold, d.start):d.end]
                       for d in sorted(chosen, key=lambda d: d.start))
    used = {tokens[i].text for tokens in [_tokens(body)] for i in range(len(tokens) - 1)
            if tokens[i].kind == 'ident' and tokens[i + 1].text == '.'}
    imports = [spec for local, spec in _imports(gold) if local in used]
    package = re.search(r'^package\s+(\w+)', gold, re.M)
    if package is None:
        raise SensitivityRefused(f'REFUSED: {source_path} has no package clause')
    constraints = [line for line in gold[:package.start()].splitlines()
                   if line.startswith('//go:build') or line.startswith('// +build')]
    parts = []
    if constraints:
        parts.append('\n'.join(constraints) + '\n')
    parts.append(f'// Supplied by the harness from {source_path} for the retained tests.\n')
    parts.append(f'package {package.group(1)}\n')
    if imports:
        parts.append('import (\n' + ''.join(f'\t{spec}\n' for spec in imports) + ')\n')
    parts.append(body + '\n')
    return '\n'.join(parts)


def missing_helpers(context, installed, helpers=None):
    """{gold path: [names]}: the retained-test helpers an answer set lacks.

    ``installed`` is the candidate's exact answer set, as bytes or text. A
    helper is missing unless an answer file in the selected package declares
    that name at package level. Packages without retained helpers lack
    nothing. This is the whole decision; `overlay` only builds its files.
    """
    helpers = RETAINED_HELPERS if helpers is None else helpers
    package = context['package_dir']
    declared = set()
    for path, raw in installed.items():
        if PurePosixPath(path).parent.as_posix() == package:
            declared |= declared_names(raw.decode('utf-8') if isinstance(raw, bytes) else raw)
    missing = {}
    for source_path, names in sorted(helpers.items()):
        if PurePosixPath(source_path).parent.as_posix() != package:
            continue
        absent = [name for name in names if name not in declared]
        if absent:
            missing[source_path] = absent
    return missing


def overlay(context, installed, gold_root, helpers=None):
    """Return ({copy path: bytes}, {gold path: [supplied names]}) for one attempt.

    Every helper `missing_helpers` finds is copied from the preserved gold.
    """
    supplied = missing_helpers(context, installed, helpers)
    files = {}
    gold_root = Path(gold_root).resolve()
    for source_path, names in supplied.items():
        gold = (gold_root / source_path).read_text(encoding='utf-8')
        target = f"{context['package_dir']}/{OVERLAY_PREFIX}{PurePosixPath(source_path).name}"
        files[target] = helper_source(gold, source_path, names).encode('utf-8')
    return files, supplied
