"""Deterministic mutant enumerator and applier for the behave/Python stack.

The twin of `r2t/php/mutate.php`, written under the same three rules and for
the same reason (SPEC_C3_PARALLEL §3.11): the mutant population must be
DEFINED before anything is computed over it, and the definition has to be
reproducible from the bytes of a tree alone.

**TWO MODES, ONE PROGRAM, deliberately.**  The code that says "mutant M
exists here" and the code that materialises M must not be able to disagree
about what M is: `--apply-file` re-enumerates the single file it is about to
rewrite and REFUSES unless the requested record appears in that fresh
enumeration, field for field.  A file edited between enumeration and
application then fails loudly instead of scoring some other mutation under
M's identifier.

**This program assigns NO identifiers.**  `r2t.mutation` owns the id scheme,
so an id can outlive a change in traversal here.

**Determinism is the requirement, not a nicety.**  The campaign metadata
carries a digest of a manifest built from this output; if the digest moves,
every mutation number computed from it is unfalsifiable.  Two orderings are
pinned by hand — the file list is sorted (`os.walk` yields directory order,
which is inode order on ext4: stable on one machine and different on a
restored copy of the same tree), and per file the mutants are sorted by
(start byte, end byte, operator) after collection, so the result does not
depend on the AST walk order at all.

Positions
---------
Everything internal is an absolute BYTE offset into the file, and the record
carries 1-based line/column BYTE coordinates — `col = col_offset + 1` for an
AST node, because CPython's `col_offset` is already a UTF-8 byte offset
within its line.  Bytes rather than characters because the applier's splice
is a byte splice and `original` is compared byte for byte; a character column
would make that arithmetic depend on how the file is decoded.

`tokenize` reports CHARACTER columns, so every token position is converted
through the decoded line before it is used.  Both line tables split on `"\n"`
ALONE — `str.splitlines()` also breaks on `\v`, `\f`, `\x1c-\x1e`, `\x85`,
` ` and ` `, and a single form feed inside a string literal would
then shift every later line number by one.  That is the exact bug the PHP
twin records having had (`preg_split('/\\R/')`), and it is not repeated here.
A file whose line terminators disagree between `tokenize` (which splits on
`\n`) and `compile` (which also accepts a lone `\r`) is RECORDED AS AN ERROR
rather than enumerated, because the two would number its lines differently.

Operator profiles
-----------------
The immutable shared-eight profile is `r2t.mutation.OPERATORS_V1`; the default
`OPERATORS` profile appends the three v2 operators below.  What each name
MEANS in Python is not always what it means in PHP, and every difference is
written down here rather than left to be discovered from a count:

* `ConditionalBoundary` — `<` → `<=`, `<=` → `<`, `>` → `>=`, `>=` → `>`.
  Identical to the PHP twin.
* `NegateConditional` — `==` → `!=`, `!=` → `==`, `<` → `>=`, `>=` → `<`,
  `>` → `<=`, `<=` → `>`, and the two IDENTITY/MEMBERSHIP pairs Python has
  and PHP does not: `is` ↔ `is not`, `in` ↔ `not in`.  PHP's `===`/`!==`
  have no Python spelling; `is`/`in` are the operators that occupy the same
  place in a Python condition, so they are enumerated under the same name.
* `Increment` — `x += n` ↔ `x -= n` where `n` is a numeric literal.  **This
  is a DOCUMENTED SEMANTIC DEVIATION from the PHP twin and it needed a
  reviewer's sign-off** (plan risk 7): PHP's `++`/`--` change a variable by
  exactly one and their mutant is the same statement in the other direction,
  so `original` and `mutated` are both single tokens and the mutant moves the
  value by 2.  Python has no `++`; the nearest thing that is still "the
  increment operator" is a compound assignment by a constant, and mutating
  `x += 5` to `x -= 5` moves the value by 10, not by 2.  Same operator NAME,
  same intent (an off-by-direction change to an accumulating variable), a
  magnitude that depends on the literal.  A campaign that needs the operator
  suppressed passes an operator set without it; nothing here silently
  narrows the population.  **Measured, so the decision can be taken on
  evidence**: over python-docx's `src/` the enumerated population of this
  operator is ZERO.  The tree holds five augmented assignments and not one
  has a numeric literal on the right (`chunk_offset += 4 + 4 + …`,
  `xml += "  </w:tblGrid>\\n"`, three by attribute) — and the string ones are
  exactly the mutants the literal restriction exists to keep out, since
  `xml -= "…"` is a `TypeError` in every execution, i.e. killed by the
  interpreter rather than by any test.  So accepting the analogue and
  shipping the operator empty-population produce the SAME manifest for this
  corpus; the ruling binds a future one.
* `ArithmeticOperator` — `+` → `-`, `-` → `+`, `*` → `/`, `/` → `*`,
  `%` → `*`, on binary operators only.  Compound assignment (`+=`) belongs to
  `Increment` above and unary minus is excluded, exactly as in the PHP twin.
  Python's `+` and `%` are also string/sequence operators, so a few of these
  mutants die on a `TypeError` in every execution rather than on the
  behaviour under test.  They are still enumerated: an operator that silently
  skipped the cases it thought uninteresting would make the population depend
  on a judgement no reader can see.  (The PHP twin has the same property for
  `.`-adjacent numeric strings and does the same thing.)
* `TrueValue` / `FalseValue` — a `True` literal becomes `False` and vice
  versa.  The NAMES follow the PHP twin's implementation, where `TrueValue`
  is the operator that applies WHERE A `true` LITERAL IS (and replaces it
  with `false`).  `r2t.mutation`'s summary comment reads the other way round;
  the implementation is the authority both engines follow, so the two engines
  agree with each other.
* `ReturnValue` — `return <expr>` → `return None`.  A bare `return` and a
  literal `return None` are skipped (they already return None, so the mutant
  would be a no-op).  The PHP twin ALSO skips returns whose declared type
  forbids null, because PHP raises `TypeError` on them and the mutant is
  killed by construction; **Python annotations are not enforced at run time**,
  so there is no such class here and nothing is excluded on that ground.
  That is why this operator's Python population is proportionally larger, and
  it is a real difference in what the number means, not a bug.
* `MethodCallRemoval` — an expression statement whose value is a CALL becomes
  `pass`.  A call in statement position discards its value by definition,
  which is the "value unused" case the spec names; a call whose result is
  assigned, returned or passed on is not an expression statement and is left
  alone (deleting it would leave a NameError, i.e. a mutant killed by the
  interpreter rather than by the test).  **Wider than the PHP twin**, which
  takes only `$o->m()`/`A::m()` and leaves plain `foo()` alone: in Python the
  same syntax covers both and the plan (D5) specifies `Expr(Call) → pass`.
  The replacement is `pass` rather than nothing for the reason the PHP twin
  writes `;` — a braceless suite (`if x: log()`) has exactly one statement
  slot, and deleting the bytes leaves a file that does not parse.
* `LogicalConnector` — each `and` token becomes `or`, and each `or` becomes
  `and`.  A flattened `a and b and c` BoolOp yields two independent mutants,
  one per source connector.  This is the classical LCR family and the direct
  Python twin of PHP's `&&`/`||` and lower-precedence `and`/`or` replacements.
* `RemoveNegation` — delete the `not` token of an `ast.Not` unary expression.
  `is not` and `not in` remain `NegateConditional` comparisons; duplicating
  them here would create two names for the same semantic replacement.
* `ConstantReplacement` — a plain integer token `n` becomes decimal `n + 1`.
  Booleans are excluded even though `bool` subclasses `int`.  In `-1`, the
  literal node/token is `1` under Python's AST and therefore becomes `2`
  (the whole expression becomes `-2`); unary-sign insertion/deletion is a
  deliberately excluded family, not smuggled into constant replacement.

Deliberate v2 exclusions are UOI insertion (population explosion), string
literal mutation (high equivalent rate), general statement deletion (raises
the crash propensity this profile is intended to reduce), and bitwise,
argument and exception mutations.  The standards mapping and exact/partial
semantic labels live in `benchmark/MUTATION_OPERATOR_MAPPING_V2.md`.

Exclusions
----------
`@generated` / `GENERATED by` in the head of a file (nobody maintains a test
for generated code, so every one of its mutants is born unkillable), path
segments that are never the code under test, and coverage.py's own
`# pragma: no cover` — the analogue of the PHP twin's
`@codeCoverageIgnoreStart`/`End`.  A pragma on a CLAUSE HEADER excludes the
whole indented block it heads, which is what coverage.py does; a pragma on a
plain line excludes that line.  Two limits are stated rather than hidden: the
scan is textual, so a `# pragma: no cover` inside a triple-quoted string
excludes lines it does not mean to (coverage.py has the same limitation), and
a header whose block is written on the same line (`if x: f()  # pragma: no
cover`) is excluded as a single line, which is correct.

That pragma rule is frozen for the shared v1 operators because changing it
would detach archived rows.  The three appended v2 families enumerate the
production AST even on pragma-marked lines: a coverage exclusion is not a
mutation-ignore directive.  This distinction is observable in python-docx at
`src/docx/image/jpeg.py:223`, whose `if not byte_  # pragma: no cover` supplies
the 37th RemoveNegation candidate.  File/path/generated-code exclusions still
apply to both profiles.  If that pragma-marked mutant is execution-trivial,
the later assertion-stripped screen is expected to remove it from the hard
subset; source coverage policy does not pre-judge that behavioral question.

Usage
-----
ENUMERATE::

    python mutate.py --root /work --path src [--path ...] [--out FILE] \
        [--operator-profile v1|v2]

`v2` is the default.  Explicit `v1` enumeration runs only the frozen shared
traversal and retains the historical envelope shape, so its rows can be passed
directly to manifest construction with `OPERATORS_V1` rather than filtered
after the producer has already emitted a different population.

    {"engine": "r2t-mutate-py", "engine_version": "1.0",
     "parser": "cpython 3.12.13",
     "files": 95, "errors": {"<rel>": "<why>"},
     "n_invalid": 2,                 // optional; omitted when zero
     "enumerator_rev": "...",       // opt-in; omitted for legacy/v1
     "mutants": [{"file": "<rel>", "start_line": 42, "start_col": 17,
                  "end_line": 42, "end_col": 18,   // inclusive, 1-based BYTES
                  "operator": "NegateConditional",
                  "original": "<", "mutated": ">="}]}

APPLY::

    python mutate.py --root /work --apply-file <rel> \\
        --start-line N --start-col N --operator OP \\
        --original TEXT --mutated TEXT --out <rel>

Exit codes: 0 ok, 2 usage, 3 output failure, 4 REFUSED (integrity).
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import os
import platform
import re
import sys
import tokenize

#: First-party, and saying so is the point: an operator set that merely
#: RESEMBLES a published tool's must not be reported under that tool's name.
#: The `-py` suffix is what keeps this population and the PHP one from sharing
#: an id space — `r2t.mutation.mutant_id` hashes both fields.
ENGINE = "r2t-mutate-py"
ENGINE_VERSION = "1.0"
# This revision describes the enumerator implementation, not the population
# vocabulary.  Legacy/v1 construction deliberately does not record it: those
# manifests predate the field and must continue to reproduce byte-for-byte.
# A v2 caller opts in with ``--record-enumerator-rev`` and the manifest then
# carries this value inside its digest.
ENUMERATOR_REV = "r2t-mutate-py/m3-operators-v2-1"

#: Exit codes, quoted from `mutate.php`'s header so the two programs can be
#: driven by one caller.
EXIT_OK, EXIT_USAGE, EXIT_OUTPUT, EXIT_REFUSED = 0, 2, 3, 4

#: Path SEGMENTS that are never the code under test.  Matched segment-wise
#: (never as a substring) so a directory called `varnish` or a package called
#: `vendored_thing` is not swept up — the PHP twin's rule, for its reason.
#: `var/` and `vendor/` are named for cross-stack symmetry; the three Python
#: ones are where third-party bytes and build droppings actually live.
EXCLUDED_SEGMENTS: tuple[str, ...] = (
    "vendor", "var", "__pycache__", ".git", ".venv", "site-packages")

#: `# pragma: no cover`, as coverage.py's default `exclude_lines` spells it
#: (`#\s*(pragma|PRAGMA)[:\s]?\s*(no|NO)\s*(cover|COVER)`), reproduced rather
#: than referenced because this program must not import coverage.
_PRAGMA = re.compile(r"#\s*pragma[:\s]?\s*no\s*cover", re.IGNORECASE)

#: How many lines of a file count as its head, for the `@generated` banner.
#: A `@generated` in a docstring 900 lines down is a comment about something
#: else.
_HEAD_LINES = 40


def refuse(msg: str) -> "None":
    sys.stderr.write("REFUSED: " + msg + "\n")
    raise SystemExit(EXIT_REFUSED)


# ------------------------------------------------------------ source geometry
def line_starts(data: bytes) -> list[int]:
    """Byte offset of the start of each line; index 0 is line 1."""
    starts = [0]
    for i, byte in enumerate(data):
        if byte == 0x0A:
            starts.append(i + 1)
    return starts


def pos_to_linecol(starts: list[int], pos: int) -> tuple[int, int]:
    """(1-based line, 1-based BYTE column) for an absolute byte offset."""
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return (lo + 1, pos - starts[lo] + 1)


def linecol_to_pos(starts: list[int], line: int, col: int):
    if line < 1 or line > len(starts) or col < 1:
        return None
    return starts[line - 1] + (col - 1)


def _byte_cols(text: str) -> list[list[int]]:
    """Per line, the byte offset of each character position within the line.

    `tokenize` reports CHARACTER columns and every other coordinate here is a
    byte, so the conversion has to exist somewhere; doing it once per file is
    cheaper than re-encoding a prefix per token.  Entry `[line][c]` is the
    byte offset of character `c` within that line, and the list is one longer
    than the line so that an END column (which is one past the last character)
    converts too.
    """
    out: list[list[int]] = []
    for line in text.split("\n"):
        cols = [0]
        n = 0
        for ch in line:
            n += len(ch.encode("utf-8"))
            cols.append(n)
        out.append(cols)
    return out


# ------------------------------------------------------------- exclusions
def is_generated(text: str) -> bool:
    head = "\n".join(text.split("\n")[:_HEAD_LINES])
    return "@generated" in head or "GENERATED by" in head


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip())


def ignore_ranges(text: str) -> list[tuple[int, int]]:
    """Inclusive 1-based line ranges excluded by `# pragma: no cover`.

    coverage.py excludes the line the pragma is on, and — when that line
    OPENS A BLOCK — the whole block with it, which is the only reading under
    which `else:  # pragma: no cover` means anything.  Reproduced here by
    indentation, because the alternative (an AST lookup) cannot see an `else`
    or an `elif`: neither is a node of its own, so a pragma on one of them
    would silently exclude nothing and its body's mutants would enter the
    denominator as declared-untestable-but-counted.
    """
    lines = text.split("\n")
    ranges: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        if not _PRAGMA.search(line):
            continue
        start = i + 1
        end = start
        stripped = line.split("#")[0].rstrip()
        if stripped.endswith(":"):
            # A clause header: everything indented under it belongs to it.
            indent = _indent_of(line)
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if nxt.strip() and _indent_of(nxt) <= indent:
                    break
                if nxt.strip():
                    end = j + 1
                j += 1
        ranges.append((start, end))
    return ranges


def in_ignored(ranges: list[tuple[int, int]], line: int) -> bool:
    return any(a <= line <= b for a, b in ranges)


def is_excluded_path(relpath: str) -> bool:
    return any(seg in EXCLUDED_SEGMENTS
               for seg in relpath.replace(os.sep, "/").split("/"))


# --------------------------------------------------------- operator tables
#: `<` and `>` appear in TWO tables on purpose: `a < b` yields both a
#: `ConditionalBoundary` (`<=`) and a `NegateConditional` (`>=`) at the same
#: byte position.  They are different mutants — an off-by-one guard kills the
#: first and not always the second — which is why (file, line, col) alone is
#: not a mutant identity and the record carries the operator.
_BOUNDARY = {
    ast.Lt: ("<", "<="),
    ast.LtE: ("<=", "<"),
    ast.Gt: (">", ">="),
    ast.GtE: (">=", ">"),
}

_NEGATE_SYMBOL = {
    ast.Eq: ("==", "!="),
    ast.NotEq: ("!=", "=="),
    ast.Lt: ("<", ">="),
    ast.GtE: (">=", "<"),
    ast.Gt: (">", "<="),
    ast.LtE: ("<=", ">"),
}

#: The two comparison operators Python spells with WORDS.  The value is the
#: sequence of tokens that make up the operator (so that the region covers
#: `is  not` however it is spaced) and its replacement text.
_NEGATE_WORD = {
    ast.Is: (("is",), "is not"),
    ast.IsNot: (("is", "not"), "is"),
    ast.In: (("in",), "not in"),
    ast.NotIn: (("not", "in"), "in"),
}

_ARITHMETIC = {
    ast.Add: ("+", "-"),
    ast.Sub: ("-", "+"),
    ast.Mult: ("*", "/"),
    ast.Div: ("/", "*"),
    ast.Mod: ("%", "*"),
}

_INCREMENT = {
    ast.Add: ("+=", "-="),
    ast.Sub: ("-=", "+="),
}

_LOGICAL = {
    ast.And: ("and", "or"),
    ast.Or: ("or", "and"),
}


# ------------------------------------------------------------- enumeration
class _Token:
    __slots__ = ("text", "start", "end")

    def __init__(self, text: str, start: int, end: int) -> None:
        self.text = text
        self.start = start          # absolute byte offset, inclusive
        self.end = end              # absolute byte offset, EXCLUSIVE


def tokens_of(data: bytes, text: str, starts: list[int]) -> list[_Token]:
    """Every NAME and OP token, with absolute byte positions.

    Only those two kinds: an operator is one or the other, and a `+` inside a
    comment or a string literal is a COMMENT/STRING token, so it can never be
    mistaken for one.  That is the whole reason this goes through `tokenize`
    instead of scanning the bytes between two operands.
    """
    cols = _byte_cols(text)
    out: list[_Token] = []
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type not in (tokenize.NAME, tokenize.OP):
            continue
        (srow, scol), (erow, ecol) = tok.start, tok.end
        if srow - 1 >= len(cols) or erow - 1 >= len(cols):
            continue
        out.append(_Token(tok.string,
                          starts[srow - 1] + cols[srow - 1][scol],
                          starts[erow - 1] + cols[erow - 1][ecol]))
    return out


def _find_sequence(tokens: list[_Token], token_starts: list[int],
                   lo: int, hi: int, words: tuple[str, ...]):
    """First occurrence of `words` (in order) inside the byte window [lo, hi).

    Returns `(start, end_inclusive)` or None.  The window is always the gap
    BETWEEN two operand nodes, so the first hit is the operator token: a
    `BinOp` node spans left..right and carries no position for the operator
    between them, and neither does `ast.Compare`.

    `words` are CONSECUTIVE in the NAME/OP stream, which is what lets `is not`
    and `not in` be found as one region: whitespace, line breaks inside
    brackets and comments are none of them NAME or OP, so nothing can come
    between the two halves of a two-word operator.
    """
    import bisect
    i = bisect.bisect_left(token_starts, lo)
    n = len(tokens)
    while i < n and tokens[i].end <= hi:
        if tokens[i].text == words[0]:
            j = i
            ok = True
            for want in words[1:]:
                j += 1
                if j >= n or tokens[j].end > hi or tokens[j].text != want:
                    ok = False
                    break
            if ok:
                return (tokens[i].start, tokens[j].end - 1)
        i += 1
    return None


def enumerate_file(relpath: str, data: bytes, text: str, *,
                   operator_profile: str = "v2") -> list[dict]:
    """Every mutant in one file's bytes, in canonical order.

    Raises `SyntaxError`/`ValueError` to the caller, which records the file as
    an error rather than dropping it: a file that stops parsing after a
    refactor would otherwise remove its mutants from the population and move
    the recall denominator without anything saying so.
    """
    if operator_profile not in {"v1", "v2"}:
        raise ValueError(
            f"unknown operator profile {operator_profile!r}; expected v1 or v2")
    tree = ast.parse(text, filename=relpath)
    starts = line_starts(data)
    tokens = tokens_of(data, text, starts)
    token_starts = [t.start for t in tokens]
    ignored = ignore_ranges(text)
    out: list[dict] = []

    def node_start(node) -> int:
        return starts[node.lineno - 1] + node.col_offset

    def node_end(node) -> int:
        """EXCLUSIVE byte offset one past the node's last byte."""
        return starts[node.end_lineno - 1] + node.end_col_offset

    def emit(operator: str, start: int, end: int, mutated: str, *,
             honour_pragma: bool = True) -> None:
        sl, sc = pos_to_linecol(starts, start)
        if honour_pragma and in_ignored(ignored, sl):
            return
        el, ec = pos_to_linecol(starts, end)
        original = data[start:end + 1].decode("utf-8")
        if original == mutated:
            return                              # identity is not a mutant
        out.append({"file": relpath,
                    "start_line": sl, "start_col": sc,
                    "end_line": el, "end_col": ec,
                    "operator": operator,
                    "original": original, "mutated": mutated,
                    "_pos": start, "_end": end})

    def operator_region(left, right, words: tuple[str, ...], what: str):
        hit = _find_sequence(tokens, token_starts, node_end(left),
                             node_start(right), words)
        if hit is None:
            # Unreachable for well-formed source: the parser produced this
            # node, so the token is between its operands.  Raising rather than
            # skipping keeps a tokenizer change that splits operators
            # differently from silently shrinking the population.
            raise ValueError(
                f"{relpath}:{getattr(left, 'lineno', '?')}: {what} token "
                f"{' '.join(words)!r} not found between operands")
        return hit

    def walk(node) -> None:
        line = getattr(node, "lineno", None)
        if line is not None and in_ignored(ignored, line):
            # Prune the whole subtree, the way the PHP twin prunes under a
            # `@codeCoverageIgnore` docblock: a declared-untestable block's
            # inner expressions are declared untestable too.
            return

        if isinstance(node, ast.Compare):
            operands = [node.left] + list(node.comparators)
            for i, op in enumerate(node.ops):
                left, right = operands[i], operands[i + 1]
                kind = type(op)
                if kind in _BOUNDARY:
                    tok, repl = _BOUNDARY[kind]
                    s, e = operator_region(left, right, (tok,),
                                           "ConditionalBoundary")
                    emit("ConditionalBoundary", s, e, repl)
                if kind in _NEGATE_SYMBOL:
                    tok, repl = _NEGATE_SYMBOL[kind]
                    s, e = operator_region(left, right, (tok,),
                                           "NegateConditional")
                    emit("NegateConditional", s, e, repl)
                elif kind in _NEGATE_WORD:
                    words, repl = _NEGATE_WORD[kind]
                    s, e = operator_region(left, right, words,
                                           "NegateConditional")
                    emit("NegateConditional", s, e, repl)
        elif isinstance(node, ast.BinOp) and type(node.op) in _ARITHMETIC:
            tok, repl = _ARITHMETIC[type(node.op)]
            s, e = operator_region(node.left, node.right, (tok,),
                                   "ArithmeticOperator")
            emit("ArithmeticOperator", s, e, repl)
        elif isinstance(node, ast.AugAssign) and type(node.op) in _INCREMENT \
                and _is_numeric_literal(node.value):
            tok, repl = _INCREMENT[type(node.op)]
            s, e = operator_region(node.target, node.value, (tok,), "Increment")
            emit("Increment", s, e, repl)
        elif isinstance(node, ast.Constant) and node.value is True:
            emit("TrueValue", node_start(node), node_end(node) - 1, "False")
        elif isinstance(node, ast.Constant) and node.value is False:
            emit("FalseValue", node_start(node), node_end(node) - 1, "True")
        elif isinstance(node, ast.Return):
            value = node.value
            already_none = isinstance(value, ast.Constant) and value.value is None
            if value is not None and not already_none:
                emit("ReturnValue", node_start(node), node_end(node) - 1,
                     "return None")
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            emit("MethodCallRemoval", node_start(node), node_end(node) - 1,
                 "pass")

        for child in ast.iter_child_nodes(node):
            walk(child)

    walk(tree)

    # The three appended families are a production-AST profile.  They do not
    # inherit coverage.py pragmas as mutation ignores; see the module header.
    # Keeping this as a separate traversal also makes it mechanically clear
    # that no shared-v1 descriptor or suppression rule moved for v2.
    def walk_v2(node) -> None:
        if isinstance(node, ast.BoolOp) and type(node.op) in _LOGICAL:
            tok, repl = _LOGICAL[type(node.op)]
            for left, right in zip(node.values, node.values[1:]):
                s, e = operator_region(left, right, (tok,),
                                       "LogicalConnector")
                emit("LogicalConnector", s, e, repl, honour_pragma=False)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            hit = _find_sequence(tokens, token_starts, node_start(node),
                                 node_start(node.operand), ("not",))
            if hit is None:
                raise ValueError(
                    f"{relpath}:{node.lineno}: RemoveNegation token 'not' "
                    "not found before operand")
            emit("RemoveNegation", hit[0], hit[1], "", honour_pragma=False)
        elif isinstance(node, ast.Constant) \
                and isinstance(node.value, int) \
                and not isinstance(node.value, bool):
            emit("ConstantReplacement", node_start(node), node_end(node) - 1,
                 str(node.value + 1), honour_pragma=False)
        for child in ast.iter_child_nodes(node):
            walk_v2(child)

    if operator_profile == "v2":
        walk_v2(tree)

    # Canonical order, independent of the walk above: byte position, then
    # operator name for the several mutants a single token yields.
    out.sort(key=lambda m: (m["_pos"], m["_end"], m["operator"]))
    for m in out:
        del m["_pos"]
        del m["_end"]
    return out


def _is_numeric_literal(node) -> bool:
    """A plain `int`/`float` constant — never a bool, which `isinstance` calls
    an int and which `x += True` would then enumerate as an Increment."""
    return (isinstance(node, ast.Constant)
            and not isinstance(node.value, bool)
            and isinstance(node.value, (int, float)))


# ------------------------------------------------------------- file handling
def read_source(abspath: str) -> tuple[bytes, str, "str | None"]:
    """`(bytes, text, error)` — every rejection RECORDED, never dropped."""
    try:
        with open(abspath, "rb") as fh:
            data = fh.read()
    except OSError as e:
        return (b"", "", f"cannot read file: {e}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        # `original` is raw source and the manifest is UTF-8 JSON, so one
        # Latin-1 literal anywhere in the tree would otherwise abort the whole
        # enumeration with no clue which file did it.
        return (data, "", "file is not valid UTF-8; its source bytes cannot "
                          "be carried in a UTF-8 manifest")
    if re.search(r"\r(?!\n)", text):
        return (data, text,
                "file contains a bare CR; `tokenize` treats it as text and "
                "`compile` treats it as a line break, so the two would number "
                "this file's lines differently")
    return (data, text, None)


def compile_valid_mutants(relpath: str, data: bytes,
                          mutants: list[dict]) -> tuple[list[dict], int]:
    """Return ``(valid, n_invalid)`` after compiling every candidate.

    Enumeration proves only that the *original* file parses.  A replacement
    can still make the candidate invalid (especially once deletion operators
    exist), and such a row would otherwise be killed by the interpreter
    rather than by a test.  Each splice starts from the same original bytes;
    candidates are never composed with one another.
    """
    starts = line_starts(data)
    valid: list[dict] = []
    n_invalid = 0
    for mutant in mutants:
        offset = linecol_to_pos(
            starts, mutant["start_line"], mutant["start_col"])
        original = mutant["original"].encode("utf-8")
        if offset is None or data[offset:offset + len(original)] != original:
            # This is an enumerator integrity defect, not an invalid mutant.
            # Counting it would hide a bad source span as ordinary filtering.
            raise ValueError(
                f"{relpath}:{mutant['start_line']}:{mutant['start_col']}: "
                "enumerated original bytes do not match the source")
        candidate = (data[:offset] + mutant["mutated"].encode("utf-8")
                     + data[offset + len(original):])
        try:
            compile(candidate, relpath, "exec")
        except (SyntaxError, ValueError):
            n_invalid += 1
            continue
        valid.append(mutant)
    return valid, n_invalid


def process_file(relpath: str, abspath: str, *, validate_candidates: bool = True,
                 operator_profile: str = "v2"
                 ) -> tuple[list, int, "str | None", bool]:
    """``(mutants, n_invalid, error, skipped)`` for one source file."""
    data, text, err = read_source(abspath)
    if err is not None:
        return ([], 0, err, False)
    if is_generated(text):
        return ([], 0, None, True)
    try:
        mutants = enumerate_file(
            relpath, data, text, operator_profile=operator_profile)
        if validate_candidates:
            mutants, n_invalid = compile_valid_mutants(
                relpath, data, mutants)
            return (mutants, n_invalid, None, False)
        return (mutants, 0, None, False)
    except SyntaxError as e:
        return ([], 0, f"SyntaxError: {e}", False)
    except ValueError as e:
        return ([], 0, f"ValueError: {e}", False)
    except RecursionError as e:
        return ([], 0, f"RecursionError: {e}", False)


def collect_files(root: str, rel: str, errors: dict) -> list[str]:
    """Every `.py` file under `root/rel`, sorted."""
    abspath = os.path.join(root, rel.strip("/"))
    if os.path.isfile(abspath):
        if not abspath.lower().endswith(".py"):
            # A directory `--path` is filtered to *.py; a file `--path` was
            # not, so `--path pyproject.toml` would be parsed as Python,
            # produce a SyntaxError and still be counted.  Refusing it keeps
            # `files` meaning what the envelope says it means.
            errors[rel] = "not a .py file"
            return []
        return [abspath]
    if not os.path.isdir(abspath):
        errors[rel] = "not found"
        return []
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(abspath):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in EXCLUDED_SEGMENTS)
        for name in sorted(filenames):
            if name.lower().endswith(".py"):
                found.append(os.path.join(dirpath, name))
    found.sort()                     # see the determinism note in the header
    return found


def parser_version() -> str:
    """WHICH parser decided these spans.

    The PHP twin reads `nikic/php-parser` out of the tree's own lock file
    because the parser is a dependency there.  Python's parser is the
    interpreter, so the interpreter is what gets named — and it is the
    interpreter running THIS program, which is why enumeration happens inside
    the same image the applier runs in.
    """
    return f"{platform.python_implementation().lower()} " \
           f"{platform.python_version()}"


# --------------------------------------------------------------- the modes
def _mode_apply(opts, root: str) -> int:
    for req in ("start_line", "start_col", "operator", "original", "mutated",
                "out"):
        if getattr(opts, req) is None:
            sys.stderr.write("apply mode needs --"
                             + req.replace("_", "-") + "\n")
            return EXIT_USAGE
    if opts.path:
        sys.stderr.write("--path is meaningless in apply mode\n")
        return EXIT_USAGE

    rel = opts.apply_file.lstrip("/")
    if is_excluded_path(rel):
        refuse(f"{rel} is under an excluded path segment; no mutant of it is "
               f"in any manifest this program produced")
    abspath = os.path.join(root, rel)
    if not os.path.isfile(abspath):
        refuse(f"apply target does not exist: {rel}")

    data, _text, err = read_source(abspath)
    if err is not None:
        refuse(f"{rel}: {err}")
    # The one-time population build compiles every candidate.  Apply mode
    # rechecks only the requested row below; recompiling every other mutant in
    # this file for every campaign pair would turn the one-time gate into the
    # dominant per-mutant cost.
    mutants, _n_invalid, err, skipped = process_file(
        rel, abspath, validate_candidates=False,
        operator_profile=opts.operator_profile)
    if err is not None:
        refuse(f"{rel} does not enumerate now ({err}); it did when the "
               f"manifest was built")
    if skipped:
        refuse(f"{rel} is excluded as generated; no mutant of it is in the "
               f"manifest")

    # The whole point of one program with two modes: the requested record must
    # still be produced by the enumerator, field for field.
    match = None
    for m in mutants:
        if (m["start_line"] == opts.start_line
                and m["start_col"] == opts.start_col
                and m["operator"] == opts.operator
                and m["original"] == opts.original
                and m["mutated"] == opts.mutated):
            match = m
            break
    if match is None:
        # Deliberately does not guess which side is wrong: either the file
        # moved under the manifest, or the caller invented a record.  Both are
        # "do not score this run", and a message that picked one would be a
        # guess printed as a fact.
        refuse(f"enumerating {rel} now yields no mutant {opts.operator} at "
               f"{opts.start_line}:{opts.start_col} with this "
               f"original/mutated text -- the file has changed since the "
               f"manifest was built, or the record is not from it")
    valid_match, _invalid_match = compile_valid_mutants(rel, data, [match])
    if not valid_match:
        refuse(f"the requested mutant no longer compiles in {rel}; an "
               "invalid candidate cannot belong to a manifest")

    starts = line_starts(data)
    off = linecol_to_pos(starts, match["start_line"], match["start_col"])
    if off is None:
        refuse(f"position {match['start_line']}:{match['start_col']} is "
               f"outside {rel}")
    original = opts.original.encode("utf-8")
    # Belt and braces over the enumerator agreement above: compare the bytes
    # themselves, because that is the invariant the score depends on.
    if data[off:off + len(original)] != original:
        refuse(f"source at {rel}:{match['start_line']}:{match['start_col']} "
               f"is not byte-identical to --original")

    mutated = data[:off] + opts.mutated.encode("utf-8") \
        + data[off + len(original):]
    out_abs = _resolve(root, opts.out)
    directory = os.path.dirname(out_abs)
    if directory and not os.path.isdir(directory):
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as e:
            sys.stderr.write(f"cannot create output directory {directory}: "
                             f"{e}\n")
            return EXIT_OUTPUT
    try:
        with open(out_abs, "wb") as fh:
            fh.write(mutated)
    except OSError as e:
        sys.stderr.write(f"cannot write {out_abs}: {e}\n")
        return EXIT_OUTPUT
    sys.stderr.write(
        f"applied {opts.operator} at {rel}:{match['start_line']}:"
        f"{match['start_col']} ({len(data)} -> {len(mutated)} bytes) "
        f"-> {out_abs}\n")
    return EXIT_OK


def _mode_enumerate(opts, root: str) -> int:
    errors: dict = {}
    mutants: list[dict] = []
    n_files = 0
    n_invalid = 0
    seen: set = set()

    for rel in opts.path:
        for abspath in collect_files(root, rel, errors):
            relpath = os.path.relpath(abspath, root).replace(os.sep, "/")
            if is_excluded_path(relpath):
                continue
            # Two overlapping --path arguments must not double-count a file:
            # the manifest would then carry the same mutant twice and every
            # rate computed from it would be wrong in a way no digest catches.
            if relpath in seen:
                continue
            seen.add(relpath)
            file_mutants, file_invalid, err, skipped = process_file(
                relpath, abspath, operator_profile=opts.operator_profile)
            if err is not None:
                errors[relpath] = err
                continue
            if skipped:
                continue
            n_files += 1
            n_invalid += file_invalid
            mutants.extend(file_mutants)

    # Files were visited in sorted order per --path, but --path arguments are
    # taken in the order given, so a caller that lists paths differently would
    # otherwise get a different document.
    mutants.sort(key=lambda m: (m["file"], m["start_line"], m["start_col"],
                                m["end_line"], m["end_col"], m["operator"]))
    doc = {
        "engine": ENGINE,
        "engine_version": ENGINE_VERSION,
        "parser": parser_version(),
        "files": n_files,
        "errors": dict(sorted(errors.items())),
        "mutants": mutants,
    }
    # Omit zero so validity metadata has one canonical representation.  A v1
    # manifest is reconstructed from shared rows under OPERATORS_V1; this
    # v2-default envelope itself is not described as historical bytes.
    if n_invalid:
        doc["n_invalid"] = n_invalid
    if opts.record_enumerator_rev:
        doc["enumerator_rev"] = ENUMERATOR_REV
    payload = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False)
    if opts.out:
        out_abs = _resolve(root, opts.out)
        directory = os.path.dirname(out_abs)
        if directory and not os.path.isdir(directory):
            try:
                os.makedirs(directory, exist_ok=True)
            except OSError as e:
                sys.stderr.write(f"cannot create output directory "
                                 f"{directory}: {e}\n")
                return EXIT_OUTPUT
        try:
            with open(out_abs, "w", encoding="utf-8") as fh:
                fh.write(payload)
        except OSError as e:
            sys.stderr.write(f"cannot write {out_abs}: {e}\n")
            return EXIT_OUTPUT
        sys.stderr.write(f"enumerated {len(mutants)} mutants over {n_files} "
                         f"files, {len(errors)} errors -> {out_abs}\n")
    else:
        sys.stdout.write(payload)
    return EXIT_OK


def _resolve(root: str, path: str) -> str:
    """`--out` and `--apply-file` are root-relative; absolute still works."""
    return path if path.startswith("/") else os.path.join(root, path.lstrip("/"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(add_help=True, description=(
        "enumerate or apply mutants for the behave/Python stack"))
    ap.add_argument("--root", default=None)
    ap.add_argument("--path", action="append", default=[])
    ap.add_argument("--out", default=None)
    ap.add_argument("--apply-file", dest="apply_file", default=None)
    ap.add_argument("--start-line", dest="start_line", type=int, default=None)
    ap.add_argument("--start-col", dest="start_col", type=int, default=None)
    ap.add_argument("--operator", default=None)
    ap.add_argument("--original", default=None)
    ap.add_argument("--mutated", default=None)
    ap.add_argument(
        "--operator-profile", choices=("v1", "v2"), default="v2",
        help="emit the immutable shared-eight v1 profile or the v2 default")
    ap.add_argument("--record-enumerator-rev", action="store_true",
                    help="record this engine's revision in the envelope; "
                         "legacy/v1 callers omit it for byte compatibility")
    opts = ap.parse_args(argv)

    if opts.root is None:
        sys.stderr.write(
            "usage: mutate.py --root DIR --path REL [--path REL ...] "
            "[--out FILE]\n"
            "       mutate.py --root DIR --apply-file REL --start-line N "
            "--start-col N \\\n"
            "           --operator OP --original TEXT --mutated TEXT "
            "--out REL\n")
        return EXIT_USAGE
    root = opts.root.rstrip("/") or "/"
    if not os.path.isdir(root):
        sys.stderr.write(f"root is not a directory: {root}\n")
        return EXIT_USAGE

    if opts.apply_file is not None:
        return _mode_apply(opts, root)
    if not opts.path:
        sys.stderr.write("usage: mutate.py --root DIR --path REL "
                         "[--path REL ...] [--out FILE]\n")
        return EXIT_USAGE
    return _mode_enumerate(opts, root)


# ----------------------------------------------------------------- selftest
_FIXTURE = '''\
"""A fixture exercising every operator, once each at least."""


def boundary(a, b):
    if a < b:
        return 1
    if a <= b:
        return 2
    if a > b:
        return 3
    if a >= b:
        return 4
    return 0


def negate(a, b, xs):
    if a == b:
        pass
    if a != b:
        pass
    if a is b:
        pass
    if a is not b:
        pass
    if a in xs:
        pass
    if a not in xs:
        pass


def arithmetic(a, b):
    return a + b - a * b / (a % b)


def increment(n):
    total = 0
    total += 2
    total -= 3
    total += n
    total += True
    return total


def booleans():
    flag = True
    other = False
    if not flag:
        return 9
    return flag or other


def returns(a):
    if a:
        return
    if a is None:
        return None
    return a


def calls(logger, a):
    logger.info("x")
    print(a)
    value = logger.get()
    return value


def ignored(a):  # pragma: no cover
    if a < 1:
        return a + 1
    return 0


def partly(a):
    if a:
        return a * 2
    else:  # pragma: no cover
        return a / 2
'''


def selftest() -> int:                                    # noqa: C901
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    data = _FIXTURE.encode("utf-8")
    mutants = enumerate_file("fixture.py", data, _FIXTURE)
    by_op: dict = {}
    for m in mutants:
        by_op.setdefault(m["operator"], []).append(m)

    from ..mutation import OPERATORS, OPERATORS_V1

    check("the operator NAMES are r2t.mutation's, mirrored exactly",
          set(by_op) == set(OPERATORS),
          f"missing {sorted(set(OPERATORS) - set(by_op))}, "
          f"extra {sorted(set(by_op) - set(OPERATORS))}")
    check("the engine names itself, and not the PHP engine",
          ENGINE == "r2t-mutate-py" and ENGINE_VERSION == "1.0", ENGINE)

    def texts(op):
        return [(m["original"], m["mutated"]) for m in by_op.get(op, [])]

    check("ConditionalBoundary moves the boundary and nothing else",
          sorted(texts("ConditionalBoundary"))
          == sorted([("<", "<="), ("<=", "<"), (">", ">="), (">=", ">")]),
          str(sorted(texts("ConditionalBoundary"))))
    check("NegateConditional negates the six symbolic comparisons",
          {("==", "!="), ("!=", "=="), ("<", ">="), ("<=", ">"),
           (">", "<="), (">=", "<")} <= set(texts("NegateConditional")),
          str(sorted(set(texts("NegateConditional")))))
    check("...and the two Python spells with WORDS, both ways",
          {("is", "is not"), ("is not", "is"),
           ("in", "not in"), ("not in", "in")}
          <= set(texts("NegateConditional")),
          str(sorted(set(texts("NegateConditional")))))
    check("ArithmeticOperator covers + - * / % and nothing else",
          set(texts("ArithmeticOperator"))
          == {("+", "-"), ("-", "+"), ("*", "/"), ("/", "*"), ("%", "*")},
          str(sorted(set(texts("ArithmeticOperator")))))
    check("Increment is the compound assignment by a NUMERIC LITERAL, both "
          "directions", sorted(texts("Increment"))
          == sorted([("+=", "-="), ("-=", "+=")]),
          str(sorted(texts("Increment"))))
    # `total += n` and `total += True` are the two ways the operator would
    # over-reach: a variable is not a literal, and `True` is an `int` to
    # `isinstance` but is not a number anybody increments by.
    check("...and neither `+= n` nor `+= True` is one of them",
          len(by_op["Increment"]) == 2, str(texts("Increment")))
    check("TrueValue applies where a `True` literal IS, and writes `False` "
          "(the PHP twin's direction)",
          set(texts("TrueValue")) == {("True", "False")},
          str(texts("TrueValue")))
    check("FalseValue is its mirror",
          set(texts("FalseValue")) == {("False", "True")},
          str(texts("FalseValue")))
    check("ReturnValue rewrites a value-bearing return",
          all(m["mutated"] == "return None" for m in by_op["ReturnValue"]),
          str(texts("ReturnValue")[:3]))
    check("...and skips a bare `return` and a literal `return None`, which "
          "would be no-ops",
          not any(m["original"] in ("return", "return None")
                  for m in by_op["ReturnValue"]),
          str([m["original"] for m in by_op["ReturnValue"]]))
    check("MethodCallRemoval takes a call in STATEMENT position and leaves an "
          "assigned one alone",
          sorted(m["original"] for m in by_op["MethodCallRemoval"])
          == ['logger.info("x")', "print(a)"],
          str([m["original"] for m in by_op["MethodCallRemoval"]]))
    check("...and replaces it with `pass`, never with nothing (a braceless "
          "suite has exactly one statement slot)",
          all(m["mutated"] == "pass" for m in by_op["MethodCallRemoval"]))
    check("LogicalConnector replaces each source connector in both directions",
          set(texts("LogicalConnector")) == {("or", "and")},
          str(texts("LogicalConnector")))
    check("RemoveNegation deletes only a unary `not` token",
          texts("RemoveNegation") == [("not", "")],
          str(texts("RemoveNegation")))
    check("ConstantReplacement increments integer literal tokens and never "
          "treats bool as int",
          by_op["ConstantReplacement"]
          and all(int(m["mutated"]) == int(m["original"]) + 1
                  for m in by_op["ConstantReplacement"])
          and not any(m["original"] in {"True", "False"}
                      for m in by_op["ConstantReplacement"]),
          str(texts("ConstantReplacement")[:8]))

    # -- positions ---------------------------------------------------------
    starts = line_starts(data)
    lines = _FIXTURE.split("\n")

    def at(m):
        off = linecol_to_pos(starts, m["start_line"], m["start_col"])
        raw = m["original"].encode("utf-8")
        return data[off:off + len(raw)] == raw

    bad_pos = [m for m in mutants if not at(m)]
    check("every record's (line, col) points at its own `original` bytes -- "
          "the one property the applier's byte splice depends on",
          not bad_pos, str(bad_pos[:2]))
    check("columns are 1-based (col_offset + 1), so column 0 never appears",
          all(m["start_col"] >= 1 and m["start_line"] >= 1 for m in mutants))
    check("the end position is INCLUSIVE, so a two-byte operator spans two "
          "columns",
          all(m["end_col"] - m["start_col"] + 1 == len(m["original"])
              for m in mutants
              if m["start_line"] == m["end_line"] and "\n" not in m["original"]))

    # -- exclusions --------------------------------------------------------
    ignored_line = next(i + 1 for i, ln in enumerate(lines)
                        if ln.startswith("def ignored"))
    check("a `# pragma: no cover` on a def excludes the WHOLE function, not "
          "just its own line, for every shared-v1 operator",
          not any(ignored_line <= m["start_line"] <= ignored_line + 3
                  and m["operator"] in OPERATORS_V1 for m in mutants),
          str([m["start_line"] for m in mutants
               if ignored_line <= m["start_line"] <= ignored_line + 3]))
    check("the appended v2 families treat coverage pragmas as coverage policy, "
          "not mutation-ignore directives",
          any(ignored_line <= m["start_line"] <= ignored_line + 3
              and m["operator"] == "ConstantReplacement" for m in mutants))
    else_line = next(i + 1 for i, ln in enumerate(lines)
                     if ln.strip().startswith("else:"))
    check("...and on a bare `else:` too -- the clause that has no AST node of "
          "its own, so an AST-only implementation would silently exclude "
          "nothing",
          not any(m["start_line"] in (else_line, else_line + 1)
                  and m["operator"] in OPERATORS_V1 for m in mutants),
          str([m["start_line"] for m in mutants
               if m["start_line"] >= else_line]))
    check("the line ABOVE that else is still enumerated, so the exclusion is "
          "not simply swallowing the tail of the file",
          any(m["start_line"] == else_line - 1 for m in mutants),
          str(sorted({m["start_line"] for m in mutants})[-4:]))

    # -- determinism -------------------------------------------------------
    again = enumerate_file("fixture.py", data, _FIXTURE)
    check("enumeration is a pure function of the bytes", again == mutants)
    check("the canonical order is (start, end, operator)",
          [(m["start_line"], m["start_col"], m["operator"]) for m in mutants]
          == sorted((m["start_line"], m["start_col"], m["operator"])
                    for m in mutants))

    # -- the two operators at one position ---------------------------------
    lt = [m for m in mutants if m["original"] == "<" and m["start_line"] ==
          next(i + 1 for i, ln in enumerate(lines) if ln.strip() == "if a < b:")]
    check("one `<` yields TWO mutants at ONE position, which is why the "
          "operator is part of a mutant's identity",
          sorted(m["operator"] for m in lt)
          == ["ConditionalBoundary", "NegateConditional"]
          and len({(m["start_line"], m["start_col"]) for m in lt}) == 1,
          str(lt))

    # -- a comment that looks like an operator -----------------------------
    tricky = 'x = 1  # a + b < c\ny = "a + b"\nz = 2 + 3\n'
    tm = enumerate_file("t.py", tricky.encode(), tricky)
    check("an operator inside a comment or a string is not a mutant -- the "
          "token stream says so, a byte scan would not",
          [(m["start_line"], m["original"])
           for m in tm if m["operator"] == "ArithmeticOperator"]
          == [(3, "+")],
          str([(m["start_line"], m["operator"], m["original"]) for m in tm]))

    # -- v2 operator edge spellings ---------------------------------------
    v2_spelling = "def f(a, b, c):\n    return (a and b and c) or not a\n"
    vm = enumerate_file("v2.py", v2_spelling.encode(), v2_spelling)
    check("a flattened BoolOp emits one LogicalConnector per token",
          [(m["original"], m["mutated"])
           for m in vm if m["operator"] == "LogicalConnector"]
          == [("and", "or"), ("and", "or"), ("or", "and")], str(vm))
    check("the unary not in a compound expression has an exact byte span",
          [(m["original"], m["mutated"])
           for m in vm if m["operator"] == "RemoveNegation"]
          == [("not", "")], str(vm))
    constants = "x = 0x10\ny = -1\nz = True\n"
    cm = enumerate_file("c.py", constants.encode(), constants)
    check("integer spellings canonicalise to decimal n+1 and a negative "
          "literal mutates its unsigned AST token",
          [(m["original"], m["mutated"])
           for m in cm if m["operator"] == "ConstantReplacement"]
          == [("0x10", "17"), ("1", "2")], str(cm))

    # -- odd spelling of `is not` ------------------------------------------
    spaced = "def f(a, b):\n    return a is  not b\n"
    sm = enumerate_file("s.py", spaced.encode(), spaced)
    isnot = [m for m in sm if m["operator"] == "NegateConditional"]
    check("`is  not` with two spaces is ONE region whose `original` is the "
          "source bytes, so the applier's byte compare matches",
          [m["original"] for m in isnot] == ["is  not"], str(isnot))

    # -- non-ASCII ---------------------------------------------------------
    wide = 'S = "ééé"\n\n\ndef f(a, b):\n    return a + b\n'
    wm = enumerate_file("w.py", wide.encode("utf-8"), wide)
    plus = [m for m in wm if m["operator"] == "ArithmeticOperator"]
    check("a non-ASCII line above does not shift a later record's byte column",
          len(plus) == 1 and wide.split("\n")[plus[0]["start_line"] - 1]
          .encode("utf-8")[plus[0]["start_col"] - 1:plus[0]["start_col"]]
          == b"+", str(plus))

    # -- candidate compile validity ---------------------------------------
    probe = b"value = 1\n"
    probe_col = probe.index(b"1") + 1
    descriptor = {
        "file": "probe.py", "start_line": 1, "start_col": probe_col,
        "end_line": 1, "end_col": probe_col,
        "operator": "ConstantReplacement", "original": "1",
    }
    probe_mutants = [dict(descriptor, mutated="2"),
                     dict(descriptor, mutated="(")]
    probe_valid, probe_invalid = compile_valid_mutants(
        "probe.py", probe, probe_mutants)
    check("candidate compilation retains a valid splice and drops a "
          "syntax-breaking one",
          probe_valid == probe_mutants[:1] and probe_invalid == 1,
          f"valid={probe_valid}, invalid={probe_invalid}")

    # -- files that must be recorded, not dropped --------------------------
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "repo")
        os.makedirs(os.path.join(root, "src", "pkg"))
        good = os.path.join(root, "src", "pkg", "good.py")
        with open(good, "w", encoding="utf-8") as fh:
            fh.write(_FIXTURE)
        with open(os.path.join(root, "src", "pkg", "broken.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("def oops(:\n")
        with open(os.path.join(root, "src", "pkg", "gen.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("# @generated by a tool\nx = 1 + 2\n")
        with open(os.path.join(root, "src", "pkg", "latin.py"), "wb") as fh:
            fh.write(b'S = "\xe9"\nx = 1 + 2\n')
        os.makedirs(os.path.join(root, "src", "pkg", "__pycache__"))
        with open(os.path.join(root, "src", "pkg", "__pycache__", "c.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("x = 1 + 2\n")

        out = os.path.join(d, "raw.json")
        rc = main(["--root", root, "--path", "src", "--out", out])
        check("enumerating a tree exits 0", rc == 0, str(rc))
        with open(out, encoding="utf-8") as fh:
            doc = json.load(fh)
        check("the envelope names the engine, its version and the parser",
              doc["engine"] == ENGINE and doc["engine_version"] == ENGINE_VERSION
              and doc["parser"].startswith("cpython "), str(doc["parser"]))
        check("default envelopes omit zero invalid count and an unrequested "
              "revision (v1 reconstruction names OPERATORS_V1 separately)",
              "n_invalid" not in doc and "enumerator_rev" not in doc,
              str(sorted(doc)))
        v1_out = os.path.join(d, "raw-v1.json")
        v1_rc = main(["--root", root, "--path", "src",
                      "--operator-profile", "v1", "--out", v1_out])
        with open(v1_out, encoding="utf-8") as fh:
            v1_doc = json.load(fh)
        expected_v1_doc = dict(doc)
        expected_v1_doc["mutants"] = [
            m for m in doc["mutants"] if m["operator"] in OPERATORS_V1]
        check("the explicit v1 mode emits exactly the shared-eight projection "
              "with the historical envelope shape",
              v1_rc == 0 and v1_doc == expected_v1_doc
              and {m["operator"] for m in v1_doc["mutants"]}
              <= set(OPERATORS_V1),
              str(sorted({m["operator"] for m in v1_doc["mutants"]})))
        check("a file that does not parse is an ERROR, never an empty file",
              "src/pkg/broken.py" in doc["errors"]
              and "SyntaxError" in doc["errors"]["src/pkg/broken.py"],
              str(doc["errors"]))
        check("a non-UTF-8 file is an error too, rather than aborting the run",
              "src/pkg/latin.py" in doc["errors"]
              and "UTF-8" in doc["errors"]["src/pkg/latin.py"],
              str(doc["errors"]))
        check("a @generated file is SKIPPED, not errored, and contributes "
              "nothing",
              "src/pkg/gen.py" not in doc["errors"]
              and not any(m["file"] == "src/pkg/gen.py"
                          for m in doc["mutants"]))
        check("__pycache__ is not walked",
              not any("__pycache__" in m["file"] for m in doc["mutants"]))
        check("`files` counts the files actually enumerated",
              doc["files"] == 1, str(doc["files"]))
        rc2 = main(["--root", root, "--path", "src", "--out", out + "2"])
        with open(out + "2", encoding="utf-8") as fh:
            doc2 = json.load(fh)
        check("re-enumerating the same tree yields the same document",
              rc2 == 0 and doc2 == doc)
        revised = os.path.join(d, "revised.json")
        main(["--root", root, "--path", "src",
              "--record-enumerator-rev", "--out", revised])
        with open(revised, encoding="utf-8") as fh:
            revised_doc = json.load(fh)
        check("revision provenance is opt-in and does not change the rows",
              revised_doc.get("enumerator_rev") == ENUMERATOR_REV
              and revised_doc["mutants"] == doc["mutants"]
              and "n_invalid" not in revised_doc,
              str(revised_doc.get("enumerator_rev")))
        overlap = os.path.join(d, "overlap.json")
        main(["--root", root, "--path", "src", "--path", "src/pkg",
              "--out", overlap])
        with open(overlap, encoding="utf-8") as fh:
            doc3 = json.load(fh)
        check("two overlapping --path arguments do not double-count a file",
              doc3["mutants"] == doc["mutants"] and doc3["files"] == 1)
        toml = os.path.join(root, "pyproject.toml")
        with open(toml, "w", encoding="utf-8") as fh:
            fh.write("[project]\n")
        main(["--root", root, "--path", "pyproject.toml", "--out",
              os.path.join(d, "t.json")])
        with open(os.path.join(d, "t.json"), encoding="utf-8") as fh:
            doc4 = json.load(fh)
        check("a non-.py --path is an error, not a file counted as enumerated",
              doc4["errors"].get("pyproject.toml") == "not a .py file"
              and doc4["files"] == 0, str(doc4["errors"]))

        # -- APPLY: the round trip, and the three refusals -----------------
        target = next(m for m in doc["mutants"]
                      if m["operator"] == "ArithmeticOperator")
        with open(good, "rb") as fh:
            before = fh.read()
        argv = ["--root", root, "--apply-file", "src/pkg/good.py",
                "--start-line", str(target["start_line"]),
                "--start-col", str(target["start_col"]),
                "--operator", target["operator"],
                "--original", target["original"],
                "--mutated", target["mutated"],
                "--out", "src/pkg/good.py"]
        check("applying a real mutant exits 0", main(argv) == 0)
        with open(good, "rb") as fh:
            after = fh.read()
        want_off = linecol_to_pos(line_starts(before), target["start_line"],
                                  target["start_col"])
        want = (before[:want_off] + target["mutated"].encode("utf-8")
                + before[want_off + len(target["original"].encode()):])
        check("...and rewrites exactly the recorded region, byte for byte",
              after == want and after != before,
              f"{len(after)} vs {len(want)} bytes")
        def refuses(args) -> bool:
            try:
                main(args)
            except SystemExit as e:
                return e.code == EXIT_REFUSED
            return False

        # A REVERT IS A BYTE RESTORE, NOT AN INVERSE APPLY, and the difference
        # is not academic: `mutation_run.revert_mutant` holds the original
        # bytes and writes them back precisely because the inverse of a
        # mutant need not be a mutant.  `return <expr>` -> `return None` is
        # the case that proves it — the mutated statement already returns
        # None, so the enumerator skips it and the inverse record is one no
        # enumeration produces.  Both halves are checked, because a gate that
        # reverted by inverse-apply passed for `+`/`-` and failed for this.
        def inverse_of(m):
            return ["--root", root, "--apply-file", "src/pkg/good.py",
                    "--start-line", str(m["start_line"]),
                    "--start-col", str(m["start_col"]),
                    "--operator", m["operator"],
                    "--original", m["mutated"], "--mutated", m["original"],
                    "--out", "src/pkg/good.py"]

        rc_back = main(inverse_of(target))
        with open(good, "rb") as fh:
            restored = fh.read()
        check("for an operator whose inverse IS a mutant, applying the "
              "inverse restores the bytes exactly",
              rc_back == 0 and restored == before,
              f"rc={rc_back}, {len(restored)} vs {len(before)} bytes")
        check("applying the same mutant twice is REFUSED: after the first the "
              "file no longer enumerates it",
              main(argv) == 0 and refuses(argv))
        with open(good, "wb") as fh:                # what revert_mutant does
            fh.write(before)
        check("...and a file restored to its original bytes applies it again, "
              "which is what proves a revert put the tree back",
              main(argv) == 0)
        with open(good, "wb") as fh:
            fh.write(before)

        ret = next(m for m in doc["mutants"] if m["operator"] == "ReturnValue")
        ret_argv = ["--root", root, "--apply-file", "src/pkg/good.py",
                    "--start-line", str(ret["start_line"]),
                    "--start-col", str(ret["start_col"]),
                    "--operator", ret["operator"],
                    "--original", ret["original"], "--mutated", ret["mutated"],
                    "--out", "src/pkg/good.py"]
        check("a ReturnValue mutant applies", main(ret_argv) == 0)
        check("...but its INVERSE is refused, because `return None` is not a "
              "ReturnValue mutant -- so a revert can never be an apply",
              refuses(inverse_of(ret)))
        with open(good, "wb") as fh:
            fh.write(before)

        forged = list(argv)
        forged[forged.index("--original") + 1] = "@@"
        check("a FORGED mutant (an `original` no enumeration produced) is "
              "REFUSED", refuses(forged))
        moved = list(argv)
        moved[moved.index("--start-line") + 1] = "1"
        check("a mutant at a position this file does not have is REFUSED",
              refuses(moved))
        renamed = list(argv)
        renamed[renamed.index("--operator") + 1] = "TrueValue"
        check("the right bytes under the WRONG operator name are REFUSED -- "
              "the operator is part of a mutant's identity",
              refuses(renamed))
        gen = list(argv)
        gen[gen.index("--apply-file") + 1] = "src/pkg/gen.py"
        check("applying to a @generated file is REFUSED: no manifest contains "
              "a mutant of it", refuses(gen))
        vendored = list(argv)
        vendored[vendored.index("--apply-file") + 1] = "vendor/x/y.py"
        check("applying under an excluded path segment is REFUSED, on the "
              "same terms the enumerator prunes it",
              refuses(vendored))
        with open(good, "rb") as fh:
            check("every refusal left the file untouched", fh.read() == before)

        # A file edited under the manifest is the case the one-program rule
        # exists for.
        with open(good, "a", encoding="utf-8") as fh:
            fh.write("\n\ndef added(a):\n    return a + 1\n")
        shifted = list(argv)
        check("a mutant whose file changed since enumeration is still "
              "applicable when its own bytes did not move",
              main(shifted) == 0)
        with open(good, "w", encoding="utf-8") as fh:
            fh.write("x = 1\n")
        check("...and is REFUSED once those bytes are gone", refuses(argv))

    print("\n" + ("ALL PASS (py.mutate)" if ok else "FAILURES (py.mutate)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
