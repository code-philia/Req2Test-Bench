"""Assertion-stripped reference solutions for Python/behave.

This is the AST-backed twin of :mod:`r2t.toolkit.strip`.  Closure identities decide
which functions are Then-only; Python's own parser supplies exact source
spans, so decorators, imports, Given/When functions, helpers, comments and
formatting remain untouched while each selected function body becomes
``pass``.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os

from .strip import (StripRefused, definition_roles, load_closures,
                    then_definitions)


def _offsets(source: str) -> list[int]:
    """UTF-8 byte offsets, matching CPython AST column semantics."""
    starts = [0]
    for line in source.splitlines(keepends=True):
        starts.append(starts[-1] + len(line.encode("utf-8")))
    return starts


def _position(starts: list[int], lineno: int, col: int) -> int:
    return starts[lineno - 1] + col


def strip_python_source(source: str, functions: list[str]) -> str:
    """Replace exactly the selected function bodies with ``pass``."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise StripRefused(
            f"REFUSED: gold Python module does not parse: {exc}") from exc
    wanted = set(functions)
    found: dict[str, list[ast.AST]] = {name: [] for name in wanted}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name in wanted:
            found[node.name].append(node)
    bad = {name: len(nodes) for name, nodes in found.items()
           if len(nodes) != 1}
    if bad:
        raise StripRefused(
            f"REFUSED: expected exactly one Python function for each Then "
            f"definition; observed {bad}.")

    starts = _offsets(source)
    encoded = source.encode("utf-8")
    edits = []
    for name in sorted(wanted):
        node = found[name][0]
        if not node.body:
            raise StripRefused(
                f"REFUSED: Python function {name!r} has no body span.")
        first, last = node.body[0], node.body[-1]
        start = _position(starts, first.lineno, first.col_offset)
        end = _position(starts, last.end_lineno, last.end_col_offset)
        # ``start`` is already *after* the indentation on the first body
        # line, so the prefix retained in ``source[:start]`` supplies it.
        edits.append((start, end, "pass"))
    for start, end, replacement in sorted(edits, reverse=True):
        encoded = encoded[:start] + replacement.encode("utf-8") + encoded[end:]
    source = encoded.decode("utf-8")
    try:
        ast.parse(source)
    except SyntaxError as exc:                              # pragma: no cover
        raise StripRefused(
            f"REFUSED: assertion stripping produced invalid Python: {exc}") \
            from exc
    return source


def stripped_solution(gold_root: str, closure: dict, *,
                      source_texts: dict[str, str] | None = None) -> dict:
    """Return the adapter payload for one assertion-stripped gold closure."""
    selected = then_definitions(closure)
    by_file: dict[str, list[str]] = {}
    for rel, _module, function in selected:
        by_file.setdefault(rel, []).append(function)
    files = []
    for rel in closure.get("files") or []:
        if source_texts is not None:
            try:
                original = source_texts[rel]
            except KeyError as exc:
                raise StripRefused(
                    f"REFUSED: frozen gold closure omits {rel!r}") from exc
        else:
            path = os.path.join(gold_root, rel)
            try:
                with open(path, encoding="utf-8") as fh:
                    original = fh.read()
            except OSError as exc:
                raise StripRefused(
                    f"REFUSED: cannot read gold closure file {rel!r}: "
                    f"{exc}") from exc
        files.append({"file_path": rel,
                      "code": strip_python_source(
                          original, by_file.get(rel, []))})
    missing = sorted(set(by_file) - set(closure.get("files") or []))
    if missing:
        raise StripRefused(
            f"REFUSED: Then definitions name files outside the gold closure: "
            f"{missing}.")
    identities = [{"file": rel, "module": module, "function": function}
                  for rel, module, function in selected]
    return {
        "files": files,
        "metadata": {
            "source": "stripped_gold", "stripped_gold": True,
            "item_id": closure.get("item_id"),
            "n_then_definitions": len(selected),
            "then_definitions": identities,
            "definition_identity_sha256": hashlib.sha256(
                json.dumps(identities, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        },
    }


def make_strip_adapter(gold_root: str, closures_path: str):
    """Fixture adapter used to produce the stripped baseline and N=2 sweep."""
    from ..bench.adapters import Adapter
    closures = load_closures(closures_path)

    def run(task: dict) -> dict:
        item_id = task.get("item_id")
        closure = closures.get(item_id)
        if closure is None:
            return {"files": [], "metadata": {
                "adapter_error": f"no closure for {item_id}",
                "strip_refusal": True, "source": "stripped_gold",
                "stripped_gold": True, "item_id": item_id}}
        try:
            return stripped_solution(gold_root, closure)
        except StripRefused as exc:
            return {"files": [], "metadata": {
                "adapter_error": str(exc), "strip_refusal": True,
                "source": "stripped_gold", "stripped_gold": True,
                "item_id": item_id}}

    return Adapter("stripped-gold", run,
                   {"gold": gold_root, "closures": closures_path})


def selftest() -> int:
    import tempfile
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    source = """from behave import given, then

@given('setup')
def setup(context):
    context.value = 1

@then('check')
def check_value(context):
    actual = context.value
    assert actual == 1
"""
    stripped = strip_python_source(source, ["check_value"])
    check("Python Then body becomes pass and setup remains byte-present",
          "context.value = 1" in stripped and "assert actual" not in stripped
          and "def check_value(context):\n    pass" in stripped, stripped)
    unicode_source = """def check_value(context):
    actual = "é"
    assert actual == "é"
"""
    unicode_stripped = strip_python_source(unicode_source, ["check_value"])
    check("AST UTF-8 byte columns cannot truncate a non-ASCII Then body",
          unicode_stripped == "def check_value(context):\n    pass\n",
          unicode_stripped)
    closure = {"item_id": "i", "files": ["steps.py"], "di_fragment": {},
               "steps": [
                   {"keyword": "Given", "side": "removable",
                    "definition": {"file": "steps.py", "class": "steps",
                                   "method": "setup"}},
                   {"keyword": "Then", "side": "removable",
                    "definition": {"file": "steps.py", "class": "steps",
                                   "method": "check_value"}},
               ]}
    with tempfile.TemporaryDirectory() as root:
        with open(os.path.join(root, "steps.py"), "w", encoding="utf-8") as fh:
            fh.write(source)
        doc = stripped_solution(root, closure)
        check("behave solution carries every closure file and exact identity",
              [entry["file_path"] for entry in doc["files"]] == ["steps.py"]
              and doc["metadata"]["n_then_definitions"] == 1)
    roles = definition_roles(closure)
    check("effective closure roles, not decorator spelling, select the body",
          roles[("steps.py", "steps", "check_value")] == {"then"})
    print("\n" + ("ALL PASS (strip_py)" if ok else "FAILURES (strip_py)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
