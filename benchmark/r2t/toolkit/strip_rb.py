"""AST-backed assertion stripping for Cucumber-Ruby step blocks."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Optional

from .strip import StripRefused, load_closures, then_definitions
from .rbstep_index import analyze_sources


def _line_offsets(encoded: bytes) -> list[int]:
    # CRuby positions advance lines only at LF bytes. Python's splitlines also
    # treats lone CR and Unicode separators as line endings, which would move
    # every later native coordinate and can cut unrelated source bytes.
    return [0] + [offset + 1 for offset, byte in enumerate(encoded) if byte == 0x0A]


def _offset(starts: list[int], line: int, column: int) -> int:
    if line < 1 or line > len(starts):
        raise StripRefused("REFUSED: Ruby AST position is outside the source")
    return starts[line - 1] + column


def _definition_line(method: str) -> int:
    if not isinstance(method, str) or not method.startswith("step@"):
        raise StripRefused(f"REFUSED: unsupported Ruby definition identity {method!r}")
    try:
        line = int(method[5:])
    except ValueError as exc:
        raise StripRefused(f"REFUSED: malformed Ruby definition identity {method!r}") from exc
    if line < 1:
        raise StripRefused(f"REFUSED: malformed Ruby definition line {line}")
    return line


def strip_ruby_source(source: str, methods: list[str], *, path: str = "steps.rb") -> str:
    analysis = analyze_sources(sources={path: source})["files"][0]
    if analysis.get("error"):
        raise StripRefused(f"REFUSED: gold Ruby source does not parse: {analysis['error']}")
    if analysis.get("errors"):
        raise StripRefused(f"REFUSED: unsupported Ruby step syntax: {analysis['errors']}")
    by_line: dict[int, list[dict]] = {}
    for definition in analysis.get("definitions", []):
        by_line.setdefault(definition["line"], []).append(definition)
    encoded = source.encode("utf-8")
    starts = _line_offsets(encoded)
    edits = []
    for method in sorted(set(methods)):
        line = _definition_line(method)
        definitions = by_line.get(line, [])
        if len(definitions) != 1:
            raise StripRefused(
                f"REFUSED: expected exactly one top-level Ruby step block at line {line}; "
                f"observed {len(definitions)}")
        body = definitions[0]["body"]
        start = _offset(starts, body["start_line"], body["start_column"])
        end = _offset(starts, body["end_line"], body["end_column"])
        if not 0 <= start < end <= len(encoded):
            raise StripRefused("REFUSED: Ruby step body has an invalid native span")
        edits.append((start, end, b"nil"))
    for start, end, replacement in sorted(edits, reverse=True):
        encoded = encoded[:start] + replacement + encoded[end:]
    try:
        result = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StripRefused("REFUSED: Ruby body span split a UTF-8 character") from exc
    checked = analyze_sources(sources={path: result})["files"][0]
    if checked.get("error"):
        raise StripRefused(
            f"REFUSED: assertion stripping produced invalid Ruby: {checked['error']}")
    return result


def stripped_solution(gold_root: str, closure: dict, *,
                      source_texts: Optional[dict[str, str]] = None) -> dict:
    selected = then_definitions(closure, resolve_inherited=True)
    by_file: dict[str, list[str]] = {}
    for rel, cls, method in selected:
        if cls != "<top-level>":
            raise StripRefused(
                f"REFUSED: Ruby step definition is not a top-level DSL block: {cls!r}")
        by_file.setdefault(rel, []).append(method)
    files = []
    for rel in closure.get("files") or []:
        if source_texts is not None:
            if rel not in source_texts:
                raise StripRefused(f"REFUSED: frozen gold closure omits {rel!r}")
            original = source_texts[rel]
        else:
            try:
                with open(os.path.join(gold_root, rel), "rb") as fh:
                    raw = fh.read()
                original = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise StripRefused(
                    f"REFUSED: cannot read UTF-8 gold closure file {rel!r}: {exc}") from exc
        files.append({"file_path": rel,
                      "code": strip_ruby_source(original, by_file.get(rel, []), path=rel)})
    missing = sorted(set(by_file) - set(closure.get("files") or []))
    if missing:
        raise StripRefused(
            f"REFUSED: Then definitions name files outside the gold closure: {missing}")
    identities = [{"file": rel, "class": cls, "method": method}
                  for rel, cls, method in selected]
    return {"files": files, "metadata": {
        "source": "stripped_gold", "stripped_gold": True,
        "item_id": closure.get("item_id"),
        "n_then_definitions": len(identities),
        "then_definitions": identities,
        "definition_identity_sha256": hashlib.sha256(
            json.dumps(identities, sort_keys=True,
                       separators=(",", ":")).encode("utf-8")).hexdigest()}}


def make_strip_adapter(gold_root: str, closures_path: str):
    from ..bench.adapters import Adapter
    closures = load_closures(closures_path)

    def run(task: dict) -> dict:
        closure = closures.get(task.get("item_id"))
        if closure is None:
            return {"files": [], "metadata": {
                "adapter_error": f"no closure for {task.get('item_id')}",
                "strip_refusal": True, "source": "stripped_gold",
                "stripped_gold": True, "item_id": task.get("item_id")}}
        try:
            return stripped_solution(gold_root, closure)
        except StripRefused as exc:
            return {"files": [], "metadata": {
                "adapter_error": str(exc), "strip_refusal": True,
                "source": "stripped_gold", "stripped_gold": True,
                "item_id": task.get("item_id")}}
    return Adapter("stripped-gold", run,
                   {"gold": gold_root, "closures": closures_path})


def selftest() -> int:
    ok = True
    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}" +
              (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    source = """Given(/^setup$/) do
  @value = "é"
end

Then(/^works$/) do
  actual = @value
  expect(actual).to eq("é")
end
"""
    closure = {"item_id": "i", "files": ["features/step_definitions/x.rb"],
               "steps": [
        {"keyword": "Given", "text": "setup", "side": "removable",
         "definition": {"file": "features/step_definitions/x.rb",
                         "class": "<top-level>", "method": "step@1"}},
        {"keyword": "Then", "text": "works", "side": "removable",
         "definition": {"file": "features/step_definitions/x.rb",
                         "class": "<top-level>", "method": "step@5"}}]}
    stripped = strip_ruby_source(source, ["step@5"])
    expected = source.replace('  actual = @value\n  expect(actual).to eq("é")', '  nil')
    check("exact Then body becomes nil", stripped == expected, stripped)
    check("Given and non-ASCII bytes stay exact", '@value = "é"' in stripped)
    heredoc = """Then(/^heredoc$/) do
  expect(value).to eq(<<~TEXT)
true
TEXT
end
# outside
"""
    heredoc_expected = """Then(/^heredoc$/) do
  nil
end
# outside
"""
    check("owned heredoc content and terminator are stripped",
          strip_ruby_source(heredoc, ["step@1"]) == heredoc_expected)
    crlf = ("Then(/^crlf$/) do\r\n  expect(true).to eq(true)\r\n"
            "end\r\n# untouched\r\n")
    crlf_expected = "Then(/^crlf$/) do\r\n  nil\r\nend\r\n# untouched\r\n"
    check("CRLF and all outside bytes remain exact",
          strip_ruby_source(crlf, ["step@1"]) == crlf_expected)
    doc = stripped_solution("/unused", closure,
                            source_texts={"features/step_definitions/x.rb": source})
    check("adapter carries every closure file",
          doc["files"] == [{"file_path": "features/step_definitions/x.rb",
                             "code": expected}])
    mixed = {**closure, "steps": [closure["steps"][0],
             {**closure["steps"][1], "definition": closure["steps"][0]["definition"]}]}
    try:
        stripped_solution("/unused", mixed,
                          source_texts={"features/step_definitions/x.rb": source})
        refused = False
    except StripRefused:
        refused = True
    check("definition shared by setup and assertion is refused", refused)
    print("\n" + ("ALL PASS (strip_rb)" if ok else "FAILURES (strip_rb)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
