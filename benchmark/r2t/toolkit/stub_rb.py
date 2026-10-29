"""Vacuous Cucumber-Ruby stubs from native closure bindings."""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Optional

from ..bench.runner import item_key

STEPS_DIR = "features/step_definitions"
_ALREADY_ANSWERED = frozenset({"retained", "production"})
_ARGUMENT_KINDS = {None: 0, "doc_string": 1, "data_table": 1}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class StubRubyRefused(ValueError):
    pass


def _ruby_literal(text: str) -> str:
    if not isinstance(text, str) or not text or _CONTROL.search(text):
        raise StubRubyRefused("REFUSED: Ruby stub text is empty or has a control character")
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def step_keys(item: dict, closure: Optional[dict]) -> list[tuple[str, Optional[str]]]:
    if closure is None:
        raise StubRubyRefused("REFUSED: a Ruby stub requires native closure bindings")
    if closure.get("item_id") not in (None, item.get("item_id")):
        raise StubRubyRefused("REFUSED: closure belongs to a different item")
    seen: dict[str, Optional[str]] = {}
    out = []
    for step in closure.get("steps") or []:
        status = step.get("status", "matched")
        if status != "matched":
            raise StubRubyRefused(
                f"REFUSED: {status} native binding is not a vacuity result")
        if step.get("side") in _ALREADY_ANSWERED:
            continue
        if not isinstance(step.get("definition"), dict):
            raise StubRubyRefused("REFUSED: matched Ruby step has no definition evidence")
        text = step.get("text")
        kind = step.get("arg_kind")
        if kind not in _ARGUMENT_KINDS:
            raise StubRubyRefused(f"REFUSED: unsupported multiline argument kind {kind!r}")
        if text in seen:
            if seen[text] != kind:
                raise StubRubyRefused(
                    f"REFUSED: step {text!r} has inconsistent multiline argument kinds")
            continue
        seen[text] = kind
        out.append((text, kind))
    return out


def module_name(item_id: str) -> str:
    return "r2t_stub_" + item_key(item_id)


def ruby_module(item_id: str, keys: list[tuple[str, Optional[str]]]) -> tuple[str, str]:
    if len(keys) != len(set(keys)):
        raise StubRubyRefused("REFUSED: duplicate Ruby stub key")
    path = f"{STEPS_DIR}/{module_name(item_id)}.rb"
    lines = ["# frozen_string_literal: true", "",
             "# Generated vacuous floor: exact step text, empty bodies."]
    for text, kind in keys:
        literal = _ruby_literal(text)
        params = " |argument|" if _ARGUMENT_KINDS[kind] else ""
        # Cucumber accepts Regexp definitions. Regexp.escape runs in the same
        # Ruby process as registration; \A/\z make this an exact literal and
        # eliminate every capture from the original definition.
        lines += [f"Given(Regexp.new('\\\\A' + Regexp.escape({literal}) + '\\\\z')) do{params}",
                  "  nil", "end", ""]
    return path, "\n".join(lines)


def stub_solution(item: dict, closure: Optional[dict]) -> dict:
    keys = step_keys(item, closure)
    path, code = ruby_module(item["item_id"], keys)
    return {"files": [{"file_path": path, "code": code}],
            "metadata": {"stub": True, "n_steps": len(keys),
                         "closure_available": closure is not None}}


def load_closures(path: str) -> dict[str, dict]:
    with open(path, encoding="utf-8") as fh:
        return {closure["item_id"]: closure for closure in json.load(fh)}


def make_stub_adapter(closures_path: str):
    from ..bench.adapters import Adapter
    closures = load_closures(closures_path)

    def run(task: dict) -> dict:
        try:
            return stub_solution(task, closures.get(task["item_id"]))
        except Exception as exc:  # noqa: BLE001
            return {"files": [], "metadata": {
                "adapter_error": f"{type(exc).__name__}: {exc}",
                "stub_refusal": True}}
    return Adapter("stub", run, {"closures": closures_path})


def _load_jsonl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def acceptance(items_path: str, closures_path: str,
               project: Optional[str] = None) -> dict:
    closures = load_closures(closures_path)
    items = [item for item in _load_jsonl(items_path)
             if project is None or item.get("project") == project]
    failures = []
    paths = set()
    emitted = 0
    for item in items:
        try:
            one = stub_solution(item, closures.get(item["item_id"]))
            two = stub_solution(item, closures.get(item["item_id"]))
            if one != two:
                failures.append(f"{item['item_id']}: regeneration changed bytes")
                continue
            path = one["files"][0]["file_path"]
            if path in paths:
                failures.append(f"{item['item_id']}: duplicate output path {path}")
            paths.add(path)
            emitted += one["metadata"]["n_steps"]
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{item['item_id']}: {type(exc).__name__}: {exc}")
    if failures:
        raise SystemExit("REFUSED: Ruby stub acceptance failed:\n  " + "\n  ".join(failures))
    return {"items": len(items), "definitions_emitted": emitted,
            "violations": [], "closures": closures_path}


def cmd_stub_accept(args) -> int:
    from ..core.boundary import load_boundary
    boundary = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    closures = args.closures or os.path.join(args.artifacts, "closures.json")
    print(json.dumps(acceptance(args.release, closures, boundary.project), indent=1))
    return 0


def selftest() -> int:
    ok = True
    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}" +
              (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    item = {"item_id": "e-petitions/features/f.feature:4"}
    definition = {"file": "features/step_definitions/x.rb", "line": 1,
                  "class": "<top-level>", "method": "step@1"}
    closure = {"item_id": item["item_id"], "steps": [
        {"text": "I choose {raw}/(text)", "status": "matched",
         "side": "removable", "arg_kind": None, "definition": definition},
        {"text": "I submit rows", "status": "matched", "side": "removable",
         "arg_kind": "data_table", "definition": definition},
        {"text": "I submit rows", "status": "matched", "side": "removable",
         "arg_kind": "data_table", "definition": definition},
    ]}
    keys = step_keys(item, closure)
    path, source = ruby_module(item["item_id"], keys)
    check("distinct native texts yield distinct exact definitions", len(keys) == 2)
    check("generated definitions remove original text captures",
          "Regexp.escape('I choose {raw}/(text)')" in source and "|argument|" in source)
    check("only a native multiline argument produces one block parameter",
          source.count("|argument|") == 1, source)
    check("output path is isolated under Cucumber glue", path.startswith(STEPS_DIR + "/"))
    from .rbstep_index import analyze_sources
    analyzed = analyze_sources(sources={path: source})["files"][0]
    check("Ripper accepts generated Ruby", not analyzed.get("error"), str(analyzed))
    check("native AST sees arities zero and one",
          [d["arity"] for d in analyzed["definitions"]] == [0, 1], str(analyzed))
    bad = {**closure, "steps": [{**closure["steps"][0], "status": "undefined",
                                  "definition": None}]}
    try:
        step_keys(item, bad)
        refused = False
    except StubRubyRefused:
        refused = True
    check("undefined native binding is refused", refused)
    check("regeneration is byte-identical", ruby_module(item["item_id"], keys) == (path, source))
    print("\n" + ("ALL PASS (stub_rb)" if ok else "FAILURES (stub_rb)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
