"""Per-scenario Ruby/Cucumber closure from native bindings and Ripper edges."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from ..core.boundary import Boundary, PRODUCTION, REMOVABLE, RETAINED
from ..core.gherkin import Block, Feature
from .closure import ItemClosure, StepBinding

GOLD_SIDECAR_FIELDS = (
    "item_id", "files", "di_fragment", "context_classes", "feature_file",
    "scenario_line")


@dataclass
class RubyStepBinding(StepBinding):
    source_line: Optional[int] = None
    example_line: Optional[int] = None
    arg_kind: Optional[str] = None
    status: str = "matched"


@dataclass
class RubyItemClosure(ItemClosure):
    example_lines: list[int] = field(default_factory=list)
    source_steps: int = 0

    def to_json(self) -> dict:
        doc = super().to_json()
        for out, binding in zip(doc["steps"], self.steps):
            definition = binding.definition
            if definition is not None:
                out["definition"] = {key: definition.get(key) for key in (
                    "file", "class", "method", "kind", "pattern", "line",
                    "arity", "pattern_type", "capture_count")}
            out.update(source_line=binding.source_line,
                       example_line=binding.example_line,
                       arg_kind=binding.arg_kind, status=binding.status)
        doc["example_lines"] = list(self.example_lines)
        doc["counts"]["source_steps"] = self.source_steps
        doc["counts"]["example_rows"] = len(self.example_lines)
        return doc


def gold_sidecar(closure_json: dict) -> dict:
    return {key: closure_json[key] for key in GOLD_SIDECAR_FIELDS}


class RubyClosureExtractor:
    """Build closures over native seeds, literal requires, and World support."""

    def __init__(self, rb_index: dict, matches: dict, boundary: Boundary):
        self.index = rb_index
        self.matches_doc = matches
        self.boundary = boundary
        self.files = rb_index["files"]
        self.repo_root = os.path.abspath(boundary.repo_root)
        self.locations = {
            (rel, definition["line"]): definition
            for rel, info in self.files.items()
            for definition in info.get("definitions", [])
        }
        self.cases: dict[tuple[str, int], list[dict]] = {}
        for case in matches.get("cases", []):
            uri = str(case.get("uri") or "").replace(os.sep, "/").lstrip("./")
            self.cases.setdefault((uri, case["scenario_line"]), []).append(case)
        # Retained World providers are present for every item. A removable
        # glue file that calls World is restored only when a native binding
        # or reviewed edge reaches it; otherwise every item would silently
        # acquire web_steps.rb and email_steps.rb.
        self.world_files = {
            rel for rel in rb_index.get("world_files") or []
            if boundary.classify(rel) == RETAINED
        }

    def _definition(self, definition: Optional[dict]) -> Optional[dict]:
        if definition is None:
            return None
        key = (definition.get("file"), definition.get("line"))
        static = self.locations.get(key)
        if static is None:
            return definition
        return {**definition, "arity": static["arity"]}

    def bind_steps(self, feature: Feature, scenario: Block) -> list[RubyStepBinding]:
        rel = os.path.relpath(os.path.abspath(feature.path), self.repo_root).replace(os.sep, "/")
        cases = sorted(self.cases.get((rel, scenario.line), []),
                       key=lambda c: (c.get("example_line") is None,
                                      c.get("example_line") or 0,
                                      c.get("pickle_id", "")))
        if not cases:
            raise ValueError(f"REFUSED: native matcher has no case for {rel}:{scenario.line}")
        out = []
        for case in cases:
            for step in case.get("steps", []):
                definition = self._definition(step.get("definition"))
                side = None if definition is None else self.boundary.classify(definition["file"])
                out.append(RubyStepBinding(
                    text=step["text"], origin=step["origin"],
                    keyword=step["keyword"], definition=definition, side=side,
                    source_line=step.get("source_line"),
                    example_line=step.get("example_line"),
                    arg_kind=step.get("arg_kind"), status=step["status"]))
        return out

    def expand(self, seeds: set[str]) -> tuple[set[str], set[str], set[str]]:
        removable: set[str] = set()
        retained: set[str] = set()
        production: set[str] = set()
        # Cucumber loads all World registrations into every scenario's World.
        # They are explicit syntax-indexed files; no module name is guessed.
        queue = list(seeds | self.world_files)
        seen: set[str] = set()
        while queue:
            rel = queue.pop()
            if rel in seen:
                continue
            seen.add(rel)
            info = self.files.get(rel)
            side = self.boundary.classify(rel)
            if info is None:
                production.add(rel)
                continue
            if side == RETAINED:
                retained.add(rel)
                continue
            if side == PRODUCTION:
                production.add(rel)
                continue
            removable.add(rel)
            production.update(info.get("external") or [])
            queue.extend(ref for ref in info.get("refs") or [] if ref not in seen)
        return removable, retained, production

    def closure_for(self, item_id: str, feature: Feature,
                    scenario: Block) -> RubyItemClosure:
        steps = self.bind_steps(feature, scenario)
        rel = os.path.relpath(os.path.abspath(feature.path), self.repo_root).replace(os.sep, "/")
        closure = RubyItemClosure(
            item_id=item_id, feature_file=rel, scenario_line=scenario.line,
            steps=steps,
            source_steps=len(scenario.steps) + (len(feature.background.steps)
                                                if feature.background else 0),
            example_lines=sorted({step.example_line for step in steps
                                  if step.example_line is not None}))
        seeds = {step.definition["file"] for step in steps
                 if step.definition and step.side == REMOVABLE}
        removable, retained, production = self.expand(seeds)
        closure.files = sorted(removable)
        closure.retained_files = sorted(retained)
        closure.classes = sorted(removable)
        closure.context_classes = sorted(
            rel for rel in removable if self.files.get(rel, {}).get("definitions"))
        closure.production_deps = sorted(production)
        closure.di_fragment = {}
        seen = set()
        for step in steps:
            key = (step.status, step.keyword, step.text)
            if step.status in {"undefined", "ambiguous"} and key not in seen:
                seen.add(key)
                closure.problems.append(
                    f"{step.status}_step: {step.keyword} {step.text}")
            elif step.definition is not None and step.definition.get("arity") is None:
                problem = ("native_definition_missing_static_arity: "
                           f"{step.definition['file']}:{step.definition['line']}")
                if problem not in closure.problems:
                    closure.problems.append(problem)
        return closure


def load_extractor(index_path: str, matches_path: str, boundary_path: str,
                   repo_root: Optional[str] = None) -> RubyClosureExtractor:
    from ..core.boundary import load_boundary
    with open(index_path, encoding="utf-8") as fh:
        index = json.load(fh)
    with open(matches_path, encoding="utf-8") as fh:
        matches = json.load(fh)
    from .rbstep_index import RubyIndexRefused, crosscheck
    problems = crosscheck(index, matches)
    if problems:
        raise RubyIndexRefused(
            "REFUSED: Ruby closure artifacts failed index cross-check:\n  "
            + "\n  ".join(problems))
    boundary = load_boundary(boundary_path, repo_root=repo_root)
    return RubyClosureExtractor(index, matches, boundary)


def cmd_closures(args) -> int:
    from ..core.boundary import load_boundary
    from .pystep_index import features_rel, walk_features
    boundary = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    extractor = load_extractor(
        os.path.join(args.artifacts, "rb_index.json"),
        os.path.join(args.artifacts, "matches.json"), args.boundary,
        repo_root=boundary.repo_root)
    from ..ruby.e_petitions import partition
    walked, excluded = partition(walk_features(
        boundary.repo_root, features_rel(args, boundary), boundary.project),
        boundary.project)
    out = [extractor.closure_for(item_id, feature, scenario).to_json()
           for item_id, feature, scenario in walked]
    destination = os.path.join(args.artifacts, "closures.json")
    with open(destination, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, ensure_ascii=False)
    print(f"{len(out)} Ruby items -> {destination}; "
          f"{sum(c['counts']['steps_unmatched'] for c in out)} unbound steps; "
          f"{len(excluded)} explicitly excluded by project tag policy")
    return 0


def selftest() -> int:
    from ..core.gherkin import parse_feature_file

    ok = True
    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}" +
              (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    boundary = Boundary(version=1, project="ruby", repo_root="/x",
        removable=[("features/step_definitions/", "")],
        retained=[("features/support/", ""), ("spec/factories.rb", "")])
    index = {"files": {
        "features/step_definitions/x.rb": {
            "definitions": [{"line": 2, "dsl": "Given", "arity": 1}],
            "refs": ["spec/factories.rb"], "external": ["json"], "worlds": []},
        "features/support/helpers.rb": {"definitions": [], "refs": [],
            "external": [], "worlds": [{"module": "Helpers", "line": 3}]},
        "spec/factories.rb": {"definitions": [], "refs": [],
            "external": [], "worlds": []}},
        "world_files": ["features/support/helpers.rb"], "errors": {}}
    native_definition = {"file": "features/step_definitions/x.rb", "line": 2,
        "class": "<top-level>", "method": "step@2", "kind": "Given",
        "pattern": "^a value$", "pattern_type": "REGULAR_EXPRESSION",
        "capture_count": 1}
    matches = {"docker_env": True, "registry": [{
        "file": "features/step_definitions/x.rb", "line": 2}],
        "cases": [{"uri": "features/f.feature", "scenario_line": 3,
        "pickle_id": "p", "example_line": None, "steps": [{
            "text": "a value", "keyword": "Given", "origin": "scenario",
            "source_line": 4, "example_line": None, "arg_kind": None,
            "status": "matched", "definition": native_definition}]}]}
    feature = parse_feature_file("/x/features/f.feature",
        "Feature: F\n\n  Scenario: S\n    Given a value\n")
    closure = RubyClosureExtractor(index, matches, boundary).closure_for(
        "ruby/features/f.feature:3", feature, feature.scenarios[0])
    doc = closure.to_json()
    check("native binding seeds the removable definition file",
          closure.files == ["features/step_definitions/x.rb"], str(closure.files))
    check("Ripper arity is joined to the native source location",
          doc["steps"][0]["definition"]["arity"] == 1, str(doc["steps"]))
    check("World and reviewed factory support edges are retained",
          closure.retained_files == ["features/support/helpers.rb", "spec/factories.rb"],
          str(closure.retained_files))
    check("external require is recorded without traversal",
          closure.production_deps == ["json"], str(closure.production_deps))
    check("Ruby has no DI fragment and gold sidecar stays exactly six fields",
          closure.di_fragment == {} and set(gold_sidecar(doc)) == set(GOLD_SIDECAR_FIELDS))

    import tempfile
    from pathlib import Path
    from .rbstep_index import RubyIndexRefused
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        index_path, matches_path = root / "index.json", root / "matches.json"
        boundary_path = root / "boundary.yml"
        boundary_path.write_text(json.dumps({
            "version": 1, "project": "ruby", "repo_root": "/x",
            "removable": [{"path": "features/step_definitions/"}],
            "retained": [{"path": "features/support/"}]}))
        index_path.write_text(json.dumps(index))
        matches_path.write_text(json.dumps(matches))
        loaded = load_extractor(str(index_path), str(matches_path),
                                str(boundary_path), repo_root="/x")
        check("qualified artifacts load through the cross-check",
              isinstance(loaded, RubyClosureExtractor))
        refused = []
        for bad_index, bad_matches in ((index, {**matches, "docker_env": False}),
                                       ({**index, "errors": {"bad.rb": ["syntax"]}}, matches)):
            index_path.write_text(json.dumps(bad_index))
            matches_path.write_text(json.dumps(bad_matches))
            try:
                load_extractor(str(index_path), str(matches_path),
                               str(boundary_path), repo_root="/x")
            except RubyIndexRefused:
                refused.append(True)
            else:
                refused.append(False)
        check("host-only witnesses and index errors are refused before closure use",
              refused == [True, True], str(refused))

    broken = {"cases": [{**matches["cases"][0], "steps": [{
        **matches["cases"][0]["steps"][0], "status": "ambiguous",
        "definition": None}]}]}
    bad = RubyClosureExtractor(index, broken, boundary).closure_for(
        "ruby/features/f.feature:3", feature, feature.scenarios[0])
    check("ambiguous and undefined remain distinct closure problems",
          bad.problems == ["ambiguous_step: Given a value"], str(bad.problems))
    print("\n" + ("ALL PASS (closure_rb)" if ok else "FAILURES (closure_rb)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
