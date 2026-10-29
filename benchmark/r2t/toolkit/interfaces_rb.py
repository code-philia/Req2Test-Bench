"""Ripper-backed target interfaces for the reviewed Ruby/Cucumber stack.

Native registry locations in the closure select exact original step blocks.
Only syntactic constant reads in those bodies and uniquely resolved,
closure-local top-level or ``World(Module)`` helper bodies contribute. The
shared interfaces artifact owns output shape and behaviour/setup semantics.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from typing import Optional

from ..core.boundary import PRODUCTION, REMOVABLE, Boundary, load_boundary
from .interfaces import (
    EMPTY_NO_DECLARATION, EMPTY_NO_MEMBER, InterfacesError, ItemInterfaces,
    extract_all, summary, write_interfaces,
)
from .mutation_rb import PARSER_VERSION

SOURCE = str(Path(__file__).resolve().parents[1] / "ruby" / "interfaces.rb")
SYNTAX_SCHEMA = "r2t.rbinterfaces-syntax/1"
PROD_SCHEMA = "r2t.rb_prod_index/1"

__all__ = ["EMPTY_NO_DECLARATION", "EMPTY_NO_MEMBER", "InterfacesError",
           "ItemInterfaces", "RubyInterfaceExtractor", "analyze_sources",
           "cmd_interfaces", "extract_all", "load_extractor", "summary",
           "write_interfaces"]


def analyze_sources(root: str, files: list[str]) -> dict:
    """Read the named original files with pinned CRuby/Ripper, without loading them."""
    from .rbstep_index import _ruby
    request = {"root": os.path.abspath(root), "files": sorted(set(files))}
    cp = subprocess.run([_ruby(), SOURCE], input=json.dumps(request), text=True,
                        capture_output=True, timeout=120)
    if cp.returncode:
        raise InterfacesError(
            f"REFUSED: Ruby interface analyzer exited {cp.returncode}: {cp.stderr[-2000:]}")
    try:
        doc = json.loads(cp.stdout)
    except json.JSONDecodeError as exc:
        raise InterfacesError("REFUSED: Ruby interface analyzer emitted invalid JSON") from exc
    if doc.get("schema") != SYNTAX_SCHEMA or doc.get("parser") != PARSER_VERSION:
        raise InterfacesError(
            "REFUSED: Ruby interface analyzer did not use the reviewed Ripper/CRuby 3.2.11 parser")
    errors = {row.get("path"): row.get("error") for row in doc.get("files", [])
              if row.get("error")}
    if errors:
        raise InterfacesError(f"REFUSED: original Ruby interface sources do not parse: {errors}")
    return doc


class RubyInterfaceExtractor:
    """Exact registry binding, Ruby T5/T6 traversal, then shared F1/F2."""

    def __init__(self, gold_root: str, prod_index: dict, boundary: Boundary,
                 files: Optional[list[str]] = None):
        self.gold_root = os.path.abspath(gold_root)
        self.repo_root = os.path.abspath(boundary.repo_root)
        self.boundary = boundary
        if not isinstance(prod_index, dict):
            raise InterfacesError("REFUSED: malformed rb_prod_index.json")
        if prod_index.get("schema") != PROD_SCHEMA or prod_index.get("errors"):
            raise InterfacesError(
                "REFUSED: rb_prod_index.json is missing or has Ruby source errors")
        if prod_index.get("parser") != PARSER_VERSION:
            raise InterfacesError(
                "REFUSED: rb_prod_index.json was not built by the reviewed Ripper/CRuby 3.2.11 parser")

        self.declaring_files: dict[str, set[str]] = {}
        files_doc = prod_index.get("files")
        if not isinstance(files_doc, dict):
            raise InterfacesError("REFUSED: rb_prod_index.json has no file inventory")
        for path, info in files_doc.items():
            if not isinstance(path, str) or not isinstance(info, dict):
                raise InterfacesError("REFUSED: malformed Ruby production file row")
            declarations = info.get("declarations")
            if not isinstance(declarations, list):
                raise InterfacesError(
                    f"REFUSED: rb_prod_index.json carries no exact declarations for {path}")
            for row in declarations:
                if (not isinstance(row, dict) or set(row) != {"name", "kind", "line"}
                        or row.get("kind") not in {"class", "module", "struct"}
                        or not isinstance(row.get("name"), str) or not row["name"]
                        or not isinstance(row.get("line"), int) or row["line"] < 1):
                    raise InterfacesError(
                        f"REFUSED: malformed Ruby production declaration in {path}")
                self.declaring_files.setdefault(row["name"], set()).add(path)
        self.first_party = {
            name for name, paths in self.declaring_files.items()
            if any(boundary.classify(path) == PRODUCTION for path in paths)
        }
        self.sources: dict[str, dict] = {}
        if files:
            self._load(files)

    def _load(self, files: list[str]) -> None:
        wanted = sorted(set(files) - set(self.sources))
        if not wanted:
            return
        for path in wanted:
            if self.boundary.classify(path) != REMOVABLE:
                raise InterfacesError(
                    f"REFUSED: closure source {path} is not removable under the reviewed boundary")
        doc = analyze_sources(self.gold_root, wanted)
        rows = {row["path"]: row for row in doc["files"]}
        if set(rows) != set(wanted):
            raise InterfacesError("REFUSED: Ruby analyzer omitted or duplicated a closure source")
        self.sources.update(rows)

    @staticmethod
    def _scope_paths(name: str, scope: Optional[str]) -> list[str]:
        if name.startswith("::"):
            return [name[2:]]
        parents = scope.split("::") if scope else []
        out = []
        while parents:
            out.append("::".join(parents + [name]))
            parents.pop()
        out.append(name)
        return out

    def _resolve_type(self, ref: dict) -> Optional[str]:
        name, scope = ref.get("name"), ref.get("scope")
        if not isinstance(name, str) or not name:
            raise InterfacesError("REFUSED: malformed constant reference from Ruby analyzer")
        raw_parts = name.removeprefix("::").split("::")
        attempts = []
        if name.startswith("::"):
            attempts.append((raw_parts, 1))
        else:
            parents = scope.split("::") if scope else []
            while parents:
                attempts.append((parents + raw_parts, len(parents) + 1))
                parents.pop()
            attempts.append((raw_parts, 1))
        for parts, minimum in attempts:
            for size in range(len(parts), minimum - 1, -1):
                candidate = "::".join(parts[:size])
                if candidate in self.declaring_files:
                    if candidate in self.first_party:
                        present = [p for p in self.declaring_files[candidate]
                                   if self.boundary.classify(p) == PRODUCTION
                                   and os.path.isfile(os.path.join(self.repo_root, p))]
                        if not present:
                            raise InterfacesError(
                                f"REFUSED: production declaration for {candidate} is absent from the pinned tree")
                    return candidate
        return None

    @staticmethod
    def _world_owners(docs: list[dict], helper_owners: set[str]) -> set[str]:
        owners = set()
        for doc in docs:
            for world in doc.get("worlds") or []:
                for name in RubyInterfaceExtractor._scope_paths(
                        world.get("name", ""), world.get("scope")):
                    if name in helper_owners:
                        owners.add(name)
                        break
        return owners

    def _surface(self, start: dict, docs: list[dict]) -> tuple[set[str], list[dict]]:
        helpers = []
        for doc in docs:
            for row in doc.get("helpers") or []:
                helpers.append({**row, "file": doc["path"]})
        owners = {row["owner"] for row in helpers if row["owner"] != "<top-level>"}
        eligible_owners = {"<top-level>"} | self._world_owners(docs, owners)
        eligible = [row for row in helpers if row["owner"] in eligible_owners
                    and self.boundary.classify(row["file"]) == REMOVABLE]
        found: set[str] = set()
        witnesses: list[dict] = []
        seen: set[tuple] = set()
        todo = [start]
        while todo:
            facts = todo.pop()
            key = (facts.get("file"), facts.get("owner"), facts.get("name"),
                   facts.get("line"))
            if key in seen:
                continue
            seen.add(key)
            for ref in facts.get("constants") or []:
                name = ref.get("name")
                if isinstance(name, str) and name:
                    found.add(name.removeprefix("::"))
            if facts is not start:
                witnesses.append({k: facts[k] for k in ("file", "owner", "name", "line")})
            for call in facts.get("calls") or []:
                matches = [row for row in eligible if row.get("name") == call]
                if len(matches) > 1:
                    where = sorted(f"{r['file']}:{r['line']}" for r in matches)
                    raise InterfacesError(
                        f"REFUSED: ambiguous removable Ruby helper {call}: {where}")
                if matches:
                    todo.append(matches[0])
        return found, sorted(witnesses,
                             key=lambda row: (row["file"], row["line"], row["owner"], row["name"]))

    def for_item(self, closure: dict) -> ItemInterfaces:
        item = ItemInterfaces(closure["item_id"], closure["feature_file"],
                              closure["scenario_line"])
        files = list(closure.get("files") or [])
        self._load(files)
        docs = [self.sources[path] for path in files]
        by_location: dict[tuple[str, int], list[dict]] = {}
        for doc in docs:
            for row in doc.get("steps") or []:
                by_location.setdefault((doc["path"], row["line"]), []).append(row)

        groups = {"scenario": set(), "background": set()}
        resolved = {"scenario": set(), "background": set()}
        seen = set()
        for step in closure.get("steps") or []:
            side = step.get("side")
            definition = step.get("definition")
            if definition is None:
                raise InterfacesError(
                    f"REFUSED: item {item.item_id} has a missing native Ruby step binding")
            if side != REMOVABLE:
                continue
            if step.get("status", "matched") != "matched":
                raise InterfacesError(
                    f"REFUSED: item {item.item_id} has a non-matched removable Ruby binding")
            origin = step.get("origin")
            path, line = definition.get("file"), definition.get("line")
            if not isinstance(path, str) or not isinstance(line, int):
                raise InterfacesError(
                    f"REFUSED: malformed Ruby registry location for {item.item_id}")
            if origin not in groups or path not in files or self.boundary.classify(path) != REMOVABLE:
                raise InterfacesError(
                    f"REFUSED: invalid removable Ruby binding for {item.item_id}: {path}:{line}")
            if definition.get("class") != "<top-level>" or definition.get("method") != f"step@{line}":
                raise InterfacesError(
                    f"REFUSED: stale Ruby definition identity for {item.item_id}: {path}:{line}")
            matches = by_location.get((path, line), [])
            if len(matches) != 1:
                raise InterfacesError(
                    f"REFUSED: expected one Ruby step block for {item.item_id} at {path}:{line}; observed {len(matches)}")
            key = (origin, path, line)
            if key in seen:
                continue
            seen.add(key)
            start = {**matches[0], "file": path, "owner": "<step>", "name": f"step@{line}"}
            surface, helpers = self._surface(start, docs)
            groups[origin].update(surface)
            for ref in matches[0].get("constants") or []:
                target = self._resolve_type(ref)
                if target:
                    resolved[origin].add(target)
            # Helper constants require their own recorded lexical scope.
            helper_by_key = {
                (doc["path"], row["owner"], row["name"], row["line"]):
                    {**row, "file": doc["path"]}
                for doc in docs for row in doc.get("helpers") or []}
            for helper in helpers:
                row = helper_by_key[(helper["file"], helper["owner"], helper["name"], helper["line"])]
                for ref in row.get("constants") or []:
                    target = self._resolve_type(ref)
                    if target:
                        resolved[origin].add(target)
            item.members.append({"file": path, "line": line, "origin": origin,
                                 "helpers": helpers})

        scenario, background = groups["scenario"], groups["background"]
        item.candidates = {"behaviour": sorted(scenario),
                           "setup": sorted(background - scenario)}
        item.behaviour = sorted(resolved["scenario"] & self.first_party)
        item.setup = sorted((resolved["background"] & self.first_party)
                            - set(item.behaviour))
        if not item.behaviour:
            item.empty_reason = (EMPTY_NO_DECLARATION
                                 if any(m["origin"] == "scenario" for m in item.members)
                                 else EMPTY_NO_MEMBER)
        return item


def load_extractor(prod_index_path: str, boundary_path: str, gold_root: str,
                   closures: list[dict], repo_root: Optional[str] = None) -> RubyInterfaceExtractor:
    try:
        with open(prod_index_path, encoding="utf-8") as stream:
            prod_index = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise InterfacesError(f"REFUSED: cannot load Ruby production index: {exc}") from exc
    if not isinstance(closures, list) or any(not isinstance(c, dict) for c in closures):
        raise InterfacesError("REFUSED: malformed Ruby closures artifact")
    boundary = load_boundary(boundary_path, repo_root=repo_root)
    files = sorted({path for closure in closures for path in (closure.get("files") or [])})
    return RubyInterfaceExtractor(gold_root, prod_index, boundary, files)


def cmd_interfaces(args) -> int:
    from ..core.constants import PROD_INDEX_NAMES
    boundary = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    closures_path = os.path.join(args.artifacts, "closures.json")
    try:
        with open(closures_path, encoding="utf-8") as stream:
            closures = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"REFUSED: cannot load Ruby closures: {exc}") from exc
    try:
        extractor = load_extractor(
            os.path.join(args.artifacts, PROD_INDEX_NAMES["ruby"]),
            args.boundary, args.gold, closures, repo_root=boundary.repo_root)
        items = extract_all(closures, extractor)
        destination = os.path.join(args.artifacts, "interfaces.json")
        write_interfaces(items, destination)
    except InterfacesError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(dict(summary(items), wrote=destination), indent=1))
    return 0


def selftest() -> int:
    import tempfile
    from .prod_index_rb import build_prod_index

    def refused(fn) -> bool:
        try:
            fn()
        except InterfacesError:
            return True
        return False

    from contextlib import ExitStack
    from importlib import import_module
    import sys
    from unittest.mock import patch
    from .rbstep_index import _ruby
    ruby = _ruby()
    parser = subprocess.run(
        [ruby, "-rripper", "-e", 'puts "ripper stdlib; #{RUBY_DESCRIPTION}"'],
        capture_output=True, text=True, timeout=30)
    if parser.returncode or not parser.stdout.strip().startswith("ripper stdlib; ruby "):
        print("[FAIL] Ruby >=3.0 with Ripper required for interfaces fixture")
        return 1
    fixture_parser = parser.stdout.strip()
    production_parser = PARSER_VERSION
    # Production remains fixed to CRuby 3.2.11. Only this isolated fixture
    # follows the supported host Ruby, and both module spellings are restored
    # even when selftest is invoked directly through ``python -m``.
    canonical = import_module("r2t.toolkit.interfaces_rb")
    modules = {id(module): module for module in (sys.modules[__name__], canonical)}
    with ExitStack() as stack:
        for module in modules.values():
            stack.enter_context(patch.object(module, "PARSER_VERSION", fixture_parser))
        with tempfile.TemporaryDirectory(prefix="r2t-ruby-interfaces-") as temp:
            base = Path(temp)
            repo, gold = base / "repo", base / "gold"
            (repo / "app/models").mkdir(parents=True)
            (repo / "lib/retained").mkdir(parents=True)
            (gold / "features/step_definitions").mkdir(parents=True)
            production = """class Petition; end
    module Archived
      class Petition; end
    end
    module Nested
      class Thing; end
    end
    module Rooted
      class Type; end
    end
    module Helpers
      module Inner
        class Thing; end
      end
    end
    FeedbackSignature = Struct.new(:value)
    module Reopen; end
    module Reopen; end
    Dynamic = make_type
    """
            (repo / "app/models/types.rb").write_text(production)
            (repo / "app/models/shared.rb").write_text("module Shared; end\n")
            (repo / "lib/retained/shared.rb").write_text("module Shared; end\n")
            glue = """module Helpers
      def helper
        Nested::Thing.call
        Inner::Thing.call
        second
      end
      def second
        ::Rooted::Type.call
      end
    end
    World(Helpers)
    Given("scenario") do
      Petition::VALIDATED_STATE
      Archived::Petition.find
      Shared.touch
      helper
      Object.const_get(:IgnoredDynamic)
      IgnoredDefinition = DefinitionValue
      OmniAuth.config.mock_auth[:example] = @user
      value.IgnoredMethod
      "IgnoredString"
      :IgnoredSymbol
      rows.each { Nested::Thing.call }
      step "ignored gherkin"
    end
    Given("background") do
      FeedbackSignature.new
    end
    """
            rel = "features/step_definitions/x.rb"
            (gold / rel).write_text(glue)
            boundary = Boundary(1, "ruby", str(repo),
                                removable=[("features/step_definitions/", "")],
                                retained=[("lib/retained/", "")])
            prod = build_prod_index(str(repo), ruby=ruby)
            declarations = prod["files"]["app/models/types.rb"]["declarations"]
            names = [row["name"] for row in declarations]
            assert names.count("Reopen") == 2 and "FeedbackSignature" in names and "Dynamic" not in names
            steps = analyze_sources(str(gold), [rel])["files"][0]["steps"]
            scenario_line, background_line = steps[0]["line"], steps[1]["line"]
            closure = {"item_id": "ruby/f:1", "feature_file": "features/f.feature",
                       "scenario_line": 1, "files": [rel], "steps": [
                {"origin": "scenario", "side": REMOVABLE,
                 "definition": {"file": rel, "line": scenario_line,
                                "class": "<top-level>", "method": f"step@{scenario_line}"}},
                {"origin": "background", "side": REMOVABLE,
                 "definition": {"file": rel, "line": background_line,
                                "class": "<top-level>", "method": f"step@{background_line}"}}]}
            ex = RubyInterfaceExtractor(str(gold), prod, boundary, [rel])
            item = ex.for_item(closure)
            assert item.behaviour == ["Archived::Petition", "Helpers::Inner::Thing",
                                      "Nested::Thing", "Petition", "Rooted::Type", "Shared"], item
            assert item.setup == ["FeedbackSignature"], item
            assert "IgnoredDynamic" not in item.candidates["behaviour"]
            assert "IgnoredDefinition" not in item.candidates["behaviour"]
            assert "DefinitionValue" in item.candidates["behaviour"]
            assert "OmniAuth" in item.candidates["behaviour"]
            assert "IgnoredMethod" not in item.candidates["behaviour"]
            assert "IgnoredString" not in item.candidates["behaviour"]
            assert "IgnoredSymbol" not in item.candidates["behaviour"]
            assert item.members[0]["helpers"] == [
                {"file": rel, "owner": "Helpers", "name": "helper", "line": 2},
                {"file": rel, "owner": "Helpers", "name": "second", "line": 7}]
            first, second = base / "first.json", base / "second.json"
            write_interfaces([item], str(first)); write_interfaces([ex.for_item(closure)], str(second))
            assert first.read_bytes() == second.read_bytes()

            artifacts = base / "artifacts"
            artifacts.mkdir()
            (artifacts / "rb_prod_index.json").write_text(json.dumps(prod))
            (artifacts / "closures.json").write_text(json.dumps([closure]))
            boundary_path = base / "boundary.yml"
            boundary_path.write_text(json.dumps({
                "version": 1, "project": "ruby", "repo_root": str(repo),
                "removable": [{"path": "features/step_definitions/"}],
                "retained": []}))
            from contextlib import redirect_stdout
            from io import StringIO
            from types import SimpleNamespace
            args = SimpleNamespace(boundary=str(boundary_path), repo=str(repo),
                                   gold=str(gold), artifacts=str(artifacts))
            with redirect_stdout(StringIO()):
                assert cmd_interfaces(args) == 0
            written = json.loads((artifacts / "interfaces.json").read_text())
            assert written["items"][0]["target_interfaces"] == {
                "behaviour": item.behaviour, "setup": item.setup}
            from importlib import import_module
            from ..stacks import cucumber_ruby
            canonical = import_module("r2t.toolkit.interfaces_rb")
            assert cucumber_ruby.cmd_interfaces is canonical.cmd_interfaces
            assert "cmd_interfaces" in cucumber_ruby.MEMBERS and not cucumber_ruby.PENDING

            stale = json.loads(json.dumps(closure))
            stale["steps"][0]["definition"]["line"] = 999
            stale["steps"][0]["definition"]["method"] = "step@999"
            assert refused(lambda: ex.for_item(stale))
            missing = json.loads(json.dumps(closure))
            missing["steps"][0]["definition"] = None
            assert refused(lambda: ex.for_item(missing))
            legacy = json.loads(json.dumps(prod))
            del legacy["files"]["app/models/types.rb"]["declarations"]
            assert refused(lambda: RubyInterfaceExtractor(str(gold), legacy, boundary))

            duplicate_rel = "features/step_definitions/duplicate.rb"
            (gold / duplicate_rel).write_text("def helper\n  Petition.find\nend\n")
            ambiguous = json.loads(json.dumps(closure))
            ambiguous["files"].append(duplicate_rel)
            amb_ex = RubyInterfaceExtractor(str(gold), prod, boundary, ambiguous["files"])
            assert refused(lambda: amb_ex.for_item(ambiguous))

            retained = {"item_id": "ruby/f:2", "feature_file": "features/f.feature",
                        "scenario_line": 2, "files": [], "steps": [{
                            "origin": "scenario", "side": "retained",
                            "definition": {"file": "features/support/env.rb", "line": 1}}]}
            empty = ex.for_item(retained)
            assert empty.behaviour == [] and empty.empty_reason == EMPTY_NO_MEMBER

            # A reopened type survives F2 because one exact declaration is
            # production. Removing that production declaration file makes the
            # same bound member refuse rather than falling back to the retained row.
            (repo / "app/models/shared.rb").unlink()
            assert refused(lambda: ex.for_item(closure))
    assert PARSER_VERSION == production_parser
    wrong_parser = {**prod, "parser": "ripper stdlib; ruby 9.9 fixture"}
    assert refused(lambda: RubyInterfaceExtractor(str(gold), wrong_parser, boundary))
    if fixture_parser != production_parser:
        assert refused(lambda: RubyInterfaceExtractor(str(gold), prod, boundary))
    print("ALL PASS (interfaces_rb)")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
