"""Native Cucumber-Ruby step binding and Ripper-backed static index."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Optional

from ..core.gherkin import Block, Feature
from .pystep_index import (CUCUMBER_DIALECT, StepRef, effective_steps,
                           render_template)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MATCHER = os.path.join(HERE, "ruby", "match_steps.rb")
DEFAULT_IMAGE = os.environ.get(
    "R2T_CUCUMBER_RUBY_IMAGE",
    "sha256:df58279c613fb59500be4a53989d239b13c1dd257f7b292b47c9dce3117f6d96")
CONTAINER_ROOT = "/app"
CONTAINER_SCRATCH = "/r2t"


class RubyIndexRefused(ValueError):
    """Native evidence is missing or disagrees with indexed source."""


def examples_rows(feature: Feature, scenario: Block) -> list[tuple[int, dict]]:
    from .pystep_index import examples_rows as _rows
    return _rows(feature, scenario, dialect=CUCUMBER_DIALECT)


def item_steps(feature: Feature, scenario: Block) -> list[StepRef]:
    """Static projection for diagnostics; native messages own bindings."""
    base = effective_steps(feature, scenario)
    rows = examples_rows(feature, scenario) if scenario.kind == "Scenario Outline" else []
    if not rows:
        return [StepRef(k, s.text, origin, s.line, s.keyword, s.text)
                for k, origin, s in base]
    out = []
    for row_number, (line, values) in enumerate(rows, 1):
        out.extend(StepRef(k, render_template(s.text, values), origin, s.line,
                           s.keyword, s.text, line, row_number)
                   for k, origin, s in base)
    return out


def _ruby() -> str:
    configured = os.environ.get("R2T_RUBY")
    candidates = [configured, "/srv/binhang/host/bin/ruby", shutil.which("ruby")]
    for value in candidates:
        if value and os.path.isfile(value) and os.access(value, os.X_OK):
            return value
    raise RubyIndexRefused("REFUSED: no Ruby interpreter for Ripper indexing")


def analyze_sources(*, repo_root: str = ".", files: Optional[list[str]] = None,
                    sources: Optional[dict[str, str]] = None) -> dict:
    request = {"root": os.path.abspath(repo_root), "files": files or [],
               "sources": sources or {}}
    cp = subprocess.run([_ruby(), MATCHER, "analyze"], input=json.dumps(request),
                        text=True, capture_output=True, timeout=120)
    if cp.returncode:
        raise RubyIndexRefused(
            f"REFUSED: native Ruby analyzer exited {cp.returncode}: {cp.stderr[-2000:]}")
    try:
        doc = json.loads(cp.stdout)
    except json.JSONDecodeError as exc:
        raise RubyIndexRefused("REFUSED: native Ruby analyzer emitted invalid JSON") from exc
    if doc.get("schema") != "r2t.rbsyntax/1":
        raise RubyIndexRefused("REFUSED: native Ruby analyzer schema is missing")
    return doc


def _with_rb(path: str, repo_root: str) -> Optional[str]:
    path = path.replace(os.sep, "/").lstrip("./")
    for candidate in (path, path + ".rb", path + "/init.rb"):
        if os.path.isfile(os.path.join(repo_root, *candidate.split("/"))):
            return candidate
    return None

# Dynamic expressions that Ripper deliberately reports as non-literals. These
# are reviewed pinned-project facts, not inferred constant/global references.
COMPANION_EDGES = {
    "features/step_definitions/web_steps.rb": ("features/support/paths.rb",),
    "features/support/constituency_api.rb": (
        "spec/support/constituency_api_helpers.rb",),
}
FACTORY_COMPANION = "spec/factories.rb"
FACTORY_USERS = (
    "features/step_definitions/actioned_steps.rb",
    "features/step_definitions/admin_hub_steps.rb",
    "features/step_definitions/admin_search_steps.rb",
    "features/step_definitions/authentication_steps.rb",
    "features/step_definitions/constituency_search_steps.rb",
    "features/step_definitions/debate_outcome_steps.rb",
    "features/step_definitions/feedback_steps.rb",
    "features/step_definitions/moderation_steps.rb",
    "features/step_definitions/petition_email_steps.rb",
    "features/step_definitions/petition_steps.rb",
    "features/step_definitions/pickle_steps.rb",
    "features/step_definitions/rate_limit_steps.rb",
    "features/step_definitions/signature_steps.rb",
    "features/step_definitions/sponsor_steps.rb",
    "features/step_definitions/trending_steps.rb",
)
for _factory_user in FACTORY_USERS:
    COMPANION_EDGES[_factory_user] = (FACTORY_COMPANION,)


def build_index(repo_root: str, paths: Optional[list[str]] = None) -> dict:
    root = os.path.abspath(repo_root)
    roots = paths or ["features/step_definitions", "features/support",
                      "spec/factories.rb", "spec/support"]
    files: list[str] = []
    for rel in roots:
        full = os.path.join(root, *rel.split("/"))
        if os.path.isfile(full) and rel.endswith(".rb"):
            files.append(rel)
        elif os.path.isdir(full):
            for dirpath, dirs, names in os.walk(full):
                dirs[:] = sorted(d for d in dirs if d not in {".git", "node_modules"})
                for name in sorted(names):
                    if name.endswith(".rb"):
                        files.append(os.path.relpath(os.path.join(dirpath, name), root)
                                     .replace(os.sep, "/"))
    for companions in COMPANION_EDGES.values():
        for rel in companions:
            if os.path.isfile(os.path.join(root, *rel.split("/"))):
                files.append(rel)
    files = sorted(set(files))
    raw = analyze_sources(repo_root=root, files=files)
    indexed: dict[str, dict] = {}
    errors: dict[str, list[str]] = {}
    for info in raw["files"]:
        rel = info["path"].replace(os.sep, "/")
        if info.get("error"):
            errors[rel] = [info["error"]]
            continue
        refs: set[str] = set(COMPANION_EDGES.get(rel, ()))
        external: set[str] = set()
        dynamic: list[dict] = []
        for req in info.get("requires", []):
            value = req.get("value")
            if not req.get("literal"):
                dynamic.append(req)
                continue
            if req["kind"] == "require_relative":
                target = _with_rb(os.path.normpath(os.path.join(os.path.dirname(rel), value)), root)
            else:
                target = (_with_rb(value, root) or _with_rb(os.path.join("lib", value), root)
                          or _with_rb(os.path.join("features", value), root))
            (refs if target else external).add(target or value)
        own_errors = list(info.get("errors") or [])
        for req in dynamic:
            if rel not in COMPANION_EDGES:
                own_errors.append(
                    f"line {req.get('line')}: dynamic {req.get('kind')} has no reviewed companion edge")
        if own_errors:
            errors[rel] = own_errors
        indexed[rel] = {"requires": info.get("requires", []),
                        "refs": sorted(refs), "external": sorted(external),
                        "worlds": info.get("worlds", []),
                        "definitions": info.get("definitions", [])}
    for rel, info in indexed.items():
        absent = [ref for ref in info["refs"] if ref not in indexed]
        if absent:
            errors.setdefault(rel, []).append(
                f"reviewed/local dependency absent from index: {absent}")
    world_files = sorted(rel for rel, info in indexed.items() if info["worlds"])
    return {"schema": "r2t.rbindex/1", "ruby_version": raw["ruby_version"],
            "files": indexed, "errors": errors, "world_files": world_files,
            "companion_edges": {k: list(v) for k, v in COMPANION_EDGES.items()},
            "counts": {"files": len(indexed),
                       "step_definitions": sum(len(v["definitions"]) for v in indexed.values()),
                       "world_files": len(world_files), "errors": len(errors)}}


def _children(node: dict):
    feature = node.get("feature") or {}
    return feature.get("children") or []


def _ast_maps(documents: list[dict]) -> tuple[dict, dict, dict]:
    scenarios, steps, rows = {}, {}, {}

    def block_steps(block: dict, uri: str, origin: str):
        for step in block.get("steps") or []:
            steps[step["id"]] = {"uri": uri, "origin": origin,
                                  "source_line": step["location"]["line"],
                                  "keyword": step.get("keyword", "").strip()}

    def walk(children: list[dict], uri: str):
        for child in children:
            if "background" in child:
                block_steps(child["background"], uri, "background")
            elif "scenario" in child:
                scenario = child["scenario"]
                scenarios[scenario["id"]] = {"uri": uri,
                    "scenario_line": scenario["location"]["line"]}
                block_steps(scenario, uri, "scenario")
                for examples in scenario.get("examples") or []:
                    for row in examples.get("tableBody") or []:
                        rows[row["id"]] = row["location"]["line"]
            elif "rule" in child:
                walk(child["rule"].get("children") or [], uri)
    for document in documents:
        uri = document.get("uri")
        walk(_children(document), uri)
    return scenarios, steps, rows


def parse_messages(data: str | list[dict], witness: dict) -> dict:
    if isinstance(data, str):
        envelopes = [json.loads(line) for line in data.splitlines() if line.strip()]
    else:
        envelopes = list(data)
    definitions = {e["stepDefinition"]["id"]: e["stepDefinition"]
                   for e in envelopes if "stepDefinition" in e}
    pickles = {e["pickle"]["id"]: e["pickle"] for e in envelopes if "pickle" in e}
    test_cases = {e["testCase"]["id"]: e["testCase"]
                  for e in envelopes if "testCase" in e}
    starts = {e["testCaseStarted"]["id"]: e["testCaseStarted"]
              for e in envelopes if "testCaseStarted" in e}
    finishes: dict[tuple[str, str], dict] = {}
    for e in envelopes:
        if "testStepFinished" in e:
            value = e["testStepFinished"]
            finishes[(value["testCaseStartedId"], value["testStepId"])] = value
    docs = [e["gherkinDocument"] for e in envelopes if "gherkinDocument" in e]
    scenarios, ast_steps, ast_rows = _ast_maps(docs)
    cases = []
    for started_id, started in starts.items():
        case = test_cases.get(started.get("testCaseId"))
        if not case:
            raise RubyIndexRefused("REFUSED: testCaseStarted names no testCase")
        pickle = pickles.get(case.get("pickleId"))
        if not pickle:
            raise RubyIndexRefused("REFUSED: testCase names no pickle")
        scenario_ids = [i for i in pickle.get("astNodeIds", []) if i in scenarios]
        if len(scenario_ids) != 1:
            raise RubyIndexRefused("REFUSED: pickle has no unique scenario AST identity")
        scenario = scenarios[scenario_ids[0]]
        row_ids = [i for i in pickle.get("astNodeIds", []) if i in ast_rows]
        example_line = ast_rows[row_ids[0]] if len(row_ids) == 1 else None
        test_steps = {s.get("pickleStepId"): s for s in case.get("testSteps", [])
                      if s.get("pickleStepId")}
        bound = []
        for pstep in pickle.get("steps") or []:
            tstep = test_steps.get(pstep["id"])
            if not tstep:
                raise RubyIndexRefused("REFUSED: pickle step has no source test step")
            finished = finishes.get((started_id, tstep["id"]))
            if not finished:
                raise RubyIndexRefused("REFUSED: source test step has no finished result")
            result_status = finished.get("testStepResult", {}).get("status", "").upper()
            definition_ids = list(tstep.get("stepDefinitionIds") or [])
            if len(definition_ids) == 1:
                status = "matched"
                definition = definitions.get(definition_ids[0])
                if definition is None:
                    raise RubyIndexRefused("REFUSED: binding names an absent definition")
            elif result_status == "AMBIGUOUS" or len(definition_ids) > 1:
                status, definition = "ambiguous", None
            elif result_status == "UNDEFINED":
                status, definition = "undefined", None
            else:
                raise RubyIndexRefused(
                    f"REFUSED: empty native binding has status {result_status!r}")
            ast_ids = pstep.get("astNodeIds") or []
            source_ids = [i for i in ast_ids if i in ast_steps]
            if len(source_ids) != 1:
                raise RubyIndexRefused("REFUSED: pickle step has no unique source AST step")
            source = ast_steps[source_ids[0]]
            argument = pstep.get("argument") or {}
            arg_kind = ("doc_string" if "docString" in argument else
                        "data_table" if "dataTable" in argument else None)
            match_lists = tstep.get("stepMatchArgumentsLists") or []
            capture_count = 0
            if len(match_lists) == 1:
                capture_count = len(match_lists[0].get("stepMatchArguments") or [])
            elif len(match_lists) > 1:
                status, definition = "ambiguous", None
            normalized = None
            if definition is not None:
                ref = definition.get("sourceReference") or {}
                loc = ref.get("location") or {}
                uri = str(ref.get("uri") or "").replace("file://", "")
                uri = uri.removeprefix(CONTAINER_ROOT + "/").lstrip("./")
                pattern = definition.get("pattern") or {}
                normalized = {"file": uri, "line": loc.get("line"),
                              "class": "<top-level>",
                              "method": f"step@{loc.get('line')}",
                              "kind": source["keyword"],
                              "pattern": pattern.get("source"),
                              "pattern_type": pattern.get("type"),
                              "capture_count": capture_count}
            bound.append({"text": pstep.get("text", ""),
                          "keyword": source["keyword"],
                          "origin": source["origin"],
                          "source_line": source["source_line"],
                          "example_line": example_line,
                          "arg_kind": arg_kind, "status": status,
                          "definition": normalized})
        cases.append({"pickle_id": pickle["id"], "uri": scenario["uri"],
                      "scenario_line": scenario["scenario_line"],
                      "example_line": example_line, "steps": bound})
    registry = []
    for definition in definitions.values():
        ref = definition.get("sourceReference") or {}
        uri = str(ref.get("uri") or "").replace("file://", "")
        uri = uri.removeprefix(CONTAINER_ROOT + "/").lstrip("./")
        registry.append({"id": definition["id"], "file": uri,
                         "line": (ref.get("location") or {}).get("line"),
                         "pattern": definition.get("pattern")})
    registry.sort(key=lambda d: (d["file"], d["line"] or 0, d["id"]))
    return {**witness, "schema": "r2t.rbmatches/1", "framework": "cucumber_ruby",
            "definitions": len(definitions), "registry": registry, "cases": cases,
            "counts": {"cases": len(cases),
                       "steps": sum(len(c["steps"]) for c in cases)}}


def _docker(argv: list[str]) -> list[str]:
    from ..core.docker_cli import docker_command
    return docker_command(argv[1:], executable=argv[0])


def run_matcher(repo_root: str, locations: list[str], *, image: str = DEFAULT_IMAGE,
                timeout: int = 1800, project: Optional[str] = None) -> dict:
    from ..ruby.e_petitions import matcher_tag_args
    scratch = tempfile.mkdtemp(prefix="r2t_rbmatch_")
    workspace = os.path.join(scratch, "workspace")
    try:
        shutil.copytree(repo_root, workspace, symlinks=True,
                        ignore=shutil.ignore_patterns(".git", "node_modules", "log", "tmp",
                                                       "coverage", "storage"))
        shutil.copyfile(MATCHER, os.path.join(scratch, "match_steps.rb"))
        messages = os.path.join(scratch, "messages.ndjson")
        meta = os.path.join(scratch, "meta.json")
        inner = ["/usr/local/bin/r2t-ruby-exec", "ruby",
                 f"{CONTAINER_SCRATCH}/match_steps.rb", "run",
                 "--messages", f"{CONTAINER_SCRATCH}/messages.ndjson",
                 "--meta", f"{CONTAINER_SCRATCH}/meta.json", "--",
                 "bundle", "exec", "cucumber", "--no-profile", "--strict",
                 "--publish-quiet", "--dry-run",
                 "--require", "features",
                 "--format", "message", "--out",
                 f"{CONTAINER_SCRATCH}/messages.ndjson"] + matcher_tag_args(project) + locations
        argv = ["docker", "run", "--rm", "--network", "none",
                "-v", f"{workspace}:{CONTAINER_ROOT}",
                "-v", f"{scratch}:{CONTAINER_SCRATCH}", "-w", CONTAINER_ROOT,
                image] + inner
        cp = subprocess.run(_docker(argv), capture_output=True, text=True,
                            timeout=timeout)
        if cp.returncode or not os.path.isfile(meta) or not os.path.isfile(messages):
            raise RubyIndexRefused(
                f"REFUSED: in-container matcher failed ({cp.returncode}): "
                f"{cp.stderr[-2000:]}")
        with open(meta, encoding="utf-8") as fh:
            witness = json.load(fh)
        witness["image_id"] = image
        with open(messages, encoding="utf-8") as fh:
            result = parse_messages(fh.read(), witness)
        if not result["cases"]:
            raise RubyIndexRefused(
                "REFUSED: native matcher selected no test case; an empty "
                "message stream cannot establish undefined or matched steps")
        return result
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def crosscheck(index: dict, matches: dict) -> list[str]:
    problems = []
    if not matches.get("docker_env"):
        problems.append("matcher witness does not establish container execution")
    if index.get("errors"):
        problems.append(f"{len(index['errors'])} Ruby source file(s) have index errors")
    locations = {(path, d["line"]): d for path, info in index.get("files", {}).items()
                 for d in info.get("definitions", [])}
    native_locations = {(d.get("file"), d.get("line"))
                        for d in matches.get("registry", [])}
    missing_native = sorted(set(locations) - native_locations)
    missing_static = sorted(native_locations - set(locations))
    if missing_native:
        problems.append(f"{len(missing_native)} Ripper definition(s) absent from native registry")
    if missing_static:
        problems.append(f"{len(missing_static)} native definition(s) absent from Ripper index")
    for case in matches.get("cases", []):
        for step in case.get("steps", []):
            definition = step.get("definition")
            if definition and (definition["file"], definition["line"]) not in locations:
                problems.append("native definition absent from Ripper index: "
                                f"{definition['file']}:{definition['line']}")
    return sorted(set(problems))


def _index_paths(boundary) -> list[str]:
    out = []
    for value in boundary.removable_prefixes() + boundary.retained_prefixes():
        rel = value.rstrip("/")
        full = os.path.join(boundary.repo_root, rel)
        if (os.path.isfile(full) and rel.endswith(".rb")) or os.path.isdir(full):
            out.append(rel)
    return sorted(set(out))


def cmd_index(args) -> int:
    from ..bench.cli import _bound_container_image
    from ..core.boundary import load_boundary
    from .pystep_index import features_rel
    image = _bound_container_image(args.container)
    boundary = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    features = features_rel(args, boundary)
    os.makedirs(args.artifacts, exist_ok=True)
    index = build_index(boundary.repo_root, _index_paths(boundary))
    matches = run_matcher(boundary.repo_root, [features], image=image,
                          project=boundary.project)
    problems = crosscheck(index, matches)
    for name, doc in (("rb_index.json", index), ("matches.json", matches)):
        with open(os.path.join(args.artifacts, name), "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True, ensure_ascii=False)
    if problems:
        raise SystemExit("REFUSED: Ruby index cross-check failed:\n  " + "\n  ".join(problems))
    print(f"indexed {index['counts']['step_definitions']} definitions; "
          f"native matcher bound {matches['counts']['steps']} source steps")
    return 0


def selftest() -> int:
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}" +
              (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    source = """require 'json'
require_relative 'helper'
World(Helpers)
And 'a literal step' do |table|
  table
end
"""
    syntax = analyze_sources(sources={"features/step_definitions/x.rb": source})
    info = syntax["files"][0]
    check("Ripper records literal require kinds",
          [(r["kind"], r["value"]) for r in info["requires"]]
          == [("require", "json"), ("require_relative", "helper")], str(info))
    check("World constant and Cucumber And alias are syntax nodes",
          info["worlds"][0]["module"] == "Helpers"
          and info["definitions"][0]["dsl"] == "And", str(info))
    check("native AST records multiline argument arity and body span",
          info["definitions"][0]["arity"] == 1
          and info["definitions"][0]["body"]["start_line"] == 5, str(info))

    envelopes = [
        {"gherkinDocument": {"uri": "features/f.feature", "feature": {
            "children": [{"scenario": {"id": "scenario", "location": {"line": 2},
                "steps": [{"id": "ast-step", "location": {"line": 3},
                           "keyword": "And "}],
                "examples": [{"tableBody": [{"id": "row", "location": {"line": 7}}]}]}}]}}},
        {"pickle": {"id": "pickle", "uri": "features/f.feature",
            "astNodeIds": ["scenario", "row"], "steps": [{"id": "pickle-step",
                "text": "a literal step", "astNodeIds": ["ast-step", "row"],
                "argument": {"dataTable": {"rows": []}}}]}},
        {"stepDefinition": {"id": "definition",
            "pattern": {"source": "a literal step", "type": "CUCUMBER_EXPRESSION"},
            "sourceReference": {"uri": "features/step_definitions/x.rb",
                                "location": {"line": 4}}}},
        {"testCase": {"id": "case", "pickleId": "pickle", "testSteps": [{
            "id": "test-step", "pickleStepId": "pickle-step",
            "stepDefinitionIds": ["definition"],
            "stepMatchArgumentsLists": [{"stepMatchArguments": []}]}]}},
        {"testCaseStarted": {"id": "started", "testCaseId": "case"}},
        {"testStepFinished": {"testCaseStartedId": "started",
            "testStepId": "test-step", "testStepResult": {"status": "SKIPPED"}}},
    ]
    matches = parse_messages(envelopes, {"docker_env": True})
    step = matches["cases"][0]["steps"][0]
    check("testCase/pickle/definition/result join binds one source step",
          step["status"] == "matched" and step["definition"]["line"] == 4,
          str(step))
    check("outline AST row and multiline argument survive the join",
          matches["cases"][0]["example_line"] == 7
          and step["arg_kind"] == "data_table", str(matches))
    check("container witness is retained", matches["docker_env"] is True)
    index = {"errors": {}, "files": {"features/step_definitions/x.rb": {
        "definitions": [{"line": 4}]}}}
    check("bidirectional native/static location cross-check is exact",
          crosscheck(index, matches) == [], str(crosscheck(index, matches)))
    check("host-only matcher evidence is refused",
          any("container" in problem for problem in
              crosscheck(index, {**matches, "docker_env": False})))
    print("\n" + ("ALL PASS (rbstep_index)" if ok else
                   "FAILURES (rbstep_index)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
