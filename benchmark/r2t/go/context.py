"""Pure, closed Go item context; no subject imports or framework execution.

GO_STACK_SPEC sections 3-5 own this carrier. Runtime context is a coordinator
snapshot of closures, never a selection made by submitted source or metadata.
"""
from __future__ import annotations

import json
import posixpath
import re
from types import MappingProxyType

SCHEMA = "r2t.go-suite-context/1"
HANDLER_FIELDS = ('file', 'line', 'start_byte', 'end_byte', 'name', 'kind', 'signature')
FIELDS = frozenset({
    "schema", "feature_path", "scenario_line", "glue_path", "package_dir",
    "package_name", "test_name", "suite_line", "go_build_expression",
    "go_build_tags", "godog_tags", "godog_tags_origin"})


class ContextRefused(ValueError):
    """Structural input failure, never an adapter failure or scored answer."""


def handler_identity(handler):
    """Original native handler identity, shared by attribution and census replay."""
    if not isinstance(handler, dict) or any(k not in handler for k in HANDLER_FIELDS):
        raise ContextRefused('Go interfaces requires exact native handler identity')
    result = {k: handler[k] for k in HANDLER_FIELDS}
    if any(type(result[k]) is not int for k in ('line', 'start_byte', 'end_byte')) \
            or result['line'] <= 0 or not 0 <= result['start_byte'] < result['end_byte'] \
            or result['kind'] not in ('function_or_method', 'function_literal') \
            or any(not isinstance(result[k], str) or not result[k] for k in ('file','name','signature')):
        raise ContextRefused('Go interfaces has invalid handler identity')
    return result


def _refuse(message: str):
    raise ContextRefused("REFUSED: Go suite context: " + message)


def is_go(record: dict) -> bool:
    return (record.get("framework") == "godog" or record.get("language") == "go"
            or "go_suite" in record
            or str(record.get("item_id", "")).startswith("coddy-agent/"))


def _path(value, field):
    if (not isinstance(value, str) or not value or value.startswith("/")
            or "\\" in value or any(ord(c) < 32 for c in value)
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        _refuse(f"{field} must be a normalized repository-relative POSIX path")
    return value


def _line(value, field):
    if type(value) is not int or value <= 0:
        _refuse(f"{field} must be a positive integer")


def validate_suite_context(context: dict) -> dict:
    """Validate only the closed carrier, without requiring a fabricated item."""
    if not isinstance(context, dict) or set(context) != FIELDS:
        _refuse("requires the closed go_suite object")
    if context["schema"] != SCHEMA:
        _refuse("unsupported schema")
    for field in ("feature_path", "glue_path", "package_dir"):
        _path(context[field], field)
    if not context["feature_path"].endswith(".feature"):
        _refuse("feature_path must name a .feature file")
    glue = context["glue_path"]
    if (not posixpath.basename(glue).startswith("bdd_")
            or not glue.endswith("_test.go")
            or posixpath.dirname(glue) != context["package_dir"]):
        _refuse("glue_path must name the original bdd_*_test.go in package_dir")
    for field in ("scenario_line", "suite_line"):
        _line(context[field], field)
    for field in ("package_name", "test_name"):
        if not isinstance(context[field], str) or not re.fullmatch(
                r"[A-Za-z_][A-Za-z_0-9]*", context[field]):
            _refuse(f"{field} must be a Go identifier")
    if not re.fullmatch(r"Test(?:[A-Z_0-9][A-Za-z_0-9]*)?", context["test_name"]):
        _refuse("test_name must name the original top-level Go test")
    for field in ("go_build_expression", "godog_tags"):
        if not isinstance(context[field], str) or any(
                ord(c) < 32 for c in context[field]):
            _refuse(f"{field} must be a single-line string")
    if context["go_build_tags"] not in ([], ["http"], ["cli"]):
        _refuse("go_build_tags must be [], ['http'], or ['cli']")
    origin = context["godog_tags_origin"]
    if (not isinstance(origin, dict) or set(origin) != {"kind", "line"}
            or not isinstance(origin["kind"], str)
            or origin["kind"] not in {"literal", "default", "linux_ansi_override"}):
        _refuse("godog_tags_origin must contain the reviewed kind and line")
    _line(origin["line"], "godog_tags_origin.line")
    return json.loads(json.dumps(context))


def validate_context(record: dict, *, boundary=None, project=None) -> dict:
    """Validate an admitted item or closure and return its detached context."""
    if not isinstance(record, dict):
        _refuse("item or closure must be an object")
    context = validate_suite_context(record.get("go_suite"))
    glue = context["glue_path"]
    selected_project = project or record.get("project") or "coddy-agent"
    if selected_project != "coddy-agent":
        _refuse("only coddy-agent is admitted to this context contract")
    for field, expected in (("project", selected_project), ("language", "go"),
                            ("framework", "godog")):
        if field in record and record[field] != expected:
            _refuse(f"{field} disagrees with the Go context")
    key = (context["feature_path"], context["scenario_line"])
    if record.get("item_id") != f"{selected_project}/{key[0]}:{key[1]}":
        _refuse("item_id disagrees with original feature/header identity")
    if "provenance" in record:
        provenance = record["provenance"]
        if not isinstance(provenance, dict) or (
                provenance.get("file_path"), provenance.get("line")) != key:
            _refuse("item provenance disagrees with original feature/header identity")
        _line(provenance.get("line"), "provenance.line")
        if record.get("task") != "criterion_to_test":
            _refuse("only admitted criterion items carry Go suite context")
    elif "feature_file" not in record:
        _refuse("record needs item provenance or closure feature identity")
    if "feature_file" in record:
        if (record["feature_file"], record.get("scenario_line")) != key:
            _refuse("closure disagrees with original feature/header identity")
        _line(record.get("scenario_line"), "closure.scenario_line")
    if "files" in record or "feature_file" in record:
        _answer_paths(record, context, boundary=boundary, project=selected_project)
    if boundary is not None:
        if boundary.project != selected_project or boundary.classify(glue) != "removable":
            _refuse("selected glue is not REMOVABLE under the project boundary")
    return json.loads(json.dumps(context))


def _answer_paths(record, context, *, boundary=None, project=None):
    files = record.get("files")
    if not isinstance(files, list) or not files:
        _refuse("requires a nonempty witnessed files path list")
    for path in files:
        _path(path, "files entry")
        if (not posixpath.basename(path).startswith("bdd_")
                or not path.endswith("_test.go") or any(c in path for c in "*?[]")):
            _refuse("answer files must name original BDD Go files")
    if len(files) != len(set(files)) or context["glue_path"] not in files:
        _refuse("answer files must be unique and include the primary glue")
    if boundary is not None and (boundary.project != project or any(
            boundary.classify(path) != "removable" for path in files)):
        _refuse("every answer file must be REMOVABLE under the project boundary")
    return tuple(sorted(files))


def answer_paths(record: dict, *, boundary=None, project=None) -> tuple[str, ...]:
    """Exact original paths carried from a witnessed closure, never source bytes."""
    context = validate_context(record, boundary=boundary, project=project)
    return _answer_paths(record, context, boundary=boundary,
                         project=project or record.get("project") or "coddy-agent")


def compare_context(left: dict, right: dict, *, boundary=None, project=None):
    """Require identical item/closure/sidecar context without adding authority."""
    a = validate_context(left, boundary=boundary, project=project)
    b = validate_context(right, boundary=boundary, project=project)
    if "files" in left and "files" in right and answer_paths(left) != answer_paths(right):
        _refuse(f"{left.get('item_id')!r}: item and closure/sidecar files differ")
    if a != b:
        _refuse(f"{left.get('item_id')!r}: item and closure/sidecar contexts differ")
    return a


class ContextTable:
    """Immutable closure snapshot used by the future Go harness facade."""

    def __init__(self, closures, *, boundary, project):
        contexts = {}
        files = {}
        for record in closures:
            if not isinstance(record, dict) or "feature_file" not in record:
                _refuse("runtime context table requires witnessed closure records")
            context = validate_context(record, boundary=boundary, project=project)
            key = context["feature_path"], context["scenario_line"]
            if key in contexts:
                _refuse(f"duplicate original feature/header key {key!r}")
            contexts[key] = json.dumps(context, sort_keys=True)
            files[key] = answer_paths(record, boundary=boundary, project=project)
        if not contexts:
            _refuse("a runtime harness requires a nonempty witnessed closure table")
        self._contexts = MappingProxyType(contexts)
        self._files = MappingProxyType(files)
        self._project = project

    def context_for(self, feature_path: str, scenario_line: int) -> dict:
        _path(feature_path, "feature_path")
        _line(scenario_line, "scenario_line")
        raw = self._contexts.get((feature_path, scenario_line))
        if raw is None:
            _refuse(f"no witnessed suite for {feature_path}:{scenario_line}")
        return json.loads(raw)

    def files_for(self, feature_path: str, scenario_line: int) -> tuple[str, ...]:
        """Immutable original-path set for the coordinator-selected item."""
        self.context_for(feature_path, scenario_line)
        return self._files[(feature_path, scenario_line)]

    def check_context(self, record: dict):
        context = validate_context(record, project=self._project)
        key = context["feature_path"], context["scenario_line"]
        if answer_paths(record) != self.files_for(*key):
            _refuse(f"{record.get('item_id')!r} files differ from the harness snapshot")
        if context != self.context_for(*key):
            _refuse(f"{record.get('item_id')!r} differs from the harness snapshot")


def preflight(harness, records):
    """Optional legacy-compatible seam, called before execution/generation effects."""
    check = getattr(harness, "check_context", None)
    for record in records:
        if check is not None:
            check(record)
        elif is_go(record):
            _refuse("Go harness does not implement check_context")


def canonical_item() -> dict:
    """Fixed metadata-only fixture for new Go prompt digests and tests."""
    context = {
        "schema": SCHEMA, "feature_path": "features/canonical.feature",
        "scenario_line": 1, "glue_path": "external/httpserver/bdd_hooks_test.go",
        "package_dir": "external/httpserver", "package_name": "httpserver",
        "test_name": "TestHooksTrustHTTPFeature", "suite_line": 242,
        "go_build_expression": "http", "go_build_tags": ["http"],
        "godog_tags": "@http", "godog_tags_origin": {"kind": "literal", "line": 248}}
    return {"files": [context["glue_path"]],
            "item_id": "coddy-agent/features/canonical.feature:1",
            "task": "criterion_to_test", "project": "coddy-agent",
            "language": "go", "framework": "godog",
            "provenance": {"file_path": context["feature_path"], "line": 1},
            "go_suite": context}


def selftest() -> int:
    """Network-free contract tests, including real shared preflight call sites."""
    import copy
    import os
    import tempfile
    from pathlib import Path
    from types import SimpleNamespace
    from unittest.mock import patch
    import yaml
    from ..core.boundary import Boundary
    from ..data import profile, prompt, release
    from ..bench import cli, fixtures, runner, validate
    from ..toolkit.release_build import build_release

    ok = True

    def check(name, condition):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}")
        ok = ok and bool(condition)

    def refuses(name, call, error=ContextRefused):
        try:
            call()
        except error:
            check(name, True)
        else:
            check(name, False)

    item = canonical_item()
    ctx = item["go_suite"]
    glue = ctx["glue_path"]
    boundary = Boundary(1, "coddy-agent", "/unused", removable=[(glue, "answer")])

    def closure(task):
        context = copy.deepcopy(task["go_suite"])
        return {"item_id": task["item_id"], "go_suite": context,
                "feature_file": context["feature_path"],
                "scenario_line": context["scenario_line"],
                "files": [context["glue_path"]], "di_fragment": {},
                "context_classes": [], "counts": {"steps_unmatched": 0}}

    cl = closure(item)
    check("closed suite validates without a fabricated item",
          validate_suite_context(ctx) == ctx)
    check("item and closure share original identity",
          compare_context(item, cl, boundary=boundary) == ctx)
    cases = [
        ("missing context", lambda x: x.pop("go_suite")),
        ("unknown nested field", lambda x: x["go_suite"].update(answer="leak")),
        ("unknown origin field", lambda x: x["go_suite"]["godog_tags_origin"].update(extra=1)),
        ("boolean header line", lambda x: x["go_suite"].update(scenario_line=True)),
        ("boolean provenance line", lambda x: x["provenance"].update(line=True)),
        ("escaping path", lambda x: x["go_suite"].update(glue_path="../bdd_x_test.go")),
        ("other package", lambda x: x["go_suite"].update(package_dir="internal/agent")),
        ("duplicate tags", lambda x: x["go_suite"].update(go_build_tags=["http", "http"])),
        ("unsupported tags", lambda x: x["go_suite"].update(go_build_tags=["ui"])),
        ("unknown origin", lambda x: x["go_suite"]["godog_tags_origin"].update(kind="ambient")),
        ("wrong feature", lambda x: x["provenance"].update(file_path="features/other.feature")),
        ("wrong task", lambda x: x.update(task="requirement_to_test")),
        ("wrong project", lambda x: x.update(project="python-docx")),
    ]
    for name, change in cases:
        bad = copy.deepcopy(item)
        change(bad)
        refuses(name, lambda: validate_context(bad, boundary=boundary))
    retained = Boundary(1, "coddy-agent", "/unused", retained=[(glue, "support")])
    refuses("retained glue refuses", lambda: validate_context(item, boundary=retained))
    helper = "external/httpserver/bdd_other_test.go"
    multi = dict(cl, files=[glue, helper])
    multi_boundary = Boundary(1, "coddy-agent", "/unused",
                             removable=[(glue, "answer"), (helper, "answer")])
    multi_item = dict(item, files=[helper, glue])
    multi_table = ContextTable([multi], boundary=multi_boundary, project="coddy-agent")
    check("multi-file original paths preserve primary context",
          validate_context(multi, boundary=multi_boundary) == ctx
          and multi_table.files_for(ctx["feature_path"], 1) == tuple(sorted([glue, helper])))
    multi_table.check_context(multi_item)
    for label, files in (("missing primary", [helper]), ("duplicate", [glue, glue]),
                         ("escape", [glue, "../bdd_x_test.go"]),
                         ("glob", [glue, "external/httpserver/bdd_*_test.go"]),
                         ("retained", [glue, "external/httpserver/helper_test.go"]),
                         ("non-BDD", [glue, "external/httpserver/production.go"])):
        refuses(label + " closure paths refuse", lambda files=files:
                answer_paths(dict(multi, files=files), boundary=multi_boundary))
    refuses("runtime rejects a missing sibling", lambda: multi_table.check_context(item))
    no_paths = dict(item); no_paths.pop("files")
    check("bootstrap context does not invent a closure", validate_context(no_paths) == ctx)
    refuses("candidate task requires witnessed files", lambda: release.task_view(no_paths))
    refuses("runtime requires witnessed files", lambda: multi_table.check_context(no_paths))
    multi["files"].clear()
    check("witnessed path snapshot is detached", len(multi_table.files_for(ctx["feature_path"], 1)) == 2)
    multi_view = release.task_view(multi_item)
    multi_view["files"].clear()
    check("task path projection is detached", len(multi_item["files"]) == 2)
    check("non-Go unknown files remain withheld", "files" not in release.task_view(
          {"item_id": "other/item", "files": ["secret"]}))
    refuses("items cannot substitute for witnessed closure inputs", lambda: ContextTable(
        [item], boundary=boundary, project="coddy-agent"))
    table = ContextTable([cl], boundary=boundary, project="coddy-agent")
    cl["go_suite"]["go_build_tags"].clear()
    detached = table.context_for(ctx["feature_path"], 1)
    detached["godog_tags_origin"]["kind"] = "default"
    check("snapshot detaches nested input and returned data",
          table.context_for(ctx["feature_path"], 1) == ctx)
    cl = closure(item)
    refuses("duplicate original key refuses", lambda: ContextTable(
        [cl, cl], boundary=boundary, project="coddy-agent"))
    bad = copy.deepcopy(item)
    bad["go_suite"]["godog_tags"] = "@other"
    refuses("same item with a changed filter refuses", lambda: table.check_context(bad))
    refuses("unknown original key refuses", lambda: table.context_for("features/no.feature", 1))
    refuses("absent Go harness seam refuses", lambda: preflight(object(), [item]))
    preflight(object(), [{"item_id": "old/item:1"}])
    check("old harness needs no context method", True)

    # The closed task projection withholds retrieval provenance and takes a copy.
    exported_item = copy.deepcopy(item)
    exported_item["provenance"].update(repo_url="https://invalid/answer", commit="secret")
    exported_item.update(reference_scenarios=["answer"], unknown="answer")
    view = release.task_view(exported_item)
    check("task export retains context but withholds answers and retrieval identity",
          view["go_suite"] == ctx and "unknown" not in view
          and "reference_scenarios" not in view and "repo_url" not in view["provenance"]
          and "commit" not in view["provenance"])
    view["go_suite"]["go_build_tags"].clear()
    check("task projection cannot mutate original nested context",
          exported_item["go_suite"] == ctx)

    with tempfile.TemporaryDirectory(prefix="go-context-") as directory:
        root = Path(directory)
        # A temporary schema witness, not a new admitted profile or digest freeze.
        original = profile.load_profile(os.path.join(profile.CONFIG_DIR, "profile_behave_example.yml"))
        doc = copy.deepcopy(original.raw)
        doc.update(project="coddy-agent", language="go", language_label="Go",
                   framework="godog", boundary="boundary.yml")
        doc["submission"].update(acceptance_mode="item_path", example_path=glue,
                                 example_code="package httpserver", suffixes=[".go"],
                                 retained_note="`external/httpserver/helper_test.go` remains")
        doc["submission"].pop("acceptance_root")
        doc["submission"].pop("placement_hint", None)
        boundary_doc = {"version": 1, "project": "coddy-agent", "repo_root": directory,
                        "removable": [{"path": glue}],
                        "retained": [{"path": "external/httpserver/helper_test.go"}]}
        (root / "boundary.yml").write_text(yaml.safe_dump(boundary_doc))
        profile_path = root / "profile.yml"

        def load_doc(document):
            profile_path.write_text(yaml.safe_dump(document))
            return profile.load_profile(str(profile_path), verify_digests=False)

        go_profile = load_doc(doc)
        check("item_path omits root and accepts the exact removable example",
              go_profile.acceptance_root is None and go_profile.acceptance_mode == "item_path")
        refuses("item_path cannot advertise a directory", go_profile.acceptance_prefix,
                profile.ProfileError)
        for label, change in (
            ("explicit null root", lambda d: d["submission"].update(acceptance_root=None)),
            ("directory root", lambda d: d["submission"].update(acceptance_root="external/")),
            ("foreign framework", lambda d: d.update(framework="behave")),
            ("retained example", lambda d: d["submission"].update(example_path="external/httpserver/helper_test.go")),
            ("false retained promise", lambda d: d["submission"].update(retained_note="`external/no.go` remains")),
            ("unknown mode", lambda d: d["submission"].update(acceptance_mode="glob")),
        ):
            broken = copy.deepcopy(doc)
            change(broken)
            refuses(label, lambda: load_doc(broken), profile.ProfileError)
        go_profile = load_doc(doc)
        actual = prompt.build_user_prompt(item, go_profile)
        base = prompt.agent_prompt_base(go_profile)
        check("Go placement overrides the example and states both independent filters",
              f"repo/{glue}" in actual and ctx["test_name"] in actual
              and 'Go build tags: ["http"]' in actual and 'Godog tag expression: "@http"' in actual
              and "overrides" in actual and "those directories" not in base)
        prompt_multi = dict(item, files=[glue, helper])
        multi_doc = copy.deepcopy(boundary_doc)
        multi_doc["removable"].append({"path": helper})
        (root / "boundary.yml").write_text(yaml.safe_dump(multi_doc))
        rendered_multi = prompt.build_user_prompt(prompt_multi, go_profile)
        check("multi-file prompt names every original path and keeps primary suite",
              all("repo/" + path in rendered_multi for path in prompt_multi["files"])
              and ctx["test_name"] in rendered_multi and "Every listed file is required" in rendered_multi)
        (root / "boundary.yml").write_text(yaml.safe_dump(boundary_doc))
        refuses("profile refuses missing witnessed file list",
                lambda: profile.check_item(go_profile, no_paths), profile.ProfileError)
        check("new canonical fixture is coherent without changing old canonical input",
              prompt.canonical_task(original) is prompt.CANONICAL_TASK
              and prompt.canonical_task(go_profile)["go_suite"] == ctx
              and "go_suite" not in prompt.CANONICAL_TASK)
        for key in profile.PROMPT_KEYS:
            rendered = prompt.canonical_prompt(go_profile, key)
            check(f"new {key} prompt renders without directory fallback", bool(rendered))
            if key != "single_shot":
                check(f"Go {key} prompt discloses validated retained helpers",
                      go_profile.retained_note in rendered)
        with patch.object(profile, "load_profile", return_value=go_profile):
            contract = release.task_contract("coddy-agent", str(profile_path))
        check("task contract declares exact selector and no directory root",
              contract["acceptance_mode"] == "item_path"
              and contract["acceptance_path"] == "files"
              and "acceptance_root" not in contract)
        refuses("profile rejects missing admitted context",
                lambda: profile.check_item(go_profile, dict(item, go_suite=None)), profile.ProfileError)

        # Every runtime preflight stops before downstream reads, writes or adapters.
        class Reject:
            def check_context(self, record):
                raise ContextRefused("test refusal")

        rejects = Reject()
        output = root / "untouched.jsonl"
        output.write_text("keep\n")
        refuses("run_one checks before reading feature or preparing workspace",
                lambda: runner.run_one(rejects, None, item))
        refuses("validate_item checks before feature or empty/gold execution",
                lambda: validate.validate_item(rejects, "missing", cl))
        refuses("validate_all checks before deleting an existing output",
                lambda: validate.validate_all(rejects, "missing", [cl], str(output), resume=False))
        check("validation output survived structural refusal", output.read_text() == "keep\n")
        args = SimpleNamespace(release="missing", item=[], limit=None)
        with patch.object(runner, "_load_release", return_value=[item]), \
                patch.object(cli, "_boundary", return_value=boundary), \
                patch.object(cli, "_harness", return_value=(rejects, boundary, None)), \
                patch.object(runner, "build_adapter") as build:
            refuses("cmd_generate preflights before adapter construction",
                    lambda: cli.cmd_generate(args))
            check("generation adapter was never constructed", not build.called)
        args = SimpleNamespace(release="missing", item=[], limit=None, adapter="empty")
        rejects.boundary = boundary
        with patch.object(runner, "_load_release", return_value=[item]), \
                patch.object(runner, "validate_submitted_project"), \
                patch.object(runner, "_bind_submitted_population"), \
                patch.object(runner, "build_adapter") as build, \
                patch.object(runner, "_run_output_path") as out:
            refuses("run preflights before adapter construction or runlog selection",
                    lambda: runner._run_adapter_locked(rejects, args, directory))
            check("run adapter and output were untouched", not build.called and not out.called)

        gold_dir = root / "gold"
        gold_dir.mkdir()
        (gold_dir / "manifest.json").write_text(json.dumps({item["item_id"]: "one.json"}))
        bad_cl = closure(bad)
        (gold_dir / "one.json").write_text(json.dumps(bad_cl))
        refuses("gold sidecar preflight precedes source reads",
                lambda: fixtures.make_gold_adapter(directory, "missing",
                                                   context_check=table.check_context))
        (gold_dir / "one.json").write_text(json.dumps(cl))
        (root / "release.jsonl").write_text(json.dumps(bad) + "\n")
        refuses("gold builder checks release/sidecar join before adapter use",
                lambda: fixtures._build_gold(SimpleNamespace(
                    release=str(root / "release.jsonl"), gold="missing"), table))
        (gold_dir / "manifest.json").write_text("{}")
        refuses("missing Go gold sidecar refuses during construction",
                lambda: fixtures.make_gold_adapter(directory, "missing",
                    context_check=table.check_context, items=[item]))
        (gold_dir / "manifest.json").write_text(json.dumps({item["item_id"]: "one.json"}))
        gold_source = root / "source" / glue
        gold_source.parent.mkdir(parents=True)
        gold_source.write_text("package httpserver\n")
        gold = fixtures.make_gold_adapter(directory, str(root / "source"),
                                         context_check=table.check_context)
        # Mutation after construction cannot swap the checked sidecar metadata.
        (gold_dir / "one.json").write_text(json.dumps(bad_cl))
        check("gold serves bytes using its checked sidecar snapshot",
              gold(item)["files"] == [{"file_path": glue, "code": "package httpserver\n"}])
        refuses("gold task mismatch refuses before source reads", lambda: gold(bad))

        items_path = root / "items.jsonl"
        items_path.write_text(json.dumps(item) + "\n")
        (root / "closures.json").write_text(json.dumps([cl]))
        (root / "quality.json").write_text(json.dumps({item["item_id"]: {
            "has_oracle": True, "live_effective_step_count": 3}}))
        (root / "validation.jsonl").write_text(json.dumps({
            "item_id": item["item_id"], "admitted": True, "seconds": 0}) + "\n")
        assembled = root / "assembled"
        result = build_release(directory, str(items_path), str(assembled), project="coddy-agent")
        released = json.loads((assembled / release.DEFAULT_ITEMS_NAME).read_text())
        sidecar = release.load_gold(str(assembled), item["item_id"])
        check("assembly preserves item and explicit gold-sidecar context",
              result["included"] == 1 and released["go_suite"] == ctx and sidecar["go_suite"] == ctx
              and released["files"] == sidecar["files"] == [glue])
        bootstrap = dict(item); bootstrap.pop("files")
        items_path.write_text(json.dumps(bootstrap) + "\n")
        (root / "closures.json").write_text(json.dumps([dict(cl, files=[glue, helper])]))
        multi_out = root / "multi-assembled"
        build_release(directory, str(items_path), str(multi_out), project="coddy-agent")
        multi_release = json.loads((multi_out / release.DEFAULT_ITEMS_NAME).read_text())
        check("release derives all answer paths from witnessed closure",
              multi_release["files"] == sorted([glue, helper])
              and set(release.load_gold(str(multi_out), item["item_id"])["files"]) == {glue, helper})
        from .. import cli as composed_cli
        targets = {"behaviour": ["example.org/project.Service"], "setup": []}
        (root / "interfaces.json").write_text(json.dumps({
            "schema": "r2t.interfaces/1", "items": [{"item_id": item["item_id"],
                "target_interfaces": targets}]}))
        cli_out = root / "cli-assembled"
        config = Path(__file__).resolve().parents[2] / "config"
        assert composed_cli.main([
            "--boundary", str(config / "boundary_coddy_agent.yml"),
            "--artifacts", directory, "release", "--items", str(items_path),
            "--out", str(cli_out), "--min-live-steps", "2"]) == 0
        cli_item = json.loads((cli_out / release.DEFAULT_ITEMS_NAME).read_text())
        check("real release CLI keeps Go target interfaces and multi-file native context",
              cli_item["target_interfaces"] == targets
              and cli_item["files"] == sorted([glue, helper])
              and cli_item["go_suite"] == ctx)
        items_path.write_text(json.dumps(dict(item, files=[glue])) + "\n")
        refuses("release refuses item/closure path-set mismatch",
                lambda: build_release(directory, str(items_path), str(root / "bad-paths"), project="coddy-agent"))
        (root / "closures.json").write_text(json.dumps([bad_cl]))
        refuses("assembly refuses context mismatch before writing item output",
                lambda: build_release(directory, str(items_path), str(root / "refused"),
                                      project="coddy-agent"))
        check("mismatched assembly has no item output", not (root / "refused" / release.DEFAULT_ITEMS_NAME).exists())
        bad_export = root / "bad-items.jsonl"
        bad_export.write_text(json.dumps(dict(item, go_suite=None)) + "\n")
        refuses("task export validates before replacing output",
                lambda: release.export_tasks(str(bad_export), str(output)))
        check("export output survived structural refusal", output.read_text() == "keep\n")

    print("\n" + ("ALL PASS" if ok else "FAILURES") + " (go context)")
    return 0 if ok else 1


if __name__ == "__main__":
    from r2t.go.context import selftest
    raise SystemExit(selftest())
