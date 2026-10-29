"""Ruby's v2 Ripper producer/applier bound to the shared mutation contracts.

The native program owns engine and enumerator identity. Production manifests
require the B1 parser; network-free synthetic fixtures may use Ruby >= 3.0 and
always report their actual interpreter. No Ruby population is shipped here.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Iterable, Optional

from ..data import mutation as M

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RB_ENGINE_DIR = os.path.join(HERE, "ruby")
RB_SOURCE = os.path.join(RB_ENGINE_DIR, "mutate.rb")


def _source_constant(name: str) -> str:
    with open(RB_SOURCE, encoding="utf-8") as handle:
        match = re.search(r'^  ' + re.escape(name) + r' = "([^"\n]+)"$',
                          handle.read(), re.MULTILINE)
    if match is None:
        raise RuntimeError(f"Ruby mutation source has no simple {name} constant")
    return match.group(1)


ENGINE = _source_constant("ENGINE")
ENGINE_VERSION = _source_constant("ENGINE_VERSION")
ENUMERATOR_REV = _source_constant("ENUMERATOR_REV")
PARSER_VERSION = ("ripper stdlib; ruby 3.2.11 (2026-03-27 revision "
                  "5483bfc1ae) [x86_64-linux]")
DEFAULT_IMAGE = "sha256:df58279c613fb59500be4a53989d239b13c1dd257f7b292b47c9dce3117f6d96"
DEFAULT_PATHS: tuple[str, ...] = ("app", "lib")
EXCLUDED_PREFIXES: tuple[str, ...] = (
    "!app", "!lib", ".git/", "vendor/", "node_modules/", "_bench/", "tmp/",
    "log/", "coverage/", "app/assets/builds/", "public/assets/",
)
CONTAINER_ROOT = "/work"
CONTAINER_SCRATCH = "/r2t-mutate"


def applier():
    from ..bench.mutation_run import Applier
    return Applier(source="mutate.rb", rel="var/bench_mutate/mutate.rb",
                   interpreter="ruby")


def _docker(argv: list[str]) -> list[str]:
    from ..core.docker_cli import docker_argv
    return docker_argv(argv)


def _profile(value: str) -> None:
    if value != "v2":
        raise ValueError("REFUSED: Ruby supports only operator profile v2")


def probe_parser_version(image: str = DEFAULT_IMAGE, timeout: int = 300) -> str:
    argv = ["run", "--rm", "--pull=never", "--network", "none",
            "--entrypoint", "ruby", image, "-rripper", "-e",
            'puts "ripper stdlib; #{RUBY_DESCRIPTION}"']
    cp = subprocess.run(_docker(argv), capture_output=True, text=True,
                        timeout=timeout)
    if cp.returncode or cp.stdout.strip() != PARSER_VERSION:
        raise SystemExit(f"REFUSED: Ruby image parser differs from B1: "
                         f"rc={cp.returncode}, parser={cp.stdout.strip()!r}\n"
                         f"{cp.stderr[-800:]}")
    return cp.stdout.strip()


def enumerate_in_image(repo_root: str, paths: Iterable[str],
                       image: str = DEFAULT_IMAGE,
                       timeout: int = 1800, *,
                       record_enumerator_rev: bool = False,
                       operator_profile: str = "v2",
                       expected_enumerator_sha256: Optional[str] = None) -> dict:
    """Enumerate an immutable source mount offline through Docker authority.

    The Ruby entrypoint bypasses Rails/PG startup: only the parser is needed.
    Revision is always recorded; canonical callers also pin staged bytes.
    """
    _profile(operator_profile)
    if record_enumerator_rev and expected_enumerator_sha256 is None:
        raise ValueError("REFUSED: canonical enumeration requires staged "
                         "producer SHA-256")
    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT
    with tempfile.TemporaryDirectory(prefix="r2t-rb-mutate-") as scratch:
        staged = os.path.join(scratch, "mutate.rb")
        if expected_enumerator_sha256 is None:
            shutil.copyfile(RB_SOURCE, staged)
        else:
            AUDIT.stage_preserved_file(RB_SOURCE, staged,
                                      expected_enumerator_sha256,
                                      label="Ruby enumerator")
        inner = [f"{CONTAINER_SCRATCH}/mutate.rb", "--root", CONTAINER_ROOT,
                 "--out", f"{CONTAINER_SCRATCH}/raw.json",
                 "--operator-profile", "v2"]
        for path in paths:
            inner += ["--path", path]
        argv = ["run", "--rm", "--pull=never", "--network", "none",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--entrypoint", "ruby",
                "-v", f"{os.path.abspath(repo_root)}:{CONTAINER_ROOT}:ro",
                "-v", f"{scratch}:{CONTAINER_SCRATCH}",
                "-w", CONTAINER_ROOT, image, *inner]
        cp = subprocess.run(_docker(argv), capture_output=True, text=True,
                            timeout=timeout)
        if cp.stderr.strip():
            print(cp.stderr.strip())
        out = os.path.join(scratch, "raw.json")
        if not os.path.isfile(out):
            raise SystemExit(f"REFUSED: Ruby enumerator rc={cp.returncode}; "
                             f"no envelope\n{cp.stdout[-2000:]}\n"
                             f"{cp.stderr[-2000:]}")
        with open(out, encoding="utf-8") as handle:
            doc = json.load(handle)
        if cp.returncode:
            raise SystemExit(f"REFUSED: Ruby enumerator rc={cp.returncode}; "
                             f"file errors={doc.get('errors')!r}")
        return A.validate_enumerator_envelope(
            doc, expected_engine=ENGINE, expected_engine_version=ENGINE_VERSION,
            expected_parser_version=PARSER_VERSION,
            expected_enumerator_rev=ENUMERATOR_REV)


def production_only(raw: list, boundary) -> tuple[list, int]:
    from ..core.boundary import PRODUCTION
    kept = [row for row in raw
            if boundary.classify(M.normalise_path(row["file"])) == PRODUCTION]
    return kept, len(raw) - len(kept)


def build_population(raw: list, *, parser_version: str,
                     operators: Iterable[str] = M.OPERATORS,
                     exclusions: Iterable[str] = EXCLUDED_PREFIXES,
                     sample: Optional[int] = None, seed=None,
                     n_invalid: Optional[int] = None,
                     enumerator_rev: Optional[str] = None) -> dict:
    operators = tuple(operators)
    if operators != tuple(M.OPERATORS):
        raise ValueError("REFUSED: Ruby requires the complete ordered v2 profile")
    if parser_version != PARSER_VERSION or enumerator_rev != ENUMERATOR_REV:
        raise ValueError("REFUSED: Ruby population parser/revision differs "
                         "from reviewed B1 identity")
    return M.build_manifest(
        raw, parser_version=parser_version, operators=operators,
        exclusions=exclusions, engine=ENGINE, engine_version=ENGINE_VERSION,
        sample=sample, seed=seed, n_invalid=n_invalid,
        enumerator_rev=enumerator_rev)


def load_raw_doc(doc: dict) -> list:
    from ..data import mutation_attestation as A
    A.validate_enumerator_envelope(
        doc, expected_engine=ENGINE, expected_engine_version=ENGINE_VERSION,
        expected_parser_version=PARSER_VERSION,
        expected_enumerator_rev=ENUMERATOR_REV)
    return doc["mutants"]


def load_raw(path: str) -> list:
    with open(path, encoding="utf-8") as handle:
        return load_raw_doc(json.load(handle))


def population_for(doc: dict, boundary, boundary_name: str, *,
                   sample: Optional[int] = None, seed=None,
                   operators: Iterable[str] = M.OPERATORS) -> tuple[dict, int]:
    kept, non_production = production_only(load_raw_doc(doc), boundary)
    manifest = build_population(
        kept, parser_version=doc["parser"], operators=operators,
        sample=sample, seed=seed, n_invalid=doc.get("n_invalid"),
        enumerator_rev=doc["enumerator_rev"])
    manifest["exclusions"] += [f"non-production by {boundary_name}"]
    manifest["n_non_production_excluded"] = non_production
    manifest["digest"] = M.manifest_digest(manifest)
    return manifest, non_production


def cmd_mutants(args) -> int:
    """Ruby build/map dispatch through the unchanged shared manifest spine."""
    from ..core.boundary import load_boundary
    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT
    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))

    if args.action == "map":
        try:
            out_fd = AUDIT.reserve_output(
                args.out, input_paths=(args.manifest, args.coverage_run,
                                       getattr(args, "release", None),
                                       args.boundary))
        except A.MutationAssetRefused as exc:
            raise SystemExit(str(exc))
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = json.load(fh)
        if manifest.get("engine") != ENGINE:
            raise SystemExit(
                f"REFUSED: {args.manifest} was built by "
                f"{manifest.get('engine')!r}, not {ENGINE!r}. Its mutant ids "
                f"hash the other engine, so a map built from it would name "
                f"mutants this stack cannot apply.")
        cov = {}
        with open(args.coverage_run, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    row = json.loads(line)
                    if row.get("coverage_lines"):
                        if row["item_id"] in cov:
                            raise SystemExit(
                                "REFUSED: coverage run repeats item_id "
                                f"{row['item_id']!r}")
                        cov[row["item_id"]] = row["coverage_lines"]
        by_mutant, uncovered = M.map_mutants_to_items(manifest, cov)
        if getattr(args, "release", None):
            release_ids = A.load_release_ids(args.release)
            bad_items = sorted(
                {item for items in by_mutant.values() for item in items}
                - release_ids)
            if bad_items:
                raise SystemExit(
                    f"REFUSED: coverage map names item IDs outside --release, "
                    f"e.g. {bad_items[:3]}")
            payload = A.build_map_artifact(
                manifest, by_mutant, uncovered,
                coverage_sha256=A.sha256_file(args.coverage_run),
                release_sha256=A.sha256_file(args.release))
            A.validate_map(payload, manifest, release_ids=release_ids,
                           coverage_by_item=cov)
        else:
            payload = {"by_mutant": by_mutant, "uncovered": uncovered}
        AUDIT.write_reserved_json(out_fd, payload)
        print(json.dumps({"out": args.out, "mutants": manifest["n"],
                          "covered": len(by_mutant),
                          "uncovered": len(uncovered),
                          "items_with_coverage": len(cov)}, indent=1))
        return 0

    from ..bench.cli import _bound_container_image
    operator_profile = getattr(args, "operator_profile", "v2")
    _profile(operator_profile)
    operators = M.OPERATORS
    image = _bound_container_image(args.container)
    print(f"image_id: {image}")
    try:
        enumerator_identity = A.pinned_enumerator_identity("r2t/ruby/mutate.rb")
    except A.MutationAssetRefused as exc:
        raise SystemExit(str(exc)) from exc
    if enumerator_identity["enumerator_rev"] != ENUMERATOR_REV:
        raise SystemExit("REFUSED: Ruby registry and producer revision differ")
    expected_enumerator_rev = ENUMERATOR_REV
    try:
        build_outputs = [args.out] + ([args.raw_out]
                                      if getattr(args, "raw_out", None)
                                      else [])
        build_fds = AUDIT.reserve_outputs(
            build_outputs, input_paths=(args.boundary,))
        out_fd = build_fds[0]
        raw_out_fd = build_fds[1] if len(build_fds) == 2 else None
    except A.MutationAssetRefused as exc:
        raise SystemExit(str(exc))
    paths = list(args.path or DEFAULT_PATHS)
    doc = enumerate_in_image(
        b.repo_root, paths, image=image,
        record_enumerator_rev=True,
        operator_profile=operator_profile,
        expected_enumerator_sha256=enumerator_identity["sha256"])
    probed = probe_parser_version(image)
    try:
        doc = A.validate_enumerator_envelope(
            doc, expected_engine=ENGINE,
            expected_engine_version=ENGINE_VERSION,
            expected_parser_version=probed,
            expected_enumerator_rev=expected_enumerator_rev)
    except A.MutationAssetRefused as exc:
        # Keep the per-file witness visible as well as the fail-closed summary.
        errors = doc.get("errors") if isinstance(doc, dict) else None
        if isinstance(errors, dict):
            for rel, why in sorted(errors.items()):
                print(f"  PROBLEM: {rel}: {why}")
        raise SystemExit(str(exc))

    manifest, non_production = population_for(
        doc, b, os.path.basename(args.boundary),
        sample=args.sample, seed=args.seed, operators=operators)
    raw_manifest = None
    if getattr(args, "raw_out", None):
        raw_manifest = build_population(
            load_raw_doc(doc), parser_version=doc["parser"],
            sample=args.sample, seed=args.seed, n_invalid=doc.get("n_invalid"),
            enumerator_rev=doc["enumerator_rev"])
    AUDIT.write_reserved_json(out_fd, manifest)
    if raw_manifest is not None:
        AUDIT.write_reserved_json(raw_out_fd, raw_manifest)

    per_operator: dict = {}
    for m in manifest["mutants"]:
        per_operator[m["operator"]] = per_operator.get(m["operator"], 0) + 1
    summary = {"out": args.out, "n": manifest["n"],
               "n_excluded": manifest["n_excluded"],
               "n_non_production_excluded": non_production,
               "files": doc["files"],
               "digest": manifest["digest"],
               "engine": manifest["engine"],
               "parser": manifest["parser"],
               "per_operator": dict(sorted(per_operator.items()))}
    summary["image_id"] = image
    print(json.dumps(summary, indent=1))
    return 0


def selftest() -> int:
    """Compile and apply actual Ruby fixtures, without Rails, Docker or gems."""
    import pathlib
    ruby = os.environ.get("R2T_RUBY") or shutil.which("ruby")
    if not ruby:
        print("  [FAIL] Ruby >=3.0 required (or set R2T_RUBY)")
        return 1
    version = subprocess.run([ruby, "-e", "puts RUBY_VERSION"],
                             capture_output=True, text=True, timeout=30)
    if version.returncode or tuple(map(int, version.stdout.strip().split(".")[:2])) < (3, 0):
        print("  [FAIL] Ruby compiler must be >=3.0")
        return 1
    ok = True

    def check(name, condition):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}")
        ok = bool(condition) and ok

    def refused(fn):
        try:
            fn()
        except (ValueError, SystemExit):
            return True
        return False

    with tempfile.TemporaryDirectory(prefix="r2t-ruby-fixtures-") as scratch:
        root = pathlib.Path(scratch)
        (root / "app").mkdir()
        (root / "lib").mkdir()

        def run(*args):
            # Preserve Ruby launcher library variables; no subject is executed.
            return subprocess.run([ruby, RB_SOURCE, "--root", scratch, *args],
                                  capture_output=True, text=True, timeout=90)

        def enumerate_source(text, name="fixture.rb"):
            data = text.encode("utf-8") if isinstance(text, str) else text
            (root / "app" / name).write_bytes(data)
            result = run("--path", f"app/{name}")
            return result, json.loads(result.stdout)

        operators = '''def exercise(a, b)
  a += 2
  a -= 1.5
  a < b
  a <= b
  a > b
  a >= b
  a == b
  a != b
  a + b - 1 * 2 / 3 % 4
  true && false || true and false or true
  not !!a
  return a
end
exercise(1, 2)
'''
        cp, doc = enumerate_source(operators)
        rows = doc["mutants"]
        check("all eleven real Ruby operator families enumerate",
              cp.returncode == 0 and not doc["errors"]
              and {row["operator"] for row in rows} == set(M.OPERATORS))
        check("native engine identity and nonoptional v2 revision",
              doc["engine"] == ENGINE and doc["engine_version"] == ENGINE_VERSION
              and doc["enumerator_rev"] == ENUMERATOR_REV
              and doc["parser"].startswith("ripper stdlib; ruby ")
              and ENGINE != M.ENGINE)
        pairs = [(r["operator"], r["original"], r["mutated"]) for r in rows]
        check("comparison ties and exact direction replacements",
              ("ConditionalBoundary", "<", "<=") in pairs
              and ("NegateConditional", "<", ">=") in pairs
              and ("Increment", "+=", "-=") in pairs
              and ("Increment", "-=", "+=") in pairs
              and pairs.count(("RemoveNegation", "!", "")) == 2)
        check("canonical envelope ordering",
              rows == sorted(rows, key=lambda r: tuple(r[k] for k in (
                  "file", "start_line", "start_col", "end_line", "end_col", "operator"))))

        # Real project shape: Department passes a lambda body to facet.
        # Body statements keep eligibility when callbacks are values; ordinary
        # assigned/argument/parenthesized calls remain value-consuming.
        callback_source = """facet :all, -> { by_name }
callback = -> { ping }
callback2 = proc do
  pong
end
register(-> { nested }) do
  outer
end
value = consume(taken)
result = (begin; consumed; end)
"""
        cp, callbacks = enumerate_source(callback_source)
        removed = {r["original"] for r in callbacks["mutants"]
                   if r["operator"] == "MethodCallRemoval"}
        check("callback bodies in arguments and assignments keep statement eligibility",
              cp.returncode == 0 and not callbacks["errors"]
              and removed == {"facet :all, -> { by_name }", "by_name", "ping",
                              "pong", "register(-> { nested }) do\n  outer\nend",
                              "nested", "outer"})

        # The real e-petitions date-validator shape exposed a false second
        # binding that swallowed the surrounding begin keyword. Markers on
        # both sides distinguish that block from its first call without
        # choosing an arbitrary shortest span or widening eligibility.
        scoped_calls = """def validate(value)
  begin
    Date.parse(value.to_s)
  rescue ArgumentError
    record.errors.add(:date, :invalid)
  ensure
    cleanup
  end
end
def nested
  begin
    begin
      operation do
        inner
      end
    rescue Error
      recover
    end
  end
end
"""
        cp, scoped = enumerate_source(scoped_calls)
        scoped_removed = {r["original"] for r in scoped["mutants"]
                          if r["operator"] == "MethodCallRemoval"}
        check("calls inside begin/rescue/ensure and nested blocks bind their own complete spans",
              cp.returncode == 0 and not scoped["errors"]
              and scoped_removed == {"Date.parse(value.to_s)",
                  "record.errors.add(:date, :invalid)", "cleanup",
                  "operation do\n        inner\n      end", "inner", "recover"})

        # Petition#statistics uses `super || create_statistics!`; :zsuper
        # has no positional leaf. Empty hashes in the real controller/helper
        # defaults have the same geometry. Surround both with other leaves
        # so pruning must retain precisely the old legal intervals.
        calls = [f"operation_{i:03d}" for i in range(200)]
        cp, leafless = enumerate_source(
            "def many_statements\n" + "\n".join(calls[:100])
            + "\nsuper || create_statistics!\noptions = incoming || {}\n"
            + "\n".join(calls[100:]) + "\nend\n")
        check("leafless super and empty hash bind among unrelated source leaves",
              cp.returncode == 0 and not leafless["errors"]
              and [r["original"] for r in leafless["mutants"]
                   if r["operator"] == "MethodCallRemoval"] == calls
              and [(r["original"], r["mutated"]) for r in leafless["mutants"]
                   if r["operator"] == "LogicalConnector"] == [("||", "&&")] * 2)

        overloaded = "class Number\n def +(other); 1; end\n def <(other); true; end\nend\nNumber.new + Number.new\nNumber.new < Number.new\n"
        cp, overloads = enumerate_source(overloaded)
        check("overloaded-method declarations do not suppress operator syntax",
              cp.returncode == 0
              and [(r["operator"], r["original"]) for r in overloads["mutants"]
                   if r["operator"] in {"ArithmeticOperator", "ConditionalBoundary", "NegateConditional"}]
              == [("ArithmeticOperator", "+"), ("ConditionalBoundary", "<"), ("NegateConditional", "<")])
        shape_program = """require 'ripper'; require 'json'
shape = lambda { |n| n[0] == :binary ? [n[2], shape.call(n[1]), shape.call(n[3])] : n[1][1] }
puts JSON.generate(shape.call(Ripper.sexp_raw(STDIN.read)[1][2]))
"""
        for text, family, expected in (
                ("a || b && c", {"&&", "||"}, ["||", "a", ["&&", "b", "c"]]),
                ("a or b and c", {"and", "or"}, ["and", ["or", "a", "b"], "c"])):
            cp, chain = enumerate_source(text)
            replacements = [r for r in chain["mutants"] if r["operator"] == "LogicalConnector"]
            original_shape = subprocess.run([ruby, "-e", shape_program], input=text,
                                            text=True, capture_output=True, timeout=30)
            valid_shapes = []
            for row in replacements:
                candidate = text[:row["start_col"] - 1] + row["mutated"] + text[row["end_col"]:]
                parsed = subprocess.run([ruby, "-e", shape_program], input=candidate,
                                        text=True, capture_output=True, timeout=30)
                valid_shapes.append(json.loads(parsed.stdout) if parsed.returncode == 0 else None)
            check(f"native precedence and same-family single-token mutations {family}",
                  cp.returncode == 0 and json.loads(original_shape.stdout) == expected
                  and len(replacements) == 2
                  and all(r["original"] in family and r["mutated"] in family for r in replacements)
                  and all(shape is not None for shape in valid_shapes)
                  and all(shape != expected for shape in valid_shapes))

        geometry = '''def value
  return (
    build(1)
  )
end
obj&.call(
  "café", 2
)
emit "λ", 3,
  4
outer(1) do |x|
  inner(x) { ping }
end
send_text <<~TEXT
  café
TEXT
"é"; left < right
'''
        for ending in ("\n", "\r\n"):
            data = geometry.replace("\n", ending).encode()
            cp, geom = enumerate_source(data)
            check(f"complete expression geometry {ending!r}", cp.returncode == 0)
            originals = {r["original"] for r in geom["mutants"]
                         if r["operator"] in {"ReturnValue", "MethodCallRemoval"}}
            check(f"closing parentheses, command/block/heredoc ownership {ending!r}",
                  all(text.replace("\n", ending) in originals for text in (
                      "return (\n    build(1)\n  )", 'obj&.call(\n  "café", 2\n)',
                      'emit "λ", 3,\n  4', "outer(1) do |x|\n  inner(x) { ping }\nend",
                      "send_text <<~TEXT\n  café\nTEXT")))
            lines = data.splitlines(keepends=True)
            exact = True
            for row in geom["mutants"]:
                start = sum(map(len, lines[:row["start_line"] - 1])) + row["start_col"] - 1
                end = sum(map(len, lines[:row["end_line"] - 1])) + row["end_col"]
                exact &= data[start:end] == row["original"].encode()
                candidate = data[:start] + row["mutated"].encode() + data[end:]
                syntax = subprocess.run([ruby, "-c"], input=candidate,
                                        capture_output=True, timeout=30)
                exact &= syntax.returncode == 0
            comparison = next(r for r in geom["mutants"]
                              if r["operator"] == "ConditionalBoundary")
            check(f"byte-exact inclusive ranges and independently compiled candidates {ending!r}",
                  exact and comparison["start_col"] == len('"é"; left '.encode()) + 1)

        excluded = '''def declarations(a)
  a === 1
  a <=> 2
  a =~ /true + 3/
  a !~ /false - 4/
  a.eql?(1)
  a.equal?(2)
  a += other
  a -= -1
  a += "text"
  x = call_a(1)
  [call_b]
  {key: call_c}
  "#{call_d} true 123 +"
  :true
  :false
  :"literal + 123"
  0xff; 0b10; 0o10; 012; 1.5; 2r; 3i; ?a
  -1
  return
  return nil
  return()
  return ((nil))
  return call_e
end
call_f if condition
if condition_call
  body_call
else
  other_body_call
end
yield_call = -> { yield if false }
super_call = -> { super() }
'''
        cp, skipped = enumerate_source(excluded)
        removals = [r["original"] for r in skipped["mutants"]
                    if r["operator"] == "MethodCallRemoval"]
        check("value-consuming calls, conditions, modifiers and lexical lookalikes excluded",
              cp.returncode == 0 and removals == ["a.eql?(1)", "a.equal?(2)",
                                                  "body_call", "other_body_call"])
        check("bare/nil returns excluded; explicit return retained",
              [r["original"] for r in skipped["mutants"] if r["operator"] == "ReturnValue"]
              == ["return call_e"])
        check("nondecimal and noninteger tokens excluded; unary sign outside literal",
              not any(r["original"] in {"0xff", "0b10", "0o10", "012", "1.5", "2r", "3i", "?a", "-1"}
                      for r in skipped["mutants"] if r["operator"] == "ConstantReplacement")
              and not any(r["operator"] == "Increment" for r in skipped["mutants"]))
        cp, separators = enumerate_source("def f; return 1; end\na=1; a+b;\nf;\n")
        check("statement separators remain outside bound expressions", cp.returncode == 0
              and all(not r["original"].endswith(";") for r in separators["mutants"]))
        cp, empty = enumerate_source('def f\n return []\nend\nputs ""\n[] == {}\n')
        check("leafless literals bind uniquely", cp.returncode == 0
              and any(r["original"] == "return []" for r in empty["mutants"]))
        cp, returns = enumerate_source('''def f
 return build(1) do |x|
  inner(x)
 end
 return <<~TEXT
 body
TEXT
end
''')
        check("complete block and heredoc return values", cp.returncode == 0
              and [r["original"] for r in returns["mutants"] if r["operator"] == "ReturnValue"]
              == ["return build(1) do |x|\n  inner(x)\n end", "return <<~TEXT\n body\nTEXT"])
        invalid_source = "foo(a=1)\na /b\n"
        cp, invalid = enumerate_source(invalid_source)
        check("real lexical-local removal is syntax-invalid, not a span error",
              cp.returncode == 0 and invalid.get("n_invalid") == 1
              and invalid["files"] == 1 and not invalid["errors"]
              and not any(r["operator"] == "MethodCallRemoval" for r in invalid["mutants"]))
        invalid_apply = run("--apply-file", "app/fixture.rb", "--start-line", "1",
                            "--start-col", "1", "--operator", "MethodCallRemoval",
                            "--original", "foo(a=1)", "--mutated", "nil", "--out", "app/fixture.rb")
        check("selected syntax-invalid candidate refuses before in-place write",
              invalid_apply.returncode == 4 and "syntactically invalid" in invalid_apply.stderr
              and (root / "app/fixture.rb").read_text() == invalid_source)
        cp, ambiguous = enumerate_source("true\nf <<TEXT; other\nbody\nTEXT\n")
        check("unbound contiguous heredoc span makes a whole-file error, never partial rows",
              cp.returncode != 0 and ambiguous["files"] == 0
              and ambiguous["errors"] and ambiguous["mutants"] == [])
        for bad in (b"def broken(\n", b"true\rfalse\n", b'"\xff"\n'):
            cp, malformed = enumerate_source(bad)
            check(f"named parser/encoding refusal {bad!r}", cp.returncode != 0
                  and malformed["files"] == 0 and malformed["errors"]
                  and malformed["mutants"] == [])

        pristine = '"é"; value < 2\n'.encode()
        _, current = enumerate_source(pristine)
        row = next(r for r in current["mutants"] if r["operator"] == "ConditionalBoundary")

        def apply(descriptor, out="app/fixture.rb"):
            return run("--apply-file", "app/fixture.rb", "--start-line", str(descriptor["start_line"]),
                       "--start-col", str(descriptor["start_col"]), "--operator", descriptor["operator"],
                       "--original", descriptor["original"], "--mutated", descriptor["mutated"], "--out", out)

        target = root / "app/fixture.rb"
        applied = apply(row)
        check("applier accepts exact re-enumeration in place and preserves unrelated UTF-8 bytes",
              applied.returncode == 0 and target.read_bytes() == '"é"; value <= 2\n'.encode())
        before = target.read_bytes()
        check("stale descriptor refused before destination write", apply(row).returncode == 4
              and target.read_bytes() == before)
        target.write_bytes(pristine)  # The shared coordinator owns this restore.
        check("coordinator restoration is byte-for-byte", target.read_bytes() == pristine)
        wrong = dict(row, operator="ArithmeticOperator")
        check("wrong operator and forged replacement refused", apply(wrong).returncode == 4
              and apply(dict(row, mutated="???")).returncode == 4
              and target.read_bytes() == pristine)
        (root / "app/link.rb").symlink_to(target)
        cp = run("--path", "app/link.rb")
        check("symlink source refused", cp.returncode != 0 and "symlink" in cp.stdout)
        link = root / "app/output.rb"
        link.symlink_to(target)
        check("symlink output refused without touching target", apply(row, "app/output.rb").returncode == 4
              and target.read_bytes() == pristine)
        link.unlink()
        (root / "app/link.rb").unlink()
        (root / "app/notes.txt").write_text("not ruby")
        (root / "app/vendor_name.rb").write_text("true\n")
        (root / "app/assets/builds").mkdir(parents=True)
        (root / "app/assets/builds/excluded.rb").write_text("false\n")
        cp = run("--path", "app", "--path", "app/vendor_name.rb")
        all_doc = json.loads(cp.stdout)
        check("prefix exclusions, ignored suffixes, overlapping roots deduplicated",
              cp.returncode == 0 and all_doc["files"] == 2
              and {r["file"] for r in all_doc["mutants"]} == {"app/fixture.rb", "app/vendor_name.rb"})
        check("direct non-Ruby, path escape, outside keep root and v1 refused",
              run("--path", "app/notes.txt").returncode != 0
              and run("--path", "../escape.rb").returncode != 0
              and run("--path", "vendor").returncode != 0
              and run("--path", "app", "--operator-profile", "v1").returncode == 2)

        # These rows are synthetic arithmetic inputs, not collected populations.
        manifest = build_population(current["mutants"], parser_version=PARSER_VERSION,
                                    enumerator_rev=ENUMERATOR_REV)
        check("shared manifest identity, revision and digest", manifest["engine"] == ENGINE
              and manifest["enumerator_rev"] == ENUMERATOR_REV
              and manifest["digest"] == M.manifest_digest(manifest))
        check("manifest refuses foreign parser, revision and partial profile",
              refused(lambda: build_population([], parser_version="fixture", enumerator_rev=ENUMERATOR_REV))
              and refused(lambda: build_population([], parser_version=PARSER_VERSION, enumerator_rev="other"))
              and refused(lambda: build_population([], parser_version=PARSER_VERSION,
                                                   enumerator_rev=ENUMERATOR_REV, operators=M.OPERATORS_V1)))
        envelope = dict(current, parser=PARSER_VERSION)
        check("exact envelope enters the shared validator", load_raw_doc(envelope) == current["mutants"])
        check("file errors and missing revision refuse partial population",
              refused(lambda: load_raw_doc(dict(envelope, errors={"app/a.rb": "bad"})))
              and refused(lambda: load_raw_doc({k: v for k, v in envelope.items() if k != "enumerator_rev"})))
        from ..core.boundary import PRODUCTION, RETAINED

        class Boundary:
            def classify(self, file):
                return RETAINED if file == "app/fixture.rb" else PRODUCTION

        scored, count = population_for(envelope, Boundary(), "fixture-boundary.yml")
        check("boundary exclusion is counted and covered by shared digest", count == len(current["mutants"])
              and scored["n"] == 0 and scored["digest"] == M.manifest_digest(scored)
              and scored["exclusions"][-1] == "non-production by fixture-boundary.yml")
        check("applier stage stays outside hashed source roots", applier().source == "mutate.rb"
              and applier().rel == "var/bench_mutate/mutate.rb" and applier().interpreter == "ruby")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
