"""S3 — the static index of a behave test tree, built by Python's own parser.

The twin of `r2t/php/analyze_php.php`, and deliberately much smaller, because
the two languages hand the benchmark different amounts of trouble.

**What PHP needed and Python does not.**  `analyze_php.php` runs inside the
container against the project's own `vendor/nikic/php-parser`, resolves `use`
aliases with a NameResolver pass, and records classes because a Behat context
IS a class and its collaborators arrive through a service container.  Python
ships `ast` in the standard library, so this runs on the host; behave has no
container, so there is no DI edge to index; and behave's unit is the MODULE —
`load_step_modules` execs every `.py` under `features/steps/` and whatever
decorators run register themselves.  A class is an implementation detail of a
step module here, never the thing that gets registered.

**What Python needs and PHP did not.**  behave puts the step directory on
`sys.path` (`runner_util.PathManager`) and its base directory too
(`Runner.setup_paths` → `self.path_manager.add(base_dir)`), then `exec`s each
module rather than importing it as a package.  So `from helpers import
test_docx` — a BARE module name, no package, no dots — is how the 21
python-docx step modules reach their shared helper, and resolving that name
against the right two directories is the whole of the code-edge story.  It is
also why a RELATIVE import (`from .helpers import …`) is recorded as a problem
rather than resolved: under `exec_file` there is no package for the dot to
mean anything, so such a module would fail to load at run time.

**What this index is FOR.**  Two things, and neither is matching:

1. the code edges `closure_py` expands over — file → file, one per resolved
   import;
2. a second, independent census of the step definitions, so that the
   registry's answer (467 registrations, taken in-container from behave
   itself) can be checked against the source (467 decorators, taken here).
   Matching is behave's job and is never done here — see `py/match_steps.py`
   and the `match_steps.php:2-19` rule it inherits.

The index is FILE-granular for the same reason `closure.py` is: what gets
removed, restored and scored is a file.
"""
from __future__ import annotations

import ast
import os
from typing import Iterable, Optional

#: The four step-decorator names behave installs, lower-cased.
#:
#: Taken from `behave.step_registry.setup_step_decorators`, which does
#: `run_context[step_type.title()] = run_context[step_type] = decorator` for
#: exactly these four — so `@given` and `@Given` are the same object and both
#: have to be recognised.  `step` is the keyword-agnostic one: a definition
#: registered under it answers a Given, a When AND a Then
#: (`find_step_definition` appends `self.steps["step"]` to every candidate
#: list), which is why it is a keyword in its own right here rather than an
#: alias of one.
STEP_DECORATORS: tuple[str, ...] = ("given", "when", "then", "step")

#: Where a behave step module's imports may resolve FROM, beyond the two
#: search directories: anything importable from the interpreter itself.
#: Recorded as `external` rather than followed, exactly as `closure.py`
#: records a production FQCN and stops.
_DUNDER_FUTURE = "__future__"


# --------------------------------------------------------------- extraction
class _ModuleVisitor(ast.NodeVisitor):
    """One module's imports, step decorators and module-level names.

    Written as a visitor over the TOP-LEVEL body only for the decorators, and
    over the whole tree for the imports.  The asymmetry is deliberate and it
    is behave's: `load_step_modules` execs the module, so a decorator inside
    an `if` or a `def` really would register a step — but a decorator inside a
    function body registers nothing until that function is called, and no
    step module in either corpus does either.  Recording only what runs at
    module level, and recording anything else as `dynamic_steps`, keeps the
    census honest: an unexplained gap between this count and the registry's
    is a finding, and quietly guessing would hide it.
    """

    def __init__(self) -> None:
        #: local name -> canonical behave decorator name
        self.decorator_aliases: dict[str, str] = {}
        #: local name -> the behave module it names (`behave`, `bh`, …)
        self.module_aliases: set[str] = set()
        self.imports: list[dict] = []
        self.steps: list[dict] = []
        self.dynamic_steps: list[dict] = []
        self.register_types: list[dict] = []
        self.matcher_switches: list[dict] = []
        self.defines: list[str] = []

    # -- imports ------------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            local = a.asname or a.name.split(".")[0]
            if a.name == "behave" or a.name.startswith("behave."):
                self.module_aliases.add(local)
            self.imports.append({"kind": "import", "module": a.name,
                                 "names": [], "level": 0, "line": node.lineno,
                                 "asname": a.asname})
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        names = [a.name for a in node.names]
        if mod == "behave" or mod.startswith("behave."):
            for a in node.names:
                if a.name.lower() in STEP_DECORATORS:
                    self.decorator_aliases[a.asname or a.name] = a.name.lower()
        self.imports.append({"kind": "from", "module": mod, "names": names,
                             "level": node.level, "line": node.lineno,
                             "asname": None})
        self.generic_visit(node)

    # -- module-level names -------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._maybe_step(node)

    def visit_AsyncFunctionDef(self, node) -> None:              # noqa: N802
        self._maybe_step(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:        # noqa: N802
        self.defines.append(node.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:            # noqa: N802
        for t in node.targets:
            if isinstance(t, ast.Name):
                self.defines.append(t.id)
        self.generic_visit(node)

    # -- calls that change what a pattern MEANS ------------------------------
    def visit_Call(self, node: ast.Call) -> None:                # noqa: N802
        name = _called_name(node.func)
        if name == "register_type":
            # behave's replacement for Behat's `@Transform`: a NAMED type
            # usable as `{value:Bool}` in any pattern registered afterwards.
            # The registry is global (`Matcher.TYPE_REGISTRY`), so the module
            # that calls this and the module whose pattern uses the name need
            # not be the same one — which is a code edge with no import behind
            # it, and the only one in this language that a plain import graph
            # would miss.  python-docx calls it zero times; `closure_py`
            # follows the edge anyway, because a corpus that does call it
            # would otherwise ship closures that cannot load.
            for kw in node.keywords:
                if kw.arg:
                    self.register_types.append({"name": kw.arg,
                                                "line": node.lineno})
        elif name in ("use_step_matcher", "step_matcher"):
            arg = node.args[0] if node.args else None
            self.matcher_switches.append({
                "matcher": arg.value if isinstance(arg, ast.Constant) else None,
                "line": node.lineno})
        self.generic_visit(node)

    # -- the step decorators -------------------------------------------------
    def _maybe_step(self, node) -> None:
        self.defines.append(node.name)
        # The line behave will REPORT for anything registered here.  A
        # `Matcher`'s `FileLocation` is built from the wrapped function's
        # `__code__.co_firstlineno`, and since Python 3.8 that is the line of
        # the function's FIRST DECORATOR, not of its `def` — which is why
        # `api.py`'s first definition is `features/steps/api.py:13` (the
        # `@given` line) while `ast` puts the `FunctionDef` at 14.  Two
        # decorators on one function therefore register two definitions at
        # ONE location, so the cross-check against the registry joins on sets
        # of `(file, registry_line)` rather than counting.
        registry_line = min([d.lineno for d in node.decorator_list]
                            + [node.lineno])
        for dec in node.decorator_list:
            found = self._classify_decorator(dec)
            if found is None:
                continue
            keyword, pattern = found
            entry = {"keyword": keyword, "func": node.name,
                     "line": dec.lineno, "registry_line": registry_line,
                     "def_line": node.lineno}
            if pattern is None:
                self.dynamic_steps.append(entry)
            else:
                entry["pattern"] = pattern
                self.steps.append(entry)
        self.generic_visit(node)

    def _classify_decorator(self, dec: ast.expr):
        """`(keyword, pattern|None)` for a behave step decorator, else None.

        `pattern is None` means "this IS a step decorator but its pattern is
        not a literal" — a case that must be counted, not skipped, because
        the registry will have a definition this index cannot name.
        """
        target = dec.func if isinstance(dec, ast.Call) else dec
        keyword: Optional[str] = None
        if isinstance(target, ast.Name):
            keyword = self.decorator_aliases.get(target.id)
        elif isinstance(target, ast.Attribute):
            base = target.value
            if isinstance(base, ast.Name) and base.id in self.module_aliases \
                    and target.attr.lower() in STEP_DECORATORS:
                keyword = target.attr.lower()
        if keyword is None:
            return None
        if not isinstance(dec, ast.Call):
            # `@given` with no pattern: behave would call the decorator
            # factory with the function as its pattern and raise.  Real, and
            # a defect in the source rather than here.
            return (keyword, None)
        if dec.args and isinstance(dec.args[0], ast.Constant) \
                and isinstance(dec.args[0].value, str):
            return (keyword, dec.args[0].value)
        return (keyword, None)


def _called_name(func: ast.expr) -> Optional[str]:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


# --------------------------------------------------------------- resolution
def _candidate_rels(module: str, search_paths: Iterable[str]) -> list[str]:
    """Repo-relative files a bare/dotted module name could name, in order.

    behave's own order: the step directories first (inserted at `sys.path[0]`
    by `runner_util.PathManager` inside `load_step_modules`), then the base
    directory (`Runner.setup_paths` adds it before the step modules load).
    Getting the order wrong would matter only for a project that shadows a
    name across the two, which is a thing to notice rather than to guess at.
    """
    parts = module.split(".")
    out: list[str] = []
    for root in search_paths:
        base = "/".join([root.rstrip("/")] + parts) if root else "/".join(parts)
        out.append(base + ".py")
        out.append(base + "/__init__.py")
    return out


def resolve_import(entry: dict, search_paths: Iterable[str],
                   known: set[str]) -> tuple[list[str], list[str]]:
    """`(files in the index, unresolved module names)` for one import.

    `from X import a, b` resolves X, and ALSO `X/a.py` and `X/b.py` — the
    from-import of a submodule is indistinguishable from the from-import of a
    name until the tree is on disk, and a missed submodule edge is a closure
    that cannot load.
    """
    if entry["level"]:
        # Relative import.  behave `exec`s step modules with no package, so
        # `from .helpers import x` raises ImportError at load time; recording
        # it as unresolved (and letting `build_index` report it as a problem)
        # is the honest answer.
        return ([], [("." * entry["level"]) + (entry["module"] or "")])
    mod = entry["module"]
    if not mod or mod == _DUNDER_FUTURE:
        return ([], [])
    files: list[str] = []
    unresolved: list[str] = []
    wanted = [mod]
    if entry["kind"] == "from":
        wanted += [f"{mod}.{n}" for n in entry["names"] if n != "*"]
    for name in wanted:
        hit = next((c for c in _candidate_rels(name, search_paths)
                    if c in known), None)
        if hit is not None:
            files.append(hit)
        elif name == mod:
            unresolved.append(name)
    return (files, unresolved)


# -------------------------------------------------------------------- index
def module_name_for(rel: str, search_paths: Iterable[str]) -> str:
    """The name a behave step module is IMPORTED as, from its path.

    `features/steps/helpers.py` under search path `features/steps` is
    `helpers` — bare, because behave puts the directory itself on `sys.path`
    rather than treating it as a package.  This is the value that goes into a
    closure's `context_classes`: the Behat field names the classes a
    synthesised suite has to register, and the behave answer to "what does
    this closure register" is the module import names.
    """
    rel = rel.replace(os.sep, "/")
    for root in sorted(search_paths, key=len, reverse=True):
        pre = root.rstrip("/") + "/"
        if root and rel.startswith(pre):
            inner = rel[len(pre):]
            break
    else:
        inner = rel
    if inner.endswith("/__init__.py"):
        inner = inner[: -len("/__init__.py")]
    elif inner.endswith(".py"):
        inner = inner[: -len(".py")]
    return inner.replace("/", ".")


def build_index(repo_root: str, paths: Iterable[str],
                search_paths: Optional[Iterable[str]] = None) -> dict:
    """Index every `.py` under `paths`, repo-relative, with its edges.

    `paths` are the trees the boundary calls test code — for python-docx,
    `features/steps` and `features/environment.py`.  Production code is NOT
    indexed and that is decision D4's "no pyprod index": the docx release
    renders `api_similarity` as `not_measured` rather than shipping a number
    derived from an index nobody built.
    """
    root = os.path.abspath(repo_root)
    search = list(search_paths) if search_paths is not None \
        else list(default_search_paths(paths))

    rels: list[str] = []
    for p in paths:
        full = os.path.join(root, p)
        if os.path.isfile(full):
            if full.endswith(".py"):
                rels.append(os.path.relpath(full, root).replace(os.sep, "/"))
            continue
        for dirpath, dirnames, files in os.walk(full):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            for f in sorted(files):
                if f.endswith(".py"):
                    rels.append(os.path.relpath(os.path.join(dirpath, f), root)
                                .replace(os.sep, "/"))
    rels = sorted(set(rels))
    known = set(rels)

    files: dict[str, dict] = {}
    errors: dict[str, str] = {}
    for rel in rels:
        with open(os.path.join(root, rel), encoding="utf-8",
                  errors="replace") as fh:
            src = fh.read()
        try:
            tree = ast.parse(src, filename=rel)
        except SyntaxError as e:
            errors[rel] = f"{type(e).__name__}: {e}"
            continue
        v = _ModuleVisitor()
        v.visit(tree)
        refs: list[str] = []
        external: list[str] = []
        problems: list[str] = []
        for entry in v.imports:
            hits, miss = resolve_import(entry, search, known)
            refs.extend(h for h in hits if h != rel)
            external.extend(miss)
            if entry["level"]:
                problems.append(
                    f"relative_import_line_{entry['line']}: behave execs step "
                    f"modules without a package, so this cannot load")
        files[rel] = {
            "module": module_name_for(rel, search),
            "imports": v.imports,
            "refs": sorted(set(refs)),
            "external": sorted(set(external)),
            "steps": v.steps,
            "dynamic_steps": v.dynamic_steps,
            "register_types": v.register_types,
            "matcher_switches": v.matcher_switches,
            "defines": sorted(set(v.defines)),
            "problems": problems,
        }

    return {
        "schema": "r2t.py_index/1",
        "root": root,
        "paths": list(paths),
        "search_paths": search,
        "files": files,
        "errors": errors,
        "counts": {
            "files": len(files),
            "step_definitions": sum(len(f["steps"]) for f in files.values()),
            "dynamic_step_definitions":
                sum(len(f["dynamic_steps"]) for f in files.values()),
            "register_types": sum(len(f["register_types"])
                                  for f in files.values()),
            "errors": len(errors),
        },
    }


def default_search_paths(paths: Iterable[str]) -> list[str]:
    """behave's two `sys.path` additions, derived from the indexed trees.

    A STEP DIRECTORY goes on the path inside `load_step_modules`
    (`with PathManager(step_paths)`, inserting at `sys.path[0]`), and behave's
    BASE DIRECTORY — the one holding `environment.py` and the `.feature`
    files — was already added by `Runner.setup_paths`.  So the step
    directories come FIRST, and the order is not cosmetic: a module name
    present in both resolves to whichever directory `sys.path` reaches
    first, and getting it backwards would draw an import edge to the wrong
    file (and, worse, to a RETAINED one, which expansion does not recurse
    into).  Directory arguments are step directories; a `.py` argument
    (`features/environment.py`) contributes only its parent.
    """
    dirs: list[str] = []
    parents: list[str] = []
    for p in paths:
        p = p.replace(os.sep, "/").rstrip("/")
        if p.endswith(".py"):
            parent = os.path.dirname(p)
            if parent and parent not in parents:
                parents.append(parent)
            continue
        if p and p not in dirs:
            dirs.append(p)
    for p in dirs:
        parent = os.path.dirname(p)
        if parent and parent not in parents:
            parents.append(parent)
    return dirs + [p for p in parents if p not in dirs]


def step_definition_locations(index: dict, include_dynamic: bool = True
                              ) -> set[tuple[str, int]]:
    """`(file, registry_line)` of every step decorator the SOURCE declares.

    Joined against the registry's own `FileLocation`s in
    `pystep_index.crosscheck`, which is the point of building it: two censuses
    of the same 467 definitions, one from Python's parser and one from
    behave's registry, and a location the registry reports that this set does
    not contain is a definition the closure extractor cannot attribute to a
    file it knows how to restore.

    `include_dynamic` is on by default because a decorator whose pattern is
    not a literal still REGISTERS: it belongs in the location census even
    though the index cannot say what it matches.
    """
    out: set[tuple[str, int]] = set()
    for rel, f in index["files"].items():
        entries = list(f["steps"])
        if include_dynamic:
            entries += list(f["dynamic_steps"])
        for s in entries:
            out.add((rel, s["registry_line"]))
    return out


# ----------------------------------------------------------------- selftest
def selftest() -> int:
    import tempfile
    import textwrap

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    with tempfile.TemporaryDirectory() as d:
        steps = os.path.join(d, "features", "steps")
        os.makedirs(steps)
        with open(os.path.join(d, "features", "environment.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("def before_all(context):\n    pass\n")
        with open(os.path.join(steps, "helpers.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("import os\n\n\ndef test_docx(name):\n    return name\n")
        with open(os.path.join(steps, "types.py"), "w",
                  encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""
                from behave import register_type


                def parse_bool(text):
                    return text == "True"


                register_type(Bool=parse_bool)
            """).lstrip())
        with open(os.path.join(steps, "font.py"), "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent('''
                """Steps."""

                from behave import given, then, when as w
                import behave

                from docx import Document
                from helpers import test_docx
                from environment import scratch_dir
                import types


                @given("a font")
                def given_a_font(context):
                    Document(test_docx("x"))


                @w("I assign {value} to font.bold")
                def when_assign(context, value):
                    pass


                @behave.then("font.bold is {value:Bool}")
                def then_bold(context, value):
                    pass


                @given(PATTERN)
                def given_dynamic(context):
                    pass
            ''').lstrip())
        with open(os.path.join(steps, "broken.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("def oops(:\n")

        # Argument order deliberately puts the FILE first, because that is
        # the order `pystep_index.index_paths_for` produces (it sorts, and
        # `features/environment.py` sorts before `features/steps`) and the
        # search path must come out step-directory-first regardless.
        idx = build_index(d, ["features/environment.py", "features/steps"])
        font = idx["files"]["features/steps/font.py"]

        check("the step directory searches BEFORE behave's base directory, "
              "whatever order the indexed trees were given in",
              idx["search_paths"] == ["features/steps", "features"],
              str(idx["search_paths"]))
        check("a bare-name import of a sibling step module is a code edge",
              "features/steps/helpers.py" in font["refs"], str(font["refs"]))
        check("an import of the RETAINED base-dir module resolves too -- "
              "behave puts `features/` on sys.path as well",
              "features/environment.py" in font["refs"], str(font["refs"]))
        check("a same-named stdlib module is shadowed by the step directory, "
              "the way behave's sys.path order shadows it",
              "features/steps/types.py" in font["refs"], str(font["refs"]))
        check("a third-party import is external, not an edge",
              "docx" in font["external"] and
              not any(r.endswith("docx.py") for r in font["refs"]),
              str(font["external"]))

        check("`@given(\"...\")` is a given", any(
            s["keyword"] == "given" and s["pattern"] == "a font"
            for s in font["steps"]), str(font["steps"]))
        check("an ALIASED decorator (`when as w`) is still a when", any(
            s["keyword"] == "when" and s["func"] == "when_assign"
            for s in font["steps"]), str(font["steps"]))
        check("a MODULE-qualified decorator (`@behave.then`) is still a then",
              any(s["keyword"] == "then" and s["func"] == "then_bold"
                  for s in font["steps"]), str(font["steps"]))
        check("a decorator whose pattern is not a literal is COUNTED as "
              "dynamic rather than silently skipped",
              [s["func"] for s in font["dynamic_steps"]] == ["given_dynamic"],
              str(font["dynamic_steps"]))
        check("the literal patterns are three, and the census says so",
              idx["counts"]["step_definitions"] == 3
              and idx["counts"]["dynamic_step_definitions"] == 1,
              str(idx["counts"]))

        types_f = idx["files"]["features/steps/types.py"]
        check("`register_type` is recorded with the NAME it registers -- the "
              "one code edge no import graph carries",
              [t["name"] for t in types_f["register_types"]] == ["Bool"],
              str(types_f["register_types"]))

        check("a module that does not parse is an ERROR, never an empty file",
              "features/steps/broken.py" in idx["errors"]
              and "features/steps/broken.py" not in idx["files"],
              str(idx["errors"]))

        check("module import names are BARE, as behave imports them",
              idx["files"]["features/steps/helpers.py"]["module"] == "helpers"
              and idx["files"]["features/environment.py"]["module"]
              == "environment")
        # The join key is the line behave's FileLocation will report, which is
        # the FIRST DECORATOR's line and not the `def`'s.  `@given("a font")`
        # sits on line 12 of the fixture and `def given_a_font` on 13.
        first = next(s for s in font["steps"] if s["func"] == "given_a_font")
        check("a step's registry line is its decorator's, not its def's -- "
              "that is what behave's FileLocation reports",
              first["registry_line"] == first["line"] == first["def_line"] - 1,
              str(first))
        check("step decorator locations are (file, registry_line) pairs for "
              "the registry cross-check, dynamic ones included",
              ("features/steps/font.py", first["registry_line"])
              in step_definition_locations(idx)
              and len(step_definition_locations(idx)) == 4,
              str(sorted(step_definition_locations(idx))))

        # A relative import is a LOAD failure under behave, so it must be a
        # recorded problem rather than a resolved edge.
        with open(os.path.join(steps, "rel.py"), "w", encoding="utf-8") as fh:
            fh.write("from .helpers import test_docx\n")
        idx2 = build_index(d, ["features/steps"])
        rel = idx2["files"]["features/steps/rel.py"]
        check("a relative import is refused as a problem, not resolved",
              rel["refs"] == [] and any("relative_import" in p
                                        for p in rel["problems"]),
              f"{rel['refs']} {rel['problems']}")

    print("\n" + ("ALL PASS (py.analyze_py)" if ok else "FAILURES (py.analyze_py)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
