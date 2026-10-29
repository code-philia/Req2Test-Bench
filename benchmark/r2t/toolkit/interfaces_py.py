"""Target interfaces -- the declared interaction surface, per item
(TARGET_INTERFACES_SPEC section 3), for Python/behave.

The twin of `toolkit/interfaces.py`, and the shape of the answer is the same:
for one item, the first-party production symbols that the reference step
definitions bound to the item's OWN steps *declare* they interact through,
after the same two filters (F1 the project's own production index, F2 the
reviewed boundary), in the same two labelled lists (spec D1, owner ruling
2026-09-03: `behaviour` is the surface of the scenario's own steps, `setup`
is what Background-origin steps add beyond it).  `ItemInterfaces`, the
refusal type, the artifact schema, the writer and the summary are IMPORTED
from `interfaces.py`, not re-declared: one artifact shape, one reader.

What is different is the language, and it is different in three ways.

**There is no per-function index to read.**  `interfaces.py` gets T1/T2/T3
handed to it by `php_index.json`, because `analyze_php.php` records each step
method's parameter types, return type and `$this->` references.  The Python
side's `py/analyze_py.py` is deliberately module-granular -- it records a
module's imports, its decorators and its module-level names, and does no
per-function pass at all (that file's own docstring says so).  So this module
does the per-function pass itself, with `ast`, over the step sources at the
pinned commit; the repo root is therefore an input where the PHP twin takes
an index path.  Nothing is approximated to cover the gap and nothing new is
persisted: the pass is a pure function of bytes the corpus already pins.

**The unit is a dotted name, and the signal is the import binding.**  A Behat
context receives collaborators through a container; a behave step function
receives everything on `context` and reaches production through MODULE-LEVEL
IMPORTS.  So the declared surface of a step function is the set of production
symbols its body (and its parameter/return annotations, which are
declarations) names through a binding that an `import` statement created:

    from docx.table import Table   ; Table(...)             -> docx.table.Table
    import docx                    ; docx.document.Document -> docx.document.Document
    from docx.shared import RGBColor; RGBColor.from_string  -> docx.shared.RGBColor

An attribute chain is taken WHOLE (its outermost `Attribute` node, never its
own prefixes as separate references) and then collapsed to the longest prefix
that resolves in the production index, which is what keeps method names and
enum MEMBERS off the list without a special case for either.  Depth is zero:
no flow analysis over `context.<attr>` (spec 4.3 measured that a within-
scenario flow rule adds no symbol to any scenario's set and that pyright
resolves 17 of 18 probed receivers to `Any`), no descent into the removable
`helpers` module, no expansion into production, no sibling scenarios, no
frequency statistic, no hand list.

**Corpus evidence predates the index-reader repair (#403).**  Owner ruling
D2(a) ships python-docx's type-level list.  The historical measurements in
this docstring and `TARGET_INTERFACES_PILOT_EVALUATION.md` section 3 have not
been recomputed with the corrected reader.  Their near-constancy finding is
provisional until extraction is rerun from the preserved inputs, before
final Python annotation collection.  The naming decisions below are
unchanged; their corpus counts describe the pre-fix evidence.

DECISIONS taken where the rule is ambiguous on a real case in this corpus.
Each is a naming decision only; none of them changes which step functions are
read or which references are seen.

D-a  *A reference is a maximal attribute chain.*  `docx.document.Document`
     is one reference naming one symbol, not three references naming `docx`,
     `docx.document` and `docx.document.Document`.  Reading every sub-chain
     as its own reference is what the section-4.3 scratch pass did, and it is
     the single largest cause of the difference between its figures and
     these (REPORT.md).

D-b  *`from docx import Document` names `docx`, not `docx.Document`.*  F1 is
     "resolves in the production index", and `py_prod_index.json` is built by
     `ast` from `def`/`class` statements, so `docx/__init__.py` contributes
     the module `docx` and its one module-level function
     `part_class_selector` -- not the `Document` it RE-EXPORTS from
     `docx.api`.  `docx.Document` is therefore a module-level function the
     index does not list, and the rule's own fallback applies: the bare
     module, which does resolve.  Following the re-export would mean parsing
     production sources, which is expansion into production at depth > 0, and
     it would also produce a member that spec 7.1's "every member passes F1,
     re-checked from the artifact" cannot re-check.  639 references collapse
     this way; `docx.Document` is kept as a candidate (D-f), so the decision
     is auditable from the artifact.

D-c  *A module-level ALIAS collapses to its module for the same reason.*
     `WD_ALIGN_PARAGRAPH = WD_PARAGRAPH_ALIGNMENT` (docx/enum/text.py:67),
     `WD_ORIENT`, `WD_SECTION`, `MSO_THEME_COLOR` are assignments, not class
     statements, so the index does not list them and
     `docx.enum.text.WD_ALIGN_PARAGRAPH` collapses to `docx.enum.text`.  This
     is a real loss of precision -- the canonical class IS in the index --
     and REPORT.md names the 5 aliases, the 4 items affected and the one-line
     index change that would close it.  It is reported rather than patched
     because resolving an alias is a production-side pass this rule does not
     have.

D-d  *Decorators are not the body; annotations are.*  `@given("...")` is the
     registration, not the interaction surface, and `given` is a `behave`
     name that F1 would drop anyway; excluding the decorator list keeps it
     out of `candidates` too.  Parameter annotations and the return
     annotation ARE declarations and are read (the analogue of the PHP T1 and
     T2).  Measured: they contribute `behave.runner.Context` and `str` and no
     first-party symbol, exactly as spec 4.3 says.

D-e  *A name the function rebinds is not an import binding.*  A parameter,
     assignment target, `for`/`with` target or nested `def` of the same name
     shadows the module-level import for the whole function, so it is not a
     reference to the imported symbol.  Measured on this corpus: 0 of 470
     step functions rebind an imported name, so the rule is a no-op here and
     is written because it is what "references through import bindings"
     means, not to guard a case this corpus produces.

D-f  *`candidates` names what was touched at the rule's own unit, before
     both filters.*  In the PHP twin no collapse happens, so `candidates` is
     a superset of the list and F1 and F2 are visible as the difference;
     here the collapse is lossy, so storing the collapsed name would destroy
     exactly what spec 7.2's rater has to see -- that the step reached
     `Document`, not merely `docx`.  So a candidate is the chain cut to
     `module.Symbol` (spec 3.1's unit): the longest prefix that is a MODULE
     in the index, plus at most one further segment.  `docx.Document`,
     `docx.enum.text.WD_ALIAS` and `docx.shared.RGBColor` are candidates;
     `.CENTER` and `.from_string` are not, so no method or member identifier
     enters the artifact on either side (spec 5.4).  A chain whose root the
     index does not know is kept verbatim (`behave.runner.Context`,
     `helpers.test_docx`, `os.path.join`), because there is no module to cut
     it at and the rater is entitled to see it.  `behaviour` is therefore
     NOT a subset of `candidates` on this stack -- `docx.Document` is a
     candidate and `docx` is the member -- and that is the collapse being
     legible rather than a schema drift.  A chain rooted in a name no import
     bound -- a builtin, a local, `context` -- is not a reference at all and
     appears nowhere.

REFUSALS (spec section 8), in the PHP twin's style: a production index built
from a different repo root, a bound step module absent from the pinned tree,
and a bound function the module does not define at module level.  An empty
list is a value, not a failure.
"""
from __future__ import annotations

import ast
import os
from typing import Optional

from ..core.boundary import PRODUCTION, REMOVABLE, Boundary, load_boundary
from ..py.prod_index import module_name
from .interfaces import (EMPTY_NO_DECLARATION, EMPTY_NO_MEMBER, SCHEMA,
                         InterfacesError, ItemInterfaces, extract_all,
                         summary, write_interfaces)

__all__ = ["EMPTY_NO_DECLARATION", "EMPTY_NO_MEMBER", "SCHEMA",
           "InterfacesError", "ItemInterfaces", "PyInterfaceExtractor",
           "extract_all", "load_extractor", "summary", "write_interfaces"]

#: `from __future__ import annotations` binds nothing a body can reference.
_FUTURE = "__future__"


class _StepModule:
    """One step module's module-level import bindings and its functions.

    `bindings` maps the LOCAL name a body would write to the dotted name the
    import statement bound it to (`Table` -> `docx.table.Table`, `docx` ->
    `docx`, `dt` -> `datetime`).  `functions` holds the module-level `def`s
    by name, which is the granularity the closure binds at: behave registers
    a FUNCTION, and `definition.method` is its name.
    """

    def __init__(self, tree: ast.Module):
        self.bindings: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for a in node.names:
                    # `import a.b` binds `a`; `import a.b as c` binds `c` to a.b.
                    self.bindings[a.asname or a.name.split(".")[0]] = (
                        a.name if a.asname else a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level or not node.module or node.module == _FUTURE:
                    # A relative import cannot resolve under behave's
                    # `exec_file` loader at all (`py/analyze_py.py` records it
                    # as a problem rather than resolving it), and nothing this
                    # corpus imports is relative.
                    continue
                for a in node.names:
                    if a.name != "*":
                        self.bindings[a.asname or a.name] = f"{node.module}.{a.name}"
        self.functions: dict[str, ast.FunctionDef] = {
            n.name: n for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _chain(node: ast.AST) -> Optional[list[str]]:
    """The dotted parts of an attribute chain rooted in a loaded `Name`.

    `None` when the chain is rooted in anything else -- `f(x).attr`,
    `d["k"].attr` -- because then the receiver is a value, not an import
    binding, and naming it would be the flow analysis this rule does not do.
    """
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        parts.append(node.id)
        return list(reversed(parts))
    return None


def _rebound(fn: ast.AST, args: list) -> set[str]:
    """Every name the function binds itself (D-e)."""
    out = {a.arg for a in args}
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del)):
            out.add(sub.id)
        elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(sub.name)
        elif isinstance(sub, (ast.Import, ast.ImportFrom)):
            for a in sub.names:
                out.add(a.asname or a.name.split(".")[0])
    return out


class PyInterfaceExtractor:
    """Not a subclass of `InterfaceExtractor`: it shares no method with it.

    The PHP extractor's whole body is index lookups (`members`, `fields`,
    `surface_of`) over a per-method index that has no Python counterpart.
    What the two share is the ARTIFACT -- `ItemInterfaces`, `to_json`, the
    empty-reason constants, the writer, the summary -- and that is imported.
    """

    def __init__(self, repo_root: str, prod_index: dict, boundary: Boundary):
        self.repo_root = os.path.abspath(repo_root)
        self.boundary = boundary
        indexed_root = prod_index.get("root")
        if indexed_root and (os.path.realpath(indexed_root)
                             != os.path.realpath(self.repo_root)):
            raise InterfacesError(
                f"REFUSED: py_prod_index.json was built from {indexed_root!r} "
                f"and the step sources are being read from {self.repo_root!r}; "
                f"the index and the corpus are not the same checkout.")
        # F1: what the project itself declares, and where.  One map for both
        # units the rule admits -- a symbol (`docx.table.Table`, and a
        # module-level function the index lists) and a bare module (`docx`).
        self.declaring_file: dict[str, str] = {}
        #: The module half of it on its own, which is where a candidate name
        #: is cut (D-f).
        self.module_file: dict[str, str] = {}
        for path, finfo in prod_index["files"].items():
            # The producer records module names through paths, including
            # files with no class or function declarations.
            module = module_name(path)
            if module:
                self.declaring_file.setdefault(module, path)
                self.module_file.setdefault(module, path)
            for c in finfo.get("classes") or []:
                if not c.get("name"):
                    continue
                if c.get("kind") == "module":
                    for m in c.get("methods") or []:
                        self.declaring_file[f"{c['name']}.{m['name']}"] = path
                else:
                    self.declaring_file[c["name"]] = path
        # F2: of those, the ones the reviewed boundary calls production.
        self.first_party: set[str] = {
            n for n, p in self.declaring_file.items()
            if boundary.classify(p) == PRODUCTION}
        self._modules: dict[str, _StepModule] = {}

    # ------------------------------------------------------------- sources
    def module(self, rel_path: str) -> _StepModule:
        """The parsed step module at `rel_path`, cached for the sweep."""
        got = self._modules.get(rel_path)
        if got is not None:
            return got
        path = os.path.join(self.repo_root, rel_path)
        try:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
        except OSError as exc:
            raise InterfacesError(
                f"REFUSED: step module {rel_path} is bound by the closure but "
                f"absent from the pinned corpus at {self.repo_root} ({exc}).")
        try:
            tree = ast.parse(source, rel_path)
        except SyntaxError as exc:
            raise InterfacesError(
                f"REFUSED: step module {rel_path} does not parse ({exc}).")
        self._modules[rel_path] = _StepModule(tree)
        return self._modules[rel_path]

    # ------------------------------------------------------------ resolving
    def resolve(self, dotted: str) -> Optional[str]:
        """The longest prefix of `dotted` the production index declares.

        This is F1 and the attribute-chain collapse at once, which is why an
        enum member (`...WD_UNDERLINE.SINGLE`), an accessor
        (`...RGBColor.from_string`) and a re-export (`docx.Document`) all come
        back as something the index can re-check, and why none of them puts a
        method name on the list.
        """
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            prefix = ".".join(parts[:i])
            if prefix in self.declaring_file:
                return prefix
        return None

    def candidate_of(self, dotted: str) -> str:
        """The same chain named at spec 3.1's unit, unfiltered (D-f)."""
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            if ".".join(parts[:i]) in self.module_file:
                return ".".join(parts[:min(i + 1, len(parts))])
        return dotted

    def surface_of(self, module_name: str, func: str, rel_path: str) -> set[str]:
        """The candidate surface of one bound step function, unfiltered.

        `module_name` is the closure's `definition.class`, which for behave is
        the module IMPORT NAME (`closure_py._as_definition`); it is checked
        against the file rather than used to find it, so a closure whose two
        fields disagree is a refusal and not a silent mismatch.
        """
        mod = self.module(rel_path)
        fn = mod.functions.get(func)
        if fn is None:
            raise InterfacesError(
                f"REFUSED: step function {func} is bound by the closure to "
                f"{rel_path} but that module defines no module-level `def` of "
                f"that name; the closure and the pinned sources are not the "
                f"same commit.")
        expected = os.path.splitext(os.path.basename(rel_path))[0]
        if module_name != expected:
            raise InterfacesError(
                f"REFUSED: the closure binds a step to module {module_name!r} "
                f"in file {rel_path}, whose module name is {expected!r}.")
        a = fn.args
        args = (list(getattr(a, "posonlyargs", [])) + list(a.args)
                + list(a.kwonlyargs)
                + ([a.vararg] if a.vararg else [])
                + ([a.kwarg] if a.kwarg else []))
        # The body and the DECLARATIONS -- parameter and return annotations
        # (D-d).  The decorator list is deliberately not here.
        roots: list[ast.AST] = list(fn.body)
        roots += [x.annotation for x in args if x.annotation is not None]
        if fn.returns is not None:
            roots.append(fn.returns)
        rebound = _rebound(fn, args)
        out: set[str] = set()

        def visit(node: ast.AST) -> None:
            if isinstance(node, (ast.Attribute, ast.Name)):
                chain = _chain(node)
                if chain is not None:
                    root = chain[0]
                    if root not in rebound and root in mod.bindings:
                        out.add(".".join([mod.bindings[root]] + chain[1:]))
                    return          # the whole chain is one reference (D-a)
            for child in ast.iter_child_nodes(node):
                visit(child)

        for r in roots:
            visit(r)
        return out

    # ---------------------------------------------------------------- item
    def for_item(self, closure: dict) -> ItemInterfaces:
        it = ItemInterfaces(closure["item_id"], closure["feature_file"],
                            closure["scenario_line"])
        scen: set[str] = set()
        back: set[str] = set()
        scen_raw: set[str] = set()
        back_raw: set[str] = set()
        seen: set[tuple[str, str, str]] = set()
        for st in closure.get("steps") or []:
            d = st.get("definition")
            if not d or st.get("side") != REMOVABLE:
                continue                # unbound, or answered by retained code
            key = (d["class"], d["method"], st["origin"])
            if key in seen:
                continue
            seen.add(key)
            it.members.append({"class": d["class"], "method": d["method"],
                               "origin": st["origin"]})
            raw = self.surface_of(d["class"], d["method"], d["file"])
            resolved = {r for r in (self.resolve(n) for n in raw) if r}
            named = {self.candidate_of(n) for n in raw}
            if st["origin"] == "scenario":
                scen_raw |= named
                scen |= resolved
            else:
                back_raw |= named
                back |= resolved
        it.candidates = {"behaviour": sorted(scen_raw),          # D-f
                         "setup": sorted(back_raw - scen_raw)}
        it.behaviour = sorted(scen & self.first_party)
        it.setup = sorted((back & self.first_party) - scen)
        if not it.behaviour:
            it.empty_reason = (EMPTY_NO_DECLARATION
                               if any(m["origin"] == "scenario" for m in it.members)
                               else EMPTY_NO_MEMBER)
        return it


def load_extractor(repo_root: str, prod_index_path: str,
                   boundary_path: str) -> PyInterfaceExtractor:
    """The PHP twin takes an index path where this takes the repo root.

    Not a signature drift: the PHP surface IS `php_index.json` and the Python
    surface is the step sources themselves (module docstring).  `repo_root` is
    passed to the boundary too, so one path decides both what is read and how
    it classifies.
    """
    import json
    with open(prod_index_path, encoding="utf-8") as fh:
        prod_index = json.load(fh)
    return PyInterfaceExtractor(repo_root, prod_index,
                                load_boundary(boundary_path, repo_root=repo_root))


def cmd_interfaces(args) -> int:
    """`r2t interfaces --profile …`, the behave arm (TARGET_INTERFACES_SPEC).

    Reads the closure the `closures` verb wrote and the production index the
    `index-prod` verb wrote, and writes `interfaces.json` beside them -- the
    same artifact, in the same shape, as the PHP arm's `cmd_interfaces`.
    """
    import json
    from .interfaces import extract_all, summary, write_interfaces
    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    ex = load_extractor(b.repo_root,
                        os.path.join(args.artifacts, "py_prod_index.json"),
                        args.boundary)
    with open(os.path.join(args.artifacts, "closures.json"), encoding="utf-8") as fh:
        closures = json.load(fh)
    items = extract_all(closures, ex)
    dst = os.path.join(args.artifacts, "interfaces.json")
    write_interfaces(items, dst)
    print(json.dumps(dict(summary(items), wrote=dst), indent=1))
    return 0


# ------------------------------------------------------------------ selftest
def selftest() -> int:
    import json
    import tempfile

    from ..py.prod_index import build_prod_index

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    STEPS = {
        "features/steps/table.py": '''
from behave import given, then
from behave.runner import Context

import docx
from docx import Document
from docx.api import Document as ApiDocument
from docx.table import Table
from docx.enum.text import WD_UNDERLINE, WD_ALIGN_PARAGRAPH
from docx.internals import Helper
from docx.opc.oxml import ThirdParty
from docx.section import Section

from helpers import test_docx


@given("a table")
def given_a_table(context: Context, name: str):
    context.table_ = Table(test_docx(name), Helper(), ThirdParty())
    assert isinstance(context.table_.rows[0], docx.table._Row)
    assert context.table_.cell(0, 0).underline == WD_UNDERLINE.SINGLE


@then("aliased")
def then_aliased(context):
    context.p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    Document()


@given("a document directly")
def given_a_document_directly(context):
    context.doc = ApiDocument()


@then("package metadata")
def then_package_metadata(context):
    context.metadata = docx.enum.__doc__


@then("shadowed")
def then_shadowed(context):
    Table = context.table_
    return Table


@then("retained side")
def then_retained_side(context):
    Section(context.doc)
''',
        "features/steps/setup.py": '''
from behave import given
from docx.styles.style import BaseStyle


@given("a style")
def given_a_style(context):
    context.style = BaseStyle(None)
''',
        "features/steps/vendorish.py": '''
import os
from behave import given
from helpers import test_docx


@given("nothing first party")
def given_nothing(context):
    context.path = os.path.join(test_docx("x"), "y")
''',
    }
    # Build the real producer's schema; handwritten module/module_level
    # fields previously let this selftest pass while corpus extraction failed.
    PROD_SOURCES = {
        "src/docx/__init__.py": '''
from docx.api import Document

def part_class_selector():
    pass
''',
        "src/docx/api.py": "def Document():\n    pass\n",
        "src/docx/table.py": "class Table: pass\nclass _Row: pass\n",
        "src/docx/enum/__init__.py": "__doc__ = 'Enumeration types.'\n",
        "src/docx/enum/text.py": '''
class WD_UNDERLINE:
    SINGLE = 1

class WD_PARAGRAPH_ALIGNMENT:
    CENTER = 1

WD_ALIGN_PARAGRAPH = WD_PARAGRAPH_ALIGNMENT
''',
        "src/docx/styles/style.py": "class BaseStyle: pass\n",
        "src/docx/internals.py": "class Helper: pass\n",
        "src/docx/section.py": "class Section: pass\n",
    }
    T, ROW = "docx.table.Table", "docx.table._Row"
    UND, STYLE = "docx.enum.text.WD_UNDERLINE", "docx.styles.style.BaseStyle"
    HELPER = "docx.internals.Helper"        # declared in a RETAINED file
    SECT = "docx.section.Section"           # touched only by a RETAINED step

    def step(text, origin, module, method, side, path=None):
        return {"text": text, "origin": origin, "keyword": "Given", "side": side,
                "definition": None if module is None else {
                    "file": path or f"features/steps/{module}.py",
                    "class": module, "method": method, "kind": "given",
                    "pattern": text}}

    with tempfile.TemporaryDirectory() as root:
        for rel, src in {**STEPS, **PROD_SOURCES}.items():
            os.makedirs(os.path.join(root, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                fh.write(src)
        prod = build_prod_index(root)
        # `src/docx/internals.py` is carved back out as retained, the way the
        # real boundary carves `features/steps/test_files` out of a removable
        # prefix; everything else under `src/` falls through to PRODUCTION.
        b = Boundary(version=1, project="t", repo_root=root,
                     removable=[("features/steps/", "")],
                     retained=[("src/docx/internals.py", "")])
        ex = PyInterfaceExtractor(root, prod, b)

        item = {"item_id": "t/f.feature:5", "feature_file": "features/f.feature",
                "scenario_line": 5, "steps": [
                    step("a style", "background", "setup", "given_a_style", REMOVABLE),
                    step("infra", "background", "table", "then_retained_side",
                         "retained"),
                    step("a table", "scenario", "table", "given_a_table", REMOVABLE),
                    step("aliased", "scenario", "table", "then_aliased", REMOVABLE),
                    step("shadowed", "scenario", "table", "then_shadowed", REMOVABLE),
                    step("unbound", "scenario", None, None, None)]}
        got = ex.for_item(item)

        check("an imported class the body calls is named module.Symbol",
              T in got.behaviour, str(got.behaviour))
        check("an attribute chain off an `import docx` binding resolves to the "
              "symbol, not to the package", ROW in got.behaviour)
        check("an enum MEMBER collapses to the enum, and no member or method "
              "identifier reaches EITHER list (spec 5.4)",
              UND in got.behaviour
              and not any(n.endswith((".SINGLE", ".CENTER", ".cell"))
                          for n in got.behaviour + got.setup
                          + got.candidates["behaviour"] + got.candidates["setup"]))
        check("a re-export the index does not list falls back to the bare "
              "module (D-b), and the unfiltered name stays in candidates",
              "docx" in got.behaviour and "docx.Document" not in got.behaviour
              and "docx.Document" in got.candidates["behaviour"])
        check("a module-level alias the index does not list falls back to its "
              "module (D-c)",
              "docx.enum.text" in got.behaviour
              and "docx.enum.text.WD_ALIGN_PARAGRAPH" not in got.behaviour
              and "docx.enum.text.WD_ALIGN_PARAGRAPH"
              in got.candidates["behaviour"])
        check("F1 drops an imported name the production index does not "
              "declare",
              "docx.opc.oxml.ThirdParty" not in got.behaviour
              and "helpers.test_docx" in got.candidates["behaviour"]
              and "helpers.test_docx" not in got.behaviour)
        check("F2 drops a symbol whose declaring file the boundary calls "
              "retained",
              HELPER in got.candidates["behaviour"] and HELPER not in got.behaviour)
        check("a parameter annotation is read as a declaration, and a name no "
              "import bound is not a reference",
              "behave.runner.Context" in got.candidates["behaviour"]
              and "str" not in got.candidates["behaviour"])
        check("no flow analysis: nothing rooted at `context` is named",
              not any(n.startswith("context") for n in got.candidates["behaviour"]))
        check("a name the function rebinds is not an import binding (D-e): the "
              "shadowing step contributes no `docx.table.Table` of its own",
              got.behaviour == sorted({T, ROW, UND, "docx", "docx.enum.text"}),
              str(got.behaviour))
        check("a Background-origin symbol goes to the setup list, and only "
              "there",
              got.setup == [STYLE] and STYLE not in got.behaviour
              and got.candidates["setup"] == [STYLE])
        check("a step answered by retained code contributes nothing",
              all(m["method"] != "then_retained_side" for m in got.members)
              and SECT not in got.behaviour + got.setup
              and SECT not in got.candidates["behaviour"] + got.candidates["setup"])
        check("the members record carries origin for every bound removable "
              "member",
              sorted((m["method"], m["origin"]) for m in got.members)
              == [("given_a_style", "background"), ("given_a_table", "scenario"),
                  ("then_aliased", "scenario"), ("then_shadowed", "scenario")])
        check("a non-empty list has no empty_reason", got.empty_reason is None)

        direct = ex.for_item(dict(item, steps=[
            step("a document directly", "scenario", "table",
                 "given_a_document_directly", REMOVABLE)]))
        check("a directly imported module-level function keeps its full name",
              direct.behaviour == ["docx.api.Document"]
              and direct.candidates["behaviour"] == ["docx.api.Document"],
              str(direct.to_json()))

        metadata = ex.for_item(dict(item, steps=[
            step("package metadata", "scenario", "table",
                 "then_package_metadata", REMOVABLE)]))
        check("an assignment-only package with no indexed declarations still "
              "resolves as a module",
              metadata.behaviour == ["docx.enum"]
              and metadata.candidates["behaviour"] == ["docx.enum.__doc__"],
              str(metadata.to_json()))

        only_bg = dict(item, steps=item["steps"][:2] + [item["steps"][-1]])
        e1 = ex.for_item(only_bg)
        check("no removable scenario member -> empty behaviour with its "
              "reason, setup still measured",
              e1.behaviour == [] and e1.setup == [STYLE]
              and e1.empty_reason == EMPTY_NO_MEMBER)

        e2 = ex.for_item({"item_id": "t/g.feature:1",
                          "feature_file": "features/g.feature", "scenario_line": 1,
                          "steps": [step("nothing first party", "scenario",
                                         "vendorish", "given_nothing", REMOVABLE)]})
        check("members that declare no first-party symbol -> empty with the "
              "other reason",
              e2.behaviour == []
              and e2.candidates["behaviour"] == ["helpers.test_docx",
                                                 "os.path.join"]
              and e2.empty_reason == EMPTY_NO_DECLARATION,
              str(e2.candidates))

        try:
            ex.for_item({"item_id": "t/h.feature:1", "feature_file": "h",
                         "scenario_line": 1,
                         "steps": [step("s", "scenario", "table", "no_such_func",
                                        REMOVABLE)]})
            check("a bound function the module does not define is refused", False)
        except InterfacesError as exc:
            check("a bound function the module does not define is refused",
                  "no module-level `def`" in str(exc))
        try:
            ex.for_item({"item_id": "t/h.feature:2", "feature_file": "h",
                         "scenario_line": 2,
                         "steps": [step("s", "scenario", "gone", "f", REMOVABLE)]})
            check("a bound step module absent from the pinned tree is refused",
                  False)
        except InterfacesError as exc:
            check("a bound step module absent from the pinned tree is refused",
                  "absent from the pinned corpus" in str(exc))
        try:
            PyInterfaceExtractor(root, dict(prod, root=os.path.join(root, "other")), b)
            check("a production index built from another checkout is refused",
                  False)
        except InterfacesError as exc:
            check("a production index built from another checkout is refused",
                  "not the same checkout" in str(exc))

        p1, p2 = os.path.join(root, "a.json"), os.path.join(root, "b.json")
        write_interfaces(extract_all([item, only_bg], ex), p1)
        write_interfaces(extract_all([item, only_bg], ex), p2)
        with open(p1, "rb") as f1, open(p2, "rb") as f2:
            b1, b2 = f1.read(), f2.read()
        doc = json.loads(b1)
        check("re-extraction is byte-identical", b1 == b2)
        check("the artifact declares the PHP twin's schema and round-trips "
              "both lists",
              doc["schema"] == SCHEMA
              and doc["items"][0]["target_interfaces"]
              == {"behaviour": got.behaviour, "setup": got.setup})
        check("every member is sorted, deduplicated and re-checkable against "
              "F1 and F2 from the artifact alone",
              all(sorted(set(v)) == v
                  and all(ex.boundary.classify(ex.declaring_file[n]) == PRODUCTION
                          for n in v)
                  for i in doc["items"]
                  for v in i["target_interfaces"].values()))

    s = summary([got, e1])
    check("summary counts the empties by reason and both lists' sizes",
          s["items"] == 2 and s["empty"][EMPTY_NO_MEMBER] == 1
          and s["empty"][EMPTY_NO_DECLARATION] == 0 and s["distinct"] == 6
          and s["behaviour"]["max"] == 5 and s["setup"]["max"] == 1, str(s))
    print("ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
