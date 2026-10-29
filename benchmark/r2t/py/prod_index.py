"""The PRODUCTION method index for a Python project, built by `ast`.

`analyze_py.py` is this package's index of TEST code — what a step module
imports and which decorators it registers.  This is the other half, and the
one `metrics.load_prod_index` reads: for every production file, the methods
declared in it, each with the DECLARATION LINE a recorded call event names
and the body span the nested-function fold reads.  `ApiCallSimilarity` is
defined over the result — the set of public production methods the gold test
invoked directly, against the set the generated test invoked — so without an
index of this shape the `api precision`, `api recall` and `api f1` rows have
nothing to be computed from and render `not_measured`.

It is the analogue of the class/method half of `r2t/php/analyze_php.php`, and
like `analyze_py.py` it is much smaller than the PHP program, for the same
reason: `ast` ships with the interpreter, so this runs on the HOST.  There is
no container to reach, no `vendor/` to find a parser in, and therefore none of
the Docker workload binding `index-prod` needs on the PHP side.

**Two lines per method, and what each is for.**  `decl` is the line CPython
gives the code object as `co_firstlineno` — the first DECORATOR where the
method has one, the `def` otherwise — and it is what a recorded call event is
joined on (`API_DIRECT_INVOCATION_SPEC.md` §2.3): a property's getter and its
setter are told apart by exactly this line.  `start`/`end` is the BODY span,
from `node.body[0].lineno` to `node.end_lineno`, so the decorators, the `def`
and a multi-line signature fall outside it; scoring reads it for the fold a
named closure needs, having no index entry of its own — it is credited to the
innermost indexed method whose span contains its declaration line.  The one
case a span cannot separate is a body that starts ON the `def` line
(`def part(self): return self._part`); python-docx has 9 such methods out of
1,289 and they are counted in `counts.ambiguous_one_line_spans`.

**What `public` means.**  PHP declares it; Python spells it in the name, and
the rule here is the convention plus one correction the data forces.  A
leading underscore is non-public — but a DUNDER is the public protocol, not a
private name: `len(document.paragraphs)` calls `__len__`, `Document(path)`
calls `__init__`, and python-docx declares 156 dunder methods including 83
constructors.  Scoring them as private would drop every constructor and the
whole container protocol from both sides of the comparison.  It would also
diverge from the PHP index, where `__construct` is `public function` and
`isPublic()` returns true for it.  So `__init__` is public, `_private` and
`__mangled` are not.

**What owns a module-level function.**  `metrics.Method` is keyed by
`(fqcn, name)`, a two-level space that assumes every method has a class.
`docx.api.Document` — the entry point of the entire library, and 22 functions
like it — has none.  Dropping them would make the most-called production
function in the corpus invisible to the metric, so the MODULE is recorded as
their owner: one entry per file whose `kind` is `"module"` and whose `name` is
the dotted module path.  `load_prod_index` reads it exactly like a class,
because for its purposes that is what it is: the thing a called function
belongs to.

**Generated xmlchemy properties.** Schema 2 adds `accessors` beside each
class's unchanged `methods`. The declaring class owns each accessor, its
assignment supplies `declaring_line`, and the installed property supplies
`attribute` and `access_kind`. Repeating-element descriptors install a
`<name>_lst` getter; attribute descriptors install a getter and a setter.
These entries have no body span and never enter the ordinary method join.
Only the six descriptor factories used by the pinned python-docx source are
recognized, through their imports from `docx.oxml.xmlchemy`. Their arguments
are not evaluated and neither the corpus nor xmlchemy is imported.

**What is not checked here.**  Whether an indexed file is production code.
`metrics.direct_methods` classifies a call event's callee through the
boundary BEFORE joining it against this index, so a file that is not
production never reaches the join and contributes nothing however it got in
here.  A second boundary filter would guard a case the consumer already
closes.
"""
from __future__ import annotations

import ast
import os
from typing import Iterable, Optional

SCHEMA = "r2t.py_prod_index/2"

#: The trees `index-prod` indexes for a Python project when `--path` is not
#: given.  `src` and not `src/docx`, because it is the boundary's own
#: statement of what production code is: `boundary_python_docx.yml` ends
#: "`features/*.feature` and `src/**` are PRODUCTION by falling through both
#: lists", and `py/bench_environment.py` collects coverage with
#: `Coverage(source=["src"])` and then filters to `src/` a second time.  An
#: index over a narrower tree than the recorder measures would leave covered
#: lines with no method to attribute them to.
PY_PROD_PATHS: tuple[str, ...] = ("src",)

#: The directory that is on `sys.path`, and therefore the prefix that turns a
#: repo-relative path into the dotted name a class is known by.
#: `profile_python_docx.yml` states the fact the layout rests on -- "the
#: library under test is imported as `docx` and lives in `src/docx/`; `src` is
#: already on the import path" -- so `src/docx/text/paragraph.py` is the
#: module `docx.text.paragraph`.  A path outside this prefix keeps its full
#: relative path as its dotted name rather than being renamed to something
#: that is not importable either way.
IMPORT_ROOT = "src"

#: Decorators that make a function a property -- a method the caller reaches
#: as an attribute.  python-docx declares 484 `@property`, 32 `@lazyproperty`
#: (its own caching variant, `docx.shared.lazyproperty`) and about 50
#: `@<name>.setter`, which is 56% of its class-level functions: the property
#: IS this library's API surface, so they are indexed as the methods they
#: are.  A getter and its setter are two of them and are keyed APART -- the
#: setter as `<name>.setter`, a deleter as `<name>.deleter` -- because
#: reading `Paragraph.text` and assigning to it are different API and a call
#: event names one declaration line or the other (spec §2.2).
_PROPERTY_DECORATORS = frozenset({"property", "lazyproperty",
                                  "cached_property"})
_PROPERTY_SUFFIXES = (".setter", ".getter", ".deleter")

_FUNC = (ast.FunctionDef, ast.AsyncFunctionDef)

# Installed property names and operations in python-docx e454546's
# MetaOxmlElement factories. The generated add/remove/create helpers are
# methods, not properties, and are outside Amendment 2's accessor rule.
_XMLCHEMY_PROPERTIES = {
    "OptionalAttribute": ("", ("get", "set")),
    "RequiredAttribute": ("", ("get", "set")),
    "OneAndOnlyOne": ("", ("get",)),
    "ZeroOrOne": ("", ("get",)),
    "OneOrMore": ("_lst", ("get",)),
    "ZeroOrMore": ("_lst", ("get",)),
}


# --------------------------------------------------------------- extraction
def _decorator_names(node) -> list[str]:
    """Each decorator as source text (`property`, `x.setter`, `overload`).

    `ast.unparse` rather than a match on node types, because the three forms
    that matter here -- a bare name, an attribute, and a call -- would each
    need their own branch to produce the same string.  A decorator this
    cannot name is recorded as its unparsed source and simply matches none of
    the sets below, which is the correct answer for a decorator nobody asked
    about.
    """
    out = []
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        try:
            out.append(ast.unparse(target))
        except Exception:                                # pragma: no cover
            out.append("<unparseable>")
    return out


def is_public(name: str) -> bool:
    """The visibility rule -- see the module docstring for why dunders win."""
    if name.startswith("__") and name.endswith("__"):
        return True
    return not name.startswith("_")


def module_name(rel: str) -> str:
    """`src/docx/text/paragraph.py` -> `docx.text.paragraph`."""
    parts = rel[:-len(".py")].split("/")
    if parts and parts[0] == IMPORT_ROOT:
        parts = parts[1:]
    # A package is named by its directory, never by `__init__`: the classes in
    # `src/docx/__init__.py` are `docx.Document`, which is how every caller
    # spells them.
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _method(node) -> dict:
    """One declared function, in `metrics.load_prod_index`'s method shape.

    `name`, `start`, `end` and `public` are the four that loader refuses to
    default, and `decl` is the fifth the direct-call join reads; `static`,
    `abstract` and `property` are carried as census, the way
    `analyze_php.php` carries the first two.  `static` covers
    `@classmethod` as well as `@staticmethod` because the field's meaning is
    "reached through the class rather than an instance", which is true of
    both -- 127 of python-docx's are classmethods and calling them all
    instance methods would be the less accurate of the two answers.
    """
    decorators = _decorator_names(node)
    # A setter and a deleter are methods of their own and are keyed apart
    # from the getter they share a `def` name with; visibility is read from
    # the DECLARED name before the suffix, so `_p.setter` is as non-public
    # as `_p`.
    suffix = next((s for s in (".setter", ".deleter")
                   if any(d.endswith(s) for d in decorators)), "")
    entry = {
        "name": node.name + suffix,
        # What CPython gives the code object as `co_firstlineno`, which a
        # call event names: the first decorator, or the `def` where there is
        # none.  `node.lineno` alone is the `def` line and would match no
        # decorated method at all.
        "decl": (node.decorator_list[0].lineno if node.decorator_list
                 else node.lineno),
        # See the module docstring: the BODY, never the `def`.
        "start": node.body[0].lineno,
        "end": node.end_lineno,
        "public": is_public(node.name),
        "static": any(d in ("staticmethod", "classmethod")
                      for d in decorators),
        # `@abstractmethod` only.  A body that merely raises
        # NotImplementedError is the same shape as a method that raises for
        # its own reasons, and the difference is not recoverable from source.
        "abstract": any(d.split(".")[-1] == "abstractmethod"
                        for d in decorators),
        "property": any(d in _PROPERTY_DECORATORS
                        or d.endswith(_PROPERTY_SUFFIXES)
                        for d in decorators),
    }
    if node.body[0].lineno == node.lineno:
        # `def part(self): return self._part` -- the body could not be
        # excluded from the `def`, so importing the module marks this span.
        # Written only where it is TRUE (9 methods of python-docx's 1,289),
        # so a reader meets the caveat on the method it applies to rather
        # than reading a `false` on every other one.
        entry["declaration_line_in_span"] = True
    return entry


def _accessors(body: list, factories: dict[str, str]) -> list[dict]:
    """Own xmlchemy declarations, without copying inherited properties.

    All descriptor assignments in the pinned corpus have one named target,
    with either Assign or AnnAssign syntax. An inherited property stays on
    its declaring class; an overriding assignment gets a new owner/line.
    """
    out = []
    for stmt in body:
        if isinstance(stmt, ast.AnnAssign):
            target, value = stmt.target, stmt.value
        elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value
        else:
            continue
        if not isinstance(target, ast.Name) or not isinstance(value, ast.Call) \
                or not isinstance(value.func, ast.Name):
            continue
        factory = factories.get(value.func.id)
        if factory is None:
            continue
        suffix, kinds = _XMLCHEMY_PROPERTIES[factory]
        attribute = target.id + suffix
        out.extend({"declaring_line": stmt.lineno, "attribute": attribute,
                    "access_kind": kind, "public": is_public(attribute)}
                   for kind in kinds)
    return out


def _classes(body: list, prefix: str,
             factories: dict[str, str]) -> list[dict]:
    """Class entries for one statement list, nested classes included.

    Only class bodies are descended into.  A `def` inside a `def` is a
    closure, and its lines already belong to the span of the method that
    declares it -- indexing it separately would attribute the same covered
    line to two methods.
    """
    out = []
    for stmt in body:
        if not isinstance(stmt, ast.ClassDef):
            continue
        fqcn = f"{prefix}.{stmt.name}" if prefix else stmt.name
        out.append({
            "name": fqcn,
            "kind": "class",
            "line": stmt.lineno,
            "methods": [_method(f) for f in stmt.body if isinstance(f, _FUNC)],
            "accessors": _accessors(stmt.body, factories),
        })
        out.extend(_classes(stmt.body, fqcn, factories))
    return out


def index_source(src: str, rel: str) -> list[dict]:
    """The class entries of one module's source, module functions first.

    Only DIRECT children of the module body and of a class body are taken, so
    a class or a method defined under an `if` or a `try` is not indexed.  That
    is a measured decision rather than an assumed one: python-docx's `src/`
    contains zero such definitions, and a descent written for a construct the
    corpus does not use would be untested code guarding nothing.  If a project
    that uses it is ever indexed, its methods are absent rather than wrong --
    they join to nothing, exactly like an unparsed file.

    Raises `SyntaxError`; `build_prod_index` turns that into an `errors` row.
    Accessors are generated from the class-level xmlchemy assignments in
    this source file. An imported class's declarations remain in its own
    file, so inheritance never changes the indexed owner.
    """
    tree = ast.parse(src, filename=rel)
    mod = module_name(rel)
    factories = {
        alias.asname or alias.name: alias.name
        for stmt in tree.body
        if isinstance(stmt, ast.ImportFrom)
        and stmt.module == "docx.oxml.xmlchemy" and stmt.level == 0
        for alias in stmt.names if alias.name in _XMLCHEMY_PROPERTIES
    }
    entries = []
    functions = [_method(f) for f in tree.body if isinstance(f, _FUNC)]
    if functions:
        entries.append({"name": mod, "kind": "module", "line": 1,
                        "methods": functions, "accessors": []})
    entries.extend(_classes(tree.body, mod, factories))
    return entries


def build_prod_index(repo_root: str,
                     paths: Optional[Iterable[str]] = None) -> dict:
    """Index every `.py` under `paths`, keyed by repo-relative path.

    The keys are what `metrics.direct_methods` looks a call event's
    `callee_file` up by, so they are repo-relative with forward slashes --
    the same spelling `py/bench_environment.py` writes into a record
    (`os.path.relpath(path, base)`, `src/`-prefixed).  A key that did not
    match would not fail: it would silently contribute no methods, which is
    why the two spellings are derived the same way rather than converted.
    """
    root = os.path.abspath(repo_root)
    paths = list(PY_PROD_PATHS if paths is None else paths)

    rels: list[str] = []
    for p in paths:
        full = os.path.join(root, p)
        if os.path.isfile(full):
            if full.endswith(".py"):
                rels.append(os.path.relpath(full, root).replace(os.sep, "/"))
            continue
        for dirpath, dirnames, names in os.walk(full):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            for f in sorted(names):
                if f.endswith(".py"):
                    rels.append(os.path.relpath(os.path.join(dirpath, f), root)
                                .replace(os.sep, "/"))
    rels = sorted(set(rels))

    files: dict[str, dict] = {}
    errors: dict[str, str] = {}
    for rel in rels:
        with open(os.path.join(root, rel), encoding="utf-8",
                  errors="replace") as fh:
            src = fh.read()
        try:
            classes = index_source(src, rel)
        except SyntaxError as e:
            # Not a skip: a file the indexer could not parse contributes no
            # methods, so every line covered in it joins to nothing and the
            # comparison quietly shrinks.  Recorded so the gap is a number a
            # reader can see next to the one derived from it.
            errors[rel] = f"{type(e).__name__}: {e}"
            continue
        files[rel] = {"classes": classes}

    methods = [m for f in files.values() for c in f["classes"]
               for m in c["methods"]]
    accessors = [a for f in files.values() for c in f["classes"]
                 for a in c["accessors"]]
    return {
        "schema": SCHEMA,
        "root": root,
        "paths": paths,
        "files": files,
        "errors": errors,
        "counts": {
            "files": len(files),
            "classes": sum(len(f["classes"]) for f in files.values()),
            "methods": len(methods),
            "public_methods": sum(1 for m in methods if m["public"]),
            "properties": sum(1 for m in methods if m["property"]),
            "accessors": len(accessors),
            "public_accessors": sum(1 for a in accessors if a["public"]),
            "errors": len(errors),
            "ambiguous_one_line_spans": sum(
                1 for m in methods if m.get("declaration_line_in_span")),
        },
    }


# ---------------------------------------------------------------- selftest
def selftest() -> int:
    """Every claim the module docstring makes, against real parsed source.

    Both lines are checked against the source text they name -- the decorator
    line for `decl`, the first body statement for `start` -- rather than
    against each other, because an index that had shifted one of them by one
    for the wrong reason would still satisfy `decl < start`.
    """
    import tempfile
    import textwrap

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    with tempfile.TemporaryDirectory() as d:
        pkg = os.path.join(d, "src", "lib")
        os.makedirs(pkg)
        with open(os.path.join(d, "src", "lib", "__init__.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("VERSION = '1'\n")
        with open(os.path.join(pkg, "text.py"), "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent('''
                """Module docstring."""

                from functools import cached_property


                def Document(path):
                    """The module-level entry point."""
                    return Paragraph(path)


                class Paragraph:
                    """A paragraph."""

                    STYLE = "body"

                    def __init__(self, path):
                        self._path = path

                    @property
                    def text(
                        self,
                    ):
                        """Docstring, not an executable line."""
                        return self._path

                    @text.setter
                    def text(self, value):
                        self._path = value

                    @staticmethod
                    def blank():
                        return Paragraph("")

                    @classmethod
                    def of(cls, path):
                        return cls(path)

                    def _internal(self):
                        return 1

                    def __len__(self):
                        return len(self._path)

                    def never_called(self):
                        return 99

                    def one_liner(self): return 7

                    def outer(self):
                        def inner():
                            return 2
                        return inner()

                    class Nested:
                        def deep(self):
                            return 3
            ''').lstrip())
        with open(os.path.join(pkg, "broken.py"), "w", encoding="utf-8") as fh:
            fh.write("def oops(:\n")

        idx = build_prod_index(d)
        rel = "src/lib/text.py"
        check("the index is keyed by repo-relative path, the spelling a "
              "coverage block uses", rel in idx["files"],
              str(sorted(idx["files"])))
        entries = {c["name"]: c for c in idx["files"][rel]["classes"]}
        # Keyed by `(owner, name)` like the metric itself -- which is why a
        # property's setter has to be keyed `text.setter`: under one name it
        # would overwrite its getter here and be invisible to scoring.
        methods = {(c["name"], m["name"]): m
                   for c in idx["files"][rel]["classes"] for m in c["methods"]}
        para = entries["lib.text.Paragraph"]["methods"]

        check("a file that does not parse is an error, not a silent skip",
              list(idx["errors"]) == ["src/lib/broken.py"]
              and idx["counts"]["errors"] == 1, str(idx["errors"]))
        check("the dotted name drops the import root",
              "lib.text.Paragraph" in entries, str(sorted(entries)))
        check("a package is named by its directory, not by `__init__`",
              module_name("src/lib/__init__.py") == "lib"
              and module_name("src/lib/text.py") == "lib.text")
        check("module-level functions are owned by the MODULE, so the "
              "library's entry point is indexable at all",
              entries["lib.text"]["kind"] == "module"
              and ("lib.text", "Document") in methods,
              str(sorted(entries)))
        check("a nested class is its own entry under a qualified name",
              "lib.text.Paragraph.Nested" in entries
              and ("lib.text.Paragraph.Nested", "deep") in methods,
              str(sorted(entries)))
        check("a closure is NOT a method -- its lines belong to the method "
              "that declares it",
              ("lib.text.Paragraph", "inner") not in methods
              and methods[("lib.text.Paragraph", "outer")]["end"]
              > methods[("lib.text.Paragraph", "outer")]["start"])

        # -- the span rule, checked as the failure it prevents.
        src_lines = open(os.path.join(pkg, "text.py"),
                         encoding="utf-8").read().splitlines()
        never = methods[("lib.text.Paragraph", "never_called")]
        never_at = src_lines.index("    def never_called(self):") + 1
        check("a span starts BELOW its `def`",
              never["start"] == never_at + 1 and never["end"] == never_at + 1,
              f"def at {never_at}, span {never['start']}-{never['end']}")
        getter = next(m for m in para if m["name"] == "text")
        check("a decorator and a multi-line signature are outside the span",
              src_lines[getter["start"] - 1].strip().startswith('"""'),
              f"line {getter['start']}: {src_lines[getter['start'] - 1]!r}")

        # -- the declaration line, which is what a call event names.
        prop_at = src_lines.index("    @property") + 1
        setter_at = src_lines.index("    @text.setter") + 1
        check("a decorated method's `decl` is its FIRST decorator line -- "
              "the `co_firstlineno` the interpreter gives its code object",
              getter["decl"] == prop_at,
              f"@property at {prop_at}, decl {getter['decl']}")
        check("an undecorated method's `decl` is its `def` line",
              never["decl"] == never_at,
              f"def at {never_at}, decl {never['decl']}")
        setter = methods[("lib.text.Paragraph", "text.setter")]
        check("a setter is keyed `text.setter` and its getter keeps `text`, "
              "so the two are told apart by the line a call event carries",
              setter["decl"] == setter_at and setter["start"] > setter_at
              and ("lib.text.Paragraph", "text") in methods,
              str(sorted(n for _o, n in methods)))
        check("a body that begins on the `def` line is counted as the "
              "ambiguity it is, and only there",
              idx["counts"]["ambiguous_one_line_spans"] == 1
              and methods[("lib.text.Paragraph",
                           "one_liner")]["declaration_line_in_span"] is True
              and "declaration_line_in_span" not in never,
              str(idx["counts"]))

        # -- visibility.
        check("a dunder is public: `__init__` and `__len__` are the API",
              methods[("lib.text.Paragraph", "__init__")]["public"]
              and methods[("lib.text.Paragraph", "__len__")]["public"])
        check("a single underscore is not",
              methods[("lib.text.Paragraph", "_internal")]["public"] is False)

        # -- census fields.
        check("a getter and its setter are both indexed as properties",
              [m["name"] for m in para if m["name"].startswith("text")]
              == ["text", "text.setter"]
              and all(m["property"] for m in para
                      if m["name"].startswith("text")))
        check("`static` covers both ways of reaching a method through the "
              "class",
              methods[("lib.text.Paragraph", "blank")]["static"]
              and methods[("lib.text.Paragraph", "of")]["static"]
              and not methods[("lib.text.Paragraph", "__init__")]["static"])

        # -- the join the whole index exists for: `metrics.direct_methods`
        # looks a call event up by (callee_file, callee_line), so the loader
        # has to carry `decl` through.
        from ..bench.metrics import load_prod_index
        import json
        out = os.path.join(d, "py_prod_index.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(idx, fh)
        loaded = load_prod_index(out)
        by_key = {m.key: m for m in loaded.get(rel, ())}
        check("the produced index loads through `metrics.load_prod_index` "
              "with the declaration line the join reads",
              ("lib.text.Paragraph", "text.setter") in by_key
              and by_key[("lib.text.Paragraph", "text")].decl == prop_at
              and by_key[("lib.text.Paragraph", "text.setter")].decl
              == setter_at,
              str(sorted(loaded)))

        descriptor_source = textwrap.dedent('''
            from docx.oxml.xmlchemy import (
                BaseOxmlElement, OneAndOnlyOne, OneOrMore, ZeroOrMore,
                ZeroOrOne, OptionalAttribute, RequiredAttribute,
            )
            from docx.oxml.xmlchemy import OptionalAttribute as Attribute
            from unrelated import OptionalAttribute as UnrelatedAttribute

            class Base(BaseOxmlElement):
                value: str = RequiredAttribute("w:val", ST_String)
                optional = Attribute("w:optional", ST_String)
                child: Child = OneAndOnlyOne(
                    "w:child"
                )
                maybe: Child | None = ZeroOrOne("w:maybe")
                many = ZeroOrMore("w:many")
                required_many = OneOrMore("w:required")
                _private = OptionalAttribute("w:private", ST_String)
                unrelated = UnrelatedAttribute("w:ignored", ST_String)
                many_lst: list[Child]

                @property
                def ordinary(self):
                    return self.value

                @ordinary.setter
                def ordinary(self, value):
                    self.value = value

            class Inherited(Base):
                pass

            class Override(Base):
                child = ZeroOrOne("w:replacement")
                value = OptionalAttribute("w:replacement", ST_String)
        ''').lstrip()
        accessor_path = os.path.join(pkg, "xml.py")
        with open(accessor_path, "w", encoding="utf-8") as fh:
            fh.write(descriptor_source)
        descriptor_index = build_prod_index(d, ["src/lib/xml.py"])
        descriptor_classes = descriptor_index["files"]["src/lib/xml.py"]["classes"]
        by_owner = {c["name"]: c for c in descriptor_classes}
        base = by_owner["lib.xml.Base"]
        lines = descriptor_source.splitlines()

        def declaration(text):
            return next(i for i, line in enumerate(lines, 1)
                        if line.lstrip() == text)

        expected = [
            (declaration('value: str = RequiredAttribute("w:val", ST_String)'),
             "value", "get", True),
            (declaration('value: str = RequiredAttribute("w:val", ST_String)'),
             "value", "set", True),
            (declaration('optional = Attribute("w:optional", ST_String)'),
             "optional", "get", True),
            (declaration('optional = Attribute("w:optional", ST_String)'),
             "optional", "set", True),
            (declaration("child: Child = OneAndOnlyOne("), "child", "get", True),
            (declaration('maybe: Child | None = ZeroOrOne("w:maybe")'),
             "maybe", "get", True),
            (declaration('many = ZeroOrMore("w:many")'), "many_lst", "get", True),
            (declaration('required_many = OneOrMore("w:required")'),
             "required_many_lst", "get", True),
            (declaration('_private = OptionalAttribute("w:private", ST_String)'),
             "_private", "get", False),
            (declaration('_private = OptionalAttribute("w:private", ST_String)'),
             "_private", "set", False),
        ]
        actual = [(a["declaring_line"], a["attribute"], a["access_kind"],
                   a["public"]) for a in base["accessors"]]
        check("all six xmlchemy factory shapes use assignment lines and "
              "installed property names, including annotations and *_lst",
              descriptor_index["schema"] == "r2t.py_prod_index/2"
              and actual == expected, str(actual))
        check("accessor entries carry no invented body span or helper "
              "methods; ordinary getter/setter methods keep their keys",
              all(set(a) == {"declaring_line", "attribute", "access_kind", "public"}
                  for c in descriptor_classes for a in c["accessors"])
              and [m["name"] for m in base["methods"]]
                  == ["ordinary", "ordinary.setter"]
              and base["methods"][0]["decl"] == declaration("@property")
              and base["methods"][0]["start"] == declaration("return self.value")
              and base["methods"][1]["decl"] == declaration("@ordinary.setter")
              and base["methods"][1]["end"] == declaration("self.value = value"))
        check("inherited accessors stay on their declaring class while "
              "overrides have the subclass's new declaration identities",
              by_owner["lib.xml.Inherited"]["accessors"] == []
              and [(a["declaring_line"], a["attribute"], a["access_kind"])
                   for a in by_owner["lib.xml.Override"]["accessors"]] == [
                      (declaration('child = ZeroOrOne("w:replacement")'),
                       "child", "get"),
                      (declaration('value = OptionalAttribute("w:replacement", ST_String)'),
                       "value", "get"),
                      (declaration('value = OptionalAttribute("w:replacement", ST_String)'),
                       "value", "set")])
        check("accessor counts are separate from the unchanged method census",
              descriptor_index["counts"]["accessors"] == 13
              and descriptor_index["counts"]["public_accessors"] == 11
              and descriptor_index["counts"]["methods"] == 2
              and descriptor_index["counts"]["properties"] == 2)

        traversal = textwrap.dedent('''
            from docx.oxml.xmlchemy import BaseOxmlElement, OneAndOnlyOne, ZeroOrOne, OptionalAttribute
            class CT_Inline(BaseOxmlElement):
                graphic: CT_GraphicalObject = OneAndOnlyOne("a:graphic")
            class CT_GraphicalObject(BaseOxmlElement):
                graphicData: CT_GraphicalObjectData = OneAndOnlyOne("a:graphicData")
            class CT_GraphicalObjectData(BaseOxmlElement):
                pic: CT_Picture = ZeroOrOne("pic:pic")
            class CT_Picture(BaseOxmlElement):
                blipFill: CT_BlipFillProperties = OneAndOnlyOne("pic:blipFill")
            class CT_BlipFillProperties(BaseOxmlElement):
                blip: CT_Blip = ZeroOrOne("a:blip")
            class CT_Blip(BaseOxmlElement):
                embed: str | None = OptionalAttribute("r:embed", ST_RelationshipId)
        ''').lstrip()
        traversal_entries = index_source(traversal, "src/docx/oxml/shape.py")
        check("the six-accessor picture traversal indexes distinct declaring "
              "owners even though its factories share closure code",
              [(c["name"], a["attribute"], a["declaring_line"])
               for c in traversal_entries for a in c["accessors"]
               if a["access_kind"] == "get"] == [
                  ("docx.oxml.shape.CT_Inline", "graphic", 3),
                  ("docx.oxml.shape.CT_GraphicalObject", "graphicData", 5),
                  ("docx.oxml.shape.CT_GraphicalObjectData", "pic", 7),
                  ("docx.oxml.shape.CT_Picture", "blipFill", 9),
                  ("docx.oxml.shape.CT_BlipFillProperties", "blip", 11),
                  ("docx.oxml.shape.CT_Blip", "embed", 13)]
              and all(c["methods"] == [] for c in traversal_entries))

    print("ALL PASS (py.prod_index)" if ok else "FAILURES (py.prod_index)")
    return 0 if ok else 1


if __name__ == "__main__":                               # pragma: no cover
    raise SystemExit(selftest())
