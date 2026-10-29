"""Assertion-stripped reference solutions for Java/cucumber-jvm.

The third twin of :mod:`r2t.toolkit.strip`, after :mod:`r2t.toolkit.strip_py`.  What is
language-agnostic is not re-implemented here: the closure decides which
definitions are Then-only, and that decision — including the refusal for a
definition SHARED between an assertion and a setup/action step — is
`strip.then_definitions`, imported and re-exported by identity rather than
mirrored.  A second implementation of "which method is an assertion" would
be a second answer to the question the whole screen rests on.

ONE ARGUMENT IS PASSED TO IT, AND IT IS A FACT ABOUT THE PRODUCER RATHER
THAN ABOUT THE LANGUAGE.  `closure_java.py` records the Gherkin keyword AS
WRITTEN — its own words, and correct, because a cucumber expression is
keyword-agnostic and the keyword is decoration to the registry.  behave's
closures arrive with And/But/`*` already resolved (`pystep_index`), so
`strip.definition_roles` was written to refuse anything else.  This twin
therefore calls it with `resolve_inherited=True` and the shared
`strip.effective_keywords` does the resolution over the closure's own
ordered steps.  Without it the screen refused every cucumber item that
writes `And` — 51 of the 111 frozen Algorand items, and 2,230 of the 5,555
EPUBCheck closure steps carry a non-concrete keyword.

What is Java's is here: emptying a method body without touching a byte of
anything else.  PHP is emptied by finding `function <name>` and Python by
asking its own parser for the body's source span; Java has neither a
`function` keyword nor a parser on this side of the container, so the
declaration is recognised structurally and every ambiguity is REFUSED.

The deviations from both twins, and why each one is not a choice
---------------------------------------------------------------
**A declaration is recognised by what precedes the name, and anything
ambiguous is refused.**  `strip.py` can anchor on
`\\bfunction\\s+&?\\s*<name>\\s*\\(` because PHP marks a declaration with a
keyword and `strip_py.py` can ask `ast`.  Java marks it with a TYPE,
so the rule here is: the name is preceded (across whitespace) by a type —
an identifier that is not a Java keyword, or the `>` of a generic, or the
`]` of an array.  Everything else in the language that can precede
`name(` — `;`, `}`, `=`, `,`, `(`, `.`, `return`, `new` — is a CALL, and a
call is skipped.  As in the PHP twin the scan is over raw bytes, so a
javadoc line that also reads like the declaration produces a second match
and the whole item is refused rather than half-stripped.

**A method whose return type is not `void` is refused.**  `pass` is a legal
body for any Python function and an empty PHP body is legal whatever the
declared return type; an empty Java body is legal only for `void`, because
`missing return statement` is a compile error.  A non-void assertion method
would therefore be stripped into a tree that does not build, and a candidate
scored against a tree that does not build is not measuring anything.  The
refusal is inert on today's corpora and the number is counted rather than
assumed — counted over METHODS, because an annotation is not a method.
The rule: a method counts once if it carries at least one
`@Given/@When/@Then/@And/@But` outside comments and string literals.
Under it the pinned checkouts (epubcheck `82b174ec`, algorand-java-sdk
`4e38dad`) declare 382 step-annotated methods — 53 and 329 — and every
one of them returns `void`.  The annotation OCCURRENCES are 386, 57 and
329: four epubcheck methods carry two step annotations each, the shape
`stub_java.py` cites at `CLISteps.java:153-155`.  Both counts are
written down because reading the 57 as a method count is the mistake
this paragraph made, and because a comment-blind grep answers 59 for
epubcheck — two `@Then` lines in `AssertionSteps.java` are commented
out.  It is implemented because that is a property of two repositories
rather than of the language, and because the failure it prevents reads
as a harness bug rather than as a corpus fact.

**A Java text block is refused rather than scanned.**  `\"\"\"` opens a text
block in Java 15+; the atom scanner here would read it as an empty string
followed by an unterminated one and could walk out of a body.  Both Java
corpora build under JDK 8 and 11 (`stacks.cucumber.ProjectQuirks.jdk_major`),
where a text block does not compile at all, so refusing is free today and
loud the day it is not.

**The closure's `class` does not locate the method.**  It is carried into
the emitted identity (as it is in the PHP twin) but the search is by method
name over the file, so two methods of that name in one file — an overload,
or a nested class with a same-named method — are refused rather than
disambiguated.  That is the PHP twin's behaviour exactly; Java simply has
more ways to reach it.

**No registration fragment.**  `strip.py` re-emits a Behat services file for
the definitions it kept.  cucumber-jvm scans the runner's package and
cucumber-picocontainer builds what it finds, so there is nothing to re-emit,
exactly as there is nothing for the behave twin to re-emit.

What stripping does NOT change
------------------------------
The `@Then` annotation stays.  An assertion method with an empty body is
still registered and still answers its step, so the scenario runs to the end
and reports `passed` — which is the whole point of the control: the
stripped reference is a submission that does everything the gold does
except assert.

An explicit ``assertion_selection`` from the shared authenticated selector
uses the approved response-verifier targets instead of Then selection.
Only the chosen bodies change; policy admission and recipe identity remain
with the shared caller. The default historical path does not opt into it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Optional

from .strip import (StripRefused, definition_roles, load_closures,
                    then_definitions)
from ..core.paths import CONFIG_DIR

#: Java's reserved words, minus the ones that ARE types.  A name preceded by
#: one of these is a call or a control-flow construct, never a declaration:
#: `return check();` and `throw check();` both put an identifier-shaped token
#: in front of `check(`, and neither declares anything.  `void` and the eight
#: primitives are deliberately absent — they are exactly the keywords that
#: CAN precede a method name.
_NOT_A_TYPE = frozenset("""
    abstract assert break case catch class const continue default do else
    enum extends final finally for goto if implements import instanceof
    interface native new package private protected public return static
    strictfp super switch synchronized this throw throws transient try
    volatile while true false null
""".split())

#: The one return type an emptied body is legal for.
_VOID = "void"


def _skip_java_atom(source: str, index: int) -> int:
    """Return the first index after a literal or comment at *index*."""
    n = len(source)
    if source.startswith("//", index):
        end = source.find("\n", index)
        return n if end < 0 else end + 1
    if source.startswith("/*", index):
        end = source.find("*/", index + 2)
        if end < 0:
            raise StripRefused("REFUSED: unterminated Java block comment.")
        return end + 2
    if source.startswith('"""', index):
        raise StripRefused(
            "REFUSED: Java text block (\"\"\") in a gold closure file. This "
            "scanner would read it as an empty string followed by an "
            "unterminated one; both Java corpora build under JDK 8/11, where "
            "a text block does not compile at all.")
    quote = source[index]
    if quote not in "'\"":
        return index + 1
    index += 1
    while index < n:
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return index + 1
        if char == "\n":
            # A Java string or char literal cannot span a line; walking past
            # this newline would put the brace counter inside code it thinks
            # is a literal.
            raise StripRefused(
                "REFUSED: Java literal is not closed on its own line.")
        index += 1
    raise StripRefused("REFUSED: unterminated Java literal.")


def _matching_brace(source: str, opening: int) -> int:
    depth = 0
    index = opening
    while index < len(source):
        if source.startswith(("//", "/*"), index) or source[index] in "'\"":
            index = _skip_java_atom(source, index)
            continue
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise StripRefused(
        "REFUSED: Java method body has no matching closing brace.")


def _preceding_token(source: str, index: int) -> str:
    """The token immediately before *index*, across whitespace.

    `">"` and `"]"` come back as themselves — a generic or an array return
    type — and an identifier comes back whole.  Anything else comes back as
    the single character it is, which is enough for both callers: they only
    ever ask "is this a type".
    """
    end = index - 1
    while end >= 0 and source[end] in " \t\r\n":
        end -= 1
    if end < 0:
        return ""
    if source[end] == ">" and end > 0 and source[end - 1] == "-":
        # A lambda arrow, not the close of a generic.  `xs.forEach(x ->
        # assertNoErrors())` is a CALL, and without this the `>` would read
        # as a return type and the file would be refused as ambiguous — a
        # false refusal rather than a wrong strip, but a whole class of one.
        return "->"
    if not (source[end].isalnum() or source[end] in "_$"):
        return source[end]
    start = end
    while start >= 0 and (source[start].isalnum() or source[start] in "_$"):
        start -= 1
    return source[start + 1:end + 1]


def _declarations(source: str, method: str) -> list[re.Match]:
    """Every occurrence of `method(` that a type precedes.

    Raw bytes, comments included, exactly as the PHP twin scans: a second
    match is a refusal rather than a choice, so a javadoc that quotes the
    signature stops the strip instead of steering it.
    """
    pattern = re.compile(r"(?<![\w$.])" + re.escape(method) + r"\s*\(")
    out = []
    for match in pattern.finditer(source):
        token = _preceding_token(source, match.start())
        if token in (">", "]"):
            out.append(match)
        elif token and (token[0].isalpha() or token[0] in "_$") \
                and token not in _NOT_A_TYPE:
            out.append(match)
    return out


def _method_span(source: str, method: str) -> tuple[int, int, str]:
    """Interior span and indentation for exactly one named Java method."""
    matches = _declarations(source, method)
    if len(matches) != 1:
        raise StripRefused(
            f"REFUSED: expected exactly one Java method declaration named "
            f"{method!r}, found {len(matches)}.")
    match = matches[0]
    returns = _preceding_token(source, match.start())
    if returns != _VOID:
        raise StripRefused(
            f"REFUSED: Java method {method!r} returns {returns!r}, not "
            f"`void`; an emptied body would not compile (`missing return "
            f"statement`), and a reference that does not build measures "
            f"nothing.")
    index = match.end() - 1
    parens = 0
    while index < len(source):
        if source.startswith(("//", "/*"), index) or source[index] in "'\"":
            index = _skip_java_atom(source, index)
            continue
        char = source[index]
        if char == "(":
            parens += 1
        elif char == ")":
            parens -= 1
        elif char == "{" and parens == 0:
            closing = _matching_brace(source, index)
            line_start = source.rfind("\n", 0, index) + 1
            indent = re.match(r"[ \t]*",
                              source[line_start:index]).group(0)
            return index + 1, closing, indent
        elif char == ";" and parens == 0:
            raise StripRefused(
                f"REFUSED: {method!r} is abstract and has no body to strip.")
        index += 1
    raise StripRefused(
        f"REFUSED: cannot locate body of Java method {method!r}.")


def strip_java_source(source: str, methods: list[str]) -> str:
    """Empty the named Java method bodies, preserving every other byte.

    Byte-for-byte the PHP twin's algorithm: each interior span becomes a
    newline and the declaration's own indentation, so the closing brace
    lands where it was and every annotation, import, comment and
    Given/When method is untouched.  Stripping an already-stripped file is
    therefore the identity — the check that says so is in `selftest`.
    """
    spans = []
    for method in sorted(set(methods)):
        start, end, indent = _method_span(source, method)
        spans.append((start, end, "\n" + indent))
    for start, end, replacement in sorted(spans, reverse=True):
        source = source[:start] + replacement + source[end:]
    return source


def _explicit_definitions(closure: dict, selection: dict) \
        -> list[tuple[str, str, str]]:
    """Check the Java source binding of S1's authenticated selection.

    Policy admission and the per-item target table belong to the shared
    selector. This pure transformer does not choose either: it requires the
    selected definitions to remain bound, removable members of this closure
    before it locates their bodies in the supplied Java source.
    """
    fields = ("file", "class", "method")
    if not isinstance(selection, dict) \
            or set(selection) != {"policy", "definitions"} \
            or selection["policy"] != "r2t.reviewed-assertion-targets/1" \
            or not isinstance(selection["definitions"], list):
        raise StripRefused("REFUSED: malformed Java assertion selection.")
    selected = []
    for definition in selection["definitions"]:
        if not isinstance(definition, dict) or set(definition) != set(fields) \
                or any(not isinstance(definition[field], str)
                       or not definition[field] for field in fields):
            raise StripRefused("REFUSED: malformed Java assertion definition.")
        selected.append(tuple(definition[field] for field in fields))
    if not selected or selected != sorted(set(selected)):
        raise StripRefused(
            "REFUSED: explicit Java assertion definitions must be nonempty, "
            "sorted and unique.")
    bound = definition_roles(closure, resolve_inherited=True)
    for key in selected:
        if key not in bound:
            raise StripRefused(
                f"REFUSED: explicit Java assertion is not bound to this "
                f"closure: {key!r}.")
        uses = [step for step in closure["steps"]
                if tuple(step["definition"][field] for field in fields) == key]
        if any(step.get("side") != "removable" for step in uses):
            raise StripRefused(
                f"REFUSED: explicit Java assertion must be removable: {key!r}.")
    return selected


def stripped_solution(gold_root: str, closure: dict, *,
                      source_texts: Optional[dict[str, str]] = None,
                      assertion_selection: Optional[dict] = None) -> dict:
    """Return one pure Java control payload, without executing tests.

    ``assertion_selection`` is S1's authenticated ``{policy, definitions}``
    object for this item under the approved target policy. Its complete
    selection replaces automatic Then selection. Omission retains the
    historical Then-only behavior and metadata byte-for-byte.
    """
    selected = (then_definitions(closure, resolve_inherited=True)
                if assertion_selection is None else
                _explicit_definitions(closure, assertion_selection))
    by_file: dict[str, list[str]] = {}
    for rel, _cls, method in selected:
        by_file.setdefault(rel, []).append(method)
    files = []
    for rel in closure.get("files") or []:
        if source_texts is not None:
            try:
                original = source_texts[rel]
            except KeyError as exc:
                raise StripRefused(
                    f"REFUSED: frozen gold closure omits {rel!r}") from exc
        else:
            path = os.path.join(gold_root, rel)
            try:
                with open(path, encoding="utf-8") as fh:
                    original = fh.read()
            except OSError as exc:
                raise StripRefused(
                    f"REFUSED: cannot read gold closure file {rel!r}: "
                    f"{exc}") from exc
        files.append({"file_path": rel,
                      "code": strip_java_source(original,
                                                by_file.get(rel, []))})
    missing = sorted(set(by_file) - set(closure.get("files") or []))
    if missing:
        raise StripRefused(
            f"REFUSED: {'Then' if assertion_selection is None else 'Explicit'} "
            f"definitions name files outside the gold closure: "
            f"{missing}.")
    identities = [{"file": rel, "class": cls, "method": method}
                  for rel, cls, method in selected]
    metadata = {
        "source": "stripped_gold", "stripped_gold": True,
        "item_id": closure.get("item_id"),
    }
    if assertion_selection is not None:
        metadata["assertion_selection"] = {
            "policy": assertion_selection["policy"],
            "definitions": identities,
        }
        return {"files": files, "metadata": metadata}
    return {
        "files": files,
        "metadata": {
            **metadata,
            "n_then_definitions": len(selected),
            "then_definitions": identities,
            "definition_identity_sha256": hashlib.sha256(
                json.dumps(identities, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        },
    }


def make_strip_adapter(gold_root: str, closures_path: str):
    """Fixture adapter used to produce the stripped baseline and N=2 sweep."""
    from ..bench.adapters import Adapter
    closures = load_closures(closures_path)

    def run(task: dict) -> dict:
        item_id = task.get("item_id")
        closure = closures.get(item_id)
        if closure is None:
            return {"files": [], "metadata": {
                "adapter_error": f"no closure for {item_id}",
                "strip_refusal": True, "source": "stripped_gold",
                "stripped_gold": True, "item_id": item_id}}
        try:
            return stripped_solution(gold_root, closure)
        except StripRefused as exc:
            return {"files": [], "metadata": {
                "adapter_error": str(exc), "strip_refusal": True,
                "source": "stripped_gold", "stripped_gold": True,
                "item_id": item_id}}

    return Adapter("stripped-gold", run,
                   {"gold": gold_root, "closures": closures_path})


# ----------------------------------------------------------------- selftest
#: One realistic glue file: a Given, a When and two Thens, in the shape and
#: the brace style the epubcheck corpus is written in (Allman, two spaces).
#: Every refusal fixture below is a MUTATION of this one, so what a case
#: proves is the difference between it and this text and nothing else.
_GLUE = '''package org.w3c.epubcheck.test;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

public class ExampleSteps
{

  private int code = -1;

  @Given("EPUBCheck with default settings")
  public void configure()
  {
    this.code = 0;
  }

  @When("checking EPUB {string}")
  public void check(String path)
  {
    // a brace in a comment: } and a "}" in a string
    this.code = path.length() > 0 ? 0 : 1;
  }

  @Then("the return code is {int}")
  public void assertReturnCode(int expected)
  {
    if (this.code != expected)
    {
      throw new AssertionError("bad code: }");
    }
  }

  @Then("no errors are reported")
  public void assertNoErrors()
  {
    assertThat(this.code, is(0));
  }
}
'''

#: `method -> (its declaration and body in _GLUE, the same declaration with
#: an emptied body)`.  The expectation of a strip is the WHOLE file with
#: these substitutions applied, not a list of substrings that must survive:
#: a brace counter that walked out of a body would leave every substring in
#: place and add a stray `}` somewhere else, and only equality sees that.
_EMPTIED: dict[str, tuple[str, str]] = {
    "assertNoErrors": (
        "  public void assertNoErrors()\n"
        "  {\n"
        "    assertThat(this.code, is(0));\n"
        "  }",
        "  public void assertNoErrors()\n"
        "  {\n"
        "  }"),
    "assertReturnCode": (
        "  public void assertReturnCode(int expected)\n"
        "  {\n"
        "    if (this.code != expected)\n"
        "    {\n"
        "      throw new AssertionError(\"bad code: }\");\n"
        "    }\n"
        "  }",
        "  public void assertReturnCode(int expected)\n"
        "  {\n"
        "  }"),
}

#: `name -> the methods to empty`.  One row per shape worth distinguishing:
#: a flat body, both Thens at once (which is also the Given/When
#: preservation case, since the expectation is the whole file), and a body
#: whose braces nest inside an `if` and inside a string literal.
_STRIP_CASES: dict[str, list[str]] = {
    "one Then body": ["assertNoErrors"],
    "both Then bodies, Given/When byte-preserved":
        ["assertNoErrors", "assertReturnCode"],
    "a body whose braces and strings nest": ["assertReturnCode"],
}

#: The other brace style, which is in the SAME corpus rather than another
#: one: `CLISteps.java:121` opens its body at the end of the signature line
#: while `AssertionSteps.java:37` opens it on the next.  The indentation the
#: emptied body keeps is the DECLARATION's, so both shapes have to be
#: written down or the K&R one would be re-indented and the diff against
#: gold would be noise.
_GLUE_KR = '''package org.w3c.epubcheck.test;

public class KRSteps {
  @Given("stderr is redirected to stdout")
  public void redirect() {
    System.setErr(new PrintStream(stdout));
  }

  @Then("the return code is {int}")
  public void assertReturnCode(int code) {
    assertThat(this.code, is(code));
  }
}
'''

_GLUE_KR_STRIPPED = '''package org.w3c.epubcheck.test;

public class KRSteps {
  @Given("stderr is redirected to stdout")
  public void redirect() {
    System.setErr(new PrintStream(stdout));
  }

  @Then("the return code is {int}")
  public void assertReturnCode(int code) {
  }
}
'''

#: `name -> (the mutation applied to _GLUE, the method, the refusal needle)`.
_REFUSAL_CASES: dict[str, tuple[str, str, str, str]] = {
    "an overload is ambiguous, never guessed": (
        "  public void assertNoErrors()\n  {",
        "  public void assertNoErrors(int n)\n  {\n  }\n\n"
        "  public void assertNoErrors()\n  {",
        "assertNoErrors", "found 2"),
    "a javadoc that quotes the signature is ambiguous too": (
        "  @Then(\"no errors are reported\")",
        "  /** void assertNoErrors() does the checking. */\n"
        "  @Then(\"no errors are reported\")",
        "assertNoErrors", "found 2"),
    "a non-void assertion method cannot be emptied": (
        "  public void assertNoErrors()",
        "  public boolean assertNoErrors()",
        "assertNoErrors", "not `void`"),
    "a generic return type is non-void and says so": (
        "  public void assertNoErrors()",
        "  public List<String> assertNoErrors()",
        "assertNoErrors", "not `void`"),
    "an abstract declaration has no body to strip": (
        "  public void assertNoErrors()\n  {\n    assertThat(this.code, "
        "is(0));\n  }",
        "  public abstract void assertNoErrors();",
        "assertNoErrors", "abstract"),
    "a method nothing declares is refused": (
        "  public void assertNoErrors()", "  public void assertNoErrors()",
        "assertSomethingElse", "found 0"),
    "a text block is refused rather than scanned": (
        "    assertThat(this.code, is(0));",
        "    String s = \"\"\"\n      x\n      \"\"\";",
        "assertNoErrors", "text block"),
    "an unterminated block comment is refused": (
        "    assertThat(this.code, is(0));",
        "    /* never closed",
        "assertNoErrors", "unterminated Java block comment"),
}


def _closure(steps: list[tuple[str, str, str]], *,
             files: Optional[list[str]] = None) -> dict:
    """`[(keyword, class, method)]` -> a closure over one glue file."""
    return {"item_id": "epubcheck/f.feature:3",
            "files": ["src/test/java/org/w3c/epubcheck/test/ExampleSteps"
                      ".java"] if files is None else files,
            "steps": [{"keyword": keyword, "side": "removable",
                       "definition": {
                           "file": "src/test/java/org/w3c/epubcheck/test/"
                                   "ExampleSteps.java",
                           "class": cls, "method": method}}
                      for keyword, cls, method in steps]}


#: The shared-definition table: which effective roles a method is used
#: under, and what `then_definitions` must do about it.  ENUMERATED rather
#: than sampled, because "a method backing both a Then and a Given is
#: reported, not silently stripped" is the one claim the whole screen's
#: honesty rests on.
_ROLE_CASES: dict[str, tuple[list[tuple[str, str, str]], Optional[list[str]],
                             str]] = {
    "Then-only is selected": (
        [("Given", "ExampleSteps", "configure"),
         ("Then", "ExampleSteps", "assertNoErrors")],
        ["assertNoErrors"], ""),
    "two Then-only definitions are both selected": (
        [("Then", "ExampleSteps", "assertReturnCode"),
         ("Then", "ExampleSteps", "assertNoErrors")],
        ["assertNoErrors", "assertReturnCode"], ""),
    "shared with Given is REFUSED, not stripped": (
        [("Given", "ExampleSteps", "assertNoErrors"),
         ("Then", "ExampleSteps", "assertNoErrors")],
        None, "shared with Given/When"),
    "shared with When is REFUSED, not stripped": (
        [("When", "ExampleSteps", "assertNoErrors"),
         ("Then", "ExampleSteps", "assertNoErrors")],
        None, "shared with Given/When"),
    "shared through a THIRD step under a third keyword is still shared": (
        [("Given", "ExampleSteps", "configure"),
         ("Then", "ExampleSteps", "assertNoErrors"),
         ("When", "ExampleSteps", "assertNoErrors")],
        None, "shared with Given/When"),
    "no Then at all is REFUSED: the item cannot be screened": (
        [("Given", "ExampleSteps", "configure"),
         ("When", "ExampleSteps", "check")],
        None, "no Then-only definition"),
}


def selftest() -> int:                                        # noqa: C901
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def raises(fn, needle="") -> bool:
        try:
            fn()
        except (Exception, SystemExit) as e:                  # noqa: BLE001
            return needle in str(e)
        return False

    def stripped(source: str, methods: list[str]) -> str:
        """The stripped text, or the refusal as text.

        A refusal is a RESULT here rather than an exception, so a case that
        starts refusing shows up as the named check failing with the reason
        attached instead of as a traceback that stops the file.
        """
        try:
            return strip_java_source(source, methods)
        except Exception as e:                                # noqa: BLE001
            return f"REFUSED[{type(e).__name__}]: {e}"

    # -- the emptying, over one realistic glue file -----------------------
    for name, methods in _STRIP_CASES.items():
        expected = _GLUE
        for method in methods:
            before, after = _EMPTIED[method]
            check(f"the fixture for {name!r} quotes {method}'s real body",
                  before in expected, before)
            expected = expected.replace(before, after, 1)
        out = stripped(_GLUE, methods)
        check(f"strip: {name} -- the WHOLE file, byte for byte",
              out == expected, out)
        check(f"...and stripping it again is the identity: {name}",
              stripped(out, methods) == out)
    check("the order the methods are named in cannot change the bytes",
          stripped(_GLUE, ["assertNoErrors", "assertReturnCode"])
          == stripped(_GLUE, ["assertReturnCode", "assertNoErrors"]))
    check("naming one method twice is the same as naming it once",
          stripped(_GLUE, ["assertNoErrors", "assertNoErrors"])
          == stripped(_GLUE, ["assertNoErrors"]))
    check("emptying nothing changes nothing, byte for byte",
          stripped(_GLUE, []) == _GLUE)
    check("a `}` inside a string literal and inside a comment do not close "
          "the body: the When body's commented brace and the Then body's "
          "quoted one both survive the walk over the other method",
          '// a brace in a comment: } and a "}" in a string'
          in stripped(_GLUE, ["assertReturnCode", "assertNoErrors"]))
    check("the annotation is NOT removed: an emptied Then still registers "
          "and still answers its step, which is what makes the scenario run",
          stripped(_GLUE, ["assertNoErrors"]).count("@Then(") == 2)
    check("a body opened at the end of the signature line -- the OTHER brace "
          "style, in the same corpus -- keeps that line and its own indent",
          stripped(_GLUE_KR, ["assertReturnCode"]) == _GLUE_KR_STRIPPED,
          stripped(_GLUE_KR, ["assertReturnCode"]))
    check("...and that one is idempotent too",
          stripped(_GLUE_KR_STRIPPED, ["assertReturnCode"])
          == _GLUE_KR_STRIPPED)

    # -- the refusals -----------------------------------------------------
    for name, (before, after, method, needle) in _REFUSAL_CASES.items():
        check(f"the fixture for {name!r} really is a mutation of the glue",
              before in _GLUE, before)
        mutated = _GLUE.replace(before, after, 1)
        check(f"refuse: {name}",
              raises(lambda m=mutated, k=method: strip_java_source(m, [k]),
                     needle), needle)

    # A call that looks like a declaration is the case a naive `name\\s*\\(`
    # scan gets wrong in the other direction: it would count two matches and
    # refuse a file that is perfectly ordinary.
    gold_body = "    assertThat(this.code, is(0));"
    call_body = ("    assertReturnCode(0);\n"
                 "    this.assertReturnCode(1);\n"
                 "    if (true) assertReturnCode(2);\n"
                 # A lambda arrow, whose `>` would otherwise read as the
                 # close of a generic return type.
                 "    list.forEach(x -> assertReturnCode(3));\n"
                 # `return <void call>;` is legal Java inside a void method,
                 # and it is the one call shape that puts a bare IDENTIFIER
                 # in front of the name -- the case `_NOT_A_TYPE` exists for.
                 "    return assertReturnCode(4);")
    calls = _GLUE.replace(gold_body, call_body)
    calls_expected = calls
    for method in ("assertNoErrors", "assertReturnCode"):
        before, after = _EMPTIED[method]
        calls_expected = calls_expected.replace(
            before.replace(gold_body, call_body), after, 1)
    check("a CALL is not a declaration: five calls to a method beside its "
          "one declaration still strip -- the lambda's `->` is not the close "
          "of a generic and `return f();` is not a return type, and those "
          "two are the whole reason `_preceding_token` and `_NOT_A_TYPE` "
          "exist",
          stripped(calls, ["assertReturnCode", "assertNoErrors"])
          == calls_expected,
          stripped(calls, ["assertReturnCode", "assertNoErrors"]))
    check("...and the same file with the declaration renamed away refuses, "
          "so the calls alone are never mistaken for one",
          raises(lambda: strip_java_source(
              calls.replace("  public void assertReturnCode(int expected)",
                            "  public void unrelatedName(int expected)"),
              ["assertReturnCode"]), "found 0"))

    # -- the shared-definition table -------------------------------------
    check("the shared-definition rule is the PHP twin's own function, not a "
          "copy of it",
          then_definitions is __import__(
              "r2t.toolkit.strip", fromlist=["then_definitions"]).then_definitions)
    for name, (steps, expect, needle) in _ROLE_CASES.items():
        closure = _closure(steps)
        if expect is None:
            check(f"roles: {name}",
                  raises(lambda c=closure: then_definitions(c), needle),
                  needle)
            # ...and the refusal reaches the solution, so no caller can get a
            # stripped file for an item the rule refuses.
            check(f"...and `stripped_solution` refuses it too: {name}",
                  raises(lambda c=closure: stripped_solution(
                      "/nonexistent", c,
                      source_texts={c["files"][0]: _GLUE}), needle))
        else:
            got = [method for _f, _c, method in then_definitions(closure)]
            check(f"roles: {name}", got == sorted(expect), str(got))
    roles = definition_roles(_closure(
        [("Given", "ExampleSteps", "configure"),
         ("Then", "ExampleSteps", "assertNoErrors"),
         ("Then", "ExampleSteps", "configure")]))
    check("the closure's EFFECTIVE keyword decides the role and a "
          "definition used twice accumulates both -- the Java source is "
          "read for a BODY, never for a role, so an `@Then` sitting over a "
          "method no Then step reached cannot select it",
          sorted((key[2], sorted(value)) for key, value in roles.items())
          == [("assertNoErrors", ["then"]),
              ("configure", ["given", "then"])], str(roles))

    # -- the two approved Algorand response-verifier shapes ----------------
    # These fixtures exercise the bounded Java seam. S1 authenticates the
    # per-item selection before calling it; this is not a second policy
    # registry or a fixture that authorizes collection.
    import copy
    java_rel = "src/test/java/com/algorand/algosdk/unit/IndexerResponses.java"
    shared_rel = "src/test/java/com/algorand/algosdk/unit/ResponsesShared.java"
    java_class = "com.algorand.algosdk.unit.IndexerResponses"
    accounts_method = (
        "the_parsed_SearchAccounts_response_should_be_valid_on_round_and_"
        "the_array_should_be_of_len_and_the_element_at_index_should_have_"
        "authorizing_address")
    transactions_method = (
        "the_parsed_SearchForTransactions_response_should_be_valid_on_round_"
        "and_the_array_should_be_of_len_and_the_element_at_index_should_"
        "have_rekey_to")
    java_source = """package com.algorand.algosdk.unit;
public class IndexerResponses {
    @When("we make any SearchAccounts call")
    public void accounts() {
        ClientMocker.infect(client);
        accountsResponse = client.searchForAccounts().execute();
    }
    @When("we make any SearchForTransactions call")
    public void transactions() {
        ClientMocker.infect(client);
        transactionsResponse = client.searchForTransactions().execute();
    }
    @Then("another account response should be valid")
    public void anotherAccountsCheck() {
        verifyResponse(accountsResponse, shared.bodyFile);
    }
    @When("the parsed SearchAccounts response should be valid")
    public void ACCOUNTS(Integer a, Integer b, Integer c, String address) throws IOException {
        verifyResponse(accountsResponse, shared.bodyFile);
    }
    @When("the parsed SearchForTransactions response should be valid")
    public void TRANSACTIONS(Integer a, Integer b, Integer c, String address) throws IOException {
        verifyResponse(transactionsResponse, shared.bodyFile);
    }
}
""".replace("ACCOUNTS", accounts_method).replace(
        "TRANSACTIONS", transactions_method)
    shared_source = """public class ResponsesShared {
    @Given("mock http responses loaded")
    public void mockResponse() {
        Assert.assertTrue(fixture.exists());
        ClientMocker.loadFixture(fixture);
    }
}
"""
    sources = {java_rel: java_source, shared_rel: shared_source}
    for line, action, method, response in (
            (106, "accounts", accounts_method, "accountsResponse"),
            (115, "transactions", transactions_method, "transactionsResponse")):
        definition = {"file": java_rel, "class": java_class, "method": method}
        selected = {"policy": "r2t.reviewed-assertion-targets/1",
                    "definitions": [definition]}
        control_closure = {
            "item_id": "algorand-sdk/features/unit/"
                       f"v2indexerclient_responses.feature:{line}",
            "files": [java_rel, shared_rel],
            "steps": [
                {"keyword": "Given", "side": "removable", "definition": {
                    "file": shared_rel, "class": "ResponsesShared",
                    "method": "mockResponse"}},
                {"keyword": "When", "side": "removable", "definition": {
                    "file": java_rel, "class": java_class, "method": action}},
                {"keyword": "And", "side": "removable",
                 "definition": definition},
            ],
        }
        selected_before = copy.deepcopy(selected)
        payload = stripped_solution(
            "", control_closure, source_texts=sources,
            assertion_selection=selected)
        signature = next(line for line in java_source.splitlines()
                         if f"void {method}(" in line)
        expected = java_source.replace(
            signature + f"\n        verifyResponse({response}, shared.bodyFile);"
            "\n    }", signature + "\n    }", 1)
        check(f"explicit Algorand :{line} empties only its verifier body, "
              "preserving mock setup, SDK actions and the other verifier",
              payload["files"] == [
                  {"file_path": java_rel, "code": expected},
                  {"file_path": shared_rel, "code": shared_source}])
        check(f"explicit :{line} emits the exact selection metadata, "
              "without claiming Then-only definitions",
              payload["metadata"] == {
                  "source": "stripped_gold", "stripped_gold": True,
                  "item_id": control_closure["item_id"],
                  "assertion_selection": selected_before}
              and selected == selected_before
              and sources == {java_rel: java_source, shared_rel: shared_source})
        check(f"default :{line} retains the historical no-Then refusal",
              raises(lambda: stripped_solution(
                  "", control_closure, source_texts=sources), "no Then-only"))
        action_then = copy.deepcopy(control_closure)
        action_then["steps"][1]["keyword"] = "Then"
        check(f"explicit :{line} replaces automatic selection rather than "
              "unioning the SDK action into the stripped targets",
              stripped_solution("", action_then, source_texts=sources,
                                assertion_selection=selected) == payload)
        wrong = copy.deepcopy(selected)
        wrong["definitions"][0]["class"] = "AnotherClass"
        check(f"explicit :{line} rejects a changed definition binding",
              raises(lambda: stripped_solution(
                  "", control_closure, source_texts=sources,
                  assertion_selection=wrong), "not bound"))
        retained = copy.deepcopy(control_closure)
        retained["steps"][-1]["side"] = "retained"
        check(f"explicit :{line} never strips a retained helper target",
              raises(lambda: stripped_solution(
                  "", retained, source_texts=sources,
                  assertion_selection=selected), "must be removable"))
        changed_source = {**sources, java_rel: java_source.replace(
            "public void " + method, "public void renamedVerifier")}
        check(f"explicit :{line} refuses a source whose target disappeared",
              raises(lambda: stripped_solution(
                  "", control_closure, source_texts=changed_source,
                  assertion_selection=selected), "found 0"))
        check(f"explicit :{line} preserves missing-source refusal",
              raises(lambda: stripped_solution(
                  "", control_closure, source_texts={shared_rel: shared_source},
                  assertion_selection=selected), "frozen gold closure omits"))
        empty = {**selected, "definitions": []}
        check(f"explicit :{line} refuses an empty selection instead of "
              "returning unmodified gold",
              raises(lambda: stripped_solution(
                  "", control_closure, source_texts=sources,
                  assertion_selection=empty), "nonempty"))

    # -- the solution ------------------------------------------------------
    rel = "src/test/java/org/w3c/epubcheck/test/ExampleSteps.java"
    closure = _closure([("Given", "ExampleSteps", "configure"),
                        ("When", "ExampleSteps", "check"),
                        ("Then", "ExampleSteps", "assertNoErrors")])
    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_GLUE)
        doc = stripped_solution(root, closure)
    check("the solution carries every closure file and the exact identity",
          [f["file_path"] for f in doc["files"]] == [rel]
          and doc["metadata"]["then_definitions"] == [
              {"file": rel, "class": "ExampleSteps",
               "method": "assertNoErrors"}]
          and doc["metadata"]["n_then_definitions"] == 1, str(doc["metadata"]))
    check("...and it is the stripped text, not the original",
          doc["files"][0]["code"] == strip_java_source(_GLUE,
                                                       ["assertNoErrors"]))
    check("the identity digest is over the identities and nothing else",
          doc["metadata"]["definition_identity_sha256"]
          == hashlib.sha256(json.dumps(
              doc["metadata"]["then_definitions"], sort_keys=True,
              separators=(",", ":")).encode("utf-8")).hexdigest())
    check("a frozen closure missing one of its own files is REFUSED",
          raises(lambda: stripped_solution("/nonexistent", closure,
                                           source_texts={}), "omits"))
    check("a Then definition in a file the closure does not carry is REFUSED",
          raises(lambda: stripped_solution(
              "/nonexistent",
              dict(_closure([("Then", "ExampleSteps", "assertNoErrors")]),
                   files=["other.java"]),
              source_texts={"other.java": _GLUE}), "outside the gold closure"))
    check("an unreadable gold file is a refusal, not a traceback",
          raises(lambda: stripped_solution("/nonexistent", closure),
                 "cannot read gold closure file"))

    # -- the adapter -------------------------------------------------------
    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_GLUE)
        cpath = os.path.join(root, "closures.json")
        with open(cpath, "w", encoding="utf-8") as fh:
            json.dump([closure,
                       _closure([("Given", "ExampleSteps", "assertNoErrors"),
                                 ("Then", "ExampleSteps", "assertNoErrors")])
                       | {"item_id": "epubcheck/f.feature:9"}], fh)
        adapter = make_strip_adapter(root, cpath)
        check("the adapter is named stripped-gold",
              adapter.name == "stripped-gold", adapter.name)
        good = adapter({"item_id": closure["item_id"]})
        check("an item with a strippable closure produces the stripped file",
              len(good["files"]) == 1
              and good["metadata"]["stripped_gold"] is True
              and "strip_refusal" not in good["metadata"], str(good))
        shared = adapter({"item_id": "epubcheck/f.feature:9"})
        check("a SHARED definition comes back as a refusal on the record, so "
              "it enters the fidelity accounting instead of being scored",
              shared["files"] == []
              and shared["metadata"]["strip_refusal"] is True
              and "shared with Given/When"
              in shared["metadata"]["adapter_error"], str(shared["metadata"]))
        unknown = adapter({"item_id": "epubcheck/f.feature:99"})
        check("an item with no closure is a refusal too, never a pass-through",
              unknown["files"] == []
              and "no closure" in unknown["metadata"]["adapter_error"])

    # -- the seam this milestone lands ------------------------------------
    import argparse

    from ..bench.fixtures import _strip_maker
    from ..stacks import cucumber as _cucumber
    check("the cucumber stack exposes stripped_solution and its adapter "
          "factory, and both ARE these functions",
          getattr(_cucumber, "stripped_solution", None) is stripped_solution
          and getattr(_cucumber, "make_strip_adapter", None)
          is make_strip_adapter)
    profile = os.path.join(CONFIG_DIR, "profile_epubcheck.yml")
    if os.path.isfile(profile):
        check("a run carrying the epubcheck profile builds THIS strip "
              "adapter -- a PHP or Python stripper over a Java tree would "
              "empty nothing and the de-saturation control would be gold",
              _strip_maker(argparse.Namespace(profile=profile))
              is make_strip_adapter)
    else:
        print(f"  [SKIP] no {profile}, so the fixture dispatch could not be "
              f"driven")
    from . import strip as _php_strip
    check("a run with no profile still builds the PHP one",
          _strip_maker(argparse.Namespace()) is _php_strip.make_strip_adapter)

    print("\n" + ("ALL PASS (strip_java)" if ok else "FAILURES (strip_java)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
