"""The vacuous floor of the anti-vacuity gate, for cucumber-jvm (SPEC §3.10).

The third twin, after `r2t/toolkit/stub.py` (Behat) and `r2t/toolkit/stub_py.py` (behave):
the same three rules, against a framework that enforces each one
differently, plus two rules the LANGUAGE rather than the framework forces.

A recall-style metric rewards a submission that *runs* the scenario, and the
cheapest way to run a cucumber scenario is to define every step it needs
with an empty body: cucumber then reports every step `passed` while the
submission asserts nothing at all.  This module builds exactly that
submission, so the benchmark can measure what a maximally vacuous candidate
scores instead of assuming it scores nothing.  As in both other twins,
"stub = 0 by construction" is an EXPECTATION and not a proof: the stub
replaces only the removable half, while the retained runner, the retained
`EPUBCheckConfiguration`/`TestEnvironment` hooks and cucumber's own JSON
formatter still run and can fail on a mutated production line the empty
bodies never observed.  The gate is honoured only if the MEASURED stub
mutation recall is ≤ 0.02.

The three rules, and what each one becomes in cucumber-jvm
----------------------------------------------------------
**1. One definition per DISTINCT step, and "distinct" means the TEXT.**
Behat matches on text alone and `stub.py` keys on text; behave matches per
keyword and `stub_py.py` keys on the `(keyword, text)` PAIR.  cucumber-jvm
is the Behat case, and the corpus says so in its own bytes rather than the
documentation saying it here: `EPUBCheckConfiguration.java:106` registers
`EPUBCheck configured to check EPUB {version} rules` with `@And`, and
`epub2/opf-publication.feature:21` writes that step as `Given` (so does
`TestEnvironment.java:30`'s `@And`-registered default-locale step, written
`Given` at `localization/localization.feature:23`).  An `@And` annotation
could never answer a `Given` line if the keyword took part in matching, so
the keyword does not, and the key here is the text.  Both witnesses are
re-read from the pinned checkout by `selftest` when it is present.

Emitting one method per step OCCURRENCE would register the same expression
twice, which cucumber refuses; emitting one per `(keyword, text)` pair would
do the same for a text that appears under two keywords, which is why the
behave twin's key is WRONG here rather than merely different.

**2. The pattern is anchored, and this module anchors it.**  cucumber-jvm
decides whether an annotation's string is a Cucumber Expression or a regular
expression by looking at the string: one that begins with `^` and ends with
`$` is a regular expression.  Every pattern here carries BOTH anchors, so
the reading does not depend on which of the two markers the factory tests
for.  A Cucumber Expression is not an option: `{`, `(` and `/` are all
syntax there — `{int}` is a parameter, `(s)` is optional text, `are/is` is
an alternation — and epubcheck's own glue uses all three in one line
(`AssertionSteps.java:36`, `@Then("no( other) warning(s)/error(s) or
error(s)/warning(s) are/is reported")`).  A literal step text handed to that
parser is not a literal at all.

The escaping is PER-CHARACTER (`regex_quote` below), not
`java.util.regex.Pattern.quote`.  `Pattern.quote` produces `\\Q…\\E`, which
makes the compiled engine treat the span literally but leaves a `(` or a `[`
visible in the pattern SOURCE to anything that reads the source rather than
the compiled pattern — and how cucumber counts a step definition's capture
groups is a question this file cannot answer without the jar.  Per-character
escaping is the spelling both twins already use (`preg_quote`, `re.escape`),
it costs nothing, and it removes the question.

**3. A step already answered by RETAINED or PRODUCTION code is not defined
again.**  Two definitions matching one step is
`io.cucumber.core.runner.AmbiguousStepDefinitionsException` — the name is
imported from `stacks.cucumber.AMBIGUOUS_EXCEPTION` rather than retyped, and
that stack already folds AMBIGUOUS to `failed`, so a stub that re-defined a
retained step would score 0 for a reason that is not vacuity.  The
vocabulary is `boundary.py`'s and both `retained` and `production` survive
stripping.  Unlike the behave twin's corpus, this rule is NOT inert here:
`config/boundary_epubcheck.yml` discloses that the retained
`EPUBCheckConfiguration` and `TestEnvironment` answer steps the candidate
therefore never writes, and most epubcheck scenarios open with some of
them.  Nine methods between the two carry a STEP annotation — seven and
two — and `EPUBCheckConfiguration` carries two more that are `@Before`/
`@After` hooks and answer no step of any scenario.  The distinction is
spelled out because the boundary file records making the opposite mistake
with the same number, and a stub that counted the hooks would be
excluding steps nothing had answered.

The two rules JAVA adds
-----------------------
**4. A method's parameter list must match the step's multiline argument.**
The PHP twin absorbs a `TableNode`/`PyStringNode` with two OPTIONAL typed
parameters, because Behat can call a method with fewer arguments than it
declares.  Java cannot: a method has one arity, and cucumber checks it —
a step carrying a DocString or a DataTable supplies one extra argument, in
the LAST parameter.  epubcheck's own glue shows the shape at
`CLISteps.java:153-155`, where one method with two parameters carries both
`@Then("{outputStream} is")` (the DocString fills the second) and
`@Then("{outputStream} is {string}")` (the text fills it).  So the stub has
to be told, per step, whether that argument exists — a zero-parameter method
for a DocString step is an ERROR rather than a vacuous pass, and an erroring
stub is scored 0 by ineligibility, which is the one direction of error the
≤ 0.02 bound cannot survive (it shrinks the population the bound is measured
over and makes the floor look lower than it is).

The vocabulary is `gherkin.Step.arg_kind`'s — `None`, `"table"`,
`"pystring"` — and not a third one invented here.  `step_keys` still
REFUSES a closure step that does not carry the key, because a default would
be a guess about the shape of a scenario, silently wrong for exactly the
items that carry the argument.

WHERE THE KEY COMES FROM IS THE PINNED .FEATURE BYTES, not the closure.  No
cucumber closure carries it and none can: `closure_java.py` binds steps
from cucumber's own registry, which reports WHICH method matched and never
what followed the step, so the DocString/DataTable/neither question has no
answer on that side.  It has one in the source line, and `gherkin`'s reader
already answers it.  `resolve_closure_steps` therefore joins each closure
step to the pinned feature file by `feature_file` + `source_line`, refuses
any step it cannot locate, refuses any line whose written keyword disagrees
with the bytes — the check that proves the tree is the one the closure was
built from — and hands `step_keys` a closure with the measured
`arg_kind` and the unchanged written keyword.  Measured over the frozen Algorand
release: 1,821 closure steps, 1,821 located, 0 keyword disagreements.

That reader has a gap this module cannot repair and will not hide:
`gherkin._PYSTRING` recognises `\"\"\"` and `'''`, while Gherkin also allows
a ``` fence and epubcheck's `cli.feature` uses it (line 18, under `And
stdout is`).  A closure built from this tree's reader therefore reports
`arg_kind: None` for those steps, and the stub would emit a zero-parameter
method for a step cucumber hands a DocString.  `selftest` demonstrates the
gap against the real parser rather than describing it; closing it is J4's,
because the closure is where the shape is decided.

**5. The glue class goes where THIS project's runner scans, and nowhere
else.**  cucumber-jvm discovers glue by scanning the runner's package, so a
class in the wrong package is not glue at all — every step comes out
`undefined` and the measured floor reads 0.00 for a reason that has nothing
to do with vacuity, which is the failure `fixtures._stub_maker`
exists to prevent between LANGUAGES and which would reappear here between
PROJECTS.  The destination is therefore read from
`stacks.cucumber.quirks_for`, the same closed routing decision the runner
uses, and an unknown project is a refusal rather than epubcheck's package by
default.

Why there is no closure-free fallback
-------------------------------------
`stub.py` can recover a Behat item's steps by parsing
`requirement.background` and `criterion.gherkin` out of the release.  That
is impossible here for both of the reasons the behave twin gives: a Scenario
Outline's stored gherkin carries the TEMPLATE steps without the Examples
table, and a parse of the item cannot tell a step the retained code already
answers from one it does not.  A third reason is this stack's own: rule 4
needs the multiline argument of the step cucumber will actually run.  So a
closure is REQUIRED and its absence is a refusal, not a degraded mode.

What cucumber does not need
---------------------------
No registration fragment.  Behat needs a services file and behave needs the
module to sit under `features/steps/`; cucumber-jvm scans the runner's
package, so installing the class in that quirk's `glue_rel` IS registering
it.
The stub class declares no constructor, so cucumber-picocontainer builds it
with no dependencies to resolve.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Optional

from ..bench.runner import item_key
from ..core.paths import BENCHMARK_ROOT, CONFIG_DIR

#: The top-level Maven test source root used by the original Java corpora.
#: The stack also recognizes Kapua module roots. This constant is named
#: here rather than imported to keep this module importable from
#: `stacks/cucumber.py` (which binds the seam at its own end); `selftest`
#: asserts the two constants agree.
JAVA_TEST_ROOT = "src/test/java"

#: Closure step `side` values naming code that SURVIVES stripping, and whose
#: definitions the stub must therefore not duplicate.  `boundary.py`'s
#: vocabulary (`removable | retained | production`, and `None` for a step
#: with no definition at all), the same frozenset both twins use.
_ALREADY_ANSWERED = frozenset({"retained", "production"})

#: The multiline argument a step carries -> the trailing parameter the glue
#: method must declare for it, and the type's import.  The keys are
#: `gherkin.Step.arg_kind`'s own vocabulary; `selftest` re-derives them by
#: running the real parser over a feature that carries both, so a fourth
#: kind added there fails a check here rather than reaching a container.
ARGUMENT_PARAMETER: dict[Optional[str], tuple[str, str]] = {
    None: ("", ""),
    "pystring": ("String docString", ""),
    "table": ("DataTable dataTable", "io.cucumber.datatable.DataTable"),
}

#: The one annotation every stub method carries.  ANY of cucumber's five
#: would answer any step (rule 1), so the file uses one and says why here
#: rather than mirroring a keyword that does not take part in matching.
_ANNOTATION = "Given"
_ANNOTATION_IMPORT = "io.cucumber.java.en.Given"

#: Cap on the derived part of a method name.  Java imposes no limit; a cap
#: keeps the generated class legible and keeps the sha1 suffix at the end of
#: the line rather than pushed off it.
_NAME_CAP = 60

#: Any C0 control character or DEL.  REFUSED rather than escaped: `\\n` and
#: friends would put a second interpretation layer between the step text and
#: the pattern, and the `\\uXXXX` spelling that handles every other character
#: cannot be used for these at all — javac processes a unicode escape in the
#: LEXER, before the string literal exists, so `\\u000a` inside a literal is a
#: real newline and does not compile.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

#: The metacharacters of `java.util.regex`.  `/` is absent (Java patterns
#: carry no delimiter, so the character that costs the PHP twin an explicit
#: `preg_quote($t, '/')` costs nothing here), and so are `#` and whitespace
#: (special only under the COMMENTS flag, which cucumber does not set: it
#: compiles the annotation string as written).  `-` is here although it is
#: special only inside a character class: escaping it is legal and free, and
#: the alternative is a rule about context.
_REGEX_SPECIAL = frozenset("\\^$.|?*+()[]{}-")


class StubJavaRefused(ValueError):
    """This module refusing to build a stub, loudly, with the reason."""


# ----------------------------------------------------------- where it goes
def glue_dir_for(project: str, source_feature: str | None = None) -> str:
    """The removable glue directory selected by the harness runner."""
    from ..stacks.cucumber import quirks_for
    return quirks_for(project, source_feature).glue_rel


def package_for(project: str, source_feature: str | None = None) -> str:
    """The Java package `glue_dir_for(project)` IS.

    The same arithmetic `stacks.cucumber.class_name` does in the other
    direction, so a class this module writes and that function reads agree
    about their own name; `selftest` closes the loop through the real
    function rather than asserting it here.
    """
    from ..stacks.cucumber import class_name as qualified_class_name
    directory = glue_dir_for(project, source_feature)
    path = directory + "/Stub.java"
    qualified = qualified_class_name(path, project)
    if qualified == path or not qualified.endswith(".Stub"):
        raise StubJavaRefused(
            f"REFUSED: glue directory {directory!r} for {project!r} is not "
            "under its Java test source roots, so no stub package resolves.")
    return qualified[:-len(".Stub")]


# ----------------------------------------------------------------- the keys
def step_keys(item: dict,
              closure: Optional[dict]) -> list[tuple[str, Optional[str]]]:
    """The distinct `(text, arg_kind)` pairs this item needs defined.

    In first-appearance order, which is the order cucumber will ask about
    them, so a generated class reads in the order its scenario runs.

    The closure's `text` is the text AFTER Examples substitution — i.e.
    exactly the question cucumber's glue will be asked — and its `arg_kind`
    is the step's multiline argument.  Neither is re-derived here.

    Two occurrences of one text with DIFFERENT multiline arguments are
    refused rather than reconciled: one text is one expression, one
    expression is one method, and one method has one arity.  Answering both
    would need two methods carrying the same expression, which is the
    duplicate registration rule 1 exists to prevent.

    A closure is REQUIRED; see the module docstring for the three reasons a
    Gherkin fallback cannot exist here.
    """
    if closure is None:
        raise StubJavaRefused(
            f"REFUSED: no closure for {item.get('item_id')!r}. A cucumber "
            f"stub cannot be built from the item alone: `criterion.gherkin` "
            f"holds an outline's TEMPLATE steps without its Examples table, "
            f"an item cannot say which steps the retained code already "
            f"answers, and it cannot say which steps carry a DocString or a "
            f"DataTable — and a method with the wrong arity ERRORS instead "
            f"of vacuously passing.")
    if closure.get("item_id") not in (None, item.get("item_id")):
        # A closure joined to the wrong item would produce a stub for a
        # different scenario — one that passes or fails for reasons that
        # have nothing to do with the item being scored.
        raise StubJavaRefused(
            f"closure {closure.get('item_id')!r} does not belong to item "
            f"{item.get('item_id')!r}")

    seen: dict[str, Optional[str]] = {}
    out: list[tuple[str, Optional[str]]] = []
    for step in closure.get("steps") or []:
        if step.get("side") in _ALREADY_ANSWERED:
            continue
        keyword = str(step.get("keyword") or "").lower()
        if keyword not in ("given", "when", "then", "and", "but", "*"):
            # Cucumber stubs match text, not setup/assertion roles. A leading
            # And/But/* is valid native syntax even when its role is unknown.
            raise StubJavaRefused(
                f"REFUSED: step keyword {keyword!r} is not a supported "
                f"Gherkin keyword in {item.get('item_id')!r}")
        text = step["text"]
        if "arg_kind" not in step:
            raise StubJavaRefused(
                f"REFUSED: closure step {text!r} of {item.get('item_id')!r} "
                f"carries no `arg_kind`. Java has no optional parameters, so "
                f"the stub cannot absorb a DocString or a DataTable the way "
                f"the PHP twin does: it has to declare the trailing "
                f"parameter or cucumber refuses the arity. J4's "
                f"`closure_java.py` must carry `gherkin.Step.arg_kind`.")
        arg_kind = step["arg_kind"]
        if arg_kind not in ARGUMENT_PARAMETER:
            known = sorted(k or "none" for k in ARGUMENT_PARAMETER)
            raise StubJavaRefused(
                f"REFUSED: unsupported arg_kind {arg_kind!r} for step "
                f"{text!r}; `gherkin.Step.arg_kind` spells them {known}")
        if text in seen:
            if seen[text] != arg_kind:
                raise StubJavaRefused(
                    f"REFUSED: step text {text!r} appears in "
                    f"{item.get('item_id')!r} both with arg_kind "
                    f"{seen[text]!r} and with {arg_kind!r}. One text is one "
                    f"expression and one method, and one method has one "
                    f"arity — answering both would need two methods carrying "
                    f"the same expression.")
            continue
        seen[text] = arg_kind
        out.append((text, arg_kind))
    return out


# ---------------------------------------------------------------- the names
def method_name(text: str, taken: set[str]) -> str:
    """A deterministic, unique, legal Java method name for one step text.

    The sha1 suffix is UNCONDITIONAL, exactly as in the PHP twin and for the
    same reason: a suffix added only on collision would name the same text
    differently depending on which of a colliding pair the generator reached
    first, and the emitted class would then depend on iteration order — two
    runs over one item could differ in bytes, which is what the
    byte-identical-regeneration check exists to catch.

    It also makes a Java KEYWORD impossible: `class` and `new` are legal
    step texts and illegal method names, but `class_1a2b3c4d` is neither a
    keyword nor ambiguous, and the suffix is always there.

    `taken` is a corruption check, not the disambiguator: a name already in
    it means the caller passed one text twice, or two texts collided in the
    leading 32 bits of sha1.  Both are refusals, never silent renames.
    """
    words = re.findall(r"[A-Za-z0-9]+", text)
    base = "".join(w.lower() if i == 0 else w[0].upper() + w[1:]
                   for i, w in enumerate(words))[:_NAME_CAP]
    if not base or base[0].isdigit():
        # A Java method name may not start with a digit, and a text of pure
        # punctuation yields no words at all.
        base = "step" + base
    name = f"{base}_{hashlib.sha1(text.encode('utf-8')).hexdigest()[:8]}"
    if name in taken:
        raise StubJavaRefused(
            f"method name {name!r} already taken — duplicate step text or "
            f"sha1 collision for {text!r}")
    taken.add(name)
    return name


def class_name(item_id: str) -> str:
    """`Stub<item_key>Steps` — a legal identifier, unique per item.

    `runner.item_key` is the same sha1[:16] the release uses to name gold
    records, so a stub artifact joins to its item by filename and two items
    can never collide on a class name.  The `Stub` prefix is what keeps the
    name from starting with a digit, which half of sha1's output does.
    """
    return f"Stub{item_key(item_id)}Steps"


# -------------------------------------------------------------- the pattern
def regex_quote(text: str) -> str:
    """`text` as a `java.util.regex` pattern matching exactly itself.

    Per character, like `preg_quote` and `re.escape`, over `_REGEX_SPECIAL`.
    A backslash before an ASCII punctuation character is a literal in Java's
    grammar; a backslash before a LETTER is either a construct or an error,
    which is why nothing here escapes anything else.
    """
    return "".join("\\" + ch if ch in _REGEX_SPECIAL else ch for ch in text)


def pattern_for(text: str) -> str:
    """The anchored regular expression cucumber will compile for `text`.

    Both anchors, always: they are what makes the annotation a regular
    expression rather than a Cucumber Expression, and `Matcher.matches`
    would anchor anyway — but the pattern is also read by cucumber before it
    is compiled, so the anchors are written rather than assumed.
    """
    if not text.strip():
        raise StubJavaRefused(
            "REFUSED: empty step text; the anchored pattern `^$` would match "
            "every empty step in the suite")
    bad = _CONTROL.search(text)
    if bad:
        raise StubJavaRefused(
            f"REFUSED: step text carries control character {bad.group(0)!r} "
            f"at offset {bad.start()}, which cannot be written into a "
            f"one-line Java annotation: {text!r}")
    return "^" + regex_quote(text) + "$"


# ------------------------------------------------------- the string literal
def java_literal(value: str) -> str:
    """`value` as a Java string literal, ASCII-only.

    Every character above `~` becomes a `\\uXXXX` escape, one per UTF-16
    code unit.  That is a deviation from both twins, which emit the
    character itself, and the reason is javac rather than taste: the source
    encoding is a compiler flag (`-encoding`, defaulting to the platform
    charset), so a non-ASCII byte in a generated file compiles differently
    on two machines that both "work".  An escaped file has no encoding.

    A control character is REFUSED rather than escaped, because a unicode
    escape is processed by the lexer before the literal exists: `\\u000a` is
    a real newline in the source and does not compile.
    """
    out = ["\""]
    for ch in value:
        if ch == "\"":
            out.append("\\\"")
        elif ch == "\\":
            out.append("\\\\")
        elif " " <= ch <= "~":
            out.append(ch)
        elif _CONTROL.match(ch):
            raise StubJavaRefused(
                f"REFUSED: {ch!r} cannot appear in a Java string literal: a "
                f"unicode escape is expanded by the lexer, so the escaped "
                f"spelling would put the character itself back into the "
                f"source.")
        else:
            units = ch.encode("utf-16-be", "surrogatepass")
            for i in range(0, len(units), 2):
                out.append("\\u%02x%02x" % (units[i], units[i + 1]))
    out.append("\"")
    return "".join(out)


def read_java_literal(literal: str) -> str:
    """The inverse of `java_literal`, used to READ BACK an emitted class.

    The round trip is asserted rather than trusted because the emitted class
    is a program the benchmark will not read again before javac and cucumber
    do.
    """
    if len(literal) < 2 or literal[0] != "\"" or literal[-1] != "\"":
        raise StubJavaRefused(f"REFUSED: not a Java string literal: "
                              f"{literal!r}")
    body, out, i = literal[1:-1], [], 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1:i + 2]
        if nxt == "u":
            out.append(chr(int(body[i + 2:i + 6], 16)))
            i += 6
        elif nxt in ("\"", "\\"):
            out.append(nxt)
            i += 2
        else:
            raise StubJavaRefused(
                "REFUSED: unsupported escape " + repr("\\" + nxt) + " in "
                + repr(literal) + "; `java_literal` emits only a quote, a "
                "backslash and a unicode escape.")
    # Surrogate pairs come back as two escapes and have to be rejoined, or a
    # text outside the BMP would read back as two lone surrogates and the
    # round-trip check would fail on a class that is perfectly correct.
    return "".join(out).encode("utf-16", "surrogatepass").decode("utf-16")


# --------------------------------------------------------------- the class
def java_class(project: str, item_id: str,
               keys: list[tuple[str, Optional[str]]],
               source_feature: str | None = None) -> tuple[str, str]:
    """`(repo-relative path, Java source)` for one item's stub class.

    `project` is an argument here where neither twin needs one, because rule
    5 is per project: the class has to land in the package this project's
    runner scans.

    One method per key, every body empty.  The emitted source is READ BACK
    (`definitions_in`) and the patterns compared against what it was built
    from, so "the class carries the expressions it was asked for" is a
    checked property.  The other half of §3.10's acceptance — that javac
    compiles it and that cucumber's glue loader registers every expression
    without an ambiguous match — needs the image, exactly as it does for the
    PHP twin, and NO PROGRAM RUNS IT TODAY:
    `benchmark/scripts/gate_s5_vacuity.py` refuses for every stack before
    any Docker contact, and the body behind that refusal reads a behave
    report shape this module does not emit.  The cucumber arm lands with the
    reviewed gate workload binding
    (`benchmark/J0_DOCKER_AUTHORITY_AMENDMENT.md`); see
    `CONTAINER_HALF_NOTE`, which `selftest` holds to the gate's own bytes.
    """
    package = package_for(project, source_feature)
    cls = class_name(item_id)
    path = f"{glue_dir_for(project, source_feature)}/{cls}.java"
    if "*/" in item_id or any(ch < " " or ch > "~" for ch in item_id):
        # The item id is the one caller-supplied string that reaches the
        # javadoc rather than a string literal, so it is the one that can
        # close the comment early or put a byte in the file whose meaning
        # depends on javac's `-encoding`.  The PHP twin refuses `*/` in the
        # pattern for the first half of that reason.
        raise StubJavaRefused(
            f"REFUSED: item id {item_id!r} cannot be written into the "
            f"generated class header: it closes the javadoc or carries a "
            f"character the source encoding decides.")

    seen: set[str] = set()
    taken: set[str] = set()
    emitted: list[tuple[str, str, str]] = []   # (pattern, name, parameter)
    imports = {_ANNOTATION_IMPORT}
    for text, arg_kind in keys:
        if text in seen:
            # The caller is expected to have deduplicated (`step_keys`
            # does).  Emitting the duplicate would register one expression
            # twice, which is the failure rule 1 exists to prevent, so it is
            # refused where it becomes possible.
            raise StubJavaRefused(
                f"duplicate step text handed to java_class: {text!r}")
        seen.add(text)
        parameter, needed = ARGUMENT_PARAMETER[arg_kind]
        if needed:
            imports.add(needed)
        emitted.append((pattern_for(text), method_name(text, taken),
                        parameter))

    lines = [f"package {package};", ""]
    lines += [f"import {name};" for name in sorted(imports)]
    lines += [
        "",
        "/**",
        " * GENERATED by r2t.toolkit.stub_java (SPEC_C3_PARALLEL 3.10) -- the",
        " * vacuous floor of the anti-vacuity gate.  Every step this",
        " * scenario needs and the retained code does not already define,",
        " * with an empty body: cucumber reports every step passed and",
        " * nothing is asserted.",
        " *",
        f" * item: {item_id}",
        " */",
        f"public class {cls}",
        "{",
    ]
    for i, (pattern, name, parameter) in enumerate(emitted):
        if i:
            lines.append("")
        lines += [
            f"  @{_ANNOTATION}({java_literal(pattern)})",
            f"  public void {name}({parameter})",
            "  {",
            "  }",
        ]
    lines += ["}", ""]
    source = "\n".join(lines)

    read_back = definitions_in(source)
    if read_back != emitted:
        raise StubJavaRefused(
            f"REFUSED: the emitted class does not carry the definitions it "
            f"was built from: {read_back!r} vs {emitted!r}")
    return path, source


#: One emitted definition, exactly as this module writes it.  A reader over
#: the module's OWN output shape, which is what makes it a read-back rather
#: than a Java parser: the PHP twin defers "is this valid" to a container
#: for the same reason, and so does this one.
_DEFINITION = re.compile(
    r"^  @" + _ANNOTATION + r"\((?P<literal>\"(?:[^\"\\\n]|\\.)*\")\)\n"
    r"  public void (?P<name>[A-Za-z_$][\w$]*)\((?P<parameter>[^()]*)\)\n"
    r"  \{\n"
    r"  \}$", re.M)


def definitions_in(source: str) -> list[tuple[str, str, str]]:
    """`(pattern, method name, parameter)` for every definition in a class.

    The pattern comes back DECODED, so a literal this module escaped and a
    literal it read are compared as the same string rather than as two
    spellings of one.
    """
    return [(read_java_literal(m.group("literal")), m.group("name"),
             m.group("parameter"))
            for m in _DEFINITION.finditer(source)]


# -------------------------------------------------------------- the adapter
def _feature_step_index(feature_root: str, rel: str, cache: dict) -> dict:
    """`{1-based line -> gherkin.Step}` for one pinned feature file.

    Every block's steps, Background included, keyed on the line the step is
    written at — which is the join the closure already carries in
    `source_line`.  Parsed once per file per caller; the cache is the
    caller's so an adapter over a corpus parses 15 files rather than 111.
    """
    if rel in cache:
        return cache[rel]
    from ..core.gherkin import parse_feature_file
    if not isinstance(rel, str) or not rel or os.path.isabs(rel) \
            or ".." in rel.split("/"):
        raise StubJavaRefused(
            f"REFUSED: closure names feature file {rel!r}, which is not a "
            f"repository-relative path.")
    path = os.path.join(feature_root, *rel.split("/"))
    if os.path.islink(path) or not os.path.isfile(path):
        raise StubJavaRefused(
            f"REFUSED: no pinned feature file at {path}. The stub's "
            f"`arg_kind` is a syntactic fact of the .feature bytes, so the "
            f"corpus tree the closure was built from has to be the one this "
            f"run is against.")
    try:
        feature = parse_feature_file(path)
    except (OSError, ValueError) as exc:
        raise StubJavaRefused(
            f"REFUSED: cannot read pinned feature file {path}: {exc}") from exc
    blocks = ([feature.background] if feature.background else [])
    blocks = blocks + list(feature.scenarios)
    index: dict[int, object] = {}
    for block in blocks:
        for step in block.steps:
            index[step.line] = step
    cache[rel] = index
    return index


def resolve_closure_steps(closure: dict, feature_root: str,
                          cache: Optional[dict] = None) -> dict:
    """Join closure steps to pinned syntax without inventing assertion roles.

    Multiline argument kind comes from the original feature line; the written
    keyword must match that line too. Cucumber definitions match text alone,
    so stubs do not need the role inference used by assertion stripping. In
    particular a native scenario may begin with And/But/* without an earlier
    concrete keyword. Keep that keyword rather than guessing a role.
    """
    if not isinstance(closure, dict):
        raise StubJavaRefused("REFUSED: a stub requires a closure object.")
    steps = list(closure.get("steps") or [])
    index = _feature_step_index(
        feature_root, closure.get("feature_file"),
        cache if cache is not None else {})
    out = []
    for step in steps:
        line = step.get("source_line")
        parsed = index.get(line) if isinstance(line, int) else None
        if parsed is None:
            raise StubJavaRefused(
                f"REFUSED: closure step {step.get('text')!r} of "
                f"{closure.get('item_id')!r} names source line {line!r}, "
                f"which is not a step of the pinned "
                f"{closure.get('feature_file')!r}. A stub cannot be built "
                f"for a step whose bytes this run cannot find.")
        if parsed.keyword != str(step.get("keyword") or ""):
            raise StubJavaRefused(
                f"REFUSED: line {line} of {closure.get('feature_file')!r} is "
                f"a {parsed.keyword!r} step in the pinned bytes and "
                f"{step.get('keyword')!r} in the closure. These are two "
                f"different corpora; no `arg_kind` read here would belong to "
                f"this closure.")
        out.append({**step, "arg_kind": parsed.arg_kind})
    return {**closure, "steps": out}


def stub_solution(item: dict, closure: Optional[dict], *,
                  feature_root: str, cache: Optional[dict] = None) -> dict:
    """The adapter contract: `{"files": [...], "metadata": {...}}`.

    One file, no registration fragment: installing a class in the package
    the runner scans IS registering it with cucumber.

    `feature_root` is the pinned corpus tree the closure's `feature_file` is
    relative to.  It is required rather than optional because no cucumber
    closure this benchmark has ever built carries `arg_kind`, so a default
    would be a way to reach `step_keys`' refusal by accident instead of a
    way to answer it.
    """
    if closure is not None:
        closure = resolve_closure_steps(closure, feature_root, cache)
    keys = step_keys(item, closure)
    project = item.get("project")
    if not project:
        raise StubJavaRefused(
            f"REFUSED: item {item.get('item_id')!r} carries no `project`, so "
            f"the package its runner scans is unknown. See rule 5.")
    source_feature = (item.get("provenance") or {}).get("file_path")
    path, code = java_class(project, item["item_id"], keys, source_feature)
    return {
        "files": [{"file_path": path, "code": code}],
        "metadata": {"stub": True, "n_steps": len(keys),
                     "closure_available": closure is not None},
    }


def load_closures(path: str) -> dict[str, dict]:
    with open(path, encoding="utf-8") as fh:
        return {c["item_id"]: c for c in json.load(fh)}


def make_stub_adapter(closures_path: str, feature_root: str):
    """The `stub` adapter — the control §3.10 requires before publishing
    pass@1.

    `feature_root` is the workspace this run is against, which is where
    `fixtures._build_stub` reads it from: the harness resolves ONE
    root for classification and writing (`--repo`, set from `--worker`), and
    the corpus under it is the seed's, whose digest every campaign and every
    mutation observation already records.  The parsed features are cached
    across items, so a 111-item sweep parses each of the 15 files once.
    """
    from ..bench.adapters import Adapter

    closures = load_closures(closures_path)
    features: dict = {}

    def run(task: dict) -> dict:
        closure = closures.get(task["item_id"])
        if closure is None:
            return {"files": [], "metadata": {
                "adapter_error": f"no closure for {task['item_id']}: a "
                                 f"cucumber stub cannot be built without "
                                 f"one"}}
        try:
            return stub_solution(task, closure, feature_root=feature_root,
                                 cache=features)
        except Exception as e:                                # noqa: BLE001
            return {"files": [], "metadata": {
                "adapter_error": f"{type(e).__name__}: {e}"}}

    return Adapter("stub", run,
                   {"closures": closures_path, "features": feature_root})


# --------------------------------------------------------------- acceptance
def _load_jsonl(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def acceptance(items_path: str, closures_path: str, feature_root: str,
               project: Optional[str] = None,
               task: str = "criterion_to_test") -> dict:
    """Generate for every item and check everything that needs no container.

    The other half — that javac compiles the class and that cucumber's glue
    loader registers every expression with no duplicate and no ambiguous
    match — needs the image, and no program runs it today
    (`CONTAINER_HALF_NOTE` says why, and `selftest` holds that sentence to
    `benchmark/scripts/gate_s5_vacuity.py`'s own bytes).  This
    half is the part that must hold for a corpus rather than for a run:
    byte-identical output on repetition, distinct expressions within an
    item, distinct paths and class names across items, and a RECOMPUTATION
    of the two censuses the design rests on (how many items share a step
    text, and how many emitted steps carry a multiline argument), so that a
    corpus change which invalidates either is caught here rather than in a
    container log.

    Raises `SystemExit` on any violation; returns the report otherwise.
    """
    items = [i for i in _load_jsonl(items_path)
             if (project is None or i.get("project") == project)
             and (task is None or i.get("task") == task)]
    closures = load_closures(closures_path)
    features: dict = {}

    violations: list[str] = []
    refused: list[dict] = []
    paths: dict[str, str] = {}
    n_methods = 0
    missing_closure: list[str] = []
    items_per_text: dict[str, int] = {}
    dup_within_item = 0
    with_argument = 0

    for item in items:
        iid = item["item_id"]
        closure = closures.get(iid)
        if closure is None:
            missing_closure.append(iid)
            continue

        occurrences = [s["text"] for s in closure.get("steps") or []
                       if s.get("side") not in _ALREADY_ANSWERED
                       and "text" in s]
        if len(occurrences) != len(set(occurrences)):
            dup_within_item += 1

        # `step_keys` is inside the try with the generation it feeds: a
        # closure missing `arg_kind` or carrying a control character is a
        # corrupt artifact, and an acceptance that names the item is worth
        # more than a traceback that names the line.
        try:
            keys = step_keys(
                item, resolve_closure_steps(closure, feature_root, features))
            source_feature = (item.get("provenance") or {}).get("file_path")
            path, code = java_class(item["project"], iid, keys,
                                    source_feature)
            path2, code2 = java_class(item["project"], iid, keys,
                                      source_feature)
        except Exception as e:                                # noqa: BLE001
            refused.append({"item_id": iid, "why": f"{type(e).__name__}: {e}"})
            continue
        for text, arg_kind in keys:
            items_per_text[text] = items_per_text.get(text, 0) + 1
            if arg_kind is not None:
                with_argument += 1

        if (path, code) != (path2, code2):
            violations.append(f"{iid}: regenerating changed the output")
        if path in paths and paths[path] != iid:
            violations.append(f"{path}: emitted for both {paths[path]} "
                              f"and {iid}")
        paths[path] = iid

        definitions = definitions_in(code)
        patterns = [pattern for pattern, _n, _p in definitions]
        if len(patterns) != len(set(patterns)):
            violations.append(
                f"{iid}: two definitions share an expression "
                f"({len(patterns)} emitted, {len(set(patterns))} distinct) — "
                f"cucumber's duplicate registration")
        if len(definitions) != len(keys):
            violations.append(f"{iid}: {len(keys)} keys but "
                              f"{len(definitions)} definitions")
        n_methods += len(definitions)

    if missing_closure:
        violations.append(
            f"{len(missing_closure)} item(s) have no closure "
            f"(e.g. {missing_closure[0]}); a cucumber stub cannot be built "
            f"without one")
    if refused:
        violations.append(f"{len(refused)} item(s) refused: {refused[:3]}")

    shared = {t: n for t, n in items_per_text.items() if n > 1}
    top = max(items_per_text.items(), key=lambda kv: (kv[1], kv[0]),
              default=("", 0))
    report = {
        "items": len(items),
        "methods_emitted": n_methods,
        "items_refused": len(refused),
        "refusals": refused,
        "closures": closures_path,
        "distinct_step_texts": len(items_per_text),
        "texts_in_more_than_one_item": len(shared),
        "max_items_sharing_a_text": top[1],
        "most_shared_text": top[0],
        "items_with_duplicate_step_text": dup_within_item,
        # Rule 4's census: how many emitted methods carry a trailing
        # parameter.  Zero would mean the arity rule is inert on this
        # corpus, which it is not — and if it ever were, the number says so
        # rather than the prose.
        "methods_with_multiline_argument": with_argument,
        "violations": violations,
    }
    if violations:
        raise SystemExit("REFUSED: stub acceptance failed:\n  "
                         + "\n  ".join(violations))
    return report


# ------------------------------------------------------------- the CLI verb
#: The one operator-facing sentence about the half this module does NOT do.
#: A module constant rather than a literal inside the `print`, because
#: `selftest` reads it back and checks it against
#: `benchmark/scripts/gate_s5_vacuity.py`'s own bytes: the sentence and the
#: gate's state are two halves of one statement, and this file has already
#: shipped two seam paragraphs that went stale because a human-read claim
#: about state had nothing holding it to the state.
#:
#: What it must keep saying, whatever the wording becomes: it does not name
#: a program that CHECKS the container half today (none does), it says what
#: the operator must not conclude, and it points at the blocking CONDITION
#: -- the reviewed gate workload binding -- rather than at a milestone id
#: invented for the sentence.  No milestone in the plan doc lands the live
#: gate: §J6 names `gate_s5_vacuity.py` itself.
CONTAINER_HALF_NOTE = (
    "NOTE: this is the corpus half, and today it is the only half that runs. "
    "That every class COMPILES, that cucumber's glue loader registers every "
    "expression and that no item raises AmbiguousStepDefinitionsException is "
    "NOT checked by any program yet: benchmark/scripts/gate_s5_vacuity.py "
    "refuses before any Docker contact for every stack (no reviewed gate "
    "workload binding -- benchmark/J0_DOCKER_AUTHORITY_AMENDMENT.md), and "
    "the body behind that refusal reads a behave report shape this module "
    "does not emit. The cucumber arm lands with that binding; until then "
    "nothing has run javac or the glue loader over these classes."
)


def cmd_stub_accept(args) -> int:
    """`r2t stub-accept --profile config/profile_epubcheck.yml`

    The cucumber arm of `cli.cmd_stub_accept`, reached through
    `cli._other_stack`.  The corpus half only — said here rather than left
    implied: an operator who read this verb's output as "the stubs are
    accepted" would be reading a claim about generated TEXT as a claim about
    javac and cucumber.
    """
    from ..core.boundary import load_boundary
    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    closures = args.closures or os.path.join(args.artifacts, "closures.json")
    info = acceptance(args.release, closures, b.repo_root, project=b.project)
    print(json.dumps(info, indent=1))
    print(CONTAINER_HALF_NOTE)
    return 0


# ----------------------------------------------------------------- selftest
#: `text -> the pattern it must produce`.  Hand-checked against Java's
#: `Pattern` grammar; every entry is a character class the corpus really
#: carries (cucumber expression syntax, an epubcheck message id, a path).
_PATTERN_CASES: dict[str, str] = {
    "a run": "^a run$",
    "the return code is 0": "^the return code is 0$",
    # `/` needs no escape in Java, which is the whole of the PHP twin's
    # delimiter problem gone.
    "warning(s)/error(s) are/is reported": (
        r"^warning\(s\)/error\(s\) are/is reported$"),
    "checking EPUB 'a-b.epub'": r"^checking EPUB 'a\-b\.epub'$",
    "the message contains \"a\"": "^the message contains \"a\"$",
    "a {int} thing": r"^a \{int\} thing$",
    "1 + 1": r"^1 \+ 1$",
    "a\\b": r"^a\\b$",
    "a^b$c|d": r"^a\^b\$c\|d$",
    "x [1] y": r"^x \[1\] y$",
}

#: The selftest's pinned corpus, in the shapes the two real Java corpora
#: carry: a Background, an `And` under a `When`, an `And` under a `Then`, a
#: DocString and a second scenario.  Line numbers are load-bearing — the
#: closures below join to it by `source_line`, which is the join
#: `resolve_closure_steps` makes and the one a corrupt closure fails.
_FIXTURE_FEATURE = """Feature: cli

  Background:
    Given stderr is redirected to stdout

  Scenario: help
    When running `epubcheck -h`
    Then the return code is 0
    And stdout is
      \"\"\"
      body
      \"\"\"
    And stderr is redirected to stdout

  Scenario: version
    Given stderr is redirected to stdout
    Then the return code is 0
"""

#: `value -> its Java literal`.  The escaping and the ASCII rule, together.
_LITERAL_CASES: dict[str, str] = {
    "plain": '"plain"',
    "a\"b": '"a\\"b"',
    "a\\b": '"a\\\\b"',
    "caf\u00e9": '"caf\\u00e9"',
    # Outside the BMP: two UTF-16 code units, two escapes.
    "\U0001f600": '"\\ud83d\\ude00"',
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

    # -- rule 1, against the corpus's own bytes ---------------------------
    #
    # The claim is "cucumber-jvm matches a step against every definition
    # whatever keyword registered it", and it decides the KEY, so it is read
    # out of the pinned checkout rather than asserted.  Two witnesses, each
    # a step registered with `@And` and written `Given`.
    corpus = "/data2/binhang/req2test_corpora/epubcheck"
    witnesses = [
        ("src/test/java/org/w3c/epubcheck/test/EPUBCheckConfiguration.java",
         '@And("EPUBCheck configured to check EPUB {version} rules")',
         "src/test/resources/epub2/opf-publication.feature",
         "Given EPUBCheck configured to check EPUB 3 rules"),
        ("src/test/java/org/w3c/epubcheck/test/TestEnvironment.java",
         '@And("(the )default locale (is )(set to )(\'){locale}(\')")',
         "src/test/resources/localization/localization.feature",
         "Given the default locale is set to 'fr-FR'"),
    ]
    if os.path.isdir(corpus):
        for glue_rel, annotation, feature_rel, line in witnesses:
            try:
                with open(os.path.join(corpus, glue_rel),
                          encoding="utf-8") as fh:
                    glue = fh.read()
                with open(os.path.join(corpus, feature_rel),
                          encoding="utf-8") as fh:
                    feature = fh.read()
            except OSError as e:
                glue = feature = ""
                print(f"  [SKIP] {glue_rel}: {e}")
                continue
            check(f"a step registered with @And is written Given in "
                  f"{os.path.basename(feature_rel)} -- cucumber matches on "
                  f"the TEXT, so the key here is the text",
                  annotation in glue
                  and any(ln.strip() == line for ln in feature.splitlines()),
                  f"{annotation!r} / {line!r}")
    else:
        print(f"  [SKIP] no {corpus}, so rule 1's two corpus witnesses could "
              f"not be re-read")

    # -- rule 4's vocabulary, derived from the parser that owns it --------
    from ..core import gherkin as _gherkin
    feature_text = (
        "Feature: f\n"
        "  Scenario: s\n"
        "    Given plain\n"
        "    When a table\n"
        "      | a | b |\n"
        "    Then a pystring\n"
        "      \"\"\"\n"
        "      body\n"
        "      \"\"\"\n")
    parsed = _gherkin.parse_feature_file("x.feature", feature_text)
    kinds = [s.arg_kind for s in parsed.scenarios[0].steps]
    check("the arg_kind vocabulary is the Gherkin reader's own, re-derived "
          "by running it rather than retyped",
          kinds == [None, "table", "pystring"]
          and set(kinds) <= set(ARGUMENT_PARAMETER), str(kinds))
    backticked = feature_text.replace('"""', "```")
    back_kinds = [s.arg_kind
                  for s in _gherkin.parse_feature_file(
                      "x.feature", backticked).scenarios[0].steps]
    check("...and the ``` DocString fence Gherkin also allows is NOT seen by "
          "that reader, so a closure built from it under-reports arg_kind "
          "for epubcheck's cli.feature -- J4's, demonstrated not described",
          back_kinds == [None, "table", None], str(back_kinds))

    # -- the keys ---------------------------------------------------------
    item = {"item_id": "epubcheck/src/test/resources/cli/cli.feature:14",
            "project": "epubcheck", "task": "criterion_to_test"}

    def step(text, keyword="Given", side="removable", arg_kind=None):
        return {"keyword": keyword, "text": text, "side": side,
                "arg_kind": arg_kind}

    # The shape a CUCUMBER producer really writes: the keyword as written,
    # the line it is written at, the block it came from -- and no
    # `arg_kind`, because the registry it was built from never saw one.
    def bstep(text, keyword, line, origin="scenario", side="removable"):
        return {"keyword": keyword, "text": text, "side": side,
                "source_line": line, "origin": origin, "example_row": 0}

    closure = {"item_id": item["item_id"], "steps": [
        step("stderr is redirected to stdout"),
        step("running `epubcheck -h`", keyword="When"),
        step("the return code is 0", keyword="Then"),
        step("stdout is", keyword="Then", arg_kind="pystring"),
        step("stderr is redirected to stdout"),
    ]}
    keys = step_keys(item, closure)
    check("the key is the TEXT, and a repeated text collapses to one entry",
          keys == [("stderr is redirected to stdout", None),
                   ("running `epubcheck -h`", None),
                   ("the return code is 0", None),
                   ("stdout is", "pystring")], str(keys))
    check("one text under two keywords is ONE definition -- the behave "
          "twin's (keyword, text) key would emit two, and cucumber refuses "
          "the second registration",
          step_keys(item, {"item_id": item["item_id"], "steps": [
              step("a run", keyword="Given"),
              step("a run", keyword="Then")]}) == [("a run", None)])
    for side in ("retained", "production"):
        check(f"a step answered by {side.upper()} code is not redefined -- "
              f"two definitions matching one step is "
              f"AmbiguousStepDefinitionsException",
              step_keys(item, {"item_id": item["item_id"], "steps": [
                  step("x", side=side)]}) == [])
    check("a step with NO definition at all is still stubbed: side None is "
          "not 'already answered'",
          step_keys(item, {"item_id": item["item_id"], "steps": [
              step("x", side=None)]}) == [("x", None)])
    refusals = [
        ("a closure from another item is REFUSED",
         lambda: step_keys(item, dict(closure, item_id="other")),
         "does not belong"),
        ("NO closure is a refusal, not a Gherkin fallback",
         lambda: step_keys(item, None), "REFUSED: no closure"),
        ("a keyword no Gherkin parser produces is refused",
         lambda: step_keys(item, {"item_id": item["item_id"],
                                  "steps": [step("x", keyword="If")]}),
         "not a supported Gherkin keyword"),
        ("a step with NO arg_kind key is REFUSED, naming J4 -- a default "
         "would be a guess about the shape of the scenario",
         lambda: step_keys(item, {"item_id": item["item_id"], "steps": [
             {"keyword": "Given", "text": "x", "side": "removable"}]}),
         "closure_java.py"),
        ("an arg_kind this module cannot spell is REFUSED",
         lambda: step_keys(item, {"item_id": item["item_id"], "steps": [
             step("x", arg_kind="docstring")]}),
         "unsupported arg_kind"),
        ("one text carrying two different multiline shapes is REFUSED: one "
         "expression, one method, one arity",
         lambda: step_keys(item, {"item_id": item["item_id"], "steps": [
             step("x"), step("x", arg_kind="table")]}),
         "one method has one arity"),
    ]
    for name, fn, needle in refusals:
        check(name, raises(fn, needle))

    # -- names ------------------------------------------------------------
    check("a name is a pure function of its text, so insertion order cannot "
          "move it",
          method_name("a run", set()) == method_name("a run", set()))
    check("every name is a legal Java identifier",
          all(re.fullmatch(r"[A-Za-z_$][\w$]*", method_name(t, set()))
              for t in ("42 things", "/", "a $ b", "  x  ", "class", "new")))
    check("a step text that IS a Java keyword cannot produce one: the sha1 "
          "suffix is unconditional",
          method_name("class", set()).startswith("class_")
          and method_name("class", set()) != "class")
    long_a = "the quantity of the product named " + "x" * 200 + " is one"
    long_b = "the quantity of the product named " + "x" * 200 + " is two"
    na, nb = method_name(long_a, set()), method_name(long_b, set())
    check("a very long text is capped and still unique",
          len(na) <= _NAME_CAP + 9 and na != nb
          and na.rsplit("_", 1)[0] == nb.rsplit("_", 1)[0], f"{len(na)} {na}")
    check("a text with no alphanumerics still yields a legal name",
          method_name("/", set())
          == "step_" + hashlib.sha1(b"/").hexdigest()[:8],
          method_name("/", set()))
    check("a name reused inside one class is REFUSED, never silently renamed",
          raises(lambda: method_name("a run", {method_name("a run", set())}),
                 "already taken"))
    check("two items never share a class name",
          class_name("a") != class_name("b")
          and re.fullmatch(r"Stub[0-9a-f]{16}Steps", class_name("a")))

    # -- patterns ---------------------------------------------------------
    for text, want in _PATTERN_CASES.items():
        got = pattern_for(text)
        check(f"pattern_for({text!r})", got == want, f"got {got!r}")
    for text in _PATTERN_CASES:
        check(f"...and it matches its own text and nothing longer: {text!r}",
              re.fullmatch(pattern_for(text), text)
              and not re.fullmatch(pattern_for(text), text + " more"))
    check("every pattern carries BOTH anchors, which is what makes cucumber "
          "read it as a regular expression rather than a Cucumber Expression",
          all(pattern_for(t).startswith("^") and pattern_for(t).endswith("$")
              for t in _PATTERN_CASES))
    check("`/` is NOT escaped -- Java patterns carry no delimiter, so the "
          "PHP twin's `preg_quote($t, '/')` has no counterpart here",
          "\\/" not in pattern_for("a/b"))
    for bad, why in [("two\nlines", "newline"), ("two\rlines", "carriage "
                                                 "return"), ("a\tb", "tab")]:
        check(f"a {why} in a step text is REFUSED",
              raises(lambda b=bad: pattern_for(b), "control character"))
    check("an empty step text is REFUSED",
          raises(lambda: pattern_for("   "), "REFUSED"))

    # -- the string literal ----------------------------------------------
    for value, want in _LITERAL_CASES.items():
        got = java_literal(value)
        check(f"java_literal({value!r})", got == want, f"got {got!r}")
    for value in list(_LITERAL_CASES) + list(_PATTERN_CASES.values()):
        check(f"...and it reads back identically: {value[:32]!r}",
              read_java_literal(java_literal(value)) == value)
    check("the literal is pure ASCII, so the emitted file has no encoding to "
          "get wrong",
          all(ch <= "~" for ch in java_literal("caf\u00e9\U0001f600")))
    check("a control character is REFUSED by the literal too, because a "
          "unicode escape is expanded by the LEXER",
          raises(lambda: java_literal("a\nb"), "expanded by the lexer"))

    # -- where it goes ----------------------------------------------------
    offline_source = "features/unit/offline.feature"
    check("the harness and stub share one closed glue routing decision",
          glue_dir_for("algorand-sdk")
          == "src/test/java/com/algorand/algosdk/unit"
          and glue_dir_for("algorand-sdk", offline_source)
          == "src/test/java/com/algorand/algosdk/integration"
          and raises(lambda: glue_dir_for("metasfresh"), "REFUSED"))
    check("the package IS the directory under src/test/java",
          package_for("epubcheck") == "org.w3c.epubcheck.test"
          and package_for("algorand-sdk", offline_source)
          == "com.algorand.algosdk.integration")

    # -- the class --------------------------------------------------------
    path, code = java_class("epubcheck", item["item_id"], keys)
    check("the path is under this project's glue directory and named for "
          "the item",
          path == f"{glue_dir_for('epubcheck')}/{class_name(item['item_id'])}"
                  f".java", path)
    check("the file name IS the public class name, which javac requires",
          os.path.basename(path) == class_name(item["item_id"]) + ".java")
    check("two items never share a path",
          java_class("epubcheck", "a", keys)[0]
          != java_class("epubcheck", "b", keys)[0])
    definitions = definitions_in(code)
    check("exactly one method per key, every body empty, read back off the "
          "emitted bytes",
          len(definitions) == len(keys) == 4
          and code.count("\n  {\n  }") == 4, code)
    check("the method for a DocString step declares the trailing parameter "
          "and no other method does -- rule 4",
          [p for _pat, _n, p in definitions]
          == ["", "", "", "String docString"], str(definitions))
    check("the expressions read back are the ones the keys asked for",
          [pat for pat, _n, _p in definitions]
          == [pattern_for(t) for t, _a in keys])
    check("only the imports the class uses are emitted",
          "import io.cucumber.java.en.Given;" in code
          and "import io.cucumber.datatable.DataTable;" not in code, code)
    table_keys = [("the following errors are reported", "table")]
    _p, table_code = java_class("epubcheck", "i", table_keys)
    check("...and a DataTable step brings its type's import with it",
          "import io.cucumber.datatable.DataTable;" in table_code
          and "public void theFollowingErrorsAreReported_" in table_code
          and "(DataTable dataTable)" in table_code, table_code)
    check("the class declares the package its directory is",
          code.startswith("package org.w3c.epubcheck.test;\n"))
    check("regeneration is byte-identical",
          java_class("epubcheck", item["item_id"], keys) == (path, code))
    check("a duplicate text handed to java_class is REFUSED",
          raises(lambda: java_class("epubcheck", "i",
                                    [("x", None), ("x", None)]),
                 "duplicate step text"))
    empty_code = java_class("epubcheck", "i", [])[1]
    check("an item whose steps are ALL retained yields a legal empty class",
          "public void " not in empty_code
          and empty_code.endswith("public class Stub" + item_key("i")
                                  + "Steps\n{\n}\n"), empty_code)
    unicode_keys = [("a café \U0001f600 and a } brace", None)]
    _p, unicode_code = java_class("epubcheck", "i", unicode_keys)
    check("the emitted class is pure ASCII even for a non-ASCII step text, "
          "so javac's `-encoding` cannot change what it means",
          all(" " <= ch <= "~" or ch == "\n" for ch in unicode_code),
          unicode_code)
    check("...and that text still reads back out of the class it was "
          "escaped into",
          [pat for pat, _n, _pp in definitions_in(unicode_code)]
          == [pattern_for(t) for t, _a in unicode_keys], unicode_code)
    check("an item id that would close the generated javadoc is REFUSED",
          raises(lambda: java_class("epubcheck", "a/*/b.feature:1", []),
                 "closes the javadoc"))
    # The emitter checks its own output before returning it, which is only
    # worth anything if the check can fire: the reader is swapped for one
    # that agrees with nothing, and the emitter must refuse rather than hand
    # back a class it cannot read.
    global _DEFINITION
    saved_reader = _DEFINITION
    try:
        _DEFINITION = re.compile(r"^this matches no emitted class$", re.M)
        check("a class whose definitions cannot be READ BACK is refused "
              "rather than shipped",
              raises(lambda: java_class("epubcheck", item["item_id"], keys),
                     "does not carry the definitions"))
    finally:
        _DEFINITION = saved_reader
    # A backslash and both quote characters in one text: the two escapers
    # have to compose, and the read-back is what proves they did.
    tricky = [("a path 'c:\\x' and \"y\"", None),
              ("value is '\\n' literally", None)]
    _p, tricky_code = java_class("epubcheck", "t", tricky)
    check("a backslash and both quote characters survive into the class and "
          "read back identically",
          [pat for pat, _n, _pp in definitions_in(tricky_code)]
          == [pattern_for(t) for t, _a in tricky], tricky_code)
    check("...and the expression read back still matches its own text",
          all(re.fullmatch(pat, t)
              for (pat, _n, _pp), (t, _a)
              in zip(definitions_in(tricky_code), tricky)))

    # -- solution + adapter, over a PINNED corpus -------------------------
    #
    # Every call below hands the derivation a real .feature tree, because
    # that is the only shape this module now has: `arg_kind` is a fact about
    # the source line and the closure's producer cannot state it.  The
    # fixture carries a Background, an `And` under a `When`, an `And` under
    # a `Then`, a DocString and a DataTable, so the resolution and the
    # derivation are both exercised on the shapes the corpora really carry.
    with tempfile.TemporaryDirectory() as d:
        corpus = os.path.join(d, "corpus")
        feature_rel = "src/test/resources/cli/cli.feature"
        os.makedirs(os.path.join(corpus, os.path.dirname(feature_rel)))
        with open(os.path.join(corpus, feature_rel), "w",
                  encoding="utf-8") as fh:
            fh.write(_FIXTURE_FEATURE)
        closure = {"item_id": item["item_id"],
                   "feature_file": feature_rel, "steps": [
                       bstep("stderr is redirected to stdout", "Given", 4,
                             origin="background"),
                       bstep("running `epubcheck -h`", "When", 7),
                       bstep("the return code is 0", "Then", 8),
                       bstep("stdout is", "And", 9),
                       bstep("stderr is redirected to stdout", "And", 13)]}
        derived = resolve_closure_steps(closure, corpus)
        check("written keywords are preserved and multiline argument kinds "
              "come from the pinned feature bytes",
              [(s["keyword"], s["arg_kind"]) for s in derived["steps"]]
              == [("Given", None), ("When", None), ("Then", None),
                  ("And", "pystring"), ("And", None)],
              str([(s["keyword"], s["arg_kind"]) for s in derived["steps"]]))
        check("...and the keys that come out are the ones the hand-written "
              "closure produced, so the derivation ADDS an authority rather "
              "than changing an answer",
              step_keys(item, derived) == keys, str(step_keys(item, derived)))
        check("a step whose line is not a step of the pinned feature is "
              "REFUSED, never defaulted",
              raises(lambda: resolve_closure_steps(
                  {**closure, "steps": [bstep("nowhere", "Given", 99)]},
                  corpus), "not a step of the pinned"))
        leading_rel = "src/test/resources/cli/leading.feature"
        with open(os.path.join(corpus, leading_rel), "w", encoding="utf-8") as fh:
            fh.write("Feature: leading connector\n  Scenario: native syntax\n"
                     "    And unclassified action\n")
        leading = {**closure, "feature_file": leading_rel,
                   "steps": [bstep("unclassified action", "And", 3)]}
        resolved = resolve_closure_steps(leading, corpus)
        from .strip import effective_keywords
        check("a native leading And can be stubbed without guessing an "
              "assertion role or weakening assertion stripping",
              resolved["steps"][0]["keyword"] == "And"
              and step_keys(item, resolved) == [("unclassified action", None)]
              and raises(lambda: effective_keywords(leading["steps"]),
                         "opens its block"))
        check("a closure whose written keyword disagrees with the bytes at "
              "its own line is REFUSED as two different corpora",
              raises(lambda: resolve_closure_steps(
                  {**closure, "steps": [bstep("running `epubcheck -h`",
                                              "Given", 7)]}, corpus),
                     "two different corpora"))
        check("a feature file the run does not carry is a refusal, not an "
              "empty index",
              raises(lambda: resolve_closure_steps(
                  {**closure, "feature_file": "src/no/such.feature"}, corpus),
                     "no pinned feature file"))
        # ANTI-VACUITY.  Remove the DocString fence from the bytes and the
        # derived arity MUST move; a constant `None` would pass every check
        # above and be wrong for exactly the steps rule 4 exists for.
        flat = os.path.join(d, "flat")
        os.makedirs(os.path.join(flat, os.path.dirname(feature_rel)))
        with open(os.path.join(flat, feature_rel), "w",
                  encoding="utf-8") as fh:
            fh.write(_FIXTURE_FEATURE.replace('      """\n      body\n'
                                              '      """\n', ""))
        check("with the DocString gone from the bytes, the SAME closure "
              "derives `None` for that step -- the arity is read, not "
              "assumed",
              [s["arg_kind"] for s in resolve_closure_steps(
                  {**closure, "steps": closure["steps"][:4]},
                  flat)["steps"]] == [None, None, None, None])
        sol = stub_solution(item, closure, feature_root=corpus)
        check("the solution is exactly one file and no registration fragment",
              len(sol["files"]) == 1
              and sol["files"][0]["file_path"].startswith(
                  glue_dir_for("epubcheck") + "/"),
              str([f["file_path"] for f in sol["files"]]))
        offline_item = dict(
            item,
            item_id="algorand-sdk/features/unit/offline.feature:1",
            project="algorand-sdk",
            provenance={"file_path": offline_source})
        offline_closure = dict(closure, item_id=offline_item["item_id"])
        offline_sol = stub_solution(offline_item, offline_closure,
                                    feature_root=corpus)
        check("an offline Algorand stub follows its integration runner",
              offline_sol["files"][0]["file_path"].startswith(
                  glue_dir_for("algorand-sdk", offline_source) + "/"))
        check("metadata records n_steps and closure availability",
              sol["metadata"] == {"stub": True, "n_steps": 4,
                                  "closure_available": True},
              str(sol["metadata"]))
        check("an item with no `project` is REFUSED rather than stubbed into "
              "epubcheck's package",
              raises(lambda: stub_solution({"item_id": item["item_id"]},
                                           closure, feature_root=corpus),
                     "carries no `project`"))

        cpath = os.path.join(d, "closures.json")
        with open(cpath, "w", encoding="utf-8") as fh:
            json.dump([closure], fh)
        adapter = make_stub_adapter(cpath, corpus)
        check("the adapter is named stub", adapter.name == "stub",
              adapter.name)
        good = adapter(dict(item))
        check("an item with a closure produces one file",
              len(good["files"]) == 1 and good["metadata"]["n_steps"] == 4)
        missing = adapter({"item_id": "nope"})
        check("an item with no closure is an explicit metadata error, never "
              "a silent fallback",
              missing["files"] == []
              and "no closure" in missing["metadata"]["adapter_error"],
              str(missing["metadata"]))

        # -- acceptance over a hand-written two-item corpus --------------
        item2 = {"item_id": "epubcheck/src/test/resources/cli/cli.feature:82",
                 "project": "epubcheck", "task": "criterion_to_test"}
        closure2 = {"item_id": item2["item_id"],
                    "feature_file": feature_rel, "steps": [
                        bstep("stderr is redirected to stdout", "Given", 16),
                        bstep("the return code is 0", "Then", 17,
                              side="retained")]}
        ipath = os.path.join(d, "items.jsonl")
        with open(ipath, "w", encoding="utf-8") as fh:
            for record in (item, item2, {"item_id": "other/x:1",
                                         "project": "other",
                                         "task": "criterion_to_test"}):
                fh.write(json.dumps(record) + "\n")
        cpath2 = os.path.join(d, "closures2.json")
        with open(cpath2, "w", encoding="utf-8") as fh:
            json.dump([closure, closure2], fh)

        rep = acceptance(ipath, cpath2, corpus, project="epubcheck")
        check("acceptance counts only the project's items, and the methods "
              "they emit",
              rep["items"] == 2 and rep["methods_emitted"] == 5, str(rep))
        check("the retained step is excluded from the emitted census",
              rep["distinct_step_texts"] == 4, str(rep))
        check("acceptance RECOMPUTES the sharing census",
              rep["texts_in_more_than_one_item"] == 1
              and rep["max_items_sharing_a_text"] == 2
              and rep["most_shared_text"] == "stderr is redirected to stdout",
              str(rep))
        check("...and rule 4's census, so an inert arity rule would say so "
              "in a number rather than in prose",
              rep["methods_with_multiline_argument"] == 1, str(rep))
        check("acceptance refuses nothing on clean input",
              rep["items_refused"] == 0 and rep["violations"] == [])
        with open(cpath2, "w", encoding="utf-8") as fh:
            json.dump([closure], fh)
        check("an item without a closure FAILS the acceptance",
              raises(lambda: acceptance(ipath, cpath2, corpus,
                                        project="epubcheck"),
                     "no closure"))
        with open(cpath2, "w", encoding="utf-8") as fh:
            json.dump([closure, dict(closure2, steps=[
                step("two\nlines")])], fh)
        check("a closure carrying an impossible step text is REFUSED with "
              "the ITEM named, not a traceback",
              raises(lambda: acceptance(ipath, cpath2, corpus,
                                        project="epubcheck"),
                     "item(s) refused"))

    # -- the seam this milestone lands ------------------------------------
    import argparse

    from ..bench import cli as _cli
    from ..bench import fixtures as _fixtures
    from ..bench.fixtures import _stub_maker
    from ..stacks import cucumber as _cucumber
    check("the cucumber stack exposes stub_solution, and it IS this function",
          getattr(_cucumber, "stub_solution", None) is stub_solution)
    check("...and it is no longer listed as pending",
          "stub_solution" not in _cucumber.PENDING)
    check("the test source root and the ambiguity this rule guards against "
          "are the stack's constants, not copies",
          _cucumber.JAVA_TEST_ROOT == JAVA_TEST_ROOT
          and "Ambiguous" in _cucumber.AMBIGUOUS_EXCEPTION)
    check("the stub destination is the harness's glue destination",
          glue_dir_for("epubcheck")
          == _cucumber.quirks_for("epubcheck").glue_rel
          and glue_dir_for("algorand-sdk", offline_source)
          == _cucumber.quirks_for(
              "algorand-sdk", offline_source).glue_rel)
    check("the stub's own class resolves to the FQCN the harness reports",
          _cucumber.class_name(path)
          == f"{package_for('epubcheck')}.{class_name(item['item_id'])}",
          _cucumber.class_name(path))

    from ..java.kapua import FEATURE_SUITES
    kapua_routes = []
    for feature, suite in FEATURE_SUITES.items():
        iid = "kapua/" + feature + ":1"
        stub_path, stub_code = java_class("kapua", iid, keys, feature)
        expected = suite.generated_package
        kapua_routes.append(
            package_for("kapua", feature) == expected
            and stub_path == suite.generated_root + class_name(iid) + ".java"
            and stub_code.startswith("package " + expected + ";\n")
            and _cucumber.class_name(stub_path, "kapua")
                == expected + "." + class_name(iid))
    check("every Kapua feature's stub uses its native module runner package",
          len(kapua_routes) == len(FEATURE_SUITES) and all(kapua_routes))

    profile = os.path.join(CONFIG_DIR, "profile_epubcheck.yml")
    if os.path.isfile(profile):
        check("the real epubcheck profile routes `stub-accept` to THIS stack",
              _cli._other_stack(argparse.Namespace(profile=profile),
                                "cmd_stub_accept") is cmd_stub_accept)
        check("a run carrying the epubcheck profile builds THIS stub "
              "adapter, and names the framework whose factory needs the "
              "corpus",
              _stub_maker(argparse.Namespace(profile=profile))
              == (make_stub_adapter, "cucumber")
              and "cucumber" in _fixtures._STUB_NEEDS_CORPUS)
    else:
        print(f"  [SKIP] no {profile}, so the CLI routes could not be driven")
    from . import stub as _php_stub
    check("a run with no profile still builds the PHP one -- every archived "
          "CoreShop stub sweep is one of those -- and behat is NOT handed a "
          "corpus, so its factory is called with the one argument it has "
          "always been called with",
          _stub_maker(argparse.Namespace())
          == (_php_stub.make_stub_adapter, "behat")
          and "behat" not in _fixtures._STUB_NEEDS_CORPUS
          and "behave" not in _fixtures._STUB_NEEDS_CORPUS)
    check("an invocation with no --profile still takes the behat path",
          _cli._other_stack(argparse.Namespace(), "cmd_stub_accept") is None)

    config = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "..", "config", "boundary_epubcheck.yml")
    if os.path.isfile(config):
        from ..core.boundary import load_boundary
        b = load_boundary(config)
        check("the stub is written where the boundary says the ANSWER "
              "lives, so installing it is legal and stripping removes it",
              b.classify(path) == "removable",
              f"{path} -> {b.classify(path)}")
        check("...and the retained environment substrate is NOT where it "
              "goes",
              b.classify(
                  f"{glue_dir_for('epubcheck')}/TestEnvironment.java")
              == "retained")
    else:
        print(f"  [SKIP] no {config}, so the glue directory could not be "
              f"checked against the real boundary")

    # -- the claim this module makes about the half it does NOT do --------
    #
    # `CONTAINER_HALF_NOTE` is a statement about ANOTHER file's state, and
    # this stage has already shipped two seam paragraphs that were true when
    # written and false when read.  So the sentence is checked against
    # `benchmark/scripts/gate_s5_vacuity.py`'s own bytes instead of against
    # anybody's memory, the way `stacks/cucumber.py` reads "the applier is
    # ready and the seam is deliberately unbound" out of the modules.
    # Deliberately NO `[SKIP]` branch: the gate is an in-repo file that is
    # always present, and a skip on a missing file would retire the check
    # silently — which is the exact failure this probe exists for.
    import ast as _ast
    import inspect as _inspect
    _gate = os.path.join(BENCHMARK_ROOT, "scripts", "gate_s5_vacuity.py")
    with open(_gate, encoding="utf-8") as fh:
        _gate_src = fh.read()
    _main_fn = next((n for n in _ast.walk(_ast.parse(_gate_src))
                     if isinstance(n, _ast.FunctionDef)
                     and n.name == "_main"), None)

    def _is_the_refusal(stmt) -> bool:
        # A BARE `raise SystemExit("REFUSED: the S5 live gate ...")` in
        # `_main`'s own body — unconditional, so every stack meets it, and
        # ahead of every check the gate would otherwise run.  Read as a
        # STATEMENT of `_main`, not anywhere in the file: a refusal that
        # moved under an `if` would be a gate that sometimes runs, and this
        # module's sentence would then be wrong in the other direction.
        return (isinstance(stmt, _ast.Raise)
                and isinstance(stmt.exc, _ast.Call)
                and getattr(stmt.exc.func, "id", "") == "SystemExit"
                and bool(stmt.exc.args)
                and isinstance(stmt.exc.args[0], _ast.Constant)
                and isinstance(stmt.exc.args[0].value, str)
                and stmt.exc.args[0].value.startswith(
                    "REFUSED: the S5 live gate"))

    _closed = _main_fn is not None and any(
        _is_the_refusal(s) for s in _main_fn.body)
    check("the S5 live gate is still closed for EVERY stack, read out of "
          "its own bytes rather than remembered", _closed, _gate)

    def _positions(note: str) -> tuple[bool, bool]:
        """`(the note says the gate CHECKS this half, it says NOTHING does)`.

        A keyword test, and said to be one: these two phrases are the
        sentence's contract with this probe rather than a reading of
        English.  Reword the note and this pair moves with it.
        """
        return ("is checked by" in note and "gate_s5_vacuity" in note,
                "NOT checked by any program yet" in note)

    # Both twins, not just this one.  `stub_py.py` prints the identical
    # sentence about the identical gate — true when it was written, stale
    # once the gate closed — and a probe that covered only the Java note
    # would rebuild the asymmetry it exists to remove.  The pair is checked
    # HERE because the reading of the gate is here: a second implementation
    # of "is the S5 live gate closed?" would be a second answer to one
    # question, which is the rule `strip_java` follows for `then_definitions`.
    from . import stub_py as _stub_py
    for _who, _note in (("this module's", CONTAINER_HALF_NOTE),
                        ("the behave twin's", getattr(
                            _stub_py, "CONTAINER_HALF_NOTE", None))):
        check(f"{_who} operator-facing note is a sentence this probe can "
              f"still read, so it cannot be retired by renaming it",
              isinstance(_note, str) and bool(_note), repr(_note)[:80])
        _says_runs, _says_nothing_runs = _positions(_note or "")
        check(f"{_who} note takes exactly ONE of the two positions on the "
              f"container half, so it cannot go quiet instead of going "
              f"stale", _says_runs != _says_nothing_runs, _note)
        check(f"...and the position {_who} note takes is the one the gate's "
              f"bytes support -- a BICONDITIONAL, so the day someone opens "
              f"the gate this line reddens too until the sentence moves "
              f"with it", _says_nothing_runs == _closed, _note)
    check("...and the gate could not consume this module's report even if "
          "it were opened: it reads behave's key names, none of which this "
          "module's `acceptance` emits",
          all(k in _gate_src and k not in _inspect.getsource(acceptance)
              for k in ("functions_emitted", "distinct_step_keys")), _gate)

    print("\n" + ("ALL PASS (stub_java)" if ok else "FAILURES (stub_java)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
