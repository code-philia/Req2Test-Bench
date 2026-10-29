"""The vacuous floor of the anti-vacuity gate (SPEC_C3_PARALLEL §3.10).

A recall-style metric rewards a submission that *runs* the scenario, and
the cheapest way to run a scenario is to define every step it needs with
an empty body: Behat then reports every step passed while the submission
asserts nothing at all.  This module builds exactly that submission, so
the benchmark can measure what a maximally vacuous candidate scores
instead of assuming it scores nothing.

**"stub = 0 by construction" was WITHDRAWN by review v2.**  The stub only
replaces the *removable* half of the harness; retained hooks, the Pimcore
bootstrap and the recorder still run, and any of them can fail on a
mutated production line and thereby "kill" a mutant that the empty step
bodies never observed.  So `stub ≈ 0` is an EXPECTATION, and the gate is
honoured only if the MEASURED stub mutation recall is ≤ 0.02.  Nothing in
this file may be read as a proof of that bound.

Two measured facts sink the naive one-method-per-step design, both
re-checked by `acceptance()` on every run (review P1-6):

* **129 of the 422 released items repeat a concrete step text.**  A method
  per step *occurrence* emits the same `@Given` pattern twice and Behat
  refuses the whole suite with `RedundantStepException` (see
  `vendor/behat/behat/src/Behat/Behat/Definition/Exception/`
  `RedundantStepException.php`).  Hence one method per *distinct* text.
* **4 distinct released step texts contain `/`** — three postal addresses
  (`"9-11/N3"`) and one `should have value "/"`.  `/` is **not** in
  `preg_quote`'s default set on ANY PHP version, 8.3 included (verified
  against 8.3.16 — see `preg_quote` below), so `preg_quote($text)` leaves
  that `/` unescaped, which closes the `/^…$/` delimiter and turns the
  pattern into a syntax error.  Hence `preg_quote($t, '/')` — the second
  argument is load-bearing, not belt-and-braces — and hence a
  delimiter-aware port here.

A third rule is not about pattern syntax at all: a step already answered
by RETAINED code must NOT be defined again.  Behat's search engine matches
a step against *every* registered definition and throws
`AmbiguousMatchException` on two matches (`Definition/Search/`
`RepositorySearchEngine.php`), so re-defining a retained step is as fatal
as duplicating one — it just fails under a different exception name.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
from typing import Optional

from ..bench.runner import item_key
from ..core.gherkin import parse_feature_file
from .pystep_index import BEHAT_DIALECT, examples_rows, render_template

#: Gherkin step lines, as written in `requirement.background` and
#: `criterion.gherkin`.  `\*` is legal Gherkin and appears in the wild;
#: `(.*\S)` drops trailing whitespace, which matters because Behat's
#: docblock reader strips `\s*$` from an annotation line and a pattern
#: carrying trailing space would therefore never match the step it came
#: from.
_STEP_LINE = re.compile(r"^\s*(Given|When|Then|And|But|\*)\s+(.*\S)$")

#: PHP's `preg_quote` special set, verbatim from the switch in
#: `ext/pcre/php_pcre.c`: . \ + * ? [ ^ ] $ ( ) { } = ! < > | : - and `#`
#: (`#` added in PHP 7.3).  NUL is handled separately (below).
#:
#: `/` is deliberately NOT here.  It is a myth — one this file used to
#: repeat — that PHP 7.3 added `/` to the default set; 7.3 added `#`.  An
#: exhaustive byte-for-byte sweep of `preg_quote(chr($b), $delim)` for
#: every ASCII byte under the delimiters `/ # % x`, run against the
#: executor's own PHP 8.3.16, shows `/` escaped when and only when it is
#: the delimiter.  So the `'/'` argument at the one call site is what
#: saves the 4 released texts containing `/`, on every PHP version.
_PREG_SPECIAL = frozenset(".\\+*?[^]$(){}=!<>|:-#")

#: Cap on the derived part of a method name.  PHP imposes no limit; a cap
#: keeps the generated file legible and keeps the sha1 suffix visible at
#: the end of the line rather than pushed off it.
_NAME_CAP = 60

_NAMESPACE = "CoreShop\\Behat\\Context\\Domain"
_DIR = "src/CoreShop/Behat/Context/Domain"

#: Closure step `side` values naming code that SURVIVES stripping, and
#: whose step definitions the stub must therefore not duplicate.  The
#: vocabulary is `boundary.py`'s (`removable | retained | production` and
#: `None` for a step with no definition at all), not one invented here.
_ALREADY_ANSWERED = frozenset({"retained", "production"})

# PHP/Behat only. Other frameworks retain their existing fixture version.
ADAPTER_VERSION = 2
# Sylius Behat 4 discovers attributes, not PHPDoc step annotations.
SYLIUS_ADAPTER_VERSION = 3


# --------------------------------------------------------------- steps
def _check_version(adapter_version: int) -> None:
    if type(adapter_version) is not int or adapter_version not in (1, 2, 3):
        raise ValueError(f"unsupported PHP stub adapter version {adapter_version!r}")


def _concrete_texts(item: dict, closure: Optional[dict], *,
                    adapter_version: int = ADAPTER_VERSION) -> list[tuple[str, str]]:
    """Every step occurrence as `(text, side)`, in execution order.

    `side` is `"unknown"` for the closure-free fallback, which is what
    makes the fallback unusable for a scored run: it cannot tell a step
    the retained code already answers from one it does not.
    """
    _check_version(adapter_version)
    if closure is not None:
        # A closure joined to the wrong item would produce a stub for a
        # different scenario — one that passes or fails for reasons that
        # have nothing to do with the item being scored.  Cheap to check,
        # impossible to notice downstream.
        if closure.get("item_id") not in (None, item.get("item_id")):
            raise ValueError(f"closure {closure.get('item_id')!r} does not "
                             f"belong to item {item.get('item_id')!r}")
        steps = list(closure.get("steps") or [])
    else:
        steps = []
        for origin, blob in (
                ("background", (item.get("requirement") or {}).get("background")),
                ("scenario", (item.get("criterion") or {}).get("gherkin"))):
            for line in (blob or "").splitlines():
                m = _STEP_LINE.match(line)
                if m:
                    steps.append({"text": m.group(2), "origin": origin})

    # Recorded version 1 recipes rederive their original bytes, including
    # their literal outline patterns. Never repair historical control input
    # while claiming to authenticate the source that produced it.
    if adapter_version == 1:
        return [(s["text"], s.get("side") or "unknown") for s in steps]
    feature = parse_feature_file(
        str(item.get("item_id")),
        text=(item.get("criterion") or {}).get("gherkin") or "")
    outlines = [s for s in feature.scenarios
                if s.kind in {"Scenario Outline", "Scenario Template"}]
    if not outlines:
        return [(s["text"], s.get("side") or "unknown") for s in steps]
    if len(feature.scenarios) != 1:
        raise ValueError("a stub item must name exactly one scenario outline")
    rows = examples_rows(feature, outlines[0], dialect=BEHAT_DIALECT)
    if not rows:
        raise ValueError("a stub outline requires its released Examples rows")
    # Behat expands the outline's own steps, never its Background. Keep the
    # closure's retained/production classification on every concrete text.
    return [(render_template(s["text"], values)
             if s.get("origin") == "scenario" else s["text"],
             s.get("side") or "unknown")
            for _line, values in rows for s in steps]


def step_texts(item: dict, closure: Optional[dict], *,
               adapter_version: int = ADAPTER_VERSION) -> list[str]:
    """The distinct step texts this item needs defined, in first-appearance order.

    With a closure, every step ALREADY ANSWERED BY CODE THAT SURVIVES
    STRIPPING is EXCLUDED, because a second definition makes Behat's
    definition search ambiguous (`AmbiguousMatchException`), which aborts
    the scenario just as surely as the redundancy it would be easy to
    worry about instead.

    `closure.py` classifies a step's defining file with `boundary.py`'s
    vocabulary — `removable | retained | production | None` — and BOTH
    `retained` and `production` survive stripping, so both are excluded.
    An earlier revision excluded only `retained` and documented a side
    value `"unmatched"` that `closure.py` never emits (a step with no
    definition carries `side: None`).  On this release the distinction is
    inert — the 6934 step occurrences are 6773 `removable` and 161
    `retained`, no `production` and no `None` — so this changes no emitted
    byte; it closes the case that would have failed silently, in exactly
    the way re-defining a retained step fails.

    `removable` steps are included: those are the definitions the item
    removed.  So is any side this module does not recognise, `None`
    included — the fallback's `"unknown"` depends on it, and a step with
    no definition at all must be defined by the stub or the scenario
    cannot run.

    Without a closure the step list is recovered by parsing
    `requirement.background` and `criterion.gherkin`.  **That fallback
    cannot exclude retained steps and must never be used for a scored
    run**; it exists so corpus statistics can be recomputed from the
    public release alone.  On this corpus it yields 1093 distinct texts
    against the closure's 1049 non-retained ones — 44 texts that a scored
    stub would define on top of retained code and lose.
    """
    seen: set[str] = set()
    out: list[str] = []
    for text, side in _concrete_texts(item, closure,
                                     adapter_version=adapter_version):
        if side in _ALREADY_ANSWERED or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


# ---------------------------------------------------------------- names
def method_name(text: str, taken: set[str]) -> str:
    """A deterministic, unique, valid PHP method name for `text`.

    The sha1 suffix is UNCONDITIONAL, and that is the whole point.  35 of
    the 1093 released step texts share a camelCase base with another text
    (`the cart total should be "0"` / `the cart total should be 0`
    collapse to the same alphanumeric words), so a suffix added only on
    collision would name the same text differently depending on which of
    the pair the generator reached first — and the emitted file would then
    depend on iteration order, so two runs over the same item could differ
    in bytes.  A counter has the same defect and is worse: it also changes
    every downstream name when one step is added.

    `taken` is a corruption check, not the disambiguator.  A name already
    in it means either the caller passed the same text twice (which would
    emit two identical methods — a PHP fatal error) or two texts collided
    in the leading **32 bits** of sha1 (8 hex characters, not 40 as an
    earlier revision of this docstring claimed); both are refusals, never
    silent renames.  The name is added to `taken` on success.  Measured on
    the release: 0 collisions over the 1049 emitted texts, and the largest
    single class holds 30 of them.

    The check is exact-match while PHP resolves method names
    case-insensitively, so in principle two names differing only in case
    would slip past it and hit "Cannot redeclare" instead.  That needs a
    32-bit sha1 collision as well (the suffix is lowercase hex), i.e. it
    is the same event, and it does not occur on this release.
    """
    words = re.findall(r"[A-Za-z0-9]+", text)
    base = "".join(w.lower() if i == 0 else w[0].upper() + w[1:]
                   for i, w in enumerate(words))
    base = base[:_NAME_CAP]
    # A PHP method name may not start with a digit, and a text of pure
    # punctuation ("/") yields no words at all.
    if not base or base[0].isdigit():
        base = "step" + base
    name = f"{base}_{hashlib.sha1(text.encode('utf-8')).hexdigest()[:8]}"
    if name in taken:
        raise ValueError(f"method name {name!r} already taken — duplicate "
                         f"step text or sha1 collision for {text!r}")
    taken.add(name)
    return name


# ----------------------------------------------------------- preg_quote
def preg_quote(text: str, delimiter: str = "/") -> str:
    """Python port of PHP's `preg_quote($str, $delimiter)`.

    Escaped set, verbatim from the switch in `ext/pcre/php_pcre.c` and
    re-derived from the executor's PHP 8.3.16 by an exhaustive sweep of
    every ASCII byte under four delimiters::

        . \\ + * ? [ ^ ] $ ( ) { } = ! < > | : -       (all versions)
        #                                             (since PHP 7.3)

    `/` is NOT in that set on any version — PHP 7.3 added `#`, not `/`,
    and the sweep confirms 8.3.16 leaves a bare `/` alone under the
    delimiters `#`, `%` and `x`.

    NUL is handled separately: it becomes the four characters ``\\000``
    (PHP emits the octal escape rather than a backslash-NUL, because a
    literal NUL cannot survive a C string).  Every other byte, including
    the double quotes that wrap most CoreShop step arguments and the
    non-breaking space in `"1,00\\xa0$"`, is passed through unchanged.

    `delimiter` is escaped too, whether or not it is in the set above,
    and that is the ONLY thing that escapes `/`.  The stub therefore
    always passes `'/'` explicitly and must keep doing so: drop the
    argument and the 4 released texts containing `/` produce
    `/^…9\\-11/N3…$/`, an unterminated pattern, on PHP 8.3 exactly as on
    PHP 7.2.  A character is escaped once or not at all, so passing a
    delimiter that is already in the set costs nothing.
    """
    out = []
    for ch in text:
        if ch == "\x00":
            out.append("\\000")
        elif ch in _PREG_SPECIAL or (delimiter and ch == delimiter):
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


# ------------------------------------------------------------ PHP class
#: PHPDoc embedding rule, enforced by `_annotation` below.
#:
#: (1) The quoted pattern can never contain `*/`, because `preg_quote`
#:     escapes BOTH characters: `*/` becomes `\*\/`.  So the docblock
#:     cannot be closed early by any step text.  This is checked after
#:     quoting rather than asserted in prose, because it is the single
#:     property the whole docblock depends on.
#: (2) The annotation must occupy ONE line: Behat splits the docblock on
#:     "\n" and matches `/^\@(given|when|then)\s+(.+)$/i` per line
#:     (`Context/Reader/AnnotatedContextReader.php`), so a text containing
#:     a newline or a carriage return would silently register a TRUNCATED
#:     pattern — a stub that passes for the wrong reason.  Any C0 control
#:     character or DEL is therefore REFUSED, not stripped.  Zero of the
#:     1093 released texts contain one, so the refusal costs nothing here
#:     and catches a corrupt corpus loudly.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _annotation(text: str) -> str:
    if not text.strip():
        raise ValueError("empty step text: /^$/ would match every empty "
                         "step in the suite")
    bad = _CONTROL.search(text)
    if bad:
        raise ValueError(
            f"step text carries control character {bad.group(0)!r} at "
            f"offset {bad.start()} and cannot be embedded in a one-line "
            f"PHPDoc annotation: {text!r}")
    pattern = "/^" + preg_quote(text, "/") + "$/"
    if "*/" in pattern:
        raise ValueError(f"quoted pattern would close the docblock: {pattern!r}")
    return pattern


def php_context(item_id: str, texts: list[str], *,
                namespace: str = _NAMESPACE,
                dir_: str = _DIR,
                adapter_version: int = ADAPTER_VERSION) -> tuple[str, str]:
    """`(repo-relative path, PHP source)` for one item's stub context.

    `namespace`/`dir_` are the project row (`repo.BehatProject`'s
    `stub_namespace` and `stub_dir`); they default to CoreShop's so every
    existing call site writes exactly the file it always wrote.

    One class, one public method per text, every body empty.  The class
    name carries `runner.item_key(item_id)` — the same sha1[:16] the
    release uses to name gold records — so two items can never collide on
    a file path or a class name, and a stub artifact joins to its item by
    filename.

    The parameter list is a DEVIATION from the `(): void` in §3.10, and it
    is deliberate: 54 of the 422 released items contain a step carrying a
    table or a docstring, and Behat appends that node to the definition's
    arguments.  Against a zero-parameter method
    `MixedArgumentOrganiser::prepareArguments` throws
    `UnexpectedMultilineArgumentException` ("you have passed a TableNode
    or PystringNode, but it was not used"), so those 54 stubs would ERROR
    instead of vacuously passing — and an erroring stub is scored 0 by
    ineligibility, which would quietly shrink the population the ≤ 0.02
    bound is measured over to 87% of the corpus and make the floor look
    lower than it is.  Two optional typed parameters absorb the node
    (typed, so Behat routes it as a typehinted argument and never as a
    numbered one) and are ignored; the bodies stay empty. The table parameter
    also accepts arrays: retained Behat transformations may replace a table
    with an array before invoking the step (PrestaShop's locale/value table).
    Its TableNode union arm preserves the original multiline routing.
    """
    _check_version(adapter_version)
    table_type = "?TableNode" if adapter_version == 1 else "TableNode|array|null"
    key = item_key(item_id)
    path = f"{dir_}/Stub{key}Context.php"

    seen: set[str] = set()
    taken: set[str] = set()
    methods = []
    for text in texts:
        if text in seen:
            # The caller is expected to have deduplicated (`step_texts`
            # does).  Emitting the duplicate would produce two identical
            # @Given patterns and Behat would abort the suite with
            # RedundantStepException — the exact failure §3.10 exists to
            # prevent, so it is refused at the point it becomes possible.
            raise ValueError(f"duplicate step text handed to php_context: "
                             f"{text!r}")
        seen.add(text)
        methods.append((method_name(text, taken), _annotation(text)))

    lines = [
        "<?php",
        "",
        "declare(strict_types=1);",
        "",
        f"namespace {namespace};",
        "",
        "use Behat\\Behat\\Context\\Context;",
        "use Behat\\Gherkin\\Node\\PyStringNode;",
        "use Behat\\Gherkin\\Node\\TableNode;",
        "",
        "/**",
        " * GENERATED by r2t.toolkit.stub (SPEC_C3_PARALLEL §3.10) — the vacuous",
        " * floor of the anti-vacuity gate.  Every step this scenario needs",
        " * and the retained code does not already define, with an empty",
        " * body: Behat reports every step passed and nothing is asserted.",
        f" * item: {item_id}",
        " */",
        f"class Stub{key}Context implements Context",
        "{",
    ]
    for i, (name, pattern) in enumerate(methods):
        if i:
            lines.append("")
        if adapter_version == SYLIUS_ADAPTER_VERSION:
            # PHP single-quoted literal: preserve the regex bytes, including
            # backslashes and apostrophes; never interpolate step text.
            literal = pattern.replace("\\", "\\\\").replace("'", "\\'")
            lines.append("    #[\\Behat\\Step\\Given('" + literal + "')]")
        else:
            lines.extend(["    /**", f"     * @Given {pattern}", "     */"])
        lines.extend([
            f"    public function {name}({table_type} $table = null, "
            f"?PyStringNode $string = null): void",
            "    {",
            "    }",
        ])
    lines.extend(["}", ""])
    return path, "\n".join(lines)


# ------------------------------------------------------------- adapter
def stub_solution(item: dict, closure: Optional[dict], *,
                  namespace: str = _NAMESPACE, dir_: str = _DIR,
                  adapter_version: int = ADAPTER_VERSION) -> dict:
    """The adapter contract: `{"files": [...], "metadata": {...}}`.

    No `behat_services.yml`.  The stub class has no constructor, so the
    harness's autowired registration (`harness.write_registration`) wires
    it unaided; shipping a fragment would only add a way to get the
    registration wrong.
    """
    texts = step_texts(item, closure, adapter_version=adapter_version)
    path, code = php_context(item["item_id"], texts, namespace=namespace,
                             dir_=dir_, adapter_version=adapter_version)
    return {
        "files": [{"file_path": path, "code": code}],
        "metadata": {"stub": True, "n_steps": len(texts),
                     "closure_available": closure is not None},
    }


def load_closures(path: str) -> dict[str, dict]:
    with open(path, encoding="utf-8") as fh:
        return {c["item_id"]: c for c in json.load(fh)}


def make_stub_adapter(closures_path: str, *, namespace: str = _NAMESPACE,
                      dir_: str = _DIR,
                      adapter_version: int = ADAPTER_VERSION):
    """The `stub` adapter — the control §3.10 requires before publishing pass@1.

    The namespace/directory pair is the project row, defaulting to
    CoreShop's: a second Behat project writes its stub under its own
    `Behat\\` PSR-4 root or the file is not autoloaded at all.
    """
    from ..bench.adapters import Adapter

    _check_version(adapter_version)
    closures = load_closures(closures_path)

    def run(task: dict) -> dict:
        closure = closures.get(task["item_id"])
        if closure is None:
            # Falling back to the Gherkin parse here would look like it
            # worked and would silently redefine retained steps, so the
            # run would die on AmbiguousMatchException far from the cause.
            # `adapter_error` is the key `generate.generate_all` buckets on.
            return {"files": [], "metadata": {
                "adapter_error": f"no closure for {task['item_id']}: a stub "
                                 f"cannot exclude retained steps without one"}}
        try:
            return stub_solution(task, closure, namespace=namespace,
                                 dir_=dir_, adapter_version=adapter_version)
        except Exception as e:                                 # noqa: BLE001
            return {"files": [], "metadata": {
                "adapter_error": f"{type(e).__name__}: {e}"}}

    return Adapter("stub", run, {"closures": closures_path,
                                  "adapter_version": adapter_version})


# ---------------------------------------------------------- acceptance
def _load_jsonl(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def acceptance(items_path: str, closures_path: Optional[str]) -> dict:
    """Generate for every released item and check what can be checked here.

    Half of §3.10's acceptance is PHP-side — valid PHP, successful Behat
    definition discovery, no ambiguous definitions — and needs the
    container; **the coordinator runs that half separately**.  This half
    needs no PHP: byte-identical output on repetition, distinct patterns
    within an item, distinct file paths across items, and a recomputation
    of the two corpus statistics §3.10 cites, so a change to the release
    that invalidates them is caught here rather than in a container log.

    Raises `SystemExit` on any violation; returns the report otherwise.
    """
    items = _load_jsonl(items_path)
    closures = load_closures(closures_path) if closures_path else {}

    n_methods = 0
    refused: list[dict] = []
    paths: dict[str, str] = {}
    dup_all = 0            # items repeating a concrete step text (all steps)
    dup_emitted = 0        # ... after retained steps are excluded
    distinct_all: set[str] = set()
    distinct_emitted: set[str] = set()
    missing_closure: list[str] = []
    violations: list[str] = []

    for item in items:
        iid = item["item_id"]
        closure = closures.get(iid)
        if closures_path and closure is None:
            missing_closure.append(iid)

        occurrences = [t for t, _side in _concrete_texts(item, closure)]
        distinct_all.update(occurrences)
        if len(occurrences) != len(set(occurrences)):
            dup_all += 1

        texts = step_texts(item, closure)
        distinct_emitted.update(texts)
        emitted_occurrences = [t for t, side in _concrete_texts(item, closure)
                               if side != "retained"]
        if len(emitted_occurrences) != len(set(emitted_occurrences)):
            dup_emitted += 1

        try:
            path, code = php_context(iid, texts)
            path2, code2 = php_context(iid, texts)
        except Exception as e:                                 # noqa: BLE001
            refused.append({"item_id": iid, "why": f"{type(e).__name__}: {e}"})
            continue

        if (path, code) != (path2, code2):
            violations.append(f"{iid}: regenerating changed the output")
        if path in paths and paths[path] != iid:
            violations.append(f"{path}: emitted for both {paths[path]} and {iid}")
        paths[path] = iid

        patterns = re.findall(r"^\s*\* @Given (.*)$", code, re.M)
        if len(patterns) != len(set(patterns)):
            violations.append(f"{iid}: duplicate @Given pattern "
                              f"({len(patterns)} emitted, "
                              f"{len(set(patterns))} distinct) — "
                              f"RedundantStepException")
        if len(patterns) != len(texts):
            violations.append(f"{iid}: {len(texts)} texts but "
                              f"{len(patterns)} patterns")
        n_methods += len(patterns)

    if missing_closure:
        violations.append(
            f"{len(missing_closure)} items have no closure "
            f"(e.g. {missing_closure[0]}); a scored stub run needs one per "
            f"item to exclude retained steps")
    if refused:
        violations.append(f"{len(refused)} items refused: {refused[:3]}")

    report = {
        "items": len(items),
        "methods_emitted": n_methods,
        "items_refused": len(refused),
        "refusals": refused,
        "closures": closures_path,
        "source": "closures" if closures_path else "gherkin_fallback",
        # The two figures §3.10 cites, over ALL concrete step occurrences —
        # that is the population in which the naive design breaks.
        "items_with_duplicate_step_text": dup_all,
        "distinct_step_texts": len(distinct_all),
        "distinct_step_texts_with_slash": sum(1 for t in distinct_all if "/" in t),
        # And the same two over what the stub ACTUALLY emits, which is
        # smaller because retained steps are excluded.
        "items_with_duplicate_emitted_text": dup_emitted,
        "distinct_emitted_texts": len(distinct_emitted),
        "distinct_emitted_texts_with_slash": sum(1 for t in distinct_emitted
                                                 if "/" in t),
        "violations": violations,
    }
    if violations:
        raise SystemExit("REFUSED: stub acceptance failed:\n  "
                         + "\n  ".join(violations))
    return report


# ----------------------------------------------------------- selftest
def selftest() -> int:
    import shutil
    import subprocess
    import tempfile
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    # ---- preg_quote, against hand-checked PHP behaviour
    cases = {
        ("a/b", "/"): "a\\/b",
        # `/` is NOT in preg_quote's default set on any PHP, 8.3 included:
        # only the delimiter argument escapes it.  Verified byte-for-byte
        # against PHP 8.3.16.  An earlier revision asserted "a\\/b" here
        # and was simply wrong about PHP.
        ("a/b", "#"): "a/b",
        ("a/b", ""): "a/b",               # no delimiter -> no `/` escape
        ("a#b", "/"): "a\\#b",            # `#` IS in the set (since 7.3)
        ("#tag", "/"): "\\#tag",
        ("9-11", "/"): "9\\-11",
        ("{n}", "/"): "\\{n\\}",
        ("1.0", "/"): "1\\.0",
        ("a\x00b", "/"): "a\\000b",
        ("back\\slash", "/"): "back\\\\slash",
        ('say "hi", ok', "/"): 'say "hi", ok',   # quotes/commas untouched
        ("100%", "%"): "100\\%",                 # delimiter outside the set
        ("a^b$c|d", "/"): "a\\^b\\$c\\|d",
        ("<x> = !y", "/"): "\\<x\\> \\= \\!y",
    }
    for (text, delim), want in cases.items():
        got = preg_quote(text, delim)
        check(f"preg_quote({text!r}, {delim!r})", got == want, f"got {got!r}")
    check("no character is escaped twice",
          preg_quote("/", "/") == "\\/", repr(preg_quote("/", "/")))

    # ---- the 4 released `/` texts survive embedding in /^...$/
    slashy = 'the customer has an address "9-11/N3"'
    _, src = php_context("x", [slashy])
    check("a `/` in the text cannot close the pattern delimiter",
          "9\\-11\\/N3" in src and src.count("/^") == 1, src)
    # ...and it is the DELIMITER argument that does that work, not the
    # default set.  Without this the "redundant on 7.3+" myth reappears
    # and someone drops the `'/'` at the one call site.
    check("dropping the delimiter argument would leave that `/` bare",
          preg_quote(slashy, "") == 'the customer has an address "9\\-11/N3"',
          repr(preg_quote(slashy, "")))
    check("the escaped set is exactly PHP's, `/` excluded",
          "/" not in _PREG_SPECIAL and "#" in _PREG_SPECIAL
          and set(".\\+*?[^]$(){}=!<>|:-#") == set(_PREG_SPECIAL),
          "".join(sorted(_PREG_SPECIAL)))

    # ---- distinct texts, duplicates collapsed, retained excluded
    closure = {"item_id": "i1", "steps": [
        {"text": "the store exists", "side": "retained", "origin": "background"},
        {"text": "the cart is empty", "side": "removable", "origin": "background"},
        {"text": "the cart is empty", "side": "removable", "origin": "scenario"},
        # `closure.py` gives a step with no definition `side: None` — it
        # has no value "unmatched", which an earlier revision of this
        # fixture invented and then "tested".
        {"text": "I add a product", "side": None, "origin": "scenario"},
    ]}
    item = {"item_id": "i1",
            "requirement": {"background": "  Background:\n"
                                          "    Given the store exists\n"
                                          "    And the cart is empty\n"},
            "criterion": {"gherkin": "  Scenario: s\n"
                                     "    Given the cart is empty\n"
                                     "    When I add a product\n"}}
    with_cl = step_texts(item, closure)
    without = step_texts(item, None)
    check("duplicate texts collapse to one entry",
          with_cl == ["the cart is empty", "I add a product"], str(with_cl))
    check("retained steps are excluded when a closure is supplied",
          "the store exists" not in with_cl, str(with_cl))
    check("removable and definition-less steps are both kept",
          set(with_cl) == {"the cart is empty", "I add a product"}, str(with_cl))
    # `production` survives stripping exactly as `retained` does, so
    # re-defining it is the same AmbiguousMatchException.
    prod = dict(closure, steps=[s if s["text"] != "the cart is empty"
                                else dict(s, side="production")
                                for s in closure["steps"]])
    check("a step answered by PRODUCTION code is excluded too",
          step_texts(item, prod) == ["I add a product"],
          str(step_texts(item, prod)))
    check("the exclusion set is boundary.py's, not one invented here",
          _ALREADY_ANSWERED == {"retained", "production"},
          str(sorted(_ALREADY_ANSWERED)))
    check("the closure-free fallback cannot exclude retained steps",
          without == ["the store exists", "the cart is empty",
                      "I add a product"], str(without))
    check("a closure from another item is refused",
          _raises(lambda: step_texts(item, dict(closure, item_id="other"))))

    # The PrestaShop order_stock outlines carry literal <index> in their
    # closures, but Behat executes product1..product11 and product1..product2.
    outline = {"item_id": "prestashop/order_stock.feature:20",
               "criterion": {"gherkin": """Scenario Outline: Order stock
    Given there is a product named "product<index>"
    When I create "dummy_cart<index>"
    Then product "product<index>" stock should be:
      | employee | delta_quantity |
      | Mummy    | 100            |
    Examples:
      | index | order_status |
      | 1     | Payment      |
      | 2     | Payment      |
    @other-statuses
    Examples:
      | index | order_status |
      | 11    | Shipped      |
      | 1     | Shipped      |
"""}}
    outline_closure = {"item_id": outline["item_id"], "steps": [
        {"text": "email sending is disabled", "side": "retained",
         "origin": "background"},
        {"text": 'literal "<index>" in background', "side": "removable",
         "origin": "background"},
        {"text": 'there is a product named "product<index>"',
         "side": "removable", "origin": "scenario"},
        {"text": 'I create "dummy_cart<index>"',
         "side": "removable", "origin": "scenario"},
        {"text": 'product "product<index>" stock should be:',
         "side": "production", "origin": "scenario"},
    ]}
    expanded = step_texts(outline, outline_closure)
    check("outline uses every Examples block, deduplicates and keeps boundaries",
          expanded == ['literal "<index>" in background',
                       'there is a product named "product1"',
                       'I create "dummy_cart1"',
                       'there is a product named "product2"',
                       'I create "dummy_cart2"',
                       'there is a product named "product11"',
                       'I create "dummy_cart11"'], str(expanded))
    no_examples = {**outline, "criterion": {
        "gherkin": 'Scenario Outline: missing\n Given product "<index>"'}}
    check("outline without released Examples refuses instead of emitting a template",
          _raises(lambda: step_texts(no_examples, outline_closure)))
    malformed = {**outline, "criterion": {"gherkin":
        outline["criterion"]["gherkin"].replace("| 11    | Shipped      |", "| 11 |")}}
    check("malformed Examples row refuses instead of dropping a column",
          _raises(lambda: step_texts(malformed, outline_closure)))
    legacy_outline = stub_solution(outline, outline_closure, adapter_version=1)
    check("recorded version 1 retains literal outline patterns and its original signature",
          legacy_outline["metadata"]["n_steps"] == 3
          and r"product\<index\>" in legacy_outline["files"][0]["code"]
          and "?TableNode $table" in legacy_outline["files"][0]["code"])
    check("ordinary version 1 bytes differ only by the repaired table signature",
          php_context("same", ["one step"], adapter_version=1)[1]
          == php_context("same", ["one step"])[1].replace(
              "TableNode|array|null $table", "?TableNode $table"))

    # The attribute literal decodes to the identical pattern, including
    # apostrophes, backslashes, dollar signs and delimiter characters.
    tricky = ["the customer's path is C:\\shop/a", 'the price is "$5"', "a # tag"]
    old_php = php_context("sylius/fixture:1", tricky, adapter_version=2)[1]
    new_php = php_context("sylius/fixture:1", tricky, adapter_version=3)[1]
    literals = re.findall(r"#\[\\Behat\\Step\\Given\('((?:\\.|[^'])*)'\)\]", new_php)
    decoded = [re.sub(r"\\([\\'])", r"\1", value) for value in literals]
    check("Sylius attribute strings retain exact regex bytes",
          decoded == [_annotation(text) for text in tricky], str(decoded))
    check("Sylius registration changes no method body or signature",
          re.findall(r"public function.*?\n    \{\n    \}", new_php) ==
          re.findall(r"public function.*?\n    \{\n    \}", old_php))
    check("historical v2 keeps docblocks and v3 uses attributes only",
          "@Given" in old_php and "@Given" not in new_php and len(literals) == 3)

    # ---- names: pure function of the text, so order cannot matter
    texts = [f"the cart total should be \"{i}\"" for i in range(1, 21)] + \
            ["the cart total should be 0", 'the cart total should be "0"']
    ordered = {t: method_name(t, set()) for t in texts}
    shuffled = list(texts)
    random.Random(7).shuffle(shuffled)
    taken: set[str] = set()
    reshuffled = {t: method_name(t, taken) for t in shuffled}
    check("method names do not depend on insertion order",
          ordered == reshuffled, "names moved under a shuffle")
    check("names are unique across colliding camelCase bases",
          len(set(ordered.values())) == len(texts),
          f"{len(set(ordered.values()))} names for {len(texts)} texts")
    check("a name reused inside one class is refused",
          _raises(lambda: method_name("x", {method_name("x", set())})))
    check("a text with no alphanumerics still yields a legal method name",
          re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", method_name("/", set()))
          is not None, method_name("/", set()))
    long_a = "the quantity of the product named " + "x" * 200 + " is one"
    long_b = "the quantity of the product named " + "x" * 200 + " is two"
    na_l, nb_l = method_name(long_a, set()), method_name(long_b, set())
    check("a very long text is capped, suffix included, and stays unique",
          len(na_l) == _NAME_CAP + 9 and na_l != nb_l
          and na_l.split("_")[0] == nb_l.split("_")[0], f"{len(na_l)} {na_l}")
    check("a text starting with a digit yields a legal method name",
          method_name("42 things exist", set()).startswith("step"),
          method_name("42 things exist", set()))

    # ---- two texts differing only in an escaped character stay distinct
    a, b = "the value is a-b", "the value is a.b"
    na, nb = method_name(a, set()), method_name(b, set())
    _, src_ab = php_context("i2", [a, b])
    pats = re.findall(r"^\s*\* @Given (.*)$", src_ab, re.M)
    check("texts differing only in an escaped char get distinct methods",
          na != nb, f"{na} == {nb}")
    check("...and distinct patterns", len(pats) == 2 and pats[0] != pats[1],
          str(pats))
    check("...even though their camelCase bases are identical",
          na.split("_")[0] == nb.split("_")[0], f"{na} {nb}")

    # ---- PHPDoc escaping
    _, src_star = php_context("i3", ["a */ b closes nothing"])
    star_pat = re.findall(r"^\s*\* @Given (.*)$", src_star, re.M)
    check("a text containing */ is escaped, not dropped",
          len(star_pat) == 1 and star_pat[0] == "/^a \\*\\/ b closes nothing$/"
          and "*/" not in star_pat[0], str(star_pat))
    check("...and the docblock is still closed exactly where it should be",
          src_star.count("*/") == 2, str(src_star.count("*/")))
    check("a newline in a step text is refused",
          _raises(lambda: php_context("i4", ["two\nlines"])))
    check("a carriage return in a step text is refused",
          _raises(lambda: php_context("i4", ["two\rlines"])))
    check("a tab in a step text is refused",
          _raises(lambda: php_context("i4", ["a\tb"])))
    check("an empty step text is refused",
          _raises(lambda: php_context("i4", ["   "])))
    check("a duplicate text handed to php_context is refused",
          _raises(lambda: php_context("i4", ["same", "same"])))

    # ---- the emitted class
    three = ["the cart is empty", "I add a product", "the total is \"10\""]
    path, src = php_context("coreshop/features/x.feature:12", three)
    key = item_key("coreshop/features/x.feature:12")
    check("path and class name derive from item_key",
          path == f"{_DIR}/Stub{key}Context.php"
          and f"class Stub{key}Context implements Context" in src, path)
    check("two items never share a path",
          php_context("a", three)[0] != php_context("b", three)[0])
    check("exactly one method per distinct text",
          src.count("public function ") == 3, str(src.count("public function ")))
    check("exactly one annotation per method",
          src.count("@Given ") == 3, str(src.count("@Given ")))
    check("every body is empty",
          re.findall(r"\{\n    \}", src) and "return" not in src, src)
    check("the class declares the Behat Context interface the indexer looks for",
          "use Behat\\Behat\\Context\\Context;" in src
          and f"namespace {_NAMESPACE};" in src)

    # The row: a second Behat project's stub has to land under ITS own
    # `Behat\` PSR-4 root, or composer's autoloader never finds the class
    # and every stub item is a container error rather than a vacuous pass.
    spath, ssrc = php_context(
        "sylius/features/api/address_book.feature:12", ["I add an address"],
        namespace="Sylius\\Behat\\Context\\Api",
        dir_="src/Sylius/Behat/Context/Api")
    check("the stub's namespace and directory are the project's row, and "
          "CoreShop's remain the defaults",
          spath.startswith("src/Sylius/Behat/Context/Api/")
          and "namespace Sylius\\Behat\\Context\\Api;" in ssrc
          and _NAMESPACE == "CoreShop\\Behat\\Context\\Domain"
          and _DIR == "src/CoreShop/Behat/Context/Domain",
          spath)
    from ..bench.repo import CORESHOP_BEHAT
    check("...and the row the publication adapter now passes IS that pair, "
          "so a CoreShop stub still lands where it lands today",
          (CORESHOP_BEHAT.stub_namespace, CORESHOP_BEHAT.stub_dir)
          == (_NAMESPACE, _DIR),
          f"{CORESHOP_BEHAT.stub_namespace} {CORESHOP_BEHAT.stub_dir}")
    check("regeneration is byte-identical",
          php_context("coreshop/features/x.feature:12", three) == (path, src))

    # ---- solution + adapter
    sol = stub_solution(item, closure)
    check("the solution is one file and no services fragment",
          len(sol["files"]) == 1
          and not any(f["file_path"].endswith("behat_services.yml")
                      for f in sol["files"]), str(sol["files"]))
    check("metadata records n_steps and closure availability",
          sol["metadata"]["n_steps"] == 2
          and sol["metadata"]["closure_available"] is True,
          str(sol["metadata"]))
    check("without a closure the metadata says so",
          stub_solution(item, None)["metadata"]["closure_available"] is False)

    with tempfile.TemporaryDirectory() as d:
        cpath = os.path.join(d, "closures.json")
        with open(cpath, "w", encoding="utf-8") as fh:
            json.dump([closure], fh)
        adapter = make_stub_adapter(cpath)
        check("the adapter is named stub", adapter.name == "stub", adapter.name)
        check("PHP stub exposes its changed producer version",
              adapter.config["adapter_version"] == 2)
        legacy_adapter = make_stub_adapter(cpath, adapter_version=1)
        check("recorded producer version selects the historical implementation",
              legacy_adapter.config["adapter_version"] == 1
              and legacy_adapter(item) == stub_solution(item, closure, adapter_version=1))
        check("unknown and boolean producer versions refuse before reading inputs",
              all(_raises(lambda v=v: make_stub_adapter("absent", adapter_version=v), ValueError)
                  for v in (0, 4, True)))
        good = adapter({"item_id": "i1", "requirement": {}, "criterion": {}})
        check("an item with a closure produces one file",
              len(good["files"]) == 1 and good["metadata"]["n_steps"] == 2,
              str(good["metadata"]))
        missing = adapter({"item_id": "nope", "requirement": {}, "criterion": {}})
        check("an item with no closure is an explicit metadata error",
              missing["files"] == []
              and "no closure" in missing["metadata"]["adapter_error"],
              str(missing["metadata"]))

        # ---- acceptance on a hand-written two-item release
        # The `/` counts are deliberately DIFFERENT from each other and
        # from 1: one slash text is retained (counted in `distinct_step_
        # texts_with_slash`, not in the emitted one), two are emitted.  A
        # fixture where both counts are 1 is satisfied by an implementation
        # that returns the constant 1, which is how this check was written
        # before and is not a check at all.
        item2 = {"item_id": "i2",
                 "requirement": {"background": "  Background:\n"
                                               "    Given the store exists\n"
                                               "    And the path is \"a/b\"\n"},
                 "criterion": {"gherkin": "  Scenario: s\n"
                                          "    Then value is \"/\"\n"
                                          "    Then value is \"/\"\n"
                                          "    Then value is \"x/y\"\n"}}
        closure2 = {"item_id": "i2", "steps": [
            {"text": "the store exists", "side": "retained"},
            {"text": 'the path is "a/b"', "side": "retained"},
            {"text": 'value is "/"', "side": "removable"},
            {"text": 'value is "/"', "side": "removable"},
            {"text": 'value is "x/y"', "side": "removable"},
        ]}
        ipath = os.path.join(d, "items.jsonl")
        with open(ipath, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(item) + "\n")
            fh.write(json.dumps(item2) + "\n")
        cpath2 = os.path.join(d, "closures2.json")
        with open(cpath2, "w", encoding="utf-8") as fh:
            json.dump([closure, closure2], fh)

        rep = acceptance(ipath, cpath2)
        check("acceptance counts items and methods",
              rep["items"] == 2 and rep["methods_emitted"] == 4, str(rep))
        check("acceptance recomputes the duplicate-text statistic",
              rep["items_with_duplicate_step_text"] == 2
              and rep["items_with_duplicate_emitted_text"] == 2, str(rep))
        check("acceptance recomputes the `/` statistic over ALL texts",
              rep["distinct_step_texts_with_slash"] == 3, str(rep))
        check("...and separately over the texts it actually emits",
              rep["distinct_emitted_texts_with_slash"] == 2, str(rep))
        check("acceptance separates emitted texts from all texts",
              rep["distinct_step_texts"] == 6
              and rep["distinct_emitted_texts"] == 4, str(rep))
        check("acceptance refuses nothing on clean input",
              rep["items_refused"] == 0 and rep["violations"] == [], str(rep))

        # a release item whose closure is missing must stop the acceptance
        with open(cpath2, "w", encoding="utf-8") as fh:
            json.dump([closure], fh)
        check("an item without a closure fails the acceptance",
              _raises(lambda: acceptance(ipath, cpath2), SystemExit))

        # the closure-free run is allowed, and says which source it used
        rep_fb = acceptance(ipath, None)
        check("the closure-free acceptance is labelled as such",
              rep_fb["source"] == "gherkin_fallback"
              and rep_fb["distinct_emitted_texts"] == 6
              and rep_fb["distinct_emitted_texts_with_slash"] == 3,
              str(rep_fb))

        php = shutil.which("php")
        if php:
            # Execute generated PHP: a signature-text assertion would miss
            # both invalid syntax and rejection of transformed arrays.
            _path, code = php_context("multiline", ["one step"])
            generated = os.path.join(d, "stub.php")
            with open(generated, "w", encoding="utf-8") as fh:
                fh.write(code)
            php_code = r"""
namespace Behat\Behat\Context { interface Context {} }
namespace Behat\Gherkin\Node { class TableNode {} class PyStringNode {} }
namespace {
    require %s;
    $context = new \CoreShop\Behat\Context\Domain\Stub%sContext();
    $method = new \ReflectionMethod($context, %s);
    $method->invokeArgs($context, []);
    $method->invokeArgs($context, [new \Behat\Gherkin\Node\TableNode()]);
    $method->invokeArgs($context, [[1 => 'localized value']]);
    $method->invokeArgs($context, [null, new \Behat\Gherkin\Node\PyStringNode()]);
    echo 'passed';
}
""" % (json.dumps(generated), item_key("multiline"),
       json.dumps(method_name("one step", set())))
            cp = subprocess.run([php, "-r", php_code], capture_output=True,
                                text=True, timeout=30)
            check("generated PHP accepts plain, table, transformed-array and docstring calls",
                  cp.returncode == 0 and cp.stdout == "passed", cp.stderr)
        else:
            print("  [SKIP] generated PHP invocation (php is not installed)")

    print("\n" + ("ALL PASS (stub)" if ok else "FAILURES (stub)"))
    return 0 if ok else 1


def _raises(fn, exc=Exception) -> bool:
    try:
        fn()
    except exc:
        return True
    return False


if __name__ == "__main__":
    raise SystemExit(selftest())
