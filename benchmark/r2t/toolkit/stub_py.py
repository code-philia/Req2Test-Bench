"""The vacuous floor of the anti-vacuity gate, for behave (SPEC §3.10).

The twin of `r2t/toolkit/stub.py`, under the same three rules, against a framework
that enforces them differently at every point.

A recall-style metric rewards a submission that *runs* the scenario, and the
cheapest way to run a behave scenario is to define every step it needs with an
empty body: behave then reports every step passed while the submission asserts
nothing at all.  This module builds exactly that submission, so the benchmark
can measure what a maximally vacuous candidate scores instead of assuming it
scores nothing.  As in the PHP twin, "stub = 0 by construction" is an
EXPECTATION and not a proof: the stub replaces only the removable half, while
the retained `features/environment.py` and the recorder still run and can
fail on a mutated production line the empty bodies never observed.  The gate
is honoured only if the MEASURED stub mutation recall is ≤ 0.02.

The three rules, and what each one becomes in behave
----------------------------------------------------
**1. One definition per DISTINCT step, and "distinct" means the PAIR.**  Behat
matches on text alone, so `stub.py` keys on text.  behave's
`StepRegistry.find_step_definition` looks only in `registry.steps[step_type]`
(plus the keyword-agnostic `step` list), so `Given a run` and `Then a run` are
two different questions and a stub that answered only one of them would leave
the other undefined.  The key here is therefore `(effective keyword, text)` —
`effective` because a Gherkin `And` carries no type of its own and behave's
parser resolves it from the previous step (`pystep_index.resolve_block_
keywords`); the closure has already done that resolution.

**2. The pattern is anchored, and behave anchors it.**  `use_step_matcher("re")`
selects `SimplifiedRegexMatcher`, which wraps the pattern in `^…$` ITSELF and
**raises `ValueError` on a pattern that already starts with `^` or ends with
`$`** (verified against behave 1.3.3 in `r2t_docx_img:base`).  So the design
note's `re.escape(text) + "$"` would raise at import for every step — the
pattern here is `re.escape(text)` and nothing else, and the anchoring is
behave's own.  The anchoring is not optional: `RegexMatcher.check_match` calls
`regex.match`, which anchors only at the START, so an unanchored `a run` would
also match `a run with text` and the stub would answer a step it was not
written for.  One consequence has to be handled rather than assumed away: a
step text ENDING in `$` escapes to a pattern ending in `$`, which is the very
shape `SimplifiedRegexMatcher` refuses — so a trailing `\\$` is re-spelled as
the equivalent `\\x24`.  Zero of this corpus's 1159 texts need it; it is here
because the failure mode is an exception at import time for a corpus nobody
has looked at yet, and because the fix is the regex language's own escape and
not a workaround.

**3. A step already answered by RETAINED or PRODUCTION code is not defined
again.**  behave raises `AmbiguousStep` at REGISTRATION when a newly
registered pattern matches an existing pattern's own text within the same
keyword list, so re-defining a surviving step aborts the import — the same
failure `stub.py` describes under a different exception name.  The vocabulary
is `boundary.py`'s, and both `retained` and `production` survive stripping.
On python-docx the rule is inert (all 1856 step occurrences over the 239
criterion items bind to `removable` files); it is implemented because the
inertness is a property of one corpus and the failure would be silent.

Why there is no closure-free fallback
-------------------------------------
`stub.py` can recover a Behat item's steps by parsing `requirement.background`
and `criterion.gherkin` out of the release.  That is IMPOSSIBLE here and the
impossibility is worth stating: `criterion.gherkin` for a Scenario Outline
carries the template steps and **not the Examples table** (checked against
`items.jsonl`: `python-docx/features/txt-font-props.feature:7` is stored as
two lines with `<color>` and `<value>` still in them), while behave runs one
real scenario per data row with the values substituted.  A fallback would
therefore emit `a font having <color> highlighting`, which matches nothing
behave ever asks about, for 124 of the 239 items.  So a closure is REQUIRED
and its absence is a refusal, not a degraded mode.

What behave does not need
-------------------------
No services fragment and no registration: behave imports every `.py` under
`features/steps/` and whatever decorators run register themselves, so
installing the module IS the registration.  No parameters on the stub
functions either — behave hands a table or a docstring to the step through
`context.table` / `context.text` rather than as arguments, so the two optional
typed parameters `stub.py` needs (54 of 422 Behat items would otherwise error)
have no counterpart here.  The signature is `(context)` because the pattern
carries no capture groups: `re.escape` escapes `(`, so a group cannot appear
by accident.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from typing import Optional

from ..bench.runner import item_key
from ..core.paths import CONFIG_DIR

#: Where behave finds step definitions: `<base_dir>/steps`, the directory the
#: boundary calls removable and `pystep_index.steps_dirs_for` names.  A
#: constant rather than a derived path because `stub_solution`'s signature is
#: the stack seam's and carries no repository; the real boundary is checked
#: against it in `selftest`.
STEPS_DIR = "features/steps"

#: Closure step `side` values naming code that SURVIVES stripping, and whose
#: definitions the stub must therefore not duplicate.  `boundary.py`'s
#: vocabulary (`removable | retained | production`, and `None` for a step with
#: no definition at all), not one invented here — the same frozenset
#: `stub.py` uses, for the same reason.
_ALREADY_ANSWERED = frozenset({"retained", "production"})

#: Cap on the derived part of a function name.  Python imposes no limit; a cap
#: keeps the generated module legible and keeps the sha1 suffix at the end of
#: the line rather than pushed off it.
_NAME_CAP = 60

#: Any C0 control character or DEL.  REFUSED rather than stripped: a newline
#: inside a step text would end the decorator's source line, and a carriage
#: return would make the emitted module's line numbering disagree with the
#: location behave reports for the definition.  Zero of the corpus's 1159
#: texts contain one.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


# ----------------------------------------------------------------- the keys
def step_keys(item: dict, closure: Optional[dict]) -> list[tuple[str, str]]:
    """The distinct `(keyword, text)` pairs this item needs defined.

    In first-appearance order, which is the order behave will ask about them,
    so a generated module reads in the order its scenario runs.

    The closure's `keyword` is the EFFECTIVE keyword (`closure_py` writes
    `ref.keyword.title()`) and its `text` is the text AFTER Examples
    substitution — i.e. exactly the question `find_step_definition` will be
    asked.  Neither is re-derived here: `pystep_index` already resolves
    And/But behave's way and substitutes rows `ScenarioOutlineBuilder`'s way,
    and a second implementation of either would be a second source of truth.

    A closure is REQUIRED; see the module docstring for why the Gherkin
    fallback that `stub.py` offers cannot exist here.
    """
    if closure is None:
        raise ValueError(
            f"REFUSED: no closure for {item.get('item_id')!r}. A behave stub "
            f"cannot be built from the item alone: `criterion.gherkin` holds "
            f"an outline's TEMPLATE steps without its Examples table, so half "
            f"this corpus would be stubbed with patterns behave never asks "
            f"about, and no closure means no way to tell a step the retained "
            f"code already answers from one it does not.")
    if closure.get("item_id") not in (None, item.get("item_id")):
        # A closure joined to the wrong item would produce a stub for a
        # different scenario — one that passes or fails for reasons that have
        # nothing to do with the item being scored.
        raise ValueError(f"closure {closure.get('item_id')!r} does not belong "
                         f"to item {item.get('item_id')!r}")

    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for step in closure.get("steps") or []:
        side = step.get("side")
        if side in _ALREADY_ANSWERED:
            continue
        key = (str(step["keyword"]).lower(), step["text"])
        if key[0] not in ("given", "when", "then"):
            # `step` is a DEFINITION keyword, never a Gherkin line's own; a
            # closure carrying one means the keyword resolution upstream
            # produced something behave's parser cannot.
            raise ValueError(f"REFUSED: step keyword {key[0]!r} is not one of "
                             f"given/when/then in {item.get('item_id')!r}")
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


# ---------------------------------------------------------------- the names
def function_name(keyword: str, text: str, taken: set[str]) -> str:
    """A deterministic, unique, legal Python function name for one key.

    The sha1 suffix is UNCONDITIONAL, and it hashes the KEYWORD as well as the
    text.  Both halves matter:

    * unconditional, because a suffix added only on collision would name the
      same step differently depending on which of a colliding pair the
      generator reached first, and the emitted module would then depend on
      iteration order — two runs over one item could differ in bytes, which is
      exactly what the byte-identical-regeneration gate exists to catch;
    * keyword-included, because `Given a run` and `Then a run` are two
      definitions in one module.  Hashing the text alone would give them the
      same name, the second `def` would rebind the first (silently — both
      decorators have already registered, so nothing fails), and the module's
      namespace would then disagree with the registry about what it contains.

    `taken` is a corruption check, not the disambiguator: a name already in it
    means the caller passed one key twice, or two keys collided in the leading
    32 bits of sha1.  Both are refusals, never silent renames.
    """
    words = re.findall(r"[A-Za-z0-9]+", text)
    base = "_".join(w.lower() for w in words)[:_NAME_CAP].rstrip("_")
    digest = hashlib.sha1(f"{keyword}\0{text}".encode("utf-8")).hexdigest()[:8]
    # The keyword leads, so the name always starts with a letter however the
    # text starts, and a reader can see which registry list the definition
    # went into without re-reading the decorator.
    name = f"{keyword}_{base}_{digest}" if base else f"{keyword}_{digest}"
    if name in taken:
        raise ValueError(f"function name {name!r} already taken — duplicate "
                         f"step key or sha1 collision for "
                         f"({keyword!r}, {text!r})")
    taken.add(name)
    return name


# -------------------------------------------------------------- the pattern
def pattern_for(text: str) -> str:
    """The regex `use_step_matcher("re")` will wrap in `^…$`.

    `re.escape` and nothing else — no anchors of our own, because
    `SimplifiedRegexMatcher.__init__` raises `ValueError` on a pattern that
    already carries one, and no hand-rolled escaping, because `re.escape` is
    the language's own answer and was checked to produce byte-identical output
    on the generator's interpreter (3.10) and the image's (3.12) for all 1159
    corpus texts.

    The one repair: a text ending in `$` escapes to `…\\$`, whose last
    character is `$`, which is the shape behave refuses.  `\\x24` is the same
    character class of one literal `$` written so the pattern does not end in
    that byte.  Anything else that could still trip the constraint is REFUSED
    rather than repaired, because a silent repair of a case nobody has seen is
    a guess printed as a fact.
    """
    if not text.strip():
        raise ValueError("REFUSED: empty step text; the anchored pattern "
                         "`^$` would match every empty step in the suite")
    bad = _CONTROL.search(text)
    if bad:
        raise ValueError(
            f"REFUSED: step text carries control character {bad.group(0)!r} "
            f"at offset {bad.start()}, which cannot survive a one-line "
            f"decorator: {text!r}")
    pattern = re.escape(text)
    if pattern.endswith("$"):
        if not pattern.endswith("\\$"):                       # unreachable
            raise ValueError(f"REFUSED: escaped pattern ends in an unescaped "
                             f"`$`: {pattern!r}")
        pattern = pattern[:-2] + "\\x24"
    if pattern.startswith("^") or pattern.endswith("$"):
        raise ValueError(
            f"REFUSED: behave's `re` matcher (SimplifiedRegexMatcher) raises "
            f"ValueError on a pattern carrying its own begin/end markers, and "
            f"this one would: {pattern!r}")
    return pattern


def _literal(value: str) -> str:
    """`value` as a Python string literal, checked by re-reading it.

    `repr` is the only correct escaper for an arbitrary string, and it is
    deterministic given the string, so regeneration stays byte-identical.  The
    round trip is asserted rather than trusted because the whole module is a
    program the benchmark will not read again before behave imports it.
    """
    out = repr(value)
    if ast.literal_eval(out) != value:                        # unreachable
        raise ValueError(f"REFUSED: {value!r} does not round-trip through a "
                         f"Python literal")
    return out


# --------------------------------------------------------------- the module
def module_name(item_id: str) -> str:
    """`stub_<item_key>` — a legal identifier, unique per item.

    `runner.item_key` is the same sha1[:16] the release uses to name gold
    records, so a stub artifact joins to its item by filename and two items can
    never collide on a module name.  The `stub_` prefix is what keeps the name
    from starting with a digit.
    """
    return f"stub_{item_key(item_id)}"


def python_module(item_id: str, keys: list[tuple[str, str]]
                  ) -> tuple[str, str]:
    """`(repo-relative path, module source)` for one item's stub.

    One function per key, every body `pass`.  The emitted source is PARSED
    before it is returned and each decorator's pattern read back out of the
    tree, so "the module is valid Python and carries the patterns it was asked
    for" is a checked property rather than a hope — the half of §3.10's
    acceptance that the PHP twin has to defer to a container, because there is
    no PHP parser on this side.
    """
    path = f"{STEPS_DIR}/{module_name(item_id)}.py"

    seen: set[tuple[str, str]] = set()
    taken: set[str] = set()
    emitted: list[tuple[str, str, str]] = []      # (keyword, name, pattern)
    for keyword, text in keys:
        if (keyword, text) in seen:
            # The caller is expected to have deduplicated (`step_keys` does).
            # Emitting the duplicate would put two identical patterns in one
            # keyword list, which is the case behave's AmbiguousStep exists
            # for, so it is refused where it becomes possible.
            raise ValueError(f"duplicate step key handed to python_module: "
                             f"({keyword!r}, {text!r})")
        seen.add((keyword, text))
        emitted.append((keyword, function_name(keyword, text, taken),
                        pattern_for(text)))

    used = sorted({kw for kw, _n, _p in emitted} | {"use_step_matcher"})
    lines = [
        '"""GENERATED by r2t.toolkit.stub_py (SPEC_C3_PARALLEL §3.10) — the vacuous',
        "floor of the anti-vacuity gate.  Every step this scenario needs and",
        "the retained code does not already define, with an empty body:",
        "behave reports every step passed and nothing is asserted.",
        "",
        f"item: {item_id}",
        '"""',
        f"from behave import {', '.join(used)}",
        "",
        "use_step_matcher(\"re\")",
        "",
    ]
    for keyword, name, pattern in emitted:
        lines += [
            "",
            f"@{keyword}({_literal(pattern)})",
            f"def {name}(context):",
            "    pass",
            "",
        ]
    source = "\n".join(lines)

    read_back = _patterns_in(source)
    if read_back != [(kw, p) for kw, _n, p in emitted]:
        raise ValueError(f"REFUSED: the emitted module does not carry the "
                         f"patterns it was built from: {read_back!r} vs "
                         f"{[(kw, p) for kw, _n, p in emitted]!r}")
    return path, source


def _patterns_in(source: str) -> list[tuple[str, str]]:
    """`(decorator name, pattern)` for every step definition in a module.

    Read out of the AST rather than with a regex, for the reason this whole
    milestone exists: a regex over source lines is what silently dropped a
    step with trailing whitespace in the PHP twin.
    """
    out: list[tuple[str, str]] = []
    for node in ast.parse(source).body:
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) \
                    and dec.args and isinstance(dec.args[0], ast.Constant):
                out.append((dec.func.id, dec.args[0].value))
    return out


# -------------------------------------------------------------- the adapter
def stub_solution(item: dict, closure: Optional[dict]) -> dict:
    """The adapter contract: `{"files": [...], "metadata": {...}}`.

    One file, no registration fragment: installing a module under
    `features/steps/` IS registering it with behave.
    """
    keys = step_keys(item, closure)
    path, code = python_module(item["item_id"], keys)
    return {
        "files": [{"file_path": path, "code": code}],
        "metadata": {"stub": True, "n_steps": len(keys),
                     "closure_available": closure is not None},
    }


def load_closures(path: str) -> dict[str, dict]:
    with open(path, encoding="utf-8") as fh:
        return {c["item_id"]: c for c in json.load(fh)}


def make_stub_adapter(closures_path: str):
    """The `stub` adapter — the control §3.10 requires before publishing
    pass@1."""
    from ..bench.adapters import Adapter

    closures = load_closures(closures_path)

    def run(task: dict) -> dict:
        closure = closures.get(task["item_id"])
        if closure is None:
            return {"files": [], "metadata": {
                "adapter_error": f"no closure for {task['item_id']}: a behave "
                                 f"stub cannot be built without one"}}
        try:
            return stub_solution(task, closure)
        except Exception as e:                                # noqa: BLE001
            return {"files": [], "metadata": {
                "adapter_error": f"{type(e).__name__}: {e}"}}

    return Adapter("stub", run, {"closures": closures_path})


# ------------------------------------------------------------- acceptance
def _load_jsonl(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def acceptance(items_path: str, closures_path: str,
               project: Optional[str] = None,
               task: str = "criterion_to_test") -> dict:
    """Generate for every item and check everything that needs no container.

    The other half — that behave's own registry loads the module, registers
    every step and raises no `AmbiguousStep` — needs the image and is
    `py/stub_accept.py`, whose only driver, `scripts/gate_s5_vacuity.py`, now
    refuses for every stack before any Docker contact — so nothing has run
    that half since (`CONTAINER_HALF_NOTE`).  This half is
    the part that must hold for a corpus rather than for a run: byte-identical
    output on repetition, distinct patterns within an item, distinct paths and
    module names across items, and a RECOMPUTATION of the multiplicity census
    the design rests on, so that a corpus change which invalidates it is
    caught here rather than in a container log.

    Raises `SystemExit` on any violation; returns the report otherwise.
    """
    items = [i for i in _load_jsonl(items_path)
             if (project is None or i.get("project") == project)
             and (task is None or i.get("task") == task)]
    closures = load_closures(closures_path)

    violations: list[str] = []
    refused: list[dict] = []
    paths: dict[str, str] = {}
    n_functions = 0
    missing_closure: list[str] = []
    # The P1 census: how many items share a step key.  Over the keys the stub
    # ACTUALLY emits, because those are the ones that would collide.
    items_per_key: dict[tuple[str, str], int] = {}
    dup_within_item = 0

    for item in items:
        iid = item["item_id"]
        closure = closures.get(iid)
        if closure is None:
            missing_closure.append(iid)
            continue

        occurrences = [(str(s["keyword"]).lower(), s["text"])
                       for s in closure.get("steps") or []
                       if s.get("side") not in _ALREADY_ANSWERED]
        if len(occurrences) != len(set(occurrences)):
            dup_within_item += 1

        # `step_keys` is inside the try with the generation it feeds: a
        # closure missing a `keyword` or carrying a control character is a
        # corrupt artifact, and an acceptance that named the item is worth
        # more than a traceback that names the line.
        try:
            keys = step_keys(item, closure)
            path, code = python_module(iid, keys)
            path2, code2 = python_module(iid, keys)
        except Exception as e:                                # noqa: BLE001
            refused.append({"item_id": iid, "why": f"{type(e).__name__}: {e}"})
            continue
        for key in keys:
            items_per_key[key] = items_per_key.get(key, 0) + 1

        if (path, code) != (path2, code2):
            violations.append(f"{iid}: regenerating changed the output")
        if path in paths and paths[path] != iid:
            violations.append(f"{path}: emitted for both {paths[path]} "
                              f"and {iid}")
        paths[path] = iid

        patterns = _patterns_in(code)
        if len(patterns) != len(set(patterns)):
            violations.append(
                f"{iid}: two definitions share a (keyword, pattern) "
                f"({len(patterns)} emitted, {len(set(patterns))} distinct) — "
                f"behave's AmbiguousStep")
        if len(patterns) != len(keys):
            violations.append(f"{iid}: {len(keys)} keys but "
                              f"{len(patterns)} definitions")
        n_functions += len(patterns)

    if missing_closure:
        violations.append(
            f"{len(missing_closure)} item(s) have no closure "
            f"(e.g. {missing_closure[0]}); a behave stub cannot be built "
            f"without one")
    if refused:
        violations.append(f"{len(refused)} item(s) refused: {refused[:3]}")

    shared = {k: n for k, n in items_per_key.items() if n > 1}
    top = max(items_per_key.items(), key=lambda kv: (kv[1], kv[0]),
              default=(("", ""), 0))
    report = {
        "items": len(items),
        "functions_emitted": n_functions,
        "items_refused": len(refused),
        "refusals": refused,
        "closures": closures_path,
        # The multiplicity the ISOLATED-import design rests on.  A corpus in
        # which no key were shared would not need it, so the number is
        # recomputed rather than cited.
        "distinct_step_keys": len(items_per_key),
        "keys_in_more_than_one_item": len(shared),
        "max_items_sharing_a_key": top[1],
        "most_shared_key": list(top[0]),
        "items_with_duplicate_step_key": dup_within_item,
        "violations": violations,
    }
    if violations:
        raise SystemExit("REFUSED: stub acceptance failed:\n  "
                         + "\n  ".join(violations))
    return report


# ---------------------------------------------------------------- the CLI verb
#: The behave twin of `stub_java.CONTAINER_HALF_NOTE`: one operator-facing
#: sentence about the half this module does not do.
#:
#: This sentence WAS TRUE when it was written — `py/stub_accept.py` is the
#: in-container half and `scripts/gate_s5_vacuity.py` drove it — and the gate
#: was closed for every stack afterwards, which is exactly why it is a
#: constant now rather than a literal inside the `print`.  A statement about
#: another file's state with nothing holding it to that state goes stale the
#: next time the other file moves, and nobody reading this one finds out.
#: `stub_java.selftest` checks BOTH twins' notes against the gate's own
#: bytes; the reading lives there because a second implementation of "is the
#: S5 live gate closed?" would be a second answer to one question.
CONTAINER_HALF_NOTE = (
    "NOTE: this is the corpus half, and today it is the only half that runs. "
    "That every module IMPORTS, that every step RESOLVES through behave's "
    "registry and that no item raises AmbiguousStep is NOT checked by any "
    "program yet: benchmark/r2t/py/stub_accept.py would do it in the image, "
    "but the only thing that drives it -- benchmark/scripts/gate_s5_vacuity.py "
    "-- refuses before any Docker contact for every stack (no reviewed gate "
    "workload binding, benchmark/J0_DOCKER_AUTHORITY_AMENDMENT.md). The live "
    "arm returns with that binding; until then nothing has imported these "
    "modules into behave's registry."
)


def cmd_stub_accept(args) -> int:
    """`r2t stub-accept --profile config/profile_python_docx.yml`

    The behave arm of `cli.cmd_stub_accept`, reached through
    `cli._other_stack`.  The corpus half only — the container half needs the
    image and a step directory it may empty between items, and NOTHING RUNS
    IT TODAY: `scripts/gate_s5_vacuity.py`, the only driver of
    `py/stub_accept.py`, refuses for every stack before any Docker contact
    (see `CONTAINER_HALF_NOTE`).  Said here rather than left implied: an
    operator who read this verb's output as "the stubs are accepted" would be
    reading a claim about VALID PYTHON as a claim about behave.
    """
    from ..core.boundary import load_boundary
    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    closures = args.closures or os.path.join(args.artifacts, "closures.json")
    info = acceptance(args.release, closures, project=b.project)
    print(json.dumps(info, indent=1))
    print(CONTAINER_HALF_NOTE)
    return 0


# ----------------------------------------------------------------- selftest
def selftest() -> int:                                        # noqa: C901
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def raises(fn, needle="") -> bool:
        # `SystemExit` is a BaseException, and `acceptance` raises it: a
        # helper that caught only `Exception` would let the refusal escape
        # the selftest and be read as a crash rather than as the check
        # passing.
        try:
            fn()
        except (Exception, SystemExit) as e:                  # noqa: BLE001
            return needle in str(e)
        return False

    # -- the keys ----------------------------------------------------------
    item = {"item_id": "python-docx/features/f.feature:7"}
    closure = {"item_id": item["item_id"], "steps": [
        {"keyword": "Given", "text": "a blank document", "side": "removable"},
        {"keyword": "When", "text": "I add a run", "side": "removable"},
        {"keyword": "Then", "text": "a run", "side": "removable"},
        {"keyword": "Given", "text": "a run", "side": "removable"},
        {"keyword": "Given", "text": "a blank document", "side": "removable"},
    ]}
    keys = step_keys(item, closure)
    check("the key is the PAIR, so one text under two keywords is two "
          "definitions",
          keys == [("given", "a blank document"), ("when", "I add a run"),
                   ("then", "a run"), ("given", "a run")], str(keys))
    check("a repeated pair collapses to one entry",
          len(keys) == 4 and len(set(keys)) == 4)
    check("a step answered by RETAINED code is not redefined -- behave's "
          "AmbiguousStep fires at registration",
          step_keys(item, dict(closure, steps=[
              dict(closure["steps"][0], side="retained")])) == [])
    check("...and PRODUCTION code survives stripping in exactly the same way",
          step_keys(item, dict(closure, steps=[
              dict(closure["steps"][0], side="production")])) == [])
    check("a step with NO definition at all is still stubbed: side None is "
          "not 'already answered'",
          step_keys(item, dict(closure, steps=[
              dict(closure["steps"][0], side=None)]))
          == [("given", "a blank document")])
    check("a closure from another item is REFUSED",
          raises(lambda: step_keys(item, dict(closure, item_id="other")),
                 "does not belong"))
    check("NO closure is a refusal, not a Gherkin fallback -- an outline's "
          "Examples table is not in the item",
          raises(lambda: step_keys(item, None), "REFUSED"))
    check("a keyword behave's parser cannot produce is refused",
          raises(lambda: step_keys(item, dict(closure, steps=[
              {"keyword": "And", "text": "x", "side": "removable"}])),
                 "not one of given/when/then"))

    # -- names -------------------------------------------------------------
    n_given = function_name("given", "a run", set())
    n_then = function_name("then", "a run", set())
    check("the same text under two keywords gets two names -- hashing the "
          "text alone would silently rebind one def onto the other",
          n_given != n_then and n_given.startswith("given_")
          and n_then.startswith("then_"), f"{n_given} {n_then}")
    check("a name is a pure function of its key, so insertion order cannot "
          "move it",
          function_name("given", "a run", set()) == n_given)
    check("every name is a legal Python identifier",
          all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function_name(k, t, set()))
              for k, t in [("given", "42 things"), ("when", "/"),
                           ("then", "a $ b"), ("given", "  x  ")]))
    long_a = "the quantity of the product named " + "x" * 200 + " is one"
    long_b = "the quantity of the product named " + "x" * 200 + " is two"
    na, nb = function_name("given", long_a, set()), \
        function_name("given", long_b, set())
    check("a very long text is capped and still unique",
          len(na) <= len("given_") + _NAME_CAP + 9 and na != nb
          and na.rsplit("_", 1)[0] == nb.rsplit("_", 1)[0], f"{len(na)} {na}")
    check("a text with no alphanumerics still yields a legal name",
          function_name("given", "/", set()) == "given_"
          + hashlib.sha1(b"given\0/").hexdigest()[:8],
          function_name("given", "/", set()))
    check("a name reused inside one module is REFUSED, never silently renamed",
          raises(lambda: function_name("given", "a run",
                                       {function_name("given", "a run", set())}),
                 "already taken"))

    # -- patterns ----------------------------------------------------------
    check("the pattern carries NO anchors of its own: behave's `re` matcher "
          "adds `^...$` and raises ValueError on a pattern that has them",
          pattern_for("a run") == re.escape("a run")
          and not pattern_for("a run").startswith("^")
          and not pattern_for("a run").endswith("$"))
    check("a regex metacharacter in a step text is escaped, so `document.add "
          "()` cannot become a wildcard",
          pattern_for("I call docx.Document() with a path")
          == r"I\ call\ docx\.Document\(\)\ with\ a\ path",
          pattern_for("I call docx.Document() with a path"))
    check("a text ending in `$` becomes a pattern that does NOT end in `$` -- "
          "the one shape SimplifiedRegexMatcher refuses",
          pattern_for("it costs 5$").endswith("\\x24")
          and not pattern_for("it costs 5$").endswith("$"),
          pattern_for("it costs 5$"))
    check("...and that pattern still matches the text exactly, and nothing "
          "longer -- anchored the way behave anchors it",
          re.match("^" + pattern_for("it costs 5$") + "$", "it costs 5$")
          and not re.match("^" + pattern_for("it costs 5$") + "$",
                           "it costs 5$ more"))
    check("a text starting with `^` is escaped, not anchored",
          re.match("^" + pattern_for("^caret") + "$", "^caret")
          and not pattern_for("^caret").startswith("^"))
    for bad, why in [("two\nlines", "newline"), ("two\rlines", "carriage "
                                                 "return"), ("a\tb", "tab")]:
        check(f"a {why} in a step text is REFUSED",
              raises(lambda b=bad: pattern_for(b), "control character"))
    check("an empty step text is REFUSED", raises(lambda: pattern_for("   "),
                                                  "REFUSED"))

    # The defect this milestone exists not to repeat.  `stub.py`'s step-line
    # regex ends `(.*\S)$`, so a Gherkin line with TRAILING WHITESPACE matches
    # nothing and the step is silently dropped.  The bytes below are
    # `features/txt-font-props.feature:8` of the pinned corpus, trailing space
    # and all — the one real occurrence, and the reason the census of
    # `(keyword, text)` pairs differs by one between a regex reader and behave.
    live = "    Given a font having <color> highlighting "
    defect = re.compile(r"^\s*(Given|When|Then|And|But|\*)\s+(.*\S)$")
    check("a `(.*\\S)$`-shaped step-line regex DROPS the corpus's one "
          "trailing-whitespace step -- the defect class, demonstrated",
          defect.match(live) is None, repr(live))
    check("...and this module reads no step lines at all: its keys come from "
          "the closure, i.e. from behave's own parse",
          "Given|When|Then" not in open(__file__.replace(".pyc", ".py"),
                                        encoding="utf-8").read()
          .split("selftest")[0])
    # What the closure carries for that step, and what the stub does with it:
    # behave strips a step name after its keyword (`line[len(kw):].strip()`),
    # so the trailing space is not part of the name and the substituted text
    # is what gets keyed.
    ws_item = {"item_id": "python-docx/features/txt-font-props.feature:7"}
    ws_closure = {"item_id": ws_item["item_id"], "steps": [
        {"keyword": "Given", "text": "a font having no highlighting",
         "side": "removable", "example_line": 13},
        {"keyword": "Then", "text": "font.highlight_color is None",
         "side": "removable", "example_line": 13}]}
    ws_path, ws_code = python_module(ws_item["item_id"],
                                     step_keys(ws_item, ws_closure))
    check("the trailing-whitespace step IS keyed and IS stubbed",
          ("given", r"a\ font\ having\ no\ highlighting")
          in _patterns_in(ws_code), ws_code)

    # -- the module --------------------------------------------------------
    path, code = python_module(item["item_id"], keys)
    check("the path is under behave's step directory and named for the item",
          path == f"{STEPS_DIR}/{module_name(item['item_id'])}.py"
          and item_key(item["item_id"]) in path, path)
    check("two items never share a module path or a module name",
          python_module("a", keys)[0] != python_module("b", keys)[0]
          and module_name("a") != module_name("b"))
    check("the module switches to the `re` matcher BEFORE any decorator runs",
          code.index('use_step_matcher("re")') < code.index("@given"))
    bodies = [n.body for n in ast.parse(code).body
              if isinstance(n, ast.FunctionDef)]
    check("exactly one function per key, and every body is EXACTLY `pass` -- "
          "read off the tree, so a body that asserted anything would fail "
          "here rather than quietly raise the floor",
          len(_patterns_in(code)) == 4 and len(bodies) == 4
          and all(len(b) == 1 and isinstance(b[0], ast.Pass) for b in bodies),
          code)
    check("the decorator is the step's OWN keyword, because behave matches "
          "per keyword",
          [kw for kw, _p in _patterns_in(code)]
          == ["given", "when", "then", "given"], str(_patterns_in(code)))
    check("only the decorators the module uses are imported",
          "from behave import given, then, use_step_matcher, when" in code,
          code.splitlines()[7])
    check("the emitted module is valid Python -- checked by parsing it, which "
          "is the half of §3.10's acceptance the PHP twin cannot do host-side",
          isinstance(ast.parse(code), ast.Module))
    check("regeneration is byte-identical",
          python_module(item["item_id"], keys) == (path, code))
    check("a duplicate key handed to python_module is REFUSED",
          raises(lambda: python_module("i", [("given", "x"), ("given", "x")]),
                 "duplicate step key"))
    check("an item whose steps are ALL retained yields a legal empty module",
          "def " not in python_module("i", [])[1]
          and isinstance(ast.parse(python_module("i", [])[1]), ast.Module))

    # A backslash and a quote in one text: `repr` is the only escaper that
    # gets both right, and 54 of the corpus's texts carry a backslash.
    tricky = [("given", "a path 'c:\\x' and \"y\""),
              ("then", "value is '\\n' literally")]
    _p, tricky_code = python_module("t", tricky)
    check("a backslash and both quote characters survive into the module and "
          "read back identically",
          _patterns_in(tricky_code)
          == [(kw, pattern_for(t)) for kw, t in tricky], tricky_code)
    check("...and the pattern read back still matches its own text",
          all(re.match("^" + p + "$", t)
              for (_kw, p), (_k2, t) in zip(_patterns_in(tricky_code), tricky)))

    # -- solution + adapter ------------------------------------------------
    sol = stub_solution(item, closure)
    check("the solution is exactly one file and no registration fragment",
          len(sol["files"]) == 1
          and sol["files"][0]["file_path"].startswith(STEPS_DIR + "/"),
          str([f["file_path"] for f in sol["files"]]))
    check("metadata records n_steps and closure availability",
          sol["metadata"] == {"stub": True, "n_steps": 4,
                              "closure_available": True}, str(sol["metadata"]))

    with tempfile.TemporaryDirectory() as d:
        cpath = os.path.join(d, "closures.json")
        with open(cpath, "w", encoding="utf-8") as fh:
            json.dump([closure], fh)
        adapter = make_stub_adapter(cpath)
        check("the adapter is named stub", adapter.name == "stub", adapter.name)
        good = adapter(dict(item))
        check("an item with a closure produces one file",
              len(good["files"]) == 1 and good["metadata"]["n_steps"] == 4)
        missing = adapter({"item_id": "nope"})
        check("an item with no closure is an explicit metadata error, never a "
              "silent fallback",
              missing["files"] == []
              and "no closure" in missing["metadata"]["adapter_error"],
              str(missing["metadata"]))

        # -- acceptance over a hand-written two-item corpus ----------------
        #
        # The two items SHARE `Given a blank document`, which is the whole
        # point: the census must report the sharing, because the isolated
        # install/import cycle exists for it.
        item2 = {"item_id": "python-docx/features/g.feature:3",
                 "project": "python-docx", "task": "criterion_to_test"}
        closure2 = {"item_id": item2["item_id"], "steps": [
            {"keyword": "Given", "text": "a blank document",
             "side": "removable"},
            {"keyword": "Then", "text": "it has 1 paragraph",
             "side": "retained"}]}
        it1 = dict(item, project="python-docx", task="criterion_to_test")
        ipath = os.path.join(d, "items.jsonl")
        with open(ipath, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(it1) + "\n")
            fh.write(json.dumps(item2) + "\n")
            fh.write(json.dumps({"item_id": "other/x:1", "project": "other",
                                 "task": "criterion_to_test"}) + "\n")
        cpath2 = os.path.join(d, "closures2.json")
        with open(cpath2, "w", encoding="utf-8") as fh:
            json.dump([closure, closure2], fh)

        rep = acceptance(ipath, cpath2, project="python-docx")
        check("acceptance counts only the project's items, and the functions "
              "they emit",
              rep["items"] == 2 and rep["functions_emitted"] == 5, str(rep))
        check("the retained step is excluded from the emitted count",
              rep["distinct_step_keys"] == 4, str(rep))
        check("acceptance RECOMPUTES the multiplicity census the isolated "
              "import cycle rests on",
              rep["keys_in_more_than_one_item"] == 1
              and rep["max_items_sharing_a_key"] == 2
              and rep["most_shared_key"] == ["given", "a blank document"],
              str(rep))
        check("acceptance refuses nothing on clean input",
              rep["items_refused"] == 0 and rep["violations"] == [])
        with open(cpath2, "w", encoding="utf-8") as fh:
            json.dump([closure], fh)
        check("an item without a closure FAILS the acceptance",
              raises(lambda: acceptance(ipath, cpath2, project="python-docx"),
                     "no closure"))
        # A corrupt closure names its item rather than raising through the
        # gate: `step_keys` is inside the same try as the generation.
        with open(cpath2, "w", encoding="utf-8") as fh:
            json.dump([closure, dict(closure2, item_id=item2["item_id"],
                                     steps=[{"keyword": "Given",
                                             "text": "two\nlines",
                                             "side": "removable"}])], fh)
        check("a closure carrying an impossible step text is REFUSED with the "
              "ITEM named, not a traceback",
              raises(lambda: acceptance(ipath, cpath2, project="python-docx"),
                     "item(s) refused"))

    # -- the container half is behave's own loader, not a re-implementation -
    #
    # The `match_steps.php:2-19` rule, inherited: the program that decides
    # whether a stub registered must go through behave, and must not compile a
    # pattern of its own.  Checked against its bytes rather than restated,
    # exactly as `pystep_index.selftest` checks the matcher's.
    accept_src_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                   "py", "stub_accept.py")
    with open(accept_src_path, encoding="utf-8") as fh:
        accept_src = fh.read()
    for needle in ("load_step_modules", "registry.find_step_definition",
                   "registry.clear()", "AmbiguousStep"):
        check(f"the in-container acceptance goes through behave's own "
              f"`{needle}`", needle in accept_src)
    check("...and compiles no regex of its own -- behave's matcher is the "
          "only thing that decides what a stub answers",
          "re.compile" not in accept_src
          and not any(ln.strip() in ("import re", "import re as re")
                      for ln in accept_src.splitlines()),
          [ln for ln in accept_src.splitlines() if "re.compile" in ln])
    check("it clears the registry AND the step directory per item: either one "
          "alone is not isolation",
          "shutil.rmtree(steps_dir)" in accept_src
          and accept_src.index("shutil.rmtree(steps_dir)")
          < accept_src.index("registry.clear()"))

    # -- the seam this milestone lands ------------------------------------
    import argparse

    from ..bench import cli as _cli
    from ..stacks import behave as _behave
    check("the behave stack exposes stub_solution, and it IS this function",
          getattr(_behave, "stub_solution", None) is stub_solution)
    check("...and it is no longer listed as pending",
          "stub_solution" not in _behave.PENDING)
    profile = os.path.join(CONFIG_DIR, "profile_python_docx.yml")
    if os.path.isfile(profile):
        check("the real python-docx profile routes `stub-accept` to THIS "
              "stack",
              _cli._other_stack(argparse.Namespace(profile=profile),
                                "cmd_stub_accept") is cmd_stub_accept)
    check("an invocation with no --profile still takes the behat path, so "
          "every CoreShop runbook is unchanged",
          _cli._other_stack(argparse.Namespace(), "cmd_stub_accept") is None)

    # The FIXTURE dispatch, which is the one that would fail silently: a PHP
    # context class installed into a behave workspace defines nothing, so
    # every step comes out `undefined` and the measured floor reads 0.00 for
    # a reason that is not vacuity.
    from . import stub as _php_stub
    from ..bench import fixtures as _fixtures
    from ..bench.fixtures import _stub_maker
    if os.path.isfile(profile):
        check("a run carrying the python-docx profile builds THIS stub "
              "adapter, and behave is NOT one of the frameworks whose "
              "factory is handed a corpus -- this closure carries the shape "
              "already, so its factory keeps the one argument it had",
              _stub_maker(argparse.Namespace(profile=profile))
              == (make_stub_adapter, "behave")
              and "behave" not in _fixtures._STUB_NEEDS_CORPUS)
    check("...and a run with no profile still builds the PHP one -- every "
          "archived CoreShop stub sweep is one of those",
          _stub_maker(argparse.Namespace())
          == (_php_stub.make_stub_adapter, "behat")
          and _stub_maker(argparse.Namespace(profile=None))
          == (_php_stub.make_stub_adapter, "behat"))

    config = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "..", "config", "boundary_python_docx.yml")
    if os.path.isfile(config):
        from ..core.boundary import load_boundary
        b = load_boundary(config)
        stub_path = python_module("python-docx/features/f.feature:7", keys)[0]
        check("the stub is written where the boundary says the ANSWER lives, "
              "so installing it is legal and stripping removes it",
              b.classify(stub_path) == "removable", f"{stub_path} -> "
              f"{b.classify(stub_path)}")
        check("...and not into the retained fixture carve-out",
              b.classify(f"{STEPS_DIR}/test_files/x.docx") == "retained")
    else:
        print(f"  [SKIP] no {config}, so the step directory could not be "
              f"checked against the real boundary")

    print("\n" + ("ALL PASS (stub_py)" if ok else "FAILURES (stub_py)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
