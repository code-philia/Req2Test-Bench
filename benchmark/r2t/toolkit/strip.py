"""Assertion-stripped reference solutions for the PHP/Behat stack.

The hard-subset screen is deliberately candidate-blind.  It starts from the
reference closure, preserves every setup/action definition used by Given and
When, and empties only definitions used exclusively by effective Then steps.
The closure is the authority for those effective keywords; re-parsing the
feature here would duplicate And/But resolution and outline expansion.

TWO PRODUCERS ANSWER THAT AUTHORITY DIFFERENTLY, and `definition_roles`
takes a flag rather than guessing which one wrote a document.  behave's
closures arrive already resolved (`pystep_index`: "It resolves And/But/`*`
to a CONCRETE keyword") and Behat's registry keys on the pattern, so for
both of those an unresolved keyword is a defect and stays a refusal.
cucumber's closures record the keyword AS WRITTEN, deliberately, because a
cucumber expression is keyword-agnostic — so `strip_java` opts in to
`resolve_inherited=True` and the resolution runs over the closure's own
ordered steps.  It is still not a re-parse: the steps, their order, their
blocks and their bound definitions all come from the closure.

A definition used by both setup/action and assertion steps is *shared*.  It
cannot be emptied without also deleting setup, and leaving it intact would
silently retain an assertion.  Such an item is refused and later appears in
the stripped-baseline fidelity accounting rather than being mislabelled as a
successful screen.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Optional


class StripRefused(ValueError):
    """The reference cannot be assertion-stripped without changing setup."""


_SURVIVING_SIDES = frozenset({"retained", "production"})

#: The three keywords that carry their own role.  A closure step spelled with
#: one of these needs no resolution, whichever producer wrote it.
CONCRETE_KEYWORDS = ("given", "when", "then")

#: The keywords that carry NO role of their own and inherit the nearest
#: preceding concrete one.  Spelled exactly as `gherkin._INHERITING` spells
#: them, lowercased, because that reader is the one this benchmark trusts to
#: say what Gherkin means.
INHERITING_KEYWORDS = frozenset({"and", "but", "*"})

#: The fields that identify WHICH block of a feature a closure step came
#: from.  Inheritance does not cross a Background/Scenario boundary and does
#: not cross an Examples row, because neither is a place a Gherkin reader
#: would carry a keyword across: each is a fresh step list.  A producer whose
#: closure carries none of these leaves the tuple constant, and the rule
#: degenerates to "one block", which is what a single-block closure is.
_BLOCK_FIELDS = ("origin", "example_line", "example_row")


def _block_of(step: dict) -> tuple:
    return tuple(step.get(field) for field in _BLOCK_FIELDS)


def effective_keywords(steps: list) -> list[str]:
    """The role of each step, with And/But/`*` resolved, in order.

    THE RULE IS CUCUMBER'S OWN, and it is the rule `gherkin._parse_steps`
    applies to feature bytes: an inheriting keyword takes the nearest
    preceding concrete keyword of its own block.  It is applied to the
    CLOSURE's ordered steps rather than to the feature file because the
    closure is the authority for outline expansion and for which definition
    each step bound to, and re-parsing here would be a second answer to a
    question the closure already answered.

    A block whose FIRST step is inheriting is REFUSED rather than seeded with
    a default.  `gherkin._parse_steps` seeds `last_concrete = "Given"` for
    exactly that case; doing the same here would silently label an assertion
    as setup, which is the one error the hard-subset screen cannot survive —
    it decides whether a definition is emptied.  That shape is a corrupt
    closure, not a scenario anybody wrote.
    """
    resolved: list[str] = []
    carried: Optional[str] = None
    block: Optional[tuple] = None
    for step in steps:
        if not isinstance(step, dict):
            raise StripRefused(
                f"REFUSED: closure step is not an object: {step!r}.")
        here = _block_of(step)
        if here != block:
            block, carried = here, None
        keyword = str(step.get("keyword") or "").strip().lower()
        if keyword in CONCRETE_KEYWORDS:
            carried = keyword
        elif keyword in INHERITING_KEYWORDS:
            if carried is None:
                raise StripRefused(
                    f"REFUSED: closure step {step.get('text')!r} opens its "
                    f"block with the inheriting keyword "
                    f"{step.get('keyword')!r}, which has no preceding "
                    f"concrete keyword to take. No Gherkin reader can resolve "
                    f"that shape and this screen will not guess one.")
        else:
            raise StripRefused(
                f"REFUSED: closure carries unsupported keyword "
                f"{step.get('keyword')!r}; expected one of "
                f"{sorted(CONCRETE_KEYWORDS)} or "
                f"{sorted(INHERITING_KEYWORDS)}.")
        resolved.append(carried)
    return resolved


def _definition_key(step: dict) -> tuple[str, str, str]:
    definition = step.get("definition")
    if not isinstance(definition, dict):
        raise StripRefused(
            f"REFUSED: {step.get('keyword')} step {step.get('text')!r} has no "
            "bound definition; an unmatched assertion cannot be stripped.")
    values = (definition.get("file"), definition.get("class"),
              definition.get("method"))
    if not all(isinstance(value, str) and value for value in values):
        raise StripRefused(
            f"REFUSED: malformed definition identity for step "
            f"{step.get('text')!r}: {definition!r}.")
    return values


def definition_roles(closure: dict, *, resolve_inherited: bool = False) \
        -> dict[tuple[str, str, str], set[str]]:
    """Definition identity -> effective Gherkin roles used by this item.

    `resolve_inherited` is OFF by default, and that default is the contract
    rather than a convenience.  A producer that already resolves And/But/`*`
    before it writes the closure — `pystep_index` does it for behave, and
    Behat's registry keys on the pattern — hands this function concrete
    keywords, and an unresolved one from such a producer is a defect that
    must still be refused.  Only a producer that deliberately records the
    keyword AS WRITTEN opts in, which today is the cucumber closure builder
    (`java/closure_java.py`, whose `kind` is "the Gherkin keyword as
    written, which is decoration for cucumber").  The two paths therefore
    take the same function and neither can silently become the other.
    """
    if not isinstance(closure, dict):
        raise StripRefused("REFUSED: stripped gold requires a closure object.")
    steps = list(closure.get("steps") or [])
    keywords = (effective_keywords(steps) if resolve_inherited
                else [str(step.get("keyword") or "").lower()
                      for step in steps])
    roles: dict[tuple[str, str, str], set[str]] = {}
    for step, keyword in zip(steps, keywords):
        if keyword not in CONCRETE_KEYWORDS:
            raise StripRefused(
                f"REFUSED: closure carries unsupported effective keyword "
                f"{step.get('keyword')!r}; expected Given/When/Then.")
        key = _definition_key(step)
        roles.setdefault(key, set()).add(keyword)
    return roles


def then_definitions(closure: dict, *, resolve_inherited: bool = False) \
        -> list[tuple[str, str, str]]:
    """Canonical list of removable definitions used exclusively by Then."""
    roles = definition_roles(closure, resolve_inherited=resolve_inherited)
    shared = sorted(key for key, value in roles.items()
                    if "then" in value and value != {"then"})
    if shared:
        detail = [
            {"file": key[0], "class": key[1], "method": key[2],
             "roles": sorted(roles[key])}
            for key in shared
        ]
        raise StripRefused(
            "REFUSED: assertion definition(s) are shared with Given/When; "
            f"emptying them would delete setup/action: {detail!r}.")

    selected = sorted(key for key, value in roles.items()
                      if value == {"then"})
    if not selected:
        raise StripRefused(
            "REFUSED: closure has no Then-only definition to strip; this item "
            "cannot contribute an assertion-screened mutant.")

    steps_by_key: dict[tuple[str, str, str], list[dict]] = {}
    for step in closure.get("steps") or []:
        steps_by_key.setdefault(_definition_key(step), []).append(step)
    surviving = [key for key in selected
                 if any(step.get("side") in _SURVIVING_SIDES
                        for step in steps_by_key[key])]
    if surviving:
        raise StripRefused(
            "REFUSED: Then definition(s) live in retained/production code and "
            f"cannot be replaced by a removable solution: {surviving!r}.")
    unknown_sides = [
        {"definition": key, "sides": sorted({str(step.get("side"))
                                              for step in steps_by_key[key]})}
        for key in selected
        if any(step.get("side") != "removable" for step in steps_by_key[key])
    ]
    if unknown_sides:
        raise StripRefused(
            "REFUSED: Then-only definition side must be exactly 'removable'; "
            f"the closure carries unsupported/mixed sides: {unknown_sides!r}.")
    return selected


def _skip_php_atom(source: str, index: int) -> int:
    """Return the first index after a quoted string or comment at *index*."""
    n = len(source)
    if source.startswith("//", index) or source.startswith("#", index):
        end = source.find("\n", index)
        return n if end < 0 else end + 1
    if source.startswith("/*", index):
        end = source.find("*/", index + 2)
        if end < 0:
            raise StripRefused("REFUSED: unterminated PHP block comment.")
        return end + 2
    quote = source[index]
    if quote not in "'\"`":
        return index + 1
    index += 1
    while index < n:
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == quote:
            return index + 1
        index += 1
    raise StripRefused("REFUSED: unterminated PHP string literal.")


def _matching_brace(source: str, opening: int) -> int:
    depth = 0
    index = opening
    while index < len(source):
        if source.startswith(("//", "/*"), index) \
                or source[index] in "#'\"`":
            index = _skip_php_atom(source, index)
            continue
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise StripRefused("REFUSED: PHP method body has no matching closing brace.")


def _method_span(source: str, method: str) -> tuple[int, int, str]:
    """Interior span and indentation for exactly one named PHP method."""
    pattern = re.compile(
        r"\bfunction\s+&?\s*" + re.escape(method) + r"\s*\(",
        re.IGNORECASE)
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        raise StripRefused(
            f"REFUSED: expected exactly one PHP method {method!r}, found "
            f"{len(matches)}.")
    index = matches[0].end() - 1
    parens = 0
    while index < len(source):
        if source.startswith(("//", "/*"), index) \
                or source[index] in "#'\"`":
            index = _skip_php_atom(source, index)
            continue
        char = source[index]
        if char == "(":
            parens += 1
        elif char == ")":
            parens -= 1
        elif char == "{" and parens == 0:
            closing = _matching_brace(source, index)
            line_start = source.rfind("\n", 0, index) + 1
            indent = re.match(r"[ \t]*", source[line_start:index]).group(0)
            return index + 1, closing, indent
        elif char == ";" and parens == 0:
            raise StripRefused(
                f"REFUSED: {method!r} is abstract and has no body to strip.")
        index += 1
    raise StripRefused(f"REFUSED: cannot locate body of PHP method {method!r}.")


def strip_php_source(source: str, methods: list[str]) -> str:
    """Empty the named PHP method bodies, preserving every other byte."""
    spans = []
    for method in sorted(set(methods)):
        start, end, indent = _method_span(source, method)
        spans.append((start, end, "\n" + indent))
    for start, end, replacement in sorted(spans, reverse=True):
        source = source[:start] + replacement + source[end:]
    return source


def _services_file(fragment: dict) -> Optional[dict]:
    if not fragment:
        return None
    services = {}
    for sid, body in fragment.items():
        entry = {"class": body["class"]}
        if body.get("arguments"):
            entry["arguments"] = body["arguments"]
        if body.get("tags"):
            entry["tags"] = body["tags"]
        services[sid] = entry
    import yaml
    return {"file_path": "behat_services.yml",
            "code": yaml.safe_dump({"services": services}, sort_keys=False)}


# SYLIUS319_STRIPPED_CART_STATE_AMENDMENT: only these six derived controls
# retain the original data dependency after removing its count/name checks.
SYLIUS_CART_ITEMS = frozenset(
    "sylius/features/shop/cart/shopping_cart/" + suffix for suffix in (
        "adding_product_to_cart.feature:13",
        *(f"maintaining_cart_after_authorization.feature:{line}"
          for line in (14, 22, 32, 44, 56))))
_SYLIUS_CART_TARGET = (
    "src/Sylius/Behat/Context/Api/Shop/CartContext.php",
    "Sylius\\Behat\\Context\\Api\\Shop\\CartContext",
    "thereShouldBeOneItemInMyCart")
_SYLIUS_CART_ORIGINAL = """
        $response = $this->shopClient->getLastResponse();
        $items = $this->responseChecker->getValue($response, 'items');

        Assert::count($items, 1);

        if (null !== $productName) {
            Assert::same($items[0]['productName'], $productName);
        }

        $this->sharedStorage->set('item', $items[0]);
    """
_SYLIUS_CART_STATE = """
        $response = $this->shopClient->getLastResponse();
        $items = $this->responseChecker->getValue($response, 'items');
        $this->sharedStorage->set('item', $items[0]);
    """


def stripped_solution(gold_root: str, closure: dict, *,
                      source_texts: Optional[dict[str, str]] = None,
                      assertion_selection: Optional[dict] = None,
                      preserve_sylius_cart_state: bool = False) -> dict:
    """Return the adapter payload for one assertion-stripped gold closure."""
    item_id = closure.get("item_id")
    if assertion_selection is None:
        selected = then_definitions(closure)
    else:
        from .assertion_selection import validate_assertion_selection
        selected = validate_assertion_selection(closure, assertion_selection)
    mixed = preserve_sylius_cart_state and item_id in SYLIUS_CART_ITEMS
    if mixed and _SYLIUS_CART_TARGET not in selected:
        raise StripRefused("REFUSED: reviewed mixed cart definition is not selected")
    by_file: dict[str, list[str]] = {}
    for rel, _class, method in selected:
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
        if mixed and rel == _SYLIUS_CART_TARGET[0]:
            start, end, _ = _method_span(original, _SYLIUS_CART_TARGET[2])
            if original[start:end] != _SYLIUS_CART_ORIGINAL:
                raise StripRefused("REFUSED: reviewed mixed cart method body changed")
        code = strip_php_source(original, by_file.get(rel, []))
        if mixed and rel == _SYLIUS_CART_TARGET[0]:
            start, end, _ = _method_span(code, _SYLIUS_CART_TARGET[2])
            code = code[:start] + _SYLIUS_CART_STATE + code[end:]
        files.append({"file_path": rel, "code": code})
    missing_files = sorted(set(by_file) - set(closure.get("files") or []))
    if missing_files:
        raise StripRefused(
            f"REFUSED: Then definitions name files outside the gold closure: "
            f"{missing_files}.")
    services = _services_file(closure.get("di_fragment") or {})
    if services:
        files.append(services)
    identities = [{"file": rel, "class": cls, "method": method}
                  for rel, cls, method in selected
                  if not (mixed and (rel, cls, method) == _SYLIUS_CART_TARGET)]
    metadata = {"source": "stripped_gold", "stripped_gold": True,
                "item_id": item_id}
    if assertion_selection is None:
        metadata.update({
            "n_then_definitions": len(identities),
            "then_definitions": identities,
            "definition_identity_sha256": hashlib.sha256(
                json.dumps(identities, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        })
    else:
        metadata["assertion_selection"] = {
            "policy": assertion_selection["policy"],
            "definitions": identities,
        }
    if mixed:
        metadata["state_preserving_assertion"] = {
            "policy": "r2t.sylius319-cart-state/1",
            "definition": dict(zip(("file", "class", "method"), _SYLIUS_CART_TARGET))}
    return {"files": files, "metadata": metadata}


def load_closures(path: str) -> dict[str, dict]:
    with open(path, encoding="utf-8") as fh:
        return {value["item_id"]: value for value in json.load(fh)}


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


def selftest() -> int:
    import tempfile
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    source = """<?php
class C {
    public function setup(): void { $this->x = 1; }
    public function assertIt(): void
    {
        if ($this->x) { throw new \\RuntimeException(\"}\"); }
    }
}
"""
    stripped = strip_php_source(source, ["assertIt"])
    check("PHP Then body is empty while Given/When setup is byte-preserved",
          "$this->x = 1" in stripped and "RuntimeException" not in stripped,
          stripped)
    closure = {"item_id": "i", "files": ["C.php"], "di_fragment": {},
               "steps": [
                   {"keyword": "Given", "side": "removable",
                    "definition": {"file": "C.php", "class": "C",
                                   "method": "setup"}},
                   {"keyword": "Then", "side": "removable",
                    "definition": {"file": "C.php", "class": "C",
                                   "method": "assertIt"}},
               ]}
    with tempfile.TemporaryDirectory() as root:
        with open(os.path.join(root, "C.php"), "w", encoding="utf-8") as fh:
            fh.write(source)
        doc = stripped_solution(root, closure)
        check("stripped solution records the exact Then definition identity",
              doc["metadata"]["then_definitions"] == [
                  {"file": "C.php", "class": "C", "method": "assertIt"}])
    shared = json.loads(json.dumps(closure))
    shared["steps"].append({
        "keyword": "When", "side": "removable",
        "definition": {"file": "C.php", "class": "C",
                       "method": "assertIt"}})
    try:
        then_definitions(shared)
        refused = False
    except StripRefused as exc:
        refused = "shared with Given/When" in str(exc)
    check("a setup/assertion-shared definition is refused", refused)

    def _raises(fn, fragment):
        try:
            fn()
        except StripRefused as exc:
            return fragment in str(exc)
        return False

    # Exact six-case exception: assertion removal retains only original
    # state expressions, while recorded/default whole-body output stays old.
    rel, cls, method = _SYLIUS_CART_TARGET
    source = ("<?php\nclass CartContext {\n"
              " public function action() { $this->cart->add(); }\n"
              " public function thereShouldBeOneItemInMyCart(?string $productName = null): void\n    {"
              + _SYLIUS_CART_ORIGINAL + "}\n"
              " public function thisItemShouldHaveName(array $item, string $productName): void\n"
              "    { Assert::same($item['name'], $productName); }\n}\n")
    for iid in SYLIUS_CART_ITEMS:
        c = {"item_id": iid, "files": [rel], "steps": [
            {"keyword": "Then", "side": "removable", "definition": {
                "file": rel, "class": cls, "method": m}}
            for m in (method, "thisItemShouldHaveName")]}
        old = stripped_solution("unused", c, source_texts={rel: source})
        new = stripped_solution("unused", c, source_texts={rel: source},
                                preserve_sylius_cart_state=True)
        text = new["files"][0]["code"]
        check("mixed cart preserves state and action, never assertions: " + iid,
              _SYLIUS_CART_STATE in text and "Assert::" not in text
              and "$this->cart->add();" in text
              and "sharedStorage" not in old["files"][0]["code"])
        check("mixed cart metadata does not claim whole-body removal",
              new["metadata"]["n_then_definitions"] == 1
              and new["metadata"]["state_preserving_assertion"]["definition"]["method"] == method)
        check("changed mixed-method source refuses",
              _raises(lambda: stripped_solution("unused", c,
                  source_texts={rel: source.replace("Assert::count($items, 1)", "Assert::count($items, 2)")},
                  preserve_sylius_cart_state=True), "method body changed"))
    ordinary = dict(c, item_id="sylius/unlisted:1")
    check("other controls retain byte-identical derivation",
          stripped_solution("unused", ordinary, source_texts={rel: source}) ==
          stripped_solution("unused", ordinary, source_texts={rel: source}, preserve_sylius_cart_state=True))

    # -- And/But/`*` resolution, opt-in and refused rather than seeded ----
    def kstep(keyword, method, line, origin="scenario", row=0):
        return {"keyword": keyword, "text": f"step {line}", "origin": origin,
                "example_row": row, "source_line": line, "side": "removable",
                "definition": {"file": "C.java", "class": "C",
                               "method": method}}

    written = {"item_id": "p/f.feature:1", "steps": [
        kstep("Given", "setUp", 4, origin="background"),
        kstep("When", "act", 7),
        kstep("And", "act2", 8),
        kstep("Then", "assertIt", 9),
        kstep("And", "assertMore", 10),
    ]}
    check("`And` takes the nearest preceding concrete keyword of its own "
          "block, which is the rule the Gherkin reader applies to bytes",
          effective_keywords(written["steps"])
          == ["given", "when", "when", "then", "then"],
          str(effective_keywords(written["steps"])))
    check("...so an item whose assertions are written `And` under a `Then` "
          "yields BOTH of them as Then-only definitions",
          then_definitions(written, resolve_inherited=True)
          == [("C.java", "C", "assertIt"), ("C.java", "C", "assertMore")],
          str(then_definitions(written, resolve_inherited=True)))
    check("...and an `And` under a `When` is an ACTION, not an assertion -- "
          "the direction of error that would empty setup",
          ("C.java", "C", "act2")
          not in then_definitions(written, resolve_inherited=True))
    check("the same closure is REFUSED without the opt-in, so a producer "
          "that already resolves cannot hand over an unresolved one",
          _raises(lambda: then_definitions(written),
                  "unsupported effective keyword"))
    check("a block that OPENS with `And` is REFUSED rather than seeded with "
          "`Given` the way the byte reader seeds it",
          _raises(lambda: effective_keywords(
              [kstep("And", "assertIt", 8)]), "opens its block"))
    check("...and the refusal is per BLOCK, not per closure: a background "
          "carry does not reach the scenario that follows it",
          _raises(lambda: effective_keywords([
              kstep("Then", "assertIt", 4, origin="background"),
              kstep("And", "act", 7)]), "opens its block"))
    check("an unknown keyword is still refused, whichever mode is asked for",
          _raises(lambda: effective_keywords([kstep("Wenn", "act", 7)]),
                  "unsupported keyword"))
    print("\n" + ("ALL PASS (strip)" if ok else "FAILURES (strip)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
