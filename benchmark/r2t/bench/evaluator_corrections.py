"""Which recorded attempts the harness-25 evaluator corrections change.

Audience: the operator who re-executes the existing configurations under
specifications/EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md section 5, and
the analyst who checks the rebuilt cells.

`select` reads one recorded run offline -- the rows' saved candidate bytes,
nothing executed -- and predicts, for each row, the three fields a harness-25
execution records, with the harness's own decision code:

* `supplied_helpers` (coddy-agent, correction A): `go.sensitivity.
  missing_helpers` over the row's answer files, when they are the item's
  exact answer set (the harness rejects any other set before execution);
* `relisted_contexts` (PrestaShop and Sylius, B): `harness.
  contexts_to_relist` over the contexts the row's own execution registered
  (`registered_contexts`), the item's suite and the classes' step patterns;
* `autowired_services` (CoreShop and Sylius, C): `harness.
  leaves_required_unwired` over the row's `behat_services.yml`, without the
  entries its execution rejected and unless the fragment's `_defaults` says
  `autowire`.

A row is affected when one of them is non-empty.  A row of a gold run never
is: one by the gold, stripped-gold or stub adapter that was not replayed
(`runner.is_gold_run_adapter`); a replayed gold row is a candidate run.  B
and C need each class's step patterns and constructor parameters, which the
harness reads with php-parser inside the worker; offline they are read from
the PHP source by `php_classes`.  An entry whose class's constructor that
reader cannot follow, or whose class the row registered as a context but the
reader did not find, is listed under `unread_services`, and a class whose
steps it cannot place makes its other-suite contexts `unread_contexts`; both
count as affected, so the offline reading can over-select but not miss an
attempt.  Re-executing an unaffected attempt only reproduces it.

`compose` builds a rebuilt cell (section 5, step 5): for each item in the
recorded order, the harness-25 row where the item was selected and the
recorded row otherwise, with one composition entry per item naming the
source.  Its verdict follows its row; a recorded CoreShop row's verdict is
its cell's `RESCORE_SCHEMA` record's, correction D applied without execution
(`test_quality.rescore_recorded`, section 5 step 4).
"""
from __future__ import annotations

import re
from typing import Iterable, Mapping, Optional

SELECTION_SCHEMA = "r2t.h25-selection/1"
COMPOSITION_SCHEMA = "r2t.h25-composition/1"
RESCORE_SCHEMA = "r2t.h25-rescore/1"
FIELDS = ("supplied_helpers", "relisted_contexts", "autowired_services")
#: The projects each correction can change (amendment section 2).
PROJECTS = {"supplied_helpers": ("coddy-agent",),
            "relisted_contexts": ("prestashop", "sylius"),
            "autowired_services": ("coreshop", "sylius")}


# ------------------------------------------------------------ PHP reading
_PHP_SKIP = re.compile(r"""
    (?P<string>'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")
  | (?P<comment>/\*.*?\*/|//[^\n]*|\#(?!\[)[^\n]*)
""", re.S | re.X)
_PHP_BUILTIN = frozenset(
    "int float string bool array callable iterable object mixed void null "
    "false true never self static parent".split())
_PHP_MODIFIERS = frozenset({"public", "private", "protected", "readonly"})


def _php_code(source: str) -> str:
    """The source with comments and string bodies blanked, offsets kept."""
    def blank(match):
        text = match.group()
        if match.group("comment"):
            return re.sub(r"[^\n]", " ", text)
        return text[0] + " " * (len(text) - 2) + text[-1]
    return _PHP_SKIP.sub(blank, source)


_PHP_STEP_ATTRIBUTE = re.compile(
    r"""\#\[\s*\\?(?:[\w\\]*\\)?(Given|When|Then)\s*\(\s*"""
    r"""(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)")""")


def _step_patterns(raw: str) -> list:
    """Step patterns in a class body: `@Given ...` docblock lines, as
    `analyze_php.php` `parse_annotations` reads them, and the first string
    argument of `#[Given(...)]`-style attributes.

    The docblock keeps its delimiters, as php-parser hands it over, so a line
    that opens with `/**` is no step: one-line `/** @Given x */` is ignored
    there and here alike."""
    patterns = []
    for doc in re.findall(r"/\*\*.*?\*/", raw, re.S):
        for line in re.split(r"\r\n|\r|\n", doc):
            line = re.sub(r"^\s*\*\s?", "", line)
            match = re.match(r"^\s*@(Given|When|Then)\b\s*(.*)$", line)
            if match:
                patterns.append(match.group(2).rstrip())
    for match in _PHP_STEP_ATTRIBUTE.finditer(raw):
        if match.group(2) is not None:
            patterns.append(re.sub(r"\\([\\'])", r"\1", match.group(2)))
        else:
            patterns.append(re.sub(r'\\([\\"])', r"\1", match.group(3)))
    return patterns


def _balanced(text: str, start: int, opening: str, closing: str) -> Optional[int]:
    """Index of the bracket closing the one at `start`, or None."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == opening:
            depth += 1
        elif text[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_top_level(text: str) -> list:
    parts, depth, start = [], 0, 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def _without_attributes(text: str) -> Optional[str]:
    while "#[" in text:
        start = text.index("#[")
        end = _balanced(text, start + 1, "[", "]")
        if end is None:
            return None
        text = text[:start] + " " + text[end + 1:]
    return text


def _parameter(text: str, resolve) -> Optional[dict]:
    match = re.search(r"\$(\w+)", text)
    if match is None:
        return None
    before = text[:match.start()]
    types = [resolve(token.lstrip("?"))
             for token in re.split(r"[\s|&()]+", before.replace("...", " "))
             if token and token.lstrip("?") and token not in _PHP_MODIFIERS]
    return {"name": match.group(1), "types": types,
            "has_default": text[match.end():].lstrip().startswith("="),
            "variadic": "..." in before}


def php_classes(source: str) -> dict:
    """`{FQCN: {"constructor": ..., "steps": ...}}` of a file's concrete classes.

    The facts `analyze_php.php` records that `write_registration` and
    `contexts_to_relist` read: each constructor parameter's name, types
    (resolved through the file's namespace and `use` imports), `has_default`
    and `variadic`, and each step pattern.  A class without a constructor
    has none.  A constructor this reader cannot follow is None, and so are
    the steps of a class whose body it cannot delimit.
    """
    code = _php_code(source)
    namespace = re.search(r"\bnamespace\s+([\w\\]+)\s*[;{]", code)
    prefix = namespace.group(1) + "\\" if namespace else ""
    imports = {(alias or name.rsplit("\\", 1)[-1]): name.lstrip("\\")
               for name, alias in re.findall(
                   r"^\s*use\s+([\w\\]+)(?:\s+as\s+(\w+))?\s*;", code, re.M)}

    def resolve(name: str) -> str:
        if name.lower() in _PHP_BUILTIN or name.startswith("\\"):
            return name.lstrip("\\")
        head, _, rest = name.partition("\\")
        if head in imports:
            return imports[head] + ("\\" + rest if rest else "")
        return prefix + name

    out: dict = {}
    for match in re.finditer(
            r"(?<![\w$>:])((?:(?:abstract|final|readonly)\s+)*)class\s+(\w+)",
            code):
        if code[:match.start()].rstrip().endswith("new") \
                or "abstract" in match.group(1):
            continue
        name = prefix + match.group(2)
        brace = code.find("{", match.end())
        end = _balanced(code, brace, "{", "}") if brace >= 0 else None
        if end is None:
            out[name] = {"constructor": None, "steps": None}
            continue
        body = code[brace:end]
        info = {"steps": _step_patterns(source[brace:end]), "constructor": []}
        out[name] = info
        constructor = re.search(r"\bfunction\s+__construct\s*\(", body, re.I)
        if constructor is None:
            continue
        close = _balanced(body, constructor.end() - 1, "(", ")")
        signature = (None if close is None else
                     _without_attributes(body[constructor.end():close]))
        parameters = (None if signature is None else
                      [_parameter(part, resolve)
                       for part in _split_top_level(signature) if part.strip()])
        info["constructor"] = (None if parameters is None or None in parameters
                               else parameters)
    return out


# -------------------------------------------------------------- selection
def corrections(project: str, row: dict, *, item: Optional[dict] = None,
                suite_map: Optional[dict] = None,
                closure: Optional[dict] = None) -> dict:
    """The harness-25 fields one recorded row's execution would record.

    `item` is the row's release item and `suite_map` the project's
    `suite_map.json` (PrestaShop, Sylius); `closure` is the item's
    `closures.json` entry (coddy-agent).
    """
    from .harness import (SERVICES_FRAGMENT_NAME, contexts_of_other_suites,
                          contexts_to_relist, leaves_required_unwired,
                          parse_services_fragment)
    from .runner import GOLD_RUN_ADAPTERS
    out: dict = {}
    files = row.get("produced_files") or []
    candidate = not (row.get("adapter") in GOLD_RUN_ADAPTERS
                     and "replayed_from" not in (row.get("metadata") or {}))
    written = set(row.get("written_files") or (f["file_path"] for f in files))
    classes: dict = {}
    for f in files:
        if f["file_path"] in written and f["file_path"].endswith(".php"):
            classes.update(php_classes(f.get("code") or ""))
    if project in PROJECTS["supplied_helpers"]:
        from ..go.sensitivity import missing_helpers
        answers = {f["file_path"]: f["code"] for f in files}
        out["supplied_helpers"] = (
            missing_helpers(closure["go_suite"], answers)
            if candidate and closure is not None
            and set(answers) == set(closure["files"]) else {})
    if project in PROJECTS["relisted_contexts"]:
        from ..toolkit.behat_suites import select_suite
        suite = None
        if candidate and item is not None and suite_map is not None:
            suite = select_suite(suite_map,
                                 (item.get("bench_meta") or {}).get("tags") or [],
                                 (item.get("provenance") or {}).get("file_path"))
        contexts = list(row.get("registered_contexts") or [])
        relisted, unread = [], []
        if suite is not None:
            if any((classes.get(ctx) or {}).get("steps") is None
                   for ctx in contexts):
                unread = contexts_of_other_suites(suite_map["suites"],
                                                  contexts, suite)
            else:
                relisted = contexts_to_relist(
                    suite_map["suites"], contexts, suite,
                    {ctx: classes[ctx]["steps"] for ctx in contexts})
        out["relisted_contexts"] = relisted
        if unread:
            out["unread_contexts"] = unread
    if project in PROJECTS["autowired_services"]:
        fragment = {}
        for f in files:
            if f["file_path"].rsplit("/", 1)[-1] == SERVICES_FRAGMENT_NAME:
                fragment, _why = parse_services_fragment(f.get("code") or "")
        rejected = {entry.get("service_id")
                    for entry in row.get("rejected_files") or ()}
        constructors = {name: info["constructor"]
                        for name, info in classes.items()}
        registered = set(row.get("registered_contexts") or ())
        defaults = fragment.get("_defaults")
        autowired, unread = [], []
        if candidate and not (isinstance(defaults, dict)
                              and "autowire" in defaults):
            for sid, body in fragment.items():
                if sid in rejected:
                    continue
                body = {} if body is None else body
                cls = str((body.get("class") if isinstance(body, dict)
                           else None) or sid).lstrip("\\")
                # A constructor the reader could not follow, or a context
                # the harness registered that the reader did not find.
                unread_class = (constructors[cls] is None
                                if cls in constructors else cls in registered)
                if (isinstance(body, dict) and unread_class
                        and not {"alias", "autowire"} & set(body)):
                    unread.append(sid)
                elif leaves_required_unwired(body, sid, constructors):
                    autowired.append(sid)
        out["autowired_services"] = autowired
        if unread:
            out["unread_services"] = unread
    return out


def select(project: str, rows: Iterable[dict], *,
           items: Optional[Mapping[str, dict]] = None,
           suite_map: Optional[dict] = None,
           closures: Optional[Mapping[str, dict]] = None) -> dict:
    """The selection of one recorded run: per-field counts and affected rows.

    `items` and `closures` are keyed by item id.  The caller adds the run's
    identity (`SELECTION_SCHEMA` record, `benchmark/scripts/
    select_h25_affected.py`).
    """
    affected, counts, n_rows = [], {}, 0
    for row in rows:
        n_rows += 1
        iid = row["item_id"]
        fields = corrections(project, row, item=(items or {}).get(iid),
                             suite_map=suite_map,
                             closure=(closures or {}).get(iid))
        changed = {key: value for key, value in fields.items() if value}
        for key in changed:
            counts[key] = counts.get(key, 0) + 1
        if changed:
            affected.append({"item_id": iid, **fields})
    return {"project": project, "rows": n_rows,
            "affected": affected, "counts": {"affected": len(affected),
                                             **dict(sorted(counts.items()))}}


def compose(recorded: Iterable[dict], harness_25: Iterable[dict],
            selected: Iterable[str]) -> tuple:
    """`(rows, entries)` of a rebuilt cell, in the recorded order.

    Each selected item takes its harness-25 row and every other item its
    recorded row; each entry names the source, the recorded line and the
    harness version of the row it took, so the cell states its versions.  A
    selected item without exactly one harness-25 row, or a harness-25 row of
    an item that was not selected, is refused: the cell would hold a row
    whose correction the selection does not account for.
    """
    selected = set(selected)
    new: dict = {}
    for row in harness_25:
        if row["item_id"] in new:
            raise ValueError(f"REFUSED: two harness-25 rows for {row['item_id']}")
        new[row["item_id"]] = row
    recorded = list(recorded)
    ids = [row["item_id"] for row in recorded]
    missing = sorted(selected - set(new))
    stray = sorted(set(new) - (selected & set(ids)))
    if missing or stray:
        raise ValueError(f"REFUSED: selected items without a harness-25 row "
                         f"{missing[:3]}, harness-25 rows outside the "
                         f"selection {stray[:3]}")
    rows, entries = [], []
    for line, row in enumerate(recorded, 1):
        iid = row["item_id"]
        chosen = new[iid] if iid in selected else row
        rows.append(chosen)
        entries.append({"item_id": iid,
                        "from": "harness_25" if iid in selected else "recorded",
                        "recorded_line": line,
                        "harness_version": chosen.get("harness_version")})
    return rows, entries


# ---------------------------------------------------------------- selftest
def selftest() -> int:
    """Offline predictions against the harness's own rules, no execution."""
    import json
    import os
    import tempfile
    from ..toolkit.behat_suites import SUITE_MAP_SCHEMA

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    php = r"""<?php
declare(strict_types=1);

namespace Sylius\Behat\Context\Api\Shop;

use Sylius\Behat\Client\ApiClientInterface;
use Sylius\Behat\Service\SharedStorageInterface as Storage;
use Webmozart\Assert\Assert;

/** A docblock that says class Decoy { function __construct($x) } */
final class CartContext implements \Behat\Behat\Context\Context
{
    public function __construct(
        #[Autowire(service: 'sylius.behat.api_platform_client.shop')]
        private readonly ApiClientInterface $shopClient,
        private Storage $sharedStorage,
        private ?string $locale = 'en_US', // a comment with $notAParameter
        array $options = ['a' => [1, 2]],
        \Countable&\Traversable ...$rest,
    ) {
        $helper = new class () { public function __construct() {} };
    }

    /**
     * @Given I specify the first name as :firstName
     * @When /^I (?:add|remove) it$/
     */
    public function name(): string { return CartContext::class; }

    #[\Behat\Step\Then('the cart should say \'empty\'')]
    public function empty(): void {}
}

abstract class AbstractThing { public function __construct($x) {} }

final class Plain {}
"""
    found = php_classes(php)
    cart = "Sylius\\Behat\\Context\\Api\\Shop\\CartContext"
    plain = "Sylius\\Behat\\Context\\Api\\Shop\\Plain"
    check("[H25] the offline reader finds the concrete classes, not the "
          "abstract one, a docblock or an anonymous class",
          sorted(found) == [cart, plain], str(sorted(found)))
    check("[H25] ...and reads each constructor parameter as the PHP index "
          "records it: resolved types, defaults and the variadic",
          found[cart]["constructor"] == [
              {"name": "shopClient", "types":
               ["Sylius\\Behat\\Client\\ApiClientInterface"],
               "has_default": False, "variadic": False},
              {"name": "sharedStorage", "types":
               ["Sylius\\Behat\\Service\\SharedStorageInterface"],
               "has_default": False, "variadic": False},
              {"name": "locale", "types": ["string"],
               "has_default": True, "variadic": False},
              {"name": "options", "types": ["array"],
               "has_default": True, "variadic": False},
              {"name": "rest", "types": ["Countable", "Traversable"],
               "has_default": False, "variadic": True}]
          and found[plain] == {"constructor": [], "steps": []},
          str(found.get(cart)))
    check("[H25] ...and its step patterns, from docblocks and attributes",
          found[cart]["steps"] == ["I specify the first name as :firstName",
                                   "/^I (?:add|remove) it$/",
                                   "the cart should say 'empty'"],
          str(found[cart]["steps"]))
    check("[H25] a constructor the reader cannot follow is None, not empty",
          php_classes("<?php class Broken { function __construct("
                      "#[Attr $x) {} }")["Broken"]["constructor"] is None)
    check("[H25] a one-line docblock defines no step, as analyze_php.php "
          "reads it",
          php_classes("<?php class One {\n    /** @Given x */\n"
                      "    public function a() {}\n}\n")["One"]["steps"] == [])

    def fragment(entries: dict) -> dict:
        import yaml
        return {"file_path": "behat_services.yml",
                "code": yaml.safe_dump({"services": entries})}

    source = {"file_path": "src/Sylius/Behat/Context/Api/Shop/CartContext.php",
              "code": php}
    partial = {"app.cart": {"class": cart, "arguments": ["@client"]}}
    row = {"item_id": "sylius/a.feature:3", "adapter": "codex",
           "metadata": {"model": "m"},
           "produced_files": [source, fragment(partial)],
           "written_files": [source["file_path"]], "rejected_files": [],
           "registered_contexts": [cart]}
    check("[H25-C] a partial definition of a returned class is predicted "
          "autowired",
          corrections("coreshop", row) == {"autowired_services": ["app.cart"]},
          str(corrections("coreshop", row)))
    empty_body = dict(row, produced_files=[source, fragment({cart: None})])
    check("[H25-C] ...and so is an empty body (`Foo: ~`)",
          corrections("coreshop", empty_body) == {"autowired_services": [cart]},
          str(corrections("coreshop", empty_body)))
    complete = dict(row, produced_files=[source, fragment({"app.cart": {
        "class": cart, "arguments": {"$shopClient": "@a",
                                     "$sharedStorage": "@b"}}})])
    aliased = dict(row, produced_files=[source, fragment({
        cart: {"alias": "app.cart"},
        "app.cart": {"class": cart, "autowire": True}})])
    rejected = dict(row, rejected_files=[{
        "file_path": "behat_services.yml", "service_id": "app.cart",
        "why": "protected_service_id:app.cart"}])
    gold = dict(row, adapter="gold", metadata={"source": "gold"})
    for name, case in (("a complete one", complete),
                       ("an alias entry beside an autowired definition "
                        "(the passing complex_promotions shape)", aliased),
                       ("an entry its execution rejected", rejected),
                       ("a gold run's row", gold)):
        check(f"[H25-C] ...and none for {name}",
              corrections("coreshop", case) == {"autowired_services": []},
              str(corrections("coreshop", case)))
    replayed = dict(gold, metadata={"source": "gold",
                                    "replayed_from": "gold.jsonl"})
    check("[H25] a replayed gold row is a candidate run",
          corrections("coreshop", replayed) == {"autowired_services": ["app.cart"]},
          str(corrections("coreshop", replayed)))
    unreadable = dict(row, produced_files=[
        {"file_path": source["file_path"],
         "code": "<?php namespace Sylius\\Behat\\Context\\Api\\Shop; "
                 "class CartContext { function __construct(#[A $x) {} }"},
        fragment(partial)])
    check("[H25-C] a definition whose constructor the reader cannot follow "
          "is selected rather than missed",
          corrections("coreshop", unreadable) == {
              "autowired_services": [], "unread_services": ["app.cart"]},
          str(corrections("coreshop", unreadable)))
    unfound = dict(row, produced_files=[fragment(partial)])
    check("[H25-C] ...and so is one of a context the harness registered "
          "that the reader did not find",
          corrections("coreshop", unfound) == {
              "autowired_services": [], "unread_services": ["app.cart"]},
          str(corrections("coreshop", unfound)))

    other = "Sylius\\Behat\\Context\\Api\\Shop\\RegistrationContext"

    def registration(pattern: str) -> dict:
        return {"file_path": "src/Sylius/Behat/Context/Api/Shop/"
                             "RegistrationContext.php",
                "code": "<?php\nnamespace Sylius\\Behat\\Context\\Api\\Shop;\n"
                        "final class RegistrationContext {\n"
                        "    /**\n"
                        f"     * @Given {pattern}\n"
                        "     */\n"
                        "    public function step(): void {}\n}\n"}

    suite_map = {"schema": SUITE_MAP_SCHEMA, "project": "sylius", "suites": {
        "account": {"arm": True, "tag_filter": "@account&&@api", "paths": [],
                    "contexts": ["ctx.cart"], "retained": [],
                    "classes": {"ctx.cart": cart}},
        "register": {"arm": True, "tag_filter": "@register&&@api",
                     "paths": [], "contexts": ["ctx.registration"],
                     "retained": [],
                     "classes": {"ctx.registration": other}}}}
    item = {"item_id": row["item_id"],
            "bench_meta": {"tags": ["@account", "@api"]},
            "provenance": {"file_path": "features/a.feature"}}

    def with_registration(pattern: str) -> dict:
        extra = registration(pattern)
        return dict(row, registered_contexts=[cart, other],
                    produced_files=row["produced_files"] + [extra],
                    written_files=row["written_files"] + [extra["file_path"]])

    relisting = with_registration("I register my account")
    check("[H25-B] a returned context of another suite whose steps no class "
          "listed before it defines is predicted relisted, and Sylius gets "
          "both of its fields",
          corrections("sylius", relisting, item=item, suite_map=suite_map)
          == {"relisted_contexts": [other], "autowired_services": ["app.cart"]},
          str(corrections("sylius", relisting, item=item, suite_map=suite_map)))
    repeating = with_registration("I specify the first name as :firstName")
    check("[H25-B] ...but not one that repeats a step of the suite's class, "
          "as a gold closure's dependency does",
          corrections("sylius", repeating, item=item, suite_map=suite_map)
          ["relisted_contexts"] == [])
    check("[H25-B] ...and never in a gold run's row",
          corrections("sylius", dict(relisting, adapter="gold"),
                      item=item, suite_map=suite_map)
          == {"relisted_contexts": [], "autowired_services": []})

    helper = "internal/agent/bdd_loop_guard_test.go"
    glue = "internal/agent/bdd_glue_test.go"
    closure = {"files": [glue, helper],
               "go_suite": {"package_dir": "internal/agent"}}
    coddy = {"item_id": "coddy-agent/f.feature:2", "metadata": {},
             "produced_files": [
                 {"file_path": glue, "code": "package agent\n"},
                 {"file_path": helper, "code": "package agent\n\n"
                  "func bddLoopedThought() string { return \"\" }\n"}]}
    from ..go.sensitivity import RETAINED_HELPERS
    lacking = {path: [name for name in names if name != "bddLoopedThought"]
               for path, names in RETAINED_HELPERS.items()
               if path.startswith("internal/agent/")}
    check("[H25-A] the helpers an accepted coddy answer set lacks are "
          "predicted supplied: all of its package's but the one it declares",
          corrections("coddy-agent", coddy, closure=closure)
          == {"supplied_helpers": lacking}
          and lacking[helper] == ["bddLoopProvider", "bddLoopedSentence"],
          str(corrections("coddy-agent", coddy, closure=closure)))
    short = dict(coddy, produced_files=coddy["produced_files"][:1])
    check("[H25-A] ...and none for an answer set the harness rejects",
          corrections("coddy-agent", short, closure=closure)
          == {"supplied_helpers": {}})

    selection = select("sylius", [row, dict(complete, item_id="sylius/b:1"),
                                  dict(relisting, item_id="sylius/c:2")],
                       items={"sylius/c:2": dict(item, item_id="sylius/c:2")},
                       suite_map=suite_map)
    check("[H25] a run's selection counts its affected rows per correction",
          selection["rows"] == 3
          and [entry["item_id"] for entry in selection["affected"]]
          == ["sylius/a.feature:3", "sylius/c:2"]
          and selection["counts"] == {"affected": 2, "autowired_services": 2,
                                      "relisted_contexts": 1},
          json.dumps(selection["counts"]))

    recorded = [{"item_id": "i1", "outcome": "failed", "harness_version": 23},
                {"item_id": "i2", "outcome": "passed", "harness_version": 23},
                {"item_id": "i3", "outcome": "solution_error",
                 "harness_version": 23}]
    redone = [{"item_id": "i3", "outcome": "passed", "harness_version": 25}]
    rows, entries = compose(recorded, redone, ["i3"])
    check("[H25] a rebuilt cell keeps the recorded order, takes the "
          "harness-25 row exactly where the item was selected, and states "
          "each row's harness version",
          rows == recorded[:2] + redone
          and entries == [{"item_id": "i1", "from": "recorded",
                           "recorded_line": 1, "harness_version": 23},
                          {"item_id": "i2", "from": "recorded",
                           "recorded_line": 2, "harness_version": 23},
                          {"item_id": "i3", "from": "harness_25",
                           "recorded_line": 3, "harness_version": 25}],
          str(entries))
    for name, args in (("a selected item without a harness-25 row",
                        (recorded, [], ["i3"])),
                       ("a harness-25 row of an item not selected",
                        (recorded, redone, [])),
                       ("two harness-25 rows of one item",
                        (recorded, redone + redone, ["i3"]))):
        try:
            compose(*args)
        except ValueError as exc:
            check(f"[H25] composing refuses {name}", "REFUSED" in str(exc))
        else:
            check(f"[H25] composing refuses {name}", False, "composed")

    with tempfile.TemporaryDirectory() as td:
        # The script's own round trip over files.
        import subprocess
        import sys
        run = os.path.join(td, "run.jsonl")
        # Neither line is in the form json.dumps(sort_keys=True) writes.
        affected_line = json.dumps(row) + "\n"
        other_line = '{"outcome":"failed",  "item_id":"sylius/b:1"}\n'
        with open(run, "w", encoding="utf-8") as fh:
            fh.write(affected_line + other_line)
        out = os.path.join(td, "selection.json")
        script = os.path.join(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))), "scripts",
            "select_h25_affected.py")
        done = subprocess.run([sys.executable, script, "select",
                               "--project", "coreshop", "--run", run,
                               "--out", out], capture_output=True, text=True)
        written = json.load(open(out, encoding="utf-8")) \
            if done.returncode == 0 else {}
        check("[H25] the selection script writes the record with the run's "
              "identity",
              written.get("schema") == SELECTION_SCHEMA
              and written.get("run", {}).get("rows") == 2
              and written.get("counts") == {"affected": 1,
                                            "autowired_services": 1},
              done.stderr[-500:] or json.dumps(written)[:300])
        redone = os.path.join(td, "harness25.jsonl")
        redone_line = ('{"item_id": "sylius/a.feature:3", '
                       '"outcome": "passed", "harness_version": 25}\n')
        with open(redone, "w", encoding="utf-8") as fh:
            fh.write(redone_line)
        rebuilt = os.path.join(td, "rebuilt.jsonl")
        done = subprocess.run([sys.executable, script, "compose",
                               "--run", run, "--harness-25", redone,
                               "--selection", out, "--out", rebuilt,
                               "--record", os.path.join(td, "composition.json")],
                              capture_output=True, text=True)
        composed = (open(rebuilt, encoding="utf-8").read()
                    if done.returncode == 0 else "")
        check("[H25] the composition script writes each row with its source "
              "line's bytes, in the recorded order",
              composed == redone_line + other_line,
              done.stderr[-500:] or composed[:300])

    print("\n" + ("ALL PASS (evaluator_corrections)" if ok
                  else "FAILURES (evaluator_corrections)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
