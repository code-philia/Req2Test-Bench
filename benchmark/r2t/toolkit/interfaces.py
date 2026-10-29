"""Target interfaces -- the declared interaction surface, per item
(TARGET_INTERFACES_SPEC section 3), for PHP/Behat.

For one item, the list is the first-party production types that the reference
step definitions bound to the item's OWN steps *declare* they interact
through:

  T1  the declared types of a bound step method's parameters;
  T2  its declared return type;
  T3  the declared types of the context's collaborator fields the method body
      references (`$this->x`), resolved from promoted-constructor parameters
      and property declarations -- a field the body never touches contributes
      nothing, which is what makes the list a property of the scenario rather
      than of its context class (measured: median 6 against 8 per item);
  T5  the fully-qualified names the method BODY references -- `new X(`,
      `X::CONST`, static calls, `instanceof`, `catch`, closure parameter
      types, and the `@var X` docblock CoreShop puts on a local it fills from
      a generically typed factory.  The parity edge: the Java rule always had
      `new X(` and typed locals; the pilot rating found the per-scenario
      discriminator hiding in exactly these forms;
  T6  the same surface of the context's own methods the member delegates to
      through `$this->helper()`, transitively within the context and the
      traits it uses.  A call is resolved against the BOUND class first and
      only then against the trait being visited: a trait helper that calls
      an abstract method the class implements (`getConditionFormClass()` in
      CoreShop's form traits) reaches the class override, and a trait helper
      that calls a helper of a sibling trait reaches it through the class
      that uses both.  That is PHP's own rule -- a class method overrides a
      trait's.  Still depth zero with respect to PRODUCTION: a private
      helper is part of how the bound step is written, not a hop into the
      code under test.

Two labelled lists (spec D1, owner ruling 2026-09-03): `behaviour` is the
surface of the scenario's own steps; `setup` is what the Background's steps
add beyond it.  The split discloses nothing the Gherkin's own `Background:`
does not, and it gives the system the whole localization the setting claims
to donate rather than the scenario's share of it.

Depth zero.  No `extends`/`implements`/trait chasing, no "every name in the
declaring file" edge (that edge is why `closure.production_deps` holds a
median of 72 names per item), no expansion into production, no resolution of
a declared type through the container to the class it injects (spec D6), no
sibling scenarios, no frequency statistic, no hand list.  Two filters, both
already-reviewed artifacts: the type must be declared in the project's own
production index (F1) and its declaring file must classify PRODUCTION under
the project's boundary (F2).

What is REUSED.  `closures.json` already binds every step to a `(class,
method)` with `origin` and `side`, and `php_index.json` already carries each
step method's declared parameter types and each class's constructor types.
The one thing the index lacked -- which fields a given method body touches --
is `steps[].this_props`, emitted by `php/analyze_php.php` alongside
`steps[].return_types` and `classes[].properties`.  An index without that
field predates the extension and is REFUSED rather than approximated: the
whole-constructor fallback is a different, coarser measurement (spec D3).

What the artifact is.  `interfaces.json` is an EXTRACTION artifact beside
`closures.json`, and like `php_index.json` it is answer-bearing: it carries
the unfiltered candidate set and the members it came from, for validation
sampling (spec section 7.2).  Only `target_interfaces` reaches the released
task record.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from ..core.boundary import PRODUCTION, REMOVABLE, Boundary, load_boundary

SCHEMA = "r2t.interfaces/1"

#: Why a list is empty.  Two reasons, both values rather than exclusions.
EMPTY_NO_MEMBER = "no_removable_scenario_member"
EMPTY_NO_DECLARATION = "no_first_party_declaration"


class InterfacesError(Exception):
    """A refusal: the inputs cannot answer the question honestly."""


@dataclass
class ItemInterfaces:
    item_id: str
    feature_file: str
    scenario_line: int
    #: The scenario's own surface after F1 and F2, sorted, deduplicated.
    behaviour: list[str] = field(default_factory=list)
    #: What the Background's members add beyond it, after F1 and F2.
    setup: list[str] = field(default_factory=list)
    #: Q_i before filtering, per origin: the validation superset (spec 7.2).
    candidates: dict = field(default_factory=lambda: {"behaviour": [], "setup": []})
    #: The bound members the surface was taken from, with origin.
    members: list[dict] = field(default_factory=list)
    empty_reason: Optional[str] = None

    def to_json(self) -> dict:
        return {
            "item_id": self.item_id,
            "feature_file": self.feature_file,
            "scenario_line": self.scenario_line,
            "target_interfaces": {"behaviour": list(self.behaviour),
                                  "setup": list(self.setup)},
            "candidates": {k: list(v) for k, v in self.candidates.items()},
            "members": [dict(m) for m in self.members],
            "empty_reason": self.empty_reason,
        }


class InterfaceExtractor:
    def __init__(self, php_index: dict, prod_index: dict, boundary: Boundary):
        # NO index-root cross-check.  Both indexes record `root`, but it is
        # the path the analyzer was pointed at INSIDE its container
        # (`/var/www/html` for every index this pipeline builds), not the
        # host checkout -- so comparing the two can never separate two
        # checkouts, which is the case a check here would exist to catch.
        # What DOES separate them is the corpus commit, and no index records
        # it.  A guard over a constant is scaffolding for a case this
        # pipeline cannot produce (AGENTS.md).  The reachable inconsistency,
        # an index that predates the analyzer extension, is refused in
        # `_own` on the field it actually lacks.
        self.boundary = boundary
        # (class, method) -> the declared surface's inputs, for EVERY method
        # of every test class (delegation targets included), and the same for
        # the annotated members that a step binds to.
        self.members: dict[tuple[str, str], dict] = {}
        # class -> field name -> declared types
        self.fields: dict[str, dict[str, set[str]]] = {}
        # class -> the traits it uses (their methods are its own, textually)
        self.traits: dict[str, list[str]] = {}
        for finfo in php_index["files"].values():
            for c in finfo["classes"]:
                fields: dict[str, set[str]] = {}
                for p in c.get("constructor") or []:
                    if p.get("promoted") and p.get("name"):
                        fields.setdefault(p["name"], set()).update(p.get("types") or [])
                for p in c.get("properties") or []:
                    if p.get("name"):
                        fields.setdefault(p["name"], set()).update(p.get("types") or [])
                self.fields[c["name"]] = fields
                self.traits[c["name"]] = list(c.get("traits") or [])
                for s in (c.get("methods") or []) + (c.get("steps") or []) \
                        + (c.get("transforms") or []):
                    self.members[(c["name"], s["name"] if "name" in s else s["method"])] = s
        # F1: what the project itself declares, and where.
        self.declaring_file: dict[str, str] = {}
        for path, finfo in prod_index["files"].items():
            for c in finfo.get("classes") or []:
                if c.get("name"):
                    self.declaring_file[c["name"]] = path
        # F2: of those, the ones the reviewed boundary calls production.
        self.first_party: set[str] = {
            n for n, p in self.declaring_file.items()
            if boundary.classify(p) == PRODUCTION}

    # ------------------------------------------------------------ surface
    def _own(self, cls: str, method: str) -> dict:
        s = self.members.get((cls, method))
        if s is None:
            raise InterfacesError(
                f"REFUSED: step definition {cls}::{method} is bound by the "
                f"closure but absent from php_index.json; the index and the "
                f"closure were not built from the same sources.")
        for key in ("this_props", "return_types", "body_refs", "this_calls"):
            if key not in s:
                raise InterfacesError(
                    f"REFUSED: php_index.json carries no `{key}` for "
                    f"{cls}::{method}; it predates the analyzer extension. "
                    f"Re-run `index` -- a coarser index is a different "
                    f"measurement, not a substitute (TARGET_INTERFACES_SPEC D3).")
        return s

    def _resolve_call(self, cls: str, name: str) -> Optional[tuple[str, str]]:
        """`$this->name()` inside `cls`: its own method, or one of a used trait's."""
        if (cls, name) in self.members:
            return (cls, name)
        for t in self.traits.get(cls, ()):
            if (t, name) in self.members:
                return (t, name)
        return None

    def surface_of(self, cls: str, method: str) -> set[str]:
        """T1 | T2 | T3 | T5 for one bound member, plus the same of every
        same-object method it delegates to (T6), unfiltered.

        `$this->name()` is resolved against the BOUND class `cls` first (its
        own methods, then its traits') and only then against the class or
        trait currently being visited.  Resolving against the visited trait
        alone stopped at a trait's abstract declaration and never reached
        the class's override -- measured on CoreShop, that lost the rule
        form type from 294 of the 545 ITEMS (318 of their 1,090 lists; 260
        items lacked exactly one entry), and cost no item an entry."""
        out: set[str] = set()
        seen: set[tuple[str, str]] = set()
        todo = [(cls, method)]
        while todo:
            key = todo.pop()
            if key in seen:
                continue
            seen.add(key)
            s = self._own(*key)
            for p in s.get("params") or []:
                out.update(p.get("types") or [])                  # T1
            out.update(s.get("return_types") or [])                # T2
            fields = self.fields.get(key[0], {})
            for name in s["this_props"]:                           # T3
                out.update(fields.get(name, ()))
            out.update(s["body_refs"])                             # T5
            for name in s["this_calls"]:                           # T6
                target = (self._resolve_call(cls, name)
                          or self._resolve_call(key[0], name))
                if target is not None:
                    todo.append(target)
        return out

    def for_item(self, closure: dict) -> ItemInterfaces:
        it = ItemInterfaces(closure["item_id"], closure["feature_file"],
                            closure["scenario_line"])
        scen: set[str] = set()
        back: set[str] = set()
        seen: set[tuple[str, str, str]] = set()
        for st in closure.get("steps") or []:
            d = st.get("definition")
            if not d or st.get("side") != REMOVABLE:
                continue                    # unbound, or answered by retained code
            key = (d["class"], d["method"], st["origin"])
            if key in seen:
                continue
            seen.add(key)
            it.members.append({"class": d["class"], "method": d["method"],
                               "origin": st["origin"]})
            surface = self.surface_of(d["class"], d["method"])
            (scen if st["origin"] == "scenario" else back).update(surface)
        it.candidates = {"behaviour": sorted(scen), "setup": sorted(back - scen)}
        it.behaviour = sorted(scen & self.first_party)
        it.setup = sorted((back & self.first_party) - scen)
        if not it.behaviour:
            it.empty_reason = (EMPTY_NO_DECLARATION
                               if any(m["origin"] == "scenario" for m in it.members)
                               else EMPTY_NO_MEMBER)
        return it


def extract_all(closures: list[dict], ex: InterfaceExtractor) -> list[ItemInterfaces]:
    return [ex.for_item(c) for c in closures]


def write_interfaces(items: list[ItemInterfaces], path: str) -> None:
    doc = {"schema": SCHEMA, "items": [i.to_json() for i in items]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
        fh.write("\n")


def load_extractor(php_index_path: str, prod_index_path: str,
                   boundary_path: str) -> InterfaceExtractor:
    with open(php_index_path, encoding="utf-8") as fh:
        php_index = json.load(fh)
    with open(prod_index_path, encoding="utf-8") as fh:
        prod_index = json.load(fh)
    return InterfaceExtractor(php_index, prod_index, load_boundary(boundary_path))


def summary(items: list[ItemInterfaces]) -> dict:
    """Size distribution.  `median` is the lower median (`statistics.
    median_low`) and `p90` the nearest-rank 90th percentile
    (`sizes[ceil(0.9 n) - 1]`), so both are values that occur."""
    n = len(items)

    def dist(sizes):
        sizes = sorted(sizes)
        if not n:
            return {}
        return {"median": sizes[(n - 1) // 2],
                "p90": sizes[max(0, -(-9 * n // 10) - 1)],
                "max": sizes[-1]}
    return {
        "items": n,
        "behaviour": dist(len(i.behaviour) for i in items),
        "setup": dist(len(i.setup) for i in items),
        "empty": {r: sum(1 for i in items if i.empty_reason == r)
                  for r in (EMPTY_NO_MEMBER, EMPTY_NO_DECLARATION)},
        "distinct": len({t for i in items for t in i.behaviour + i.setup}),
    }


# ------------------------------------------------------------------ selftest
def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    b = Boundary(version=1, project="t", repo_root="/x",
                 removable=[("test/glue/", "")],
                 retained=[("test/infra/", ""), ("src/TestBundle/", "")])
    P, R, V = "Prod\\Model\\CartInterface", "Prod\\Repo\\CartRepositoryInterface", \
        "Vendor\\Doctrine\\ObjectManager"
    SS = "Prod\\TestBundle\\SharedStorageInterface"   # declared in a RETAINED file
    U = "Prod\\Service\\UnusedFactoryInterface"       # injected, never referenced
    RT = "Prod\\Model\\TotalInterface"                # a return type
    BG = "Prod\\Model\\StoreInterface"                # background-only
    NW = "Prod\\Command\\InstallCommand"             # `new X(` in the body (T5)
    HL = "Prod\\Model\\OrderItemInterface"            # only via a private helper (T6)
    TR = "Prod\\Form\\ConditionType"                  # only via a used trait's method (T6)
    CT = "Prod\\Form\\PriceRuleConditionType"         # a trait helper calls back into the class
    AH = "Prod\\Form\\ActionType"                     # a trait helper calls a sibling trait's helper
    php_index = {"files": {
        "test/glue/CartContext.php": {"classes": [{
            "name": "G\\CartContext",
            "constructor": [
                {"name": "repo", "types": [R], "promoted": True},
                {"name": "storage", "types": [SS], "promoted": True},
                {"name": "unused", "types": [U], "promoted": True},
                {"name": "om", "types": [V], "promoted": True}],
            "properties": [{"name": "store", "types": [BG], "static": False}],
            "traits": ["G\\ConditionFormTrait", "G\\ActionFormTrait"],
            "methods": [
                {"name": "addItem", "params": [], "return_types": [],
                 "this_props": [], "body_refs": [HL], "this_calls": []},
                # the class's override of the trait's abstract method
                {"name": "getConditionFormClass", "params": [],
                 "return_types": ["string"], "this_props": [],
                 "body_refs": [CT], "this_calls": []}],
            "steps": [
                {"method": "iAdd", "kind": "When", "pattern": "x", "line": 1,
                 "params": [{"name": "cart", "types": [P]}],
                 "return_types": [], "this_props": ["om", "repo", "storage"],
                 "body_refs": [NW, "Webmozart\\Assert\\Assert"],
                 "this_calls": ["addItem", "assertConditionForm", "iAdd",
                                "createConditionWithForm"]},
                {"method": "total", "kind": "Then", "pattern": "y", "line": 2,
                 "params": [], "return_types": [RT], "this_props": [],
                 "body_refs": [], "this_calls": []},
                {"method": "site", "kind": "Given", "pattern": "z", "line": 3,
                 "params": [], "return_types": [], "this_props": ["store"],
                 "body_refs": [], "this_calls": []},
                {"method": "old", "kind": "Given", "pattern": "w", "line": 4,
                 "params": []}],
            "transforms": []}]},
        "test/glue/ConditionFormTrait.php": {"classes": [{
            "name": "G\\ConditionFormTrait", "kind": "trait", "constructor": [],
            "properties": [], "traits": [], "steps": [], "transforms": [],
            "methods": [{"name": "assertConditionForm", "params": [],
                         "return_types": [], "this_props": [],
                         "body_refs": [TR], "this_calls": []},
                        # calls back into the class, and across to a sibling trait
                        {"name": "createConditionWithForm", "params": [],
                         "return_types": [], "this_props": [], "body_refs": [],
                         "this_calls": ["getConditionFormClass", "actionHelper"]},
                        # the trait's ABSTRACT declaration: no body, no refs
                        {"name": "getConditionFormClass", "params": [],
                         "return_types": ["string"], "this_props": [],
                         "body_refs": [], "this_calls": []}]}]},
        "test/glue/ActionFormTrait.php": {"classes": [{
            "name": "G\\ActionFormTrait", "kind": "trait", "constructor": [],
            "properties": [], "traits": [], "steps": [], "transforms": [],
            "methods": [{"name": "actionHelper", "params": [],
                         "return_types": [], "this_props": [],
                         "body_refs": [AH], "this_calls": []}]}]},
        "test/infra/Purger.php": {"classes": [{
            "name": "I\\Infra", "constructor": [], "properties": [],
            "steps": [{"method": "bg", "kind": "Given", "pattern": "q", "line": 1,
                       "params": [{"name": "c", "types": [P]}],
                       "return_types": [], "this_props": [],
                       "body_refs": [], "this_calls": []}],
            "transforms": []}]},
    }}
    prod_index = {"files": {
        "src/Model/CartInterface.php": {"classes": [{"name": P}]},
        "src/Repo/CartRepositoryInterface.php": {"classes": [{"name": R}]},
        "src/Service/UnusedFactoryInterface.php": {"classes": [{"name": U}]},
        "src/Model/TotalInterface.php": {"classes": [{"name": RT}]},
        "src/Model/StoreInterface.php": {"classes": [{"name": BG}]},
        "src/TestBundle/SharedStorageInterface.php": {"classes": [{"name": SS}]},
        "src/Command/InstallCommand.php": {"classes": [{"name": NW}]},
        "src/Model/OrderItemInterface.php": {"classes": [{"name": HL}]},
        "src/Form/ConditionType.php": {"classes": [{"name": TR}]},
        "src/Form/PriceRuleConditionType.php": {"classes": [{"name": CT}]},
        "src/Form/ActionType.php": {"classes": [{"name": AH}]},
    }}
    ex = InterfaceExtractor(php_index, prod_index, b)

    def step(text, origin, cls, method, side):
        return {"text": text, "origin": origin, "keyword": "Given", "side": side,
                "definition": {"file": "f", "class": cls, "method": method,
                               "kind": "Given", "pattern": "p"}}

    item = {"item_id": "t/f.feature:5", "feature_file": "f.feature", "scenario_line": 5,
            "steps": [step("site", "background", "G\\CartContext", "site", "removable"),
                      step("infra", "background", "I\\Infra", "bg", "retained"),
                      step("add", "scenario", "G\\CartContext", "iAdd", "removable"),
                      step("total", "scenario", "G\\CartContext", "total", "removable"),
                      step("nothing", "scenario", None, None, None)]}
    item["steps"][-1]["definition"] = None
    got = ex.for_item(item)
    check("T1 parameter type, T2 return type and T3 referenced field are listed",
          {P, RT, R} <= set(got.behaviour), str(got.behaviour))
    check("an injected collaborator the step bodies never reference is NOT listed",
          U not in got.behaviour and U not in got.candidates["behaviour"])
    check("F1 drops a vendor type the project does not declare",
          V in got.candidates["behaviour"] and V not in got.behaviour)
    check("F2 drops a type whose declaring file the boundary calls retained",
          SS in got.candidates["behaviour"] and SS not in got.behaviour)
    check("T5 lists a type the body instantiates, and T6 one reached only "
          "through a private helper and one only through a used trait's method",
          {NW, HL, TR} <= set(got.behaviour), str(got.behaviour))
    check("T6 does not loop on a self-call, and a vendor body reference is "
          "filtered like any other",
          "Webmozart\\Assert\\Assert" in got.candidates["behaviour"]
          and "Webmozart\\Assert\\Assert" not in got.behaviour)
    check("T6 resolves a trait helper's call-back against the BOUND class: the "
          "class's override of the trait's abstract method is reached",
          CT in got.behaviour, str(got.behaviour))
    check("T6 resolves a trait helper's call to a sibling trait's helper "
          "through the class that uses both",
          AH in got.behaviour, str(got.behaviour))
    check("the behaviour list is exactly the eight, sorted and deduplicated",
          got.behaviour == sorted({P, RT, R, NW, HL, TR, CT, AH}), str(got.behaviour))
    check("a second extractor over the same inputs yields the same record",
          InterfaceExtractor(php_index, prod_index, b).for_item(item).to_json()
          == got.to_json())
    check("a differing index `root` is NOT a refusal: it is the analyzer's "
          "in-container path, the same constant for every index this "
          "pipeline builds, so a check over it would guard nothing",
          InterfaceExtractor(dict(php_index, root="/a"),
                             dict(prod_index, root="/b"), b)
          .for_item(item).behaviour == got.behaviour)
    check("a Background-only type goes to the setup list, and only there",
          got.setup == [BG] and BG not in got.behaviour
          and got.candidates["setup"] == [BG])
    check("a step answered by retained code contributes nothing",
          all(m["class"] != "I\\Infra" for m in got.members))
    check("the members record carries origin for every bound removable member",
          sorted((m["method"], m["origin"]) for m in got.members)
          == [("iAdd", "scenario"), ("site", "background"), ("total", "scenario")])
    check("a non-empty list has no empty_reason", got.empty_reason is None)

    only_bg = dict(item, steps=item["steps"][:2] + [item["steps"][-1]])
    e1 = ex.for_item(only_bg)
    check("no removable scenario member -> empty behaviour with its reason, "
          "setup still measured",
          e1.behaviour == [] and e1.setup == [BG]
          and e1.empty_reason == EMPTY_NO_MEMBER)
    vendor_only = {"files": {"test/glue/X.php": {"classes": [{
        "name": "G\\X", "constructor": [{"name": "om", "types": [V], "promoted": True}],
        "properties": [], "transforms": [],
        "steps": [{"method": "m", "kind": "Given", "pattern": "p", "line": 1,
                   "params": [], "return_types": [], "this_props": ["om"],
                   "body_refs": [], "this_calls": []}]}]}}}
    e2 = InterfaceExtractor(vendor_only, prod_index, b).for_item(
        {"item_id": "t/g.feature:1", "feature_file": "g", "scenario_line": 1,
         "steps": [step("s", "scenario", "G\\X", "m", "removable")]})
    check("members that declare no first-party type -> empty with the other reason",
          e2.behaviour == [] and e2.candidates["behaviour"] == [V]
          and e2.empty_reason == EMPTY_NO_DECLARATION)

    try:
        ex.for_item({"item_id": "t/h.feature:1", "feature_file": "h", "scenario_line": 1,
                     "steps": [step("s", "scenario", "G\\CartContext", "old", "removable")]})
        check("an index without this_props is refused, not approximated", False)
    except InterfacesError as e:
        check("an index without this_props is refused, not approximated",
              "this_props" in str(e) and "D3" in str(e))
    stale = {"files": {"test/glue/X.php": {"classes": [{
        "name": "G\\X", "constructor": [], "properties": [], "transforms": [],
        "steps": [{"method": "m", "kind": "Given", "pattern": "p", "line": 1,
                   "params": [], "return_types": [], "this_props": []}]}]}}}
    try:
        InterfaceExtractor(stale, prod_index, b).for_item(
            {"item_id": "t/i.feature:1", "feature_file": "i", "scenario_line": 1,
             "steps": [step("s", "scenario", "G\\X", "m", "removable")]})
        check("an index from before the body-reference edge is refused too", False)
    except InterfacesError as e:
        check("an index from before the body-reference edge is refused too",
              "body_refs" in str(e))
    try:
        ex.for_item({"item_id": "t/h.feature:2", "feature_file": "h", "scenario_line": 2,
                     "steps": [step("s", "scenario", "G\\Nope", "m", "removable")]})
        check("a bound member absent from the index is refused", False)
    except InterfacesError as e:
        check("a bound member absent from the index is refused", "absent" in str(e))

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p1, p2 = os.path.join(d, "a.json"), os.path.join(d, "b.json")
        write_interfaces(extract_all([item, only_bg], ex), p1)
        write_interfaces(extract_all([item, only_bg], ex), p2)
        with open(p1, "rb") as f1, open(p2, "rb") as f2:
            b1, b2 = f1.read(), f2.read()
        doc = json.loads(b1)
        check("re-extraction is byte-identical", b1 == b2)
        check("the artifact declares its schema and round-trips both lists",
              doc["schema"] == SCHEMA
              and doc["items"][0]["target_interfaces"]
              == {"behaviour": got.behaviour, "setup": got.setup})
    s = summary([got, e1])
    check("summary counts the empties by reason and both lists' sizes, with "
          "the lower median and the nearest-rank p90 (values that occur)",
          s["items"] == 2 and s["empty"][EMPTY_NO_MEMBER] == 1
          and s["empty"][EMPTY_NO_DECLARATION] == 0 and s["distinct"] == 9
          and s["behaviour"] == {"median": 0, "p90": 8, "max": 8}
          and s["setup"]["max"] == 1, str(s))
    # n = 10 is where the two candidate definitions disagree: the lower
    # median is the 5th value and nearest-rank p90 the 9th, while the
    # truncating `sizes[int(n * 0.9)]` this replaced returns the 10th.  A
    # fixture of two items cannot tell them apart, so the sizes are made
    # here rather than measured.
    ten = [ItemInterfaces(f"t/f.feature:{i}", "f", i,
                          behaviour=[f"P\\C{j}" for j in range(i)])
           for i in range(1, 11)]
    s10 = summary(ten)
    check("the median is the LOWER median and p90 the NEAREST-RANK value, "
          "not the truncating index they replaced",
          s10["behaviour"] == {"median": 5, "p90": 9, "max": 10},
          str(s10["behaviour"]))
    print("ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
