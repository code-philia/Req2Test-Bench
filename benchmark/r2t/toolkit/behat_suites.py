"""Which Behat suite an item belongs to, and the map that answers it.

CoreShop synthesises ONE suite for every item: its own suites partition
the corpus by component, but the contexts a scenario can reach are the
same set either way, so the harness registers the retained contexts plus
whatever the solution wrote and runs.  Sylius cannot be read that way.
Its 6919 distinct step texts hit more than one definition 3635 times —
the Api and Ui contexts are twins, same patterns, different bodies — so
"which definition answers this step" has no answer until you know WHICH
SUITE the scenario runs under.  All 1955 `@api` scenarios reach exactly
one of the 69 API suites (measured), and that suite is what makes the
binding single-valued.

So the strip writes the map down -- into the gold tree, beside the rest of
the answer -- and two readers use it: `closure.py` restricts an item's live
definitions to its suite's contexts, and `harness.py` registers that
suite's retained context ids.  Both ask the same question with the same
evaluator, which is the point of putting it here rather than in either of
them.

The evaluator is Behat's own `TagFilter`, not an approximation of it:
`&&` separates AND groups, `,` separates OR alternatives inside a group,
a leading `~` negates, and every `@` is stripped before comparison.  A
scenario that matches no arm suite is OUTSIDE the arm (the API arm does
not measure the UI corpus); a scenario that matches two is a refusal,
because Behat would run it under both and nothing here may pick one.

Tags are not the only thing Behat selects on, and on PrestaShop they are
not the thing at all: most of its suites carry no tag filter and are
separated by `paths` instead, so a tag-only selector would hand every
suite the same scenario.  A suite therefore matches when its filter
matches (or it has none) AND the item's feature file is under one of its
paths (or it declares none) -- which is what Behat itself runs.  A suite
with neither is still a match for nothing: that is the one shape whose
"matches everything" reading would be silent.
"""
from __future__ import annotations

import os
from typing import Optional

#: The schema string the suite map carries.
SUITE_MAP_SCHEMA = "r2t.behat-suite-map/1"

#: Its filename, at the root of the GOLD tree and nowhere else: a suite's
#: entry lists that suite's removable context service ids, so the map is
#: evidence and never workspace content (owner ruling 2026-09-10).
SUITE_MAP_NAME = "suite_map.json"


class SuiteSelectionRefused(RuntimeError):
    """Two arm suites claim one scenario.

    Behat would execute it under both, with two different context sets and
    therefore two different bindings, and a harness that picked one would
    be reporting a coin toss as a measurement.
    """


def matches_filter(expression: Optional[str], tags) -> bool:
    """Behat's `TagFilter` semantics, exactly.

    `explode('&&')` gives AND groups; inside a group `explode(',')` gives
    OR alternatives; `str_replace('@','')` then `~` negates.  An EMPTY or
    absent expression is False rather than "matches everything": Behat has
    no meaning for one (its own loop indexes `$tag[0]` and would fatal),
    and an arm suite with no filter that silently claimed every scenario
    is the failure this function exists to make impossible.
    """
    if not expression or not expression.strip():
        return False
    have = {str(t).replace("@", "").strip() for t in tags}
    have.discard("")
    for and_group in expression.split("&&"):
        satisfied = False
        for alternative in and_group.split(","):
            tag = alternative.replace("@", "").strip()
            if not tag:
                continue
            if tag.startswith("~"):
                satisfied = tag[1:] not in have or satisfied
            else:
                satisfied = tag in have or satisfied
        if not satisfied:
            return False
    return True


#: Behat's placeholder for the directory of the config file the run is
#: pointed at.
_PATHS_BASE = "%paths.base%"


def paths_base(bp) -> str:
    """Where `%paths.base%` points for this project, repo-relative.

    Behat resolves it against the config file it was given, which for a
    project whose suites live in one YAML file IS that file: PrestaShop's
    `tests/Integration/Behaviour/behat.yml` makes
    `%paths.base%/Features/Scenario/cart` mean
    `tests/Integration/Behaviour/Features/Scenario/cart`, which is how its
    own boundary census reads it.

    Sylius is the other shape -- a root `behat.dist.php` importing a
    suites tree -- so this would name the importing directory rather than
    the repository root there.  It resolves nothing on Sylius: not one of
    its 69 API suites declares `paths`, they are separated by tag filters,
    and a suite with no paths is unrestricted by path.
    """
    return os.path.dirname(
        os.path.join(bp.config_dir, bp.suites_entry)).replace(os.sep, "/")


def suite_path(path: str, base: str = "") -> str:
    """A suite `paths` entry as the map records it: repo-relative, `/`.

    Idempotent: a path the map already carries has no placeholder left,
    so re-normalising a recorded value is a no-op.
    """
    path = str(path).replace(os.sep, "/").strip()
    if path.startswith(_PATHS_BASE):
        rest = path[len(_PATHS_BASE):].strip("/")
        path = f"{base.strip('/')}/{rest}" if base.strip("/") else rest
    return path.strip("/")


def repo_relative(path: Optional[str], root: Optional[str]) -> Optional[str]:
    """A feature file's path in the same terms as `suite_path`.

    None in, None out: a caller with no path in hand asks for no path
    narrowing, and gets no suite that declares one.
    """
    if not path:
        return None
    rel = os.path.relpath(path, root) if root else path
    return rel.replace(os.sep, "/")


def selects_path(suite_paths, feature_path: Optional[str]) -> bool:
    """Is `feature_path` under one of a suite's paths?

    A suite that declares NO paths is unrestricted — that is Behat's own
    reading, and it is what keeps Sylius's selection what it was.  One
    that declares paths and is asked without a feature path selects
    nothing: the question it answers was not asked.  A path that is the
    repository root selects nothing for the same reason an empty tag
    filter does — it cannot tell one suite from another.
    """
    if not suite_paths:
        return True
    if not feature_path:
        return False
    for raw in suite_paths:
        declared = suite_path(raw)
        if declared and (feature_path == declared
                         or feature_path.startswith(declared + "/")):
            return True
    return False


def build_suite_map(suites: dict, services: dict, boundary, bp,
                    repo_root: str) -> dict:
    """The suites, their contexts and which side of the boundary each is on.

    `arm` is the suite whose own CONFIG FILE is removable — i.e. the
    suites this arm strips, which is exactly the set an item may be
    selected into.  That reading alone is too wide wherever the arm's own
    suites are not the only removable ones: Sylius's HYBRID suites are
    removable config because their DI names removable Api contexts, and an
    item whose scenario one of them claims was attributed to it instead of
    falling outside the API arm.  `bp.arm_suite_prefixes` names where the
    arm's own suite files live and narrows `arm` to those; unset, this is
    exactly the reading above.

    `retained`/`removable` split a suite's contexts by where their class
    file falls, so the harness knows which ids it may register as they are
    (`retained`) and which are the answer the system under test has to
    supply (`removable`).  `paths` is the other half of what Behat selects
    on, repo-relative so it compares directly against an item's feature
    file; Sylius's suites declare none and are selected by their tag
    filter alone, exactly as before.
    """
    from ..core.boundary import REMOVABLE, _matches
    from ..bench.repo import _class_path_guess
    from .behat_wiring import resolve_context_ref

    base = paths_base(bp)
    # Read exactly as a boundary prefix is read, by the same function.
    arm_prefixes = tuple(str(p).replace(os.sep, "/").lstrip("/")
                         for p in (bp.arm_suite_prefixes or ()))
    out: dict = {}
    for name in sorted(suites):
        suite = suites[name]
        rel = os.path.relpath(suite.file, repo_root).replace(os.sep, "/")
        contexts, retained, removable, classes = [], [], [], {}
        for ref in suite.contexts:
            contexts.append(ref)
            cls = resolve_context_ref(ref, services)
            if cls:
                classes[ref] = cls
            path = _class_path_guess(cls, bp.psr4) if cls else None
            if path and boundary.classify(path) == REMOVABLE:
                removable.append(ref)
            else:
                retained.append(ref)
        out[name] = {
            "file": rel,
            "arm": (boundary.classify(rel) == REMOVABLE
                    and (not arm_prefixes
                         or any(_matches(rel, p) for p in arm_prefixes))),
            "tag_filter": suite.tag_filter,
            "paths": [suite_path(p, base) for p in (suite.paths or [])],
            "contexts": contexts,
            "retained": retained,
            "removable": removable,
            "classes": classes,
        }
    return {"schema": SUITE_MAP_SCHEMA, "project": boundary.project,
            "suites": out}


def _suite_selects(body: dict, tags, feature_path: Optional[str]) -> bool:
    """Behat's two selectors, as Behat applies them: filter AND paths.

    A suite with neither selects NOTHING.  Behat would indeed run every
    scenario it was pointed at under such a suite, but a suite with
    nothing to select on cannot be told apart from any other, and an arm
    that silently claimed the whole corpus is the failure this module
    exists to make impossible.
    """
    tag_filter = body.get("tag_filter")
    paths = body.get("paths") or []
    if not tag_filter and not paths:
        return False
    if tag_filter and not matches_filter(tag_filter, tags):
        return False
    return selects_path(paths, feature_path)


def select_suite(suite_map: dict, tags,
                 feature_path: Optional[str] = None) -> Optional[str]:
    """The one ARM suite this item's tags and feature file select.

    `None` when there is none: the item is outside the arm, which for the
    Sylius API arm is what the UI, CLI and domain corpus is.  Two is a
    refusal — see `SuiteSelectionRefused`.

    `feature_path` is repo-relative (`repo_relative`).  Omitting it is not
    "any path": a suite that selects by directory is not selected at all
    without one, because choosing between such suites on tags they do not
    have would be a coin toss.
    """
    suites = suite_map.get("suites") or {}
    hits = [name for name in sorted(suites)
            if suites[name].get("arm")
            and _suite_selects(suites[name], tags, feature_path)]
    if not hits:
        return None
    if len(hits) > 1:
        raise SuiteSelectionRefused(
            f"REFUSED: tags {sorted(set(tags))} and feature "
            f"{feature_path!r} select {len(hits)} arm suites ({hits[:4]}). "
            f"Behat would run this scenario under each of them, with a "
            f"different context set and therefore a different step binding, "
            f"and the harness must not choose.")
    return hits[0]


def load_suite_map(path: str) -> dict:
    """Read a written map, refusing a schema this code does not answer for."""
    import json
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if doc.get("schema") != SUITE_MAP_SCHEMA:
        raise SuiteSelectionRefused(
            f"REFUSED: {path} carries schema {doc.get('schema')!r}, not "
            f"{SUITE_MAP_SCHEMA!r}.")
    return doc


def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refused(fn):
        try:
            fn()
        except SuiteSelectionRefused:
            return True
        return False

    # -- the evaluator, against Behat's own rules --------------------------
    api_book = ["@address_book", "@api"]
    check("`&&` is AND: both tags present is a match",
          matches_filter("@address_book&&@api", api_book))
    check("...and one missing is not",
          not matches_filter("@address_book&&@api", ["@api"])
          and not matches_filter("@address_book&&@api", ["@address_book"]))
    check("`,` is OR inside an AND group",
          matches_filter("@ui,@api&&@address_book", api_book)
          and matches_filter("@ui,@api&&@address_book",
                             ["@ui", "@address_book"])
          and not matches_filter("@ui,@api&&@address_book",
                                 ["@cli", "@address_book"]))
    check("a leading `~` negates",
          matches_filter("@api&&~@todo", api_book)
          and not matches_filter("@api&&~@todo", api_book + ["@todo"]))
    check("`@` is optional on both sides, and whitespace is ignored",
          matches_filter(" api && address_book ", api_book)
          and matches_filter("@api", ["api"]))
    check("an empty or absent filter matches nothing rather than everything",
          not matches_filter("", api_book) and not matches_filter(None, api_book)
          and not matches_filter("   ", api_book))

    # -- the map, and selection over it ------------------------------------
    from ..core.boundary import Boundary
    from ..bench.repo import BehatProject
    from .behat_wiring import ServiceDef, SuiteDef

    cfg = "src/Demo/Behat/Resources/config"
    b = Boundary(version=1, project="demo", repo_root="/x",
                 removable=[("src/Demo/Behat/Context/Api/", ""),
                            (f"{cfg}/suites/api/", ""),
                            (f"{cfg}/suites/hybrid/", ""),
                            (f"{cfg}/services/contexts/api.php", "")],
                 retained=[("src/Demo/Behat/Context/Setup/", ""),
                           ("src/Demo/Behat/Context/Hook/", "")],
                 removable_config=[f"{cfg}/suites/api/",
                                   f"{cfg}/suites/hybrid/",
                                   f"{cfg}/services/contexts/api.php"])
    bp = BehatProject(psr4=(("Demo\\Behat\\", "src/Demo/Behat/"),))
    services = {
        "demo.context.hook.orm": ServiceDef(
            id="demo.context.hook.orm", file="x",
            cls="Demo\\Behat\\Context\\Hook\\DoctrineORMContext"),
        "demo.context.setup.address": ServiceDef(
            id="demo.context.setup.address", file="x",
            cls="Demo\\Behat\\Context\\Setup\\AddressContext"),
        "demo.context.api.shop.address": ServiceDef(
            id="demo.context.api.shop.address", file="x",
            cls="Demo\\Behat\\Context\\Api\\Shop\\AddressContext"),
    }
    root = "/x"
    suites = {
        "api_address_book": SuiteDef(
            name="api_address_book",
            file=f"{root}/{cfg}/suites/api/account/address_book.php",
            contexts=["demo.context.hook.orm", "demo.context.setup.address",
                      "demo.context.api.shop.address"],
            tag_filter="@address_book&&@api"),
        "api_customer": SuiteDef(
            name="api_customer",
            file=f"{root}/{cfg}/suites/api/account/customer.php",
            contexts=["demo.context.api.shop.address"],
            tag_filter="@customer&&@api"),
        "ui_address_book": SuiteDef(
            name="ui_address_book",
            file=f"{root}/{cfg}/suites/ui/address_book.php",
            contexts=["demo.context.setup.address"],
            tag_filter="@address_book&&@ui"),
        # Sylius's HYBRID shape: a suite that drives the UI and asserts
        # over the API, so its own config is removable_config (it names a
        # removable Api context) while the suite is not one of the API
        # arm's own.
        "hybrid_shopping_cart": SuiteDef(
            name="hybrid_shopping_cart",
            file=f"{root}/{cfg}/suites/hybrid/shopping_cart.php",
            contexts=["demo.context.setup.address",
                      "demo.context.api.shop.address"],
            tag_filter="@shopping_cart&&@api"),
    }
    m = build_suite_map(suites, services, b, bp, root)

    check("the map declares its schema and its project",
          m["schema"] == SUITE_MAP_SCHEMA and m["project"] == "demo", str(m)[:120])
    check("a suite whose config file is removable is an ARM suite",
          m["suites"]["api_address_book"]["arm"] is True
          and m["suites"]["api_customer"]["arm"] is True)
    check("...and one whose file survives the strip is not",
          m["suites"]["ui_address_book"]["arm"] is False)
    check("with no `arm_suite_prefixes` that is the whole rule, so a HYBRID "
          "suite -- removable config because its DI names a removable Api "
          "context -- counts as an arm suite and claims its item",
          m["suites"]["hybrid_shopping_cart"]["arm"] is True
          and select_suite(m, ["@shopping_cart", "@api"])
          == "hybrid_shopping_cart")

    pref = build_suite_map(
        suites, services, b,
        BehatProject(psr4=(("Demo\\Behat\\", "src/Demo/Behat/"),),
                     arm_suite_prefixes=(f"{cfg}/suites/api/",)),
        root)
    check("naming the ARM's own suite directory keeps the api suites and "
          "drops the hybrid one, which is what puts its item outside the "
          "arm rather than under a suite the arm does not strip",
          [name for name in sorted(pref["suites"])
           if pref["suites"][name]["arm"]]
          == ["api_address_book", "api_customer"]
          and select_suite(pref, ["@shopping_cart", "@api"]) is None,
          str({n: pref["suites"][n]["arm"] for n in sorted(pref["suites"])}))
    check("...and nothing else about the map moves: only `arm` reads the "
          "prefixes",
          [dict(body, arm=None) for _n, body in sorted(pref["suites"].items())]
          == [dict(body, arm=None) for _n, body in sorted(m["suites"].items())])
    book = m["suites"]["api_address_book"]
    check("contexts are captured in suite order",
          book["contexts"] == ["demo.context.hook.orm",
                               "demo.context.setup.address",
                               "demo.context.api.shop.address"],
          str(book["contexts"]))
    check("retained/removable split the contexts by where their CLASS FILE "
          "falls, through the project's own PSR-4 roots",
          book["retained"] == ["demo.context.hook.orm",
                               "demo.context.setup.address"]
          and book["removable"] == ["demo.context.api.shop.address"],
          str((book["retained"], book["removable"])))
    check("every context's class is recorded, which is what restricts an "
          "item's live step definitions",
          book["classes"]["demo.context.api.shop.address"]
          == "Demo\\Behat\\Context\\Api\\Shop\\AddressContext")
    check("the suite file is repo-relative, so the map is portable between "
          "the repo and the gold tree",
          book["file"] == f"{cfg}/suites/api/account/address_book.php",
          book["file"])

    check("an item's tags select exactly its arm suite",
          select_suite(m, ["@address_book", "@api"]) == "api_address_book"
          and select_suite(m, ["@customer", "@api"]) == "api_customer")
    check("a UI scenario selects nothing — it is outside the arm, and the "
          "release excludes it rather than guessing",
          select_suite(m, ["@address_book", "@ui"]) is None)
    check("...and so does a scenario with no tag the arm knows",
          select_suite(m, []) is None)

    two = dict(m)
    two["suites"] = dict(m["suites"])
    two["suites"]["api_duplicate"] = dict(book, tag_filter="@address_book&&@api")
    check("two arm suites claiming one scenario is a refusal, not a choice",
          refused(lambda: select_suite(two, ["@address_book", "@api"])))
    check("a suite that declares no paths is selected by its tags whatever "
          "the item's feature file is -- which is every Sylius suite, and "
          "why passing the path changes nothing there",
          select_suite(m, ["@address_book", "@api"],
                       "features/api/shop/address.feature")
          == "api_address_book")

    # -- the OTHER shape: YAML suites, contexts named by class, no DI, and
    #    suites separated by PATHS rather than by tags (PrestaShop's 57
    #    suites, most of which carry no tag filter at all).
    import tempfile as _tempfile
    from .behat_wiring import load_suites

    with _tempfile.TemporaryDirectory() as proot:
        beh = "tests/Integration/Behaviour"
        cctx = "Tests\\Integration\\Behaviour\\Features\\Context"
        os.makedirs(os.path.join(proot, beh))
        with open(os.path.join(proot, beh, "behat.yml"), "w",
                  encoding="utf-8") as fh:
            fh.write(f"""default:
  suites:
    cart:
      paths: [ '%paths.base%/Features/Scenario/cart' ]
      contexts:
        - {cctx}\\CommonFeatureContext
        - {cctx}\\Domain\\CartContext
    order:
      paths: [ '%paths.base%/Features/Scenario/order' ]
      contexts:
        - {cctx}\\CommonFeatureContext
        - {cctx}\\Domain\\OrderContext
""")
        pb = Boundary(
            version=1, project="prestashop", repo_root=proot,
            removable=[(f"{beh}/Features/Context/Domain/", ""),
                       (f"{beh}/behat.yml", "")],
            retained=[(f"{beh}/Features/Context/CommonFeatureContext.php",
                       "")],
            removable_config=[f"{beh}/behat.yml"])
        pbp = BehatProject(
            config_dir=beh, suites_entry="behat.yml", services_entry=None,
            hook_services=None, test_config=None,
            original_services_import=None, bench_services_import=None,
            psr4=(("Tests\\Integration\\Behaviour\\", f"{beh}/"),),
            suite_scoped=True)
        pm = build_suite_map(
            load_suites(os.path.join(proot, beh, "behat.yml")), {}, pb, pbp,
            proot)

        cart = pm["suites"]["cart"]
        check("[paths] a suite's paths are recorded repo-relative, with "
              "`%paths.base%` resolved against the config file that "
              "declares them -- which is how this project's own boundary "
              "census reads them",
              cart["paths"] == [f"{beh}/Features/Scenario/cart"],
              str(cart["paths"]))
        check("[paths] contexts named by CLASS resolve with no service "
              "definitions at all, and still split by the boundary",
              cart["classes"][f"{cctx}\\Domain\\CartContext"]
              == f"{cctx}\\Domain\\CartContext"
              and cart["removable"] == [f"{cctx}\\Domain\\CartContext"]
              and cart["retained"] == [f"{cctx}\\CommonFeatureContext"],
              str((cart["retained"], cart["removable"])))
        check("[paths] both suites are arm suites: the file that declares "
              "them is what the strip removes",
              all(pm["suites"][n]["arm"] for n in ("cart", "order"))
              and all(pm["suites"][n]["tag_filter"] is None
                      for n in ("cart", "order")))

        feature = f"{beh}/Features/Scenario/cart/add_product.feature"
        check("[paths] an untagged item is selected by the directory its "
              "feature file is in",
              select_suite(pm, [], feature) == "cart"
              and select_suite(
                  pm, [], f"{beh}/Features/Scenario/order/pay.feature")
              == "order", str(select_suite(pm, [], feature)))
        check("[paths] the prefix is a DIRECTORY prefix, not a string one: "
              "`cart_rules` is not `cart`",
              select_suite(
                  pm, [], f"{beh}/Features/Scenario/cart_rules/x.feature")
              is None)
        check("[paths] a feature under no suite's paths selects nothing, "
              "which is the item being outside the arm",
              select_suite(pm, [], "tests/Other/x.feature") is None)
        check("[paths] and a path-selected suite is not selected without a "
              "path: tags it does not have cannot choose between two of "
              "them",
              select_suite(pm, []) is None
              and select_suite(pm, ["@cart"]) is None)

        wide = dict(pm)
        wide["suites"] = dict(pm["suites"], everything=dict(
            cart, paths=[f"{beh}/Features/Scenario"]))
        check("[paths] two arm suites whose paths both contain the feature "
              "is the same refusal a double tag match is",
              refused(lambda: select_suite(wide, [], feature)))
        blind = dict(pm)
        blind["suites"] = dict(pm["suites"],
                               everything=dict(cart, paths=[]))
        check("[paths] a suite with neither a tag filter nor paths claims "
              "nothing rather than everything, so it does not turn every "
              "item into an ambiguity: `cart` is still the single answer",
              select_suite(blind, [], feature) == "cart"
              and select_suite(blind, [], "tests/Other/x.feature") is None)

    import json
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, SUITE_MAP_NAME)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(m, fh)
        check("a written map round-trips",
              select_suite(load_suite_map(path), ["@api", "@customer"])
              == "api_customer")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(dict(m, schema="r2t.behat-suite-map/9"), fh)
        check("a map written under another schema is refused rather than "
              "read", refused(lambda: load_suite_map(path)))

    print("\n" + ("ALL PASS (behat_suites)" if ok else "FAILURES (behat_suites)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
