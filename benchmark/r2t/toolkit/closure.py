"""S3 — the per-scenario ground-truth closure, for PHP/Behat.

ART computes this for Python with a language server and for Java with a
type-reference pass; PHP has neither in ART, and CoreShop adds a problem
neither language had: **contexts receive their collaborators through
Symfony DI**, so a step definition's dependencies are not visible in its
own source at all.

    final class CartContext implements Context {
        public function __construct(private CartContextInterface $cart) {}

The closure therefore runs over three edge kinds, seeded by Behat's own
step matcher:

  seeds       every step definition matching a step of the scenario —
              **including its Background steps**, which the scenario
              cannot run without — plus every `@Transform` whose pattern
              matches one of those steps' captured arguments.
  code edges  extends / implements / traits / any fully-qualified class
              the file references (from nikic/php-parser NameResolver,
              so `use`-aliases are already resolved).
  DI edges    for a seeded class, the service definition that registers
              it; each `@service` argument whose target class is itself
              test code is followed.

Expansion stops at the boundary (`boundary.py`): production classes are
recorded as dependencies but never recursed into — the same rule as
ART, whose product-side closure is depth-1 while the test side is
transitive.

The result is FILE-granular, not method-granular.  ART's Python closure
is function-granular because Pyright can resolve a symbol to its
definition; the PHP index resolves class names only.  A file-granular
gold set is a strictly larger ground truth, which the §5 round-trip gate
then has to justify: if the file set does not make the scenario pass,
the item is excluded rather than silently shipped.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from ..core.boundary import Boundary, REMOVABLE, RETAINED
from ..core.gherkin import Block, Feature


@dataclass
class StepBinding:
    text: str
    origin: str                 # "background" | "scenario"
    keyword: str
    definition: Optional[dict]  # {file,class,method,kind,pattern,captures}
    side: Optional[str]         # removable | retained | production | None


@dataclass
class ItemClosure:
    item_id: str
    feature_file: str
    scenario_line: int
    steps: list[StepBinding] = field(default_factory=list)
    files: list[str] = field(default_factory=list)          # removable, to restore
    retained_files: list[str] = field(default_factory=list)  # touched but kept
    classes: list[str] = field(default_factory=list)         # removable classes
    context_classes: list[str] = field(default_factory=list)  # Behat contexts to register
    di_fragment: dict[str, dict] = field(default_factory=dict)
    production_deps: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    #: The arm suite this item runs under, on a project whose suites
    #: partition the corpus by tags (`behat_suites.select_suite`).  None
    #: for CoreShop, which synthesises one suite for every item -- and
    #: emitted by `to_json` only when set, so CoreShop's closure bytes are
    #: what they always were.
    suite: Optional[str] = None

    # -- measured properties the inclusion rule and the paper both need --
    @property
    def n_steps(self) -> int:
        return len(self.steps)

    @property
    def n_steps_removable(self) -> int:
        return sum(1 for s in self.steps if s.side == REMOVABLE)

    @property
    def n_steps_retained(self) -> int:
        return sum(1 for s in self.steps if s.side == RETAINED)

    @property
    def n_steps_unmatched(self) -> int:
        return sum(1 for s in self.steps if s.definition is None)

    @property
    def answered_entirely_by_retained(self) -> bool:
        """No removable step definition is involved.

        Such an item still passes in the stripped repo, so it cannot
        measure generation; §5's must-fail leg rejects it and this flag
        predicts that before any run.
        """
        return self.n_steps > 0 and self.n_steps_removable == 0

    def to_json(self) -> dict:
        doc = {
            "item_id": self.item_id,
            "feature_file": self.feature_file,
            "scenario_line": self.scenario_line,
            "files": self.files,
            "retained_files": self.retained_files,
            "classes": self.classes,
            "context_classes": self.context_classes,
            "di_fragment": self.di_fragment,
            "production_deps": self.production_deps,
            "problems": self.problems,
            "steps": [{"text": s.text, "origin": s.origin, "keyword": s.keyword,
                       "side": s.side,
                       "definition": (None if s.definition is None else {
                           k: s.definition[k]
                           for k in ("file", "class", "method", "kind", "pattern")})}
                      for s in self.steps],
            "counts": {
                "steps": self.n_steps,
                "steps_removable": self.n_steps_removable,
                "steps_retained": self.n_steps_retained,
                "steps_unmatched": self.n_steps_unmatched,
                "files": len(self.files),
                "context_classes": len(self.context_classes),
            },
            "answered_entirely_by_retained": self.answered_entirely_by_retained,
        }
        if self.suite is not None:
            doc["suite"] = self.suite
        return doc


class ClosureExtractor:
    def __init__(self, php_index: dict, matches: dict, boundary: Boundary,
                 services: Optional[dict] = None,
                 registered_classes: Optional[set[str]] = None,
                 suite_map: Optional[dict] = None):
        self.index = php_index
        self.matches = matches
        self.boundary = boundary
        self.services = services or {}
        # Behat only ever sees definitions belonging to a context that some
        # suite registers.  CoreShop ships two context classes that no suite
        # wires (Behat's own Hook\DoctrineORMContext, and
        # Transform\PimcoreClassContext with its 12 @Transform rules); left
        # in the universe they contaminate 69 closures with a file Behat
        # would never load.  `registered_classes` is that universe, taken
        # from the ORIGINAL suite configuration.
        self.registered_classes = registered_classes
        #: Per-ITEM narrowing of the same universe, for a project whose
        #: suites partition the corpus by tags.  Sylius's Api and Ui
        #: contexts are twins -- 3635 of 6919 step texts match in both --
        #: so "which definition answers this step" has no answer until the
        #: item's suite is known.  None (and no narrowing at all) for a
        #: project that synthesises one suite for every item.
        self.suite_map = suite_map
        self._item_classes: Optional[set[str]] = None
        #: Contexts the synthesised suite registers for EVERY item.
        self.always_registered = set(boundary.retained_contexts or ())

        self.class_file: dict[str, str] = {}
        self.class_info: dict[str, dict] = {}
        for path, finfo in php_index["files"].items():
            for c in finfo["classes"]:
                self.class_file[c["name"]] = path
                self.class_info[c["name"]] = c
        self.file_refs: dict[str, list[str]] = {
            p: f["refs"] for p, f in php_index["files"].items()}

        # class -> [service ids] over the ORIGINAL wiring
        self.services_by_class: dict[str, list[str]] = {}
        for sid, sd in self.services.items():
            if getattr(sd, "cls", None):
                self.services_by_class.setdefault(sd.cls, []).append(sid)

    # ------------------------------------------------------------ seeding
    def _live(self, hits: list[dict]) -> list[dict]:
        allowed = (self._item_classes if self._item_classes is not None
                   else self.registered_classes)
        if allowed is None:
            return hits
        return [h for h in hits if h["class"] in allowed]

    def _with_traits(self, classes: set[str]) -> set[str]:
        """The same classes, plus every TRAIT they use, transitively.

        A step a context gets from a trait is one of that context's own
        methods as far as Behat is concerned, but the index records the
        definition under the TRAIT's name -- that is the class the
        attribute is written in.  So a live set of context classes alone
        drops it: `ManagingChannelsContext` answers `I should be notified
        that :field is too long` from
        `Api\\Admin\\Helper\\ValidationTrait`, and 24 of Sylius's 1956 API
        items reported `unmatched_step` for exactly those.

        Adding the traits does not un-narrow the set: the Api and Ui
        `ValidationTrait`s are twins with the same three patterns, and an
        item still reaches only the one its suite's contexts use.

        Transitive because a trait may itself `use` a trait.
        """
        out = set(classes)
        queue = list(out)
        while queue:
            info = self.class_info.get(queue.pop())
            for name in (info or {}).get("traits") or []:
                name = name.lstrip("\\")
                if name and name not in out:
                    out.add(name)
                    queue.append(name)
        return out

    def _prefer_retained(self, hits: list[dict]) -> list[dict]:
        """Drop a removable provider when the retained substrate provides
        the SAME pattern.

        CoreShop ships `Behat\Context\Transform\SharedStorageContext` and
        `TestBundle\Context\Transform\SharedStorageContext` with identical
        transform patterns; the domain suites register the TestBundle one.
        Since the synthesised suite ALWAYS registers the retained contexts,
        a removable twin is never the definition Behat would reach — and
        putting it in the gold closure made 105 items ask the system under
        test for a file it does not need.  The gate cannot catch this:
        over-approximation still passes.
        """
        if not self.always_registered:
            return hits
        by_pattern: dict[str, list[dict]] = {}
        for h in hits:
            by_pattern.setdefault(h["pattern"], []).append(h)
        out = []
        for _pattern, group in by_pattern.items():
            retained = [h for h in group if h["class"] in self.always_registered]
            out.extend(retained or group)
        return out

    def bind_steps(self, feature: Feature, scenario: Block) -> list[StepBinding]:
        out: list[StepBinding] = []
        blocks: list[tuple[str, Block]] = []
        if feature.background is not None:
            blocks.append(("background", feature.background))
        blocks.append(("scenario", scenario))
        for origin, blk in blocks:
            for st in blk.steps:
                hits = self._prefer_retained(
                    self._live(self.matches["steps"].get(st.text, [])))
                if len(hits) == 1:
                    d = hits[0]
                    out.append(StepBinding(st.text, origin, st.resolved, d,
                                           self.boundary.classify(d["file"])))
                elif not hits:
                    out.append(StepBinding(st.text, origin, st.resolved, None, None))
                else:
                    # Behat itself raises AmbiguousMatchException here.
                    b = StepBinding(st.text, origin, st.resolved, hits[0],
                                    self.boundary.classify(hits[0]["file"]))
                    out.append(b)
        return out

    def _transform_classes(self, steps: list[StepBinding]) -> set[str]:
        want: set[str] = set()
        for s in steps:
            if not s.definition:
                continue
            for cap in s.definition.get("captures", []) or []:
                for t in self._prefer_retained(
                        self._live(self.matches["transforms"].get(str(cap), []))):
                    want.add(t["class"])
        return want

    # ---------------------------------------------------------- expansion
    def _service_class(self, sid: str) -> Optional[str]:
        """The concrete class a service id resolves to, following aliases.

        CoreShop wires most of its Behat collaborators by interface:
        `…\\LoginPageInterface: '@…\\LoginPage'`.  Behat's YAML calls that an
        alias, and `ServiceDef.cls` is None for one — so reading `.cls`
        directly silently dropped the edge and the closure never reached the
        implementing class.  A type checker cannot recover this; the container
        is the only thing that knows WHICH implementor is injected, which is
        also why no language server would have helped.

        The chain is followed with a seen-set: Symfony rejects a cyclic alias
        at compile time, but this code also runs against fragments a solution
        supplied, which are not compiled first.
        """
        seen: set[str] = set()
        while sid and sid not in seen:
            seen.add(sid)
            sd = self.services.get(sid)
            if sd is None:
                # Not a declared service: an FQCN used as its own id.
                return sid if "\\" in sid else None
            if getattr(sd, "cls", None):
                return sd.cls
            nxt = getattr(sd, "alias_of", None)
            if not nxt:
                return None
            sid = nxt.lstrip("@?")
        return None

    def expand(self, seeds: set[str]) -> tuple[set[str], set[str], set[str]]:
        """(removable classes, retained classes touched, production deps)."""
        removable: set[str] = set()
        retained: set[str] = set()
        production: set[str] = set()
        queue = list(seeds)
        # `_service_class` resolves an argument's service id to a concrete
        # class, following `id: '@other'` aliases — see there for why.
        seen: set[str] = set()
        while queue:
            fqcn = queue.pop()
            if fqcn in seen:
                continue
            seen.add(fqcn)
            path = self.class_file.get(fqcn)
            if path is None:
                # Not in the index: production, vendor, or a PHP builtin.
                production.add(fqcn)
                continue
            side = self.boundary.classify(path)
            if side == RETAINED:
                retained.add(fqcn)
                continue          # a stable substrate: do not recurse
            if side != REMOVABLE:
                production.add(fqcn)
                continue
            removable.add(fqcn)

            info = self.class_info[fqcn]
            nxt: set[str] = set()
            nxt.update(info.get("extends") or [])
            nxt.update(info.get("implements") or [])
            nxt.update(info.get("traits") or [])
            for p in info.get("constructor") or []:
                nxt.update(p.get("types") or [])
            nxt.update(self.file_refs.get(path, []))
            for sid in self.services_by_class.get(fqcn, []):
                sd = self.services[sid]
                for arg in getattr(sd, "arguments", []) or []:
                    if isinstance(arg, str) and arg.startswith("@"):
                        cls = self._service_class(arg.lstrip("@?"))
                        if cls:
                            nxt.add(cls)
            for n in nxt:
                n = n.lstrip("\\")
                if n and n not in seen:
                    queue.append(n)
        return removable, retained, production

    # ------------------------------------------------------------- driver
    def closure_for(self, item_id: str, feature: Feature,
                    scenario: Block) -> ItemClosure:
        from .behat_suites import repo_relative, select_suite
        # `cmd_closures` walks the boundary's repository root and hands the
        # parser an ABSOLUTE path, so `feature.path` is one.  What a closure
        # records is the repo-relative spelling: the sidecar is read on a
        # worker, against a workspace that is not the tree it was extracted
        # from, and `validate.validate_item` refuses an absolute one by name
        # ("closure feature_file must be repo-relative").  The Python and
        # Ruby extractors already relativise here; this one did not, and the
        # first Sylius `validate` run refused every item for it.
        feature_file = repo_relative(feature.path, self.boundary.repo_root)
        suite = None
        if self.suite_map is not None:
            tags = list(feature.tags) + list(scenario.tags)
            # The other half of what Behat selects on -- the same relative
            # spelling, which is what the suite map's `paths` compare
            # against.
            suite = select_suite(self.suite_map, tags, feature_file)
            if suite is None:
                # Outside the arm. Not a defect and not an empty answer to
                # a real question: the API arm does not measure the UI
                # corpus, and the release excludes such an item by refusal
                # rather than shipping a closure nothing could satisfy.
                cl = ItemClosure(item_id=item_id, feature_file=feature_file,
                                 scenario_line=scenario.line)
                cl.problems.append(f"no_suite: {' '.join(tags)}")
                return cl
            self._item_classes = self._with_traits(set(
                (self.suite_map["suites"][suite].get("classes")
                 or {}).values()))
        try:
            return self._closure_for(item_id, feature, scenario, suite,
                                     feature_file)
        finally:
            self._item_classes = None

    def _closure_for(self, item_id: str, feature: Feature, scenario: Block,
                     suite: Optional[str], feature_file: str) -> ItemClosure:
        steps = self.bind_steps(feature, scenario)
        cl = ItemClosure(item_id=item_id,
                         feature_file=feature_file,
                         scenario_line=scenario.line,
                         steps=steps, suite=suite)

        seeds = {s.definition["class"] for s in steps
                 if s.definition and s.side == REMOVABLE}
        for c in self._transform_classes(steps):
            if self.boundary.classify(self.class_file.get(c, "")) == REMOVABLE:
                seeds.add(c)

        removable, retained, production = self.expand(seeds)

        cl.classes = sorted(removable)
        cl.files = sorted({self.class_file[c] for c in removable})
        cl.retained_files = sorted({self.class_file[c] for c in retained})
        cl.production_deps = sorted(production)
        cl.context_classes = sorted(
            c for c in removable
            if self.class_info[c].get("is_context")
            and self.class_info[c].get("kind") == "class"
            and not self.class_info[c].get("abstract"))

        for c in removable:
            for sid in self.services_by_class.get(c, []):
                sd = self.services[sid]
                cl.di_fragment[sid] = {
                    "class": sd.cls,
                    "arguments": list(getattr(sd, "arguments", []) or []),
                    "tags": list(getattr(sd, "tags", []) or []),
                }

        for s in steps:
            if s.definition is None:
                cl.problems.append(f"unmatched_step: {s.text}")
        from ..bench.repo import behat_project
        if behat_project(self.boundary).services_entry is not None:
            for c in cl.context_classes:
                if not self.services_by_class.get(c):
                    cl.problems.append(f"context_without_service_definition: {c}")
        return cl


def load_extractor(index_path: str, matches_path: str, boundary_path: str,
                   services_entry: Optional[str] = None,
                   suites_entry: Optional[str] = None,
                   repo_root: Optional[str] = None,
                   suite_map_path: Optional[str] = None) -> ClosureExtractor:
    from .behat_wiring import load_services, load_suites, resolve_context_ref
    from ..core.boundary import load_boundary

    with open(index_path, encoding="utf-8") as fh:
        index = json.load(fh)
    with open(matches_path, encoding="utf-8") as fh:
        matches = json.load(fh)
    b = load_boundary(boundary_path, repo_root=repo_root)
    services = load_services(services_entry) if services_entry else {}

    registered = None
    suite_map = None
    if suites_entry:
        suites = load_suites(suites_entry)
        registered = set()
        for suite in suites.values():
            for ref in suite.contexts:
                cls = resolve_context_ref(ref, services)
                if cls:
                    registered.add(cls)
        # A suite-scoped project narrows that universe PER ITEM, and the
        # map it narrows through is built from the same two entries the
        # universe above came from -- the strip's own gold `suite_map.json`
        # is that same structure, written for the harness, which has no
        # config tree to read.
        from ..bench.repo import behat_project
        bp = behat_project(b)
        if bp.suite_scoped:
            from .behat_suites import build_suite_map, load_suite_map
            if suite_map_path and os.path.isfile(suite_map_path):
                # AFTER a strip the arm's suite files are in gold and the
                # rest are still in the repository, so neither root can be
                # read for the whole set. The strip wrote the map while the
                # tree was still whole; that is the answer here.
                suite_map = load_suite_map(suite_map_path)
            else:
                # BEFORE the strip: the same structure, from the same two
                # entries, built by the same function the strip calls.
                # `repo_root` is where those entries were read from, and the
                # suite file paths are recorded relative to it.
                tail = os.path.join(bp.config_dir, bp.suites_entry)
                entry = os.path.abspath(suites_entry)
                root = (entry[:-len(tail)].rstrip(os.sep)
                        if entry.endswith(tail) else b.repo_root)
                suite_map = build_suite_map(suites, services, b, bp, root)
    return ClosureExtractor(index, matches, b, services, registered, suite_map)


def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    from .behat_wiring import ServiceDef
    from ..core.boundary import Boundary
    from ..core.gherkin import parse_feature_file

    b = Boundary(version=1, project="t", repo_root="/x",
                 removable=[("test/glue/", "")],
                 retained=[("test/infra/", "")])

    index = {"files": {
        "test/glue/CartContext.php": {
            "namespace": "G", "uses": {}, "refs": ["G\\Helper", "Prod\\Service",
                                                   "I\\Infra"],
            "classes": [{"name": "G\\CartContext", "kind": "class", "abstract": False,
                         "extends": [], "implements": ["Behat\\Behat\\Context\\Context"],
                         "traits": [], "is_context": True,
                         "constructor": [{"name": "h", "types": ["G\\Helper"]}],
                         "steps": [{"method": "m", "kind": "Then",
                                    "pattern": "/^total is \"([^\"]+)\"$/",
                                    "line": 1, "params": []}],
                         "transforms": [], "line": 1}]},
        "test/glue/Helper.php": {
            "namespace": "G", "uses": {}, "refs": ["G\\Deep"],
            "classes": [{"name": "G\\Helper", "kind": "class", "abstract": False,
                         "extends": [], "implements": [], "traits": [],
                         "is_context": False, "constructor": [], "steps": [],
                         "transforms": [], "line": 1}]},
        "test/glue/Deep.php": {
            "namespace": "G", "uses": {}, "refs": [],
            "classes": [{"name": "G\\Deep", "kind": "class", "abstract": False,
                         "extends": [], "implements": [], "traits": [],
                         "is_context": False, "constructor": [], "steps": [],
                         "transforms": [], "line": 1}]},
        "test/glue/CartTransform.php": {
            "namespace": "G", "uses": {}, "refs": [],
            "classes": [{"name": "G\\CartTransform", "kind": "class", "abstract": False,
                         "extends": [], "implements": ["Behat\\Behat\\Context\\Context"],
                         "traits": [], "is_context": True, "constructor": [],
                         "steps": [],
                         "transforms": [{"method": "t", "pattern": "/^my cart$/",
                                         "line": 3, "params": [],
                                         "return_types": []}], "line": 1}]},
        "test/infra/Purger.php": {
            "namespace": "I", "uses": {}, "refs": ["G\\NeverFollowed"],
            "classes": [{"name": "I\\Infra", "kind": "class", "abstract": False,
                         "extends": [], "implements": [], "traits": [],
                         "is_context": False, "constructor": [], "steps": [
                             {"method": "bg", "kind": "Given",
                              "pattern": "/^the site exists$/", "line": 2,
                              "params": []}],
                         "transforms": [], "line": 1}]},
    }}
    matches = {
        "steps": {
            "the site exists": [{"file": "test/infra/Purger.php", "class": "I\\Infra",
                                 "method": "bg", "kind": "Given",
                                 "pattern": "/^the site exists$/", "captures": []}],
            'total is "5"': [{"file": "test/glue/CartContext.php", "class": "G\\CartContext",
                              "method": "m", "kind": "Then",
                              "pattern": "/^total is \"([^\"]+)\"$/",
                              "captures": ["5"]}],
            "I look at my cart": [{"file": "test/glue/CartContext.php",
                                   "class": "G\\CartContext", "method": "m2",
                                   "kind": "When", "pattern": "/^I look at (my cart)$/",
                                   "captures": ["my cart"]}],
            "nothing matches this": [],
        },
        "transforms": {
            "my cart": [{"file": "test/glue/CartTransform.php",
                         "class": "G\\CartTransform", "method": "t",
                         "pattern": "/^my cart$/"}],
        },
    }
    services = {
        "svc.cart": ServiceDef(id="svc.cart", file="x", cls="G\\CartContext",
                               arguments=["@svc.helper"]),
        "svc.helper": ServiceDef(id="svc.helper", file="x", cls="G\\Helper"),
        "svc.transform": ServiceDef(id="svc.transform", file="x",
                                    cls="G\\CartTransform"),
    }

    src = """Feature: F

  Background:
    Given the site exists

  Scenario: Totals
    When I look at my cart
    Then total is "5"
"""
    # ABSOLUTE, the way `cmd_closures` hands it over: it walks
    # `os.path.join(b.repo_root, args.features)`.  The closure records the
    # repo-relative spelling, and the checks below say so.
    feat = parse_feature_file("/x/f.feature", src)
    ex = ClosureExtractor(index, matches, b, services)
    cl = ex.closure_for("t/f.feature:6", feat, feat.scenarios[0])

    check("background step is bound", cl.steps[0].origin == "background")
    check("background step is retained-side", cl.steps[0].side == RETAINED)
    check("scenario steps bound to removable",
          cl.n_steps_removable == 2 and cl.n_steps_retained == 1,
          f"{cl.n_steps_removable}/{cl.n_steps_retained}")
    check("closure includes the seed context",
          "G\\CartContext" in cl.classes)
    check("closure follows a code reference (Helper)",
          "G\\Helper" in cl.classes, str(cl.classes))
    check("closure is transitive (Deep behind Helper)",
          "G\\Deep" in cl.classes, str(cl.classes))
    check("closure includes the transform context",
          "G\\CartTransform" in cl.classes, str(cl.classes))
    check("retained code is recorded but NOT recursed into",
          "I\\Infra" not in cl.classes
          and "G\\NeverFollowed" not in cl.classes, str(cl.classes))
    check("production dependency recorded, not followed",
          "Prod\\Service" in cl.production_deps, str(cl.production_deps))
    check("files are the removable files only",
          set(cl.files) == {"test/glue/CartContext.php", "test/glue/Helper.php",
                            "test/glue/Deep.php", "test/glue/CartTransform.php"},
          str(cl.files))
    check("contexts to register are the Context implementors",
          cl.context_classes == ["G\\CartContext", "G\\CartTransform"],
          str(cl.context_classes))
    check("DI fragment carries the original arguments",
          cl.di_fragment["svc.cart"]["arguments"] == ["@svc.helper"],
          str(cl.di_fragment))

    # Direct FQCN suites have no Symfony service definitions. The analyzer
    # also marks abstract bases as Context implementors, but those files are
    # dependencies rather than classes Behat can instantiate.
    from dataclasses import replace
    plain = replace(b, raw={"behat": {
        "services_entry": None, "hook_services": None, "test_config": None,
        "original_services_import": None, "bench_services_import": None}})
    inherited = json.loads(json.dumps(index))
    inherited["files"]["test/glue/Helper.php"]["classes"][0].update(
        is_context=True, abstract=True)
    inherited["files"]["test/glue/Deep.php"]["classes"][0].update(
        is_context=True, kind="interface")
    direct_cl = ClosureExtractor(inherited, matches, plain).closure_for(
        "t/f.feature:6", feat, feat.scenarios[0])
    check("direct-class suites register concrete contexts without invented DI errors",
          direct_cl.context_classes == cl.context_classes
          and not any(p.startswith("context_without_service_definition:")
                      for p in direct_cl.problems),
          str(direct_cl.to_json()))
    missing_di = ClosureExtractor(index, matches, b).closure_for(
        "t/f.feature:6", feat, feat.scenarios[0])
    check("a DI-wired suite still refuses missing context service definitions",
          any(p.startswith("context_without_service_definition:")
              for p in missing_di.problems))

    # An item whose every step is answered by retained code cannot fail in
    # the stripped repo, so it must be flagged before it is ever run.
    src2 = """Feature: F

  Scenario: Only infra
    Given the site exists
"""
    f2 = parse_feature_file("/x/g.feature", src2)
    cl2 = ex.closure_for("t/g.feature:3", f2, f2.scenarios[0])
    check("retained-only item flagged", cl2.answered_entirely_by_retained)
    check("retained-only item has an empty gold closure", cl2.files == [])

    src3 = """Feature: F

  Scenario: Unknown
    Given nothing matches this
"""
    f3 = parse_feature_file("/x/h.feature", src3)
    cl3 = ex.closure_for("t/h.feature:3", f3, f3.scenarios[0])
    check("unmatched step is a recorded problem",
          cl3.n_steps_unmatched == 1
          and any(p.startswith("unmatched_step") for p in cl3.problems),
          str(cl3.problems))

    check("a CoreShop closure carries no `suite` key at all -- the field is "
          "emitted only when a project has one",
          "suite" not in cl.to_json() and cl.suite is None)

    # An absolute path in, a repo-relative one out.  The sidecar is read on
    # a worker, against a workspace that is not the tree it was extracted
    # from, so `validate.validate_item` refuses an absolute `feature_file`
    # by name -- which is what the first Sylius `validate` run hit, on every
    # item.
    check("the closure records the feature file repo-relative, whatever the "
          "extractor was handed",
          [c.feature_file for c in (cl, cl2, cl3)]
          == ["f.feature", "g.feature", "h.feature"]
          and cl.to_json()["feature_file"] == "f.feature",
          str([c.feature_file for c in (cl, cl2, cl3)]))

    # -- the suite-scoped reading: Api and Ui twins, and the arm that
    #    decides between them.
    #
    # Sylius ships two contexts with the SAME step pattern (3635 of its
    # 6919 step texts match in more than one definition), so the universe
    # of "definitions Behat could reach" does not bind a step. The item's
    # SUITE does, and that is the only thing narrowed here.
    from .behat_suites import SUITE_MAP_SCHEMA

    twin_index = {"files": {
        "test/glue/api/AddressContext.php": {
            "namespace": "A", "uses": {}, "refs": [],
            "classes": [{"name": "A\\AddressContext", "kind": "class",
                         "abstract": False, "extends": [], "implements": [],
                         "traits": ["A\\ValidationTrait"], "is_context": True,
                         "constructor": [],
                         "steps": [{"method": "m", "kind": "When",
                                    "pattern": "/^I add an address$/",
                                    "line": 1, "params": []}],
                         "transforms": [], "line": 1}]},
        "test/glue/ui/AddressContext.php": {
            "namespace": "U", "uses": {}, "refs": [],
            "classes": [{"name": "U\\AddressContext", "kind": "class",
                         "abstract": False, "extends": [], "implements": [],
                         "traits": ["U\\ValidationTrait"], "is_context": True,
                         "constructor": [],
                         "steps": [{"method": "m", "kind": "When",
                                    "pattern": "/^I add an address$/",
                                    "line": 1, "params": []}],
                         "transforms": [], "line": 1}]},
        # Sylius's `Api\Admin\Helper\ValidationTrait` and its Ui twin:
        # the same patterns, defined in a TRAIT that each side's contexts
        # `use`, and recorded in the index under the trait's own name.
        "test/glue/api/ValidationTrait.php": {
            "namespace": "A", "uses": {}, "refs": [],
            "classes": [{"name": "A\\ValidationTrait", "kind": "trait",
                         "abstract": False, "extends": [], "implements": [],
                         "traits": ["A\\NotifyTrait"], "is_context": False,
                         "constructor": [],
                         "steps": [{"method": "v", "kind": "Then",
                                    "pattern": "/^the field is too long$/",
                                    "line": 1, "params": []}],
                         "transforms": [], "line": 1}]},
        "test/glue/ui/ValidationTrait.php": {
            "namespace": "U", "uses": {}, "refs": [],
            "classes": [{"name": "U\\ValidationTrait", "kind": "trait",
                         "abstract": False, "extends": [], "implements": [],
                         "traits": ["U\\NotifyTrait"], "is_context": False,
                         "constructor": [],
                         "steps": [{"method": "v", "kind": "Then",
                                    "pattern": "/^the field is too long$/",
                                    "line": 1, "params": []}],
                         "transforms": [], "line": 1}]},
        # A trait a trait uses, so the widening has to be transitive.
        "test/glue/api/NotifyTrait.php": {
            "namespace": "A", "uses": {}, "refs": [],
            "classes": [{"name": "A\\NotifyTrait", "kind": "trait",
                         "abstract": False, "extends": [], "implements": [],
                         "traits": [], "is_context": False,
                         "constructor": [],
                         "steps": [{"method": "n", "kind": "Then",
                                    "pattern": "/^I am notified$/",
                                    "line": 1, "params": []}],
                         "transforms": [], "line": 1}]},
        "test/glue/ui/NotifyTrait.php": {
            "namespace": "U", "uses": {}, "refs": [],
            "classes": [{"name": "U\\NotifyTrait", "kind": "trait",
                         "abstract": False, "extends": [], "implements": [],
                         "traits": [], "is_context": False,
                         "constructor": [],
                         "steps": [{"method": "n", "kind": "Then",
                                    "pattern": "/^I am notified$/",
                                    "line": 1, "params": []}],
                         "transforms": [], "line": 1}]},
    }}
    twin_matches = {"steps": {"I add an address": [
        {"file": "test/glue/api/AddressContext.php", "class": "A\\AddressContext",
         "method": "m", "kind": "When", "pattern": "/^I add an address$/",
         "captures": []},
        {"file": "test/glue/ui/AddressContext.php", "class": "U\\AddressContext",
         "method": "m", "kind": "When", "pattern": "/^I add an address$/",
         "captures": []},
    ], "the field is too long": [
        {"file": "test/glue/api/ValidationTrait.php",
         "class": "A\\ValidationTrait", "method": "v", "kind": "Then",
         "pattern": "/^the field is too long$/", "captures": []},
        {"file": "test/glue/ui/ValidationTrait.php",
         "class": "U\\ValidationTrait", "method": "v", "kind": "Then",
         "pattern": "/^the field is too long$/", "captures": []},
    ], "I am notified": [
        {"file": "test/glue/api/NotifyTrait.php",
         "class": "A\\NotifyTrait", "method": "n", "kind": "Then",
         "pattern": "/^I am notified$/", "captures": []},
        {"file": "test/glue/ui/NotifyTrait.php",
         "class": "U\\NotifyTrait", "method": "n", "kind": "Then",
         "pattern": "/^I am notified$/", "captures": []},
    ]}, "transforms": {}}
    twin_b = Boundary(version=1, project="sylius", repo_root="/x",
                      removable=[("test/glue/", "")], retained=[])
    suite_map = {"schema": SUITE_MAP_SCHEMA, "project": "sylius", "suites": {
        "api_address_book": {"file": "cfg/suites/api/address_book.php",
                             "arm": True, "tag_filter": "@address_book&&@api",
                             "contexts": ["api.address"], "retained": [],
                             "removable": ["api.address"],
                             "classes": {"api.address": "A\\AddressContext"}},
        "ui_address_book": {"file": "cfg/suites/ui/address_book.php",
                            "arm": False, "tag_filter": "@address_book&&@ui",
                            "contexts": ["ui.address"], "retained": [],
                            "removable": ["ui.address"],
                            "classes": {"ui.address": "U\\AddressContext"}},
    }}
    tex = ClosureExtractor(twin_index, twin_matches, twin_b, {}, None, suite_map)

    api_src = """@api
Feature: Address book

  @address_book
  Scenario: Add
    When I add an address
    Then the field is too long
    Then I am notified
"""
    api_feat = parse_feature_file("/x/api.feature", api_src)
    api_cl = tex.closure_for("sylius/api.feature:5", api_feat,
                             api_feat.scenarios[0])
    check("[suite-scoped] the item's suite is recorded on the closure and "
          "in its json",
          api_cl.suite == "api_address_book"
          and api_cl.to_json()["suite"] == "api_address_book",
          str(api_cl.suite))
    bound = {step.text: (step.definition or {}).get("class")
             for step in api_cl.steps}
    check("[suite-scoped] the twin the item's suite does NOT register is not "
          "a candidate, so the step binds to exactly one definition",
          api_cl.n_steps == 3
          and bound["I add an address"] == "A\\AddressContext",
          str(bound))
    check("[suite-scoped] a step the live context gets from a TRAIT binds "
          "too -- Behat sees the trait's method on the using class, and the "
          "index records the definition under the TRAIT's own name -- and "
          "it binds to the ARM's trait, not the Ui twin with the same "
          "pattern",
          bound["the field is too long"] == "A\\ValidationTrait",
          str(bound))
    check("[suite-scoped] ...and transitively, through a trait that trait "
          "itself uses",
          bound["I am notified"] == "A\\NotifyTrait", str(bound))
    check("[suite-scoped] no step of the item is left unmatched",
          api_cl.n_steps_unmatched == 0
          and not [p for p in api_cl.problems
                   if p.startswith("unmatched_step")],
          str(api_cl.problems))
    check("[suite-scoped] ...and the gold closure is that suite's files "
          "only: the context and the traits behind it",
          api_cl.files == ["test/glue/api/AddressContext.php",
                           "test/glue/api/NotifyTrait.php",
                           "test/glue/api/ValidationTrait.php"],
          str(api_cl.files))

    ui_src = """@ui
Feature: Address book

  @address_book
  Scenario: Add
    When I add an address
"""
    ui_feat = parse_feature_file("/x/ui.feature", ui_src)
    ui_cl = tex.closure_for("sylius/ui.feature:5", ui_feat,
                            ui_feat.scenarios[0])
    check("[suite-scoped] an item no ARM suite claims gets `no_suite` and an "
          "empty closure -- that is the API restriction taking effect",
          ui_cl.problems == ["no_suite: @ui @address_book"]
          and ui_cl.files == [] and ui_cl.suite is None,
          str((ui_cl.problems, ui_cl.files)))
    check("[suite-scoped] ...and both legs relativise the same way: the "
          "closure of an arm item and the refusal of a non-arm one",
          (api_cl.feature_file, ui_cl.feature_file)
          == ("api.feature", "ui.feature"),
          str((api_cl.feature_file, ui_cl.feature_file)))
    check("[suite-scoped] the narrowing is per item and does not leak into "
          "the next one",
          tex._item_classes is None
          and tex.closure_for("sylius/api.feature:5", api_feat,
                              api_feat.scenarios[0]).files
          == ["test/glue/api/AddressContext.php",
              "test/glue/api/NotifyTrait.php",
              "test/glue/api/ValidationTrait.php"])

    # The widening lives on the per-item narrowing, which only a suite-scoped
    # project has.  CoreShop synthesises one suite for every item, reads the
    # unnarrowed `registered_classes` universe instead, and ships four traits
    # that define no step and no transform between them -- so not one of its
    # closures can move.
    plain = ClosureExtractor(twin_index, twin_matches, twin_b, {},
                             {"A\\AddressContext"}, None)
    plain_cl = plain.closure_for("t/api.feature:5", api_feat,
                                 api_feat.scenarios[0])
    check("a project that is NOT suite-scoped keeps exactly the binding it "
          "had: with no suite map there is no per-item set to widen, so the "
          "trait steps still meet the unwidened `registered_classes`",
          plain.suite_map is None and plain._item_classes is None
          and sorted(p for p in plain_cl.problems
                     if p.startswith("unmatched_step"))
          == ["unmatched_step: I am notified",
              "unmatched_step: the field is too long"],
          str(plain_cl.problems))
    check("...and its FILES were already the same, because `expand` follows "
          "a class's `traits` edge and always did -- this fix moves the "
          "step binding, not the closure",
          plain_cl.files == api_cl.files, str(plain_cl.files))

    print("\n" + ("ALL PASS (closure)" if ok else "FAILURES (closure)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
