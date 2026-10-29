"""S3 — the per-scenario ground-truth closure, for Python/behave.

`closure.py` computes this for Behat over THREE edge kinds — seeds, code
references, and the DI edges that exist because a Behat context receives its
collaborators through a Symfony container.  behave has no container: a step
module is `exec`'d, its decorated functions register themselves, and shared
state travels on the `context` object.  So this is the same computation over
TWO edge kinds, and the third is not "omitted" but absent — `di_fragment` is
`{}` for every python item, which is a fact about the framework rather than a
gap in the extractor.

    seeds       every step definition behave's own registry binds to a step of
                the scenario — INCLUDING its Background steps, and including
                every Examples row's substituted text, because behave runs an
                outline as one real scenario per row.
    code edges  the modules a seeded module imports, resolved against the two
                directories behave puts on `sys.path`; plus the module that
                `register_type`s a custom type any of a restored module's
                patterns names, which is the one edge no import carries.

Expansion stops at the boundary exactly as `closure.py`'s does: a RETAINED
file is recorded and not recursed into (it is stable substrate that survives
stripping), and anything outside the index — `docx`, `behave`, `os` — is a
production dependency recorded by name and never followed.

**What is REUSED, and what is not.**  `ItemClosure` and `StepBinding` are
imported from `closure.py` and subclassed, not copied: the two stacks'
closures are the same object with the same counts, the same
`answered_entirely_by_retained` rule and the same `to_json` keys, and the
release's gold sidecar is written from those keys by one function
(`release.build_release`) that must not learn which stack it is looking at.
The subclasses add what an outline needs (an Examples row line per binding)
and nothing else.

**The unit is the FILE.**  Behat's index resolves class names, so
`closure.py` expands over classes and maps them to files at the end.  behave
registers whatever a MODULE's decorators declare, so a module IS the unit
here; `classes` holds module import names and `context_classes` holds the
import names of the modules that actually declare steps, which is the honest
Python reading of "the contexts a suite must register".

**`feature_file` is repo-RELATIVE here, and absolute in the CoreShop
closures.**  Not a cosmetic difference: `validate.py` joins it onto the
harness root, and an absolute path makes that join resolve back to the
extraction tree instead of to the workspace under measurement.  CoreShop's
`.feature` files are production code that stripping never touches, so the two
resolve to identical bytes and nothing published changes; a relative path is
what a second project needed anyway, and it is what this stack writes.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from ..core.boundary import Boundary, PRODUCTION, REMOVABLE, RETAINED
from .closure import ItemClosure, StepBinding
from ..core.gherkin import Block, Feature
from .pystep_index import StepRef, item_steps
from ..core.paths import CONFIG_DIR


@dataclass
class PyStepBinding(StepBinding):
    """A `StepBinding` that also knows which Examples row produced it.

    Additive, with defaults, so that everything reading a `StepBinding` —
    `ItemClosure`'s counts, `stub.py`'s `(text, side)` pairs — keeps working
    unchanged.  `example_line` is the DATA ROW's line, which is the line the
    recorder stamps a per-row record with, so a binding can be joined to the
    record of the row it belongs to.
    """
    example_line: Optional[int] = None
    example_row: Optional[int] = None
    source_line: Optional[int] = None


@dataclass
class PyItemClosure(ItemClosure):
    """An `ItemClosure` carrying the outline structure the counts flatten.

    `counts.steps` counts step OCCURRENCES — for an outline that is (rows ×
    step lines), because that is how many steps behave executes and how many
    a stub has to define.  `source_steps` and `example_rows` are recorded
    beside it so a reader can tell an outline with 5 rows of 3 steps from a
    scenario with 15.
    """
    source_steps: int = 0
    example_lines: list = field(default_factory=list)
    modules: list = field(default_factory=list)

    def to_json(self) -> dict:
        doc = super().to_json()
        for out, binding in zip(doc["steps"], self.steps):
            out["example_line"] = getattr(binding, "example_line", None)
            out["example_row"] = getattr(binding, "example_row", None)
            out["source_line"] = getattr(binding, "source_line", None)
        doc["example_lines"] = list(self.example_lines)
        doc["counts"]["source_steps"] = self.source_steps
        doc["counts"]["example_rows"] = len(self.example_lines)
        return doc


class PyClosureExtractor:
    """Builds one item's closure from the static index and behave's answers.

    Constructed once per sweep and reused, like `ClosureExtractor`: it holds
    the whole index and the whole match table, and rebuilding those per item
    is the difference between seconds and hours.
    """

    def __init__(self, py_index: dict, matches: dict, boundary: Boundary):
        self.index = py_index
        self.boundary = boundary
        self.files: dict[str, dict] = py_index["files"]
        self.repo_root = os.path.abspath(boundary.repo_root)

        #: (keyword, text) -> the match record behave produced.
        self.matches: dict[tuple, dict] = {
            (m["keyword"], m["text"]): m for m in matches.get("matches", [])}

        #: file -> the custom `parse` types its patterns name.  Grouped from
        #: the registry's own view of every definition, because whether a
        #: `{x:Bool}` is a CUSTOM type or one of `parse`'s built-ins is a
        #: question only the live registry can answer.
        self.file_types: dict[str, set] = {}
        for d in matches.get("definitions", []):
            if d.get("custom_types"):
                self.file_types.setdefault(d["file"], set()).update(
                    d["custom_types"])

        #: custom type name -> the files whose `register_type` declares it.
        self.type_registrars: dict[str, set] = {}
        for rel, info in self.files.items():
            for t in info.get("register_types") or []:
                self.type_registrars.setdefault(t["name"], set()).add(rel)

        #: The files a stripped repository still has.  behave loads every
        #: module under `features/steps/`, so a RETAINED module there is
        #: registered for every item whether or not the closure names it —
        #: which is what `_prefer_retained` is about.
        self.always_present = {rel for rel in self.files
                               if boundary.classify(rel) == RETAINED}

    # ------------------------------------------------------------ seeding
    def _prefer_retained(self, hits: list) -> list:
        """Drop a removable provider when RETAINED code answers the same
        pattern.

        The port of `ClosureExtractor._prefer_retained`, and worth
        understanding before reading the behave version of it.  CoreShop ships
        `Behat\\Context\\Transform\\SharedStorageContext` and
        `TestBundle\\Context\\Transform\\SharedStorageContext` with identical
        patterns; the synthesised suite ALWAYS registers the retained one, so
        the removable twin is never what Behat reaches — and putting it in the
        gold closure made **105 items** ask the system under test for a file
        it does not need.  The round-trip gate cannot catch that, because an
        over-approximated closure still passes; it is a ground-truth error
        that only shows up as an inflated recall denominator.

        behave reaches the same conclusion by a different route, and the
        difference is worth stating.  Behat picks by registration; behave
        picks by FILENAME ORDER (`load_step_modules` walks `sorted(listdir)`
        and `find_step_definition` returns the first candidate), so a restored
        removable twin might well be the one that runs.  That makes including
        it worse than redundant: two modules whose patterns match each other
        raise `AmbiguousStep` at import and the item fails for a reason that
        is not the system under test's.  Either way the answer is the same —
        if the substrate already answers the step, the closure does not need
        the twin.

        python-docx has no retained `.py` under `features/steps/`, so this
        fires zero times there.  It is written because the first corpus that
        keeps a shared step module retained would otherwise ship 105 items'
        worth of quiet over-approximation.
        """
        if not self.always_present or len(hits) < 2:
            return hits
        by_pattern: dict[str, list] = {}
        for h in hits:
            by_pattern.setdefault(h["pattern"], []).append(h)
        out: list = []
        for _pattern, group in by_pattern.items():
            retained = [h for h in group if h["file"] in self.always_present]
            out.extend(retained or group)
        return out

    def _as_definition(self, entry: Optional[dict]) -> Optional[dict]:
        """behave's registry entry, in the vocabulary `ItemClosure` exports.

        `closure.ItemClosure.to_json` writes `(file, class, method, kind,
        pattern)` for every bound step, and a release reader joins on those
        names whichever stack produced them.  Python has no class to put in
        `class`, so it carries the MODULE IMPORT NAME — which is the thing
        that plays the Behat context's role here: what a suite would have to
        register, and what `context_classes` is a list of.  behave's own keys
        (`func`, `keyword`, `matcher`, `custom_types`) are kept beside the
        translated ones rather than replaced, so nothing is lost by the
        translation.
        """
        if entry is None:
            return None
        return dict(entry,
                    **{"class": self.module_of(entry["file"]),
                       "method": entry.get("func"),
                       "kind": entry.get("keyword")})

    def _definition_for(self, ref: StepRef) -> tuple[Optional[dict], int, list]:
        """`(definition, n_candidates, cross-file candidate files)`.

        The definition is behave's OWN answer unless `_prefer_retained` says
        the substrate already provides the pattern, in which case it is the
        retained provider — see there.
        """
        m = self.matches.get(ref.key)
        if m is None:
            return (None, 0, [])
        cands = m.get("candidates") or []
        chosen = m.get("definition")
        if chosen is not None:
            # Only ever OVERRIDE behave's answer, never invent one: if the
            # registry bound nothing, the step is unmatched and that is the
            # finding, whatever the candidate list looks like.
            preferred = self._prefer_retained(cands)
            if preferred and preferred[0] != chosen:
                chosen = preferred[0]
        files = sorted({c["file"] for c in cands})
        return (self._as_definition(chosen), m.get("n_candidates", len(cands)),
                files if len(files) > 1 else [])

    def bind_steps(self, feature: Feature, scenario: Block) -> list:
        """Every step occurrence of the item, bound to the definition that
        answers it.

        `pystep_index.item_steps` has already done the two things behave does
        before its registry is ever consulted: resolved And/But/`*` to a
        concrete keyword, and substituted each Examples row into the step
        text.  What is left here is the lookup.
        """
        return [b for b, _note in self._bind(feature, scenario)]

    def _bind(self, feature: Feature, scenario: Block) -> list:
        """`(binding, cross-file-ambiguity note or None)` per occurrence.

        One pass, because an outline asks the same question once per Examples
        row and there are 535 of them in this corpus: the bindings and the
        ambiguity notes come out of the same lookup rather than out of two.
        """
        out: list = []
        for ref in item_steps(feature, scenario):
            d, n, cross = self._definition_for(ref)
            side = None if d is None else self.boundary.classify(d["file"])
            note = None
            if n > 1 and cross:
                # behave takes the first match by filename order, so a
                # cross-FILE ambiguity makes the closure depend on which
                # module sorts first -- a real finding.  An ambiguity inside
                # ONE file cannot change which file is restored, and is
                # therefore not recorded as a problem: python-docx has 70 of
                # those and 0 of these.
                note = (f"ambiguous_step_across_files: {ref.keyword} "
                        f"{ref.text} -> {', '.join(cross)}")
            out.append((PyStepBinding(
                text=ref.text, origin=ref.origin, keyword=ref.keyword.title(),
                definition=d, side=side, example_line=ref.example_line,
                example_row=ref.example_row, source_line=ref.source_line),
                note))
        return out

    # ---------------------------------------------------------- expansion
    def expand(self, seeds: set) -> tuple[set, set, set]:
        """`(removable files, retained files touched, production deps)`.

        Worklist over the index's own resolved import edges — traversal order
        is not significant, the answer is a set — with the two stopping rules
        `closure.expand` uses: RETAINED code is recorded and never recursed
        into (it survives stripping, so what it depends on is not the system
        under test's problem), and anything the index does not know is a
        production/vendor/stdlib dependency recorded by NAME.

        `production` therefore holds module NAMES (`docx`, `behave`, `os`),
        not paths.  The one branch that can put a path in it is a seed or an
        edge naming a file the index lacks, which `pystep_index.crosscheck`
        refuses before this ever runs; it is kept so that a future caller
        skipping the cross-check gets a recorded dependency rather than a
        `KeyError`.
        """
        removable: set = set()
        retained: set = set()
        production: set = set()
        queue = list(seeds)
        seen: set = set()
        while queue:
            rel = queue.pop()
            if rel in seen:
                continue
            seen.add(rel)
            info = self.files.get(rel)
            if info is None:
                production.add(rel)
                continue
            side = self.boundary.classify(rel)
            if side == RETAINED:
                retained.add(rel)
                continue
            if side != REMOVABLE:
                production.add(rel)
                continue
            removable.add(rel)

            nxt = set(info.get("refs") or [])
            production.update(info.get("external") or [])
            # The `register_type` edge.  A restored module's decorators all
            # run at import, and behave compiles a `parse` pattern the first
            # time it is TRIED — including while searching for some other
            # step's definition — so an unregistered `{x:Bool}` anywhere in a
            # restored file raises during a scenario that has nothing to do
            # with it.  The file-level rule is therefore the safe one.
            for t in self.file_types.get(rel, ()):
                nxt.update(self.type_registrars.get(t, ()))
            for n in nxt:
                if n not in seen:
                    queue.append(n)
        return removable, retained, production

    # ------------------------------------------------------------- driver
    def module_of(self, rel: str) -> str:
        info = self.files.get(rel)
        if info is not None:
            return info["module"]
        from ..py.analyze_py import module_name_for
        return module_name_for(rel, self.index.get("search_paths") or [])

    def declares_steps(self, rel: str) -> bool:
        info = self.files.get(rel) or {}
        return bool(info.get("steps") or info.get("dynamic_steps"))

    def closure_for(self, item_id: str, feature: Feature,
                    scenario: Block) -> PyItemClosure:
        bound = self._bind(feature, scenario)
        steps = [b for b, _n in bound]
        rel_feature = os.path.relpath(
            os.path.abspath(feature.path), self.repo_root).replace(os.sep, "/")
        cl = PyItemClosure(item_id=item_id,
                           feature_file=rel_feature,
                           scenario_line=scenario.line,
                           steps=steps,
                           source_steps=len(scenario.steps) + (
                               len(feature.background.steps)
                               if feature.background is not None else 0),
                           example_lines=sorted(
                               {b.example_line for b in steps
                                if b.example_line is not None}))

        seeds = {s.definition["file"] for s in steps
                 if s.definition and s.side == REMOVABLE}
        removable, retained, production = self.expand(seeds)

        cl.files = sorted(removable)
        cl.retained_files = sorted(retained)
        cl.classes = sorted(self.module_of(r) for r in removable)
        cl.context_classes = sorted(self.module_of(r) for r in removable
                                    if self.declares_steps(r))
        cl.production_deps = sorted(production)
        cl.modules = list(cl.classes)
        # behave has no service container, so there is nothing to synthesise
        # and nothing to record.  Spelled as an assignment rather than left
        # to the dataclass default so that reading this function answers the
        # question instead of deferring it.
        cl.di_fragment = {}

        # One problem per DISTINCT (keyword, text), not per occurrence: an
        # outline with 20 rows over one unmatched step is ONE finding, and 20
        # identical lines would bury every other item in the same report.
        seen: set = set()
        for s, note in bound:
            if s.definition is None and (s.keyword, s.text) not in seen:
                seen.add((s.keyword, s.text))
                cl.problems.append(f"unmatched_step: {s.keyword} {s.text}")
            if note is not None and note not in cl.problems:
                cl.problems.append(note)
        return cl


# ------------------------------------------------------------ gold sidecar
#: The six keys shared by Behat/behave release gold sidecars.
#:
#: The selftest builds a real non-Go release from its extracted closure and
#: checks the emitted fields, values and bytes. Serializer syntax is free to
#: change without weakening the existing sidecar contract.
GOLD_SIDECAR_FIELDS: tuple[str, ...] = (
    "item_id", "files", "di_fragment", "context_classes", "feature_file",
    "scenario_line")


def gold_sidecar(closure_json: dict) -> dict:
    """One item's gold sidecar, exactly as the release writes it."""
    return {k: closure_json[k] for k in GOLD_SIDECAR_FIELDS}


# ---------------------------------------------------------------- loading
def load_extractor(index_path: str, matches_path: str, boundary_path: str,
                   repo_root: Optional[str] = None) -> PyClosureExtractor:
    """The behave twin of `closure.load_extractor`.

    Four positional parameters instead of six: `services_entry` and
    `suites_entry` are Behat's container and suite files, and behave has
    neither.  The signature is deliberately NOT padded with two `None`s to
    look the same — a stack's seams are allowed to have the shape their
    framework has, and `stacks.base.StackRunner` declares `extract_closure`
    with `*args, **kwargs` for exactly this reason.
    """
    from ..core.boundary import load_boundary
    with open(index_path, encoding="utf-8") as fh:
        index = json.load(fh)
    with open(matches_path, encoding="utf-8") as fh:
        matches = json.load(fh)
    b = load_boundary(boundary_path, repo_root=repo_root)
    return PyClosureExtractor(index, matches, b)


# ------------------------------------------------------------- the CLI verb
def cmd_closures(args) -> int:
    """`r2t closures --profile … --features features`, the behave arm.

    Prints the same five summary lines the PHP arm prints, because they are
    what an operator reads to decide whether the corpus is usable, and two
    stacks whose `closures` say different things would be two benchmarks.
    """
    import statistics

    from ..core.boundary import load_boundary
    from .pystep_index import features_rel, walk_features

    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    features = features_rel(args, b)
    ex = load_extractor(os.path.join(args.artifacts, "py_index.json"),
                        os.path.join(args.artifacts, "matches.json"),
                        args.boundary, repo_root=b.repo_root)
    print(f"step definitions: {sum(len(f['steps']) for f in ex.files.values())} "
          f"in {len(ex.files)} indexed modules; "
          f"{len(ex.always_present)} of those modules are retained")

    out = []
    for item_id, feat, sc in walk_features(b.repo_root, features,
                                          b.project):
        out.append(ex.closure_for(item_id, feat, sc).to_json())
    dst = os.path.join(args.artifacts, "closures.json")
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)

    sizes = [len(c["files"]) for c in out]
    print(f"{len(out)} items -> {dst}")
    print(f"  closure files: min {min(sizes)} median "
          f"{statistics.median(sizes):.0f} max {max(sizes)}")
    print(f"  unmatched steps: {sum(c['counts']['steps_unmatched'] for c in out)}")
    print(f"  answered entirely by retained code: "
          f"{sum(1 for c in out if c['answered_entirely_by_retained'])}")
    probs = sum(1 for c in out if c["problems"])
    print(f"  items with extractor problems: {probs}")
    print(f"  outlines: {sum(1 for c in out if c['counts']['example_rows'])} "
          f"({sum(c['counts']['example_rows'] for c in out)} Examples rows)")
    return 0


# ----------------------------------------------------------------- selftest
def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    from ..core.gherkin import parse_feature_file

    b = Boundary(version=1, project="t", repo_root="/x",
                 removable=[("features/steps/", "")],
                 retained=[("features/steps/common.py", ""),
                           ("features/environment.py", "")])

    index = {
        "search_paths": ["features/steps", "features"],
        "files": {
            "features/steps/font.py": {
                "module": "font", "refs": ["features/steps/helpers.py",
                                           "features/steps/common.py"],
                "external": ["docx", "behave"],
                "steps": [{"keyword": "given", "pattern": "a font",
                           "registry_line": 3}],
                "dynamic_steps": [], "register_types": []},
            "features/steps/helpers.py": {
                "module": "helpers", "refs": ["features/steps/deep.py"],
                "external": ["os"], "steps": [], "dynamic_steps": [],
                "register_types": []},
            "features/steps/deep.py": {
                "module": "deep", "refs": [], "external": [], "steps": [],
                "dynamic_steps": [], "register_types": []},
            "features/steps/typed.py": {
                "module": "typed", "refs": [], "external": [],
                "steps": [{"keyword": "then", "pattern": "it is {v:Bool}",
                           "registry_line": 3}],
                "dynamic_steps": [], "register_types": []},
            "features/steps/reg.py": {
                "module": "reg", "refs": [], "external": [], "steps": [],
                "dynamic_steps": [],
                "register_types": [{"name": "Bool", "line": 5}]},
            "features/steps/common.py": {
                "module": "common", "refs": ["features/steps/never.py"],
                "external": [],
                "steps": [{"keyword": "given", "pattern": "a store",
                           "registry_line": 3}],
                "dynamic_steps": [], "register_types": []},
            "features/steps/twin.py": {
                "module": "twin", "refs": [], "external": [],
                "steps": [{"keyword": "given", "pattern": "a store",
                           "registry_line": 3}],
                "dynamic_steps": [], "register_types": []},
            "features/steps/never.py": {
                "module": "never", "refs": [], "external": [], "steps": [],
                "dynamic_steps": [], "register_types": []},
        }}

    def d(f, kw, pattern, func="fn", types=()):
        return {"file": f, "line": 3, "keyword": kw, "pattern": pattern,
                "func": func, "matcher": "parse", "custom_types": list(types)}

    font = d("features/steps/font.py", "given", "a font")
    typed = d("features/steps/typed.py", "then", "it is {v:Bool}",
              types=["Bool"])
    common = d("features/steps/common.py", "given", "a store")
    twin = d("features/steps/twin.py", "given", "a store")

    matches = {"definitions": [font, typed, common, twin], "matches": [
        {"keyword": "given", "text": "a font", "definition": font,
         "n_candidates": 1, "candidates": [font]},
        {"keyword": "then", "text": "it is True", "definition": typed,
         "n_candidates": 1, "candidates": [typed]},
        # behave would take the removable twin (`twin.py` sorts after
        # `common.py`... but registration order is what decides, and the
        # fixture makes it the twin on purpose): the extractor must still
        # prefer the retained provider.
        {"keyword": "given", "text": "a store", "definition": twin,
         "n_candidates": 2, "candidates": [twin, common]},
        {"keyword": "given", "text": "nothing matches this",
         "definition": None, "n_candidates": 0, "candidates": []},
    ]}
    ex = PyClosureExtractor(index, matches, b)

    src = """Feature: F

  Scenario: One font
    Given a font
"""
    feat = parse_feature_file("/x/features/f.feature", src)
    cl = ex.closure_for("t/features/f.feature:3", feat, feat.scenarios[0])

    check("the seed module is in the closure",
          "features/steps/font.py" in cl.files, str(cl.files))
    check("a bare-name import edge is followed (helpers.py) -- the gate that "
          "decides whether 21 python-docx modules can load at all",
          "features/steps/helpers.py" in cl.files, str(cl.files))
    check("...and transitively (deep.py behind helpers.py)",
          "features/steps/deep.py" in cl.files, str(cl.files))
    check("a production/vendor/stdlib import is recorded by NAME, not "
          "followed", set(cl.production_deps) >= {"docx", "behave", "os"},
          str(cl.production_deps))
    check("context_classes are the import names of the modules that DECLARE "
          "steps -- helpers.py is in the closure and is not one",
          cl.context_classes == ["font"], str(cl.context_classes))
    check("classes are every removable module in the closure",
          cl.classes == ["deep", "font", "helpers"], str(cl.classes))
    check("di_fragment is EMPTY for behave, and present rather than absent",
          cl.di_fragment == {} and "di_fragment" in cl.to_json())
    check("feature_file is repo-RELATIVE, so validate's join lands in the "
          "workspace", cl.feature_file == "features/f.feature", cl.feature_file)

    # -- the retained-twin rule ------------------------------------------
    src2 = """Feature: F

  Scenario: Uses a step the substrate answers
    Given a store
"""
    f2 = parse_feature_file("/x/features/g.feature", src2)
    cl2 = ex.closure_for("t/features/g.feature:3", f2, f2.scenarios[0])
    check("a step the RETAINED substrate answers binds to the retained "
          "provider, not to behave's first-by-filename removable twin",
          cl2.steps[0].definition["file"] == "features/steps/common.py",
          str(cl2.steps[0].definition))
    check("...so the removable twin is NOT in the gold closure (the "
          "over-approximation that cost 105 CoreShop items)",
          cl2.files == [], str(cl2.files))
    check("...and the item is flagged as answered entirely by retained code",
          cl2.answered_entirely_by_retained)
    # `font.py` imports the retained `common.py`, which imports `never.py`.
    # The retained file is a stable substrate that survives stripping, so it
    # is RECORDED as touched and expansion stops there -- exactly the rule
    # `closure.expand` applies, and the reason `never.py` is not part of any
    # answer.
    check("retained code is recorded but never recursed into",
          cl.retained_files == ["features/steps/common.py"]
          and "features/steps/never.py" not in cl.files
          and "never" not in cl.classes,
          f"{cl.retained_files} {cl.files}")

    # -- the register_type edge -------------------------------------------
    src3 = """Feature: F

  Scenario: Custom type
    Then it is True
"""
    f3 = parse_feature_file("/x/features/h.feature", src3)
    cl3 = ex.closure_for("t/features/h.feature:3", f3, f3.scenarios[0])
    check("the module that `register_type`s a pattern's custom type is an "
          "edge with no import behind it, and it is followed",
          set(cl3.files) == {"features/steps/typed.py",
                             "features/steps/reg.py"}, str(cl3.files))

    # -- unmatched ---------------------------------------------------------
    src4 = """Feature: F

  Scenario: Unknown
    Given nothing matches this
"""
    f4 = parse_feature_file("/x/features/i.feature", src4)
    cl4 = ex.closure_for("t/features/i.feature:3", f4, f4.scenarios[0])
    check("an unmatched step is a recorded problem and an empty closure",
          cl4.n_steps_unmatched == 1 and cl4.files == []
          and any(p.startswith("unmatched_step") for p in cl4.problems),
          str(cl4.problems))

    # -- outlines ----------------------------------------------------------
    src5 = """Feature: F

  Scenario Outline: Rows
    Given a <thing>
     Then it is True

    Examples:
      | thing |
      | font  |
      | font  |
"""
    f5 = parse_feature_file("/x/features/j.feature", src5)
    cl5 = ex.closure_for("t/features/j.feature:3", f5, f5.scenarios[0])
    doc = cl5.to_json()
    check("an outline binds one step per (row x step line)",
          doc["counts"]["steps"] == 4 and doc["counts"]["source_steps"] == 2,
          str(doc["counts"]))
    check("...and the row count is recorded so 2 rows of 2 is not read as a "
          "4-step scenario", doc["counts"]["example_rows"] == 2,
          str(doc["counts"]))
    check("every binding carries its Examples DATA-ROW line (9 and 10 here; "
          "8 is the heading row and is not a case)",
          [s["example_line"] for s in doc["steps"]] == [9, 9, 10, 10],
          str([s["example_line"] for s in doc["steps"]]))
    check("the item's own scenario_line stays the `Scenario Outline:` line, "
          "so it still matches the item id it was extracted under",
          doc["scenario_line"] == 3 and doc["example_lines"] == [9, 10],
          f"{doc['scenario_line']} {doc['example_lines']}")
    check("the substituted text is what a stub would have to define",
          [s["text"] for s in doc["steps"]][:2] == ["a font", "it is True"],
          str([s["text"] for s in doc["steps"]]))
    check("an outline's closure is the union over its rows",
          set(cl5.files) >= {"features/steps/font.py",
                             "features/steps/typed.py"}, str(cl5.files))

    # -- actual release sidecar, independent of serializer syntax ----------
    import tempfile
    from pathlib import Path

    from . import release_build as _release

    iid = doc["item_id"]
    expected_sidecar = {
        "item_id": iid, "files": doc["files"],
        "di_fragment": doc["di_fragment"], "context_classes": doc["context_classes"],
        "feature_file": doc["feature_file"], "scenario_line": doc["scenario_line"],
    }
    with tempfile.TemporaryDirectory(prefix="r2t_gold_sidecar_") as tmp:
        root = Path(tmp)
        # Reuse the real closure above. Only release eligibility is supplied;
        # this fixture makes no native validation or publication claim.
        inputs = {
            "closures.json": json.dumps([doc]),
            "items.jsonl": json.dumps({"item_id": iid, "project": b.project,
                                      "task": "criterion_to_test"}) + "\n",
            "quality.json": json.dumps({iid: {"has_oracle": True,
                                             "live_effective_step_count": 3}}),
            "validation.jsonl": json.dumps({"item_id": iid, "admitted": True,
                                           "seconds": 0}) + "\n",
        }
        for name, contents in inputs.items():
            (root / name).write_text(contents, encoding="utf-8")
        output = root / "release"
        summary = _release.build_release(str(root), str(root / "items.jsonl"),
            str(output), project=b.project, portable_paths=True)
        check("the extracted behave closure reaches the real release writer",
              summary["included"] == 1 and summary["excluded"] == 0, str(summary))
        manifest = json.loads((output / "gold/manifest.json").read_text(encoding="utf-8"))
        raw = (output / "gold" / manifest[iid]).read_bytes()
        written = json.loads(raw)
        check("GOLD_SIDECAR_FIELDS is exactly what a non-Go release writes",
              set(written) == set(GOLD_SIDECAR_FIELDS) == set(expected_sidecar),
              str(sorted(written)))
        check("the release preserves all six gold sidecar values",
              written == expected_sidecar, str(written))
        check("non-Go gold sidecar serialization preserves its exact bytes",
              raw == json.dumps(expected_sidecar, indent=1, sort_keys=True).encode("utf-8"),
              repr(raw))
    for key in GOLD_SIDECAR_FIELDS:
        check(f"the gold sidecar's `{key}` is present, unchanged from the "
              f"Behat shape", key in doc)
    check("gold_sidecar() over a behave closure yields those six and nothing "
          "else", set(gold_sidecar(doc)) == set(GOLD_SIDECAR_FIELDS),
          str(sorted(gold_sidecar(doc))))
    check("the counts release.py reads are all present",
          {"steps_unmatched", "files", "context_classes"}
          <= set(doc["counts"]), str(sorted(doc["counts"])))
    check("`steps` entries carry the (text, side) pair stub.py joins on",
          all({"text", "side", "keyword"} <= set(s) for s in doc["steps"]))
    check("the closure JSON round-trips through json.dumps unchanged",
          json.loads(json.dumps(doc, sort_keys=True)) == doc)

    # -- reuse, not a fork -------------------------------------------------
    check("PyStepBinding IS a StepBinding and PyItemClosure IS an "
          "ItemClosure -- the release writer must not learn which stack it "
          "is reading",
          isinstance(cl.steps[0], StepBinding)
          and isinstance(cl, ItemClosure))
    check("the counts come from ItemClosure's own properties, not a second "
          "implementation",
          type(cl).n_steps is ItemClosure.n_steps
          and type(cl).answered_entirely_by_retained
          is ItemClosure.answered_entirely_by_retained)
    check("PRODUCTION is a classification this extractor can produce",
          b.classify("src/docx/api.py") == PRODUCTION)

    # -- the stack the CLI dispatches to ----------------------------------
    #
    # Checked here rather than in `stacks/__init__.py` so that S3 adds no
    # line to a file two other milestones are editing.  The claims are the
    # ones `stacks.selftest` makes about `behat`: every member IS the object
    # it names (by `is`, so a forwarding wrapper fails), and the module
    # itself defines nothing.
    import argparse
    from importlib import import_module

    from ..bench import cli as _cli
    from ..stacks import behave as _behave

    def resolve(dotted: str):
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            try:
                obj = import_module(".".join(parts[:i]))
            except ImportError:
                continue
            for attr in parts[i:]:
                obj = getattr(obj, attr)
            return obj
        raise AssertionError(f"cannot resolve {dotted}")

    for member, dotted in _behave.MEMBERS.items():
        check(f"behave.{member} IS {dotted}",
              getattr(_behave, member, None) is resolve(dotted))
    own = [n for n, v in vars(_behave).items()
           if not n.startswith("_") and callable(v)
           and getattr(v, "__module__", None) == _behave.__name__]
    # Until S4 this asserted `own == []` -- the index half was a pure façade.
    # The execution half is the stack being WRITTEN, so the module now
    # declares what it defines (`OWN_MEMBERS`) and the check holds it to
    # exactly that list: a helper that creeps in undeclared still fails here,
    # and every re-exported member is still held to identity above.
    check("the behave stack defines exactly the execution half it declares "
          "in OWN_MEMBERS, and nothing else",
          sorted(own) == sorted(_behave.OWN_MEMBERS),
          f"{sorted(own)} vs {sorted(_behave.OWN_MEMBERS)}")
    check("the seams S4 and S5 land are ABSENT rather than stubbed, so "
          "`stacks.verb` refuses them instead of a sweep running on a stub",
          all(not hasattr(_behave, s) for s in _behave.PENDING), )
    check("the behave stack names itself `behave` and its language `python`",
          _behave.FRAMEWORK == "behave" and _behave.LANGUAGE == "python")

    profile = os.path.join(CONFIG_DIR, "profile_python_docx.yml")
    if os.path.isfile(profile):
        args = argparse.Namespace(profile=profile)
        check("the real python-docx profile routes `index` and `closures` to "
              "THIS stack -- read out of the file, digests and all",
              _cli._stack(args) is _behave
              and _cli._other_stack(args, "cmd_index") is _behave.cmd_index
              and _cli._other_stack(args, "cmd_closures")
              is _behave.cmd_closures)
    else:
        print(f"  [SKIP] no {profile}, so the real dispatch could not be "
              f"resolved")
    # The other half of that claim, and the one CoreShop's byte-stability
    # rests on: an invocation with NO profile still runs the PHP body.
    check("an invocation with no --profile still takes the behat path for "
          "both verbs, so every CoreShop runbook is unchanged",
          _cli._other_stack(argparse.Namespace(), "cmd_index") is None
          and _cli._other_stack(argparse.Namespace(profile=None),
                                "cmd_closures") is None)

    print("\n" + ("ALL PASS (closure_py)" if ok else "FAILURES (closure_py)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
