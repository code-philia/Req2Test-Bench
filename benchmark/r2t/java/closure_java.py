"""S3 — the per-scenario ground-truth closure, for Java/Cucumber-JVM.

The third implementation of one computation.  `closure.py` does it for Behat
over three edge kinds (seeds, code references, Symfony DI); `closure_py.py`
does it for behave over two (seeds, imports) and says so — the DI edge is
absent rather than omitted.  This does it for cucumber-jvm over **one**, and
the reason is not that Java has fewer edges but that the ANSWER comes from a
different place.

    seeds   every step definition cucumber's OWN registry bound to a step of
            the scenario — including its Background steps, and including every
            Examples row, because cucumber runs an outline as one pickle per
            row.  The registry says so in its json plugin's `match.location`,
            which is a fully qualified `Class.method(ParamTypes)`.

**Why a registry parse and not a static matcher.**  Behat's and behave's
matchers are re-implementable: a pattern is a regex or a `parse` expression,
and `pystep_index` asks the live matcher only because compiling `parse` is
behave's job.  Cucumber's is not.  A cucumber-jvm step definition can come
from an annotation, from a lambda registered in a constructor, or from a
`@ParameterType`-typed expression whose regexp the registry builds at load
time out of other registrations; glue classes are discovered by SCANNING the
runner's package, and `cucumber-picocontainer` instantiates them by
reflection.  Any regex over the glue source would be a second, worse
implementation of that, and it would be wrong in exactly the cases that
matter — which is why this module NEVER reads a `.java` file to decide what
answers a step.  It reads cucumber's own answer.

**The registry supplies the seed set; reviewed companion edges complete a
project's closure.**  The PHP and Python twins expand transitively
because their indexes resolve a reference to a file: nikic/php-parser's
NameResolver for one, `ast` imports for the other.  There is no Java parser
here — ART's was tree-sitter, which is not among this benchmark's pinned
dependencies (PyYAML, jsonschema) — so there is no reference graph to walk,
and inventing one lexically would be the static analysis the paragraph above
refuses.  The only addition to cucumber's registry answers is an exact,
owner-supplied companion table, in two key shapes:

  * A `@ParameterType` registration is invisible to dry-run JSON BY
    CONSTRUCTION: the json plugin reports which method matched, never the
    expression it matched with.  The reviewed EPUBCheck edge therefore says
    only that `ViewportSteps.assertResult` needs `SharedParameterTypes`; it
    does not
    guess imports, scan annotations, or expand transitively.  That is the
    `(class, method)` key: METHOD-specific, because `parseViewport` and
    `assertValid` do not consume `{multimap}`.
  * A cross-package SOURCE reference is invisible to the same JSON for the
    same reason, and it is not method-specific: restoring a glue FILE
    restores every reference that file's bytes make, whichever method is
    bound.  That is the bare-FQCN key, and it is what Algorand needs — see
    `ALGORAND_COMPANION_CLASSES`.
  * Every other removable file remains registry-seed-only.
    `removable_census` names anything no item reached, so an additional
    invisible edge is a visible source decision rather than a silent guess.

**Cucumber does not match on the keyword.**  behave keys its registry on
(keyword, text) — which is why `stub_py` keys on the pair — and Behat keys on
the pattern.  A cucumber expression is keyword-agnostic: `@Given("a thing")`
answers `Then a thing` too, and the annotation kind is decoration.  So there
is no keyword resolution in this module at all: the binding key is the
(element line, step line) pair the registry itself reports, and `And`/`But`
never have to be resolved to anything.

**The unit is the FILE, and it is derived from the package, not from a
parse.**  `match.location`'s class is fully qualified, and javac requires a
class in package `a.b.c` to live at `a/b/c/` under a source root, so the file
is arithmetic over the FQCN rather than a lookup into an index built by
reading code.  `build_type_index` walks the source roots and does exactly
that; a nested class (`Outer$Inner`, which is what a picocontainer-injected
helper looks like in a code location) resolves to its top-level file.

**What is reused and what is not.**  `ItemClosure` and `StepBinding` are
imported from `closure.py` and subclassed, never copied — the same discipline
`closure_py.py` states: the release's gold sidecar is written from those keys
by one function that must not learn which stack it is looking at, and the
selftest below holds this stack's `to_json` to `closure_py.GOLD_SIDECAR_
FIELDS` rather than to a retyped list of them.  `feature_file` is repo-
RELATIVE here for `closure_py.py`'s reason.  `di_fragment` is `{}` and is
assigned rather than defaulted: cucumber-picocontainer wires the scanned glue
by reflection, so there is no container file to synthesise — which is also why
`boundary_epubcheck.yml` carries `retained_contexts: []`.

**The second half of this file is the cross-check, and the index the API
metric needs.**  ART read the same registry by a different route — cucumber
once per scenario, `pretty` plugin, `# <signature>` comment lines — and its
map is pinned under `fixtures/` with its provenance, which makes it a witness
rather than a second copy of our own answer.  `compare_to_gt` reports coverage
separately from agreement and ENUMERATES every disagreement, because ART's
epubcheck map covers 948 of the checkout's 1041 scenarios and a rate over the
intersection is not a statement about the other 93.  The gap is NOT only the
five feature files the map never ran: 41 scenarios inside the 44 it did run
are missing too, and `fixtures/PROVENANCE.md` says which and why, because
"44 feature files" reads as "those files, whole" and that is not what the
bytes say.  `build_api_index`
is ART's `collect_project_api_index.py` adapted: no tree-sitter (there is a
lexer instead, whose two hard cases are named in that section's header), and
its test-class leak fixed — epubcheck ships a `main`-method test class inside
`src/main/java`, and ART's pinned index attributes two API names to it.

Nothing here executes cucumber, Maven, Docker or a JVM.  It parses the bytes
a dry run produces, and D2b is where a dry run is produced.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..core.boundary import Boundary, PRODUCTION, REMOVABLE, RETAINED
from ..toolkit.closure import ItemClosure, StepBinding
from ..core.gherkin import Block, Feature
from ..toolkit.pystep_index import CUCUMBER_DIALECT, examples_rows


class ClosureJavaError(Exception):
    """A controlled refusal of dry-run evidence or of a closure input."""


#: `io.cucumber.plugin.event.Status`, lower-cased as the json plugin writes
#: it.  Closed: a status outside this set is a cucumber this module has not
#: been read against, and guessing what it means is how an unknown outcome
#: becomes a published number.
STATUSES = frozenset({
    "passed", "failed", "skipped", "pending", "undefined", "ambiguous"})

#: The four a DRY RUN can produce.  A dry run builds every match and invokes
#: nothing, so a definition is `passed`, a missing one is `undefined`, two
#: matching ones are `ambiguous`, and the steps after a non-passing one are
#: `skipped`.  `failed` and `pending` need a step body to run.  This is a
#: vocabulary for `dry_run_problems` to ENUMERATE against, not to refuse on:
#: an unexpected status is a finding about the run, and an unknown status name
#: is a finding about the format.
DRY_RUN_STATUSES = frozenset({"passed", "skipped", "undefined", "ambiguous"})

#: Runtime artifacts are already scoped to one project/attempt, so their
#: names do not repeat the project.  The reality capture writes the first;
#: `cmd_closures` deterministically derives the latter two.
DRY_RUN_ARTIFACT = "cucumber_dry_run.json"
CLOSURES_ARTIFACT = "closures.json"
CENSUS_ARTIFACT = "java_closure_census.json"

JAVA_TEST_SOURCE_ROOTS = ("src/test/java",)


def test_source_roots(project: str) -> tuple[str, ...]:
    if project == "kapua":
        from .kapua import TEST_SOURCE_ROOTS
        return TEST_SOURCE_ROOTS
    return JAVA_TEST_SOURCE_ROOTS


#: The one registry-invisible edge approved for EPUBCheck.  Method-specific:
#: `parseViewport` and `assertValid` do not consume `{multimap}` and therefore
#: do not inherit this file merely because they share a class.
EPUBCHECK_COMPANION_CLASSES = {
    ("org.w3c.epubcheck.util.microsyntax.ViewportSteps", "assertResult"): (
        "org.w3c.epubcheck.SharedParameterTypes",),
}

#: The registry-invisible edges approved for algorand-sdk, keyed on the bare
#: FQCN because they are WHOLE-CLASS: the gold solution restores a glue FILE,
#: and that file's own bytes reference other removable classes regardless of
#: which of its methods an item bound.  Algorand's glue is scattered across
#: `unit`, `integration` and `cucumber.shared`, and a same-package reference
#: carries no import line, so cucumber's JSON cannot report the edge at all.
#:
#: DERIVED, NOT ASSERTED.  Each entry is the converged fixpoint of restoring
#: the key ALONE onto the stripped workspace and running the canonical image's
#: `mvn -o -B -Dmaven.repo.local=/opt/m2 test-compile` until it passes, adding
#: at each wave the removable file javac's own diagnostic named.  All 18
#: removable classes were derived; the ten below need companions and the other
#: eight compile alone.  Every value set is transitively closed (checked in
#: `selftest`).  The full derivation — per-item and per-class waves, the
#: one-shot verification over all 59 candidates, and the compile logs — is
#: `req2test_wave5_20260811/DEFECT_B_DERIVATION.md`.
#:
#: WHY THE KEY IS THE FQCN AND NEVER THE SIMPLE NAME.  Two distinct removable
#: classes are both named `AtomicTxnComposer` — one in `unit`, one in
#: `integration` — and their companion sets genuinely differ: the integration
#: one additionally drags `integration.Applications` (454 lines).  A table
#: keyed on the simple name would merge them and pull `Applications` into
#: every unit item for nothing.  The derivation itself never resolved a bare
#: simple name either: every symbol was settled by javac's own
#: `location: package P`, by an explicit single-type import in the erroring
#: file, or by that file's own `package` declaration.
#:
#: The first three keys are the ones the current candidate pool reaches; the
#: rest are true of the corpus and already satisfied by every closure that
#: names them, so adding them changes no item today and stops the table from
#: depending on which items happen to be drawn.
ALGORAND_COMPANION_CLASSES = {
    "com.algorand.algosdk.cucumber.shared.TransactionSteps": (
        "com.algorand.algosdk.integration.Stepdefs",
        "com.algorand.algosdk.integration.TransientAccount",
        "com.algorand.algosdk.unit.Base"),
    "com.algorand.algosdk.unit.AtomicTxnComposer": (
        "com.algorand.algosdk.cucumber.shared.TransactionSteps",
        "com.algorand.algosdk.integration.Stepdefs",
        "com.algorand.algosdk.integration.TransientAccount",
        "com.algorand.algosdk.unit.ABIJson",
        "com.algorand.algosdk.unit.Base"),
    "com.algorand.algosdk.unit.TealSign": (
        "com.algorand.algosdk.unit.Rekeying",),
    "com.algorand.algosdk.integration.Applications": (
        "com.algorand.algosdk.integration.Stepdefs",
        "com.algorand.algosdk.integration.TransientAccount"),
    "com.algorand.algosdk.integration.AtomicTxnComposer": (
        "com.algorand.algosdk.cucumber.shared.TransactionSteps",
        "com.algorand.algosdk.integration.Applications",
        "com.algorand.algosdk.integration.Stepdefs",
        "com.algorand.algosdk.integration.TransientAccount",
        "com.algorand.algosdk.unit.Base"),
    "com.algorand.algosdk.integration.TransientAccount": (
        "com.algorand.algosdk.integration.Stepdefs",),
    "com.algorand.algosdk.unit.AlgodPaths": (
        "com.algorand.algosdk.unit.PathsShared",),
    "com.algorand.algosdk.unit.IndexerPaths": (
        "com.algorand.algosdk.unit.PathsShared",),
    "com.algorand.algosdk.unit.AlgodResponses": (
        "com.algorand.algosdk.unit.ResponsesShared",),
    "com.algorand.algosdk.unit.IndexerResponses": (
        "com.algorand.algosdk.unit.ResponsesShared",),
}

# Measured on the pinned Kapua source in development image b0084fa24ff63:
# restore TranslatorSteps alone after the exact 24-file strip, compile offline
# with -pl translator/test -am: javac reports missing ExampleTranslator at
# TranslatorSteps.java:56. Restore only that original helper and clear prior
# step output: the identical compile exits 0. This is a whole-file dependency,
# not a new registry binding. Preserved two-compile receipt under Track K:
# translator-companion-attempt2/receipt.json, SHA256
# 2b1b7c69b7277a4fe41f23ec31f0f51acd93a697736db2b69ee72cfa1dca3f07.
KAPUA_COMPANION_CLASSES = {
    "org.eclipse.kapua.translator.test.steps.TranslatorSteps": (
        "org.eclipse.kapua.translator.test.steps.ExampleTranslator",),
}

COMPANION_CLASSES_BY_PROJECT = {
    "epubcheck": EPUBCHECK_COMPANION_CLASSES,
    "algorand-sdk": ALGORAND_COMPANION_CLASSES,
    "kapua": KAPUA_COMPANION_CLASSES,
}

UNDEFINED = "undefined"
AMBIGUOUS = "ambiguous"
PASSED = "passed"
SKIPPED = "skipped"

#: The two statuses that carry NO `match.location`, and they are not one
#: status and one accident.  `JsonFormatter.createMatchMap` writes
#: `matchMap.put("location", getCodeLocation())` under a guard on
#: `Status.UNDEFINED` alone -- but `getCodeLocation()` delegates to the
#: step's `StepDefinition.getLocation()`, and BOTH
#: `UndefinedPickleStepDefinitionMatch` and
#: `AmbiguousPickleStepDefinitionsMatch` are constructed with
#: `NoStepDefinition`, whose `getLocation()` returns null.  The mapper is
#: built with `serializationInclusion(NON_ABSENT)`, so the null is dropped
#: and an ambiguous step is written `"match": {}` -- a step with TWO
#: definitions and no name for either.  Verified with `javap -c` over
#: `cucumber-core-7.8.0.jar`, the version epubcheck's `pom.xml` pins.
LOCATIONLESS_STATUSES = frozenset({UNDEFINED, AMBIGUOUS})

#: The mirror, and the half a one-sided reader lets through.  These three are
#: only reachable by INVOKING the match: `ExecutionMode.RUN` and `DRY_RUN`
#: call `runStep`/`dryRunStep`, both of which THROW on a `NoStepDefinition`
#: (`UndefinedStepDefinitionException`, `AmbiguousStepDefinitionsException`),
#: so reaching `passed` -- or `failed`/`pending` from
#: `mapThrowableToStatus` -- means a real `StepDefinition` ran and named
#: itself.  A document that reports one of these with no `match.location` did
#: not come out of cucumber, and `unstripped_bindings` would read it as a
#: clean strip while every removable step still answered.
#:
#: `skipped` is in NEITHER set, and that asymmetry is forced rather than
#: chosen: `ExecutionMode.SKIP.execute` returns `Status.SKIPPED`
#: without touching the match at all, and `ExecutionMode.next` makes SKIP
#: absorbing, so the second undefined step of a pickle is reported `skipped`
#: with no location — genuine output this parser must not refuse — while a
#: skipped step whose OWN definition survived keeps that definition's
#: location.  `skipped` comes out both ways round, so no status-keyed
#: location rule can constrain it in either direction: a rule that demanded
#: a location for `skipped` would refuse
#: `cucumber_dry_run_epubcheck_stripped.json`, which carries two locationless
#: `skipped` steps this module was built to read.  What constrains `skipped`
#: is its POSITION instead -- see `_validate_skip_order`, which closes the
#: same corrupted-artifact hole from the one side that is actually sound.
#: (All four facts read with `javap -c` over `cucumber-core-7.8.0.jar`.)
INVOKED_STATUSES = frozenset({"passed", "failed", "pending"})

#: What a DRY RUN reports is a CUCUMBER-VERSION fact, and the two pinned
#: versions do not agree, so this parser dispatches on the version instead of
#: assuming one.  Under 7.8.0 `DRY_RUN.execute` INVOKES the match, so a bound
#: step is `passed`, a missing one is `undefined`, and everything after the
#: first non-passed outcome is `skipped` -- an ORDER, which
#: `_validate_skip_order` reads.  Under 6.6.0 `DRY_RUN.execute` returns
#: `SKIPPED` without consulting the match, so EVERY step of every pickle is
#: `skipped` whether the glue is there or not and the order carries no signal
#: at all; what separates the two trees is whether the steps carry a
#: `match.location`, uniformly over the whole document.
#:
#: Measured, not assumed (same image and argv as the phase):
#:
#:   algorand 6.6.0 unstripped dry  1585 steps  skipped, all LOCATED
#:   algorand 6.6.0 stripped   dry  1779 steps  skipped, all LOCATIONLESS
#:   epubcheck 7.8.0 unstripped dry 5555 steps  passed,  all located
#:   epubcheck 7.8.0 stripped  dry  2205 passed/located, 1136
#:                                  undefined/locationless, 2214
#:                                  skipped/locationless
#:
#: DISCLOSED RESIDUAL WEAKNESS: because 6.6.0 emits the same bytes for an
#: honestly stripped tree and for a document forged by dropping every
#: `match.location`, a single 6.6.0 dry-run document cannot tell those two
#: apart, and no rule here can recover what the format did not record.  The
#: 7.8.0 position guarantee has no exact 6.6.0 analogue.  What is enforced
#: below is the part that IS checkable -- the document must be internally
#: consistent, so a forger cannot disguise ONE answered step as unanswered --
#: and the rest of the claim is carried across legs by `reality`
#: (`pickle_sets_stable`, `stripped_bindings_empty`, and a non-empty
#: unstripped binding set), never by one document alone.
#: Kapua 6.11.0 has the invoking dry-run contract: its native Account capture
#: reports 63 passed/located steps; removing answer files yields 6 passed,
#: 20 undefined and 37 skipped steps (Maven exit 1). See fixtures/PROVENANCE.md.
DRY_RUN_CONTRACTS = frozenset({"7.8.0", "6.6.0", "6.11.0"})

#: The two states a 6.6.0 dry-run document may be in, uniformly.  `LOCATED`
#: is an unstripped capture (every step names its glue), `LOCATIONLESS` is a
#: stripped one (no step does).
LOCATED = "located"
LOCATIONLESS = "locationless"
DOCUMENT_STATES = frozenset({LOCATED, LOCATIONLESS})


def dry_run_contract(project: str) -> str:
    """The pinned cucumber version whose dry-run contract `project` obeys.

    The authority is `j0.PARSER_STACKS`, the closed per-project record that
    already pins this project's parser artifacts by sha256 -- not a second
    copy of the version kept here.  Imported lazily: `j0` does not import
    this module, but it is a large module and nothing else here needs it.
    """
    from .j0 import PARSER_STACKS

    spec = PARSER_STACKS.get(project)
    version = spec.get("cucumber_version") if isinstance(spec, dict) else None
    if version not in DRY_RUN_CONTRACTS:
        raise ClosureJavaError(
            f"{project!r}: no reviewed cucumber dry-run contract (pinned "
            f"version {version!r}); this parser has been read against "
            f"{sorted(DRY_RUN_CONTRACTS)} and guessing at a third is how an "
            f"unread execution model becomes a published number")
    return version


def _validate_dry_run_6_6_0(case, where: str) -> set:
    """One 6.6.0 dry-run pickle, returning the location states it showed.

    Nothing is invoked, so any INVOKED status is a document that did not come
    from a dry run of this cucumber.  `undefined` is not refused here: 6.6.0
    does not emit it in this mode, and if a future capture does, it is a
    finding for `dry_run_problems` to ENUMERATE exactly as it does under
    7.8.0, not a parse refusal.
    """
    states = set()
    for origin, step in case.all_steps:
        if step.status != SKIPPED:
            raise ClosureJavaError(
                f"{where}: the {origin} step at line {step.line} is "
                f"{step.status!r}, but cucumber 6.6.0's DRY_RUN.execute "
                f"returns SKIPPED without consulting the match, so every "
                f"step of a genuine 6.6.0 dry run is 'skipped'")
        states.add(LOCATED if step.location is not None else LOCATIONLESS)
    return states
#: nothing here (cucumber flattens them into the scenario's own element), and
#: a third type would mean this reader is looking at a document it has not
#: been read against.
ELEMENT_TYPES = frozenset({"background", "scenario"})

#: How a feature is addressed in `uri`.  `classpath:` is what epubcheck's
#: `@CucumberOptions(features = "classpath:")` produces; `file:` is what a
#: path-configured suite produces (the shape in the real metasfresh output
#: this parser's fixtures were modelled on).  Anything else is refused rather
#: than guessed at, because a uri that does not resolve to a repo-relative
#: path silently produces a closure for the wrong item.
URI_SCHEMES = ("classpath:", "file:")

#: `fully.qualified.Class.method(fully.qualified.ParamTypes)` — the shape
#: `MethodFormat.FULL` writes and the one both real cucumber json output and
#: ART's `pretty`-plugin map carry.  Java type names have no parentheses in
#: them, so the parameter list is everything between the last pair.
LOCATION = re.compile(
    r"^(?P<cls>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
    r"\.(?P<method>[A-Za-z_$][\w$]*)"
    r"\((?P<params>[^()]*)\)$")


# ------------------------------------------------------------- validation
def _object(value: Any, required: set, optional: set, where: str) -> dict:
    """A json object with EXACTLY `required`, and nothing outside `optional`.

    Two-sided on purpose.  A missing required key is a reader that would have
    produced `None` where a fact belongs; an unknown key is a cucumber whose
    output has grown a member this module has never been read against, and
    ignoring it is how a format change becomes a silent behaviour change.
    """
    if not isinstance(value, dict):
        raise ClosureJavaError(f"{where}: expected object")
    actual = set(value)
    missing = required - actual
    unknown = actual - required - optional
    if missing or unknown:
        raise ClosureJavaError(
            f"{where}: schema mismatch; missing={sorted(missing)!r}, "
            f"unknown={sorted(unknown)!r}")
    return value


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ClosureJavaError(f"{where}: expected string")
    return value


def _line(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ClosureJavaError(f"{where}: expected 1-based line number")
    return value


def _array(value: Any, where: str) -> list:
    if not isinstance(value, list):
        raise ClosureJavaError(f"{where}: expected array")
    return value


def normalize_uri(uri: str, feature_root: str, where: str) -> str:
    """A cucumber feature `uri`, as the repo-relative path an item id uses.

    `classpath:` is resolved against the resource root the features are
    packaged from; `file:` is already repo-relative in the output this parser
    was read against.  The result must land under `feature_root` — a uri that
    escapes it is a suite pointed somewhere this repository does not own.
    """
    for scheme in URI_SCHEMES:
        if uri.startswith(scheme):
            rest = uri[len(scheme):].lstrip("/")
            rel = (f"{feature_root}/{rest}" if scheme == "classpath:" else rest)
            break
    else:
        raise ClosureJavaError(
            f"{where}: uri {uri!r} uses no known scheme {URI_SCHEMES!r}")
    rel = rel.replace(os.sep, "/")
    if not rel.startswith(feature_root.rstrip("/") + "/"):
        raise ClosureJavaError(
            f"{where}: uri {uri!r} resolves to {rel!r}, outside the feature "
            f"root {feature_root!r}")
    return rel


# ---------------------------------------------------------------- records
@dataclass(frozen=True)
class DryRunStep:
    """One step of one pickle, as the registry answered it."""
    keyword: str                  # "Given ", "And " — cucumber's own, spaced
    name: str                     # the step text, Examples row substituted
    line: int                     # the step's SOURCE line in the feature
    status: str
    location: Optional[str]       # `match.location`, or None if unbound

    @property
    def bound(self) -> bool:
        """Did the registry NAME a method for this step?

        The `location` and not the status, because they answer different
        questions -- and `skipped` is the status that proves it, by coming
        out BOTH ways round.  Cucumber matches every step of a pickle before
        it runs any of them (`Runner.createTestStepsForPickleSteps`), so a
        step that was never reached keeps whatever its match already carried:
        a real definition's `match.location` survives being skipped
        (`ExecutionMode.SKIP.execute` returns SKIPPED without touching the
        match, and `createMatchMap`'s location guard is on `UNDEFINED`
        alone), while a step whose match is the `NoStepDefinition`
        placeholder is skipped with no location at all -- which is exactly
        what a stripped tree writes for the second glue step of a two-glue-
        step scenario.  So `skipped` is in neither `LOCATIONLESS_STATUSES`
        nor `INVOKED_STATUSES`, `_validate_step` constrains it in neither
        direction, and reading the status here would answer the wrong
        question in both.

        That exemption is not a blind spot, because what `skipped` escapes
        here it does not escape one level up: `_validate_skip_order`
        constrains a `skipped` step by POSITION, which is the property SKIP
        propagation actually fixes.  A genuinely `passed` step disguised as a
        locationless `skipped` one would be invisible to `bound` -- and never
        reaches `bound`, because the parser refuses it.

        `ambiguous` is what makes the distinction load-bearing: it has TWO
        definitions and cucumber names NEITHER, because
        `AmbiguousPickleStepDefinitionsMatch` carries a `NoStepDefinition`
        (see `LOCATIONLESS_STATUSES`).  So `bound` is False for it, its
        closure is missing BOTH glue files, and calling that "unmatched"
        would name the wrong defect -- which is why `closure_for` reports it
        as `ambiguous_step` and `dry_run_problems` enumerates it.
        """
        return self.location is not None

    @property
    def ambiguous(self) -> bool:
        """Did cucumber find more than one definition for this step?

        A separate question from `bound`, and the reason `bound` alone is not
        enough to build a closure on: this is the case where the registry has
        the answer and refuses to give it.
        """
        return self.status == AMBIGUOUS


@dataclass(frozen=True)
class DryRunCase:
    """One PICKLE: a scenario, or one Examples row of an outline.

    `line` is the pickle's own line — the `Scenario:` line for a plain
    scenario and the Examples DATA ROW's line for an outline row, which is
    what makes `example_line` joinable to the record the harness stamps.
    """
    uri: str
    line: int
    name: str
    keyword: str
    background: tuple                     # tuple[DryRunStep, ...]
    steps: tuple                          # tuple[DryRunStep, ...]
    #: The `before`-hook STATUSES of this pickle, in emission order, and the
    #: only thing read off a hook.  They matter for one reason: a hook that
    #: did not pass puts the whole test case into `ExecutionMode.SKIP` before
    #: its first step, which is the one way a pickle can genuinely OPEN with
    #: a `skipped` step (see `_validate_skip_order`).  `dry_run_problems`
    #: enumerates every non-passed one, so that exemption is a disclosed
    #: finding rather than a free pass.
    before_hooks: tuple = ()              # tuple[str, ...]

    @property
    def all_steps(self) -> list:
        return [("background", s) for s in self.background] + \
               [("scenario", s) for s in self.steps]


class DryRun:
    """Every pickle a `--dry-run` reported, keyed by `(uri, line)`."""

    def __init__(self, cases: list):
        self.cases: dict = {}
        for case in cases:
            key = (case.uri, case.line)
            if key in self.cases:
                raise ClosureJavaError(
                    f"{case.uri}:{case.line}: two pickles share one line; a "
                    f"pickle's line is its identity here")
            self.cases[key] = case

    def case(self, uri: str, line: int) -> DryRunCase:
        try:
            return self.cases[(uri, line)]
        except KeyError:
            raise ClosureJavaError(
                f"{uri}:{line}: the dry run reports no pickle here") from None

    def uris(self) -> list:
        return sorted({uri for uri, _line in self.cases})


# ------------------------------------------------------------------ parse
_FEATURE = ({"uri", "elements"},
            {"description", "id", "keyword", "line", "name", "tags"})
_ELEMENT = ({"type", "keyword", "line", "name", "steps"},
            {"description", "id", "tags", "start_timestamp", "before", "after"})
_STEP = ({"keyword", "line", "name", "match", "result"},
         {"rows", "doc_string", "output", "embeddings"})
_RESULT = ({"status"}, {"duration", "error_message"})
_MATCH = (set(), {"location", "arguments"})
#: A hook entry of an element's `before`/`after` list.
#: `handleTestStepFinished` puts `match` and `result` into
#: `currentStepOrHookMap` for hooks exactly as it does for steps, and
#: `handleWrite`/`handleEmbedding` add `output` and `embeddings` to that same
#: map (`javap -c` over `cucumber-core-7.8.0.jar`).
_HOOK = ({"match", "result"}, {"output", "embeddings"})


def _validate_step(raw: Any, where: str) -> DryRunStep:
    step = _object(raw, *_STEP, where)
    result = _object(step["result"], *_RESULT, f"{where}.result")
    status = _string(result["status"], f"{where}.result.status")
    if status not in STATUSES:
        raise ClosureJavaError(
            f"{where}.result.status: {status!r} is not one of "
            f"{sorted(STATUSES)!r}")
    match = _object(step["match"], *_MATCH, f"{where}.match")
    location = match.get("location")
    if location is not None:
        location = _string(location, f"{where}.match.location")
        if LOCATION.fullmatch(location) is None:
            raise ClosureJavaError(
                f"{where}.match.location: {location!r} is not a "
                f"Class.method(ParamTypes) code location")
    if status in LOCATIONLESS_STATUSES and location is not None:
        # Neither an `undefined` nor an `ambiguous` step can name a method:
        # both carry a `NoStepDefinition` whose `getLocation()` is null (see
        # `LOCATIONLESS_STATUSES`).  Both at once means one of the two is not
        # what it claims, and a closure built on it would name a file for a
        # step nothing answered -- or, for `ambiguous`, name ONE file for a
        # step two files answer.
        raise ClosureJavaError(
            f"{where}: status is {status!r} but a code location is "
            f"reported ({location!r})")
    if status in INVOKED_STATUSES and location is None:
        # The other direction, and the one that matters for safety: a
        # `passed` step with its location deleted is a step `unstripped_
        # bindings` cannot see, which turns the D2b round-trip gate's "no
        # step of any pickle is answered by a REMOVABLE file" into a question
        # nobody asked.  Refused rather than guessed at, like everything else
        # here.  `skipped` is exempt from BOTH directions here for the reason
        # `INVOKED_STATUSES` gives -- and is not thereby unchecked: the same
        # deletion done under a `skipped` status is refused by
        # `_validate_skip_order`, one level up, on position instead.
        raise ClosureJavaError(
            f"{where}: status is {status!r} but no code location is "
            f"reported; only {sorted(LOCATIONLESS_STATUSES)} and 'skipped' "
            f"can be locationless")
    return DryRunStep(keyword=_string(step["keyword"], f"{where}.keyword"),
                      name=_string(step["name"], f"{where}.name"),
                      line=_line(step["line"], f"{where}.line"),
                      status=status, location=location)


def _hook_statuses(element: dict, where: str) -> tuple:
    """The `before`-hook outcomes of one json element, in emission order.

    Read for exactly one reason: a hook that did not pass puts the whole test
    case into `ExecutionMode.SKIP` before its first step, which is the ONE
    way a pickle can genuinely OPEN with a `skipped` step.  Without this,
    `_validate_skip_order` would refuse a real document whose `@Before` threw.

    Only the STATUS is read.  A hook's `match.location` comes from
    `HookDefinitionMatch.getCodeLocation`, a different formatter from the
    `MethodFormat.FULL` one `LOCATION` was written against, and this module
    has not been read against it -- so it is carried, not parsed.
    """
    out: list = []
    for h_index, raw in enumerate(
            _array(element.get("before", []), f"{where}.before")):
        hwhere = f"{where}.before[{h_index}]"
        hook = _object(raw, *_HOOK, hwhere)
        result = _object(hook["result"], *_RESULT, f"{hwhere}.result")
        status = _string(result["status"], f"{hwhere}.result.status")
        if status not in STATUSES:
            raise ClosureJavaError(
                f"{hwhere}.result.status: {status!r} is not one of "
                f"{sorted(STATUSES)!r}")
        out.append(status)
    return tuple(out)


def _validate_skip_order(case: DryRunCase, where: str) -> None:
    """`skipped` is not free to appear anywhere, and that is the whole check.

    One pickle is one `TestCase.run`, and that method is a SINGLE chained
    fold -- before-hooks (offsets 86-93), then the background's steps and the
    scenario's own in emission order (offsets 140-144), each link threading
    one `ExecutionMode` through `.next()`.  `TestStep.run` ends
    `return result.getStatus().is(PASSED) ? executionMode : SKIP` (offsets
    105-127), `ExecutionMode.next(other)` returns `other` when `other` is
    SKIP and `this` otherwise (offsets 0-12, so SKIP is absorbing), and
    `ExecutionMode$3.execute` -- SKIP -- returns `Status.SKIPPED` in two
    instructions without ever consulting the match.  Two directions fall out,
    and they are one rule:

      * AFTER the first non-passed outcome, every remaining step is
        `skipped`; SKIP.execute has no other answer to give.
      * BEFORE it, no step can be `skipped`; the mode is still RUN or
        DRY_RUN, both of which invoke the match and report what it did.

    Why this and not a status-keyed location rule: `skipped` is the one
    status that comes out BOTH ways round (see `INVOKED_STATUSES`), so
    demanding a location for it would refuse
    `cucumber_dry_run_epubcheck_stripped.json`.  But that same exemption is
    what a corrupted artifact can hide in -- take a genuinely `passed` step
    bound to REMOVABLE glue, flip it to `skipped`, drop its location, and
    `unstripped_bindings` (which reads locations) and `dry_run_problems`
    (which reads statuses against `DRY_RUN_STATUSES`) both go blind, so a
    tree that was never stripped certifies as a clean strip.  The disguise
    does not survive POSITION: the flipped step's predecessors all passed, so
    nothing put its test case into SKIP.  A forger has to make the whole
    prefix consistent -- at which point the document is no longer claiming
    those steps were answered, which is the honest claim to begin with.

    (Every offset read with `javap -c` over `cucumber-core-7.8.0.jar`, the
    version epubcheck's `pom.xml` pins.)
    """
    skipping = any(status != PASSED for status in case.before_hooks)
    for origin, step in case.all_steps:
        if skipping and step.status != SKIPPED:
            raise ClosureJavaError(
                f"{where}: the {origin} step at line {step.line} is "
                f"{step.status!r}, but an outcome before it in this pickle "
                f"did not pass; SKIP is absorbing and SKIP.execute returns "
                f"SKIPPED without consulting the match, so cucumber can "
                f"report nothing else here")
        if not skipping and step.status == SKIPPED:
            raise ClosureJavaError(
                f"{where}: the {origin} step at line {step.line} is "
                f"'skipped', but every outcome before it in this pickle "
                f"passed; nothing put this test case into ExecutionMode."
                f"SKIP, so cucumber would have INVOKED the match and "
                f"reported what it found")
        if step.status != PASSED:
            skipping = True


def parse_dry_run(doc: Any, feature_root: str, *, project: str,
                  dry_run: bool = True,
                  expect_state: Optional[str] = None) -> DryRun:
    """The json plugin's document, as pickles.

    A background is its own element, emitted immediately before the scenario
    element it ran for — cucumber repeats it once per scenario — so the
    pairing here is positional and a background that no scenario follows is a
    document this reader does not understand.

    The pairing is also what makes `_validate_skip_order` possible: the two
    elements are ONE `TestCase.run`, so SKIP propagation is a property of the
    joined pickle and cannot be checked element by element.

    `project` selects the dry-run contract (see `DRY_RUN_CONTRACTS`).
    `dry_run` says whether this document came from `--dry-run`; it defaults to
    the STRICT branch so that a call site which forgets to declare an ordinary
    run refuses loudly instead of being admitted under the wrong model.  Only
    6.6.0 dry runs read it: a 6.6.0 ORDINARY run is RUN mode, whose SKIP
    propagation is the same fact 7.8.0's is, so it keeps `_validate_skip_order`.

    `expect_state` is the location state this leg MUST be in -- `LOCATED` for
    an unstripped capture, `LOCATIONLESS` for a stripped one.  Pass it wherever
    the leg is known; where it is not, leaving it `None` still requires the
    document to be uniform, which is the part that stops a one-step forgery.
    """
    contract = dry_run_contract(project)
    if expect_state is not None and expect_state not in DOCUMENT_STATES:
        raise ClosureJavaError(
            f"expect_state {expect_state!r} is not one of "
            f"{sorted(DOCUMENT_STATES)}")
    version_6_6_0_dry = contract == "6.6.0" and dry_run
    states: set = set()
    cases: list = []
    for f_index, raw_feature in enumerate(_array(doc, "dry-run")):
        where = f"dry-run[{f_index}]"
        feature = _object(raw_feature, *_FEATURE, where)
        uri = normalize_uri(_string(feature["uri"], f"{where}.uri"),
                            feature_root, f"{where}.uri")
        pending: Optional[tuple] = None
        for e_index, raw_element in enumerate(
                _array(feature["elements"], f"{where}.elements")):
            ewhere = f"{where}.elements[{e_index}]"
            element = _object(raw_element, *_ELEMENT, ewhere)
            kind = _string(element["type"], f"{ewhere}.type")
            if kind not in ELEMENT_TYPES:
                raise ClosureJavaError(
                    f"{ewhere}.type: {kind!r} is not one of "
                    f"{sorted(ELEMENT_TYPES)!r}")
            steps = tuple(
                _validate_step(raw_step, f"{ewhere}.steps[{s_index}]")
                for s_index, raw_step in enumerate(
                    _array(element["steps"], f"{ewhere}.steps")))
            hooks = _hook_statuses(element, ewhere)
            if kind == "background":
                if pending is not None:
                    raise ClosureJavaError(
                        f"{ewhere}: a background element follows another with "
                        f"no scenario between them")
                pending = (steps, hooks)
                continue
            # `JsonFormatter.addHookStepToTestCaseMap` files a BEFORE hook
            # under `currentTestCaseMap`, which is the SCENARIO element -- but
            # the hooks run before the background's steps either way, so both
            # elements' lists are collected and both precede every step.
            background, background_hooks = pending or ((), ())
            case = DryRunCase(
                uri=uri, line=_line(element["line"], f"{ewhere}.line"),
                name=_string(element["name"], f"{ewhere}.name"),
                keyword=_string(element["keyword"], f"{ewhere}.keyword"),
                background=background, steps=steps,
                before_hooks=background_hooks + hooks)
            if version_6_6_0_dry:
                states |= _validate_dry_run_6_6_0(
                    case, f"{uri}:{case.line}")
            else:
                _validate_skip_order(case, f"{uri}:{case.line}")
            cases.append(case)
            pending = None
        if pending is not None:
            raise ClosureJavaError(
                f"{where}: the last background element has no scenario")
    if version_6_6_0_dry and states:
        if len(states) > 1:
            raise ClosureJavaError(
                f"this 6.6.0 dry run mixes {sorted(states)} steps; a capture "
                f"is either wholly bound (unstripped) or wholly unbound "
                f"(stripped), and a document that is both is the one forgery "
                f"6.6.0's all-skipped output still lets this reader catch")
        state = states.pop()
        if expect_state is not None and state != expect_state:
            raise ClosureJavaError(
                f"this 6.6.0 dry run is {state!r}, but the leg it was "
                f"captured for is {expect_state!r}")
    return DryRun(cases)


def load_dry_run(path: str, feature_root: str, *, project: str,
                 dry_run: bool = True,
                 expect_state: Optional[str] = None) -> DryRun:
    with open(path, encoding="utf-8") as fh:
        return parse_dry_run(json.load(fh), feature_root, project=project,
                             dry_run=dry_run, expect_state=expect_state)


# ------------------------------------------------------------- code location
def split_location(location: str, where: str) -> tuple:
    """`(fqcn, method, param types)` out of a cucumber code location."""
    m = LOCATION.fullmatch(location)
    if m is None:
        raise ClosureJavaError(
            f"{where}: {location!r} is not a Class.method(ParamTypes) code "
            f"location")
    return (m.group("cls"), m.group("method"), m.group("params"))


def top_level_class(fqcn: str) -> str:
    """The class whose FILE holds `fqcn`.

    `Outer$Inner` is what a nested glue helper looks like in a code location —
    `ViewportSteps$TestErrorHandler` is a real one in this corpus — and it
    lives in `Outer.java`.
    """
    return fqcn.split("$", 1)[0]


def build_type_index(repo_root: str, source_roots) -> dict:
    """`fully.qualified.Class -> repo-relative .java path`, by walking.

    No code is read.  javac resolves `a.b.C` on the source path by looking for
    `a/b/C.java`, so under a source root the path IS the fully qualified name;
    `build_api_index` re-derives the same name from the `package` declaration
    and refuses a disagreement, which is where that rule is checked rather
    than assumed.
    """
    index: dict = {}
    for root in source_roots:
        base = os.path.join(repo_root, root)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(dirnames)
            for name in sorted(filenames):
                if not name.endswith(".java"):
                    continue
                rel = os.path.relpath(os.path.join(dirpath, name),
                                      repo_root).replace(os.sep, "/")
                fqcn = rel[len(root):].strip("/")[:-len(".java")].replace(
                    "/", ".")
                if fqcn in index:
                    raise ClosureJavaError(
                        f"{fqcn}: declared by two files, {index[fqcn]!r} and "
                        f"{rel!r}")
                index[fqcn] = rel
    return index


# -------------------------------------------------------------- the closure
@dataclass
class JavaStepBinding(StepBinding):
    """A `StepBinding` that also carries what the registry said.

    Additive with defaults, so everything that reads a `StepBinding` —
    `ItemClosure`'s counts, the `(text, side)` pairs a stub is built from —
    keeps working.  `example_line` is the Examples DATA ROW's line, the same
    field and the same meaning `closure_py.PyStepBinding` gives it, because a
    binding has to be joinable to the per-row record whichever stack produced
    it.  `location` and `status` are the registry's own words, kept rather
    than translated away.
    """
    example_line: Optional[int] = None
    example_row: Optional[int] = None
    source_line: Optional[int] = None
    location: Optional[str] = None
    status: Optional[str] = None


@dataclass
class JavaItemClosure(ItemClosure):
    """An `ItemClosure` carrying the outline structure the counts flatten."""
    source_steps: int = 0
    example_lines: list = field(default_factory=list)
    locations: list = field(default_factory=list)

    def to_json(self) -> dict:
        doc = super().to_json()
        for out, binding in zip(doc["steps"], self.steps):
            out["example_line"] = binding.example_line
            out["example_row"] = binding.example_row
            out["source_line"] = binding.source_line
            out["location"] = binding.location
            out["status"] = binding.status
        doc["example_lines"] = list(self.example_lines)
        doc["locations"] = list(self.locations)
        doc["counts"]["source_steps"] = self.source_steps
        doc["counts"]["example_rows"] = len(self.example_lines)
        return doc


class JavaClosureExtractor:
    """Builds one item's closure out of the registry's answers for it.

    Constructed once per sweep and reused, like both twins: it holds the whole
    dry run and the whole type index, and rebuilding either per item is the
    difference between seconds and hours.
    """

    def __init__(self, dry_run: DryRun, boundary: Boundary, type_index: dict,
                 companion_classes: Optional[dict] = None):
        self.dry_run = dry_run
        self.boundary = boundary
        self.type_index = type_index
        self.repo_root = os.path.abspath(boundary.repo_root)
        self.companion_classes = dict(companion_classes or {})
        for source, companions in self.companion_classes.items():
            # Two key shapes, and the shape IS the scope: a `(class, method)`
            # pair is a method-specific edge, a bare string is whole-class.
            # Anything else is a table this reader has not been built against,
            # and a silently ignored key is a closure that is quietly short a
            # file -- exactly the defect the whole-class shape exists to fix.
            if not (isinstance(source, str)
                    or (isinstance(source, tuple) and len(source) == 2
                        and all(isinstance(part, str) for part in source))):
                raise ClosureJavaError(
                    f"companion edge {source!r}: a key is either a class FQCN "
                    "(whole-class) or a (class, method) pair (method-"
                    "specific), and this is neither")
            for companion in companions:
                rel = self.file_of(companion)
                if rel is None:
                    raise ClosureJavaError(
                        f"companion edge {source!r}: class {companion!r} "
                        "is absent from the Java type index")
                verdict = self.boundary.classify(rel)
                if verdict != REMOVABLE:
                    raise ClosureJavaError(
                        f"companion edge {source!r}: {companion!r} resolves "
                        f"to {rel!r}, classified {verdict}, not removable")

    # ------------------------------------------------------------ seeding
    def file_of(self, fqcn: str) -> Optional[str]:
        """The repo-relative file holding `fqcn`, or None if it is not ours.

        None is the twins' PRODUCTION verdict: a class the index does not know
        is vendor, JDK or production code, recorded by name and never followed.
        """
        return self.type_index.get(top_level_class(fqcn))

    def _definition(self, step: DryRunStep, where: str) -> Optional[dict]:
        """The registry's answer in the vocabulary `ItemClosure` exports.

        `closure.ItemClosure.to_json` writes `(file, class, method, kind,
        pattern)` for every bound step and a release reader joins on those
        names whichever stack produced them.  `pattern` is None here and that
        is a fact about cucumber's json plugin rather than a gap: it reports
        WHICH method matched and never the expression it matched with.  `kind`
        carries the Gherkin keyword as written, which is decoration for
        cucumber (see the module header) but is what the field means.
        """
        if step.location is None:
            return None
        fqcn, method, params = split_location(step.location, where)
        return {"file": self.file_of(fqcn), "class": fqcn, "method": method,
                "kind": step.keyword.strip(), "pattern": None,
                "params": params, "location": step.location}

    def _cases(self, rel: str, feature: Feature, scenario: Block,
               selected_lines: Optional[frozenset] = None) -> list:
        """`(example_line, example_row, case)` for the item's pickles.

        A plain scenario is one pickle at its own line.  An outline is one per
        Examples data row, at the row's line — which is what cucumber writes
        and what `examples_rows` reads out of the Gherkin, so the two are
        joined on the row line rather than on position.  The rows must be read
        under cucumber-JVM's own cell split for that join to hold on a row
        carrying trailing prose after its final `|`.

        `selected_lines` SCOPES the item to the pickles a reviewed census
        admitted.  An `Examples:` block carries its own tags, so a suite's tag
        filter can take some of an outline's blocks and leave others: for
        `unit/responses.feature:4` it takes 17 blocks (156 rows) of 22 (167).
        The 11 rows it never takes are not in the dry run at all, so the
        unscoped walk cannot even be performed over them -- `dry_run.case`
        refuses each one -- and a closure claiming them would demand gold glue
        for rows the suite never executes.  The item IS its selected subset,
        so that is what the closure is derived over.  `None` keeps the whole
        scenario, which is what the source-only walker (`extract_closures`)
        wants: it has no census in hand.

        `example_row` stays the row's index in the WHOLE outline, so scoping
        never renumbers a row that was admitted.
        """
        if not scenario.kind.startswith(("Scenario Outline",
                                         "Scenario Template")):
            if selected_lines is not None \
                    and set(selected_lines) != {scenario.line}:
                raise ClosureJavaError(
                    f"{rel}:{scenario.line}: a plain scenario is one pickle "
                    f"at its own line, but the census scopes it to "
                    f"{sorted(selected_lines)}")
            return [(None, None, self.dry_run.case(rel, scenario.line))]
        rows = list(enumerate(examples_rows(feature, scenario,
                                            dialect=CUCUMBER_DIALECT)))
        if selected_lines is None:
            return [(line, idx, self.dry_run.case(rel, line))
                    for idx, (line, _row) in rows]
        unknown = set(selected_lines) - {line for _idx, (line, _row) in rows}
        if unknown:
            raise ClosureJavaError(
                f"{rel}:{scenario.line}: the census scopes this outline to "
                f"{sorted(unknown)}, which are not Examples rows of it")
        chosen = [(line, idx) for idx, (line, _row) in rows
                  if line in selected_lines]
        if not chosen:
            raise ClosureJavaError(
                f"{rel}:{scenario.line}: the census scopes this outline to "
                f"none of its Examples rows")
        return [(line, idx, self.dry_run.case(rel, line))
                for line, idx in chosen]

    def bind_steps(self, rel: str, feature: Feature, scenario: Block,
                   selected_lines: Optional[frozenset] = None) -> list:
        out: list = []
        for example_line, example_row, case in self._cases(rel, feature,
                                                           scenario,
                                                           selected_lines):
            for origin, step in case.all_steps:
                where = f"{rel}:{case.line} {step.keyword}{step.name}"
                definition = self._definition(step, where)
                side = (None if definition is None
                        else self.boundary.classify(definition["file"] or ""))
                out.append(JavaStepBinding(
                    text=step.name, origin=origin,
                    keyword=step.keyword.strip(), definition=definition,
                    side=side, example_line=example_line,
                    example_row=example_row, source_line=step.line,
                    location=step.location, status=step.status))
        return out

    # ------------------------------------------------------------- driver
    def closure_for(self, item_id: str, feature: Feature, scenario: Block,
                    selected_lines: Optional[frozenset] = None) \
            -> JavaItemClosure:
        """This item's closure; `selected_lines` scopes it (see `_cases`)."""
        rel = os.path.relpath(os.path.abspath(feature.path),
                              self.repo_root).replace(os.sep, "/")
        steps = self.bind_steps(rel, feature, scenario, selected_lines)
        cl = JavaItemClosure(
            item_id=item_id, feature_file=rel, scenario_line=scenario.line,
            steps=steps,
            source_steps=len(scenario.steps) + (
                len(feature.background.steps)
                if feature.background is not None else 0),
            example_lines=sorted({s.example_line for s in steps
                                  if s.example_line is not None}))

        removable: set = set()
        retained: set = set()
        production: set = set()
        for s in steps:
            if s.definition is None:
                continue
            if s.side == REMOVABLE:
                removable.add(s.definition["class"])
                # Both edge shapes, and the whole-class one is NOT transitive
                # here: each table value is already the converged fixpoint
                # (see `ALGORAND_COMPANION_CLASSES`), so one lookup per bound
                # class is the whole expansion and there is no walk to get
                # wrong.  `selftest` pins the closedness that makes that true.
                removable.update(self.companion_classes.get(
                    (s.definition["class"], s.definition["method"]), ()))
                removable.update(self.companion_classes.get(
                    s.definition["class"], ()))
            elif s.side == RETAINED:
                retained.add(s.definition["class"])
            else:
                production.add(s.definition["class"])

        cl.classes = sorted(removable)
        cl.files = sorted({self.file_of(c) for c in removable})
        cl.retained_files = sorted({self.file_of(c) for c in retained})
        cl.production_deps = sorted(production)
        # Every removable class in this closure must be scanned: registry
        # seeds and the one explicit parameter-type companion alike.
        cl.context_classes = sorted(removable)
        cl.locations = sorted({s.location for s in steps
                               if s.location is not None})
        cl.di_fragment = {}

        seen: set = set()
        for s in steps:
            # An ambiguous step is unbound and is NOT unmatched: cucumber
            # found two definitions and named neither, so this closure is
            # missing two glue files rather than zero, and the two defects
            # need different repairs.  Named apart for that reason; both are
            # problems and neither is silent.
            kind = "ambiguous_step" if s.status == AMBIGUOUS else \
                "unmatched_step"
            if s.definition is None and (kind, s.text) not in seen:
                seen.add((kind, s.text))
                cl.problems.append(f"{kind}: {s.keyword} {s.text}")
            if s.status is not None and s.status not in DRY_RUN_STATUSES:
                note = f"status_outside_dry_run_vocabulary: {s.status} {s.text}"
                if note not in cl.problems:
                    cl.problems.append(note)
        for path, verdict in containment_violations(cl.files, self.boundary):
            cl.problems.append(f"closure_file_not_removable: {verdict} {path}")
        return cl


# -------------------------------------------------------------- loading/CLI

def load_kapua_dry_runs(artifacts: str, *, stripped: bool = False) -> DryRun:
    """Resolve each native registry document using its measured module root.

    Raw JSON stays untouched. A runner's feature set must match its declaration;
    missing captures or a misplaced/colliding report cannot shrink the census.
    """
    from .kapua import SUITES, capture_path

    cases = []
    for suite in SUITES:
        path = capture_path(artifacts, suite, stripped=stripped)
        capture = load_dry_run(path, suite.module + "/src/test/resources",
                               project="kapua")
        if set(capture.uris()) != set(suite.features):
            raise ClosureJavaError(
                f"{path}: native feature set differs from its Kapua runner; "
                f"missing={sorted(set(suite.features) - set(capture.uris()))} "
                f"extra={sorted(set(capture.uris()) - set(suite.features))}")
        cases.extend(capture.cases.values())
    return DryRun(cases)


def load_extractor(dry_run_path: str, boundary_path: str, feature_root: str,
                   repo_root: Optional[str] = None) -> JavaClosureExtractor:
    """Build the cucumber extractor from captured registry answers."""
    from ..core.boundary import load_boundary

    boundary = load_boundary(boundary_path, repo_root=repo_root)
    source_roots = test_source_roots(boundary.project)
    type_index = build_type_index(boundary.repo_root, source_roots)
    if not type_index:
        raise ClosureJavaError(
            f"{boundary.repo_root}: no Java sources under {source_roots!r}")
    # The leg kind is not in hand here: this is the CLI over one captured
    # file, with no preparation to say whether it was stripped.  Plain
    # uniformity is what applies, per `parse_dry_run`'s `expect_state`.
    capture = (load_kapua_dry_runs(os.path.dirname(dry_run_path))
               if boundary.project == "kapua" else
               load_dry_run(dry_run_path, feature_root, project=boundary.project))
    return JavaClosureExtractor(
        capture, boundary, type_index,
        COMPANION_CLASSES_BY_PROJECT.get(boundary.project))


def extract_closures(extractor: JavaClosureExtractor, feature_root: str,
                     project: str) -> list[JavaItemClosure]:
    """Every feature item, in the shared walker's deterministic order."""
    from ..toolkit.pystep_index import walk_features

    item_path = None
    if project == "algorand-sdk":
        from .algorand import admit_before_contact, workspace_to_source_feature
        item_path = workspace_to_source_feature
    if project == "kapua":
        from .kapua import feature_items
        walked = feature_items(extractor.repo_root)
    else:
        walked = list(walk_features(
            extractor.repo_root, feature_root, project, item_path=item_path))
    if project == "algorand-sdk":
        # Authenticate and subtract the 51 live-algod criteria before the
        # extractor is called.  ``closure_for`` is the first downstream actor
        # on this source-only path; a post-hoc filter would already have let
        # those criteria reach it.
        walked, _policy = admit_before_contact(
            walked, item_id=lambda entry: entry[0])
    closures = [extractor.closure_for(item_id, feature, scenario)
                for item_id, feature, scenario in walked]
    if not closures:
        raise ClosureJavaError(
            f"{extractor.repo_root}/{feature_root}: no feature items")
    return closures


def cmd_closures(args) -> int:
    """`r2t closures --profile …`, from captured cucumber JSON only."""
    import statistics

    from ..core.boundary import load_boundary

    boundary = load_boundary(args.boundary,
                             repo_root=getattr(args, "repo", None))
    supplied = getattr(args, "features", None) or "src/test/resources"
    features = os.path.normpath(supplied).replace(os.sep, "/").rstrip("/")
    if boundary.project == "kapua":
        # Suite.module owns all 37 paths; no single --features root can bind them.
        features = "."
    elif os.path.isabs(supplied) or features in ("", ".", "..") \
            or features.startswith("../") \
            or not os.path.isdir(os.path.join(boundary.repo_root, features)):
        raise SystemExit(
            f"REFUSED: `--features {supplied}` names no repo-relative "
            f"feature directory under {boundary.repo_root}; for EPUBCheck "
            "pass `--features src/test/resources`.")

    extractor = load_extractor(
        os.path.join(args.artifacts, DRY_RUN_ARTIFACT), args.boundary,
        features, repo_root=boundary.repo_root)
    closures = extract_closures(extractor, features, boundary.project)
    documents = [closure.to_json() for closure in closures]
    closures_path = os.path.join(args.artifacts, CLOSURES_ARTIFACT)
    with open(closures_path, "w", encoding="utf-8") as fh:
        json.dump(documents, fh, indent=1, sort_keys=True)

    census = removable_census(
        closures, boundary, extractor.type_index)
    census_path = os.path.join(args.artifacts, CENSUS_ARTIFACT)
    with open(census_path, "w", encoding="utf-8") as fh:
        json.dump(census, fh, indent=1, sort_keys=True)

    sizes = [len(document["files"]) for document in documents]
    print(f"{len(documents)} items -> {closures_path}")
    print(f"  closure files: min {min(sizes)} median "
          f"{statistics.median(sizes):.0f} max {max(sizes)}")
    print("  unmatched steps: " + str(sum(
        document["counts"]["steps_unmatched"] for document in documents)))
    print("  answered entirely by retained code: " + str(sum(
        1 for document in documents
        if document["answered_entirely_by_retained"])))
    print("  items with extractor problems: " + str(sum(
        1 for document in documents if document["problems"])))
    print("  outlines: " + str(sum(
        1 for document in documents if document["counts"]["example_rows"]))
        + " (" + str(sum(document["counts"]["example_rows"]
                         for document in documents)) + " Examples rows)")
    print(f"  removable census: {len(census['reached'])} reached, "
          f"{len(census['unreached'])} unreached -> {census_path}")
    return 0


# ----------------------------------------------------------- containment
def containment_violations(files, boundary: Boundary) -> list:
    """`(path, verdict)` for every closure file the boundary does NOT remove.

    Pure over `(closure files, boundary)`: no filesystem, no dry run, no
    extractor state, so it can be asked of a closure that was loaded from
    `closures.json` rather than computed.  A closure must be a subset of the
    removable tree because that is what a strip removes and a solution may
    write: a gold file outside it is either a retained substrate the candidate
    never has to produce (an item that cannot fail) or production code the
    harness would refuse to touch (an item that cannot pass).

    A `None` path is a class the type index did not know — production or
    vendor — and is reported as such rather than skipped.
    """
    out: list = []
    for path in sorted(files, key=lambda p: (p is None, p or "")):
        if path is None:
            out.append((None, PRODUCTION))
            continue
        verdict = boundary.classify(path)
        if verdict != REMOVABLE:
            out.append((path, verdict))
    return out


def is_contained(files, boundary: Boundary) -> bool:
    """Is this closure a subset of the removable tree?"""
    return not containment_violations(files, boundary)


# ---------------------------------------------------------------- census
def removable_files(boundary: Boundary, type_index: dict) -> list:
    """Every indexed `.java` the boundary calls removable, in path order."""
    return sorted({rel for rel in type_index.values()
                   if boundary.classify(rel) == REMOVABLE})


def removable_census(closures, boundary: Boundary, type_index: dict) -> dict:
    """Which removable glue the registry's answers reached, and which not.

    A removable file NO item's closure names is either dead glue or another
    edge cucumber cannot report.  The reviewed `{multimap}` companion is
    already included in the closures that consume it; anything else remains
    enumerated rather than counted, because only a name permits an owner
    decision about whether the file is dead or another explicit companion.
    """
    universe = removable_files(boundary, type_index)
    reached: set = set()
    for closure in closures:
        reached.update(f for f in closure.files if f is not None)
    return {"removable": universe,
            "reached": sorted(reached & set(universe)),
            "unreached": sorted(set(universe) - reached),
            "reached_outside_removable": sorted(reached - set(universe))}


def dry_run_problems(dry_run: DryRun) -> list:
    """Everything about this dry run a gate has to be told about.

    Three kinds, and the last two are why this is not just a vocabulary
    check.  A step status OUTSIDE `DRY_RUN_STATUSES` is a run that did
    something a dry run cannot do — `failed` means a hook threw, most likely.
    An `ambiguous` status is INSIDE the vocabulary (a dry run builds every
    match, and two matches is one of the answers building can give) and is a
    defect all the same: cucumber names neither definition, so every closure
    over that step silently loses both glue files.  Reporting only the first
    kind is how a seed-only closure under-approximates and still passes D2b's
    "non-empty closure, contained in removable" criteria.

    The third kind is a non-passed BEFORE-HOOK, and it is here to keep
    `_validate_skip_order` honest rather than to describe the steps.  That
    rule refuses a `skipped` step whose predecessors all passed — which is
    what defeats the disguise a corrupted artifact would use — and the one
    document shape it must let through is a pickle whose `@Before` did not
    pass, because SKIP then reaches the first step legitimately.  Left
    silent, that exemption would BE the disguise: seven added bytes of
    `"before"` would excuse a wholly `skipped` pickle and `unstripped_
    bindings` would call it a clean strip.  Reported, it says out loud that
    these steps are skipped for a reason that is not a strip.  In a real dry
    run it never fires: `ExecutionMode.DRY_RUN.execute` calls
    `dryRunStep` and returns PASSED, and `HookDefinitionMatch.dryRunStep`
    does nothing, so hooks in a dry run always pass.

    Enumerated, not refused: the FORMAT is what `parse_dry_run` refuses on,
    and a finding about the RUN has to reach a gate rather than be rejected
    as unparseable.
    """
    out: list = []
    for (uri, line), case in sorted(dry_run.cases.items()):
        for h_index, status in enumerate(case.before_hooks):
            if status != PASSED:
                out.append(f"{uri}:{line}: {status} before-hook [{h_index}] "
                           f"(it put this pickle into ExecutionMode.SKIP, so "
                           f"the steps below it are skipped for a reason "
                           f"that is not a strip)")
        for _origin, step in case.all_steps:
            if step.status not in DRY_RUN_STATUSES:
                out.append(f"{uri}:{line}: {step.status} "
                           f"{step.keyword}{step.name}")
            elif step.ambiguous:
                out.append(f"{uri}:{line}: ambiguous (two definitions, "
                           f"cucumber names neither) "
                           f"{step.keyword}{step.name}")
    return out


def unstripped_bindings(dry_run: DryRun, boundary: Boundary,
                        type_index: dict) -> list:
    """Steps a STRIPPED tree's dry run still binds to removable code.

    The precise form of "a stripped-tree dry run is all undefined", which for
    this corpus is not literally true and must not be written as if it were:
    `boundary_epubcheck.yml` retains `EPUBCheckConfiguration` and
    `TestEnvironment`, and their nine annotated methods keep answering steps
    after a strip.  The question a gate can actually ask is this one — no step
    of any pickle is answered by a REMOVABLE file — and the retained
    substrate answering its own steps is the disclosed leak, not a failure.
    """
    out: list = []
    for (uri, line), case in sorted(dry_run.cases.items()):
        for _origin, step in case.all_steps:
            if step.location is None:
                continue
            fqcn, _method, _params = split_location(
                step.location, f"{uri}:{line}")
            rel = type_index.get(top_level_class(fqcn))
            if rel is not None and boundary.classify(rel) == REMOVABLE:
                out.append(f"{uri}:{line}: {step.keyword}{step.name} -> "
                           f"{step.location} ({rel})")
    return out


# ------------------------------------------------------- the ART witnesses
#: ART read the SAME registry this module reads, by a different route: it ran
#: cucumber once per scenario and parsed the `pretty` plugin's `# <signature>`
#: comment lines, where this reads the `json` plugin's `match.location`.  That
#: makes its map a WITNESS rather than a second copy of our own answer, which
#: is the only kind of cross-check worth having.  Both files are pinned under
#: `fixtures/` with their provenance; see `fixtures/PROVENANCE.md`.
GT_SCHEMA = "r2t.java-art-step-definition-map/1"
ART_API_INDEX_SCHEMA = "r2t.java-art-api-index/1"

_WITNESS_PROVENANCE = {"kind", "source", "retrieved", "produced_by",
                       "transformation"}


def _witness(doc: Any, schema: str, payload: str, where: str) -> dict:
    """A pinned witness: right schema, provenance present, payload present."""
    wrapper = _object(doc, {"schema", "provenance", payload}, set(), where)
    if wrapper["schema"] != schema:
        raise ClosureJavaError(
            f"{where}.schema: {wrapper['schema']!r} is not {schema!r}")
    provenance = wrapper["provenance"]
    if not isinstance(provenance, dict):
        raise ClosureJavaError(f"{where}.provenance: expected object")
    missing = _WITNESS_PROVENANCE - set(provenance)
    if missing:
        raise ClosureJavaError(
            f"{where}.provenance: a witness with no {sorted(missing)!r} is a "
            f"number somebody typed")
    return wrapper


@dataclass(frozen=True)
class GtScenario:
    """One scenario as ART's map recorded it."""
    uri: str
    line: int
    title: str
    step_definitions: tuple       # tuple[(keyworded step text, signature)]

    @property
    def pairs(self) -> frozenset:
        """`(fqcn, method)` for every step definition the witness names."""
        out = set()
        for text, signature in self.step_definitions:
            fqcn, method, _params = split_location(
                signature, f"{self.uri}:{self.line} {text}")
            out.add((fqcn, method))
        return frozenset(out)


def load_gt_map(path: str) -> dict:
    """ART's map, keyed by `(uri, line)` — the key an item id is built on."""
    with open(path, encoding="utf-8") as fh:
        doc = _witness(json.load(fh), GT_SCHEMA, "scenarios", "gt-map")
    out: dict = {}
    for index, raw in enumerate(_array(doc["scenarios"], "gt-map.scenarios")):
        where = f"gt-map.scenarios[{index}]"
        entry = _object(raw, {"uri", "line", "title", "step_definitions"},
                        set(), where)
        defs: list = []
        for i, pair in enumerate(
                _array(entry["step_definitions"],
                       f"{where}.step_definitions")):
            pwhere = f"{where}.step_definitions[{i}]"
            if not isinstance(pair, list) or len(pair) != 2:
                raise ClosureJavaError(
                    f"{pwhere}: expected a (step text, signature) pair")
            defs.append((_string(pair[0], f"{pwhere}[0]"),
                         _string(pair[1], f"{pwhere}[1]")))
        scenario = GtScenario(uri=_string(entry["uri"], f"{where}.uri"),
                              line=_line(entry["line"], f"{where}.line"),
                              title=_string(entry["title"], f"{where}.title"),
                              step_definitions=tuple(defs))
        key = (scenario.uri, scenario.line)
        if key in out:
            raise ClosureJavaError(f"{where}: two scenarios at {key}")
        out[key] = scenario
    return out


@dataclass
class GtAgreement:
    """What a witness and this extractor agree and disagree about.

    Reported in three separate numbers because they answer three different
    questions and adding them would hide the one that matters.  `covered` is
    how many of OUR items the witness saw at all — ART's epubcheck map covers
    948 of the checkout's 1041 scenarios, and an agreement rate over the
    intersection is not a statement about the other 93.  `uncovered` is where
    they go, and it is the only place the SECOND half of that gap shows up:
    41 of the 93 are scenarios inside the 44 feature files the map did run
    (`fixtures/PROVENANCE.md` enumerates them), so a reader who takes
    "44 files" for "44 whole files" is over-reading the denominator by 41
    items.  `agreed`/`covered` is the
    item-level rate a gate can put a threshold on.  `pairs_agreed`/
    `pairs_total` is the micro-average over step definitions, which moves when
    one step of one item disagrees and the item rate does not.
    """
    covered: list = field(default_factory=list)
    uncovered: list = field(default_factory=list)
    witness_only: list = field(default_factory=list)
    agreed: list = field(default_factory=list)
    disagreements: list = field(default_factory=list)
    pairs_agreed: int = 0
    pairs_total: int = 0

    @property
    def item_agreement(self) -> float:
        return len(self.agreed) / len(self.covered) if self.covered else 0.0

    @property
    def pair_agreement(self) -> float:
        return self.pairs_agreed / self.pairs_total if self.pairs_total else 0.0

    def summary(self) -> list:
        return [
            f"items compared: {len(self.covered)} "
            f"(witness does not cover {len(self.uncovered)}; "
            f"witness has {len(self.witness_only)} we did not ask about)",
            f"item agreement: {len(self.agreed)}/{len(self.covered)} "
            f"= {self.item_agreement:.4f}",
            f"step-definition agreement: {self.pairs_agreed}/"
            f"{self.pairs_total} = {self.pair_agreement:.4f}",
        ] + list(self.disagreements)


def compare_to_gt(closures, gt: dict) -> GtAgreement:
    """Closure-vs-witness, with every disagreement named.

    The unit is the SET of `(class, method)` pairs an item's steps resolved
    to.  Not the ordered list: an outline's closure is the union over its
    Examples rows while a witness may have recorded one row, and a set is the
    only unit both sides can be asked in.  Not the file set either: a witness
    that names a method in a class we agree about is agreeing at a finer grain
    than the file, and coarsening it would hide a real difference.

    Disagreements are ENUMERATED — one line per item, naming what each side
    has that the other does not.  A rate with no list behind it is a number a
    gate can pass while the closure is wrong about the same class every time.
    """
    report = GtAgreement()
    seen: set = set()
    for closure in closures:
        key = (closure.feature_file, closure.scenario_line)
        witness = gt.get(key)
        if witness is None:
            report.uncovered.append(closure.item_id)
            continue
        seen.add(key)
        report.covered.append(closure.item_id)
        ours = frozenset(
            (s.definition["class"], s.definition["method"])
            for s in closure.steps if s.definition is not None)
        theirs = witness.pairs
        report.pairs_agreed += len(ours & theirs)
        report.pairs_total += len(ours | theirs)
        if ours == theirs:
            report.agreed.append(closure.item_id)
            continue
        report.disagreements.append(
            f"{closure.item_id}: ours_only="
            f"{sorted('.'.join(p) for p in ours - theirs)!r} "
            f"witness_only={sorted('.'.join(p) for p in theirs - ours)!r}")
    report.witness_only = sorted(f"{uri}:{line}" for uri, line in gt
                                 if (uri, line) not in seen)
    return report


# -------------------------------------------------- the production API index
#
# ART's `collect_project_api_index.py` builds `method name -> [fully qualified
# class]` over a project's own source, so that an API call in test code can be
# attributed to the class that declares it.  This is that program, adapted,
# with the deviations a twin is required to declare:
#
# 1. **No tree-sitter.**  ART's parser is `utils/java_code_parser.py`, which
#    needs `tree_sitter` plus a compiled grammar; the pinned dependency set
#    here is PyYAML and jsonschema, and vendoring a parser to match a witness
#    is not a trade this benchmark makes.  `java_declarations` is a lexer
#    instead: comments and string/char literals are blanked, the result is
#    tokenised, and a declaration is `IDENT (` whose predecessor is a type
#    (an identifier, a primitive, `>` or `]`) or -- for a constructor -- a
#    modifier, and whose parameter list is followed by `{`, `;` or `throws`.
#    The two constructs that make that under- or over-count are handled by
#    name: a primitive return type (`boolean canDecrypt(URL)`, whose
#    predecessor is a KEYWORD) and an explicitly-typed generic invocation
#    (`Optional.<OPFItem> absent()`, whose predecessor is a `>` that closes a
#    `<` preceded by a dot).  Verified against ART's own output over the 197
#    files of epubcheck `src/main/java` at the pinned `82b174ec`: restricting
#    to declarations WITH a body reproduces ART's 923 entries exactly, and the
#    37 extra `(name, class)` pairs the full scan finds are all body-less --
#    interface and abstract methods, which ART's `body: (block)` query
#    structurally cannot see and which are production API all the same.  That
#    is why `java_declarations` reports `has_body`: a gate can reproduce the
#    witness byte for byte, and this index does not have to be wrong to do it.
#
# 2. **The test-class leak, fixed.**  ART indexes every `.java` under
#    `project_source_dir`, and its Python branch skips `tests/` while its Java
#    branch skips nothing.  epubcheck ships `com/adobe/epubcheck/util/
#    DateParserTest.java` INSIDE `src/main/java`, so ART's pinned index
#    attributes `main` and `testisISO8601Date` to
#    `com.adobe.epubcheck.util.DateParserTest` -- a test class in the
#    production API index, which inflates the denominator and lets a call to
#    `main` resolve to a test.  Two rules exclude it, and both are recorded
#    rather than silently applied: the boundary's own verdict (anything it
#    does not call PRODUCTION is test code by this benchmark's contract) and
#    Maven Surefire's DEFAULT INCLUDES, which is the build's own definition of
#    what it runs as a test.  A name rule is needed because `DateParserTest`
#    imports no test framework at all -- it is a `main`-method test -- so
#    there is no import to key on.
#
# 3. **The FQCN comes from the `package` declaration**, cross-checked against
#    the path, where ART derives it from the path alone.  Same answer for all
#    228 files of this checkout; a disagreement is a refusal rather than a
#    class filed under a name javac would not resolve.

#: `maven-surefire-plugin`'s default `includes`, which is what the BUILD calls
#: a test class.  Not a taste: a class matching one of these is compiled and
#: run by `mvn test`, so calling its methods production API contradicts the
#: build.
SUREFIRE_TEST_INCLUDES = ("Test*", "*Test", "*Tests", "*TestCase")

JAVA_KEYWORDS = frozenset("""
abstract assert boolean break byte case catch char class const continue
default do double else enum extends final finally float for goto if
implements import instanceof int interface long native new package private
protected public return short static strictfp super switch synchronized this
throw throws transient try void volatile while
""".split())

#: A primitive (and `void`) is a keyword AND a legal return type, so it has to
#: be readmitted where a type is expected.  Leaving it out cost every
#: `boolean canDecrypt(URL url)` in the corpus.
JAVA_PRIMITIVES = frozenset(
    "boolean byte char double float int long short void".split())

#: A modifier directly before `Name(` means there is no return type between
#: them, and a method always has one — so this is a constructor.
JAVA_MODIFIERS = frozenset("""
public protected private static final abstract synchronized native strictfp
default
""".split())

_TOKEN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*|[^\sA-Za-z0-9_$]")
_TYPE_KEYWORDS = ("class", "interface", "enum", "record")


def _is_identifier(token: str) -> bool:
    return bool(token) and (token[0].isalpha() or token[0] in "_$")


def strip_comments_and_literals(text: str, where: str) -> str:
    """Java source with comments and literal CONTENTS replaced by spaces.

    Newline-preserving, so a line in the result is a line in the source.  The
    quotes and comment delimiters survive; what is inside them does not, which
    is what stops an annotation's step expression (`@Then("the parsed viewport
    equals {multimap}")`) from contributing tokens.

    Java 15 text blocks are REFUSED rather than mis-parsed: `\"\"\"` opens a
    literal this reader does not understand, and treating it as two empty
    strings would silently swallow the rest of the file.
    """
    if '"""' in text:
        raise ClosureJavaError(
            f'{where}: contains a `\"\"\"` text block, which this reader does '
            f"not parse")
    out: list = []
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char == "/" and text[i:i + 2] == "//":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif char == "/" and text[i:i + 2] == "/*":
            out.append("  ")
            i += 2
            while i < n and text[i:i + 2] != "*/":
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
        elif char in '"\'':
            out.append(char)
            i += 1
            while i < n and text[i] != char:
                out.append(" ")
                if text[i] == "\\":
                    i += 1
                    if i < n:
                        out.append(" ")
                i += 1
            out.append(char)
            i += 1
        else:
            out.append(char)
            i += 1
    return "".join(out)


def java_tokens(text: str, where: str) -> list:
    return _TOKEN.findall(strip_comments_and_literals(text, where))


def java_package(text: str, where: str) -> str:
    """The `package` declaration, which every file in this corpus has first."""
    tokens = java_tokens(text, where)
    if not tokens or tokens[0] != "package":
        raise ClosureJavaError(
            f"{where}: no `package` declaration; a class in the default "
            f"package has no fully qualified name to index it under")
    parts: list = []
    index = 1
    while index < len(tokens) and tokens[index] != ";":
        if tokens[index] != ".":
            parts.append(tokens[index])
        index += 1
    return ".".join(parts)


def java_declarations(text: str, where: str) -> set:
    """`(name, kind, has_body)` for every method and constructor declared.

    `kind` is `"method"` or `"constructor"`; `has_body` is False for an
    interface or abstract declaration, which is what lets a caller reproduce
    ART's body-requiring tree-sitter query exactly (see the section header).
    """
    tokens = java_tokens(text, where)
    types: set = set()
    for index, token in enumerate(tokens):
        if token in _TYPE_KEYWORDS and index + 1 < len(tokens):
            name = tokens[index + 1]
            if _is_identifier(name) and name not in JAVA_KEYWORDS:
                types.add(name)
    out: set = set()
    for index, token in enumerate(tokens):
        if index == 0 or index + 1 >= len(tokens) or tokens[index + 1] != "(":
            continue
        if token in JAVA_KEYWORDS or not _is_identifier(token):
            continue
        close = _matching(tokens, index + 1, "(", ")")
        if close < 0:
            continue
        after = tokens[close + 1] if close + 1 < len(tokens) else None
        if after not in ("{", ";", "throws"):
            continue
        has_body = after == "{"
        if after == "throws":
            cursor = close + 2
            while cursor < len(tokens) and tokens[cursor] not in ("{", ";"):
                cursor += 1
            has_body = cursor < len(tokens) and tokens[cursor] == "{"
        previous = tokens[index - 1]
        if previous in _TYPE_KEYWORDS:
            # `record Point(int x, int y) {}` — a type header, not a method.
            # `record` is a CONTEXTUAL keyword, so it reaches the identifier
            # branch below and would be read as a return type.  This corpus is
            # Java 8 and has none; the guard is here so that a Java 16 one is
            # not silently counted as an API.
            continue
        if previous == ">":
            open_at = _matching(tokens, index - 1, ">", "<", step=-1)
            if open_at <= 0 or tokens[open_at - 1] == ".":
                # `Optional.<OPFItem> absent()` — an invocation carrying an
                # explicit type argument, not a declaration with a generic
                # return type.  The dot before the `<` is the whole
                # difference, and without this the corpus gains two APIs that
                # are only ever called.
                continue
            out.add((token, "method", has_body))
        elif previous == "]" or previous in JAVA_PRIMITIVES or (
                previous not in JAVA_KEYWORDS and _is_identifier(previous)):
            out.add((token, "method", has_body))
        elif previous in JAVA_MODIFIERS or previous in ("{", "}", ";", ")"):
            if token in types:
                out.add((token, "constructor", has_body))
    return out


def _matching(tokens: list, start: int, opener: str, closer: str,
              step: int = 1) -> int:
    depth = 0
    index = start
    while 0 <= index < len(tokens):
        if tokens[index] == opener:
            depth += 1
        elif tokens[index] == closer:
            depth -= 1
            if depth == 0:
                return index
        index += step
    return -1


def is_surefire_test_class(simple_name: str) -> bool:
    """Would `mvn test` run this class as a test, by Surefire's defaults?"""
    return (simple_name.startswith("Test")
            or simple_name.endswith(("Test", "Tests", "TestCase")))


def build_api_index(repo_root: str, source_roots, boundary: Boundary) -> dict:
    """`method name -> [fully qualified class]` over PRODUCTION source only.

    The exclusions are recorded, not silently applied: `excluded` names every
    file that was skipped and why, so a corpus where the rule removes more
    than one file is a visible fact rather than a smaller number.
    """
    index: dict = {}
    excluded: list = []
    for root in source_roots:
        base = os.path.join(repo_root, root)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(dirnames)
            for name in sorted(filenames):
                if not name.endswith(".java"):
                    continue
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, repo_root).replace(os.sep, "/")
                simple = name[:-len(".java")]
                verdict = boundary.classify(rel)
                if verdict != PRODUCTION:
                    excluded.append([rel, f"boundary:{verdict}"])
                    continue
                if is_surefire_test_class(simple):
                    excluded.append([rel, "surefire_default_includes"])
                    continue
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                package = java_package(text, rel)
                from_path = os.path.dirname(
                    rel[len(root):].strip("/")).replace("/", ".")
                if package != from_path:
                    raise ClosureJavaError(
                        f"{rel}: package {package!r} does not match its "
                        f"directory {from_path!r}; javac would not find it "
                        f"on the source path")
                fqcn = f"{package}.{simple}" if package else simple
                for decl, _kind, _has_body in java_declarations(text, rel):
                    index.setdefault(decl, set()).add(fqcn)
    return {"schema": "r2t.java-api-index/1",
            "project": boundary.project,
            "source_roots": list(source_roots),
            "total_apis": len(index),
            "api_index": {k: sorted(v) for k, v in sorted(index.items())},
            "excluded": sorted(excluded)}


def load_art_api_index(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        doc = _witness(json.load(fh), ART_API_INDEX_SCHEMA, "api_index",
                       "art-api-index")
    return doc["api_index"]


def drop_test_classes(api_index: dict) -> tuple:
    """`(index without test classes, the entries dropped)`.

    The leak fix applied to an index that already exists — ART's, which is
    pinned under `fixtures/` precisely so this can be shown on the bytes that
    carried the defect rather than on an imitation of them.  A name left with
    no class at all is dropped with its last class, because a method name
    mapping to nothing is not an API.
    """
    clean: dict = {}
    dropped: list = []
    for name, classes in api_index.items():
        kept = []
        for fqcn in classes:
            if is_surefire_test_class(fqcn.rsplit(".", 1)[-1]):
                dropped.append([name, fqcn])
            else:
                kept.append(fqcn)
        if kept:
            clean[name] = kept
    return clean, sorted(dropped)


# --------------------------------------------------------------- fixtures
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refused(callable_: Callable) -> bool:
        try:
            callable_()
        except ClosureJavaError:
            return True
        return False

    from ..core.boundary import load_boundary
    from ..toolkit.closure_py import GOLD_SIDECAR_FIELDS
    from ..core.gherkin import parse_feature_file

    here = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    fixtures = fixtures_dir()
    feature_root = "src/test/resources"
    java_root = "src/test/java"

    # -- every fixture says where it came from -----------------------------
    with open(os.path.join(fixtures, "PROVENANCE.md"), encoding="utf-8") as fh:
        provenance = fh.read()
    present = sorted(n for n in os.listdir(fixtures) if n != "PROVENANCE.md")
    check("every file in fixtures/ has a PROVENANCE.md entry, so a witness "
          "cannot be added without saying where it came from",
          all(f"## `{name}`" in provenance for name in present),
          str([n for n in present if f"## `{n}`" not in provenance]))

    # Native Kapua captures: the dry contract invokes matching, and the strip
    # preserves retained setup while exposing missing answer steps.
    kapua_root = "service/account/test/src/test/resources"
    kapua_captures = {}
    for kind in ("ordinary", "dry", "stripped_dry"):
        path = os.path.join(fixtures, f"cucumber_6_11_kapua_{kind}.json")
        kapua_captures[kind] = load_dry_run(
            path, kapua_root, project="kapua", dry_run=kind != "ordinary")
    from collections import Counter
    outcomes = {kind: Counter(step.status for case in capture.cases.values()
                              for _, step in case.all_steps)
                for kind, capture in kapua_captures.items()}
    check("native Kapua ordinary/dry captures bind all three excerpt steps",
          outcomes["ordinary"] == outcomes["dry"] == {"passed": 3}
          and all(len(capture.cases) == 2 for capture in kapua_captures.values()))
    check("native Kapua strip preserves setup, then undefined/skipped order",
          outcomes["stripped_dry"] == {"passed": 1, "undefined": 1, "skipped": 1}
          and all(not dry_run_problems(capture)
                  for capture in kapua_captures.values()))
    with open(os.path.join(fixtures, "cucumber_6_11_kapua_dry.json"),
              encoding="utf-8") as fh:
        forged_kapua = json.load(fh)
    step = forged_kapua[0]["elements"][1]["steps"][0]
    step["result"] = {"status": "skipped"}
    step["match"] = {}
    check("Kapua cannot hide a bound first step as locationless skipped",
          refused(lambda: parse_dry_run(forged_kapua, kapua_root, project="kapua")))

    # A native classpath URI alone carries no reactor module. Two captures
    # with the same URI must keep separate source identities after routing.
    import tempfile
    from unittest.mock import patch
    from dataclasses import replace
    from . import kapua
    with tempfile.TemporaryDirectory(prefix="kapua-closure-routing-") as temp:
        with open(os.path.join(fixtures, "cucumber_6_11_kapua_dry.json"),
                  encoding="utf-8") as fh:
            raw = fh.read()
        first = kapua.FEATURE_SUITES[kapua_root + "/features/AccountService.feature"]
        second = replace(first, module="service/other/test",
                         runner_package="org.example.other",
                         features=("service/other/test/src/test/resources/features/AccountService.feature",))
        for suite in (first, second):
            path = kapua.capture_path(temp, suite)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(raw)
        with patch.object(kapua, "SUITES", (first, second)):
            routed = load_kapua_dry_runs(temp)
            check("same native URI in two modules retains four distinct pickle identities",
                  len(routed.cases) == 4 and set(routed.uris()) ==
                  set(first.features + second.features))
            path = kapua.capture_path(temp, second)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(raw.replace("features/AccountService.feature", "features/Wrong.feature"))
            check("a misplaced native report cannot shrink or substitute the runner census",
                  refused(lambda: load_kapua_dry_runs(temp)))
        with patch.object(kapua, "SUITES", (first, first)):
            check("duplicate runner captures refuse rather than overwrite pickle identities",
                  refused(lambda: load_kapua_dry_runs(temp)))

    # -- the real boundary, and a type index over the real glue paths ------
    b = load_boundary(
        os.path.join(here, "config", "boundary_epubcheck.yml"),
        repo_root="/selftest/epubcheck")
    glue = {
        "org.w3c.epubcheck.test.ExecutionSteps": "test/ExecutionSteps.java",
        "org.w3c.epubcheck.test.AssertionSteps": "test/AssertionSteps.java",
        "org.w3c.epubcheck.test.CLISteps": "test/CLISteps.java",
        "org.w3c.epubcheck.test.EPUBCheckConfiguration":
            "test/EPUBCheckConfiguration.java",
        "org.w3c.epubcheck.test.TestEnvironment": "test/TestEnvironment.java",
        "org.w3c.epubcheck.test.ParameterTypes": "test/ParameterTypes.java",
        "org.w3c.epubcheck.SharedParameterTypes": "SharedParameterTypes.java",
        "org.w3c.epubcheck.util.microsyntax.ViewportSteps":
            "util/microsyntax/ViewportSteps.java",
        "org.w3c.epubcheck.url.URLFragmentSteps": "url/URLFragmentSteps.java",
        "org.w3c.epubcheck.url.URLUtilsTest": "url/URLUtilsTest.java",
    }
    type_index = {fqcn: f"{java_root}/org/w3c/epubcheck/{rel}"
                  for fqcn, rel in glue.items()}

    # -- the parser, against the checked-in dry run -------------------------
    run = load_dry_run(os.path.join(fixtures,
                                    "cucumber_dry_run_epubcheck.json"),
                       feature_root, project="epubcheck")
    loc = "src/test/resources/localization/localization.feature"
    view = "src/test/resources/epub3/F-viewport-meta-tag/viewport-syntax.feature"
    check("a `classpath:` uri resolves against the resource root, which is "
          "the scheme epubcheck's own @CucumberOptions produces",
          run.uris() == [view, loc], str(run.uris()))
    check("a pickle is keyed by (uri, line), and an outline contributes one "
          "per Examples DATA ROW",
          sorted(l for u, l in run.cases if u == view) == [14, 16],
          str(sorted(l for u, l in run.cases if u == view)))
    case = run.case(loc, 11)
    check("a background element is attached to the scenario element that "
          "follows it, and is not a pickle of its own",
          [s.line for s in case.background] == [6, 7]
          and [s.line for s in case.steps] == [12, 13]
          and (loc, 5) not in run.cases,
          str([s.line for s in case.background]))
    check("the registry's own answer is carried verbatim",
          case.steps[0].location
          == "org.w3c.epubcheck.test.ExecutionSteps.check(java.lang.String)",
          str(case.steps[0].location))
    check("a step with a location is BOUND whatever its status says",
          all(s.bound for _o, s in case.all_steps))
    check("asking for a pickle the dry run has no answer for is a refusal, "
          "not an empty closure",
          refused(lambda: run.case(loc, 999)))

    stripped = load_dry_run(
        os.path.join(fixtures, "cucumber_dry_run_epubcheck_stripped.json"),
        feature_root, project="epubcheck")
    s_case = stripped.case(loc, 11)
    check("a stripped tree's dry run reports the FIRST removable step "
          "`undefined` and the one after it `skipped`, both with no location "
          "at all -- `TestStep.run` returns SKIP once a result is not PASSED "
          "and `ExecutionMode.next` makes SKIP absorbing",
          [(s.status, s.location) for s in s_case.steps]
          == [("undefined", None), ("skipped", None)],
          str([(s.status, s.location) for s in s_case.steps]))
    check("...while the RETAINED substrate keeps answering its own two "
          "background steps, which is the disclosed leak and not a failure",
          [s.status for s in s_case.background] == ["passed", "passed"]
          and all(s.bound for s in s_case.background))
    check("`unstripped_bindings` asks the question a gate can actually ask: "
          "the stripped tree binds NO step to removable code, and the gold "
          "tree binds several",
          unstripped_bindings(stripped, b, type_index) == []
          and len(unstripped_bindings(run, b, type_index)) == 10,
          str(unstripped_bindings(stripped, b, type_index)
              or len(unstripped_bindings(run, b, type_index))))

    # -- and the document that would DEFEAT that gate is refused, not read --
    #
    # `unstripped_bindings` can only see a leak that carries a location, so
    # the one malformation it cannot survive is a tree that is NOT stripped
    # (every removable step still genuinely `passed`) with the locations
    # deleted.  That is the LENS 2 threat class -- a corrupted intermediate
    # artifact -- and it has to die in the parser, because by the time it
    # reaches the gate the gate returns `[]` and calls the strip clean.
    with open(os.path.join(fixtures, "cucumber_dry_run_epubcheck.json"),
              encoding="utf-8") as fh:
        tampered = json.load(fh)
    stripped_of_locations = 0
    for _feature in tampered:
        for _element in _feature["elements"]:
            for _step in _element["steps"]:
                if _step["match"].pop("location", None) is not None:
                    stripped_of_locations += 1
    check("a `passed` dry run with every `match.location` deleted is REFUSED "
          "by the parser, so `unstripped_bindings` is never handed a "
          "document it would report as a clean strip",
          stripped_of_locations == 15
          and refused(lambda: parse_dry_run(tampered, feature_root,
                                        project="epubcheck")),
          str(stripped_of_locations))

    # -- ...and so is the DISGUISED form of the same document ---------------
    #
    # Deleting the location alone is refused by `_validate_step` because
    # `passed` is in `INVOKED_STATUSES`.  The mutation that walks around that
    # check is to flip the status to `skipped` in the same breath: `skipped`
    # is in neither location set (it has to be -- a stripped tree writes
    # locationless `skipped` steps), it is inside `DRY_RUN_STATUSES`, and it
    # is not `ambiguous`, so nothing status-keyed and nothing location-keyed
    # sees it.  Done to every removable-bound step of the gold fixture it
    # drives `unstripped_bindings` from TEN to zero and `dry_run_problems` to
    # empty: an unstripped tree certified as a clean strip.  `_validate_skip_
    # order` refuses it on position, which is the property SKIP propagation
    # actually fixes.
    with open(os.path.join(fixtures, "cucumber_dry_run_epubcheck.json"),
              encoding="utf-8") as fh:
        disguised = json.load(fh)
    disguised_steps = 0
    for _feature in disguised:
        for _element in _feature["elements"]:
            for _step in _element["steps"]:
                _loc = _step["match"].get("location")
                if _loc is None:
                    continue
                _fqcn, _m, _p = split_location(_loc, "disguise")
                _rel = type_index.get(top_level_class(_fqcn))
                if _rel is None or b.classify(_rel) != REMOVABLE:
                    continue
                _step["match"].pop("location")
                _step["result"] = {"status": "skipped"}
                disguised_steps += 1
    check("a genuinely `passed`, removable-bound step disguised as a "
          "LOCATIONLESS `skipped` one is REFUSED -- the mutation that "
          "defeats both `unstripped_bindings` and `dry_run_problems` at once "
          "dies in the parser, on the position no forgery can make "
          "consistent by deleting bytes",
          disguised_steps == 10
          and refused(lambda: parse_dry_run(disguised, feature_root,
                                        project="epubcheck")),
          str(disguised_steps))

    # ...and the asymmetry that leaves is the one cucumber actually needs.
    # `skipped` is the one status that comes out BOTH ways round, which is
    # why `_validate_step` checks it in neither direction and why `bound`
    # reads the location rather than the status.  Cucumber matches every step
    # of a pickle up front (`Runner.createTestStepsForPickleSteps`), so a
    # skipped step keeps whatever its match carried: a `NoStepDefinition`
    # placeholder carries nothing (the stripped fixture above), a real
    # definition carries its own `match.location` -- `SKIP.execute` returns
    # SKIPPED without touching the match, and `createMatchMap`'s location
    # guard is on UNDEFINED alone.  Both halves are genuine output.
    check("a `skipped` step with no location is ACCEPTED and UNBOUND -- it is "
          "what cucumber writes for the second removable step of a stripped "
          "pickle, and the parser refuses malformations, not cucumber",
          s_case.steps[1].status == "skipped" and not s_case.steps[1].bound)
    with open(os.path.join(fixtures, "cucumber_dry_run_epubcheck.json"),
              encoding="utf-8") as fh:
        skipdoc = json.load(fh)
    # The mutation has to be a shape cucumber could WRITE, which means giving
    # the skip a cause: strip the glue for the first step of the pickle (it
    # goes `undefined`, locationless) and the second is skipped with its own
    # surviving definition still named.  Flipping the second step alone --
    # `skipped` behind an all-`passed` prefix -- is refused now, and rightly:
    # nothing would have put that test case into SKIP.
    skipdoc[0]["elements"][1]["steps"][0]["result"] = {"status": "undefined"}
    skipdoc[0]["elements"][1]["steps"][0]["match"] = {}
    skipdoc[0]["elements"][1]["steps"][1]["result"] = {"status": "skipped"}
    skip_run = parse_dry_run(skipdoc, feature_root, project="epubcheck")
    check("...while a `skipped` step that DOES name a method is bound all the "
          "same, so the status alone answers neither question",
          [(s.status, s.bound) for s in skip_run.case(loc, 11).steps]
          == [("undefined", False), ("skipped", True)],
          str([(s.status, s.bound) for s in skip_run.case(loc, 11).steps]))

    # -- the ONE cause that can skip a pickle from its first step -----------
    #
    # `TestCase.run` folds the before-hooks through the same `ExecutionMode`
    # chain as the steps, so a hook that did not pass makes the background's
    # very first step `skipped` with nothing before it -- the only shape
    # `_validate_skip_order` must let through, and therefore the only shape a
    # forgery could hide in.  It is accepted AND reported, which is the whole
    # point: an exemption nobody is told about is a hole.
    with open(os.path.join(fixtures, "cucumber_dry_run_epubcheck.json"),
              encoding="utf-8") as fh:
        hookdoc = json.load(fh)
    for _element in hookdoc[0]["elements"][:2]:
        for _step in _element["steps"]:
            _step["match"] = {}
            _step["result"] = {"status": "skipped"}
    hookdoc[0]["elements"][1]["before"] = [
        {"match": {"location": "Hooks.beforeScenario()"},
         "result": {"status": "failed", "error_message": "boom"}}]
    hook_run = parse_dry_run(hookdoc, feature_root, project="epubcheck")
    check("a pickle whose `before` hook did not pass MAY open with `skipped` "
          "steps -- `TestCase.run` folds hooks through the same "
          "ExecutionMode chain -- so the parser accepts it",
          [s.status for _o, s in hook_run.case(loc, 11).all_steps]
          == ["skipped"] * 4,
          str([s.status for _o, s in hook_run.case(loc, 11).all_steps]))
    check("...and `dry_run_problems` NAMES that hook, so the one exemption "
          "`_validate_skip_order` grants cannot be used to excuse a wholly "
          "skipped pickle in silence",
          [p for p in dry_run_problems(hook_run) if "before-hook" in p]
          == [f"{loc}:11: failed before-hook [0] (it put this pickle into "
              f"ExecutionMode.SKIP, so the steps below it are skipped for a "
              f"reason that is not a strip)"],
          str(dry_run_problems(hook_run)))

    # -- the OTHER cucumber: 6.6.0's dry run says `skipped` either way ------
    #
    # Under 7.8.0 everything above reads a STATUS order.  Under 6.6.0
    # `DRY_RUN.execute` returns SKIPPED without consulting the match, so both
    # trees come back wholly `skipped` and only `match.location` separates
    # them -- measured at 1585 located steps unstripped and 1779 locationless
    # stripped on the pinned Algorand corpus.  The contract is therefore
    # dispatched on the project's pinned version, never assumed.
    def algorand_doc(location):
        """One 6.6.0-shaped pickle: background + scenario, all `skipped`."""
        def step(line, name):
            return {"keyword": "Given ", "line": line, "name": name,
                    "match": ({"location": location} if location else {}),
                    "result": {"status": "skipped"}}
        uri = "classpath:com/algorand/algosdk/integration/offline.feature"
        return [{"uri": uri, "elements": [
            {"type": "background", "keyword": "Background", "line": 3,
             "name": "", "steps": [step(4, "a client")]},
            {"type": "scenario", "keyword": "Scenario", "line": 6,
             "name": "Encode and decode addresses",
             "steps": [step(7, "I generate a key"),
                       step(8, "I decode the address")]}]}]

    algo_root = "src/test/resources"
    located = algorand_doc(
        "com.algorand.algosdk.integration.Stepdefs.genKey()")
    locationless = algorand_doc(None)

    def algo(doc, **kw):
        return parse_dry_run(doc, algo_root, project="algorand-sdk", **kw)

    check("a 6.6.0 UNSTRIPPED dry run -- every step `skipped`, every step "
          "located -- is admitted for the leg that declares it unstripped",
          len(algo(located, expect_state=LOCATED).cases) == 1)
    check("...and a 6.6.0 STRIPPED dry run -- every step `skipped`, no step "
          "located -- is admitted for the leg that declares it stripped, "
          "which the location rule the 7.8.0 side cannot use would refuse",
          len(algo(locationless, expect_state=LOCATIONLESS).cases) == 1)
    check("...and either is admitted where the leg kind is not in hand, on "
          "uniformity alone",
          len(algo(located).cases) == 1
          and len(algo(locationless).cases) == 1)

    mixed = algorand_doc("com.algorand.algosdk.integration.Stepdefs.genKey()")
    mixed[0]["elements"][1]["steps"][1]["match"] = {}
    check("a 6.6.0 document that MIXES located and locationless steps is "
          "refused: that is the one forgery -- disguising a single answered "
          "step as unanswered -- this format still lets the reader catch",
          refused(lambda: algo(mixed))
          and refused(lambda: algo(mixed, expect_state=LOCATED)))
    check("...and the per-leg form refuses a uniform document that is in the "
          "WRONG state for its leg, in both directions",
          refused(lambda: algo(located, expect_state=LOCATIONLESS))
          and refused(lambda: algo(locationless, expect_state=LOCATED)))

    invoked = algorand_doc(
        "com.algorand.algosdk.integration.Stepdefs.genKey()")
    invoked[0]["elements"][1]["steps"][0]["result"] = {"status": "passed"}
    check("a 6.6.0 'dry run' carrying an INVOKED status is refused -- "
          "6.6.0 invokes nothing in DRY_RUN, so something else produced it",
          refused(lambda: algo(invoked))
          and refused(lambda: algo(invoked, expect_state=LOCATED)))

    # A 6.6.0 ORDINARY run is RUN mode: it invokes, so it comes back all
    # `passed`/located (1543 unit + 42 offline steps on the pinned corpus).
    # The same bytes must be refused as a dry run and admitted as an ordinary
    # one -- which is why `dry_run` is declared per leg and defaults strict.
    ordinary = algorand_doc(
        "com.algorand.algosdk.integration.Stepdefs.genKey()")
    for _element in ordinary[0]["elements"]:
        for _step in _element["steps"]:
            _step["result"] = {"status": "passed"}
    check("a 6.6.0 ORDINARY run is all `passed`/located: refused under the "
          "dry-run contract, admitted as the ordinary run it declares itself "
          "-- and ordinary keeps `_validate_skip_order`, which is version-"
          "neutral because RUN mode invokes under both cucumbers",
          refused(lambda: algo(ordinary))
          and len(algo(ordinary, dry_run=False).cases) == 1)

    check("the dry-run contract is read off the pinned per-project cucumber "
          "version, and an unpinned project is refused rather than defaulted",
          dry_run_contract("algorand-sdk") == "6.6.0"
          and dry_run_contract("epubcheck") == "7.8.0"
          and refused(lambda: dry_run_contract("coreshop"))
          and refused(lambda: algo(located, expect_state="stripped")))

    # Anti-vacuity: the accepted document is accepted for the RIGHT reason.
    # Flipping exactly one field of the admitted 6.6.0 capture must refuse it,
    # or the checks above would pass over a parser that validates nothing.
    for label, flip in (
            ("a status", lambda d: d[0]["elements"][1]["steps"][0]
             ["result"].__setitem__("status", "passed")),
            ("a location", lambda d: d[0]["elements"][1]["steps"][0]
             .__setitem__("match", {}))):
        probe = algorand_doc(
            "com.algorand.algosdk.integration.Stepdefs.genKey()")
        assert len(algo(probe, expect_state=LOCATED).cases) == 1
        flip(probe)
        check(f"anti-vacuity: flipping {label} of the admitted 6.6.0 capture "
              f"reddens it",
              refused(lambda: algo(probe, expect_state=LOCATED)))

    # -- the format probes: one mutation each, all refused ------------------
    def mutate(fn):
        with open(os.path.join(fixtures, "cucumber_dry_run_epubcheck.json"),
                  encoding="utf-8") as fh:
            doc = json.load(fh)
        fn(doc)
        return lambda: parse_dry_run(doc, feature_root,
                                     project="epubcheck")

    def first_step(doc):
        return doc[0]["elements"][1]["steps"][0]

    def skip_whole_scenario(doc):
        """Every step of the scenario element, locationless and `skipped`.

        Internally CONSISTENT on purpose: the forward direction has nothing
        to complain about here, so what refuses it is the backward direction
        alone -- the two Background steps ahead of it passed, so nothing put
        this pickle into SKIP.  A probe that left one step `passed` would be
        caught by the forward rule instead and would claim the wrong check.
        """
        for step in doc[0]["elements"][1]["steps"]:
            step["match"] = {}
            step["result"] = {"status": "skipped"}

    check("the baseline document parses", parse_dry_run(
        json.load(open(os.path.join(
            fixtures, "cucumber_dry_run_epubcheck.json"), encoding="utf-8")),
        feature_root, project="epubcheck") is not None)
    probes = {
        "an unknown status name is refused rather than guessed at":
            lambda d: first_step(d)["result"].__setitem__("status", "flaky"),
        "an unknown step member is refused, so a format that grew one is a "
        "failure rather than a silent behaviour change":
            lambda d: first_step(d).__setitem__("attachments", []),
        "a missing required member is refused":
            lambda d: first_step(d)["result"].pop("status"),
        "an `undefined` status carrying a code location is a contradiction "
        "and is refused":
            lambda d: first_step(d)["result"].__setitem__("status",
                                                          "undefined"),
        "an `ambiguous` status carrying a code location is the SAME "
        "contradiction -- both statuses carry a `NoStepDefinition` -- and is "
        "refused for the same reason":
            lambda d: first_step(d)["result"].__setitem__("status",
                                                          "ambiguous"),
        "a `passed` status with NO code location is the mirror contradiction "
        "and is refused too: `passed` is only reachable by invoking a real "
        "definition, which names itself":
            lambda d: first_step(d)["match"].pop("location"),
        "a code location that is not Class.method(ParamTypes) is refused":
            lambda d: first_step(d)["match"].__setitem__("location",
                                                         "ViewportSteps:74"),
        # -- the two directions of SKIP propagation, which is where `skipped`
        # is constrained since neither location set can hold it --
        "a pickle whose every scenario step is a LOCATIONLESS `skipped` one "
        "is refused even though nothing in it contradicts SKIP propagation "
        "downstream: the two Background steps ahead of it passed, so nothing "
        "caused the skip -- this is the direction the disguised-strip "
        "forgery needs, and the one no deletion of bytes can repair":
            skip_whole_scenario,
        "a step that is still `passed` AFTER a non-passed one in the same "
        "pickle is refused: SKIP is absorbing and SKIP.execute returns "
        "SKIPPED without consulting the match, so nothing downstream of an "
        "`undefined` step can report anything else":
            lambda d: (first_step(d)["match"].clear(),
                       first_step(d).__setitem__("result",
                                                 {"status": "undefined"})),
        "...and it stays refused when a `before` list is added whose hooks "
        "all PASSED: a hook that passed put nothing into SKIP either, so the "
        "one exemption the rule grants cannot be claimed by adding the key":
            lambda d: (skip_whole_scenario(d),
                       d[0]["elements"][1].__setitem__(
                           "before", [{"match": {}, "result":
                                       {"status": "passed"}}])),
        "an unknown member inside a `before` hook is refused, like every "
        "other object here -- the hook statuses are load-bearing now":
            lambda d: d[0]["elements"][1].__setitem__(
                "before", [{"match": {}, "result": {"status": "passed"},
                            "hook_type": "before"}]),
        "an unknown uri scheme is refused":
            lambda d: d[0].__setitem__("uri", "jar:/localization.feature"),
        "a uri that escapes the feature root is refused":
            lambda d: d[0].__setitem__("uri", "file:src/main/x.feature"),
        "an unknown element type is refused":
            lambda d: d[0]["elements"][0].__setitem__("type", "rule"),
        "two backgrounds with no scenario between them are refused":
            lambda d: d[0]["elements"].insert(1, d[0]["elements"][0]),
        "a trailing background with no scenario is refused":
            lambda d: d[0]["elements"].append(d[0]["elements"][0]),
        "two pickles on one line are refused, because a line is a pickle's "
        "identity here":
            lambda d: d[1]["elements"][1].__setitem__("line", 14),
    }
    for name, fn in sorted(probes.items()):
        check(name, refused(mutate(fn)))

    # -- the closure --------------------------------------------------------
    src = """Feature: EPUBCheck ▸ Localization

  Checks the localization configuration of EPUBCheck

  Background:
    Given EPUB test files located at '/localization/files/'
    And EPUBCheck with default settings

  ## Test locale configuration

  Scenario: The default testing locale is English
    When checking EPUB 'schema-error'
    Then the following errors are reported
      | RSC-005 | Error |

  Scenario: The reporting locale can be configured
    Given the reporting locale is set to 'fr-FR'
    When checking EPUB 'schema-error'
    Then the following errors are reported
      | RSC-005 | Erreur |
"""
    repo = b.repo_root
    feat = parse_feature_file(os.path.join(repo, loc), src)
    ex = JavaClosureExtractor(
        run, b, type_index, EPUBCHECK_COMPANION_CLASSES)
    cl = ex.closure_for(f"epubcheck/{loc}:11", feat, feat.scenarios[0])

    check("the item's steps are its Background's plus its own, in that order",
          [s.origin for s in cl.steps]
          == ["background", "background", "scenario", "scenario"],
          str([s.origin for s in cl.steps]))
    check("a retained-side step is classified retained and a removable one "
          "removable, from the boundary and the registry's class alone",
          [s.side for s in cl.steps]
          == [RETAINED, RETAINED, REMOVABLE, REMOVABLE],
          str([s.side for s in cl.steps]))
    check("the closure is the removable files the registry named",
          cl.files == ["src/test/java/org/w3c/epubcheck/test/AssertionSteps.java",
                       "src/test/java/org/w3c/epubcheck/test/ExecutionSteps.java"],
          str(cl.files))
    check("the retained substrate is recorded as touched and is NOT in the "
          "gold closure",
          cl.retained_files == [
              "src/test/java/org/w3c/epubcheck/test/EPUBCheckConfiguration.java",
              "src/test/java/org/w3c/epubcheck/test/TestEnvironment.java"],
          str(cl.retained_files))
    check("counts come from ItemClosure's own properties, not a second "
          "implementation",
          type(cl).n_steps is ItemClosure.n_steps
          and type(cl).answered_entirely_by_retained
          is ItemClosure.answered_entirely_by_retained
          and (cl.n_steps, cl.n_steps_removable, cl.n_steps_retained)
          == (4, 2, 2))
    check("feature_file is repo-RELATIVE, so validate's join lands in the "
          "workspace and not in the extraction tree",
          cl.feature_file == loc, cl.feature_file)
    check("di_fragment is EMPTY for cucumber-picocontainer, and present "
          "rather than absent",
          cl.di_fragment == {} and "di_fragment" in cl.to_json())
    check("the closure has no problems: every step bound, every file "
          "removable", cl.problems == [], str(cl.problems))

    doc = cl.to_json()
    check("the gold sidecar's six fields are present, unchanged from the "
          "Behat and behave shape, and READ OUT of closure_py rather than "
          "retyped here",
          set(GOLD_SIDECAR_FIELDS) <= set(doc),
          str(sorted(set(GOLD_SIDECAR_FIELDS) - set(doc))))
    check("every binding carries the registry's own words",
          [s["location"] for s in doc["steps"]][2]
          == "org.w3c.epubcheck.test.ExecutionSteps.check(java.lang.String)"
          and all(s["status"] == "passed" for s in doc["steps"]))
    check("the closure JSON round-trips through json.dumps unchanged",
          json.loads(json.dumps(doc, sort_keys=True)) == doc)
    check("JavaStepBinding IS a StepBinding and JavaItemClosure IS an "
          "ItemClosure -- the release writer must not learn which stack it "
          "is reading",
          isinstance(cl.steps[0], StepBinding) and isinstance(cl, ItemClosure))

    # -- outlines -----------------------------------------------------------
    # The pinned checkout's own first sixteen lines, tabs and all: the row
    # LINES are the join between the Gherkin and the registry's pickles, so a
    # tidied-up copy would join to the wrong rows and prove nothing.
    view_src = (
        "Feature: Viewport meta tag syntax\n"
        "  \n"
        "  Tests the parser for the viewport meta tag syntax as defined\n"
        "  in EPUB 3.3:\n"
        "    https://www.w3.org/TR/epub-33/#app-viewport-meta-syntax\n"
        "\n"
        "  Scenario Outline: parsing valid viewport values\n"
        "\t\tWhen parsing viewport <viewport>\n"
        "    Then no error is returned\n"
        "    And the parsed viewport equals <result>\n"
        "    \n"
        "    Scenarios:\n"
        "      | viewport                 | result                  |\n"
        '      | "width=1200, height=600" | "width=1200;height=600" |\n'
        "      # single values\n"
        '      | "p1=v1"                  | "p1=v1"                 |\n')
    vfeat = parse_feature_file(os.path.join(repo, view), view_src)
    vcl = ex.closure_for(f"epubcheck/{view}:7", vfeat, vfeat.scenarios[0])
    vdoc = vcl.to_json()
    check("an outline binds one step per (Examples row x step line), and the "
          "row count is recorded so 2 rows of 3 is not read as a 6-step "
          "scenario",
          (vdoc["counts"]["steps"], vdoc["counts"]["source_steps"],
           vdoc["counts"]["example_rows"]) == (6, 3, 2),
          str(vdoc["counts"]))
    check("every binding carries its Examples DATA-ROW line, so it can be "
          "joined to the record of the row it belongs to",
          [s["example_line"] for s in vdoc["steps"]]
          == [14, 14, 14, 16, 16, 16],
          str([s["example_line"] for s in vdoc["steps"]]))
    check("the item's own scenario_line stays the `Scenario Outline:` line, "
          "so it still matches the item id it was extracted under, and the "
          "commented-out line between the two rows is not a case",
          vdoc["scenario_line"] == 7 and vdoc["example_lines"] == [14, 16])
    check("the SUBSTITUTED step text is what the registry answered and what "
          "a stub would have to define",
          vdoc["steps"][0]["text"] == 'parsing viewport "width=1200, height=600"'
          and vdoc["steps"][3]["text"] == 'parsing viewport "p1=v1"',
          str([s["text"] for s in vdoc["steps"]]))
    check("the method-specific `{multimap}` edge adds its one invisible "
          "parameter-type companion to files, classes and scan contexts",
          vcl.files == [
              "src/test/java/org/w3c/epubcheck/SharedParameterTypes.java",
              "src/test/java/org/w3c/epubcheck/util/microsyntax/"
              "ViewportSteps.java"]
          and vcl.classes == [
              "org.w3c.epubcheck.SharedParameterTypes",
              "org.w3c.epubcheck.util.microsyntax.ViewportSteps"]
          and vcl.context_classes == vcl.classes,
          f"{vcl.files} {vcl.classes} {vcl.context_classes}")
    check("the companion edge is keyed on `assertResult`, not on the whole "
          "ViewportSteps class, and invents no registry location",
          EPUBCHECK_COMPANION_CLASSES == {
              ("org.w3c.epubcheck.util.microsyntax.ViewportSteps",
               "assertResult"):
              ("org.w3c.epubcheck.SharedParameterTypes",)}
          and all("SharedParameterTypes" not in location
                  for location in vcl.locations), str(vcl.locations))
    check("top_level_class folds a nested glue helper onto the file that "
          "declares it",
          top_level_class("org.w3c.epubcheck.util.microsyntax.ViewportSteps"
                          "$TestErrorHandler")
          == "org.w3c.epubcheck.util.microsyntax.ViewportSteps")

    # -- the WHOLE-CLASS edge shape, shown against the method-specific one --
    # The two shapes are shown to DIFFER on one fixture rather than asserted
    # to differ, and the pair is its own anti-vacuity probe: same item, same
    # registry answers, only the key's SHAPE changes.  A method key that
    # names a method this item does not bind reaches nothing; the bare FQCN
    # reaches the companion whichever method bound, which is what a
    # cross-package SOURCE reference needs (see ALGORAND_COMPANION_CLASSES).
    VIEWPORT = "org.w3c.epubcheck.util.microsyntax.ViewportSteps"
    SHARED = "org.w3c.epubcheck.SharedParameterTypes"
    SHARED_REL = "src/test/java/org/w3c/epubcheck/SharedParameterTypes.java"
    miss = JavaClosureExtractor(run, b, type_index,
                                {(VIEWPORT, "notBoundByThisItem"): (SHARED,)})
    misscl = miss.closure_for(f"epubcheck/{view}:7", vfeat, vfeat.scenarios[0])
    check("anti-vacuity: a METHOD key naming a method the item never bound "
          "reaches nothing, so the next check is not passing by accident",
          SHARED_REL not in misscl.files and SHARED not in misscl.classes,
          str(misscl.files))
    whole = JavaClosureExtractor(run, b, type_index, {VIEWPORT: (SHARED,)})
    wholecl = whole.closure_for(f"epubcheck/{view}:7", vfeat,
                                vfeat.scenarios[0])
    check("a WHOLE-CLASS key on the same class reaches the companion from "
          "whichever method bound, and lands it in files, classes and scan "
          "contexts exactly as the method-specific edge does",
          SHARED_REL in wholecl.files and SHARED in wholecl.classes
          and wholecl.context_classes == wholecl.classes
          and wholecl.files == vcl.files and wholecl.classes == vcl.classes,
          f"{wholecl.files} {wholecl.classes}")
    check("a whole-class companion invents no registry location either -- it "
          "adds a FILE to restore, never a step definition that answered",
          all(SHARED not in location for location in wholecl.locations),
          str(wholecl.locations))
    check("a key that is neither an FQCN nor a (class, method) pair is a "
          "controlled refusal, because a silently ignored key is a closure "
          "quietly short a file -- the very defect this shape repairs",
          refused(lambda: JavaClosureExtractor(
              run, b, type_index, {(VIEWPORT,): (SHARED,)}))
          and refused(lambda: JavaClosureExtractor(
              run, b, type_index, {(VIEWPORT, "assertResult", "x"): (SHARED,)}))
          and refused(lambda: JavaClosureExtractor(
              run, b, type_index, {17: (SHARED,)})))
    check("a whole-class companion is held to the SAME two guards as a "
          "method-specific one: in the type index, and classified removable",
          refused(lambda: JavaClosureExtractor(
              run, b, type_index, {VIEWPORT: ("org.w3c.epubcheck.Absent",)})))

    # -- EPUBCheck is unchanged BY CONSTRUCTION, not by re-measurement ------
    check("every EPUBCheck key is a (class, method) PAIR, so the new bare-"
          "FQCN lookup is a dict miss for every class EPUBCheck can bind: "
          "its closures cannot move, whatever this table gains for another "
          "project",
          all(isinstance(key, tuple) and len(key) == 2
              for key in EPUBCHECK_COMPANION_CLASSES)
          and all(EPUBCHECK_COMPANION_CLASSES.get(binding.definition["class"],
                                                  ()) == ()
                  for binding in vcl.steps if binding.definition is not None))
    check("and the project table gives EPUBCheck no algorand key to inherit: "
          "the two entries are disjoint and each names only its own corpus",
          set(COMPANION_CLASSES_BY_PROJECT) == {"epubcheck", "algorand-sdk", "kapua"}
          and not (set(EPUBCHECK_COMPANION_CLASSES)
                   & set(ALGORAND_COMPANION_CLASSES))
          and all(key.startswith("com.algorand.algosdk.")
                  and all(value.startswith("com.algorand.algosdk.")
                          for value in values)
                  for key, values in ALGORAND_COMPANION_CLASSES.items()))

    # -- the algorand table as DATA: the properties its derivation claims ---
    # The bytes behind these were derived by restoring each key alone onto the
    # stripped workspace and compiling in the canonical image to a fixpoint
    # (req2test_wave5_20260811/DEFECT_B_DERIVATION.md).  What is checkable
    # without a container is the shape those runs converged to.
    check("every algorand key is a bare FQCN -- the whole-class shape -- and "
          "no entry names itself",
          all(isinstance(key, str) for key in ALGORAND_COMPANION_CLASSES)
          and all(key not in values
                  for key, values in ALGORAND_COMPANION_CLASSES.items()))
    check("every value set is TRANSITIVELY CLOSED, which is what lets "
          "`closure_for` do one lookup per bound class instead of walking a "
          "graph it has no parser to build",
          all(set(ALGORAND_COMPANION_CLASSES.get(companion, ()))
              <= set(values) | {key}
              for key, values in ALGORAND_COMPANION_CLASSES.items()
              for companion in values),
          str({key: sorted(set(ALGORAND_COMPANION_CLASSES.get(c, ()))
                           - set(v) - {key})
               for key, v in ALGORAND_COMPANION_CLASSES.items()
               for c in v}))
    check("the two classes named `AtomicTxnComposer` are separate keys with "
          "DIFFERENT companion sets -- the integration one alone drags "
          "`Applications` -- which is why the key is the FQCN and could "
          "never have been the simple name",
          ALGORAND_COMPANION_CLASSES[
              "com.algorand.algosdk.integration.AtomicTxnComposer"]
          != ALGORAND_COMPANION_CLASSES[
              "com.algorand.algosdk.unit.AtomicTxnComposer"]
          and "com.algorand.algosdk.integration.Applications"
          in ALGORAND_COMPANION_CLASSES[
              "com.algorand.algosdk.integration.AtomicTxnComposer"]
          and "com.algorand.algosdk.integration.Applications"
          not in ALGORAND_COMPANION_CLASSES[
              "com.algorand.algosdk.unit.AtomicTxnComposer"])
    check("no two algorand keys share a simple name without differing, so a "
          "reader cannot collapse the table to simple names and get the same "
          "answer -- the ambiguity is real, not decorative",
          len({key.rsplit(".", 1)[1]
               for key in ALGORAND_COMPANION_CLASSES})
          < len(ALGORAND_COMPANION_CLASSES))
    check("the three keys the 59-item candidate pool reaches expand to "
          "exactly six classes -- the five the 13 excluded items had to GAIN, "
          "plus `unit.Base`, which every closure that reaches these keys "
          "already listed and which therefore added nothing to any item",
          {companion
           for key in ("com.algorand.algosdk.cucumber.shared.TransactionSteps",
                       "com.algorand.algosdk.unit.AtomicTxnComposer",
                       "com.algorand.algosdk.unit.TealSign")
           for companion in ALGORAND_COMPANION_CLASSES[key]} == {
               "com.algorand.algosdk.cucumber.shared.TransactionSteps",
               "com.algorand.algosdk.integration.Stepdefs",
               "com.algorand.algosdk.integration.TransientAccount",
               "com.algorand.algosdk.unit.ABIJson",
               "com.algorand.algosdk.unit.Base",
               "com.algorand.algosdk.unit.Rekeying"})

    # -- an unmatched step is a problem and an empty closure ----------------
    sfeat = parse_feature_file(os.path.join(repo, loc), src)
    sex = JavaClosureExtractor(stripped, b, type_index)
    scl = sex.closure_for(f"epubcheck/{loc}:11", sfeat, sfeat.scenarios[0])
    check("in a stripped tree the item's glue steps are unmatched, the gold "
          "closure is empty, and both are recorded as problems",
          scl.n_steps_unmatched == 2 and scl.files == []
          and len([p for p in scl.problems
                   if p.startswith("unmatched_step")]) == 2,
          str(scl.problems))
    check("...and the item is flagged as answered entirely by retained code, "
          "which is what the fail leg has to see",
          scl.answered_entirely_by_retained)

    # -- an AMBIGUOUS step is the other unbound case, and not the same one --
    #
    # Cucumber answers a step with two definitions by naming neither: the
    # match carries a `NoStepDefinition`, so the json plugin writes
    # `"match": {}` with `"status": "ambiguous"`.  Read as "unmatched" that is
    # an under-approximated closure with a finding that names the wrong
    # defect, and D2b's criteria (non-empty closure, contained in removable)
    # cannot see it, because the OTHER steps still produce a non-empty
    # contained closure.  So it has to be loud here.
    with open(os.path.join(fixtures, "cucumber_dry_run_epubcheck.json"),
              encoding="utf-8") as fh:
        amb_doc = json.load(fh)
    amb_step = amb_doc[0]["elements"][1]["steps"][0]
    amb_step["result"] = {"status": "ambiguous"}
    amb_step["match"] = {}
    # `ambiguous` is not `passed`, so SKIP takes the rest of the pickle with
    # it -- the step after keeps its own location and goes `skipped`, which
    # is what makes it still BOUND two checks below.
    amb_doc[0]["elements"][1]["steps"][1]["result"] = {"status": "skipped"}
    amb_run = parse_dry_run(amb_doc, feature_root, project="epubcheck")
    amb_cl = JavaClosureExtractor(amb_run, b, type_index).closure_for(
        f"epubcheck/{loc}:11", sfeat, sfeat.scenarios[0])
    check("an ambiguous step is UNBOUND -- cucumber names neither of its two "
          "definitions -- so `bound` is False and the closure loses the file",
          [s.bound for _o, s in amb_run.case(loc, 11).all_steps]
          == [True, True, False, True]
          and amb_cl.files == [f"{java_root}/org/w3c/epubcheck/test/"
                               f"AssertionSteps.java"],
          str([s.bound for _o, s in amb_run.case(loc, 11).all_steps])
          + str(amb_cl.files))
    check("...and it is reported as `ambiguous_step`, NOT as "
          "`unmatched_step`: two answers and no answers are different "
          "defects and want different repairs",
          [p for p in amb_cl.problems] ==
          ["ambiguous_step: When checking EPUB 'schema-error'"],
          str(amb_cl.problems))
    check("...and `dry_run_problems` names it too, so the whole-run gate "
          "sees it even though `ambiguous` is a status a dry run CAN produce "
          "and is deliberately inside DRY_RUN_STATUSES",
          len(dry_run_problems(amb_run)) == 1
          and "ambiguous" in dry_run_problems(amb_run)[0]
          and dry_run_problems(amb_run)[0].startswith(f"{loc}:11:"),
          str(dry_run_problems(amb_run)))

    # -- containment, table-driven ------------------------------------------
    java = "src/test/java/org/w3c/epubcheck"
    res = "src/test/resources"
    table = (
        ([f"{java}/test/ExecutionSteps.java"], []),
        ([f"{java}/container/FilenameCheckerSteps.java",
          f"{java}/util/microsyntax/ViewportSteps.java",
          f"{java}/SharedParameterTypes.java"], []),
        ([f"{java}/test/ParameterTypes.java"],
         [(f"{java}/test/ParameterTypes.java", RETAINED)]),
        ([f"{java}/RunCucumberTest.java"],
         [(f"{java}/RunCucumberTest.java", RETAINED)]),
        ([f"{java}/url/URLUtilsTest.java"],
         [(f"{java}/url/URLUtilsTest.java", PRODUCTION)]),
        ([f"{res}/cli/cli.feature"], [(f"{res}/cli/cli.feature", PRODUCTION)]),
        ([f"{res}/cucumber.properties"], []),
        ([f"{java}/test/ExecutionSteps.java", f"{java}/test/TestReport.java"],
         [(f"{java}/test/TestReport.java", RETAINED)]),
        ([None], [(None, PRODUCTION)]),
        ([], []),
    )
    for files, want in table:
        got = containment_violations(files, b)
        check(f"containment: {[os.path.basename(f) if f else None for f in files]}"
              f" -> {[v for _p, v in want] or 'contained'}",
              got == want and is_contained(files, b) == (not want), str(got))

    # -- the census ---------------------------------------------------------
    census = removable_census([cl, vcl], b, type_index)
    check("the census names every removable glue file neither the registry "
          "nor the explicit companion edge reached",
          census["unreached"] == [
              f"{java}/test/CLISteps.java",
              f"{java}/url/URLFragmentSteps.java"],
          str(census["unreached"]))
    check("...and the `{multimap}` companion is reached without reaching "
          "anything outside the removable boundary",
          f"{java}/SharedParameterTypes.java" in census["reached"]
          and census["reached_outside_removable"] == [])
    missing_companion = dict(type_index)
    missing_companion.pop("org.w3c.epubcheck.SharedParameterTypes")
    check("a declared companion missing from the type index is a controlled "
          "refusal, never a `None` mixed into the sorted file set",
          refused(lambda: JavaClosureExtractor(
              run, b, missing_companion, EPUBCHECK_COMPANION_CLASSES)))
    check("a declared companion classified retained is refused before it "
          "can broaden the candidate-editable closure",
          refused(lambda: JavaClosureExtractor(
              run, b, type_index, {
                  ("org.w3c.epubcheck.util.microsyntax.ViewportSteps",
                   "assertResult"):
                  ("org.w3c.epubcheck.test.ParameterTypes",)})))
    check("dry_run_problems is empty for a clean dry run",
          dry_run_problems(run) == [] and dry_run_problems(stripped) == [])

    # -- the type index, over a tree rather than a dict ---------------------
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o700)
        for rel in ("src/main/java/com/x/Prod.java",
                    "src/test/java/com/x/glue/Steps.java",
                    "src/test/java/com/x/glue/notes.txt"):
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("package com.x;\n")
            os.chmod(path, 0o600)
        index = build_type_index(tmp, ("src/main/java", "src/test/java"))
        check("the type index is the javac source-path rule as arithmetic: "
              "a class in package a.b.c lives at a/b/c/, so no code is read "
              "to know which file holds it",
              index == {"com.x.Prod": "src/main/java/com/x/Prod.java",
                        "com.x.glue.Steps":
                            "src/test/java/com/x/glue/Steps.java"},
              str(index))
        dup = os.path.join(tmp, "src/main/java/com/x/glue/Steps.java")
        os.makedirs(os.path.dirname(dup), exist_ok=True)
        with open(dup, "w", encoding="utf-8") as fh:
            fh.write("package com.x.glue;\n")
        os.chmod(dup, 0o600)
        check("one fully qualified name claimed by two files is refused, "
              "because the closure would silently name whichever root the "
              "walk reached last",
              refused(lambda: build_type_index(
                  tmp, ("src/main/java", "src/test/java"))))

    # -- loader + shared CLI seam, over a two-item temporary checkout ------
    import argparse

    with tempfile.TemporaryDirectory() as tmp:
        artifacts = os.path.join(tmp, "artifacts")
        os.makedirs(artifacts)
        source_files = {
            loc: src.split("\n  Scenario: The reporting", 1)[0] + "\n",
            view: view_src,
        }
        for rel, text in source_files.items():
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        for rel in type_index.values():
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("// type-index fixture\n")
        with open(os.path.join(fixtures,
                               "cucumber_dry_run_epubcheck.json"),
                  encoding="utf-8") as fh:
            dry_doc = json.load(fh)
        dry_path = os.path.join(artifacts, DRY_RUN_ARTIFACT)
        with open(dry_path, "w", encoding="utf-8") as fh:
            json.dump(dry_doc, fh)

        loaded = load_extractor(
            dry_path, os.path.join(here, "config",
                                   "boundary_epubcheck.yml"),
            feature_root, repo_root=tmp)
        swept = extract_closures(loaded, feature_root, "epubcheck")
        check("load_extractor builds the Java index once and the shared "
              "feature walker returns the two items in deterministic order",
              [closure.item_id for closure in swept] == [
                  f"epubcheck/{view}:7", f"epubcheck/{loc}:11"],
              str([closure.item_id for closure in swept]))
        check("the project-selected companion edge survives the loader, "
              "without a caller having to restate EPUBCheck knowledge",
              "src/test/java/org/w3c/epubcheck/SharedParameterTypes.java"
              in swept[0].files, str(swept[0].files))

        ns = argparse.Namespace(
            boundary=os.path.join(here, "config",
                                  "boundary_epubcheck.yml"),
            repo=tmp, features=feature_root, artifacts=artifacts)
        check("cmd_closures writes closures and the removable census",
              cmd_closures(ns) == 0
              and os.path.isfile(os.path.join(artifacts,
                                              CLOSURES_ARTIFACT))
              and os.path.isfile(os.path.join(artifacts, CENSUS_ARTIFACT)))
        with open(os.path.join(artifacts, CLOSURES_ARTIFACT), "rb") as fh:
            closure_bytes = fh.read()
        with open(os.path.join(artifacts, CENSUS_ARTIFACT), "rb") as fh:
            census_bytes = fh.read()
        cmd_closures(ns)
        with open(os.path.join(artifacts, CLOSURES_ARTIFACT), "rb") as fh:
            closure_bytes_again = fh.read()
        with open(os.path.join(artifacts, CENSUS_ARTIFACT), "rb") as fh:
            census_bytes_again = fh.read()
        check("running the source-only closure command twice is byte "
              "deterministic for both derived artifacts",
              closure_bytes_again == closure_bytes
              and census_bytes_again == census_bytes)

    # -- the ART witness, and what it does and does not cover ---------------
    gt = load_gt_map(os.path.join(fixtures,
                                  "art_step_definition_map_epubcheck.json"))
    check("the witness is keyed by (uri, line) -- the pair an item id is "
          "built from -- over 948 scenarios drawn from 44 feature files "
          "(drawn from, not covering: see the next two checks)",
          len(gt) == 948 and len({uri for uri, _l in gt}) == 44
          and (loc, 11) in gt, f"{len(gt)} scenarios")
    check("a witness with no provenance is refused, because a number nobody "
          "can trace is not a cross-check",
          refused(lambda: _witness(
              {"schema": GT_SCHEMA, "provenance": {"kind": "imported"},
               "scenarios": []}, GT_SCHEMA, "scenarios", "probe")))
    check("a witness under the wrong schema is refused",
          refused(lambda: _witness(
              {"schema": "other/1", "provenance": {}, "scenarios": []},
              GT_SCHEMA, "scenarios", "probe")))
    check("the witness reads the localization item exactly as this "
          "extractor's closure does -- four steps, Background first",
          [sig for _t, sig in gt[(loc, 11)].step_definitions]
          == [s.location for s in cl.steps],
          str([sig for _t, sig in gt[(loc, 11)].step_definitions]))

    agree = compare_to_gt([cl], gt)
    check("an item both sides saw and agree about is counted once and "
          "produces no disagreement",
          (len(agree.covered), len(agree.agreed), agree.disagreements)
          == (1, 1, []) and agree.item_agreement == 1.0
          and agree.pair_agreement == 1.0, str(agree.summary()))
    check("the five feature files the witness never ran are reported as "
          "UNCOVERED rather than as agreement, so the ratio cannot be read "
          "as a statement about items it never saw",
          compare_to_gt([vcl], gt).uncovered == [vcl.item_id]
          and compare_to_gt([vcl], gt).covered == [],
          str(compare_to_gt([vcl], gt).uncovered))
    check("...and the viewport feature is one of exactly five the pinned "
          "witness does not cover, which is a fact about ART's map and is "
          "written down in PROVENANCE.md",
          len({u for u, _l in gt}) == 44
          and not any(u.endswith("viewport-syntax.feature") for u, _l in gt))

    # The gap has a SECOND half, and the file-level phrasing hides it: 41
    # scenarios INSIDE the 44 files the witness did run are absent from it as
    # well.  A probe drawn from that list -- an `Example:`-keyword scenario
    # of a covered feature file, which ART's extractor never asked about --
    # has to land in `uncovered` exactly as the five unrun files do, or the
    # agreement denominator quietly grows by items nobody witnessed.
    vocab = "src/test/resources/epub3/D-vocabularies/vocabularies.feature"
    inside = JavaItemClosure(item_id=f"epubcheck/{vocab}:20",
                             feature_file=vocab, scenario_line=20, steps=[])
    check("a scenario the witness omits from a file it DID run is uncovered "
          "too: the map covers 44 feature files, NOT 44 whole files",
          any(u == vocab for u, _l in gt) and (vocab, 20) not in gt
          and compare_to_gt([inside], gt).uncovered == [inside.item_id]
          and compare_to_gt([inside], gt).covered == [],
          str(compare_to_gt([inside], gt).uncovered))
    check("...and PROVENANCE.md discloses both halves BY NUMBER, so 948 "
          "cannot be read as a count over the checkout",
          all(s in provenance for s in
              ("1041 scenarios", "989 scenarios",
               "Forty-one scenarios INSIDE")),
          "the KNOWN INCOMPLETENESS entry no longer states the in-file gap")

    # The class/signature half of the same disclosure, re-derived from the
    # map's own bytes rather than dictated into the prose.  The checkout has
    # TEN classes that declare a step (the eight removable glue ones the
    # boundary counts, plus the two retained ones whose leak it discloses);
    # the map names seven of them -- five removable and both retained.  The
    # entry said "seven of the eight", which is arithmetically impossible in
    # either direction.
    witness_classes = {c for s in gt.values() for c, _m in s.pairs}
    witness_sigs = {sig for s in gt.values()
                    for _t, sig in s.step_definitions}
    check("the witness names 7 distinct step classes and 27 distinct "
          "signatures, and PROVENANCE.md states the denominator those seven "
          "are seven OF (ten in the checkout, not eight)",
          (len(witness_classes), len(witness_sigs)) == (7, 27)
          and "seven of the checkout's ten step-declaring" in " ".join(
              provenance.split()),
          f"{len(witness_classes)} classes, {len(witness_sigs)} signatures")
    # ...and WHICH seven, because five of them are glue and two are the
    # retained substrate: "seven step classes" is not seven answers a
    # candidate has to write.  The path is the javac rule this module already
    # relies on (`build_type_index`), applied to the witness's own FQCNs.
    def _rel_of(fqcn):
        return f"{java_root}/{fqcn.replace('.', '/')}.java"

    check("...and WHICH seven: five of the removable eight, plus BOTH "
          "retained classes -- so 'seven step classes' is not seven classes "
          "a candidate would have to write",
          {c for c in witness_classes
           if b.classify(_rel_of(c)) == REMOVABLE} == {
               "org.w3c.epubcheck.container.FilenameCheckerSteps",
               "org.w3c.epubcheck.test.AssertionSteps",
               "org.w3c.epubcheck.test.ExecutionSteps",
               "org.w3c.epubcheck.test.JSONReportAssertionSteps",
               "org.w3c.epubcheck.test.XMLReportAssertionSteps"}
          and {c for c in witness_classes
               if b.classify(_rel_of(c)) == RETAINED} == {
                   "org.w3c.epubcheck.test.EPUBCheckConfiguration",
                   "org.w3c.epubcheck.test.TestEnvironment"},
          str(sorted(witness_classes)))

    # A disagreement must be ENUMERATED, not averaged away: the probe swaps
    # one binding's class for another real glue class and the report has to
    # name both sides of the difference.
    import copy as _copy

    wrong = _copy.deepcopy(cl)
    wrong.steps[2].definition = dict(
        wrong.steps[2].definition,
        **{"class": "org.w3c.epubcheck.test.CLISteps"})
    off = compare_to_gt([wrong], gt)
    check("a disagreeing item is named, with what each side has that the "
          "other does not",
          len(off.agreed) == 0 and len(off.disagreements) == 1
          and "CLISteps.check" in off.disagreements[0]
          and "ExecutionSteps.check" in off.disagreements[0],
          str(off.disagreements))
    check("...and the step-definition micro-average moves where the item "
          "rate only goes to zero: 3 of 5 pairs still agree",
          (off.pairs_agreed, off.pairs_total) == (3, 5)
          and off.item_agreement == 0.0, str(off.summary()))

    # -- the production API index ------------------------------------------
    art = load_art_api_index(os.path.join(fixtures,
                                          "art_api_index_epubcheck.json"))
    check("ART's pinned index is 923 names, exactly as its own header says",
          len(art) == 923, str(len(art)))
    check("...and it LEAKS a test class into the production API index: "
          "`DateParserTest` lives under src/main/java, so `main` and "
          "`testisISO8601Date` resolve to it",
          "com.adobe.epubcheck.util.DateParserTest" in art["main"]
          and art["testisISO8601Date"]
          == ["com.adobe.epubcheck.util.DateParserTest"],
          str(art.get("testisISO8601Date")))
    clean, dropped = drop_test_classes(art)
    check("the fix drops exactly those two entries, on the real bytes that "
          "carried the defect",
          dropped == [["main", "com.adobe.epubcheck.util.DateParserTest"],
                      ["testisISO8601Date",
                       "com.adobe.epubcheck.util.DateParserTest"]],
          str(dropped))
    check("...`main` survives on the production class that also declares it, "
          "and `testisISO8601Date` is gone entirely, because a method name "
          "mapping to nothing is not an API",
          clean["main"] == ["com.adobe.epubcheck.tool.Checker"]
          and "testisISO8601Date" not in clean and len(clean) == 922,
          f"{clean.get('main')} {len(clean)}")
    check("Surefire's default includes are the rule, not a taste: they are "
          "what `mvn test` compiles and runs as a test",
          SUREFIRE_TEST_INCLUDES == ("Test*", "*Test", "*Tests", "*TestCase")
          and all(is_surefire_test_class(n)
                  for n in ("DateParserTest", "TestSuite", "OPFTests",
                            "URLUtilsTest", "FooTestCase"))
          and not any(is_surefire_test_class(n)
                      for n in ("DateParser", "Contest", "Latest",
                                "Attestation")))

    # -- the declaration scanner, table-driven ------------------------------
    scanner = (
        ("a plain method", "void foo() {}", {("foo", "method", True)}),
        ("a primitive return type -- the case that cost every "
         "`boolean canDecrypt(URL)` in the corpus",
         "public boolean canDecrypt(URL url) { return true; }",
         {("canDecrypt", "method", True)}),
        ("a generic return type", "public List<String> names() { return null; }",
         {("names", "method", True)}),
        ("a nested generic return type",
         "Map<String, List<X>> m() { return null; }",
         {("m", "method", True)}),
        ("an array return type", "String[] all() { return null; }",
         {("all", "method", True)}),
        ("a `throws` clause between the parameters and the body",
         "void go() throws IOException {}", {("go", "method", True)}),
        ("an interface declaration has no body and is still an API",
         "interface I { String get(); }",
         {("get", "method", False)}),
        ("an abstract declaration, likewise",
         "abstract class A { abstract void run(); }",
         {("run", "method", False)}),
        ("a constructor, which has no return type",
         "class Foo { public Foo(int a) {} }",
         {("Foo", "constructor", True)}),
        ("a call is not a declaration",
         "class C { void a() { helper(1); } }",
         {("a", "method", True)}),
        ("`new X(...)` is not a declaration",
         "class C { void a() { X x = new X(1); } }",
         {("a", "method", True)}),
        ("a control-flow keyword is not a declaration",
         "class C { void a() { if (x) { while (y) {} } } }",
         {("a", "method", True)}),
        ("`Optional.<T> absent()` is an invocation with an explicit type "
         "argument, not a generic declaration -- the other case that had to "
         "be handled by name",
         "class C { Optional<T> f() { return Optional.<T> absent(); } }",
         {("f", "method", True)}),
        ("a step expression inside an annotation contributes nothing, "
         "because a literal's CONTENTS are blanked before tokenising",
         '@Then("the parsed viewport equals {multimap}")\n'
         'void assertResult(M m) {}', {("assertResult", "method", True)}),
        ("a commented-out declaration contributes nothing",
         "// void ghost() {}\n/* void ghost2() {} */\nvoid real() {}",
         {("real", "method", True)}),
        ("an apostrophe in a comment does not swallow the file",
         "// it's fine\nvoid real() {}", {("real", "method", True)}),
        ("an escaped quote inside a literal does not swallow the file",
         'class C { String s = "a\\"b"; void real() {} }',
         {("real", "method", True)}),
    )
    for name, source, want in scanner:
        got = java_declarations(source, "probe")
        check(f"scanner: {name}", got == want, f"{got} != {want}")
    check("a Java 15 text block is refused rather than mis-parsed",
          refused(lambda: java_declarations('String s = """x""";', "probe")))
    check("a file with no `package` declaration is refused: a class in the "
          "default package has no name to index it under",
          refused(lambda: java_package("class C {}", "probe"))
          and java_package("/* c */ package a.b;\nclass C {}", "probe")
          == "a.b")

    # -- the index over a tree, with the leak planted in it ----------------
    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o700)
        tree = {
            "src/main/java/com/x/Prod.java":
                "package com.x;\npublic class Prod { public int go() { "
                "return 1; } public Prod() {} }\n",
            "src/main/java/com/x/Api.java":
                "package com.x;\npublic interface Api { String name(); }\n",
            # upstream's own misfiling, the epubcheck case exactly
            "src/main/java/com/x/ProdTest.java":
                "package com.x;\npublic class ProdTest { public static void "
                "main(String[] a) {} public void testGo() {} }\n",
            "src/test/java/com/x/glue/Steps.java":
                "package com.x.glue;\npublic class Steps { public void "
                "step() {} }\n",
        }
        for rel, text in tree.items():
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(path, 0o600)
        tb = Boundary(version=1, project="probe", repo_root=tmp,
                      removable=[("src/test/java/", "")], retained=[])
        built = build_api_index(tmp, ("src/main/java", "src/test/java"), tb)
        check("the index is production source only: the glue the boundary "
              "removes and the test class Surefire would run are BOTH out, "
              "and each exclusion says which rule removed it",
              built["api_index"] == {"Prod": ["com.x.Prod"],
                                     "go": ["com.x.Prod"],
                                     "name": ["com.x.Api"]}
              and built["excluded"] == [
                  ["src/main/java/com/x/ProdTest.java",
                   "surefire_default_includes"],
                  ["src/test/java/com/x/glue/Steps.java",
                   "boundary:removable"]],
              f"{built['api_index']} {built['excluded']}")
        check("an interface method is in the index, which is where this "
              "adaptation is deliberately WIDER than ART's body-requiring "
              "tree-sitter query",
              "name" in built["api_index"]
              and ("name", "method", False)
              in java_declarations(tree["src/main/java/com/x/Api.java"], "p"))
        bad = os.path.join(tmp, "src/main/java/com/x/Wrong.java")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("package com.y;\nclass Wrong {}\n")
        os.chmod(bad, 0o600)
        check("a `package` declaration that disagrees with the directory is "
              "refused, because javac would not find that class on the "
              "source path and the FQCN would be a name nothing resolves",
              refused(lambda: build_api_index(
                  tmp, ("src/main/java", "src/test/java"), tb)))

    print("\n" + ("ALL PASS (java.closure_java)" if ok
                  else "FAILURES (java.closure_java)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
