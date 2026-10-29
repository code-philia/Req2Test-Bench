"""The cucumber/Java stack — J5's harness half, over cucumber's own JSON.

`behat.py` is a façade over code that already existed and `behave.py` is the
stack that was written second; this is the third, and it is the first whose
RECORDER is not ours.  Behat and behave both run a hook the strip installs,
and that hook writes `r2t.record/1` directly.  cucumber-jvm already ships a
JSON formatter that reports every scenario, every step, every status and
every exception, so this stack installs no recorder at all: it declares
cucumber's own `json:` plugin on a harness-owned runner class and FOLDS the
document cucumber wrote into the same `r2t.record/1` lines the other two
stacks emit.  One vocabulary, three producers, and this one is the
framework's rather than ours.

What that buys and what it costs, both stated because the difference decides
several rules below:

* the statuses are cucumber's (`passed/skipped/pending/undefined/ambiguous/
  failed`), not a mapping we invented, so `AMBIGUOUS` — two step definitions
  matching one step, which is the single most likely way a generated glue
  class collides with the retained substrate — arrives as its own name
  rather than as an exception message we would have had to pattern-match;
* the fold runs on the HOST, after the container exits, so a step definition
  cannot see it and the harness never has to trust code it just installed to
  report on itself;
* but the JSON is written into the workspace by the run, and a step
  definition executes with that workspace writable.  So the identity rule
  the other two stacks apply to the record file applies here to the folded
  records unchanged: `harness.fold_scenario_records` keeps only the records
  whose `scenario_line` is one of the lines THIS harness synthesised, and a
  record on any other line is excluded wherever it sits in the document.

The decisions this file pins, each with the reason it is not the obvious
alternative:

* **The JSON plugin is declared by a harness-owned runner class, and
  `-Dcucumber.plugin` never appears in any invocation.**  Both corpora have
  a runner of their own that the boundary RETAINS (`RunCucumberTest`,
  `RunCucumberUnitTest`), and neither declares a JSON plugin; algorand's
  declares a `progress` plugin on STDOUT, so adding a second STDOUT plugin
  from the command line is an error the ART recipe hit and worked around by
  omitting the flag entirely (`ReqEnhancement/configs.py`, algorand-sdk
  `cucumber_plugin: ''`).  A runner the HARNESS owns and installs at strip
  time sidesteps the whole class of conflicts, is hashed into the substrate
  baseline like every other harness-owned file, and leaves each project's
  own runner byte-identical.
* **One scenario per run, selected by the synthesised feature.**  The item's
  scenario is written to a feature file of its own (`FEATURE_REL`) and
  `-Dcucumber.features` points at it on the classpath.  A name filter is a
  per-project quirk rather than the rule: for a `Scenario Outline` cucumber
  names each pickle with the Examples row SUBSTITUTED, so a filter built
  from the outline's own title matches nothing — `filter_name_regex` is what
  makes the algorand quirk safe on the corpus that is half outlines.
* **`AMBIGUOUS` folds to `failed`** with the exception preserved on the
  record, and an UNRECOGNISED status VOIDS the run rather than guessing at
  it (`no_steps_ran` — "we did not measure this", ranked ahead of every
  verdict by `RunResult.outcome`).  A status this stack has never seen means
  the container's cucumber is not the pinned one, and a verdict derived from
  a vocabulary we cannot read is not a measurement.

The J4 closure seam and J6 mutation/stub seams are re-exported at the FOOT of
this file.  The Java population CLI reaches the reviewed canonical-image
producer there; exposing a source-local javac shortcut would let the same
project mint a different population under the coordinator's ambient JDK.
"""
from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, replace

from ..bench import harness as _hz
from ..bench import repo as _repo
from ..core.boundary import PRODUCTION
from ..core.gherkin import standalone_feature
from ..core.paths import DATA_ROOT_ENV, project_path
from ..java import direct_calls as _dc
from ..java import kapua as _kapua

#: The value of `framework:` in `config/profile_epubcheck.yml`, and the key
#: `stacks.for_framework` dispatches on.  Checked against the registry name
#: there: a module derived from another stack's that kept ITS `FRAMEWORK`
#: would be routed under its own name and then take that stack's branch of
#: every dispatch — i.e. run a Java project through the PHP harness.
FRAMEWORK = "cucumber"

#: The language, checked against `framework:` when a profile loads.
LANGUAGE = "java"


class CucumberStackRefused(RuntimeError):
    """This stack refusing to act, loudly, with the reason attached.

    One error type for the whole module.  Every refusal below is the same
    kind of finding — "the tree, the document or the project is not the one
    this stack was written against" — and a caller that wants to tell them
    apart reads the message, which names the file and the value.  Raised
    rather than returned: each of these makes every number downstream of it
    unfalsifiable, and a sweep that continued past one would produce results
    indistinguishable from valid ones later.
    """


# ------------------------------------------------------ per-project quirks
#
# Two Java corpora, one framework, and four differences that reach the argv.
# They are DATA in one table rather than branches spread through `execute`,
# because the failure mode they guard against is a rule from one project
# silently applying to the other: algorand's `-Dcucumber.plugin` conflict is
# not epubcheck's problem, and epubcheck's surefire working directory is not
# algorand's.  Each field is read out of the projects' own pinned bytes, and
# the comment says where.


@dataclass(frozen=True)
class ProjectQuirks:
    """What differs between two cucumber-jvm projects, at the argv."""

    #: The `-Dtest=` value.  Simple class name or FQCN is a SUREFIRE VERSION
    #: fact, not a taste: epubcheck pins surefire 2.18.1, whose `-Dtest`
    #: matches on the simple class name only (fully-qualified patterns
    #: arrived in 2.19); algorand pins 3.0.0-M5 and the ART recipe passes it
    #: the FQCN (`ReqEnhancement/configs.py`, `cucumber_runner_class`).
    test_selector: str

    #: Where the harness-owned runner is installed, and what it is called.
    #: The PACKAGE supplies cucumber's default glue path.  `runner_options`
    #: names any additional packages required by this prepared workspace.
    runner_rel: str
    runner_package: str
    runner_class: str

    #: Removable package into which generated step definitions are installed.
    glue_rel: str

    #: The `@CucumberOptions` elements, verbatim and in order, BESIDE the
    #: `plugin` one (which is derived below from the JSON path).  Whatever
    #: the project's own runner needs to find its glue goes here.
    runner_options: tuple[str, ...]

    #: The working directory of the SUREFIRE FORK, workspace-relative, and
    #: the pom expression that must produce it.  cucumber resolves a `json:`
    #: plugin path against the forked JVM's cwd, so this is what decides
    #: where the document the fold reads actually lands.  epubcheck's pom
    #: sets `<workingDirectory>` explicitly; algorand's does not, and the
    #: fork then runs in the project basedir.  `None` means "the element
    #: must be absent", and `integrity_baseline` refuses either way round —
    #: a pom whose working directory moved would write the JSON somewhere
    #: the harness never looks, and every item would read `no_scenario_ran`.
    fork_workdir: str
    fork_workdir_pom: str | None

    #: Cucumber's JSON document, workspace-relative.  Under `target/`, which
    #: is a BUILD root (purged at strip, sitting under no substrate root), so
    #: writing it per item disturbs no baseline.
    json_rel: str

    #: Whether the invocation ALSO filters by scenario name.  Not needed to
    #: select — the synthesised feature holds exactly one scenario — and it
    #: is a quirk rather than a rule because a name filter has to be built
    #: from the SUBSTITUTED pickle names for an outline (`filter_name_regex`).
    select_by_name: bool

    #: The JDK the project's image must carry, and the reason it is not one
    #: number for both: epubcheck's pom compiles with `<source>/<target>` 1.8
    #: (JDK 8 does that), algorand's with `<release>8`, which JDK 8's javac
    #: has no `--release` flag for at all.  The image is J3's and J8's; here
    #: it is what the selftest holds `direct_call_agent` against, and it was
    #: recorded because the pair is exactly the fact that gets lost between
    #: two milestones.
    jdk_major: int

    #: Whether a coverage run attaches the direct-invocation agent
    #: (`API_DIRECT_INVOCATION_SPEC.md` 2.4).  A per-project fact and not the
    #: stack's rule because the agent is a `--release 11` class file
    #: (`direct_calls.JAVA_RELEASE`) and epubcheck's fork is `jdk_major` 8: a
    #: JVM handed an agent it cannot read aborts before any test runs, so no
    #: epubcheck item could be measured at all.  False leaves that project's
    #: coverage invocation byte-for-byte the one this stack has always
    #: issued, with `direct_calls` null: not collected.
    direct_call_agent: bool

    #: Kapua's fork runs from its selected Maven module's basedir. Empty
    #: preserves the original single-module projects' command and path shape.
    module_rel: str = ""
    prerequisite_tag: str | None = None

    @property
    def json_plugin(self) -> str:
        """The `plugin` element's value, as the RUNNER must spell it.

        Derived from the two facts above rather than written a third time:
        the path cucumber writes is resolved against the fork's cwd, and the
        path the harness reads is workspace-relative, so exactly one of them
        can be typed and the other has to be computed from it.
        """
        fork_root = os.path.join(self.module_rel, self.fork_workdir) or "."
        return "json:" + os.path.relpath(self.json_rel, fork_root)


QUIRKS: dict[str, ProjectQuirks] = {
    "epubcheck": ProjectQuirks(
        test_selector="R2TBenchCucumberTest",
        runner_rel="src/test/java/org/w3c/epubcheck/R2TBenchCucumberTest.java",
        runner_package="org.w3c.epubcheck",
        runner_class="R2TBenchCucumberTest",
        glue_rel="src/test/java/org/w3c/epubcheck/test",
        # `features = "classpath:"` is the retained `RunCucumberTest`'s own
        # option, kept so that a run WITHOUT `-Dcucumber.features` (an
        # operator debugging by hand) behaves the way the project does.
        runner_options=('features = "classpath:"',),
        fork_workdir="target/test-classes",
        fork_workdir_pom="${project.build.directory}/test-classes",
        json_rel="target/r2t-cucumber.json",
        # The synthesised feature holds one scenario, so the feature path
        # selects it exactly; a second selector could only ever subtract.
        select_by_name=False,
        jdk_major=8,
        direct_call_agent=False),
    # J8's project.  Its boundary, profile and image land there; the argv
    # facts are recorded HERE because they are the reason this table exists,
    # and because two of them are things J8 would otherwise have to
    # rediscover: `-Dcucumber.plugin` is unusable (the project's own runner
    # already holds STDOUT with `progress`), and its cucumber is 6.6.0,
    # whose `@CucumberOptions` still carries the `strict` element that 7.x
    # removed — declaring it is the harness-owned pin of the behaviour the
    # exit-code witness rests on.
    "algorand-sdk": ProjectQuirks(
        test_selector="com.algorand.algosdk.unit.R2TBenchCucumberTest",
        runner_rel=("src/test/java/com/algorand/algosdk/unit/"
                    "R2TBenchCucumberTest.java"),
        runner_package="com.algorand.algosdk.unit",
        runner_class="R2TBenchCucumberTest",
        glue_rel="src/test/java/com/algorand/algosdk/unit",
        # `extraGlue` is upstream's (`RunCucumberUnitTest`): the shared step
        # definitions live outside the runner's package and a runner without
        # it finds half the glue.  `tags` is deliberately NOT copied — the
        # upstream runner tags itself `@disabled.by.default` so that a plain
        # `mvn test` runs nothing, and this runner exists to run exactly the
        # one synthesised feature it is pointed at.  `publish` is not copied
        # either: it POSTs the report to cucumber's service, and the image
        # runs on a no-egress network.
        runner_options=('extraGlue = "com.algorand.algosdk.cucumber.shared"',
                        'strict = true'),
        fork_workdir="",
        fork_workdir_pom=None,
        json_rel="target/r2t-cucumber.json",
        select_by_name=True,
        jdk_major=11,
        direct_call_agent=True),
}

def _kapua_quirks(suite: _kapua.Suite) -> ProjectQuirks:
    klass = "R2TBench" + suite.upstream_runner_class
    # Cucumber scans packages recursively without deduplicating classes across
    # glue roots. Unit runners already scan the generated package's parent.
    generated_is_scanned = any(
        suite.generated_package == package
        or suite.generated_package.startswith(package + ".")
        for package in suite.glue)
    glue = (suite.glue if generated_is_scanned
            else (*suite.glue, suite.generated_package))
    return ProjectQuirks(
        test_selector=suite.runner_package + "." + klass,
        runner_rel=(suite.module + "/src/test/java/"
                    + suite.runner_package.replace(".", "/") + "/" + klass + ".java"),
        runner_package=suite.runner_package,
        runner_class=klass,
        glue_rel=suite.generated_root.rstrip("/"),
        runner_options=("glue = {" + ", ".join(
            json.dumps(package) for package in glue) + "}",),
        fork_workdir="", fork_workdir_pom=None,
        json_rel=suite.module + "/target/r2t-cucumber.json",
        select_by_name=False, jdk_major=17, direct_call_agent=True,
        module_rel=suite.module, prerequisite_tag="@setup")


_KAPUA_SUITES = _kapua.SUITES + _kapua.DIAGNOSTIC_SUITES
_KAPUA_RUNNERS = tuple(_kapua_quirks(suite) for suite in _KAPUA_SUITES)
_KAPUA_FEATURE_QUIRKS = {
    feature: quirks
    for suite, quirks in zip(_KAPUA_SUITES, _KAPUA_RUNNERS)
    for feature in suite.features
}
QUIRKS["kapua"] = _KAPUA_RUNNERS[0]


_ALGORAND_INTEGRATION_UNSTRIPPED = replace(
    QUIRKS["algorand-sdk"],
    test_selector="com.algorand.algosdk.integration.R2TBenchCucumberTest",
    runner_rel=("src/test/java/com/algorand/algosdk/integration/"
                "R2TBenchCucumberTest.java"),
    runner_package="com.algorand.algosdk.integration",
    glue_rel="src/test/java/com/algorand/algosdk/integration",
    # Integration (this runner's own package, cucumber's default glue) plus
    # the shared steps -- exactly what upstream's own
    # `RunCucumberIntegrationTest` declares, and NOT the unit package.
    # Co-scanning unit was a synthesized belief the first live run falsified:
    # upstream declares identical step texts in both packages, so cucumber
    # refused the offline leg outright with a
    # `DuplicateStepDefinitionException` over
    # `unit.Rekeying.i_add_a_rekeyTo_field_with_address(String)` and
    # `integration.Stepdefs.i_add_a_rekeyTo_field_with_address(String)`.
    # Upstream never co-scans -- each suite has its own runner -- and unit
    # items are served by the unit runner, so nothing is lost: every step of
    # the relocated offline feature binds inside `integration.Stepdefs`.
    runner_options=('extraGlue = "com.algorand.algosdk.cucumber.shared"',
                    'strict = true'))

# The stripped workspace contains no upstream answer glue.  Its offline
# runner must also scan the unit package that the profile tells an agent to
# write.  The unstripped twin above stays narrow because upstream unit and
# integration glue contain duplicate expressions.
_ALGORAND_INTEGRATION = replace(
    _ALGORAND_INTEGRATION_UNSTRIPPED,
    runner_options=(
        'extraGlue = {"com.algorand.algosdk.cucumber.shared", '
        '"com.algorand.algosdk.unit"}',
        'strict = true'))


def quirks_for(project: str, source_feature: str | None = None) \
        -> ProjectQuirks:
    """This project's argv facts, or a refusal naming the ones that exist.

    A CLOSED lookup.  Falling back to epubcheck's for an unknown project
    would run a third Java repository with epubcheck's surefire assumptions:
    the JSON would be read from a path nothing wrote, every item would score
    `no_scenario_ran`, and the finding would wear the new project's name.
    """
    quirks = QUIRKS.get(project)
    if quirks is None:
        raise CucumberStackRefused(
            f"REFUSED: no cucumber quirks for project {project!r}. This "
            f"stack knows {sorted(QUIRKS)}; a third Java project needs its "
            f"own row (surefire version, fork working directory, runner "
            f"package) before anything here can run it — every one of those "
            f"decides where cucumber's JSON lands, and a wrong answer reads "
            f"as 'no scenario ran' on every item.")
    if project == "kapua" and source_feature is not None:
        try:
            return _KAPUA_FEATURE_QUIRKS[source_feature]
        except KeyError:
            raise CucumberStackRefused(
                f"REFUSED: Kapua feature {source_feature!r} has no measured "
                "admitted runner binding") from None
    if project == "algorand-sdk":
        from ..java.algorand import OFFLINE_SOURCE, OFFLINE_WORKSPACE
        if source_feature in (OFFLINE_SOURCE, OFFLINE_WORKSPACE):
            return _ALGORAND_INTEGRATION
    return quirks


def runner_variants_for(project: str, *,
                        stripped: bool = True) -> tuple[ProjectQuirks, ...]:
    """Every generated runner this project's prepared workspace needs."""
    default = quirks_for(project)
    if project == "kapua":
        return _KAPUA_RUNNERS
    integration = (_ALGORAND_INTEGRATION
                   if stripped else _ALGORAND_INTEGRATION_UNSTRIPPED)
    return ((default, integration)
            if project == "algorand-sdk" else (default,))


#: A `Scenario Outline` placeholder, as a CAPTURING group.  The capture is
#: the whole point: `re.split` KEEPS what a capturing pattern matched and
#: DROPS what a non-capturing one matched, so only this spelling hands back
#: literal and placeholder alternately.  With `r"<[^<>]*>"` — no group —
#: every element of the split is a literal, and the `i % 2` alternation
#: below then replaces every second LITERAL with `.*` and discards the
#: placeholders: `Rows <n> of <table>` came out as `^Rows\ .*$`, with " of "
#: silently gone.  Written as a compiled constant so the two spellings
#: cannot be confused again by an edit to the comprehension alone.
_PLACEHOLDER = re.compile(r"(<[^<>]*>)")


def filter_name_regex(title: str) -> str:
    """`-Dcucumber.filter.name`'s value for one scenario, outlines included.

    cucumber matches this against the PICKLE's name, and a pickle of a
    `Scenario Outline` is named with its Examples row substituted: the
    outline `Rows <n>` produces `Rows 1`, `Rows 2`, ...  A filter built by
    escaping the title whole therefore matches none of them, which on the
    algorand corpus — 121 of its 125 admitted items are outlines — would be
    every item scoring `no_scenario_ran` for a reason no log states.

    So the placeholders become `.*`, everything BETWEEN them is escaped and
    kept, and the result is anchored: `Rows <n> of <table>` ->
    `^Rows\\ .*\\ of\\ .*$`.  The literals are what makes this a filter at
    all — an outline title is mostly its literals, and dropping them leaves
    a pattern that matches by prefix.

    Still over-broad by construction: `.*` admits more than any Examples
    cell could hold, so a sibling scenario sharing this one's literal
    skeleton would be selected too.  That is the safe direction for the
    corpus this quirk exists for (algorand, where the synthesised file holds
    the item's outline alone) and it is bounded rather than unbounded, which
    matters on the `requirement_to_test` path: there the feature is the
    SOLUTION's, `write_feature` takes the last scenario in it as the
    expected one, and a filter that had kept only the first literal would
    select every earlier scenario in the same file.
    """
    parts = [".*" if i % 2 else re.escape(p)
             for i, p in enumerate(_PLACEHOLDER.split(title))]
    return "^" + "".join(parts) + "$"


# --------------------------------------------------- cucumber's vocabulary
#
# The statuses cucumber-jvm's JSON formatter writes, mapped onto the five
# `stacks.base.STEP_RESULTS` values every stack's records are read in.
# Six of cucumber's, five of ours, and the one collapse is deliberate.

#: cucumber status -> `r2t.record/1` step result.  A status ABSENT from this
#: table voids the run (see `records_from_json`); it is not defaulted.
STEP_RESULT_BY_STATUS: dict[str, str] = {
    "passed": "passed",
    # cucumber skips the rest of a scenario after a failure, and it skips
    # every step of a scenario whose Background failed.  Both are the
    # schema's `skipped`, which `record_outcome` deliberately does not rank:
    # a scenario whose steps were skipped did not pass and is not undefined.
    "skipped": "skipped",
    "pending": "pending",
    "undefined": "undefined",
    "failed": "failed",
    # AMBIGUOUS is cucumber's name for "this step matched more than one step
    # definition", which is what happens when a generated glue class
    # re-declares a step the retained substrate already declares.  It is a
    # FAILURE of the submission, not of the environment: the run reached the
    # step and could not decide what to execute.  The exception cucumber
    # raises is preserved on the record so the row says which definitions
    # collided rather than only that something did.
    "ambiguous": "failed",
}

#: The exception class an `ambiguous` step carries when cucumber's own
#: message does not name one.  cucumber raises exactly this type, and the
#: name is on the record because "which exception" is the difference between
#: a failed assertion and a glue collision.
AMBIGUOUS_EXCEPTION = (
    "io.cucumber.core.runner.AmbiguousStepDefinitionsException")

#: The class recorded for a failed step whose message names no exception
#: type.  A step can fail without an exception (cucumber records a message
#: only), and an empty class would read as "we did not look".
UNTYPED_EXCEPTION = "io.cucumber.core.exception.CucumberException"

#: Longest exception message kept on a record, matching the PHP recorder's
#: own cap (`BenchRecorderHook.php`, `stopStep`) so that one stack's rows cannot be
#: an order of magnitude larger than another's for the same failure.
MESSAGE_MAX = 4000

#: A fully-qualified Java class name, for reading the type off the first
#: line of `error_message` (`java.lang.AssertionError: expected ...`).
_FQCN = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$")

#: A stack-trace frame, dropped from the message.  cucumber's
#: `error_message` is the whole trace; the frames say where the harness's
#: own JVM was, and they would be most of every failing row's bytes.
_TRACE_FRAME = re.compile(r"^\s+(at\s|\.\.\.\s\d+\smore)")

#: The line the void note is written as, into the run's captured output.
#: Namespaced so that it cannot be confused with anything Maven or cucumber
#: prints, and it goes to stdout rather than into the record because the
#: record has no field for "this document could not be read".
VOID_NOTE = "R2T-CUCUMBER-VOID"


def _message(raw: str | None) -> str:
    """cucumber's `error_message`, minus the stack frames, capped."""
    kept = [line for line in (raw or "").split("\n")
            if not _TRACE_FRAME.match(line)]
    return "\n".join(kept).strip()[:MESSAGE_MAX]


def _exception(raw: str | None, default_class: str) -> dict:
    """`{class, message}` for a step cucumber reported as not passing.

    The class is read off the message's first line when that line names one
    — which is every JVM exception's own `toString()` — and falls back to
    the caller's default otherwise.  A parsed class is a fact about the run;
    the default is a fact about which branch produced the record, and both
    are better than an empty string that reads as "nobody looked".
    """
    message = _message(raw)
    head, sep, _tail = message.split("\n", 1)[0].partition(": ")
    return {"class": head if sep and _FQCN.match(head) else default_class,
            "message": message}


def step_record(entry: dict, keyword: str | None = None) -> dict:
    """One `stacks.base.STEP_FIELDS` object from one cucumber step.

    `keyword` overrides the document's for a HOOK, which has none: cucumber
    writes hooks as bare `{result, match}` objects in the element's `before`
    and `after` arrays, and a hook that did not pass decides the scenario
    exactly as a step does.
    """
    result_block = entry.get("result") or {}
    status = result_block.get("status")
    result = STEP_RESULT_BY_STATUS[status]
    exception = None
    if result in ("failed",):
        exception = _exception(
            result_block.get("error_message"),
            AMBIGUOUS_EXCEPTION if status == "ambiguous"
            else UNTYPED_EXCEPTION)
    return {
        "line": entry.get("line"),
        "keyword": (keyword if keyword is not None
                    else (entry.get("keyword") or "")).strip(),
        # A hook has no name; its `match.location` is the method that ran,
        # which is the only thing a reader could act on.
        "text": entry.get("name") or (entry.get("match") or {}).get(
            "location") or "",
        "result": result,
        # cucumber reports nanoseconds, and omits the field entirely for a
        # step that never ran.
        "seconds": round((result_block.get("duration") or 0) / 1e9, 6),
        "exception": exception,
    }


def _hook_steps(element: dict, key: str) -> list[dict]:
    """The element's `before`/`after` hooks that did NOT pass.

    A passed hook is not part of anything the item was asked to write, and
    putting it on the record would add steps nobody authored to every row.
    A hook that did not pass is the opposite: it decides the scenario (a
    failed `@Before` skips every step after it), and a record that dropped
    it would show a scenario whose steps were all `skipped` with no reason
    anywhere on the row.
    """
    out = []
    for entry in element.get(key) or []:
        status = ((entry.get("result") or {}).get("status"))
        if STEP_RESULT_BY_STATUS.get(status) == "passed":
            continue
        out.append(step_record(entry, keyword=key.capitalize()))
    return out


def _statuses(element: dict, background: dict | None) -> list[str]:
    """Every status the fold is about to read, hooks and background too."""
    seen = []
    for block in (background, element):
        if block is None:
            continue
        for key in ("before", "after"):
            seen += [(e.get("result") or {}).get("status")
                     for e in block.get(key) or []]
        seen += [(s.get("result") or {}).get("status")
                 for s in block.get("steps") or []]
    return seen


def records_from_json(document: list, coverage: dict | None = None,
                      direct_calls: list | None = None,
                      ) -> tuple[list[dict], list[dict]]:
    """`(records, voids)` — cucumber's document as `r2t.record/1` lines.

    One record per SCENARIO element, in document order, with three joins the
    shape of cucumber's JSON forces:

    * **the Background's steps are the scenario's.**  cucumber emits a
      separate `background` element immediately before each scenario that
      has one, holding the steps that ran as part of that scenario.  Folded
      in front of the scenario's own, because a Background step that failed
      is why the rest were skipped, and a record that dropped it would say
      only that nothing ran.
    * **hooks that did not pass are steps** (`_hook_steps`).
    * **`scenario_line` is the element's own line**, which for a
      `Scenario Outline` is the EXAMPLES DATA ROW — cucumber emits one
      element per row and stamps each with the row's line.  That is the
      identity `harness.fold_scenario_records` selects on, and it is why an
      outline scores on every row rather than on its keyword line.

    `voids` is the other half of the answer, and it is not an error list:
    a status this stack has no mapping for means the container's cucumber is
    not the one this stack was written against.  The record for that
    scenario is emitted with NO steps — `record_outcome` reads that as
    `no_steps_ran` and `RunResult.outcome` ranks it ahead of every verdict —
    so the run is voided rather than guessed at, and `execute` writes the
    status and the line into the captured output so the row says which value
    it was.
    """
    records: list[dict] = []
    voids: list[dict] = []
    for feature in document:
        background = None
        for element in feature.get("elements") or []:
            if element.get("type") == "background":
                background = element
                continue
            unknown = [s for s in _statuses(element, background)
                       if s not in STEP_RESULT_BY_STATUS]
            steps: list[dict] = []
            if unknown:
                voids.append({"feature_file": feature.get("uri"),
                              "scenario_line": element.get("line"),
                              "statuses": sorted(set(unknown))})
            else:
                for block in (background, element):
                    if block is None:
                        continue
                    steps += _hook_steps(block, "before")
                    steps += [step_record(s) for s in block.get("steps") or []]
                    steps += _hook_steps(block, "after")
            records.append({
                "feature_file": feature.get("uri"),
                "feature_title": feature.get("name") or "",
                "scenario_title": element.get("name") or "",
                "scenario_line": element.get("line"),
                "suite": "bench",
                "steps": steps,
                # Null when coverage was not requested; `{"files": {},
                # "units": []}` when it was requested and nothing under the
                # project's own source root executed.  Two different
                # findings, and `runner._record` tells them apart by exactly
                # this truthiness.
                "coverage": coverage,
                # The direct-invocation agent's unique (callee, caller) tuples
                # (spec 2.5), one block per fork exactly like `coverage`, and
                # null on the same terms: not collected, as opposed to `[]`,
                # collected and nothing called.
                "direct_calls": direct_calls,
                "seconds": round(sum(s["seconds"] for s in steps), 6),
                # The DOCUMENT's own verdict, summarised from the statuses
                # it wrote.  Recorded, cross-checked against the exit code
                # by `RunResult.outcome`, and never decisive on its own.
                "scenario_result": ("passed" if steps and all(
                    s["result"] == "passed" for s in steps) else "not-passed"),
            })
            background = None
    return records, voids


def scenario_timings_from_json(document: list) -> list[dict]:
    """Diagnostic per-pickle durations, including passed hooks/background.

    `records_from_json` deliberately omits passed hooks from verdict rows;
    timing cannot omit work merely because it passed. This helper sums
    cucumber's raw nanoseconds once per emitted scenario element. It is
    reality-spike diagnostics, not the separately gated N=3 measurement.
    """
    records, voids = records_from_json(document)
    if voids:
        raise CucumberStackRefused(
            "REFUSED: scenario timing input contains an unknown status")
    out: list[dict] = []
    record_index = 0
    for feature in document:
        background = None
        for element in feature.get("elements") or []:
            if element.get("type") == "background":
                background = element
                continue
            nanoseconds = 0
            for block in (background, element):
                if block is None:
                    continue
                entries = ((block.get("before") or [])
                           + (block.get("steps") or [])
                           + (block.get("after") or []))
                for entry in entries:
                    value = (entry.get("result") or {}).get("duration") or 0
                    if isinstance(value, bool) or not isinstance(value, int) \
                            or value < 0:
                        raise CucumberStackRefused(
                            "REFUSED: cucumber duration is not non-negative "
                            "integer nanoseconds")
                    nanoseconds += value
            record = records[record_index]
            record_index += 1
            out.append({
                "feature_file": record["feature_file"],
                "feature_title": record["feature_title"],
                "scenario_title": record["scenario_title"],
                "scenario_line": record["scenario_line"],
                "duration_ns": nanoseconds,
                "seconds": round(nanoseconds / 1e9, 9),
                "scenario_result": record["scenario_result"],
            })
            background = None
    return out


def cmd_interfaces(args) -> int:
    """`interfaces` on a cucumber project: WITHHELD in v1 by owner ruling D4
    (TARGET_INTERFACES_SPEC section 4.4, 2026-09-03), not merely unbuilt.
    Every step-parameter type in the algorand glue is a JDK type, and the
    endpoint under test is selected by a string literal inside one `switch`,
    so a declared-type surface would be identical across whole clusters and
    would misdescribe the setting.  `release` passes no interfaces path for
    this stack; no list is minted and no disclosing profile exists for it."""
    raise CucumberStackRefused(
        "REFUSED: target interfaces are withheld for the cucumber stack in v1 "
        "(TARGET_INTERFACES_SPEC section 4.4, owner ruling D4): the declared "
        "surface of a Java step is JDK types and a string-selected endpoint, "
        "so no per-scenario list can be minted honestly. This is a ruling, "
        "not a pending seam.")


def void_note(voids: list[dict]) -> str:
    """The line `execute` appends to a voided run's captured output."""
    return "\n".join(
        f"{VOID_NOTE}: {v['feature_file']}:{v['scenario_line']} reported "
        f"{v['statuses']}, which is not one of "
        f"{sorted(STEP_RESULT_BY_STATUS)} — the run is voided, not scored."
        for v in voids)


# ------------------------------------------------------------- the workspace
#
# Where the per-item files live, and why each is where it is.

#: The synthesised feature.  Under `src/test/resources`, which is where the
#: retained fixtures and the corpus's own `.feature` files live, because
#: cucumber finds features on the CLASSPATH and Maven copies that tree onto
#: it.  That puts it INSIDE a substrate root, which is the one thing the
#: behave twin did not have to deal with — hence the volatile exemption in
#: `repo.CUCUMBER_SUBSTRATE_VOLATILE`, which names this exact path.
FEATURE_REL = "src/test/resources/_bench_item.feature"

#: ...and how the invocation names it.  A classpath URI rather than a path,
#: because the surefire fork's working directory is a per-project quirk
#: (epubcheck runs its tests from `target/test-classes`) and a relative path
#: would be resolved against it, while the classpath root is the same tree
#: whichever directory the JVM was started in.
FEATURE_CLASSPATH = "classpath:_bench_item.feature"

#: Maven's `testOutputDirectory` — where `process-test-resources` copies the
#: synthesised feature.  Swept per item with the source copy: leaving the
#: PREVIOUS item's scenario on the classpath is the residue that makes an
#: item pass on a feature nobody asked for.
TEST_OUTPUT_DIR = "target/test-classes"
FEATURE_COPY_REL = f"{TEST_OUTPUT_DIR}/_bench_item.feature"

#: The test sources root both corpora use, for reading a written file's
#: class name back out of its path.
JAVA_TEST_ROOT = "src/test/java"

#: The Maven repository the image bakes (`mvn dependency:go-offline` at
#: build time, plan §B3 J3).  Passed EXPLICITLY on every invocation rather
#: than left to the image's `settings.xml`, for the reason the behave stack
#: sets `PYTHONDONTWRITEBYTECODE` at the exec even though the image bakes
#: it: a container someone started by hand must not resolve differently from
#: one the worker plan started, and `-o` turns a repository that is not
#: there into a resolution failure rather than a download.
MAVEN_LOCAL_REPO = "/opt/m2"

#: The project's own sources, and the only tree a unit of coverage may name.
#: Both corpora are single-module Maven builds with Java under this root, so
#: `<package name="com/adobe/epubcheck/api">` plus `<sourcefile name="X.java">`
#: is `src/main/java/com/adobe/epubcheck/api/X.java` — see `coverage_doc`.
SOURCE_ROOT = "src/main/java"

#: JaCoCo's two outputs.  Both under `target/`: a BUILD root, so they sit
#: under no substrate root and are swept per item with everything else the
#: run leaves behind.
JACOCO_EXEC_REL = "target/jacoco.exec"
JACOCO_XML_REL = "target/site/jacoco/jacoco.xml"

#: The direct-invocation agent (`API_DIRECT_INVOCATION_SPEC.md` 2.4), as the
#: fork is told to find it INSIDE the container: the path worker provisioning
#: binds the jar to read-only (`worker provision --direct-call-agent-jar`),
#: owned by the collector module so the two cannot drift apart.  Its output
#: is `direct_calls.OUTPUT_REL`, under `target/` beside JaCoCo's two.
AGENT_JAR_RUNTIME = _dc.AGENT_JAR_RUNTIME

#: How long the compile gate may take.  Candidate test classes are rebuilt
#: from source for every item; production classes and Maven's dependency
#: repository remain warm.
COMPILE_TIMEOUT = 900

#: stdout substrings that mean "the environment failed before the test could
#: run" — `container_error`, not a verdict about the generated test.  They
#: are consulted ONLY when no record matched (`RunResult.outcome`), so a
#: failing step whose output happens to contain one cannot be misread.
#:
#: Every entry is Maven's or the JVM's own framing of a fault in the image
#: or the invocation, and the two obvious candidates that are NOT here are
#: the reason the list is short:
#:
#:   * `The forked VM terminated without properly saying goodbye` is what a
#:     step definition calling `System.exit` produces, and that is the
#:     SUBMISSION's doing.  Calling it a container error would excuse
#:     exactly the trick the plan's ninth gate claim exists to catch.
#:   * `CucumberException` covers "failed to instantiate glue class", i.e. a
#:     constructor the submission wrote throwing — also its doing.
CUCUMBER_ERROR_MARKERS = (
    # `-o` and a repository that does not hold the pinned dependencies.
    "Could not resolve dependencies",
    "Non-resolvable parent POM",
    "The repository system is offline",
    # Maven 3.9.6's plugin-resolution path uses neither sentence above.  Its
    # actual diagnostic is "Plugin ... or one of its dependencies could not
    # be resolved: ... Cannot access central (...) in offline mode".  Keep
    # both lower-case fragments: either half can be the only surviving line
    # after Maven/BuildKit framing, and both describe the image rather than
    # the generated test.
    "could not be resolved",
    "in offline mode",
    # A broken `argLine` (the JaCoCo recipe's failure mode) reaches the JVM,
    # not the test.
    "Could not create the Java Virtual Machine",
    "Unrecognized option:",
    # ...and so does a `-javaagent` the JVM cannot open: a worker whose
    # container lacks the direct-invocation agent jar at `AGENT_JAR_RUNTIME`
    # is the environment's fault, and every item would otherwise read
    # `no_scenario_ran`.
    "Error opening zip file or JAR manifest missing",
    "agent library failed to init",
    # A JRE where the image should have baked a JDK.
    "No compiler is provided in this environment",
    # A goal or a phase that does not exist: the invocation is wrong, and
    # nothing about the item was measured.
    "Unknown lifecycle phase",
)


# ------------------------------------------------------------ the invocation
#
# Command CONSTRUCTION only.  Execution stays behind the harness's runner
# seam exactly as the behave stack keeps it, so that these bytes can be
# pinned by a selftest with no container anywhere near it.


def _mvn(goal: str, quirks: ProjectQuirks | None = None) -> list[str]:
    """The prefix every invocation shares.

    `-o` is the offline pin (the image bakes the repository; a run that
    reached the network would be measuring a different dependency set), and
    `-B` is batch mode — no ANSI, no interactivity, the JVM twin of behat's
    `--no-interaction --no-colors`.
    """
    argv = ["mvn", "-o", "-B", f"-Dmaven.repo.local={MAVEN_LOCAL_REPO}"]
    if quirks is not None and quirks.module_rel:
        argv += ["-Dcheckstyle.skip=true", "-Dmaven.buildNumber.skip=true",
                 "-pl", quirks.module_rel]
    return argv + [goal]


def compile_command(quirks: ProjectQuirks) -> str:
    """`mvn -o test-compile` — the syntax gate, in the image's own javac.

    The question "does this compile" is a question about the toolchain that
    will execute it, and the two corpora do not even agree on which JDK that
    is (`ProjectQuirks.jdk_major`).  A non-empty error map routes the run to
    `parse_or_compile_error` through the same `runner._record` branch both
    other stacks use.
    """
    if quirks.module_rel:
        # Step definitions are dependency JARs in Kapua. Replacing their
        # source is insufficient: install the selected reactor's rebuilt
        # dependencies before testing just its own module.
        return " ".join(_mvn("install", quirks)
                        + ["-am", "-DskipTests", "-Djacoco.skip=true"])
    return " ".join(_mvn("test-compile", quirks))


def test_command(quirks: ProjectQuirks, scenario_title: str,
                 coverage: bool = False, *,
                 agent_argline: str | None = None) -> str:
    """`mvn -o test` for ONE scenario, as this project must spell it.

    `-Dcucumber.plugin` appears NOWHERE, by construction: the JSON plugin is
    declared by the harness-owned runner class, so no invocation can collide
    with a project runner that already holds STDOUT.

    `-DfailIfNoTests=false` is deliberately absent too.  A `-Dtest` that
    matched nothing is a harness fault — the wrong selector for this
    project's surefire — and the loud version of it is a failed build, not
    a green one with no records that reads as `no_scenario_ran` a hundred
    times before anybody looks.

    Coverage is a SWITCH rather than a goal: the strip put the JaCoCo agent
    in the pom, so an uninstrumented run is the one that has to say so
    (`-Djacoco.skip=true`).  Doing it the other way round — adding
    `jacoco:prepare-agent` to the goal list when coverage is wanted — would
    put the agent in a run whose `argLine` was never prepared for it, which
    is the failure `pom_with_coverage` documents.

    The direct-invocation agent is the second switch, and it is ONLY thrown
    on a coverage invocation (spec 2.4): `agent_argline` -- the
    `-javaagent:<jar>=<output>` option `direct_calls.agent_option` spells --
    is passed as `-Dr2t.agent.argline=...`, the property the strip wrote
    beside JaCoCo's token in surefire's argLine, so an in-trajectory trial
    attaches neither agent and pays for neither.  Maven's own interpolation
    resolves `${r2t.agent.argline}` when it evaluates the plugin parameter,
    and a `-D` user property outranks the pom's empty project property, which
    is why the switch works from the command line; without it the property
    resolves to that empty default and the invocation is byte-for-byte the
    one this stack has always issued.
    """
    argv = _mvn("test", quirks) + [
        f"-Djacoco.skip={'false' if coverage else 'true'}",
        f"-Dtest={quirks.test_selector}",
        f"-Dcucumber.features={FEATURE_CLASSPATH}",
        # The corpus's own `cucumber.properties` is `removable_config` and
        # the strip moves it to gold, so the setting it carried is set here
        # instead: quiet means the run neither prints the publish banner nor
        # tries to reach the reporting service from a no-egress network.
        "-Dcucumber.publish.quiet=true"]
    if coverage and agent_argline:
        # One unquoted JVM argument through a Maven `-D` and Maven's property
        # interpolation: `agent_option` refuses a path with whitespace in it.
        argv.append(shlex.quote(f"-D{AGENT_ARG_LINE_PROPERTY}={agent_argline}"))
    if quirks.select_by_name:
        argv.append(shlex.quote(
            f"-Dcucumber.filter.name={filter_name_regex(scenario_title)}"))
    return " ".join(argv)


SUITE_CAPTURE_PREFIX: tuple[str, ...] = (
    "mvn", "--offline", "--no-transfer-progress", "-Dstyle.color=never",
    f"-Dmaven.repo.local={MAVEN_LOCAL_REPO}", "-DreuseForks=false",
    "-DfailIfNoTests=true", "-Dsurefire.failIfNoSpecifiedTests=true")


def kapua_report_command(quirks: ProjectQuirks, workdir: str) -> str:
    """Report each selected dependency module against the one test fork's exec."""
    if not quirks.module_rel:
        raise CucumberStackRefused("Kapua reporting requires a selected module")
    data_file = (workdir.rstrip("/") + "/" + quirks.module_rel
                 + "/" + JACOCO_EXEC_REL)
    return shlex.join(_mvn("org.jacoco:jacoco-maven-plugin:0.8.8:report", quirks)
                      + ["-am", "-Djacoco.skip=false",
                         "-Djacoco.dataFile=" + data_file])


def suite_capture_argv(project: str, *, dry_run: bool = False,
                       source_feature: str | None = None) -> tuple[str, ...]:
    """Exact offline native-suite argv for EPUBCheck or one Kapua suite.

    Kapua requires an admitted source feature to select its module and original
    runner. Dependencies must already be installed in the prepared workspace.
    The JSON path is module-relative; callers preserve each runner's raw file
    separately through ``kapua.capture_path``. This command neither strips a
    workspace nor qualifies it as a reality transcript. Algorand retains its
    separate reviewed command binding.
    """
    quirks_for(project)
    if project == "kapua":
        suite = _kapua.FEATURE_SUITES.get(source_feature)
        if suite is None:
            raise CucumberStackRefused(
                "REFUSED: Kapua suite capture needs an admitted source feature")
        quirks = quirks_for(project, source_feature)
        plugin = "target/r2t-cucumber-dry-run.json" if dry_run else "target/r2t-cucumber.json"
        return tuple(_mvn("test", quirks)[:-1]) + (
            "-Dtest=" + suite.runner_package + "." + suite.upstream_runner_class,
            "-Dcucumber.filter.tags=@env_none and not (@env_docker or @env_docker_base)",
            "-Dcucumber.publish.quiet=true", "-Djacoco.skip=true",
            "-DfailIfNoTests=true", "-Dcucumber.execution.dry-run=" + str(dry_run).lower(),
            "-Dcucumber.plugin=json:" + plugin, "test")
    if project != "epubcheck":
        raise CucumberStackRefused(
            "REFUSED: the reviewed suite-capture argv is EPUBCheck-only; "
            "Algorand needs its own separately reviewed capture binding")
    plugin = ("../r2t-cucumber-dry-run.json" if dry_run
              else "../r2t-cucumber.json")
    argv = SUITE_CAPTURE_PREFIX
    if dry_run:
        argv += ("-Djacoco.skip=true", "-Dtest=RunCucumberTest",
                 "-Dcucumber.execution.dry-run=true")
    return argv + (f"-Dcucumber.plugin=json:{plugin}",
                   "-Dcucumber.publish.quiet=true", "test")


#: A javac diagnostic as Maven prints it:
#: `[ERROR] /work/src/test/java/.../Steps.java:[12,5] cannot find symbol`.
_JAVAC_ERROR = re.compile(
    r"^\[ERROR\]\s+(?P<path>/\S+\.java):\[(?P<line>\d+),(?P<col>\d+)\]\s*"
    r"(?P<message>.*)$", re.M)


def compile_errors(output: str, workdir: str) -> dict:
    """`{repo-relative path: first diagnostic}` from a Maven build log.

    FIRST, not all: one missing import produces a diagnostic per use, and a
    row carrying thirty of them says nothing the first one does not.  Paths
    come back workspace-relative because that is the vocabulary every other
    field on the row uses; a path outside the workspace is kept verbatim
    rather than mangled into one, because a compile error in a file the
    harness cannot locate is a finding of its own.
    """
    prefix = workdir.rstrip("/") + "/"
    errors: dict[str, str] = {}
    for match in _JAVAC_ERROR.finditer(output):
        path = match.group("path")
        rel = path[len(prefix):] if path.startswith(prefix) else path
        errors.setdefault(rel, f"{match.group('line')}:"
                               f"{match.group('col')} "
                               f"{match.group('message')}")
    return errors


def class_name(rel: str, project: str | None = None) -> str:
    """`src/test/java/org/w3c/epubcheck/test/S.java` -> `org...test.S`.

    This stack's honest reading of "registered contexts": cucumber-jvm scans
    the runner's package for annotated methods, so what a submission
    registered is the classes it wrote there.  A path outside the test
    source root comes back unchanged — visible on the row rather than
    dropped, since `install_solution` accepted it and something has to say
    where it went.
    """
    roots = (_kapua.TEST_SOURCE_ROOTS if project == "kapua"
             else (JAVA_TEST_ROOT,))
    if rel.endswith(".java"):
        for root in roots:
            if rel.startswith(root + "/"):
                return rel[len(root) + 1:-len(".java")].replace("/", ".")
    return rel


# ---------------------------------------------------------------- the harness
#: `CucumberHarness(agent_jar=...)` left unsaid: the project's own answer,
#: `ProjectQuirks.direct_call_agent`.  A sentinel and not None, because None
#: already means something -- a coverage run WITHOUT the agent, the section 8
#: comparison leg -- and the two have to stay tellable apart.
PROJECT_AGENT_JAR = object()


class CucumberHarness:
    """One cucumber workspace: install, synthesise, compile, execute, verify.

    NOT a subclass of `harness.Harness`, for the reason `BehaveHarness` is
    not: four of that class's methods are Symfony (registration vetting, DI
    aliasing, container invalidation, the services file) and inheriting them
    would hand this stack a `vet_fragment` that silently accepts anything.
    What IS the same is ASSIGNED, not copied — the class attributes below
    are the PHP harness's own function objects, held to identity by the
    selftest through `CLASS_MEMBERS`, which is also CLOSED over them: a
    fourth assignment from that class has to declare itself there or fail a
    check.  So a fix to either is a fix to both, and that stays true.
    """

    #: Same path arithmetic, same escape refusal.
    _abs = _hz.Harness._abs

    #: Same acceptance rule.  Nothing in it is PHP: boundary classification,
    #: the `.feature` refusal for `criterion_to_test`, the path-escape
    #: refusal.  Two implementations of "where may a solution write" would
    #: be two chances to disagree about the answer space — and for this
    #: corpus the answer space is the boundary's removable Java packages,
    #: whose broadest member is the profile's `submission.acceptance_root`
    #: (`src/test/java/org/w3c/epubcheck/test/`).
    install_solution = _hz.Harness.install_solution

    #: Same integrity check (it reads the MANIFEST's roots — recorded by the
    #: cucumber strip as the cucumber roots) and same raise-on-mismatch.
    verify_substrate = _hz.Harness.verify_substrate

    def __init__(self, manifest: _repo.StripManifest, boundary, runner, *,
                 agent_jar: str | None | object = PROJECT_AGENT_JAR):
        root = os.path.abspath(manifest.repo_root)
        if os.path.abspath(boundary.repo_root) != root:
            # The H1 refusal: one workspace per harness.  `--repo` reached
            # only the boundary once, and the harness then classified
            # against one worker and wrote into another.
            raise CucumberStackRefused(
                f"the boundary classifies against {boundary.repo_root} while "
                f"the manifest writes into {manifest.repo_root}. One "
                f"workspace per harness: pass --repo, which sets both.")
        if not manifest.build_roots:
            # A Java manifest that declares no build roots was not written
            # by `strip_repo_cucumber`, which means `target/` was never
            # purged — and `target/test-classes/**/*.class` is the removed
            # glue with its Cucumber Expressions intact in the constant
            # pool.  The common way to get here is pointing --gold at
            # another stack's gold tree.
            raise CucumberStackRefused(
                "this manifest declares no build_roots, so it was not "
                "written by strip_repo_cucumber — most likely --gold points "
                "at another stack's gold tree. A cucumber workspace run "
                "under it still holds a compiled copy of the answer, which "
                "an agent that can list its own workspace does not have to "
                "be clever to read.")
        self.man = manifest
        self.boundary = boundary
        self.runner = runner
        self.root = root
        #: Refuses an unknown project HERE, before anything runs, rather
        #: than at the first `execute` with the wrong JSON path.
        self.quirks = quirks_for(boundary.project)
        # A saved seed baseline can be internally valid but carry runners
        # generated by an older harness. Refuse before any candidate work.
        if boundary.project == "kapua":
            verify_runner_sources(root, boundary.project)
        #: The scenario `write_feature` last wrote, for the projects whose
        #: invocation also filters by name.  State on the harness because
        #: the `StackRunner.execute` signature is fixed and the title is not
        #: one of its arguments; `execute` refuses when it is missing rather
        #: than running the previous item's filter.
        self._scenario_title: str | None = None
        #: `rel -> sha256` for production files a MUTATION campaign has
        #: deliberately edited (J6's seam, same shape as both other
        #: harnesses').
        self.expected_mutations: dict = {}
        #: The direct-invocation agent jar inside the container, or None for
        #: a coverage run WITHOUT it.  Left unsaid it is the project's answer:
        #: `AGENT_JAR_RUNTIME` where `quirks.direct_call_agent` says the fork
        #: can load the agent (algorand), None where it cannot (epubcheck's
        #: JDK 8), whose coverage invocation then stays the one this stack has
        #: always issued.  None passed by name is the section 8 comparison
        #: leg, which needs the same scenario's `coverage_lines` with and
        #: without the agent in the argument line.  Neither None is a
        #: fallback: the fork then writes no file and the record reads
        #: `direct_calls: null`.
        if agent_jar is PROJECT_AGENT_JAR:
            agent_jar = (AGENT_JAR_RUNTIME if self.quirks.direct_call_agent
                         else None)
        self.agent_jar = agent_jar

    @property
    def workdir_root(self) -> str:
        return self.runner.workdir

    # --------------------------------------------------------- housekeeping
    def _remove(self, rels) -> list[str]:
        removed = []
        for rel in rels:
            path = self._abs(rel)
            if os.path.exists(path):
                os.remove(path)
                removed.append(rel)
        return removed

    def _remove_outputs(self) -> list[str]:
        """What the LAST run left behind, gone before the next one starts.

        Maven's main build output is not purged between items — the whole
        point of the J0 timing probe is that warm production classes make a
        per-scenario run affordable.  Candidate `target/test-classes` is
        separately removed before every compile.  The previous item's copied
        feature and JSON document are still sitting there when the next item
        runs.
        A stale document is the previous item's verdict for a run that wrote
        none; a stale copy of the feature is the previous item's SCENARIO,
        still on the classpath.  Maven's `process-test-resources` puts the
        current one back from `src/test/resources` at the start of the run,
        so removing the copy costs nothing and closes that door.

        The synthesised feature itself is NOT here: `execute` calls this,
        and a sweep that deleted the feature it was about to run would
        report `no_scenario_ran` for every item.

        The direct-invocation agent's file is here for the reason JaCoCo's
        two are: the sweep is this list and not the directory (`target/classes`
        is deliberately kept warm), and an unswept file would make a fork
        that wrote no events report the previous item's calls as this
        item's (spec 2.4).
        """
        if self.boundary.project == "kapua":
            # KapuaLiquibaseClient.loadChangelogs leaves this directory in
            # the private worker JVM's measured java.io.tmpdir. Reusing it
            # changes production line coverage between otherwise equal runs.
            reset = self.runner.run("rm -rf -- /tmp/kapua-liquibase", timeout=60)
            if reset.returncode:
                raise CucumberStackRefused("could not reset Kapua Liquibase temporary state")
        return self._remove(self._output_paths())

    def _output_paths(self) -> list[str]:
        """Host-visible run outputs; inventory only, with no runtime reset."""
        if self.boundary.project == "kapua":
            module_outputs = [module + "/" + rel
                              for module in _kapua.TEST_MODULES
                              for rel in (FEATURE_COPY_REL, JACOCO_EXEC_REL,
                                          JACOCO_XML_REL,
                                          "target/r2t-cucumber.json")]
            # Production reports are emitted in dependency modules, too.
            # Clearing only test modules would reuse an earlier item's XML.
            reports = [(module + "/" if module != "." else "")
                       + JACOCO_XML_REL for module in _kapua.MODULES]
            surefire = [suite.module + "/target/surefire-reports/TEST-"
                        + suite.runner_package + ".R2TBench" + suite.upstream_runner_class + ".xml"
                        for suite in _kapua.SUITES + _kapua.DIAGNOSTIC_SUITES]
            return module_outputs + reports + surefire + [JACOCO_EXEC_REL,
                                                          _dc.OUTPUT_REL,
                                                          _hz.RECORD_REL]
        return [FEATURE_COPY_REL, self.quirks.json_rel, JACOCO_EXEC_REL,
                JACOCO_XML_REL, _dc.OUTPUT_REL, _hz.RECORD_REL]

    def _remove_run_files(self) -> list[str]:
        """The outputs AND the synthesised feature — the whole per-item set.

        For the two moments where nothing of this item may remain: before a
        system generates (the previous scenario sitting in the workspace is
        something an agent that reads it can see) and after the sweep.
        """
        features = (_kapua.FEATURE_PATHS if self.boundary.project == "kapua"
                    else (FEATURE_REL,))
        return self._remove(features) + self._remove_outputs()

    def _remove_compiled_candidate_glue(self) -> None:
        """Drop all prior candidate test bytecode before the next compile."""
        outputs = [TEST_OUTPUT_DIR]
        if self.boundary.project == "kapua":
            outputs = [root.removesuffix("/src/main/java") + "/target"
                       for root in _kapua.STEP_SOURCE_ROOTS]
            outputs += [module + "/" + TEST_OUTPUT_DIR
                        for module in _kapua.TEST_MODULES]
            outputs += [MAVEN_LOCAL_REPO + "/org/eclipse/kapua/" + artifact
                        for artifact in _kapua.STEP_ARTIFACTS]
        command = "rm -rf -- " + " ".join(shlex.quote(path) for path in outputs)
        completed = self.runner.run(command, timeout=60)
        if completed.returncode != 0:
            raise CucumberStackRefused(
                "could not remove the previous candidate's compiled glue: "
                + ((completed.stderr or completed.stdout or "")[-500:]))
        if any(os.path.lexists(self._abs(path)) for path in outputs
               if not os.path.isabs(path)):
            raise CucumberStackRefused(
                "compiled candidate test output survived cleanup")

    def prepare_for_generation(self) -> None:
        """Everything that must be gone BEFORE a system generates.

        This preparation removes generated run files.  After the candidate
        source is installed, `run_solution` removes exactly
        `target/test-classes` before compiling it, so no prior candidate glue
        survives.  It deliberately keeps `target/classes` and Maven's
        dependency repository warm.
        """
        _repo.clean_workspace(self.man, self.boundary)
        self._remove_run_files()
        self.verify_substrate()

    def clear_registration(self) -> None:
        """End-of-sweep tidy-up, same contract as both other harnesses'.

        cucumber has no registration file — glue is discovered by scanning —
        so what this stack leaves behind is the synthesised feature and the
        last run's output, and "leave the workspace as we found it" is the
        same rule either way.
        """
        self._remove_run_files()

    # ---------------------------------------------------------------- suite
    def write_feature(self, feature, scenario, override=None):
        """The one scenario that will run, at `FEATURE_REL`.

        Same synthesis and the SAME line arithmetic as both other harnesses:
        the expected lines are derived from the file we WRITE (the
        standalone file re-headers and inlines nothing — it copies the
        Background as its own block — so every line moves), and
        `Harness._example_row_lines` is called rather than re-implemented,
        because the Examples-row derivation is the fold's other half and two
        copies of it would be two chances to disagree about which rows an
        outline may claim.
        """
        source_rel = os.path.relpath(
            os.path.abspath(feature.path), self.root).replace(os.sep, "/")
        self.quirks = quirks_for(self.boundary.project, source_rel)
        text = override if override is not None else standalone_feature(
            feature, scenario, prerequisite_tag=self.quirks.prerequisite_tag,
            allow_tag_gaps=self.boundary.project == "kapua")
        path = self._abs(os.path.join(self.quirks.module_rel, FEATURE_REL))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        lines = [i for i, ln in enumerate(text.split("\n"), 1)
                 if _hz._SCENARIO_LINE.match(ln)]
        expected_line = lines[-1] if lines else None
        expected_lines = None
        if expected_line is not None:
            expected_lines = [expected_line] + _hz.Harness._example_row_lines(
                text, expected_line)
        # The TITLE as the file we just wrote spells it, not as the
        # repository spells it: for `requirement_to_test` the feature is the
        # system's own, and a filter built from the repository's scenario
        # would then select nothing.
        self._scenario_title = (
            text.split("\n")[expected_line - 1].split(":", 1)[1].strip()
            if expected_line is not None else None)
        return text, expected_line, expected_lines

    # ------------------------------------------------------------- indexing
    def index_paths(self, rel_paths: list) -> dict:
        """The syntax gate: `mvn -o test-compile`, in the container.

        `files` comes back empty on purpose.  The PHP stack's index is what
        `write_registration` reads and the behave stack's is a compile
        check; here the static index of a Java tree is J4's (`closure_java`,
        from cucumber's own registry rather than a regex), and inventing a
        half of one here would be a second answer to a question that
        milestone is about to answer properly.  What this returns is the
        thing `runner._record` actually reads: `errors`.
        """
        if not rel_paths and self.boundary.project != "kapua":
            return {"root": self.workdir_root, "files": {}, "errors": {}}
        # Even an empty Kapua candidate needs freshly installed empty step
        # artifacts after the previous answer's compiled copies were purged.
        cp = self.runner.run(compile_command(self.quirks),
                             timeout=COMPILE_TIMEOUT)
        output = (cp.stdout or "") + (cp.stderr or "")
        errors = compile_errors(output, self.workdir_root)
        if cp.returncode != 0 and not errors:
            # The build failed for something that is not a diagnostic — a
            # missing dependency, a plugin fault.  Reported in the same
            # shape the PHP analyzer's own faults are, so the row reads
            # `parse_or_compile_error` with the reason attached rather than
            # the sweep dying on one item.
            errors = {"compiler": output[-2000:]}
        return {"root": self.workdir_root, "files": {}, "errors": errors}

    # ------------------------------------------------------------ execution
    def _document(self) -> list:
        """cucumber's JSON for the run that just finished, or nothing.

        Absent means the run never reached the formatter — the build failed,
        the fork died, the selector matched no test — and an empty document
        is the honest input for that: no records, so `RunResult.outcome`
        consults the error markers and answers `container_error` or
        `no_scenario_ran`.
        """
        path = self._abs(self.quirks.json_rel)
        if not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return json.loads(fh.read())

    def _coverage(self) -> dict | None:
        """This run's coverage block, or None when nothing measured it.

        None rather than an empty block when the report is absent, and the
        distinction is the whole reason `runner._record` looks at
        truthiness: a JaCoCo that did not run and a JaCoCo that ran over a
        scenario touching no production line are different findings, and
        reporting the first as the second is a zero nobody would question.

        What IS per-scenario about it: the item is one scenario in one
        forked JVM over a `jacoco.exec` this harness deleted before the run.
        For an OUTLINE the fork covers every Examples row together, so the
        same block is attached to each row's record — the truthful reading,
        since JaCoCo dumps once per JVM and nothing in the file says which
        row reached which line.
        """
        if self.boundary.project == "kapua":
            return kapua_coverage_doc(self.root, self.boundary)
        path = self._abs(JACOCO_XML_REL)
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return coverage_doc(fh.read(), self.root)

    def _agent_argline(self) -> str | None:
        """The `-javaagent` option for this worker, or None without a jar."""
        if self.agent_jar is None:
            return None
        option = _dc.agent_option(self.agent_jar,
                                  self.runner.workdir.rstrip("/") + "/"
                                  + _dc.OUTPUT_REL)
        if self.boundary.project == "kapua":
            from ..java.kapua import code_source_map
            relative = "target/r2t-code-sources.tsv"
            path = self._abs(relative)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            try:
                mapping = code_source_map(self.root, self.boundary,
                                          workdir=self.runner.workdir)
            except (OSError, ValueError) as exc:
                raise CucumberStackRefused(f"Kapua code-source mapping: {exc}") from exc
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(mapping)
            option += " -Dr2t.code.sources=" + self.runner.workdir.rstrip("/") + "/" + relative
        return option

    def _direct_calls(self) -> list | None:
        """This run's `direct_calls` (spec 2.5), or None when no agent wrote them.

        The same None-versus-empty distinction as `_coverage`, drawn from the
        same evidence: the agent writes its file from a shutdown hook even
        when it recorded nothing, so `[]` means the fork ran the agent and the
        scenario activated no production method, and a missing file means no
        agent ran -- a fork killed at the timeout, a workspace whose pom never
        carried the hook, a project whose fork cannot load the agent
        (`ProjectQuirks.direct_call_agent`), a harness constructed with
        `agent_jar=None`.  One block per fork, attached to every record, for
        the reason the coverage block is: the agent dumps once per JVM, so an
        outline's rows share it.
        """
        events = _dc.read_direct_calls(self._abs(_dc.OUTPUT_REL))
        if events is not None and self.boundary.project == "kapua":
            import xml.etree.ElementTree as ET
            suite = next(s for s in _kapua.SUITES + _kapua.DIAGNOSTIC_SUITES
                         if s.module == self.quirks.module_rel
                         and s.runner_package == self.quirks.runner_package)
            report = self._abs(suite.module + "/target/surefire-reports/TEST-"
                               + self.quirks.test_selector + ".xml")
            try:
                properties = {p.get("name"): p.get("value")
                              for p in ET.parse(report).getroot().iter("property")}
                classpath = properties["java.class.path"]
                if properties.get("surefire.test.class.path") != classpath:
                    raise ValueError("Surefire and JVM classpaths differ")
                with open(self._abs("target/r2t-code-sources.tsv"), encoding="utf-8") as handle:
                    _kapua.verify_code_source_classpath(
                        self.root, suite, classpath, handle.read(), workdir=self.runner.workdir)
            except (OSError, KeyError, ValueError, ET.ParseError) as exc:
                raise CucumberStackRefused(
                    f"Kapua direct calls lack their measured suite classpath: {exc}") from exc
        return events

    def _write_records(self, records: list) -> None:
        """The folded records, where every stack keeps them.

        This stack's file is an OUTPUT rather than an input: behat's and
        behave's recorders write theirs from inside the container and the
        harness reads them back, while here the harness writes it after
        folding cucumber's document on the host.  It is written anyway, at
        the same path, because it is what an operator inspecting a kept
        workspace, and `--keep-artifacts`, go looking for — and because
        `repo.CUCUMBER_SUBSTRATE_VOLATILE` exempts that path, and an
        exemption for a file nothing writes is a hole in the tampering
        check with nothing on the other side of it.
        """
        path = self._abs(_hz.RECORD_REL)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")

    def execute(self, coverage: bool = False, timeout: int = 600,
                expected_line=None, expected_lines=None) -> _hz.RunResult:
        if self.quirks.select_by_name and self._scenario_title is None:
            raise CucumberStackRefused(
                f"{self.boundary.project} selects its scenario by name, and "
                f"no feature has been written in this workspace yet. "
                f"`write_feature` is what learns the title; executing before "
                f"it would filter on the PREVIOUS item's scenario.")
        self._remove_outputs()
        command = test_command(
            self.quirks, self._scenario_title or "", coverage=coverage,
            agent_argline=self._agent_argline() if coverage else None)
        # Outside the bind mount on purpose (`_bench/` is a substrate root);
        # the shared counter distinguishes concurrent executions in one
        # process whichever stack they belong to.
        pid_file = (f"/tmp/r2t-cucumber-{os.getpid()}-"
                    f"{next(_hz._EXEC_SEQ)}.pid")
        started = time.time()
        timed_out = False
        cleanup = None
        kapua_report_complete = False
        try:
            cp = self.runner.run(
                f"printf '%s' $$ > {shlex.quote(pid_file)} && "
                f"exec {command}", timeout=timeout)
            code, out = cp.returncode, (cp.stdout or "") + (cp.stderr or "")
            if coverage and self.boundary.project == "kapua" and os.path.isfile(
                    self._abs(self.quirks.module_rel + "/" + JACOCO_EXEC_REL)):
                # Native JaCoCo reports at prepare-package, after test. Keep
                # its explicit report phase inside this item's existing budget
                # and retain the test exit code even if reporting succeeds.
                remaining = timeout - (time.time() - started)
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout, output=out)
                report_command = kapua_report_command(
                    self.quirks, self.runner.workdir)
                try:
                    report = self.runner.run(
                        f"printf '%s' $$ > {shlex.quote(pid_file)} && "
                        f"exec {report_command}", timeout=remaining)
                except subprocess.TimeoutExpired as error:
                    tail = error.stdout or ""
                    if isinstance(tail, bytes):
                        tail = tail.decode("utf-8", "replace")
                    raise subprocess.TimeoutExpired(
                        error.cmd, error.timeout, output=out + tail) from error
                out += (report.stdout or "") + (report.stderr or "")
                if report.returncode:
                    self.runner.run(f"rm -f {shlex.quote(pid_file)}", timeout=60)
                    # Existing scenario records take precedence over environment
                    # markers in the fold. Refuse before issuing a result with
                    # partial coverage from a failed report invocation.
                    raise CucumberStackRefused(
                        f"Kapua coverage report failed (test exit {code}, "
                        f"report exit {report.returncode}): " + out[-2000:])
                kapua_report_complete = True
        except subprocess.TimeoutExpired as e:
            timed_out = True
            # `docker exec` without a TTY does not forward the kill into the
            # container; the shared tree-killer walks the recorded pid's
            # whole subtree — which for Maven means the surefire fork as
            # well as `mvn` itself — and reports whether anything survived.
            cleanup = _hz._kill_process_tree(self.runner, pid_file)
            code = -1
            out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(
                e.stdout, bytes) else (e.stdout or "")
        wall = time.time() - started
        if not timed_out:
            self.runner.run(f"rm -f {shlex.quote(pid_file)}", timeout=60)

        # A timed-out reactor may have emitted only some module reports, or
        # stopped halfway through an XML file. Neither is complete coverage.
        collect_coverage = coverage and (self.boundary.project != "kapua"
                                        or kapua_report_complete)
        try:
            document = self._document()
        except ValueError as exc:
            # cucumber's json plugin creates its report when the run starts
            # and writes it only when the run finishes, so a fork killed at
            # the timeout leaves it empty or cut short.  That run is scored
            # `timeout` whatever it recorded (`RunResult.outcome`), so the
            # unreadable report yields no records instead of failing the
            # slice.  A run that finished with an unreadable report still
            # raises: nothing explains that one.
            if not timed_out:
                raise
            document = []
            out += (f"\n[r2t] cucumber report {self.quirks.json_rel} "
                    f"unreadable after the timeout kill: {exc}")
        records, voids = records_from_json(
            document, coverage=self._coverage() if collect_coverage else None,
            direct_calls=self._direct_calls() if collect_coverage else None)
        if voids:
            # Into the captured output, which is what reaches the row as
            # `stdout_tail`: the record has no field for "this document
            # could not be read", and a void nobody can see on the row is a
            # void nobody will investigate.
            out = out + "\n" + void_note(voids)
        self._write_records(records)
        return _hz.RunResult(exit_code=code, stdout=out, wall_seconds=wall,
                             records=records, timed_out=timed_out,
                             expected_line=expected_line,
                             timeout_cleanup=cleanup,
                             expected_lines=expected_lines,
                             # This stack's environment-failure vocabulary;
                             # None would mean Symfony's (`_DI_MARKERS`).
                             error_markers=CUCUMBER_ERROR_MARKERS)

    # --------------------------------------------------------------- driver
    def run_solution(self, feature, scenario, solution: _hz.Solution,
                     coverage: bool = False, timeout: int = 600,
                     repeats: int = 1, task: str = "criterion_to_test",
                     keep_stdout: bool = False) -> dict:
        # Integrity at the execution boundary, before AND after — the same
        # two checks, for the same reasons, as both other harnesses: before,
        # RAISE, because a tree already wrong makes nothing attributable;
        # after, REPORT, because raising would discard the evidence of what
        # the submission did, and `runner._record` turns the report into
        # `substrate_violation` so the row can never read as a pass.
        source_rel = os.path.relpath(
            os.path.abspath(feature.path), self.root).replace(os.sep, "/")
        selected_quirks = quirks_for(self.boundary.project, source_rel)
        self.verify_substrate()
        _repo.clean_workspace(self.man, self.boundary)
        self._remove_run_files()
        self.quirks = selected_quirks
        written, rejected = self.install_solution(solution, task=task)
        if solution.services_fragment:
            # cucumber-picocontainer instantiates every glue class it
            # scanned and fills each constructor argument from the same set,
            # so there is nothing to register out of band and the profile
            # says so (`wiring_channel: null`). A `behat_services.yml` in a
            # solution is a file aimed at another framework: recorded as a
            # rejection, the same route a refused file takes, rather than
            # silently dropped.
            rejected = rejected + [{"file_path": _hz.SERVICES_FRAGMENT_NAME,
                                    "why": "no_wiring_channel:cucumber"}]
        java_written = [p for p in written if p.endswith(".java")]
        self._remove_compiled_candidate_glue()
        index = self.index_paths(java_written)
        produced_feature = None
        if task == "requirement_to_test":
            produced_feature = next(
                (f.code for f in solution.files
                 if f.file_path.endswith(".feature")), None)
        _text, expected_line, expected_lines = self.write_feature(
            feature, scenario, override=produced_feature)

        runs = [self.execute(coverage=coverage, timeout=timeout,
                             expected_line=expected_line,
                             expected_lines=expected_lines)
                for _ in range(max(1, repeats))]

        after = _repo.verify_substrate(self.man, self.boundary,
                                       expected=self.expected_mutations)
        violation = None
        if after["baseline"] and (after["changed"] or after["missing"]
                                  or after["added"]):
            violation = {k: after[k][:8]
                         for k in ("changed", "missing", "added")}
        return {
            "substrate_violation": violation,
            "written_files": written,
            "rejected_files": rejected,
            "feature_from_solution": produced_feature is not None,
            "index_errors": index.get("errors") or {},
            "registered_contexts": sorted(class_name(p, self.boundary.project)
                                          for p in java_written),
            "runs": [r.to_json(keep_stdout=keep_stdout) for r in runs],
            "outcomes": [r.outcome for r in runs],
        }


# ------------------------------------------------------------------- the pom
#
# `pom.xml` is a FILE substrate root (D1): it decides the classpath every
# scenario compiles against, so any edit to it after the baseline is taken
# is already a tampering abort.  What the digests cannot defend is the
# moment the baseline is TAKEN — a pom that was already wrong then is
# laundered into the record of what "unchanged" means.  These two functions
# are what stands there.

#: The pom, workspace-relative.  One per project: both corpora are single
#: -module builds, which is also why the JaCoCo report needs no
#: dependency-unpacking branch (the ART recipe's `test_only` case).
POM_REL = "pom.xml"

#: Surefire settings that decide whether the EXIT CODE is a witness, and
#: what each one would cost.  A pom carrying any of them is refused: the
#: two-witness rule is that the recorder's per-step results and the
#: framework's own exit code must agree before a run counts as a pass, and
#: each of these makes the second witness say something else.
WITNESS_KNOBS: dict[str, str] = {
    "forkCount": "0 runs the steps inside Maven's own JVM, where a step "
                 "definition calling System.exit takes the build's exit "
                 "code with it instead of crashing a fork",
    "forkMode": "the deprecated spelling of forkCount; `never` is 0",
    "reuseForks": "decides whether one JVM runs several test classes, which "
                  "is what makes a per-scenario run attributable at all",
    "testFailureIgnore": "true makes a failing test a SUCCESSFUL build, "
                         "which is the exit-code witness saying the "
                         "opposite of what happened",
    "rerunFailingTestsCount": "re-runs a failing test until it passes and "
                              "reports a green build with a flake, i.e. a "
                              "pass this benchmark's all-repeats-must-pass "
                              "rule exists to refuse",
}

#: The two knobs whose surefire USER PROPERTY is spelled nothing like the
#: element, and the element each reaches.  A translation table, and only a
#: translation table — it is NOT the list of property spellings that matter.
_RENAMED_PROPERTIES: dict[str, str] = {
    "maven.test.failure.ignore": "testFailureIgnore",
    "surefire.rerunFailingTestsCount": "rerunFailingTestsCount",
}

#: Every `<properties>` name that reaches a witness knob -> the knob it
#: reaches.  DERIVED from `WITNESS_KNOBS` rather than written out, because
#: writing it out is what let three of the five through: `forkCount`,
#: `reuseForks` and `forkMode` are maven-surefire-plugin parameters whose
#: user property is spelled EXACTLY like the element, so Maven resolves them
#: out of project `<properties>` — and the element walk never sees them
#: there, since `<properties>` is not inside a `<plugin>`.  A knob added
#: above is now refused in both spellings without a second edit.
WITNESS_PROPERTIES: dict[str, str] = dict(
    _RENAMED_PROPERTIES, **{knob: knob for knob in WITNESS_KNOBS})

#: What the harness-owned runner class looks like.  Generated rather than
#: copied out of `r2t/java/` (the behave stack's `bench_environment.py`
#: precedent) because the two things that vary — the package cucumber scans
#: for glue, and the path the JSON plugin writes to — are exactly the two
#: fields of the project's quirk row, and a per-project file on disk would
#: be a second place for them to disagree.
RUNNER_TEMPLATE = """package {package};

import org.junit.runner.RunWith;

import io.cucumber.junit.Cucumber;
import io.cucumber.junit.CucumberOptions;

/**
 * Written by r2t's cucumber strip (r2t/stacks/cucumber.py) and hashed into
 * the substrate baseline; editing it during a run is a tampering abort.
 *
 * It exists so that the JSON plugin the harness folds is declared HERE and
 * never on the command line: {project}'s own runner is retained
 * byte-for-byte, and a `-Dcucumber.plugin` flag would collide with any
 * runner that already holds STDOUT.
 */
@RunWith(Cucumber.class)
@CucumberOptions({options})
public class {klass}
{{
}}
"""


#: The harness-owned Cucumber plugin that tells the direct-invocation agent
#: which step is executing.  Installed BESIDE the runner, in the runner's own
#: package, and registered through the runner's `@CucumberOptions` plugin list
#: — `-Dcucumber.plugin` is unusable here for the same reason the JSON plugin
#: is declared in the runner.
LISTENER_CLASS = "R2TStepTagListener"

#: Java 8 source, because epubcheck's fork is a JDK 8 (this class is not
#: installed there, but the stack compiles one recipe) and because Kapua and
#: algorand compile their test sources at `--release 8`.  It reaches the agent
#: by REFLECTION only: the agent jar is bind-mounted at
#: `direct_calls.AGENT_JAR_RUNTIME` and is on no Maven compile classpath, so a
#: direct reference would not compile.  A workspace run without the agent
#: (no `-javaagent`) finds no class and every call is a no-op.
LISTENER_TEMPLATE = """package {package};

import java.lang.reflect.Method;

import io.cucumber.plugin.ConcurrentEventListener;
import io.cucumber.plugin.event.EventPublisher;
import io.cucumber.plugin.event.PickleStepTestStep;
import io.cucumber.plugin.event.TestCase;
import io.cucumber.plugin.event.TestCaseStarted;
import io.cucumber.plugin.event.TestStep;
import io.cucumber.plugin.event.TestStepFinished;
import io.cucumber.plugin.event.TestStepStarted;

/**
 * Written by r2t's cucumber strip (r2t/stacks/cucumber.py) and hashed into
 * the substrate baseline; editing it during a run is a tampering abort.
 *
 * It stamps every direct-call event with the step that made it
 * (TARGET_INTERFACES_V2_SPEC.md section 4): the index of the executing pickle
 * step among this test case's pickle steps, which is the order
 * `records_from_json` writes the record's `steps` in -- the Background's
 * steps first, then the scenario's own, hooks excluded.  Between steps, and
 * before the first one, the index is cleared, so a call made by a hook or by
 * glue construction carries null.
 *
 * Which steps are actions or checks is decided later, in Python, from the
 * feature text.  Nothing here knows or decides that.
 */
public final class {klass} implements ConcurrentEventListener
{{
    private static final int NO_STEP = -1;

    /** `DirectCallRecorder.setStep(int)`, or null when no agent is attached. */
    private static final Method SET_STEP = resolve();

    private static Method resolve()
    {{
        try
        {{
            return Class.forName("r2t.directcalls.DirectCallRecorder")
                .getMethod("setStep", int.class);
        }}
        catch (ClassNotFoundException | NoSuchMethodException absent)
        {{
            return null;
        }}
    }}

    private static void setStep(int index)
    {{
        if (SET_STEP == null)
        {{
            return;
        }}
        try
        {{
            SET_STEP.invoke(null, Integer.valueOf(index));
        }}
        catch (ReflectiveOperationException failed)
        {{
            // The recorder is present and its own method refused the call:
            // every event after this would carry a wrong step silently.
            throw new IllegalStateException("r2t step tag listener", failed);
        }}
    }}

    private static int indexOf(TestCase testCase, TestStep target)
    {{
        int index = 0;
        for (TestStep step : testCase.getTestSteps())
        {{
            if (step instanceof PickleStepTestStep)
            {{
                if (step.getId().equals(target.getId()))
                {{
                    return index;
                }}
                index++;
            }}
        }}
        return NO_STEP;
    }}

    @Override
    public void setEventPublisher(EventPublisher publisher)
    {{
        publisher.registerHandlerFor(TestCaseStarted.class,
            (io.cucumber.plugin.event.EventHandler<TestCaseStarted>)
            event -> setStep(NO_STEP));
        publisher.registerHandlerFor(TestStepStarted.class,
            (io.cucumber.plugin.event.EventHandler<TestStepStarted>) event ->
            {{
                if (event.getTestStep() instanceof PickleStepTestStep)
                {{
                    setStep(indexOf(event.getTestCase(), event.getTestStep()));
                }}
            }});
        publisher.registerHandlerFor(TestStepFinished.class,
            (io.cucumber.plugin.event.EventHandler<TestStepFinished>) event ->
            {{
                if (event.getTestStep() instanceof PickleStepTestStep)
                {{
                    setStep(NO_STEP);
                }}
            }});
    }}
}}
"""


def listener_rel(quirks: ProjectQuirks) -> str:
    """Where this project's step-tag listener is installed, beside the runner."""
    return posixpath.join(posixpath.dirname(quirks.runner_rel),
                          LISTENER_CLASS + ".java")


def listener_class(quirks: ProjectQuirks) -> str:
    """The FQCN the runner's `plugin` element names."""
    return quirks.runner_package + "." + LISTENER_CLASS


def listener_source(quirks: ProjectQuirks) -> str:
    """The harness-owned step-tag listener, as it will be written."""
    source = LISTENER_TEMPLATE.format(package=quirks.runner_package,
                                      klass=LISTENER_CLASS)
    if quirks.prerequisite_tag:
        # A retained prerequisite runs in the same fork but is not part of
        # the selected target's step list. Keep its raw API events, with no
        # target-step attribution. Other projects retain their listener bytes.
        needle = "                    setStep(indexOf(event.getTestCase(), event.getTestStep()));"
        guard = ("                    if (event.getTestCase().getTags().contains("
                 + json.dumps(quirks.prerequisite_tag) + "))\n"
                 "                    {\n"
                 "                        setStep(NO_STEP);\n"
                 "                        return;\n"
                 "                    }\n")
        source = source.replace(needle, guard + needle)
    return source


def runner_source(quirks: ProjectQuirks, project: str) -> str:
    """The harness-owned runner for this project, as it will be written."""
    plugins = [quirks.json_plugin]
    if quirks.direct_call_agent:
        # The listener accompanies the agent and only the agent: a project
        # with no `-javaagent` records no direct calls, so a step tag would
        # be a plugin with nothing to tell, and installing it would move
        # that project's runner bytes, seed and substrate baseline for no
        # collected data.
        plugins.append(listener_class(quirks))
    options = ", ".join(
        quirks.runner_options
        + ("plugin = {" + ", ".join(f'"{p}"' for p in plugins) + "}",))
    return RUNNER_TEMPLATE.format(package=quirks.runner_package,
                                  klass=quirks.runner_class,
                                  project=project, options=options)


def installed_sources_for(project: str, *,
                          stripped: bool = True) -> dict[str, str]:
    """Every harness-owned Java source the strip installs: rel -> text.

    One entry per runner, plus one step-tag listener per PACKAGE that holds a
    runner with the agent enabled — Kapua's five `integration.service.user`
    runners share a package and therefore share one listener file.
    """
    sources: dict[str, str] = {}
    for variant in runner_variants_for(project, stripped=stripped):
        sources[variant.runner_rel] = runner_source(variant, project)
        if variant.direct_call_agent:
            sources.setdefault(listener_rel(variant), listener_source(variant))
    return sources


def _local(element) -> str:
    """An element's tag without Maven's namespace."""
    return element.tag.rsplit("}", 1)[-1]


def _surefire_plugins(root):
    """Every `<plugin>` element declaring maven-surefire-plugin.

    Every one, wherever it sits — `<build>`, `<pluginManagement>`, a
    `<profile>` — because a knob that only takes effect under a profile
    still takes effect, and the conservative direction here is to look at
    all of them.
    """
    for element in root.iter():
        if _local(element) != "plugin":
            continue
        for child in element:
            if (_local(child) == "artifactId"
                    and (child.text or "").strip()
                    == "maven-surefire-plugin"):
                yield element


def refuse_witness_tampering(pom_text: str, quirks: ProjectQuirks) -> None:
    """Refuse a pom whose surefire configuration breaks the exit code.

    Three findings, one refusal each:

    * a `WITNESS_KNOBS` element inside a surefire plugin.  `skipTests` is
      deliberately NOT one of them, and that is a fact checked against real
      bytes rather than a judgement: algorand's pinned pom really does carry
      `<skipTests>true</skipTests>` at plugin level with `false` in the
      execution that runs the unit tests, so a blanket refusal would refuse
      the corpus.  Skipping also produces no document at all, which the fold
      already reports as `no_scenario_ran`;
    * EVERY one of the same knobs in its `<properties>` spelling — the two
      surefire renames (`_RENAMED_PROPERTIES`) and the three whose user
      property is spelled exactly like the element, which is what
      `WITNESS_PROPERTIES` derives.  `<properties>` sits outside every
      `<plugin>`, so the element walk above cannot reach either kind;
    * a surefire `<workingDirectory>` that is not the one this project's
      quirk row was written against.  That element decides the forked JVM's
      cwd, cucumber resolves the JSON plugin's path against it, and the
      harness reads the document at a path derived from it — so moving it
      does not break loudly, it makes every item score `no_scenario_ran` off
      a document sitting somewhere nobody looks.
    """
    import xml.etree.ElementTree as ET

    root = ET.fromstring(pom_text)
    for plugin in _surefire_plugins(root):
        for element in plugin.iter():
            knob = _local(element)
            if knob in WITNESS_KNOBS:
                raise CucumberStackRefused(
                    f"REFUSED: {POM_REL} configures surefire's {knob!r} "
                    f"(<{knob}>{(element.text or '').strip()}</{knob}>). "
                    f"{WITNESS_KNOBS[knob]}. The exit code is one of the two "
                    f"witnesses a run needs to count as a pass, so a tree "
                    f"carrying this cannot be baselined or measured.")
        working = [(e.text or "").strip() for e in plugin.iter()
                   if _local(e) == "workingDirectory"]
        expected = ([quirks.fork_workdir_pom]
                    if quirks.fork_workdir_pom is not None else [])
        if working != expected:
            raise CucumberStackRefused(
                f"REFUSED: {POM_REL} declares surefire "
                f"workingDirectory={working} where this project's quirk row "
                f"expects {expected}. cucumber resolves its `json:` plugin "
                f"path against the fork's working directory, and this "
                f"stack reads the document at {quirks.json_rel} because of "
                f"that value — change one and every item scores "
                f"`no_scenario_ran` off a document nothing reads.")
    for properties in root.iter():
        if _local(properties) != "properties":
            continue
        for element in properties:
            name = _local(element)
            knob = WITNESS_PROPERTIES.get(name)
            if knob is None:
                continue
            spelling = ("" if knob == name
                        else f", which is surefire's {knob!r} by another "
                             f"name")
            raise CucumberStackRefused(
                f"REFUSED: {POM_REL} sets the property {name!r}{spelling}. "
                f"{WITNESS_KNOBS[knob]}. Maven resolves surefire's parameter "
                f"from <properties> exactly as it does from the plugin "
                f"element, and no <plugin> contains this one — so it is the "
                f"same tampering in the spelling the element walk cannot "
                f"see.")


# --------------------------------------------------------------- coverage
#
# The ART recipe (`ReqEnhancement/coverage_collector.py:441-573`), narrowed
# to what these two projects are: single-module builds whose own classes are
# the only ones in `target/classes`, so there is no dependency-unpacking
# branch and no `<includes>` — the report covers the project's own `src/main`
# because that is all that is there, and `coverage_doc` fences it a second
# time by refusing to name a file that is not in this workspace.
#
# It is applied ONCE, at strip time, and the patched bytes are what the
# baseline hashes.  Patching per item would be a substrate change per item.

#: The plugin block appended before the first `</plugins>`.  `report` binds
#: to `test` and the plugin is appended LAST, so within that phase Maven
#: runs surefire (declared earlier) and then the report over what it left.
JACOCO_PLUGIN = """
            <plugin>
                <groupId>org.jacoco</groupId>
                <artifactId>jacoco-maven-plugin</artifactId>
                <version>0.8.11</version>
                <executions>
                    <execution>
                        <id>prepare-agent</id>
                        <goals>
                            <goal>prepare-agent</goal>
                        </goals>
                    </execution>
                    <execution>
                        <id>report</id>
                        <phase>test</phase>
                        <goals>
                            <goal>report</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>"""

#: The late-replacement token surefire resolves at execution time, which is
#: what lets one `argLine` hold both the project's own JVM flags and the
#: agent the `prepare-agent` goal sets.
ARG_LINE_TOKEN = "@{argLine}"

#: ...and the empty default that makes the skip case survivable.  With
#: `-Djacoco.skip=true` the agent goal never sets the `argLine` property, and
#: surefire then passes the literal `@{argLine}` to the JVM, which refuses to
#: start ("Unrecognized option"). Declaring the property empty gives the late
#: replacement something to resolve; `prepare-agent` overwrites it when it
#: does run, because the token is resolved at execution rather than at
#: model-build time.  This is the JaCoCo/surefire interaction the recipe
#: cannot be read without.
ARG_LINE_PROPERTY = "\n        <argLine></argLine>"

#: The SECOND JVM argument in surefire's argLine: the direct-invocation
#: agent's `-javaagent` option, or nothing (spec 2.4).  NOT a late-replacement
#: token like `@{argLine}`: `${...}` is resolved by Maven's own property
#: interpolation when it evaluates the plugin parameter, and a `-D` user
#: property outranks a project property, so a coverage run's
#: `-Dr2t.agent.argline=-javaagent:...` lands in the fork's argument line
#: while an ordinary run, passing no `-D`, gets the empty default declared
#: in `<properties>` -- declared for exactly the reason `argLine` is, so the
#: reference never reaches the JVM as a literal.  JaCoCo's token comes FIRST
#: so that JaCoCo's transformer sees the original class bytes: its class ids
#: are computed over what it receives, and a class the recorder had already
#: rewritten would match nothing in the report it renders from
#: `target/classes`.  Two `-javaagent` options in one line are ordinary JVM
#: usage; section 8 measures that `coverage_lines` is identical either way.
AGENT_ARG_LINE_PROPERTY = "r2t.agent.argline"
AGENT_ARG_LINE_TOKEN = "${" + AGENT_ARG_LINE_PROPERTY + "}"
AGENT_ARG_LINE_DEFAULT = (f"\n        <{AGENT_ARG_LINE_PROPERTY}>"
                          f"</{AGENT_ARG_LINE_PROPERTY}>")


def _kapua_pom_with_agent(pom_text: str) -> str:
    """Preserve Kapua's native JaCoCo recipe and add only our agent hook.

    JaCoCo 0.8.8's AbstractAgentMojo.skipMojo supplies the empty native
    argLine when skipped. The upstream ${argLine} and plugin executions
    therefore remain verbatim; the generic patch's refusal is unchanged.
    """
    if AGENT_ARG_LINE_PROPERTY in pom_text:
        raise CucumberStackRefused(
            "REFUSED: Kapua pom.xml already carries the direct-call hook; "
            "strip a fresh clone.")
    # The Eclipse lifecycle-mapping filter also mentions this artifactId;
    # count plugin declarations, not every textual mention in the POM.
    native_plugins = re.findall(
        r"<plugin>\s*<groupId>org.jacoco</groupId>\s*"
        r"<artifactId>jacoco-maven-plugin</artifactId>", pom_text)
    if (len(native_plugins) != 1
            or "<jacoco.version>0.8.8</jacoco.version>" not in pom_text
            or "<id>default-prepare-agent</id>" not in pom_text
            or "<id>default-report</id>" not in pom_text):
        raise CucumberStackRefused(
            "REFUSED: Kapua pom.xml does not carry its pinned native JaCoCo recipe.")
    blocks = [m for m in re.finditer(r"<plugin>.*?</plugin>", pom_text, re.S)
              if "<artifactId>maven-surefire-plugin</artifactId>" in m.group()]
    if len(blocks) != 1 or "</properties>" not in pom_text:
        raise CucumberStackRefused(
            "REFUSED: Kapua pom.xml has no unique Surefire plugin or properties block.")
    plugin = blocks[0]
    arglines = list(re.finditer(r"<argLine>[^<]*</argLine>", plugin.group()))
    if len(arglines) != 1 or arglines[0].group().count("${argLine}") != 1:
        raise CucumberStackRefused(
            "REFUSED: Kapua Surefire does not carry its native ${argLine}.")
    argline = arglines[0]
    start = plugin.start() + argline.start()
    end = plugin.start() + argline.end()
    patched = (pom_text[:start] + argline.group().replace(
        "${argLine}", "${argLine} " + AGENT_ARG_LINE_TOKEN, 1)
        + pom_text[end:])
    return patched.replace("</properties>", AGENT_ARG_LINE_DEFAULT
                           + "\n    </properties>", 1)


def pom_with_coverage(pom_text: str) -> str:
    """The pom, with the JaCoCo agent and the direct-invocation hook in it — or a refusal.

    Three edits on TEXT rather than on a parsed tree, deliberately: a pom
    re-serialised by ElementTree loses its comments, its namespace prefixes
    and its formatting, and the diff a reviewer of this strip has to read
    would then be the whole file. Each edit refuses when its anchor is
    missing rather than guessing at a shape, because the alternative to a
    refusal here is a silently uninstrumented workspace whose coverage
    numbers are all zero for a reason nothing states.
    """
    if "jacoco-maven-plugin" in pom_text:
        raise CucumberStackRefused(
            f"REFUSED: {POM_REL} already configures jacoco-maven-plugin. "
            f"This is not the pinned upstream tree, and a second agent "
            f"declaration would double-instrument the run.")
    if ARG_LINE_TOKEN in pom_text:
        raise CucumberStackRefused(
            f"REFUSED: {POM_REL} already carries {ARG_LINE_TOKEN}, so it has "
            f"been patched before. Strip a fresh clone.")
    if "</properties>" not in pom_text:
        raise CucumberStackRefused(
            f"REFUSED: {POM_REL} declares no <properties>, so there is "
            f"nowhere to give `argLine` an empty default — and without one "
            f"an uninstrumented run passes the literal {ARG_LINE_TOKEN} to "
            f"the JVM, which refuses to start.")
    surefire = re.search(
        r"<artifactId>maven-surefire-plugin</artifactId>.*?<configuration>",
        pom_text, re.S)
    if surefire is None:
        raise CucumberStackRefused(
            f"REFUSED: {POM_REL} has no maven-surefire-plugin "
            f"<configuration> to put the agent's argLine in. A cucumber "
            f"project whose tests run under some other plugin is not one "
            f"this stack knows how to instrument.")
    # SCOPED to that configuration block: a project can carry an `<argLine>`
    # elsewhere (a `<properties>` default, another plugin), and rewriting the
    # wrong one would leave surefire's untouched and the agent unattached.
    start = surefire.end()
    end = pom_text.find("</configuration>", start)
    if end == -1:
        raise CucumberStackRefused(
            f"REFUSED: {POM_REL}'s surefire <configuration> is never closed.")
    block = pom_text[start:end]
    existing = re.search(r"<argLine>([^<]*)</argLine>", block)
    if existing is not None:
        kept = existing.group(1).strip()
        block = block.replace(existing.group(0), "<argLine>" + " ".join(
            [ARG_LINE_TOKEN, AGENT_ARG_LINE_TOKEN] + ([kept] if kept else []))
            + "</argLine>", 1)
    else:
        block = (f"\n                    <argLine>{ARG_LINE_TOKEN} "
                 f"{AGENT_ARG_LINE_TOKEN}</argLine>" + block)
    text = pom_text[:start] + block + pom_text[end:]
    text = text.replace("</properties>",
                        ARG_LINE_PROPERTY + AGENT_ARG_LINE_DEFAULT
                        + "\n    </properties>", 1)

    if "</plugins>" not in text:
        raise CucumberStackRefused(
            f"REFUSED: {POM_REL} has no <plugins> section to append the "
            f"JaCoCo plugin to.")
    return text.replace("</plugins>", JACOCO_PLUGIN + "\n        </plugins>",
                        1)


def coverage_doc(report_xml: str, repo_root: str, *,
                 source_root: str = SOURCE_ROOT) -> dict:
    """JaCoCo's XML report as the record's `coverage` block.

    `{"files": {rel: covered_line_count}, "units": ["rel::L<line>"]}` — both
    halves, because `files` is what a human reads and `units` is what the
    mutation map joins on, and `runner._coverage_mismatch` flags a run where
    they disagree rather than trusting it.

    A line counts as covered when JaCoCo says at least one INSTRUCTION on it
    executed (`ci`), which is the same reading the ART collector takes.

    Two fences, and the second is the one that matters: the path is built
    under the report's `source_root`, and a path that is not a file in THIS
    workspace is dropped.  A coverage collector left at whole-tree scope credits the
    instrumentation itself, and a report that named a class from a
    dependency (which the ART recipe's test-only branch deliberately
    unpacks into `target/classes`) would credit somebody else's code to
    this project's scenario.
    """
    import xml.etree.ElementTree as ET

    files: dict[str, int] = {}
    units: list[str] = []
    for package in ET.fromstring(report_xml).iter("package"):
        name = package.get("name") or ""
        for sourcefile in package.findall("sourcefile"):
            rel = f"{source_root}/{name}/{sourcefile.get('name')}"
            if not os.path.isfile(os.path.join(repo_root, rel)):
                continue
            covered = sorted(int(line.get("nr"))
                             for line in sourcefile.findall("line")
                             if int(line.get("ci") or 0) > 0)
            if not covered:
                continue
            files[rel] = len(covered)
            units += [f"{rel}::L{n}" for n in covered]
    return {"files": files, "units": sorted(units)}


def kapua_coverage_doc(repo_root: str, boundary) -> dict | None:
    """Merge native module reports, counting only boundary-owned production.

    Each XML comes from that module's target/classes and resolves against its
    own src/main/java. A package shared by two modules never makes their files
    interchangeable. Missing reports mean no measurement; an existing report
    with no production hits means a measured empty result.
    """
    files = {}
    units = []
    seen = False
    for module in _kapua.MODULES:
        prefix = module + "/" if module != "." else ""
        path = os.path.join(repo_root, prefix + JACOCO_XML_REL)
        if not os.path.isfile(path):
            continue
        seen = True
        with open(path, encoding="utf-8") as stream:
            document = coverage_doc(stream.read(), repo_root,
                                    source_root=prefix + SOURCE_ROOT)
        production = {path: count for path, count in document["files"].items()
                      if boundary.classify(path) == PRODUCTION}
        files.update(production)
        units.extend(unit for unit in document["units"]
                     if unit.rsplit("::L", 1)[0] in production)
    return {"files": files, "units": sorted(units)} if seen else None


def verify_runner_sources(repo_root: str, project: str, *,
                          stripped: bool = True) -> None:
    """Require generated Java runners and step-tag listeners to match this recipe."""
    variants = runner_variants_for(project, stripped=stripped)
    listeners = {rel: text
                 for rel, text in installed_sources_for(
                     project, stripped=stripped).items()
                 if rel.endswith("/" + LISTENER_CLASS + ".java")}
    for variant in variants:
        runner = os.path.join(repo_root, variant.runner_rel)
        if not os.path.isfile(runner):
            raise CucumberStackRefused(
                f"REFUSED: {variant.runner_rel} is missing, so this "
                f"workspace was not prepared by `strip_repo_cucumber` (or "
                f"the runner was removed after it was). It is the class "
                f"`-Dtest={variant.test_selector}` selects and the only "
                f"place the JSON plugin is declared: without it a run "
                f"executes nothing and writes no document.")
        with open(runner, encoding="utf-8") as fh:
            actual = fh.read()
        if actual != runner_source(variant, project):
            raise CucumberStackRefused(
                f"REFUSED: {variant.runner_rel} is not the generated "
                f"harness runner for {project!r}; prepare a fresh seed "
                "with the current reviewed harness.")
    for rel, expected in listeners.items():
        listener = os.path.join(repo_root, rel)
        if not os.path.isfile(listener):
            raise CucumberStackRefused(
                f"REFUSED: {rel} is missing, so this workspace was not "
                f"prepared by `strip_repo_cucumber` (or the listener was "
                f"removed after it was). It is the `@CucumberOptions` plugin "
                f"that tells the direct-invocation agent which step is "
                f"executing: without it every recorded event would carry no "
                f"step and no item could be scored against its action and "
                f"check steps.")
        with open(listener, encoding="utf-8") as fh:
            actual = fh.read()
        if actual != expected:
            raise CucumberStackRefused(
                f"REFUSED: {rel} is not the generated harness step-tag "
                f"listener for {project!r}; prepare a fresh seed with the "
                "current reviewed harness.")


def integrity_baseline(manifest: _repo.StripManifest, boundary,
                       manifest_path: str, *, stripped: bool = True) -> dict:
    """`repo.baseline_substrate`, with the pom read before it is hashed.

    The other two stacks alias this seam straight to `baseline_substrate`,
    because for them the answer to "what must not change" is entirely in
    the digests.  Here one of the hashed files is a BUILD SCRIPT, and a
    digest cannot tell a pom that pins the run from a pom that unpins it:
    both hash fine, and the second one is only visible before its bytes
    become the definition of "unchanged".

    So this refuses first and delegates second.  Re-baselining a tampered
    tree would launder the tampering, which is the same reason
    `cli.cmd_manifest_baseline` refuses a tree that no longer matches an
    existing baseline.
    """
    quirks = quirks_for(boundary.project)
    pom = os.path.join(manifest.repo_root, POM_REL)
    if not os.path.isfile(pom):
        raise CucumberStackRefused(
            f"REFUSED: no {POM_REL} at {manifest.repo_root}. A cucumber "
            f"workspace with no build script is not a tree anything here "
            f"can compile, run or hash.")
    verify_runner_sources(manifest.repo_root, boundary.project, stripped=stripped)
    with open(pom, encoding="utf-8") as fh:
        text = fh.read()
    refuse_witness_tampering(text, quirks)
    jacoco_token = "${argLine}" if boundary.project == "kapua" else ARG_LINE_TOKEN
    if jacoco_token not in text or "jacoco-maven-plugin" not in text \
            or AGENT_ARG_LINE_TOKEN not in text:
        raise CucumberStackRefused(
            f"REFUSED: {POM_REL} does not carry the coverage recipe "
            f"(`{jacoco_token}` and `{AGENT_ARG_LINE_TOKEN}` in surefire's "
            f"argLine, jacoco-maven-plugin "
            f"in the build). `strip_repo_cucumber` puts it there, so this "
            f"tree was prepared some other way — and a baseline taken over "
            f"it would freeze a workspace whose coverage runs measure "
            f"nothing, with every `--coverage` row reading zero for a "
            f"reason no log states.")
    return _repo.baseline_substrate(manifest, boundary, manifest_path)


# ------------------------------------------------------------------- strip
#: The archived Kilo corpora tree, protected always.  Every checkout
#: `corpora.yml` declares is data-root-relative (`load_corpora` refuses an
#: absolute `root`), so this one absolute prefix cannot be derived from the
#: config and stays written down beside the derivation.
ARCHIVED_CORPORA = "/data2/binhang/req2test_corpora"

#: Gold trees `cmd_strip` refuses to write into, by prefix.  A cucumber
#: strip pointed at the portable CoreShop root's `gold/strip_manifest.json`
#: would overwrite CoreShop's integrity baseline with a Java manifest, and
#: every CoreShop worker would abort its next item as tampered.
PROTECTED_GOLD = (
    # The portable entry is checkable only under a configured data root;
    # the archived Kilo tree stays protected always.
    project_path("coreshop", "gold"),
    "/data2/binhang/coreshop_bench",
)


def strip_repo_cucumber(boundary, gold_root: str,
                        dry_run: bool = False, *,
                        stripped: bool = True) -> _repo.StripManifest:
    """Move the answer out of a cucumber CLONE and install the runner.

    The cucumber arm of `repo.strip_repo`, sharing its mechanics
    (`_iter_files`/`_move`/`_prune_empty_dirs`, classify-every-file,
    `sanitise_repo` for the `.git` copy of the answer) and differing where
    the stacks genuinely differ:

    * the manifest records the CUCUMBER roots and, for the first time on any
      stack, `build_roots` — so `sanitise_repo` empties `target/`, whose
      `test-classes/**/*.class` is the removed glue with its Cucumber
      Expressions intact in the constant pool;
    * one generated runner is installed per glue package the benchmark uses;
      each declares the JSON plugin and is classified PRODUCTION by the
      boundary, so a solution cannot write it and its bytes are baseline
      material.

    There is no `harness_dir` parameter, unlike the other two stacks' strip
    functions: this stack installs no program of ours.  cucumber's own JSON
    formatter is the recorder, and the one file written here is generated
    from the project's quirk row.
    """
    repo_root = os.path.abspath(boundary.repo_root)
    quirks = quirks_for(boundary.project)
    # Every checkout `config/corpora.yml` declares, by prefix, plus the
    # archived tree.  The pinned corpora are the S0 gate's ground truth —
    # epubcheck at `82b174ec` must re-derive its items byte-identically — and
    # `boundary_epubcheck.yml`'s default `repo_root` points INTO one of them,
    # so "strip with the default flags" must be a refusal rather than a
    # corpus-destroying default.  Declared roots first, so a data root that
    # happens to live inside the archived tree still names the tree the
    # operator asked for.
    for protected in _repo.declared_corpus_roots() + (ARCHIVED_CORPORA,):
        protected = os.path.abspath(protected)
        if repo_root == protected or repo_root.startswith(protected + os.sep):
            raise SystemExit(
                f"REFUSED: {repo_root} is inside the pinned corpus tree "
                f"({protected}). The corpora are the S0 gate's ground truth "
                f"— epubcheck at 82b174ec must re-derive its items "
                f"byte-identically — and the boundary config's default "
                f"repo_root points here precisely so that extraction reads "
                f"the pinned bytes. Strip a CLONE: pass --repo at a copy.")
    pom = os.path.join(repo_root, POM_REL)
    test_roots = (tuple(module + "/" + rel
                        for module in _kapua.TEST_MODULES
                        for rel in (JAVA_TEST_ROOT, "src/test/resources"))
                  if boundary.project == "kapua"
                  else (JAVA_TEST_ROOT, "src/test/resources"))
    if not (os.path.isfile(pom)
            and all(os.path.isdir(os.path.join(repo_root, rel))
                    for rel in test_roots)):
        raise SystemExit(
            f"REFUSED: {repo_root} does not look like a cucumber-jvm "
            f"project (no {POM_REL}, no {JAVA_TEST_ROOT}/ or no "
            f"src/test/resources/).")
    # BEFORE anything moves.  A tree whose pom already unpins the run is not
    # a tree to strip and then discover about: the strip is irreversible for
    # everything it moves, and the refusal is free here.
    with open(pom, encoding="utf-8") as fh:
        refuse_witness_tampering(fh.read(), quirks)

    man = _repo.StripManifest(
        repo_root=repo_root, gold_root=os.path.abspath(gold_root),
        boundary_version=boundary.version,
        # Recorded, not defaulted: an empty roots list on this manifest
        # would mean CoreShop's roots, i.e. a substrate check walking
        # `vendor/behat` in a Java checkout and verifying a tree it never
        # looked at.  `CucumberHarness.__init__` refuses a manifest whose
        # build_roots are empty for the same reason from the other side.
        substrate_roots=list(_repo.CUCUMBER_SUBSTRATE_ROOTS_BY_PROJECT.get(
            boundary.project, _repo.CUCUMBER_SUBSTRATE_ROOTS)),
        substrate_volatile=sorted(
            _repo.CUCUMBER_SUBSTRATE_VOLATILE_BY_PROJECT.get(
                boundary.project, _repo.CUCUMBER_SUBSTRATE_VOLATILE)),
        # A JVM compiles ahead of time and writes nothing under a substrate
        # root, so there is no bytecode to sweep per item — `build_roots` is
        # the Java answer to the question `bytecode_roots` asks in Python.
        bytecode_roots=[], build_roots=list(
            _repo.CUCUMBER_BUILD_ROOTS_BY_PROJECT.get(
                boundary.project, _repo.CUCUMBER_BUILD_ROOTS)))

    config_prefixes = set(boundary.removable_config)
    seen: set = set()
    for prefix, _ in boundary.removable:
        for rel in _repo._iter_files(repo_root, prefix):
            if rel in seen or boundary.classify(rel) != _REMOVABLE:
                continue
            seen.add(rel)
            (man.moved_config if any(rel.startswith(c.rstrip("/"))
                                     for c in config_prefixes)
             else man.moved).append(rel)
    for prefix in boundary.removable_config:
        for rel in _repo._iter_files(repo_root, prefix):
            if rel not in seen:
                seen.add(rel)
                man.moved_config.append(rel)

    if dry_run:
        return man

    for rel in man.moved + man.moved_config:
        _repo._move(repo_root, man.gold_root, rel)
    for prefix, _ in boundary.removable:
        _repo._prune_empty_dirs(repo_root, prefix)
    for prefix in boundary.removable_config:
        _repo._prune_empty_dirs(repo_root, prefix)

    # The runners and, beside each one whose fork carries the direct-call
    # agent, the step-tag listener its `plugin` element names.
    for rel, text in installed_sources_for(
            boundary.project, stripped=stripped).items():
        path = os.path.join(repo_root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        man.installed.append(rel)

    # The coverage agent goes into the pom HERE, once, so that the bytes the
    # baseline is about to hash are the bytes every run executes.  Patching
    # per item would be a substrate change per item, i.e. a tampering abort
    # on the second one.
    with open(pom, encoding="utf-8") as fh:
        patch_pom = (_kapua_pom_with_agent if boundary.project == "kapua"
                     else pom_with_coverage)
        patched = patch_pom(fh.read())
    with open(pom, "w", encoding="utf-8") as fh:
        fh.write(patched)
    man.patched.append(POM_REL)

    # The answer's other copies: `.git` (every removed file at HEAD) moves
    # to gold, and `target/` — a compiled copy of the glue that a decompiler
    # reads back — is deleted, because Maven regenerates it from source and
    # a gold copy of it would preserve nothing.
    man.installed += _repo.sanitise_repo(repo_root, man.gold_root,
                                         man.bytecode_roots, man.build_roots)
    man.save(os.path.join(man.gold_root, "strip_manifest.json"))
    return man


def cmd_strip(args) -> int:
    """`r2t strip --profile config/profile_epubcheck.yml --repo <clone>
    --gold <gold>` — the cucumber arm, reached through `cli._other_stack`."""
    from ..core.boundary import load_boundary
    gold_abs = os.path.abspath(args.gold)
    for protected_path in PROTECTED_GOLD:
        # A data-root default can only be materialized (or violated) under a
        # configured data root; the archived absolute entries always apply.
        if not isinstance(protected_path, str) \
                and not os.environ.get(DATA_ROOT_ENV):
            continue
        protected = os.path.abspath(protected_path)
        if gold_abs == protected or gold_abs.startswith(protected + os.sep):
            raise SystemExit(
                f"REFUSED: --gold {args.gold} is inside {protected}, the "
                f"CoreShop data root. A cucumber strip manifest written "
                f"there would replace CoreShop's integrity baseline, and "
                f"every CoreShop worker would abort its next item as "
                f"tampered. Pass a gold tree of this project's own.")
    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    man = strip_repo_cucumber(b, args.gold, dry_run=args.dry_run)
    print(f"{'would move' if args.dry_run else 'moved'} {len(man.moved)} "
          f"test-code files and {len(man.moved_config)} lifecycle/config "
          f"files -> {args.gold}")
    if not args.dry_run:
        print(f"installed: {man.installed}")
    return 0


# --------------------------------------------------------- CLI construction
def make_harness(args):
    """`(harness, boundary, manifest)` for `framework: cucumber`.

    Mirrors the behave body's resolution rule (one `--repo`, setting both
    the classification root and the write root) and its workdir refusal:
    `/var/www/html` is both argparse's default and the CoreShop convention,
    so its presence here means "nobody said where this worker mounts", and
    executing against a guessed mount point is the H2 failure — every item
    scoring off a document written at a path that does not exist.
    """
    from ..core.boundary import load_boundary
    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    manifest_path = os.path.join(args.gold, "strip_manifest.json")
    if not os.path.isfile(manifest_path):
        raise SystemExit(
            f"REFUSED: no strip manifest at {manifest_path}. Strip a clone "
            f"first (`r2t strip --profile config/profile_epubcheck.yml "
            f"--repo <clone> --gold <gold>`), and point --gold at THAT gold "
            f"tree — the default --gold is CoreShop's.")
    man = _repo.load_manifest(manifest_path)
    man.repo_root = os.path.abspath(b.repo_root)
    man.gold_root = os.path.abspath(args.gold)
    if not os.path.isdir(man.repo_root):
        raise SystemExit(f"REFUSED: no such workspace: {man.repo_root}")
    workdir = getattr(args, "workdir", None)
    if workdir in (None, "/var/www/html"):
        raise SystemExit(
            "REFUSED: no workdir for a cucumber worker. `/var/www/html` is "
            "argparse's default and the CoreShop mount convention, so it "
            "cannot mean 'this cucumber container'; pass --worker FILE from "
            "`r2t worker plan` (which sets --repo, --container and --workdir "
            "together), or an explicit --workdir.")
    runner = _hz.DockerRunner(args.container, workdir=workdir)
    return CucumberHarness(man, b, runner), b, man


# ------------------------------------------------------ module-level seams
#
# The `StackRunner` names, so `stacks.verb(stack, ...)` and the protocol
# check find them.  `install_solution` and `execute` are the unbound
# methods, exactly as both other stacks expose their harnesses'.

strip = strip_repo_cucumber
install_solution = CucumberHarness.install_solution
execute = CucumberHarness.execute

# `boundary.REMOVABLE` under the name the strip walk uses; imported late to
# keep the top of the file about the seams rather than the plumbing.
from ..core.boundary import REMOVABLE as _REMOVABLE  # noqa: E402


#: Every re-exported member, and the dotted path of the object it must BE.
#: Walked with `is` by this module's selftest — a member that starts
#: WRAPPING something instead of re-exporting it fails that walk.
MEMBERS: dict[str, str] = {
    # The acceptance rule is the SAME function on all three harnesses.
    "install_solution": "r2t.bench.harness.Harness.install_solution",
}

#: The class attributes `CucumberHarness` ASSIGNS from the PHP harness, and
#: the dotted path of the object each must BE.  Its docstring says they are
#: "held to identity by the selftest"; this is the table that makes that
#: sentence true of all three rather than of the one that happened to also
#: be re-exported at module level.  Walked with `is`, and CLOSED — an
#: attribute that becomes one of `harness.Harness`'s functions without a row
#: here fails a check, because the failure this defends against is a later
#: session replacing `verify_substrate` with a local one that REPORTS
#: instead of raising, or an `_abs` that drops the path-escape refusal,
#: while every named check still passes and the docstring still claims the
#: two are one object.
CLASS_MEMBERS: dict[str, str] = {
    "_abs": "r2t.bench.harness.Harness._abs",
    "install_solution": "r2t.bench.harness.Harness.install_solution",
    "verify_substrate": "r2t.bench.harness.Harness.verify_substrate",
}

#: What this module defines ITSELF.  The selftest compares the module's own
#: callables against exactly this tuple, so a helper that creeps in without
#: being declared here fails a check rather than accreting silently.
OWN_MEMBERS: tuple[str, ...] = (
    "CucumberHarness", "CucumberStackRefused", "ProjectQuirks", "class_name",
    "cmd_interfaces", "cmd_strip", "compile_command", "compile_errors",
    "coverage_doc", "kapua_coverage_doc", "kapua_report_command",
    "execute", "filter_name_regex", "installed_sources_for",
    "integrity_baseline", "listener_class", "listener_rel", "listener_source",
    "make_harness",
    "pom_with_coverage", "quirks_for", "records_from_json",
    "refuse_witness_tampering", "runner_source", "selftest", "step_record",
    "runner_variants_for", "scenario_timings_from_json", "strip",
    "strip_repo_cucumber",
    "suite_capture_argv", "test_command", "verify_runner_sources", "void_note")

#: The seams that have NOT landed, and which milestone lands each.  Asserted
#: genuinely ABSENT by the selftest: "not implemented yet" is then a checked
#: claim rather than an absence nobody notices, and `stacks.verb` turns each
#: into a refusal that names the verb instead of an `AttributeError`.
#:
PENDING: dict[str, str] = {
    "extract_closure": "J4 (S3 closures): r2t/java/closure_java.py",
    "stub_solution": "J6 (S5 stub): r2t/toolkit/stub_java.py",
}


# ----------------------------------------------------------------- selftest
def _check_listener_events(check):
    """Exercise generated Java through the event API, without a Maven/network dependency."""
    import shutil
    import tempfile
    from pathlib import Path

    javac, java = shutil.which("javac"), shutil.which("java")
    if not javac or not java:
        check("listener event fixture requires the self-test JDK", False)
        return
    with tempfile.TemporaryDirectory(prefix="cucumber-listener-") as root:
        root = Path(root)
        sources = {
            "io/cucumber/plugin/ConcurrentEventListener.java":
                "package io.cucumber.plugin; public interface ConcurrentEventListener { "
                "void setEventPublisher(io.cucumber.plugin.event.EventPublisher p); }",
            "io/cucumber/plugin/event/EventHandler.java":
                "package io.cucumber.plugin.event; public interface EventHandler<T> { void receive(T e); }",
            "io/cucumber/plugin/event/EventPublisher.java":
                "package io.cucumber.plugin.event; public interface EventPublisher { "
                "<T> void registerHandlerFor(Class<T> c, EventHandler<T> h); }",
            "io/cucumber/plugin/event/TestStep.java":
                "package io.cucumber.plugin.event; public interface TestStep { String getId(); }",
            "io/cucumber/plugin/event/PickleStepTestStep.java":
                "package io.cucumber.plugin.event; public interface PickleStepTestStep extends TestStep {}",
            "io/cucumber/plugin/event/TestCase.java":
                "package io.cucumber.plugin.event; public interface TestCase { "
                "java.util.List<TestStep> getTestSteps(); java.util.List<String> getTags(); }",
            "io/cucumber/plugin/event/TestCaseStarted.java":
                "package io.cucumber.plugin.event; public class TestCaseStarted {}",
            "r2t/directcalls/DirectCallRecorder.java":
                "package r2t.directcalls; public class DirectCallRecorder { "
                "public static int step = -1; public static void setStep(int s) { step = s; } }",
        }
        for name in ("TestStepStarted", "TestStepFinished"):
            sources["io/cucumber/plugin/event/" + name + ".java"] = (
                "package io.cucumber.plugin.event; public class " + name + " { "
                "private final TestCase c; private final TestStep s; public " + name
                + "(TestCase c, TestStep s) { this.c=c; this.s=s; } "
                "public TestCase getTestCase() { return c; } public TestStep getTestStep() { return s; } }")
        kapua = quirks_for("kapua", "service/account/test/src/test/resources/features/AccountService.feature")
        algo = quirks_for("algorand-sdk")
        for variant in (kapua, algo):
            sources[listener_class(variant).replace(".", "/") + ".java"] = listener_source(variant)
        sources["ListenerEvents.java"] = r'''import java.util.*;
import io.cucumber.plugin.ConcurrentEventListener;
import io.cucumber.plugin.event.*;
import r2t.directcalls.DirectCallRecorder;
public class ListenerEvents implements EventPublisher {
    final Map<Class<?>, EventHandler<?>> handlers = new HashMap<>();
    public <T> void registerHandlerFor(Class<T> c, EventHandler<T> h) { handlers.put(c,h); }
    @SuppressWarnings("unchecked")
    <T> void fire(Class<T> c, T e) { ((EventHandler<T>)handlers.get(c)).receive(e); }
    static class Step implements PickleStepTestStep {
        final String id; Step(String id) { this.id=id; } public String getId() { return id; }
    }
    static class Hook implements TestStep { public String getId() { return "hook"; } }
    static class Case implements TestCase {
        final List<TestStep> steps; final List<String> tags;
        Case(List<TestStep> steps, String... tags) { this.steps=steps; this.tags=Arrays.asList(tags); }
        public List<TestStep> getTestSteps() { return steps; }
        public List<String> getTags() { return tags; }
    }
    static void expect(int wanted) {
        if (DirectCallRecorder.step != wanted)
            throw new AssertionError("wanted step " + wanted + ", got " + DirectCallRecorder.step);
    }
    public static void main(String[] args) throws Exception {
        ListenerEvents p = new ListenerEvents();
        ((ConcurrentEventListener)Class.forName(args[0]).getDeclaredConstructor().newInstance()).setEventPublisher(p);
        boolean prerequisite = Boolean.parseBoolean(args[1]);
        Step first = new Step("first"), second = new Step("second"); Hook hook = new Hook();
        Case setup = new Case(Arrays.asList(hook,first), "@setup");
        Case target = new Case(Arrays.asList(hook,first,hook,second));
        p.fire(TestCaseStarted.class,new TestCaseStarted()); expect(-1);
        p.fire(TestStepStarted.class,new TestStepStarted(setup,first)); expect(prerequisite ? -1 : 0);
        // The same production call in the following target must retain its target tag.
        p.fire(TestStepFinished.class,new TestStepFinished(setup,first)); expect(-1);
        p.fire(TestCaseStarted.class,new TestCaseStarted()); expect(-1);
        p.fire(TestStepStarted.class,new TestStepStarted(target,hook)); expect(-1);
        p.fire(TestStepStarted.class,new TestStepStarted(target,first)); expect(0);
        p.fire(TestStepFinished.class,new TestStepFinished(target,first)); expect(-1);
        p.fire(TestStepStarted.class,new TestStepStarted(target,hook)); expect(-1);
        p.fire(TestStepStarted.class,new TestStepStarted(target,second)); expect(1);
        p.fire(TestStepFinished.class,new TestStepFinished(target,second)); expect(-1);
        // An ordinary case with no prerequisite also starts at zero, including repeated outline cases.
        p.fire(TestCaseStarted.class,new TestCaseStarted());
        p.fire(TestStepStarted.class,new TestStepStarted(target,first)); expect(0);
        p.fire(TestStepFinished.class,new TestStepFinished(target,first)); expect(-1);
    }
}
'''
        paths = []
        for relative, source in sources.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
            paths.append(str(path))
        cp = subprocess.run([javac, "--release", "8", "-d", str(root), *paths],
                            capture_output=True, text=True, timeout=60)
        check("step-listener fixture compiles with Java 8 source API", cp.returncode == 0, cp.stderr)
        if cp.returncode:
            return
        for variant, guarded in ((kapua, True), (algo, False)):
            cp = subprocess.run([java, "-cp", str(root), "ListenerEvents", listener_class(variant),
                                 str(guarded).lower()], capture_output=True, text=True, timeout=30)
            check("listener events preserve target, hook and case-reset tags; prerequisite exclusion="
                  + str(guarded), cp.returncode == 0, cp.stderr)
        check("non-prerequisite Java listener bytes are unchanged",
              listener_source(algo) == LISTENER_TEMPLATE.format(package=algo.runner_package, klass=LISTENER_CLASS))


def selftest() -> int:
    """The fold, checked against documents rather than against itself.

    Everything here is a claim about bytes cucumber writes, so every check
    drives the real functions over a real-shaped document: the statuses come
    from cucumber-jvm's own vocabulary, the outline shape from a two-row
    Examples table, and the joins (Background, hooks) from the element
    layout cucumber's JSON formatter emits.  What NEEDS the container —
    that cucumber 7.8.0 in the epubcheck image really does stamp an outline
    row with the row's line — is the S4 gate's, and the constants that
    reading rests on are pinned here so a drive-by edit fails a named check
    first.
    """
    import argparse
    import tempfile

    from ..bench import runner as _runner
    from ..core.boundary import PRODUCTION, Boundary, load_boundary
    from ..core.gherkin import parse_feature_file
    from . import base as _base

    here = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    boundary_path = os.path.join(here, "config", "boundary_epubcheck.yml")

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refused(fn):
        try:
            fn()
            return False
        except CucumberStackRefused:
            return True

    # ------------------------------------------------------ the vocabulary
    check("every cucumber status maps into the five-value vocabulary the "
          "other two stacks' records are read in",
          set(STEP_RESULT_BY_STATUS.values()) <= set(_base.STEP_RESULTS),
          str(sorted(set(STEP_RESULT_BY_STATUS.values()))))
    check("ambiguous folds to failed -- a glue collision is a failure of the "
          "submission, and the fold must rank it as one",
          STEP_RESULT_BY_STATUS["ambiguous"] == "failed")
    check("`unknown` is deliberately NOT in the table: a status this stack "
          "cannot read voids the run instead of being guessed at",
          "unknown" not in STEP_RESULT_BY_STATUS)

    # --------------------------------------------------- the document fold
    def step(status, name="a font", line=7, keyword="Given ", **kw):
        block = {"status": status, "duration": 12000000}
        block.update(kw)
        return {"line": line, "name": name, "keyword": keyword,
                "match": {"location": "Steps.given()"}, "result": block}

    def document(*elements, uri="classpath:_bench_item.feature"):
        return [{"uri": uri, "name": "F", "line": 1, "keyword": "Feature",
                 "elements": list(elements)}]

    def scenario(line, *steps, keyword="Scenario", name="S", **kw):
        el = {"line": line, "name": name, "description": "", "type":
              "scenario", "keyword": keyword, "steps": list(steps)}
        el.update(kw)
        return el

    recs, voids = records_from_json(document(
        scenario(6, step("passed"), step("passed", line=8))))
    check("a passing scenario yields one record whose keys are exactly "
          "RECORD_FIELDS -- derived from the schema, not retyped",
          len(recs) == 1 and set(recs[0]) == set(_base.RECORD_FIELDS),
          str(sorted(recs[0])))
    check("...and each step's keys are exactly STEP_FIELDS",
          all(set(s) == set(_base.STEP_FIELDS) for s in recs[0]["steps"]))
    check("...and it folds to passed through the SHARED record_outcome",
          _hz.record_outcome(recs[0]) == "passed" and not voids)
    check("the document's own verdict uses the two-value vocabulary",
          recs[0]["scenario_result"] in _base.SCENARIO_RESULTS
          and recs[0]["scenario_result"] == "passed")
    check("coverage is null when it was not requested -- readers tell "
          "'not measured' from 'measured, empty' by exactly this",
          recs[0]["coverage"] is None)
    check("the keyword is stripped of cucumber's trailing space, so a "
          "record reads `Given` and not `Given `",
          recs[0]["steps"][0]["keyword"] == "Given")
    check("nanoseconds become seconds",
          recs[0]["steps"][0]["seconds"] == 0.012
          and recs[0]["seconds"] == 0.024, str(recs[0]["seconds"]))

    # -- the four statuses that are not `passed`, each through the fold
    table = (("failed", "failed"), ("undefined", "undefined_steps"),
             ("pending", "pending"), ("skipped", "not_passed"),
             ("ambiguous", "failed"))
    for status, outcome in table:
        recs, _v = records_from_json(document(
            scenario(6, step("passed"), step(status, line=8))))
        check(f"a {status} step folds the scenario to {outcome}",
              _hz.record_outcome(recs[0]) == outcome,
              _hz.record_outcome(recs[0]))

    # -- the exception, which is the whole point of preserving ambiguous
    trace = ("io.cucumber.core.runner.AmbiguousStepDefinitionsException: "
             "\"a font\" matches more than one step definition:\n"
             "  ↳ Steps.given()\n  ↳ Retained.given()\n"
             "\tat io.cucumber.core.runner.PickleStepDefinitionMatch.run\n"
             "\t... 17 more")
    recs, _v = records_from_json(document(
        scenario(6, step("ambiguous", line=8, error_message=trace))))
    exc = recs[0]["steps"][0]["exception"]
    check("an ambiguous step keeps cucumber's exception CLASS on the record",
          exc["class"] == AMBIGUOUS_EXCEPTION, str(exc)[:120])
    check("...and the message keeps both colliding definitions and drops "
          "the stack frames",
          "Retained.given()" in exc["message"]
          and "at io.cucumber" not in exc["message"], exc["message"])
    recs, _v = records_from_json(document(
        scenario(6, step("failed", line=8,
                         error_message="java.lang.AssertionError: v was 2\n"
                                       "\tat Steps.given(Steps.java:41)"))))
    exc = recs[0]["steps"][0]["exception"]
    check("a failed step's class is read off cucumber's own message",
          exc == {"class": "java.lang.AssertionError", "message":
                  "java.lang.AssertionError: v was 2"}, str(exc))
    recs, _v = records_from_json(document(
        scenario(6, step("failed", line=8, error_message="boom"))))
    check("a failure whose message names no type still records one, rather "
          "than an empty class that reads as 'nobody looked'",
          recs[0]["steps"][0]["exception"] == {"class": UNTYPED_EXCEPTION,
                                               "message": "boom"})
    recs, _v = records_from_json(document(
        scenario(6, step("undefined", line=8))))
    check("an undefined step carries no exception -- there was no code to "
          "raise one", recs[0]["steps"][0]["exception"] is None)

    # -- the Background join
    background = {"line": 3, "name": "", "description": "", "type":
                  "background", "keyword": "Background",
                  "steps": [step("failed", name="a store", line=4,
                                 error_message="java.lang.IllegalState: x")]}
    recs, _v = records_from_json(document(
        background, scenario(6, step("skipped", line=7))))
    check("a Background element's steps are folded into the scenario that "
          "follows it -- one record, not two",
          len(recs) == 1 and len(recs[0]["steps"]) == 2
          and recs[0]["steps"][0]["text"] == "a store", str(recs))
    check("...so a failed Background is why the scenario failed, instead of "
          "a record showing only skipped steps",
          _hz.record_outcome(recs[0]) == "failed")
    check("...and the record's line is the SCENARIO's, never the "
          "Background's -- the fold selects on that identity",
          recs[0]["scenario_line"] == 6)
    recs, _v = records_from_json(document(
        background, scenario(6, step("passed", line=7)),
        scenario(11, step("passed", line=12))))
    check("a Background is claimed by ONE scenario: cucumber re-emits it "
          "per pickle, so carrying it forward would double-count it",
          [len(r["steps"]) for r in recs] == [2, 1],
          str([len(r["steps"]) for r in recs]))

    # -- hooks
    hook_failed = {"result": {"status": "failed", "duration": 1000000,
                              "error_message": "java.lang.RuntimeException: "
                                               "no fixture root"},
                   "match": {"location": "Configuration.before()"}}
    hook_ok = {"result": {"status": "passed", "duration": 1000},
               "match": {"location": "Configuration.after()"}}
    recs, _v = records_from_json(document(
        scenario(6, step("skipped", line=7), before=[hook_failed],
                 after=[hook_ok])))
    check("a hook that did not pass is on the record, with the method that "
          "ran as its text",
          [s["text"] for s in recs[0]["steps"]]
          == ["Configuration.before()", "a font"], str(recs[0]["steps"]))
    check("...and it decides the scenario rather than leaving a row whose "
          "steps are all skipped with no reason on it",
          _hz.record_outcome(recs[0]) == "failed")
    check("a hook that PASSED is not on the record -- nobody authored it",
          all(s["text"] != "Configuration.after()"
              for s in recs[0]["steps"]))

    timed_background = {
        "line": 3, "name": "", "description": "", "type": "background",
        "keyword": "Background",
        "steps": [step("passed", name="fixture", line=4,
                       duration=2_000_000)]}
    timed_hook_before = {
        "result": {"status": "passed", "duration": 5_000_000},
        "match": {"location": "Configuration.before()"}}
    timed_hook_after = {
        "result": {"status": "passed", "duration": 7_000_000},
        "match": {"location": "Configuration.after()"}}
    timings = scenario_timings_from_json(document(
        timed_background,
        scenario(6, step("passed", duration=3_000_000),
                 before=[timed_hook_before], after=[timed_hook_after])))
    check("suite timing includes passed hooks and Background work that the "
          "verdict-oriented record intentionally omits",
          len(timings) == 1
          and timings[0]["duration_ns"] == 17_000_000
          and timings[0]["seconds"] == 0.017
          and timings[0]["scenario_result"] == "passed",
          str(timings))
    check("a negative cucumber duration is refused rather than subtracted "
          "from the reality-spike timing",
          refused(lambda: scenario_timings_from_json(document(
              scenario(6, step("passed", duration=-1))))))

    # -- the outline, folded through the shared fold
    outline = document(
        scenario(14, step("passed", line=11), keyword="Scenario Outline",
                 name="Rows 1"),
        scenario(15, step("failed", line=11, error_message="AssertionError"),
                 keyword="Scenario Outline", name="Rows 2"))
    recs, _v = records_from_json(outline)
    run = _hz.RunResult(exit_code=1, stdout="", wall_seconds=0.2,
                        records=recs, expected_line=9,
                        expected_lines=[9, 14, 15])
    check("an outline yields one record per Examples ROW, at the row's own "
          "line", [r["scenario_line"] for r in recs] == [14, 15])
    check("one failing Examples row folds the whole outline to failed",
          run.outcome == "failed", run.outcome)
    all_green = _hz.RunResult(
        exit_code=0, stdout="", wall_seconds=0.2,
        records=records_from_json(document(
            scenario(14, step("passed"), keyword="Scenario Outline"),
            scenario(15, step("passed"), keyword="Scenario Outline")))[0],
        expected_line=9, expected_lines=[9, 14, 15])
    check("...and an outline every row of which passed, with the exit code "
          "agreeing, is the only way to a pass", all_green.outcome == "passed")
    forged = _hz.RunResult(
        exit_code=0, stdout="", wall_seconds=0.2,
        records=records_from_json(document(
            scenario(99, step("passed"))))[0],
        expected_line=9, expected_lines=[9, 14, 15])
    check("a record on a line this harness never synthesised is excluded by "
          "the shared identity fold, wherever in the document it sits",
          forged.outcome == "no_scenario_ran", forged.outcome)

    # -- the void
    recs, voids = records_from_json(document(
        scenario(6, step("passed"), step("unknown", line=8))))
    check("an unrecognised status voids the record: no steps, so the fold "
          "reads `no_steps_ran` -- 'we did not measure this'",
          recs[0]["steps"] == [] and _hz.record_outcome(recs[0])
          == "no_steps_ran")
    voided = _hz.RunResult(exit_code=0, stdout="", wall_seconds=0.1,
                           records=recs, expected_line=6,
                           expected_lines=[6])
    check("...and a voided run can never read as a pass, whatever the exit "
          "code said", voided.outcome == "no_steps_ran", voided.outcome)
    check("the void names the status and the line it came from, so the row "
          "says which value it was",
          voids == [{"feature_file": "classpath:_bench_item.feature",
                     "scenario_line": 6, "statuses": ["unknown"]}], str(voids))
    check("...and the note that carries it into the captured output is "
          "namespaced and quotes the vocabulary it checked against",
          VOID_NOTE in void_note(voids)
          and "'unknown'" in void_note(voids).replace('"', "'"),
          void_note(voids))
    _r, voids = records_from_json(document(
        scenario(6, step("passed"), before=[{"result": {"status": "weird"}}])))
    check("a hook wearing an unknown status voids the run too -- the "
          "vocabulary check covers every status the fold would read",
          [v["statuses"] for v in voids] == [["weird"]], str(voids))

    # ------------------------------------------------------------- quirks
    check("an unknown project is refused rather than given epubcheck's "
          "surefire assumptions", refused(lambda: quirks_for("metasfresh")))
    epub, algo = quirks_for("epubcheck"), quirks_for("algorand-sdk")
    offline = quirks_for("algorand-sdk", "features/unit/offline.feature")
    check("the direct-invocation agent is a per-project switch: ON for "
          "algorand-sdk (both runners), OFF for epubcheck, and never on for "
          f"a fork whose JDK cannot load a `--release {_dc.JAVA_RELEASE}` "
          "class file -- epubcheck's is 8, and a JVM handed an agent it "
          "cannot read refuses to start before any test runs",
          algo.direct_call_agent and offline.direct_call_agent
          and not epub.direct_call_agent
          and epub.jdk_major < int(_dc.JAVA_RELEASE)
          and all(q.jdk_major >= int(_dc.JAVA_RELEASE)
                  for q in QUIRKS.values() if q.direct_call_agent))
    check("the JSON plugin path is DERIVED from the fork's working "
          "directory, so the path cucumber writes and the path the harness "
          "reads cannot disagree",
          epub.json_plugin == "json:../r2t-cucumber.json"
          and algo.json_plugin == "json:target/r2t-cucumber.json",
          f"{epub.json_plugin} {algo.json_plugin}")
    check("the two projects' JDKs are recorded, and they differ -- "
          "algorand's pom compiles with `--release`, which JDK 8 has not",
          (epub.jdk_major, algo.jdk_major) == (8, 11))
    check("neither project's runner options ask cucumber to publish -- the "
          "image runs with no egress",
          not any("publish" in o for q in (epub, algo)
                  for o in q.runner_options))

    # ------------------------------------------- the step-tag listener
    check("a runner whose fork carries the agent registers the step-tag "
          "listener in its OWN plugin list -- never `-Dcucumber.plugin`, "
          "which the project's own runner already conflicts with",
          f'plugin = {{"{algo.json_plugin}", '
          f'"{listener_class(algo)}"}}' in runner_source(algo, "algorand-sdk")
          and listener_class(algo) == "com.algorand.algosdk.unit.R2TStepTagListener")
    check("a project with no agent keeps its runner bytes: epubcheck's fork "
          f"is a JDK {epub.jdk_major}, it records no direct calls, and a "
          "listener there would move its seed and substrate baseline for no "
          "collected data",
          runner_source(epub, "epubcheck").count("plugin = {") == 1
          and LISTENER_CLASS not in runner_source(epub, "epubcheck")
          and installed_sources_for("epubcheck") == {
              epub.runner_rel: runner_source(epub, "epubcheck")})
    check("the listener sits in the runner's own package, beside it, so it "
          "is inside whatever boundary entry retains the runner",
          listener_rel(algo)
          == "src/test/java/com/algorand/algosdk/unit/R2TStepTagListener.java"
          and listener_source(algo).startswith(
              f"package {algo.runner_package};"))
    check("the listener reaches the recorder by reflection only -- the agent "
          "jar is bind-mounted at a runtime path and is on no compile "
          "classpath -- and is a no-op when no agent is attached",
          'Class.forName("r2t.directcalls.DirectCallRecorder")'
          in listener_source(algo)
          and '"setStep", int.class' in listener_source(algo)
          and "r2t.directcalls" not in listener_source(algo).split(
              "Class.forName", 1)[0])
    check("Java 8 source: the fork that compiles it is a `--release 8` "
          "javac, so no `var` and no diamond-on-anonymous",
          not re.search(r"\bvar\s+\w+\s*=", listener_source(algo)))
    algorand_installed = installed_sources_for("algorand-sdk")
    check("Algorand installs a listener beside each of its two runners",
          list(algorand_installed) == [
              algo.runner_rel, listener_rel(algo),
              offline.runner_rel, listener_rel(offline)])
    _check_listener_events(check)
    kapua_installed = installed_sources_for("kapua")
    kapua_variants = runner_variants_for("kapua")
    check("Kapua's five runners in one package share ONE listener file: the "
          "install is keyed by path, not by runner",
          len(kapua_variants) == 18
          and sum(rel.endswith("/" + LISTENER_CLASS + ".java")
                  for rel in kapua_installed) == 14
          and len(kapua_installed) == 32
          and all(variant.runner_rel in kapua_installed
                  for variant in kapua_variants),
          f"{len(kapua_variants)} runners, {len(kapua_installed)} files")
    check("the runner classes sit in the package whose glue they must scan",
          epub.runner_rel.endswith(
              epub.runner_package.replace(".", "/") + "/"
              + epub.runner_class + ".java")
          and algo.runner_rel.endswith(
              algo.runner_package.replace(".", "/") + "/"
              + algo.runner_class + ".java"))
    check("Algorand has one runner per admitted glue package, while the "
          "other Java project still has one",
          runner_variants_for("algorand-sdk") == (algo, offline)
          and runner_variants_for("algorand-sdk", stripped=False)
          == (algo, _ALGORAND_INTEGRATION_UNSTRIPPED)
          and runner_variants_for("epubcheck") == (epub,))
    from ..java.algorand import OFFLINE_WORKSPACE
    check("both identities of the canonical offline feature route to "
          "integration glue",
          algo.runner_package == "com.algorand.algosdk.unit"
          and offline.runner_package == "com.algorand.algosdk.integration"
          and quirks_for("algorand-sdk", OFFLINE_WORKSPACE) is offline
          and quirks_for("algorand-sdk", "features/unit/other.feature")
          is algo)

    account_feature = ("service/account/test/src/test/resources/features/"
                       "AccountService.feature")
    account = quirks_for("kapua", account_feature)
    check("Kapua uses its measured module, runner package and setup prerequisite",
          account.module_rel == "service/account/test"
          and account.runner_package == "org.eclipse.kapua.service.account.test"
          and account.runner_class == "R2TBenchRunAccountUnitTest"
          and account.prerequisite_tag == "@setup"
          and account.jdk_major == 17 and not account.select_by_name)
    check("Kapua JSON resolves within the selected module's basedir",
          account.fork_workdir == "" and account.fork_workdir_pom is None
          and account.json_plugin == "json:target/r2t-cucumber.json"
          and account.json_rel == "service/account/test/target/r2t-cucumber.json")
    account_argv = shlex.split(test_command(account, "Create an account"))
    check("Kapua executes exactly the selected Maven module and generated runner",
          account_argv[account_argv.index("-pl") + 1] == "service/account/test"
          and "-am" not in account_argv
          and "-Dtest=org.eclipse.kapua.service.account.test.R2TBenchRunAccountUnitTest"
          in account_argv
          and "-Dcheckstyle.skip=true" in account_argv
          and "-Dmaven.buildNumber.skip=true" in account_argv)
    account_compile = shlex.split(compile_command(account))
    check("Kapua installs rebuilt reactor dependencies before its separate test fork",
          "install" in account_compile and "-am" in account_compile
          and "-DskipTests" in account_compile
          and account_compile[account_compile.index("-pl") + 1]
          == "service/account/test")
    from types import SimpleNamespace
    empty_compile_commands = []
    def empty_compile(command, timeout):
        empty_compile_commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    empty_harness = SimpleNamespace(
        boundary=SimpleNamespace(project="kapua"), quirks=account,
        workdir_root="/work", runner=SimpleNamespace(run=empty_compile))
    empty_index = CucumberHarness.index_paths(empty_harness, [])
    check("an empty Kapua candidate still rebuilds its stripped dependency artifacts",
          empty_compile_commands == [compile_command(account)]
          and empty_index["errors"] == {})
    account_suite = next(suite for suite in _KAPUA_SUITES
                         if account_feature in suite.features)
    account_glue = json.loads("[" + account.runner_options[0][8:-1] + "]")
    check("Kapua unit glue keeps the native parent scan without a duplicate generated scan",
          account.glue_rel.startswith("service/account/test/src/test/java/")
          and account.glue_rel.endswith("/r2t/generated")
          and account_glue == list(account_suite.glue)
          and "org.eclipse.kapua.service.account.test" in account_glue
          and account_suite.generated_package not in account_glue)
    integration_feature = ("qa/integration/src/test/resources/features/account/"
                           "AccountTagService.feature")
    integration_suite = next(suite for suite in _KAPUA_SUITES
                             if integration_feature in suite.features)
    integration = quirks_for("kapua", integration_feature)
    integration_glue = json.loads("[" + integration.runner_options[0][8:-1] + "]")
    check("Kapua integration glue still adds the generated package outside native roots",
          integration_glue[:-1] == list(integration_suite.glue)
          and integration_glue[-1] == integration_suite.generated_package
          and integration_glue.count(integration_suite.generated_package) == 1)
    held_feature = ("qa/integration/src/test/resources/features/datastore/"
                    "DatastoreMetricStore.feature")
    check("the held Datastore diagnostic has a runner without joining the admitted map",
          quirks_for("kapua", held_feature).runner_class
          == "R2TBenchRunDatastoreTransportI9nTest"
          and held_feature not in _kapua.FEATURE_SUITES
          and len(_kapua.FEATURE_SUITES) == 37
          and len(_kapua.SUITES) == 17)
    check("Kapua does not guess a runner for an unbound feature",
          refused(lambda: quirks_for("kapua", "unknown.feature")))
    check("Kapua class names resolve from removable src/main glue roots",
          class_name("service/account/test-steps/src/main/java/"
                     "org/eclipse/kapua/service/account/steps/AccountServiceSteps.java",
                     "kapua")
          == "org.eclipse.kapua.service.account.steps.AccountServiceSteps")
    check("Kapua declares generated features as volatile and module targets as build output",
          "service/account/test/src/test/resources/_bench_item.feature"
          in _repo.CUCUMBER_SUBSTRATE_VOLATILE_BY_PROJECT["kapua"]
          and "service/account/test-steps/target"
          in _repo.CUCUMBER_BUILD_ROOTS_BY_PROJECT["kapua"]
          and "service/account/test-steps/target"
          not in _repo.CUCUMBER_SUBSTRATE_ROOTS_BY_PROJECT["kapua"])

    # -- the name filter, which is the algorand quirk's whole risk
    check("a plain scenario's name filter is its title, escaped and "
          "anchored", filter_name_regex("Adding a product (2)")
          == r"^Adding\ a\ product\ \(2\)$",
          filter_name_regex("Adding a product (2)"))
    pattern = filter_name_regex("Rows <n> of <table>")
    check("an outline's placeholders become `.*`, so the filter matches "
          "every SUBSTITUTED pickle name cucumber generates",
          re.match(pattern, "Rows 1 of orders")
          and re.match(pattern, "Rows 27 of items")
          and not re.match(pattern, "Other rows 1 of orders"), pattern)
    # The literals BETWEEN two placeholders, which a NON-capturing
    # `re.split` silently drops.  Compared as a whole string rather than
    # only matched against substituted names, because every row of the
    # outline matches the truncated `^Rows\ .*$` too: the defect is
    # invisible to a check that only asks "does a real pickle name match".
    check("...and every literal BETWEEN placeholders survives, so the "
          "filter is the title's whole skeleton and not its first word",
          pattern == r"^Rows\ .*\ of\ .*$"
          and filter_name_regex("x <a> MID <b> y") == r"^x\ .*\ MID\ .*\ y$",
          f"{pattern} / {filter_name_regex('x <a> MID <b> y')}")
    check("...which is what keeps a name sharing only the FIRST literal "
          "out -- the selection a truncated filter would make on the "
          "`requirement_to_test` path, where the file is the solution's "
          "and may hold more than the scenario the fold expects",
          not re.match(pattern, "Rows 1 for orders")
          and not re.match(pattern, "Rows 1"), pattern)

    # --------------------------------------------- the workspace's paths
    check("the synthesised feature is the file repo.py exempts BY NAME -- "
          "it sits inside a substrate root, which is the one thing the "
          "behave twin never had to deal with",
          FEATURE_REL in _repo.CUCUMBER_SUBSTRATE_VOLATILE
          and any(FEATURE_REL.startswith(r + "/")
                  for r in _repo.CUCUMBER_SUBSTRATE_ROOTS))
    check("...and so is the record file this stack writes after folding",
          _hz.RECORD_REL in _repo.CUCUMBER_SUBSTRATE_VOLATILE)
    check("cucumber's document and Maven's copy of the feature are under a "
          "BUILD root and under no substrate root, so they need no "
          "exemption and can be swept per item",
          all(any(rel == b or rel.startswith(b + "/")
                  for b in _repo.CUCUMBER_BUILD_ROOTS)
              and not any(rel.startswith(r + "/")
                          for r in _repo.CUCUMBER_SUBSTRATE_ROOTS)
              for rel in (FEATURE_COPY_REL, epub.json_rel, algo.json_rel,
                          _dc.OUTPUT_REL)))
    check("the feature is named on the classpath, not by path -- the "
          "surefire fork's working directory is a per-project quirk and a "
          "relative path would be resolved against it",
          FEATURE_CLASSPATH == "classpath:" + os.path.basename(FEATURE_REL))

    # ------------------------------------------------ the invocation bytes
    epub_test = test_command(epub, "Adding a product")
    algo_test = test_command(algo, "Rows <n>")
    offline_test = test_command(offline, "Sign offline <kind>")
    check("`-Dcucumber.plugin` appears in NO invocation, on either project "
          "-- the JSON plugin is the harness-owned runner's",
          "-Dcucumber.plugin" not in epub_test
          and "-Dcucumber.plugin" not in algo_test
          and "-Dcucumber.plugin" not in offline_test, epub_test)
    check("every invocation is offline and batch, against the repository "
          "the image bakes",
          all(f in epub_test and f in algo_test
              for f in ("mvn -o -B",
                        f"-Dmaven.repo.local={MAVEN_LOCAL_REPO}")),
          epub_test)
    check("the scenario is selected by the synthesised feature",
          f"-Dcucumber.features={FEATURE_CLASSPATH}" in epub_test)
    check("epubcheck passes surefire the SIMPLE class name (2.18.1 matches "
          "nothing else) and algorand the FQCN (3.0.0-M5, the ART recipe)",
          "-Dtest=R2TBenchCucumberTest" in epub_test
          and "-Dtest=com.algorand.algosdk.unit.R2TBenchCucumberTest"
          in algo_test
          and "-Dtest=com.algorand.algosdk.integration.R2TBenchCucumberTest"
          in offline_test)
    check("only the project whose quirk says so filters by name, and the "
          "filter is shell-quoted -- it is a regex full of `^$\\`",
          "-Dcucumber.filter.name" not in epub_test
          and r"'-Dcucumber.filter.name=^Rows\ .*$'" in algo_test, algo_test)
    check("nothing tells cucumber to publish, and the quiet flag replaces "
          "the `cucumber.properties` the strip moves to gold",
          "-Dcucumber.publish.quiet=true" in epub_test
          and "publish=true" not in epub_test)
    check("`-DfailIfNoTests=false` is NOWHERE: a selector that matched no "
          "test is a harness fault, and the loud version of it is a failed "
          "build rather than a hundred quiet `no_scenario_ran` rows",
          "failIfNoTests" not in epub_test and "failIfNoTests" not in
          algo_test)
    check("an ordinary run says so: the agent is in the pom the strip "
          "patched, so it is the UNinstrumented run that carries a flag",
          "-Djacoco.skip=true" in epub_test
          and "-Djacoco.skip=false" in test_command(epub, "S", coverage=True)
          and "jacoco:prepare-agent" not in test_command(epub, "S",
                                                         coverage=True))
    agent = _dc.agent_option("/opt/r2t/agent.jar",
                             "/work/target/r2t-direct-calls.json")
    with_agent = test_command(epub, "S", coverage=True, agent_argline=agent)
    check("the direct-invocation agent rides ONLY on a coverage invocation, "
          "through the property the strip wrote into the argLine, as one "
          "unquoted argument (spec 2.4)",
          f"-D{AGENT_ARG_LINE_PROPERTY}={agent}" in with_agent.split()
          and AGENT_ARG_LINE_PROPERTY not in test_command(
              epub, "S", coverage=False, agent_argline=agent), with_agent)
    check("...and without a jar the invocation is byte-for-byte the one this "
          "stack has always issued: the property's empty default resolves "
          "to nothing",
          AGENT_ARG_LINE_PROPERTY not in test_command(epub, "S", coverage=True)
          and test_command(epub, "S", coverage=True).split()
          == [t for t in with_agent.split()
              if not t.startswith(f"-D{AGENT_ARG_LINE_PROPERTY}=")])
    check("the compile gate is `mvn -o test-compile`, sharing the same "
          "offline prefix", compile_command(epub)
          == f"mvn -o -B -Dmaven.repo.local={MAVEN_LOCAL_REPO} test-compile",
          compile_command(epub))
    full_capture = suite_capture_argv("epubcheck")
    dry_capture = suite_capture_argv("epubcheck", dry_run=True)
    check("the full-suite reality capture has one exact offline argv",
          full_capture == (
              "mvn", "--offline", "--no-transfer-progress",
              "-Dstyle.color=never",
              f"-Dmaven.repo.local={MAVEN_LOCAL_REPO}",
              "-DreuseForks=false", "-DfailIfNoTests=true",
              "-Dsurefire.failIfNoSpecifiedTests=true",
              "-Dcucumber.plugin=json:../r2t-cucumber.json",
              "-Dcucumber.publish.quiet=true", "test"),
          str(full_capture))
    check("the dry capture adds the uninstrumented switch, exact upstream "
          "runner selector, dry-run switch and its own output",
          dry_capture == (
              "mvn", "--offline", "--no-transfer-progress",
              "-Dstyle.color=never",
              f"-Dmaven.repo.local={MAVEN_LOCAL_REPO}",
              "-DreuseForks=false", "-DfailIfNoTests=true",
              "-Dsurefire.failIfNoSpecifiedTests=true",
              "-Djacoco.skip=true", "-Dtest=RunCucumberTest",
              "-Dcucumber.execution.dry-run=true",
              "-Dcucumber.plugin=json:../r2t-cucumber-dry-run.json",
              "-Dcucumber.publish.quiet=true", "test"),
          str(dry_capture))
    check("the EPUBCheck suite-capture binding refuses Algorand rather than "
          "leaking this runner/plugin override across the shared stack",
          refused(lambda: suite_capture_argv("algorand-sdk")))

    account_capture = suite_capture_argv(
        "kapua", source_feature="service/account/test/src/test/resources/features/AccountService.feature")
    check("Kapua native capture uses the measured original Account runner and isolated module",
          account_capture == (
              "mvn", "-o", "-B", "-Dmaven.repo.local=/opt/m2",
              "-Dcheckstyle.skip=true", "-Dmaven.buildNumber.skip=true",
              "-pl", "service/account/test",
              "-Dtest=org.eclipse.kapua.service.account.test.RunAccountUnitTest",
              "-Dcucumber.filter.tags=@env_none and not (@env_docker or @env_docker_base)",
              "-Dcucumber.publish.quiet=true", "-Djacoco.skip=true", "-DfailIfNoTests=true",
              "-Dcucumber.execution.dry-run=false",
              "-Dcucumber.plugin=json:target/r2t-cucumber.json", "test"))
    check("Kapua capture requires an admitted feature and excludes held suites",
          refused(lambda: suite_capture_argv("kapua"))
          and all(refused(lambda feature=feature: suite_capture_argv(
              "kapua", source_feature=feature))
              for suite in _kapua.DIAGNOSTIC_SUITES for feature in suite.features))
    for suite in _kapua.SUITES:
        captures = [suite_capture_argv("kapua", source_feature=feature, dry_run=True)
                    for feature in suite.features]
        check("Kapua native capture selects only " + suite.upstream_runner_class,
              len(set(captures)) == 1
              and captures[0][captures[0].index("-pl") + 1] == suite.module
              and ("-Dtest=" + suite.runner_package + "." + suite.upstream_runner_class) in captures[0]
              and "-Dcucumber.execution.dry-run=true" in captures[0]
              and "-Dcucumber.plugin=json:target/r2t-cucumber-dry-run.json" in captures[0])

    # -- javac diagnostics, as Maven prints them
    log = ("[INFO] Compiling 3 source files\n"
           "[ERROR] COMPILATION ERROR :\n"
           "[ERROR] /work/src/test/java/org/w3c/epubcheck/test/S.java:[12,5] "
           "cannot find symbol\n"
           "[ERROR] /work/src/test/java/org/w3c/epubcheck/test/S.java:[19,7] "
           "cannot find symbol\n"
           "[ERROR] /elsewhere/T.java:[3,1] class expected\n")
    errors = compile_errors(log, "/work")
    check("a javac diagnostic comes back keyed on the WORKSPACE-relative "
          "path, with the first message for that file and no others",
          errors == {"src/test/java/org/w3c/epubcheck/test/S.java":
                     "12:5 cannot find symbol",
                     "/elsewhere/T.java": "3:1 class expected"}, str(errors))
    check("a build log with no diagnostics yields no errors, so a passing "
          "compile cannot route an item to parse_or_compile_error",
          compile_errors("[INFO] BUILD SUCCESS\n", "/work") == {})
    check("a written file's class name is read back out of its path -- this "
          "stack's reading of `registered_contexts`",
          class_name("src/test/java/org/w3c/epubcheck/test/S.java")
          == "org.w3c.epubcheck.test.S"
          and class_name("elsewhere/S.java") == "elsewhere/S.java")

    # ------------------------------------------------ a mini workspace
    #
    # One JaCoCo report, used twice: by `coverage_doc` below over a tree
    # holding two of its three files, and by the fake container here, which
    # writes it exactly when the invocation says the agent is on.
    report = """<?xml version="1.0" encoding="UTF-8"?>
<report name="epubcheck">
  <package name="com/adobe/epubcheck/api">
    <sourcefile name="EpubCheck.java">
      <line nr="41" mi="0" ci="3"/>
      <line nr="42" mi="4" ci="0"/>
      <line nr="44" mi="0" ci="7"/>
    </sourcefile>
    <sourcefile name="Nothing.java"><line nr="9" mi="2" ci="0"/></sourcefile>
  </package>
  <package name="org/vendored/lib">
    <sourcefile name="Helper.java"><line nr="3" mi="0" ci="9"/></sourcefile>
  </package>
</report>"""

    # What the current recorder's shutdown hook leaves: one `step` per event,
    # null for a call made outside any step (the `<init>` reached through a
    # framework frame below).  Unsorted here, so the fold's canonicalisation
    # is what the check reads.
    direct_calls_file = json.dumps({
        "schema": _dc.OUTPUT_SCHEMA, "activations": 3, "transform_failures": [],
        "events": [
            {"callee_file": "src/main/java/com/adobe/epubcheck/api/EpubCheck.java",
             "callee_line": None,
             "callee": "com.adobe.epubcheck.api.EpubCheck.check:()I",
             "caller_file": "src/test/java/org/w3c/epubcheck/test/Steps.java",
             "step": 1},
            {"callee_file": "src/main/java/com/adobe/epubcheck/api/EpubCheck.java",
             "callee_line": None,
             "callee": "com.adobe.epubcheck.api.EpubCheck.<init>:()V",
             "caller_file": None, "step": None},
            {"callee_file": "src/main/java/com/adobe/epubcheck/api/EpubCheck.java",
             "callee_line": None,
             "callee": "com.adobe.epubcheck.api.EpubCheck.<init>:()V",
             "caller_file": "src/test/java/org/w3c/epubcheck/test/Steps.java",
             "step": 0}]})

    class _FakeRunner(_hz.DockerRunner):
        """Records what it was asked; writes what cucumber would have."""

        def __init__(self, workdir="/work", root=None, document=None,
                     compile_log="[INFO] BUILD SUCCESS\n", compile_rc=0,
                     raise_timeout=False, json_rel=None, report=None,
                     json_bytes=None):
            super().__init__("fake", workdir=workdir, docker_group=False)
            self.calls: list = []
            self.root = root
            self.document = document
            self.compile_log = compile_log
            self.compile_rc = compile_rc
            self.raise_timeout = raise_timeout
            self.json_rel = json_rel
            self.report = report
            # Raw report bytes the run leaves before it exits or times out:
            # what the json plugin's file holds when the fork is killed.
            self.json_bytes = json_bytes

        def run(self, inner, env=None, timeout=900):
            _hz._docker_exec_env_args(env)
            self.calls.append((inner, dict(env or {})))
            if inner.startswith("rm -rf -- "):
                for relative in shlex.split(inner)[3:]:
                    shutil.rmtree(os.path.join(self.root, relative),
                                  ignore_errors=True)
                return subprocess.CompletedProcess([], 0, "", "")
            if "test-compile" in inner:
                return subprocess.CompletedProcess([], self.compile_rc,
                                                   self.compile_log, "")
            if "exec mvn" in inner:
                if self.json_bytes is not None:
                    path = os.path.join(self.root, self.json_rel)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as fh:
                        fh.write(self.json_bytes)
                if self.raise_timeout:
                    self.raise_timeout = False
                    raise subprocess.TimeoutExpired("mvn", timeout,
                                                    output="tail")
                if self.document is not None:
                    path = os.path.join(self.root, self.json_rel)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump(self.document, fh)
                if self.report is not None and "-Djacoco.skip=false" in inner:
                    path = os.path.join(self.root, JACOCO_XML_REL)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(self.report)
                if self.report is not None and "-javaagent:" in inner:
                    # What the agent's shutdown hook leaves: unsorted here, so
                    # the fold's canonicalisation is what the check reads.
                    path = os.path.join(self.root, _dc.OUTPUT_REL)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(direct_calls_file)
                return subprocess.CompletedProcess([], 0, "Tests run: 1", "")
            return subprocess.CompletedProcess([], 0, "killed\n", "")

    with tempfile.TemporaryDirectory() as root:
        def write(rel, text="x"):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        write("pom.xml", "<project/>\n")
        write("src/main/java/com/adobe/epubcheck/api/EpubCheck.java", "//\n")
        write("src/test/java/org/w3c/epubcheck/RunCucumberTest.java", "//\n")
        write("src/test/java/org/w3c/epubcheck/test/ParameterTypes.java", "//")
        write("src/test/resources/epub3/03-resources/files/x.opf", "<opf/>")
        write(f"{TEST_OUTPUT_DIR}/_bench_item.feature", "Feature: stale\n")
        b = load_boundary(boundary_path, repo_root=root)
        man = _repo.StripManifest(
            repo_root=root, gold_root=os.path.join(root, "_gold"),
            substrate_roots=list(_repo.CUCUMBER_SUBSTRATE_ROOTS),
            substrate_volatile=sorted(_repo.CUCUMBER_SUBSTRATE_VOLATILE),
            bytecode_roots=[], build_roots=list(_repo.CUCUMBER_BUILD_ROOTS))

        # -- constructor refusals
        check("a manifest with no build roots is refused -- it is another "
              "stack's, and the workspace under it still holds the compiled "
              "answer",
              refused(lambda: CucumberHarness(
                  _repo.StripManifest(repo_root=root, gold_root=root), b,
                  _FakeRunner())))
        other = load_boundary(boundary_path,
                              repo_root=os.path.join(root, "elsewhere"))
        check("a harness whose boundary and manifest disagree is refused "
              "(H1)",
              refused(lambda: CucumberHarness(man, other, _FakeRunner())))

        feature_src = ("Feature: Cart\n\n"
                       "  Background:\n    Given a store\n\n"
                       "  Scenario: Adding a product\n"
                       "    Then it is there\n")
        parsed = parse_feature_file("cart.feature", feature_src)
        scenario_block = parsed.scenarios[0]
        run_doc = [{"uri": FEATURE_CLASSPATH, "name": "Cart", "elements": [
            {"type": "background", "keyword": "Background", "line": 3,
             "name": "", "steps": [step("passed", name="a store", line=4)]},
            {"type": "scenario", "keyword": "Scenario", "line": 6,
             "name": "Adding a product",
             "steps": [step("passed", name="it is there", line=7)]}]}]

        runner = _FakeRunner(workdir="/srv/w7", root=root, document=run_doc,
                             json_rel=epub.json_rel)
        h = CucumberHarness(man, b, runner)
        text, expected_line, expected_lines = h.write_feature(
            parsed, scenario_block)
        check("the synthesised feature landed where the classpath URI names "
              "it", os.path.isfile(os.path.join(root, FEATURE_REL)))
        check("the harness learned the title from the file it WROTE, which "
              "is what the name filter would have to match",
              h._scenario_title == "Adding a product", str(h._scenario_title))
        check("the expected lines are derived by the SHARED derivation, off "
              "the written text",
              expected_lines == [expected_line]
              and text.split("\n")[expected_line - 1].strip()
              == "Scenario: Adding a product", str(expected_lines))

        result = h.execute(timeout=5, expected_line=expected_line,
                           expected_lines=expected_lines)
        invocation = [c for c in runner.calls if "exec mvn" in c[0]][0][0]
        check("the run is the invocation the quirk describes, launched "
              "under a recorded pid so a timeout can kill the whole tree",
              invocation.endswith("exec " + test_command(epub, ""))
              and "/tmp/r2t-cucumber-" in invocation, invocation[:100])
        check("the pid file lives outside the workspace, so no hashed root "
              "ever sees it",
              invocation.startswith("printf '%s' $$ > /tmp/r2t-cucumber-")
              and root not in invocation.split(" && ")[0],
              invocation.split(" && ")[0])
        check("cucumber's document became the run's records, Background "
              "step and all, and the fold reads a pass",
              result.outcome == "passed"
              and [s["text"] for s in result.scenario["steps"]]
              == ["a store", "it is there"], result.outcome)
        with open(os.path.join(root, _hz.RECORD_REL), encoding="utf-8") as fh:
            on_disk = [json.loads(line) for line in fh if line.strip()]
        check("...and the folded records are written where every stack "
              "keeps them, one JSON object per line",
              on_disk == result.records, str(on_disk)[:120])
        check("the previous item's copy of the feature under target/ is "
              "swept before the run, not left on the classpath",
              not os.path.exists(os.path.join(root, FEATURE_COPY_REL)))

        # -- coverage, end to end through the same seam
        cov_runner = _FakeRunner(workdir="/work", root=root,
                                 document=run_doc, json_rel=epub.json_rel,
                                 report=report)
        hc = CucumberHarness(man, b, cov_runner)
        hc.write_feature(parsed, scenario_block)
        measured = hc.execute(coverage=True, timeout=5,
                              expected_line=expected_line,
                              expected_lines=expected_lines)
        check("a coverage run attaches ONE block to every record of the "
              "run, restricted to this project's own src/main",
              measured.scenario["coverage"]["files"]
              == {"src/main/java/com/adobe/epubcheck/api/EpubCheck.java": 2},
              str(measured.scenario["coverage"]))
        check("...and an ordinary run leaves it null, which is how a reader "
              "tells 'not measured' from 'measured, nothing ran'",
              result.scenario["coverage"] is None)
        cov_invocation = [c for c in cov_runner.calls
                          if "exec mvn" in c[0]][-1][0]
        check("epubcheck's coverage invocation is byte-for-byte the one this "
              "stack has always issued -- no `-javaagent`, no property -- "
              "because its JDK 8 fork cannot load the agent "
              "(`ProjectQuirks.direct_call_agent`), and its records read "
              "`direct_calls` null: not collected",
              cov_invocation.endswith(
                  "exec " + test_command(epub, "", coverage=True))
              and AGENT_ARG_LINE_PROPERTY not in cov_invocation
              and hc.agent_jar is None
              and measured.scenario["direct_calls"] is None
              and all(r["direct_calls"] is None for r in measured.records),
              cov_invocation)
        check("an ordinary run leaves `direct_calls` null too",
              result.scenario["direct_calls"] is None
              and "-javaagent" not in invocation)

        # -- the same fake as algorand-sdk, the project whose fork loads it
        algo_b = replace(b, project="algorand-sdk")
        algo_runner = _FakeRunner(workdir="/work", root=root,
                                  document=run_doc, json_rel=algo.json_rel,
                                  report=report)
        ha = CucumberHarness(man, algo_b, algo_runner)
        ha.write_feature(parsed, scenario_block)
        collected = ha.execute(coverage=True, timeout=5,
                               expected_line=expected_line,
                               expected_lines=expected_lines)
        algo_invocation = [c for c in algo_runner.calls
                           if "exec mvn" in c[0]][-1][0]
        check("algorand-sdk's coverage invocation carries the "
              "direct-invocation agent BY DEFAULT, pointed at this worker's "
              "mount of the agent's output",
              ha.agent_jar == AGENT_JAR_RUNTIME
              and f"-D{AGENT_ARG_LINE_PROPERTY}=-javaagent:{AGENT_JAR_RUNTIME}"
              f"=/work/{_dc.OUTPUT_REL}" in algo_invocation.split(),
              algo_invocation)
        check("...and folds the agent's file into every record as "
              "`direct_calls`: the canonical section 2.5 list, unique, "
              "sorted with null before any string and the step that made "
              "each call",
              collected.scenario["direct_calls"] == [
                  {"callee_file": "src/main/java/com/adobe/epubcheck/api/"
                                  "EpubCheck.java", "callee_line": None,
                   "callee": "com.adobe.epubcheck.api.EpubCheck.<init>:()V",
                   "caller_file": None, "step": None},
                  {"callee_file": "src/main/java/com/adobe/epubcheck/api/"
                                  "EpubCheck.java", "callee_line": None,
                   "callee": "com.adobe.epubcheck.api.EpubCheck.<init>:()V",
                   "caller_file": "src/test/java/org/w3c/epubcheck/test/"
                                  "Steps.java", "step": 0},
                  {"callee_file": "src/main/java/com/adobe/epubcheck/api/"
                                  "EpubCheck.java", "callee_line": None,
                   "callee": "com.adobe.epubcheck.api.EpubCheck.check:()I",
                   "caller_file": "src/test/java/org/w3c/epubcheck/test/"
                                  "Steps.java", "step": 1}]
              and all(r["direct_calls"] == collected.scenario["direct_calls"]
                      for r in collected.records),
              str(collected.scenario["direct_calls"]))
        ha.write_feature(parsed, scenario_block)
        unmeasured = ha.execute(coverage=False, timeout=5,
                                expected_line=expected_line,
                                expected_lines=expected_lines)
        check("the previous run's report and the agent's file are swept, so "
              "a later uninstrumented run cannot inherit either",
              unmeasured.scenario["coverage"] is None
              and unmeasured.scenario["direct_calls"] is None
              and not os.path.exists(os.path.join(root, JACOCO_XML_REL))
              and not os.path.exists(os.path.join(root, _dc.OUTPUT_REL)))
        bare = CucumberHarness(man, algo_b, _FakeRunner(
            workdir="/work", root=root, document=run_doc,
            json_rel=algo.json_rel, report=report), agent_jar=None)
        bare.write_feature(parsed, scenario_block)
        without = bare.execute(coverage=True, timeout=5,
                               expected_line=expected_line,
                               expected_lines=expected_lines)
        check("a coverage run WITHOUT a jar (the section 8 comparison leg, "
              "`agent_jar=None` by name) passes no agent, records coverage, "
              "and reads `direct_calls` null -- no file, not an empty list",
              without.scenario["coverage"] is not None
              and without.scenario["direct_calls"] is None
              and "-javaagent" not in [c for c in bare.runner.calls
                                       if "exec mvn" in c[0]][-1][0])

        # -- the environment vocabulary, which is deliberately narrow
        def stdout_run(text):
            return _hz.RunResult(exit_code=1, stdout=text, wall_seconds=0.1,
                                 records=[], expected_line=7,
                                 error_markers=CUCUMBER_ERROR_MARKERS)

        check("an offline resolution failure is a container_error -- the "
              "image, not the item",
              stdout_run("[ERROR] Could not resolve dependencies for "
                         "project").outcome == "container_error")
        plugin_only = (
            "[ERROR] Plugin org.jacoco:jacoco-maven-plugin:0.8.11 or one "
            "of its dependencies could not be resolved: absent")
        offline_only = (
            "[ERROR] Cannot access central "
            "(https://repo.maven.apache.org/maven2) in offline mode")
        check("Maven 3.9.6's actual plugin-resolution wording is an "
              "environment error even though it contains none of the three "
              "older Maven markers",
              stdout_run(plugin_only).outcome == "container_error")
        check("the independent offline-mode half of that diagnostic is also "
              "an environment error",
              stdout_run(offline_only).outcome == "container_error")
        check("a JVM that could not open the direct-invocation agent jar is "
              "an environment error, not an item's `no_scenario_ran`",
              stdout_run("Error opening zip file or JAR manifest missing : "
                         f"{AGENT_JAR_RUNTIME}\nError occurred during "
                         "initialization of VM\nagent library failed to "
                         "init: instrument").outcome == "container_error"
              and stdout_run("agent library failed to init: instrument"
                             ).outcome == "container_error")
        check("both new markers are load-bearing, not vacuous additions",
              _hz.RunResult(
                  exit_code=1, stdout=plugin_only, wall_seconds=0.1,
                  records=[], expected_line=7,
                  error_markers=tuple(
                      marker for marker in CUCUMBER_ERROR_MARKERS
                      if marker != "could not be resolved"),
              ).outcome == "no_scenario_ran"
              and _hz.RunResult(
                  exit_code=1, stdout=offline_only, wall_seconds=0.1,
                  records=[], expected_line=7,
                  error_markers=tuple(
                      marker for marker in CUCUMBER_ERROR_MARKERS
                      if marker != "in offline mode"),
              ).outcome == "no_scenario_ran")
        check("a step definition that killed the fork is NOT excused as a "
              "container error",
              stdout_run("The forked VM terminated without properly saying "
                         "goodbye").outcome == "no_scenario_ran")
        check("neither is a glue class whose constructor threw",
              stdout_run("io.cucumber.core.exception.CucumberException: "
                         "Failed to instantiate").outcome
              == "no_scenario_ran")
        check("Symfony's DI vocabulary is not recognised here",
              stdout_run("Cannot autowire service").outcome
              == "no_scenario_ran")

        # -- the timeout kill is the SHARED tree-killer
        rt = _FakeRunner(workdir="/work", root=root, raise_timeout=True,
                         json_rel=epub.json_rel)
        ht = CucumberHarness(man, b, rt)
        ht.write_feature(parsed, scenario_block)
        timed = ht.execute(timeout=5)
        check("a timed-out Maven is killed by the shared subtree walker, "
              "scoped to the recorded pid -- `mvn` forks surefire, which "
              "forks the JVM the steps run in",
              timed.timed_out and timed.timeout_cleanup == "killed"
              and "/proc/" in rt.calls[-1][0] and "pgrep" not in rt.calls[-1][0]
              and "pkill -f" not in rt.calls[-1][0])

        # -- the json plugin creates its report at run start and fills it at
        # run end, so a fork killed in between leaves it empty or cut short
        whole_doc = json.dumps(run_doc).encode("utf-8")

        def killed_run(raw, timed=True):
            harness = CucumberHarness(man, b, _FakeRunner(
                workdir="/work", root=root, raise_timeout=timed,
                json_rel=epub.json_rel, json_bytes=raw))
            harness.write_feature(parsed, scenario_block)
            return harness.execute(timeout=5, expected_line=expected_line,
                                   expected_lines=expected_lines)

        for label, raw in (("an empty", b""),
                           ("a partial", whole_doc[:len(whole_doc) // 2]),
                           ("a non-UTF-8", b"\xff\xfe[")):
            cut = killed_run(raw)
            check(f"{label} report left by a timed-out fork records the "
                  "timeout with no records, and names the unreadable report "
                  "in the output",
                  cut.timed_out and cut.outcome == "timeout"
                  and cut.records == []
                  and "unreadable after the timeout kill" in cut.stdout,
                  f"{cut.outcome} {cut.records} {cut.stdout[-120:]!r}")
        complete = killed_run(whole_doc)
        check("a complete report under a timeout is still read: its records "
              "are kept and the outcome stays timeout",
              complete.outcome == "timeout"
              and [s["text"] for s in complete.scenario["steps"]]
              == ["a store", "it is there"]
              and "unreadable" not in complete.stdout, complete.outcome)

        def raises_value_error(fn):
            try:
                fn()
                return False
            except ValueError:
                return True

        check("a run that finished with an unreadable report still raises: "
              "only the timeout explains a cut-short report",
              raises_value_error(lambda: killed_run(
                  whole_doc[:len(whole_doc) // 2], timed=False))
              and raises_value_error(lambda: killed_run(b"", timed=False)))

        # -- run_solution end to end (container faked)
        sol = _hz.Solution(files=[
            _hz.SourceFile("src/test/java/org/w3c/epubcheck/test/S.java",
                           "package org.w3c.epubcheck.test;\n"),
            _hz.SourceFile("src/main/java/com/adobe/epubcheck/api/"
                           "EpubCheck.java", "// patched\n")])
        h2 = CucumberHarness(man, b, _FakeRunner(
            workdir="/work", root=root, document=run_doc,
            json_rel=epub.json_rel))
        out = h2.run_solution(parsed, scenario_block, sol, timeout=5)
        check("a production-path file is refused and the glue class is "
              "written",
              out["written_files"]
              == ["src/test/java/org/w3c/epubcheck/test/S.java"]
              and any(r["why"].startswith("not_test_code")
                      for r in out["rejected_files"]),
              str(out["rejected_files"]))
        stale = (f"{TEST_OUTPUT_DIR}/org/w3c/epubcheck/container/"
                 "CandidateOne$Helper.class")
        stale_root = (f"{TEST_OUTPUT_DIR}/org/w3c/epubcheck/"
                      "UnexpectedTopLevel.class")
        stale_shadow = (f"{TEST_OUTPUT_DIR}/com/adobe/epubcheck/api/"
                        "MismatchedDeclaredPackage.class")
        retained = "target/classes/com/adobe/epubcheck/api/EpubCheck.class"
        write(stale, "candidate one")
        write(stale_root, "candidate one top-level")
        write(stale_shadow, "candidate one shadow")
        write(retained, "production")
        second = _hz.Solution(files=[
            _hz.SourceFile(
                "src/test/java/org/w3c/epubcheck/test/CandidateTwo.java",
                "package org.w3c.epubcheck.test;\n")])
        h2.run_solution(parsed, scenario_block, second, timeout=5)
        check("a second candidate cannot discover the first candidate's "
              "warm compiled glue, while production classes stay warm",
              not os.path.lexists(os.path.join(root, stale))
              and not os.path.lexists(os.path.join(root, stale_root))
              and not os.path.lexists(os.path.join(root, stale_shadow))
              and os.path.isfile(os.path.join(root, retained)))
        cleanup_calls = [command for command, _env in h2.runner.calls
                         if command.startswith("rm -rf -- ")]
        check("candidate cleanup targets exactly the test bytecode tree",
              cleanup_calls
              and all(command == "rm -rf -- target/test-classes"
                      for command in cleanup_calls), str(cleanup_calls))
        check("the result carries every key validate/runner/mutation_run "
              "read",
              {"substrate_violation", "written_files", "rejected_files",
               "feature_from_solution", "index_errors",
               "registered_contexts", "runs", "outcomes"} <= set(out))
        check("registered_contexts are the classes cucumber will scan",
              out["registered_contexts"] == ["org.w3c.epubcheck.test.S"],
              str(out["registered_contexts"]))
        frag = _hz.Solution(services_fragment={"my.ctx": {"class": "X"}})
        out2 = h2.run_solution(parsed, scenario_block, frag, timeout=5)
        check("a behat_services.yml aimed at this stack is recorded as "
              "rejected -- cucumber-picocontainer has no wiring channel",
              any(r.get("why") == "no_wiring_channel:cucumber"
                  for r in out2["rejected_files"]))

        broken = CucumberHarness(man, b, _FakeRunner(
            workdir="/work", root=root, document=run_doc,
            json_rel=epub.json_rel, compile_rc=1,
            compile_log="[ERROR] /work/src/test/java/org/w3c/epubcheck/test/"
                        "S.java:[2,1] cannot find symbol\n"))
        out3 = broken.run_solution(parsed, scenario_block, sol, timeout=5)
        row = _runner._record("t/x.feature:6", {}, {"files": []}, 0.0, out3)
        check("a solution that does not compile routes to "
              "parse_or_compile_error through the existing index_errors "
              "branch", row["outcome"] == "parse_or_compile_error",
              row["outcome"])
        empty = CucumberHarness(man, b, _FakeRunner(
            workdir="/work", root=root, json_rel=epub.json_rel))
        empty.write_feature(parsed, scenario_block)
        no_doc = empty.execute(timeout=5, expected_line=expected_line,
                               expected_lines=expected_lines)
        check("a run that wrote no document reads as no_scenario_ran, never "
              "as a pass", no_doc.outcome == "no_scenario_ran")

        # -- prepare/clear leave no per-item residue
        h.write_feature(parsed, scenario_block)
        h.clear_registration()
        check("clearing the workspace removes the synthesised feature and "
              "the record file",
              not os.path.exists(os.path.join(root, FEATURE_REL))
              and not os.path.exists(os.path.join(root, _hz.RECORD_REL)))

    # -------------------------------------------------------------- the pom
    def pom(surefire: str = "", properties: str = "") -> str:
        return ("<project xmlns='http://maven.apache.org/POM/4.0.0'>"
                f"<properties>{properties}</properties><build><plugins>"
                "<plugin><groupId>org.apache.maven.plugins</groupId>"
                "<artifactId>maven-surefire-plugin</artifactId>"
                "<version>2.18.1</version><configuration>"
                "<argLine>-Xmx1g</argLine>"
                "<workingDirectory>${project.build.directory}/test-classes"
                "</workingDirectory>"
                f"{surefire}</configuration></plugin>"
                "</plugins></build></project>")

    check("the pinned shape of the pom this project's quirk row was written "
          "against is accepted",
          refuse_witness_tampering(pom(), epub) is None)
    for knob in WITNESS_KNOBS:
        check(f"a surefire <{knob}> is refused -- {WITNESS_KNOBS[knob][:48]}",
              refused(lambda k=knob: refuse_witness_tampering(
                  pom(surefire=f"<{k}>0</{k}>"), epub)))
    for prop in WITNESS_PROPERTIES:
        check(f"...and so is the property spelling `{prop}`",
              refused(lambda p=prop: refuse_witness_tampering(
                  pom(properties=f"<{p}>true</{p}>"), epub)))
    # Driven off `WITNESS_KNOBS` rather than off the property table, because
    # a loop over the property table re-derives its negatives from the very
    # list it is checking: while `WITNESS_PROPERTIES` was written out by
    # hand it held two of five names, and `<properties><forkCount>0` --
    # exactly what a surefire user property of that spelling reaches -- was
    # ACCEPTED by both the rule and its test.
    check("every knob is refused in its ELEMENT spelling from <properties> "
          "too, whatever the property table happens to contain",
          all(refused(lambda k=knob: refuse_witness_tampering(
              pom(properties=f"<{k}>0</{k}>"), epub))
              for knob in WITNESS_KNOBS),
          str([k for k in WITNESS_KNOBS
               if not refused(lambda k=k: refuse_witness_tampering(
                   pom(properties=f"<{k}>0</{k}>"), epub))]))
    check("...and the property table SAYS so, deriving one entry per knob "
          "beside the two surefire renames",
          set(WITNESS_PROPERTIES) == set(WITNESS_KNOBS) | {
              "maven.test.failure.ignore", "surefire.rerunFailingTestsCount"},
          str(sorted(WITNESS_PROPERTIES)))
    check("`skipTests` is deliberately NOT a witness knob: algorand's "
          "pinned pom really does carry it, and skipping produces no "
          "document at all -- which the fold already reads as "
          "`no_scenario_ran`",
          "skipTests" not in WITNESS_KNOBS
          and refuse_witness_tampering(
              pom(surefire="<skipTests>true</skipTests>"), epub) is None)
    check("a moved surefire workingDirectory is refused -- it decides where "
          "cucumber writes the document this stack reads",
          refused(lambda: refuse_witness_tampering(
              pom().replace("test-classes</workingDirectory>",
                            "elsewhere</workingDirectory>"), epub)))
    check("...and so is one ADDED to a project whose quirk row says there "
          "is none", refused(lambda: refuse_witness_tampering(pom(), algo)))
    check("a knob hidden in a <profile> is found too -- a setting that only "
          "applies under a profile still applies",
          refused(lambda: refuse_witness_tampering(
              "<project xmlns='http://maven.apache.org/POM/4.0.0'>"
              "<profiles><profile><build><plugins><plugin>"
              "<artifactId>maven-surefire-plugin</artifactId>"
              "<configuration><forkCount>0</forkCount></configuration>"
              "</plugin></plugins></build></profile></profiles></project>",
              algo)))

    # -- against the corpora's REAL bytes, which is the only way to know the
    #    rule refuses tampering rather than refusing Maven.
    for project, corpus in (("epubcheck", "epubcheck"),
                            ("algorand-sdk", "algorand-java-sdk")):
        real = os.path.join(ARCHIVED_CORPORA, corpus, POM_REL)
        if not os.path.isfile(real):
            print(f"  [SKIP] no {real}, so the pinned pom could not be read")
            continue
        with open(real, encoding="utf-8") as fh:
            text = fh.read()
        check(f"the pinned {project} pom passes the witness check as it "
              f"stands", refuse_witness_tampering(
                  text, quirks_for(project)) is None)

    # ------------------------------------------------- the coverage recipe
    kapua_pom = """<project><properties>
        <jacoco.version>0.8.8</jacoco.version></properties>
        <build><plugins><plugin><artifactId>maven-surefire-plugin</artifactId>
        <configuration><argLine>--add-opens java.base/java.lang=ALL-UNNAMED
        ${argLine} --add-opens java.base/java.util=ALL-UNNAMED</argLine>
        </configuration></plugin><plugin><groupId>org.jacoco</groupId>
        <artifactId>jacoco-maven-plugin</artifactId>
        <version>${jacoco.version}</version><executions>
        <execution><id>default-prepare-agent</id><goals><goal>prepare-agent</goal>
        </goals></execution><execution><id>default-report</id><goals><goal>report</goal>
        </goals></execution></executions></plugin></plugins></build></project>"""
    kapua_patched = _kapua_pom_with_agent(kapua_pom)
    check("Kapua keeps its native JaCoCo bytes and adds only the direct-call hook",
          kapua_patched.replace(" " + AGENT_ARG_LINE_TOKEN, "", 1).replace(
              AGENT_ARG_LINE_DEFAULT + "\n    ", "", 1) == kapua_pom
          and ARG_LINE_TOKEN not in kapua_patched)
    check("the generic JaCoCo refusal remains intact and the Kapua hook is once-only",
          refused(lambda: pom_with_coverage(kapua_pom))
          and refused(lambda: _kapua_pom_with_agent(kapua_patched))
          and refused(lambda: _kapua_pom_with_agent(
              kapua_pom.replace("${argLine}", ""))))
    patched = pom_with_coverage(pom())
    check("the ART recipe keeps the project's own JVM flags and puts the "
          "late-replacement token and the agent property in front of them, "
          "JaCoCo's token FIRST",
          "<argLine>@{argLine} ${r2t.agent.argline} -Xmx1g</argLine>" in patched,
          patched)
    check("...and gives `argLine` an empty default in <properties>, without "
          "which an uninstrumented run passes the literal @{argLine} to a "
          "JVM that refuses to start",
          "<argLine></argLine>" in patched.split("</properties>")[0])
    check("...and the agent property the same empty default, for the same "
          "reason: an ordinary run passes no -D for it (spec 2.4)",
          "<r2t.agent.argline></r2t.agent.argline>"
          in patched.split("</properties>")[0]
          and patched.count(AGENT_ARG_LINE_TOKEN) == 1)
    check("...and appends the agent LAST, so within the `test` phase Maven "
          "runs surefire (declared earlier) and then reports over what it "
          "left",
          patched.index("jacoco-maven-plugin")
          > patched.index("maven-surefire-plugin")
          and "<goal>prepare-agent</goal>" in patched
          and "<phase>test</phase>" in patched)
    check("a surefire configuration with no argLine of its own gets one",
          "<argLine>@{argLine} ${r2t.agent.argline}</argLine>"
          in pom_with_coverage(
              pom().replace("<argLine>-Xmx1g</argLine>", "")))
    check("the patch refuses a pom it has already patched, and one that "
          "brought its own JaCoCo",
          refused(lambda: pom_with_coverage(patched))
          and refused(lambda: pom_with_coverage(
              pom().replace("</plugins>",
                            "<plugin><artifactId>jacoco-maven-plugin"
                            "</artifactId></plugin></plugins>"))))
    check("...and one with nowhere to put either half",
          refused(lambda: pom_with_coverage(
              pom().replace("<properties></properties>", "")))
          and refused(lambda: pom_with_coverage(
              "<project><properties/><build/></project>")))
    elsewhere = pom_with_coverage(pom(properties="<argLine>-Dfoo</argLine>"))
    check("an <argLine> that is not surefire's is left alone -- the rewrite "
          "is scoped to that plugin's own configuration block, and a "
          "project-wide search would have found this one first",
          "<argLine>-Dfoo</argLine>" in elsewhere
          and "<argLine>@{argLine} ${r2t.agent.argline} -Xmx1g</argLine>"
          in elsewhere, elsewhere)
    for project, corpus in (("epubcheck", "epubcheck"),
                            ("algorand-sdk", "algorand-java-sdk")):
        real = os.path.join(ARCHIVED_CORPORA, corpus, POM_REL)
        if not os.path.isfile(real):
            continue
        with open(real, encoding="utf-8") as fh:
            done = pom_with_coverage(fh.read())
        check(f"the recipe applies to the pinned {project} pom, and the "
              f"result still passes the witness check",
              ARG_LINE_TOKEN in done and AGENT_ARG_LINE_TOKEN in done
              and "jacoco-maven-plugin" in done
              and refuse_witness_tampering(
                  done, quirks_for(project)) is None)

    # -- the report, restricted to the project's own sources
    with tempfile.TemporaryDirectory() as cov_root:
        os.makedirs(os.path.join(cov_root, SOURCE_ROOT,
                                 "com/adobe/epubcheck/api"))
        for name in ("EpubCheck.java", "Nothing.java"):
            with open(os.path.join(cov_root, SOURCE_ROOT,
                                   "com/adobe/epubcheck/api", name),
                      "w", encoding="utf-8") as fh:
                fh.write("//\n")
        doc = coverage_doc(report, cov_root)
        check("a line counts as covered when JaCoCo says an instruction on "
              "it executed, and both halves of the block agree",
              doc == {"files": {f"{SOURCE_ROOT}/com/adobe/epubcheck/api/"
                                "EpubCheck.java": 2},
                      "units": [f"{SOURCE_ROOT}/com/adobe/epubcheck/api/"
                                "EpubCheck.java::L41",
                                f"{SOURCE_ROOT}/com/adobe/epubcheck/api/"
                                "EpubCheck.java::L44"]}, str(doc))
        check("a class the report names that is not a file in THIS "
              "workspace is dropped -- a report crediting a dependency's "
              "code to this project's scenario is the whole reason the "
              "fence exists",
              not any("vendored" in u for u in doc["units"]))
        check("...and `runner._coverage_mismatch` -- the check that refuses "
              "a row whose two halves disagree -- has nothing to report",
              _runner._coverage_mismatch(
                  doc["files"], _runner._lines_by_file(doc["units"])) == [])

    # Kapua can contain identical package/file names in different modules.
    # Their report location, not a first-match search, identifies the source.
    from ..core.boundary import Boundary
    with tempfile.TemporaryDirectory() as cov_root:
        main_modules = ("service/account/api", "service/account/internal")
        helper_module = "qa/common"
        answer_module = "service/account/test-steps"
        def module_file(module):
            return module + "/src/main/java/com/adobe/epubcheck/api/EpubCheck.java"
        kapua_boundary = Boundary(
            version=1, project="kapua", repo_root=cov_root,
            removable=[(answer_module + "/src/main/java/", "answer")],
            retained=[(helper_module + "/src/main/java/", "helper")],
            removable_config=[])
        check("missing Kapua module reports mean unmeasured coverage",
              kapua_coverage_doc(cov_root, kapua_boundary) is None)
        for module in main_modules + (helper_module, answer_module):
            source = os.path.join(cov_root, module_file(module))
            os.makedirs(os.path.dirname(source), exist_ok=True)
            with open(source, "w") as stream:
                stream.write("// fixture\n")
            xml = os.path.join(cov_root, module, JACOCO_XML_REL)
            os.makedirs(os.path.dirname(xml), exist_ok=True)
            with open(xml, "w") as stream:
                stream.write(report)
        merged = kapua_coverage_doc(cov_root, kapua_boundary)
        check("Kapua keeps same-named files module-qualified and excludes answer/helper hits",
              merged == {
                  "files": {module_file(module): 2 for module in main_modules},
                  "units": sorted(module_file(module) + "::L" + str(line)
                                  for module in main_modules for line in (41, 44))})
        removed = []
        temp_resets = []
        def reset_temp(command, timeout):
            temp_resets.append((command, timeout))
            return subprocess.CompletedProcess([], 0, "", "")
        cleaner = SimpleNamespace(boundary=kapua_boundary,
            _remove=lambda paths: removed.extend(paths),
            runner=SimpleNamespace(run=reset_temp))
        cleaner._output_paths = lambda: CucumberHarness._output_paths(cleaner)
        CucumberHarness._remove_outputs(cleaner)
        check("Kapua resets only its measured private Liquibase directory before another item",
              temp_resets == [("rm -rf -- /tmp/kapua-liquibase", 60)])
        cleaner.runner = SimpleNamespace(run=lambda *args, **kw:
            subprocess.CompletedProcess([], 1, "", "reset failed"))
        check("failed Kapua temporary reset refuses collection",
              refused(lambda: CucumberHarness._remove_outputs(cleaner)))
        check("Kapua clears production dependency XML before another item",
              all(module + "/" + JACOCO_XML_REL in removed
                  for module in main_modules + (helper_module, answer_module)))
        for module in main_modules + (helper_module, answer_module):
            with open(os.path.join(cov_root, module, JACOCO_XML_REL), "w") as stream:
                stream.write('<report name="empty"/>')
        check("existing empty Kapua reports mean measured empty coverage",
              kapua_coverage_doc(cov_root, kapua_boundary) == {"files": {}, "units": []})

        # Even an empty agent result must come from the selected suite's
        # current JVM, not a retained XML report or another module's classpath.
        for i, module in enumerate(_kapua.MODULES):
            suite_pom = os.path.join(cov_root, module, "pom.xml")
            os.makedirs(os.path.dirname(suite_pom), exist_ok=True)
            with open(suite_pom, "w") as stream:
                stream.write('<project xmlns="http://maven.apache.org/POM/4.0.0">'
                             '<groupId>org.eclipse.kapua</groupId>'
                             f'<artifactId>fixture-{i}</artifactId>'
                             '<version>2.1.0-SNAPSHOT</version></project>')
        source_map = _kapua.code_source_map(cov_root, kapua_boundary)
        mapping_path = os.path.join(cov_root, "target/r2t-code-sources.tsv")
        os.makedirs(os.path.dirname(mapping_path), exist_ok=True)
        with open(mapping_path, "w") as stream:
            stream.write(source_map)
        with open(os.path.join(cov_root, _dc.OUTPUT_REL), "w") as stream:
            json.dump({"schema": _dc.OUTPUT_SCHEMA, "activations": 0,
                       "transform_failures": [], "events": []}, stream)
        xml_rel = account.module_rel + "/target/surefire-reports/TEST-" + account.test_selector + ".xml"
        xml_path = os.path.join(cov_root, xml_rel)
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        cp = ":".join("/work/" + account.module_rel + "/target/" + x
                      for x in ("test-classes", "classes")) + ":"
        def write_classpath(value):
            with open(xml_path, "w") as stream:
                stream.write('<testsuite><properties>' + ''.join(
                    '<property name="' + key + '" value="' + value + '"/>'
                    for key in ("java.class.path", "surefire.test.class.path"))
                    + '</properties></testsuite>')
        collector = SimpleNamespace(root=cov_root, boundary=kapua_boundary,
            quirks=account, runner=SimpleNamespace(workdir="/work"),
            _abs=lambda rel: os.path.join(cov_root, rel))
        write_classpath(cp)
        check("Kapua collector joins even an empty agent set to the fresh suite classpath",
              CucumberHarness._direct_calls(collector) == [] and xml_rel in removed)
        write_classpath(cp.replace("service/account", "service/user"))
        check("Kapua collector refuses another module's classpath",
              refused(lambda: CucumberHarness._direct_calls(collector)))
        os.remove(xml_path)
        check("Kapua collector refuses agent output without a current Surefire identity",
              refused(lambda: CucumberHarness._direct_calls(collector)))

        exec_path = os.path.join(cov_root, account.module_rel, JACOCO_EXEC_REL)
        os.makedirs(os.path.dirname(exec_path), exist_ok=True)
        with open(exec_path, "w") as stream:
            stream.write("fresh execution fixture")
        commands = []
        test_rc = report_rc = 0
        report_timeout = False
        def measured_run(command, timeout):
            commands.append((command, timeout))
            if "jacoco-maven-plugin:0.8.8:report" in command:
                if report_timeout:
                    raise subprocess.TimeoutExpired(command, timeout, output="report tail")
                return subprocess.CompletedProcess([], report_rc, "report output", "")
            return subprocess.CompletedProcess([], test_rc, "test output", "")
        collections = []
        def collect_modules():
            collections.append(True)
            return merged
        measurement = SimpleNamespace(
            quirks=account, boundary=kapua_boundary, _scenario_title="S",
            runner=SimpleNamespace(run=measured_run, workdir="/work"),
            _abs=lambda rel: os.path.join(cov_root, rel), _remove_outputs=lambda: None,
            _agent_argline=lambda: None, _coverage=collect_modules,
            _direct_calls=lambda: None, _write_records=lambda records: None,
            _document=lambda: document(scenario(3, step("passed"))))
        from unittest.mock import patch
        with patch.object(time, "time", side_effect=[100, 102, 103]):
            measured = CucumberHarness.execute(measurement, coverage=True, timeout=10)
        report_call = next(call for call in commands if ":report" in call[0])
        report_argv = shlex.split(kapua_report_command(account, "/work"))
        check("Kapua's report consumes only the existing timeout remainder and one fork's data",
              measured.outcome == "passed" and report_call[1] == 8
              and "-Djacoco.dataFile=/work/service/account/test/target/jacoco.exec"
              in report_argv and "-am" in report_argv and "-o" in report_argv)
        test_rc = 1
        measured = CucumberHarness.execute(measurement, coverage=True, timeout=10)
        check("a successful report cannot erase the selected test's nonzero exit",
              measured.exit_code == 1 and measured.outcome == "passed_but_nonzero_exit")
        test_rc, report_rc = 0, 1
        check("a failed report refuses even when the scenario already passed",
              refused(lambda: CucumberHarness.execute(measurement, coverage=True, timeout=10)))
        report_rc, report_timeout = 0, True
        collection_count = len(collections)
        with patch.object(_hz, "_kill_process_tree", return_value={"fixture": "killed"}) as kill:
            measured = CucumberHarness.execute(measurement, coverage=True, timeout=10)
        check("a report timeout retains test output and kills the recorded process tree",
              measured.timed_out and measured.outcome == "timeout"
              and "test output" in measured.stdout and "report tail" in measured.stdout
              and kill.call_count == 1)
        check("a timed-out report cannot collect partial or truncated module XML",
              len(collections) == collection_count
              and all(record["coverage"] is None for record in measured.records))

    # -- the runner the strip generates
    source = runner_source(epub, "epubcheck")
    check("the generated runner declares the JSON plugin the harness reads, "
          "in the package whose glue it must scan",
          f"package {epub.runner_package};" in source
          and f'plugin = {{"{epub.json_plugin}"}}' in source
          and f"public class {epub.runner_class}" in source, source)
    algo_sources = [runner_source(q, "algorand-sdk")
                    for q in runner_variants_for("algorand-sdk")]
    check("...and both Algorand variants carry the shared options without "
          "the disabled tag or publication switch",
          all("com.algorand.algosdk.cucumber.shared" in s
              and "strict = true" in s
              and "@disabled.by.default" not in s
              and "publish" not in s for s in algo_sources))
    def scans_unit(text):
        return '"com.algorand.algosdk.unit"' in text

    stripped_offline_source = algo_sources[1]
    unstripped_offline_source = runner_source(
        runner_variants_for("algorand-sdk", stripped=False)[1],
        "algorand-sdk")
    check("the stripped offline runner scans the profile's unit answer "
          "package as well as integration and shared glue",
          "package com.algorand.algosdk.integration;"
          in stripped_offline_source
          and "com.algorand.algosdk.cucumber.shared"
          in stripped_offline_source
          and scans_unit(stripped_offline_source),
          stripped_offline_source)
    check("the unstripped offline runner scans integration plus shared, "
          "but not the duplicate upstream unit glue",
          "package com.algorand.algosdk.integration;"
          in unstripped_offline_source
          and 'extraGlue = "com.algorand.algosdk.cucumber.shared"'
          in unstripped_offline_source
          and not scans_unit(unstripped_offline_source),
          unstripped_offline_source)

    # A historically valid seed can contain a now-obsolete generated runner.
    with tempfile.TemporaryDirectory() as root:
        b = load_boundary(os.path.join(here, "config", "boundary_kapua.yml"),
                          repo_root=root)
        variants = runner_variants_for("kapua")
        # Runners AND the step-tag listeners beside them: a workspace with
        # one and not the other is not one `strip_repo_cucumber` prepared.
        kapua_sources = installed_sources_for("kapua")
        for rel, text in kapua_sources.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(text)
        man = _repo.StripManifest(
            repo_root=root, gold_root=os.path.join(root, "gold"),
            substrate_roots=list(kapua_sources),
            build_roots=list(_kapua.BUILD_ROOTS))
        runtime = _FakeRunner(root=root)
        current = CucumberHarness(man, b, runtime)
        check("current Kapua runners are accepted without native execution",
              current.root == root and not runtime.calls)
        account_suite = next(suite for suite in _KAPUA_SUITES
                             if account_feature in suite.features)
        account = quirks_for("kapua", account_feature)
        old = replace(account, runner_options=("glue = {" + ", ".join(
            json.dumps(package) for package in
            (*account_suite.glue, account_suite.generated_package)) + "}",))
        with open(os.path.join(root, account.runner_rel), "w", encoding="utf-8") as stream:
            stream.write(runner_source(old, "kapua"))
        # Simulate the baseline saved by the older strip, not a current
        # rebaseline (which must refuse this obsolete runner).
        manifest_path = os.path.join(root, "old-manifest.json")
        _repo.baseline_substrate(man, b, manifest_path)
        _hz.Harness.verify_substrate(current)
        check("Kapua refuses obsolete seed runners despite their valid saved baseline",
              refused(lambda: CucumberHarness(man, b, runtime))
              and not runtime.calls)

    # ------------------------------------------------------------ the strip
    with tempfile.TemporaryDirectory() as root:
        def write(rel, text="x"):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        java = "src/test/java/org/w3c/epubcheck"
        write(POM_REL, pom())
        write(f"{java}/test/AssertionSteps.java", "// the answer\n")
        write(f"{java}/test/ParameterTypes.java", "// R1.5, retained\n")
        write(f"{java}/container/FilenameCheckerSteps.java", "// answer\n")
        write(f"{java}/RunCucumberTest.java", "// retained runner\n")
        write(f"{java}/url/URLUtilsTest.java", "// unit test\n")
        write("src/main/java/com/adobe/epubcheck/api/EpubCheck.java", "//\n")
        write("src/test/resources/cucumber.properties",
              "cucumber.publish.quiet=true\n")
        write("src/test/resources/epub3/03-resources/files/x.opf", "<opf/>")
        write("target/test-classes/org/w3c/epubcheck/test/"
              "AssertionSteps.class", "\x00compiled answer")
        write(".git/HEAD", "ref: refs/heads/master\n")
        b = load_boundary(boundary_path, repo_root=root)
        gold = os.path.join(root, "_gold")

        dry = strip_repo_cucumber(b, gold, dry_run=True)
        check("dry run names the moves and makes none",
              sorted(dry.moved) == [f"{java}/container/"
                                    "FilenameCheckerSteps.java",
                                    f"{java}/test/AssertionSteps.java"]
              and dry.moved_config == ["src/test/resources/"
                                       "cucumber.properties"]
              and os.path.isfile(os.path.join(
                  root, f"{java}/test/AssertionSteps.java")), str(dry.moved))

        man = strip_repo_cucumber(b, gold)
        check("the glue moved to gold; the retained substrate, the runner "
              "and the fixtures did not",
              not os.path.exists(os.path.join(
                  root, f"{java}/test/AssertionSteps.java"))
              and os.path.isfile(os.path.join(
                  gold, f"{java}/test/AssertionSteps.java"))
              and os.path.isfile(os.path.join(
                  root, f"{java}/test/ParameterTypes.java"))
              and os.path.isfile(os.path.join(
                  root, f"{java}/RunCucumberTest.java"))
              and os.path.isfile(os.path.join(
                  root, "src/test/resources/epub3/03-resources/files/x.opf")))
        check("the compiled copy of the answer is DELETED, not moved -- "
              "Maven regenerates target/ from source and a gold copy of it "
              "would preserve nothing",
              not os.path.exists(os.path.join(root, "target"))
              and not os.path.exists(os.path.join(gold, "target")))
        check("the harness's runner is installed, and it is the class the "
              "invocation selects",
              os.path.isfile(os.path.join(root, epub.runner_rel))
              and epub.runner_rel in man.installed
              and epub.test_selector in open(
                  os.path.join(root, epub.runner_rel),
                  encoding="utf-8").read())
        check("...and the boundary classifies it as production, so no "
              "solution may write it and its bytes are in the baseline",
              b.classify(epub.runner_rel) == PRODUCTION,
              b.classify(epub.runner_rel))
        check("the manifest records the cucumber roots and the build root, "
              "as DATA rather than as CoreShop's fallback",
              man.roots() == _repo.CUCUMBER_SUBSTRATE_ROOTS
              and man.volatile() == _repo.CUCUMBER_SUBSTRATE_VOLATILE
              and man.build_roots == list(_repo.CUCUMBER_BUILD_ROOTS)
              and man.bytecode_roots == [])
        check(".git moved to gold (the answer at HEAD) and the manifest "
              "saved OUTSIDE the repo",
              not os.path.isdir(os.path.join(root, ".git"))
              and os.path.isdir(os.path.join(gold, "_git"))
              and os.path.isfile(os.path.join(gold, "strip_manifest.json")))

        # -- the baseline, over the tree the strip just prepared
        man.repo_root = root
        info = integrity_baseline(man, b, os.path.join(
            gold, "strip_manifest.json"))
        check("the baseline hashes the retained substrate and the runner it "
              "just installed", info["files"] > 0
              and epub.runner_rel in man.digests
              and f"{java}/test/ParameterTypes.java" in man.digests,
              str(info))
        check("...and hashes neither of the volatile per-item files, so a "
              "run that writes them cannot abort the next item",
              not any(rel in man.digests
                      for rel in (FEATURE_REL, _hz.RECORD_REL)))
        check("the strip patched the pom and SAID SO on the manifest, so "
              "the coverage recipe is in the bytes the baseline hashed",
              man.patched == [POM_REL]
              and ARG_LINE_TOKEN in open(os.path.join(root, POM_REL),
                                         encoding="utf-8").read())
        write(POM_REL, pom())
        check("a baseline over a pom carrying no coverage recipe is "
              "refused: it would freeze a workspace whose every "
              "`--coverage` row reads zero for a reason no log states",
              refused(lambda: integrity_baseline(
                  man, b, os.path.join(gold, "strip_manifest.json"))))
        write(POM_REL, pom_with_coverage(pom()).replace(
            " " + AGENT_ARG_LINE_TOKEN, ""))
        check("...and so is one carrying JaCoCo's half but not the agent's: "
              "a tree the OLD strip prepared, whose every coverage run would "
              "read `direct_calls` null for a reason no log states",
              refused(lambda: integrity_baseline(
                  man, b, os.path.join(gold, "strip_manifest.json"))))
        write(POM_REL, pom_with_coverage(
            pom(surefire="<forkCount>0</forkCount>")))
        check("a baseline over a pom that unpins the exit code is REFUSED "
              "rather than taken -- digests cannot tell a pom that pins the "
              "run from one that unpins it, and taking it launders the "
              "tampering into the definition of `unchanged`",
              refused(lambda: integrity_baseline(
                  man, b, os.path.join(gold, "strip_manifest.json"))))
        write(POM_REL, pom_with_coverage(pom()))
        os.remove(os.path.join(root, epub.runner_rel))
        check("a baseline over a workspace with no harness runner is "
              "refused: nothing would select a test or write a document",
              refused(lambda: integrity_baseline(
                  man, b, os.path.join(gold, "strip_manifest.json"))))

        # -- make_harness
        with open(os.path.join(gold, "strip_manifest.json"),
                  encoding="utf-8") as fh:
            portable = json.load(fh)
        portable["repo_root"] = "."
        portable["gold_root"] = "."
        with open(os.path.join(gold, "strip_manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(portable, fh, indent=1, sort_keys=True)
        ns = argparse.Namespace(boundary=boundary_path, repo=root, gold=gold,
                                container="c", workdir="/var/www/html")
        try:
            make_harness(ns)
            check("the CoreShop default workdir is refused -- a cucumber "
                  "worker's mount point must be said, not guessed", False,
                  "accepted")
        except SystemExit as e:
            check("the CoreShop default workdir is refused -- a cucumber "
                  "worker's mount point must be said, not guessed",
                  "workdir" in str(e))
        ns.workdir = "/work"
        h3, _b3, _man3 = make_harness(ns)
        check("an explicit workdir yields a harness pointed at one "
              "workspace, holding this project's quirks",
              isinstance(h3, CucumberHarness) and h3.root == root
              and h3.runner.workdir == "/work" and h3.quirks is epub
              and _man3.gold_root == os.path.abspath(gold))
        try:
            make_harness(argparse.Namespace(
                boundary=boundary_path, repo=root, container="c",
                workdir="/work", gold=os.path.join(root, "nowhere")))
            check("a missing strip manifest is refused with the strip "
                  "command named", False, "accepted")
        except SystemExit as e:
            check("a missing strip manifest is refused with the strip "
                  "command named", "strip" in str(e))

    # -- the corpus can never be stripped: load the shipped default under a
    #    portable data root, independently of the constant being tested, and
    #    prove the guard fires before even creating the configured tree.
    saved_data_root = os.environ.get(DATA_ROOT_ENV)
    try:
        with tempfile.TemporaryDirectory() as fixture_data_root:
            os.environ[DATA_ROOT_ENV] = fixture_data_root
            corpus_b = load_boundary(boundary_path)
            corpus_root = os.path.abspath(corpus_b.repo_root)
            gold_root = os.path.join(fixture_data_root, "gold")
            try:
                strip_repo_cucumber(corpus_b, gold_root)
                portable_refusal = "accepted"
            except SystemExit as e:
                portable_refusal = str(e)
            check("the shipped epubcheck boundary refuses its portable "
                  "default before any filesystem mutation",
                  corpus_root == os.path.join(
                      fixture_data_root, "projects", "epubcheck", "source")
                  and "pinned corpus" in portable_refusal
                  and os.listdir(fixture_data_root) == [], portable_refusal)

            archived_b = Boundary(
                version=1, project="epubcheck",
                repo_root="/data2/binhang/req2test_corpora/epubcheck",
                removable=[(JAVA_TEST_ROOT + "/", "")], retained=[])
            try:
                strip_repo_cucumber(archived_b, gold_root)
                archived_refusal = "accepted"
            except SystemExit as e:
                archived_refusal = str(e)
            check("the archived pinned corpus tree remains refused by "
                  "prefix, before anything is touched",
                  "pinned corpus" in archived_refusal, archived_refusal)

            def strip_refusal(root):
                b = Boundary(version=1, project="epubcheck", repo_root=root,
                             removable=[(JAVA_TEST_ROOT + "/", "")],
                             retained=[])
                try:
                    strip_repo_cucumber(b, gold_root)
                    return "accepted"
                except SystemExit as e:
                    return str(e)

            # The declared checkout no literal ever named.  algorand's step
            # definitions are pinned in their OWN repository, and that tree
            # is maven-shaped — pom, `src/test/java`, `src/test/resources` —
            # so it is exactly what this arm strips.
            for project in ("algorand-java-sdk", "algorand-sdk",
                            "python-docx", "coreshop"):
                refusal = strip_refusal(os.path.join(
                    fixture_data_root, "projects", project, "source"))
                check(f"stripping inside the pinned {project} tree is "
                      f"refused by prefix, before anything is touched",
                      "pinned corpus" in refusal, refusal)
            check("a clone outside every declared corpus is not refused "
                  "here -- it reaches the shape check, which is what stops "
                  "a non-cucumber tree",
                  "does not look like a cucumber-jvm project"
                  in strip_refusal(os.path.join(fixture_data_root, "clone")))
            check("...and nothing was created on the way to any of those "
                  "answers", os.listdir(fixture_data_root) == [],
                  str(os.listdir(fixture_data_root)))
    finally:
        if saved_data_root is None:
            os.environ.pop(DATA_ROOT_ENV, None)
        else:
            os.environ[DATA_ROOT_ENV] = saved_data_root
    from ..bench.cli import DEFAULT_GOLD as _DEFAULT_GOLD
    check("the active portable CoreShop gold default is protected from a "
          "cucumber strip",
          any(_DEFAULT_GOLD == protected for protected in PROTECTED_GOLD))
    try:
        cmd_strip(argparse.Namespace(boundary=boundary_path, repo=None,
                                     gold=PROTECTED_GOLD[1], dry_run=True))
        check("a cucumber strip into CoreShop's gold is refused", False,
              "accepted")
    except SystemExit as e:
        check("a cucumber strip into CoreShop's gold is refused",
              "CoreShop data root" in str(e), str(e)[:80])

    # ------------------------------------------------------- CLI dispatch
    profile = os.path.join(here, "config", "profile_epubcheck.yml")
    if os.path.isfile(profile):
        # Compared against the CANONICALLY imported module's attributes, not
        # this file's globals: under `python -m r2t.stacks.cucumber` this
        # code runs as `__main__` while the dispatcher imports
        # `r2t.stacks.cucumber` fresh, and the two hold distinct
        # (equal-bytes) function objects.
        from . import cucumber as _canonical
        from ..bench import cli as _cli
        ns = argparse.Namespace(profile=profile)
        check("the epubcheck profile routes make_harness and cmd_strip to "
              "THIS stack -- read out of the file, digests and all",
              _cli._other_stack(ns, "make_harness") is _canonical.make_harness
              and _cli._other_stack(ns, "cmd_strip") is _canonical.cmd_strip)
        check("...and closures route to this stack's Java source-only verb, "
              "never the PHP body",
              _cli._other_stack(ns, "cmd_closures")
              is _canonical.cmd_closures)
    else:
        print(f"  [SKIP] no {profile}, so the real dispatch could not be "
              f"resolved")

    # A profile-conforming answer for one of the nine relocated offline items
    # can move from undefined to executable under the broad stripped runner.
    # That is a verdict change, so the global harness identity advances.
    from ..bench import validate as _validate

    check("the offline-runner correction advanced the harness past H7",
          _validate.HARNESS_VERSION >= 8, str(_validate.HARNESS_VERSION))

    # ------------------------------------------------- the module's shape
    from importlib import import_module

    def resolve(dotted: str):
        """`r2t.bench.harness.Harness.install_solution` -> the object itself."""
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

    mine = globals()
    for member, dotted in MEMBERS.items():
        # `is`, never `==`: an equality check would pass for a wrapper that
        # forwards, which is exactly the thing a re-export promises not to be.
        check(f"cucumber.{member} IS {dotted}",
              mine.get(member) is resolve(dotted), str(mine.get(member)))
    # The CLASS attributes, which the module walk above cannot see: they are
    # `CucumberHarness`'s namespace, not this module's, and the class
    # docstring says all three are "held to identity by the selftest".
    for member, dotted in CLASS_MEMBERS.items():
        have = getattr(CucumberHarness, member, None)
        check(f"CucumberHarness.{member} IS {dotted}",
              have is resolve(dotted), str(have))
    borrowed = sorted(n for n, v in vars(CucumberHarness).items()
                      if not n.startswith("__")
                      and getattr(_hz.Harness, n, None) is v)
    check("...and the table is CLOSED over what this class borrows, so a "
          "fourth assignment cannot arrive with no `is` behind it",
          borrowed == sorted(CLASS_MEMBERS), str(borrowed))
    own = sorted(n for n, v in mine.items()
                 if not n.startswith("_") and callable(v)
                 and getattr(v, "__module__", None) == __name__)
    check("the module defines exactly what it declares it defines",
          own == sorted(OWN_MEMBERS), str(own))
    for seam, milestone in PENDING.items():
        check(f"`{seam}` is genuinely absent until {milestone} lands it",
              seam not in mine)
    try:
        cmd_interfaces(None)
        check("`interfaces` on cucumber refuses as a RULING (D4), not as a "
              "pending seam", False, "returned")
    except CucumberStackRefused as e:
        check("`interfaces` on cucumber refuses as a RULING (D4), not as a "
              "pending seam",
              "withheld" in str(e) and "D4" in str(e) and "pending" in str(e))
    # Read the engine and campaign registry independently of MEMBERS: the
    # stack re-export, population identity, and compiled applier must all name
    # one implementation.
    from ..toolkit import mutation_java as _mutation_java
    from ..bench import mutation_run as _mutation_run
    from ..data import release as _release

    check("the bound Java population builder and campaign applier name one "
          "engine",
          mutant_population is _mutation_java.build_population
          and _mutation_run.binding_for(_mutation_java.ENGINE)[0]
          == _mutation_java.JAVA_ENGINE_DIR)
    check("...and the refusal that keeps an unreleasable claim out of a "
          "manifest is where it always was, naming that same engine",
          _release._known_engines().get(_mutation_java.ENGINE)
          == _mutation_java.ENGINE_VERSION)

    print("\n" + ("ALL PASS (stacks.cucumber)" if ok
                  else "FAILURES (stacks.cucumber)"))
    return 0 if ok else 1


# =============================================== J4 (S3 closure extraction) ==
#
# Re-export the reviewed Java registry reader and its source-only CLI body.
# Both are identities, not wrappers, so the common stack contract and CLI
# dispatcher reach the same objects the closure module tests directly.

from ..java import closure_java as _closure_java  # noqa: E402

extract_closure = _closure_java.load_extractor
cmd_closures = _closure_java.cmd_closures

MEMBERS.update({
    "extract_closure": "r2t.java.closure_java.load_extractor",
    "cmd_closures": "r2t.java.closure_java.cmd_closures",
})
PENDING.pop("extract_closure", None)


# ================================================= J6 (S5 stub: the floor) ==
#
# The anti-vacuity seam, APPENDED rather than written into the tables above,
# exactly as `stacks/behave.py` appends its S5 half: a dict UPDATE and a
# `PENDING.pop` touch no line J5 owns, so the two milestones merge without a
# conflict and neither can silently drop the other's entry.  Everything here
# is a re-export, like the rest of this module.
#
from ..toolkit import strip_java as _assertion_strip  # noqa: E402
from ..toolkit import stub_java as _stub_java  # noqa: E402
from ..toolkit import mutation_java as _mutation_java  # noqa: E402

#: Seam 6 — the anti-vacuity control: a submission whose glue is
#: syntactically valid and semantically empty.  One class per item in the
#: package this project's runner scans, keyed on the step TEXT because
#: cucumber matches a step against every definition whatever keyword
#: registered it.
stub_solution = _stub_java.stub_solution

#: ...and the adapter the sweep drives it through, dispatched from
#: `fixtures._stub_maker`.  A behave module or a PHP context class
#: installed into a Maven workspace defines nothing, so the floor would read
#: 0.00 for the wrong reason; that is why the fixture is per-stack at all.
make_stub_adapter = _stub_java.make_stub_adapter

#: The corpus half of §3.10's stub acceptance, reached from
#: `cli.cmd_stub_accept` through `cli._other_stack`.  The javac/glue-loader
#: half needs the image and no program runs it today: the verb prints
#: `stub_java.CONTAINER_HALF_NOTE`, which says so and names the blocking
#: condition, and `stub_java.selftest` holds that sentence to
#: `benchmark/scripts/gate_s5_vacuity.py`'s own bytes.
cmd_stub_accept = _stub_java.cmd_stub_accept

#: Candidate-blind de-saturation: gold with the Then-only method bodies
#: emptied.  An additive fixture seam rather than one of `StackRunner`'s
#: seven historical operations, which is why it is not in `PENDING` and
#: never was — both other stacks bind it beside their harness rather than
#: at a milestone boundary.  A PHP or Python stripper over a Java tree
#: would empty nothing at all and the control would silently be gold, so
#: the dispatch in `fixtures._strip_maker` is what this pair of
#: names exists for.
stripped_solution = _assertion_strip.stripped_solution
make_strip_adapter = _assertion_strip.make_strip_adapter

#: Seam 7 and its CLI: population production is permitted only through
#: mutation_java.cmd_mutants, whose build arm authenticates the provided
#: release subset, v3 worker pool, Docker authority, canonical image, exact
#: Surefire classpath and sourcepath before starting javac.
mutant_population = _mutation_java.build_population
cmd_mutants = _mutation_java.cmd_mutants

#: The mutation engine, under the names `stacks.base.ENGINE_MEMBERS` gives it
#: on every stack.  `r2t-mutate-java` and its version are read out of
#: `Mutate.java` itself and hashed into every mutant id this stack mints, so
#: they are identity and not a label; the exclusion policy is what that
#: population is defined over.
engine = _mutation_java.ENGINE
engine_version = _mutation_java.ENGINE_VERSION
excluded_prefixes = _mutation_java.EXCLUDED_PREFIXES
engine_dir = _mutation_java.JAVA_ENGINE_DIR
applier = _mutation_java.applier

MEMBERS.update({
    "stub_solution": "r2t.toolkit.stub_java.stub_solution",
    "make_stub_adapter": "r2t.toolkit.stub_java.make_stub_adapter",
    "cmd_stub_accept": "r2t.toolkit.stub_java.cmd_stub_accept",
    "stripped_solution": "r2t.toolkit.strip_java.stripped_solution",
    "make_strip_adapter": "r2t.toolkit.strip_java.make_strip_adapter",
    "mutant_population": "r2t.toolkit.mutation_java.build_population",
    "cmd_mutants": "r2t.toolkit.mutation_java.cmd_mutants",
    "engine": "r2t.toolkit.mutation_java.ENGINE",
    "engine_version": "r2t.toolkit.mutation_java.ENGINE_VERSION",
    "excluded_prefixes": "r2t.toolkit.mutation_java.EXCLUDED_PREFIXES",
    "engine_dir": "r2t.toolkit.mutation_java.JAVA_ENGINE_DIR",
    "applier": "r2t.toolkit.mutation_java.applier",
})
PENDING.pop("stub_solution", None)


if __name__ == "__main__":
    raise SystemExit(selftest())
