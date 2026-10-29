"""S6 — the run harness: install a solution, synthesise its suite, execute it.

The same code path runs the GOLD closure and a system under test.  That
symmetry is the point (SPEC §4): if the synthesised wiring is weak, the
round-trip validation gate sees it first, on gold, and the item is
excluded — rather than a system being scored down for a harness bug.

A "solution" is the adapter contract, generalising ART's
`GeneratedTestFiles`:

    {files: [{file_path, code}], metadata: {...}}

with one addition CoreShop forces.  ART's projects wire step definitions
by convention (a module in `features/steps`); CoreShop wires them through
Symfony DI, and 28% of its real contexts cannot be autowired at all
(un-aliased repositories, `Doctrine\\Persistence\\ObjectManager`,
per-registry form types).  A solution may therefore include a file named
`behat_services.yml` holding Symfony service definitions for its own
classes.  Gold uses exactly that channel — its fragment is the original
`arguments:` list — so neither side gets a wiring privilege the other
lacks.
"""
from __future__ import annotations

import hashlib
import io
import itertools
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from typing import Iterable, Mapping, Optional

import yaml

from ..core.boundary import Boundary
from ..core.gherkin import Block, Feature, parse_feature_file, standalone_feature
from .repo import (BENCH_CONFIG, BENCH_DIR, CORESHOP_BEHAT, StripManifest,
                   behat_project, error_reporting_int)
from ..core.paths import BENCHMARK_ROOT

_SCENARIO_LINE = re.compile(
    r"^\s*(Scenario Outline|Scenario Template|Scenario|Example)\s*:")

SERVICES_FRAGMENT_NAME = "behat_services.yml"
RECORD_REL = f"{BENCH_DIR}/run_record.jsonl"
FEATURE_REL = f"{BENCH_DIR}/item.feature"
REGISTRATION_REL = f"{BENCH_DIR}/services_item.yml"
RECORDER_CONTEXT = "CoreShop\\Behat\\Bench\\BenchRecorderHook"
#: Projects whose Behat kernel runs with debug off, so its cache pools keep
#: source-derived metadata across executions: `Harness.clear_cache_pools`
#: empties them before every mutation pair (harness 27).
COLD_POOL_PROJECTS = frozenset({"sylius"})

#: What `write_registration` renders for a CoreShop-shaped index, byte for
#: byte: one alias, one context, one constructor-free helper.
#:
#: Pinned because the rule that keeps Sylius's private-constructor
#: constants-holders out of the container may not change what CoreShop
#: registers.  CoreShop's Behat tree has no non-public constructor, so this
#: document is the same whether the index records methods or not.  Both
#: kinds exist: the analyzer in CoreShop's scoring seed v1 predates
#: `methods`, and the current one, in seed v2 and scoring seed v1.1
#: (BENCHMARK_V2_SPEC.md section 8.5), records them.
CORESHOP_ITEM_SERVICES = (
    "# GENERATED per item by r2t.bench.harness \u2014 registration for the\n"
    "# solution under test (SPEC \u00a74, decision D2).\n"
    "# solution-digest: none\n"
    "services:\n"
    "  _defaults:\n"
    "    public: true\n"
    "    autoconfigure: true\n"
    "  CoreShop\\Component\\Order\\Repository\\CartRepositoryInterface:"
    " '@coreshop.repository.cart'\n"
    "  CoreShop\\Behat\\Context\\Domain\\CartContext:\n"
    "    autowire: true\n"
    "  CoreShop\\Behat\\Context\\Domain\\Money:\n"
    "    autowire: true\n"
)

#: What `write_behat_config` renders for CoreShop, byte for byte.
#:
#: Pinned because the per-project rows must not be able to move it: a
#: boundary with no `behat:` block resolves to the module constants above,
#: and this is what those constants render.  A row that leaks into the
#: CoreShop path shows up here rather than in a container three hours later.
CORESHOP_BENCH_CONFIG = (
    "# GENERATED per item by r2t.bench.harness (SPEC \u00a74).\n"
    "bench:\n"
    "  formatters:\n"
    "    pretty:\n"
    "      verbose: true\n"
    "      paths: false\n"
    "      snippets: false\n"
    "  extensions:\n"
    "    FriendsOfBehat\\SymfonyExtension:\n"
    "      bootstrap: behat-bootstrap.php\n"
    "      kernel:\n"
    "        path: src/BehatKernel.php\n"
    "        class: BehatKernel\n"
    "        environment: test\n"
    "  suites:\n"
    "    bench:\n"
    "      paths:\n"
    "      - '%paths.base%/_bench/item.feature'\n"
    "      contexts:\n"
    "      - CoreShop\\Behat\\Context\\Hook\\PimcoreSetupContext\n"
    "      - CoreShop\\Behat\\Context\\Hook\\CoreShopSetupContext\n"
    "      - CoreShop\\Bundle\\TestBundle\\Context\\Hook\\DoctrineORMContext\n"
    "      - CoreShop\\Behat\\Context\\Hook\\PimcoreDaoContext\n"
    "      - CoreShop\\Bundle\\TestBundle\\Context\\Transform\\SharedStorageContext\n"
    "      - CoreShop\\Bundle\\TestBundle\\Context\\Transform\\ClassContext\n"
    "      - CoreShop\\Bundle\\TestBundle\\Context\\Setup\\ClassContext\n"
    "      - CoreShop\\Bundle\\TestBundle\\Context\\Domain\\ClassContext\n"
    "      - CoreShop\\Bundle\\TestBundle\\Context\\Domain\\PimcoreContext\n"
    "      - CoreShop\\Behat\\Context\\Domain\\CartContext\n"
    "      - CoreShop\\Behat\\Bench\\BenchRecorderHook\n")


#: What `write_behat_config` renders for the SHIPPED Sylius boundary
#: (`config/boundary_sylius.yml`, which the selftest below loads rather than
#: rebuilding), byte for byte.
#:
#: Pinned for the reason `CORESHOP_BENCH_CONFIG` is, and with one addition:
#: no PHP runs on the host that develops this harness, so the bytes are the
#: only place the second rendering can be read before a container reads it.
#:
#: The tester options and the extensions are upstream's `behat.dist.php`
#: (lines 36-107) with one deviation -- `screenshot: false` on
#: MinkDebugExtension, for the reason the boundary gives.  They are not
#: decoration: retained Sylius services hold LAZY kernel-container bridges
#: to `fob_symfony.mink*`, which the Behat container defines only while
#: `Behat\MinkExtension` is registered, so a profile without the Mink stack
#: failed the first API step of a live smoke with a `ServiceNotFoundException`
#: the harness scored `container_error`.
#:
#: The `withTesterOptions` line is 36-37, and the profile used to start one
#: line BELOW it: Behat then ran every step under this image's bare
#: `error_reporting()` (32767), escalated an `E_DEPRECATED` raised inside an
#: in-process kernel request into a `CallErrorException`, and the kernel
#: returned it as the 500 the scenario read back as its response
#: (`tester_error_reporting` in `bench/repo.py` and in the boundary carry
#: the measurement).
SYLIUS_BENCH_CONFIG_PHP = r"""<?php
// GENERATED per item by r2t.bench.harness (SPEC §4).

declare(strict_types=1);

use Behat\Config\Config;
use Behat\Config\Extension;
use Behat\Config\Formatter\Formatter;
use Behat\Config\Profile;
use Behat\Config\Suite;
use Behat\Config\TesterOptions;

return (new Config())
    ->withProfile(
        (new Profile('bench'))
            ->withFormatter(new Formatter('pretty', [
                'verbose' => true,
                'paths' => false,
                'snippets' => false,
            ]))
            ->withTesterOptions((new TesterOptions())->withErrorReporting(\E_ALL & ~(\E_DEPRECATED | \E_USER_DEPRECATED)))
            ->withExtension(new Extension(\DMore\ChromeExtension\Behat\ServiceContainer\ChromeExtension::class))
            ->withExtension(new Extension(\Robertfausk\Behat\PantherExtension\ServiceContainer\PantherExtension::class))
            ->withExtension(new Extension(\FriendsOfBehat\MinkDebugExtension\ServiceContainer\MinkDebugExtension::class, [
                'directory' => 'etc/build',
                'clean_start' => false,
                'screenshot' => false,
            ]))
            ->withExtension(new Extension(\Behat\MinkExtension\ServiceContainer\MinkExtension::class, [
                'files_path' => '%paths.base%/src/Sylius/Behat/Resources/fixtures/',
                'base_url' => 'http://127.0.0.1:8080/',
                'default_session' => 'symfony',
                'javascript_session' => 'panther',
                'sessions' => [
                    'symfony' => [
                        'symfony' => null,
                    ],
                    'chromedriver' => [
                        'chrome' => [
                            'api_url' => 'http://127.0.0.1:9222',
                            'validate_certificate' => false,
                        ],
                    ],
                    'chrome_headless_second_session' => [
                        'chrome' => [
                            'api_url' => 'http://127.0.0.1:9222',
                            'validate_certificate' => false,
                        ],
                    ],
                    'panther' => [
                        'panther' => [
                            'manager_options' => [
                                'connection_timeout_in_ms' => 5000,
                                'request_timeout_in_ms' => 120000,
                                'chromedriver_arguments' => [
                                    '--log-path=etc/build/chromedriver.log',
                                    '--verbose',
                                ],
                                'capabilities' => [
                                    'acceptSslCerts' => true,
                                    'acceptInsecureCerts' => true,
                                    'unexpectedAlertBehaviour' => 'accept',
                                    'goog:chromeOptions' => [
                                        'args' => [
                                            '--user-data-dir=/tmp/panther-chrome-data',
                                            '--window-size=1920,1200',
                                            '--no-sandbox',
                                            '--disable-dev-shm-usage',
                                            '--disable-gpu',
                                            '--disable-infobars',
                                            '--disable-features=TranslateUI',
                                            '--disable-translate',
                                            '--disable-popup-blocking',
                                            '--disable-blink-features=AutomationControlled',
                                            '--disable-component-extensions-with-background-pages',
                                            '--disable-background-networking',
                                            '--disable-dev-tools',
                                            '--disable-extensions',
                                        ],
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
                'show_auto' => false,
            ]))
            ->withExtension(new Extension(\FriendsOfBehat\SymfonyExtension\ServiceContainer\SymfonyExtension::class, [
                'kernel' => [
                    'path' => 'src/Kernel.php',
                    'class' => 'App\\Kernel',
                    'environment' => 'test_cached',
                ],
            ]))
            ->withExtension(new Extension(\FriendsOfBehat\VariadicExtension\ServiceContainer\VariadicExtension::class))
            ->withExtension(new Extension(\SyliusLabs\SuiteTagsExtension\ServiceContainer\SuiteTagsExtension::class))
            ->withExtension(new Extension(\Sylius\Bundle\ApiBundle\Behat\Extension\SyliusApiBundleExtension::class))
            ->withSuite(
                (new Suite('bench'))
                    ->withContexts(
                        'sylius.behat.context.hook.doctrine_orm',
                        'Sylius\\Behat\\Context\\Api\\Shop\\MyContext',
                        'Sylius\\Behat\\Bench\\BenchRecorderHook',
                    )
                    ->withPaths('%paths.base%/_bench/item.feature')
            )
    );
"""


@dataclass
class SourceFile:
    file_path: str
    code: str


def parse_services_fragment(code: str) -> tuple[dict, Optional[str]]:
    """The DI fragment, parsed defensively — it is AUTHORED BY THE SYSTEM.

    Every failure mode of a YAML parser is a thing a system under test can
    freely choose to do, and all three used to escape as an exception:

      * a tab-indented block, or any other syntax error, raises
        `yaml.YAMLError`;
      * a document that is a bare list or a scalar makes `parsed.get`
        an `AttributeError`;
      * `services: foo` parses fine and yields a STRING where every later
        consumer (`vet_fragment`, `write_registration`) iterates a mapping.

    `runner.run_one` calls `Solution.from_json` OUTSIDE the guard that
    catches adapter exceptions, so one malformed file from one item killed
    the whole shard process and discarded every remaining item of a paid
    sweep — a failure of the system under test presented as a failure of the
    run.

    An unusable fragment is therefore treated as NO fragment: the scenario
    runs without the solution's DI wiring and fails as the DI failure it is,
    which is a solution error and belongs on the row.  The reason is returned
    rather than dropped, because a silently missing fragment shows up later
    only as an unexplained `container_error`.
    """
    try:
        parsed = yaml.safe_load(code or "")
    except Exception as e:                                  # noqa: BLE001
        # Deliberately `Exception`, not `yaml.YAMLError`: the parser is being
        # handed arbitrary bytes, and a reader error on a lone surrogate is
        # not a YAMLError.  Nothing here is worth aborting a sweep for.
        return {}, f"unparseable YAML: {type(e).__name__}: {str(e)[:200]}"
    if parsed is None:
        # An empty file is not an error; it is a solution that needed no
        # explicit wiring, which is the common case.
        return {}, None
    if not isinstance(parsed, dict):
        return {}, (f"{SERVICES_FRAGMENT_NAME} is a YAML "
                    f"{type(parsed).__name__}, not a mapping")
    # No `services:` key means the whole document IS the mapping — the shape
    # gold's own fragment takes when it is written by hand.
    fragment = parsed.get("services", parsed)
    if fragment is None:
        return {}, None
    if not isinstance(fragment, dict):
        return {}, (f"`services:` is a {type(fragment).__name__}, not a "
                    f"mapping of service id to definition")
    return fragment, None


@dataclass
class Solution:
    files: list[SourceFile] = field(default_factory=list)
    services_fragment: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    #: A gold run (harness 25; specifications/EVALUATOR_CORRECTIONS_20261015_
    #: AMENDMENT.md section 3): the files are a ground-truth closure run by
    #: the gold, stripped-gold or stub adapter, by a mutation observation of
    #: those legs, or by `req2test validate`.  Gold runs keep harness 24's
    #: suite and wiring rules; every other run is a candidate run.  Only the
    #: coordinator sets it -- the runner from the adapter it built
    #: (`runner.is_gold_run_adapter`), a mutation slice from its campaign
    #: side, `gold_solution` -- never `from_json`, so nothing a submission or
    #: a replayed row says selects it, and a replay of gold rows is a
    #: candidate run.
    gold_run: bool = False

    @classmethod
    def from_json(cls, doc: dict) -> "Solution":
        files, fragment, why = [], {}, None
        for f in doc.get("files") or []:
            path = f["file_path"]
            if os.path.basename(path) == SERVICES_FRAGMENT_NAME:
                fragment, why = parse_services_fragment(f.get("code") or "")
                continue
            files.append(SourceFile(file_path=path, code=f["code"]))
        metadata = (doc.get("metadata") or
                    ({"thinking": doc["thinking"]} if "thinking" in doc else {}))
        if why:
            # Written into the metadata dict the ADAPTER supplied, which is the
            # same object `runner._record` copies onto the row, so the reason
            # travels with the outcome instead of living only in this object.
            metadata["services_fragment_error"] = why
        return cls(files=files, services_fragment=fragment, metadata=metadata)


#: Container/compile failures, which are a different research signal from
#: "the generated test was wrong" and must not share a bucket with it.
_DI_MARKERS = ("Cannot autowire", "DefinitionErrorExceptionPass",
               "LoaderLoadException", "Can not find a matching value",
               "ServiceNotFoundException", "circular reference",
               "non-existent service", "CheckExceptionOnInvalidReference",
               "has no service", "is not autowirable", "ParseException",
               "You have requested a non-existent service",
               # Symfony's named-argument check: a generated step-context
               # service whose constructor lacks an argument the wiring
               # names.  The container never compiles, so Behat never starts.
               "ResolveNamedArgumentsPass", "Invalid service",
               "has no argument named")


#: Distinguishes the pid files of concurrent executions in one container.
#: Process-local, so it is combined with the pid rather than trusted alone.
_EXEC_SEQ = itertools.count()


def record_outcome(rec: dict) -> str:
    """What ONE recorder record says happened, without the exit-code witness.

    Factored out of `RunResult.outcome` because a Scenario Outline produces
    one record PER Examples row and the fold below has to reason about each
    row separately before it can say anything about the outline.  The check
    order is the original one, so a single record maps exactly as it always
    did.
    """
    results = [s["result"] for s in rec.get("steps", [])]
    if not results:
        return "no_steps_ran"
    if all(r == "passed" for r in results):
        return "passed"
    if any(r == "undefined" for r in results):
        return "undefined_steps"
    if any(r == "failed" for r in results):
        return "failed"
    if any(r == "pending" for r in results):
        return "pending"
    return "not_passed"


def fold_lines(expected_line: Optional[int],
               expected_lines: Optional[list] = None) -> Optional[list]:
    """The set of lines a record may legitimately claim, from either shape.

    Rows written before the outline fold existed carry only the scalar
    `expected_line`; they fold to themselves, which is why the archived runs
    re-score bit-identically.  `expected_lines` is the additive successor and
    wins whenever it is present and non-empty.
    """
    if expected_lines:
        return list(expected_lines)
    return None if expected_line is None else [expected_line]


def fold_scenario_records(records: Optional[list],
                          expected_lines: Optional[list],
                          ) -> tuple[list[dict], Optional[dict]]:
    """Every record belonging to the scenario we asked for, and its delegate.

    Behat runs a `Scenario Outline` once per Examples row and the recorder
    hook fires `@AfterScenario` each time, stamping each record with the
    line of the EXAMPLES ROW rather than the `Scenario Outline:` keyword
    line.  Selecting on the keyword line alone therefore matched nothing for
    an outline — the run scored `no_scenario_ran` — and had the lines
    happened to align it would have scored only the LAST row, silently
    discarding the rest.  CoreShop has no outlines, so nothing published so
    far is affected; roughly half the Python corpus is outlines, so nothing
    from it could be scored at all.

    Returns `(matched, representative)`:

      * `matched` is every record whose `scenario_line` is one of the lines
        the harness synthesised for this scenario — the keyword line plus
        each Examples data row.  A record on any OTHER line is excluded
        WHEREVER it sits in the file: the record file is inside the
        bind-mounted workspace and a context supplied by the system under
        test can append a forged all-passed line from an earlier hook.
      * `representative` is the record whose per-step detail is reported.
        The first non-passing record if there is one, so a diagnosis lands
        on the row that actually broke, else the first.

    With exactly one match this is an IDENTITY on the old behaviour, which
    is the property that lets the fold ship without re-scoring anything.
    """
    records = list(records or [])
    if not records:
        return [], None
    if not expected_lines:
        # No identity to check against (an override whose text held no
        # scenario keyword).  Unchanged: the last record, alone.
        return [records[-1]], records[-1]
    wanted = set(expected_lines)
    matched = [r for r in records if r.get("scenario_line") in wanted]
    if not matched:
        return [], None
    rep = next((r for r in matched if record_outcome(r) != "passed"),
               matched[0])
    return matched, rep


def _direct_call_records(records: Optional[list], expected_line: Optional[int],
                         expected_lines: Optional[list]) -> list:
    """Complete required-record selection shared by API events and schema."""
    required = fold_lines(expected_line, expected_lines)
    if required and len(required) > 1:
        required = [line for line in required if line != expected_line]
    matched, _representative = fold_scenario_records(records, required)
    if not matched or (required and set(required) != {
            record.get("scenario_line") for record in matched}):
        return []
    return matched


#: The collector markers whose API sets fold into an item row.  A recorder
#: bumps its own marker when its event shape changes -- `/3` and `/2` are the
#: Python and Ruby shapes that stamp each event with the step that made it
#: (`step`, TARGET_INTERFACES_V2_SPEC section 4), `r2t.php_direct_calls/1` is
#: the first PHP marker at all.  The harness version cannot stand in for the
#: marker: a new harness can execute an old seed whose recorder is substrate.
DIRECT_CALLS_SCHEMAS = frozenset({
    "r2t.python_direct_calls/2", "r2t.python_direct_calls/3",
    "r2t.ruby_direct_calls/1", "r2t.ruby_direct_calls/2",
    "r2t.php_direct_calls/1"})


def fold_direct_calls(records: Optional[list], expected_line: Optional[int],
                      expected_lines: Optional[list] = None) -> Optional[list]:
    """Union complete API observations from this execution's required rows.

    The expected lines contain the scenario keyword followed by its Examples
    rows. An outline requires each Examples row, not an extra keyword-line
    record. Missing records and absent/null collection withhold only this API
    set; the existing representative, coverage and outcome folds do not change.
    """
    matched = _direct_call_records(records, expected_line, expected_lines)
    if not matched:
        return None
    if any(not isinstance(record.get("direct_calls"), list)
           for record in matched):
        return None
    if len(matched) == 1:
        return matched[0]["direct_calls"]
    # Equality is over the whole recorded event, including all accessor
    # binding fields and the distinction between an absent and null binding.
    # No hash or guessed factory identity substitutes for those bytes.
    unique = {json.dumps(event, sort_keys=True, separators=(",", ":")): event
              for record in matched for event in record["direct_calls"]}
    events = [unique[key] for key in sorted(unique)]
    if all(str(record.get("direct_calls_schema", "")).startswith("r2t.ruby_direct_calls/")
           for record in matched):
        def ruby_order(event):
            # Sorting never authenticates evidence. Preserve malformed JSON
            # events for direct_record_issue to exclude the complete API set.
            invalid = (1, json.dumps(event, sort_keys=True, separators=(",", ":")))
            if not isinstance(event, dict):
                return invalid
            binding = event.get("ruby_binding")
            if binding is not None and not isinstance(binding, dict):
                return invalid
            binding = binding or {}
            values = [event.get(k) for k in ("callee_file", "callee_line", "callee", "caller_file")]
            values += [binding.get(k) for k in ("declaring_file", "declaring_line", "owner", "method_kind", "method_name")]
            values += [event.get("ruby_binding_issue"), event.get("step")]
            if any(value is not None and type(value) is not (int if i in (1, 5, 10) else str)
                   for i, value in enumerate(values)):
                return invalid
            return (0, tuple((value is not None, value) for value in values))
        events.sort(key=ruby_order)
    return events


def fold_direct_calls_schema(records: Optional[list], expected_line: Optional[int],
                             expected_lines: Optional[list] = None) -> Optional[str]:
    """Carry a compatible collector marker only when every required row has it."""
    matched = _direct_call_records(records, expected_line, expected_lines)
    schema = matched[0].get("direct_calls_schema") if matched else None
    if schema not in DIRECT_CALLS_SCHEMAS:
        return None
    return (schema if matched and all(record.get("direct_calls_schema") == schema
                                     for record in matched) else None)


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    wall_seconds: float
    records: list[dict] = field(default_factory=list)
    timed_out: bool = False
    expected_line: Optional[int] = None
    #: `killed` / `survived` / `no_pid` / None when the run did not time out.
    #: `survived` means a Behat process is still writing into the record file
    #: the next item will read, which is a reason to stop, not a footnote.
    timeout_cleanup: Optional[str] = None
    #: The keyword line PLUS every Examples data-row line of the scenario, so
    #: an outline's per-row records can be recognised.  Additive: `None` on a
    #: run whose caller did not supply it, and the scalar is then used alone.
    expected_lines: Optional[list] = None
    #: The stdout substrings that mean "the container/interpreter failed
    #: before the test could run", i.e. `container_error` rather than a
    #: verdict about the generated test.  `None` means `_DI_MARKERS`, which is
    #: Symfony's vocabulary and the only one every existing caller has ever
    #: had — so a run constructed the way `Harness.execute` constructs it is
    #: byte-identical to before.  A second stack's harness (behave has no DI
    #: container at all, and its equivalent failures spell themselves
    #: `ImportError` / `ModuleNotFoundError`) passes its own tuple rather than
    #: teaching this dataclass a second framework's error strings.
    #:
    #: Deliberately NOT exported by `to_json`: the markers are an INPUT to the
    #: classification, not a fact about the run, and adding a key to the row a
    #: sweep writes would change the bytes of every archived-comparable run
    #: file for no measurement anybody could read off it.
    error_markers: Optional[tuple] = None
    resource_reset_seconds: Optional[float] = None
    #: PrestaShop upload fixtures this execution consumed and the reset
    #: restored (`prestashop_resources.FIXTURES`); None when it consumed none.
    fixture_consumed: Optional[list] = None
    #: The runtime crash that ended the test process while a MUTANT was
    #: applied (`go_panic` / `go_fatal_error`), or None.  Only the Go
    #: mutation route sets it (`r2t/go/runtime.py`), after the capture
    #: proved cleanup and integrity and the unfinished native stream proved
    #: an empty or consistent prefix.  Owner ruling 2026-09-28: such a crash
    #: kills the mutant, so the outcome is `failed` and the label travels on
    #: the mutation row for disclosure.  Exported only when set.
    crash: Optional[str] = None

    @property
    def fold(self) -> tuple[list[dict], Optional[dict]]:
        """The records for the scenario we asked for — not merely the first."""
        return fold_scenario_records(
            self.records, fold_lines(self.expected_line, self.expected_lines))

    @property
    def scenario(self) -> Optional[dict]:
        """The record whose per-step detail stands for this run.

        `outcome` reads the whole fold rather than this one record: an
        outline passes only if EVERY row did, and reporting the delegate's
        label alone would let one green row speak for four red ones.
        """
        return self.fold[1]

    @property
    def direct_calls(self) -> Optional[list]:
        """The complete API event union, separate from per-step detail."""
        return fold_direct_calls(
            self.records, self.expected_line, self.expected_lines)

    @property
    def direct_calls_schema(self) -> Optional[str]:
        """Collector identity shared by all required API observations."""
        return fold_direct_calls_schema(
            self.records, self.expected_line, self.expected_lines)

    @property
    def outcome(self) -> str:
        """One label for what happened, in the vocabulary SPEC §5 needs.

        The same checks as the single-record version, in the same order,
        asked of every record in the fold at once.  For one record that is
        an identity; for an outline it means a row that ran no steps is
        reported as `no_steps_ran` (we did not measure the outline) ahead of
        any verdict, and one undefined row outranks another row's failure.
        """
        if self.fixture_consumed:
            # The run changed its own inputs; its verdict is not a measurement.
            return "fixture_consumed"
        if self.timed_out:
            return "timeout"
        if self.crash is not None:
            # The mutant crashed the test process before its native witness
            # completed, so there is no record to fold: the crash is the kill.
            return "failed"
        matched, rec = self.fold
        if rec is None:
            if any(m in self.stdout for m in (
                    _DI_MARKERS if self.error_markers is None else self.error_markers)):
                return "container_error"
            return "no_scenario_ran"
        labels = [record_outcome(r) for r in matched]
        if any(lab == "no_steps_ran" for lab in labels):
            return "no_steps_ran"
        if all(lab == "passed" for lab in labels):
            # Two independent witnesses must agree before a run counts as a
            # pass: the recorder's per-step results and Behat's own exit code
            # under --strict.  A disagreement is reported, never resolved in
            # favour of the more convenient one.
            return "passed" if self.exit_code == 0 else "passed_but_nonzero_exit"
        for lab in ("undefined_steps", "failed", "pending"):
            if lab in labels:
                return lab
        return "not_passed"

    def to_json(self, keep_stdout: bool = False) -> dict:
        # `expected_line` is exported because downstream readers have to be
        # able to repeat `scenario`'s identity selection.  Without it the
        # runner had no choice but to read `records[0]`, i.e. the slot the
        # identity check exists to protect.
        #
        # The stdout is truncated to a tail because it goes into a per-item
        # row of a run file, and a Behat pretty-format log with a PHP stack
        # trace runs to hundreds of kilobytes.  `keep_stdout` adds the whole
        # thing for a caller that is about to write it to a FILE — the
        # `--keep-artifacts` path — because a diagnosis of "why did this item
        # fail" is exactly the case where the interesting part (the container
        # compile error, the first fatal) is at the START of the log and the
        # tail is the useless summary.
        doc = {"exit_code": self.exit_code, "outcome": self.outcome,
               "wall_seconds": round(self.wall_seconds, 3),
               "timed_out": self.timed_out,
               "timeout_cleanup": self.timeout_cleanup,
               "expected_line": self.expected_line,
               # Additive.  A reader that only knows the scalar still folds
               # correctly on everything the scalar could express; a reader
               # that knows both can recognise an outline's per-row records.
               "expected_lines": self.expected_lines,
               "records": self.records,
               "stdout_tail": self.stdout[-4000:]}
        if self.fixture_consumed:
            doc["fixture_consumed"] = list(self.fixture_consumed)
        if self.crash is not None:
            doc["crash"] = self.crash
        if self.resource_reset_seconds is not None:
            doc["resource_reset_seconds"] = round(self.resource_reset_seconds, 3)
        if keep_stdout:
            doc["stdout"] = self.stdout
        return doc


def _process_tree_cleanup_script(pid_file: str) -> str:
    """Reap the owned Linux subtree without requiring procps in the image."""
    return (f'p=$(cat {shlex.quote(pid_file)} 2>/dev/null); '
            f'rm -f {shlex.quote(pid_file)}; '
            'if [ -z "$p" ]; then echo no_pid; exit 0; fi; ' + r'''
read_process() {
    process_line=
    if IFS= read -r process_line 2>/dev/null < "/proc/$1/stat"; then
        process_fields=${process_line##*) }
        set -- $process_fields
        [ "$#" -ge 2 ] || return 2
        process_state=$1
        process_parent=$2
        return 0
    fi
    [ ! -e "/proc/$1/stat" ] && return 1
    return 2
}
tree() {
    echo "$1"
    for process_file in /proc/[0-9]*/stat; do
        child=${process_file#/proc/}
        child=${child%/stat}
        if read_process "$child"; then
            if [ "$process_parent" = "$1" ]; then
                tree "$child" || return 1
            fi
        else
            process_error=$?
            [ "$process_error" -eq 1 ] || return 1
        fi
    done
}
live() {
    if read_process "$1"; then
        case "$process_state" in Z|X) return 1;; esac
        return 0
    else
        process_error=$?
        [ "$process_error" -ne 1 ]
    fi
}
all=$(tree "$p") || { echo survived; exit 0; }
for q in $all; do live "$q" && kill -TERM "$q" 2>/dev/null; done
i=0; while [ $i -lt 20 ]; do
    left=""; for q in $all; do live "$q" && left=1; done
    [ -z "$left" ] && break
    sleep 0.25; i=$((i+1))
done
for q in $all; do live "$q" && kill -KILL "$q" 2>/dev/null; done
sleep 0.5
left=""; for q in $all; do live "$q" && left=1; done
if [ -n "$left" ]; then echo survived; else echo killed; fi
''')


def _kill_process_tree(runner, pid_file: str, timeout: int = 120) -> str:
    """Kill the process whose pid is in `pid_file`, and its whole subtree.

    Shared with `Harness._kill_behat` because the kill
    is a property of running ANY test process under `docker exec`, not of
    Behat: a second stack's harness times out the same way (the local client
    dies, the process in the container keeps running and keeps appending to
    the record file the NEXT item reads), and a re-implementation would be a
    second chance to get the reparenting order wrong.

    Returns `no_pid` / `killed` / `survived` / `cleanup_failed:<Error>`, and
    the caller is expected to put that on the row: a `survived` that is
    swallowed is a corrupted next item with no witness.

    The WHY of the script itself, which is what makes it worth sharing:

    * The whole SUBTREE, walked, not the process and its direct children.
      `pkill -P` reaches exactly one level, so a grandchild — or anything a
      step daemonised — survived a cleanup the harness then reported as
      successful, and went on writing into the worker workspace that every
      later trial for that item and the authoritative final run both read.
    * A process GROUP would be the tidier boundary, but `setsid` does not
      give one here: measured in this image, `exec setsid --wait behat` leaves
      the recorded pid at 79 while the new group's PGID is the child's, 85 —
      so `kill -PGID` from the recorded pid signals the wrong group and
      orphans the process.  The tree is walked from the recorded pid instead,
      using Linux procfs, available even in images without procps. Zombies
      have stopped executing and cannot keep modifying the workspace.
    * The subtree is collected BEFORE any signal: killing a parent first
      reparents its children to init and loses them.
    """
    script = _process_tree_cleanup_script(pid_file)
    try:
        cp = runner.run(script, timeout=timeout)
    except Exception as e:                                  # noqa: BLE001
        return f"cleanup_failed:{type(e).__name__}"
    if cp.returncode != 0:
        return f"cleanup_failed:exit_{cp.returncode}"
    return (cp.stdout or "").strip().split("\n")[-1] or "unknown"


# ---------------------------------------------------------------- Behat 4
#
# Behat 4 (4.0.0-alpha1, the version Sylius pins) deleted the YAML
# configuration loader: `ConfigurationLoader::loadFileConfiguration` refuses
# any `--config` whose name does not end in `.php` -- "Configuration file
# `bench.behat.yml` must be a PHP file" -- before it reads a byte.  So the
# per-item profile is rendered TWICE from ONE document: `write_behat_config`
# builds the same mapping either way, and the project's row picks the
# renderer and, with it, the file name.
#
# `Behat\Config\Formatter\Formatter` rather than `PrettyFormatter` on
# purpose.  `Profile::withFormatter` stores `$formatter->toArray()` under
# `$formatter->name()`, so the generic class stores EXACTLY the three
# settings the YAML document carries; `PrettyFormatter` would additionally
# stamp its seven constructor defaults into the profile, which is a
# different document that happens to behave the same today.


def _php_literal(value, indent: int) -> str:
    """One PHP literal for a value of the synthesised profile document.

    The document holds only what `write_behat_config` puts there: the
    scalars, lists and nested mappings of one Behat profile.  `null` is a
    VALUE here rather than an absence -- Mink spells a driver that takes no
    options `'symfony' => ['symfony' => null]` -- so it is rendered, not
    dropped, exactly as `yaml.safe_dump` writes it on the other branch.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):                  # before int: bool IS an int
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        # PHP single quotes: only `\` and `'` are escapes inside them, which
        # matters here because every context and every extension is a
        # backslash-separated class name.
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"
    if isinstance(value, dict):
        pad, inner = " " * indent, " " * (indent + 4)
        body = "".join(
            f"{inner}{_php_literal(k, indent + 4)} => "
            f"{_php_literal(v, indent + 4)},\n" for k, v in value.items())
        return f"[\n{body}{pad}]"
    if isinstance(value, list):
        # A PHP list, i.e. an array with the integer keys PHP supplies: the
        # settings that are sequences (`args`, `chromedriver_arguments`) are
        # read positionally by Symfony's config tree, so the keys must not
        # be written out.
        pad, inner = " " * indent, " " * (indent + 4)
        body = "".join(f"{inner}{_php_literal(v, indent + 4)},\n"
                       for v in value)
        return f"[\n{body}{pad}]"
    raise TypeError(f"no PHP literal for {value!r} in the Behat profile")


def _render_behat_php(profile: str, doc: dict) -> str:
    """The synthesised profile as a Behat 4 PHP configuration file.

    `doc` is the one profile's body -- the same mapping the YAML renderer
    dumps -- so the two renderings cannot drift apart in what they say,
    only in how they spell it.  `calls.error_reporting` is the one key whose
    two spellings differ in MATERIAL: here the constant expression upstream
    writes, which PHP adds up on the way into
    `TesterOptions::withErrorReporting(int)`, and there the mask itself.
    """
    uses = ["Behat\\Config\\Config", "Behat\\Config\\Extension",
            "Behat\\Config\\Formatter\\Formatter", "Behat\\Config\\Profile",
            "Behat\\Config\\Suite"]
    reporting = (doc.get("calls") or {}).get("error_reporting")
    if reporting is not None:
        uses.append("Behat\\Config\\TesterOptions")
    out = ["<?php\n",
           "// GENERATED per item by r2t.bench.harness (SPEC \u00a74).\n",
           "\n",
           "declare(strict_types=1);\n",
           "\n"]
    out += [f"use {name};\n" for name in uses]
    out += ["\n",
            "return (new Config())\n",
            "    ->withProfile(\n",
            f"        (new Profile({_php_literal(profile, 8)}))\n"]
    for name, settings in (doc.get("formatters") or {}).items():
        out.append(f"            ->withFormatter(new Formatter("
                   f"{_php_literal(name, 12)}, "
                   f"{_php_literal(settings, 12)}))\n")
    if reporting is not None:
        # Where upstream puts it: on the Profile, before the extensions.
        # Every constant is written with the root-namespace `\` the way
        # `behat.dist.php` writes it -- this file declares no namespace, so
        # the prefix is spelling rather than resolution, and it is here so
        # that `SYLIUS_BENCH_CONFIG_PHP` reads as upstream's own line.
        expr = re.sub(r"E_[A-Z_]+", r"\\\g<0>", reporting)
        out.append(f"            ->withTesterOptions((new TesterOptions())"
                   f"->withErrorReporting({expr}))\n")
    for name, settings in (doc.get("extensions") or {}).items():
        # A bare extension is `Ext: null` in the YAML -- Behat's own spelling
        # for "register it, no options" -- and an `Extension` with no
        # settings argument here.
        args = "" if not settings else f", {_php_literal(settings, 12)}"
        out.append(f"            ->withExtension(new Extension("
                   f"\\{name}::class{args}))\n")
    for name, suite in (doc.get("suites") or {}).items():
        out.append("            ->withSuite(\n"
                   f"                (new Suite({_php_literal(name, 16)}))\n"
                   "                    ->withContexts(\n")
        for context in suite["contexts"]:
            out.append(f"                        "
                       f"{_php_literal(context, 24)},\n")
        out.append("                    )\n")
        out.append("                    ->withPaths("
                   + ", ".join(_php_literal(path, 20)
                               for path in suite["paths"]) + ")\n")
        out.append("            )\n")
    out.append("    );\n")
    return "".join(out)


def _write_if_changed(path: str, text: str) -> bool:
    """Rewriting an unchanged config file is not free.

    Symfony's debug container invalidates on the mtime of every tracked
    resource, so re-emitting byte-identical YAML for each item would force
    a full container recompile (~2 s) on every run of the validation
    sweep — thousands of rebuilds that change nothing.
    """
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            if fh.read() == text:
                return False
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return True


#: Environment keys whose VALUE is a credential.
#:
#: `docker exec -e KEY=value` puts the value into the host's process
#: arguments, where every user on the machine can read it out of `/proc`
#: for as long as the exec runs.  A per-worker database password would be
#: exposed on every one of the ~19 execs an item costs.  The runner
#: therefore refuses to carry one at all: worker credentials are baked into
#: the container's environment at `docker run --env-file` from a mode-0600
#: file the coordinator owns (SPEC_C3_PARALLEL §3.2, H3), so they are never
#: an argument of anything.
#:
#: Matched on the KEY, not the value — a value-based guess would either miss
#: a password that looks like a word or refuse a coverage flag that looks
#: like a hash.
_SECRET_ENV_KEY = re.compile(
    r"(PASS|PASSWD|PASSWORD|SECRET|TOKEN|API_?KEY|CREDENTIAL|_DSN|^DSN)", re.I)


class SecretInArgv(RuntimeError):
    """Raised rather than silently publishing a credential to `/proc`."""


def _docker_exec_env_args(env: Optional[dict] = None) -> list[str]:
    """Validate and render only the pure ``docker exec`` environment part.

    Keeping the credential guard independent of Docker command construction
    lets source-only tests exercise the actual policy without fabricating an
    execution authority or touching a daemon.
    """
    envs = []
    for key, value in (env or {}).items():
        if _SECRET_ENV_KEY.search(key):
            raise SecretInArgv(
                f"refusing to pass {key} as a `docker exec -e` argument: its "
                f"value would be readable in the host's process list. "
                f"Inject worker credentials with `docker run --env-file` "
                f"instead (SPEC_C3_PARALLEL §3.2).")
        envs += ["-e", f"{key}={value}"]
    return envs


# PID 1 of a long-lived isolated Java session: it must hold the container open
# without a network, without writing anywhere, and without inventing work.  A
# sleep loop is the portable spelling (`sleep infinity` is a GNU extension the
# corpus images are not all required to carry).
_ISOLATED_JAVA_SESSION_IDLE = "while :; do sleep 3600; done"

#: The isolated-PHP session's own PID 1, and the ONLY thing that
#: container is ever told to do besides the execs the audit sends it.
#: `php -r` rather than the Java shape's `sh -lc`: this route keeps a
#: shell out of the image entirely (see `_isolated_php_argv`), and the
#: interpreter that idles is the one the probe has just identified.
_ISOLATED_PHP_SESSION_IDLE = "while (true) { sleep(3600); }"


class DockerRunner:
    """Everything that has to happen inside the PHP container."""

    def __init__(self, container: str, workdir: str = "/var/www/html",
                 docker_group: bool = True):
        self.container = container
        self.workdir = workdir
        self.docker_group = docker_group
        self._isolated_image = None

    def _docker(self, argv: list[str], *, timeout: int
                ) -> subprocess.CompletedProcess:
        from ..core.docker_cli import docker_command
        command = docker_command(argv, docker_group=self.docker_group)
        return subprocess.run(command, capture_output=True, text=True,
                              timeout=timeout)

    def _image_for_isolated_run(self) -> str:
        """Resolve this worker's exact image once for trusted sidecars."""
        if self._isolated_image is not None:
            return self._isolated_image
        cp = self._docker(
            ["inspect", "--format", "{{.Image}}", self.container],
            timeout=120)
        image = (cp.stdout or "").strip()
        if cp.returncode != 0 or re.fullmatch(r"sha256:[0-9a-f]{64}", image) \
                is None:
            raise RuntimeError(
                "REFUSED: cannot resolve the mutation worker's exact image "
                f"for isolated Java analysis: {(cp.stderr or cp.stdout)[-300:]}")
        self._isolated_image = image
        return image

    def _isolated_docker_run(
            self, argv: list[str], *, timeout: int, label: str = "java"
            ) -> subprocess.CompletedProcess:
        """Run a named disposable sidecar and reap it if the client dies.

        ``docker run --rm`` removes a container after its process exits; it
        does not remove a still-running container when Python times out and
        kills only the attached Docker client.  A surviving Java applier
        would retain the workspace's RW mount and could write after mutation
        restoration.  Give every sidecar an unguessable exact name, force it
        away on every client exception, and prove the name is absent before
        control returns to restoration code.
        """
        if argv[:2] != ["run", "--rm"]:
            raise RuntimeError(
                "REFUSED: isolated Docker lifecycle requires run --rm")
        name = f"r2t-{label}-sidecar-" + secrets.token_hex(16)
        named_argv = [*argv[:2], "--name", name, *argv[2:]]
        try:
            return self._docker(named_argv, timeout=timeout)
        except BaseException as launch_error:               # noqa: BLE001
            cleanup_problem = self._reap_isolated_container(name)
            if cleanup_problem is not None:
                raise RuntimeError(
                    "REFUSED: isolated Java sidecar client failed and its "
                    "container could not be proved absent: "
                    + cleanup_problem) from launch_error
            raise

    def _reap_isolated_container(self, name: str) -> Optional[str]:
        """Force one named sidecar away and prove the name absent.

        Returns ``None`` when absence is proved -- including the ordinary case
        where the container had already exited and removed itself, so `rm -f`
        failed but the census is empty -- and otherwise the exact problem
        text, which every caller must surface rather than swallow.
        """
        removal_problem = None
        try:
            removed = self._docker(["rm", "-f", name], timeout=120)
            if removed.returncode != 0:
                removal_problem = (
                    "docker rm -f rc=" + str(removed.returncode) + ": "
                    + (removed.stderr or removed.stdout or "")[-300:])
        except BaseException as exc:                        # noqa: BLE001
            removal_problem = (
                "docker rm -f raised " + type(exc).__name__ + ": "
                + str(exc))
        absence_problem = None
        try:
            census = self._docker(
                ["ps", "-aq", "--no-trunc", "--filter",
                 "name=^/" + name + "$"], timeout=120)
            if census.returncode != 0 or (census.stdout or "").strip():
                absence_problem = (
                    "sidecar absence was not proved (rc="
                    + str(census.returncode) + ", ids="
                    + repr((census.stdout or "").strip()) + "): "
                    + (census.stderr or "")[-300:])
        except BaseException as exc:                        # noqa: BLE001
            absence_problem = (
                "sidecar census raised " + type(exc).__name__ + ": "
                + str(exc))
        if absence_problem is None:
            return None
        cleanup_detail = ([removal_problem]
                          if removal_problem is not None else [])
        cleanup_detail.append(absence_problem)
        return "; ".join(cleanup_detail)

    @staticmethod
    def _isolated_base_flags(tmpfs_size: str, *,
                             detach: bool = False) -> list[str]:
        """The isolation posture every trusted sidecar shares, in ONE place.

        `_isolated_java_argv`'s docstring already makes the argument for the
        two Java shapes -- mounts, network, pids, privilege, root filesystem
        and tmpfs must not drift apart -- and a third language made the list
        a fourth literal copy.  Only the tmpfs size and the detach flag ever
        differ, so only those are arguments.
        """
        return [
            "run", "--rm", *(["-d"] if detach else []),
            "--network", "none", "--pids-limit", "128",
            "--security-opt", "no-new-privileges", "--read-only",
            "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size={tmpfs_size}",
        ]

    @staticmethod
    def _isolated_env_args(env: Optional[dict]) -> list[str]:
        """Render an isolated container's environment, for `run` and `exec`.

        One renderer so a session's per-mutant `exec` carries the variable
        in exactly the spelling and order the equivalent `docker run` would
        have carried it: the transport changed, the applier's environment
        did not.
        """
        return [part for key, value in sorted((env or {}).items())
                for part in ("--env", f"{key}={value}")]

    @staticmethod
    def _isolated_bind(host: str, runtime: str, *, readonly: bool) -> list[str]:
        host = os.path.abspath(host)
        if ("," in host or "," in runtime or not runtime.startswith("/")
                or os.path.islink(host) or os.path.realpath(host) != host):
            raise RuntimeError(
                "REFUSED: isolated Java mount is not a canonical safe path: "
                f"{host} -> {runtime}")
        option = f"type=bind,src={host},dst={runtime}"
        if readonly:
            option += ",readonly"
        return ["--mount", option]

    @staticmethod
    def _isolated_java_env() -> list[str]:
        """Override Java launcher inputs that may be set by image metadata."""
        # Import lazily: harness is a shared stack primitive while the Java
        # mutator is an optional binding loaded by mutation_run.
        from ..toolkit.mutation_java import AMBIENT_JAVA_ENV_KEYS
        return [part for key in AMBIENT_JAVA_ENV_KEYS
                for part in ("--env", key + "=")]

    def prepare_isolated_java_applier(
            self, source_host: str, classes_host: str, *, timeout: int = 300,
            java_home: Optional[str] = None
            ) -> subprocess.CompletedProcess:
        """Compile the trusted engine where submitted processes cannot see it."""
        from ..toolkit.mutation_java import java_sidecar_shell_prefix

        source = os.path.abspath(source_host)
        classes = os.path.abspath(classes_host)
        if not os.path.isfile(source) or os.path.islink(source) \
                or not os.path.isdir(classes) or os.path.islink(classes):
            raise RuntimeError(
                "REFUSED: isolated Java engine source/classes are not "
                "canonical regular inputs")
        source_runtime = "/opt/r2t-engine-source"
        classes_runtime = "/opt/r2t-engine-classes"
        command = (
            java_sidecar_shell_prefix(self.workdir, java_home=java_home)
            + "\"$JAVA_HOME/bin/javac\" -proc:none "
            "-classpath \"$JAVA_HOME/lib/tools.jar\" "
            f"-d {shlex.quote(classes_runtime)} "
            f"{shlex.quote(source_runtime + '/' + os.path.basename(source))}")
        argv = [
            *self._isolated_base_flags("256m"),
            *self._isolated_java_env(),
            *self._isolated_bind(os.path.dirname(source), source_runtime,
                                 readonly=True),
            *self._isolated_bind(classes, classes_runtime, readonly=False),
            "--entrypoint", "/bin/sh", self._image_for_isolated_run(),
            "-lc", command,
        ]
        return self._isolated_docker_run(argv, timeout=timeout)

    def probe_isolated_java_toolchain(
            self, *, timeout: int = 120,
            java_home: Optional[str] = None) -> subprocess.CompletedProcess:
        """Identify java and javac in the exact image used by sidecars."""
        from ..toolkit.mutation_java import toolchain_probe_command
        argv = [
            *self._isolated_base_flags("64m"),
            *self._isolated_java_env(),
            "--entrypoint", "/bin/sh", self._image_for_isolated_run(),
            "-lc", toolchain_probe_command(
                self.workdir, java_home=java_home),
        ]
        return self._isolated_docker_run(argv, timeout=timeout)

    def _isolated_php_argv(
            self, *, workspace_host: Optional[str], env: Optional[dict],
            entrypoint: str, arguments: list[str],
            tmpfs_size: str, detach: bool = False) -> list[str]:
        """The one isolated-PHP container shape every PHP sidecar shares.

        Deliberately NOT `sh -lc`, which is what the Java shape needs for its
        launcher prefix: a PHP mutant descriptor carries the original and
        mutated SOURCE TEXT (`--original '$a && $b'`), and handing that to a
        shell would make the population's own contents decide the argv.  The
        applier is the entrypoint and its arguments are container arguments,
        so no shell ever sees them.

        Everything else is the isolated-Java posture, for the same reasons:
        no network, no new privileges, a read-only root filesystem with one
        small tmpfs, and a pids cap.  The one read-write mount is the
        disposable copy, at the same `workdir` the worker binds its workspace
        at -- so a `--root` the audit computes from `workdir` names the same
        tree the host reads back afterwards.
        """
        return [
            *self._isolated_base_flags(tmpfs_size, detach=detach),
            *self._isolated_env_args(env),
            *(self._isolated_bind(workspace_host, self.workdir,
                                  readonly=False)
              if workspace_host is not None else []),
            *(["--workdir", self.workdir] if workspace_host is not None
              else []),
            "--entrypoint", entrypoint, self._image_for_isolated_run(),
            *arguments,
        ]

    def probe_isolated_php_toolchain(
            self, *, interpreter: str = "php", timeout: int = 120
            ) -> subprocess.CompletedProcess:
        """Identify the PHP interpreter in the exact image used by sidecars.

        The counterpart of `probe_isolated_java_toolchain`, and narrower on
        purpose: a PHP population's parser identity is `composer.lock`'s, read
        from the disposable copy and confirmed again by every parse the
        applier reports, so this probe owns one question only -- is the
        interpreter the applier is about to be run under actually present in
        this image.  Answering it costs one container and saves a population's
        worth of `exited 127`.
        """
        return self._isolated_docker_run(
            self._isolated_php_argv(
                workspace_host=None, env=None, entrypoint=interpreter,
                arguments=["--version"], tmpfs_size="64m"),
            timeout=timeout, label="php")

    def open_isolated_php_session(
            self, *, workspace_host: str, interpreter: str = "php",
            timeout: int = 300) -> "IsolatedPhpSession":
        """Open ONE isolated PHP container to be driven by many cheap execs.

        The Java route's answer, ported (`open_isolated_java_session`).  A
        `docker run` per applier invocation cost track S about 2.5 s per
        mutant in the Sylius image -- TWO container starts, the applier and
        the parse -- which is ~30 h for that population's 43,670 mutants.  A
        `docker exec` into an already-running container costs 0.1-0.3 s, and
        the container it execs into is the one `_isolated_php_argv` would
        have started anyway: same image, same single read-write mount at
        `workdir`, same network/pids/privilege/root-filesystem/tmpfs flags,
        same absence of a shell.  This is TRANSPORT ONLY.

        The safety property the per-call sidecar bought by exiting -- nothing
        retains the disposable copy's read-write mount once control returns
        to restoration code -- is bought here by the close protocol, exactly
        as the Java session buys it: any exec failure closes the session, and
        every close force-removes the container and proves the name absent.
        """
        argv = self._isolated_php_argv(
            workspace_host=workspace_host, env=None, entrypoint=interpreter,
            arguments=["-r", _ISOLATED_PHP_SESSION_IDLE],
            tmpfs_size="256m", detach=True)
        if argv[:3] != ["run", "--rm", "-d"]:
            raise RuntimeError(
                "REFUSED: isolated PHP session lifecycle requires "
                "run --rm -d")
        name = "r2t-php-session-" + secrets.token_hex(16)
        named_argv = [*argv[:3], "--name", name, *argv[3:]]
        try:
            cp = self._docker(named_argv, timeout=timeout)
        except BaseException as launch_error:               # noqa: BLE001
            cleanup_problem = self._reap_isolated_container(name)
            if cleanup_problem is not None:
                raise RuntimeError(
                    "REFUSED: isolated PHP session client failed and its "
                    "container could not be proved absent: "
                    + cleanup_problem) from launch_error
            raise
        if cp.returncode != 0:
            cleanup_problem = self._reap_isolated_container(name)
            raise RuntimeError(
                "REFUSED: the isolated PHP audit session container did not "
                f"start (rc={cp.returncode}): "
                + (cp.stderr or cp.stdout or "")[-300:]
                + ("" if cleanup_problem is None
                   else "; " + cleanup_problem))
        return IsolatedPhpSession(self, name=name)

    def _isolated_java_argv(
            self, inner: str, *, workspace_host: str, analysis_host: str,
            classes_host: str, analysis_runtime: str, classes_runtime: str,
            detach: bool) -> list[str]:
        """Build the one isolated-Java container shape both transports use.

        The per-mutant sidecar and the long-lived audit session differ by
        exactly ``-d`` and the shell they are handed.  Building both here is
        what keeps their mounts, network, pids, privilege, root-filesystem
        and launcher-environment flags from drifting apart.
        """
        workspace = os.path.abspath(workspace_host)
        if not os.path.isdir(workspace) or os.path.islink(workspace):
            raise RuntimeError(
                "REFUSED: isolated Java workspace is not canonical")
        from ..toolkit.mutation_java import java_sidecar_shell_prefix
        return [
            *self._isolated_base_flags("256m", detach=detach),
            *self._isolated_java_env(),
            *self._isolated_bind(workspace, self.workdir, readonly=False),
            *self._isolated_bind(analysis_host, analysis_runtime,
                                 readonly=True),
            *self._isolated_bind(classes_host, classes_runtime, readonly=True),
            "--workdir", self.workdir, "--entrypoint", "/bin/sh",
            self._image_for_isolated_run(), "-lc",
            java_sidecar_shell_prefix(self.workdir) + inner,
        ]

    def run_isolated_java(
            self, inner: str, *, workspace_host: str, analysis_host: str,
            classes_host: str, analysis_runtime: str, classes_runtime: str,
            timeout: int = 900) -> subprocess.CompletedProcess:
        """Run javac with recipe/engine mounts hidden from submitted code.

        The long-lived worker exposes only ``workspace_host`` read-write.
        This short-lived container receives the authenticated analysis tree
        and compiled mutation engine as nested read-only authorities.  A
        daemon left by submitted test code in the worker therefore cannot
        observe, rewrite, or ABA-swap either pathname while javac consumes it.
        """
        argv = self._isolated_java_argv(
            inner, workspace_host=workspace_host, analysis_host=analysis_host,
            classes_host=classes_host, analysis_runtime=analysis_runtime,
            classes_runtime=classes_runtime, detach=False)
        return self._isolated_docker_run(argv, timeout=timeout)

    def open_isolated_java_session(
            self, *, workspace_host: str, analysis_host: str,
            classes_host: str, analysis_runtime: str, classes_runtime: str,
            timeout: int = 300) -> "IsolatedJavaSession":
        """Open ONE isolated container to be driven by many cheap execs.

        `run_isolated_java` pays a container start/stop round trip per call.
        That is free for a handful of fixture mutants and ruinous for a real
        population: the first full-population Java materialisation audit
        measured 0.6-1.8 mutants/min over 7,766 mutants -- three to nine days
        -- with the driver process at 0.1% CPU, waiting on Docker rather than
        computing (PROVENANCE §A27 step 5).  The proven DOCX audit pays for one
        container and walks 2,942 mutants inside it in about 15 minutes.
        This is that shape for Java, and it is TRANSPORT ONLY: the image, the
        mounts, the isolation flags and the guarded inner command bytes are
        the ones `run_isolated_java` would have used, one `docker exec` at a
        time instead of one `docker run` at a time.
        """
        argv = self._isolated_java_argv(
            _ISOLATED_JAVA_SESSION_IDLE, workspace_host=workspace_host,
            analysis_host=analysis_host, classes_host=classes_host,
            analysis_runtime=analysis_runtime,
            classes_runtime=classes_runtime, detach=True)
        if argv[:3] != ["run", "--rm", "-d"]:
            raise RuntimeError(
                "REFUSED: isolated Java session lifecycle requires "
                "run --rm -d")
        name = "r2t-java-session-" + secrets.token_hex(16)
        named_argv = [*argv[:3], "--name", name, *argv[3:]]
        try:
            cp = self._docker(named_argv, timeout=timeout)
        except BaseException as launch_error:               # noqa: BLE001
            cleanup_problem = self._reap_isolated_container(name)
            if cleanup_problem is not None:
                raise RuntimeError(
                    "REFUSED: isolated Java session client failed and its "
                    "container could not be proved absent: "
                    + cleanup_problem) from launch_error
            raise
        if cp.returncode != 0:
            cleanup_problem = self._reap_isolated_container(name)
            raise RuntimeError(
                "REFUSED: the isolated Java audit session container did not "
                f"start (rc={cp.returncode}): "
                + (cp.stderr or cp.stdout or "")[-300:]
                + ("" if cleanup_problem is None
                   else "; " + cleanup_problem))
        return IsolatedJavaSession(self, name=name)

    def _wrap(self, inner: str, env: Optional[dict] = None, *,
              stdin: bool = False) -> list[str]:
        envs = _docker_exec_env_args(env)
        from ..core.docker_cli import docker_command
        return docker_command(
            ["exec", *(["-i"] if stdin else []), *envs, self.container, "sh", "-lc",
             f"cd {shlex.quote(self.workdir)} && {inner}"],
            docker_group=self.docker_group)

    def in_container(self, rel: str) -> str:
        """A workspace-relative path as the CONTAINER sees it.

        The workspace is bind-mounted at `workdir`, which is `/var/www/html`
        for every worker by convention but is NOT hard-coded: a worker
        mounted anywhere else used to score every item `no_scenario_ran`,
        because the recorder was told to write to a path that did not exist
        and the harness then read an empty record file (defect 2, H2).
        """
        return f"{self.workdir.rstrip('/')}/{rel.lstrip('/')}"

    def run(self, inner: str, env: Optional[dict] = None,
            timeout: int = 900, *, input: Optional[str] = None
            ) -> subprocess.CompletedProcess:
        # Source transforms can exceed the OS per-argument limit. Pass their
        # encoded bytes through Docker exec stdin instead of the shell command.
        # Subject diagnostics can contain malformed UTF-8 (including under a
        # mutant). Keep those bytes visible as escapes instead of aborting the
        # campaign while decoding console output; recorded test data is separate.
        kwargs = {} if input is None else {"input": input}
        return subprocess.run(self._wrap(inner, env, stdin=input is not None),
                              capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="backslashreplace",
                              **kwargs)


class IsolatedJavaSession:
    """One long-lived isolated Java container, one cheap exec per mutant.

    The container is the one `DockerRunner.run_isolated_java` would have
    started -- same image, same three mounts with the same read-only
    settings, same network/pids/privilege/root-filesystem flags, same erased
    Java launcher environment, same guarded inner shell -- held open for the
    whole walk.  The safety property the per-call sidecar bought by exiting
    (nothing retains the read-write workspace mount once control returns to
    restoration code) is bought here by the close protocol: any exec failure
    closes the session, and every close force-removes the container and
    proves the name absent before returning.
    """

    def __init__(self, runner: DockerRunner, *, name: str):
        self.runner = runner
        self.name = name
        self.workdir = runner.workdir
        self.execs = 0
        self.opened = True

    def run(self, inner: str, *, timeout: int = 900
            ) -> subprocess.CompletedProcess:
        if not self.opened:
            raise RuntimeError(
                "REFUSED: the isolated Java session is closed")
        from ..toolkit.mutation_java import java_sidecar_shell_prefix
        argv = [
            "exec", *self.runner._isolated_java_env(),
            "--workdir", self.runner.workdir, self.name, "/bin/sh", "-lc",
            java_sidecar_shell_prefix(self.runner.workdir) + inner,
        ]
        try:
            cp = self.runner._docker(argv, timeout=timeout)
        except BaseException as exec_error:                 # noqa: BLE001
            self.opened = False
            cleanup_problem = self.runner._reap_isolated_container(self.name)
            if cleanup_problem is not None:
                raise RuntimeError(
                    "REFUSED: an isolated Java session exec failed and its "
                    "container could not be proved absent: "
                    + cleanup_problem) from exec_error
            raise
        self.execs += 1
        return cp

    def close(self) -> None:
        if not self.opened:
            return
        self.opened = False
        cleanup_problem = self.runner._reap_isolated_container(self.name)
        if cleanup_problem is not None:
            raise RuntimeError(
                "REFUSED: the isolated Java session container could not be "
                "proved absent: " + cleanup_problem)


class IsolatedPhpSession:
    """One long-lived isolated PHP container, one cheap exec per mutant.

    The container is the one `DockerRunner._isolated_php_argv` describes --
    same image, the disposable copy as the ONE read-write mount at `workdir`,
    the same network/pids/privilege/root-filesystem/tmpfs flags, and NO shell
    anywhere -- held open for a whole walk instead of started and reaped per
    invocation.

    The applier's argument vector is still the W11 descriptor: what a
    `docker exec` is handed is the interpreter and two constant, path-shaped
    tokens, so a deletion-shaped mutant's empty replacement never becomes a
    Docker argument here either.
    """

    def __init__(self, runner: DockerRunner, *, name: str):
        self.runner = runner
        self.name = name
        self.workdir = runner.workdir
        self.execs = 0
        self.opened = True

    def run(self, argv: list[str], *, env: Optional[dict] = None,
            timeout: int = 900) -> subprocess.CompletedProcess:
        """One applier invocation, as a `docker exec` into this session.

        ``argv`` is what `run` would have handed the container as its
        entrypoint and arguments: every path in it already names the
        container's view, because only the caller knows which of its
        arguments are paths.
        """
        if not self.opened:
            raise RuntimeError(
                "REFUSED: the isolated PHP session is closed")
        exec_argv = [
            "exec", *self.runner._isolated_env_args(env),
            "--workdir", self.runner.workdir, self.name, *argv,
        ]
        try:
            cp = self.runner._docker(exec_argv, timeout=timeout)
        except BaseException as exec_error:                 # noqa: BLE001
            self.opened = False
            cleanup_problem = self.runner._reap_isolated_container(self.name)
            if cleanup_problem is not None:
                raise RuntimeError(
                    "REFUSED: an isolated PHP session exec failed and its "
                    "container could not be proved absent: "
                    + cleanup_problem) from exec_error
            raise
        self.execs += 1
        return cp

    def close(self) -> None:
        if not self.opened:
            return
        self.opened = False
        cleanup_problem = self.runner._reap_isolated_container(self.name)
        if cleanup_problem is not None:
            raise RuntimeError(
                "REFUSED: the isolated PHP session container could not be "
                "proved absent: " + cleanup_problem)


def _constructor_is_public(entry: dict) -> bool:
    """Whether this class can be constructed from outside — and so be a service.

    Read off the index's own record of every method's visibility:
    `analyze_php.php` writes `'public' => $st->isPublic()` into each
    `methods[]` entry, and the constructor is matched there by name the way
    the indexer matches it, case-insensitively.  There is no second key to
    read it from, and there could not be: the analyzer installed in a
    workspace is under the substrate digest baseline and is deliberately
    never refreshed, so a new key would reach no index that already exists.

    A class that declares no constructor is instantiable, and so is every
    class of an index taken before `methods` existed (the analyzer in
    CoreShop's scoring seed v1 still writes such indexes): with no record of
    the constructor, the answer is the one this file gave before it read
    visibility at all.
    """
    for method in entry.get("methods") or ():
        if (method.get("name") or "").lower() == "__construct":
            return bool(method.get("public"))
    return True


def _suite_names(body: dict) -> set:
    """Every spelling a suite-map suite gives its contexts.

    By FQCN and by service id both: the map records `{service id: FQCN}`
    for every context of the suite (retained ones included), while a
    registration may hand either spelling.  `contexts` fills in a ref the
    strip could not resolve to a class.
    """
    by_id = body.get("classes") or {}
    return set(by_id) | set(by_id.values()) | set(body.get("contexts") or ())


def contexts_of_other_suites(suites: Mapping, contexts: Iterable[str],
                             suite: str) -> list:
    """The `contexts` that a suite map files under other suites only.

    `suites` is a `suite_map.json`'s `suites`.  `write_behat_config` leaves
    these out of the item's suite (a gold closure carries them as
    constructor dependencies); `contexts_to_relist` decides which of them a
    candidate run lists after all.
    """
    mine = _suite_names(suites[suite])
    anywhere = set().union(*(_suite_names(body) for body in suites.values()))
    return [ctx for ctx in contexts if ctx not in mine and ctx in anywhere]


def contexts_to_relist(suites: Mapping, contexts: list, suite: str,
                       patterns: Mapping[str, Iterable[str]]) -> list:
    """The other-suite contexts a candidate run lists (harness 25, B).

    Sorted by class name, each other-suite context is listed unless one of
    its step patterns is already defined by a returned class listed before
    it: the suite's own and the novel classes, which harness 24 already
    lists, then the other-suite contexts already relisted.  `patterns` maps
    a class to its step patterns as the solution index records them
    (`analyze_php.php` `steps`).  A gold closure carries other suites'
    contexts as constructor dependencies, and in 30 Sylius closures such a
    dependency repeats a returned class's pattern (`RegistrationContext`
    and `CustomerContext` both define `I specify the first name as
    :firstName`); a verbatim copy of gold therefore still runs.  A pattern
    that repeats a RETAINED context, and an ambiguous step, still fail.
    """
    other = contexts_of_other_suites(suites, contexts, suite)
    defined = {pattern for ctx in contexts if ctx not in other
               for pattern in patterns.get(ctx) or ()}
    relisted = []
    for ctx in sorted(set(other)):
        own = set(patterns.get(ctx) or ())
        if own & defined:
            continue
        relisted.append(ctx)
        defined |= own
    return relisted


def step_patterns(index: dict) -> dict:
    """`{class: [step pattern, ...]}` of a solution index (`steps`)."""
    return {c["name"]: [step["pattern"] for step in c.get("steps") or ()]
            for finfo in index.get("files", {}).values()
            for c in finfo.get("classes", [])}


def leaves_required_unwired(body, service_id: str,
                            constructors: Mapping[str, list]) -> bool:
    """Whether a submitted fragment entry needs `autowire: true` (harness 25).

    True for a service DEFINITION of one of the solution's classes that does
    not say `autowire` either way and gives some required constructor
    parameter no argument.  An empty body (`Foo: ~`) defines its id's class;
    an `alias:` entry and an `'@id'` string define nothing; an entry for a
    class the solution does not define has no parameters here.  The parameters are the solution index's
    (`analyze_php.php` records each one's name, types, `has_default` and
    `variadic`); one with a default or a variadic one is not required.  An
    argument counts by position (a list entry, an integer key or
    `index_N`), by name (`$name`) or by type (a class or interface key).
    The fragment's own `_defaults` is the caller's to read.
    """
    body = {} if body is None else body
    if not isinstance(body, dict) or "alias" in body or "autowire" in body:
        return False
    parameters = constructors.get(str(body.get("class") or service_id).lstrip("\\"))
    arguments = body.get("arguments")
    keys = ({str(key).lstrip("\\") for key in arguments}
            if isinstance(arguments, dict) else set())
    for position, parameter in enumerate(parameters or ()):
        if parameter.get("has_default") or parameter.get("variadic"):
            continue
        if isinstance(arguments, list) and position < len(arguments):
            continue
        names = {str(position), f"index_{position}",
                 *(str(t).lstrip("\\") for t in parameter.get("types") or ())}
        if parameter.get("name"):
            names.add("$" + parameter["name"])
        if not names & keys:
            return True
    return False


class Harness:
    """One workspace, classified and written by the same root (H1).

    The boundary decides WHICH paths may be written and the manifest decides
    WHERE they are written, and until now nothing checked that the two
    agreed.  `--repo` reached only the boundary, so pointing the harness at
    worker 3 classified against worker 3 and then installed, swept and
    executed in worker 0 — silently, because every path involved existed in
    both.  The constructor refuses the disagreement instead of leaving it to
    each call site to remember.
    """

    def __init__(self, manifest: StripManifest, boundary: Boundary,
                 runner: DockerRunner, alias_table: Optional[dict] = None,
                 autowirable_types: Optional[set] = None,
                 derived_baseline: Optional[Mapping[str, bytes]] = None):
        root = os.path.abspath(manifest.repo_root)
        if os.path.abspath(boundary.repo_root) != root:
            raise ValueError(
                f"the boundary classifies against {boundary.repo_root} while "
                f"the manifest writes into {manifest.repo_root}. One workspace "
                f"per harness: pass --repo, which sets both.")
        self.man = manifest
        self.boundary = boundary
        #: The per-project row (`repo.BehatProject`).  A boundary with no
        #: `behat:` block is CoreShop's, so every value below is today's
        #: constant and no CoreShop path reads a new key.
        self.behat = behat_project(boundary)
        self._suite_map: Optional[dict] = None
        self.runner = runner
        self.alias_table = alias_table or {}
        self.autowirable_types = set(autowirable_types or ())
        self.root = root
        self._protected_ids: Optional[set] = None
        #: `rel -> sha256` for production files a MUTATION campaign has
        #: deliberately edited.  Empty for every ordinary run, so the
        #: tampering guard keeps its full strength; a mutation run declares
        #: exactly one file and the guard still refuses anything else.
        self.expected_mutations: dict = {}
        #: `rel -> seed bytes` for every seed member under
        #: `repo.DERIVED_STATE_ROOTS`, read from the verified seed by the
        #: routes that execute mutated pairs (`mutation-run`, `test-quality`)
        #: and by `worker reset-probe`.  Empty restores nothing, which is
        #: what every other route has always done.
        self.derived_baseline: dict = dict(derived_baseline or {})

    # --------------------------------------------------------------- rows
    @property
    def recorder_context(self) -> str:
        """The recorder's context class, in THIS project's namespace.

        `RECORDER_CONTEXT` is CoreShop's and stays what it is; the strip
        rewrites the hook's one namespace line for a project whose `Behat\\`
        PSR-4 root is somewhere else, and this is the same fact read from
        the row.
        """
        return f"{self.behat.recorder_namespace}\\BenchRecorderHook"

    def suite_map(self) -> dict:
        """`suite_map.json`, from the GOLD root, read once per workspace.

        Written by the strip, from the wiring the strip removed, and kept
        OUT of the workspace: each suite's entry names that suite's
        removable context service ids and their classes, which is the list
        of files the system under test is being asked to write (owner
        ruling 2026-09-10).  Gold is where the rest of the answer already
        lives and where `closures` already reads this file from.

        Read once because it does not change: reading it per item would be
        reading the same bytes 1955 times.
        """
        if self._suite_map is None:
            from ..toolkit.behat_suites import SUITE_MAP_NAME, load_suite_map
            path = os.path.join(self.man.gold_root, SUITE_MAP_NAME)
            if not os.path.isfile(path):
                raise RuntimeError(
                    f"REFUSED: {self.boundary.project} selects a suite per "
                    f"item, and {SUITE_MAP_NAME} is not in this run's gold "
                    f"root ({self.man.gold_root}). It is written by `strip` "
                    f"beside `strip_manifest.json`, and it is deliberately "
                    f"not in the workspace -- it names every suite's "
                    f"removable context ids, which is the answer. A gold "
                    f"root without it cannot say which contexts an item "
                    f"runs under; a workspace stripped before this ruling "
                    f"carries the old `{BENCH_DIR}/{SUITE_MAP_NAME}` and "
                    f"has to be re-cut, not read.")
            self._suite_map = load_suite_map(path)
        return self._suite_map

    def select_suite(self, tags,
                     feature_path: Optional[str] = None) -> Optional[str]:
        """Which arm suite this item belongs to, by tags and by path.

        `feature_path` is repo-relative, which is how a suite's own
        `paths` are recorded.  A project whose suites select by directory
        rather than by tag (PrestaShop) has nothing else to go on; one
        whose suites carry no paths (Sylius) is selected by tags exactly as
        before.
        """
        from ..toolkit.behat_suites import select_suite
        return select_suite(self.suite_map(), tags, feature_path)

    def feature_rel(self, feature) -> Optional[str]:
        """The item's feature file, as the suite map spells its paths.

        The runner parses it from `harness.root`, so this is that join
        undone; a feature read from outside the workspace stays outside
        every suite's paths, which selects no suite rather than the wrong
        one.
        """
        from ..toolkit.behat_suites import repo_relative
        return repo_relative(getattr(feature, "path", None), self.root)

    # ------------------------------------------------------------- writing
    def _abs(self, rel: str) -> str:
        path = os.path.normpath(os.path.join(self.root, rel))
        if not path.startswith(self.root + os.sep):
            raise ValueError(f"refusing to write outside the repo: {rel}")
        return path

    def install_solution(self, solution: Solution,
                         task: str = "criterion_to_test",
                         ) -> tuple[list[str], list[dict]]:
        """Write the solution's files, but only where test code may live.

        A solution that returns `src/CoreShop/Component/Order/Model/Order.php`
        would otherwise overwrite PRODUCTION code — permanently, since
        `clean_workspace` only sweeps removable territory, so the damage
        would silently persist into every later item.  It is also the
        cheapest way to pass a scenario without writing a test: patch the
        implementation instead.  Such files are refused and recorded; the
        refusal is data, not an error.
        """
        from ..core.boundary import REMOVABLE
        written: list[str] = []
        rejected: list[dict] = []
        for f in solution.files:
            rel = os.path.normpath(f.file_path.lstrip("/")).replace(os.sep, "/")
            if rel.endswith(".feature"):
                # For `requirement_to_test` the Gherkin IS part of the answer,
                # so `write_feature` consumes it and it is never written into
                # src.  For `criterion_to_test` the scenario is given and
                # fixed, and a `.feature` from the solution would replace the
                # very thing being measured.  That path was open: the boundary
                # classifies `src/CoreShop/Behat/**/*.feature` as removable, so
                # such a file was neither written nor rejected — it was
                # silently promoted to the executed feature, which also left
                # `expected_line` unset and disabled record identification.
                if task == "requirement_to_test":
                    continue
                rejected.append({"file_path": rel,
                                 "why": "feature_not_accepted_for_task"})
                continue
            if rel.startswith("..") or os.path.isabs(f.file_path):
                rejected.append({"file_path": f.file_path, "why": "path_escape"})
                continue
            if self.boundary.classify(rel) != REMOVABLE:
                rejected.append({"file_path": rel,
                                 "why": f"not_test_code:{self.boundary.classify(rel)}"})
                continue
            dst = self._abs(rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w", encoding="utf-8") as fh:
                fh.write(f.code)
            written.append(rel)
        return written, rejected

    # ------------------------------------------------------------ indexing
    def index_paths(self, rel_paths: list[str]) -> dict:
        """Static index of just-written files, via nikic/php-parser.

        The two maps are normalised because PHP's `json_encode` renders an
        EMPTY associative array as `[]`, not `{}`.  So a solution whose files
        ALL failed to parse — a syntax error, the single most likely output of
        a generator, and one the system under test chooses freely — produced
        `{"files": []}` here and crashed `write_registration` with
        `'list' object has no attribute 'values'`, aborting the sweep instead
        of recording `parse_or_compile_error` for that one item.
        """
        if not rel_paths:
            return {"root": self.workdir_root, "files": {}, "errors": {}}
        args = " ".join(f"--path {shlex.quote(p)}" for p in sorted(set(rel_paths)))
        out_rel = f"{BENCH_DIR}/solution_index.json"
        cp = self.runner.run(
            f"php {BENCH_DIR}/analyze_php.php --root {self.workdir_root} {args} "
            f"--out {out_rel}")
        path = os.path.join(self.root, out_rel)
        if cp.returncode != 0 or not os.path.isfile(path):
            return {"root": self.workdir_root, "files": {},
                    "errors": {"analyzer": cp.stderr[-2000:]}}
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["files"] = doc.get("files") or {}
        doc["errors"] = doc.get("errors") or {}
        return doc

    @property
    def workdir_root(self) -> str:
        return self.runner.workdir

    # ------------------------------------------------------- registration
    def protected_service_ids(self) -> set:
        """Service ids a solution's fragment may not define, alias or claim.

        `_bench/services.yml` imports `retained_services.yml` and THEN
        `services_item.yml`, and in Symfony a later definition replaces an
        earlier one — so an unvetted fragment is a channel for redefining any
        retained service by id.  Two of them decide the measurement:
        `RECORDER_CONTEXT` is the instrument that scores the run, and the
        retained `DoctrineORMContext` is the only per-scenario database
        isolation there is, because the container runs with
        `CORESHOP_SKIP_DB_SETUP=1` and nothing else rebuilds the schema.

        FriendsOfBehat resolves a suite `contexts:` entry as a service id, so
        merely *defining* one of these ids is enough — the container then has
        it, and the solution's class is what gets instantiated.

        A project with no Symfony wiring (`services_entry: null`) installs
        no `retained_services.yml`, and the set is then the recorder plus
        the boundary's always-registered contexts — which is the whole of
        what such a project registers by id, not a gap in the check.
        """
        if self._protected_ids is None:
            ids = {self.recorder_context}
            ids.update(self.boundary.retained_contexts)
            path = self._abs(f"{BENCH_DIR}/retained_services.yml")
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh) or {}
                ids.update(sid for sid in (doc.get("services") or {})
                           if sid != "_defaults")
            self._protected_ids = ids
        return self._protected_ids

    def vet_fragment(self, fragment: dict) -> tuple[dict, list[dict]]:
        """Drop fragment entries that reach outside the solution's own code.

        Only the entry's own identity is checked — its id, `class` and
        `alias`.  Its `arguments` are not: referring to a retained service
        (`@coreshop.behat.shared_storage`) is exactly what the channel is for,
        and gold's own fragment does it on nearly every item.
        """
        from ..core.boundary import REMOVABLE
        from .repo import _class_path_guess
        protected = self.protected_service_ids()
        clean, rejected = {}, []
        for sid, body in (fragment or {}).items():
            claims = [sid]
            if isinstance(body, dict):
                claims += [body.get("class"), body.get("alias")]
            elif isinstance(body, str):
                claims.append(body.lstrip("@"))
            why = None
            for claim in [c for c in claims if c]:
                claim = claim.lstrip("@?").lstrip("\\")
                if claim in protected:
                    why = f"protected_service_id:{claim}"
                    break
                guessed = _class_path_guess(claim, self.behat.psr4)
                if guessed and self.boundary.classify(guessed) != REMOVABLE:
                    why = (f"not_test_code:"
                           f"{self.boundary.classify(guessed)}:{claim}")
                    break
            if why:
                rejected.append({"file_path": SERVICES_FRAGMENT_NAME,
                                 "service_id": sid, "why": why})
                continue
            clean[sid] = body
        return clean, rejected

    def write_registration(self, index: dict, fragment: dict,
                           solution_digest: str = "none",
                           suite: Optional[str] = None,
                           candidate: bool = False) -> dict:
        """Symfony service definitions for the solution's own classes.

        Everything the solution defines is registered public + autowired +
        autoconfigured; `autoconfigure` is what makes a Behat context
        visible to FriendsOfBehat (it tags `Context` implementors) and what
        makes attribute-based registrations such as `#[AsCountryContext]`
        take effect.  An explicit fragment entry overrides the autowired
        default for that class.

        In a `candidate` run (not `Solution.gold_run`; harness 25), a
        fragment entry that leaves a required constructor parameter without
        an argument and says nothing about autowiring is autowired: the
        prompt promises every returned class is, and asks for an entry only
        for arguments autowiring cannot supply (`leaves_required_unwired`;
        specifications/EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md section
        3.3).  Not when the fragment's own `_defaults` says `autowire`
        either way.  A gold run's fragment is written exactly as given.  The
        ids that received it are returned as `autowired`.

        `suite` is this item's arm suite, for the FQCN alias below and
        nothing else; None everywhere it is not known, which is every
        project that is not suite-scoped.

        The returned `services` is every id this document defines -- the
        solution's FQCNs, the fragment's own ids, the type aliases and the
        FQCN aliases below.  It is what `write_behat_config` names the
        suite by: an id no registration defines is an id the container does
        not have.
        """
        # `autowire` is deliberately NOT in `_defaults`.  Symfony validates
        # every constructor parameter of an autowired service, so switching
        # it on for a definition that already carries a complete positional
        # `arguments:` list turns CoreShop's own wiring into a compile
        # error: `Setup\ProductContext` supplies 7 arguments to an 8-parameter
        # constructor whose last parameter has a default, which upstream is
        # free to leave unwired and autowiring is not.  Autowiring is applied
        # per service, only where no explicit definition was supplied -- and,
        # in a candidate run, to a supplied definition that leaves a required
        # parameter unwired, which cannot be instantiated without it.
        fragment, fragment_rejected = self.vet_fragment(fragment)
        services: dict = {"_defaults": {"public": True, "autoconfigure": True}}
        classes, contexts, ctor_free = [], [], set()
        constructors: dict = {}
        for finfo in index.get("files", {}).values():
            for c in finfo.get("classes", []):
                if c["kind"] != "class" or c.get("abstract"):
                    continue
                classes.append(c["name"])
                constructors[c["name"]] = c.get("constructor") or []
                if c.get("is_context"):
                    contexts.append(c["name"])
                required = [p for p in (c.get("constructor") or [])
                            if not p.get("has_default") and not p.get("variadic")]
                # A non-public constructor is not "no arguments needed",
                # it is "not instantiable at all": Symfony's
                # DefinitionErrorExceptionPass fails the WHOLE container with
                # `its constructor must be public`.  The index already
                # records the visibility of every method, so the constructor
                # is read there; an index that records no methods reads
                # exactly as it did before.
                if not required and _constructor_is_public(c):
                    ctor_free.add(c["name"])

        # Types CoreShop wires by service id rather than by class: without
        # these aliases an autowired registration cannot compile, and the
        # failure would be charged to the system under test rather than to
        # the wiring.  The table is derived from the substrate as a whole,
        # never from the item, so it reveals nothing about this scenario.
        #
        # Two guards, both learned the hard way.  A type the container can
        # ALREADY autowire is left alone: overriding it would silently
        # re-point an existing alias at a different implementation (CoreShop
        # has real cases — `ShippableCarrierValidatorInterface` resolves to
        # a composite by autowiring and to a concrete validator by hand).
        # And a type whose service id IS its own FQCN must not be aliased to
        # itself; Symfony rejects the container outright.
        needed_types = set()
        for finfo in index.get("files", {}).values():
            for c in finfo.get("classes", []):
                for p in c.get("constructor") or []:
                    needed_types.update(p.get("types") or [])
        for t in sorted(needed_types):
            t = t.lstrip("\\")
            if t in services or t in self.autowirable_types:
                continue
            target = self.alias_table.get(t)
            if target and target != t:
                services[t] = "@" + target

        # A Behat context has to be fetchable from the container, so it is
        # always registered.  A plain helper class is only registered when
        # it needs no constructor arguments AND its constructor is public:
        # registering an unwirable helper would break the whole container,
        # while leaving it unregistered costs nothing — the autoloader still
        # finds it, and any class that `new`s it does not care.
        #
        # The visibility half is Sylius: `Behat\Context\Api\Resources` and
        # `Subresources` are `final class R { public const ...; private
        # function __construct() {} }` constants-holders that most Api
        # contexts reference (`Resources::ADMINISTRATORS`), so they sit in
        # most closures.  Registered, they took the container down and
        # charged `container_error`/`di_unresolvable` to the system under
        # test; nothing ever needed them as services, because their
        # constants are read statically.
        fragment_classes = {
            (body.get("class") if isinstance(body, dict) else None) or sid
            for sid, body in (fragment or {}).items()}
        for name in classes:
            if name in fragment_classes:
                continue
            if name in contexts or name in ctor_free:
                services.setdefault(name, {"autowire": True})

        defaults = (fragment or {}).get("_defaults")
        autowire_free = candidate and not (isinstance(defaults, dict)
                                           and "autowire" in defaults)
        autowired = []
        for sid, body in (fragment or {}).items():
            if autowire_free and leaves_required_unwired(body, sid, constructors):
                body = dict(body or {}, autowire=True)
                autowired.append(sid)
            services[sid] = body

        # A `contexts:` entry that is a CLASS name still has to be
        # fetchable from the container, and a supplied fragment registers
        # the class under a dotted service id instead.  With no suite the
        # synthesised profile names EVERY context by class (CoreShop), and
        # a suite-scoped profile names one by class whenever this item's
        # registration defines no id the suite lists for it -- a novel
        # context, or a rewritten one the submission left to the autowired
        # FQCN.  FriendsOfBehat looks a `contexts:` entry up as a service id
        # and, when the container does not have it, hands the string to
        # Behat, which reflectively instantiates it and dies on the first
        # constructor argument.  An FQCN alias per context closes that gap
        # and keeps the suite vocabulary uniform.
        #
        # One class can have SEVERAL definitions — Sylius defines
        # `Api\Common\SaveContext` once per API client — and there is only
        # one FQCN to alias, so the alias picks one of them.  A
        # suite-scoped item's suite already says which definition it runs
        # (`write_behat_config` lists that id), and the alias follows it,
        # because the alias is how an injection BY TYPE is resolved and
        # handing such an injection the OTHER client's instance is defect 6
        # in the other channel.  With no suite, or a class the suite does
        # not list, the first definition wins as it always has.
        suite_ids = frozenset(
            self.suite_map()["suites"][suite].get("contexts") or ()
        ) if suite else frozenset()
        by_class: dict = {}
        for sid, body in services.items():
            if not isinstance(body, dict):
                continue
            cls = body.get("class")
            if cls and cls in contexts and cls not in services:
                by_class.setdefault(cls, []).append(sid)
        for cls, sids in by_class.items():
            # The explicit `alias:` + `public: true` form, not the
            # `Id: '@target'` shorthand: `_defaults.public` does not
            # reach shorthand aliases, so Symfony treats them as private
            # and RemoveUnusedDefinitionsPass deletes them — leaving
            # FriendsOfBehat unable to find the context and Behat
            # reflectively instantiating a class with constructor
            # arguments.  Verified on IndexContext, whose alias was
            # silently absent from the compiled container.
            services[cls] = {"alias": next((s for s in sids if s in suite_ids),
                                           sids[0]),
                             "public": True}

        doc = {"services": services}
        # The digest makes the compiled container depend on the solution's
        # CODE, not only on the shape of its registration: two consecutive
        # solutions with the same class names and constructor types produce
        # identical YAML, and without it the second would silently run
        # against the first's compiled container.
        text = ("# GENERATED per item by r2t.bench.harness — registration for the\n"
                "# solution under test (SPEC §4, decision D2).\n"
                f"# solution-digest: {solution_digest}\n"
                + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))
        if _write_if_changed(self._abs(REGISTRATION_REL), text):
            self.invalidate_container()
        return {"classes": classes, "contexts": contexts,
                "rejected_services": fragment_rejected,
                "services": sorted(k for k in services if k != "_defaults"),
                "aliases": sorted(k for k, v in services.items()
                                  if isinstance(v, str) and v.startswith("@")),
                "autowired": autowired}

    def prepare_for_generation(self) -> None:
        """Everything that must be gone BEFORE a system generates.

        `clean_workspace` sweeps removable territory, which is where a
        solution's files go — but two answer-bearing files live outside it
        and survived into the next item's generation window:

        * `_bench/solution_index.json`, the previous item's static index —
          its gold files, their constructors and every step-definition
          pattern with method names and parameter types;
        * `var/cache/test`, the compiled container, which names the
          previous item's context classes and their service arguments.

        Neither is removable territory (both classify as production), so
        neither sweep touched them, and an agent that reads the workspace
        could simply open them.  Cleared here, before generation.

        This is also where the substrate is verified, because it is the last
        moment at which a mismatch can still be attributed to the PREVIOUS
        item rather than to this one.
        """
        from .repo import clean_workspace
        clean_workspace(self.man, self.boundary)
        stale = self._abs(f"{BENCH_DIR}/solution_index.json")
        if os.path.exists(stale):
            os.remove(stale)
        self.runner.run(f"rm -rf {self.behat.cache_dir}", timeout=120)
        # The third thing that survives outside removable territory, on a
        # stack that has one: compiled python bytecode. It is answer-bearing
        # (a `.pyc` of a step module is a compiled answer) and it is ADDED
        # inside a substrate root, so leaving it turns the verification on the
        # next line into a tampering abort.
        self.purge_bytecode()
        self.verify_substrate()

    def purge_bytecode(self) -> list:
        """Sweep compiled bytecode, from inside the container and then out.

        Two halves, and the order is the whole point — the same order and the
        same reason as `invalidate_container`.  The `.pyc` files are written
        by a process running as ROOT inside the container, on a bind mount, so
        a host-side delete raises EPERM; the in-container `rm` runs as the uid
        that created them, and the host-side sweep then RE-SCANS and raises if
        anything survived.  Without the second half the first is unverified,
        and an unverified purge is what turned this into a silent no-op
        against a real worker the first time it ran.

        A no-op, with no container round trip at all, when the manifest
        declares no bytecode roots — which is every PHP tree.
        """
        from .repo import BYTECODE_DIR, purge_bytecode
        roots = list(self.man.bytecode_roots)
        if not roots:
            return []
        quoted = " ".join(shlex.quote(r) for r in roots)
        # `; true` so a root that does not exist in this tree is not a failed
        # exec: `find` exits nonzero for a missing path, and a purge that
        # reports failure because the tree is smaller than the policy would be
        # noise on every item.  Anything that really SURVIVES is caught by the
        # host-side sweep below, which is the check that matters.
        self.runner.run(
            f"find {quoted} -name {shlex.quote(BYTECODE_DIR)} -type d -prune "
            f"-exec rm -rf {{}} + 2>/dev/null; "
            f"find {quoted} -name '*.pyc' -delete 2>/dev/null; true",
            timeout=120)
        return purge_bytecode(self.root, roots)

    def verify_substrate(self) -> dict:
        """Refuse to continue against a tree that has changed under us.

        A solution's PHP runs as root on a read-write bind mount of the
        repository (`DockerRunner._wrap` passes no `--user`), so the write
        refusal in `install_solution` does not bound what the installed code
        does once it executes.  Nothing else in the harness would notice: a
        replaced recorder still writes records, and a patched production file
        still makes scenarios green.
        """
        from .repo import SubstrateTampered, verify_substrate
        if self.boundary.project == "prestashop":
            from .prestashop_resources import verify_entry
            verify_entry(self.man)
        report = verify_substrate(self.man, self.boundary,
                                  expected=self.expected_mutations)
        if report["baseline"] and (report["changed"] or report["missing"]
                                   or report["added"]):
            raise SubstrateTampered(report)
        return report

    def restore_derived_state(self, when: str = "before this pair") -> list:
        """Put generated class files back to their seed bytes before a pair.

        `verify_substrate` proves the SOURCE is what the campaign declared;
        this is the other half, the files the retained steps GENERATE from
        that source (`repo.DERIVED_STATE_ROOTS`).  A pair run under a mutant
        can regenerate `var/classes/DataObject/CoreShopProduct.php` without a
        return type its interface declares, and the mutant revert restores
        only the mutated source file -- so without this every later pair on
        the worker died on autoload.  Restored paths go to stderr, never
        stdout, which several verbs keep for one parseable JSON report;
        `when` says which pair boundary the line belongs to
        (`mutation_run.run_slice` also restores after a shard's last pair).

        Raises `repo.DerivedStateUnrestored` ("This worker must be
        reprovisioned") when a member will not take its seed bytes.
        """
        if not self.derived_baseline:
            return []
        from .repo import restore_derived_state
        restored = restore_derived_state(self.root, self.derived_baseline,
                                         self.runner)
        if restored:
            print(f"r2t: restored {len(restored)} derived-state file(s) to "
                  f"their seed bytes {when}: {', '.join(restored)}",
                  file=sys.stderr, flush=True)
        return restored

    def invalidate_container(self) -> None:
        """Delete the compiled container after changing its input.

        Symfony's freshness check is `filemtime(resource) <=
        filemtime(cache)`, at ONE-SECOND resolution.  Items in a batch are
        seconds apart, so a rewritten `services_item.yml` regularly lands
        in the same second as the previous run's compiled container and is
        judged fresh — the next item then runs against the PREVIOUS item's
        service graph, FriendsOfBehat cannot find its contexts, and Behat
        reflectively instantiates them and dies on the first constructor
        argument.  That failure is indistinguishable from a wiring bug and
        vanishes when the same item is run alone, which is exactly what
        made it worth a comment: it cost an hour of misdiagnosis.

        The deletion happens INSIDE the container.  `var/cache/test` is
        created by the containerised PHP process and is owned by root
        mode 755, so a host-side `os.remove` raises EPERM — which an
        `except OSError: pass` swallowed, turning this whole method into
        a silent no-op and reintroducing the bug it exists to prevent.
        The result is checked rather than assumed.
        """
        # Bytecode is the same bug in the other language: Symfony judges a
        # compiled container fresh by mtime at one-second resolution, and
        # CPython judges a `.pyc` fresh by the source's mtime and size at the
        # same resolution. Both hand the next item the previous item's code.
        # Swept here, at the site that exists for exactly that failure, and a
        # no-op with no container round trip on a stack that declares no
        # bytecode roots.
        self.purge_bytecode()
        bp = self.behat
        cache = os.path.join(self.root, *bp.cache_dir.split("/"))
        if not os.path.isdir(cache):
            return
        # Symfony's wrapper loads dumped services from Container<hash>/.
        # Removing only the wrapper leaves thousands of generated PHP files
        # behind per registration change. Both belong to this invalidation.
        prefixes = (bp.container_prefix, "Container")
        patterns = " ".join(shlex.quote(f"{bp.cache_dir}/{prefix}") + "*"
                            for prefix in prefixes)
        self.runner.run(f"rm -rf -- {patterns}", timeout=120)
        stale = [n for n in os.listdir(cache) if n.startswith(prefixes)]
        if stale:
            raise RuntimeError(
                "could not invalidate the compiled container; these survived "
                f"deletion and the next run would use a stale service graph: "
                f"{stale[:4]}")

    def clear_cache_pools(self) -> None:
        """Empty the kernel's cache pools before a mutation pair (harness 27).

        A Behat kernel with debug off keeps what it derives from source in
        `<cache_dir>/pools` and never checks it against that source.  On
        Sylius (`test_cached`) that includes the validator's class metadata:
        built constraint objects, rehydrated on a hit without running the
        constraint's constructor.  `invalidate_container` keeps the pools,
        and the container is rebuilt only when the item changes, so a mutant
        acting in a constraint constructor survived exactly when the
        worker's previous pair was the same item
        (`specifications/SYLIUS_VALIDATOR_CACHE_CORRECTION_AMENDMENT.md`).
        Emptied before every pair, the pools are built under the pair's own
        mutant, as on the cold first pair of a worker.

        A no-op for the debug kernels (CoreShop, PrestaShop), which register
        no validator mapping cache.  Deleted inside the container and then
        checked from the host, for the reason `invalidate_container` gives.
        """
        if self.boundary.project not in COLD_POOL_PROJECTS:
            return
        pools = f"{self.behat.cache_dir}/pools"
        self.runner.run(f"rm -rf -- {shlex.quote(pools)}", timeout=120)
        if os.path.exists(os.path.join(self.root, *pools.split("/"))):
            raise RuntimeError(
                f"could not empty the cache pools {pools}; the next mutation "
                "pair would read metadata built under an earlier mutant")

    def clear_registration(self) -> None:
        _write_if_changed(self._abs(REGISTRATION_REL), "services: {}\n")

    # -------------------------------------------------------------- suite
    @staticmethod
    def _example_row_lines(text: str, keyword_line: int) -> list:
        """1-based lines of the Examples DATA rows under `keyword_line`.

        Derived by re-parsing the file we just synthesised, not by guessing
        from the source feature: the standalone file has a different header
        and inlines the Background, so every line moved.  `Block.examples_lines`
        gives 0-based half-open spans that INCLUDE the `Examples:` keyword and
        the table's header row, so within each span the data rows are the
        `|` lines after the first one.
        """
        try:
            parsed = parse_feature_file("<synthesised>", text)
        except Exception:                                   # noqa: BLE001
            # The text can be authored by the system under test.  A file we
            # cannot re-parse means no extra lines, never a crash: the fold
            # then falls back to the keyword line alone, which is what the
            # scalar always did.
            return []
        block = parsed.scenario_at(keyword_line)
        if block is None:
            return []
        lines = text.split("\n")
        rows: list = []
        for start, end in block.examples_lines:
            header_seen = False
            for i in range(max(0, start), min(end, len(lines))):
                if not lines[i].lstrip().startswith("|"):
                    continue
                if not header_seen:
                    header_seen = True     # the column names, not a case
                    continue
                rows.append(i + 1)
        return rows

    def write_feature(self, feature: Feature, scenario: Block,
                      override: Optional[str] = None,
                      ) -> tuple[str, Optional[int], Optional[list]]:
        """The one scenario that will run.

        `override` exists for `requirement_to_test`, where the Gherkin is
        part of what the system had to produce: there the executed feature
        is the system's own, not the repository's.  What that outcome
        *means* is a metric question (a scenario asserting nothing also
        goes green) and is deferred with the rest of the metrics; v1
        records the raw execution outcome only.
        """
        text = override if override is not None else standalone_feature(
            feature, scenario, allow_tag_gaps=self.boundary.project == "prestashop")
        with open(self._abs(FEATURE_REL), "w", encoding="utf-8") as fh:
            fh.write(text)
        # The scenario's line in the SYNTHESISED file, which is NOT its line
        # in the repository: the standalone file has a different header and
        # inlines the Background.  The recorder reports the executed file's
        # line, so identifying a run's record by the source line matched
        # nothing for most items and matched by coincidence for the rest.
        #
        # Scanned for BOTH branches.  Leaving it None for an override meant
        # `RunResult.scenario` fell back to `records[-1]`, i.e. the identity
        # check that exists because the record file is forgeable was switched
        # off exactly when the solution had supplied the feature.
        #
        # A `Scenario Outline` runs once per Examples row and the recorder
        # stamps each record with the line of the ROW, never the keyword line
        # computed here.  The scalar is kept because archived rows carry it
        # and `to_json` exports it; `expected_lines` is what the fold matches
        # against, and for a plain scenario it is the scalar in a list.
        lines = [i for i, ln in enumerate(text.split("\n"), 1)
                 if _SCENARIO_LINE.match(ln)]
        expected_line = lines[-1] if lines else None
        expected_lines = None
        if expected_line is not None:
            expected_lines = [expected_line] + self._example_row_lines(
                text, expected_line)
        return text, expected_line, expected_lines

    def write_behat_config(self, contexts: list[str],
                           suite: Optional[str] = None,
                           registered: Iterable[str] = (),
                           relisted: Iterable[str] = ()) -> list[str]:
        """One profile, one suite, one feature file, no tag filter.

        No tag filter is deliberate: CoreShop's own profile filters on
        `@domain&&~@wip` and its suites filter per component, so any
        inherited filter would silently select ZERO scenarios and report
        success — a green run that executed nothing.

        `suite` is the arm suite this item belongs to, for a project whose
        row says `suite_scoped` (`select_suite`); its RETAINED context ids
        go in front of the boundary's always-registered ones, because on
        such a project the substrate a scenario needs is its suite's, not
        the union of every suite's.  A project that is not suite-scoped
        passes None and gets exactly the list it gets today.

        `contexts` is every `Context` implementor of the SOLUTION INDEX,
        which on a suite-scoped project is wider than the suite: the
        closure restores a context's DEPENDENCIES too, and a dependency is
        a service the container injects, not a member of the suite.
        Sylius's `Context\Api\Shop\CustomerContext` takes
        `RegistrationContext` and `LoginContext` through its constructor,
        so the closure carries their files (correctly) — but upstream's
        `api_resend_verification_email` binds `api.email`,
        `api.shop.customer` and `api.shop.login` and NOT
        `api.shop.registration`.  Listing every implementor put
        `CustomerContext` and `RegistrationContext` in one suite, both
        define `I specify the first name as :firstName`, and Behat aborts
        the run on the first step with `RedundantStepException` — the item
        scores `closure_incomplete` for a wiring artefact.

        So a solution context joins the suite only when (a) it is one of
        THIS suite's classes, or (b) it is in NO suite's classes -- a novel
        context has to be loaded or its steps are undefined.  One that
        belongs only to OTHER suites (`contexts_of_other_suites`) is left
        out of `contexts:`; it stays a registered service
        (`write_registration`) so the injection still resolves, and it
        stays in the closure.

        `relisted` takes some of those back, in a candidate run (harness
        25; specifications/EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md
        section 3.2).  Its prompt promises that every class it returns is
        registered, and which upstream suite a class name belongs to is
        evaluator data its view never shows: a context it wrote under the
        name of another suite's class used to vanish with every step it
        defined.  The caller decides which, and in which order
        (`contexts_to_relist`).  They are listed by class name, like a novel
        one, after everything harness 24 lists and before the recorder,
        which stays last: the recorder opens its coverage and call window in
        its `@BeforeScenario` hook and closes it in its `@AfterScenario`
        hook, and Behat runs hooks in context order, so a relisted class's
        hooks fall on the same side of that window as every other returned
        class's.  A gold run passes none, and its profile is harness 24's.

        A context of case (a) is listed by the SUITE'S OWN SERVICE ID for
        it, not by its class name (defect 6).  One class can carry several
        service definitions -- `Context\Api\Common\SaveContext` is defined
        once per API client, `...api.admin.save` on the admin client and
        `...api.shop.save` on the shop one -- and an item's closure carries
        every definition of a class it restores.  Listed by CLASS, the
        entry resolves through the FQCN alias to whichever definition came
        first, so a shop scenario ran the ADMIN SaveContext: its
        `CustomerContext` prepared a request on the shop client, `I try to
        save my changes` saved on the admin client, and 16
        `api_customer_account` items died at that step with `Call to a
        member function method() on null`.  The suite's id names the
        definition upstream's own suite runs; a class the suite maps under
        several ids gets each of them, in the suite's `contexts` order.  A
        novel context (case (b)) has no id to be named by and stays an
        FQCN, which is what `write_registration` registers it under.

        `registered` is the service ids THIS item's registration defines
        (`write_registration`'s `services`), and a suite id is listed only
        when it is one of them.  Gold always defines them -- its
        `di_fragment` carries upstream's own ids, which is why the 16 items
        above are fixed by naming `...api.shop.save` -- but an arm
        submission is under no such obligation: `profile_sylius.yml` tells
        it the harness registers every class it returns as public,
        autowired and autoconfigured, and offers the fragment only for
        constructor arguments autowiring cannot supply.  A submission that
        rewrites `Api\Shop\CustomerContext` and returns no fragment (or one
        under an id of its own, `app.my_customer`) is registered under its
        FQCN alone; listing `...api.shop.customer` for it would name an id
        the container does not have, FriendsOfBehat would skip it, and
        Behat's `UninitializedContextEnvironment` would throw
        `ContextNotFoundException` on the raw id -- killing the run instead
        of running the submission's context.  So an unregistered suite id
        falls back to the FQCN, which IS registered: as `{autowire: true}`
        when the submission gave no definition, and as the public alias to
        the submission's own id when it gave one under a name of its own.
        """
        bp = self.behat
        if suite is None:
            all_contexts = list(self.boundary.retained_contexts) + list(contexts)
        else:
            suites = self.suite_map()["suites"]
            mine = _suite_names(suites[suite])
            elsewhere = frozenset(contexts_of_other_suites(suites, contexts,
                                                           suite))
            # The inverse of `classes`, in the suite's own order: every id
            # THIS suite lists a class under.
            by_class: dict = {}
            declared = suites[suite].get("classes") or {}
            for sid in suites[suite].get("contexts") or ():
                cls = declared.get(sid)
                if cls:
                    by_class.setdefault(cls, []).append(sid)
            # Deduplicated, because the two lists genuinely overlap here: a
            # suite's retained ids and the boundary's always-registered ones
            # name the same hook contexts, and Behat aborts a suite that
            # registers one context twice.  The mapped ids go through the
            # same check: an id already listed as retained is not listed
            # again for the class the solution rewrote.
            all_contexts = list(suites[suite]["retained"])
            for ctx in self.boundary.retained_contexts:
                if ctx not in all_contexts:
                    all_contexts.append(ctx)
            defines = frozenset(registered)
            for ctx in contexts:
                if ctx in mine:
                    # `or [ctx]` is the ref the strip could not resolve to a
                    # class: it is in the suite by its own spelling, and that
                    # spelling is what the suite lists.  The filter is what
                    # keeps the suite's vocabulary to ids the container
                    # actually has; the trailing `or [ctx]` is the
                    # submission that registered none of them.
                    listed = [sid for sid in (by_class.get(ctx) or [ctx])
                              if sid in defines] or [ctx]
                elif ctx in elsewhere:
                    continue
                else:
                    listed = [ctx]
                for name in listed:
                    if name not in all_contexts:
                        all_contexts.append(name)
            for ctx in relisted:
                if ctx not in all_contexts:
                    all_contexts.append(ctx)
        all_contexts.append(self.recorder_context)

        # The row's settings are the BASE of each extension's body; the
        # SymfonyExtension's kernel block is computed on top, because which
        # kernel this project boots is not a setting a boundary spells
        # twice.  An extension with neither is `null` -- Behat's own
        # spelling for "register it, no options".
        declared = dict(bp.extension_settings)
        extensions: dict = {}
        for name in bp.extensions:
            body: dict = dict(declared.get(name) or {})
            if name.rsplit("\\", 1)[-1] == "SymfonyExtension":
                if bp.bootstrap is not None:
                    body["bootstrap"] = bp.bootstrap
                body["kernel"] = {"path": bp.kernel_path,
                                  "class": bp.kernel_class,
                                  "environment": bp.app_env}
            extensions[name] = body or None
        body: dict = {
            "formatters": {"pretty": {"verbose": True, "paths": False,
                                      "snippets": False}},
        }
        if bp.tester_error_reporting is not None:
            # `calls` is the key BOTH Behats read the level under: it is
            # `CallExtension::getConfigKey()` in 3 and in 4, and it is where
            # `TesterOptions::withErrorReporting` puts it
            # (`CALLS_SETTINGS_GROUP`).  Written here as the project's
            # EXPRESSION, which is what the PHP rendering needs; the YAML
            # rendering below adds it up, because a YAML scalar cannot name
            # a PHP constant and Behat hands the value straight to
            # `error_reporting()`.
            body["calls"] = {"error_reporting": bp.tester_error_reporting}
        body["extensions"] = extensions
        body["suites"] = {"bench": {"paths": ["%paths.base%/" + FEATURE_REL],
                                    "contexts": all_contexts}}
        # ONE document, two spellings.  Behat 4 refuses a YAML `--config` by
        # file name, so a project that runs it says `bench_config_format:
        # php` and gets the same profile rendered through the vendored
        # `Behat\Config` API, under the name that loader accepts.
        if bp.bench_config_format == "php":
            text = _render_behat_php("bench", body)
        else:
            if bp.tester_error_reporting is not None:
                # The one key the YAML cannot spell the way the profile
                # declares it, so it carries the sum instead -- in place, so
                # the two documents are the same document in the same order.
                body = dict(body, calls={
                    "error_reporting": error_reporting_int(
                        bp.tester_error_reporting, self.boundary.project)})
            text = ("# GENERATED per item by r2t.bench.harness (SPEC §4).\n"
                    + yaml.safe_dump({"bench": body}, sort_keys=False,
                                     allow_unicode=True,
                                     default_flow_style=False))
        _write_if_changed(self._abs(bp.bench_config), text)
        return all_contexts

    # ---------------------------------------------------------- execution
    def _kill_behat(self, pid_file: str) -> str:
        """Kill exactly the Behat this call started, and say whether it died.

        The old cleanup was `pkill -f 'vendor/bin/behat'`, which is
        container-wide (defect 3): with more than one execution sharing a
        container it kills a healthy neighbour's run, and that neighbour is
        then scored on a truncated record file.  Container-per-worker makes
        that rarer rather than impossible — a trial and a scoring run share a
        worker — so the scope is the PID instead.

        `execute` writes the shell's own `$$` and then `exec`s Behat over it,
        so the recorded PID *is* Behat's.  Direct children go first (a step
        that shelled out), then the process itself, then the same pair with
        SIGKILL.  The result is returned rather than swallowed: a Behat that
        survives keeps appending to the record file the NEXT item reads, and
        an `except: pass` made that invisible.

        The shared script lives in `_kill_process_tree` because
        nothing in it is about Behat — see that function for the reasoning the
        shape of the script encodes.
        """
        return _kill_process_tree(self.runner, pid_file)

    def execute(self, coverage: bool = False, timeout: int = 600,
                expected_line: Optional[int] = None,
                expected_lines: Optional[list] = None) -> RunResult:
        if self.boundary.project != "prestashop":
            return self._execute(coverage, timeout, expected_line, expected_lines)
        from .prestashop_resources import (
            ResourceResetError, RetainedHookDatabaseFault, ensure_seeded_schema,
            post_execute, retained_hook_database_fault, snapshot_fixtures)
        self.verify_substrate()
        # Harness 26 (BENCHMARK_V2_SPEC section 8.1): no execution runs on a
        # schema that lacks a seeded table; the full dump restores it, or
        # `SeededSchemaFault` stops the worker.
        ensure_seeded_schema(self, "before this execution")
        # Read only now: the entry check has just proved these bytes pristine.
        self.fixture_snapshot = snapshot_fixtures(self.man.repo_root)
        self.fixture_consumed = None
        self._resource_process_stopped = True
        self._resource_stop_detail = None
        result = None
        try:
            result = self._execute(coverage, timeout, expected_line, expected_lines)
        finally:
            if not self._resource_process_stopped:
                raise ResourceResetError(
                    "Native process stop was not confirmed "
                    f"({self._resource_stop_detail}); resources were not reset")
            reset_started = time.monotonic()
            post_execute(self)
            if result is not None:
                result.resource_reset_seconds = time.monotonic() - reset_started
                result.fixture_consumed = self.fixture_consumed
            if result is None or result.timed_out:
                # The killed Behat may have stopped inside a native table
                # restore, between its DROP and its CREATE (2026-10-16).
                ensure_seeded_schema(self, "after a killed or timed-out execution")
        # Under an applied mutant the hook's database exception can be the
        # mutant's own (`CommonFeatureContext::prepare()` boots the shop
        # through classes/ and src/), so a mutation pair keeps harness 25's
        # reading: `no_scenario_ran`, retried once, then excluded. Both
        # schema checks above still run for it.
        fault = (None if self.expected_mutations
                 else retained_hook_database_fault(self, result.stdout))
        if fault is not None:
            # Nothing was measured. Repair what can be repaired before the
            # next execution, and make the row infrastructure.
            ensure_seeded_schema(self, "after a database exception in a "
                                       "retained BeforeSuite hook")
            raise RetainedHookDatabaseFault(fault)
        return result

    def _execute(self, coverage: bool = False, timeout: int = 600,
                 expected_line: Optional[int] = None,
                 expected_lines: Optional[list] = None) -> RunResult:
        record = self._abs(RECORD_REL)
        if os.path.exists(record):
            os.remove(record)
        # Derived from the runner's own workdir, never hard-coded: a worker
        # bind-mounted anywhere other than `/var/www/html` told the recorder
        # to write to a path that did not exist, and every item then scored
        # `no_scenario_ran` off an empty record file (defect 2, H2).
        record_in_container = self.runner.in_container(RECORD_REL)
        env = {"XDEBUG_MODE": "off", "BENCH_RECORD_PATH": record_in_container}
        if coverage:
            # `trace` beside `coverage`: the recorder's per-scenario function
            # trace (API_DIRECT_INVOCATION_SPEC §2.4) rides on the same mode
            # the coverage collector needs, so a trial execution, which runs
            # with coverage off, pays for neither.
            env = {"XDEBUG_MODE": "coverage,trace", "BEHAT_ALLOW_XDEBUG": "1",
                   "BENCH_COVERAGE": "1",
                   "BENCH_RECORD_PATH": record_in_container}
        # Outside the bind mount on purpose.  `_bench/` is a SUBSTRATE_ROOT,
        # so a pid file written there is reported as `added` by
        # `verify_substrate` and aborts the next item as tampering.
        pid_file = f"/tmp/r2t-behat-{os.getpid()}-{next(_EXEC_SEQ)}.pid"
        # The provisioned image's ini says `xdebug.start_with_request=yes`,
        # which under a mode that includes `trace` starts a request-scoped
        # trace of the WHOLE process at PHP start -- measured at 4.3 GB and
        # +590 s per item before the recorder's own stop could run.  The
        # per-invocation `-d` keeps the ini file untouched and leaves the
        # recorder's per-scenario trace the only one; a trial invocation
        # runs with xdebug off and its command line is unchanged.
        php = "php -d xdebug.start_with_request=no " if coverage else ""
        started = time.time()
        timed_out = False
        cleanup = None
        try:
            if self.boundary.project == "prestashop":
                self._resource_process_stopped = False
            cp = self.runner.run(
                f"printf '%s' $$ > {shlex.quote(pid_file)} && "
                f"exec {php}vendor/bin/behat "
                f"--config {self.behat.bench_config} -p bench "
                f"--no-interaction --no-colors --strict", env=env, timeout=timeout)
            self._resource_process_stopped = True
            code, out = cp.returncode, (cp.stdout or "") + (cp.stderr or "")
        except subprocess.TimeoutExpired as e:
            timed_out = True
            # `docker exec` without a TTY does not forward the kill into the
            # container: the local client dies, Behat keeps running, and it
            # keeps appending to the record file the NEXT item will read.
            cleanup = self._kill_behat(pid_file)
            self._resource_stop_detail = cleanup
            self._resource_process_stopped = cleanup == "killed"
            code = -1
            out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(
                e.stdout, bytes) else (e.stdout or "")
        except BaseException:
            if self.boundary.project == "prestashop":
                self._resource_stop_detail = self._kill_behat(pid_file)
                self._resource_process_stopped = self._resource_stop_detail == "killed"
            raise
        wall = time.time() - started
        if not timed_out:
            self.runner.run(f"rm -f {shlex.quote(pid_file)}", timeout=60)

        records = []
        if os.path.isfile(record):
            with open(record, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        return RunResult(exit_code=code, stdout=out, wall_seconds=wall,
                         records=records, timed_out=timed_out,
                         expected_line=expected_line, timeout_cleanup=cleanup,
                         expected_lines=expected_lines)

    # ------------------------------------------------------------- driver
    def run_solution(self, feature: Feature, scenario: Block,
                     solution: Solution, coverage: bool = False,
                     timeout: int = 600, repeats: int = 1,
                     task: str = "criterion_to_test",
                     keep_stdout: bool = False) -> dict:
        """Execute with a substrate postcondition even on exceptional exits.

        `_run_solution` records a normal post-execution violation in its
        result.  This wrapper closes the other path: install, configuration or
        execution can raise before that result is constructed.  In that case
        the original exception propagates when the substrate is pristine; a
        substrate violation instead becomes the fatal exception, with the
        original retained as its context.  Mutation coordinators can then
        quarantine the worker rather than continuing on changed source.
        """
        try:
            return self._run_solution(
                feature, scenario, solution, coverage=coverage,
                timeout=timeout, repeats=repeats, task=task,
                keep_stdout=keep_stdout)
        except BaseException:                               # noqa: BLE001
            # `verify_substrate` raises when the exceptional path also changed
            # retained source.  Otherwise it returns and the bare raise below
            # preserves the original exception and traceback.
            self.verify_substrate()
            raise

    def _run_solution(self, feature: Feature, scenario: Block,
                      solution: Solution, coverage: bool = False,
                      timeout: int = 600, repeats: int = 1,
                      task: str = "criterion_to_test",
                      keep_stdout: bool = False) -> dict:
        from .repo import clean_workspace
        if self.boundary.project == "prestashop":
            # Native Behat attaches tags across blank/comment lines. Recover
            # them before suite selection too, including for callers that
            # parsed with the shared contiguous-tag default.
            feature = parse_feature_file(feature.path, "\n".join(feature.lines),
                                         allow_tag_gaps=True)
            scenario = feature.scenario_at(scenario.line)
            if scenario is None:
                raise ValueError("selected scenario is absent from its source feature")
        # Integrity is checked at the EXECUTION boundary, not once per item.
        #
        # `prepare_for_generation` verified the substrate before the agent
        # generated, which is the wrong boundary for three reasons. A C3 trial
        # calls this method directly, so an item's five trials ran with no
        # check between them. Submitted PHP executes as root on a read-write
        # bind mount, so it can patch production or the recorder DURING a
        # trial and the authoritative final run then scores against a tree the
        # submission edited. And the next item's preflight is too late anyway
        # — it does not protect the last item of a sweep.
        #
        # Before: raise, because the tree was already wrong when we arrived and
        # nothing produced here would be attributable.
        self.verify_substrate()
        # The generated half of the same promise: whatever an earlier pair
        # regenerated from (possibly mutated) source is back to seed bytes
        # before this pair's first process autoloads it.
        self.restore_derived_state()
        clean_workspace(self.man, self.boundary)
        # The previous item's solution index still describes ITS classes;
        # left in place it is a small answer key for the next item.
        stale_index = self._abs(f"{BENCH_DIR}/solution_index.json")
        if os.path.exists(stale_index):
            os.remove(stale_index)
        written, rejected = self.install_solution(solution, task=task)
        index = self.index_paths([p for p in written if p.endswith(".php")])
        digest = hashlib.sha256(
            "".join(f"{f.file_path}\0{f.code}\0" for f in solution.files)
            .encode("utf-8")).hexdigest()[:16]
        # Selected before the registration is written, because the alias
        # that registration emits for a class with several definitions is
        # the suite's own (`write_registration`).  Nothing about the
        # selection depends on the solution: it is the item's tags and its
        # feature path.
        suite = None
        if self.behat.suite_scoped:
            suite = self.select_suite(list(feature.tags) + list(scenario.tags),
                                      feature_path=self.feature_rel(feature))
        # A candidate run and a gold run differ in two rules (harness 25,
        # `Solution.gold_run`); a gold run keeps harness 24's.
        candidate = not solution.gold_run
        reg = self.write_registration(index, solution.services_fragment,
                                      digest, suite=suite, candidate=candidate)
        relisted = (contexts_to_relist(self.suite_map()["suites"],
                                       reg["contexts"], suite,
                                       step_patterns(index))
                    if candidate and suite is not None else [])
        # A refused service definition is the same kind of finding as a
        # refused file, and reaches the record by the same route.
        rejected = rejected + reg["rejected_services"]
        produced_feature = None
        if task == "requirement_to_test":
            produced_feature = next(
                (f.code for f in solution.files
                 if f.file_path.endswith(".feature")), None)
        _text, expected_line, expected_lines = self.write_feature(
            feature, scenario, override=produced_feature)
        contexts = self.write_behat_config(reg["contexts"], suite=suite,
                                           registered=reg["services"],
                                           relisted=relisted)

        runs = [self.execute(coverage=coverage, timeout=timeout,
                             expected_line=expected_line,
                             expected_lines=expected_lines)
                for _ in range(max(1, repeats))]

        # After: reported, not raised. Raising here would discard the very
        # evidence of what the submission did, and the correct response is to
        # void this outcome and quarantine the worker — which the caller can
        # only do if it is told. `_record` turns a non-empty violation into
        # `substrate_violation`, so the row can never read as a pass.
        from .repo import verify_substrate as _verify
        after = _verify(self.man, self.boundary,
                        expected=self.expected_mutations)
        violation = None
        if after["baseline"] and (after["changed"] or after["missing"]
                                  or after["added"]):
            violation = {k: after[k][:8] for k in ("changed", "missing", "added")}
        # What harness 25 did differently from 24 for this solution, on the
        # projects where each rule can apply; empty in a gold run.
        corrections = {}
        if self.behat.suite_scoped:
            corrections["relisted_contexts"] = relisted
        if self.behat.services_entry is not None:
            corrections["autowired_services"] = reg["autowired"]
        return {
            **corrections,
            "substrate_violation": violation,
            "written_files": written,
            "rejected_files": rejected,
            "feature_from_solution": produced_feature is not None,
            "index_errors": index.get("errors") or {},
            "registered_classes": reg["classes"],
            "registered_contexts": reg["contexts"],
            "aliases_emitted": reg["aliases"],
            "suite_contexts": contexts,
            # WHICH arm suite this item ran under, for a suite-scoped
            # project. None everywhere else, and not part of `r2t.record/1`:
            # a row says which suite answered it, the recorder does not.
            "suite": suite,
            "runs": [r.to_json(keep_stdout=keep_stdout) for r in runs],
            "outcomes": [r.outcome for r in runs],
        }


def _process_cleanup_selftest(check) -> None:
    """Real owned subprocesses; no Docker or benchmark application."""
    import ctypes
    from pathlib import Path
    import shutil
    import signal
    import tempfile

    def state(pid):
        try:
            return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
        except FileNotFoundError:
            return None

    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    # Linux PR_{GET,SET}_CHILD_SUBREAPER; keep fixture orphans ours to reap.
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0 \
            or libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot isolate fixture descendants")
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            for name in ("cat", "rm", "sleep"):
                (tools / name).symlink_to(shutil.which(name))

            class LocalRunner:
                def run(self, inner, timeout=120):
                    return subprocess.run(
                        ["/bin/sh", "-c", inner], capture_output=True, text=True,
                        timeout=timeout, env={**os.environ, "PATH": str(tools)})

            fixture = root / "tree.py"
            fixture.write_text(
                "import os, signal, subprocess, sys, time\n"
                "from pathlib import Path\n"
                "depth = int(sys.argv[1]); root = Path(sys.argv[2])\n"
                "Path('/proc/self/comm').write_text('r2t ) child')\n"
                "if depth:\n"
                "    child = subprocess.Popen([sys.executable, __file__, str(depth-1), str(root)])\n"
                "    def stop(*args):\n"
                "        child.wait(timeout=10); raise SystemExit(0)\n"
                "    signal.signal(signal.SIGTERM, stop)\n"
                "(root / (str(depth)+'.pid')).write_text(str(os.getpid()))\n"
                "time.sleep(60)\n")
            peer = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            parent = subprocess.Popen(
                [sys.executable, str(fixture), "2", str(root)])
            owned = [parent.pid]
            try:
                deadline = time.monotonic() + 10
                while not all((root / f"{i}.pid").exists() for i in range(3)):
                    if time.monotonic() > deadline:
                        raise RuntimeError("fixture tree did not start")
                    time.sleep(0.01)
                owned = [int((root / f"{i}.pid").read_text()) for i in range(3)]
                pid_file = root / "owned root.pid"
                pid_file.write_text(str(parent.pid))
                verdict = _kill_process_tree(LocalRunner(), str(pid_file))
                parent.wait(timeout=10)
                check("without procps, cleanup stops the owned subtree and leaves a peer alive",
                      verdict == "killed"
                      and all(state(pid) in (None, "Z", "X") for pid in owned)
                      and peer.poll() is None, verdict)
            finally:
                for pid in owned:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                parent.wait(timeout=10)
                peer.kill()
                peer.wait(timeout=10)
                for pid in owned:
                    try:
                        os.waitpid(pid, 0)
                    except ChildProcessError:
                        pass

            zombie = os.fork()
            if zombie == 0:
                os._exit(0)
            try:
                deadline = time.monotonic() + 10
                while state(zombie) != "Z":
                    if time.monotonic() > deadline:
                        raise RuntimeError("fixture child did not become a zombie")
                    time.sleep(0.01)
                pid_file = root / "zombie.pid"
                pid_file.write_text(str(zombie))
                check("an unreaped zombie cannot keep writing and is confirmed stopped",
                      _kill_process_tree(LocalRunner(), str(pid_file)) == "killed")
            finally:
                os.waitpid(zombie, 0)

            class FailedRunner:
                def run(self, inner, timeout=120):
                    return subprocess.CompletedProcess([], 17, "killed\n", "exec failed")
            check("failed cleanup execution cannot claim success from its stdout",
                  _kill_process_tree(FailedRunner(), "/tmp/unused.pid")
                  == "cleanup_failed:exit_17")
    finally:
        libc.prctl(36, previous.value, 0, 0, 0)


def selftest() -> int:
    """The guards that stop a solution from scoring itself.

    Container-free: everything here is path classification, YAML vetting and
    record selection against a temporary tree.
    """
    import tempfile
    from ..core.boundary import load_boundary
    from .repo import BENCH_DIR as _BD, StripManifest

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    _process_cleanup_selftest(check)

    # -- an agent-authored `behat_services.yml` cannot take the shard down.
    #
    # `run_one` calls `Solution.from_json` outside its adapter guard, so every
    # one of these used to propagate out of the item loop and end the sweep.
    def frag(code: str) -> Solution:
        return Solution.from_json(
            {"files": [{"file_path": SERVICES_FRAGMENT_NAME, "code": code}],
             "metadata": {"model": "x"}})

    good = frag("services:\n  my.ctx:\n    class: X\\Y\n")
    check("a valid fragment still parses to its services mapping",
          good.services_fragment == {"my.ctx": {"class": "X\\Y"}}
          and "services_fragment_error" not in good.metadata,
          str(good.services_fragment))
    check("a document with no `services:` key is taken as the mapping itself",
          frag("my.ctx:\n  class: X\n").services_fragment
          == {"my.ctx": {"class": "X"}})
    broken = frag("services:\n  my.ctx:\n\t\tclass: X\n")
    check("malformed YAML yields no fragment instead of raising",
          broken.services_fragment == {}
          and "unparseable" in broken.metadata.get("services_fragment_error", ""),
          str(broken.metadata))
    listed = frag("- one\n- two\n")
    check("a YAML list is refused as a fragment, not handed to `.get`",
          listed.services_fragment == {}
          and "not a mapping" in listed.metadata.get("services_fragment_error",
                                                     ""),
          str(listed.metadata))
    scalar = frag("services: foo\n")
    check("`services: foo` yields no fragment rather than a string one",
          scalar.services_fragment == {}
          and "not a" in scalar.metadata.get("services_fragment_error", ""),
          str(scalar.metadata))
    check("an empty or `services:`-only file is no wiring, not an error",
          frag("").services_fragment == {}
          and "services_fragment_error" not in frag("").metadata
          and frag("services:\n").services_fragment == {}
          and "services_fragment_error" not in frag("services:\n").metadata)
    check("the reason reaches the metadata the row is built from",
          frag("services: foo\n").metadata.get("model") == "x")

    here = BENCHMARK_ROOT
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, _BD))
        with open(os.path.join(root, _BD, "retained_services.yml"), "w",
                  encoding="utf-8") as fh:
            yaml.safe_dump({"services": {
                "coreshop.behat.context.hook.doctrine_orm": {
                    "class": "CoreShop\\Behat\\Context\\Hook\\DoctrineORMContext"},
            }}, fh)
        b = load_boundary(os.path.join(here, "config", "boundary_coreshop.yml"),
                          repo_root=root)
        h = Harness(StripManifest(repo_root=root, gold_root=root), b,
                    DockerRunner("none", docker_group=False))

        # -- the DI fragment may not reach outside the solution's own code.
        def rejected(frag):
            return bool(h.vet_fragment(frag)[1])

        check("fragment cannot redefine the recorder that scores the run",
              rejected({RECORDER_CONTEXT: {"class": "X\\Y"}}))
        check("fragment cannot redefine a retained service id",
              rejected({"coreshop.behat.context.hook.doctrine_orm":
                        {"class": "CoreShop\\Behat\\Context\\Domain\\Mine"}}))
        check("fragment cannot claim a retained context class",
              rejected({"mine": {"class":
                                 "CoreShop\\Behat\\Context\\Hook\\PimcoreDaoContext"}}))
        check("fragment cannot point an id at production code",
              rejected({"mine": {"class":
                                 "CoreShop\\Component\\Order\\Model\\Order"}}))
        check("fragment cannot alias-take-over a retained id",
              rejected({"CoreShop\\Behat\\Context\\Hook\\PimcoreDaoContext":
                        "@mine"}))
        check("a solution's OWN context, wired to a retained service, is kept",
              not rejected({"my.ctx": {
                  "class": "CoreShop\\Behat\\Context\\Domain\\CartContext",
                  "arguments": ["@coreshop.behat.shared_storage"]}}),
              str(h.vet_fragment({"my.ctx": {
                  "class": "CoreShop\\Behat\\Context\\Domain\\CartContext",
                  "arguments": ["@coreshop.behat.shared_storage"]}})[1]))

        # -- a .feature is the scenario under measurement, not an answer.
        feat = Solution(files=[SourceFile(
            "src/CoreShop/Behat/Context/Domain/X.feature", "Feature: mine\n")])
        _w, rej = h.install_solution(feat, task="criterion_to_test")
        check("a .feature is refused for criterion_to_test",
              [r["why"] for r in rej] == ["feature_not_accepted_for_task"],
              str(rej))
        _w, rej = h.install_solution(feat, task="requirement_to_test")
        check("a .feature is accepted for requirement_to_test", not rej)

        # -- the lines an outline may claim come from the file we WRITE.
        #
        # `standalone_feature` re-headers the file and inlines the Background,
        # so every line moves; deriving the Examples rows from the repository
        # text would name lines that are not in the executed file.
        src = ("@domain\n"
               "Feature: Totals\n"
               "\n"
               "  Background:\n"
               "    Given a store\n"
               "\n"
               "  Scenario: Untemplated\n"
               "    Given nothing\n"
               "\n"
               "  Scenario Outline: Totals\n"
               "    When I add <n> products\n"
               "    Then the total is <total>\n"
               "\n"
               "    Examples:\n"
               "      | n | total |\n"
               "      | 1 | 2400  |\n"
               "      | 2 | 4800  |\n")
        parsed_src = parse_feature_file("mem.feature", src)
        text, kw_line, all_lines = h.write_feature(parsed_src,
                                                   parsed_src.scenarios[1])
        written = text.split("\n")
        check("the scalar still names the `Scenario Outline:` keyword line",
              written[kw_line - 1].strip().startswith("Scenario Outline:"),
              f"{kw_line}: {written[kw_line - 1] if kw_line else None!r}")
        check("every Examples data row of the written file is an expected line",
              all_lines[0] == kw_line
              and [written[i - 1].strip() for i in all_lines[1:]]
              == ["| 1 | 2400  |", "| 2 | 4800  |"],
              f"{all_lines} -> {[written[i - 1] for i in all_lines[1:]]}")
        check("the table HEADER is not an expected line",
              all(written[i - 1].strip() != "| n | total |" for i in all_lines))
        _t2, kw2, lines2 = h.write_feature(parsed_src, parsed_src.scenarios[0])
        check("a plain scenario's expected lines are the keyword line alone",
              lines2 == [kw2] and kw2 is not None, str(lines2))

    # ---------------------------------------------------- H1, H2, H7, §3.2
    # These are the four defects that made K-way impossible, checked without
    # a container by driving the harness with a runner that records what it
    # was asked to do instead of doing it.
    class _FakeRunner(DockerRunner):
        def __init__(self, workdir="/var/www/html", raise_timeout=False):
            super().__init__("fake", workdir=workdir, docker_group=False)
            self.calls: list[tuple] = []
            self.raise_timeout = raise_timeout

        def run(self, inner, env=None, timeout=900):
            _docker_exec_env_args(env)      # exercise the real secret guard
            self.calls.append((inner, dict(env or {})))
            if self.raise_timeout and "vendor/bin/behat" in inner:
                self.raise_timeout = False   # the cleanup call must go through
                raise subprocess.TimeoutExpired("behat", timeout, output="tail")
            return subprocess.CompletedProcess([], 0, "killed\n", "")

    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, _BD))
        b = load_boundary(os.path.join(here, "config", "boundary_coreshop.yml"),
                          repo_root=root)
        man = StripManifest(repo_root=root, gold_root=root)

        # H1 -- the classification root and the write root cannot disagree.
        other = load_boundary(os.path.join(here, "config",
                                           "boundary_coreshop.yml"),
                              repo_root=os.path.join(root, "elsewhere"))
        try:
            Harness(man, other, _FakeRunner())
            check("a harness whose boundary and manifest disagree is refused",
                  False, "constructed anyway")
        except ValueError:
            check("a harness whose boundary and manifest disagree is refused",
                  True)
        check("--repo pointing both at one workspace is accepted",
              Harness(man, b, _FakeRunner()).root == os.path.abspath(root))

        # H2 -- the recorder is told a path derived from the runner's workdir.
        r = _FakeRunner(workdir="/srv/worker3")
        h2 = Harness(man, b, r)
        h2.execute(coverage=False, timeout=5)
        behat = [c for c in r.calls if "vendor/bin/behat" in c[0]][0]
        check("BENCH_RECORD_PATH follows the worker's mount point",
              behat[1]["BENCH_RECORD_PATH"] == f"/srv/worker3/{RECORD_REL}",
              behat[1].get("BENCH_RECORD_PATH"))
        check("a worker mounted at the convention still gets the same path",
              _FakeRunner().in_container(RECORD_REL)
              == f"/var/www/html/{RECORD_REL}")
        check("coverage mode does not lose the derived record path",
              (lambda rr: (Harness(man, b, rr).execute(coverage=True, timeout=5),
                           [c for c in rr.calls if "vendor/bin/behat" in c[0]]
                           [0][1]["BENCH_RECORD_PATH"])[1])(
                  _FakeRunner(workdir="/srv/w9")) == f"/srv/w9/{RECORD_REL}")

        # The recorder's function trace rides on XDEBUG_MODE: it is on for a
        # coverage invocation and only there, so a trial execution pays for
        # neither the coverage collector nor the trace.
        rc = _FakeRunner()
        Harness(man, b, rc).execute(coverage=True, timeout=5)
        cov_env = [c for c in rc.calls if "vendor/bin/behat" in c[0]][0][1]
        check("a coverage invocation runs xdebug in coverage AND trace mode",
              cov_env.get("XDEBUG_MODE") == "coverage,trace"
              and cov_env.get("BENCH_COVERAGE") == "1", str(cov_env))
        cov_cmd = [c for c in rc.calls if "vendor/bin/behat" in c[0]][0][0]
        check("...and starts no request-scoped trace: the ini's "
              "start_with_request is overridden on that command line only",
              "exec php -d xdebug.start_with_request=no vendor/bin/behat" in cov_cmd
              and "exec vendor/bin/behat" in behat[0], cov_cmd[:160])
        check("an execution without coverage runs xdebug off, so no trace "
              "is started either",
              behat[1].get("XDEBUG_MODE") == "off"
              and "BENCH_COVERAGE" not in behat[1], str(behat[1]))

        # The `--config` and the file `write_behat_config` writes are one
        # fact: Behat 4 picks its loader from the file NAME, so a project
        # whose profile is PHP must also be INVOKED with that name.  A
        # mismatch is not a parse error later, it is "Configuration file
        # `bench.behat.yml` must be a PHP file" on every item.
        check("the `--config` names this project's own per-item profile",
              "--config bench.behat.yml -p bench" in behat[0], behat[0][:200])
        php_b = load_boundary(os.path.join(here, "config",
                                           "boundary_coreshop.yml"),
                              repo_root=root)
        php_b.raw = {"behat": {"bench_config_format": "php"}}
        rp = _FakeRunner()
        Harness(man, php_b, rp).execute(coverage=False, timeout=5)
        check("...and a Behat 4 project is invoked with the PHP one",
              "--config bench.behat.php -p bench"
              in [c for c in rp.calls if "vendor/bin/behat" in c[0]][0][0],
              [c for c in rp.calls if "vendor/bin/behat" in c[0]][0][0][:200])

        # H7 -- the timeout kill is scoped to the PID this call started.
        r = _FakeRunner(raise_timeout=True)
        res = Harness(man, b, r).execute(coverage=False, timeout=5)
        killer = r.calls[-1][0]
        check("behat is exec'd over a shell that recorded its own pid",
              "printf '%s' $$ >" in r.calls[0][0]
              and "exec vendor/bin/behat" in r.calls[0][0], r.calls[0][0][:120])
        check("the timeout kill names a pid, not every behat in the container",
              "pkill" not in killer and "pgrep" not in killer
              and "/proc/" in killer, killer[:160])
        check("the kill walks the whole subtree, not just direct children",
              "tree()" in killer and "pkill -P" not in killer, killer[:200])
        check("the subtree is collected BEFORE any signal, so reparenting "
              "cannot lose a child",
              killer.index("all=$(tree") < killer.index("kill -TERM"))
        check("the pid file lives outside the hashed substrate roots",
              "/tmp/r2t-behat-" in r.calls[0][0] and BENCH_DIR not in killer)
        check("whether the kill worked is recorded, not swallowed",
              res.timeout_cleanup == "killed" and res.timed_out,
              str(res.timeout_cleanup))
        check("a run that did not time out records no cleanup verdict",
              Harness(man, b, _FakeRunner()).execute(
                  coverage=False, timeout=5).timeout_cleanup is None)

        # -- the tree-killer is SHARED, not Behat's.  A second stack's harness
        #    calls it directly, so it has to work with nothing but a runner,
        #    and it has to be the same bytes the Behat path sends: two copies
        #    of this script are two chances to get the reparenting order
        #    wrong, which is the bug it was written to fix.
        shared = _FakeRunner()
        # The pid file the timed-out run above wrote, read back out of its own
        # command line, so the two scripts are comparable byte for byte.
        pid_path = r.calls[0][0].split(">", 1)[1].split("&&", 1)[0].strip()
        verdict = _kill_process_tree(shared, pid_path)
        check("the shared tree-killer runs from a runner alone and reports "
              "the verdict it read",
              verdict == "killed" and len(shared.calls) == 1, verdict)
        check("the Behat path sends EXACTLY the shared script -- one copy, "
              "not two that can drift",
              shared.calls[0][0] == killer, shared.calls[0][0][:120])

    # -- v1.1: the GENERATED half of the tree under measurement.  A pair run
    #    under a CoreExtension return-type mutant (or the reset probe's leg
    #    A) leaves CoreShopProduct.php other than the seed's; the NEXT pair's
    #    behat must start from the seed's bytes, while a class the scenario
    #    itself generated (`definition_Behat*.php`) stays for the purge.
    product_rel = "var/classes/DataObject/CoreShopProduct.php"
    behat_class_rel = "var/classes/definition_BehatBrickTestX.php"
    seed_class = (b"<?php\nclass CoreShopProduct {\npublic function "
                  b"getUnitDefinitions(): ?\\UnitDefinitions {}\n}\n")
    regenerated = seed_class.replace(b": ?\\UnitDefinitions", b"")

    class _SeeingRunner(_FakeRunner):
        """Records what the class file held when behat was started."""

        def __init__(self, workspace):
            super().__init__()
            self.workspace = workspace
            self.seen: list = []

        def run(self, inner, env=None, timeout=900):
            if "vendor/bin/behat" in inner:
                with open(os.path.join(self.workspace, product_rel),
                          "rb") as fh:
                    self.seen.append(fh.read())
            return super().run(inner, env, timeout)

    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, _BD))
        os.makedirs(os.path.join(root, os.path.dirname(product_rel)))
        b = load_boundary(os.path.join(here, "config", "boundary_coreshop.yml"),
                          repo_root=root)
        man = StripManifest(repo_root=root, gold_root=root)
        pair = parse_feature_file(
            "mem.feature", "Feature: F\n\n  Scenario: S\n    Given a\n")

        def previous_pair_left(data):
            with open(os.path.join(root, product_rel), "wb") as fh:
                fh.write(data)
            with open(os.path.join(root, behat_class_rel), "wb") as fh:
                fh.write(b"<?php // generated by the scenario\n")

        previous_pair_left(regenerated)
        restoring = _SeeingRunner(root)
        Harness(man, b, restoring,
                derived_baseline={product_rel: seed_class}).run_solution(
            pair, pair.scenarios[0], Solution(files=[]), timeout=5)
        check("the next pair's behat starts from the SEED's class bytes, not "
              "the class the previous pair regenerated",
              restoring.seen == [seed_class], str(restoring.seen))
        check("...and a class the scenario generated itself is left for the "
              "Behat% purge",
              os.path.isfile(os.path.join(root, behat_class_rel)))

        previous_pair_left(seed_class + b"\n// r2t-reset-probe-class 0f1e\n")
        unrestored = _SeeingRunner(root)
        Harness(man, b, unrestored).run_solution(
            pair, pair.scenarios[0], Solution(files=[]), timeout=5)
        check("COUNTER: a harness with no derived baseline (every harness "
              "before v1.1) starts behat from whatever the previous pair "
              "left -- the defect, and what the reset probe's production-"
              "class marker sees",
              unrestored.seen == [seed_class
                                  + b"\n// r2t-reset-probe-class 0f1e\n"],
              str(unrestored.seen))

    # §3.2 -- a credential must never become a host process argument.
    def refuses(key):
        try:
            _docker_exec_env_args({key: "s3cret"})
            return False
        except SecretInArgv:
            return True

    check("the DSN cannot be passed as `docker exec -e`",
          refuses("PIMCORE_TEST_DB_DSN"))
    check("a password cannot be passed as `docker exec -e`",
          refuses("MYSQL_PASSWORD") and refuses("PIMCORE_INSTALL_MYSQL_PASSWORD"))
    check("an api key cannot be passed as `docker exec -e`",
          refuses("R2T_LLM_API_KEY"))
    check("the harness's own non-secret env is still allowed",
          not refuses("XDEBUG_MODE") and not refuses("BENCH_RECORD_PATH")
          and not refuses("BENCH_COVERAGE"))

    class _DockerCommandProbe(DockerRunner):
        def __init__(self):
            super().__init__("worker", docker_group=False)
            self._isolated_image = "sha256:" + "a" * 64
            self.argv = None

        def _docker(self, argv, *, timeout):
            self.argv = list(argv)
            return subprocess.CompletedProcess([], 0, "", "")

    with tempfile.TemporaryDirectory() as isolated:
        workspace = os.path.join(isolated, "workspace")
        analysis = os.path.join(isolated, "analysis")
        classes = os.path.join(isolated, "classes")
        for path in (workspace, analysis, classes):
            os.mkdir(path)
        probe = _DockerCommandProbe()
        probe.run_isolated_java(
            "java Mutate", workspace_host=workspace,
            analysis_host=analysis, classes_host=classes,
            analysis_runtime="/opt/r2t-analysis",
            classes_runtime="/opt/r2t-engine")
        mounts = [probe.argv[i + 1] for i, value in enumerate(probe.argv[:-1])
                  if value == "--mount"]
        check("Java analysis runs in a short-lived networkless read-only-root "
              "container",
              probe.argv[:2] == ["run", "--rm"]
              and "--name" in probe.argv
              and "--network" in probe.argv
              and probe.argv[probe.argv.index("--network") + 1] == "none"
              and "--read-only" in probe.argv)
        check("the submitted workspace is the only writable Java sidecar "
              "mount",
              any(f"src={workspace},dst=/var/www/html" in mount
                  and "readonly" not in mount for mount in mounts)
              and all("readonly" in mount for mount in mounts
                      if f"src={analysis}" in mount
                      or f"src={classes}" in mount), str(mounts))
        from ..toolkit.mutation_java import AMBIENT_JAVA_ENV_KEYS
        sidecar_env = [probe.argv[i + 1]
                       for i, value in enumerate(probe.argv[:-1])
                       if value == "--env"]
        check("Java sidecars erase launcher options inherited from image "
              "metadata",
              sidecar_env == [key + "=" for key in AMBIENT_JAVA_ENV_KEYS]
              and ("unset " + " ".join(AMBIENT_JAVA_ENV_KEYS) + ";")
              in probe.argv[-1],
              str(sidecar_env) + " / " + probe.argv[-1][:180])

        class _DockerTimeoutProbe(DockerRunner):
            def __init__(self):
                super().__init__("worker", docker_group=False)
                self._isolated_image = "sha256:" + "b" * 64
                self.calls = []

            def _docker(self, argv, *, timeout):
                self.calls.append(list(argv))
                if argv[0] == "run":
                    raise subprocess.TimeoutExpired(["docker", *argv], timeout)
                return subprocess.CompletedProcess([], 0, "", "")

        timeout_probe = _DockerTimeoutProbe()
        try:
            timeout_probe.run_isolated_java(
                "java Mutate", workspace_host=workspace,
                analysis_host=analysis, classes_host=classes,
                analysis_runtime="/opt/r2t-analysis",
                classes_runtime="/opt/r2t-engine", timeout=1)
        except subprocess.TimeoutExpired:
            pass
        else:
            check("a timed-out Java sidecar propagates timeout", False)
        sidecar_name = (timeout_probe.calls[0][
            timeout_probe.calls[0].index("--name") + 1]
            if timeout_probe.calls and "--name" in timeout_probe.calls[0]
            else "")
        check("a timed-out Java sidecar is force-removed and its absence is "
              "checked before timeout propagates",
              bool(sidecar_name)
              and timeout_probe.calls[1] == ["rm", "-f", sidecar_name]
              and timeout_probe.calls[2]
              == ["ps", "-aq", "--no-trunc", "--filter",
                  "name=^/" + sidecar_name + "$"],
              repr(timeout_probe.calls))

        # -- the long-lived audit session: one container for a whole mutant
        #    walk, one cheap exec per mutant.  It is only a TRANSPORT change
        #    if its container is the sidecar's container and its per-mutant
        #    shell is the sidecar's shell, so both are compared literally
        #    against the shape `run_isolated_java` would have sent.
        from ..toolkit.mutation_java import java_sidecar_shell_prefix

        class _SessionProbe(DockerRunner):
            def __init__(self, exec_timeout=False):
                super().__init__("worker", docker_group=False)
                self._isolated_image = "sha256:" + "c" * 64
                self.calls = []
                self.exec_timeout = exec_timeout

            def _docker(self, argv, *, timeout):
                self.calls.append(list(argv))
                if self.exec_timeout and argv[0] == "exec":
                    raise subprocess.TimeoutExpired(["docker", *argv], timeout)
                return subprocess.CompletedProcess([], 0, "", "")

        mounts_kwargs = dict(
            workspace_host=workspace, analysis_host=analysis,
            classes_host=classes, analysis_runtime="/opt/r2t-analysis",
            classes_runtime="/opt/r2t-engine")
        session_probe = _SessionProbe()
        sidecar_argv = session_probe._isolated_java_argv(
            "java Mutate", detach=False, **mounts_kwargs)
        session = session_probe.open_isolated_java_session(**mounts_kwargs)
        session.run("java Mutate")
        session.run("java Mutate")
        exec_argv = list(session_probe.calls[-1])
        session.close()
        start_argv = session_probe.calls[0]
        session_name = start_argv[4] if len(start_argv) > 4 else ""
        check("the audit session detaches ONE container whose image, mounts, "
              "network, pids, privilege, root filesystem and erased launcher "
              "environment are the per-mutant sidecar's, flag for flag",
              start_argv[:4] == ["run", "--rm", "-d", "--name"]
              and re.fullmatch(r"r2t-java-session-[0-9a-f]{32}", session_name)
              and start_argv[5:-1] == sidecar_argv[2:-1]
              and start_argv[-1] == java_sidecar_shell_prefix(
                  session_probe.workdir) + _ISOLATED_JAVA_SESSION_IDLE,
              repr(start_argv))
        check("each mutant costs one `docker exec` carrying the EXACT guarded "
              "command bytes the per-mutant sidecar would have run",
              [call[0] for call in session_probe.calls]
              == ["run", "exec", "exec", "rm", "ps"]
              and exec_argv[0] == "exec"
              and exec_argv[1:-6] == list(
                  session_probe._isolated_java_env())
              and exec_argv[-6:-3] == ["--workdir", session_probe.workdir,
                                       session_name]
              and exec_argv[-3:-1] == ["/bin/sh", "-lc"]
              and exec_argv[-1] == sidecar_argv[-1]
              and session.execs == 2,
              repr(exec_argv))
        check("closing the audit session force-removes its container and "
              "proves the name absent",
              session_probe.calls[-2] == ["rm", "-f", session_name]
              and session_probe.calls[-1]
              == ["ps", "-aq", "--no-trunc", "--filter",
                  "name=^/" + session_name + "$"]
              and not session.opened,
              repr(session_probe.calls[-2:]))

        exec_timeout_probe = _SessionProbe(exec_timeout=True)
        timed_out_session = exec_timeout_probe.open_isolated_java_session(
            **mounts_kwargs)
        timed_out_name = exec_timeout_probe.calls[0][4]
        try:
            timed_out_session.run("java Mutate", timeout=1)
        except subprocess.TimeoutExpired:
            pass
        else:
            check("a timed-out session exec propagates timeout", False)
        check("a timed-out session exec force-removes the container, proves "
              "its absence, and closes the session against further execs",
              [call[0] for call in exec_timeout_probe.calls]
              == ["run", "exec", "rm", "ps"]
              and exec_timeout_probe.calls[2] == ["rm", "-f", timed_out_name]
              and exec_timeout_probe.calls[3]
              == ["ps", "-aq", "--no-trunc", "--filter",
                  "name=^/" + timed_out_name + "$"]
              and not timed_out_session.opened,
              repr(exec_timeout_probe.calls))
        closed_refused = False
        try:
            timed_out_session.run("java Mutate")
        except RuntimeError as exc:
            closed_refused = "session is closed" in str(exc)
        check("a closed session admits no further exec", closed_refused)

    # The real Symfony layout has a kernel wrapper plus dumped service
    # directories. Exercise the deletion command on disk without Docker.
    from dataclasses import replace

    class _CacheRunner:
        def __init__(self, root):
            self.root = root

        def run(self, inner, *, timeout):
            return subprocess.run(["sh", "-c", inner], cwd=self.root,
                                  capture_output=True, text=True,
                                  timeout=timeout)

    for cache_dir, prefix in (("var/cache/test", "BehatKernel"),
                              ("var/cache/test_cached", "App_KernelTest_cached")):
        with tempfile.TemporaryDirectory() as root:
            boundary = load_boundary(os.path.join(
                here, "config", "boundary_coreshop.yml"), repo_root=root)
            cache_harness = Harness(
                StripManifest(repo_root=root, gold_root=root), boundary,
                _CacheRunner(root))
            cache_harness.behat = replace(cache_harness.behat,
                cache_dir=cache_dir, container_prefix=prefix)
            cache = os.path.join(root, cache_dir)
            os.makedirs(os.path.join(cache, "pools"))
            pool_file = os.path.join(cache, "pools", "application-cache")
            other_cache = os.path.join(root, "var/cache/prod/ContainerKeep")
            os.makedirs(other_cache)
            with open(pool_file, "w", encoding="utf-8") as fh:
                fh.write("unrelated application cache")
            for generation in range(3):
                dumped = os.path.join(cache, f"ContainerFixture{generation}")
                os.mkdir(dumped)
                with open(os.path.join(dumped, "getService.php"), "w",
                          encoding="utf-8") as fh:
                    fh.write("<?php /* compiled service */")
                with open(os.path.join(cache, prefix + ".php"), "w",
                          encoding="utf-8") as fh:
                    fh.write("<?php /* kernel wrapper */")
                cache_harness.invalidate_container()
            check(f"{cache_dir}: repeated invalidation removes kernel and "
                  "dumped service files and keeps the cache pools, which "
                  "clear_cache_pools owns",
                  os.listdir(cache) == ["pools"]
                  and os.path.isfile(pool_file) and os.path.isdir(other_cache))

            # Harness 27: the pools are emptied before a mutation pair on a
            # non-debug kernel (Sylius) and kept on a debug kernel.
            cache_harness.clear_cache_pools()
            kept_on_debug = os.path.isfile(pool_file)
            cache_harness.boundary = replace(boundary, project="sylius")
            cache_harness.clear_cache_pools()
            check(f"{cache_dir}: clear_cache_pools keeps a debug-kernel "
                  "project's pools and empties Sylius's, and only those",
                  kept_on_debug and os.listdir(cache) == []
                  and os.path.isdir(other_cache))

            # A surviving dump must refuse even after its wrapper is gone.
            os.mkdir(os.path.join(cache, "Container0AEUyTK"))
            os.makedirs(os.path.join(cache, "pools", "system"))
            cache_harness.runner.run = lambda *_args, **_kwargs: (
                subprocess.CompletedProcess([], 0, "", ""))
            survived = False
            try:
                cache_harness.invalidate_container()
            except RuntimeError as exc:
                survived = "Container0AEUyTK" in str(exc)
            check(f"{cache_dir}: a leftover service dump fails invalidation",
                  survived)
            pools_survived = False
            try:
                cache_harness.clear_cache_pools()
            except RuntimeError as exc:
                pools_survived = "cache pools" in str(exc)
            check(f"{cache_dir}: pools that survive deletion fail "
                  "clear_cache_pools", pools_survived)

    # -- the per-step record is chosen by identity, not by position, and a
    #    Scenario Outline's per-row records are FOLDED rather than dropped.
    from .runner import _scenario_record
    forged = {"scenario_line": 99, "steps": [{"result": "passed"}]}
    real = {"scenario_line": 22, "steps": [{"result": "failed"}]}
    check("a forged leading record does not become the run's record",
          _scenario_record({"records": [forged, real], "expected_line": 22})
          is real)
    check("a forged record is excluded wherever it sits, not just first",
          _scenario_record({"records": [real, forged], "expected_line": 22})
          is real
          and fold_scenario_records([real, forged, dict(forged)], [22])
          == ([real], real))
    check("no identity means no silent first-record fallback",
          _scenario_record({"records": [forged, real],
                            "expected_line": None}) is real)
    check("one matching record folds to itself",
          fold_scenario_records([forged, real], [22]) == ([real], real))

    def row(line, *results, **kw):
        return dict({"scenario_line": line,
                     "steps": [{"result": r} for r in results]}, **kw)

    def outlined(*rows, exit_code=0, lines=(10, 14, 15, 16)):
        return RunResult(exit_code=exit_code, stdout="", wall_seconds=0.1,
                         records=list(rows), expected_line=lines[0],
                         expected_lines=list(lines))

    green = [row(14, "passed", "passed"), row(15, "passed", "passed"),
             row(16, "passed", "passed")]
    check("an outline whose every Examples row passed is a pass",
          outlined(*green).outcome == "passed", outlined(*green).outcome)
    check("the same rows with a non-zero exit code are not a pass",
          outlined(*green, exit_code=1).outcome == "passed_but_nonzero_exit")
    one_red = [row(14, "passed", "passed"), row(15, "passed", "failed"),
               row(16, "passed", "passed")]
    res = outlined(*one_red)
    check("one failing Examples row fails the whole outline",
          res.outcome == "failed", res.outcome)
    check("the failing row is what the per-step detail describes",
          res.scenario is one_red[1], str(res.scenario))
    mixed = outlined(row(14, "passed", "failed"), row(15, "undefined"))
    check("an undefined row outranks another row's failure",
          mixed.outcome == "undefined_steps", mixed.outcome)
    check("an Examples row that ran no steps is reported, not scored",
          outlined(row(14, "passed"), row(15)).outcome == "no_steps_ran")
    check("a keyword-line record still counts as the outline's own",
          outlined(row(10, "passed", "passed")).outcome == "passed")
    check("records on none of the expected lines are still no scenario",
          outlined(row(77, "passed")).outcome == "no_scenario_ran"
          and outlined(row(77, "passed")).scenario is None)

    call_a = {"callee_file": "src/product.py", "callee_line": 10,
              "callee": "Product.a", "caller_file": "features/steps/use.py",
              "accessor_binding": None}
    call_b = dict(call_a, callee_line=20, callee="Product.b")
    api_rows = [row(14, "passed", direct_calls=[call_a]),
                row(15, "failed", direct_calls=[call_b]),
                row(16, "passed", direct_calls=[])]
    api_run = outlined(*api_rows)
    check("an outline unions disjoint calls while retaining its failing "
          "per-step representative and outcome",
          api_run.direct_calls == [call_a, call_b]
          and api_run.scenario is api_rows[1] and api_run.outcome == "failed"
          and api_run.records == api_rows)
    check("record and event permutations and duplicate observations do "
          "not change the outline API union",
          outlined(api_rows[2], dict(api_rows[1], direct_calls=[call_b, call_b]),
                   api_rows[0], api_rows[0]).direct_calls == api_run.direct_calls)
    check("unrelated and keyword-line observations do not enter or "
          "invalidate required Examples evidence",
          outlined(row(10, "passed", direct_calls=None), *api_rows,
                   row(99, "passed", direct_calls=None)).direct_calls
          == api_run.direct_calls)
    missing = outlined(api_rows[0], api_rows[0], api_rows[2])
    check("a missing required row cannot be replaced by a duplicate record "
          "and only withholds API evidence",
          missing.direct_calls is None and missing.outcome == "passed")
    check("absent and null required recordings withhold the whole API set",
          outlined(api_rows[0], row(15, "passed"), api_rows[2]).direct_calls is None
          and outlined(api_rows[0], row(15, "passed", direct_calls=None),
                       api_rows[2]).direct_calls is None)
    check("complete empty recordings are measured empty, including an "
          "outline with one Examples row",
          outlined(*(row(line, "passed", direct_calls=[])
                     for line in (14, 15, 16))).direct_calls == []
          and outlined(row(14, "passed", direct_calls=[]),
                       lines=(10, 14)).direct_calls == [])
    single = row(22, "passed", direct_calls=[call_b, call_a])
    check("a single scenario retains its original event list and the "
          "existing identity-free fallback stays on one record",
          fold_direct_calls([single], 22) is single["direct_calls"]
          and fold_direct_calls([api_rows[0], single], None)
          is single["direct_calls"])
    # The step a call was made from is part of the event's identity
    # (TARGET_INTERFACES_V2_SPEC section 4), so one call made from two steps
    # of an outline's rows is two events here; `metrics.direct_methods`
    # collapses them to the same pair again.
    at_0, at_1 = dict(call_a, step=0), dict(call_a, step=1)
    stepped = outlined(row(14, "passed", direct_calls=[at_0]),
                       row(15, "passed", direct_calls=[at_1, at_0]),
                       row(16, "passed", direct_calls=[])).direct_calls
    check("the same call from two steps survives the union as two events",
          stepped == [at_0, at_1], str(stepped))

    binding = {"declaring_file": "src/model.py", "declaring_line": 30,
               "owner": "model.Model", "attribute": "child",
               "access_kind": "get"}
    bound = dict(call_a, callee="Factory._getter.<locals>.get_child",
                 accessor_binding=binding)
    variants = [bound] + [dict(bound, accessor_binding=dict(binding, **{key: value}))
                         for key, value in (
                             ("declaring_file", "src/other.py"),
                             ("declaring_line", 31), ("owner", "model.Other"),
                             ("attribute", "other"), ("access_kind", "set"))]
    old_event = {key: value for key, value in call_a.items()
                 if key != "accessor_binding"}
    binding_union = outlined(
        row(14, "passed", direct_calls=variants + [call_a]),
        row(15, "passed", direct_calls=variants + [old_event]),
        row(16, "passed", direct_calls=[])).direct_calls
    check("deduplication retains every accessor identity field and "
          "distinguishes old absent binding from explicit null",
          len(binding_union) == len(variants) + 2
          and all(event in binding_union for event in variants + [call_a, old_event]))
    schema = "r2t.python_direct_calls/2"
    marked = [dict(record, direct_calls_schema=schema) for record in api_rows]
    check("Python collector identity is carried only from all required records",
          outlined(*marked).direct_calls_schema == schema
          and outlined(marked[0], api_rows[1], marked[2]).direct_calls_schema is None
          and outlined(marked[0], marked[2]).direct_calls_schema is None
          and outlined(marked[0], dict(marked[1], direct_calls_schema="unknown"),
                       marked[2]).direct_calls_schema is None)
    unresolved = outlined(marked[0], dict(marked[1], direct_calls=None), marked[2])
    check("an identified but unresolved collector remains API-unscored",
          unresolved.direct_calls_schema == schema and unresolved.direct_calls is None)
    check("an old empty recording cannot acquire the new collector identity",
          outlined(*(row(line, "passed", direct_calls=[])
                     for line in (14, 15, 16))).direct_calls_schema is None)
    stepped = [dict(record, direct_calls_schema="r2t.python_direct_calls/3",
                    direct_calls=[dict(event, step=index) for event in record["direct_calls"]])
               for index, record in enumerate(api_rows)]
    check("the per-step markers fold like their predecessors and the step "
          "is part of the event identity",
          outlined(*stepped).direct_calls_schema == "r2t.python_direct_calls/3"
          and outlined(*[dict(r, direct_calls_schema="r2t.ruby_direct_calls/2")
                         for r in stepped]).direct_calls_schema == "r2t.ruby_direct_calls/2"
          and outlined(*[dict(r, direct_calls_schema="r2t.php_direct_calls/1")
                         for r in stepped]).direct_calls_schema == "r2t.php_direct_calls/1"
          and len(outlined(*stepped).direct_calls)
          == len({json.dumps(e, sort_keys=True) for r in stepped for e in r["direct_calls"]}))

    # -- `error_markers`: which stdout strings mean "the environment failed",
    #    as a per-run INPUT rather than a constant only Symfony can satisfy.
    #    Default None is the property that matters most: every row already on
    #    disk and every caller that never heard of the field must classify
    #    exactly as before.
    def stdout_run(text, **kw):
        return RunResult(exit_code=1, stdout=text, wall_seconds=0.1,
                         records=[], expected_line=7, **kw)

    di = "Cannot autowire service \"App\\Foo\""
    check("the default markers are Symfony's, unchanged, when nothing is set",
          stdout_run(di).error_markers is None
          and stdout_run(di).outcome == "container_error")
    check("a run with its own markers classifies on THOSE",
          stdout_run("ModuleNotFoundError: no module named steps",
                     error_markers=("ModuleNotFoundError",)).outcome
          == "container_error")
    check("...and stops recognising the markers it was not given -- a stack "
          "does not inherit another framework's error vocabulary",
          stdout_run(di, error_markers=("ModuleNotFoundError",)).outcome
          == "no_scenario_ran")
    check("an explicit empty marker set disables text-based classification",
          stdout_run(di, error_markers=()).outcome == "no_scenario_ran")
    # The CoreShop checked-interfaces-v2 aider cells recorded 37 rows whose
    # container failed Symfony's named-argument pass; with the markers above
    # missing they fell through to `no_scenario_ran` (execution rung) instead
    # of `container_error` (compilation rung).  Stdout as those rows recorded it.
    named_arg = ('\nIn ResolveNamedArgumentsPass.php line 87:\n\n'
                 '  Invalid service "CoreShop\\Behat\\Context\\Domain\\'
                 'PaymentProviderRuleContext": method "__construct()" has no '
                 'argument named "$sharedStorage". Check your service definition.\n')
    check("a named-argument container failure is a container_error",
          stdout_run(named_arg).outcome == "container_error")
    check("the markers are an input, never a field of the row: `to_json` "
          "writes the same keys it always did",
          "error_markers" not in stdout_run(di, error_markers=("X",)).to_json())

    # A run row serialised BEFORE `expected_lines` existed carries only the
    # scalar.  It must fold exactly as it always did -- this is the property
    # that lets every archived run re-score bit-identically.
    old_row = {"records": [forged, real], "expected_line": 22}
    check("an old row without `expected_lines` folds on the scalar alone",
          _scenario_record(old_row) is real
          and fold_lines(22, None) == [22] and fold_lines(None, None) is None
          and fold_lines(22, [22, 30]) == [22, 30])

    # The derivation of `expected_lines` from the file we actually write,
    # against a hand-written outline whose row numbers are counted by hand.
    outline_text = ("Feature: F\n"                       # 1
                    "\n"                                 # 2
                    "  Background:\n"                    # 3
                    "    Given a store\n"                # 4
                    "\n"                                 # 5
                    "  Scenario Outline: Totals\n"       # 6
                    "    When I add <n> products\n"      # 7
                    "    Then the total is <total>\n"    # 8
                    "\n"                                 # 9
                    "    Examples:\n"                    # 10
                    "      | n | total |\n"              # 11
                    "      | 1 | 2400  |\n"              # 12
                    "      | 2 | 4800  |\n")             # 13
    check("the Examples DATA rows are the expected lines, not the header",
          Harness._example_row_lines(outline_text, 6) == [12, 13],
          str(Harness._example_row_lines(outline_text, 6)))
    check("a plain scenario contributes no example rows",
          Harness._example_row_lines(
              "Feature: F\n\n  Scenario: S\n    Given a\n", 3) == [])
    check("text we cannot locate the scenario in yields no extra lines",
          Harness._example_row_lines(outline_text, 99) == [])

    # -- the synthesised Behat profile, for CoreShop and for a project that
    #    answers the same questions differently.
    #
    # The CoreShop rendering is pinned as BYTES because the row is not
    # allowed to change it: a boundary with no `behat:` block resolves to
    # today's constants, and this is what those constants render.
    with tempfile.TemporaryDirectory() as root:
        b = load_boundary(os.path.join(here, "config", "boundary_coreshop.yml"),
                          repo_root=root)
        h = Harness(StripManifest(repo_root=root, gold_root=root), b,
                    DockerRunner("none", docker_group=False))
        h.write_behat_config(["CoreShop\\Behat\\Context\\Domain\\CartContext"])
        rendered = open(os.path.join(root, BENCH_CONFIG), encoding="utf-8").read()
        check("[coreshop] the row does not move a byte of the synthesised "
              "profile: one SymfonyExtension, bootstrap before kernel, "
              "`test`, and the recorder last",
              rendered == CORESHOP_BENCH_CONFIG, repr(rendered[-400:]))
        check("[coreshop] ...nor the name it is written under, nor the "
              "`--config` Behat is given",
              h.behat.bench_config == BENCH_CONFIG == "bench.behat.yml",
              h.behat.bench_config)
        check("[coreshop] ...and the recorder context is the module constant",
              h.recorder_context == RECORDER_CONTEXT)
        check("[coreshop] a boundary with no `behat:` block IS the defaults",
              h.behat is CORESHOP_BEHAT)
        check("[coreshop] ...which says nothing about error reporting, so "
              "Behat keeps the level it has and the profile keeps its bytes",
              "error_reporting" not in rendered and "calls" not in rendered)
        # The YAML half of `tester_error_reporting`, which no shipped project
        # sets today: `calls.error_reporting` is where BOTH Behats read the
        # level (`CallExtension::getConfigKey`), and Behat hands the value
        # straight to `error_reporting()` -- so the YAML spelling is the mask
        # itself, because a YAML scalar cannot name a PHP constant.
        h.behat = replace(h.behat, tester_error_reporting=(
            "E_ALL & ~(E_DEPRECATED | E_USER_DEPRECATED)"))
        h.write_behat_config(["CoreShop\\Behat\\Context\\Domain\\CartContext"])
        with_row = open(os.path.join(root, BENCH_CONFIG),
                        encoding="utf-8").read()
        check("[coreshop] a YAML project that DOES set the row gets the mask "
              "the expression adds up to, under the key Behat 3 reads it "
              "from, and nothing else moves",
              "\n  calls:\n    error_reporting: 8191\n" in with_row
              and with_row.replace(
                  "  calls:\n    error_reporting: 8191\n", "")
              == CORESHOP_BENCH_CONFIG, repr(with_row[:400]))

    # -- registration: "takes no arguments" is not "can be a service".
    #
    # Sylius's removable tree holds two constants-holders --
    # `Behat\Context\Api\Resources` and `Subresources`, each
    # `final class R { public const ...; private function __construct() {} }`
    # -- that most Api contexts reference (`Resources::ADMINISTRATORS`), so
    # they sit in most closures.  Registered as autowired services they fail
    # Symfony's WHOLE container (`DefinitionErrorExceptionPass`: "its
    # constructor must be public"), and the item is charged
    # `container_error`/`di_unresolvable` -- which is a harness bug charged
    # to the system under test.  It took 2 of the 3 items of track S's first
    # admitted-item run on a real Sylius pool.
    #
    # The visibility is read off the `methods[]` entry the index ALREADY
    # carries for every method (`analyze_php.php`: `'public' =>
    # $st->isPublic()`), which is why nothing in the analyzer changes: the
    # copy installed in a workspace is under the substrate baseline and is
    # never refreshed, so a new key would reach no index that exists.
    #
    # The CoreShop-shaped rendering is pinned as BYTES alongside, because
    # this fix may not move it -- and it is written the way an index from an
    # analyzer older than `methods` is written (CoreShop's scoring seed v1
    # still installs one), with no `methods` at all, which is the reading
    # this rule degrades to.  The same index with its methods recorded, as
    # the current analyzer writes it, renders the same bytes.
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, _BD))
        b = load_boundary(os.path.join(here, "config", "boundary_coreshop.yml"),
                          repo_root=root)
        ns = "CoreShop\\Behat\\Context\\Domain\\"
        wired = ("CoreShop\\Component\\Order\\Repository"
                 "\\CartRepositoryInterface")

        def method_entry(name, public=True):
            """One `methods[]` entry, in the shape `analyze_php.php` writes.

            `public` is `isPublic()`, so a private and a protected
            constructor are the SAME recorded fact -- and the same answer:
            neither can be called from a container.
            """
            return {"name": name, "start": 10, "end": 12, "public": public,
                    "static": False, "abstract": False, "params": [],
                    "return_types": [], "this_props": [], "body_refs": [],
                    "this_calls": []}

        coreshop_shaped = {"files": {
            "CartContext.php": {"classes": [{
                "name": ns + "CartContext", "kind": "class", "is_context": True,
                "constructor": [{"name": "cartRepository", "types": [wired],
                                 "has_default": False, "variadic": False}]}]},
            "Money.php": {"classes": [{
                "name": ns + "Money", "kind": "class", "is_context": False,
                "constructor": []}]}}}
        recorded = json.loads(json.dumps(coreshop_shaped))
        for rel, mnames in (("CartContext.php", ["__construct", "addProduct"]),
                            ("Money.php", ["__construct", "asDecimal"])):
            recorded["files"][rel]["classes"][0]["methods"] = [
                method_entry(m) for m in mnames]
        holders = json.loads(json.dumps(recorded))
        holders["files"]["Resources.php"] = {"classes": [{
            "name": ns + "Resources", "kind": "class", "is_context": False,
            "constructor": [],
            "methods": [method_entry("__construct", public=False)]}]}
        holders["files"]["Subresources.php"] = {"classes": [{
            "name": ns + "Subresources", "kind": "class", "is_context": False,
            "constructor": [],
            "methods": [method_entry("__CONSTRUCT", public=False)]}]}
        rh = Harness(StripManifest(repo_root=root, gold_root=root), b,
                     DockerRunner("none", docker_group=False),
                     alias_table={wired: "coreshop.repository.cart"})
        written = os.path.join(root, *REGISTRATION_REL.split("/"))

        def register(index):
            rh.write_registration(index, {})
            with open(written, encoding="utf-8") as fh:
                text = fh.read()
            return text, (yaml.safe_load(text) or {}).get("services") or {}

        rendered = register(coreshop_shaped)[0]
        check("[coreshop] an index that records no methods -- every index "
              "taken before they were recorded -- registers exactly what it "
              "did: the alias, the context, the ctor-free helper",
              rendered == CORESHOP_ITEM_SERVICES, repr(rendered))
        check("...and recording them, with the constructors public, is the "
              "same document byte for byte",
              register(recorded)[0] == CORESHOP_ITEM_SERVICES)
        held, held_services = register(holders)
        check("[sylius] a constants-holder whose recorded `__construct` is "
              "not public is not registered -- matched case-insensitively, "
              "as the indexer matches it -- and adding two of them to the "
              "same index does not move a byte of the document",
              held == rendered
              and ns + "Resources" not in held_services
              and ns + "Subresources" not in held_services
              and ns + "Money" in held_services
              and ns + "CartContext" in held_services,
              repr(sorted(held_services)))
        check("...and the index is still reported in full: the holders are "
              "the solution's classes, they are only not services",
              rh.write_registration(holders, {})["classes"]
              == [ns + "CartContext", ns + "Money", ns + "Resources",
                  ns + "Subresources"])
        private_context = json.loads(json.dumps(recorded))
        private_context["files"]["HookContext.php"] = {"classes": [{
            "name": ns + "HookContext", "kind": "class", "is_context": True,
            "constructor": [],
            "methods": [method_entry("__construct", public=False)]}]}
        _, context_services = register(private_context)
        check("...and a CONTEXT is unaffected by the rule: FriendsOfBehat "
              "has to fetch it from the container whatever it declares",
              ns + "HookContext" in context_services,
              repr(sorted(context_services)))

    # The SHIPPED Sylius boundary, loaded the way the CoreShop leg above
    # loads its own: a PHP config tree, a different kernel, upstream's eight
    # extensions with their settings, no bootstrap, hooks as attributes, and
    # a suite chosen per item by its tags.  Not a fixture -- a fixture would
    # let `config/boundary_sylius.yml` and the pin below drift apart, and
    # the pin is the only place a second rendering is read at all on a host
    # with no PHP.
    with tempfile.TemporaryDirectory() as root:
        from ..toolkit.behat_suites import SUITE_MAP_NAME, SUITE_MAP_SCHEMA
        os.makedirs(os.path.join(root, _BD))
        # Gold is a SEPARATE tree here, as it is in a real run, so that "the
        # harness reads the map from gold" is a claim this fixture can
        # actually fail: with the two roots equal the check would pass on
        # either spelling (owner ruling 2026-09-10).
        gold = os.path.join(root, "_gold")
        os.makedirs(gold)
        sb = load_boundary(os.path.join(here, "config", "boundary_sylius.yml"),
                           repo_root=root)
        api = "Sylius\\Behat\\Context\\Api\\Shop\\"
        ctx, base = "sylius.behat.context.", "Sylius\\Behat\\Context\\"
        # `api_customer_account`, the suite defect 6 was found in,
        # transcribed id for id and class for class from the strip's real
        # gold `suite_map.json` (the selftest reads no data root).  Its
        # shape is the whole point: `Api\Common\SaveContext` is listed HERE
        # as `...api.shop.save` and by the admin suites as
        # `...api.admin.save`, so a rule that lists the class name cannot
        # say which of the two definitions runs.
        account = [line.split() for line in r"""
            hook.doctrine_orm                Hook\DoctrineORMContext
            hook.guest_cart                  Hook\GuestCartContext
            setup.cart                       Setup\CartContext
            setup.channel                    Setup\ChannelContext
            setup.currency                   Setup\CurrencyContext
            setup.customer                   Setup\CustomerContext
            setup.geographical               Setup\GeographicalContext
            setup.order                      Setup\OrderContext
            setup.payment                    Setup\PaymentContext
            setup.product                    Setup\ProductContext
            setup.shipping                   Setup\ShippingContext
            setup.shop_api_security          Setup\ShopSecurityContext
            setup.user                       Setup\UserContext
            setup.zone                       Setup\ZoneContext
            transform.address                Transform\AddressContext
            transform.channel                Transform\ChannelContext
            transform.country                Transform\CountryContext
            transform.customer               Transform\CustomerContext
            transform.lexical                Transform\LexicalContext
            transform.order                  Transform\OrderContext
            transform.payment                Transform\PaymentMethodContext
            transform.product                Transform\ProductContext
            transform.shared_storage         Transform\SharedStorageContext
            transform.shipping_method        Transform\ShippingMethodContext
            transform.user                   Transform\UserContext
            transform.zone                   Transform\ZoneContext
            api.debug                        Api\DebugContext
            api.email                        Api\EmailContext
            api.shop.checkout                Api\Shop\CheckoutContext
            api.shop.checkout.order_details  Api\Shop\Checkout\CheckoutOrderDetailsContext
            api.shop.customer                Api\Shop\CustomerContext
            api.shop.login                   Api\Shop\LoginContext
            api.shop.order                   Api\Shop\OrderContext
            api.shop.order_item              Api\Shop\OrderItemContext
            api.shop.payment                 Api\Shop\PaymentContext
            api.shop.response                Api\Common\ResponseContext
            api.shop.save                    Api\Common\SaveContext
            api.shop.shipment                Api\Shop\ShipmentContext
        """.strip().splitlines()]
        account_ids = [ctx + sid for sid, _ in account]
        # The real map's own split, by the same rule the boundary applies:
        # this arm's removable code is the Api context tree.
        customer_account = {
            "file": ("src/Sylius/Behat/Resources/config/suites/api/account"
                     "/customer.php"),
            "arm": True, "tag_filter": "@customer_account&&@api", "paths": [],
            "contexts": account_ids,
            "retained": [i for i in account_ids
                         if not i.startswith(ctx + "api.")],
            "removable": [i for i in account_ids
                          if i.startswith(ctx + "api.")],
            "classes": {ctx + sid: base + cls for sid, cls in account}}
        with open(os.path.join(gold, SUITE_MAP_NAME), "w",
                  encoding="utf-8") as fh:
            json.dump({"schema": SUITE_MAP_SCHEMA, "project": "sylius",
                       "suites": {
                           "api_address_book": {
                               "file": "src/.../api/account/address_book.php",
                               "arm": True,
                               "tag_filter": "@address_book&&@api",
                               "contexts": ["sylius.behat.context.hook."
                                            "doctrine_orm",
                                            "sylius.behat.context.api.shop."
                                            "address"],
                               "retained": ["sylius.behat.context.hook."
                                            "doctrine_orm"],
                               "removable": ["sylius.behat.context.api.shop."
                                             "address"],
                               "classes": {
                                   "sylius.behat.context.hook.doctrine_orm":
                                       "Sylius\\Behat\\Context\\Hook"
                                       "\\DoctrineORMContext",
                                   "sylius.behat.context.api.shop.address":
                                       api + "AddressContext"}},
                           # The OTHER API suite the defect turns on: it is
                           # where `RegistrationContext` is a member, and a
                           # `CustomerContext` that injects one drags its
                           # file into the address-book closure.
                           "api_register": {
                               "file": "src/.../api/account/register.php",
                               "arm": True,
                               "tag_filter": "@registration&&@api",
                               "contexts": ["sylius.behat.context.api.shop."
                                            "registration"],
                               "retained": [],
                               "removable": ["sylius.behat.context.api.shop."
                                             "registration"],
                               "classes": {
                                   "sylius.behat.context.api.shop."
                                   "registration":
                                       api + "RegistrationContext"}},
                           "ui_address_book": {
                               "file": "src/.../ui/address_book.php",
                               "arm": False,
                               "tag_filter": "@address_book&&@ui",
                               "contexts": [], "retained": [],
                               "removable": [], "classes": {}},
                           # The OTHER definition of `Common\SaveContext`:
                           # the admin suites bind it to the admin API
                           # client, and an item's closure carries both.
                           "api_managing_administrators": {
                               "file": "src/.../api/admin/administrator.php",
                               "arm": True,
                               "tag_filter": "@managing_administrators&&@api",
                               "contexts": [ctx + "api.admin.save"],
                               "retained": [],
                               "removable": [ctx + "api.admin.save"],
                               "classes": {
                                   ctx + "api.admin.save":
                                       base + "Api\\Common\\SaveContext"}},
                           "api_customer_account": customer_account}}, fh)
        sh = Harness(StripManifest(repo_root=root, gold_root=gold), sb,
                     DockerRunner("none", docker_group=False))
        suite = sh.select_suite(["@address_book", "@api"])
        check("[sylius] the item's tags select its arm suite",
              suite == "api_address_book", str(suite))
        # Owner ruling 2026-09-10.  A suite's `removable` list names the
        # context service ids -- and through `classes` the class names --
        # that the system under test is being asked to write, so the map is
        # gold-side evidence.  Under `_bench` it travelled in the seed's
        # `workspace.tar` to every worker and, through the profile's
        # readable paths, into the agent's own workspace.
        check("[sylius] the suite map is read from the GOLD root, and the "
              "workspace has no copy of it at all",
              os.path.isfile(os.path.join(gold, SUITE_MAP_NAME))
              and not os.path.exists(os.path.join(root, _BD, SUITE_MAP_NAME))
              and sh.suite_map()["project"] == "sylius"
              and (sh.suite_map()["suites"]["api_address_book"]["removable"]
                   == ["sylius.behat.context.api.shop.address"]),
              str(sorted(os.listdir(os.path.join(root, _BD)))))
        try:
            Harness(StripManifest(repo_root=root,
                                  gold_root=os.path.join(root, "_no_gold")),
                    sb, DockerRunner("none", docker_group=False)).suite_map()
            no_map = "accepted"
        except RuntimeError as exc:
            no_map = str(exc)
        check("[sylius] ...and a gold root without it is refused BY NAME "
              "rather than silently selecting no suite -- an item with no "
              "suite registers no retained contexts and fails as the "
              "submission's fault",
              "REFUSED" in no_map and SUITE_MAP_NAME in no_map
              and "sylius" in no_map and "_no_gold" in no_map, no_map)
        check("[sylius] a UI scenario selects no arm suite",
              sh.select_suite(["@address_book", "@ui"]) is None)
        out = sh.write_behat_config(["Sylius\\Behat\\Context\\Api\\Shop"
                                     "\\MyContext"], suite=suite)
        # Behat 4 refuses a YAML `--config` by file name, so this project's
        # profile is PHP -- and it is pinned as BYTES for the same reason
        # CoreShop's is.  Nothing here runs PHP: what the pin can state is
        # that the document survived the change of spelling, and that the
        # text is shaped like the PHP it claims to be.
        check("[sylius] the profile is written under the name Behat 4's "
              "loader accepts, and no YAML file is written at all",
              sh.behat.bench_config == "bench.behat.php"
              and os.path.isfile(os.path.join(root, "bench.behat.php"))
              and not os.path.exists(os.path.join(root, BENCH_CONFIG)))
        php = open(os.path.join(root, sh.behat.bench_config),
                   encoding="utf-8").read()
        check("[sylius] ...and it renders the whole document through the "
              "vendored `Behat\\Config` API: upstream's eight extensions in "
              "row order with their settings, the kernel block on "
              "SymfonyExtension and no `bootstrap` key, the contexts in "
              "registration order, the item's feature file",
              php == SYLIUS_BENCH_CONFIG_PHP, repr(php))
        # No PHP on this host, so the closest thing to `php -l` a Python
        # selftest can state: the parentheses close, the statement is the
        # one Behat 4 requires (`return` of a `ConfigInterface`), and every
        # context reaches PHP as a quoted string rather than a bare word.
        check("[sylius] ...and the rendered text is shaped like PHP: "
              "balanced parens and brackets, one `return (new Config())`, "
              "every context quoted",
              php.count("(") == php.count(")")
              and php.count("[") == php.count("]")
              and php.count("return (new Config())") == 1
              and php.rstrip().endswith(");")
              and all(f"'{c}'" in php.replace("\\\\", "\\")
                      for c in out),
              str((php.count("("), php.count(")"), php.count("["),
                   php.count("]"))))
        # Defect 7: the profile used to start one line BELOW upstream's
        # tester options, so Behat ran every step under this image's bare
        # `error_reporting()` and escalated an in-request `E_DEPRECATED` into
        # the 500 an API scenario read back as its response.
        tester_lines = (
            "use Behat\\Config\\TesterOptions;\n",
            r"            ->withTesterOptions((new TesterOptions())"
            r"->withErrorReporting(\E_ALL & ~(\E_DEPRECATED"
            r" | \E_USER_DEPRECATED)))" "\n")
        check("[sylius] upstream's tester options are rendered where upstream "
              "renders them -- on the Profile, after the formatter and before "
              "the first extension -- with every constant root-namespaced",
              all(line in php for line in tester_lines)
              and (php.index("->withFormatter(")
                   < php.index("->withTesterOptions(")
                   < php.index("->withExtension(")),
              repr(php[:600]))
        was, sh.behat = sh.behat, replace(sh.behat,
                                          tester_error_reporting=None)
        sh.write_behat_config(["Sylius\\Behat\\Context\\Api\\Shop"
                               "\\MyContext"], suite=suite)
        silent = open(os.path.join(root, sh.behat.bench_config),
                      encoding="utf-8").read()
        sh.behat = was
        sh.write_behat_config(["Sylius\\Behat\\Context\\Api\\Shop"
                               "\\MyContext"], suite=suite)
        check("[sylius] ...and those two lines are the WHOLE of what the row "
              "adds: a PHP project that declares no level renders neither the "
              "call nor the `use`, which is what keeps every other project's "
              "profile where it was",
              "TesterOptions" not in silent
              and silent == SYLIUS_BENCH_CONFIG_PHP.replace(
                  tester_lines[0], "").replace(tester_lines[1], ""),
              repr(silent[:600]))
        check("[sylius] the suite's retained context ids are registered, then "
              "the solution's class, then the recorder in ITS namespace",
              out == ["sylius.behat.context.hook.doctrine_orm",
                      "Sylius\\Behat\\Context\\Api\\Shop\\MyContext",
                      "Sylius\\Behat\\Bench\\BenchRecorderHook"], str(out))
        check("[sylius] the removable context ids are NOT registered -- they "
              "are the answer the system under test has to write",
              "sylius.behat.context.api.shop.address" not in out)

        # From here the two halves run as ONE, the way `run_solution` runs
        # them: the registration is written first and the profile is
        # rendered from the ids it defined.  A suite id in `contexts:` says
        # nothing on its own -- FriendsOfBehat can only fetch it if this
        # item's registration put it in the container.
        def index_of(classes: list, steps: Optional[dict] = None) -> dict:
            return {"files": {c.rsplit("\\", 1)[-1] + ".php": {"classes": [
                {"name": c, "kind": "class", "is_context": True,
                 "constructor": [],
                 "steps": [{"kind": "Given", "pattern": pattern}
                           for pattern in (steps or {}).get(c, ())]}]}
                for c in classes}}

        def render(classes: list, in_suite: str, fragment: dict,
                   candidate: bool = False,
                   steps: Optional[dict] = None) -> tuple:
            index = index_of(classes, steps)
            r = sh.write_registration(index, fragment, suite=in_suite,
                                      candidate=candidate)
            relisted = (contexts_to_relist(sh.suite_map()["suites"],
                                           r["contexts"], in_suite,
                                           step_patterns(index))
                        if candidate else [])
            return (sh.write_behat_config(classes, suite=in_suite,
                                          registered=r["services"],
                                          relisted=relisted),
                    r["services"])

        def unfetchable(entries: list, in_suite: str, defined: list) -> list:
            """Rendered entries the container could not hand FriendsOfBehat.

            A legal entry is one of the suite's RETAINED ids or one of the
            boundary's always-registered contexts (upstream's own services,
            in the container whatever the item registers), an id or an FQCN
            THIS item's registration defines, or the recorder.  Anything
            else is a name FriendsOfBehat skips, and Behat's
            `UninitializedContextEnvironment` then throws
            `ContextNotFoundException` on the raw string.
            """
            known = (set(defined)
                     | set(sh.suite_map()["suites"][in_suite]["retained"])
                     | set(sh.boundary.retained_contexts)
                     | {sh.recorder_context})
            return [e for e in entries if e not in known]

        # Defect 5.  The closure restores a context's DEPENDENCIES, so the
        # solution index of a suite-scoped project is wider than the suite:
        # `CustomerContext` injects `RegistrationContext`, both define `I
        # specify the first name as :firstName`, and a suite holding both
        # aborts on its first step (`RedundantStepException`) -- an item
        # scored `closure_incomplete` for a wiring artefact.
        solution = [api + "AddressContext", api + "RegistrationContext",
                    api + "MyContext"]
        # Gold's shape: the `di_fragment` carries upstream's own id for the
        # context it rewrote, so the suite's id IS a service the item
        # defines.
        book_fragment = {ctx + "api.shop.address": {
            "class": api + "AddressContext",
            "arguments": ["@sylius.behat.api_platform_client.shop"]}}
        members, book_ids = render(solution, suite, book_fragment)
        check("[sylius] a solution context of THIS suite is listed, one that "
              "belongs only to ANOTHER suite is not, and a novel context in "
              "no suite is -- retained ids first, then the suite's own "
              "solution contexts in the order given, recorder last",
              members == ["sylius.behat.context.hook.doctrine_orm",
                          "sylius.behat.context.api.shop.address",
                          api + "MyContext",
                          "Sylius\\Behat\\Bench\\BenchRecorderHook"],
              str(members))
        check("[sylius] ...and the one of THIS suite is listed by the SUITE'S "
              "OWN SERVICE ID, while the novel one -- which no suite has an "
              "id for -- stays the class name it is registered under",
              "sylius.behat.context.api.shop.address" in members
              and api + "AddressContext" not in members
              and api + "MyContext" in members, str(members))
        flat = open(os.path.join(root, sh.behat.bench_config),
                    encoding="utf-8").read().replace("\\\\", "\\")
        check("[sylius] ...so the redundant definition never reaches the "
              "rendered profile at all",
              f"'{api}RegistrationContext'" not in flat
              and "'sylius.behat.context.api.shop.address'" in flat
              and f"'{api}AddressContext'" not in flat
              and f"'{api}MyContext'" in flat)
        check("[sylius] ...and every entry of the rendered suite is one the "
              "container has: a retained id, or a service THIS item's "
              "registration defines, or the recorder",
              unfetchable(members, suite, book_ids) == [],
              str(unfetchable(members, suite, book_ids)))

        # Defect 6.  `Api\Common\SaveContext` has ONE class and TWO service
        # definitions, one per API client; the closure of an
        # `api_customer_account` item carries both, and the class name
        # cannot tell them apart.  Listed by class, FriendsOfBehat resolved
        # it through the FQCN alias to the ADMIN definition while the
        # suite's `CustomerContext` had prepared its request on the SHOP
        # client, and 16 items died at `I try to save my changes` with
        # `Call to a member function method() on null`.  Replayed here
        # against that suite as the strip really records it.
        account_suite = sh.select_suite(["@customer_account", "@api"])
        closure = [base + "Api\\Common\\SaveContext",
                   base + "Api\\Shop\\CustomerContext",
                   base + "Api\\Shop\\LoginContext",
                   base + "Api\\Shop\\RegistrationContext"]
        account_index = index_of(closure)
        # Gold again: upstream's ids, both `SaveContext` definitions
        # among them, which is why naming `...api.shop.save` fixes the 16.
        gold_fragment = {ctx + sid: {
            "class": base + cls,
            "arguments": ["@sylius.behat.api_platform_client." + client]}
            for sid, cls, client in (
                ("api.admin.save", "Api\\Common\\SaveContext", "admin"),
                ("api.shop.save", "Api\\Common\\SaveContext", "shop"),
                ("api.shop.customer", "Api\\Shop\\CustomerContext", "shop"),
                ("api.shop.login", "Api\\Shop\\LoginContext", "shop"),
                ("api.shop.registration",
                 "Api\\Shop\\RegistrationContext", "shop"))}
        replay, gold_ids = render(closure, account_suite, gold_fragment)
        check("[sylius] the real `api_customer_account` suite is the one its "
              "item's tags select", account_suite == "api_customer_account",
              str(account_suite))
        check("[sylius] ...and its solution contexts are listed by ITS ids: "
              "the SHOP save, not the admin one and not the class name; the "
              "suite's retained ids first, then the closure's own in the "
              "order given, recorder last",
              replay == customer_account["retained"]
              + [ctx + "api.shop.save", ctx + "api.shop.customer",
                 ctx + "api.shop.login",
                 "Sylius\\Behat\\Bench\\BenchRecorderHook"],
              str(replay[len(customer_account["retained"]):]))
        check("[sylius] ...with the admin definition of the same class "
              "nowhere in the suite, and no Api context named by class at "
              "all",
              ctx + "api.admin.save" not in replay
              and not [c for c in replay if c.startswith(base + "Api")],
              str([c for c in replay if "save" in c or c.startswith(base)]))
        check("[sylius] ...and `RegistrationContext`, which this suite does "
              "not list and `api_register` does, is out by both spellings "
              "-- it is the dependency `CustomerContext` injects, not a "
              "member of the suite",
              api + "RegistrationContext" not in replay
              and ctx + "api.shop.registration" not in replay)
        check("[sylius] ...and the suite's ids are listed BECAUSE gold's "
              "fragment defines them: every entry is a retained id, a "
              "service this item registered, or the recorder",
              unfetchable(replay, account_suite, gold_ids) == []
              and ctx + "api.shop.save" in gold_ids,
              str(unfetchable(replay, account_suite, gold_ids)))

        # The ARM's shape, which gold's never is.  `profile_sylius.yml`
        # tells a submission that the harness registers every class it
        # returns as public, autowired and autoconfigured, and offers the
        # fragment only for constructor arguments autowiring cannot supply;
        # nothing tells it to reuse upstream's service ids.  A submission
        # that rewrites `Api\Shop\CustomerContext` and returns NO fragment
        # is therefore in the container under its FQCN and under nothing
        # else.  Listing `...api.shop.customer` for it names an id the
        # container does not have: FriendsOfBehat skips the entry, and
        # Behat's `UninitializedContextEnvironment` throws
        # `ContextNotFoundException` on the raw id -- the run dies instead
        # of running the submission's context, and the arm is charged for
        # a wiring artefact the way defect 5's items were.
        plain, plain_ids = render(closure, account_suite, {},
                                  candidate=True)
        check("[sylius] a submission that rewrites a MAPPED class and "
              "returns no fragment is listed by CLASS: the suite's id is "
              "not a service it defined, and the FQCN is (`autowire: "
              "true`); its `RegistrationContext`, a class of another suite "
              "only, is listed by class too (harness 25)",
              plain == customer_account["retained"]
              + [base + "Api\\Common\\SaveContext",
                 base + "Api\\Shop\\CustomerContext",
                 base + "Api\\Shop\\LoginContext",
                 base + "Api\\Shop\\RegistrationContext",
                 "Sylius\\Behat\\Bench\\BenchRecorderHook"],
              str(plain[len(customer_account["retained"]):]))
        check("[sylius] ...so the rendered profile holds no id this "
              "registration does not define -- not `...api.shop.save`, not "
              "`...api.shop.customer`",
              unfetchable(plain, account_suite, plain_ids) == []
              and not [c for c in plain if c.startswith(ctx + "api.")],
              str(unfetchable(plain, account_suite, plain_ids)))

        # The same submission with a fragment under an id of ITS OWN: the
        # id is a real service, but it is not one the suite lists, and the
        # suite's vocabulary is the suite's.  The FQCN is what names the
        # class here, and it resolves -- `write_registration` aliases it,
        # public, to `app.my_customer`, so the container hands Behat
        # exactly the definition the submission wrote.
        own_id = {"app.my_customer": {
            "class": base + "Api\\Shop\\CustomerContext",
            "arguments": ["@sylius.behat.api_platform_client.shop"]}}
        mine_out, mine_ids = render(closure, account_suite, own_id,
                                    candidate=True)
        check("[sylius] a fragment under the submission's OWN id is listed "
              "by CLASS too: `app.my_customer` is a service but not one "
              "this suite lists, and the FQCN the registration aliases to "
              "it is",
              mine_out == plain
              and "app.my_customer" not in mine_out
              and "app.my_customer" in mine_ids
              and base + "Api\\Shop\\CustomerContext" in mine_ids,
              str(mine_out[len(customer_account["retained"]):]))
        aliased = yaml.safe_load(open(os.path.join(root, REGISTRATION_REL),
                                      encoding="utf-8"))["services"]
        check("[sylius] ...and that FQCN entry is the public alias to the "
              "submission's own id, so the class name in `contexts:` "
              "fetches the submission's definition",
              aliased[base + "Api\\Shop\\CustomerContext"]
              == {"alias": "app.my_customer", "public": True},
              str(aliased.get(base + "Api\\Shop\\CustomerContext")))
        check("[sylius] ...and every entry of that profile is fetchable too",
              unfetchable(mine_out, account_suite, mine_ids) == [],
              str(unfetchable(mine_out, account_suite, mine_ids)))

        # The alias half of the same fact.  `contexts:` no longer resolves
        # through it, but an injection BY TYPE still does, and a fragment
        # dict's order is not an opinion about which client should answer.
        save_fragment = {ctx + "api.admin.save": {
            "class": base + "Api\\Common\\SaveContext",
            "arguments": ["@sylius.behat.api_platform_client.admin"]},
            ctx + "api.shop.save": {
                "class": base + "Api\\Common\\SaveContext",
                "arguments": ["@sylius.behat.api_platform_client.shop"]}}

        def alias_of(**kw):
            sh.write_registration(account_index, save_fragment, **kw)
            doc = yaml.safe_load(open(os.path.join(root, REGISTRATION_REL),
                                      encoding="utf-8"))["services"]
            return doc.get(base + "Api\\Common\\SaveContext")

        suite_alias, plain_alias = alias_of(suite=account_suite), alias_of()
        check("[sylius] the FQCN alias for a class with two definitions is "
              "the one THIS suite runs, not whichever the closure listed "
              "first",
              suite_alias == {"alias": ctx + "api.shop.save", "public": True},
              str(suite_alias))
        check("[sylius] ...and with no suite in hand it is the first "
              "definition, which is what every project that is not "
              "suite-scoped has always got",
              plain_alias == {"alias": ctx + "api.admin.save",
                              "public": True}, str(plain_alias))
        index = {"files": {cls.rsplit("\\", 1)[-1] + ".php": {"classes": [
            {"name": cls, "kind": "class", "is_context": True,
             "constructor": []}]} for cls in solution}}
        reg = sh.write_registration(index, {})
        registered = yaml.safe_load(open(os.path.join(root, REGISTRATION_REL),
                                         encoding="utf-8"))["services"]
        check("[sylius] ...while the one left out of the suite is still a "
              "registered service, so the injection that put it in the "
              "closure still resolves",
              reg["contexts"] == solution
              and api + "RegistrationContext" in registered,
              str((reg["contexts"], sorted(registered))))
        check("[sylius] the compiled container the harness invalidates is "
              "this project's",
              sh.behat.cache_dir == "var/cache/test_cached"
              and sh.behat.container_prefix == "App_KernelTest_cached")

        # Harness 25, correction B (specifications/EVALUATOR_CORRECTIONS_
        # 20261015_AMENDMENT.md section 3.2).  Gold's closure carries
        # `RegistrationContext` as `CustomerContext`'s dependency and keeps
        # it out of the suite (defect 5 above).  A candidate run lists such a
        # context after all, by class name, unless one of its step patterns
        # is already defined by a returned class listed before it -- which
        # is what keeps a verbatim copy of gold runnable.
        recorder = "Sylius\\Behat\\Bench\\BenchRecorderHook"
        suites = sh.suite_map()["suites"]
        first_name = "I specify the first name as :firstName"
        gold_steps = {base + "Api\\Shop\\CustomerContext": [first_name],
                      api + "RegistrationContext": [first_name,
                                                    "I register this account"]}
        check("[sylius][H25-B] the contexts a gold run leaves out are exactly "
              "the returned classes of other suites only",
              contexts_of_other_suites(suites, closure, account_suite)
              == [api + "RegistrationContext"],
              str(contexts_of_other_suites(suites, closure, account_suite)))
        copied, copied_ids = render(closure, account_suite, gold_fragment,
                                    candidate=True, steps=gold_steps)
        check("[sylius][H25-B] the gold closure of an api_customer_account "
              "item submitted as a candidate lists exactly what gold does: "
              "`RegistrationContext` repeats `CustomerContext`'s first-name "
              "step, so it stays out",
              copied == replay
              and contexts_to_relist(suites, closure, account_suite,
                                     gold_steps) == [],
              str(copied[len(customer_account["retained"]):]))
        own_steps = {base + "Api\\Shop\\CustomerContext": [first_name],
                     api + "RegistrationContext": ["I register my account"]}
        listed, listed_ids = render(closure, account_suite, gold_fragment,
                                    candidate=True, steps=own_steps)
        check("[sylius][H25-B] a candidate's other-suite context whose steps "
              "no class listed before it defines is listed by class name, "
              "after everything harness 24 lists and before the recorder, "
              "which stays last",
              listed == replay[:-1] + [api + "RegistrationContext", recorder]
              and listed[-1] == recorder,
              str(listed[len(customer_account["retained"]):]))
        check("[sylius][H25-B] ...and that class name is a service this "
              "registration defines (the public alias to the candidate's "
              "own definition), so FriendsOfBehat can fetch it",
              unfetchable(listed, account_suite, listed_ids) == []
              and api + "RegistrationContext" in listed_ids,
              str(unfetchable(listed, account_suite, listed_ids)))
        admin_save = base + "Api\\Common\\SaveContext"
        check("[sylius][H25-B] other-suite contexts are relisted sorted by "
              "class name, each checked against every returned class listed "
              "before it, the relisted ones included",
              contexts_to_relist(
                  suites, [api + "RegistrationContext", api + "OtherContext",
                           admin_save, api + "ThirdContext"],
                  "api_address_book",
                  {api + "RegistrationContext": ["a"], admin_save: ["b"],
                   api + "OtherContext": ["c"], api + "ThirdContext": []})
              == [admin_save, api + "RegistrationContext"]
              and contexts_to_relist(
                  suites, [api + "RegistrationContext", admin_save],
                  "api_address_book",
                  {api + "RegistrationContext": ["a"], admin_save: ["a"]})
              == [admin_save]
              and contexts_to_relist(
                  suites, [api + "RegistrationContext", api + "OtherContext"],
                  "api_address_book",
                  {api + "RegistrationContext": ["c"],
                   api + "OtherContext": ["c"]}) == [])
        address_index = index_of([api + "AddressContext", api + "NewContext",
                                  api + "RegistrationContext", admin_save])
        address_reg = sh.write_registration(address_index, {},
                                            suite="api_address_book",
                                            candidate=True)
        ordered = sh.write_behat_config(
            address_reg["contexts"], suite="api_address_book",
            registered=address_reg["services"],
            relisted=contexts_to_relist(suites, address_reg["contexts"],
                                        "api_address_book", {}))
        check("[sylius][H25-B] ...so the profile is harness 24's list, then "
              "the relisted classes by name, then the recorder",
              ordered == ["sylius.behat.context.hook.doctrine_orm",
                          api + "AddressContext", api + "NewContext",
                          admin_save, api + "RegistrationContext", recorder],
              str(ordered))

        # Correction C (section 3.3).  A submitted definition of one of the
        # solution's classes that leaves a required constructor parameter
        # without an argument, and says nothing about autowiring, cannot be
        # instantiated (`ArgumentCountError`); the prompt promises every
        # returned class is autowired.
        storage = "Sylius\\Behat\\Service\\SharedStorageInterface"
        client = "Sylius\\Behat\\Client\\ApiClientInterface"
        cart = api + "CartContext"

        def parameter(name, types, default=False, variadic=False):
            return {"name": name, "types": types, "promoted": True,
                    "has_default": default, "variadic": variadic}

        wiring = {"files": {"CartContext.php": {"classes": [
            {"name": cart, "kind": "class", "is_context": True,
             "constructor": [parameter("shopClient", [client]),
                             parameter("sharedStorage", [storage]),
                             parameter("locale", ["string"], default=True),
                             parameter("extra", ["string"],
                                       variadic=True)]}]}}}

        def autowired(fragment, candidate=True):
            reg = sh.write_registration(wiring, fragment, suite=account_suite,
                                        candidate=candidate)
            doc = yaml.safe_load(open(os.path.join(root, REGISTRATION_REL),
                                      encoding="utf-8"))["services"]
            return reg["autowired"], doc

        partial = {"app.cart": {"class": cart,
                                "arguments": ["@sylius.behat.client"]}}
        got, doc = autowired(partial)
        check("[sylius][H25-C] a submitted definition that leaves a required "
              "parameter unwired is autowired, and the id is reported",
              got == ["app.cart"]
              and doc["app.cart"] == {"class": cart,
                                      "arguments": ["@sylius.behat.client"],
                                      "autowire": True}
              and partial["app.cart"] == {"class": cart, "arguments":
                                          ["@sylius.behat.client"]},
              str((got, doc.get("app.cart"))))
        got, doc = autowired(partial, candidate=False)
        check("[sylius][H25-C] ...while a gold run's fragment is written "
              "exactly as given",
              got == [] and doc["app.cart"] == partial["app.cart"],
              str((got, doc.get("app.cart"))))
        unchanged = {
            "every required parameter by position (the optional and the "
            "variadic ones may stay unwired)":
                {"app.cart": {"class": cart, "arguments": ["@a", "@b"]}},
            "by name": {"app.cart": {"class": cart, "arguments": {
                "$shopClient": "@a", "$sharedStorage": "@b"}}},
            "by type": {"app.cart": {"class": cart, "arguments": {
                "\\" + client: "@a", storage: "@b"}}},
            "by integer key and index_N": {"app.cart": {
                "class": cart, "arguments": {0: "@a", "index_1": "@b"}}},
            "an entry that switches autowiring off itself":
                {"app.cart": {"class": cart, "arguments": ["@a"],
                              "autowire": False}},
            "an entry that already autowires":
                {"app.cart": {"class": cart, "autowire": True}},
            "a fragment whose _defaults says autowire: false":
                {"_defaults": {"autowire": False}, **partial},
            "a fragment whose _defaults says autowire: true":
                {"_defaults": {"autowire": True}, **partial},
            "an alias entry (with a complete definition)":
                {cart: {"alias": "app.cart", "public": True},
                 "app.cart": {"class": cart, "arguments": ["@a", "@b"]}},
            "an '@id' string":
                {"app.cart.shortcut": "@app.cart",
                 "app.cart": {"class": cart, "arguments": ["@a", "@b"]}},
            "a definition of a class the solution does not define":
                {"app.other": {"class": api + "OtherContext",
                               "arguments": []}},
        }
        for case, fragment in unchanged.items():
            got, doc = autowired(fragment)
            check(f"[sylius][H25-C] left as written: {case}",
                  got == [] and all(doc[sid] == body
                                    for sid, body in fragment.items()),
                  str((got, {sid: doc.get(sid) for sid in fragment})))
        got, _doc = autowired({cart: {"arguments": {"$shopClient": "@a"}}})
        check("[sylius][H25-C] an entry keyed by the class name without "
              "`class:` is a definition of that class too",
              got == [cart], str(got))
        got, doc = autowired({cart: None})
        check("[sylius][H25-C] ...and so is an empty body (`Foo: ~`), which "
              "is autowired",
              got == [cart] and doc[cart] == {"autowire": True},
              str((got, doc.get(cart))))

        # The whole route: `run_solution` reads which of the two a run is
        # from `Solution.gold_run`, which the coordinator sets and no
        # submitted byte can, and reports what the corrections changed.
        # Index and execution are stubbed; the registration and the profile
        # are written for real.
        account_feature = parse_feature_file(
            os.path.join(root, "account.feature"),
            "@customer_account @api\nFeature: Account\n\n"
            "  Scenario: Changing my name\n    Given I am a customer\n")
        customer = base + "Api\\Shop\\CustomerContext"

        def routed_run(steps: dict, fragment: dict, **marks) -> dict:
            index = index_of(closure, steps)
            for finfo in index["files"].values():
                for entry in finfo["classes"]:
                    if entry["name"] == customer:
                        entry["constructor"] = [
                            parameter("client", [client]),
                            parameter("registration",
                                      [api + "RegistrationContext"])]
            files = [SourceFile("src/Sylius/Behat/"
                                + c[len("Sylius\\Behat\\"):].replace("\\", "/")
                                + ".php", f"<?php // {c}\n") for c in closure]
            routed = Harness(StripManifest(repo_root=root, gold_root=gold), sb,
                             _FakeRunner())
            routed.index_paths = lambda _paths: index
            return routed.run_solution(
                account_feature, account_feature.scenarios[0],
                Solution(files=files, services_fragment=fragment, **marks),
                timeout=5)

        partial_customer = {"app.customer": {
            "class": customer, "arguments": ["@sylius.behat.client"]}}
        gold_run = routed_run(own_steps, partial_customer,
                              metadata={"source": "gold"}, gold_run=True)
        check("[sylius][H25] a gold run keeps harness 24's rules and records "
              "both corrections' fields empty",
              gold_run["relisted_contexts"] == []
              and gold_run["autowired_services"] == []
              and api + "RegistrationContext" not in gold_run["suite_contexts"],
              str({k: gold_run.get(k) for k in ("relisted_contexts",
                                                 "autowired_services")}))
        claimed = routed_run(own_steps, partial_customer,
                             metadata={"source": "gold"})
        check("[sylius][H25] ...but a candidate run whose metadata merely "
              "says `gold` (a replayed gold row) is a candidate run: it "
              "relists its other-suite context and autowires its partial "
              "definition, and says so",
              claimed["relisted_contexts"] == [api + "RegistrationContext"]
              and claimed["autowired_services"] == ["app.customer"]
              and api + "RegistrationContext" in claimed["suite_contexts"],
              str({k: claimed.get(k) for k in ("relisted_contexts",
                                                "autowired_services",
                                                "suite_contexts")}))
        verbatim = routed_run(gold_steps, gold_fragment)
        check("[sylius][H25] ...and a verbatim copy of the gold closure run as "
              "a candidate lists exactly gold's suite",
              verbatim["relisted_contexts"] == []
              and verbatim["suite_contexts"] == replay,
              str(verbatim["suite_contexts"][len(customer_account["retained"]):]))

    # The third project shape: no Symfony wiring, and suites separated by
    # the directory their features live in.
    with tempfile.TemporaryDirectory() as root:
        from ..core.boundary import Boundary
        from ..toolkit.behat_suites import SUITE_MAP_NAME, SUITE_MAP_SCHEMA
        os.makedirs(os.path.join(root, _BD))
        gold = os.path.join(root, "_gold")
        os.makedirs(gold)
        beh = "tests/Integration/Behaviour"
        common = ("Tests\\Integration\\Behaviour\\Features\\Context"
                  "\\CommonFeatureContext")
        pb = Boundary(version=1, project="prestashop", repo_root=root,
                      removable=[(f"{beh}/Features/Context/Domain/", "")],
                      retained=[(f"{beh}/Features/Context/", "")],
                      retained_contexts=[common],
                      raw={"behat": {
                          "config_dir": beh, "suites_entry": "behat.yml",
                          "services_entry": None, "hook_services": None,
                          "test_config": None,
                          "original_services_import": None,
                          "bench_services_import": None,
                          "recorder_namespace":
                              "Tests\\Integration\\Behaviour"
                              "\\Features\\Bench",
                          "suite_scoped": True}})
        with open(os.path.join(gold, SUITE_MAP_NAME), "w",
                  encoding="utf-8") as fh:
            json.dump({"schema": SUITE_MAP_SCHEMA, "project": "prestashop",
                       "suites": {
                           "cart": {"file": f"{beh}/behat.yml", "arm": True,
                                    "tag_filter": None,
                                    "paths": [f"{beh}/Features/Scenario/cart"],
                                    "contexts": [common], "retained": [common],
                                    "removable": [], "classes": {}},
                           "order": {"file": f"{beh}/behat.yml", "arm": True,
                                     "tag_filter": None,
                                     "paths": [f"{beh}/Features/Scenario/"
                                               f"order"],
                                     "contexts": [common],
                                     "retained": [common], "removable": [],
                                     "classes": {}}}}, fh)
        ph = Harness(StripManifest(repo_root=root, gold_root=gold), pb,
                     DockerRunner("none", docker_group=False))
        check("[no-DI] the second project shape reads its map from gold "
              "too, and its workspace has no copy either -- the rule is the "
              "map's content, not one project's config format",
              ph.suite_map()["project"] == "prestashop"
              and not os.path.exists(os.path.join(root, _BD, SUITE_MAP_NAME)),
              str(sorted(os.listdir(os.path.join(root, _BD)))))
        check("[no-DI] the protected ids are the recorder and the boundary's "
              "always-registered contexts -- there is no "
              "`retained_services.yml` to read, and that is the whole set "
              "rather than a gap",
              ph.protected_service_ids() == {
                  "Tests\\Integration\\Behaviour\\Features\\Bench"
                  "\\BenchRecorderHook", common},
              str(sorted(ph.protected_service_ids())))

        feat = parse_feature_file(
            os.path.join(root, beh,
                         "Features/Scenario/cart/add_product.feature"),
            "Feature: Cart\n\n  Scenario: Add\n    When I add a product\n")
        check("[no-DI] the item's feature file is put back in repo-relative "
              "terms, which is how a suite's paths are recorded",
              ph.feature_rel(feat) == f"{beh}/Features/Scenario/cart/"
                                      f"add_product.feature",
              str(ph.feature_rel(feat)))
        check("[no-DI] ...and that is what selects the suite, for suites "
              "that carry no tag to select on",
              ph.select_suite([], ph.feature_rel(feat)) == "cart"
              and ph.select_suite([]) is None,
              str(ph.select_suite([], ph.feature_rel(feat))))

    # -- the isolated-PHP session shape ------------------------------------
    #
    # The Behat/PHP materialisation audit runs the applier here rather than
    # on a host that has no `php`, and it runs a whole walk inside ONE
    # container per disposable copy.  Source-only: `_image_for_isolated_run`
    # is the one thing that would contact a daemon, so it is stood in for,
    # and what is asserted is the argv the audit would send.
    with tempfile.TemporaryDirectory(prefix="r2t-isolated-php-") as php_root:
        workspace = os.path.realpath(php_root)

        class _PhpSessionProbe(DockerRunner):
            def __init__(self, exec_timeout=False):
                super().__init__("worker-0", workdir="/work",
                                 docker_group=False)
                self._isolated_image = "sha256:" + "e" * 64
                self.calls = []
                self.exec_timeout = exec_timeout

            def _docker(self, argv, *, timeout):
                self.calls.append(list(argv))
                if self.exec_timeout and argv[0] == "exec":
                    raise subprocess.TimeoutExpired(["docker", *argv], timeout)
                return subprocess.CompletedProcess([], 0, "", "")

        # THE POSTURE ITSELF, as a literal.  Every check below compares a
        # container's argv against `_isolated_base_flags`, so the builder and
        # its callers move together and a flag deleted from the builder
        # disappears from the tree silently -- which is exactly what happened
        # to `no-new-privileges` when this section replaced the per-invocation
        # applier check that pinned it.  One shared builder feeds the Java
        # sidecar, the Java session, the PHP probe and the PHP session, so it
        # is pinned here once, spelled out.
        check("the isolation posture every trusted sidecar shares is these "
              "exact flags -- no network, a pids cap, no new privileges, a "
              "read-only root and one small noexec tmpfs",
              DockerRunner._isolated_base_flags("256m", detach=True) == [
                  "run", "--rm", "-d", "--network", "none",
                  "--pids-limit", "128",
                  "--security-opt", "no-new-privileges", "--read-only",
                  "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m"]
              and DockerRunner._isolated_base_flags("64m") == [
                  "run", "--rm", "--network", "none",
                  "--pids-limit", "128",
                  "--security-opt", "no-new-privileges", "--read-only",
                  "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m"],
              str(DockerRunner._isolated_base_flags("256m", detach=True)))

        php_runner = _PhpSessionProbe()
        applier_env = {"R2T_PHP_AUTOLOAD": "/work/vendor/autoload.php"}
        applier_argv = ["php", "/work/var/bench_mutate/mutate_argv.php",
                        "/work/var/bench_mutate/argv.json"]
        session = php_runner.open_isolated_php_session(
            workspace_host=workspace)
        session.run(applier_argv, env=applier_env)
        session.run(applier_argv, env=applier_env)
        exec_argv = list(php_runner.calls[-1])
        session.close()
        start_argv = php_runner.calls[0]
        session_name = start_argv[4] if len(start_argv) > 4 else ""
        check("the audit session detaches ONE container with no network, no "
              "new privileges, a read-only root and ONE read-write mount: "
              "the disposable copy, at the worker's own workdir",
              start_argv[:4] == ["run", "--rm", "-d", "--name"]
              and re.fullmatch(r"r2t-php-session-[0-9a-f]{32}", session_name)
              and start_argv[5:8] == DockerRunner._isolated_base_flags(
                  "256m", detach=True)[3:6]
              and start_argv[3:4] + start_argv[5:] == [
                  "--name",
                  *DockerRunner._isolated_base_flags("256m",
                                                     detach=True)[3:],
                  "--mount", f"type=bind,src={workspace},dst=/work",
                  "--workdir", "/work", "--entrypoint", "php",
                  php_runner._isolated_image,
                  "-r", _ISOLATED_PHP_SESSION_IDLE],
              str(start_argv))
        # A mutant descriptor carries SOURCE TEXT, and the shim reads it out
        # of a file.  A shell anywhere on this route would let the
        # population's own contents decide an argv, so there is none: not in
        # the session's own PID 1, and not in the exec that drives it.
        check("no shell is started on this route -- the interpreter is the "
              "session's entrypoint and the exec's first token",
              "/bin/sh" not in start_argv and "-lc" not in start_argv
              and "/bin/sh" not in exec_argv and "-lc" not in exec_argv
              and exec_argv[-3:] == applier_argv,
              str(start_argv[-4:]) + str(exec_argv[-4:]))
        check("each mutant costs one `docker exec` through the same Docker "
              "authority, carrying the environment rendering the equivalent "
              "`docker run` would have carried",
              [call[0] for call in php_runner.calls]
              == ["run", "exec", "exec", "rm", "ps"]
              and exec_argv == [
                  "exec", *DockerRunner._isolated_env_args(applier_env),
                  "--workdir", "/work", session_name, *applier_argv]
              and DockerRunner._isolated_env_args(applier_env)
              == ["--env", "R2T_PHP_AUTOLOAD=/work/vendor/autoload.php"]
              # `core.docker_cli.docker_argv` refuses an empty or NUL-bearing
              # token, and `_docker` is the only way out of this class.
              and all(isinstance(part, str) and part and "\0" not in part
                      for part in exec_argv)
              and session.execs == 2,
              repr(exec_argv))
        check("closing the audit session force-removes its container and "
              "proves the name absent",
              php_runner.calls[-2] == ["rm", "-f", session_name]
              and php_runner.calls[-1]
              == ["ps", "-aq", "--no-trunc", "--filter",
                  "name=^/" + session_name + "$"]
              and not session.opened,
              repr(php_runner.calls[-2:]))

        timed_out_probe = _PhpSessionProbe(exec_timeout=True)
        timed_out_session = timed_out_probe.open_isolated_php_session(
            workspace_host=workspace)
        timed_out_name = timed_out_probe.calls[0][4]
        try:
            timed_out_session.run(applier_argv, timeout=1)
        except subprocess.TimeoutExpired:
            pass
        else:
            check("a timed-out PHP session exec propagates timeout", False)
        closed_refused = False
        try:
            timed_out_session.run(applier_argv)
        except RuntimeError as exc:
            closed_refused = "session is closed" in str(exc)
        check("a timed-out session exec force-removes the container, proves "
              "its absence, and closes the session against further execs",
              [call[0] for call in timed_out_probe.calls]
              == ["run", "exec", "rm", "ps"]
              and timed_out_probe.calls[2] == ["rm", "-f", timed_out_name]
              and timed_out_probe.calls[3]
              == ["ps", "-aq", "--no-trunc", "--filter",
                  "name=^/" + timed_out_name + "$"]
              and not timed_out_session.opened and closed_refused,
              repr(timed_out_probe.calls))

        probe_argv = php_runner._isolated_php_argv(
            workspace_host=None, env=None, entrypoint="php",
            arguments=["--version"], tmpfs_size="64m")
        check("the interpreter probe mounts nothing at all -- it answers "
              "'is php in this image', not 'what is in the workspace'",
              "--mount" not in probe_argv and "--workdir" not in probe_argv
              and "--env" not in probe_argv
              and probe_argv[-1] == "--version"
              and probe_argv[probe_argv.index("--tmpfs") + 1]
              == "/tmp:rw,nosuid,nodev,noexec,size=64m",
              str(probe_argv))

    # The stdin route carries supported large Go source files without placing
    # their bytes in an argv element. No-input callers keep their old argv.
    from unittest.mock import patch
    payload = "A" * 220168  # base64 size of the pinned HTTP openapi.go source
    docker_runner = DockerRunner("fixture", workdir="/work", docker_group=False)
    with patch("r2t.core.docker_cli.docker_command",
               side_effect=lambda argv, **kwargs: ["docker", *argv]), \
            patch.object(subprocess, "run") as launched:
        docker_runner.run("base64 -d > /r2t-go/run/file.go", timeout=17,
                          input=payload)
        argv, = launched.call_args.args
        options = launched.call_args.kwargs
        check("large source bytes use stdin, not the shell argument",
              argv[:3] == ["docker", "exec", "-i"]
              and payload not in " ".join(argv) and options["input"] == payload
              and options["timeout"] == 17)
        docker_runner.run("true", timeout=17)
        argv, = launched.call_args.args
        check("Docker exec argv stays unchanged with explicit diagnostic decoding",
              argv == ["docker", "exec", "fixture", "sh", "-lc", "cd /work && true"]
              and launched.call_args.kwargs
              == {"capture_output": True, "text": True, "timeout": 17,
                  "encoding": "utf-8", "errors": "backslashreplace"})

    # Exercise real subprocess decoding without Docker. A fake CompletedProcess
    # would miss the UnicodeDecodeError that stopped PrestaShop's mutation run.
    command = [sys.executable, "-c",
               "import os, sys; "
               "data = sys.stdin.buffer.read(); "
               "os.write(1, data + b'\\xe2!\\r\\n'); "
               "os.write(2, b'error: \\xff\\n'); "
               "sys.exit(3)"]
    with patch.object(docker_runner, "_wrap", return_value=command):
        result = docker_runner.run("fixture", input="caf\u00e9\n", timeout=10)
    check("malformed console bytes preserve exit status, UTF-8 stdin and text",
          result.returncode == 3 and result.stdout == "caf\u00e9\n\\xe2!\n"
          and result.stderr == "error: \\xff\n", repr(result))
    with patch.object(docker_runner, "_wrap", return_value=[
            sys.executable, "-c", "import os; os.write(1, b'\\xe2')"]):
        result = docker_runner.run("fixture", timeout=10)
    check("truncated UTF-8 on the no-stdin route remains a successful process",
          result.returncode == 0 and result.stdout == "\\xe2"
          and result.stderr == "", repr(result))

    print("\n" + ("ALL PASS (harness)" if ok else "FAILURES (harness)"))
    return 0 if ok else 1


def gold_solution(
        gold_root: str, closure: dict, *,
        source_bytes: Optional[Mapping[str, bytes]] = None) -> Solution:
    """The reference solution: the closure's files, verbatim, plus its wiring."""
    if source_bytes is not None \
            and set(source_bytes) != set(closure["files"]):
        raise ValueError(
            "bound gold-source set differs from the selected closure")
    files = []
    for rel in closure["files"]:
        if source_bytes is None:
            with open(os.path.join(gold_root, rel), encoding="utf-8") as fh:
                code = fh.read()
        else:
            raw = source_bytes[rel]
            if not isinstance(raw, bytes):
                raise ValueError("bound gold source is not bytes")
            # Match TextIOWrapper/open(newline=None): publication freezes the
            # raw bytes, while the existing harness consumes universal-newline
            # decoded text.
            with io.TextIOWrapper(
                    io.BytesIO(raw), encoding="utf-8", errors="strict",
                    newline=None) as fh:
                code = fh.read()
        files.append(SourceFile(file_path=rel, code=code))
    fragment = {}
    for sid, body in (closure.get("di_fragment") or {}).items():
        entry: dict = {"class": body["class"]}
        if body.get("arguments"):
            entry["arguments"] = body["arguments"]
        if body.get("tags"):
            entry["tags"] = body["tags"]
        fragment[sid] = entry
    return Solution(files=files, services_fragment=fragment,
                    metadata={"source": "gold"}, gold_run=True)


if __name__ == "__main__":
    raise SystemExit(selftest())
