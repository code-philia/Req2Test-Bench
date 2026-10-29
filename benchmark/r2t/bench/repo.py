"""S4 — build and manage the stripped repository.

Removal is repo-wide (SPEC §2): every removable file leaves the working
tree.  Nothing is deleted, though — files are MOVED into a gold tree, so
"restore exactly the extracted ground-truth test code" (§5) is a copy
back, and the stripped state is recoverable in either direction.

Three edits make the stripped repo boot at all; each is recorded in the
manifest because each is a place where the benchmark differs from a
plain `rm -rf`:

1. `config/packages/test/config.yaml` imports the Behat services file
   that repo-wide removal deletes.  Without rewriting that one line the
   test kernel throws LoaderLoadException before any scenario runs — a
   build error masquerading as a benchmark result.
2. The retained substrate's own registration (the payum `offline`
   gateway, `core_shop_resource` mapping for the retained Behat/Model
   stubs, the shared-storage aliases, the tagged index extensions, the
   four hook contexts) lives inside the removed file, so it is
   re-emitted into a harness-owned file.
3. The recorder hook (SPEC §6) is installed under the retained tree.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import tempfile
from dataclasses import dataclass, field, fields as _dataclass_fields, replace
from typing import Optional

import yaml

from ..java import kapua as _kapua
from ..core.boundary import Boundary, REMOVABLE
from ..core.paths import DATA_ROOT_ENV
from ..core.paths import BENCHMARK_ROOT
from ..data.mutation import CORESHOP_PROD_PATHS


def declared_corpus_roots() -> tuple[str, ...]:
    """Every checkout `config/corpora.yml` declares, absolute.

    The one list the three strip arms refuse to write into.  It used to be
    three hand-kept literals — CoreShop here, python-docx/python-pptx/
    algorand-sdk in `stacks.behave`, epubcheck in `stacks.cucumber` — and a
    corpus the config declared but no literal named was simply unguarded:
    `strip` moved its test code and its `.git` into a gold tree and reported
    success, and the damage surfaced later, from `r2t/toolkit/extract.py`, as
    "has origin 'none'".  Coverage of a config file the process already
    loads is not a thing to keep by hand.

    Empty when no data root is configured: `load_corpora` refuses an
    absolute `root`, so every declared checkout lives below `R2T_DATA_ROOT`
    and without one there is no path a strip could be pointed at.  When
    `corpora.yml` is absent `corpus_entries()` refuses by name rather than
    falling back to a different corpus, so the guard never opens up.
    """
    if not os.environ.get(DATA_ROOT_ENV):
        return ()
    from r2t.toolkit.extract import corpus_entries
    roots = []
    for entry in corpus_entries():
        # `step_definitions_root` is a corpus too: algorand's Gherkin and the
        # Java that answers it are pinned in DIFFERENT repositories, and the
        # second one is maven-shaped, i.e. exactly what `strip_repo_cucumber`
        # accepts.
        for key in ("root", "step_definitions_root"):
            if entry.get(key):
                roots.append(os.path.abspath(entry[key]))
    return tuple(dict.fromkeys(roots))


BENCH_DIR = "_bench"
BENCH_CONFIG = "bench.behat.yml"
#: The same file under a Behat that refuses YAML.
#:
#: Behat 4 (`behat/behat` 4.0.0-alpha1, which Sylius pins) deleted the YAML
#: loader: `ConfigurationLoader::loadFileConfiguration` refuses anything whose
#: name does not end in `.php` -- "Configuration file `bench.behat.yml` must
#: be a PHP file" -- and it refuses before reading a byte.  So the NAME and
#: the FORMAT are one fact, and `BehatProject.bench_config` derives the name
#: from `bench_config_format` rather than letting a row set the two apart.
BENCH_CONFIG_PHP = "bench.behat.php"
#: The two renderings `harness.write_behat_config` knows, and the file name
#: each is written under.  A CLOSED set, for the reason `reset_program` is
#: one: a misspelled format that fell through to CoreShop's YAML on a project
#: whose Behat refuses YAML is every item failing in a container three hours
#: later, rather than the row failing where it is read.
BENCH_CONFIG_NAMES = {"yaml": BENCH_CONFIG, "php": BENCH_CONFIG_PHP}
TEST_CONFIG = "config/packages/test/config.yaml"
ORIGINAL_SERVICES_IMPORT = "../../../src/CoreShop/Behat/Resources/config/services.yml"
BENCH_SERVICES_IMPORT = "../../../_bench/services.yml"
RECORDER_REL = "src/CoreShop/Behat/Bench/BenchRecorderHook.php"

#: How the project's Behat FINDS the recorder's hooks.  A CLOSED set, for
#: the reason `bench_config_format` is one: a misspelling that fell through
#: to the docblock spelling on a Behat 4 project is a recorder whose hooks
#: never fire, and that is not visible until an item has been scored.
HOOK_STYLES = ("annotation", "attribute")

#: Which `SebastianBergmann\CodeCoverage\Filter` API the project's vendored
#: php-code-coverage has.  A CLOSED set, and closed for a reason the other
#: two rows do not share: the recorder's own `catch (\Throwable)` SWALLOWS
#: the failure.  php-code-coverage 11 dropped `Filter::includeDirectory`,
#: leaving `includeFile`/`includeFiles`; CoreShop vendors 10.1.16, which
#: still has it, and Sylius vendors 12.5.7, which does not.  On 12 the
#: template's line raises `Error: Call to undefined method`, the catch turns
#: it into one line of stderr, and every row of that project is then scored
#: with no coverage and `direct_calls: null` -- the trace starts only when
#: the collector exists.  Both of those are gold checks, so the whole
#: project fails them, and nothing in the run says why.
COVERAGE_FILTERS = ("directory", "files")

#: The vocabulary a `tester_error_reporting` expression is written in: PHP's
#: error-level constants, with the values PHP 8 gives them, and the three
#: bitwise operators.  CLOSED by NAME rather than by shape, because the two
#: renderings need different things from it and both fail silently on a name
#: that is not one of these: PHP resolves an unknown `\E_TYPO` to an
#: `Error: Undefined constant` at profile load -- every item of the project
#: dying before a scenario runs -- and the YAML spelling has no constant to
#: resolve at all, so it has to compute the mask here.
#:
#: `E_ALL` is 32767 on every PHP 8, which is also what the Sylius image
#: reports from a bare `error_reporting()`.
PHP_ERROR_LEVELS = {
    "E_ERROR": 1, "E_WARNING": 2, "E_PARSE": 4, "E_NOTICE": 8,
    "E_CORE_ERROR": 16, "E_CORE_WARNING": 32, "E_COMPILE_ERROR": 64,
    "E_COMPILE_WARNING": 128, "E_USER_ERROR": 256, "E_USER_WARNING": 512,
    "E_USER_NOTICE": 1024, "E_STRICT": 2048, "E_RECOVERABLE_ERROR": 4096,
    "E_DEPRECATED": 8192, "E_USER_DEPRECATED": 16384, "E_ALL": 32767,
}

#: One token of such an expression: a constant name, an operator, a bracket,
#: or the whitespace between them.  Anything the scan does not cover is
#: refused with the text of it.
ERROR_LEVEL_TOKEN = re.compile(r"E_[A-Z_]+|[&|~()]|\s+")


def error_reporting_int(expr, project: str,
                        row: str = "tester_error_reporting") -> int:
    """The mask an expression names, refusing anything outside the vocabulary.

    Called where the boundary is READ, so a mistyped constant is a boundary
    that will not load rather than a container that will not boot; and called
    again by the YAML rendering, which cannot spell a PHP constant and has to
    hand Behat the integer (`calls.error_reporting` is a scalar node whose
    value goes straight into `error_reporting()`).

    Python's own `~ & |` over ints agree with PHP's on both precedence and
    result -- `32767 & ~(8192 | 16384)` is 8191 in either language -- so the
    evaluation of the checked token stream is the arithmetic itself.
    """
    if not isinstance(expr, str):
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {project} boundary declares "
            f"`{row}: {expr!r}`, which is a {type(expr).__name__}. The row is "
            f"the PHP constant expression the profile renders -- write the "
            f"levels by name, e.g. `E_ALL & ~E_DEPRECATED`.")
    out, pos = [], 0
    for m in ERROR_LEVEL_TOKEN.finditer(expr):
        if m.start() != pos:
            raise SystemExit(
                f"REFUSED: the `behat:` block of the {project} boundary "
                f"declares `{row}: {expr!r}`, which contains "
                f"{expr[pos:m.start()]!r}. The vocabulary is the PHP error "
                f"constants, `& | ~`, brackets and spaces -- nothing else "
                f"reaches PHP as a level.")
        pos = m.end()
        token = m.group()
        if token.startswith("E_"):
            if token not in PHP_ERROR_LEVELS:
                raise SystemExit(
                    f"REFUSED: the `behat:` block of the {project} boundary "
                    f"names `{token}` in `{row}`, which is not a PHP error "
                    f"level. PHP resolves an unknown constant to an "
                    f"`Error: Undefined constant` while it loads the profile, "
                    f"so every item of the project would die before a "
                    f"scenario ran. The levels are "
                    f"{sorted(PHP_ERROR_LEVELS)}.")
            out.append(str(PHP_ERROR_LEVELS[token]))
        else:
            out.append(token)
    if pos != len(expr):
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {project} boundary declares "
            f"`{row}: {expr!r}`, which contains {expr[pos:]!r}. The "
            f"vocabulary is the PHP error constants, `& | ~`, brackets and "
            f"spaces -- nothing else reaches PHP as a level.")
    try:
        # Only digits, `& | ~`, brackets and spaces are left: the tokens were
        # all matched above and every name was replaced by its value.
        return int(eval("".join(out), {"__builtins__": {}}, {}))  # noqa: S307
    except Exception:                                        # noqa: BLE001
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {project} boundary declares "
            f"`{row}: {expr!r}`, whose tokens are all levels and operators "
            f"but do not form an expression. PHP would not parse it either, "
            f"and a profile that does not parse is every item of the project "
            f"failing before a scenario ran.") from None


#: What a solution's own code must never be able to change.
#:
#: `install_solution` refuses to WRITE outside removable territory, but that
#: constrains the harness, not the solution: the PHP it writes then executes
#: as root on a read-write bind mount of this whole tree (`DockerRunner` passes
#: no `--user`, `disable_functions` is empty).  So a step body can rewrite the
#: recorder that scores it, the retained hook that isolates the database, or
#: production code — and `clean_workspace` sweeps only removable territory, so
#: the change would persist silently into every later item.
#:
#: These roots are hashed once and re-verified before every item.  The point is
#: not prevention — it is that a corrupted sweep must not be indistinguishable
#: from a clean one after the fact.
SUBSTRATE_ROOTS = ("src", "config", BENCH_DIR, "behat-bootstrap.php",
                   "composer.json", "vendor/bin", "vendor/behat",
                   "vendor/friends-of-behat", "vendor/phpunit")

#: Files inside those roots that change by design and are not substrate input.
#:
#: CoreShop's `config/reference.php` is framework-generated: Symfony's
#: `PhpConfigReferenceDumpPass`, registered when `kernel.debug` is true,
#: recomputes it from the compiled container and rewrites it when bytes differ.
SUBSTRATE_VOLATILE = frozenset({
    "config/reference.php",
    f"{BENCH_DIR}/services_item.yml",
    f"{BENCH_DIR}/item.feature",
    f"{BENCH_DIR}/run_record.jsonl",
    f"{BENCH_DIR}/solution_index.json",
})

#: The same three lists for a python+behave project (plan decision D3).
#:
#: DATA, not code: the two constant sets above are CoreShop's answer to "what
#: must not change while the benchmark runs", and a second stack needs its own
#: answer, not a second implementation.  What is recorded in the manifest is
#: what is checked, so a stack that forgets to record its roots verifies
#: nothing rather than verifying the wrong tree.
#:
#: `features/steps/test_files` IS a root, and that is the whole reason this
#: tuple is not simply `("src",)`.  The 53 fixtures are retained test DATA
#: sitting inside removable territory; a step definition executes as the
#: harness's own user with the repository writable, so a solution that
#: rewrites `doc-default.docx` has changed what every scenario asserts ABOUT.
#: That is answer-space tampering, and it must abort the sweep rather than
#: pass it.
#:
#: `features/environment.py` is a FILE root rather than a directory: the rest
#: of `features/` is production `.feature` text and the per-item scratch
#: directory the retained hook creates, and hashing a directory that is
#: written to by design would abort every second item.
BEHAVE_SUBSTRATE_ROOTS = ("src", "features/environment.py",
                          "features/steps/test_files", BENCH_DIR,
                          "pyproject.toml")

#: Only one, because a behave run has only one harness-owned output: the
#: recorder's record file.  The synthesised feature lives at
#: `features/_bench_item.feature`, which is under no root above and therefore
#: needs no exemption.
BEHAVE_SUBSTRATE_VOLATILE = frozenset({f"{BENCH_DIR}/run_record.jsonl"})

#: Where CPython drops compiled bytecode in a behave checkout.
#:
#: `src` is the one that matters: `PYTHONPATH=src` + `import docx` writes
#: `src/docx/__pycache__/*.pyc`, which is a file ADDED inside a substrate
#: root, which aborts the next item as tampering — a benchmark that stops
#: itself the first time it runs.  `features` is here as well because bytecode
#: outliving the module it was compiled from is a whole class of
#: stale-import bug and the tree is small enough that sweeping it is free.
#:
#: `_bench` is here for the FUTURE, not for today's tree: it is a substrate
#: root, so bytecode written under it aborts the sweep exactly like bytecode
#: under `src`, and the harness owns that directory — the moment S4 puts an
#: importable `.py` there, an unswept root would be a tampering abort with no
#: sweep behind it and nothing that noticed.  Sweeping a directory that holds
#: no python costs one `find` over a handful of files.  The invariant in the
#: selftest is what keeps the two tuples from drifting apart again.
BEHAVE_BYTECODE_ROOTS = ("src", "features", BENCH_DIR)

#: The directory CPython writes it into, and the suffixes it writes.
BYTECODE_DIR = "__pycache__"
BYTECODE_SUFFIXES = (".pyc", ".pyo")

#: The same three lists again, for a java+cucumber project (Java corpus D1).
#:
#: DATA for the third time, and the shape is the argument: each stack answers
#: "what must not change while the benchmark runs" for its own tree, and the
#: manifest records the answer so that a run verifies the tree it was taken
#: over rather than some other project's idea of one.
#:
#: Four roots and one file, and each is here for a different reason:
#:
#: * `src/main` is the checker under test.  Production, never touched.
#: * `src/test/java` holds BOTH the retained substrate and the JUnit-only tree
#:   that falls through to production.  `substrate_digests` skips whatever the
#:   boundary calls removable, so naming the directory hashes exactly the
#:   seven retained sources plus the fifteen production ones -- which is what
#:   owner ruling R1.5 means operationally when it says the evidence must bind
#:   `ParameterTypes.java`'s exact retained bytes.
#: * `src/test/resources` is the reason this is not simply `("src",)`.  It
#:   holds the 49 `.feature` criteria AND 3096 retained fixture files, and a
#:   step body runs as the harness's own user with the repository writable.
#:   A solution that rewrites `epub3/05-package-document/files/*.opf` has
#:   changed what every scenario asserts ABOUT; that is answer-space
#:   tampering and it must abort the sweep rather than pass it.
#: * `pom.xml` is a FILE root: it decides the classpath every scenario
#:   compiles against, so a solution that adds a dependency there has changed
#:   the environment rather than written a test.
CUCUMBER_SUBSTRATE_ROOTS = ("src/main", "src/test/java", "src/test/resources",
                            "pom.xml", BENCH_DIR)

#: Two, and J5 wrote the second one when the code that writes it landed.
#:
#: * the record file, for the same reason behave has one -- it is where the
#:   per-item scoring evidence lands inside a hashed root.  This stack's copy
#:   is written by the HARNESS after folding cucumber's own JSON rather than
#:   by a recorder inside the container (`stacks/cucumber.py:_write_records`),
#:   which changes who writes it and not whether it changes per item.
#: * the synthesised item feature.  Cucumber's runner takes
#:   `features = "classpath:"`, so the one scenario under measurement has to
#:   land somewhere Maven puts on the classpath, and that is
#:   `src/test/resources` -- inside a root.  D1 deliberately left this line
#:   naming only the record file, because naming a file no code writes yet
#:   would be an exemption with nothing behind it, and an exemption is
#:   exactly the thing that must not be granted speculatively: it is a hole
#:   in the tampering check.  `stacks.cucumber.FEATURE_REL` is that file, the
#:   selftest there checks the two constants are the same string, and the
#:   `target/test-classes` copy Maven makes of it needs no exemption at all
#:   (it is under a BUILD root, and under no substrate root).
CUCUMBER_SUBSTRATE_VOLATILE = frozenset({
    f"{BENCH_DIR}/run_record.jsonl",
    "src/test/resources/_bench_item.feature",
})

#: Maven's build output, purged from a candidate-visible workspace.
#:
#: This is NOT the bytecode sweep's problem wearing a JVM hat.  `target/` sits
#: under no substrate root, so nothing in it would ever abort an item; it is
#: purged because it is a copy of the ANSWER, in the same class as the `.git`
#: directory `sanitise_repo` moves into gold.  A tree built before the strip
#: leaves `target/test-classes/org/w3c/epubcheck/test/AssertionSteps.class`
#: on disk, and a decompiler turns that back into the step definitions the
#: candidate was asked to write -- patterns, parameter types and all.
#:
#: The whole directory goes, not the `.class` files in it.  A `.class`-only
#: sweep would leave `*.jar`, `surefire-reports/` (whose stack traces name
#: every gold step that ran) and `generated-test-sources/`, and each of those
#: is the same leak in another format.  Maven regenerates all of it from
#: source, so there is nothing in `target/` that is an input.
CUCUMBER_BUILD_ROOTS = ("target",)

# Kapua is a reactor: each measured module's source/POM is substrate and
# each module's target is generated output. Existing projects keep the
# original single-module constants above.
CUCUMBER_SUBSTRATE_ROOTS_BY_PROJECT = {
    "kapua": _kapua.SUBSTRATE_ROOTS + (BENCH_DIR,),
}
CUCUMBER_SUBSTRATE_VOLATILE_BY_PROJECT = {
    "kapua": frozenset(_kapua.FEATURE_PATHS + (f"{BENCH_DIR}/run_record.jsonl",)),
}
CUCUMBER_BUILD_ROOTS_BY_PROJECT = {"kapua": _kapua.BUILD_ROOTS}

#: Go compiles in the worker's disposable /r2t-go/run/work copy. Original
#: sources, retained tests, embed resources and module inputs stay protected;
#: only the exported record is mutable here. No build output belongs in /work.
GO_SUBSTRATE_ROOTS = (
    "cmd", "internal", "external", "features", "go.mod", "go.sum", BENCH_DIR,
)
GO_SUBSTRATE_VOLATILE = frozenset({f"{BENCH_DIR}/run_record.jsonl"})
GO_BYTECODE_ROOTS = ()
GO_BUILD_ROOTS = ()


#: CoreShop's PSR-4 roots: namespace prefix -> the directory it maps to.
#:
#: A PAIR LIST rather than a dict because it is a value of a FROZEN row, and
#: because the mapping is prefix -> DIRECTORY rather than prefix -> namespace:
#: Sylius wires
#: `Sylius\Abstraction\StateMachine\` to `.../StateMachine/src/`, whose
#: directory does not mirror the namespace at all.
CORESHOP_PSR4 = (("CoreShop\\Behat\\", "src/CoreShop/Behat/"),
                 ("CoreShop\\Bundle\\", "src/CoreShop/Bundle/"),
                 ("CoreShop\\Component\\", "src/CoreShop/Component/"))


@dataclass(frozen=True)
class BehatProject:
    """Per-project facts of the Behat stack, as DATA.

    Every default is CoreShop's constant, verbatim, so a boundary that
    declares no ``behat:`` block gets exactly today's behaviour -- and a
    CoreShop invocation does not even read a new key.  A second Behat
    project (Sylius) adds a ROW; nothing in the shared logic is rewritten.

    The fields are grouped the way the consumers read them: where the
    wiring lives, what the strip rewrites, what the index covers, what the
    synthesised Behat profile says, what the substrate guard hashes, how a
    suite is chosen, where a stub is written, and how a worker names its
    database.
    """

    # -- where the Behat wiring lives ------------------------------------
    config_dir: str = "src/CoreShop/Behat/Resources/config"
    config_format: str = "yaml"              # "yaml" | "php"
    #: None for a project with NO Behat Symfony wiring: PrestaShop names
    #: its contexts by class in the suite file and Behat constructs them,
    #: so there is no services file to read -- nothing to re-emit after
    #: removal, no alias table to derive from, and no container to ask what
    #: it can autowire.  Each of those steps is then SKIPPED rather than
    #: pointed at an invented path.
    services_entry: Optional[str] = "services.yml"
    suites_entry: str = "suites.yml"
    #: Read only when `services_entry` is set and the format is YAML: it is
    #: the second half of what `retained_services_yaml` re-emits.
    hook_services: Optional[str] = "services/contexts/hook.yml"

    # -- what the strip rewrites -----------------------------------------
    #: These three are ONE fact -- which file imports the wiring the strip
    #: removes, and what that import becomes -- so they are all set or all
    #: None; `behat_project` refuses a half-declared trio.  All None is a
    #: project whose test configuration never imported the Behat wiring,
    #: and the strip then has no import to redirect.
    test_config: Optional[str] = TEST_CONFIG
    original_services_import: Optional[str] = ORIGINAL_SERVICES_IMPORT
    bench_services_import: Optional[str] = BENCH_SERVICES_IMPORT
    suite_root: str = "features/domain"
    recorder_rel: str = RECORDER_REL
    recorder_namespace: str = "CoreShop\\Behat\\Bench"
    #: `annotation` for a Behat 3 project, `attribute` for a Behat 4 one.
    #: Behat 4 deleted the annotation reader entirely -- of
    #: `Behat\Behat\Context\Annotation\` only `DocBlockHelper` is left, and
    #: `Hook\Context\Attribute\HookAttributeReader` is the only thing that
    #: turns a context method into a hook -- so on such a project the
    #: template's `/** @BeforeScenario */` is a comment.  Measured on a live
    #: Sylius pool (2026-09-09): Behat ran the scenario, printed `1 scenario
    #: (1 undefined) / 8 steps`, and the item scored `no_scenario_ran` off an
    #: empty record file.  `recorder_source` rewrites the five declarations
    #: for a row that says `attribute`; the TEMPLATE keeps the Behat 3
    #: spelling, because the CoreShop copy of it is bytes in CoreShop's seed.
    hook_style: str = "annotation"
    #: `directory` for a project whose vendored php-code-coverage still has
    #: `Filter::includeDirectory` (CoreShop: 10.1.16), `files` for one where
    #: it is gone (Sylius: 12.5.7, whose `Filter` has only `includeFile` and
    #: `includeFiles(array)`).  `recorder_source` then rewrites the one
    #: `includeDirectory` line into an enumeration of the `.php` files under
    #: `src/` plus `includeFiles($files)`; the TEMPLATE keeps the
    #: `includeDirectory` spelling, because the CoreShop copy of it is bytes
    #: in CoreShop's seed.
    #:
    #: This row exists because the recorder cannot report its own failure:
    #: `bootRecorder` wraps the filter construction in `catch (\Throwable)`,
    #: so on 12 the undefined-method `Error` becomes one line of stderr, the
    #: collector stays null, and with it `direct_calls` -- the trace is armed
    #: only when the collector exists.  Every row of the project would then
    #: carry null coverage and null `direct_calls`, which is two of T5's four
    #: gold checks failing for a reason no scored row records.
    coverage_filter: str = "directory"
    # Coverage denominator, trace call sites and accepted callees are distinct.
    coverage_roots: tuple = ("src",)
    trace_roots: tuple = ("src",)
    callee_roots: tuple = ("src",)
    #: Where the project's FRAMEWORK generates product classes, so a call
    #: into one is credited to the first-party contract method it implements
    #: instead of dropped (TARGET_INTERFACES_V2_SPEC §3.3, owner ruling
    #: V2-D1(a)).  CoreShop's Pimcore DataObjects live in `var/classes` and
    #: its Doctrine proxies in `var/cache`; the default IS that pair, because
    #: the template's literal is CoreShop's and its installed copy has to
    #: stay byte-identical to it.  A project whose framework generates
    #: nothing declares `[]` -- unlike the three roots above, an empty list
    #: here is a meaningful row, not a missing one.
    generated_roots: tuple = ("var/classes", "var/cache")
    psr4: tuple = CORESHOP_PSR4

    # -- what the index covers -------------------------------------------
    index_paths: tuple = ("src/CoreShop/Behat", "src/CoreShop/Bundle/TestBundle")
    index_guard: str = "src/CoreShop/Behat/Context/Domain"
    #: The project's production code, and the ONE row that says so: the
    #: production index is built over it and, since a second Behat project
    #: arrived, so is the mutation population (`mutation.exclusions_for_prod_paths`).
    #: The default is `data.mutation.CORESHOP_PROD_PATHS`, which is also where
    #: `EXCLUDED_PREFIXES` comes from -- one tuple, not two copies.
    prod_paths: tuple = CORESHOP_PROD_PATHS
    #: Path fragments INSIDE `prod_paths` whose mutants are not part of the
    #: mutation population: the unit tests, specs, migrations, DI/routing
    #: configuration and data fixtures a project ships beside its product
    #: code rather than in a tree of its own.
    #:
    #: OWNER RULING, 2026-09-11 (track S register §5): Sylius's population
    #: is product code only -- by KIND, so both spellings of each kind are
    #: written out.  Its three roots enumerate 43,670 mutants, of which
    #: 12,373 are product code; the rest are `tests/` (26,436),
    #: `Resources/config/` (2,551), `test/` (240), `Migrations/` (1,237),
    #: `Fixture/` (750), `Test/` (38), `Tests/` (30) and `config/` (15).
    #: The production boundary cannot separate them --
    #: it answers which files are the BEHAT GLUE, and none of these is glue
    #: -- so every one arrived classified `production`, the scored role
    #: excluded nothing, and `mutants validate` refused the mint by name
    #: ("boundary_scored role excludes no rows").
    #:
    #: Read by `mutation_attestation.derive_boundary_scored_manifest`, so
    #: what the row moves is the SCORED role: the raw catalogue still holds
    #: every mutant the engine produced under the roots, and its digest is
    #: what the materialisation audit binds.  CoreShop names none, and a
    #: project that names none is scored exactly as before -- the fragments
    #: are not consulted at all.  The matching rule is
    #: `data.mutation.is_population_excluded`.
    mutation_exclude: tuple = ()

    # -- what the synthesised Behat profile says -------------------------
    #: How the per-item profile is WRITTEN: "yaml" for a Behat 3 project,
    #: "php" for a Behat 4 one.  The document is the same either way -- one
    #: profile, one suite, the same contexts in the same order -- so this
    #: chooses a renderer, not a configuration.  It also chooses the file
    #: NAME (`bench_config`), because Behat 4 decides which loader to use
    #: from the extension alone.
    bench_config_format: str = "yaml"
    app_env: str = "test"
    kernel_path: str = "src/BehatKernel.php"
    kernel_class: str = "BehatKernel"
    bootstrap: Optional[str] = "behat-bootstrap.php"
    extensions: tuple = ("FriendsOfBehat\\SymfonyExtension",)
    #: Per-extension settings, as `(class name, settings mapping)` pairs in
    #: the boundary's order.  CoreShop declares none: its one extension's
    #: body is the kernel block the harness computes, and every other
    #: extension a project registers is bare (`Ext: null`, Behat's own
    #: spelling for "register it, no options").
    #:
    #: Sylius needs them because its RETAINED services reach Mink lazily.
    #: The FriendsOfBehat SymfonyExtension bundle registers `behat.mink`,
    #: `behat.mink.default_session` and `behat.mink.parameters` in the
    #: KERNEL container as lazy bridges that fetch `fob_symfony.mink*` out
    #: of the Behat container, and the Behat-side `fob_symfony.mink` alias
    #: exists only when `Behat\MinkExtension` is registered
    #: (`SymfonyExtension::registerMinkDriver`).  Retained Sylius services
    #: (`sylius.behat.cookie_setter`, `SessionManager`, the notification
    #: accessors, `CurrentPageResolver`) hold those bridges, so the first
    #: lazy resolution on an API path threw "You have requested a
    #: non-existent service `fob_symfony.mink`" -- scored `container_error`
    #: -> `di_unresolvable` on the live smoke.  Upstream never sees it
    #: because `behat.dist.php` loads the whole Mink stack globally.
    #:
    #: The keys are CLOSED against `extensions`: settings for an extension
    #: this project does not register would be dropped in silence, and a
    #: mistyped class name is exactly how that happens.
    extension_settings: tuple = ()
    #: The error-reporting mask Behat's call handler runs a step under,
    #: written as the PHP constant expression upstream writes -- or None,
    #: which emits nothing and leaves Behat on its own default.
    #:
    #: That default is `error_reporting()` as the process happens to have
    #: it (`Testwork\Call\ServiceContainer\CallExtension::configure`, in
    #: Behat 3 and 4 alike), which in the Sylius image is 32767 = `E_ALL`.
    #: `RuntimeCallHandler` then installs that level as an error handler
    #: around every step call, so a PHP diagnostic raised INSIDE an
    #: in-process kernel request becomes a `CallErrorException` the kernel
    #: returns as a 500 -- which an API scenario reads back as the response
    #: under test.  Measured on the Sylius first runs (2026-09-09, tag
    #: `onb-sprint-1-sylius-e`): `ApiPlatformClient::buildUpdateRequest`
    #: PUTs a fetched JSON-LD body back, symfony/var-exporter's
    #: `LazyGhostTrait` (line 240) writes `$@context` onto a Doctrine proxy,
    #: PHP raises `Creation of dynamic property
    #: Proxies\__CG__\...\Customer::$@context is deprecated`, and
    #: `RuntimeCallHandler.php:67` escalates it.  14 of the 19
    #: `closure_incomplete` items of `api_customer_account` died that way,
    #: and the same exception appears inside items that were ADMITTED (a
    #: passing admin taxon scenario in the worker logs) -- so a run without
    #: this row is contaminated rather than merely failing.
    #:
    #: Upstream masks the two deprecation levels (`behat.dist.php:36-37`);
    #: a project that says nothing keeps today's behaviour exactly, CoreShop
    #: included.
    tester_error_reporting: Optional[str] = None
    cache_dir: str = "var/cache/test"
    container_prefix: str = "BehatKernel"

    # -- what the substrate guard hashes ---------------------------------
    substrate_roots: tuple = SUBSTRATE_ROOTS
    substrate_volatile: frozenset = SUBSTRATE_VOLATILE

    # -- how a suite is chosen -------------------------------------------
    #: True when the arm's suites partition the corpus by tags, so the
    #: contexts an item runs under are ITS suite's rather than every
    #: suite's.  CoreShop synthesises one suite for every item and says so
    #: with False.
    suite_scoped: bool = False
    #: Which suite files are the ARM's, as repo-relative prefixes read the
    #: way boundary rules are read: a trailing `/` is a directory, anything
    #: else is that path or something under it.
    #:
    #: None is the reading that came before, and CoreShop's: an arm suite
    #: is any suite whose own config file is REMOVABLE.  On Sylius that
    #: also catches the HYBRID suites, whose config is removable only
    #: because their DI names removable Api contexts -- and one item
    #: (`continuing_cart_processing_from_ui_in_api.feature`) was then
    #: attributed to `hybrid_shopping_cart` rather than falling outside the
    #: API arm.  Naming the arm's own suite directory says which is which.
    arm_suite_prefixes: Optional[tuple] = None

    # -- where a stub context is written ---------------------------------
    stub_namespace: str = "CoreShop\\Behat\\Context\\Domain"
    stub_dir: str = "src/CoreShop/Behat/Context/Domain"

    # -- how a worker names its database ---------------------------------
    db_dsn_env: str = "PIMCORE_TEST_DB_DSN"
    db_dsn_suffix: str = ""
    #: Pimcore's installer reads four `PIMCORE_INSTALL_MYSQL_*` variables
    #: beside the DSN; Sylius reads the DSN alone.
    db_install_vars: bool = True
    # Synchronous initialization before worker binding/attestation.
    worker_init: Optional[str] = None

    # -- how the per-execution reset is written and observed -------------
    #: Which reset PROGRAM `worker reset-probe` runs.  A program, not a set
    #: of names: what a per-scenario purge IS differs by stack, so the
    #: marker context's body and the admin SQL differ with it.  `pimcore`
    #: writes a DataObject, a materialised class definition and a
    #: `versions` row; `doctrine` writes one row into a mapped table --
    #: which is what `ORMPurger::purge()` empties -- and one into the
    #: Doctrine Migrations version table, which is not a mapped entity and
    #: so outside its reach.  `worker.RESET_PROGRAMS` is the closed set,
    #: and a name outside it is refused there rather than defaulted.
    reset_program: str = "pimcore"
    #: Where the marker context is installed.  Inside `stub_dir`, so it is
    #: written by `install_solution` and swept by `clean_workspace` exactly
    #: as a candidate's context is -- the legs must travel the path a pair
    #: travels, not a shortcut around it.
    reset_context_rel: str = \
        "src/CoreShop/Behat/Context/R2tResetProbeContext.php"
    #: The table the per-scenario purge does NOT touch: the probe's own
    #: control, and the one durable marker the cleanup has to remove.
    reset_control_table: str = "versions"
    #: A table the purge DOES empty: the marker whose absence in leg B is
    #: the reset, and whose presence there is state crossing the boundary.
    reset_marker_table: str = "objects"
    #: The table name -- or the PAIR of names -- `db_probe_php` writes into
    #: its cross-schema denial checks.  CoreShop's probe reads `objects` in
    #: three of the four checks and `users` in the plain SELECT, so a pool
    #: where exactly one of the two is reachable is still caught; a project
    #: that names one table uses that name for both.  A denial is a denial
    #: either way -- MySQL refuses on privilege before it resolves a table
    #: name -- so what this decides is what a BROKEN pool's operator is
    #: told: a name that does not exist there answers 1146 rather than
    #: 1044, which reads as `denials_without_a_permission_error` and names
    #: a cause that is not the one.
    probe_table: tuple = ("objects", "users")

    @property
    def bench_config(self) -> str:
        """The per-item Behat configuration file, named by its format."""
        return BENCH_CONFIG_NAMES[self.bench_config_format]


#: The defaults, named.  `behat_project` returns exactly this object for a
#: boundary with no `behat:` block.
CORESHOP_BEHAT = BehatProject()

#: Why a list row refuses a scalar.  `tuple("src/Sylius/Component")` is a
#: tuple of twenty-two CHARACTERS, not a one-element path list, and no
#: reader of these rows can tell the two apart: every one of them treats
#: "matched nothing" as a legitimate answer for a project that named
#: nothing.  `mutants build` derives its whole mutation population from
#: `prod_paths`, so a scalar there is a population of zero -- reported as a
#: project with no mutable code rather than as a boundary nobody can read.
_NOT_A_LIST = (
    "A scalar is not a one-element list: it is read character by character, "
    "and a row of characters matches no path and no class name anywhere -- "
    "a mutation population of zero, a substrate that hashes nothing, an "
    "index over no file, none of which is an error further down. Write the "
    "single value as a list of one.")

#: ...and why the settings row refuses a list.  Same door: the value is
#: indexed by the names it carries, so the wrong shape is either silent or
#: a `TypeError` from inside a comprehension that names no boundary.
_NOT_A_MAPPING = (
    "The row is a mapping of extension class name to that extension's "
    "settings, kept in the boundary's order and checked against "
    "`extensions`; a list here is indexed by a class name and raises a bare "
    "TypeError naming neither the boundary nor the row.")

#: ...and why `~` is not "this project has none of these" either.  These
#: fields are not Optional, so nothing downstream reads None as a value:
#: written as null the row reaches every consumer as None and dies in
#: whichever one iterates or indexes it first, with a bare TypeError naming
#: neither the boundary nor the row.  The empty answer these rows have is
#: the empty list.
_NOT_WRITTEN = (
    "The row is not Optional: null reaches every reader of it as None "
    "rather than as an empty list, and the first one to iterate or index it "
    "raises a bare TypeError naming neither this boundary nor this row. A "
    "project that names nothing here writes the empty list.")


def _shaped(shape, build, written, harm):
    """One row's coercion, refusing the YAML shape it cannot read.

    The rows that use this are read as SETS -- of paths, of class names --
    and an empty set is a legitimate answer everywhere they are read, so a
    row written in the wrong shape is caught nowhere downstream.  Refused
    here by name, the way the closed-key and closed-value rows are.

    `probe_table` is deliberately NOT one of these: it takes one name or a
    list of them, and says so.  Neither is `psr4`, for the same kind of
    reason: its accepted shape is a mapping OR a list of pairs, which is a
    second rule and not this one.
    """
    def coerce(value, row, project):
        if value is None:
            raise SystemExit(
                f"REFUSED: the `behat:` block of the {project} boundary "
                f"declares `{row}` as null, which is not a value this row "
                f"can carry. {_NOT_WRITTEN}")
        if not isinstance(value, shape):
            raise SystemExit(
                f"REFUSED: the `behat:` block of the {project} boundary "
                f"declares `{row}: {value!r}`, which is a "
                f"{type(value).__name__} rather than {written}. {harm}")
        return build(value)
    return coerce


#: The five path/name rows, which are one coercion because they are one
#: shape: a YAML list of strings, carried as the tuple the field declares.
_PATH_LIST = _shaped(list, tuple, "a YAML list", _NOT_A_LIST)


def _mutation_exclude_row(value, row, project):
    """`mutation_exclude`: the one list row whose ELEMENTS are checked too.

    Its strings are path FRAGMENTS -- runs of directory segments matched
    under the production roots -- and a fragment naming no segment is not
    "a fragment that matches nothing" but a zero-length run, which is a
    subsequence of every path.  Written by accident (`- ""`, `- "/"`, a
    stray `-` that YAML reads as null inside the list), it would take the
    WHOLE population out of the scored role, and a population of zero is a
    number that validates: `mutants build` would report it, the mint would
    refuse for the count rather than the cause, and nothing would name this
    row.  `is_population_excluded` skips such a fragment for a direct
    caller; a boundary is refused here by name instead.
    """
    fragments = _PATH_LIST(value, row, project)
    empty = [item for item in fragments
             if not isinstance(item, str)
             or not [part for part in item.split("/") if part]]
    if empty:
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {project} boundary declares "
            f"`{row}` with {empty!r} in it, which names no directory "
            f"segment. A fragment is a run of directory segments matched "
            f"under the production roots, and an empty run is a subsequence "
            f"of every path -- the row would take the whole mutation "
            f"population out of the scored role rather than one subtree of "
            f"it.")
    return fragments


def _null_kept(coerce):
    """A row where `row: ~` is carried through as None rather than shaped.

    `arm_suite_prefixes` because its FIELD is declared Optional and its
    None is a reading: an arm suite is any suite whose own config file is
    removable.  `psr4` and `probe_table` because their accepted shapes are
    each a second rule -- a mapping or a list of pairs, one name or a list
    of them -- and neither is settled here.  Every other coerced row is a
    non-Optional field, so null there is refused where the row is read.
    """
    def keep(value, row, project):
        return None if value is None else coerce(value, row, project)
    return keep


#: Row name -> how the YAML value becomes the field value, called with the
#: row name and the project so a wrong shape -- null included -- is refused
#: by name.  A field absent here is taken as-is (every one of those is a
#: string or a bool, and several of them are legitimately null).
_BEHAT_COERCE = {
    "psr4": _null_kept(lambda v, row, project: tuple((k, v[k]) for k in v)
                       if isinstance(v, dict)
                       else tuple(tuple(pair) for pair in v)),
    "index_paths": _PATH_LIST,
    "coverage_roots": _PATH_LIST,
    "trace_roots": _PATH_LIST,
    "callee_roots": _PATH_LIST,
    "generated_roots": _PATH_LIST,
    # The one Optional field of the six list rows: `~` is its default
    # reading, not a row nobody wrote.
    "arm_suite_prefixes": _null_kept(_PATH_LIST),
    "prod_paths": _PATH_LIST,
    # Shape AND elements: an empty fragment matches every path, so it is
    # not a row that excludes nothing but one that excludes everything.
    "mutation_exclude": _mutation_exclude_row,
    "extensions": _PATH_LIST,
    # A mapping of class name -> settings, kept in the boundary's order the
    # way `psr4` is: the settings themselves stay the nested
    # strings/bools/ints/lists/mappings both renderers already understand.
    "extension_settings": _shaped(dict, lambda v: tuple((k, v[k]) for k in v),
                                  "a YAML mapping", _NOT_A_MAPPING),
    "substrate_roots": _PATH_LIST,
    # The same list, built into the frozenset this field is declared as: a
    # scalar here would be a set of single CHARACTERS, and the substrate
    # guard would then treat every real volatile path as tampering.
    "substrate_volatile": _shaped(list, frozenset, "a YAML list",
                                  _NOT_A_LIST),
    # One name or a list of them.  A boundary that names one table writes
    # it as the scalar it is, rather than as a one-element list whose shape
    # only exists because CoreShop happens to use two names.
    "probe_table": _null_kept(lambda v, row, project: (v,)
                              if isinstance(v, str) else tuple(v)),
}

_BEHAT_FIELDS = tuple(f.name for f in _dataclass_fields(BehatProject))


def behat_project(boundary) -> BehatProject:
    """The boundary's `behat:` block over CoreShop's defaults.

    A missing block IS CoreShop's, so no CoreShop code path reads a new
    key.  The block is CLOSED: an unknown key is refused rather than
    ignored, because a typo there is a row that silently keeps the wrong
    default -- the same reason `profile.runtime` refuses one.
    """
    block = (getattr(boundary, "raw", None) or {}).get("behat") or {}
    if not isinstance(block, dict):
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {boundary.project} boundary "
            f"is a {type(block).__name__}, not a mapping of row name to value.")
    unknown = sorted(set(block) - set(_BEHAT_FIELDS))
    if unknown:
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {boundary.project} boundary "
            f"names {unknown}, which is not a row of BehatProject. The rows "
            f"are {list(_BEHAT_FIELDS)}.")
    if not block:
        # THE object, not an equal copy: `harness.behat is CORESHOP_BEHAT` is
        # the cheapest statement of "a CoreShop invocation did not read a
        # new key".
        return CORESHOP_BEHAT
    values = {}
    for key, value in block.items():
        # A null goes to the coercion too: for all but the three rows that
        # keep it, the field is not Optional and `row: ~` is a value no
        # reader of it can carry.
        coerce = _BEHAT_COERCE.get(key)
        values[key] = coerce(value, key, boundary.project) \
            if coerce is not None else value
    row = replace(CORESHOP_BEHAT, **values)
    # The import trio is one fact in three fields.  A row that says "this
    # project has no test config to patch" while still carrying CoreShop's
    # two import strings would strip cleanly and then be read by a strip
    # that patches nothing with a resource nobody wrote -- so the trio is
    # all-or-nothing, and the refusal names which side is missing.
    trio = {name: getattr(row, name)
            for name in ("test_config", "original_services_import",
                         "bench_services_import")}
    unset = sorted(k for k, v in trio.items() if v is None)
    if unset and len(unset) != len(trio):
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {boundary.project} boundary "
            f"declares {unset} as null and {sorted(set(trio) - set(unset))} "
            f"as a value. They are one fact -- which file imports the wiring "
            f"the strip removes, and what that import becomes -- and half of "
            f"it would leave the strip redirecting an import it cannot name.")
    if row.bench_config_format not in BENCH_CONFIG_NAMES:
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {boundary.project} boundary "
            f"declares `bench_config_format: {row.bench_config_format!r}`, "
            f"which is not one of {sorted(BENCH_CONFIG_NAMES)}. The format "
            f"picks the file NAME too, and Behat decides which loader to use "
            f"from that name alone -- so an unknown one is a per-item profile "
            f"no Behat would read, not a default.")
    if row.hook_style not in HOOK_STYLES:
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {boundary.project} boundary "
            f"declares `hook_style: {row.hook_style!r}`, which is not one of "
            f"{list(HOOK_STYLES)}. An unknown style would leave the recorder "
            f"spelled for a Behat that cannot read it, and a recorder whose "
            f"hooks never fire scores every item `no_scenario_ran`.")
    if row.coverage_filter not in COVERAGE_FILTERS:
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {boundary.project} boundary "
            f"declares `coverage_filter: {row.coverage_filter!r}`, which is "
            f"not one of {list(COVERAGE_FILTERS)}. The recorder catches every "
            f"Throwable around the filter it builds, so a call the vendored "
            f"php-code-coverage does not have becomes one line of stderr and "
            f"a run with null coverage and null `direct_calls` on every row.")
    if row.worker_init not in (None, "prestashop"):
        raise SystemExit(f"REFUSED: unknown worker_init {row.worker_init!r}")
    for name in ("coverage_roots", "trace_roots", "callee_roots"):
        if not getattr(row, name):
            raise SystemExit(f"REFUSED: {name} must name a production/call-site root")
    if row.tester_error_reporting is not None:
        # Read for the refusal, not for the value: the PHP rendering spells
        # the constants and lets PHP add them up.  A boundary is the last
        # place the expression can be refused cheaply -- after this it is a
        # profile a container fails to load.
        error_reporting_int(row.tester_error_reporting, boundary.project)
    stray = sorted(name for name, _ in row.extension_settings
                   if name not in row.extensions)
    if stray:
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {boundary.project} boundary "
            f"gives `extension_settings` for {stray}, which it does not "
            f"register in `extensions`. Those settings would be dropped in "
            f"silence -- name the extension exactly as `extensions` spells "
            f"it, or register it.")
    # `probe_table` is INDEXED, not iterated: `dbadmin.db_probe_php` writes
    # `names[0]` into every cross-schema check.  An empty list coerces to
    # `()` and the renderer raises IndexError from inside the script builder,
    # naming neither the boundary nor the row.  Refused here by name, the way
    # `worker.reset_program_for` refuses a program it does not know.
    if not row.probe_table:
        raise SystemExit(
            f"REFUSED: the `behat:` block of the {boundary.project} boundary "
            f"declares an empty `probe_table`. The §3.2 probe names a table "
            f"in every one of its cross-schema checks, so an empty row is a "
            f"probe that cannot be written rather than a probe with nothing "
            f"to check -- name the table a neighbour's schema holds, or the "
            f"pair of them.")
    return row


#: The recorder template's five hook declarations, and what each becomes for
#: a `hook_style: attribute` project.  The attribute classes are
#: `Behat\Hook\{BeforeSuite,BeforeScenario,BeforeStep,AfterStep,
#: AfterScenario}`, each `#[Attribute(TARGET_METHOD|IS_REPEATABLE)]` with one
#: optional `?string $filterString` -- so a bare `#[...]` is the whole
#: declaration, and a fully qualified name means no `use` line moves either.
#:
#: `bootRecorder` STAYS `public static`, because Behat requires it there: a
#: suite hook is dispatched against an `UninitializedContextEnvironment`,
#: whose `bindCallee` (inherited from `Testwork\Environment\StaticEnvironment`)
#: hands back the callable as it is, and for a non-static method
#: `ContextMethodCallableFactory` produces a `LateBoundContextMethodCallable`
#: whose `__invoke` throws "Cannot directly invoke ... it has not been bound
#: to a Context".  Every hook is called with the scope as its single argument
#: (`Testwork\Hook\Call\HookCall`), which the no-argument `bootRecorder`
#: ignores: extra arguments to a userland function are allowed, and Behat's
#: `Argument\Validator` checks only for MISSING ones.
_HOOK_ATTRIBUTES = (
    ("    /** @BeforeSuite */\n",
     "    #[\\Behat\\Hook\\BeforeSuite]\n"),
    ("    /** @BeforeScenario */\n",
     "    #[\\Behat\\Hook\\BeforeScenario]\n"),
    ("    /** @BeforeStep */\n",
     "    #[\\Behat\\Hook\\BeforeStep]\n"),
    # This one is a tag inside a prose docblock, and the docblock STAYS: it
    # is what `HookAttributeReader` reads the hook's description from, and
    # what it says (the 0/10/20/30/99 result codes) is why it was written.
    ("     *\n     * @AfterStep\n     */\n    public function stopStep(",
     "     */\n    #[\\Behat\\Hook\\AfterStep]\n"
     "    public function stopStep("),
    ("    /** @AfterScenario */\n",
     "    #[\\Behat\\Hook\\AfterScenario]\n"),
)


#: The template's one coverage-filter line, and what it becomes for a
#: `coverage_filter: files` project.  php-code-coverage 11 removed
#: `Filter::includeDirectory`, so on 12 the directory call is an undefined
#: method; `includeFiles(array $filenames)` is what is left, and the
#: enumeration it wants is exactly what php-file-iterator's
#: `Facade::getFilesAsArray(array|string $paths, array|string $suffixes = '',
#: ...): list<non-empty-string>` returns -- realpaths, unique and sorted
#: (php-file-iterator/src/Facade.php:30, version 6.0.2 as vendored by
#: phpunit/phpunit 12.5.35 and reachable through Composer's classmap).  The
#: name is written out in full rather than imported, for the reason the hook
#: attributes are: the template's `use` block stays where CoreShop's seed
#: has it.
_COVERAGE_FILTER_FILES = (
    "                $filter->includeDirectory(self::$root . '/src');\n",
    "                $files = (new \\SebastianBergmann\\FileIterator\\Facade)\n"
    "                    ->getFilesAsArray(self::$root . '/src', '.php');\n"
    "                $filter->includeFiles($files);\n",
)


def recorder_source(template: str, bp: BehatProject,
                    where: str = "BenchRecorderHook.php") -> str:
    """The recorder THIS project gets, rewritten from the one template.

    Three per-project rewrites, each driven by a row: the namespace, so the
    project's own `Behat\\` PSR-4 root autoloads the class; the hook style,
    so the project's Behat can see its hooks at all; and the coverage
    filter, so the collector it builds survives the vendored
    php-code-coverage.  Then the root rows, which move literals rather than
    declarations: the coverage roots, the trace call-site roots, the callee
    roots that decide what is first-party, and the roots under which this
    project's framework GENERATES product classes.  A project that declares
    none of them gets the
    template back unchanged -- which is what makes "the CoreShop copy IS the
    template" a statement a selftest can check without a container.

    Every substitution must apply EXACTLY once or the call is refused.  A
    hook rewrite that silently matched nothing is the failure this function
    exists to end: it costs a live run to notice, because Behat reports a
    plausible `1 scenario (1 undefined)` and the harness reads an empty
    record file.
    """
    src = template
    if bp.recorder_namespace != CORESHOP_BEHAT.recorder_namespace:
        # The recorder autoloads through the project's own `Behat\` PSR-4
        # root, so the one CoreShop literal in it is its namespace line.
        old_ns = f"namespace {CORESHOP_BEHAT.recorder_namespace};"
        if src.count(old_ns) != 1:
            raise SystemExit(
                f"REFUSED: {where} does not declare {old_ns!r} exactly once, "
                f"so the namespace this project needs cannot be substituted "
                f"into it.")
        src = src.replace(old_ns, f"namespace {bp.recorder_namespace};")
    if bp.hook_style == "attribute":
        for old, new in _HOOK_ATTRIBUTES:
            if src.count(old) != 1:
                raise SystemExit(
                    f"REFUSED: {where} does not carry {old!r} exactly once, "
                    f"so its hooks cannot be rewritten as the PHP attributes "
                    f"a Behat 4 project reads. A recorder whose hooks never "
                    f"fire records nothing, and every item then scores "
                    f"`no_scenario_ran`.")
            src = src.replace(old, new)
    if bp.coverage_filter == "files":
        old, new = _COVERAGE_FILTER_FILES
        if src.count(old) != 1:
            raise SystemExit(
                f"REFUSED: {where} does not carry {old!r} exactly once, so "
                f"its coverage filter cannot be rewritten for a "
                f"php-code-coverage that has no `includeDirectory`. The "
                f"recorder catches the undefined-method Error and continues "
                f"with no collector, so every row would be scored with null "
                f"coverage and null `direct_calls`.")
        src = src.replace(old, new)
    if bp.coverage_roots != ("src",):
        if bp.coverage_filter == "directory":
            old = _COVERAGE_FILTER_FILES[0]
            new = "".join(
                f"                $filter->includeDirectory(self::$root . {json.dumps('/' + p)});\n"
                for p in bp.coverage_roots)
        else:
            old = "->getFilesAsArray(self::$root . '/src', '.php');"
            roots = ", ".join("self::$root . " + json.dumps('/' + p)
                              for p in bp.coverage_roots)
            new = f"->getFilesAsArray([{roots}], '.php');"
        if src.count(old) != 1:
            raise SystemExit(f"REFUSED: {where} coverage root anchor changed")
        src = src.replace(old, new)
        old = ("        foreach (self::$cov->getData()->lineCoverage() as $file => $lines) {\n"
               "            if (strncmp($file, $src, strlen($src)) !== 0) {")
        tests = " && ".join(
            f"strncmp($file, self::$root . {json.dumps('/' + p.rstrip('/') + '/')}, "
            f"strlen(self::$root . {json.dumps('/' + p.rstrip('/') + '/')})) !== 0"
            for p in bp.coverage_roots)
        new = ("        foreach (self::$cov->getData()->lineCoverage() as $file => $lines) {\n"
               f"            if ({tests}) {{")
        if src.count(old) != 1:
            raise SystemExit(f"REFUSED: {where} coverage result root anchor changed")
        src = src.replace(old, new)
    if bp.trace_roots != ("src",):
        old = "[self::$root . '/src/']"
        roots = ", ".join("self::$root . " + json.dumps('/' + p.rstrip('/') + '/')
                          for p in bp.trace_roots)
        if src.count(old) != 1:
            raise SystemExit(f"REFUSED: {where} trace root anchor changed")
        src = src.replace(old, f"[{roots}]")
    if bp.callee_roots != ("src",):
        # One test, two readers: the fence that keeps a production callee and
        # the first-party test the generated-class credit applies to an
        # ancestor's declaring file.
        old = ("            return strncmp($file, $root . '/src/', "
               "strlen($root . '/src/')) === 0;")
        tests = " || ".join(
            f"strncmp($file, $root . {json.dumps('/' + p.rstrip('/') + '/')}, "
            f"strlen($root . {json.dumps('/' + p.rstrip('/') + '/')})) === 0"
            for p in bp.callee_roots)
        if src.count(old) != 1:
            raise SystemExit(f"REFUSED: {where} callee root anchor changed")
        src = src.replace(old, f"            return {tests};")
    if bp.generated_roots != CORESHOP_BEHAT.generated_roots:
        old = ("    private static array $generatedRoots = "
               "['var/classes', 'var/cache'];")
        roots = ", ".join(json.dumps(p.strip('/')) for p in bp.generated_roots)
        if src.count(old) != 1:
            raise SystemExit(
                f"REFUSED: {where} does not declare its generated roots "
                f"exactly once, so this project's cannot be substituted into "
                f"it. Left at CoreShop's, a call into a class THIS framework "
                f"generates is credited to a contract method the project does "
                f"not have, or dropped with no diagnostic that says why.")
        src = src.replace(
            old, f"    private static array $generatedRoots = [{roots}];")
    return src


# Ruby/Cucumber's e-petitions substrate (NEW_STACK_SPEC section 5). Narrow
# asset roots keep generated builds outside the integrity set. Boundary
# classification removes answer files from features, while retained helpers
# and fixture inputs stay hashed. Runtime dependencies are image-owned.
RUBY_SUBSTRATE_ROOTS = (
    "app/controllers", "app/helpers", "app/jobs", "app/lib", "app/mailers",
    "app/models", "app/presenters", "app/previews", "app/validators", "app/views",
    "app/assets/config", "app/assets/fonts", "app/assets/images",
    "app/assets/javascripts", "app/assets/stylesheets",
    "bin", "config", "data", "db", "features", "lib", "public",
    "spec/factories.rb", "spec/fixtures", "spec/support",
    "Gemfile", "Gemfile.lock", "package.json", "package-lock.json",
    "esbuild.mjs", "Rakefile", "config.ru", ".ruby-version",
    ".env", ".env.test", ".env.development", BENCH_DIR,
)
RUBY_SUBSTRATE_VOLATILE = frozenset({
    f"{BENCH_DIR}/run_record.jsonl", f"{BENCH_DIR}/item.feature",
})
#: Derived state: files the retained substrate REGENERATES from source that a
#: mutant can change, so the harness puts them back before every pair.
#:
#: `var/classes` holds Pimcore's generated DataObject classes, and two kinds
#: live there.  `Behat%` classes are created and purged per scenario by the
#: retained `PimcoreDaoContext::purgeClasses` hook.  The PRODUCTION classes
#: (`DataObject/CoreShopProduct.php`, its `Listing.php`,
#: `definition_CoreShopProduct.php`, ...) come from the seed and are
#: regenerated IN PLACE whenever a retained step re-saves a class
#: (`TestBundle` `Setup\ClassContext` -> `ClassUpdate::save`).  Each getter's
#: return type comes from CoreShop's own `CoreExtension` data types, which are
#: under mutation, so a pair run under a mutant can write a class file that
#: kills every later PHP process on autoload ("Declaration of ...::
#: getUnitDefinitions() must be compatible with ...").  Nothing hashed it
#: (`var/` is under no substrate root), nothing reset it (the purge is
#: `Behat%` only), and the mutant revert restores only the mutated source
#: file.  That lost 16,788 CoreShop full-gold pairs to one absorbing
#: `solution_error` state.
#:
#: So `restore_derived_state` puts every SEED member under these roots back
#: to its seed bytes before every pair.  Files ADDED under a root are left
#: alone: they are the `Behat%` classes the purge owns, and deleting them from
#: under it would orphan their `classes` rows.
#:
#: Only Pimcore's reset program regenerates these seeded class definitions.
#: Other Behat projects share the harness, not Pimcore's derived-state policy.
#: python-docx and Algorand likewise declare no derived-state restore.
DERIVED_STATE_ROOTS = ("var/classes",)
BEHAVE_DERIVED_STATE_ROOTS: tuple = ()
CUCUMBER_DERIVED_STATE_ROOTS: tuple = ()
# Ruby's reset helper clears generated assets/cache and truncates its private
# database before every pair. It has no seeded generated classes to restore.
RUBY_DERIVED_STATE_ROOTS: tuple = ()
# Go prepares and retires a disposable execution copy for each attempt. Its
# build cache and temporary files live outside the sealed workspace; there
# are no seeded generated files to restore in the original workspace.
GODOG_DERIVED_STATE_ROOTS: tuple = ()

#: Keyed by the profile's `framework:`, and closed like
#: `seed.RULES_BY_FRAMEWORK`: a stack nobody answered for gets a refusal, not
#: CoreShop's answer.
_DERIVED_STATE_ROOTS_BY_FRAMEWORK = {
    "behave": BEHAVE_DERIVED_STATE_ROOTS,
    "cucumber": CUCUMBER_DERIVED_STATE_ROOTS,
    "cucumber_ruby": RUBY_DERIVED_STATE_ROOTS,
    "godog": GODOG_DERIVED_STATE_ROOTS,
}
_DERIVED_STATE_ROOTS_BY_RESET_PROGRAM = {
    "pimcore": DERIVED_STATE_ROOTS,
    "doctrine": (),
    "prestashop": (),
}

#: The mode a restored member gets: what `seed.unpack_workspace` gives every
#: seed member of these roots (0644 or 0666 in the tar, minus peer write).
DERIVED_STATE_FILE_MODE = 0o644

#: Host-owned staging for the in-container fallback.  Under `var/`, so under
#: no substrate root, and removed after every use.
DERIVED_STATE_STAGING = "var/bench_derived_restore"


def derived_state_roots(framework: str, *,
                        behat: Optional[BehatProject] = None) -> tuple:
    """The selected project's derived-state roots, not Behat-wide defaults."""
    if framework == "behat":
        if behat is None:
            raise ValueError("REFUSED: Behat derived-state policy requires the project's Behat row")
        try:
            return _DERIVED_STATE_ROOTS_BY_RESET_PROGRAM[behat.reset_program]
        except KeyError:
            raise ValueError(
                f"REFUSED: no derived-state policy for reset program {behat.reset_program!r}") from None
    try:
        return _DERIVED_STATE_ROOTS_BY_FRAMEWORK[framework]
    except KeyError:
        raise ValueError(
            f"REFUSED: no derived-state policy for framework {framework!r}; "
            f"the known ones are {sorted(['behat', *_DERIVED_STATE_ROOTS_BY_FRAMEWORK])}."
        ) from None


class SubstrateTampered(RuntimeError):
    """Raised when the tree under measurement no longer matches its baseline.

    This aborts rather than warns.  Every number produced after the substrate
    changed is unfalsifiable — the run could have been scored by a replaced
    recorder, or against production code the previous item edited — and a
    sweep that continues past this point produces results that cannot be
    distinguished from valid ones later.
    """

    def __init__(self, report: dict):
        self.report = report
        parts = []
        for key in ("changed", "missing", "added"):
            if report.get(key):
                shown = ", ".join(report[key][:6])
                more = (f" (+{len(report[key]) - 6} more)"
                        if len(report[key]) > 6 else "")
                parts.append(f"{key}: {shown}{more}")
        super().__init__(
            "the repository under measurement no longer matches the digests "
            "recorded for it — " + "; ".join(parts)
            + ". The sweep is aborted because results produced after this "
              "point cannot be trusted. Investigate, restore the tree, then "
              "re-baseline with `python3 -m r2t.cli manifest-baseline`.")


class DerivedStateUnrestored(RuntimeError):
    """Derived state that is not, and could not be put back to, seed bytes.

    Raised rather than warned for `SubstrateTampered`'s reason: every pair
    after this point would run against a class file some earlier pair
    generated, which is the absorbing state the restore exists to prevent.
    """

    def __init__(self, paths: list, why: str):
        self.paths = list(paths)
        shown = ", ".join(self.paths[:6])
        more = (f" (+{len(self.paths) - 6} more)"
                if len(self.paths) > 6 else "")
        super().__init__(
            f"REFUSED: {why}: {shown}{more}. This worker must be "
            f"reprovisioned.")


@dataclass
class StripManifest:
    repo_root: str
    gold_root: str
    moved: list[str] = field(default_factory=list)
    moved_config: list[str] = field(default_factory=list)
    patched: list[str] = field(default_factory=list)
    installed: list[str] = field(default_factory=list)
    boundary_version: int = 0
    #: rel path -> sha256 for every retained/production file (see
    #: SUBSTRATE_ROOTS).  Empty on a manifest written before this existed,
    #: in which case verification is skipped and says so.
    digests: dict[str, str] = field(default_factory=dict)
    #: WHICH tree the digests above cover, recorded by the strip that took
    #: them (plan decision D1, the data half).  Empty means "written before
    #: this existed", and the CoreShop constants are then used — every
    #: archived manifest on disk is exactly that case and verifies today
    #: byte-for-byte as it always has.
    #:
    #: Recorded rather than derived because the alternative is a second stack
    #: silently inheriting the first one's idea of what must not change:
    #: `substrate_digests` would walk `vendor/behat` in a python checkout,
    #: find nothing, hash nothing, and report a clean substrate for a tree it
    #: never looked at.
    substrate_roots: list[str] = field(default_factory=list)
    #: Files inside those roots that change by design without being substrate
    #: input, on the same "empty means CoreShop's" rule.
    substrate_volatile: list[str] = field(default_factory=list)
    #: Where compiled bytecode is swept from between items.  Empty for a PHP
    #: tree, and empty is the honest answer there rather than a gap: there is
    #: no bytecode to purge, and walking 84,000 files per item to prove it is
    #: a cost with nothing on the other side.
    bytecode_roots: list[str] = field(default_factory=list)
    #: Build-output directories deleted at strip time because they are copies
    #: of the answer (`CUCUMBER_BUILD_ROOTS`).  Empty for PHP and Python,
    #: which compile nothing ahead of time, and empty is again the honest
    #: answer rather than a gap.
    build_roots: list[str] = field(default_factory=list)
    # PrestaShop only: seed resource metadata, with bytes beside protected gold.
    prestashop_resources: Optional[dict] = None

    def roots(self) -> tuple:
        """The substrate roots this manifest's digests were taken over."""
        return tuple(self.substrate_roots) or SUBSTRATE_ROOTS

    def volatile(self) -> frozenset:
        """The per-item files inside those roots that are exempt."""
        return (frozenset(self.substrate_volatile) if self.substrate_volatile
                else SUBSTRATE_VOLATILE)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "repo_root": self.repo_root, "gold_root": self.gold_root,
                "moved": self.moved, "moved_config": self.moved_config,
                "patched": self.patched, "installed": self.installed,
                "boundary_version": self.boundary_version,
                "digests": self.digests,
                "substrate_roots": self.substrate_roots,
                "substrate_volatile": self.substrate_volatile,
                "bytecode_roots": self.bytecode_roots,
                "build_roots": self.build_roots,
                **({"prestashop_resources": self.prestashop_resources}
                   if self.prestashop_resources is not None else {}),
            }, fh, indent=1, sort_keys=True)


def _iter_files(root: str, rel_prefix: str):
    abs_prefix = os.path.join(root, rel_prefix)
    if os.path.isfile(abs_prefix):
        yield rel_prefix
        return
    if not os.path.isdir(abs_prefix):
        return
    for dirpath, dirnames, files in os.walk(abs_prefix):
        dirnames[:] = sorted(dirnames)
        for f in sorted(files):
            full = os.path.join(dirpath, f)
            yield os.path.relpath(full, root).replace(os.sep, "/")


def _move(repo_root: str, gold_root: str, rel: str) -> None:
    src = os.path.join(repo_root, rel)
    dst = os.path.join(gold_root, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.move(src, dst)


def _prune_empty_dirs(root: str, rel_prefix: str) -> None:
    base = os.path.join(root, rel_prefix)
    if not os.path.isdir(base):
        return
    for dirpath, dirnames, files in os.walk(base, topdown=False):
        if not os.listdir(dirpath):
            os.rmdir(dirpath)


def retained_services_yaml(original_services_path: str,
                           hook_contexts_path: str,
                           boundary: Boundary) -> str:
    """Re-emit the parts of the removed services file that are substrate.

    The removed file is not only a service list: it also carries extension
    configuration (`payum.gateways`, `core_shop_address`,
    `core_shop_resource.mapping.paths`) that the retained code depends on.
    Dropping it silently would make retained Pimcore model stubs
    unregistered and the `offline` payment gateway absent — failures that
    look like generation failures.
    """
    with open(original_services_path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    with open(hook_contexts_path, encoding="utf-8") as fh:
        hooks = yaml.safe_load(fh) or {}

    out: dict = {}
    for key, value in doc.items():
        if key in ("imports", "services"):
            continue
        out[key] = value

    services: dict = {"_defaults": {"public": True}}
    for sid, body in (doc.get("services") or {}).items():
        if sid == "_defaults":
            continue
        cls = sid if "\\" in sid else None
        if isinstance(body, dict) and body.get("class"):
            cls = body["class"]
        if isinstance(body, str):
            # An alias.  Keep it when its TARGET is not removable.
            target = body.lstrip("@")
            tpath = _class_path_guess(target)
            if tpath and boundary.classify(tpath) == REMOVABLE:
                continue
            services[sid] = body
            continue
        if cls is not None:
            cpath = _class_path_guess(cls)
            if cpath and boundary.classify(cpath) == REMOVABLE:
                continue
        services[sid] = body

    for sid, body in (hooks.get("services") or {}).items():
        if sid == "_defaults":
            continue
        services[sid] = body

    # FriendsOfBehat resolves a suite `contexts:` entry as a SERVICE ID and
    # falls back to reflectively `new`-ing the string as a class name when
    # the container does not have it — which throws ArgumentCountError for
    # any context with constructor arguments.  CoreShop registers its hook
    # contexts under dotted ids only, so the synthesised suite could not
    # name them by class.  Aliasing every retained context to its own FQCN
    # lets the boundary config speak one vocabulary (class names) and
    # removes that whole failure mode.
    for sid, body in list(services.items()):
        if not isinstance(body, dict):
            continue
        cls = body.get("class")
        # Contexts only: aliasing an arbitrary vendor class (payum's
        # GatewayFactoryBuilder, say) to one concrete instance would change
        # the application's own wiring.
        if cls and "\\Context\\" in cls and cls not in services:
            # Explicit alias form: the `Id: '@target'` shorthand does not
            # inherit `_defaults.public` and is pruned as unused.
            services[cls] = {"alias": sid, "public": True}

    out["services"] = services
    header = (
        "# GENERATED by r2t.bench.repo — the retained test substrate (SPEC §3.1).\n"
        "# Re-emits the non-removable part of the Behat services file that\n"
        "# repo-wide removal deletes: extension configuration, the retained\n"
        "# index/payum/model registrations, and the four environment hook\n"
        "# contexts.  Nothing here defines a step or a transform.\n")
    return header + yaml.safe_dump(out, sort_keys=False, allow_unicode=True)


def _class_path_guess(fqcn: str, psr4: tuple = CORESHOP_PSR4) -> Optional[str]:
    """FQCN -> repo path, through a project's PSR-4 roots.

    The mapping is prefix -> DIRECTORY: the path is the directory plus the
    rest of the namespace, so a root whose directory does not mirror its
    namespace (`Sylius\\Abstraction\\StateMachine\\` ->
    `src/Sylius/Abstraction/StateMachine/src/`) resolves without a second
    rule.  `psr4` defaults to CoreShop's, which is what every existing
    caller passes by omission.
    """
    fqcn = fqcn.lstrip("@?").lstrip("\\")
    for prefix, root in psr4:
        if fqcn.startswith(prefix):
            return root + fqcn[len(prefix):].replace("\\", "/") + ".php"
    return None


def retained_services_php(bp: BehatProject) -> str:
    """The harness-owned services file for a PHP-configurator project.

    Nothing has to be re-emitted here.  A YAML project's removal takes the
    whole services file with it, extension configuration and retained hook
    contexts included, so `retained_services_yaml` rebuilds the surviving
    half; a PHP project's arm removes only its own context files, and the
    configurator tree that registers everything else survives whole.  What
    the strip DID break is the one import it redirected, so this file puts
    it back.

    `bp.original_services_import` is spelled relative to `bp.test_config`,
    and both that file and `_bench/retained_services.yml` sit one directory
    below the repository root -- so the same relative resource resolves
    from here.
    """
    return (
        "# GENERATED by r2t.bench.repo -- the retained test substrate.\n"
        "# The PHP configurator tree survives repo-wide removal whole (only\n"
        "# this arm's own context files are removable), so the harness's own\n"
        "# services file re-imports it rather than re-emitting it.\n"
        "imports:\n"
        f"    - {{ resource: {bp.original_services_import} }}\n")


#: `$container->import('resource')`, the one import form the Symfony PHP
#: configurator files in a Behat config tree use.
_PHP_IMPORT_LINE = re.compile(r"->import\(\s*'([^']+)'\s*\)")


def _removable_import_lines(repo_root: str, cfg_abs: str, bp: BehatProject,
                            boundary: Boundary) -> dict:
    """`rel path -> {0-based line}` for imports of files the strip removes.

    A PHP project's arm is removed by taking its context configurator files
    out of the tree, and the file that IMPORTS them survives -- so without
    this the stripped kernel dies in `import()` with a
    `LoaderLoadException`, which is a build error wearing an item's
    clothes.  Exactly the CoreShop case that `bp.test_config` fixes, one
    level further in.

    Resolved BEFORE anything moves, because a glob import has to be
    expanded against the tree that still has the files.  A glob is dropped
    only when every file it currently reaches is removable; a non-glob
    import names one file and answers for itself.
    """
    from ..toolkit.behat_wiring_php import reachable_php_files, resolve_import
    out: dict = {}

    def rel_of(path: str) -> str:
        return os.path.relpath(path, repo_root).replace(os.sep, "/")

    for path in reachable_php_files(os.path.join(cfg_abs, bp.services_entry)):
        if boundary.classify(rel_of(path)) == REMOVABLE:
            continue                      # the whole file leaves the tree
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        drop = set()
        for i, line in enumerate(lines):
            m = _PHP_IMPORT_LINE.search(line)
            if not m:
                continue
            targets = resolve_import(path, m.group(1))
            if targets and all(boundary.classify(rel_of(t)) == REMOVABLE
                               for t in targets):
                drop.add(i)
        if drop:
            out[rel_of(path)] = drop
    return out


def strip_repo(boundary: Boundary, gold_root: str, harness_php_dir: str,
               dry_run: bool = False) -> StripManifest:
    repo_root = os.path.abspath(boundary.repo_root)
    for protected in declared_corpus_roots():
        if repo_root == protected or repo_root.startswith(protected + os.sep):
            raise SystemExit(
                f"REFUSED: {repo_root} is inside a corpus checkout "
                f"config/corpora.yml declares ({protected}). The corpora are "
                f"this benchmark's ground truth — the Track B pilot runs out "
                f"of the CoreShop tree and its published items key on those "
                f"bytes. Point boundary.repo_root at a copy.")
    bp = behat_project(boundary)
    if not os.path.isdir(os.path.join(repo_root, bp.suite_root)):
        raise SystemExit(f"REFUSED: {repo_root} does not look like "
                         f"{boundary.project}: no {bp.suite_root}/")

    man = StripManifest(repo_root=repo_root, gold_root=os.path.abspath(gold_root),
                        boundary_version=boundary.version,
                        # Written down rather than left to the fallback, so a
                        # manifest produced today says which tree its digests
                        # cover instead of relying on the reader knowing.  The
                        # values ARE the constants, so a tree stripped before
                        # and after this change verifies identically; the
                        # archived manifests keep saying nothing and keep
                        # meaning exactly this.
                        substrate_roots=list(bp.substrate_roots),
                        substrate_volatile=sorted(bp.substrate_volatile),
                        # PHP: nothing compiles to `.pyc` here, and nothing is
                        # compiled ahead of time at all.
                        bytecode_roots=[], build_roots=[])

    cfg_abs = os.path.join(repo_root, bp.config_dir)
    if bp.services_entry is None:
        # No Symfony wiring to lose: this project's suites name their
        # contexts by class and Behat constructs them, so removal takes no
        # service definition with it and there is nothing to re-emit.
        retained_yaml = None
    elif bp.config_format == "yaml":
        retained_yaml = retained_services_yaml(
            os.path.join(cfg_abs, bp.services_entry),
            os.path.join(cfg_abs, bp.hook_services), boundary)
    else:
        retained_yaml = retained_services_php(bp)

    # Both are read from the tree that still HAS the arm: the suite map
    # names contexts whose files are about to move into gold, and a glob
    # import cannot be expanded once its targets are gone.  They answer two
    # different questions, though, and only the second one is about PHP.
    suite_map = None
    import_patches: dict = {}
    if bp.suite_scoped:
        # WHICH suite an item runs under is asked by every project whose
        # suites partition the corpus, whatever its config tree is written
        # in: PrestaShop's suites are YAML, are separated by `paths`, and
        # name their contexts by class because the project has no Symfony
        # wiring at all.  The loader dispatches on the entry's suffix, and
        # an empty `services` is the right argument for a project with no
        # services file -- `resolve_context_ref` then reads each context as
        # the FQCN the suite itself wrote.
        from ..toolkit.behat_wiring import load_services, load_suites
        from ..toolkit.behat_suites import build_suite_map
        suite_map = build_suite_map(
            load_suites(os.path.join(cfg_abs, bp.suites_entry)),
            ({} if bp.services_entry is None
             else load_services(os.path.join(cfg_abs, bp.services_entry))),
            boundary, bp, repo_root)
    if bp.config_format == "php":
        # PHP-only, and nothing to do with suites: a configurator tree
        # imports its fragments by hand, so the RETAINED importer has to
        # lose the lines whose targets the strip moved into gold.
        import_patches = _removable_import_lines(repo_root, cfg_abs, bp,
                                                 boundary)

    config_prefixes = set(boundary.removable_config)
    seen: set[str] = set()
    for prefix, _ in boundary.removable:
        for rel in _iter_files(repo_root, prefix):
            if rel in seen or boundary.classify(rel) != REMOVABLE:
                continue
            seen.add(rel)
            (man.moved_config if any(rel.startswith(c.rstrip("/")) for c in config_prefixes)
             else man.moved).append(rel)

    if dry_run:
        return man

    for rel in man.moved + man.moved_config:
        _move(repo_root, man.gold_root, rel)
    for prefix, _ in boundary.removable:
        _prune_empty_dirs(repo_root, prefix)
    for prefix in boundary.removable_config:
        _prune_empty_dirs(repo_root, prefix)

    bench = os.path.join(repo_root, BENCH_DIR)
    os.makedirs(bench, exist_ok=True)
    # `services.yml` is the harness's registration channel: the retained
    # substrate first, the solution's own fragment second, so the later
    # definition wins.  A project with no wiring to re-emit writes the
    # second half alone -- and writes it even where no Symfony kernel can
    # read it, because an inert file costs nothing and a channel that
    # exists on one project and not another is a second code path.
    imports = ([] if retained_yaml is None else ["retained_services.yml"])
    imports.append("services_item.yml")
    if retained_yaml is not None:
        with open(os.path.join(bench, "retained_services.yml"), "w",
                  encoding="utf-8") as fh:
            fh.write(retained_yaml)
        man.installed.append(f"{BENCH_DIR}/retained_services.yml")
    with open(os.path.join(bench, "services_item.yml"), "w", encoding="utf-8") as fh:
        fh.write("services: {}\n")
    with open(os.path.join(bench, "services.yml"), "w", encoding="utf-8") as fh:
        fh.write("imports:\n"
                 + "".join(f"    - {{ resource: {name} }}\n"
                           for name in imports))
    man.installed += [f"{BENCH_DIR}/services_item.yml",
                      f"{BENCH_DIR}/services.yml"]

    if suite_map is not None:
        # GOLD-SIDE EVIDENCE, never workspace content (owner ruling
        # 2026-09-10).  Every suite's entry lists that suite's REMOVABLE
        # context service ids and the class each one names -- which is the
        # list of answer files the agent is being asked to write.  Under
        # `_bench` that list travelled in the seed's `workspace.tar` to
        # every worker and, through `profile_sylius.yml`'s readable paths,
        # into the agent's own workspace.  It goes beside
        # `strip_manifest.json` instead, which is where both readers were
        # already looking: `closures` takes the path from `--gold`, and the
        # harness from `manifest.gold_root`.
        from ..toolkit.behat_suites import SUITE_MAP_NAME
        os.makedirs(man.gold_root, exist_ok=True)
        with open(os.path.join(man.gold_root, SUITE_MAP_NAME), "w",
                  encoding="utf-8") as fh:
            fh.write(json.dumps(suite_map, indent=1, sort_keys=True) + "\n")
        # Recorded the way `sanitise_repo` records what it puts in gold: an
        # arrow, not a workspace path, so nothing reads it back as a file
        # the repository is supposed to have.
        man.installed.append(f"{SUITE_MAP_NAME} -> gold/")

    if bp.worker_init == "prestashop":
        init_rel = "tests/Integration/Behaviour/Bench/prestashop_worker_init.php"
        init_dst = os.path.join(repo_root, init_rel)
        os.makedirs(os.path.dirname(init_dst), exist_ok=True)
        shutil.copyfile(os.path.join(harness_php_dir, "prestashop_worker_init.php"), init_dst)
        man.installed.append(init_rel)

    recorder_dst = os.path.join(repo_root, bp.recorder_rel)
    os.makedirs(os.path.dirname(recorder_dst), exist_ok=True)
    recorder_src = os.path.join(harness_php_dir, "BenchRecorderHook.php")
    with open(recorder_src, encoding="utf-8") as fh:
        template = fh.read()
    with open(recorder_dst, "w", encoding="utf-8") as fh:
        fh.write(recorder_source(template, bp, recorder_src))
    man.installed.append(bp.recorder_rel)

    # A project whose test configuration never imported the Behat wiring
    # has no import to redirect -- the trio is None together, which
    # `behat_project` enforces, so this is one condition and not three.
    if bp.test_config is not None:
        test_cfg = os.path.join(repo_root, bp.test_config)
        if not os.path.isfile(test_cfg):
            raise SystemExit(
                f"REFUSED: {bp.test_config} is missing from {repo_root}. It "
                f"is the file whose import the strip redirects to the "
                f"harness's own services; without it the stripped kernel "
                f"loads the removed wiring and every item fails as a build "
                f"error.")
        with open(test_cfg, encoding="utf-8") as fh:
            text = fh.read()
        if bp.original_services_import in text:
            text = text.replace(bp.original_services_import,
                                bp.bench_services_import)
            with open(test_cfg, "w", encoding="utf-8") as fh:
                fh.write(text)
            man.patched.append(bp.test_config)

    for rel, drop in sorted(import_patches.items()):
        full = os.path.join(repo_root, rel)
        with open(full, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        kept = [ln for i, ln in enumerate(lines) if i not in drop]
        with open(full, "w", encoding="utf-8") as fh:
            fh.write("\n".join(kept))
        man.patched.append(rel)

    behat_dist = os.path.join(repo_root, "behat.yml.dist")
    if os.path.isfile(behat_dist):
        os.makedirs(man.gold_root, exist_ok=True)
        shutil.move(behat_dist, os.path.join(man.gold_root, "behat.yml.dist"))
        man.moved_config.append("behat.yml.dist")

    man.installed += sanitise_repo(repo_root, man.gold_root,
                                   man.bytecode_roots, man.build_roots)
    # The manifest lists every removed path, so it is an index of the
    # answer: it lives OUTSIDE the repository under test.
    if boundary.project == "prestashop":
        from .prestashop_resources import capture
        capture(man)
    man.save(os.path.join(man.gold_root, "strip_manifest.json"))
    return man


#: Files that hold the answer without holding the code.
#:
#: `suite_map.json` (`behat_suites.SUITE_MAP_NAME`, pinned to this tuple by
#: `selftest`) is here for the trees that were stripped BEFORE the map became
#: gold-side evidence: they carry `_bench/suite_map.json`, and a re-strip must
#: sweep it out of the workspace rather than leave the old copy beside the new
#: gold one.
_EXTRACTION_ARTIFACTS = ("php_index.json", "matches.json", "steps.json",
                         "solution_index.json", "suite_map.json")


def purge_bytecode(repo_root: str, roots=()) -> list[str]:
    """Remove `__pycache__` trees and stray `.pyc` files under `roots`.

    Compiled bytecode is state that survives an item, and it is the only such
    state a python stack creates without being asked.  Two things go wrong
    when it is left alone, and the second one is the expensive one:

    * `import docx` from `PYTHONPATH=src` writes
      `src/docx/__pycache__/*.pyc`.  `src` is a SUBSTRATE ROOT, so the next
      item's `verify_substrate` sees a file ADDED to the tree under
      measurement and aborts the sweep as tampering — the benchmark stopping
      itself the first time it runs, with a message about corruption.
    * a `.pyc` outliving the module it was compiled from is the `.pyc`
      spelling of the one-second-mtime staleness bug that
      `invalidate_container` exists for, and it fails the same way: the
      previous item's code still in play, the failure charged to this item's
      solution.

    `PYTHONDONTWRITEBYTECODE=1` in the execution environment is the primary
    defence and this is the sweep behind it, because the environment variable
    only covers processes the harness starts — a solution is free to spawn
    its own interpreter without it.

    EMPTY `roots` is a no-op and returns immediately.  That is the honest
    answer for a PHP checkout: there is nothing to purge, and walking 84,000
    files per item to establish it would cost real time for no information.

    THE RESULT IS CHECKED RATHER THAN ASSUMED, which is not defensive
    programming — it is the bug this function had for its first hour.  The
    bytecode is written by a process running as root inside the container, on
    a bind mount, so a host-side `shutil.rmtree` raises EPERM; with
    `ignore_errors=True` it returned a list of twelve directories it had
    removed, none of which were gone.  That is exactly the failure
    `invalidate_container` documents for `var/cache/test`, and it is worse
    here because the next thing to run is the substrate check the purge exists
    to keep clean.  So the sweep re-scans and RAISES, and the caller that owns
    a container purges from inside it first.
    """
    removed: list[str] = []
    for root_rel in roots:
        base = os.path.join(repo_root, root_rel)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, files in os.walk(base, topdown=True):
            if os.path.basename(dirpath) == BYTECODE_DIR:
                # Do not descend into a tree that is about to be deleted.
                dirnames[:] = []
                shutil.rmtree(dirpath, ignore_errors=True)
                removed.append(os.path.relpath(dirpath, repo_root)
                               .replace(os.sep, "/"))
                continue
            for name in files:
                if name.endswith(BYTECODE_SUFFIXES):
                    full = os.path.join(dirpath, name)
                    try:
                        os.remove(full)
                    except OSError:
                        pass
                    removed.append(os.path.relpath(full, repo_root)
                                   .replace(os.sep, "/"))
    survivors = [rel for rel in removed
                 if os.path.exists(os.path.join(repo_root, rel))]
    if survivors:
        raise BytecodeSurvived(repo_root, survivors)
    return sorted(removed)


class BytecodeSurvived(RuntimeError):
    """Compiled bytecode that could not be removed from the tree.

    Raised rather than warned for the same reason `SubstrateTampered` is: the
    files are inside a hashed substrate root, so the next item's verification
    will abort anyway — and it will abort with a message about the repository
    being tampered with, which sends the reader looking for a solution that
    escaped its boundary instead of for a permission bit.
    """

    def __init__(self, repo_root: str, survivors: list[str]):
        self.survivors = survivors
        shown = ", ".join(survivors[:6])
        more = f" (+{len(survivors) - 6} more)" if len(survivors) > 6 else ""
        super().__init__(
            f"could not remove {len(survivors)} compiled-bytecode path(s) "
            f"from {repo_root}: {shown}{more}. They are almost certainly owned "
            f"by root, written by the container on a bind mount — purge them "
            f"from INSIDE the container, as the same uid that created them, "
            f"before sweeping from the host.")


def purge_build_output(repo_root: str, roots=()) -> list[str]:
    """Delete ahead-of-time build output under `roots`, wholesale.

    A compiled language keeps a second copy of every source file it has ever
    built, and after a strip that second copy is the ANSWER.
    `target/test-classes/org/w3c/epubcheck/test/AssertionSteps.class` is the
    removed step definitions with their Cucumber Expression patterns intact in
    the constant pool; `javap -c` reads them without a decompiler, and a
    decompiler gives back most of the method bodies.  An agent that can list
    its own workspace does not have to be clever to find that.

    So this is a sibling of `sanitise_repo`'s `.git` move rather than of
    `purge_bytecode`: it is not protecting the substrate check (`target/` sits
    under no substrate root and would never abort an item), it is closing a
    read path to the gold answer.

    DELETED rather than moved into gold, which is the one place this differs
    from every other removal in this module.  Build output is derived state:
    Maven reproduces `target/` from `src/` and the pinned `/opt/m2` cache, so
    there is nothing here that a gold tree would preserve and nothing a
    reviewer could learn from a copy of it.  What IS preserved is that the
    strip manifest records the roots it emptied (`StripManifest.build_roots`).

    EMPTY `roots` is a no-op and returns immediately -- the honest answer for
    a PHP or Python checkout, which compiles nothing ahead of time.

    THE RESULT IS RE-SCANNED AND THE FAILURE RAISES, for the reason
    `purge_bytecode` learned the hard way: these files are written by a
    container process running as root on a bind mount, so a host-side
    `rmtree` can fail with EPERM and report success.  A purge that quietly
    removed nothing would leave the answer readable in a workspace the
    campaign then treats as clean, and nothing downstream would look wrong.
    """
    removed: list[str] = []
    for root_rel in roots:
        base = os.path.join(repo_root, root_rel)
        if not os.path.exists(base):
            continue
        shutil.rmtree(base, ignore_errors=True)
        removed.append(root_rel)
    survivors = [rel for rel in removed
                 if os.path.exists(os.path.join(repo_root, rel))]
    if survivors:
        raise BuildOutputSurvived(repo_root, survivors)
    return sorted(removed)


class BuildOutputSurvived(RuntimeError):
    """Build output that could not be removed from a candidate's workspace.

    Separate from `BytecodeSurvived` because the finding is different: that
    one is "the next item will abort as tampering", this one is "the answer is
    still readable in the tree the agent is about to be given". The remedy is
    the same and is stated for the same reason -- the files belong to root
    because a container wrote them on a bind mount.
    """

    def __init__(self, repo_root: str, survivors: list[str]):
        self.survivors = survivors
        super().__init__(
            f"could not remove build output {', '.join(survivors)} from "
            f"{repo_root}. Compiled test classes are the removed step "
            f"definitions in another format, so a workspace that still has "
            f"them hands the agent the answer. They are almost certainly "
            f"owned by root, written by the container on a bind mount — purge "
            f"them from INSIDE the container, as the same uid that created "
            f"them, before sweeping from the host.")


def sanitise_repo(repo_root: str, gold_root: str, bytecode_roots=(),
                  build_roots=()) -> list[str]:
    """Remove the copies of the answer that stripping does not touch.

    Deleting the source files is not enough for a system under test that
    can read the repository — an agent, as opposed to a single-shot model,
    can simply look elsewhere:

    * `.git` still contains every removed file at HEAD
      (`git show HEAD:src/CoreShop/Behat/Context/Domain/CartContext.php`).
    * the extraction artifacts the pipeline writes into `_bench/`
      (`php_index.json`, `matches.json`) list every removed class, its
      constructor parameters and every step-definition pattern.
    * Composer's optimised classmap still maps removed classes to their
      paths, and a stale compiled container still carries their service
      definitions and arguments.
    * a compiled tree keeps the removed classes as bytecode
      (`target/test-classes/**/*.class` for Maven), which reads back as the
      step definitions with their patterns intact.

    Each is moved into the gold tree rather than deleted, so the removal
    is reversible and auditable — except the two derived-state sweeps
    (`bytecode_roots`, `build_roots`), which are regenerated from source and
    would preserve nothing.
    """
    moved = []
    git_dir = os.path.join(repo_root, ".git")
    if os.path.isdir(git_dir):
        dst = os.path.join(gold_root, "_git")
        if os.path.exists(dst):
            shutil.rmtree(dst, ignore_errors=True)
        shutil.move(git_dir, dst)
        moved.append(".git -> gold/_git")

    bench = os.path.join(repo_root, BENCH_DIR)
    keep = os.path.join(gold_root, "_extraction")
    os.makedirs(keep, exist_ok=True)
    for name in _EXTRACTION_ARTIFACTS:
        src = os.path.join(bench, name)
        if os.path.isfile(src):
            shutil.move(src, os.path.join(keep, name))
            moved.append(f"{BENCH_DIR}/{name} -> gold/_extraction")

    for rel in ("var/cache", "var/log"):
        path = os.path.join(repo_root, rel)
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            os.makedirs(path, exist_ok=True)
            moved.append(f"{rel} cleared")

    stale_manifest = os.path.join(bench, "strip_manifest.json")
    if os.path.isfile(stale_manifest):
        shutil.move(stale_manifest, os.path.join(gold_root, "strip_manifest.json"))
        moved.append(f"{BENCH_DIR}/strip_manifest.json -> gold/")

    # Bytecode compiled from the code that was just moved into gold.  It is
    # not a copy of the answer (a `.pyc` of a step module is a compiled
    # ANSWER, which is worse), and it is the first thing the baseline about to
    # be taken would record as part of the substrate.  A PHP tree declares no
    # roots and this is a no-op there.
    purged = purge_bytecode(repo_root, bytecode_roots)
    if purged:
        moved.append(f"{len(purged)} bytecode path(s) purged")

    # Ahead-of-time build output compiled from the code that was just moved
    # into gold. A PHP or Python tree declares no roots and this is a no-op
    # there, which is why every existing caller is unchanged.
    built = purge_build_output(repo_root, build_roots)
    if built:
        moved.append(f"build output purged: {', '.join(built)}")
    return moved


# --------------------------------------------------------------- workspace
def restore(manifest: StripManifest, rel_paths: list[str]) -> list[str]:
    """Copy gold files back into the working tree (the §5 pass leg)."""
    done = []
    for rel in rel_paths:
        src = os.path.join(manifest.gold_root, rel)
        if not os.path.isfile(src):
            raise FileNotFoundError(f"gold file missing: {rel}")
        dst = os.path.join(manifest.repo_root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
        done.append(rel)
    return done


def clean_workspace(manifest: StripManifest, boundary: Boundary) -> list[str]:
    """Remove every file currently sitting in removable territory.

    This is what makes runs independent: whatever the previous item (or a
    system under test) wrote into the stripped tree is gone before the
    next one starts.
    """
    from ..core.boundary import REMOVABLE
    removed = []
    for prefix, _ in boundary.removable:
        for rel in list(_iter_files(manifest.repo_root, prefix)):
            # Classify EVERY file, do not trust the prefix.  `removable`
            # is a broad prefix narrowed by `retained` exceptions, so a
            # prefix-only sweep deletes the retained substrate — which it
            # did once, taking Behat/Service/Index, Behat/Model and the
            # recorder hook with it.
            if boundary.classify(rel) != REMOVABLE:
                continue
            os.remove(os.path.join(manifest.repo_root, rel))
            removed.append(rel)
        _prune_empty_dirs(manifest.repo_root, prefix)
    return removed


def derived_state_drift(repo_root: str, baseline: dict) -> list[str]:
    """Seed members whose workspace copy is missing or holds other bytes.

    `baseline` maps each seed member under the derived-state roots to its
    seed bytes.  A file ADDED under a root is not drift (see
    `DERIVED_STATE_ROOTS`).  A symlink anywhere on a member's path is refused
    rather than read or written through: the seed holds none, so something
    that executed planted it, and restoring through it would write seed bytes
    wherever it points.
    """
    drift = []
    for rel in sorted(baseline):
        path = repo_root
        for part in rel.split("/"):
            path = os.path.join(path, part)
            if os.path.islink(path):
                raise DerivedStateUnrestored(
                    [rel], f"derived-state path passes through a symlink "
                           f"({path})")
        try:
            with open(os.path.join(repo_root, rel), "rb") as fh:
                same = fh.read() == baseline[rel]
        except OSError:
            same = False
        if not same:
            drift.append(rel)
    return drift


def _write_seed_bytes(repo_root: str, rel: str, data: bytes) -> None:
    """Replace one member with its seed bytes from the host, atomically.

    A rename over the old file needs write permission on the DIRECTORY only,
    so this also replaces a file a rootful container left root-owned inside a
    seed-made (host-owned) directory.
    """
    path = os.path.join(repo_root, rel)
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".r2t-restore-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, DERIVED_STATE_FILE_MODE)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _restore_in_container(repo_root: str, members: dict, runner) -> None:
    """Copy members into place from INSIDE the container.

    For the members the host could not write: under a rootful daemon a
    directory the container (re)created belongs to root, and the host cannot
    create a file in it -- `Harness.invalidate_container`'s lesson.  The seed
    bytes are staged in a host-owned directory inside the bind mount and
    copied by the container's own root.  The caller re-compares from the host,
    so a copy that did not take is caught there, not trusted from an exit code.
    """
    stage_rel = f"{DERIVED_STATE_STAGING}/{secrets.token_hex(8)}"
    steps = []
    try:
        for rel, data in sorted(members.items()):
            staged = os.path.join(repo_root, stage_rel, rel)
            os.makedirs(os.path.dirname(staged), exist_ok=True)
            with open(staged, "wb") as fh:
                fh.write(data)
            target = shlex.quote(rel)
            steps.append(
                f"mkdir -p {shlex.quote(os.path.dirname(rel))} && "
                f"cp {shlex.quote(stage_rel + '/' + rel)} {target} && "
                f"chmod {DERIVED_STATE_FILE_MODE:o} {target}")
        runner.run(" && ".join(steps), timeout=120)
    finally:
        shutil.rmtree(os.path.join(repo_root, DERIVED_STATE_STAGING),
                      ignore_errors=True)


def restore_derived_state(repo_root: str, baseline: dict,
                          runner) -> list[str]:
    """Put every drifted seed member back to its seed bytes; verify; return.

    Host writes first (the rootless daemon's case: the workspace is the
    operator's), then the container for whatever the host could not write,
    then ONE re-comparison from the host that decides.  Anything still not
    seed bytes raises `DerivedStateUnrestored`.  Returns the restored paths,
    sorted; an empty list when nothing had drifted, which is every pair whose
    predecessor re-saved no class.
    """
    drift = derived_state_drift(repo_root, baseline)
    if not drift:
        return []
    refused: dict = {}
    problems: list[str] = []
    for rel in drift:
        try:
            _write_seed_bytes(repo_root, rel, baseline[rel])
        except OSError as exc:
            refused[rel] = baseline[rel]
            problems.append(f"host: {type(exc).__name__}")
    if refused:
        try:
            _restore_in_container(repo_root, refused, runner)
        except OSError as exc:
            problems.append(f"container staging: {type(exc).__name__}")
    still = derived_state_drift(repo_root, baseline)
    if still:
        detail = f" ({'; '.join(sorted(set(problems)))})" if problems else ""
        raise DerivedStateUnrestored(
            still, f"derived state did not restore to its seed bytes{detail}")
    return drift


def load_manifest(path: str) -> StripManifest:
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    return StripManifest(repo_root=d["repo_root"], gold_root=d["gold_root"],
                         moved=d["moved"], moved_config=d["moved_config"],
                         patched=d["patched"], installed=d["installed"],
                         boundary_version=d.get("boundary_version", 0),
                         digests=d.get("digests") or {},
                         # Absent on every manifest written before the roots
                         # were data. Left ABSENT rather than filled in, so
                         # `roots()` answers with the CoreShop constants and
                         # an archived tree verifies exactly as it did.
                         substrate_roots=list(d.get("substrate_roots") or []),
                         substrate_volatile=list(
                             d.get("substrate_volatile") or []),
                         bytecode_roots=list(d.get("bytecode_roots") or []),
                         build_roots=list(d.get("build_roots") or []),
                         prestashop_resources=d.get("prestashop_resources"))


# ------------------------------------------------------- substrate integrity
def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def substrate_digests(repo_root: str, boundary: Boundary,
                      roots: tuple = SUBSTRATE_ROOTS,
                      volatile=SUBSTRATE_VOLATILE, *, skip=None) -> dict[str, str]:
    """sha256 of every file that must not change while the benchmark runs.

    Removable territory is excluded: that is where solutions legitimately
    write, and it is swept between items anyway.  What is left is the
    retained test substrate, the production code, the harness's own recorder
    and the Behat/Symfony machinery that executes all of it.

    `roots` and `volatile` default to CoreShop's so that every existing
    caller is unchanged; `verify_substrate` and `baseline_substrate` pass the
    manifest's own, which is what makes a second stack hash its own tree
    instead of looking for `vendor/behat` in a python checkout and reporting
    a clean substrate it never examined.
    """
    digests: dict[str, str] = {}
    for root_rel in roots:
        for rel in _iter_files(repo_root, root_rel):
            if rel in volatile or (skip is not None and skip(rel)):
                continue
            if boundary.classify(rel) == REMOVABLE:
                continue
            path = os.path.join(repo_root, rel)
            if boundary.project == "prestashop" and os.path.islink(path):
                from .prestashop_resources import selected
                if selected(rel):
                    digests[rel] = hashlib.sha256(
                        b"symlink\0" + os.fsencode(os.readlink(path))).hexdigest()
                    continue
            digests[rel] = _sha256(path)
    return digests


def verify_substrate(manifest: StripManifest, boundary: Boundary,
                     expected: Optional[dict] = None) -> dict:
    """Compare the tree against its baseline.  Cheap enough to run per item.

    `expected` is the ONE legitimate reason production code differs: a
    mutation campaign deliberately edits a production file and then executes
    against it.  It maps `rel -> sha256 of the mutated file`, so the guard
    still refuses every change that was not declared in advance — the point
    being that "a file under measurement changed" must never become a warning
    a mutation run teaches everyone to ignore.
    """
    if not manifest.digests:
        return {"baseline": False, "checked": 0,
                "changed": [], "missing": [], "added": [], "mutated": []}
    volatile = manifest.volatile()
    # A declaration can postdate an installed manifest, whose digest map then
    # still contains the newly volatile path.  Apply the same exclusion to
    # both sides in memory; verification must not rewrite that manifest.
    baseline = {r: d for r, d in manifest.digests.items()
                if r not in volatile}
    now = substrate_digests(manifest.repo_root, boundary,
                            manifest.roots(), volatile)
    return compare_substrate_inventory(baseline, now, expected)


def compare_substrate_inventory(baseline: dict[str, str], now: dict[str, str],
                                expected: Optional[dict] = None) -> dict:
    """Compare complete inventories against an already-established baseline.

    Host and container-only Go copies use the same comparison. Callers own
    inventory completeness, exact volatility and independent baseline authority;
    this pure function never blesses freshly observed bytes as that authority.
    An empty explicit baseline is still established. Legacy missing-baseline
    handling remains in verify_substrate before this function is called.
    """
    expected = expected or {}
    honoured = sorted(r for r, d in expected.items() if now.get(r) == d)
    return {
        "baseline": True,
        "checked": len(now),
        "changed": sorted(r for r, d in now.items()
                          if r in baseline and baseline[r] != d
                          and expected.get(r) != d),
        "missing": sorted(set(baseline) - set(now)),
        "added": sorted(set(now) - set(baseline)),
        "mutated": honoured,
    }


def baseline_substrate(manifest: StripManifest, boundary: Boundary,
                       manifest_path: str) -> dict:
    """Record the CURRENT tree as the baseline, and save the manifest.

    This is a one-shot for a tree stripped before digests existed.  It asserts
    nothing about whether that tree is clean — the caller has to establish
    that separately (for CoreShop, by diffing the production sources against
    an independent copy of the same checkout).  Re-running it after a
    tampering abort would launder the tampering, so it prints what it
    replaced.
    """
    previous = dict(manifest.digests)
    manifest.digests = substrate_digests(manifest.repo_root, boundary,
                                         manifest.roots(), manifest.volatile())
    if boundary.project == "prestashop":
        from .prestashop_resources import verify_inputs, verify_entry
        verify_inputs(manifest)
        verify_entry(manifest)
    manifest.save(manifest_path)
    changed = sorted(r for r, d in manifest.digests.items()
                     if r in previous and previous[r] != d)
    return {"files": len(manifest.digests), "had_baseline": bool(previous),
            "changed_from_previous": changed}


# ------------------------------------------------------------------ selftest
def selftest() -> int:
    """The substrate guard's ARITHMETIC, on a tree built here.

    Everything below runs against a hand-made checkout rather than against
    CoreShop, because the questions are all of the form "does the guard look
    where the manifest says?" and the answer must not depend on which
    repository happens to be mounted.  The one thing that would be invisible
    without a fixture is the failure this milestone exists to prevent: a
    `__pycache__` directory appearing inside a substrate root and turning the
    NEXT item into a tampering abort.
    """
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    here = BENCHMARK_ROOT
    from ..core.boundary import load_boundary

    with tempfile.TemporaryDirectory() as root:
        def write(rel, text="x"):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        # A python+behave checkout in miniature, stripped: production under
        # `src`, the retained hook, the retained fixtures, and one step module
        # sitting where a solution's answer goes.
        write("src/docx/__init__.py", "VERSION = 1\n")
        write("src/docx/document.py", "class Document: pass\n")
        write("features/environment.py", "def before_all(context): pass\n")
        write("features/steps/test_files/doc-default.docx", "PK\x03\x04")
        write("features/doc-add-table.feature", "Feature: tables\n")
        write("features/steps/document.py", "# a solution\n")
        write("pyproject.toml", "[project]\n")
        write(f"{BENCH_DIR}/run_record.jsonl", "{}\n")
        write("config/reference.php", "<?php // generated before strip\n")
        write("config/services.yml", "services: {}\n")

        b = load_boundary(os.path.join(here, "config",
                                       "boundary_python_docx.yml"),
                          repo_root=root)
        core_b = load_boundary(os.path.join(here, "config",
                                            "boundary_coreshop.yml"),
                               repo_root=root)
        man = StripManifest(
            repo_root=root, gold_root=os.path.join(root, "_gold"),
            substrate_roots=list(BEHAVE_SUBSTRATE_ROOTS),
            substrate_volatile=sorted(BEHAVE_SUBSTRATE_VOLATILE),
            bytecode_roots=list(BEHAVE_BYTECODE_ROOTS))
        baseline = substrate_digests(root, b, man.roots(), man.volatile())

        check("the fixtures are hashed — tampering with one is tampering with "
              "the answer space",
              "features/steps/test_files/doc-default.docx" in baseline)
        check("production and the retained hook are hashed",
              "src/docx/document.py" in baseline
              and "features/environment.py" in baseline
              and "pyproject.toml" in baseline)
        check("a solution's own file is NOT hashed — that is where it writes",
              "features/steps/document.py" not in baseline)
        check("the per-item record file is exempt as volatile",
              f"{BENCH_DIR}/run_record.jsonl" not in baseline)

        # A CoreShop manifest written before `config/reference.php` was
        # declared volatile still has its digest.  Rebuild that exact shape by
        # hashing the two config files without exemptions, then verify it with
        # today's declaration while leaving the stored digest map untouched.
        legacy = StripManifest(
            repo_root=root, gold_root=os.path.join(root, "_gold"),
            substrate_roots=["config"])
        legacy.digests = substrate_digests(
            root, core_b, legacy.roots(), volatile=frozenset())
        stale_reference_digest = legacy.digests["config/reference.php"]
        write("config/reference.php", "<?php // regenerated by framework\n")
        rep = verify_substrate(legacy, core_b)
        check("a declared regenerated path is not hashed and its stale digest "
              "does not report missing",
              "config/reference.php" not in substrate_digests(
                  root, core_b, legacy.roots(), legacy.volatile())
              and not any(rep[k] for k in ("changed", "missing", "added"))
              and legacy.digests["config/reference.php"]
              == stale_reference_digest,
              str(rep))
        write("config/services.yml", "services: { changed: true }\n")
        rep = verify_substrate(legacy, core_b)
        check("an undeclared changed sibling remains substrate tampering",
              rep["changed"] == ["config/services.yml"]
              and not rep["missing"] and not rep["added"], str(rep))

        check("nothing outside the declared roots is hashed",
              "features/doc-add-table.feature" not in baseline)

        man.digests = baseline
        check("an untouched tree verifies clean",
              not any(verify_substrate(man, b)[k]
                      for k in ("changed", "missing", "added")))

        # The failure this milestone exists to prevent, demonstrated.
        pyc_dir = os.path.join(root, "src", "docx", BYTECODE_DIR)
        os.makedirs(pyc_dir)
        with open(os.path.join(pyc_dir, "document.cpython-312.pyc"), "wb") as fh:
            fh.write(b"\x00\x00\x00\x00")
        rep = verify_substrate(man, b)
        check("bytecode inside a substrate root WOULD abort the next item",
              rep["added"] == [f"src/docx/{BYTECODE_DIR}/document.cpython-312.pyc"],
              str(rep["added"]))
        purged = purge_bytecode(root, man.bytecode_roots)
        check("the purge removes it, naming what it removed",
              purged == [f"src/docx/{BYTECODE_DIR}"] and not os.path.isdir(pyc_dir),
              str(purged))
        check("and the tree verifies clean again",
              not any(verify_substrate(man, b)[k]
                      for k in ("changed", "missing", "added")))
        stray = os.path.join(root, "src", "docx", "stale.pyc")
        with open(stray, "wb") as fh:
            fh.write(b"\x00")
        purge_bytecode(root, man.bytecode_roots)
        check("a stray .pyc beside its source goes too, not just the "
              "__pycache__ tree", not os.path.exists(stray))
        check("an EMPTY roots list is a no-op, which is what a PHP tree wants",
              purge_bytecode(root, ()) == []
              and os.path.isfile(os.path.join(root, "src/docx/document.py")))

        # A purge that reports success without removing anything is worse than
        # no purge: the tampering abort still happens, one item later, with a
        # message about the repository being edited. This is not hypothetical
        # -- the first version of this function passed `ignore_errors=True` and
        # returned twelve directory names against a real worker, none of which
        # were gone, because the container writes them as root on a bind mount.
        undeletable = os.path.join(root, "src", "docx", "oxml", BYTECODE_DIR)
        os.makedirs(undeletable)
        with open(os.path.join(undeletable, "x.cpython-312.pyc"), "wb") as fh:
            fh.write(b"\x00")
        real_rmtree = shutil.rmtree

        def rmtree_that_fails(path, *a, **kw):
            return None                      # what EPERM + ignore_errors does

        shutil.rmtree = rmtree_that_fails
        try:
            try:
                purge_bytecode(root, man.bytecode_roots)
                fired = ""
            except SubstrateTampered:                      # noqa: BLE001
                fired = "wrong exception"
            except RuntimeError as e:
                fired = str(e)
            check("a purge that removes nothing RAISES instead of reporting "
                  "the paths it did not remove",
                  "could not remove" in fired and "INSIDE the container" in fired,
                  fired[:200])
        finally:
            shutil.rmtree = real_rmtree
        purge_bytecode(root, man.bytecode_roots)

        # Tampering with a fixture is the whole reason `test_files` is a root.
        write("features/steps/test_files/doc-default.docx", "PK\x03\x04TAMPERED")
        rep = verify_substrate(man, b)
        check("rewriting a fixture .docx is detected as a CHANGE",
              rep["changed"] == ["features/steps/test_files/doc-default.docx"],
              str(rep["changed"]))

        # And the fallback: a manifest that records nothing is CoreShop's,
        # which is what every archived strip_manifest.json on disk is.
        old = StripManifest(repo_root=root, gold_root=man.gold_root)
        check("a manifest with no roots recorded falls back to CoreShop's",
              old.roots() == SUBSTRATE_ROOTS
              and old.volatile() == SUBSTRATE_VOLATILE
              and old.bytecode_roots == [])
        check("a stack that records its own roots does not inherit them",
              man.roots() == BEHAVE_SUBSTRATE_ROOTS
              and man.roots() != SUBSTRATE_ROOTS
              and man.volatile() == BEHAVE_SUBSTRATE_VOLATILE)
        # The invariant that makes the purge WORTH running: every substrate
        # root that can hold python is swept.  A root that imports but is not
        # swept is the abort this whole mechanism exists to prevent, and
        # nothing else in the codebase would notice the two lists drifting.
        #
        # The test is the COMPLEMENT — a root counts as importable unless it
        # is a file with a non-python suffix — because the other reading
        # ("sweep `src` and the `.py` roots") is a promise about the future
        # that this file cannot keep: a DIRECTORY root holds whatever a later
        # milestone puts in it, and `_bench` is a directory the harness itself
        # writes to.  Naming the exceptions is a decision somebody makes;
        # naming the inclusions lets a new root arrive unswept in silence.
        def swept(rel: str) -> bool:
            return any(rel == b or rel.startswith(b + "/")
                       for b in BEHAVE_BYTECODE_ROOTS)

        def importable(rel: str) -> bool:
            ext = os.path.splitext(rel)[1]
            return ext in ("", ".py")

        unswept = [r for r in BEHAVE_SUBSTRATE_ROOTS
                   if importable(r) and not swept(r)]
        check("every substrate root that python can import from is swept for "
              "bytecode", not unswept, f"unswept: {unswept}")
        check("...and the rule is the complement, so a directory root added "
              "later cannot arrive unswept in silence",
              importable(BENCH_DIR) and importable("features/steps")
              and not importable("pyproject.toml"))

        # Round trip: what is saved is what comes back, or the recording is
        # decoration.
        path = os.path.join(root, "strip_manifest.json")
        man.save(path)
        back = load_manifest(path)
        check("the roots survive a save/load round trip",
              back.roots() == man.roots()
              and back.volatile() == man.volatile()
              and back.bytecode_roots == man.bytecode_roots)
        # A manifest file written before the fields existed.
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for key in ("substrate_roots", "substrate_volatile", "bytecode_roots"):
            doc.pop(key)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        check("a manifest written before the fields existed still loads, and "
              "still means CoreShop",
              load_manifest(path).roots() == SUBSTRATE_ROOTS)

    # -- java+cucumber: the third stack's answer to the same three questions.
    #
    # Synthetic again, and for the same reason: these are questions about
    # where the guard LOOKS, and the answer must not depend on a 3177-file
    # checkout being mounted.  What that checkout decides -- that the boundary
    # classifies every one of those files -- is
    # `scripts/gate_s2_boundary_epubcheck.py`'s job.
    with tempfile.TemporaryDirectory() as root:
        def write(rel, text="x"):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        java = "src/test/java/org/w3c/epubcheck"
        res = "src/test/resources"
        # An epubcheck checkout in miniature, stripped and then BUILT: the
        # checker under test, the retained substrate, a retained fixture, a
        # criterion, a solution's own file where the answer goes, and the
        # Maven output of a build that happened before the strip.
        write("src/main/java/com/adobe/epubcheck/api/EpubCheck.java",
              "public class EpubCheck {}\n")
        write(f"{java}/test/ParameterTypes.java", "// R1.5 substrate\n")
        write(f"{java}/test/EPUBCheckConfiguration.java", "// hooks\n")
        write(f"{java}/RunCucumberTest.java", "// runner\n")
        write(f"{java}/url/URLUtilsTest.java", "// production unit test\n")
        write(f"{res}/epub3/05-package-document/files/pkg-valid.opf", "<opf/>")
        write(f"{res}/epub3/05-package-document/package-document.feature",
              "Feature: package document\n")
        write("pom.xml", "<project/>\n")
        # Removable: the answer.
        write(f"{java}/test/AssertionSteps.java", "// a solution\n")
        write(f"{res}/cucumber.properties", "cucumber.publish.quiet=true")
        write(f"{BENCH_DIR}/run_record.jsonl", "{}\n")
        # The leak: the pre-strip build, still holding the glue as bytecode.
        write("target/test-classes/org/w3c/epubcheck/test/AssertionSteps.class",
              "\xca\xfe\xba\xbe")
        write("target/surefire-reports/TEST-RunCucumberTest.xml", "<ts/>")
        write("target/epubcheck.jar", "PK\x03\x04")

        b = load_boundary(os.path.join(here, "config",
                                       "boundary_epubcheck.yml"),
                          repo_root=root)
        man = StripManifest(
            repo_root=root, gold_root=os.path.join(root, "_gold"),
            substrate_roots=list(CUCUMBER_SUBSTRATE_ROOTS),
            substrate_volatile=sorted(CUCUMBER_SUBSTRATE_VOLATILE),
            bytecode_roots=[], build_roots=list(CUCUMBER_BUILD_ROOTS))
        baseline = substrate_digests(root, b, man.roots(), man.volatile())

        cases = {
            "src/main/java/com/adobe/epubcheck/api/EpubCheck.java": True,
            f"{java}/test/ParameterTypes.java": True,
            f"{java}/test/EPUBCheckConfiguration.java": True,
            f"{java}/RunCucumberTest.java": True,
            f"{java}/url/URLUtilsTest.java": True,
            f"{res}/epub3/05-package-document/files/pkg-valid.opf": True,
            f"{res}/epub3/05-package-document/package-document.feature": True,
            "pom.xml": True,
            # Where a solution writes, and the runtime config removal takes:
            # neither is hashed, because both legitimately move.
            f"{java}/test/AssertionSteps.java": False,
            f"{res}/cucumber.properties": False,
            # Harness-owned, per item by design.
            f"{BENCH_DIR}/run_record.jsonl": False,
            # Outside every declared root.
            "target/test-classes/org/w3c/epubcheck/test/AssertionSteps.class":
                False,
        }
        for rel, want in cases.items():
            check(f"[cucumber] {rel} {'is' if want else 'is NOT'} hashed",
                  (rel in baseline) == want)
        check("[cucumber] R1.5's exact retained bytes are what the manifest "
              "binds -- that is what 'hashed substrate' means operationally",
              baseline[f"{java}/test/ParameterTypes.java"]
              == hashlib.sha256(b"// R1.5 substrate\n").hexdigest())

        man.digests = baseline
        check("[cucumber] an untouched tree verifies clean",
              not any(verify_substrate(man, b)[k]
                      for k in ("changed", "missing", "added")))
        write(f"{res}/epub3/05-package-document/files/pkg-valid.opf",
              "<opf tampered='1'/>")
        rep = verify_substrate(man, b)
        check("[cucumber] rewriting a fixture .opf is answer-space tampering "
              "and is detected as a CHANGE",
              rep["changed"]
              == [f"{res}/epub3/05-package-document/files/pkg-valid.opf"],
              str(rep["changed"]))
        write(f"{res}/epub3/05-package-document/files/pkg-valid.opf", "<opf/>")
        write(f"{java}/test/AssertionSteps.java", "// a second solution\n")
        check("[cucumber] ...while a solution rewriting its OWN file is not, "
              "which is the line the two lists draw",
              not any(verify_substrate(man, b)[k]
                      for k in ("changed", "missing", "added")))

        # The purge. `target/` aborts nothing -- it is under no root, as the
        # table above asserts -- so what it costs is not a false tampering
        # report, it is the answer being readable.
        leak = os.path.join(
            root, "target/test-classes/org/w3c/epubcheck/test/"
                  "AssertionSteps.class")
        check("[cucumber] before the purge, the removed glue is on disk as "
              "bytecode a decompiler reads",
              os.path.isfile(leak))
        purged = purge_build_output(root, man.build_roots)
        check("[cucumber] the purge takes the whole build root, naming what "
              "it removed",
              purged == ["target"]
              and not os.path.exists(os.path.join(root, "target")),
              str(purged))
        check("[cucumber] ...which is the jar and the surefire reports too, "
              "not only the .class files -- each is the same leak in another "
              "format",
              not os.path.exists(os.path.join(root, "target/epubcheck.jar")))
        check("[cucumber] and the tree it was measured over is untouched by "
              "it", not any(verify_substrate(man, b)[k]
                            for k in ("changed", "missing", "added")))
        check("[cucumber] an EMPTY roots list is a no-op, which is what a PHP "
              "or Python tree wants",
              purge_build_output(root, ()) == []
              and purge_build_output(root, man.build_roots) == []
              and os.path.isfile(os.path.join(root, "pom.xml")))

        # A purge that reports success without removing anything hands the
        # agent the answer in a workspace the campaign then calls clean. Same
        # cause as `purge_bytecode`'s: root-owned files on a bind mount.
        write("target/test-classes/x.class", "\xca\xfe")
        real_rmtree = shutil.rmtree

        def rmtree_that_fails(path, *a, **kw):
            return None                      # what EPERM + ignore_errors does

        shutil.rmtree = rmtree_that_fails
        try:
            try:
                purge_build_output(root, man.build_roots)
                fired = ""
            except RuntimeError as e:
                fired = str(e)
            check("[cucumber] a build purge that removes nothing RAISES, and "
                  "says the answer is still readable rather than reporting a "
                  "path it did not remove",
                  "could not remove build output" in fired
                  and "hands the agent the answer" in fired
                  and "INSIDE the container" in fired, fired[:200])
        finally:
            shutil.rmtree = real_rmtree
        purge_build_output(root, man.build_roots)

        # Three stacks, three answers, and no stack inherits another's.
        check("[cucumber] the roots are this stack's own, not behave's and "
              "not CoreShop's",
              man.roots() == CUCUMBER_SUBSTRATE_ROOTS
              and man.roots() not in (SUBSTRATE_ROOTS, BEHAVE_SUBSTRATE_ROOTS)
              and man.volatile() == CUCUMBER_SUBSTRATE_VOLATILE)
        check("[cucumber] a JVM tree declares no BYTECODE roots: `.class` "
              "files are build output, swept by `build_roots`, and a "
              "`__pycache__` sweep over a Maven tree would find nothing",
              man.bytecode_roots == []
              and man.build_roots == list(CUCUMBER_BUILD_ROOTS))
        # The invariant that keeps the two build lists from drifting: no
        # substrate root may sit inside a build root, or the purge would
        # delete the tree the guard is hashing and every item would abort as
        # `missing`.
        overlapping = [r for r in CUCUMBER_SUBSTRATE_ROOTS
                       for bld in CUCUMBER_BUILD_ROOTS
                       if r == bld or r.startswith(bld + "/")]
        check("[cucumber] no substrate root sits inside a build root, so the "
              "purge cannot delete what the guard hashes",
              not overlapping, f"overlapping: {overlapping}")

        path = os.path.join(root, "strip_manifest.json")
        man.save(path)
        back = load_manifest(path)
        check("[cucumber] the build roots survive a save/load round trip",
              back.build_roots == man.build_roots
              and back.roots() == man.roots()
              and back.volatile() == man.volatile())
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc.pop("build_roots")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        check("[cucumber] a manifest written before `build_roots` existed "
              "still loads and still purges nothing",
              load_manifest(path).build_roots == []
              and purge_build_output(root, load_manifest(path).build_roots)
              == [])


    # ---- the rows themselves: defaults, refusal, and one PHP strip --------
    #
    # `behat_project` is what makes a second Behat project a ROW rather than
    # a second implementation, and the two things it must never do are
    # "read a key CoreShop did not have" and "accept a key nobody defined".
    from ..core.boundary import Boundary as _B

    plain = _B(version=1, project="coreshop", repo_root="/x",
               removable=[], retained=[])
    check("a boundary with no `behat:` block IS the CoreShop defaults, the "
          "object and not a copy of it",
          behat_project(plain) is CORESHOP_BEHAT)
    check("...and those defaults ARE the module constants this file already "
          "had, so nothing moved",
          CORESHOP_BEHAT.substrate_roots == SUBSTRATE_ROOTS
          and CORESHOP_BEHAT.substrate_volatile == SUBSTRATE_VOLATILE
          and CORESHOP_BEHAT.test_config == TEST_CONFIG
          and CORESHOP_BEHAT.recorder_rel == RECORDER_REL
          and CORESHOP_BEHAT.original_services_import
          == ORIGINAL_SERVICES_IMPORT
          and CORESHOP_BEHAT.bench_services_import == BENCH_SERVICES_IMPORT
          and CORESHOP_BEHAT.psr4 == CORESHOP_PSR4)
    # `prod_paths` is now read by TWO producers -- the production index and,
    # since a second Behat project arrived, the mutation population -- so the
    # roots are one object shared with `data.mutation`, not a second copy.
    check("the production-roots row IS the tuple the mutation exclusions are "
          "built from, one object and not a second copy",
          CORESHOP_BEHAT.prod_paths is CORESHOP_PROD_PATHS
          and CORESHOP_PROD_PATHS
          == ("src/CoreShop/Component", "src/CoreShop/Bundle"),
          str(CORESHOP_BEHAT.prod_paths))
    from ..core.boundary import load_boundary as _load_boundary
    sylius_row = behat_project(_load_boundary(
        os.path.join(BENCHMARK_ROOT, "config", "boundary_sylius.yml")))
    check("the reviewed Sylius boundary declares its own three production "
          "roots, which is what its population is now enumerated over",
          sylius_row.prod_paths == ("src/Sylius/Component",
                                    "src/Sylius/Bundle",
                                    "src/Sylius/Abstraction"),
          str(sylius_row.prod_paths))
    # ...and, under the owner's 2026-09-11 ruling, which parts of those
    # roots are not PRODUCT code.  The boundary above cannot answer that:
    # `removable`/`retained` say which files are the Behat glue, and a
    # component's own unit test is not glue, so all 31,004 of them arrived
    # classified `production` and the scored role excluded nothing.
    # Both spellings of each kind: the ruling names unit tests, migrations,
    # configuration and fixtures, and Sylius writes `test/` for its 26
    # per-bundle test applications and `Test/` for the covered default-channel
    # factory as well as the plural forms.
    check("...and the fragments inside those roots whose mutants the owner "
          "ruled out of the population, while CoreShop names none",
          sylius_row.mutation_exclude == (
              "tests/", "Tests/", "test/", "Test/", "spec/", "Migrations/",
              "Resources/config/", "config/", "Fixture/")
          and CORESHOP_BEHAT.mutation_exclude == (),
          str(sylius_row.mutation_exclude))
    # `prod_paths:` written with no value used to reach the row as None,
    # and the population producer had to refuse THAT shape too.  It is
    # refused where the row is read now, with the other five list rows --
    # checked below, where `row_refusal` is in scope.
    # `exclusions_for_prod_paths` still refuses an empty root tuple, which
    # is what `prod_paths: []` produces.

    partial = _B(version=1, project="sylius", repo_root="/x",
                 removable=[], retained=[],
                 raw={"behat": {"app_env": "test_cached",
                                "suite_scoped": True,
                                "psr4": {"Sylius\\Behat\\": "src/Sylius/Behat/"},
                                "index_paths": ["src/Sylius/Behat"],
                                "substrate_volatile": ["_bench/item.feature"],
                                "bootstrap": None}})
    row = behat_project(partial)
    check("a partial block overrides only what it names",
          row.app_env == "test_cached" and row.suite_scoped is True
          and row.bootstrap is None
          and row.kernel_class == CORESHOP_BEHAT.kernel_class
          and row.db_dsn_env == CORESHOP_BEHAT.db_dsn_env,
          str(row.kernel_class))
    check("a YAML mapping becomes the PSR-4 pair list, and YAML lists "
          "become the tuple/frozenset the row is declared as",
          row.psr4 == (("Sylius\\Behat\\", "src/Sylius/Behat/"),)
          and row.index_paths == ("src/Sylius/Behat",)
          and row.substrate_volatile == frozenset({"_bench/item.feature"}),
          str(row.psr4))

    # The reset probe and the §3.2 probe are per-project PROGRAMS, and a row
    # left at its default is CoreShop's program on CoreShop's tables.
    check("a boundary that names no reset row runs CoreShop's program, from "
          "CoreShop's path, over CoreShop's two tables",
          (CORESHOP_BEHAT.reset_program, CORESHOP_BEHAT.reset_control_table,
           CORESHOP_BEHAT.reset_marker_table, CORESHOP_BEHAT.probe_table)
          == ("pimcore", "versions", "objects", ("objects", "users"))
          and CORESHOP_BEHAT.reset_context_rel.startswith(
              CORESHOP_BEHAT.stub_dir.rsplit("/", 1)[0] + "/")
          and row.reset_program == "pimcore",
          str(CORESHOP_BEHAT.probe_table))
    reset_row = behat_project(_B(
        version=1, project="sylius", repo_root="/x", removable=[],
        retained=[], raw={"behat": {"reset_program": "doctrine",
                                    "reset_control_table": "sylius_migrations",
                                    "reset_marker_table": "sylius_channel",
                                    "probe_table": "sylius_channel"}}))
    check("...and a project that names ONE probe table writes it as the "
          "scalar it is, while a pair stays a pair",
          reset_row.probe_table == ("sylius_channel",)
          and behat_project(_B(
              version=1, project="sylius", repo_root="/x", removable=[],
              retained=[], raw={"behat": {"probe_table": ["a", "b"]}}
          )).probe_table == ("a", "b")
          and reset_row.reset_program == "doctrine"
          and reset_row.reset_control_table == "sylius_migrations",
          str(reset_row.probe_table))

    def row_refusal(block):
        try:
            behat_project(_B(version=1, project="sylius", repo_root="/x",
                             removable=[], retained=[], raw={"behat": block}))
            return "accepted"
        except SystemExit as exc:
            return str(exc)

    check("an unknown key is REFUSED rather than ignored -- a typo there is "
          "a row that silently keeps the wrong default",
          "kernal_class" in row_refusal({"kernal_class": "App\\Kernel"})
          and "not a row of BehatProject"
          in row_refusal({"kernal_class": "App\\Kernel"}),
          row_refusal({"kernal_class": "App\\Kernel"}))
    check("...and so is a block that is not a mapping",
          "not a mapping" in row_refusal(["app_env"]),
          row_refusal(["app_env"]))
    # The row is indexed by `dbadmin.db_probe_php`, so an empty one is an
    # IndexError raised from inside the script builder rather than a boundary
    # refused by name.
    empty_probe = row_refusal({"probe_table": []})
    check("...and so is an empty `probe_table`, which would otherwise reach "
          "the probe renderer as an IndexError naming no boundary",
          empty_probe.startswith("REFUSED:")
          and "probe_table" in empty_probe and "empty" in empty_probe,
          empty_probe)

    # Behat 4 refuses a YAML config by NAME, so the format and the file name
    # are one row and the set of formats is closed.
    check("a boundary that names no format writes CoreShop's YAML, under "
          "CoreShop's name",
          CORESHOP_BEHAT.bench_config_format == "yaml"
          and CORESHOP_BEHAT.bench_config == BENCH_CONFIG == "bench.behat.yml",
          CORESHOP_BEHAT.bench_config)
    php_cfg = behat_project(_B(
        version=1, project="sylius", repo_root="/x", removable=[],
        retained=[], raw={"behat": {"bench_config_format": "php"}}))
    check("...and a Behat 4 row moves the name with the format, because the "
          "loader picks its parser from the extension alone",
          php_cfg.bench_config == BENCH_CONFIG_PHP == "bench.behat.php",
          php_cfg.bench_config)
    bad_fmt = row_refusal({"bench_config_format": "yml"})
    check("...and a format outside the closed set is refused here rather "
          "than defaulting to YAML on a Behat that refuses YAML",
          bad_fmt.startswith("REFUSED:") and "bench_config_format" in bad_fmt
          and "'php'" in bad_fmt and "'yaml'" in bad_fmt, bad_fmt)

    # `hook_style` is closed for the same reason, and with a worse failure
    # if it were not: a Behat 4 project left on the docblock spelling RUNS,
    # prints a scenario count, and records nothing.
    bad_hook = row_refusal({"hook_style": "attributes"})
    check("a hook style outside the closed set is refused where the row is "
          "read, not where the empty record file is",
          bad_hook.startswith("REFUSED:") and "hook_style" in bad_hook
          and "'annotation'" in bad_hook and "'attribute'" in bad_hook,
          bad_hook)
    # `coverage_filter` is closed for a WORSE reason still: the recorder
    # catches the undefined-method Error itself, so a wrong value is one
    # line of stderr and a whole project scored with no coverage.
    bad_cov = row_refusal({"coverage_filter": "file"})
    check("a coverage-filter API outside the closed set is refused where the "
          "row is read -- the recorder's own catch would otherwise turn it "
          "into a run with null coverage and null `direct_calls`",
          bad_cov.startswith("REFUSED:") and "coverage_filter" in bad_cov
          and "'directory'" in bad_cov and "'files'" in bad_cov, bad_cov)
    # `tester_error_reporting` is closed by NAME rather than by value set,
    # because its vocabulary is PHP's error constants.  Nothing downstream
    # can catch a bad one: PHP raises `Undefined constant` while it loads the
    # profile, and the YAML spelling has no constant to resolve at all.
    check("no project says anything about error reporting by default, which "
          "is what leaves CoreShop's profile byte-identical",
          CORESHOP_BEHAT.tester_error_reporting is None)
    check("upstream's Sylius expression is the mask that masks exactly the "
          "two deprecation levels -- `E_ALL` minus 8192 and 16384",
          error_reporting_int("E_ALL & ~(E_DEPRECATED | E_USER_DEPRECATED)",
                              "sylius") == 32767 - 8192 - 16384 == 8191)
    bad_const = row_refusal(
        {"tester_error_reporting": "E_ALL & ~E_DEPRACATED"})
    check("a constant PHP does not have is refused BY NAME where the row is "
          "read, not as an `Undefined constant` in every container",
          bad_const.startswith("REFUSED:") and "E_DEPRACATED" in bad_const
          and "tester_error_reporting" in bad_const, bad_const)
    bad_token = row_refusal(
        {"tester_error_reporting": "E_ALL & shell_exec('id')"})
    check("...and so is anything outside the vocabulary, quoted back",
          bad_token.startswith("REFUSED:") and "shell_exec" in bad_token,
          bad_token)
    bad_shape = row_refusal({"tester_error_reporting": 8191})
    check("...and an integer, which is a level PHP would accept but not the "
          "expression this row renders",
          bad_shape.startswith("REFUSED:") and "int" in bad_shape, bad_shape)
    bad_expr = row_refusal({"tester_error_reporting": "E_ALL E_NOTICE"})
    check("...and known tokens that do not form an expression, which PHP "
          "would not parse either",
          bad_expr.startswith("REFUSED:") and "expression" in bad_expr,
          bad_expr)

    # Settings for an extension the project does not register are dropped in
    # silence by the renderer -- and a mistyped class name is exactly how
    # that happens, on rows whose values are all class names.
    stray = row_refusal({"extension_settings": {"Behat\\Nope": {"a": 1}}})
    check("...and `extension_settings` for an extension `extensions` does "
          "not name is refused rather than silently dropped",
          stray.startswith("REFUSED:") and "Nope" in stray
          and "extension_settings" in stray, stray)
    settings_row = behat_project(_B(
        version=1, project="sylius", repo_root="/x", removable=[],
        retained=[], raw={"behat": {
            "extensions": ["A\\B", "C\\D"],
            "extension_settings": {"C\\D": {"directory": "etc/build"}}}}))
    check("...while a declared one is carried as `(name, settings)` pairs in "
          "the boundary's order, the way `psr4` is",
          settings_row.extension_settings
          == (("C\\D", {"directory": "etc/build"}),)
          and CORESHOP_BEHAT.extension_settings == (),
          str(settings_row.extension_settings))

    # The SHAPE of a list row.  A row written as a scalar is not a
    # one-element list: `tuple("src/X")` is a tuple of characters, and the
    # readers of these rows all treat "matched nothing" as an answer -- so
    # `prod_paths: src/Sylius/Component` would be a mutation population of
    # zero reported as a project with no mutable code.  Refused by name,
    # here, where the row is read.
    for shape_row in ("prod_paths", "index_paths", "extensions",
                      "substrate_roots", "arm_suite_prefixes",
                      "substrate_volatile", "mutation_exclude"):
        scalar = row_refusal({shape_row: "src/Sylius/Component"})
        check(f"a scalar `{shape_row}` is REFUSED by name rather than read "
              f"character by character",
              scalar.startswith("REFUSED:") and f"`{shape_row}:" in scalar
              and "a YAML list" in scalar, scalar)
    shaped_row = behat_project(_B(
        version=1, project="sylius", repo_root="/x", removable=[],
        retained=[], raw={"behat": {
            "prod_paths": ["src/Sylius/Component"],
            "index_paths": ["src/Sylius/Behat"],
            "extensions": ["A\\B"],
            "substrate_roots": ["src", "_bench"],
            "arm_suite_prefixes": ["src/Sylius/Behat/suites/api/"],
            "mutation_exclude": ["tests/", "Resources/config/"],
            "substrate_volatile": ["_bench/item.feature"]}}))
    check("...while the YAML list every boundary on disk writes is carried "
          "through as the tuple -- or frozenset -- the field declares",
          (shaped_row.prod_paths, shaped_row.index_paths,
           shaped_row.extensions, shaped_row.substrate_roots,
           shaped_row.arm_suite_prefixes, shaped_row.mutation_exclude)
          == (("src/Sylius/Component",), ("src/Sylius/Behat",), ("A\\B",),
              ("src", "_bench"), ("src/Sylius/Behat/suites/api/",),
              ("tests/", "Resources/config/"))
          and shaped_row.substrate_volatile
          == frozenset({"_bench/item.feature"}),
          str(shaped_row.prod_paths))
    check("...and the shape check moves no CoreShop row: an empty block is "
          "still THE default object, and every checked row still holds the "
          "value it was declared with",
          behat_project(plain) is CORESHOP_BEHAT
          and (CORESHOP_BEHAT.prod_paths, CORESHOP_BEHAT.index_paths,
               CORESHOP_BEHAT.extensions, CORESHOP_BEHAT.arm_suite_prefixes)
          == (("src/CoreShop/Component", "src/CoreShop/Bundle"),
              ("src/CoreShop/Behat", "src/CoreShop/Bundle/TestBundle"),
              ("FriendsOfBehat\\SymfonyExtension",), None)
          and CORESHOP_BEHAT.substrate_roots == SUBSTRATE_ROOTS
          and CORESHOP_BEHAT.substrate_volatile == SUBSTRATE_VOLATILE
          and CORESHOP_BEHAT.extension_settings == (),
          str(CORESHOP_BEHAT.prod_paths))
    # `mutation_exclude` is the one list row whose ELEMENTS decide what is
    # matched rather than what is named: its strings are runs of directory
    # segments, and a fragment naming none is a ZERO-LENGTH run -- a
    # subsequence of every path.  Written by accident it would take the
    # whole population out of the scored role, and a population of zero is
    # a number that validates all the way to the mint.
    for empty_fragment in ([""], ["tests/", ""], ["/"], [None], ["//"]):
        blank = row_refusal({"mutation_exclude": empty_fragment})
        check("an empty `mutation_exclude` fragment is REFUSED by name -- "
              f"{empty_fragment!r} would exclude every path, not none",
              blank.startswith("REFUSED:")
              and "`mutation_exclude`" in blank
              and "names no directory segment" in blank, blank)
    settings_list = row_refusal({"extensions": ["A\\B"],
                                 "extension_settings": ["A\\B"]})
    check("...and `extension_settings` written as a LIST is refused by that "
          "same door, rather than raising a bare TypeError out of the "
          "comprehension that indexes it by class name",
          settings_list.startswith("REFUSED:")
          and "`extension_settings:" in settings_list
          and "a YAML mapping" in settings_list, settings_list)

    # And `row: ~`, which the coercion did not use to see at all -- the
    # dispatch skipped it and handed None straight to the field.  None of
    # these fields is Optional, so that None reaches every reader as None
    # and dies in whichever one iterates or indexes it first, with a bare
    # TypeError naming neither the boundary nor the row.  `prod_paths` is
    # the one row that had a consumer-side guard for it
    # (`exclusions_for_prod_paths`, which the mutation population is built
    # through); the other five had none.
    for null_row in ("prod_paths", "index_paths", "extensions",
                     "substrate_roots", "substrate_volatile",
                     "extension_settings", "mutation_exclude"):
        wrote_null = row_refusal({null_row: None})
        check(f"a null `{null_row}` is REFUSED by name rather than carried "
              f"through to whichever reader iterates it first",
              wrote_null.startswith("REFUSED:")
              and f"`{null_row}`" in wrote_null
              and "not Optional" in wrote_null, wrote_null)
    null_prefixes = behat_project(_B(
        version=1, project="sylius", repo_root="/x", removable=[],
        retained=[], raw={"behat": {"arm_suite_prefixes": None}}))
    check("...while `arm_suite_prefixes: ~` still yields None, because "
          "THAT field is Optional and its None is a reading: an arm suite "
          "is any suite whose own config file is removable",
          null_prefixes.arm_suite_prefixes is None,
          str(null_prefixes.arm_suite_prefixes))

    # The import trio: which file imports the wiring the strip removes, and
    # what that import becomes.  A row may drop all three (a project whose
    # test configuration never imported it) but not one or two -- half of it
    # is a strip that patches nothing while still carrying CoreShop's paths,
    # or one that patches a file it was told not to have.
    half = row_refusal({"test_config": None})
    check("a half-declared import trio is refused, naming which side is "
          "missing",
          "test_config" in half and "original_services_import" in half
          and "one fact" in half, half)
    check("...in either direction",
          "bench_services_import" in row_refusal(
              {"test_config": None, "original_services_import": None}))
    nodi_row = behat_project(_B(
        version=1, project="prestashop", repo_root="/x", removable=[],
        retained=[], raw={"behat": {"services_entry": None,
                                    "hook_services": None,
                                    "test_config": None,
                                    "original_services_import": None,
                                    "bench_services_import": None}}))
    check("...and dropping all three, with no services file either, is a "
          "project with no Symfony wiring rather than a refusal",
          nodi_row.services_entry is None and nodi_row.test_config is None
          and nodi_row.suites_entry == CORESHOP_BEHAT.suites_entry)

    check("the PSR-4 lookup is prefix -> DIRECTORY, so a root whose "
          "directory does not mirror its namespace still resolves",
          _class_path_guess("Sylius\\Abstraction\\StateMachine\\Foo\\Bar",
                            (("Sylius\\Abstraction\\StateMachine\\",
                              "src/Sylius/Abstraction/StateMachine/src/"),))
          == "src/Sylius/Abstraction/StateMachine/src/Foo/Bar.php"
          and _class_path_guess("CoreShop\\Behat\\Context\\Domain\\CartContext")
          == "src/CoreShop/Behat/Context/Domain/CartContext.php")

    # -- the recorder the shipped template becomes, per row.  Against the
    #    REAL template, because that is what a project gets and what the
    #    CoreShop seed already carries.
    template_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "php", "BenchRecorderHook.php")
    with open(template_path, encoding="utf-8") as fh:
        template = fh.read()
    check("[recorder] CoreShop's copy IS the template, byte for byte -- a "
          "row may not move the bytes that are already in its seed",
          recorder_source(template, CORESHOP_BEHAT) == template)
    attr = recorder_source(template, replace(CORESHOP_BEHAT,
                                             hook_style="attribute"))
    check("[recorder] ...and a `hook_style: attribute` row rewrites all five "
          "declarations into `Behat\\Hook` attributes, leaving no docblock "
          "hook tag behind -- Behat 4 has no annotation reader, so a missed "
          "one is a hook that never fires and an item scored "
          "`no_scenario_ran`",
          all(f"    #[\\Behat\\Hook\\{hook}]\n" in attr
              for hook in ("BeforeSuite", "BeforeScenario", "BeforeStep",
                           "AfterStep", "AfterScenario"))
          and not re.search(r"^\s*(/\*\*|\*)\s*@(Before|After)"
                            r"(Suite|Scenario|Step)\b", attr, re.M),
          attr[:400])
    check("[recorder] ...and only the hook lines move: `bootRecorder` stays "
          "`public static` (Behat binds a suite hook against an "
          "UNINITIALIZED environment, so a non-static one throws), the "
          "namespace is untouched by this row, and the AfterStep docblock "
          "survives as the hook's description",
          "public static function bootRecorder(): void" in attr
          and "namespace CoreShop\\Behat\\Bench;" in attr
          and "Behat's TestResult codes are 0/10/20/30/99" in attr
          # The AfterStep tag was a line INSIDE a docblock, so exactly one
          # line is dropped; the other four are swapped one for one.
          and attr.count("\n") == template.count("\n") - 1,
          str((attr.count("\n"), template.count("\n"))))

    def hook_refusal(broken):
        try:
            return recorder_source(broken, replace(CORESHOP_BEHAT,
                                                   hook_style="attribute"))
        except SystemExit as exc:
            return str(exc)

    moved = hook_refusal(template.replace("    /** @BeforeStep */\n", ""))
    check("[recorder] a template whose hook lines have moved is REFUSED "
          "rather than installed with a hook that cannot fire -- silence "
          "here costs a live run to notice",
          moved.startswith("REFUSED:")
          and "cannot be rewritten as the PHP attributes" in moved, moved)

    # The coverage filter, the third rewrite.  CoreShop's `directory` row is
    # already covered by "the CoreShop copy IS the template" above; this is
    # the `files` rendering a php-code-coverage 12 project needs.
    files_src = recorder_source(template, replace(CORESHOP_BEHAT,
                                                  coverage_filter="files"))
    check("[recorder] a `coverage_filter: files` row rewrites the one "
          "`includeDirectory` call into php-file-iterator's enumeration plus "
          "`includeFiles`, leaving no `includeDirectory` behind -- "
          "php-code-coverage 11 removed that method, and the recorder's own "
          "`catch (\\Throwable)` would turn the call into one line of stderr "
          "and a project scored with null coverage and null `direct_calls`",
          "includeDirectory" not in files_src
          and "$filter->includeFiles($files);" in files_src
          and "\\SebastianBergmann\\FileIterator\\Facade" in files_src
          and "->getFilesAsArray(self::$root . '/src', '.php');" in files_src,
          files_src[files_src.find("BENCH_COVERAGE"):][:400])
    check("[recorder] ...and nothing else moves with it: the filter is still "
          "built and handed to the same collector inside the same try, and "
          "the two rewrites compose on the Sylius row",
          "$filter = new Filter();" in files_src
          and "new CodeCoverage((new Selector())->forLineCoverage($filter), "
              "$filter)" in files_src
          and template.count("\n") + 2 == files_src.count("\n")
          and "#[\\Behat\\Hook\\BeforeSuite]" in recorder_source(
              template, replace(CORESHOP_BEHAT, hook_style="attribute",
                                coverage_filter="files")),
          str((template.count("\n"), files_src.count("\n"))))

    def cov_refusal(broken):
        try:
            return recorder_source(broken, replace(CORESHOP_BEHAT,
                                                   coverage_filter="files"))
        except SystemExit as exc:
            return str(exc)

    gone = cov_refusal(template.replace(
        "$filter->includeDirectory(self::$root . '/src');", "// gone"))
    check("[recorder] ...and a template whose filter line has moved is "
          "REFUSED rather than installed unrewritten -- the recorder cannot "
          "report that failure itself",
          gone.startswith("REFUSED:")
          and "coverage filter cannot be rewritten" in gone, gone)

    # The generated roots, the row the V2-D1(a) credit reads: a call into a
    # class the framework generates is credited to the first-party contract
    # method it implements, and WHICH directories hold generated classes is
    # the project's to say.
    rooted = recorder_source(template, replace(
        CORESHOP_BEHAT, callee_roots=("src", "classes"),
        generated_roots=("var/generated",)))
    check("[recorder] a project's own generated roots replace CoreShop's, "
          "and the first-party test the credit applies to an ancestor is the "
          "SAME one the production fence uses",
          "private static array $generatedRoots = [\"var/generated\"];" in rooted
          and "['var/classes', 'var/cache']" not in rooted
          and ("            return strncmp($file, $root . \"/src/\", "
               "strlen($root . \"/src/\")) === 0 || strncmp($file, $root . "
               "\"/classes/\", strlen($root . \"/classes/\")) === 0;") in rooted
          and rooted.count("\n") == template.count("\n"),
          rooted[rooted.find("$generatedRoots"):][:120])
    check("[recorder] ...a project whose framework generates nothing says so "
          "with an empty list, which is a row and not a missing one",
          "private static array $generatedRoots = [];" in recorder_source(
              template, replace(CORESHOP_BEHAT, generated_roots=())))

    def generated_refusal(broken):
        try:
            return recorder_source(broken, replace(CORESHOP_BEHAT,
                                                   generated_roots=("var/x",)))
        except SystemExit as exc:
            return str(exc)

    moved_roots = generated_refusal(template.replace(
        "['var/classes', 'var/cache']", "[]"))
    check("[recorder] ...and a template whose generated-roots literal has "
          "moved is REFUSED rather than installed with CoreShop's roots -- "
          "the recorder would credit this project's generated calls to "
          "contracts it does not have, or drop them",
          moved_roots.startswith("REFUSED:")
          and "generated roots" in moved_roots, moved_roots)

    # A PHP-configurator project's strip, on a tree small enough to read.
    # Every claim below is a thing repo-wide removal BREAKS for such a
    # project and the strip has to put back.
    with tempfile.TemporaryDirectory() as root:
        def write(rel, text):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        cfg = "src/Sylius/Behat/Resources/config"
        write("features/api/address_book.feature",
              "@api\nFeature: Address book\n\n  @address_book\n"
              "  Scenario: Add\n    When I add an address\n")
        write("config/services_test.yaml",
              "imports:\n"
              "    - { resource: ../src/Sylius/Behat/Resources/config/"
              "services.php }\n")
        write(f"{cfg}/services.php", """<?php
return static function ($container) {
    $container->import('services/contexts.php');
};
""")
        write(f"{cfg}/services/contexts.php", """<?php
return static function ($container) {
    $container->import('contexts/api.php');
    $container->import('contexts/hook.php');
    $container->import('contexts/setup.php');
};
""")
        write(f"{cfg}/services/contexts/api.php", """<?php
use Sylius\\Behat\\Context\\Api\\Shop\\AddressContext;
return static function ($container) {
    $container->services()
        ->set('sylius.behat.context.api.shop.address', AddressContext::class);
};
""")
        write(f"{cfg}/services/contexts/hook.php", """<?php
use Sylius\\Behat\\Context\\Hook\\DoctrineORMContext;
return static function ($container) {
    $container->services()
        ->set('sylius.behat.context.hook.doctrine_orm',
              DoctrineORMContext::class);
};
""")
        write(f"{cfg}/services/contexts/setup.php", """<?php
use Sylius\\Behat\\Context\\Setup\\AddressContext;
return static function ($container) {
    $container->services()
        ->set('sylius.behat.context.setup.address', AddressContext::class);
};
""")
        write(f"{cfg}/suites.php", """<?php
use Behat\\Config\\Config;
return (new Config())->import(['suites/api.php', 'suites/ui.php']);
""")
        write(f"{cfg}/suites/api.php", """<?php
use Behat\\Config\\Config;
return (new Config())->import(['api/address_book.php']);
""")
        write(f"{cfg}/suites/api/address_book.php", """<?php
use Behat\\Config\\Config;
use Behat\\Config\\Filter\\TagFilter;
use Behat\\Config\\Profile;
use Behat\\Config\\Suite;
return (new Config())
    ->withProfile((new Profile('default'))->withSuite(
        (new Suite('api_address_book', ['javascript' => false]))
            ->withContexts('sylius.behat.context.hook.doctrine_orm',
                           'sylius.behat.context.setup.address',
                           'sylius.behat.context.api.shop.address')
            ->withFilter(new TagFilter('@address_book&&@api')),
    ));
""")
        write(f"{cfg}/suites/ui.php", """<?php
use Behat\\Config\\Config;
use Behat\\Config\\Filter\\TagFilter;
use Behat\\Config\\Profile;
use Behat\\Config\\Suite;
return (new Config())
    ->withProfile((new Profile('default'))->withSuite(
        (new Suite('ui_address_book', []))
            ->withContexts('sylius.behat.context.setup.address')
            ->withFilter(new TagFilter('@address_book&&@ui')),
    ));
""")
        write("src/Sylius/Behat/Context/Api/Shop/AddressContext.php",
              "<?php\nnamespace Sylius\\Behat\\Context\\Api\\Shop;\n"
              "class AddressContext {}\n")
        write("src/Sylius/Behat/Context/Setup/AddressContext.php",
              "<?php\nnamespace Sylius\\Behat\\Context\\Setup;\n"
              "class AddressContext {}\n")
        write("src/Sylius/Behat/Context/Hook/DoctrineORMContext.php",
              "<?php\nnamespace Sylius\\Behat\\Context\\Hook;\n"
              "class DoctrineORMContext {}\n")
        write("src/Sylius/Component/Order/Model/Order.php",
              "<?php\nnamespace Sylius\\Component\\Order\\Model;\n"
              "class Order {}\n")

        harness_php = os.path.join(root, "_harness_php")
        os.makedirs(harness_php)
        with open(os.path.join(harness_php, "BenchRecorderHook.php"), "w",
                  encoding="utf-8") as fh:
            fh.write("<?php\n\ndeclare(strict_types=1);\n\n"
                     "namespace CoreShop\\Behat\\Bench;\n\n"
                     "final class BenchRecorderHook {}\n")

        sb = Boundary(
            version=1, project="sylius", repo_root=root,
            removable=[("src/Sylius/Behat/Context/Api/", ""),
                       (f"{cfg}/suites/api/", ""),
                       (f"{cfg}/services/contexts/api.php", "")],
            retained=[("src/Sylius/Behat/Context/Setup/", ""),
                      ("src/Sylius/Behat/Context/Hook/", "")],
            removable_config=[f"{cfg}/suites/api/",
                              f"{cfg}/services/contexts/api.php"],
            raw={"behat": {
                "config_dir": cfg,
                "config_format": "php",
                "services_entry": "services.php",
                "suites_entry": "suites.php",
                "test_config": "config/services_test.yaml",
                "original_services_import":
                    "../src/Sylius/Behat/Resources/config/services.php",
                "bench_services_import": "../_bench/services.yml",
                "suite_root": "features",
                "recorder_rel": "src/Sylius/Behat/Bench/BenchRecorderHook.php",
                "recorder_namespace": "Sylius\\Behat\\Bench",
                "psr4": {"Sylius\\Behat\\": "src/Sylius/Behat/",
                         "Sylius\\Component\\": "src/Sylius/Component/"},
                "substrate_roots": ["src", "config", BENCH_DIR],
                "substrate_volatile": [f"{BENCH_DIR}/run_record.jsonl"],
                "suite_scoped": True}})
        gold = os.path.join(root, "_gold")
        man = strip_repo(sb, gold, harness_php)

        from ..toolkit.behat_suites import SUITE_MAP_NAME

        def shape_refusal(suite_root):
            other = Boundary(**{**sb.__dict__,
                                "raw": {"behat": dict(sb.raw["behat"],
                                                      suite_root=suite_root)}})
            try:
                strip_repo(other, os.path.join(root, "_gold2"), harness_php)
                return "accepted"
            except SystemExit as exc:
                return str(exc)

        check("[php] the shape check is the ROW's suite root, and the "
              "refusal names the project and the directory it wanted",
              "does not look like sylius: no features/domain/"
              in shape_refusal("features/domain"),
              shape_refusal("features/domain"))
        check("[php] the arm's context config and suite files are moved into "
              "gold, and the retained ones are not",
              f"{cfg}/services/contexts/api.php" in man.moved_config
              and f"{cfg}/suites/api/address_book.php" in man.moved_config
              and not os.path.exists(
                  os.path.join(root, cfg, "services/contexts/api.php"))
              and os.path.isfile(
                  os.path.join(root, cfg, "services/contexts/hook.php")),
              str(man.moved_config))
        test_cfg_now = open(os.path.join(root, "config/services_test.yaml"),
                            encoding="utf-8").read()
        check("[php] the test config's import is redirected to the "
              "harness's own services file",
              "../_bench/services.yml" in test_cfg_now
              and "config/services_test.yaml" in man.patched,
              test_cfg_now)
        contexts_now = open(
            os.path.join(root, cfg, "services/contexts.php"),
            encoding="utf-8").read()
        check("[php] the RETAINED importer loses exactly the import lines "
              "whose target the strip removed -- without that the stripped "
              "kernel dies in `import()` before any scenario runs",
              "contexts/api.php" not in contexts_now
              and "contexts/hook.php" in contexts_now
              and "contexts/setup.php" in contexts_now
              and f"{cfg}/services/contexts.php" in man.patched,
              contexts_now)
        channel = open(os.path.join(root, BENCH_DIR, "services.yml"),
                       encoding="utf-8").read()
        check("[php] the registration channel imports the retained substrate "
              "FIRST and the item's fragment second -- the order is what "
              "lets a solution's definition win, and it is the same bytes "
              "CoreShop's strip writes",
              channel == "imports:\n"
                         "    - { resource: retained_services.yml }\n"
                         "    - { resource: services_item.yml }\n", channel)
        bench_services = open(
            os.path.join(root, BENCH_DIR, "retained_services.yml"),
            encoding="utf-8").read()
        check("[php] the harness's services file re-imports the configurator "
              "tree rather than re-emitting it -- only the arm was removed",
              "resource: ../src/Sylius/Behat/Resources/config/services.php"
              in bench_services, bench_services)
        recorder = open(
            os.path.join(root, "src/Sylius/Behat/Bench/BenchRecorderHook.php"),
            encoding="utf-8").read()
        check("[php] the recorder is installed under THIS project's Behat "
              "root with its namespace rewritten -- it autoloads through the "
              "project's own PSR-4 root or not at all",
              "namespace Sylius\\Behat\\Bench;" in recorder
              and "CoreShop" not in recorder, recorder)
        smap = json.load(open(os.path.join(gold, SUITE_MAP_NAME),
                              encoding="utf-8"))
        check("[php] the suite map is captured BEFORE the files move, into "
              "the GOLD tree beside `strip_manifest.json`",
              set(smap["suites"]) == {"api_address_book", "ui_address_book"}
              and smap["project"] == "sylius"
              and os.path.isfile(os.path.join(gold, "strip_manifest.json")),
              str(sorted(smap["suites"])))
        # Owner ruling 2026-09-10.  The `removable` entry checked three
        # checks below is the reason: that list IS the set of answer files
        # the agent is asked to write, so a copy under `_bench` shipped it
        # in `workspace.tar` to every worker and into the agent seed.
        check("[php] ...and the stripped workspace is LEFT with no copy of "
              "it under `_bench` -- the map is evidence, and the workspace "
              "is what the agent reads (`strip_repo` has already run its "
              "sanitise pass here, so this is the end state, not the "
              "write)",
              not os.path.exists(
                  os.path.join(root, BENCH_DIR, SUITE_MAP_NAME))
              and f"{BENCH_DIR}/{SUITE_MAP_NAME}" not in man.installed,
              str(man.installed))
        check("[php] ...and the manifest records it as gold content, the "
              "way `sanitise_repo` records what it moves there -- an arrow, "
              "not a path the workspace is supposed to have",
              f"{SUITE_MAP_NAME} -> gold/" in man.installed
              and SUITE_MAP_NAME in _EXTRACTION_ARTIFACTS,
              str(man.installed))
        check("[php] the arm's suite is the one whose config file the strip "
              "removed",
              smap["suites"]["api_address_book"]["arm"] is True
              and smap["suites"]["ui_address_book"]["arm"] is False)
        check("[php] a suite's retained context ids are separated from the "
              "ids the system under test has to supply",
              smap["suites"]["api_address_book"]["retained"]
              == ["sylius.behat.context.hook.doctrine_orm",
                  "sylius.behat.context.setup.address"]
              and smap["suites"]["api_address_book"]["removable"]
              == ["sylius.behat.context.api.shop.address"],
              str(smap["suites"]["api_address_book"]))
        check("[php] the gold copy is the ONE copy, and it is what "
              "`closures` reads once the config tree has left the "
              "repository",
              json.load(open(os.path.join(gold, SUITE_MAP_NAME),
                             encoding="utf-8")) == smap)
        check("[php] the manifest records THIS project's substrate roots, "
              "not CoreShop's",
              man.roots() == ("src", "config", BENCH_DIR)
              and man.volatile() == frozenset({f"{BENCH_DIR}/run_record.jsonl"}))

    # A project with NO Behat Symfony wiring at all (PrestaShop's shape:
    # YAML suites naming their contexts by class, a bootstrap, and no
    # services file for the removal to take anything out of).  Each check
    # below is a step the strip performs for CoreShop and must SKIP here,
    # plus the steps it must still perform.
    from ..toolkit.behat_suites import SUITE_MAP_NAME, select_suite
    with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as nodi_gold:
        def write(rel, text):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        beh = "tests/Integration/Behaviour"
        ctx = f"{beh}/Features/Context"
        write(f"{beh}/Features/Scenario/cart/cart.feature",
              "Feature: Cart\n\n  Scenario: Add\n    When I add a product\n")
        write(f"{beh}/behat.yml", f"""default:
  suites:
    cart:
      paths: [ '%paths.base%/Features/Scenario/cart' ]
      contexts:
        - Tests\\Integration\\Behaviour\\Features\\Context\\CommonFeatureContext
        - Tests\\Integration\\Behaviour\\Features\\Context\\Domain\\CartContext
""")
        write(f"{beh}/bootstrap.php", "<?php\n// boots the installed shop\n")
        write(f"{ctx}/CommonFeatureContext.php",
              "<?php\nnamespace Tests\\Integration\\Behaviour\\Features"
              "\\Context;\nclass CommonFeatureContext {}\n")
        write(f"{ctx}/Domain/CartContext.php",
              "<?php\nnamespace Tests\\Integration\\Behaviour\\Features"
              "\\Context\\Domain;\nclass CartContext {}\n")
        write("src/Core/Cart/Cart.php",
              "<?php\nnamespace Core\\Cart;\nclass Cart {}\n")

        harness_php = os.path.join(root, "_harness_php")
        os.makedirs(harness_php)
        with open(os.path.join(harness_php, "BenchRecorderHook.php"), "w",
                  encoding="utf-8") as fh:
            fh.write("<?php\n\nnamespace CoreShop\\Behat\\Bench;\n\n"
                     "final class BenchRecorderHook {}\n")

        nodi = Boundary(
            version=1, project="prestashop", repo_root=root,
            removable=[(f"{ctx}/Domain/", ""), (f"{beh}/behat.yml", "")],
            retained=[(f"{ctx}/CommonFeatureContext.php", ""),
                      (f"{beh}/bootstrap.php", "")],
            removable_config=[f"{beh}/behat.yml"],
            raw={"behat": {
                "config_dir": beh,
                "services_entry": None,
                "hook_services": None,
                "suites_entry": "behat.yml",
                "test_config": None,
                "original_services_import": None,
                "bench_services_import": None,
                "suite_root": f"{beh}/Features/Scenario",
                "recorder_rel":
                    f"{beh}/Features/Bench/BenchRecorderHook.php",
                "recorder_namespace":
                    "Tests\\Integration\\Behaviour\\Features\\Bench",
                "psr4": {"Tests\\Integration\\Behaviour\\": f"{beh}/"},
                "bootstrap": "bootstrap.php",
                "substrate_roots": ["tests", "src", BENCH_DIR],
                "substrate_volatile": [f"{BENCH_DIR}/run_record.jsonl"],
                # Its suites DO partition the corpus -- by `paths`, not by
                # tags -- so which contexts a scenario runs under is its
                # suite's, exactly as on Sylius and for the same reason.
                "suite_scoped": True}})

        # The same tree stripped as a project whose suites do NOT partition
        # the corpus, which is CoreShop's row: no map is captured, and none
        # is installed.  Written as its own copy because the strip MOVES the
        # files it reads the suites from.
        with tempfile.TemporaryDirectory() as unscoped_base:
            unscoped_root = os.path.join(unscoped_base, "repo")
            shutil.copytree(root, unscoped_root)
            unscoped = Boundary(**{
                **nodi.__dict__, "repo_root": unscoped_root,
                "raw": {"behat": dict(nodi.raw["behat"],
                                      suite_scoped=False)}})
            uman = strip_repo(unscoped, os.path.join(unscoped_base, "_gold"),
                              os.path.join(unscoped_root, "_harness_php"))
            check("[no-DI] a project whose suites do not partition the "
                  "corpus gets NO suite map -- the capture is the row's "
                  "`suite_scoped`, not its config format, so CoreShop's "
                  "strip still installs exactly what it installed",
                  not os.path.exists(os.path.join(unscoped_root, BENCH_DIR,
                                                  SUITE_MAP_NAME))
                  and f"{SUITE_MAP_NAME} -> gold/" not in uman.installed
                  and not os.path.exists(os.path.join(unscoped_base, "_gold",
                                                      SUITE_MAP_NAME)),
                  str(uman.installed))

        nman = strip_repo(nodi, nodi_gold, harness_php)

        check("[no-DI] nothing is re-emitted, because removal took no "
              "service definition with it: no `retained_services.yml` on "
              "disk and none claimed in the manifest",
              not os.path.exists(
                  os.path.join(root, BENCH_DIR, "retained_services.yml"))
              and f"{BENCH_DIR}/retained_services.yml" not in nman.installed,
              str(nman.installed))
        channel = open(os.path.join(root, BENCH_DIR, "services.yml"),
                       encoding="utf-8").read()
        check("[no-DI] the registration channel is still written, with the "
              "item's fragment as its only import -- one channel on every "
              "project, inert where no kernel reads it",
              channel == "imports:\n    - { resource: services_item.yml }\n"
              and open(os.path.join(root, BENCH_DIR, "services_item.yml"),
                       encoding="utf-8").read() == "services: {}\n", channel)
        check("[no-DI] no test configuration is patched, and a project that "
              "has none is not refused for missing it",
              nman.patched == [], str(nman.patched))
        check("[no-DI] the rest of the strip is unchanged: the arm's context "
              "and the suite file move into gold, the retained context and "
              "the bootstrap stay",
              f"{ctx}/Domain/CartContext.php" in nman.moved
              and f"{beh}/behat.yml" in nman.moved_config
              and os.path.isfile(os.path.join(root, ctx,
                                              "CommonFeatureContext.php"))
              and os.path.isfile(os.path.join(root, beh, "bootstrap.php")),
              str((nman.moved, nman.moved_config)))
        recorder = open(os.path.join(root, beh,
                                     "Features/Bench/BenchRecorderHook.php"),
                        encoding="utf-8").read()
        check("[no-DI] the recorder is installed under THIS project's "
              "autoloadable root with its namespace rewritten",
              "namespace Tests\\Integration\\Behaviour\\Features"
              "\\Bench;" in recorder and "CoreShop" not in recorder,
              recorder)

        nsmap = json.load(open(os.path.join(nodi_gold, SUITE_MAP_NAME),
                               encoding="utf-8"))
        cart = nsmap["suites"]["cart"]
        check("[no-DI] the suite map is captured for a SUITE-SCOPED project "
              "whose config is YAML and which has no Symfony wiring at all "
              "-- it is the only record of the arm's suites once their file "
              "is in gold, and nothing else can answer which suite an item "
              "runs under",
              set(nsmap["suites"]) == {"cart"}
              and nsmap["project"] == "prestashop"
              and f"{SUITE_MAP_NAME} -> gold/" in nman.installed
              and not os.path.exists(
                  os.path.join(root, BENCH_DIR, SUITE_MAP_NAME))
              and cart["arm"] is True, str(nsmap))
        check("[no-DI] with no services file to resolve through, a context "
              "named by class IS its class, and the two sides of the "
              "boundary are still separated",
              cart["removable"] == ["Tests\\Integration\\Behaviour"
                                    "\\Features\\Context\\Domain"
                                    "\\CartContext"]
              and cart["retained"] == ["Tests\\Integration\\Behaviour"
                                       "\\Features\\Context"
                                       "\\CommonFeatureContext"]
              and cart["classes"] == {ref: ref for ref in cart["contexts"]},
              str(cart))
        check("[no-DI] the suite's `paths` are recorded repo-relative and "
              "select the item's feature file -- these suites carry no tag "
              "filter, so the path is the whole selector",
              cart["tag_filter"] is None
              and cart["paths"] == [f"{beh}/Features/Scenario/cart"]
              and select_suite(nsmap, [],
                               f"{beh}/Features/Scenario/cart/cart.feature")
              == "cart", str(cart["paths"]))
        check("[no-DI] ...and the second project shape puts it in gold too: "
              "the rule is the map's CONTENT, not one project's config "
              "format",
              os.path.isfile(os.path.join(nodi_gold, SUITE_MAP_NAME))
              and f"{BENCH_DIR}/{SUITE_MAP_NAME}" not in nman.installed,
              str(nman.installed))

    # Belt and braces for the trees stripped BEFORE the owner's 2026-09-10
    # ruling: every Sylius seed and pool cut so far carries
    # `_bench/suite_map.json`, and re-cutting one runs the sanitiser over
    # that workspace.  The map holds the answer without holding the code,
    # which is what `_EXTRACTION_ARTIFACTS` is.
    with tempfile.TemporaryDirectory() as stale_root:
        os.makedirs(os.path.join(stale_root, BENCH_DIR))
        with open(os.path.join(stale_root, BENCH_DIR, SUITE_MAP_NAME), "w",
                  encoding="utf-8") as fh:
            fh.write('{"schema": "r2t.behat-suite-map/1"}\n')
        stale_gold = os.path.join(stale_root, "_gold")
        swept = sanitise_repo(stale_root, stale_gold)
        check("a workspace stripped before the ruling still carries "
              f"`{BENCH_DIR}/{SUITE_MAP_NAME}`, and the sanitiser sweeps it "
              "out of the workspace into gold",
              not os.path.exists(os.path.join(stale_root, BENCH_DIR,
                                              SUITE_MAP_NAME))
              and os.path.isfile(os.path.join(stale_gold, "_extraction",
                                              SUITE_MAP_NAME))
              and f"{BENCH_DIR}/{SUITE_MAP_NAME} -> gold/_extraction"
              in swept, str(swept))
    # -- derived state (v1.1): the seed's generated class files go back to
    #    their seed bytes; anything ADDED stays; a symlink is refused; and a
    #    restore that does not take refuses instead of reporting success.
    import stat
    import subprocess

    def _raises(call, kind):
        try:
            call()
        except kind:
            return True
        return False

    with tempfile.TemporaryDirectory() as root:
        product = "var/classes/DataObject/P.php"
        listing = "var/classes/DataObject/P/Listing.php"
        definition = "var/classes/definition_P.php"
        seed_bytes = {
            product: b"<?php\nclass P {\npublic function getX(): array {}\n}\n",
            listing: b"<?php // listing\n",
            definition: b"<?php return ['modificationDate' => 1];\n"}

        def put(rel, data):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(data)

        def read(rel):
            with open(os.path.join(root, rel), "rb") as fh:
                return fh.read()

        class _ContainerRunner:
            """Runs the in-container command in the workspace, as the
            container's shell would after `cd workdir`; `act=False` is a
            container whose copy silently does nothing."""

            def __init__(self, act=True):
                self.act = act
                self.calls = []

            def run(self, inner, env=None, timeout=900):
                self.calls.append(inner)
                if not self.act:
                    return subprocess.CompletedProcess([], 0, "", "")
                return subprocess.run(["sh", "-c", inner], cwd=root,
                                      capture_output=True, text=True,
                                      timeout=timeout)

        for rel, data in seed_bytes.items():
            put(rel, data)
        check("[derived] the roots are CoreShop's var/classes and nothing "
              "for behave, cucumber or godog, and an unknown stack is refused",
              derived_state_roots("behat", behat=CORESHOP_BEHAT) == ("var/classes",)
              and derived_state_roots("behave") == ()
              and derived_state_roots("cucumber") == ()
              and derived_state_roots("godog") == ()
              and _raises(lambda: derived_state_roots("gradle"), ValueError)
              and _raises(lambda: derived_state_roots("behat"), ValueError)
              and _raises(lambda: derived_state_roots(
                  "behat", behat=replace(CORESHOP_BEHAT, reset_program="unknown")), ValueError))
        quiet = _ContainerRunner()
        check("[derived] a workspace at its seed bytes has no drift and a "
              "restore touches nothing",
              derived_state_drift(root, seed_bytes) == []
              and restore_derived_state(root, seed_bytes, quiet) == []
              and quiet.calls == [])

        # What psvi does under a return-type mutant, and what a scenario's
        # own class does beside it.
        put(product, b"<?php\nclass P {\npublic function getX() {}\n}\n")
        os.remove(os.path.join(root, listing))
        put("var/classes/definition_BehatX.php", b"<?php // a scenario's\n")
        host = _ContainerRunner()
        restored = restore_derived_state(root, seed_bytes, host)
        check("[derived] a CHANGED and a MISSING member are written back to "
              "their seed bytes from the host, and named",
              restored == [product, listing]
              and all(read(rel) == data for rel, data in seed_bytes.items())
              and host.calls == [], str(restored))
        check("[derived] an ADDED file under the root is left alone -- the "
              "Behat% purge owns it",
              read("var/classes/definition_BehatX.php")
              == b"<?php // a scenario's\n")
        check("[derived] a restored member has the mode the seed unpack gives "
              "it, whatever the umask",
              all(stat.S_IMODE(os.stat(os.path.join(root, rel)).st_mode)
                  == DERIVED_STATE_FILE_MODE for rel in (product, listing)))

        # A member the host cannot write (a root-owned directory under a
        # rootful daemon) goes through the container, from a staging area
        # that does not outlive the copy.
        host_writer = globals()["_write_seed_bytes"]

        def host_refuses(*_args):
            raise PermissionError(13, "Permission denied")

        put(product, b"<?php // regenerated as root\n")
        container = _ContainerRunner()
        globals()["_write_seed_bytes"] = host_refuses
        try:
            via_container = restore_derived_state(root, seed_bytes, container)
        finally:
            globals()["_write_seed_bytes"] = host_writer
        check("[derived] a member the host cannot write is copied into place "
              "from INSIDE the container, and the staging area is removed",
              via_container == [product] and len(container.calls) == 1
              and f"cp {DERIVED_STATE_STAGING}/" in container.calls[0]
              and read(product) == seed_bytes[product]
              and not os.path.lexists(os.path.join(root,
                                                   DERIVED_STATE_STAGING)),
              str(container.calls))

        put(product, b"<?php // regenerated as root\n")
        globals()["_write_seed_bytes"] = host_refuses
        try:
            restore_derived_state(root, seed_bytes, _ContainerRunner(act=False))
            untaken = "accepted"
        except DerivedStateUnrestored as exc:
            untaken = str(exc)
        finally:
            globals()["_write_seed_bytes"] = host_writer
        check("[derived] a restore that does not take -- the container's copy "
              "did nothing -- refuses by re-comparison, names the file and "
              "says the worker must be reprovisioned",
              product in untaken and "must be reprovisioned" in untaken
              and "PermissionError" in untaken, untaken)
        put(product, seed_bytes[product])

        # A symlink on a member's path is refused, never written through.
        outside = os.path.join(root, "outside.php")
        put("outside.php", b"<?php // not the workspace's\n")
        os.remove(os.path.join(root, product))
        os.symlink(outside, os.path.join(root, product))
        try:
            restore_derived_state(root, seed_bytes, _ContainerRunner())
            linked = "accepted"
        except DerivedStateUnrestored as exc:
            linked = str(exc)
        check("[derived] a symlinked member is refused, and its target is not "
              "overwritten with seed bytes",
              "symlink" in linked and "must be reprovisioned" in linked
              and read("outside.php") == b"<?php // not the workspace's\n",
              linked)
        os.remove(os.path.join(root, product))
        put(product, seed_bytes[product])
        moved = os.path.join(root, "elsewhere")
        os.rename(os.path.join(root, "var/classes/DataObject"), moved)
        os.symlink(moved, os.path.join(root, "var/classes/DataObject"))
        check("[derived] ...and so is a symlinked DIRECTORY on the path",
              _raises(lambda: derived_state_drift(root, seed_bytes),
                      DerivedStateUnrestored))

    saved_data_root = os.environ.pop(DATA_ROOT_ENV, None)
    try:
        with tempfile.TemporaryDirectory() as fixture_data_root:
            explicit_root = os.path.join(fixture_data_root, "explicit-clone")
            explicit = Boundary(version=1, project="coreshop",
                                repo_root=explicit_root,
                                removable=[], retained=[])
            try:
                strip_repo(explicit, os.path.join(fixture_data_root, "gold"),
                           fixture_data_root)
                explicit_refusal = "accepted"
            except SystemExit as exc:
                explicit_refusal = str(exc)
            check("explicit strip paths do not require a configured data "
                  "root",
                  "does not look like coreshop: no features/domain/"
                  in explicit_refusal,
                  explicit_refusal)

            check("no data root means nothing to protect -- every declared "
                  "root is relative to one", declared_corpus_roots() == ())

            os.environ[DATA_ROOT_ENV] = fixture_data_root

            def strip_refusal(root):
                b = Boundary(version=1, project="coreshop", repo_root=root,
                             removable=[], retained=[])
                try:
                    strip_repo(b, os.path.join(fixture_data_root,
                                               "other-gold"),
                               fixture_data_root)
                    return "accepted"
                except SystemExit as exc:
                    return str(exc)

            # CoreShop is what this arm strips; the rest are declared
            # checkouts the guard used to let through, and the `--repo`
            # under them is the case the exact-match test could not see.
            for project in ("coreshop", "python-docx", "epubcheck",
                            "algorand-java-sdk"):
                refusal = strip_refusal(os.path.join(
                    fixture_data_root, "projects", project, "source"))
                check(f"a configured canonical {project} source remains "
                      f"protected before the tree is touched",
                      "config/corpora.yml declares" in refusal, refusal)
            check("...and so is a path INSIDE one, which an exact-match "
                  "guard admitted", "config/corpora.yml declares"
                  in strip_refusal(os.path.join(
                      fixture_data_root, "projects", "coreshop", "source",
                      "features")))
            check("a clone outside every declared corpus still reaches the "
                  "shape check", "does not look like coreshop: no features/domain/"
                  in strip_refusal(explicit_root))
            check("...and nothing was created on the way to any of those "
                  "answers", os.listdir(fixture_data_root) == [],
                  str(os.listdir(fixture_data_root)))
    finally:
        if saved_data_root is None:
            os.environ.pop(DATA_ROOT_ENV, None)
        else:
            os.environ[DATA_ROOT_ENV] = saved_data_root

    # Distributed Go glue must not exempt its package's protected siblings.
    with tempfile.TemporaryDirectory() as root:
        def go_write(rel, text="original"):
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)

        protected = ("cmd/coddy/main.go", "internal/agent/agent.go",
                     "internal/agent/agent_test.go", "internal/agent/prompt.md",
                     "external/httpserver/server_http.go", "features/run.feature",
                     "go.mod", "go.sum", "_bench/go/support/runner.go")
        answer = "internal/agent/bdd_agent_test.go"
        b = Boundary(1, "go-fixture", root,
                     removable=[(answer, "answer")],
                     retained=[("internal/agent/agent_test.go", "helper")])
        for rel in protected + (answer, "_bench/run_record.jsonl"):
            go_write(rel)
        man = StripManifest(
            repo_root=root, gold_root=os.path.join(root, "gold"),
            substrate_roots=list(GO_SUBSTRATE_ROOTS),
            substrate_volatile=sorted(GO_SUBSTRATE_VOLATILE),
            bytecode_roots=list(GO_BYTECODE_ROOTS),
            build_roots=list(GO_BUILD_ROOTS))
        man.digests = substrate_digests(root, b, man.roots(), man.volatile())
        go_write(answer, "new answer")
        go_write("_bench/run_record.jsonl", "new record")
        check("Go answers and the exact exported record may change",
              set(man.digests) == set(protected)
              and verify_substrate(man, b)["changed"] == [])
        for rel in protected:
            go_write(rel, "modified")
            check("Go substrate detects changes to " + rel,
                  verify_substrate(man, b)["changed"] == [rel])
            go_write(rel)
        os.unlink(os.path.join(root, "internal/agent/agent_test.go"))
        go_write("_bench/go/support/extra.go")
        report = verify_substrate(man, b)
        remote = substrate_digests(root, b, man.roots(), man.volatile())
        check("host and remote inventories use the same integrity report",
              compare_substrate_inventory(man.digests, remote) == report)
        declared = "internal/agent/agent.go"
        go_write(declared, "declared mutation")
        observed = substrate_digests(root, b, man.roots(), man.volatile())
        expected = {declared: observed[declared]}
        check("the pure comparison honours only the declared changed bytes",
              compare_substrate_inventory(man.digests, observed, expected)
              == verify_substrate(man, b, expected)
              and compare_substrate_inventory(man.digests, observed)["changed"]
              == [declared])
        check("Go missing retained helpers and added support are detected",
              report["missing"] == ["internal/agent/agent_test.go"]
              and report["added"] == ["_bench/go/support/extra.go"])

    print("\n" + ("ALL PASS (repo)" if ok else "FAILURES (repo)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
