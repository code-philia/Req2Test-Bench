"""The mutant population, and the recall computed over it (SPEC_C3_PARALLEL
§3.11, and the mutation-recall metric of §3.10).

v2 of the spec conflated covered *lines* with *mutants*.  A line yields
zero, one or several mutants — `$a + $b` on a covered line yields one
`ArithmeticOperator` mutant, `if ($a < $b)` yields two (`ConditionalBoundary`
and `NegateConditional`), and a line of `use` statements yields none — so the
151,180 `(line, item)` pairs of A.9 are not `(mutant, item)` executions and
the 205 h / 51 h cost rows derived from them are provisional.  Nothing may be
computed until the population is *defined*, which is what this module does:
it turns an enumerator's raw output into a manifest with a reproducible
digest, maps that manifest onto the coverage the runner already records, and
scores the result.

**The engine is first-party.**  There is no mutation engine in this project's
vendor tree and no network access to install one, so the operators below are
implemented by a PHP enumerator written for this benchmark.  It is named
`r2t-mutate` and versioned separately rather than borrowing the name of
Infection or PIT: an operator set that merely *resembles* a published one
must not be reported under that one's name, because the published mutation
scores would then look comparable to these and they are not.  The
`nikic/php-parser` version is read out of the application's `composer.lock`
at manifest-build time (never hard-coded — a `composer update` would
otherwise leave the manifest asserting a parser that no longer produced it)
and recorded, because the parser decides the node spans that the mutant ids
are computed from.

The JSON contract with the PHP enumerator
-----------------------------------------
The enumerator writes UTF-8 JSON: one array, one object per line, or the
`{"engine":…, "mutants":[…]}` envelope `r2t/php/mutate.php --out` produces
(`load_raw` accepts all three and reads only the mutant array out of the
envelope).  Each element is exactly:

    {"file":       "src/CoreShop/Component/Order/Model/Order.php",
     "operator":   "NegateConditional",
     "start_line": 412,          // 1-based, the line the replaced node starts on
     "start_col":  17,           // 1-based column of its first byte on that line
     "original":   "$a < $b",    // the exact source bytes being replaced
     "mutated":    "$a >= $b",   // the exact source bytes replacing them
     // optional, carried into the manifest, never part of the id:
     "end_line": 412, "end_col": 23, "class": "...", "method": "..."}

The complete envelope may additionally carry a positive ``n_invalid`` and a
non-empty ``enumerator_rev``.  Zero invalid candidates is encoded by omitting
the field.  Revision recording is explicit: legacy/v1 construction omits it
and selects :data:`OPERATORS_V1`, so its manifest object, canonical bytes and
digest remain exactly reproducible while new construction defaults to v2.

Guarantees the enumerator must provide, because the manifest cannot check
them and the campaign cannot recover from them:

* `file` is repo-root-relative with `/` separators — the same spelling
  `runner.coverage_lines` uses, since the two are joined by string equality;
* every emitted mutant is *syntactically valid*: the enumerator re-parses the
  mutated file before emitting.  A mutant that fatals at run time is scored
  as infrastructure here (excluded and counted), never as a kill, so an
  invalid mutant that slips through silently shrinks the denominator;
* it does NOT de-duplicate or number its output — this module refuses
  duplicates rather than merging them, and assigns the ids.  It MAY sort
  (`mutate.php` does, by span); it does not matter either way, because this
  module re-sorts into its own canonical order so that the digest cannot
  depend on the enumerator's traversal order OR on its sort key;
* it is deterministic: the same tree must yield the same array.

Extra keys are refused rather than ignored.  An unrecognised key means the
enumerator's contract changed, and this module cannot know whether the new
field belongs in the identity of a mutant; guessing either way produces a
manifest whose digest no longer means what it claims.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Iterable, Optional

from ..core.paths import project_path
from ..core.paths import BENCHMARK_ROOT, CONFIG_DIR

#: First-party, and saying so is the point — see the module docstring.
ENGINE = "r2t-mutate"
ENGINE_VERSION = "1.0"

#: Where the application's lock file lives.  The parser version is a property
#: of the tree being mutated, not of this repository, so it is read from there.
COMPOSER_LOCK = project_path("coreshop", "source", "composer.lock")
PARSER_PACKAGE = "nikic/php-parser"

#: The exact v1 catalogues behind the published Slice 1 mutation numbers.
#: They are release inputs now, stored through Git LFS and pinned independently
#: by the release inventory and ``slice1_mutation_assets.json``.  Resolving
#: from this module makes every checkout test the repository evidence rather
#: than an operator-specific absolute path.  A missing LFS object is a failed
#: deterministic check, never a SKIP or an environment-variable escape hatch.
ARCHIVED_MANIFEST = os.path.join(
    BENCHMARK_ROOT, "release", "coreshop", "mutants_v1.json")
ARCHIVED_PYTHON_DOCX_MANIFEST = os.path.join(
    BENCHMARK_ROOT, "release", "python-docx", "mutants_v1.json")
ARCHIVED_MANIFESTS = {
    "coreshop": ARCHIVED_MANIFEST,
    "python-docx": ARCHIVED_PYTHON_DOCX_MANIFEST,
}

#: The operator profiles.  Each member is a total function from one AST node
#: to one replacement, which is what makes
#: `(file, line, col, original, mutated)` a complete description of a mutant.
#:
#:   ConditionalBoundary   <  -> <=,  >  -> >=,  <= -> <,  >= -> >
#:   NegateConditional     == -> !=,  === -> !==, < -> >=, and their inverses
#:   Increment             ++ -> --,  -- -> ++
#:   ArithmeticOperator    +  -> -,   *  -> /,   % -> *, and their inverses
#:   TrueValue             a boolean-valued literal/condition -> true
#:   FalseValue            ... -> false
#:   ReturnValue           return $x; -> return null; (typed: 0 / '' / [])
#:   MethodCallRemoval     $o->m($a); -> ;  (statement-position calls only)
#:   LogicalConnector      && <-> ||, and <-> or
#:   RemoveNegation        delete boolean ! / Python not
#:   ConstantReplacement   integer literal n -> n + 1
#:
#: ``OPERATORS_V1`` is immutable evidence: both frozen Slice 1 population
#: entries carry it byte-for-byte.  ``OPERATORS`` is the v2 default.  Appending
#: operators is safe precisely because `mutant_id` carries no positional index
#: (see `mutant_id`): every shared-v1 descriptor retains the same id.
OPERATORS_V1: tuple[str, ...] = (
    "ConditionalBoundary",
    "NegateConditional",
    "Increment",
    "ArithmeticOperator",
    "TrueValue",
    "FalseValue",
    "ReturnValue",
    "MethodCallRemoval",
)
OPERATORS: tuple[str, ...] = OPERATORS_V1 + (
    "LogicalConnector",
    "RemoveNegation",
    "ConstantReplacement",
)


def record_enumerator_revision(operator_profile: str,
                               requested: bool = False) -> bool:
    """Return whether a population build must record enumerator provenance.

    Low-level enumerators keep revision output opt-in so archived v1 objects
    can still be reconstructed byte-for-byte.  A production population build
    has a stronger contract: every new v2 population records and verifies the
    pinned revision, while a v1 reconstruction must not attach provenance it
    never carried.  Both stack entry points call this one policy function so
    the PHP and Python paths cannot drift.
    """
    if operator_profile not in {"v1", "v2"}:
        raise ValueError(
            f"unknown operator profile {operator_profile!r}; expected v1 or "
            "v2")
    if operator_profile == "v1" and requested:
        raise ValueError(
            "--record-enumerator-rev is incompatible with --operator-profile "
            "v1; archived v1 populations never carried that field")
    return operator_profile == "v2"


def operator_profile_for(operators: Iterable[str]) -> str:
    """Resolve the one executable profile named by a manifest operator list."""
    profile = tuple(operators)
    if profile == OPERATORS_V1:
        return "v1"
    if profile == OPERATORS:
        return "v2"
    raise ValueError(
        "manifest operators are neither the exact ordered v1 profile nor the "
        "exact ordered v2 profile; no applier profile can be inferred")


#: The production roots of the FIRST Behat project, written ONCE.
#: `bench.repo.BehatProject.prod_paths` takes its default from this name, so
#: "which code is CoreShop's production code" is one tuple rather than two
#: copies that happen to agree.
CORESHOP_PROD_PATHS: tuple[str, ...] = (
    "src/CoreShop/Component",
    "src/CoreShop/Bundle",
)

#: Never mutated, whatever the keep roots say.
#:
#: `vendor/` and `var/` are named even though the keep roots already exclude
#: them.  The redundancy is deliberate: they are the two trees that would
#: dominate the mutant count if they were ever reachable (the whole-tree
#: enumeration counted 32,196 mutants against a benchmark surface an order of
#: magnitude smaller — §3.11), and `var/classes` in particular holds Pimcore
#: DataObject classes that are *generated*, not written: `Behat%` classes are
#: created and purged per scenario, and the production classes are
#: regenerated in place by any retained class save and restored to their seed
#: bytes by the harness before every pair (`repo.DERIVED_STATE_ROOTS`).  A
#: mutant there would be overwritten by one of those and score as survived
#: for reasons that have nothing to do with the test.
DROPPED_PREFIXES: tuple[str, ...] = ("vendor/", "var/")


def exclusions_for_prod_paths(prod_paths: Iterable[str]) -> tuple[str, ...]:
    """The keep/drop policy one project's production roots define.

    A second Behat project does not live under `src/CoreShop`, and this list
    used to be a constant, so `mutants build` enumerated a Sylius tree and
    then excluded EVERY mutant in it -- keeps that match nothing exclude
    everything (`is_excluded`).  The roots are now the boundary's own
    `behat.prod_paths` row, the same row the production index is built over,
    and the two orders match by construction: CoreShop's row is
    `CORESHOP_PROD_PATHS`, so `EXCLUDED_PREFIXES` below is the literal it
    replaced, byte for byte, and every archived CoreShop manifest still
    re-verifies against its own recorded `exclusions`.

    An absent, empty or blank root list is refused rather than defaulted.
    With no keeps, `is_excluded` drops only `vendor/` and `var/` and the
    population becomes the whole repository -- test glue included -- which is
    a wrong answer that validates.  `None` gets the same refusal rather than
    a `TypeError`, for a direct caller: from a boundary it can no longer
    arrive, because `repo.behat_project` refuses a null `prod_paths` where
    the row is read.
    """
    roots = tuple(prod_paths or ())
    if not roots or not all(isinstance(root, str) and root for root in roots):
        raise ValueError(
            "REFUSED: a mutation population needs at least one production "
            f"root; the boundary's prod_paths row is {prod_paths!r}.")
    return tuple("!" + root for root in roots) + DROPPED_PREFIXES


#: The exclusion policy, as one serialisable object so that the manifest can
#: record the whole of it and the digest can depend on the whole of it.
#:
#: An entry beginning with `!` is a KEEP root: a path that matches no keep
#: root is excluded.  That is how "everything outside a project's production
#: roots" is expressed as a prefix list — for CoreShop, everything outside
#: `src/CoreShop/{Component,Bundle}`.  A plain entry is an outright exclusion.
#:
#: This name is CoreShop's policy and stays the default of `build_manifest`,
#: `is_excluded` and the behat stack façade.  `mutants build` does NOT read
#: it any more: it derives the policy from the boundary's own row, which for
#: CoreShop is this tuple exactly.
EXCLUDED_PREFIXES: tuple[str, ...] = exclusions_for_prod_paths(
    CORESHOP_PROD_PATHS)

#: Fields the enumerator must supply, and the ones it may.
REQUIRED_FIELDS: tuple[str, ...] = ("file", "operator", "start_line",
                                    "start_col", "original", "mutated")
OPTIONAL_FIELDS: tuple[str, ...] = ("end_line", "end_col", "class", "method")

#: §3.13 lever 2: a behat process costs 3.27 s to boot and ~1.0 s per
#: additional scenario (derived — A.9), so the scenarios covering one mutant
#: share one process.  The cap is not a performance knob — at 25 scenarios the
#: boot is already down to 12% of the batch — it bounds the blast radius: a
#: batch that dies loses every result in it and all of them must be re-run.
DEFAULT_BATCH_SCENARIOS = 25

#: Outcome vocabulary, quoted from `harness.RunResult.outcome` and
#: `runner._record`.  Kill is pinned by §3.10 to `failed` (plus the
#: conditional timeout below); everything else is either a survival or an
#: exclusion, and an outcome in NEITHER table is refused rather than bucketed,
#: because a label this module has never seen is exactly the case where a
#: silent default would mis-score a whole campaign.
KILL_OUTCOMES = frozenset({"failed"})
SURVIVED_OUTCOMES = frozenset({"passed"})
#: Excluded from the denominator and counted (§3.10).  Three groups:
#: the harness or container failing (`container_error`, `no_scenario_ran`,
#: `scenario_not_found`, `no_run`, `no_steps_ran`, `setup_error`,
#: `setup_failed`, `harness_error`); the two witnesses disagreeing so the run
#: reads as neither killed nor survived (`passed_but_nonzero_exit`,
#: `feature_substituted`); and the mutant breaking the application rather than
#: the test detecting it (`solution_error`, `parse_or_compile_error`,
#: `undefined_steps`, `pending`, `not_passed`).  The third group is the
#: debatable one: mutation-testing convention would credit a fatal as a kill,
#: but §3.10 pins the kill definition to `failed`, so crediting it here would
#: quietly widen the definition.  They are counted instead, and the count is
#: what tells a reader whether that decision was material.
#:
#: A fourth group was MISSING and would have aborted scoring: `report.STAGE`
#: is this project's outcome vocabulary and it lists `adapter_error`,
#: `parse_error`, `no_files_returned` and `no_writable_files`, all of which
#: `runner._record` can emit (`no_writable_files` on its own line).  An
#: outcome outside all three sets raises — deliberately — so a real harness
#: label absent from here does not fail safe, it fails a 205-hour campaign at
#: scoring time.  All four are "no output" stages: no test ran, so none of
#: them can be a kill or a survival, and they belong here.
#:
#: `setup_error`, `setup_failed` and `harness_error` are NOT produced by
#: anything in this codebase today (grep says so); they are kept as forward
#: declarations for a mutation runner that has yet to be written, and are
#: marked as such rather than being presented as quotations.
INFRASTRUCTURE_OUTCOMES = frozenset({
    "container_error", "no_scenario_ran", "scenario_not_found", "no_run",
    "no_steps_ran", "setup_error", "setup_failed", "harness_error",
    "passed_but_nonzero_exit", "feature_substituted", "solution_error",
    "parse_or_compile_error", "undefined_steps", "pending", "not_passed",
    "adapter_error", "parse_error", "no_files_returned", "no_writable_files",
    # PrestaShop: the run consumed its own upload fixtures, which the reset
    # restored (prestashop_resources.FIXTURES); its verdict is not measured.
    "fixture_consumed",
    # Go (owner ruling 2026-09-30): the mutant's test only added files to its
    # disposable copy, which was retired; the pair is unscorable for everyone.
    "unscorable_substrate",
})


# --------------------------------------------------------------- parser id
def read_parser_version(lock_path: str = COMPOSER_LOCK,
                        package: str = PARSER_PACKAGE) -> str:
    """`nikic/php-parser` as pinned by the application's composer.lock.

    The `dist.reference` is included because a Composer version tag can be
    re-pointed upstream while the version string stays put; the reference is
    the commit whose bytes actually parsed the tree.  Absence is refused: a
    manifest that cannot name the parser cannot claim its spans are
    reproducible, and the enumerator would not run at all.

    `package` is a parameter and not the constant it defaults to for the same
    reason `lock_path` always was: WHICH parser identifies a mutant's spans is
    a property of the tree being mutated.  A stack whose parser is not a
    Composer package answers this question with its own function and passes
    the string to `build_manifest`; nothing here guesses on its behalf.
    """
    if not os.path.isfile(lock_path):
        raise ValueError(f"REFUSED: no composer.lock at {lock_path}; the "
                         f"manifest cannot record which parser produced it.")
    with open(lock_path, encoding="utf-8") as fh:
        lock = json.load(fh)
    for section in ("packages", "packages-dev"):
        for pkg in lock.get(section) or []:
            if pkg.get("name") == package:
                ref = (pkg.get("dist") or {}).get("reference") or ""
                version = pkg.get("version") or "?"
                return f"{package} {version}" + (f"@{ref}" if ref else "")
    raise ValueError(f"REFUSED: {package} is not in {lock_path}; the "
                     f"enumerator has nothing to parse PHP with.")


# ------------------------------------------------------------- exclusions
def _matches(rel: str, prefix: str) -> bool:
    """Prefix match that respects directory boundaries (as `boundary.py`).

    Without it `src/CoreShop/Componentry/` would match the `Component` keep
    root and a whole unrelated tree would enter the population.
    """
    if prefix.endswith("/"):
        return rel.startswith(prefix)
    return rel == prefix or rel.startswith(prefix + "/")


def normalise_path(rel_path: str) -> str:
    """Repo-relative, `/`-separated, with any `./` prefix removed.

    `str.lstrip("./")` is NOT used, and the distinction is not cosmetic:
    `lstrip` takes a SET OF CHARACTERS, so it eats every leading `.` and `/`
    of the name itself.  `.github/x.php` became `github/x.php` and
    `../../src/CoreShop/Component/A.php` became `src/CoreShop/Component/A.php`
    — i.e. a path that escapes the repository was silently rewritten into one
    that passes the keep-root test and enters the population.  Only a literal
    leading `./` is removed here, and a leading `/` once, so a `..` segment
    survives to be judged by `is_excluded` (it matches no keep root, so it is
    excluded, which is the correct answer).
    """
    rel = str(rel_path).replace(os.sep, "/").replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    return rel.lstrip("/")


def is_excluded(rel_path: str,
                exclusions: Iterable[str] = EXCLUDED_PREFIXES) -> bool:
    """Apply the `!keep` / plain-exclude policy of `EXCLUDED_PREFIXES`."""
    rel = normalise_path(rel_path)
    keeps = [p[1:] for p in exclusions if p.startswith("!")]
    drops = [p for p in exclusions if not p.startswith("!")]
    if keeps and not any(_matches(rel, k) for k in keeps):
        return True
    return any(_matches(rel, d) for d in drops)


def is_population_excluded(rel_path: str, fragments: Iterable[str],
                           prod_paths: Iterable[str]) -> bool:
    """True when a path sits in a subtree its project declared non-product.

    The keep roots of `exclusions_for_prod_paths` are whole trees, and a
    project can ship unit tests, specs, migrations, DI configuration and
    data fixtures INSIDE one of them.  Sylius does: of the 43,670 mutants
    its three roots enumerate, 12,373 are product code and the rest are
    `tests/` (26,436), `Resources/config/` (2,551), `test/` (240),
    `Migrations/` (1,237), `Fixture/` (750), `Test/` (38), `Tests/` (30)
    and `config/` (15) -- the singular spellings are separate fragments,
    because the match is on whole segments.  The production boundary cannot
    separate them -- it answers which files are the BEHAT GLUE, and none of
    these is glue -- so the project declares them, in the
    `behat.mutation_exclude` row that reaches this function.

    THE RULE, exactly.  A fragment is a run of DIRECTORY segments.  It
    matches `rel_path` when

      1. the path lies under one of `prod_paths` -- the most specific one,
         if the roots nest -- and
      2. the fragment's segments appear as a CONTIGUOUS run of the
         directory segments of the remainder: the path below that root,
         with its file name dropped.

    So `tests/` takes `src/Sylius/Component/Core/tests/Foo.php` and
    `.../tests/unit/Foo.php`, at any depth and directly under the root; it
    does not take a file NAMED `tests.php`, a directory called `tests2`, or
    anything outside the production roots.  `Resources/config/` is two
    segments and matches only where the two are adjacent, in that order.

    The segments are the whole of it.  A substring test would let `spec/`
    take `.../SpecialCase/spec_helper.php` with it; a bare `startswith`
    would match only directly under the root and miss every one of the
    26,436 rows this row exists for.

    An empty fragment is SKIPPED rather than matching everything, which is
    what a zero-length run would do.  `repo.behat_project` refuses one by
    name where the row is read, so this is the answer for a direct caller,
    and it is the conservative one: the population unchanged rather than a
    population of nothing.
    """
    rel = normalise_path(rel_path)
    root = None
    for candidate in prod_paths or ():
        candidate = normalise_path(candidate).rstrip("/")
        if candidate and _matches(rel, candidate) \
                and (root is None or len(candidate) > len(root)):
            root = candidate
    if root is None:
        return False
    directories = rel[len(root):].lstrip("/").split("/")[:-1]
    for fragment in fragments or ():
        wanted = [part for part in normalise_path(fragment).split("/")
                  if part]
        if not wanted:
            continue
        span = len(wanted)
        if any(directories[at:at + span] == wanted
               for at in range(len(directories) - span + 1)):
            return True
    return False


# ------------------------------------------------------------- identity
def mutant_id(rel_path: str, operator: str, start_line: int, start_col: int,
              original: str, mutated: str, engine: str = ENGINE,
              engine_version: str = ENGINE_VERSION) -> str:
    """A content-addressed name for one mutant: sha1(NUL-joined)[:16].

    The id deliberately carries NO positional index.  With an index, enabling
    a ninth operator — or fixing a bug that makes the enumerator emit one more
    mutant in `Cart.php` — renumbers every mutant after it in the file, so
    every stored `(mutant_id, item_id, outcome)` row from an earlier campaign
    would silently re-attach to a *different* mutant.  Nothing would fail; the
    recall would simply be wrong, and there would be no witness.  Keyed on
    content instead, adding an operator adds ids and leaves every existing one
    valid, which is what makes a 205-hour campaign resumable and re-scorable.

    `engine` and `engine_version` are inside the hash for the same reason: two
    engines can produce the same textual replacement at the same span by
    different rules, and results from one must not merge into the other's.

    NUL is the field separator because PHP source cannot contain it; a field
    that does contain one is refused rather than allowed to forge a collision
    across field boundaries.
    """
    fields = [engine, engine_version, normalise_path(rel_path), operator,
              str(int(start_line)), str(int(start_col)), original, mutated]
    for f in fields:
        if "\0" in f:
            raise ValueError("REFUSED: a mutant field contains NUL, which is "
                             "the id's field separator; the id would be "
                             "ambiguous across two different mutants.")
    return hashlib.sha1("\0".join(fields).encode("utf-8")).hexdigest()[:16]


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def manifest_digest(manifest: dict) -> str:
    """sha256 over canonical JSON of the manifest MINUS its own digest field.

    §3.11 requires the digest in campaign metadata and requires a rerun over
    the same inputs to reproduce it.  It therefore covers the policy as well
    as the mutants — operators, exclusions, sample, seed, engine, parser —
    because a campaign run against the same 4,000 mutants under a different
    exclusion list is not the same campaign, and a digest over the mutant
    array alone would call them identical.
    """
    return hashlib.sha256(
        _canonical({k: v for k, v in manifest.items() if k != "digest"})
    ).hexdigest()


# ------------------------------------------------------------- manifest
def load_raw(path: str, *, engine: str = ENGINE,
             engine_version: str = ENGINE_VERSION) -> list[dict]:
    """Read the enumerator's output.

    Three accepted shapes, because the enumerator that actually ships here
    (`r2t/php/mutate.php --out`) writes the third and an earlier version of
    this function could not read it — it fell through to the JSONL branch and
    died with a bare `json.JSONDecodeError` on the second line of a
    pretty-printed document, which is a stack trace rather than a diagnosis:

    * one JSON array of mutant objects;
    * one mutant object per line (JSONL);
    * one JSON object carrying the array under `"mutants"` — the envelope
      `mutate.php` emits, whose sibling keys (`engine`, `parser`, `files`,
      `errors`) are the enumerator's own report and are deliberately NOT
      trusted here: `build_manifest` records the engine, the parser and the
      exclusions from ITS arguments, so a manifest can never inherit an
      unverified claim about which parser produced it.

    `engine`/`engine_version` say which enumerator's output this is ALLOWED to
    be — they default to this module's PHP constants, so the CoreShop path is
    unchanged, and a second stack passes its own pair.  The refusal below is
    the point of having them: reading `r2t-mutate-py` output under
    `r2t-mutate`'s identity would mint ids that hash the wrong engine and
    silently pool two populations.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    if not text:
        return []
    if text[0] == "[":
        doc = json.loads(text)
        if not isinstance(doc, list):
            raise ValueError("REFUSED: enumerator output is not a JSON array.")
        return doc
    if text[0] == "{":
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            doc = None          # several objects: JSONL, handled below.
        if isinstance(doc, dict) and "mutants" in doc:
            if not isinstance(doc["mutants"], list):
                raise ValueError("REFUSED: the enumerator envelope's "
                                 "'mutants' key is not an array.")
            # §3.11 asks for "mutation engine and exact version".  The manifest
            # states them from THIS module's constants, and `mutant_id` hashes
            # them, so an enumerator that has been re-versioned under the same
            # name would silently re-mint every id while the manifest went on
            # claiming 1.0.  The one claim in the envelope that is checkable is
            # checked; disagreement is a refusal, not a preference.
            for key, ours in (("engine", engine),
                              ("engine_version", engine_version)):
                theirs = doc.get(key)
                if theirs is not None and theirs != ours:
                    raise ValueError(
                        f"REFUSED: the enumerator reports {key}={theirs!r} but "
                        f"this module identifies mutants as {ours!r}. Every "
                        f"mutant id hashes {key}, so the two disagree about "
                        f"what a mutant IS; reconcile them deliberately.")
            return doc["mutants"]
        if isinstance(doc, dict) and doc and not (set(REQUIRED_FIELDS) & set(doc)):
            raise ValueError("REFUSED: enumerator output is a JSON object "
                             "with no 'mutants' array and no mutant fields; "
                             "this module cannot guess where the population "
                             f"is. Keys: {sorted(doc)}")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _validate(raw: dict, operators: Iterable[str], index: int) -> dict:
    where = f"raw mutant #{index}"
    if not isinstance(raw, dict):
        raise ValueError(f"REFUSED: {where} is not an object.")
    missing = [f for f in REQUIRED_FIELDS if f not in raw]
    if missing:
        raise ValueError(f"REFUSED: {where} is missing {missing}; the "
                         f"enumerator contract is broken and the manifest "
                         f"would describe a population it cannot locate.")
    unknown = sorted(set(raw) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS))
    if unknown:
        raise ValueError(f"REFUSED: {where} carries unrecognised field(s) "
                         f"{unknown}; this module cannot know whether they "
                         f"belong in the mutant identity, and guessing makes "
                         f"the digest mean something other than it claims.")
    if raw["operator"] not in set(operators):
        raise ValueError(f"REFUSED: {where} has operator "
                         f"{raw['operator']!r}, which is not in the declared "
                         f"operator set; the enumerator and the manifest "
                         f"disagree about what the population is.")
    for field in ("start_line", "start_col"):
        value = raw[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"REFUSED: {where} has {field}={value!r}; lines "
                             f"and columns are 1-based integers (line 0 would "
                             f"never join to any coverage row).")
    for field in ("file", "original"):
        if not isinstance(raw[field], str) or not raw[field].strip():
            raise ValueError(f"REFUSED: {where} has a non-string or empty "
                             f"{field}.")
    if not isinstance(raw["mutated"], str):
        raise ValueError(f"REFUSED: {where} has a non-string mutated value.")
    if raw["mutated"] == "" and raw["operator"] != "RemoveNegation":
        raise ValueError(
            f"REFUSED: {where} has an empty mutated value, but only "
            "RemoveNegation is a deletion operator.")
    if raw["original"] == raw["mutated"]:
        # A no-op replacement executes identically to the original, so it can
        # never be killed and would enter every denominator as a permanent
        # survivor, deflating every candidate's recall by an equal amount that
        # nothing in the results would explain.
        raise ValueError(f"REFUSED: {where} mutates {raw['original']!r} into "
                         f"itself; that is not a mutant.")
    out = {f: raw[f] for f in REQUIRED_FIELDS}
    out["file"] = normalise_path(out["file"])
    for f in OPTIONAL_FIELDS:
        if f in raw:
            out[f] = raw[f]
    return out


def _select_sample(mutants: list[dict], sample: int, seed) -> list[dict]:
    """Deterministic subset, reproducible across Python versions.

    `random.Random(seed).sample` is NOT used: its output is a property of
    CPython's Mersenne Twister plumbing and has changed between releases, and
    a manifest digest that must still reproduce in two years cannot depend on
    that.  Hashing `(seed, mutant_id)` and taking the lowest N is stable
    forever, independent of the input order, and stable under *adding*
    mutants — a re-enumeration that finds one more mutant elsewhere in the
    tree does not reshuffle the sample.
    """
    ranked = sorted(mutants, key=lambda m: hashlib.sha256(
        f"{seed}\0{m['id']}".encode("utf-8")).hexdigest())
    keep = {m["id"] for m in ranked[:sample]}
    return [m for m in mutants if m["id"] in keep]


def build_manifest(raw: list[dict], *, parser_version: str,
                   operators: Iterable[str] = OPERATORS,
                   exclusions: Iterable[str] = EXCLUDED_PREFIXES,
                   engine: str = ENGINE,
                   engine_version: str = ENGINE_VERSION,
                   sample: Optional[int] = None, seed=None,
                   n_invalid: Optional[int] = None,
                   enumerator_rev: Optional[str] = None) -> dict:
    """Validate, exclude, identify, sort, sample — then digest.

    The sort is the load-bearing step.  The enumerator walks the tree in
    whatever order the filesystem hands it directories, so two runs over an
    identical tree can emit identical mutants in different orders; without a
    canonical sort the digest would differ and §3.11's "a rerun over the same
    inputs must reproduce it" would fail for a reason that has nothing to do
    with the population.

    Every knob that decides WHAT A MUTANT IS is an argument.  New construction
    defaults to the v2 operators; archived CoreShop evidence re-verifies only
    by explicitly naming ``OPERATORS_V1`` (checked in `selftest`).  A second
    stack builds through this function rather than a copy of it.  The engine
    reaches both the manifest header and `mutant_id`, which is the whole reason
    it cannot be a constant:
    ids that hash `r2t-mutate` while the manifest says `r2t-mutate-py` would
    be a population claiming an engine that did not produce it.
    """
    operators = tuple(operators)
    exclusions = tuple(exclusions)
    if n_invalid is not None:
        if not isinstance(n_invalid, int) or isinstance(n_invalid, bool) \
                or n_invalid < 0:
            raise ValueError(f"REFUSED: n_invalid={n_invalid!r} must be a "
                             "non-negative integer.")
        # Zero is represented by absence.  This keeps the archived v1 object
        # byte-for-byte reproducible and prevents two encodings of one fact.
        if n_invalid == 0:
            n_invalid = None
    if enumerator_rev is not None \
            and (not isinstance(enumerator_rev, str)
                 or not enumerator_rev.strip()):
        raise ValueError("REFUSED: enumerator_rev must be a non-empty string.")
    if sample is not None:
        if seed is None:
            raise ValueError("REFUSED: sample without seed. An unseeded "
                             "sample cannot be reproduced, so the digest "
                             "would certify a population that no rerun can "
                             "reconstruct.")
        if not isinstance(sample, int) or isinstance(sample, bool) or sample < 1:
            raise ValueError(f"REFUSED: sample={sample!r} must be a positive "
                             f"integer.")
        try:
            _canonical({"seed": seed})
        except TypeError:
            raise ValueError(f"REFUSED: seed={seed!r} is not JSON "
                             f"serialisable, so the manifest cannot record "
                             f"it and the digest cannot cover it.") from None

    kept: list[dict] = []
    n_excluded = 0
    for i, item in enumerate(raw):
        record = _validate(item, operators, i)
        if is_excluded(record["file"], exclusions):
            # Counted, never silently dropped: the exclusion count is the only
            # evidence that the enumerator was pointed at the right tree.  A
            # policy typo that excludes everything and one that excludes
            # nothing both produce a manifest that *looks* fine; the count is
            # what distinguishes them.
            n_excluded += 1
            continue
        record["id"] = mutant_id(record["file"], record["operator"],
                                 record["start_line"], record["start_col"],
                                 record["original"], record["mutated"],
                                 engine=engine, engine_version=engine_version)
        kept.append(record)

    seen: dict[str, dict] = {}
    for record in kept:
        prior = seen.get(record["id"])
        if prior is not None:
            # Two mutants with one id means the manifest has fewer entries
            # than the enumerator produced, and every result row for that id
            # is attributable to either — so the merge is refused rather than
            # resolved.
            raise ValueError(
                f"REFUSED: duplicate mutant id {record['id']} for "
                f"{record['file']}:{record['start_line']}:"
                f"{record['start_col']} ({record['operator']}). The "
                f"enumerator emitted the same mutation twice, or two "
                f"mutations are genuinely indistinguishable at this span.")
        seen[record["id"]] = record

    kept.sort(key=lambda m: (m["file"], m["start_line"], m["start_col"],
                             m["operator"], m["id"]))
    if sample is not None:
        if sample > len(kept):
            # Otherwise the manifest records `sample: 5000` beside `n: 4800`
            # and a reader cannot tell a sampled campaign from an exhaustive
            # one that merely asked for more mutants than exist.
            raise ValueError(
                f"REFUSED: sample={sample} exceeds the population "
                f"({len(kept)} mutants after exclusions), so the manifest "
                f"would record a sample that was never taken.")
        kept = _select_sample(kept, sample, seed)

    manifest = {
        "engine": engine,
        "engine_version": engine_version,
        "parser": parser_version,
        "operators": list(operators),
        "exclusions": list(exclusions),
        "sample": sample,
        "seed": seed,
        "n": len(kept),
        "n_excluded": n_excluded,
        "mutants": kept,
    }
    # Both are opt-in metadata.  Existing/v1 callers pass neither, so their
    # manifest keys, canonical bytes and digest remain exactly unchanged.
    if n_invalid is not None:
        manifest["n_invalid"] = n_invalid
    if enumerator_rev is not None:
        manifest["enumerator_rev"] = enumerator_rev
    manifest["digest"] = manifest_digest(manifest)
    return manifest


# ------------------------------------------------------- coverage mapping
def map_mutants_to_items(manifest: dict,
                         coverage_by_item: dict) -> tuple[dict, list]:
    """Which items execute each mutant's line.

    `coverage_by_item` is `{item_id: {rel_path: [line, ...]}}` — exactly the
    shape `runner._record` writes into `coverage_lines`, so a completed gold
    sweep is the input with no reshaping.

    Attribution is by `(file, start_line)`.  Xdebug attributes an executed
    statement to the line the statement starts on, which is the same line
    php-parser reports for the node being replaced; using the end line as well
    would add mutants whose start line no scenario executes, i.e. mutants no
    test in the batch can possibly kill, straight into the denominator.  A
    mutant whose start line is covered by nothing is REPORTED as uncovered
    rather than being given an empty batch — see `batches`.
    """
    covered: dict[tuple[str, int], list] = {}
    for item_id in sorted(coverage_by_item):
        for path, lines in (coverage_by_item[item_id] or {}).items():
            path = normalise_path(path)
            for line in lines or ():
                covered.setdefault((path, int(line)), []).append(item_id)

    items_by_mutant: dict[str, list] = {}
    uncovered: list[str] = []
    for mutant in manifest.get("mutants") or []:
        hits = covered.get((mutant["file"], mutant["start_line"]))
        if hits:
            items_by_mutant[mutant["id"]] = sorted(set(hits))
        else:
            uncovered.append(mutant["id"])
    return items_by_mutant, sorted(uncovered)


def pool_additions(manifest: dict, coverage_by_item: dict,
                   pool_pairs: Iterable[tuple]) -> list:
    """The pairs an eq. 2 rebuild adds to an existing pool, sorted.

    The pool of an instance is every mutant whose start line its
    ground-truth run covers (`map_mutants_to_items`).  At harness 18 and
    later an outline's `coverage_lines` is the union over its Examples rows
    (V2-D3(a)), so a pool mapped from an earlier run that kept one row lacks
    the mutants only the other rows reach: python-docx's
    (specifications/EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md section 3.5).
    `coverage_by_item` is the later run's, restricted to the instances whose
    pools are rebuilt; `pool_pairs` are their existing `(item, mutant)`
    pairs, which keep their recorded outcomes.  Each returned pair needs one
    ground-truth observation.  An existing pair outside the rebuilt pools is
    refused: the rebuild only adds.
    """
    by_mutant, _uncovered = map_mutants_to_items(manifest, coverage_by_item)
    rebuilt = {(item, mutant) for mutant, items in by_mutant.items()
               for item in items}
    existing = set(pool_pairs)
    outside = sorted(existing - rebuilt)
    if outside:
        raise ValueError(
            f"REFUSED: {len(outside)} existing pool pair(s) lie outside the "
            f"pools this coverage maps, e.g. {outside[:3]}; a rebuild may "
            f"only add pairs")
    return sorted(rebuilt - existing)


#: A kit pool row's `gold_outcome`, by the single-observation reference rule.
KIT_GOLD_OUTCOMES = ("killed", "survived", "excluded")


def kit_gold_outcome(outcome: str) -> str:
    """A new pool pair's `gold_outcome` from its one ground-truth observation.

    The reference rule the existing pairs were recorded under
    (`bench/reference_controls.py`, section 5.1): a literal `failed` is a
    kill, `passed` a survivor, and a terminal timeout or an infrastructure
    outcome leaves the pair `excluded` from G_i.  An unknown label refuses,
    as `classify_outcome` does.
    """
    if outcome == "timeout":
        return "excluded"
    return {"kill": "killed", "survived": "survived",
            "infrastructure": "excluded"}[classify_outcome("passed", outcome)]


# ------------------------------------------------------------- batching
def batches(items_by_mutant: dict,
            max_scenarios: int = DEFAULT_BATCH_SCENARIOS) -> list[dict]:
    """One behat process per mutant (§3.13 lever 2), in a fixed order.

    A behat process costs 3.27 s to boot and about 1.0 s per additional
    scenario (derived — A.9), so running the 15-odd scenarios that cover a
    mutant one process each pays the boot 15 times: that ratio is the
    difference between the 205 h and 51 h rows of §4.

    **Required reset, and where it goes.**  The workspace is swept and the
    mutant reverted BETWEEN batches and never within one.  A batch shares one
    compiled Symfony container and one PHP process tree, so a file reverted
    mid-batch does not change the code already loaded — the later scenarios in
    the batch would be scored against a mutant that is no longer on disk, and
    the run record would look entirely healthy.  Every batch is therefore
    single-mutant by construction, and the caller applies exactly one
    mutate → run-batch → revert → sweep cycle per entry in this list.

    A mutant with no covering items has no batch: an empty behat process
    reports nothing, which would be read as "not killed" and would enter the
    denominator as a survivor purely because nothing ran.  Uncovered mutants
    belong in the uncovered list `map_mutants_to_items` returns.
    """
    if (not isinstance(max_scenarios, int) or isinstance(max_scenarios, bool)
            or max_scenarios < 1):
        raise ValueError(f"REFUSED: max_scenarios={max_scenarios!r} must be a "
                         f"positive integer.")
    out: list[dict] = []
    for mid in sorted(items_by_mutant):
        item_ids = list(items_by_mutant[mid])
        if not item_ids:
            raise ValueError(
                f"REFUSED: mutant {mid} has no covering items, so a batch for "
                f"it would run zero scenarios and score it survived. It "
                f"belongs in the uncovered list, not in the batch plan.")
        item_ids = sorted(set(item_ids))
        chunks = [item_ids[i:i + max_scenarios]
                  for i in range(0, len(item_ids), max_scenarios)]
        for part, chunk in enumerate(chunks, start=1):
            out.append({"mutant_id": mid, "part": part,
                        "n_parts": len(chunks), "item_ids": chunk})
    return out


# --------------------------------------------------------------- scoring
#: The one reviewed list of mutants that scoring leaves out of every G_i.
NONDETERMINISTIC_MUTANTS_FILE = os.path.join(CONFIG_DIR,
                                             "nondeterministic_mutants.yml")
NONDETERMINISTIC_MUTANTS_SCHEMA = "r2t.nondeterministic-mutants/1"


def nondeterministic_mutants(path: str = NONDETERMINISTIC_MUTANTS_FILE
                             ) -> frozenset:
    """The mutant ids scoring removes from every ground-truth kill set G_i.

    Harness 25 (specifications/EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md
    section 3.4): a listed mutant is killed or not by a random draw, so its
    pairs leave G_i before KillComplete and recall are computed, for every
    configuration.  Execution is unchanged.  Both scoring routes read this
    one file -- `r2t.bench.test_quality` and the `recall` verb here, and
    the public `req2test` engine (`req2test/score.py`, `req2test/mutate.py`)
    -- and none keeps a copy.
    """
    import yaml
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    entries = doc.get("mutants") if isinstance(doc, dict) else None
    ids = [entry.get("mutant_id") for entry in entries or ()
           if isinstance(entry, dict)]
    if not isinstance(doc, dict) \
            or doc.get("schema") != NONDETERMINISTIC_MUTANTS_SCHEMA \
            or not isinstance(entries, list) or len(ids) != len(entries) \
            or not all(isinstance(mid, str) and len(mid) == 16 for mid in ids):
        raise ValueError(
            f"REFUSED: {path} is not a {NONDETERMINISTIC_MUTANTS_SCHEMA} list "
            f"of 16-character mutant ids")
    return frozenset(ids)


def classify_outcome(baseline_outcome: Optional[str],
                     outcome: str) -> str:
    """`kill` / `survived` / `infrastructure`, per §3.10.

    The timeout rule is written out rather than being left implicit in the
    eligibility test.  Today only a baseline that PASSED is eligible, so a
    baseline can never have timed out and every mutant timeout is a kill —
    but if eligibility is ever widened, an item that times out on its own
    would start scoring a kill for every mutant, which is the same
    "reward for failing" inversion this rewrite exists to remove, one level
    down.  The condition stays explicit so that widening eligibility cannot
    silently invert it.
    """
    if outcome in KILL_OUTCOMES:
        return "kill"
    if outcome == "timeout":
        return "infrastructure" if baseline_outcome == "timeout" else "kill"
    if outcome in SURVIVED_OUTCOMES:
        return "survived"
    if outcome in INFRASTRUCTURE_OUTCOMES:
        return "infrastructure"
    raise ValueError(
        f"REFUSED: unknown mutant-run outcome {outcome!r}. Bucketing an "
        f"unrecognised harness label by default is how a whole campaign gets "
        f"mis-scored without a witness; add it to KILL_OUTCOMES, "
        f"SURVIVED_OUTCOMES or INFRASTRUCTURE_OUTCOMES deliberately.")


def recall(baseline_by_item: dict, mutant_results: list,
           gold_killed: dict, expected_pairs: Optional[set] = None) -> dict:
    """Mutation recall (§3.10), as review P1-1 rewrote it.

    * `baseline_by_item`: `{item_id: outcome}` from the FINAL, UNMUTATED run —
      the authoritative scoring run of §3.9, never a trial.
    * `mutant_results`: `[{"item_id", "mutant_id", "outcome"}]`, outcomes in
      the harness's own vocabulary.
    * `gold_killed`: `{item_id: set(mutant_ids gold killed)}`.  The POPULATION
      is the items whose gold set is non-empty; an item gold cannot kill
      anything on carries no information about a candidate, and leaving it in
      would let a candidate be scored 0 on a mutant nothing can detect.

    **Eligibility is the whole point of this rewrite.**  An item scores only
    if its baseline run PASSED.  The metric it replaces defined a kill as
    "the mutated run did not pass", so a test that always fails — an empty
    stub, a syntax error, a container that never boots — killed every mutant
    it was scored against and came out at 1.0: the vacuous candidate scored
    *higher* than a real one.  Here an ineligible item scores nothing at all,
    and a candidate with no eligible items scores exactly 0.

    Aggregation is macro over eligible items, as §3.10 requires: pooling would
    let one item with a thousand covered mutants outvote fifty items with ten.
    `recall` must always be read with `n_eligible` beside it — a 1.0 over two
    eligible items out of 422 is not a capability result, and reporting the
    number alone is the same mistake in a different disguise.
    """
    population = sorted(i for i, killed in gold_killed.items() if killed)
    pop_set = set(population)
    n_items = len(set(baseline_by_item) | set(gold_killed))

    by_pair: dict[tuple[str, str], str] = {}
    for row in mutant_results:
        for key in ("item_id", "mutant_id", "outcome"):
            if key not in row:
                raise ValueError(f"REFUSED: mutant result row is missing "
                                 f"{key!r}: {row!r}")
        pair = (row["item_id"], row["mutant_id"])
        if pair in by_pair:
            # §3.10 puts the single retry in the CALLER, so two rows for one
            # pair mean either an unresolved retry or a double execution.
            # Whichever won would depend on list order, which is exactly the
            # kind of silent, order-dependent scoring the accidental K=2 run
            # already produced once (26 outcome disagreements on
            # byte-identical input — A.7).
            raise ValueError(
                f"REFUSED: two results for item {pair[0]} / mutant {pair[1]} "
                f"({by_pair[pair]!r} and {row['outcome']!r}). Resolve the "
                f"retry before scoring; which row wins must not depend on "
                f"list order.")
        by_pair[pair] = row["outcome"]

    per_item: dict[str, dict] = {}
    ineligible: list[str] = []
    n_equivalent = 0
    n_infrastructure = 0
    n_candidate_only = 0

    results_by_item: dict[str, set] = {}
    for (item_id, mid) in by_pair:
        results_by_item.setdefault(item_id, set()).add(mid)

    for item_id in population:
        baseline = baseline_by_item.get(item_id)
        if baseline != "passed":
            # Always-failing, non-compiling, container-boot failure, or simply
            # never run: none of them may score, and none of them may be
            # counted as killing anything.
            ineligible.append(item_id)
            continue
        gold_set = set(gold_killed[item_id])
        killed = 0
        denominator = 0
        for mid in sorted(gold_set):
            outcome = by_pair.get((item_id, mid))
            if outcome is None:
                # A missing row is indistinguishable from an execution that
                # never happened.  Assuming "survived" would let a crashed
                # worker manufacture a low score for the candidate; assuming
                # "killed" would let it manufacture a high one.  Excluded and
                # counted, like any other infrastructure outcome.
                n_infrastructure += 1
                continue
            verdict = classify_outcome(baseline, outcome)
            if verdict == "infrastructure":
                n_infrastructure += 1
                continue
            denominator += 1
            if verdict == "kill":
                killed += 1
        for mid in sorted(results_by_item.get(item_id, ())):
            if mid in gold_set:
                continue
            outcome = by_pair[(item_id, mid)]
            verdict = classify_outcome(baseline, outcome)
            if verdict == "infrastructure":
                n_infrastructure += 1
            elif verdict == "kill":
                # The candidate detects a mutant gold does not.  It cannot
                # raise a recall whose denominator is gold's set, but it is
                # not an equivalent mutant either, and reporting it is the
                # only way a reader can tell the gold set is incomplete.
                n_candidate_only += 1
            else:
                # Neither gold nor the candidate distinguishes it: equivalent
                # as far as this benchmark can observe.  Out of the
                # denominator (§3.10) and reported.
                n_equivalent += 1
        per_item[item_id] = {
            "killed": killed,
            "denominator": denominator,
            # Denominator 0 means every one of this item's gold mutants was
            # excluded, so there is nothing to score — None, not 0.0, because
            # 0.0 would drag the macro average down for an item the candidate
            # was never actually tested on.
            "recall": (round(killed / denominator, 6) if denominator else None),
        }

    # Completeness, when the caller can say what completeness is.
    #
    # Duplicates are already refused above, which is what protects a
    # resharded campaign. The opposite mistake is silent: a short file scores
    # on whatever it holds and its recall is indistinguishable from a complete
    # one. `expected_pairs` is the set of (item_id, mutant_id) the campaign
    # was supposed to execute; anything missing is named rather than averaged
    # over.
    missing_pairs: list = []
    if expected_pairs is not None:
        got = {(r["item_id"], r["mutant_id"]) for r in mutant_results}
        missing_pairs = sorted(set(expected_pairs) - got)
        if missing_pairs:
            raise ValueError(
                f"REFUSED: {len(missing_pairs)} expected (item, mutant) "
                f"execution(s) are absent from the results, e.g. "
                f"{missing_pairs[:3]}. A recall computed over a short file is "
                f"not a smaller measurement of the same thing — it is a "
                f"different denominator. Finish or resume the campaign, or "
                f"pass the reduced expectation deliberately.")

    scored = [v["recall"] for v in per_item.values() if v["recall"] is not None]
    return {
        "recall": round(sum(scored) / len(scored), 6) if scored else 0.0,
        "n_eligible": len(scored),
        "n_items": n_items,
        "n_population": len(pop_set),
        "per_item": per_item,
        "excluded": {"equivalent": n_equivalent,
                     "infrastructure": n_infrastructure,
                     "candidate_only_kill": n_candidate_only},
        "ineligible": sorted(ineligible),
        "completeness_checked": expected_pairs is not None,
    }


def _completeness_checks(check) -> None:
    """A short results file must refuse, and a complete one must not."""
    base = {"i1": "passed"}
    gold = {"i1": {"m1", "m2"}}
    rows = [{"item_id": "i1", "mutant_id": "m1", "outcome": "failed"},
            {"item_id": "i1", "mutant_id": "m2", "outcome": "passed"}]
    expected = {("i1", "m1"), ("i1", "m2")}
    check("a complete results file scores normally",
          recall(base, rows, gold, expected_pairs=expected)["recall"] == 0.5)
    check("completeness is recorded as having been checked",
          recall(base, rows, gold, expected_pairs=expected)
          ["completeness_checked"] is True)
    try:
        recall(base, rows[:1], gold, expected_pairs=expected)
        check("a SHORT results file is refused, not scored", False, "scored")
    except ValueError as e:
        check("a SHORT results file is refused, not scored",
              "are absent from the results" in str(e))
    check("without an expectation the old behaviour is unchanged",
          recall(base, rows[:1], gold)["completeness_checked"] is False)


def selftest() -> int:
    import os as _os
    import random
    import tempfile
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def raises(fn, needle=""):
        try:
            fn()
        except ValueError as e:
            return needle in str(e)
        except Exception:  # noqa: BLE001
            return False
        return False

    # ---------------------------------------------------------- identity
    args = ("src/CoreShop/Component/Order/Model/Order.php", "NegateConditional",
            412, 17, "$a < $b", "$a >= $b")
    base = mutant_id(*args)
    check("mutant_id is stable across calls",
          base == mutant_id(*args) == mutant_id(*args), base)
    check("mutant_id is 16 hex chars",
          len(base) == 16 and all(c in "0123456789abcdef" for c in base), base)
    variants = {
        "file": ("src/CoreShop/Bundle/CoreBundle/X.php",) + args[1:],
        "operator": (args[0], "ConditionalBoundary") + args[2:],
        "start_line": args[:2] + (413,) + args[3:],
        "start_col": args[:3] + (18,) + args[4:],
        "original": args[:4] + ("$a <= $b", args[5]),
        "mutated": args[:5] + ("$a > $b",),
    }
    for field, alt in variants.items():
        check(f"mutant_id changes with {field}", mutant_id(*alt) != base)
    check("mutant_id changes with engine",
          mutant_id(*args, engine="infection") != base)
    check("mutant_id changes with engine_version",
          mutant_id(*args, engine_version="2.0") != base)
    check("a NUL in a field is refused, not hashed",
          raises(lambda: mutant_id(args[0], args[1], 1, 1, "a\0b", "c"),
                 "REFUSED"))

    # ---------------------------------------------------------- exclusions
    check("production under the keep roots is included",
          not is_excluded("src/CoreShop/Component/Order/Model/Order.php")
          and not is_excluded("src/CoreShop/Bundle/CoreBundle/X.php"))
    check("vendor/ and var/ are excluded",
          is_excluded("vendor/behat/behat/src/X.php")
          and is_excluded("var/classes/DataObject/Product.php"))
    check("everything outside the keep roots is excluded",
          is_excluded("src/CoreShop/Behat/Context/Domain/CartContext.php")
          and is_excluded("features/domain/cart/x.feature")
          and is_excluded("bin/console"))
    check("keep roots respect directory boundaries",
          is_excluded("src/CoreShop/Componentry/X.php"))
    # `lstrip("./")` strips a CHARACTER SET, so it ate the leading dot of a
    # real name and, worse, turned an escaping path into an included one.
    check("a leading './' is removed but a dotted name is not eaten",
          normalise_path("./src/CoreShop/Component/A.php")
          == "src/CoreShop/Component/A.php"
          and normalise_path(".github/scripts/x.php") == ".github/scripts/x.php",
          normalise_path(".github/scripts/x.php"))
    check("a path that escapes the repo is not rewritten into an included one",
          normalise_path("../../src/CoreShop/Component/A.php")
          == "../../src/CoreShop/Component/A.php"
          and is_excluded("../../src/CoreShop/Component/A.php"),
          normalise_path("../../src/CoreShop/Component/A.php"))

    # -- the keep roots are now the boundary's `behat.prod_paths` row --------
    #
    # CoreShop first, and byte for byte: the literal below is what
    # `EXCLUDED_PREFIXES` was before the row became its source, and both the
    # tuple AND a manifest built from a CoreShop-shaped fixture have to be
    # identical under it -- the manifest carries `exclusions` inside the
    # bytes the digest covers, so every archived CoreShop population
    # re-verifies or it does not.
    from . import mutation_attestation as _MA
    frozen_coreshop_exclusions = (
        "!src/CoreShop/Component", "!src/CoreShop/Bundle", "vendor/", "var/")
    check("CoreShop's row derives exactly the exclusions constant it replaced",
          exclusions_for_prod_paths(CORESHOP_PROD_PATHS)
          == frozen_coreshop_exclusions == EXCLUDED_PREFIXES,
          str(EXCLUDED_PREFIXES))
    coreshop_fixture = [
        {"file": "src/CoreShop/Component/Order/Model/Order.php",
         "operator": "NegateConditional", "start_line": 412, "start_col": 17,
         "original": "$a < $b", "mutated": "$a >= $b"},
        {"file": "src/CoreShop/Bundle/CoreBundle/X.php",
         "operator": "ConditionalBoundary", "start_line": 8, "start_col": 3,
         "original": "$a < $b", "mutated": "$a <= $b"},
        {"file": "src/CoreShop/Behat/Context/Domain/CartContext.php",
         "operator": "TrueValue", "start_line": 3, "start_col": 5,
         "original": "$x", "mutated": "true"},
        {"file": "vendor/behat/behat/src/X.php", "operator": "TrueValue",
         "start_line": 1, "start_col": 1, "original": "$y", "mutated": "true"},
    ]
    check("a CoreShop population is byte-identical under the derived policy",
          _MA.canonical_bytes(build_manifest(
              coreshop_fixture, parser_version="nikic/php-parser 5.0.0",
              exclusions=frozen_coreshop_exclusions))
          == _MA.canonical_bytes(build_manifest(
              coreshop_fixture, parser_version="nikic/php-parser 5.0.0",
              exclusions=exclusions_for_prod_paths(CORESHOP_PROD_PATHS))))

    # Sylius: three roots, and the defect this closes.  Under the CoreShop
    # constant every one of these mutants was excluded and the verb wrote an
    # n=0 manifest.
    sylius_roots = ("src/Sylius/Component", "src/Sylius/Bundle",
                    "src/Sylius/Abstraction")
    sylius_exclusions = exclusions_for_prod_paths(sylius_roots)
    check("a second Behat project's row yields its own three keep roots",
          sylius_exclusions == (
              "!src/Sylius/Component", "!src/Sylius/Bundle",
              "!src/Sylius/Abstraction", "vendor/", "var/"),
          str(sylius_exclusions))
    check("Sylius production is kept while vendor/, var/ and the Behat glue "
          "are dropped -- under the CoreShop constant all five were dropped",
          not is_excluded("src/Sylius/Component/Core/Model/Order.php",
                          sylius_exclusions)
          and not is_excluded("src/Sylius/Bundle/ApiBundle/X.php",
                              sylius_exclusions)
          # The PSR-4 map puts this package's code two levels below the row's
          # root; a keep root matches the directory and everything under it.
          and not is_excluded(
              "src/Sylius/Abstraction/StateMachine/src/S.php",
              sylius_exclusions)
          and is_excluded("src/Sylius/Behat/Context/Api/T.php",
                          sylius_exclusions)
          and is_excluded("vendor/x/Y.php", sylius_exclusions)
          and is_excluded("var/cache/Z.php", sylius_exclusions)
          and is_excluded("src/Sylius/Componentry/X.php", sylius_exclusions))
    sylius_manifest = build_manifest(
        [{"file": path, "operator": "ArithmeticOperator", "start_line": 1,
          "start_col": 3, "original": "+", "mutated": "-"}
         for path in ("src/Sylius/Component/Core/Model/Order.php",
                      "src/Sylius/Bundle/ApiBundle/X.php",
                      "src/Sylius/Abstraction/StateMachine/src/S.php",
                      "src/Sylius/Behat/Context/Api/T.php",
                      "vendor/x/Y.php")],
        parser_version="nikic/php-parser 5.3.1@fixture",
        exclusions=sylius_exclusions)
    # `_audit_roots` is UNCHANGED and reads the manifest's `!` entries; this
    # is the statement that the audit walks Sylius's three roots and that
    # every kept mutant really lies inside them.
    audit_roots = _MA._audit_roots(sylius_manifest)
    check("the unchanged audit-root derivation walks Sylius's three roots, "
          "and every kept mutant lies inside them",
          sylius_manifest["n"] == 3 and sylius_manifest["n_excluded"] == 2
          and audit_roots == ["src/Sylius/Abstraction", "src/Sylius/Bundle",
                              "src/Sylius/Component"]
          and _MA._mutants_outside_roots(sylius_manifest, audit_roots) == [],
          str(audit_roots))
    check("a row with no production root is refused, not defaulted to the "
          "whole repository",
          raises(lambda: exclusions_for_prod_paths(()),
                 "needs at least one production root")
          and raises(lambda: exclusions_for_prod_paths(("",)),
                     "needs at least one production root")
          # None is the same refusal here and not a TypeError out of
          # `tuple(None)`.  A boundary cannot produce it any more --
          # `behat_project` refuses a null `prod_paths` where the row is
          # read -- so this stands for a direct caller.
          and raises(lambda: exclusions_for_prod_paths(None),
                     "needs at least one production root"))

    # -- and the fragments a project declares non-product INSIDE those roots
    #
    # OWNER RULING 2026-09-11: the population is product code only.  Sylius
    # keeps its unit tests, specs, migrations, DI configuration and fixtures
    # under the same three roots as its product code -- 31,297 of 43,670
    # mutants -- and neither `is_excluded` (whose keeps and drops are whole
    # trees) nor the production boundary (which answers which files are the
    # BEHAT GLUE) can separate them.  The ruling names KINDS, so the row
    # carries both spellings of each; whole-segment matching is exactly why
    # `tests/` does not also take the singular `test/`.
    sylius_fragments = ("tests/", "Tests/", "test/", "Test/", "spec/",
                        "Migrations/", "Resources/config/", "config/",
                        "Fixture/")

    def declared(path, fragments=sylius_fragments, roots=sylius_roots):
        return is_population_excluded(path, fragments, roots)

    check("a declared fragment matches at any depth under a production root "
          "-- directly under it and far below it",
          declared("src/Sylius/Component/Core/tests/Model/OrderTest.php")
          and declared("src/Sylius/Component/Core/tests/a/b/DeepTest.php")
          and declared("src/Sylius/Component/Core/tests/X.php")
          and declared("src/Sylius/Bundle/ApiBundle/Migrations/Version1.php")
          and declared("src/Sylius/Abstraction/StateMachine/spec/S.php"))
    # Asked of the two-segment fragment ALONE: the row also carries `config/`,
    # which subsumes it, and this is the statement about adjacency and order.
    two_segment = ("Resources/config/",)
    check("...and a two-segment fragment matches only where its segments are "
          "adjacent, in its order",
          is_population_excluded(
              "src/Sylius/Bundle/ApiBundle/Resources/config/api.php",
              two_segment, sylius_roots)
          and not is_population_excluded(
              "src/Sylius/Bundle/ApiBundle/Resources/X.php",
              two_segment, sylius_roots)
          and not is_population_excluded(
              "src/Sylius/Bundle/Api/config/Resources/X.php",
              two_segment, sylius_roots))
    # The P1 of the review of PR #597: the first row read `tests/`/`Tests/`
    # only, and left 240 mutants in 26 per-bundle test applications and the
    # 38 of `Component/Core/Test/Services` -- 35 of them COVERED, in the
    # default-channel factory every scenario's setup runs -- inside the
    # scored population.  A plural fragment does not match a singular
    # directory, and that is the point of whole-segment matching.
    check("the singular and plural spellings are SEPARATE fragments, and "
          "both are declared",
          declared("src/Sylius/Bundle/AdminBundle/test/src/Kernel.php")
          and declared("src/Sylius/Component/Core/Test/Services/"
                       "DefaultChannelFactory.php")
          and declared("src/Sylius/Abstraction/StateMachine/config/"
                       "services.php")
          and not is_population_excluded(
              "src/Sylius/Bundle/AdminBundle/test/src/Kernel.php",
              ("tests/", "Tests/"), sylius_roots)
          and not is_population_excluded(
              "src/Sylius/Component/Core/Test/Services/"
              "DefaultChannelFactory.php", ("tests/", "Tests/"),
              sylius_roots))
    # The three shapes a looser rule takes with it.  A substring test loses
    # `spec_helper.php` and `SpecialCase/`; a prefix test loses every
    # `tests/` below the first level, which is most of the 26,436.
    check("the match is on DIRECTORY segments: a FILE with a fragment's "
          "name, and a directory that merely begins with one, are product "
          "code",
          not declared("src/Sylius/Component/Core/tests.php")
          and not declared("src/Sylius/Component/Core/Fixture.php")
          and not declared("src/Sylius/Component/Core/tests2/X.php")
          and not declared("src/Sylius/Component/SpecialCase/spec_helper.php"))
    check("product code is never taken, and neither is a path outside the "
          "production roots -- a fragment is read UNDER a root",
          not declared("src/Sylius/Component/Core/Model/Order.php")
          and not declared("src/Sylius/Behat/Context/Api/tests/X.php")
          and not declared("tests/Functional/X.php"))
    check("a project that declares nothing loses nothing, and a fragment "
          "naming no segment is SKIPPED rather than read as the zero-length "
          "run that is a subsequence of every path",
          not is_population_excluded(
              "src/Sylius/Component/Core/tests/X.php", (), sylius_roots)
          and not is_population_excluded(
              "src/Sylius/Component/Core/tests/X.php", ("", "/"),
              sylius_roots)
          and not is_population_excluded(
              "src/Sylius/Component/Core/Model/Order.php", ("", "/"),
              sylius_roots))
    check("nested roots read the fragment under the MOST SPECIFIC one, so a "
          "root's own segments are never part of a match",
          is_population_excluded("a/b/tests/X.php", ("tests/",), ("a", "a/b"))
          and is_population_excluded("a/b/X.php", ("b/",), ("a",))
          and not is_population_excluded("a/b/X.php", ("b/",), ("a", "a/b")))

    # ---------------------------------------------------------- manifest
    def raw_mutant(path, op, line, col, orig="$a < $b", mut="$a >= $b"):
        return {"file": path, "operator": op, "start_line": line,
                "start_col": col, "original": orig, "mutated": mut}

    C = "src/CoreShop/Component/Order/Model/Order.php"
    B = "src/CoreShop/Bundle/CoreBundle/Cart.php"
    raw = [
        raw_mutant(C, "NegateConditional", 412, 17),
        raw_mutant(C, "ConditionalBoundary", 412, 17, "$a < $b", "$a <= $b"),
        raw_mutant(C, "ArithmeticOperator", 90, 5, "$a + $b", "$a - $b"),
        raw_mutant(B, "ReturnValue", 12, 9, "return $x;", "return null;"),
        raw_mutant(B, "MethodCallRemoval", 40, 9, "$o->m();", ";"),
        raw_mutant("vendor/x/y/Z.php", "TrueValue", 3, 1, "$q", "true"),
        raw_mutant("var/classes/DataObject/P.php", "FalseValue", 8, 2, "$q", "false"),
        raw_mutant("src/CoreShop/Behat/Context/Domain/CartContext.php",
                   "Increment", 5, 5, "$i++", "$i--"),
    ]
    man = build_manifest(raw, parser_version="nikic/php-parser v5.7.0@dca41cd")
    check("excluded paths are counted, not silently dropped",
          man["n"] == 5 and man["n_excluded"] == 3,
          f"n={man['n']} n_excluded={man['n_excluded']}")
    check("the digest is stored on the manifest and recomputable",
          man["digest"] == manifest_digest(man))
    man2 = build_manifest(list(raw),
                          parser_version="nikic/php-parser v5.7.0@dca41cd")
    check("the digest reproduces over the same input",
          man2["digest"] == man["digest"])
    check("the v2 default is the exact v1 prefix plus three named operators",
          OPERATORS[:len(OPERATORS_V1)] == OPERATORS_V1
          and OPERATORS[len(OPERATORS_V1):] == (
              "LogicalConnector", "RemoveNegation", "ConstantReplacement")
          and man["operators"] == list(OPERATORS))
    check("production revision policy is mandatory for v2 and absent for v1",
          record_enumerator_revision("v2") is True
          and record_enumerator_revision("v2", requested=True) is True
          and record_enumerator_revision("v1") is False)
    check("a v1 build cannot fabricate current enumerator provenance",
          raises(lambda: record_enumerator_revision("v1", requested=True),
                 "incompatible"))
    check("the manifest operator list selects the same profile at apply time",
          operator_profile_for(OPERATORS_V1) == "v1"
          and operator_profile_for(OPERATORS) == "v2")
    check("an unknown or reordered operator list has no guessed profile",
          raises(lambda: operator_profile_for(reversed(OPERATORS)),
                 "neither the exact ordered"))
    legacy = build_manifest(
        list(raw), parser_version="nikic/php-parser v5.7.0@dca41cd",
        operators=OPERATORS_V1)
    legacy_keys = set(legacy)
    zero_invalid = build_manifest(
        list(raw), parser_version="nikic/php-parser v5.7.0@dca41cd",
        operators=OPERATORS_V1, n_invalid=0)
    check("an explicit zero invalid count uses the legacy omit encoding",
          zero_invalid == legacy and set(zero_invalid) == legacy_keys)
    revised = build_manifest(
        list(raw), parser_version="nikic/php-parser v5.7.0@dca41cd",
        n_invalid=2, enumerator_rev="r2t-mutate/m1-validity-1")
    check("nonzero invalid count and enumerator revision enter the manifest "
          "and its digest",
          revised["n_invalid"] == 2
          and revised["enumerator_rev"] == "r2t-mutate/m1-validity-1"
          and revised["digest"] == manifest_digest(revised)
          and revised["digest"] != man["digest"])
    check("invalid optional enumerator metadata is refused",
          raises(lambda: build_manifest(raw, parser_version="p",
                                        n_invalid=-1), "n_invalid")
          and raises(lambda: build_manifest(raw, parser_version="p",
                                            n_invalid=True), "n_invalid")
          and raises(lambda: build_manifest(raw, parser_version="p",
                                            enumerator_rev="  "),
                     "enumerator_rev"))

    # One shuffle seed is not a test of order-independence: with the sort key
    # truncated to (file, line, col) — i.e. no tie-break at all between the two
    # mutants sharing C:412:17 — 13 of the 20 seeds below produce a different
    # digest, but seed 7 alone does not.  The original check used seed 7 and
    # passed against a broken sort. All 20 are used now.
    shuffled = list(raw)
    random.Random(7).shuffle(shuffled)
    digests = set()
    orders = set()
    for _seed in range(20):
        _sh = list(raw)
        random.Random(_seed).shuffle(_sh)
        _m = build_manifest(_sh, parser_version="nikic/php-parser v5.7.0@dca41cd")
        digests.add(_m["digest"])
        orders.add(tuple(x["id"] for x in _m["mutants"]))
    check("mutants sort independently of the enumerator's traversal order "
          "(20 input permutations, one digest)",
          digests == {man["digest"]} and orders ==
          {tuple(m["id"] for m in man["mutants"])},
          f"{len(digests)} distinct digests, {len(orders)} distinct orders")
    # The positional assertion covers the operator tie-break too: the two
    # mutants at C:412:17 differ only in operator and id, so asserting
    # (file, line, col) alone said nothing about how the tie is broken.
    check("the canonical order is (file, line, col, operator, id)",
          [(m["file"], m["start_line"], m["start_col"], m["operator"])
           for m in man["mutants"]]
          == [(B, 12, 9, "ReturnValue"), (B, 40, 9, "MethodCallRemoval"),
              (C, 90, 5, "ArithmeticOperator"),
              (C, 412, 17, "ConditionalBoundary"),
              (C, 412, 17, "NegateConditional")],
          str([(m["file"], m["start_line"], m["operator"])
               for m in man["mutants"]]))

    man_ops = build_manifest(
        [r for r in raw if r["operator"] != "Increment"],
        parser_version="nikic/php-parser v5.7.0@dca41cd",
        operators=tuple(o for o in OPERATORS if o != "Increment"))
    check("a different operator set changes the digest",
          man_ops["digest"] != man["digest"])
    man_excl = build_manifest(raw,
                              parser_version="nikic/php-parser v5.7.0@dca41cd",
                              exclusions=EXCLUDED_PREFIXES + ("src/CoreShop/Bundle/CoreBundle",))
    check("a different exclusion list changes the digest and the population",
          man_excl["digest"] != man["digest"] and man_excl["n"] == 3
          and man_excl["n_excluded"] == 5, str(man_excl["n"]))
    man_parser = build_manifest(raw, parser_version="nikic/php-parser v5.6.0@aaaa")
    check("a different parser version changes the digest",
          man_parser["digest"] != man["digest"])

    # -- the ENGINE is a parameter now, and it has to reach both the header
    #    and every id.  A manifest that renamed its engine while its ids still
    #    hashed the old one would let two populations share id space, which is
    #    exactly what `mutant_id` puts the engine in the hash to prevent.
    man_py = build_manifest(raw, parser_version="nikic/php-parser v5.6.0@aaaa",
                            engine="r2t-mutate-py", engine_version="1.0")
    check("a second engine's manifest declares ITS engine, not this module's",
          man_py["engine"] == "r2t-mutate-py"
          and man_py["engine_version"] == "1.0", man_py["engine"])
    check("...and the engine reaches every mutant id, not just the header",
          {m["id"] for m in man_py["mutants"]}.isdisjoint(
              {m["id"] for m in man_parser["mutants"]})
          and man_py["mutants"][0]["id"] == mutant_id(
              man_py["mutants"][0]["file"], man_py["mutants"][0]["operator"],
              man_py["mutants"][0]["start_line"],
              man_py["mutants"][0]["start_col"],
              man_py["mutants"][0]["original"],
              man_py["mutants"][0]["mutated"],
              engine="r2t-mutate-py", engine_version="1.0"))
    check("the default engine is still the PHP one and reaches the manifest "
          "without an implicit engine-profile fork",
          man["engine"] == ENGINE and man["engine_version"] == ENGINE_VERSION
          and build_manifest(raw, parser_version="nikic/php-parser v5.7.0@dca41cd",
                             engine=ENGINE, engine_version=ENGINE_VERSION
                             )["digest"] == man["digest"])

    # Sampling is checked on 12 mutants, not on the 5 of `man`.  Two seeds over
    # a 2-of-5 sample agreed by coincidence, so `_select_sample` could ignore
    # its seed completely (`return mutants[:sample]`) and every sampling check
    # below still passed — "a different sample seed changes the digest" is true
    # of ANY implementation, because `seed` is itself a digested manifest field.
    # The seed must therefore be shown to change the SELECTED SET.
    samp_raw = [raw_mutant(C, "TrueValue", n, 1, f"$q{n}", "true")
                for n in range(1, 13)]
    samp_all = build_manifest(samp_raw, parser_version="p")
    canonical_ids = [m["id"] for m in samp_all["mutants"]]
    samp_shuf = list(samp_raw)
    random.Random(3).shuffle(samp_shuf)
    s1 = build_manifest(samp_raw, parser_version="p", sample=4, seed=1)
    s1b = build_manifest(samp_shuf, parser_version="p", sample=4, seed=1)
    s2 = build_manifest(samp_raw, parser_version="p", sample=4, seed=2)
    ids1 = [m["id"] for m in s1["mutants"]]
    ids2 = [m["id"] for m in s2["mutants"]]
    check("sampling is deterministic given the seed, whatever the input order",
          s1["digest"] == s1b["digest"] and ids1 == [m["id"] for m in s1b["mutants"]]
          and s1["n"] == 4)
    check("a different sample seed selects a DIFFERENT SET, not just a "
          "different digest",
          set(ids1) != set(ids2) and s2["digest"] != s1["digest"],
          f"{ids1} vs {ids2}")
    check("the sample is not simply the first n in canonical order",
          ids1 != canonical_ids[:4] and ids2 != canonical_ids[:4],
          f"{ids1} vs prefix {canonical_ids[:4]}")
    check("the seed is recorded in the manifest", s1["seed"] == 1 and s1["sample"] == 4)
    check("a sample keeps the canonical order",
          ids1 == [i for i in canonical_ids if i in set(ids1)]
          and ids2 == [i for i in canonical_ids if i in set(ids2)],
          f"{ids1}")
    check("sampling without a seed is refused",
          raises(lambda: build_manifest(raw, parser_version="p", sample=2),
                 "REFUSED"))
    check("a sample larger than the population is refused, never silently "
          "recorded",
          raises(lambda: build_manifest(samp_raw, parser_version="p",
                                        sample=13, seed=1),
                 "exceeds the population"))
    check("a seed the manifest cannot serialise is refused",
          raises(lambda: build_manifest(samp_raw, parser_version="p",
                                        sample=2, seed={1, 2}),
                 "not JSON"))

    dup = [raw_mutant(C, "NegateConditional", 412, 17),
           raw_mutant(C, "NegateConditional", 412, 17)]
    check("duplicate mutant ids are refused",
          raises(lambda: build_manifest(dup, parser_version="p"),
                 "duplicate mutant id"))
    check("a missing required field is refused",
          raises(lambda: build_manifest([{"file": C, "operator": "TrueValue"}],
                                        parser_version="p"), "REFUSED"))
    check("an unrecognised enumerator field is refused",
          raises(lambda: build_manifest(
              [dict(raw_mutant(C, "TrueValue", 1, 1), score=3)],
              parser_version="p"), "unrecognised"))
    check("an operator outside the declared set is refused",
          raises(lambda: build_manifest([raw_mutant(C, "Nonsense", 1, 1)],
                                        parser_version="p"), "operator set"))
    check("a no-op mutation is refused",
          raises(lambda: build_manifest(
              [raw_mutant(C, "TrueValue", 1, 1, "true", "true")],
              parser_version="p"), "into itself"))
    deletion = build_manifest(
        [raw_mutant(C, "RemoveNegation", 1, 1, "!", "")],
        parser_version="p")
    check("an empty replacement is a valid deletion mutant, not missing "
          "metadata",
          deletion["n"] == 1
          and deletion["mutants"][0]["mutated"] == "")
    check("a non-string replacement is still refused",
          raises(lambda: build_manifest(
              [raw_mutant(C, "RemoveNegation", 1, 1, "!", None)],
              parser_version="p"), "non-string mutated"))
    check("an empty replacement is refused for non-deletion operators",
          raises(lambda: build_manifest(
              [raw_mutant(C, "TrueValue", 1, 1, "true", "")],
              parser_version="p"), "only RemoveNegation"))
    check("a 0-based line is refused",
          raises(lambda: build_manifest([raw_mutant(C, "TrueValue", 0, 1)],
                                        parser_version="p"), "1-based"))
    # Both halves of the claim are asserted.  Asserting only that the ids match
    # was satisfied by dropping the optional fields on the floor (demonstrated:
    # deleting the OPTIONAL_FIELDS copy loop in `_validate` left this green).
    _with = build_manifest([dict(raw_mutant(C, "TrueValue", 1, 1),
                                 method="foo", end_line=1, end_col=4)],
                           parser_version="p")["mutants"][0]
    _without = build_manifest([raw_mutant(C, "TrueValue", 1, 1)],
                              parser_version="p")["mutants"][0]
    check("an optional field survives into the manifest but not the id",
          _with["id"] == _without["id"]
          and _with.get("method") == "foo" and _with.get("end_line") == 1
          and _with.get("end_col") == 4 and "method" not in _without,
          str(_with))

    # ------------------------------------------------------ parser version
    with tempfile.TemporaryDirectory() as d:
        lock = _os.path.join(d, "composer.lock")
        with open(lock, "w", encoding="utf-8") as fh:
            json.dump({"packages": [{"name": "symfony/console", "version": "v5.4"}],
                       "packages-dev": [{"name": "nikic/php-parser",
                                         "version": "v5.7.0",
                                         "dist": {"reference": "dca41cd"}}]}, fh)
        check("the parser version is read from composer.lock, not hard-coded",
              read_parser_version(lock) == "nikic/php-parser v5.7.0@dca41cd",
              read_parser_version(lock))
        empty = _os.path.join(d, "empty.lock")
        with open(empty, "w", encoding="utf-8") as fh:
            json.dump({"packages": []}, fh)
        check("a lock file without the parser is refused",
              raises(lambda: read_parser_version(empty), "REFUSED"))
        check("a missing lock file is refused",
              raises(lambda: read_parser_version(_os.path.join(d, "nope.lock")),
                     "REFUSED"))
        arr = _os.path.join(d, "raw.json")
        with open(arr, "w", encoding="utf-8") as fh:
            json.dump(raw[:2], fh)
        jsonl = _os.path.join(d, "raw.jsonl")
        with open(jsonl, "w", encoding="utf-8") as fh:
            for r in raw[:2]:
                fh.write(json.dumps(r) + "\n")
        check("the enumerator's array and JSONL forms load identically",
              load_raw(arr) == load_raw(jsonl) == raw[:2])
        one = _os.path.join(d, "one.jsonl")
        with open(one, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(raw[0]) + "\n")
        check("a one-line JSONL file is not mistaken for an envelope",
              load_raw(one) == raw[:1], str(load_raw(one)))
        # The shape `r2t/php/mutate.php --out` actually writes: a
        # JSON_PRETTY_PRINT object with the array under "mutants".  Reading it
        # used to die with a bare JSONDecodeError on line 2.
        env = _os.path.join(d, "manifest.json")
        with open(env, "w", encoding="utf-8") as fh:
            json.dump({"engine": ENGINE, "engine_version": ENGINE_VERSION,
                       "parser": "v5.7.0", "files": 412, "errors": {},
                       "mutants": raw[:2]}, fh, indent=4)
        check("the PHP enumerator's own envelope loads, and only its mutants do",
              load_raw(env) == raw[:2], str(load_raw(env))[:120])
        bad_env = _os.path.join(d, "bad.json")
        with open(bad_env, "w", encoding="utf-8") as fh:
            json.dump({"engine": ENGINE, "files": 412}, fh, indent=4)
        check("an envelope with no mutant array is refused, not stack-traced",
              raises(lambda: load_raw(bad_env), "REFUSED"))
        drift = _os.path.join(d, "drift.json")
        with open(drift, "w", encoding="utf-8") as fh:
            json.dump({"engine": ENGINE, "engine_version": "1.1",
                       "mutants": raw[:2]}, fh)
        check("an enumerator on a different engine version is refused, since "
              "the id hashes it",
              raises(lambda: load_raw(drift), "what a mutant IS"))
        # The refusal follows the PARAMETER, not the constant: a second
        # stack's enumerator output is foreign to this module's default and
        # native to its own, and getting that backwards would either refuse
        # every python manifest or accept a PHP one under python's identity.
        py_env = _os.path.join(d, "py.json")
        with open(py_env, "w", encoding="utf-8") as fh:
            json.dump({"engine": "r2t-mutate-py", "engine_version": "1.0",
                       "mutants": raw[:2]}, fh)
        check("a foreign engine's envelope is refused under the default "
              "identity", raises(lambda: load_raw(py_env), "what a mutant IS"))
        check("...and loads under its own", load_raw(
            py_env, engine="r2t-mutate-py", engine_version="1.0") == raw[:2])
        check("the PHP envelope is then refused under the python identity -- "
              "the check is symmetric, not a one-way allowance",
              raises(lambda: load_raw(env, engine="r2t-mutate-py",
                                      engine_version="1.0"),
                     "what a mutant IS"))

    # ------------------------------------------------------ coverage map
    ids = {(m["file"], m["start_line"], m["operator"]): m["id"]
           for m in man["mutants"]}
    m_neg = ids[(C, 412, "NegateConditional")]
    m_bnd = ids[(C, 412, "ConditionalBoundary")]
    m_ari = ids[(C, 90, "ArithmeticOperator")]
    m_ret = ids[(B, 12, "ReturnValue")]
    m_mcr = ids[(B, 40, "MethodCallRemoval")]
    # The line numbers here are DELIBERATELY collided across files.  With a
    # fixture whose line numbers were disjoint per file, an implementation that
    # ignored the path entirely and joined on the line number alone passed
    # every check in this block, including the one named "by file AND line"
    # (demonstrated: keying `covered` on ("ANY", line) left the selftest green).
    # i2 covers B:90 where the only line-90 mutant is in C; i3 covers C:40
    # where the only line-40 mutant is in B.
    coverage = {
        "i1": {C: [90, 412], B: [12]},
        "i2": {C: [412], B: [90]},             # B:90 holds no mutant
        "i3": {C: [40, 91], B: [12, 41]},      # C:40, C:91, B:41 hold none
    }
    by_mutant, uncovered = map_mutants_to_items(man, coverage)
    check("mapping is by file AND line",
          by_mutant[m_ari] == ["i1"] and by_mutant[m_ret] == ["i1", "i3"],
          str(by_mutant))
    check("two mutants on one covered line both map to that line's items",
          by_mutant[m_neg] == ["i1", "i2"] and by_mutant[m_bnd] == ["i1", "i2"])
    check("the same line number in ANOTHER file does not map (i2 covers B:90, "
          "the line-90 mutant is in C)",
          "i2" not in by_mutant[m_ari], str(by_mutant[m_ari]))
    check("a mutant is uncovered when only the same line in another file ran "
          "(i3 covers C:40, the line-40 mutant is in B)",
          m_mcr not in by_mutant)
    check("uncovered mutants are reported, never silently dropped",
          uncovered == [m_mcr] and m_mcr not in by_mutant, str(uncovered))
    check("every mutant is either mapped or reported uncovered",
          len(by_mutant) + len(uncovered) == man["n"])

    # ---------------------------------------------------------- batching
    plan = batches(by_mutant)
    check("one batch per covered mutant, all its scenarios in one process",
          len(plan) == 4 and all(b["n_parts"] == 1 for b in plan)
          and sorted(b["mutant_id"] for b in plan) == sorted(by_mutant))
    check("batch ordering is deterministic",
          [(b["mutant_id"], b["part"]) for b in plan]
          == [(b["mutant_id"], b["part"]) for b in batches(by_mutant)]
          and [b["mutant_id"] for b in plan] == sorted(by_mutant))
    big = {"m": [f"i{n}" for n in range(1, 60)]}
    split = batches(big, max_scenarios=25)
    check("a mutant with more scenarios than the cap splits into parts",
          [len(b["item_ids"]) for b in split] == [25, 25, 9]
          and all(b["n_parts"] == 3 for b in split))
    check("splitting loses no scenario and duplicates none",
          sorted(i for b in split for i in b["item_ids"]) == sorted(big["m"]))
    check("a mutant with no covering items has no batch, it is refused",
          raises(lambda: batches({"m": []}), "zero scenarios"))
    check("a non-integer scenario cap is refused (True is not a cap of 1)",
          raises(lambda: batches({"m": ["a", "b"]}, max_scenarios=True),
                 "REFUSED")
          and raises(lambda: batches({"m": ["a"]}, max_scenarios=0), "REFUSED"))

    # ---------------------------------------------------------- recall
    def rows(pairs):
        return [{"item_id": i, "mutant_id": m, "outcome": o}
                for (i, m, o) in pairs]

    gold = {"i1": {"m1", "m2"}, "i2": {"m3"}}

    perfect = recall({"i1": "passed", "i2": "passed"},
                     rows([("i1", "m1", "failed"), ("i1", "m2", "failed"),
                           ("i2", "m3", "failed")]), gold)
    check("a candidate that kills every mutant it is eligible for scores 1.0",
          perfect["recall"] == 1.0 and perfect["n_eligible"] == 2,
          str(perfect["recall"]))

    always_failing = recall(
        {"i1": "failed", "i2": "failed"},
        rows([("i1", "m1", "failed"), ("i1", "m2", "failed"),
              ("i2", "m3", "failed")]), gold)
    check("an always-failing candidate scores EXACTLY 0, not 1.0",
          always_failing["recall"] == 0.0
          and always_failing["n_eligible"] == 0
          and always_failing["ineligible"] == ["i1", "i2"]
          and always_failing["per_item"] == {}, str(always_failing["recall"]))

    broken = recall(
        {"i1": "parse_or_compile_error", "i2": "parse_or_compile_error"},
        rows([("i1", "m1", "failed"), ("i1", "m2", "failed"),
              ("i2", "m3", "failed")]), gold)
    check("a syntax-invalid candidate scores EXACTLY 0",
          broken["recall"] == 0.0 and broken["n_eligible"] == 0,
          str(broken["recall"]))

    boot = recall({"i1": "container_error", "i2": "passed"},
                  rows([("i1", "m1", "failed"), ("i1", "m2", "failed"),
                        ("i2", "m3", "failed")]), gold)
    check("a container-boot failure is ineligible, and its kills do not count",
          boot["ineligible"] == ["i1"] and "i1" not in boot["per_item"]
          and boot["n_eligible"] == 1)

    half = recall({"i1": "passed"},
                  rows([("i1", "m1", "failed"), ("i1", "m2", "passed")]),
                  {"i1": {"m1", "m2"}})
    check("a candidate that kills half scores 0.5",
          half["recall"] == 0.5 and half["per_item"]["i1"]["denominator"] == 2,
          str(half["recall"]))

    macro_gold = {"big": {f"m{n}" for n in range(10)}, "small": {"s1"}}
    macro = recall(
        {"big": "passed", "small": "passed"},
        rows([("big", f"m{n}", "failed") for n in range(10)]
             + [("small", "s1", "passed")]), macro_gold)
    check("macro is not micro, and macro is what is returned",
          macro["recall"] == 0.5 and round(10 / 11, 6) != 0.5,
          f"{macro['recall']} vs micro {round(10/11, 6)}")

    equiv = recall({"i1": "passed"},
                   rows([("i1", "m1", "failed"), ("i1", "e1", "passed"),
                         ("i1", "e2", "passed")]), {"i1": {"m1"}})
    check("equivalent mutants leave the denominator and are reported",
          equiv["per_item"]["i1"]["denominator"] == 1
          and equiv["excluded"]["equivalent"] == 2 and equiv["recall"] == 1.0,
          str(equiv["excluded"]))

    infra = recall({"i1": "passed"},
                   rows([("i1", "m1", "failed"), ("i1", "m2", "container_error")]),
                   {"i1": {"m1", "m2"}})
    check("an infrastructure outcome leaves the denominator and is counted",
          infra["per_item"]["i1"]["denominator"] == 1
          and infra["excluded"]["infrastructure"] == 1
          and infra["recall"] == 1.0, str(infra["excluded"]))

    unscorable = recall({"i1": "passed"},
                        rows([("i1", "m1", "failed"),
                              ("i1", "m2", "unscorable_substrate")]),
                        {"i1": {"m1", "m2"}})
    check("an unscorable-substrate pair is infrastructure: excluded, "
          "never a kill or a survival",
          classify_outcome("passed", "unscorable_substrate")
          == classify_outcome("timeout", "unscorable_substrate")
          == "infrastructure"
          and unscorable["per_item"]["i1"]["denominator"] == 1
          and unscorable["excluded"]["infrastructure"] == 1,
          str(unscorable["excluded"]))

    missing = recall({"i1": "passed"}, rows([("i1", "m1", "failed")]),
                     {"i1": {"m1", "m2"}})
    check("a missing result row is excluded and counted, never assumed",
          missing["per_item"]["i1"]["denominator"] == 1
          and missing["excluded"]["infrastructure"] == 1)

    to_kill = recall({"i1": "passed"}, rows([("i1", "m1", "timeout")]),
                     {"i1": {"m1"}})
    check("a mutant timeout is a kill when the baseline did not time out",
          to_kill["recall"] == 1.0
          and classify_outcome("passed", "timeout") == "kill")
    check("a mutant timeout is NOT a kill when the baseline timed out",
          classify_outcome("timeout", "timeout") == "infrastructure")
    to_ineligible = recall({"i1": "timeout"}, rows([("i1", "m1", "timeout")]),
                           {"i1": {"m1"}})
    check("an item whose baseline timed out scores nothing at all",
          to_ineligible["recall"] == 0.0
          and to_ineligible["ineligible"] == ["i1"])

    pop = recall({"i1": "passed", "i2": "passed"},
                 rows([("i1", "m1", "failed"), ("i2", "m9", "passed")]),
                 {"i1": {"m1"}, "i2": set()})
    check("items whose gold killed set is empty are not in the population",
          pop["n_population"] == 1 and "i2" not in pop["per_item"]
          and "i2" not in pop["ineligible"] and pop["n_items"] == 2
          and pop["recall"] == 1.0, str(pop))

    all_excluded = recall({"i1": "passed"},
                          rows([("i1", "m1", "container_error")]),
                          {"i1": {"m1"}})
    check("an item that loses its whole denominator is not averaged as 0",
          all_excluded["per_item"]["i1"]["recall"] is None
          and all_excluded["n_eligible"] == 0
          and all_excluded["recall"] == 0.0)

    only = recall({"i1": "passed"},
                  rows([("i1", "m1", "failed"), ("i1", "x9", "failed")]),
                  {"i1": {"m1"}})
    check("a kill gold cannot make is reported, not counted as equivalent",
          only["excluded"]["candidate_only_kill"] == 1
          and only["excluded"]["equivalent"] == 0 and only["recall"] == 1.0)

    check("two rows for one (item, mutant) pair are refused",
          raises(lambda: recall({"i1": "passed"},
                                rows([("i1", "m1", "failed"),
                                      ("i1", "m1", "passed")]),
                                {"i1": {"m1"}}), "REFUSED"))
    check("an unknown outcome label is refused, never bucketed by default",
          raises(lambda: recall({"i1": "passed"},
                                rows([("i1", "m1", "banana")]),
                                {"i1": {"m1"}}), "unknown mutant-run outcome"))
    check("a result row missing a field is refused",
          raises(lambda: recall({"i1": "passed"}, [{"item_id": "i1"}],
                                {"i1": {"m1"}}), "REFUSED"))

    _completeness_checks(check)

    # ----------------------- both archived v1 catalogues, end-to-end checked
    # The shared validator binds the exact producer bytes to the frozen asset
    # index, validates every mutant id and canonical ordering, then strips the
    # ids and rebuilds the COMPLETE document under its recorded v1 engine,
    # profile and policy.  This is deliberately unconditional: a source-only
    # clone whose LFS objects were not fetched must fail rather than silently
    # losing the only real-data regression witness.
    from . import mutation_attestation as _MA
    try:
        archived = _MA.validate_archived_v1_manifests()
    except (_MA.MutationAssetRefused, OSError, json.JSONDecodeError) as exc:
        check("both archived v1 mutant manifests are present and byte-verified",
              False, str(exc))
    else:
        check("both archived v1 mutant manifests are present and byte-verified",
              set(archived) == set(ARCHIVED_MANIFESTS), str(archived))
        for project, facts in sorted(archived.items()):
            check(f"{project}'s preserved SHA, canonical SHA, manifest digest, "
                  "count and v1 id rebuild all match the frozen authority",
                  facts["path"] == ARCHIVED_MANIFESTS[project]
                  and facts["n_ids_rebuilt"] == facts["n"], str(facts))

    # Harness 25, correction D: the reviewed list scoring removes from G_i.
    shipped = nondeterministic_mutants()
    check("[H25-D] the reviewed nondeterministic-mutant list is the two "
          "CoreShop random-draw mutants",
          shipped == {"96e02276fdb04ae5", "2ad72862f21752d7"}, str(shipped))
    with tempfile.TemporaryDirectory() as td:
        bad = _os.path.join(td, "list.yml")
        for text in ("mutants: [96e02276fdb04ae5]\n",
                     f"schema: {NONDETERMINISTIC_MUTANTS_SCHEMA}\n"
                     "mutants:\n  - project: coreshop\n",
                     "- not a mapping\n"):
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write(text)
            check(f"[H25-D] a malformed list refuses rather than scoring "
                  f"with nothing removed: {text.splitlines()[0]!r}",
                  raises(lambda: nondeterministic_mutants(bad), "REFUSED"))

    # Harness 25, correction P: an outline's pool from ALL its Examples rows.
    # One outline, two rows: row 1 runs line 10 of a.py, row 2 line 20.  A
    # harness-12 run kept row 1 only; the harness-18 run unions both.
    outline = "p/f.feature:3"
    pool_manifest = {"mutants": [
        {"id": "m_row1", "file": "a.py", "start_line": 10},
        {"id": "m_row1_b", "file": "a.py", "start_line": 10},
        {"id": "m_row2", "file": "a.py", "start_line": 20},
        {"id": "m_other", "file": "a.py", "start_line": 30},
        {"id": "m_plain", "file": "b.py", "start_line": 5}]}
    one_row = {outline: {"a.py": [10]}, "p/g.feature:2": {"b.py": [5]}}
    both_rows = {outline: {"a.py": [10, 20]}, "p/g.feature:2": {"b.py": [5]}}
    old_pool, _ = map_mutants_to_items(pool_manifest, one_row)
    old_pairs = {(item, mid) for mid, items in old_pool.items()
                 for item in items}
    added = pool_additions(pool_manifest, both_rows, old_pairs)
    check("[H25-P] the rebuild of a two-row outline adds exactly the "
          "mutants only its second row reaches, and nothing for a plain "
          "scenario",
          added == [(outline, "m_row2")], str(added))
    rebuilt, _ = map_mutants_to_items(pool_manifest, both_rows)
    check("[H25-P] ...and keeps every existing pair",
          old_pairs <= {(item, mid) for mid, items in rebuilt.items()
                        for item in items}
          and len(old_pairs) == 3, str(sorted(old_pairs)))
    check("[H25-P] a pool pair outside the rebuilt pools refuses",
          raises(lambda: pool_additions(pool_manifest, one_row,
                                        old_pairs | {(outline, "m_other")}),
                 "may only add"))
    check("[H25-P] a new pair's one observation becomes its pool outcome by "
          "the reference rule: failed killed, passed survived, a timeout or "
          "an infrastructure outcome excluded",
          [kit_gold_outcome(o) for o in ("failed", "passed", "timeout",
                                         "container_error")]
          == ["killed", "survived", "excluded", "excluded"])
    check("[H25-P] ...and an unknown label refuses",
          raises(lambda: kit_gold_outcome("mystery"), "unknown"))

    print("\n" + ("ALL PASS (mutation)" if ok else "FAILURES (mutation)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
