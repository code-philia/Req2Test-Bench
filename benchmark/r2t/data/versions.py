"""Read `VERSIONS.yml`, and make the parts of it a machine can check fail.

WHY THIS MODULE EXISTS.

`VERSIONS.yml` records the benchmark's live components and retired provenance
-- dataset, harness, egress gate, adapters, protocol -- so that two
numbers printed side by side can be told apart when something underneath them
moved.  A manifest is worth exactly as much as the cross-checks behind it: a
version file that nothing compares against becomes a comment within one
cycle, and a stale comment about which harness produced a published number is
worse than none, because a reader will believe it.

So the selftest here does the five comparisons that remain honestly
mechanisable, and refuses to pretend at what is not (see check 4):

  1. the harness version in the manifest EQUALS `validate.HARNESS_VERSION` --
     the code is the authority, the manifest is the claim, and the day
     somebody bumps the constant for a verdict-changing fix this check is
     what makes the un-updated manifest loud rather than silent;
  2. every pinned dataset digest is the sha256 of the file actually on disk,
     recomputed here -- the dataset is frozen BY CONTENT, so an edited line
     of `eval100.jsonl` must be a failure even though no version changed;
  3. the retired egress-gate record names the two gate versions applied to the
     published eval100 standard arm, a retained result record, and the reviewed
     Git authorities for its former code constants.  It is NOT compared with a
     live classifier;
  4. every `r2t/**/*.py` on disk appears in the ownership table.  That is
     COMPLETENESS, not correctness: a new module cannot be silently unowned,
     but nothing here can tell whether the change inside it should bump
     anything.  That judgment is human and stays human -- the table says so
     in its own header, and this module does not paper over it;
  5. the protocol files are the bytes the manifest pins, AND the document
     digests `r2t/bench/protocol_file.py` pins are the ones the manifest records.  Two
     checks rather than one because they answer different questions: the file
     digest catches an EDIT to an immutable recipe, and the document digest is
     what a run row actually cites -- a manifest that agreed with the bytes
     but not with the citation would be describing a different protocol from
     the one the numbers were produced under.

Most component declarations remain cross-checks for humans and selftests.
Population v2 adds one deliberately narrow runtime surface: artifact builders
and report readers resolve a stable ``population_id`` through this module.
Those lookups validate the complete registry before returning a defensive
copy; code constants and frozen artifact bytes remain the underlying
authorities.

The manifest retains `egress_gate` as historical provenance for the published
eval100 standard arm.  It is deliberately not compared with live code: the
approved network-control retirement retires that publication gate, and the
result record named as its authority is the surviving source for which
historical classifiers were applied.
"""
from __future__ import annotations

import copy
import hashlib
import os
from typing import Any, Optional
from ..core.paths import BENCHMARK_ROOT

#: The manifest, resolved from THIS file rather than the working directory --
#: the same reason `pricing.DEFAULT_TABLE_PATH` is absolute.  A selftest is
#: run from wherever a developer happens to be standing, and a relative path
#: would turn "the manifest disagrees with the code" into "no manifest here".
DEFAULT_MANIFEST_PATH = os.path.join(
    BENCHMARK_ROOT,
    "VERSIONS.yml")

#: The directory the dataset paths in the manifest are relative to: the
#: `benchmark/` root, i.e. the manifest's own directory.
BENCH_ROOT = os.path.dirname(DEFAULT_MANIFEST_PATH)

#: Components a manifest must describe.  Retired historical provenance remains
#: in the inventory because omission and retirement are different statements.
REQUIRED_COMPONENTS = ("dataset", "harness", "egress_gate", "adapters",
                       "protocol", "mutation_assets")

POPULATION_SCHEMA = "r2t.population/1"
POPULATION_FIELDS = frozenset({
    "schema", "project", "generation", "engine", "engine_version",
    "parser", "operators", "enumerator_rev", "asset_index",
    "asset_index_sha256", "asset_project", "catalogue", "scored",
    "boundary",
})
CATALOGUE_FIELDS = frozenset({
    "role", "n", "manifest_digest", "canonical_sha256",
    "preserved_file_sha256",
})
SCORED_FIELDS = frozenset({
    "role", "n", "manifest_digest", "canonical_sha256",
    "raw_manifest_digest", "n_non_production_excluded",
})
BOUNDARY_FIELDS = frozenset({"config", "classification", "sha256"})
HARD_SUBSET_REGISTRY_SCHEMA = "r2t.hard-subset-registry/1"
HARD_SUBSET_REGISTRY_FIELDS = frozenset({"schema", "pins"})
HARD_SUBSET_PIN_FIELDS = frozenset({"path", "sha256", "artifact_digest"})
ENVELOPE_EQUIVALENCE_SCHEMA = "r2t.population-envelope-equivalence/1"
ENVELOPE_EQUIVALENCE_FIELDS = frozenset({"schema", "rows"})
ENVELOPE_EQUIVALENCE_ROW_FIELDS = frozenset({
    "population_id", "ruling", "difference",
    "registered_scored_manifest_digest",
    "equivalent_scored_manifest_digest",
    "equivalent_scored_canonical_sha256",
    "registered_boundary_sha256", "equivalent_boundary_sha256",
    "shared_raw_manifest_digest", "asset_index", "asset_index_sha256",
})

#: (path, mtime) -> parsed manifest, for the same reason `pricing` caches its
#: table: several checks read it in one selftest run.
_CACHE: dict[tuple, dict] = {}


class ManifestError(ValueError):
    """A missing or malformed `VERSIONS.yml`.

    Raised before a population-bound artifact or table is built.  Runtime
    lookups read this file now, so every refusal must happen before candidate
    execution or report output rather than halfway through either.
    """


def _full_sha256(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(ch in "0123456789abcdef" for ch in value))


def _exact_fields(value, wanted: frozenset, label: str) -> None:
    if not isinstance(value, dict) or set(value) != wanted:
        got = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise ManifestError(
            f"{label} must contain exactly {sorted(wanted)}; got {got}")


def _validate_population_registry(doc: dict, source: str) -> dict:
    """Validate the stable population-id registry without reading artifacts.

    Artifact bytes are cross-checked in `selftest`; load-time validation owns
    shape and internal relationships so a runtime lookup cannot accept a
    half-described population merely because the selftest was not run.
    """
    registry = doc.get("populations")
    if not isinstance(registry, dict) or not registry:
        raise ManifestError(
            f"{source} has no `populations` mapping; a mutation score must "
            f"name the operator catalogue it was measured against")

    seen_generation = set()
    seen_scored = set()
    for population_id, entry in registry.items():
        label = f"population {population_id!r}"
        if not isinstance(population_id, str) or not population_id \
                or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" \
                       for ch in population_id):
            raise ManifestError(
                f"{source} has unsafe population id {population_id!r}; use "
                f"lower-case letters, digits and hyphens")
        _exact_fields(entry, POPULATION_FIELDS, label)
        if entry["schema"] != POPULATION_SCHEMA:
            raise ManifestError(
                f"{label} has schema {entry['schema']!r}, not "
                f"{POPULATION_SCHEMA!r}")
        for key in ("project", "engine", "engine_version", "parser",
                    "asset_index", "asset_project"):
            if not isinstance(entry[key], str) or not entry[key]:
                raise ManifestError(f"{label}.{key} must be a non-empty string")
        if os.path.isabs(entry["asset_index"]) \
                or ".." in entry["asset_index"].replace("\\", "/").split("/"):
            raise ManifestError(
                f"{label}.asset_index must be benchmark-relative and may not "
                f"escape the manifest directory")
        if not isinstance(entry["generation"], int) \
                or isinstance(entry["generation"], bool) \
                or entry["generation"] < 1:
            raise ManifestError(f"{label}.generation must be a positive integer")
        generation_key = (entry["project"], entry["generation"])
        if generation_key in seen_generation:
            raise ManifestError(
                f"{source} assigns project/generation {generation_key!r} to "
                f"more than one population id")
        seen_generation.add(generation_key)
        operators = entry["operators"]
        if not isinstance(operators, list) or not operators \
                or not all(isinstance(op, str) and op for op in operators) \
                or len(operators) != len(set(operators)):
            raise ManifestError(
                f"{label}.operators must be a non-empty ordered list of "
                f"unique names")
        if entry["enumerator_rev"] is not None \
                and (not isinstance(entry["enumerator_rev"], str)
                     or not entry["enumerator_rev"].strip()):
            raise ManifestError(
                f"{label}.enumerator_rev must be null for legacy evidence or "
                f"the non-empty revision string emitted by the enumerator")
        if not _full_sha256(entry["asset_index_sha256"]):
            raise ManifestError(f"{label}.asset_index_sha256 is not SHA-256")

        catalogue = entry["catalogue"]
        scored = entry["scored"]
        boundary = entry["boundary"]
        _exact_fields(catalogue, CATALOGUE_FIELDS, f"{label}.catalogue")
        _exact_fields(scored, SCORED_FIELDS, f"{label}.scored")
        _exact_fields(boundary, BOUNDARY_FIELDS, f"{label}.boundary")
        if catalogue["role"] != "pre_boundary_catalogue":
            raise ManifestError(
                f"{label}.catalogue.role must be pre_boundary_catalogue")
        if scored["role"] not in {"boundary_scored", "raw_equals_scored"}:
            raise ManifestError(f"{label}.scored.role is unsupported")
        for block_name, block, hash_fields in (
                ("catalogue", catalogue,
                 ("manifest_digest", "canonical_sha256",
                  "preserved_file_sha256")),
                ("scored", scored,
                 ("manifest_digest", "canonical_sha256",
                  "raw_manifest_digest"))):
            if not isinstance(block["n"], int) or isinstance(block["n"], bool) \
                    or block["n"] < 1:
                raise ManifestError(f"{label}.{block_name}.n must be positive")
            for key in hash_fields:
                if not _full_sha256(block[key]):
                    raise ManifestError(
                        f"{label}.{block_name}.{key} is not SHA-256")
        if scored["raw_manifest_digest"] != catalogue["manifest_digest"]:
            raise ManifestError(
                f"{label}.scored does not point back to its catalogue digest")
        excluded = scored["n_non_production_excluded"]
        if not isinstance(excluded, int) or isinstance(excluded, bool) \
                or excluded < 0 or scored["n"] + excluded != catalogue["n"]:
            raise ManifestError(
                f"{label}.scored count plus exclusions must equal catalogue n")
        if scored["role"] == "raw_equals_scored" and (
                excluded != 0 or scored["n"] != catalogue["n"]
                or scored["manifest_digest"] != catalogue["manifest_digest"]
                or scored["canonical_sha256"] != catalogue["canonical_sha256"]):
            raise ManifestError(
                f"{label} claims raw_equals_scored but its identities differ")
        if scored["role"] == "boundary_scored" and excluded < 1:
            raise ManifestError(
                f"{label} claims boundary_scored but excludes no mutant")
        scored_key = (entry["project"], scored["manifest_digest"])
        if scored_key in seen_scored:
            raise ManifestError(
                f"{source} assigns scored population {scored_key!r} twice")
        seen_scored.add(scored_key)
        if boundary["classification"] != "production" \
                or not isinstance(boundary["config"], str) \
                or not boundary["config"] \
                or not _full_sha256(boundary["sha256"]):
            raise ManifestError(f"{label}.boundary is malformed")
    return registry


def _validate_hard_subset_registry(doc: dict, source: str) -> dict:
    """Shape-check content/file pins for released hard-subset artifacts.

    C4 lands the registry empty; C5 adds one immutable pin only after its N=2
    sweeps exist.  Absence of a pin is therefore an explicit refusal at score
    time, never a fallback to the full-gold denominator.
    """
    registry = doc.get("hard_subset_artifacts")
    _exact_fields(registry, HARD_SUBSET_REGISTRY_FIELDS,
                  "hard_subset_artifacts")
    if registry["schema"] != HARD_SUBSET_REGISTRY_SCHEMA:
        raise ManifestError(
            f"hard_subset_artifacts has schema {registry['schema']!r}, not "
            f"{HARD_SUBSET_REGISTRY_SCHEMA!r}")
    pins = registry["pins"]
    if not isinstance(pins, dict):
        raise ManifestError("hard_subset_artifacts.pins must be a mapping")
    populations_ = doc.get("populations") or {}
    for population_id, pin in pins.items():
        if population_id not in populations_:
            raise ManifestError(
                f"hard-subset pin names unknown population {population_id!r}")
        _exact_fields(pin, HARD_SUBSET_PIN_FIELDS,
                      f"hard-subset pin {population_id!r}")
        path = pin["path"]
        if not isinstance(path, str) or not path or os.path.isabs(path) \
                or ".." in path.replace("\\", "/").split("/"):
            raise ManifestError(
                f"hard-subset pin {population_id!r}.path must be a safe "
                "benchmark-relative path")
        if not _full_sha256(pin["sha256"]) \
                or not _full_sha256(pin["artifact_digest"]):
            raise ManifestError(
                f"hard-subset pin {population_id!r} has malformed digest(s)")
    return pins


def _validate_envelope_equivalences(doc: dict, source: str) -> list:
    """Validate the envelope-equivalence ledger against the registry.

    A row here is a ruling of record, not a second population.  It binds one
    ADDITIONAL envelope -- the digests produced by re-deriving the same mutant
    catalogue under renamed boundary bytes -- to a population id that is
    already registered, and it must restate exactly the entry it extends, so
    the historical row is never edited and never ambiguous.  The registry
    itself cannot carry the second envelope any other way: a second entry for
    the same project is refused by the project/generation uniqueness rule
    above, which is the right refusal for a genuinely new population and the
    wrong one for a renamed envelope around the same one.

    The first row records the 2026-08-19 interactive owner ruling on
    disposition row LB7 ("register equivalence",
    `EVAL100_STD_WRAPPER_COMPLETION_SPEC.md` section 10): CoreShop's
    preserved eval100-std evidence is ONE population under both envelope
    digests, differing only by the portable `repo_root:` line of
    `boundary_coreshop.yml` (commit 53d5f9f).  The second records the
    2026-09-01 ruling extending the same treatment to python-docx, where the
    rename moved the asset index alone -- a population that excludes nothing
    folds no boundary bytes into its scored manifest.
    """
    ledger = doc.get("population_envelope_equivalences")
    _exact_fields(ledger, ENVELOPE_EQUIVALENCE_FIELDS,
                  "population_envelope_equivalences")
    if ledger["schema"] != ENVELOPE_EQUIVALENCE_SCHEMA:
        raise ManifestError(
            f"population_envelope_equivalences has schema "
            f"{ledger['schema']!r}, not {ENVELOPE_EQUIVALENCE_SCHEMA!r}")
    rows = ledger["rows"]
    if not isinstance(rows, list):
        raise ManifestError(
            "population_envelope_equivalences.rows must be a list")
    registry = doc.get("populations") or {}
    # project -> population id -> the digests that already resolve to it.  A
    # row may restate its OWN population's scored digest: a rename that
    # excludes nothing moves no scored manifest, which is the python-docx
    # case.  Binding a digest ANOTHER population of the project answers to is
    # the only way the ledger could make `population_id_for` return two
    # matches, and that stays refused.
    claimed: dict[str, dict[str, set]] = {}
    for pid, entry in registry.items():
        claimed.setdefault(entry["project"], {})[pid] = {
            entry["catalogue"]["manifest_digest"],
            entry["scored"]["manifest_digest"]}
    for position, row in enumerate(rows):
        label = f"envelope-equivalence row {position}"
        _exact_fields(row, ENVELOPE_EQUIVALENCE_ROW_FIELDS, label)
        population_id = row["population_id"]
        if population_id not in registry:
            raise ManifestError(
                f"{label} names unregistered population {population_id!r}; "
                f"an equivalence extends an existing entry, never invents one")
        entry = registry[population_id]
        label = f"envelope-equivalence row for {population_id!r}"
        for key in ("ruling", "difference"):
            if not isinstance(row[key], str) or not row[key].strip():
                raise ManifestError(
                    f"{label}.{key} must state the ruling of record in words")
        for key in ("registered_scored_manifest_digest",
                    "equivalent_scored_manifest_digest",
                    "equivalent_scored_canonical_sha256",
                    "registered_boundary_sha256",
                    "equivalent_boundary_sha256",
                    "shared_raw_manifest_digest",
                    "asset_index_sha256"):
            if not _full_sha256(row[key]):
                raise ManifestError(f"{label}.{key} is not SHA-256")
        if not isinstance(row["asset_index"], str) or not row["asset_index"] \
                or os.path.isabs(row["asset_index"]) \
                or ".." in row["asset_index"].replace("\\", "/").split("/"):
            raise ManifestError(
                f"{label}.asset_index must be benchmark-relative and may not "
                f"escape the manifest directory")
        if row["registered_scored_manifest_digest"] \
                != entry["scored"]["manifest_digest"] \
                or row["registered_boundary_sha256"] \
                != entry["boundary"]["sha256"] \
                or row["shared_raw_manifest_digest"] \
                != entry["catalogue"]["manifest_digest"]:
            raise ManifestError(
                f"{label} does not restate the registered identity it "
                f"extends; both fingerprints must be named exactly")
        if row["equivalent_boundary_sha256"] == entry["boundary"]["sha256"]:
            raise ManifestError(
                f"{label} renames nothing: the equivalent boundary bytes are "
                f"the registered ones, so there is no envelope to equate")
        equivalent = row["equivalent_scored_manifest_digest"]
        rivals = sorted(other for other, digests
                        in claimed[entry["project"]].items()
                        if other != population_id and equivalent in digests)
        if rivals:
            raise ManifestError(
                f"{label}.equivalent_scored_manifest_digest {equivalent!r} "
                f"already identifies registered {entry['project']!r} "
                f"population(s) {rivals}; the ledger may not make a lookup "
                f"ambiguous")
        claimed[entry["project"]][population_id].add(equivalent)
    return rows


def _validate_harness_compatibility(doc: dict, source: str) -> dict:
    """Shape-check `components.harness.compatible_reference_versions`.

    Absent means no project is listed, so every comparison stays exact.  Each
    list must name the current harness version: one written for an earlier
    version would otherwise keep admitting old references across a later bump
    nobody judged for that project.  `accepted_reference_appliers`, read by
    `reference_applier_accepted`, and `accepted_reference_seeds`, read by
    `reference_seed_accepted`, are shape-checked here too.
    """
    harness = doc["components"]["harness"]
    table = harness.get("compatible_reference_versions", {})
    if not isinstance(table, dict):
        raise ManifestError(
            f"{source}: components.harness.compatible_reference_versions must "
            f"map each project to a list of harness versions")
    current = harness.get("version")
    for project, listed in table.items():
        if not isinstance(project, str) or not project \
                or not isinstance(listed, list) \
                or not all(isinstance(v, int) and not isinstance(v, bool)
                           for v in listed) \
                or current not in listed:
            raise ManifestError(
                f"{source}: compatible_reference_versions[{project!r}] must "
                f"be a list of integer harness versions that includes the "
                f"current version {current!r}; got {listed!r}")
    appliers = harness.get("accepted_reference_appliers", {})

    def digest(value):
        return isinstance(value, str) and len(value) == 64 \
            and all(c in "0123456789abcdef" for c in value)
    if not isinstance(appliers, dict) or not all(
            isinstance(project, str) and project and isinstance(accepted, dict)
            and all(digest(recorded) and isinstance(later, list) and later
                    and all(digest(value) and value != recorded
                            for value in later)
                    for recorded, later in accepted.items())
            for project, accepted in appliers.items()):
        raise ManifestError(
            f"{source}: components.harness.accepted_reference_appliers must "
            f"map each project to {{recorded applier sha256: [later applier "
            f"sha256, ...]}}; got {appliers!r}")
    seeds = harness.get("accepted_reference_seeds", {})

    def seed_pair(value):
        return isinstance(value, dict) and set(value) == set(SEED_FIELDS) \
            and all(digest(value[key]) for key in SEED_FIELDS)
    if not isinstance(seeds, dict) or not all(
            isinstance(project, str) and project and isinstance(entries, list)
            and entries
            and all(isinstance(entry, dict)
                    and set(entry) == {"recorded", "accepted"}
                    and seed_pair(entry["recorded"])
                    and isinstance(entry["accepted"], list)
                    and entry["accepted"]
                    and all(seed_pair(value) and value != entry["recorded"]
                            for value in entry["accepted"])
                    for entry in entries)
            for project, entries in seeds.items()):
        raise ManifestError(
            f"{source}: components.harness.accepted_reference_seeds must map "
            f"each project to a list of {{recorded: {{{', '.join(SEED_FIELDS)}"
            f"}}, accepted: [later pair, ...]}}; got {seeds!r}")
    return table


def manifest(path: Optional[str] = None) -> dict:
    """Parse and shape-check `VERSIONS.yml`."""
    path = path or DEFAULT_MANIFEST_PATH
    try:
        key = (os.path.abspath(path), os.path.getmtime(path))
    except OSError as e:
        raise ManifestError(f"no version manifest at {path}: {e}") from e
    if key in _CACHE:
        return _CACHE[key]

    import yaml

    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    if not isinstance(doc, dict):
        raise ManifestError(f"{path} is not a mapping")
    comps = doc.get("components")
    if not isinstance(comps, dict):
        raise ManifestError(f"{path} has no `components` mapping")
    missing = [c for c in REQUIRED_COMPONENTS if c not in comps]
    if missing:
        raise ManifestError(
            f"{path} describes no {missing} component(s); a component that is "
            f"not ready yet is written with a null version, never omitted")
    own = doc.get("ownership")
    if not isinstance(own, dict) or not own:
        raise ManifestError(f"{path} has no `ownership` table")
    files = comps["dataset"].get("files")
    if not isinstance(files, dict) or not files:
        raise ManifestError(f"{path} pins no dataset files; the dataset is "
                            f"frozen by content, so an empty pin freezes "
                            f"nothing")
    _validate_population_registry(doc, path)
    _validate_envelope_equivalences(doc, path)
    _validate_hard_subset_registry(doc, path)
    _validate_harness_compatibility(doc, path)
    _CACHE[key] = doc
    return doc


def component(name: str, path: Optional[str] = None) -> Any:
    """The manifest's entry for one component, by name."""
    comps = manifest(path)["components"]
    if name not in comps:
        raise ManifestError(f"no component {name!r} in the manifest; known: "
                            f"{sorted(comps)}")
    return comps[name]


def reference_harness_compatible(project: Optional[str], recorded: object,
                                 scoring: object,
                                 path: Optional[str] = None) -> bool:
    """Whether a candidate at harness `scoring` may be compared with a
    reference of `project` recorded at harness `recorded`.

    Equal versions always may.  Otherwise only when both versions are on
    `compatible_reference_versions` for `project`: the list names the harness
    versions that give that project identical MUTATION outcomes (owner ruling
    2026-09-15; `EVALUATION_ONLY_NATIVE_BUNDLE_SPEC.md` section 4), so a
    saved score stays comparable after a later bump that keeps both listed.
    An unlisted project keeps exact equality.

    Mutation outcomes, not coverage numbers: the three callers of this are
    mutation-run comparisons, and a bump can leave those identical while
    moving a project's coverage (the harness-18 outline union does exactly
    that on a corpus with outlines).  Coverage is compared under exact
    equality and does not read this table.  See `VERSIONS.yml`, which records
    both readings of the lists.
    """
    if recorded == scoring:
        return True
    harness = component("harness", path)
    listed = harness.get("compatible_reference_versions", {}).get(project, ())
    return recorded in listed and scoring in listed


def reference_applier_accepted(project: Optional[str], recorded: object,
                               running: object,
                               path: Optional[str] = None) -> bool:
    """Whether a candidate campaign running applier bytes `running` may be
    compared with a reference of `project` whose observations ran `recorded`.

    Equal digests always may.  Otherwise only when `VERSIONS.yml`
    `accepted_reference_appliers` lists `running` under `recorded` for
    `project`: a reviewed entry, backed by evidence that both appliers write
    identical bytes for every mutant of that project's manifest.  Every other
    difference stays a refusal.
    """
    if recorded == running:
        return True
    accepted = component("harness", path).get(
        "accepted_reference_appliers", {}).get(project, {})
    return running in accepted.get(recorded, ())


#: The two seed facts a reference authority records and a candidate pool
#: must share with it: the workspace archive and the substrate baseline.
SEED_FIELDS = ("workspace_seed_digest", "substrate_baseline_sha256")


def reference_seed_accepted(project: Optional[str], recorded: dict,
                            running: dict, path: Optional[str] = None) -> bool:
    """Whether a candidate pool on seed `running` may be compared with a
    reference of `project` whose observations ran on seed `recorded`.

    Each side is read for `SEED_FIELDS` only, so a reference authority and a
    pool's facts or a summary can be passed whole.  Equal pairs always may.
    Otherwise only when `VERSIONS.yml` `accepted_reference_seeds` lists the
    running pair, whole, beside the recorded pair for `project`: a reviewed
    entry for a seed that differs from the recorded one only where its
    evidence says (CoreShop's seed v1.1, BENCHMARK_V2_SPEC.md section 8.5).
    Every other difference stays a refusal.
    """
    recorded = {key: recorded.get(key) for key in SEED_FIELDS}
    running = {key: running.get(key) for key in SEED_FIELDS}
    if recorded == running:
        return True
    entries = component("harness", path).get(
        "accepted_reference_seeds", {}).get(project, ())
    return any(entry["recorded"] == recorded and running in entry["accepted"]
               for entry in entries)


def ownership(path: Optional[str] = None) -> dict:
    """Module file name -> the component a change to it would bump.

    Documentation, and deliberately so: see the table's header in the
    manifest.  Exposed as a function only so the completeness check below and
    a human reading a diff look at the same bytes.
    """
    return dict(manifest(path)["ownership"])


def populations(path: Optional[str] = None) -> dict:
    """Stable population id -> an isolated copy of its validated entry."""
    return copy.deepcopy(manifest(path)["populations"])


def population(population_id: str, path: Optional[str] = None) -> dict:
    """One population entry, refusing an unregistered id."""
    registry = populations(path)
    if population_id not in registry:
        raise ManifestError(
            f"unknown population_id {population_id!r}; known: "
            f"{sorted(registry)}")
    return registry[population_id]


def envelope_equivalences(path: Optional[str] = None) -> list:
    """Ruled envelope-equivalence rows, as isolated copies."""
    return copy.deepcopy(
        manifest(path)["population_envelope_equivalences"]["rows"])


def equivalent_asset_indexes(population_id: str,
                             path: Optional[str] = None) -> tuple:
    """Asset-index digests a ruled equivalence binds to one population.

    Empty for a population no row extends, and for an id this manifest never
    registered -- an unknown id is refused where it is resolved, not here.
    The registered pin is deliberately absent: a caller already holds it from
    the entry, and an equivalence is symmetric, so admissibility is "the
    registered digest OR one of these", and a stamp matching neither still
    refuses.
    """
    return tuple(
        row["asset_index_sha256"]
        for row in manifest(path)["population_envelope_equivalences"]["rows"]
        if row["population_id"] == population_id)


def hard_subset_pins(path: Optional[str] = None) -> dict:
    """Population id -> isolated immutable hard-subset artifact pin."""
    return copy.deepcopy(manifest(path)["hard_subset_artifacts"]["pins"])


def hard_subset_pin(population_id: str,
                    path: Optional[str] = None) -> dict:
    """One released pin, refusing a population whose C5 artifact is absent."""
    # Resolve the population first so an unknown id is never misreported as a
    # merely pending artifact.
    population(population_id, path)
    pins = hard_subset_pins(path)
    if population_id not in pins:
        raise ManifestError(
            f"population {population_id!r} has no hard-subset artifact pin; "
            "C4 must not fall back to full-gold scoring. Complete the N=2 "
            "stripped sweep and register its path, file SHA-256 and canonical "
            "artifact digest in VERSIONS.yml.")
    return pins[population_id]


def population_id_for(project: str, manifest_digest: str, *,
                      engine: Optional[str] = None,
                      engine_version: Optional[str] = None,
                      path: Optional[str] = None) -> Optional[str]:
    """Resolve a real score to one population id.

    Unknown fixture projects return `None`.  A registered project whose
    digest or engine no longer matches refuses: silently dropping the id in
    exactly that case would let a changed population masquerade as legacy.
    Catalogue digests are accepted for artifact-building; test-quality
    summaries normally match the scored digest.

    A digest bound to an id by a ruled row of
    ``population_envelope_equivalences`` resolves to that same id: per the
    2026-08-19 LB7 owner ruling, CoreShop's preserved eval100-std evidence is
    one population under both its pre- and post-portability envelope digests,
    so the lookup returns exactly one identity rather than refusing on the
    renamed envelope.
    """
    registry = populations(path)
    project_entries = {
        pid: entry for pid, entry in registry.items()
        if entry["project"] == project
    }
    if not project_entries:
        return None
    aliases: dict[str, set] = {}
    for row in manifest(path)["population_envelope_equivalences"]["rows"]:
        aliases.setdefault(row["population_id"], set()).add(
            row["equivalent_scored_manifest_digest"])
    matches = []
    for pid, entry in project_entries.items():
        digests = {entry["catalogue"]["manifest_digest"],
                   entry["scored"]["manifest_digest"]}
        digests |= aliases.get(pid, set())
        if manifest_digest not in digests:
            continue
        if engine is not None and entry["engine"] != engine:
            continue
        if engine_version is not None \
                and entry["engine_version"] != engine_version:
            continue
        matches.append(pid)
    if len(matches) != 1:
        raise ManifestError(
            f"registered project {project!r} with manifest "
            f"{manifest_digest!r} and engine {(engine, engine_version)!r} "
            f"matches {matches}; refusing an absent or ambiguous "
            f"population_id")
    return matches[0]


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def selftest() -> int:
    """Cross-check the manifest against the code and the data it describes."""
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    doc = manifest()
    check("the manifest parses and describes every required component",
          all(c in doc["components"] for c in REQUIRED_COMPONENTS),
          str(sorted(doc["components"])))

    # (a) The code is the authority; the manifest is the claim.  When a
    # sibling branch bumps HARNESS_VERSION for a verdict-changing fix, this is
    # the check that makes the un-updated manifest impossible to miss.
    from ..bench import validate
    declared = component("harness").get("version")
    check("the manifest's harness version is the constant the code stamps",
          declared == validate.HARNESS_VERSION,
          f"VERSIONS.yml says {declared!r}, "
          f"validate.HARNESS_VERSION is {validate.HARNESS_VERSION!r}")
    check("...and it names where that authority lives",
          component("harness").get("authority")
          == "r2t/bench/validate.py:HARNESS_VERSION",
          str(component("harness").get("authority")))

    # (b) The dataset is frozen BY CONTENT: recompute, never trust the pin.
    for rel, pinned in sorted(component("dataset")["files"].items()):
        abs_path = os.path.join(BENCH_ROOT, rel)
        if not os.path.exists(abs_path):
            check(f"the pinned dataset file {rel} exists", False,
                  f"{abs_path} is missing; a pin on an absent file freezes "
                  f"nothing")
            continue
        actual = sha256_file(abs_path)
        check(f"{rel} still hashes to the digest the manifest pins",
              actual == pinned, f"pinned {pinned}, on disk {actual}")

    # (c) Current gate authority plus the untouched historical provenance.
    from .. import egress
    gate = component("egress_gate")
    applied = gate.get("published_eval100_standard") or {}
    check("the current egress-gate manifest pins the live gate-5 authority",
          gate.get("version") == egress.EGRESS_GATE_VERSION == 5
          and gate.get("status") == "current"
          and gate.get("retired") is False
          and gate.get("authority")
          == "r2t/egress.py:EGRESS_GATE_VERSION",
          str(gate))
    pinned_rules = gate.get("detection_rules_digest")
    live_rules = egress.detection_rules_digest(egress.DETECTION_RULES)
    check("the manifest pins the digest of the live detection-rule tables",
          pinned_rules == live_rules == egress.DETECTION_RULES_DIGEST,
          f"pinned {pinned_rules}, live {live_rules}")
    check("the historical egress-gate record preserves which classifiers "
          "were applied to the published eval100 standard arm",
          gate.get("historical_gate4_version") == 4
          and gate.get("historical_gate4_status")
          == "retired_historical_provenance"
          and applied.get("originally_cleared_under") == 1
          and applied.get("rechecked_under") == 4,
          str(gate))
    historical_commit = "98b5c9ed4fad4af010b5c0a42e866308904c4f5d"
    gate_authority = gate.get("historical_gate4_authority") or {}
    exemption_authority = gate.get("namespace_exemption_authority") or {}
    check("the retired code authorities name their exact reviewed Git "
          "commit, path, and constants instead of dangling live symbols",
          gate_authority == {
              "commit": historical_commit,
              "path": "benchmark/r2t/egress.py",
              "symbol": "EGRESS_GATE_VERSION",
          }
          and exemption_authority == {
              "commit": historical_commit,
              "path": "benchmark/r2t/egress.py",
              "symbol": "NAMESPACE_EXEMPTION_RULES",
          },
          f"gate={gate_authority}, exemption={exemption_authority}")
    publication_authority = applied.get("authority")
    table = applied.get("table")
    check("the published-arm authority and table resolve to retained records",
          isinstance(publication_authority, str)
          and os.path.isfile(os.path.join(BENCH_ROOT, publication_authority))
          and isinstance(table, str)
          and os.path.isfile(os.path.join(BENCH_ROOT, table)),
          f"authority={publication_authority!r}, table={table!r}")

    # (d) Completeness only.  A module nobody assigned is a module whose bump
    # nobody considered; that is the one thing a machine can notice here.
    from ..core.components import package_files
    own = ownership()
    on_disk = set(package_files())
    unowned = sorted(on_disk - set(own))
    check("every r2t module on disk is assigned an owning component",
          not unowned,
          f"unowned: {unowned} -- add them to the ownership table in "
          f"VERSIONS.yml (and decide, while you are there, what a change to "
          f"them would bump)")
    ghosts = sorted(set(own) - on_disk)
    check("the ownership table names no module that no longer exists",
          not ghosts, f"stale entries: {ghosts}")
    check("this module owns itself", own.get("data/versions.py") == "infrastructure",
          str(own.get("data/versions.py")))

    # The table is documentation, and must keep saying so where a reader of
    # the file will trip over it -- not only in a docstring nobody opens.
    with open(DEFAULT_MANIFEST_PATH, encoding="utf-8") as fh:
        text = fh.read()
    check("the ownership table still declares itself documentation, not a rule",
          "THIS TABLE IS DOCUMENTATION" in text
          and "a selftest cannot classify a semantic change" in text)

    # (e) The protocol artifact, checked THREE ways because it is pinned two
    # ways and neither alone is enough.
    #
    #   * the FILES are frozen by content (sha256 of the bytes on disk),
    #     because a protocol file is IMMUTABLE -- a changed knob is a new
    #     protocol_vN.yml, so a moved digest means somebody edited a recipe
    #     that archived rows already cite;
    #   * the DOCUMENT digests (`protocol.protocol_digest`) are what a row
    #     actually carries, and they are what `protocol.selftest` pins -- so
    #     the manifest and the code must agree about them, or a citation and a
    #     manifest would name different recipes;
    #   * and `version` must be a protocol that EXISTS, because "the current
    #     protocol" pointing at no file is worse than pointing at an old one.
    proto = component("protocol")
    check("the protocol component names a version that exists as a file",
          isinstance(proto.get("version"), int)
          and f"protocol/protocol_v{proto['version']}.yml"
          in (proto.get("files") or {}), str(proto))
    for rel, pinned in sorted((proto.get("files") or {}).items()):
        abs_path = os.path.join(BENCH_ROOT, rel)
        if not os.path.exists(abs_path):
            check(f"the pinned protocol file {rel} exists", False, abs_path)
            continue
        actual = sha256_file(abs_path)
        check(f"{rel} still hashes to the digest the manifest pins -- a "
              f"protocol file is IMMUTABLE",
              actual == pinned, f"pinned {pinned}, on disk {actual}")
    from ..bench import protocol_file as P
    PINNED_DIGESTS = P.PINNED_DIGESTS
    declared = {int(k): v for k, v in (proto.get("digests") or {}).items()}
    check("the manifest's protocol digests are the ones protocol_file.py pins",
          declared == PINNED_DIGESTS,
          f"VERSIONS.yml says {declared}, protocol_file.py pins "
          f"{P.PINNED_DIGESTS}")
    for version, pinned in sorted(declared.items()):
        try:
            got = P.protocol_digest(P.load(version))
        except P.ProtocolError as e:
            got = f"refused: {e}"
        check(f"...and protocol v{version} on disk really digests to {pinned}",
              got == pinned, f"manifest {pinned}, computed {got}")
    check("the manifest still says v1 is a RETROSPECTIVE encoding, which is "
          "the one thing a reader must not miss about it",
          "reconstructed" in (proto.get("note") or ""), str(proto.get("note")))

    # (f) What defines a mutant.  The v1 populations remain bound to their
    # HISTORICAL producer blobs; the live enumerators have since gained the M1
    # validity filter and v2 operator profile, and are pinned independently by
    # revision and current content.  Replacing the old SHA with the current one
    # would falsely claim new bytes produced old manifests, so the two
    # identities never share a field.
    assets = component("mutation_assets")
    asset_files = assets.get("files") or {}
    historical = assets.get("historical_engine_sources") or {}
    historical_files = historical.get("files") or {}
    current_enumerators = assets.get("current_enumerators") or {}
    check("the mutation-asset component is frozen by content and names the "
          "frozen index as its authority",
          assets.get("frozen_by_content") is True
          and assets.get("authority") == "release/slice1_mutation_assets.json"
          and bool(asset_files) and bool(historical_files)
          and bool(current_enumerators), str(assets))
    recomputed = {}
    for rel, pinned in sorted(asset_files.items()):
        if rel in historical_files:
            # Recomputed below from commit:path/blob, never from the live path.
            continue
        abs_path = os.path.join(BENCH_ROOT, rel)
        if not os.path.exists(abs_path):
            check(f"the pinned mutation asset {rel} exists", False, abs_path)
            continue
        actual = sha256_file(abs_path)
        recomputed[os.path.relpath(abs_path, os.path.dirname(BENCH_ROOT))] = \
            actual
        check(f"{rel} still hashes to the digest the manifest pins -- this "
              f"file decides which mutants exist",
              actual == pinned, f"pinned {pinned}, on disk {actual}")
    from . import mutation_attestation as MA
    declared = {
        os.path.relpath(os.path.join(BENCH_ROOT, rel),
                        os.path.dirname(BENCH_ROOT)): digest
        for rel, digest in asset_files.items()
    }
    # The v1 producers are blobs in HISTORY; a single-commit mirror of this
    # repository cannot resolve them, and says so rather than failing.
    import subprocess
    absent = sorted({
        b["commit"] for b in MA.legacy_engine_source_bindings().values()
        if subprocess.run(["git", "-C", os.path.dirname(BENCH_ROOT),
                           "cat-file", "-e", b["commit"] + "^{commit}"],
                          stdin=subprocess.DEVNULL,
                          capture_output=True).returncode != 0})
    if absent:
        print(f"  [SKIP] the v1 engine SHAs resolve from the recorded local "
              f"Git commit/blob: pinned commit(s) "
              f"{', '.join(c[:12] for c in absent)} are not in this "
              f"repository (a single-commit mirror)")
    else:
        try:
            indexed = MA.asset_pin_expectations()
            pin_facts = MA.validate_asset_pins()
        except MA.MutationAssetRefused as e:
            indexed = f"refused: {e}"
            pin_facts = indexed
        checked_files = (pin_facts.get("files")
                         if isinstance(pin_facts, dict) else pin_facts)
        check("the v1 engine SHAs resolve from the recorded local Git "
              "commit/blob, while boundaries resolve from live repository "
              "bytes",
              checked_files == declared,
              f"VERSIONS.yml {declared}, checked {checked_files}")
        check("...and those four pins are exactly the frozen index's pins",
              indexed == declared,
              f"VERSIONS.yml {declared}, frozen index {indexed}")

    # The current source identity is a different seam.  Its revision is
    # opt-in at enumeration time so legacy manifests retain their old bytes.
    current_actual = {}
    for rel, claim in sorted(current_enumerators.items()):
        abs_path = os.path.join(BENCH_ROOT, rel)
        if not isinstance(claim, dict) or set(claim) != {
                "enumerator_rev", "sha256"} or not os.path.isfile(abs_path):
            current_actual[rel] = "invalid current-enumerator claim"
            continue
        current_actual[rel] = sha256_file(abs_path)
    check("current enumerator sources rehash to their independent pins",
          current_actual == {rel: claim.get("sha256")
                             for rel, claim in current_enumerators.items()},
          str(current_actual))
    from ..py import mutate as PY_MUTATE
    from ..toolkit import mutation_java as JAVA_MUTATE
    from ..toolkit import mutation_go as GO_MUTATE
    from ..toolkit import mutation_rb as RUBY_MUTATE
    php_path = os.path.join(BENCH_ROOT, "r2t", "php", "mutate.php")
    try:
        import re
        with open(php_path, encoding="utf-8") as fh:
            match = re.search(
                r"const ENUMERATOR_REV = '([^']+)';", fh.read())
        php_rev = match.group(1) if match else None
    except OSError:
        php_rev = None
    actual_revs = {
        "r2t/go/mutate.go": GO_MUTATE.ENUMERATOR_REV,
        "r2t/java/Mutate.java": JAVA_MUTATE.ENUMERATOR_REV,
        "r2t/php/mutate.php": php_rev,
        "r2t/py/mutate.py": PY_MUTATE.ENUMERATOR_REV,
        "r2t/ruby/mutate.rb": RUBY_MUTATE.ENUMERATOR_REV,
    }
    check("current enumerator revision constants match their version pins",
          actual_revs == {rel: claim.get("enumerator_rev")
                          for rel, claim in current_enumerators.items()},
          str(actual_revs))

    # (g) A population is the named bridge from those source assets to one
    # scored manifest.  The registry deliberately repeats the frozen index's
    # facts; this loop is what turns the repetition into a cross-check rather
    # than a second source of truth.
    import copy
    import json
    registry = populations()
    required_v1 = {"coreshop-v1", "python-docx-v1"}
    check("the population registry retains both frozen v1 catalogue ids",
          required_v1 <= set(registry),
          str(sorted(registry)))
    check("the minted, natively validated algorand-sdk catalogue is "
          "registered beside them -- a project whose population exists is "
          "resolvable, not None",
          "algorand-sdk-v2" in registry, str(sorted(registry)))
    loaded_indexes = {}
    for population_id, entry in sorted(registry.items()):
        rel = entry["asset_index"]
        abs_path = os.path.join(BENCH_ROOT, rel)
        check(f"{population_id}'s frozen asset index exists",
              os.path.isfile(abs_path), abs_path)
        if not os.path.isfile(abs_path):
            continue
        actual_sha = sha256_file(abs_path)
        check(f"{population_id} pins the bytes of its asset index",
              actual_sha == entry["asset_index_sha256"],
              f"registry {entry['asset_index_sha256']}, disk {actual_sha}")
        if abs_path not in loaded_indexes:
            with open(abs_path, encoding="utf-8") as fh:
                loaded_indexes[abs_path] = json.load(fh)
            try:
                MA.validate_asset_index(loaded_indexes[abs_path])
            except MA.MutationAssetRefused as e:
                check(f"{rel} is a valid frozen mutation-asset index", False,
                      str(e))
        project_claim = (loaded_indexes[abs_path].get("projects") or {}).get(
            entry["asset_project"])
        check(f"{population_id} names a project present in its asset index",
              isinstance(project_claim, dict), str(entry["asset_project"]))
        if not isinstance(project_claim, dict):
            continue
        expected = {
            "engine": project_claim.get("engine"),
            "engine_version": project_claim.get("engine_version"),
            "parser": project_claim.get("parser"),
            "catalogue": project_claim.get("raw_population"),
            "scored": project_claim.get("scored_population"),
            "boundary": project_claim.get("boundary"),
        }
        actual = {key: entry[key] for key in expected}
        check(f"{population_id} is exactly the population its frozen index "
              "describes", actual == expected,
              f"registry {actual}, index {expected}")

    from . import mutation as M
    v1_ops = list(M.OPERATORS_V1)
    check("both v1 population ids carry the engine's ordered v1 profile",
          all(registry[key]["generation"] == 1
              and registry[key]["operators"] == v1_ops
              and registry[key]["enumerator_rev"] is None
              for key in required_v1),
          str({key: registry[key]["operators"] for key in required_v1}))
    # THE GENERATION INTEGER IS AN OPERATOR-CATALOGUE LABEL, NOT A PER-PROJECT
    # COUNTER.  `report.eligible_set_tables` compares this integer and nothing
    # else before pooling rows into one macro table, so the integer is a
    # catalogue comparison only while it resolves to ONE profile across every
    # registered project.  Previously that condition was asserted by naming
    # the single id allowed to be generation 2; a second engine makes the
    # whitelist unstatable, so state the condition itself.  A project's first
    # population is therefore not automatically generation 1: algorand-sdk
    # was enumerated straight into the eleven-family catalogue.
    profile_of_generation = {1: "v1", 2: "v2"}
    carried = {}
    for population_id, entry in sorted(registry.items()):
        try:
            profile = M.operator_profile_for(entry["operators"])
        except ValueError as e:
            profile = f"unresolved ({e})"
        carried[population_id] = (entry["generation"], profile)
    mislabelled = {key: value for key, value in carried.items()
                   if profile_of_generation.get(value[0]) != value[1]}
    check("every registered generation is the number of the operator profile "
          "its populations actually carry, which is what makes report's "
          "integer comparison a catalogue comparison",
          not mislabelled, str(carried))
    # `mutation.record_enumerator_revision`: every v2 population records the
    # pinned revision, and a v1 reconstruction "must not attach provenance it
    # never carried".  Engine-specific, because the revision a v2 population
    # must match is the one its own enumerator emits.
    engine_revs = {"r2t-mutate-go": GO_MUTATE.ENUMERATOR_REV,
                   "r2t-mutate": php_rev,
                   "r2t-mutate-py": PY_MUTATE.ENUMERATOR_REV,
                   "r2t-mutate-java": JAVA_MUTATE.ENUMERATOR_REV}
    # `.get()` returns None for an engine this map does not know, and a
    # later-generation entry may legally carry `enumerator_rev: null` only
    # while it is generation 1 -- so an UNKNOWN engine would compare
    # None != None, be silently excluded from `wrong_rev`, and pass.  That is
    # the exact shape the whitelist above was replaced to prevent: a fourth
    # engine arriving and slipping through the check meant to hold it.  Name
    # the engines this tree can produce a revision for, first.
    unknown_rev_engine = sorted(
        key for key, entry in registry.items()
        if entry["generation"] != 1 and entry["engine"] not in engine_revs)
    check("every later-generation population names an engine whose pinned "
          "enumerator revision this tree can actually produce, so a null "
          "revision under an unknown engine cannot match by accident",
          not unknown_rev_engine, str(unknown_rev_engine))
    wrong_rev = {
        key: entry["enumerator_rev"]
        for key, entry in sorted(registry.items())
        if entry["enumerator_rev"] != (None if entry["generation"] == 1
                                       else engine_revs.get(entry["engine"]))
    }
    check("v1 populations carry no enumerator provenance and every later "
          "generation carries its own engine's pinned revision",
          not wrong_rev, str(wrong_rev))
    check("algorand-sdk's registered population is the Java eleven-operator "
          "catalogue at generation 2 -- the number python-docx-v2 will take "
          "for the same profile, not the v1 number its project order suggests",
          carried.get("algorand-sdk-v2") == (2, "v2")
          and (registry.get("algorand-sdk-v2") or {}).get("engine")
          == "r2t-mutate-java", str(carried.get("algorand-sdk-v2")))
    # The six checks above verify the ENTRY's internal consistency.
    # This one verifies the behaviour the registration exists to
    # produce: `test_quality.registered_population_id` returning the id
    # instead of None for a real Algorand manifest.  That None is the
    # refusal which blocked hard-subset and D4 scoring, and it is
    # reachable only through `test_quality`, not through this module.
    from ..bench import test_quality as _TQ
    algorand = registry.get("algorand-sdk-v2") or {}
    check("a native algorand-sdk summary's frozen assets resolve "
          "through test_quality to algorand-sdk-v2 rather than to None",
          _TQ.registered_population_id(
              algorand.get("asset_project"),
              (algorand.get("scored") or {}).get("manifest_digest"),
              algorand.get("engine"),
              algorand.get("engine_version")) == "algorand-sdk-v2")
    docx_v2 = registry.get("python-docx-v2")
    check("python-docx-v2, when registered, still takes generation 2 under "
          "its own Python engine",
          docx_v2 is None or (docx_v2["project"] == "python-docx"
                              and docx_v2["generation"] == 2
                              and docx_v2["engine"] == "r2t-mutate-py"),
          str(docx_v2))
    pins = hard_subset_pins()
    check("hard-subset registry is explicit before and after C5 pins it",
          doc["hard_subset_artifacts"].get("schema")
          == HARD_SUBSET_REGISTRY_SCHEMA
          and doc["hard_subset_artifacts"].get("pins") == pins,
          str(doc.get("hard_subset_artifacts")))
    if "python-docx-v1" not in pins:
        try:
            hard_subset_pin("python-docx-v1")
            check("an unpinned hard subset refuses instead of using full gold",
                  False, "accepted")
        except ManifestError as e:
            check("an unpinned hard subset refuses instead of using full gold",
                  "must not fall back" in str(e), str(e))
    else:
        check("a C5 python-docx pin resolves through the checked registry",
              hard_subset_pin("python-docx-v1") == pins["python-docx-v1"])
    for population_id, entry in sorted(registry.items()):
        for role in ("catalogue", "scored"):
            resolved = population_id_for(
                entry["project"], entry[role]["manifest_digest"],
                engine=entry["engine"],
                engine_version=entry["engine_version"])
            check(f"{population_id} resolves from its {role} digest and "
                  "engine", resolved == population_id, str(resolved))
    check("an unregistered fixture project has no fabricated population id",
          population_id_for("fixture", "f" * 64) is None)
    try:
        population_id_for("coreshop", "f" * 64,
                          engine="r2t-mutate", engine_version="1.0")
        check("a changed digest on a registered project refuses", False,
              "accepted")
    except ManifestError as e:
        check("a changed digest on a registered project refuses",
              "population_id" in str(e) and "matches []" in str(e), str(e))

    # (h) The envelope-equivalence ledger: each ruled row must be the fact it
    # claims -- same population, renamed envelope -- against real bytes, and
    # the lookup must honour it.  These checks are the tripwire for the LB7
    # binding: neutering the alias consult in `population_id_for` reddens the
    # resolution check by name.
    ledger = doc["population_envelope_equivalences"]
    check("the envelope-equivalence ledger declares its schema",
          ledger.get("schema") == ENVELOPE_EQUIVALENCE_SCHEMA,
          str(ledger.get("schema")))
    for row in ledger["rows"]:
        population_id = row["population_id"]
        entry = registry[population_id]
        rel = row["asset_index"]
        abs_path = os.path.join(BENCH_ROOT, rel)
        check(f"{population_id}'s renamed-envelope asset index exists",
              os.path.isfile(abs_path), abs_path)
        if not os.path.isfile(abs_path):
            continue
        actual_sha = sha256_file(abs_path)
        check(f"{population_id}'s renamed-envelope asset index hashes to the "
              "ledger's pin", actual_sha == row["asset_index_sha256"],
              f"ledger {row['asset_index_sha256']}, disk {actual_sha}")
        with open(abs_path, encoding="utf-8") as fh:
            claim = (json.load(fh).get("projects") or {}).get(
                entry["asset_project"]) or {}
        scored_claim = claim.get("scored_population") or {}
        raw_claim = claim.get("raw_population") or {}
        boundary_claim = claim.get("boundary") or {}
        check(f"{population_id}'s ruled-equivalent envelope is exactly the "
              "identity its index states",
              scored_claim.get("manifest_digest")
              == row["equivalent_scored_manifest_digest"]
              and scored_claim.get("canonical_sha256")
              == row["equivalent_scored_canonical_sha256"]
              and boundary_claim.get("sha256")
              == row["equivalent_boundary_sha256"]
              and claim.get("engine") == entry["engine"]
              and claim.get("engine_version") == entry["engine_version"],
              str(scored_claim))
        check(f"{population_id}'s equivalence is an envelope RENAME, not a "
              "population change -- raw catalogue, scored count and "
              "exclusions are the registered ones",
              raw_claim.get("manifest_digest")
              == entry["catalogue"]["manifest_digest"]
              and scored_claim.get("raw_manifest_digest")
              == entry["catalogue"]["manifest_digest"]
              and scored_claim.get("n") == entry["scored"]["n"]
              and scored_claim.get("n_non_production_excluded")
              == entry["scored"]["n_non_production_excluded"],
              str(raw_claim))
        # REPO-ROOT-relative, and that is the LEGACY spelling, not the
        # current one.  The frozen Slice-1 index wrote `benchmark/config/...`
        # and coreshop-v1/python-docx-v1 restate it, but no producer in the
        # tree writes that form any more: `mutation_java.build_asset_index`
        # and `mutation_attestation.derive_boundary_scored_manifest` both
        # emit `os.path.basename`, and `validate_index_binding` compares
        # basename to basename.  So a freshly minted population carries the
        # BARE filename (algorand-sdk-v2 does), this join is the outlier, and
        # a future reader must not "fix" the bare form to match this line --
        # `:817` already pins each entry's whole boundary dict to its index.
        boundary_abs = os.path.join(os.path.dirname(BENCH_ROOT),
                                    entry["boundary"]["config"])
        boundary_actual = (sha256_file(boundary_abs)
                           if os.path.isfile(boundary_abs) else "absent")
        check(f"{population_id}'s renamed boundary envelope is the config in "
              "the tree today",
              boundary_actual == row["equivalent_boundary_sha256"],
              f"ledger {row['equivalent_boundary_sha256']}, "
              f"disk {boundary_actual}")
        try:
            resolved = population_id_for(
                entry["project"], row["equivalent_scored_manifest_digest"],
                engine=entry["engine"],
                engine_version=entry["engine_version"])
        except ManifestError as e:
            resolved = f"refused: {e}"
        check(f"{population_id} resolves from its ruled-equivalent scored "
              "digest and engine -- the register-equivalence binding this "
              "row rules on",
              resolved == population_id, str(resolved))
        check(f"{population_id}'s ruled asset index is the one a campaign "
              "under the renamed envelope stamps, and the registry still "
              "pins the index its historical evidence was collected under",
              row["asset_index_sha256"]
              in equivalent_asset_indexes(population_id)
              and row["asset_index_sha256"] != entry["asset_index_sha256"],
              f"ledger {row['asset_index_sha256']}, registry "
              f"{entry['asset_index_sha256']}")

    unregistered_row = copy.deepcopy(doc)
    unregistered_row["population_envelope_equivalences"]["rows"][0][
        "population_id"] = "never-registered-v1"
    try:
        _validate_envelope_equivalences(unregistered_row, "fixture.yml")
        check("an equivalence row cannot name an unregistered population",
              False, "accepted")
    except ManifestError as e:
        check("an equivalence row cannot name an unregistered population",
              "unregistered population" in str(e), str(e))
    misquoted = copy.deepcopy(doc)
    misquoted["population_envelope_equivalences"]["rows"][0][
        "registered_scored_manifest_digest"] = "f" * 64
    try:
        _validate_envelope_equivalences(misquoted, "fixture.yml")
        check("an equivalence row must restate exactly the registered "
              "identity it extends", False, "accepted")
    except ManifestError as e:
        check("an equivalence row must restate exactly the registered "
              "identity it extends", "restate" in str(e), str(e))
    renames_nothing = copy.deepcopy(doc)
    renames_nothing["population_envelope_equivalences"]["rows"][0][
        "equivalent_boundary_sha256"] = \
        doc["populations"]["coreshop-v1"]["boundary"]["sha256"]
    try:
        _validate_envelope_equivalences(renames_nothing, "fixture.yml")
        check("an equivalence whose envelope bytes are the registered ones "
              "refuses as vacuous", False, "accepted")
    except ManifestError as e:
        check("an equivalence whose envelope bytes are the registered ones "
              "refuses as vacuous", "renames nothing" in str(e), str(e))
    self_restating = copy.deepcopy(doc)
    self_restating["population_envelope_equivalences"]["rows"][0][
        "equivalent_scored_manifest_digest"] = \
        doc["populations"]["coreshop-v1"]["scored"]["manifest_digest"]
    try:
        _validate_envelope_equivalences(self_restating, "fixture.yml")
        admitted = True
    except ManifestError as e:
        admitted = f"refused: {e}"
    check("a rename that moves no scored manifest is still an equivalence -- "
          "the row restates its own population's digest, as python-docx's "
          "real row does", admitted is True, str(admitted))
    ambiguous = copy.deepcopy(doc)
    rival = copy.deepcopy(ambiguous["populations"]["coreshop-v1"])
    rival["generation"] = 2
    rival["scored"]["manifest_digest"] = "d" * 64
    ambiguous["populations"]["coreshop-v2"] = rival
    ambiguous["population_envelope_equivalences"]["rows"][0][
        "equivalent_scored_manifest_digest"] = "d" * 64
    try:
        _validate_envelope_equivalences(ambiguous, "fixture.yml")
        check("an equivalence may not bind a digest another population of "
              "the project already claims", False, "accepted")
    except ManifestError as e:
        check("an equivalence may not bind a digest another population of "
              "the project already claims",
              "ambiguous" in str(e) and "coreshop-v2" in str(e), str(e))

    isolated = populations()
    isolated["coreshop-v1"]["operators"].append("caller-mutation")
    check("a caller cannot mutate the cached population authority through a "
          "returned nested object",
          "caller-mutation" not in population("coreshop-v1")["operators"])

    future_revision = copy.deepcopy(doc)
    future_revision["populations"]["coreshop-v1"]["enumerator_rev"] = \
        "r2t-mutate/m3-operators-v2-1"
    try:
        _validate_population_registry(future_revision, "fixture.yml")
        revision_ok = True
    except ManifestError:
        revision_ok = False
    check("a future population accepts the enumerator's digest-covered "
          "revision identifier rather than requiring it to masquerade as a "
          "source SHA-256", revision_ok)
    blank_revision = copy.deepcopy(future_revision)
    blank_revision["populations"]["coreshop-v1"]["enumerator_rev"] = "  "
    try:
        _validate_population_registry(blank_revision, "fixture.yml")
        check("a blank enumerator revision still refuses", False, "accepted")
    except ManifestError as e:
        check("a blank enumerator revision still refuses",
              "non-empty revision string" in str(e), str(e))

    malformed = copy.deepcopy(doc)
    malformed["populations"]["coreshop-v1"]["surprise"] = True
    try:
        _validate_population_registry(malformed, "fixture.yml")
        check("an unversioned population field refuses at load time", False,
              "accepted")
    except ManifestError as e:
        check("an unversioned population field refuses at load time",
              "exactly" in str(e), str(e))
    duplicate = copy.deepcopy(doc)
    duplicate["populations"]["coreshop-copy"] = copy.deepcopy(
        duplicate["populations"]["coreshop-v1"])
    try:
        _validate_population_registry(duplicate, "fixture.yml")
        check("two ids cannot claim one project generation", False,
              "accepted")
    except ManifestError as e:
        check("two ids cannot claim one project generation",
              "more than one population id" in str(e), str(e))

    # Per-project reference harness compatibility (owner ruling 2026-09-15),
    # read from the live manifest so the ruled entries are what is exercised.
    compatible = reference_harness_compatible
    current = component("harness")["version"]
    check("python-docx and algorand-sdk references recorded at harness 12 "
          "may be scored by a candidate at the current harness",
          compatible("python-docx", 12, current)
          and compatible("algorand-sdk", 12, current))
    check("a coreshop reference recorded at harness 12 may not, one recorded "
          "at the current harness may",
          not compatible("coreshop", 12, current)
          and compatible("coreshop", current, current))
    check("an unlisted project keeps exact equality",
          not compatible("fixture-project", 12, current)
          and compatible("fixture-project", 12, 12))
    check("a harness version not on the project's list is refused",
          not compatible("python-docx", 12, current + 1)
          and not compatible("python-docx", 13, current))
    check("two listed versions stay comparable in either order, so a saved "
          "score can be re-checked after a later bump that keeps both",
          compatible("python-docx", current, 12))
    check("the Sylius harness-21 references may be scored at the current "
          "harness (EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md section 4)",
          compatible("sylius", 21, current))
    # Accepted reference appliers: the CoreShop #874 references ran
    # a2cff289's mutate.php; master's is accepted beside it, nothing else.
    sealed = "0da1838b156531c307d34e3eb77537e32e953e4d9b61f43f09291cc6e88a4e8c"
    later = "3c9321e13c4675c6e7591ecc6491054cfc0c1a9af934732d12bbdffe6879d215"
    accepted = reference_applier_accepted
    check("the CoreShop sealed applier accepts master's applier, for "
          "CoreShop only and in that direction only; equal bytes always pass",
          accepted("coreshop", sealed, later)
          and not accepted("sylius", sealed, later)
          and not accepted("coreshop", later, sealed)
          and not accepted("coreshop", sealed, "f" * 64)
          and accepted("fixture-project", "f" * 64, "f" * 64))
    for label, value in (
            ("a non-digest recorded applier", {"coreshop": {"0da1": [later]}}),
            ("an empty accepted list", {"coreshop": {sealed: []}}),
            ("an applier accepted beside itself", {"coreshop": {sealed: [sealed]}}),
            ("a list instead of a per-project mapping", [sealed])):
        broken = copy.deepcopy(doc)
        broken["components"]["harness"]["accepted_reference_appliers"] = value
        try:
            _validate_harness_compatibility(broken, "fixture.yml")
            check(f"{label} refuses at load time", False, "accepted")
        except ManifestError as e:
            check(f"{label} refuses at load time",
                  "accepted_reference_appliers" in str(e), str(e))
    # Accepted reference seeds: the CoreShop #874 references ran on seed v1;
    # seed v1.1 (BENCHMARK_V2_SPEC.md section 8.5) is accepted beside it as a
    # whole pair, for CoreShop only, and nothing else.
    seed_v1 = {
        "workspace_seed_digest":
            "48ae54d44ea912ae67446253bbcf22edd6fe7533fbc623d90d9cb08b6256028a",
        "substrate_baseline_sha256":
            "6aad2429988b9748d1a1c9df2a5f0d6662281af73fbe47935b06ad185f857d59"}
    seed_v1_1 = {
        "workspace_seed_digest":
            "9ea1bae0807dcd9a1626c6e9af9186510c505d0f67cd1265cadc79ab79454b62",
        "substrate_baseline_sha256":
            "ef3468e288b803c722fb4aa7fc1d62a61fdf0436ae7e529bc81934c4563f7ade"}
    seed_ok = reference_seed_accepted
    authority = {**seed_v1, "applier_sha256": sealed, "harness_version": 18}
    check("the CoreShop seed-v1 references accept seed v1.1's workspace and "
          "substrate, read off whole records, for CoreShop only and in that "
          "direction only; equal pairs always pass",
          seed_ok("coreshop", authority, {**seed_v1_1, "timeout_seconds": 600})
          and not seed_ok("sylius", authority, seed_v1_1)
          and not seed_ok("coreshop", seed_v1_1, seed_v1)
          and seed_ok("coreshop", authority, seed_v1)
          and seed_ok("fixture-project", seed_v1_1, dict(seed_v1_1)))
    check("one field of seed v1.1's pair alone, or any other seed, refuses",
          not seed_ok("coreshop", seed_v1, {
              **seed_v1, "workspace_seed_digest":
                  seed_v1_1["workspace_seed_digest"]})
          and not seed_ok("coreshop", seed_v1, {
              **seed_v1, "substrate_baseline_sha256":
                  seed_v1_1["substrate_baseline_sha256"]})
          and not seed_ok("coreshop", seed_v1, {
              **seed_v1_1, "workspace_seed_digest": "f" * 64})
          and not seed_ok("coreshop", seed_v1,
                          {"workspace_seed_digest":
                           seed_v1_1["workspace_seed_digest"]}))
    for label, value in (
            ("a non-digest seed field",
             {"coreshop": [{"recorded": seed_v1, "accepted": [
                 {**seed_v1_1, "workspace_seed_digest": "9ea1"}]}]}),
            ("a pair missing its substrate",
             {"coreshop": [{"recorded": seed_v1, "accepted": [
                 {"workspace_seed_digest":
                  seed_v1_1["workspace_seed_digest"]}]}]}),
            ("an empty accepted list",
             {"coreshop": [{"recorded": seed_v1, "accepted": []}]}),
            ("a seed accepted beside itself",
             {"coreshop": [{"recorded": seed_v1, "accepted": [seed_v1]}]}),
            ("an entry with an extra key",
             {"coreshop": [{"recorded": seed_v1, "accepted": [seed_v1_1],
                            "note": "x"}]}),
            ("a mapping instead of a per-project list",
             {"coreshop": {"recorded": seed_v1, "accepted": [seed_v1_1]}})):
        broken = copy.deepcopy(doc)
        broken["components"]["harness"]["accepted_reference_seeds"] = value
        try:
            _validate_harness_compatibility(broken, "fixture.yml")
            check(f"{label} refuses at load time", False, "accepted")
        except ManifestError as e:
            check(f"{label} refuses at load time",
                  "accepted_reference_seeds" in str(e), str(e))
    for label, value in (
            ("a list without the current version", {"python-docx": [12]}),
            ("a non-integer version", {"python-docx": ["12", current]}),
            ("a bare version instead of a list", {"python-docx": current}),
            ("a list instead of a per-project mapping", [12, current])):
        broken = copy.deepcopy(doc)
        broken["components"]["harness"]["compatible_reference_versions"] = \
            value
        try:
            _validate_harness_compatibility(broken, "fixture.yml")
            check(f"{label} refuses at load time", False, "accepted")
        except ManifestError as e:
            check(f"{label} refuses at load time",
                  "compatible_reference_versions" in str(e), str(e))
    import tempfile
    import yaml
    with tempfile.TemporaryDirectory() as tmp:
        stale = copy.deepcopy(doc)
        stale["components"]["harness"]["compatible_reference_versions"] = {
            "python-docx": [12]}
        stale_path = os.path.join(tmp, "VERSIONS.yml")
        with open(stale_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(stale, fh)
        try:
            compatible("python-docx", 12, current, path=stale_path)
            check("a malformed list in the file refuses the comparison "
                  "itself", False, "accepted")
        except ManifestError as e:
            check("a malformed list in the file refuses the comparison "
                  "itself", "includes the current version" in str(e), str(e))

    print("\n" + ("ALL PASS (versions)" if ok else "FAILURES (versions)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
