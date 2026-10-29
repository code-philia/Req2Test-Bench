"""Fail-closed identity checks for mutation assets.

This module validates joins; it does not score results. Historical evidence
is explicitly reported as legacy_consistency and is never upgraded by
inventing provenance absent from the original rows.  The materialisation
audit itself, the producer's scratch and reserved-output discipline and the
validation-report builders live in `toolkit/mutation_audit.py` (wave M5),
which imports this module; nothing here imports it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Iterable, Optional

from . import mutation as M
from ..core import reviewed_git
from ..core.paths import BENCHMARK_ROOT

MAP_SCHEMA = "r2t.mutant-map/1"
ASSET_INDEX_SCHEMA = "r2t.mutation-assets/1"
ASSET_PIN_SCHEMA = "r2t.mutation-asset-pins/1"
AUDIT_SCHEMA_V1 = "r2t.mutation-materialisation-audit/1"
AUDIT_SCHEMA = "r2t.mutation-materialisation-audit/2"
LEGACY_SCHEMA = "r2t.mutation-legacy-consistency/1"
DISPOSABLE_MARKER = ".r2t-disposable-mutation-audit"
#: Resolved from the installed package rather than the working directory,
#: for the same reason `versions.DEFAULT_MANIFEST_PATH` is: a gate is run
#: from wherever an operator happens to be standing, and a relative path
#: would turn "the pinned file moved" into "no such file here".
REPOSITORY_ROOT = os.path.dirname(BENCHMARK_ROOT)
ASSET_INDEX_PATH = os.path.join(BENCHMARK_ROOT, "release",
                                "slice1_mutation_assets.json")
LEGACY_CATALOGUE_PATH = os.path.join(
    BENCHMARK_ROOT, "release", "legacy_consistency", "index.json")
# Historical accident: 10,205 rows with the pre-boundary count still at
# 10,463.  It is evidence of an inconsistent object, never an asset identity.
FORBIDDEN_STALE_MANIFEST_DIGEST = (
    "fcc062c0a8bf725918b854277a1c1f3234b8e24e4d2180eec766ffdc1d1ff718")

ENUMERATOR_ENVELOPE_REQUIRED_FIELDS = frozenset({
    "engine", "engine_version", "parser", "files", "errors", "mutants",
})
ENUMERATOR_ENVELOPE_OPTIONAL_FIELDS = frozenset({
    "n_invalid", "enumerator_rev", "analysis_recipe", "go_build_contexts",
})
CURRENT_ENUMERATOR_PIN_FIELDS = frozenset({"enumerator_rev", "sha256"})

# Population-v2 is a closed, owner-approved reproduction target, not a set of
# values an evidence producer may fill from what it happened to observe.  Keep
# the literal profiles here as an independent acceptance boundary: comparing
# only with mutation.OPERATORS would let a later edit move both sides of the
# check together.
_POPULATION_V2_V1_OPERATORS = (
    "ConditionalBoundary", "NegateConditional", "Increment",
    "ArithmeticOperator", "TrueValue", "FalseValue", "ReturnValue",
    "MethodCallRemoval",
)
_POPULATION_V2_OPERATORS = _POPULATION_V2_V1_OPERATORS + (
    "LogicalConnector", "RemoveNegation", "ConstantReplacement",
)
_POPULATION_V2_TARGETS = {
    "coreshop": {
        "engine": "r2t-mutate",
        "enumerator": "r2t/php/mutate.php",
        "v1_n": 10463,
        "v2_n": 15886,
        "additions": {
            "LogicalConnector": 549,
            "RemoveNegation": 1224,
            "ConstantReplacement": 3650,
        },
    },
    "python-docx": {
        "engine": "r2t-mutate-py",
        "enumerator": "r2t/py/mutate.py",
        "v1_n": 2225,
        "v2_n": 2942,
        "additions": {
            "LogicalConnector": 54,
            "RemoveNegation": 37,
            "ConstantReplacement": 626,
        },
    },
}


class MutationAssetRefused(ValueError):
    """The supplied bytes do not establish one unambiguous population."""


class MaterialisationAuditRefused(MutationAssetRefused):
    """A failed full audit, carrying the durable evidence document."""

    def __init__(self, message: str, report: dict):
        super().__init__(message)
        self.report = report


def _refuse(message: str) -> None:
    raise MutationAssetRefused("REFUSED: " + message)


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def canonical_sha256(value) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_preserved_file(path: str, expected_sha256: str,
                            label: str = "preserved file") -> str:
    if not _is_sha256(expected_sha256):
        _refuse(f"{label} expected digest is not SHA-256")
    # A content digest does not make a pathname immutable.  In particular, a
    # symlink can be retargeted between validation and a later consumer while
    # preserving a formerly valid report.  Evidence named by an attestation
    # is therefore a regular file at the named path, never an indirection.
    if os.path.islink(path) or not os.path.isfile(path):
        _refuse(f"{label} must be a non-symlink regular file: {path}")
    actual = sha256_file(path)
    if actual != expected_sha256:
        _refuse(f"{label} SHA-256 is {actual}, expected {expected_sha256}")
    return actual


def _is_sha256(value) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _nonnegative_int(value, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _refuse(f"{label}={value!r} is not a non-negative integer")
    return value


def _positive_int(value, label: str) -> int:
    value = _nonnegative_int(value, label)
    if value == 0:
        _refuse(f"{label} must be positive")
    return value


def _exact_keys(value: dict, expected: set[str], label: str) -> None:
    if not isinstance(value, dict):
        _refuse(f"{label} is not an object")
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing or unknown:
        _refuse(f"{label} fields differ; missing={missing}, unknown={unknown}")


def _go_context_files(document):
    """Validate Go's recorded compiler contexts; other engines keep their shape."""
    if document.get("engine") != "r2t-mutate-go":
        if "go_build_contexts" in document:
            _refuse("a non-Go artifact carries Go build context authority")
        return None
    if "go_build_contexts" not in document:
        _refuse("Go artifact is missing go_build_contexts authority")
    from ..toolkit import mutation_go as GO
    try:
        contexts = GO.validate_build_contexts(document["go_build_contexts"])
    except (TypeError, ValueError, GO.GoMutationRefused) as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))
    return {path for context in contexts for path in context["production_files"]}


def validate_manifest(manifest: dict, *, expected_engine: Optional[str] = None,
                      raw_manifest: Optional[dict] = None) -> dict:
    """Validate count, digest, IDs, uniqueness, ordering and derivation."""
    if not isinstance(manifest, dict):
        _refuse("the mutant manifest is not a JSON object")
    required = ("engine", "engine_version", "parser", "operators",
                "exclusions", "sample", "seed", "n", "n_excluded",
                "mutants", "digest")
    missing = [key for key in required if key not in manifest]
    if missing:
        _refuse(f"the mutant manifest is missing {missing}")
    allowed_top = set(required) | {
        "population_role", "n_non_production_excluded",
        "n_mutation_excluded", "raw_manifest_digest", "boundary_policy",
        "n_invalid", "enumerator_rev", "analysis_recipe", "go_build_contexts"}
    unknown_top = sorted(set(manifest) - allowed_top)
    if unknown_top:
        _refuse(f"the mutant manifest has unknown fields {unknown_top}")
    if manifest.get("digest") == FORBIDDEN_STALE_MANIFEST_DIGEST:
        _refuse("manifest carries the known inconsistent pre-boundary-count "
                "digest; rebuild it from the preserved raw population")
    if expected_engine is not None and manifest["engine"] != expected_engine:
        _refuse(f"manifest engine={manifest['engine']!r}, expected "
                f"{expected_engine!r}")
    go_files = _go_context_files(manifest)
    java_recipe = None
    JAVA = None
    if manifest.get("engine") == "r2t-mutate-java":
        if "analysis_recipe" not in manifest:
            _refuse("Java manifest is missing its analysis recipe authority")
        try:
            from ..toolkit import mutation_java as JAVA
            java_recipe = JAVA.validate_analysis_recipe(
                manifest["analysis_recipe"])
        except (TypeError, ValueError) as exc:
            _refuse(str(exc).removeprefix("REFUSED: "))
    elif "analysis_recipe" in manifest:
        _refuse("a non-Java manifest carries Java analysis recipe authority")
    if not all(isinstance(manifest[k], str) and manifest[k]
               for k in ("engine", "engine_version", "parser")):
        _refuse("engine, engine_version and parser must be non-empty strings")
    operators = manifest["operators"]
    if not isinstance(operators, list) or not operators \
            or not all(isinstance(item, str) and item for item in operators) \
            or len(set(operators)) != len(operators):
        _refuse("operators must be non-empty unique strings")
    if not isinstance(manifest["exclusions"], list) \
            or not all(isinstance(x, str) for x in manifest["exclusions"]) \
            or len(set(manifest["exclusions"])) \
            != len(manifest["exclusions"]):
        _refuse("exclusions must be a list of unique strings")
    mutants = manifest["mutants"]
    if not isinstance(mutants, list):
        _refuse("manifest.mutants is not an array")
    _nonnegative_int(manifest["n"], "manifest.n")
    _nonnegative_int(manifest["n_excluded"], "manifest.n_excluded")
    if "n_invalid" in manifest:
        _nonnegative_int(manifest["n_invalid"], "manifest.n_invalid")
        if manifest["n_invalid"] == 0:
            _refuse("manifest.n_invalid must be omitted when zero")
    if "enumerator_rev" in manifest \
            and (not isinstance(manifest["enumerator_rev"], str)
                 or not manifest["enumerator_rev"].strip()):
        _refuse("manifest.enumerator_rev must be a non-empty string")
    if manifest["n"] != len(mutants):
        _refuse(f"manifest says n={manifest['n']} but carries "
                f"{len(mutants)} mutant records")
    sample = manifest["sample"]
    seed = manifest["seed"]
    if sample is None:
        if seed is not None:
            _refuse("manifest records a seed without a sample")
    elif not isinstance(sample, int) or isinstance(sample, bool) \
            or sample < 1 or seed is None or manifest["n"] != sample:
        _refuse("manifest sample/seed/count do not describe an exact "
                "reproducible sample")
    digest = M.manifest_digest(manifest)
    if manifest["digest"] != digest:
        _refuse(f"manifest digest is {manifest['digest']!r}, recomputed "
                f"{digest!r}")

    allowed = set(M.REQUIRED_FIELDS) | set(M.OPTIONAL_FIELDS) | {"id"}
    seen: set[str] = set()
    for index, mutant in enumerate(mutants):
        if not isinstance(mutant, dict):
            _refuse(f"mutant #{index} is not an object")
        unknown = sorted(set(mutant) - allowed)
        if unknown:
            _refuse(f"mutant #{index} has unknown fields {unknown}")
        if "id" not in mutant:
            _refuse(f"mutant #{index} has no id")
        try:
            record = M._validate(
                {k: v for k, v in mutant.items() if k != "id"},
                operators, index)
        except ValueError as exc:
            raise MutationAssetRefused(str(exc)) from None
        if go_files is not None and record["file"] not in go_files:
            _refuse(f"Go mutant #{index} file {record['file']!r} is outside its recorded compiler contexts")
        if java_recipe is not None \
                and not JAVA.analysis_path_covers(
                    java_recipe, record["file"]):
            _refuse(f"Java mutant #{index} file {record['file']!r} is outside "
                    "its authenticated sourcepath")
        if record["file"] != mutant["file"]:
            _refuse(f"mutant {mutant['id']!r} has a non-canonical path")
        if any(part in ("", ".", "..")
               for part in record["file"].split("/")):
            _refuse(f"mutant {mutant['id']!r} path is not a canonical "
                    "repository-relative file")
        try:
            wanted = M.mutant_id(
                record["file"], record["operator"], record["start_line"],
                record["start_col"], record["original"], record["mutated"],
                engine=manifest["engine"],
                engine_version=manifest["engine_version"])
        except ValueError as exc:
            raise MutationAssetRefused(str(exc)) from None
        if mutant["id"] != wanted:
            _refuse(f"mutant #{index} id={mutant['id']!r}, recomputed "
                    f"{wanted!r}")
        if wanted in seen:
            _refuse(f"duplicate mutant id {wanted}")
        seen.add(wanted)

    ordered = sorted(mutants, key=lambda item: (
        item["file"], item["start_line"], item["start_col"],
        item["operator"], item["id"]))
    if mutants != ordered:
        _refuse("mutants are not in canonical manifest order")

    role = manifest.get("population_role", "raw")
    if role not in ("raw", "boundary_scored"):
        _refuse(f"unknown population_role {role!r}")
    non_production = manifest.get("n_non_production_excluded", 0)
    _nonnegative_int(non_production, "manifest.n_non_production_excluded")
    # The sub-count of `n_non_production_excluded` attributable to the
    # boundary's `behat.mutation_exclude` row, written only when there is
    # one -- the encoding `n_invalid` already uses, so zero has exactly one
    # spelling and no manifest that never had the field changes shape.  It
    # is a SUB-count and not a second exclusion: the arithmetic every
    # consumer checks stays `raw.n == scored.n + n_non_production_excluded`.
    if "n_mutation_excluded" in manifest:
        if role != "boundary_scored":
            _refuse("only a boundary-scored manifest records "
                    "n_mutation_excluded")
        declared = _positive_int(manifest["n_mutation_excluded"],
                                 "manifest.n_mutation_excluded")
        if declared > non_production:
            _refuse("manifest.n_mutation_excluded exceeds the rows the "
                    "scored role excluded")
    if role == "raw":
        forbidden = sorted({"raw_manifest_digest", "boundary_policy"}
                           & set(manifest))
        if forbidden or non_production != 0:
            _refuse("raw manifest carries boundary-derivation fields")
    if role == "boundary_scored":
        for key in ("raw_manifest_digest", "boundary_policy",
                    "n_non_production_excluded"):
            if key not in manifest:
                _refuse(f"boundary-scored manifest is missing {key}")
        if not _is_sha256(manifest["raw_manifest_digest"]):
            _refuse("raw_manifest_digest is not a SHA-256 digest")
        policy = manifest["boundary_policy"]
        if not isinstance(policy, dict) or set(policy) != {
                "classification", "config", "sha256"}:
            _refuse("boundary_policy must contain classification, config, sha256")
        if policy["classification"] != "production" \
                or not isinstance(policy["config"], str) \
                or not _is_sha256(policy["sha256"]):
            _refuse("boundary_policy does not identify production-only bytes")
        if raw_manifest is not None:
            raw_facts = validate_manifest(raw_manifest)
            for key in ("n_invalid", "enumerator_rev", "go_build_contexts"):
                if manifest.get(key) != raw_manifest.get(key):
                    _refuse(f"scored manifest changes raw enumerator {key}")
            if manifest["raw_manifest_digest"] != raw_manifest["digest"]:
                _refuse("scored manifest names a different raw manifest")
            if manifest.get("sample") is None:
                reconciles = raw_facts["n"] == manifest["n"] + non_production
            else:
                reconciles = (raw_facts["n"] >= manifest["n"] + non_production
                              and manifest["n"] == manifest["sample"])
            if not reconciles:
                _refuse("raw/scored counts do not reconcile")
            raw_ids = {m["id"] for m in raw_manifest["mutants"]}
            if not seen <= raw_ids:
                _refuse("scored population has IDs absent from raw")

    facts = {
        "engine": manifest["engine"],
        "engine_version": manifest["engine_version"],
        "parser": manifest["parser"],
        "role": role,
        "n": manifest["n"],
        "n_excluded": manifest["n_excluded"],
        "n_non_production_excluded": non_production,
        "digest": digest,
        "canonical_sha256": canonical_sha256(manifest),
    }
    # Preserve the exact legacy facts shape stored in validation reports.
    # New metadata is returned only when the manifest actually carries it.
    #
    # `n_mutation_excluded` is here because `mutants validate` is where a
    # Sylius operator reads it: the build verb prints it, but a scored
    # population re-derived from a preserved raw catalogue never runs that
    # verb, and these facts are what `mutation_audit` writes into the
    # `r2t.mutation-validation/1` report (`raw_manifest`/`scored_manifest`).
    # Both sides of that report's re-derivation comparison come from THIS
    # function, so adding it moves no saved report whose manifest lacks it.
    for key in ("n_invalid", "enumerator_rev", "n_mutation_excluded"):
        if key in manifest:
            facts[key] = manifest[key]
    return facts


def _validate_population_v2_catalogue(
        project: str, *, archived_v1: dict, v1_replay: dict,
        v2_catalogue: dict, expected_enumerator_rev: str) -> dict:
    """Pure population-v2 join; injectable inputs are for selftests only."""
    target = _POPULATION_V2_TARGETS.get(project)
    if target is None:
        _refuse(f"population-v2 has no approved project {project!r}")
    if not isinstance(expected_enumerator_rev, str) \
            or not expected_enumerator_rev.strip():
        _refuse("expected population-v2 enumerator revision is invalid")
    if tuple(M.OPERATORS_V1) != _POPULATION_V2_V1_OPERATORS \
            or tuple(M.OPERATORS) != _POPULATION_V2_OPERATORS:
        _refuse("runtime mutation profiles differ from the approved ordered "
                "population-v2 profiles")

    archived_facts = validate_manifest(
        archived_v1, expected_engine=target["engine"])
    replay_facts = validate_manifest(
        v1_replay, expected_engine=target["engine"])
    v2_facts = validate_manifest(
        v2_catalogue, expected_engine=target["engine"])
    for label, facts in (("archived v1", archived_facts),
                         ("explicit v1 replay", replay_facts),
                         ("proposed v2 catalogue", v2_facts)):
        if facts["role"] != "raw":
            _refuse(f"{project} {label} is not a raw pre-boundary catalogue")

    if archived_v1["operators"] != list(_POPULATION_V2_V1_OPERATORS):
        _refuse(f"{project} archived v1 catalogue does not use the exact "
                "ordered eight-operator profile")
    if archived_v1["n"] != target["v1_n"]:
        _refuse(f"{project} archived raw v1 count={archived_v1['n']}, "
                f"expected {target['v1_n']}")
    if archived_v1.get("sample") is not None \
            or archived_v1.get("seed") is not None:
        _refuse(f"{project} archived v1 catalogue is sampled")
    if "n_invalid" in archived_v1 or "enumerator_rev" in archived_v1:
        _refuse(f"{project} archived v1 catalogue fabricates post-v1 "
                "enumerator metadata")

    # Equality is deliberately stronger than an id-set join.  Optional span,
    # class and method metadata is not hashed into mutant ids, but it remains
    # part of the reusable v1 row and must survive a current-producer replay.
    if v1_replay != archived_v1:
        _refuse(f"{project} explicit v1 replay differs from the archived raw "
                "v1 catalogue")

    if v2_catalogue["operators"] != list(_POPULATION_V2_OPERATORS):
        _refuse(f"{project} v2 catalogue does not use the exact ordered "
                "eleven-operator profile")
    if v2_catalogue.get("sample") is not None \
            or v2_catalogue.get("seed") is not None:
        _refuse(f"{project} v2 catalogue must be complete, not sampled")
    if "n_invalid" in v2_catalogue:
        _refuse(f"{project} v2 catalogue did not reproduce zero invalid "
                "candidates with the omit-when-zero encoding")
    if v2_catalogue.get("enumerator_rev") != expected_enumerator_rev:
        _refuse(f"{project} v2 enumerator_rev="
                f"{v2_catalogue.get('enumerator_rev')!r}, expected current "
                f"{expected_enumerator_rev!r}")
    if v2_catalogue["n"] != target["v2_n"]:
        _refuse(f"{project} v2 catalogue count={v2_catalogue['n']}, "
                f"expected {target['v2_n']}")

    changed_identity = [
        key for key in ("engine", "engine_version", "parser", "exclusions",
                        "n_excluded")
        if v2_catalogue.get(key) != archived_v1.get(key)
    ]
    changed_scope = [
        key for key in ("population_role", "n_non_production_excluded")
        if (key in v2_catalogue) != (key in archived_v1)
        or v2_catalogue.get(key) != archived_v1.get(key)
    ]
    if changed_identity or changed_scope:
        _refuse(f"{project} v2 catalogue changes inherited identity/scope "
                f"facts {changed_identity + changed_scope}")

    v1_names = set(_POPULATION_V2_V1_OPERATORS)
    inherited = [row for row in v2_catalogue["mutants"]
                 if row["operator"] in v1_names]
    if inherited != archived_v1["mutants"]:
        _refuse(f"{project} v2 inherited-v1 projection differs from the "
                "archived descriptors, optional metadata, or ids")
    if len(inherited) != target["v1_n"]:
        _refuse(f"{project} v2 inherited-v1 count={len(inherited)}, "
                f"expected {target['v1_n']}")

    additions = {name: 0 for name in target["additions"]}
    for row in v2_catalogue["mutants"]:
        if row["operator"] in additions:
            additions[row["operator"]] += 1
    if additions != target["additions"]:
        _refuse(f"{project} v2 addition counts={additions!r}, expected "
                f"{target['additions']!r}")
    if target["v1_n"] + sum(additions.values()) != target["v2_n"]:
        _refuse(f"{project} approved population-v2 target arithmetic is "
                "inconsistent")

    return {
        "project": project,
        "v1_n": archived_facts["n"],
        "v2_n": v2_facts["n"],
        "inherited_v1_n": len(inherited),
        "addition_counts": additions,
        "v1_manifest_digest": archived_facts["digest"],
        "v1_replay_manifest_digest": replay_facts["digest"],
        "v1_rows_sha256": canonical_sha256(archived_v1["mutants"]),
        "inherited_v1_rows_sha256": canonical_sha256(inherited),
        "v2_manifest_digest": v2_facts["digest"],
        "v2_rows_sha256": canonical_sha256(v2_catalogue["mutants"]),
        "enumerator_rev": expected_enumerator_rev,
    }


def validate_population_v2_catalogue(
        project: str, *, v1_replay: dict, v2_catalogue: dict) -> dict:
    """Authenticate and join one future full population-v2 catalogue.

    This verifier returns facts only.  It neither writes nor registers an
    artifact, and a green synthetic selftest is never canonical evidence.
    Production callers cannot inject a friendly archive, target, or revision:
    those are resolved through the existing repository authorities here.
    """
    target = _POPULATION_V2_TARGETS.get(project)
    if target is None:
        _refuse(f"population-v2 has no approved project {project!r}")
    verified = validate_archived_v1_manifests()
    if project not in verified:
        _refuse(f"archived v1 authority has no project {project!r}")
    try:
        archived_path = M.ARCHIVED_MANIFESTS[project]
    except KeyError:
        _refuse(f"archived v1 paths have no project {project!r}")
    archived_v1 = _read_json_object(
        archived_path, f"{project} authenticated archived v1 catalogue")
    consumed = validate_manifest(
        archived_v1, expected_engine=target["engine"])
    expected = verified[project]
    changed = [
        label for label, actual, wanted in (
            ("canonical_sha256", consumed["canonical_sha256"],
             expected["canonical_sha256"]),
            ("manifest_digest", consumed["digest"],
             expected["manifest_digest"]),
            ("n", consumed["n"], expected["n"]),
        ) if actual != wanted
    ]
    if changed:
        _refuse(f"{project} archived v1 catalogue changed between "
                f"authentication and consumption in {changed}")
    enumerator = pinned_enumerator_identity(target["enumerator"])
    return _validate_population_v2_catalogue(
        project, archived_v1=archived_v1, v1_replay=v1_replay,
        v2_catalogue=v2_catalogue,
        expected_enumerator_rev=enumerator["enumerator_rev"])


def _declared_non_product(boundary):
    """The boundary's own `behat.mutation_exclude` row, and its roots.

    Read from the BOUNDARY rather than passed in, because every consumer of
    the raw->scored distinction re-derives the scored manifest from the raw
    one plus the boundary bytes and compares the result
    (`validate_index_binding`, `validate_campaign_asset_inputs`,
    `mutants validate`, the materialisation audit, `test_quality`).  A
    population policy an operator could supply beside the boundary would be
    a policy those re-derivations could not reproduce.

    A boundary with no `behat:` block -- CoreShop's, python-docx's, every
    Java one -- yields the empty row, and the caller then does not consult
    it at all.
    """
    from ..bench.repo import behat_project
    row = behat_project(boundary)
    return tuple(row.mutation_exclude), tuple(row.prod_paths)


def derive_boundary_scored_manifest(raw_manifest: dict, boundary,
                                    boundary_config: str,
                                    boundary_sha256: str, *,
                                    sample: Optional[int] = None,
                                    seed=None) -> dict:
    """Derive a scored population without overwriting raw identity.

    Two things leave the scored role, and the raw catalogue keeps both.
    The boundary CLASSIFIES a mutant's file as something other than
    production -- the Behat glue and the harness scaffolding retained
    beside it.  Or the project has DECLARED that subtree non-product in its
    `behat.mutation_exclude` row: tests, specs, migrations, DI
    configuration and fixtures that sit inside the production roots and
    that the classifier, which answers a question about the glue, cannot
    separate (owner ruling, 2026-09-11).

    Both are the same statement -- this row is not product code -- so both
    are counted in `n_non_production_excluded`, which keeps
    `raw.n == scored.n + n_non_production_excluded` true everywhere it is
    already checked.  `n_mutation_excluded` is the SUB-COUNT of that total
    attributable to the declared fragments, written only when there is one;
    the fragments themselves join `exclusions`, which the manifest digest
    covers, and the boundary bytes that define them are named by
    `boundary_policy.sha256`.
    """
    validate_manifest(raw_manifest)
    if not _is_sha256(boundary_sha256):
        _refuse("boundary_sha256 is not a SHA-256 digest")
    fragments, prod_paths = _declared_non_product(boundary)
    kept = []
    n_declared = 0
    for mutant in raw_manifest["mutants"]:
        rel = M.normalise_path(mutant["file"])
        if boundary.classify(rel) != "production":
            continue
        if fragments and M.is_population_excluded(rel, fragments, prod_paths):
            n_declared += 1
            continue
        kept.append(mutant)
    # Every row the scored role ADMITS, before any sample: what the
    # boundary classified production and the project did not declare
    # otherwise.  `raw.n` minus this is the whole of what left.
    n_admitted = len(kept)
    if sample is not None:
        if seed is None or not isinstance(sample, int) \
                or isinstance(sample, bool) or sample < 1:
            _refuse("a boundary-scored sample needs a positive count and seed")
        if sample > len(kept):
            _refuse("boundary-scored sample exceeds the production population")
        kept = M._select_sample(kept, sample, seed)
    scored = json.loads(json.dumps(raw_manifest))
    scored["mutants"] = kept
    scored["n"] = len(kept)
    label = f"non-production by {os.path.basename(boundary_config)}"
    scored["exclusions"] = list(scored.get("exclusions") or ())
    if label not in scored["exclusions"]:
        scored["exclusions"].append(label)
    if fragments:
        # Written whenever the row EXISTS, not only when it matched: a
        # population scored under a policy that names these fragments is
        # not the same population as one scored under no such policy, and
        # the digest covers `exclusions`, so it says which was in force.
        declared = (f"declared non-product under the production roots by "
                    f"{os.path.basename(boundary_config)}: "
                    + ", ".join(fragments))
        if declared not in scored["exclusions"]:
            scored["exclusions"].append(declared)
    scored["sample"] = sample
    scored["seed"] = seed
    scored["n_non_production_excluded"] = raw_manifest["n"] - n_admitted
    if n_declared:
        scored["n_mutation_excluded"] = n_declared
    scored["population_role"] = "boundary_scored"
    scored["raw_manifest_digest"] = raw_manifest["digest"]
    scored["boundary_policy"] = {
        "classification": "production",
        "config": os.path.basename(boundary_config),
        "sha256": boundary_sha256,
    }
    scored["digest"] = M.manifest_digest(scored)
    validate_manifest(scored, raw_manifest=raw_manifest)
    return scored


def derive_raw_equals_scored_manifest(raw_manifest: dict, boundary,
                                      boundary_config: str,
                                      boundary_sha256: str) -> dict:
    """Prove that applying the production boundary excludes zero mutants.

    Some preserved Python manifests were constructed after boundary filtering.
    Their bytes therefore remain both the raw and scored identity, but equality
    is accepted only after classifying every frozen row against the supplied
    boundary.  This is an explicit zero-exclusion derivation, not a shortcut
    based on equal counts.
    """
    validate_manifest(raw_manifest)
    if not _is_sha256(boundary_sha256):
        _refuse("boundary_sha256 is not a SHA-256 digest")
    non_production = [
        mutant["id"] for mutant in raw_manifest["mutants"]
        if boundary.classify(M.normalise_path(mutant["file"])) != "production"
    ]
    if non_production:
        _refuse("raw-equals-scored derivation excluded non-production mutants "
                f"under {os.path.basename(boundary_config)}: "
                f"{non_production[:3]}")
    # The other half of the same statement.  Without it one boundary would
    # define two different populations depending on which derivation names
    # it, and the equality this function certifies would be false for the
    # rows its own `behat.mutation_exclude` row declares non-product.
    fragments, prod_paths = _declared_non_product(boundary)
    declared = [
        mutant["id"] for mutant in raw_manifest["mutants"]
        if fragments and M.is_population_excluded(
            M.normalise_path(mutant["file"]), fragments, prod_paths)
    ]
    if declared:
        _refuse("raw-equals-scored derivation excluded mutants the "
                f"{os.path.basename(boundary_config)} `mutation_exclude` row "
                f"declares non-product: {declared[:3]}")
    # A deep copy makes callers compare the complete derived object while
    # preserving the historical manifest's exact content address.
    return json.loads(json.dumps(raw_manifest))


def map_digest(mapping: dict) -> str:
    return canonical_sha256({k: v for k, v in mapping.items()
                             if k != "digest"})


def audit_digest(report: dict) -> str:
    return canonical_sha256({k: v for k, v in report.items()
                             if k != "digest"})


def build_map_artifact(manifest: dict, by_mutant: dict, uncovered: list,
                       *, coverage_sha256: str, release_sha256: str) -> dict:
    validate_manifest(manifest)
    mapping = {
        "schema": MAP_SCHEMA,
        "manifest_digest": manifest["digest"],
        "coverage_sha256": coverage_sha256,
        "release_sha256": release_sha256,
        "n_mutants": manifest["n"],
        "n_mapped": len(by_mutant),
        "n_uncovered": len(uncovered),
        "n_pairs": sum(len(items) for items in by_mutant.values()),
        "by_mutant": {key: sorted(value)
                      for key, value in sorted(by_mutant.items())},
        "uncovered": sorted(uncovered),
    }
    mapping["digest"] = map_digest(mapping)
    return mapping


def validate_map(mapping: dict, manifest: dict, *,
                 release_ids: Optional[set[str]] = None,
                 paid_view_subset: bool = False,
                 coverage_by_item: Optional[dict] = None,
                 allow_legacy: bool = False) -> dict:
    """Validate one mutant map, optionally against a release.

    `paid_view_subset` says the release handed in is a PAID VIEW of the
    population the map was built over, rather than that population itself.
    It is off by default and the default path is byte-unchanged.

    WHY THE DIRECTION IS ASYMMETRIC.  The two containments answer different
    questions and only one of them is load-bearing:

    * `release_ids <= covered items` -- every item that will be SCORED has
      map coverage.  Without it a scheduled pair could name an item no
      mutant covers, and the denominator would be a fiction.  This is
      enforced in BOTH modes.
    * `mapped items <= release_ids` -- the map names nothing outside the
      release.  This was a fact about the complete-admitted-census era, when
      every released item was paid, and it was written as a rule.  Under C5
      the paid view is a step-definition census -- algorand is 111 of 117 --
      so the map legitimately names 6 items the paid view does not, and the
      frozen pair set already excludes their associations.  Demanding it
      here made the Slice-3 seam unsatisfiable: `launch_mutation_job`
      requires `--release` to EQUAL the frozen 111-row view, and this
      required it to cover all 117, on the same single argument.

    So the subset mode drops that second containment and nothing else.
    """
    validate_manifest(manifest)
    if not isinstance(mapping, dict):
        _refuse("the mutant map is not a JSON object")
    if not isinstance(mapping.get("by_mutant"), dict) \
            or not isinstance(mapping.get("uncovered"), list):
        _refuse("the mutant map needs by_mutant and uncovered")
    legacy = mapping.get("schema") is None
    if legacy and not allow_legacy:
        _refuse("map lacks identity envelope; use legacy_consistency")
    if not legacy and mapping.get("schema") != MAP_SCHEMA:
        _refuse(f"unknown mutant map schema {mapping.get('schema')!r}")
    if legacy:
        _exact_keys(mapping, {"by_mutant", "uncovered"}, "legacy mutant map")
    else:
        _exact_keys(mapping, {
            "schema", "manifest_digest", "coverage_sha256",
            "release_sha256", "n_mutants", "n_mapped", "n_uncovered",
            "n_pairs", "by_mutant", "uncovered", "digest"},
            "mutant map")

    by_mutant = mapping["by_mutant"]
    mapped_ids: set[str] = set()
    covered_items: set[str] = set()
    pair_count = 0
    for mutant_id, items in by_mutant.items():
        if not isinstance(mutant_id, str) or not isinstance(items, list) \
                or not items:
            _refuse(f"map entry {mutant_id!r} is not a non-empty item list")
        if not all(isinstance(item, str) and item for item in items):
            _refuse(f"map entry {mutant_id!r} has a non-string item ID")
        if items != sorted(set(items)):
            _refuse(f"map entry {mutant_id!r} is not sorted and unique")
        if release_ids is not None and not paid_view_subset \
                and not set(items) <= release_ids:
            bad = sorted(set(items) - release_ids)
            _refuse(f"map entry {mutant_id!r} names unknown release IDs "
                    f"{bad[:3]}")
        mapped_ids.add(mutant_id)
        covered_items.update(items)
        pair_count += len(items)
    if release_ids is not None and paid_view_subset:
        # The load-bearing direction, and the only containment a paid view
        # owes: everything that will be SCORED is covered by some mutant.
        orphans = sorted(release_ids - covered_items)
        if orphans:
            _refuse(f"paid view names release ID(s) with no map coverage "
                    f"{orphans[:3]}")
    uncovered = mapping["uncovered"]
    if not all(isinstance(item, str) and item for item in uncovered) \
            or uncovered != sorted(set(uncovered)):
        _refuse("uncovered IDs are not sorted and unique")
    uncovered_ids = set(uncovered)
    if mapped_ids & uncovered_ids:
        _refuse("mapped and uncovered mutant ID sets overlap")
    manifest_ids = {m["id"] for m in manifest["mutants"]}
    combined = mapped_ids | uncovered_ids
    if combined != manifest_ids:
        _refuse(f"map is not an exact manifest partition; "
                f"missing={sorted(manifest_ids-combined)[:3]}, "
                f"extra={sorted(combined-manifest_ids)[:3]}")

    if not legacy:
        required = ("manifest_digest", "coverage_sha256", "release_sha256",
                    "n_mutants", "n_mapped", "n_uncovered", "n_pairs", "digest")
        missing = [key for key in required if key not in mapping]
        if missing:
            _refuse(f"map is missing identity fields {missing}")
        if mapping["manifest_digest"] != manifest["digest"]:
            _refuse("map names a different manifest digest")
        for key, actual in (("n_mutants", len(manifest_ids)),
                            ("n_mapped", len(mapped_ids)),
                            ("n_uncovered", len(uncovered_ids)),
                            ("n_pairs", pair_count)):
            _nonnegative_int(mapping[key], f"map.{key}")
            if mapping[key] != actual:
                _refuse(f"map {key}={mapping[key]}, recomputed {actual}")
        for key in ("coverage_sha256", "release_sha256"):
            if not _is_sha256(mapping[key]):
                _refuse(f"map {key} is not a SHA-256 digest")
        wanted = map_digest(mapping)
        if mapping["digest"] != wanted:
            _refuse(f"map digest is {mapping['digest']!r}, recomputed {wanted!r}")
    if coverage_by_item is not None:
        expected_by, expected_uncovered = M.map_mutants_to_items(
            manifest, coverage_by_item)
        if by_mutant != expected_by or uncovered != expected_uncovered:
            _refuse("map membership does not rederive from coverage rows")
    return {
        "schema": mapping.get("schema"),
        "legacy_format": legacy,
        "manifest_digest": manifest["digest"],
        "n_mutants": len(manifest_ids),
        "n_mapped": len(mapped_ids),
        "n_uncovered": len(uncovered_ids),
        "n_pairs": pair_count,
        "digest": map_digest(mapping),
        "canonical_sha256": canonical_sha256(mapping),
    }


def load_jsonl(path: str) -> list[dict]:
    rows: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                _refuse(f"{path} line {number} is not JSON ({exc})")
            if not isinstance(row, dict):
                _refuse(f"{path} line {number} is not a JSON object")
            rows.append(row)
    return rows


def load_release_ids(path: str) -> set[str]:
    ids: set[str] = set()
    for number, row in enumerate(load_jsonl(path), 1):
        item_id = row.get("item_id")
        if not isinstance(item_id, str) or not item_id:
            _refuse(f"release row {number} has no item_id")
        if item_id in ids:
            _refuse(f"release repeats item_id {item_id!r}")
        ids.add(item_id)
    return ids


def coverage_from_rows(rows: Iterable[dict]) -> dict:
    coverage: dict = {}
    for row in rows:
        item_id = row.get("item_id")
        if not isinstance(item_id, str) or not item_id:
            _refuse("a coverage row has no item_id")
        if item_id in coverage:
            _refuse(f"coverage has two rows for item {item_id!r}")
        coverage[item_id] = row.get("coverage_lines") or {}
    return coverage


def solution_digest(files_by_item: dict) -> str:
    """The historical candidate-digest algorithm, used only for checking."""
    h = hashlib.sha256()
    for item_id in sorted(files_by_item):
        if not isinstance(item_id, str) or not item_id or "\0" in item_id:
            _refuse("candidate item IDs must be non-empty NUL-free strings")
        h.update(item_id.encode())
        h.update(b"\0")
        files = files_by_item[item_id]
        if not isinstance(files, list):
            _refuse(f"produced_files for {item_id!r} is not a list")
        if not all(isinstance(produced, dict) for produced in files):
            _refuse(f"produced_files for {item_id!r} has a non-object")
        paths = [produced.get("file_path") for produced in files]
        if not all(isinstance(path, str) and path and "\0" not in path
                   for path in paths) or len(set(paths)) != len(paths):
            _refuse(f"produced_files for {item_id!r} needs unique, non-empty, "
                    "NUL-free file paths")
        for produced in sorted(files, key=lambda item: item["file_path"]):
            if not isinstance(produced, dict):
                _refuse(f"produced_files for {item_id!r} has a non-object")
            code = produced.get("code")
            if not isinstance(code, str) or "\0" in code:
                _refuse(f"produced_files for {item_id!r} needs NUL-free "
                        "string code")
            h.update(produced["file_path"].encode())
            h.update(b"\0")
            h.update(code.encode("utf-8", "surrogateescape"))
            h.update(b"\0")
        h.update(b"\n")
    return h.hexdigest()[:16]


def _passed_files(run_rows: Iterable[dict]) -> dict:
    files: dict = {}
    seen: set[str] = set()
    for row in run_rows:
        item_id = row.get("item_id")
        if not isinstance(item_id, str) or not item_id:
            _refuse("candidate run has a row without an item_id")
        if item_id in seen:
            _refuse(f"candidate run repeats item_id {item_id!r}")
        seen.add(item_id)
        if row.get("outcome") != "passed":
            continue
        files[item_id] = row.get("produced_files") or []
    return files


def _gold_files(gold_rows: Iterable[dict], item_ids: set[str]) -> dict:
    files: dict = {}
    for row in gold_rows:
        item_id = row.get("item_id")
        if item_id not in item_ids:
            continue
        if item_id in files:
            _refuse(f"gold baseline has two rows for {item_id!r}")
        files[item_id] = row.get("produced_files") or []
    missing = sorted(item_ids - set(files))
    if missing:
        _refuse(f"gold baseline is missing passed items {missing[:3]}")
    return files


def legacy_scoring_pairs(mapping: dict,
                         candidate_run_rows: list[dict]) -> set[tuple[str, str]]:
    """The recall-oriented (item, mutant) universe of a legacy report."""
    passed_item_ids = set(_passed_files(candidate_run_rows))
    return {
        (item_id, mutant_id)
        for mutant_id, item_ids in mapping["by_mutant"].items()
        for item_id in item_ids if item_id in passed_item_ids}

def legacy_consistency(*, scored_manifest: dict, mapping: dict,
                       candidate_run_rows: list[dict],
                       gold_baseline_rows: list[dict],
                       candidate_result_rows: list[dict],
                       gold_result_rows: list[dict],
                       raw_manifest: Optional[dict] = None,
                       release_ids: Optional[set[str]] = None) -> dict:
    """Prove preserved joins without inventing historical provenance."""
    validate_manifest(scored_manifest, raw_manifest=raw_manifest)
    map_manifest = raw_manifest if raw_manifest is not None else scored_manifest
    validate_map(mapping, map_manifest, release_ids=release_ids,
                 allow_legacy=True)
    passed = _passed_files(candidate_run_rows)
    if not passed:
        _refuse("candidate run has no passed solutions to attest")
    passed_ids = set(passed)
    gold = _gold_files(gold_baseline_rows, passed_ids)
    candidate_digest = solution_digest(passed)
    gold_digest = solution_digest(gold)
    scored_ids = {m["id"] for m in scored_manifest["mutants"]}
    expected = {(mutant_id, item_id)
                for mutant_id, items in mapping["by_mutant"].items()
                if mutant_id in scored_ids
                for item_id in items if item_id in passed_ids}
    records = {m["id"]: m for m in scored_manifest["mutants"]}

    def check_rows(label: str, rows: list[dict], digest: str) -> dict:
        pairs: list[tuple[str, str]] = []
        native_manifest_rows = 0
        absent_descriptors: set[str] = set()
        for number, row in enumerate(rows, 1):
            if "mutant_id" not in row or "item_id" not in row:
                _refuse(f"{label} row {number} lacks mutant_id/item_id")
            pair = (row["mutant_id"], row["item_id"])
            pairs.append(pair)
            mutant = records.get(pair[0])
            if mutant is None:
                _refuse(f"{label} row {number} names unknown mutant {pair[0]}")
            for key in ("file", "operator", "start_line"):
                if key not in row:
                    _refuse(f"{label} row {number} lacks recorded {key}")
            # Historical rows recorded the locator trio above but not the
            # original/mutated text or column. Compare every descriptor that
            # actually exists; never manufacture the absent fields.
            for key in ("file", "operator", "start_line", "start_col",
                        "original", "mutated"):
                if key not in row:
                    absent_descriptors.add(key)
                elif row[key] != mutant.get(key):
                    _refuse(f"{label} row {number} {key} differs from manifest")
            if row.get("engine") not in (None, scored_manifest["engine"]):
                _refuse(f"{label} row {number} names another engine")
            if row.get("engine_version") not in (
                    None, scored_manifest["engine_version"]):
                _refuse(f"{label} row {number} names another engine version")
            row_manifest = row.get("manifest_digest")
            if row_manifest is not None:
                if row_manifest != scored_manifest["digest"]:
                    _refuse(f"{label} row {number} names another manifest")
                native_manifest_rows += 1
            if row.get("candidate_digest") != digest:
                _refuse(f"{label} row {number} candidate bytes digest differs "
                        "from preserved input bytes")
        if len(set(pairs)) != len(pairs):
            _refuse(f"{label} results contain duplicate pairs")
        got = set(pairs)
        if got != expected:
            _refuse(f"{label} pair set differs; "
                    f"missing={sorted(expected-got)[:3]}, "
                    f"extra={sorted(got-expected)[:3]}")
        return {"rows": len(rows), "pairs": len(got),
                "rows_with_manifest_digest": native_manifest_rows,
                "absent_descriptor_fields": sorted(absent_descriptors)}

    candidate_facts = check_rows("candidate", candidate_result_rows,
                                 candidate_digest)
    gold_facts = check_rows("gold", gold_result_rows, gold_digest)
    native_rows = (candidate_facts["rows_with_manifest_digest"]
                   + gold_facts["rows_with_manifest_digest"])
    total_rows = candidate_facts["rows"] + gold_facts["rows"]
    return {
        "schema": LEGACY_SCHEMA,
        "validation_class": "legacy_consistency",
        "native_provenance": False,
        "historical_manifest_digest_present": native_rows == total_rows,
        "manifest_digest": scored_manifest["digest"],
        "raw_manifest_digest": (raw_manifest or {}).get("digest"),
        "candidate_digest": candidate_digest,
        "gold_digest": gold_digest,
        "n_passed": len(passed),
        "n_expected_pairs": len(expected),
        "candidate": candidate_facts,
        "gold": gold_facts,
        "limitations": [
            "Association is reconstructed from preserved bytes and exact "
            "ID/pair joins, not native identity on every historical row.",
            "No historical row was modified or backfilled.",
            "Historical rows omit descriptor fields recorded only in the "
            "manifest; full identity is resolved by mutant_id. Missing fields "
            f"were candidate={candidate_facts['absent_descriptor_fields']} "
            f"and gold={gold_facts['absent_descriptor_fields']}.",
        ],
    }


def pinned_enumerator_identity(relative_path: str) -> dict:
    """Resolve and authenticate one current enumerator authority record.

    ``VERSIONS.yml`` is the single pin.  Producers still have to emit their
    self-declared revision, but execution sites also need the authority's
    content digest so they can authenticate the exact staged bytes.  Returning
    both values avoids re-reading a mutable source after it was checked.
    """
    from . import versions

    try:
        assets = versions.component("mutation_assets")
    except (versions.ManifestError, OSError, KeyError, TypeError) as exc:
        _refuse(f"cannot resolve current enumerator pins: {exc}")
    if not isinstance(assets, dict):
        _refuse("mutation_assets version authority is not an object")
    current = assets.get("current_enumerators")
    if not isinstance(current, dict):
        _refuse("mutation-assets authority has no current_enumerators map")
    claim = current.get(relative_path)
    _exact_keys(claim, set(CURRENT_ENUMERATOR_PIN_FIELDS),
                f"current enumerator pin {relative_path!r}")
    revision = claim["enumerator_rev"]
    if not isinstance(revision, str) or not revision.strip():
        _refuse(f"current enumerator pin {relative_path!r} has no revision")
    if not _is_sha256(claim["sha256"]):
        _refuse(f"current enumerator pin {relative_path!r} has invalid SHA-256")
    source = os.path.abspath(os.path.join(BENCHMARK_ROOT, relative_path))
    try:
        inside = os.path.commonpath((BENCHMARK_ROOT, source)) == BENCHMARK_ROOT
    except ValueError:
        inside = False
    if not inside:
        _refuse(f"current enumerator path escapes benchmark root: "
                f"{relative_path!r}")
    validate_preserved_file(
        source, claim["sha256"],
        label=f"current enumerator {relative_path!r}")
    return {"enumerator_rev": revision, "sha256": claim["sha256"]}


def pinned_enumerator_revision(relative_path: str) -> str:
    """Resolve one authenticated current enumerator revision."""
    return pinned_enumerator_identity(relative_path)["enumerator_rev"]


def validate_enumerator_envelope(
        document, *, expected_engine: str, expected_engine_version: str,
        expected_parser_version: Optional[str] = None,
        expected_enumerator_rev: Optional[str] = None) -> dict:
    """Validate a complete enumerator report without discarding witnesses."""
    if not isinstance(document, dict):
        _refuse("canonical construction requires the enumerator envelope")
    missing = sorted(ENUMERATOR_ENVELOPE_REQUIRED_FIELDS - set(document))
    unknown = sorted(
        set(document)
        - ENUMERATOR_ENVELOPE_REQUIRED_FIELDS
        - ENUMERATOR_ENVELOPE_OPTIONAL_FIELDS)
    if missing or unknown:
        _refuse("enumerator envelope fields differ; "
                f"missing={missing}, unknown={unknown}")
    if expected_engine == "r2t-mutate-java" \
            and "analysis_recipe" not in document:
        _refuse("Java enumerator envelope is missing analysis recipe authority")
    if expected_engine != "r2t-mutate-java" \
            and "analysis_recipe" in document:
        _refuse("non-Java enumerator envelope carries Java analysis authority")
    if not isinstance(document["mutants"], list):
        _refuse("canonical construction requires the enumerator envelope")
    for key, expected in (("engine", expected_engine),
                          ("engine_version", expected_engine_version)):
        if document.get(key) != expected:
            _refuse(f"enumerator {key}={document.get(key)!r}, "
                    f"expected {expected!r}")
    go_files = _go_context_files(document)
    if go_files is not None:
        for index, mutant in enumerate(document["mutants"]):
            if (not isinstance(mutant, dict) or not isinstance(mutant.get("file"), str)
                    or mutant["file"] not in go_files):
                _refuse(f"Go enumerator mutant #{index} is outside its recorded compiler contexts")
    errors = document.get("errors")
    if not isinstance(errors, dict):
        _refuse("enumerator errors witness is not an object")
    if errors:
        _refuse(f"enumerator reports {len(errors)} failed files")
    if not isinstance(document.get("files"), int) \
            or isinstance(document.get("files"), bool) \
            or document["files"] < 0:
        _refuse("enumerator files count is invalid")
    if not isinstance(document.get("parser"), str) or not document["parser"]:
        _refuse("enumerator did not report its parser")
    if expected_parser_version is not None \
            and document["parser"] != expected_parser_version:
        _refuse(f"enumerator parser={document['parser']!r}, "
                f"expected {expected_parser_version!r}")
    if "n_invalid" in document:
        _nonnegative_int(document["n_invalid"], "enumerator.n_invalid")
        if document["n_invalid"] == 0:
            _refuse("enumerator.n_invalid must be omitted when zero")
    if "enumerator_rev" in document \
            and (not isinstance(document["enumerator_rev"], str)
                 or not document["enumerator_rev"].strip()):
        _refuse("enumerator.enumerator_rev must be a non-empty string")
    if expected_enumerator_rev is not None:
        if not isinstance(expected_enumerator_rev, str) \
                or not expected_enumerator_rev.strip():
            _refuse("expected_enumerator_rev must be a non-empty string")
        if document.get("enumerator_rev") != expected_enumerator_rev:
            _refuse("enumerator enumerator_rev="
                    f"{document.get('enumerator_rev')!r}, expected "
                    f"{expected_enumerator_rev!r}")
    return document


def load_enumerator_envelope(path: str, *, expected_engine: str,
                             expected_engine_version: str,
                             expected_parser_version: Optional[str] = None,
                             expected_enumerator_rev: Optional[str] = None
                             ) -> dict:
    """Read and validate one complete enumerator report."""
    with open(path, encoding="utf-8") as fh:
        document = json.load(fh)
    return validate_enumerator_envelope(
        document, expected_engine=expected_engine,
        expected_engine_version=expected_engine_version,
        expected_parser_version=expected_parser_version,
        expected_enumerator_rev=expected_enumerator_rev)


def _normalised_roots(values, label: str) -> list[str]:
    """Sorted, deduplicated, repository-relative bounded source roots.

    Every party that names a bounded source set -- the manifest's own keep
    policy, the audit attestation, and the frozen index entry -- goes through
    this one function before the three are compared.  Comparing the raw lists
    instead would make `src/` and `src` two different source sets, and a
    spelling difference is not a fact about which files were audited.
    """
    if not isinstance(values, list) or not values:
        _refuse(f"{label} names no bounded source roots")
    roots = []
    for value in values:
        if not isinstance(value, str) or not value:
            _refuse(f"{label} names an invalid bounded source root")
        root = M.normalise_path(value).rstrip("/")
        if not root or root == "." or root == ".." or root.startswith("../"):
            _refuse(f"{label} bounded source root {value!r} is not a "
                    "repository-relative directory")
        roots.append(root)
    return sorted(set(roots))


def _audit_roots(manifest: dict) -> list[str]:
    """The bounded source set this manifest itself defines.

    Derived from the manifest and from nothing an operator supplies, because
    `validate_completed_audit_binding` must be able to RECOMPUTE the source
    set an attestation claims to have audited.  A root that can be widened at
    audit time is a root a fabricated attestation can name instead.
    """
    roots = [value[1:] for value in manifest.get("exclusions") or ()
             if isinstance(value, str) and value.startswith("!")]
    if not roots:
        roots = [M.normalise_path(m["file"]).split("/", 1)[0]
                 for m in manifest["mutants"]]
    if not roots:
        _refuse("cannot derive a bounded source set from an empty manifest")
    return _normalised_roots(roots, "manifest keep policy")


def _mutants_outside_roots(manifest: dict,
                           roots: Iterable[str]) -> list[str]:
    """Manifest files that are neither a root nor strictly below one.

    The `+ "/"` is the whole check: a plain `startswith(root)` would let an
    attestation over `src` cover a mutant in `src2`, a different directory
    the audit never opened.
    """
    exact = set(roots)
    prefixes = tuple(root + "/" for root in sorted(exact))
    return sorted({rel for rel in (M.normalise_path(m["file"])
                                   for m in manifest["mutants"])
                   if rel not in exact and not rel.startswith(prefixes)})


def expected_runtime_parser(manifest: dict) -> str:
    """Parser spelling emitted by the engine's own enumeration envelope."""
    parser = manifest["parser"]
    if manifest["engine"] == M.ENGINE:
        return parser.split(" ", 1)[-1].split("@", 1)[0]
    return parser


def _offline_git_env() -> dict:
    """The one closed environment a reviewed Git object read runs under.

    This used to copy the caller's environment and overlay three controls.
    The controls were the right ones -- a partial/promisor clone may contact
    its remote from an apparently read-only ``cat-file``, and a full object ID
    is still replace-ref aware, so a mutable local ``refs/replace/<commit>``
    can resolve ``<commit>:<path>`` through another tree while the command
    line keeps naming the reviewed commit -- but everything left alone
    survived, including ``GIT_DIR``, ``GIT_OBJECT_DIRECTORY``,
    ``GIT_ALTERNATE_OBJECT_DIRECTORIES`` and the ``GIT_CONFIG_COUNT`` triple,
    each of which outranks ``-C <repository>``.  A caller could therefore
    answer a reviewed-blob question out of a repository it supplied.  The
    environment now comes from `r2t.core.reviewed_git`, which BUILDS it.
    """
    return reviewed_git.closed_environment()


def validate_asset_index(index: dict) -> dict:
    """Validate the small frozen index's schema and content addresses."""
    _exact_keys(index, {"schema", "version", "projects"}, "asset index")
    if index.get("schema") != ASSET_INDEX_SCHEMA:
        _refuse("unknown mutation asset index schema")
    if type(index.get("version")) is not int \
            or index["version"] != 1 \
            or not isinstance(index.get("projects"), dict):
        _refuse("mutation asset index version/projects are invalid")
    if not index["projects"]:
        _refuse("mutation asset index has no projects")
    for project, entry in index["projects"].items():
        if not isinstance(project, str) or not isinstance(entry, dict):
            _refuse("mutation asset index has an invalid project entry")
        _exact_keys(entry, {
            "engine", "engine_version", "parser", "raw_population",
            "scored_population", "boundary", "mutation_map",
            "coverage_oracle", "release", "engine_source",
            "materialisation_audit"}, f"asset index project {project}")
        if not all(isinstance(entry[key], str) and entry[key]
                   for key in ("engine", "engine_version", "parser")):
            _refuse(f"{project} engine/version/parser identity is invalid")

        raw = entry["raw_population"]
        _exact_keys(raw, {"role", "n", "manifest_digest",
                          "canonical_sha256", "preserved_file_sha256"},
                    f"{project}.raw_population")
        if raw["role"] != "pre_boundary_catalogue":
            _refuse(f"{project} raw population role is not pre-boundary")
        _positive_int(raw["n"], f"{project}.raw_population.n")
        for key in ("manifest_digest", "canonical_sha256",
                    "preserved_file_sha256"):
            if not _is_sha256(raw[key]):
                _refuse(f"{project}.raw_population.{key} is invalid")
            if raw[key] == FORBIDDEN_STALE_MANIFEST_DIGEST:
                _refuse(f"{project} cites the forbidden stale digest")

        scored = entry["scored_population"]
        _exact_keys(scored, {"role", "n", "manifest_digest",
                             "canonical_sha256", "raw_manifest_digest",
                             "n_non_production_excluded"},
                    f"{project}.scored_population")
        if scored["role"] not in ("boundary_scored", "raw_equals_scored"):
            _refuse(f"{project} scored population role is invalid")
        _positive_int(scored["n"], f"{project}.scored_population.n")
        _nonnegative_int(scored["n_non_production_excluded"],
                         f"{project}.scored_population exclusions")
        for key in ("manifest_digest", "canonical_sha256",
                    "raw_manifest_digest"):
            if not _is_sha256(scored[key]):
                _refuse(f"{project}.scored_population.{key} is invalid")
            if scored[key] == FORBIDDEN_STALE_MANIFEST_DIGEST:
                _refuse(f"{project} cites the forbidden stale digest")
        if scored["raw_manifest_digest"] != raw["manifest_digest"]:
            _refuse(f"{project} scored population names another raw digest")
        if scored["role"] == "boundary_scored":
            if raw["n"] != (scored["n"]
                            + scored["n_non_production_excluded"]):
                _refuse(f"{project} boundary population counts do not derive")
            if scored["n_non_production_excluded"] == 0:
                _refuse(f"{project} boundary_scored role excludes no rows")
        else:
            if (raw["n"] != scored["n"]
                    or scored["n_non_production_excluded"] != 0
                    or raw["manifest_digest"] != scored["manifest_digest"]
                    or raw["canonical_sha256"]
                    != scored["canonical_sha256"]):
                _refuse(f"{project} raw_equals_scored identities differ")

        boundary = entry["boundary"]
        _exact_keys(boundary, {"config", "classification", "sha256"},
                    f"{project}.boundary")
        if not isinstance(boundary["config"], str) or not boundary["config"] \
                or boundary["classification"] != "production" \
                or not _is_sha256(boundary["sha256"]):
            _refuse(f"{project} boundary identity is invalid")

        mapping = entry["mutation_map"]
        _exact_keys(mapping, {"manifest_role", "n_mutants", "n_mapped",
                              "n_uncovered", "n_pairs", "digest",
                              "canonical_sha256", "coverage_sha256",
                              "release_sha256"},
                    f"{project}.mutation_map")
        if mapping["manifest_role"] != "scored_population":
            _refuse(f"{project} mutation map is not bound to scored rows")
        for key in ("n_mutants", "n_mapped", "n_uncovered", "n_pairs"):
            _nonnegative_int(mapping[key], f"{project}.mutation_map.{key}")
        if mapping["n_mutants"] != scored["n"] \
                or mapping["n_mapped"] + mapping["n_uncovered"] \
                != mapping["n_mutants"]:
            _refuse(f"{project} mutation map counts do not partition scored")
        for key in ("digest", "canonical_sha256", "coverage_sha256",
                    "release_sha256"):
            if not _is_sha256(mapping[key]):
                _refuse(f"{project}.mutation_map.{key} is invalid")

        coverage = entry["coverage_oracle"]
        release = entry["release"]
        coverage_keys = {"rows", "sha256"}
        if project == "kapua" and isinstance(coverage, dict) and "projection_sha256" in coverage:
            coverage_keys.add("projection_sha256")
            if not _is_sha256(coverage["projection_sha256"]):
                _refuse("Kapua coverage projection digest is invalid")
        _exact_keys(coverage, coverage_keys, f"{project}.coverage_oracle")
        _exact_keys(release, {"items", "sha256"}, f"{project}.release")
        _positive_int(coverage["rows"], f"{project}.coverage_oracle.rows")
        _positive_int(release["items"], f"{project}.release.items")
        if coverage["rows"] != release["items"]:
            _refuse(f"{project} coverage/release counts differ")
        if not _is_sha256(coverage["sha256"]) \
                or not _is_sha256(release["sha256"]):
            _refuse(f"{project} coverage/release digest is invalid")
        if mapping["coverage_sha256"] != coverage["sha256"] \
                or mapping["release_sha256"] != release["sha256"]:
            _refuse(f"{project} map envelope names other coverage/release")

        engine_source = entry["engine_source"]
        _exact_keys(engine_source, {"sha256"}, f"{project}.engine_source")
        if not _is_sha256(engine_source["sha256"]):
            _refuse(f"{project}.engine_source.sha256 is invalid")

        audit = entry["materialisation_audit"]
        _exact_keys(audit, {"expected_mutants", "status",
                            "attestation_digest", "release_blocker",
                            "bounded_roots", "n_source_files",
                            "source_set_sha256", "runtime_parser_identity",
                            "engine_source_sha256"},
                    f"{project}.materialisation_audit")
        if audit["expected_mutants"] != raw["n"]:
            _refuse(f"{project} audit count does not match raw population")
        roots = audit["bounded_roots"]
        if not isinstance(roots, list) or not roots \
                or roots != sorted(set(roots)) \
                or not all(isinstance(root, str) and root for root in roots):
            _refuse(f"{project} audit bounded roots are invalid")
        _positive_int(audit["n_source_files"],
                      f"{project}.materialisation_audit.n_source_files")
        if not _is_sha256(audit["source_set_sha256"]):
            _refuse(f"{project} audit source-set digest is invalid")
        if audit["runtime_parser_identity"] != entry["parser"]:
            _refuse(f"{project} audit parser identity differs from project")
        if audit["engine_source_sha256"] != engine_source["sha256"]:
            _refuse(f"{project} audit engine source differs from project")
        if audit["status"] not in ("provisional", "complete"):
            _refuse(f"{project} materialisation audit status is invalid")
        attestation = audit.get("attestation_digest")
        if audit["status"] == "complete":
            if not _is_sha256(attestation):
                _refuse(f"{project} complete audit lacks attestation digest")
            if audit.get("release_blocker") is not None:
                _refuse(f"{project} complete audit still names a blocker")
        elif attestation is not None:
            _refuse(f"{project} provisional audit must not claim a digest")
        elif not isinstance(audit.get("release_blocker"), str) \
                or not audit["release_blocker"]:
            _refuse(f"{project} provisional audit does not explain its blocker")
    return {"schema": ASSET_INDEX_SCHEMA, "version": 1,
            "projects": sorted(index["projects"])}


def validate_archived_v1_manifests(
        index: Optional[dict] = None,
        paths: Optional[dict[str, str]] = None) -> dict:
    """Bind both repository archives to the v1 population authority.

    Four different identities answer four different tampering questions:
    ``preserved_file_sha256`` covers the producer's serialization bytes,
    ``canonical_sha256`` covers the parsed JSON object, ``manifest_digest``
    covers the manifest without its self-reference, and the exact rebuild
    recomputes every content-addressed mutant id.  None substitutes for
    another, so all four are mandatory and sourced from the already-frozen
    Slice 1 asset index.

    ``paths`` is injectable only for mutation-probe tests.  Production calls
    always use :data:`r2t.data.mutation.ARCHIVED_MANIFESTS`, which are repository
    release paths rather than mutable external corpus locations.
    """
    if index is None:
        index = _read_json_object(ASSET_INDEX_PATH,
                                  "frozen mutation asset index")
    validate_asset_index(index)
    paths = dict(M.ARCHIVED_MANIFESTS if paths is None else paths)
    projects = set(index["projects"])
    if set(paths) != projects:
        _refuse("archived v1 manifest paths differ from the frozen projects; "
                f"missing={sorted(projects-set(paths))}, "
                f"unknown={sorted(set(paths)-projects)}")

    verified = {}
    v1_profile = list(getattr(M, "OPERATORS_V1", M.OPERATORS))
    for project in sorted(projects):
        entry = index["projects"][project]
        claim = entry["raw_population"]
        path = paths[project]
        preserved_sha = validate_preserved_file(
            path, claim["preserved_file_sha256"],
            f"{project} archived v1 manifest")
        try:
            with open(path, encoding="utf-8") as fh:
                manifest = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            _refuse(f"cannot read {project} archived v1 manifest: {exc}")

        facts = validate_manifest(manifest,
                                  expected_engine=entry["engine"])
        identity = {
            "engine": manifest["engine"],
            "engine_version": manifest["engine_version"],
            "parser": manifest["parser"],
        }
        expected_identity = {
            "engine": entry["engine"],
            "engine_version": entry["engine_version"],
            "parser": entry["parser"],
        }
        if identity != expected_identity:
            _refuse(f"{project} archived v1 engine identity differs from "
                    "the frozen asset index")
        if manifest["operators"] != v1_profile:
            _refuse(f"{project} archived manifest does not use the immutable "
                    "v1 operator profile")
        if "n_invalid" in manifest or "enumerator_rev" in manifest:
            _refuse(f"{project} archived v1 manifest fabricates post-v1 "
                    "enumerator metadata")

        actual_claim = {
            "role": "pre_boundary_catalogue",
            "n": facts["n"],
            "manifest_digest": facts["digest"],
            "canonical_sha256": facts["canonical_sha256"],
            "preserved_file_sha256": preserved_sha,
        }
        if actual_claim != claim:
            changed = sorted(key for key in claim
                             if actual_claim.get(key) != claim[key])
            _refuse(f"{project} archived v1 population differs from its "
                    f"frozen {changed} claim(s)")

        rebuilt = M.build_manifest(
            [{key: value for key, value in mutant.items() if key != "id"}
             for mutant in manifest["mutants"]],
            operators=manifest["operators"],
            exclusions=manifest["exclusions"],
            parser_version=manifest["parser"],
            engine=manifest["engine"],
            engine_version=manifest["engine_version"],
            sample=manifest["sample"], seed=manifest["seed"])
        # The docx v1 producer explicitly recorded the already-proven zero
        # boundary exclusion.  It predates build_manifest's boundary layer,
        # so restore that one historical top-level fact before recomputing the
        # complete document digest; no other field is copied from the input.
        if "n_non_production_excluded" in manifest:
            rebuilt["n_non_production_excluded"] = \
                manifest["n_non_production_excluded"]
            rebuilt["digest"] = M.manifest_digest(rebuilt)
        if rebuilt != manifest:
            _refuse(f"{project} archived v1 manifest does not rebuild "
                    "exactly from id-free mutant records")

        verified[project] = {
            "path": path,
            "preserved_file_sha256": preserved_sha,
            "canonical_sha256": facts["canonical_sha256"],
            "manifest_digest": facts["digest"],
            "n": facts["n"],
            "n_ids_rebuilt": len(rebuilt["mutants"]),
        }
    return verified


def require_index_release_ready(index: dict, project: str) -> None:
    validate_asset_index(index)
    entry = index["projects"].get(project)
    if entry is None:
        _refuse(f"asset index has no project {project!r}")
    if entry["materialisation_audit"]["status"] != "complete":
        _refuse(f"{project} mutation assets are provisional: the frozen index "
                "does not yet bind a completed full materialisation audit")


def _pinned_repository_file(root: str, rel: str, label: str) -> str:
    """Resolve one repository-relative pinned path to a real regular file."""
    if not isinstance(rel, str) or not rel or os.path.isabs(rel):
        _refuse(f"{label} is not a repository-relative path: {rel!r}")
    normal = os.path.normpath(rel.replace("\\", "/"))
    if normal == ".." or normal.startswith(".." + os.sep) or normal == ".":
        _refuse(f"{label} escapes the repository root: {rel}")
    absolute = os.path.join(root, normal)
    if not os.path.lexists(absolute):
        _refuse(f"{label} is missing from the repository: {rel}")
    if os.path.islink(absolute):
        _refuse(f"{label} is a symlink, and a pin on a link pins whatever the "
                f"link is repointed at: {rel}")
    if os.path.realpath(absolute) != absolute:
        _refuse(f"{label} is reached through a symlinked parent: {rel}")
    if not os.path.isfile(absolute):
        _refuse(f"{label} is not a regular file: {rel}")
    try:
        inside = os.path.commonpath((root, absolute)) == root
    except ValueError:
        inside = False
    if not inside:
        _refuse(f"{label} resolves outside the repository root: {rel}")
    return absolute


def asset_pin_expectations(index: Optional[dict] = None) -> dict:
    """Logical repository path -> the SHA-256 the frozen index pins.

    Boundaries resolve to live files.  Engine paths are logical producer paths
    whose v1 bytes resolve through ``historical_engine_sources`` to Git blobs;
    current enumerators are independently pinned.  The engine path is still
    resolved through `mutation_run.binding_for`, the same function the
    campaign and audit use, so an unknown engine is refused rather than
    silently skipped.
    """
    if index is None:
        index = _read_json_object(ASSET_INDEX_PATH,
                                  "frozen mutation asset index")
    validate_asset_index(index)
    from ..bench.mutation_run import binding_for
    pins: dict[str, str] = {}

    def pin(rel, sha256: str, label: str) -> None:
        if not isinstance(rel, str) or not rel:
            _refuse(f"{label} names no file")
        rel = rel.replace(os.sep, "/")
        if not _is_sha256(sha256):
            _refuse(f"{label} carries no SHA-256 pin")
        if pins.get(rel, sha256) != sha256:
            _refuse(f"the frozen index pins two different digests for {rel}")
        pins[rel] = sha256

    for project in sorted(index["projects"]):
        entry = index["projects"][project]
        pin(entry["boundary"]["config"], entry["boundary"]["sha256"],
            f"{project} boundary configuration")
        try:
            engine_dir, applier = binding_for(entry["engine"])
        except (RuntimeError, ValueError, ImportError) as exc:
            _refuse(f"{project} names mutation engine {entry['engine']!r}, "
                    f"which resolves to no applier: {exc}")
        pin(os.path.relpath(os.path.join(engine_dir, applier.source),
                            REPOSITORY_ROOT),
            entry["engine_source"]["sha256"],
            f"{project} mutation engine source")
    if not pins:
        _refuse("the frozen index pins no in-repository asset file")
    return pins


def legacy_engine_source_bindings() -> dict:
    """Historical v1 producer identities from ``VERSIONS.yml``.

    The live enumerators may evolve without being retroactively claimed as
    the producers of preserved v1 manifests.  Each old SHA is therefore tied
    to an exact commit:path and Git blob.  No network fetch is attempted: a
    shallow/source-only checkout that lacks the object fails loudly.
    """
    from . import versions as V
    block = V.component("mutation_assets").get("historical_engine_sources")
    if not isinstance(block, dict) or set(block) != {"commit", "files"}:
        _refuse("VERSIONS.yml has no exact historical_engine_sources binding")
    commit = block["commit"]
    files = block["files"]
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) \
            is None or not isinstance(files, dict) or not files:
        _refuse("VERSIONS.yml historical engine commit/files are invalid")
    bindings = {}
    for rel, item in sorted(files.items()):
        if not isinstance(item, dict) or set(item) != {"git_blob", "sha256"}:
            _refuse(f"historical engine source {rel!r} has invalid fields")
        blob = item["git_blob"]
        digest = item["sha256"]
        if re.fullmatch(r"[0-9a-f]{40}", str(blob)) is None \
                or not _is_sha256(digest):
            _refuse(f"historical engine source {rel!r} has invalid identity")
        repository_rel = os.path.relpath(
            os.path.join(V.BENCH_ROOT, rel), REPOSITORY_ROOT).replace(
                os.sep, "/")
        bindings[repository_rel] = {
            "commit": commit, "path": repository_rel,
            "git_blob": blob, "sha256": digest,
        }
    return bindings


def validate_legacy_engine_source_bindings(*, repository_root: Optional[str]
                                           = None) -> dict:
    """Resolve and hash every recorded v1 producer blob, without network."""
    root = os.path.realpath(repository_root or REPOSITORY_ROOT)
    git = shutil.which("git")
    if git is None:
        _refuse("git is unavailable; historical engine blobs cannot be checked")
    env = _offline_git_env()
    checked = {}
    for rel, binding in legacy_engine_source_bindings().items():
        commit = binding["commit"]
        blob = binding["git_blob"]

        def run(*args, text=False):
            cp = subprocess.run(
                [git, "-C", root, *args], capture_output=True, text=text,
                timeout=30, env=env)
            if cp.returncode != 0:
                stderr = cp.stderr.strip() if text else cp.stderr.decode(
                    "utf-8", "replace").strip()
                _refuse(f"historical engine Git object is unavailable for "
                        f"{rel}: {' '.join(args)}: {stderr[-400:]}. "
                        f"VERSIONS.yml pins this producer as a blob in "
                        f"history, not as a working-tree file, so it needs a "
                        f"full clone; a shallow or single-branch clone cannot "
                        f"answer for it.")
            return cp.stdout

        commit_type = run("cat-file", "-t", commit, text=True).strip()
        if commit_type != "commit":
            _refuse(f"historical engine commit {commit} has type "
                    f"{commit_type!r}, not commit")
        resolved = run("rev-parse", f"{commit}:{rel}", text=True).strip()
        if resolved != blob:
            _refuse(f"historical engine {commit}:{rel} resolves to {resolved}, "
                    f"but VERSIONS.yml pins blob {blob}")
        blob_type = run("cat-file", "-t", blob, text=True).strip()
        if blob_type != "blob":
            _refuse(f"historical engine object {blob} has type "
                    f"{blob_type!r}, not blob")
        contents = run("cat-file", "blob", blob)
        digest = hashlib.sha256(contents).hexdigest()
        if digest != binding["sha256"]:
            _refuse(f"historical engine blob {blob} hashes to {digest}, but "
                    f"VERSIONS.yml pins {binding['sha256']}")
        checked[rel] = dict(binding)
    return checked


def validate_asset_pins(index: Optional[dict] = None, *,
                        repository_root: Optional[str] = None,
                        git_repository_root: Optional[str] = None) -> dict:
    """Rehash live boundaries and the exact Git blobs that produced v1.

    A pin nothing recomputes is a comment.  This is the focused gate; it is
    called by the aggregate selftest and by CI (through
    `scripts/validate_asset_pins.py`), and the same four files are
    additionally frozen by content in `VERSIONS.yml`, so a moved byte is red
    in two independent places.
    """
    root = os.path.realpath(repository_root or REPOSITORY_ROOT)
    pins = asset_pin_expectations(index)
    historical = validate_legacy_engine_source_bindings(
        repository_root=(git_repository_root
                         if git_repository_root is not None else root))
    files: dict[str, str] = {}
    for rel in sorted(pins):
        if rel in historical:
            if historical[rel]["sha256"] != pins[rel]:
                _refuse(f"historical producer binding for {rel} pins "
                        f"{historical[rel]['sha256']}, but the frozen index "
                        f"pins {pins[rel]}")
            files[rel] = historical[rel]["sha256"]
            continue
        label = f"pinned mutation asset {rel}"
        actual = sha256_file(_pinned_repository_file(root, rel, label))
        if actual != pins[rel]:
            _refuse(f"{label} hashes to {actual}, but the frozen index pins "
                    f"{pins[rel]}")
        files[rel] = actual
    return {"schema": ASSET_PIN_SCHEMA, "repository_root": root,
            "n_files": len(files), "files": files,
            "historical_engine_sources": historical}


def validate_completed_audit_binding(audit_entry: dict, report: dict,
                                     manifest: dict,
                                     project_entry: dict) -> None:
    """Prove the attestation, the frozen index and the manifest are one world.

    WHAT THIS FUNCTION PROVES, exactly: document/manifest self-consistency.
    One population and one digest; one engine, engine version and parser
    identity; a bounded source set that is the one the MANIFEST defines and
    that really contains every mutant file; pristine and equal before/after
    source-set digests; no collateral change; and every mutant attempted,
    applied, parsed and restored.

    WHAT IT DOES NOT PROVE: that the real engine ran.  `operator_gate.mode`
    and `disposable_marker` are strings the document writes about itself, and
    a document is cheap to write.  The trust root for "the engine really
    materialised this population" is the REVIEWED FROZEN INDEX plus the
    two-party operator execution that flips an entry to `complete` (plan §4
    gates A1 and B3: a second party re-runs the audit and compares digests
    before the entry moves).  This function is the machine half of that
    arrangement and never a substitute for it.
    """
    if audit_entry.get("status") != "complete":
        _refuse("frozen index does not name a completed audit")
    report_keys = {
        "schema", "status", "manifest_digest", "engine", "engine_version",
        "parser", "n_mutants", "n_attempted", "n_applied",
        "n_parse_valid", "n_restored", "n_source_files", "bounded_roots",
        "source_set_sha256_before", "source_set_sha256_after",
        "failing_mutant_id", "failure_stage", "failure", "collateral",
        "operator_gate", "digest"}
    schema = report.get("schema") if isinstance(report, dict) else None
    if schema == AUDIT_SCHEMA:
        report_keys |= {"source_lstat_sha256_before",
                        "source_lstat_sha256_after"}
        # A parallel audit walks k byte-identical disposable trees instead of
        # one, and says so.  The block is ADDITIVE and present only when
        # k > 1, so every sequential attestation ever produced -- including
        # every archived DOCX one -- keeps the exact key set it was written
        # with, and a document cannot quietly acquire multi-root semantics.
        if isinstance(report, dict) and "parallel_audit" in report:
            report_keys |= {"parallel_audit"}
    elif schema != AUDIT_SCHEMA_V1:
        _refuse("materialisation audit schema is not a supported complete "
                "audit schema")
    _exact_keys(report, report_keys, "materialisation audit attestation")
    parallel = report.get("parallel_audit")
    if parallel is not None:
        _exact_keys(parallel, {"n_roots", "mutants_by_root"},
                    "parallel materialisation audit")
        n_roots = parallel["n_roots"]
        by_root = parallel["mutants_by_root"]
        if isinstance(n_roots, bool) or not isinstance(n_roots, int) \
                or n_roots < 2 or not isinstance(by_root, list) \
                or len(by_root) != n_roots \
                or any(isinstance(value, bool) or not isinstance(value, int)
                       or value < 0 for value in by_root) \
                or sum(by_root) != report.get("n_attempted"):
            _refuse("parallel materialisation audit does not account for "
                    "every audited tree")
    if report.get("digest") != audit_digest(report):
        _refuse("audit attestation digest does not recompute")
    _exact_keys(report["collateral"], {"added", "changed", "deleted"},
                "materialisation audit collateral")
    if any(report["collateral"][key] != []
           for key in ("added", "changed", "deleted")):
        _refuse("completed audit records collateral source changes")
    gate = report["operator_gate"]
    from ..bench.mutation_run import binding_for
    try:
        _engine_dir, bound_applier = binding_for(manifest["engine"])
    except Exception as exc:
        _refuse(f"cannot resolve attested mutation applier: {exc}")
    compiled_expected = bound_applier.entrypoint is not None
    gate_fields = {"mode", "disposable_marker", "engine_source_sha256",
                   "runtime_parser_identity", "runtime_parser_reported"}
    if compiled_expected:
        gate_fields.add("compiled_applier")
    _exact_keys(gate, gate_fields, "materialisation audit operator gate")
    compiled = gate.get("compiled_applier")
    compiled_valid = not compiled_expected
    # Archived /1 reports remain readable for their already frozen engines;
    # every newly produced /2 report, and every compiled Java report, carries
    # the stronger lstat witness.
    metadata_valid = schema == AUDIT_SCHEMA_V1
    if schema == AUDIT_SCHEMA:
        before_lstat = report["source_lstat_sha256_before"]
        after_lstat = report["source_lstat_sha256_after"]
        metadata_valid = (_is_sha256(before_lstat)
                          and before_lstat == after_lstat)
    if compiled_expected:
        if schema != AUDIT_SCHEMA:
            _refuse("compiled Java audit lacks v2 mode/uid/gid attestation")
        _exact_keys(compiled, {
            "schema", "source_sha256", "interpreter", "entrypoint",
            "classes_rel", "classes_sha256", "compiler_identity",
            "compiler_executable_sha256", "runtime_identity",
            "runtime_executable_sha256", "tools_jar_sha256",
            "analysis_recipe_digest",
        }, "compiled materialisation applier")
        sha_fields = ("source_sha256", "classes_sha256",
                      "compiler_executable_sha256",
                      "runtime_executable_sha256")
        compiled_valid = (
            compiled.get("schema") == "r2t.compiled-applier/2"
            and all(_is_sha256(compiled.get(key)) for key in sha_fields)
            and (compiled.get("tools_jar_sha256") is None
                 or _is_sha256(compiled.get("tools_jar_sha256")))
            and compiled.get("source_sha256")
            == gate.get("engine_source_sha256")
            and compiled.get("interpreter") == bound_applier.interpreter
            and compiled.get("entrypoint") == bound_applier.entrypoint
            and compiled.get("classes_rel")
            == bound_applier.classes_rel.replace(os.sep, "/")
            and isinstance(compiled.get("compiler_identity"), str))
        from ..toolkit import mutation_java as J
        authority = manifest.get("analysis_recipe", {})
        if authority.get("schema") == J.MODULE_ANALYSIS_SCHEMA:
            try:
                engine_toolchain = J.module_engine_toolchain(authority)
            except ValueError as exc:
                _refuse(f"compiled Java audit has invalid module authority: {exc}")
            compiled_valid = (compiled_valid
                              and compiled.get("compiler_identity")
                              == engine_toolchain["parser"].split(" [", 1)[0]
                              and compiled.get("runtime_identity")
                              == engine_toolchain["parser"]
                              and all(compiled.get(key) == engine_toolchain[key]
                                      for key in (
                                          "compiler_executable_sha256",
                                          "runtime_executable_sha256",
                                          "tools_jar_sha256")))
        else:
            compiled_valid = (compiled_valid
                              and manifest["parser"].startswith(
                                  compiled.get("compiler_identity", "") + " [")
                              and compiled.get("runtime_identity")
                              == manifest["parser"])
        compiled_valid = (compiled_valid
                          and compiled.get("analysis_recipe_digest")
                          == manifest.get("analysis_recipe", {}).get("digest"))
    expected_reported_parser = expected_runtime_parser(manifest)
    # THE JOIN TO THE WORLD (review correction 10).  Everything else in this
    # function compares the attestation with the index entry, i.e. two copies
    # of what the same operator wrote.  These two checks recompute the source
    # set from the POPULATION and refuse an attestation that is internally
    # tidy but describes a tree the manifest does not live in.
    expected_roots = _audit_roots(manifest)
    report_roots = _normalised_roots(report["bounded_roots"],
                                     "materialisation audit attestation")
    index_roots = _normalised_roots(audit_entry["bounded_roots"],
                                    "frozen index materialisation audit")
    if report_roots != expected_roots or index_roots != expected_roots:
        _refuse(
            "attested bounded source roots are not the roots this manifest "
            f"defines: manifest {expected_roots}, attestation {report_roots}, "
            f"frozen index {index_roots}. There is no widening override -- "
            "the audited source set is a function of the population")
    outside = _mutants_outside_roots(manifest, expected_roots)
    if outside:
        _refuse(
            f"{len(outside)} manifest mutant file(s) lie outside the attested "
            f"bounded source roots {expected_roots}: {outside[:3]}. A root is "
            "matched exactly or as a directory prefix, so 'src2' never "
            "satisfies 'src'")
    source_before = report["source_set_sha256_before"]
    source_after = report["source_set_sha256_after"]
    for key in ("n_mutants", "n_attempted", "n_applied", "n_parse_valid",
                "n_restored"):
        _nonnegative_int(report[key], f"materialisation audit {key}")
    _positive_int(report["n_source_files"],
                  "materialisation audit n_source_files")
    exact_counts = all(report[key] == manifest["n"] for key in (
        "n_mutants", "n_attempted", "n_applied", "n_parse_valid",
        "n_restored"))
    if report["digest"] != audit_entry["attestation_digest"] \
            or report["status"] != "complete" \
            or report["manifest_digest"] != manifest["digest"] \
            or report["engine"] != project_entry["engine"] \
            or report["engine_version"] != project_entry["engine_version"] \
            or report["parser"] != project_entry["parser"] \
            or not exact_counts \
            or report["n_source_files"] != audit_entry["n_source_files"] \
            or report["n_source_files"] <= 0 \
            or report["bounded_roots"] != audit_entry["bounded_roots"] \
            or not _is_sha256(source_before) \
            or not _is_sha256(source_after) \
            or source_before != source_after \
            or not metadata_valid \
            or source_before != audit_entry["source_set_sha256"] \
            or report["failing_mutant_id"] is not None \
            or report["failure_stage"] is not None \
            or report["failure"] is not None \
            or gate["mode"] != "real_engine" \
            or gate["disposable_marker"] != DISPOSABLE_MARKER \
            or gate["engine_source_sha256"] \
            != project_entry["engine_source"]["sha256"] \
            or gate["engine_source_sha256"] \
            != audit_entry["engine_source_sha256"] \
            or gate["runtime_parser_identity"] != manifest["parser"] \
            or gate["runtime_parser_identity"] \
            != audit_entry["runtime_parser_identity"] \
            or gate["runtime_parser_reported"] != expected_reported_parser \
            or not compiled_valid \
            or not metadata_valid:
        _refuse("completed audit does not bind a pristine full population")


def coverage_projection_identity(project: str, coverage_path: str,
                                 release_path: str, boundary_path: str) -> Optional[str]:
    """A Kapua census oracle preserves and rederives its full-release origin."""
    if project != "kapua":
        return None
    from ..java import kapua_gold_coverage as G
    path = G.projection_path(coverage_path)
    if not os.path.lexists(path):
        return None
    G.load_projection(coverage_path, release_path, boundary_path)
    return sha256_file(path)


def validate_index_binding(index: dict, project: str, *, raw_manifest: dict,
                           scored_manifest: dict, mapping: dict,
                           boundary_path: str, coverage_path: str,
                           release_path: str, engine_source_path: str,
                           historical_engine_source: Optional[dict] = None,
                           raw_manifest_path: Optional[str] = None,
                           audit_attestation: Optional[dict] = None,
                           require_release_ready: bool = False) -> dict:
    """Bind supplied bytes to one frozen project entry."""
    validate_asset_index(index)
    entry = index["projects"].get(project)
    if entry is None:
        _refuse(f"asset index has no project {project!r}")
    projection = coverage_projection_identity(project, coverage_path, release_path, boundary_path)
    if entry["coverage_oracle"].get("projection_sha256") != projection:
        _refuse("coverage projection receipt and frozen index binding differ; a projected oracle cannot downgrade to ordinary coverage")
    raw = validate_manifest(raw_manifest)
    scored = validate_manifest(scored_manifest, raw_manifest=raw_manifest)
    from ..core.boundary import load_boundary
    boundary_sha256 = sha256_file(boundary_path)
    if os.path.basename(boundary_path) \
            != os.path.basename(entry["boundary"]["config"]):
        _refuse(f"{project} boundary filename differs from frozen index")
    role = entry["scored_population"]["role"]
    boundary = load_boundary(boundary_path)
    if role == "boundary_scored":
        expected_scored = derive_boundary_scored_manifest(
            raw_manifest, boundary, boundary_path, boundary_sha256,
            sample=scored_manifest.get("sample"),
            seed=scored_manifest.get("seed"))
        if expected_scored != scored_manifest:
            _refuse(f"{project} scored population does not derive exactly "
                    "from the frozen boundary and raw catalogue")
        boundary_derivation = {
            "role": role,
            "n_raw": raw_manifest["n"],
            "n_scored": scored_manifest["n"],
            "n_non_production_excluded":
                scored_manifest["n_non_production_excluded"],
        }
    elif role == "raw_equals_scored":
        expected_scored = derive_raw_equals_scored_manifest(
            raw_manifest, boundary, boundary_path, boundary_sha256)
        if expected_scored != scored_manifest:
            _refuse(f"{project} raw-equals-scored bytes differ")
        boundary_derivation = {
            "role": role,
            "n_raw": raw_manifest["n"],
            "n_scored": scored_manifest["n"],
            "n_non_production_excluded": 0,
        }
    else:  # validate_asset_index has already made this unreachable.
        _refuse(f"{project} has an unsupported scored population role")
    release_ids = load_release_ids(release_path)
    coverage = coverage_from_rows(load_jsonl(coverage_path))
    map_facts = validate_map(mapping, scored_manifest, release_ids=release_ids,
                             coverage_by_item=coverage)
    coverage_sha256 = sha256_file(coverage_path)
    release_sha256 = sha256_file(release_path)
    if historical_engine_source is None:
        engine_source_sha256 = sha256_file(engine_source_path)
    else:
        if not isinstance(historical_engine_source, dict) \
                or set(historical_engine_source) != {
                    "commit", "path", "git_blob", "sha256"}:
            _refuse("historical engine source binding has invalid fields")
        logical_path = historical_engine_source["path"]
        known = legacy_engine_source_bindings().get(logical_path)
        checked = validate_legacy_engine_source_bindings().get(logical_path)
        if known is None or historical_engine_source != known \
                or checked != known:
            _refuse("historical engine source binding is not the reviewed "
                    "commit:path/blob identity")
        expected_path = os.path.join(REPOSITORY_ROOT, logical_path)
        if os.path.abspath(engine_source_path) != expected_path:
            _refuse("historical engine logical path differs from the saved "
                    "engine source path")
        engine_source_sha256 = known["sha256"]
    checks = {
        "engine": (scored["engine"], entry["engine"]),
        "engine_version": (scored["engine_version"], entry["engine_version"]),
        "parser": (scored["parser"], entry["parser"]),
        "raw n": (raw["n"], entry["raw_population"]["n"]),
        "raw digest": (raw["digest"],
                       entry["raw_population"]["manifest_digest"]),
        "raw canonical SHA-256": (
            raw["canonical_sha256"],
            entry["raw_population"]["canonical_sha256"]),
        "scored n": (scored["n"], entry["scored_population"]["n"]),
        "scored digest": (
            scored["digest"], entry["scored_population"]["manifest_digest"]),
        "scored canonical SHA-256": (
            scored["canonical_sha256"],
            entry["scored_population"]["canonical_sha256"]),
        "map digest": (map_facts["digest"],
                       entry["mutation_map"]["digest"]),
        "map canonical SHA-256": (
            map_facts["canonical_sha256"],
            entry["mutation_map"]["canonical_sha256"]),
        "map n_mutants": (
            map_facts["n_mutants"], entry["mutation_map"]["n_mutants"]),
        "map n_mapped": (
            map_facts["n_mapped"], entry["mutation_map"]["n_mapped"]),
        "map n_uncovered": (
            map_facts["n_uncovered"], entry["mutation_map"]["n_uncovered"]),
        "map n_pairs": (
            map_facts["n_pairs"], entry["mutation_map"]["n_pairs"]),
        "map coverage SHA-256": (
            mapping["coverage_sha256"], coverage_sha256),
        "map release SHA-256": (
            mapping["release_sha256"], release_sha256),
        "boundary SHA-256": (
            boundary_sha256, entry["boundary"]["sha256"]),
        "coverage SHA-256": (
            coverage_sha256, entry["coverage_oracle"]["sha256"]),
        "coverage rows": (
            len(coverage), entry["coverage_oracle"]["rows"]),
        "release SHA-256": (
            release_sha256, entry["release"]["sha256"]),
        "release items": (len(release_ids), entry["release"]["items"]),
        "engine source SHA-256": (
            engine_source_sha256, entry["engine_source"]["sha256"]),
    }
    preserved_sha = entry["raw_population"].get("preserved_file_sha256")
    if preserved_sha is not None:
        if raw_manifest_path is None:
            _refuse(f"{project} index binds preserved raw file bytes but no "
                    "raw_manifest_path was supplied")
        validate_preserved_file(raw_manifest_path, preserved_sha,
                                f"{project} preserved raw manifest")
    for label, (actual, expected) in checks.items():
        if actual != expected:
            _refuse(f"{project} {label} is {actual!r}, frozen index says "
                    f"{expected!r}")
    audit_entry = entry["materialisation_audit"]
    release_ready = audit_entry["status"] == "complete"
    if release_ready:
        if audit_attestation is None:
            _refuse(f"{project} index names a completed audit but its "
                    "attestation was not supplied")
        validate_completed_audit_binding(
            audit_entry, audit_attestation, raw_manifest, entry)
    elif audit_attestation is not None:
        _refuse(f"{project} supplied an audit attestation that the frozen "
                "index does not bind")
    if require_release_ready:
        require_index_release_ready(index, project)
    return {"project": project, "index_binding": "valid",
            "release_ready": release_ready,
            "release_blocker": (None if release_ready else
                                "completed full materialisation audit missing"),
            "boundary_derivation": boundary_derivation,
            "raw_manifest": raw, "scored_manifest": scored, "map": map_facts}


def _read_json_object(path: str, label: str) -> dict:
    if os.path.islink(path) or not os.path.isfile(path):
        _refuse(f"{label} must be a non-symlink regular file: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        _refuse(f"cannot read {label} at {path}: {exc}")
    if not isinstance(value, dict):
        _refuse(f"{label} is not a JSON object")
    return value


def _legacy_catalogue_overrides(report_path: str, report: dict) -> dict:
    """Resolve migrated inputs for an exact untouched legacy report."""
    catalogue = _read_json_object(
        LEGACY_CATALOGUE_PATH, "legacy consistency catalogue")
    absolute_report = os.path.abspath(report_path)
    for item in catalogue["cells"].values():
        reference = item.get("report")
        if reference is None:
            continue
        registered = os.path.abspath(os.path.join(
            REPOSITORY_ROOT, reference["path"]))
        if absolute_report != registered:
            continue
        validate_preserved_file(
            registered, reference["sha256"], "catalogued legacy report")
        refs = {
            "asset_index": catalogue["asset_index"],
            "boundary": catalogue["boundaries"][item["project"]],
        }
        release = (catalogue.get("releases") or {}).get(item["project"])
        if release is not None:
            refs["release"] = release
        for label, frozen in refs.items():
            if report["inputs"][label]["sha256"] != frozen["sha256"]:
                _refuse(f"catalogued {label} does not match the untouched "
                        "legacy report")
        return {label: os.path.join(REPOSITORY_ROOT, frozen["path"])
                for label, frozen in refs.items()}
    return {}


def _saved_report_paths(
        report: dict, report_path: str, *,
        input_paths: Optional[dict[str, str]] = None) -> tuple[str, dict]:
    base = report.get("path_base")
    _exact_keys(base, {"kind", "relative_to_report"},
                "saved report path_base")
    if base["kind"] != "repository_root" \
            or not isinstance(base["relative_to_report"], str) \
            or not base["relative_to_report"] \
            or os.path.isabs(base["relative_to_report"]):
        _refuse("saved report path_base is not a relative repository root")
    report_directory = os.path.dirname(os.path.abspath(report_path))
    repository_root = os.path.realpath(os.path.join(
        report_directory, base["relative_to_report"]))
    inputs = report.get("inputs")
    if not isinstance(inputs, dict):
        _refuse("saved validation report has no inputs object")
    if input_paths is not None:
        if (report.get("evidence") or {}).get("validation_class") != "native":
            _refuse("explicit saved-report input locations require native evidence")
        _exact_keys(input_paths, set(inputs), "relocated native report inputs")
    catalogue_overrides = (_legacy_catalogue_overrides(report_path, report)
                           if input_paths is None else {})
    resolved: dict[str, str] = {}
    for label, reference in inputs.items():
        _exact_keys(reference, {"path", "sha256"},
                    f"saved report input {label}")
        recorded = reference["path"]
        if not isinstance(recorded, str) or not recorded:
            _refuse(f"saved report input {label} has no path")
        if not _is_sha256(reference["sha256"]):
            _refuse(f"saved report input {label} has no SHA-256")
        if input_paths is not None:
            supplied = input_paths[label]
            if not isinstance(supplied, str) or not supplied:
                _refuse(f"relocated native report input {label} has no path")
            path = os.path.abspath(supplied)
        elif label in catalogue_overrides:
            path = catalogue_overrides[label]
        elif os.path.isabs(recorded):
            path = os.path.abspath(recorded)
        else:
            normal = os.path.normpath(recorded)
            if normal == ".." or normal.startswith(".." + os.sep):
                _refuse(f"saved report input {label} escapes repository root")
            path = os.path.abspath(os.path.join(repository_root, normal))
            real = os.path.realpath(path)
            try:
                inside = os.path.commonpath((repository_root, real)) \
                    == repository_root
            except ValueError:
                inside = False
            if not inside:
                _refuse(f"saved report input {label} resolves outside "
                        "repository root")
        historical = None
        if input_paths is None and label == "engine_source" \
                and not os.path.isabs(recorded):
            repository_rel = os.path.normpath(recorded).replace(os.sep, "/")
            historical = legacy_engine_source_bindings().get(repository_rel)
        if historical is not None \
                and historical["sha256"] == reference["sha256"]:
            checked = validate_legacy_engine_source_bindings(
                repository_root=repository_root)
            if checked.get(repository_rel) != historical:
                _refuse("saved report historical engine source did not "
                        "resolve to its recorded Git binding")
        else:
            validate_preserved_file(
                path, reference["sha256"], f"saved report input {label}")
        resolved[label] = path
    return repository_root, resolved


def validate_saved_validation_report(
        report_path: str, *, expected_validation_class: Optional[str] = None,
        require_release_ready: bool = False,
        input_paths: Optional[dict[str, str]] = None) -> dict:
    """Revalidate a saved validation report from the bytes it names.

    This is the reader boundary for cached-gold and legacy wrappers.  It does
    not trust summaries in the report: every input is resolved relative to the
    explicitly declared repository root (or kept as an absolute preserved
    evidence path), re-hashed, re-parsed, and fed through the same derivation
    and frozen-index validators as the producing CLI.

    A native report may instead name a complete set of relocated input
    locations through `input_paths`. Every label and original input digest
    is still required; nothing falls back to producer paths. This preserves
    the report bytes and the report SHA already recorded by observations.
    The caller owns the installed inventory; this reader owns the unchanged
    native derivation and release-ready audit checks.
    """
    if not isinstance(report_path, str) or not report_path:
        _refuse("a saved validation report path is required")
    if os.path.islink(report_path) or not os.path.isfile(report_path):
        _refuse("saved validation report itself must be a non-symlink "
                "regular file")
    report = _read_json_object(report_path, "saved validation report")
    _exact_keys(report, {
        "schema", "status", "path_base", "raw_manifest",
        "scored_manifest", "map", "legacy_raw_map", "evidence",
        "asset_index", "materialisation_audit", "inputs"},
        "saved validation report")
    if report["schema"] != "r2t.mutation-validation/1" \
            or report["status"] != "valid":
        _refuse("saved validation report is not a completed valid report")
    evidence_claim = report["evidence"]
    if not isinstance(evidence_claim, dict):
        _refuse("saved validation report evidence is not an object")
    validation_class = evidence_claim.get("validation_class")
    if validation_class not in ("native", "legacy_consistency"):
        _refuse("saved validation report has an unknown validation class")
    if expected_validation_class is not None \
            and validation_class != expected_validation_class:
        _refuse(f"saved validation class is {validation_class!r}, expected "
                f"{expected_validation_class!r}")
    index_claim = report["asset_index"]
    if not isinstance(index_claim, dict) \
            or index_claim.get("index_binding") != "valid" \
            or not isinstance(index_claim.get("project"), str):
        _refuse("saved report has no valid frozen asset-index binding")
    _repository_root, paths = _saved_report_paths(
        report, report_path, input_paths=input_paths)
    common_inputs = {
        "raw_manifest", "map", "coverage_run", "release", "asset_index",
        "boundary", "engine_source"}
    class_inputs = ({"candidate_run", "gold_baseline", "candidate_results",
                     "gold_results"}
                    if validation_class == "legacy_consistency" else set())
    # `audit_attestation` is optional for BOTH classes, and deliberately so
    # (review correction 9, finding 6).  Once an index entry's audit flips to
    # `complete`, `validate_index_binding` FORCES the producer to record the
    # attestation -- for a legacy report exactly as for a native one -- so
    # admitting it only for `native` made `require_release_ready=True`
    # unsatisfiable for every preserved legacy sweep the moment the assets
    # were frozen.  Admitting the key is not a promotion: the class stays
    # `legacy_consistency`, the evidence stays explicitly non-native, and the
    # audit block below binds the same document either way.
    optional_inputs = {"audit_attestation"}
    if validation_class == "legacy_consistency":
        optional_inputs.add("candidate_egress_attestation")
    if validation_class == "native":
        optional_inputs = optional_inputs | {"manifest"}
    missing = sorted((common_inputs | class_inputs) - set(paths))
    unknown = sorted(set(paths) - common_inputs - class_inputs
                     - optional_inputs)
    if missing or unknown:
        _refuse(f"saved validation inputs differ; missing={missing}, "
                f"unknown={unknown}")

    index = _read_json_object(paths["asset_index"], "saved asset index")
    validate_asset_index(index)
    project = index_claim["project"]
    entry = index["projects"].get(project)
    if entry is None:
        _refuse(f"saved report names unknown asset-index project {project!r}")

    raw_manifest = _read_json_object(
        paths["raw_manifest"], "saved raw manifest")
    raw_facts = validate_manifest(raw_manifest)
    from ..core.boundary import load_boundary
    boundary = load_boundary(paths["boundary"])
    boundary_sha256 = sha256_file(paths["boundary"])
    role = entry["scored_population"]["role"]
    if role == "boundary_scored":
        derived_scored = derive_boundary_scored_manifest(
            raw_manifest, boundary, paths["boundary"], boundary_sha256)
    elif role == "raw_equals_scored":
        derived_scored = derive_raw_equals_scored_manifest(
            raw_manifest, boundary, paths["boundary"], boundary_sha256)
    else:
        _refuse(f"saved report has unsupported scored role {role!r}")
    if validation_class == "native" and "manifest" in paths:
        scored_manifest = _read_json_object(
            paths["manifest"], "saved scored manifest")
        if scored_manifest != derived_scored:
            _refuse("saved scored manifest differs from boundary derivation")
    else:
        scored_manifest = derived_scored
    scored_facts = validate_manifest(
        scored_manifest, raw_manifest=(raw_manifest
                                       if raw_manifest["digest"]
                                       != scored_manifest["digest"] else None))
    release_ids = load_release_ids(paths["release"])
    coverage = coverage_from_rows(load_jsonl(paths["coverage_run"]))
    supplied_map = _read_json_object(paths["map"], "saved mutant map")

    if validation_class == "legacy_consistency":
        candidate_run_rows = load_jsonl(paths["candidate_run"])
        raw_map_facts = validate_map(
            supplied_map, raw_manifest, release_ids=release_ids,
            coverage_by_item=coverage, allow_legacy=True)
        by_mutant, uncovered = M.map_mutants_to_items(
            scored_manifest, coverage)
        strict_mapping = build_map_artifact(
            scored_manifest, by_mutant, uncovered,
            coverage_sha256=sha256_file(paths["coverage_run"]),
            release_sha256=sha256_file(paths["release"]))
        map_facts = validate_map(
            strict_mapping, scored_manifest, release_ids=release_ids,
            coverage_by_item=coverage)
        evidence = legacy_consistency(
            scored_manifest=scored_manifest, mapping=supplied_map,
            raw_manifest=(raw_manifest if raw_manifest["digest"]
                          != scored_manifest["digest"] else None),
            release_ids=release_ids,
            candidate_run_rows=candidate_run_rows,
            gold_baseline_rows=load_jsonl(paths["gold_baseline"]),
            candidate_result_rows=load_jsonl(paths["candidate_results"]),
            gold_result_rows=load_jsonl(paths["gold_results"]))
    else:
        strict_mapping = supplied_map
        raw_map_facts = None
        map_facts = validate_map(
            strict_mapping, scored_manifest, release_ids=release_ids,
            coverage_by_item=coverage)
        evidence = {"validation_class": "native"}

    # The published CoreShop+aider cell is the one preserved campaign whose
    # release review requires the strict post-hoc egress rerun.  Terminal
    # output is not evidence: require a content-addressed sidecar, re-hash it
    # through `_saved_report_paths`, and bind its clean result to these exact
    # candidate-run bytes and item denominator.  This is deliberately a
    # report-level requirement rather than a project asset claim -- the same
    # mutation population is shared by cell 2, but egress is a property of a
    # candidate run, not of its mutant catalogue.
    candidate_egress_facts = None
    if validation_class == "legacy_consistency":
        agent_systems = {row.get("agent_system")
                         for row in candidate_run_rows}
        needs_candidate_egress = (
            project == "coreshop" and agent_systems == {"aider"})
        has_candidate_egress = "candidate_egress_attestation" in paths
        if needs_candidate_egress and not has_candidate_egress:
            _refuse("CoreShop+aider legacy report omits its content-addressed "
                    "strict-egress attestation")
        if has_candidate_egress:
            from ..bench import egress_attestation as EA
            egress_document = _read_json_object(
                paths["candidate_egress_attestation"],
                "saved candidate egress attestation")
            candidate_egress_facts = EA.validate_attestation(egress_document)
            candidate_run_sha256 = report["inputs"]["candidate_run"][
                "sha256"]
            n_candidate_items = len({row.get("item_id")
                                     for row in candidate_run_rows})
            if candidate_egress_facts["candidate_run_sha256"] \
                    != candidate_run_sha256:
                _refuse("candidate egress attestation names another run")
            if candidate_egress_facts["n_items"] != n_candidate_items:
                _refuse("candidate egress attestation names another item "
                        "denominator")

    # THE INDEXED AUDIT STATE DECIDES, NOT THE VALIDATION CLASS.  When the
    # frozen entry says `complete` the attestation is REQUIRED; its bytes
    # were re-hashed against the report's own digest by
    # `_saved_report_paths`, and `validate_index_binding` below revalidates
    # its binding -- for `legacy_consistency` exactly as for `native`.  What
    # differs between the classes is the evidence document, which stays
    # explicitly non-native for legacy rows and is never promoted here.
    audit = report["materialisation_audit"]
    audit_entry = entry["materialisation_audit"]
    if audit_entry["status"] == "complete":
        if "audit_attestation" not in paths:
            _refuse(f"release-ready saved report omits its audit attestation "
                    f"({validation_class} class; the frozen index entry for "
                    f"{project!r} names a completed audit)")
        audit_document = _read_json_object(
            paths["audit_attestation"], "saved audit attestation")
        named_audit = audit_document.get("materialisation_audit",
                                         audit_document)
        if audit != named_audit:
            _refuse("saved report audit differs from its named attestation")
        audit_attestation = audit
    else:
        expected_not_run = {
            "status": "not_run",
            "reason": "operator-gated disposable workspace required",
            "expected_mutants": raw_manifest["n"],
        }
        if audit != expected_not_run:
            _refuse("provisional saved report claims an unbound audit")
        audit_attestation = None

    engine_reference = report["inputs"]["engine_source"]
    engine_logical_path = os.path.normpath(
        engine_reference["path"]).replace(os.sep, "/")
    # Explicit locations carry the actual preserved enumerator bytes, already
    # hashed against this report. The producer checkout's logical Git path is
    # provenance, not an installed location. The index below still requires
    # exactly the same engine-source digest.
    historical_engine_source = (legacy_engine_source_bindings().get(
        engine_logical_path) if input_paths is None else None)
    if historical_engine_source is not None \
            and historical_engine_source["sha256"] \
            != engine_reference["sha256"]:
        historical_engine_source = None
    index_facts = validate_index_binding(
        index, project, raw_manifest=raw_manifest,
        scored_manifest=scored_manifest, mapping=strict_mapping,
        boundary_path=paths["boundary"], coverage_path=paths["coverage_run"],
        release_path=paths["release"],
        engine_source_path=paths["engine_source"],
        historical_engine_source=historical_engine_source,
        raw_manifest_path=paths["raw_manifest"],
        audit_attestation=audit_attestation,
        require_release_ready=require_release_ready)
    claims = {
        "raw_manifest": (report["raw_manifest"], raw_facts),
        "scored_manifest": (report["scored_manifest"], scored_facts),
        "map": (report["map"], map_facts),
        "legacy_raw_map": (report["legacy_raw_map"], raw_map_facts),
        "evidence": (report["evidence"], evidence),
        "asset_index": (report["asset_index"], index_facts),
    }
    for label, (claimed, derived) in claims.items():
        if claimed != derived:
            _refuse(f"saved report {label} differs from re-derived evidence")
    return {
        "schema": report["schema"],
        "status": "valid",
        "validation_class": validation_class,
        "project": project,
        "index_binding": "valid",
        "release_ready": index_facts["release_ready"],
        "candidate_egress_attested": candidate_egress_facts is not None,
        "n_inputs_rehashed": len(paths),
    }


def load_validated_saved_report(
        report_path: str, *, expected_validation_class: Optional[str] = None,
        require_release_ready: bool = False,
        input_paths: Optional[dict[str, str]] = None) -> tuple[dict, dict, dict]:
    """Return validated facts, exact report, and resolved immutable inputs.

    Consumers such as cached-gold and legacy sidecar binding need the source
    paths only *after* the complete PR-2 derivation gate has passed.  Keeping
    that sequence here prevents each consumer from inventing a weaker path
    resolver or trusting the report's input claims before revalidation.
    """
    facts = validate_saved_validation_report(
        report_path, expected_validation_class=expected_validation_class,
        require_release_ready=require_release_ready, input_paths=input_paths)
    report = _read_json_object(report_path, "saved validation report")
    _repository_root, paths = _saved_report_paths(
        report, report_path, input_paths=input_paths)
    return facts, report, paths


def load_validated_legacy_scoring_inputs(
        report_path: str, *, require_release_ready: bool = True) -> dict:
    """Reconstruct the only inputs a preserved legacy sweep may score.

    Historical rows cannot carry a native campaign identity retroactively.
    Their saved PR-2 report therefore is not merely supporting evidence: it
    is the authority for the candidate run, gold baseline, result bytes,
    boundary-scored population and coverage-derived map.  Returning those
    exact revalidated objects in one operation prevents a consumer from
    checking the result-row hashes and then scoring a caller-supplied
    baseline, boundary or denominator.
    """
    facts, report, paths = load_validated_saved_report(
        report_path, expected_validation_class="legacy_consistency",
        require_release_ready=require_release_ready)
    raw_manifest = _read_json_object(
        paths["raw_manifest"], "saved legacy raw manifest")
    index = _read_json_object(paths["asset_index"], "saved asset index")
    entry = index["projects"][facts["project"]]
    from ..core.boundary import load_boundary
    boundary = load_boundary(paths["boundary"])
    role = entry["scored_population"]["role"]
    if role == "boundary_scored":
        scored_manifest = derive_boundary_scored_manifest(
            raw_manifest, boundary, paths["boundary"],
            sha256_file(paths["boundary"]))
    elif role == "raw_equals_scored":
        scored_manifest = derive_raw_equals_scored_manifest(
            raw_manifest, boundary, paths["boundary"],
            sha256_file(paths["boundary"]))
    else:  # validate_saved_validation_report made this unreachable.
        _refuse(f"saved legacy report has unsupported scored role {role!r}")

    coverage = coverage_from_rows(load_jsonl(paths["coverage_run"]))
    release_ids = load_release_ids(paths["release"])
    by_mutant, uncovered = M.map_mutants_to_items(scored_manifest, coverage)
    strict_mapping = build_map_artifact(
        scored_manifest, by_mutant, uncovered,
        coverage_sha256=sha256_file(paths["coverage_run"]),
        release_sha256=sha256_file(paths["release"]))
    validate_map(strict_mapping, scored_manifest, release_ids=release_ids,
                 coverage_by_item=coverage)

    candidate_run_rows = load_jsonl(paths["candidate_run"])
    passed_item_ids = set(_passed_files(candidate_run_rows))
    expected_pairs = legacy_scoring_pairs(
        strict_mapping, candidate_run_rows)

    # `load_validated_saved_report` has already replayed legacy_consistency
    # over these bytes and proved both historical result sets equal this
    # passed-item universe.  Load them only after that gate, and never accept
    # substitutes from the scoring CLI.
    return {
        "facts": facts,
        "report": report,
        "paths": paths,
        "boundary": boundary,
        "manifest": scored_manifest,
        "map": strict_mapping,
        "candidate_run_rows": candidate_run_rows,
        "gold_baseline_rows": load_jsonl(paths["gold_baseline"]),
        "candidate_result_rows": load_jsonl(paths["candidate_results"]),
        "gold_result_rows": load_jsonl(paths["gold_results"]),
        "passed_item_ids": passed_item_ids,
        "expected_pairs": expected_pairs,
    }


def validate_campaign_asset_inputs(
        report_path: str, *, manifest_path: str, map_path: str,
        release_path: str, require_release_ready: bool = True,
        paid_view_subset: bool = False,
        budgeted_sidecar: Optional[str] = None,
        input_paths: Optional[dict[str, str]] = None) -> dict:
    """Bind a new campaign's exact scored manifest/map/release to PR-2.

    A structurally valid manifest is not necessarily the frozen scored
    population (the historical CoreShop raw catalogue is structurally valid
    too).  New mutation execution therefore consumes a native saved report,
    not an in-memory filter or a bare digest copied from one.

    `budgeted_sidecar` says the map handed in is the DERIVED map of a
    budgeted population (HEADROOM_SUBSET_AND_BUDGETED_SAMPLE_SPEC.md section
    2), so the report's `inputs.map` pin names its PARENT.  The pin is not
    relaxed: it is verified against the report's own resolved map path, the
    parent's facts are compared to the report exactly as they are for every
    other campaign, and the derived map is then admitted only as the
    restriction its sidecar declares.  Off by default, and the default path
    is byte-unchanged.
    """
    facts, report, paths = load_validated_saved_report(
        report_path, expected_validation_class="native",
        require_release_ready=require_release_ready, input_paths=input_paths)
    manifest = _read_json_object(manifest_path, "campaign scored manifest")
    manifest_facts = validate_manifest(manifest)
    # In budgeted mode the map the CAMPAIGN runs is not the map the REPORT
    # pinned, so every existing check below keeps reading the pinned parent
    # -- resolved and re-hashed by the loader above, exactly as the Slice-3
    # paid view resolves its population document.
    parent_map_path = paths["map"] if budgeted_sidecar is not None \
        else map_path
    mapping = _read_json_object(parent_map_path, "campaign mutation map")
    release_ids = load_release_ids(release_path)
    if paid_view_subset:
        # The report's `release` pin names the POPULATION document the map
        # was built over, never the paid view handed in as `release_path`
        # (Slice-3: algorand 111 of 117).  The pin is NOT relaxed: the
        # validated saved report records that document's identity and path
        # (`inputs.release`), `load_validated_saved_report` re-hashed it at
        # load, and it is re-verified here at the moment of use, so a
        # missing or changed population document fails closed rather than
        # being skipped.
        population_path = paths["release"]
        population_sha256 = report["inputs"]["release"]["sha256"]
        validate_preserved_file(
            population_path, population_sha256,
            "campaign population release document")
        if sha256_file(release_path) == population_sha256:
            # The handed release IS the pinned population document -- the
            # complete-census case.  Subset mode then adds nothing: the
            # strict default semantics apply byte-unchanged, which is what
            # lets a scoring caller key this flag on bound-observation
            # evidence without moving any population-handing campaign's
            # answer.
            paid_view_subset = False
    if paid_view_subset:
        population_ids = load_release_ids(population_path)
        # The map's id universe is validated STRICTLY against the
        # population id set; the paid view then owes only the covered
        # direction (view <= covered), which the subset-mode call enforces.
        validate_map(mapping, manifest, release_ids=population_ids)
        if mapping.get("release_sha256") != population_sha256:
            _refuse("campaign map envelope does not name the population "
                    "release bytes the saved report pinned")
        map_facts = validate_map(mapping, manifest, release_ids=release_ids,
                                 paid_view_subset=True)
    else:
        map_facts = validate_map(mapping, manifest, release_ids=release_ids)

    index = _read_json_object(paths["asset_index"], "saved asset index")
    role = index["projects"][facts["project"]]["scored_population"]["role"]
    manifest_input = ("manifest" if "manifest" in report["inputs"]
                      else "raw_manifest")
    if role == "boundary_scored" and manifest_input != "manifest":
        _refuse("native boundary-scored campaign report does not name its "
                "scored manifest bytes")
    expected_files = {
        manifest_input: manifest_path,
        "map": parent_map_path,
        # In subset mode the pinned `release` bytes are the population
        # document resolved above; the paid view's own identity is owed to
        # (and enforced by) the Slice-3 seam, which requires `release_path`
        # to EQUAL the frozen item view.
        "release": population_path if paid_view_subset else release_path,
    }
    for key, supplied in expected_files.items():
        wanted = report["inputs"][key]["sha256"]
        validate_preserved_file(
            supplied, wanted, f"campaign {key} input")
    if report["scored_manifest"] != manifest_facts \
            or report["map"] != map_facts:
        _refuse("campaign manifest/map facts differ from the fully validated "
                "saved report")
    assets = {
        "validation_class": facts["validation_class"],
        "validation_sha256": sha256_file(report_path),
        "asset_index_sha256": report["inputs"]["asset_index"]["sha256"],
        "asset_project": facts["project"],
        "n_non_production_excluded": report["scored_manifest"][
            "n_non_production_excluded"],
        "manifest": manifest,
        "map": mapping,
        "release_items": len(release_ids),
    }
    if budgeted_sidecar is None:
        return assets
    from . import subsets
    try:
        budgeted = subsets.admit_budgeted_derived_map(
            budgeted_sidecar, parent_map_path, map_path, manifest,
            release_ids=release_ids)
    except subsets.SubsetRefused as exc:
        raise MutationAssetRefused(str(exc)) from exc
    # The sidecar's `parent_map_digest` is not compared to `report["map"]`
    # separately: `verify_budgeted_sample` compares it to the parent
    # document, `validate_map` recomputes that document's digest, and
    # `report["map"] == map_facts` above pins the recomputation -- so the two
    # comparisons are the same one, and a third would be a guard justified
    # only by the guard before it.
    sidecar = budgeted["sidecar"]
    # The campaign runs the derived map, so that is the map every caller is
    # handed; what says it is a budget rather than the population is the
    # basis and the sidecar's own bytes, which travel into the identity.
    assets["map"] = budgeted["derived_map"]
    assets["population_basis"] = subsets.BUDGETED_BASIS
    assets["budgeted_sample_sha256"] = sha256_file(budgeted_sidecar)
    assets["parent_map_sha256"] = sidecar["parent_map_sha256"]
    return assets

def selftest() -> int:
    import ast
    import contextlib
    import inspect
    import io
    import tempfile
    from ..core.boundary import Boundary

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    def refused(fn, contains="REFUSED"):
        try:
            fn()
        except (MutationAssetRefused, ValueError) as exc:
            return contains in str(exc)
        return False

    def population_v2_fixture(project):
        """Synthetic full-size rows exercise the fixed approved arithmetic."""
        target = _POPULATION_V2_TARGETS[project]
        suffix = "php" if project == "coreshop" else "py"

        def row(index, operator, family):
            line = index + 1
            return {
                "file": f"src/fixture/{family}.{suffix}",
                "operator": operator,
                "start_line": line,
                "start_col": 1,
                "end_line": line,
                "end_col": 2,
                "original": f"{family}-before-{index}",
                "mutated": f"{family}-after-{index}",
            }

        v1_rows = [
            row(index,
                _POPULATION_V2_V1_OPERATORS[
                    index % len(_POPULATION_V2_V1_OPERATORS)],
                "v1")
            for index in range(target["v1_n"])
        ]
        archived = M.build_manifest(
            v1_rows, parser_version=f"{project}-fixture-parser",
            operators=_POPULATION_V2_V1_OPERATORS, exclusions=(),
            engine=target["engine"], engine_version="1.0")
        # The frozen python-docx v1 object is both raw and scored and records
        # that zero-row boundary fact; CoreShop's raw 10,463-row object does
        # not borrow the distinct 10,205-row scored representation.
        if project == "python-docx":
            archived["n_non_production_excluded"] = 0
            archived["digest"] = M.manifest_digest(archived)
        replay = json.loads(json.dumps(archived))
        v2_rows = [
            {key: value for key, value in mutant.items() if key != "id"}
            for mutant in archived["mutants"]
        ]
        next_index = target["v1_n"]
        for operator, count in target["additions"].items():
            v2_rows.extend(
                row(next_index + offset, operator, operator)
                for offset in range(count))
            next_index += count
        v2 = M.build_manifest(
            v2_rows, parser_version=archived["parser"],
            operators=_POPULATION_V2_OPERATORS, exclusions=(),
            engine=target["engine"], engine_version=archived["engine_version"],
            enumerator_rev=f"{project}/fixture-current")
        if project == "python-docx":
            v2["n_non_production_excluded"] = 0
            v2["digest"] = M.manifest_digest(v2)
        return archived, replay, v2

    def reidentify(manifest, mutant):
        mutant["id"] = M.mutant_id(
            mutant["file"], mutant["operator"], mutant["start_line"],
            mutant["start_col"], mutant["original"], mutant["mutated"],
            engine=manifest["engine"],
            engine_version=manifest["engine_version"])
        manifest["digest"] = M.manifest_digest(manifest)

    docx_v1, docx_replay, docx_v2 = population_v2_fixture("python-docx")
    docx_v2_facts = _validate_population_v2_catalogue(
        "python-docx", archived_v1=docx_v1,
        v1_replay=docx_replay, v2_catalogue=docx_v2,
        expected_enumerator_rev="python-docx/fixture-current")
    check("PV2 fixture accepts the complete python-docx 2,225 -> 2,942 "
          "catalogue join",
          docx_v2_facts["v1_n"] == 2225
          and docx_v2_facts["v2_n"] == 2942
          and docx_v2_facts["addition_counts"] == {
              "LogicalConnector": 54,
              "RemoveNegation": 37,
              "ConstantReplacement": 626,
          })

    core_v1, core_replay, core_v2 = population_v2_fixture("coreshop")
    core_v2_facts = _validate_population_v2_catalogue(
        "coreshop", archived_v1=core_v1,
        v1_replay=core_replay, v2_catalogue=core_v2,
        expected_enumerator_rev="coreshop/fixture-current")
    check("PV2 fixture accepts the complete CoreShop raw 10,463 -> 15,886 "
          "catalogue join",
          core_v2_facts["v1_n"] == 10463
          and core_v2_facts["v2_n"] == 15886
          and core_v2_facts["addition_counts"] == {
              "LogicalConnector": 549,
              "RemoveNegation": 1224,
              "ConstantReplacement": 3650,
          })

    changed_replay = json.loads(json.dumps(docx_replay))
    changed_replay["mutants"][0]["original"] += "-drift"
    changed_replay["mutants"][0]["mutated"] += "-drift"
    reidentify(changed_replay, changed_replay["mutants"][0])
    check("PV2 mutation probe kills a self-consistent explicit-v1 replay "
          "descriptor drift",
          refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=changed_replay, v2_catalogue=docx_v2,
              expected_enumerator_rev="python-docx/fixture-current"),
                  "v1 replay differs"))

    lost_optional = json.loads(json.dumps(docx_v2))
    inherited_row = next(
        row for row in lost_optional["mutants"]
        if row["operator"] in _POPULATION_V2_V1_OPERATORS)
    original_id = inherited_row["id"]
    inherited_row.pop("end_col")
    lost_optional["digest"] = M.manifest_digest(lost_optional)
    check("PV2 mutation probe kills inherited optional-metadata loss even "
          "when the mutant id is unchanged",
          inherited_row["id"] == original_id
          and refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=docx_replay, v2_catalogue=lost_optional,
              expected_enumerator_rev="python-docx/fixture-current"),
                      "inherited-v1 projection differs"))

    substituted = json.loads(json.dumps(docx_v2))
    inherited_row = next(
        row for row in substituted["mutants"]
        if row["operator"] in _POPULATION_V2_V1_OPERATORS)
    inherited_row["original"] += "-substituted"
    inherited_row["mutated"] += "-substituted"
    reidentify(substituted, inherited_row)
    check("PV2 mutation probe kills a same-count inherited-v1 substitution",
          refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=docx_replay, v2_catalogue=substituted,
              expected_enumerator_rev="python-docx/fixture-current"),
                  "inherited-v1 projection differs"))

    reordered = json.loads(json.dumps(docx_v2))
    reordered["operators"][-2:] = reversed(reordered["operators"][-2:])
    reordered["digest"] = M.manifest_digest(reordered)
    check("PV2 mutation probe kills a reordered eleven-operator profile",
          refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=docx_replay, v2_catalogue=reordered,
              expected_enumerator_rev="python-docx/fixture-current"),
                  "ordered eleven-operator"))

    changed_scope = json.loads(json.dumps(docx_v2))
    changed_scope["parser"] = "other-fixture-parser"
    changed_scope["n_excluded"] = 1
    changed_scope["digest"] = M.manifest_digest(changed_scope)
    check("PV2 mutation probe kills inherited parser and scope-fact drift",
          refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=docx_replay, v2_catalogue=changed_scope,
              expected_enumerator_rev="python-docx/fixture-current"),
                  "identity/scope facts"))

    redistributed = json.loads(json.dumps(docx_v2))
    new_row = next(row for row in redistributed["mutants"]
                   if row["operator"] == "LogicalConnector")
    new_row["operator"] = "RemoveNegation"
    reidentify(redistributed, new_row)
    check("PV2 mutation probe kills equal-total redistribution between new "
          "operator families",
          redistributed["n"] == docx_v2["n"]
          and refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=docx_replay, v2_catalogue=redistributed,
              expected_enumerator_rev="python-docx/fixture-current"),
                      "addition counts"))

    nonzero_invalid = json.loads(json.dumps(docx_v2))
    nonzero_invalid["n_invalid"] = 1
    nonzero_invalid["digest"] = M.manifest_digest(nonzero_invalid)
    explicit_zero_invalid = json.loads(json.dumps(docx_v2))
    explicit_zero_invalid["n_invalid"] = 0
    explicit_zero_invalid["digest"] = M.manifest_digest(
        explicit_zero_invalid)
    check("PV2 mutation probes kill nonzero and explicit-zero invalid-count "
          "encodings",
          refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=docx_replay, v2_catalogue=nonzero_invalid,
              expected_enumerator_rev="python-docx/fixture-current"),
                  "zero invalid")
          and refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=docx_replay, v2_catalogue=explicit_zero_invalid,
              expected_enumerator_rev="python-docx/fixture-current"),
                      "omitted"))

    sampled = json.loads(json.dumps(docx_v2))
    sampled["sample"] = sampled["n"]
    sampled["seed"] = 17
    sampled["digest"] = M.manifest_digest(sampled)
    check("PV2 mutation probe kills a full-count manifest labelled sampled",
          refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=docx_replay, v2_catalogue=sampled,
              expected_enumerator_rev="python-docx/fixture-current"),
                  "not sampled"))

    missing_revision = json.loads(json.dumps(docx_v2))
    missing_revision.pop("enumerator_rev")
    missing_revision["digest"] = M.manifest_digest(missing_revision)
    check("PV2 mutation probes kill missing and stale enumerator revisions",
          refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=docx_replay, v2_catalogue=missing_revision,
              expected_enumerator_rev="python-docx/fixture-current"),
                  "expected current")
          and refused(lambda: _validate_population_v2_catalogue(
              "python-docx", archived_v1=docx_v1,
              v1_replay=docx_replay, v2_catalogue=docx_v2,
              expected_enumerator_rev="python-docx/other-revision"),
                      "expected current"))

    core_scored = M.build_manifest(
        [{key: value for key, value in mutant.items() if key != "id"}
         for mutant in core_v1["mutants"][:10205]],
        parser_version=core_v1["parser"],
        operators=_POPULATION_V2_V1_OPERATORS, exclusions=(),
        engine=core_v1["engine"],
        engine_version=core_v1["engine_version"])
    core_scored.update({
        "population_role": "boundary_scored",
        "n_non_production_excluded": 258,
        "raw_manifest_digest": core_v1["digest"],
        "boundary_policy": {
            "classification": "production",
            "config": "boundary_fixture.yml",
            "sha256": "a" * 64,
        },
    })
    core_scored["digest"] = M.manifest_digest(core_scored)
    check("PV2 mutation probe kills CoreShop scored 10,205 as the inherited "
          "base; the contract requires raw 10,463",
          core_scored["n"] == 10205
          and refused(lambda: _validate_population_v2_catalogue(
              "coreshop", archived_v1=core_scored,
              v1_replay=core_scored, v2_catalogue=core_v2,
              expected_enumerator_rev="coreshop/fixture-current"),
                      "not a raw pre-boundary"))

    public_parameters = inspect.signature(
        validate_population_v2_catalogue).parameters
    check("PV2 public acceptance resolves archive, targets and revision "
          "internally rather than accepting a synthetic authority",
          set(public_parameters) == {"project", "v1_replay", "v2_catalogue"}
          and all(name not in public_parameters for name in (
              "archived_v1", "expected_enumerator_rev", "targets")))

    substituted_archive = json.loads(json.dumps(docx_v1))
    substituted_archive["mutants"][0]["original"] += "-second-read"
    substituted_archive["mutants"][0]["mutated"] += "-second-read"
    reidentify(substituted_archive, substituted_archive["mutants"][0])
    authenticated_archive = validate_manifest(docx_v1)
    original_archive_validator = validate_archived_v1_manifests
    original_archive_reader = _read_json_object
    original_pin_reader = pinned_enumerator_identity
    pin_reads = []

    def record_pin_read(relative_path):
        pin_reads.append(relative_path)
        return {"enumerator_rev": "python-docx/fixture-current",
                "sha256": "a" * 64}

    try:
        globals()["validate_archived_v1_manifests"] = lambda: {
            "python-docx": {
                "canonical_sha256": authenticated_archive[
                    "canonical_sha256"],
                "manifest_digest": authenticated_archive["digest"],
                "n": authenticated_archive["n"],
            },
        }
        globals()["_read_json_object"] = \
            lambda _path, _label: substituted_archive
        globals()["pinned_enumerator_identity"] = record_pin_read
        reread_refused = refused(
            lambda: validate_population_v2_catalogue(
                "python-docx", v1_replay=docx_replay,
                v2_catalogue=docx_v2),
            "changed between authentication and consumption")
    finally:
        globals()["validate_archived_v1_manifests"] = \
            original_archive_validator
        globals()["_read_json_object"] = original_archive_reader
        globals()["pinned_enumerator_identity"] = original_pin_reader
    check("PV2 public-wrapper mutation probe kills a self-consistent, "
          "count-matching archive substituted on the consumed re-read",
          substituted_archive["n"] == authenticated_archive["n"]
          and substituted_archive["digest"] != authenticated_archive["digest"]
          and reread_refused and not pin_reads)

    raw_records = [
        {"file": "src/app.py", "operator": "ArithmeticOperator",
         "start_line": 1, "start_col": 3, "original": "+", "mutated": "-"},
        {"file": "tests/helper.py", "operator": "TrueValue",
         "start_line": 1, "start_col": 1, "original": "True",
         "mutated": "False"},
    ]
    raw = M.build_manifest(raw_records, parser_version="fixture-parser",
                           exclusions=())
    boundary = Boundary(version=1, project="fixture", repo_root=".",
                        retained=[("tests/", "test support")])
    scored = derive_boundary_scored_manifest(
        raw, boundary, "boundary_fixture.yml", "a" * 64)
    check("raw identity is preserved while scoring corrects n",
          raw["n"] == 2 and scored["n"] == 1
          and scored["raw_manifest_digest"] == raw["digest"]
          and scored["n_non_production_excluded"] == 1)
    check("scored digest covers the explicit boundary policy",
          scored["digest"] == M.manifest_digest(scored)
          and scored["boundary_policy"]["sha256"] == "a" * 64)
    revised_raw = M.build_manifest(
        raw_records, parser_version="fixture-parser", exclusions=(),
        n_invalid=3, enumerator_rev="fixture/m1")
    revised_facts = validate_manifest(revised_raw)
    check("optional validity provenance validates and is returned as facts",
          revised_facts["n_invalid"] == 3
          and revised_facts["enumerator_rev"] == "fixture/m1")
    zero_invalid = json.loads(json.dumps(raw))
    zero_invalid["n_invalid"] = 0
    zero_invalid["digest"] = M.manifest_digest(zero_invalid)
    check("zero n_invalid has one canonical encoding: omission",
          refused(lambda: validate_manifest(zero_invalid), "omitted"))
    production_raw = M.build_manifest(
        raw_records[:1], parser_version="fixture-parser", exclusions=())
    check("raw-equals-scored classifies every row and proves zero exclusions",
          derive_raw_equals_scored_manifest(
              production_raw, boundary, "boundary_fixture.yml", "a" * 64)
          == production_raw)
    check("raw-equals-scored refuses even one boundary exclusion",
          refused(lambda: derive_raw_equals_scored_manifest(
              raw, boundary, "boundary_fixture.yml", "a" * 64),
                  "excluded non-production"))

    # -- the second reason a row leaves the scored role: the project's own
    #    declaration, INSIDE its production roots (owner ruling 2026-09-11).
    #    The boundary below classifies EVERY fixture row production, so only
    #    the declaration can move this population -- which is the Sylius
    #    case that made `mutants validate` refuse the mint by name.
    declared_records = [
        {"file": "src/app/Model/Order.php", "operator": "ArithmeticOperator",
         "start_line": 1, "start_col": 3, "original": "+", "mutated": "-"},
        {"file": "src/app/Resources/config/services.php",
         "operator": "TrueValue", "start_line": 2, "start_col": 1,
         "original": "$x", "mutated": "true"},
        {"file": "src/app/tests/OrderTest.php",
         "operator": "ArithmeticOperator", "start_line": 1, "start_col": 3,
         "original": "+", "mutated": "-"},
    ]
    declared_raw = M.build_manifest(declared_records,
                                    parser_version="fixture-parser",
                                    exclusions=("!src/app",))
    declaring = Boundary(
        version=1, project="fixture", repo_root=".",
        raw={"behat": {"prod_paths": ["src/app"],
                       "mutation_exclude": ["tests/", "Resources/config/"]}})
    silent = Boundary(version=1, project="fixture", repo_root=".",
                      raw={"behat": {"prod_paths": ["src/app"]}})
    declared_scored = derive_boundary_scored_manifest(
        declared_raw, declaring, "boundary_fixture.yml", "b" * 64)
    silent_scored = derive_boundary_scored_manifest(
        declared_raw, silent, "boundary_fixture.yml", "b" * 64)
    check("the boundary classifies every fixture row production, so the same "
          "population without the row loses nothing -- which is exactly the "
          "state the Sylius mint refused",
          all(declaring.classify(record["file"]) == "production"
              for record in declared_records)
          and silent_scored["n"] == declared_raw["n"] == 3
          and silent_scored["n_non_production_excluded"] == 0
          and "n_mutation_excluded" not in silent_scored)
    check("the RAW catalogue keeps every declared row while the scored "
          "population drops them",
          sorted(M.normalise_path(mutant["file"])
                 for mutant in declared_raw["mutants"])
          == ["src/app/Model/Order.php",
              "src/app/Resources/config/services.php",
              "src/app/tests/OrderTest.php"]
          and [mutant["file"] for mutant in declared_scored["mutants"]]
          == ["src/app/Model/Order.php"]
          and declared_scored["raw_manifest_digest"] == declared_raw["digest"])
    check("...and the count and the fragments are recorded where the digest "
          "covers them, with the arithmetic every consumer re-checks intact",
          declared_scored["n"] == 1
          and declared_scored["n_mutation_excluded"] == 2
          and declared_scored["n_non_production_excluded"] == 2
          and declared_raw["n"] == (
              declared_scored["n"]
              + declared_scored["n_non_production_excluded"])
          and declared_scored["exclusions"][-1] == (
              "declared non-product under the production roots by "
              "boundary_fixture.yml: tests/, Resources/config/")
          and declared_scored["digest"] == M.manifest_digest(declared_scored),
          str(declared_scored["exclusions"]))
    only_product = M.build_manifest(declared_records[:1],
                                    parser_version="fixture-parser",
                                    exclusions=("!src/app",))
    check("the policy is part of the identity even where it matched nothing: "
          "a population scored under a row that names fragments is not the "
          "one scored under no row at all",
          derive_boundary_scored_manifest(
              only_product, declaring, "boundary_fixture.yml",
              "b" * 64)["digest"]
          != derive_boundary_scored_manifest(
              only_product, silent, "boundary_fixture.yml",
              "b" * 64)["digest"])
    check("raw-equals-scored refuses a declared row too -- one boundary may "
          "not define two different populations",
          refused(lambda: derive_raw_equals_scored_manifest(
              declared_raw, declaring, "boundary_fixture.yml", "b" * 64),
                  "`mutation_exclude` row"))
    over_counted = json.loads(json.dumps(declared_scored))
    over_counted["n_mutation_excluded"] = 3
    over_counted["digest"] = M.manifest_digest(over_counted)
    check("a sub-count larger than the rows the scored role excluded is "
          "refused: it is part of that total, not a second exclusion",
          refused(lambda: validate_manifest(over_counted), "exceeds"))
    stray_declared = json.loads(json.dumps(declared_raw))
    stray_declared["n_mutation_excluded"] = 1
    stray_declared["digest"] = M.manifest_digest(stray_declared)
    check("...and a RAW manifest may not carry it at all",
          refused(lambda: validate_manifest(stray_declared),
                  "only a boundary-scored manifest"))
    check("the sub-count is re-exported in the validated facts, which is "
          "where `mutants validate` reports it -- a population re-derived "
          "from a preserved raw catalogue never runs the build verb that "
          "prints it -- and is absent from the facts of a manifest without "
          "it",
          validate_manifest(declared_scored).get("n_mutation_excluded") == 2
          and "n_mutation_excluded" not in validate_manifest(silent_scored)
          and "n_mutation_excluded" not in validate_manifest(declared_raw),
          str(sorted(validate_manifest(declared_scored))))
    zero_declared = json.loads(json.dumps(declared_scored))
    zero_declared["n_mutation_excluded"] = 0
    zero_declared["digest"] = M.manifest_digest(zero_declared)
    check("...and zero has one encoding here too, as it has for n_invalid: "
          "omission",
          refused(lambda: validate_manifest(zero_declared),
                  "must be positive"))
    parser_fixture = json.loads(json.dumps(raw))
    parser_fixture["parser"] = "nikic/php-parser v5.7.0@deadbeef"
    parser_fixture["digest"] = M.manifest_digest(parser_fixture)
    check("runtime PHP parser identity is derived from locked manifest identity",
          expected_runtime_parser(parser_fixture) == "v5.7.0")

    try:
        pinned_php_identity = pinned_enumerator_identity(
            "r2t/php/mutate.php")
        pinned_php_rev = pinned_php_identity["enumerator_rev"]
    except MutationAssetRefused as exc:
        pinned_php_identity = {}
        pinned_php_rev = f"refused: {exc}"
    try:
        with open(os.path.join(BENCHMARK_ROOT, "r2t", "php", "mutate.php"),
                  encoding="utf-8") as fh:
            php_rev_match = re.search(
                r"const ENUMERATOR_REV = '([^']+)';", fh.read())
        emitted_php_rev = (php_rev_match.group(1)
                           if php_rev_match is not None else None)
    except OSError as exc:
        emitted_php_rev = f"unreadable: {exc}"
    check("the PHP producer bytes and revision cannot drift from the single "
          "current enumerator pin",
          emitted_php_rev == pinned_php_rev,
          f"producer={emitted_php_rev!r}, pin={pinned_php_rev!r}")

    bad_count = json.loads(json.dumps(scored))
    bad_count["n"] += 1
    bad_count["digest"] = M.manifest_digest(bad_count)
    check("a re-digested false manifest count is refused",
          refused(lambda: validate_manifest(bad_count), "says n="))
    bad_digest = json.loads(json.dumps(scored))
    bad_digest["parser"] = "tampered"
    check("a manifest tamper is refused by its digest",
          refused(lambda: validate_manifest(bad_digest), "digest"))
    stale = json.loads(json.dumps(scored))
    stale["digest"] = FORBIDDEN_STALE_MANIFEST_DIGEST
    check("the known stale count/population digest is explicitly refused",
          refused(lambda: validate_manifest(stale), "known inconsistent"))
    bad_id = json.loads(json.dumps(scored))
    bad_id["mutants"][0]["id"] = "0" * 16
    bad_id["digest"] = M.manifest_digest(bad_id)
    check("a re-digested forged mutant id is refused",
          refused(lambda: validate_manifest(bad_id), "recomputed"))
    extra_manifest_field = json.loads(json.dumps(scored))
    extra_manifest_field["future_policy"] = "silently ignored"
    extra_manifest_field["digest"] = M.manifest_digest(extra_manifest_field)
    check("unknown manifest policy cannot hide inside a valid digest",
          refused(lambda: validate_manifest(extra_manifest_field),
                  "unknown fields"))
    false_sample = json.loads(json.dumps(scored))
    false_sample["sample"] = false_sample["n"] + 1
    false_sample["seed"] = 7
    false_sample["digest"] = M.manifest_digest(false_sample)
    check("sample metadata must reconcile with the carried population",
          refused(lambda: validate_manifest(false_sample),
                  "sample/seed/count"))
    escaping_path = json.loads(json.dumps(production_raw))
    escaping_path["mutants"][0]["file"] = "../src/app.py"
    mutant = escaping_path["mutants"][0]
    mutant["id"] = M.mutant_id(
        mutant["file"], mutant["operator"], mutant["start_line"],
        mutant["start_col"], mutant["original"], mutant["mutated"],
        engine=escaping_path["engine"],
        engine_version=escaping_path["engine_version"])
    escaping_path["digest"] = M.manifest_digest(escaping_path)
    check("a re-digested manifest cannot address outside the repository",
          refused(lambda: validate_manifest(escaping_path),
                  "repository-relative"))

    with tempfile.TemporaryDirectory() as envelope_dir:
        envelope_path = os.path.join(envelope_dir, "raw.json")
        envelope = {
            "engine": raw["engine"],
            "engine_version": raw["engine_version"],
            "parser": "fixture-runtime",
            "files": 2,
            "errors": {},
            "mutants": raw_records,
        }
        with open(envelope_path, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh)
        envelope_sha = sha256_file(envelope_path)
        check("canonical construction retains a clean enumerator witness",
              len(load_enumerator_envelope(
                  envelope_path, expected_engine=raw["engine"],
                  expected_engine_version=raw["engine_version"],
                  expected_parser_version="fixture-runtime")["mutants"]) == 2)
        check("requesting an enumerator revision refuses an envelope that "
              "omits it",
              refused(lambda: load_enumerator_envelope(
                  envelope_path, expected_engine=raw["engine"],
                  expected_engine_version=raw["engine_version"],
                  expected_enumerator_rev="fixture/m1"), "expected"))
        typo_envelope = dict(envelope, enumerator_revv="fixture/m1")
        with open(envelope_path, "w", encoding="utf-8") as fh:
            json.dump(typo_envelope, fh)
        check("an unknown enumerator envelope field cannot be ignored",
              refused(lambda: load_enumerator_envelope(
                  envelope_path, expected_engine=raw["engine"],
                  expected_engine_version=raw["engine_version"]),
                  "unknown"))
        missing_envelope = dict(envelope)
        del missing_envelope["parser"]
        with open(envelope_path, "w", encoding="utf-8") as fh:
            json.dump(missing_envelope, fh)
        check("every required enumerator envelope field must be present",
              refused(lambda: load_enumerator_envelope(
                  envelope_path, expected_engine=raw["engine"],
                  expected_engine_version=raw["engine_version"]),
                  "missing"))
        envelope["n_invalid"] = 2
        envelope["enumerator_rev"] = "fixture/m1"
        with open(envelope_path, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh)
        loaded_envelope = load_enumerator_envelope(
            envelope_path, expected_engine=raw["engine"],
            expected_engine_version=raw["engine_version"],
            expected_enumerator_rev="fixture/m1")
        check("enumerator validity metadata is retained after validation",
              loaded_envelope["n_invalid"] == 2
              and loaded_envelope["enumerator_rev"] == "fixture/m1")
        check("a requested enumerator revision must match exactly",
              refused(lambda: load_enumerator_envelope(
                  envelope_path, expected_engine=raw["engine"],
                  expected_engine_version=raw["engine_version"],
                  expected_enumerator_rev="fixture/m2"), "expected"))
        bad_envelope = dict(envelope, n_invalid=0)
        with open(envelope_path, "w", encoding="utf-8") as fh:
            json.dump(bad_envelope, fh)
        check("an envelope must omit a zero invalid count",
              refused(lambda: load_enumerator_envelope(
                  envelope_path, expected_engine=raw["engine"],
                  expected_engine_version=raw["engine_version"]),
                  "omitted"))
        with open(envelope_path, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh)
        envelope_sha = sha256_file(envelope_path)
        check("preserved raw file bytes are checked, not only parsed content",
              validate_preserved_file(envelope_path, envelope_sha)
              == envelope_sha)
        with open(envelope_path, "a", encoding="utf-8") as fh:
            fh.write(" ")
        check("serialization-only raw file tampering is refused",
              refused(lambda: validate_preserved_file(
                  envelope_path, envelope_sha), "SHA-256"))
        envelope["errors"] = {"src/broken.py": "parse failed"}
        with open(envelope_path, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh)
        check("an enumerator error cannot silently shrink the population",
              refused(lambda: load_enumerator_envelope(
                  envelope_path, expected_engine=raw["engine"],
                  expected_engine_version=raw["engine_version"]),
                  "failed files"))

    mutant_id = scored["mutants"][0]["id"]
    by_mutant = {mutant_id: ["item-1"]}
    mapping = build_map_artifact(
        scored, by_mutant, [], coverage_sha256="b" * 64,
        release_sha256="c" * 64)
    coverage = {"item-1": {"src/app.py": [1]}}
    check("a bound map validates partition and coverage join",
          validate_map(mapping, scored, release_ids={"item-1"},
                       coverage_by_item=coverage)["n_pairs"] == 1)
    wrong_count = json.loads(json.dumps(mapping))
    wrong_count["n_pairs"] = 2
    wrong_count["digest"] = map_digest(wrong_count)
    check("a re-digested false map count is refused",
          refused(lambda: validate_map(wrong_count, scored), "recomputed"))
    wrong_member = json.loads(json.dumps(mapping))
    wrong_member["by_mutant"][mutant_id] = ["item-2"]
    wrong_member["digest"] = map_digest(wrong_member)
    check("a re-digested membership tamper is refused by coverage",
          refused(lambda: validate_map(
              wrong_member, scored, release_ids={"item-1", "item-2"},
              coverage_by_item=coverage), "does not rederive"))
    unknown_release = json.loads(json.dumps(mapping))
    unknown_release["by_mutant"][mutant_id] = ["missing-item"]
    unknown_release["digest"] = map_digest(unknown_release)
    check("an unknown release item is refused",
          refused(lambda: validate_map(
              unknown_release, scored, release_ids={"item-1"}),
                  "unknown release"))
    # Under C5 a paid view is a step-definition census of the release the
    # map was built over (algorand: 111 of 117), so `mapped <= release` is
    # a fact about the complete-census era rather than a rule.  What must
    # survive is the other direction: everything scored is covered.
    paid_view = json.loads(json.dumps(mapping))
    paid_view["by_mutant"][mutant_id] = ["item-1", "item-2"]
    paid_view["n_pairs"] = 2
    paid_view["digest"] = map_digest(paid_view)
    check("a paid view that is a strict subset of the mapped population is "
          "admitted in subset mode -- the Slice-3 seam hands `--release` "
          "the frozen view, not the population the map was built over",
          validate_map(paid_view, scored, release_ids={"item-1"},
                       paid_view_subset=True)["n_pairs"] == 2)
    check("...and the same map and view are refused in the default mode, "
          "so the flag is load-bearing rather than decorative",
          refused(lambda: validate_map(
              paid_view, scored, release_ids={"item-1"}),
                  "unknown release"))
    check("...and the complete population is admitted in both modes, so no "
          "existing caller's answer moves",
          validate_map(paid_view, scored,
                       release_ids={"item-1", "item-2"})["n_pairs"] == 2
          and validate_map(paid_view, scored,
                           release_ids={"item-1", "item-2"},
                           paid_view_subset=True)["n_pairs"] == 2)
    check("the direction that survives: a paid view naming an item no "
          "mutant covers is refused even in subset mode, and the refusal "
          "names the offending id -- a scheduled pair on an uncovered item "
          "would make the denominator a fiction",
          refused(lambda: validate_map(
              paid_view, scored, release_ids={"item-1", "item-9"},
              paid_view_subset=True), "item-9"))
    check("a map validated with no release at all is unchanged by either "
          "mode",
          validate_map(paid_view, scored)["n_pairs"] == 2
          and validate_map(paid_view, scored,
                           paid_view_subset=True)["n_pairs"] == 2)
    overlapping = json.loads(json.dumps(mapping))
    overlapping["uncovered"] = [mutant_id]
    overlapping["n_uncovered"] = 1
    overlapping["digest"] = map_digest(overlapping)
    check("mapped/uncovered overlap is refused",
          refused(lambda: validate_map(overlapping, scored), "overlap"))
    extra_map_field = json.loads(json.dumps(mapping))
    extra_map_field["unreviewed"] = True
    extra_map_field["digest"] = map_digest(extra_map_field)
    check("unknown map envelope fields are refused even when re-digested",
          refused(lambda: validate_map(extra_map_field, scored), "unknown"))

    legacy_map = {"by_mutant": by_mutant, "uncovered": []}
    candidate_run = [{"item_id": "item-1", "outcome": "passed",
                      "produced_files": [{"file_path": "steps.py",
                                          "code": "assert value"}]}]
    mixed_candidate_run = candidate_run + [
        {"item_id": "item-failed", "outcome": "failed",
         "produced_files": []}]
    check("legacy scoring reconstructs pairs only for candidate PASSES",
          legacy_scoring_pairs(
              {"by_mutant": {mutant_id: ["item-1", "item-failed"]}},
              mixed_candidate_run) == {("item-1", mutant_id)})
    gold_run = [{"item_id": "item-1", "outcome": "passed",
                 "produced_files": [{"file_path": "steps.py",
                                     "code": "assert reference"}]}]

    def result_row(files):
        mutant = scored["mutants"][0]
        # Shape of preserved Slice 1 rows: the locator trio, not the column or
        # source replacement bytes. Their absence remains a report limitation.
        return {"mutant_id": mutant["id"], "item_id": "item-1",
                "file": mutant["file"], "operator": mutant["operator"],
                "start_line": mutant["start_line"],
                "outcome": "failed", "engine": scored["engine"],
                "engine_version": scored["engine_version"],
                "manifest_digest": None,
                "candidate_digest": solution_digest(files)}

    candidate_files = _passed_files(candidate_run)
    gold_files = _gold_files(gold_run, {"item-1"})
    candidate_results = [result_row(candidate_files)]
    gold_results = [result_row(gold_files)]
    report = legacy_consistency(
        scored_manifest=scored, mapping=legacy_map,
        candidate_run_rows=candidate_run, gold_baseline_rows=gold_run,
        candidate_result_rows=candidate_results,
        gold_result_rows=gold_results)
    check("legacy evidence stays explicitly non-native",
          report["validation_class"] == "legacy_consistency"
          and report["native_provenance"] is False
          and report["historical_manifest_digest_present"] is False)
    check("real-shaped legacy rows report absent descriptors, not backfills",
          report["candidate"]["absent_descriptor_fields"]
          == ["mutated", "original", "start_col"])
    tampered_run = json.loads(json.dumps(candidate_run))
    tampered_run[0]["produced_files"][0]["code"] = "changed bytes"
    check("candidate byte tampering is refused",
          refused(lambda: legacy_consistency(
              scored_manifest=scored, mapping=legacy_map,
              candidate_run_rows=tampered_run, gold_baseline_rows=gold_run,
              candidate_result_rows=candidate_results,
              gold_result_rows=gold_results), "candidate bytes digest"))
    check("a missing historical pair is refused",
          refused(lambda: legacy_consistency(
              scored_manifest=scored, mapping=legacy_map,
              candidate_run_rows=candidate_run, gold_baseline_rows=gold_run,
              candidate_result_rows=[], gold_result_rows=gold_results),
                  "pair set differs"))
    check("a duplicate historical pair is refused",
          refused(lambda: legacy_consistency(
              scored_manifest=scored, mapping=legacy_map,
              candidate_run_rows=candidate_run, gold_baseline_rows=gold_run,
              candidate_result_rows=candidate_results + candidate_results,
              gold_result_rows=gold_results), "duplicate"))

    here = BENCHMARK_ROOT
    index_path = os.path.join(here, "release", "slice1_mutation_assets.json")
    with open(index_path, encoding="utf-8") as fh:
        index = json.load(fh)
    check("the frozen Slice 1 mutation index validates",
          validate_asset_index(index)["projects"]
          == ["coreshop", "python-docx"])
    try:
        archived_v1 = validate_archived_v1_manifests(index=index)
    except (MutationAssetRefused, OSError, json.JSONDecodeError) as exc:
        archived_v1 = str(exc)
    check("M1: both LFS-backed v1 manifests match their preserved SHA, "
          "canonical SHA, manifest digest/count and exact id rebuild",
          isinstance(archived_v1, dict)
          and set(archived_v1) == {"coreshop", "python-docx"}
          and all(facts["n"] == facts["n_ids_rebuilt"]
                  for facts in archived_v1.values()), str(archived_v1))
    core = index["projects"]["coreshop"]
    check("frozen CoreShop identity keeps raw 10,463 separate from scored 10,205",
          core["raw_population"]["n"] == 10463
          and core["scored_population"]["n"] == 10205
          and core["scored_population"]["raw_manifest_digest"]
          == core["raw_population"]["manifest_digest"]
          and core["scored_population"]["manifest_digest"]
          != FORBIDDEN_STALE_MANIFEST_DIGEST)
    check("release gate accepts the completed, audit-bound CoreShop index",
          require_index_release_ready(index, "coreshop") is None)
    provisional_index = json.loads(json.dumps(index))
    provisional_audit = provisional_index["projects"]["coreshop"][
        "materialisation_audit"]
    provisional_audit["status"] = "provisional"
    provisional_audit["attestation_digest"] = None
    provisional_audit["release_blocker"] = "fixture audit still pending"
    check("release gate still refuses a structurally valid provisional copy",
          refused(lambda: require_index_release_ready(
              provisional_index, "coreshop"), "provisional"))
    stale_index = json.loads(json.dumps(index))
    stale_index["projects"]["coreshop"]["raw_population"][
        "manifest_digest"] = FORBIDDEN_STALE_MANIFEST_DIGEST
    check("the stale CoreShop digest is forbidden anywhere in the index",
          refused(lambda: validate_asset_index(stale_index),
                  "forbidden stale"))
    bad_role_index = json.loads(json.dumps(index))
    bad_role_index["projects"]["coreshop"]["scored_population"]["role"] = \
        "raw_equals_scored"
    check("population role and derivation identities must agree",
          refused(lambda: validate_asset_index(bad_role_index),
                  "identities differ"))
    bad_map_count_index = json.loads(json.dumps(index))
    bad_map_count_index["projects"]["coreshop"]["mutation_map"][
        "n_uncovered"] -= 1
    check("indexed map counts must partition the scored population",
          refused(lambda: validate_asset_index(bad_map_count_index),
                  "do not partition"))
    bad_map_input_index = json.loads(json.dumps(index))
    bad_map_input_index["projects"]["coreshop"]["mutation_map"][
        "coverage_sha256"] = "e" * 64
    check("indexed map envelope must name indexed coverage bytes",
          refused(lambda: validate_asset_index(bad_map_input_index),
                  "other coverage/release"))
    bad_release_count_index = json.loads(json.dumps(index))
    bad_release_count_index["projects"]["coreshop"]["release"]["items"] = 99
    check("indexed coverage and release counts must agree",
          refused(lambda: validate_asset_index(bad_release_count_index),
                  "counts differ"))
    nested_extra_index = json.loads(json.dumps(index))
    nested_extra_index["projects"]["coreshop"]["boundary"]["surprise"] = True
    check("unknown nested index fields are fail-closed",
          refused(lambda: validate_asset_index(nested_extra_index),
                  "unknown"))
    legacy_catalogue_path = LEGACY_CATALOGUE_PATH
    with open(legacy_catalogue_path, encoding="utf-8") as fh:
        legacy_catalogue = json.load(fh)
    repository_root = REPOSITORY_ROOT
    legacy_index_path = os.path.join(
        repository_root, legacy_catalogue["asset_index"]["path"])
    catalogue_reports_valid = True
    catalogue_egress_valid = True
    for cell, item in legacy_catalogue["cells"].items():
        expected_catalogue_status = (
            "legacy_consistency_valid_superseded"
            if cell.endswith("_superseded")
            else "legacy_consistency_valid")
        report_ref = item.get("report")
        if report_ref is None:
            catalogue_reports_valid = False
            continue
        report_path = os.path.join(repository_root, report_ref["path"])
        if sha256_file(report_path) != report_ref["sha256"]:
            catalogue_reports_valid = False
            continue
        with open(report_path, encoding="utf-8") as fh:
            archived = json.load(fh)
        try:
            paths = _legacy_catalogue_overrides(report_path, archived)
            validate_preserved_file(
                paths["asset_index"],
                archived["inputs"]["asset_index"]["sha256"],
                "catalogued legacy asset index")
            validate_preserved_file(
                paths["boundary"],
                archived["inputs"]["boundary"]["sha256"],
                "catalogued legacy boundary")
            release_path = paths.get("release") or os.path.join(
                repository_root, archived["inputs"]["release"]["path"])
            validate_preserved_file(
                release_path, archived["inputs"]["release"]["sha256"],
                "catalogued legacy release")
        except (MutationAssetRefused, OSError, ValueError, KeyError):
            catalogue_reports_valid = False
            continue
        expected_boundary = os.path.join(
            repository_root,
            legacy_catalogue["boundaries"][item["project"]]["path"])
        egress_ref = item.get("egress_attestation")
        if cell == "cell1":
            try:
                from ..bench import egress_attestation as EA
                _exact_keys(egress_ref, {
                    "path", "sha256", "attestation_sha256", "status"},
                    "cell1 egress catalogue reference")
                egress_path = os.path.join(repository_root,
                                           egress_ref["path"])
                with open(egress_path, encoding="utf-8") as fh:
                    egress_document = json.load(fh)
                egress_facts = EA.validate_attestation(egress_document)
                catalogue_egress_valid = (
                    catalogue_egress_valid
                    and egress_ref["status"] == "clean"
                    and sha256_file(egress_path) == egress_ref["sha256"]
                    and egress_facts["attestation_sha256"]
                        == egress_ref["attestation_sha256"]
                    and egress_facts["candidate_run_sha256"]
                        == archived.get("inputs", {}).get(
                            "candidate_run", {}).get("sha256")
                    and archived.get("inputs", {}).get(
                        "candidate_egress_attestation", {}).get("sha256")
                        == egress_ref["sha256"])
            except (MutationAssetRefused, OSError, ValueError, TypeError,
                    EA.EgressAttestationRefused, AttributeError):
                catalogue_egress_valid = False
        elif egress_ref is not None:
            catalogue_egress_valid = False
        catalogue_reports_valid = (
            catalogue_reports_valid
            and archived.get("status") == "valid"
            and archived.get("evidence", {}).get("validation_class")
                == "legacy_consistency"
            and archived.get("evidence", {}).get("native_provenance") is False
            and item.get("status") == expected_catalogue_status
            and item.get("validation_class") == "legacy_consistency"
            and item.get("native_provenance") is False
            and archived.get("asset_index", {}).get("index_binding")
                == "valid"
            and archived.get("asset_index", {}).get("project")
                == item.get("project")
            and archived.get("inputs", {}).get("asset_index", {}).get(
                "sha256") == legacy_catalogue["asset_index"]["sha256"]
            and os.path.abspath(paths["asset_index"])
                == os.path.abspath(legacy_index_path)
            and os.path.abspath(paths["boundary"])
                == os.path.abspath(expected_boundary))
    check("all durable legacy reports resolve their frozen in-repository "
          "inputs and bind their bytes and non-native class",
          catalogue_reports_valid
          and catalogue_egress_valid
          and sha256_file(legacy_index_path)
          == legacy_catalogue["asset_index"]["sha256"])

    # A real release re-mint must not rewrite the registered report or make
    # its old release digest start referring to the annotated current file.
    with tempfile.TemporaryDirectory() as temporary:
        from unittest.mock import patch

        def fixture_json(name, value):
            path = os.path.join(temporary, name)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(value, fh)
                fh.write("\n")
            return path

        current = fixture_json("current.jsonl", {"item_id": "i"})
        frozen = fixture_json("frozen.jsonl", {"item_id": "i"})
        fixture_inputs = {
            label: {"path": os.path.basename(fixture_json(label + ".json", {}))}
            for label in ("asset_index", "boundary")}
        for ref in fixture_inputs.values():
            ref["sha256"] = sha256_file(os.path.join(temporary, ref["path"]))
        fixture_inputs["release"] = {"path": "current.jsonl",
                                     "sha256": sha256_file(frozen)}
        fixture_report = {"path_base": {"kind": "repository_root",
                                         "relative_to_report": "."},
                          "inputs": fixture_inputs}
        fixture_report_path = fixture_json("report.json", fixture_report)
        catalogue = {
            "asset_index": fixture_inputs["asset_index"],
            "boundaries": {"python-docx": fixture_inputs["boundary"]},
            "releases": {"python-docx": {"path": "frozen.jsonl",
                                         "sha256": sha256_file(frozen)}},
            "cells": {"cell": {"project": "python-docx", "report": {
                "path": "report.json", "sha256": sha256_file(fixture_report_path)}}}}
        fixture_catalogue = fixture_json("catalogue.json", catalogue)
        fixture_json("current.jsonl", {"item_id": "i", "target_interfaces": {
            "behaviour": [], "setup": []}})
        with patch(__name__ + ".REPOSITORY_ROOT", temporary), \
                patch(__name__ + ".LEGACY_CATALOGUE_PATH", fixture_catalogue):
            _root, resolved = _saved_report_paths(fixture_report, fixture_report_path)
            check("saved historical reports use the preserved input after current tasks are reminted",
                  resolved["release"] == frozen
                  and sha256_file(current) != sha256_file(frozen)
                  and sha256_file(fixture_report_path)
                  == catalogue["cells"]["cell"]["report"]["sha256"])
            copied_report = fixture_json("unregistered.json", fixture_report)
            check("the release relocation applies only to the exact registered report",
                  _legacy_catalogue_overrides(copied_report, fixture_report) == {}
                  and refused(lambda: _saved_report_paths(fixture_report, copied_report),
                              "saved report input release"))
            catalogue["releases"]["python-docx"]["sha256"] = "0" * 64
            fixture_json("catalogue.json", catalogue)
            check("a catalogue cannot replace the report's recorded release identity",
                  refused(lambda: _saved_report_paths(fixture_report, fixture_report_path),
                          "catalogued release does not match"))
            catalogue["releases"]["python-docx"]["sha256"] = fixture_inputs["release"]["sha256"]
            fixture_json("catalogue.json", catalogue)
            fixture_json("frozen.jsonl", {"item_id": "changed"})
            check("changed preserved release bytes still refuse",
                  refused(lambda: _saved_report_paths(fixture_report, fixture_report_path),
                          "saved report input release"))

    # ------------------------------------------------------------- MA1/MA2
    # The four in-repository files the frozen index pins by sha256, re-derived
    # from the bytes on disk.  Before this, nothing CI could reach recomputed
    # them (review finding 18, correction 20).
    # A RED PIN GATE MUST BE A COUNTED FAILURE, NOT AN ESCAPING TRACEBACK.
    # `validate_asset_pins` refuses by raising, which is right for a gate and
    # wrong for a selftest: a genuinely tampered asset file would kill this
    # module mid-run, skipping every later check and the ALL PASS/FAILURES
    # ledger line that tells a reader what else was verified.  Every call
    # below therefore goes through one of these two shims.
    def pins(repository_root=None):
        """The `files` mapping, or the refusal text, never an exception."""
        try:
            return validate_asset_pins(
                repository_root=repository_root,
                git_repository_root=(REPOSITORY_ROOT
                                     if repository_root else None))["files"]
        except MutationAssetRefused as exc:
            return str(exc)

    def indexed_pins(source=None):
        try:
            return asset_pin_expectations(source)
        except MutationAssetRefused as exc:
            return str(exc)

    # The v1 producers are pinned as Git blobs in HISTORY, so the gate needs
    # the pinned commit; a single-commit mirror of this repository does not
    # have it, and everything else here still runs there.
    historical_bindings = legacy_engine_source_bindings()
    pinned_commit = next(iter(historical_bindings.values()))["commit"]
    if subprocess.run(["git", "-C", REPOSITORY_ROOT, "cat-file", "-e",
                       pinned_commit + "^{commit}"], stdin=subprocess.DEVNULL,
                      capture_output=True).returncode != 0:
        print(f"  [SKIP] MA1/MA2: the frozen index pins the v1 producers as "
              f"Git blobs at commit {pinned_commit[:12]}, which is not in "
              f"this repository (a single-commit mirror)")
    else:
        pin_files = pins()
        check("MA1: live boundaries and historical engine Git blobs all rehash "
              "to the frozen index pins",
              isinstance(pin_files, dict)
              and sorted(pin_files) == [
                  "benchmark/config/boundary_coreshop.yml",
                  "benchmark/config/boundary_python_docx.yml",
                  "benchmark/r2t/php/mutate.php",
                  "benchmark/r2t/py/mutate.py"],
              str(pin_files))
        frozen_pins = indexed_pins(index)
        check("MA1: the pins are the frozen index's own boundary and "
              "historical engine-source digests, resolved through `binding_for`",
              isinstance(frozen_pins, dict)
              and frozen_pins == pin_files
              and frozen_pins.get("benchmark/r2t/php/mutate.php")
              == index["projects"]["coreshop"]["engine_source"]["sha256"]
              and frozen_pins.get("benchmark/r2t/py/mutate.py")
              == index["projects"]["python-docx"]["engine_source"]["sha256"],
              str(frozen_pins))
        check("MA1: each v1 producer SHA is bound to an exact commit:path/blob",
              isinstance(frozen_pins, dict)
              and set(historical_bindings) == {
                  "benchmark/r2t/php/mutate.php",
                  "benchmark/r2t/py/mutate.py"}
              and all(item["sha256"] == frozen_pins.get(rel)
                      for rel, item in historical_bindings.items()),
              str(historical_bindings))
        replace_guard_ok = False
        replace_guard_detail = "git unavailable"
        git = shutil.which("git")
        if git is not None:
            with tempfile.TemporaryDirectory() as replace_repo:
                try:
                    def fixture_git(*args, env=None):
                        return subprocess.run(
                            [git, "-C", replace_repo, *args],
                            capture_output=True, text=True, timeout=30,
                            check=True, env=env).stdout.strip()

                    fixture_git("init", "-q")
                    fixture_git("config", "user.name", "r2t selftest")
                    fixture_git("config", "user.email", "r2t@example.invalid")
                    with open(os.path.join(replace_repo, "producer"), "w",
                              encoding="utf-8") as fh:
                        fh.write("reviewed producer\n")
                    fixture_git("add", "producer")
                    fixture_git("-c", "commit.gpgSign=false", "commit", "-q",
                                "-m", "reviewed")
                    reviewed = fixture_git("rev-parse", "HEAD")
                    reviewed_blob = fixture_git(
                        "rev-parse", f"{reviewed}:producer")
                    with open(os.path.join(replace_repo, "producer"), "w",
                              encoding="utf-8") as fh:
                        fh.write("replacement producer\n")
                    fixture_git("add", "producer")
                    fixture_git("-c", "commit.gpgSign=false", "commit", "-q",
                                "-m", "replacement")
                    replacement = fixture_git("rev-parse", "HEAD")
                    replacement_blob = fixture_git(
                        "rev-parse", f"{replacement}:producer")
                    fixture_git("replace", reviewed, replacement)
                    replace_aware_env = dict(os.environ)
                    replace_aware_env.pop("GIT_NO_REPLACE_OBJECTS", None)
                    replaced_lookup = fixture_git(
                        "rev-parse", f"{reviewed}:producer",
                        env=replace_aware_env)
                    guarded_lookup = fixture_git(
                        "rev-parse", f"{reviewed}:producer",
                        env=_offline_git_env())
                    replace_guard_ok = (
                        reviewed_blob != replacement_blob
                        and replaced_lookup == replacement_blob
                        and guarded_lookup == reviewed_blob)
                    replace_guard_detail = json.dumps({
                        "reviewed_blob": reviewed_blob,
                        "replacement_blob": replacement_blob,
                        "replace_aware_lookup": replaced_lookup,
                        "guarded_lookup": guarded_lookup,
                    }, sort_keys=True)
                except (OSError, subprocess.SubprocessError) as exc:
                    replace_guard_detail = str(exc)
        check("MA1: exact historical commit:path lookup ignores mutable local "
              "Git replacement refs", replace_guard_ok, replace_guard_detail)
        with tempfile.TemporaryDirectory() as no_git:
            check("MA1: an unavailable historical Git object fails loudly, names "
                  "the clone shape, and never triggers a network fetch",
                  refused(lambda: validate_legacy_engine_source_bindings(
                      repository_root=no_git), "needs a full clone"))
        unknown_engine_index = json.loads(json.dumps(index))
        unknown_engine_index["projects"]["coreshop"]["engine"] = "r2t-mutate-xyz"
        check("MA2: an engine the harness cannot materialise refuses instead of "
              "leaving its source unpinned",
              refused(lambda: asset_pin_expectations(unknown_engine_index),
                      "resolves to no applier"))
        if not isinstance(frozen_pins, dict) or not isinstance(pin_files, dict):
            # Both guards matter.  The battery's controls compare a mirror's
            # verdict with the repository's, and two IDENTICAL REFUSALS compare
            # equal -- so on an already-red repository it would pass as a
            # tautology.  Report it unrun instead of claiming the coverage.
            already_red = (frozen_pins if not isinstance(frozen_pins, dict)
                           else pin_files)
            check("MA2: the pinned-asset tamper battery ran", False,
                  f"NOT RUN: the pin gate is already red, so its mirror controls "
                  f"would compare two refusals -- {already_red}")
        else:
            with tempfile.TemporaryDirectory() as mirror:
                for rel in sorted(frozen_pins):
                    target = os.path.join(mirror, rel)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    shutil.copyfile(os.path.join(REPOSITORY_ROOT, rel), target)
                check("MA2: a byte-identical boundary mirror plus the recorded "
                      "producer blobs passes the same gate",
                      pins(mirror) == pin_files)
                live_rels = sorted(set(frozen_pins) - set(historical_bindings))
                for rel in live_rels:
                    target = os.path.join(mirror, rel)
                    with open(target, "rb") as fh:
                        original_bytes = fh.read()
                    with open(target, "ab") as fh:
                        fh.write(b"\n")
                    tampered = "the frozen index pins" in str(pins(mirror))
                    with open(target, "wb") as fh:
                        fh.write(original_bytes)
                    check(f"MA2: one appended byte in {rel} fails the pin gate, "
                          "and restoring the bytes clears it",
                          tampered and pins(mirror) == pin_files)
                victim = live_rels[0]
                victim_path = os.path.join(mirror, victim)
                os.unlink(victim_path)
                check("MA2: a missing pinned file refuses",
                      "missing from the repository" in str(pins(mirror)))
                os.symlink(os.path.join(REPOSITORY_ROOT, victim), victim_path)
                check("MA2: a symlink to the right bytes still refuses -- a pin "
                      "on a link pins whatever the link is repointed at",
                      "is a symlink" in str(pins(mirror)))
                os.unlink(victim_path)
                shutil.copyfile(os.path.join(REPOSITORY_ROOT, victim),
                                victim_path)
                check("MA2: paths that escape the repository root refuse before "
                      "any byte is read",
                      refused(lambda: _pinned_repository_file(
                          mirror, "../outside.yml", "probe"), "escapes")
                      and refused(lambda: _pinned_repository_file(
                          mirror, os.path.join(REPOSITORY_ROOT, victim), "probe"),
                          "repository-relative")
                      and pins(mirror) == pin_files)
        from . import versions as V
        frozen = V.component("mutation_assets")
        check("MA2: `VERSIONS.yml` freezes the same four files by content, so a "
              "tamper is red at the focused gate AND at the aggregate one",
              frozen.get("frozen_by_content") is True
              and {os.path.relpath(os.path.join(V.BENCH_ROOT, rel),
                                   REPOSITORY_ROOT): digest
                   for rel, digest in (frozen.get("files") or {}).items()}
              == frozen_pins,
              str(frozen.get("files")))
    print("\n" + ("ALL PASS (mutation_attestation)" if ok
                    else "FAILURES (mutation_attestation)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
