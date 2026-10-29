"""Fetch and validate the versioned per-project scoring bundles.

The reader half: what a consumer needs to fetch a published bundle,
verify it against the dataset manifest and read the roles it installs.
`toolkit/bundle_build.py` builds the bundles this validates.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
from typing import Callable, Optional

from ..core.paths import DATA_ROOT_ENV, data_root
from .release import LEGACY_EVIDENCE_ROLES


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)
DATASET_MANIFEST = os.path.join(BENCHMARK, "release",
                                "dataset_manifest.json")
ASSET_INDEX = os.path.join(BENCHMARK, "release",
                           "slice1_mutation_assets.json")
DEFAULT_GITHUB_REPOSITORY = "code-philia/req2test-bench"
GITHUB_REPOSITORY_ENV = "R2T_GITHUB_REPOSITORY"
GITHUB_TOKEN_ENV = "R2T_GITHUB_TOKEN"

# ------------------------------------------------ the published eval100-std arm
#
# Roadmap D5.  The rc.4 asset ships the Cell 2 OpenHands arm.  The arm v1
# PUBLISHES is the eval100 standard arm, whose rendered table is byte-pinned
# at `release/v1/legacy_table_eval100_std.md`; until an asset ships that arm's
# bytes, `REPRODUCTION_STANDARD.md`'s Tier 1b promise cannot be kept, because
# a consumer holds the pinned table and nothing it was rendered from.
#
# What "that arm's bytes" means is not decided here.  It is decided by the
# shipping list the fourth (consent) run of the D4/J3 ceremony wrote --
# `consumed_inputs_manifest.json`, whose file set was enumerated by an
# `addaudithook("open")` trace over `results()` + `render()` rather than
# inferred -- and the dataset manifest pins that list by digest.  Every role
# below is joined to a digest the LIST records, or to one the ceremony's own
# validated legacy-consistency report records.  Nothing here mints a digest
# of its own, and no recorded input may go undispositioned (`_std_arm_plan`).
#
# TWO THINGS THIS DELIBERATELY DOES NOT CLAIM:
#
#  1. The shipped wrapper is not re-armable on another host.  Its
#     `candidate_results`, `gold_results` and `source_sidecar` fields are
#     `_wrapper_reference` spellings relative to the ceremony's own output
#     directory (`../../../../data2/...`), and `_validate_rebinding_chain`
#     re-derives the whole wrapper from the files those spellings name.  The
#     bundle therefore ships the wrapper as the ceremony's provenance record
#     -- the artifact that carries the owner's ruling-2.6 consent -- and joins
#     it to the shipped bytes BY DIGEST.  Re-arming the byte pin on a consumer
#     host means re-running `test-quality-bind` over these bundled bytes to
#     mint a host-local wrapper; that is Tier 1b work, not this join.
#  2. The engine source is a Git object, not a working-tree file.  The
#     ceremony validated `benchmark/r2t/php/mutate.php` at blob
#     `d26300d4...` (commit `f0143ef`), which `VERSIONS.yml`
#     `historical_engine_sources` records and which the live file at the
#     reviewed tag no longer equals.  An installed bundle is not a Git
#     repository, so it cannot resolve that object: the bundle ships the
#     BLOB'S BYTES under the existing `engine_source` role
#     (`_stage_engine_source`), the build checks the object store, and the
#     installed validator checks the bytes.
STD_ARM_ROLES = {
    # role: (bundle-relative destination, source kind, recorded path tail)
    #
    # `evidence` sources are preserved bytes under the author host's data
    # root, located by the absolute path the shipping list records.  `out`
    # sources are the ceremony's own outputs, located by basename BESIDE the
    # shipping list, so an evidence directory that moves intact still builds.
    # `document` sources are the two ceremony documents the list does not
    # enumerate (it cannot name itself, and the report is its prose form);
    # the dataset manifest pins those two.
    #
    # The run, its campaign stamp and its sidecar install under the data root
    # at the exact spellings `results.py` reads: `draws.check_campaign_pair`
    # wants `<run>.campaign.json` and `find_sidecar` derives
    # `<run stem>.test_quality.json`.  A bundle that renamed them would ship
    # evidence no reader finds.
    "std_candidate_run": (
        "projects/coreshop/artifacts/runs/eval100_std.merged.jsonl",
        "evidence", "artifacts/runs/eval100_std.merged.jsonl"),
    "std_campaign": (
        "projects/coreshop/artifacts/runs/"
        "eval100_std.merged.jsonl.campaign.json",
        "evidence", "artifacts/runs/eval100_std.merged.jsonl.campaign.json"),
    "std_test_quality": (
        "projects/coreshop/artifacts/runs/eval100_std.merged.test_quality.json",
        "evidence", "artifacts/runs/eval100_std.merged.test_quality.json"),
    "std_gold_run": (
        "projects/coreshop/artifacts/runs/eval100_gold.jsonl",
        "evidence", "artifacts/runs/eval100_gold.jsonl"),
    "std_candidate_results": (
        "bundles/v1/coreshop/evidence/std/candidate_mutation.jsonl",
        "evidence", "artifacts/test_quality_std/candidate_mutation.jsonl"),
    "std_gold_results": (
        "bundles/v1/coreshop/evidence/std/gold_mutation.jsonl",
        "evidence", "artifacts/test_quality_std/gold_mutation.jsonl"),
    "std_legacy_consistency": (
        "bundles/v1/coreshop/evidence/std/eval100_std_legacy_consistency.json",
        "out", "eval100_std_legacy_consistency.json"),
    "std_test_quality_wrapper": (
        "bundles/v1/coreshop/evidence/std/eval100_std.tq_wrapper.json",
        "out", "eval100_std.tq_wrapper.json"),
    "std_pin_transcript": (
        "bundles/v1/coreshop/evidence/std/pc8_armed_selftest.txt",
        "out", "pc8_armed_selftest.txt"),
    "std_ceremony_report": (
        "bundles/v1/coreshop/evidence/std/D4_J3_ceremony_report.md",
        "document", "report"),
    "std_shipping_list": (
        "bundles/v1/coreshop/evidence/std/consumed_inputs_manifest.json",
        "document", "shipping_list"),
}

#: rc.4 roles the ceremony consumed too, and the tail it recorded them at.
#: These bytes are ALREADY in the bundle; the join proves the published arm
#: was scored over the population, boundary, map and release this asset
#: ships, rather than over some other tree's.
STD_ARM_SHARED_ROLES = {
    "production_index": "artifacts/php_prod_index.json",
    "raw_manifest": "tq_inputs/mutants.json",
    "legacy_map": "tq_inputs/mutant_items.json",
    "coverage_run": "tq_inputs/gold_baseline_seed_accept.jsonl",
    "gold_baseline": "tq_inputs/gold_baseline_seed_accept.jsonl",
    "release_items": "benchmark/release/eval100.jsonl",
    "mutation_asset_index": "benchmark/release/slice1_mutation_assets.json",
    "audit_attestation": "benchmark/release/coreshop/"
                         "materialisation_audit_v1.json",
    "boundary": "benchmark/config/boundary_coreshop.yml",
}

#: Recorded inputs that are byte-identical copies of a role's bytes.  The
#: ceremony read the sidecar twice (a second preserved copy) and read the map
#: and gold baseline through a VOLATILE `/tmp` scratchpad the wrapper's own
#: claims name.  The bundle ships one copy; the digests are compared so
#: "byte-identical" is checked rather than asserted.
STD_ARM_RECORDED_COPIES = {
    "artifacts/test_quality_std/summary.json": "std_test_quality",
    "scratchpad/mutant_items.json": "legacy_map",
    "scratchpad/seed_accept.jsonl": "coverage_run",
}

#: Recorded inputs the reviewed REPOSITORY carries, which a bundle does not
#: ship because the checkout is their authority.  `True` re-hashes the file
#: at build time: the published table is what this arm's numbers are pinned
#: to, so a builder whose tree has re-frozen it must stop and re-run the
#: ceremony.  The other two change with ordinary repository work -- this very
#: pull request edits `VERSIONS.yml` -- so pinning them would refuse every
#: future build for no finding.
STD_ARM_REPOSITORY_INPUTS = {
    "benchmark/release/v1/legacy_table_eval100_std.md": True,
    "benchmark/release/legacy_consistency/index.json": False,
    "benchmark/VERSIONS.yml": False,
}

#: `inputs` keys of the ceremony's legacy-consistency report -> the role whose
#: bundled bytes must hash to what the report validated.  Required to cover
#: the report's input set exactly, so a report naming an input this table
#: forgot refuses instead of passing unjoined.
STD_ARM_REPORT_INPUTS = {
    "candidate_run": "std_candidate_run",
    "candidate_results": "std_candidate_results",
    "gold_results": "std_gold_results",
    "raw_manifest": "raw_manifest",
    "map": "legacy_map",
    "coverage_run": "coverage_run",
    "gold_baseline": "gold_baseline",
    "release": "release_items",
    "boundary": "boundary",
    "asset_index": "mutation_asset_index",
    "audit_attestation": "audit_attestation",
    "engine_source": "engine_source",
}


class BundleRefused(RuntimeError):
    pass


def _refuse(message: str) -> None:
    raise BundleRefused("REFUSED: " + message)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_json(path: str, label: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        _refuse(f"cannot read {label} at {path}: {exc}")
    if not isinstance(doc, dict):
        _refuse(f"{label} is not a JSON object")
    return doc


def _authority(project: str, version: str,
               manifest_path: str = DATASET_MANIFEST) -> tuple[dict, dict]:
    doc = _read_json(manifest_path, "dataset manifest")
    if doc.get("schema") != "r2t.dataset_manifest/3":
        _refuse("dataset manifest does not declare scoring bundles")
    block = (doc.get("projects") or {}).get(project)
    if not isinstance(block, dict) or not isinstance(block.get("bundle"), dict):
        _refuse(f"dataset manifest has no bundle for project {project!r}")
    bundle = block["bundle"]
    if bundle.get("version") != version:
        _refuse(f"project {project!r} has bundle version "
                f"{bundle.get('version')!r}, not {version!r}")
    return doc, block


def _artifact_path(root: str, block: dict, role: str) -> Optional[str]:
    rel = block["bundle"]["artifacts"][role]
    return None if rel is None else os.path.join(root, *rel.split("/"))


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 \
        and all(character in "0123456789abcdef" for character in value)


def _annotated_release_declaration(project: str, block: dict) -> Optional[dict]:
    """An annotated companion never replaces the historical release role."""
    bundle = block["bundle"]
    declaration = bundle.get("annotated_release")
    path = bundle["artifacts"].get("annotated_release_items")
    if declaration is None and path is None:
        return None
    expected = f"projects/{project}/artifacts/release/annotated_items.jsonl"
    if not isinstance(declaration, dict) \
            or set(declaration) != {"file", "sha256"} \
            or not isinstance(declaration["file"], str) \
            or not declaration["file"] \
            or os.path.isabs(declaration["file"]) \
            or os.path.normpath(declaration["file"]).startswith("..") \
            or not _is_sha256(declaration["sha256"]) \
            or path != expected \
            or path in (value for role, value in bundle["artifacts"].items()
                        if role != "annotated_release_items"):
        _refuse("annotated release needs its own declared sibling path, "
                "release-relative source file and SHA-256")
    return declaration


def _validate_annotated_release(path: str, historical_path: str,
                                declaration: dict) -> int:
    """Check the new bytes and compare tasks directly, excluding annotation."""
    from .profile import ProfileError
    from .prompt import ANNOTATION_BLOCKS, validate_annotation

    actual = _sha256_file(path) if os.path.isfile(path) else None
    if actual != declaration["sha256"]:
        _refuse(f"annotated release SHA-256 is {actual}, dataset manifest "
                f"says {declaration['sha256']}")
    try:
        with open(path, encoding="utf-8") as fh:
            annotated = [json.loads(line) for line in fh if line.strip()]
        with open(historical_path, encoding="utf-8") as fh:
            historical = [json.loads(line) for line in fh if line.strip()]
    except (OSError, ValueError) as exc:
        _refuse(f"cannot read annotated/historical release JSONL: {exc}")
    if len(annotated) != len(historical):
        _refuse("annotated release changes the historical task count")
    for new, old in zip(annotated, historical):
        if not isinstance(new, dict) or not isinstance(old, dict) \
                or {k: v for k, v in new.items() if k not in ANNOTATION_BLOCKS} \
                != {k: v for k, v in old.items() if k not in ANNOTATION_BLOCKS}:
            _refuse("annotated release changes historical tasks or their order")
        try:
            # Use the same shape, ordering and disjointness rules as prompts.
            validate_annotation(new, path)
        except ProfileError as exc:
            _refuse(str(exc).removeprefix("REFUSED: "))
    return len(annotated)


def _scoring_gold_declaration(project: str, block: dict) -> Optional[dict]:
    """The optional current reference is separate from mutation evidence."""
    bundle = block["bundle"]
    declaration = bundle.get("scoring_gold")
    path = bundle["artifacts"].get("scoring_gold")
    if declaration is None and path is None:
        return None
    expected = f"projects/{project}/artifacts/runs/gold_direct.jsonl"
    if not isinstance(declaration, dict) \
            or set(declaration) != {"sha256"} \
            or not _is_sha256(declaration["sha256"]) \
            or path != expected \
            or bundle.get("production_index") is None:
        _refuse("scoring gold needs its own declared path, SHA-256 and "
                "production method index")
    return declaration


def _legacy_evidence_declaration(project: str, block: dict) -> Optional[dict]:
    """The preserved mutation-evidence roles, or None when none is declared.

    Same shape as `_annotated_release_declaration`: the manifest says whether
    the role exists (`release.LEGACY_EVIDENCE_ROLES`, all declared or all
    null), and a build that supplies an input for an undeclared role, or
    omits one for a declared role, is refused.  Half a declaration is refused
    too, because a bundle carrying a scored manifest without the report that
    validated it would be read as evidence it is not.
    """
    artifacts = block["bundle"]["artifacts"]
    declared = {role: artifacts.get(role) for role in LEGACY_EVIDENCE_ROLES}
    absent = sorted(role for role, path in declared.items() if path is None)
    if not absent:
        return declared
    if len(absent) != len(LEGACY_EVIDENCE_ROLES):
        _refuse(f"{project} declares legacy mutation evidence for some roles "
                f"and not others (null: {absent}); a bundle ships the whole "
                "set or none of it")
    return None


def _release_pool_declaration(project: str, block: dict,
                              legacy: Optional[dict]) -> Optional[dict]:
    """The release pool a bundle without preserved evidence ships.

    The legacy report pins the pool bytes for the Slice 1 projects; a project
    with no report names its pool in the manifest, release-root-relative, and
    the renderer measured its SHA-256.  Exactly one of the two exists, so a
    bundle never ships the whole population by default and never carries two
    answers to "which items".
    """
    declaration = block["bundle"].get("release_pool")
    if (declaration is None) != (legacy is not None):
        _refuse(f"{project} names a release pool exactly when it declares no "
                "legacy mutation evidence")
    if declaration is None:
        return None
    if not isinstance(declaration, dict) \
            or set(declaration) != {"file", "sha256"} \
            or not isinstance(declaration["file"], str) \
            or not declaration["file"] \
            or os.path.isabs(declaration["file"]) \
            or os.path.normpath(declaration["file"]).startswith("..") \
            or not _is_sha256(declaration["sha256"]):
        _refuse("release pool needs a release-relative file and its SHA-256")
    return declaration


def _coverage_oracle_declaration(project: str, block: dict,
                                 legacy: Optional[dict]) -> Optional[dict]:
    """The declared SHA-256 of the coverage oracle a no-legacy bundle ships.

    The legacy report pins the gold baseline for the Slice 1 projects; a
    project with no report declares the digest in the manifest, like the seed
    manifest's, and `build_bundle` and the installed-bundle validator both
    check the file against it, so the coverage metric is never measured
    against an oracle nobody named.
    """
    declaration = block["bundle"].get("coverage_run")
    if (declaration is None) != (legacy is not None):
        _refuse(f"{project} declares its coverage oracle's SHA-256 exactly "
                "when it declares no legacy mutation evidence")
    if declaration is None:
        return None
    if not isinstance(declaration, dict) \
            or set(declaration) != {"sha256"} \
            or not _is_sha256(declaration["sha256"]):
        _refuse("coverage oracle declaration needs exactly its SHA-256")
    return declaration


def _validate_production_index(root: str, block: dict) -> Optional[str]:
    production = block["bundle"]["production_index"]
    if production is None:
        return None
    path = _artifact_path(root, block, "production_index")
    actual = _sha256_file(path) if os.path.isfile(path) else None
    if actual != production["sha256"]:
        _refuse(f"bundled production index SHA-256 is {actual}, expected "
                f"{production['sha256']}")
    return path


def _validate_scoring_gold(root: str, project: str,
                           block: dict) -> Optional[dict]:
    """Validate complete new rows without replacing the historical oracle.

    Outcomes and the scorer's production-line projection must match the old
    baseline. Collection's stronger all-file witness checks remain operator
    gates; this join establishes that selecting the new reference cannot
    change the coverage metrics. No field is copied between the two runs.
    """
    declaration = _scoring_gold_declaration(project, block)
    if declaration is None:
        return None
    path = _artifact_path(root, block, "scoring_gold")
    actual = _sha256_file(path) if os.path.isfile(path) else None
    if actual != declaration["sha256"]:
        _refuse(f"bundled scoring gold SHA-256 is {actual}, expected "
                f"{declaration['sha256']}")
    index_path = _validate_production_index(root, block)
    from . import mutation_attestation as A
    from ..bench import metrics as M
    from ..core.boundary import load_boundary
    try:
        raw = A.load_jsonl(path)
        rows = {}
        for number, row in enumerate(raw, 1):
            item_id = row.get("item_id")
            if not isinstance(item_id, str) or not item_id or item_id in rows:
                _refuse(f"scoring gold row {number} has a missing or duplicate item_id")
            if not isinstance(row.get("direct_calls"), list):
                _refuse(f"scoring gold {item_id} has no collected direct_calls")
            rows[item_id] = row
        release_ids = A.load_release_ids(
            _artifact_path(root, block, "release_items"))
        if set(rows) != release_ids:
            _refuse("scoring gold does not contain exactly the released items")
        baseline = M.load_runs(_artifact_path(root, block, "gold_baseline"))
        boundary = load_boundary(_artifact_path(root, block, "boundary"))
        M.check_scorable(rows, path)
        for item_id, row in rows.items():
            old = baseline.get(item_id)
            if old is None or row.get("outcome") != old.get("outcome"):
                _refuse(f"scoring gold {item_id} changes the baseline outcome")
            lines = M.production_lines(row, boundary)
            if lines is None or lines != M.production_lines(old, boundary):
                _refuse(f"scoring gold {item_id} changes production coverage")
        index = M.load_prod_index(index_path)
        check = M.gold_self_check(rows, index, boundary)
        if not check["ok"] or check["n_api_skipped"]:
            _refuse("scoring gold fails the gold self-check: " + str(check))
        unmapped = sum(M.direct_methods(row, boundary, index)[1]
                       for row in rows.values())
    except (A.MutationAssetRefused, M.MetricsInputError, OSError,
            ValueError, TypeError, KeyError, AttributeError) as exc:
        _refuse("invalid scoring gold: " + str(exc).removeprefix("REFUSED: "))
    return {"path": block["bundle"]["artifacts"]["scoring_gold"],
            "sha256": actual, "rows": len(rows),
            "n_with_methods": check["n_with_methods"],
            "unmapped_direct_events": unmapped}


def installed_scoring_gold(artifacts: str, project: str, *,
                           manifest_path: str = DATASET_MANIFEST) -> Optional[str]:
    """Resolve only a declared, verified current reference in an installation.

    An arbitrary artifacts directory keeps the ordinary explicit --gold
    route. A declared role that is absent or invalid is a refusal, never a
    silent fallback to the historical baseline.
    """
    artifacts = os.path.abspath(artifacts)
    suffix = os.path.join("projects", project, "artifacts")
    if not artifacts.endswith(os.sep + suffix):
        return None
    document = _read_json(manifest_path, "dataset manifest")
    block = (document.get("projects") or {}).get(project)
    if not isinstance(block, dict) or "bundle" not in block:
        return None
    root = artifacts[:-(len(suffix) + 1)] or os.sep
    reference = _validate_scoring_gold(root, project, block)
    return (os.path.join(root, *reference["path"].split("/"))
            if reference is not None else None)


def _std_arm(version: str, block: dict) -> Optional[dict]:
    """The eval100-std declaration this asset VERSION must ship, if any.

    Inert by construction until the declared asset version is the one being
    built or validated.  The published rc.4 asset does not contain these
    roles; requiring them of it would refuse bytes that are correct, so the
    declaration names the version that first ships the arm and equality --
    not presence -- switches the joins on.
    """
    declaration = block["bundle"].get("std_arm")
    if declaration is None or declaration["asset_version"] != version:
        return None
    return declaration


def _shipping_list(path: str, declaration: dict) -> dict:
    """The ceremony's own enumeration of what the published arm consumed."""
    ceremony = declaration["ceremony"]
    expected = ceremony["shipping_list_sha256"]
    actual = _sha256_file(path) if os.path.isfile(path) else None
    if actual != expected:
        _refuse(f"eval100-std shipping list {path} hashes to {actual}, the "
                f"dataset manifest pins {expected}")
    document = _read_json(path, "eval100-std shipping list")
    if document.get("tag") != ceremony["tag"] \
            or document.get("commit") != ceremony["commit"]:
        _refuse(f"eval100-std shipping list names ceremony "
                f"{document.get('tag')!r} at {document.get('commit')!r}, the "
                f"dataset manifest declares {ceremony['tag']!r} at "
                f"{ceremony['commit']!r}")
    # A run whose render leg stopped early enumerates less than it consumed,
    # and the third J3 run is exactly that run: it withheld the two mutation
    # cells and never reached their inputs.  Its list must not ship an arm.
    if document.get("not_reached"):
        _refuse("the eval100-std ceremony did not reach "
                f"{len(document['not_reached'])} of its inputs; its shipping "
                "list is not a complete account of the published arm")
    files = document.get("files")
    if not isinstance(files, list) or not files:
        _refuse("the eval100-std shipping list enumerates no input file")
    for entry in files:
        if not isinstance(entry, dict) \
                or not isinstance(entry.get("path"), str) \
                or not entry["path"] \
                or not _is_sha256(entry.get("sha256")):
            _refuse("the eval100-std shipping list has a malformed input "
                    f"entry: {entry!r}")
    return document


def _recorded(document: dict, tail: str, label: str) -> str:
    """The one digest the shipping list records for a path ending in `tail`.

    Matched by tail rather than by absolute path because two of the recorded
    spellings are the ceremony's own: its detached worktree and its output
    directory both carry a run-specific name, and the same bytes are recorded
    at both a `/data2` and a worktree spelling.  Disagreeing digests under one
    tail refuse rather than picking one.
    """
    digests = {entry["sha256"] for entry in document["files"]
               if entry["path"] == tail or entry["path"].endswith("/" + tail)}
    if not digests:
        _refuse(f"the eval100-std shipping list records no {label}: no "
                f"recorded input path ends in {tail!r}")
    if len(digests) > 1:
        _refuse(f"the eval100-std shipping list records {len(digests)} "
                f"different digests for {label} ({tail!r}): {sorted(digests)}")
    return digests.pop()


def _std_arm_engine(document: dict) -> dict:
    """The one Git-object input the ceremony resolved, as a closed record.

    This is the input that cannot ship as a file role naively: the frozen
    producer is a Git blob, and the working-tree file at the reviewed tag is
    a later enumerator.  The record travels with the arm; the BYTES ship
    under the existing `engine_source` role.
    """
    entries = document.get("git_resolved_inputs")
    if not isinstance(entries, list) or len(entries) != 1:
        _refuse("the eval100-std shipping list must record exactly one "
                "Git-resolved input, the frozen engine source")
    entry = entries[0]
    if not isinstance(entry, dict) or not _is_sha256(entry.get("sha256")) \
            or not isinstance(entry.get("git_blob"), str) \
            or not isinstance(entry.get("git_commit"), str):
        _refuse(f"the eval100-std Git-resolved input is malformed: {entry!r}")
    return entry


def _std_arm_plan(declaration: dict, document: dict) -> dict:
    """`{role: expected SHA-256}`, with every recorded input dispositioned.

    Fail-closed on both sides.  A role the list does not record refuses, and
    a recorded input that no role, copy or repository disposition claims
    refuses too -- so a later ceremony that consumes something new cannot
    ship an arm that silently leaves it behind.
    """
    ceremony = declaration["ceremony"]
    expected = {}
    for role, (_destination, kind, tail) in STD_ARM_ROLES.items():
        expected[role] = (ceremony[f"{tail}_sha256"] if kind == "document"
                          else _recorded(document, tail, f"{role} bytes"))
    for role, tail in STD_ARM_SHARED_ROLES.items():
        expected[role] = _recorded(document, tail, f"{role} bytes")
    expected["engine_source"] = _std_arm_engine(document)["sha256"]
    for tail, role in STD_ARM_RECORDED_COPIES.items():
        copied = _recorded(document, tail, f"the copy of {role}")
        if copied != expected[role]:
            _refuse(f"the eval100-std shipping list records ...{tail} as "
                    f"{copied}, which is not the {role} bytes "
                    f"{expected[role]} it is recorded as copying")
    dispositioned = ([tail for _d, kind, tail in STD_ARM_ROLES.values()
                      if kind != "document"]
                     + list(STD_ARM_SHARED_ROLES.values())
                     + list(STD_ARM_RECORDED_COPIES)
                     + list(STD_ARM_REPOSITORY_INPUTS))
    for entry in document["files"]:
        path = entry["path"]
        if not any(path == tail or path.endswith("/" + tail)
                   for tail in dispositioned):
            _refuse("the eval100-std shipping list records an input this "
                    f"bundle neither ships nor accounts for: {path} "
                    f"({entry.get('role')})")
    return expected


def _std_path(root: str, role: str) -> str:
    return os.path.join(root, *STD_ARM_ROLES[role][0].split("/"))


def _validate_std_arm(root: str, block: dict, declaration: dict) -> dict:
    """Join every installed eval100-std role to the ceremony's own records.

    The ceremony is the authority twice over, and both are consulted: its
    shipping list says which bytes the published render consumed, and its
    legacy-consistency report -- the document the wrapper pins and
    `_validate_rebinding_chain` re-derives from -- says which bytes it
    validated.  A role that satisfies one and not the other is not the
    published arm.
    """
    shipped_list = _std_path(root, "std_shipping_list")
    document = _shipping_list(shipped_list, declaration)
    expected = _std_arm_plan(declaration, document)

    digests: dict[str, str] = {}

    def digest(role: str, path: str) -> str:
        if os.path.islink(path) or not os.path.isfile(path):
            _refuse(f"bundle is missing eval100-std {role}: "
                    f"{os.path.relpath(path, root)}")
        # One physical file, one hashing pass: `coverage_run` and
        # `gold_baseline` are the same 14 MB artifact under two role names.
        absolute = os.path.abspath(path)
        if absolute not in digests:
            digests[absolute] = _sha256_file(path)
        actual = digests[absolute]
        if actual != expected[role]:
            _refuse(f"bundled eval100-std {role} hashes to {actual}, the "
                    f"ceremony recorded {expected[role]}")
        return actual

    installed = {role: digest(role, _std_path(root, role))
                 for role in STD_ARM_ROLES}
    for role in STD_ARM_SHARED_ROLES:
        installed[role] = digest(role, _artifact_path(root, block, role))
    installed["engine_source"] = digest(
        "engine_source", _artifact_path(root, block, "engine_source"))

    report = _read_json(_std_path(root, "std_legacy_consistency"),
                        "bundled eval100-std legacy-consistency report")
    inputs = report.get("inputs")
    if not isinstance(inputs, dict) \
            or set(inputs) != set(STD_ARM_REPORT_INPUTS):
        _refuse("the bundled eval100-std legacy-consistency report validates "
                f"input set {sorted(inputs or ())}, not the "
                f"{len(STD_ARM_REPORT_INPUTS)} roles this bundle joins it to")
    for key, role in STD_ARM_REPORT_INPUTS.items():
        validated = (inputs.get(key) or {}).get("sha256")
        if validated != installed[role]:
            _refuse(f"the bundled eval100-std report validated {key} as "
                    f"{validated}, but this bundle's {role} is "
                    f"{installed[role]}")

    wrapper = _read_json(_std_path(root, "std_test_quality_wrapper"),
                         "bundled eval100-std test-quality wrapper")
    chain = wrapper.get("legacy_rebinding") or {}
    # Ruling 2.6: a mutation number computed over gold that carries
    # infrastructure outcomes publishes only with the operator's recorded
    # consent (leg a), the disclosed count (b) and the per-item list (c).
    # The consent is a decision, not a fact about bytes; it travels in the
    # wrapper, so the wrapper travels with the evidence or the arm does not
    # ship.  The third J3 run produced an otherwise complete wrapper with
    # this field false, and that wrapper must not become a released asset.
    pairs = wrapper.get("gold_infrastructure_pairs")
    if wrapper.get("allow_degraded_gold") is not True:
        _refuse("the bundled eval100-std wrapper records no operator consent "
                "(allow_degraded_gold is not true); the published mutation "
                "cells may not ship without owner ruling 2.6 leg (a)")
    if not isinstance(pairs, list) \
            or wrapper.get("gold_infrastructure_outcomes") != len(pairs):
        disclosed = len(pairs) if isinstance(pairs, list) else None
        _refuse("the bundled eval100-std wrapper discloses "
                f"{wrapper.get('gold_infrastructure_outcomes')!r} degraded "
                f"gold outcome(s) and {disclosed} per-item pair(s); ruling "
                "2.6 legs (b) and (c) must agree")
    if (wrapper.get("binding") or {}).get("run_sha256") \
            != installed["std_candidate_run"]:
        _refuse("the bundled eval100-std wrapper is bound to run "
                f"{(wrapper.get('binding') or {}).get('run_sha256')}, not to "
                f"the shipped run {installed['std_candidate_run']}")
    if chain.get("source_sidecar_sha256") != installed["std_test_quality"]:
        _refuse("the bundled eval100-std wrapper chains to preserved sidecar "
                f"{chain.get('source_sidecar_sha256')}, not to the shipped "
                f"sidecar {installed['std_test_quality']}")
    if chain.get("validation_report_sha256") \
            != installed["std_legacy_consistency"]:
        _refuse("the bundled eval100-std wrapper chains to validation report "
                f"{chain.get('validation_report_sha256')}, not to the shipped "
                f"report {installed['std_legacy_consistency']}")
    # The wrapper's evidence spellings are the ceremony host's and are not
    # re-resolvable here (see the module note); its report reference is the
    # one that must resolve inside the bundle, so the shipped pair is
    # self-checking wherever the bundle is installed.
    report_name = os.path.basename(STD_ARM_ROLES["std_legacy_consistency"][0])
    base = (wrapper.get("path_base") or {}).get("relative_to_wrapper")
    if base != "." or chain.get("validation_report") != report_name:
        _refuse("the bundled eval100-std wrapper names its validation report "
                f"{chain.get('validation_report')!r} relative to {base!r}; "
                f"the bundled pair must resolve as {report_name!r} beside "
                "the wrapper")
    return {"ceremony": declaration["ceremony"]["tag"],
            "roles": len(installed),
            "wrapper_sha256": installed["std_test_quality_wrapper"]}


@contextlib.contextmanager
def _using_data_root(root: str):
    previous = os.environ.get(DATA_ROOT_ENV)
    os.environ[DATA_ROOT_ENV] = os.path.abspath(root)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(DATA_ROOT_ENV, None)
        else:
            os.environ[DATA_ROOT_ENV] = previous


def _gold_digest(root: str, block: dict) -> str:
    gold_dir = _artifact_path(root, block, "release_gold")
    assert gold_dir is not None
    manifest_path = os.path.join(gold_dir, "manifest.json")
    manifest = _read_json(manifest_path, "bundled gold manifest")
    on_disk = {name for name in os.listdir(gold_dir)
               if name != "manifest.json"
               and os.path.isfile(os.path.join(gold_dir, name))}
    if set(manifest.values()) != on_disk:
        _refuse("bundled gold manifest and sidecar files disagree")
    release_prefix = block.get("dir") or "."
    entries = []
    for name in sorted(on_disk):
        rel = os.path.join("gold", name)
        if release_prefix != ".":
            rel = os.path.join(release_prefix, rel)
        entries.append({"path": rel.replace(os.sep, "/"),
                        "sha256": _sha256_file(os.path.join(gold_dir, name))})
    canonical = json.dumps(entries, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_release_gold(root: str, block: dict,
                           release_ids: set[str]) -> None:
    """Validate the staged answer key and its removed source tree."""
    release_gold = _artifact_path(root, block, "release_gold")
    assert release_gold is not None
    manifest_path = os.path.join(release_gold, "manifest.json")
    if _sha256_file(manifest_path) != block["gold_manifest_sha256"] \
            or _gold_digest(root, block) != block["gold_sidecars_sha256"]:
        _refuse("bundled gold differs from dataset manifest")

    gold_manifest = _read_json(manifest_path, "bundled gold manifest")
    missing_gold = sorted(release_ids - set(gold_manifest))
    if missing_gold:
        _refuse(f"bundled release items lack gold sidecars: {missing_gold[:3]}")

    gold_root = _artifact_path(root, block, "gold")
    assert gold_root is not None
    if not os.path.isfile(os.path.join(gold_root, "strip_manifest.json")):
        _refuse("bundled gold tree lacks strip_manifest.json")
    missing_files = set()
    for item_id in release_ids:
        sidecar = _read_json(
            os.path.join(release_gold, gold_manifest[item_id]),
            f"gold sidecar for {item_id}")
        for rel in sidecar.get("files") or []:
            if not os.path.isfile(os.path.join(gold_root, rel)):
                missing_files.add(rel)
    if missing_files:
        _refuse("bundled gold tree lacks files named by release sidecars: "
                f"{sorted(missing_files)[:3]}")


def _validate_prestashop_resources(gold_root: str) -> dict:
    """Read the existing protected resource authority at its installed location."""
    from ..bench.repo import load_manifest
    from ..bench.prestashop_resources import ResourceResetError, verify_inputs
    try:
        manifest = load_manifest(os.path.join(gold_root, "strip_manifest.json"))
        manifest.gold_root = os.path.abspath(gold_root)
        entries = verify_inputs(manifest)
        for rel, entry in entries.items():
            if entry["kind"] == "link":
                target = os.path.normpath(os.path.join(
                    os.path.dirname(rel), entry["target"]))
                if os.path.isabs(entry["target"]) or target == ".." \
                        or target.startswith("../"):
                    _refuse(f"native resource link escapes its snapshot: {rel}")
        return entries
    except (OSError, ValueError, KeyError, ResourceResetError) as exc:
        _refuse(f"bundled PrestaShop native resource inputs do not verify: {exc}")


def validate_installed_bundle(project: str, version: str,
                              root: Optional[str] = None, *,
                              authority: Optional[dict] = None,
                              block: Optional[dict] = None,
                              release_index_path: Optional[str] = None,
                              manifest_path: str = DATASET_MANIFEST) -> dict:
    """Revalidate the extracted bytes through their existing authorities."""
    root = os.path.abspath(root or data_root())
    from . import evaluation_bundle as evaluation
    if evaluation.is_evaluation_bundle(project, version):
        return evaluation.validate_evaluation_bundle(
            project=project, version=version, root=root,
            release_index_path=release_index_path)
    if project == "algorand-sdk":
        from ..toolkit import algorand_bundle as native
        try:
            return native.validate_bundle(root, version=version)
        except native.AlgorandBundleRefused as exc:
            _refuse(str(exc).removeprefix("REFUSED: "))
    if authority is None or block is None:
        authority, block = _authority(project, version, manifest_path)
    artifacts = block["bundle"]["artifacts"]
    directories = {"gold", "release_gold", "seed"}
    for role, rel in artifacts.items():
        if rel is None:
            continue
        path = _artifact_path(root, block, role)
        exists = os.path.isdir(path) if role in directories else os.path.isfile(path)
        if not exists:
            _refuse(f"bundle is missing {role}: {rel}")

    from ..bench import seed as S
    seed_dir = _artifact_path(root, block, "seed")
    seed_sha = _sha256_file(os.path.join(seed_dir, S.SEED_MANIFEST))
    if seed_sha != block["bundle"]["seed"]["manifest_sha256"]:
        _refuse("bundled seed manifest differs from dataset manifest")
    if not S.verify_seed(seed_dir)["artifacts_ok"]:
        _refuse("bundled seed archive does not verify")
    if project == "prestashop":
        _validate_prestashop_resources(_artifact_path(root, block, "gold"))

    legacy = _legacy_evidence_declaration(project, block)
    pool = _release_pool_declaration(project, block, legacy)
    oracle = _coverage_oracle_declaration(project, block, legacy)
    release_path = _artifact_path(root, block, "release_items")
    from . import mutation_attestation as A
    release_ids = A.load_release_ids(release_path)
    if pool is not None and _sha256_file(release_path) != pool["sha256"]:
        _refuse("bundled release pool differs from the dataset manifest")
    if oracle is not None and _sha256_file(
            _artifact_path(root, block, "coverage_run")) != oracle["sha256"]:
        _refuse("bundled coverage oracle differs from the dataset manifest")
    _validate_release_gold(root, block, release_ids)
    annotation = _annotated_release_declaration(project, block)
    if annotation is not None:
        _validate_annotated_release(
            _artifact_path(root, block, "annotated_release_items"),
            release_path, annotation)

    scoring_gold = _validate_scoring_gold(root, project, block)
    if scoring_gold is None:
        _validate_production_index(root, block)

    worker_plan = _read_json(
        _artifact_path(root, block, "worker_plan"), "bundled worker plan")
    expected_plan = {"schema": "r2t.worker-plan/1", "project": project,
                     **block["bundle"]["worker_plan"]}
    if worker_plan != expected_plan:
        _refuse("bundled worker plan differs from dataset manifest")

    with _using_data_root(root):
        from .profile import ProfileError, config_stem, load_profile
        try:
            profile = load_profile(_artifact_path(root, block, "profile"))
            if legacy is not None:
                validation_path = _artifact_path(
                    root, block, "mutation_validation")
                facts = A.validate_saved_validation_report(
                    validation_path,
                    expected_validation_class="native",
                    require_release_ready=False)
                campaign = A.validate_campaign_asset_inputs(
                    validation_path,
                    manifest_path=_artifact_path(root, block, "scored_manifest"),
                    map_path=_artifact_path(root, block, "mutation_map"),
                    release_path=release_path, require_release_ready=False)
                scoring = A.load_validated_legacy_scoring_inputs(
                    _artifact_path(root, block, "gold_results_attestation"),
                    require_release_ready=False)
        except (A.MutationAssetRefused, ProfileError,
                OSError, ValueError) as exc:
            _refuse(str(exc).removeprefix("REFUSED: "))
    if profile.project != project:
        _refuse("bundled profile names another project")
    from ..bench import worker as W
    W.plan_workers(
        os.path.join(root, "projects", project, "workers"),
        worker_plan["k"], workdir=worker_plan["workdir"],
        prefix=config_stem(profile.project),
        kind=worker_plan["container_kind"],
        needs_database=profile.needs_database)
    if legacy is not None:
        scored = _read_json(_artifact_path(root, block, "scored_manifest"),
                            "bundled scored manifest")
        mapping = _read_json(_artifact_path(root, block, "mutation_map"),
                             "bundled mutation map")
        if scored != scoring["manifest"] or mapping != scoring["map"] \
                or campaign["manifest"] != scored or campaign["map"] != mapping:
            _refuse("bundled scored manifest/map differ from native or "
                    "legacy validated evidence")
    declaration = _std_arm(version, block)
    std = (None if declaration is None
           else _validate_std_arm(root, block, declaration))
    report = {"project": project, "version": version,
            "release_items": len(release_ids),
            # None, not False: a bundle with no mutation evidence has no
            # release-readiness to report, and nothing may read "not ready".
            "release_ready": (facts["release_ready"] if legacy is not None
                              else None),
            "worker_plan": worker_plan, "std_arm": std}
    if scoring_gold is not None:
        report["scoring_gold"] = scoring_gold
    if annotation is not None:
        report["annotated_release_items"] = artifacts["annotated_release_items"]
    return report


def _open(opener: Callable, request: urllib.request.Request, label: str,
          token: Optional[str]):
    try:
        return opener(request)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 404):
            if not token:
                _refuse(f"cannot read {label} from GitHub without credentials; "
                        "the repository or the release may be private, so set "
                        f"{GITHUB_TOKEN_ENV} to a token with repository access")
            _refuse(f"cannot read {label} from the private GitHub repository; "
                    f"set {GITHUB_TOKEN_ENV} to a token with repository access")
        _refuse(f"GitHub returned HTTP {exc.code} for {label}")
    except urllib.error.URLError as exc:
        _refuse(f"cannot read {label} from GitHub: {exc.reason}")


def _download_asset(*, repository: str, version: str, asset_name: str,
                    token: Optional[str], destination: str,
                    opener: Callable = urllib.request.urlopen) -> None:
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "r2t-bundle-fetch"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    release_url = (f"https://api.github.com/repos/{repository}/releases/tags/"
                   f"{version}")
    response = _open(opener, urllib.request.Request(release_url, headers=headers),
                     f"release {version}", token)
    with response:
        try:
            release = json.loads(response.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _refuse(f"GitHub release metadata is not JSON: {exc}")
    asset = next((item for item in release.get("assets", [])
                  if item.get("name") == asset_name), None)
    if asset is None or not asset.get("url"):
        _refuse(f"release {version} has no asset named {asset_name}")
    asset_headers = dict(headers)
    asset_headers["Accept"] = "application/octet-stream"
    response = _open(opener, urllib.request.Request(
        asset["url"], headers=asset_headers), f"asset {asset_name}", token)
    with response, open(destination, "wb") as fh:
        shutil.copyfileobj(response, fh)


def _extract_verified_archive(archive: str, *, asset_name: str,
                              expected_sha256: str,
                              destination: str) -> str:
    """Verify the one trust-boundary digest before creating extracted data."""
    actual = _sha256_file(archive)
    if actual != expected_sha256:
        _refuse(f"bundle asset {asset_name} SHA-256 is {actual}, "
                f"dataset manifest expected {expected_sha256}")
    os.makedirs(destination)
    with tarfile.open(archive, "r:gz") as bundle_archive:
        bundle_archive.extractall(destination)
    return actual


def _installation(project: str, version: str, manifest_path: str,
                  root: Optional[str]) -> tuple[dict, dict, str]:
    """Resolve the reviewed archive and refuse occupied destinations."""
    authority, block = _authority(project, version, manifest_path)
    asset = block["bundle"]["asset"]
    expected = asset["sha256"]
    if expected is None:
        index = _read_json(ASSET_INDEX, "mutation asset index")
        entry = (index.get("projects") or {}).get(project) or {}
        blocker = (entry.get("materialisation_audit") or {}).get(
            "release_blocker")
        _refuse(f"bundle {asset['name']} is not released: "
                f"{blocker or 'the asset digest has not been recorded'}")
    root = os.path.abspath(root or data_root())
    os.makedirs(root, exist_ok=True)
    project_destination = os.path.join(root, "projects", project)
    bundle_destination = os.path.join(root, "bundles", "v1", project)
    if os.path.lexists(project_destination) or os.path.lexists(bundle_destination):
        _refuse(f"bundle destination already exists for {project!r}")
    return authority, block, root


def _install_archive(archive: str, temporary: str, *, project: str,
                     version: str, root: str, authority: dict,
                     block: dict) -> dict:
    """Install only after the staged archive and all existing roles validate."""
    asset = block["bundle"]["asset"]
    extracted = os.path.join(temporary, "extracted")
    actual = _extract_verified_archive(
        archive, asset_name=asset["name"], expected_sha256=asset["sha256"],
        destination=extracted)
    facts = validate_installed_bundle(
        project, version, extracted, authority=authority, block=block)
    _install_roots(extracted, root, project_root=f"projects/{project}",
                   bundle_root=f"bundles/v1/{project}")
    return {**facts, "asset": asset["name"], "sha256": actual,
            "data_root": root}


def _install_roots(extracted: str, root: str, *, project_root: str,
                   bundle_root: str) -> None:
    """Commit the two validated owned trees; undo the first move on failure."""
    project_destination = os.path.join(root, *project_root.split("/"))
    bundle_destination = os.path.join(root, *bundle_root.split("/"))
    os.makedirs(os.path.dirname(project_destination), exist_ok=True)
    os.makedirs(os.path.dirname(bundle_destination), exist_ok=True)
    source_project = os.path.join(extracted, *project_root.split("/"))
    os.rename(source_project, project_destination)
    try:
        os.rename(os.path.join(extracted, *bundle_root.split("/")),
                  bundle_destination)
    except OSError:
        os.rename(project_destination, source_project)
        raise


def install_bundle(*, project: str, version: str, archive: str,
                   manifest_path: str = DATASET_MANIFEST,
                   release_index_path: Optional[str] = None,
                   root: Optional[str] = None) -> dict:
    """Install a local archive against its reviewed pin, without fetching."""
    from . import evaluation_bundle as evaluation
    if evaluation.is_evaluation_bundle(project, version):
        return evaluation.install_evaluation_bundle(
            project=project, version=version, archive=archive, root=root,
            release_index_path=release_index_path)
    if project == "algorand-sdk":
        from ..toolkit import algorand_bundle as native
        try:
            return native.install_bundle(
                version=version, archive=archive, root=root,
                release_index_path=release_index_path)
        except native.AlgorandBundleRefused as exc:
            _refuse(str(exc).removeprefix("REFUSED: "))
    authority, block, root = _installation(
        project, version, manifest_path, root)
    with tempfile.TemporaryDirectory(prefix=".r2t-bundle-", dir=root) as temp:
        staged = os.path.join(temp, block["bundle"]["asset"]["name"])
        # Hash and extract the same private snapshot, even if the operator's
        # source archive is replaced while installation is in progress.
        try:
            shutil.copyfile(archive, staged)
        except OSError as exc:
            _refuse(f"cannot read local bundle archive {archive}: {exc}")
        return _install_archive(
            staged, temp, project=project, version=version, root=root,
            authority=authority, block=block)


def fetch_bundle(*, project: str, version: str,
                 manifest_path: str = DATASET_MANIFEST,
                 release_index_path: Optional[str] = None,
                 root: Optional[str] = None, token: Optional[str] = None,
                 repository: Optional[str] = None,
                 opener: Callable = urllib.request.urlopen) -> dict:
    """Fetch, verify, validate, and install one released project bundle."""
    from . import evaluation_bundle as evaluation
    if evaluation.is_evaluation_bundle(project, version):
        return evaluation.fetch_evaluation_bundle(
            project=project, version=version, root=root,
            release_index_path=release_index_path, token=token,
            repository=repository, opener=opener)
    if project == "algorand-sdk":
        if repository is not None:
            _refuse("Algorand bundle repository comes from its release index")
        from ..toolkit import algorand_bundle as native
        try:
            return native.fetch_bundle(
                version=version, root=root, token=token,
                release_index_path=release_index_path, opener=opener)
        except native.AlgorandBundleRefused as exc:
            _refuse(str(exc).removeprefix("REFUSED: "))
    authority, block, root = _installation(
        project, version, manifest_path, root)
    asset = block["bundle"]["asset"]
    token = token or os.environ.get(GITHUB_TOKEN_ENV)
    repository = repository or os.environ.get(
        GITHUB_REPOSITORY_ENV, DEFAULT_GITHUB_REPOSITORY)

    with tempfile.TemporaryDirectory(prefix=".r2t-bundle-", dir=root) as temp:
        archive = os.path.join(temp, asset["name"])
        _download_asset(repository=repository, version=version,
                        asset_name=asset["name"], token=token,
                        destination=archive, opener=opener)
        return _install_archive(
            archive, temp, project=project, version=version, root=root,
            authority=authority, block=block)


def selftest() -> int:
    from types import SimpleNamespace
    from pathlib import Path
    from unittest import mock

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        ok = ok and bool(condition)
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))

    def refused(fn, text: str) -> bool:
        try:
            fn()
        except BundleRefused as exc:
            return text in str(exc)
        return False

    with tempfile.TemporaryDirectory() as temporary:
        import copy

        historical = os.path.join(temporary, "items.jsonl")
        annotated = os.path.join(temporary, "annotated_items.jsonl")
        old = [{"item_id": "one", "scenario": "read"},
               {"item_id": "two", "scenario": "write"}]
        new = [dict(old[0], target_interfaces={
            "behaviour": ["example.Reader"], "setup": ["example.Document"]}),
            dict(old[1], target_interfaces={"behaviour": [], "setup": []})]

        def write_rows(path, rows):
            with open(path, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row) + "\n")

        write_rows(historical, old)
        write_rows(annotated, new)
        annotation = {"file": "coreshop/eval100.jsonl",
                      "sha256": _sha256_file(annotated)}
        block = {"bundle": {"annotated_release": annotation, "artifacts": {
            "release_items": "projects/coreshop/artifacts/release/items.jsonl",
            "annotated_release_items":
                "projects/coreshop/artifacts/release/annotated_items.jsonl"}}}
        check("the annotated role is explicit and accepts populated/empty lists",
              _annotated_release_declaration("coreshop", block) == annotation
              and _validate_annotated_release(annotated, historical, annotation) == 2)
        legacy = {"bundle": {"artifacts": {}}}
        check("old manifests need no annotated role",
              _annotated_release_declaration("coreshop", legacy) is None)
        legacy["bundle"]["annotated_release"] = None
        legacy["bundle"]["artifacts"]["annotated_release_items"] = None
        check("explicit null declares no annotated role",
              _annotated_release_declaration("coreshop", legacy) is None)
        bad = copy.deepcopy(block)
        bad["bundle"]["artifacts"]["annotated_release_items"] = None
        check("a declared annotation cannot omit its role",
              refused(lambda: _annotated_release_declaration("coreshop", bad),
                      "own declared sibling path"))
        bad["bundle"]["artifacts"]["annotated_release_items"] = \
            bad["bundle"]["artifacts"]["release_items"]
        check("an annotated role cannot overwrite frozen release items",
              refused(lambda: _annotated_release_declaration("coreshop", bad),
                      "own declared sibling path"))

        write_rows(annotated, [dict(new[0], scenario="changed"), new[1]])
        check("installed annotation bytes must match their declared digest",
              refused(lambda: _validate_annotated_release(
                  annotated, historical, annotation), "annotated release SHA-256"))
        for name, rows, reason in (
                ("changed task", [dict(new[0], scenario="changed"), new[1]],
                 "historical tasks"),
                ("changed order", list(reversed(new)), "historical tasks"),
                ("missing item", new[:1], "task count"),
                ("missing annotation", old, "no `target_interfaces`"),
                ("wrong annotation shape", [dict(new[0], target_interfaces=[]), new[1]],
                 "must be a mapping"),
                ("unsorted types", [dict(new[0], target_interfaces={
                    "behaviour": ["Z", "A"], "setup": []}), new[1]], "not sorted"),
                ("duplicate types", [dict(new[0], target_interfaces={
                    "behaviour": ["A", "A"], "setup": []}), new[1]], "deduplicated"),
                ("overlapping lists", [dict(new[0], target_interfaces={
                    "behaviour": ["A"], "setup": ["A"]}), new[1]], "both")):
            write_rows(annotated, rows)
            measured = dict(annotation, sha256=_sha256_file(annotated))
            check(f"even a declared digest cannot admit {name}",
                  refused(lambda: _validate_annotated_release(
                      annotated, historical, measured), reason))

        # THE V2 ANNOTATION (TARGET_INTERFACES_V2_SPEC section 5).  A
        # companion may add `checked_interfaces` instead of, or beside, the
        # v1 lists, and it is held to the v2 renderer's shape rules -- the
        # same rules the prompt applies, because it is the same function.
        entry = {"key": ["example.Reader", "read"],
                 "declaration": "def read(self, path):"}
        v2 = [dict(old[0], checked_interfaces={
            "checked": [entry], "empty_reason": None}),
            dict(old[1], checked_interfaces={
                "checked": [], "empty_reason": "no_action_or_check_call"})]
        write_rows(annotated, v2)
        measured = dict(annotation, sha256=_sha256_file(annotated))
        check("a v2 companion is admitted, populated and empty-with-reason "
              "alike, with no v1 field present at all",
              _validate_annotated_release(annotated, historical, measured) == 2)
        write_rows(annotated, [dict(v2[0], target_interfaces={
            "behaviour": ["example.Reader"], "setup": []}), v2[1]])
        measured = dict(annotation, sha256=_sha256_file(annotated))
        check("a companion may carry both annotations at once",
              _validate_annotated_release(annotated, historical, measured) == 2)
        for name, rows, reason in (
                ("the v1 shape under the v2 key",
                 [dict(old[0], checked_interfaces={"behaviour": [], "setup": []}),
                  v2[1]], "exactly the keys `checked` and `empty_reason`"),
                ("an unsorted v2 list",
                 [dict(old[0], checked_interfaces={"checked": [
                     dict(entry, key=["z.Late", "m"]), entry],
                     "empty_reason": None}), v2[1]], "not sorted"),
                ("an entry with no declaration",
                 [dict(old[0], checked_interfaces={
                     "checked": [{"key": ["example.Reader", "read"]}],
                     "empty_reason": None}), v2[1]], "`declaration` string"),
                ("an empty v2 list with no reason",
                 [dict(old[0], checked_interfaces={"checked": [],
                                                   "empty_reason": None}),
                  v2[1]], "never an omission"),
                ("a reason this benchmark does not define",
                 [dict(old[0], checked_interfaces={"checked": [],
                                                   "empty_reason": "dunno"}),
                  v2[1]], "the only reason")):
            write_rows(annotated, rows)
            measured = dict(annotation, sha256=_sha256_file(annotated))
            check(f"even a declared digest cannot admit {name}",
                  refused(lambda: _validate_annotated_release(
                      annotated, historical, measured), reason))

    from ..toolkit import algorand_bundle as native_algorand
    routed = []
    real_fetch = native_algorand.fetch_bundle
    native_algorand.fetch_bundle = \
        lambda **kwargs: routed.append(kwargs) or {"fixture": True}
    try:
        fetch_bundle(project="algorand-sdk", version="1")
        fetch_bundle(project="algorand-sdk", version="2")
        fetch_bundle(project="algorand-sdk", version="3")
        fetch_bundle(project="algorand-sdk", version="4")
        fetch_bundle(project="algorand-sdk", version="5")
    finally:
        native_algorand.fetch_bundle = real_fetch
    check("generic Algorand fetch preserves the explicit version and lets "
          "the native route select its matching index",
          [call["version"] for call in routed]
          == ["1", "2", "3", "4", "5"]
          and all(call["release_index_path"] is None for call in routed))

    from . import bundle as module
    from ..bench import cli
    from ..toolkit.bundle_build import _write_archive
    import io

    with tempfile.TemporaryDirectory() as temporary:
        stage = Path(temporary, "stage")
        (stage / "projects/coreshop/seed").mkdir(parents=True)
        (stage / "projects/coreshop/seed/seed.json").write_text("{}\n")
        (stage / "bundles/v1/coreshop").mkdir(parents=True)
        (stage / "bundles/v1/coreshop/plan.json").write_text("{}\n")
        archive = str(Path(temporary, "local.tar.gz"))
        digest = _write_archive(str(stage), archive)
        declaration = {
            "schema": "r2t.dataset_manifest/3",
            "projects": {"coreshop": {"bundle": {
                "version": "fixture-v1",
                "asset": {"name": "declared.tar.gz", "sha256": digest},
                "artifacts": {"seed": "projects/coreshop/seed"},
                "seed": {"manifest_sha256": "0" * 64},
            }}},
        }
        manifest = str(Path(temporary, "manifest.json"))
        Path(manifest).write_text(json.dumps(declaration))
        installed = str(Path(temporary, "installed"))
        validated = []

        def accept(project, version, root, **kwargs):
            validated.append((project, version, root, kwargs))
            assert Path(root, "bundles/v1/coreshop/plan.json").read_text() == "{}\n"
            assert not Path(installed, "projects/coreshop").exists()
            return {"project": project, "version": version, "fixture": True}

        with mock.patch.object(module, "validate_installed_bundle", accept), \
                mock.patch.object(module, "_download_asset",
                                  side_effect=AssertionError("network reached")):
            report = module.install_bundle(
                project="coreshop", version="fixture-v1", archive=archive,
                manifest_path=manifest, root=installed)
        check("local generic install checks the declared digest and validates "
              "staged roles before installing both roots without a download",
              report == {"project": "coreshop", "version": "fixture-v1",
                         "fixture": True, "asset": "declared.tar.gz",
                         "sha256": digest, "data_root": installed}
              and len(validated) == 1
              and validated[0][3]["authority"] == declaration
              and Path(installed, "projects/coreshop/seed/seed.json")
                  .read_text() == "{}\n"
              and Path(installed, "bundles/v1/coreshop/plan.json")
                  .read_text() == "{}\n"
              and not any(Path(installed).glob(".r2t-bundle-*")))
        check("an occupied local destination refuses before reading the archive",
              refused(lambda: module.install_bundle(
                  project="coreshop", version="fixture-v1", archive="absent",
                  manifest_path=manifest, root=installed),
                  "destination already exists"))
        dangling_root = Path(temporary, "dangling")
        (dangling_root / "bundles/v1").mkdir(parents=True)
        (dangling_root / "bundles/v1/coreshop").symlink_to("missing")
        check("a dangling destination link is also an occupied destination",
              refused(lambda: module.install_bundle(
                  project="coreshop", version="fixture-v1", archive="absent",
                  manifest_path=manifest, root=str(dangling_root)),
                  "destination already exists")
              and (dangling_root / "bundles/v1/coreshop").is_symlink())

        bad_archive = Path(temporary, "corrupt.tar.gz")
        bad_archive.write_bytes(b"not the reviewed archive")
        corrupt_root = Path(temporary, "corrupt")
        with mock.patch.object(module, "validate_installed_bundle",
                               side_effect=AssertionError("validation reached")):
            corrupt_refused = refused(lambda: module.install_bundle(
                project="coreshop", version="fixture-v1", archive=str(bad_archive),
                manifest_path=manifest, root=str(corrupt_root)),
                "dataset manifest expected")
        check("a mismatched local archive installs no role and leaves no staging",
              corrupt_refused and list(corrupt_root.iterdir()) == [])
        invalid_root = Path(temporary, "invalid-roles")
        check("a digest-matching local archive still must pass the real seed gate",
              refused(lambda: module.install_bundle(
                  project="coreshop", version="fixture-v1", archive=archive,
                  manifest_path=manifest, root=str(invalid_root)),
                  "seed manifest differs")
              and list(invalid_root.iterdir()) == [])
        missing_root = Path(temporary, "missing-local")
        check("an unreadable local archive is a named refusal with no installation",
              refused(lambda: module.install_bundle(
                  project="coreshop", version="fixture-v1", archive="absent",
                  manifest_path=manifest, root=str(missing_root)),
                  "cannot read local bundle archive")
              and list(missing_root.iterdir()) == [])

        rollback_root = str(Path(temporary, "rename-failure"))
        real_rename = os.rename

        def fail_bundle_rename(source, destination):
            if destination == os.path.join(rollback_root, "bundles/v1/coreshop"):
                raise OSError("fixture second rename failure")
            return real_rename(source, destination)

        with mock.patch.object(module, "validate_installed_bundle",
                               return_value={"fixture": True}), \
                mock.patch.object(module.os, "rename", fail_bundle_rename):
            rolled_back = False
            try:
                module.install_bundle(
                    project="coreshop", version="fixture-v1", archive=archive,
                    manifest_path=manifest, root=rollback_root)
            except OSError as exc:
                rolled_back = "second rename failure" in str(exc)
        check("a failed second rename rolls back the first installed root",
              rolled_back
              and not Path(rollback_root, "projects/coreshop").exists()
              and not Path(rollback_root, "bundles/v1/coreshop").exists()
              and not any(Path(rollback_root).glob(".r2t-bundle-*"))
              and _sha256_file(archive) == digest)
        declaration["projects"]["coreshop"]["bundle"]["asset"]["sha256"] = None
        Path(manifest).write_text(json.dumps(declaration))
        unpinned_root = Path(temporary, "unpinned")
        check("an unrecorded archive pin refuses before reading local input",
              refused(lambda: module.install_bundle(
                  project="coreshop", version="fixture-v1", archive="absent",
                  manifest_path=manifest, root=str(unpinned_root)),
                  "asset digest has not been recorded")
              and not unpinned_root.exists())

        # The public command has no caller-supplied digest or manifest path.
        cli_calls = []
        with mock.patch.object(module, "install_bundle", side_effect=lambda **kw:
                               cli_calls.append(kw) or {"fixture": True}), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["bundle", "install", "--project", "coreshop",
                           "--version", "fixture-v1", "--archive", archive])
        check("bundle install CLI passes only project, version and local archive",
              rc == 0 and cli_calls == [{"project": "coreshop",
                                        "version": "fixture-v1",
                                        "archive": archive}])

        with mock.patch.object(native_algorand, "install_bundle",
                               return_value={"native": True}) as native_install:
            routed_local = module.install_bundle(
                project="algorand-sdk", version="5", archive=archive)
        check("generic local install routes Algorand to its versioned authority",
              routed_local == {"native": True}
              and native_install.call_args.kwargs == {
                  "version": "5", "archive": archive, "root": None,
                  "release_index_path": None})

    print("\n" + ("ALL PASS (bundle)" if ok else "FAILURES (bundle)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
