"""Mint one ``r2t.mutation-assets/1`` index from measured population evidence.

Nothing in this tree could MINT an asset-index entry for a Behat/PHP project.
``mutants validate`` only BINDS supplied bytes against an entry that already
exists (`bench/cli.py`, the ``--asset-index``/``--asset-project`` pair), the
only general writer sat inside `mutation_java.build_asset_index` behind two
Java-pinned lines, and `scripts/prepare_coreshop_mutation_authority.py`
rewrites the three measured fields of ONE frozen CoreShop template.  A newly
onboarded Behat project therefore had a population, a map and an audit, and
no way to name them together.

The construction here is the Java one with its two pinned lines lifted into
parameters -- the expected engine name, and the engine source whose bytes the
entry binds.  `mutation_java.build_asset_index` is now a call to it and its
output for Java is byte-identical (checked in that module's own self-test
against an entry built inline from the same fixture).

WHAT THE MINT WRITES, and why it is two documents.  The index alone is what
`require_index_release_ready` reads.  It is not what the consumers open:
`bundle_build`, the evaluation-reference route and every cached-gold reader go
through `validate_saved_validation_report`, which wants the native
``r2t.mutation-validation/1`` report *beside* the index -- the same report
`scripts/prepare_coreshop_mutation_authority.py` writes for CoreShop.  A minted
index with no report beside it is an index no consumer can use, so `mint`
produces both or neither.

WHAT THE MINT DOES NOT DO.  It runs nothing: no engine, no container, no
enumeration.  Every input is evidence some other verb already produced, and
the mint's whole job is to refuse unless those documents describe one world.
In particular the materialisation audit is READ, never inferred: an incomplete
or field-short report is named and refused rather than patched, because the
alternative is an index whose ``materialisation_audit`` block asserts a
completed audit that no attestation supports.
"""
from __future__ import annotations

import os
from typing import Optional

from ..data import mutation as M
from ..data import mutation_attestation as A


def _refuse(message: str) -> None:
    raise A.MutationAssetRefused("REFUSED: " + message)


#: ``materialisation_audit`` index field <- path into the audit report.
#:
#: The document is written in two layers, and both are the same on every
#: route.  `mutation_audit.audit_population` writes the population, source-set
#: and counter fields; the caller that actually RAN an engine then attaches
#: `operator_gate` and recomputes `digest` over it -- `audit_with_engine` for
#: the PHP/Python route (`mutation_audit.py`, after `verify_runtime_binding`)
#: and `mutation_java.audit_population_in_image` for the Java one.  A report
#: from either therefore carries all of these, and the table exists so a
#: report that does not is refused BY FIELD NAME rather than through a
#: `KeyError` naming nothing an operator can act on.
_AUDIT_SOURCES = (
    ("attestation_digest", ("digest",)),
    ("bounded_roots", ("bounded_roots",)),
    ("n_source_files", ("n_source_files",)),
    ("source_set_sha256", ("source_set_sha256_before",)),
    ("runtime_parser_identity", ("operator_gate", "runtime_parser_identity")),
    ("engine_source_sha256", ("operator_gate", "engine_source_sha256")),
)


def _materialisation_audit(audit: dict, *, expected_mutants: int,
                           audit_path: Optional[str]) -> dict:
    """The index's audit block, read field by field from the attestation."""
    label = ("materialisation audit report " + audit_path if audit_path
             else "the materialisation audit report")
    if not isinstance(audit, dict):
        _refuse(f"{label} is not a JSON object")
    status = audit.get("status")
    if status != "complete":
        _refuse(f"{label} has status {status!r}. Only a COMPLETE audit may be "
                "minted into an asset index: the entry it would write asserts "
                "a finished full materialisation, and nothing else here can "
                "make that true")
    block = {"expected_mutants": expected_mutants, "status": "complete",
             "release_blocker": None}
    for field, source in _AUDIT_SOURCES:
        value = audit
        for key in source:
            if not isinstance(value, dict) or key not in value:
                _refuse(f"{label} has no {'.'.join(source)}, which the asset "
                        f"index binds as materialisation_audit.{field}")
            value = value[key]
        block[field] = value
    return block


def _scored_population(raw_manifest: dict, raw_facts: dict,
                       scored_manifest: dict, scored_facts: dict) -> dict:
    """The scored-population block, in one of the two roles the index has.

    `validate_asset_index` accepts exactly ``raw_equals_scored`` and
    ``boundary_scored``, and `validate_index_binding` REDERIVES the scored
    manifest for each -- from `derive_raw_equals_scored_manifest` and
    `derive_boundary_scored_manifest` respectively.  So the role is not a
    label the mint chooses: it is a statement about which derivation produced
    the second manifest, and a scored manifest that is neither is refused
    here rather than turned into whichever role fits its counts.
    """
    if scored_manifest == raw_manifest:
        return {
            "role": "raw_equals_scored",
            "n": raw_manifest["n"],
            "manifest_digest": raw_manifest["digest"],
            "canonical_sha256": raw_facts["canonical_sha256"],
            "raw_manifest_digest": raw_manifest["digest"],
            "n_non_production_excluded": 0,
        }
    role = scored_manifest.get("population_role", "raw")
    if role != "boundary_scored":
        _refuse(
            "the scored population is neither the raw catalogue itself "
            f"(raw_equals_scored) nor a boundary derivation of it: its "
            f"population_role is {role!r}. `mutants build --boundary ... "
            "--raw-out` writes the two manifests this index accepts; a third "
            "population has no role in r2t.mutation-assets/1")
    return {
        "role": "boundary_scored",
        "n": scored_manifest["n"],
        "manifest_digest": scored_manifest["digest"],
        "canonical_sha256": scored_facts["canonical_sha256"],
        "raw_manifest_digest": scored_manifest["raw_manifest_digest"],
        "n_non_production_excluded":
            scored_manifest["n_non_production_excluded"],
    }


def build_asset_entry(*, engine: str, engine_source_path: str,
                      raw_manifest: dict, raw_manifest_path: str,
                      scored_manifest: dict, mapping: dict,
                      coverage_path: str, release_path: str,
                      boundary_path: str, audit: dict,
                      audit_path: Optional[str] = None) -> dict:
    """One project's entry, derived from the exact evidence it names."""
    raw_facts = A.validate_manifest(raw_manifest, expected_engine=engine)
    if scored_manifest == raw_manifest:
        scored_facts = raw_facts
    else:
        scored_facts = A.validate_manifest(
            scored_manifest, expected_engine=engine, raw_manifest=raw_manifest)
    # The role first: it is a statement about the two manifests alone, and
    # the map below is validated AGAINST the scored one -- so a third
    # population would otherwise be reported as a map/manifest digest
    # mismatch, which names the wrong document.
    scored_population = _scored_population(
        raw_manifest, raw_facts, scored_manifest, scored_facts)
    release_ids = A.load_release_ids(release_path)
    coverage = A.coverage_from_rows(A.load_jsonl(coverage_path))
    map_facts = A.validate_map(
        mapping, scored_manifest, release_ids=release_ids,
        coverage_by_item=coverage)
    engine_source_sha256 = A.sha256_file(engine_source_path)
    return {
        "engine": scored_manifest["engine"],
        "engine_version": scored_manifest["engine_version"],
        "parser": scored_manifest["parser"],
        "raw_population": {
            "role": "pre_boundary_catalogue",
            "n": raw_manifest["n"],
            "manifest_digest": raw_manifest["digest"],
            "canonical_sha256": raw_facts["canonical_sha256"],
            "preserved_file_sha256": A.sha256_file(raw_manifest_path),
        },
        "scored_population": scored_population,
        "boundary": {
            "config": os.path.basename(boundary_path),
            "classification": "production",
            "sha256": A.sha256_file(boundary_path),
        },
        "mutation_map": {
            "manifest_role": "scored_population",
            "n_mutants": map_facts["n_mutants"],
            "n_mapped": map_facts["n_mapped"],
            "n_uncovered": map_facts["n_uncovered"],
            "n_pairs": map_facts["n_pairs"],
            "digest": map_facts["digest"],
            "canonical_sha256": map_facts["canonical_sha256"],
            "coverage_sha256": A.sha256_file(coverage_path),
            "release_sha256": A.sha256_file(release_path),
        },
        "coverage_oracle": {
            "rows": len(coverage), "sha256": A.sha256_file(coverage_path)},
        "release": {
            "items": len(release_ids), "sha256": A.sha256_file(release_path)},
        "engine_source": {"sha256": engine_source_sha256},
        "materialisation_audit": _materialisation_audit(
            audit, expected_mutants=raw_manifest["n"], audit_path=audit_path),
    }


def build_asset_index(project: str, **kwargs) -> dict:
    """One validated single-project ``r2t.mutation-assets/1`` index."""
    index = {
        "schema": A.ASSET_INDEX_SCHEMA,
        "version": 1,
        "projects": {project: build_asset_entry(**kwargs)},
    }
    projection = A.coverage_projection_identity(project, kwargs["coverage_path"],
                                                 kwargs["release_path"], kwargs["boundary_path"])
    if projection is not None:
        index["projects"][project]["coverage_oracle"]["projection_sha256"] = projection
    A.validate_asset_index(index)
    return index


def _report_references(paths: dict, report_path: str) -> tuple[dict, str]:
    """Root-relative input references for the portable native report.

    `validate_saved_validation_report` resolves every input against the root
    the report declares and refuses one that resolves outside it, so the root
    is the common ancestor of the report and its inputs -- which is what
    `scripts/prepare_coreshop_mutation_authority.py` computes too.  Computed
    BEFORE the outputs are reserved: a caller whose inputs and outputs share
    no ancestor should learn that without leaving a reserved file behind.
    """
    report_directory = os.path.dirname(os.path.abspath(report_path))
    try:
        root = os.path.commonpath([report_directory, *paths.values()])
    except ValueError as exc:
        _refuse(f"the mint outputs and their inputs share no common root "
                f"({exc}); a portable native validation report cannot name "
                "them from one declared root")
    references = {label: os.path.relpath(path, root)
                  for label, path in paths.items()}
    return references, os.path.relpath(root, report_directory)


def mint(project: str, *, raw_manifest_path: str, scored_manifest_path: str,
         map_path: str, coverage_path: str, release_path: str,
         boundary_path: str, audit_path: str, asset_index_out: str,
         validation_out: str, engine_source_path: Optional[str] = None,
         expected_engine: str = M.ENGINE) -> dict:
    """Mint one project's asset index and the native report beside it.

    ``expected_engine`` defaults to the Behat/PHP engine because that is the
    stack this entry point exists for; a Java or Python manifest handed to it
    refuses at `validate_manifest` instead of minting an entry checked against
    the wrong engine's identity.
    """
    from . import mutation_audit as AUDIT

    raw_manifest = A._read_json_object(
        raw_manifest_path, "raw mutation population")
    scored_manifest = (
        raw_manifest if os.path.abspath(scored_manifest_path)
        == os.path.abspath(raw_manifest_path)
        else A._read_json_object(
            scored_manifest_path, "scored mutation population"))
    mapping = A._read_json_object(map_path, "mutation map")
    # The audit is accepted either as the bare attestation `audit_with_engine`
    # returns or wrapped in the validation report that carried it, exactly as
    # `mutants validate --audit-attestation` and `build_native_validation_report`
    # accept it.  One shape on disk, two producers.
    audit_document = A._read_json_object(audit_path, "materialisation audit")
    audit = audit_document.get("materialisation_audit", audit_document)

    if engine_source_path is None:
        from ..bench.mutation_run import binding_for
        engine_dir, applier = binding_for(raw_manifest.get("engine"))
        engine_source_path = os.path.join(engine_dir, applier.source)

    index = build_asset_index(
        project, engine=expected_engine,
        engine_source_path=engine_source_path,
        raw_manifest=raw_manifest, raw_manifest_path=raw_manifest_path,
        scored_manifest=scored_manifest, mapping=mapping,
        coverage_path=coverage_path, release_path=release_path,
        boundary_path=boundary_path, audit=audit, audit_path=audit_path)
    A.validate_index_binding(
        index, project, raw_manifest=raw_manifest,
        scored_manifest=scored_manifest, mapping=mapping,
        boundary_path=boundary_path, coverage_path=coverage_path,
        release_path=release_path, engine_source_path=engine_source_path,
        raw_manifest_path=raw_manifest_path, audit_attestation=audit,
        require_release_ready=True)

    paths = {label: os.path.abspath(path) for label, path in (
        ("raw_manifest", raw_manifest_path),
        ("manifest", scored_manifest_path),
        ("map", map_path),
        ("coverage_run", coverage_path),
        ("release", release_path),
        ("boundary", boundary_path),
        ("engine_source", engine_source_path),
        ("audit_attestation", audit_path),
        ("asset_index", asset_index_out))}
    references, relative_to_report = _report_references(paths, validation_out)

    index_fd, report_fd = AUDIT.reserve_outputs(
        (asset_index_out, validation_out),
        input_paths=[path for label, path in paths.items()
                     if label != "asset_index"])
    AUDIT.write_reserved_json(index_fd, index)
    report = AUDIT.build_native_validation_report(
        project=project, paths=paths, references=references,
        relative_to_report=relative_to_report)
    AUDIT.write_reserved_json(report_fd, report)
    A.validate_saved_validation_report(
        validation_out, expected_validation_class="native",
        require_release_ready=True)
    entry = index["projects"][project]
    return {
        "project": project,
        "asset_index": os.path.abspath(asset_index_out),
        "mutation_validation": os.path.abspath(validation_out),
        "engine": entry["engine"],
        "parser": entry["parser"],
        "raw_n": entry["raw_population"]["n"],
        "scored_role": entry["scored_population"]["role"],
        "scored_n": entry["scored_population"]["n"],
        "n_pairs": entry["mutation_map"]["n_pairs"],
        "release_items": entry["release"]["items"],
        "audit_digest": entry["materialisation_audit"]["attestation_digest"],
    }


def selftest() -> int:
    import contextlib
    import io
    import json
    import tempfile

    from ..core.boundary import load_boundary
    from ..bench.mutation_run import binding_for

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    def refused(fn, fragment):
        try:
            fn()
        except (A.MutationAssetRefused, ValueError) as exc:
            return fragment in str(exc)
        return False

    engine_dir, applier = binding_for(M.ENGINE)
    engine_source = os.path.join(engine_dir, applier.source)
    engine_sha256 = A.sha256_file(engine_source)
    parser_identity = "nikic/php-parser 5.3.1@0d1a1c1"

    def php_manifest(records, **kwargs):
        return M.build_manifest(records, parser_version=parser_identity,
                                exclusions=("!src", "vendor/"), **kwargs)

    def audit_for(manifest, roots=("src",), files=3):
        document = {
            "schema": A.AUDIT_SCHEMA,
            "status": "complete",
            "manifest_digest": manifest["digest"],
            "engine": manifest["engine"],
            "engine_version": manifest["engine_version"],
            "parser": manifest["parser"],
            "n_mutants": manifest["n"],
            "n_attempted": manifest["n"],
            "n_applied": manifest["n"],
            "n_parse_valid": manifest["n"],
            "n_restored": manifest["n"],
            "n_source_files": files,
            "bounded_roots": list(roots),
            "source_set_sha256_before": "a" * 64,
            "source_set_sha256_after": "a" * 64,
            "source_lstat_sha256_before": "b" * 64,
            "source_lstat_sha256_after": "b" * 64,
            "failing_mutant_id": None,
            "failure_stage": None,
            "failure": None,
            "collateral": {"added": [], "changed": [], "deleted": []},
            "operator_gate": {
                "mode": "real_engine",
                "disposable_marker": A.DISPOSABLE_MARKER,
                "engine_source_sha256": engine_sha256,
                "runtime_parser_identity": manifest["parser"],
                "runtime_parser_reported":
                    A.expected_runtime_parser(manifest),
            },
        }
        document["digest"] = A.audit_digest(document)
        return document

    with tempfile.TemporaryDirectory(prefix="r2t-mint-assets-") as temporary:
        root = os.path.abspath(temporary)

        def write(name, value):
            path = os.path.join(root, name)
            with open(path, "wb") as handle:
                handle.write(A.canonical_bytes(value) + b"\n")
            return path

        def write_rows(name, rows):
            path = os.path.join(root, name)
            with open(path, "wb") as handle:
                for row in rows:
                    handle.write(A.canonical_bytes(row) + b"\n")
            return path

        boundary_path = os.path.join(root, "boundary_fixture.yml")
        with open(boundary_path, "w", encoding="utf-8") as handle:
            handle.write(
                "version: 1\n"
                "project: fixture\n"
                "repo_root: /nonexistent/fixture\n"
                "removable:\n"
                "  - path: src/Behat/\n"
                "    why: the fixture's Behat glue\n"
                "retained: []\n")
        boundary = load_boundary(boundary_path)

        production = [
            {"file": "src/App/Money.php", "operator": "ArithmeticOperator",
             "start_line": line, "start_col": 3,
             "original": "+", "mutated": "-"}
            for line in (1, 2)]
        glue = [{"file": "src/Behat/Context/Api/ThingContext.php",
                 "operator": "ArithmeticOperator", "start_line": 1,
                 "start_col": 3, "original": "+", "mutated": "-"}]
        raw_manifest = php_manifest(production + glue)
        scored_manifest = A.derive_boundary_scored_manifest(
            raw_manifest, boundary, boundary_path,
            A.sha256_file(boundary_path))
        check("the fixture population really loses a mutant at the boundary",
              raw_manifest["n"] == 3 and scored_manifest["n"] == 2
              and scored_manifest["n_non_production_excluded"] == 1)

        raw_path = write("population_raw.json", raw_manifest)
        scored_path = write("population.json", scored_manifest)
        release_path = write_rows(
            "release.jsonl", [{"item_id": "item-a"}, {"item_id": "item-b"}])
        coverage_rows = [
            {"item_id": "item-a",
             "coverage_lines": {"src/App/Money.php": [1]}},
            {"item_id": "item-b",
             "coverage_lines": {"src/App/Money.php": [2]}}]
        coverage_path = write_rows("gold.jsonl", coverage_rows)
        coverage = A.coverage_from_rows(coverage_rows)
        by_mutant, uncovered = M.map_mutants_to_items(
            scored_manifest, coverage)
        mapping = A.build_map_artifact(
            scored_manifest, by_mutant, uncovered,
            coverage_sha256=A.sha256_file(coverage_path),
            release_sha256=A.sha256_file(release_path))
        map_path = write("mutant_map.json", mapping)
        audit_path = write("audit.json", audit_for(raw_manifest))

        def mint_into(directory, **overrides):
            os.makedirs(os.path.join(root, directory), exist_ok=True)
            arguments = {
                "raw_manifest_path": raw_path,
                "scored_manifest_path": scored_path,
                "map_path": map_path,
                "coverage_path": coverage_path,
                "release_path": release_path,
                "boundary_path": boundary_path,
                "audit_path": audit_path,
                "asset_index_out": os.path.join(
                    root, directory, "asset_index.json"),
                "validation_out": os.path.join(
                    root, directory, "mutation_validation.json"),
            }
            arguments.update(overrides)
            return mint("fixture", **arguments)

        answer = mint_into("minted")
        with open(os.path.join(root, "minted", "asset_index.json"),
                  encoding="utf-8") as handle:
            minted = json.load(handle)
        entry = minted["projects"]["fixture"]
        expected_entry = {
            "engine": M.ENGINE,
            "engine_version": M.ENGINE_VERSION,
            "parser": parser_identity,
            "raw_population": {
                "role": "pre_boundary_catalogue",
                "n": 3,
                "manifest_digest": raw_manifest["digest"],
                "canonical_sha256": A.canonical_sha256(raw_manifest),
                "preserved_file_sha256": A.sha256_file(raw_path),
            },
            "scored_population": {
                "role": "boundary_scored",
                "n": 2,
                "manifest_digest": scored_manifest["digest"],
                "canonical_sha256": A.canonical_sha256(scored_manifest),
                "raw_manifest_digest": raw_manifest["digest"],
                "n_non_production_excluded": 1,
            },
            "boundary": {
                "config": "boundary_fixture.yml",
                "classification": "production",
                "sha256": A.sha256_file(boundary_path),
            },
            "mutation_map": {
                "manifest_role": "scored_population",
                "n_mutants": 2, "n_mapped": 2, "n_uncovered": 0,
                "n_pairs": 2,
                "digest": mapping["digest"],
                "canonical_sha256": A.canonical_sha256(mapping),
                "coverage_sha256": A.sha256_file(coverage_path),
                "release_sha256": A.sha256_file(release_path),
            },
            "coverage_oracle": {
                "rows": 2, "sha256": A.sha256_file(coverage_path)},
            "release": {"items": 2, "sha256": A.sha256_file(release_path)},
            "engine_source": {"sha256": engine_sha256},
            "materialisation_audit": {
                "expected_mutants": 3,
                "status": "complete",
                "attestation_digest": audit_for(raw_manifest)["digest"],
                "release_blocker": None,
                "bounded_roots": ["src"],
                "n_source_files": 3,
                "source_set_sha256": "a" * 64,
                "runtime_parser_identity": parser_identity,
                "engine_source_sha256": engine_sha256,
            },
        }
        check("a Behat/PHP population mints the exact boundary-scored entry",
              entry == expected_entry,
              detail=str(sorted(
                  key for key in set(entry) | set(expected_entry)
                  if entry.get(key) != expected_entry.get(key))))
        check("the mint reports the role, the counts and the audit it bound",
              answer["scored_role"] == "boundary_scored"
              and answer["raw_n"] == 3 and answer["scored_n"] == 2
              and answer["n_pairs"] == 2 and answer["release_items"] == 2
              and answer["audit_digest"]
              == expected_entry["materialisation_audit"][
                  "attestation_digest"])

        A.validate_asset_index(minted)
        A.require_index_release_ready(minted, "fixture")
        binding = A.validate_index_binding(
            minted, "fixture", raw_manifest=raw_manifest,
            scored_manifest=scored_manifest, mapping=mapping,
            boundary_path=boundary_path, coverage_path=coverage_path,
            release_path=release_path, engine_source_path=engine_source,
            raw_manifest_path=raw_path,
            audit_attestation=audit_for(raw_manifest),
            require_release_ready=True)
        check("the minted index is release-ready and binds its own bytes "
              "through the validator `mutants validate` uses",
              binding["index_binding"] == "valid"
              and binding["release_ready"] is True
              and binding["boundary_derivation"] == {
                  "role": "boundary_scored", "n_raw": 3, "n_scored": 2,
                  "n_non_production_excluded": 1})

        saved = A.validate_saved_validation_report(
            os.path.join(root, "minted", "mutation_validation.json"),
            expected_validation_class="native", require_release_ready=True)
        check("the native report written beside the index reopens through "
              "the reader every consumer uses",
              isinstance(saved, dict))

        # The Sylius case, in miniature: a boundary whose removable/retained
        # lists are EMPTY, so every row classifies production and the scored
        # role would exclude nothing -- which is what `validate_asset_index`
        # refuses by name ("boundary_scored role excludes no rows", the
        # refusal the live mint hit on 2026-09-10).  The project's own
        # `mutation_exclude` row is what makes the population product code
        # only, and the mint has to accept THAT as the exclusion.
        declared_boundary_path = os.path.join(root, "boundary_declared.yml")
        with open(declared_boundary_path, "w", encoding="utf-8") as handle:
            handle.write(
                "version: 1\n"
                "project: fixture\n"
                "repo_root: /nonexistent/fixture\n"
                "removable: []\n"
                "retained: []\n"
                "behat:\n"
                "  prod_paths: [src]\n"
                "  mutation_exclude: [Behat/]\n")
        declared_boundary = load_boundary(declared_boundary_path)
        declared_scored = A.derive_boundary_scored_manifest(
            raw_manifest, declared_boundary, declared_boundary_path,
            A.sha256_file(declared_boundary_path))
        check("a boundary that classifies every row production still loses "
              "the rows its own `mutation_exclude` row declares non-product",
              all(declared_boundary.classify(mutant["file"]) == "production"
                  for mutant in raw_manifest["mutants"])
              and declared_scored["n"] == 2
              and declared_scored["n_non_production_excluded"] == 1
              and declared_scored["n_mutation_excluded"] == 1)
        declared_by_mutant, declared_uncovered = M.map_mutants_to_items(
            declared_scored, coverage)
        declared_map = A.build_map_artifact(
            declared_scored, declared_by_mutant, declared_uncovered,
            coverage_sha256=A.sha256_file(coverage_path),
            release_sha256=A.sha256_file(release_path))
        declared_answer = mint_into(
            "minted_declared",
            scored_manifest_path=write("population_declared.json",
                                       declared_scored),
            map_path=write("mutant_map_declared.json", declared_map),
            boundary_path=declared_boundary_path)
        with open(os.path.join(root, "minted_declared", "asset_index.json"),
                  encoding="utf-8") as handle:
            declared_index = json.load(handle)
        check("...and the index minted from it passes the release-ready "
              "check that refuses a boundary_scored role excluding no rows, "
              "over the SAME raw catalogue and the same materialisation "
              "audit",
              declared_answer["scored_role"] == "boundary_scored"
              and declared_answer["raw_n"] == 3
              and declared_answer["scored_n"] == 2
              and declared_index["projects"]["fixture"]["raw_population"]
              == expected_entry["raw_population"]
              and declared_index["projects"]["fixture"][
                  "materialisation_audit"]
              == expected_entry["materialisation_audit"]
              and not refused(lambda: A.require_index_release_ready(
                  declared_index, "fixture"), "excludes no rows"),
              json.dumps(declared_answer))

        check("an occupied output is refused rather than replaced",
              refused(lambda: mint_into("minted"),
                      "output already exists and will not be replaced"))

        short_audit = audit_for(raw_manifest)
        del short_audit["n_source_files"]
        short_audit["digest"] = A.audit_digest(short_audit)
        short_path = write("audit_short.json", short_audit)
        check("an audit report missing a bound field is named, not patched",
              refused(lambda: mint_into("short", audit_path=short_path),
                      f"materialisation audit report {short_path} has no "
                      "n_source_files"))

        gateless = audit_for(raw_manifest)
        del gateless["operator_gate"]["engine_source_sha256"]
        gateless["digest"] = A.audit_digest(gateless)
        gateless_path = write("audit_gateless.json", gateless)
        check("a gate missing the engine source digest is named too",
              refused(lambda: mint_into("gateless",
                                        audit_path=gateless_path),
                      "has no operator_gate.engine_source_sha256"))

        provisional = audit_for(raw_manifest)
        provisional["status"] = "failed"
        provisional["digest"] = A.audit_digest(provisional)
        provisional_path = write("audit_failed.json", provisional)
        check("an audit that did not complete cannot be minted",
              refused(lambda: mint_into("failed",
                                        audit_path=provisional_path),
                      "Only a COMPLETE audit may be minted"))

        third = php_manifest(production)
        third_path = write("population_third.json", third)
        check("a scored population that is neither role is refused",
              refused(lambda: mint_into("third",
                                        scored_manifest_path=third_path),
                      "neither the raw catalogue itself"))

        # The shim is argparse over `mint`, and this is the one refusal that
        # does not come out of `mint` itself: `binding_for` raises
        # `MutationAborted` -- a RuntimeError -- for an engine no applier
        # knows, which is reachable whenever the manifest names one and
        # `--engine-source` was left to default.
        from scripts import mint_mutation_assets as SHIM
        unknown_engine = write("population_unknown_engine.json",
                               {**raw_manifest, "engine": "r2t-mutate-nowhere"})
        complaint = io.StringIO()
        with contextlib.redirect_stderr(complaint):
            code = SHIM.main([
                "--project", "fixture",
                "--raw-manifest", unknown_engine,
                "--manifest", unknown_engine,
                "--map", map_path, "--coverage-run", coverage_path,
                "--release", release_path, "--boundary", boundary_path,
                "--audit-attestation", audit_path,
                "--asset-index-out",
                os.path.join(root, "unknown", "asset_index.json"),
                "--validation-out",
                os.path.join(root, "unknown", "mutation_validation.json")])
        check("an engine no applier knows leaves the script's refusal line, "
              "not a traceback",
              code == 1 and complaint.getvalue().startswith("REFUSED: ")
              and "r2t-mutate-nowhere" in complaint.getvalue(),
              detail=repr(complaint.getvalue()[:120]))

        # -- raw_equals_scored: the role the Java route uses, reached here by
        #    naming the raw catalogue as the scored population.  The fixture
        #    boundary must exclude nothing from it, which is why it is built
        #    from the production records alone.
        equal_raw = php_manifest(production)
        equal_path = write("population_equal.json", equal_raw)
        equal_map = A.build_map_artifact(
            equal_raw, *M.map_mutants_to_items(equal_raw, coverage),
            coverage_sha256=A.sha256_file(coverage_path),
            release_sha256=A.sha256_file(release_path))
        equal_map_path = write("mutant_map_equal.json", equal_map)
        equal_audit_path = write(
            "audit_equal.json", audit_for(equal_raw, files=2))
        equal_answer = mint_into(
            "equal", raw_manifest_path=equal_path,
            scored_manifest_path=equal_path, map_path=equal_map_path,
            audit_path=equal_audit_path)
        with open(os.path.join(root, "equal", "asset_index.json"),
                  encoding="utf-8") as handle:
            equal_index = json.load(handle)
        check("naming one catalogue as both populations mints "
              "raw_equals_scored",
              equal_answer["scored_role"] == "raw_equals_scored"
              and equal_index["projects"]["fixture"]["scored_population"] == {
                  "role": "raw_equals_scored", "n": 2,
                  "manifest_digest": equal_raw["digest"],
                  "canonical_sha256": A.canonical_sha256(equal_raw),
                  "raw_manifest_digest": equal_raw["digest"],
                  "n_non_production_excluded": 0})
        A.validate_saved_validation_report(
            os.path.join(root, "equal", "mutation_validation.json"),
            expected_validation_class="native", require_release_ready=True)

    print("mutation_asset_index selftest: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1
