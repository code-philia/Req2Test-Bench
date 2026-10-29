"""Standard N=3 release gate for the research-minimal Java path.

This validates ordinary ``validation.jsonl`` evidence.  It is deliberately
not a publication-v3/result-v3 lifecycle: each candidate has three no-glue
runs, three exact-gold runs, six separately hashed raw records, and one
manifest joining the image/reality/source identities to the generated release
count.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import tempfile
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Protocol, Sequence

from ..bench.validate import HARNESS_VERSION
from . import research_minimal as minimal
from .closure_java import ClosureJavaError, dry_run_contract
from .research_minimal import (PATH, PROJECTS, precontact_admission,
                               validate_research_census)


SCHEMA = "r2t.java-standard-validation-manifest/1"
RUN_SCHEMA = "r2t.java-standard-validation-run/1"
PHASE_SCHEMA = "r2t.java-research-minimal-validation/1"
RELEASE_MANIFEST_SCHEMA = "r2t.java-research-minimal-release-manifest/1"
RELEASE_RECEIPT_SCHEMA = "r2t.java-research-minimal-release-receipt/1"
SOURCE_ARTIFACTS_SCHEMA = "r2t.java-research-minimal-source-artifacts/1"
MUTATION_AUTHORITY_DIR = "java-mutation-authority"
REPEATS = 3
MISSING_GLUE = "undefined_steps"
_REASON = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_WORKER = re.compile(r"r2t-java-release-[0-9a-f]{32}\Z")
_PID_FILE = re.compile(r"/tmp/r2t-cucumber-[0-9]+-[0-9]+\.pid\Z")
_ITEM_BUILD_CLEANUP = (
    "rm -rf -- target/test-classes && test ! -e target/test-classes")
_CANDIDATE_TEST_CLASSES_CLEANUP = "rm -rf -- target/test-classes"
REQUIRED_BINDINGS = frozenset({
    "source", "base_repository_digest", "base_config_id",
    "discovery_manifest", "discovery_payload_tree", "canonical_dockerfile",
    "canonical_transcript", "canonical_image_id", "reality_manifest",
    "boundary", "profile", "strip", "gold", "release",
})


class JavaReleaseValidationRefused(RuntimeError):
    pass


def _refuse(message: str) -> JavaReleaseValidationRefused:
    return JavaReleaseValidationRefused("REFUSED: " + message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_jsonl(path: str) -> tuple[list[dict], bytes]:
    raw = Path(path).read_bytes()
    try:
        rows = [json.loads(line) for line in raw.splitlines() if line]
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse(f"{path} is not UTF-8 JSONL") from exc
    if any(not isinstance(row, dict) for row in rows):
        raise _refuse(f"{path} contains a non-object row")
    return rows, raw


def _read_map(path: str, *, array: bool = False) -> tuple[dict, bytes]:
    raw = Path(path).read_bytes()
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse(f"{path} is not UTF-8 JSON") from exc
    if array:
        if not isinstance(value, list) or any(not isinstance(row, dict)
                                              for row in value):
            raise _refuse(f"{path} is not an object array")
        rows = value
    elif not isinstance(value, dict):
        raise _refuse(f"{path} is not an object")
    else:
        return value, raw
    out = {}
    for row in rows:
        item_id = row.get("item_id")
        if not isinstance(item_id, str) or not item_id or item_id in out:
            raise _refuse(f"{path} repeats or omits item_id")
        out[item_id] = row
    return out, raw


def _machine_reason(value: object, label: str) -> str:
    if not isinstance(value, str) or _REASON.fullmatch(value) is None:
        raise _refuse(f"{label} is not one machine-readable reason")
    return value


def _complete_closure_ledger(rows: Mapping[str, dict],
                             eligible: set[str]) -> dict[str, dict]:
    if set(rows) != eligible:
        raise _refuse("closure ledger is not the complete admitted population")
    out = {}
    for item_id in sorted(eligible):
        row = rows[item_id]
        files = row.get("files")
        admitted = row.get("admitted")
        reason = row.get("reason")
        if not isinstance(admitted, bool) or not isinstance(files, list) \
                or any(not isinstance(path, str) or not path for path in files) \
                or len(files) != len(set(files)):
            raise _refuse(f"{item_id}: closure disposition is malformed")
        if admitted:
            if reason is not None or not files:
                raise _refuse(f"{item_id}: admitted closure is empty/reasoned")
        else:
            _machine_reason(reason, f"{item_id} closure reason")
        out[item_id] = {"admitted": admitted, "reason": reason}
    return out


def _complete_quality_ledger(rows: Mapping[str, dict],
                             eligible: set[str]) -> dict[str, dict]:
    if set(rows) != eligible:
        raise _refuse("quality ledger is not the complete admitted population")
    out = {}
    for item_id in sorted(eligible):
        row = rows[item_id]
        admitted = row.get("admitted")
        reason = row.get("reason")
        oracle = row.get("has_oracle")
        if not isinstance(admitted, bool) or not isinstance(oracle, bool):
            raise _refuse(f"{item_id}: quality disposition is malformed")
        if admitted:
            if reason is not None or not oracle:
                raise _refuse(f"{item_id}: admitted quality lacks an oracle")
        else:
            _machine_reason(reason, f"{item_id} quality reason")
        out[item_id] = {"admitted": admitted, "reason": reason}
    return out


def _regular_beneath(root: str, rel: str) -> str:
    if not isinstance(rel, str) or not rel or os.path.isabs(rel) \
            or os.path.normpath(rel) != rel or rel.startswith("../"):
        raise _refuse("validation record path is not normalized relative")
    root = os.path.realpath(root)
    path = os.path.join(root, rel)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) \
            or not os.path.realpath(path).startswith(root + os.sep):
        raise _refuse(f"validation record is not regular beneath root: {rel}")
    return path


def _validation_verdict(row: Mapping[str, Any]) -> tuple[bool, str | None]:
    fail = (row.get("fail_leg") or {}).get("outcomes_all_runs")
    passed = row.get("pass_leg")
    if not isinstance(fail, list) or len(fail) != REPEATS:
        return False, "malformed_fail_leg"
    if not isinstance(passed, list) or len(passed) != REPEATS \
            or any(not isinstance(run, dict) or "outcome" not in run
                   for run in passed):
        return False, "malformed_pass_leg"
    if len(set(fail)) != 1:
        return False, "flaky"
    if fail[0] == "passed":
        return False, "passes_without_glue"
    if fail[0] != MISSING_GLUE:
        return False, "wrong_missing_glue_outcome"
    outcomes = [run["outcome"] for run in passed]
    if len(set(outcomes)) != 1:
        return False, "flaky"
    if outcomes[0] != "passed":
        return False, "closure_incomplete"
    return True, None


def _admission_with_census(project: str, items_path: str,
                           census_path: str | None) -> tuple[dict, bytes]:
    if project not in PROJECTS:
        raise _refuse(f"unsupported Java project {project!r}")
    if census_path is None:
        raise _refuse("standard release requires the discovery census")
    try:
        admission = precontact_admission(project, items_path)
        census_raw = Path(census_path).read_bytes()
        census_doc = json.loads(census_raw)
        admission = validate_research_census(
            project, census_path, expected_sha256=_sha256(census_raw),
            snapshot=SimpleNamespace(identity=census_doc["source"]),
            admission=admission)
    except (OSError, KeyError, TypeError, json.JSONDecodeError,
            UnicodeDecodeError, RuntimeError) as exc:
        raise _refuse("standard release discovery census is invalid") from exc
    return admission, census_raw


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"))
            + "\n").encode("utf-8")


def _private_output(path: str) -> str:
    if not isinstance(path, str) or not os.path.isabs(path) \
            or os.path.normpath(path) != path or os.path.lexists(path):
        raise _refuse("release producer output must be one absent absolute path")
    os.mkdir(path, 0o700)
    return path


def _write_new(path: str, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def produce_source_artifacts(
        project: str, *, items_path: str, census_path: str,
        reality_transcript: str, approved_reality_sha256: str,
        source_root: str, source_manifest: str,
        preparation_manifest: str, boundary_path: str, profile_path: str,
        out: str) -> dict:
    """Build admitted-only Java closure/quality evidence from reality bytes.

    EPUBCheck has one unstripped dry-run capture.  Algorand has two, produced
    in fresh unit/offline workspaces.  The latter must be combined before the
    closure extractor is constructed, while the source walk must be limited
    to the discovery census's 125 admitted constructs rather than the 132
    pre-contact constructs present in the composed tree.
    """
    try:
        if re.fullmatch(r"[0-9a-f]{64}", approved_reality_sha256 or "") \
                is None:
            raise _refuse("approved reality transcript SHA-256 is malformed")
        items_rows, items_raw = _read_jsonl(items_path)
        source_raw = Path(source_manifest).read_bytes()
        snapshot = minimal._authenticate_source(
            project, source_root, source_manifest, _sha256(source_raw))
        admission = precontact_admission(project, items_path)
        census_raw = Path(census_path).read_bytes()
        admission = validate_research_census(
            project, census_path, expected_sha256=_sha256(census_raw),
            snapshot=snapshot, admission=admission)
        reality, reality_root, reality_refs = _validate_reality_bundle(
            project, reality_transcript=reality_transcript,
            expected_transcript_sha256=approved_reality_sha256,
            snapshot=snapshot, census_path=census_path,
            census_sha256=_sha256(census_raw), admission=admission)

        tag_expression = admission["tag_census"]["tag_expression"]
        plans = minimal.reality_runs(
            project, tag_expression=tag_expression)
        runs = reality.get("runs")
        run_keys = {
            "name", "target", "dry_run", "stripped", "docker_argv",
            "maven_argv", "pickle_ids", "features", "bindings",
            "undefined_steps", "folded_records", "surefire", "exit_code",
            "preparation_manifest_sha256", "strip_manifest_sha256",
        }
        if not isinstance(runs, list) or len(runs) != len(plans) \
                or any(not isinstance(run, dict) or set(run) != run_keys
                       for run in runs):
            raise _refuse("reality run ledger has another shape")
        # The ledger is re-checked here against the SAME cucumber-version
        # contract `reality` enforced live, read from the same authority
        # (`j0.PARSER_STACKS[project]["cucumber_version"]`), so this gate
        # cannot drift from the phase that produced the rows.  A stripped
        # leg exits 1 under 7.8.0 (its undefined steps are surefire
        # failures) and 0 under 6.6.0 (the tree is wholly `skipped`); the
        # undefined COUNT follows the same fact -- some under 7.8.0, where
        # how many is a per-project number this gate cannot know, and
        # exactly none under 6.6.0, which never emits `undefined` in
        # dry-run mode.  Both directions refuse.
        stripped_exit = minimal.stripped_dry_run_exit(project)
        contract = dry_run_contract(project)
        for plan, run in zip(plans, runs):
            if run["name"] != plan.name or run["target"] != plan.target \
                    or run["dry_run"] is not plan.dry_run \
                    or run["stripped"] is not plan.stripped \
                    or run["exit_code"] != (stripped_exit if plan.stripped
                                            else 0) \
                    or not isinstance(run["undefined_steps"], int) \
                    or isinstance(run["undefined_steps"], bool) \
                    or (plan.stripped and (
                        run["undefined_steps"] <= 0 if contract == "7.8.0"
                        else run["undefined_steps"] != 0)) \
                    or run["maven_argv"] != list(plan.maven_argv) \
                    or re.fullmatch(
                        r"[0-9a-f]{64}",
                        run["preparation_manifest_sha256"] or "") is None \
                    or re.fullmatch(
                        r"[0-9a-f]{64}",
                        run["strip_manifest_sha256"] or "") is None:
                raise _refuse("reality run ledger differs from the exact plan")
        run_by_name = {run["name"]: run for run in runs}
        if len(run_by_name) != len(runs):
            raise _refuse("reality run ledger repeats a run name")

        capture_names = (["unstripped-dry-run"] if project == "epubcheck"
                         else ["unit-unstripped-dry-run",
                               "offline-unstripped-dry-run"])
        documents = []
        capture_refs = []
        capture_pickles: set[str] = set()
        from .closure_java import (COMPANION_CLASSES_BY_PROJECT,
                                   JAVA_TEST_SOURCE_ROOTS, LOCATED,
                                   JavaClosureExtractor, build_type_index,
                                   parse_dry_run)
        for name in capture_names:
            rel = f"runs/{name}/artifacts/cucumber.json"
            ref = reality_refs.get(rel)
            if ref is None:
                raise _refuse(f"reality bundle lacks {name} Cucumber JSON")
            raw = Path(reality_root, *rel.split("/")).read_bytes()
            try:
                document = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise _refuse(f"{name} Cucumber JSON is malformed") from exc
            if not isinstance(document, list):
                raise _refuse(f"{name} Cucumber JSON is not a feature array")
            # `capture_names` is exactly the UNSTRIPPED dry-run captures,
            # so the per-leg state is known here.
            selected = parse_dry_run(document, "src/test/resources",
                                     project=project, dry_run=True,
                                     expect_state=LOCATED)
            pickle_ids = sorted(
                f"{uri}:{line}" for uri, line in selected.cases)
            if pickle_ids != run_by_name[name]["pickle_ids"] \
                    or capture_pickles.intersection(pickle_ids):
                raise _refuse(
                    f"{name} Cucumber bytes differ from the reality ledger")
            capture_pickles.update(pickle_ids)
            documents.extend(document)
            capture_refs.append({"name": name, "path": rel,
                                 "sha256": ref["sha256"]})
        if sorted(capture_pickles) != admission["admitted_pickle_ids"]:
            raise _refuse("unstripped reality captures differ from the census")

        preparation_run = ("unstripped-dry-run" if project == "epubcheck"
                           else "unit-unstripped-dry-run")
        prepared = minimal._validate_preparation(
            project, snapshot, preparation_manifest,
            run_by_name[preparation_run]["preparation_manifest_sha256"],
            stripped=False)

        boundary_path = minimal._absolute(
            boundary_path, "source-artifact boundary")
        profile_path = minimal._absolute(
            profile_path, "source-artifact profile")
        boundary_raw = Path(boundary_path).read_bytes()
        profile_raw = Path(profile_path).read_bytes()
        from ..core.boundary import load_boundary
        from ..data.profile import load_profile
        boundary = load_boundary(boundary_path, repo_root=prepared.workspace)
        profile = load_profile(profile_path)
        if boundary.project != project or profile.project != project \
                or profile.framework != "cucumber" \
                or os.path.abspath(profile.boundary_path) != boundary_path \
                or _sha256(boundary_raw) \
                != prepared.document["boundary_sha256"]:
            raise _refuse(
                "source-artifact boundary/profile differs from preparation")

        # `documents` is the concatenation of those same unstripped
        # dry-run captures.
        dry_run = parse_dry_run(documents, "src/test/resources",
                                project=project, dry_run=True,
                                expect_state=LOCATED)
        extractor = JavaClosureExtractor(
            dry_run, boundary,
            build_type_index(prepared.workspace, JAVA_TEST_SOURCE_ROOTS),
            COMPANION_CLASSES_BY_PROJECT.get(project))
        criterion_by_id = {}
        for row in items_rows:
            if row.get("project") == project \
                    and row.get("task") == "criterion_to_test":
                item_id = row.get("item_id")
                if not isinstance(item_id, str) or item_id in criterion_by_id:
                    raise _refuse("criterion item rows repeat/miss item_id")
                criterion_by_id[item_id] = row
        admitted_ids = admission["admitted_item_ids"]
        if any(item_id not in criterion_by_id for item_id in admitted_ids):
            raise _refuse("census admits an item absent from items JSONL")

        # The census's own partial records, read from the document this phase
        # already authenticated by sha256.  They are deliberately NOT taken
        # from the admission mapping: that mapping is embedded verbatim in the
        # reality transcript, and growing it would invalidate every retained
        # transcript that carries the old shape.
        partials = {}
        for row in json.loads(census_raw)["items"]:
            if row.get("partial_selection") is not None:
                partials[row["item_id"]] = row["partial_selection"]

        from ..core.gherkin import parse_feature_file
        from .algorand import runtime_feature_path
        features = {}
        closures = []
        admitted_rows = []
        for item_id in admitted_ids:
            row = criterion_by_id[item_id]
            provenance = row.get("provenance")
            if not isinstance(provenance, dict) \
                    or not isinstance(provenance.get("file_path"), str) \
                    or not isinstance(provenance.get("line"), int) \
                    or isinstance(provenance.get("line"), bool):
                raise _refuse(f"{item_id}: criterion provenance is malformed")
            expected_pickles = minimal._source_item_pickles(
                project, snapshot, row)
            admitted_pickles = admission["admitted_item_pickle_ids"][item_id]
            record = partials.get(item_id)
            if record is None:
                # A wholly admitted item: the source scenario's pickles ARE
                # the census's, exactly, as before.
                if sorted(expected_pickles) != admitted_pickles:
                    raise _refuse(
                        f"{item_id}: census differs from source scenario")
            else:
                # A partly admitted item.  An `Examples:` block carries its
                # own tags, so the suite's tag filter may take whole blocks
                # and leave others -- which is why whole-item equality is the
                # wrong question here and refused this corpus's one Scenario
                # Outline (167 source rows, 156 admitted).  The census
                # RECORDED the cut; this holds that record against the source
                # (blocks == selected + omitted, nothing extra either side)
                # and then requires the admitted pickles to be exactly the
                # selected blocks' rows.  A cut through a block cannot pass:
                # no union of whole blocks equals part of one.
                selected, every = minimal.selected_block_pickles(
                    project, snapshot, row, record)
                if sorted(expected_pickles) != every:
                    raise _refuse(
                        f"{item_id}: source scenario rows differ from its "
                        f"own Examples blocks")
                if selected != admitted_pickles:
                    raise _refuse(
                        f"{item_id}: census admits pickles the selected "
                        f"Examples blocks do not contain")
            runtime_rel = runtime_feature_path(
                project, provenance["file_path"])
            feature = features.get(runtime_rel)
            if feature is None:
                feature_path = os.path.join(
                    prepared.workspace, *runtime_rel.split("/"))
                feature = features[runtime_rel] = parse_feature_file(
                    feature_path)
            scenario = feature.scenario_at(provenance["line"])
            if scenario is None:
                raise _refuse(f"{item_id}: source scenario line is absent")
            # The closure is derived over the pickles the census ADMITTED --
            # for every item, not only the partial one, since for a wholly
            # admitted item that set is the whole scenario and the scope is a
            # no-op.  The benchmark item is its selected subset: that is what
            # reality measured, what N=3 runs and what a submission is scored
            # on, so a closure over never-selected rows would demand gold glue
            # for rows the suite never executes.  It is also the only
            # derivable answer -- the omitted rows are absent from the dry run
            # this extractor reads, so the unscoped walk refuses them.
            closures.append(extractor.closure_for(
                item_id, feature, scenario,
                frozenset(int(value.rsplit(":", 1)[1])
                          for value in admitted_pickles)).to_json())
            admitted_rows.append(row)
        if [row["item_id"] for row in closures] != admitted_ids:
            raise _refuse("source closures differ from census item order")

        closures_raw = _canonical(closures)
        from ..toolkit.quality import build as build_quality, dependencies_for
        with tempfile.TemporaryDirectory(prefix="r2t-java-source-") as tmp:
            tmp_items = os.path.join(tmp, "items.jsonl")
            tmp_closures = os.path.join(tmp, "closures.json")
            tmp_quality = os.path.join(tmp, "quality.json")
            Path(tmp_items).write_bytes(b"".join(
                _canonical(row) for row in admitted_rows))
            Path(tmp_closures).write_bytes(closures_raw)
            count = build_quality(
                boundary, tmp_items, tmp_closures, tmp_quality, None,
                gold_root=prepared.gold,
                deps=dependencies_for(profile.framework))
            quality = json.loads(Path(tmp_quality).read_bytes())
        if count != len(admitted_ids) or set(quality) != set(admitted_ids):
            raise _refuse("source quality differs from census population")
        quality_raw = _canonical(quality)
    except JavaReleaseValidationRefused:
        raise
    except (OSError, RuntimeError, ClosureJavaError, KeyError, TypeError,
            ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("source-artifact inputs are not exact") from exc

    output = _private_output(out)
    closures_path = os.path.join(output, "source-closures.json")
    quality_path = os.path.join(output, "source-quality.json")
    _write_new(closures_path, closures_raw)
    _write_new(quality_path, quality_raw)
    manifest = {
        "schema": SOURCE_ARTIFACTS_SCHEMA, "path": PATH,
        "project": project,
        "inputs": {
            "items_sha256": _sha256(items_raw),
            "source_manifest_sha256": _sha256(source_raw),
            "census_sha256": _sha256(census_raw),
            "reality_transcript_sha256": approved_reality_sha256,
            "reality_manifest_sha256": reality["manifest"]["sha256"],
            "preparation_manifest_sha256":
                run_by_name[preparation_run]["preparation_manifest_sha256"],
            "boundary_sha256": _sha256(boundary_raw),
            "profile_sha256": _sha256(profile_raw),
            "captures": capture_refs,
        },
        "population": {"items": len(admitted_ids),
                       "pickles": len(capture_pickles)},
        "outputs": {
            "source-closures.json": {"sha256": _sha256(closures_raw)},
            "source-quality.json": {"sha256": _sha256(quality_raw)},
        },
    }
    manifest_raw = _canonical(manifest)
    manifest_path = os.path.join(output, "manifest.json")
    _write_new(manifest_path, manifest_raw)
    return {
        "project": project, **manifest["population"],
        "source_closures_path": closures_path,
        "source_quality_path": quality_path,
        "manifest_path": manifest_path,
        "source_closures_sha256": _sha256(closures_raw),
        "source_quality_sha256": _sha256(quality_raw),
        "manifest_sha256": _sha256(manifest_raw),
    }


def produce_complete_dispositions(
        project: str, *, items_path: str, census_path: str,
        source_closures_path: str, source_quality_path: str, out: str,
        min_live_steps: int = 3) -> dict:
    """Derive complete accepted/excluded ledgers from existing artifacts."""
    admission, census_raw = _admission_with_census(
        project, items_path, census_path)
    source_closures, source_closures_raw = _read_map(
        source_closures_path, array=True)
    source_quality, source_quality_raw = _read_map(source_quality_path)
    eligible = list(admission["admitted_item_ids"])
    closure_rows = []
    quality_rows = {}
    for item_id in eligible:
        source = source_closures.get(item_id)
        if source is None:
            row = {"item_id": item_id, "files": [], "admitted": False,
                   "reason": "no_closure_extracted"}
        else:
            row = dict(source)
            files = row.get("files")
            if not isinstance(files, list) or any(
                    not isinstance(value, str) or not value for value in files):
                raise _refuse(f"{item_id}: source closure files are malformed")
            problems = row.get("problems", [])
            counts = row.get("counts", {})
            if not isinstance(problems, list) or not isinstance(counts, dict):
                raise _refuse(f"{item_id}: source closure evidence is malformed")
            if not files:
                admitted, reason = False, "empty_closure"
            elif problems:
                admitted, reason = False, "closure_extractor_problem"
            elif counts.get("steps_unmatched", 0):
                admitted, reason = False, "unresolvable_step_definitions"
            else:
                admitted, reason = True, None
            row.update({"admitted": admitted, "reason": reason})
        closure_rows.append(row)

        source_q = source_quality.get(item_id)
        if source_q is None:
            qrow = {"has_oracle": False, "admitted": False,
                    "reason": "no_quality_record"}
        else:
            qrow = dict(source_q)
            oracle = qrow.get("has_oracle")
            commented = qrow.get("commented_out", False)
            # D3 revision (2026-08-12, owner): the bar is still 3, but it is
            # read against the steps the runner EXECUTES -- body + Background
            # -- not the body alone.  Absence of the effective count is a
            # refusal, never a silent zero: a record written before the field
            # existed cannot be dispositioned under this rule, and defaulting
            # it to 0 would mark an entire population thin without saying so.
            effective = qrow.get("live_effective_step_count")
            if not isinstance(oracle, bool) or not isinstance(commented, bool) \
                    or not isinstance(effective, int) \
                    or isinstance(effective, bool) or effective < 0:
                raise _refuse(f"{item_id}: source quality evidence is malformed")
            if not oracle:
                admitted, reason = False, "no_oracle"
            elif commented:
                admitted, reason = False, "commented_out"
            elif effective < min_live_steps:
                admitted, reason = False, "thin_scenario"
            else:
                admitted, reason = True, None
            qrow.update({"admitted": admitted, "reason": reason})
        quality_rows[item_id] = qrow

    output = _private_output(out)
    closures_raw = _canonical(closure_rows)
    quality_raw = _canonical(quality_rows)
    closures_path = os.path.join(output, "closures.json")
    quality_path = os.path.join(output, "quality.json")
    _write_new(closures_path, closures_raw)
    _write_new(quality_path, quality_raw)
    return {
        "project": project, "admitted_population": len(eligible),
        "closures_path": closures_path, "quality_path": quality_path,
        "closures_sha256": _sha256(closures_raw),
        "quality_sha256": _sha256(quality_raw),
        "inputs": {"items": _sha256(Path(items_path).read_bytes()),
                   "census": _sha256(census_raw),
                   "source_closures": _sha256(source_closures_raw),
                   "source_quality": _sha256(source_quality_raw)},
    }


def _generated_reconciliation(project: str, admission: dict,
                              closure_dispositions: Mapping[str, dict],
                              quality_dispositions: Mapping[str, dict],
                              ledger: Mapping[str, dict]) \
        -> tuple[dict, list[str]]:
    eligible = set(admission["admitted_item_ids"])
    candidates = {
        item_id for item_id in eligible
        if closure_dispositions[item_id]["admitted"]
        and quality_dispositions[item_id]["admitted"]}
    if set(ledger) != candidates:
        raise _refuse("validation ledger is not the complete candidate set")
    criteria = list(admission["criterion_item_ids"])
    released = [item_id for item_id in criteria
                if item_id in candidates and ledger[item_id]["admitted"]]
    exclusions: dict[str, int] = {}
    for item_id in candidates:
        if not ledger[item_id]["admitted"]:
            reason = _machine_reason(
                ledger[item_id].get("reason"),
                f"{item_id} validation reason")
            exclusions[reason] = exclusions.get(reason, 0) + 1
    blocked = set(admission["precontact_excluded_item_ids"])
    tag_excluded = set(admission["tag_exclusions"])
    released_set = set(released)
    dispositions = {}
    for item_id in criteria:
        if item_id in blocked:
            disposition = {"stage": "precontact_excluded",
                           "reasons": ["needs_live_algod"]}
        elif item_id in tag_excluded:
            disposition = {"stage": "tag_excluded",
                           "reasons": ["tag_expression_excluded"]}
        elif item_id not in eligible:
            raise _refuse(f"{item_id}: admitted population has an unexplained gap")
        elif item_id not in candidates:
            reasons = []
            closure = closure_dispositions[item_id]
            quality = quality_dispositions[item_id]
            if not closure["admitted"]:
                reasons.append("closure." + closure["reason"])
            if not quality["admitted"]:
                reasons.append("quality." + quality["reason"])
            if not reasons:
                raise _refuse(f"{item_id}: candidate exclusion has no reason")
            disposition = {"stage": "closure_quality_excluded",
                           "reasons": reasons}
        elif item_id in released_set:
            disposition = {"stage": "released", "reasons": []}
        else:
            disposition = {
                "stage": "validation_excluded",
                "reasons": ["validation." + ledger[item_id]["reason"]]}
        dispositions[item_id] = disposition
    if set(dispositions) != set(criteria) or len(dispositions) != len(criteria):
        raise _refuse("generated per-item criterion reconciliation is not closed")
    stages = ("precontact_excluded", "tag_excluded",
              "closure_quality_excluded", "validation_excluded", "released")
    stage_counts = {stage: sum(row["stage"] == stage
                               for row in dispositions.values())
                    for stage in stages}
    cfg = PROJECTS[project]
    reconciliation = {
        "input_criteria": cfg.criterion_items,
        "requirements_deferred": cfg.requirement_items,
        "counts": stage_counts,
        "validation_exclusions": dict(sorted(exclusions.items())),
        "item_dispositions": dispositions,
    }
    if sum(stage_counts.values()) != cfg.criterion_items \
            or stage_counts["validation_excluded"] != sum(exclusions.values()) \
            or stage_counts["released"] != len(released):
        raise _refuse("generated criterion reconciliation is not closed")
    return reconciliation, released


def _runtime_pickle_projection(evidence: Mapping[str, Any],
                               intended: list[str]) -> dict:
    """Derive observed synthetic pickle IDs, never substitute census IDs."""
    from .closure_java import ClosureJavaError, normalize_uri
    from ..stacks.cucumber import FEATURE_REL
    records = evidence.get("records")
    lines = evidence.get("expected_lines")
    if lines is None:
        lines = [evidence.get("expected_line")]
    if not isinstance(records, list) or not isinstance(lines, list) \
            or any(not isinstance(line, int) or isinstance(line, bool)
                   for line in lines):
        raise _refuse("harness raw run has no exact pickle evidence")
    observed = []
    try:
        for index, record in enumerate(records):
            if not isinstance(record, dict) \
                    or not isinstance(record.get("feature_file"), str) \
                    or not isinstance(record.get("scenario_line"), int) \
                    or isinstance(record.get("scenario_line"), bool):
                raise _refuse("harness raw Cucumber record is malformed")
            uri = normalize_uri(
                record["feature_file"], "src/test/resources",
                f"validation record {index}.feature_file")
            observed.append(f"{uri}:{record['scenario_line']}")
    except ClosureJavaError as exc:
        raise _refuse(f"harness raw Cucumber URI is invalid: {exc}") from exc
    observed.sort()
    if len(observed) != len(set(observed)):
        raise _refuse("harness raw run repeats a pickle identity")

    # A plain Scenario emits its keyword line.  An outline's expected-lines
    # vector starts with the outline keyword and then its Examples data rows;
    # Cucumber emits one record per data row, not one for the keyword.
    if len(lines) == len(intended):
        runtime_lines = lines
    elif len(lines) == len(intended) + 1:
        runtime_lines = lines[1:]
    else:
        runtime_lines = []
    expected = sorted(f"{FEATURE_REL}:{line}" for line in runtime_lines)
    projection = ([{"observed": actual, "intended": logical}
                   for actual, logical in zip(observed, intended)]
                  if observed == expected and len(observed) == len(intended)
                  else [])
    return {"pickle_ids": observed, "expected_pickle_ids": expected,
            "pickle_projection": projection}


def _evidence_verdict(row: Mapping[str, Any], pickle_sets: list[list[str]],
                      expected_sets: list[list[str]],
                      projections: list[list[dict]],
                      substrates: list[str], intended: list[str]) \
        -> tuple[bool, str | None]:
    admitted, reason = _validation_verdict(row)
    if len(set(substrates)) != 1:
        return False, "altered_substrate"
    encoded = [json.dumps((actual, expected, projection),
                          sort_keys=True, separators=(",", ":"))
               for actual, expected, projection in zip(
                   pickle_sets, expected_sets, projections)]
    if len(set(encoded[:REPEATS])) != 1 \
            or len(set(encoded[REPEATS:])) != 1:
        return False, "flaky"
    if any(not value for value in pickle_sets):
        return False, "missing_scenario"
    intended_projection = [
        [{"observed": observed, "intended": logical}
         for observed, logical in zip(actual, intended)]
        if actual == expected and len(actual) == len(intended) else []
        for actual, expected in zip(pickle_sets, expected_sets)]
    if projections != intended_projection or any(
            actual != expected
            for actual, expected in zip(pickle_sets, expected_sets)):
        return False, "foreign_pickle"
    return admitted, reason


class StandardValidationExecutor(Protocol):
    def execute(self, *, item_id: str, closure: dict,
                intended_pickle_ids: list[str], repeats: int,
                timeout: int) -> Mapping[str, Any]: ...


def _validate_worker_maven(argv: list[str]) -> None:
    prefix = ["mvn", "-o", "-B", "-Dmaven.repo.local=/opt/m2"]
    if argv[:len(prefix)] != prefix:
        raise _refuse("release worker Maven prefix is not exact offline")
    tail = argv[len(prefix):]
    if tail == ["test-compile"]:
        return
    selectors = {
        "R2TBenchCucumberTest",
        "com.algorand.algosdk.unit.R2TBenchCucumberTest",
        "com.algorand.algosdk.integration.R2TBenchCucumberTest",
    }
    if len(tail) not in {5, 6} or tail[:2] != [
            "test", "-Djacoco.skip=true"] \
            or not tail[2].startswith("-Dtest=") \
            or tail[2].removeprefix("-Dtest=") not in selectors \
            or tail[3:5] != [
                "-Dcucumber.features=classpath:_bench_item.feature",
                "-Dcucumber.publish.quiet=true"] \
            or len(tail) == 6 and (
                not tail[-1].startswith("-Dcucumber.filter.name=")
                or len(tail[-1]) > 4096):
        raise _refuse("release worker Maven test argv is not reviewed")


def _validate_worker_shell(inner: str) -> None:
    from ..bench import harness as harness_module
    try:
        argv = shlex.split(inner, posix=True)
    except ValueError as exc:
        raise _refuse("release worker shell command is malformed") from exc
    if inner == _ITEM_BUILD_CLEANUP:
        return
    if inner == _CANDIDATE_TEST_CLASSES_CLEANUP:
        return
    if len(argv) == 3 and argv[:2] == ["rm", "-f"] \
            and _PID_FILE.fullmatch(argv[2]):
        return
    launch = re.fullmatch(
        r"printf '%s' \$\$ > (?P<pid>/tmp/r2t-cucumber-[0-9]+-[0-9]+\.pid) "
        r"&& exec (?P<maven>.+)", inner)
    if launch is not None:
        _validate_worker_maven(shlex.split(launch.group("maven"), posix=True))
        return
    cleanup = re.match(
        r"p=\$\(cat (?P<pid>/tmp/r2t-cucumber-[0-9]+-[0-9]+\.pid) ",
        inner)
    if cleanup is not None and inner == harness_module._process_tree_cleanup_script(
            cleanup.group("pid")):
        return
    _validate_worker_maven(argv)


def validate_release_docker_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Closed Docker vocabulary for one canonical-image N=3 worker."""
    value = tuple(argv)
    if not value or any(not isinstance(token, str) or not token
                        or "\x00" in token for token in value):
        raise _refuse("release Docker argv is malformed")
    if len(value) == 12 and value[:3] == ("run", "-d", "--name") \
            and _WORKER.fullmatch(value[3]) \
            and value[4:8] == ("--network", "none", "--pull=never", "--mount") \
            and value[9:11] == ("--workdir", "/work") \
            and re.fullmatch(r"sha256:[0-9a-f]{64}", value[11]):
        minimal._live_bind(value[8], "/work")
        return value
    if len(value) == 7 and value[:3] == ("exec", "--workdir", "/work") \
            and _WORKER.fullmatch(value[3]) \
            and value[4:6] == ("/bin/sh", "-lc"):
        _validate_worker_shell(value[6])
        return value
    if len(value) == 3 and value[:2] == ("rm", "-f") \
            and _WORKER.fullmatch(value[2]):
        return value
    if len(value) == 5 and value[:4] == (
            "ps", "-aq", "--no-trunc", "--filter") \
            and value[4].startswith("name=^/r2t-java-release-") \
            and value[4].endswith("$") \
            and _WORKER.fullmatch(value[4][len("name=^/"):-1]):
        return value
    raise _refuse("release Docker argv is outside the closed vocabulary")


class AuthorityWorkerRunner:
    """Existing Cucumber harness runner over one reviewed immutable image."""

    workdir = "/work"

    def __init__(self, live_runner: Any, *, workspace: str, image_id: str):
        self.live_runner = live_runner
        self.workspace = minimal._absolute(workspace, "release workspace")
        self.image_id = image_id
        self.name = "r2t-java-release-" + secrets.token_hex(16)
        self.commands: list[list[str]] = []
        self.started = False

    def _run(self, argv: Sequence[str], timeout: int):
        exact = tuple(argv)
        result = self.live_runner.run(exact, timeout=timeout)
        if tuple(result.argv) != exact:
            raise _refuse("release runner reported another Docker argv")
        self.commands.append(list(exact))
        return result

    def start(self) -> None:
        argv = (
            "run", "-d", "--name", self.name, "--network", "none",
            "--pull=never", "--mount",
            f"type=bind,source={self.workspace},target=/work",
            "--workdir", "/work", self.image_id)
        result = self._run(argv, 300)
        if result.returncode != 0 or result.timed_out or result.overflowed:
            raise _refuse("canonical N=3 worker did not start")
        self.started = True

    def run(self, inner: str, env=None, timeout: int = 900):
        if env not in (None, {}):
            raise _refuse("release worker admits no ambient environment")
        if not self.started:
            raise _refuse("release worker is not running")
        argv = ("exec", "--workdir", "/work", self.name,
                "/bin/sh", "-lc", inner)
        result = self._run(argv, timeout)
        stdout = result.stdout.decode("utf-8", "replace")
        stderr = result.stderr.decode("utf-8", "replace")
        if result.timed_out or result.overflowed:
            raise subprocess.TimeoutExpired(
                inner, timeout, output=result.stdout, stderr=result.stderr)
        return subprocess.CompletedProcess(
            [inner], result.returncode, stdout=stdout, stderr=stderr)

    def reset_item_build(self) -> None:
        """Remove prior candidate bytecode before the next fail leg.

        Only `target/test-classes` holds candidate glue, so only it is
        removed; `target/classes` is compiled from the same unmutated
        production sources for every item and stays warm.
        """
        result = self.run(_ITEM_BUILD_CLEANUP, timeout=120)
        if result.returncode != 0 or os.path.lexists(
                os.path.join(self.workspace, "target/test-classes")):
            raise _refuse(
                "release worker did not prove target/test-classes absent")

    def close(self) -> None:
        if not self.started:
            return
        removed = self._run(("rm", "-f", self.name), 120)
        census = self._run((
            "ps", "-aq", "--no-trunc", "--filter",
            f"name=^/{self.name}$"), 120)
        self.started = False
        if removed.returncode != 0 or removed.timed_out or removed.overflowed \
                or census.returncode != 0 or census.timed_out \
                or census.overflowed or census.stdout.strip():
            raise _refuse("canonical N=3 worker cleanup was not proved")


class HarnessN3Executor:
    """Adapter from the existing Java harness/validate_item to raw N=3 legs."""

    def __init__(self, harness: Any, gold_root: str):
        self.harness = harness
        self.gold_root = gold_root

    def execute(self, *, item_id: str, closure: dict,
                intended_pickle_ids: list[str], repeats: int,
                timeout: int) -> Mapping[str, Any]:
        reset = getattr(getattr(self.harness, "runner", None),
                        "reset_item_build", None)
        if not callable(reset):
            raise _refuse("N=3 harness has no release item-build reset")
        reset()
        from ..bench.validate import validate_item
        observed: dict[str, list[dict]] = {}

        def observe(leg: str, runs: list[dict]) -> None:
            for repeat, run in enumerate(runs, 1):
                if (run.get("timed_out") is True
                        or run.get("outcome") == "timeout") \
                        and run.get("timeout_cleanup") != "killed":
                    raise _refuse(
                        f"{item_id}: {leg} repeat {repeat} timed out "
                        "without exact killed cleanup")
            observed[leg] = runs

        verdict = validate_item(
            self.harness, self.gold_root, closure, repeats=repeats,
            timeout=timeout, complete_legs=True,
            run_observer=observe)
        if verdict.item_id != item_id or set(observed) != {"fail", "pass"}:
            raise _refuse(f"{item_id}: harness did not produce both N=3 legs")
        self.harness.verify_substrate()
        digests = getattr(getattr(self.harness, "man", None), "digests", None)
        if not isinstance(digests, dict) or not digests:
            raise _refuse(f"{item_id}: harness has no substrate baseline")
        substrate = _sha256(_canonical(digests))

        def normalize(run: dict) -> dict:
            pickle_evidence = _runtime_pickle_projection(
                run, intended_pickle_ids)
            return {"outcome": run.get("outcome"), **pickle_evidence,
                    "substrate_sha256": substrate,
                    "evidence": run}

        return {leg: [normalize(run) for run in observed[leg]]
                for leg in ("fail", "pass")}


def produce_standard_validation(
        project: str, *, items_path: str, census_path: str,
        closures_path: str, quality_path: str, out: str,
        bindings: Mapping[str, Any],
        executor_factory: Callable[[], StandardValidationExecutor],
        timeout: int = 600) -> dict:
    """Produce, hash, then self-validate every exact N=3 fail/pass record."""
    # This entire population/authentication block precedes executor creation,
    # which is the seam allowed to acquire authority or reach Docker.
    admission, census_raw = _admission_with_census(
        project, items_path, census_path)
    closures, closures_raw = _read_map(closures_path, array=True)
    quality, quality_raw = _read_map(quality_path)
    eligible = set(admission["admitted_item_ids"])
    closure_dispositions = _complete_closure_ledger(closures, eligible)
    quality_dispositions = _complete_quality_ledger(quality, eligible)
    candidates = sorted(
        item_id for item_id in eligible
        if closure_dispositions[item_id]["admitted"]
        and quality_dispositions[item_id]["admitted"])
    validated_bindings = _validate_bindings(dict(bindings))
    if not callable(executor_factory) or not candidates:
        raise _refuse("standard validation has no executor/candidates")

    output = _private_output(out)
    records_root = os.path.join(output, "records")
    os.mkdir(records_root, 0o700)
    executor = executor_factory()
    ledger_rows = []
    record_manifest = {}
    ledger = {}
    for item_index, item_id in enumerate(candidates):
        intended = admission["admitted_item_pickle_ids"][item_id]
        batch = executor.execute(
            item_id=item_id, closure=closures[item_id],
            intended_pickle_ids=list(intended), repeats=REPEATS,
            timeout=timeout)
        if not isinstance(batch, Mapping) or set(batch) != {"fail", "pass"} \
                or any(not isinstance(batch[leg], list)
                       or len(batch[leg]) != REPEATS for leg in ("fail", "pass")):
            raise _refuse(f"{item_id}: executor did not return exact N=3+3")
        item_dir = os.path.join(records_root, f"{item_index:06d}")
        os.mkdir(item_dir, 0o700)
        refs = {"fail": [], "pass": []}
        pickle_sets = []
        expected_sets = []
        projections = []
        substrates = []
        outcomes = {"fail": [], "pass": []}
        for leg in ("fail", "pass"):
            for repeat, observed in enumerate(batch[leg]):
                if not isinstance(observed, Mapping) or set(observed) != {
                        "outcome", "pickle_ids", "expected_pickle_ids",
                        "pickle_projection", "substrate_sha256", "evidence"} \
                        or not isinstance(observed["outcome"], str) \
                        or not isinstance(observed["pickle_ids"], list) \
                        or observed["pickle_ids"] != sorted(
                            set(observed["pickle_ids"])) \
                        or not isinstance(observed["expected_pickle_ids"], list) \
                        or observed["expected_pickle_ids"] != sorted(
                            set(observed["expected_pickle_ids"])) \
                        or not isinstance(observed["pickle_projection"], list) \
                        or any(not isinstance(pair, dict)
                               or set(pair) != {"observed", "intended"}
                               or any(not isinstance(pair[key], str)
                                      or not pair[key]
                                      for key in pair)
                               for pair in observed["pickle_projection"]) \
                        or any(not isinstance(value, str) or not value
                               for value in observed["pickle_ids"]
                               + observed["expected_pickle_ids"]) \
                        or not isinstance(observed["substrate_sha256"], str) \
                        or re.fullmatch(r"[0-9a-f]{64}",
                                        observed["substrate_sha256"]) is None \
                        or not isinstance(observed["evidence"], dict) \
                        or observed["evidence"].get("outcome") \
                        != observed["outcome"]:
                    raise _refuse(f"{item_id}: executor raw run is malformed")
                derived = _runtime_pickle_projection(
                    observed["evidence"], intended)
                if any(observed[name] != derived[name] for name in (
                        "pickle_ids", "expected_pickle_ids",
                        "pickle_projection")):
                    raise _refuse(
                        f"{item_id}: executor pickle claims differ from raw evidence")
                record = {
                    "schema": RUN_SCHEMA, "item_id": item_id,
                    "leg": leg, "repeat": repeat,
                    "outcome": observed["outcome"],
                    "image_id": validated_bindings[
                        "canonical_image_id"]["identity"],
                    "network": "none", "pull": "never",
                    "closure_identity": (
                        None if leg == "fail" else
                        validated_bindings["gold"]["identity"]),
                    "pickle_ids": observed["pickle_ids"],
                    "expected_pickle_ids": observed["expected_pickle_ids"],
                    "pickle_projection": observed["pickle_projection"],
                    "substrate_sha256": observed["substrate_sha256"],
                    "evidence": observed["evidence"],
                }
                raw = _canonical(record)
                rel = f"{item_index:06d}/{leg}-{repeat}.json"
                _write_new(os.path.join(records_root, rel), raw)
                refs[leg].append({"path": rel, "sha256": _sha256(raw)})
                pickle_sets.append(list(observed["pickle_ids"]))
                expected_sets.append(list(observed["expected_pickle_ids"]))
                projections.append(list(observed["pickle_projection"]))
                substrates.append(observed["substrate_sha256"])
                outcomes[leg].append(observed["outcome"])
        row = {
            "item_id": item_id, "harness_version": HARNESS_VERSION,
            "fail_leg": {"outcome": outcomes["fail"][0],
                         "outcomes_all_runs": outcomes["fail"]},
            "pass_leg": [{"outcome": value}
                         for value in outcomes["pass"]],
        }
        row["admitted"], row["reason"] = _evidence_verdict(
            row, pickle_sets, expected_sets, projections, substrates,
            intended)
        ledger_rows.append(row)
        ledger[item_id] = row
        record_manifest[item_id] = refs

    ledger_raw = b"".join(_canonical(row) for row in ledger_rows)
    ledger_path = os.path.join(output, "validation.jsonl")
    _write_new(ledger_path, ledger_raw)
    reconciliation, _released = _generated_reconciliation(
        project, admission, closure_dispositions, quality_dispositions,
        ledger)
    manifest = {
        "schema": SCHEMA, "path": PATH, "project": project,
        "inputs": {name: {"sha256": digest} for name, digest in {
            "items": _sha256(Path(items_path).read_bytes()),
            "census": _sha256(census_raw),
            "closures": _sha256(closures_raw),
            "quality": _sha256(quality_raw),
            "ledger": _sha256(ledger_raw),
        }.items()},
        "records": record_manifest, "bindings": validated_bindings,
        "reconciliation": reconciliation,
    }
    manifest_path = os.path.join(output, "manifest.json")
    _write_new(manifest_path, _canonical(manifest))
    return validate_standard_release(
        project, items_path=items_path, census_path=census_path,
        closures_path=closures_path, quality_path=quality_path,
        ledger_path=ledger_path, manifest_path=manifest_path,
        records_root=records_root)


def _validate_bindings(bindings: object) -> dict:
    if not isinstance(bindings, dict) or set(bindings) != REQUIRED_BINDINGS:
        raise _refuse("release bindings differ from the exact joined set")
    for name, value in bindings.items():
        if not isinstance(value, dict) or set(value) != {"identity"} \
                or not isinstance(value["identity"], str) \
                or not value["identity"]:
            raise _refuse(f"release binding {name} is malformed")
    return bindings


def validate_standard_release(
        project: str, *, items_path: str, census_path: str | None,
        closures_path: str, quality_path: str, ledger_path: str,
        manifest_path: str, records_root: str) -> dict:
    """Validate six raw executions per candidate and derive reconciliation."""
    admission, census_raw = _admission_with_census(
        project, items_path, census_path)
    closures, closures_raw = _read_map(closures_path, array=True)
    quality, quality_raw = _read_map(quality_path)
    ledger_rows, ledger_raw = _read_jsonl(ledger_path)
    try:
        manifest_raw = Path(manifest_path).read_bytes()
        manifest = json.loads(manifest_raw)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("validation manifest is unreadable JSON") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
            "schema", "path", "project", "inputs", "records", "bindings",
            "reconciliation"} \
            or manifest["schema"] != SCHEMA or manifest["path"] != PATH \
            or manifest["project"] != project:
        raise _refuse("validation manifest has another schema/path/project")
    _validate_bindings(manifest["bindings"])

    inputs = manifest["inputs"]
    expected_inputs = {
        "items": _sha256(Path(items_path).read_bytes()),
        "census": _sha256(census_raw),
        "closures": _sha256(closures_raw),
        "quality": _sha256(quality_raw),
        "ledger": _sha256(ledger_raw),
    }
    if inputs != {name: {"sha256": digest}
                  for name, digest in expected_inputs.items()}:
        raise _refuse("validation manifest input hashes differ")

    eligible = set(admission["admitted_item_ids"])
    closure_dispositions = _complete_closure_ledger(closures, eligible)
    quality_dispositions = _complete_quality_ledger(quality, eligible)
    candidates = sorted(
        item_id for item_id in eligible
        if closure_dispositions[item_id]["admitted"]
        and quality_dispositions[item_id]["admitted"])
    ledger = {}
    for row in ledger_rows:
        item_id = row.get("item_id")
        if not isinstance(item_id, str) or item_id in ledger:
            raise _refuse("validation ledger repeats or omits item_id")
        ledger[item_id] = row
    if set(ledger) != set(candidates):
        raise _refuse("validation ledger is not the complete candidate set")
    if not isinstance(manifest["records"], dict) \
            or set(manifest["records"]) != set(candidates):
        raise _refuse("raw-record manifest is not the complete candidate set")

    for item_id in candidates:
        row = ledger[item_id]
        if row.get("harness_version") != HARNESS_VERSION:
            raise _refuse(f"{item_id}: stale harness version")
        refs = manifest["records"][item_id]
        if not isinstance(refs, dict) or set(refs) != {"fail", "pass"} \
                or any(not isinstance(refs[leg], list)
                       or len(refs[leg]) != REPEATS for leg in ("fail", "pass")):
            raise _refuse(f"{item_id}: raw-run references are not N=3+3")
        pickle_sets: list[list[str]] = []
        expected_sets: list[list[str]] = []
        projections: list[list[dict]] = []
        substrates: list[str] = []
        for leg in ("fail", "pass"):
            expected_outcomes = (row["fail_leg"]["outcomes_all_runs"]
                                 if leg == "fail" else
                                 [run["outcome"] for run in row["pass_leg"]])
            for repeat, ref in enumerate(refs[leg]):
                if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
                    raise _refuse(f"{item_id}: malformed raw-run reference")
                path = _regular_beneath(records_root, ref["path"])
                raw = Path(path).read_bytes()
                if _sha256(raw) != ref["sha256"]:
                    raise _refuse(f"{item_id}: raw-run record hash differs")
                try:
                    record = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise _refuse(f"{item_id}: raw-run record is not JSON") from exc
                expected = {
                    "schema": RUN_SCHEMA, "item_id": item_id, "leg": leg,
                    "repeat": repeat, "outcome": expected_outcomes[repeat],
                    "image_id": manifest["bindings"][
                        "canonical_image_id"]["identity"],
                    "network": "none", "pull": "never",
                    "closure_identity": (None if leg == "fail" else
                                         manifest["bindings"]["gold"]["identity"]),
                }
                if not isinstance(record, dict) \
                        or set(record) != set(expected) | {
                            "pickle_ids", "expected_pickle_ids",
                            "pickle_projection", "substrate_sha256", "evidence"} \
                        or any(record[name] != value
                               for name, value in expected.items()) \
                        or not isinstance(record["pickle_ids"], list) \
                        or len(record["pickle_ids"]) \
                        != len(set(record["pickle_ids"])) \
                        or not isinstance(record["expected_pickle_ids"], list) \
                        or record["expected_pickle_ids"] != sorted(
                            set(record["expected_pickle_ids"])) \
                        or not isinstance(record["pickle_projection"], list) \
                        or any(not isinstance(pair, dict)
                               or set(pair) != {"observed", "intended"}
                               for pair in record["pickle_projection"]) \
                        or not isinstance(record["substrate_sha256"], str) \
                        or len(record["substrate_sha256"]) != 64 \
                        or set(record["substrate_sha256"]) - set("0123456789abcdef") \
                        or not isinstance(record["evidence"], dict) \
                        or record["evidence"].get("outcome") \
                        != record["outcome"]:
                    raise _refuse(f"{item_id}: raw-run record is malformed")
                derived = _runtime_pickle_projection(
                    record["evidence"],
                    admission["admitted_item_pickle_ids"][item_id])
                if any(record[name] != derived[name] for name in (
                        "pickle_ids", "expected_pickle_ids",
                        "pickle_projection")):
                    raise _refuse(
                        f"{item_id}: retained pickle claims differ from raw evidence")
                pickle_sets.append(record["pickle_ids"])
                expected_sets.append(record["expected_pickle_ids"])
                projections.append(record["pickle_projection"])
                substrates.append(record["substrate_sha256"])
        intended = admission["admitted_item_pickle_ids"].get(item_id)
        admitted, reason = _evidence_verdict(
            row, pickle_sets, expected_sets, projections, substrates,
            intended)
        if row.get("admitted") is not admitted \
                or row.get("reason") != reason:
            raise _refuse(f"{item_id}: ledger summary disagrees with six runs")
    reconciliation, released = _generated_reconciliation(
        project, admission, closure_dispositions, quality_dispositions,
        ledger)
    if manifest["reconciliation"] != reconciliation:
        raise _refuse("hand-written reconciliation differs from generated counts")
    return {"project": project, "candidate_items": len(candidates),
            "released_item_ids": released, "reconciliation": reconciliation,
            "ledger_sha256": _sha256(ledger_raw),
            "manifest_sha256": _sha256(manifest_raw)}


def _approval(project: str, phase: str, approval_path: str | None,
              approved_digest: str | None):
    try:
        return minimal.require_source_approval(
            project, phase, approval_path=approval_path,
            approved_digest=approved_digest)
    except RuntimeError as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc


def _profile_path(project: str) -> str:
    """This project's shipped profile, named by the one authority for it.

    Was a two-name conditional whose `else` returned the Algorand profile for
    anything that was not epubcheck.  For the two Java projects that is the
    same answer `profile_stem` gives, and for a third it was a wrong file that
    only failed later as "boundary/profile/strip/gold differ from approval" --
    a sentence about an approval, for a validator that had opened the wrong
    project.
    """
    from ..data.profile import profile_stem
    name = f"profile_{profile_stem(project)}.yml"
    return str(Path(__file__).resolve().parents[2] / "config" / name)


def _release_file_manifest(root: str) -> tuple[dict, str]:
    from .j0 import framed_tree_sha256
    try:
        files = minimal._tree_files(root)
    except RuntimeError as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    entries = [{"path": rel, "bytes": len(raw), "sha256": _sha256(raw)}
               for rel, raw in sorted(files.items())]
    return ({"schema": RELEASE_MANIFEST_SCHEMA, "path": PATH,
             "files": entries}, framed_tree_sha256(files.items()))


def _install_mutation_authority(
        controls: str, *, snapshot: Any, reality: Mapping[str, Any],
        reality_transcript: str, canonical_transcript: str,
        m2_manifest_sha256: str, m2_tree_sha256: str) -> str:
    """Retain only the reviewed bytes Java population production consumes.

    No parallel evidence schema is minted here.  The two phase transcripts,
    the reality manifest, and the Maven manifest keep their existing schemas;
    the source and Surefire files retain their exact bytes at deterministic
    paths.  The enclosing release manifest content-addresses this whole
    subset along with the rest of the provided release.
    """
    authority = os.path.join(controls, MUTATION_AUTHORITY_DIR)
    os.mkdir(authority, 0o700)

    reality_path = minimal._absolute(
        reality_transcript, "mutation-authority reality transcript")
    canonical_path = minimal._absolute(
        canonical_transcript, "mutation-authority canonical transcript")
    reality_root = os.path.dirname(reality_path)
    manifest_ref = reality.get("manifest")
    if not isinstance(manifest_ref, dict) \
            or manifest_ref.get("path") != "manifest.json":
        raise _refuse("reality transcript has no exact manifest reference")
    reality_manifest_path = os.path.join(reality_root, "manifest.json")
    reality_manifest_raw = Path(reality_manifest_path).read_bytes()
    if len(reality_manifest_raw) != manifest_ref.get("bytes") \
            or _sha256(reality_manifest_raw) != manifest_ref.get("sha256"):
        raise _refuse("reality manifest changed before mutation retention")
    try:
        reality_manifest = json.loads(reality_manifest_raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("reality manifest is not JSON") from exc
    refs = reality_manifest.get("files") \
        if isinstance(reality_manifest, dict) else None
    if not isinstance(refs, list):
        raise _refuse("reality manifest has no file inventory")
    ref_by_path = {
        ref.get("path"): ref for ref in refs
        if isinstance(ref, dict) and isinstance(ref.get("path"), str)
    }
    if len(ref_by_path) != len(refs):
        raise _refuse("reality manifest repeats or malforms a file reference")

    _write_new(os.path.join(authority, "reality-transcript.json"),
               Path(reality_path).read_bytes())
    _write_new(os.path.join(authority, "reality-manifest.json"),
               reality_manifest_raw)
    _write_new(os.path.join(authority, "canonical-transcript.json"),
               Path(canonical_path).read_bytes())

    relevant_runs = []
    for run in reality.get("runs", ()):  # shape was closed by preflight
        if run.get("stripped") is False:
            relevant_runs.append(run["name"])
    if not relevant_runs:
        raise _refuse("reality has no non-stripped mutation authority run")
    for run_name in relevant_runs:
        prefix = f"runs/{run_name}/artifacts/surefire/"
        selected = sorted(
            rel for rel in ref_by_path
            if rel.startswith(prefix) and rel.endswith(".xml"))
        if not selected:
            raise _refuse(
                f"{run_name} has no retained Surefire mutation authority")
        for rel in selected:
            source = os.path.join(reality_root, *rel.split("/"))
            raw = Path(source).read_bytes()
            ref = ref_by_path[rel]
            if len(raw) != ref.get("bytes") \
                    or _sha256(raw) != ref.get("sha256"):
                raise _refuse(
                    f"reality Surefire bytes changed before retention: {rel}")
            destination = os.path.join(authority, "reality", *rel.split("/"))
            os.makedirs(os.path.dirname(destination), mode=0o700,
                        exist_ok=True)
            _write_new(destination, raw)

    source_rows = sorted(
        (rel, raw) for rel, raw in snapshot.files.items()
        if rel.startswith("src/main/java/"))
    if not source_rows:
        raise _refuse("reviewed source has no src/main/java authority")
    for rel, raw in source_rows:
        destination = os.path.join(authority, "source", *rel.split("/"))
        os.makedirs(os.path.dirname(destination), mode=0o700,
                    exist_ok=True)
        _write_new(destination, raw)

    canonical_m2 = os.path.join(
        os.path.dirname(canonical_path), "context", "approved-m2")
    try:
        m2_manifest, m2_tree = minimal._manifest(
            minimal._tree_files(canonical_m2))
    except (OSError, RuntimeError) as exc:
        raise _refuse("canonical Maven payload is unavailable for mutation") \
            from exc
    m2_raw = _canonical(m2_manifest)
    if _sha256(m2_raw) != m2_manifest_sha256 \
            or m2_tree != m2_tree_sha256:
        raise _refuse("canonical Maven payload differs before mutation retention")
    _write_new(os.path.join(authority, "m2-manifest.json"), m2_raw)
    return authority


def _validate_release_file_manifest(root: str, manifest_path: str,
                                    expected_manifest: str,
                                    expected_tree: str) -> dict:
    raw = Path(manifest_path).read_bytes()
    if _sha256(raw) != expected_manifest:
        raise _refuse("generated release manifest differs from final review")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("generated release manifest is not JSON") from exc
    actual, tree = _release_file_manifest(root)
    if not isinstance(document, dict) or set(document) != {
            "schema", "path", "files", "project", "released_item_ids",
            "tree_sha256"} \
            or any(document.get(name) != actual[name]
                   for name in ("schema", "path", "files")) \
            or document.get("tree_sha256") != tree \
            or tree != expected_tree:
        raise _refuse("generated release files differ from their reviewed tree")
    return document


def _validate_reality_bundle(
        project: str, *, reality_transcript: str,
        expected_transcript_sha256: str, snapshot: Any,
        census_path: str, census_sha256: str, admission: Mapping[str, Any],
        expected_authority: object = None, expected_image_id: str | None = None,
        expected_manifest_sha256: str | None = None,
        expected_base: object = None) -> tuple[dict, str, dict[str, dict]]:
    """Authenticate a complete reality directory without reaching Docker."""
    reality_path = minimal._absolute(
        reality_transcript, "release reality transcript")
    reality_raw = Path(reality_path).read_bytes()
    if _sha256(reality_raw) != expected_transcript_sha256:
        raise _refuse("reality transcript differs from reviewed SHA-256")
    try:
        reality = json.loads(reality_raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("reality transcript is not JSON") from exc
    expected_keys = {
        "schema", "path", "project", "status", "execution_identity",
        "authority", "admission", "base", "source", "census",
        "canonical_transcript_sha256", "image_id", "network", "pull",
        "runs", "manifest", "result"}
    authority = reality.get("authority") if isinstance(reality, dict) else None
    base = reality.get("base") if isinstance(reality, dict) else None
    census_ref = reality.get("census") if isinstance(reality, dict) else None
    daemon_valid = isinstance(authority, dict) and re.fullmatch(
        r"[0-9a-f]{64}", authority.get("daemon_fingerprint") or "") \
        is not None
    base_valid = isinstance(base, dict) and all(
        re.fullmatch(r"sha256:[0-9a-f]{64}", base.get(name) or "")
        is not None for name in ("repository_digest", "config_id"))
    image_valid = re.fullmatch(
        r"sha256:[0-9a-f]{64}",
        (reality.get("image_id") if isinstance(reality, dict) else "") or "") \
        is not None
    if not isinstance(reality, dict) or set(reality) != expected_keys \
            or reality.get("schema") != minimal.REALITY_SCHEMA \
            or reality.get("path") != PATH or reality.get("project") != project \
            or reality.get("status") != "complete" \
            or not isinstance(authority, dict) \
            or set(authority) != {"reference", "daemon_fingerprint"} \
            or not daemon_valid \
            or expected_authority is not None \
            and authority != expected_authority \
            or not isinstance(base, dict) \
            or set(base) != {"repository_digest", "config_id"} \
            or not base_valid \
            or expected_base is not None and base != expected_base \
            or reality.get("admission") != dict(admission) \
            or reality.get("source") != dict(snapshot.identity) \
            or not image_valid \
            or expected_image_id is not None \
            and reality.get("image_id") != expected_image_id \
            or reality.get("network") != "none" \
            or reality.get("pull") != "never" \
            or census_ref != {
                "path": minimal._absolute(
                    census_path, "release discovery census"),
                "sha256": census_sha256} \
            or reality.get("result") != {
                "runs": len(reality.get("runs", [])),
                "offline_repository_unchanged": True,
                "substrate_unchanged": True,
                "pickle_sets_stable": True,
                "stripped_bindings_empty": True}:
        raise _refuse("reality transcript differs from the reviewed gate")

    reality_root = os.path.dirname(reality_path)
    manifest_ref = reality.get("manifest")
    if not isinstance(manifest_ref, dict) or set(manifest_ref) != {
            "path", "bytes", "sha256"} or manifest_ref["path"] != "manifest.json" \
            or expected_manifest_sha256 is not None \
            and manifest_ref["sha256"] != expected_manifest_sha256:
        raise _refuse("reality manifest identity differs from approval")
    manifest_path = os.path.join(reality_root, "manifest.json")
    manifest_raw = Path(manifest_path).read_bytes()
    if len(manifest_raw) != manifest_ref["bytes"] \
            or _sha256(manifest_raw) != manifest_ref["sha256"]:
        raise _refuse("reality manifest bytes changed")
    try:
        manifest = json.loads(manifest_raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("reality manifest is not JSON") from exc
    refs = manifest.get("files") if isinstance(manifest, dict) else None
    if set(manifest or {}) != {"schema", "files"} \
            or manifest.get("schema") \
            != "r2t.java-research-minimal-reality-manifest/1" \
            or not isinstance(refs, list):
        raise _refuse("reality manifest has another schema")
    named = []
    by_path = {}
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {"path", "bytes", "sha256"}:
            raise _refuse("reality manifest file reference is malformed")
        path = _regular_beneath(reality_root, ref["path"])
        raw = Path(path).read_bytes()
        if len(raw) != ref["bytes"] or _sha256(raw) != ref["sha256"]:
            raise _refuse("reality artifact differs from its manifest")
        named.append(ref["path"])
        by_path[ref["path"]] = ref
    on_disk = set(minimal._tree_files(reality_root)) - {
        "manifest.json", "transcript.json"}
    if named != sorted(set(named)) or set(named) != on_disk:
        raise _refuse("reality manifest is not a complete artifact inventory")
    return reality, reality_root, by_path


def _validate_reality_and_canonical(
        project: str, *, reality_transcript: str,
        canonical_transcript: str, approval: Any,
        snapshot: Any, census_path: str,
        admission: Mapping[str, Any]) -> tuple[dict, dict]:
    expected_authority = {
        "reference": approval.authority_reference,
        "daemon_fingerprint": approval.daemon_fingerprint,
    }
    expected_base = {"repository_digest": approval.base_digest,
                     "config_id": approval.base_config_id}
    reality, _reality_root, _refs = _validate_reality_bundle(
        project, reality_transcript=reality_transcript,
        expected_transcript_sha256=approval.predecessor_transcript_sha256,
        snapshot=snapshot, census_path=census_path,
        census_sha256=approval.census_sha256, admission=admission,
        expected_authority=expected_authority,
        expected_image_id=approval.image_id,
        expected_manifest_sha256=approval.reality_manifest_sha256,
        expected_base=expected_base)

    canonical_hash = reality.get("canonical_transcript_sha256")
    try:
        canonical = minimal._read_document(
            minimal._absolute(canonical_transcript,
                              "release canonical transcript"),
            expected_sha256=canonical_hash, phase="canonical",
            project=project)
    except RuntimeError as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    expected_definition = _sha256(minimal.canonical_dockerfile(
        PROJECTS[project], approval.base_digest))
    result = canonical.get("result", {})
    if canonical.get("source") != dict(snapshot.identity) \
            or canonical.get("authority") != reality.get("authority") \
            or canonical.get("base") != expected_base \
            or canonical.get("definition", {}).get("sha256") \
            != expected_definition \
            or canonical.get("discovery_census", {}).get("sha256") \
            != approval.census_sha256 \
            or result.get("candidate_image_id") != approval.image_id \
            or result.get("base_config_id") != approval.base_config_id \
            or result.get("m2_manifest_sha256") \
            != approval.m2_manifest_sha256 \
            or result.get("m2_tree_sha256") != approval.m2_tree_sha256:
        raise _refuse("canonical transcript differs from release approval")
    return reality, canonical


def _validation_preflight(
        project: str, *, items_path: str, census_path: str,
        closures_path: str, quality_path: str, source_root: str,
        source_manifest: str, preparation_manifest: str,
        reality_transcript: str, canonical_transcript: str,
        approval: Any) -> tuple[dict, Any, Any, dict, dict, dict]:
    try:
        admission = precontact_admission(project, items_path)
        source_raw = Path(source_manifest).read_bytes()
        snapshot = minimal._authenticate_source(
            project, source_root, source_manifest,
            approval.source_manifest_sha256)
        if _sha256(source_raw) != approval.source_manifest_sha256:
            raise _refuse("source manifest differs from validation approval")
        admission = validate_research_census(
            project, census_path, expected_sha256=approval.census_sha256,
            snapshot=snapshot, admission=admission)
        closures, closure_raw = _read_map(closures_path, array=True)
        quality, quality_raw = _read_map(quality_path)
        if _sha256(closure_raw) != approval.closures_sha256 \
                or _sha256(quality_raw) != approval.quality_sha256:
            raise _refuse("closure/quality ledgers differ from validation review")
        eligible = set(admission["admitted_item_ids"])
        _complete_closure_ledger(closures, eligible)
        _complete_quality_ledger(quality, eligible)
        prepared = minimal._validate_preparation(
            project, snapshot, preparation_manifest,
            approval.preparation_manifest_sha256, stripped=True)
        boundary_raw = Path(minimal._boundary_path(project)).read_bytes()
        strip_raw = Path(prepared.gold, "strip_manifest.json").read_bytes()
        gold_tree = minimal._tree_identity(
            minimal._tree_files(prepared.gold))["tree_sha256"]
        profile_path = _profile_path(project)
        profile_raw = Path(profile_path).read_bytes()
        from ..data.profile import load_profile
        profile = load_profile(profile_path)
        if profile.project != project \
                or _sha256(boundary_raw) != approval.boundary_sha256 \
                or _sha256(profile_raw) != approval.profile_sha256 \
                or _sha256(strip_raw) != approval.strip_manifest_sha256 \
                or gold_tree != approval.gold_tree_sha256:
            raise _refuse("boundary/profile/strip/gold differ from approval")
        reality, canonical = _validate_reality_and_canonical(
            project, reality_transcript=reality_transcript,
            canonical_transcript=canonical_transcript, approval=approval,
            snapshot=snapshot, census_path=census_path,
            admission=admission)
    except JavaReleaseValidationRefused:
        raise
    except (OSError, RuntimeError, KeyError, TypeError, ValueError) as exc:
        raise _refuse("validation preflight input is not exact") from exc
    return admission, snapshot, prepared, reality, canonical, {
        "closures": closures, "quality": quality}


def _derived_bindings(project: str, approval: Any, snapshot: Any,
                      prepared: Any, reality: dict,
                      canonical: dict) -> dict:
    source_identity = _sha256(_canonical(dict(snapshot.identity)))
    release_policy = _sha256(_canonical({
        "schema": PHASE_SCHEMA, "project": project,
        "census": approval.census_sha256,
        "closures": approval.closures_sha256,
        "quality": approval.quality_sha256,
        "min_live_steps": 3, "repeats": REPEATS,
        "harness_version": HARNESS_VERSION}))
    values = {
        "source": source_identity,
        "base_repository_digest": approval.base_digest,
        "base_config_id": approval.base_config_id,
        "discovery_manifest": approval.m2_manifest_sha256,
        "discovery_payload_tree": approval.m2_tree_sha256,
        "canonical_dockerfile": canonical["definition"]["sha256"],
        "canonical_transcript": reality["canonical_transcript_sha256"],
        "canonical_image_id": approval.image_id,
        "reality_manifest": approval.reality_manifest_sha256,
        "boundary": approval.boundary_sha256,
        "profile": approval.profile_sha256,
        "strip": approval.strip_manifest_sha256,
        "gold": approval.gold_tree_sha256,
        "release": release_policy,
    }
    return _validate_bindings({name: {"identity": value}
                               for name, value in values.items()})


def run_approved_validation(
        project: str, *, items_path: str, census_path: str,
        closures_path: str, quality_path: str, source_root: str,
        source_manifest: str, preparation_manifest: str,
        reality_transcript: str, canonical_transcript: str, out: str,
        runner: Any, approval_path: str | None,
        approved_digest: str | None, timeout: int = 600) -> dict:
    """Execute one reviewed N=3 phase and generate the runner release pool."""
    approval = _approval(
        project, "validation", approval_path, approved_digest)
    admission, snapshot, prepared, reality, canonical, _ledgers = \
        _validation_preflight(
            project, items_path=items_path, census_path=census_path,
            closures_path=closures_path, quality_path=quality_path,
            source_root=source_root, source_manifest=source_manifest,
            preparation_manifest=preparation_manifest,
            reality_transcript=reality_transcript,
            canonical_transcript=canonical_transcript, approval=approval)
    bindings = _derived_bindings(
        project, approval, snapshot, prepared, reality, canonical)
    output = _private_output(out)
    try:
        authority = minimal._authority(runner, approval)
    except RuntimeError as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc

    workers: list[AuthorityWorkerRunner] = []

    def executor_factory():
        from ..stacks.cucumber import CucumberHarness
        worker = AuthorityWorkerRunner(
            runner, workspace=prepared.workspace, image_id=approval.image_id)
        workers.append(worker)
        worker.start()
        harness = CucumberHarness(
            prepared.strip_manifest, prepared.boundary, worker)
        return HarnessN3Executor(harness, prepared.gold)

    validation_dir = os.path.join(output, "validation")
    try:
        validation = produce_standard_validation(
            project, items_path=items_path, census_path=census_path,
            closures_path=closures_path, quality_path=quality_path,
            out=validation_dir, bindings=bindings,
            executor_factory=executor_factory, timeout=timeout)
    finally:
        for worker in workers:
            worker.close()

    from ..toolkit.release_build import build_release
    release_dir = os.path.join(output, "release")
    release = build_release(
        validation_dir, items_path, release_dir, min_live_steps=3,
        project=project, items_name="items.jsonl",
        closures_path=closures_path, quality_path=quality_path,
        validation_path=os.path.join(validation_dir, "validation.jsonl"),
        portable_paths=True,
        item_dispositions=validation[
            "reconciliation"]["item_dispositions"])
    released_rows, _released_raw = _read_jsonl(
        os.path.join(release_dir, "items.jsonl"))
    released_ids = [row.get("item_id") for row in released_rows]
    if released_ids != validation["released_item_ids"]:
        raise _refuse("generated runner release differs from N=3 admissions")
    # The registered gold/stripped-gold/stub adapters consume these exact
    # paths in a later, genuinely native-v2 generation campaign.  Retain the
    # reviewed source-gold tree (including its strip manifest) and the
    # complete dispositions; do not mint a campaign sidecar here.
    reference_gold = os.path.join(release_dir, "reference-gold")
    os.mkdir(reference_gold, 0o700)
    reference_files = minimal._tree_files(prepared.gold)
    try:
        strip_document = json.loads(reference_files.pop(
            "strip_manifest.json"))
    except (KeyError, TypeError, json.JSONDecodeError,
            UnicodeDecodeError) as exc:
        raise _refuse("reviewed source-gold strip manifest is malformed") from exc
    strip_document["gold_root"] = reference_gold
    for rel, raw in sorted(reference_files.items()):
        target = os.path.join(reference_gold, *rel.split("/"))
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        _write_new(target, raw)
    _write_new(os.path.join(reference_gold, "strip_manifest.json"),
               _canonical(strip_document))
    controls = os.path.join(release_dir, "control-artifacts")
    os.mkdir(controls, 0o700)
    _write_new(os.path.join(controls, "closures.json"),
               Path(closures_path).read_bytes())
    _write_new(os.path.join(controls, "quality.json"),
               Path(quality_path).read_bytes())
    _write_new(os.path.join(controls, "validation.jsonl"),
               Path(validation_dir, "validation.jsonl").read_bytes())
    _write_new(os.path.join(controls, "reconciliation.json"),
               _canonical(validation["reconciliation"]))
    _install_mutation_authority(
        controls, snapshot=snapshot, reality=reality,
        reality_transcript=reality_transcript,
        canonical_transcript=canonical_transcript,
        m2_manifest_sha256=approval.m2_manifest_sha256,
        m2_tree_sha256=approval.m2_tree_sha256)
    release_manifest, release_tree = _release_file_manifest(release_dir)
    release_manifest.update({
        "project": project, "released_item_ids": released_ids,
        "tree_sha256": release_tree})
    release_manifest_raw = _canonical(release_manifest)
    release_manifest_path = os.path.join(output, "release-manifest.json")
    _write_new(release_manifest_path, release_manifest_raw)

    transcript = {
        "schema": PHASE_SCHEMA, "path": PATH, "project": project,
        "status": "complete_pending_review",
        "execution_identity": approval.execution_identity,
        "authority": authority,
        "inputs": {
            "items_sha256": admission["items_file_sha256"],
            "source_manifest_sha256": approval.source_manifest_sha256,
            "census_sha256": approval.census_sha256,
            "reality_transcript_sha256":
                approval.predecessor_transcript_sha256,
            "reality_manifest_sha256": approval.reality_manifest_sha256,
            "preparation_manifest_sha256":
                approval.preparation_manifest_sha256,
            "closures_sha256": approval.closures_sha256,
            "quality_sha256": approval.quality_sha256,
        },
        "bindings": bindings,
        "worker": {
            "image_id": approval.image_id, "network": "none",
            "pull": "never",
            "commands": [command for worker in workers
                         for command in worker.commands],
        },
        "validation": {
            "path": "validation", **validation},
        "release": {
            "root": "release", "items": "release/items.jsonl",
            "reference_gold": "release/reference-gold",
            "control_artifacts": "release/control-artifacts",
            "summary": release,
            "manifest_path": "release-manifest.json",
            "manifest_sha256": _sha256(release_manifest_raw),
            "tree_sha256": release_tree,
        },
    }
    _write_new(os.path.join(output, "transcript.json"), _canonical(transcript))
    return transcript


def finalize_release(
        project: str, *, items_path: str, census_path: str,
        closures_path: str, quality_path: str, validation_root: str,
        out: str, approval_path: str | None,
        approved_digest: str | None) -> dict:
    """Source-only stopped review: mark exact generated bytes provided."""
    approval = _approval(project, "release", approval_path, approved_digest)
    try:
        precontact_admission(project, items_path)
        root = minimal._absolute(validation_root, "validation phase root")
        transcript_path = os.path.join(root, "transcript.json")
        transcript_raw = Path(transcript_path).read_bytes()
        if _sha256(transcript_raw) != approval.predecessor_transcript_sha256:
            raise _refuse("validation transcript differs from final approval")
        transcript = json.loads(transcript_raw)
        if not isinstance(transcript, dict) \
                or transcript.get("schema") != PHASE_SCHEMA \
                or transcript.get("path") != PATH \
                or transcript.get("project") != project \
                or transcript.get("status") != "complete_pending_review":
            raise _refuse("final predecessor is not a pending validation phase")
        validation = validate_standard_release(
            project, items_path=items_path, census_path=census_path,
            closures_path=closures_path, quality_path=quality_path,
            ledger_path=os.path.join(root, "validation", "validation.jsonl"),
            manifest_path=os.path.join(root, "validation", "manifest.json"),
            records_root=os.path.join(root, "validation", "records"))
        release_ref = transcript.get("release", {})
        if validation["manifest_sha256"] \
                != approval.validation_manifest_sha256 \
                or validation["ledger_sha256"] \
                != approval.validation_ledger_sha256 \
                or release_ref.get("manifest_sha256") \
                != approval.release_manifest_sha256 \
                or release_ref.get("tree_sha256") \
                != approval.release_tree_sha256:
            raise _refuse("reviewed final hashes differ from validation output")
        release_manifest = _validate_release_file_manifest(
            os.path.join(root, "release"),
            os.path.join(root, "release-manifest.json"),
            approval.release_manifest_sha256,
            approval.release_tree_sha256)
        if release_manifest.get("project") != project \
                or release_manifest.get("released_item_ids") \
                != validation["released_item_ids"] \
                or release_manifest.get("tree_sha256") \
                != approval.release_tree_sha256:
            raise _refuse("release manifest population differs from N=3")
    except JavaReleaseValidationRefused:
        raise
    except (OSError, RuntimeError, KeyError, TypeError, ValueError,
            json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _refuse("final release evidence is invalid") from exc
    receipt = {
        "schema": RELEASE_RECEIPT_SCHEMA, "path": PATH,
        "project": project, "status": "provided",
        "execution_identity": approval.execution_identity,
        "validation_transcript_sha256":
            approval.predecessor_transcript_sha256,
        "validation_manifest_sha256":
            approval.validation_manifest_sha256,
        "validation_ledger_sha256": approval.validation_ledger_sha256,
        "release_manifest_sha256": approval.release_manifest_sha256,
        "release_tree_sha256": approval.release_tree_sha256,
        "released_item_ids": validation["released_item_ids"],
        "operator_approved_digest": approved_digest,
    }
    target = minimal._absolute(out, "release receipt output")
    if os.path.lexists(target):
        raise _refuse("release receipt output must be absent")
    _write_new(target, _canonical(receipt))
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m benchmark.r2t.java.release_validation")
    sub = parser.add_subparsers(dest="command", required=True)
    source = sub.add_parser("source-artifacts")
    for argument in (
            "project", "items", "census", "reality-transcript",
            "approved-reality-sha256", "source-root", "source-manifest",
            "preparation-manifest", "boundary", "profile", "out"):
        source.add_argument("--" + argument, required=True,
                            choices=(sorted(PROJECTS)
                                     if argument == "project" else None))
    dispositions = sub.add_parser("dispositions")
    dispositions.add_argument("--project", required=True,
                              choices=sorted(PROJECTS))
    dispositions.add_argument("--items", required=True)
    dispositions.add_argument("--census", required=True)
    dispositions.add_argument("--source-closures", required=True)
    dispositions.add_argument("--source-quality", required=True)
    dispositions.add_argument("--out", required=True)

    run = sub.add_parser("run")
    for argument in ("project", "items", "census", "closures", "quality",
                     "source-root", "source-manifest",
                     "preparation-manifest", "reality-transcript",
                     "canonical-transcript", "out", "approval",
                     "approved-digest", "docker-authority"):
        run.add_argument("--" + argument, required=True,
                         choices=(sorted(PROJECTS)
                                  if argument == "project" else None))
    run.add_argument("--timeout", type=int, default=600)

    final = sub.add_parser("finalize")
    for argument in ("project", "items", "census", "closures", "quality",
                     "validation-root", "out", "approval",
                     "approved-digest"):
        final.add_argument("--" + argument, required=True,
                           choices=(sorted(PROJECTS)
                                    if argument == "project" else None))
    args = parser.parse_args(argv)

    if args.command == "source-artifacts":
        document = produce_source_artifacts(
            args.project, items_path=args.items, census_path=args.census,
            reality_transcript=args.reality_transcript,
            approved_reality_sha256=args.approved_reality_sha256,
            source_root=args.source_root,
            source_manifest=args.source_manifest,
            preparation_manifest=args.preparation_manifest,
            boundary_path=args.boundary, profile_path=args.profile,
            out=args.out)
    elif args.command == "dispositions":
        document = produce_complete_dispositions(
            args.project, items_path=args.items, census_path=args.census,
            source_closures_path=args.source_closures,
            source_quality_path=args.source_quality, out=args.out)
    elif args.command == "run":
        approval = _approval(
            args.project, "validation", args.approval,
            args.approved_digest)
        authority_path = minimal._absolute(
            args.docker_authority, "release Docker authority")
        if (approval.authority_reference or {}).get("path") != authority_path:
            raise _refuse("CLI Docker authority differs from validation approval")
        from ..core import docker_cli
        from ..toolkit.epubcheck_image import LiveDockerRunner
        docker_cli.configure(authority_path=authority_path)
        runner = LiveDockerRunner(
            approval.authority_reference or {},
            argv_validator=validate_release_docker_argv,
            mutation_predicate=lambda _argv: True)
        document = run_approved_validation(
            args.project, items_path=args.items, census_path=args.census,
            closures_path=args.closures, quality_path=args.quality,
            source_root=args.source_root,
            source_manifest=args.source_manifest,
            preparation_manifest=args.preparation_manifest,
            reality_transcript=args.reality_transcript,
            canonical_transcript=args.canonical_transcript,
            out=args.out, runner=runner, approval_path=args.approval,
            approved_digest=args.approved_digest, timeout=args.timeout)
    else:
        document = finalize_release(
            args.project, items_path=args.items, census_path=args.census,
            closures_path=args.closures, quality_path=args.quality,
            validation_root=args.validation_root, out=args.out,
            approval_path=args.approval,
            approved_digest=args.approved_digest)
    print(json.dumps(document, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
