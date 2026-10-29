"""Build the versioned per-project scoring bundles.

The writer half of `data/bundle.py` (wave M5): `build_bundle` stages the
recorded roles, the frozen v1 engine producer and the published
eval100-std arm into one archive, then validates what it staged with the
reader half it is built on.  Fetching and validating an installed bundle
stays in `data/bundle.py`, which this module imports; nothing there
imports this.
"""
from __future__ import annotations

import gzip
import json
import os
import shutil
import tarfile
import tempfile
from typing import Iterable, Optional

from ..data.bundle import (ASSET_INDEX, BENCHMARK, DATASET_MANIFEST,
                            STD_ARM_REPOSITORY_INPUTS, STD_ARM_ROLES,
                            _annotated_release_declaration,
                            _artifact_path, _authority,
                            _coverage_oracle_declaration,
                            _legacy_evidence_declaration, _read_json,
                            _release_pool_declaration,
                            _recorded, _refuse, _sha256_file, _shipping_list,
                            _scoring_gold_declaration,
                            _std_arm, _std_arm_plan, _std_path,
                            _validate_annotated_release,
                            validate_installed_bundle)
REPOSITORY_ROOT = os.path.dirname(BENCHMARK)
LEGACY_REPORTS = {
    "coreshop": os.path.join(
        BENCHMARK, "release", "legacy_consistency",
        "cell2_coreshop_openhands.json"),
    "python-docx": os.path.join(
        BENCHMARK, "release", "legacy_consistency",
        "cell4_python_docx_aider.json"),
}


def _write_json(path: str, value: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(value, fh, indent=1, sort_keys=True)
        fh.write("\n")


def _copy_file(source: str, destination: str) -> None:
    if not os.path.isfile(source):
        _refuse(f"bundle input is not a file: {source}")
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    shutil.copyfile(source, destination)


def _historical_report(project: str, path: Optional[str] = None) -> dict:
    if path is None:
        try:
            path = LEGACY_REPORTS[project]
        except KeyError:
            _refuse(f"no preserved legacy mutation evidence for {project!r}")
    report = _read_json(path, f"{project} legacy consistency report")
    if report.get("schema") != "r2t.mutation-validation/1" \
            or report.get("status") != "valid" \
            or (report.get("evidence") or {}).get("validation_class") \
            != "legacy_consistency":
        _refuse(f"{project} preserved mutation report is not valid legacy "
                "evidence")
    if (report.get("asset_index") or {}).get("project") != project:
        _refuse(f"legacy consistency report is not for {project!r}")
    return report


def _match_historical(report: dict, label: str, path: str) -> None:
    expected = (report.get("inputs") or {}).get(label, {}).get("sha256")
    actual = _sha256_file(path) if os.path.isfile(path) else None
    if not expected or actual != expected:
        _refuse(f"{label} SHA-256 is {actual}, preserved evidence says "
                f"{expected}")


def _historical_release_path(project: str, report: dict,
                             report_path: Optional[str] = None,
                             supplied_path: Optional[str] = None) -> str:
    if supplied_path is not None:
        _match_historical(report, "release", supplied_path)
        return supplied_path
    reference = report["inputs"]["release"]["path"]
    if os.path.isabs(reference):
        path = reference
    else:
        if report_path is None:
            report_path = LEGACY_REPORTS[project]
        base = report["path_base"]["relative_to_report"]
        root = os.path.realpath(os.path.join(os.path.dirname(report_path), base))
        path = os.path.join(root, *reference.split("/"))
    _match_historical(report, "release", path)
    return path


def _declared_release_items(dataset: dict, pool: dict,
                            release_root: str) -> str:
    """The release pool a bundle without preserved evidence ships.

    For the Slice 1 projects the legacy report pins the pool bytes; here the
    manifest's `release_pool` declaration and its release inventory do, and
    both must agree with the file, so the bundle ships exactly the pool the
    reviewed manifest names and never the whole population by inference.
    """
    relative = pool["file"]
    path = os.path.join(release_root, *relative.split("/"))
    inventory = (dataset.get("release_inventory") or {}).get("files") or {}
    actual = _sha256_file(path) if os.path.isfile(path) else None
    if actual is None or actual != pool["sha256"] \
            or inventory.get(relative) != actual:
        _refuse(f"release pool {relative} is not the declared, inventoried "
                f"release file (on disk {actual}; declared {pool['sha256']}; "
                f"inventory {inventory.get(relative)})")
    return path


def _current_sources(project: str, block: dict, *,
                     legacy: bool = True) -> dict:
    """The repository-side inputs: profile and boundary, and for a project
    with preserved mutation evidence the asset index and engine source."""
    if not legacy:
        # The profile names its boundary; nothing here guesses how the file
        # beside it is spelled.
        from ..data.profile import ProfileError, load_profile, profile_path_for
        profile = profile_path_for(None, project)
        if not os.path.exists(profile):
            _refuse(f"current profile is missing: {profile}")
        try:
            boundary = load_profile(profile).boundary_path
        except ProfileError as exc:
            _refuse(str(exc).removeprefix("REFUSED: "))
        if not os.path.exists(boundary):
            _refuse(f"current boundary is missing: {boundary}")
        return {"boundary": boundary, "profile": profile}
    from ..data import mutation_attestation as A
    from ..bench.mutation_run import binding_for

    index = _read_json(ASSET_INDEX, "mutation asset index")
    A.validate_asset_index(index)
    entry = index["projects"].get(project)
    if entry is None:
        _refuse(f"mutation asset index has no project {project!r}")
    boundary = os.path.join(REPOSITORY_ROOT,
                            *entry["boundary"]["config"].split("/"))
    engine_dir, applier = binding_for(entry["engine"])
    engine_source = os.path.join(engine_dir, applier.source)
    profile = os.path.join(
        BENCHMARK, "config", f"profile_{project.replace('-', '_')}.yml")
    for label, path in (("boundary", boundary), ("engine source", engine_source),
                        ("profile", profile)):
        if not os.path.exists(path):
            _refuse(f"current {label} is missing: {path}")
    return {
        "mutation_asset_index": ASSET_INDEX,
        "boundary": boundary,
        "engine_source": engine_source,
        "profile": profile,
    }


def _std_arm_sources(list_path: str, declaration: dict, document: dict,
                     expected: dict) -> dict:
    """`{role: producer-host path}` for the roles the std arm ADDS.

    Evidence roles keep the absolute spelling the ceremony recorded, because
    that is where the preserved bytes are.  The ceremony's own outputs are
    taken from beside the shipping list instead, so an evidence directory
    that moves intact still builds; their digests are checked either way.
    """
    list_path = os.path.abspath(list_path)
    out_dir = os.path.dirname(list_path)
    sources = {}
    for role, (_destination, kind, tail) in STD_ARM_ROLES.items():
        if kind == "evidence":
            named = sorted({entry["path"] for entry in document["files"]
                            if entry["path"].endswith("/" + tail)})
            if len(named) != 1:
                _refuse(f"the eval100-std shipping list records {len(named)} "
                        f"preserved paths for {role}; exactly one location "
                        "is required to build from")
            source = named[0]
        elif kind == "out":
            source = os.path.join(out_dir, tail)
        elif tail == "shipping_list":
            source = list_path
        else:
            source = os.path.join(out_dir, declaration["ceremony"][tail])
        if os.path.islink(source) or not os.path.isfile(source):
            _refuse(f"eval100-std {role} is absent or is not a regular file: "
                    f"{source}")
        actual = _sha256_file(source)
        if actual != expected[role]:
            _refuse(f"eval100-std {role} at {source} hashes to {actual}, the "
                    f"ceremony recorded {expected[role]}")
        sources[role] = source
    return sources


def _std_arm_repository_inputs(document: dict,
                               root: str = REPOSITORY_ROOT) -> None:
    """Re-hash the recorded repository inputs this builder must still match."""
    for tail, verify in STD_ARM_REPOSITORY_INPUTS.items():
        recorded = _recorded(document, tail, f"repository input {tail}")
        if not verify:
            continue
        path = os.path.join(root, *tail.split("/"))
        actual = _sha256_file(path) if os.path.isfile(path) else None
        if actual != recorded:
            _refuse(f"this checkout's {tail} hashes to {actual}, but the "
                    f"eval100-std ceremony rendered against {recorded}; the "
                    "published table and the shipped arm must be one pair")


def _stage_engine_source(project: str, live_source: str,
                         destination: str) -> None:
    """Stage the bytes the FROZEN INDEX pins, not the live enumerator's.

    `binding_for` resolves the CURRENT applier, and both current appliers
    have moved on: at the reviewed tag `r2t/php/mutate.php` hashes
    `0da1838b...` while the frozen index pins the v1 producer `391436fc...`,
    and `r2t/py/mutate.py` has diverged the same way.  Copying the live file
    makes `validate_index_binding` refuse the build outright -- neither
    project's asset can be rebuilt today -- and would misattribute the
    preserved population if the digests ever coincided again.  `VERSIONS.yml`
    records the producer as a Git blob and `validate_asset_pins` already
    treats that object as the pin's subject; this stages exactly it.
    """
    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT
    index = _read_json(ASSET_INDEX, "mutation asset index")
    pinned = (index.get("projects") or {}).get(project, {}).get(
        "engine_source", {}).get("sha256")
    logical = os.path.relpath(live_source, REPOSITORY_ROOT).replace(
        os.sep, "/")
    binding = A.legacy_engine_source_bindings().get(logical)
    if binding is None or binding["sha256"] != pinned:
        _copy_file(live_source, destination)
        return
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    AUDIT.materialise_legacy_engine_source(binding, destination)


def _stage_gold(project: str, source: str, target: str) -> dict:
    """Preserve only PrestaShop's already-verified native resource snapshot."""
    if project != "prestashop":
        shutil.copytree(source, target)
        return {}
    from ..bench import prestashop_resources as resources
    from ..data.bundle import _validate_prestashop_resources
    entries = _validate_prestashop_resources(source)
    # Other gold inputs keep their existing copy semantics. The snapshot's
    # dangling native module link is metadata, not a file to dereference.
    shutil.copytree(source, target, ignore=lambda directory, names:
                    [resources.NAME] if directory == source else [])
    resources._copy_entries(os.path.join(source, resources.NAME),
                            os.path.join(target, resources.NAME), entries)
    _validate_prestashop_resources(target)
    return entries


def _archive_members(root: str) -> list[tuple[str, bool]]:
    members: list[tuple[str, bool]] = []
    for directory, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        rel_dir = os.path.relpath(directory, root)
        if rel_dir != ".":
            members.append((rel_dir.replace(os.sep, "/"), True))
        for name in filenames:
            rel = os.path.join(rel_dir, name) if rel_dir != "." else name
            members.append((rel.replace(os.sep, "/"), False))
    return members


def _write_archive(root: str, out: str, *, sort_members: bool = False,
                   prestashop_resources: Optional[dict] = None,
                   executable_paths: Iterable[str] = ()) -> str:
    if os.path.exists(out):
        _refuse(f"bundle output already exists: {out}")
    parent = os.path.dirname(os.path.abspath(out))
    if not os.path.isdir(parent):
        _refuse(f"bundle output parent does not exist: {parent}")
    try:
        with open(out, "xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                               mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w",
                                  format=tarfile.PAX_FORMAT) as archive:
                    members = _archive_members(root)
                    resources = prestashop_resources or {}
                    executable_paths = set(executable_paths)
                    listed = {rel for rel, _is_dir in members}
                    # os.walk omits directory links. Resource links, whether
                    # live or dangling, must be represented exactly once.
                    members.extend(
                        (rel, False) for rel, entry in sorted(resources.items())
                        if entry["kind"] == "link" and rel not in listed)
                    if sort_members:
                        members.sort(key=lambda item: item[0].encode("utf-8"))
                    for rel, is_dir in members:
                        info = tarfile.TarInfo(rel)
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mtime = 0
                        resource = resources.get(rel)
                        if resource is not None and resource["kind"] == "link":
                            path = os.path.join(root, *rel.split("/"))
                            if not os.path.islink(path) or \
                                    os.readlink(path) != resource["target"]:
                                _refuse(f"protected native resource link changed: {rel}")
                            info.type = tarfile.SYMTYPE
                            info.mode = resource["mode"]
                            info.linkname = resource["target"]
                            archive.addfile(info)
                        elif is_dir:
                            info.type = tarfile.DIRTYPE
                            info.mode = resource["mode"] if resource else 0o755
                            archive.addfile(info)
                        else:
                            path = os.path.join(root, *rel.split("/"))
                            info.size = os.path.getsize(path)
                            info.mode = (resource["mode"] if resource else
                                         0o755 if rel in executable_paths else 0o644)
                            with open(path, "rb") as fh:
                                archive.addfile(info, fh)
    except Exception:
        if os.path.isfile(out):
            os.unlink(out)
        raise
    return _sha256_file(out)


def build_evaluation_bundle(*, inputs_path: str, out: str) -> dict:
    """Build the approved input-only layout from admitted, sealed sources."""
    from ..data import evaluation_bundle as E

    inputs = E._read(inputs_path, "evaluation build inputs")
    E._exact(inputs, {"schema", "project", "version", "producer", "scope",
                      "sources", "admitted_trees", "seed_workspace_members"},
             "evaluation build inputs")
    if inputs["schema"] != E.INPUT_SCHEMA:
        _refuse("unknown evaluation build input schema")
    selected = E.layout(inputs["project"], inputs["version"])
    E._producer(inputs["producer"])
    E._scope(inputs["scope"], inputs["project"])
    sources = E._exact(inputs["sources"],
                       set(selected["files"]) | set(selected["trees"]),
                       "evaluation build source roles")
    for role, source in sources.items():
        if not isinstance(source, str) or not os.path.isabs(source):
            _refuse(f"evaluation source {role} must name an absolute input path")
    admission = E._admission(os.path.join(
        sources["provenance"], "payload-admission.json"), selected,
        reference_attestation=sources["gold_results_attestation"])
    if admission["trees"] != inputs["admitted_trees"] \
            or admission["seed_workspace_members"] != inputs["seed_workspace_members"]:
        _refuse("build descriptor differs from the owner's preserved payload admission")
    for role in selected["trees"]:
        actual = E.tree_paths(sources[role], role)
        if actual != admission["trees"][role]:
            _refuse(f"{role} source contains files outside its admitted inputs")
    out = os.path.abspath(out)
    manifest_out = out + ".manifest.json"
    if os.path.basename(out) != selected["asset"]:
        _refuse(f"evaluation archive must be named {selected['asset']}")
    if os.path.lexists(out) or os.path.lexists(manifest_out):
        _refuse("evaluation archive or manifest output already exists")
    with tempfile.TemporaryDirectory(prefix="r2t-evaluation-build-") as temporary:
        stage = os.path.join(temporary, "root")
        os.mkdir(stage)
        roles = {}
        for role, relative in selected["files"].items():
            if os.path.islink(sources[role]):
                _refuse(f"evaluation source {role} is linked")
            target = E._at(stage, relative)
            _copy_file(sources[role], target)
            roles[role] = {"path": relative, "sha256": _sha256_file(target)}
        for role, relative in selected["trees"].items():
            target = E._at(stage, relative)
            shutil.copytree(sources[role], target)
            inventory = f"{selected['bundle_root']}/trees/{role}.json"
            E.write_document(E._at(stage, inventory), E.tree_document(target, role))
            roles[role] = {"path": relative, "manifest_path": inventory,
                           "manifest_sha256": _sha256_file(E._at(stage, inventory))}
        manifest = {"schema": selected["schema"], "project": inputs["project"],
                    "version": selected["version"], "producer": inputs["producer"],
                    "scope": inputs["scope"], "roles": roles}
        manifest["digest"] = E.document_digest(manifest)
        E.write_document(E._at(stage, selected["manifest"]), manifest)
        E._validate_evaluation_payload(project=inputs["project"],
                                       version=selected["version"], root=stage)
        executables = []
        if inputs["project"] == "coddy-agent":
            prefix = selected["trees"]["go_toolchain"]
            executables = [f"{prefix}/{relative}" for relative in E.tree_paths(
                E._at(stage, prefix), "go_toolchain")
                if os.stat(E._at(stage, f"{prefix}/{relative}")).st_mode & 0o111]
        digest = _write_archive(stage, out, sort_members=True,
                                executable_paths=executables)
        try:
            E.write_document(manifest_out, manifest)
        except Exception:
            os.unlink(out)
            raise
    return {"project": inputs["project"], "version": selected["version"],
            "out": out, "sha256": digest, "manifest": manifest_out,
            "release_ready": True, "scope": inputs["scope"]}


def build_bundle(*, project: str, version: str, out: str,
                 seed_dir: Optional[str] = None, gold_dir: Optional[str] = None,
                 release_gold: Optional[str] = None,
                 raw_manifest: Optional[str] = None, legacy_map: Optional[str] = None,
                 coverage_run: Optional[str] = None,
                 candidate_run: Optional[str] = None, candidate_results: Optional[str] = None,
                 gold_results: Optional[str] = None,
                 production_index: Optional[str] = None,
                 audit_attestation: Optional[str] = None,
                 alias_table: Optional[str] = None,
                 autowirable_types: Optional[str] = None,
                 std_arm: Optional[str] = None,
                 legacy_report: Optional[str] = None,
                 scoring_gold: Optional[str] = None,
                 historical_release: Optional[str] = None,
                 annotated_release: Optional[str] = None,
                 inputs_path: Optional[str] = None,
                 manifest_path: str = DATASET_MANIFEST,
                 release_root: str = os.path.join(BENCHMARK, "release")) -> dict:
    """Construct one deterministic archive from the preserved v1 evidence,
    or from the seed, gold and release alone when the dataset manifest
    declares no such evidence for the project."""
    from ..data import evaluation_bundle as E
    historical = {
        "seed": seed_dir, "gold": gold_dir, "release-gold": release_gold,
        "raw-manifest": raw_manifest, "legacy-map": legacy_map,
        "coverage-run": coverage_run, "candidate-run": candidate_run,
        "candidate-results": candidate_results, "gold-results": gold_results,
        "production-index": production_index, "audit-attestation": audit_attestation,
        "alias-table": alias_table, "autowirable-types": autowirable_types,
        "std-arm": std_arm, "legacy-report": legacy_report,
        "scoring-gold": scoring_gold, "historical-release": historical_release,
        "annotated-release": annotated_release,
    }
    if E.is_evaluation_bundle(project, version):
        conflicting = ["--" + name for name, value in historical.items() if value is not None]
        if conflicting:
            _refuse("evaluation builds accept only --inputs; incompatible inputs: "
                    + ", ".join(conflicting))
        if inputs_path is None:
            _refuse("evaluation bundle build requires --inputs")
        descriptor = E._read(inputs_path, "evaluation build inputs")
        if descriptor.get("project") != project or str(descriptor.get("version")) != str(version):
            _refuse("evaluation build inputs name another project or version")
        return build_evaluation_bundle(inputs_path=inputs_path, out=out)
    if inputs_path is not None:
        _refuse("historical bundle builds do not accept evaluation --inputs")
    core = ("seed", "gold", "release-gold", "coverage-run")
    missing = ["--" + name for name in core if historical[name] is None]
    if missing:
        _refuse("historical bundle build requires " + ", ".join(missing))
    dataset, block = _authority(project, version, manifest_path)
    bundle = block["bundle"]
    artifacts = bundle["artifacts"]
    legacy = _legacy_evidence_declaration(project, block)
    pool = _release_pool_declaration(project, block, legacy)
    oracle = _coverage_oracle_declaration(project, block, legacy)
    legacy_inputs = ("raw-manifest", "legacy-map", "candidate-run",
                     "candidate-results", "gold-results")
    if legacy is not None:
        missing = ["--" + name for name in legacy_inputs
                   if historical[name] is None]
        if missing:
            _refuse("historical bundle build requires " + ", ".join(missing))
    else:
        offered = ["--" + name for name in
                   (*legacy_inputs, "legacy-report", "historical-release",
                    "audit-attestation")
                   if historical[name] is not None]
        if offered:
            _refuse(f"{project} declares no legacy mutation evidence; "
                    + ", ".join(offered)
                    + " name evidence this bundle cannot ship")
    annotation = _annotated_release_declaration(project, block)
    if (annotated_release is None) != (annotation is None):
        _refuse("--annotated-release input and declared bundle role disagree")
    scoring_declaration = _scoring_gold_declaration(project, block)
    if (scoring_gold is None) != (scoring_declaration is None):
        _refuse("--scoring-gold input and declared bundle role disagree")
    if scoring_gold is not None:
        actual = _sha256_file(scoring_gold) if os.path.isfile(scoring_gold) else None
        if actual != scoring_declaration["sha256"]:
            _refuse(f"scoring gold SHA-256 is {actual}, dataset manifest "
                    f"says {scoring_declaration['sha256']}")
    if os.path.basename(out) != bundle["asset"]["name"]:
        _refuse(f"bundle output basename must be {bundle['asset']['name']}")
    declaration = _std_arm(version, block)
    if declaration is None and std_arm is not None:
        _refuse(f"{project} bundle {version} declares no eval100-std arm, so "
                "--std-arm names evidence this asset cannot ship")
    if declaration is not None and std_arm is None:
        _refuse(f"{project} bundle {version} ships the published eval100-std "
                "arm; --std-arm must name the J3 ceremony's shipping list "
                f"({declaration['ceremony']['shipping_list']})")
    std_sources: dict = {}
    if declaration is not None:
        document = _shipping_list(std_arm, declaration)
        _std_arm_repository_inputs(document)
        std_sources = _std_arm_sources(
            std_arm, declaration, document,
            _std_arm_plan(declaration, document))
    if legacy is not None:
        report = _historical_report(project, legacy_report)
        supplied = {
            "raw_manifest": raw_manifest,
            "map": legacy_map,
            "coverage_run": coverage_run,
            "candidate_run": candidate_run,
            "candidate_results": candidate_results,
            "gold_results": gold_results,
        }
        for label, path in supplied.items():
            _match_historical(report, label, path)
        _match_historical(report, "gold_baseline", coverage_run)
        release_items = _historical_release_path(
            project, report, legacy_report, historical_release)
    else:
        release_items = _declared_release_items(dataset, pool, release_root)
        actual = (_sha256_file(coverage_run) if os.path.isfile(coverage_run)
                  else None)
        if actual != oracle["sha256"]:
            _refuse(f"coverage oracle SHA-256 is {actual}, dataset manifest "
                    f"says {oracle['sha256']}")
    if annotation is not None:
        _validate_annotated_release(annotated_release, release_items, annotation)
    if not os.path.isdir(release_gold):
        _refuse(f"release gold is not a directory: {release_gold}")
    if not os.path.isfile(os.path.join(gold_dir, "strip_manifest.json")):
        _refuse(f"gold tree has no strip_manifest.json: {gold_dir}")

    from ..bench import seed as S
    seed_manifest = os.path.join(seed_dir, S.SEED_MANIFEST)
    expected_seed = bundle["seed"]["manifest_sha256"]
    actual_seed = (_sha256_file(seed_manifest)
                   if os.path.isfile(seed_manifest) else None)
    if actual_seed != expected_seed:
        _refuse(f"seed manifest SHA-256 is {actual_seed}, dataset manifest "
                f"says {expected_seed}")
    seed_report = S.verify_seed(seed_dir)
    if not seed_report["artifacts_ok"]:
        _refuse("canonical seed archive does not verify")

    expected_prod = bundle["production_index"]
    if expected_prod is None:
        if production_index is not None:
            _refuse(f"{project} declares no production-method index")
    else:
        if production_index is None:
            _refuse(f"{project} bundle needs --production-index")
        actual = _sha256_file(production_index)
        if actual != expected_prod["sha256"]:
            _refuse(f"production index SHA-256 is {actual}, dataset manifest "
                    f"says {expected_prod['sha256']}")
    if (audit_attestation is None) != (artifacts["audit_attestation"] is None):
        _refuse("audit attestation input and declared bundle role disagree")
    runtime_indexes = {
        "alias_table": alias_table,
        "autowirable_types": autowirable_types,
    }
    for role, source in runtime_indexes.items():
        if (source is None) != (artifacts[role] is None):
            _refuse(f"{role} input and declared bundle role disagree")

    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT
    try:
        current = _current_sources(project, block, legacy=legacy is not None)
    except (A.MutationAssetRefused, OSError, ValueError) as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))
    with tempfile.TemporaryDirectory(prefix="r2t-bundle-build-") as temporary:
        stage = os.path.join(temporary, "root")
        os.makedirs(stage)

        def destination(role: str) -> str:
            path = _artifact_path(stage, block, role)
            assert path is not None
            return path

        _copy_file(release_items, destination("release_items"))
        if annotated_release is not None:
            _copy_file(annotated_release, destination("annotated_release_items"))
        shutil.copytree(release_gold, destination("release_gold"))
        native_resources = _stage_gold(project, gold_dir, destination("gold"))
        for role in ("profile", "boundary"):
            _copy_file(current[role], destination(role))
        if legacy is not None:
            _copy_file(current["mutation_asset_index"],
                       destination("mutation_asset_index"))
            _stage_engine_source(project, current["engine_source"],
                                 destination("engine_source"))
        for role, source in std_sources.items():
            _copy_file(source, _std_path(stage, role))
        if legacy is not None:
            for role, source in (
                    ("raw_manifest", raw_manifest), ("legacy_map", legacy_map),
                    ("coverage_run", coverage_run),
                    ("gold_results", gold_results),
                    ("candidate_run", candidate_run),
                    ("candidate_results", candidate_results)):
                _copy_file(source, destination(role))
        else:
            _copy_file(coverage_run, destination("coverage_run"))
        shutil.copytree(seed_dir, destination("seed"))
        if production_index is not None:
            _copy_file(production_index, destination("production_index"))
        if scoring_gold is not None:
            _copy_file(scoring_gold, destination("scoring_gold"))
        if audit_attestation is not None:
            _copy_file(audit_attestation, destination("audit_attestation"))
        for role, source in runtime_indexes.items():
            if source is not None:
                _copy_file(source, destination(role))

        if legacy is not None:
            validation_paths = {
                "raw_manifest": destination("raw_manifest"),
                "map": destination("legacy_map"),
                "coverage_run": destination("coverage_run"),
                "release": destination("release_items"),
                "asset_index": destination("mutation_asset_index"),
                "boundary": destination("boundary"),
                "engine_source": destination("engine_source"),
                "candidate_run": destination("candidate_run"),
                "gold_baseline": destination("gold_baseline"),
                "candidate_results": destination("candidate_results"),
                "gold_results": destination("gold_results"),
            }
            validation_references = {
                "raw_manifest": artifacts["raw_manifest"],
                "map": artifacts["legacy_map"],
                "coverage_run": artifacts["coverage_run"],
                "release": artifacts["release_items"],
                "asset_index": artifacts["mutation_asset_index"],
                "boundary": artifacts["boundary"],
                "engine_source": artifacts["engine_source"],
                "candidate_run": artifacts["candidate_run"],
                "gold_baseline": artifacts["gold_baseline"],
                "candidate_results": artifacts["candidate_results"],
                "gold_results": artifacts["gold_results"],
            }
            if audit_attestation is not None:
                validation_paths["audit_attestation"] = destination(
                    "audit_attestation")
                validation_references["audit_attestation"] = artifacts[
                    "audit_attestation"]

            try:
                built = AUDIT.build_legacy_validation_report(
                    project=project, paths=validation_paths,
                    references=validation_references,
                    relative_to_report="../../..")
                _write_json(destination("scored_manifest"),
                            built["scored_manifest"])
                _write_json(destination("mutation_map"), built["mutation_map"])
                _write_json(destination("gold_results_attestation"),
                            built["report"])
                native_paths = {
                    "raw_manifest": destination("raw_manifest"),
                    "manifest": destination("scored_manifest"),
                    "map": destination("mutation_map"),
                    "coverage_run": destination("coverage_run"),
                    "release": destination("release_items"),
                    "asset_index": destination("mutation_asset_index"),
                    "boundary": destination("boundary"),
                    "engine_source": destination("engine_source"),
                }
                native_references = {
                    "raw_manifest": artifacts["raw_manifest"],
                    "manifest": artifacts["scored_manifest"],
                    "map": artifacts["mutation_map"],
                    "coverage_run": artifacts["coverage_run"],
                    "release": artifacts["release_items"],
                    "asset_index": artifacts["mutation_asset_index"],
                    "boundary": artifacts["boundary"],
                    "engine_source": artifacts["engine_source"],
                }
                if audit_attestation is not None:
                    native_paths["audit_attestation"] = destination(
                        "audit_attestation")
                    native_references["audit_attestation"] = artifacts[
                        "audit_attestation"]
                native = AUDIT.build_native_validation_report(
                    project=project, paths=native_paths,
                    references=native_references, relative_to_report="../../..")
                _write_json(destination("mutation_validation"), native)
            except (A.MutationAssetRefused, OSError, ValueError) as exc:
                _refuse(str(exc).removeprefix("REFUSED: "))
        _write_json(destination("worker_plan"), {
            "schema": "r2t.worker-plan/1",
            "project": project,
            **bundle["worker_plan"],
        })
        validate_installed_bundle(
            project, version, stage, authority=dataset, block=block)
        from ..bench.prestashop_resources import NAME as resource_name
        resource_prefix = os.path.relpath(
            os.path.join(destination("gold"), resource_name), stage)
        resource_prefix = resource_prefix.replace(os.sep, "/")
        archive_sha256 = _write_archive(stage, out, prestashop_resources={
            f"{resource_prefix}/{rel}": entry
            for rel, entry in native_resources.items()})
        expected_archive = bundle["asset"]["sha256"]
        if expected_archive is not None and archive_sha256 != expected_archive:
            os.unlink(out)
            _refuse(f"rebuilt asset SHA-256 is {archive_sha256}, dataset "
                    f"manifest says {expected_archive}")
    return {"project": project, "version": version, "out": out,
            "sha256": archive_sha256,
            "release_ready": (built["report"]["asset_index"]["release_ready"]
                              if legacy is not None else None)}


def selftest() -> int:
    from types import SimpleNamespace
    from unittest.mock import patch
    import hashlib
    import urllib.error
    import urllib.request
    from ..data.bundle import (BundleRefused, GITHUB_TOKEN_ENV,
                                STD_ARM_RECORDED_COPIES, STD_ARM_REPORT_INPUTS,
                                STD_ARM_SHARED_ROLES, _download_asset,
                                _extract_verified_archive, _gold_digest,
                                _validate_release_gold, _validate_std_arm,
                                _validate_scoring_gold, installed_scoring_gold,
                                fetch_bundle)

    ok = True
    declared_versions = {
        project: block["bundle"]["version"]
        for project, block in _read_json(
            DATASET_MANIFEST, "dataset manifest")["projects"].items()
        if block.get("bundle") is not None}

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
        import contextlib
        import io
        from ..bench import cli as C

        def at(name: str) -> str:
            return os.path.join(temporary, name)

        old_report = _historical_report("python-docx")
        check("omitting --legacy-report retains the preserved baseline pin",
              old_report["inputs"]["coverage_run"]["sha256"]
              == "3f8bc40cd92001a574cd337ef95137a1cf032ea4e74f1a809270e5a45b3fc52f")
        _write_json(at("release.jsonl"), {"item_id": "i"})
        _write_json(at("gold.jsonl"), {
            "item_id": "i", "outcome": "passed", "direct_calls": []})
        roles = ("raw_manifest", "map", "coverage_run", "candidate_run",
                 "candidate_results", "gold_results", "gold_baseline")
        report = copy.deepcopy(old_report)
        report["inputs"] = {
            role: {"path": "gold.jsonl", "sha256": _sha256_file(at("gold.jsonl"))}
            for role in roles}
        report["inputs"]["release"] = {
            "path": "release.jsonl", "sha256": _sha256_file(at("release.jsonl"))}
        report["path_base"]["relative_to_report"] = ".."
        report_path = at("reports/recollected.json")
        _write_json(report_path, report)
        selected = _historical_report("python-docx", report_path)
        check("a selected report resolves release items from its own directory",
              _historical_release_path("python-docx", selected, report_path)
              == at("release.jsonl"))
        for role in roles:
            _match_historical(selected, role, at("gold.jsonl"))
            check(f"the selected report still refuses different {role} bytes",
                  refused(lambda: _match_historical(
                      selected, role, at("release.jsonl")), "SHA-256"))
        check("the default report refuses the recollected coverage bytes",
              refused(lambda: _match_historical(
                  old_report, "coverage_run", at("gold.jsonl")), "SHA-256"))
        check("an omitted digest and missing file cannot match each other",
              refused(lambda: _match_historical({}, "coverage_run", at("absent")),
                      "SHA-256"))
        for key, value in (("status", "invalid"), ("schema", "unknown"),
                           ("evidence", {"validation_class": "native"}),
                           ("asset_index", {"project": "coreshop"})):
            bad = dict(report, **{key: value})
            _write_json(at("bad.json"), bad)
            check(f"a selected report with wrong {key} refuses",
                  refused(lambda: _historical_report("python-docx", at("bad.json")),
                          "report"))

        # Exercise argparse -> command dispatch -> real builder, stopping at
        # the next missing input before any staging or archive construction.
        # These historical-role tests need an explicitly unannotated fixture,
        # independently of the roles the current published version declares.
        provisional = _read_json(DATASET_MANIFEST, "dataset manifest")
        legacy_bundle = provisional["projects"]["python-docx"]["bundle"]
        legacy_bundle["version"] = "v-test-legacy"
        legacy_bundle["asset"] = {
            "name": "r2t-v-test-legacy-python-docx.tar.gz", "sha256": None}
        for role, declaration in (("annotated_release_items", "annotated_release"),
                                  ("scoring_gold", "scoring_gold")):
            legacy_bundle.pop(declaration, None)
            legacy_bundle["artifacts"].pop(role, None)
        provisional_manifest = at("dataset.json")
        _write_json(provisional_manifest, provisional)
        authority = _authority

        argv = ["bundle", "build", "--project", "python-docx",
                "--version", "v-test-legacy", "--seed", at("seed"),
                "--gold", at("gold"), "--release-gold", at("release-gold"),
                "--out", at(legacy_bundle["asset"]["name"])]
        for option in ("raw-manifest", "legacy-map", "coverage-run",
                       "candidate-run", "candidate-results", "gold-results"):
            argv.extend(["--" + option, at("gold.jsonl")])

        def cli_refused(arguments, message):
            try:
                with contextlib.redirect_stdout(io.StringIO()), \
                        patch(__name__ + "._authority", side_effect=lambda p, v, m:
                              authority(p, v, provisional_manifest)):
                    C.main(arguments)
            except SystemExit as exc:
                return message in str(exc)
            return False

        check("the CLI defaults to old pins and forwards an explicit report "
              "through all historical joins before staging",
              cli_refused(argv, "raw_manifest SHA-256")
              and cli_refused(argv + ["--legacy-report", report_path],
                              "release gold is not a directory"))
        check("the CLI forwards scoring gold and refuses an undeclared role",
              cli_refused(argv + ["--scoring-gold", at("gold.jsonl")],
                          "--scoring-gold input and declared bundle role disagree"))
        check("the CLI forwards annotation and refuses an undeclared role",
              cli_refused(argv + ["--annotated-release", at("release.jsonl")],
                          "--annotated-release input and declared bundle role disagree"))
        shutil.copyfile(at("release.jsonl"), at("frozen.jsonl"))
        _write_json(at("release.jsonl"), {"item_id": "i", "target_interfaces": {
            "behaviour": [], "setup": []}})
        check("a reminted historical pathname refuses by default",
              cli_refused(argv + ["--legacy-report", report_path],
                          "release SHA-256"))
        check("the CLI accepts relocated exact historical bytes after remint",
              cli_refused(argv + ["--legacy-report", report_path,
                                 "--historical-release", at("frozen.jsonl")],
                          "release gold is not a directory"))
        check("relocated historical input still enforces the unchanged digest",
              cli_refused(argv + ["--legacy-report", report_path,
                                 "--historical-release", at("gold.jsonl")],
                          "release SHA-256"))
        shutil.copyfile(at("frozen.jsonl"), at("release.jsonl"))
        selected["inputs"]["release"]["path"] = at("release.jsonl")
        check("absolute release paths from mutants validate remain supported",
              _historical_release_path("python-docx", selected, report_path)
              == at("release.jsonl"))
        _write_json(at("release.jsonl"), {"item_id": "changed"})
        check("selected report release bytes must match too",
              refused(lambda: _historical_release_path(
                  "python-docx", selected, report_path), "release SHA-256"))

    # Real staging/archive/installed validation, with tiny mutation authorities.
    # The stubs below leave every new role and historical-file check real.
    with tempfile.TemporaryDirectory() as temporary:
        from ..bench import seed as S
        from ..data import mutation_attestation as A
        from . import mutation_audit as AUDIT

        project = "python-docx"
        dataset = _read_json(DATASET_MANIFEST, "dataset manifest")
        block = dataset["projects"][project]
        bundle = block["bundle"]
        bundle["asset"] = {"name": "r2t-v-test-python-docx.tar.gz", "sha256": None}
        bundle["version"] = "v-test"
        bundle["production_index"] = None
        roles = bundle["artifacts"]
        bundle.pop("scoring_gold", None)
        roles.pop("scoring_gold", None)
        roles["production_index"] = roles["audit_attestation"] = None
        roles["annotated_release_items"] = \
            "projects/python-docx/artifacts/release/annotated_items.jsonl"
        source = os.path.join(temporary, "source")

        def source_path(role):
            return _artifact_path(source, block, role)

        for role in ("raw_manifest", "legacy_map", "coverage_run",
                     "candidate_run", "candidate_results", "gold_results",
                     "boundary", "mutation_asset_index", "engine_source"):
            _write_json(source_path(role), {"fixture": role})
        _copy_file(os.path.join(BENCHMARK, "config", "profile_python_docx.yml"),
                   source_path("profile"))
        _copy_file(os.path.join(BENCHMARK, "config", "boundary_python_docx.yml"),
                   source_path("boundary"))
        original = {"item_id": "one", "scenario": "read"}
        os.makedirs(os.path.dirname(source_path("release_items")))
        with open(source_path("release_items"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(original) + "\n")
        with open(source_path("annotated_release_items"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(original, target_interfaces={
                "behaviour": ["example.Reader"], "setup": []})) + "\n")
        bundle["annotated_release"] = {
            "file": "python-docx/items.jsonl",
            "sha256": _sha256_file(source_path("annotated_release_items"))}
        gold = source_path("gold")
        _write_json(os.path.join(gold, "strip_manifest.json"), {})
        _write_json(os.path.join(gold, "features/steps.json"), {"answer": True})
        release_gold = source_path("release_gold")
        _write_json(os.path.join(release_gold, "manifest.json"), {"one": "one.json"})
        _write_json(os.path.join(release_gold, "one.json"), {
            "item_id": "one", "files": ["features/steps.json"]})
        block["gold_manifest_sha256"] = _sha256_file(
            os.path.join(release_gold, "manifest.json"))
        block["gold_sidecars_sha256"] = _gold_digest(source, block)
        seed = source_path("seed")
        os.makedirs(seed)
        ws = S._tar_workspace(gold, ["features/steps.json"],
                              os.path.join(seed, S.WORKSPACE_TAR), keep_empty=())
        _write_json(os.path.join(seed, S.SEED_MANIFEST), {
            "format": S.SEED_FORMAT, "seed_key": "fixture", "workspace": ws,
            "needs_database": False, "database": {"declared": S.NO_DATABASE}})
        bundle["seed"]["manifest_sha256"] = _sha256_file(
            os.path.join(seed, S.SEED_MANIFEST))
        report = _historical_report(project)
        role_labels = {"raw_manifest": "raw_manifest", "map": "legacy_map",
                       "coverage_run": "coverage_run", "candidate_run": "candidate_run",
                       "candidate_results": "candidate_results", "gold_results": "gold_results",
                       "gold_baseline": "gold_baseline", "release": "release_items"}
        report["inputs"] = {label: {"path": source_path(role),
                                   "sha256": _sha256_file(source_path(role))}
                            for label, role in role_labels.items()}
        report_path = os.path.join(temporary, "legacy.json")
        manifest_path = os.path.join(temporary, "dataset.json")
        _write_json(report_path, report)
        _write_json(manifest_path, dataset)
        options = dict(project=project, version="v-test", seed_dir=seed,
                       gold_dir=gold, release_gold=release_gold,
                       out=os.path.join(temporary, bundle["asset"]["name"]),
                       legacy_report=report_path, manifest_path=manifest_path)
        for key in ("raw_manifest", "legacy_map", "coverage_run", "candidate_run",
                    "candidate_results", "gold_results"):
            options[key] = source_path(key)
        check("a declared annotated companion is required before staging",
              refused(lambda: build_bundle(**options),
                      "--annotated-release input and declared bundle role disagree"))
        options["annotated_release"] = source_path("annotated_release_items")
        bindings = []
        facts = {"manifest": {}, "map": {}, "release_ready": True}

        def legacy_validation(**kwargs):
            bindings.append(kwargs["paths"]["release"])
            return {"scored_manifest": {}, "mutation_map": {},
                    "report": {"asset_index": {"release_ready": True}}}

        def native_validation(**kwargs):
            bindings.append(kwargs["paths"]["release"])
            return {}

        def campaign_validation(*args, **kwargs):
            bindings.append(kwargs["release_path"])
            return facts

        current = {role: source_path(role) for role in (
            "boundary", "profile", "mutation_asset_index", "engine_source")}
        with patch(__name__ + "._current_sources", return_value=current), \
                patch(__name__ + "._stage_engine_source", side_effect=lambda p, s, d: _copy_file(s, d)), \
                patch.object(AUDIT, "build_legacy_validation_report", side_effect=legacy_validation), \
                patch.object(AUDIT, "build_native_validation_report", side_effect=native_validation), \
                patch.object(A, "validate_saved_validation_report", return_value=facts), \
                patch.object(A, "validate_campaign_asset_inputs", side_effect=campaign_validation), \
                patch.object(A, "load_validated_legacy_scoring_inputs", return_value=facts):
            built = build_bundle(**options)
            installed = os.path.join(temporary, "installed")
            _extract_verified_archive(options["out"], asset_name=bundle["asset"]["name"],
                                      expected_sha256=built["sha256"], destination=installed)
            verified = validate_installed_bundle(
                project, "v-test", installed, manifest_path=manifest_path)
            check("annotated bundle builds, extracts and validates both exact files",
                  verified["annotated_release_items"] == roles["annotated_release_items"]
                  and all(open(_artifact_path(installed, block, role), "rb").read()
                          == open(source_path(role), "rb").read()
                          for role in ("release_items", "annotated_release_items")))
            check("all mutation and historical joins still receive the frozen role",
                  len(bindings) == 4
                  and all(path.endswith(roles["release_items"]) for path in bindings))
            with open(_artifact_path(installed, block, "annotated_release_items"),
                      "a", encoding="utf-8") as fh:
                fh.write("\n")
            check("installed bundle rejects changed annotated bytes",
                  refused(lambda: validate_installed_bundle(
                      project, "v-test", installed, manifest_path=manifest_path),
                          "annotated release SHA-256"))

    with tempfile.TemporaryDirectory() as temporary:
        # A project onboarded after Slice 1 has no preserved v1 mutation
        # evidence: its manifest declares every legacy role null and names
        # the release pool its bundle ships, and its bundle is the seed, the
        # gold, the coverage oracle and that pool, built, installed and
        # validated end to end with nothing stubbed.
        from ..bench import seed as S
        from ..data.bundle import (LEGACY_EVIDENCE_ROLES,
                                   _legacy_evidence_declaration,
                                   _release_pool_declaration)
        project = "python-docx"
        dataset = _read_json(DATASET_MANIFEST, "dataset manifest")
        block = dataset["projects"][project]
        bundle = block["bundle"]
        bundle["asset"] = {"name": "r2t-v-lean-python-docx.tar.gz", "sha256": None}
        bundle["version"] = "v-lean"
        bundle["production_index"] = None
        bundle.pop("scoring_gold", None)
        bundle["annotated_release"] = None
        roles = bundle["artifacts"]
        roles.pop("scoring_gold", None)
        roles["annotated_release_items"] = None
        roles["production_index"] = roles["audit_attestation"] = None
        for role in LEGACY_EVIDENCE_ROLES:
            roles[role] = None
        source = os.path.join(temporary, "source")
        release_root = os.path.join(temporary, "release")

        def source_path(role):
            return _artifact_path(source, block, role)

        pool_relative = block["items"]
        pool_path = os.path.join(release_root, *pool_relative.split("/"))
        os.makedirs(os.path.dirname(pool_path))
        with open(pool_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "one", "scenario": "read"}) + "\n")
        pool_sha = _sha256_file(pool_path)
        dataset["release_inventory"] = {"files": {pool_relative: pool_sha}}
        os.makedirs(os.path.dirname(source_path("coverage_run")))
        with open(source_path("coverage_run"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "one", "outcome": "passed",
                                 "coverage_lines": {"src/docx/api.py": [1]}})
                     + "\n")
        gold = source_path("gold")
        _write_json(os.path.join(gold, "strip_manifest.json"), {})
        _write_json(os.path.join(gold, "features/steps.json"), {"answer": True})
        release_gold = source_path("release_gold")
        _write_json(os.path.join(release_gold, "manifest.json"), {"one": "one.json"})
        _write_json(os.path.join(release_gold, "one.json"), {
            "item_id": "one", "files": ["features/steps.json"]})
        block["gold_manifest_sha256"] = _sha256_file(
            os.path.join(release_gold, "manifest.json"))
        block["gold_sidecars_sha256"] = _gold_digest(source, block)
        seed = source_path("seed")
        os.makedirs(seed)
        ws = S._tar_workspace(gold, ["features/steps.json"],
                              os.path.join(seed, S.WORKSPACE_TAR), keep_empty=())
        _write_json(os.path.join(seed, S.SEED_MANIFEST), {
            "format": S.SEED_FORMAT, "seed_key": "fixture", "workspace": ws,
            "needs_database": False, "database": {"declared": S.NO_DATABASE}})
        bundle["seed"]["manifest_sha256"] = _sha256_file(
            os.path.join(seed, S.SEED_MANIFEST))
        manifest_path = os.path.join(temporary, "dataset.json")
        check("a manifest declaring every legacy role null yields no legacy "
              "declaration and must name its release pool",
              _legacy_evidence_declaration(project, block) is None
              and refused(lambda: _release_pool_declaration(
                  project, block, None), "exactly when"))
        bundle["release_pool"] = {"file": pool_relative, "sha256": pool_sha}
        check("...and its coverage oracle's SHA-256",
              refused(lambda: _coverage_oracle_declaration(
                  project, block, None), "exactly when"))
        bundle["coverage_run"] = {"sha256": "0" * 64}
        _write_json(manifest_path, dataset)
        check("the release pool is the declared, inventoried file on disk, "
              "or refused",
              _declared_release_items(dataset, bundle["release_pool"],
                                      release_root) == pool_path
              and refused(lambda: _declared_release_items(
                  {"release_inventory": {"files": {pool_relative: "0" * 64}}},
                  bundle["release_pool"], release_root), "inventoried")
              and refused(lambda: _declared_release_items(
                  dataset, {"file": pool_relative, "sha256": "0" * 64},
                  release_root), "inventoried"))
        options = dict(project=project, version="v-lean", seed_dir=seed,
                       gold_dir=gold, release_gold=release_gold,
                       coverage_run=source_path("coverage_run"),
                       out=os.path.join(temporary, bundle["asset"]["name"]),
                       manifest_path=manifest_path, release_root=release_root)
        check("a coverage oracle other than the declared one is refused",
              refused(lambda: build_bundle(**options), "coverage oracle")
              and not os.path.lexists(options["out"]))
        bundle["coverage_run"] = {"sha256": _sha256_file(
            source_path("coverage_run"))}
        _write_json(manifest_path, dataset)
        check("an input for an undeclared legacy role refuses before staging",
              refused(lambda: build_bundle(
                  **options, raw_manifest=source_path("coverage_run")),
                      "declares no legacy mutation evidence")
              and refused(lambda: build_bundle(
                  **options, legacy_report=manifest_path),
                      "declares no legacy mutation evidence")
              and refused(lambda: build_bundle(
                  **options, audit_attestation=source_path("coverage_run")),
                      "declares no legacy mutation evidence")
              and not os.path.lexists(options["out"]))
        built = build_bundle(**options)
        installed = os.path.join(temporary, "installed")
        _extract_verified_archive(options["out"], asset_name=bundle["asset"]["name"],
                                  expected_sha256=built["sha256"], destination=installed)
        verified = validate_installed_bundle(
            project, "v-lean", installed, manifest_path=manifest_path)
        with tarfile.open(options["out"], "r:gz") as archive:
            names = archive.getnames()
        check("a project with no legacy evidence builds from seed, gold, "
              "coverage and its declared pool alone, installs, validates, "
              "and ships no mutation role",
              built["release_ready"] is None
              and verified["release_ready"] is None
              and verified["release_items"] == 1
              and not any("artifacts/mutation" in name or "/evidence/" in name
                          or name.endswith("mutation_validation.json")
                          or name.endswith("slice1_mutation_assets.json")
                          for name in names)
              and open(_artifact_path(installed, block, "release_items"), "rb").read()
              == open(pool_path, "rb").read()
              and open(_artifact_path(installed, block, "coverage_run"), "rb").read()
              == open(source_path("coverage_run"), "rb").read()
              and open(_artifact_path(installed, block, "profile"), "rb").read()
              == open(os.path.join(BENCHMARK, "config",
                                   "profile_python_docx.yml"), "rb").read(),
              str(names))
        with open(_artifact_path(installed, block, "release_items"), "a",
                  encoding="utf-8") as fh:
            fh.write("\n")
        check("an installed bundle whose pool is not the declared one is refused",
              refused(lambda: validate_installed_bundle(
                  project, "v-lean", installed, manifest_path=manifest_path),
                      "release pool"))
        with open(_artifact_path(installed, block, "release_items"), "rb+") as fh:
            fh.seek(0, os.SEEK_END); fh.truncate(fh.tell() - 1)
        with open(_artifact_path(installed, block, "coverage_run"), "a",
                  encoding="utf-8") as fh:
            fh.write("\n")
        check("...and one whose coverage oracle is not the declared one",
              refused(lambda: validate_installed_bundle(
                  project, "v-lean", installed, manifest_path=manifest_path),
                      "coverage oracle"))
        roles["raw_manifest"] = f"projects/{project}/artifacts/mutation/raw_manifest.json"
        check("a partial legacy declaration refuses",
              refused(lambda: _legacy_evidence_declaration(project, block),
                      "some roles and not others"))

    with tempfile.TemporaryDirectory() as temporary:
        project = "python-docx"
        artifact_root = f"projects/{project}/artifacts"
        roles = {
            "scoring_gold": f"{artifact_root}/runs/gold_direct.jsonl",
            "gold_baseline": f"{artifact_root}/runs/gold_baseline.jsonl",
            "release_items": f"{artifact_root}/release/items.jsonl",
            "production_index": f"{artifact_root}/py_prod_index.json",
            "boundary": f"bundles/v1/{project}/boundary.yml",
        }

        def role_path(role):
            return os.path.join(temporary, roles[role])

        def write_rows(role, rows):
            path = role_path(role)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row) + "\n")

        old = [{"item_id": item, "outcome": "passed", "coverage_lines": {
            "src/prod.py": [11], "features/recorder.py": [10]}}
            for item in ("one", "two")]
        new = [dict(row, harness_version=12,
                    direct_calls_schema="r2t.python_direct_calls/2",
                    coverage_lines={"src/prod.py": [11],
                                         "features/recorder.py": [20]},
                    direct_calls=[]) for row in old]
        new[0]["direct_calls"] = [{
            "callee_file": "src/prod.py", "callee_line": 10,
            "callee": "Product.read", "caller_file": "features/steps/steps.py",
            "accessor_binding": None}]
        write_rows("gold_baseline", old)
        write_rows("scoring_gold", new)
        write_rows("release_items", [{"item_id": row["item_id"]} for row in old])
        _write_json(role_path("boundary"), {
            "version": 1, "project": project, "repo_root": ".",
            "removable": [{"path": "features/steps/"}],
            "retained": [{"path": "features/recorder.py"}]})
        _write_json(role_path("production_index"), {"schema": "r2t.py_prod_index/2", "files": {
            "src/prod.py": {"classes": [{"name": "Product", "accessors": [], "methods": [{
                "name": "read", "start": 11, "end": 15,
                "decl": 10, "public": True}]}]}}})
        block = {"bundle": {"artifacts": roles, "production_index": {
            "sha256": _sha256_file(role_path("production_index"))},
            "scoring_gold": {"sha256": _sha256_file(role_path("scoring_gold"))}}}
        old_bytes = open(role_path("gold_baseline"), "rb").read()
        facts = _validate_scoring_gold(temporary, project, block)
        check("a separate complete scoring reference preserves historical "
              "rows and coverage while permitting disclosed empty direct sets",
              facts["rows"] == 2 and facts["n_with_methods"] == 1
              and open(role_path("gold_baseline"), "rb").read() == old_bytes)
        authority_path = os.path.join(temporary, "dataset.json")

        def resolve_reference():
            _write_json(authority_path, {"schema": "r2t.dataset_manifest/3",
                                        "projects": {project: block}})
            return installed_scoring_gold(
                os.path.join(temporary, artifact_root), project,
                manifest_path=authority_path)

        check("ordinary installed reference lookup returns the declared "
              "validated role", resolve_reference() == role_path("scoring_gold"))
        index_bytes = open(role_path("production_index"), "rb").read()
        _write_json(role_path("production_index"), {"files": {
            "src/prod.py": {"classes": [{"name": "Product", "methods": [{
                "name": "read", "start": 11, "end": 15,
                "decl": 10, "public": False}]}]}}})
        check("installed lookup refuses a different index even when its "
              "events still map and gold would self-check",
              refused(resolve_reference, "production index SHA-256"))
        with open(role_path("production_index"), "wb") as fh:
            fh.write(index_bytes)
        block["bundle"]["scoring_gold"]["sha256"] = "0" * 64
        check("a declared invalid reference refuses instead of falling back",
              refused(resolve_reference, "scoring gold SHA-256"))
        for name, changed, expected in (
                ("duplicate item", new + [new[0]], "duplicate item_id"),
                ("missing item", new[:1], "exactly the released items"),
                ("missing collection", [dict(new[0], direct_calls=None), new[1]],
                 "no collected direct_calls"),
                ("changed outcome", [dict(new[0], outcome="failed"), new[1]],
                 "changes the baseline outcome"),
                ("changed production coverage", [dict(new[0], coverage_lines={
                    "src/prod.py": [12]}), new[1]], "changes production coverage")):
            write_rows("scoring_gold", changed)
            block["bundle"]["scoring_gold"]["sha256"] = _sha256_file(
                role_path("scoring_gold"))
            check(f"a pinned scoring reference with {name} refuses",
                  refused(resolve_reference, expected))
        write_rows("scoring_gold", [dict(new[0], direct_calls=[dict(
            new[0]["direct_calls"][0], callee_line=90)]), new[1]])
        block["bundle"]["scoring_gold"]["sha256"] = _sha256_file(
            role_path("scoring_gold"))
        check("unmapped direct events remain a reported diagnostic, as "
              "the API specification requires",
              _validate_scoring_gold(temporary, project, block)[
                  "unmapped_direct_events"] == 1)
        block["bundle"].pop("scoring_gold")
        roles.pop("scoring_gold")
        check("an undeclared file cannot become the installed default",
              resolve_reference() is None)

    with tempfile.TemporaryDirectory() as temporary:
        # The real native module link resolves in a workspace but is dangling
        # in the selected resource snapshot. copytree must not follow it, and
        # the outer bundle must retain the recorded executable and dir modes.
        from pathlib import Path
        import stat
        from ..bench import prestashop_resources as resources, seed as S
        from ..bench.repo import StripManifest, load_manifest
        from ..data.bundle import LEGACY_EVIDENCE_ROLES, _install_archive
        project = "prestashop"
        dataset = _read_json(DATASET_MANIFEST, "dataset manifest")
        block = json.loads(json.dumps(dataset["projects"]["python-docx"])
                           .replace("python-docx", project).replace("python_docx", project))
        dataset["projects"][project] = block
        bundle = block["bundle"]
        bundle.update(version="v-resource-test", production_index=None,
                      asset={"name": "resources.tar.gz", "sha256": None},
                      annotated_release=None)
        bundle.pop("scoring_gold", None)
        roles = bundle["artifacts"]
        roles.pop("scoring_gold", None)
        roles["production_index"] = roles["audit_attestation"] = None
        roles["annotated_release_items"] = None
        for role in LEGACY_EVIDENCE_ROLES:
            roles[role] = None
        source = Path(temporary, "source")
        worker = Path(temporary, "worker")
        gold = Path(_artifact_path(str(source), block, "gold"))
        gold.mkdir(parents=True)
        module = worker / "modules/ps_apiresources"
        module.mkdir(parents=True)
        (module / "module.php").write_text("<?php // native module\n")
        executable = "tests/Resources/modules/ps_banner/logo.png"
        path = worker / executable
        path.parent.mkdir(parents=True)
        path.write_bytes(b"executable resource")
        path.chmod(0o755)
        empty = worker / "tests/Resources/download/empty"
        empty.mkdir(parents=True)
        empty.chmod(0o750)
        link = "tests/Resources/modules/ps_apiresources"
        (worker / link).symlink_to("../../../modules/ps_apiresources")
        manifest = StripManifest(repo_root=str(worker), gold_root=str(gold))
        resources.capture(manifest)
        manifest.digests = {rel: entry["sha256"] for rel, entry in
                            manifest.prestashop_resources["entries"].items()
                            if entry["kind"] == "file"}
        manifest.save(str(gold / "strip_manifest.json"))
        (gold / "ordinary.php").write_text("<?php // ordinary gold\n")
        (gold / "ordinary.php").chmod(0o755)
        release_gold = Path(_artifact_path(str(source), block, "release_gold"))
        _write_json(str(release_gold / "manifest.json"), {"one": "one.json"})
        _write_json(str(release_gold / "one.json"),
                    {"item_id": "one", "files": ["ordinary.php"]})
        block["gold_manifest_sha256"] = _sha256_file(str(release_gold / "manifest.json"))
        block["gold_sidecars_sha256"] = _gold_digest(str(source), block)
        release_root = Path(temporary, "release")
        pool = release_root / block["items"]
        pool.parent.mkdir(parents=True)
        pool.write_text(json.dumps({"item_id": "one", "scenario": "read"}) + "\n")
        pool_sha = _sha256_file(str(pool))
        dataset["release_inventory"] = {"files": {block["items"]: pool_sha}}
        bundle["release_pool"] = {"file": block["items"], "sha256": pool_sha}
        coverage = _artifact_path(str(source), block, "coverage_run")
        Path(coverage).parent.mkdir(parents=True, exist_ok=True)
        Path(coverage).write_text(json.dumps({"item_id": "one", "outcome": "passed"}) + "\n")
        bundle["coverage_run"] = {"sha256": _sha256_file(coverage)}
        seed = Path(_artifact_path(str(source), block, "seed"))
        seed.mkdir(parents=True)
        entries = manifest.prestashop_resources["entries"]
        workspace = S._tar_workspace(str(worker), S.workspace_files(str(worker)),
            str(seed / S.WORKSPACE_TAR), keep_empty=(),
            resource_directories={rel: entry["mode"] for rel, entry in entries.items()
                                  if entry["kind"] == "directory"})
        _write_json(str(seed / S.SEED_MANIFEST), {
            "format": S.SEED_FORMAT, "seed_key": "resource-fixture", "workspace": workspace,
            "needs_database": False, "database": {"declared": S.NO_DATABASE}})
        bundle["seed"]["manifest_sha256"] = _sha256_file(str(seed / S.SEED_MANIFEST))
        authority_path = str(Path(temporary, "dataset.json"))
        _write_json(authority_path, dataset)
        archive_path = str(Path(temporary, "resources.tar.gz"))
        built = build_bundle(project=project, version="v-resource-test", seed_dir=str(seed),
            gold_dir=str(gold), release_gold=str(release_gold), coverage_run=coverage,
            out=archive_path, manifest_path=authority_path, release_root=str(release_root))
        bundle["asset"]["sha256"] = built["sha256"]
        installed = Path(temporary, "installed")
        install_stage = Path(temporary, "install-stage")
        install_stage.mkdir()
        _install_archive(archive_path, str(install_stage), project=project,
            version="v-resource-test", root=str(installed), authority=dataset, block=block)
        relocated_gold = Path(_artifact_path(str(installed), block, "gold"))
        native = relocated_gold / resources.NAME
        check("bundle build/install preserves native dangling module link and executable bytes",
              (native / link).is_symlink() and not (native / link).exists()
              and os.readlink(native / link) == "../../../modules/ps_apiresources"
              and (native / executable).read_bytes() == b"executable resource"
              and stat.S_IMODE((native / executable).stat().st_mode) == 0o755
              and stat.S_IMODE((native / "tests/Resources/download/empty").stat().st_mode) == 0o750)
        check("ordinary gold file permissions keep the existing bundle normalization",
              stat.S_IMODE((relocated_gold / "ordinary.php").stat().st_mode) == 0o644)
        runtime = Path(temporary, "relocated-worker")
        S.unpack_workspace(_artifact_path(str(installed), block, "seed"), str(runtime))
        relocated = load_manifest(str(relocated_gold / "strip_manifest.json"))
        relocated.gold_root, relocated.repo_root = str(relocated_gold), str(runtime)
        resources.verify_inputs(relocated)
        resources.restore(relocated)
        resources.verify_entry(relocated)
        check("relocated protected inputs restore and verify the exact native entry state",
              resources.inventory(str(runtime)) == entries
              and (relocated_gold / "strip_manifest.json").read_bytes()
              == (gold / "strip_manifest.json").read_bytes())
        (native / executable).chmod(0o644)
        check("installed bundle rejects resource mode drift even with unchanged file bytes",
              refused(lambda: validate_installed_bundle(project, "v-resource-test",
                      str(installed), authority=dataset, block=block), "native resource"))
        (native / executable).chmod(0o755)
        # Supporting this one recorded link does not open arbitrary external
        # tar links: even a self-consistent snapshot cannot escape its root.
        (native / link).unlink()
        (native / link).symlink_to("/outside-snapshot")
        relocated.prestashop_resources["entries"][link]["target"] = "/outside-snapshot"
        relocated.save(str(relocated_gold / "strip_manifest.json"))
        check("resource transport refuses an external link even when metadata agrees",
              refused(lambda: validate_installed_bundle(project, "v-resource-test",
                      str(installed), authority=dataset, block=block), "link escapes"))

    with tempfile.TemporaryDirectory() as temporary:
        stage = os.path.join(temporary, "stage")
        os.makedirs(os.path.join(stage, "projects", "p", "artifacts"))
        os.makedirs(os.path.join(stage, "bundles", "v1", "p"))
        shared = os.path.join(stage, "projects", "p", "artifacts", "gold.jsonl")
        with open(shared, "w", encoding="utf-8") as fh:
            fh.write('{"item_id":"i"}\n')
        with open(os.path.join(stage, "bundles", "v1", "p", "plan.json"),
                  "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        first = os.path.join(temporary, "first.tar.gz")
        second = os.path.join(temporary, "second.tar.gz")
        one = _write_archive(stage, first)
        two = _write_archive(stage, second)
        check("building the same staged bundle twice is byte-identical",
              one == two and open(first, "rb").read() == open(second, "rb").read())
        with tarfile.open(first, "r:gz") as archive:
            names = archive.getnames()
        check("one physical coverage/gold-baseline artifact is archived once",
              names.count("projects/p/artifacts/gold.jsonl") == 1
              and len(names) == len(set(names)), str(names))
        extracted = os.path.join(temporary, "verified-extraction")
        _extract_verified_archive(
            first, asset_name="first.tar.gz", expected_sha256=one,
            destination=extracted)
        check("a matching outer digest extracts the declared fixed layout",
              os.path.isfile(os.path.join(
                  extracted, "projects", "p", "artifacts", "gold.jsonl"))
              and os.path.isfile(os.path.join(
                  extracted, "bundles", "v1", "p", "plan.json")))

        payload = b"downloaded bundle"
        digest = hashlib.sha256(payload).hexdigest()

        class Response:
            def __init__(self, body):
                self.body = body
                self.offset = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, size=-1):
                if size is None or size < 0:
                    size = len(self.body) - self.offset
                chunk = self.body[self.offset:self.offset + size]
                self.offset += len(chunk)
                return chunk

        requests = []

        def opener(request):
            requests.append(request)
            if len(requests) == 1:
                return Response(json.dumps({"assets": [{
                    "name": "asset.tar.gz",
                    "url": "https://api.github.test/assets/1"}]}).encode())
            return Response(payload)

        downloaded = os.path.join(temporary, "downloaded.tar.gz")
        _download_asset(repository="owner/private", version="v1.0.0",
                        asset_name="asset.tar.gz", token="secret",
                        destination=downloaded, opener=opener)
        check("private fetch authenticates metadata and exact asset download",
              _sha256_file(downloaded) == digest
              and all(request.get_header("Authorization") == "Bearer secret"
                      for request in requests)
              and requests[1].get_header("Accept")
              == "application/octet-stream")

        corrupt_destination = os.path.join(temporary, "must-not-extract")
        mismatch = None
        try:
            _extract_verified_archive(
                downloaded, asset_name="asset.tar.gz",
                expected_sha256="0" * 64,
                destination=corrupt_destination)
        except BundleRefused as exc:
            mismatch = str(exc)
        check("a corrupt download names expected/actual digests and extracts "
              "nothing",
              mismatch is not None and "asset.tar.gz" in mismatch
              and digest in mismatch and "0" * 64 in mismatch
              and not os.path.exists(corrupt_destination), str(mismatch))

    with tempfile.TemporaryDirectory() as staged:
        release_gold = os.path.join(staged, "release", "gold")
        gold_root = os.path.join(staged, "removed")
        sidecar_name = "answer.json"
        _write_json(os.path.join(release_gold, "manifest.json"),
                    {"item": sidecar_name})
        _write_json(os.path.join(release_gold, sidecar_name),
                    {"item_id": "item", "files": ["src/A.php"]})
        _write_json(os.path.join(gold_root, "strip_manifest.json"), {})
        source = os.path.join(gold_root, "src", "A.php")
        os.makedirs(os.path.dirname(source), exist_ok=True)
        with open(source, "w", encoding="utf-8") as fh:
            fh.write("<?php\n")
        staged_block = {
            "dir": ".",
            "bundle": {"artifacts": {
                "release_gold": "release/gold", "gold": "removed"}},
            "gold_manifest_sha256": _sha256_file(
                os.path.join(release_gold, "manifest.json")),
        }
        staged_block["gold_sidecars_sha256"] = _gold_digest(
            staged, staged_block)
        accepted = True
        try:
            _validate_release_gold(staged, staged_block, {"item"})
        except BundleRefused:
            accepted = False
        check("a staged installed release-gold fixture validates against its "
              "retained identities and removed source tree", accepted)
        os.unlink(source)
        check("the staged release-gold validation refuses a missing source "
              "named by a sidecar",
              refused(lambda: _validate_release_gold(
                  staged, staged_block, {"item"}),
                      "lacks files named by release sidecars"))

    with tempfile.TemporaryDirectory() as installed:
        source = os.path.join(installed, "projects", "coreshop", "source")
        gold = os.path.join(installed, "projects", "coreshop", "gold")
        artifacts = os.path.join(
            installed, "projects", "coreshop", "artifacts")
        boundary = os.path.join(
            installed, "bundles", "v1", "coreshop",
            "boundary_coreshop.yml")
        for directory in (os.path.join(source, "_bench"), gold, artifacts):
            os.makedirs(directory, exist_ok=True)
        # Both config roles, into the one directory the dataset manifest
        # declares for them (`bundles/v1/coreshop/`).  The profile is not
        # decoration here: an installed bundle is read with no `--profile`,
        # and which stack runs is resolved as `profile_<project>.yml` beside
        # the boundary.  A fixture staging the boundary alone was describing
        # a layout this project does not ship.
        _copy_file(os.path.join(BENCHMARK, "config", "boundary_coreshop.yml"),
                   boundary)
        _copy_file(os.path.join(BENCHMARK, "config", "profile_coreshop.yml"),
                   os.path.join(os.path.dirname(boundary),
                                "profile_coreshop.yml"))

        from ..bench.repo import StripManifest
        StripManifest(repo_root=source, gold_root=gold).save(
            os.path.join(gold, "strip_manifest.json"))
        collision = (
            "CoreShop\\Component\\Shipping\\Validator\\"
            "ShippableCarrierValidatorInterface")
        aliases = {collision: (
            "CoreShop\\Component\\Shipping\\Validator\\"
            "ShippingRuleCarrierValidator")}
        _write_json(os.path.join(artifacts, "alias_table.json"), aliases)
        with open(os.path.join(artifacts, "autowirable_types.json"), "w",
                  encoding="utf-8") as fh:
            json.dump([collision], fh)

        from ..bench.cli import _harness
        harness, _bundle_boundary, _manifest = _harness(SimpleNamespace(
            profile=None, boundary=boundary, repo=source, gold=gold,
            artifacts=artifacts, container="none", workdir="/var/www/html"))
        registration = harness.write_registration({"files": {"X.php": {
            "classes": [{
                "kind": "class", "abstract": False,
                "name": "CoreShop\\Behat\\Context\\Domain\\XContext",
                "is_context": True,
                "constructor": [{"types": [collision],
                                 "has_default": False,
                                 "variadic": False}],
            }],
        }}}, {})
        check("an installed CoreShop bundle feeds both wiring indexes to the "
              "harness without redirecting an already-autowirable type",
              harness.alias_table == aliases
              and harness.autowirable_types == {collision}
              and collision not in registration["aliases"],
              str({"alias_table": harness.alias_table,
                   "autowirable_types": sorted(harness.autowirable_types),
                   "emitted_aliases": registration["aliases"]}))

    with tempfile.TemporaryDirectory() as temporary:
        provisional_manifest = os.path.join(temporary, "manifest.json")
        provisional = _read_json(DATASET_MANIFEST, "dataset manifest")
        provisional["projects"]["coreshop"]["bundle"]["asset"][
            "sha256"] = None
        _write_json(provisional_manifest, provisional)
        check("an unrecorded asset refuses before network access",
              refused(lambda: fetch_bundle(
                  project="coreshop", version=declared_versions["coreshop"],
                  manifest_path=provisional_manifest, token="unused",
                  opener=lambda _request: (_ for _ in ()).throw(
                      AssertionError("network reached"))),
                      "asset digest has not been recorded"))
    with tempfile.TemporaryDirectory() as temporary:
        fake_manifest = os.path.join(temporary, "manifest.json")
        _write_json(fake_manifest, {
            "schema": "r2t.dataset_manifest/3",
            "projects": {"p": {"bundle": {
                "version": "v1.0.0",
                "asset": {"name": "p.tar.gz", "sha256": "a" * 64},
            }}},
        })

        attempts = []

        def denied(request):
            attempts.append(request)
            raise urllib.error.HTTPError(
                request.full_url, 404, "Not Found", {}, None)

        def refusal(token: Optional[str], root: str) -> str:
            try:
                fetch_bundle(project="p", version="v1.0.0",
                             manifest_path=fake_manifest,
                             root=os.path.join(temporary, root), token=token,
                             opener=denied)
            except BundleRefused as exc:
                return str(exc)
            return ""

        saved_token = os.environ.pop(GITHUB_TOKEN_ENV, None)
        try:
            anonymous = refusal(None, "anonymous")
            authenticated = refusal("secret", "authenticated")
        finally:
            if saved_token is not None:
                os.environ[GITHUB_TOKEN_ENV] = saved_token
        check("a fetch without a token still asks GitHub anonymously",
              len(attempts) == 2 and attempts[0].get_header("Authorization")
              is None, str(attempts))
        check("an anonymous denial names both the missing token and the "
              "possibly private repository",
              GITHUB_TOKEN_ENV in anonymous and "may be private" in anonymous,
              anonymous)
        check("a token that GitHub denies keeps the private-repository "
              "refusal",
              len(attempts) == 2
              and attempts[1].get_header("Authorization") == "Bearer secret"
              and authenticated == (
                  "REFUSED: cannot read release v1.0.0 from the private "
                  f"GitHub repository; set {GITHUB_TOKEN_ENV} to a token "
                  "with repository access"), authenticated)

    # --------------------------------- the published eval100-std arm (D5)
    #
    # Fixture bytes throughout: the real arm is 35 MB of preserved evidence
    # under `/data2` plus an operator's ceremony directory, and a
    # network-free pull-request check may read neither.  What is exercised
    # here is the JOIN, which is what this module owns -- every role against
    # the digest the ceremony recorded for it, the wrapper against the bytes
    # it claims, and the disposition of every recorded input.
    def std_fixture(root: str, *, wrapper_edit=None, report_edit=None,
                    list_edit=None) -> tuple[dict, dict]:
        _dataset, coreshop = _authority("coreshop", declared_versions["coreshop"])
        block = {"bundle": {"artifacts": coreshop["bundle"]["artifacts"]}}
        digests: dict[str, str] = {}

        def put(path: str, payload: bytes) -> str:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(payload)
            return hashlib.sha256(payload).hexdigest()

        derived = {"std_legacy_consistency", "std_test_quality_wrapper",
                   "std_shipping_list"}
        for role in STD_ARM_ROLES:
            if role not in derived:
                digests[role] = put(_std_path(root, role),
                                    f"{role} fixture bytes\n".encode())
        for role in list(STD_ARM_SHARED_ROLES) + ["engine_source"]:
            path = _artifact_path(root, block, role)
            digests[role] = (_sha256_file(path) if os.path.isfile(path)
                             else put(path, f"{role} fixture bytes\n".encode()))
        report = {"schema": "r2t.mutation-validation/1", "status": "valid",
                  "inputs": {key: {"path": f"fixture/{key}",
                                   "sha256": digests[role]}
                             for key, role in STD_ARM_REPORT_INPUTS.items()}}
        if report_edit is not None:
            report_edit(report)
        digests["std_legacy_consistency"] = put(
            _std_path(root, "std_legacy_consistency"),
            json.dumps(report, sort_keys=True).encode())
        wrapper = {
            "allow_degraded_gold": True,
            "gold_infrastructure_outcomes": 2,
            "gold_infrastructure_pairs": [{"item_id": "i", "mutant_id": "m"},
                                          {"item_id": "j", "mutant_id": "n"}],
            "binding": {"run_sha256": digests["std_candidate_run"]},
            "path_base": {"kind": "wrapper_directory",
                          "relative_to_wrapper": "."},
            "legacy_rebinding": {
                "source_sidecar_sha256": digests["std_test_quality"],
                "validation_report": os.path.basename(
                    STD_ARM_ROLES["std_legacy_consistency"][0]),
                "validation_report_sha256":
                    digests["std_legacy_consistency"]},
        }
        if wrapper_edit is not None:
            wrapper_edit(wrapper)
        digests["std_test_quality_wrapper"] = put(
            _std_path(root, "std_test_quality_wrapper"),
            json.dumps(wrapper, sort_keys=True).encode())

        def entry(tail: str, role: str) -> dict:
            return {"path": "/fixture/" + tail, "sha256": digests[role],
                    "bytes": 1, "role": f"fixture {role}"}

        files = [entry(tail, role)
                 for role, (_d, kind, tail) in STD_ARM_ROLES.items()
                 if kind != "document"]
        files += [entry(tail, role)
                  for role, tail in STD_ARM_SHARED_ROLES.items()]
        files += [entry(tail, role)
                  for tail, role in STD_ARM_RECORDED_COPIES.items()]
        files += [{"path": "/fixture/" + tail, "sha256": "e" * 64,
                   "bytes": 1, "role": "fixture repository input"}
                  for tail in STD_ARM_REPOSITORY_INPUTS]
        document = {
            "tag": "fixture-tag", "commit": "f" * 40, "not_reached": [],
            "files": files,
            "git_resolved_inputs": [{
                "path": "benchmark/r2t/php/mutate.php (git blob)",
                "git_commit": "a" * 40, "git_blob": "b" * 40,
                "sha256": digests["engine_source"], "bytes": 1}],
        }
        if list_edit is not None:
            list_edit(document)
        list_digest = put(_std_path(root, "std_shipping_list"),
                          json.dumps(document, sort_keys=True).encode())
        # The declared identity is fixed, not read back from the (possibly
        # edited) list: a list that names another ceremony must disagree.
        block["bundle"]["std_arm"] = {
            "asset_version": "v1.0.0-rc.5",
            "ceremony": {
                "tag": "fixture-tag", "commit": "f" * 40,
                "report": "D4_J3_ceremony_report.md",
                "report_sha256": digests["std_ceremony_report"],
                "shipping_list": "consumed_inputs_manifest.json",
                "shipping_list_sha256": list_digest},
        }
        return block, block["bundle"]["std_arm"]

    def std_refused(root: str, text: str, **kwargs) -> bool:
        block, declaration = std_fixture(root, **kwargs)
        return refused(lambda: _validate_std_arm(root, block, declaration),
                       text)

    with tempfile.TemporaryDirectory() as temporary:
        def at(name: str) -> str:
            return os.path.join(temporary, name)

        installed = at("green")
        block, declaration = std_fixture(installed)
        facts = _validate_std_arm(installed, block, declaration)
        check("an installed bundle joins every eval100-std role to the digest "
              "the J3 ceremony recorded for it",
              facts["roles"] == len(STD_ARM_ROLES)
              + len(STD_ARM_SHARED_ROLES) + 1, str(facts))

        current_version = declared_versions["coreshop"]
        _dataset, real = _authority("coreshop", current_version)
        check("the declared CoreShop asset is the one that ships the arm, so "
              "its joins are live, and the superseded rc.4 asset stays "
              "untouched by an arm it does not contain",
              (_std_arm(current_version, real) or {})
              .get("ceremony", {}).get("shipping_list")
              == "consumed_inputs_manifest.json"
              and _std_arm("v1.0.0-rc.4", real) is None
              and _std_arm("v1.0.0-rc.5", real) is None)

        tampered = at("tampered-role")
        block, declaration = std_fixture(tampered)
        with open(_std_path(tampered, "std_gold_run"), "wb") as fh:
            fh.write(b"another arm's gold run\n")
        check("a shipped role whose bytes are not the ceremony's refuses by "
              "role name",
              refused(lambda: _validate_std_arm(tampered, block, declaration),
                      "bundled eval100-std std_gold_run hashes to"))

        missing = at("missing-role")
        block, declaration = std_fixture(missing)
        os.unlink(_std_path(missing, "std_campaign"))
        check("a role the asset does not carry refuses by role name",
              refused(lambda: _validate_std_arm(missing, block, declaration),
                      "bundle is missing eval100-std std_campaign"))

        shared = at("shared-role")
        block, declaration = std_fixture(shared)
        with open(_artifact_path(shared, block, "boundary"), "wb") as fh:
            fh.write(b"another project's boundary\n")
        check("an rc.4 role the ceremony also consumed must be the bytes it "
              "consumed: the published arm and the population it was scored "
              "over ship together",
              refused(lambda: _validate_std_arm(shared, block, declaration),
                      "bundled eval100-std boundary hashes to"))

        swapped = at("swapped-list")
        block, declaration = std_fixture(swapped)
        with open(_std_path(swapped, "std_shipping_list"), "wb") as fh:
            fh.write(b'{"files": []}\n')
        check("a shipping list that is not the pinned one refuses before any "
              "role is believed",
              refused(lambda: _validate_std_arm(swapped, block, declaration),
                      "the dataset manifest pins"))

        def extra(document: dict) -> None:
            document["files"].append({
                "path": "/fixture/artifacts/runs/a_later_input.jsonl",
                "sha256": "c" * 64, "bytes": 1, "role": "a new input"})

        check("a recorded input this bundle neither ships nor accounts for "
              "refuses, naming it",
              std_refused(at("extra"), "a_later_input.jsonl", list_edit=extra))

        def unreached(document: dict) -> None:
            document["not_reached"] = ["the mutation cells"]

        check("a ceremony whose render leg did not reach every input cannot "
              "ship an arm",
              std_refused(at("unreached"), "did not reach",
                          list_edit=unreached))

        def other_ceremony(document: dict) -> None:
            document["tag"] = "some-other-tag"

        check("a shipping list from another ceremony than the declared one "
              "refuses, naming both",
              std_refused(at("other"), "some-other-tag",
                          list_edit=other_ceremony))

        def broken_copy(document: dict) -> None:
            for item in document["files"]:
                if item["path"].endswith("/scratchpad/seed_accept.jsonl"):
                    item["sha256"] = "d" * 64

        check("a recorded copy that is not byte-identical to the role it "
              "copies refuses instead of being taken on trust",
              std_refused(at("copy"), "it is recorded as copying",
                          list_edit=broken_copy))

        def no_consent(wrapper: dict) -> None:
            wrapper["allow_degraded_gold"] = False

        check("a wrapper carrying no recorded consent cannot ship the "
              "published mutation cells (owner ruling 2.6 leg a)",
              std_refused(at("consent"), "ruling 2.6 leg (a)",
                          wrapper_edit=no_consent))

        def undisclosed(wrapper: dict) -> None:
            wrapper["gold_infrastructure_outcomes"] = 22

        check("a consented wrapper whose disclosed count and per-item list "
              "disagree refuses (ruling 2.6 legs b and c)",
              std_refused(at("disclosure"), "legs (b) and (c)",
                          wrapper_edit=undisclosed))

        def other_run(wrapper: dict) -> None:
            wrapper["binding"]["run_sha256"] = "1" * 64

        check("a wrapper bound to another run than the shipped one refuses",
              std_refused(at("run"), "not to the shipped run",
                          wrapper_edit=other_run))

        def other_sidecar(wrapper: dict) -> None:
            wrapper["legacy_rebinding"]["source_sidecar_sha256"] = "2" * 64

        check("a wrapper chained to another preserved sidecar refuses",
              std_refused(at("sidecar"), "not to the shipped sidecar",
                          wrapper_edit=other_sidecar))

        def elsewhere(wrapper: dict) -> None:
            wrapper["legacy_rebinding"]["validation_report"] = \
                "../../../elsewhere.json"

        check("a wrapper whose validation report does not resolve beside it "
              "inside the bundle refuses",
              std_refused(at("elsewhere"), "must resolve as",
                          wrapper_edit=elsewhere))

        def fewer(report: dict) -> None:
            report["inputs"].pop("engine_source")

        def more(report: dict) -> None:
            report["inputs"]["a_later_input"] = {"path": "x",
                                                 "sha256": "4" * 64}

        check("a legacy-consistency report validating a different input set "
              "than this bundle joins refuses -- in both directions, so a "
              "later ceremony's new input cannot pass unjoined",
              std_refused(at("inputs"),
                          f"not the {len(STD_ARM_REPORT_INPUTS)} roles",
                          report_edit=fewer)
              and std_refused(at("inputs-more"),
                              f"not the {len(STD_ARM_REPORT_INPUTS)} roles",
                              report_edit=more))

        def other_results(report: dict) -> None:
            report["inputs"]["gold_results"]["sha256"] = "3" * 64

        check("a report that validated other gold rows than the bundle ships "
              "refuses, naming both digests",
              std_refused(at("results"),
                          "but this bundle's std_gold_results is",
                          report_edit=other_results))

        # The producer's own contract, both ways round.  Neither refusal can
        # be reached by an operator who supplies the flag correctly, and both
        # are reachable by one who does not: D6 builds the declared asset,
        # and the superseded rc.4 asset remains buildable from the same
        # command line as before.  Retain the shipped arm declaration while
        # omitting optional roles so their earlier checks cannot mask either
        # standard-arm refusal.  The real declaration is checked above.
        document = _read_json(DATASET_MANIFEST, "dataset manifest")
        bundle_block = document["projects"]["coreshop"]["bundle"]
        for role, declaration in (("annotated_release_items", "annotated_release"),
                                  ("scoring_gold", "scoring_gold")):
            bundle_block.pop(declaration, None)
            bundle_block["artifacts"].pop(role, None)
        std_manifest = at("std-manifest.json")
        _write_json(std_manifest, document)
        asset = bundle_block["asset"]["name"]
        arguments = dict(
            project="coreshop", seed_dir=at("seed"), gold_dir=at("gold"),
            release_gold=at("release-gold"),
            raw_manifest=at("raw"), legacy_map=at("map"),
            coverage_run=at("coverage"), candidate_run=at("run"),
            candidate_results=at("candidate"), gold_results=at("gold-rows"))
        check("the declared asset version ships the published arm, so it "
              "refuses to build without the ceremony's shipping list",
              refused(lambda: build_bundle(
                  version=current_version, out=at(asset),
                  manifest_path=std_manifest, **arguments),
                      "must name the J3 ceremony's shipping list"))
        superseded = at("rc4.json")
        bundle_block["version"] = "v1.0.0-rc.4"
        bundle_block["asset"] = dict(
            bundle_block["asset"], name="r2t-v1.0.0-rc.4-coreshop.tar.gz")
        _write_json(superseded, document)
        check("...and an asset version that does not ship it refuses one",
              refused(lambda: build_bundle(
                  version="v1.0.0-rc.4",
                  out=at("r2t-v1.0.0-rc.4-coreshop.tar.gz"),
                  manifest_path=superseded,
                  std_arm=at("green/bundles/v1/coreshop/evidence/std/"
                             "consumed_inputs_manifest.json"), **arguments),
                      "declares no eval100-std arm"))

        # The build-side join the installed asset cannot make: the published
        # table is what this arm's numbers are pinned to, and it lives in the
        # builder's checkout rather than in the bundle.
        std_fixture(at("repo-input"))
        document = _read_json(_std_path(at("repo-input"), "std_shipping_list"),
                              "fixture shipping list")
        checkout = at("checkout")
        table = os.path.join(checkout, "benchmark", "release", "v1",
                             "legacy_table_eval100_std.md")
        os.makedirs(os.path.dirname(table))
        with open(table, "w", encoding="utf-8") as fh:
            fh.write("| metric | value |\n")
        check("a checkout whose published table is not the one the ceremony "
              "rendered against refuses the build",
              refused(lambda: _std_arm_repository_inputs(document, checkout),
                      "the published table and the shipped arm must be one "
                      "pair"))
        for item in document["files"]:
            if item["path"].endswith("/legacy_table_eval100_std.md"):
                item["sha256"] = _sha256_file(table)
        _std_arm_repository_inputs(document, checkout)
        check("...and the same checkout carrying that table builds", True)

    # The frozen v1 producer is a Git object, not the working-tree file: the
    # live enumerator moved on after the population was minted, so a bundle
    # that staged the live file would refuse its own frozen-index binding.
    with tempfile.TemporaryDirectory() as temporary:
        import subprocess
        from ..bench.mutation_run import binding_for
        from ..data import mutation_attestation as A
        index = _read_json(ASSET_INDEX, "mutation asset index")
        engine_dir, applier = binding_for(
            index["projects"]["coreshop"]["engine"])
        live = os.path.join(engine_dir, applier.source)
        staged = os.path.join(temporary, "evidence", "mutate.php")
        pinned = index["projects"]["coreshop"]["engine_source"]["sha256"]
        commit = A.legacy_engine_source_bindings()[os.path.relpath(
            live, REPOSITORY_ROOT).replace(os.sep, "/")]["commit"]
        # The producer is a blob in HISTORY, so the check needs the pinned
        # commit; a single-commit mirror of this repository does not have
        # it, and everything else here still runs there.
        if subprocess.run(["git", "-C", REPOSITORY_ROOT, "cat-file", "-e",
                           commit + "^{commit}"], stdin=subprocess.DEVNULL,
                          capture_output=True).returncode != 0:
            print(f"  [SKIP] the bundle stages the frozen v1 engine producer "
                  f"from the Git object store: pinned commit {commit[:12]} "
                  f"is not in this repository (a single-commit mirror)")
        else:
            _stage_engine_source("coreshop", live, staged)
            check("the bundle stages the frozen v1 engine producer from the "
                  "Git object store, not the live enumerator beside it",
                  _sha256_file(staged) == pinned
                  and _sha256_file(live) != pinned,
                  f"staged={_sha256_file(staged)} live={_sha256_file(live)} "
                  f"pinned={pinned}")

    print("\n" + ("ALL PASS (bundle_build)" if ok else "FAILURES (bundle_build)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
