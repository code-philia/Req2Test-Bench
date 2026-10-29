"""Closed evaluation-only bundle layouts, portable validation and installation.

The source writer lives in ``toolkit.bundle_build``. These readers preserve
the native authorities and source admission supplied by the project owner;
neither a release reservation nor a newly measured inventory admits inputs.
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
import urllib.request
from contextlib import contextmanager
from typing import Optional

from ..core.paths import data_root
from . import bundle as B
from . import mutation_attestation as A
from . import versions
from .profile import load_profile

TREE_SCHEMA = "r2t.evaluation-bundle-tree/1"
INPUT_SCHEMA = "r2t.evaluation-bundle-inputs/1"
INDEX_SCHEMA = "r2t.mutation-evaluation-release/1"
ADMISSION_SCHEMA = "r2t.evaluation-payload-admission/1"
INPUT_MAP_SCHEMA = "r2t.native-validation-inputs/1"
RELEASE_TAG = "v1.0.0-rc.10"
SCOPE_FIELDS = frozenset({
    "id", "population_id", "task_items_sha256", "map_release_sha256",
    "mutation_map_sha256", "reference_attestation_sha256",
})
PROJECT_SCOPES = {
    "coddy-agent": {
        "id": "coddy-agent-full282-single-observation-v1",
        "population_id": "coddy-agent-v1", "items": 282,
        "task_items_sha256": "7e3b829d48bb13a20e04ad9dcf3f553f4f0c51b0f6ae6744130b3e7aa0f3b606",
        "map_release_sha256": "7e3b829d48bb13a20e04ad9dcf3f553f4f0c51b0f6ae6744130b3e7aa0f3b606",
    },
    "python-docx": {
        "id": "python-docx-full239-single-observation-v1",
        "population_id": "python-docx-v1", "items": 239,
        "task_items_sha256":
            "9358e4144a0abe31762747edaa8874c7816ff4ec05a10162f1adb1d64895b67d",
        "map_release_sha256":
            "4626a2857364014fe6d0f397305c0ac28b41fc0115d058b232e3e440fa5f032d",
    },
    "coreshop": {
        "id": "coreshop-full422-single-observation-v1",
        "population_id": "coreshop-v1", "items": 422,
        "task_items_sha256":
            "19678c89808b13cb2c9cf0a8d3758670e9085e5286c6d51942357fb750797087",
        "map_release_sha256":
            "19678c89808b13cb2c9cf0a8d3758670e9085e5286c6d51942357fb750797087",
    },
    "algorand-sdk": {
        "id": "algorand-sdk-declared111-single-observation-v1",
        "population_id": "algorand-sdk-v2", "items": 111,
        "task_items_sha256":
            "01253f00c5d1d38333cef96d1fb1e469e225a00786bd948fa89918e01c189437",
        "map_release_sha256":
            "0f537d6eacb4fa75d384c300b34e6c1d8a359e1f2520165e1068a81be2fd7407",
    },
}
CORESHOP_SEED_PINS = {
    "seed.json": "f4c2816ffac50b85fe77dd1d7729cbc059260c0ac562e6cac674487b01cce531",
    "workspace.tar": "48ae54d44ea912ae67446253bbcf22edd6fe7533fbc623d90d9cb08b6256028a",
    "database.sql": "e069e9a4515b897ac47207cedae3700c4256b1d2219e2bf7efb602d94d28a41d",
}
CORESHOP_CAPTURES = {
    "var/capture/_orig_assert_589ca1e1faf12d0bce4131a4d31fd368.php": 60097,
    "var/capture/p2cart.jsonl": 782945,
    "var/capture/p2run1.jsonl": 6795,
    "var/capture/p2run2.jsonl": 6795,
    "var/capture/p2run3.jsonl": 6795,
    "var/capture/trial1.jsonl": 200463,
    "var/capture/tune1.jsonl": 6821,
    "var/capture/tune2.jsonl": 6821,
}
CORESHOP_DISCLOSURE_REVISION = "26308d141e0e9f4773d6f9b63c289114201bb272"


def _exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        B._refuse(f"{label} must contain exactly {sorted(keys)}")
    return value


def _sha(value, label):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        B._refuse(f"{label} is not a SHA-256")
    return value


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def document_digest(value):
    return hashlib.sha256(canonical_bytes(
        {key: item for key, item in value.items() if key != "digest"})).hexdigest()


def write_document(path, value):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "xb") as handle:
        handle.write(canonical_bytes(value) + b"\n")


def _read(path, label):
    if os.path.islink(path) or not os.path.isfile(path):
        B._refuse(f"{label} is not a regular file: {path}")
    return B._read_json(path, label)


def _relative(value, label):
    if not isinstance(value, str) or not value or "\\" in value \
            or value.startswith("/") or posixpath.normpath(value) != value \
            or value in {".", ".."} or value.startswith("../"):
        B._refuse(f"{label} is not an installed relative path")
    return value


def _at(root, relative):
    return os.path.join(root, *_relative(relative, "bundle path").split("/"))


def is_evaluation_bundle(project, version):
    return project in PROJECT_SCOPES and str(version) == (
        "8" if project == "algorand-sdk" else RELEASE_TAG)


def layout(project, version):
    if not is_evaluation_bundle(project, version):
        B._refuse(f"no evaluation bundle layout for {project!r} {version!r}")
    native = project == "algorand-sdk"
    root = ("bundles/v8/algorand-sdk" if native
            else f"bundles/evaluation/v1/{project}")
    project_root = f"projects/{project}"
    stem = {"python-docx": "python_docx", "coreshop": "coreshop",
            "algorand-sdk": "algorand", "coddy-agent": "coddy_agent"}[project]
    files = {
        "release_items": f"{project_root}/artifacts/release/items.jsonl",
        "map_release": f"{root}/mutation/map-release.jsonl",
        "profile": f"{root}/config/profile_{stem}.yml",
        "boundary": f"{root}/config/boundary_{stem}.yml",
        "worker_plan": f"{root}/runtime/worker-plan.json",
        "raw_manifest": f"{root}/mutation/raw-manifest.json",
        "scored_manifest": f"{root}/mutation/scored-manifest.json",
        "mutation_map": f"{project_root}/artifacts/mutation/mutant-map.json",
        "mutation_asset_index": f"{root}/mutation/assets.json",
        "engine_source": f"{root}/mutation/applier",
        "audit_attestation": f"{root}/mutation/materialisation-audit.json",
        "coverage_run": f"{root}/mutation/coverage.jsonl",
        "gold_baseline": f"{project_root}/artifacts/runs/gold-baseline.jsonl",
        "gold_results_attestation": f"{root}/reference-controls.json",
    }
    trees = {
        "release_gold": f"{project_root}/artifacts/release/gold",
        "gold": f"{project_root}/gold", "seed": f"{project_root}/seed/v1",
        "mutation_validation": f"{root}/mutation/validation",
        "reference_inputs": f"{root}/reference-inputs",
        "gold_results": f"{project_root}/artifacts/mutation/reference-controls",
        "provenance": f"{root}/provenance",
    }
    if project == "python-docx":
        files.update(production_index=f"{project_root}/artifacts/py_prod_index.json",
                     task_binding=f"{root}/task-binding.json")
    elif project == "coreshop":
        files.update(
            production_index=f"{project_root}/artifacts/php_prod_index.json",
            alias_table=f"{project_root}/artifacts/alias_table.json",
            autowirable_types=f"{project_root}/artifacts/autowirable_types.json")
    elif project == "coddy-agent":
        files.update(
            closures=f"{project_root}/artifacts/closures.json",
            oci_image=f"{root}/runtime/oci-image.json",
            production_index=f"{project_root}/artifacts/go_prod_index.json",
            go_interface_attribution=f"{project_root}/artifacts/go_interface_attribution.json",
            source_view_map=f"{root}/source-views/target-body-map.json")
        trees.update(
            go_control_plans=f"{root}/go-control-plans",
            go_control_sources=f"{root}/runtime/go-control-sources",
            go_toolchain=f"{root}/runtime/go-toolchain",
            source=f"{project_root}/source")
    else:
        files.update(
            execution_view=f"{root}/release/execution-view.json",
            closures=f"{root}/release/closures.json",
            protocol=f"{root}/config/protocol.yml",
            oci_image=f"{root}/runtime/oci-image.json",
            production_index=f"{project_root}/artifacts/java_prod_index.json",
            direct_call_agent=f"{root}/runtime/direct-calls-agent.jar")
    return {
        "project": project, "version": 8 if native else RELEASE_TAG,
        "schema": ("r2t.algorand-native-bundle/8" if native
                   else "r2t.mutation-evaluation-bundle/1"),
        "bundle_root": root, "project_root": project_root,
        "manifest": f"{root}/bundle.json", "files": files, "trees": trees,
        "asset": ("r2t-algorand-bundle-v8.tar.gz" if native
                  else f"r2t-{RELEASE_TAG}-{project}.tar.gz"),
    }


def _producer(value):
    _exact(value, {"tag", "commit"}, "bundle producer")
    if not isinstance(value["tag"], str) or not value["tag"].strip() \
            or re.fullmatch(r"[0-9a-f]{40}", str(value["commit"])) is None:
        B._refuse("bundle producer needs its reviewed tag and full commit")
    return value


def _scope(value, project):
    _exact(value, SCOPE_FIELDS, "evaluation scope")
    for key in SCOPE_FIELDS - {"id", "population_id"}:
        _sha(value[key], f"evaluation scope {key}")
    for key in ("id", "population_id", "task_items_sha256", "map_release_sha256"):
        if value[key] != PROJECT_SCOPES[project][key]:
            B._refuse(f"evaluation scope {key} differs from the approved project scope")
    return value


def _file_list(value, label):
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value) \
            or value != sorted(set(value), key=lambda x: x.encode("utf-8")):
        B._refuse(f"{label} must be a sorted unique path list")
    for path in value:
        _relative(path, label)
    return value


def tree_paths(root, role):
    if os.path.islink(root) or not os.path.isdir(root):
        B._refuse(f"{role} tree is absent or linked")
    paths = []
    for directory, dirs, names in os.walk(root):
        for name in dirs:
            if os.path.islink(os.path.join(directory, name)):
                B._refuse(f"{role} tree contains a linked directory")
        for name in names:
            path = os.path.join(directory, name)
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode):
                B._refuse(f"{role} tree contains a nonregular file")
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            paths.append(_relative(relative, role))
    return sorted(paths, key=lambda x: x.encode("utf-8"))


def tree_rows(root, role):
    return [{"path": relative, "bytes": os.path.getsize(_at(root, relative)),
             "sha256": B._sha256_file(_at(root, relative)),
             **({"executable": bool(os.stat(_at(root, relative)).st_mode & 0o111)}
                if role == "go_toolchain" else {})}
            for relative in tree_paths(root, role)]


def tree_document(root, role):
    value = {"schema": TREE_SCHEMA, "role": role, "files": tree_rows(root, role)}
    value["digest"] = document_digest(value)
    return value


def _inventory(root, selected, manifest):
    expected = {selected["manifest"]}
    paths = {}
    trees = {}
    _exact(manifest["roles"], set(selected["files"]) | set(selected["trees"]),
           "evaluation bundle roles")
    for role, relative in selected["files"].items():
        record = _exact(manifest["roles"][role], {"path", "sha256"}, role)
        if record["path"] != relative:
            B._refuse(f"{role} differs from its fixed evaluation layout path")
        path = _at(root, relative)
        A.validate_preserved_file(path, _sha(record["sha256"], role), role)
        paths[role] = path
        expected.add(relative)
    for role, relative in selected["trees"].items():
        record = _exact(manifest["roles"][role],
                        {"path", "manifest_path", "manifest_sha256"}, role)
        inventory = f"{selected['bundle_root']}/trees/{role}.json"
        if record["path"] != relative or record["manifest_path"] != inventory:
            B._refuse(f"{role} differs from its fixed evaluation tree paths")
        A.validate_preserved_file(_at(root, inventory), record["manifest_sha256"], role)
        document = _read(_at(root, inventory), f"{role} inventory")
        if document != tree_document(_at(root, relative), role):
            B._refuse(f"{role} inventory differs from its exact installed files")
        paths[role] = _at(root, relative)
        trees[role] = [row["path"] for row in document["files"]]
        expected.add(inventory)
        expected.update(f"{relative}/{row['path']}" for row in document["files"])
    actual, directories = set(), set()
    owned = (selected["bundle_root"], selected["project_root"])
    for prefix in owned:
        start = _at(root, prefix)
        if os.path.islink(start) or not os.path.isdir(start):
            B._refuse(f"evaluation owned root is absent or linked: {prefix}")
        for directory, dirs, names in os.walk(start):
            directories.add(os.path.relpath(directory, root).replace(os.sep, "/"))
            for name in dirs + names:
                if os.path.islink(os.path.join(directory, name)):
                    B._refuse("evaluation inventory contains a linked member")
            actual.update(os.path.relpath(os.path.join(directory, name), root)
                          .replace(os.sep, "/") for name in names)
    expected_dirs = set(selected["trees"].values())
    for path in expected | expected_dirs.copy():
        parent = posixpath.dirname(path)
        while any(parent == p or parent.startswith(p + "/") for p in owned):
            expected_dirs.add(parent)
            parent = posixpath.dirname(parent)
    if actual != expected or directories != expected_dirs:
        B._refuse("evaluation payload differs from its closed file/directory inventory")
    return paths, trees, expected


def provenance_members(project: str, reference_basis=None) -> frozenset[str]:
    """The provenance files actually consumed by this evaluation layout.

    A caller's admission list describes source locations; it cannot create
    another provenance role for candidate outputs or study material.
    """
    roles = (("full_gold",) if project == "coddy-agent"
             and reference_basis == "full_gold" else
             ("full_gold", "stripped_gold", "stub"))
    members = {
        "collection-scope.json", "payload-admission.json", "reference-closures.json",
        *(f"reference-recipes/{role}.json" for role in roles),
    }
    if project == "coreshop":
        members.add("coreshop-seed-disclosure.md")
    elif project == "algorand-sdk":
        from ..toolkit.algorand_bundle import EVALUATION_PROVENANCE
        members.update(EVALUATION_PROVENANCE.values())
    return frozenset(members)


def _admission(path, selected, *, reference_attestation=None):
    document = _read(path, "owner payload admission")
    _exact(document, {"schema", "trees", "seed_workspace_members"}, "payload admission")
    if document["schema"] != ADMISSION_SCHEMA:
        B._refuse("unknown evaluation payload admission schema")
    _exact(document["trees"], selected["trees"], "admitted trees")
    for role, files in document["trees"].items():
        _file_list(files, f"admitted {role}")
    supplied = set(document["trees"]["provenance"])
    basis = (_read(reference_attestation, "sealed reference controls").get("reference_basis")
             if reference_attestation is not None else None)
    expected = provenance_members(selected["project"], basis)
    if supplied != expected:
        B._refuse("provenance differs from the project source-role contract: "
                  f"missing={sorted(expected - supplied)}, unexpected={sorted(supplied - expected)}")
    _file_list(document["seed_workspace_members"], "admitted workspace members")
    return document


def resolve_validation_inputs(path: str, data_root: str) -> dict[str, str]:
    """Resolve a complete native input map without following producer paths."""
    location_map = _read(path, "native input locations")
    _exact(location_map, {"schema", "report", "inputs"}, "native input locations")
    if location_map["schema"] != INPUT_MAP_SCHEMA or location_map["report"] != "report.json":
        B._refuse("native validation requires its unchanged report.json and input map")
    report = _read(os.path.join(os.path.dirname(path), "report.json"), "native report")
    inputs = report.get("inputs")
    if not isinstance(inputs, dict):
        B._refuse("native report has no input pins")
    _exact(location_map["inputs"], inputs, "native report input locations")
    resolved = {}
    for label, relative in location_map["inputs"].items():
        _relative(relative, f"native input {label}")
        resolved[label] = _at(os.path.abspath(data_root), relative)
    return resolved


def native_validation_inputs(root, role_paths, inventory_files):
    resolved = resolve_validation_inputs(os.path.join(
        role_paths["mutation_validation"], "inputs.json"), root)
    for label, path in resolved.items():
        relative = os.path.relpath(path, root).replace(os.sep, "/")
        if relative not in inventory_files:
            B._refuse(f"native input {label} is outside the closed bundle inventory")
    validate_native_input_roles(resolved, role_paths)
    return resolved


def validate_native_input_roles(resolved: dict[str, str],
                                 role_paths: dict[str, str]) -> None:
    """Join report-bound bytes to emitted roles before or after installation.

    The catalog enumerator input may differ from the runtime applier role;
    their respective native/report and observation joins remain separate.
    """
    common = {
        "raw_manifest": "raw_manifest", "manifest": "scored_manifest",
        "map": "mutation_map", "coverage_run": "coverage_run",
        "release": "map_release", "asset_index": "mutation_asset_index",
        "boundary": "boundary", "audit_attestation": "audit_attestation",
    }
    for label, role in common.items():
        if label in resolved and B._sha256_file(resolved[label]) != B._sha256_file(role_paths[role]):
            B._refuse(f"native report {label} differs from the installed {role} role")


def _workspace_members(path):
    members = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            relative = _relative(member.name.rstrip("/"), "workspace archive member")
            if relative in members or not (member.isfile() or member.isdir()):
                B._refuse("workspace archive has duplicate or unsupported members")
            members[relative] = (member.size, member.isdir())
    return members


def _seed(project, paths, admission):
    from ..bench import seed as S
    facts = S.verify_seed(paths["seed"])
    if not facts["artifacts_ok"]:
        B._refuse("evaluation seed does not verify against its original manifest")
    expected_seed = {S.SEED_MANIFEST, S.WORKSPACE_TAR}
    if facts["needs_database"]:
        expected_seed.add(S.DATABASE_SQL)
    if set(admission["trees"]["seed"]) != expected_seed:
        B._refuse("evaluation seed contains files outside its complete seed format")
    members = _workspace_members(os.path.join(paths["seed"], S.WORKSPACE_TAR))
    if sorted(members, key=lambda p: p.encode("utf-8")) != admission["seed_workspace_members"]:
        B._refuse("nested seed workspace differs from its admitted member set")
    if project == "coreshop":
        for name, sha in CORESHOP_SEED_PINS.items():
            A.validate_preserved_file(os.path.join(paths["seed"], name), sha,
                                      "approved disclosed CoreShop seed")
        captures = {path: size for path, (size, is_dir) in members.items()
                    if path.startswith("var/capture/") and not is_dir}
        if captures != CORESHOP_CAPTURES:
            B._refuse("CoreShop seed captures differ from the exact eight-member disposition")
        disclosure = os.path.join(paths["provenance"], "coreshop-seed-disclosure.md")
        if os.path.islink(disclosure) or not os.path.isfile(disclosure):
            B._refuse("CoreShop seed requires its external disclosure")
        with open(disclosure, encoding="utf-8") as handle:
            text = handle.read()
        required = [CORESHOP_DISCLOSURE_REVISION, *CORESHOP_SEED_PINS.values(),
                    *(posixpath.basename(p) for p in CORESHOP_CAPTURES),
                    "evaluation-only", "legacy_consistency"]
        if any(value not in text for value in required):
            B._refuse("CoreShop seed disclosure omits its approved revision, identities or limits")
    return facts


@contextmanager
def _feature_root(project, seed):
    if project not in {"algorand-sdk", "coddy-agent"}:
        yield None
        return
    with tempfile.TemporaryDirectory(prefix="r2t-evaluation-features-") as temporary:
        with tarfile.open(os.path.join(seed, "workspace.tar"), "r:*") as archive:
            for member in archive:
                if member.isfile() and member.name.endswith(".feature"):
                    target = _at(temporary, member.name)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with archive.extractfile(member) as source, open(target, "xb") as out:
                        shutil.copyfileobj(source, out)
        yield temporary


def _reference(project, paths, scope, inputs):
    from ..bench.evaluation_reference import validate_evaluation_reference_inputs
    with _feature_root(project, paths["seed"]) as feature_root:
        return validate_evaluation_reference_inputs(
            project=project, role_paths=paths, scope=scope,
            validation_input_paths=inputs, feature_root=feature_root)


def _runtime_and_gold(project, paths, seed_facts, reference):
    profile = load_profile(paths["profile"])
    if profile.project != project:
        B._refuse("evaluation profile names another project")
    plan = _read(paths["worker_plan"], "evaluation worker plan")
    _exact(plan, {"schema", "project", "k", "workdir", "container_kind"}, "worker plan")
    if plan["schema"] != "r2t.worker-plan/1" or plan["project"] != project \
            or type(plan["k"]) is not int or plan["k"] < 1 \
            or not isinstance(plan["workdir"], str) or not plan["workdir"].startswith("/") \
            or plan["container_kind"] not in {"php", "py", "java", "go"}:
        B._refuse("evaluation worker plan is malformed")
    if project != "algorand-sdk":
        # The descriptor-driven project's published runtime contract owns
        # these two fields. Generic worker planning accepts other mount/name
        # choices, but that does not qualify them for this project bundle.
        runtime = _read(B.DATASET_MANIFEST, "project runtime contracts")["projects"][project]
        expected_plan = runtime["bundle"]["worker_plan"]
        if runtime["framework"] != profile.framework or any(
                plan[field] != expected_plan[field] for field in ("workdir", "container_kind")):
            B._refuse("evaluation worker plan differs from the project profile/runtime contract")
    if bool(profile.needs_database) != bool(seed_facts["needs_database"]):
        B._refuse("evaluation profile and seed disagree about their database")
    authority = reference["controls"]["authority"]
    recorded = authority["harness_version"]
    current = versions.component("harness")["version"]
    if not versions.reference_harness_compatible(project, recorded, current):
        B._refuse(f"evaluation reference harness {recorded} is incompatible "
                  f"with current harness {current} for {project}")
    for field, half in (("workspace_seed_digest", "workspace"),
                        ("database_dump_digest", "database")):
        if authority.get(field) != seed_facts[half]["actual"]:
            B._refuse(f"reference {field} differs from the installed seed")
    items = A.load_release_ids(paths["release_items"])
    if len(items) != PROJECT_SCOPES[project]["items"]:
        B._refuse("evaluation tasks differ from the approved item count")
    gold = _read(os.path.join(paths["release_gold"], "manifest.json"), "release gold manifest")
    if set(gold) != items:
        B._refuse("evaluation release gold does not cover exactly the execution tasks")
    expected = {"manifest.json"}
    for item, name in gold.items():
        _relative(name, f"gold sidecar {item}")
        expected.add(name)
        sidecar = _read(_at(paths["release_gold"], name), f"gold sidecar {item}")
        for path in sidecar.get("files", []):
            if not os.path.isfile(_at(paths["gold"], path)):
                B._refuse(f"release gold names missing reference source {path}")
    if {row["path"] for row in tree_rows(paths["release_gold"], "release_gold")} != expected:
        B._refuse("release gold tree contains undeclared sidecars")
    _read(os.path.join(paths["gold"], "strip_manifest.json"), "gold strip manifest")
    return plan


def _coddy_originals(paths, image_id):
    """Verify original authority against portable seed/gold, not producer paths."""
    from ..core.boundary import load_boundary
    from ..go import mutation_runtime as runtime
    from ..go.prod_index import GoIndexRefused
    from ..toolkit.strip import load_closures
    boundary = load_boundary(paths["boundary"])
    try:
        _, hashes, _ = runtime.original_source_metadata(
            list(load_closures(paths["closures"]).values()),
            _read(paths["production_index"], "Coddy production index"),
            _read(paths["go_interface_attribution"], "Coddy original attribution"),
            _read(paths["scored_manifest"], "Coddy scored manifest"),
            boundary, image_id=image_id)
        # The seed must install exactly the runtime applier this bundle ships.
        with open(paths["engine_source"], "rb") as handle:
            applier = runtime.applier_sha256(handle.read())
    except (runtime.MutationRuntimeRefused, GoIndexRefused) as exc:
        B._refuse(str(exc))
    strip = _read(os.path.join(paths["gold"], "strip_manifest.json"), "Coddy strip manifest")
    seed_hashes = {path: digest for path, digest in hashes.items()
                   if boundary.classify(path) != "removable"}
    seed_hashes[runtime.ENGINE_PATH] = applier
    with tarfile.open(os.path.join(paths["seed"], "workspace.tar"), "r:*") as archive:
        for member in archive:
            path = member.name.rstrip("/")
            if path not in seed_hashes or not member.isfile():
                continue
            with archive.extractfile(member) as stream:
                # Chunked, not hashlib.file_digest: that is Python 3.11+ and
                # the benchmark's floor is CPython 3.10.
                sha = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    sha.update(chunk)
                digest = sha.hexdigest()
            if digest != seed_hashes.pop(path):
                B._refuse("Coddy original source/engine differs from preserved seed: " + path)
    if seed_hashes:
        B._refuse("Coddy original source/engine absent from preserved seed: " + sorted(seed_hashes)[0])
    for path, digest in hashes.items():
        if boundary.classify(path) == "removable":
            if path not in strip.get("moved", []):
                B._refuse("Coddy original answer absent from strip manifest: " + path)
            A.validate_preserved_file(os.path.join(paths["gold"], path), digest,
                                      "Coddy original answer")


def _coddy_sources(paths, seed_facts, reference):
    """Bind portable source views and planner dependencies without execution."""
    from ..core.source_view import qualify_source_seed
    from ..go import assertion_strip, controls
    if B._sha256_file(paths["closures"]) != B._sha256_file(os.path.join(
            paths["provenance"], "reference-closures.json")):
        B._refuse("Coddy execution and reference closures differ")
    from ..go.control_adapter import plan_member
    from ..toolkit.strip import load_closures
    closures = load_closures(paths["closures"])
    expected_plans = {plan_member(role, closure).as_posix() for role in ("stripped_gold", "stub")
                      for closure in closures.values()}
    if set(tree_paths(paths["go_control_plans"], "go_control_plans")) != expected_plans:
        B._refuse("Coddy saved-plan tree differs from the complete control member set")
    profile = load_profile(paths["profile"])
    source = qualify_source_seed(
        root=paths["source"], project="coddy-agent",
        runtime_seed_digest=seed_facts["workspace"]["actual"],
        readable_paths=profile.readable_paths)
    view = _read(paths["source_view_map"], "Coddy full282 source-view map")
    items = A.load_release_ids(paths["release_items"])
    if view.get("project") != "coddy-agent" \
            or view.get("runtime_seed_digest") != source.runtime_seed_digest \
            or view.get("source_files_digest") != source.files_digest \
            or {item.get("item_id") for item in view.get("items", [])} != items \
            or len(view.get("items", [])) != len(items):
        B._refuse("Coddy source-view map differs from the full release/source/seed")
    expected_sources = {
        "assertion_strip.go": os.path.join(os.path.dirname(assertion_strip.__file__),
                                           "support", "assertion_strip.go"),
        "controls.go": os.path.join(os.path.dirname(controls.__file__),
                                    "support", "controls.go"),
    }
    if set(tree_paths(paths["go_control_sources"], "go_control_sources")) != set(expected_sources):
        B._refuse("Coddy control source tree differs from the two native planners")
    for name, source_path in expected_sources.items():
        A.validate_preserved_file(os.path.join(paths["go_control_sources"], name),
                                  B._sha256_file(source_path), "Coddy native planner")
    compiler = os.path.join(paths["go_toolchain"], "bin", "go")
    version = os.path.join(paths["go_toolchain"], "VERSION")
    if not os.path.isfile(compiler) or not os.access(compiler, os.X_OK) \
            or not os.path.isfile(version):
        B._refuse("Coddy bundle omits its preserved Go compiler")
    with open(version, encoding="utf-8") as handle:
        if handle.readline().strip() != "go1.25.0":
            B._refuse("Coddy compiler differs from Go 1.25.0")
    image = _read(paths["oci_image"], "Coddy original image identity")
    if image.get("config_image_id") != reference["controls"]["authority"]["container_image_digest"]:
        B._refuse("Coddy original compiler image differs from the reference runtime")
    _coddy_originals(paths, image["config_image_id"])


def _manifest(path, selected):
    value = _read(path, "evaluation bundle manifest")
    _exact(value, {"schema", "version", "project", "producer", "scope", "roles", "digest"},
           "evaluation bundle manifest")
    if value["schema"] != selected["schema"] or value["project"] != selected["project"] \
            or type(value["version"]) is not type(selected["version"]) \
            or value["version"] != selected["version"]:
        B._refuse("bundle manifest does not name the selected evaluation layout")
    _producer(value["producer"])
    _scope(value["scope"], selected["project"])
    if _sha(value["digest"], "bundle manifest digest") != document_digest(value):
        B._refuse("evaluation bundle manifest digest does not rederive")
    return value


def _release_index(project, version, path=None):
    selected = layout(project, version)
    if path is None:
        path = os.path.join(B.BENCHMARK, "release", "evaluation", project + ".json")
    value = _read(path, "evaluation release index")
    _exact(value, {"schema", "project", "version", "release_tag", "asset", "producer",
                   "bundle_manifest_sha256", "scope"}, "evaluation release index")
    _exact(value["asset"], {"name", "sha256"}, "evaluation release asset")
    if value["schema"] != INDEX_SCHEMA or value["project"] != project \
            or value["version"] != selected["version"] \
            or type(value["version"]) is not type(selected["version"]) \
            or value["release_tag"] != RELEASE_TAG \
            or value["asset"]["name"] != selected["asset"]:
        B._refuse("evaluation release index differs from the selected layout")
    _sha(value["asset"]["sha256"], "evaluation archive pin")
    _sha(value["bundle_manifest_sha256"], "evaluation manifest pin")
    _producer(value["producer"])
    _scope(value["scope"], project)
    return value


def _validate_evaluation_payload(*, project: str, version, root: str,
                                 index: Optional[dict] = None) -> dict:
    selected = layout(project, version)
    root = os.path.abspath(root)
    manifest_path = _at(root, selected["manifest"])
    manifest = _manifest(manifest_path, selected)
    if index is not None:
        if B._sha256_file(manifest_path) != index["bundle_manifest_sha256"] \
                or manifest["producer"] != index["producer"] \
                or manifest["scope"] != index["scope"]:
            B._refuse("evaluation manifest/source/scope differ from the release index")
    paths, trees, inventory = _inventory(root, selected, manifest)
    admission = _admission(
        os.path.join(paths["provenance"], "payload-admission.json"), selected,
        reference_attestation=paths["gold_results_attestation"])
    if admission["trees"] != trees:
        B._refuse("evaluation trees differ from their owner's admitted inputs")
    for field, role in (("task_items_sha256", "release_items"),
                        ("map_release_sha256", "map_release"),
                        ("mutation_map_sha256", "mutation_map"),
                        ("reference_attestation_sha256", "gold_results_attestation")):
        if B._sha256_file(paths[role]) != manifest["scope"][field]:
            B._refuse(f"evaluation scope {field} differs from its installed input")
    seed = _seed(project, paths, admission)
    inputs = native_validation_inputs(root, paths, inventory)
    reference = _reference(project, paths, manifest["scope"], inputs)
    plan = _runtime_and_gold(project, paths, seed, reference)
    if project == "coddy-agent":
        _coddy_sources(paths, seed, reference)
    report = {"project": project, "version": selected["version"],
              "manifest": manifest, "manifest_path": manifest_path,
              "role_paths": paths, "validation_input_paths": inputs,
              "reference": {
                  "digest": reference["controls"]["digest"],
                  "pairs": reference["controls"]["pairs"],
                  "declared_subset": reference["controls"].get("declared_subset"),
                  "reference_observation_count":
                      reference["controls"]["reference_observation_count"],
              }, "release_ready": True, "worker_plan": plan}
    if project == "algorand-sdk":
        from ..toolkit.algorand_bundle import validate_evaluation_roles
        native = validate_evaluation_roles(role_paths=paths,
                                           producer=manifest["producer"])
        # How the installed boundary stands to the reviewed one is a fact the
        # consumer reads, not one the validator keeps to itself.
        report["boundary_approval"] = native["boundary_approval"]
    return report


def validate_evaluation_bundle(*, project: str, version, root: str,
                               release_index_path: Optional[str] = None) -> dict:
    """Validate an installation against its default or private measured index."""
    index = _release_index(project, version, release_index_path)
    return _validate_evaluation_payload(project=project, version=version,
                                        root=root, index=index)


def _extract_archive(archive, destination, selected):
    allowed_roots = (selected["project_root"], selected["bundle_root"])
    parents = set()
    for root in allowed_roots:
        current = root
        while current:
            parents.add(current)
            current = posixpath.dirname(current)
    seen = set()
    os.makedirs(destination)
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        for member in members:
            name = _relative(member.name.rstrip("/"), "evaluation archive member")
            owned = any(name == root or name.startswith(root + "/") for root in allowed_roots)
            if name in seen or not (member.isfile() or member.isdir()) \
                    or not (owned or member.isdir() and name in parents):
                B._refuse("evaluation archive contains a duplicate or unowned member")
            seen.add(name)
        source.extractall(destination, members=members)


def measure_evaluation_release(*, archive: str, manifest: str, out: str) -> dict:
    document = _read(manifest, "measured bundle manifest")
    selected = layout(document.get("project"), document.get("version"))
    _manifest(manifest, selected)
    if os.path.basename(archive) != selected["asset"]:
        B._refuse("measured evaluation archive has the wrong asset name")
    with tempfile.TemporaryDirectory(prefix="r2t-evaluation-measure-") as temporary:
        extracted = os.path.join(temporary, "extracted")
        _extract_archive(archive, extracted, selected)
        packaged = _at(extracted, selected["manifest"])
        if B._sha256_file(packaged) != B._sha256_file(manifest):
            B._refuse("measured manifest is not the one inside the archive")
        _validate_evaluation_payload(project=selected["project"], version=selected["version"],
                                     root=extracted)
    index = {"schema": INDEX_SCHEMA, "project": selected["project"],
             "version": selected["version"], "release_tag": RELEASE_TAG,
             "asset": {"name": selected["asset"], "sha256": B._sha256_file(archive)},
             "producer": document["producer"], "scope": document["scope"],
             "bundle_manifest_sha256": B._sha256_file(manifest)}
    write_document(out, index)
    return index


def _install_archive(archive, temporary, root, selected, index, index_path):
    A.validate_preserved_file(archive, index["asset"]["sha256"], "evaluation archive")
    extracted = os.path.join(temporary, "extracted")
    _extract_archive(archive, extracted, selected)
    facts = validate_evaluation_bundle(project=selected["project"],
                                      version=selected["version"], root=extracted,
                                      release_index_path=index_path)
    B._install_roots(extracted, root, project_root=selected["project_root"],
                     bundle_root=selected["bundle_root"])
    return {"project": selected["project"], "version": selected["version"],
            "release_ready": facts["release_ready"], "asset": selected["asset"],
            "sha256": index["asset"]["sha256"], "data_root": root}


def _installation(project, version, root, release_index_path):
    selected = layout(project, version)
    index = _release_index(project, version, release_index_path)
    root = os.path.abspath(root or data_root())
    if any(os.path.lexists(_at(root, selected[key])) for key in ("project_root", "bundle_root")):
        B._refuse(f"evaluation destination already exists for {project!r}")
    os.makedirs(root, exist_ok=True)
    return selected, index, root


def install_evaluation_bundle(*, project: str, version, archive: str,
                              root: Optional[str] = None,
                              release_index_path: Optional[str] = None) -> dict:
    selected, index, root = _installation(project, version, root, release_index_path)
    with tempfile.TemporaryDirectory(prefix=".r2t-evaluation-", dir=root) as temporary:
        snapshot = os.path.join(temporary, selected["asset"])
        try:
            shutil.copyfile(archive, snapshot)
        except OSError as exc:
            B._refuse(f"cannot read local evaluation archive {archive}: {exc}")
        # Validate against the same complete authority snapshot used to pin
        # the archive; the caller's private file need not remain at this path.
        index_path = os.path.join(temporary, "release.json")
        write_document(index_path, index)
        return _install_archive(snapshot, temporary, root, selected, index, index_path)


def fetch_evaluation_bundle(*, project: str, version, root: Optional[str] = None,
                            release_index_path: Optional[str] = None,
                            token: Optional[str] = None, repository: Optional[str] = None,
                            opener=urllib.request.urlopen) -> dict:
    selected, index, root = _installation(project, version, root, release_index_path)
    with tempfile.TemporaryDirectory(prefix=".r2t-evaluation-", dir=root) as temporary:
        archive = os.path.join(temporary, selected["asset"])
        B._download_asset(repository=repository or os.environ.get(
            B.GITHUB_REPOSITORY_ENV, B.DEFAULT_GITHUB_REPOSITORY),
            version=index["release_tag"], asset_name=selected["asset"],
            token=token or os.environ.get(B.GITHUB_TOKEN_ENV), destination=archive,
            opener=opener)
        index_path = os.path.join(temporary, "release.json")
        write_document(index_path, index)
        return _install_archive(archive, temporary, root, selected, index, index_path)
