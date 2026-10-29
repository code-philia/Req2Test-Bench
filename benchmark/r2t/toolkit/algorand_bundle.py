"""Build, validate, fetch, and install a native Algorand bundle version."""
from __future__ import annotations

from dataclasses import dataclass
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
from pathlib import Path
from typing import Callable, Mapping, Optional


PROJECT = "algorand-sdk"
TREE_SCHEMA = "r2t.algorand-bundle-tree/1"
RELEASE_SCHEMA = "r2t.algorand-bundle-release/1"
RELEASE_SCHEMA_V2 = "r2t.algorand-bundle-release/2"
SOURCE_SCHEMA = "r2t.algorand-source-approval/1"
MUTATION_SCHEMA = "r2t.algorand-bundle-mutation-validation/1"
OCI_SCHEMA = "r2t.algorand-oci-image-reference/1"
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)
PROJECT_ROOT = "projects/algorand-sdk"

SDK_REPOSITORY = "algorand/java-algorand-sdk"
SDK_COMMIT = "4e38dadc4eec827ed8742c8bb272e0545c801932"
SDK_TREE = "120c79cf5d99274faca46abdd09355e11bc3675f57c5023a3aef339ff8871559"
TESTING_REPOSITORY = "algorand/algorand-sdk-testing"
TESTING_COMMIT = "7c67284b52675257e66c017cc3606bcd4803f4c6"
TESTING_TREE = "e9fdc199385ddee3ae6a04ab3d839f10e378d45ebf71f0acd673ea2567609a54"

# The v1 runtime image identity of record (ALGORAND_BUNDLE_V1_SPEC.md sections
# 4 and 12, B1).  Distribution is registry pull-by-digest of the manifest
# stored on the canonical evidence host, so the pushed manifest digest is the
# value the canonical, reality, and validation records all carry under the
# label "image ID"; that manifest's config descriptor digest is a second,
# distinct identity and never an alias of it.
IMAGE_PATH = "java-research-minimal-oci/v1"
PUBLICATION_SCHEMA = "r2t.algorand-oci-registry-publication/1"
IMAGE_MANIFEST_DIGEST = \
    "sha256:3823e49a15013b52e63e03a3378110910825240f1fdadb9fab053e1082eb3eb3"
IMAGE_CONFIG_ID = \
    "sha256:ed3153915e378a1edca7bc9c232d561711265b099b6b1fae44b2e1c7b13c30bf"

# The profile role ships the producer checkout's bytes.  The N=3 release
# validation approved the same file at commit fee673e3, before merge ca1738c
# added the mandatory `api_scoring: none` line, so the approval names a
# different digest and the bundle discloses that pair (section 12, B4).
APPROVED_PROFILE_SHA256 = \
    "5216a55dee94e20571c8e8b069c01e5a357cab523912eb43a471c527a0e2e310"
APPROVED_PROFILE_DIFF = b"api_scoring: none\n"

# The boundary role also ships the producer checkout's bytes, and checked-
# interfaces v2 moved the reviewed file after the published v8 bundle was
# minted: `config/boundary_algorand.yml` gained the two retained entries for
# the harness-owned step-tag listener (TARGET_INTERFACES_V2_SPEC section 4).
# So an installed bundle's boundary is either today's reviewed bytes or those
# bytes without this block, and nothing else; `_boundary_disclosure` states
# which and refuses any other difference.
DISCLOSED_BOUNDARY_DIFF = b"""\
  - path: src/test/java/com/algorand/algosdk/unit/R2TStepTagListener.java
    why: harness-owned step-tag listener the unit runner's plugin list names
  - path: src/test/java/com/algorand/algosdk/integration/R2TStepTagListener.java
    why: harness-owned step-tag listener the offline runner's plugin list names
"""

GOLD_BASELINE_ROLE = "gold_baseline"
GOLD_BASELINE_PATH = \
    f"{PROJECT_ROOT}/artifacts/runs/gold_baseline.jsonl"
GOLD_BASELINE_KEYS = frozenset({
    "role", "byte_length", "row_count", "collection_harness_commit",
    "source_bundle_version", "source_bundle_manifest_sha256",
    "repro_check_count",
})
GOLD_BASELINE_COLLECTION_COMMIT = \
    "69e74aff99aaa3976d9ec294da0280110d1acff1"
GOLD_BASELINE_SOURCE_MANIFEST_SHA256 = \
    "2783cfe51fb64d63a3ddfa2cf2298f55721d7d75e6aaab1ed15531b40fd7cea2"
GOLD_BASELINE_SHA256 = \
    "368ff973620328d52f500efbb1521cc8b040d7eaa29f269c499b44655e0e1683"
GOLD_BASELINE_BYTE_LENGTH = 3530953
GOLD_BASELINE_V5_SHA256 = \
    "6652c9eb5c9157f1b845d47c64669653889b4ccae8a5758d6eccbff20a4a4ce0"
GOLD_BASELINE_V5_BYTE_LENGTH = 3530937

SCORED_MANIFEST_ROLE = "scored_manifest"
GOLD_RESULTS_ROLE = "gold_results"
GOLD_RESULTS_ATTESTATION_ROLE = "gold_results_attestation"
CANDIDATE_RUN_ROLE = "candidate_run"
CANDIDATE_RESULTS_ROLE = "candidate_results"
V4_ADDED_ROLES = frozenset({
    SCORED_MANIFEST_ROLE, GOLD_RESULTS_ROLE,
    GOLD_RESULTS_ATTESTATION_ROLE, CANDIDATE_RUN_ROLE,
    CANDIDATE_RESULTS_ROLE,
})
V5_ADDED_ROLES = frozenset({
    SCORED_MANIFEST_ROLE, GOLD_RESULTS_ROLE,
    GOLD_RESULTS_ATTESTATION_ROLE,
})
_QUALITY_SHARD_REQUIRED_MEMBERS = frozenset({
    "schema", "status", "campaign_identity",
    "mutation_campaign_digest", "out", "rows", "rows_sha256",
    "expected_pairs", "expected_pairs_sha256", "observation_id",
    "slice3_execution_binding_digest", "slice3_mutation_job_digest",
})
V4_CONTROL_OBSERVATIONS = {
    "full_gold_a": "4dc72a19103fbfa923d146aa7c255693",
    "full_gold_b": "cadde8d728181977ef99c50da6c0914f",
    "stripped_gold_a": "5644490e02cb2321b248291ea4f776ba",
    "stripped_gold_b": "b0a1c7b90a00896fdb5da30cddd2f797",
    "stub_a": "31f0f1b6106e9cee2939088e29a8af8a",
    "stub_b": "e1d535787f0e89e5ab5feb6638ae1ec1",
}
V4_EXECUTION_BINDING_DIGEST = \
    "0b62adf3c07671d2ef58942612c6d3fbe99700f35ba53cc8ceb15e95add517f6"
V4_PAIR_SET_DIGEST = \
    "6ae0ffc6aa6baf5ffa7daaaf1055f5ce06438c83640e352fa561a9ca51b788e4"
V4_ELIGIBILITY_SHA256 = \
    "e7a7511858d8fe0609b8b72b7343cb2eeb7fd20c72f06dfac8af832f98dfdc93"
V4_CANDIDATE_RUN_SHA256 = \
    "f18f3dbbb05e2d0b7693ccb654c8f702cbf085a9435b3a0aadced245323412a6"
V4_CANDIDATE_GENERATED_TESTS_SHA256 = \
    "c2d74412f333978e3cc8e333de3d70bdc2a81d33a4ca1067c0c71bed415141f7"
V4_CANDIDATE_OBSERVATION_ID = "4030645a8e091ebbdda5b4324f54b754"
V4_GENERATION_ATTEMPT_ID = \
    "algorand-aider-cell1-s1-a1-20260813T100326Z-19e92045"

V4_CAPABILITIES = {
    "mutation": True, "coverage": True, "api_similarity": False,
}
V4_CAPABILITY_NOTES = {
    "mutation": ("r2t-mutate-java 1.0 over the validated Algorand mutation "
                 "substrate, with the frozen Java20 binding and preserved "
                 "controls"),
    "coverage": "the preserved 111-row Algorand gold baseline",
    "api_similarity": ("not measured: the Algorand profile declares "
                       "api_scoring none and no production index exists"),
}

DERIVED_FILE_ROLES = frozenset({
    "source_approval", "mutation_validation", "oci_image",
})
EVIDENCE_KEYS = {
    "sdk_root", "testing_root", "composition_root", "release_root",
    "validation_approval", "validation_approved_digest",
    "preparation_manifest", "release_approved_digest",
    "mutation_validation_report",
    "oci_publication_receipt",
}

# V8's common inventory/reader belongs to data.evaluation_bundle. These are
# the native owner's preserved provenance files inside its provenance role.
EVALUATION_PROVENANCE = {
    "source_approval": "source-approval.json",
    "composition": "composition-manifest.json",
    "release_approval": "release-approval.json",
    "release_receipt": "release-receipt.json",
    "release_manifest": "release-manifest.json",
}


def _file_roles(bundle_root: str, *, gold_baseline: bool = False,
                quality_evidence: bool = False,
                reference_quality: bool = False) \
        -> dict[str, str]:
    roles = {
        "source_approval": f"{bundle_root}/source/source-approval.json",
        "release_approval": f"{bundle_root}/approval/release-approval.json",
        "release_receipt": f"{bundle_root}/approval/release-receipt.json",
        "released_items": f"{bundle_root}/release/released-items.jsonl",
        "execution_view": f"{bundle_root}/release/execution-view.json",
        "execution_release": f"{PROJECT_ROOT}/artifacts/release/items.jsonl",
        "closures": f"{bundle_root}/release/closures.json",
        "mutation_manifest":
            f"{PROJECT_ROOT}/artifacts/mutation/manifest.json",
        "mutation_map":
            f"{PROJECT_ROOT}/artifacts/mutation/mutant-map.json",
        "mutation_validation": f"{bundle_root}/mutation/validation.json",
        "worker_plan": f"{bundle_root}/worker-plan.json",
        "boundary": f"{bundle_root}/config/boundary_algorand.yml",
        "profile": f"{bundle_root}/config/profile_algorand.yml",
        "protocol": f"{bundle_root}/protocol/protocol_v8.yml",
        "oci_image": f"{bundle_root}/runtime/oci-image.json",
    }
    if gold_baseline:
        roles[GOLD_BASELINE_ROLE] = GOLD_BASELINE_PATH
    if quality_evidence or reference_quality:
        roles.update({
            SCORED_MANIFEST_ROLE:
                f"{bundle_root}/quality/scored-manifest.json",
            GOLD_RESULTS_ATTESTATION_ROLE:
                f"{PROJECT_ROOT}/artifacts/test-quality/"
                "six-gate-eligibility.json",
        })
    if quality_evidence:
        roles.update({
            CANDIDATE_RUN_ROLE:
                f"{PROJECT_ROOT}/artifacts/runs/aider.merged.jsonl",
        })
    return roles


def _tree_roles(bundle_root: str, *, quality_evidence: bool = False,
                reference_quality: bool = False) \
        -> dict[str, tuple[str, str]]:
    roles = {
        "gold": (f"{PROJECT_ROOT}/gold",
                 f"{bundle_root}/trees/gold.json"),
        "release_gold": (f"{PROJECT_ROOT}/artifacts/release/gold",
                         f"{bundle_root}/trees/release-gold.json"),
        "stripped_seed": (f"{PROJECT_ROOT}/seed/v1",
                          f"{bundle_root}/trees/seed.json"),
    }
    if quality_evidence or reference_quality:
        roles.update({
            GOLD_RESULTS_ROLE: (
                f"{PROJECT_ROOT}/artifacts/test-quality/gold-results",
                f"{bundle_root}/trees/gold-results.json"),
        })
    if quality_evidence:
        roles.update({
            CANDIDATE_RESULTS_ROLE: (
                f"{PROJECT_ROOT}/artifacts/test-quality/candidate-results",
                f"{bundle_root}/trees/candidate-results.json"),
        })
    return roles


@dataclass(frozen=True)
class BundleLayout:
    version: str
    manifest_version: int
    bundle_schema: str
    input_schema: str
    asset_name: str
    release_index: str
    bundle_root: str
    bundle_manifest: str
    file_roles: dict[str, str]
    tree_roles: dict[str, tuple[str, str]]
    roles: frozenset[str]
    input_roles: frozenset[str]
    image_repository: str


def _make_layout(version: str, repository: str, *, gold_baseline=False,
                 quality_evidence=False, reference_quality=False) \
        -> BundleLayout:
    bundle_root = f"bundles/v{version}/algorand-sdk"
    files = _file_roles(
        bundle_root, gold_baseline=gold_baseline,
        quality_evidence=quality_evidence,
        reference_quality=reference_quality)
    trees = _tree_roles(
        bundle_root, quality_evidence=quality_evidence,
        reference_quality=reference_quality)
    roles = frozenset(files) | frozenset(trees)
    return BundleLayout(
        version=version, manifest_version=int(version),
        bundle_schema=f"r2t.algorand-native-bundle/{version}",
        input_schema=f"r2t.algorand-bundle-inputs/{version}",
        asset_name=f"r2t-algorand-bundle-v{version}.tar.gz",
        release_index=os.path.join(
            BENCHMARK, "release", f"algorand_bundle_v{version}.json"),
        bundle_root=bundle_root,
        bundle_manifest=f"{bundle_root}/bundle.json",
        file_roles=files, tree_roles=trees, roles=roles,
        input_roles=roles - DERIVED_FILE_ROLES,
        image_repository=repository)


_LAYOUTS = {
    "1": _make_layout(
        "1", "ghcr.io/code-philia/r2t-java-algorand-sdk"),
    "2": _make_layout(
        "2", "ghcr.io/qibinhang/r2t-java-algorand-sdk"),
    "3": _make_layout(
        "3", "ghcr.io/qibinhang/r2t-java-algorand-sdk",
        gold_baseline=True),
    "4": _make_layout(
        "4", "ghcr.io/qibinhang/r2t-java-algorand-sdk",
        gold_baseline=True, quality_evidence=True),
    "5": _make_layout(
        "5", "ghcr.io/qibinhang/r2t-java-algorand-sdk",
        gold_baseline=True, reference_quality=True),
}


def layout(version: str) -> BundleLayout:
    try:
        return _LAYOUTS[version]
    except (KeyError, TypeError):
        raise _refuse(
            "Algorand bundle version must be '1', '2', '3', '4', or '5'") \
            from None


# Published v1 module constants remain its exact public/default surface.
_V1 = _LAYOUTS["1"]
VERSION = _V1.version
BUNDLE_SCHEMA = _V1.bundle_schema
INPUT_SCHEMA = _V1.input_schema
ASSET_NAME = _V1.asset_name
RELEASE_INDEX = _V1.release_index
BUNDLE_ROOT = _V1.bundle_root
BUNDLE_MANIFEST = _V1.bundle_manifest
FILE_ROLES = _V1.file_roles
TREE_ROLES = _V1.tree_roles
ROLES = _V1.roles
INPUT_ROLES = _V1.input_roles
IMAGE_REPOSITORY = _V1.image_repository

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class AlgorandBundleRefused(ValueError):
    pass


def _refuse(message: str) -> AlgorandBundleRefused:
    return AlgorandBundleRefused("REFUSED: " + message)


def _exact(value: object, keys: set[str] | frozenset[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise _refuse(f"{label} is not its closed schema")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _refuse(f"{label} is not lower-case SHA-256")
    return value


def _image(value: object, label: str) -> str:
    if not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None:
        raise _refuse(f"{label} is not one immutable sha256 ID")
    return value


def _canonical(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise _refuse(f"document is not canonical JSON: {exc}") from exc


def _document_digest(value: Mapping[str, object]) -> str:
    unsigned = dict(value)
    unsigned.pop("digest", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _validate_digest(value: dict, label: str) -> dict:
    claimed = _sha(value.get("digest"), f"{label} digest")
    if claimed != _document_digest(value):
        raise _refuse(f"{label} digest does not rederive")
    return value


def _read_bytes(path: str, label: str) -> bytes:
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise _refuse(f"{label} is linked or special")
        return Path(path).read_bytes()
    except OSError as exc:
        raise _refuse(f"cannot read {label}: {path}") from exc


def _read_json(path: str, label: str) -> tuple[dict, bytes]:
    raw = _read_bytes(path, label)
    try:
        from ..docker_authority import loads_exact_json
        value = loads_exact_json(raw, label=label)
    except (UnicodeDecodeError, RuntimeError, ValueError) as exc:
        raise _refuse(f"{label} is not exact JSON") from exc
    if not isinstance(value, dict):
        raise _refuse(f"{label} is not a JSON object")
    return value, raw


def _write_json(path: str, value: Mapping[str, object], *, canonical=True,
                final_lf=True) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if canonical:
        raw = _canonical(value)
    else:
        raw = json.dumps(value, sort_keys=True, indent=1,
                         ensure_ascii=False).encode()
        if final_lf:
            raw += b"\n"
    with open(path, "xb") as handle:
        handle.write(raw)


def _hash(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise _refuse(f"cannot hash bundle file: {path}") from exc
    return digest.hexdigest()


def _relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") \
            or posixpath.normpath(value) != value or value.startswith("../") \
            or "//" in value or "\x00" in value:
        raise _refuse(f"{label} is not a normalized relative path")
    return value


def _absolute(value: object, label: str) -> str:
    if not isinstance(value, str) or not os.path.isabs(value) \
            or os.path.normpath(value) != value:
        raise _refuse(f"{label} is not a normalized absolute path")
    return value


def _at(root: str, relative: str) -> str:
    return os.path.join(root, *relative.split("/"))


def _tree_rows(root: str, role: str) -> list[dict]:
    rows = []
    if os.path.islink(root) or not os.path.isdir(root):
        raise _refuse(f"{role} tree is absent or linked")
    for directory, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        for name in tuple(dirnames):
            if os.path.islink(os.path.join(directory, name)):
                raise _refuse(f"{role} tree contains a linked directory")
        for name in filenames:
            path = os.path.join(directory, name)
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise _refuse(f"{role} tree contains a linked or special file")
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            rows.append({"path": _relative(rel, f"{role} tree path"),
                         "bytes": info.st_size, "sha256": _hash(path)})
    return sorted(rows, key=lambda row: row["path"].encode("utf-8"))


def _tree_document(root: str, role: str) -> dict:
    value = {"schema": TREE_SCHEMA, "role": role,
             "files": _tree_rows(root, role), "digest": "0" * 64}
    value["digest"] = _document_digest(value)
    return value


def _validate_tree(root: str, manifest_path: str, role: str) -> dict:
    value, raw = _read_json(manifest_path, f"{role} tree manifest")
    _exact(value, {"schema", "role", "files", "digest"},
           f"{role} tree manifest")
    _validate_digest(value, f"{role} tree manifest")
    if value["schema"] != TREE_SCHEMA or value["role"] != role \
            or value["files"] != _tree_rows(root, role) \
            or raw != _canonical(value):
        raise _refuse(f"{role} tree manifest differs from installed bytes")
    return value


def _load_inputs(path: str, *, version: str = VERSION) -> dict:
    selected = layout(version)
    value, _raw = _read_json(_absolute(path, "bundle inputs"), "bundle inputs")
    keys = {"schema", "producer", "roles", "evidence"}
    if GOLD_BASELINE_ROLE in selected.file_roles:
        keys.add(GOLD_BASELINE_ROLE)
    _exact(value, keys, "bundle inputs")
    if value["schema"] != selected.input_schema:
        raise _refuse("bundle inputs use another schema")
    producer = _exact(value["producer"], {"repository_tag", "repository_commit"},
                      "bundle input producer")
    if not isinstance(producer["repository_tag"], str) \
            or not producer["repository_tag"] \
            or not isinstance(producer["repository_commit"], str) \
            or _COMMIT.fullmatch(producer["repository_commit"]) is None:
        raise _refuse("bundle input producer is malformed")
    if selected.version in {"4", "5"} \
            and isinstance(value.get("roles"), dict):
        present = set(value["roles"])
        if present != set(selected.input_roles):
            raise _refuse(
                f"v{selected.version} bundle input roles differ; missing="
                f"{sorted(set(selected.input_roles) - present)}, unknown="
                f"{sorted(present - set(selected.input_roles))}")
    roles = _exact(value["roles"], selected.input_roles, "bundle input roles")
    for role, source in roles.items():
        path_value = _absolute(source, f"{role} input")
        exists = os.path.isdir(path_value) if role in selected.tree_roles \
            else os.path.isfile(path_value)
        if not exists or os.path.islink(path_value):
            raise _refuse(f"{role} input is absent or linked")
    if selected.version in {"4", "5"}:
        ordered = sorted(roles.items())
        for index, (left_role, left_path) in enumerate(ordered):
            for right_role, right_path in ordered[index + 1:]:
                left_resolved = os.path.realpath(left_path)
                right_resolved = os.path.realpath(right_path)
                try:
                    common = os.path.commonpath(
                        (left_resolved, right_resolved))
                except ValueError:
                    continue
                if common in {left_resolved, right_resolved} \
                        or os.path.samefile(left_path, right_path):
                    raise _refuse(
                        f"v{selected.version} bundle inputs overlap roles "
                        f"{left_role!r} and "
                        f"{right_role!r}")
    if GOLD_BASELINE_ROLE in selected.file_roles:
        _validate_gold_baseline_provenance(
            value[GOLD_BASELINE_ROLE], roles[GOLD_BASELINE_ROLE],
            version=selected.version)
    evidence = _exact(value["evidence"], EVIDENCE_KEYS,
                      "bundle input evidence")
    for name in ("sdk_root", "testing_root", "composition_root",
                 "release_root"):
        source = _absolute(evidence[name], f"{name} evidence")
        if not os.path.isdir(source) or os.path.islink(source):
            raise _refuse(f"{name} evidence is absent or linked")
    for name in ("validation_approval", "preparation_manifest",
                 "mutation_validation_report", "oci_publication_receipt"):
        source = _absolute(evidence[name], f"{name} evidence")
        if not os.path.isfile(source) or os.path.islink(source):
            raise _refuse(f"{name} evidence is absent or linked")
    _sha(evidence["validation_approved_digest"],
         "validation approval evidence digest")
    _sha(evidence["release_approved_digest"],
         "release approval evidence digest")
    return value


def _validate_producer(producer: Mapping[str, str]) -> None:
    """Require the declared producer to be this clean detached exact tag."""
    from ..core import reviewed_git
    repository = reviewed_git.repository_root()

    def git(args: tuple[str, ...], label: str, allowed=(0,)):
        try:
            result = reviewed_git.run(repository, args)
        except reviewed_git.ReviewedGitRefused as exc:
            raise _refuse(f"producer {label}: {exc.detail}") from exc
        if result.returncode not in allowed:
            detail = os.fsdecode(result.stderr or result.stdout).strip()
            raise _refuse(f"producer {label}: {detail or 'Git read failed'}")
        return result

    commit = producer["repository_commit"]
    tag = producer["repository_tag"]
    if git(("rev-parse", "HEAD"), "HEAD").stdout \
            != (commit + "\n").encode() \
            or git(("symbolic-ref", "--quiet", "HEAD"), "detached HEAD",
                   allowed=(0, 1)).returncode != 1 \
            or git(("status", "--porcelain=v1", "--untracked-files=all"),
                   "status").stdout:
        raise _refuse("producer worktree is not clean and detached at commit")
    if git(("check-ref-format", "refs/tags/" + tag), "tag syntax").returncode \
            != 0 \
            or git(("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"),
                   "tag resolution").stdout != (commit + "\n").encode():
        raise _refuse("producer tag does not resolve exactly to commit")


def _project_portable_metadata(stage: str, selected: BundleLayout) -> None:
    strip_path = _at(
        stage, selected.tree_roles["gold"][0] + "/strip_manifest.json")
    strip, _raw = _read_json(strip_path, "gold strip manifest")
    strip["repo_root"] = "."
    strip["gold_root"] = "."
    os.unlink(strip_path)
    _write_json(strip_path, strip, canonical=False, final_lf=False)

    seed_path = _at(
        stage, selected.tree_roles["stripped_seed"][0] + "/seed.json")
    seed, _raw = _read_json(seed_path, "stripped seed manifest")
    workspace = seed.get("workspace")
    if not isinstance(workspace, dict) or "path" not in workspace:
        raise _refuse("stripped seed manifest has no workspace path")
    seed["built_from"] = "."
    workspace["path"] = "workspace.tar"
    os.unlink(seed_path)
    _write_json(seed_path, seed, canonical=False, final_lf=False)


def build_bundle(*, inputs_path: str, out: str,
                 version: str = VERSION) -> dict:
    """Build one deterministic archive from an approved native role set."""
    if version == "8":
        from .bundle_build import build_bundle as build_evaluation_bundle
        from ..data.bundle import BundleRefused
        try:
            return build_evaluation_bundle(
                project=PROJECT, version="8", inputs_path=inputs_path, out=out)
        except BundleRefused as exc:
            raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    selected = layout(version)
    inputs = _load_inputs(inputs_path, version=version)
    out = _absolute(out, "bundle output")
    if os.path.basename(out) != selected.asset_name:
        raise _refuse(
            f"bundle output basename must be {selected.asset_name}")
    if os.path.lexists(out):
        raise _refuse("bundle output already exists")
    if not os.path.isdir(os.path.dirname(out)):
        raise _refuse("bundle output parent does not exist")
    _validate_producer(inputs["producer"])
    derived = _validate_build_evidence(inputs, selected=selected)
    with tempfile.TemporaryDirectory(prefix="r2t-algorand-bundle-") as temp:
        stage = os.path.join(temp, "root")
        os.makedirs(stage)
        for role, relative in selected.file_roles.items():
            target = _at(stage, relative)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if role in DERIVED_FILE_ROLES:
                _write_json(target, derived[role])
            else:
                shutil.copyfile(inputs["roles"][role], target)
        for role, (relative, _manifest) in selected.tree_roles.items():
            shutil.copytree(
                inputs["roles"][role], _at(stage, relative),
                symlinks=selected.version in {"4", "5"})
        _project_portable_metadata(stage, selected)

        role_refs = {}
        for role, relative in selected.file_roles.items():
            role_refs[role] = {"path": relative,
                               "sha256": _hash(_at(stage, relative))}
        for role, (relative, manifest_relative) in selected.tree_roles.items():
            tree = _tree_document(_at(stage, relative), role)
            manifest_path = _at(stage, manifest_relative)
            _write_json(manifest_path, tree)
            role_refs[role] = {
                "path": relative, "manifest_path": manifest_relative,
                "manifest_sha256": _hash(manifest_path),
            }
        manifest = {
            "schema": selected.bundle_schema,
            "version": selected.manifest_version, "project": PROJECT,
            "producer": dict(inputs["producer"]), "roles": role_refs,
            "digest": "0" * 64,
        }
        if GOLD_BASELINE_ROLE in selected.file_roles:
            manifest[GOLD_BASELINE_ROLE] = dict(
                inputs[GOLD_BASELINE_ROLE])
        manifest["digest"] = _document_digest(manifest)
        _write_json(_at(stage, selected.bundle_manifest), manifest)
        facts = validate_bundle(stage, version=version)
        from .bundle_build import _write_archive
        archive_sha256 = _write_archive(
            stage, _absolute(out, "bundle output"), sort_members=True)
    return {**facts, "out": out, "asset": selected.asset_name,
            "asset_bytes": os.path.getsize(out), "asset_sha256": archive_sha256}


def _source_approval(path: str) -> dict:
    value, _raw = _read_json(path, "source approval")
    _exact(value, {"schema", "project", "sdk", "testing",
                   "composition_manifest_sha256", "composed_tree_sha256",
                   "digest"}, "source approval")
    _validate_digest(value, "source approval")
    if value["schema"] != SOURCE_SCHEMA or value["project"] != PROJECT:
        raise _refuse("source approval names another schema or project")
    expected = (("sdk", SDK_REPOSITORY, SDK_COMMIT, SDK_TREE),
                ("testing", TESTING_REPOSITORY, TESTING_COMMIT, TESTING_TREE))
    for label, repository, commit, tree in expected:
        source = _exact(value[label], {"repository", "commit", "tree_sha256"},
                        f"source approval {label}")
        if source != {"repository": repository, "commit": commit,
                      "tree_sha256": tree}:
            raise _refuse(f"source approval {label} differs from the J0 pin")
    _sha(value["composition_manifest_sha256"], "composition manifest")
    _sha(value["composed_tree_sha256"], "composed tree")
    return value


def _release_authority(approval_path: str, receipt_path: str) -> tuple[dict, dict]:
    approval, _raw = _read_json(approval_path, "release approval")
    from ..java import research_minimal as minimal
    from .. import docker_authority
    _exact(approval, {"schema", "path", "project", "phase", "approval",
                      "digest"}, "release approval")
    if approval["schema"] != minimal.APPROVAL_SCHEMA \
            or approval["path"] != minimal.PATH \
            or approval["project"] != PROJECT or approval["phase"] != "release" \
            or docker_authority.semantic_digest(
                approval, domain=minimal.APPROVAL_SCHEMA) != approval["digest"]:
        raise _refuse("release approval is not the reviewed release phase")
    try:
        selected = minimal._validate_approval(
            minimal.Approval(**approval["approval"]), PROJECT, "release")
    except (TypeError, RuntimeError, ValueError) as exc:
        raise _refuse("release approval fields are malformed") from exc

    receipt, _raw = _read_json(receipt_path, "release receipt")
    keys = {"schema", "path", "project", "status", "execution_identity",
            "validation_transcript_sha256", "validation_manifest_sha256",
            "validation_ledger_sha256", "release_manifest_sha256",
            "release_tree_sha256", "released_item_ids",
            "operator_approved_digest"}
    _exact(receipt, keys, "release receipt")
    from ..java import release_validation
    if receipt["schema"] != release_validation.RELEASE_RECEIPT_SCHEMA \
            or receipt["path"] != minimal.PATH \
            or receipt["project"] != PROJECT or receipt["status"] != "provided" \
            or receipt["execution_identity"] != selected.execution_identity \
            or receipt["operator_approved_digest"] != approval["digest"]:
        raise _refuse("release receipt differs from its approval")
    joins = {
        "validation_transcript_sha256": selected.predecessor_transcript_sha256,
        "validation_manifest_sha256": selected.validation_manifest_sha256,
        "validation_ledger_sha256": selected.validation_ledger_sha256,
        "release_manifest_sha256": selected.release_manifest_sha256,
        "release_tree_sha256": selected.release_tree_sha256,
    }
    if any(receipt[name] != wanted for name, wanted in joins.items()):
        raise _refuse("release receipt hashes differ from its approval")
    ids = receipt["released_item_ids"]
    if not isinstance(ids, list) or len(ids) != 117 \
            or any(not isinstance(item, str) or not item for item in ids) \
            or len(set(ids)) != 117:
        raise _refuse("release receipt does not name 117 ordered items")
    return approval, receipt


def _jsonl(path: str, label: str) -> tuple[list[dict], bytes, dict[str, bytes]]:
    raw = _read_bytes(path, label)
    if not raw.endswith(b"\n") or b"\r" in raw:
        raise _refuse(f"{label} is not LF-terminated JSONL")
    rows = []
    lines = {}
    for number, line in enumerate(raw.splitlines(keepends=True), 1):
        if not line.strip():
            raise _refuse(f"{label} contains a blank row")
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _refuse(f"{label} row {number} is malformed") from exc
        item_id = row.get("item_id") if isinstance(row, dict) else None
        if not isinstance(item_id, str) or not item_id or item_id in lines:
            raise _refuse(f"{label} repeats or omits item_id")
        rows.append(row)
        lines[item_id] = line
    return rows, raw, lines


def _historical_slice3_release_projection(rows: list[dict]) -> bytes:
    """Return the historical Slice-3 JSONL serialization in row order."""
    return b"".join(
        (json.dumps(row, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False) + "\n").encode("utf-8")
        for row in rows)


def _gold_baseline_record(raw: bytes, rows: list[dict], *,
                          collection_harness_commit: str,
                          source_bundle_manifest_sha256: str) -> dict:
    if not isinstance(collection_harness_commit, str) \
            or _COMMIT.fullmatch(collection_harness_commit) is None:
        raise _refuse("gold baseline collection commit is not 40-hex")
    _sha(source_bundle_manifest_sha256,
         "gold baseline source bundle manifest")
    return {
        "role": GOLD_BASELINE_ROLE,
        "byte_length": len(raw),
        "row_count": len(rows),
        "collection_harness_commit": collection_harness_commit,
        "source_bundle_version": 2,
        "source_bundle_manifest_sha256": source_bundle_manifest_sha256,
        "repro_check_count": 1,
    }


def _gold_baseline_provenance(path: str, *,
                              collection_harness_commit: str,
                              source_bundle_manifest_sha256: str) -> dict:
    rows, raw, _lines = _jsonl(path, "gold baseline")
    return _gold_baseline_record(
        raw, rows, collection_harness_commit=collection_harness_commit,
        source_bundle_manifest_sha256=source_bundle_manifest_sha256)


def _validate_gold_baseline_provenance(
        value: object, path: str, *, version: str) -> tuple[list[dict], bytes]:
    provenance = _exact(value, GOLD_BASELINE_KEYS,
                        "gold baseline provenance")
    for key in ("byte_length", "row_count", "source_bundle_version",
                "repro_check_count"):
        if not isinstance(provenance[key], int) \
                or isinstance(provenance[key], bool):
            raise _refuse(
                f"gold baseline provenance {key} is not an integer")
    rows, raw, _lines = _jsonl(path, "gold baseline")
    expected = _gold_baseline_record(
        raw, rows,
        collection_harness_commit=provenance.get(
            "collection_harness_commit"),
        source_bundle_manifest_sha256=provenance.get(
            "source_bundle_manifest_sha256"))
    if provenance != expected:
        raise _refuse("gold baseline provenance differs from its bytes")
    production_identity = \
        provenance["collection_harness_commit"] \
        == GOLD_BASELINE_COLLECTION_COMMIT \
        or provenance["source_bundle_manifest_sha256"] \
        == GOLD_BASELINE_SOURCE_MANIFEST_SHA256
    approved_byte_length, approved_sha256 = (
        (GOLD_BASELINE_V5_BYTE_LENGTH, GOLD_BASELINE_V5_SHA256)
        if version == "5"
        else (GOLD_BASELINE_BYTE_LENGTH, GOLD_BASELINE_SHA256))
    if production_identity and (
            provenance["collection_harness_commit"]
            != GOLD_BASELINE_COLLECTION_COMMIT
            or provenance["source_bundle_manifest_sha256"]
            != GOLD_BASELINE_SOURCE_MANIFEST_SHA256
            or len(raw) != approved_byte_length
            or hashlib.sha256(raw).hexdigest() != approved_sha256):
        raise _refuse(
            "gold baseline differs from the approved production bytes")
    return rows, raw


def _gold_coverage_payload(row: dict) -> bool:
    lines = row.get("coverage_lines")
    files = row.get("coverage_files")
    return isinstance(lines, dict) and bool(lines) \
        and isinstance(files, dict) and set(files) == set(lines) \
        and all(isinstance(path, str) and path
                and isinstance(covered, list) and bool(covered)
                and all(isinstance(line, int) and not isinstance(line, bool)
                        for line in covered)
                and isinstance(files[path], int)
                and not isinstance(files[path], bool)
                and files[path] == len(covered)
                for path, covered in lines.items())


def _gold_baseline(path: str, ordered_ids: list[str],
                   provenance: object, *, version: str) -> dict:
    rows, raw = _validate_gold_baseline_provenance(
        provenance, path, version=version)
    if len(rows) != 111 \
            or [row["item_id"] for row in rows] != ordered_ids:
        raise _refuse(
            "gold baseline is not the 111-item execution release in order")
    for row in rows:
        if row.get("outcome") != "passed" \
                or row.get("coverage_requested") is not True \
                or row.get("coverage_collected") is not True \
                or not _gold_coverage_payload(row) \
                or row.get("coverage_mismatch") != [] \
                or row.get("metadata") != {"source": "gold"}:
            raise _refuse(
                f"gold baseline row {row['item_id']!r} differs from the "
                "approved coverage facts")
    return {**dict(provenance), "path": GOLD_BASELINE_PATH,
            "sha256": hashlib.sha256(raw).hexdigest()}


def _closures(path: str, released_ids: list[str]) -> tuple[dict, bytes]:
    raw = _read_bytes(path, "closure ledger")
    try:
        rows = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _refuse("closure ledger is malformed") from exc
    if not isinstance(rows, list) or len(rows) != 125:
        raise _refuse("closure ledger does not contain 125 admitted rows")
    by_id = {}
    for row in rows:
        item_id = row.get("item_id") if isinstance(row, dict) else None
        if not isinstance(item_id, str) or not item_id or item_id in by_id:
            raise _refuse("closure ledger repeats or omits item_id")
        if row.get("admitted") is not True:
            raise _refuse("closure ledger contains a non-admitted row")
        by_id[item_id] = row
    missing = [item_id for item_id in released_ids
               if item_id not in by_id or by_id[item_id].get("admitted") is not True]
    if missing:
        raise _refuse(f"released items lack admitted closures: {missing[:3]}")
    return by_id, raw


def _execution_view(view_path: str, released_rows: list[dict],
                    released_raw: bytes, closures: dict,
                    closure_raw: bytes) -> tuple[dict, list[str]]:
    from ..data import release
    from ..bench import slice3_evidence as slice3_eval
    selector_rows = []
    for row in released_rows:
        item_id = row["item_id"]
        closure = closures[item_id]
        files = closure.get("files")
        if not isinstance(files, list) or not files:
            raise _refuse(f"released closure {item_id!r} has no files")
        selector_rows.append({
            "item_id": item_id,
            "closure_id": release.cluster_id(files),
            "stepdef_key": slice3_eval.stepdef_key(closure, item_id),
        })
    expected = slice3_eval.select_stepdef_view(
        PROJECT, selector_rows, hashlib.sha256(released_raw).hexdigest(),
        hashlib.sha256(closure_raw).hexdigest())
    actual, _raw = _read_json(view_path, "execution view")
    if actual != expected:
        raise _refuse("execution view does not rederive from released closures")
    selected = expected["execution_manifest"]["ordered_item_ids"]
    if len(released_rows) != 117 or len(selected) != 111:
        raise _refuse("bundle population is not the fixed 117/111 view")
    return expected, selected


def _release_gold(root: str, selected: list[str], closures: dict,
                  gold_root: str) -> None:
    manifest, _raw = _read_json(os.path.join(root, "manifest.json"),
                                "release-gold manifest")
    if set(manifest) != set(selected) or len(set(manifest.values())) != 111:
        raise _refuse("release-gold manifest does not cover the execution view")
    on_disk = {
        row["path"] for row in _tree_rows(root, "release_gold")
        if row["path"] != "manifest.json"
    }
    if set(manifest.values()) != on_disk:
        raise _refuse("release-gold manifest and sidecars disagree")
    sidecar_keys = {"item_id", "files", "di_fragment", "context_classes",
                    "feature_file", "scenario_line"}
    for item_id in selected:
        basename = _relative(manifest[item_id], "release-gold sidecar name")
        if "/" in basename:
            raise _refuse("release-gold sidecar name is not one basename")
        sidecar, _raw = _read_json(os.path.join(root, basename),
                                   f"release-gold sidecar {item_id}")
        _exact(sidecar, sidecar_keys, "release-gold sidecar")
        closure = closures[item_id]
        expected = {key: closure.get(key) for key in sidecar_keys}
        expected["item_id"] = item_id
        if sidecar != expected:
            raise _refuse(f"release-gold sidecar differs from {item_id!r} closure")
        for relative in sidecar["files"]:
            rel = _relative(relative, "gold file")
            if not os.path.isfile(_at(gold_root, rel)):
                raise _refuse(f"gold tree lacks {rel!r}")


def _portable_metadata(gold_root: str, seed_root: str) -> None:
    strip, _raw = _read_json(os.path.join(gold_root, "strip_manifest.json"),
                             "gold strip manifest")
    if strip.get("repo_root") != "." or strip.get("gold_root") != ".":
        raise _refuse("gold strip manifest is not the portable projection")
    seed, _raw = _read_json(os.path.join(seed_root, "seed.json"),
                            "stripped seed manifest")
    workspace = seed.get("workspace")
    if seed.get("built_from") != "." \
            or not isinstance(workspace, dict) \
            or workspace.get("path") != "workspace.tar" \
            or isinstance(workspace.get("bytes"), bool) \
            or not isinstance(workspace.get("bytes"), int) \
            or workspace["bytes"] <= 0 \
            or isinstance(workspace.get("n_files"), bool) \
            or not isinstance(workspace.get("n_files"), int) \
            or workspace["n_files"] < 0:
        raise _refuse("stripped seed manifest is not the portable projection")
    from ..bench import seed as seed_module
    try:
        report = seed_module.verify_seed(seed_root)
        if not report["artifacts_ok"] or report["needs_database"] is not False:
            raise _refuse("stripped seed artifacts do not verify")
        if os.path.getsize(os.path.join(seed_root, "workspace.tar")) \
                != workspace["bytes"]:
            raise _refuse("stripped seed workspace byte count differs")
        with tempfile.TemporaryDirectory(prefix="r2t-seed-verify-") as unpacked:
            seed_module.unpack_workspace(seed_root, unpacked)
    except (OSError, tarfile.TarError, seed_module.SeedRefused) as exc:
        raise _refuse("stripped seed artifacts do not verify") from exc


def _mutation(manifest_path: str, map_path: str, validation_path: str,
              released_path: str, boundary_path: str,
              released_ids: set[str]) -> dict:
    manifest, _raw = _read_json(manifest_path, "mutation manifest")
    mapping, _raw = _read_json(map_path, "mutation map")
    validation, _raw = _read_json(validation_path, "mutation validation")
    from ..data import mutation_attestation as attestation
    from . import mutation_java
    try:
        facts = attestation.validate_manifest(
            manifest, expected_engine=mutation_java.ENGINE)
        attestation.validate_map(mapping, manifest, release_ids=released_ids)
    except (RuntimeError, ValueError) as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    _exact(validation, {"schema", "project", "status",
                        "source_validation_sha256", "source_inputs", "packaged",
                        "engine", "engine_version", "digest"},
           "mutation validation")
    _validate_digest(validation, "mutation validation")
    if validation["schema"] != MUTATION_SCHEMA \
            or validation["project"] != PROJECT \
            or validation["status"] != "release_ready" \
            or validation["engine"] != facts["engine"] \
            or validation["engine_version"] != facts["engine_version"]:
        raise _refuse("mutation validation names another population")
    source_keys = {"raw_manifest_sha256", "coverage_run_sha256",
                   "asset_index_sha256", "engine_source_sha256",
                   "audit_attestation_sha256"}
    source = _exact(validation["source_inputs"], source_keys,
                    "mutation validation source inputs")
    for key, value in source.items():
        _sha(value, key)
    packaged = _exact(validation["packaged"],
                      {"manifest_sha256", "map_sha256",
                       "released_items_sha256", "boundary_sha256"},
                      "mutation validation packaged inputs")
    expected = {"manifest_sha256": _hash(manifest_path),
                "map_sha256": _hash(map_path),
                "released_items_sha256": _hash(released_path),
                "boundary_sha256": _hash(boundary_path)}
    if packaged != expected:
        raise _refuse("mutation validation differs from packaged inputs")
    if mapping.get("release_sha256") != expected["released_items_sha256"] \
            or mapping.get("coverage_sha256") \
            != source["coverage_run_sha256"]:
        raise _refuse("mutation map differs from its release or coverage input")
    _sha(validation["source_validation_sha256"], "source validation")
    return validation


def _v4_quality_shard(
        directory: str, label: str, *,
        allow_producer_provenance: bool = False) -> tuple[str, dict]:
    """Resolve one closed historical shard/provenance directory."""
    if os.path.islink(directory) or not os.path.isdir(directory):
        raise _refuse(f"{label} directory is absent or linked")
    names = sorted(os.listdir(directory))
    shards = [name for name in names if name.endswith(".jsonl")]
    if len(shards) != 1:
        raise _refuse(f"{label} must contain exactly one JSONL shard")
    shard_name = shards[0]
    provenance_name = shard_name + ".provenance.json"
    if set(names) != {shard_name, provenance_name}:
        raise _refuse(
            f"{label} inventory is not one shard and adjacent provenance")
    shard_path = os.path.join(directory, shard_name)
    if not _read_bytes(shard_path, f"{label} shard"):
        raise _refuse(f"{label} shard is empty")
    sidecar, _raw = _read_json(
        os.path.join(directory, provenance_name), f"{label} provenance")
    if allow_producer_provenance:
        if not _QUALITY_SHARD_REQUIRED_MEMBERS <= set(sidecar):
            raise _refuse(f"{label} provenance lacks required members")
    else:
        _exact(sidecar, _QUALITY_SHARD_REQUIRED_MEMBERS,
               f"{label} provenance")
    if sidecar["schema"] != "r2t.mutation-shard/v1" \
            or sidecar["status"] != "complete" \
            or sidecar["out"] != shard_name:
        raise _refuse(f"{label} provenance does not bind its complete shard")
    return shard_path, sidecar


def _v4_campaign_bridge(identity: object, *, projection: dict,
                        manifest: dict, manifest_path: str, map_path: str,
                        release_sha256: str, side: str,
                        candidate_run_sha256: Optional[str] = None,
                        candidate_generated_tests_sha256: Optional[str] = None
                        ) -> dict:
    """Join one preserved v2 campaign identity to portable installed roles."""
    from ..bench import mutation_run
    if not isinstance(identity, dict):
        raise _refuse("v4 mutation provenance has no campaign identity")
    try:
        version = mutation_run.identity_version(identity)
        mutation_run.campaign_identity_digest(identity)
    except mutation_run.MutationAborted as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    if version != "v2":
        raise _refuse("v4 preserves exactly the v2 mutation campaign schema")
    expected = {
        "asset_project": PROJECT,
        "mutation_validation_class": "native",
        "asset_index_sha256": projection["source_inputs"][
            "asset_index_sha256"],
        "mutation_validation_sha256": projection[
            "source_validation_sha256"],
        "manifest_sha256": _hash(manifest_path),
        "map_sha256": _hash(map_path),
        "manifest_digest": manifest["digest"],
        "release_sha256": release_sha256,
        "container_image_digest": IMAGE_MANIFEST_DIGEST,
        "engine": "r2t-mutate-java",
        "engine_version": "1.0",
        "timeout_seconds": 600,
        "side": side,
    }
    changed = sorted(key for key, value in expected.items()
                     if identity.get(key) != value)
    if changed:
        raise _refuse(
            "v4 mutation campaign differs from installed role bridge in "
            + ", ".join(changed))
    if side == "candidate":
        candidate_expected = {
            "candidate_run_sha256": candidate_run_sha256,
            "candidate_generated_tests_sha256":
                candidate_generated_tests_sha256,
            "solution_generated_tests_sha256":
                candidate_generated_tests_sha256,
            "generation_attempt_id": V4_GENERATION_ATTEMPT_ID,
        }
        changed = sorted(key for key, value in candidate_expected.items()
                         if identity.get(key) != value)
        if changed:
            raise _refuse(
                "v4 candidate campaign differs from sealed run in "
                + ", ".join(changed))
        from ..bench import test_quality
        try:
            test_quality.refuse_unpublishable_generation(
                identity.get("generation_provenance_class"),
                "v4 candidate mutation evidence")
        except test_quality.TestQualityRefused as exc:
            raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    return identity


def _v4_scored_manifest(*, root: str, selected: BundleLayout,
                        mutation_manifest: dict, mutation_map: dict,
                        execution_view: dict) -> dict:
    """Validate and rederive the wrapped frozen Java20 execution binding."""
    from ..bench import slice3_evidence as slice3_eval
    path = _at(root, selected.file_roles[SCORED_MANIFEST_ROLE])
    wrapper, raw = _read_json(path, "v4 scored manifest")
    _exact(wrapper, {"mutation_execution_binding"}, "v4 scored manifest")
    if raw != _canonical(wrapper):
        raise _refuse("v4 scored manifest is not canonical wrapped JSON")
    binding = _exact(
        wrapper["mutation_execution_binding"],
        {"schema", "producer", "producer_argument", "projects",
         "candidate_policy", "digest"},
        "v4 mutation execution binding")
    projects = _exact(binding["projects"], {PROJECT},
                      "v4 binding projects")
    project = _exact(
        projects[PROJECT],
        {"mutant_manifest_digest", "pair_set_digest", "ordered_pairs",
         "control_observations"},
        "v4 binding Algorand project")
    ordered_pairs = project["ordered_pairs"]
    if not isinstance(ordered_pairs, list) or len(ordered_pairs) != 69 \
            or any(not isinstance(pair, list) or len(pair) != 2
                   or any(not isinstance(value, str) or not value
                          for value in pair)
                   for pair in ordered_pairs) \
            or len({tuple(pair) for pair in ordered_pairs}) != 69:
        raise _refuse("v4 binding is not the distinct 69-pair scope")
    controls = project["control_observations"]
    if not isinstance(controls, list) \
            or len(controls) != len(slice3_eval.OBSERVATION_ROLES):
        raise _refuse("v4 binding does not carry the six controls")
    if binding["digest"] != V4_EXECUTION_BINDING_DIGEST \
            or project["pair_set_digest"] != V4_PAIR_SET_DIGEST:
        raise _refuse("v4 binding differs from the frozen production identity")
    observation_ids = {}
    for role, control in zip(slice3_eval.OBSERVATION_ROLES, controls):
        _exact(control, {"role", "observation_id", "pair_set_digest"},
               f"v4 {role} binding control")
        if control["role"] != role \
                or control["observation_id"] \
                != V4_CONTROL_OBSERVATIONS[role] \
                or control["pair_set_digest"] != project["pair_set_digest"]:
            raise _refuse(f"v4 binding control {role} differs from its role")
        observation_ids[role] = control["observation_id"]
    execution_manifest = execution_view.get("execution_manifest")
    if not isinstance(execution_manifest, dict):
        raise _refuse("v4 execution view has no execution manifest")
    mutants = []
    for row in mutation_manifest["mutants"]:
        mutant_id = row["id"]
        mutants.append({
            "project": PROJECT, "mutant_id": mutant_id,
            "operator": row["operator"], "file": row["file"],
            "valid": True, "scored": True,
            "mapped_item_ids": list(
                mutation_map["by_mutant"].get(mutant_id, [])),
        })
    from ..bench import mutation_run
    try:
        views = slice3_eval.select_mutants(
            mutants, {PROJECT: execution_manifest},
            {PROJECT: _hash(_at(
                root, selected.file_roles["mutation_manifest"]))},
            {PROJECT: _hash(_at(
                root, selected.file_roles["mutation_map"]))})
        expected = slice3_eval.build_mutation_execution_binding(
            views, {PROJECT: observation_ids})
    except (slice3_eval.Slice3Refused,
            mutation_run.MutationAborted) as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    selected_view = views["projects"][PROJECT]
    if selected_view["count"] != 20 \
            or len(selected_view["ordered_pairs"]) != 69 \
            or expected != binding:
        raise _refuse(
            "v4 scored manifest does not rederive from manifest, map, and "
            "execution view")
    return binding


def _v4_candidate_run(path: str, execution_ids: list[str]) \
        -> tuple[list[dict], str]:
    """Validate the sealed Aider run without inventing a row-order join."""
    rows, raw, _lines = _jsonl(path, "v4 candidate run")
    run_sha256 = hashlib.sha256(raw).hexdigest()
    if run_sha256 != V4_CANDIDATE_RUN_SHA256 \
            or len(rows) != 111 \
            or {row["item_id"] for row in rows} != set(execution_ids):
        raise _refuse("v4 candidate run differs from the sealed 111-item run")
    files_by_item = {}
    for row in rows:
        if not all(key in row for key in (
                "item_id", "outcome", "agent_system", "produced_files")) \
                or not isinstance(row["outcome"], str) \
                or not row["outcome"] \
                or row["agent_system"] != "aider" \
                or not isinstance(row["produced_files"], list):
            raise _refuse("v4 candidate run row lacks the Aider projection")
        seen = set()
        for produced in row["produced_files"]:
            if not isinstance(produced, dict) \
                    or set(produced) != {"file_path", "code"} \
                    or not isinstance(produced["file_path"], str) \
                    or not produced["file_path"] \
                    or not isinstance(produced["code"], str) \
                    or produced["file_path"] in seen:
                raise _refuse(
                    "v4 candidate run carries malformed produced files")
            seen.add(produced["file_path"])
        files_by_item[row["item_id"]] = row["produced_files"]
    from ..bench import mutation_run
    try:
        generated = mutation_run.candidate_digest(files_by_item)
    except mutation_run.MutationAborted as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    if generated != V4_CANDIDATE_GENERATED_TESTS_SHA256:
        raise _refuse("v4 candidate generated-test digest does not rederive")
    return rows, generated


def _validate_reference_quality(*, root: str, selected: BundleLayout,
                                mutation_manifest: dict, mutation_map: dict,
                                mutation_projection: dict,
                                execution_view: dict,
                                execution_ids: list[str],
                                campaign_release_sha256: str) \
        -> tuple[dict, dict]:
    """Validate the three reviewed V4/V5 reference roles and their joins."""
    from ..bench import mutation_run
    from ..bench import slice3_evidence as slice3_eval, slice3_test_quality
    binding = _v4_scored_manifest(
        root=root, selected=selected,
        mutation_manifest=mutation_manifest, mutation_map=mutation_map,
        execution_view=execution_view)
    capability = {"mutation_execution_binding": binding}
    manifest_path = _at(root, selected.file_roles["mutation_manifest"])
    map_path = _at(root, selected.file_roles["mutation_map"])

    gold_root = _at(root, selected.tree_roles[GOLD_RESULTS_ROLE][0])
    if sorted(os.listdir(gold_root)) \
            != sorted(slice3_eval.OBSERVATION_ROLES):
        raise _refuse("v4 gold results do not contain the exact six controls")
    observations = {}
    for role in slice3_eval.OBSERVATION_ROLES:
        shard_path, sidecar = _v4_quality_shard(
            os.path.join(gold_root, role),
            f"v{selected.version} control {role}",
            allow_producer_provenance=selected.version == "5")
        if sidecar["observation_id"] != V4_CONTROL_OBSERVATIONS[role]:
            raise _refuse(f"v4 control {role} has another observation ID")
        _v4_campaign_bridge(
            sidecar["campaign_identity"], projection=mutation_projection,
            manifest=mutation_manifest, manifest_path=manifest_path,
            map_path=map_path, release_sha256=campaign_release_sha256,
            side="gold")
        try:
            observations[role] = \
                slice3_eval._load_bound_mutation_observation(
                    shard_path, bundle=capability, project=PROJECT, role=role,
                    observation_id=V4_CONTROL_OBSERVATIONS[role])
        except (slice3_eval.Slice3Refused,
                mutation_run.MutationAborted) as exc:
            raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc

    selected_pairs = [
        {"project": PROJECT, "item_id": item_id, "mutant_id": mutant_id}
        for item_id, mutant_id in binding["projects"][PROJECT][
            "ordered_pairs"]
    ]
    try:
        eligibility = slice3_eval.validate_six_observations(
            selected_pairs, observations, {PROJECT: execution_ids})
    except slice3_eval.Slice3Refused as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    attestation_path = _at(
        root, selected.file_roles[GOLD_RESULTS_ATTESTATION_ROLE])
    attestation, attestation_raw = _read_json(
        attestation_path, "v4 gold-results attestation")
    _exact(attestation,
           {"schema", "adaptive_expansion", "status",
            "eligible_projects", "projects"},
           "v4 gold-results attestation")
    attestation_projects = _exact(
        attestation.get("projects"), {PROJECT},
        "v4 eligibility projects")
    project_attestation = _exact(
        attestation_projects[PROJECT],
        {"status", "reasons", "observation_ids", "gold_flip_rate",
         "stub_twin_intersection_macro_recall", "hard_pairs", "items"},
        "v4 Algorand eligibility")
    attestation_items = project_attestation.get("items")
    if not isinstance(attestation_items, dict) \
            or any(not isinstance(item, dict) or set(item) != {
            "item_id", "status", "hard_mutant_ids",
            "stub_twin_intersection_recall"}
            for item in attestation_items.values()):
        raise _refuse("v4 eligibility items differ from their closed schema")
    derived_raw = slice3_test_quality.eligibility_bytes(eligibility)
    eligible_items = [
        item for item in attestation_items.values()
        if item["status"] == "eligible"
    ]
    if hashlib.sha256(attestation_raw).hexdigest() \
            != V4_ELIGIBILITY_SHA256 \
            or attestation_raw != derived_raw \
            or attestation != eligibility \
            or attestation["status"] != "mutation_eligible" \
            or attestation["eligible_projects"] != [PROJECT] \
            or project_attestation["status"] != "mutation_eligible" \
            or project_attestation["reasons"] \
            or project_attestation["observation_ids"] \
            != V4_CONTROL_OBSERVATIONS \
            or project_attestation["gold_flip_rate"] != 0.0 \
            or project_attestation["stub_twin_intersection_macro_recall"] \
            != 0.0 \
            or len(project_attestation["items"]) != 111 \
            or len(eligible_items) != 8 \
            or len(project_attestation["hard_pairs"]) != 9:
        raise _refuse(
            "v4 gold-results attestation does not byte-rederive from controls")

    return binding, eligibility


def _validate_v4_quality(*, root: str, selected: BundleLayout,
                         mutation_manifest: dict, mutation_map: dict,
                         mutation_projection: dict, execution_view: dict,
                         execution_ids: list[str]) -> None:
    """Validate V4's candidate roles after its shared reference roles."""
    from ..bench import mutation_run
    from ..bench import slice3_evidence as slice3_eval
    execution_release_path = _at(
        root, selected.file_roles["execution_release"])
    campaign_release_sha256 = _hash(execution_release_path)
    binding, eligibility = _validate_reference_quality(
        root=root, selected=selected,
        mutation_manifest=mutation_manifest, mutation_map=mutation_map,
        mutation_projection=mutation_projection,
        execution_view=execution_view, execution_ids=execution_ids,
        campaign_release_sha256=campaign_release_sha256)
    capability = {"mutation_execution_binding": binding}
    manifest_path = _at(root, selected.file_roles["mutation_manifest"])
    map_path = _at(root, selected.file_roles["mutation_map"])

    candidate_path = _at(root, selected.file_roles[CANDIDATE_RUN_ROLE])
    _candidate_rows, generated_sha256 = _v4_candidate_run(
        candidate_path, execution_ids)
    candidate_run_sha256 = _hash(candidate_path)
    candidate_root = _at(
        root, selected.tree_roles[CANDIDATE_RESULTS_ROLE][0])
    if os.listdir(candidate_root) != ["candidate_run1_aider"]:
        raise _refuse(
            "v4 candidate results are not exactly Aider run 1")
    candidate_shard, candidate_sidecar = _v4_quality_shard(
        os.path.join(candidate_root, "candidate_run1_aider"),
        "v4 candidate run 1")
    if candidate_sidecar["observation_id"] \
            != V4_CANDIDATE_OBSERVATION_ID:
        raise _refuse("v4 candidate run 1 has another observation ID")
    _v4_campaign_bridge(
        candidate_sidecar["campaign_identity"],
        projection=mutation_projection, manifest=mutation_manifest,
        manifest_path=manifest_path, map_path=map_path,
        release_sha256=campaign_release_sha256, side="candidate",
        candidate_run_sha256=candidate_run_sha256,
        candidate_generated_tests_sha256=generated_sha256)
    try:
        candidate_rows = slice3_eval._load_bound_mutation_observation(
            candidate_shard, bundle=capability, project=PROJECT,
            role="candidate_run1:aider", eligibility=eligibility)
        run2 = slice3_eval.authorize_mutation_job(
            binding, project=PROJECT, role="candidate_run2:aider",
            observation_id="f" * 32, eligibility=eligibility,
            run1_rows=candidate_rows)
    except (slice3_eval.Slice3Refused,
            mutation_run.MutationAborted) as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    if run2["required"] or run2["planned_pairs"]:
        raise _refuse(
            "v4 candidate run 1 requires an absent D4 run 2")


def _profile_disclosure(profile_path: str) -> dict:
    """State, and check, how the packaged profile differs from the approved.

    The bundled bytes are the producer checkout's, which the N=3 validation
    approval predates by one added line.  The disclosure is exact rather than
    asserted: deleting that one line from the packaged bytes must reproduce
    the approved digest, so any further drift refuses (spec section 12, B4).
    The removed line is not part of the `prompt_digest` block `_configuration`
    checks against protocol v8, which is why the two share every prompt digest.
    """
    packaged = _read_bytes(profile_path, "bundled profile")
    approved = packaged.replace(APPROVED_PROFILE_DIFF, b"", 1)
    if approved == packaged \
            or hashlib.sha256(approved).hexdigest() != APPROVED_PROFILE_SHA256:
        raise _refuse("bundled profile differs from the validation-approved "
                      "bytes by more than the disclosed `api_scoring` line")
    return {"packaged_sha256": hashlib.sha256(packaged).hexdigest(),
            "approved_sha256": APPROVED_PROFILE_SHA256,
            "difference": APPROVED_PROFILE_DIFF.decode().strip()}


def _boundary_disclosure(boundary_path: str) -> dict:
    """State, and check, how the packaged boundary differs from the reviewed.

    The bundled bytes are the producer checkout's, which the published v8
    bundle minted before checked-interfaces v2 added the two retained
    `R2TStepTagListener` entries to `config/boundary_algorand.yml`.  Like the
    profile disclosure the check is exact rather than asserted: deleting that
    one declared block from the reviewed bytes must reproduce the packaged
    bytes, so an installation that dropped or moved anything else refuses.  A
    bundle minted from the current tree carries the reviewed bytes unchanged
    and discloses no difference.
    """
    reviewed_path = os.path.join(BENCHMARK, "config", "boundary_algorand.yml")
    packaged = _read_bytes(boundary_path, "bundled boundary")
    reviewed = _read_bytes(reviewed_path, "reviewed boundary")
    minted = reviewed.replace(DISCLOSED_BOUNDARY_DIFF, b"", 1)
    if minted == reviewed:
        raise _refuse("reviewed boundary no longer carries the disclosed "
                      "`R2TStepTagListener` retained entries")
    if packaged not in (reviewed, minted):
        raise _refuse("bundled boundary differs from the reviewed boundary by "
                      "more than the disclosed `R2TStepTagListener` entries")
    return {"packaged_sha256": hashlib.sha256(packaged).hexdigest(),
            "reviewed_sha256": hashlib.sha256(reviewed).hexdigest(),
            "difference": (None if packaged == reviewed
                           else DISCLOSED_BOUNDARY_DIFF.decode())}


def _configuration(boundary_path: str, profile_path: str,
                   protocol_path: str, worker_plan_path: str,
                   root: str) -> tuple[dict, dict]:
    from ..data.profile import ProfileError, load_profile
    from ..bench import protocol_file as protocol
    reviewed = {
        "profile": (profile_path,
                    os.path.join(BENCHMARK, "config", "profile_algorand.yml")),
        "protocol": (protocol_path,
                     os.path.join(BENCHMARK, "protocol", "protocol_v8.yml")),
    }
    for role, (path, source) in reviewed.items():
        if _read_bytes(path, "bundled configuration") \
                != _read_bytes(source, "reviewed configuration"):
            raise _refuse(f"bundled {role} differs from reviewed v1")
    boundary_approval = _boundary_disclosure(boundary_path)
    try:
        profile = load_profile(profile_path)
        recipe = protocol.load(protocol_path)
    except (OSError, ProfileError, protocol.ProtocolError, ValueError) as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    if profile.project != PROJECT or profile.needs_database \
            or recipe["protocol_version"] != 8 \
            or recipe["prompt_profile"]["project"] != PROJECT \
            or recipe["prompt_profile"]["prompt_digest"] != profile.prompt_digest:
        raise _refuse("bundled profile/protocol do not describe Algorand v8")
    plan, _raw = _read_json(worker_plan_path, "worker plan")
    expected = {"schema": "r2t.worker-plan/1", "project": PROJECT,
                "k": 4, "workdir": "/work", "container_kind": "java"}
    if plan != expected:
        raise _refuse("worker plan is not the fixed Algorand K=4 plan")
    from ..bench.worker import plan_workers
    plan_workers(os.path.join(root, PROJECT_ROOT, "workers"), 4,
                 workdir="/work", prefix="algorand", kind="java",
                 needs_database=False)
    return plan, boundary_approval


def _repository(value: object) -> str:
    """One literal registry/repository, carrying no tag and no digest."""
    if not isinstance(value, str) or not value \
            or "@" in value or "://" in value \
            or ":" in value.rsplit("/", 1)[-1]:
        raise _refuse("OCI repository is malformed")
    return value


EVALUATION_JAVA_INPUT_KEYS = frozenset({
    "production_index_sha256", "direct_call_agent_sha256", "direct_call_agent_route",
    "direct_call_agent_runtime", "substrate_baseline_sha256", "pom_sha256",
    "stripped_corpus_sha256"})


def _evaluation_runtime_pins() -> dict:
    """The Java input identities the frozen V8 bundle was built with.

    The V7 reservation and historical coverage baseline do not admit a V8
    bundle. Its actual new observations and release index are checked by the
    shared reader. These pins are the identity of the reused jar, index and
    stripped runtime inputs, declared with the V8 bundle in
    config/evaluation_bundles.yml. The project's own declaration in
    dataset_manifest.yml follows its current lineage (#673 moved it to the
    checked-interfaces v2 jar and seed revision 3), so it cannot identify
    the bytes V8 carries.
    """
    import yaml
    path = os.path.join(BENCHMARK, "config", "evaluation_bundles.yml")
    with open(path, encoding="utf-8") as handle:
        entry = (yaml.safe_load(handle).get("projects") or {}).get(PROJECT) or {}
    pins = entry.get("java_inputs")
    if entry.get("version") != 8 or not isinstance(pins, dict) \
            or set(pins) != EVALUATION_JAVA_INPUT_KEYS:
        raise _refuse("evaluation_bundles.yml declares no exact V8 Java inputs")
    return pins


def _evaluation_release_files(path: str, receipt: dict) -> dict:
    """Read the approved full release inventory without its producer tree."""
    from ..java import release_validation, research_minimal
    manifest, raw = _read_json(path, "preserved release manifest")
    _exact(manifest, {"schema", "path", "project", "released_item_ids",
                      "tree_sha256", "files"}, "preserved release manifest")
    if hashlib.sha256(raw).hexdigest() != receipt["release_manifest_sha256"] \
            or manifest["schema"] != release_validation.RELEASE_MANIFEST_SCHEMA \
            or manifest["path"] != research_minimal.PATH \
            or manifest["project"] != PROJECT \
            or manifest["released_item_ids"] != receipt["released_item_ids"] \
            or manifest["tree_sha256"] != receipt["release_tree_sha256"]:
        raise _refuse("preserved release manifest differs from its receipt")
    if not isinstance(manifest["files"], list):
        raise _refuse("preserved release manifest has no file inventory")
    files = {}
    for row in manifest["files"]:
        _exact(row, {"path", "bytes", "sha256"}, "preserved release file")
        relative = _relative(row["path"], "preserved release file")
        if relative in files or type(row["bytes"]) is not int \
                or row["bytes"] < 0:
            raise _refuse("preserved release file repeats or has invalid size")
        _sha(row["sha256"], "preserved release file")
        files[relative] = row
    return files


def validate_evaluation_roles(*, role_paths: Mapping[str, str],
                              producer: Mapping[str, str]) -> dict:
    """Check V8's native joins after the shared evaluation reader's gates.

    S1 owns producer/scope admission, the complete inventory, seed validation,
    byte-exact native-report input_paths and reference source/observation
    joins. This callback neither revalidates that report nor uses the legacy
    compact mutation authority. All provenance is resolved inside the named
    roles; recorded producer paths are never reopened.
    """
    del producer  # Authenticated and joined to the reference by S1.
    paths = role_paths
    provenance = {
        name: os.path.join(paths["provenance"], relative)
        for name, relative in EVALUATION_PROVENANCE.items()
    }
    source = _source_approval(provenance["source_approval"])
    composition, raw = _read_json(provenance["composition"],
                                  "preserved composition manifest")
    from ..java import compose_algorand
    if hashlib.sha256(raw).hexdigest() != source["composition_manifest_sha256"] \
            or composition.get("schema") != compose_algorand.SCHEMA \
            or composition.get("sources") != compose_algorand._expected_sources() \
            or composition.get("destination_tree_sha256") \
            != source["composed_tree_sha256"] \
            or source["composed_tree_sha256"] != compose_algorand.EXPECTED_TREE_SHA256:
        raise _refuse("preserved composition differs from the approved sources")
    _approval, receipt = _release_authority(
        provenance["release_approval"], provenance["release_receipt"])
    release_files = _evaluation_release_files(
        provenance["release_manifest"], receipt)

    def released_file(path: str, relative: str) -> None:
        expected = release_files.get(relative)
        if expected is None or _hash(path) != expected["sha256"] \
                or os.path.getsize(path) != expected["bytes"]:
            raise _refuse(f"installed {relative!r} differs from the approved release")

    released_file(paths["map_release"], "items.jsonl")
    released_file(paths["closures"], "control-artifacts/closures.json")
    released, released_raw, lines = _jsonl(paths["map_release"], "map release")
    ids = [row["item_id"] for row in released]
    if ids != receipt["released_item_ids"] \
            or any(row.get("project") != PROJECT for row in released):
        raise _refuse("map release differs from the approved Algorand release")
    closures, closure_raw = _closures(paths["closures"], ids)
    if _read_bytes(os.path.join(paths["provenance"], "reference-closures.json"),
                   "reference closures") != closure_raw:
        raise _refuse("reference closures differ from the released closure ledger")
    view, selected = _execution_view(paths["execution_view"], released,
                                     released_raw, closures, closure_raw)
    if _read_bytes(paths["release_items"], "execution tasks") \
            != b"".join(lines[item] for item in selected):
        raise _refuse("execution tasks are not the exact 111 selected source rows")
    _release_gold(paths["release_gold"], selected, closures, paths["gold"])
    for row in _tree_rows(paths["gold"], "gold"):
        if row["path"] != "strip_manifest.json":
            released_file(_at(paths["gold"], row["path"]),
                          "reference-gold/" + row["path"])

    plan, boundary_approval = _configuration(
        paths["boundary"], paths["profile"], paths["protocol"],
        paths["worker_plan"], paths["provenance"])
    oci = _oci(paths["oci_image"], _hash(provenance["source_approval"]),
               _hash(provenance["release_receipt"]),
               receipt["validation_transcript_sha256"], selected=layout("2"))
    attestation, _raw = _read_json(paths["gold_results_attestation"],
                                   "reference attestation")
    if attestation.get("authority", {}).get("container_image_digest") \
            != oci["config_image_id"]:
        raise _refuse("reference runtime differs from the OCI config image")

    pins = _evaluation_runtime_pins()
    for role, key in (("direct_call_agent", "direct_call_agent_sha256"),
                      ("production_index", "production_index_sha256")):
        if _hash(paths[role]) != pins[key]:
            raise _refuse(f"installed {role} differs from the declared Java input")
    from ..java import direct_calls
    if pins["direct_call_agent_route"] != "read_only_mount" \
            or pins["direct_call_agent_runtime"] != direct_calls.AGENT_JAR_RUNTIME:
        raise _refuse("Java direct-call input does not use its read-only runtime mount")
    strip, _raw = _read_json(os.path.join(paths["gold"], "strip_manifest.json"),
                             "runtime strip manifest")
    digests = strip.get("digests")
    if not isinstance(digests, dict) \
            or hashlib.sha256(json.dumps(
                digests, sort_keys=True, separators=(",", ":")).encode()).hexdigest() \
            != pins["substrate_baseline_sha256"] \
            or digests.get("pom.xml") != pins["pom_sha256"]:
        raise _refuse("runtime strip substrate differs from the declared Java inputs")
    from ..bench import seed
    seed_doc = seed.read_seed(paths["seed"])
    if seed_doc["workspace_seed_digest"] != pins["stripped_corpus_sha256"] \
            or seed_doc["workspace"]["digest"] != seed_doc["workspace_seed_digest"]:
        raise _refuse("runtime seed differs from the declared Java inputs")
    return {"project": PROJECT, "released_items": len(ids),
            "execution_items": len(selected), "view_digest": view["view_digest"],
            "source_digest": source["digest"], "worker_plan": plan,
            "boundary_approval": boundary_approval,
            "oci_manifest_digest": oci["manifest_digest"],
            "config_image_id": oci["config_image_id"]}


def _oci(path: str, source_sha: str, receipt_sha: str,
         validation_transcript: str, *, selected: BundleLayout) -> dict:
    value, _raw = _read_json(path, "OCI image reference")
    _exact(value, {"schema", "path", "project", "platform",
                   "distribution_mode", "repository", "manifest_digest",
                   "config_image_id", "publication_receipt_sha256",
                   "canonical_transcript_sha256", "reality_transcript_sha256",
                   "validation_transcript_sha256", "source_approval_sha256",
                   "release_receipt_sha256", "digest"},
           "OCI image reference")
    _validate_digest(value, "OCI image reference")
    if value["schema"] != OCI_SCHEMA or value["path"] != IMAGE_PATH \
            or value["project"] != PROJECT \
            or value["platform"] != "linux/amd64" \
            or value["distribution_mode"] != "registry_digest":
        raise _refuse("OCI image reference names another distribution")
    _repository(value["repository"])
    if value["repository"] != selected.image_repository:
        raise _refuse("OCI image reference is not the selected bundle "
                      "repository")
    # The recorded pair is two distinct identities, so a reference that
    # substituted one for the other fails this equality; `_publication_record`
    # refuses the alias in the external evidence a build reads them from.
    if _image(value["manifest_digest"], "OCI manifest digest") \
            != IMAGE_MANIFEST_DIGEST \
            or _image(value["config_image_id"], "OCI config image ID") \
            != IMAGE_CONFIG_ID:
        raise _refuse("OCI image reference is not the recorded v1 image")
    for key in ("publication_receipt_sha256", "canonical_transcript_sha256",
                "reality_transcript_sha256", "validation_transcript_sha256",
                "source_approval_sha256", "release_receipt_sha256"):
        _sha(value[key], key)
    if value["source_approval_sha256"] != source_sha \
            or value["release_receipt_sha256"] != receipt_sha \
            or value["validation_transcript_sha256"] != validation_transcript:
        raise _refuse("OCI reference differs from bundled source/release")
    return value


def _publication_record(path: str, *,
                        selected: BundleLayout) -> tuple[dict, bytes]:
    """Validate the reviewed registry publication record (section 12, B1).

    The record is the owner's GHCR push evidence, outside the archive: it
    names the repository it pushed to, the digest the registry committed the
    manifest under, and that manifest's config descriptor digest.
    """
    value, raw = _read_json(path, "OCI publication record")
    _exact(value, {"schema", "path", "project", "platform",
                   "distribution_mode", "repository", "manifest_digest",
                   "config_image_id"}, "OCI publication record")
    if value["schema"] != PUBLICATION_SCHEMA or value["path"] != IMAGE_PATH \
            or value["project"] != PROJECT \
            or value["platform"] != "linux/amd64" \
            or value["distribution_mode"] != "registry_digest":
        raise _refuse("OCI publication record names another distribution")
    _repository(value["repository"])
    if value["repository"] != selected.image_repository:
        raise _refuse("OCI publication record is not the selected bundle "
                      "repository")
    if _image(value["manifest_digest"], "pushed OCI manifest digest") \
            == _image(value["config_image_id"], "pushed OCI config image ID"):
        raise _refuse("OCI manifest and config image IDs are aliases")
    return value, raw


def _source_evidence(inputs: dict) -> tuple[dict, object]:
    """Rebuild the two clean source pins and their frozen composition."""
    from ..java import compose_algorand, j0, research_minimal
    evidence = inputs["evidence"]
    try:
        sdk = j0.build_source_archive_manifest(
            compose_algorand.SDK_PROJECT, evidence["sdk_root"])
        testing = j0.build_source_archive_manifest(
            compose_algorand.TESTING_PROJECT, evidence["testing_root"])
        manifest_path = os.path.join(
            evidence["composition_root"], "manifest.json")
        snapshot = research_minimal._authenticate_source(
            PROJECT, os.path.join(evidence["composition_root"], "workspace"),
            manifest_path, _hash(manifest_path))
    except (OSError, RuntimeError, ValueError) as exc:
        raise _refuse(f"Algorand source evidence is invalid: {exc}") from exc
    expected = {
        "schema": SOURCE_SCHEMA, "project": PROJECT,
        "sdk": {"repository": SDK_REPOSITORY, "commit": SDK_COMMIT,
                "tree_sha256": sdk["archive_tree_sha256"]},
        "testing": {"repository": TESTING_REPOSITORY,
                    "commit": TESTING_COMMIT,
                    "tree_sha256": testing["archive_tree_sha256"]},
        "composition_manifest_sha256": _hash(manifest_path),
        "composed_tree_sha256": snapshot.identity[
            "destination_tree_sha256"],
        "digest": "0" * 64,
    }
    expected["digest"] = _document_digest(expected)
    return expected, snapshot


def _same_tree(left: str, right: str, label: str) -> None:
    if _tree_rows(left, label) != _tree_rows(right, label):
        raise _refuse(f"{label} differs from the approved release tree")


def _release_evidence(inputs: dict, source: dict,
                      snapshot: object) -> tuple[dict, dict, dict]:
    """Authenticate the reviewed validation and final release chain."""
    from ..java import research_minimal as minimal
    from . import mutation_java
    evidence = inputs["evidence"]
    roles = inputs["roles"]
    try:
        validation = minimal.require_source_approval(
            PROJECT, "validation",
            approval_path=evidence["validation_approval"],
            approved_digest=evidence["validation_approved_digest"])
        prepared = minimal._validate_preparation(
            PROJECT, snapshot, evidence["preparation_manifest"],
            validation.preparation_manifest_sha256, stripped=True)
        prepared_strip_sha256 = _hash(os.path.join(
            prepared.gold, "strip_manifest.json"))
        prepared_gold_sha256 = minimal._tree_identity(
            minimal._tree_files(prepared.gold))["tree_sha256"]
        release = mutation_java.validate_population_release(
            evidence["release_root"], project=PROJECT,
            approval_path=roles["release_approval"],
            approved_digest=evidence["release_approved_digest"])
    except (OSError, RuntimeError, ValueError) as exc:
        raise _refuse(f"Algorand release evidence is invalid: {exc}") from exc
    approval, receipt = _release_authority(
        roles["release_approval"], roles["release_receipt"])
    if approval["digest"] != evidence["release_approved_digest"]:
        raise _refuse("release approval is not the operator-approved document")

    release_root = evidence["release_root"]
    closures_path = os.path.join(
        release_root, "control-artifacts", "closures.json")
    if _read_bytes(release["items_path"], "approved released items") \
            != _read_bytes(roles["released_items"], "released items input") \
            or _read_bytes(closures_path, "approved closures") \
            != _read_bytes(roles["closures"], "closure input"):
        raise _refuse("released items or closures differ from the approved tree")
    if release["closures_sha256"] != _hash(closures_path) \
            or release["manifest_sha256"] \
            != receipt["release_manifest_sha256"] \
            or release["tree_sha256"] != receipt["release_tree_sha256"]:
        raise _refuse("release validator facts differ from the final receipt")
    _same_tree(roles["gold"], os.path.join(release_root, "reference-gold"),
               "reference gold")

    supplied_gold, _raw = _read_json(
        os.path.join(roles["release_gold"], "manifest.json"),
        "release-gold input manifest")
    approved_gold_root = os.path.join(release_root, "gold")
    approved_gold, _raw = _read_json(
        os.path.join(approved_gold_root, "manifest.json"),
        "approved release-gold manifest")
    for item_id, name in supplied_gold.items():
        if approved_gold.get(item_id) != name \
                or _read_bytes(os.path.join(roles["release_gold"], name),
                               "release-gold input sidecar") \
                != _read_bytes(os.path.join(approved_gold_root, name),
                               "approved release-gold sidecar"):
            raise _refuse("release-gold input is not an approved subset")

    transcript_path = os.path.join(os.path.dirname(release_root),
                                   "transcript.json")
    transcript, transcript_raw = _read_json(
        transcript_path, "validation transcript")
    from ..java import release_validation
    transcript_inputs = transcript.get("inputs") \
        if isinstance(transcript, dict) else None
    expected_inputs = {
        "source_manifest_sha256": validation.source_manifest_sha256,
        "census_sha256": validation.census_sha256,
        "reality_transcript_sha256":
            validation.predecessor_transcript_sha256,
        "reality_manifest_sha256": validation.reality_manifest_sha256,
        "preparation_manifest_sha256":
            validation.preparation_manifest_sha256,
        "closures_sha256": validation.closures_sha256,
        "quality_sha256": validation.quality_sha256,
    }
    if hashlib.sha256(transcript_raw).hexdigest() \
            != receipt["validation_transcript_sha256"] \
            or transcript.get("schema") != release_validation.PHASE_SCHEMA \
            or transcript.get("path") != minimal.PATH \
            or transcript.get("project") != PROJECT \
            or transcript.get("status") != "complete_pending_review" \
            or transcript.get("execution_identity") \
            != validation.execution_identity \
            or not isinstance(transcript_inputs, dict) \
            or set(transcript_inputs) != {"items_sha256"} | set(expected_inputs) \
            or any(transcript_inputs.get(name) != value
                   for name, value in expected_inputs.items()) \
            or (transcript.get("worker") or {}).get("image_id") \
            != validation.image_id \
            or (transcript.get("release") or {}).get("manifest_sha256") \
            != receipt["release_manifest_sha256"] \
            or (transcript.get("release") or {}).get("tree_sha256") \
            != receipt["release_tree_sha256"]:
        raise _refuse("validation transcript differs from its approvals")
    validation_output = transcript.get("validation") or {}
    if validation_output.get("manifest_sha256") \
            != receipt["validation_manifest_sha256"] \
            or validation_output.get("ledger_sha256") \
            != receipt["validation_ledger_sha256"]:
        raise _refuse("validation output differs from the final receipt")
    _sha(transcript_inputs["items_sha256"], "validation items input")
    # The approval names the profile bytes as they stood at commit fee673e3,
    # which the packaged checkout bytes have since moved past by one line.
    # The join is to that recorded approved digest, and the packaged bytes
    # carry the disclosed difference instead of hiding it (section 12, B4).
    if validation.profile_sha256 != APPROVED_PROFILE_SHA256:
        raise _refuse("validation approval does not name the recorded "
                      "approved profile digest")
    if validation.source_manifest_sha256 \
            != source["composition_manifest_sha256"] \
            or validation.boundary_sha256 != _hash(roles["boundary"]) \
            or validation.closures_sha256 != _hash(roles["closures"]) \
            or validation.quality_sha256 != _hash(os.path.join(
                release_root, "control-artifacts", "quality.json")) \
            or validation.strip_manifest_sha256 != prepared_strip_sha256 \
            or validation.gold_tree_sha256 != prepared_gold_sha256:
        raise _refuse("validation approval differs from packaged source/config")
    from ..bench import seed
    try:
        seed_report = seed.verify_seed(
            roles["stripped_seed"], source_root=prepared.workspace)
        seed_document = seed.read_seed(roles["stripped_seed"])
        rules = seed.SeedRules.from_manifest(seed_document)
        files = seed.workspace_files(prepared.workspace, rules)
        with tempfile.TemporaryDirectory(prefix="r2t-seed-derive-") as temp:
            derived_path = os.path.join(temp, seed.WORKSPACE_TAR)
            seed._tar_workspace(
                prepared.workspace, files, derived_path, rules.keep_empty)
            derived_raw = _read_bytes(derived_path, "derived seed workspace")
        supplied_raw = _read_bytes(
            os.path.join(roles["stripped_seed"], seed.WORKSPACE_TAR),
            "stripped seed workspace")
    except (OSError, RuntimeError, ValueError) as exc:
        raise _refuse(f"Algorand stripped seed is invalid: {exc}") from exc
    if not seed_report["artifacts_ok"] \
            or seed_report["needs_database"] is not False \
            or seed_report["stale"] is not False \
            or supplied_raw != derived_raw:
        raise _refuse("stripped seed does not derive from approved preparation")
    return validation, receipt, transcript


def _mutation_evidence(inputs: dict) -> dict:
    """Revalidate the full native report and its portable projection."""
    from ..data import mutation_attestation as attestation
    roles = inputs["roles"]
    report_path = inputs["evidence"]["mutation_validation_report"]
    try:
        campaign = attestation.validate_campaign_asset_inputs(
            report_path, manifest_path=roles["mutation_manifest"],
            map_path=roles["mutation_map"],
            release_path=roles["released_items"], require_release_ready=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise _refuse(f"Algorand mutation evidence is invalid: {exc}") from exc
    report, _raw = _read_json(report_path, "full mutation validation report")
    references = report.get("inputs")
    needed = ("raw_manifest", "coverage_run", "asset_index", "boundary",
              "engine_source", "audit_attestation")
    if campaign.get("validation_class") != "native" \
            or campaign.get("asset_project") != PROJECT \
            or campaign.get("release_items") != 117 \
            or not isinstance(references, dict) \
            or any(not isinstance(references.get(name), dict)
                   for name in needed):
        raise _refuse("full mutation report is not release-ready Algorand")
    source_inputs = {
        "raw_manifest_sha256": references["raw_manifest"].get("sha256"),
        "coverage_run_sha256": references["coverage_run"].get("sha256"),
        "asset_index_sha256": references["asset_index"].get("sha256"),
        "engine_source_sha256": references["engine_source"].get("sha256"),
        "audit_attestation_sha256": references["audit_attestation"].get(
            "sha256"),
    }
    for name, value in source_inputs.items():
        _sha(value, name)
    if references["boundary"].get("sha256") != _hash(roles["boundary"]):
        raise _refuse("full mutation report names another boundary")
    manifest = campaign["manifest"]
    expected = {
        "schema": MUTATION_SCHEMA, "project": PROJECT,
        "status": "release_ready",
        "source_validation_sha256": campaign["validation_sha256"],
        "source_inputs": source_inputs,
        "packaged": {
            "manifest_sha256": _hash(roles["mutation_manifest"]),
            "map_sha256": _hash(roles["mutation_map"]),
            "released_items_sha256": _hash(roles["released_items"]),
            "boundary_sha256": _hash(roles["boundary"]),
        },
        "engine": manifest["engine"],
        "engine_version": manifest["engine_version"], "digest": "0" * 64,
    }
    expected["digest"] = _document_digest(expected)
    return expected


def _oci_evidence(inputs: dict, source: dict, validation: object,
                  receipt: dict, *, selected: BundleLayout) -> dict:
    """Join the registry publication record to source and release evidence."""
    roles = inputs["roles"]
    evidence = inputs["evidence"]
    from ..java import research_minimal as minimal
    publication, publication_raw = _publication_record(
        evidence["oci_publication_receipt"], selected=selected)
    # The evidence host's containerd store pushes the stored manifest bytes
    # unchanged, so the digest the registry committed the manifest under is
    # the value the canonical, reality, and validation records all carry
    # under the label "image ID".  That is settled here rather than assumed:
    # a push that re-encoded the manifest states another digest and fails
    # this equality closed (ALGORAND_BUNDLE_V1_SPEC.md section 12, B1).
    if publication["manifest_digest"] != validation.image_id:
        raise _refuse("OCI image reference differs from publication evidence")

    authority_root = os.path.join(
        evidence["release_root"], "control-artifacts",
        "java-mutation-authority")
    canonical_path = os.path.join(authority_root, "canonical-transcript.json")
    reality_path = os.path.join(authority_root, "reality-transcript.json")
    canonical, canonical_raw = _read_json(
        canonical_path, "retained canonical transcript")
    reality, reality_raw = _read_json(
        reality_path, "retained reality transcript")
    canonical_sha = hashlib.sha256(canonical_raw).hexdigest()
    reality_sha = hashlib.sha256(reality_raw).hexdigest()
    image = {
        "schema": OCI_SCHEMA, "path": IMAGE_PATH,
        "project": PROJECT, "platform": "linux/amd64",
        "distribution_mode": "registry_digest",
        "repository": publication["repository"],
        "manifest_digest": publication["manifest_digest"],
        "config_image_id": publication["config_image_id"],
        "publication_receipt_sha256": hashlib.sha256(
            publication_raw).hexdigest(),
        "canonical_transcript_sha256": canonical_sha,
        "reality_transcript_sha256": reality_sha,
        "validation_transcript_sha256":
            receipt["validation_transcript_sha256"],
        "source_approval_sha256": hashlib.sha256(
            _canonical(source)).hexdigest(),
        "release_receipt_sha256": _hash(roles["release_receipt"]),
        "digest": "0" * 64,
    }
    image["digest"] = _document_digest(image)
    source_identity = canonical.get("source") or {}
    expected_authority = {
        "reference": validation.authority_reference,
        "daemon_fingerprint": validation.daemon_fingerprint,
    }
    expected_base = {"repository_digest": validation.base_digest,
                     "config_id": validation.base_config_id}
    canonical_result = canonical.get("result") or {}
    reality_manifest = os.path.join(authority_root, "reality-manifest.json")
    if canonical.get("schema") != minimal.IMAGE_SCHEMA \
            or canonical.get("path") != minimal.PATH \
            or canonical.get("project") != PROJECT \
            or canonical.get("phase") != "canonical" \
            or canonical.get("status") != "complete" \
            or canonical.get("authority") != expected_authority \
            or canonical.get("base") != expected_base \
            or canonical_result.get("candidate_image_id") \
            != image["manifest_digest"] \
            or canonical_result.get("base_config_id") \
            != validation.base_config_id \
            or canonical_result.get("m2_manifest_sha256") \
            != validation.m2_manifest_sha256 \
            or canonical_result.get("m2_tree_sha256") \
            != validation.m2_tree_sha256 \
            or source_identity.get("manifest_sha256") \
            != source["composition_manifest_sha256"] \
            or source_identity.get("destination_tree_sha256") \
            != source["composed_tree_sha256"] \
            or reality.get("schema") != minimal.REALITY_SCHEMA \
            or reality.get("path") != minimal.PATH \
            or reality.get("project") != PROJECT \
            or reality.get("status") != "complete" \
            or reality.get("authority") != expected_authority \
            or reality.get("base") != expected_base \
            or reality.get("image_id") != image["manifest_digest"] \
            or (reality.get("census") or {}).get("sha256") \
            != validation.census_sha256 \
            or (reality.get("manifest") or {}).get("sha256") \
            != validation.reality_manifest_sha256 \
            or reality.get("canonical_transcript_sha256") != canonical_sha \
            or reality.get("source") != source_identity \
            or reality_sha != validation.predecessor_transcript_sha256 \
            or _hash(reality_manifest) != validation.reality_manifest_sha256:
        raise _refuse("OCI image differs from retained canonical/reality evidence")
    return image


def _validate_build_evidence(inputs: dict, *,
                             selected: BundleLayout) -> dict:
    source, snapshot = _source_evidence(inputs)
    validation, receipt, _transcript = _release_evidence(
        inputs, source, snapshot)
    mutation = _mutation_evidence(inputs)
    image = _oci_evidence(
        inputs, source, validation, receipt, selected=selected)
    return {"source_approval": source, "mutation_validation": mutation,
            "oci_image": image}


def validate_bundle(root: str, *, version: str = VERSION,
                    expected_manifest_sha256: Optional[str] = None,
                    expected_producer: Optional[Mapping[str, str]] = None,
                    release_index_path: Optional[str] = None) -> dict:
    """Validate one extracted or staged native Algorand bundle."""
    if version == "8":
        if expected_manifest_sha256 is not None or expected_producer is not None:
            raise _refuse(
                "V8 validates its measured release index; legacy "
                "expected_manifest_sha256/expected_producer arguments are "
                "not supported. Supply release_index_path for a private index")
        from ..data import evaluation_bundle
        from ..data.bundle import BundleRefused
        try:
            return evaluation_bundle.validate_evaluation_bundle(
                project=PROJECT, version="8", root=root,
                release_index_path=release_index_path)
        except BundleRefused as exc:
            raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    if release_index_path is not None:
        raise _refuse("a private evaluation release index requires Algorand v8")
    selected = layout(version)
    root = _absolute(root, "bundle root")
    manifest_path = _at(root, selected.bundle_manifest)
    manifest, raw = _read_json(manifest_path, "bundle manifest")
    manifest_keys = {
        "schema", "version", "project", "producer", "roles", "digest",
    }
    if GOLD_BASELINE_ROLE in selected.file_roles:
        manifest_keys.add(GOLD_BASELINE_ROLE)
    _exact(manifest, manifest_keys, "bundle manifest")
    _validate_digest(manifest, "bundle manifest")
    exact_version = selected.version not in {"4", "5"} \
        or type(manifest["version"]) is int
    if raw != _canonical(manifest) \
            or manifest["schema"] != selected.bundle_schema \
            or not exact_version \
            or manifest["version"] != selected.manifest_version \
            or manifest["project"] != PROJECT:
        raise _refuse("bundle manifest is not the selected Algorand version")
    if expected_manifest_sha256 is not None \
            and _hash(manifest_path) != expected_manifest_sha256:
        raise _refuse("bundle manifest differs from release index")
    producer = _exact(manifest["producer"],
                      {"repository_tag", "repository_commit"},
                      "bundle producer")
    if not isinstance(producer["repository_tag"], str) \
            or not producer["repository_tag"] \
            or not isinstance(producer["repository_commit"], str) \
            or _COMMIT.fullmatch(producer["repository_commit"]) is None \
            or expected_producer is not None and producer != dict(expected_producer):
        raise _refuse("bundle producer differs from its authority")
    roles = _exact(manifest["roles"], selected.roles, "bundle roles")

    expected_files = {selected.bundle_manifest}
    for role, relative in selected.file_roles.items():
        reference = _exact(roles[role], {"path", "sha256"}, f"{role} reference")
        if reference["path"] != relative \
                or _hash(_at(root, relative)) != reference["sha256"]:
            raise _refuse(f"{role} reference differs from installed bytes")
        expected_files.add(relative)
    for role, (relative, manifest_relative) in selected.tree_roles.items():
        reference = _exact(roles[role],
                           {"path", "manifest_path", "manifest_sha256"},
                           f"{role} reference")
        if reference != {"path": relative, "manifest_path": manifest_relative,
                         "manifest_sha256": _hash(_at(root, manifest_relative))}:
            raise _refuse(f"{role} reference differs from its tree manifest")
        tree = _validate_tree(_at(root, relative),
                              _at(root, manifest_relative), role)
        expected_files.add(manifest_relative)
        expected_files.update(f"{relative}/{row['path']}" for row in tree["files"])

    actual_files = set()
    actual_directories = set()
    for owned in (selected.bundle_root, PROJECT_ROOT):
        owned_path = _at(root, owned)
        if os.path.islink(owned_path) or not os.path.isdir(owned_path):
            raise _refuse("bundle owned root is absent or linked")
        actual_directories.add(owned)
        for directory, dirnames, filenames in os.walk(owned_path):
            for name in dirnames:
                if os.path.islink(os.path.join(directory, name)):
                    raise _refuse("bundle contains a linked directory")
                actual_directories.add(os.path.relpath(
                    os.path.join(directory, name), root).replace(os.sep, "/"))
            for name in filenames:
                path = os.path.join(directory, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    raise _refuse("bundle contains a linked or special file")
                actual_files.add(
                    os.path.relpath(path, root).replace(os.sep, "/"))
    if actual_files != expected_files:
        raise _refuse("bundle file inventory differs from its closed roles")
    expected_directories = set()
    for relative in expected_files:
        parent = posixpath.dirname(relative)
        while parent:
            expected_directories.add(parent)
            parent = posixpath.dirname(parent)
    expected_directories = {
        path for path in expected_directories
        if any(path == owned or path.startswith(owned + "/")
               for owned in (selected.bundle_root, PROJECT_ROOT))
    }
    if actual_directories != expected_directories:
        raise _refuse("bundle directory inventory differs from its closed roles")

    source = _source_approval(
        _at(root, selected.file_roles["source_approval"]))
    _approval, receipt = _release_authority(
        _at(root, selected.file_roles["release_approval"]),
        _at(root, selected.file_roles["release_receipt"]))
    released, released_raw, released_lines = _jsonl(
        _at(root, selected.file_roles["released_items"]), "released items")
    ids = [row["item_id"] for row in released]
    if len(ids) != 117 or ids != receipt["released_item_ids"] \
            or any(row.get("project") != PROJECT for row in released):
        raise _refuse("released items differ from the 117-item receipt")
    closures, closure_raw = _closures(
        _at(root, selected.file_roles["closures"]), ids)
    view, selected_ids = _execution_view(
        _at(root, selected.file_roles["execution_view"]), released,
        released_raw,
        closures, closure_raw)
    expected_execution = b"".join(
        released_lines[item] for item in selected_ids)
    execution_release_path = _at(
        root, selected.file_roles["execution_release"])
    execution_release_rows = None
    if selected.version == "5":
        execution_release_rows, execution_release_raw, _lines = _jsonl(
            execution_release_path, "execution release")
    else:
        execution_release_raw = _read_bytes(
            execution_release_path, "execution release")
    if execution_release_raw != expected_execution:
        raise _refuse("execution release is not the selected source rows")
    v5_campaign_release_sha256 = None
    if execution_release_rows is not None:
        projection = _historical_slice3_release_projection(
            execution_release_rows)
        v5_campaign_release_sha256 = hashlib.sha256(projection).hexdigest()
    baseline = None
    if GOLD_BASELINE_ROLE in selected.file_roles:
        baseline = _gold_baseline(
            _at(root, selected.file_roles[GOLD_BASELINE_ROLE]),
            selected_ids, manifest[GOLD_BASELINE_ROLE],
            version=selected.version)
    gold_root = _at(root, selected.tree_roles["gold"][0])
    seed_root = _at(root, selected.tree_roles["stripped_seed"][0])
    _portable_metadata(gold_root, seed_root)
    _release_gold(_at(root, selected.tree_roles["release_gold"][0]),
                  selected_ids, closures, gold_root)
    mutation = _mutation(
        _at(root, selected.file_roles["mutation_manifest"]),
        _at(root, selected.file_roles["mutation_map"]),
        _at(root, selected.file_roles["mutation_validation"]),
        _at(root, selected.file_roles["released_items"]),
        _at(root, selected.file_roles["boundary"]), set(ids))
    worker_plan, boundary_approval = _configuration(
        _at(root, selected.file_roles["boundary"]),
        _at(root, selected.file_roles["profile"]),
        _at(root, selected.file_roles["protocol"]),
        _at(root, selected.file_roles["worker_plan"]), root)
    profile_approval = _profile_disclosure(
        _at(root, selected.file_roles["profile"]))
    oci = _oci(
        _at(root, selected.file_roles["oci_image"]),
        _hash(_at(root, selected.file_roles["source_approval"])),
        _hash(_at(root, selected.file_roles["release_receipt"])),
        receipt["validation_transcript_sha256"], selected=selected)
    if selected.version in {"4", "5"}:
        mutation_manifest, _raw = _read_json(
            _at(root, selected.file_roles["mutation_manifest"]),
            "v4 mutation manifest")
        mutation_map, _raw = _read_json(
            _at(root, selected.file_roles["mutation_map"]),
            "v4 mutation map")
        quality_args = {
            "root": root, "selected": selected,
            "mutation_manifest": mutation_manifest,
            "mutation_map": mutation_map,
            "mutation_projection": mutation, "execution_view": view,
            "execution_ids": selected_ids,
        }
        if selected.version == "4":
            _validate_v4_quality(**quality_args)
        else:
            _validate_reference_quality(
                **quality_args,
                campaign_release_sha256=v5_campaign_release_sha256)
    oci_path = _at(root, selected.file_roles["oci_image"])
    report = {"project": PROJECT, "version": selected.version,
              "bundle_manifest_sha256": _hash(manifest_path),
              "released_items": 117, "execution_items": 111,
              "worker_plan": worker_plan,
              "boundary_approval": boundary_approval,
              "profile_approval": profile_approval,
              "mutation_validation_sha256": _hash(
                  _at(root, selected.file_roles["mutation_validation"])),
              "oci_repository": oci["repository"],
              "oci_image_sha256": _hash(oci_path),
              "oci_manifest_digest": oci["manifest_digest"],
              "config_image_id": oci["config_image_id"],
              "producer": dict(producer),
              "view_digest": view["view_digest"],
              "source_digest": source["digest"],
              "mutation_digest": mutation["digest"]}
    if baseline is not None:
        report[GOLD_BASELINE_ROLE] = baseline
    return report


def slice3_inputs(root: str, *, version: str = VERSION) -> dict:
    """Return authenticated installed paths/facts for Slice-3 source build."""
    if version == "5":
        raise _refuse(
            "Algorand v5 is reference-only and has no Slice-3 execution route")
    selected = layout(version)
    root = _absolute(root, "installed Algorand bundle root")
    validated = validate_bundle(root, version=version)
    released_path = _at(root, selected.file_roles["released_items"])
    rows, raw, _lines = _jsonl(released_path, "released items")
    closures_path = _at(root, selected.file_roles["closures"])
    validation_path = _at(root, selected.file_roles["mutation_validation"])
    projection, _raw = _read_json(
        validation_path, "mutation validation projection")
    manifest_path = _at(root, selected.file_roles["mutation_manifest"])
    map_path = _at(root, selected.file_roles["mutation_map"])
    manifest, _raw = _read_json(manifest_path, "mutation manifest")
    mapping, _raw = _read_json(map_path, "mutation map")
    assets = {
        "validation_class": "native",
        "validation_sha256": _hash(validation_path),
        "asset_index_sha256": projection["source_inputs"][
            "asset_index_sha256"],
        "asset_project": PROJECT,
        "n_non_production_excluded": manifest.get(
            "n_non_production_excluded", 0),
        "manifest": manifest, "map": mapping,
        "release_items": len(rows),
    }
    report = {
        "release": {
            "root": root, "items_path": released_path, "item_rows": rows,
            "items_sha256": hashlib.sha256(raw).hexdigest(),
            "closures_sha256": _hash(closures_path),
        },
        "assets": assets, "closures_path": closures_path,
        "manifest_path": manifest_path, "map_path": map_path,
    }
    if GOLD_BASELINE_ROLE in validated:
        baseline = dict(validated[GOLD_BASELINE_ROLE])
        baseline["path"] = _at(root, baseline["path"])
        report[GOLD_BASELINE_ROLE] = baseline
    return report


def validate_installed_mutation_inputs(*, validation_path: str,
                                       manifest_path: str, map_path: str,
                                       release_path: str,
                                       version: str = VERSION) -> dict:
    """Validate one Slice-3 paid view against its installed bundle."""
    if version == "5":
        raise _refuse(
            "Algorand v5 is reference-only and has no mutation execution route")
    selected = layout(version)
    validation_path = _absolute(validation_path, "compact mutation validation")
    suffix = os.sep + selected.file_roles["mutation_validation"].replace(
        "/", os.sep)
    if not validation_path.endswith(suffix):
        raise _refuse("compact mutation validation is outside its bundle role")
    root = validation_path[:-len(suffix)]
    packaged = slice3_inputs(root, version=version)
    expected = {
        "manifest": packaged["manifest_path"],
        "map": packaged["map_path"],
    }
    supplied = {"manifest": _absolute(manifest_path, "mutation manifest"),
                "map": _absolute(map_path, "mutation map")}
    if supplied != expected:
        raise _refuse("compact mutation inputs differ from installed roles")
    paid_rows, _raw, _lines = _jsonl(
        _absolute(release_path, "mutation release"), "mutation paid view")
    from ..data import mutation_attestation
    try:
        mutation_attestation.validate_map(
            packaged["assets"]["map"], packaged["assets"]["manifest"],
            release_ids={row["item_id"] for row in paid_rows},
            paid_view_subset=True)
    except (RuntimeError, ValueError) as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    return {**packaged["assets"], "release_items": len(paid_rows)}


def _release_index(path: str, *, selected: BundleLayout) -> dict:
    value, raw = _read_json(path, "Algorand bundle release index")
    keys = {"schema", "project", "bundle_schema", "bundle_version",
            "repository", "release_tag", "asset_name", "asset_bytes",
            "asset_sha256", "bundle_manifest_sha256", "producer_tag",
            "producer_commit", "digest"}
    release_schema = RELEASE_SCHEMA
    if selected.version in {"4", "5"}:
        keys.update({"capabilities", "capability_notes", "mutation_engine",
                     "bundle"})
        release_schema = RELEASE_SCHEMA_V2
    _exact(value, keys, "Algorand bundle release index")
    _validate_digest(value, "Algorand bundle release index")
    exact_version = selected.version not in {"4", "5"} \
        or type(value["bundle_version"]) is int
    if raw != _canonical(value) or value["schema"] != release_schema \
            or value["project"] != PROJECT \
            or value["bundle_schema"] != selected.bundle_schema \
            or not exact_version \
            or value["bundle_version"] != selected.manifest_version \
            or value["asset_name"] != selected.asset_name \
            or not isinstance(value["repository"], str) \
            or "/" not in value["repository"] \
            or not isinstance(value["release_tag"], str) \
            or not value["release_tag"] \
            or not isinstance(value["asset_bytes"], int) \
            or isinstance(value["asset_bytes"], bool) \
            or value["asset_bytes"] <= 0 \
            or not isinstance(value["producer_commit"], str) \
            or _COMMIT.fullmatch(value["producer_commit"]) is None \
            or not isinstance(value["producer_tag"], str) \
            or not value["producer_tag"]:
        raise _refuse("Algorand bundle release index is malformed")
    for key in ("asset_sha256", "bundle_manifest_sha256"):
        _sha(value[key], key)
    if selected.version in {"4", "5"}:
        if value["capabilities"] != V4_CAPABILITIES \
                or value["capability_notes"] != V4_CAPABILITY_NOTES \
                or value["mutation_engine"] != "r2t-mutate-java":
            raise _refuse(
                f"Algorand v{selected.version} capability declaration "
                "differs from its "
                "reviewed values")
        from ..data import release
        try:
            release._check_capabilities(PROJECT, value)
        except release.ManifestRefused as exc:
            raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
        declaration = _exact(
            value["bundle"], {"version", "artifacts"},
            f"Algorand v{selected.version} bundle declaration")
        artifact_roles = (
            "mutation_validation", SCORED_MANIFEST_ROLE,
            "mutation_map", GOLD_BASELINE_ROLE, GOLD_RESULTS_ROLE,
            GOLD_RESULTS_ATTESTATION_ROLE,
        )
        if selected.version == "4":
            artifact_roles += (CANDIDATE_RUN_ROLE, CANDIDATE_RESULTS_ROLE)
        expected_artifacts = {
            role: (selected.tree_roles[role][0]
                   if role in selected.tree_roles
                   else selected.file_roles[role])
            for role in artifact_roles
        }
        artifacts = declaration.get("artifacts")
        if not isinstance(artifacts, dict) \
                or set(artifacts) != set(expected_artifacts):
            present = set(artifacts) if isinstance(artifacts, dict) else set()
            raise _refuse(
                f"Algorand v{selected.version} bundle artifact roles differ; "
                "missing="
                f"{sorted(set(expected_artifacts) - present)}, unknown="
                f"{sorted(present - set(expected_artifacts))}")
        for role, relative in artifacts.items():
            _relative(
                relative, f"Algorand v{selected.version} {role} artifact")
        if declaration["version"] != selected.version \
                or artifacts != expected_artifacts:
            raise _refuse(
                f"Algorand v{selected.version} bundle declaration differs "
                "from manifest roles")
    return value


def _inspect_archive(path: str, destination: str, *,
                     selected: BundleLayout) -> None:
    header = _read_bytes(path, "bundle archive")[:10]
    if len(header) != 10 or header[:3] != b"\x1f\x8b\x08" \
            or header[3] != 0 or header[4:8] != b"\0\0\0\0":
        raise _refuse("bundle gzip header is not canonical")
    seen = set()
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name.rstrip("/") for member in members]
        if names != sorted(names, key=lambda name: name.encode("utf-8")):
            raise _refuse("bundle archive members are not canonically ordered")
        for member, name in zip(members, names):
            rel = _relative(name, "bundle archive member")
            admitted = {
                "bundles", f"bundles/v{selected.version}",
                selected.bundle_root,
                "projects", PROJECT_ROOT,
            }
            if rel not in admitted \
                    and not rel.startswith(selected.bundle_root + "/") \
                    and not rel.startswith(PROJECT_ROOT + "/"):
                raise _refuse("bundle archive contains an unowned member")
            if rel in seen:
                raise _refuse("bundle archive repeats a member")
            seen.add(rel)
            allowed_pax = not member.pax_headers \
                or selected.version in {"4", "5"} \
                and member.pax_headers == {"path": name}
            if member.uid != 0 or member.gid != 0 or member.uname \
                    or member.gname or member.mtime != 0 or not allowed_pax:
                raise _refuse("bundle archive member metadata is not canonical")
            if member.isdir():
                if member.mode != 0o755:
                    raise _refuse("bundle archive directory mode is not 0755")
            elif member.isfile():
                if member.mode != 0o644:
                    raise _refuse("bundle archive file mode is not 0644")
            else:
                raise _refuse("bundle archive contains a link or special member")
            target = os.path.realpath(_at(destination, rel))
            if os.path.commonpath((os.path.realpath(destination), target)) \
                    != os.path.realpath(destination):
                raise _refuse("bundle archive member escapes extraction root")
        archive.extractall(destination)


def _installation(version: str, root: Optional[str],
                  release_index_path: Optional[str]) \
        -> tuple[BundleLayout, dict, str]:
    """Resolve the indexed archive before reading it or contacting GitHub."""
    selected = layout(version)
    index = _release_index(
        release_index_path or selected.release_index, selected=selected)
    if root is None:
        from ..core.paths import data_root
        root = data_root()
    root = _absolute(root, "R2T_DATA_ROOT")
    if not os.path.isdir(root):
        raise _refuse("R2T_DATA_ROOT must already exist")
    project_destination = _at(root, PROJECT_ROOT)
    bundle_destination = _at(root, selected.bundle_root)
    if os.path.lexists(project_destination) or os.path.lexists(bundle_destination):
        raise _refuse("Algorand bundle destination already exists")
    return selected, index, root


def _install_archive(archive: str, temporary: str, *, selected: BundleLayout,
                     index: dict, root: str) -> dict:
    """Use the same archive, manifest, producer and inventory gates offline."""
    if os.path.getsize(archive) != index["asset_bytes"] \
            or _hash(archive) != index["asset_sha256"]:
        raise _refuse("Algorand bundle differs from release index")
    extracted = os.path.join(temporary, "extracted")
    os.mkdir(extracted, 0o700)
    try:
        _inspect_archive(archive, extracted, selected=selected)
    except (OSError, tarfile.TarError) as exc:
        if selected.version not in {"4", "5"}:
            raise
        raise _refuse(
            f"Algorand v{selected.version} archive cannot be read") \
            from exc
    facts = validate_bundle(
        extracted, version=selected.version,
        expected_manifest_sha256=index["bundle_manifest_sha256"],
        expected_producer={"repository_tag": index["producer_tag"],
                           "repository_commit": index["producer_commit"]})
    project_destination = _at(root, PROJECT_ROOT)
    bundle_destination = _at(root, selected.bundle_root)
    os.makedirs(os.path.dirname(project_destination), exist_ok=True)
    os.makedirs(os.path.dirname(bundle_destination), exist_ok=True)
    source_project = _at(extracted, PROJECT_ROOT)
    source_bundle = _at(extracted, selected.bundle_root)
    os.rename(source_project, project_destination)
    try:
        os.rename(source_bundle, bundle_destination)
    except OSError:
        os.rename(project_destination, source_project)
        raise
    return {**facts, "asset": selected.asset_name,
            "asset_sha256": index["asset_sha256"], "data_root": root}


def install_bundle(*, version: str, archive: str, root: Optional[str] = None,
                   release_index_path: Optional[str] = None) -> dict:
    """Install a local archive using the unchanged versioned release index."""
    selected, index, root = _installation(version, root, release_index_path)
    with tempfile.TemporaryDirectory(prefix=".r2t-algorand-bundle-", dir=root) \
            as temp:
        staged = os.path.join(temp, selected.asset_name)
        try:
            shutil.copyfile(archive, staged)
        except OSError as exc:
            raise _refuse(f"cannot read local bundle archive {archive}: {exc}") \
                from exc
        return _install_archive(
            staged, temp, selected=selected, index=index, root=root)


def fetch_bundle(*, version: str, root: Optional[str] = None,
                 token: Optional[str] = None,
                 release_index_path: Optional[str] = None,
                 opener: Callable = urllib.request.urlopen) -> dict:
    """Fetch, validate, and install one native Algorand bundle version."""
    selected, index, root = _installation(version, root, release_index_path)
    from ..data.bundle import GITHUB_TOKEN_ENV, _download_asset
    token = token or os.environ.get(GITHUB_TOKEN_ENV)

    with tempfile.TemporaryDirectory(prefix=".r2t-algorand-bundle-", dir=root) \
            as temp:
        archive = os.path.join(temp, selected.asset_name)
        _download_asset(repository=index["repository"],
                        version=index["release_tag"],
                        asset_name=selected.asset_name,
                        token=token, destination=archive, opener=opener)
        return _install_archive(
            archive, temp, selected=selected, index=index, root=root)


def remint_v4_test_quality(*, out: str, root: Optional[str] = None,
                           release_index_path: Optional[str] = None) -> dict:
    """Derive one host-local Aider sidecar from validated installed V4 roles.

    The copied run and persistent sibling observation view are operator output,
    never bundle members.  Historical mutation provenance is copied exactly;
    only the ordinary test-quality summary beside the host-local run is new.
    """
    selected = layout("4")
    index = _release_index(
        release_index_path or selected.release_index, selected=selected)
    if root is None:
        from ..core.paths import data_root
        root = data_root()
    root = _absolute(root, "installed V4 data root")
    installed_before = validate_bundle(
        root, version="4",
        expected_manifest_sha256=index["bundle_manifest_sha256"],
        expected_producer={"repository_tag": index["producer_tag"],
                           "repository_commit": index["producer_commit"]})

    out = _absolute(out, "host-local test-quality output")
    real_root = os.path.realpath(root)
    real_out = os.path.realpath(out)
    if os.path.commonpath((real_root, real_out)) == real_root:
        raise _refuse(
            "host-local test-quality output must be outside R2T_DATA_ROOT")
    if os.path.lexists(out):
        raise _refuse("host-local test-quality output already exists")
    if not os.path.isdir(os.path.dirname(out)):
        raise _refuse("host-local test-quality output parent does not exist")

    artifacts = index["bundle"]["artifacts"]
    run_path = os.path.join(out, os.path.basename(
        artifacts[CANDIDATE_RUN_ROLE]))
    observations = os.path.join(out, "slice3-inputs")
    from ..bench import slice3_evidence as slice3_eval
    from ..bench import test_quality
    from ..bench import slice3_test_quality
    created = False
    try:
        os.mkdir(out)
        created = True
        shutil.copyfile(_at(root, artifacts[CANDIDATE_RUN_ROLE]), run_path)
        os.mkdir(observations)
        gold_root = _at(root, artifacts[GOLD_RESULTS_ROLE])
        for role in slice3_eval.OBSERVATION_ROLES:
            shutil.copytree(os.path.join(gold_root, role),
                            os.path.join(observations, role))
        shutil.copyfile(
            _at(root, artifacts[GOLD_RESULTS_ATTESTATION_ROLE]),
            os.path.join(observations, "six-gate-eligibility.json"))
        candidate_root = _at(root, artifacts[CANDIDATE_RESULTS_ROLE])
        shutil.copytree(
            os.path.join(candidate_root, "candidate_run1_aider"),
            os.path.join(observations, "candidate_run1_aider"))
        summary = slice3_test_quality.build_summary(
            run_path, observations_dir=observations,
            bundle_path=_at(root, artifacts[SCORED_MANIFEST_ROLE]))
        sidecar = test_quality.write_sidecar(summary, run_path)
        test_quality.load_bound_test_quality(run_path)
        installed_after = validate_bundle(
            root, version="4",
            expected_manifest_sha256=index["bundle_manifest_sha256"],
            expected_producer={"repository_tag": index["producer_tag"],
                               "repository_commit": index["producer_commit"]})
        if installed_after != installed_before:
            raise _refuse(
                "installed V4 facts changed during host-local remint")
    except AlgorandBundleRefused:
        if created:
            shutil.rmtree(out, ignore_errors=True)
        raise
    except (OSError, slice3_eval.Slice3Refused,
            test_quality.TestQualityRefused) as exc:
        if created:
            shutil.rmtree(out, ignore_errors=True)
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    return {"project": PROJECT, "version": "4", "run": run_path,
            "sidecar": sidecar, "observations": observations}


def _fixture_v4_quality(paths: dict[str, str], *, execution_ids: list[str],
                        execution_view: dict, mutation_manifest: dict,
                        mutation_map: dict, mutation_projection: dict,
                        campaign_release_sha256: str,
                        producer_provenance: Optional[
                            Mapping[str, object]] = None) -> None:
    """Write the shared reference closure and V4 candidate extension."""
    from ..bench import mutation_run
    from ..bench import slice3_evidence as slice3_eval, slice3_test_quality
    mutants = [{
        "project": PROJECT, "mutant_id": row["id"],
        "operator": row["operator"], "file": row["file"],
        "valid": True, "scored": True,
        "mapped_item_ids": list(mutation_map["by_mutant"].get(row["id"], [])),
    } for row in mutation_manifest["mutants"]]
    views = slice3_eval.select_mutants(
        mutants, {PROJECT: execution_view["execution_manifest"]},
        {PROJECT: _hash(paths["mutation_manifest"])},
        {PROJECT: _hash(paths["mutation_map"])})
    observation_ids = {
        role: hashlib.sha256(f"v4-fixture:{role}".encode()).hexdigest()[:32]
        for role in slice3_eval.OBSERVATION_ROLES
    }
    binding = slice3_eval.build_mutation_execution_binding(
        views, {PROJECT: observation_ids})
    pairs = [tuple(pair) for pair in binding["projects"][PROJECT][
        "ordered_pairs"]]
    if len(pairs) != 69:
        raise _refuse("v4 fixture selector did not produce 69 pairs")
    _write_json(paths[SCORED_MANIFEST_ROLE], {
        "mutation_execution_binding": binding})

    candidate_evidence = CANDIDATE_RUN_ROLE in paths
    candidate_run_sha256 = None
    candidate_generated_sha256 = None
    if candidate_evidence:
        candidate_rows = [{
            "item_id": item_id, "outcome": "passed",
            "agent_system": "aider",
            "produced_files": [{
                "file_path": f"src/test/java/Fixture{index:03d}Test.java",
                "code": f"// synthetic test {index}\n",
            }],
        } for index, item_id in enumerate(reversed(execution_ids))]
        with open(paths[CANDIDATE_RUN_ROLE], "xb") as handle:
            for row in candidate_rows:
                handle.write(_canonical(row))
        candidate_run_sha256 = _hash(paths[CANDIDATE_RUN_ROLE])
        candidate_generated_sha256 = mutation_run.candidate_digest({
            row["item_id"]: row["produced_files"] for row in candidate_rows})

    def identity_for(side: str, pair_list: list[tuple[str, str]], *,
                     run_sha256: str, generated_sha256: str,
                     attempt: str) -> dict:
        return mutation_run.build_campaign_identity(
            asset_index_sha256=mutation_projection["source_inputs"][
                "asset_index_sha256"],
            asset_project=PROJECT,
            mutation_validation_sha256=mutation_projection[
                "source_validation_sha256"],
            mutation_validation_class="native",
            manifest_sha256=_hash(paths["mutation_manifest"]),
            map_sha256=_hash(paths["mutation_map"]),
            release_sha256=campaign_release_sha256,
            candidate_run_sha256=run_sha256,
            solution_generated_tests_sha256=generated_sha256,
            candidate_generated_tests_sha256=generated_sha256,
            substrate_baseline_sha256="f" * 64,
            worker_resources_sha256="1" * 64, harness_version=7,
            container_image_digest=IMAGE_MANIFEST_DIGEST,
            workspace_seed_digest="3" * 64,
            database_dump_digest="no_database",
            expected_pairs=pair_list, engine="r2t-mutate-java",
            engine_version="1.0", parser="javac fixture", side=side,
            shard=0, of=1, timeout=600,
            generation_provenance_class="native_v2",
            generation_attempt_id=attempt,
            generation_campaign_digest="0123456789abcdef",
            generation_agent_runtime_sha256="4" * 64,
            generation_network_semantics="fixture_closed",
            generation_condition="c3", generation_protocol_version=8,
            generation_protocol_digest="89abcdef01234567",
            generation_native_budget={"max_reflections": 10},
            manifest_digest=mutation_manifest["digest"],
            applier_sha256="6" * 64)

    def write_shard(directory: str, name: str, rows: list[dict],
                    identity: dict, observation_id: str,
                    job_digest: str) -> str:
        os.makedirs(directory)
        out = os.path.join(directory, name)
        campaign_digest = mutation_run.campaign_identity_digest(identity)
        with open(out, "xb") as handle:
            for row in rows:
                handle.write(_canonical({
                    **row,
                    **mutation_run.row_identity_stamp(
                        identity, campaign_digest),
                }))
        provenance = {
            **dict(producer_provenance or {}),
            "observation_id": observation_id,
            "slice3_execution_binding_digest": binding["digest"],
            "slice3_mutation_job_digest": job_digest,
        }
        mutation_run.write_shard_provenance(
            out, identity, "running", provenance=provenance)
        mutation_run.write_shard_provenance(
            out, identity, "complete", provenance=provenance)
        return out

    by_item: dict[str, list[tuple[str, str]]] = {}
    for pair in pairs:
        by_item.setdefault(pair[0], []).append(pair)
    repeated_item = next(
        item_id for item_id, item_pairs in by_item.items()
        if len(item_pairs) >= 2)
    hard_pairs = set(by_item[repeated_item][:2])
    for item_id, item_pairs in by_item.items():
        if item_id != repeated_item and len({pair[0] for pair in hard_pairs}) < 8:
            hard_pairs.add(item_pairs[0])
    if len(hard_pairs) != 9 \
            or len({item_id for item_id, _mutant_id in hard_pairs}) != 8:
        raise _refuse("v4 fixture did not derive nine hard pairs over eight items")

    observations = {}
    for role in slice3_eval.OBSERVATION_ROLES:
        job = slice3_eval.authorize_mutation_job(
            binding, project=PROJECT, role=role,
            observation_id=observation_ids[role])
        rows = [{
            "item_id": item_id, "mutant_id": mutant_id,
            "outcome": ("failed" if role.startswith("full_gold")
                        and (item_id, mutant_id) in hard_pairs else "passed"),
        } for item_id, mutant_id in reversed(pairs)]
        write_shard(
            os.path.join(paths[GOLD_RESULTS_ROLE], role),
            "gold.w0.jsonl", rows,
            identity_for(
                "gold", pairs, run_sha256="9" * 64,
                generated_sha256="8" * 64, attempt="fixture-gold-attempt"),
            observation_ids[role], job["digest"])
        observations[role] = [{
            "project": PROJECT, "item_id": row["item_id"],
            "mutant_id": row["mutant_id"], "outcome": row["outcome"],
            "observation_id": observation_ids[role],
        } for row in rows]

    eligibility = slice3_eval.validate_six_observations(
        [{"project": PROJECT, "item_id": item_id, "mutant_id": mutant_id}
         for item_id, mutant_id in pairs],
        observations, {PROJECT: execution_ids})
    Path(paths[GOLD_RESULTS_ATTESTATION_ROLE]).write_bytes(
        slice3_test_quality.eligibility_bytes(eligibility))

    if not candidate_evidence:
        return
    candidate_observation_id = "9" * 32
    candidate_job = slice3_eval.authorize_mutation_job(
        binding, project=PROJECT, role="candidate_run1:aider",
        observation_id=candidate_observation_id, eligibility=eligibility)
    write_shard(
        os.path.join(paths[CANDIDATE_RESULTS_ROLE], "candidate_run1_aider"),
        "candidate.w0.jsonl",
        [{"item_id": item_id, "mutant_id": mutant_id,
          "outcome": ("undefined_steps" if index == 0
                      else "parse_or_compile_error" if index == 1
                      else "passed")}
         for index, (item_id, mutant_id) in enumerate(reversed(pairs))],
        identity_for(
            "candidate", pairs, run_sha256=candidate_run_sha256,
            generated_sha256=candidate_generated_sha256,
            attempt="fixture-aider-attempt"),
        candidate_observation_id, candidate_job["digest"])


def _fixture_inputs(root: str, *, version: str = VERSION) -> str:
    """Create one coherent, tiny-bytes 117/111 bundle input world."""
    selected_layout = layout(version)
    inputs = os.path.join(root, "inputs")
    os.makedirs(inputs)
    paths = {role: os.path.join(inputs, role)
             for role in selected_layout.roles}
    for role in selected_layout.tree_roles:
        os.makedirs(paths[role])

    evidence_root = os.path.join(root, "evidence")
    sdk_root = os.path.join(evidence_root, "sdk")
    testing_root = os.path.join(evidence_root, "testing")
    composition_root = os.path.join(evidence_root, "composition")
    preparation_root = os.path.join(evidence_root, "preparation")
    for directory in (sdk_root, testing_root,
                      os.path.join(composition_root, "workspace"),
                      os.path.join(preparation_root, "workspace")):
        os.makedirs(directory)
    composition_manifest = os.path.join(composition_root, "manifest.json")
    _write_json(composition_manifest, {"fixture": "composition"})
    preparation_manifest = os.path.join(preparation_root, "preparation.json")
    _write_json(preparation_manifest, {"fixture": "preparation"})
    Path(preparation_root, "workspace", "pom.xml").write_text(
        "<project/>\n", encoding="utf-8")
    validation_approval_path = os.path.join(
        evidence_root, "validation-approval.json")
    _write_json(validation_approval_path, {"fixture": "validation approval"})
    full_mutation_report = os.path.join(
        evidence_root, "mutation-validation.json")
    _write_json(full_mutation_report, {"inputs": {
        "raw_manifest": {"sha256": "a" * 64},
        "coverage_run": {"sha256": "8" * 64},
        "asset_index": {"sha256": "c" * 64},
        "boundary": {"sha256": "0" * 64},
        "engine_source": {"sha256": "d" * 64},
        "audit_attestation": {"sha256": "e" * 64},
    }})

    source = {
        "schema": SOURCE_SCHEMA, "project": PROJECT,
        "sdk": {"repository": SDK_REPOSITORY, "commit": SDK_COMMIT,
                "tree_sha256": SDK_TREE},
        "testing": {"repository": TESTING_REPOSITORY,
                    "commit": TESTING_COMMIT,
                    "tree_sha256": TESTING_TREE},
        "composition_manifest_sha256": _hash(composition_manifest),
        "composed_tree_sha256": "2" * 64, "digest": "0" * 64,
    }
    source["digest"] = _document_digest(source)
    _write_json(paths["source_approval"], source)

    from ..java import research_minimal as minimal
    approval = minimal.Approval(
        project=PROJECT, phase="release", execution_identity="fixture-release",
        predecessor_transcript_sha256="3" * 64,
        validation_manifest_sha256="4" * 64,
        validation_ledger_sha256="5" * 64,
        release_manifest_sha256="6" * 64,
        release_tree_sha256="7" * 64)
    approval_doc = minimal.phase_approval_document(approval)
    _write_json(paths["release_approval"], approval_doc)

    ids = [f"algorand-sdk/features/unit/f{i:03d}.feature:{i + 1}"
           for i in range(117)]
    receipt = {
        "schema": "r2t.java-research-minimal-release-receipt/1",
        "path": minimal.PATH, "project": PROJECT, "status": "provided",
        "execution_identity": approval.execution_identity,
        "validation_transcript_sha256": approval.predecessor_transcript_sha256,
        "validation_manifest_sha256": approval.validation_manifest_sha256,
        "validation_ledger_sha256": approval.validation_ledger_sha256,
        "release_manifest_sha256": approval.release_manifest_sha256,
        "release_tree_sha256": approval.release_tree_sha256,
        "released_item_ids": ids,
        "operator_approved_digest": approval_doc["digest"],
    }
    _write_json(paths["release_receipt"], receipt)

    released_rows = [
        {"item_id": item_id, "project": PROJECT, "language": "java",
         "framework": "cucumber", "task": "criterion_to_test"}
        for item_id in ids]
    released_lines = {
        row["item_id"]: (
            (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
            if selected_layout.version == "5"
            else _canonical(row))
        for row in released_rows
    }
    with open(paths["released_items"], "xb") as handle:
        for row in released_rows:
            handle.write(released_lines[row["item_id"]])
    released_raw = Path(paths["released_items"]).read_bytes()

    closures = []
    for index, item_id in enumerate(ids):
        definition = index if index < 111 else index - 111
        file_name = ("src/test/java/com/algorand/algosdk/unit/"
                     f"Steps{definition:03d}.java")
        class_name = f"com.algorand.algosdk.unit.Steps{definition:03d}"
        closures.append({
            "item_id": item_id, "admitted": True, "files": [file_name],
            "steps": [{"definition": {"file": file_name,
                                       "class": class_name,
                                       "method": "step"}}],
            "di_fragment": None, "context_classes": [class_name],
            "feature_file": f"features/unit/f{index:03d}.feature",
            "scenario_line": index + 1,
        })
    for index in range(8):
        closures.append({
            "item_id": f"algorand-sdk/features/unit/excluded.feature:{index + 1}",
            "admitted": True,
            "files": [f"src/test/java/Excluded{index}.java"],
            "steps": [{"definition": {
                "file": f"src/test/java/Excluded{index}.java",
                "class": f"Excluded{index}", "method": "step"}}],
            "di_fragment": None, "context_classes": [f"Excluded{index}"],
            "feature_file": "features/unit/excluded.feature",
            "scenario_line": index + 1,
        })
    with open(paths["closures"], "xb") as handle:
        handle.write(json.dumps(closures, sort_keys=True,
                                separators=(",", ":")).encode() + b"\n")
    closure_raw = Path(paths["closures"]).read_bytes()

    from ..data import release
    from ..bench import slice3_evidence as slice3_eval
    selectors = [{
        "item_id": row["item_id"],
        "closure_id": release.cluster_id(row["files"]),
        "stepdef_key": slice3_eval.stepdef_key(row, row["item_id"]),
    } for row in closures[:117]]
    view = slice3_eval.select_stepdef_view(
        PROJECT, selectors, hashlib.sha256(released_raw).hexdigest(),
        hashlib.sha256(closure_raw).hexdigest())
    _write_json(paths["execution_view"], view)
    selected = view["execution_manifest"]["ordered_item_ids"]
    with open(paths["execution_release"], "xb") as handle:
        for item_id in selected:
            handle.write(released_lines[item_id])

    baseline_provenance = None
    if GOLD_BASELINE_ROLE in selected_layout.file_roles:
        coverage_path = "src/main/java/com/algorand/algosdk/F.java"
        with open(paths[GOLD_BASELINE_ROLE], "xb") as handle:
            for item_id in selected:
                handle.write(_canonical({
                    "item_id": item_id,
                    "outcome": "passed",
                    "coverage_requested": True,
                    "coverage_collected": True,
                    "coverage_lines": {coverage_path: [1]},
                    "coverage_files": {coverage_path: 1},
                    "coverage_mismatch": [],
                    "metadata": {"source": "gold"},
                }))
        baseline_provenance = _gold_baseline_provenance(
            paths[GOLD_BASELINE_ROLE],
            collection_harness_commit="f" * 40,
            source_bundle_manifest_sha256="b" * 64)

    strip = {"repo_root": "/source", "gold_root": "/gold",
             "moved": [], "moved_config": [], "patched": [],
             "installed": [], "boundary_version": 1, "digests": {},
             "substrate_roots": ["src"], "substrate_volatile": [],
             "bytecode_roots": [], "build_roots": ["target"]}
    _write_json(os.path.join(paths["gold"], "strip_manifest.json"), strip,
                canonical=False, final_lf=False)
    gold_files = {}
    for closure in closures[:111]:
        relative = closure["files"][0]
        target = _at(paths["gold"], relative)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        Path(target).write_text("// fixture\n", encoding="utf-8")
        gold_files[closure["item_id"]] = relative

    gold_manifest = {}
    by_id = {row["item_id"]: row for row in closures}
    for index, item_id in enumerate(selected):
        basename = f"{index:03d}.json"
        gold_manifest[item_id] = basename
        closure = by_id[item_id]
        sidecar = {key: closure[key] for key in (
            "item_id", "files", "di_fragment", "context_classes",
            "feature_file", "scenario_line")}
        _write_json(os.path.join(paths["release_gold"], basename), sidecar)
    _write_json(os.path.join(paths["release_gold"], "manifest.json"),
                gold_manifest)

    shutil.copytree(paths["gold"], os.path.join(preparation_root, "gold"))

    from ..bench import seed as seed_module
    prepared_workspace = os.path.join(preparation_root, "workspace")
    rules = seed_module.CUCUMBER_RULES
    prepared_files = seed_module.workspace_files(prepared_workspace, rules)
    # `_tar_workspace` records each file's real mode, which is right for a
    # real seed: those bytes come from a stripped Git checkout, so the modes
    # recorded are the tree's and two operators freeze the same seed.  This
    # workspace is synthesized above with `write_text`, so its modes are
    # `0o666 & ~umask` and `workspace.tar` -- and every digest computed from
    # it, up to the frozen archive pins in `selftest` -- would otherwise move
    # with the operator's shell.  Present the modes a checkout presents, the
    # same 0o644 the bundle writer normalises its own members to.
    for relative in prepared_files:
        os.chmod(os.path.join(prepared_workspace, relative), 0o644)
    workspace = seed_module._tar_workspace(
        prepared_workspace, prepared_files,
        os.path.join(paths["stripped_seed"], "workspace.tar"),
        rules.keep_empty)
    workspace_raw = Path(
        paths["stripped_seed"], "workspace.tar").read_bytes()
    key = seed_module.seed_key(
        prepared_workspace, seed_module.NO_DATABASE, prepared_files, rules)
    seed = {
        "format": seed_module.SEED_FORMAT, **key,
        "built_at": "2026-08-18T00:00:00+0000",
        "built_from": prepared_workspace, "build_seconds": 0.0,
        "needs_database": False,
        "workspace": {"path": "/seed/workspace.tar",
                      "bytes": len(workspace_raw),
                      "n_files": workspace["n_files"],
                      "digest": hashlib.sha256(workspace_raw).hexdigest()},
        "database": {"declared": "no_database", "digest": "no_database",
                     "path": None, "bytes": 0},
        **rules.to_manifest(), "cleanliness": {},
        "workspace_seed_digest": hashlib.sha256(workspace_raw).hexdigest(),
        "database_dump_digest": "no_database",
    }
    _write_json(os.path.join(paths["stripped_seed"], "seed.json"), seed,
                canonical=False, final_lf=False)

    from ..data import mutation_attestation
    from . import mutation_java
    if selected_layout.version in {"4", "5"}:
        raw_mutant = [{
            "file": ("src/main/java/com/algorand/algosdk/"
                     f"Fixture{index:02d}.java"),
            "operator": "MethodCallRemoval", "start_line": index + 1,
            "start_col": 1, "original": f"call{index}();", "mutated": ";",
        } for index in range(21)]
    else:
        raw_mutant = [{
            "file": "src/main/java/com/algorand/algosdk/F.java",
            "operator": "MethodCallRemoval", "start_line": 1,
            "start_col": 1, "original": "call();", "mutated": ";",
        }]
    recipe = {"schema": mutation_java.ANALYSIS_SCHEMA, "classpath": [],
              "sourcepath": [{"path": "src/main/java", "kind": "tree",
                              "sha256": "6" * 64}], "module_path": []}
    recipe["digest"] = mutation_java._canonical_sha256(recipe)
    mutant_manifest = mutation_java.build_population(
        raw_mutant, parser_version="javac fixture", exclusions=(),
        enumerator_rev=mutation_java.ENUMERATOR_REV,
        analysis_recipe=recipe)
    _write_json(paths["mutation_manifest"], mutant_manifest)
    if selected_layout.version in {"4", "5"}:
        from ..bench import slice3_evidence as slice3_eval
        provisional = [{
            "project": PROJECT, "mutant_id": row["id"],
            "operator": row["operator"], "file": row["file"],
            "valid": True, "scored": True,
            "mapped_item_ids": [selected[0]],
        } for row in mutant_manifest["mutants"]]
        selected_mutants = slice3_eval.select_mutants(
            provisional, {PROJECT: view["execution_manifest"]},
            {PROJECT: "1" * 64}, {PROJECT: "2" * 64})[
                "projects"][PROJECT]["ordered_mutant_ids"]
        selected_set = set(selected_mutants)
        by_mutant = {}
        for index, mutant_id in enumerate(selected_mutants):
            count = 4 if index < 9 else 3
            by_mutant[mutant_id] = [
                selected[(index * 3 + offset) % len(selected)]
                for offset in range(count)
            ]
        remaining = [row["id"] for row in mutant_manifest["mutants"]
                     if row["id"] not in selected_set]
        if len(remaining) != 1:
            raise _refuse("v4 fixture did not leave one coverage mutant")
        by_mutant[remaining[0]] = ids
    else:
        mutant_id = mutant_manifest["mutants"][0]["id"]
        by_mutant = {mutant_id: ids}
    mutant_map = mutation_attestation.build_map_artifact(
        mutant_manifest, by_mutant, [], coverage_sha256="8" * 64,
        release_sha256=_hash(paths["released_items"]))
    _write_json(paths["mutation_map"], mutant_map)
    mutation_projection = {
        "schema": MUTATION_SCHEMA, "project": PROJECT,
        "status": "release_ready",
        "source_validation_sha256": _hash(full_mutation_report),
        "source_inputs": {
            "raw_manifest_sha256": "a" * 64,
            "coverage_run_sha256": "8" * 64,
            "asset_index_sha256": "c" * 64,
            "engine_source_sha256": "d" * 64,
            "audit_attestation_sha256": "e" * 64,
        },
        "packaged": {
            "manifest_sha256": _hash(paths["mutation_manifest"]),
            "map_sha256": _hash(paths["mutation_map"]),
            "released_items_sha256": _hash(paths["released_items"]),
            "boundary_sha256": "0" * 64,
        },
        "engine": mutation_java.ENGINE,
        "engine_version": mutation_java.ENGINE_VERSION, "digest": "0" * 64,
    }

    for role, source_path in (
            ("boundary", os.path.join(BENCHMARK, "config",
                                      "boundary_algorand.yml")),
            ("profile", os.path.join(BENCHMARK, "config",
                                     "profile_algorand.yml")),
            ("protocol", os.path.join(BENCHMARK, "protocol",
                                      "protocol_v8.yml"))):
        shutil.copyfile(source_path, paths[role])
    full_report, _raw = _read_json(
        full_mutation_report, "fixture full mutation report")
    full_report["inputs"]["boundary"]["sha256"] = _hash(paths["boundary"])
    os.unlink(full_mutation_report)
    _write_json(full_mutation_report, full_report)
    mutation_projection["source_validation_sha256"] = _hash(
        full_mutation_report)
    mutation_projection["packaged"]["boundary_sha256"] = _hash(
        paths["boundary"])
    mutation_projection["digest"] = _document_digest(mutation_projection)
    _write_json(paths["mutation_validation"], mutation_projection)
    if selected_layout.version in {"4", "5"}:
        campaign_release_sha256 = _hash(paths["execution_release"])
        if selected_layout.version == "5":
            execution_rows, _raw, _lines = _jsonl(
                paths["execution_release"], "fixture v5 execution release")
            projection = _historical_slice3_release_projection(
                execution_rows)
            campaign_release_sha256 = hashlib.sha256(
                projection).hexdigest()
        _fixture_v4_quality(
            paths, execution_ids=selected, execution_view=view,
            mutation_manifest=mutant_manifest, mutation_map=mutant_map,
            mutation_projection=mutation_projection,
            campaign_release_sha256=campaign_release_sha256,
            producer_provenance=({
                "run": "/fixture/runs/reference.jsonl",
                "manifest": "/fixture/mutation/manifest.json",
                "release": "/fixture/release/items.jsonl",
            } if selected_layout.version == "5" else None))
    _write_json(paths["worker_plan"], {
        "schema": "r2t.worker-plan/1", "project": PROJECT, "k": 4,
        "workdir": "/work", "container_kind": "java"})

    from ..java import release_validation as validation_module
    validation_root = os.path.join(evidence_root, "validation")
    release_root = os.path.join(validation_root, "release")
    controls = os.path.join(release_root, "control-artifacts")
    authority_root = os.path.join(controls, "java-mutation-authority")
    os.makedirs(authority_root)
    shutil.copyfile(paths["released_items"],
                    os.path.join(release_root, "items.jsonl"))
    shutil.copyfile(paths["closures"], os.path.join(controls, "closures.json"))
    quality_path = os.path.join(controls, "quality.json")
    _write_json(quality_path, {"fixture": "quality"})
    shutil.copytree(paths["gold"], os.path.join(release_root, "reference-gold"))
    shutil.copytree(paths["release_gold"], os.path.join(release_root, "gold"))

    # The canonical, reality, and validation records carry the recorded image
    # ID, which registry distribution publishes as the manifest digest; the
    # config descriptor digest is the second, distinct identity (B1).
    image_id = IMAGE_MANIFEST_DIGEST
    base = {"repository_digest": "sha256:" + "b" * 64,
            "config_id": "sha256:" + "c" * 64}
    authority = {"reference": {"path": "/fixture/authority.json",
                               "file_sha256": "1" * 64,
                               "digest": "2" * 64},
                 "daemon_fingerprint": "3" * 64}
    source_identity = {
        "kind": "algorand-composition",
        "manifest_sha256": _hash(composition_manifest),
        "destination_tree_sha256": "2" * 64,
        "sources": [],
    }
    canonical = {
        "schema": minimal.IMAGE_SCHEMA, "path": minimal.PATH,
        "project": PROJECT, "phase": "canonical", "status": "complete",
        "authority": authority, "base": base, "source": source_identity,
        "result": {"candidate_image_id": image_id,
                   "base_config_id": base["config_id"],
                   "m2_manifest_sha256": "4" * 64,
                   "m2_tree_sha256": "5" * 64},
    }
    canonical_path = os.path.join(authority_root, "canonical-transcript.json")
    _write_json(canonical_path, canonical)
    canonical_sha = _hash(canonical_path)
    reality_manifest_path = os.path.join(authority_root,
                                         "reality-manifest.json")
    _write_json(reality_manifest_path, {"schema": "fixture-reality"})
    reality = {
        "schema": minimal.REALITY_SCHEMA, "path": minimal.PATH,
        "project": PROJECT, "status": "complete", "authority": authority,
        "base": base, "source": source_identity,
        "census": {"path": "/fixture/census.json", "sha256": "6" * 64},
        "canonical_transcript_sha256": canonical_sha,
        "image_id": image_id,
        "manifest": {"path": "manifest.json", "bytes": 0,
                     "sha256": _hash(reality_manifest_path)},
    }
    reality_path = os.path.join(authority_root, "reality-transcript.json")
    _write_json(reality_path, reality)
    reality_sha = _hash(reality_path)

    validation_manifest_sha = "4" * 64
    validation_ledger_sha = "5" * 64
    release_manifest_sha = "6" * 64
    release_tree_sha = "7" * 64
    validation_transcript = {
        "schema": validation_module.PHASE_SCHEMA, "path": minimal.PATH,
        "project": PROJECT, "status": "complete_pending_review",
        "execution_identity": "fixture-release",
        "inputs": {
            "items_sha256": _hash(paths["released_items"]),
            "source_manifest_sha256": _hash(composition_manifest),
            "census_sha256": "6" * 64,
            "reality_transcript_sha256": reality_sha,
            "reality_manifest_sha256": _hash(reality_manifest_path),
            "preparation_manifest_sha256": _hash(preparation_manifest),
            "closures_sha256": _hash(paths["closures"]),
            "quality_sha256": _hash(quality_path),
        },
        "worker": {"image_id": image_id, "network": "none", "pull": "never"},
        "validation": {"manifest_sha256": validation_manifest_sha,
                       "ledger_sha256": validation_ledger_sha},
        "release": {"manifest_sha256": release_manifest_sha,
                    "tree_sha256": release_tree_sha},
    }
    validation_transcript_path = os.path.join(validation_root, "transcript.json")
    _write_json(validation_transcript_path, validation_transcript)
    validation_transcript_sha = _hash(validation_transcript_path)

    approval = minimal.Approval(
        project=PROJECT, phase="release", execution_identity="fixture-release",
        predecessor_transcript_sha256=validation_transcript_sha,
        validation_manifest_sha256=validation_manifest_sha,
        validation_ledger_sha256=validation_ledger_sha,
        release_manifest_sha256=release_manifest_sha,
        release_tree_sha256=release_tree_sha)
    approval_doc = minimal.phase_approval_document(approval)
    Path(paths["release_approval"]).unlink()
    _write_json(paths["release_approval"], approval_doc)
    receipt.update({
        "validation_transcript_sha256": validation_transcript_sha,
        "validation_manifest_sha256": validation_manifest_sha,
        "validation_ledger_sha256": validation_ledger_sha,
        "release_manifest_sha256": release_manifest_sha,
        "release_tree_sha256": release_tree_sha,
        "operator_approved_digest": approval_doc["digest"],
    })
    Path(paths["release_receipt"]).unlink()
    _write_json(paths["release_receipt"], receipt)

    publication = {
        "schema": PUBLICATION_SCHEMA, "path": IMAGE_PATH,
        "project": PROJECT, "platform": "linux/amd64",
        "distribution_mode": "registry_digest",
        "repository": selected_layout.image_repository,
        "manifest_digest": image_id, "config_image_id": IMAGE_CONFIG_ID,
    }
    publication_path = os.path.join(evidence_root, "oci-receipt.json")
    _write_json(publication_path, publication)
    oci = {
        "schema": OCI_SCHEMA, "path": IMAGE_PATH,
        "project": PROJECT, "platform": "linux/amd64",
        "distribution_mode": "registry_digest",
        "repository": publication["repository"],
        "manifest_digest": image_id, "config_image_id": IMAGE_CONFIG_ID,
        "publication_receipt_sha256": _hash(publication_path),
        "canonical_transcript_sha256": canonical_sha,
        "reality_transcript_sha256": reality_sha,
        "validation_transcript_sha256": receipt[
            "validation_transcript_sha256"],
        "source_approval_sha256": _hash(paths["source_approval"]),
        "release_receipt_sha256": _hash(paths["release_receipt"]),
        "digest": "0" * 64,
    }
    oci["digest"] = _document_digest(oci)
    _write_json(paths["oci_image"], oci)

    descriptor = {
        "schema": selected_layout.input_schema,
        "producer": {"repository_tag": "v1.0.0-fixture",
                     "repository_commit": "1" * 40},
        "roles": {role: paths[role] for role in selected_layout.input_roles},
        "evidence": {
            "sdk_root": sdk_root,
            "testing_root": testing_root,
            "composition_root": composition_root,
            "validation_approval": validation_approval_path,
            "validation_approved_digest": "a" * 64,
            "preparation_manifest": preparation_manifest,
            "release_root": release_root,
            "release_approved_digest": approval_doc["digest"],
            "mutation_validation_report": full_mutation_report,
            "oci_publication_receipt": publication_path,
        },
    }
    if baseline_provenance is not None:
        descriptor[GOLD_BASELINE_ROLE] = baseline_provenance
    descriptor_path = os.path.join(root, "inputs.json")
    _write_json(descriptor_path, descriptor)
    return descriptor_path


def _evaluation_entrypoints_selftest(check, refused) -> None:
    """The legacy public names forward V8 to S1's actual common APIs."""
    from types import ModuleType
    from unittest.mock import patch
    from .. import data as data_package
    from ..data.bundle import BundleRefused
    from . import bundle_build

    built = {"asset_sha256": "a" * 64, "manifest_path": "/fixture/archive.manifest.json"}
    with patch.object(bundle_build, "build_bundle", return_value=built) as build, \
            patch(__name__ + ".layout", side_effect=AssertionError("legacy layout called")):
        result = build_bundle(inputs_path="/fixture/inputs.json",
                              out="/fixture/archive.tar.gz", version="8")
        check("native build-algorand V8 entry forwards to the shared project/version builder",
              result is built and build.call_args.kwargs == {
                  "project": PROJECT, "version": "8", "inputs_path": "/fixture/inputs.json",
                  "out": "/fixture/archive.tar.gz"})
        build.side_effect = BundleRefused("REFUSED: descriptor project/version mismatch")
        check("V8 build preserves the shared descriptor refusal through the native API",
              refused(lambda: build_bundle(inputs_path="/fixture/inputs.json",
                                            out="/fixture/archive.tar.gz", version="8"),
                      "descriptor project/version mismatch"))

    calls = []
    validated = {"project": PROJECT, "version": 8, "release_ready": True}
    shared = ModuleType("r2t.data.evaluation_bundle")

    def validate(**kwargs):
        calls.append(kwargs)
        return validated

    shared.validate_evaluation_bundle = validate
    with patch.dict("sys.modules", {shared.__name__: shared}), \
            patch.object(data_package, "evaluation_bundle", shared, create=True), \
            patch(__name__ + ".layout", side_effect=AssertionError("legacy layout called")):
        result = validate_bundle("/fixture/installed", version="8",
                                 release_index_path="/fixture/private-index.json")
        check("native V8 validation forwards the complete private-index reader result",
              result is validated and calls == [{
                  "project": PROJECT, "version": "8", "root": "/fixture/installed",
                  "release_index_path": "/fixture/private-index.json"}])
        validate_bundle("/fixture/installed", version="8")
        check("native V8 validation retains the default measured index route",
              calls[-1]["release_index_path"] is None)
        before = len(calls)
        for argument, value in (("expected_manifest_sha256", "a" * 64),
                                ("expected_producer", {"repository_tag": "fixture",
                                                       "repository_commit": "1" * 40})):
            check("V8 refuses rather than ignores the legacy " + argument + " authority",
                  refused(lambda: validate_bundle("/fixture/installed", version="8",
                                                   **{argument: value}),
                          "legacy expected_manifest_sha256/expected_producer")
                  and len(calls) == before)
        check("historical native readers refuse a V8 private release index",
              refused(lambda: validate_bundle("/fixture/installed", version="2",
                                               release_index_path="/fixture/index.json"),
                      "requires Algorand v8")
              and len(calls) == before)

        def reject(**kwargs):
            raise BundleRefused("REFUSED: measured V8 release pin mismatch")

        shared.validate_evaluation_bundle = reject
        check("V8 measured-index failures retain the native reader's refusal surface",
              refused(lambda: validate_bundle("/fixture/installed", version="8"),
                      "measured V8 release pin mismatch"))


def _fixture_evaluation_roles(root: str) -> tuple[dict, dict]:
    """Synthetic native roles with authentic internal source/release joins."""
    from ..java import compose_algorand, release_validation, research_minimal
    descriptor = _fixture_inputs(root, version="2")
    inputs, _raw = _read_json(descriptor, "fixture inputs")
    original = inputs["roles"]
    # Upgrade only this evaluation fixture. Historical _fixture_inputs
    # callers retain their original bytes and frozen archive expectations.
    # Synthetic IDs now name Scenario line 3 in valid standalone features;
    # the same 117 features retain their 111 definition groups.
    from ..bench import repo, seed as seed_module
    from ..bench import slice3_evidence as slice3_eval
    from ..core.boundary import load_boundary
    from ..data import release

    prepared_workspace = os.path.join(
        os.path.dirname(inputs["evidence"]["preparation_manifest"]), "workspace")
    production = Path(prepared_workspace, "src/main/java/com/algorand/algosdk/Fixture.java")
    production.parent.mkdir(parents=True, exist_ok=True)
    production.write_text(
        "package com.algorand.algosdk;\n"
        "public class Fixture {\n"
        "    public void addA(int a, int b) { int value = a + b; }\n"
        "    public void addB(int a, int b) { int value = a + b; }\n"
        "}\n", encoding="utf-8")
    previous_closures = json.loads(Path(original["closures"]).read_text())
    released_rows, closures = [], []
    for index in range(117):
        definition = index if index < 111 else index - 111
        logical_feature = f"features/unit/f{index:03d}.feature"
        feature = f"src/test/resources/com/algorand/algosdk/unit/f{index:03d}.feature"
        item_id = f"{PROJECT}/{logical_feature}:3"
        file_name = ("src/test/java/com/algorand/algosdk/unit/"
                     f"Steps{definition:03d}.java")
        class_name = f"com.algorand.algosdk.unit.Steps{definition:03d}"
        given = f"fixture {definition:03d} is prepared"
        then = f"fixture {definition:03d} has its expected value"
        scenario = f"  Scenario: Fixture {index:03d}\n    Given {given}\n    Then {then}\n"
        feature_path = Path(prepared_workspace, feature)
        feature_path.parent.mkdir(parents=True, exist_ok=True)
        feature_path.write_text(f"Feature: Fixture {index:03d}\n\n" + scenario,
                                encoding="utf-8")
        if index < 111:
            gold_path = Path(original["gold"], file_name)
            gold_path.write_text(
                "package com.algorand.algosdk.unit;\n\n"
                "import io.cucumber.java.en.Given;\n"
                "import io.cucumber.java.en.Then;\n\n"
                f"public class Steps{definition:03d} {{\n"
                "    private int value;\n\n"
                f'    @Given("{given}")\n'
                "    public void prepare() { value = 2; }\n\n"
                f'    @Then("{then}")\n'
                '    public void assertValue() { if (value != 2) { throw new AssertionError("value"); } }\n'
                "}\n", encoding="utf-8")
        closures.append({
            "item_id": item_id, "admitted": True, "files": [file_name],
            "steps": [
                {"keyword": keyword, "text": text, "side": "removable",
                 "source_line": line, "origin": "scenario", "example_row": 0,
                 "definition": {"file": file_name, "class": class_name,
                                "method": method, "kind": keyword}}
                for keyword, text, line, method in (
                    ("Given", given, 4, "prepare"),
                    ("Then", then, 5, "assertValue"))],
            "di_fragment": None, "context_classes": [class_name],
            "feature_file": feature, "scenario_line": 3})
        released_rows.append({
            "item_id": item_id, "project": PROJECT, "language": "java",
            "framework": "cucumber", "task": "criterion_to_test",
            "provenance": {"file_path": logical_feature, "line": 3},
            "requirement": {"feature_title": f"Fixture {index:03d}",
                            "background": None, "narrative": None},
            "criterion": {"kind": "Scenario", "scenario_title": f"Fixture {index:03d}",
                          "gherkin": scenario.rstrip("\n")}})
    # Keep the eight nonreleased extraction rows in the native ledger.
    closure_raw = _canonical(closures + previous_closures[117:])
    Path(original["closures"]).write_bytes(closure_raw)
    released_lines = {row["item_id"]: _canonical(row) for row in released_rows}
    released_raw = b"".join(released_lines.values())
    Path(original["released_items"]).write_bytes(released_raw)
    selectors = [{"item_id": row["item_id"],
                  "closure_id": release.cluster_id(row["files"]),
                  "stepdef_key": slice3_eval.stepdef_key(row, row["item_id"])}
                 for row in closures]
    view = slice3_eval.select_stepdef_view(
        PROJECT, selectors, hashlib.sha256(released_raw).hexdigest(),
        hashlib.sha256(closure_raw).hexdigest())
    Path(original["execution_view"]).write_bytes(_canonical(view))
    selected = view["execution_manifest"]["ordered_item_ids"]
    Path(original["execution_release"]).write_bytes(
        b"".join(released_lines[item_id] for item_id in selected))
    by_id = {row["item_id"]: row for row in closures}
    gold_manifest = {}
    for index, item_id in enumerate(selected):
        basename = f"{index:03d}.json"
        gold_manifest[item_id] = basename
        sidecar = {key: by_id[item_id][key] for key in (
            "item_id", "files", "di_fragment", "context_classes",
            "feature_file", "scenario_line")}
        Path(original["release_gold"], basename).write_bytes(_canonical(sidecar))
    Path(original["release_gold"], "manifest.json").write_bytes(_canonical(gold_manifest))
    receipt = json.loads(Path(original["release_receipt"]).read_text())
    receipt["released_item_ids"] = [row["item_id"] for row in released_rows]
    Path(original["release_receipt"]).write_bytes(_canonical(receipt))

    # Freeze the production and feature sources before runtime pins or the
    # approved release inventory are derived. No gold answers enter the seed.
    boundary = load_boundary(original["boundary"], repo_root=prepared_workspace)
    strip_path = Path(original["gold"], "strip_manifest.json")
    strip = json.loads(strip_path.read_text())
    strip["substrate_roots"] = list(repo.CUCUMBER_SUBSTRATE_ROOTS)
    strip["digests"] = repo.substrate_digests(
        prepared_workspace, boundary, roots=repo.CUCUMBER_SUBSTRATE_ROOTS,
        volatile=frozenset())
    strip_path.write_bytes(_canonical(strip))
    rules = seed_module.CUCUMBER_RULES
    prepared_files = seed_module.workspace_files(prepared_workspace, rules)
    for relative in prepared_files:
        os.chmod(os.path.join(prepared_workspace, relative), 0o644)
    workspace = seed_module._tar_workspace(
        prepared_workspace, prepared_files,
        os.path.join(original["stripped_seed"], "workspace.tar"), rules.keep_empty)
    seed_path = Path(original["stripped_seed"], "seed.json")
    seed_doc = json.loads(seed_path.read_text())
    seed_doc.update(seed_module.seed_key(
        prepared_workspace, seed_module.NO_DATABASE, prepared_files, rules))
    seed_doc["workspace"].update(bytes=workspace["bytes"], n_files=workspace["n_files"],
                                 digest=workspace["digest"])
    seed_doc["workspace_seed_digest"] = workspace["digest"]
    seed_path.write_bytes(_canonical(seed_doc))
    release_root = inputs["evidence"]["release_root"]
    shutil.copyfile(original["released_items"], os.path.join(release_root, "items.jsonl"))
    shutil.copyfile(original["closures"], os.path.join(release_root, "control-artifacts", "closures.json"))
    shutil.copytree(original["gold"], os.path.join(release_root, "reference-gold"), dirs_exist_ok=True)
    shutil.copytree(original["release_gold"], os.path.join(release_root, "gold"), dirs_exist_ok=True)

    payload = os.path.join(root, "payload")
    os.mkdir(payload)
    roles = {}
    for role, old in {
        "map_release": "released_items", "release_items": "execution_release",
        "closures": "closures", "execution_view": "execution_view",
        "gold": "gold", "release_gold": "release_gold", "seed": "stripped_seed",
        "worker_plan": "worker_plan",
    }.items():
        roles[role] = (os.path.join(payload, "release", "gold")
                       if role == "release_gold" else os.path.join(payload, role))
        if os.path.isdir(original[old]):
            shutil.copytree(original[old], roles[role])
        else:
            shutil.copyfile(original[old], roles[role])
    for role, basename in (("profile", "profile_algorand.yml"),
                           ("boundary", "boundary_algorand.yml"),
                           ("protocol", "protocol.yml")):
        roles[role] = os.path.join(payload, basename)
        shutil.copyfile(original[role], roles[role])
    roles["provenance"] = os.path.join(payload, "provenance")
    os.mkdir(roles["provenance"])
    provenance = {key: os.path.join(roles["provenance"], name)
                  for key, name in EVALUATION_PROVENANCE.items()}
    composition = {
        "schema": compose_algorand.SCHEMA,
        "sources": compose_algorand._expected_sources(),
        "destination_tree_sha256": compose_algorand.EXPECTED_TREE_SHA256,
    }
    _write_json(provenance["composition"], composition)
    source, _raw = _read_json(os.path.join(root, "inputs", "source_approval"),
                              "fixture source approval")
    source["composition_manifest_sha256"] = _hash(provenance["composition"])
    source["composed_tree_sha256"] = compose_algorand.EXPECTED_TREE_SHA256
    source["digest"] = _document_digest(source)
    _write_json(provenance["source_approval"], source)
    receipt, _raw = _read_json(original["release_receipt"], "fixture receipt")
    release_manifest, tree = release_validation._release_file_manifest(
        inputs["evidence"]["release_root"])
    release_manifest.update(project=PROJECT, tree_sha256=tree,
                            released_item_ids=receipt["released_item_ids"])
    _write_json(provenance["release_manifest"], release_manifest)
    approval, _raw = _read_json(original["release_approval"], "fixture approval")
    approval_fields = dict(approval["approval"])
    approval_fields.update(release_manifest_sha256=_hash(provenance["release_manifest"]),
                           release_tree_sha256=tree)
    approval = research_minimal.phase_approval_document(
        research_minimal.Approval(**approval_fields))
    _write_json(provenance["release_approval"], approval)
    receipt.update(release_manifest_sha256=approval_fields["release_manifest_sha256"],
                   release_tree_sha256=tree, operator_approved_digest=approval["digest"])
    _write_json(provenance["release_receipt"], receipt)
    shutil.copyfile(roles["closures"], os.path.join(
        roles["provenance"], "reference-closures.json"))
    oci, _raw = _read_json(os.path.join(root, "inputs", "oci_image"), "fixture OCI")
    oci.update(source_approval_sha256=_hash(provenance["source_approval"]),
               release_receipt_sha256=_hash(provenance["release_receipt"]))
    oci["digest"] = _document_digest(oci)
    roles["oci_image"] = os.path.join(payload, "oci-image.json")
    _write_json(roles["oci_image"], oci)
    roles["gold_results_attestation"] = os.path.join(payload, "reference-controls.json")
    _write_json(roles["gold_results_attestation"], {
        "authority": {"container_image_digest": IMAGE_CONFIG_ID}})
    for role, raw in (("direct_call_agent", b"synthetic agent jar"),
                      ("production_index", b'{"schema":"r2t.java_prod_index/1"}')):
        roles[role] = os.path.join(payload, role)
        Path(roles[role]).write_bytes(raw)
    strip_path = os.path.join(roles["gold"], "strip_manifest.json")
    strip, _raw = _read_json(strip_path, "fixture strip manifest")
    seed_doc, _raw = _read_json(os.path.join(roles["seed"], "seed.json"), "fixture seed")
    from ..java import direct_calls
    pins = {
        "direct_call_agent_sha256": _hash(roles["direct_call_agent"]),
        "production_index_sha256": _hash(roles["production_index"]),
        "direct_call_agent_route": "read_only_mount",
        "direct_call_agent_runtime": direct_calls.AGENT_JAR_RUNTIME,
        "pom_sha256": strip["digests"]["pom.xml"],
        "substrate_baseline_sha256": hashlib.sha256(json.dumps(
            strip["digests"], sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "stripped_corpus_sha256": seed_doc["workspace_seed_digest"],
    }
    # Only the payload survives. The callback may not reopen producer paths
    # from the preserved approvals or strip/seed metadata.
    shutil.rmtree(os.path.join(root, "evidence"))
    shutil.rmtree(os.path.join(root, "inputs"))
    return roles, pins


def _evaluation_roles_selftest(check, refused) -> None:
    from unittest.mock import patch
    import builtins
    import yaml
    real_open = builtins.open

    def without_project_declaration(path, *args, **kwargs):
        if os.path.basename(os.fspath(path)) == "dataset_manifest.yml":
            raise AssertionError("V8 pins read the project's moving declaration")
        return real_open(path, *args, **kwargs)

    with patch("builtins.open", without_project_declaration):
        declared = _evaluation_runtime_pins()
    check("V8 Java inputs come from the V8 bundle declaration, not the project's current lineage",
          set(declared) == EVALUATION_JAVA_INPUT_KEYS
          and declared["direct_call_agent_route"] == "read_only_mount")
    with real_open(os.path.join(BENCHMARK, "config", "evaluation_bundles.yml"),
                   encoding="utf-8") as handle:
        declarations = yaml.safe_load(handle)
    declarations["projects"][PROJECT].pop("java_inputs")
    with patch("yaml.safe_load", return_value=declarations):
        check("a V8 declaration without its Java inputs refuses",
              refused(_evaluation_runtime_pins, "declares no exact V8 Java inputs"))
    with tempfile.TemporaryDirectory() as root:
        paths, pins = _fixture_evaluation_roles(root)
        producer = {"tag": "v1.0.0-fixture", "commit": "1" * 40}
        with patch(__name__ + "._evaluation_runtime_pins", return_value=pins):
            def validate():
                return validate_evaluation_roles(role_paths=paths, producer=producer)

            facts = validate()
            check("V8 native joins validate 111 execution items against the preserved 117 release",
                  facts["released_items"] == 117 and facts["execution_items"] == 111
                  and facts["config_image_id"] == IMAGE_CONFIG_ID)

            def changed(path, raw, wanted):
                before = Path(path).read_bytes()
                try:
                    Path(path).write_bytes(raw)
                    return refused(validate, wanted)
                finally:
                    Path(path).write_bytes(before)

            checks = (
                ("source approval", os.path.join(paths["provenance"], "source-approval.json"),
                 b"{}", "source approval"),
                ("composition", os.path.join(paths["provenance"], "composition-manifest.json"),
                 b"{}", "composition"),
                ("release inventory", os.path.join(paths["provenance"], "release-manifest.json"),
                 b"{}", "release manifest"),
                ("historical map release", paths["map_release"], b"{}\n", "approved release"),
                ("closure authority", paths["closures"], b"[]", "approved release"),
                ("reference closure bridge", os.path.join(paths["provenance"], "reference-closures.json"),
                 b"[]", "reference closures"),
                ("execution view", paths["execution_view"], b"{}", "execution view"),
                ("execution task bytes", paths["release_items"], b"{}\n", "111 selected"),
                ("gold oracle", os.path.join(paths["release_gold"], "manifest.json"),
                 b"{}", "release-gold manifest"),
                ("profile", paths["profile"], b"project: other\n", "bundled profile"),
                ("protocol", paths["protocol"], b"{}", "bundled protocol"),
                ("OCI", paths["oci_image"], b"{}", "OCI image reference"),
                ("runtime image", paths["gold_results_attestation"],
                 _canonical({"authority": {"container_image_digest": IMAGE_MANIFEST_DIGEST}}),
                 "OCI config image"),
                ("agent jar", paths["direct_call_agent"], b"different jar", "direct_call_agent"),
                ("production index", paths["production_index"], b"different index", "production_index"),
                ("runtime strip", os.path.join(paths["gold"], "strip_manifest.json"),
                 b'{"digests":{}}', "strip substrate"),
            )
            for label, path, raw, wanted in checks:
                check("V8 native joins refuse changed " + label, changed(path, raw, wanted))
            source = next(row["path"] for row in _tree_rows(paths["gold"], "gold")
                          if row["path"] != "strip_manifest.json")
            check("V8 gold code must retain the approved source bytes",
                  changed(_at(paths["gold"], source), b"// changed gold\n", "approved release"))
            extra = os.path.join(paths["gold"], "extra.java")
            Path(extra).write_text("// unapproved source\n")
            check("V8 rejects an extra gold source absent from the approved release",
                  refused(validate, "approved release"))
            os.unlink(extra)
            seed_path = os.path.join(paths["seed"], "seed.json")
            seed_doc, _raw = _read_json(seed_path, "fixture seed")
            seed_doc["workspace_seed_digest"] = "e" * 64
            check("V8 runtime seed identity stays bound to the declared Java inputs",
                  changed(seed_path, _canonical(seed_doc), "runtime seed"))
            seed_doc, _raw = _read_json(seed_path, "fixture seed")
            seed_doc["workspace"]["digest"] = "e" * 64
            check("V8 cannot retain the declared seed alias over a different verified archive",
                  changed(seed_path, _canonical(seed_doc), "runtime seed"))
            # The published v8 bundle was minted before checked-interfaces
            # v2 added the two retained `R2TStepTagListener` entries to the
            # reviewed boundary, so the boundary a consumer installs is the
            # reviewed file minus exactly that block.  The fixture copies the
            # reviewed file, which is why no fixture reaches the branch the
            # real archive takes unless the substitution is made here.
            def with_boundary(raw):
                before = Path(paths["boundary"]).read_bytes()
                try:
                    Path(paths["boundary"]).write_bytes(raw)
                    return validate()
                finally:
                    Path(paths["boundary"]).write_bytes(before)

            reviewed_boundary = Path(paths["boundary"]).read_bytes()
            reviewed_sha = hashlib.sha256(reviewed_boundary).hexdigest()
            published_boundary = reviewed_boundary.replace(
                DISCLOSED_BOUNDARY_DIFF, b"", 1)
            check("a bundle carrying today's reviewed boundary discloses no "
                  "difference",
                  facts["boundary_approval"] == {
                      "packaged_sha256": reviewed_sha,
                      "reviewed_sha256": reviewed_sha, "difference": None},
                  str(facts["boundary_approval"]))
            disclosed = with_boundary(published_boundary)
            check("V8 accepts the published bundle's boundary -- the reviewed "
                  "file minus the disclosed listener entries -- and records "
                  "the delta",
                  disclosed["boundary_approval"] == {
                      "packaged_sha256": hashlib.sha256(
                          published_boundary).hexdigest(),
                      "reviewed_sha256": reviewed_sha,
                      "difference": DISCLOSED_BOUNDARY_DIFF.decode()}
                  and {k: v for k, v in disclosed.items()
                       if k != "boundary_approval"}
                  == {k: v for k, v in facts.items()
                      if k != "boundary_approval"},
                  str(disclosed["boundary_approval"]))
            # Half the block is not the block, and a different retained
            # entry is not it either: both are line removals the byte check
            # would admit if it accepted "some lines missing".
            unit_listener = b"\n".join(
                DISCLOSED_BOUNDARY_DIFF.split(b"\n")[:2]) + b"\n"
            other_entry = (
                b"  - path: src/test/java/com/algorand/algosdk/unit/"
                b"RunCucumberUnitTest.java\n"
                b"    why: retained unit-suite runner; it contains no step "
                b"definitions\n")
            variants = [reviewed_boundary.replace(unit_listener, b"", 1),
                        reviewed_boundary.replace(other_entry, b"", 1),
                        reviewed_boundary + b"\n"]
            check("the accepted delta is that exact block and nothing else",
                  all(variant not in (reviewed_boundary, published_boundary)
                      and refused(lambda v=variant: with_boundary(v),
                                  "more than the disclosed")
                      for variant in variants))
            # Relocation changes every supplied location without changing a
            # single role's bytes or the preserved historical provenance.
            old = os.path.join(root, "payload")
            relocated = os.path.join(root, "relocated")
            os.rename(old, relocated)
            paths = {role: path.replace(old + os.sep, relocated + os.sep, 1)
                     for role, path in paths.items()}
            check("V8 native joins reopen after relocation without the producer tree",
                  validate() == facts)


def selftest() -> int:
    global GOLD_BASELINE_BYTE_LENGTH, GOLD_BASELINE_SHA256
    global GOLD_BASELINE_V5_BYTE_LENGTH, GOLD_BASELINE_V5_SHA256
    global V4_CONTROL_OBSERVATIONS, V4_EXECUTION_BINDING_DIGEST
    global V4_PAIR_SET_DIGEST, V4_ELIGIBILITY_SHA256
    global V4_CANDIDATE_RUN_SHA256
    global V4_CANDIDATE_GENERATED_TESTS_SHA256
    global V4_CANDIDATE_OBSERVATION_ID, V4_GENERATION_ATTEMPT_ID
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        ok = ok and bool(condition)
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))

    def refused(fn, text=""):
        try:
            fn()
        except AlgorandBundleRefused as exc:
            return not text or text in str(exc)
        return False

    def accepted(fn):
        try:
            fn()
        except AlgorandBundleRefused:
            return False
        return True

    _evaluation_entrypoints_selftest(check, refused)
    _evaluation_roles_selftest(check, refused)

    with tempfile.TemporaryDirectory() as root:
        descriptor = _fixture_inputs(root)
        fixture = _load_inputs(descriptor)
        v2_root = os.path.join(root, "v2-world")
        os.mkdir(v2_root)
        v2_descriptor = _fixture_inputs(v2_root, version="2")
        v2_fixture = _load_inputs(v2_descriptor, version="2")
        v3_root = os.path.join(root, "v3-world")
        os.mkdir(v3_root)
        v3_descriptor = _fixture_inputs(v3_root, version="3")
        v3_fixture = _load_inputs(v3_descriptor, version="3")
        v4_root = os.path.join(root, "v4-world")
        os.mkdir(v4_root)
        v4_descriptor = _fixture_inputs(v4_root, version="4")
        v4_fixture = _load_inputs(v4_descriptor, version="4")
        v5_root = os.path.join(root, "v5-world")
        os.mkdir(v5_root)
        v5_descriptor = _fixture_inputs(v5_root, version="5")
        v5_fixture = _load_inputs(v5_descriptor, version="5")
        check("bundle input schemas select exactly one version",
              refused(lambda: _load_inputs(v2_descriptor), "another schema")
              and refused(lambda: _load_inputs(
                  descriptor, version="2"), "another schema")
              and refused(lambda: _load_inputs(
                  v3_descriptor, version="2"))
              and refused(lambda: _load_inputs(
                  v2_descriptor, version="3"))
              and refused(lambda: _load_inputs(
                  v4_descriptor, version="3"))
              and refused(lambda: _load_inputs(
                  v3_descriptor, version="4"))
              and refused(lambda: _load_inputs(
                  v5_descriptor, version="4"))
              and refused(lambda: _load_inputs(
                  v4_descriptor, version="5")))
        check("v3 introduces the gold baseline inherited by v4 and v5",
              GOLD_BASELINE_ROLE not in _V1.roles
              and GOLD_BASELINE_ROLE not in layout("2").roles
              and layout("3").file_roles[GOLD_BASELINE_ROLE]
              == GOLD_BASELINE_PATH
              and v3_fixture[GOLD_BASELINE_ROLE]["role"]
              == GOLD_BASELINE_ROLE)
        v4 = layout("4")
        check("v4 inherits v3 and adds exactly five closed quality roles",
              v4.bundle_schema == "r2t.algorand-native-bundle/4"
              and v4.input_schema == "r2t.algorand-bundle-inputs/4"
              and v4.asset_name == "r2t-algorand-bundle-v4.tar.gz"
              and v4.bundle_root == "bundles/v4/algorand-sdk"
              and v4.roles - layout("3").roles == V4_ADDED_ROLES
              and len(v4.roles) == 24 and len(v4.input_roles) == 21
              and GOLD_BASELINE_ROLE in v4.roles
              and v4.file_roles[SCORED_MANIFEST_ROLE]
              == "bundles/v4/algorand-sdk/quality/scored-manifest.json"
              and v4.tree_roles[GOLD_RESULTS_ROLE] == (
                  "projects/algorand-sdk/artifacts/test-quality/gold-results",
                  "bundles/v4/algorand-sdk/trees/gold-results.json")
              and v4.file_roles[GOLD_RESULTS_ATTESTATION_ROLE]
              == ("projects/algorand-sdk/artifacts/test-quality/"
                  "six-gate-eligibility.json")
              and v4.file_roles[CANDIDATE_RUN_ROLE]
              == "projects/algorand-sdk/artifacts/runs/aider.merged.jsonl"
              and v4.tree_roles[CANDIDATE_RESULTS_ROLE] == (
                  "projects/algorand-sdk/artifacts/test-quality/"
                  "candidate-results",
                  "bundles/v4/algorand-sdk/trees/candidate-results.json"))
        v5 = layout("5")
        check("v5 inherits v3 and adds exactly three closed reference roles",
              v5.manifest_version == 5
              and v5.bundle_schema == "r2t.algorand-native-bundle/5"
              and v5.input_schema == "r2t.algorand-bundle-inputs/5"
              and v5.asset_name == "r2t-algorand-bundle-v5.tar.gz"
              and v5.release_index.endswith(
                  "benchmark/release/algorand_bundle_v5.json")
              and v5.bundle_root == "bundles/v5/algorand-sdk"
              and v5.roles - layout("3").roles == V5_ADDED_ROLES
              and len(v5.roles) == 22 and len(v5.input_roles) == 19
              and v5.file_roles[SCORED_MANIFEST_ROLE]
              == "bundles/v5/algorand-sdk/quality/scored-manifest.json"
              and v5.tree_roles[GOLD_RESULTS_ROLE] == (
                  "projects/algorand-sdk/artifacts/test-quality/gold-results",
                  "bundles/v5/algorand-sdk/trees/gold-results.json")
              and v5.file_roles[GOLD_RESULTS_ATTESTATION_ROLE]
              == ("projects/algorand-sdk/artifacts/test-quality/"
                  "six-gate-eligibility.json")
              and not ({CANDIDATE_RUN_ROLE, CANDIDATE_RESULTS_ROLE}
                       & v5.roles)
              and v4.roles - v5.roles
              == {CANDIDATE_RUN_ROLE, CANDIDATE_RESULTS_ROLE})
        fixture_wrapper, _raw = _read_json(
            v4_fixture["roles"][SCORED_MANIFEST_ROLE],
            "fixture v4 scored manifest")
        fixture_binding = fixture_wrapper["mutation_execution_binding"]
        fixture_project_binding = fixture_binding["projects"][PROJECT]
        fixture_candidate_rows, fixture_candidate_raw, _lines = _jsonl(
            v4_fixture["roles"][CANDIDATE_RUN_ROLE],
            "fixture v4 candidate run")
        from ..bench import mutation_run as fixture_mutation_run
        fixture_generated_sha256 = fixture_mutation_run.candidate_digest({
            row["item_id"]: row["produced_files"]
            for row in fixture_candidate_rows})
        _fixture_candidate_shard, fixture_candidate_sidecar = \
            _v4_quality_shard(os.path.join(
                v4_fixture["roles"][CANDIDATE_RESULTS_ROLE],
                "candidate_run1_aider"), "fixture v4 candidate")
        fixture_attestation_raw = Path(
            v4_fixture["roles"][GOLD_RESULTS_ATTESTATION_ROLE]).read_bytes()
        fixture_v4_pins = {
            "controls": {
                row["role"]: row["observation_id"]
                for row in fixture_project_binding["control_observations"]
            },
            "binding": fixture_binding["digest"],
            "pairs": fixture_project_binding["pair_set_digest"],
            "eligibility": hashlib.sha256(
                fixture_attestation_raw).hexdigest(),
            "run": hashlib.sha256(fixture_candidate_raw).hexdigest(),
            "generated": fixture_generated_sha256,
            "candidate_observation": fixture_candidate_sidecar[
                "observation_id"],
            "attempt": fixture_candidate_sidecar["campaign_identity"][
                "generation_attempt_id"],
        }
        production_v4_pins = {
            "controls": dict(V4_CONTROL_OBSERVATIONS),
            "binding": V4_EXECUTION_BINDING_DIGEST,
            "pairs": V4_PAIR_SET_DIGEST,
            "eligibility": V4_ELIGIBILITY_SHA256,
            "run": V4_CANDIDATE_RUN_SHA256,
            "generated": V4_CANDIDATE_GENERATED_TESTS_SHA256,
            "candidate_observation": V4_CANDIDATE_OBSERVATION_ID,
            "attempt": V4_GENERATION_ATTEMPT_ID,
        }
        check("synthetic v4 evidence exercises production shapes without "
              "impersonating production bytes",
              len(fixture_project_binding["ordered_pairs"]) == 69
              and fixture_v4_pins["binding"] \
              != production_v4_pins["binding"]
              and fixture_v4_pins["eligibility"] \
              != production_v4_pins["eligibility"]
              and fixture_v4_pins["run"] != production_v4_pins["run"])
        v5_wrapper, _raw = _read_json(
            v5_fixture["roles"][SCORED_MANIFEST_ROLE],
            "fixture v5 scored manifest")
        fixture_v5_attestation_raw = Path(
            v5_fixture["roles"][
                GOLD_RESULTS_ATTESTATION_ROLE]).read_bytes()
        fixture_v4_reference_semantics = json.loads(
            json.dumps(fixture_wrapper))
        fixture_v5_reference_semantics = json.loads(
            json.dumps(v5_wrapper))
        for reference_semantics in (
                fixture_v4_reference_semantics,
                fixture_v5_reference_semantics):
            reference_binding = reference_semantics[
                "mutation_execution_binding"]
            reference_binding.pop("digest")
            reference_binding["projects"][PROJECT].pop(
                "mutant_manifest_digest")
        fixture_v4_sidecars = {}
        fixture_v5_sidecars = {}
        for role in V4_CONTROL_OBSERVATIONS:
            fixture_v4_sidecars[role] = _read_json(os.path.join(
                v4_fixture["roles"][GOLD_RESULTS_ROLE], role,
                "gold.w0.jsonl.provenance.json"),
                f"fixture v4 {role} provenance")[0]
            fixture_v5_sidecars[role] = _read_json(os.path.join(
                v5_fixture["roles"][GOLD_RESULTS_ROLE], role,
                "gold.w0.jsonl.provenance.json"),
                f"fixture v5 {role} provenance")[0]
        fixture_v4_release_raw = Path(
            v4_fixture["roles"]["execution_release"]).read_bytes()
        fixture_v5_release_rows, fixture_v5_release_raw, _lines = _jsonl(
            v5_fixture["roles"]["execution_release"],
            "fixture v5 execution release")
        fixture_v5_release_projection = \
            _historical_slice3_release_projection(fixture_v5_release_rows)
        fixture_v4_raw_sha256 = hashlib.sha256(
            fixture_v4_release_raw).hexdigest()
        fixture_v5_raw_sha256 = hashlib.sha256(
            fixture_v5_release_raw).hexdigest()
        fixture_v5_projection_sha256 = hashlib.sha256(
            fixture_v5_release_projection).hexdigest()
        projected_v5_rows = [
            json.loads(line)
            for line in fixture_v5_release_projection.splitlines()]
        fixture_producer_members = {"run", "manifest", "release"}
        check("noncanonical v5 raw release and historical projection differ "
              "without changing parsed objects or order",
              fixture_v5_release_raw != fixture_v5_release_projection
              and fixture_v5_raw_sha256 != fixture_v5_projection_sha256
              and fixture_v5_release_rows == projected_v5_rows)
        check("v4 sidecars retain the raw bridge while v5 sidecars bind the "
              "historical projection",
              all(sidecar["campaign_identity"]["release_sha256"]
                  == fixture_v4_raw_sha256
                  for sidecar in fixture_v4_sidecars.values())
              and all(sidecar["campaign_identity"]["release_sha256"]
                      == fixture_v5_projection_sha256
                      for sidecar in fixture_v5_sidecars.values()))
        check("v5 fixture sidecars contain every required member plus "
              "representative producer provenance",
              all(_QUALITY_SHARD_REQUIRED_MEMBERS <= set(sidecar)
                  and fixture_producer_members <= set(sidecar)
                  and _QUALITY_SHARD_REQUIRED_MEMBERS < set(sidecar)
                  for sidecar in fixture_v5_sidecars.values()))
        def fixture_observation_rows(path: str) -> list[dict]:
            return [
                {key: row[key]
                 for key in ("item_id", "mutant_id", "outcome")}
                for row in (json.loads(line)
                            for line in Path(path).read_bytes().splitlines())]

        check("v5 reuses the synthetic V4 reference semantics with its "
              "version-specific bridge and without candidate bytes",
              fixture_v5_reference_semantics
              == fixture_v4_reference_semantics
              and fixture_v5_attestation_raw == fixture_attestation_raw
              and all(fixture_observation_rows(os.path.join(
                  v5_fixture["roles"][GOLD_RESULTS_ROLE], role,
                  "gold.w0.jsonl"))
                  == fixture_observation_rows(os.path.join(
                      v4_fixture["roles"][GOLD_RESULTS_ROLE], role,
                      "gold.w0.jsonl"))
                  for role in V4_CONTROL_OBSERVATIONS)
              and v5_wrapper["mutation_execution_binding"][
                  "candidate_policy"]["arms"] == ["aider", "openhands"]
              and CANDIDATE_RUN_ROLE not in v5_fixture["roles"]
              and CANDIDATE_RESULTS_ROLE not in v5_fixture["roles"])
        saved_v4_descriptor = Path(v4_descriptor).read_bytes()
        missing_v4 = json.loads(saved_v4_descriptor)
        missing_v4["roles"].pop(GOLD_RESULTS_ROLE)
        Path(v4_descriptor).write_bytes(_canonical(missing_v4))
        missing_v4_named = refused(
            lambda: _load_inputs(v4_descriptor, version="4"),
            GOLD_RESULTS_ROLE)
        Path(v4_descriptor).write_bytes(saved_v4_descriptor)
        extra_v4 = json.loads(saved_v4_descriptor)
        extra_v4["roles"]["quality_alias"] = extra_v4["roles"][
            SCORED_MANIFEST_ROLE]
        Path(v4_descriptor).write_bytes(_canonical(extra_v4))
        extra_v4_named = refused(
            lambda: _load_inputs(v4_descriptor, version="4"),
            "quality_alias")
        Path(v4_descriptor).write_bytes(saved_v4_descriptor)
        overlap_v4 = json.loads(saved_v4_descriptor)
        overlap_v4["roles"][CANDIDATE_RESULTS_ROLE] = \
            overlap_v4["roles"][GOLD_RESULTS_ROLE]
        Path(v4_descriptor).write_bytes(_canonical(overlap_v4))
        overlap_v4_refused = refused(
            lambda: _load_inputs(v4_descriptor, version="4"), "overlap")
        Path(v4_descriptor).write_bytes(saved_v4_descriptor)
        hardlink_alias = os.path.join(v4_root, "hardlink-role-alias.json")
        os.link(v4_fixture["roles"][GOLD_RESULTS_ATTESTATION_ROLE],
                hardlink_alias)
        alias_v4 = json.loads(saved_v4_descriptor)
        alias_v4["roles"][CANDIDATE_RUN_ROLE] = hardlink_alias
        Path(v4_descriptor).write_bytes(_canonical(alias_v4))
        alias_v4_refused = refused(
            lambda: _load_inputs(v4_descriptor, version="4"), "overlap")
        Path(v4_descriptor).write_bytes(saved_v4_descriptor)
        os.unlink(hardlink_alias)
        check("v4 inputs name missing generic roles and reject overlap or "
              "physical alias",
              missing_v4_named and extra_v4_named
              and overlap_v4_refused and alias_v4_refused)
        saved_v5_descriptor = Path(v5_descriptor).read_bytes()
        candidate_v5 = json.loads(saved_v5_descriptor)
        candidate_v5["roles"].update({
            CANDIDATE_RUN_ROLE:
                v4_fixture["roles"][CANDIDATE_RUN_ROLE],
            CANDIDATE_RESULTS_ROLE:
                v4_fixture["roles"][CANDIDATE_RESULTS_ROLE],
        })
        Path(v5_descriptor).write_bytes(_canonical(candidate_v5))
        candidate_v5_refused = refused(
            lambda: _load_inputs(v5_descriptor, version="5"))
        alias_v5 = json.loads(saved_v5_descriptor)
        alias_v5["roles"]["quality_alias"] = alias_v5["roles"][
            SCORED_MANIFEST_ROLE]
        Path(v5_descriptor).write_bytes(_canonical(alias_v5))
        named_alias_v5_refused = refused(
            lambda: _load_inputs(v5_descriptor, version="5"))
        null_v5 = json.loads(saved_v5_descriptor)
        null_v5["roles"][GOLD_RESULTS_ATTESTATION_ROLE] = None
        Path(v5_descriptor).write_bytes(_canonical(null_v5))
        null_v5_refused = refused(
            lambda: _load_inputs(v5_descriptor, version="5"))
        physical_alias_v5 = json.loads(saved_v5_descriptor)
        physical_alias_v5["roles"][GOLD_RESULTS_ATTESTATION_ROLE] = \
            physical_alias_v5["roles"][SCORED_MANIFEST_ROLE]
        Path(v5_descriptor).write_bytes(_canonical(physical_alias_v5))
        physical_alias_v5_refused = refused(
            lambda: _load_inputs(v5_descriptor, version="5"), "overlap")
        Path(v5_descriptor).write_bytes(saved_v5_descriptor)
        check("v5 inputs exclude candidate roles, aliases, and null "
              "placeholders",
              candidate_v5_refused and named_alias_v5_refused
              and null_v5_refused and physical_alias_v5_refused)
        historical_path = v3_fixture["roles"][GOLD_BASELINE_ROLE]
        historical_rows, historical_raw, _lines = _jsonl(
            historical_path, "fixture historical baseline")
        v5_production_path = os.path.join(root, "v5-production-baseline.jsonl")
        v5_production_rows = [dict(row) for row in historical_rows]
        v5_production_rows[0]["generation_seconds"] = 0.0
        Path(v5_production_path).write_bytes(
            b"".join(_canonical(row) for row in v5_production_rows))
        historical_production = _gold_baseline_provenance(
            historical_path,
            collection_harness_commit=GOLD_BASELINE_COLLECTION_COMMIT,
            source_bundle_manifest_sha256=
            GOLD_BASELINE_SOURCE_MANIFEST_SHA256)
        v5_production = _gold_baseline_provenance(
            v5_production_path,
            collection_harness_commit=GOLD_BASELINE_COLLECTION_COMMIT,
            source_bundle_manifest_sha256=
            GOLD_BASELINE_SOURCE_MANIFEST_SHA256)
        saved_baseline_pins = (
            GOLD_BASELINE_BYTE_LENGTH, GOLD_BASELINE_SHA256,
            GOLD_BASELINE_V5_BYTE_LENGTH, GOLD_BASELINE_V5_SHA256)
        try:
            GOLD_BASELINE_BYTE_LENGTH = len(historical_raw)
            GOLD_BASELINE_SHA256 = hashlib.sha256(
                historical_raw).hexdigest()
            v5_production_raw = Path(v5_production_path).read_bytes()
            GOLD_BASELINE_V5_BYTE_LENGTH = len(v5_production_raw)
            GOLD_BASELINE_V5_SHA256 = hashlib.sha256(
                v5_production_raw).hexdigest()
            check("production baseline admission selects one identity per "
                  "bundle version",
                  accepted(lambda: _validate_gold_baseline_provenance(
                      historical_production, historical_path, version="3"))
                  and accepted(lambda: _validate_gold_baseline_provenance(
                      historical_production, historical_path, version="4"))
                  and accepted(lambda: _validate_gold_baseline_provenance(
                      v5_production, v5_production_path, version="5"))
                  and refused(lambda: _validate_gold_baseline_provenance(
                      v5_production, v5_production_path, version="3"),
                      "approved production bytes")
                  and refused(lambda: _validate_gold_baseline_provenance(
                      v5_production, v5_production_path, version="4"),
                      "approved production bytes")
                  and refused(lambda: _validate_gold_baseline_provenance(
                      historical_production, historical_path, version="5"),
                      "approved production bytes"))
            ordered_ids = [row["item_id"] for row in historical_rows]
            check("gold-baseline semantic admission carries the selected "
                  "version",
                  accepted(lambda: _gold_baseline(
                      historical_path, ordered_ids, historical_production,
                      version="4"))
                  and accepted(lambda: _gold_baseline(
                      v5_production_path, ordered_ids, v5_production,
                      version="5"))
                  and refused(lambda: _gold_baseline(
                      v5_production_path, ordered_ids, v5_production,
                      version="4"), "approved production bytes"))
            check("nonproduction baselines still validate against their own "
                  "fixture bytes",
                  accepted(lambda: _validate_gold_baseline_provenance(
                      v3_fixture[GOLD_BASELINE_ROLE], historical_path,
                      version="3"))
                  and accepted(lambda: _validate_gold_baseline_provenance(
                      v5_fixture[GOLD_BASELINE_ROLE],
                      v5_fixture["roles"][GOLD_BASELINE_ROLE], version="5")))
        finally:
            (GOLD_BASELINE_BYTE_LENGTH, GOLD_BASELINE_SHA256,
             GOLD_BASELINE_V5_BYTE_LENGTH, GOLD_BASELINE_V5_SHA256) = \
                saved_baseline_pins
        check("historical v3/v4 and measured v5 production pins are exact",
              GOLD_BASELINE_SHA256
              == "368ff973620328d52f500efbb1521cc8b040d7eaa29f269c499b44655e0e1683"
              and GOLD_BASELINE_BYTE_LENGTH == 3530953
              and GOLD_BASELINE_V5_SHA256
              == "6652c9eb5c9157f1b845d47c64669653889b4ccae8a5758d6eccbff20a4a4ce0"
              and GOLD_BASELINE_V5_BYTE_LENGTH == 3530937)
        from ..core import reviewed_git
        original_repository_root = reviewed_git.repository_root
        original_git_run = reviewed_git.run
        git_dirty = {"value": False}
        def fixture_git(_repository, args):
            commit = fixture["producer"]["repository_commit"]
            if args == ("symbolic-ref", "--quiet", "HEAD"):
                return type("GitResult", (), {
                    "returncode": 1, "stdout": b"", "stderr": b""})()
            if args == ("status", "--porcelain=v1", "--untracked-files=all"):
                stdout = b" M benchmark/r2t/toolkit/algorand_bundle.py\n" \
                    if git_dirty["value"] else b""
            elif args[0] == "rev-parse":
                stdout = (commit + "\n").encode()
            else:
                stdout = b""
            return type("GitResult", (), {
                "returncode": 0, "stdout": stdout, "stderr": b""})()
        reviewed_git.repository_root = lambda: "/fixture/repository"
        reviewed_git.run = fixture_git
        try:
            producer_valid = True
            try:
                _validate_producer(fixture["producer"])
            except AlgorandBundleRefused:
                producer_valid = False
            git_dirty["value"] = True
            producer_dirty_refused = refused(
                lambda: _validate_producer(fixture["producer"]),
                "not clean and detached")
        finally:
            reviewed_git.repository_root = original_repository_root
            reviewed_git.run = original_git_run
        check("producer is the declared clean detached exact tag",
              producer_valid and producer_dirty_refused)

        roles = dict(fixture["roles"])
        roles.update({
            role: os.path.join(root, "inputs", role)
            for role in DERIVED_FILE_ROLES
        })
        evidence = fixture["evidence"]
        source, _raw = _read_json(roles["source_approval"],
                                  "fixture source approval")
        transcript, _raw = _read_json(
            os.path.join(os.path.dirname(evidence["release_root"]),
                         "transcript.json"), "fixture validation transcript")
        authority_root = os.path.join(
            evidence["release_root"], "control-artifacts",
            "java-mutation-authority")
        canonical, _raw = _read_json(
            os.path.join(authority_root, "canonical-transcript.json"),
            "fixture canonical transcript")
        reality, _raw = _read_json(
            os.path.join(authority_root, "reality-transcript.json"),
            "fixture reality transcript")
        validation = type("FixtureValidation", (), {
            "execution_identity": transcript["execution_identity"],
            "source_manifest_sha256": transcript["inputs"][
                "source_manifest_sha256"],
            "preparation_manifest_sha256": transcript["inputs"][
                "preparation_manifest_sha256"],
            "predecessor_transcript_sha256": transcript["inputs"][
                "reality_transcript_sha256"],
            "reality_manifest_sha256": transcript["inputs"][
                "reality_manifest_sha256"],
            "census_sha256": transcript["inputs"]["census_sha256"],
            "closures_sha256": transcript["inputs"]["closures_sha256"],
            "quality_sha256": transcript["inputs"]["quality_sha256"],
            "boundary_sha256": _hash(roles["boundary"]),
            # The approval predates the packaged profile bytes by the one
            # disclosed line, so it names the recorded approved digest.
            "profile_sha256": APPROVED_PROFILE_SHA256,
            "image_id": canonical["result"]["candidate_image_id"],
            "base_digest": canonical["base"]["repository_digest"],
            "base_config_id": canonical["base"]["config_id"],
            "m2_manifest_sha256": canonical["result"]["m2_manifest_sha256"],
            "m2_tree_sha256": canonical["result"]["m2_tree_sha256"],
            "authority_reference": canonical["authority"]["reference"],
            "daemon_fingerprint": canonical["authority"][
                "daemon_fingerprint"],
        })()
        from ..java import j0, research_minimal
        from ..bench import seed as seed_module
        from . import mutation_java
        from ..data import mutation_attestation as attestation
        originals = {
            "source": j0.build_source_archive_manifest,
            "snapshot": research_minimal._authenticate_source,
            "validation": research_minimal.require_source_approval,
            "preparation": research_minimal._validate_preparation,
            "release": mutation_java.validate_population_release,
            "mutation": attestation.validate_campaign_asset_inputs,
        }
        released_rows, released_raw, _lines = _jsonl(
            roles["released_items"], "fixture released items")
        receipt, _raw = _read_json(roles["release_receipt"],
                                   "fixture release receipt")
        mutation_manifest, _raw = _read_json(
            roles["mutation_manifest"], "fixture mutation manifest")
        publication_path = evidence["oci_publication_receipt"]
        publication, publication_raw = _read_json(
            publication_path, "fixture OCI publication record")
        snapshot = type("FixtureSnapshot", (), {
            "identity": canonical["source"],
        })()
        prepared = type("FixturePreparation", (), {
            "workspace": os.path.join(
                os.path.dirname(evidence["preparation_manifest"]),
                "workspace"),
            "gold": os.path.join(
                os.path.dirname(evidence["preparation_manifest"]), "gold"),
        })()
        validation.strip_manifest_sha256 = _hash(os.path.join(
            prepared.gold, "strip_manifest.json"))
        validation.gold_tree_sha256 = research_minimal._tree_identity(
            research_minimal._tree_files(prepared.gold))["tree_sha256"]

        def source_manifest(project, _root):
            return {"archive_tree_sha256":
                    SDK_TREE if project == PROJECT else TESTING_TREE}

        def release_facts(release_root, *_args, **_kwargs):
            items_path = os.path.join(release_root, "items.jsonl")
            current_rows, current_raw, _current_lines = _jsonl(
                items_path, "fixture approved released items")
            return {
                "root": release_root,
                "manifest_path": os.path.join(
                    os.path.dirname(release_root),
                    "release-manifest.json"),
                "items_path": items_path,
                "released_item_ids": {
                    row["item_id"] for row in current_rows},
                "item_rows": current_rows,
                "items_sha256": hashlib.sha256(current_raw).hexdigest(),
                "closures_sha256": _hash(os.path.join(
                    release_root, "control-artifacts", "closures.json")),
                "manifest_sha256": receipt["release_manifest_sha256"],
                "tree_sha256": receipt["release_tree_sha256"],
            }

        def mutation_facts(*_args, **_kwargs):
            return {
                "validation_class": "native",
                "validation_sha256": _hash(
                    evidence["mutation_validation_report"]),
                "asset_project": PROJECT, "release_items": 117,
                "manifest": mutation_manifest,
                "map": _read_json(roles["mutation_map"],
                                  "fixture mutation map")[0],
            }

        j0.build_source_archive_manifest = source_manifest
        research_minimal._authenticate_source = lambda *_args, **_kwargs: snapshot
        research_minimal.require_source_approval = (
            lambda *_args, **_kwargs: validation)
        research_minimal._validate_preparation = (
            lambda *_args, **_kwargs: prepared)
        mutation_java.validate_population_release = release_facts
        attestation.validate_campaign_asset_inputs = mutation_facts
        try:
            evidence_valid = True
            try:
                _validate_build_evidence(fixture, selected=_V1)
            except AlgorandBundleRefused:
                evidence_valid = False
            check("approved source/release/mutation/OCI evidence joins",
                  evidence_valid)

            v2_evidence_valid = True
            try:
                _validate_build_evidence(v2_fixture, selected=layout("2"))
            except AlgorandBundleRefused:
                v2_evidence_valid = False
            check("approved evidence also joins the selected v2 repository",
                  v2_evidence_valid)
            v3_evidence_valid = True
            try:
                _validate_build_evidence(v3_fixture, selected=layout("3"))
            except AlgorandBundleRefused:
                v3_evidence_valid = False
            check("v3 retains the approved v2 image evidence",
                  v3_evidence_valid)
            v4_evidence_valid = True
            try:
                _validate_build_evidence(v4_fixture, selected=layout("4"))
            except AlgorandBundleRefused:
                v4_evidence_valid = False
            check("v4 inherits the approved v3 source and image evidence",
                  v4_evidence_valid)
            v2_publication_path = v2_fixture["evidence"][
                "oci_publication_receipt"]
            v2_publication_raw = Path(v2_publication_path).read_bytes()
            v2_publication, _raw = _read_json(
                v2_publication_path, "fixture v2 OCI publication record")
            v2_publication["repository"] = _V1.image_repository
            os.unlink(v2_publication_path)
            _write_json(v2_publication_path, v2_publication)
            check("v2 publication rejects the organization repository",
                  refused(lambda: _validate_build_evidence(
                      v2_fixture, selected=layout("2")),
                      "selected bundle repository"))
            os.unlink(v2_publication_path)
            Path(v2_publication_path).write_bytes(v2_publication_raw)

            wrong_validation = type("WrongValidation", (), {})()
            for name, value in validation.__class__.__dict__.items():
                if not name.startswith("__"):
                    setattr(wrong_validation, name, value)
            wrong_validation.execution_identity = "another-validation"
            research_minimal.require_source_approval = (
                lambda *_args, **_kwargs: wrong_validation)
            check("validation transcript refuses another approved identity",
                  refused(lambda: _validate_build_evidence(
                      fixture, selected=_V1),
                          "validation transcript"))
            research_minimal.require_source_approval = (
                lambda *_args, **_kwargs: validation)

            saved_gold_identity = validation.gold_tree_sha256
            validation.gold_tree_sha256 = "9" * 64
            check("validation approval must name the prepared gold tree",
                  refused(lambda: _validate_build_evidence(
                      fixture, selected=_V1),
                          "packaged source/config"))
            validation.gold_tree_sha256 = saved_gold_identity

            report_path = evidence["mutation_validation_report"]
            saved_report = Path(report_path).read_bytes()
            wrong_boundary = json.loads(saved_report)
            wrong_boundary["inputs"]["boundary"]["sha256"] = "9" * 64
            Path(report_path).write_bytes(_canonical(wrong_boundary))
            check("full mutation evidence must name the packaged boundary",
                  refused(lambda: _validate_build_evidence(
                      fixture, selected=_V1),
                          "another boundary"))
            Path(report_path).write_bytes(saved_report)

            saved_profile_sha = validation.profile_sha256
            validation.profile_sha256 = _hash(roles["profile"])
            check("validation approval must name the approved profile digest",
                  refused(lambda: _validate_build_evidence(
                      fixture, selected=_V1),
                          "recorded approved profile digest"))
            validation.profile_sha256 = saved_profile_sha

            def republish(**changes):
                record = {**publication, **changes}
                os.unlink(publication_path)
                _write_json(publication_path, record)

            republish(repository=(
                "ghcr.io/qibinhang/r2t-java-algorand-sdk"))
            check("v1 publication stays on the organization repository",
                  refused(lambda: _validate_build_evidence(
                      fixture, selected=_V1),
                          "selected bundle repository"))
            republish(manifest_digest="sha256:" + "e" * 64)
            check("publication record must carry the recorded image identity",
                  refused(lambda: _validate_build_evidence(
                      fixture, selected=_V1),
                          "publication evidence"))
            republish(config_image_id=publication["manifest_digest"])
            check("publication record refuses one digest as both identities",
                  refused(lambda: _validate_build_evidence(
                      fixture, selected=_V1),
                          "aliases"))
            os.unlink(publication_path)
            _write_json(publication_path, {
                "schema": PUBLICATION_SCHEMA, "path": IMAGE_PATH,
                "project": PROJECT, "platform": "linux/amd64",
                "distribution_mode": "oci_archive",
                "asset_name": "algorand.oci.tar",
                "object_sha256": "a" * 64,
                "manifest_digest": publication["manifest_digest"],
                "config_image_id": publication["config_image_id"]})
            check("an archive-mode publication receipt no longer satisfies it",
                  refused(lambda: _validate_build_evidence(
                      fixture, selected=_V1),
                          "closed schema"))
            os.unlink(publication_path)
            Path(publication_path).write_bytes(publication_raw)

            seed_path = os.path.join(roles["stripped_seed"], "workspace.tar")
            seed_manifest_path = os.path.join(
                roles["stripped_seed"], "seed.json")
            saved_seed = Path(seed_path).read_bytes()
            saved_seed_manifest = Path(seed_manifest_path).read_bytes()
            alternate_workspace = os.path.join(root, "alternate-workspace")
            os.mkdir(alternate_workspace)
            Path(alternate_workspace, "pom.xml").write_text(
                "<different/>\n", encoding="utf-8")
            seed_module._tar_workspace(
                alternate_workspace, ["pom.xml"], seed_path,
                seed_module.CUCUMBER_RULES.keep_empty)
            altered_seed = json.loads(saved_seed_manifest)
            altered_seed["workspace"]["bytes"] = os.path.getsize(seed_path)
            altered_seed["workspace"]["digest"] = _hash(seed_path)
            altered_seed["workspace_seed_digest"] = _hash(seed_path)
            Path(seed_manifest_path).write_text(
                json.dumps(altered_seed, indent=1, sort_keys=True),
                encoding="utf-8")
            check("a re-signed seed from another workspace refuses",
                  refused(lambda: _validate_build_evidence(
                      fixture, selected=_V1),
                          "does not derive from approved preparation"))
            Path(seed_path).write_bytes(saved_seed)
            Path(seed_manifest_path).write_bytes(saved_seed_manifest)
        finally:
            j0.build_source_archive_manifest = originals["source"]
            research_minimal._authenticate_source = originals["snapshot"]
            research_minimal.require_source_approval = originals["validation"]
            research_minimal._validate_preparation = originals["preparation"]
            mutation_java.validate_population_release = originals["release"]
            attestation.validate_campaign_asset_inputs = originals["mutation"]

        out_a_dir = os.path.join(root, "a")
        out_b_dir = os.path.join(root, "b")
        os.mkdir(out_a_dir)
        os.mkdir(out_b_dir)
        out_a = os.path.join(out_a_dir, ASSET_NAME)
        out_b = os.path.join(out_b_dir, ASSET_NAME)
        evidence_calls = []
        producer_calls = []
        real_evidence_validator = globals()["_validate_build_evidence"]
        real_producer_validator = globals()["_validate_producer"]
        def fixture_evidence(current, *, selected):
            evidence_calls.append(current)
            projection, _raw = _read_json(
                roles["mutation_validation"],
                "fixture mutation projection")
            projection["packaged"] = {
                "manifest_sha256": _hash(current["roles"][
                    "mutation_manifest"]),
                "map_sha256": _hash(current["roles"]["mutation_map"]),
                "released_items_sha256": _hash(current["roles"][
                    "released_items"]),
                "boundary_sha256": _hash(current["roles"]["boundary"]),
            }
            projection["digest"] = _document_digest(projection)
            fixture_input_root = os.path.dirname(
                current["roles"]["worker_plan"])
            image, _raw = _read_json(
                os.path.join(fixture_input_root, "oci_image"),
                "fixture OCI image reference")
            if selected.version in {"2", "3", "4", "5"}:
                image["repository"] = selected.image_repository
                image["publication_receipt_sha256"] = _hash(
                    current["evidence"]["oci_publication_receipt"])
                image["digest"] = "0" * 64
                image["digest"] = _document_digest(image)
            return {"source_approval": source,
                    "mutation_validation": projection,
                    "oci_image": image}
        globals()["_validate_build_evidence"] = fixture_evidence
        globals()["_validate_producer"] = producer_calls.append
        first = build_bundle(inputs_path=descriptor, out=out_a)
        second = build_bundle(inputs_path=descriptor, out=out_b)
        check("native Algorand bundle build is byte-identical",
              first["asset_sha256"] == second["asset_sha256"]
              and Path(out_a).read_bytes() == Path(out_b).read_bytes())
        # RESTORED, and not to be "corrected" again without reproducing
        # first.  `cf40200` replaced this pin and the v2 pin below with
        # values no checkout of this tree produces.  Both `4f94aac` (the
        # commit that introduced them) and `30a8fcd` build these exact
        # bytes under CPython 3.10, repeated builds are byte-identical,
        # and two TMPDIRs agree; the 3.12 run reported in PR #161 also
        # rejected `cf40200`'s values.
        #
        # WHAT THIS DIGEST DEPENDS ON.  `_fixture_inputs` synthesizes most of
        # the input world in a tempdir, but it also COPIES three tracked
        # files into the archive: `config/boundary_algorand.yml`,
        # `config/profile_algorand.yml` and `protocol/protocol_v8.yml`.  No
        # external or Git-LFS artifact is consumed, so a checkout with LFS
        # pointers cannot move this value -- but an edit to any of those
        # three legitimately can.  A future mismatch is therefore a real
        # change to the archive or to one of those inputs; find which before
        # touching the constant.
        #
        # Moved once, on purpose: `config/boundary_algorand.yml` gained the
        # two `R2TStepTagListener` retained entries beside the two runners it
        # already retained (TARGET_INTERFACES_V2_SPEC section 4).  Checked by
        # restoring the previous boundary bytes with every other change of
        # that commit in place, which reproduces
        # 5cca2c6a338af03c308d4242586a29525518ff10e292b1dde8bab02c49b204e8
        # and d4026107ad7a8caec43632ca52698bd08126e9af75ae566e4f73fbf7108eef0c.
        check("v1 synthetic archive bytes remain unchanged",
              first["asset_sha256"]
              == "8d0878178e7cce058c3685561e21cc831286e2763e142b0265a76c1302b8c2c6",
              first["asset_sha256"])
        check("native bundle rederives the fixed 117/111 population",
              first["released_items"] == 117
              and first["execution_items"] == 111
              and len(evidence_calls) == 2 and len(producer_calls) == 2)
        # A frozen archive digest has to be a fact about this tree, not about
        # the operator's shell.  `_write_archive` normalises its own member
        # modes, but the fixture's stripped seed embeds a NESTED tar whose
        # member modes are the staged files' real modes, so before
        # `_fixture_inputs` normalised them the pin above held only under
        # umask 022 and failed under umask 002 with no reachable explanation.
        # That signature has been misread as a host-dependent discrepancy more
        # than once.  Rebuild the whole fixture world under each umask and
        # require one answer; `first` was built under whatever the operator
        # runs with, so agreeing with both covers either ambient value.
        umask_digests = []
        saved_umask = os.umask(0o022)
        try:
            for index, mask in enumerate((0o002, 0o022)):
                os.umask(mask)
                umask_root = os.path.join(root, f"umask-{index}")
                os.mkdir(umask_root)
                umask_out_dir = os.path.join(umask_root, "out")
                os.mkdir(umask_out_dir)
                umask_digests.append(build_bundle(
                    inputs_path=_fixture_inputs(umask_root),
                    out=os.path.join(umask_out_dir, ASSET_NAME))[
                        "asset_sha256"])
        finally:
            os.umask(saved_umask)
        check("synthetic archive bytes do not follow the process umask",
              umask_digests == [first["asset_sha256"]] * 2,
              f"{umask_digests} vs {first['asset_sha256']}")
        check("the bundle names the recorded image by registry digest",
              first["oci_manifest_digest"] == IMAGE_MANIFEST_DIGEST
              and first["config_image_id"] == IMAGE_CONFIG_ID)
        check("the build discloses the packaged/approved profile digest pair",
              first["profile_approval"] == {
                  "packaged_sha256": _hash(roles["profile"]),
                  "approved_sha256": APPROVED_PROFILE_SHA256,
                  "difference": "api_scoring: none"})

        v2 = layout("2")
        v2_a_dir = os.path.join(root, "v2-a")
        v2_b_dir = os.path.join(root, "v2-b")
        os.mkdir(v2_a_dir)
        os.mkdir(v2_b_dir)
        v2_a = os.path.join(v2_a_dir, v2.asset_name)
        v2_b = os.path.join(v2_b_dir, v2.asset_name)
        third = build_bundle(
            inputs_path=v2_descriptor, out=v2_a, version="2")
        fourth = build_bundle(
            inputs_path=v2_descriptor, out=v2_b, version="2")
        check("native Algorand bundle v2 build is byte-identical",
              third["asset_sha256"] == fourth["asset_sha256"]
              and Path(v2_a).read_bytes() == Path(v2_b).read_bytes())
        check("v2 synthetic archive bytes remain unchanged",
              third["asset_sha256"]
              == "443118663200ba0257f65dce3a2685175f623c657478cf932fbe957f27083dff",
              third["asset_sha256"])
        shared_facts = {
            "released_items", "execution_items", "worker_plan",
            "boundary_approval", "profile_approval",
            "mutation_validation_sha256",
            "oci_manifest_digest", "config_image_id", "view_digest",
            "source_digest", "mutation_digest",
        }
        check("v2 changes delivery identities and no scientific fact",
              all(first[key] == third[key] for key in shared_facts)
              and first["version"] == "1" and third["version"] == "2"
              and first["oci_repository"] == _V1.image_repository
              and third["oci_repository"] == v2.image_repository
              and first["bundle_manifest_sha256"]
              != third["bundle_manifest_sha256"]
              and first["oci_image_sha256"] != third["oci_image_sha256"])

        v3 = layout("3")
        v3_a_dir = os.path.join(root, "v3-a")
        os.mkdir(v3_a_dir)
        v3_a = os.path.join(v3_a_dir, v3.asset_name)
        fifth = build_bundle(
            inputs_path=v3_descriptor, out=v3_a, version="3")
        check("native Algorand bundle v3 carries the gold baseline",
              fifth["version"] == "3"
              and fifth[GOLD_BASELINE_ROLE]["path"] == GOLD_BASELINE_PATH
              and fifth[GOLD_BASELINE_ROLE]["row_count"] == 111
              and fifth[GOLD_BASELINE_ROLE]["role"] == GOLD_BASELINE_ROLE)

        production_pin_dir = os.path.join(root, "v4-production-pin")
        os.mkdir(production_pin_dir)
        v5_production_pin_dir = os.path.join(root, "v5-production-pin")
        os.mkdir(v5_production_pin_dir)
        check("synthetic v4 evidence refuses under production identity pins",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(production_pin_dir, v4.asset_name),
                  version="4"), "frozen production identity")
              and not os.listdir(production_pin_dir))
        check("synthetic v5 reference evidence refuses under production "
              "identity pins",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_production_pin_dir, v5.asset_name),
                  version="5"), "frozen production identity")
              and not os.listdir(v5_production_pin_dir))
        V4_CANDIDATE_RUN_SHA256 = fixture_v4_pins["run"]
        V4_CANDIDATE_GENERATED_TESTS_SHA256 = fixture_v4_pins["generated"]
        V4_CANDIDATE_OBSERVATION_ID = fixture_v4_pins[
            "candidate_observation"]
        V4_GENERATION_ATTEMPT_ID = fixture_v4_pins["attempt"]
        from ..bench import slice3_test_quality as fixture_slice3_quality
        saved_slice3_pins = (
            fixture_slice3_quality.FROZEN_EXECUTION_BINDING_DIGEST,
            fixture_slice3_quality.FROZEN_ELIGIBILITY_SHA256,
        )
        def select_fixture_reference_identity(
                wrapper: dict, attestation_raw: bytes) -> None:
            global V4_CONTROL_OBSERVATIONS, V4_EXECUTION_BINDING_DIGEST
            global V4_PAIR_SET_DIGEST, V4_ELIGIBILITY_SHA256
            binding = wrapper["mutation_execution_binding"]
            project_binding = binding["projects"][PROJECT]
            V4_CONTROL_OBSERVATIONS = {
                row["role"]: row["observation_id"]
                for row in project_binding["control_observations"]
            }
            V4_EXECUTION_BINDING_DIGEST = binding["digest"]
            V4_PAIR_SET_DIGEST = project_binding["pair_set_digest"]
            V4_ELIGIBILITY_SHA256 = hashlib.sha256(
                attestation_raw).hexdigest()
            fixture_slice3_quality.FROZEN_EXECUTION_BINDING_DIGEST = \
                V4_EXECUTION_BINDING_DIGEST
            fixture_slice3_quality.FROZEN_ELIGIBILITY_SHA256 = \
                V4_ELIGIBILITY_SHA256

        select_fixture_reference_identity(
            fixture_wrapper, fixture_attestation_raw)

        v4_a_dir = os.path.join(root, "v4-a")
        v4_b_dir = os.path.join(root, "v4-b")
        os.mkdir(v4_a_dir)
        os.mkdir(v4_b_dir)
        v4_a = os.path.join(v4_a_dir, v4.asset_name)
        v4_b = os.path.join(v4_b_dir, v4.asset_name)
        sixth = build_bundle(
            inputs_path=v4_descriptor, out=v4_a, version="4")
        seventh = build_bundle(
            inputs_path=v4_descriptor, out=v4_b, version="4")
        check("native Algorand bundle v4 is deterministic and returns exact "
              "installed identity facts",
              sixth["asset_sha256"] == seventh["asset_sha256"]
              and Path(v4_a).read_bytes() == Path(v4_b).read_bytes()
              and sixth["project"] == PROJECT and sixth["version"] == "4")
        select_fixture_reference_identity(
            v5_wrapper, fixture_v5_attestation_raw)
        v5_a_dir = os.path.join(root, "v5-a")
        v5_b_dir = os.path.join(root, "v5-b")
        os.mkdir(v5_a_dir)
        os.mkdir(v5_b_dir)
        v5_a = os.path.join(v5_a_dir, v5.asset_name)
        v5_b = os.path.join(v5_b_dir, v5.asset_name)
        eighth = build_bundle(
            inputs_path=v5_descriptor, out=v5_a, version="5")
        ninth = build_bundle(
            inputs_path=v5_descriptor, out=v5_b, version="5")
        v5_archive_stage = os.path.join(root, "v5-archive-stage")
        os.mkdir(v5_archive_stage)
        _inspect_archive(v5_a, v5_archive_stage, selected=v5)
        validated_v5_archive = validate_bundle(
            v5_archive_stage, version="5")
        check("native Algorand bundle v5 is deterministic, reference-only, "
              "archive-valid, and returns exact installed identity facts",
              eighth["asset_sha256"] == ninth["asset_sha256"]
              and Path(v5_a).read_bytes() == Path(v5_b).read_bytes()
              and eighth["project"] == PROJECT and eighth["version"] == "5"
              and validated_v5_archive["project"] == PROJECT
              and validated_v5_archive["version"] == "5")
        select_fixture_reference_identity(
            fixture_wrapper, fixture_attestation_raw)
        check("v4 accepts candidate item-set equality without inventing a "
              "release row-order constraint",
              [row["item_id"] for row in fixture_candidate_rows]
              == list(reversed(_read_json(
                  v4_fixture["roles"]["execution_view"],
                  "fixture execution view")[0]["execution_manifest"][
                      "ordered_item_ids"])))

        scored_input = v4_fixture["roles"][SCORED_MANIFEST_ROLE]
        wrapped_scored = Path(scored_input).read_bytes()
        Path(scored_input).write_bytes(_canonical(fixture_binding))
        bare_dir = os.path.join(root, "v4-bare-binding")
        os.mkdir(bare_dir)
        check("v4 rejects a valid bare execution binding in the scored role",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(bare_dir, v4.asset_name), version="4"),
                  "v4 scored manifest")
              and not os.listdir(bare_dir))
        Path(scored_input).write_bytes(wrapped_scored)

        noncanonical_dir = os.path.join(root, "v4-noncanonical-wrapper")
        os.mkdir(noncanonical_dir)
        Path(scored_input).write_bytes(json.dumps(
            fixture_wrapper, indent=1, sort_keys=True).encode())
        check("v4 rejects a semantically equal noncanonical wrapper",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(noncanonical_dir, v4.asset_name),
                  version="4"), "canonical wrapped JSON")
              and not os.listdir(noncanonical_dir))
        Path(scored_input).write_bytes(wrapped_scored)

        from ..bench import slice3_evidence as fixture_slice3_eval
        changed_wrapper = json.loads(wrapped_scored)
        changed_binding = changed_wrapper["mutation_execution_binding"]
        changed_binding["candidate_policy"]["arms"] = [
            "openhands", "aider"]
        unsigned_binding = dict(changed_binding)
        unsigned_binding.pop("digest")
        changed_binding["digest"] = fixture_slice3_eval._digest(
            unsigned_binding)
        V4_EXECUTION_BINDING_DIGEST = changed_binding["digest"]
        Path(scored_input).write_bytes(_canonical(changed_wrapper))
        resigned_dir = os.path.join(root, "v4-resigned-binding")
        os.mkdir(resigned_dir)
        check("v4 rederives a re-signed binding instead of trusting its "
              "ordinary file reference",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(resigned_dir, v4.asset_name), version="4"),
                  "does not rederive")
              and not os.listdir(resigned_dir))
        select_fixture_reference_identity(
            fixture_wrapper, fixture_attestation_raw)
        Path(scored_input).write_bytes(wrapped_scored)

        control_shard, control_sidecar = _v4_quality_shard(
            os.path.join(v4_fixture["roles"][GOLD_RESULTS_ROLE],
                         "full_gold_a"), "fixture v4 full gold A")
        control_provenance = control_shard + ".provenance.json"
        saved_control_provenance = Path(control_provenance).read_bytes()
        extended_v4_sidecar = json.loads(saved_control_provenance)
        extended_v4_sidecar["manifest"] = "/fixture/mutation/manifest.json"
        Path(control_provenance).write_bytes(_canonical(extended_v4_sidecar))
        extended_v4_dir = os.path.join(root, "v4-extended-provenance")
        os.mkdir(extended_v4_dir)
        check("v4 retains its closed mutation-shard provenance schema",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(extended_v4_dir, v4.asset_name),
                  version="4"), "closed schema")
              and not os.listdir(extended_v4_dir))
        Path(control_provenance).write_bytes(saved_control_provenance)
        bridge_sidecar = json.loads(saved_control_provenance)
        bridge_sidecar["campaign_identity"]["release_sha256"] = _hash(
            v4_fixture["roles"]["released_items"])
        Path(control_provenance).write_bytes(_canonical(bridge_sidecar))
        bridge_dir = os.path.join(root, "v4-campaign-bridge")
        os.mkdir(bridge_dir)
        check("v4 compact campaign bridge distinguishes the 111-row "
              "execution release from the 117-row packaged release",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(bridge_dir, v4.asset_name), version="4"),
                  "release_sha256")
              and not os.listdir(bridge_dir))
        Path(control_provenance).write_bytes(saved_control_provenance)
        def reseal_fixture_shard(shard_path: str, sidecar: dict) -> None:
            provenance_path = shard_path + ".provenance.json"
            os.unlink(provenance_path)
            provenance = {
                "observation_id": sidecar["observation_id"],
                "slice3_execution_binding_digest":
                    sidecar["slice3_execution_binding_digest"],
                "slice3_mutation_job_digest":
                    sidecar["slice3_mutation_job_digest"],
            }
            fixture_mutation_run.write_shard_provenance(
                shard_path, sidecar["campaign_identity"], "running",
                provenance=provenance)
            fixture_mutation_run.write_shard_provenance(
                shard_path, sidecar["campaign_identity"], "complete",
                provenance=provenance)

        saved_control_shard = Path(control_shard).read_bytes()
        control_rows = [json.loads(line)
                        for line in saved_control_shard.splitlines()]
        control_rows[0]["outcome"] = "timeout"
        Path(control_shard).write_bytes(
            b"".join(_canonical(row) for row in control_rows))
        reseal_fixture_shard(control_shard, control_sidecar)
        control_outcome_dir = os.path.join(root, "v4-control-outcome")
        os.mkdir(control_outcome_dir)
        check("v4 controls reject an infrastructure outcome after all row "
              "and provenance hashes are re-sealed",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(control_outcome_dir, v4.asset_name),
                  version="4"), "infrastructure")
              and not os.listdir(control_outcome_dir))
        Path(control_shard).write_bytes(saved_control_shard)
        Path(control_provenance).write_bytes(saved_control_provenance)

        attestation_input = v4_fixture["roles"][
            GOLD_RESULTS_ATTESTATION_ROLE]
        saved_attestation = Path(attestation_input).read_bytes()
        alternate_attestation = json.dumps(
            json.loads(saved_attestation), sort_keys=True,
            separators=(",", ":")).encode()
        V4_ELIGIBILITY_SHA256 = hashlib.sha256(
            alternate_attestation).hexdigest()
        Path(attestation_input).write_bytes(alternate_attestation)
        attestation_dir = os.path.join(root, "v4-attestation-bytes")
        os.mkdir(attestation_dir)
        check("v4 eligibility requires the derived byte serialization even "
              "when alternate bytes are re-pinned",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(attestation_dir, v4.asset_name),
                  version="4"), "byte-rederive")
              and not os.listdir(attestation_dir))
        select_fixture_reference_identity(
            fixture_wrapper, fixture_attestation_raw)
        Path(attestation_input).write_bytes(saved_attestation)

        select_fixture_reference_identity(
            v5_wrapper, fixture_v5_attestation_raw)
        v5_scored_input = v5_fixture["roles"][SCORED_MANIFEST_ROLE]
        saved_v5_scored = Path(v5_scored_input).read_bytes()
        v5_candidate_wrapper = json.loads(saved_v5_scored)
        v5_candidate_wrapper[CANDIDATE_RUN_ROLE] = {"bytes": "excluded"}
        Path(v5_scored_input).write_bytes(_canonical(v5_candidate_wrapper))
        v5_candidate_wrapper_dir = os.path.join(
            root, "v5-candidate-wrapper")
        os.mkdir(v5_candidate_wrapper_dir)
        check("v5 rejects candidate bytes hidden in the scored reference "
              "role",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(
                      v5_candidate_wrapper_dir, v5.asset_name),
                  version="5"), "closed schema")
              and not os.listdir(v5_candidate_wrapper_dir))
        Path(v5_scored_input).write_bytes(saved_v5_scored)

        v5_execution_view = v5_fixture["roles"]["execution_view"]
        saved_v5_execution_view = Path(v5_execution_view).read_bytes()
        changed_v5_execution_view = json.loads(saved_v5_execution_view)
        changed_v5_execution_view["execution_manifest"][
            "ordered_item_ids"].reverse()
        Path(v5_execution_view).write_bytes(
            _canonical(changed_v5_execution_view))
        v5_execution_view_dir = os.path.join(root, "v5-execution-view")
        os.mkdir(v5_execution_view_dir)
        check("v5 rejects changed selector bytes before accepting reference "
              "quality evidence",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_execution_view_dir, v5.asset_name),
                  version="5"), "does not rederive from released closures")
              and not os.listdir(v5_execution_view_dir))
        Path(v5_execution_view).write_bytes(saved_v5_execution_view)

        v5_changed_selector = json.loads(saved_v5_scored)
        changed_selector_binding = v5_changed_selector[
            "mutation_execution_binding"]
        changed_selector_binding["projects"][PROJECT][
            "mutant_manifest_digest"] = "0" * 64
        unsigned_selector = dict(changed_selector_binding)
        unsigned_selector.pop("digest")
        changed_selector_binding["digest"] = fixture_slice3_eval._digest(
            unsigned_selector)
        V4_EXECUTION_BINDING_DIGEST = changed_selector_binding["digest"]
        Path(v5_scored_input).write_bytes(_canonical(v5_changed_selector))
        v5_selector_dir = os.path.join(root, "v5-selector")
        os.mkdir(v5_selector_dir)
        check("v5 rederives the Java20 mutant selector instead of trusting "
              "a re-signed wrapper",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_selector_dir, v5.asset_name),
                  version="5"), "does not rederive")
              and not os.listdir(v5_selector_dir))
        select_fixture_reference_identity(
            v5_wrapper, fixture_v5_attestation_raw)
        Path(v5_scored_input).write_bytes(saved_v5_scored)

        v5_changed_pairs = json.loads(saved_v5_scored)
        changed_pairs_binding = v5_changed_pairs[
            "mutation_execution_binding"]
        changed_pairs = changed_pairs_binding["projects"][PROJECT][
            "ordered_pairs"]
        changed_pairs[0] = [changed_pairs[0][0], "excluded-mutant"]
        unsigned_pairs = dict(changed_pairs_binding)
        unsigned_pairs.pop("digest")
        changed_pairs_binding["digest"] = fixture_slice3_eval._digest(
            unsigned_pairs)
        V4_EXECUTION_BINDING_DIGEST = changed_pairs_binding["digest"]
        Path(v5_scored_input).write_bytes(_canonical(v5_changed_pairs))
        v5_pairs_dir = os.path.join(root, "v5-pair-set")
        os.mkdir(v5_pairs_dir)
        check("v5 rejects a changed 69-pair set after its wrapper is "
              "re-signed",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_pairs_dir, v5.asset_name),
                  version="5"), "does not rederive")
              and not os.listdir(v5_pairs_dir))
        select_fixture_reference_identity(
            v5_wrapper, fixture_v5_attestation_raw)
        Path(v5_scored_input).write_bytes(saved_v5_scored)

        v5_gold_input = v5_fixture["roles"][GOLD_RESULTS_ROLE]
        hidden_candidate = os.path.join(
            v5_gold_input, "candidate_run1_aider")
        shutil.copytree(os.path.join(
            v4_fixture["roles"][CANDIDATE_RESULTS_ROLE],
            "candidate_run1_aider"), hidden_candidate)
        v5_hidden_candidate_dir = os.path.join(
            root, "v5-hidden-candidate")
        os.mkdir(v5_hidden_candidate_dir)
        check("v5 rejects a candidate shard hidden under gold results",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_hidden_candidate_dir, v5.asset_name),
                  version="5"), "exact six controls")
              and not os.listdir(v5_hidden_candidate_dir))
        shutil.rmtree(hidden_candidate)

        v5_control_shard, v5_control_sidecar = _v4_quality_shard(
            os.path.join(v5_gold_input, "full_gold_a"),
            "fixture v5 full gold A", allow_producer_provenance=True)
        v5_control_provenance = v5_control_shard + ".provenance.json"
        saved_v5_control_shard = Path(v5_control_shard).read_bytes()
        saved_v5_control_provenance = Path(
            v5_control_provenance).read_bytes()
        missing_v5_sidecar = json.loads(saved_v5_control_provenance)
        missing_v5_sidecar.pop("out")
        Path(v5_control_provenance).write_bytes(
            _canonical(missing_v5_sidecar))
        missing_v5_member_dir = os.path.join(
            root, "v5-missing-sidecar-member")
        os.mkdir(missing_v5_member_dir)
        check("v5 refuses a provenance-extended sidecar missing one "
              "required member without escaping its controlled refusal",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(missing_v5_member_dir, v5.asset_name),
                  version="5"), "required members")
              and not os.listdir(missing_v5_member_dir))
        Path(v5_control_provenance).write_bytes(
            saved_v5_control_provenance)
        v5_bridge_sidecar = json.loads(saved_v5_control_provenance)
        v5_bridge_sidecar["campaign_identity"]["release_sha256"] = _hash(
            v5_fixture["roles"]["released_items"])
        Path(v5_control_provenance).write_bytes(
            _canonical(v5_bridge_sidecar))
        v5_bridge_dir = os.path.join(root, "v5-campaign-bridge")
        os.mkdir(v5_bridge_dir)
        check("v5 compact provenance bridge distinguishes the 111-row view "
              "from the 117-row release",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_bridge_dir, v5.asset_name),
                  version="5"), "release_sha256")
              and not os.listdir(v5_bridge_dir))
        Path(v5_control_provenance).write_bytes(
            saved_v5_control_provenance)
        v5_raw_bridge_sidecar = json.loads(saved_v5_control_provenance)
        v5_raw_bridge_sidecar["campaign_identity"]["release_sha256"] = \
            fixture_v5_raw_sha256
        Path(v5_control_provenance).write_bytes(
            _canonical(v5_raw_bridge_sidecar))
        v5_raw_bridge_dir = os.path.join(root, "v5-raw-campaign-bridge")
        os.mkdir(v5_raw_bridge_dir)
        check("v5 refuses the raw execution-release digest without a "
              "projection fallback",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_raw_bridge_dir, v5.asset_name),
                  version="5"), "release_sha256")
              and not os.listdir(v5_raw_bridge_dir))
        Path(v5_control_provenance).write_bytes(
            saved_v5_control_provenance)

        changed_value_rows = [dict(row) for row in fixture_v5_release_rows]
        changed_value_rows[0]["task"] = "changed_fixture_value"
        changed_value_sha256 = hashlib.sha256(
            _historical_slice3_release_projection(
                changed_value_rows)).hexdigest()
        v5_changed_value_sidecar = json.loads(saved_v5_control_provenance)
        v5_changed_value_sidecar["campaign_identity"][
            "release_sha256"] = changed_value_sha256
        Path(v5_control_provenance).write_bytes(
            _canonical(v5_changed_value_sidecar))
        v5_changed_value_dir = os.path.join(
            root, "v5-changed-release-value")
        os.mkdir(v5_changed_value_dir)
        check("v5 refuses a sidecar bound to a one-value-changed parsed "
              "release projection",
              changed_value_sha256 != fixture_v5_projection_sha256
              and refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_changed_value_dir, v5.asset_name),
                  version="5"), "release_sha256")
              and not os.listdir(v5_changed_value_dir))
        Path(v5_control_provenance).write_bytes(
            saved_v5_control_provenance)

        reordered_rows = [fixture_v5_release_rows[1],
                          fixture_v5_release_rows[0],
                          *fixture_v5_release_rows[2:]]
        reordered_sha256 = hashlib.sha256(
            _historical_slice3_release_projection(
                reordered_rows)).hexdigest()
        v5_reordered_sidecar = json.loads(saved_v5_control_provenance)
        v5_reordered_sidecar["campaign_identity"]["release_sha256"] = \
            reordered_sha256
        Path(v5_control_provenance).write_bytes(
            _canonical(v5_reordered_sidecar))
        v5_reordered_dir = os.path.join(root, "v5-reordered-release")
        os.mkdir(v5_reordered_dir)
        check("v5 refuses a sidecar bound to a reordered parsed release "
              "projection",
              reordered_sha256 != fixture_v5_projection_sha256
              and refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_reordered_dir, v5.asset_name),
                  version="5"), "release_sha256")
              and not os.listdir(v5_reordered_dir))
        Path(v5_control_provenance).write_bytes(
            saved_v5_control_provenance)

        v5_control_rows = [json.loads(line)
                           for line in saved_v5_control_shard.splitlines()]
        v5_control_rows[0]["outcome"] = "timeout"
        Path(v5_control_shard).write_bytes(
            b"".join(_canonical(row) for row in v5_control_rows))
        reseal_fixture_shard(v5_control_shard, v5_control_sidecar)
        v5_control_dir = os.path.join(root, "v5-control-outcome")
        os.mkdir(v5_control_dir)
        check("v5 rejects changed control bytes after row and provenance "
              "hashes are re-sealed",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_control_dir, v5.asset_name),
                  version="5"), "infrastructure")
              and not os.listdir(v5_control_dir))
        Path(v5_control_shard).write_bytes(saved_v5_control_shard)
        Path(v5_control_provenance).write_bytes(
            saved_v5_control_provenance)

        v5_attestation_input = v5_fixture["roles"][
            GOLD_RESULTS_ATTESTATION_ROLE]
        saved_v5_attestation = Path(v5_attestation_input).read_bytes()
        alternate_v5_attestation = json.dumps(
            json.loads(saved_v5_attestation), sort_keys=True,
            separators=(",", ":")).encode()
        V4_ELIGIBILITY_SHA256 = hashlib.sha256(
            alternate_v5_attestation).hexdigest()
        Path(v5_attestation_input).write_bytes(alternate_v5_attestation)
        v5_attestation_dir = os.path.join(root, "v5-attestation-bytes")
        os.mkdir(v5_attestation_dir)
        check("v5 eligibility requires byte-identical rederivation even "
              "after alternate bytes are re-pinned",
              refused(lambda: build_bundle(
                  inputs_path=v5_descriptor,
                  out=os.path.join(v5_attestation_dir, v5.asset_name),
                  version="5"), "byte-rederive")
              and not os.listdir(v5_attestation_dir))
        select_fixture_reference_identity(
            v5_wrapper, fixture_v5_attestation_raw)
        Path(v5_attestation_input).write_bytes(saved_v5_attestation)

        select_fixture_reference_identity(
            fixture_wrapper, fixture_attestation_raw)
        candidate_input = v4_fixture["roles"][CANDIDATE_RUN_ROLE]
        saved_candidate_input = Path(candidate_input).read_bytes()
        changed_candidate_rows = [json.loads(line)
                                  for line in saved_candidate_input.splitlines()]
        changed_candidate_rows[0]["agent_system"] = "openhands"
        changed_candidate_input = b"".join(
            _canonical(row) for row in changed_candidate_rows)
        V4_CANDIDATE_RUN_SHA256 = hashlib.sha256(
            changed_candidate_input).hexdigest()
        Path(candidate_input).write_bytes(changed_candidate_input)
        candidate_arm_dir = os.path.join(root, "v4-candidate-arm")
        os.mkdir(candidate_arm_dir)
        check("v4 revalidates the sealed candidate's Aider projection after "
              "its raw input is re-pinned",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(candidate_arm_dir, v4.asset_name),
                  version="4"), "Aider projection")
              and not os.listdir(candidate_arm_dir))
        V4_CANDIDATE_RUN_SHA256 = fixture_v4_pins["run"]
        Path(candidate_input).write_bytes(saved_candidate_input)

        candidate_shard = _fixture_candidate_shard
        candidate_provenance = candidate_shard + ".provenance.json"
        saved_candidate_shard = Path(candidate_shard).read_bytes()
        saved_candidate_provenance = Path(candidate_provenance).read_bytes()
        d4_sidecar = json.loads(saved_candidate_provenance)
        d4_rows = [json.loads(line)
                   for line in saved_candidate_shard.splitlines()]
        eligibility_doc = json.loads(saved_attestation)
        d4_item = eligibility_doc["projects"][PROJECT]["hard_pairs"][0][
            "item_id"]
        for row in d4_rows:
            if row["item_id"] == d4_item:
                row["outcome"] = "failed"
        Path(candidate_shard).write_bytes(
            b"".join(_canonical(row) for row in d4_rows))
        reseal_fixture_shard(candidate_shard, d4_sidecar)
        d4_dir = os.path.join(root, "v4-d4-required")
        os.mkdir(d4_dir)
        check("v4 refuses a valid run 1 whose complete hard subset requires "
              "an absent D4 run 2",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(d4_dir, v4.asset_name), version="4"),
                  "requires an absent D4 run 2")
              and not os.listdir(d4_dir)
              and {row["outcome"] for row in
                   (json.loads(line)
                    for line in saved_candidate_shard.splitlines())}
              >= {"passed", "undefined_steps", "parse_or_compile_error"})
        Path(candidate_shard).write_bytes(saved_candidate_shard)
        Path(candidate_provenance).write_bytes(saved_candidate_provenance)

        candidate_tree_input = v4_fixture["roles"][CANDIDATE_RESULTS_ROLE]
        extra_candidate = os.path.join(candidate_tree_input, "output-plan.json")
        Path(extra_candidate).write_text("{}\n", encoding="utf-8")
        extra_candidate_dir = os.path.join(root, "v4-extra-candidate")
        os.mkdir(extra_candidate_dir)
        check("v4 rejects an output-plan member outside the candidate role",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(extra_candidate_dir, v4.asset_name),
                  version="4"), "candidate results")
              and not os.listdir(extra_candidate_dir))
        os.unlink(extra_candidate)

        linked_candidate = os.path.join(
            candidate_tree_input, "candidate_run1_aider", "linked.json")
        os.symlink(v4_fixture["roles"][CANDIDATE_RUN_ROLE], linked_candidate)
        linked_candidate_dir = os.path.join(root, "v4-linked-candidate")
        os.mkdir(linked_candidate_dir)
        check("v4 preserves producer-tree links into staging so closed tree "
              "validation can reject them",
              refused(lambda: build_bundle(
                  inputs_path=v4_descriptor,
                  out=os.path.join(linked_candidate_dir, v4.asset_name),
                  version="4"), "linked or special file")
              and not os.listdir(linked_candidate_dir))
        os.unlink(linked_candidate)

        v3_baseline_path = v3_fixture["roles"][GOLD_BASELINE_ROLE]
        saved_baseline = Path(v3_baseline_path).read_bytes()
        os.unlink(v3_baseline_path)
        missing_baseline_dir = os.path.join(root, "missing-baseline")
        os.mkdir(missing_baseline_dir)
        check("v3 requires one gold baseline input",
              refused(lambda: build_bundle(
                  inputs_path=v3_descriptor,
                  out=os.path.join(missing_baseline_dir, v3.asset_name),
                  version="3"), "gold_baseline input is absent")
              and not os.listdir(missing_baseline_dir))
        Path(v3_baseline_path).write_bytes(saved_baseline)

        changed_rows = [json.loads(line)
                        for line in saved_baseline.splitlines()]
        changed_rows[0]["outcome"] = "failed"
        Path(v3_baseline_path).write_bytes(
            b"".join(_canonical(row) for row in changed_rows))
        changed_baseline_dir = os.path.join(root, "changed-baseline")
        os.mkdir(changed_baseline_dir)
        check("a semantically changed gold baseline row refuses",
              refused(lambda: build_bundle(
                  inputs_path=v3_descriptor,
                  out=os.path.join(changed_baseline_dir, v3.asset_name),
                  version="3"), "approved coverage facts")
              and not os.listdir(changed_baseline_dir))
        Path(v3_baseline_path).write_bytes(saved_baseline)

        mixed_v1_dir = os.path.join(root, "mixed-v1")
        mixed_v2_dir = os.path.join(root, "mixed-v2")
        os.mkdir(mixed_v1_dir)
        os.mkdir(mixed_v2_dir)
        check("bundle output asset names cannot cross build routes",
              refused(lambda: build_bundle(
                  inputs_path=descriptor,
                  out=os.path.join(mixed_v1_dir, v2.asset_name)),
                  "output basename")
              and refused(lambda: build_bundle(
                  inputs_path=v2_descriptor,
                  out=os.path.join(mixed_v2_dir, ASSET_NAME), version="2"),
                  "output basename")
              and not os.listdir(mixed_v1_dir)
              and not os.listdir(mixed_v2_dir))

        wrong_v1_root = os.path.join(root, "v2-as-v1")
        wrong_v2_root = os.path.join(root, "v1-as-v2")
        os.mkdir(wrong_v1_root)
        os.mkdir(wrong_v2_root)
        check("bundle archive roots cannot cross version routes",
              refused(lambda: _inspect_archive(
                  v2_a, wrong_v1_root, selected=_V1),
                      "unowned member")
              and refused(lambda: _inspect_archive(
                  out_a, wrong_v2_root, selected=v2), "unowned member")
              and not os.listdir(wrong_v1_root)
              and not os.listdir(wrong_v2_root))

        before_preflight = (len(evidence_calls), len(producer_calls))
        check("output collision refuses before provenance/evidence work",
              refused(lambda: build_bundle(
                  inputs_path=descriptor, out=out_a), "already exists")
              and (len(evidence_calls), len(producer_calls))
              == before_preflight)

        evidence_out_dir = os.path.join(root, "bad-evidence")
        os.mkdir(evidence_out_dir)
        def reject_evidence(_inputs, **_kwargs):
            raise _refuse("approved evidence mismatch")
        globals()["_validate_build_evidence"] = reject_evidence
        check("an evidence refusal leaves no archive",
              refused(lambda: build_bundle(
                  inputs_path=descriptor,
                  out=os.path.join(evidence_out_dir, ASSET_NAME)),
                  "approved evidence mismatch")
              and not os.listdir(evidence_out_dir))
        globals()["_validate_build_evidence"] = fixture_evidence

        bad_view_path = _load_inputs(descriptor)["roles"]["execution_view"]
        good_view = Path(bad_view_path).read_bytes()
        bad_view, _raw = _read_json(bad_view_path, "fixture execution view")
        bad_view["execution_manifest"]["ordered_item_ids"].pop()
        bad_view["execution_manifest"]["count"] = 110
        bad_view["execution_manifest"]["digest"] = "0" * 64
        bad_view["execution_manifest"]["digest"] = _document_digest(
            bad_view["execution_manifest"])
        bad_view["view_digest"] = "0" * 64
        bad_view["view_digest"] = _document_digest(bad_view)
        Path(bad_view_path).write_bytes(_canonical(bad_view))
        bad_dir = os.path.join(root, "bad-view")
        os.mkdir(bad_dir)
        check("a 110-item view refuses before archive creation",
              refused(lambda: build_bundle(
                  inputs_path=descriptor,
                  out=os.path.join(bad_dir, ASSET_NAME)), "execution view"))
        Path(bad_view_path).write_bytes(good_view)

        role_inputs = _load_inputs(descriptor)["roles"]
        closures_path = role_inputs["closures"]
        good_closures = Path(closures_path).read_bytes()
        bad_closures = json.loads(good_closures)
        bad_closures[-1]["admitted"] = False
        Path(closures_path).write_bytes(
            json.dumps(bad_closures, sort_keys=True,
                       separators=(",", ":")).encode() + b"\n")
        closure_dir = os.path.join(root, "bad-closures")
        os.mkdir(closure_dir)
        check("all 125 closure rows must be admitted",
              refused(lambda: build_bundle(
                  inputs_path=descriptor,
                  out=os.path.join(closure_dir, ASSET_NAME)),
                  "non-admitted row"))
        Path(closures_path).write_bytes(good_closures)

        from ..data import mutation_attestation as attestation
        map_path = role_inputs["mutation_map"]
        good_map = Path(map_path).read_bytes()
        bad_map, _raw = _read_json(map_path, "fixture mutation map")
        bad_map["coverage_sha256"] = "7" * 64
        bad_map["digest"] = attestation.map_digest(bad_map)
        Path(map_path).write_bytes(_canonical(bad_map))
        map_dir = os.path.join(root, "bad-map")
        os.mkdir(map_dir)
        check("mutation map must name the projected coverage input",
              refused(lambda: build_bundle(
                  inputs_path=descriptor,
                  out=os.path.join(map_dir, ASSET_NAME)),
                  "release or coverage input"))
        Path(map_path).write_bytes(good_map)

        seed_path = os.path.join(role_inputs["stripped_seed"], "seed.json")
        good_seed = Path(seed_path).read_bytes()
        bad_seed = json.loads(good_seed)
        bad_seed["needs_database"] = True
        Path(seed_path).write_text(json.dumps(
            bad_seed, sort_keys=True, indent=1), encoding="utf-8")
        seed_dir = os.path.join(root, "bad-seed")
        os.mkdir(seed_dir)
        check("a database-backed seed cannot satisfy the no-database plan",
              refused(lambda: build_bundle(
                  inputs_path=descriptor,
                  out=os.path.join(seed_dir, ASSET_NAME)),
                  "seed artifacts"))
        Path(seed_path).write_bytes(good_seed)

        protocol_path = role_inputs["protocol"]
        good_protocol = Path(protocol_path).read_bytes()
        Path(protocol_path).write_bytes(good_protocol + b"\n")
        config_dir = os.path.join(root, "bad-config")
        os.mkdir(config_dir)
        check("the bundle carries the reviewed protocol bytes exactly",
              refused(lambda: build_bundle(
                  inputs_path=descriptor,
                  out=os.path.join(config_dir, ASSET_NAME)),
                  "bundled protocol differs from reviewed v1"))
        Path(protocol_path).write_bytes(good_protocol)

        image_path = roles["oci_image"]
        good_image = Path(image_path).read_bytes()
        drifted_image, _raw = _read_json(image_path, "fixture OCI reference")
        drifted_image["repository"] = \
            "ghcr.io/qibinhang/r2t-java-algorand-sdk"
        drifted_image["digest"] = "0" * 64
        drifted_image["digest"] = _document_digest(drifted_image)
        os.unlink(image_path)
        _write_json(image_path, drifted_image)
        repository_dir = os.path.join(root, "bad-image-repository")
        os.mkdir(repository_dir)
        check("the bundled v1 OCI role stays on the organization repository",
              refused(lambda: build_bundle(
                  inputs_path=descriptor,
                  out=os.path.join(repository_dir, ASSET_NAME)),
                  "selected bundle repository"))
        os.unlink(image_path)
        Path(image_path).write_bytes(good_image)

        drifted_image, _raw = _read_json(image_path, "fixture OCI reference")
        drifted_image["manifest_digest"] = "sha256:" + "e" * 64
        drifted_image["digest"] = "0" * 64
        drifted_image["digest"] = _document_digest(drifted_image)
        os.unlink(image_path)
        _write_json(image_path, drifted_image)
        image_dir = os.path.join(root, "bad-image")
        os.mkdir(image_dir)
        check("the bundled reference must name the recorded v1 image",
              refused(lambda: build_bundle(
                  inputs_path=descriptor,
                  out=os.path.join(image_dir, ASSET_NAME)),
                  "recorded v1 image"))
        os.unlink(image_path)
        Path(image_path).write_bytes(good_image)

        packaged_profile = Path(role_inputs["profile"]).read_bytes()
        drifted_profile = os.path.join(root, "drifted-profile.yml")
        Path(drifted_profile).write_bytes(packaged_profile + b"extra: 1\n")
        approved_profile = os.path.join(root, "approved-profile.yml")
        Path(approved_profile).write_bytes(
            packaged_profile.replace(APPROVED_PROFILE_DIFF, b"", 1))
        check("the profile role ships exactly the disclosed checkout bytes",
              refused(lambda: _profile_disclosure(drifted_profile),
                      "disclosed `api_scoring` line")
              and refused(lambda: _profile_disclosure(approved_profile),
                          "disclosed `api_scoring` line")
              and _hash(approved_profile) == APPROVED_PROFILE_SHA256)

        nested = os.path.join(role_inputs["release_gold"], "extra", "x.json")
        os.makedirs(os.path.dirname(nested))
        Path(nested).write_text("{}\n", encoding="utf-8")
        gold_dir = os.path.join(root, "bad-release-gold")
        os.mkdir(gold_dir)
        check("release-gold contains only its manifest and 111 sidecars",
              refused(lambda: build_bundle(
                  inputs_path=descriptor,
                  out=os.path.join(gold_dir, ASSET_NAME)),
                  "manifest and sidecars disagree"))
        os.unlink(nested)
        os.rmdir(os.path.dirname(nested))
        globals()["_validate_build_evidence"] = real_evidence_validator
        globals()["_validate_producer"] = real_producer_validator

        release_index = {
            "schema": RELEASE_SCHEMA, "project": PROJECT,
            "bundle_schema": BUNDLE_SCHEMA, "bundle_version": 1,
            "repository": "owner/private", "release_tag": "v1.0.0-fixture",
            "asset_name": ASSET_NAME,
            "asset_bytes": os.path.getsize(out_a),
            "asset_sha256": _hash(out_a),
            "bundle_manifest_sha256": first["bundle_manifest_sha256"],
            "producer_tag": first["producer"]["repository_tag"],
            "producer_commit": first["producer"]["repository_commit"],
            "digest": "0" * 64,
        }
        release_index["digest"] = _document_digest(release_index)
        release_index_path = os.path.join(root, "release-index.json")
        _write_json(release_index_path, release_index)

        class Response:
            def __init__(self, body): self.body = body
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, size=-1):
                if size is None or size < 0:
                    size = len(self.body)
                body, self.body = self.body[:size], self.body[size:]
                return body

        calls = []
        archive_raw = Path(out_a).read_bytes()
        def opener(request):
            calls.append(request)
            if len(calls) == 1:
                return Response(json.dumps({"assets": [{
                    "name": ASSET_NAME,
                    "url": "https://api.github.test/assets/1"}]}).encode())
            return Response(archive_raw)

        install = os.path.join(root, "install")
        os.mkdir(install)
        fetched = fetch_bundle(
            version="1", root=install, token="fixture-secret",
            release_index_path=release_index_path, opener=opener)
        check("fake private fetch validates and installs exactly two roots",
              fetched["released_items"] == 117
              and os.path.isdir(_at(install, BUNDLE_ROOT))
              and os.path.isdir(_at(install, PROJECT_ROOT))
              and len(calls) == 2)
        before = len(calls)
        check("destination collision refuses before network access",
              refused(lambda: fetch_bundle(
                  version="1", root=install, token="fixture-secret",
                  release_index_path=release_index_path, opener=opener),
                  "destination already exists") and len(calls) == before)

        v2_index = {
            "schema": RELEASE_SCHEMA, "project": PROJECT,
            "bundle_schema": v2.bundle_schema,
            "bundle_version": v2.manifest_version,
            "repository": "owner/private",
            "release_tag": "v2.0.0-fixture",
            "asset_name": v2.asset_name,
            "asset_bytes": os.path.getsize(v2_a),
            "asset_sha256": _hash(v2_a),
            "bundle_manifest_sha256": third["bundle_manifest_sha256"],
            "producer_tag": third["producer"]["repository_tag"],
            "producer_commit": third["producer"]["repository_commit"],
            "digest": "0" * 64,
        }
        v2_index["digest"] = _document_digest(v2_index)
        v2_index_path = os.path.join(root, "release-index-v2.json")
        _write_json(v2_index_path, v2_index)
        v2_archive_raw = Path(v2_a).read_bytes()
        v2_calls = []
        def v2_opener(request):
            v2_calls.append(request)
            if len(v2_calls) == 1:
                return Response(json.dumps({"assets": [{
                    "name": v2.asset_name,
                    "url": "https://api.github.test/assets/2"}]}).encode())
            return Response(v2_archive_raw)

        v2_install = os.path.join(root, "install-v2")
        os.mkdir(v2_install)
        fetched_v2 = fetch_bundle(
            version="2", root=v2_install, token="fixture-secret",
            release_index_path=v2_index_path, opener=v2_opener)
        check("fake v2 fetch selects its index, asset, roots and repository",
              fetched_v2["version"] == "2"
              and fetched_v2["asset"] == v2.asset_name
              and fetched_v2["oci_repository"] == v2.image_repository
              and os.path.isdir(_at(v2_install, v2.bundle_root))
              and os.path.isdir(_at(v2_install, PROJECT_ROOT))
              and len(v2_calls) == 2)

        v3_index = {
            "schema": RELEASE_SCHEMA, "project": PROJECT,
            "bundle_schema": v3.bundle_schema,
            "bundle_version": v3.manifest_version,
            "repository": "owner/private",
            "release_tag": "v3.0.0-fixture",
            "asset_name": v3.asset_name,
            "asset_bytes": os.path.getsize(v3_a),
            "asset_sha256": _hash(v3_a),
            "bundle_manifest_sha256": fifth["bundle_manifest_sha256"],
            "producer_tag": fifth["producer"]["repository_tag"],
            "producer_commit": fifth["producer"]["repository_commit"],
            "digest": "0" * 64,
        }
        v3_index["digest"] = _document_digest(v3_index)
        v3_index_path = os.path.join(root, "release-index-v3.json")
        _write_json(v3_index_path, v3_index)
        v3_archive_raw = Path(v3_a).read_bytes()
        v3_calls = []
        def v3_opener(request):
            v3_calls.append(request)
            if len(v3_calls) == 1:
                return Response(json.dumps({"assets": [{
                    "name": v3.asset_name,
                    "url": "https://api.github.test/assets/3"}]}).encode())
            return Response(v3_archive_raw)

        v3_install = os.path.join(root, "install-v3")
        os.mkdir(v3_install)
        fetched_v3 = fetch_bundle(
            version="3", root=v3_install, token="fixture-secret",
            release_index_path=v3_index_path, opener=v3_opener)
        check("fake v3 fetch installs and reports the gold baseline role",
              fetched_v3["version"] == "3"
              and fetched_v3["asset"] == v3.asset_name
              and fetched_v3[GOLD_BASELINE_ROLE]["row_count"] == 111
              and os.path.isfile(_at(v3_install, GOLD_BASELINE_PATH))
              and len(v3_calls) == 2)

        v4_artifacts = {
            role: (v4.tree_roles[role][0]
                   if role in v4.tree_roles else v4.file_roles[role])
            for role in (
                "mutation_validation", SCORED_MANIFEST_ROLE,
                "mutation_map", GOLD_BASELINE_ROLE, GOLD_RESULTS_ROLE,
                GOLD_RESULTS_ATTESTATION_ROLE, CANDIDATE_RUN_ROLE,
                CANDIDATE_RESULTS_ROLE)
        }
        v4_index = {
            "schema": RELEASE_SCHEMA_V2, "project": PROJECT,
            "bundle_schema": v4.bundle_schema,
            "bundle_version": v4.manifest_version,
            "repository": "owner/private",
            "release_tag": "v4.0.0-fixture",
            "asset_name": v4.asset_name,
            "asset_bytes": os.path.getsize(v4_a),
            "asset_sha256": _hash(v4_a),
            "bundle_manifest_sha256": sixth["bundle_manifest_sha256"],
            "producer_tag": sixth["producer"]["repository_tag"],
            "producer_commit": sixth["producer"]["repository_commit"],
            "capabilities": dict(V4_CAPABILITIES),
            "capability_notes": dict(V4_CAPABILITY_NOTES),
            "mutation_engine": "r2t-mutate-java",
            "bundle": {"version": "4", "artifacts": v4_artifacts},
            "digest": "0" * 64,
        }
        v4_index["digest"] = _document_digest(v4_index)
        v4_index_path = os.path.join(root, "release-index-v4.json")
        _write_json(v4_index_path, v4_index)
        checked_v4_declaration = _release_index(v4_index_path, selected=v4)

        def changed_v4_index(name: str, change: Callable[[dict], None]) -> str:
            value = json.loads(json.dumps(v4_index))
            change(value)
            value["digest"] = _document_digest(value)
            path = os.path.join(root, f"release-index-v4-{name}.json")
            _write_json(path, value)
            return path

        v4_schema_v1 = changed_v4_index(
            "schema-v1", lambda value: value.update(
                {"schema": RELEASE_SCHEMA}))
        v4_float_version = changed_v4_index(
            "float-version", lambda value: value.update(
                {"bundle_version": 4.0}))
        v4_numeric_declaration = changed_v4_index(
            "numeric-declaration", lambda value: value["bundle"].update(
                {"version": 4}))
        v4_alias_artifact = changed_v4_index(
            "alias-artifact", lambda value: value["bundle"][
                "artifacts"].update({
                    SCORED_MANIFEST_ROLE:
                        value["bundle"]["artifacts"][CANDIDATE_RUN_ROLE]}))
        v4_wrong_engine = changed_v4_index(
            "wrong-engine", lambda value: value.update(
                {"mutation_engine": "another-engine"}))
        v4_null_commit = changed_v4_index(
            "null-commit", lambda value: value.update(
                {"producer_commit": None}))
        check("v4 release declarations reject /1, coerced versions, role "
              "aliases, malformed producers, and another capability engine",
              refused(lambda: _release_index(v4_schema_v1, selected=v4),
                      "malformed")
              and refused(lambda: _release_index(
                  v4_float_version, selected=v4), "malformed")
              and refused(lambda: _release_index(
                  v4_numeric_declaration, selected=v4),
                  "declaration differs")
              and refused(lambda: _release_index(
                  v4_alias_artifact, selected=v4), "declaration differs")
              and refused(lambda: _release_index(
                  v4_null_commit, selected=v4), "malformed")
              and refused(lambda: _release_index(
                  v4_wrong_engine, selected=v4),
                  "capability declaration"))

        corrupt_v4_archive = \
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xffnot-a-tar"
        corrupt_v4_index = changed_v4_index(
            "corrupt-archive", lambda value: value.update({
                "asset_bytes": len(corrupt_v4_archive),
                "asset_sha256": hashlib.sha256(
                    corrupt_v4_archive).hexdigest(),
            }))
        corrupt_v4_calls = []
        def corrupt_v4_opener(request):
            corrupt_v4_calls.append(request)
            if len(corrupt_v4_calls) == 1:
                return Response(json.dumps({"assets": [{
                    "name": v4.asset_name,
                    "url": "https://api.github.test/assets/4-corrupt",
                }]}).encode())
            return Response(corrupt_v4_archive)
        corrupt_v4_root = os.path.join(root, "install-v4-corrupt")
        os.mkdir(corrupt_v4_root)
        check("v4 fetch normalizes a digest-matching unreadable archive and "
              "installs nothing",
              refused(lambda: fetch_bundle(
                  version="4", root=corrupt_v4_root,
                  release_index_path=corrupt_v4_index,
                  opener=corrupt_v4_opener), "archive cannot be read")
              and len(corrupt_v4_calls) == 2
              and not os.listdir(corrupt_v4_root))

        missing_role_index = json.loads(json.dumps(v4_index))
        missing_role_index["bundle"]["artifacts"].pop(GOLD_RESULTS_ROLE)
        missing_role_index["digest"] = _document_digest(missing_role_index)
        missing_role_index_path = os.path.join(
            root, "release-index-v4-missing-role.json")
        _write_json(missing_role_index_path, missing_role_index)
        v4_preflight_calls = []
        check("v4 release declaration refuses a missing enabled generic role "
              "before network access",
              refused(lambda: fetch_bundle(
                  version="4", root=os.path.join(root, "unused-v4-root"),
                  release_index_path=missing_role_index_path,
                  opener=lambda request: v4_preflight_calls.append(request)),
                  GOLD_RESULTS_ROLE)
              and not v4_preflight_calls)

        v4_archive_raw = Path(v4_a).read_bytes()
        v4_calls = []
        def v4_opener(request):
            v4_calls.append(request)
            if len(v4_calls) == 1:
                return Response(json.dumps({"assets": [{
                    "name": v4.asset_name,
                    "url": "https://api.github.test/assets/4"}]}).encode())
            return Response(v4_archive_raw)

        v4_install = os.path.join(root, "install-v4")
        os.mkdir(v4_install)
        fetched_v4 = fetch_bundle(
            version="4", root=v4_install, token="fixture-secret",
            release_index_path=v4_index_path, opener=v4_opener)
        from ..data import bundle as generic_bundle_v4
        generic_v4_fact = generic_bundle_v4.validate_installed_bundle(
            PROJECT, "4", v4_install)
        check("fake v4 fetch validates /2, installs both roots, and returns "
              "exact string identity facts",
              fetched_v4["project"] == PROJECT
              and fetched_v4["version"] == "4"
              and generic_v4_fact["project"] == PROJECT
              and generic_v4_fact["version"] == "4"
              and os.path.isdir(_at(v4_install, v4.bundle_root))
              and os.path.isdir(_at(v4_install, PROJECT_ROOT))
              and len(v4_calls) == 2)

        installed_v4_manifest_path = _at(v4_install, v4.bundle_manifest)
        installed_v4_manifest_raw = Path(
            installed_v4_manifest_path).read_bytes()
        installed_v4_manifest = json.loads(installed_v4_manifest_raw)
        installed_v4_manifest["version"] = 4.0
        installed_v4_manifest["digest"] = _document_digest(
            installed_v4_manifest)
        Path(installed_v4_manifest_path).write_bytes(
            _canonical(installed_v4_manifest))
        check("v4 bundle manifests require integer 4 without numeric "
              "coercion",
              refused(lambda: validate_bundle(v4_install, version="4"),
                      "selected Algorand version"))
        Path(installed_v4_manifest_path).write_bytes(
            installed_v4_manifest_raw)

        v5_artifact_roles = (
            "mutation_validation", SCORED_MANIFEST_ROLE,
            "mutation_map", GOLD_BASELINE_ROLE, GOLD_RESULTS_ROLE,
            GOLD_RESULTS_ATTESTATION_ROLE,
        )
        v5_artifacts = {
            role: (v5.tree_roles[role][0]
                   if role in v5.tree_roles else v5.file_roles[role])
            for role in v5_artifact_roles
        }
        v5_index = {
            "schema": RELEASE_SCHEMA_V2, "project": PROJECT,
            "bundle_schema": v5.bundle_schema,
            "bundle_version": v5.manifest_version,
            "repository": "owner/private",
            "release_tag": "v5.0.0-fixture",
            "asset_name": v5.asset_name,
            "asset_bytes": os.path.getsize(v5_a),
            "asset_sha256": _hash(v5_a),
            "bundle_manifest_sha256": eighth["bundle_manifest_sha256"],
            "producer_tag": eighth["producer"]["repository_tag"],
            "producer_commit": eighth["producer"]["repository_commit"],
            "capabilities": dict(V4_CAPABILITIES),
            "capability_notes": dict(V4_CAPABILITY_NOTES),
            "mutation_engine": "r2t-mutate-java",
            "bundle": {"version": "5", "artifacts": v5_artifacts},
            "digest": "0" * 64,
        }
        v5_index["digest"] = _document_digest(v5_index)
        v5_index_path = os.path.join(root, "release-index-v5.json")
        _write_json(v5_index_path, v5_index)
        checked_v5_declaration = _release_index(v5_index_path, selected=v5)
        check("v5 release /2 declares exactly six identically named role "
              "paths and exact version types",
              checked_v5_declaration["schema"] == RELEASE_SCHEMA_V2
              and type(checked_v5_declaration["bundle_version"]) is int
              and checked_v5_declaration["bundle_version"] == 5
              and checked_v5_declaration["bundle"]["version"] == "5"
              and set(checked_v5_declaration["bundle"]["artifacts"])
              == set(v5_artifact_roles)
              and checked_v5_declaration["bundle"]["artifacts"]
              == v5_artifacts)

        def changed_v5_index(name: str, change: Callable[[dict], None]) -> str:
            value = json.loads(json.dumps(v5_index))
            change(value)
            value["digest"] = _document_digest(value)
            path = os.path.join(root, f"release-index-v5-{name}.json")
            _write_json(path, value)
            return path

        v5_schema_v1 = changed_v5_index(
            "schema-v1", lambda value: value.update(
                {"schema": RELEASE_SCHEMA}))
        v5_float_version = changed_v5_index(
            "float-version", lambda value: value.update(
                {"bundle_version": 5.0}))
        v5_numeric_declaration = changed_v5_index(
            "numeric-declaration", lambda value: value["bundle"].update(
                {"version": 5}))
        v5_alias_artifact = changed_v5_index(
            "alias-artifact", lambda value: value["bundle"][
                "artifacts"].update({
                    SCORED_MANIFEST_ROLE:
                        value["bundle"]["artifacts"][GOLD_BASELINE_ROLE]}))
        v5_null_artifact = changed_v5_index(
            "null-artifact", lambda value: value["bundle"][
                "artifacts"].update({GOLD_RESULTS_ROLE: None}))
        v5_candidate_artifacts = changed_v5_index(
            "candidate-artifacts", lambda value: value["bundle"][
                "artifacts"].update({CANDIDATE_RUN_ROLE: None,
                                     CANDIDATE_RESULTS_ROLE: None}))
        v5_changed_note = changed_v5_index(
            "changed-note", lambda value: value["capability_notes"].update(
                {"coverage": "another note"}))
        check("v5 release declarations reject /1, numeric coercion, aliases, "
              "nulls, candidate placeholders, and changed capabilities",
              refused(lambda: _release_index(v5_schema_v1, selected=v5),
                      "malformed")
              and refused(lambda: _release_index(
                  v5_float_version, selected=v5), "malformed")
              and refused(lambda: _release_index(
                  v5_numeric_declaration, selected=v5),
                  "declaration differs")
              and refused(lambda: _release_index(
                  v5_alias_artifact, selected=v5), "declaration differs")
              and refused(lambda: _release_index(
                  v5_null_artifact, selected=v5))
              and refused(lambda: _release_index(
                  v5_candidate_artifacts, selected=v5),
                  "artifact roles differ")
              and refused(lambda: _release_index(
                  v5_changed_note, selected=v5),
                  "capability declaration"))
        v5_preflight_calls = []
        check("an invalid v5 candidate declaration refuses before fetch",
              refused(lambda: fetch_bundle(
                  version="5", root=os.path.join(root, "unused-v5-root"),
                  release_index_path=v5_candidate_artifacts,
                  opener=lambda request: v5_preflight_calls.append(request)),
                  "artifact roles differ")
              and not v5_preflight_calls)
        check("v4 and v5 release indexes cannot select one another",
              refused(lambda: _release_index(v4_index_path, selected=v5),
                      "malformed")
              and refused(lambda: _release_index(v5_index_path, selected=v4),
                          "malformed"))

        select_fixture_reference_identity(
            v5_wrapper, fixture_v5_attestation_raw)
        v5_archive_raw = Path(v5_a).read_bytes()
        v5_calls = []
        def v5_opener(request):
            v5_calls.append(request)
            if len(v5_calls) == 1:
                return Response(json.dumps({"assets": [{
                    "name": v5.asset_name,
                    "url": "https://api.github.test/assets/5"}]}).encode())
            return Response(v5_archive_raw)

        v5_install = os.path.join(root, "install-v5")
        os.mkdir(v5_install)
        fetched_v5 = fetch_bundle(
            version="5", root=v5_install, token="fixture-secret",
            release_index_path=v5_index_path, opener=v5_opener)
        from ..data import bundle as local_bundle
        from unittest import mock
        local_installs = []
        with mock.patch.object(local_bundle, "_download_asset",
                               side_effect=AssertionError("network reached")):
            for selected, local_archive, local_index, fetched_fact in (
                    (_V1, out_a, release_index_path, fetched),
                    (v2, v2_a, v2_index_path, fetched_v2),
                    (v3, v3_a, v3_index_path, fetched_v3),
                    (v4, v4_a, v4_index_path, fetched_v4),
                    (v5, v5_a, v5_index_path, fetched_v5)):
                if selected.version == "4":
                    select_fixture_reference_identity(
                        fixture_wrapper, fixture_attestation_raw)
                elif selected.version == "5":
                    select_fixture_reference_identity(
                        v5_wrapper, fixture_v5_attestation_raw)
                local_root = os.path.join(root, "local-v" + selected.version)
                os.mkdir(local_root)
                local_fact = local_bundle.install_bundle(
                    project=PROJECT, version=selected.version,
                    archive=local_archive, root=local_root,
                    release_index_path=local_index)
                local_installs.append(
                    local_fact == {**fetched_fact, "data_root": local_root}
                    and os.path.isdir(_at(local_root, PROJECT_ROOT))
                    and os.path.isdir(_at(local_root, selected.bundle_root)))
        check("local install validates all five native versions against their "
              "indexes and returns the same facts as fetch without a download",
              all(local_installs) and len(local_installs) == 5)
        check("local native destination collision refuses before archive access",
              refused(lambda: install_bundle(
                  version="5", archive="absent", root=local_root,
                  release_index_path=v5_index_path),
                  "destination already exists"))
        local_mismatch = os.path.join(root, "local-digest-mismatch")
        os.mkdir(local_mismatch)
        check("a local native archive must match its indexed bytes and length",
              refused(lambda: install_bundle(
                  version="2", archive=out_a, root=local_mismatch,
                  release_index_path=v2_index_path),
                  "differs from release index")
              and os.listdir(local_mismatch) == [])
        local_wrong_manifest = os.path.join(root, "local-manifest-mismatch")
        os.mkdir(local_wrong_manifest)
        wrong_manifest_index = dict(release_index,
                                    bundle_manifest_sha256="0" * 64)
        wrong_manifest_index["digest"] = _document_digest(wrong_manifest_index)
        wrong_manifest_path = os.path.join(root, "wrong-local-manifest.json")
        _write_json(wrong_manifest_path, wrong_manifest_index)
        check("matching local archive bytes cannot bypass the manifest pin",
              refused(lambda: install_bundle(
                  version="1", archive=out_a, root=local_wrong_manifest,
                  release_index_path=wrong_manifest_path),
                  "manifest differs from release index")
              and os.listdir(local_wrong_manifest) == [])
        installed_v5_fact = validate_bundle(v5_install, version="5")
        generic_v5_fact = generic_bundle_v4.validate_installed_bundle(
            PROJECT, "5", v5_install)
        before_v5_collision = len(v5_calls)
        check("fake v5 fetch completely validates before returning the exact "
              "installed fact and preserves no-clobber behavior",
              fetched_v5["project"] == PROJECT
              and fetched_v5["version"] == "5"
              and installed_v5_fact["project"] == PROJECT
              and installed_v5_fact["version"] == "5"
              and generic_v5_fact["project"] == PROJECT
              and generic_v5_fact["version"] == "5"
              and os.path.isdir(_at(v5_install, v5.bundle_root))
              and os.path.isdir(_at(v5_install, PROJECT_ROOT))
              and len(v5_calls) == 2
              and refused(lambda: fetch_bundle(
                  version="5", root=v5_install,
                  release_index_path=v5_index_path, opener=v5_opener),
                  "destination already exists")
              and len(v5_calls) == before_v5_collision)
        installed_v5_sidecar = os.path.join(
            _at(v5_install, v5.tree_roles[GOLD_RESULTS_ROLE][0]),
            "full_gold_a", os.path.basename(v5_control_provenance))
        installed_v5_sidecars = [
            _read_json(os.path.join(
                _at(v5_install, v5.tree_roles[GOLD_RESULTS_ROLE][0]),
                role, "gold.w0.jsonl.provenance.json"),
                f"installed v5 {role} provenance")[0]
            for role in V4_CONTROL_OBSERVATIONS
        ]
        check("installed v5 validates every projection-bound sidecar and "
              "preserves extended producer provenance byte-identically",
              Path(installed_v5_sidecar).read_bytes()
              == Path(v5_control_provenance).read_bytes()
              and Path(_at(
                  v5_install,
                  v5.file_roles["execution_release"])).read_bytes()
              == fixture_v5_release_raw
              and all(sidecar["campaign_identity"]["release_sha256"]
                      == fixture_v5_projection_sha256
                      and fixture_producer_members <= set(sidecar)
                      for sidecar in installed_v5_sidecars))
        check("v5 remains closed on compact Slice-3 and mutation execution "
              "APIs",
              refused(lambda: slice3_inputs(v5_install, version="5"),
                      "reference-only")
              and refused(lambda: validate_installed_mutation_inputs(
                  validation_path=_at(
                      v5_install, v5.file_roles["mutation_validation"]),
                  manifest_path=_at(
                      v5_install, v5.file_roles["mutation_manifest"]),
                  map_path=_at(v5_install, v5.file_roles["mutation_map"]),
                  release_path=_at(
                      v5_install, v5.file_roles["execution_release"]),
                  version="5"), "reference-only"))

        import contextlib
        import io
        from .. import cli as v5_cli
        v5_validate_output = io.StringIO()
        with generic_bundle_v4._using_data_root(v5_install), \
                contextlib.redirect_stdout(v5_validate_output):
            v5_validate_rc = v5_cli.main([
                "bundle", "validate", "--project", PROJECT,
                "--version", "5"])
        check("explicit bundle validation routes version 5 to the complete "
              "installed fact",
              v5_validate_rc == 0
              and json.loads(v5_validate_output.getvalue())
              == generic_v5_fact)

        installed_v5_manifest_path = _at(v5_install, v5.bundle_manifest)
        installed_v5_manifest_raw = Path(
            installed_v5_manifest_path).read_bytes()
        installed_v5_manifest = json.loads(installed_v5_manifest_raw)
        installed_v5_manifest["version"] = 5.0
        installed_v5_manifest["digest"] = _document_digest(
            installed_v5_manifest)
        Path(installed_v5_manifest_path).write_bytes(
            _canonical(installed_v5_manifest))
        v5_float_manifest_refused = refused(
            lambda: validate_bundle(v5_install, version="5"),
            "selected Algorand version")
        Path(installed_v5_manifest_path).write_bytes(
            installed_v5_manifest_raw)
        installed_v5_manifest = json.loads(installed_v5_manifest_raw)
        installed_v5_manifest["roles"].update({
            CANDIDATE_RUN_ROLE: None, CANDIDATE_RESULTS_ROLE: None})
        installed_v5_manifest["digest"] = _document_digest(
            installed_v5_manifest)
        Path(installed_v5_manifest_path).write_bytes(
            _canonical(installed_v5_manifest))
        v5_candidate_manifest_refused = refused(
            lambda: validate_bundle(v5_install, version="5"))
        Path(installed_v5_manifest_path).write_bytes(
            installed_v5_manifest_raw)
        installed_v5_manifest = json.loads(installed_v5_manifest_raw)
        installed_v5_manifest["roles"]["quality_alias"] = dict(
            installed_v5_manifest["roles"][SCORED_MANIFEST_ROLE])
        installed_v5_manifest["digest"] = _document_digest(
            installed_v5_manifest)
        Path(installed_v5_manifest_path).write_bytes(
            _canonical(installed_v5_manifest))
        v5_alias_manifest_refused = refused(
            lambda: validate_bundle(v5_install, version="5"))
        Path(installed_v5_manifest_path).write_bytes(
            installed_v5_manifest_raw)
        installed_v5_manifest = json.loads(installed_v5_manifest_raw)
        installed_v5_manifest["roles"][SCORED_MANIFEST_ROLE] = None
        installed_v5_manifest["digest"] = _document_digest(
            installed_v5_manifest)
        Path(installed_v5_manifest_path).write_bytes(
            _canonical(installed_v5_manifest))
        v5_null_manifest_refused = refused(
            lambda: validate_bundle(v5_install, version="5"))
        Path(installed_v5_manifest_path).write_bytes(
            installed_v5_manifest_raw)
        check("v5 manifests require integer 5 and exclude candidate roles, "
              "aliases, and null placeholders",
              v5_float_manifest_refused
              and v5_candidate_manifest_refused
              and v5_alias_manifest_refused and v5_null_manifest_refused)

        v5_tree_extra = os.path.join(
            _at(v5_install, v5.tree_roles[GOLD_RESULTS_ROLE][0]),
            "full_gold_a", "candidate.jsonl")
        Path(v5_tree_extra).write_bytes(b"{}\n")
        check("v5 installed validation rejects an extra reference-tree "
              "member",
              refused(lambda: validate_bundle(v5_install, version="5"),
                      "tree manifest"))
        os.unlink(v5_tree_extra)

        candidate_archive_member = _at(
            v5_archive_stage,
            f"{PROJECT_ROOT}/artifacts/runs/candidate.jsonl")
        Path(candidate_archive_member).write_bytes(b"{}\n")
        from .bundle_build import _write_archive as write_fixture_archive
        v5_extra_archive = os.path.join(
            root, "r2t-algorand-bundle-v5-extra.tar.gz")
        write_fixture_archive(
            v5_archive_stage, v5_extra_archive, sort_members=True)
        v5_extra_extract = os.path.join(root, "v5-extra-extract")
        os.mkdir(v5_extra_extract)
        _inspect_archive(v5_extra_archive, v5_extra_extract, selected=v5)
        check("v5 rejects a candidate member added to an otherwise valid "
              "archive",
              refused(lambda: validate_bundle(
                  v5_extra_extract, version="5"), "file inventory"))

        v4_as_v5 = os.path.join(root, "v4-as-v5")
        v5_as_v4 = os.path.join(root, "v5-as-v4")
        os.mkdir(v4_as_v5)
        os.mkdir(v5_as_v4)
        check("v4 and v5 archive roots cannot select one another",
              refused(lambda: _inspect_archive(
                  v4_a, v4_as_v5, selected=v5), "unowned member")
              and refused(lambda: _inspect_archive(
                  v5_a, v5_as_v4, selected=v4), "unowned member")
              and not os.listdir(v4_as_v5) and not os.listdir(v5_as_v4))

        from . import doctor as doctor_module
        ready_rows = {row["name"]: row for row in
                      doctor_module._metric_readiness(
                          PROJECT, "4", checked_v4_declaration,
                          doctor_module._project_profile(PROJECT),
                          generic_v4_fact)}
        check("v4 uses generic readiness while the live mutation route stays "
              "closed",
              ready_rows[doctor_module.MUTATION_READINESS_ROW]["status"]
              == "fail"
              and "preserved-evidence-only" in ready_rows[
                  doctor_module.MUTATION_READINESS_ROW]["detail"]
              and ready_rows[doctor_module.COVERAGE_READINESS_ROW]["status"]
              == "pass"
              and ready_rows["production method index"]["status"] == "pass"
              and doctor_module.ALGORAND_ROUTE_VERSION == "2")

        select_fixture_reference_identity(
            fixture_wrapper, fixture_attestation_raw)
        installed_before_remint = validate_bundle(v4_install, version="4")
        remint_out = os.path.join(root, "v4-host-local")
        reminted = remint_v4_test_quality(
            out=remint_out, root=v4_install,
            release_index_path=v4_index_path)
        from ..bench import test_quality as test_quality_module
        reminted_summary = test_quality_module.load_bound_test_quality(
            reminted["run"])
        installed_after_remint = validate_bundle(v4_install, version="4")
        copied_candidate_sidecar = os.path.join(
            reminted["observations"], "candidate_run1_aider",
            os.path.basename(_fixture_candidate_shard) + ".provenance.json")
        source_candidate_sidecar = \
            _fixture_candidate_shard + ".provenance.json"
        check("host-local remint copies exact persistent roles, writes a "
              "revalidatable sidecar, and leaves installed inventory closed",
              Path(reminted["run"]).read_bytes()
              == Path(v4_fixture["roles"][CANDIDATE_RUN_ROLE]).read_bytes()
              and Path(copied_candidate_sidecar).read_bytes()
              == Path(source_candidate_sidecar).read_bytes()
              and os.path.isdir(reminted["observations"])
              and os.path.isfile(reminted["sidecar"])
              and reminted_summary["run"] == reminted["run"]
              and installed_after_remint == installed_before_remint)
        reminted_eligibility = os.path.join(
            reminted["observations"], "six-gate-eligibility.json")
        moved_eligibility = reminted_eligibility + ".moved"
        os.rename(reminted_eligibility, moved_eligibility)
        try:
            test_quality_module.load_bound_test_quality(reminted["run"])
        except test_quality_module.TestQualityRefused:
            missing_persistent_view_refused = True
        else:
            missing_persistent_view_refused = False
        finally:
            os.rename(moved_eligibility, reminted_eligibility)
        check("a host-local sidecar remains valid only while its persistent "
              "copied view remains available",
              missing_persistent_view_refused
              and test_quality_module.load_bound_test_quality(
                  reminted["run"])["run"] == reminted["run"])
        inside_remint = os.path.join(v4_install, "operator-output")
        check("host-local remint refuses output inside installed inventory",
              refused(lambda: remint_v4_test_quality(
                  out=inside_remint, root=v4_install,
                  release_index_path=v4_index_path),
                  "outside R2T_DATA_ROOT")
              and not os.path.lexists(inside_remint))
        aliased_install = os.path.join(root, "v4-install-alias")
        os.symlink(v4_install, aliased_install)
        aliased_remint = os.path.join(aliased_install, "operator-output")
        check("host-local remint resolves a symlinked parent before its "
              "outside-inventory decision",
              refused(lambda: remint_v4_test_quality(
                  out=aliased_remint, root=v4_install,
                  release_index_path=v4_index_path),
                  "outside R2T_DATA_ROOT")
              and not os.path.lexists(aliased_remint))
        os.unlink(aliased_install)

        V4_CONTROL_OBSERVATIONS = dict(production_v4_pins["controls"])
        V4_EXECUTION_BINDING_DIGEST = production_v4_pins["binding"]
        V4_PAIR_SET_DIGEST = production_v4_pins["pairs"]
        V4_ELIGIBILITY_SHA256 = production_v4_pins["eligibility"]
        V4_CANDIDATE_RUN_SHA256 = production_v4_pins["run"]
        V4_CANDIDATE_GENERATED_TESTS_SHA256 = production_v4_pins["generated"]
        V4_CANDIDATE_OBSERVATION_ID = production_v4_pins[
            "candidate_observation"]
        V4_GENERATION_ATTEMPT_ID = production_v4_pins["attempt"]
        (fixture_slice3_quality.FROZEN_EXECUTION_BINDING_DIGEST,
         fixture_slice3_quality.FROZEN_ELIGIBILITY_SHA256) = saved_slice3_pins
        installed_v3 = slice3_inputs(v3_install, version="3")
        check("v3 installed inputs expose gold_baseline without changing "
              "mutation assets",
              installed_v3[GOLD_BASELINE_ROLE]["path"]
              == _at(v3_install, GOLD_BASELINE_PATH)
              and installed_v3[GOLD_BASELINE_ROLE]["sha256"]
              == fifth[GOLD_BASELINE_ROLE]["sha256"]
              and "coverage_run" not in installed_v3["assets"])
        paid_v3 = validate_installed_mutation_inputs(
            validation_path=_at(
                v3_install, v3.file_roles["mutation_validation"]),
            manifest_path=installed_v3["manifest_path"],
            map_path=installed_v3["map_path"],
            release_path=_at(
                v3_install, v3.file_roles["execution_release"]),
            version="3")
        check("v3 installed validation keeps the 111-item mutation view",
              paid_v3["release_items"] == 111
              and paid_v3["validation_class"] == "native")
        before_v2_collision = len(v2_calls)
        check("shared project root prevents mixed installed versions",
              refused(lambda: fetch_bundle(
                  version="2", root=install, token="fixture-secret",
                  release_index_path=v2_index_path, opener=v2_opener),
                  "destination already exists")
              and len(v2_calls) == before_v2_collision)
        cross_calls = []
        def cross_opener(request):
            cross_calls.append(request)
            return Response(b"")
        cross_root_1 = os.path.join(root, "cross-index-1")
        cross_root_2 = os.path.join(root, "cross-index-2")
        cross_root_3 = os.path.join(root, "cross-index-asset")
        os.mkdir(cross_root_1)
        os.mkdir(cross_root_2)
        os.mkdir(cross_root_3)
        wrong_asset_index = dict(v2_index)
        wrong_asset_index["asset_name"] = ASSET_NAME
        wrong_asset_index["digest"] = "0" * 64
        wrong_asset_index["digest"] = _document_digest(wrong_asset_index)
        wrong_asset_index_path = os.path.join(
            root, "release-index-v2-wrong-asset.json")
        _write_json(wrong_asset_index_path, wrong_asset_index)
        check("release indexes cannot cross bundle versions",
              refused(lambda: fetch_bundle(
                  version="2", root=cross_root_1,
                  release_index_path=release_index_path,
                  opener=cross_opener), "release index is malformed")
              and refused(lambda: fetch_bundle(
                  version="1", root=cross_root_2,
                  release_index_path=v2_index_path,
                  opener=cross_opener), "release index is malformed")
              and refused(lambda: fetch_bundle(
                  version="2", root=cross_root_3,
                  release_index_path=wrong_asset_index_path,
                  opener=cross_opener), "release index is malformed")
              and not cross_calls)

        broken = dict(release_index)
        broken["asset_bytes"] += 1
        broken["digest"] = "0" * 64
        broken["digest"] = _document_digest(broken)
        broken_path = os.path.join(root, "broken-index.json")
        _write_json(broken_path, broken)
        failed_root = os.path.join(root, "failed-install")
        os.mkdir(failed_root)
        failure_calls = []
        def failure_opener(request):
            failure_calls.append(request)
            if len(failure_calls) == 1:
                return Response(json.dumps({"assets": [{
                    "name": ASSET_NAME,
                    "url": "https://api.github.test/assets/2"}]}).encode())
            return Response(archive_raw)
        check("asset length mismatch installs neither destination",
              refused(lambda: fetch_bundle(
                  version="1", root=failed_root, token="fixture-secret",
                  release_index_path=broken_path, opener=failure_opener),
                  "differs from release index")
              and not os.path.lexists(_at(failed_root, BUNDLE_ROOT))
              and not os.path.lexists(_at(failed_root, PROJECT_ROOT)))

        extracted = os.path.join(root, "extracted")
        os.mkdir(extracted)
        _inspect_archive(out_b, extracted, selected=_V1)
        compact_inputs = slice3_inputs(extracted)
        check("installed bundle exposes the compact Slice-3 authority",
              len(compact_inputs["release"]["item_rows"]) == 117
              and compact_inputs["assets"]["validation_class"]
              == "native")
        paid_assets = validate_installed_mutation_inputs(
            validation_path=_at(
                extracted, FILE_ROLES["mutation_validation"]),
            manifest_path=compact_inputs["manifest_path"],
            map_path=compact_inputs["map_path"],
            release_path=_at(extracted, FILE_ROLES["execution_release"]))
        check("compact mutation authority validates the 111-item paid view",
              paid_assets["release_items"] == 111
              and paid_assets["validation_class"] == "native")
        from .. import cli
        from ..bench import cli as bench_cli
        from ..data import bundle as generic_bundle
        import contextlib
        import io
        native_facts = validate_bundle(extracted)
        validate_output = io.StringIO()
        fetch_calls = []
        real_generic_fetch = generic_bundle.fetch_bundle
        generic_bundle.fetch_bundle = lambda **kwargs: (
            fetch_calls.append(kwargs) or {"unexpected": "fetch"})
        try:
            with generic_bundle._using_data_root(extracted), \
                    contextlib.redirect_stdout(validate_output):
                validate_rc = cli.main([
                    "bundle", "validate", "--project", PROJECT,
                    "--version", "1"])
        finally:
            generic_bundle.fetch_bundle = real_generic_fetch
        check("bundle validate returns the native facts for the same staged "
              "Algorand tree without fetching",
              validate_rc == 0
              and json.loads(validate_output.getvalue()) == native_facts
              and not fetch_calls)

        absent_install = os.path.join(root, "absent-installation")
        os.mkdir(absent_install)
        absent_message = ""
        try:
            with generic_bundle._using_data_root(absent_install):
                cli.main([
                    "bundle", "validate", "--project", PROJECT,
                    "--version", "1"])
        except SystemExit as exc:
            absent_message = str(exc)
        check("bundle validate refuses an absent installation",
              "cannot read bundle manifest" in absent_message
              and not os.listdir(absent_install), absent_message)

        captured_args = []
        real_mutation_run = bench_cli.cmd_mutation_run
        bench_cli.cmd_mutation_run = lambda args: (
            captured_args.append(args) or 0)
        try:
            parse_rc = cli.main([
                "mutation-run",
                "--mutation-validation", _at(
                    extracted, FILE_ROLES["mutation_validation"]),
                "--manifest", compact_inputs["manifest_path"],
                "--seed", _at(extracted, TREE_ROLES["stripped_seed"][0]),
                "--worker-pool", os.path.join(root, "worker0.json"),
                "--map", compact_inputs["map_path"],
                "--candidate", _at(
                    extracted, FILE_ROLES["execution_release"]),
                "--release", _at(
                    extracted, FILE_ROLES["execution_release"]),
                "--out", os.path.join(root, "mutation-output"),
            ])
        finally:
            bench_cli.cmd_mutation_run = real_mutation_run
        compact_args = captured_args[0]
        cli_assets = bench_cli._validated_mutation_assets(
            compact_args, paid_view_subset=True, compact_allowed=True)
        try:
            bench_cli._validated_mutation_assets(
                compact_args, paid_view_subset=True, compact_allowed=False)
        except attestation.MutationAssetRefused:
            unbound_compact_refused = True
        else:
            unbound_compact_refused = False
        check("mutation-run routes compact authority only under Slice-3",
              parse_rc == 0 and len(captured_args) == 1
              and compact_args.algorand_bundle_version == "1"
              and os.fspath(compact_args.boundary)
              != _at(extracted, FILE_ROLES["boundary"])
              and cli_assets["release_items"] == 111
              and unbound_compact_refused)

        extracted_v2 = os.path.join(root, "extracted-v2")
        os.mkdir(extracted_v2)
        _inspect_archive(v2_b, extracted_v2, selected=v2)
        compact_v2 = slice3_inputs(extracted_v2, version="2")
        captured_v2_args = []
        bench_cli.cmd_mutation_run = \
            lambda args: captured_v2_args.append(args) or 0
        try:
            parse_v2_rc = cli.main([
                "mutation-run", "--algorand-bundle-version", "2",
                "--mutation-validation", _at(
                    extracted_v2, v2.file_roles["mutation_validation"]),
                "--manifest", compact_v2["manifest_path"],
                "--seed", _at(
                    extracted_v2, v2.tree_roles["stripped_seed"][0]),
                "--worker-pool", os.path.join(root, "worker-v2.json"),
                "--map", compact_v2["map_path"],
                "--candidate", _at(
                    extracted_v2, v2.file_roles["execution_release"]),
                "--release", _at(
                    extracted_v2, v2.file_roles["execution_release"]),
                "--out", os.path.join(root, "mutation-output-v2"),
            ])
        finally:
            bench_cli.cmd_mutation_run = real_mutation_run
        compact_v2_args = captured_v2_args[0]
        cli_v2_assets = bench_cli._validated_mutation_assets(
            compact_v2_args, paid_view_subset=True, compact_allowed=True,
            algorand_bundle_version=compact_v2_args.algorand_bundle_version)
        check("explicit mutation-run v2 routing selects only installed v2 "
              "roles",
              parse_v2_rc == 0 and len(captured_v2_args) == 1
              and compact_v2_args.algorand_bundle_version == "2"
              and cli_v2_assets["release_items"] == 111
              and refused(lambda: validate_installed_mutation_inputs(
                  validation_path=compact_v2_args.mutation_validation,
                  manifest_path=compact_v2_args.manifest,
                  map_path=compact_v2_args.map,
                  release_path=compact_v2_args.release),
                  "outside its bundle role")
              and refused(lambda: validate_installed_mutation_inputs(
                  validation_path=compact_args.mutation_validation,
                  manifest_path=compact_args.manifest,
                  map_path=compact_args.map,
                  release_path=compact_args.release, version="2"),
                  "outside its bundle role")
              and refused(lambda: validate_installed_mutation_inputs(
                  validation_path=compact_v2_args.mutation_validation,
                  manifest_path=compact_args.manifest,
                  map_path=compact_args.map,
                  release_path=compact_v2_args.release, version="2"),
                  "differ from installed roles"))
        captured_recall = []
        real_recall = bench_cli.cmd_recall
        bench_cli.cmd_recall = lambda args: captured_recall.append(args) or 0
        try:
            recall_rc = cli.main([
                "recall", "--algorand-bundle-version", "2",
                "--baseline", os.path.join(root, "baseline.jsonl"),
                "--results", os.path.join(root, "candidate.jsonl"),
                "--gold-results", os.path.join(root, "gold.jsonl"),
            ])
            recall_v3_rc = cli.main([
                "recall", "--algorand-bundle-version", "3",
                "--baseline", os.path.join(root, "baseline-v3.jsonl"),
                "--results", os.path.join(root, "candidate-v3.jsonl"),
                "--gold-results", os.path.join(root, "gold-v3.jsonl"),
            ])
        finally:
            bench_cli.cmd_recall = real_recall
        check("recall keeps the existing installed v2/v3 selections",
              recall_rc == 0 and recall_v3_rc == 0
              and [args.algorand_bundle_version for args in captured_recall]
              == ["2", "3"])
        closed_route_errors = []
        for closed_argv in ([
                "mutation-run", "--algorand-bundle-version", "4",
                "--mutation-validation", "validation.json",
                "--manifest", "manifest.json", "--seed", "seed",
                "--worker-pool", "workers.json", "--map", "map.json",
                "--candidate", "candidate.jsonl", "--release",
                "release.jsonl", "--out", "out"], [
                "recall", "--algorand-bundle-version", "4",
                "--baseline", "baseline.jsonl", "--results",
                "candidate.jsonl", "--gold-results", "gold.jsonl"], [
                "mutation-run", "--algorand-bundle-version", "5",
                "--mutation-validation", "validation.json",
                "--manifest", "manifest.json", "--seed", "seed",
                "--worker-pool", "workers.json", "--map", "map.json",
                "--candidate", "candidate.jsonl", "--release",
                "release.jsonl", "--out", "out"], [
                "recall", "--algorand-bundle-version", "5",
                "--baseline", "baseline.jsonl", "--results",
                "candidate.jsonl", "--gold-results", "gold.jsonl"]):
            closed_stderr = io.StringIO()
            try:
                with contextlib.redirect_stderr(closed_stderr):
                    cli.main(closed_argv)
            except SystemExit as exc:
                closed_route_errors.append(
                    exc.code == 2 and "invalid choice:"
                    in closed_stderr.getvalue())
            else:
                closed_route_errors.append(False)
        check("v4 and v5 remain closed on live mutation and recall routes",
              closed_route_errors == [True, True, True, True])
        from . import algorand_bundle as installed_algorand
        captured_builds = []
        real_installed_build = installed_algorand.build_bundle
        installed_algorand.build_bundle = \
            lambda **kwargs: captured_builds.append(kwargs) or {
                "fixture": True}
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                build_v1_rc = cli.main([
                    "bundle", "build-algorand", "--inputs", descriptor,
                    "--out", os.path.join(root, "cli-v1.tar.gz")])
                build_v2_rc = cli.main([
                    "bundle", "build-algorand", "--version", "2",
                    "--inputs", v2_descriptor,
                    "--out", os.path.join(root, "cli-v2.tar.gz")])
                build_v3_rc = cli.main([
                    "bundle", "build-algorand", "--version", "3",
                    "--inputs", v3_descriptor,
                    "--out", os.path.join(root, "cli-v3.tar.gz")])
                build_v4_rc = cli.main([
                    "bundle", "build-algorand", "--version", "4",
                    "--inputs", v4_descriptor,
                    "--out", os.path.join(root, "cli-v4.tar.gz")])
                build_v5_rc = cli.main([
                    "bundle", "build-algorand", "--version", "5",
                    "--inputs", v5_descriptor,
                    "--out", os.path.join(root, "cli-v5.tar.gz")])
        finally:
            installed_algorand.build_bundle = real_installed_build
        check("bundle build CLI preserves v1-v4 and explicitly routes v5",
              build_v1_rc == 0 and build_v2_rc == 0 and build_v3_rc == 0
              and build_v4_rc == 0 and build_v5_rc == 0
              and [call["version"] for call in captured_builds]
              == ["1", "2", "3", "4", "5"])
        other = os.path.join(extracted, "projects", "other", "kept.txt")
        os.makedirs(os.path.dirname(other))
        Path(other).write_text("other bundle\n", encoding="utf-8")
        check("installed validation permits another project in the data root",
              slice3_inputs(extracted)["assets"]["asset_project"] == PROJECT)
        empty = _at(extracted, TREE_ROLES["gold"][0] + "/empty")
        os.mkdir(empty)
        check("an unowned empty archive directory refuses",
              refused(lambda: validate_bundle(extracted),
                      "directory inventory"))
        os.rmdir(empty)
        extra = _at(extracted, TREE_ROLES["gold"][0] + "/extra.java")
        Path(extra).write_text("extra\n", encoding="utf-8")
        check("an extra tree file refuses the installed bundle",
              refused(lambda: validate_bundle(extracted), "tree manifest"))

    print("\n" + ("ALL PASS (algorand_bundle)" if ok
                  else "FAILURES (algorand_bundle)"))
    return 0 if ok else 1


if __name__ == "__main__":
    # Generic dispatch imports the package spelling.  Keep the standalone
    # module self-test on this same instance so its fixture-local V4 pins are
    # not split across two module objects.
    import sys
    sys.modules.setdefault("r2t.toolkit.algorand_bundle", sys.modules[__name__])
    raise SystemExit(selftest())
