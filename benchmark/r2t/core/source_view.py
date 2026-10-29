"""Shared, parser-free source-view builder (IMPLEMENTATION_VISIBILITY_SPEC §5).

Selectors resolve language declarations and review delegation. This module
qualifies bytes, applies their edits, and verifies the actual derived tree.
It never executes subject code or changes the original execution repository.
A valid manifest proves a transformation, not completeness of its reviewed map.

A target-hidden plan may also carry reviewed repairs (BENCHMARK_V2_SPEC
section 3.2): whole-file bytes that replace or add view files after the
transformation, matched by `runtime_pack.init_attempt`'s rule.  They are data,
never generated here.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Mapping

from .ledger_primitives import domain_digest, semantic_digest, loads_exact_json
from .paths import locate_recorded

FILE_TREE_DOMAIN = "r2t.file-tree/v1"
VIEW_SCHEMA = "r2t.agent-view/v1"
SCOPES = ("full", "target_hidden", "all_hidden")
# Exact exception approved by CORESHOP_ZERO_BODY_TREATMENT_AMENDMENT (#483).
ZERO_BODY_ITEM_IDS = frozenset({
    "coreshop/features/domain/category/create_category.feature:13",
    "coreshop/features/domain/category/create_category.feature:19",
    "coreshop/features/domain/product/adding_product_category.feature:6",
})


class ViewRefused(ValueError):
    """A source, selection, or actual workspace disagrees with its binding."""


def _need(value, message):
    if not value:
        raise ViewRefused(message)


def _path(value: str) -> str:
    _need(isinstance(value, str) and value and "\\" not in value,
          "view path must be a relative POSIX path")
    parsed = PurePosixPath(value)
    _need(not parsed.is_absolute() and str(parsed) == value
          and all(p not in (".", "..") for p in parsed.parts),
          f"non-canonical view path: {value!r}")
    return value


def _digest(value: str, label: str) -> str:
    _need(isinstance(value, str) and len(value) == 64
          and all(c in "0123456789abcdef" for c in value),
          f"invalid {label} digest")
    return value


def file_record(path: str, raw: bytes) -> dict:
    return {"path": _path(path), "byte_length": len(raw),
            "file_sha256": hashlib.sha256(raw).hexdigest()}


def file_tree_digest(records: list) -> str:
    """The existing ledger file-tree identity, shared with confined evidence."""
    return domain_digest(FILE_TREE_DOMAIN, records)


def _records(records) -> tuple:
    _need(isinstance(records, (tuple, list)), "files must be an inventory")
    paths = []
    for record in records:
        _need(isinstance(record, Mapping)
              and set(record) == {"path", "byte_length", "file_sha256"},
              "invalid view file record")
        paths.append(_path(record["path"]))
        _need(type(record["byte_length"]) is int and record["byte_length"] >= 0,
              "invalid view file length")
        _digest(record["file_sha256"], "file")
    _need(paths == sorted(set(paths)), "view inventory must be sorted and unique")
    return tuple(FileRecord(**record) for record in records)


@dataclass(frozen=True)
class FileRecord:
    path: str
    byte_length: int
    file_sha256: str


@dataclass(frozen=True)
class SourceSeed:
    root: str
    project: str
    runtime_seed_digest: str
    files: tuple[FileRecord, ...]

    @property
    def files_digest(self) -> str:
        return file_tree_digest([asdict(f) for f in self.files])


@dataclass(frozen=True)
class BodyRef:
    path: str
    declaration_id: str
    kind: str
    start_byte: int
    end_byte: int


@dataclass(frozen=True)
class BodyEdit:
    body: BodyRef
    replacement: bytes


@dataclass(frozen=True)
class ContractFile:
    path: str
    content: bytes


@dataclass(frozen=True)
class Selection:
    """Resolved edits plus reviewed resource omissions; supplied by a selector."""
    bodies: tuple[BodyEdit, ...] = ()
    omitted_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class GeneratedOperationJudgment:
    operation: str
    realizes_target_behavior: bool
    treatment: str
    reason: str


def parse_generated_operation_judgments(records) -> tuple[GeneratedOperationJudgment, ...]:
    """Read the reviewed per-item evidence from a map or evaluator manifest."""
    _need(isinstance(records, list), "generated_operation_judgments must be a list")
    fields = {"operation", "realizes_target_behavior", "treatment", "reason"}
    for record in records:
        _need(isinstance(record, Mapping) and set(record) == fields,
              "invalid generated-operation judgment fields")
        _need(type(record["realizes_target_behavior"]) is bool,
              "generated-operation realizes_target_behavior must be boolean")
        _need(all(isinstance(record[key], str) and record[key]
                  for key in ("operation", "treatment", "reason")),
              "generated-operation judgment needs operation, treatment and reason")
    return tuple(GeneratedOperationJudgment(**record) for record in records)


@dataclass(frozen=True)
class ZeroBodyTreatment:
    decision: str
    reason: str

    def __post_init__(self):
        _need(self.decision == "unchanged_target_hidden",
              "invalid zero-body treatment decision")
        _need(isinstance(self.reason, str) and self.reason.strip(),
              "zero-body treatment requires a nonempty reason")


def parse_zero_body_treatment(record) -> ZeroBodyTreatment:
    """Read the approved explicit exception, never infer it from an empty map."""
    _need(isinstance(record, Mapping) and set(record) == {"decision", "reason"},
          "invalid zero-body treatment fields")
    return ZeroBodyTreatment(**record)


@dataclass(frozen=True)
class ItemSelection:
    item_id: str
    principals: tuple[str, ...]
    selection: Selection
    generated_operation_judgments: tuple[GeneratedOperationJudgment, ...] = ()
    zero_body_treatment: ZeroBodyTreatment | None = None


@dataclass(frozen=True)
class TargetMap:
    """Reviewed mapping input. #405 supplies all_selection using its inventory."""
    project: str
    source_files_digest: str
    population_digest: str
    interfaces_digest: str
    items: tuple[ItemSelection, ...]
    contracts: tuple[ContractFile, ...] = ()
    all_selection: Selection | None = None

    def document(self) -> dict:
        value = asdict(self)
        # JSON preserves exact bytes without assuming the subject encoding.
        for item in value["items"]:
            for edit in item["selection"]["bodies"]:
                edit["replacement"] = edit["replacement"].hex()
        if value["all_selection"] is not None:
            for edit in value["all_selection"]["bodies"]:
                edit["replacement"] = edit["replacement"].hex()
        for contract in value["contracts"]:
            contract["content"] = contract["content"].hex()
        return {"schema": "r2t.visibility-map/v1", **value}

    @property
    def digest(self) -> str:
        return semantic_digest(self.document())


@dataclass(frozen=True)
class ViewPolicy:
    project: str
    scope: str
    profile_digest: str
    protocol_digest: str
    boundary_digest: str
    # Explicit first-party file inventory, excluding retained/third-party data.
    subject_paths: tuple[str, ...]
    transformer: str
    feedback: str = "final_only"

    @property
    def digest(self) -> str:
        return semantic_digest({"schema": "r2t.visibility-policy/v1", **asdict(self)})


@dataclass(frozen=True)
class RepairEntry:
    """One reviewed TH-view repair (BENCHMARK_V2_SPEC section 3.2).

    The view file at `path` whose sha256 is `th_sha256` becomes `content`;
    with `th_sha256` None, `content` is added at `path` when the view lacks it.
    """
    path: str
    th_sha256: str | None
    repaired_sha256: str
    rule: str
    content: bytes


REPAIR_FIELDS = frozenset({"path", "th_sha256", "repaired_sha256", "rule"})


def parse_repair_set(records, blob) -> tuple[RepairEntry, ...]:
    """Read a reviewed repair index: `{path, th_sha256, repaired_sha256, rule}`
    entries, with `blob(repaired_sha256)` returning the bytes stored under that
    name.  Refuses a malformed entry, two entries for one `(path, th_sha256)`
    and a blob whose sha256 differs from its name."""
    _need(isinstance(records, list), "repair index must be a list of entries")
    entries, keys, blobs = [], set(), {}
    for record in records:
        _need(isinstance(record, Mapping) and set(record) == REPAIR_FIELDS,
              "invalid repair entry fields")
        path, th, sha = _path(record["path"]), record["th_sha256"], record["repaired_sha256"]
        if th is not None:
            _digest(th, "repair th")
        _digest(sha, "repaired")
        _need(isinstance(record["rule"], str) and bool(record["rule"]),
              f"repair entry for {path} names no rule")
        _need((path, th) not in keys, f"two repairs for one view file: {path} {th}")
        keys.add((path, th))
        if sha not in blobs:
            raw = blob(sha)
            _need(isinstance(raw, bytes) and hashlib.sha256(raw).hexdigest() == sha,
                  f"repair blob {sha} holds other bytes")
            blobs[sha] = raw
        entries.append(RepairEntry(path, th, sha, record["rule"], blobs[sha]))
    return tuple(entries)


@dataclass(frozen=True)
class AgentViewPlan:
    source_seed: SourceSeed
    item_id: str
    policy: ViewPolicy
    target_map: TargetMap
    selection: Selection
    generated_operation_judgments: tuple[GeneratedOperationJudgment, ...]
    zero_body_treatment: ZeroBodyTreatment | None
    #: Reviewed repairs, applied by `build_agent_view`; target-hidden only.
    repairs: tuple[RepairEntry, ...] = ()


# Manifests are JSON objects, so the confined consumer only needs stdlib code.
AgentViewManifest = dict


def inventory(root: str, readable_paths: tuple[str, ...] | None = None) -> tuple[FileRecord, ...]:
    """Inventory exact regular files; symlinks and other leaves are refused."""
    base = Path(root)
    _need(base.is_dir() and not base.is_symlink(), "view root is not a regular directory")
    found = {}

    def visit(path: Path):
        mode = path.lstat().st_mode
        _need(stat.S_ISDIR(mode) or stat.S_ISREG(mode),
              f"non-regular view entry: {path.relative_to(base)}")
        if stat.S_ISDIR(mode):
            for child in sorted(path.iterdir()):
                visit(child)
        else:
            relative = path.relative_to(base).as_posix()
            found[relative] = FileRecord(**file_record(relative, path.read_bytes()))

    for relative in readable_paths if readable_paths is not None else ("",):
        if relative:
            _path(relative)
            # lstat every path component so a symlink is never followed.
            current = base
            for part in PurePosixPath(relative).parts:
                current = current / part
                _need(current.exists() and not current.is_symlink(),
                      f"missing or aliased readable path: {relative}")
        visit(base / relative)
    return tuple(found[key] for key in sorted(found))


def qualify_source_seed(*, root: str, project: str, runtime_seed_digest: str,
                        readable_paths: tuple[str, ...] | None = None) -> SourceSeed:
    """Qualify an already stripped, coordinator-only original source projection."""
    _digest(runtime_seed_digest, "runtime seed")
    _need(isinstance(project, str) and bool(project), "missing source project")
    return SourceSeed(os.path.abspath(root), project, runtime_seed_digest,
                      inventory(root, readable_paths))


def _selection(selection: Selection, seed: SourceSeed, policy: ViewPolicy) -> Selection:
    files = {f.path: f for f in seed.files}
    subjects = set(policy.subject_paths)
    _need(len(subjects) == len(policy.subject_paths), "duplicate subject path")
    for path in subjects:
        _path(path)
    _need(subjects <= files.keys(), "subject inventory names absent source")
    omissions = set(selection.omitted_paths)
    _need(len(omissions) == len(selection.omitted_paths)
          and omissions <= subjects, "invalid omitted resource selection")
    edits = sorted(selection.bodies, key=lambda e: (e.body.path, e.body.start_byte,
                                                  -e.body.end_byte, e.body.declaration_id))
    selected = []
    identities = {}
    for edit in edits:
        body = edit.body
        _need(body.path in subjects and body.path not in omissions,
              f"body is not a retained subject file: {body.path}")
        _need(body.declaration_id and body.kind, "body declaration identity is empty")
        _need(type(body.start_byte) is int and type(body.end_byte) is int
              and 0 <= body.start_byte <= body.end_byte <= files[body.path].byte_length,
              f"invalid body span: {body.declaration_id}")
        _need(isinstance(edit.replacement, bytes) and edit.replacement,
              "body replacement must be nonempty bytes")
        identity = (body.path, body.declaration_id, body.kind)
        if identity in identities:
            _need(identities[identity] == edit,
                  f"conflicting body declaration: {identity}")
            continue  # Several reviewed delegation paths can reach one body.
        identities[identity] = edit
        if selected and selected[-1].body.path == body.path:
            previous = selected[-1].body
            if body.start_byte < previous.end_byte:
                _need(body.end_byte <= previous.end_byte,
                      f"partially overlapping body spans: {body.declaration_id}")
                # An enclosing selected body already removes this nested body.
                continue
        selected.append(edit)
    return Selection(tuple(selected), tuple(sorted(omissions)))


def plan_agent_view(*, source_seed: SourceSeed, item_id: str,
                    policy: ViewPolicy, target_map: TargetMap,
                    repairs: tuple[RepairEntry, ...] = ()) -> AgentViewPlan:
    _need(policy.scope in SCOPES, "unsupported source visibility scope")
    repairs = tuple(repairs)
    _need(all(isinstance(entry, RepairEntry) for entry in repairs), "invalid repair entries")
    _need(not repairs or policy.scope == "target_hidden",
          "repairs apply to target-hidden views only")
    _need(policy.feedback == "final_only", "source views require final-only feedback")
    _need(bool(policy.transformer), "missing transformer identity")
    for name in ("profile_digest", "protocol_digest", "boundary_digest"):
        _digest(getattr(policy, name), name)
    _need(source_seed.project == policy.project == target_map.project,
          "source, map and policy projects disagree")
    _need(source_seed.files_digest == target_map.source_files_digest,
          "visibility map belongs to different source bytes")
    _digest(target_map.population_digest, "population")
    _digest(target_map.interfaces_digest, "interfaces")
    item_ids = [i.item_id for i in target_map.items]
    _need(all(isinstance(i, str) and i for i in item_ids)
          and len(item_ids) == len(set(item_ids)), "invalid map item identities")
    matches = [item for item in target_map.items if item.item_id == item_id]
    _need(len(matches) == 1, f"visibility map has no unique item: {item_id}")
    selected = matches[0].selection
    zero_body_treatment = matches[0].zero_body_treatment
    if zero_body_treatment is not None:
        _need(policy.project == "coreshop" and item_id in ZERO_BODY_ITEM_IDS,
              "zero-body treatment is not approved for this project/item")
        _need(not selected.bodies and not selected.omitted_paths,
              "zero-body treatment requires an empty target selection")
    if policy.scope == "all_hidden":
        _need(target_map.all_selection is not None,
              "all-hidden view requires the all-production selector's inventory")
        selected = target_map.all_selection
    elif policy.scope == "full":
        selected = Selection()
    selected = _selection(selected, source_seed, policy)
    existing = {f.path for f in source_seed.files}
    additions = set()
    for contract in target_map.contracts:
        _path(contract.path)
        _need(isinstance(contract.content, bytes), "contract content must be bytes")
        _need(contract.path not in existing | additions,
              f"contract supplement overwrites an existing file: {contract.path}")
        additions.add(contract.path)
    paths = existing | additions
    for path in paths:
        _need(not any(str(parent) in paths for parent in PurePosixPath(path).parents
                      if str(parent) != "."), f"file/directory collision: {path}")
    # Scope replaces the body selection, never the item's reviewed judgments.
    return AgentViewPlan(source_seed, item_id, policy, target_map, selected,
                         matches[0].generated_operation_judgments, zero_body_treatment,
                         repairs)


def _bindings(plan: AgentViewPlan) -> dict:
    return {"project": plan.policy.project, "item_id": plan.item_id,
            "runtime_seed_digest": plan.source_seed.runtime_seed_digest,
            "source_files_digest": plan.source_seed.files_digest,
            "policy_digest": plan.policy.digest, "map_digest": plan.target_map.digest,
            "population_digest": plan.target_map.population_digest,
            "interfaces_digest": plan.target_map.interfaces_digest,
            "scope": plan.policy.scope, "feedback": plan.policy.feedback,
            "generated_operation_judgments": [asdict(judgment) for judgment
                                              in plan.generated_operation_judgments],
            "zero_body_treatment": (asdict(plan.zero_body_treatment)
                                    if plan.zero_body_treatment is not None else None)}


def _source_bytes(seed: SourceSeed, record: FileRecord) -> bytes:
    path = Path(seed.root, record.path)
    _need(path.is_file(), f"missing source: {record.path}")
    raw = path.read_bytes()
    _need(file_record(record.path, raw) == asdict(record),
          f"source changed since qualification: {record.path}")
    return raw


def _apply_repairs(output: dict, repairs) -> tuple[RepairEntry, ...]:
    """Apply `repairs` to the transformed view `output` in memory.

    `runtime_pack.init_attempt`'s rule, unchanged, because the c2r census ran
    under it: an entry applies where the view has `path` with sha256
    `th_sha256`, or lacks `path` (no file, no directory) when that is None.
    Every entry is matched against the view as transformed before any is
    applied, so no entry matches another's output; entries that match nothing
    belong to other instances.  The view's files are all written alike, so a
    replaced file keeps its mode and an added one gets the same (0644 under
    the runner's umask 022).  Returns the entries that applied.
    """
    directories = {str(parent) for path in output
                   for parent in PurePosixPath(path).parents if str(parent) != "."}
    found = {}
    for entry in repairs:
        if entry.path not in found:
            raw = output.get(entry.path)
            found[entry.path] = (hashlib.sha256(raw).hexdigest() if raw is not None
                                 else "" if entry.path in directories else None)
    applied = tuple(entry for entry in repairs if found[entry.path] == entry.th_sha256)
    for entry in applied:
        _need(not any(str(parent) in output for parent in PurePosixPath(entry.path).parents),
              f"repair adds a file below a view file: {entry.path}")
        output[entry.path] = entry.content
    return applied


def build_agent_view(plan: AgentViewPlan, *, destination: str,
                     applied: list | None = None) -> AgentViewManifest:
    """Apply the reviewed transformation outside the source; no-clobber output.

    The plan's repairs are applied after the transformation and before any
    byte is written, so the manifest's `files` describe the repaired bytes
    while `hidden_bodies` and `omitted_paths` still say what the map hid.
    With `applied`, the repair entries that applied are appended to it.
    """
    source = Path(plan.source_seed.root).resolve()
    destination = Path(destination)
    resolved = destination.resolve()
    _need(resolved != source and source not in resolved.parents,
          "agent view destination must be outside its source")
    _need(not os.path.lexists(destination), "agent view destination already exists")
    # Read/transform before writing anything: stale input cannot leave a view.
    output = {}
    changes = {}
    for edit in plan.selection.bodies:
        changes.setdefault(edit.body.path, []).append(edit)
    for record in plan.source_seed.files:
        raw = _source_bytes(plan.source_seed, record)
        if record.path in plan.selection.omitted_paths:
            continue
        for edit in reversed(changes.get(record.path, [])):
            body = edit.body
            raw = raw[:body.start_byte] + edit.replacement + raw[body.end_byte:]
        output[record.path] = raw
    for contract in plan.target_map.contracts:
        output[contract.path] = contract.content
    repaired = _apply_repairs(output, plan.repairs)
    if applied is not None:
        applied.extend(repaired)
    destination.mkdir(parents=True, exist_ok=False)
    for path, raw in sorted(output.items()):
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
    files = [file_record(path, raw) for path, raw in sorted(output.items())]
    manifest = {"schema": VIEW_SCHEMA, **_bindings(plan), "files": files,
                "files_digest": file_tree_digest(files),
                "hidden_bodies": [asdict(edit.body) for edit in plan.selection.bodies],
                "omitted_paths": list(plan.selection.omitted_paths)}
    manifest["digest"] = semantic_digest(manifest)
    verify_agent_view(str(destination), manifest)
    return manifest


def validate_view_manifest(manifest: Mapping) -> tuple[FileRecord, ...]:
    fields = {"schema", "project", "item_id", "runtime_seed_digest",
              "source_files_digest", "policy_digest", "map_digest",
              "population_digest", "interfaces_digest", "scope", "feedback",
              "files", "files_digest", "hidden_bodies", "omitted_paths", "digest",
              "generated_operation_judgments", "zero_body_treatment"}
    _need(isinstance(manifest, Mapping) and set(manifest) == fields,
          "invalid agent-view manifest fields")
    _need(manifest["schema"] == VIEW_SCHEMA and manifest["scope"] in SCOPES
          and manifest["feedback"] == "final_only", "invalid agent-view policy")
    for name in fields:
        if name.endswith("digest"):
            _digest(manifest[name], name)
    _need(manifest["digest"] == semantic_digest(manifest), "view manifest digest mismatch")
    parse_generated_operation_judgments(manifest["generated_operation_judgments"])
    if manifest["zero_body_treatment"] is not None:
        parse_zero_body_treatment(manifest["zero_body_treatment"])
        _need(manifest["project"] == "coreshop" and manifest["item_id"] in ZERO_BODY_ITEM_IDS,
              "zero-body treatment is not approved for this project/item")
        if manifest["scope"] != "all_hidden":
            _need(manifest["hidden_bodies"] == [] and manifest["omitted_paths"] == [],
                  "zero-body treatment requires an unchanged full/target view")
    records = _records(manifest["files"])
    _need(manifest["files_digest"] == file_tree_digest(manifest["files"]),
          "view files digest mismatch")
    return records


def verify_agent_view(root: str, manifest: Mapping) -> None:
    records = validate_view_manifest(manifest)
    _need(inventory(root) == records, "actual agent view differs from approved inventory")


def verify_view_bindings(manifest: Mapping, plan: AgentViewPlan) -> None:
    """Join authenticated view evidence to this run's source/item/condition."""
    _need(all(manifest.get(key) == value for key, value in _bindings(plan).items()),
          "agent view is bound to another source, item, map or policy")


def _infrastructure_row(row: Mapping) -> bool:
    """The recorded shapes that are an outage rather than an answer.

    The same vocabulary the generation cache already resumes on
    (`generate._resume`): an exception inside the adapter, a harness crash
    written down as a row, and a conversation the transport killed with nothing
    written.  A run error WITH files is a partial answer and an empty file list
    without a marker is an answer, so neither of those is exempt.
    """
    metadata = row.get("metadata") or {}
    if metadata.get("adapter_error") or metadata.get("harness_error"):
        return True
    run_errors = (metadata.get("agent_stats") or {}).get("run_errors")
    return bool(run_errors) and not row.get("produced_files")


def verify_recorded_view(row: Mapping) -> dict:
    """Resume/replay retain consumed per-item view evidence, not just a label.

    Returns the `R2T_RECORDED_ROOTS` entry the manifest was read through, or
    `{}` when it was read at its recorded path (or the row names none).  Every
    byte, digest and identity check below applies to the bytes actually read.
    """
    identity = row.get("visibility")
    if identity is None:
        return {}
    _need(isinstance(identity, dict) and identity.get("schema") == "r2t.visibility-run/v1",
          "invalid recorded visibility identity")
    reference = (row.get("metadata") or {}).get("agent_view")
    if reference is None:
        # Infrastructure failures may happen before materialization or after
        # the manifest is saved but before its reference reaches the row.
        # Either case can lack a reference; any supplied reference is still
        # validated in full below.
        _need(_infrastructure_row(row),
              "recorded source view has no manifest reference")
        return {}
    _need(isinstance(reference, dict)
          and set(reference) == {"path", "file_sha256", "digest"},
          "recorded source view has no manifest reference")
    _need(isinstance(reference["path"], str) and os.path.isabs(reference["path"]),
          "recorded source-view manifest path is not absolute")
    try:
        located, relocated = locate_recorded(reference["path"])
        raw = Path(located).read_bytes()
        manifest = loads_exact_json(raw, label="recorded source-view manifest")
    except (OSError, RuntimeError, ValueError) as exc:
        raise ViewRefused(f"cannot read recorded source-view evidence: {exc}") from exc
    _need(hashlib.sha256(raw).hexdigest() == reference["file_sha256"],
          "recorded source-view manifest bytes changed")
    validate_view_manifest(manifest)
    _need(manifest["digest"] == reference["digest"]
          and manifest["item_id"] == row.get("item_id"),
          "recorded source-view manifest has wrong item or digest")
    for key in ("source_files_digest", "runtime_seed_digest", "map_digest", "policy_digest",
                "population_digest", "interfaces_digest", "scope", "feedback"):
        _need(identity.get(key) == manifest[key], f"recorded source-view {key} differs")
    return relocated
