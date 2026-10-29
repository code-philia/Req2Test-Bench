"""Build a reviewed, never-launchable PrestaShop continuation packet.

This builder deliberately takes every mutable path as an argument.  It never
launches Docker or mutation workers and refuses incomplete/stale parent sets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

EXPECTED_FULL = 132800
EXPECTED_RETAINED = 69065
EXPECTED_REMAINING = 63735
EXPECTED_WORKERS = 24
EXPECTED_MEMORY = 4294967296
EXPECTED_SWAP = 0
SOURCE_FILES = (
    "harness.py", "mutation_run.py", "prestashop_resources.py",
    "prestashop_continuation.py", "mutation_continuation.py",
    "worker.py", "prestashop_memory.py",
)
ADMISSION_SCHEMA = "r2t.prestashop-prefix-admission/1"
ADMISSION_DECISION = "retain_verified_prefix_after_empty_shop_repair"
PARENT_COMMIT = "17ff8fa1dafbdf9df5880245a83d7bb8511165a8"
PARENT_TAG = "onb-prestashop-memory4g-20260922"
PARENT_OBSERVATION = "544d26655aa8e5024a89e43a0ca79d27"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ref(path: Path) -> dict:
    path = path.resolve()
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"required regular file is missing: {path}")
    return {"path": str(path), "sha256": _sha256(path)}


def _parent_paths(parent_root: Path) -> list[Path]:
    native = parent_root / "native"
    paths = [native / f"gold.w{index}.jsonl" for index in range(EXPECTED_WORKERS)]
    if not native.is_dir():
        raise ValueError(f"parent native directory is missing: {native}")
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"parent shard is missing: {path}")
    return paths


def _row_count(path: Path) -> int:
    count = 0
    with path.open("rb") as handle:
        for line in handle:
            if line.strip():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSON row in {path}") from exc
                if not isinstance(row, dict):
                    raise ValueError(f"row is not an object in {path}")
                count += 1
    return count


def validate_parent_set(parent_root: Path, *, expected_rows: int = EXPECTED_RETAINED) -> list[Path]:
    paths = _parent_paths(parent_root.resolve())
    counts = [_row_count(path) for path in paths]
    if any(count <= 0 for count in counts):
        raise ValueError("every parent shard must contain durable rows")
    if sum(counts) != expected_rows:
        raise ValueError(f"parent row count {sum(counts)} != expected {expected_rows}")
    return paths


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON document: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON document is not an object: {path}")
    return value


def _validate_admission(admission: Path, parents: list[Path], output_plan: Path) -> dict:
    receipt = _load_json(admission)
    if receipt.get("schema") != ADMISSION_SCHEMA or receipt.get("decision") != ADMISSION_DECISION:
        raise ValueError("admission schema or decision differs")
    if (receipt.get("parent_source_commit"), receipt.get("parent_source_tag"),
            receipt.get("parent_observation_id")) != (PARENT_COMMIT, PARENT_TAG, PARENT_OBSERVATION):
        raise ValueError("admission parent source identity differs")
    evidence = receipt.get("parent_evidence")
    if not isinstance(evidence, dict) or set(evidence) != {"parents", "output_plan"}:
        raise ValueError("admission parent evidence is not closed")
    rows = evidence["parents"]
    if not isinstance(rows, list) or len(rows) != EXPECTED_WORKERS:
        raise ValueError("admission does not bind all 24 parent shards")
    for expected, entry in zip(parents, rows):
        if not isinstance(entry, dict) or set(entry) != {"rows", "sidecar"}:
            raise ValueError("admission parent entry is malformed")
        if entry["rows"] != _ref(expected):
            raise ValueError("admission parent row bytes differ")
        sidecar = expected.with_name(expected.name + ".provenance.json")
        if entry["sidecar"] != _ref(sidecar):
            raise ValueError("admission parent sidecar bytes differ")
    if evidence["output_plan"] != _ref(output_plan):
        raise ValueError("admission output plan differs")
    for key in ("parent_source_files", "child_source_files"):
        refs = receipt.get(key)
        if not isinstance(refs, dict) or set(refs) != {"harness.py", "mutation_run.py", "prestashop_resources.py"}:
            raise ValueError(f"admission {key} is incomplete")
    if not isinstance(receipt.get("child_core"), dict):
        raise ValueError("admission child identity is missing")
    return receipt


def _git(source: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(source), *args],
                            check=False, capture_output=True, text=True)
    if result.returncode:
        raise ValueError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _bind_source(admission_doc: dict, commit: str, source_tag: str) -> None:
    """The packet's source must be the child source the admission reviewed."""
    if (admission_doc.get("child_source_commit"), admission_doc.get("child_source_tag")) != (commit, source_tag):
        raise ValueError("admission was reviewed for a different child source commit/tag")


def build_packet(*, parent_root: Path, source: Path, output_plan: Path,
                 admission: Path, out: Path, source_tag: str | None = None) -> dict:
    source = source.resolve()
    if not source.is_dir():
        raise ValueError(f"source checkout is missing: {source}")
    if _git(source, "status", "--porcelain"):
        raise ValueError("source checkout is dirty")
    commit = _git(source, "rev-parse", "HEAD")
    if len(commit) != 40:
        raise ValueError("source commit is not a full commit identity")
    if not isinstance(source_tag, str) or not source_tag or any(ch.isspace() for ch in source_tag):
        raise ValueError("reviewed source tag is required")
    tagged = _git(source, "rev-parse", "--verify", f"refs/tags/{source_tag}^{{commit}}")
    if tagged != commit:
        raise ValueError("source tag does not resolve to source HEAD")
    parents = validate_parent_set(parent_root)
    parent_rows = [_row_count(path) for path in parents]
    output_plan = output_plan.resolve()
    if not output_plan.is_file() or output_plan.is_symlink():
        raise ValueError(f"parent output plan is missing: {output_plan}")
    admission = admission.resolve()
    if not admission.is_file() or admission.is_symlink():
        raise ValueError(f"native admission receipt is missing: {admission}")
    admission_doc = _validate_admission(admission, parents, output_plan)
    _bind_source(admission_doc, commit, source_tag)
    files = {}
    for name in SOURCE_FILES:
        path = source / "benchmark/r2t/bench" / name
        files[name] = _sha256(path)
    packet = {
        "schema": "r2t.prestashop-retained-prefix/packet/1",
        "status": "prepared_not_launched",
        "source": {"worktree": str(source), "commit": commit, "tag": source_tag,
                    "files": files},
        "parents": [_ref(path) for path in parents],
        "parent_rows": parent_rows,
        "parent_output_plan": _ref(output_plan),
        "admission": _ref(admission),
        "admission_identity": {key: admission_doc[key] for key in ("parent_source_commit", "parent_source_tag", "parent_observation_id", "child_source_commit", "child_source_tag")},
        "expected": {"retained_pairs": EXPECTED_RETAINED,
                     "remaining_pairs": EXPECTED_REMAINING,
                     "full_pairs": EXPECTED_FULL,
                     "workers": EXPECTED_WORKERS,
                     "memory_bytes": EXPECTED_MEMORY,
                     "swap_bytes": EXPECTED_SWAP},
        "holds": ["fresh repaired K24 pool-ready receipt", "final coordinator packet review"],
        "launch_policy": "No launch from this packet. Dispatch must verify exact admission, fresh pool and source hashes, then use a new observation.",
    }
    out = out.resolve()
    if out.exists():
        raise ValueError(f"refusing to overwrite packet: {out}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return packet


def selftest() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        parent = root / "parent"; (parent / "native").mkdir(parents=True)
        for index in range(24):
            (parent / "native" / f"gold.w{index}.jsonl").write_text(
                json.dumps({"shard": index}) + "\n", encoding="utf-8")
        parents = validate_parent_set(parent, expected_rows=24)
        try:
            validate_parent_set(parent)
        except ValueError:
            pass
        else:
            raise AssertionError("stale/incomplete parent set was accepted")
        for path in parents:
            path.with_name(path.name + ".provenance.json").write_text("{}\n")
        output_plan = root / "mutation-output-plan.json"; output_plan.write_text("{}\n")
        for name in ("harness.py", "mutation_run.py", "prestashop_resources.py"):
            (root / name).write_text(name + "\n")
        refs = {name: _ref(root / name) for name in ("harness.py", "mutation_run.py", "prestashop_resources.py")}
        receipt = {"schema": ADMISSION_SCHEMA, "decision": ADMISSION_DECISION,
                   "parent_source_commit": PARENT_COMMIT, "parent_source_tag": PARENT_TAG,
                   "parent_observation_id": PARENT_OBSERVATION,
                   "parent_source_files": refs, "child_source_files": refs,
                   "child_core": {}, "parent_evidence": {
                       "parents": [{"rows": _ref(path), "sidecar": _ref(path.with_name(path.name + ".provenance.json"))} for path in parents],
                       "output_plan": _ref(output_plan)}}
        admission = root / "admission.json"; admission.write_text(json.dumps(receipt) + "\n")
        _validate_admission(admission, parents, output_plan)
        receipt["parent_evidence"]["parents"][0]["rows"]["sha256"] = "0" * 64
        admission.write_text(json.dumps(receipt) + "\n")
        try:
            _validate_admission(admission, parents, output_plan)
        except ValueError:
            pass
        else:
            raise AssertionError("foreign admission parent was accepted")
        child = {"child_source_commit": "a" * 40, "child_source_tag": "child"}
        _bind_source(child, "a" * 40, "child")
        for commit, tag in (("b" * 40, "child"), ("a" * 40, "other")):
            try:
                _bind_source(child, commit, tag)
            except ValueError:
                pass
            else:
                raise AssertionError("packet source differing from the admitted child source was accepted")
    print("  [PASS] explicit parent root, exact row-count, and admission binding refusal")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-root", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output-plan", required=True)
    parser.add_argument("--admission", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--source-tag")
    args = parser.parse_args(argv)
    try:
        packet = build_packet(parent_root=Path(args.parent_root), source=Path(args.source),
                              output_plan=Path(args.output_plan), admission=Path(args.admission),
                              out=Path(args.out), source_tag=args.source_tag)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    print(json.dumps(packet, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest() if os.environ.get("R2T_PACKET_SELFTEST") == "1" else main())
