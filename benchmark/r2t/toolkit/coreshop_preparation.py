"""Stage the released CoreShop inputs without collecting or packaging results.

The preserved installation has an eval100 task file but a complete 422-item
answer key. Join that key to the released pool, and copy only named inputs.
This is preparation, not a mutation authority or an installed bundle.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from ..data.mutation import manifest_digest


ITEM_COUNT = 422
MUTANT_COUNT = 10205
CATALOG_DIGEST = "72747b079b558cce7d1a12582c0f11b67d276121c6929e471c371673eb87ae85"
BENCHMARK = Path(__file__).resolve().parents[2]


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError("REFUSED: " + message)


def _items(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _gold_inputs(items: list[dict], gold: Path, closures_path: Path,
                 gold_tree: Path, declaration: dict) -> tuple[list[dict], set[str]]:
    ids = [row["item_id"] for row in items]
    _require(len(ids) == len(set(ids)), "duplicate released item")
    manifest = _json(gold / "manifest.json")
    _require(set(manifest) == set(ids), "release/gold membership differs")
    _require(_sha(gold / "manifest.json") == declaration["gold_manifest_sha256"],
             "gold manifest differs from the released pin")
    entries = [{"path": "gold/" + name, "sha256": _sha(gold / name)}
               for name in sorted(manifest.values())]
    aggregate = hashlib.sha256(json.dumps(
        entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    _require(aggregate == declaration["gold_sidecars_sha256"],
             "gold sidecars differ from the released pin")
    extracted = _json(closures_path)
    by_id = {row["item_id"]: row for row in extracted}
    _require(len(by_id) == len(extracted), "duplicate extracted closure")
    selected, files = [], set()
    for item_id in ids:
        sidecar = _json(gold / manifest[item_id])
        _require(sidecar["item_id"] == item_id, "misfiled gold sidecar")
        _require(item_id in by_id, f"missing binding-aware closure: {item_id}")
        closure = by_id[item_id]
        for field in ("files", "context_classes", "di_fragment", "scenario_line"):
            # Lists are compared as collected; this is not a new extraction.
            _require(closure[field] == sidecar[field],
                     f"closure/sidecar {field} differs: {item_id}")
        _require(closure.get("steps") and not closure.get("problems"),
                 f"unresolved gold closure: {item_id}")
        for name in sidecar["files"]:
            _require((gold_tree / name).is_file(), f"missing gold file: {name}")
            files.add(name)
        # Derive a new input; never rewrite the preserved extraction. The
        # released sidecar supplies the reviewed portable feature spelling.
        selected.append(dict(closure, feature_file=sidecar["feature_file"]))
    return selected, files


def prepare(*, data_root: Path, controls: Path, out: Path,
            benchmark: Path = BENCHMARK) -> dict:
    _require(not out.exists(), f"output already exists: {out}")
    project = data_root / "projects/coreshop"
    release = benchmark / "release"
    declaration = _json(release / "dataset_manifest.json")["projects"]["coreshop"]
    items_path = release / "items_v1.jsonl"
    items = _items(items_path)
    _require(len(items) == ITEM_COUNT and all(
        row["project"] == "coreshop" for row in items), "expected all 422 CoreShop items")
    _require(_sha(items_path) == declaration["digests"]["items"],
             "release items differ from the declared pin")
    annotated_path = release / "coreshop/items.jsonl"
    annotated = _items(annotated_path)
    # The same rule the two companion validators apply, from the same table:
    # a companion may ADD any annotation the prompt renders and nothing else.
    # Reading the key set from `ANNOTATION_BLOCKS` is what stops this third
    # reader from refusing a companion the release and the bundle admit.
    from ..data.prompt import ANNOTATION_BLOCKS
    _require([{k: v for k, v in row.items() if k not in ANNOTATION_BLOCKS}
              for row in annotated] == items,
             "annotated release changes the underlying ordered items")
    gold = project / "artifacts/release/gold"
    selected, closure_files = _gold_inputs(
        items, gold, controls / "closures.json", project / "gold", declaration)
    mutation_root = project / "artifacts/mutation"
    catalog = _json(mutation_root / "scored_manifest.json")
    _require(catalog["n"] == MUTANT_COUNT and len(catalog["mutants"]) == MUTANT_COUNT
             and len({m["id"] for m in catalog["mutants"]}) == MUTANT_COUNT,
             "expected the frozen 10,205 production mutants")
    _require(catalog["digest"] == CATALOG_DIGEST == manifest_digest(catalog),
             "production catalog differs from the frozen identity")
    raw = _json(mutation_root / "raw_manifest.json")
    _require(raw["digest"] == catalog["raw_manifest_digest"] == manifest_digest(raw),
             "raw catalog differs from the production catalog's source")
    strip = _json(project / "gold/strip_manifest.json")
    names = set(strip["moved"] + strip["moved_config"]) | closure_files
    seed_root = project / "seed/v1"
    seed = _json(seed_root / "seed.json")
    _require(_sha(seed_root / "seed.json") == declaration["bundle"]["seed"]["manifest_sha256"],
             "seed manifest differs from the released pin")
    for name, field in (("workspace.tar", "workspace_seed_digest"),
                        ("database.sql", "database_dump_digest")):
        _require(_sha(seed_root / name) == seed[field], f"seed {name} differs from its pin")

    # No directory-wide copying: the neighboring runs, candidate evidence,
    # old maps, environments, and .git extraction backup are not inputs here.
    copies = {
        "data/projects/coreshop/artifacts/release/items.jsonl": items_path,
        "data/projects/coreshop/artifacts/release/annotated_items.jsonl": annotated_path,
        "data/projects/coreshop/artifacts/release/closure_clusters.json": release / "closure_clusters.json",
        "data/projects/coreshop/gold/strip_manifest.json": project / "gold/strip_manifest.json",
    }
    for name in ("alias_table.json", "autowirable_types.json", "php_prod_index.json"):
        copies[f"data/projects/coreshop/artifacts/{name}"] = project / "artifacts" / name
    for name in ("php_index.json", "matches.json"):
        copies[f"data/projects/coreshop/artifacts/{name}"] = controls / name
    for name in ("raw_manifest.json", "scored_manifest.json"):
        copies[f"data/projects/coreshop/artifacts/mutation/{name}"] = mutation_root / name
    for name in ("manifest.json", *_json(gold / "manifest.json").values()):
        copies[f"data/projects/coreshop/artifacts/release/gold/{name}"] = gold / name
    for name in sorted(names):
        copies[f"data/projects/coreshop/gold/{name}"] = project / "gold" / name
    for name in ("seed.json", "workspace.tar", "database.sql"):
        copies[f"data/projects/coreshop/seed/v1/{name}"] = seed_root / name
    for name in ("boundary_coreshop.yml", "profile_coreshop.yml"):
        copies[f"data/bundles/v1/coreshop/{name}"] = benchmark / "config" / name
    for path in copies.values():
        _require(path.is_file(), f"missing preparation input: {path}")

    report = {
        "status": "prepared_inputs_only",
        "release_items": ITEM_COUNT, "gold_sidecars": len(selected),
        "closure_files": len(closure_files), "gold_files": len(names),
        "mutants": MUTANT_COUNT, "catalog_digest": CATALOG_DIGEST,
        "raw_catalog_digest": raw["digest"],
        "gold_manifest_sha256": declaration["gold_manifest_sha256"],
        "gold_sidecars_sha256": declaration["gold_sidecars_sha256"],
        "workspace_seed_digest": seed["workspace_seed_digest"],
        "database_dump_digest": seed["database_dump_digest"],
        "sources": {"data_root": str(data_root.resolve()),
                    "closures": str((controls / "closures.json").resolve()),
                    "closures_sha256": _sha(controls / "closures.json"),
                    "release": str(items_path.resolve()),
                    "release_sha256": declaration["digests"]["items"]},
        "closure_derivation": "Select released IDs in release order; use each released sidecar's feature_file; preserve every other field.",
        "copied_files": sorted(copies),
        "generated_files": ["data/projects/coreshop/artifacts/closures.json"],
        "bytes_to_copy": sum(p.stat().st_size for p in copies.values()),
        "reference_roles": ["full-gold", "assertion-stripped-gold", "stub-control"],
        "remaining_gates": ["reviewed_scope_and_operator_authorization",
                            "current_runtime_all422_gold_coverage",
                            "new_map_and_native_authority", "dedicated_pool_qualification",
                            "three_reference_observations", "seal_and_reopen",
                            "candidate_free_bundle", "private_scoped_replay"],
    }
    out.mkdir(parents=True)
    for name, source in copies.items():
        destination = out / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    (out / report["generated_files"][0]).write_text(
        json.dumps(selected, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (out / "preparation.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def selftest() -> int:
    """Exercise the real preserved-input joins with small local fixtures."""
    from unittest.mock import patch

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        gold, tree = root / "gold", root / "tree"
        gold.mkdir(); tree.mkdir()
        (tree / "a.php").write_text("<?php /* gold */\n")
        sidecar = {"item_id": "one", "files": ["a.php"], "context_classes": ["A"],
                   "di_fragment": {}, "scenario_line": 3, "feature_file": "features/a.feature"}
        (gold / "a.json").write_text(json.dumps(sidecar))
        (gold / "manifest.json").write_text(json.dumps({"one": "a.json"}))
        closure = dict(sidecar, feature_file="/old/worker/features/a.feature",
                       steps=[{"definition": {"file": "a.php"}}], problems=[])
        closures = root / "closures.json"
        closures.write_text(json.dumps([closure, dict(closure, item_id="unreleased")]))
        entries = [{"path": "gold/a.json", "sha256": _sha(gold / "a.json")}]
        declaration = {"gold_manifest_sha256": _sha(gold / "manifest.json"),
                       "gold_sidecars_sha256": hashlib.sha256(json.dumps(
                           entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        items = [{"item_id": "one"}]
        def read():
            return _gold_inputs(items, gold, closures, tree, declaration)
        def refused(expected):
            try:
                read()
            except ValueError as exc:
                assert expected in str(exc), str(exc)
            else:
                raise AssertionError("accepted " + expected)
        selected, files = read()
        assert files == {"a.php"} and len(selected) == 1
        assert selected[0] == dict(closure, feature_file="features/a.feature")
        assert _json(closures)[0] == closure
        items.append({"item_id": "missing"}); refused("membership"); items.pop()
        items.append(items[0]); refused("duplicate released"); items.pop()
        (gold / "a.json").write_text(json.dumps(dict(sidecar, scenario_line=4)))
        refused("released pin")
        (gold / "a.json").write_text(json.dumps(sidecar))
        closures.write_text(json.dumps([dict(closure, files=["other.php"])]))
        refused("closure/sidecar files")
        closures.write_text(json.dumps([closure]))
        (tree / "a.php").unlink(); refused("missing gold file")
        (tree / "a.php").write_text("<?php /* gold */\n")

        benchmark, data, controls = root / "benchmark", root / "data", root / "controls"
        project = data / "projects/coreshop"
        def write(path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))
        release = benchmark / "release"
        write(release / "items_v1.jsonl", {"item_id": "one", "project": "coreshop"})
        write(release / "coreshop/items.jsonl", {
            "item_id": "one", "project": "coreshop", "target_interfaces": {}})
        write(release / "closure_clusters.json", {"one": "cluster"})
        shutil.copytree(gold, project / "artifacts/release/gold")
        shutil.copytree(tree, project / "gold")
        write(project / "gold/strip_manifest.json", {"moved": ["a.php"], "moved_config": []})
        write(controls / "closures.json", [closure])
        raw = {"mutants": [{"id": "m"}], "n": 1}
        raw["digest"] = manifest_digest(raw)
        catalog = dict(raw, raw_manifest_digest=raw["digest"])
        catalog["digest"] = manifest_digest(catalog)
        write(project / "artifacts/mutation/raw_manifest.json", raw)
        write(project / "artifacts/mutation/scored_manifest.json", catalog)
        seed_root = project / "seed/v1"
        write(seed_root / "workspace.tar", "seed fixture")
        write(seed_root / "database.sql", "SQL fixture")
        write(seed_root / "seed.json", {
            "workspace_seed_digest": _sha(seed_root / "workspace.tar"),
            "database_dump_digest": _sha(seed_root / "database.sql")})
        write(release / "dataset_manifest.json", {"projects": {"coreshop": dict(
            declaration, digests={"items": _sha(release / "items_v1.jsonl")},
            bundle={"seed": {"manifest_sha256": _sha(seed_root / "seed.json")}})}})
        for name in ("alias_table.json", "autowirable_types.json", "php_prod_index.json"):
            write(project / "artifacts" / name, {})
        for name in ("php_index.json", "matches.json"):
            write(controls / name, {})
        for name in ("boundary_coreshop.yml", "profile_coreshop.yml"):
            write(benchmark / "config" / name, {})
        for name in ("artifacts/runs/candidate.jsonl", "artifacts/mutation/mutant_map.json",
                     "artifacts/mutation/gold_results.jsonl", "gold/_git/config",
                     "artifacts/release/gold/generated_candidate.php"):
            write(project / name, "must not ship")
        destination = root / "prepared"
        with patch.multiple(__name__, ITEM_COUNT=1, MUTANT_COUNT=1,
                            CATALOG_DIGEST=catalog["digest"]):
            report = prepare(data_root=data, controls=controls, out=destination, benchmark=benchmark)
            actual = {str(p.relative_to(destination)) for p in destination.rglob("*") if p.is_file()}
            assert actual == set(report["copied_files"] + report["generated_files"] + ["preparation.json"])
            assert not any("candidate" in name or "gold_results" in name or "mutant_map" in name
                           or "/_git/" in name for name in actual)
            assert (destination / "data/projects/coreshop/seed/v1/workspace.tar").read_bytes() == (seed_root / "workspace.tar").read_bytes()
            try:
                prepare(data_root=data, controls=controls, out=destination, benchmark=benchmark)
            except ValueError as exc:
                assert "output already exists" in str(exc)
            else:
                raise AssertionError("overwrote an existing preparation")
            write(project / "artifacts/mutation/scored_manifest.json", dict(catalog, digest="changed"))
            try:
                prepare(data_root=data, controls=controls, out=root / "refused", benchmark=benchmark)
            except ValueError as exc:
                assert "production catalog differs" in str(exc)
            else:
                raise AssertionError("accepted a changed catalog")
            assert not (root / "refused").exists()
    print("  CoreShop preparation: gold membership, pins, bindings, and missing files PASS")
    print("  CoreShop preparation: input allowlist, byte reuse, catalog refusal, and no-clobber PASS")
    from scripts.check_coreshop_control_fixtures import selftest as control_fixtures
    result = control_fixtures()
    from scripts.prepare_coreshop_control_files import selftest as control_files
    return result or control_files()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--controls", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = prepare(data_root=args.data_root, controls=args.controls, out=args.out)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, str(exc) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "copied_files"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
