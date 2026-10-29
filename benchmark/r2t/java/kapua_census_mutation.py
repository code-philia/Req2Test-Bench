"""Kapua census330 mutation inputs: a sealed, host-portable B100 workset.

KAPUA_CENSUS330_MUTATION_AMENDMENT.md. The owner-approved census330 release
(`kapua_census`) is the item set. The historical K8 gold stays the coverage
authority. It has 605 rows and is the pilot's map coverage authority. It is
admitted by its pinned SHA-256 rather than by reopening the original host's
approval chain, which only that host's recorded paths satisfy (amendment
section 2).

`prepare` writes one self-contained sealed root:
- `in/`: byte copies of every input, each checked against its pin;
- `release/`: a copy of the census release directory (rows, receipt, `gold/`)
  and its `kapua_census.SHARDS` item-shard files;
- `census/`: the census workset, B100 over all 330 items. It holds the
  census330 rows of that gold (byte for byte, original order), the parent
  map, the B100 draw (the existing budgeted sampler, seed 20260909, 100 per
  item), the native asset index and validation report, and a receipt beside
  the B100 sidecar. The draw is anchored to the pilot's B100, so each of the
  24 pilot IDs keeps its pilot selection;
- `MANIFEST.json`: every file's relative path and SHA-256.

Receipts name absolute paths. A copy to another host therefore goes to the
same absolute root, and `verify` checks it there.

Reference observations are whole-census campaigns against this workset.
Candidate scoring is split by item shard (amendment section 4). `restrict`
projects a complete census330 cell onto one shard, byte for byte, beside a
proof, and the candidate reader admits that view against the census
workset. `restrict-items` projects a complete composed cell of a targeted
re-collection onto the items it replaced, which its composition record
lists, so that only the replacement passes are scored
(SANDBOX_EXPOSURE_TARGETED_RECOLLECTION_AMENDMENT.md section 7, item-level
scoring). The reader admits that view in the same way. Nothing here executes
a test.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

from . import kapua_census as KC
from . import kapua_gold_coverage as G
from ..data import mutation as M, mutation_attestation as A, subsets as S

COVERAGE_SCHEMA = "r2t.kapua-gold-census330-projection/1"
COVERAGE_DERIVATION = "historical gold row bytes on the census330 items, in original order"
INPUTS_SCHEMA = "r2t.kapua-census330-mutation-inputs/1"
#: Beside the B100 sidecar, as the pilot's selection proof sits beside its rows.
SUFFIX = ".census330.json"
VIEW_SCHEMA = "r2t.kapua-census330-shard-view/1"
VIEW_SUFFIX = ".census-shard.json"
VIEW_DERIVATION = "original census330 cell row bytes on the shard's items, in original order"
#: A replacement-items view's proof sits where a shard view's does (VIEW_SUFFIX).
ITEMS_VIEW_SCHEMA = "r2t.kapua-census330-items-view/1"
ITEMS_VIEW_DERIVATION = ("complete census330 cell row bytes on the items its composition replaced, "
                         "in original order")
SEAL_SCHEMA = "r2t.kapua-census330-mutation-seal/1"
SEAL = "MANIFEST.json"
REASON = "fixed implementation census; development mutation sensitivity; no population inference"
#: `kapua_gold-execution_gold-results-historical_v1` member `gold.jsonl`: the K8
#: 605-row gold whose coverage built the pilot's parent map.
HISTORICAL_GOLD_SHA256 = "dd29510c00839c1c22598ed5756cfdcab403eeae1c9b2871bd92ae6e143d134a"
#: `kapua_gold-execution_gold-results_v1` member `gold.jsonl` (census amendment
#: section 5.2): the reviewed gold test files every full-gold baseline must run.
FRESH_GOLD_SHA256 = "a20c2fb0ae3e32b380fb31af9c36b2ec40928e914f531d3e3bcea84d4d483ad3"
#: `kapua_mutation_item-map-pilot24_v1` members `B100.json` and `parent-map.json`.
PILOT_B100_SHA256 = "31b0c19ea75727f815c3ab86d74e8fe1895ce8cf086fa1934e47ff333ad1a169"
PILOT_PARENT_MAP_SHA256 = "ae03bc88f5c3455245d17872044dd149c03154988983b2a65a4a52da12fa377f"
SEED = 20260909
PER_ITEM = 100
#: Where each input's copy lives under `in/`. The boundary keeps its name,
#: which the asset index binds.
COPIES = {"historical_gold": "k8-gold.jsonl", "fresh_gold": "fresh-gold.jsonl",
          "manifest": "manifest.json", "audit": "materialization-audit.json",
          "boundary": "boundary_kapua.yml", "engine_source": "Mutate.java",
          "pilot_sidecar": "pilot-B100.json", "pilot_parent_map": "pilot-parent-map.json"}
#: The runtime rule (amendment section 4): every reference and candidate
#: observation runs at the census lane's runtime, on whichever host holds the shard.
RUNTIME = {
    "harness_version": 23,
    "container_image_digest": "sha256:f85238958f62f5f4d8e95863427ea7eb1572cbaa98fe666fc1134491f5a33882",
    "workspace_seed_digest": "15870dabe51f63feee87af57b4f0b53d747d23790f9133c4941914a1ea4d7bbf",
    "database_dump_digest": "no_database",
}


def is_census(path):
    """Every `kapua-census*.jsonl` release; its reader admits only census330
    and its shards."""
    return KC.is_selection(path)


def census_ids(items):
    """The census330 or shard item IDs, in release order, under KC's pin."""
    return list(KC.load_selection(items)["item_ids"])


def _is_shard(release):
    return release.get("schema") == KC.SHARD_SCHEMA


def _new_root(out, inputs):
    out = Path(G.canonical(out))
    G.require(out.resolve() == out and not os.path.lexists(out),
              "census mutation output exists or is noncanonical")
    G.require(not any(out.is_relative_to(Path(G.canonical(path)).parent) for path in inputs),
              "census mutation output lies inside an input directory")
    out.mkdir()
    return out


def _projected(historical_gold, ids):
    raw = G.checked({"path": G.canonical(historical_gold), "sha256": HISTORICAL_GOLD_SHA256})
    G.require(raw.endswith(b"\n"), "historical gold does not end at an LF-terminated row")
    wanted, seen, kept = set(ids), set(), []
    for line in raw.split(b"\n")[:-1]:
        iid = json.loads(line)["item_id"]
        seen.add(iid)
        if iid in wanted:
            kept.append(line + b"\n")
    G.require(wanted <= seen, "historical gold lacks census items: " + str(sorted(wanted - seen)[:3]))
    return b"".join(kept)


def project_coverage(historical_gold, items, out):
    """The release's rows of the historical gold, as the map's coverage run."""
    ids = census_ids(items)
    selected = _projected(historical_gold, ids)
    root = _new_root(out, [historical_gold, items])
    coverage = root / "gold.jsonl"
    with coverage.open("xb") as handle:
        handle.write(selected)
    doc = {"schema": COVERAGE_SCHEMA, "project": "kapua", "route": "development",
           "census_release": G.reference(items),
           "historical_gold": {"path": G.canonical(historical_gold), "sha256": HISTORICAL_GOLD_SHA256},
           "coverage": G.reference(coverage), "items": len(ids), "derivation": COVERAGE_DERIVATION}
    G.write(G.projection_path(coverage), doc)
    load_coverage(str(coverage), items)
    return doc


def load_coverage(coverage_run, items_path, boundary_path=None, *, release=None):
    """`kapua_gold_coverage.load_projection` for the census330 schema.

    The boundary is not part of this projection (the asset index binds it).
    The full K6 release is not either: `mutants map` binds that release, so
    a census map comes from `prepare`, never from `mutants map`.
    """
    try:
        doc = G.document(G.reference(G.projection_path(coverage_run)))
        G.require(set(doc) == {"schema", "project", "route", "census_release", "historical_gold",
                               "coverage", "items", "derivation"}
                  and doc["schema"] == COVERAGE_SCHEMA and doc["project"] == "kapua"
                  and doc["route"] == "development" and doc["derivation"] == COVERAGE_DERIVATION,
                  "census330 coverage receipt shape differs")
        G.require(release is None, "census330 coverage binds the census release, not the full K6 "
                  "release; build its map with kapua_census_mutation prepare")
        G.require(doc["census_release"] == G.reference(items_path), "coverage names another census release")
        ids = census_ids(items_path)
        G.require(doc["historical_gold"]["sha256"] == HISTORICAL_GOLD_SHA256,
                  "coverage names another historical gold")
        G.require(doc["coverage"]["path"] == G.canonical(coverage_run), "receipt names other coverage")
        raw = G.checked(doc["coverage"])
        G.require(raw == _projected(doc["historical_gold"]["path"], ids),
                  "coverage rows are not the historical gold's census330 row bytes")
        rows = G.L._json_lines(raw, "Kapua census330 coverage")
        G.require(type(doc["items"]) is int and doc["items"] == len(rows) == len(ids)
                  and {row["item_id"] for row in rows} == set(ids),
                  "coverage omits or duplicates census items")
        return {row["item_id"]: row["coverage_lines"] for row in rows}, doc["coverage"]["sha256"]
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        raise ValueError("REFUSED: malformed Kapua census330 coverage receipt") from exc


def _derived(items, sidecar_path, parent_path, anchor):
    """Facts every reader rederives: the B100 shape, the pilot anchor and
    counts. Every pilot ID keeps its pilot selection."""
    sidecar = S.verify_budgeted_sample(sidecar_path, parent_path)
    G.require(sidecar["seed"] == SEED and sidecar["per_item"] == PER_ITEM,
              "workset is not the B100 draw (seed 20260909, 100 per item)")
    release = KC.load_selection(items)
    G.require(not _is_shard(release) and set(anchor) == {"pilot_sidecar", "pilot_parent_map"},
              "the workset is the whole census, anchored to the pilot B100")
    for ref in anchor.values():
        G.checked(ref)
    G.require(anchor["pilot_sidecar"]["sha256"] == PILOT_B100_SHA256
              and anchor["pilot_parent_map"]["sha256"] == PILOT_PARENT_MAP_SHA256,
              "pilot B100 differs from the pinned pilot workset")
    pilot = S.verify_budgeted_sample(anchor["pilot_sidecar"]["path"], anchor["pilot_parent_map"]["path"])
    pilot_ids = release["pilot24_item_ids"]
    G.require(set(pilot["allocation"]) == set(pilot_ids)
              and (pilot["seed"], pilot["per_item"], pilot["manifest_digest"])
              == (sidecar["seed"], sidecar["per_item"], sidecar["manifest_digest"]),
              "pilot B100 is not the same draw over the same manifest")
    differ = sorted(iid for iid in pilot_ids if sidecar["allocation"][iid] != pilot["allocation"][iid])
    G.require(not differ, "census B100 changes the pilot selection of " + str(len(differ))
              + " pilot IDs, e.g. " + str(differ[:1]))
    parent = json.loads(G.raw_file(parent_path))
    return {"items": sidecar["totals"]["items"], "pairs": sidecar["totals"]["pairs"],
            "mutants": len({mid for ids in sidecar["allocation"].values() for mid in ids}),
            "parent_mapped": parent["n_mapped"], "parent_pairs": parent["n_pairs"],
            "short_items": len(sidecar["short_items"]), "unfloored_items": len(sidecar["unfloored_items"]),
            "pilot_items_unchanged": len(release["pilot24_item_ids"])}


def _unit(copies, items, out, anchor):
    """One workset: coverage, parent map, B100, native index and receipt."""
    from ..toolkit import mutation_asset_index as ASSETS, mutation_java as MJ
    from ..toolkit.subset_writer import write_budgeted_sample, write_provenance

    ids = census_ids(items)
    out.mkdir()
    projection = project_coverage(copies["historical_gold"], items, str(out / "historical-gold"))
    coverage_run = projection["coverage"]["path"]
    coverage, coverage_sha256 = load_coverage(coverage_run, items)
    population = A._read_json_object(copies["manifest"], "Kapua mutant manifest")
    A.validate_manifest(population, expected_engine=MJ.ENGINE)
    by_mutant, uncovered = M.map_mutants_to_items(population, coverage)
    parent = A.build_map_artifact(population, by_mutant, uncovered, coverage_sha256=coverage_sha256,
                                  release_sha256=G.reference(items)["sha256"])
    A.validate_map(parent, population, release_ids=set(ids), coverage_by_item=coverage)
    parent_path = str(out / "parent-map.json")
    write_provenance(parent_path, parent)
    map_path, sidecar_path = write_budgeted_sample(
        S.budgeted_sample(str(items), parent_path, copies["manifest"], PER_ITEM, SEED), str(out / "B100"))
    minted = ASSETS.mint("kapua", raw_manifest_path=copies["manifest"], scored_manifest_path=copies["manifest"],
        map_path=parent_path, coverage_path=coverage_run, release_path=str(items),
        boundary_path=copies["boundary"], audit_path=copies["audit"],
        asset_index_out=str(out / "asset-index.json"), validation_out=str(out / "native-validation.json"),
        engine_source_path=copies["engine_source"], expected_engine=MJ.ENGINE)
    doc = {"schema": INPUTS_SCHEMA, "project": "kapua", "route": "development",
           "inference_valid": False, "inference_reason": REASON, "seed": SEED, "per_item": PER_ITEM,
           "inputs": {"release": G.reference(items),
                      **{key: G.reference(copies[key]) for key in
                         ("manifest", "audit", "boundary", "engine_source")},
                      "coverage_projection": G.reference(G.projection_path(coverage_run)),
                      "fresh_gold": {"path": copies["fresh_gold"], "sha256": FRESH_GOLD_SHA256},
                      "anchor": anchor},
           "outputs": {"coverage": projection["coverage"], "parent_map": G.reference(parent_path),
                       "map": G.reference(map_path), "budgeted_sidecar": G.reference(sidecar_path),
                       "asset_index": G.reference(minted["asset_index"]),
                       "mutation_validation": G.reference(minted["mutation_validation"])},
           "counts": _derived(str(items), sidecar_path, parent_path, anchor)}
    G.write(sidecar_path + SUFFIX, doc)
    load_inputs(sidecar_path)
    return doc


def prepare(*, census_release, historical_gold, fresh_gold, manifest, audit, boundary, engine_source,
            pilot_sidecar, pilot_parent_map, out):
    """Write the sealed root: input copies, the release and its shard files,
    the census workset and the manifest."""
    census_release = Path(G.canonical(census_release))
    KC.load_selection(census_release)
    G.require(census_release.name == KC.NAME, "prepare starts from the census330 release itself")
    gold_tree = census_release.parent / "gold"
    G.require((gold_tree / "manifest.json").is_file(), "census release has no gold/ tree")
    sources = {"historical_gold": historical_gold, "fresh_gold": fresh_gold, "manifest": manifest,
               "audit": audit, "boundary": boundary, "engine_source": engine_source,
               "pilot_sidecar": pilot_sidecar, "pilot_parent_map": pilot_parent_map}
    root = _new_root(out, [census_release, *sources.values()])
    (root / "in").mkdir()
    copies = {}
    for key, source in sources.items():
        target = root / "in" / COPIES[key]
        shutil.copyfile(G.canonical(source), target)
        G.require(G.reference(target)["sha256"] == G.reference(source)["sha256"], "copy differs: " + key)
        copies[key] = str(target)
    G.checked({"path": copies["fresh_gold"], "sha256": FRESH_GOLD_SHA256})
    release = root / "release"
    release.mkdir()
    for name in (KC.NAME, KC.RECEIPT):
        shutil.copyfile(census_release.parent / name, release / name)
    shutil.copytree(gold_tree, release / "gold")
    KC.write_shards(release / KC.NAME)
    _unit(copies, release / KC.NAME, root / "census",
          {"pilot_sidecar": G.reference(copies["pilot_sidecar"]),
           "pilot_parent_map": G.reference(copies["pilot_parent_map"])})
    return seal(root)


def load_inputs(budgeted_sidecar, assets=None):
    """A workset receipt, with its B100 and anchor facts rederived.

    `assets` (the reference reader's five inputs) must name this receipt's
    files. The consumers' own native-report admission then authenticates the
    manifest, parent map, coverage projection and derived map.
    """
    try:
        doc = G.document(G.reference(str(budgeted_sidecar) + SUFFIX))
        G.require(set(doc) == {"schema", "project", "route", "inference_valid", "inference_reason", "seed",
                               "per_item", "inputs", "outputs", "counts"}
                  and doc["schema"] == INPUTS_SCHEMA and doc["project"] == "kapua"
                  and doc["route"] == "development" and doc["inference_valid"] is False
                  and doc["inference_reason"] == REASON
                  and (doc["seed"], doc["per_item"]) == (SEED, PER_ITEM),
                  "census workset receipt shape differs")
        inputs, outputs = doc["inputs"], doc["outputs"]
        G.require(set(inputs) == {"release", "manifest", "audit", "boundary", "engine_source",
                                  "coverage_projection", "fresh_gold", "anchor"}
                  and set(outputs) == {"coverage", "parent_map", "map", "budgeted_sidecar",
                                       "asset_index", "mutation_validation"}
                  and outputs["budgeted_sidecar"]["path"] == G.canonical(budgeted_sidecar)
                  and inputs["fresh_gold"]["sha256"] == FRESH_GOLD_SHA256,
                  "census workset receipt names other files")
        for key in ("budgeted_sidecar", "map", "parent_map", "mutation_validation", "asset_index"):
            G.checked(outputs[key])
        G.checked(inputs["release"])
        if assets is not None:
            supplied = {key: G.canonical(assets[key]) for key in
                        ("mutation_validation", "manifest", "map", "release", "budgeted_sidecar")}
            recorded = {"mutation_validation": outputs["mutation_validation"]["path"],
                        "manifest": inputs["manifest"]["path"], "map": outputs["map"]["path"],
                        "release": inputs["release"]["path"],
                        "budgeted_sidecar": outputs["budgeted_sidecar"]["path"]}
            G.require(supplied == recorded, "mutation inputs differ from the census workset receipt")
        G.require(doc["counts"] == _derived(inputs["release"]["path"], outputs["budgeted_sidecar"]["path"],
                                            outputs["parent_map"]["path"], inputs["anchor"]),
                  "census workset counts differ")
        return doc
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        raise ValueError("REFUSED: malformed Kapua census workset receipt") from exc


def _files(root):
    table = {}
    for path in sorted(root.rglob("*")):
        G.require(not path.is_symlink(), "sealed root holds a symlink: " + str(path))
        if path.is_file() and path.relative_to(root).as_posix() != SEAL:
            table[path.relative_to(root).as_posix()] = G.reference(path)["sha256"]
    return table


def _units(root):
    census = load_inputs(str(root / "census/B100.json"))
    drawn = json.loads(G.checked(census["outputs"]["budgeted_sidecar"]))["allocation"]
    shards, seen = {}, []
    for index in range(KC.SHARDS):
        ids = census_ids(root / "release" / KC.shard_name(index))
        shards[KC.shard_name(index)] = {"items": len(ids), "pairs": sum(len(drawn[iid]) for iid in ids)}
        seen.extend(ids)
    G.require(sorted(seen) == sorted(drawn), "shard files do not partition the census workset")
    return {"census": census["counts"], "shards": shards}


def seal(root):
    root = Path(G.canonical(root))
    doc = {"schema": SEAL_SCHEMA, "project": "kapua", "root": str(root), "shards": KC.SHARDS,
           "units": _units(root), "files": _files(root)}
    G.write(root / SEAL, doc)
    return doc


def verify(root):
    """A sealed root at its recorded absolute path: every file, every workset."""
    root = Path(G.canonical(root))
    doc = G.document(G.reference(root / SEAL))
    G.require(doc.get("schema") == SEAL_SCHEMA and doc.get("root") == str(root)
              and doc.get("shards") == KC.SHARDS,
              "sealed root moved or has another shape; copy it to its recorded absolute path")
    actual = _files(root)
    changed = sorted(set(actual) ^ set(doc["files"])) + sorted(
        rel for rel in set(actual) & set(doc["files"]) if actual[rel] != doc["files"][rel])
    G.require(not changed, "sealed files differ: " + str(changed[:3]))
    G.require(_units(root) == doc["units"], "sealed workset counts differ")
    return doc


def _complete(rows, path, items, label):
    from ..bench import population as P
    ids = [row["item_id"] for row in rows]
    G.require(len(ids) == len(set(ids)) and set(ids) == set(census_ids(items)),
              label + " is not one complete " + Path(items).name.removesuffix(".jsonl") + " cell")
    try:
        population = P.resolve(rows, str(path), explicit_release=str(items))
    except P.PopulationRefusal as exc:
        raise ValueError(str(exc)) from exc
    G.require(population["complete"] is True, label + " does not cover its release")


def _view_lines(source, items, release):
    raw = G.checked(source)
    census = Path(G.canonical(items)).parent / KC.NAME
    rows = G.L._json_lines(raw, "Kapua census cell")
    _complete(rows, source["path"], str(census), "view source")
    keep = set(release["item_ids"])
    # `_json_lines` admitted exactly one LF-terminated record per line.
    return b"".join(line + b"\n" for line, row in zip(raw.split(b"\n"), rows) if row["item_id"] in keep)


def restrict(run, items, out):
    """One complete census330 cell's rows on one shard's items (`items` is
    the shard file), byte for byte, beside a proof. No observation is made
    and no row is rewritten, so the rows keep their census stamps."""
    release = KC.load_selection(items)
    G.require(_is_shard(release), "a view restricts a census cell to one shard")
    source = G.reference(run)
    selected = _view_lines(source, items, release)
    root = _new_root(out, [run, items])
    view = root / "candidate.jsonl"
    with view.open("xb") as handle:
        handle.write(selected)
    proof = {"schema": VIEW_SCHEMA, "project": "kapua", "route": "development", "release": G.reference(items),
             "source_run": source, "run": G.reference(view), "new_observations": 0,
             "derivation": VIEW_DERIVATION, "inference_valid": False}
    G.write(str(view) + VIEW_SUFFIX, proof)
    validate_candidates(view, Path(G.canonical(items)).parent / KC.NAME)
    return proof


def _item_lines(source, items, ids, composition):
    """The rows of `source`, one complete census330 cell, on `ids`, byte for
    byte and in its order. `composition` is the re-collection's record of
    that cell (`run_agent_cells.py finalize`): it must name these source
    bytes and replace exactly `ids`."""
    raw = G.checked(source)
    rows = G.L._json_lines(raw, "Kapua census cell")
    _complete(rows, source["path"], items, "items view source")
    G.require(type(ids) is list and ids and len(ids) == len(set(ids)), "an items view lists each item once")
    outside = sorted(set(ids) - {row["item_id"] for row in rows})
    G.require(not outside, "items view names items outside its source cell: " + str(outside[:3]))
    doc = json.loads(G.checked(composition))
    G.require(doc["view"]["sha256"] == source["sha256"]
              and set(ids) == {entry["item_id"] for entry in doc["rows"] if entry["from"] == "replacement"},
              "items view does not list exactly the replaced items of its source's composition")
    keep = set(ids)
    return b"".join(line + b"\n" for line, row in zip(raw.split(b"\n"), rows) if row["item_id"] in keep)


def restrict_items(run, items, item_ids, composition, out):
    """One complete census330 cell's rows on the items a targeted
    re-collection replaced (`item_ids`, one ID per line; `composition`, its
    record of the cell), byte for byte, beside a proof. `items` is the
    census330 release. As with `restrict`, no observation is made and no row
    is rewritten."""
    G.require(not _is_shard(KC.load_selection(items)), "an items view restricts a cell of the whole census")
    source = G.reference(run)
    ids = [line.strip() for line in G.raw_file(item_ids).decode().splitlines() if line.strip()]
    selected = _item_lines(source, str(items), ids, G.reference(composition))
    root = _new_root(out, [run, items, item_ids, composition])
    view = root / "candidate.jsonl"
    with view.open("xb") as handle:
        handle.write(selected)
    proof = {"schema": ITEMS_VIEW_SCHEMA, "project": "kapua", "route": "development", "release": G.reference(items),
             "source_run": source, "composition": G.reference(composition),
             "items": [json.loads(line)["item_id"] for line in selected.splitlines()],
             "run": G.reference(view), "new_observations": 0, "derivation": ITEMS_VIEW_DERIVATION,
             "inference_valid": False}
    G.write(str(view) + VIEW_SUFFIX, proof)
    validate_candidates(view, items)
    return proof


def validate_candidates(path, items):
    """For the census workset (`items` is the census330 release): a complete
    census330 cell, or a shard or replacement-items view of one when its
    proof lies beside it. Luna and the three census arms qualify alike; only
    passed rows are scored."""
    G.require(not _is_shard(KC.load_selection(items)), "candidates are scored against the census workset")
    if not os.path.lexists(str(path) + VIEW_SUFFIX):
        _complete(G.L._json_lines(G.raw_file(path), "Kapua census candidates"), path, items, "candidate")
        return
    try:
        proof = G.document(G.reference(str(path) + VIEW_SUFFIX))
        if isinstance(proof, dict) and proof.get("schema") == ITEMS_VIEW_SCHEMA:
            G.require(set(proof) == {"schema", "project", "route", "release", "source_run", "composition", "items",
                                     "run", "new_observations", "derivation", "inference_valid"}
                      and proof["project"] == "kapua" and proof["route"] == "development"
                      and type(proof["new_observations"]) is int and proof["new_observations"] == 0
                      and proof["derivation"] == ITEMS_VIEW_DERIVATION and proof["inference_valid"] is False,
                      "items view proof shape differs")
            G.require(proof["release"] == G.reference(items), "items view names another census release")
            G.require(proof["run"]["path"] == G.canonical(path)
                      and G.checked(proof["run"]) == _item_lines(proof["source_run"], str(items), proof["items"],
                                                                 proof["composition"]),
                      "items view is not the source cell's row bytes on its items")
            return
        G.require(set(proof) == {"schema", "project", "route", "release", "source_run", "run",
                                 "new_observations", "derivation", "inference_valid"}
                  and proof["schema"] == VIEW_SCHEMA and proof["project"] == "kapua"
                  and proof["route"] == "development" and type(proof["new_observations"]) is int
                  and proof["new_observations"] == 0 and proof["derivation"] == VIEW_DERIVATION
                  and proof["inference_valid"] is False, "shard view proof shape differs")
        G.checked(proof["release"])
        shard = Path(proof["release"]["path"])
        release = KC.load_selection(shard)
        G.require(_is_shard(release) and shard.parent == Path(G.canonical(items)).parent
                  and release["census"]["sha256"] == G.reference(items)["sha256"],
                  "shard view names a shard of another census release")
        G.require(proof["run"]["path"] == G.canonical(path)
                  and G.checked(proof["run"]) == _view_lines(proof["source_run"], str(shard), release),
                  "shard view is not the source cell's row bytes on the shard")
    except (KeyError, TypeError, IndexError) as exc:
        raise ValueError("REFUSED: malformed Kapua census view proof") from exc


def validate_full_gold(path, items, inputs):
    """A new full-gold baseline over the workset's release that runs the
    reviewed gold files."""
    rows = G.L._json_lines(G.raw_file(path), "Kapua census full-gold baseline")
    _complete(rows, path, items, "full-gold baseline")
    wanted, reviewed = set(census_ids(items)), {}
    fresh = G.checked(inputs["inputs"]["fresh_gold"])
    for line in fresh.split(b"\n")[:-1]:
        row = json.loads(line)
        if row["item_id"] in wanted:
            reviewed[row["item_id"]] = row["produced_files"]
    changed = sorted(row["item_id"] for row in rows if row.get("produced_files") != reviewed.get(row["item_id"]))
    G.require(not changed, "full-gold baseline does not run the reviewed gold files: " + str(changed[:3]))


def runtime_differences(identity):
    return sorted(key for key, value in RUNTIME.items() if identity.get(key) != value)


def _fixture(root):
    """A three-item census330-shaped release with its inputs; two pilot IDs."""
    from ..bench.mutation_run import binding_for
    from ..toolkit import mutation_java as MJ
    from ..toolkit.subset_writer import write_budgeted_sample, write_provenance

    def lines(rows):
        return b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in rows)

    reviewed = json.loads((Path(__file__).resolve().parents[3] / "maps/kapua/census334/census330.json").read_bytes())
    source = root / "source"
    compiler = {"java_home": "/opt/java/openjdk", "parser": "javac 17.0.17",
                "runtime_executable_sha256": "a" * 64, "compiler_executable_sha256": "b" * 64,
                "tools_jar_sha256": None, "encoding": "UTF-8", "source": "1.8", "target": "1.8", "release": None}
    files = ["commons/src/main/java/example/A.java", "service/src/main/java/example/B.java"]
    modules, mutants = [], []
    for rel in files:
        (source / rel).parent.mkdir(parents=True)
        (source / rel).write_text("class Example {}\n")
        name = rel.split("/src/main/java/")[0]
        (source / name / "target/classes").mkdir(parents=True)
        (source / name / "target/classes/Example.class").write_bytes(b"fixture class")
        child = MJ.make_module_analysis_child_recipe(str(source), name, classpath=[name + "/target/classes"])
        modules.append({"module": name, "source_root": name + "/src/main/java", "source_files": [rel],
                        "compiler": compiler, "recipe": child})
        mutants.extend({"file": rel, "start_line": line, "start_col": 1, "end_line": line, "end_col": 7,
                        "operator": "ReturnValue", "original": "return 1;", "mutated": "return 0;",
                        "class": "Example", "method": "m" + str(line)} for line in range(1, 9))
    recipe = MJ.make_module_analysis_recipe(str(source), modules)
    population = MJ.build_population(mutants, parser_version=MJ.module_analysis_parser(recipe),
                                     enumerator_rev=MJ.ENUMERATOR_REV, analysis_recipe=recipe)
    inputs = root / "inputs"
    inputs.mkdir()
    G.write(inputs / "manifest.json", population)
    ids = ["kapua/a.feature:1", "kapua/b.feature:2", "kapua/c.feature:3"]
    pilot_ids = ids[:2]
    release = root / "release"
    (release / "gold").mkdir(parents=True)
    G.write(release / "gold/manifest.json", {iid: f"{n}.json" for n, iid in enumerate(ids)})
    items = release / KC.NAME
    items.write_bytes(lines([{"item_id": iid, "project": "kapua", "checked_interfaces": {}} for iid in ids]))
    receipt = {**reviewed, "item_ids": ids, "pilot24_item_ids": pilot_ids, "outputs": {
        **reviewed["outputs"], "items": {"member": KC.NAME, "n": len(ids), "sha256": G.reference(items)["sha256"]}}}
    (release / KC.RECEIPT).write_bytes((json.dumps(receipt, indent=1, sort_keys=True) + "\n").encode())
    # Historical gold: the census rows plus one requirement outside it. 16
    # mutants: a covers 7, b 8 and c 2, so c is short at the fixture budget of 3.
    coverage_of = {ids[0]: {files[0]: [1, 2, 3, 4, 5, 6], files[1]: [1]},
                   ids[1]: {files[1]: list(range(1, 9))}, ids[2]: {files[0]: [7, 8]},
                   "kapua/z.feature:9": {files[0]: [1]}}
    history = root / "k8/gold.jsonl"
    history.parent.mkdir()
    history.write_bytes(lines([{"item_id": iid, "coverage_lines": cov, "outcome": "passed"}
                               for iid, cov in sorted(coverage_of.items(), reverse=True)]))
    gold_files = {iid: [{"file_path": "tests/Steps.java", "code": "class Steps {} // " + iid}]
                  for iid in [*ids, "kapua/z.feature:9"]}
    fresh = root / "fresh/gold.jsonl"
    fresh.parent.mkdir()
    fresh.write_bytes(lines([{"item_id": iid, "produced_files": value} for iid, value in gold_files.items()]))
    # The pilot's own B100: the same sampler over its own items and map.
    pilot = root / "pilot"
    pilot.mkdir()
    pilot_items = pilot / "kapua-pilot.jsonl"
    pilot_items.write_bytes(lines([{"item_id": iid, "project": "kapua"} for iid in pilot_ids]))
    pilot_cov = {iid: coverage_of[iid] for iid in pilot_ids}
    write_provenance(str(pilot / "parent-map.json"), A.build_map_artifact(
        population, *M.map_mutants_to_items(population, pilot_cov),
        coverage_sha256="1" * 64, release_sha256=G.reference(pilot_items)["sha256"]))
    _map, pilot_sidecar = write_budgeted_sample(S.budgeted_sample(
        str(pilot_items), str(pilot / "parent-map.json"), str(inputs / "manifest.json"), 3, SEED), str(pilot / "B100"))
    # A structurally complete audit for the real mint, as the gold-coverage self-test builds it.
    engine_dir, applier = binding_for(population["engine"])
    engine_source = str(Path(engine_dir) / applier.source)
    engine_sha = A.sha256_file(engine_source)
    compiled = {"schema": "r2t.compiled-applier/2", "source_sha256": engine_sha,
                "interpreter": applier.interpreter, "entrypoint": applier.entrypoint,
                "classes_rel": applier.classes_rel.replace(os.sep, "/"), "classes_sha256": "a" * 64,
                "compiler_identity": compiler["parser"].split(" [", 1)[0],
                "compiler_executable_sha256": compiler["compiler_executable_sha256"],
                "runtime_identity": compiler["parser"],
                "runtime_executable_sha256": compiler["runtime_executable_sha256"], "tools_jar_sha256": None,
                "analysis_recipe_digest": population["analysis_recipe"]["digest"]}
    audit = {"schema": A.AUDIT_SCHEMA, "status": "complete", "manifest_digest": population["digest"],
             "engine": population["engine"], "engine_version": population["engine_version"],
             "parser": population["parser"],
             **{key: population["n"] for key in ("n_mutants", "n_attempted", "n_applied",
                                                "n_parse_valid", "n_restored")},
             "n_source_files": len(files), "bounded_roots": A._audit_roots(population),
             "source_set_sha256_before": "d" * 64, "source_set_sha256_after": "d" * 64,
             "source_lstat_sha256_before": "e" * 64, "source_lstat_sha256_after": "e" * 64,
             "failing_mutant_id": None, "failure_stage": None, "failure": None,
             "collateral": {"added": [], "changed": [], "deleted": []},
             "operator_gate": {"mode": "real_engine", "disposable_marker": A.DISPOSABLE_MARKER,
                               "engine_source_sha256": engine_sha,
                               "runtime_parser_identity": population["parser"],
                               "runtime_parser_reported": A.expected_runtime_parser(population),
                               "compiled_applier": compiled}}
    audit["digest"] = A.audit_digest(audit)
    G.write(inputs / "audit.json", audit)
    (inputs / "boundary_kapua.yml").write_text(json.dumps({"version": 1, "project": "kapua",
                                                          "repo_root": str(source), "removable": [], "retained": []}))
    arguments = {"census_release": str(items), "historical_gold": str(history), "fresh_gold": str(fresh),
                 "manifest": str(inputs / "manifest.json"), "audit": str(inputs / "audit.json"),
                 "boundary": str(inputs / "boundary_kapua.yml"), "engine_source": engine_source,
                 "pilot_sidecar": pilot_sidecar, "pilot_parent_map": str(pilot / "parent-map.json")}
    pins = {"HISTORICAL_GOLD_SHA256": G.reference(history)["sha256"], "FRESH_GOLD_SHA256": G.reference(fresh)["sha256"],
            "PILOT_B100_SHA256": G.reference(pilot_sidecar)["sha256"],
            "PILOT_PARENT_MAP_SHA256": G.reference(pilot / "parent-map.json")["sha256"], "PER_ITEM": 3}
    return {"arguments": arguments, "pins": pins, "ids": ids, "pilot_ids": pilot_ids, "gold_files": gold_files,
            "receipt_sha256": G.reference(release / KC.RECEIPT)["sha256"], "lines": lines,
            "population": population, "pilot_items": str(pilot_items), "pilot_cov": pilot_cov, "files": files}


def selftest():
    """Real census, shard, coverage, map, sampler, mint and admission readers
    over a fixture census; only the pins move to the fixture's bytes."""
    import contextlib
    import io
    import sys
    import tempfile
    from unittest.mock import patch
    from .. import docker_authority as D
    from ..toolkit.subset_writer import write_budgeted_sample, write_provenance

    def refuses(label, fn, fragment):
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                fn()
        except (ValueError, OSError, A.MutationAssetRefused, D.DockerAuthorityRefused) as exc:
            assert fragment in str(exc), label + ": " + str(exc)
            print("PASS refusal:", label)
            return
        raise AssertionError("accepted " + label)

    module = sys.modules[__name__]
    with tempfile.TemporaryDirectory(prefix="kapua_census_mut_") as tmp:
        root = Path(tmp)
        fx = _fixture(root)
        arguments, ids, lines = fx["arguments"], fx["ids"], fx["lines"]
        sealed = root / "sealed"
        with patch.object(KC, "RECEIPT_SHA256", fx["receipt_sha256"]), patch.object(KC, "SHARDS", 2), \
                patch.multiple(module, **fx["pins"]):
            with contextlib.redirect_stdout(io.StringIO()):
                doc = prepare(**arguments, out=str(sealed))
            assert verify(str(sealed)) == doc
            items = sealed / "release" / KC.NAME
            shard0, shard1 = (sealed / "release" / KC.shard_name(index) for index in (0, 1))
            assert census_ids(shard0) == ids[0::2] and census_ids(shard1) == ids[1::2]
            census = load_inputs(str(sealed / "census/B100.json"))
            # The coverage is the historical rows' own bytes, census only, in file order.
            history = Path(arguments["historical_gold"]).read_bytes()
            coverage_run = census["outputs"]["coverage"]["path"]
            assert G.checked(census["outputs"]["coverage"]) == b"".join(
                line for line in history.splitlines(keepends=True) if json.loads(line)["item_id"] in ids)
            drawn = json.loads(G.checked(census["outputs"]["budgeted_sidecar"]))
            assert doc["units"]["census"] == {"items": 3, "pairs": 8, "parent_mapped": 16, "parent_pairs": 17,
                                              "mutants": len({m for v in drawn["allocation"].values() for m in v}),
                                              "short_items": 1, "unfloored_items": 0, "pilot_items_unchanged": 2}
            assert doc["units"]["shards"] == {
                KC.shard_name(0): {"items": 2, "pairs": len(drawn["allocation"][ids[0]]) + len(drawn["allocation"][ids[2]])},
                KC.shard_name(1): {"items": 1, "pairs": len(drawn["allocation"][ids[1]])}}
            pilot_draw = json.loads(Path(arguments["pilot_sidecar"]).read_bytes())
            assert all(drawn["allocation"][iid] == pilot_draw["allocation"][iid] for iid in fx["pilot_ids"])
            # The native consumer and the dispatcher read the census workset.
            assert G.load_projection(coverage_run, str(items), census["inputs"]["boundary"]["path"])[1] \
                == census["outputs"]["coverage"]["sha256"]
            assets = {"mutation_validation": census["outputs"]["mutation_validation"]["path"],
                      "manifest": census["inputs"]["manifest"]["path"], "map": census["outputs"]["map"]["path"],
                      "release": str(items), "budgeted_sidecar": census["outputs"]["budgeted_sidecar"]["path"]}

            def consume():
                return A.validate_campaign_asset_inputs(
                    assets["mutation_validation"], manifest_path=assets["manifest"], map_path=assets["map"],
                    release_path=assets["release"], budgeted_sidecar=assets["budgeted_sidecar"])
            consumed = consume()
            assert consumed["population_basis"] == "budgeted_sample" and consumed["release_items"] == 3
            assert load_inputs(assets["budgeted_sidecar"], assets) == census
            refuses("other reference inputs", lambda: load_inputs(assets["budgeted_sidecar"],
                    {**assets, "map": census["outputs"]["parent_map"]["path"]}), "differ from the census workset")
            refuses("mutants map route over the census coverage",
                    lambda: G.load_projection(coverage_run, str(items), "unused", release={}), "not the full K6")
            refuses("a workset over one shard", lambda: _derived(
                str(shard0), assets["budgeted_sidecar"], census["outputs"]["parent_map"]["path"],
                census["inputs"]["anchor"]), "whole census")
            # Tampering: coverage, the historical-gold copy, a census row, an extra file.
            projection = Path(G.projection_path(coverage_run))
            for label, path, fragment in (
                    ("changed coverage row", Path(coverage_run), "evidence bytes changed"),
                    ("changed historical gold copy", sealed / "in" / COPIES["historical_gold"], "evidence bytes changed"),
                    ("changed census row", items, "another census release")):
                before = path.read_bytes()
                path.write_bytes(before.replace(b'"kapua/a', b'"kapua/A', 1) if path == items else before + b"\n")
                refuses(label, lambda: load_coverage(coverage_run, str(items)), fragment)
                refuses(label + " at the native consumer", consume, "")
                refuses(label + " in the sealed root", lambda: verify(str(sealed)), "")
                path.write_bytes(before)
            before = projection.read_bytes()
            projection.unlink()
            refuses("projected oracle downgraded to ordinary coverage", consume, "projection")
            projection.write_bytes(before)
            (sealed / "census/extra.json").write_text("{}")
            refuses("extra file in the sealed root", lambda: verify(str(sealed)), "sealed files differ")
            (sealed / "census/extra.json").unlink()
            assert verify(str(sealed)) == doc
            moved = root / "moved"
            shutil.copytree(sealed, moved, symlinks=True)
            refuses("sealed root at another path", lambda: verify(str(moved)), "recorded absolute path")
            refuses("existing output", lambda: prepare(**arguments, out=str(sealed)), "exists")
            refuses("output inside an input directory",
                    lambda: prepare(**arguments, out=str(Path(arguments["census_release"]).parent / "m")),
                    "inside an input")
            # Pilot anchors: another seed, and a same-seed pilot whose selection differs.
            other = root / "pilot-other"
            other.mkdir()
            _map, other_sidecar = write_budgeted_sample(S.budgeted_sample(
                fx["pilot_items"], arguments["pilot_parent_map"], arguments["manifest"], 3, SEED + 1),
                str(other / "B100"))
            with patch.object(module, "PILOT_B100_SHA256", G.reference(other_sidecar)["sha256"]):
                refuses("pilot drawn with another seed",
                        lambda: prepare(**{**arguments, "pilot_sidecar": other_sidecar}, out=str(root / "o1")),
                        "same draw")
                refuses("census reader over another pilot",
                        lambda: load_inputs(str(sealed / "census/B100.json")), "pinned pilot")
            narrow = root / "pilot-narrow"
            narrow.mkdir()
            write_provenance(str(narrow / "parent-map.json"), A.build_map_artifact(
                fx["population"], *M.map_mutants_to_items(
                    fx["population"], {**fx["pilot_cov"], ids[0]: {fx["files"][0]: [1, 2, 3, 4, 5, 6]}}),
                coverage_sha256="2" * 64, release_sha256=G.reference(fx["pilot_items"])["sha256"]))
            _map, narrow_sidecar = write_budgeted_sample(S.budgeted_sample(
                fx["pilot_items"], str(narrow / "parent-map.json"), arguments["manifest"], 3, SEED),
                str(narrow / "B100"))
            with patch.multiple(module, PILOT_B100_SHA256=G.reference(narrow_sidecar)["sha256"],
                                PILOT_PARENT_MAP_SHA256=G.reference(narrow / "parent-map.json")["sha256"]):
                refuses("census draw that changes a pilot selection",
                        lambda: prepare(**{**arguments, "pilot_sidecar": narrow_sidecar,
                                           "pilot_parent_map": str(narrow / "parent-map.json")},
                                        out=str(root / "o2")), "changes the pilot selection")
            # Candidates: a complete census330 cell, and its shard views, both
            # admitted against the census workset.
            identity = KC.identify(items)
            cell = [{"item_id": iid, "project": "kapua", "outcome": "passed", "adapter": "codex",
                     "subset_id": identity["subset_id"], "subset_digest": identity["subset_digest"]}
                    for iid in reversed(ids)]
            (root / "cells").mkdir()
            run = root / "cells/candidate.jsonl"
            run.write_bytes(lines(cell))
            validate_candidates(run, items)
            refuses("candidates against a shard release", lambda: validate_candidates(run, shard0), "census workset")
            proof = restrict(str(run), str(shard0), str(root / "view0"))
            view = proof["run"]["path"]
            assert Path(view).read_bytes() == lines([row for row in cell if row["item_id"] in ids[0::2]])
            validate_candidates(view, items)
            view_bytes, run_bytes = Path(view).read_bytes(), run.read_bytes()
            for label, path, changed in (("changed view row", Path(view), view_bytes.replace(b'"codex"', b'"aider"', 1)),
                                         ("changed source row", run, run_bytes.replace(b'"passed"', b'"failed"', 1))):
                path.write_bytes(changed)
                refuses(label, lambda: validate_candidates(view, items), "evidence bytes changed")
                path.write_bytes(run_bytes if path == run else view_bytes)
            proof_path = Path(view + VIEW_SUFFIX)
            proof_bytes = proof_path.read_bytes()
            proof_path.unlink()
            refuses("view without its proof", lambda: validate_candidates(view, items), "complete kapua-census330")
            proof_path.write_bytes(proof_bytes)
            forged = json.loads(proof_bytes)
            forged["release"] = G.reference(shard1)
            proof_path.write_text(json.dumps(forged))
            refuses("view proof naming another shard", lambda: validate_candidates(view, items),
                    "not the source cell's row bytes")
            proof_path.write_bytes(proof_bytes)
            validate_candidates(view, items)
            # A replacement-items view: the complete composed cell's rows on the
            # items its composition replaced, admitted like a shard view.
            replaced = [ids[0], ids[2]]
            composition = root / "cells/composition.json"
            composition.write_text(json.dumps({"view": {"sha256": G.reference(run)["sha256"]}, "rows": [
                {"item_id": row["item_id"], "from": "replacement" if row["item_id"] in replaced else "original"}
                for row in cell]}))
            item_ids = root / "cells/items.txt"
            item_ids.write_text("".join(iid + "\n" for iid in replaced))

            def by_items(listed, out):
                item_ids.write_text("".join(iid + "\n" for iid in listed))
                try:
                    return restrict_items(str(run), str(items), str(item_ids), str(composition), str(root / out))
                finally:
                    item_ids.write_text("".join(iid + "\n" for iid in replaced))
            iproof = by_items(replaced, "iview")
            iview = iproof["run"]["path"]
            assert iproof["items"] == [ids[2], ids[0]]  # the cell's order
            assert Path(iview).read_bytes() == lines([row for row in cell if row["item_id"] in replaced])
            validate_candidates(iview, items)
            ibytes = Path(iview).read_bytes()
            Path(iview).write_bytes(ibytes.replace(b'"codex"', b'"aider"', 1))
            refuses("changed items view row", lambda: validate_candidates(iview, items), "evidence bytes changed")
            iproof_path = Path(iview + VIEW_SUFFIX)
            iproof_bytes = iproof_path.read_bytes()
            iproof_path.write_text(json.dumps({**iproof, "run": G.reference(iview)}))
            refuses("changed items view row under a matching proof digest", lambda: validate_candidates(iview, items),
                    "not the source cell's row bytes on its items")
            Path(iview).write_bytes(ibytes)
            iproof_path.write_text(json.dumps({**iproof, "items": [ids[2]]}))
            refuses("items view proof listing fewer items", lambda: validate_candidates(iview, items),
                    "replaced items of its source's composition")
            iproof_path.write_bytes(iproof_bytes)
            validate_candidates(iview, items)
            refuses("items view of an item outside the source", lambda: by_items([*replaced, "kapua/z.feature:9"], "iv-z"),
                    "outside its source cell")
            refuses("items view of other items than the composition replaced", lambda: by_items(ids[:1], "iv-1"),
                    "replaced items of its source's composition")
            refuses("items view over a shard", lambda: restrict_items(
                str(run), str(shard0), str(item_ids), str(composition), str(root / "iv-shard")), "whole census")
            for label, bad in (("missing", cell[1:]), ("duplicate", cell + cell[:1]),
                               ("foreign", [{**cell[0], "item_id": "kapua/z.feature:9"}, *cell[1:]]),
                               ("other stamps", [{**row, "subset_digest": "0" * 16} for row in cell])):
                run.write_bytes(lines(bad))
                refuses(label + " census candidate", lambda: validate_candidates(run, items),
                        "disagrees" if label == "other stamps" else "complete kapua-census330 cell")
                refuses(label + " view source", lambda: restrict(str(run), str(shard0), str(root / ("v-" + label))),
                        "disagrees" if label == "other stamps" else "complete kapua-census330 cell")
                refuses(label + " items view source", lambda: by_items(replaced, "iv-" + label),
                        "disagrees" if label == "other stamps" else "complete kapua-census330 cell")
            run.write_bytes(run_bytes)
            validate_candidates(iview, items)
            refuses("view of the whole census", lambda: restrict(str(run), str(items), str(root / "v-census")),
                    "one shard")
            # The full-gold baseline: a new census observation of the reviewed files.
            gold_rows = [{"item_id": iid, "project": "kapua", "outcome": "passed", "adapter": "gold",
                          "metadata": {"source": "gold"}, "harness_version": RUNTIME["harness_version"],
                          "subset_id": identity["subset_id"], "subset_digest": identity["subset_digest"],
                          "produced_files": fx["gold_files"][iid]} for iid in ids]
            baseline = root / "gold-h23.jsonl"
            baseline.write_bytes(lines(gold_rows))
            validate_full_gold(baseline, items, census)
            baseline.write_bytes(lines([{**gold_rows[0], "produced_files": [{"file_path": "x", "code": ""}]},
                                        *gold_rows[1:]]))
            refuses("full-gold baseline running other files", lambda: validate_full_gold(baseline, items, census),
                    "reviewed gold files")
            baseline.write_bytes(lines(gold_rows[1:]))
            refuses("partial full-gold baseline", lambda: validate_full_gold(baseline, items, census), "complete")
            assert runtime_differences(dict(RUNTIME)) == []
            assert runtime_differences({**RUNTIME, "harness_version": 19}) == ["harness_version"]
        refuses("fixture census under the reviewed receipt pin", lambda: census_ids(items), "not the owner-approved")
        refuses("fixture historical gold under the reviewed pin",
                lambda: _projected(arguments["historical_gold"], ids), "evidence bytes changed")
    print("PASS: Kapua census330 sealed root (pilot selections kept), native mint, shard partition, "
          "shard and replacement-items views and census admission")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare", help="write the sealed census330 B100 root into a new directory")
    for flag in ("census-release", "historical-gold", "fresh-gold", "manifest", "audit", "boundary",
                 "engine-source", "pilot-sidecar", "pilot-parent-map", "out"):
        p.add_argument("--" + flag, required=True)
    p = commands.add_parser("verify", help="check a sealed root at its recorded absolute path")
    p.add_argument("--root", required=True)
    p = commands.add_parser("restrict", help="project a complete census330 cell onto one shard")
    for flag in ("run", "items", "out"):
        p.add_argument("--" + flag, required=True)
    p = commands.add_parser("restrict-items", help="project a complete composed census330 cell onto the items "
                                                   "its targeted re-collection replaced")
    for flag in ("run", "items", "item-ids", "composition", "out"):
        p.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        doc = prepare(**{key: getattr(args, key) for key in
                         ("census_release", "historical_gold", "fresh_gold", "manifest", "audit", "boundary",
                          "engine_source", "pilot_sidecar", "pilot_parent_map", "out")})
        result = {"root": doc["root"], "files": len(doc["files"]), "units": doc["units"]}
    elif args.command == "verify":
        doc = verify(args.root)
        result = {"root": doc["root"], "files": len(doc["files"]), "units": doc["units"]}
    elif args.command == "restrict-items":
        result = restrict_items(args.run, args.items, args.item_ids, args.composition, args.out)
    else:
        result = restrict(args.run, args.items, args.out)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
