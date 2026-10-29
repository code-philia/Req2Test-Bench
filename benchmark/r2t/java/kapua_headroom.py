"""Authenticated Kapua headroom gold and sample1 scoring projections.

These are offline byte projections. Full release/gold/K7 evidence stays with
its existing census parent; W4 alone decides the selected L workset.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import kapua_gold_coverage as G
from ..data import subsets as S

GOLD_SCHEMA = "r2t.kapua-gold-headroom-projection/1"
RUN_SCHEMA = "r2t.kapua-run-headroom-projection/1"
RUN_SUFFIX = ".headroom.json"


def _new_output(out, parent, items_path):
    out = Path(G.canonical(out))
    G.require(out.resolve() == out and not os.path.lexists(out), "headroom output exists or is noncanonical")
    approved = G.document(parent["approval"])
    protected = (parent["release_root"], approved["source_root"],
                 approved["native_capture"]["root"], approved["compiler_capture"]["root"],
                 str(Path(parent["full_gold"]["path"]).parent),
                 str(Path(parent["coverage"]["path"]).parent), str(Path(items_path).parent))
    for path in protected:
        G.require(not out.is_relative_to(path), "headroom output is inside protected input evidence")
    out.mkdir()
    return out


def _selection(items_path, parent, boundary_path):
    try:
        replay = S.replay_headroom(items_path)
    except S.SubsetRefused as exc:
        raise ValueError(str(exc)) from exc
    source = parent["selection"]["items"]
    G.checked(source)
    G.require(G.reference(replay["source_items"])["sha256"] == source["sha256"],
              "headroom source census differs from the authenticated parent")
    G.require(G.reference(boundary_path)["sha256"] == replay["provenance"]["boundary_sha256"],
              "headroom boundary differs from the original approved boundary")
    return replay


def project_gold(census_gold, items_path, out):
    parent_ref = G.reference(G.projection_path(census_gold))
    parent = G.document(parent_ref)
    G.require(parent.get("schema") == G.PROJECTION_SCHEMA, "headroom parent must be the original census projection")
    approved = G.document(parent["approval"])
    boundary_path = approved["boundary"]["path"]
    G.load_census_projection(census_gold, parent["selection"]["items"]["path"], boundary_path)
    replay = _selection(items_path, parent, boundary_path)
    raw = G._projected_gold_bytes(census_gold, replay["item_ids"])
    target = _new_output(out, parent, items_path)
    gold = target / "gold.jsonl"
    with gold.open("xb") as handle:
        handle.write(raw)
    receipt = {"schema": GOLD_SCHEMA, "project": "kapua", "route": "development",
               "parent": parent_ref,
               "selection": {"items": G.reference(items_path), "provenance": G.reference(replay["sidecar"])},
               "coverage": G.reference(gold), "items": len(replay["item_ids"]),
               "derivation": "selected original census-gold row bytes in original order",
               "approval_created": False}
    G.write(G.projection_path(gold), receipt)
    load_gold(str(gold), items_path, boundary_path)
    return receipt


def _load_gold(coverage_run, items_path, boundary_path, *, release=None):
    receipt = G.document(G.reference(G.projection_path(coverage_run)))
    G.require(set(receipt) == {"schema", "project", "route", "parent", "selection", "coverage",
                              "items", "derivation", "approval_created"}
              and receipt["schema"] == GOLD_SCHEMA and receipt["project"] == "kapua"
              and receipt["route"] == "development" and receipt["approval_created"] is False
              and receipt["derivation"] == "selected original census-gold row bytes in original order",
              "headroom gold receipt schema/derivation differs")
    parent = G.document(receipt["parent"])
    G.require(parent.get("schema") == G.PROJECTION_SCHEMA, "headroom gold parent is not a census projection")
    census_gold = parent["coverage"]["path"]
    G.require(receipt["parent"]["path"] == G.projection_path(census_gold), "headroom parent path differs")
    G.load_census_projection(census_gold, parent["selection"]["items"]["path"], boundary_path, release=release)
    replay = _selection(items_path, parent, boundary_path)
    selection = {"items": G.reference(items_path), "provenance": G.reference(replay["sidecar"])}
    G.require(receipt["selection"] == selection and type(receipt["items"]) is int
              and receipt["items"] == len(replay["item_ids"]), "headroom gold selection/count differs")
    G.require(receipt["coverage"]["path"] == G.canonical(coverage_run), "headroom gold path differs")
    raw = G.checked(receipt["coverage"])
    G.require(raw == G._projected_gold_bytes(census_gold, replay["item_ids"]),
              "headroom gold is not the original selected row bytes")
    rows = G.L._json_lines(raw, "Kapua headroom gold")
    G.require(len(rows) == len(replay["item_ids"]) and {r["item_id"] for r in rows} == set(replay["item_ids"]),
              "headroom gold omits or duplicates selected items")
    return {r["item_id"]: r["coverage_lines"] for r in rows}, receipt["coverage"]["sha256"], replay, parent


def load_gold(coverage_run, items_path, boundary_path, *, release=None):
    try:
        coverage, digest, _replay, _parent = _load_gold(coverage_run, items_path, boundary_path, release=release)
        return coverage, digest
    except (KeyError, TypeError, IndexError) as exc:
        raise ValueError("REFUSED: malformed Kapua headroom gold projection") from exc


def _gold_context(headroom_gold):
    receipt = G.document(G.reference(G.projection_path(headroom_gold)))
    G.require(receipt.get("schema") == GOLD_SCHEMA, "candidate view needs authenticated headroom gold")
    parent = G.document(receipt["parent"])
    approved = G.document(parent["approval"])
    boundary = approved["boundary"]["path"]
    items = receipt["selection"]["items"]["path"]
    _coverage, _digest, replay, parent = _load_gold(headroom_gold, items, boundary)
    return replay, parent


def _source_rows(run_path, replay, parent):
    from ..bench import population as P
    source = G.reference(run_path)
    matches = [entry for entry in replay["provenance"]["source_runs"]
               if entry["sample"] == 1 and entry["path"] == source["path"]
               and entry["sha256"] == source["sha256"]]
    G.require(len(matches) == 1, "candidate source is not one actual W4 sample1 run")
    raw = G.checked(source)
    rows = G.L._json_lines(raw, "Kapua sample1 source")
    ids = [r["item_id"] for r in rows]
    census = parent["selection"]["items"]["path"]
    G.require(len(ids) == len(set(ids)) and set(ids) == {iid for iid, _ in S.read_items(census)},
              "sample1 source is not the exact census")
    G.require(all(r.get("agent_system") == matches[0]["agent"] for r in rows), "sample1 source agent differs")
    identity = S.identify_for_inference(census)
    G.require(identity and all(r.get("subset_id") == identity["subset_id"]
              and r.get("subset_digest") == identity["subset_digest"] for r in rows), "sample1 census stamps differ")
    G.require(not any("campaign_digest" in r for r in rows), "headroom sample1 projection is ordinary development only")
    P.resolve(rows, run_path, explicit_release=census)
    wanted = set(replay["item_ids"])
    selected = b"".join(line for line in raw.splitlines(keepends=True)
                        if line.strip() and json.loads(line)["item_id"] in wanted)
    return source, selected, identity


def project_sample1(headroom_gold, source_run, out):
    replay, parent = _gold_context(headroom_gold)
    source, raw, _identity = _source_rows(source_run, replay, parent)
    target = _new_output(out, parent, replay["items"])
    path = target / "candidate.jsonl"
    with path.open("xb") as handle:
        handle.write(raw)
    receipt = {"schema": RUN_SCHEMA, "source_run": source,
               "headroom_gold": G.reference(headroom_gold),
               "gold_projection": G.reference(G.projection_path(headroom_gold)),
               "run": G.reference(path), "new_observations": 0,
               "derivation": "selected original sample1 row bytes in original order"}
    G.write(str(path) + RUN_SUFFIX, receipt)
    load_run_projection(str(path))
    return receipt


def load_run_projection(run_path):
    """Return an upstream-proved frozen L workset with original C stamps."""
    from ..bench import population as P, result_ledger as L
    try:
        receipt = G.document(G.reference(str(run_path) + RUN_SUFFIX))
        G.require(set(receipt) == {"schema", "source_run", "headroom_gold", "gold_projection", "run",
                                  "new_observations", "derivation"}
                  and receipt["schema"] == RUN_SCHEMA and type(receipt["new_observations"]) is int
                  and receipt["new_observations"] == 0
                  and receipt["derivation"] == "selected original sample1 row bytes in original order",
                  "sample1 headroom projection schema differs")
        G.checked(receipt["headroom_gold"])
        G.checked(receipt["gold_projection"])
        G.require(receipt["gold_projection"]["path"] == G.projection_path(receipt["headroom_gold"]["path"]),
                  "sample1 headroom gold proof path differs")
        replay, parent = _gold_context(receipt["headroom_gold"]["path"])
        source, expected, identity = _source_rows(receipt["source_run"]["path"], replay, parent)
        G.require(source == receipt["source_run"] and receipt["run"]["path"] == G.canonical(run_path)
                  and G.checked(receipt["run"]) == expected, "sample1 headroom view changed source or selected row bytes")
        ids = replay["item_ids"]
        scope = P.frozen_scope(item_ids=ids, workset={"item_count": len(ids),
            "ordered_item_ids_digest": L.ordered_item_ids_digest(ids)},
            subset_id=identity["subset_id"], subset_digest=identity["subset_digest"],
            source="validated Kapua sample1 projection onto headroom/control L")
        return {"scope": scope, "release": G.reference(replay["items"]),
                "source_run": source, "inference_valid": False,
                "inference_reason": replay["provenance"]["inference_reason"],
                "selection": G.reference(replay["sidecar"])}
    except (KeyError, TypeError, IndexError) as exc:
        raise ValueError("REFUSED: malformed Kapua sample1 headroom projection") from exc


def validate_candidate_workset(run_path, release_path):
    """The live/saved TQ input gate; a deleted view proof cannot change scope."""
    proof = str(run_path) + RUN_SUFFIX
    if os.path.lexists(proof):
        view = load_run_projection(run_path)
        G.require(G.reference(release_path) == view["release"], "candidate projection and mutation L differ")
        return
    if os.path.basename(str(release_path)).startswith("headroom_"):
        from ..bench import population as P
        rows = G.L._json_lines(G.raw_file(run_path), "headroom candidate")
        try:
            population = P.resolve(rows, run_path, explicit_release=release_path)
            G.require(population["complete"] is True, "candidate does not cover the complete L workset")
        except P.PopulationRefusal as exc:
            raise ValueError(str(exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("project-gold")
    p.add_argument("--census-gold", required=True)
    p.add_argument("--items", required=True)
    p.add_argument("--out", required=True)
    p = commands.add_parser("project-sample1")
    p.add_argument("--headroom-gold", required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = (project_gold(args.census_gold, args.items, args.out) if args.command == "project-gold"
              else project_sample1(args.headroom_gold, args.run, args.out))
    print(json.dumps(result, sort_keys=True))
    return 0


def _selftest_with_gold(root, census_gold, census, manifest, release, boundary, engine_source, *, reference=False):
    """Actual R/C/K7 parent fixture through native L and ordinary reporting."""
    import contextlib
    import io
    from ..bench import population as P, results as R, report as REPORT, cli, test_quality as TQ
    from ..toolkit import mutation_java as MJ, mutation_asset_index as ASSETS
    from ..toolkit.subset_writer import write_subset, write_budgeted_sample
    from ..data import mutation_attestation as A

    def refuses(label, function):
        try:
            function()
        except (ValueError, OSError, SystemExit, P.PopulationRefusal):
            return
        raise AssertionError(label + " was accepted")

    ids = [iid for iid, _ in S.read_items(census)]
    identity = S.identify_for_inference(census)
    runs = []
    original_rows = {}
    for agent in ("aider", "openhands"):
        for sample in (1, 2, 3):
            path = root / f"{agent}-sample{sample}.jsonl"
            selected = ids if sample == 1 else ids[1:]
            rows = [{"item_id": iid, "outcome": "failed" if agent == "aider" and iid == ids[0] else "passed",
                     "agent_system": agent, "model": "fixture-original-model", "condition": "c2", "trials": 0,
                     "harness_commit": "original-sample1-producer", "coverage": True,
                     "coverage_lines": {manifest["mutants"][0]["file"]: [3]},
                     "produced_files": [{"file_path": "tests/Steps.java", "code": "class Steps {}"}],
                     "subset_id": identity["subset_id"], "subset_digest": identity["subset_digest"]} for iid in selected]
            path.write_bytes(b"".join((json.dumps(r, sort_keys=True) + "\n").encode() for r in rows))
            runs.append((agent, sample, str(path)))
            original_rows[agent, sample] = rows
    drawn = S.headroom_subset(census, runs, boundary, 20260909)
    l_path, l_sidecar = write_subset(drawn, str(root / "headroom-inputs/headroom_kapua"))
    replay = S.replay_headroom(l_path)
    l_ids = set(replay["item_ids"])
    assert len(l_ids) == 2 < len(ids) and ids[0] in l_ids
    assert S.identify_for_inference(l_path)["inference_valid"] is False
    assert Path(S.headroom_boundary_path(l_path)).read_bytes() == Path(boundary).read_bytes()
    assert S.identify_for_inference(replay["source_items"])["subset_digest"] == identity["subset_digest"]
    l_gold_receipt = project_gold(census_gold, l_path, str(root / "headroom-gold"))
    gold = l_gold_receipt["coverage"]["path"]
    cov, digest = G.load_projection(gold, l_path, boundary, release=release)
    assert set(cov) == l_ids
    map_ids, release_sha = MJ._map_release_inputs(release, l_path, gold, kapua=True)
    mapping, _ = MJ._build_population_map(manifest, gold, release_ids=map_ids,
        release_sha256=release_sha, kapua_release=release, boundary_path=boundary, items_path=l_path)
    assert {iid for values in mapping["by_mutant"].values() for iid in values} == l_ids
    G.write(root / "map-headroom.json", mapping)
    native = root / "native-headroom"
    native.mkdir()
    minted = ASSETS.mint("kapua", raw_manifest_path=str(root / "population.json"),
        scored_manifest_path=str(root / "population.json"), map_path=str(root / "map-headroom.json"),
        coverage_path=gold, release_path=l_path, boundary_path=boundary, audit_path=str(root / "audit.json"),
        asset_index_out=str(native / "index.json"), validation_out=str(native / "validation.json"),
        engine_source_path=engine_source, expected_engine=MJ.ENGINE)
    draw = S.budgeted_sample(l_path, str(root / "map-headroom.json"), str(root / "population.json"), 100, 20260909)
    derived, sidecar = write_budgeted_sample(draw, str(root / "budgeted-headroom"))
    def native_read():
        return A.validate_campaign_asset_inputs(minted["mutation_validation"],
            manifest_path=str(root / "population.json"), map_path=derived,
            release_path=l_path, budgeted_sidecar=sidecar, require_release_ready=True)
    assert native_read()["map"] == draw["derived_map"]
    source_run = runs[0][2]
    source_bytes = Path(source_run).read_bytes()
    view = project_sample1(gold, source_run, str(root / "sample1-headroom-view"))
    view_path = view["run"]["path"]
    rows = G.L._json_lines(Path(view_path).read_bytes(), "view")
    assert {r["item_id"] for r in rows} == l_ids and len(rows) == 2
    assert all(r["subset_digest"] == identity["subset_digest"] and r["harness_commit"] == "original-sample1-producer" for r in rows)
    assert Path(source_run).read_bytes() == source_bytes
    direct = P.resolve(original_rows["aider", 1], source_run, explicit_release=census)
    result = P.resolve(rows, view_path, explicit_release=l_path)
    assert direct["planned_n"] == 6 and result["planned_n"] == result["observed_n"] == 2
    assert result["inference_valid"] is False and result["source_run"]["path"] == source_run
    from ..core.boundary import load_boundary
    rendered = R.results(view_path, gold_path=gold, boundary=load_boundary(boundary),
                         api_scoring="none", release_path=l_path)
    assert rendered["population"]["planned_n"] == 2 and rendered["population"]["inference_valid"] is False
    assert "descriptive-only" in R.render_text(rendered)
    with contextlib.redirect_stdout(io.StringIO()) as capture:
        reports = REPORT.report([view_path], release_paths=[l_path])
    assert "inference_valid      false" in capture.getvalue()
    assert next(iter(reports.values()))["population"]["planned_n"] == 2
    # Fresh interpreter, with only the same native-capture fixture boundary
    # replaced. All persisted gold/projection/map/report readers are real.
    import subprocess
    import sys
    child = r'''
import contextlib, io, json, sys
from pathlib import Path
from r2t.java import kapua_gold_coverage as G
from r2t.bench import population as P, results as R, report as REPORT
from r2t.core.boundary import load_boundary
root = Path(sys.argv[1])
plan = json.loads((root / 'collected/plan.json').read_text())
manifest = json.loads((root / 'population.json').read_text())
def fixture_inputs(value):
    assert value == plan['inputs']
    for key in ('boundary', 'profile'):
        G.checked(value[key])
    G.checked({'path': str(root / 'native.json'), 'sha256': value['native_capture']['receipt_sha256']})
    G.checked({'path': str(root / 'compiler.json'), 'sha256': value['compiler_capture']['receipt_sha256']})
    source_files = {p for module in manifest['analysis_recipe']['modules'] for p in module['source_files']}
    return G.P.measured_release(value['release_root']), load_boundary(value['boundary']['path']), {}, source_files
def fixture_pool(*args):
    for worker in plan['pool']['workers']:
        for key in ('spec','runtime','binding'):
            G.checked(worker[key])
    return plan['pool'], []
G.load_inputs = fixture_inputs
G.offline_pool = fixture_pool
G.W.preflight = lambda *args, **kwargs: {}
view = str(root / 'sample1-headroom-view/candidate.jsonl')
l = str(root / 'headroom-inputs/headroom_kapua.jsonl')
gold = str(root / 'headroom-gold/gold.jsonl')
result = R.results(view, gold_path=gold, boundary=load_boundary(str(root / 'boundary.yml')),
                   api_scoring='none', release_path=l)
with contextlib.redirect_stdout(io.StringIO()):
    reports = REPORT.report([view], release_paths=[l])
assert result['population']['planned_n'] == result['population']['observed_n'] == 2
assert result['population']['inference_valid'] is False
assert next(iter(reports.values()))['population']['planned_n'] == 2
source = str(root / 'aider-sample1.jsonl')
rows = [json.loads(line) for line in Path(source).read_text().splitlines()]
assert P.resolve(rows, source, explicit_release=str(root / 'census/eval-census.jsonl'))['planned_n'] == 6
print('PASS fresh-process C origin and L report/results workset')
'''
    process = subprocess.Popen([sys.executable, '-c', child, str(root)],
        env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[2]), 'PYTHONDONTWRITEBYTECODE': '1'},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    child_out, child_error = process.communicate(timeout=90)
    assert process.returncode == 0, child_out + child_error
    assert 'PASS fresh-process' in child_out
    validate_candidate_workset(view_path, l_path)
    refuses("wrong explicit workset", lambda: P.resolve(rows, view_path, explicit_release=census))
    refuses("wrong mutation workset", lambda: validate_candidate_workset(view_path, census))
    refuses("sample2 is not sample1", lambda: project_sample1(gold, runs[1][2], str(root / "bad-sample2")))
    for items in (None, l_path):
        args = argparse.Namespace(run=[view_path, view_path], items=items)
        refuses("projected inference regardless of --items", lambda: cli._compare_impl(args))
    # An ordinary hidden L run is identifiable without inventing C stamps.
    hidden = root / "hidden.jsonl"
    li = S.identify_for_inference(l_path)
    hidden_rows = [dict(row, subset_id=li["subset_id"], subset_digest=li["subset_digest"]) for row in rows]
    hidden.write_text("".join(json.dumps(row) + "\n" for row in hidden_rows))
    assert P.resolve(hidden_rows, str(hidden), explicit_release=l_path)["planned_n"] == 2
    refuses("hidden inference without --items", lambda: cli._compare_impl(argparse.Namespace(run=[str(hidden), str(hidden)], items=None)))
    for path in (Path(l_path), Path(l_sidecar), Path(S.headroom_boundary_path(l_path)),
                 Path(replay["source_items"]), Path(source_run), Path(G.projection_path(gold)),
                 Path(gold), Path(view_path)):
        before = path.read_bytes()
        path.write_bytes(before + b" ")
        if path == Path(G.projection_path(gold)):
            refuses("native projection pin tamper", native_read)
        else:
            refuses("changed proof/input " + str(path), lambda: load_run_projection(view_path))
        path.write_bytes(before)
    proof = Path(view_path + RUN_SUFFIX)
    proof_bytes = proof.read_bytes()
    changed_proof = json.loads(proof_bytes)
    changed_proof["new_observations"] = 1
    proof.write_text(json.dumps(changed_proof))
    refuses("view proof cannot claim a new observation", lambda: load_run_projection(view_path))
    proof.write_bytes(proof_bytes)
    proof.unlink()
    refuses("lost view proof cannot report L", lambda: P.resolve(rows, view_path, explicit_release=l_path))
    refuses("lost view proof cannot mutate L", lambda: validate_candidate_workset(view_path, l_path))
    proof.write_bytes(proof_bytes)
    assert load_run_projection(view_path)["scope"]["item_ids"] == tuple(replay["item_ids"])
    assert native_read()["map"] == draw["derived_map"]
    if reference:
        from . import kapua_reference as KRef
        KRef._selftest_with_headroom(root, {
            "mutation_validation": minted["mutation_validation"],
            "manifest": str(root / "population.json"), "map": derived,
            "release": l_path, "budgeted_sidecar": sidecar}, gold, runs[3][2])
    print("PASS: strict R>C>L gold/view/native W16/report population and descriptive inference")


def selftest():
    # Integrated original-receipt/native-reader fixtures live with their owner.
    return G.selftest(headroom=True)


if __name__ == "__main__":
    raise SystemExit(main())
