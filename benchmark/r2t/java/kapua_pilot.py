"""Authenticated checked-interface companions for the fixed Kapua pilot.

Historical gold remains the mutation-map authority. Fresh gold supplies actual
step attribution and the current full-gold control, never replacement history.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import kapua_census as KC
from . import kapua_gold_coverage as G
from ..data import subsets as S
from ..toolkit import checked_interfaces as CI

SCHEMA = "r2t.kapua-checked-pilot/1"
GOLD_SCHEMA = "r2t.kapua-gold-checked-pilot-projection/1"
CONTROL_SCHEMA = "r2t.kapua-pilot-full-gold/1"
RESTRICTION_SCHEMA = "r2t.kapua-pilot-census-restriction/1"
NAME = "kapua-pilot.jsonl"
SUFFIX = ".pilot.json"
RESTRICTION_SUFFIX = ".census-restriction.json"
REASON = "fixed pilot of reference implementation groups; no population inference"
#: KAPUA_CENSUS334_CHECKED_INTERFACES_AMENDMENT.md section 7.1.
COMPARISON = "cross_map_development_sensitivity"
RESTRICTION_DERIVATION = "original census-cell row bytes on the pilot IDs, in original order"


def is_pilot(path):
    return Path(path).name == NAME or os.path.lexists(str(path) + SUFFIX)


def rows(path):
    return [json.loads(line) for _iid, line in S.read_items(str(path))]


def encoded(values):
    return b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in values)


def implementation_groups(closures, item_ids):
    """Existing resolved declaration identities, without another digest scheme."""
    by_item = {}
    for closure in closures:
        iid = closure["item_id"]
        G.require(iid not in by_item, "duplicate closure item")
        by_item[iid] = closure
    grouped = {}
    for iid in item_ids:
        G.require(iid in by_item, "requirement has no closure: " + iid)
        key = set()
        for step in by_item[iid]["steps"]:
            if step["side"] == "removable":
                pair = (step["definition"]["file"], step["location"])
                G.require(all(isinstance(s, str) and s for s in pair), "missing resolved method identity")
                key.add(pair)
        G.require(key, "requirement has no removable implementation: " + iid)
        grouped.setdefault(tuple(sorted(key)), []).append(iid)
    groups = [{"methods": [list(pair) for pair in key], "representative": min(members),
               "members": sorted(members)} for key, members in sorted(grouped.items())]
    return {"schema": "r2t.kapua-implementation-groups/1", "items": len(item_ids),
            "groups": groups, "group_count": len(groups),
            "requirement_to_representative": {iid: group["representative"]
                for group in groups for iid in group["members"]}}


def fresh_gold(receipt_ref, parent):
    receipt = G.document(receipt_ref)
    plan = G.document(receipt["plan"])
    release, boundary, native, files = G.load_inputs(plan["inputs"])
    G.require(plan["release"] == parent["release"], "fresh gold names another original release")
    approved = G.document(parent["approval"])
    G.require(plan["inputs"]["source_root"] == approved["source_root"]
              and plan["inputs"]["boundary"] == approved["boundary"],
              "fresh gold changed source or boundary")
    root = Path(receipt_ref["path"]).parent
    G.require(receipt["plan"]["path"] == str(root / "plan.json")
              and receipt["rows"]["path"] == str(root / "gold.jsonl"), "fresh gold paths differ")
    G.validate_plan(plan, root, release=release, native=native)
    G.check_receipt(receipt, plan, source_files=files, boundary=boundary)
    return receipt, plan, release


def _derive(inputs):
    G.require(set(inputs) == {"census_projection", "fresh_gold_receipt", "index"}, "pilot input fields differ")
    parent = G.document(inputs["census_projection"])
    G.require(parent.get("schema") == G.PROJECTION_SCHEMA, "pilot needs original census evidence")
    approved = G.document(parent["approval"])
    boundary = approved["boundary"]["path"]
    G.require(inputs["census_projection"]["path"] == G.projection_path(parent["coverage"]["path"]),
              "pilot census proof path differs")
    coverage = G.load_census_projection(parent["coverage"]["path"], parent["selection"]["items"]["path"], boundary)
    receipt, plan, release = fresh_gold(inputs["fresh_gold_receipt"], parent)
    G.checked(inputs["index"])
    annotation = CI.derive(receipt["rows"]["path"], inputs["index"]["path"], boundary,
                           release["items_path"], approved["source_root"])
    verification = G.document(parent["selection"]["annotation_verification"])
    old_pool = rows(verification["annotated_companion"]["path"])
    census = rows(parent["selection"]["items"]["path"])
    groups = implementation_groups(G.document(G.reference(Path(release["root"]) / "control-artifacts/closures.json")),
                                   [r["item_id"] for r in old_pool])
    selected_ids = [r["item_id"] for r in census]
    representatives = groups["requirement_to_representative"]
    G.require(all(representatives[iid] == iid for iid in selected_ids)
              and len({representatives[iid] for iid in selected_ids}) == len(selected_ids),
              "pilot items are not distinct first implementation representatives")
    def annotate(source):
        return [{**row, "checked_interfaces": annotation["items"][row["item_id"]]} for row in source]
    return {"parent": parent, "fresh_receipt": receipt, "fresh_plan": plan, "coverage": coverage,
            "annotation": annotation, "groups": groups, "items": annotate(census), "pool": annotate(old_pool)}


def _new_root(out, context):
    out = Path(G.canonical(out))
    G.require(out.resolve() == out and not os.path.lexists(out), "pilot output exists or is noncanonical")
    parent = context["parent"]
    approved = G.document(parent["approval"])
    protected = [parent["release_root"], approved["source_root"], approved["native_capture"]["root"],
                 approved["compiler_capture"]["root"], str(Path(parent["coverage"]["path"]).parent),
                 str(Path(parent["selection"]["items"]["path"]).parent),
                 str(Path(context["fresh_receipt"]["rows"]["path"]).parent)]
    G.require(not any(out.is_relative_to(p) for p in protected), "pilot output lies inside retained inputs")
    out.mkdir()
    return out


def prepare(census_gold, gold_receipt, index, out):
    inputs = {"census_projection": G.reference(G.projection_path(census_gold)),
              "fresh_gold_receipt": G.reference(gold_receipt), "index": G.reference(index)}
    context = _derive(inputs)
    root = _new_root(out, context)
    outputs = {}
    for key, name in (("items", NAME), ("pool", "items.jsonl")):
        path = root / name
        path.write_bytes(encoded(context[key]))
        outputs[key] = G.reference(path)
    for key, name in (("annotation", "checked_interfaces.json"), ("groups", "implementation_groups.json")):
        path = root / name
        G.write(path, context[key])
        outputs[key] = G.reference(path)
    doc = {"schema": SCHEMA, "project": "kapua", "route": "development", "inputs": inputs,
           "outputs": outputs, "inference_valid": False, "inference_reason": REASON}
    G.write(str(root / NAME) + SUFFIX, doc)
    load_selection(root / NAME)
    return doc


def load_selection(items):
    try:
        items = G.canonical(items)
        doc = G.document(G.reference(items + SUFFIX))
        G.require(set(doc) == {"schema", "project", "route", "inputs", "outputs", "inference_valid", "inference_reason"}
                  and doc["schema"] == SCHEMA and doc["project"] == "kapua" and doc["route"] == "development"
                  and doc["inference_valid"] is False and doc["inference_reason"] == REASON, "pilot receipt shape differs")
        context = _derive(doc["inputs"])
        output = doc["outputs"]
        G.require(set(output) == {"items", "pool", "annotation", "groups"}
                  and output["items"]["path"] == items, "pilot output paths differ")
        for key in ("items", "pool"):
            G.require(G.checked(output[key]) == encoded(context[key]), "pilot changed task/annotation bytes: " + key)
        for key in ("annotation", "groups"):
            G.require(G.document(output[key]) == context[key], "pilot derivation differs: " + key)
        return doc, context
    except (KeyError, TypeError, IndexError) as exc:
        raise ValueError("REFUSED: malformed Kapua pilot receipt") from exc


def identify(items):
    doc, _context = load_selection(items)
    return {"subset_id": Path(items).stem, "subset_digest": doc["outputs"]["items"]["sha256"][:16],
            "sidecar": G.canonical(str(items) + SUFFIX), "inference_valid": False,
            "inference_reason": REASON, "allow_cluster_siblings": False}


def project_mapping(items, out):
    doc, context = load_selection(items)
    root = _new_root(out, context)
    gold = root / "gold.jsonl"
    gold.write_bytes(G.checked(context["parent"]["coverage"]))
    receipt = {"schema": GOLD_SCHEMA, "selection": G.reference(str(items) + SUFFIX),
               "coverage": G.reference(gold), "derivation": "original census-gold bytes unchanged"}
    G.write(G.projection_path(gold), receipt)
    return receipt


def load_mapping(coverage_run, items, boundary, *, release=None):
    receipt = G.document(G.reference(G.projection_path(coverage_run)))
    G.require(set(receipt) == {"schema", "selection", "coverage", "derivation"}
              and receipt["schema"] == GOLD_SCHEMA
              and receipt["derivation"] == "original census-gold bytes unchanged", "pilot gold projection shape differs")
    G.require(receipt["selection"] == G.reference(str(items) + SUFFIX), "pilot gold names another selection")
    _doc, context = load_selection(items)
    parent = context["parent"]
    if release is not None:
        G.require(parent["release"] == G.release_identity(release), "pilot gold names another full release")
    approved = G.document(parent["approval"])
    G.require(G.reference(boundary) == approved["boundary"], "pilot gold names another boundary")
    G.require(receipt["coverage"]["path"] == G.canonical(coverage_run)
              and G.checked(receipt["coverage"]) == G.checked(parent["coverage"]), "pilot changed historical gold bytes")
    return context["coverage"][0], receipt["coverage"]["sha256"]


def project_full_gold(items, out):
    _doc, context = load_selection(items)
    root = _new_root(out, context)
    gold = root / "gold.jsonl"
    gold.write_bytes(G._projected_gold_bytes(context["fresh_receipt"]["rows"]["path"],
                                            [r["item_id"] for r in context["items"]]))
    receipt = {"schema": CONTROL_SCHEMA, "selection": G.reference(str(items) + SUFFIX), "rows": G.reference(gold)}
    G.write(str(gold) + ".pilot-control.json", receipt)
    return receipt


def validate_full_gold(path, items):
    _doc, context = load_selection(items)
    ref = G.reference(path)
    proof = G.document(G.reference(str(path) + ".pilot-control.json"))
    G.require(proof == {"schema": CONTROL_SCHEMA, "selection": G.reference(str(items) + SUFFIX), "rows": ref},
              "pilot full-gold proof differs")
    G.require(G.checked(ref) == G._projected_gold_bytes(context["fresh_receipt"]["rows"]["path"],
                                                       [r["item_id"] for r in context["items"]]),
              "pilot full-gold baseline is not fresh selected original row bytes")



def _control(path, items, asset_index_sha256, role, context):
    """Replay every stamped baseline row, including authentic strip refusals."""
    from ..bench import reference_workloads as RW

    G.require(role in {"stripped_gold", "stub"}, "pilot source replay needs stripped gold or stub")
    observed = rows(path)
    G.require(observed and isinstance(observed[0].get("reference_derivation"), dict),
              "pilot control has no recorded source derivation")
    G.require(all(row.get("harness_version") == context["fresh_plan"]["producer"]["harness_version"]
                  for row in observed), "pilot control differs from the fresh harness")
    recipe = {**observed[0]["reference_derivation"], "asset_index_sha256": asset_index_sha256}
    inputs = context["fresh_plan"]["inputs"]
    release_root = Path(inputs["release_root"])
    sources = {"gold_root": G.execution_gold(inputs),
               "release_gold_root": str(release_root / "gold"),
               "closures_path": str(release_root / "control-artifacts/closures.json"),
               "feature_root": inputs["source_root"]}
    control = RW._development_control_input(project="kapua", role=role, run_path=str(path),
        recipe=recipe, execution_release_path=str(items), **sources)
    # The selection already binds the fresh plan and source trees. Preserve
    # their paths for runtime containment without creating another identity.
    control["source_paths"] = {**sources, "pilot_selection": str(items) + SUFFIX}
    return control


def validate_control(path, items, asset_index_sha256, role):
    _doc, context = load_selection(items)
    return _control(path, items, asset_index_sha256, role, context)


def _census_lines(source, census, pilot_ids):
    """The pilot-ID lines of one complete census330 cell, byte for byte."""
    raw = G.checked(source)
    G.checked(census)
    receipt = KC.load_selection(census["path"])
    identity = KC.identify(census["path"])
    G.require(set(receipt["pilot24_item_ids"]) == pilot_ids, "census receipt names other pilot IDs")
    rows = G.L._json_lines(raw, "Kapua census cell")
    ids = [row["item_id"] for row in rows]
    G.require(len(ids) == len(set(ids)) and set(ids) == set(receipt["item_ids"]),
              "restriction source is not one complete census330 cell")
    G.require(all(row.get("subset_id") == identity["subset_id"]
                  and row.get("subset_digest") == identity["subset_digest"] for row in rows),
              "restriction source rows carry another release's stamps")
    # `_json_lines` admitted exactly one LF-terminated record per line.
    return b"".join(line + b"\n" for line, row in zip(raw.split(b"\n"), rows)
                    if row["item_id"] in pilot_ids)


def _restriction(path, items, context):
    try:
        receipt = G.document(G.reference(str(path) + RESTRICTION_SUFFIX))
        G.require(set(receipt) == {"schema", "project", "route", "comparison", "selection", "census_release",
                                  "source_run", "run", "new_observations", "derivation", "inference_valid"}
                  and receipt["schema"] == RESTRICTION_SCHEMA and receipt["project"] == "kapua"
                  and receipt["route"] == "development" and receipt["comparison"] == COMPARISON
                  and type(receipt["new_observations"]) is int and receipt["new_observations"] == 0
                  and receipt["derivation"] == RESTRICTION_DERIVATION and receipt["inference_valid"] is False,
                  "census restriction proof shape differs")
        G.require(receipt["selection"] == G.reference(str(items) + SUFFIX),
                  "census restriction names another pilot selection")
        expected = _census_lines(receipt["source_run"], receipt["census_release"],
                                 {row["item_id"] for row in context["items"]})
        G.require(receipt["run"]["path"] == G.canonical(path) and G.checked(receipt["run"]) == expected,
                  "census restriction view is not the selected source row bytes")
        return receipt
    except (KeyError, TypeError, IndexError) as exc:
        raise ValueError("REFUSED: malformed Kapua census restriction") from exc


def restrict_census(items, census_release, source_run, out):
    """Census amendment section 7.1: one complete census330 cell's rows on the
    pilot IDs, for the pilot's B100 references. A cross-map development
    sensitivity: no new observation, and the rows keep their census stamps, so
    only this proof admits them as pilot candidates."""
    _doc, context = load_selection(items)
    source, census = G.reference(source_run), G.reference(census_release)
    selected = _census_lines(source, census, {row["item_id"] for row in context["items"]})
    root = _new_root(out, context)
    view = root / "candidate.jsonl"
    with view.open("xb") as handle:
        handle.write(selected)
    receipt = {"schema": RESTRICTION_SCHEMA, "project": "kapua", "route": "development",
               "comparison": COMPARISON, "selection": G.reference(str(items) + SUFFIX),
               "census_release": census, "source_run": source, "run": G.reference(view),
               "new_observations": 0, "derivation": RESTRICTION_DERIVATION, "inference_valid": False}
    G.write(str(view) + RESTRICTION_SUFFIX, receipt)
    _restriction(view, items, context)
    return receipt


def validate_candidates(path, items):
    """A complete pilot cell, or a section 7.1 restriction of a census cell."""
    from ..bench import population as P
    doc, context = load_selection(items)
    if os.path.lexists(str(path) + RESTRICTION_SUFFIX):
        _restriction(path, items, context)
        return doc
    observed = G.L._json_lines(G.raw_file(path), "Kapua pilot candidates")
    ids = [r["item_id"] for r in observed]
    G.require(len(ids) == len(set(ids)) and set(ids) == {r["item_id"] for r in context["items"]},
              "candidate does not cover the exact complete pilot")
    population = P.resolve(observed, str(path), explicit_release=str(items))
    G.require(population["complete"] is True, "candidate pilot is incomplete")
    return doc



def _selftest_with_gold(root, census_gold, gold_receipt, boundary, manifest, full_release):
    """Real original-gold, selection, native-map and ordinary-report readers."""
    from unittest.mock import patch
    from ..bench import population as POP
    from ..toolkit import mutation_java as MJ

    def refuses(label, fn):
        try:
            fn()
        except (ValueError, OSError, POP.PopulationRefusal):
            print("PASS refusal: " + label)
            return
        raise AssertionError(label + " accepted")

    # The derivation's role/public/index rules have their own real fixtures.
    # Here an independent deterministic annotation isolates provenance joins.
    index = root / "pilot-index.json"
    G.write(index, {"fixture": "index"})
    def annotation(gold, index_path, boundary_path, items_path, source):
        return {"schema": CI.SCHEMA, "project": "kapua", "items": {
            row["item_id"]: {"checked": [], "empty_reason": "no_action_or_check_call"}
            for row in rows(items_path)}, "summary": {}, "detail": {}}
    with patch.object(CI, "derive", side_effect=annotation):
        first = prepare(census_gold, gold_receipt, str(index), str(root / "pilot"))
        second = prepare(census_gold, gold_receipt, str(index), str(root / "pilot-again"))
        items = first["outputs"]["items"]["path"]
        assert G.checked(first["outputs"]["items"]) == G.checked(second["outputs"]["items"])
        doc, context = load_selection(items)
        assert context["groups"]["items"] == 12 and context["groups"]["group_count"] == 6
        assert len(context["items"]) == 6
        assert S.identify_for_inference(items)["inference_valid"] is False
        projection = project_mapping(items, str(root / "pilot-mapping"))
        mapped_gold = projection["coverage"]["path"]
        assert G.raw_file(mapped_gold) == G.raw_file(census_gold)
        assert G.load_projection(mapped_gold, items, boundary, release=full_release)[0] == context["coverage"][0]
        ids, digest = MJ._map_release_inputs(full_release, items, mapped_gold, kapua=True)
        mapping, _ = MJ._build_population_map(manifest, mapped_gold, release_ids=ids,
            release_sha256=digest, kapua_release=full_release, boundary_path=boundary, items_path=items)
        assert mapping["release_sha256"] == G.reference(items)["sha256"]
        assert mapping["coverage_sha256"] == G.reference(census_gold)["sha256"]
        fresh = project_full_gold(items, str(root / "pilot-full-gold"))
        baseline = fresh["rows"]["path"]
        validate_full_gold(baseline, items)
        original = G.raw_file(items)
        changed = rows(items)
        changed[0]["checked_interfaces"] = {"checked": [], "empty_reason": "forged"}
        Path(items).write_bytes(encoded(changed))
        # Even restating the file digest cannot authorize a replacement annotation.
        proof_path = Path(items + SUFFIX)
        proof_bytes = proof_path.read_bytes()
        updated = json.loads(proof_bytes)
        updated["outputs"]["items"] = G.reference(items)
        proof_path.write_bytes(encoded([updated]))
        refuses("annotation without matching derivation", lambda: load_selection(items))
        Path(items).write_bytes(original)
        proof_path.write_bytes(proof_bytes)
        old_gold = G.raw_file(mapped_gold)
        Path(mapped_gold).write_bytes(old_gold + b" ")
        refuses("changed historical row bytes", lambda: G.load_projection(mapped_gold, items, boundary))
        Path(mapped_gold).write_bytes(old_gold)
        proof_path.unlink()
        refuses("removed selection proof", lambda: S.identify_for_inference(items))
        proof_path.write_bytes(proof_bytes)
        identity = identify(items)
        candidate_rows = [{**row, "adapter": "aider", "agent_system": "aider",
                           "subset_id": identity["subset_id"], "subset_digest": identity["subset_digest"]}
                          for row in rows(baseline)]
        run = root / "pilot-candidate.jsonl"
        run.write_bytes(encoded(candidate_rows))
        validate_candidates(run, items)
        result = POP.resolve(candidate_rows, str(run), explicit_release=items)
        assert result["complete"] and result["planned_n"] == 6 and result["inference_valid"] is False
        for label, bad in (("missing", candidate_rows[:-1]), ("duplicate", candidate_rows + candidate_rows[:1]),
                           ("foreign", [{**candidate_rows[0], "item_id": "kapua/foreign:1"}, *candidate_rows[1:]]),
                           ("wrong subset", [{**row, "subset_digest": "0" * 16} for row in candidate_rows])):
            run.write_bytes(encoded(bad))
            refuses(label + " candidate member/identity", lambda: validate_candidates(run, items))
        run.write_bytes(encoded(candidate_rows))
        _selftest_restriction(root, items, rows(baseline), refuses)
    print("PASS: fixed pilot retains original gold and authenticates annotations, grouping and complete candidates")


def _selftest_restriction(root, items, gold_rows, refuses):
    """Section 7.1 on the real pilot selection and a census330-shaped release;
    only the census receipt pin moves to the fixture, as in `kapua_census`."""
    import hashlib
    from unittest.mock import patch
    from ..bench import population as POP
    from ..core.paths import BENCHMARK_ROOT

    pilot = [row["item_id"] for row in rows(items)]
    census_ids = sorted(pilot + ["kapua/census/Only.feature:3", "kapua/census/Only.feature:9"])
    reviewed = json.loads((Path(BENCHMARK_ROOT).parent / "maps/kapua/census334/census330.json").read_bytes())

    def release(name, pilot24):
        path = root / name / KC.NAME
        path.parent.mkdir()
        path.write_bytes(encoded([{"item_id": iid, "project": "kapua", "checked_interfaces": {}}
                                  for iid in census_ids]))
        receipt = {**reviewed, "item_ids": census_ids, "pilot24_item_ids": pilot24, "outputs": {
            **reviewed["outputs"], "items": {"member": KC.NAME, "n": len(census_ids),
                                             "sha256": G.reference(path)["sha256"]}}}
        raw = (json.dumps(receipt, indent=1, sort_keys=True) + "\n").encode()
        (path.parent / KC.RECEIPT).write_bytes(raw)
        return str(path), hashlib.sha256(raw).hexdigest()

    census, pin = release("census-release", pilot)
    with patch.object(KC, "RECEIPT_SHA256", pin):
        identity = KC.identify(census)
        by_id = {row["item_id"]: row for row in gold_rows}
        cell = [{**by_id.get(iid, {"item_id": iid, "outcome": "failed"}), "adapter": "codex",
                 "agent_system": "codex", "subset_id": identity["subset_id"],
                 "subset_digest": identity["subset_digest"]} for iid in reversed(census_ids)]
        source = root / "census-cell.jsonl"
        source.write_bytes(encoded(cell))
        proof = restrict_census(items, census, str(source), str(root / "restricted"))
        view = proof["run"]["path"]
        assert Path(view).read_bytes() == encoded([row for row in cell if row["item_id"] in pilot])
        assert proof["new_observations"] == 0 and proof["comparison"] == COMPARISON
        assert validate_candidates(view, items)["outputs"]["items"]["path"] == items
        viewed = G.L._json_lines(Path(view).read_bytes(), "restricted view")
        refuses("restricted census view reported as a pilot cell",
                lambda: POP.resolve(viewed, view, explicit_release=items))
        source_bytes, view_bytes = source.read_bytes(), Path(view).read_bytes()
        for label, path, changed in (
                ("changed restricted view row", Path(view), view_bytes.replace(b'"codex"', b'"aider"', 1)),
                ("changed census source row", source, source_bytes.replace(b'"failed"', b'"passed"', 1))):
            path.write_bytes(changed)
            refuses(label, lambda: validate_candidates(view, items))
            path.write_bytes(source_bytes if path == source else view_bytes)
        proof_path = Path(view + RESTRICTION_SUFFIX)
        proof_bytes = proof_path.read_bytes()
        proof_path.unlink()
        refuses("census-stamped view without its restriction proof", lambda: validate_candidates(view, items))
        proof_path.write_bytes(proof_bytes)
        for label, bad in (("an incomplete census cell", cell[1:]),
                           ("a cell stamped by another release", [{**cell[0], "subset_digest": "0" * 16}, *cell[1:]])):
            source.write_bytes(encoded(bad))
            refuses("restriction of " + label,
                    lambda: restrict_census(items, census, str(source), str(root / "restricted-bad")))
        source.write_bytes(source_bytes)
        validate_candidates(view, items)
    other, other_pin = release("census-other-pilot", pilot[1:])
    with patch.object(KC, "RECEIPT_SHA256", other_pin):
        refuses("census receipt naming other pilot IDs",
                lambda: restrict_census(items, other, str(source), str(root / "restricted-other")))
    refuses("fixture census under the reviewed pin", lambda: validate_candidates(view, items))
    print("PASS: census330 cell restricted to the pilot IDs byte for byte; drift and lost proof refuse")



def _fixture_controls(root, release_path=None):
    """Real Java control producers; only baseline test execution is synthetic."""
    from ..bench import reference_workloads as RW
    from ..bench.validate import HARNESS_VERSION
    from .kapua import FEATURE_SUITES

    root = Path(root)
    root.mkdir()
    feature = next(iter(FEATURE_SUITES))
    if release_path is None:
        release_path = str(root / "kapua-pilot.jsonl")
        tasks = [{"item_id": f"kapua/{feature}:{i + 2}", "project": "kapua",
                  "provenance": {"file_path": feature}} for i in range(24)]
        Path(release_path).write_bytes(encoded(tasks))
    else:
        tasks = rows(release_path)
    gold = root / "release/reference-gold"
    rel = "tests/ValueSteps.java"
    source = gold / rel
    source.parent.mkdir(parents=True)
    source.write_text('package example;\npublic class ValueSteps {\n'
                     ' public void setup() { int value = 7; }\n'
                     ' public void check() { assert true; }\n}\n')
    feature_root = root / "feature-source"
    feature_path = feature_root / feature
    feature_path.parent.mkdir(parents=True)
    feature_path.write_text("Feature: value\n Scenario: value\n Given a value\n Then the value matches\n")
    closures = root / "release/control-artifacts/closures.json"
    closures.parent.mkdir(parents=True)
    passing = max(1, len(tasks) // 4)
    records = []
    for index, task in enumerate(tasks):
        records.append({"item_id": task["item_id"], "files": [rel], "feature_file": feature,
            "steps": [{"keyword": keyword, "text": text, "source_line": line,
                       "side": "removable", "definition": {
                           "file": rel, "class": "example.ValueSteps",
                           "method": method if index < passing else "check"}}
                      for keyword, text, line, method in (("Given", "a value", 3, "setup"),
                                                         ("Then", "the value matches", 4, "check"))]})
    G.write(closures, records)
    context = {"items": tasks, "fresh_plan": {"producer": {"harness_version": HARNESS_VERSION},
        "inputs": {"release_root": str(root / "release"), "source_root": str(feature_root)}}}
    baselines = {}
    for role in ("stripped_gold", "stub"):
        adapter = RW._adapter(project="kapua", role=role, gold_root=str(gold),
            release_gold_root=str(root / "release/gold"), closures_path=str(closures),
            feature_root=str(feature_root), control_policy=None)
        observed = []
        for task in tasks:
            payload = adapter(task)
            refusal = payload.get("metadata", {}).get("strip_refusal") is True
            assert payload["files"] or role == "stripped_gold" and refusal, payload
            observed.append({"item_id": task["item_id"], "adapter": adapter.name,
                "outcome": "no_files_returned" if refusal else "passed",
                "produced_files": payload["files"], "metadata": payload["metadata"],
                "harness_version": HARNESS_VERSION, "harness_commit": "later-control-producer",
                "reference_source_tag": "fixture-reviewed-reference",
                "reference_derivation": {"adapter": adapter.name, "adapter_version": 1,
                    "release_sha256": G.reference(release_path)["sha256"], "control_policy": None}})
        path = root / (role + ".jsonl")
        path.write_bytes(encoded(observed))
        baselines[role] = str(path)
    return context, str(release_path), baselines, str(source)


def _control_selftest():
    import copy
    import tempfile
    from types import SimpleNamespace
    from unittest.mock import patch
    from ..bench import cli, mutation_run as MR, reference_workloads as RW

    with tempfile.TemporaryDirectory(prefix="kapua_controls_") as directory:
        context, items, baselines, source = _fixture_controls(Path(directory) / "controls")
        path = Path(baselines["stripped_gold"])
        original = path.read_bytes()
        with patch(__name__ + ".load_selection", return_value=({}, context)):
            control = validate_control(path, items, "a" * 64, "stripped_gold")
            assert len(control["files_by_item"]) == 6 and len(control["exclusions"]) == 18
            assert set(control["baseline_outcomes"].values()) == {"passed", "no_files_returned"}
            args = SimpleNamespace(budgeted_sidecar="bound-budget", candidate=str(path),
                release=items, reference_role="assertion-stripped-gold")
            assert cli._development_reference_control(args, assets={
                "asset_project": "kapua", "asset_index_sha256": "a" * 64}) == control
            assert len(validate_control(baselines["stub"], items, "a" * 64, "stub")["files_by_item"]) == 24
            generation = MR.reference_generation_evidence(role="assertion-stripped-gold",
                source_tag="fixture-common-freeze", candidate_rows=rows(path),
                release_item_ids=[r["item_id"] for r in context["items"]],
                release_sha256=G.reference(items)["sha256"], asset_index_sha256="a" * 64, control=control)
            assert generation["reference_source_tag"] == "fixture-common-freeze"
            assert control["reference_source_tag"] == "fixture-reviewed-reference"
            def refuses(fn):
                try:
                    fn()
                except (ValueError, SystemExit):
                    return
                raise AssertionError("changed stamped Kapua control admitted")
            args.reference_feature_root = "unbound-override"
            refuses(lambda: cli._development_reference_control(args, assets={
                "asset_project": "kapua", "asset_index_sha256": "a" * 64}))
            del args.reference_feature_root
            for change in (lambda r: r[0].pop("reference_derivation"),
                           lambda r: r[0].update(reference_source_tag="other-producer"),
                           lambda r: r[0]["reference_derivation"].update(adapter_version=True),
                           lambda r: r[-1].update(outcome="passed"),
                           lambda r: r[-1]["metadata"].update(adapter_error="invented refusal"),
                           lambda r: r.pop()):
                changed = copy.deepcopy(rows(path)); change(changed)
                path.write_bytes(encoded(changed))
                refuses(lambda: validate_control(path, items, "a" * 64, "stripped_gold"))
                path.write_bytes(original)
            before = Path(source).read_text()
            Path(source).write_text(before.replace("int value = 7", "int value = 8"))
            refuses(lambda: validate_control(path, items, "a" * 64, "stripped_gold"))
            Path(source).write_text(before)
            assert path.read_bytes() == original
        # The old broad entry point remains PrestaShop-only. Kapua must use
        # the fixed-pilot source authority, never an arbitrary explicit tree.
        try:
            RW.validate_development_control_input(project="kapua", role="stub", run_path="absent",
                recipe_path="absent", execution_release_path="absent", gold_root="absent",
                release_gold_root="absent", closures_path="absent")
        except ValueError as exc:
            assert "PrestaShop only" in str(exc)
        else:
            raise AssertionError("Kapua bypassed its pilot authority")
    print("PASS stamped Kapua controls: 6 passed, 18 authentic strip refusals, 24 stubs; drift refuses")


def selftest():
    # Grouping does not confuse overloads, order, repetition or retained helpers.
    def step(file, method, side="removable"):
        return {"side": side, "definition": {"file": file}, "location": method}
    a, b = step("Steps.java", "C.check(int)"), step("Steps.java", "C.check(String)")
    fixtures = [{"item_id": "kapua/a", "steps": [a, b, a]},
                {"item_id": "kapua/b", "steps": [b, a, step("Helpers.java", "H.setup()", "retained")]},
                {"item_id": "kapua/c", "steps": [a]}]
    grouped = implementation_groups(fixtures, [r["item_id"] for r in fixtures])
    assert grouped["group_count"] == 2 and grouped["requirement_to_representative"] == {
        "kapua/a": "kapua/a", "kapua/b": "kapua/a", "kapua/c": "kapua/c"}
    _control_selftest()
    return G.selftest(pilot=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare")
    for flag in ("census-gold", "gold-receipt", "index", "out"):
        p.add_argument("--" + flag, required=True)
    for name in ("project-mapping", "project-full-gold"):
        p = commands.add_parser(name)
        p.add_argument("--items", required=True)
        p.add_argument("--out", required=True)
    p = commands.add_parser("restrict-census")
    for flag in ("items", "census-release", "run", "out"):
        p.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        result = prepare(args.census_gold, args.gold_receipt, args.index, args.out)
    elif args.command == "restrict-census":
        result = restrict_census(args.items, args.census_release, args.run, args.out)
    else:
        result = (project_mapping if args.command == "project-mapping" else project_full_gold)(args.items, args.out)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
