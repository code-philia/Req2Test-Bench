"""Portable Sylius census of the removable step methods an agent recreates.

SYLIUS_CHECKED_INTERFACES_SPEC.md fixes eligibility before grouping. Reference
inputs are copied alongside the selection so a consumer can replay it offline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil

SCHEMA = "r2t.sylius-implementation-census/1"
NAME = "sylius-implementations.jsonl"
SUBSET_ID = NAME.removesuffix(".jsonl")
SUFFIX = ".sylius-selection.json"
REASON = "fixed implementation census; no requirement-population inference"
ORIGINAL_SHA256 = "8a54b954ad22c58a3472653e8d96ee4983b673a5bbad3c83aab18a430e56211f"
EXCLUSIONS_SHA256 = "af8b8226bcde48e01623fadf91a1e817791ef2ea66d59335d90a027a9a92afdb"
ROLES = ("items", "original_items", "closures", "exclusions", "clusters")


class SelectionRefused(ValueError):
    pass


def _require(ok, message):
    if not ok:
        raise SelectionRefused("REFUSED: Sylius selection: " + message)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _read(path):
    return json.loads(Path(path).read_bytes())


def _rows(path):
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines() if line.strip()]
    ids = [row["item_id"] for row in rows]
    _require(len(set(ids)) == len(ids), "duplicate release item")
    _require(all(row.get("project") == "sylius" and
                 isinstance(row["item_id"], str) and row["item_id"].startswith("sylius/")
                 for row in rows), "foreign project in release")
    return rows


def implementation_groups(closures, item_ids):
    _require(len(set(item_ids)) == len(item_ids), "duplicate selected requirement")
    by_item = {}
    for closure in closures:
        iid = closure["item_id"]
        _require(iid not in by_item, "duplicate closure: " + iid)
        by_item[iid] = closure
    grouped = {}
    for iid in item_ids:
        _require(iid in by_item, "missing closure: " + iid)
        closure = by_item[iid]
        _require(closure.get("problems") == [], "unresolved closure: " + iid)
        definitions = set()
        for step in closure["steps"]:
            _require(step.get("side") in ("removable", "retained") and
                     step.get("status") in (None, "matched") and
                     isinstance(step.get("definition"), dict), "unresolved step: " + iid)
            if step["side"] == "retained":
                continue
            definition = step["definition"]
            triple = tuple(definition.get(key) for key in ("file", "class", "method"))
            _require(all(isinstance(value, str) and value for value in triple),
                     "missing method identity: " + iid)
            path = PurePosixPath(triple[0])
            _require(triple[0].startswith("src/Sylius/Behat/Context/Api/") and
                     ".." not in path.parts and "\\" not in triple[0],
                     "foreign removable definition: " + iid)
            definitions.add(triple)
        _require(definitions, "empty removable implementation: " + iid)
        grouped.setdefault(tuple(sorted(definitions)), []).append(iid)
    return sorted(({"definitions": [list(identity) for identity in key],
                    "representative": min(members), "members": sorted(members)}
                   for key, members in grouped.items()), key=lambda group: group["representative"])


def _derive(paths):
    from .prompt import validate_annotation

    _require(set(paths) == set(ROLES), "selection input roles differ")
    _require(sha256(paths["original_items"]) == ORIGINAL_SHA256,
             "original release differs from the approved 1,950-item pool")
    _require(sha256(paths["exclusions"]) == EXCLUSIONS_SHA256,
             "eligibility differs from the reviewed exclusions")
    original, items = _rows(paths["original_items"]), _rows(paths["items"])
    _require([{k: v for k, v in row.items() if k != "checked_interfaces"}
              for row in items] == original, "companion changed nonannotation task content")
    for row in items:
        _require("checked_interfaces" in row, "missing checked interfaces: " + row["item_id"])
        validate_annotation(row, str(paths["items"]))
    ids = [row["item_id"] for row in original]
    excluded = _read(paths["exclusions"])["items"]
    _require(set(excluded) <= set(ids), "exclusion names an unreleased requirement")
    eligible = [iid for iid in ids if iid not in excluded]
    clusters = _read(paths["clusters"])
    _require(set(clusters) == set(ids), "closure-file membership differs from release")
    groups = implementation_groups(_read(paths["closures"]), eligible)
    selected = [group["representative"] for group in groups]
    represented = len({clusters[iid] for iid in selected})
    _require((len(ids), len(excluded), len(eligible), len(groups), represented)
             == (1950, 1284, 666, 319, 75),
             "approved 1950/1284/666/319/75 population counts changed")
    by_id = {row["item_id"]: row for row in items}
    return [by_id[iid] for iid in selected], {
        "requirements": len(ids), "eligible_requirements": len(eligible),
        "implementation_count": len(groups), "groups": groups,
        "closure_file_clusters": {iid: clusters[iid] for iid in eligible},
        "represented_file_clusters": represented}


def _encoded(rows):
    return b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in rows)


def prepare(*, items, original_items, closures, exclusions, clusters, out):
    sources = dict(items=items, original_items=original_items, closures=closures,
                   exclusions=exclusions, clusters=clusters)
    rows, grouping = _derive(sources)
    out = Path(out).absolute()
    _require(not os.path.lexists(out), "output directory already exists")
    (out / "inputs").mkdir(parents=True)
    inputs = {}
    for role, source in sources.items():
        relative = "inputs/" + role + (".jsonl" if role.endswith("items") else ".json")
        shutil.copyfile(source, out / relative)
        inputs[role] = {"path": relative, "sha256": sha256(out / relative)}
    path = out / NAME
    path.write_bytes(_encoded(rows))
    receipt = {"schema": SCHEMA, "inputs": inputs,
               "selection": {"path": NAME, "sha256": sha256(path)},
               "grouping": grouping, "inference_valid": False, "inference_reason": REASON}
    Path(str(path) + SUFFIX).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    load_selection(path)
    return str(path)


def is_selection(path):
    return Path(path).name == NAME or os.path.lexists(str(path) + SUFFIX)


def load_selection(path):
    from .profile import ProfileError

    try:
        path = Path(path).resolve(strict=True)
        doc = _read(str(path) + SUFFIX)
        _require(doc["schema"] == SCHEMA and doc["inference_valid"] is False and
                 doc["inference_reason"] == REASON, "selection interpretation differs")
        _require(doc["selection"] == {"path": path.name, "sha256": sha256(path)},
                 "selection bytes changed")
        _require(set(doc["inputs"]) == set(ROLES), "selection input roles differ")
        paths = {}
        for role, ref in doc["inputs"].items():
            relative = PurePosixPath(ref["path"])
            _require(not relative.is_absolute() and ".." not in relative.parts,
                     "input is not portable: " + role)
            paths[role] = path.parent / relative
            _require(sha256(paths[role]) == ref["sha256"], "changed input: " + role)
        rows, grouping = _derive(paths)
        _require(doc["grouping"] == grouping and path.read_bytes() == _encoded(rows),
                 "selection is not the reproduced implementation census")
        return doc
    except (OSError, KeyError, TypeError, ValueError, ProfileError) as exc:
        if isinstance(exc, SelectionRefused):
            raise
        raise SelectionRefused("REFUSED: Sylius selection: " + str(exc)) from exc


def identify(path):
    doc = load_selection(path)
    return {"subset_id": SUBSET_ID, "subset_digest": doc["selection"]["sha256"][:16],
            "sidecar": str(Path(path).resolve()) + SUFFIX, "inference_valid": False,
            "inference_reason": REASON, "allow_cluster_siblings": True}


def selftest():
    import copy
    import tempfile
    from ..core.paths import BENCHMARK_ROOT
    from ..core.ledger_primitives import ordered_item_ids_digest
    from . import subsets
    from ..bench import population

    def step(method, **kw):
        return dict(side="removable", origin="scenario", definition={
            "file": "src/Sylius/Behat/Context/Api/Shop/CartContext.php",
            "class": "Sylius\\Behat\\Context\\Api\\Shop\\CartContext", "method": method}, **kw)

    closures = [dict(item_id="b", problems=[], steps=[step("add"), step("check")]),
                dict(item_id="a", problems=[], steps=[step("check", text="different literal"),
                     step("add"), step("add"), dict(side="retained", definition={"method": "setup"})]),
                dict(item_id="c", problems=[], steps=[step("remove"), step("check")])]
    groups = implementation_groups(closures, ["b", "a", "c"])
    assert [g["members"] for g in groups] == [["a", "b"], ["c"]]
    assert implementation_groups(list(reversed(closures)), ["c", "a", "b"]) == groups
    background = copy.deepcopy(closures)
    background[0]["steps"].append(dict(step("background"), origin="background"))
    assert len(implementation_groups(background, ["a", "b", "c"])) == 3

    def refused(fn, fragment):
        try:
            fn()
        except SelectionRefused as exc:
            assert fragment in str(exc), str(exc)
        else:
            raise AssertionError("accepted " + fragment)

    refused(lambda: implementation_groups(closures, ["missing"]), "missing closure")
    refused(lambda: implementation_groups(closures, ["a", "a"]), "duplicate selected")
    refused(lambda: implementation_groups(closures + closures[:1], ["a"]), "duplicate closure")
    for change, fragment in [(lambda c: c.update(problems=["ambiguous"]), "unresolved closure"),
                             (lambda c: c.update(steps=[]), "empty removable"),
                             (lambda c: c["steps"][0].pop("definition"), "unresolved step"),
                             (lambda c: c["steps"][0]["definition"].pop("method"), "missing method")]:
        changed = copy.deepcopy(closures)
        change(changed[0])
        refused(lambda: implementation_groups(changed, ["b"]), fragment)

    # Real frozen release/eligibility, synthetic method assignments: exercise
    # the complete receipt, relocation and public population readers offline.
    bench = Path(BENCHMARK_ROOT)
    original = bench / "release/sylius/items.jsonl"
    exclusions = bench.parent / "maps/sylius/excluded_items.json"
    clusters = bench / "release/sylius/closure_clusters.json"
    rows, excluded, file_clusters = _rows(original), _read(exclusions)["items"], _read(clusters)
    eligible = sorted(row["item_id"] for row in rows if row["item_id"] not in excluded)
    cluster_groups = {}
    for iid in eligible:
        cluster_groups.setdefault(file_clusters[iid], []).append(iid)
    mapping, next_group = {}, 0
    for members in cluster_groups.values():
        for iid in members:
            mapping[iid] = next_group
        next_group += 1
    for members in cluster_groups.values():
        for iid in members[1:]:
            if next_group < 319:
                mapping[iid] = next_group
                next_group += 1
    records = [dict(item_id=iid, problems=[], steps=[step("method" + str(group))])
               for iid, group in mapping.items()]
    for row in rows:
        row["checked_interfaces"] = {"checked": [], "empty_reason": "no_action_or_check_call"}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "items.jsonl").write_bytes(_encoded(rows))
        (root / "closures.json").write_text(json.dumps(records))
        selected = prepare(items=root / "items.jsonl", original_items=original,
                           closures=root / "closures.json", exclusions=exclusions,
                           clusters=clusters, out=root / "prepared")
        doc = load_selection(selected)
        assert doc["grouping"]["implementation_count"] == 319
        assert subsets.identify_for_inference(selected)["inference_valid"] is False
        resolved = population.resolve([], str(root / "run.jsonl"), explicit_release=selected)
        assert resolved["planned_n"] == 319 and resolved["inference_valid"] is False
        identity = identify(selected)
        ids = [row["item_id"] for row in _rows(selected)]
        scope = population.frozen_scope(item_ids=ids, workset={"item_count": 319,
            "ordered_item_ids_digest": ordered_item_ids_digest(ids)},
            subset_id=SUBSET_ID, subset_digest=identity["subset_digest"])
        stamped = [dict(item_id=iid, project="sylius", condition="c2", outcome="passed",
                        subset_id=SUBSET_ID, subset_digest=identity["subset_digest"]) for iid in ids]
        assert population.resolve(stamped, str(root / "run.jsonl"),
                                  validated_scope=scope)["inference_valid"] is False
        shutil.move(root / "prepared", root / "relocated")
        selected = root / "relocated" / NAME
        assert load_selection(selected) == doc
        # Evaluation admission replays the census, rather than trusting IDs or
        # accepting another annotation companion with the same membership.
        from ..bench.evaluation_reference import _require_sylius_task_binding
        from ..bench.reference_controls import ReferenceControlsRefused
        binding = Path(str(selected) + SUFFIX)
        _require_sylius_task_binding(selected, binding, ORIGINAL_SHA256)
        for bad_path, bad_release in ((None, ORIGINAL_SHA256), (binding, "0" * 64)):
            try:
                _require_sylius_task_binding(selected, bad_path, bad_release)
            except ReferenceControlsRefused:
                pass
            else:
                raise AssertionError("missing or mismatched Sylius task authority admitted")
        bad_binding = root / "unrelated-receipt.json"
        bad_binding.write_text(json.dumps({**doc, "inference_valid": True}))
        try:
            _require_sylius_task_binding(selected, bad_binding, ORIGINAL_SHA256)
        except ReferenceControlsRefused:
            pass
        else:
            raise AssertionError("unrelated Sylius receipt admitted")
        sidecar = Path(str(selected) + SUFFIX)
        forged = _read(sidecar)
        forged["grouping"]["groups"][0]["members"].append("sylius/foreign:1")
        sidecar.write_text(json.dumps(forged))
        refused(lambda: load_selection(selected), "reproduced implementation census")
        sidecar.write_text(json.dumps(doc))
        companion = selected.parent / "inputs/items.jsonl"
        modified = _rows(companion)
        modified[0]["criterion"]["scenario_title"] += " changed"
        companion.write_bytes(_encoded(modified))
        forged = copy.deepcopy(doc)
        forged["inputs"]["items"]["sha256"] = sha256(companion)
        sidecar.write_text(json.dumps(forged))
        refused(lambda: load_selection(selected), "nonannotation task content")
        sidecar.write_text(json.dumps(doc))
        (selected.parent / "inputs/items.jsonl").write_text("{}\n")
        refused(lambda: load_selection(selected), "changed input: items")
    print("Sylius method selection, refusals, relocation and population: PASS")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    for role in ROLES:
        parser.add_argument("--" + role.replace("_", "-"))
    parser.add_argument("--out")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    for role in (*ROLES, "out"):
        if getattr(args, role) is None:
            parser.error("missing --" + role.replace("_", "-"))
    print(prepare(**{role: getattr(args, role) for role in (*ROLES, "out")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
