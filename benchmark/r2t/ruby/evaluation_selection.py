"""The fixed e-petitions census of resolved reference implementations.

E_PETITIONS_CHECKED_INTERFACES_SPEC.md: retain the complete admitted release,
select the first requirement per removable-definition set, and preserve the
coarser file clusters separately. This is descriptive development evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from ..core.paths import locate_recorded

SCHEMA = "r2t.e-petitions-implementation-census/1"
NAME = "e-petitions-implementations.jsonl"
SUBSET_ID = NAME.removesuffix(".jsonl")
SUFFIX = ".implementations.json"
REASON = "fixed implementation census; no requirement-population inference"


class SelectionRefused(ValueError):
    pass


def _require(ok, message):
    if not ok:
        raise SelectionRefused("REFUSED: e-petitions selection: " + message)


def reference(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _located(ref, relocated, message):
    """The local file for a recorded {path, sha256}, which the bytes must match.

    Read at the recorded path when it exists, as `reference` recorded it.
    Otherwise `R2T_RECORDED_ROOTS` may say where that path is on this host; the
    entry used joins `relocated`, and only the location differs.
    """
    local, used = locate_recorded(ref["path"])
    found = reference(local)
    if used:
        found["path"] = ref["path"]
    _require(found == ref, message)
    relocated.update(used)
    return local


def _rows(path):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    ids = [r["item_id"] for r in rows]
    _require(len(set(ids)) == len(ids), "duplicate release item")
    _require(all(r.get("project") == "e-petitions" and
                 r["item_id"].startswith("e-petitions/") for r in rows),
             "foreign project in release")
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
        definitions = set()
        for step in by_item[iid]["steps"]:
            _require(step.get("side") in ("removable", "retained") and
                     step.get("status") == "matched", "unresolved step: " + iid)
            if step["side"] == "retained":
                continue
            definition = step.get("definition") or {}
            file, line = definition.get("file"), definition.get("line")
            _require(isinstance(file, str) and file.startswith("features/step_definitions/")
                     and type(line) is int and line > 0,
                     "missing or foreign removable definition: " + iid)
            definitions.add((file, line))
        _require(definitions, "empty removable implementation: " + iid)
        grouped.setdefault(tuple(sorted(definitions)), []).append(iid)
    return sorted(({"definitions": [list(pair) for pair in key],
                    "representative": min(members), "members": sorted(members)}
                   for key, members in grouped.items()), key=lambda g: g["representative"])


def _derive(inputs):
    _require(set(inputs) == {"items", "original_items", "closures", "clusters"},
             "selection input roles differ")
    relocated = {}
    paths = {role: _located(ref, relocated, "changed input: " + ref["path"])
             for role, ref in inputs.items()}
    original = _rows(paths["original_items"])
    items = _rows(paths["items"])
    _require([{k: v for k, v in row.items() if k != "checked_interfaces"}
              for row in items] == original, "companion changed nonannotation task content")
    ids = [row["item_id"] for row in original]
    closures = json.loads(Path(paths["closures"]).read_text())
    clusters = json.loads(Path(paths["clusters"]).read_text())
    _require(set(clusters) == set(ids), "closure-file membership differs from release")
    groups = implementation_groups(closures, ids)
    _require((len(ids), len(groups), len(set(clusters.values()))) == (119, 98, 46),
             "approved 119 requirements / 98 implementations / 46 file clusters changed")
    by_id = {row["item_id"]: row for row in items}
    representatives = [by_id[group["representative"]] for group in groups]
    return representatives, {"requirements": len(ids), "implementation_count": len(groups),
                             "groups": groups, "closure_file_clusters": clusters}, relocated


def _encoded(rows):
    return b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in rows)


def prepare(*, items, original_items, closures, clusters, out):
    inputs = {key: reference(value) for key, value in {
        "items": items, "original_items": original_items,
        "closures": closures, "clusters": clusters}.items()}
    rows, grouping, _ = _derive(inputs)
    out = Path(out).absolute()
    _require(not os.path.lexists(out), "output directory already exists")
    out.mkdir()
    path = out / NAME
    path.write_bytes(_encoded(rows))
    receipt = {"schema": SCHEMA, "inputs": inputs, "selection": reference(path),
               "grouping": grouping, "inference_valid": False,
               "inference_reason": REASON}
    Path(str(path) + SUFFIX).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    load_selection(path)
    return str(path)


def is_selection(path):
    return Path(path).name == NAME or os.path.lexists(str(path) + SUFFIX)


def _load(path):
    """(receipt, the R2T_RECORDED_ROOTS entries used to read its paths)."""
    try:
        path = Path(path).resolve(strict=True)
        doc = json.loads(Path(str(path) + SUFFIX).read_text())
        _require(doc["schema"] == SCHEMA and doc["inference_valid"] is False and
                 doc["inference_reason"] == REASON, "selection interpretation differs")
        relocated = {}
        local = _located(doc["selection"], relocated, "selection bytes/path changed")
        _require(Path(local).resolve(strict=True) == path, "selection bytes/path changed")
        rows, grouping, inputs_relocated = _derive(doc["inputs"])
        _require(doc["grouping"] == grouping and path.read_bytes() == _encoded(rows),
                 "selection is not the reproduced complete implementation census")
        return doc, {**relocated, **inputs_relocated}
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, SelectionRefused):
            raise
        raise SelectionRefused("REFUSED: e-petitions selection: " + str(exc)) from exc


def load_selection(path):
    return _load(path)[0]


def identify(path):
    doc, relocated = _load(path)
    return {"subset_id": Path(path).stem, "subset_digest": doc["selection"]["sha256"][:16],
            "sidecar": str(Path(path).resolve()) + SUFFIX, "inference_valid": False,
            "inference_reason": REASON, "allow_cluster_siblings": True,
            **({"recorded_roots": relocated} if relocated else {})}


def selftest():
    import copy
    import tempfile
    from ..data import subsets
    from ..bench import population, cli
    from ..core.ledger_primitives import ordered_item_ids_digest
    from types import SimpleNamespace

    def step(file, line, **kwargs):
        return {"status": "matched", "side": "removable",
                "definition": {"file": "features/step_definitions/" + file, "line": line}, **kwargs}

    closures = [
        {"item_id": "b", "steps": [step("f.rb", 1), step("f.rb", 2)]},
        {"item_id": "a", "steps": [step("f.rb", 2, origin="background"), step("f.rb", 1),
                                     step("f.rb", 1, text="another literal", example_line=99)]},
        {"item_id": "c", "steps": [step("f.rb", 1), step("f.rb", 3),
                                     step("helper.rb", 4, side="retained")]},
    ]
    groups = implementation_groups(closures, ["b", "a", "c"])
    assert [g["members"] for g in groups] == [["a", "b"], ["c"]]
    assert implementation_groups(list(reversed(closures)), ["c", "a", "b"]) == groups
    for bad, ids in [(closures, ["a", "a"]), (closures, ["missing"]),
                     (closures + [closures[0]], ["a"])]:
        try:
            implementation_groups(bad, ids)
        except SelectionRefused:
            pass
        else:
            raise AssertionError("invalid grouping accepted")
    for change in (lambda s: s.pop("definition"), lambda s: s.update(status="unmatched"),
                   lambda s: s["definition"].update(file="retained/f.rb"),
                   lambda s: s["definition"].update(line=0)):
        broken = copy.deepcopy(closures)
        change(broken[0]["steps"][0])
        try:
            implementation_groups(broken, ["b"])
        except SelectionRefused:
            pass
        else:
            raise AssertionError("unresolved/foreign definition accepted")

    # Exercise the complete frozen counts and public consumers without mocking
    # the derivation: 119 requirements, 98 definitions and 46 file sets.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        original = root / "original.jsonl"
        items, records, clusters = [], [], {}
        for index in range(119):
            group = min(index, 97)
            iid = f"e-petitions/case:{index:03d}"
            items.append({"project": "e-petitions", "item_id": iid, "task": str(index)})
            records.append({"item_id": iid, "steps": [step(f"f{group % 46}.rb", group + 1)]})
            clusters[iid] = str(group % 46)
        original.write_bytes(_encoded(items))
        closure_path, cluster_path = root / "closures.json", root / "clusters.json"
        closure_path.write_text(json.dumps(records))
        cluster_path.write_text(json.dumps(clusters))
        selected = prepare(items=original, original_items=original, closures=closure_path,
                           clusters=cluster_path, out=root / "selection")
        assert load_selection(selected)["grouping"]["implementation_count"] == 98
        identity = subsets.identify_for_inference(selected)
        assert identity["subset_id"] == Path(selected).stem and not identity["inference_valid"]
        answer = population.resolve([], str(root / "run.jsonl"), explicit_release=selected)
        assert answer["planned_n"] == 98 and answer["inference_valid"] is False
        assert "recorded_roots" not in (answer.get("selection") or {}), answer  # unmapped: unchanged
        selected_ids = [row["item_id"] for row in _rows(selected)]
        scope = population.frozen_scope(
            item_ids=selected_ids, workset={"item_count": 98,
                "ordered_item_ids_digest": ordered_item_ids_digest(selected_ids)},
            subset_id=identity["subset_id"], subset_digest=identity["subset_digest"])
        stamped = [{"item_id": iid, "project": "e-petitions", "condition": "c2",
                    "outcome": "passed", "subset_id": identity["subset_id"],
                    "subset_digest": identity["subset_digest"]} for iid in selected_ids]
        answer = population.resolve(stamped, str(root / "run.jsonl"), validated_scope=scope)
        assert answer["inference_valid"] is False and answer["inference_reason"] == REASON
        run = root / "run.jsonl"
        run.write_bytes(_encoded(stamped))
        try:
            cli.cmd_compare(SimpleNamespace(run=[str(run), str(run)], items=None,
                                            gold_dir=str(root), metric="pass"))
        except SystemExit as exc:
            assert "descriptive-only" in str(exc), str(exc)
        else:
            raise AssertionError("inferential comparison without --items accepted")
        companion = root / "checked.jsonl"
        companion.write_bytes(_encoded([{**row, "checked_interfaces": {"methods": []}}
                                        for row in items]))
        prepare(items=companion, original_items=original, closures=closure_path,
                clusters=cluster_path, out=root / "checked-selection")
        changed = [dict(row) for row in items]
        changed[0]["task"] = "not the original task"
        companion.write_bytes(_encoded(changed))
        try:
            prepare(items=companion, original_items=original, closures=closure_path,
                    clusters=cluster_path, out=root / "bad-selection")
        except SelectionRefused:
            pass
        else:
            raise AssertionError("changed companion task accepted")
        before = Path(selected).read_bytes()
        for candidate in (b"", before + before.splitlines(keepends=True)[0]):
            Path(selected).write_bytes(candidate)
            try:
                load_selection(selected)
            except SelectionRefused:
                pass
            else:
                raise AssertionError("changed selected bytes accepted")
        Path(selected).write_bytes(before)
        cluster_path.write_text("{}")
        try:
            subsets.identify_for_inference(selected)
        except subsets.SubsetRefused:
            pass
        else:
            raise AssertionError("changed source input accepted")

        # The released receipt names collection-host paths. On another host
        # R2T_RECORDED_ROOTS says where they are: only the location changes.
        import shutil
        from unittest.mock import patch
        from ..core.paths import RECORDED_ROOTS_ENV
        cluster_path.write_text(json.dumps(clusters))
        receipt = Path(selected + SUFFIX).read_bytes()
        recorded = str(root.resolve())
        with tempfile.TemporaryDirectory() as there:
            host = Path(there).resolve() / "host"
            shutil.copytree(root, host)
            for name in ("original.jsonl", "closures.json", "clusters.json"):
                (root / name).unlink()
            shutil.rmtree(root / "selection")
            moved = str(host / Path(selected).relative_to(root))

            def refuses(needle):
                try:
                    load_selection(moved)
                except SelectionRefused as exc:
                    assert needle in str(exc), str(exc)
                else:
                    raise AssertionError("relocated selection accepted despite " + needle)

            with patch.dict(os.environ):
                os.environ.pop(RECORDED_ROOTS_ENV, None)
                refuses("No such file")  # an unmapped recorded path still refuses
            with patch.dict(os.environ, {RECORDED_ROOTS_ENV: f"{recorded}={host}"}):
                assert load_selection(moved)["grouping"]["implementation_count"] == 98
                assert identify(moved)["recorded_roots"] == {recorded: str(host)}
                answer = population.resolve([], str(host / "relocated-run.jsonl"),
                                            explicit_release=moved)
                assert answer["planned_n"] == 98, answer
                assert answer["selection"]["recorded_roots"] == {recorded: str(host)}, answer
                assert Path(moved + SUFFIX).read_bytes() == receipt
                # A byte-identical copy of the census and its receipt in an
                # undeclared directory is not the mapped file.
                elsewhere = Path(there).resolve() / "elsewhere"
                elsewhere.mkdir()
                copy = elsewhere / Path(moved).name
                shutil.copyfile(moved, copy)
                shutil.copyfile(moved + SUFFIX, str(copy) + SUFFIX)
                try:
                    load_selection(str(copy))
                except SelectionRefused as exc:
                    assert "selection bytes/path changed" in str(exc), str(exc)
                else:
                    raise AssertionError("an undeclared copy of the census was accepted")
                for victim, needle in ((host / "clusters.json", "changed input"),
                                       (Path(moved), "selection bytes/path changed")):
                    saved = victim.read_bytes()
                    victim.write_bytes(saved + b"\n")
                    refuses(needle)
                    victim.write_bytes(saved)
                (host / "closures.json").unlink()
                refuses("No such file")
            with patch.dict(os.environ, {RECORDED_ROOTS_ENV: "relative=" + str(host)}):
                refuses(RECORDED_ROOTS_ENV)
    print("[PASS] Ruby implementation grouping, stable representatives and population identity")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("prepare")
    for name in ("items", "original-items", "closures", "clusters", "out"):
        build.add_argument("--" + name, required=True)
    commands.add_parser("verify").add_argument("items")
    commands.add_parser("selftest")
    args = vars(parser.parse_args())
    command = args.pop("command")
    if command == "prepare":
        print(prepare(**args))
    elif command == "verify":
        print(json.dumps(identify(args["items"]), sort_keys=True))
    else:
        return selftest()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
