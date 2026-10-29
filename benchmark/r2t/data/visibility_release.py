"""The reviewed release role admitted to external visibility issuance/scoring."""
from __future__ import annotations

import json
from pathlib import Path

from . import bundle


def _historical_role(project: str, block: dict, asset_index_path: str) -> tuple[str, str, int]:
    if project == "coreshop":
        role = block["subsets"]["eval100"]
        if role["n"] != 100:
            raise bundle.BundleRefused("CoreShop visibility requires the exact eval100 role")
        return role["file"], role["content_sha256"], 100
    if project == "python-docx":
        # #443 permits re-minting this project's repository items file. The
        # bundle's preserved release role stays bound by its existing asset
        # index, even when the current dataset digest names annotated bytes.
        index = bundle._read_json(asset_index_path, "mutation asset index")
        role = index["projects"][project]["release"]
        return block["items"], role["sha256"], role["items"]
    raise bundle.BundleRefused("visibility release project is not admitted")


def visibility_release_binding(project: str, block: dict, *,
                               asset_index_path: str = bundle.ASSET_INDEX) -> dict:
    """The two existing registered identities a view asset must bind."""
    declaration = bundle._annotated_release_declaration(project, block)
    if declaration is None:
        raise bundle.BundleRefused("visibility requires the registered annotated release role")
    _path, digest, _count = _historical_role(project, block, asset_index_path)
    if not bundle._is_sha256(digest):
        raise bundle.BundleRefused("visibility historical release has no registered SHA-256")
    return {"historical_sha256": digest, "annotated_sha256": declaration["sha256"]}


def validate_visibility_release(release_path: str, project: str, *,
                                manifest_path: str = bundle.DATASET_MANIFEST,
                                historical_release: str | None = None,
                                asset_index_path: str = bundle.ASSET_INDEX) -> list[dict]:
    """Authenticate annotated tasks against the bundle's frozen release role.

    CoreShop's role is exactly eval100. python-docx keeps its registered full
    release. The annotation companion adds interfaces without replacing any
    historical task bytes; its existing bundle validator owns that join.
    """
    try:
        document = bundle._read_json(manifest_path, "dataset manifest")
        if document.get("schema") != "r2t.dataset_manifest/3" \
                or project not in ("coreshop", "python-docx"):
            raise bundle.BundleRefused("visibility needs an admitted project and bundle manifest")
        block = document["projects"][project]
        binding = visibility_release_binding(project, block, asset_index_path=asset_index_path)
        declaration = bundle._annotated_release_declaration(project, block)
        historical, _digest, count = _historical_role(project, block, asset_index_path)
        root = Path(manifest_path).resolve().parent
        historical_path = (Path(historical_release).resolve() if historical_release is not None
                           else (root / historical).resolve())
        if (historical_release is None and not historical_path.is_relative_to(root)) \
                or bundle._sha256_file(str(historical_path)) != binding["historical_sha256"]:
            raise bundle.BundleRefused("visibility historical release differs from its registered bytes")
        actual_count = bundle._validate_annotated_release(
            release_path, str(historical_path), declaration)
        if actual_count != count:
            raise bundle.BundleRefused("visibility release changes the registered denominator")
        with open(release_path, encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle if line.strip()]
        ids = [row.get("item_id") for row in rows]
        if any(row.get("project") != project for row in rows) \
                or any(not isinstance(iid, str) or not iid for iid in ids) \
                or len(set(ids)) != len(ids):
            raise bundle.BundleRefused("visibility release has foreign, missing or duplicate item identities")
        return rows
    except (KeyError, OSError, TypeError, ValueError, bundle.BundleRefused) as exc:
        raise bundle.BundleRefused(
            "REFUSED: visibility release admission: "
            + str(exc).removeprefix("REFUSED: ")) from exc


def selftest() -> int:
    import copy
    import hashlib
    import tempfile

    with tempfile.TemporaryDirectory(prefix="r2t-visibility-release-") as directory:
        root = Path(directory)
        rows = [{"item_id": f"coreshop/fixture.feature:{n}", "project": "coreshop"}
                for n in range(100)]
        historical = root / "eval100.jsonl"
        annotated = root / "annotated.jsonl"
        manifest = root / "dataset_manifest.json"

        def write(path, values):
            raw = ("".join(json.dumps(row, sort_keys=True) + "\n" for row in values)).encode()
            path.write_bytes(raw)
            return hashlib.sha256(raw).hexdigest()

        old_digest = write(historical, rows)
        annotated_rows = [dict(row, target_interfaces={"behaviour": [], "setup": []})
                          for row in rows]
        digest = write(annotated, annotated_rows)
        block = {"bundle": {
            "annotated_release": {"file": "annotated.jsonl", "sha256": digest},
            "artifacts": {"annotated_release_items":
                          "projects/coreshop/artifacts/release/annotated_items.jsonl"}},
            "subsets": {"eval100": {"file": "eval100.jsonl", "content_sha256": old_digest,
                                    "n": 100}}}
        doc = {"schema": "r2t.dataset_manifest/3", "projects": {"coreshop": block}}
        manifest.write_text(json.dumps(doc), encoding="utf-8")
        assert validate_visibility_release(str(annotated), "coreshop",
                                           manifest_path=str(manifest)) == annotated_rows

        def refused(label):
            try:
                validate_visibility_release(str(annotated), "coreshop",
                                            manifest_path=str(manifest))
            except bundle.BundleRefused:
                print(f"  [PASS] visibility release refuses {label}")
            else:
                raise AssertionError(label)

        replacement = copy.deepcopy(annotated_rows)
        replacement[-1]["item_id"] = "coreshop/foreign.feature:1"
        block["bundle"]["annotated_release"]["sha256"] = write(annotated, replacement)
        manifest.write_text(json.dumps(doc), encoding="utf-8")
        refused("another 100-item population even when its annotation hash is registered")
        write(annotated, annotated_rows)
        block["bundle"]["annotated_release"]["sha256"] = digest
        manifest.write_text(json.dumps(doc), encoding="utf-8")
        write(historical, rows[:-1])
        refused("changed frozen role bytes")
        write(historical, rows)
        block["bundle"]["annotated_release"] = None
        block["bundle"]["artifacts"]["annotated_release_items"] = None
        manifest.write_text(json.dumps(doc), encoding="utf-8")
        refused("missing registered annotation role")

        # A supported #443 re-mint changes current docx/items.jsonl while the
        # historical role in a scoring bundle keeps its exact prior bytes.
        old_docx = [{"item_id": f"python-docx/fixture.feature:{n}", "project": "python-docx"}
                    for n in range(2)]
        old_path = root / "preserved-docx.jsonl"
        old_digest = write(old_path, old_docx)
        docx = [dict(row, target_interfaces={"behaviour": [], "setup": []}) for row in old_docx]
        current = root / "docx-items.jsonl"
        current_digest = write(current, docx)
        index = root / "asset-index.json"
        index.write_text(json.dumps({"projects": {"python-docx": {
            "release": {"sha256": old_digest, "items": 2}}}}), encoding="utf-8")
        docx_block = {"items": current.name, "digests": {"items": current_digest}, "n_items": 2,
                     "bundle": {"annotated_release": {"file": current.name, "sha256": current_digest},
                                "artifacts": {"annotated_release_items":
                                    "projects/python-docx/artifacts/release/annotated_items.jsonl"}}}
        manifest.write_text(json.dumps({"schema": "r2t.dataset_manifest/3",
                                        "projects": {"python-docx": docx_block}}), encoding="utf-8")
        assert visibility_release_binding("python-docx", docx_block, asset_index_path=str(index)) == {
            "historical_sha256": old_digest, "annotated_sha256": current_digest}
        assert validate_visibility_release(str(current), "python-docx", manifest_path=str(manifest),
                                           historical_release=str(old_path),
                                           asset_index_path=str(index)) == docx
        try:
            validate_visibility_release(str(current), "python-docx", manifest_path=str(manifest),
                                        historical_release=str(current), asset_index_path=str(index))
        except bundle.BundleRefused:
            print("  [PASS] reminted docx tasks cannot replace their preserved historical role")
        else:
            raise AssertionError("reminted docx file was accepted as historical bytes")
    print("ALL PASS (visibility_release)")
    return 0
