"""The owner-approved Kapua implementation census as a run and report population.

KAPUA_CENSUS330_MUTATION_AMENDMENT.md gives the census its mutation inputs,
which belong to `kapua_census_mutation`; it replaces the "no mutation-map
projection" of the census amendment's section 7 that the next paragraph
cites. That amendment also partitions the census into `SHARDS` item shards,
so that candidate scoring can be split by item across hosts. Shard `k` is
lines `k, k + SHARDS, ...` of the census rows, byte for byte. Positions are
stable because the pinned receipt freezes the rows, and round-robin keeps the
shards within one item of each other. Each shard is written beside them as
`kapua-census330-shard-KK-of-12.jsonl`. It needs no proof file: its name and
the approved rows beside it determine every byte, and this reader rederives
them. A shard has its own subset identity, so rows run over it are stamped
with the shard rather than the census.

KAPUA_CENSUS334_CHECKED_INTERFACES_AMENDMENT.md sections 1 and 3.2: one
representative per implementation group, in item-ID order, less the four the
owner removed on 2026-09-24. `maps/kapua/census334/tools/census.py` mints the
release from the extracted release components and verifies every byte of it
against them, gold sidecars included. This reader admits exactly that release:
the receipt beside the rows must be the reviewed
`maps/kapua/census334/census330.json`, and the rows must be the bytes that
receipt names. Both are read relative to the rows' directory, so a copied
release is admitted wherever it lands. The census is descriptive
(`inference_valid: false`) and has no mutation-map projection (amendment
section 7). The fixed 24-item pilot keeps its own route, `kapua_pilot`, which
also owns section 7.1's restriction of a census cell to the pilot IDs.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

PREFIX = "kapua-census"
NAME = "kapua-census330.jsonl"
SUBSET_ID = NAME.removesuffix(".jsonl")
#: The name `census.py build` gives the receipt copy it writes beside the rows.
RECEIPT = "census334.json"
#: SHA-256 of the owner-approved receipt, `maps/kapua/census334/census330.json`.
#: It names the rows' SHA-256, the exclusions and every input identity.
RECEIPT_SHA256 = "df686d6d4b1e56a5ee44f39383502280f23d786910be8238538db0820152d27d"
#: KAPUA_CENSUS330_MUTATION_AMENDMENT.md section 4: fixed before any shard runs.
SHARDS = 12
SHARD_SCHEMA = "r2t.kapua-census330-shard/1"
_SHARD = re.compile(re.escape(SUBSET_ID) + r"-shard-(\d\d)-of-(\d\d)\.jsonl")


class SelectionRefused(ValueError):
    pass


def _require(ok, message):
    if not ok:
        raise SelectionRefused("REFUSED: Kapua census: " + message)


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def is_selection(path):
    """Every `kapua-census*.jsonl` comes here, so a superseded census (the
    334-row release) refuses instead of passing as an unlabelled item file."""
    name = Path(path).name
    return name.startswith(PREFIX) and name.endswith(".jsonl")


def shard_name(index):
    return f"{SUBSET_ID}-shard-{index:02d}-of-{SHARDS:02d}.jsonl"


def _shard_lines(raw, index):
    lines = raw.split(b"\n")
    _require(raw.endswith(b"\n") and all(lines[:-1]), "census rows are not LF-terminated records")
    return [line + b"\n" for line in lines[:-1][index::SHARDS]]


def _load_shard(path, index):
    census = path.parent / NAME
    receipt = load_selection(census)
    lines = _shard_lines(census.read_bytes(), index)
    _require(path.read_bytes() == b"".join(lines),
             f"{path.name} is not lines {index}, {index + SHARDS}, ... of the approved census rows")
    ids = [json.loads(line)["item_id"] for line in lines]
    return {"schema": SHARD_SCHEMA, "shard": index, "of": SHARDS,
            "census": {"member": NAME, "sha256": receipt["outputs"]["items"]["sha256"]},
            "item_ids": ids, "pilot24_item_ids": [iid for iid in receipt["pilot24_item_ids"] if iid in set(ids)],
            "inference_valid": False, "inference_reason": receipt["inference_reason"],
            "outputs": {"items": {"member": path.name, "n": len(ids), "sha256": _sha256(path.read_bytes())}}}


def write_shards(path):
    """Write all `SHARDS` shard files beside the approved census rows."""
    path = Path(path).resolve(strict=True)
    load_selection(path)
    raw = path.read_bytes()
    targets = [path.parent / shard_name(index) for index in range(SHARDS)]
    _require(not any(target.exists() for target in targets), "a shard file already exists")
    written = []
    for index, target in enumerate(targets):
        with target.open("xb") as handle:
            handle.write(b"".join(_shard_lines(raw, index)))
        load_selection(target)
        written.append(str(target))
    return written


def load_selection(path):
    """The approved receipt, after checking it and the rows it names; for a
    shard, the shard's own description after rederiving its bytes."""
    try:
        path = Path(path).resolve(strict=True)
        shard = _SHARD.fullmatch(path.name)
        if shard and int(shard.group(2)) == SHARDS and int(shard.group(1)) < SHARDS:
            return _load_shard(path, int(shard.group(1)))
        _require(path.name == NAME, f"{path.name} is not the owner-approved census {NAME}")
        raw = (path.parent / RECEIPT).read_bytes()
        _require(_sha256(raw) == RECEIPT_SHA256,
                 f"{RECEIPT} beside the rows is not the owner-approved census330 receipt")
        receipt = json.loads(raw)
        _require(_sha256(path.read_bytes()) == receipt["outputs"]["items"]["sha256"],
                 "census rows differ from the bytes the approved receipt names")
        return receipt
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, SelectionRefused):
            raise
        raise SelectionRefused("REFUSED: Kapua census: " + str(exc)) from exc


def identify(path):
    receipt = load_selection(path)
    return {"subset_id": Path(path).name.removesuffix(".jsonl"),
            "subset_digest": receipt["outputs"]["items"]["sha256"][:16],
            "sidecar": str(Path(path).resolve().parent / RECEIPT), "inference_valid": False,
            "inference_reason": receipt["inference_reason"], "allow_cluster_siblings": True}


def selftest():
    import os
    import shutil
    import tempfile
    from types import SimpleNamespace
    from unittest import mock
    from ..bench import cli, population
    from ..core.paths import BENCHMARK_ROOT
    from ..data import subsets
    from . import kapua_census as K, kapua_pilot

    # The pin is the reviewed receipt in Git, and that receipt is the 330.
    reviewed = Path(BENCHMARK_ROOT).parent / "maps/kapua/census334/census330.json"
    raw = reviewed.read_bytes()
    assert _sha256(raw) == RECEIPT_SHA256, "pinned receipt differs from " + str(reviewed)
    doc = json.loads(raw)
    removed = {entry["item_id"] for entry in doc["exclusions"]["items"]}
    assert doc["outputs"]["items"]["member"] == NAME and doc["inference_valid"] is False
    assert doc["outputs"]["items"]["n"] == len(doc["item_ids"]) == doc["counts"]["representatives"] == 330
    assert len(removed) == doc["counts"]["excluded"] == 4 and removed.isdisjoint(doc["item_ids"])
    assert set(doc["pilot24_item_ids"]) <= set(doc["item_ids"])
    assert not K.is_selection("kapua-pilot.jsonl") and not kapua_pilot.is_pilot(NAME)

    def refuses(label, fn, fragment, kind=SelectionRefused):
        try:
            fn()
        except (kind, SystemExit) as exc:
            assert fragment in str(exc), f"{label}: {exc}"
            print("PASS refusal:", label)
        else:
            raise AssertionError("accepted " + label)

    # Real receipt shape over synthetic rows; only the pin moves to the fixture.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        release = root / "release"
        release.mkdir()
        ids = ["kapua/a.feature:1", "kapua/b.feature:2", "kapua/c.feature:3"]
        rows = b"".join((json.dumps({"item_id": iid, "project": "kapua", "checked_interfaces": {}},
                                    sort_keys=True) + "\n").encode() for iid in ids)
        items = release / NAME
        items.write_bytes(rows)
        fixture = {**doc, "item_ids": ids,
                   "outputs": {**doc["outputs"], "items": {"member": NAME, "n": 3, "sha256": _sha256(rows)}}}
        receipt = (json.dumps(fixture, indent=1, sort_keys=True) + "\n").encode()
        (release / RECEIPT).write_bytes(receipt)
        run = str(root / "run.jsonl")
        with mock.patch.object(K, "RECEIPT_SHA256", _sha256(receipt)):
            identity = K.identify(items)
            assert identity == {"subset_id": "kapua-census330", "subset_digest": _sha256(rows)[:16],
                                "sidecar": str(release.resolve() / RECEIPT), "inference_valid": False,
                                "inference_reason": doc["inference_reason"], "allow_cluster_siblings": True}
            # Run stamping and inferential readers share this identity.
            assert subsets.identify(str(items)) == subsets.identify_for_inference(str(items)) == identity
            planned = population.resolve([], run, explicit_release=str(items))
            assert (planned["planned_n"], planned["missing_planned_ids"], planned["complete"]) == (3, ids, False)
            assert planned["inference_valid"] is False and planned["inference_reason"] == doc["inference_reason"]
            assert planned["selection"] == {"path": identity["sidecar"], "sha256": _sha256(receipt)}
            stamped = [{"item_id": iid, "project": "kapua", "condition": "c2", "outcome": "passed",
                        "subset_id": identity["subset_id"], "subset_digest": identity["subset_digest"]}
                       for iid in ids]
            assert population.resolve(stamped, run, explicit_release=str(items))["complete"] is True
            short = population.resolve(stamped[1:], run, explicit_release=str(items))
            assert short["complete"] is False and short["missing_planned_ids"] == ids[:1]
            refuses("rows stamped with another census digest",
                    lambda: population.resolve([{**stamped[0], "subset_digest": "0" * 16}], run,
                                               explicit_release=str(items)),
                    "disagrees", population.PopulationRefusal)
            # Portable: every read is relative to the rows' directory.
            shutil.move(str(release), str(root / "moved"))
            release, items = root / "moved", root / "moved" / NAME
            assert K.identify(items)["sidecar"] == str(release.resolve() / RECEIPT)

            items.write_bytes(rows.replace(b"kapua/c", b"kapua/d"))
            refuses("changed census row", lambda: K.load_selection(items), "rows differ")
            refuses("report over a changed census row",
                    lambda: population.resolve(stamped, run, explicit_release=str(items)),
                    "rows differ", population.PopulationRefusal)
            refuses("inferential identity of a changed census row",
                    lambda: subsets.identify_for_inference(str(items)), "rows differ", subsets.SubsetRefused)
            refuses("run over a changed census row",
                    lambda: cli.cmd_run(SimpleNamespace(release=str(items), adapter="gold")), "rows differ")
            items.write_bytes(rows)
            (release / RECEIPT).write_bytes(receipt.replace(b'"decided"', b'"decided" '))
            refuses("changed receipt byte", lambda: K.load_selection(items), "not the owner-approved")
            os.unlink(release / RECEIPT)
            refuses("missing receipt", lambda: K.load_selection(items), RECEIPT)
            (release / RECEIPT).write_bytes(receipt)
            assert K.load_selection(items) == fixture
            with mock.patch.object(K, "SHARDS", 2):
                shards = K.write_shards(items)
                assert [Path(p).name for p in shards] == ["kapua-census330-shard-00-of-02.jsonl",
                                                          "kapua-census330-shard-01-of-02.jsonl"]
                first = K.load_selection(shards[0])
                assert first["item_ids"] == ids[0::2] and first["pilot24_item_ids"] == []
                assert Path(shards[0]).read_bytes() == b"".join(rows.splitlines(keepends=True)[0::2])
                shard_identity = subsets.identify_for_inference(shards[0])
                assert shard_identity["subset_id"] == "kapua-census330-shard-00-of-02"
                assert shard_identity["subset_digest"] == _sha256(Path(shards[0]).read_bytes())[:16]
                on_shard = [{**row, "subset_id": shard_identity["subset_id"],
                             "subset_digest": shard_identity["subset_digest"]}
                            for row in stamped if row["item_id"] in first["item_ids"]]
                assert population.resolve(on_shard, run, explicit_release=shards[0])["complete"] is True
                refuses("census-stamped rows reported as a shard",
                        lambda: population.resolve(stamped[0::2], run, explicit_release=shards[0]),
                        "disagrees", population.PopulationRefusal)
                refuses("existing shard files", lambda: K.write_shards(items), "exists")
                shard_bytes = Path(shards[1]).read_bytes()
                Path(shards[1]).write_bytes(shard_bytes + shard_bytes)
                refuses("changed shard bytes", lambda: K.load_selection(shards[1]), "is not lines 1, 3")
                refuses("run over a changed shard",
                        lambda: cli.cmd_run(SimpleNamespace(release=shards[1], adapter="gold")), "is not lines")
                Path(shards[1]).write_bytes(shard_bytes)
                other_count = release / "kapua-census330-shard-00-of-03.jsonl"
                shutil.copyfile(shards[0], other_count)
                refuses("shard of another partition", lambda: K.load_selection(other_count), "not the owner-approved")
                os.unlink(other_count)
                items.write_bytes(rows.replace(b"kapua/c", b"kapua/d"))
                refuses("shard beside changed census rows", lambda: K.load_selection(shards[0]), "rows differ")
                items.write_bytes(rows)
                for path in shards:
                    os.unlink(path)
            superseded = release / "kapua-census334.jsonl"
            shutil.copyfile(items, superseded)
            refuses("superseded 334-row census", lambda: K.load_selection(superseded), "not the owner-approved")
            refuses("run over the superseded census",
                    lambda: cli.cmd_run(SimpleNamespace(release=str(superseded), adapter="gold")),
                    "not the owner-approved")
        refuses("fixture under the real pin", lambda: K.load_selection(items), "not the owner-approved")
    print("PASS: Kapua census330 admission, portable relocation, population resolution and refusals")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
