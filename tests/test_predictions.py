"""Predictions: validation, engine shape, and ground-truth conversion."""
import hashlib
import json

import pytest

from req2test import predictions as P


def row(**kw):
    base = {"instance_id": "python-docx/features/a.feature:3",
            "model_name_or_path": "m",
            "files": [{"path": "features/steps/x.py", "content": "pass\n"}]}
    base.update(kw)
    return base


@pytest.mark.parametrize("path", ["/abs.py", "../x.py", "a/../../x.py",
                                  "a\\b.py", "a//b.py", "./a.py", ""])
def test_bad_paths_refused(path):
    with pytest.raises(P.PredictionError):
        P.validate_row(row(files=[{"path": path, "content": ""}]), "t")


@pytest.mark.parametrize("bad", [
    {"status": "maybe"}, {"view": "xh"}, {"view": "ah"}, {"extra": 1},
    {"benchmark_version": "2"}, {"benchmark_version": "2.0"},
    {"benchmark_version": "1.x"},
    {"files": [{"path": "a.py"}]},
    {"files": [{"path": "a.py", "content": 1}]},
    {"files": [{"path": "a.py", "content": ""},
               {"path": "a.py", "content": ""}]},
    {"model_name_or_path": ""}, {"instance_id": ""}])
def test_malformed_rows_refused(bad):
    with pytest.raises(P.PredictionError):
        P.validate_row(row(**bad), "t")


def test_generation_failure_and_engine_shape():
    ok = P.validate_row(row(), "t")
    assert not ok.generation_failure
    assert P.to_engine(ok) == [{"file_path": "features/steps/x.py",
                                "code": "pass\n"}]
    assert P.validate_row(row(files=[]), "t").generation_failure
    no = P.validate_row(row(status="no_output"), "t")
    assert no.generation_failure and P.to_engine(no) == []
    assert P.to_engine(None) == []


def test_load_filters_and_refuses(tmp_path):
    path = tmp_path / "p.jsonl"
    rows = [row(), row(instance_id="coreshop/features/b.feature:1",
                       view="th")]
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    loaded = P.load(path, project="python-docx")
    assert list(loaded) == ["python-docx/features/a.feature:3"]
    path.write_text(json.dumps(row(view="ah")) + "\n")
    with pytest.raises(P.PredictionError, match="view must be one of"):
        P.load(path)                     # only the th view is offered
    path.write_text(json.dumps(row()) + "\n" + json.dumps(row()) + "\n")
    with pytest.raises(P.PredictionError, match="duplicate"):
        P.load(path)


def test_from_gt_matches_engine_gold_adapter(tmp_path, monkeypatch):
    """A ground-truth prediction is byte-identical to the engine's gold control,
    including the behat_services.yml fragment."""
    from r2t.bench.fixtures import make_gold_adapter
    iid = "coreshop/features/domain/cart/x.feature:22"
    files = {"src/A/Context.php": "<?php // a\n",
             "src/A/Setup.php": "<?php // b\n"}
    frag = {"svc.b": {"class": "B\\Ctx", "arguments": ["@x", "%y%"],
                      "tags": [{"name": "fob.context_service"}]},
            "svc.a": {"class": "A\\Ctx"}}
    data = tmp_path / "data"
    (data / "gt_tests").mkdir(parents=True)
    (data / "gt_tests" / "coreshop.jsonl").write_text(json.dumps({
        "instance_id": iid,
        "files": [{"path": p, "content": c} for p, c in files.items()],
        "di_fragment": frag}) + "\n")
    release = tmp_path / "release"
    gold_root = tmp_path / "gold"
    (release / "gold").mkdir(parents=True)
    (release / "gold" / "manifest.json").write_text(json.dumps({iid: "s.json"}))
    (release / "gold" / "s.json").write_text(json.dumps({
        "item_id": iid, "files": list(files), "di_fragment": frag}))
    for rel, content in files.items():
        (gold_root / rel).parent.mkdir(parents=True, exist_ok=True)
        (gold_root / rel).write_text(content)
    engine = make_gold_adapter(str(release), str(gold_root))({"item_id": iid})
    ours = P.from_gt("coreshop", [iid], data_dir=data)
    assert P.to_engine(ours[iid]) == engine["files"]
    assert ours[iid].files[-1]["path"] == "behat_services.yml"
    # ...and it runs as gold, like the engine's gold control (harness 25).
    assert ours[iid].ground_truth and engine["metadata"] == {"source": "gold"}
    assert "ground_truth" not in ours[iid].to_json()


def test_digest_and_normalized(tmp_path):
    a = {"x": P.validate_row(row(instance_id="x"), "t")}
    b = {"x": P.validate_row(row(instance_id="x", files=[]), "t")}
    assert P.digest(a) != P.digest(b) and P.digest(a) == P.digest(dict(a))
    out = tmp_path / "n.jsonl"
    P.write_normalized(a, ["x", "y"], out)
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["generation_failure"] for r in rows] == [False, True]
    assert rows[1]["produced_files"] == []


def test_repo_prefix_is_removed_with_one_warning_per_instance(tmp_path):
    path = tmp_path / "p.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in [
        row(files=[{"path": "repo/features/steps/a.py", "content": ""},
                   {"path": "repo/features/steps/b.py", "content": ""}]),
        row(instance_id="python-docx/features/b.feature:4"),
        row(instance_id="kapua/x.feature:1",
            files=[{"path": "repo/x/y.java", "content": ""}])]))
    warnings = []
    preds = P.load(path, project="python-docx", warn=warnings.append)
    first = preds["python-docx/features/a.feature:3"]
    assert [f["path"] for f in first.files] == ["features/steps/a.py",
                                                "features/steps/b.py"]
    assert len(warnings) == 1          # one per instance; kapua not loaded
    assert "python-docx/features/a.feature:3" in warnings[0]
    assert "2 file path(s)" in warnings[0]
    assert "'repo/features/steps/a.py' -> 'features/steps/a.py'" in warnings[0]
    # A repo/ path and its stripped twin are one file twice.
    with pytest.raises(P.PredictionError, match="duplicate path"):
        P.validate_row(row(files=[{"path": "repo/a.py", "content": ""},
                                  {"path": "a.py", "content": ""}]), "t")


def test_benchmark_version_round_trips_and_leaves_old_digests_alone():
    plain = P.validate_row(row(), "t")
    assert plain.benchmark_version is None
    assert "benchmark_version" not in plain.to_json()
    for version in P.BENCHMARK_VERSIONS:
        pred = P.validate_row(row(benchmark_version=version), "t")
        assert pred.benchmark_version == version
        assert pred.to_json()["benchmark_version"] == version
        assert P.digest({pred.instance_id: pred}) \
            != P.digest({plain.instance_id: plain})
    # A row without the field digests as it did before the field existed.
    assert P.digest({plain.instance_id: plain}) == hashlib.sha256(json.dumps(
        [row()], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
