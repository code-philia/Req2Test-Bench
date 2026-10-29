"""`validate`'s verdict from fake scored rows and mutation rows (no Docker):
survived and dropped G pairs grouped by mutant, `known_host_dependent`
matched by mutant id, and the pair-level flip rate."""
from req2test import evaluate as E
from kitfixture import write_kit

A, B, C, D = (f"python-docx/{x}.feature:1" for x in "abcd")
RULES = {"candidate_timeout": "drop", "crash_kill": False,
         "known_host_dependent": ["mh"]}


def kit(tmp_path):
    pools = [(A, "m1", "killed"), (A, "m2", "killed"), (A, "mh", "killed"),
             (B, "m1", "killed"), (B, "m3", "killed"),
             (C, "m1", "killed"), (C, "mh", "killed"),
             (D, "m1", "killed")]
    return write_kit(tmp_path / "kits", "python-docx", pools, rules=RULES)


def row(iid, passed=True, kc=True, status="scored", **extra):
    return {"instance_id": iid, "passed": passed,
            "outcome": "pass" if passed else "assertion_failure",
            "kill_complete": kc, "mutation_status": status,
            "mutation_baseline": "passed" if passed else None,
            "api_f1": 1.0 if passed else None,
            "coverage_j": 1.0 if passed else None, "recall": None, **extra}


def mrow(iid, mid, outcome):
    return {(iid, mid): {"instance_id": iid, "mutant_id": mid,
                         "outcome": outcome}}


def test_flips_grouped_by_mutant_and_known_by_mutant_id(tmp_path):
    rows = [row(A, kc=False), row(B), row(C, kc=False),
            row(D, passed=False, kc=False, status="not_passed")]
    mutation = {**mrow(A, "m1", "failed"), **mrow(A, "m2", "passed"),
                **mrow(A, "mh", "passed"),
                **mrow(B, "m1", "failed"), **mrow(B, "m3", "timeout"),
                **mrow(C, "m1", "failed"), **mrow(C, "mh", "passed")}
    pairs = E.pair_flips(kit(tmp_path), rows, mutation)
    assert (pairs["g_pairs_with_rows"], pairs["killed"], pairs["survived"],
            pairs["dropped"]) == (7, 3, 3, 1)
    assert abs(pairs["flip_rate"] - 4 / 7) < 1e-12
    assert pairs["survived_by_mutant"]["mh"] == {
        "n": 2, "instances": [A, C], "outcomes": {"passed": 2},
        "known_host_dependent": True}
    assert pairs["survived_by_mutant"]["m2"]["known_host_dependent"] is False
    assert pairs["dropped_by_mutant"] == {"m3": {
        "n": 1, "instances": [B], "outcomes": {"timeout": 1},
        "known_host_dependent": False}}
    assert pairs["flips_not_known_host_dependent"] == 2   # m2 and m3

    result = E.validation_result("python-docx", "r", rows, pairs)
    by_id = {d["instance_id"]: d for d in result["deviations"]}
    # C lost only a known host-dependent mutant: listed, not counted.
    assert by_id[C]["level"] == "known"
    # 2 of 7 pairs flipped (m2, m3) is far beyond 0.1%: A and B deviate.
    assert by_id[A]["level"] == "deviation"
    assert by_id[B]["level"] == "deviation"
    assert "dropped" in by_id[B]["causes"][0]
    assert by_id[D]["level"] == "deviation"
    assert result["flips_counted"] == 2
    assert not result["checks"]["ground_truth_passes"]
    assert not result["checks"]["flips_within_tolerance"]
    # 7 G pairs run: max(1, floor(0.007)) = 1 flip is allowed.
    assert (result["flip_tolerance"], result["flips_allowed"]) == (0.001, 1)
    assert not result["ok"]
    lines = E.describe(result)
    assert lines[0].endswith("-> DEVIATIONS")
    assert any("survived mutant mh: 2 pair(s)" in line
               and "[known host-dependent]" in line for line in lines)
    assert any("flips not known host-dependent: 2 (28.571%)" in line
               for line in lines)


def test_only_known_host_dependent_flips_is_ok(tmp_path):
    rows = [row(A, kc=False), row(B)]
    mutation = {**mrow(A, "m1", "failed"), **mrow(A, "m2", "failed"),
                **mrow(A, "mh", "passed"),
                **mrow(B, "m1", "failed"), **mrow(B, "m3", "failed")}
    pairs = E.pair_flips(kit(tmp_path), rows, mutation)
    result = E.validation_result("python-docx", "r", rows, pairs)
    assert result["ok"] and result["kill_complete"] == 1
    assert [d["level"] for d in result["deviations"]] == ["known"]
    assert E.describe(result)[0].endswith(
        "-> OK, within single-observation noise")


def test_instance_ids_in_known_host_dependent_do_not_excuse(tmp_path):
    rules = dict(RULES, known_host_dependent=[A])     # an instance id
    root = write_kit(tmp_path / "k2", "python-docx",
                     [(A, "m1", "killed"), (A, "m2", "killed")], rules=rules)
    rows = [row(A, kc=False)]
    pairs = E.pair_flips(root, rows, {**mrow(A, "m1", "passed"),
                                      **mrow(A, "m2", "passed")})
    result = E.validation_result("python-docx", "r", rows, pairs)
    assert result["flips_counted"] == 2
    assert not result["ok"]
    assert result["deviations"][0]["level"] == "deviation"


def big_pool(tmp_path, n):
    pools = [(A, f"m{i}", "killed") for i in range(n)] + [(B, "b", "killed")]
    return write_kit(tmp_path / f"big{n}", "python-docx", pools, rules=RULES)


def test_flips_allowed_is_one_or_a_tenth_of_a_percent():
    """max(1, floor(0.001 x G pairs run))."""
    assert [E.flips_allowed(n) for n in (0, 7, 999, 1000, 1999, 2000, 3000,
                                         12345)] == [1, 1, 1, 1, 1, 2, 3, 12]


def test_flip_tolerance_counts_flips_against_the_pairs_run(tmp_path):
    """One flip is always noise; two need at least 2,000 G pairs run."""
    for n, flips, ok in ((4, 1, True), (1999, 2, True), (1998, 2, False)):
        rows = [row(A, kc=False), row(B)]
        mutation = {**mrow(B, "b", "failed")}
        for i in range(n):
            mutation.update(mrow(A, f"m{i}",
                                 "passed" if i < flips else "failed"))
        pairs = E.pair_flips(big_pool(tmp_path, n), rows, mutation)
        assert pairs["g_pairs_with_rows"] == n + 1
        result = E.validation_result("python-docx", "r", rows, pairs)
        assert result["flips_counted"] == flips
        assert result["flips_allowed"] == (2 if n + 1 >= 2000 else 1)
        assert result["checks"]["flips_within_tolerance"] is ok, n
        assert result["ok"] is ok, n
        assert result["deviations"][0]["level"] == (
            "noise" if ok else "deviation")
        line = E.describe(result)[1]
        assert f"at most {result['flips_allowed']} allowed (max(1, " \
               f"floor(0.001 x {n + 1})))" in line, line


def test_coverage_floor_is_on_the_mean_with_per_instance_warnings(tmp_path):
    ids = [f"python-docx/{x}.feature:1" for x in "pqrst"]

    def verdict(low):
        rows = [row(i, status="not_scorable") for i in ids]
        rows[0]["coverage_j"] = low
        empty = {"g_pairs": 0, "g_pairs_with_rows": 0, "killed": 0,
                 "survived": 0, "dropped": 0, "flip_rate": None,
                 "flips_not_known_host_dependent": 0,
                 "survived_by_mutant": {}, "dropped_by_mutant": {}}
        return E.validation_result("python-docx", "r", rows, empty)

    ok = verdict(0.97)                  # mean 0.994
    assert ok["ok"]
    first = [d for d in ok["deviations"] if d["instance_id"] == ids[0]][0]
    assert first["level"] == "warning"
    assert "coverage J 0.9700" in first["causes"]
    bad = verdict(0.9)                  # mean 0.98
    assert not bad["ok"]
    assert not bad["checks"]["coverage_j_mean_at_least_0.99"]


def test_api_f1_mean_below_one_deviates(tmp_path):
    rows = [row(A), row(B, api_f1=0.5)]
    pairs = E.pair_flips(kit(tmp_path), rows, {
        **mrow(A, "m1", "failed"), **mrow(A, "m2", "failed"),
        **mrow(A, "mh", "failed"), **mrow(B, "m1", "failed"),
        **mrow(B, "m3", "failed")})
    result = E.validation_result("python-docx", "r", rows, pairs)
    assert not result["ok"] and not result["checks"]["api_f1_mean_is_1"]
    assert result["deviations"][0]["causes"] == ["API F1 0.5000"]


def test_unscored_pass_names_its_baseline(tmp_path):
    rows = [row(A, kc=False, status="unscored",
                mutation_baseline="infrastructure")]
    pairs = E.pair_flips(kit(tmp_path), rows, {})
    assert pairs["g_pairs"] == 3 and pairs["g_pairs_with_rows"] == 0
    result = E.validation_result("python-docx", "r", rows, pairs)
    assert result["deviations"][0]["causes"] == [
        "mutation unscored (mutation baseline infrastructure)"]
    assert not result["ok"]


def test_a_pass_whose_mutation_baseline_failed_deviates(tmp_path):
    rows = [row(A), row(B, kc=False, status="unscored",
                        mutation_baseline="failed")]
    pairs = E.pair_flips(kit(tmp_path), rows, {
        **mrow(A, "m1", "failed"), **mrow(A, "m2", "failed"),
        **mrow(A, "mh", "failed")})
    result = E.validation_result("python-docx", "r", rows, pairs)
    assert not result["checks"]["ground_truth_passes"] and not result["ok"]
    (dev,) = result["deviations"]
    assert dev["instance_id"] == B and dev["level"] == "deviation"
    assert dev["causes"] == ["mutation unscored (mutation baseline failed)"]


def test_validate_json_records_the_flip_tolerance(tmp_path, monkeypatch):
    from req2test import mutate
    from req2test import predictions as P
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path / "home"))
    root = kit(tmp_path)
    rows = [row(A), row(B)]
    monkeypatch.setattr(E, "sample_ids", lambda project, n: [A, B])
    monkeypatch.setattr(P, "from_gt", lambda project, ids, view: {})
    monkeypatch.setattr(E, "load_kit", lambda project: root)
    monkeypatch.setattr(E, "evaluate", lambda *a, **k: (
        E.run_root(k["run_id"]).mkdir(parents=True) or {"instances": rows}))
    monkeypatch.setattr(mutate, "read_rows", lambda path: {
        **mrow(A, "m1", "failed"), **mrow(A, "m2", "passed"),
        **mrow(A, "mh", "failed"), **mrow(B, "m1", "failed"),
        **mrow(B, "m3", "failed")})
    result = E.validate("python-docx", sample=2, run_id="v")
    doc = __import__("json").loads(
        (E.run_root("v") / "validate.json").read_text())
    assert (doc["flips_counted"], doc["flip_tolerance"],
            doc["flips_allowed"]) == (1, 0.001, 1)
    assert doc["ok"] is result["ok"] is True
