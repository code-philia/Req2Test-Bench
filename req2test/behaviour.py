"""API F1 and coverage Jaccard per instance, against the kit's references.

Both numbers come from the engine's own results code
(`r2t.bench.results.behaviour`, i.e. `metrics.compare`,
`metrics.coverage_similarity` and `metrics.api_call_similarity`): the
candidate's execution row is compared with the instance's ground-truth
execution row from `behaviour/gold_run.jsonl.zst`, through the kit's
production-method index and API profile.

Only passing instances are scored, as in the paper.  `coverage_j` is the
within-instance micro Jaccard of production lines; `api_f1` is the F1 of the
directly called production methods.  An instance the engine leaves out of a
block (for example a ground-truth test that calls no production method
directly) gets `null` for that metric, with the engine's reason recorded.

Output: `behaviour.json`, `{instance_id: {"api_f1", "coverage_j", ...}}` for
every executed instance (INTERFACES.md), and `behaviour.summary.json` with the
engine's block summaries and the reference files used.
"""
from __future__ import annotations

import json
from pathlib import Path

from .execute import ensure_engine_path
from .layout import decompressed, kit_inputs, read_json


def _excluded_reason(block: dict, iid: str):
    for reason, members in (block.get("excluded") or {}).items():
        if isinstance(members, dict):
            if iid in members:
                return f"{reason}: {members[iid]}"
        elif iid in (members or ()):
            return reason
    return None


def loadable_profile(profile: Path, boundary: Path, staging: Path) -> Path:
    """`profile`, or a copy beside its boundary when the kit stores it alone.

    The engine resolves a profile's boundary as a sibling file of the name the
    profile declares; a kit's `behaviour/api_profile.yml` has none beside it.
    """
    import shutil
    import yaml
    with open(profile, encoding="utf-8") as fh:
        name = (yaml.safe_load(fh) or {}).get("boundary")
    if not name or (Path(profile).parent / name).is_file():
        return Path(profile)
    staging.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(profile, staging / Path(profile).name)
    shutil.copyfile(boundary, staging / name)
    return staging / Path(profile).name


def run(kit, run_dir) -> Path:
    """Score `run_dir/exec.jsonl`; write and return `run_dir/behaviour.json`."""
    ensure_engine_path()
    from r2t.bench import results as R
    from r2t.bench import metrics as M
    from r2t.core.boundary import load_boundary
    from r2t.data.profile import load_profile

    run_dir = Path(run_dir)
    kin = kit_inputs(kit)
    cache = run_dir / "behaviour"
    cache.mkdir(parents=True, exist_ok=True)
    exec_path = run_dir / "exec.jsonl"
    rows = M.read_runs(str(exec_path))
    passed = {iid for iid, row in rows.items() if row.get("outcome") == "passed"}

    gold = decompressed(kin.gold_run, cache) if kin.gold_run else None
    index = decompressed(kin.prod_index, cache) if kin.prod_index else None
    profile = load_profile(str(loadable_profile(
        kin.api_profile or kin.worker_profile, kin.boundary,
        cache / "profile")))
    boundary = load_boundary(str(kin.boundary))
    block = R.behaviour(rows, passed, str(gold) if gold else None,
                        str(index) if index else None, boundary,
                        profile.api_scoring)
    cov, api = block["coverage"], block["api"]
    i_api = set(read_json(kin.i_api)) if kin.i_api else None
    i_cov = set(read_json(kin.i_cov)) if kin.i_cov else None

    instances = {}
    for iid in rows:
        entry = {"passed": iid in passed, "api_f1": None, "coverage_j": None,
                 "in_I_api": None if i_api is None else iid in i_api,
                 "in_I_cov": None if i_cov is None else iid in i_cov}
        if iid in passed:
            cov_item = (cov.get("per_item") or {}).get(iid)
            if cov_item is not None:
                entry["coverage_j"] = cov_item["coverage"]["micro_jaccard"]
            else:
                entry["coverage_reason"] = (_excluded_reason(cov, iid)
                                            or cov.get("reason"))
            api_item = (api.get("per_item") or {}).get(iid)
            if api_item is not None:
                entry["api_f1"] = api_item["api"]["f1"]
                entry["api_precision"] = api_item["api"]["precision"]
                entry["api_recall"] = api_item["api"]["recall"]
            else:
                entry["api_reason"] = (_excluded_reason(api, iid)
                                       or api.get("reason"))
        instances[iid] = entry

    def summary(b: dict) -> dict:
        return {key: b.get(key) for key in
                ("scored", "reason", "values", "n_passed", "n_scored")}

    doc = {"schema": "req2test.behaviour-summary/1",
           "gold_run": str(kin.gold_run) if kin.gold_run else None,
           "prod_index": str(kin.prod_index) if kin.prod_index else None,
           "api_profile": str(kin.api_profile) if kin.api_profile else None,
           "api_scoring": profile.api_scoring,
           "coverage": summary(cov), "api": summary(api)}
    (run_dir / "behaviour.summary.json").write_text(
        json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    out = run_dir / "behaviour.json"
    out.write_text(json.dumps(instances, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")
    return out
