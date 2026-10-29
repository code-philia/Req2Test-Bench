"""A minimal evaluation kit on disk, for the scorer and report tests, and
whether bubblewrap runs here."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


def bwrap_usable(*flags) -> bool:
    """Whether bubblewrap runs a command here with `flags`."""
    try:
        return subprocess.run(["bwrap", *flags, "--dev-bind", "/", "/", "true"],
                              capture_output=True).returncode == 0
    except OSError:
        return False


def write_kit(root: Path, project: str, pools: list, excluded: list = (),
              rules: dict = None, i_api: list = None,
              i_cov: list = None) -> Path:
    """`pools` rows are (item_id, mutant_id, gold_outcome)."""
    kit = Path(root) / project
    (kit / "mutation").mkdir(parents=True, exist_ok=True)
    (kit / "kit.json").write_text(json.dumps(
        {"schema": "req2test.kit/1", "project": project, "kit_version": "test"}))
    (kit / "mutation" / "rules.json").write_text(json.dumps(
        rules or {"candidate_timeout": "drop", "crash_kill": False,
                  "known_host_dependent": []}))
    with open(kit / "mutation" / "pools.jsonl", "w") as fh:
        for iid, mid, gold in pools:
            fh.write(json.dumps({"item_id": iid, "mutant_id": mid,
                                 "gold_outcome": gold}) + "\n")
    with open(kit / "mutation" / "reference_excluded.jsonl", "w") as fh:
        for iid, mid in excluded:
            fh.write(json.dumps({"item_id": iid, "mutant_id": mid,
                                 "role": "full_gold",
                                 "outcome": "no_scenario_ran"}) + "\n")
    if i_api is not None or i_cov is not None:
        (kit / "behaviour").mkdir(exist_ok=True)
        (kit / "behaviour" / "I_api.json").write_text(json.dumps(i_api or []))
        (kit / "behaviour" / "I_cov.json").write_text(json.dumps(i_cov or []))
    return kit


NATIVE = {"candidate_timeout": "kill", "crash_kill": False,
          "known_host_dependent": []}
SINGLE = {"candidate_timeout": "drop", "crash_kill": False,
          "known_host_dependent": []}
CODDY = {"candidate_timeout": "drop", "crash_kill": True,
         "known_host_dependent": []}


def write_done(cell: Path, baselines: dict = None) -> None:
    """The `mutation.done.json` a finished mutation stage leaves in `cell`."""
    import hashlib
    exec_sha = hashlib.sha256((Path(cell) / "exec.jsonl").read_bytes())
    (Path(cell) / "mutation.done.json").write_text(json.dumps({
        "schema": "req2test.mutation-done/1",
        "exec_sha256": exec_sha.hexdigest(),
        "baselines": baselines or {}}))
