"""Engine guard: the vendored engine's scoring modules are the upstream bytes.

`engine/UPSTREAM.json` records, for every file in the scoring set, the sha256
it had in the imported snapshot.  A file may differ from that only through a
listed patch, recorded in `UPSTREAM.json` as

    {"id": "P2", "files": ["benchmark/r2t/go/runtime.py"],
     "sha256_before": {"<path>": "<sha256>"},
     "sha256_after": {"<path>": "<sha256>"}, "reason": "..."}

Patches apply in list order, so a file several patches change carries their
chain: each patch's `sha256_before` is the previous one's `sha256_after`
(the first one's is the upstream sha256), and the file is the last one's
`sha256_after`.

The scoring set is the one in the harness plan, A.3 "Engine guard", plus
the nondeterministic-mutant list `benchmark/config/nondeterministic_mutants.yml`.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from . import ENGINE_ROOT, REPO_ROOT

UPSTREAM = REPO_ROOT / "engine" / "UPSTREAM.json"

#: Repository-relative patterns; `*` matches the files of one directory only.
SCORING_SET = (
    "benchmark/r2t/bench/harness.py",
    "benchmark/r2t/bench/runner.py",
    "benchmark/r2t/bench/mutation_run.py",
    "benchmark/r2t/bench/results.py",
    "benchmark/r2t/bench/metrics.py",
    "benchmark/r2t/bench/worker.py",
    "benchmark/r2t/bench/fixtures.py",
    "benchmark/r2t/data/mutation.py",
    "benchmark/r2t/stacks/*",
    "benchmark/r2t/go/runtime.py",
    "benchmark/r2t/go/mutation_runtime.py",
    "benchmark/r2t/php/*.php",
    "benchmark/r2t/py/mutate.py",
    "benchmark/r2t/ruby/*.rb",
    "benchmark/r2t/java/Mutate.java",
    # The mutants this list names are in no G_i.
    "benchmark/config/nondeterministic_mutants.yml",
)

#: The engine self-test components `selftest --engine` runs.
SELFTEST_COMPONENTS = ("data", "bench")

#: The self-tests of those components that `selftest --engine` leaves out,
#: and why: each reads research inputs that `scripts/prune_engine.py` prunes
#: (the 1.x dataset release, the agent-arm profiles and protocols, research
#: scripts and records).  They run in the research repository at the source
#: commit (`engine/UPSTREAM.json`).
SELFTEST_SKIPPED = {
    "data.profile": "loads every agent-arm and 1.x visibility profile",
    "data.mutation": "the archived 1.x mutant manifests",
    "data.mutation_attestation": "the archived 1.x mutation asset index",
    "java.kapua_census": "the Kapua census receipt under maps/",
    "data.release": "the 1.x release summaries",
    "data.bundle": "the 1.x release files VERSIONS.yml pins",
    "data.subsets": "a research sampling script",
    "data.versions": "every pinned 1.x release file and protocol",
    "data.sylius_selection": "the 1.x Sylius release and maps/",
    "bench.runner": "the 1.x release item pools",
    "bench.result_ledger": "an agent-run protocol",
    "bench.mutation_bounds": "a research ruling resolved through git",
    "bench.cli": "the 1.x legacy-consistency catalogue",
    "bench.reference_workloads": "the 1.x legacy-consistency catalogue",
    "bench.prestashop_reference_selftest":
        "the 1.x legacy-consistency catalogue",
    "bench.evaluator_corrections": "a research selection script",
    "bench.egress_attestation": "the 1.x agent-run egress evidence",
    "bench.campaign_table": "the agent campaigns' result descriptors",
    "bench.draws": "a research stamping script",
    "bench.test_quality": "a research selection script and ruling",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def scoring_set_files(root: Path = REPO_ROOT) -> list:
    """Repository-relative paths of the files the scoring set names."""
    found = set()
    for pattern in SCORING_SET:
        for path in glob.glob(str(root / pattern)):
            if os.path.isfile(path):
                found.add(Path(path).relative_to(root).as_posix())
    return sorted(found)


def scoring_set_digests(root: Path = REPO_ROOT) -> dict:
    return {rel: sha256_file(root / rel) for rel in scoring_set_files(root)}


def load_upstream(path: Path = UPSTREAM) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def check_scoring_set(root: Path = REPO_ROOT, upstream: dict = None) -> list:
    """Every way the scoring set differs from `UPSTREAM.json`; empty if none."""
    upstream = load_upstream() if upstream is None else upstream
    recorded = upstream["scoring_set"]
    patched = {}                    # rel -> the patches changing it, in order
    for patch in upstream.get("patches", []):
        for rel in patch["files"]:
            patched.setdefault(rel, []).append(patch)
    current = scoring_set_digests(root)
    problems = []
    for rel in sorted(set(recorded) - set(current)):
        problems.append(f"{rel}: recorded in UPSTREAM.json but missing")
    for rel in sorted(set(current) - set(recorded)):
        problems.append(f"{rel}: in the scoring set but not recorded in "
                        f"UPSTREAM.json")
    for rel in sorted(set(current) & set(recorded)):
        chain = patched.get(rel)
        if chain is None:
            if current[rel] != recorded[rel]:
                problems.append(f"{rel}: sha256 {current[rel]} differs from "
                                f"upstream {recorded[rel]} and no listed "
                                f"patch declares it")
            continue
        expected, source = recorded[rel], "the upstream"
        for patch in chain:
            before = patch.get("sha256_before", {}).get(rel)
            if before != expected:
                problems.append(f"{rel}: patch {patch['id']} sha256_before "
                                f"{before} is not {source} {expected}")
            expected = patch.get("sha256_after", {}).get(rel)
            source = f"patch {patch['id']} sha256_after"
        if current[rel] != expected:
            problems.append(f"{rel}: sha256 {current[rel]} is not {source} "
                            f"{expected}")
    return problems


def selftest_modules(component: str) -> list:
    """The self-test modules of `component` that `selftest --engine` runs:
    the engine's own selection (core included) less `SELFTEST_SKIPPED`."""
    if str(ENGINE_ROOT) not in sys.path:
        sys.path.insert(0, str(ENGINE_ROOT))
    from r2t.core.components import component_modules
    return [m for m in component_modules(component)
            if m not in SELFTEST_SKIPPED]


def run_engine_selftest(component: str, jobs: int = None) -> int:
    """`python -m r2t.selftest --component <component> --only ...` over
    `selftest_modules(component)`; its exit code."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(ENGINE_ROOT), env.get("PYTHONPATH")) if p)
    argv = [sys.executable, "-m", "r2t.selftest", "--component", component]
    for module in selftest_modules(component):
        argv += ["--only", module]
    if jobs is not None:
        argv += ["-j", str(jobs)]
    print(f"$ PYTHONPATH={ENGINE_ROOT} {' '.join(argv)}", flush=True)
    return subprocess.call(argv, cwd=REPO_ROOT, env=env,
                           stdin=subprocess.DEVNULL)


def selftest_engine(jobs: int = None) -> int:
    """Run the engine self-tests (`selftest_modules`) and the scoring-set
    check; 0 when all pass.

    Every step runs even after an earlier one fails, so one run reports the
    whole failure list.
    """
    failures = []
    for component in SELFTEST_COMPONENTS:
        rc = run_engine_selftest(component, jobs)
        print(f"engine self-test --component {component}: "
              f"{'PASS' if rc == 0 else f'FAIL (exit {rc})'}", flush=True)
        if rc != 0:
            failures.append(f"engine self-test --component {component}")
    problems = check_scoring_set()
    count = len(load_upstream()["scoring_set"])
    if problems:
        failures.append("scoring-set sha256 guard")
        print(f"scoring-set sha256 guard: FAIL ({len(problems)} problems)")
        for problem in problems:
            print(f"  {problem}")
    else:
        print(f"scoring-set sha256 guard: PASS ({count} files match "
              f"engine/UPSTREAM.json)")
    print()
    if failures:
        print(f"selftest --engine: {len(failures)} FAILED: "
              + "; ".join(failures))
        return 1
    print("selftest --engine: OK")
    return 0
