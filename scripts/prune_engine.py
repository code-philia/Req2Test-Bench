#!/usr/bin/env python3
"""Prune the benchmark-only mirror down to the engine this repository vendors.

    python3 scripts/prune_engine.py TREE            # delete the pruned files
    python3 scripts/prune_engine.py TREE --dry-run  # list them, change nothing
    python3 scripts/prune_engine.py TREE --json     # pruned paths as JSON

TREE is a fresh checkout of the mirror that the research repository's
`benchmark/scripts/build_distribution.py OUT` builds (see
`engine/UPSTREAM.json` for the source commit).  Do not run it on this
repository's root: the root rules would delete this repository's own
README.md, pyproject.toml, req2test/ and tests/.  The rules below are the whole prune
list.  They depend only on the paths in TREE, so the result is
deterministic, and a second run removes nothing.

What stays is what the `req2test` route reads (fetch, tasks, views, runtime,
env, evaluate, validate, report) for all eight projects, plus the inputs of
the engine self-tests that `req2test selftest --engine` runs
(`req2test/engine.py`): the engine package `benchmark/r2t` (less the build
tool-kit's own self-tests), the task profiles and boundaries the route and
those self-tests load, the protocols the views and the 1.1 population name,
`schemas`, `VERSIONS.yml`, `items.jsonl`, `release/dataset_manifest.json`
and the three legacy files the results self-test reads.  The research
dataset release, the agent-arm profiles and protocols, the image recipes and
the research scripts and records are pruned.  They stay readable in the
research repository at the source commit.

`KEEP` lists the files inside a pruned area that stay, each with its reader.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import posixpath
import sys

#: The engine self-tests of the build tool-kit (component `toolkit`), which
#: no `req2test` verb, test or `data` or `bench` module imports;
#: `req2test selftest --engine` runs components `data` and `bench` only.
#: `toolkit/source_views_selftest.py` stays: tests/test_views.py imports its
#: fixtures.
TOOLKIT_SELFTESTS = tuple(f"benchmark/r2t/{name}_selftest.py" for name in (
    "go/bootstrap", "go/capture", "go/closure_plan", "go/controls",
    "go/index_cli", "go/interfaces_cli", "go/interfaces", "go/interpose",
    "go/mutation_cli", "go/prod_index_cli", "go/registry", "go/scaffold",
    "go/stub_cli", "java/research_minimal_oci", "java/research_minimal",
    "java/source_view", "toolkit/algorand_bundle_inputs",
    "toolkit/coreshop_evaluation_inputs",
    "toolkit/coreshop_mutation_authority", "toolkit/coreshop_mutation_map",
    "toolkit/epubcheck_image", "toolkit/epubcheck_reality",
    "toolkit/interfaces_java", "toolkit/java_direct_gate",
    "toolkit/mutation_go", "toolkit/php_direct_gate",
    "toolkit/source_views_java", "toolkit/validate_cli"))

#: (pattern, reason).  A pattern ending in `/` prunes that directory's whole
#: subtree; any other pattern is matched against paths in its own directory
#: only, so `benchmark/*.md` does not reach `benchmark/config/*.md`.
PRUNE = (
    ("AGENTS.md", "the research repository's agent instructions; this "
                  "repository writes its own"),
    ("CLAUDE.md", "the research repository's agent instructions; this "
                  "repository writes its own"),
    ("README.md", "the research repository's README; this repository "
                  "writes its own"),
    ("IMPLEMENTATION_STATUS.md", "research implementation log"),
    ("pyproject.toml", "the research copy of this repository's packaging; "
                       "this repository writes its own"),
    ("req2test/", "the research copy of this repository's front end; this "
                  "repository ships its own"),
    ("tests/", "the research copy of this repository's front-end tests; "
               "this repository ships its own"),
    (".gitattributes", "attributes of the research release tree, which is "
                       "pruned"),
    ("DATA.md", "research data-offload guide (the mirror already drops it)"),
    ("docs/", "research plans (the mirror already drops them)"),
    ("maps/", "source maps and census inputs; only the maintainer view "
              "builder and the research self-tests read them"),
    ("sprint/", "research sprint records"),
    ("tools/", "research tooling"),
    ("benchmark/*.md", "specifications, amendments, reports and rulings"),
    ("benchmark/docs/", "research runbooks, runtime notes and records"),
    ("benchmark/runbooks/", "research operator runbooks and their records"),
    ("benchmark/specifications/", "research specifications and amendments"),
    ("benchmark/scripts/", "research host bootstrap, gate, preparation and "
                           "operator scripts"),
    ("benchmark/runtime_packs/", "runner sources of the runtime packs; every "
                                 "pack ships its own runner, and only the "
                                 "pack builder reads these"),
    ("benchmark/docker/", "image recipes; the evaluation kits ship the "
                          "built images"),
    ("benchmark/examples/", "the source-view example the research "
                            "self-tests read"),
    ("benchmark/fixtures/", "fixtures of the build tool-kit's self-tests"),
    ("benchmark/release/", "the research dataset release (1.x item pools, "
                           "closures, indexes, mutant lists and legacy "
                           "evidence); the dataset and the kits are on the "
                           "Hugging Face Hub"),
    ("benchmark/protocol/protocol_v*.yml",
     "generation protocols of the study's agent runs"),
    ("benchmark/requirements-*.txt",
     "research host pins; pyproject.toml pins what req2test needs"),
    ("benchmark/EVALUATION_SCIENTIFIC_PLAN_V3_FIXTURE.json",
     "research evaluation-plan fixture; nothing reads it"),
    ("benchmark/llm_config*.example.json",
     "model configs for the research agent arms, whose code the mirror "
     "already drops"),
    ("benchmark/related_work_head_to_head.csv", "paper related-work table"),
    ("benchmark/config/evaluation_scopes/*.md",
     "preparation notes; the engine reads only the JSON scopes"),
    ("benchmark/config/evaluation_provenance/",
     "preparation record of a kit's seed disclosure; the kit ships its own"),
    ("benchmark/config/profile_*_pilot_r1_*.yml", "agent-arm task profiles"),
    ("benchmark/config/profile_*_probe_*.yml", "agent-arm task profiles"),
    ("benchmark/config/profile_*_visibility_*.yml",
     "task profiles of the 1.x visibility study"),
    ("benchmark/config/profile_*_api_analysis.yml", "research task profiles"),
    ("benchmark/config/campaign_results_*.yml",
     "result-table descriptors of the study's agent campaigns"),
    ("benchmark/config/codex_models.json", "agent-arm model list"),
    ("benchmark/config/pricing.yml", "model prices of the agent arms"),
    ("benchmark/config/m3_coreshop_runtime.yml", "research runtime record"),
    ("benchmark/config/dataset_manifest.yml",
     "source of the research dataset release"),
    ("benchmark/config/evaluation_approvals.json",
     "approval record of the kit builds"),
    ("benchmark/config/reference_control_dispositions.json",
     "kit preparation input"),
    ("benchmark/config/mutation_assets_*.json",
     "mutant indexes of the kit builds; the kits ship their mutants, and "
     "only the research self-tests read these"),
    ("benchmark/r2t/go/SAVED_CONTROL_PLANS.md", "preparation notes"),
    ("benchmark/r2t/java/algorand_fixtures/",
     "Algorand indexes of the research evaluator; no shipped module reads "
     "them"),
    ("benchmark/r2t/agents/source_view_all_fixtures/",
     "fixtures of an agent-arm self-test that the mirror already drops"),
    *((path, "a self-test of the build tool-kit") for path in
      TOOLKIT_SELFTESTS),
)

#: The protocols that stay: 401-408, the c2r protocols of the maintainer view
#: recipes (`req2test/views.py`), and 417-434.  Together they are every
#: protocol `config/benchmark_2.0_population.yml` lists.
KEPT_PROTOCOLS = (*range(401, 409), *range(417, 435))

#: Files inside a pruned area that stay, and who reads them.
KEEP = {
    "benchmark/release/dataset_manifest.json":
        "data/bundle.py validates every installed kit against it",
    "benchmark/release/eval100.jsonl":
        "the self-test of bench/results.py (its frozen legacy table)",
    "benchmark/release/v1/legacy_table_eval100_std.md":
        "the self-test of bench/results.py (its frozen legacy table)",
    "benchmark/release/v1/eval100.provenance.json":
        "the self-test of bench/results.py (its frozen legacy table)",
    **{f"benchmark/protocol/protocol_v{n}.yml":
       ("req2test/views.py (maintainer recipes)" if n < 409 else
        "config/benchmark_2.0_population.yml") + " and bench/protocol_file.py"
       for n in KEPT_PROTOCOLS},
}


def matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        return path.startswith(pattern)
    return (posixpath.dirname(path) == posixpath.dirname(pattern)
            and fnmatch.fnmatchcase(posixpath.basename(path),
                                    posixpath.basename(pattern)))


def reason(path: str) -> str:
    """Why `path` is pruned, or `''` when it stays."""
    if path in KEEP:
        return ""
    for pattern, why in PRUNE:
        if matches(path, pattern):
            return why
    return ""


def tree_files(root: str) -> list:
    """Every file below `root`, `/`-joined and relative, `.git` excluded."""
    found = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        rel = os.path.relpath(directory, root)
        for name in files:
            path = name if rel == "." else posixpath.join(
                rel.replace(os.sep, "/"), name)
            found.append(path)
    return sorted(found)


def plan(root: str) -> list:
    """`[(path, reason), ...]` for every file that the rules prune."""
    if not os.path.isfile(os.path.join(root, "benchmark", "r2t",
                                       "docker_authority.py")):
        raise SystemExit(f"REFUSED: {root} has no benchmark/r2t; give the "
                         f"root of a mirror checkout")
    return [(p, reason(p)) for p in tree_files(root) if reason(p)]


def prune(root: str, pruned: list) -> None:
    for path, _ in pruned:
        os.remove(os.path.join(root, path))
    # Directories the removals emptied, deepest first.
    for directory in sorted({posixpath.dirname(p) for p, _ in pruned},
                            key=lambda d: d.count("/"), reverse=True):
        while directory:
            full = os.path.join(root, directory)
            if os.path.isdir(full) and not os.listdir(full):
                os.rmdir(full)
                directory = posixpath.dirname(directory)
            else:
                break


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("tree", help="root of the mirror checkout to prune")
    parser.add_argument("--dry-run", action="store_true",
                        help="list what would be pruned; change nothing")
    parser.add_argument("--json", action="store_true",
                        help="print the pruned paths as a JSON list")
    args = parser.parse_args(argv)
    root = os.path.abspath(args.tree)
    pruned = plan(root)
    missing = sorted(p for p in KEEP
                     if not os.path.isfile(os.path.join(root, p)))
    if missing:
        print("WARNING: kept paths absent from the tree: "
              + ", ".join(missing), file=sys.stderr)
    if not args.dry_run:
        prune(root, pruned)
    if args.json:
        print(json.dumps([p for p, _ in pruned], indent=1))
        return 0
    verb = "would prune" if args.dry_run else "pruned"
    print(f"{verb} {len(pruned)} files under {root}")
    for why in dict.fromkeys(w for _, w in pruned):
        paths = [p for p, w in pruned if w == why]
        print(f"  {len(paths):5d}  {why}")
    print(f"kept {len(KEEP)} files inside pruned areas (see KEEP)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
