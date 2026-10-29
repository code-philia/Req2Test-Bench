"""The component table, and the import direction it implies -- as a checked fact.

`COMPONENT` says, for every module in this package, which of five components
it belongs to:

  core      what every other component needs and nothing else may own:
            paths, the item boundary, the Gherkin parser, the Docker
            authority, the shared constants, and this table.
  data      the dataset contract: the release vocabulary and readers, the
            installed-bundle reader, subsets, the task profile and prompt
            renderer, the versions registry, the mutant population and
            the mutation-asset validators.  Imports `core` and nothing
            else at module level (fact (c)).
  bench     the benchmark itself: the CLI, the runner and its fixture
            adapters, campaigns, workers, the ledger, scoring, results.
            The consumer route runs on `core + data + bench` alone.
  toolkit   what BUILDS a benchmark from a repository: closures, indexes,
            stripping, stubbing, mutation engines, images, environments,
            the doctor and the self-test driver.
  agent     this study's own agent arms: drivers, the trial protocol, the
            egress proxy, pricing, the Slice-3 coordinator and every
            self-test that exercises them.  The one component a checkout
            may physically lack.

The table is the single partition.  `selftest`'s driver reads it (a component
run is `component_modules(...)`), `VERSIONS.yml`'s ownership completeness
walks the same files (`package_files`), and `selftest()` below turns the
direction the table implies into three facts a machine can check:

  (a) no module outside `agent` imports an `agent` module AT MODULE LEVEL,
      so a checkout without `agent` files can import every other module
      (`import` statements only: a module-scope CALL of a function that
      imports is invisible to an AST walk, and the mirror's own import of
      every module is the executable authority for that);
  (b) the transitive import closure of the consumer verbs' handlers and of
      the `cli` functions they reach (seeded from the composer `cli` and the
      consumer entry `bench.cli`) -- every import statement the verb could
      execute, module-level or function-local -- reaches `agent` modules
      only through the edges
      listed in `KNOWN_CONSUMER_ROUTE_LEAKS`, which the plan cuts one by one
      (rows are asserted EXACTLY: a cut edge must leave the table, a new edge
      fails);
  (c) no `data` module imports a `bench`, `toolkit` or `agent` module AT
      MODULE LEVEL, so a `core + data` checkout imports the dataset
      contract whole.  Module-level, like (a): the function-local edges a
      `data` module's own code still crosses (its self-test excluded) are
      listed in `KNOWN_DATA_ROUTE_EDGES` and asserted exactly the same way,
      so "data imports only core" is a checked statement about imports and
      not a claim about what runs.

`bench` and `toolkit` may import each other freely, in both directions,
and both may import `data`; `data` imports neither.
Imports inside `try: ... except ImportError:` and `importlib`/`__import__`
dispatch are outside both facts by definition; the benchmark-only mirror's
own check is the executable authority for those.  Everything here is
`ast`-level: nothing is imported, so the check costs a walk and a parse,
printed (measured, not asserted) by `selftest()`.
"""
from __future__ import annotations

import ast
import fnmatch
import os
import sys
import time
from collections import namedtuple
from typing import Iterable, Optional

PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH_ROOT = os.path.dirname(PACKAGE_DIR)

COMPONENTS = ("core", "data", "bench", "toolkit", "agent")

#: The root package's own `__init__.py`, which has no dotted name of its own.
ROOT = "__init__"

#: Module name (the `selftest.MODULES` spelling: `boundary`, `py.mutate`,
#: `agents.scanners`, ...) -> component.  Every `.py` under the package has
#: a row; `selftest()` refuses a file on disk with no row.
COMPONENT = {
    # -- core ----------------------------------------------------------------
    ROOT: "core",
    "core": "core",
    "core.paths": "core",
    "core.boundary": "core",
    "core.gherkin": "core",
    "docker_authority": "core",
    "core.docker_cli": "core",
    "core.reviewed_git": "core",
    "core.constants": "core",
    "core.ledger_primitives": "core",
    "core.source_view": "core",
    "core.source_view_selftest": "core",
    "core.components": "core",
    # -- data: the dataset contract; imports core and nothing else -----------
    "data": "data",
    "data.versions": "data",
    "data.subsets": "data",
    "data.step_definition_census": "data",
    "data.sylius_selection": "data",
    "data.release": "data",
    "data.visibility_release": "data",
    "data.bundle": "data",
    "data.evaluation_bundle": "data",
    "data.profile": "data",
    "data.prompt": "data",
    "data.mutation": "data",
    "data.mutation_attestation": "data",
    # `r2t/mutation.py` is the one-line re-export of `data.mutation` that the
    # frozen, byte-pinned enumerator `py/mutate.py` imports: that module under
    # its old name.
    "mutation": "data",
    # Left in `java/` (stack directories do not move) and filed here the way
    # `agents.scanners` is filed `bench`: the Algorand item/exclusion
    # descriptor has no r2t import, and `data.release` reads it inside
    # `admit_pre_execution`.
    "java.algorand": "data",
    "java.kapua": "data",
    # The owner-approved census330 run/report population, beside the pilot.
    "java.kapua_census": "data",
    "ruby.evaluation_selection": "data",
    # Pure Go carrier shared by task export, prompts and the runtime harness.
    "go": "data",
    "go.context": "data",
    "go.coddy": "data",
    "go.mutation_copy": "bench",
    "go.mutation_copy_selftest": "bench",
    "go.mutation_runtime": "bench",
    "go.mutation_runtime_selftest": "bench",
    "go.mutation_audit": "bench",
    "go.mutation_audit_selftest": "bench",
    "go.execution": "bench",
    "go.workspace": "bench",
    "go.workspace_selftest": "bench",
    "go.runtime": "bench",
    "go.runtime_selftest": "bench",
    "go.sensitivity": "bench",
    "go.execution_selftest": "bench",
    # -- bench ---------------------------------------------------------------
    "cli": "bench",
    "bench.cli": "bench",
    "bench": "bench",
    "bench.runner": "bench",
    "bench.adapters": "bench",
    "bench.fixtures": "bench",
    "bench.campaign": "bench",
    "bench.confine": "bench",
    "stacks": "bench",
    "stacks.base": "bench",
    "stacks.behat": "bench",
    "stacks.behave": "bench",
    "stacks.cucumber": "bench",
    "stacks.godog": "bench",
    "stacks.cucumber_ruby": "bench",
    "ruby": "bench",
    "ruby.e_petitions": "toolkit",
    "toolkit.rbstep_index": "toolkit",
    "toolkit.closure_rb": "toolkit",
    "toolkit.stub_rb": "toolkit",
    "toolkit.strip_rb": "toolkit",
    "toolkit.mutation_rb": "toolkit",
    "toolkit.prod_index_rb": "toolkit",
    "toolkit.interfaces_rb": "toolkit",
    "bench.harness": "bench",
    "bench.validate": "bench",
    "bench.metrics": "bench",
    "bench.results": "bench",
    "bench.report": "bench",
    "bench.population": "bench",
    "bench.worker": "bench",
    "bench.prestashop_selftest": "bench",
    "bench.dbadmin": "bench",
    "bench.draws": "bench",
    "bench.finish": "bench",
    "bench.finish_selftest": "bench",
    "bench.generate": "bench",
    "bench.campaign_table": "bench",
    "bench.result_ledger": "bench",
    "bench.result_ledger_i2_selftest": "bench",
    "bench.result_ledger_i3_selftest": "bench",
    "bench.result_ledger_i4_selftest": "bench",
    "bench.result_ledger_i5_selftest": "bench",
    "egress": "bench",
    "bench.egress_attestation": "bench",
    "bench.trajectory_validation": "bench",
    "agents.scanners": "bench",
    "agents.scanners.aider": "bench",
    "bench.test_quality": "bench",
    "bench.evaluator_corrections": "bench",
    "bench.mutation_startup_recovery": "bench",
    "bench.live_test_quality": "bench",
    "bench.mutation_run": "bench",
    "bench.mutation_continuation": "bench",
    "bench.prestashop_continuation": "bench",
    "bench.prestashop_continuation_selftest": "bench",
    "bench.prestashop_continuation_packet": "bench",
    "bench.mutation_distribution": "bench",
    "bench.mutation_bounds": "bench",
    "bench.mutation_batch": "bench",
    "bench.evaluation_reference": "bench",
    "bench.evaluation_reference_selftest": "bench",
    "bench.reference_controls": "bench",
    "bench.reference_loader": "bench",
    "bench.reference_pair_continuation": "bench",
    "bench.reference_pair_continuation_selftest": "bench",
    "bench.reference_workloads": "bench",
    "bench.prestashop_reference": "bench",
    "bench.prestashop_reference_selftest": "bench",
    "bench.seed": "bench",
    "bench.repo": "bench",
    "bench.prestashop_resources": "bench",
    "bench.prestashop_memory": "bench",
    "py": "bench",
    "py.compile_check": "bench",
    "py.bench_environment": "bench",
    "py.accessor_recorder_selftest": "bench",
    "java": "bench",
    "bench.tier1b_verdict_selftest": "bench",
    "bench.slice3_evidence": "bench",
    "bench.slice3_test_quality": "bench",
    "bench.protocol_file": "bench",
    # -- toolkit -------------------------------------------------------------
    "toolkit.cli": "toolkit",
    "toolkit.validate_cli_selftest": "toolkit",
    "toolkit": "toolkit",
    "toolkit.closure": "toolkit",
    "toolkit.closure_py": "toolkit",
    "toolkit.interfaces": "toolkit",
    "toolkit.interfaces_py": "toolkit",
    "toolkit.checked_interfaces": "toolkit",
    "toolkit.source_view_all": "toolkit",
    "agents.source_view_all_selftest": "agent",
    "toolkit.interfaces_java": "toolkit",
    "toolkit.interfaces_java_selftest": "toolkit",
    "java.closure_java": "toolkit",
    "java.source_view": "toolkit",
    "java.source_view_selftest": "toolkit",
    "go.bootstrap": "toolkit",
    "go.bootstrap_selftest": "toolkit",
    "go.index_cli": "toolkit",
    "go.index_cli_selftest": "toolkit",
    "go.registry": "toolkit",
    "go.measurement": "toolkit",
    "go.measurement_selftest": "toolkit",
    "go.closure": "toolkit",
    "go.controls": "toolkit",
    "go.control_adapter": "toolkit",
    "go.controls_selftest": "toolkit",
    "go.stub_cli": "toolkit",
    "go.stub_cli_selftest": "toolkit",
    "go.closure_plan": "toolkit",
    "go.closure_plan_selftest": "toolkit",
    "go.registry_selftest": "toolkit",
    "go.interpose_selftest": "toolkit",
    "go.scaffold_selftest": "toolkit",
    "go.capture_selftest": "toolkit",
    "go.mutation_entry": "toolkit",
    "go.mutation_cli": "toolkit",
    "go.mutation_cli_selftest": "toolkit",
    "go.interfaces": "toolkit",
    "go.interfaces_attribution": "toolkit",
    "go.interfaces_entry": "toolkit",
    "go.interfaces_cli": "toolkit",
    "go.interfaces_selftest": "toolkit",
    "go.interfaces_cli_selftest": "toolkit",
    "go.prod_index": "toolkit",
    "go.prod_index_selftest": "toolkit",
    "go.prod_index_cli": "toolkit",
    "go.prod_index_entry": "toolkit",
    "go.prod_index_cli_selftest": "toolkit",
    "go.assertion_strip": "toolkit",
    "go.assertion_strip_selftest": "toolkit",
    "go.source_view": "toolkit",
    "go.source_view_selftest": "toolkit",
    # The direct-invocation collector's host side.  `stacks.cucumber` (bench)
    # imports it at module level for the record fold, so it is bench.
    "java.direct_calls": "bench",
    "toolkit.pystep_index": "toolkit",
    "py.analyze_py": "toolkit",
    "py.prod_index": "toolkit",
    "py.source_view": "toolkit",
    "php.source_view": "toolkit",
    "ruby.source_view": "toolkit",
    "toolkit.source_views": "toolkit",
    # The two offline producers of the section 6.2/6.3 secondary inputs.
    # `toolkit` because both need what only a builder has -- the language body
    # parsers for the first, the whole gold corpus for the second -- while
    # `bench.metrics` reads their artifacts and stays parser-free.
    "toolkit.target_regions": "toolkit",
    "toolkit.control_floors": "toolkit",
    "toolkit.source_views_selftest": "toolkit",
    "toolkit.source_views_java_selftest": "toolkit",
    "py.match_steps": "toolkit",
    "toolkit.behat_wiring": "toolkit",
    "toolkit.behat_wiring_php": "toolkit",
    "toolkit.di_walk_php": "toolkit",
    "toolkit.behat_suites": "toolkit",
    "toolkit.strip": "toolkit",
    "toolkit.strip_py": "toolkit",
    "toolkit.strip_java": "toolkit",
    "toolkit.stub": "toolkit",
    "toolkit.stub_py": "toolkit",
    "toolkit.stub_java": "toolkit",
    "py.stub_accept": "toolkit",
    "toolkit.quality": "toolkit",
    "toolkit.mutation_go": "toolkit",
    "toolkit.mutation_go_selftest": "toolkit",
    "toolkit.mutation_py": "toolkit",
    "toolkit.mutation_java": "toolkit",
    "py.mutate": "toolkit",
    "toolkit.mutation_audit": "toolkit",
    "toolkit.mutation_asset_index": "toolkit",
    "toolkit.coreshop_mutation_map_selftest": "toolkit",
    "toolkit.assertion_selection": "toolkit",
    "toolkit.coreshop_mutation_authority_selftest": "toolkit",
    "toolkit.coreshop_evaluation_inputs_selftest": "toolkit",
    "toolkit.gold_killset": "toolkit",
    "toolkit.hard_subset": "toolkit",
    "toolkit.subset_writer": "toolkit",
    "toolkit.anti_vacuity": "toolkit",
    "toolkit.anti_vacuity_evidence": "toolkit",
    "toolkit.docx_v2_workload": "toolkit",
    "toolkit.release_build": "toolkit",
    "toolkit.bundle_build": "toolkit",
    "toolkit.evaluation_bundle_selftest": "toolkit",
    "toolkit.algorand_bundle": "toolkit",
    "toolkit.algorand_bundle_inputs_selftest": "toolkit",
    "toolkit.coreshop_preparation": "toolkit",
    "toolkit.php_direct_gate_selftest": "toolkit",
    "toolkit.java_direct_gate_selftest": "toolkit",
    "toolkit.algorand_image": "toolkit",
    "toolkit.images": "toolkit",
    "toolkit.epubcheck_image": "toolkit",
    "toolkit.epubcheck_image_selftest": "toolkit",
    "toolkit.epubcheck_reality": "toolkit",
    "toolkit.epubcheck_reality_selftest": "toolkit",
    "java.j0": "toolkit",
    "java.j0_fork": "toolkit",
    "java.j0_timing": "toolkit",
    "java.compose_algorand": "toolkit",
    "java.release_validation": "toolkit",
    "java.kapua_runtime": "toolkit",
    "java.kapua_compiler": "toolkit",
    "java.kapua_population": "toolkit",
    "java.kapua_gold_coverage": "toolkit",
    "java.kapua_headroom": "toolkit",
    "java.kapua_pilot": "toolkit",
    "java.kapua_census_mutation": "toolkit",
    "java.kapua_reference": "toolkit",
    "java.kapua_development_release": "toolkit",
    "java.research_minimal": "toolkit",
    "java.research_minimal_selftest": "toolkit",
    "java.research_minimal_oci": "toolkit",
    "java.research_minimal_oci_selftest": "toolkit",
    "toolkit.environment": "toolkit",
    "toolkit.environment_lifecycle": "toolkit",
    "toolkit.provision_coreshop": "toolkit",
    "toolkit.provision_sylius": "toolkit",
    "toolkit.provision_prestashop": "toolkit",
    "toolkit.doctor": "toolkit",
    "toolkit.sweep": "toolkit",
    "selftest": "toolkit",
    "toolkit.extract": "toolkit",
    # -- agent: the explicit list of files a checkout may lack ---------------
    "agents.cli": "agent",
    # ...minus the DRIVER rows, which are derived from the files themselves
    # below `modules_on_disk`: a third arm ships a driver and needs no line
    # of its own here.
    "agents": "agent",
    "agents.backends": "agent",
    "agents.base": "agent",
    "agents.registry": "agent",
    "agents.source_views": "agent",
    "agents.source_views_selftest": "agent",
    "confined": "agent",
    "confined.agent_wire_transport": "agent",
    "confined.terminate": "agent",
    "agents.trials": "agent",
    "agents.harvest": "agent",
    "confined.pricing": "agent",
    "confined.agent_stats": "agent",
    "agents.egress_proxy": "agent",
    "agents.sandbox": "agent",
    "agents.toolset_probe": "agent",
    # Filed `bench` the way `agents.scanners` is: it imports only `core`
    # (function-locally), and `req2test`'s benchmark 2.0 route (`req2test
    # fetch --packs-only`, `req2test runtime setup`) runs its manifest,
    # admission and attempt setup, so the benchmark-only mirror ships it.
    # Its self-test drives the adapter and stays `agent`.
    "agents.runtime_pack": "bench",
    "agents.runtime_pack_selftest": "agent",
    # The packs' runner versions and the operator's v1.1 pack maker: no
    # consumer verb reaches it, so the benchmark-only mirror does not ship it.
    "agents.runtime_runner": "agent",
    # The launcher's runtime gates: the preflight runs the agent sandbox,
    # and the first-rows check reads the launcher's outputs.
    "agents.runtime_preflight": "agent",
    "agents.run_health": "agent",
    "agents.visibility_mounts": "agent",
    "agents.visibility_mounts_selftest": "agent",
    "agents.agent_view_selftest": "agent",
    "agents.visibility_native_fixture": "agent",
    "agents.codex_native_fixture": "agent",
    "confined.codex_transport": "agent",
    "confined.codex_driver_selftest": "agent",
    "agents.claude_code_native_fixture": "agent",
    "confined.claude_code_transport": "agent",
    "confined.claude_code_driver_selftest": "agent",
    "agents.visibility_backend_fixture": "agent",
    "agents.publication": "agent",
    "agents.adapter": "agent",
    "agents.egress_proxy_selftest": "agent",
    "agents.chatgpt_account": "agent",
    "agents.claude_account": "agent",
    "agents.chatgpt_account_selftest": "agent",
    "agents.codex_shape_probe": "agent",
    "agents.evaluation_execution": "agent",
    "agents.evaluation_execution_selftest": "agent",
    "agents.evaluation_execution_v3": "agent",
    "agents.evaluation_execution_v3_selftest": "agent",
    "agents.evaluation_execution_v3_agent": "agent",
    "agents.evaluation_execution_v3_agent_selftest": "agent",
    "agents.evaluation_execution_v3_attempt": "agent",
    "agents.evaluation_execution_v3_attempt_selftest": "agent",
    "agents.evaluation_execution_v3_lineage": "agent",
    "agents.evaluation_execution_v3_lineage_selftest": "agent",
    "agents.slice3_eval": "agent",
    "confined.result_ledger_v2": "agent",
    "agents.result_ledger_v2_selftest": "agent",
    "agents.agent_d2_launch_observation": "agent",
    "agents.agent_d2_launch_observation_selftest": "agent",
    "agents.agent_confinement_selftest": "agent",
    "agents.smoke": "agent",
    "agents.protocol": "agent",
}

#: The consumer verbs' handlers in `bench/cli.py` -- `docker-authority
#: inspect`, `bundle fetch`, `doctor`, `environment up`, `worker provision`,
#: `tasks`, `run` (the submitted adapter) and `results` -- plus what every
#: verb runs through: `main` and `dispatch`, and each component's
#: `register`, which builds that component's parsers for every command line.
CONSUMER_HANDLERS = (
    "main", "dispatch", "register", "cmd_docker_authority", "cmd_bundle",
    "cmd_doctor", "cmd_environment", "cmd_worker", "cmd_tasks", "cmd_run",
    "cmd_results",
)

#: Every (importing module, agent module) edge the consumer closure crosses
#: today, with the plan item that removes it -- or the plain statement that
#: the plan's R7 inventory did not list it, which is a finding, not a
#: citation.  Asserted exactly by `selftest()`: a cut edge must leave this
#: table (a stale row is refused by name), and an edge not listed here
#: fails.  Every row is a function-local import -- fact (a) holds -- so the
#: closure is what the verbs COULD import; the mirror's own check is what
#: they DO.
I3 = ("I3: result_ledger.py is flat-staged into every backend tree, so its "
      "agent-verification half moves with the ledger split")
KNOWN_CONSUMER_ROUTE_LEAKS = {
    ("bench.result_ledger", "agents.registry"):
        I3 + " (`_verify_run_plan`, agent rows only)",
    ("bench.result_ledger", "confined.result_ledger_v2"):
        I3 + " (the agent-verification half; `_load_ledger_document` "
        "already asks for the reader only when a document needs it)",
    # Not a cut the plan owes: `--publication-v3` is an option of the
    # bench `run` parser (`report`, `results`, `compare` and `merge` read
    # the same ledger without the agent component), so its agent branch
    # lives in the consumer handler `cmd_run` and in `main`'s Slice-3
    # prepare seam.  Both import the moved launcher only after
    # `is_agent_publication_request` found the agent producer on disk; a
    # fixture publication and every consumer verb never execute the line.
    ("bench.cli", "agents.publication"):
        "O2: `run --publication-v3 --adapter AGENT` is dispatched by the "
        "bench `run` handler; the branch is entered only when the agent "
        "producer is present",
}

#: Every (data module, non-data non-core module) edge a `data` module's own
#: code crosses INSIDE a function -- fact (c) is module-level, so these are
#: legal and invisible to it, and an unrecorded one is how "data imports
#: only core" stops being true without anything going red.  Asserted
#: exactly, like KNOWN_CONSUMER_ROUTE_LEAKS: a cut edge must leave the
#: table, a new one fails.  `selftest` bodies are outside it, as they are
#: outside every fact: a `core + data` checkout imports the data modules and
#: cannot self-test them.
KNOWN_DATA_ROUTE_EDGES = {
    ("data.evaluation_bundle", "go.assertion_strip"):
        "Coddy installation binds the preserved native assertion planner source",
    ("data.evaluation_bundle", "go.controls"):
        "Coddy installation binds the preserved native declaration planner source",
    ("data.evaluation_bundle", "go.control_adapter"):
        "Coddy installation admits the exact saved native plan member set",
    ("data.evaluation_bundle", "go.mutation_runtime"):
        "Coddy installation shares the live original attribution/source/image contract",
    ("data.evaluation_bundle", "go.prod_index"):
        "Coddy installation reports preserved index/attribution join refusals",
    ("data.evaluation_bundle", "toolkit.strip"):
        "Coddy installation reads the original native closures for saved plan membership",
    ("data.evaluation_bundle", "bench.seed"):
        "evaluation installation authenticates the unchanged seed format and nested workspace",
    ("data.evaluation_bundle", "bench.evaluation_reference"):
        "evaluation installation rederives the three preserved reference controls and sources",
    ("data.evaluation_bundle", "toolkit.algorand_bundle"):
        "Algorand V8 retains its project-owned Java source, OCI and direct-call validation",
    ("data.release", "bench.mutation_run"):
        "`_known_engines`: the engines a release may CLAIM and the engines a "
        "campaign can EXECUTE are one table by construction "
        "(`mutation_run.engines`); a copy here would be the two-list drift "
        "the join exists to prevent",
    ("data.bundle", "toolkit.algorand_bundle"):
        "the native Algorand bundle's own fetch and validate; splitting a "
        "reader half out of that module is its own change",
    ("data.bundle", "bench.repo"):
        "PrestaShop bundle validation reads its recorded strip manifest "
        "before verifying the protected native resource snapshot",
    ("data.bundle", "bench.prestashop_resources"):
        "PrestaShop-only bundle installation reuses verify_inputs for the "
        "existing native resource kinds, modes and digests",
    ("data.bundle", "bench.seed"):
        "`validate_installed_bundle` runs `verify_seed` over the installed "
        "pair; `seed` imports `campaign` and `repo` at module level",
    ("data.bundle", "bench.worker"):
        "`validate_installed_bundle` runs `plan_workers` over the installed "
        "pool",
    ("data.bundle", "bench.metrics"):
        "the optional scoring-gold role reuses the scorer's gold self-check "
        "and production-coverage projection without changing historical "
        "mutation or std-arm evidence",
    ("data.mutation_attestation", "toolkit.mutation_go"):
        "Go-only shared artifact validation checks recorded compiler contexts with the Go validator",
    ("data.mutation_attestation", "java.kapua_gold_coverage"):
        "Kapua census map consumers rederive the projected gold oracle from its full approved receipt and actual annotated census",
    ("data.mutation_attestation", "toolkit.mutation_java"):
        "`validate_manifest`: the Java analysis-recipe authority, reached "
        "only on the Java engine's branch",
    ("data.mutation_attestation", "bench.mutation_run"):
        "`binding_for`: the engine directory and applier identity, the same "
        "one-table argument as `_known_engines`",
    ("data.mutation_attestation", "bench.egress_attestation"):
        "`validate_saved_validation_report` validates the saved candidate "
        "egress attestation",
    ("data.mutation_attestation", "bench.repo"):
        "`derive_boundary_scored_manifest`: the boundary's own "
        "`behat.mutation_exclude` fragments and `behat.prod_paths` roots, "
        "read through the ONE accessor of that block (`behat_project`, "
        "closed keys and per-row refusals). A second reader here would be "
        "the copy that accessor exists to prevent, and the row has to come "
        "off the boundary because every consumer re-derives the scored "
        "population from the raw manifest plus the boundary bytes",
    ("data.subsets", "java.kapua_pilot"):
        "Authenticate the fixed Kapua pilot companion and its descriptive selection before stamping",
    ("data.subsets", "bench.metrics"):
        "`headroom_subset` reads the six runs through `read_runs`, whose "
        "last-row-wins rule is what makes a re-run item one observation",
    ("data.subsets", "bench.results"):
        "`headroom_subset` is DEFINED by `production_coverage`'s `covering` "
        "bucket (HEADROOM_SUBSET_AND_BUDGETED_SAMPLE_SPEC.md section 1); a "
        "copy here would be the second definition of 'vacuous pass' the "
        "diagnostic exists to prevent",
}


# --- the files ------------------------------------------------------------

def package_files() -> tuple:
    """Every `.py` under the package, as `/`-joined package-relative paths.

    Recursive, `__pycache__` skipped, sorted -- the one walk both this
    module's completeness check and `versions`' ownership completeness use,
    so the two cannot disagree about which files exist.
    """
    found = []
    for dirpath, dirnames, filenames in os.walk(PACKAGE_DIR):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for name in filenames:
            if name.endswith(".py"):
                rel = os.path.relpath(os.path.join(dirpath, name), PACKAGE_DIR)
                found.append(rel.replace(os.sep, "/"))
    return tuple(sorted(found))


def module_name(relpath: str) -> str:
    """`agents/scanners/__init__.py` -> `agents.scanners`; `cli.py` -> `cli`."""
    parts = relpath[:-len(".py")].split("/")
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or ROOT


def modules_on_disk() -> dict:
    """Module name -> absolute path, for every file the table must cover."""
    return {module_name(rel): os.path.join(PACKAGE_DIR, rel)
            for rel in package_files()}


def agent_driver_modules() -> tuple:
    """Every agent DRIVER module on disk, in `MODULES` spelling and sorted.

    A driver is the script that RUNS one agent, and it is `agent` by
    construction: `agents.backends.AgentBackend.driver` names one per arm,
    and it is the only file a new arm adds under this package.  Listed in
    `COMPONENT` and in `selftest.MODULES`, that is two registry lines a
    third arm has to remember and one silent way to lose it -- a driver
    filed nowhere is a module the boundary walk refuses and a self-test the
    battery never runs.

    Read off the FILES rather than off `AGENT_BACKENDS`, for the reason this
    module exists: `core` may not import the `agent` component at module
    level (fact (a)), and the table is built at import time.  The two say
    the same thing -- a record's `driver` IS the module the walk finds --
    and the disk is the half `core` is allowed to ask.
    """
    return tuple(m for m in modules_on_disk()
                 if m.rpartition(".")[2].endswith("_driver"))


COMPONENT.update({module: "agent" for module in agent_driver_modules()})


def check_table() -> dict:
    """Refuse a module on disk with no row, or a row naming no component.

    A row whose file is absent is tolerated on purpose: that is the
    benchmark-only mirror, where the `agent` files do not exist and the table
    still has to say what they were.
    """
    bad = sorted(m for m, c in COMPONENT.items() if c not in COMPONENTS)
    if bad:
        raise SystemExit(
            f"REFUSED: {len(bad)} table row(s) name no component: "
            + ", ".join(f"{m}={COMPONENT[m]!r}" for m in bad)
            + f". Choose from {', '.join(COMPONENTS)}.")
    on_disk = modules_on_disk()
    missing = sorted(m for m in on_disk if m not in COMPONENT)
    if missing:
        raise SystemExit(
            f"REFUSED: {len(missing)} module(s) on disk have no row in "
            f"`components.COMPONENT`: {', '.join(missing)}. Add each as "
            f"core, data, bench, toolkit or agent.")
    return on_disk


def component_modules(component: str) -> tuple:
    """`selftest.MODULES` filtered to one component, in `MODULES` order.

    Order is taken from `MODULES`, never from the table, so a component run
    reads in the same sequence the full battery does.  A non-core component
    includes core: nothing runs without it, and a core regression should
    fail the component that depends on it, not only a separate core run.
    """
    from ..selftest import MODULES  # lazily: `selftest` imports this module
    check_table()
    unfiled = [m for m in MODULES if m not in COMPONENT]
    if unfiled:
        raise SystemExit(
            f"REFUSED: {len(unfiled)} registered module(s) belong to no "
            f"component: {', '.join(unfiled)}. Add each to "
            f"`components.COMPONENT`.")
    if component == "all":
        return MODULES
    if component not in COMPONENTS:
        raise SystemExit(
            f"REFUSED: unknown component {component!r}; choose from "
            f"{', '.join(COMPONENTS)} or all")
    wanted = {component, "core"}
    return tuple(m for m in MODULES if COMPONENT[m] in wanted)


def component_present(component: str) -> bool:
    """Does this checkout ship `component`?

    The distribution the mirror check builds omits the agent component, so a
    self-test whose subject only exists there prints `[SKIP]` and returns
    green instead of failing on a missing import.
    """
    if component not in COMPONENTS:
        raise SystemExit(
            f"REFUSED: unknown component {component!r}; choose from "
            f"{', '.join(COMPONENTS)}")
    return any(COMPONENT.get(module) == component
               for module in modules_on_disk())


# --- the import graph -----------------------------------------------------

#: One import statement.
Edge = namedtuple("Edge", "importer lineno imported module_level")


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    """Would this handler catch an ImportError?  A bare `except:` and
    `except Exception:` do, and are how `runner.py:553` guards `protocol`."""
    kind = handler.type
    if kind is None:
        return True
    names = (kind.elts if isinstance(kind, ast.Tuple) else [kind])
    return any(isinstance(n, ast.Name)
               and n.id in ("ImportError", "ModuleNotFoundError",
                            "Exception", "BaseException")
               for n in names)


def _targets(module: str, is_package: bool, node) -> list:
    """The r2t modules one Import/ImportFrom names, by the table's spelling.

    `from .pkg import name` names `pkg.name` when that is a module in the
    table and `pkg` otherwise (`name` is then a symbol of `pkg`).  Names
    outside r2t resolve to nothing.
    """
    def inside(parts):
        return [".".join(parts)] if ".".join(parts) in COMPONENT else []

    if isinstance(node, ast.Import):
        out = []
        for alias in node.names:
            parts = alias.name.split(".")
            if parts[0] == "r2t":
                out += inside(parts[1:]) if parts[1:] else [ROOT]
        return out
    base: Optional[list] = None
    if node.level:
        here = [] if module == ROOT else module.split(".")
        pkg = here if is_package else here[:-1]
        pkg = pkg[:len(pkg) - (node.level - 1)] if node.level > 1 else pkg
        base = pkg + (node.module.split(".") if node.module else [])
    elif node.module and node.module.split(".")[0] == "r2t":
        base = node.module.split(".")[1:]
    if base is None:
        return []
    out = []
    for alias in node.names:
        out += inside(base + [alias.name]) or inside(base) or (
            [ROOT] if not base else [])
    return out


def _edges_of(module: str, path: str, tree: ast.AST,
              functions: Optional[Iterable[str]] = None) -> list:
    """Every unguarded r2t import in one parsed module, as `Edge`s.

    With `functions`, function-local imports are kept only inside the named
    top-level functions (nested closures included); without it, inside every
    top-level function except `selftest`, which no verb runs.  Module-level
    imports are always kept.  Guarded means inside the `try:` body of a
    statement whose handlers would catch an `ImportError`.
    """
    is_package = os.path.basename(path) == "__init__.py" or module == ROOT
    only = None if functions is None else set(functions)
    edges: list = []

    def visit(node, in_function: bool, wanted: bool, guarded: bool):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if guarded or (in_function and not wanted):
                return
            for target in dict.fromkeys(_targets(module, is_package, node)):
                edges.append(Edge(module, node.lineno, target,
                                  not in_function))
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not in_function:
                wanted = (node.name != "selftest" if only is None
                          else node.name in only)
            in_function = True
        if isinstance(node, ast.Try):
            body_guarded = guarded or any(
                _catches_import_error(h) for h in node.handlers)
            for child in node.body:
                visit(child, in_function, wanted, body_guarded)
            for child in node.handlers + node.orelse + node.finalbody:
                visit(child, in_function, wanted, guarded)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, in_function, wanted, guarded)

    visit(tree, False, True, False)
    return edges


def import_edges() -> dict:
    """Module -> its `Edge`s, for every module on disk: the parsed graph."""
    graph = {}
    for module, path in sorted(modules_on_disk().items()):
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), path)
        graph[module] = _edges_of(module, path, tree)
    return graph


def direction_violations(edges: Iterable[Edge]) -> list:
    """Fact (a) over an edge set: module-level imports INTO `agent` from
    outside it, each as (importer, lineno, imported, from_component)."""
    found = []
    for edge in edges:
        if not edge.module_level:
            continue
        source = COMPONENT.get(edge.importer)
        if source != "agent" and COMPONENT.get(edge.imported) == "agent":
            found.append((edge.importer, edge.lineno, edge.imported, source))
    return sorted(found)


def data_direction_violations(edges: Iterable[Edge]) -> list:
    """Fact (c) over an edge set: module-level imports FROM a `data` module
    into `bench`, `toolkit` or `agent`, each as
    (importer, lineno, imported, to_component)."""
    found = []
    for edge in edges:
        if not edge.module_level:
            continue
        target = COMPONENT.get(edge.imported)
        if COMPONENT.get(edge.importer) == "data" \
                and target in ("bench", "toolkit", "agent"):
            found.append((edge.importer, edge.lineno, edge.imported, target))
    return sorted(found)


def data_route_edges(graph: dict) -> dict:
    """The function-local edges out of `data` (`selftest` bodies excluded,
    as `import_edges` drops them): `(data module, imported) -> [lineno]`
    for every import whose target is neither `data` nor `core`."""
    out: dict = {}
    for module, edges in graph.items():
        if COMPONENT.get(module) != "data":
            continue
        for edge in edges:
            if not edge.module_level \
                    and COMPONENT.get(edge.imported) not in ("data", "core"):
                out.setdefault((module, edge.imported), []).append(
                    edge.lineno)
    return out


def consumer_closure(graph: dict, seeds: Iterable[str]) -> tuple:
    """Fact (b): (reached modules, agent edges) from `seeds` over `graph`.

    Follows every edge of every non-`agent` module reached; an `agent`
    module is recorded as reached, with the edge that reached it, and not
    expanded (what an agent module imports is the agent's own business).
    """
    reached = set()
    leaks: dict = {}
    frontier = list(seeds)
    while frontier:
        module = frontier.pop()
        if module in reached:
            continue
        reached.add(module)
        if COMPONENT.get(module) == "agent":
            continue
        for edge in graph.get(module, ()):
            if COMPONENT.get(edge.imported) == "agent":
                leaks.setdefault((module, edge.imported), []).append(
                    edge.lineno)
            if edge.imported not in reached:
                frontier.append(edge.imported)
    return reached, leaks


def consumer_functions(tree: ast.AST) -> set:
    """The top-level `cli` functions a consumer verb can run: the handlers
    and, transitively, every top-level function one of them names -- an
    argparse `type=`, a `default=` computed while `main` builds the parser,
    a helper called from the body.  The other `cmd_*` handlers are not
    followed: `main` names every one of them when it wires the parser, and
    only the verb typed on the command line runs."""
    defs = {node.name: node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    wanted: set = set()
    frontier = list(CONSUMER_HANDLERS)
    while frontier:
        name = frontier.pop()
        if name in wanted or name not in defs:
            continue
        wanted.add(name)
        for node in ast.walk(defs[name]):
            if (isinstance(node, ast.Name) and node.id in defs
                    and (not node.id.startswith("cmd_")
                         or node.id in CONSUMER_HANDLERS)):
                frontier.append(node.id)
    return wanted


#: The `cli` modules the composer (`cli.py`) imports unguarded, narrowed by
#: `consumer_seeds`; `agents.cli` is imported under `except ImportError`
#: and so is outside fact (b) by definition.
CONSUMER_CLI_MODULES = ("bench.cli", "toolkit.cli")


def consumer_seeds(graph: dict) -> tuple:
    """`graph` with each `CONSUMER_CLI_MODULES` entry narrowed to what the
    consumer verbs can import: the handlers' own imports and those of the
    functions they reach (`consumer_functions`).  Returns (graph, the
    functions kept, as `module.function`)."""
    graph = dict(graph)
    kept = set()
    for module in CONSUMER_CLI_MODULES:
        path = os.path.join(PACKAGE_DIR, *module.split(".")) + ".py"
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), path)
        functions = consumer_functions(tree)
        graph[module] = _edges_of(module, path, tree, functions=functions)
        kept.update(f"{module}.{name}" for name in functions)
    return graph, kept


# --- the change map -------------------------------------------------------

#: Every path below is repo-relative, the way `git diff --name-only` prints
#: it, and the package's own files are recognised by these two prefixes.
PACKAGE_PATH = "benchmark/r2t/"

#: What a NON-package path changes, as `(path globs, module globs, why)`.
#: The first matching rule wins; `()` selects nothing and `("*",)` selects
#: every registered module.  A path no rule matches, and that is not a
#: package `.py`, selects everything, so an unclassified file always runs the
#: full battery and never the empty set.
#:
#: A row that names a few modules is a claim that those are ALL the modules
#: reading those bytes, and a wrong one is a hole in the gate.  So a row
#: survives here only if its readers were enumerated in the source; where
#: they were not, the row is gone and the path takes the fallback.  What was
#: enumerated, and what it cost:
#:
#: * `benchmark/config/*` -- REMOVED (`pricing.py:76`,
#:   `result_ledger_v2_selftest.py:56`, `harness.py:1610`, `adapters.py:2490`,
#:   `mutation_run.py:6869`, `bundle.py:1339` read it).
#: * `benchmark/release/*` -- kept ONLY to beat the prose glob below, and it
#:   now selects everything: `test_quality`, `mutation_attestation`,
#:   `algorand_bundle`, `campaign_table`, `result_ledger`, `report`, `draws`,
#:   `java/release_validation`, `live_test_quality`, `docx_v2_workload` and
#:   more resolve paths under `release/`, and the old seven-module row named
#:   none of them.  `release/v1/legacy_table_eval100_std.md` is a released
#:   input digested at `release/dataset_manifest.json:356` and pinned at
#:   `bundle.py:164`, so released bytes are released bytes whatever the
#:   extension and must not fall to prose.
#: * `benchmark/VERSIONS.yml` -- REMOVED.  `versions` is not its only reader:
#:   `evaluation_execution_v3_attempt_selftest.py:368` reads
#:   `versions.DEFAULT_MANIFEST_PATH`, and `mutation_attestation.py:2529`,
#:   `report.py:308` and `subsets.py:522` read the same pins.
#: * `benchmark/protocol/*` -- REMOVED.  `versions.py:690` checks the
#:   protocol file the manifest names and `algorand_bundle.py:1416`, `:2902`
#:   read `protocol/protocol_v8.yml`.
#: * `benchmark/schemas/*` -- REMOVED.  `result_ledger.py:62`/`:269` loads
#:   these files for every caller that validates a ledger document, so the
#:   reader set is the ledger's callers and not a directory listing.
#: * `benchmark/docker/*` -- REMOVED.  The old row named `environment*` and
#:   `images`, but `provision_coreshop.py:41` resolves
#:   `docker/coreshop/{Dockerfile,composer.lock,pimcore-license-gates.patch}`
#:   and `epubcheck_image_selftest.py:1844` reads
#:   `docker/epubcheck/offline-settings.xml` out of the worktree.
#: * `.github/*` -- deliberately unmapped: a workflow change is exactly when
#:   the whole battery should run once.
#: * `benchmark/r2t/*` (a non-`.py` file under the package) -- selects
#:   everything, ahead of the prose glob: `java/fixtures/PROVENANCE.md` is
#:   opened out of the worktree and asserted on by `java.closure_java`
#:   (`closure_java.py:1844`), and every other file under the package is a
#:   fixture by construction.  A `.py` never reaches this row: it is mapped
#:   to its module first.
#: * `benchmark/docs/` is NOT a prose glob, because
#:   `docs/aider_env_freeze.txt` and `docs/openhands_env_freeze.txt` are the
#:   adapters' `requirements_lock` (`agents/backends.py`); the `.md`
#:   files under it are still prose through the `*.md` glob.
#: The two package modules that go through the map rather than through their
#: component: a change to either redefines what every run is.
RUN_DEFINING = (PACKAGE_PATH + "selftest.py",
                PACKAGE_PATH + "core/components.py")

CHANGE_MAP = (
    (("benchmark/release/*",), ("*",),
     "released bytes, whose readers are not a directory listing"),
    ((PACKAGE_PATH + "*",), ("*",),
     "a non-module file under the package is a fixture some self-test reads"),
    (("*.md", "docs/*", "benchmark/runbooks/*"), (),
     "prose no command, schema, fixture or generated input reads"),
    (("experiments/*/paper-cells/*.json", "experiments/paper-results/*"), (),
     "paper-table cells and their builder: only experiments/paper-results/"
     "build_tables.py reads them, no registered module imports it, and its "
     "own unittest (test_build_tables) is their gate"),
    (("req2test/*", "tests/*", "pyproject.toml"), (),
     "the req2test front end, its tests and its package file: no registered "
     "module imports them, and python -m pytest tests is their gate"),
    (("benchmark/scripts/*", "benchmark/requirements*") + RUN_DEFINING,
     ("*",),
     "the runner, this table and the pinned inputs define what a run IS"),
)

#: `subject -> callers reached through function-local imports`.
#: The import may be in the caller's production path or its selftest body.
#: For a library with no registered selftest, its registered module-level
#: importers exercise that caller (population's tests live in report/results).
#: The rule below already runs the changed module's whole component and one
#: hop over module-level imports, so a row earns its place only when it is
#: BOTH cross-component and invisible to an AST walk of the module body.
#: One row is: `agents.scanners` is bench, `smoke` is agent, and
#: `smoke.py:474` imports it inside `selftest()` (`_edges_of` drops
#: `selftest` bodies on purpose, because no verb runs a `selftest`;
#: `smoke.py:183` is a second function-local import of it, in a helper).
#: `selftest()` refuses a row naming an import that is not in the source any
#: more.
KNOWN_TEST_EDGES = {
    "go.mutation_runtime": ("data.evaluation_bundle", "toolkit.evaluation_bundle_selftest"),
    "go.prod_index": ("data.evaluation_bundle",),
    "go.interfaces_attribution": ("bench.evaluation_reference_selftest",),
    "toolkit.subset_writer": ("data.step_definition_census",),
    "agents.scanners": ("agents.smoke",),
    #: `harvest.py:892` imports the CoreShop profile inside `selftest()` to
    #: assert the profile's harvest filter still equals `harvest`'s own
    #: default.  The claim is about `data.profile`, so a change to that file
    #: has to run `agents.harvest`; it lives there because `data.profile`'s
    #: self-test may not import an agent module.
    "data.profile": ("agents.harvest",),
    "java.kapua_headroom": ("bench.cli", "bench.population", "bench.test_quality"),
    "java.kapua_reference": ("bench.cli", "bench.test_quality"),
    "java.kapua_gold_coverage": ("data.mutation_attestation",),
    "bench.population": ("ruby.evaluation_selection", "data.sylius_selection", "java.kapua_census"),
    "bench.cli": ("data.step_definition_census", "ruby.evaluation_selection", "java.kapua_census"),
}


def change_rule(path: str) -> Optional[tuple]:
    """The first `CHANGE_MAP` row whose path globs match `path`, or None."""
    return next((r for r in CHANGE_MAP
                 if any(fnmatch.fnmatchcase(path, g) for g in r[0])), None)


def package_module(path: str) -> Optional[str]:
    """`benchmark/r2t/py/mutate.py` -> `py.mutate`; anything else -> None."""
    if path.startswith(PACKAGE_PATH) and path.endswith(".py"):
        return module_name(path[len(PACKAGE_PATH):])
    return None


def _expand(globs: Iterable[str], registered: Iterable[str]) -> list:
    """The registered modules a rule's module globs name, in `MODULES` order."""
    return [m for m in registered
            if any(fnmatch.fnmatchcase(m, g) for g in globs)]


def selftest_edges(module: str) -> list:
    """Every r2t import inside one module's `selftest()`: the edges
    `import_edges` drops on purpose, which `KNOWN_TEST_EDGES` records.
    Empty for a module whose file is absent (the mirror case), as
    `check_table` tolerates a row without a file."""
    path = modules_on_disk().get(module)
    if path is None:
        return []
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)
    return _edges_of(module, path, tree, functions=("selftest",))


def _known_test_edge_imports(graph: dict, subject: str, caller: str) -> tuple:
    """Require the declared local dependency to exist in the actual caller."""
    local = sorted({edge.lineno for edge in selftest_edges(caller)
                    if edge.imported == subject}
                   | {edge.lineno for edge in graph[caller]
                      if edge.imported == subject and not edge.module_level})
    top = [edge.lineno for edge in graph[caller]
           if edge.imported == subject and edge.module_level]
    if not (local or top):
        raise SystemExit(f"{caller}.py imports {subject} nowhere any more")
    return local, top


def _module_selection(graph: dict, module: str, registered: tuple) -> dict:
    """One changed package module -> {module to run: why}.

    The module's WHOLE COMPONENT (`core` included, as `component_modules`
    defines it), plus one hop over module-level reverse imports for the
    modules outside that component which import it, plus the function-local
    edges `KNOWN_TEST_EDGES` records.  The component is the unit because it
    is the unit the boundary is drawn around: a module's neighbours share its
    invariants whether or not they import it, and only the whole-component
    reading makes "the affected components" a true description of what the
    gate ran.
    """
    component = COMPONENT[module]
    out: dict = {name: f"is in component {component}, which r2t.{module} is in"
                 for name in component_modules(component)}
    if module in registered:
        out[module] = f"is r2t.{module}"
    for importer in registered:
        if importer != module and any(
                edge.module_level and edge.imported == module
                for edge in graph.get(importer, ())):
            out.setdefault(importer, f"imports r2t.{module} at module level")
    for name in KNOWN_TEST_EDGES.get(module, ()):
        if name in registered:
            out.setdefault(name, f"imports r2t.{module} inside a function "
                                 f"(KNOWN_TEST_EDGES)")
        elif name in graph:
            for importer in registered:
                if any(edge.module_level and edge.imported == name
                       for edge in graph.get(importer, ())):
                    out.setdefault(importer, f"tests r2t.{name}, whose function-local import "
                                             f"of r2t.{module} is in KNOWN_TEST_EDGES")
    return out


def changed_selection(paths: Iterable[str], graph: Optional[dict] = None) \
        -> dict:
    """Changed repo-relative paths -> {module to run: why}, `MODULES`-ordered.

    A package module (other than the two in `RUN_DEFINING`) selects by
    component and import; every other path goes through `CHANGE_MAP`, and a
    path no row names selects everything.  Empty exactly when every changed
    path matched a row that selects nothing (prose, the paper tables, the
    req2test front end).  The reason kept for a module is the first
    path that selected it.  `graph` is the import graph to walk; the default
    parses it, once, and only if a package `.py` is among the paths.
    """
    from ..selftest import MODULES  # lazily: `selftest` imports this module
    check_table()
    reasons: dict = {}
    for path in sorted(set(paths)):
        module = package_module(path)
        if module is not None and path not in RUN_DEFINING:
            if module not in COMPONENT:
                for name in MODULES:
                    reasons.setdefault(
                        name, f"{path}: r2t.{module} has no row in the "
                              f"component table (deleted or renamed)")
                continue
            if graph is None:
                graph = import_edges()
            for name, why in _module_selection(
                    graph, module, MODULES).items():
                reasons.setdefault(name, f"{path}: {why}")
            continue
        rule = change_rule(path)
        if rule is not None:
            for name in _expand(rule[1], MODULES):
                reasons.setdefault(name, f"{path}: {rule[2]}")
            continue
        for name in MODULES:
            reasons.setdefault(name, f"{path}: no rule maps this path")
    return {m: reasons[m] for m in MODULES if m in reasons}


# --- the check ------------------------------------------------------------

def selftest() -> int:
    failures = []

    def check(name, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + ("" if cond else f" -- {detail}"))
        if not cond:
            failures.append(name)

    def refuses(name, fn, *needles):
        try:
            fn()
        except SystemExit as exc:
            text = str(exc)
            missing = [n for n in needles if n not in text]
            check(name, not missing, f"message lacks {missing}: {text}")
        else:
            check(name, False, "did not refuse")

    # The table itself.
    on_disk = check_table()
    counts = {c: sum(1 for v in COMPONENT.values() if v == c)
              for c in COMPONENTS}
    absent = sorted(m for m in COMPONENT if m not in on_disk)
    print(f"  table: {len(COMPONENT)} rows "
          + ", ".join(f"{c}={n}" for c, n in counts.items())
          + f"; on disk {len(on_disk)}; rows without a file: "
          + (", ".join(absent) if absent else "none"))
    check("every module on disk has one row and every row names a component",
          all(m in COMPONENT for m in on_disk)
          and set(COMPONENT.values()) <= set(COMPONENTS))
    check("the root package and the sub-packages are rows",
          all(m in COMPONENT for m in (ROOT, "data", "agents", "py", "java",
                                       "stacks", "agents.scanners")))
    from ..selftest import MODULES
    for component in COMPONENTS:
        members = component_modules(component)
        check(f"component_modules({component!r}) is MODULES-ordered and "
              f"includes core",
              members == tuple(m for m in MODULES if m in set(members))
              and all(COMPONENT[m] in (component, "core") for m in members)
              and all(m in members for m in MODULES
                      if COMPONENT[m] == "core"),
              str(members))
    check("component_modules('all') is MODULES",
          component_modules("all") == MODULES)
    refuses("an unknown component is refused by name",
            lambda: component_modules("harness"), "'harness'",
            "core, data, bench")
    saved = dict(COMPONENT)
    try:
        del COMPONENT["core.boundary"]
        refuses("a module on disk with no row is refused by name",
                lambda: component_modules("core"), "core.boundary", "no row")
        COMPONENT.update(saved)
        COMPONENT["core.boundary"] = "shared"
        refuses("a row naming no component is refused by name",
                lambda: component_modules("core"), "boundary='shared'")
        COMPONENT.update(saved)
        COMPONENT["agents.acme_driver"] = "agent"
        check("a row whose file is absent is tolerated (the mirror case)",
              component_modules("agent") == tuple(
                  m for m in MODULES if saved[m] in ("agent", "core")))
        COMPONENT.update(saved)
        check("component_present sees the four components every checkout "
              "ships (the mirror drops only `agent`)",
              all(component_present(name)
                  for name in ("core", "data", "bench", "toolkit")))
        for name in [m for m, c in saved.items() if c == "agent"]:
            COMPONENT.pop(name, None)
        check("component_present is False when no file on disk is filed "
              "agent -- the mirror case the `[SKIP]` guards read",
              not component_present("agent")
              and component_present("toolkit"))
        COMPONENT.update(saved)
        refuses("component_present refuses an unknown component by name",
                lambda: component_present("harness"), "'harness'", "core")
    finally:
        COMPONENT.clear()
        COMPONENT.update(saved)

    # The graph: walked and parsed once, cost printed.
    started = time.perf_counter()
    graph = import_edges()
    parsed_seconds = time.perf_counter() - started
    edge_count = sum(len(v) for v in graph.values())
    print(f"  measured: walk + ast.parse of {len(graph)} modules, "
          f"{edge_count} r2t import edges, {parsed_seconds:.2f}s")

    # Fact (a).
    violations = direction_violations(
        e for edges in graph.values() for e in edges)
    check("(a) no module outside `agent` imports an `agent` module at "
          "module level",
          not violations,
          "; ".join(f"{m}.py:{line} ({c}) imports {t} (agent)"
                    for m, line, t, c in violations))
    synthetic = [Edge("bench.results", 7, "agents.trials", True),
                 Edge("bench.results", 8, "agents.trials", False),
                 Edge("agents.smoke", 9, "agents.trials", True),
                 Edge("toolkit.closure", 10, "bench.results", True)]
    check("(a) a synthetic module-level bench->agent edge is refused naming "
          "both modules and both components, and a function-local, an "
          "agent->agent and a toolkit->bench edge are not",
          direction_violations(synthetic)
          == [("bench.results", 7, "agents.trials", "bench")])
    refused_text = "; ".join(
        f"{m}.py:{line} ({c}) imports {t} ({COMPONENT[t]})"
        for m, line, t, c in direction_violations(synthetic))
    check("(a) the refusal text names importer, imported and both components",
          refused_text
          == "bench.results.py:7 (bench) imports agents.trials (agent)",
          refused_text)

    # Fact (c).
    data_violations = data_direction_violations(
        e for edges in graph.values() for e in edges)
    check("(c) no `data` module imports a `bench`, `toolkit` or `agent` "
          "module at module level",
          not data_violations,
          "; ".join(f"{m}.py:{line} (data) imports {t} ({c})"
                    for m, line, t, c in data_violations))
    synthetic_data = [Edge("data.release", 7, "bench.adapters", True),
                      Edge("data.release", 8, "bench.adapters", False),
                      Edge("data.release", 9, "core.paths", True),
                      Edge("bench.results", 10, "data.release", True)]
    check("(c) a synthetic module-level data->bench edge is refused naming "
          "both modules and both components, and a function-local, a "
          "data->core and a bench->data edge are not",
          data_direction_violations(synthetic_data)
          == [("data.release", 7, "bench.adapters", "bench")])
    routes = data_route_edges(graph)
    stale_routes = sorted(set(KNOWN_DATA_ROUTE_EDGES) - set(routes))
    new_routes = sorted(set(routes) - set(KNOWN_DATA_ROUTE_EDGES))
    check("(c) every function-local edge out of `data` is a "
          "KNOWN_DATA_ROUTE_EDGES row",
          not new_routes,
          "new edge(s): " + "; ".join(
              f"{m}.py:{','.join(map(str, routes[m, t]))} (data) imports "
              f"{t} ({COMPONENT[t]})" for m, t in new_routes))
    check("(c) every KNOWN_DATA_ROUTE_EDGES row is still an edge -- a cut "
          "edge leaves the table",
          not stale_routes,
          "stale row(s): " + "; ".join(f"{m} -> {t}" for m, t in stale_routes))
    for (m, t), lines in sorted(routes.items()):
        print(f"    {m}.py:{','.join(map(str, lines))} -> {t}: "
              f"{KNOWN_DATA_ROUTE_EDGES.get((m, t), '?')}")

    # Fact (b).
    seeded, functions = consumer_seeds(graph)
    reached, leaks = consumer_closure(seeded, ["cli", "bench.cli"])
    agent_reached = sorted(m for m in reached if COMPONENT.get(m) == "agent")
    print(f"  measured: the consumer verbs reach {len(functions)} top-level "
          f"cli functions; their closure reaches {len(reached)} of "
          f"{len(graph)} modules, {len(agent_reached)} of them agent, "
          f"through {len(leaks)} edge(s) from "
          f"{len({m for m, _ in leaks})} non-agent module(s)")
    stale = sorted(set(KNOWN_CONSUMER_ROUTE_LEAKS) - set(leaks))
    new = sorted(set(leaks) - set(KNOWN_CONSUMER_ROUTE_LEAKS))
    check("(b) every consumer-closure edge into `agent` is a "
          "KNOWN_CONSUMER_ROUTE_LEAKS row",
          not new,
          "new edge(s): " + "; ".join(
              f"{m}.py:{','.join(map(str, leaks[m, t]))} ({COMPONENT[m]}) "
              f"imports {t} (agent)" for m, t in new))
    check("(b) every KNOWN_CONSUMER_ROUTE_LEAKS row is still an edge -- a "
          "cut edge leaves the table",
          not stale,
          "stale row(s): " + "; ".join(f"{m} -> {t}" for m, t in stale))
    for (m, t), lines in sorted(leaks.items()):
        print(f"    {m}.py:{','.join(map(str, lines))} -> {t}: "
              f"{KNOWN_CONSUMER_ROUTE_LEAKS.get((m, t), '?')}")
    forged = dict(seeded)
    forged["bench.results"] = list(seeded["bench.results"]) + [
        Edge("bench.results", 1, "confined.pricing", False)]
    _, forged_leaks = consumer_closure(forged, ["cli", "bench.cli"])
    check("(b) a synthetic results->pricing edge on the route is a new "
          "edge, named",
          ("bench.results", "confined.pricing") in forged_leaks
          and ("bench.results", "confined.pricing") not in KNOWN_CONSUMER_ROUTE_LEAKS
          and forged_leaks[("bench.results", "confined.pricing")] == [1])
    check("`selftest` (toolkit) imports only the table it selects from and "
          "spawns every module it runs, so no module it runs is an edge",
          [(e.imported, e.module_level) for e in graph["selftest"]]
          == [("core.components", True)], str(graph["selftest"]))
    guarded = _edges_of("bench.results", "results.py", ast.parse(
        "try:\n    from ..agents.trials import parse_trials\n"
        "except ImportError:\n"
        "    pass\ntry:\n    from .. import pricing\nexcept Exception:\n"
        "    pass\nfrom ..agents import protocol\n"))
    check("an import inside `try/except ImportError` (or a handler that "
          "would catch one) is not an edge; an unguarded one beside it is",
          [(e.imported, e.lineno) for e in guarded] == [("agents.protocol", 9)],
          str(guarded))

    # The change map.
    empty_globs = sorted(g for _, globs, _ in CHANGE_MAP for g in globs
                         if g != "*" and not _expand([g], MODULES))
    check("every CHANGE_MAP module glob names a registered module",
          not empty_globs, f"name nothing: {', '.join(empty_globs)}")
    invisible = []
    for subject, tests in sorted(KNOWN_TEST_EDGES.items()):
        for test in tests:
            if test not in graph:
                print(f"  [SKIP] KNOWN_TEST_EDGES {subject} -> {test}: "
                      f"{test}.py is not in this checkout (the mirror case)")
                continue
            try:
                local, top = _known_test_edge_imports(graph, subject, test)
            except SystemExit as exc:
                check(f"KNOWN_TEST_EDGES {subject} -> {test} is a real import", False, str(exc))
                continue
            check(f"KNOWN_TEST_EDGES {subject} -> {test} is a real import", True)
            if not top:
                invisible.append(f"{test}.py:"
                                 f"{','.join(map(str, local))} -> {subject}")
    print(f"  measured: {len(invisible)} of "
          f"{sum(len(t) for t in KNOWN_TEST_EDGES.values())} "
          f"KNOWN_TEST_EDGES rows are invisible to the module-level rule -- "
          f"a row that is not earns no place here: " + "; ".join(invisible))
    check("prose selects no module",
          changed_selection(["AGENTS.md", "docs/PLAN.md",
                             "benchmark/docs/OPERATOR.md",
                             "benchmark/runbooks/RUNBOOK_ALGORAND.md",
                             "benchmark/docker/algorand/README.md"],
                            graph) == {})
    check("paper-table cells and their builder select no module",
          changed_selection(["experiments/codex-checked-interfaces-v2/paper-cells/"
                             "python-docx__aider__target_hidden.json",
                             "experiments/paper-results/build_tables.py",
                             "experiments/paper-results/cell.schema.json"],
                            graph) == {})
    check("the req2test front end, its tests and its package file select "
          "no module",
          changed_selection(["req2test/cli.py", "tests/test_cli.py",
                             "pyproject.toml"], graph) == {})
    check("the runner itself, a script and an unmapped path each select "
          "every module",
          all(tuple(changed_selection([p], graph)) == MODULES
              for p in ("benchmark/r2t/selftest.py",
                        "benchmark/scripts/build_dataset_manifest.py",
                        "experiments/statistics_scenarios/analyze.py")))
    # The three inputs a row used to swallow.  `config/pricing.yml` is read
    # by `pricing.py:76` and `result_ledger_v2_selftest.py:56`, and
    # `config/boundary_coreshop.yml` by `harness.py:1610` among others, so
    # `benchmark/config/` carries no row and runs everything; the env-freeze
    # files are the adapters' `requirements_lock` and are not prose.
    check("a checked-in config and an env freeze each select every module",
          all(tuple(changed_selection([p], graph)) == MODULES
              for p in ("benchmark/config/pricing.yml",
                        "benchmark/config/boundary_coreshop.yml",
                        "benchmark/config/mutation_assets_algorand_v18.json",
                        "benchmark/docs/aider_env_freeze.txt")))
    check("a released `.md` is released bytes, not prose",
          tuple(changed_selection(
              ["benchmark/release/v1/legacy_table_eval100_std.md"], graph))
          == MODULES)
    check("a `.md` fixture under the package is a fixture, not prose",
          tuple(changed_selection(
              ["benchmark/r2t/java/fixtures/PROVENANCE.md"], graph))
          == MODULES)
    # The five directory rows whose reader set could not be enumerated in the
    # source are gone, so these paths take the fallback rather than a row
    # that named fewer readers than they have.
    check("a version pin, a protocol file, a JSON schema and an image "
          "definition each select every module",
          all(tuple(changed_selection([p], graph)) == MODULES
              for p in ("benchmark/VERSIONS.yml",
                        "benchmark/protocol/protocol_v1.yml",
                        "benchmark/schemas/result-ledger-v2.schema.json",
                        "benchmark/docker/coreshop/Dockerfile",
                        "benchmark/docker/epubcheck/offline-settings.xml",
                        ".github/workflows/ci.yml")))
    one = changed_selection([PACKAGE_PATH + "core/gherkin.py"], graph)
    component = component_modules(COMPONENT["core.gherkin"])
    check("a changed module selects its whole component, its module-level "
          "importers and nothing else",
          set(component) <= set(one) and len(one) < len(MODULES)
          and all(m in component
                  or any(e.module_level and e.imported == "core.gherkin"
                         for e in graph[m])
                  for m in one),
          str(sorted(set(one) - set(component))))
    check("a changed module no self-test imports still selects its component",
          tuple(changed_selection([PACKAGE_PATH + "py/compile_check.py"],
                                  graph))
          == component_modules(COMPONENT["py.compile_check"]))
    check("KNOWN_TEST_EDGES adds a cross-component reader the module-level "
          "hop cannot see",
          "agents.smoke" in changed_selection(
              [PACKAGE_PATH + "agents/scanners.py"], graph)
          and COMPONENT["agents.smoke"] != COMPONENT["agents.scanners"])
    if "java.kapua_headroom" in graph:
        refuses("a fictitious headroom test edge still refuses",
                lambda: _known_test_edge_imports(graph, "java.kapua_headroom", "bench.metrics"),
                "imports", "nowhere")
        selected = changed_selection([PACKAGE_PATH + "java/kapua_headroom.py"], graph)
        check("a headroom-only change selects its actual function-local bench consumers",
              {"bench.cli", "bench.report", "bench.results", "bench.test_quality"} <= set(selected)
              and len(selected) < len(MODULES))
    if "java.kapua_gold_coverage" in graph:
        check("a gold-projection change selects its native data-attestation consumer",
              "data.mutation_attestation" in changed_selection(
                  [PACKAGE_PATH + "java/kapua_gold_coverage.py"], graph))
    check("a changed module whose row is gone selects every module",
          tuple(changed_selection([PACKAGE_PATH + "gone.py"], graph))
          == MODULES)

    if failures:
        print(f"components: {len(failures)} FAILED: " + "; ".join(failures))
        return 1
    print("components: OK")
    return 0


if __name__ == "__main__":
    sys.exit(selftest())
