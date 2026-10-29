"""S5 — the round-trip validation gate (SPEC §5).

Modelled on SWE-bench's gold-patch validation: an instance is admitted
only if the reference solution demonstrably works.  Two legs per item, in
the stripped repository:

  must FAIL without the closure   a pass here means removal did not
                                  remove the behaviour, so the item is
                                  not measuring generation at all.
  must PASS with the closure      a failure here means the extracted
                                  ground truth is incomplete or wrong.

Only fail-then-pass items are admitted.  Everything else is excluded with
a machine-readable reason, and that exclusion list is a research artifact
in its own right: it is the mechanical counterpart of the ill-posed items
human annotators find by hand, and its rate is the honest measure of how
good the PHP closure extractor is.

Flakiness: the pass leg runs N times (default 3) and an item whose
outcome is not identical across runs is excluded as `flaky`.
"""
from __future__ import annotations

import copy
import io
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Optional

from ..core.gherkin import parse_feature_file
from .harness import (Harness, Solution, fold_lines, fold_scenario_records,
                      gold_solution, record_outcome)
from .repo import SubstrateTampered, clean_workspace

# Exclusion reasons, in the order they are tested.
PASSES_WITHOUT_GLUE = "passes_without_glue"
FAIL_LEG_ERROR = "fail_leg_harness_error"
CLOSURE_INCOMPLETE = "closure_incomplete"
FLAKY = "flaky"
TIMEOUT = "timeout"
PASS_LEG_ERROR = "pass_leg_harness_error"
EMPTY_CLOSURE = "empty_closure"
CONTAINER_ERROR = "di_unresolvable"

#: Bumped whenever a harness change could alter a published number: a
#: verdict, an aggregation, a population resolution, a rendering.  Since
#: section 16 this is the only enforced evaluator identity (the commit and
#: source digest are recorded and disclosed, never refused).  Resume skips
#: rows produced by a different version instead of trusting them: the
#: first sweep of this benchmark was silently poisoned by a container
#: invalidation that never ran, and those verdicts would have survived
#: the fix because resume keyed on item_id alone.
#
# 5 -> 6: the Scenario Outline fold (`harness.fold_scenario_records`).  An
# outline used to match no record at all and score `no_scenario_ran`; it now
# scores on every Examples row.  That is a verdict change on any corpus with
# outlines, so the version moves even though CoreShop — which has none — is
# unaffected and re-scores bit-identically.
#
# 6 -> 7: assertion-hard scoring.  A passed item is now reference-equivalent
# only when it reaches recall 1.0 over the population-pinned hard subset, with
# candidate kills conservatively intersected across N=2.  Items whose hard
# subset is empty become ``not_scorable`` (D3); no full-gold fallback is
# permitted.  This can change a published verdict, so the harness version
# moves even though scenario execution itself is byte-identical.
#
# 7 -> 8: the stripped Algorand offline runner now scans the unit answer
# package promised by the profile, while its unstripped discovery twin stays
# narrow to avoid duplicate upstream glue.  This can move any of the nine
# relocated offline items from undefined steps to an executable verdict.
#
# 8 -> 9: a publication-v3 agent stopped by its unchanged wall-clock envelope
# now closes a timeout evidence chain from the wire bytes already durably
# recorded before the stop.  H8 refused the whole shard when the driver's
# timeout watchdog exited before the outer wrapper could write driver.json;
# H9 retains the same timeout and can therefore emit the item's scored row.
#
# 9 -> 10: confined agent items now seal the coordinator proxy's rejected
# CONNECT journal and join its count onto the row before gate 5 decides
# contamination. This changes which evidence can publish, so H9 cannot resume
# or merge into H10.
#
# 10 -> 11: the three API rows are defined over directly invoked methods
# (API_DIRECT_INVOCATION_SPEC.md); scored from the new `direct_calls` record
# field, never from coverage. This changes what every API number means, so
# H10 rows cannot resume into or merge with an H11 campaign.
# 11 -> 12: API Amendment 2 unions all required outline records and credits
# xmlchemy accessors by their recorded declaring binding and schema-2 index.
# Historical Python recordings lack that identity; their API rows cannot be
# relabelled by loading a new index or coordinator.
# 12 -> 13: validation now refuses a post-run substrate violation on either
# leg before emitting a verdict. H12 could admit the damaging final item; its
# validation rows must not be reused by the repaired gate.
# 13 -> 14: PrestaShop executions restore native resources from a protected
# seed baseline between every repeat, preventing filesystem state leakage.
# Interrupted H13 validation is recollected in full under the new lifecycle.
# 14 -> 15: PrestaShop retains native tags across blanks/comments, including
# database-reset hooks on each repeated scenario. H14 judgments may reflect
# leaked database state and cannot resume under the repaired execution rule.
# 15 -> 16: Kapua unit runners rely on their native parent glue scan instead
# of scanning the generated child again. Duplicate discovery could prevent
# every scenario in otherwise compilable candidates; old verdicts must not
# resume as corrected evaluations.
# 16 -> 17: Kapua rejects saved seeds whose generated runners do not match
# the current recipe. H16 accepted obsolete overlapping glue despite a valid
# saved substrate baseline; those observations cannot resume into H17.
# 17 -> 18: per-step call attribution and the outline coverage union
# (TARGET_INTERFACES_V2_SPEC.md section 4). Every direct-call event carries
# the step that made it (`step`; recorder markers python/3, ruby/2, php/1,
# java/2, go/2), and an outline item's `coverage_lines` is the union over its
# Examples records instead of one representative row. The second moves every
# coverage number on a corpus with outlines, so H17 rows cannot resume into
# or merge with an H18 campaign; the first is what the checked-interfaces
# derivation reads, and it refuses a row whose events lack it.
# 12 -> 18 on the mutation-evaluation-collection-v1.1 line (cut from
# c51836e1, H12), which is NOT master's 18: the PHP harness restores
# generated production classes (the seed's `var/classes` members) to their
# seed bytes before every pair. H12 let a class regenerated under one mutant
# persist, and every later pair on that worker died on autoload as
# `solution_error`; H12 CoreShop mutation rows cannot resume into or merge
# with that line's H18 campaign. That line does not carry master's 13-17.
# 18 -> 19: this merge. Two different harnesses were both numbered 18 --
# master's (per-step call attribution and the outline coverage union) and the
# v1.1 line's (the Pimcore `var/classes` restore) -- and the merged tree is
# neither. Every enforced check on this number is an integer equality, so a
# tree that carries BOTH behaviours cannot answer to either 18 without
# claiming to be code it is not. It therefore takes the first number above
# both. Nothing else changed here: no row recorded at either 18 is rewritten,
# and both 18s are refused by this tree on sight, which is the point.
# 19 -> 20: ordinary Go candidates with an empty recorder fail as
# no_scenario_ran; nonempty malformed witnesses and controls stay strict.
# 20 -> 21: preserve generated candidates and usage on authoritative
# execution errors; usage reports now include these previously lost calls.
# 21 -> 22: Symfony named-argument container failures (ResolveNamedArguments-
# Pass) classify as container_error, not no_scenario_ran. Both labels are
# infrastructure to mutation runs, so no mutation outcome moves.
# 22 -> 23: PrestaShop also restores the native empty-shop-ID settings
# path shop.json and attests 4 GiB/no-swap workers (runtime v4); the
# OpenHands 200-response budget now spans resumes and forced-write turns. Historical rows keep their original identity; reuse across
# this reset-policy amendment requires a separately reviewed recovery contract.
# 23 -> 24: a Go mutation attempt whose test process died of a runtime crash
# (panic/fatal error trace, then the package FAIL result) is `failed` with a
# `crash` row label, provided capture integrity held and the native stream is
# empty or a consistent prefix (owner ruling 2026-09-28). H23 refused that
# attempt, or recorded an empty recorder as no_scenario_ran. Go only.
# 24 -> 25: the evaluator corrections of
# specifications/EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md. A candidate run
# (not a gold run: the gold, stripped-gold or stub adapter, their mutation
# observations, `req2test validate`) gets every coddy-agent retained-test
# helper it does not declare (A), lists a returned other-suite context in its
# PrestaShop/Sylius suite unless it repeats a step pattern of a class listed
# before it (B), and has a partial CoreShop/Sylius service entry autowired
# (C); rows record `supplied_helpers`, `relisted_contexts` and
# `autowired_services`. Scoring drops the reviewed nondeterministic CoreShop
# mutants from every G_i (D). Candidate verdicts and recalls can move; no
# ground-truth outcome does, so 25 joins every compatible reference list.
# 25 -> 26: PrestaShop pool health (specifications/BENCHMARK_V2_SPEC.md
# section 8.1). Before every execution, and after a killed or timed-out one,
# the worker's tables are checked against the seeded list (the *.md5 restore
# inputs); a missing table restores the full dump, else `SeededSchemaFault`
# makes the row `harness_error` and the launcher stops the worker. Outside a
# mutation pair, a database exception in a retained BeforeSuite hook makes the
# row `harness_error` (a worker fault) instead of `no_scenario_ran`; mutation
# pairs keep 25's reading. Candidate rows can move; no ground-truth mutation
# outcome does, so 26 joins every compatible reference list.
# 26 -> 27: Sylius validator cache
# (specifications/SYLIUS_VALIDATOR_CACHE_CORRECTION_AMENDMENT.md). Sylius's
# Behat kernel runs with debug off, so the validator's class metadata
# (built constraint objects) lives in `<cache_dir>/pools` and a hit never
# runs a constraint constructor; the pools survived container invalidation
# and the container is rebuilt only when the item changes. A mutant acting
# only in a constraint constructor therefore survived when the worker's
# previous pair was the same item. The harness now empties the pools before
# every Sylius mutation pair and after a shard's last one. Sylius candidate
# mutation outcomes can move (masked survivals become kills), so H26 Sylius
# mutation rows cannot resume into or merge with an H27 campaign. The
# references were observed with a different item before almost every pair,
# which empties the validator pool on rebuild, so 27 joins every compatible
# reference list and the references are reused. Executions are unchanged.
HARNESS_VERSION = 27


@dataclass
class ItemVerdict:
    item_id: str
    admitted: bool
    reason: Optional[str] = None
    fail_leg: dict = field(default_factory=dict)
    pass_leg: list = field(default_factory=list)
    n_closure_files: int = 0
    seconds: float = 0.0

    def to_json(self) -> dict:
        return {"item_id": self.item_id, "admitted": self.admitted,
                "harness_version": HARNESS_VERSION,
                "reason": self.reason, "fail_leg": self.fail_leg,
                "pass_leg": self.pass_leg,
                "n_closure_files": self.n_closure_files,
                "seconds": round(self.seconds, 2)}


def _thin(run: dict) -> dict:
    """A run summary small enough to keep for every item.

    The record is the FOLD's representative, not `records[0]`.  Reading slot
    zero meant the summary described whatever was written into the record
    file first — the very slot identity selection exists to protect — and for
    a `Scenario Outline`, whose Examples rows each produce a record, it
    described one arbitrary row of several.  `example_results` appears only
    when the fold matched more than one record, so a plain scenario's summary
    is byte-identical to what this always emitted.
    """
    matched, rec = fold_scenario_records(
        run.get("records"),
        fold_lines(run.get("expected_line"), run.get("expected_lines")))
    steps = [] if rec is None else [s["result"] for s in rec.get("steps", [])]
    first_error = None
    if rec is not None:
        for s in rec.get("steps", []):
            if s.get("exception"):
                first_error = {"step": s["text"],
                               "message": s["exception"]["message"][:600]}
                break
    thin = {
        "outcome": run["outcome"], "exit_code": run["exit_code"],
        "seconds": run["wall_seconds"], "steps": steps,
        "first_error": first_error,
        "stdout_tail": (None if rec is not None else run["stdout_tail"][-1200:])}
    if "resource_reset_seconds" in run:
        thin["resource_reset_seconds"] = run["resource_reset_seconds"]
    if len(matched) > 1:
        # Which Examples rows passed, not merely that the outline did not:
        # "3 of 4 rows green" and "1 of 4" are different findings about a
        # closure and the exclusion reason cannot tell them apart.
        thin["example_results"] = [record_outcome(r) for r in matched]
    return thin


def validate_item(harness: Harness, gold_root: str, closure: dict,
                  repeats: int = 3, timeout: int = 600, *,
                  feature_text: Optional[str] = None,
                  gold_source_bytes: Optional[Mapping[str, bytes]] = None,
                  run_observer: Optional[
                      Callable[[str, list[dict]], None]] = None,
                  complete_legs: bool = False) \
        -> ItemVerdict:
    from ..go.context import preflight
    preflight(harness, [closure])
    started = time.time()
    feature_file = closure["feature_file"]
    if os.path.isabs(feature_file):
        raise SystemExit(
            "REFUSED: closure feature_file must be repo-relative; this "
            "absolute-path sidecar predates the dataset migration. Install "
            "the current release bundle or regenerate the gold sidecars.")
    feature_path = os.path.join(harness.root, feature_file)
    feature = parse_feature_file(feature_path, text=feature_text)
    scenario = feature.scenario_at(closure["scenario_line"])
    if scenario is None:
        return ItemVerdict(closure["item_id"], False, "scenario_not_found")

    v = ItemVerdict(closure["item_id"], False,
                    n_closure_files=len(closure["files"]))

    # A post-run substrate report invalidates this item immediately, even
    # when it is the last item. Preserve any raw-run observer evidence first;
    # never emit an admission or an ordinary exclusion for a damaged tree.
    # ---- leg 1: the stripped repo alone must not satisfy the scenario ----
    from ..stacks.godog import GodogHarness
    if isinstance(harness, GodogHarness):
        # Only this coordinator-owned fail leg may prepare inert declarations.
        # Restored gold below remains ordinary, unrepaired candidate execution.
        empty = harness.run_control(feature, scenario, mode="empty", closure=closure,
                                    prepared=None, deadline=None,
                                    timeout=timeout, repeats=repeats)
    else:
        empty = harness.run_solution(feature, scenario, Solution(), timeout=timeout,
                                     repeats=repeats)
    if run_observer is not None:
        run_observer("fail", list(empty["runs"]))
    if empty.get("substrate_violation"):
        raise SubstrateTampered(empty["substrate_violation"])
    fail_outcomes = [r["outcome"] for r in empty["runs"]]
    v.fail_leg = _thin(empty["runs"][0])
    v.fail_leg["outcomes_all_runs"] = fail_outcomes
    fail_reason = None
    if len(set(fail_outcomes)) > 1:
        # An item that only sometimes passes unaided (order-dependent state,
        # a retained-context side effect) would otherwise be admitted on one
        # lucky sample and then score as a success for any system at all.
        fail_reason = FLAKY
    elif v.fail_leg["outcome"] == "passed":
        fail_reason = PASSES_WITHOUT_GLUE
    elif v.fail_leg["outcome"] == "container_error":
        fail_reason = CONTAINER_ERROR
    elif v.fail_leg["outcome"] in ("no_scenario_ran", "no_steps_ran"):
        fail_reason = FAIL_LEG_ERROR
    elif v.fail_leg["outcome"] == "timeout":
        fail_reason = TIMEOUT

    if not closure["files"]:
        # Nothing to restore: the scenario is answered entirely by retained
        # infrastructure, yet it did not pass above.  Not a benchmark item.
        fail_reason = fail_reason or EMPTY_CLOSURE
    if fail_reason is not None and not complete_legs:
        v.reason = fail_reason
        v.seconds = time.time() - started
        return v

    # ---- leg 2: restoring exactly the extracted ground truth must pass ----
    sol = gold_solution(
        gold_root, closure, source_bytes=gold_source_bytes)
    got = harness.run_solution(feature, scenario, sol, timeout=timeout,
                               repeats=repeats)
    if run_observer is not None:
        run_observer("pass", list(got["runs"]))
    if got.get("substrate_violation"):
        raise SubstrateTampered(got["substrate_violation"])
    v.pass_leg = [_thin(r) for r in got["runs"]]
    outcomes = [r["outcome"] for r in v.pass_leg]

    if fail_reason is not None:
        v.reason = fail_reason
    elif any(o == "timeout" for o in outcomes):
        v.reason = TIMEOUT
    elif len(set(outcomes)) > 1:
        v.reason = FLAKY
    elif outcomes[0] == "passed":
        v.admitted = True
    elif outcomes[0] == "container_error":
        v.reason = CONTAINER_ERROR
    elif outcomes[0] in ("no_scenario_ran", "no_steps_ran",
                         "passed_but_nonzero_exit"):
        v.reason = PASS_LEG_ERROR
    else:
        v.reason = CLOSURE_INCOMPLETE
    v.seconds = time.time() - started
    return v


# ------------------------------------------------ publication-v3 validation
@dataclass
class _PublicationValidationPlan:
    execution: dict
    plan: dict
    runtime: object
    context: object
    selected_closures: list[dict]
    raw_by_path: dict[str, bytes]
    absent_paths: tuple[str, ...]
    strip_document: dict
    result_path: str
    checkpoint_path: str
    receipt_path: str

    @property
    def item_ids(self) -> list[str]:
        return self.context.item_ids

    @property
    def row_identity(self) -> dict:
        return {
            "validation_attempt_id": self.execution["attempt_id"],
            "validation_plan_digest": self.plan["digest"],
            "harness_version": self.plan["harness_version"],
            "repeats": self.plan["repeats"],
            "timeout_seconds": self.plan["timeout_seconds"],
        }


def _publication_validation_result_path(args) -> str:
    """Resolve only the output identity; do not touch validation inputs."""
    from . import runner
    artifacts = getattr(args, "artifacts", None)
    out = getattr(args, "out", None)
    if not isinstance(artifacts, str) or not artifacts \
            or not isinstance(out, str) or not out:
        raise SystemExit(
            "REFUSED: validate --publication-v3 requires explicit artifacts "
            "and output bindings; no Docker command was run.")
    artifacts_path = runner._publication_path(
        artifacts, "publication validation artifacts root")
    candidate = out if os.path.isabs(out) else os.path.join(
        artifacts_path, out)
    return runner._publication_path(
        candidate, "publication validation result path", live=False)


def _publication_validation_refuse_input_collisions(
        reader, result_path: str) -> None:
    """Keep every evidence leaf distinct from present or absence-bound input."""
    from . import result_ledger as ledger
    from . import runner
    evidence_paths = {
        result_path,
        result_path + ledger.CHECKPOINT_SUFFIX,
        result_path + ledger.RECEIPT_SUFFIX,
        runner.publication_lock_path(result_path),
    }
    input_paths = set(reader.raw_by_path) | set(reader.absent_paths)
    collisions = sorted(evidence_paths & input_paths)
    if collisions:
        raise ledger._refuse(
            "validation result evidence collides with frozen inputs: "
            f"{collisions}")


def _publication_validation_selector(args, source_ids: list[str]) \
        -> tuple[dict, list[str]]:
    raw_requested = getattr(args, "item", None)
    requested = None
    if raw_requested is not None:
        if not isinstance(raw_requested, list) or not raw_requested \
                or any(not isinstance(value, str) or not value
                       for value in raw_requested):
            raise SystemExit(
                "REFUSED: publication --item values must be a nonempty list "
                "of nonempty item IDs.")
        if len(raw_requested) != len(set(raw_requested)):
            raise SystemExit(
                "REFUSED: publication --item repeats an item ID.")
        missing = sorted(set(raw_requested) - set(source_ids))
        if missing:
            raise SystemExit(
                "REFUSED: publication --item IDs are absent from the exact "
                f"closures: {missing}.")
        requested = sorted(raw_requested)
    limit = getattr(args, "limit", None)
    if limit is not None and (not isinstance(limit, int)
                              or isinstance(limit, bool) or limit <= 0):
        raise SystemExit(
            "REFUSED: publication --limit must be a positive integer.")
    # Validation's historical order is intentionally unlike run: limit the
    # closures stream first, then apply the requested-ID filter.
    selected = source_ids[:limit] if limit is not None else list(source_ids)
    if requested is not None:
        wanted = set(requested)
        selected = [item_id for item_id in selected if item_id in wanted]
    return {"limit": limit, "requested_item_ids": requested}, selected


def _publication_gold_input(reader, root: str, relative: str) -> dict:
    from . import result_ledger as ledger
    path = ledger._contained_path(root, relative, "publication gold input")
    raw = reader.read(path, f"publication gold input {relative}")
    return {
        "relative_path": relative,
        "path": path,
        "byte_length": len(raw),
        "file_sha256": ledger.raw_sha256(raw),
    }


def _publication_validation_runtime(args, reader):
    """Build the offline complete-pool runtime projection without Docker."""
    from . import result_ledger as ledger
    from . import worker
    worker_path = getattr(args, "worker", None)
    if not worker_path:
        raise SystemExit(
            "REFUSED: validate --publication-v3 requires --worker with exact "
            "runtime-v3 evidence; no Docker command was run.")
    harness_identity = ledger._stable_harness_identity(reader)
    harness_identity["version"] = HARNESS_VERSION
    try:
        selected = worker.validate_worker_runtime_v3(
            worker_path, harness_version=HARNESS_VERSION,
            needs_database=False)
        pool_paths = [
            entry["worker_spec_path"]
            for entry in selected["binding"]["pool"]["workers"]
        ]
        complete_pool = worker.validate_offline_worker_runtime_pool(pool_paths)
    except worker.WorkerRefused as exc:
        raise SystemExit(str(exc)) from exc
    index = selected["worker"].index
    if index >= len(complete_pool) \
            or complete_pool[index]["spec_path"] != selected["spec_path"]:
        raise SystemExit(
            "REFUSED: selected validation worker is not its exact "
            "complete-pool member.")
    selected = complete_pool[index]
    reference = worker.publication_runtime_reference(
        selected, harness_identity)
    return reference, ledger._verify_runtime(reader, reference)


def _publication_validate_runtime_args(
        args, bundle: _PublicationValidationPlan) -> None:
    """Ensure the live CLI route still names the frozen worker resources."""
    from . import result_ledger as ledger
    spec = bundle.runtime.worker
    worker_path = ledger.canonical_absolute_path(
        getattr(args, "worker", ""),
        "publication validation WorkerSpec path")
    if worker_path != bundle.runtime.identity["worker_spec_path"]:
        raise ledger._refuse(
            "validation WorkerSpec path differs from frozen runtime")
    if getattr(args, "repo", None) != spec.workspace \
            or getattr(args, "container", None) != spec.container \
            or getattr(args, "workdir", None) != spec.workdir:
        raise ledger._refuse(
            "validation workspace/container/workdir differs from frozen "
            "WorkerSpec")
    artifacts = ledger.canonical_absolute_path(
        getattr(args, "artifacts", ""),
        "publication validation artifacts root")
    if artifacts != spec.artifacts_root:
        raise ledger._refuse(
            "validation artifacts root differs from frozen WorkerSpec")
    gold_root = ledger.canonical_absolute_path(
        getattr(args, "gold", ""), "publication validation gold root")
    if gold_root != bundle.context.gold_root:
        raise ledger._refuse(
            "validation gold root differs from frozen plan")
    boundary_path = ledger.canonical_absolute_path(
        getattr(args, "boundary", ""),
        "publication validation boundary path")
    if boundary_path != bundle.plan["boundary"]["path"]:
        raise ledger._refuse(
            "validation boundary path differs from frozen plan")
    from ..data.profile import profile_path_for
    profile_arg = getattr(args, "profile", None)
    profile_path = profile_arg or profile_path_for(
        boundary_path, bundle.context.boundary.project)
    profile_path = ledger.canonical_absolute_path(
        profile_path, "publication validation resolved profile path")
    if profile_path != bundle.plan["profile"]["path"]:
        raise ledger._refuse(
            "validation resolved profile differs from frozen plan")


def construct_publication_validation_plan(
        args, *, attempt_id: Optional[str] = None) \
        -> _PublicationValidationPlan:
    """Construct and self-verify one complete closed validation plan."""
    from . import result_ledger as ledger
    from . import runner

    if bool(getattr(args, "no_resume", False)):
        raise SystemExit(
            "REFUSED: publication-v3 fixes --no-resume=false; a bound path "
            "is never extended as a fresh validation.")
    if bool(getattr(args, "retry_failed", False)):
        raise SystemExit(
            "REFUSED: publication-v3 fixes --retry-failed=false; validation "
            "retries use a new attempt and output path.")
    for name in ("repeats", "timeout"):
        value = getattr(args, name, None)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise SystemExit(
                f"REFUSED: publication --{name} must be a positive integer.")
    required = ("worker", "out", "artifacts", "gold", "boundary",
                "repo", "container", "workdir")
    missing = [name for name in required if not getattr(args, name, None)]
    if missing:
        raise SystemExit(
            "REFUSED: validate --publication-v3 requires explicit bindings "
            f"{missing}; no Docker command was run.")

    reader = ledger._LiveReader()
    runtime_reference, runtime = _publication_validation_runtime(args, reader)
    spec = runtime.worker
    if getattr(args, "repo", None) != spec.workspace \
            or getattr(args, "container", None) != spec.container \
            or getattr(args, "workdir", None) != spec.workdir:
        raise SystemExit(
            "REFUSED: validation workspace/container/workdir differs from "
            "the authenticated WorkerSpec.")
    artifacts_root = runner._publication_path(
        args.artifacts,
        "publication validation artifacts root")
    if artifacts_root != spec.artifacts_root:
        raise SystemExit(
            "REFUSED: validation artifacts root differs from the "
            "authenticated WorkerSpec.")

    result_path = _publication_validation_result_path(args)
    checkpoint_path = result_path + ledger.CHECKPOINT_SUFFIX
    receipt_path = result_path + ledger.RECEIPT_SUFFIX
    lock_path = runner.publication_lock_path(result_path)
    for path, label in (
            (result_path, "result"), (checkpoint_path, "checkpoint"),
            (receipt_path, "receipt"), (lock_path, "result lock")):
        runner._publication_path(
            path, f"publication validation {label} path", live=False)
        ledger._secure_directory_chain(path)
    ledger._require_workspace_separation(
        spec.workspace,
        (result_path, checkpoint_path, receipt_path, lock_path),
        "validation result evidence")

    closures_path = artifacts_root + "/closures.json"
    closures_ref = runner._publication_raw_ref(
        reader, closures_path, "validation closures")
    closures, by_id = ledger._closure_records(
        reader.raw_by_path[closures_path], "validation closures")
    source_ids = [row["item_id"] for row in closures]
    selection, selected_ids = _publication_validation_selector(
        args, source_ids)
    selected = [by_id[item_id] for item_id in selected_ids]

    boundary_ref = runner._publication_raw_ref(
        reader, args.boundary, "validation boundary")
    boundary_value = ledger._parse_yaml(
        reader.raw_by_path[boundary_ref["path"]], "validation boundary")
    if not isinstance(boundary_value, dict) \
            or not isinstance(boundary_value.get("project"), str):
        raise SystemExit("REFUSED: publication validation boundary has no project.")
    from ..data.profile import profile_path_for
    resolved_profile = getattr(args, "profile", None) or profile_path_for(
        boundary_ref["path"], boundary_value["project"])
    profile_ref = runner._publication_raw_ref(
        reader, resolved_profile, "validation resolved profile")
    profile_value = ledger._parse_yaml(
        reader.raw_by_path[profile_ref["path"]],
        "validation resolved profile")
    framework = profile_value.get("framework") \
        if isinstance(profile_value, dict) else None
    if framework not in {"behave", "behat"}:
        raise SystemExit(
            f"REFUSED: publication validation framework {framework!r} is "
            "not admitted.")

    gold_root = runner._publication_path(
        args.gold, "publication validation gold root")
    ledger._secure_directory_chain(gold_root, include_leaf=True)
    strip_path = gold_root + "/strip_manifest.json"
    strip_ref = runner._publication_raw_ref(
        reader, strip_path, "validation strip manifest")

    gold_relatives = sorted({
        ledger._safe_relative(relative, "validation gold relative path")
        for closure in selected for relative in closure["files"]
    })
    gold_inputs = [
        _publication_gold_input(reader, gold_root, relative)
        for relative in gold_relatives
    ]

    feature_relatives = sorted({
        ledger._safe_relative(
            closure["feature_file"], "validation feature relative path")
        for closure in selected
    })
    feature_inputs = []
    for relative in feature_relatives:
        path = ledger._contained_path(
            spec.workspace, relative, "publication validation feature")
        feature_inputs.append(runner._publication_raw_ref(
            reader, path, "validation feature input"))
    feature_inputs.sort(key=lambda item: (
        item["path"], item["file_sha256"]))

    alias_table = None
    autowirable_types = None
    if framework == "behat":
        alias_path = artifacts_root + "/alias_table.json"
        alias_table = runner._publication_raw_ref(
            reader, alias_path, "validation alias table")
        auto_path = artifacts_root + "/autowirable_types.json"
        if os.path.lexists(auto_path):
            autowirable_types = runner._publication_raw_ref(
                reader, auto_path, "validation autowirable types")
        else:
            reader.require_absent(
                auto_path, "validation autowirable types")

    invocation = {
        "schema": ledger.VALIDATION_INVOCATION_SCHEMA,
        "selection": selection,
        "harness_inputs": {
            "gold_root": gold_root,
            "feature_inputs": feature_inputs,
            "alias_table": alias_table,
            "autowirable_types": autowirable_types,
        },
        "resume": {
            "checkpoint_resume": True,
            "stale_running_suffix_adoption": True,
            "no_resume": False,
            "retry_failed": False,
        },
    }
    plan = {
        "schema": ledger.VALIDATION_PLAN_SCHEMA,
        "closures": closures_ref,
        "boundary": boundary_ref,
        "profile": profile_ref,
        "strip_manifest": strip_ref,
        "gold_inputs": gold_inputs,
        "repeats": args.repeats,
        "timeout_seconds": args.timeout,
        "harness_version": HARNESS_VERSION,
        "workset": {
            "item_count": len(selected_ids),
            "ordered_item_ids_digest": ledger.ordered_item_ids_digest(
                selected_ids),
        },
        "invocation": invocation,
        "invocation_digest": ledger.domain_digest(
            ledger.VALIDATION_INVOCATION_SCHEMA, invocation),
        "digest": "0" * 64,
    }
    plan["digest"] = ledger.semantic_digest(plan)
    context = ledger._verify_validation_plan(reader, plan, runtime)
    if context.item_ids != selected_ids \
            or not ledger._same_json_value(context.selected, selected):
        raise ledger._refuse(
            "constructed validation workset does not self-replay")
    _publication_validation_refuse_input_collisions(reader, result_path)
    reader.confirm()
    # Mint only after the complete static snapshot has closed.  Production
    # immediately uses this identity for the no-clobber draft checkpoint;
    # resume never calls this path and therefore never mints a replacement.
    if attempt_id is None:
        attempt_id = str(uuid.uuid4())
    execution = {"attempt_id": attempt_id, "runtime": runtime_reference}
    empty = runner._publication_result_binding(result_path, b"", 0)
    draft_probe = _validation_checkpoint_document_values(
        execution, plan, "draft", empty, None)
    ledger.validate_checkpoint_schema(draft_probe)
    return _PublicationValidationPlan(
        execution=execution, plan=plan, runtime=runtime, context=context,
        selected_closures=selected, raw_by_path=dict(reader.raw_by_path),
        absent_paths=tuple(sorted(reader.absent_paths)),
        strip_document=copy.deepcopy(context.strip_document),
        result_path=result_path,
        checkpoint_path=checkpoint_path, receipt_path=receipt_path)


def _validation_checkpoint_document_values(
        execution: dict, plan: dict, state: str, result_prefix: dict,
        reason: Optional[str]) -> dict:
    from . import result_ledger as ledger
    document = {
        "schema": ledger.CHECKPOINT_SCHEMA,
        "artifact_kind": "validation",
        "state": state,
        "execution": execution,
        "plan": plan,
        "result_prefix": result_prefix,
        "reason": reason,
        "digest": "0" * 64,
    }
    document["digest"] = ledger.semantic_digest(document)
    ledger.validate_checkpoint_schema(document)
    return document


def _validation_checkpoint_document(
        bundle: _PublicationValidationPlan, state: str,
        result_prefix: dict, reason: Optional[str]) -> dict:
    return _validation_checkpoint_document_values(
        bundle.execution, bundle.plan, state, result_prefix, reason)


def _publication_validation_bundle_from_documents(
        execution: dict, plan: dict, result_path: str) \
        -> _PublicationValidationPlan:
    """Rehydrate an existing checkpoint's frozen validation execution."""
    from . import result_ledger as ledger
    from . import runner
    reader = ledger._LiveReader()
    runtime = ledger._verify_runtime(reader, execution["runtime"])
    context = ledger._verify_validation_plan(reader, plan, runtime)
    ledger._require_workspace_separation(
        runtime.worker.workspace,
        (result_path, result_path + ledger.CHECKPOINT_SUFFIX,
         result_path + ledger.RECEIPT_SUFFIX,
         runner.publication_lock_path(result_path)),
        "validation result evidence")
    _publication_validation_refuse_input_collisions(reader, result_path)
    reader.confirm()
    return _PublicationValidationPlan(
        execution=copy.deepcopy(execution), plan=copy.deepcopy(plan),
        runtime=runtime, context=context,
        selected_closures=copy.deepcopy(context.selected),
        raw_by_path=dict(reader.raw_by_path),
        absent_paths=tuple(sorted(reader.absent_paths)),
        strip_document=copy.deepcopy(context.strip_document),
        result_path=result_path,
        checkpoint_path=result_path + ledger.CHECKPOINT_SUFFIX,
        receipt_path=result_path + ledger.RECEIPT_SUFFIX)


def _read_validation_checkpoint_for_resume(
        checkpoint_path: str, result_path: str) -> dict:
    """Load enough frozen identity to rehydrate; state.resolve rereads it."""
    from . import result_ledger as ledger
    raw = ledger.read_trusted_bytes(
        checkpoint_path, label="result checkpoint")
    document = ledger.loads_exact_json(raw, label="result checkpoint")
    if not isinstance(document, dict):
        raise ledger._refuse("result checkpoint is not an object")
    ledger.validate_checkpoint_schema(document)
    if document.get("digest") != ledger.semantic_digest(document):
        raise ledger._refuse("result checkpoint digest does not recompute")
    if document.get("artifact_kind") != "validation":
        raise ledger._refuse(
            "result checkpoint artifact kind is not validation")
    if document["result_prefix"]["path"] != result_path \
            or checkpoint_path != result_path + ledger.CHECKPOINT_SUFFIX:
        raise ledger._refuse(
            "validation checkpoint is not derived from the requested result")
    return document


def _decode_bound_text(raw: bytes, *, errors: str, label: str) -> str:
    if not isinstance(raw, bytes):
        raise ValueError(f"{label} is not frozen bytes")
    try:
        with io.TextIOWrapper(
                io.BytesIO(raw), encoding="utf-8", errors=errors,
                newline=None) as handle:
            return handle.read()
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8") from exc


def _publication_validation_feature_text(
        bundle: _PublicationValidationPlan, closure: dict) -> str:
    from . import result_ledger as ledger
    relative = ledger._safe_relative(
        closure["feature_file"], "validation feature relative path")
    path = ledger._contained_path(
        bundle.runtime.worker.workspace, relative,
        "publication validation feature")
    if path not in bundle.raw_by_path:
        raise ledger._refuse(
            "selected validation feature is absent from frozen inputs")
    # Match parse_feature_file's diagnostic file reader exactly.
    return _decode_bound_text(
        bundle.raw_by_path[path], errors="replace",
        label="bound validation feature")


def _publication_validation_gold_bytes(
        bundle: _PublicationValidationPlan, closure: dict) \
        -> dict[str, bytes]:
    from . import result_ledger as ledger
    out = {}
    for value in closure["files"]:
        relative = ledger._safe_relative(
            value, "validation gold relative path")
        path = ledger._contained_path(
            bundle.context.gold_root, relative,
            "publication validation gold input")
        if path not in bundle.raw_by_path:
            raise ledger._refuse(
                "selected validation gold source is absent from frozen inputs")
        out[relative] = bundle.raw_by_path[path]
    if len(out) != len(closure["files"]):
        raise ledger._refuse(
            "selected validation closure repeats a gold source")
    return out


def _install_publication_validation_harness_context(
        bundle: _PublicationValidationPlan, args) -> None:
    from . import runner
    boundary = copy.deepcopy(bundle.context.boundary)
    boundary.repo_root = bundle.runtime.worker.workspace
    strip_document = copy.deepcopy(bundle.strip_document)
    bundle.strip_document = strip_document
    manifest = runner._publication_manifest_object(
        strip_document, bundle.runtime.worker.workspace,
        bundle.context.gold_root)
    harness_inputs = bundle.plan["invocation"]["harness_inputs"]
    args._publication_harness_context = {
        "boundary": boundary,
        "manifest": manifest,
        "framework": bundle.context.profile.framework,
        "raw_by_path": bundle.raw_by_path,
        "artifacts_root": bundle.runtime.worker.artifacts_root,
        "autowirable_types_present": (
            harness_inputs["autowirable_types"] is not None),
    }


def _verify_publication_validation_harness(
        bundle: _PublicationValidationPlan, harness, boundary, manifest) \
        -> None:
    from . import result_ledger as ledger
    framework = bundle.context.profile.framework
    if harness.root != bundle.runtime.worker.workspace \
            or boundary.project != bundle.context.profile.project \
            or manifest.gold_root != bundle.context.gold_root:
        raise ledger._refuse(
            "constructed validation harness differs from frozen bindings")
    if framework == "behave":
        from ..stacks.behave import BehaveHarness
        if not isinstance(harness, BehaveHarness):
            raise ledger._refuse(
                "constructed validation harness is not Behave")
    else:
        if not isinstance(harness, Harness):
            raise ledger._refuse(
                "constructed validation harness is not Behat")


class _ValidationLedger:
    """Durable validation checkpoint/result state under the result lock."""

    _TRANSITIONS = {
        "draft": frozenset({"running"}),
        "running": frozenset({"running", "interrupted", "failed"}),
        "interrupted": frozenset({"running"}),
        "failed": frozenset(),
    }

    def __init__(
            self, bundle: _PublicationValidationPlan, *,
            fault: Optional[Callable[[str], None]] = None,
            lock_confirm: Optional[Callable[[], None]] = None):
        self.bundle = bundle
        self.fault = fault
        self.lock_confirm = lock_confirm
        self.document: Optional[dict] = None
        self.pending_adoption: Optional[dict] = None

    def _event(self, event: str) -> None:
        from . import runner
        runner._publication_fault(self.fault, event)

    def _confirm_lock(self) -> None:
        if self.lock_confirm is not None:
            self.lock_confirm()

    def _verify_rows(self, rows: list[dict], *, allow_prefix: bool) -> None:
        from . import result_ledger as ledger
        ledger._verify_validation_row_sequence(
            rows, self.bundle.item_ids, execution=self.bundle.execution,
            plan=self.bundle.plan, allow_prefix=allow_prefix)

    def _durably_confirm_result_binding(self, expected: dict) -> None:
        """Fsync and reread the exact result a checkpoint will claim."""
        from . import result_ledger as ledger
        from . import runner
        if expected.get("path") != self.bundle.result_path:
            raise ledger._refuse(
                "validation checkpoint replacement claims another result")
        raw = ledger.read_trusted_bytes(
            self.bundle.result_path, label="publication validation result")
        rows = ledger._json_lines(raw, "publication validation result")
        self._verify_rows(rows, allow_prefix=True)
        binding = runner._publication_result_binding(
            self.bundle.result_path, raw, len(rows))
        if binding != expected:
            raise ledger._refuse(
                "validation result changed before checkpoint replacement")
        before = ledger._trusted_leaf(
            self.bundle.result_path, "publication validation result")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_CLOEXEC", 0)
        fd = -1
        try:
            fd = os.open(self.bundle.result_path, flags)
            opened = os.fstat(fd)
            if ledger._stat_identity(before) != ledger._stat_identity(opened):
                raise ledger._refuse(
                    "validation result changed before checkpoint fsync")
            os.fsync(fd)
            synced = os.fstat(fd)
            if ledger._stat_identity(opened) \
                    != ledger._stat_identity(synced):
                raise ledger._refuse(
                    "validation result changed during checkpoint fsync")
        except OSError as exc:
            raise ledger._refuse(
                "cannot fsync validation result before checkpoint: "
                f"{exc}") from exc
        finally:
            if fd >= 0:
                os.close(fd)
        if ledger.read_trusted_bytes(
                self.bundle.result_path,
                label="publication validation result") != raw:
            raise ledger._refuse(
                "validation result changed after checkpoint fsync")

    def _write_checkpoint(
            self, document: dict, *, create: bool,
            replace_guard: Optional[Callable[[], None]] = None) -> None:
        from . import result_ledger as ledger
        from . import runner
        payload = runner._publication_document_bytes(document)
        self._confirm_lock()
        if create:
            if replace_guard is not None:
                raise ledger._refuse(
                    "validation checkpoint creation has a replacement guard")

            def create_fault(event: str) -> None:
                self._event(event)
                self._confirm_lock()

            ledger.durable_create_bytes_no_clobber(
                self.bundle.checkpoint_path, payload,
                label="result checkpoint", fault=create_fault)
        else:

            def guarded_fault(event: str) -> None:
                self._event(event)
                self._confirm_lock()
                if event == "result checkpoint:stage_fsync":
                    self._durably_confirm_result_binding(
                        document["result_prefix"])
                    if replace_guard is not None:
                        replace_guard()

            ledger.durable_replace_bytes(
                self.bundle.checkpoint_path, payload,
                label="result checkpoint", fault=guarded_fault)
        self._confirm_lock()
        self.document = document

    def _load_checkpoint(self) -> dict:
        from . import result_ledger as ledger
        raw = ledger.read_trusted_bytes(
            self.bundle.checkpoint_path, label="result checkpoint")
        document = ledger.loads_exact_json(raw, label="result checkpoint")
        if not isinstance(document, dict):
            raise ledger._refuse("result checkpoint is not an object")
        ledger.validate_checkpoint_schema(document)
        if document.get("digest") != ledger.semantic_digest(document):
            raise ledger._refuse("result checkpoint digest does not recompute")
        report = ledger.verify_checkpoint(self.bundle.checkpoint_path)
        if report["artifact_kind"] != "validation":
            raise ledger._refuse(
                "result checkpoint artifact kind is not validation")
        if ledger.read_trusted_bytes(
                self.bundle.checkpoint_path,
                label="result checkpoint") != raw:
            raise ledger._refuse(
                "result checkpoint changed while it was resolved")
        if not ledger._same_json_value(
                document["execution"], self.bundle.execution):
            raise ledger._refuse(
                "validation checkpoint execution differs from frozen request")
        if not ledger._same_json_value(document["plan"], self.bundle.plan):
            raise ledger._refuse(
                "validation checkpoint plan differs from frozen request")
        if document["result_prefix"]["path"] != self.bundle.result_path:
            raise ledger._refuse(
                "validation checkpoint names another result")
        self.document = document
        return document

    def _ensure_empty_result(self, *, allow_existing: bool) -> None:
        from . import result_ledger as ledger
        if os.path.lexists(self.bundle.result_path):
            if not allow_existing:
                raise ledger._refuse(
                    "validation result appeared during exclusive initial "
                    "creation")
            if ledger.read_trusted_bytes(
                    self.bundle.result_path,
                    label="publication validation result") != b"":
                raise ledger._refuse(
                    "draft validation result is not exact empty bytes")
            return
        self._event("initial:before_empty_result")
        self._confirm_lock()

        def empty_fault(event: str) -> None:
            self._event(event)
            self._confirm_lock()

        ledger.durable_create_bytes_no_clobber(
            self.bundle.result_path, b"",
            label="publication empty validation result", fault=empty_fault)
        self._confirm_lock()
        self._event("initial:after_empty_result")

    def resolve(self) -> dict:
        """Create a draft or recover one exact validation checkpoint."""
        from . import result_ledger as ledger
        from . import runner
        if os.path.lexists(self.bundle.receipt_path):
            raise ledger._refuse(
                "validation receipt appeared after receipt-first resolution")
        checkpoint_exists = os.path.lexists(self.bundle.checkpoint_path)
        result_exists = os.path.lexists(self.bundle.result_path)
        if not checkpoint_exists:
            if result_exists:
                raise ledger._refuse(
                    "existing validation result without checkpoint is "
                    "unbound diagnostic evidence and cannot be upgraded")
            empty = runner._publication_result_binding(
                self.bundle.result_path, b"", 0)
            draft = _validation_checkpoint_document(
                self.bundle, "draft", empty, None)
            self._event("initial:before_draft")
            self._write_checkpoint(draft, create=True)
            self._event("initial:after_draft")
            # This invocation observed a genuinely empty evidence tuple.  The
            # empty result must therefore be our own exclusive create; an
            # exact-empty leaf appearing after that observation is still a
            # no-clobber violation, not crash residue to adopt.
            self._ensure_empty_result(allow_existing=False)
            return draft

        document = self._load_checkpoint()
        state = document["state"]
        if state == "failed":
            raise ledger._refuse(
                "failed validation checkpoint is terminal; retry with a new "
                "attempt and output path")
        if state == "draft":
            # A committed empty result can be crash residue from the original
            # exclusive create.  Only an already-existing draft may accept it.
            self._ensure_empty_result(allow_existing=True)
            return document

        raw = ledger.read_trusted_bytes(
            self.bundle.result_path,
            label="publication validation result")
        prefix = document["result_prefix"]
        if len(raw) < prefix["byte_length"]:
            raise ledger._refuse(
                "validation result is shorter than committed checkpoint")
        committed = raw[:prefix["byte_length"]]
        if ledger.raw_sha256(committed) != prefix["file_sha256"]:
            raise ledger._refuse(
                "validation result committed prefix drifted")
        suffix = raw[prefix["byte_length"]:]
        if state != "running" and suffix:
            raise ledger._refuse(
                f"validation result has a suffix from {state} state")
        if state == "running" and suffix:
            rows = ledger._json_lines(raw, "stale running validation result")
            self._verify_rows(rows, allow_prefix=True)
            self.pending_adoption = runner._publication_result_binding(
                self.bundle.result_path, raw, len(rows))
        return document

    def _durable_adoption_binding(self) -> dict:
        from . import result_ledger as ledger
        from . import runner
        if self.document is None or self.document["state"] != "running":
            raise ledger._refuse(
                "validation suffix adoption requires stale running state")
        if os.path.lexists(self.bundle.receipt_path):
            raise ledger._refuse(
                "a stale validation suffix cannot be adopted beside receipt")
        raw = ledger.read_trusted_bytes(
            self.bundle.result_path, label="stale running validation result")
        prefix = self.document["result_prefix"]
        if len(raw) <= prefix["byte_length"]:
            raise ledger._refuse(
                "pending validation suffix disappeared before adoption")
        if ledger.raw_sha256(raw[:prefix["byte_length"]]) \
                != prefix["file_sha256"]:
            raise ledger._refuse(
                "validation committed prefix drifted before adoption")
        rows = ledger._json_lines(raw, "stale running validation result")
        self._verify_rows(rows, allow_prefix=True)
        before = ledger._trusted_leaf(
            self.bundle.result_path, "stale running validation result")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_CLOEXEC", 0)
        fd = -1
        try:
            self._confirm_lock()
            fd = os.open(self.bundle.result_path, flags)
            opened = os.fstat(fd)
            if ledger._stat_identity(before) != ledger._stat_identity(opened):
                raise ledger._refuse(
                    "stale validation result changed before adoption fsync")
            os.fsync(fd)
            synced = os.fstat(fd)
            if ledger._stat_identity(opened) \
                    != ledger._stat_identity(synced):
                raise ledger._refuse(
                    "stale validation result changed during adoption fsync")
        except OSError as exc:
            raise ledger._refuse(
                f"cannot fsync stale validation result: {exc}") from exc
        finally:
            if fd >= 0:
                os.close(fd)
        confirmed = ledger.read_trusted_bytes(
            self.bundle.result_path, label="stale running validation result")
        if confirmed != raw:
            raise ledger._refuse(
                "stale validation result changed after adoption fsync")
        return runner._publication_result_binding(
            self.bundle.result_path, confirmed, len(rows))

    def adopt_pending_suffix(self) -> None:
        from . import result_ledger as ledger
        if self.pending_adoption is None:
            return
        if self.document is None or self.document["state"] != "running":
            raise ledger._refuse(
                "validation suffix adoption requires stale running state")
        adoption = self._durable_adoption_binding()
        self._event("adoption:after_result_fsync")
        adoption = self._durable_adoption_binding()
        advanced = _validation_checkpoint_document(
            self.bundle, "running", adoption, None)

        def guard_adoption() -> None:
            if self._durable_adoption_binding() != adoption:
                raise ledger._refuse(
                    "stale validation result changed before checkpoint commit")

        self._event("adoption:before_checkpoint")
        self._write_checkpoint(
            advanced, create=False, replace_guard=guard_adoption)
        self._event("adoption:after_checkpoint")
        self.pending_adoption = None

    def _synchronized_result(self) -> bytes:
        from . import result_ledger as ledger
        if self.document is None:
            raise ledger._refuse("validation checkpoint is not resolved")
        raw = ledger.read_trusted_bytes(
            self.bundle.result_path,
            label="publication validation result")
        prefix = self.document["result_prefix"]
        if len(raw) != prefix["byte_length"] \
                or ledger.raw_sha256(raw) != prefix["file_sha256"]:
            raise ledger._refuse(
                "validation result and checkpoint are not synchronized")
        rows = ledger._json_lines(raw, "publication validation result")
        if len(rows) != prefix["row_count"]:
            raise ledger._refuse(
                "validation row count differs from checkpoint")
        self._verify_rows(rows, allow_prefix=True)
        return raw

    def transition(self, state: str, *, reason: Optional[str] = None) -> None:
        from . import result_ledger as ledger
        from . import runner
        if self.document is None:
            raise ledger._refuse("validation checkpoint is not resolved")
        current = self.document["state"]
        if state not in self._TRANSITIONS.get(current, frozenset()):
            raise ledger._refuse(
                f"invalid validation transition {current} -> {state}")
        raw = self._synchronized_result()
        if state in {"draft", "running"}:
            if reason is not None:
                raise ledger._refuse(
                    f"validation state {state} cannot carry a reason")
        elif not isinstance(reason, str) or not reason.strip():
            raise ledger._refuse(
                f"validation state {state} requires a nonempty reason")
        prefix = runner._publication_result_binding(
            self.bundle.result_path, raw,
            self.document["result_prefix"]["row_count"])
        document = _validation_checkpoint_document(
            self.bundle, state, prefix, reason)
        self._event(f"transition:{current}:before:{state}")
        self._write_checkpoint(document, create=False)
        self._event(f"transition:{current}:after:{state}")

    def append(self, row: dict) -> None:
        from . import result_ledger as ledger
        from . import runner
        if self.document is None or self.document["state"] != "running":
            raise ledger._refuse(
                "validation append requires a running checkpoint")
        raw = self._synchronized_result()
        ordinal = self.document["result_prefix"]["row_count"]
        if ordinal >= len(self.bundle.item_ids):
            raise ledger._refuse(
                "validation append would extend the frozen workset")
        ledger._verify_validation_row_sequence(
            [row], [self.bundle.item_ids[ordinal]],
            execution=self.bundle.execution, plan=self.bundle.plan)
        try:
            payload = (json.dumps(
                row, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ledger._refuse(
                f"validation row is not finite JSON: {exc}") from exc
        before = ledger._trusted_leaf(
            self.bundle.result_path, "publication validation result")
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_CLOEXEC", 0)
        fd = -1
        write_started = False
        try:
            fd = os.open(self.bundle.result_path, flags)
            opened = os.fstat(fd)
            if ledger._stat_identity(before) != ledger._stat_identity(opened) \
                    or opened.st_size != len(raw):
                raise ledger._refuse(
                    "validation result changed before append")
            self._event("append:before_write")
            self._confirm_lock()
            write_started = True
            ledger._write_all(fd, payload, "publication validation row")
            self._event("append:after_write")
            os.fsync(fd)
            self._event("append:after_result_fsync")
            self._confirm_lock()
        except BaseException as exc:
            if write_started:
                raise runner._PublicationAppendUncertain(str(exc)) from exc
            raise
        finally:
            if fd >= 0:
                os.close(fd)
        full = ledger.read_trusted_bytes(
            self.bundle.result_path,
            label="publication validation result")
        if full != raw + payload:
            raise runner._PublicationAppendUncertain(
                "validation result bytes differ after durable append")
        advanced = runner._publication_result_binding(
            self.bundle.result_path, full, ordinal + 1)
        document = _validation_checkpoint_document(
            self.bundle, "running", advanced, None)
        try:
            self._event("append:before_checkpoint")
            self._write_checkpoint(document, create=False)
            self._event("append:after_checkpoint")
        except BaseException as exc:
            raise runner._PublicationAppendUncertain(str(exc)) from exc

    def final_result(self) -> tuple[dict, bytes, list[dict]]:
        from . import result_ledger as ledger
        from . import runner
        if self.document is None or self.document["state"] != "running":
            state = None if self.document is None else self.document["state"]
            raise ledger._refuse(
                f"validation sealing requires running state, not {state!r}")
        raw = self._synchronized_result()
        rows = ledger._json_lines(raw, "complete publication validation")
        self._verify_rows(rows, allow_prefix=False)
        if len(rows) != len(self.bundle.item_ids):
            raise ledger._refuse(
                "cannot seal an incomplete validation workset")
        return (runner._publication_result_binding(
            self.bundle.result_path, raw, len(rows)), raw, rows)


def _publication_validation_live_revalidate(
        bundle: _PublicationValidationPlan,
        live_validator: Callable[[], dict]) -> dict:
    """Re-run the complete live v3 gate and compare the frozen identity."""
    from . import result_ledger as ledger
    from . import worker
    reader = ledger._LiveReader()
    # The frozen plan's recorded harness is the identity; the version is
    # enforced by the live gate and `publication_runtime_reference`, drift
    # of the commit/source pair is disclosed (section 16).
    ledger.disclose_harness_drift(
        bundle.runtime.harness, ledger._stable_harness_identity(reader))
    live = live_validator()
    if isinstance(live, dict) and "publication_runtime_reference" in live:
        reference = live["publication_runtime_reference"]
    else:
        reference = worker.publication_runtime_reference(
            live, bundle.runtime.harness)
        pool_specs = live.get("pool_specs") if isinstance(live, dict) else None
        if pool_specs is None or len(pool_specs) \
                != len(bundle.runtime.pool["workers"]):
            raise ledger._refuse(
                "live validation did not return the complete worker pool")
    if not ledger._same_json_value(
            reference, bundle.execution["runtime"]):
        raise ledger._refuse(
            "live runtime identity differs from frozen validation execution")
    reader.confirm()
    return live


def _seal_publication_validation(
        bundle: _PublicationValidationPlan, state: _ValidationLedger, *,
        live_validator: Callable[[], dict],
        fault: Optional[Callable[[str], None]],
        lock_confirm: Optional[Callable[[], None]] = None) -> dict:
    from . import result_ledger as ledger
    from . import runner
    if lock_confirm is not None:
        lock_confirm()
    result, _raw, _rows = state.final_result()
    runner._publication_fault(
        fault, "finalization:before_live_revalidation")
    _publication_validation_live_revalidate(bundle, live_validator)
    runner._publication_fault(
        fault, "finalization:after_live_revalidation")
    receipt = {
        "schema": ledger.RECEIPT_SCHEMA,
        "artifact_kind": "validation",
        "execution": bundle.execution,
        "plan": bundle.plan,
        "result": result,
        "digest": "0" * 64,
    }
    receipt["digest"] = ledger.semantic_digest(receipt)
    ledger.validate_receipt_schema(receipt)
    runner._publication_fault(
        fault, "finalization:before_receipt_selfverify")
    verified = ledger.verify_receipt_document(receipt, bundle.receipt_path)
    if verified["artifact_kind"] != "validation":
        raise ledger._refuse(
            "candidate validation receipt verified as another artifact kind")
    runner._publication_fault(
        fault, "finalization:after_receipt_selfverify")
    payload = runner._publication_document_bytes(receipt)
    runner._publication_fault(fault, "finalization:before_receipt_create")
    # This second complete verification is the final stable companion read.
    # It closes mutations after construction and optional-input appearance.
    ledger.verify_receipt_document(receipt, bundle.receipt_path)
    if lock_confirm is not None:
        lock_confirm()

    def durable_fault(event: str) -> None:
        runner._publication_fault(fault, event)
        if event == "result receipt:stage_fsync":
            # The staged receipt is still private and the destination is
            # absent here.  Reclose every live companion at the last
            # deterministic pre-commit seam rather than allowing staging
            # latency to widen the final snapshot window.
            ledger.verify_receipt_document(receipt, bundle.receipt_path)
        if lock_confirm is not None:
            lock_confirm()

    ledger.durable_create_bytes_no_clobber(
        bundle.receipt_path, payload, label="result receipt",
        fault=durable_fault)
    runner._publication_fault(fault, "finalization:after_receipt_create")
    if lock_confirm is not None:
        lock_confirm()
    complete = ledger.verify_receipt(bundle.receipt_path)
    if complete["artifact_kind"] != "validation":
        raise ledger._refuse(
            "published validation receipt has another artifact kind")
    return complete


def _publication_validation_protected_paths(
        bundle: _PublicationValidationPlan) -> tuple[str, ...]:
    from . import runner
    inputs = bundle.plan["invocation"]["harness_inputs"]
    protected = [
        bundle.result_path,
        bundle.checkpoint_path,
        bundle.receipt_path,
        runner.publication_lock_path(bundle.result_path),
        bundle.plan["closures"]["path"],
        bundle.plan["boundary"]["path"],
        bundle.plan["profile"]["path"],
        bundle.plan["strip_manifest"]["path"],
        inputs["gold_root"],
        *(entry["path"] for entry in bundle.plan["gold_inputs"]),
    ]
    for name in ("alias_table", "autowirable_types"):
        if inputs[name] is not None:
            protected.append(inputs[name]["path"])
    return tuple(dict.fromkeys(protected))


def _publication_validation_row(
        bundle: _PublicationValidationPlan, harness,
        closure: dict) -> dict:
    verdict = validate_item(
        harness, bundle.context.gold_root, closure,
        repeats=bundle.plan["repeats"],
        timeout=bundle.plan["timeout_seconds"],
        feature_text=_publication_validation_feature_text(bundle, closure),
        gold_source_bytes=_publication_validation_gold_bytes(
            bundle, closure))
    row = verdict.to_json()
    row.update(bundle.row_identity)
    return row


def run_publication_v3(
        args, *, harness_factory: Callable[[], tuple],
        live_validator: Callable[[], dict],
        fault: Optional[Callable[[str], None]] = None,
        row_producer: Optional[Callable[[dict], dict]] = None) -> dict:
    """Execute, resume, and seal one explicit validation publication."""
    from . import result_ledger as ledger
    from . import runner

    result_path = _publication_validation_result_path(args)
    bound_paths = (
        result_path, result_path + ledger.CHECKPOINT_SUFFIX,
        result_path + ledger.RECEIPT_SUFFIX,
    )
    bound = any(os.path.lexists(path) for path in bound_paths)
    if bound and (bool(getattr(args, "no_resume", False))
                  or bool(getattr(args, "retry_failed", False))):
        raise SystemExit(
            "REFUSED: --no-resume and --retry-failed cannot extend any "
            "result-v3-bound validation path.")
    existing = runner._publication_resolve_existing_receipt(
        result_path, expected_artifact_kind="validation")
    if existing is not None:
        return {"already_complete": True, **existing}
    try:
        with runner._PublicationResultLock(result_path) as result_lock:
            existing = runner._publication_existing_receipt_under_lock(
                result_path, expected_artifact_kind="validation")
            if existing is not None:
                return {"already_complete": True, **existing}
            checkpoint_path = result_path + ledger.CHECKPOINT_SUFFIX
            if os.path.lexists(checkpoint_path):
                frozen = _read_validation_checkpoint_for_resume(
                    checkpoint_path, result_path)
                bundle = _publication_validation_bundle_from_documents(
                    frozen["execution"], frozen["plan"], result_path)
            else:
                if os.path.lexists(result_path):
                    raise ledger._refuse(
                        "existing validation result without checkpoint is "
                        "unbound diagnostic evidence and cannot be upgraded")
                bundle = construct_publication_validation_plan(args)
            if bundle.result_path != result_path:
                raise ledger._refuse(
                    "validation result path changed during planning")
            _publication_validate_runtime_args(args, bundle)
            args._publication_validation_plan = bundle
            args._publication_protected_paths = (
                _publication_validation_protected_paths(bundle))
            state = _ValidationLedger(
                bundle, fault=fault, lock_confirm=result_lock.confirm)
            state.resolve()
            try:
                _install_publication_validation_harness_context(bundle, args)
                harness, boundary, manifest = harness_factory()
                _verify_publication_validation_harness(
                    bundle, harness, boundary, manifest)
                _publication_validation_live_revalidate(
                    bundle, live_validator)
            except KeyboardInterrupt as exc:
                if state.document is not None \
                        and state.document["state"] == "running":
                    try:
                        state.transition(
                            "interrupted",
                            reason=runner._publication_reason(exc))
                    except BaseException:
                        pass
                raise
            except BaseException as exc:
                if state.document is not None \
                        and state.document["state"] == "running":
                    try:
                        state.transition(
                            "failed", reason=runner._publication_reason(exc))
                    except BaseException:
                        pass
                raise
            state.adopt_pending_suffix()
            if state.document["state"] in {"draft", "interrupted"}:
                state.transition("running")

            started = time.time()
            counts: dict[str, int] = {}
            with runner._ExecutionLock(harness.root):
                try:
                    first = state.document["result_prefix"]["row_count"]
                    for number, closure in enumerate(
                            bundle.selected_closures[first:], first + 1):
                        try:
                            if row_producer is None:
                                row = _publication_validation_row(
                                    bundle, harness, closure)
                            else:
                                row = row_producer(copy.deepcopy(closure))
                        except KeyboardInterrupt as exc:
                            state.transition(
                                "interrupted",
                                reason=runner._publication_reason(exc))
                            raise
                        if not isinstance(row, dict):
                            raise ledger._refuse(
                                "validation row producer returned a non-object")
                        for name, value in bundle.row_identity.items():
                            row.setdefault(name, value)
                        state.append(row)
                        key = "admitted" if row.get("admitted") else (
                            row.get("reason") or "unknown")
                        counts[key] = counts.get(key, 0) + 1
                        elapsed = time.time() - started
                        print(
                            f"[{number}/{len(bundle.selected_closures)}] "
                            f"{row['item_id']} -> {key} "
                            f"({elapsed / max(1, number - first):.1f}s/item)",
                            flush=True)

                    state.final_result()
                    from .repo import clean_workspace
                    clean_workspace(harness.man, harness.boundary)
                    harness.clear_registration()
                    verify_substrate = getattr(
                        harness, "verify_substrate", None)
                    if callable(verify_substrate):
                        verify_substrate()
                    result_lock.confirm()
                    receipt = _seal_publication_validation(
                        bundle, state, live_validator=live_validator,
                        fault=fault, lock_confirm=result_lock.confirm)
                except runner._PublicationAppendUncertain:
                    raise
                except runner._PublicationInjectedCrash:
                    raise
                except KeyboardInterrupt as exc:
                    if not os.path.lexists(bundle.receipt_path) \
                            and state.document is not None \
                            and state.document["state"] == "running":
                        try:
                            state.transition(
                                "interrupted",
                                reason=runner._publication_reason(exc))
                        except BaseException:
                            pass
                    raise
                except BaseException as exc:
                    if state.document is not None \
                            and state.document["state"] == "running":
                        try:
                            state.transition(
                                "failed", reason=runner._publication_reason(exc))
                        except BaseException:
                            pass
                    raise
            return {
                "out": bundle.result_path,
                "n": len(bundle.selected_closures),
                "outcomes": counts,
                "seconds": round(time.time() - started, 1),
                "receipt": receipt,
            }
    except ledger.ResultLedgerRefused as exc:
        raise SystemExit(str(exc)) from exc


def validate_all(harness: Harness, gold_root: str, closures: Iterable[dict],
                 out_path: str, repeats: int = 3, timeout: int = 600,
                 resume: bool = True, progress_every: int = 10) -> dict:
    from ..go.context import preflight
    closures = list(closures)
    preflight(harness, closures)
    done: set[str] = set()
    if not resume and os.path.isfile(out_path):
        os.remove(out_path)
    if resume and os.path.isfile(out_path):
        with open(out_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    row = json.loads(line)
                    if row.get("harness_version") == HARNESS_VERSION:
                        done.add(row["item_id"])

    closures = [c for c in closures if c["item_id"] not in done]
    n = len(closures)
    counts: dict[str, int] = {}
    started = time.time()
    with open(out_path, "a", encoding="utf-8") as fh:
        for i, cl in enumerate(closures, 1):
            v = validate_item(harness, gold_root, cl, repeats=repeats,
                              timeout=timeout)
            fh.write(json.dumps(v.to_json(), sort_keys=True) + "\n")
            fh.flush()
            key = "admitted" if v.admitted else (v.reason or "unknown")
            counts[key] = counts.get(key, 0) + 1
            if i % progress_every == 0 or i == n:
                el = time.time() - started
                print(f"[{i}/{n}] {el/60:.1f} min elapsed, "
                      f"{el/i:.1f}s/item :: " +
                      ", ".join(f"{k}={counts[k]}" for k in sorted(counts)),
                      flush=True)
    clean_workspace(harness.man, harness.boundary)
    harness.clear_registration()
    return counts


def summarise(path: str) -> dict:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    counts: dict[str, int] = {}
    for r in rows:
        key = "admitted" if r["admitted"] else (r["reason"] or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return {"n": len(rows), "admitted": sum(1 for r in rows if r["admitted"]),
            "by_reason": dict(sorted(counts.items(), key=lambda kv: -kv[1]))}


def selftest() -> int:
    """What the per-item summary says a run did.

    `_thin` is the only thing kept from a validation run once the sweep is
    over — the whole record file is discarded — so a summary that describes
    the wrong record is a wrong exclusion reason nobody can go back and
    check.  Registered because it used to read `records[0]`.
    """
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def step(text, result, message=None):
        return {"text": text, "result": result, "seconds": 0.1,
                "exception": ({"message": message} if message else None)}

    forged = {"scenario_line": 99, "steps": [step("forged", "passed")]}
    real = {"scenario_line": 22,
            "steps": [step("a", "passed"), step("b", "failed", "boom")]}
    run = {"outcome": "failed", "exit_code": 1, "wall_seconds": 2.0,
           "records": [forged, real], "expected_line": 22, "stdout_tail": "t"}
    t = _thin(run)
    check("the summary describes the scenario's record, not slot zero",
          t["steps"] == ["passed", "failed"], str(t["steps"]))
    check("the first error comes from that same record",
          (t["first_error"] or {}).get("message") == "boom", str(t["first_error"]))
    check("a single-record run carries no example breakdown",
          "example_results" not in t and t["stdout_tail"] is None, str(t))
    check("a run whose records match nothing keeps the stdout tail",
          _thin(dict(run, expected_line=7))["stdout_tail"] == "t")

    outline = dict(run, outcome="failed",
                   records=[{"scenario_line": 12,
                             "steps": [step("a", "passed")]},
                            {"scenario_line": 13,
                             "steps": [step("a", "undefined")]},
                            forged],
                   expected_line=6, expected_lines=[6, 12, 13])
    to = _thin(outline)
    check("an outline reports the outcome of every Examples row",
          to["example_results"] == ["passed", "undefined_steps"],
          str(to.get("example_results")))
    check("...and the row that did not pass supplies the step detail",
          to["steps"] == ["undefined"], str(to["steps"]))
    check("a forged record is in neither the breakdown nor the detail",
          len(to["example_results"]) == 2)

    check("the harness version moved above both 18s: master's per-step call "
          "attribution and outline coverage union, and the v1.1 line's "
          "derived-state restore, now both carried by one tree",
          HARNESS_VERSION > 18, str(HARNESS_VERSION))

    from types import SimpleNamespace
    try:
        validate_item(SimpleNamespace(root="/workspace"), "/gold",
                      {"item_id": "p/f.feature:1",
                       "feature_file": "/old-host/features/f.feature"})
        absolute_refusal = ""
    except SystemExit as exc:
        absolute_refusal = str(exc)
    check("an absolute feature_file names the dataset migration and refuses",
          "repo-relative" in absolute_refusal
          and "dataset migration" in absolute_refusal,
          absolute_refusal)

    # A real source/fixture mutation is reported separately from the native
    # scenario outcome. Exercise both legs even when all recorded steps pass,
    # and the final-item boundary where no later preflight can catch it.
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory(prefix="validate-integrity-") as tmp:
        root = Path(tmp)
        (root / "f.feature").write_text(
            "Feature: integrity\n  Scenario: reference\n    Given a fixture\n",
            encoding="utf-8")
        (root / "glue.php").write_text("<?php // reference\n", encoding="utf-8")
        closure = {"item_id": "p/f.feature:2", "feature_file": "f.feature",
                   "scenario_line": 2, "files": ["glue.php"]}
        report = {"changed": ["tests/Resources/fixture.txt"],
                  "missing": [], "added": []}

        class ReportingHarness:
            def __init__(self, violations):
                self.root = tmp
                self.violations = violations
                self.calls = []

            def run_solution(self, feature, scenario, solution, **kwargs):
                leg = "pass" if solution.files else "fail"
                self.calls.append(leg)
                outcome = "passed" if leg == "pass" else "undefined_steps"
                result = {"runs": [dict(run, outcome=outcome)] * 3,
                          "substrate_violation": self.violations.get(
                              len(self.calls))}
                return result

        for leg, call_number in (("fail", 1), ("pass", 2)):
            for complete in (False, True):
                observed = []
                harness = ReportingHarness({call_number: report})
                try:
                    validate_item(harness, tmp, closure,
                                  complete_legs=complete,
                                  run_observer=lambda name, runs:
                                  observed.append((name, runs)))
                    caught = None
                except SubstrateTampered as exc:
                    caught = exc
                check(f"{leg} substrate damage aborts (complete={complete})",
                      caught is not None and caught.report is report
                      and len(harness.calls) == call_number)
                check(f"{leg} raw diagnostics survive before refusal "
                      f"(complete={complete})",
                      len(observed) == call_number
                      and observed[-1][0] == leg
                      and len(observed[-1][1]) == 3)

        clean = validate_item(ReportingHarness({}), tmp, closure)
        check("clean fail-then-pass still admits", clean.admitted
              and clean.reason is None and len(clean.pass_leg) == 3)
        for leg, call_number in (("fail", 3), ("pass", 4)):
            output = root / f"{leg}.jsonl"
            harness = ReportingHarness({call_number: report})
            try:
                validate_all(harness, tmp,
                             [closure, dict(closure, item_id="final")],
                             str(output))
                caught = None
            except SubstrateTampered as exc:
                caught = exc
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            check(f"final-item {leg} damage appends no verdict",
                  caught is not None and caught.report is report
                  and len(harness.calls) == call_number
                  and len(rows) == 1 and rows[0]["item_id"] == closure["item_id"]
                  and rows[0]["admitted"])

    print("\n" + ("ALL PASS (validate)" if ok else "FAILURES (validate)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
