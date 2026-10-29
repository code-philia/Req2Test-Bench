"""Schema-/3 validation for the assertion-hard anti-vacuity release gate."""
from __future__ import annotations

import copy
import json
import os


SCHEMA = "r2t.anti_vacuity/3"
LEGACY_SCHEMA = "r2t.anti_vacuity/2"
STUB_HARD_RECALL_EXACTLY = 0.0
HARD_SUBSET_RATIO_AT_LEAST = 0.15
HARD_SUBSET_RATIO_AT_MOST = 0.50

TOP_FIELDS = frozenset({
    "schema", "project", "verdict_basis", "gate", "population",
    "candidates", "checks", "verdict", "hard_subset", "sources",
})
GATE_FIELDS = frozenset({
    "stub_hard_recall_exactly", "hard_subset_ratio_at_least",
    "hard_subset_ratio_at_most",
})
POPULATION_FIELDS = frozenset({
    "population_id", "project", "engine", "engine_version", "parser",
    "manifest_digest", "mutants",
    "expected_item_mutant_pairs", "full_gold_pairs", "hard_pairs",
})
HARD_FIELDS = frozenset({
    "path", "sha256", "digest", "population_id", "full_gold_pairs",
    "hard_pairs", "ratio_of_full_gold", "fidelity_items_total",
    "fidelity_items_passed", "fidelity_items_excluded",
    "fidelity_exclusions",
})
CANDIDATE_FIELDS = frozenset({
    "scenario_pass_rate", "scenario_passed", "scenario_instances",
    "mutation_recall", "full_recall", "hard_recall",
    "full_n_eligible_items", "hard_n_eligible_items", "full_killed",
    "full_denominator", "hard_killed", "hard_denominator",
    "candidate_hard_runs", "full_knife_edge_items",
    "hard_knife_edge_items", "incomplete_refusal", "complete",
    "executions",
})
CHECK_FIELDS = frozenset({"expected_item_mutant_pairs", "gold", "stub",
                          "kill_set"})
CHECK_GROUP_FIELDS = frozenset({"runs"})
RUN_CHECK_FIELDS = frozenset({
    "rows", "unique_pairs", "duplicate_pairs", "pairs_missing",
    "pairs_outside_population", "rows_dropped_non_production",
})
KILL_CHECK_FIELDS = frozenset({
    "full_pairs", "hard_pairs", "pairs_outside_manifest_map_population",
})
VERDICT_FIELDS = frozenset({
    "gold_full_recall", "gold_hard_recall", "stub_full_recall",
    "stub_hard_recall", "gold_hard_recall_one", "stub_hard_recall_zero",
    "hard_subset_ratio_in_band", "stripped_baseline_fidelity",
    "candidate_baselines_passed", "sweep_complete", "duplicate_free",
    "kill_set_consistent", "both_scored", "pass",
})
EXCLUSION_FIELDS = frozenset({"item_id", "outcome", "reason"})


class AntiVacuityRefused(ValueError):
    """An anti-vacuity document is legacy, incomplete, or contradictory."""


def _sha(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _exact(value, fields: frozenset[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        got = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise AntiVacuityRefused(
            f"REFUSED: {label} must contain exactly {sorted(fields)}; got "
            f"{got}.")


def _count(value, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise AntiVacuityRefused(
            f"REFUSED: {label} is not an integer >= {minimum}.")
    return value


def _recall(value, label: str, *, optional: bool = False):
    if value is None and optional:
        return None
    if not isinstance(value, (int, float)) or isinstance(value, bool) \
            or not 0 <= value <= 1:
        raise AntiVacuityRefused(
            f"REFUSED: {label} is not a recall in [0, 1].")
    return value


def control_baseline(rows: list[dict], label: str) -> dict[str, str]:
    """Validate the producer identity of one unmutated anti-vacuity control."""
    if label not in {"gold", "stub"}:
        raise AntiVacuityRefused(
            f"REFUSED: unknown anti-vacuity baseline control {label!r}.")
    expected_adapter = label
    out = {}
    for number, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise AntiVacuityRefused(
                f"REFUSED: {label} baseline row {number} is not an object.")
        item_id, outcome = row.get("item_id"), row.get("outcome")
        metadata = row.get("metadata")
        producer_ok = (
            row.get("adapter") == expected_adapter
            and isinstance(metadata, dict)
            and ((label == "gold" and metadata.get("source") == "gold")
                 or (label == "stub" and metadata.get("stub") is True)))
        if not isinstance(item_id, str) or not item_id \
                or not isinstance(outcome, str) or not outcome \
                or not producer_ok:
            raise AntiVacuityRefused(
                f"REFUSED: malformed or unauthenticated {label} baseline row "
                f"{number}; expected adapter {expected_adapter!r} and its "
                "producer-specific metadata.")
        if item_id in out:
            raise AntiVacuityRefused(
                f"REFUSED: {label} baseline repeats item {item_id!r}.")
        out[item_id] = outcome
    return out


def _candidate_metrics(candidate: dict, name: str, *, full_pairs: int,
                       hard_pairs: int, fidelity_items: int) -> dict:
    _exact(candidate, CANDIDATE_FIELDS, f"candidates.{name}")
    instances = _count(candidate["scenario_instances"],
                       f"candidates.{name}.scenario_instances", minimum=1)
    passed = _count(candidate["scenario_passed"],
                    f"candidates.{name}.scenario_passed")
    if instances != fidelity_items:
        raise AntiVacuityRefused(
            f"REFUSED: candidates.{name}.scenario_instances does not match "
            "the stripped-fidelity item corpus.")
    if passed > instances or candidate["scenario_pass_rate"] \
            != round(passed / instances, 4):
        raise AntiVacuityRefused(
            f"REFUSED: candidates.{name} baseline counts/rate disagree.")
    if candidate["candidate_hard_runs"] != 2:
        raise AntiVacuityRefused(
            f"REFUSED: candidates.{name} is not candidate hard N=2.")
    _count(candidate["executions"], f"candidates.{name}.executions")
    for field in ("full_knife_edge_items", "hard_knife_edge_items"):
        values = candidate[field]
        if not isinstance(values, list) \
                or not all(isinstance(value, str) and value for value in values) \
                or values != sorted(set(values)):
            raise AntiVacuityRefused(
                f"REFUSED: candidates.{name}.{field} is not a canonical item "
                "list.")

    present = {}
    for prefix in ("full", "hard"):
        fields = (f"{prefix}_recall", f"{prefix}_n_eligible_items",
                  f"{prefix}_killed", f"{prefix}_denominator")
        values = [candidate[field] for field in fields]
        if all(value is None for value in values):
            present[prefix] = False
            continue
        if any(value is None for value in values):
            raise AntiVacuityRefused(
                f"REFUSED: candidates.{name} has a partial {prefix} score.")
        recall = _recall(candidate[f"{prefix}_recall"],
                         f"candidates.{name}.{prefix}_recall")
        eligible = _count(candidate[f"{prefix}_n_eligible_items"],
                          f"candidates.{name}.{prefix}_n_eligible_items")
        killed = _count(candidate[f"{prefix}_killed"],
                        f"candidates.{name}.{prefix}_killed")
        denominator = _count(candidate[f"{prefix}_denominator"],
                             f"candidates.{name}.{prefix}_denominator")
        bound_pairs = full_pairs if prefix == "full" else hard_pairs
        if eligible > instances or killed > denominator \
                or denominator > bound_pairs \
                or (passed == instances and denominator != bound_pairs) \
                or (eligible == 0 and (denominator != 0 or recall != 0.0)) \
                or (eligible > 0 and denominator < eligible) \
                or ((killed == 0) != (recall == 0.0)) \
                or ((denominator > 0 and killed == denominator)
                    != (recall == 1.0)):
            raise AntiVacuityRefused(
                f"REFUSED: candidates.{name} {prefix} recall contradicts its "
                "eligible/killed/denominator accounting.")
        present[prefix] = True

    if hard_pairs == 0 and present["hard"]:
        raise AntiVacuityRefused(
            f"REFUSED: candidates.{name} hard recall must be undefined when "
            "the pinned hard subset contains zero pairs.")

    if candidate["mutation_recall"] != candidate["hard_recall"]:
        raise AntiVacuityRefused(
            f"REFUSED: candidates.{name}.mutation_recall must alias hard_recall; "
            "the legacy full-gold number cannot become primary.")
    complete = candidate.get("complete")
    expected_complete = present["full"] \
        and (present["hard"] or hard_pairs == 0)
    refusal = candidate.get("incomplete_refusal")
    if not isinstance(complete, bool) or complete is not expected_complete \
            or ((refusal is None) != complete) \
            or (refusal is not None
                and (not isinstance(refusal, str) or not refusal)):
        raise AntiVacuityRefused(
            f"REFUSED: candidates.{name} complete/refusal state contradicts "
            "its full and hard score fields.")
    return {"instances": instances, "passed": passed,
            "complete": complete}


def _validate_structure(doc: dict) -> dict:
    """Validate internal /3 shape and arithmetic without granting authority.

    This helper is intentionally private.  A self-consistent anti-vacuity JSON
    object is not release evidence: production callers must use
    :func:`validate_bound` or :func:`load_bound`, which first load the exact
    hard-subset bytes pinned by ``VERSIONS.yml`` and then reconcile every
    repeated claim to that authority.
    """
    if not isinstance(doc, dict):
        raise AntiVacuityRefused(
            "REFUSED: anti-vacuity evidence is not an object.")
    if doc.get("schema") == LEGACY_SCHEMA:
        raise AntiVacuityRefused(
            "REFUSED: r2t.anti_vacuity/2 is full-gold evidence and cannot be "
            "silently read under C4's assertion-hard semantics. Re-run the "
            "stripped baseline and N=2 mutation screen, build/pin "
            "hard_subset.json, then regenerate this artifact as "
            "r2t.anti_vacuity/3.")
    if doc.get("schema") != SCHEMA:
        raise AntiVacuityRefused(
            f"REFUSED: anti-vacuity schema is {doc.get('schema')!r}, not "
            f"{SCHEMA!r}.")
    _exact(doc, TOP_FIELDS, "anti-vacuity /3")
    if not isinstance(doc["project"], str) or not doc["project"]:
        raise AntiVacuityRefused(
            "REFUSED: anti-vacuity /3 has no project identity.")
    if doc["verdict_basis"] != "hard_subset":
        raise AntiVacuityRefused(
            "REFUSED: anti-vacuity /3 verdict_basis must be hard_subset.")
    try:
        from . import anti_vacuity_evidence as AE
        AE.validate_shape(doc["sources"])
    except (ImportError, ValueError) as exc:
        raise AntiVacuityRefused(str(exc)) from exc

    gate = doc["gate"]
    _exact(gate, GATE_FIELDS, "anti-vacuity gate")
    target = _recall(gate["stub_hard_recall_exactly"],
                     "gate.stub_hard_recall_exactly")
    low = _recall(gate["hard_subset_ratio_at_least"],
                  "gate.hard_subset_ratio_at_least")
    high = _recall(gate["hard_subset_ratio_at_most"],
                   "gate.hard_subset_ratio_at_most")
    if (target, low, high) != (
            STUB_HARD_RECALL_EXACTLY,
            HARD_SUBSET_RATIO_AT_LEAST,
            HARD_SUBSET_RATIO_AT_MOST):
        raise AntiVacuityRefused(
            "REFUSED: anti-vacuity gate must use the immutable stub target "
            f"{STUB_HARD_RECALL_EXACTLY:.1f} and hard-subset band "
            f"[{HARD_SUBSET_RATIO_AT_LEAST:.2f}, "
            f"{HARD_SUBSET_RATIO_AT_MOST:.2f}].")

    population = doc["population"]
    _exact(population, POPULATION_FIELDS, "anti-vacuity population")
    for field in ("population_id", "project", "engine", "engine_version",
                  "parser"):
        if not isinstance(population[field], str) or not population[field]:
            raise AntiVacuityRefused(
                f"REFUSED: population.{field} is not a non-empty identity.")
    if not _sha(population["manifest_digest"]):
        raise AntiVacuityRefused(
            "REFUSED: population.manifest_digest is not SHA-256.")
    _count(population["mutants"], "population.mutants", minimum=1)
    expected_pairs = _count(population["expected_item_mutant_pairs"],
                            "population.expected_item_mutant_pairs", minimum=1)
    population_full_count = _count(
        population["full_gold_pairs"], "population.full_gold_pairs", minimum=1)
    population_hard_count = _count(
        population["hard_pairs"], "population.hard_pairs")
    hard = doc["hard_subset"]
    _exact(hard, HARD_FIELDS, "anti-vacuity hard_subset")
    if not _sha(hard["digest"]) or not _sha(hard["sha256"]) \
            or not isinstance(hard["path"], str) or not hard["path"] \
            or hard["population_id"] != population["population_id"]:
        raise AntiVacuityRefused(
            "REFUSED: anti-vacuity /3 does not bind one hard artifact to its "
            "population.")
    full_count = _count(hard["full_gold_pairs"],
                        "hard_subset.full_gold_pairs", minimum=1)
    hard_count = _count(hard["hard_pairs"], "hard_subset.hard_pairs")
    ratio = _recall(hard["ratio_of_full_gold"],
                    "hard_subset.ratio_of_full_gold")
    fidelity_total = _count(hard["fidelity_items_total"],
                            "hard_subset.fidelity_items_total", minimum=1)
    fidelity_passed = _count(hard["fidelity_items_passed"],
                             "hard_subset.fidelity_items_passed")
    fidelity_excluded = _count(hard["fidelity_items_excluded"],
                               "hard_subset.fidelity_items_excluded")
    exclusions = hard["fidelity_exclusions"]
    if hard_count > full_count \
            or round(hard_count / full_count, 6) != ratio \
            or fidelity_passed + fidelity_excluded != fidelity_total \
            or not isinstance(exclusions, list) \
            or len(exclusions) != fidelity_excluded:
        raise AntiVacuityRefused(
            "REFUSED: hard-subset ratio/fidelity accounting does not conserve.")
    seen_exclusions = set()
    for exclusion in exclusions:
        _exact(exclusion, EXCLUSION_FIELDS, "hard-subset fidelity exclusion")
        item_id = exclusion["item_id"]
        if not isinstance(item_id, str) or not item_id \
                or item_id in seen_exclusions \
                or not isinstance(exclusion["outcome"], str) \
                or not exclusion["outcome"] \
                or (exclusion["reason"] is not None
                    and not isinstance(exclusion["reason"], str)):
            raise AntiVacuityRefused(
                "REFUSED: malformed hard-subset fidelity exclusion.")
        seen_exclusions.add(item_id)
    if population_full_count != full_count \
            or population_hard_count != hard_count:
        raise AntiVacuityRefused(
            "REFUSED: population and hard-subset pair counts disagree.")

    candidates = doc["candidates"]
    if not isinstance(candidates, dict) \
            or set(candidates) != {"gold", "stub"}:
        raise AntiVacuityRefused(
            "REFUSED: anti-vacuity /3 requires gold and stub candidates.")
    candidate_facts = {name: _candidate_metrics(
                           candidate, name, full_pairs=full_count,
                           hard_pairs=hard_count, fidelity_items=fidelity_total)
                       for name, candidate in candidates.items()}

    checks = doc["checks"]
    _exact(checks, CHECK_FIELDS, "anti-vacuity checks")
    if _count(checks["expected_item_mutant_pairs"],
              "checks.expected_item_mutant_pairs", minimum=1) != expected_pairs:
        raise AntiVacuityRefused(
            "REFUSED: checks and population disagree on the expected pair set.")
    sweep_complete = True
    duplicate_free = True
    population_consistent = True
    for name in ("gold", "stub"):
        group = checks[name]
        _exact(group, CHECK_GROUP_FIELDS, f"checks.{name}")
        runs = group["runs"]
        if not isinstance(runs, list) or len(runs) != 2:
            raise AntiVacuityRefused(
                f"REFUSED: checks.{name}.runs is not exact N=2.")
        execution_count = 0
        for index, run in enumerate(runs, 1):
            _exact(run, RUN_CHECK_FIELDS, f"checks.{name}.runs[{index - 1}]")
            values = {field: _count(run[field],
                                    f"checks.{name}.runs[{index - 1}].{field}")
                      for field in RUN_CHECK_FIELDS}
            if values["pairs_missing"] > expected_pairs \
                    or values["rows"] != values["unique_pairs"] \
                    + values["duplicate_pairs"] \
                    or values["unique_pairs"] != expected_pairs \
                    - values["pairs_missing"] \
                    + values["pairs_outside_population"]:
                raise AntiVacuityRefused(
                    f"REFUSED: checks.{name}.runs[{index - 1}] does not "
                    "conserve its expected/seen pair accounting.")
            execution_count += values["rows"]
            sweep_complete = sweep_complete and values["pairs_missing"] == 0
            duplicate_free = duplicate_free \
                and values["duplicate_pairs"] == 0
            population_consistent = population_consistent \
                and values["pairs_outside_population"] == 0
        if candidates[name]["executions"] != execution_count:
            raise AntiVacuityRefused(
                f"REFUSED: candidates.{name}.executions does not reproduce "
                "its N=2 run accounting.")
    kill_check = checks["kill_set"]
    _exact(kill_check, KILL_CHECK_FIELDS, "checks.kill_set")
    if _count(kill_check["full_pairs"], "checks.kill_set.full_pairs") \
            != full_count \
            or _count(kill_check["hard_pairs"], "checks.kill_set.hard_pairs") \
            != hard_count:
        raise AntiVacuityRefused(
            "REFUSED: kill-set checks disagree with the bound hard artifact.")
    kills_outside = _count(
        kill_check["pairs_outside_manifest_map_population"],
        "checks.kill_set.pairs_outside_manifest_map_population")

    verdict = doc["verdict"]
    _exact(verdict, VERDICT_FIELDS, "anti-vacuity verdict")
    expected = {
        "gold_full_recall": candidates["gold"]["full_recall"],
        "gold_hard_recall": candidates["gold"]["hard_recall"],
        "stub_full_recall": candidates["stub"]["full_recall"],
        "stub_hard_recall": candidates["stub"]["hard_recall"],
        "gold_hard_recall_one": candidates["gold"]["hard_recall"] == 1.0,
        "stub_hard_recall_zero": candidates["stub"]["hard_recall"] == target,
        "hard_subset_ratio_in_band": low <= ratio <= high,
        "stripped_baseline_fidelity":
            5 * fidelity_excluded <= fidelity_total,
        "candidate_baselines_passed": all(
            candidate["scenario_passed"] == candidate["scenario_instances"]
            for candidate in candidates.values()),
        "sweep_complete": sweep_complete,
        "duplicate_free": duplicate_free,
        "kill_set_consistent": kills_outside == 0 and population_consistent,
        "both_scored": all(facts["complete"]
                           for facts in candidate_facts.values()),
    }
    for key, value in expected.items():
        if isinstance(value, bool):
            agrees = isinstance(verdict[key], bool) and verdict[key] is value
        else:
            agrees = verdict[key] == value
        if not agrees:
            raise AntiVacuityRefused(
                f"REFUSED: verdict.{key} does not reproduce the evidence.")
    required_keys = [
        "stripped_baseline_fidelity", "candidate_baselines_passed",
        "sweep_complete", "duplicate_free", "kill_set_consistent",
        "both_scored",
    ]
    if hard_count:
        required_keys[:0] = [
            "gold_hard_recall_one", "stub_hard_recall_zero"]
    required_pass = tuple(expected[key] for key in required_keys)
    if not isinstance(verdict["pass"], bool) \
            or verdict["pass"] is not all(required_pass):
        raise AntiVacuityRefused(
            "REFUSED: anti-vacuity pass does not reproduce its component "
            "verdicts.")
    return doc


def _validate_bound_impl(doc: dict, *, require_release_inventory: bool,
                         hard_subset_path: str | None = None,
                         expected_population_id: str | None = None,
                         expected_project: str | None = None,
                         versions_path: str | None = None,
                         source_root: str | None = None,
                         released_item_ids=None,
                         release_items_path: str | None = None,
                         release_manifest_path: str | None = None,
                         expected_population_branch: str = "scored") -> dict:
    """Authenticate /3 against the one hard artifact pinned by VERSIONS.

    The pinned hard subset is loaded *before* the anti-vacuity document is
    structurally trusted.  The document supplies at most a population-id hint;
    it never supplies the authoritative path, bytes, population size, or gate
    constants.  This ordering makes a coordinated rewrite of every repeated
    /3 counter just a self-consistent forgery, not a new measurement.
    """
    from . import hard_subset as HS
    from ..data import versions as V

    # /2 has no hard-subset population to resolve. Preserve its explicit
    # migration refusal (and ordinary malformed-schema refusals) before the
    # /3-only pinned load; no /3 claim is trusted on this path.
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return _validate_structure(doc)

    claimed_population = (doc.get("population", {}).get("population_id")
                          if isinstance(doc, dict)
                          and isinstance(doc.get("population"), dict)
                          else None)
    population_id = expected_population_id or claimed_population
    if not isinstance(population_id, str) or not population_id:
        raise AntiVacuityRefused(
            "REFUSED: bound anti-vacuity validation needs a non-empty "
            "population_id before it can resolve the pinned hard subset.")
    try:
        pin = V.hard_subset_pin(population_id, versions_path)
        versions_file = versions_path or V.DEFAULT_MANIFEST_PATH
        pinned_path = os.path.abspath(os.path.join(
            os.path.dirname(os.path.abspath(versions_file)), pin["path"]))
        hard_doc = HS.load(
            pinned_path, expected_population_id=population_id,
            require_pin=True, versions_path=versions_path)
        registry = V.population(population_id, versions_path)
    except (V.ManifestError, HS.HardSubsetRefused, OSError) as exc:
        raise AntiVacuityRefused(str(exc)) from exc

    # Only after the immutable denominator is in hand may /3's own structure
    # and arithmetic be read.  Everything below is a cross-check, never an
    # authority selected by the document.
    _validate_structure(doc)
    if hard_subset_path is not None \
            and os.path.realpath(hard_subset_path) != os.path.realpath(
                pinned_path):
        raise AntiVacuityRefused(
            f"REFUSED: supplied hard subset {os.path.realpath(hard_subset_path)} "
            f"is not the VERSIONS-pinned artifact {os.path.realpath(pinned_path)}.")

    hard_population = hard_doc["population"]
    manifest_digest = hard_population["manifest_digest"]
    if expected_population_branch not in {"scored", "catalogue"}:
        raise AntiVacuityRefused(
            "REFUSED: expected_population_branch must be scored or catalogue.")
    if manifest_digest == registry["scored"]["manifest_digest"]:
        population_branch = registry["scored"]
        branch_name = "scored"
    elif manifest_digest == registry["catalogue"]["manifest_digest"]:
        population_branch = registry["catalogue"]
        branch_name = "catalogue"
    else:                                                       # HS.load guards it
        raise AntiVacuityRefused(                               # pragma: no cover
            "REFUSED: pinned hard subset names neither registered catalogue "
            "nor scored manifest digest.")
    if branch_name != expected_population_branch:
        raise AntiVacuityRefused(
            f"REFUSED: anti-vacuity release requires the registered "
            f"{expected_population_branch} population, but the pinned hard "
            f"subset names {branch_name} evidence.")

    pop = doc["population"]
    hard = doc["hard_subset"]
    checks = doc["checks"]
    kill_check = checks["kill_set"]
    fidelity = hard_doc["fidelity"]
    full = hard_doc["full_gold"]
    hard_set = hard_doc["hard_subset"]
    differences = []

    def same(label: str, actual, wanted) -> None:
        if actual != wanted:
            differences.append(label)

    same("project", doc["project"], registry["project"])
    if expected_project is not None:
        same("expected_project", doc["project"], expected_project)
    same("population.population_id", pop["population_id"], population_id)
    same("population.project", pop["project"], registry["project"])
    same("hard_subset.population_id", hard["population_id"], population_id)
    same("hard population project", hard_population["project"],
         registry["project"])
    for field in ("engine", "engine_version", "parser"):
        same(f"population.{field}", pop[field], registry[field])
        same(f"hard population {field}", hard_population[field],
             registry[field])
    same("population.manifest_digest", pop["manifest_digest"],
         manifest_digest)
    same(f"population.{branch_name}.manifest_digest", manifest_digest,
         population_branch["manifest_digest"])
    same("population.mutants", pop["mutants"], population_branch["n"])

    same("hard_subset.path", hard["path"], pin["path"])
    same("hard_subset.sha256", hard["sha256"], pin["sha256"])
    same("hard_subset.digest", hard["digest"], hard_doc["digest"])
    same("hard-subset pin digest", hard_doc["digest"],
         pin["artifact_digest"])

    expected_pairs = hard_doc["pairs"]["full_n"]
    full_count = full["count"]
    hard_count = hard_set["count"]
    ratio = hard_set["ratio"]
    same("population.expected_item_mutant_pairs",
         pop["expected_item_mutant_pairs"], expected_pairs)
    same("checks.expected_item_mutant_pairs",
         checks["expected_item_mutant_pairs"], expected_pairs)
    for label, actual, wanted in (
            ("population.full_gold_pairs", pop["full_gold_pairs"], full_count),
            ("population.hard_pairs", pop["hard_pairs"], hard_count),
            ("hard_subset.full_gold_pairs", hard["full_gold_pairs"], full_count),
            ("hard_subset.hard_pairs", hard["hard_pairs"], hard_count),
            ("hard_subset.ratio_of_full_gold",
             hard["ratio_of_full_gold"], ratio),
            ("checks.kill_set.full_pairs", kill_check["full_pairs"], full_count),
            ("checks.kill_set.hard_pairs", kill_check["hard_pairs"], hard_count)):
        same(label, actual, wanted)

    for field in ("items_total", "items_passed", "items_excluded"):
        same(f"hard_subset.fidelity_{field}",
             hard[f"fidelity_{field}"], fidelity[field])
    same("hard_subset.fidelity_exclusions", hard["fidelity_exclusions"],
         fidelity["excluded"])

    for name, candidate in doc["candidates"].items():
        same(f"candidates.{name}.scenario_instances",
             candidate["scenario_instances"], fidelity["items_total"])
        for prefix, block in (("full", full), ("hard", hard_set)):
            eligible = candidate[f"{prefix}_n_eligible_items"]
            denominator = candidate[f"{prefix}_denominator"]
            if eligible is None and denominator is None:
                continue
            if eligible > block["items"] or denominator > block["count"]:
                differences.append(f"candidates.{name}.{prefix}_bounds")
            if candidate["scenario_passed"] == candidate["scenario_instances"]:
                same(f"candidates.{name}.{prefix}_n_eligible_items",
                     eligible, block["items"])
                same(f"candidates.{name}.{prefix}_denominator",
                     denominator, block["count"])

    if source_root is None:
        raise AntiVacuityRefused(
            "REFUSED: bound anti-vacuity validation needs source_root so the "
            "archived release pool, baselines, native rows, sidecars, and "
            "observation plans can be rederived.")
    try:
        from . import anti_vacuity_evidence as AE
        derived = AE.rederive(doc["sources"], root=source_root,
                              hard_doc=hard_doc)
    except (ImportError, ValueError, OSError) as exc:
        raise AntiVacuityRefused(str(exc)) from exc
    for field in ("checks", "candidates", "verdict"):
        same(f"source-derived {field}", doc[field], derived[field])
    if released_item_ids is not None:
        try:
            expected_released = set(released_item_ids)
        except TypeError as exc:
            raise AntiVacuityRefused(
                "REFUSED: released_item_ids is not an iterable item set.") \
                from exc
        same("released item IDs", derived["release_ids"], expected_released)
    if release_items_path is not None:
        supplied_release = os.path.realpath(os.path.abspath(
            release_items_path))
        same("released item path", os.path.realpath(derived["release_path"]),
             supplied_release)
    if require_release_inventory and release_manifest_path is None:
        raise AntiVacuityRefused(
            "REFUSED: bound anti-vacuity release validation requires the "
            "externally pinned release_manifest_path; source summaries alone "
            "are not release inventory authority.")
    if release_manifest_path is not None:
        try:
            dataset = V.component("dataset", versions_path)
            manifest_pin = dataset["files"][
                "release/dataset_manifest.json"]
            AE.validate_release_inventory(
                doc["sources"], root=source_root,
                manifest_path=release_manifest_path,
                manifest_sha256=manifest_pin)
        except (V.ManifestError, KeyError, TypeError, ValueError, OSError) as exc:
            raise AntiVacuityRefused(str(exc)) from exc

    if differences:
        raise AntiVacuityRefused(
            "REFUSED: anti-vacuity /3 differs from its exact VERSIONS-pinned "
            f"hard subset / {branch_name} population in claim(s) "
            f"{sorted(set(differences))}.")
    return doc


def validate_bound(doc: dict, **authority) -> dict:
    """Authenticate a publishable /3 document against release authority.

    Unlike the producer-only prepublication check below, this public entry
    point always requires the VERSIONS-pinned dataset manifest.  Consequently
    a coherent rewrite of rows, sidecars, summaries, and their local digests
    cannot appoint itself as a new released measurement.
    """
    return _validate_bound_impl(
        doc, require_release_inventory=True, **authority)


def _validate_prepublication(doc: dict, **authority) -> dict:
    """Producer-only check before the enclosing release inventory exists.

    The builder writes no artifact until this check succeeds.  Every reader
    and release gate uses :func:`validate_bound` instead; this private path is
    solely for constructing bytes which will subsequently be inventoried and
    pinned by VERSIONS.
    """
    if authority.get("release_manifest_path") is not None:
        raise AntiVacuityRefused(
            "REFUSED: prepublication validation cannot substitute an "
            "un-pinned release manifest for public release authority.")
    return _validate_bound_impl(
        doc, require_release_inventory=False, **authority)


def validate(doc: dict, **authority) -> dict:
    """Public validation is always bound; raw structural validation is private."""
    return validate_bound(doc, **authority)


def load_bound(path: str, **authority) -> dict:
    """Load one anti-vacuity document and authenticate its pinned denominator."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise AntiVacuityRefused(
            f"REFUSED: cannot read anti-vacuity evidence {path}: {exc}") from exc
    authority.setdefault("source_root", os.path.dirname(os.path.abspath(path)))
    return validate_bound(doc, **authority)


def selftest() -> int:
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    def refuses(name, value, needle):
        try:
            value()
        except AntiVacuityRefused as exc:
            check(name, needle in str(exc), str(exc))
            return
        check(name, False, "accepted")

    try:
        validate({"schema": LEGACY_SCHEMA})
        legacy_refused = False
    except AntiVacuityRefused as exc:
        legacy_refused = "cannot be silently read" in str(exc)
    check("schema /2 has an explicit migration refusal", legacy_refused)
    def candidate(recall, killed):
        return {
            "scenario_pass_rate": 1.0, "scenario_passed": 3,
            "scenario_instances": 3, "mutation_recall": recall,
            "full_recall": recall, "hard_recall": recall,
            "full_n_eligible_items": 3, "hard_n_eligible_items": 1,
            "full_killed": killed * 4, "full_denominator": 4,
            "hard_killed": killed, "hard_denominator": 1,
            "candidate_hard_runs": 2, "full_knife_edge_items": [],
            "hard_knife_edge_items": [], "incomplete_refusal": None,
            "complete": True, "executions": 8,
        }

    run_check = {
        "rows": 4, "unique_pairs": 4, "duplicate_pairs": 0,
        "pairs_missing": 0, "pairs_outside_population": 0,
        "rows_dropped_non_production": 0,
    }
    source_observation = {
        "observation_id": "1" * 32,
        "campaign_identity_sha256": "2" * 64,
        "pairs_sha256": "3" * 64,
        "n_shards": 1, "n_rows": 4,
        "plan": {"path": "evidence/run/plan.json", "sha256": "4" * 64},
        "shards": [{"index": 0,
                    "rows_path": "evidence/run/gold.w0.jsonl",
                    "rows_sha256": "5" * 64,
                    "sidecar_path":
                        "evidence/run/gold.w0.jsonl.provenance.json",
                    "sidecar_sha256": "6" * 64}],
    }
    source_baseline = {
        "path": "evidence/gold.jsonl", "sha256": "7" * 64,
        "items": 3, "item_ids_sha256": "8" * 64,
        "outcomes_sha256": "9" * 64,
        "generated_tests_sha256": "a" * 64,
    }
    doc = {
        "schema": SCHEMA, "project": "fixture",
        "verdict_basis": "hard_subset",
        "sources": {
            "release_items": {
                "path": "items.jsonl", "sha256": "b" * 64, "items": 3,
                "item_ids_sha256": "c" * 64},
            "baselines": {"gold": copy.deepcopy(source_baseline),
                          "stub": {**copy.deepcopy(source_baseline),
                                   "path": "evidence/stub.jsonl"}},
            "observations": {
                "gold": [copy.deepcopy(source_observation),
                         {**copy.deepcopy(source_observation),
                          "observation_id": "2" * 32}],
                "stub": [
                    {**copy.deepcopy(source_observation),
                     "observation_id": "3" * 32},
                    {**copy.deepcopy(source_observation),
                     "observation_id": "4" * 32}],
            },
        },
        "gate": {"stub_hard_recall_exactly": STUB_HARD_RECALL_EXACTLY,
                 "hard_subset_ratio_at_least": HARD_SUBSET_RATIO_AT_LEAST,
                 "hard_subset_ratio_at_most": HARD_SUBSET_RATIO_AT_MOST},
        "population": {
            "population_id": "fixture-v1", "project": "fixture",
            "engine": "fixture-engine",
            "engine_version": "1", "parser": "fixture-parser",
            "manifest_digest": "c" * 64, "mutants": 4,
            "expected_item_mutant_pairs": 4, "full_gold_pairs": 4,
            "hard_pairs": 1,
        },
        "hard_subset": {"population_id": "fixture-v1",
                        "path": "release/fixture/hard_subset.json",
                        "digest": "d" * 64,
                        "sha256": "e" * 64, "full_gold_pairs": 4,
                        "hard_pairs": 1, "ratio_of_full_gold": 0.25,
                        "fidelity_items_total": 3,
                        "fidelity_items_passed": 3,
                        "fidelity_items_excluded": 0,
                        "fidelity_exclusions": []},
        "candidates": {"gold": candidate(1.0, 1),
                       "stub": candidate(0.0, 0)},
        "checks": {
            "expected_item_mutant_pairs": 4,
            "gold": {"runs": [dict(run_check), dict(run_check)]},
            "stub": {"runs": [dict(run_check), dict(run_check)]},
            "kill_set": {"full_pairs": 4, "hard_pairs": 1,
                         "pairs_outside_manifest_map_population": 0},
        },
        "verdict": {"gold_full_recall": 1.0,
                    "gold_hard_recall": 1.0,
                    "stub_full_recall": 0.0,
                    "stub_hard_recall": 0.0,
                    "gold_hard_recall_one": True,
                    "stub_hard_recall_zero": True,
                    "hard_subset_ratio_in_band": True,
                    "stripped_baseline_fidelity": True,
                    "candidate_baselines_passed": True,
                    "sweep_complete": True, "duplicate_free": True,
                    "kill_set_consistent": True, "both_scored": True,
                    "pass": True},
    }
    check("a conserving /3 hard-basis artifact is structurally exact",
          _validate_structure(doc) == doc)

    def fidelity_case(excluded: int, expected_pass: bool) -> dict:
        case = copy.deepcopy(doc)
        total = 32
        case["hard_subset"].update({
            "fidelity_items_total": total,
            "fidelity_items_passed": total - excluded,
            "fidelity_items_excluded": excluded,
            "fidelity_exclusions": [
                {"item_id": f"excluded-{index}", "outcome": "failed",
                 "reason": "fixture exclusion"}
                for index in range(excluded)],
        })
        for candidate_doc in case["candidates"].values():
            candidate_doc.update({
                "scenario_instances": total,
                "scenario_passed": total,
                "scenario_pass_rate": 1.0,
            })
        case["verdict"]["stripped_baseline_fidelity"] = expected_pass
        case["verdict"]["pass"] = expected_pass
        return case

    check("six fidelity exclusions out of 32 remain within the frozen limit",
          _validate_structure(fidelity_case(6, True))["verdict"]["pass"])
    check("seven fidelity exclusions out of 32 stop the method gate",
          _validate_structure(fidelity_case(7, False))["verdict"]["pass"]
          is False)

    high_ratio = copy.deepcopy(doc)
    high_ratio["population"]["hard_pairs"] = 3
    high_ratio["hard_subset"].update(
        {"hard_pairs": 3, "ratio_of_full_gold": 0.75})
    high_ratio["checks"]["kill_set"]["hard_pairs"] = 3
    for name, candidate_doc in high_ratio["candidates"].items():
        candidate_doc.update({
            "hard_denominator": 3,
            "hard_killed": 3 if name == "gold" else 0,
        })
    high_ratio["verdict"]["hard_subset_ratio_in_band"] = False
    check("a falsified-high hard ratio remains valid evidence",
          _validate_structure(high_ratio)["verdict"]["pass"])

    zero_hard = copy.deepcopy(doc)
    zero_hard["population"]["hard_pairs"] = 0
    zero_hard["hard_subset"].update(
        {"hard_pairs": 0, "ratio_of_full_gold": 0.0})
    zero_hard["checks"]["kill_set"]["hard_pairs"] = 0
    for candidate_doc in zero_hard["candidates"].values():
        candidate_doc.update({
            "mutation_recall": None, "hard_recall": None,
            "hard_n_eligible_items": None, "hard_killed": None,
            "hard_denominator": None,
        })
    zero_hard["verdict"].update({
        "gold_hard_recall": None, "stub_hard_recall": None,
        "gold_hard_recall_one": False,
        "stub_hard_recall_zero": False,
        "hard_subset_ratio_in_band": False,
        "pass": True,
    })
    zero_hard_checked = _validate_structure(zero_hard)
    check("zero hard pairs are valid with undefined hard recall",
          zero_hard_checked["verdict"]["pass"]
          and zero_hard_checked["verdict"]["gold_hard_recall"] is None
          and zero_hard_checked["verdict"]["stub_hard_recall"] is None)
    refuses("public validation cannot accept a self-consistent unpinned /3",
            lambda: validate(doc), "unknown population_id")
    valid_controls = {
        "gold": [{"item_id": "i", "outcome": "passed", "adapter": "gold",
                  "metadata": {"source": "gold"}}],
        "stub": [{"item_id": "i", "outcome": "passed", "adapter": "stub",
                  "metadata": {"stub": True}}],
    }
    check("gold/stub baselines authenticate their real control producers",
          control_baseline(valid_controls["gold"], "gold") == {"i": "passed"}
          and control_baseline(valid_controls["stub"], "stub")
          == {"i": "passed"})
    from . import anti_vacuity_evidence as evidence
    reference_gold = {
        "generation_provenance_class": "reference_control_exact_bytes",
        "reference_control_role": "full-gold",
    }
    reference_stub = {
        "generation_provenance_class": "reference_control_exact_bytes",
        "reference_control_role": "stub-control",
    }
    reference_admitted = True
    try:
        evidence._admit_observation_generation(
            reference_gold, "full-gold", "gold observation")
        evidence._admit_observation_generation(
            reference_stub, "stub-control", "stub observation")
    except evidence.EvidenceRefused:
        reference_admitted = False
    try:
        evidence._admit_observation_generation(
            reference_stub, "full-gold", "gold observation")
        role_swap_refused = False
    except evidence.EvidenceRefused:
        role_swap_refused = True
    check("anti-vacuity evidence admits full/stub exact-byte controls only "
          "under their mapped roles",
          reference_admitted and role_swap_refused)
    forged_stub = copy.deepcopy(valid_controls["gold"])
    forged_stub[0]["metadata"]["stub"] = True
    refuses("ordinary gold cannot masquerade as the stub control",
            lambda: control_baseline(forged_stub, "stub"), "adapter 'stub'")
    forged_gold = copy.deepcopy(valid_controls["stub"])
    forged_gold[0]["metadata"]["source"] = "gold"
    refuses("ordinary candidate/stub cannot masquerade as the gold control",
            lambda: control_baseline(forged_gold, "gold"), "adapter 'gold'")

    stale = copy.deepcopy(doc)
    stale["candidates"]["stub"]["hard_recall"] = 0.5
    refuses("a stale pass cannot survive changed stub hard recall",
            lambda: _validate_structure(stale), "hard recall contradicts")

    missing = copy.deepcopy(doc)
    missing_run = missing["checks"]["gold"]["runs"][0]
    missing_run.update({"rows": 3, "unique_pairs": 3,
                        "pairs_missing": 1})
    missing["candidates"]["gold"]["executions"] = 7
    refuses("a claimed complete sweep cannot hide a missing pair",
            lambda: _validate_structure(missing), "verdict.sweep_complete")

    duplicate = copy.deepcopy(doc)
    duplicate_run = duplicate["checks"]["stub"]["runs"][0]
    duplicate_run.update({"rows": 5, "duplicate_pairs": 1})
    duplicate["candidates"]["stub"]["executions"] = 9
    refuses("a claimed duplicate-free sweep cannot hide a duplicate pair",
            lambda: _validate_structure(duplicate), "verdict.duplicate_free")

    outside = copy.deepcopy(doc)
    outside["checks"]["kill_set"][
        "pairs_outside_manifest_map_population"] = 1
    refuses("a claimed consistent kill set cannot hide an outside pair",
            lambda: _validate_structure(outside),
            "verdict.kill_set_consistent")

    unscored = copy.deepcopy(doc)
    stub = unscored["candidates"]["stub"]
    for field in ("mutation_recall", "full_recall", "hard_recall",
                  "full_n_eligible_items", "hard_n_eligible_items",
                  "full_killed", "full_denominator", "hard_killed",
                  "hard_denominator"):
        stub[field] = None
    stub["complete"] = False
    stub["incomplete_refusal"] = "fixture refusal"
    unscored["verdict"].update({"stub_full_recall": None,
                                "stub_hard_recall": None,
                                "stub_hard_recall_zero": False})
    refuses("a claimed both-scored verdict cannot hide an unscored control",
            lambda: _validate_structure(unscored), "verdict.both_scored")

    bad_numerator = copy.deepcopy(doc)
    bad_numerator["candidates"]["stub"]["hard_killed"] = 1
    refuses("hard recall zero must reproduce its killed/denominator metrics",
            lambda: _validate_structure(bad_numerator),
            "hard recall contradicts")

    oversized = copy.deepcopy(doc)
    oversized["candidates"]["gold"].update(
        {"hard_killed": 99, "hard_denominator": 99})
    refuses("candidate hard accounting cannot exceed the pinned hard set",
            lambda: _validate_structure(oversized), "hard recall contradicts")

    short_corpus = copy.deepcopy(doc)
    for candidate_doc in short_corpus["candidates"].values():
        candidate_doc.update({"scenario_instances": 1,
                              "scenario_passed": 1})
    refuses("candidate baselines must cover the stripped-fidelity corpus",
            lambda: _validate_structure(short_corpus),
            "stripped-fidelity item corpus")
    print("\n" + ("ALL PASS (anti_vacuity)" if ok
                    else "FAILURES (anti_vacuity)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
