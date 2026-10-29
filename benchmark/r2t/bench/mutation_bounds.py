"""Sound recall intervals for a compute-capped test-quality campaign.

This module is a publication firewall, not a partial scorer.  It accepts an
``interrupted`` native test-quality campaign only when the candidate leg is
complete and every persisted reference row is authenticated by the campaign's
root plan and shard sidecar.  It then asks what recall values remain possible
as the unexecuted reference pairs are adjudicated.

The arithmetic was reviewed first in the user-owned, untracked helper named by
``REVIEW_SOURCE``.  Only the corpus-independent candidate-partition envelope
is carried here.  The helper itself remains read-only and is not an input at
runtime; its digest is recorded so the derivation can be audited explicitly.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from typing import Iterable, Optional

from ..data.mutation import classify_outcome


BOUND_SCHEMA = "r2t.mutation-recall-bound/v2"
METHOD_SCHEMA = "r2t.candidate-partitioned-recall-envelope/v1"
REVIEW_SOURCE = "benchmark/scripts/slice1_cell1_bound.py"
REVIEW_SOURCE_SHA256 = (
    "b79e93b255492e6dc086e76f4e62fdfa830c8f928e5bda9e05617b9d551497ee"
)


class BoundRefused(ValueError):
    """The supplied evidence cannot support a bounded result."""


def _refuse(message: str) -> None:
    raise BoundRefused("REFUSED: " + message)


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _regular_file(path: str, label: str) -> str:
    if os.path.islink(path) or not os.path.isfile(path):
        _refuse(f"{label} is not a non-symlink regular file: {path}.")
    return os.path.abspath(path)


def _load_object(path: str, label: str) -> dict:
    _regular_file(path, label)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        _refuse(f"cannot read {label} {path}: {exc}.")
    if not isinstance(doc, dict):
        _refuse(f"{label} {path} is not a JSON object.")
    return doc


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _pair_sequence_digest(pairs: Iterable[tuple[str, str]]) -> str:
    """SHA-256 of a pair sequence, preserving order rather than set identity."""
    digest = hashlib.sha256()
    for item_id, mutant_id in pairs:
        if not isinstance(item_id, str) or not isinstance(mutant_id, str) \
                or not item_id or not mutant_id \
                or "\0" in item_id or "\0" in mutant_id:
            _refuse(f"ordered pair sequence contains invalid identity "
                    f"{(item_id, mutant_id)!r}.")
        digest.update(item_id.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        digest.update(mutant_id.encode("utf-8", "surrogateescape"))
        digest.update(b"\n")
    return digest.hexdigest()


def _threshold(raw) -> tuple[str, Fraction]:
    """Canonical positive recall threshold and its exact rational value."""
    if isinstance(raw, bool) or raw is None:
        _refuse(f"recall threshold must be in (0, 1], got {raw!r}.")
    try:
        value = Decimal(str(raw))
    except (InvalidOperation, ValueError):
        _refuse(f"recall threshold must be a decimal in (0, 1], got {raw!r}.")
    if not value.is_finite() or value <= 0 or value > 1:
        _refuse(f"recall threshold must be in (0, 1], got {raw!r}.")
    # ``Decimal.normalize()`` applies the ambient decimal context and rounds
    # coefficients longer than its precision (28 by default).  Threshold
    # identity must preserve every supplied decimal digit.  Canonicalise the
    # exact coefficient/exponent tuple directly instead.
    sign, digits, exponent = value.as_tuple()
    digits = list(digits)
    while digits and digits[-1] == 0:
        digits.pop()
        exponent += 1
    if not digits:
        rendered = "0"
    else:
        coefficient = "".join(str(digit) for digit in digits)
        point = len(coefficient) + exponent
        if point <= 0:
            rendered = "0." + "0" * (-point) + coefficient
        elif point >= len(coefficient):
            rendered = coefficient + "0" * (point - len(coefficient))
        else:
            rendered = coefficient[:point] + "." + coefficient[point:]
        if sign:
            rendered = "-" + rendered
    if "." not in rendered:
        rendered += ".0"
    return rendered, Fraction(value)


def _fraction(value: Optional[Fraction]) -> Optional[dict]:
    if value is None:
        return None
    # A string is intentional: the numerator/denominator are authoritative,
    # and serialising a binary float would make an exact threshold comparison
    # look approximate in the evidence file.
    decimal = format(Decimal(value.numerator) / Decimal(value.denominator),
                     ".12f").rstrip("0").rstrip(".")
    if "." not in decimal:
        decimal += ".0"
    return {"numerator": value.numerator, "denominator": value.denominator,
            "decimal": decimal}


def recall_envelope(killed: int, denominator: int,
                    remaining_candidate_kills: int,
                    remaining_candidate_survivals: int) \
        -> tuple[Optional[Fraction], Optional[Fraction]]:
    """Return the tight candidate-partition recall envelope.

    ``killed``/``denominator`` are the candidate's score over reference kills
    observed so far.  Among reference pairs not yet executed, a future
    reference kill on a candidate kill adds one to numerator and denominator;
    one on a candidate non-infrastructure survival adds only to the
    denominator. ``remaining_candidate_survivals`` is therefore the `RS`
    partition, not the number of future reference survivals. Candidate
    infrastructure outcomes are deliberately absent from both remaining
    counts because the scorer excludes them from its denominator even if the
    reference later kills the mutant.

    With no observed denominator and no remaining `RK` pair, no positive
    recall is reachable and both ends are undefined.  That is deliberately
    distinct from denominator reachability: a future reference kill on an
    `RS` pair can create a positive denominator while recall stays zero.  If
    only candidate-killed pairs can make positive recall reachable, the
    conservative lower end is zero: the reference may ultimately kill none of
    them, making the item's positive-threshold binary outcome false rather
    than 1.0.
    """
    values = (killed, denominator, remaining_candidate_kills,
              remaining_candidate_survivals)
    if any(not _is_int(value) or value < 0 for value in values):
        _refuse(f"recall-envelope counts must be non-negative integers: "
                f"{values!r}.")
    if killed > denominator:
        _refuse(f"recall numerator {killed} exceeds denominator "
                f"{denominator}.")
    upper_denominator = denominator + remaining_candidate_kills
    if upper_denominator == 0:
        return None, None
    upper = Fraction(killed + remaining_candidate_kills, upper_denominator)
    lower_denominator = denominator + remaining_candidate_survivals
    lower = (Fraction(killed, lower_denominator)
             if lower_denominator else Fraction(0, 1))
    return lower, upper


def _pairs_from_rows(rows: Iterable[dict], label: str,
                     expected: set[tuple[str, str]]) \
        -> tuple[dict[tuple[str, str], str], dict[str, set[str]]]:
    by_pair: dict[tuple[str, str], str] = {}
    by_item: dict[str, set[str]] = {}
    for number, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            _refuse(f"{label} row {number} is not an object.")
        pair = (row.get("item_id"), row.get("mutant_id"))
        if pair not in expected:
            _refuse(f"{label} row {number} contains unexpected pair {pair!r}.")
        if pair in by_pair:
            _refuse(f"{label} repeats pair {pair!r}.")
        outcome = row.get("outcome")
        if not isinstance(outcome, str) or not outcome:
            _refuse(f"{label} row {number} has no outcome.")
        by_pair[pair] = outcome
        by_item.setdefault(pair[0], set()).add(pair[1])
    return by_pair, by_item


def compute_bounds(*, run_items: Iterable[str], passed_items: Iterable[str],
                   expected_pairs: set[tuple[str, str]],
                   candidate_rows: list[dict], reference_rows: list[dict],
                   gold_baseline: dict, thresholds: Iterable = ("1.0",)) \
        -> dict:
    """Pure interval calculation over an already authenticated pair set."""
    run_items = list(run_items)
    if (any(not isinstance(item, str) or not item for item in run_items)
            or len(run_items) != len(set(run_items))):
        _refuse("the candidate run denominator has missing or duplicate ids.")
    passed = set(passed_items)
    if not passed <= set(run_items):
        _refuse("passed items are not a subset of the candidate run.")
    if not passed:
        _refuse("the candidate has no passed item to bound.")
    if not expected_pairs:
        _refuse("the passed-item mutation population is empty.")
    if any(not isinstance(pair, tuple) or len(pair) != 2
           or any(not isinstance(value, str) or not value for value in pair)
           for pair in expected_pairs):
        _refuse("the expected mutation pair set is malformed.")
    expected_items = {item for item, _mutant in expected_pairs}
    if not expected_items <= passed:
        _refuse("the mutation population contains a non-passed item.")

    parsed_thresholds = [_threshold(raw) for raw in thresholds]
    if not parsed_thresholds:
        _refuse("at least one recall threshold is required.")
    if len({name for name, _value in parsed_thresholds}) \
            != len(parsed_thresholds):
        _refuse("recall thresholds contain a duplicate after normalisation.")

    candidate, _candidate_by_item = _pairs_from_rows(
        candidate_rows, "candidate leg", expected_pairs)
    if set(candidate) != expected_pairs:
        missing = sorted(expected_pairs - set(candidate))
        _refuse(f"candidate leg is incomplete: {len(missing)} pair(s) "
                f"missing, e.g. {missing[:3]}.")
    reference, reference_by_item = _pairs_from_rows(
        reference_rows, "reference leg", expected_pairs)

    expected_by_item: dict[str, set[str]] = {}
    for item_id, mutant_id in expected_pairs:
        expected_by_item.setdefault(item_id, set()).add(mutant_id)

    per_item: dict[str, dict] = {}
    reference_infrastructure = 0
    reference_kills_ignored_ineligible = 0
    for item_id in sorted(passed):
        population = expected_by_item.get(item_id, set())
        seen = reference_by_item.get(item_id, set())
        unadjudicated = population - seen
        baseline = gold_baseline.get(item_id)
        killed = 0
        denominator = 0
        candidate_excluded_observed = 0
        gold_kills_observed = 0
        for mutant_id in sorted(seen):
            gold_class = classify_outcome(
                baseline, reference[(item_id, mutant_id)])
            if baseline != "passed":
                if gold_class == "kill":
                    reference_kills_ignored_ineligible += 1
                elif gold_class == "infrastructure":
                    reference_infrastructure += 1
                continue
            if gold_class == "infrastructure":
                reference_infrastructure += 1
                continue
            if gold_class != "kill":
                continue
            gold_kills_observed += 1
            candidate_class = classify_outcome(
                "passed", candidate[(item_id, mutant_id)])
            if candidate_class == "infrastructure":
                candidate_excluded_observed += 1
                continue
            denominator += 1
            if candidate_class == "kill":
                killed += 1

        remaining = {"kill": 0, "survived": 0, "infrastructure": 0}
        for mutant_id in sorted(unadjudicated):
            klass = classify_outcome(
                "passed", candidate[(item_id, mutant_id)])
            remaining[klass] += 1

        if baseline == "passed":
            lower, upper = recall_envelope(
                killed, denominator, remaining["kill"],
                remaining["survived"])
            reason = (None if upper is not None else
                      "no positive recall is reachable")
        else:
            lower, upper = None, None
            reason = ("gold baseline is not passed; reference kills are "
                      "ineligible")

        item_thresholds = {}
        for name, threshold in parsed_thresholds:
            possible = upper is not None and upper >= threshold
            established = (possible and lower is not None
                           and lower >= threshold)
            item_thresholds[name] = (
                "established" if established
                else "unresolved" if possible
                else "excluded")
        per_item[item_id] = {
            "population_pairs": len(population),
            "reference_adjudicated": len(seen),
            "reference_unadjudicated": len(unadjudicated),
            "reference_kills_observed": gold_kills_observed,
            "candidate_kills_in_observed_reference_denominator": killed,
            "observed_reference_kills_excluded_by_candidate_infrastructure":
                candidate_excluded_observed,
            "unadjudicated_candidate_kills": remaining["kill"],
            "unadjudicated_candidate_survivals": remaining["survived"],
            "unadjudicated_candidate_infrastructure":
                remaining["infrastructure"],
            "recall_interval": {
                "lower": _fraction(lower), "upper": _fraction(upper),
                "undefined_reason": reason,
            },
            "threshold_status": item_thresholds,
        }

    threshold_bounds = []
    for name, threshold in parsed_thresholds:
        lower_count = sum(
            entry["threshold_status"][name] == "established"
            for entry in per_item.values())
        upper_count = sum(
            entry["threshold_status"][name] != "excluded"
            for entry in per_item.values())
        denominator = len(run_items)
        threshold_bounds.append({
            "threshold": {
                "decimal": name,
                "numerator": threshold.numerator,
                "denominator": threshold.denominator,
            },
            "numerator_interval": {
                "lower": lower_count, "upper": upper_count,
            },
            "rate_interval": {
                "lower": _fraction(Fraction(lower_count, denominator)),
                "upper": _fraction(Fraction(upper_count, denominator)),
            },
            "denominator": denominator,
            "state": ("established" if lower_count == upper_count
                      else "unresolved"),
        })
    return {
        "denominator": {"run_items": len(run_items),
                        "passed_items": len(passed),
                        "expected_mutation_pairs": len(expected_pairs)},
        "reference_rows": len(reference),
        "reference_infrastructure_outcomes": reference_infrastructure,
        "reference_kills_ignored_ineligible_baseline":
            reference_kills_ignored_ineligible,
        "threshold_bounds": threshold_bounds,
        "per_item": per_item,
    }


def _safe_campaign_directory(campaign_dir: str) -> str:
    campaign = os.path.abspath(campaign_dir)
    if os.path.islink(campaign) or not os.path.isdir(campaign):
        _refuse(f"campaign is not a non-symlink directory: {campaign}.")
    return campaign


def _output_outside_campaign(campaign: str, out_path: str) -> str:
    out = os.path.abspath(out_path)
    if os.path.lexists(out):
        _refuse(f"bound output already exists: {out}; use a new path.")
    try:
        inside = os.path.commonpath((os.path.realpath(campaign),
                                     os.path.realpath(out))) \
            == os.path.realpath(campaign)
    except ValueError:
        inside = False
    if inside:
        _refuse("bound output must be outside the read-only campaign tree.")
    return out


def _durable_write_new_json(path: str, value: dict) -> None:
    """Durably publish JSON with an atomic kernel no-clobber decision."""
    parent = os.path.dirname(path) or "."
    if os.path.islink(parent) or not os.path.isdir(parent):
        _refuse(f"bound output parent is not a non-symlink directory: "
                f"{parent}.")
    payload = (json.dumps(value, indent=1, sort_keys=True) + "\n").encode(
        "utf-8")
    fd = -1
    temp_path = None
    linked = False
    try:
        fd, temp_path = tempfile.mkstemp(
            prefix=".r2t-bound.", suffix=".tmp", dir=parent)
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            # Same-directory hard-link creation is an atomic create-if-absent
            # operation. Unlike lexists()+replace, a concurrent creator can
            # never be overwritten between the check and commit.
            os.link(temp_path, path, follow_symlinks=False)
            linked = True
        except FileExistsError:
            _refuse(f"bound output already exists: {path}; use a new path.")
        directory_fd = os.open(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
            os.unlink(temp_path)
            temp_path = None
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BoundRefused:
        raise
    except OSError as exc:
        state = " after the no-clobber link was created" if linked else ""
        _refuse(f"cannot durably publish bound output {path}{state}: {exc}.")
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass


def _campaign_snapshot(paths: Iterable[str]) -> dict[str, str]:
    snapshot = {}
    for path in sorted(set(paths)):
        _regular_file(path, "campaign evidence")
        snapshot[path] = _sha256_file(path)
    return snapshot


def _campaign_tree_paths(campaign: str) -> list[str]:
    """Enumerate the exact interrupted-campaign tree without following links."""
    from . import test_quality as TQ

    root_entries = set(os.listdir(campaign))
    if root_entries != {TQ.CAMPAIGN_STATE, TQ.SHARD_DIR}:
        _refuse("interrupted campaign root changed or differs from the exact "
                f"artifact set: {sorted(root_entries)!r}.")
    state_path = os.path.join(campaign, TQ.CAMPAIGN_STATE)
    _regular_file(state_path, "root campaign state")
    shard_dir = os.path.join(campaign, TQ.SHARD_DIR)
    if os.path.islink(shard_dir) or not os.path.isdir(shard_dir):
        _refuse(f"campaign shard path is not a real directory: {shard_dir}.")
    paths = [state_path]
    for name in sorted(os.listdir(shard_dir)):
        path = os.path.join(shard_dir, name)
        _regular_file(path, "shard evidence")
        paths.append(path)
    return paths


def _validate_root_plan(plan: dict, *, expected_pairs: set,
                        cap_workers: int, cap_seconds: int,
                        cap_review_authority: str,
                        campaign_dir: str) -> dict:
    from . import test_quality as TQ
    from .mutation_run import content_digest, pair_set_digest

    if not isinstance(plan, dict) \
            or set(plan) != TQ.TEST_QUALITY_PLAN_V3_FIELDS:
        _refuse("root campaign plan has missing or unknown fields.")
    if plan.get("schema") != TQ.TEST_QUALITY_PLAN_SCHEMA_V3:
        _refuse("bounded fallback requires the pre-execution cap-bound "
                f"{TQ.TEST_QUALITY_PLAN_SCHEMA_V3} root plan, got "
                f"{plan.get('schema')!r}.")
    try:
        TQ.validate_test_quality_plan_v3(plan)
    except TQ.TestQualityRefused as exc:
        raise BoundRefused(str(exc)) from exc
    if not isinstance(plan.get("jobs"), list) or not plan["jobs"] \
            or any(not isinstance(job, dict) for job in plan["jobs"]):
        _refuse("root campaign plan jobs are not a nonempty object array.")
    if TQ.shard_policy_from_plan(plan) != TQ.SHARD_POLICY_BALANCED_PAIRS_V1:
        _refuse("root campaign does not use the current policy-bound "
                "pair-balanced schedule.")
    if not TQ.policy_identity_binding_from_plan(plan):
        _refuse("root campaign shard policy is not bound into its identities.")
    if plan.get("require_complete") is not True:
        _refuse("root campaign was not planned against the complete pair set.")
    if plan.get("gold_precomputed") is not False:
        _refuse("bounded fallback needs an executed partial reference leg, "
                "not precomputed gold.")
    if plan.get("final_artifacts") != [TQ.CANDIDATE_ROWS, TQ.GOLD_ROWS,
                                       TQ.SUMMARY]:
        _refuse("root campaign final-artifact contract is malformed.")
    resources = plan.get("worker_resources")
    if not isinstance(resources, list) or len(resources) != cap_workers \
            or any(not isinstance(record, dict) for record in resources):
        _refuse(f"root worker-resource preimage does not contain exactly "
                f"{cap_workers} worker record(s).")
    if [record.get("index") for record in resources] \
            != list(range(cap_workers)):
        _refuse("root worker-resource preimage is not indexed contiguously "
                "from zero in worker-slot order.")
    if content_digest(resources) != plan.get("worker_resources_sha256"):
        _refuse("root worker-resource preimage does not match its digest.")
    if plan.get("expected_pairs") != len(expected_pairs) \
            or plan.get("expected_pairs_sha256") \
            != pair_set_digest(expected_pairs):
        _refuse("root denominator does not match the pair set reconstructed "
                "from the frozen manifest, map, and candidate run.")
    if plan.get("projection_by_side") \
            != {side: None for side in TQ.SIDES}:
        _refuse("bounded fallback does not admit a reuse projection; its "
                "estimand must be the exact full pair population.")
    if plan.get("preflight_cache_authority") is not None:
        _refuse("bounded fallback does not admit a preflight cache; its "
                "compute-cap prefix must use the uncached scalar policy.")
    if plan.get("estimand_pairs_sha256") != pair_set_digest(expected_pairs):
        _refuse("root estimand digest differs from the exact full pair "
                "population.")
    expected_delta = {side: pair_set_digest(expected_pairs)
                      for side in TQ.SIDES}
    if plan.get("delta_pairs_sha256_by_side") != expected_delta:
        _refuse("root per-side delta-set digests differ from the exact full "
                "pair population.")
    if plan.get("final_artifact_types_by_side") != {
            side: "native_observation" for side in TQ.SIDES}:
        _refuse("bounded fallback requires native candidate and gold final-"
                "artifact types.")
    observation_ids = plan.get("observation_ids_by_side")
    if not isinstance(observation_ids, dict) \
            or len(set(observation_ids.values())) != 1:
        _refuse("bounded fallback requires one root-minted observation id "
                "across both native sides.")
    cap = plan.get("compute_cap")
    try:
        TQ.validate_compute_cap(
            cap, workers=cap_workers, expected=expected_pairs,
            campaign_dir=campaign_dir)
    except TQ.TestQualityRefused as exc:
        raise BoundRefused(str(exc)) from exc
    if content_digest(cap) != plan.get("compute_cap_sha256"):
        _refuse("root compute-cap declaration does not match its digest.")
    assertions = {
        "wall_clock_seconds": cap_seconds,
        "workers": cap_workers,
        "review_authority": cap_review_authority,
    }
    changed = sorted(key for key, value in assertions.items()
                     if cap.get(key) != value)
    if changed:
        _refuse("operator cap assertion differs from the pre-execution "
                f"declaration in field(s) {changed}.")
    return cap


def _expected_jobs(*, manifest: dict, by_mutant: dict, passed: dict,
                   gold_files: dict, cap_workers: int, policy: str) \
        -> tuple[set[tuple[str, str]],
                 dict[tuple[str, int], list[tuple[str, str]]]]:
    from . import test_quality as TQ
    from .mutation_run import ordered_pairs_for_slice

    mutants, restricted, _covering = TQ.population(
        manifest, by_mutant, passed)
    expected = TQ.expected_pairs(restricted)
    if not expected:
        _refuse("the frozen population maps no mutant to a passed item.")
    files_by_side = {"candidate": passed, "gold": gold_files}
    planned: dict[tuple[str, int], list[tuple[str, str]]] = {}
    for side in TQ.SIDES:
        slices = TQ.shard_mutants(
            mutants, restricted, files_by_side[side], cap_workers,
            policy=policy)
        for worker, mutant_slice in enumerate(slices):
            if not mutant_slice:
                continue
            pairs = ordered_pairs_for_slice(
                mutant_slice, restricted, files_by_side[side])
            if not pairs:
                _refuse(f"reconstructed {side} worker {worker} is empty.")
            if len(pairs) != len(set(pairs)):
                _refuse(f"reconstructed {side} worker {worker} pair sequence "
                        "contains a duplicate.")
            planned[(side, worker)] = pairs
    return expected, planned


def _validate_job(job: dict, *, pair_sequence: list[tuple[str, str]],
                  common_claims: dict, side_generated_sha256: str,
                  expected_observation_id: str,
                  cap_workers: int, assets: dict, validation_path: str,
                  manifest_path: str, map_path: str, release_path: str) \
        -> dict:
    from . import test_quality as TQ
    from .mutation_run import (EXECUTION_POLICY_SCALAR_V1, MutationAborted,
                               campaign_identity_digest, identity_version,
                               pair_set_digest,
                               validate_campaign_asset_claims)

    fields = {"side", "worker", "of", "out", "mutation_campaign_digest",
              "campaign_identity", "preflight_cache_authority_sha256"}
    if not isinstance(job, dict) or set(job) != fields:
        _refuse("root campaign job has missing or unknown fields.")
    identity = job.get("campaign_identity")
    try:
        digest = campaign_identity_digest(identity or {})
        validate_campaign_asset_claims(
            identity, assets, validation_path=validation_path,
            manifest_path=manifest_path, map_path=map_path,
            release_path=release_path)
        TQ.refuse_unpublishable_generation(
            identity.get("generation_provenance_class"),
            "the bounded mutation campaign")
    except (MutationAborted, TQ.TestQualityRefused) as exc:
        raise BoundRefused(str(exc)) from exc
    side, worker = job.get("side"), job.get("worker")
    if side not in TQ.SIDES or not _is_int(worker) \
            or not 0 <= worker < cap_workers:
        _refuse(f"root campaign job has invalid side/worker {side!r}/{worker!r}.")
    expected_out = os.path.join(TQ.SHARD_DIR, f"{side}.w{worker}.jsonl")
    if job.get("out") != expected_out:
        _refuse(f"root campaign job has unsafe or noncanonical output "
                f"{job.get('out')!r}; expected {expected_out!r}.")
    if job.get("of") != cap_workers or identity.get("of") != cap_workers \
            or identity.get("shard") != worker \
            or identity.get("side") != side:
        _refuse(f"root job and mutation identity disagree for {side} "
                f"worker {worker}.")
    if job.get("mutation_campaign_digest") != digest:
        _refuse(f"root job digest does not authenticate {side} worker {worker}.")
    if job.get("preflight_cache_authority_sha256") is not None:
        _refuse(f"{side} worker {worker} claims a preflight-cache authority "
                "in an uncached compute-cap campaign.")
    if identity.get("kind") != "test-quality" \
            or identity.get("shard_policy") \
            != TQ.SHARD_POLICY_BALANCED_PAIRS_V1:
        _refuse(f"{side} worker {worker} is not a policy-bound test-quality "
                "identity.")
    if identity_version(identity) != "v4" \
            or identity.get("execution_policy") \
            != EXECUTION_POLICY_SCALAR_V1 \
            or identity.get("batch_plan_sha256") is not None \
            or identity.get("max_batch_members") is not None \
            or identity.get("max_batch_instances") is not None \
            or identity.get("stack_reset_sha256") is not None \
            or identity.get("batch_journal_schema") is not None \
            or identity.get("preflight_cache_policy") is not None \
            or identity.get("reuse_projection_sha256") is not None \
            or identity.get("observation_id") \
            != expected_observation_id:
        _refuse(f"{side} worker {worker} is not the exact scalar, uncached, "
                "non-projected v4 execution identity and side observation "
                "required by this bound.")
    pair_set = set(pair_sequence)
    if identity.get("expected_pairs") != len(pair_set) \
            or identity.get("expected_pairs_sha256") \
            != pair_set_digest(pair_set):
        _refuse(f"{side} worker {worker} pair identity differs from the "
                "reconstructed schedule.")
    changed = sorted(key for key, value in common_claims.items()
                     if identity.get(key) != value)
    if changed:
        _refuse(f"{side} worker {worker} differs from exact run/gold/cap "
                f"claims in field(s) {sorted(set(changed))}.")
    if identity.get("solution_generated_tests_sha256") \
            != side_generated_sha256:
        _refuse(f"{side} worker {worker} is bound to different generated "
                "test bytes.")
    if any(identity.get(key) is not None for key in (
            "gold_results_sha256", "gold_results_attestation_sha256",
            "gold_provenance_class", "gold_attestation_manifest_digest",
            "gold_attestation_pairs_sha256", "gold_attestation_engine",
            "gold_attestation_engine_version")):
        _refuse("partial-reference fallback cannot inherit precomputed-gold "
                "claims.")
    if identity.get("sample") is not None \
            or identity.get("sample_seed") is not None:
        _refuse("bounded fallback cannot turn a sampled campaign into a full "
                "population interval.")
    return identity


def _validate_identity_cores(identities: dict[tuple[str, int], dict]) -> None:
    """Require one execution core per side and one shared comparison core."""
    from . import test_quality as TQ
    from .mutation_run import content_digest

    shard_specific = {"shard", "expected_pairs", "expected_pairs_sha256"}
    representatives = {}
    for side in TQ.SIDES:
        docs = [identity for (label, _worker), identity in identities.items()
                if label == side]
        cores = [{key: value for key, value in identity.items()
                  if key not in shard_specific}
                 for identity in docs]
        if not cores or len({content_digest(core) for core in cores}) != 1:
            _refuse(f"{side} shards carry mixed campaign execution cores.")
        representatives[side] = cores[0]
    side_specific = {"side", "solution_generated_tests_sha256"}
    comparison = {
        side: {key: value for key, value in core.items()
               if key not in side_specific}
        for side, core in representatives.items()
    }
    if comparison["candidate"] != comparison["gold"]:
        changed = sorted(
            key for key in set(comparison["candidate"]) | set(comparison["gold"])
            if comparison["candidate"].get(key) != comparison["gold"].get(key))
        _refuse("candidate and reference legs carry different shared "
                f"campaign execution field(s) {changed}.")


def _build_from_validated_inputs(*, campaign_dir: str, run_path: str,
                                 gold_baseline_path: str,
                                 validation_path: str, manifest_path: str,
                                 map_path: str, release_path: str,
                                 applier_path: str,
                                 assets: dict, generation: dict,
                                 cap_seconds: int, cap_workers: int,
                                 cap_review_authority: str,
                                 thresholds: Iterable,
                                 validate_runtime_resources: bool) \
        -> tuple[dict, dict]:
    """Build from already PR-2-validated assets (the selftest seam)."""
    from . import test_quality as TQ
    from .mutation_run import (CAMPAIGN_IDENTITY_FIELDS_V2_ADDED,
                               MutationAborted, candidate_digest,
                               completed_pairs,
                               pair_set_digest, provenance_path, sha256_file)

    if not _is_int(cap_seconds) or cap_seconds < 1:
        _refuse(f"--cap-seconds must be a positive integer, got "
                f"{cap_seconds!r}.")
    if not _is_int(cap_workers) or cap_workers < 1:
        _refuse(f"--cap-workers must be a positive integer, got "
                f"{cap_workers!r}.")
    campaign = _safe_campaign_directory(campaign_dir)
    run_path = _regular_file(run_path, "candidate run")
    gold_baseline_path = _regular_file(
        gold_baseline_path, "gold baseline run")
    validation_path = _regular_file(
        validation_path, "mutation validation report")
    manifest_path = _regular_file(manifest_path, "scored mutant manifest")
    map_path = _regular_file(map_path, "mutant map")
    release_path = _regular_file(release_path, "release")
    applier_path = _regular_file(applier_path, "mutation applier")
    if not isinstance(validate_runtime_resources, bool):
        _refuse("runtime-resource validation switch is not boolean.")

    try:
        run_rows = TQ.load_jsonl(run_path)
        gold_baseline_rows = TQ.load_jsonl(gold_baseline_path)
        passed = TQ.passed_solutions(run_rows)
        for number, row in enumerate(gold_baseline_rows, 1):
            iid = row.get("item_id") if isinstance(row, dict) else None
            if not isinstance(iid, str) or not iid:
                _refuse("gold baseline row " + str(number)
                        + " has missing or non-string item_id.")
        gold_files, gold_outcomes = TQ.gold_side(
            gold_baseline_rows, passed)
    except BoundRefused:
        raise
    except (TQ.TestQualityRefused, MutationAborted, AttributeError,
            KeyError, TypeError) as exc:
        raise BoundRefused(str(exc)) from exc
    run_items = [row.get("item_id") if isinstance(row, dict) else None
                 for row in run_rows]
    if set(gold_outcomes) != set(passed) or set(gold_files) != set(passed):
        missing = sorted(set(passed) - set(gold_outcomes))
        _refuse(f"gold baseline lacks passed candidate item(s) {missing[:3]}.")

    manifest = assets.get("manifest") if isinstance(assets, dict) else None
    mapping = assets.get("map") if isinstance(assets, dict) else None
    if not isinstance(manifest, dict) or not isinstance(mapping, dict) \
            or not isinstance(mapping.get("by_mutant"), dict):
        _refuse("validated mutation assets do not expose manifest/map facts.")
    try:
        expected, reconstructed_jobs = _expected_jobs(
            manifest=manifest, by_mutant=mapping["by_mutant"], passed=passed,
            gold_files=gold_files, cap_workers=cap_workers,
            policy=TQ.SHARD_POLICY_BALANCED_PAIRS_V1)
    except (TQ.TestQualityRefused, MutationAborted, AttributeError,
            KeyError, TypeError) as exc:
        raise BoundRefused(str(exc)) from exc

    campaign_paths = _campaign_tree_paths(campaign)
    shard_dir = os.path.join(campaign, TQ.SHARD_DIR)
    state_path = os.path.join(campaign, TQ.CAMPAIGN_STATE)
    state = _load_object(state_path, "root campaign state")
    plan = state.get("plan")
    try:
        TQ._validate_campaign_state(state, plan)  # canonical root validator
    except TQ.TestQualityRefused as exc:
        raise BoundRefused(str(exc)) from exc
    if state.get("status") != "interrupted":
        _refuse("bounded fallback requires a cooperatively stopped root "
                f"status of 'interrupted', got {state.get('status')!r}.")
    try:
        cap = _validate_root_plan(
            plan, expected_pairs=expected, cap_workers=cap_workers,
            cap_seconds=cap_seconds,
            cap_review_authority=cap_review_authority,
            campaign_dir=campaign)
    except (MutationAborted, TQ.TestQualityRefused) as exc:
        raise BoundRefused(str(exc)) from exc
    interruption = state.get("interruption")
    if not isinstance(interruption, dict) \
            or interruption.get("schema") \
            != TQ.TEST_QUALITY_INTERRUPTION_SCHEMA \
            or interruption.get("kind") != TQ.INTERRUPTION_COMPUTE_CAP \
            or interruption.get("compute_cap_sha256") \
            != plan.get("compute_cap_sha256"):
        _refuse("bounded fallback requires the typed compute_cap_reached "
                "interruption bound to this exact cap; manual or untyped "
                "cancellation is not a cap result.")

    planned_jobs: dict[tuple[str, int], dict] = {}
    for job in plan["jobs"]:
        if not isinstance(job, dict):
            _refuse("root campaign jobs must be objects.")
        side, worker = job.get("side"), job.get("worker")
        if not isinstance(side, str) or not _is_int(worker):
            _refuse("root campaign job has non-string side or non-integer "
                    "worker identity.")
        key = (side, worker)
        if key in planned_jobs:
            _refuse(f"root campaign repeats job {key!r}.")
        planned_jobs[key] = job
    if set(planned_jobs) != set(reconstructed_jobs):
        _refuse("root job set differs from the schedule reconstructed from "
                f"frozen inputs: missing={sorted(set(reconstructed_jobs)-set(planned_jobs))[:3]}, "
                f"unexpected={sorted(set(planned_jobs)-set(reconstructed_jobs))[:3]}.")

    try:
        candidate_generated = candidate_digest(passed)
        gold_generated = candidate_digest(gold_files)
    except (MutationAborted, AttributeError, KeyError, TypeError,
            ValueError) as exc:
        raise BoundRefused(str(exc)) from exc
    generation_claims = {
        key: generation.get(key)
        for key in CAMPAIGN_IDENTITY_FIELDS_V2_ADDED
    }
    common_claims = {
        **generation_claims,
        "candidate_run_sha256": sha256_file(run_path),
        "candidate_generated_tests_sha256": candidate_generated,
        "gold_baseline_sha256": sha256_file(gold_baseline_path),
        "gold_generated_tests_sha256": gold_generated,
        "applier_sha256": sha256_file(applier_path),
        "worker_resources_sha256": plan["worker_resources_sha256"],
        "compute_cap_sha256": plan["compute_cap_sha256"],
        "estimand_pairs_sha256": plan["estimand_pairs_sha256"],
    }

    identities = {}
    for key, job in planned_jobs.items():
        side = key[0]
        identities[key] = _validate_job(
            job, pair_sequence=reconstructed_jobs[key],
            common_claims=common_claims,
            side_generated_sha256=(candidate_generated
                                   if side == "candidate" else gold_generated),
            expected_observation_id=plan["observation_ids_by_side"][side],
            cap_workers=cap_workers, assets=assets,
            validation_path=validation_path, manifest_path=manifest_path,
            map_path=map_path, release_path=release_path)
    _validate_identity_cores(identities)
    timeouts = {identity.get("timeout_seconds")
                for identity in identities.values()}
    if len(timeouts) != 1:
        _refuse(f"root jobs carry mixed per-pair timeouts {sorted(timeouts)!r}.")

    allowed_names = set()
    for job in planned_jobs.values():
        name = os.path.basename(job["out"])
        allowed_names.update((name, name + ".provenance.json"))
    got_names = set(os.listdir(shard_dir))
    unexpected = sorted(got_names - allowed_names)
    if unexpected:
        _refuse(f"campaign contains unplanned shard artifact(s) "
                f"{unexpected[:5]}.")
    for name in got_names:
        path = os.path.join(shard_dir, name)
        _regular_file(path, "shard evidence")
    initial_snapshot = _campaign_snapshot(campaign_paths)
    input_paths = {
        "candidate_run": run_path,
        "gold_baseline": gold_baseline_path,
        "mutation_validation": validation_path,
        "manifest": manifest_path,
        "map": map_path,
        "release": release_path,
        "mutation_applier": applier_path,
        "root_campaign": state_path,
    }
    generation_sidecar = run_path + ".campaign.json"
    if os.path.isfile(generation_sidecar) and not os.path.islink(
            generation_sidecar):
        input_paths["candidate_generation_campaign"] = generation_sidecar
    initial_input_snapshot = _campaign_snapshot(input_paths.values())

    candidate_rows: list[dict] = []
    reference_rows: list[dict] = []
    executed_prefix = []
    runtime_resources_validated = False
    for key in sorted(planned_jobs):
        side, worker = key
        job = planned_jobs[key]
        identity = identities[key]
        rows_path = os.path.join(campaign, job["out"])
        side_path = provenance_path(rows_path)
        rows_exist = os.path.isfile(rows_path) and not os.path.islink(rows_path)
        side_exists = os.path.isfile(side_path) and not os.path.islink(side_path)
        if rows_exist != side_exists:
            _refuse(f"{side} worker {worker} has only one of rows/provenance.")
        if side == "candidate" and not rows_exist:
            _refuse(f"candidate worker {worker} is absent; the candidate leg "
                    "must be complete before its verdicts can partition the "
                    "unexecuted reference pairs.")
        if not rows_exist:
            expected_sequence = reconstructed_jobs[key]
            executed_prefix.append({
                "side": side, "worker": worker, "status": "absent",
                "rows": 0, "expected_pairs": len(expected_sequence),
                "executed_pairs_sha256": pair_set_digest(set()),
                "expected_sequence_sha256":
                    _pair_sequence_digest(expected_sequence),
                "executed_prefix_sha256": _pair_sequence_digest(()),
                "rows_sha256": None,
            })
            continue
        try:
            rows = TQ.load_jsonl(rows_path)
            if any(not isinstance(row, dict) for row in rows):
                _refuse(f"{side} worker {worker} contains a non-object row.")
            done = completed_pairs(
                rows_path, identity,
                expected_pairs=set(reconstructed_jobs[key]),
                require_complete=(side == "candidate"),
                expected_shard_policy=TQ.SHARD_POLICY_BALANCED_PAIRS_V1)
        except (MutationAborted, TQ.TestQualityRefused,
                AttributeError, TypeError) as exc:
            raise BoundRefused(str(exc)) from exc
        sidecar = _load_object(side_path, "mutation shard provenance")
        if sidecar.get("worker_resources") != plan["worker_resources"]:
            _refuse(f"{side} worker {worker} does not preserve the exact "
                    "root worker-resource preimage.")
        if validate_runtime_resources and not runtime_resources_validated:
            from .mutation_run import validate_worker_resource_evidence
            try:
                validate_worker_resource_evidence(sidecar, identity)
            except MutationAborted as exc:
                raise BoundRefused(str(exc)) from exc
            runtime_resources_validated = True
        status = sidecar.get("status")
        expected_sequence = reconstructed_jobs[key]
        row_sequence = [
            (row.get("item_id"), row.get("mutant_id")) for row in rows]
        if side == "candidate":
            if status != "complete" or done != set(expected_sequence):
                _refuse(f"candidate worker {worker} is not exact and complete.")
            if row_sequence != expected_sequence:
                _refuse(f"candidate worker {worker} rows are not the exact "
                        "deterministic full pair sequence.")
        elif status not in {"complete", "interrupted"}:
            _refuse(f"reference worker {worker} status {status!r} is neither "
                    "complete nor cooperatively interrupted.")
        elif status == "complete" and done != set(expected_sequence):
            _refuse(f"reference worker {worker} claims complete with a short "
                    "pair set.")
        elif row_sequence != expected_sequence[:len(row_sequence)]:
            _refuse(f"reference worker {worker} rows are not an exact ordered "
                    "prefix of its deterministic pair sequence.")
        if {(row.get("item_id"), row.get("mutant_id")) for row in rows} != done:
            _refuse(f"{side} worker {worker} row view differs from its "
                    "authenticated pair set.")
        (candidate_rows if side == "candidate" else reference_rows).extend(rows)
        executed_prefix.append({
            "side": side, "worker": worker, "status": status,
            "rows": len(done),
            "expected_pairs": len(expected_sequence),
            "executed_pairs_sha256": pair_set_digest(done),
            "expected_sequence_sha256":
                _pair_sequence_digest(expected_sequence),
            "executed_prefix_sha256":
                _pair_sequence_digest(row_sequence),
            "rows_sha256": sidecar.get("rows_sha256"),
        })

    if validate_runtime_resources and not runtime_resources_validated:
        _refuse("no candidate shard supplied durable worker-runtime evidence.")

    final_paths = _campaign_tree_paths(campaign)
    final_snapshot = _campaign_snapshot(final_paths)
    if set(final_paths) != set(campaign_paths) \
            or final_snapshot != initial_snapshot:
        _refuse("campaign evidence changed while the bound was being read; "
                "wait for a stable interrupted campaign and retry.")
    final_input_snapshot = _campaign_snapshot(input_paths.values())
    if final_input_snapshot != initial_input_snapshot:
        _refuse("a bound input changed while it was being read; retry only "
                "after the immutable inputs are stable.")
    computed = compute_bounds(
        run_items=run_items, passed_items=passed,
        expected_pairs=expected, candidate_rows=candidate_rows,
        reference_rows=reference_rows, gold_baseline=gold_outcomes,
        thresholds=thresholds)

    report = {
        "schema": BOUND_SCHEMA,
        "state": "bounded",
        "publishable": False,
        "point_estimate": None,
        "method": {
            "schema": METHOD_SCHEMA,
            "implementation": {
                "path": "benchmark/r2t/bench/mutation_bounds.py",
                "sha256": _sha256_file(__file__),
            },
            "review_source": {"path": REVIEW_SOURCE,
                              "sha256": REVIEW_SOURCE_SHA256},
            "candidate_partition": {
                "upper": "(K + RK) / (D + RK)",
                "lower": "K / (D + RS)",
            },
            "torn_tail_policy": "refuse_unattested_or_unparseable_bytes",
        },
        "compute_cap": {
            "declaration": cap,
            "sha256": plan["compute_cap_sha256"],
        },
        "metric": {
            "name": "candidate_pass_with_reference_recall_threshold",
            "aggregation": "count_and_rate_over_exact_candidate_run",
            "candidate_failures": "count_as_not_satisfying_threshold",
        },
        "campaign": {
            "directory": campaign,
            "status": state["status"],
            "interruption": interruption,
            "interruption_detail": state["error"],
            "plan_sha256": state["plan_sha256"],
            "pair_timeout_seconds": next(iter(timeouts)),
            "worker_runtime_evidence_validated":
                runtime_resources_validated,
            "expected_pairs": len(expected),
            "expected_pairs_sha256": pair_set_digest(expected),
        },
        "denominator": computed["denominator"],
        "executed_prefix": executed_prefix,
        "candidate_leg": {"rows": len(candidate_rows), "complete": True,
                          "torn_tail_lines": 0},
        "reference_leg": {
            "rows": len(reference_rows),
            "unexecuted_pairs": len(expected) - len(reference_rows),
            "torn_tail_lines": 0,
        },
        "torn_tail_lines": 0,
        "reference_infrastructure_outcomes":
            computed["reference_infrastructure_outcomes"],
        "reference_kills_ignored_ineligible_baseline":
            computed["reference_kills_ignored_ineligible_baseline"],
        "threshold_bounds": computed["threshold_bounds"],
        "per_item": computed["per_item"],
        "inputs": {
            name: {"path": path, "sha256": final_input_snapshot[path]}
            for name, path in sorted(input_paths.items())
        },
        "campaign_evidence": [
            {"path": path, "sha256": digest}
            for path, digest in sorted(final_snapshot.items())
        ],
    }
    # A point estimate must be structurally impossible to consume by mistake.
    # ``point_estimate: null`` is an explicit disclosure; no nested ``value``
    # key or partial recall is emitted anywhere in the document.
    return report, final_snapshot


def build_report(*, campaign_dir: str, run_path: str,
                 gold_baseline_path: str, mutation_validation_path: str,
                 manifest_path: str, map_path: str, release_path: str,
                 cap_seconds: int, cap_workers: int,
                 cap_review_authority: str,
                 thresholds: Iterable = ("1.0",)) -> tuple[dict, dict]:
    """Validate all durable inputs and return ``(report, campaign snapshot)``."""
    from ..data import mutation_attestation as A
    from .mutation_run import (MutationAborted, binding_for,
                               generation_evidence_for_run)
    from . import test_quality as TQ

    try:
        assets = A.validate_campaign_asset_inputs(
            mutation_validation_path, manifest_path=manifest_path,
            map_path=map_path, release_path=release_path,
            require_release_ready=True)
        run_rows = TQ.load_jsonl(run_path)
        generation = generation_evidence_for_run(run_path, run_rows)
        generation.pop("legacy_generation_evidence", None)
        engine_dir, applier = binding_for(assets["manifest"].get("engine"))
        applier_path = os.path.join(engine_dir, applier.source)
    except (A.MutationAssetRefused, MutationAborted,
            TQ.TestQualityRefused, OSError, ValueError) as exc:
        raise BoundRefused(str(exc)) from exc
    return _build_from_validated_inputs(
        campaign_dir=campaign_dir, run_path=run_path,
        gold_baseline_path=gold_baseline_path,
        validation_path=mutation_validation_path,
        manifest_path=manifest_path, map_path=map_path,
        release_path=release_path, applier_path=applier_path,
        assets=assets, generation=generation,
        cap_seconds=cap_seconds, cap_workers=cap_workers,
        cap_review_authority=cap_review_authority,
        thresholds=thresholds, validate_runtime_resources=True)


def write_report(out_path: str, **kwargs) -> dict:
    """Build and atomically write a new report outside the campaign tree."""
    campaign = _safe_campaign_directory(kwargs["campaign_dir"])
    out = _output_outside_campaign(campaign, out_path)
    report, snapshot = build_report(**kwargs)
    current_paths = _campaign_tree_paths(campaign)
    if set(current_paths) != set(snapshot) \
            or _campaign_snapshot(current_paths) != snapshot:
        _refuse("campaign evidence changed before the bound output commit.")
    _durable_write_new_json(out, report)
    return report


def selftest() -> int:
    """Arithmetic probes plus an authenticated interrupted-campaign fixture."""
    import copy
    import itertools
    import subprocess
    import tempfile

    from . import test_quality as TQ
    from .mutation_run import (atomic_write_json, campaign_identity_digest,
                               candidate_digest, content_digest,
                               ordered_pairs_for_slice,
                               row_identity_stamp, sha256_file,
                               write_shard_provenance)

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    def refused(fn, contains="REFUSED"):
        try:
            fn()
        except BoundRefused as exc:
            return contains in str(exc)
        return False

    lower, upper = recall_envelope(1, 2, 2, 3)
    check("reviewed envelope arithmetic",
          lower == Fraction(1, 5) and upper == Fraction(3, 4))
    check("RS-only futures may create a denominator but cannot create positive "
          "recall, so the interval is undefined",
          recall_envelope(0, 0, 0, 4) == (None, None))
    check("RK-only positive-recall reachability keeps a conservative zero "
          "lower endpoint",
          recall_envelope(0, 0, 3, 0) == (Fraction(0), Fraction(1)))
    check("invalid count state refuses",
          refused(lambda: recall_envelope(2, 1, 0, 0), "exceeds"))
    exact_threshold = _threshold(
        "0.123456789012345678901234567890123456789")
    check("threshold canonicalisation preserves more than 28 digits",
          exact_threshold[0]
          == "0.123456789012345678901234567890123456789")

    # Mutation probe: enumerate every possible future reference kill subset
    # over RK candidate kills and RS candidate survivals.  Every scorable
    # completion must remain inside the computed envelope; a completion with
    # no denominator is a false positive-threshold binary result and is why
    # the lower end above is conservatively zero.
    for killed, denominator, rk, rs in ((1, 2, 2, 3), (0, 0, 2, 1),
                                        (2, 3, 0, 4), (0, 1, 5, 0)):
        lo, hi = recall_envelope(killed, denominator, rk, rs)
        sound = True
        for kill_bits in itertools.product((0, 1), repeat=rk):
            for survive_bits in itertools.product((0, 1), repeat=rs):
                final_k = killed + sum(kill_bits)
                final_d = denominator + sum(kill_bits) + sum(survive_bits)
                if final_d:
                    final = Fraction(final_k, final_d)
                    sound = sound and lo <= final <= hi
        check(f"all completions bracketed for K/D/RK/RS "
              f"{killed}/{denominator}/{rk}/{rs}", sound)

    # Tightening probes for each kind of newly adjudicated reference row.
    lo0, hi0 = recall_envelope(1, 2, 2, 3)
    lo_rk_kill, hi_rk_kill = recall_envelope(2, 3, 1, 3)
    lo_rk_survive, hi_rk_survive = recall_envelope(1, 2, 1, 3)
    lo_rs_kill, hi_rs_kill = recall_envelope(1, 3, 2, 2)
    lo_rs_survive, hi_rs_survive = recall_envelope(1, 2, 2, 2)
    all_lower = (lo_rk_kill, lo_rk_survive, lo_rs_kill, lo_rs_survive)
    all_upper = (hi_rk_kill, hi_rk_survive, hi_rs_kill, hi_rs_survive)
    check("lower endpoint is nondecreasing for RK-kill, RK-survival, "
          "RS-kill, and RS-survival adjudications",
          all(value >= lo0 for value in all_lower))
    check("upper endpoint is nonincreasing for RK-kill, RK-survival, "
          "RS-kill, and RS-survival adjudications",
          all(value <= hi0 for value in all_upper))

    expected = {("i", "m1"), ("i", "m2"), ("i", "m3")}
    candidate = [
        {"item_id": "i", "mutant_id": "m1", "outcome": "failed"},
        {"item_id": "i", "mutant_id": "m2", "outcome": "passed"},
        {"item_id": "i", "mutant_id": "m3",
         "outcome": "container_error"},
    ]
    partial = [{"item_id": "i", "mutant_id": "m1",
                "outcome": "passed"}]
    result = compute_bounds(
        run_items=["i", "failed-item"], passed_items=["i"],
        expected_pairs=expected, candidate_rows=candidate,
        reference_rows=partial, gold_baseline={"i": "passed"},
        thresholds=("0.5", "1.0"))
    item = result["per_item"]["i"]
    check("candidate infrastructure is excluded, not called survival",
          item["unadjudicated_candidate_infrastructure"] == 1
          and item["unadjudicated_candidate_survivals"] == 1)
    check("run denominator includes candidate failures",
          result["threshold_bounds"][0]["denominator"] == 2)
    check("no point value is present in pure bounds",
          '"value"' not in json.dumps(result, sort_keys=True))
    check("incomplete candidate leg refuses",
          refused(lambda: compute_bounds(
              run_items=["i"], passed_items=["i"],
              expected_pairs=expected, candidate_rows=candidate[:-1],
              reference_rows=partial, gold_baseline={"i": "passed"})),
          "")
    check("duplicate reference pair refuses",
          refused(lambda: compute_bounds(
              run_items=["i"], passed_items=["i"],
              expected_pairs=expected, candidate_rows=candidate,
              reference_rows=partial * 2,
              gold_baseline={"i": "passed"})), "")
    check("unexpected reference pair refuses",
          refused(lambda: compute_bounds(
              run_items=["i"], passed_items=["i"],
              expected_pairs=expected, candidate_rows=candidate,
              reference_rows=[{"item_id": "i", "mutant_id": "alien",
                               "outcome": "passed"}],
              gold_baseline={"i": "passed"})), "")
    check("duplicate normalized threshold refuses",
          refused(lambda: compute_bounds(
              run_items=["i"], passed_items=["i"],
              expected_pairs=expected, candidate_rows=candidate,
              reference_rows=partial, gold_baseline={"i": "passed"},
              thresholds=("1", "1.0"))), "")

    def write_json(path, value):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(value, fh, sort_keys=True)
            fh.write("\n")

    def write_jsonl(path, rows):
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    repository = os.path.dirname(os.path.realpath(os.path.join(
        os.path.dirname(__file__), os.pardir, os.pardir)))
    review_commit = subprocess.run(
        ["git", "-C", repository, "rev-parse", "--verify",
         "HEAD^{commit}"], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE).stdout.decode("ascii").strip()
    review_authority = (
        "benchmark/MUTATION_BOUND_OPERATOR.md@" + review_commit)
    TQ.validate_compute_cap_review_authority(review_authority)

    def fixture(root, *, omit_candidate=None, torn_reference=False,
                identity_tamper=False, plan_extra=False,
                cap_tamper_field=None, manual_cancel=False,
                shard_cap_missing=False, reference_mode="partial",
                candidate_reordered=False):
        campaign = os.path.join(root, "campaign")
        shards = os.path.join(campaign, TQ.SHARD_DIR)
        os.makedirs(shards)
        run_path = os.path.join(root, "candidate.jsonl")
        gold_path = os.path.join(root, "gold.jsonl")
        validation_path = os.path.join(root, "validation.json")
        manifest_path = os.path.join(root, "manifest.json")
        map_path = os.path.join(root, "map.json")
        release_path = os.path.join(root, "release.jsonl")
        applier_path = os.path.join(root, "Mutate.java")
        files = [{"file_path": "tests/Generated.java",
                  "code": "class Generated {}"}]
        gold_files = [{"file_path": "tests/Reference.java",
                       "code": "class Reference {}"}]
        run_rows = [
            {"item_id": "i", "outcome": "passed", "produced_files": files},
            {"item_id": "f", "outcome": "failed", "produced_files": []},
        ]
        gold_rows = [
            {"item_id": "i", "outcome": "passed",
             "produced_files": gold_files},
        ]
        write_jsonl(run_path, run_rows)
        write_jsonl(gold_path, gold_rows)
        write_json(validation_path, {})
        with open(applier_path, "w", encoding="utf-8") as fh:
            fh.write("final class Mutate {}\n")
        write_jsonl(release_path, [{"item_id": "i"}, {"item_id": "f"}])
        mutants = [{"id": "m1"}, {"id": "m2"}, {"id": "m3"}]
        manifest = {"mutants": mutants, "digest": "a" * 64,
                    "engine": "fixture-java", "engine_version": "1.0",
                    "parser": "fixture-parser"}
        mapping = {"by_mutant": {mutant["id"]: ["i"]
                                  for mutant in mutants}}
        write_json(manifest_path, manifest)
        write_json(map_path, mapping)
        resources = [{"index": 0, "fixture": "w0"},
                     {"index": 1, "fixture": "w1"}]
        generation = {
            "generation_provenance_class": "native_v2",
            "generation_attempt_id": "fixture-attempt",
            "generation_campaign_digest": "0123456789abcdef",
            "generation_agent_runtime_sha256": "e" * 64,
            "generation_network_semantics": "fixture_closed",
            "generation_condition": "c3",
            "generation_protocol_version": 4,
            "generation_protocol_digest": "bda1d9bcb1852e92",
            "generation_native_budget": {},
        }
        inputs = {
            **generation,
            "asset_index_sha256": "0" * 64,
            "asset_project": "fixture",
            "mutation_validation_sha256": sha256_file(validation_path),
            "mutation_validation_class": "native",
            "manifest_sha256": sha256_file(manifest_path),
            "manifest_digest": manifest["digest"],
            "map_sha256": sha256_file(map_path),
            "release_sha256": sha256_file(release_path),
            "candidate_run_sha256": sha256_file(run_path),
            "candidate_generated_tests_sha256": candidate_digest({"i": files}),
            "gold_baseline_sha256": sha256_file(gold_path),
            "gold_generated_tests_sha256": candidate_digest({"i": gold_files}),
            "gold_results_sha256": None,
            "gold_results_attestation_sha256": None,
            "gold_provenance_class": None,
            "gold_attestation_manifest_digest": None,
            "gold_attestation_pairs_sha256": None,
            "gold_attestation_engine": None,
            "gold_attestation_engine_version": None,
            "applier_sha256": sha256_file(applier_path),
            "substrate_baseline_sha256": "2" * 64,
            "worker_resources_sha256": content_digest(resources),
            "harness_version": "fixture-harness",
            "container_image_digest": "sha256:" + "3" * 64,
            "workspace_seed_digest": "4" * 64,
            "database_dump_digest": "5" * 64,
            "engine": manifest["engine"],
            "engine_version": manifest["engine_version"],
            "parser": manifest["parser"],
        }
        passed = TQ.passed_solutions(run_rows)
        gold_side_files, _outcomes = TQ.gold_side(gold_rows, passed)
        selected, restricted, _covering = TQ.population(
            manifest, mapping["by_mutant"], passed)
        expected_pairs = TQ.expected_pairs(restricted)
        cap = TQ.build_compute_cap(
            wall_clock_seconds=120, workers=2, expected=expected_pairs,
            campaign_dir=campaign, review_authority=review_authority)
        cap_sha256 = content_digest(cap)
        # The pair digest authority lives in mutation_run, not test_quality.
        from .mutation_run import pair_set_digest as _pair_set_digest
        estimand_pairs_sha256 = _pair_set_digest(expected_pairs)
        jobs = TQ.plan_jobs(
            selected, {"candidate": passed, "gold": gold_side_files},
            restricted, 2, campaign, identity_inputs=inputs,
            timeout=17, shard_policy=TQ.SHARD_POLICY_BALANCED_PAIRS_V1,
            compute_cap_sha256=cap_sha256,
            estimand_pairs_sha256=estimand_pairs_sha256,
            observation_id="a" * 32)
        # plan_jobs receives the resource digest through identity_inputs; the
        # root stores the auditable preimage separately.
        plan = TQ.build_test_quality_campaign_plan(
            jobs, expected=expected_pairs, worker_resources=resources,
            campaign_dir=campaign, compute_cap=cap)

        candidate_outcomes = {"m1": "failed", "m2": "passed",
                              "m3": "container_error"}
        paths = {}
        for job in jobs:
            side, worker = job["side"], job["worker"]
            if side == "candidate" and worker == omit_candidate:
                continue
            job_pairs = ordered_pairs_for_slice(
                job["mutants"], job["by_mutant"], job["files_by_item"])
            if side == "candidate" and candidate_reordered \
                    and len(job_pairs) > 1:
                job_pairs = list(reversed(job_pairs))
            if side == "gold":
                if reference_mode == "partial":
                    if any(key[0] == "gold" for key in paths):
                        continue
                    job_pairs = job_pairs[:1]
                elif reference_mode == "empty":
                    if any(key[0] == "gold" for key in paths):
                        continue
                    job_pairs = []
                elif reference_mode == "later_only":
                    if len(job_pairs) < 2 or any(
                            key[0] == "gold" for key in paths):
                        continue
                    job_pairs = job_pairs[1:2]
                elif reference_mode == "reordered":
                    if len(job_pairs) < 2 or any(
                            key[0] == "gold" for key in paths):
                        continue
                    job_pairs = list(reversed(job_pairs))
                elif reference_mode != "full":
                    raise AssertionError(reference_mode)
            rows_path = job["out"]
            write_jsonl(rows_path, [])
            provenance = {
                "shard_policy": TQ.SHARD_POLICY_BALANCED_PAIRS_V1,
                "worker_resources": resources,
            }
            write_shard_provenance(
                rows_path, job["identity"], "running",
                provenance=provenance)
            rows = []
            for item_id, mutant_id in job_pairs:
                outcome = (candidate_outcomes[mutant_id]
                           if side == "candidate" else "failed")
                rows.append({
                    "item_id": item_id, "mutant_id": mutant_id,
                    "outcome": outcome,
                    **row_identity_stamp(job["identity"]),
                })
            write_jsonl(rows_path, rows)
            write_shard_provenance(
                rows_path, job["identity"], "running",
                provenance=provenance)
            status = ("complete" if side == "candidate"
                      or reference_mode == "full" else "interrupted")
            write_shard_provenance(
                rows_path, job["identity"], status,
                provenance=provenance,
                error=("compute cap" if status == "interrupted" else None))
            paths[(side, worker)] = rows_path

        if identity_tamper:
            altered = plan["jobs"][0]
            altered["campaign_identity"] = copy.deepcopy(
                altered["campaign_identity"])
            altered["campaign_identity"]["candidate_run_sha256"] = "f" * 64
            altered["mutation_campaign_digest"] = campaign_identity_digest(
                altered["campaign_identity"])
        if plan_extra:
            plan["post_hoc_note"] = "not part of the schema"
        if cap_tamper_field is not None:
            if cap_tamper_field == "wall_clock_seconds":
                plan["compute_cap"][cap_tamper_field] += 1
            elif cap_tamper_field == "workers":
                plan["compute_cap"][cap_tamper_field] += 1
            elif cap_tamper_field == "expected_pairs_sha256":
                plan["compute_cap"][cap_tamper_field] = "9" * 64
            elif cap_tamper_field == "campaign_dir":
                plan["compute_cap"][cap_tamper_field] += "-other"
            elif cap_tamper_field == "review_authority":
                plan["compute_cap"][cap_tamper_field] += "-other"
            else:
                raise AssertionError(cap_tamper_field)
        if shard_cap_missing:
            plan["jobs"][0]["campaign_identity"].pop(
                "compute_cap_sha256")
        interruption = TQ.campaign_interruption(
            TQ.INTERRUPTION_OPERATOR if manual_cancel
            else TQ.INTERRUPTION_COMPUTE_CAP, plan)
        state = {
            "schema": TQ.TEST_QUALITY_CAMPAIGN_SCHEMA_V2,
            "status": "interrupted",
            "plan": plan,
            "plan_sha256": content_digest(plan),
            "history": ["running", "interrupted"],
            "artifacts": {},
            "error": "precommitted compute cap reached",
            "interruption": interruption,
        }
        atomic_write_json(os.path.join(campaign, TQ.CAMPAIGN_STATE), state,
                          refuse_existing=True)
        if torn_reference:
            reference_path = next(
                path for (side, _worker), path in paths.items()
                if side == "gold")
            with open(reference_path, "ab") as fh:
                fh.write(b'{"torn":')
        assets = {
            "validation_class": "native",
            "validation_sha256": sha256_file(validation_path),
            "asset_index_sha256": "0" * 64,
            "asset_project": "fixture",
            "manifest": manifest,
            "map": mapping,
        }
        kwargs = {
            "campaign_dir": campaign,
            "run_path": run_path,
            "gold_baseline_path": gold_path,
            "validation_path": validation_path,
            "manifest_path": manifest_path,
            "map_path": map_path,
            "release_path": release_path,
            "applier_path": applier_path,
            "assets": assets,
            "generation": generation,
            "cap_seconds": 120,
            "cap_workers": 2,
            "cap_review_authority": review_authority,
            "thresholds": ("0.8", "1.0"),
            "validate_runtime_resources": False,
        }
        return kwargs

    with tempfile.TemporaryDirectory(prefix="r2t-bound-selftest-") as tmp:
        good = fixture(os.path.join(tmp, "good"))
        report, _snapshot = _build_from_validated_inputs(**good)
        encoded = json.dumps(report, sort_keys=True)
        check("authenticated interrupted campaign produces only a bound",
              report["state"] == "bounded"
              and report["publishable"] is False
              and report["point_estimate"] is None
              and '"value"' not in encoded)
        check("candidate complete and reference prefix are explicit",
              report["candidate_leg"]["complete"] is True
              and report["candidate_leg"]["rows"] == 3
              and report["reference_leg"]["rows"] == 1
              and report["reference_leg"]["torn_tail_lines"] == 0)
        check("cap and legacy review-source digest travel with the bound",
              report["compute_cap"]["declaration"]["wall_clock_seconds"]
              == 120
              and report["compute_cap"]["declaration"]["workers"] == 2
              and report["compute_cap"]["declaration"]["review_authority"]
              == good["cap_review_authority"]
              and report["compute_cap"]["sha256"]
              == report["campaign"]["interruption"][
                  "compute_cap_sha256"]
              and report["method"]["review_source"]["sha256"]
              == REVIEW_SOURCE_SHA256)
        check("bound output inside evidence tree refuses",
              refused(lambda: _output_outside_campaign(
                  good["campaign_dir"],
                  os.path.join(good["campaign_dir"], "bound.json")),
                      "outside"))
        durable_dir = os.path.join(tmp, "durable-output")
        os.makedirs(durable_dir)
        durable_path = os.path.join(durable_dir, "bound.json")
        _durable_write_new_json(durable_path, {"proof": "durable"})
        check("durable publication commits exact JSON and removes temp link",
              _load_object(durable_path, "durable selftest output")
              == {"proof": "durable"}
              and os.listdir(durable_dir) == ["bound.json"])
        sentinel_path = os.path.join(durable_dir, "sentinel.json")
        with open(sentinel_path, "wb") as fh:
            fh.write(b"preserve-me\n")
        check("kernel no-clobber publication preserves a concurrent winner",
              refused(lambda: _durable_write_new_json(
                  sentinel_path, {"replacement": True}), "already exists")
              and open(sentinel_path, "rb").read() == b"preserve-me\n")

        missing = fixture(os.path.join(tmp, "missing"), omit_candidate=1)
        check("missing candidate shard refuses",
              refused(lambda: _build_from_validated_inputs(**missing),
                      "candidate worker"))
        torn = fixture(os.path.join(tmp, "torn"), torn_reference=True)
        check("unattested torn reference tail refuses",
              refused(lambda: _build_from_validated_inputs(**torn),
                      "not JSON"))
        mixed = fixture(os.path.join(tmp, "mixed"), identity_tamper=True)
        check("coordinated root identity change refuses",
              refused(lambda: _build_from_validated_inputs(**mixed)))
        unknown = fixture(os.path.join(tmp, "unknown"), plan_extra=True)
        check("unknown root-plan field refuses",
              refused(lambda: _build_from_validated_inputs(**unknown),
                      "missing or unknown"))
        wrong_cap = fixture(os.path.join(tmp, "wrong-cap"))
        wrong_cap["cap_workers"] = 3
        check("operator worker cap must match authenticated plan",
              refused(lambda: _build_from_validated_inputs(**wrong_cap)))
        wrong_seconds = fixture(os.path.join(tmp, "wrong-seconds"))
        wrong_seconds["cap_seconds"] = 121
        check("operator seconds must match authenticated cap",
              refused(lambda: _build_from_validated_inputs(**wrong_seconds),
                      "wall_clock_seconds"))
        wrong_review = fixture(os.path.join(tmp, "wrong-review"))
        wrong_review["cap_review_authority"] += "-other"
        check("operator review identity must match authenticated cap",
              refused(lambda: _build_from_validated_inputs(**wrong_review),
                      "review_authority"))
        for field in ("wall_clock_seconds", "workers",
                      "expected_pairs_sha256", "campaign_dir",
                      "review_authority"):
            tampered_cap = fixture(
                os.path.join(tmp, "tampered-cap-" + field.replace("_", "-")),
                cap_tamper_field=field)
            check(f"cap {field} tamper refuses",
                  refused(lambda value=tampered_cap:
                          _build_from_validated_inputs(**value)))
        manual = fixture(os.path.join(tmp, "manual"), manual_cancel=True)
        check("manual cancellation cannot masquerade as cap expiry",
              refused(lambda: _build_from_validated_inputs(**manual),
                      "compute_cap_reached"))
        missing_cap_identity = fixture(
            os.path.join(tmp, "missing-cap-identity"),
            shard_cap_missing=True)
        check("a shard missing cap identity refuses",
              refused(lambda: _build_from_validated_inputs(
                  **missing_cap_identity)))

        empty_prefix = fixture(os.path.join(tmp, "empty-prefix"),
                               reference_mode="empty")
        empty_report, _ = _build_from_validated_inputs(**empty_prefix)
        check("empty reference prefix is admitted exactly",
              empty_report["reference_leg"]["rows"] == 0)
        full_prefix = fixture(os.path.join(tmp, "full-prefix"),
                              reference_mode="full")
        full_report, _ = _build_from_validated_inputs(**full_prefix)
        check("full reference prefix is admitted exactly",
              full_report["reference_leg"]["unexecuted_pairs"] == 0)
        later_only = fixture(os.path.join(tmp, "later-only"),
                             reference_mode="later_only")
        check("reference prefix cannot skip an earlier pair",
              refused(lambda: _build_from_validated_inputs(**later_only),
                      "ordered prefix"))
        reordered_reference = fixture(
            os.path.join(tmp, "reordered-reference"),
            reference_mode="reordered")
        check("same-set reference rows in the wrong order refuse",
              refused(lambda: _build_from_validated_inputs(
                  **reordered_reference), "ordered prefix"))
        reordered_candidate = fixture(
            os.path.join(tmp, "reordered-candidate"),
            candidate_reordered=True)
        check("same-set candidate rows in the wrong order refuse",
              refused(lambda: _build_from_validated_inputs(
                  **reordered_candidate), "full pair sequence"))

        def rewrite_root(kwargs, mutate):
            state_path = os.path.join(
                kwargs["campaign_dir"], TQ.CAMPAIGN_STATE)
            with open(state_path, encoding="utf-8") as fh:
                root_state = json.load(fh)
            mutate(root_state)
            root_state["plan_sha256"] = content_digest(root_state["plan"])
            atomic_write_json(state_path, root_state)

        nonobject_plan = fixture(os.path.join(tmp, "nonobject-plan"))
        rewrite_root(nonobject_plan,
                     lambda state: state.__setitem__("plan", []))
        check("a non-object root plan is a clean bound refusal",
              refused(lambda: _build_from_validated_inputs(**nonobject_plan),
                      "plan is not an object"))

        bad_interruption_kind = fixture(
            os.path.join(tmp, "bad-interruption-kind"))
        rewrite_root(
            bad_interruption_kind,
            lambda state: state["interruption"].__setitem__("kind", []))
        check("an unhashable interruption kind is a clean bound refusal",
              refused(lambda: _build_from_validated_inputs(
                  **bad_interruption_kind), "unsupported campaign interruption"))

        for field, value in (("shard_policy", []),
                             ("execution_policy", {}),
                             ("preflight_cache_policy", [])):
            malformed_policy = fixture(os.path.join(
                tmp, "malformed-" + field.replace("_", "-")))

            def mutate_policy(state, key=field, malformed=value):
                state["plan"]["jobs"][0]["campaign_identity"][key] = malformed

            rewrite_root(malformed_policy, mutate_policy)
            check(f"malformed nested v4 {field} is a controlled refusal",
                  refused(lambda kwargs=malformed_policy:
                          _build_from_validated_inputs(**kwargs)))

        malformed_files = fixture(os.path.join(tmp, "malformed-files"))
        write_jsonl(malformed_files["run_path"], [
            {"item_id": "i", "outcome": "passed",
             "produced_files": "not-an-array"},
            {"item_id": "f", "outcome": "failed", "produced_files": []},
        ])
        check("malformed produced_files reaches the public API as BoundRefused, "
              "not an internal MutationAborted traceback",
              refused(lambda: _build_from_validated_inputs(
                  **malformed_files), "generated tests"))

        bad_gold = fixture(os.path.join(tmp, "bad-gold"))
        write_jsonl(bad_gold["gold_baseline_path"], [
            {"item_id": 7, "outcome": "passed", "produced_files": []}])
        check("mistyped gold item_id is a clean bound refusal",
              refused(lambda: _build_from_validated_inputs(**bad_gold),
                      "non-string item_id"))
        missing_gold_id = fixture(os.path.join(tmp, "missing-gold-id"))
        write_jsonl(missing_gold_id["gold_baseline_path"], [
            {"outcome": "passed", "produced_files": []}])
        check("missing gold item_id is a clean bound refusal",
              refused(lambda: _build_from_validated_inputs(
                  **missing_gold_id), "non-string item_id"))
        nul_pair = fixture(os.path.join(tmp, "nul-pair"))
        nul_run = [{"item_id": "bad\0item", "outcome": "passed",
                    "produced_files": [{"file_path": "T.java",
                                        "code": "class T {}"}]}]
        write_jsonl(nul_pair["run_path"], nul_run)
        write_jsonl(nul_pair["gold_baseline_path"], nul_run)
        nul_pair["assets"]["map"]["by_mutant"] = {
            mutant["id"]: ["bad\0item"]
            for mutant in nul_pair["assets"]["manifest"]["mutants"]}
        check("native MutationAborted identity failures are wrapped as a "
              "clean bound refusal",
              refused(lambda: _build_from_validated_inputs(**nul_pair),
                      "NUL"))
    return 0 if ok else 1
