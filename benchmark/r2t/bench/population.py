"""Bind reporting arithmetic to planned work rather than present rows.

The reporting surfaces share this resolver so a results table, a raw report,
and a campaign table cannot choose different populations for the same run.
It deliberately does not select items or assign shards.  Exact campaign
worksets arrive here only after the result-ledger verifier has replayed the
selection and the campaign's already-selected shard rule.
"""
from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from typing import Optional


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)
DEFAULT_RELEASE_ROOT = os.path.join(BENCHMARK, "release")

#: Benchmark 2.0's population (specifications/BENCHMARK_V2_SPEC.md section 6,
#: amending REPORTING_POPULATION_COMPLETENESS_SPEC.md in its section 10).  One
#: reviewed file, the only copy, read here and by the `req2test` report:
#:
#:     schema: r2t.benchmark-population/1
#:     benchmark_version: "2.0"
#:     census: <where the census of record that produced the list is>
#:     protocols: [<protocol_version>, ...]   # the 2.0 protocols (section 3.3)
#:     excluded:
#:       - instance_id: <project>/<feature path>:<line>
#:         reason: zero_body | census_pass
#:
#: Rows of a listed protocol are 2.0 rows.  Their run still collects every
#: instance, but a listed instance leaves both the planned and the observed
#: population, so it enters no numerator or denominator, and every report
#: discloses it.  Until the evidence PR (section 9, PR 5) adds the file, no
#: row is a 2.0 row and every report reads as before.  `protocols` is the
#: list of 2.0 protocols of section 3.3: the equivalence record cites this
#: file rather than restating it, and every PR that mints a 2.0 protocol
#: adds it here.
BENCHMARK_POPULATION = os.path.join(BENCHMARK, "config",
                                    "benchmark_2.0_population.yml")
BENCHMARK_POPULATION_SCHEMA = "r2t.benchmark-population/1"
#: Why an instance leaves 2.0's metrics (section 6; c2r specification 3.3).
EXCLUSION_REASONS = {
    "zero_body": "zero-body: its target-hidden view hides nothing",
    "census_pass": "its ground-truth test passes on the runnable "
                   "target-hidden view (census of record)",
}


class PopulationRefusal(RuntimeError):
    """Pinned population evidence that cannot support the report it claims."""


def _refuse(message: str) -> PopulationRefusal:
    return PopulationRefusal(f"REFUSED: reporting population {message}")


def load_benchmark_population(path: Optional[str] = None) -> dict:
    """Read and check the benchmark 2.0 population file.

    Returns the document with `excluded` as `{instance_id: reason}`.  A
    missing file raises `FileNotFoundError`; a malformed one is refused.
    """
    import yaml
    path = path or BENCHMARK_POPULATION
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    entries = doc.get("excluded") if isinstance(doc, dict) else None
    protocols = doc.get("protocols") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) \
            or doc.get("schema") != BENCHMARK_POPULATION_SCHEMA \
            or doc.get("benchmark_version") != "2.0" \
            or not isinstance(doc.get("census"), str) \
            or not doc["census"].strip() \
            or not isinstance(protocols, list) \
            or not all(isinstance(p, int) and not isinstance(p, bool)
                       for p in protocols) \
            or len(set(protocols)) != len(protocols) \
            or not isinstance(entries, list) \
            or not all(isinstance(e, dict)
                       and set(e) == {"instance_id", "reason"}
                       and isinstance(e["instance_id"], str)
                       and "/" in e["instance_id"]
                       and e["reason"] in EXCLUSION_REASONS
                       for e in entries):
        raise _refuse(
            f"file {path} is not a {BENCHMARK_POPULATION_SCHEMA} document: "
            "benchmark_version \"2.0\", a census, distinct integer protocols "
            "and excluded entries of {instance_id, reason}, with reason one "
            f"of {sorted(EXCLUSION_REASONS)}")
    excluded = {e["instance_id"]: e["reason"] for e in entries}
    if len(excluded) != len(entries):
        raise _refuse(f"file {path} lists an excluded instance twice")
    return dict(doc, path=path, excluded=excluded)


def benchmark_population(rows: list[dict],
                         path: Optional[str] = None) -> Optional[dict]:
    """The 2.0 population governing these rows, or None for other rows.

    Rows are selected by protocol, never by transformer or view digest
    (BENCHMARK_V2_SPEC.md section 3.3).  A 2.0 row is never pooled with
    another row, so a run that mixes them is refused.
    """
    path = path or BENCHMARK_POPULATION
    if not rows or not os.path.exists(path):
        return None
    doc = load_benchmark_population(path)
    protocols = {row.get("protocol_version") for row in rows}
    governed = protocols & set(doc["protocols"])
    if not governed:
        return None
    if protocols != governed:
        raise _refuse(
            f"mixes benchmark 2.0 protocol(s) {sorted(governed)} with rows of "
            f"other protocols {sorted(protocols - governed, key=repr)}; a 2.0 "
            "row is never pooled with another (BENCHMARK_V2_SPEC.md "
            "section 2)")
    return doc


def _exclusion_block(doc: dict, hit: list) -> dict:
    """The disclosure of the listed instances `hit`, as every format prints it."""
    return {"benchmark_version": doc["benchmark_version"], "path": doc["path"],
            "count": len(hit),
            "excluded": [{"item_id": iid, "reason": doc["excluded"][iid]}
                         for iid in hit]}


def row_exclusions(rows: list[dict]) -> Optional[dict]:
    """2.0's disclosure over one run's rows, or None for rows it does not govern.

    For readers that take a run without resolving its planned population
    (`report --non-vacuous-out`, `compare`): the block names the listed
    instances that have a row.
    """
    doc = benchmark_population(rows)
    if doc is None:
        return None
    return _exclusion_block(
        doc, sorted(set(doc["excluded"]) & {row["item_id"] for row in rows}))


def _apply_benchmark_population(population: dict, rows: list[dict],
                                doc: dict) -> dict:
    """Restrict a resolved population to 2.0's and disclose what left it."""
    excluded = doc["excluded"]
    planned = population.get("_planned_item_ids")
    observed = {row["item_id"] for row in rows}
    hit = sorted(set(excluded) & (observed | set(planned or ())))
    out = dict(population, population_exclusions=_exclusion_block(doc, hit))
    if not hit:
        return out
    if population["status"] == "count_only":
        raise _refuse(
            "cannot remove benchmark 2.0's excluded instances from a "
            "count-only checkpoint; it retains no item IDs")
    kept = observed - set(hit)
    out["observed_n"] = len(kept)
    if planned is None:
        return out
    planned = tuple(iid for iid in planned if iid not in excluded)
    missing = sorted(set(planned) - kept)
    complete = not missing
    out.update(
        status="complete" if complete else "incomplete",
        planned_n=len(planned), missing_planned_ids=missing,
        complete=complete, canonical_values_admitted=complete,
        withheld_reasons=[] if complete else [
            f"population incomplete: planned_n={len(planned)}, "
            f"observed_n={len(kept)}"],
        _planned_item_ids=planned)
    return out


def excluded_ids(population: Mapping) -> frozenset:
    """The instances 2.0 leaves out of every metric of this population.

    Their rows stay in the run file; every caller drops them before any
    arithmetic, so no numerator or denominator counts them.
    """
    block = population.get("population_exclusions") or {}
    return frozenset(entry["item_id"] for entry in block.get("excluded", ()))


def _values(rows: list[dict], field: str) -> tuple[bool, tuple]:
    """Whether any row asserts ``field``, and every asserted JSON value."""
    present = [field in row and row[field] is not None for row in rows]
    if not any(present):
        return False, ()
    if not all(present):
        raise _refuse(
            f"has mixed {field!r} evidence: some final rows assert it and "
            "others do not. A partial identity is not an unpinned run")
    values = {}
    for row in rows:
        value = row[field]
        if not isinstance(value, (str, int, float, bool)):
            raise _refuse(
                f"asserts invalid non-scalar {field!r} value {value!r}") \
                from None
        # Python equates False with 0 and True with 1. Identity evidence may
        # not: a Boolean shard/of claim is invalid, and must not disappear
        # behind a valid integer asserted by another row.
        values.setdefault((type(value), value), value)
    return True, tuple(values.values())


def _one(rows: list[dict], field: str):
    present, values = _values(rows, field)
    if not present:
        return None
    if len(values) != 1:
        shown = ", ".join(repr(value) for value in sorted(
            values, key=lambda value: repr(value)))
        raise _refuse(
            f"has mixed {field!r} identities across final rows: {shown}")
    return next(iter(values))


def _row_identity(rows: list[dict]) -> dict:
    """Validate the population-bearing identity claims stamped on rows."""
    subset_id = _one(rows, "subset_id")
    subset_digest = _one(rows, "subset_digest")
    if (subset_id is None) != (subset_digest is None):
        raise _refuse(
            "asserts only one of subset_id and subset_digest; the pair is one "
            "identity and cannot be completed by inference")
    if subset_id is not None:
        if not isinstance(subset_id, str) or not subset_id.strip():
            raise _refuse(f"asserts invalid subset_id {subset_id!r}")
        if not isinstance(subset_digest, str) or len(subset_digest) != 16 \
                or any(c not in "0123456789abcdef" for c in subset_digest):
            raise _refuse(f"asserts invalid subset_digest {subset_digest!r}")

    campaign_digest = _one(rows, "campaign_digest")
    shard_present, shard_values = _values(rows, "shard")
    of_value = _one(rows, "of")
    if shard_present != (of_value is not None):
        raise _refuse(
            "asserts only one of shard and of; shard scope must travel as a "
            "pair on every final row")
    if shard_present and campaign_digest is None:
        raise _refuse(
            "asserts shard/of without the campaign_digest whose selected rule "
            "defines that scope")
    if campaign_digest is not None:
        if not isinstance(campaign_digest, str) or len(campaign_digest) != 16 \
                or any(c not in "0123456789abcdef" for c in campaign_digest):
            raise _refuse(
                f"asserts invalid campaign_digest {campaign_digest!r}")
        if shard_present:
            if not isinstance(of_value, int) or isinstance(of_value, bool) \
                    or of_value < 1:
                raise _refuse(
                    f"asserts invalid campaign shard count {of_value!r}")
            invalid_shards = sorted((
                value for value in shard_values
                if not isinstance(value, int) or isinstance(value, bool)
                or value < 0 or value >= of_value), key=repr)
            if invalid_shards:
                raise _refuse(
                    f"asserts shard value(s) outside 0..{of_value - 1}: "
                    f"{invalid_shards}")
    return {
        "subset_id": subset_id,
        "subset_digest": subset_digest,
        "campaign_digest": campaign_digest,
        "shards": tuple(sorted(shard_values)) if shard_present else (),
        "shard_count": of_value,
    }


def _item_ids(path: str) -> tuple[str, ...]:
    from ..data import subsets
    try:
        item_ids = tuple(
            item_id for item_id, _line in subsets.read_items(path))
    except AttributeError:
        raise _refuse(
            f"planned workset {path!r} contains a JSON value that is not "
            "an item object") from None
    except OSError as exc:
        raise _refuse(
            f"cannot read planned workset {path!r}: {exc}") from None
    except UnicodeError as exc:
        raise _refuse(
            f"cannot decode planned workset {path!r} as UTF-8: {exc}") \
            from None
    except (subsets.SubsetRefused, TypeError) as exc:
        message = str(exc)
        if message.startswith("REFUSED: "):
            message = message[len("REFUSED: "):]
        raise _refuse(message) from None
    if not all(isinstance(item_id, str) and item_id.strip()
               for item_id in item_ids):
        raise _refuse(
            f"planned workset {path!r} contains a non-string or empty item ID")
    return item_ids


def _release_identity(path: str) -> Optional[dict]:
    from ..data import subsets
    try:
        return subsets.identify_for_inference(path)
    except OSError as exc:
        raise _refuse(
            f"cannot identify planned workset {path!r}: {exc}") from None
    except subsets.SubsetRefused as exc:
        message = str(exc)
        if message.startswith("REFUSED: "):
            message = message[len("REFUSED: "):]
        raise _refuse(message) from None
    except (AttributeError, TypeError) as exc:
        raise _refuse(
            f"cannot validate planned workset provenance for {path!r}: "
            f"{exc}") from None


def _require_subset_release(path: str, subset_id: Optional[str],
                            subset_digest: Optional[str], source: str) -> None:
    """Require an asserted subset pair to identify the exact release bytes."""
    if subset_id is None and subset_digest is None:
        return
    if (subset_id is None) != (subset_digest is None):
        raise _refuse(f"{source} carries only half a subset identity")
    found = _release_identity(path)
    expected = {"subset_id": subset_id, "subset_digest": subset_digest}
    if found is None:
        raise _refuse(
            f"{source} asserts subset {subset_id!r}/{subset_digest!r}, but "
            f"its release {path!r} has no validated subset identity")
    if any(found[field] != expected[field] for field in expected):
        raise _refuse(
            f"{source} subset {subset_id!r}/{subset_digest!r} disagrees "
            f"with its exact release bytes {found['subset_id']!r}/"
            f"{found['subset_digest']!r}")


def _resolve_subset(identity: dict, release_roots: Iterable[str]) \
        -> tuple[str, tuple[str, ...]]:
    """Resolve one asserted subset pair to strict matching published bytes."""
    from ..data import subsets
    candidates = []
    for root in release_roots:
        for path in subsets.subset_files(os.fspath(root)):
            if os.path.basename(path) == identity["subset_id"] + ".jsonl":
                candidates.append(path)
    if not candidates:
        raise _refuse(
            f"cannot resolve asserted subset {identity['subset_id']!r} with "
            f"digest {identity['subset_digest']!r} to published bytes")
    matches = []
    for path in sorted(set(candidates)):
        found = _release_identity(path)
        if found and found["subset_id"] == identity["subset_id"] \
                and found["subset_digest"] == identity["subset_digest"]:
            matches.append(path)
    if not matches:
        raise _refuse(
            f"cannot resolve asserted subset {identity['subset_id']!r} with "
            f"digest {identity['subset_digest']!r} to matching validated bytes")
    if len(matches) > 1:
        raise _refuse(
            f"asserted subset {identity['subset_id']!r} with digest "
            f"{identity['subset_digest']!r} resolves to multiple published "
            f"files: {', '.join(matches)}")
    return matches[0], _item_ids(matches[0])


def frozen_scope(*, item_ids: Iterable[str], workset: Mapping,
                 campaign_digest: Optional[str] = None,
                 subset_id: Optional[str] = None,
                 subset_digest: Optional[str] = None,
                 shard_rule: Optional[str] = None,
                 shard_count: Optional[int] = None,
                 source: str = "validated frozen workset") -> dict:
    """Validate the small projection an upstream workset verifier supplies.

    This function validates identity agreement and workset closure; it never
    validates a campaign plan itself.  Production callers obtain the values
    from ``result_ledger.publication_preflight``, which has already replayed
    selection and sharding.
    """
    from . import campaign
    from . import result_ledger

    ids = tuple(item_ids)
    if not all(isinstance(item_id, str) and item_id.strip()
               for item_id in ids):
        raise _refuse("validated frozen workset contains an invalid item ID")
    if len(ids) != len(set(ids)):
        raise _refuse("validated frozen workset repeats an item ID")
    if not isinstance(workset, Mapping) \
            or set(workset) != {"item_count", "ordered_item_ids_digest"}:
        raise _refuse(
            "validated frozen workset must contain exactly item_count and "
            "ordered_item_ids_digest")
    count = workset["item_count"]
    digest = workset["ordered_item_ids_digest"]
    expected_digest = result_ledger.ordered_item_ids_digest(ids)
    if not isinstance(count, int) or isinstance(count, bool) or count < 0 \
            or count != len(ids):
        raise _refuse(
            f"validated frozen workset item_count {count!r} does not match "
            f"its {len(ids)} item IDs")
    if digest != expected_digest:
        raise _refuse(
            "validated frozen workset ordered_item_ids_digest does not match "
            "its item IDs")
    if (subset_id is None) != (subset_digest is None):
        raise _refuse(
            "validated frozen workset carries only one member of its subset "
            "identity pair")
    if subset_id is not None:
        if not isinstance(subset_id, str) or not subset_id.strip():
            raise _refuse(
                f"validated frozen workset has invalid subset_id "
                f"{subset_id!r}")
        if not isinstance(subset_digest, str) or len(subset_digest) != 16 \
                or any(c not in "0123456789abcdef" for c in subset_digest):
            raise _refuse(
                f"validated frozen workset has invalid subset_digest "
                f"{subset_digest!r}")
    if campaign_digest is not None \
            and (not isinstance(campaign_digest, str)
                 or len(campaign_digest) != 16
                 or any(c not in "0123456789abcdef"
                        for c in campaign_digest)):
        raise _refuse(
            f"validated frozen workset has invalid campaign_digest "
            f"{campaign_digest!r}")
    if shard_rule is not None \
            and shard_rule not in {campaign.SHARD_RULE,
                                   campaign.POSITIONAL_SHARD_RULE}:
        raise _refuse(
            f"validated frozen workset names unsupported shard rule "
            f"{shard_rule!r}")
    if shard_count is not None \
            and (not isinstance(shard_count, int)
                 or isinstance(shard_count, bool) or shard_count < 1):
        raise _refuse(
            f"validated frozen workset has invalid shard count "
            f"{shard_count!r}")
    campaign_fields = (campaign_digest, shard_rule, shard_count)
    if any(value is not None for value in campaign_fields) \
            and not all(value is not None for value in campaign_fields):
        raise _refuse(
            "validated frozen workset must retain campaign_digest, "
            "shard_rule, and shard_count together")
    return {
        "item_ids": ids,
        "workset": {"item_count": count,
                    "ordered_item_ids_digest": digest},
        "campaign_digest": campaign_digest,
        "subset_id": subset_id,
        "subset_digest": subset_digest,
        "shard_rule": shard_rule,
        "shard_count": shard_count,
        "source": source,
    }


def publication_scope(role) -> dict:
    """Project one fully verified publication role into reporting scope."""
    from . import campaign
    stamp = role.substrate["effective_run_stamp"]
    campaign_document = role.agent_control_inputs["campaign"]
    _require_subset_release(
        role.release_reference["path"], stamp.get("subset_id"),
        stamp.get("subset_digest"), "validated publication workset")
    return frozen_scope(
        item_ids=role.item_ids, workset=role.workset,
        campaign_digest=campaign.campaign_digest(campaign_document),
        subset_id=stamp.get("subset_id"),
        subset_digest=stamp.get("subset_digest"),
        shard_rule=campaign_document["shard_rule"],
        shard_count=campaign_document["k_workers"],
        source="validated publication workset")


def _receipt_scope(run_path: str) -> Optional[dict]:
    """Return an adjacent complete receipt's verified report projection."""
    from . import result_ledger
    receipt_path = os.path.abspath(run_path) + result_ledger.RECEIPT_SUFFIX
    if not os.path.lexists(receipt_path):
        return None
    try:
        evidence = result_ledger.verify_reporting_workset(receipt_path)
    except (OSError, ValueError, result_ledger.ResultLedgerRefused) as exc:
        message = str(exc)
        if message.startswith("REFUSED: "):
            message = message[len("REFUSED: "):]
        raise _refuse(
            f"cannot verify applicable result receipt "
            f"{os.path.basename(receipt_path)!r}: {message}") from None
    if evidence["result_path"] != os.path.abspath(run_path):
        raise _refuse(
            "applicable result receipt resolves to another result path")
    _require_subset_release(
        evidence["release_path"], evidence["subset_id"],
        evidence["subset_digest"], "validated result receipt workset")
    return frozen_scope(
        item_ids=evidence["item_ids"], workset=evidence["workset"],
        campaign_digest=evidence["campaign_digest"],
        subset_id=evidence["subset_id"],
        subset_digest=evidence["subset_digest"],
        shard_rule=evidence["shard_rule"],
        shard_count=evidence["shard_count"],
        source=f"validated result receipt {receipt_path}")


def _reconcile_scopes(primary: dict, applicable: dict) -> dict:
    """Require two source-1 frozen-workset claims to be exactly the same."""
    for field in ("item_ids", "workset", "campaign_digest", "subset_id",
                  "subset_digest", "shard_rule", "shard_count"):
        if primary[field] != applicable[field]:
            raise _refuse(
                f"{primary['source']} {field} disagrees with the "
                f"{applicable['source']} value")
    return primary


def _verify_scope(scope: Mapping, row_identity: dict) -> dict:
    required = {"item_ids", "workset", "campaign_digest", "subset_id",
                "subset_digest", "shard_rule", "shard_count", "source"}
    if not isinstance(scope, Mapping) or set(scope) != required:
        raise _refuse("frozen workset projection has an unsupported shape")
    checked = frozen_scope(
        item_ids=scope["item_ids"], workset=scope["workset"],
        campaign_digest=scope["campaign_digest"],
        subset_id=scope["subset_id"], subset_digest=scope["subset_digest"],
        shard_rule=scope["shard_rule"], shard_count=scope["shard_count"],
        source=scope["source"])
    for field in ("campaign_digest", "subset_id", "subset_digest",
                  "shard_count"):
        asserted = row_identity[field]
        expected = checked[field]
        if asserted is not None and asserted != expected:
            raise _refuse(
                f"row-stamped {field} {asserted!r} disagrees with the "
                f"{checked['source']} value {expected!r}")
    if row_identity["campaign_digest"] is not None \
            and checked["shard_rule"] is None:
        raise _refuse(
            f"{checked['source']} does not retain the selected shard rule for "
            "campaign-stamped rows")
    return checked


def _checkpoint(run_path: str) -> Optional[dict]:
    from . import result_ledger
    path = os.path.abspath(run_path) + result_ledger.CHECKPOINT_SUFFIX
    if not os.path.lexists(path):
        return None
    try:
        report = result_ledger.verify_checkpoint(path)
    except (result_ledger.ResultLedgerRefused, OSError, ValueError) as exc:
        message = str(exc)
        if message.startswith("REFUSED: "):
            message = message[len("REFUSED: "):]
        raise _refuse(
            f"cannot verify applicable checkpoint {os.path.basename(path)!r}: "
            f"{message}") from None
    if report["artifact_kind"] != "run_shard":
        raise _refuse(
            f"applicable checkpoint {os.path.basename(path)!r} describes "
            f"{report['artifact_kind']!r}, not result rows")
    identity = report.get("population_identity")
    required = {"campaign_digest", "subset_id", "subset_digest",
                "shard_rule", "shard_count"}
    if not isinstance(identity, Mapping) or set(identity) != required:
        raise _refuse(
            f"applicable checkpoint {os.path.basename(path)!r} has no exact "
            "campaign/subset/shard identity projection")
    release_path = report.get("release_path")
    if not isinstance(release_path, str) or not os.path.isabs(release_path):
        raise _refuse(
            f"applicable checkpoint {os.path.basename(path)!r} has no exact "
            "release path projection")
    _require_subset_release(
        release_path, identity["subset_id"], identity["subset_digest"],
        "validated publication checkpoint")
    return report


def _reconcile_checkpoint(checkpoint: Optional[dict], row_identity: dict,
                          scope: Optional[dict]) -> None:
    """Join a count-only checkpoint to every applicable identity claim."""
    if checkpoint is None:
        return
    identity = checkpoint["population_identity"]
    for field in ("campaign_digest", "subset_id", "subset_digest",
                  "shard_count"):
        asserted = row_identity[field]
        if asserted is not None and asserted != identity[field]:
            raise _refuse(
                f"row-stamped {field} {asserted!r} disagrees with the "
                f"applicable checkpoint value {identity[field]!r}")
    if scope is None:
        return
    for field in ("campaign_digest", "subset_id", "subset_digest",
                  "shard_rule", "shard_count"):
        if scope[field] != identity[field]:
            raise _refuse(
                f"applicable checkpoint {field} {identity[field]!r} "
                f"disagrees with the {scope['source']} value "
                f"{scope[field]!r}")
    if checkpoint["workset"] != scope["workset"]:
        raise _refuse(
            "applicable checkpoint workset disagrees with the validated "
            "frozen report-scope workset")


def _reconcile_explicit_subset(path: str, found: Optional[dict], *,
                               subset_id: Optional[str],
                               subset_digest: Optional[str],
                               source: str) -> None:
    """Require an explicit enumerator's subset identity to match a plan."""
    actual = (None, None) if found is None else (
        found["subset_id"], found["subset_digest"])
    expected = (subset_id, subset_digest)
    if actual == expected:
        return
    if found is None:
        raise _refuse(
            f"explicit release {path!r} has no validated subset identity "
            f"but {source} asserts {subset_id!r}/{subset_digest!r}")
    raise _refuse(
        f"explicit release subset {actual[0]!r}/{actual[1]!r} disagrees "
        f"with the {source} value {subset_id!r}/{subset_digest!r}")


def _base(*, source: str, status: str, planned_n: Optional[int],
          observed_ids: set[str], missing: Optional[list[str]],
          complete: Optional[bool], admitted: bool,
          reason: Optional[str], planned_ids: Optional[tuple[str, ...]]) -> dict:
    return {
        "status": status,
        "source": source,
        "planned_n": planned_n,
        "observed_n": len(observed_ids),
        "ladder_n": None,
        "classified_n": None,
        "missing_planned_ids": missing,
        "complete": complete,
        "canonical_values_admitted": admitted,
        "withheld_reasons": [] if reason is None else [reason],
        # Report partitioning needs the validated set. It is removed from every
        # supported machine rendering and never appears in human provenance.
        "_planned_item_ids": planned_ids,
    }


def resolve(rows: list[dict], run_path: str, *,
            explicit_release: Optional[str] = None,
            validated_scope: Optional[Mapping] = None,
            release_roots: Optional[Iterable[str]] = None) -> dict:
    """An ordinary headroom proof supplies the existing selected-workset seam."""
    view = None
    if os.path.lexists(str(run_path) + ".headroom.json"):
        from ..java import kapua_headroom as H
        try:
            view = H.load_run_projection(run_path)
            if explicit_release is not None and H.G.reference(explicit_release) != view["release"]:
                raise _refuse("explicit release differs from the proven headroom workset")
            if validated_scope is not None:
                _reconcile_scopes(view["scope"], _verify_scope(validated_scope, _row_identity(rows)))
            validated_scope = view["scope"]
            explicit_release = None  # L was compared above; C stamps remain generation identity.
        except (OSError, ValueError) as exc:
            if isinstance(exc, PopulationRefusal):
                raise
            raise _refuse(str(exc)) from exc
    answer = _resolve(rows, run_path, explicit_release=explicit_release,
                      validated_scope=validated_scope, release_roots=release_roots)
    from ..ruby import evaluation_selection as R
    from ..data import sylius_selection as Y
    if (_row_identity(rows)["subset_id"] == Y.SUBSET_ID or
            (validated_scope is not None and validated_scope.get("subset_id") == Y.SUBSET_ID)):
        answer.update(inference_valid=False, inference_reason=Y.REASON)
    if (_row_identity(rows)["subset_id"] == R.SUBSET_ID or
            (validated_scope is not None and validated_scope.get("subset_id") == R.SUBSET_ID)):
        answer.update(inference_valid=False, inference_reason=R.REASON)
    if view is not None:
        answer.update(inference_valid=False, inference_reason=view["inference_reason"],
                      selection=view["selection"], source_run=view["source_run"],
                      scoring_release=view["release"])
    elif explicit_release is not None and os.path.basename(explicit_release).startswith("headroom_"):
        from ..data import subsets as S
        replay = S.replay_headroom(explicit_release)
        answer.update(inference_valid=False,
                      inference_reason=replay["provenance"]["inference_reason"],
                      selection={"path": replay["sidecar"], "sha256": S.sha256_file(replay["sidecar"])})
    if explicit_release is not None:
        if Y.is_selection(explicit_release):
            identity = Y.identify(explicit_release)
            answer.update(inference_valid=False, inference_reason=identity["inference_reason"],
                          selection={"path": identity["sidecar"],
                                     "sha256": Y.sha256(identity["sidecar"])})
        if R.is_selection(explicit_release):
            identity = R.identify(explicit_release)
            selection = {"path": identity["sidecar"],
                         "sha256": R.reference(identity["sidecar"])["sha256"]}
            if "recorded_roots" in identity:  # its paths were read through R2T_RECORDED_ROOTS
                selection["recorded_roots"] = identity["recorded_roots"]
            answer.update(inference_valid=False, inference_reason=identity["inference_reason"],
                          selection=selection)
        from ..java import kapua_pilot as K
        if K.is_pilot(explicit_release):
            identity = K.identify(explicit_release)
            answer.update(inference_valid=False, inference_reason=identity["inference_reason"],
                          selection={"path": identity["sidecar"], "sha256": K.G.reference(identity["sidecar"])["sha256"]})
        from ..java import kapua_census as KC
        if KC.is_selection(explicit_release):
            identity = KC.identify(explicit_release)
            answer.update(inference_valid=False, inference_reason=identity["inference_reason"],
                          selection={"path": identity["sidecar"], "sha256": KC.RECEIPT_SHA256})
    governing = benchmark_population(rows)
    if governing is not None:
        answer = _apply_benchmark_population(answer, rows, governing)
    return answer


def _resolve(rows: list[dict], run_path: str, *,
            explicit_release: Optional[str] = None,
            validated_scope: Optional[Mapping] = None,
            release_roots: Optional[Iterable[str]] = None) -> dict:
    """Resolve, reconcile, and compare one report cell's planned population."""
    identity = _row_identity(rows)
    observed_ids = {row["item_id"] for row in rows}
    checkpoint = _checkpoint(run_path)
    receipt_scope = _receipt_scope(run_path)
    supplied_scope = (_verify_scope(validated_scope, identity)
                      if validated_scope is not None else None)
    if supplied_scope is not None and receipt_scope is not None:
        scope = _reconcile_scopes(supplied_scope, receipt_scope)
    else:
        scope = supplied_scope or receipt_scope
    if scope is not None:
        scope = _verify_scope(scope, identity)
    _reconcile_checkpoint(checkpoint, identity, scope)

    explicit_ids = None
    explicit_identity = None
    if explicit_release is not None:
        path = os.path.abspath(os.fspath(explicit_release))
        explicit_ids = _item_ids(path)
        explicit_identity = _release_identity(path)
        if identity["subset_id"] is not None:
            _reconcile_explicit_subset(
                path, explicit_identity, subset_id=identity["subset_id"],
                subset_digest=identity["subset_digest"], source="rows")
        if scope is not None:
            _reconcile_explicit_subset(
                path, explicit_identity, subset_id=scope["subset_id"],
                subset_digest=scope["subset_digest"], source=scope["source"])
        if checkpoint is not None:
            checkpoint_identity = checkpoint["population_identity"]
            _reconcile_explicit_subset(
                path, explicit_identity,
                subset_id=checkpoint_identity["subset_id"],
                subset_digest=checkpoint_identity["subset_digest"],
                source="applicable checkpoint")
        if scope is not None:
            # An explicit report-scope workset and a verified frozen workset
            # are two equality claims. A full upstream release is not silently
            # filtered here: reporting does not select or assign shards.
            if tuple(explicit_ids) != tuple(scope["item_ids"]):
                raise _refuse(
                    "explicit release item IDs disagree with the validated "
                    "frozen report-scope workset")
        elif identity["campaign_digest"] is not None and checkpoint is None:
            raise _refuse(
                "cannot reconcile an explicit release with campaign-stamped "
                "rows without the campaign's already validated selected/shard "
                "workset or checkpoint")

    subset_path = None
    subset_ids = None
    if identity["subset_id"] is not None:
        if explicit_identity is not None:
            subset_path, subset_ids = os.path.abspath(explicit_release), explicit_ids
        elif scope is None:
            # A validated frozen scope has already reconciled the stamped
            # subset pair and carries the exact post-selection/shard workset.
            # Do not require a second repository-local copy of its source
            # subset bytes or replace the report-scope IDs with that full set.
            roots = tuple(release_roots or (DEFAULT_RELEASE_ROOT,))
            subset_path, subset_ids = _resolve_subset(identity, roots)

    subset_matches_checkpoint = False
    if subset_ids is not None and identity["campaign_digest"] is not None \
            and checkpoint is not None:
        from . import result_ledger
        subset_workset = {
            "item_count": len(subset_ids),
            "ordered_item_ids_digest":
                result_ledger.ordered_item_ids_digest(subset_ids),
        }
        # A K=1 or already-unioned campaign can retain both a source subset
        # identity and a report-scope checkpoint. Exact workset equality makes
        # the higher-precedence subset bytes enumerable without selecting or
        # inferring a shard rule here. A narrower checkpoint remains
        # count-only; reporting never filters the source subset itself.
        subset_matches_checkpoint = checkpoint["workset"] == subset_workset

    if scope is not None:
        planned_ids = tuple(scope["item_ids"])
        source = scope["source"]
    elif explicit_ids is not None:
        planned_ids = tuple(explicit_ids)
        source = f"explicit release {os.path.abspath(explicit_release)}"
    elif subset_ids is not None and (
            identity["campaign_digest"] is None
            or subset_matches_checkpoint):
        planned_ids = tuple(subset_ids)
        source = f"row-stamped subset {subset_path}"
    else:
        planned_ids = None
        source = "publication checkpoint" if checkpoint else "unpinned"

    if scope is not None and subset_ids is not None \
            and identity["campaign_digest"] is None \
            and tuple(scope["item_ids"]) != tuple(subset_ids):
        raise _refuse(
            "row-stamped subset bytes disagree with the validated frozen "
            "report-scope workset")

    if planned_ids is not None:
        planned_set = set(planned_ids)
        foreign = sorted(observed_ids - planned_set)
        if foreign:
            raise _refuse(
                f"observed foreign item ID(s) outside the planned workset: "
                f"{foreign}")
        if checkpoint is not None:
            from . import result_ledger
            workset = {
                "item_count": len(planned_ids),
                "ordered_item_ids_digest":
                    result_ledger.ordered_item_ids_digest(planned_ids),
            }
            if checkpoint["workset"] != workset:
                raise _refuse(
                    "applicable checkpoint workset disagrees with the "
                    "enumerated planned workset")
        missing = sorted(planned_set - observed_ids)
        complete = not missing
        reason = (None if complete else
                  f"population incomplete: planned_n={len(planned_ids)}, "
                  f"observed_n={len(observed_ids)}")
        return _base(
            source=source, status="complete" if complete else "incomplete",
            planned_n=len(planned_ids), observed_ids=observed_ids,
            missing=missing, complete=complete, admitted=complete,
            reason=reason, planned_ids=planned_ids)

    if checkpoint is not None:
        planned_n = checkpoint["workset"]["item_count"]
        if len(observed_ids) > planned_n:
            raise _refuse(
                f"checkpoint planned_n={planned_n} is smaller than "
                f"observed_n={len(observed_ids)}")
        reason = (f"population incomplete: planned_n={planned_n}, "
                  f"observed_n={len(observed_ids)}; exact missing IDs are "
                  "unavailable from the count-only checkpoint"
                  if len(observed_ids) < planned_n else
                  "population completeness unavailable: the publication "
                  "checkpoint is count-only")
        return _base(
            source=source, status="count_only", planned_n=planned_n,
            observed_ids=observed_ids, missing=None, complete=None,
            admitted=False, reason=reason, planned_ids=None)

    if identity["campaign_digest"] is not None:
        raise _refuse(
            f"cannot resolve campaign {identity['campaign_digest']!r} to an "
            "already validated report-scope workset")
    return _base(
        source="unpinned", status="unpinned", planned_n=None,
        observed_ids=observed_ids, missing=None, complete=None,
        admitted=False,
        reason="unpinned population: no validated planned workset is available",
        planned_ids=None)


RATIFIED_STATUS = "complete_with_ratified_exclusions"


def with_ratified_exclusions(population: dict, exclusions: list) -> dict:
    """Admit a population whose only missing items are ratified infrastructure.

    Each exclusion names a missing planned item whose attempt reached the
    agent and was killed without a row, with the note recording the owner's
    ratification (REPORTING_POPULATION_COMPLETENESS_SPEC.md section 9). The
    item stays in `missing_planned_ids`, gets no outcome and enters no
    numerator, denominator or rung; `complete` stays False, so
    markdown-legacy still refuses. The canonical values are admitted only
    when every missing planned item is named.
    """
    if not exclusions:
        return population
    if not all(isinstance(entry, Mapping) and isinstance(entry.get("item_id"), str)
               and isinstance(entry.get("note"), str) and entry["note"].strip()
               for entry in exclusions):
        raise _refuse("ratified exclusions each need an item_id and a note")
    ids = [entry["item_id"] for entry in exclusions]
    if len(set(ids)) != len(ids):
        raise _refuse(f"ratified exclusions name an item twice: {ids}")
    missing = population["missing_planned_ids"]
    if missing is None:
        raise _refuse(
            f"cannot apply ratified exclusions to a {population['status']} "
            "population: its missing planned IDs are not enumerable")
    named = sorted(set(ids) - set(missing))
    if named:
        raise _refuse(
            f"ratified exclusion(s) {named} are not missing planned IDs; only "
            "a planned item with no row can be excluded this way")
    out = dict(population, ratified_infrastructure_exclusions=[
        {"item_id": entry["item_id"], "note": entry["note"]} for entry in exclusions])
    remaining = sorted(set(missing) - set(ids))
    if remaining:
        out["withheld_reasons"] = [
            f"population incomplete: missing_planned_ids {remaining} are not "
            "ratified infrastructure exclusions"]
    else:
        out.update(status=RATIFIED_STATUS, canonical_values_admitted=True,
                   withheld_reasons=[])
    return out


def with_ladder(population: dict, ladder: Mapping) -> dict:
    """Attach issue #202's already-computed present-row counts by exact name."""
    out = dict(population)
    out["observed_n"] = ladder["n"]
    out["ladder_n"] = ladder["denominator"]
    out["classified_n"] = ladder["classified_n"]
    planned_n = out["planned_n"]
    if planned_n is not None and not (
            out["classified_n"] <= out["ladder_n"]
            <= out["observed_n"] <= planned_n):
        raise _refuse(
            "resolved counts violate classified_n <= ladder_n <= observed_n "
            "<= planned_n")
    return out


def _scoped_exclusions(population: Mapping, base: dict, project: str) -> dict:
    """Carry 2.0's exclusion disclosure into one project's partition."""
    block = population.get("population_exclusions")
    if block is not None:
        excluded = [entry for entry in block["excluded"]
                    if entry["item_id"].split("/")[0] == project]
        base["population_exclusions"] = dict(block, count=len(excluded),
                                             excluded=excluded)
    return base


def scoped(population: Mapping, rows: list[dict], project: str,
           ladder: Mapping) -> dict:
    """Project an already-resolved enumerable population into one project.

    `rows` are the project's metric rows: 2.0's excluded instances are
    already gone from them, as they are from the planned IDs.
    """
    planned = population.get("_planned_item_ids")
    if planned is None:
        if population["status"] == "count_only":
            raise _refuse(
                "cannot partition a count-only checkpoint across projects; "
                "it retains no item IDs for the per-project planned counts")
        base = _base(
            source=population["source"], status="unpinned", planned_n=None,
            observed_ids={row["item_id"] for row in rows}, missing=None,
            complete=None, admitted=False,
            reason=population["withheld_reasons"][0], planned_ids=None)
        return with_ladder(_scoped_exclusions(population, base, project),
                           ladder)
    project_ids = tuple(item_id for item_id in planned
                        if item_id.split("/")[0] == project)
    observed_ids = {row["item_id"] for row in rows}
    missing = sorted(set(project_ids) - observed_ids)
    complete = not missing
    reason = (None if complete else
              f"population incomplete: planned_n={len(project_ids)}, "
              f"observed_n={len(observed_ids)}")
    base = _base(
        source=population["source"],
        status="complete" if complete else "incomplete",
        planned_n=len(project_ids), observed_ids=observed_ids,
        missing=missing, complete=complete, admitted=complete,
        reason=reason, planned_ids=project_ids)
    if population.get("inference_valid") is False:
        base.update({key: population[key] for key in
                     ("inference_valid", "inference_reason", "selection", "source_run", "scoring_release")
                     if key in population})
    return with_ladder(_scoped_exclusions(population, base, project), ladder)


def public_view(population: Mapping) -> dict:
    """The supported machine/human fields, without the internal ID vector."""
    return {key: value for key, value in population.items()
            if not key.startswith("_")}
