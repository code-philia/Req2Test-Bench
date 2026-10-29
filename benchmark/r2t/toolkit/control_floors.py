"""Measured floors for the behavioural rows: what a WRONG test already scores.

`TARGET_INTERFACES_V2_SPEC` section 6.3 asks every table to disclose the
floor of each behavioural row -- the score a test that is not the answer
still gets -- because a coverage recall of 0.95 means nothing until you know
that another scenario's gold test scores 0.999.  Three controls:

  sibling gold             another scenario's gold test from the SAME feature
                           file: same fixture, same step methods, same target
                           APIs, different arguments and expectations.
  assertion-stripped gold  gold with its assertions removed: it executes the
                           same code and checks nothing.
  stub                     an intentionally vacuous test.

All three are computed OFFLINE, from run rows that already exist (a gold-style
row with `coverage_lines` and `direct_calls`).  The sibling floor in
particular is a re-reduction of the gold run and is never collected: there is
no sibling arm, and adding one would mean executing 422 tests against 422
other items to learn something the existing rows already say.

The method is the one the specification's evidence package used
(`target_interfaces_v2_2026-09-16/scripts/sibling_floors.py`): per item, the
TYPICAL sibling (the median over its siblings) beside the BEST one (the
maximum), because "some wrong test scores 1.0" and "the average wrong test
scores 1.0" are different claims and the second is the weaker floor.  The
per-project number is then the median over items, with its item count.
"""
from __future__ import annotations

import json
import statistics
from typing import Optional

from ..bench import metrics as M
from ..bench.metrics import CONTROL_FLOORS_SCHEMA as SCHEMA
from ..core.boundary import Boundary

#: The controls this verb reduces, beside `sibling_gold` which is derived
#: from the gold rows themselves.  Named here rather than taken from a flag
#: so a floors table always says which control a number came from.
CONTROL_ROLES = ("assertion_stripped_gold", "stub")


class FloorsInputError(RuntimeError):
    """An input cannot support the floor it was given for."""


def feature_of(item_id: str) -> str:
    """The feature file an item belongs to: its id without the line number."""
    return item_id.rsplit(":", 1)[0]


def _pairs(lines: Optional[dict[str, set[int]]]) -> Optional[frozenset]:
    if lines is None:
        return None
    return frozenset((path, n) for path, ns in lines.items() for n in ns)


def _reduce(rows: dict[str, dict], boundary: Boundary,
            prod_index) -> tuple[dict, dict]:
    """{item: covered (file, line) pairs} and {item: direct-call key set}."""
    covered, called = {}, {}
    for item_id, row in rows.items():
        covered[item_id] = _pairs(M.production_lines(row, boundary))
        direct = (M.direct_methods(row, boundary, prod_index)
                  if prod_index is not None else None)
        called[item_id] = frozenset(direct[0]) if direct is not None else None
    return covered, called


def _median(values: list) -> dict:
    """The floor and the number of items behind it, always together."""
    values = [v for v in values if v is not None]
    return {"median": statistics.median(values) if values else None,
            "n": len(values)}


def _recall(gold: frozenset, other: Optional[frozenset]) -> Optional[float]:
    if not gold or other is None:
        return None
    return len(gold & other) / len(gold)


def _region(gold: Optional[frozenset], region: dict[str, set[int]]) -> frozenset:
    """Gold's covered lines INSIDE the item's region -- the 6.2 denominator."""
    if not gold:
        return frozenset()
    return frozenset((path, n) for path, n in gold
                     if n in region.get(path, ()))


def sibling_floors(covered: dict, called: dict,
                   regions: Optional[dict] = None) -> dict:
    """Per-item typical and best sibling scores, reduced to project medians.

    A sibling is another item of the same feature file. Items with no sibling
    are not scored and are counted: a feature holding one scenario cannot say
    anything about how well the metric separates scenarios.
    """
    by_feature: dict[str, list[str]] = {}
    for item_id in covered:
        by_feature.setdefault(feature_of(item_id), []).append(item_id)
    out: dict[str, list] = {key: [] for key in (
        "line_recall_typical", "line_recall_best",
        "api_f1_typical", "api_f1_best",
        "target_region_recall_typical", "target_region_recall_best")}
    n_without_sibling = 0
    for item_id in sorted(covered):
        siblings = [other for other in by_feature[feature_of(item_id)]
                    if other != item_id]
        if not siblings:
            n_without_sibling += 1
            continue
        gold = covered[item_id]
        recalls = [r for r in (_recall(gold, covered[j]) for j in siblings)
                   if r is not None]
        if recalls:
            out["line_recall_typical"].append(statistics.median(recalls))
            out["line_recall_best"].append(max(recalls))
        if called.get(item_id):
            f1s = [M.api_call_similarity(called[item_id], called[j])["f1"]
                   for j in siblings if called.get(j) is not None]
            if f1s:
                out["api_f1_typical"].append(statistics.median(f1s))
                out["api_f1_best"].append(max(f1s))
        if regions is not None:
            target = _region(gold, regions.get(item_id, {}))
            region_recalls = [r for r in
                              (_recall(target, covered[j]) for j in siblings)
                              if r is not None]
            if region_recalls:
                out["target_region_recall_typical"].append(
                    statistics.median(region_recalls))
                out["target_region_recall_best"].append(max(region_recalls))
    floors = {key: _median(values) for key, values in out.items()}
    floors["n_items_without_sibling"] = n_without_sibling
    return floors


def control_floors_for(gold_covered: dict, gold_called: dict,
                       rows: dict[str, dict], boundary: Boundary, prod_index,
                       regions: Optional[dict] = None, *,
                       role: str) -> dict:
    """One control arm's floor against gold, item by item.

    Only items present on both sides are scored, and the count says how many
    that was: a stub run that crashed on half the corpus has a floor over the
    half it reached, and reading it as the whole corpus would understate the
    floor exactly where the control was weakest.

    An assertion-stripped row whose construction the stripper REFUSED
    (`metadata.strip_refusal`) is no stripped-gold control at all, yet it was
    still executed with no files and can carry coverage from retained code.
    It is counted in `n_construction_refused` and not scored, as METRICS.md
    treats every item the control did not reach. A stripped row that was
    constructed and then failed is a control that ran, and is scored.
    """
    refused = ({item_id for item_id, row in rows.items()
                if (row.get("metadata") or {}).get("strip_refusal") is True}
               if role == "assertion_stripped_gold" else set())
    covered, called = _reduce(
        {item_id: row for item_id, row in rows.items()
         if item_id not in refused}, boundary, prod_index)
    recalls, jaccards, f1s, region_recalls = [], [], [], []
    for item_id, gold in sorted(gold_covered.items()):
        if item_id not in covered or gold is None:
            continue
        other = covered[item_id]
        if other is not None and gold:
            recalls.append(len(gold & other) / len(gold))
            jaccards.append(len(gold & other) / len(gold | other))
        if gold_called.get(item_id) and called.get(item_id) is not None:
            f1s.append(M.api_call_similarity(gold_called[item_id],
                                             called[item_id])["f1"])
        if regions is not None and other is not None:
            target = _region(gold, regions.get(item_id, {}))
            if target:
                region_recalls.append(len(target & other) / len(target))
    return {
        "n_rows": len(rows),
        **({"n_construction_refused": len(refused)}
           if role == "assertion_stripped_gold" else {}),
        "n_scored": len(recalls),
        "n_passed": sum(1 for row in rows.values()
                        if row.get("outcome") == "passed"),
        "coverage_recall": _median(recalls),
        "coverage_jaccard": _median(jaccards),
        "api_f1": _median(f1s),
        "target_region_recall": _median(region_recalls),
    }


def control_floors(*, project: str, gold_rows: dict[str, dict],
                   boundary: Boundary, prod_index=None,
                   regions: Optional[dict] = None,
                   controls: Optional[dict[str, dict]] = None) -> dict:
    """The floors table for one project."""
    if not gold_rows:
        raise FloorsInputError(
            "REFUSED: no gold rows. Every floor here is measured against "
            "gold's own coverage and calls; there is nothing to be a floor of.")
    unknown = sorted(set(controls or {}) - set(CONTROL_ROLES))
    if unknown:
        raise FloorsInputError(
            f"REFUSED: unknown control role(s) {unknown}; expected "
            f"{list(CONTROL_ROLES)}. A floor is only readable when the table "
            f"says which control produced it.")
    gold_covered, gold_called = _reduce(gold_rows, boundary, prod_index)
    floors = {"sibling_gold": sibling_floors(gold_covered, gold_called, regions)}
    for role in CONTROL_ROLES:
        rows = (controls or {}).get(role)
        floors[role] = (control_floors_for(gold_covered, gold_called, rows,
                                           boundary, prod_index, regions,
                                           role=role)
                        if rows else None)
    return {
        "schema": SCHEMA,
        "project": project,
        "n_gold_items": len(gold_rows),
        "api_scored": prod_index is not None,
        "target_regions_scored": regions is not None,
        "floors": floors,
    }


def write_floors(document: dict, out: str) -> str:
    with open(out, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=1, sort_keys=True)
        stream.write("\n")
    return out


# --------------------------------------------------------------------------
# selftest

def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    boundary = Boundary(version=1, project="t", repo_root="/x",
                        removable=[("src/Test/", "generated test code")],
                        retained=[])

    def row(item_id, lines, outcome="passed"):
        return {"item_id": item_id, "outcome": outcome,
                "coverage_lines": {"src/Prod/Cart.php": lines}}

    # Two scenarios of one feature that share their fixture lines (10, 11) and
    # differ in one behaviour line each; a third feature holds one scenario.
    gold = {
        "f/a.feature:1": row("f/a.feature:1", [10, 11, 20]),
        "f/a.feature:5": row("f/a.feature:5", [10, 11, 21]),
        "f/b.feature:1": row("f/b.feature:1", [10, 11, 30]),
    }
    regions = {"f/a.feature:1": {"src/Prod/Cart.php": {20, 21}},
               "f/a.feature:5": {"src/Prod/Cart.php": {20, 21}},
               "f/b.feature:1": {"src/Prod/Cart.php": {30}}}
    doc = control_floors(project="t", gold_rows=gold, boundary=boundary,
                         regions=regions)
    sib = doc["floors"]["sibling_gold"]
    check("the sibling floor is high on whole-execution coverage -- the "
          "shared fixture is most of the lines",
          sib["line_recall_typical"] == {"median": 2 / 3, "n": 2}, str(sib))
    check("the sibling floor is 0.0 on the target region, which is what the "
          "region exists to show",
          sib["target_region_recall_typical"] == {"median": 0.0, "n": 2},
          str(sib))
    check("an item with no sibling is counted, not scored",
          sib["n_items_without_sibling"] == 1)
    check("without a production index the API floor is absent, not 0.0",
          sib["api_f1_typical"] == {"median": None, "n": 0}
          and doc["api_scored"] is False, str(sib))

    stripped = {iid: row(iid, sorted(r["coverage_lines"]["src/Prod/Cart.php"]))
                for iid, r in gold.items()}
    stub = {iid: row(iid, [], outcome="passed") for iid in gold}
    doc = control_floors(project="t", gold_rows=gold, boundary=boundary,
                         regions=regions,
                         controls={"assertion_stripped_gold": stripped,
                                   "stub": stub})
    check("assertion-stripped gold executes the same lines: the coverage "
          "floor is 1.0 and so is the region floor",
          doc["floors"]["assertion_stripped_gold"]["coverage_recall"]
          == {"median": 1.0, "n": 3}
          and doc["floors"]["assertion_stripped_gold"]
                 ["target_region_recall"] == {"median": 1.0, "n": 3},
          str(doc["floors"]["assertion_stripped_gold"]))
    check("a stub that covers nothing floors at 0.0 on both",
          doc["floors"]["stub"]["coverage_recall"] == {"median": 0.0, "n": 3}
          and doc["floors"]["stub"]["target_region_recall"]
              == {"median": 0.0, "n": 3},
          str(doc["floors"]["stub"]))
    check("a control arm with no rows is absent, never a floor of 0.0",
          control_floors(project="t", gold_rows=gold,
                         boundary=boundary)["floors"]["stub"] is None)

    # A refused stripping construction still EXECUTES (runner: an empty
    # solution runs with no glue) and so can carry coverage from retained
    # code: 2 of gold's 3 lines here.  Beside it, a stripped row that WAS
    # constructed, ran the fixture and failed before the behaviour line.
    refused = {**row("f/a.feature:1", [10, 11], outcome="no_files_returned"),
               "produced_files": [],
               "metadata": {"strip_refusal": True, "stripped_gold": True,
                            "item_id": "f/a.feature:1",
                            "adapter_error": "no Then-only definition"}}
    stripped = {"f/a.feature:1": refused,
                "f/a.feature:5": row("f/a.feature:5", [10, 11],
                                     outcome="failed"),
                "f/b.feature:1": row("f/b.feature:1", [10, 11, 30])}
    floor = control_floors(project="t", gold_rows=gold, boundary=boundary,
                           controls={"assertion_stripped_gold": stripped}
                           )["floors"]["assertion_stripped_gold"]
    check("a refused stripping construction is counted and not scored: it "
          "is not a stripped-gold control, whatever retained code it covered",
          floor["n_rows"] == 3 and floor.get("n_construction_refused") == 1
          and floor["n_scored"] == 2, str(floor))
    check("...while a stripped row that was constructed and then failed is "
          "still scored: the floor is over 2/3 and 1.0, not over 1.0 alone",
          floor["coverage_recall"] == {"median": (2 / 3 + 1.0) / 2, "n": 2}
          and floor["n_passed"] == 1, str(floor))

    try:
        control_floors(project="t", gold_rows=gold, boundary=boundary,
                       controls={"sibling_gold": stub})
        check("an unknown control role refuses", False, "no exception")
    except FloorsInputError as exc:
        check("an unnamed control role refuses -- a floor is unreadable "
              "without the control that produced it",
              "unknown control role" in str(exc), str(exc))
    try:
        control_floors(project="t", gold_rows={}, boundary=boundary)
        check("no gold rows refuses", False, "no exception")
    except FloorsInputError as exc:
        check("no gold rows refuses rather than printing empty floors",
              str(exc).startswith("REFUSED:"), str(exc))

    print("ALL PASS (control_floors)" if ok else "FAILURES (control_floors)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
