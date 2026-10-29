"""One canonical-results column per campaign cell, with no cross-project pool.

The single-run table remains the code of record.  This module only loads a
small descriptor, calls :func:`r2t.bench.results.results` once per available cell,
and lays the returned :func:`r2t.bench.results.table_rows` side by side.
"""
from __future__ import annotations

import json
import os
from typing import Optional

import yaml

from . import draws
from . import results as R
from ..core.boundary import load_boundary
from ..core.constants import SUBMITTED_CONDITION
from ..data.profile import API_SCORING_NONE, ProfileError, load_profile
from ..core.paths import BENCHMARK_ROOT


DESCRIPTOR_SCHEMA = "r2t.campaign-results-descriptor/v1"
OUTPUT_SCHEMA = "r2t.campaign-results/v1"

NO_MUTANTS = "no_mutants"
NOT_SCORED_MUTATION = "not_scored_mutation"
NOT_MEASURED_API = "not_measured_api"
NO_GOLD_RUN = "no_gold_run"
NO_PASS = "no_pass"
UNMERGEABLE = "unmergeable"
NOT_SCORED_COVERAGE = "not_scored_coverage"
NOT_SCORED_API = "not_scored_api"

FORMATS = ("text", "markdown", "json")
_TOP_FIELDS = frozenset({"schema", "cells"})
_CELL_FIELDS = frozenset({
    "label", "run", "profile", "boundary", "gold", "test_quality",
    "prod_index", "mutation_capable", "unavailable", "campaign", "release",
})
_PATH_FIELDS = ("run", "profile", "boundary", "gold", "test_quality",
                "prod_index", "campaign", "release")


class CampaignTableError(RuntimeError):
    """A descriptor or cell from which an honest table cannot be built."""


def _message(exc: BaseException) -> str:
    text = str(exc)
    return text[len("REFUSED: "):] if text.startswith("REFUSED: ") else text


def _path(base: str, value, field: str, *, required: bool = False):
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        suffix = "a non-empty path" if required else "a path or null"
        raise CampaignTableError(f"cell field {field!r} must be {suffix}")
    return os.path.abspath(value if os.path.isabs(value)
                           else os.path.join(base, value))


def load_descriptor(path: str) -> dict:
    """Load JSON or YAML; relative inputs are relative to this descriptor."""
    path = os.path.abspath(path)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        raise CampaignTableError(f"cannot read descriptor {path}: {exc}") \
            from None
    if not isinstance(doc, dict):
        raise CampaignTableError(f"descriptor {path} must be a mapping")
    unknown = sorted(set(doc) - _TOP_FIELDS)
    if unknown:
        raise CampaignTableError(f"descriptor {path} has unknown field(s) "
                                 f"{unknown}")
    if doc.get("schema") != DESCRIPTOR_SCHEMA:
        raise CampaignTableError(
            f"descriptor {path} has schema {doc.get('schema')!r}, not "
            f"{DESCRIPTOR_SCHEMA!r}")
    raw_cells = doc.get("cells")
    if not isinstance(raw_cells, list) or not raw_cells:
        raise CampaignTableError(f"descriptor {path} needs a non-empty cells list")

    base = os.path.dirname(path)
    cells, labels = [], set()
    for index, raw in enumerate(raw_cells):
        where = f"cells[{index}]"
        if not isinstance(raw, dict):
            raise CampaignTableError(f"{where} must be a mapping")
        unknown = sorted(set(raw) - _CELL_FIELDS)
        if unknown:
            raise CampaignTableError(f"{where} has unknown field(s) {unknown}")
        label = raw.get("label")
        if not isinstance(label, str) or not label.strip():
            raise CampaignTableError(f"{where}.label must be a non-empty string")
        if label in labels:
            raise CampaignTableError(f"campaign repeats cell label {label!r}")
        labels.add(label)

        unavailable = raw.get("unavailable")
        if unavailable not in (None, UNMERGEABLE):
            raise CampaignTableError(
                f"{where}.unavailable must be null or {UNMERGEABLE!r}")
        capable = raw.get("mutation_capable", True)
        if not isinstance(capable, bool):
            raise CampaignTableError(
                f"{where}.mutation_capable must be true or false")

        cell = {"label": label, "mutation_capable": capable,
                "unavailable": unavailable}
        for field in _PATH_FIELDS:
            cell[field] = _path(
                base, raw.get(field), f"{where}.{field}",
                required=(unavailable is None
                          and field in {"run", "profile", "boundary"}))
        cells.append(cell)
    return {"schema": DESCRIPTOR_SCHEMA, "path": path, "cells": cells}


def _row_definitions() -> list[tuple[str, str, Optional[str]]]:
    return ([(key, label, None) for key, label, _outcomes in R.LADDER]
            + [(key, label, block)
               for key, label, block, _name in R.QUALITY_ROWS])


def _campaign_digest(path: Optional[str]) -> Optional[list[str]]:
    if not path:
        return None
    from .campaign import campaign_digest
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        return [campaign_digest(doc)]
    except (OSError, ValueError, TypeError, SystemExit) as exc:
        raise CampaignTableError(
            f"cannot read cell campaign {path}: {_message(exc)}") \
            from None


def _stable_reason(block: str, res: dict, profile, capable: bool) -> str:
    reason = res[block].get("reason")
    if block == "mutation":
        if not capable:
            return NO_MUTANTS
        return NO_PASS if reason == R.NO_PASS else NOT_SCORED_MUTATION
    if block == "api" and profile.api_scoring == API_SCORING_NONE:
        return NOT_MEASURED_API
    if reason == R.NO_PASS:
        return NO_PASS
    if res.get("gold") is None:
        return NO_GOLD_RUN
    return NOT_SCORED_COVERAGE if block == "coverage" else NOT_SCORED_API


def _available_cell(row: dict, block: Optional[str], res: dict,
                    profile, capable: bool) -> dict:
    if row.get("withheld"):
        cell = {"status": "withheld", "display": row["value"],
                "number": None, "reason": row.get("reason")}
        if row.get("in_ladder") is True:
            denominator = res["ladder"]["denominator"]
            cell.update({"count": row["count"],
                         "denominator": denominator,
                         "ladder_n": denominator})
        if "sensitivity_number" in row:
            cell["sensitivity_number"] = row["sensitivity_number"]
        return cell
    if row.get("in_ladder") is True:
        denominator = res["ladder"]["denominator"]
        return {"status": "scored", "display": row["value"],
                "number": row["rate"], "count": row["count"],
                "denominator": denominator, "ladder_n": denominator,
                "reason": None}
    if row.get("not_applicable") is True:
        cell = {"status": "not_applicable", "display": row["value"],
                "number": None, "reason": row["reason"]}
        if "sensitivity_number" in row:
            cell["sensitivity_number"] = row["sensitivity_number"]
        return cell
    if row.get("not_measured") is True:
        # A gold-killed candidate slice (GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md
        # section 5): named for why, not as a generic unscored mutation cell.
        return {"status": "not_measured", "display": row["value"],
                "number": None, "reason": row["reason"]}
    if row.get("number") is not None:
        return {"status": "scored", "display": row["value"],
                "number": row["number"], "reason": None}
    stable = _stable_reason(block or "", res, profile, capable)
    return {"status": "not_scored", "display": f"n/a ({stable})",
            "number": None, "reason": stable, "detail": row["value"]}


#: The one diagnostic row, kept out of `table` for the same reason
#: `results.production_coverage` is kept out of `table_rows`: the canonical
#: block is thirteen rows, changing it is a methodology decision, and a
#: fourteenth row rendered inside it would be read as one of them.  `(key,
#: label)`, and the label is the single one `results` already publishes.
PRODUCTION_COVERAGE_ROW = ("production_coverage", R.PRODUCTION_COVERAGE_LABEL)


def _diagnostic_cell(res: dict) -> dict:
    """Project one cell's production-coverage diagnostic into a column.

    Same three shapes the canonical cells use -- scored, withheld, not scored
    with a stable reason -- so a reader does not learn a second vocabulary for
    a row that sits under the same header.  The two unscored causes stay
    apart: `no_pass` says nothing passed, `not_scored_coverage` says the
    passes were never measured, and neither is "covered nothing".
    """
    block = res["production_coverage"]
    if block["scored"]:
        return {"status": "scored",
                "display": f"{block['rate'] * 100:.1f}% "
                           f"({block['n_covering']}/{block['denominator']})",
                "number": block["rate"], "count": block["n_covering"],
                "denominator": block["denominator"],
                "ladder_n": block["denominator"],
                "zero_production_lines": block["n_zero_production_lines"],
                "reason": None}
    if not res["population"]["canonical_values_admitted"]:
        return {"status": "withheld",
                "display": f"withheld ({block['reason']})",
                "number": None, "reason": block["reason"]}
    stable = NO_PASS if not block["n_passed"] else NOT_SCORED_COVERAGE
    return {"status": "not_scored", "display": f"n/a ({stable})",
            "number": None, "reason": stable, "detail": block["reason"],
            "zero_production_lines": block["n_zero_production_lines"],
            "not_collected": block["n_not_collected"]}


def campaign_results(descriptor_path: str) -> dict:
    """Build one side-by-side table; no value is pooled across cells."""
    descriptor = load_descriptor(descriptor_path)
    definitions = _row_definitions()
    table = [{"key": key, "label": label, "cells": []}
             for key, label, _block in definitions]
    diagnostics = [{"key": PRODUCTION_COVERAGE_ROW[0],
                    "label": PRODUCTION_COVERAGE_ROW[1], "cells": []}]
    columns = []

    for spec in descriptor["cells"]:
        unavailable = spec["unavailable"]
        if unavailable:
            columns.append({
                "label": spec["label"], "unavailable": unavailable,
                "provenance": {
                    "run": spec["run"],
                    "gold": None,
                    "test_quality": None,
                    "prod_index": None,
                    "campaign_digest": _campaign_digest(spec["campaign"]),
                    "population_status": None,
                    "population_source": None,
                    "planned_n": None, "n": None, "observed_n": None,
                    "missing_planned_ids": None, "passed": None,
                    "ladder_n": None, "classified_n": None,
                    "population_withheld_reasons": None,
                    "ladder_withheld_reasons": None,
                },
            })
            for row in table + diagnostics:
                row["cells"].append({
                    "status": "not_scored",
                    "display": f"n/a ({unavailable})",
                    "number": None, "reason": unavailable,
                })
            continue

        try:
            profile = load_profile(spec["profile"])
        except ProfileError as exc:
            raise CampaignTableError(
                f"cell {spec['label']!r} profile {spec['profile']}: "
                f"{_message(exc)}") from None
        except (OSError, KeyError, TypeError, ValueError,
                yaml.YAMLError) as exc:
            raise CampaignTableError(
                f"cell {spec['label']!r} profile {spec['profile']}: {exc}") \
                from None
        try:
            boundary = load_boundary(spec["boundary"])
        except (OSError, KeyError, TypeError, ValueError,
                yaml.YAMLError) as exc:
            raise CampaignTableError(
                f"cell {spec['label']!r} boundary {spec['boundary']}: "
                f"{exc}") from None
        if profile.project != boundary.project:
            raise CampaignTableError(
                f"cell {spec['label']!r}: profile project "
                f"{profile.project!r} differs from boundary project "
                f"{boundary.project!r}")
        try:
            res = R.results(
                spec["run"], gold_path=spec["gold"] or "",
                test_quality_path=spec["test_quality"],
                prod_index_path=spec["prod_index"] or "",
                boundary=boundary, artifacts="",
                api_scoring=profile.api_scoring,
                language=profile.language,
                release_path=spec["release"])
        except (R.ResultsInputError, draws.DrawRefusal) as exc:
            raise CampaignTableError(
                f"cell {spec['label']!r}: {_message(exc)}") from None
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise CampaignTableError(
                f"cell {spec['label']!r} results inputs: {exc}") from None

        descriptor_campaign = _campaign_digest(spec["campaign"])
        if descriptor_campaign is not None \
                and descriptor_campaign != res["campaign_digest"]:
            raise CampaignTableError(
                f"cell {spec['label']!r}: descriptor campaign digest "
                f"{descriptor_campaign!r} differs from result rows "
                f"{res['campaign_digest']!r}")

        if res.get("tier") == SUBMITTED_CONDITION:
            raise CampaignTableError(
                f"cell {spec['label']!r}: submitted-tier rows never enter "
                "a campaign table; campaigns are reserved for reviewed "
                "study conditions")

        if not spec["mutation_capable"] and res["mutation"].get("scored"):
            raise CampaignTableError(
                f"cell {spec['label']!r} declares mutation_capable=false "
                "but its test-quality input contains a mutation score")
        source_rows = R.table_rows(res)
        expected = [key for key, _label, _block in definitions]
        if [row["key"] for row in source_rows] != expected:
            raise CampaignTableError(
                f"cell {spec['label']!r} returned a non-canonical row order")
        observed_n = res["population"]["observed_n"]
        columns.append({
            "label": spec["label"], "unavailable": None,
            "provenance": {
                "run": res["run"],
                "gold": res["gold"],
                "test_quality": res["test_quality"],
                "prod_index": res["prod_index"],
                "campaign_digest": res["campaign_digest"],
                "population_status": res["population"]["status"],
                "population_source": res["population"]["source"],
                "planned_n": res["population"]["planned_n"],
                "n": observed_n, "observed_n": observed_n,
                "missing_planned_ids":
                    res["population"]["missing_planned_ids"],
                "passed": res["n_passed"],
                "ladder_n": res["population"]["ladder_n"],
                "classified_n": res["population"]["classified_n"],
                "population_withheld_reasons":
                    res["population"]["withheld_reasons"],
                "ladder_withheld_reasons":
                    res["ladder"]["withheld_reasons"],
                # Only on a benchmark 2.0 cell, so 1.x tables keep their bytes.
                **({"population_exclusions":
                    res["population"]["population_exclusions"]}
                   if "population_exclusions" in res["population"] else {}),
            },
        })
        for target, source, (_key, _label, block) in zip(
                table, source_rows, definitions):
            target["cells"].append(_available_cell(
                source, block, res, profile, spec["mutation_capable"]))
        for row in diagnostics:
            row["cells"].append(_diagnostic_cell(res))

    return {"schema": OUTPUT_SCHEMA, "descriptor": descriptor["path"],
            "columns": columns, "table": table,
            "diagnostics": diagnostics}


def _digest_text(value) -> str:
    if not value:
        return "-"
    if len(value) == 1:
        return value[0]
    return f"{len(value)} DIFFERENT: {', '.join(value)}"


#: Printed above the diagnostic block in every human format.  The block is
#: physically below and outside the canonical table, but a reader who lifts
#: one row out of a pasted table has only this line to tell them the row is
#: not one of the thirteen.
DIAGNOSTIC_HEADING = "DIAGNOSTICS (not canonical metrics)"
DIAGNOSTIC_CAVEAT = (
    "A pass covering no production line ran green over none of the system "
    "under test. Measured from the `coverage_lines` already on every row; "
    "over the same denominator as `pass rate`; not one of the thirteen "
    "canonical metrics and no canonical value depends on it."
)


def render_text(report: dict) -> str:
    matrix = [["metric"] + [column["label"] for column in report["columns"]]]
    matrix.extend([[row["label"]]
                   + [cell["display"] for cell in row["cells"]]
                   for row in report["table"]])
    diagnostic_matrix = [[row["label"]]
                         + [cell["display"] for cell in row["cells"]]
                         for row in report["diagnostics"]]
    # Widths are shared with the canonical rows so the two blocks line up as
    # one readable grid; the blank line and the heading are what separate them.
    widths = [max(len(str(row[index]))
                  for row in matrix + diagnostic_matrix)
              for index in range(len(matrix[0]))]
    lines = ["CAMPAIGN RESULTS", ""]
    for index, row in enumerate(matrix):
        lines.append("  ".join(str(value).ljust(widths[i])
                               for i, value in enumerate(row)).rstrip())
        if index == 0:
            lines.append("  ".join("-" * width for width in widths))
    lines.extend(["", DIAGNOSTIC_HEADING])
    for row in diagnostic_matrix:
        lines.append("  ".join(str(value).ljust(widths[i])
                               for i, value in enumerate(row)).rstrip())
    lines.append("  " + DIAGNOSTIC_CAVEAT)
    lines.extend(["", "PROVENANCE"])
    for column in report["columns"]:
        provenance = column["provenance"]
        lines.append(f"  {column['label']}")
        lines.append(f"    run           {provenance['run'] or '-'}")
        lines.append(f"    gold          {provenance['gold'] or '-'}")
        lines.append(f"    test quality  {provenance['test_quality'] or '-'}")
        lines.append(f"    prod index    {provenance['prod_index'] or '-'}")
        lines.append("    campaign      "
                     + _digest_text(provenance["campaign_digest"]))
        lines.append("    population_status    "
                     + (provenance["population_status"] or "-"))
        lines.append("    population_source    "
                     + (provenance["population_source"] or "-"))
        planned_n = (provenance["planned_n"]
                     if provenance["planned_n"] is not None else "-")
        observed_n = (provenance["observed_n"]
                      if provenance["observed_n"] is not None else "-")
        lines.append(f"    planned_n            {planned_n}")
        lines.append(f"    observed_n           {observed_n}")
        ladder_n = (provenance["ladder_n"]
                    if provenance["ladder_n"] is not None else "-")
        classified = (provenance["classified_n"]
                      if provenance["classified_n"] is not None else "-")
        lines.append(f"    ladder_n             {ladder_n}")
        lines.append(f"    classified_n         {classified}")
        missing = provenance["missing_planned_ids"]
        lines.append("    missing_planned_ids  "
                     + ("unavailable" if missing is None else str(missing)))
        reasons = list(provenance["ladder_withheld_reasons"] or ())
        reasons.extend(
            reason for reason in
            provenance["population_withheld_reasons"] or ()
            if reason not in reasons)
        lines.append("    ladder        " + (
            "withheld (" + "; ".join(reasons) + ")" if reasons else
            "available"
            if provenance["ladder_withheld_reasons"] == []
            and provenance["population_withheld_reasons"] == [] else "-"))
        lines.append("    passed        " + (
            str(provenance["passed"])
            if provenance["passed"] is not None else "-"))
        if provenance.get("population_exclusions") is not None:
            from .report import population_exclusions_text
            lines.append("    2.0 excluded  " + population_exclusions_text(
                provenance["population_exclusions"]))
    return "\n".join(lines) + "\n"


def _md(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict) -> str:
    labels = [column["label"] for column in report["columns"]]
    lines = ["### Campaign results", "",
             "| metric | " + " | ".join(_md(label) for label in labels) + " |",
             "| --- | " + " | ".join("---" for _ in labels) + " |"]
    for row in report["table"]:
        lines.append("| " + _md(row["label"]) + " | "
                     + " | ".join(_md(cell["display"])
                                    for cell in row["cells"]) + " |")
    lines.extend(["", f"#### {DIAGNOSTIC_HEADING}", "",
                  "| diagnostic | " + " | ".join(_md(label)
                                                 for label in labels) + " |",
                  "| --- | " + " | ".join("---" for _ in labels) + " |"])
    for row in report["diagnostics"]:
        lines.append("| " + _md(row["label"]) + " | "
                     + " | ".join(_md(cell["display"])
                                    for cell in row["cells"]) + " |")
    lines.extend(["", f"*{DIAGNOSTIC_CAVEAT}*"])
    lines.extend(["", "#### Provenance", "",
                  "| cell | run | gold | test quality | prod index | "
                  "campaign | population status | population source | "
                  "planned_n | observed_n | ladder_n | classified_n | "
                  "missing_planned_ids | ladder | passed |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- | --- | "
                  "--- | --- | --- | --- | --- | --- |"])
    for column in report["columns"]:
        provenance = column["provenance"]
        lines.append("| " + " | ".join([
            _md(column["label"]), _md(provenance["run"] or "-"),
            _md(provenance["gold"] or "-"),
            _md(provenance["test_quality"] or "-"),
            _md(provenance["prod_index"] or "-"),
            _md(_digest_text(provenance["campaign_digest"])),
            _md(provenance["population_status"] or "-"),
            _md(provenance["population_source"] or "-"),
            _md(provenance["planned_n"]
                if provenance["planned_n"] is not None else "-"),
            _md(provenance["observed_n"]
                if provenance["observed_n"] is not None else "-"),
            _md(provenance["ladder_n"]
                if provenance["ladder_n"] is not None else "-"),
            _md(provenance["classified_n"]
                if provenance["classified_n"] is not None else "-"),
            _md(provenance["missing_planned_ids"]
                if provenance["missing_planned_ids"] is not None
                else "unavailable"),
            _md(("withheld (" + "; ".join(dict.fromkeys(
                (provenance["ladder_withheld_reasons"] or [])
                + (provenance["population_withheld_reasons"] or []))) + ")")
                if (provenance["ladder_withheld_reasons"]
                    or provenance["population_withheld_reasons"]) else
                "available"
                if provenance["ladder_withheld_reasons"] == []
                and provenance["population_withheld_reasons"] == [] else "-"),
            _md(provenance["passed"]
                if provenance["passed"] is not None else "-"),
        ]) + " |")
    excluded = [column for column in report["columns"]
                if column["provenance"].get("population_exclusions")
                is not None]
    if excluded:
        from .report import population_exclusions_text
        lines.append("")
        lines.extend(
            f"- {_md(column['label'])}: 2.0 excluded: "
            + _md(population_exclusions_text(
                column["provenance"]["population_exclusions"]))
            for column in excluded)
    return "\n".join(lines) + "\n"


def render_json(report: dict) -> str:
    return json.dumps(report, indent=1, sort_keys=True) + "\n"


def render(report: dict, fmt: str = "text") -> str:
    if fmt == "text":
        return render_text(report)
    if fmt == "markdown":
        return render_markdown(report)
    if fmt == "json":
        return render_json(report)
    raise CampaignTableError(
        f"unknown --format {fmt!r}; expected one of {', '.join(FORMATS)}")


def _write_jsonl(path: str, rows: list[dict]) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    return path


def selftest() -> int:
    """Descriptor, projection, reasons, renderers, and the CLI; no execution."""
    import contextlib
    import io
    import tempfile

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    benchmark = BENCHMARK_ROOT
    profile = os.path.join(benchmark, "config", "profile_algorand.yml")
    boundary = os.path.join(benchmark, "config", "boundary_algorand.yml")
    coreshop_profile = os.path.join(
        benchmark, "config", "profile_coreshop.yml")
    coreshop_boundary = os.path.join(
        benchmark, "config", "boundary_coreshop.yml")
    with tempfile.TemporaryDirectory() as root:
        passed = _write_jsonl(os.path.join(root, "passed.jsonl"), [{
            "item_id": "algorand-sdk/features/unit/example.feature:1",
            "outcome": "passed",
            "coverage_lines": {"src/main/java/Example.java": [1, 2]},
        }])
        gold = _write_jsonl(os.path.join(root, "gold.jsonl"), [{
            "item_id": "algorand-sdk/features/unit/example.feature:1",
            "outcome": "passed",
            "coverage_lines": {"src/main/java/Example.java": [1, 2]},
        }])
        failed = _write_jsonl(os.path.join(root, "failed.jsonl"), [{
            "item_id": "algorand-sdk/features/unit/example.feature:1",
            "outcome": "failed",
        }])
        unknown = _write_jsonl(os.path.join(root, "unknown.jsonl"), [
            {"item_id": "algorand-sdk/features/unit/example.feature:1",
             "outcome": "failed"},
            {"item_id": "algorand-sdk/features/unit/example.feature:2",
             "outcome": "novel_terminal",
             "n_files": 1,
             "produced_files": [{"file_path": "ExampleTest.java",
                                  "code": "class ExampleTest {}"}]},
        ])
        no_coverage = _write_jsonl(
            os.path.join(root, "no-coverage.jsonl"), [{
                "item_id": "algorand-sdk/features/unit/example.feature:1",
                "outcome": "passed",
            }])
        # The API rows are over CALL EVENTS, so the indexed cell below only
        # scores if these carry one: a production callee the
        # `_index_fixture` knows, called from a removable Behat context.
        php_calls = [{"callee_file": "src/Prod/Cart.php", "callee_line": 10,
                      "callee": "App\\Cart::total",
                      "caller_file": "src/CoreShop/Behat/Context/Domain/"
                                     "CartContext.php"}]
        php_run = _write_jsonl(os.path.join(root, "php.jsonl"), [{
            "item_id": "coreshop/features/domain/example.feature:1",
            "outcome": "passed",
            "coverage_lines": {"src/CoreShop/Component/Foo.php": [1]},
            "direct_calls": php_calls,
        }])
        php_gold = _write_jsonl(os.path.join(root, "php-gold.jsonl"), [{
            "item_id": "coreshop/features/domain/example.feature:1",
            "outcome": "passed",
            "coverage_lines": {"src/CoreShop/Component/Foo.php": [1]},
            "direct_calls": php_calls,
        }])
        php_nodirect = _write_jsonl(
            os.path.join(root, "php-nodirect.jsonl"), [{
                "item_id": "coreshop/features/domain/example.feature:1",
                "outcome": "passed",
                "coverage_lines": {"src/CoreShop/Component/Foo.php": [1]},
            }])
        discovered = _write_jsonl(
            os.path.join(root, "discovered.jsonl"), [{
                "item_id": "algorand-sdk/features/unit/example.feature:1",
                "outcome": "passed",
                "coverage_lines": {"src/main/java/Example.java": [1, 2]},
            }])
        release_one = _write_jsonl(
            os.path.join(root, "release-one.jsonl"), [{
                "item_id": "algorand-sdk/features/unit/example.feature:1",
            }])
        release_two = _write_jsonl(
            os.path.join(root, "release-two.jsonl"), [{
                "item_id": "algorand-sdk/features/unit/example.feature:1",
            }, {
                "item_id": "algorand-sdk/features/unit/example.feature:2",
            }])
        release_php = _write_jsonl(
            os.path.join(root, "release-php.jsonl"), [{
                "item_id": "coreshop/features/domain/example.feature:1",
            }])
        from . import campaign as campaign_module
        foreign_campaign_document = campaign_module.campaign_fingerprint(
            campaign_id="foreign-campaign", k_workers=1,
            shard_rule=campaign_module.SHARD_RULE, trial_budget=1,
            coverage=False, harness_version="selftest",
            config_digest="0123456789abcdef", model=None,
            container_image_digest="sha256:selftest",
            workspace_seed_digest="selftest-seed",
            database_dump_digest=campaign_module.NO_DATABASE,
            protocol_version=1, protocol_digest="0123456789abcdef")
        foreign_campaign_path = os.path.join(root, "foreign-campaign.json")
        with open(foreign_campaign_path, "w", encoding="utf-8") as fh:
            json.dump(foreign_campaign_document, fh)
        quality_doc = {
            "verdict_basis": "hard_subset",
            "per_item": {
                "algorand-sdk/features/unit/example.feature:1": {
                    "candidate_killed": 1, "denominator": 1,
                    "recall": 1.0, "full_candidate_killed": 1,
                    "full_denominator": 2, "full_recall": 0.5,
                    "candidate_only_kills": 1,
                },
            },
            **R.TQ.COMPLETE_QUALIFIER_FIXTURE,
        }
        explicit_quality = os.path.join(root, "explicit-quality.json")
        discovered_quality = R.TQ.sidecar_paths(discovered)[0]
        for quality_path in (explicit_quality, discovered_quality):
            with open(quality_path, "w", encoding="utf-8") as fh:
                json.dump(quality_doc, fh)
        prod_index = os.path.join(root, "prod-index.json")
        R._index_fixture(prod_index)
        cells = [
            {"label": "scored", "run": "passed.jsonl", "gold": "gold.jsonl",
             "profile": profile, "boundary": boundary,
             "release": "release-one.jsonl", "mutation_capable": True},
            {"label": "no gold", "run": "passed.jsonl", "profile": profile,
             "boundary": boundary, "release": "release-one.jsonl",
             "mutation_capable": True},
            {"label": "functional", "run": "passed.jsonl", "profile": profile,
             "boundary": boundary, "release": "release-one.jsonl",
             "mutation_capable": False},
            {"label": "no pass", "run": "failed.jsonl", "profile": profile,
             "boundary": boundary, "release": "release-one.jsonl",
             "mutation_capable": True},
            {"label": "missing", "unavailable": UNMERGEABLE},
            {"label": "no coverage", "run": "no-coverage.jsonl",
             "gold": "gold.jsonl", "profile": profile,
             "boundary": boundary, "release": "release-one.jsonl",
             "mutation_capable": True},
            {"label": "no api index", "run": "php.jsonl",
             "gold": "php-gold.jsonl", "profile": coreshop_profile,
             "boundary": coreshop_boundary, "release": "release-php.jsonl",
             "mutation_capable": True},
            {"label": "explicit quality", "run": "passed.jsonl",
             "gold": "gold.jsonl", "test_quality": "explicit-quality.json",
             "profile": profile, "boundary": boundary,
             "release": "release-one.jsonl", "mutation_capable": True},
            {"label": "discovered quality", "run": "discovered.jsonl",
             "gold": "gold.jsonl", "profile": profile,
             "boundary": boundary, "release": "release-one.jsonl",
             "mutation_capable": True},
            {"label": "indexed", "run": "php.jsonl",
             "gold": "php-gold.jsonl", "prod_index": "prod-index.json",
             "profile": coreshop_profile, "boundary": coreshop_boundary,
             "release": "release-php.jsonl", "mutation_capable": True},
            {"label": "unknown terminal", "run": "unknown.jsonl",
             "profile": profile, "boundary": boundary,
             "release": "release-two.jsonl", "mutation_capable": True},
            {"label": "incomplete", "run": "passed.jsonl",
             "profile": profile, "boundary": boundary,
             "release": "release-two.jsonl", "mutation_capable": True},
            {"label": "indexed without direct calls",
             "run": "php-nodirect.jsonl", "gold": "php-gold.jsonl",
             "prod_index": "prod-index.json", "profile": coreshop_profile,
             "boundary": coreshop_boundary, "release": "release-php.jsonl",
             "mutation_capable": True},
        ]
        descriptor_doc = {"schema": DESCRIPTOR_SCHEMA, "cells": cells}
        yaml_path = os.path.join(root, "campaign.yml")
        json_path = os.path.join(root, "campaign.json")
        with open(yaml_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(descriptor_doc, fh, sort_keys=False)
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(descriptor_doc, fh)

        yaml_descriptor = load_descriptor(yaml_path)
        json_descriptor = load_descriptor(json_path)
        check("JSON and YAML descriptors resolve the same cells",
              yaml_descriptor["cells"] == json_descriptor["cells"])
        check("descriptor-relative run and gold paths are resolved",
              yaml_descriptor["cells"][0]["run"] == passed
              and yaml_descriptor["cells"][0]["gold"] == gold)
        check("unavailable cells need no unused metric inputs",
              all(yaml_descriptor["cells"][4][field] is None
                  for field in ("run", "profile", "boundary")))

        real_quality_loader = R.TQ.load_bound_test_quality

        def fixture_quality_loader(run_path, summary_path=None):
            quality_path = summary_path or R.TQ.find_sidecar(run_path)
            if quality_path in {explicit_quality, discovered_quality}:
                with open(quality_path, encoding="utf-8") as fh:
                    return json.load(fh)
            return real_quality_loader(run_path, summary_path=summary_path)

        R.TQ.load_bound_test_quality = fixture_quality_loader
        report = campaign_results(yaml_path)
        check("the campaign machine schema remains exactly v1",
              report["schema"] == OUTPUT_SCHEMA
              == "r2t.campaign-results/v1")
        expected = ([row[0] for row in R.LADDER]
                    + [row[0] for row in R.QUALITY_ROWS])
        check("every canonical row appears once and in canonical order",
              [row["key"] for row in report["table"]] == expected)
        by_key = {row["key"]: row for row in report["table"]}
        single = {row["key"]: row for row in R.table_rows(R.results(
            passed, gold_path=gold, prod_index_path="",
            boundary=load_boundary(boundary), artifacts="",
            api_scoring=API_SCORING_NONE, release_path=release_one))}
        check("an available numeric cell is the single-run table's value",
              by_key["coverage_jaccard"]["cells"][0]["number"] == 1.0
              and by_key["pass_rate"]["cells"][0]["display"]
              == single["pass_rate"]["value"])
        scored_ladder_cells = [
            by_key[key]["cells"][0]
            for key, _label, _outcomes in R.LADDER]
        check("scored ladder cells retain equal denominator and ladder_n",
              all({"denominator", "ladder_n"} <= set(cell)
                  and cell["denominator"] == cell["ladder_n"] == 1
                  for cell in scored_ladder_cells))
        reason = "unknown terminal outcome(s): novel_terminal (1)"
        unknown_column = report["columns"][10]
        withheld_ladder_cells = [
            by_key[key]["cells"][10]
            for key, _label, _outcomes in R.LADDER]
        check("withheld ladder cells retain equal denominator and ladder_n",
              all(cell["status"] == "withheld"
                  and cell["number"] is None and cell["reason"] == reason
                  and {"denominator", "ladder_n"} <= set(cell)
                  and cell["denominator"] == cell["ladder_n"] == 2
                  for cell in withheld_ladder_cells),
              str(by_key["pass_rate"]["cells"][10]))
        check("campaign machine provenance exposes planned_n, observed_n, "
              "ladder_n, classified_n, and the withholding reason",
              unknown_column["provenance"]["planned_n"] == 2
              and unknown_column["provenance"]["observed_n"] == 2
              and unknown_column["provenance"]["ladder_n"] == 2
              and unknown_column["provenance"]["classified_n"] == 1
              and unknown_column["provenance"]["ladder_withheld_reasons"]
              == [reason], str(unknown_column["provenance"]))
        check("missing mutation scoring and a functional-only project differ",
              by_key["mutation_recall"]["cells"][0]["reason"]
              == NOT_SCORED_MUTATION
              and by_key["mutation_recall"]["cells"][2]["reason"]
              == NO_MUTANTS)
        check("missing gold, no pass, and unmergeable are stable reasons",
              by_key["coverage_jaccard"]["cells"][1]["reason"] == NO_GOLD_RUN
              and by_key["coverage_jaccard"]["cells"][3]["reason"] == NO_PASS
              and all(row["cells"][4]["reason"] == UNMERGEABLE
                      for row in report["table"]))
        check("profile api_scoring none is distinct from no pass",
              all(by_key[key]["cells"][index]["reason"] == NOT_MEASURED_API
                  for key in ("api_precision", "api_recall", "api_f1")
                  for index in range(4)))
        check("remaining coverage and api gaps have honest fallback reasons",
              by_key["coverage_jaccard"]["cells"][5]["reason"]
              == NOT_SCORED_COVERAGE
              and by_key["api_precision"]["cells"][6]["reason"]
              == NOT_SCORED_API)
        check("campaign projection preserves hard-onlyGen as not applicable "
              "instead of rewriting it as missing mutation scoring",
              all(by_key["mutation_only_gen"]["cells"][index]["status"]
                  == "not_applicable" for index in (7, 8))
              and all(by_key["mutation_only_gen"]["cells"][index]["display"]
                      == R.HARD_SUBSET_ONLY_GEN for index in (7, 8))
              and all(by_key["mutation_only_gen"]["cells"][index]["reason"]
                      == R.HARD_SUBSET_ONLY_GEN_REASON for index in (7, 8)))
        gold_killed_cell = _available_cell(
            {"key": "mutation_jaccard", "value": R.GOLD_KILLED_NOT_MEASURED,
             "number": None, "in_ladder": None, "scored": False,
             "not_measured": True,
             "reason": R.GOLD_KILLED_NOT_MEASURED_REASON},
            "mutation", {}, None, True)
        check("a gold-killed slice's withheld row keeps its own reason",
              gold_killed_cell == {
                  "status": "not_measured",
                  "display": R.GOLD_KILLED_NOT_MEASURED, "number": None,
                  "reason": R.GOLD_KILLED_NOT_MEASURED_REASON},
              str(gold_killed_cell))
        check("provenance is per cell and never pooled",
              report["columns"][0]["provenance"] == {
                  "run": passed, "gold": gold, "test_quality": None,
                  "prod_index": None, "campaign_digest": None,
                  "population_status": "complete",
                  "population_source": f"explicit release {release_one}",
                  "planned_n": 1, "n": 1, "observed_n": 1,
                  "missing_planned_ids": [], "passed": 1, "ladder_n": 1,
                  "classified_n": 1, "population_withheld_reasons": [],
                  "ladder_withheld_reasons": []}
              and report["columns"][4]["provenance"] == {
                  "run": None, "gold": None, "test_quality": None,
                  "prod_index": None, "campaign_digest": None,
                  "population_status": None, "population_source": None,
                  "planned_n": None, "n": None, "observed_n": None,
                  "missing_planned_ids": None,
                  "passed": None, "ladder_n": None,
                  "classified_n": None,
                  "population_withheld_reasons": None,
                  "ladder_withheld_reasons": None})
        available_provenance = [
            column["provenance"] for column in report["columns"]
            if column["unavailable"] is None]
        check("available provenance retains equal n and observed_n",
              all({"n", "observed_n"} <= set(provenance)
                  and provenance["n"] == provenance["observed_n"]
                  for provenance in available_provenance))
        unavailable_provenance = [
            column["provenance"] for column in report["columns"]
            if column["unavailable"] is not None]
        check("unavailable provenance retains null n and observed_n",
              all({"n", "observed_n"} <= set(provenance)
                  and provenance["n"] is None
                  and provenance["observed_n"] is None
                  for provenance in unavailable_provenance))
        check("campaign provenance records explicit and adjacent-discovered "
              "quality evidence plus every resolved scoring input",
              report["columns"][7]["provenance"]["test_quality"]
              == explicit_quality
              and report["columns"][8]["provenance"]["test_quality"]
              == discovered_quality
              and report["columns"][7]["provenance"]["gold"] == gold
              and report["columns"][9]["provenance"]["prod_index"]
              == prod_index)
        check("a cell without direct_calls retains its loaded index in "
              "provenance while only its API scores are withheld",
              report["columns"][12]["provenance"]["run"] == php_nodirect
              and report["columns"][12]["provenance"]["prod_index"]
              == prod_index
              and by_key["coverage_jaccard"]["cells"][12]["number"] == 1.0
              and all(by_key[key]["cells"][12]["number"] is None
                      and by_key[key]["cells"][12]["reason"] == NOT_SCORED_API
                      and by_key[key]["cells"][12]["detail"]
                      == R.NOT_SCORED_API_DIRECT
                      for key in ("api_precision", "api_recall", "api_f1")))

        incomplete_column = report["columns"][11]
        population_reason = "population incomplete: planned_n=2, observed_n=1"
        check("an incomplete campaign cell keeps population withholding "
              "separate from issue #202 while withholding every table value",
              incomplete_column["provenance"]["population_status"]
              == "incomplete"
              and incomplete_column["provenance"]["planned_n"] == 2
              and incomplete_column["provenance"]["observed_n"] == 1
              and incomplete_column["provenance"]["missing_planned_ids"]
              == ["algorand-sdk/features/unit/example.feature:2"]
              and incomplete_column["provenance"]
                  ["ladder_withheld_reasons"] == []
              and incomplete_column["provenance"]
                  ["population_withheld_reasons"] == [population_reason]
              and all(row["cells"][11]["status"] == "withheld"
                      and row["cells"][11]["number"] is None
                      and population_reason in row["cells"][11]["reason"]
                      for row in report["table"]),
              str(incomplete_column))

        # ----------------------------- the diagnostic column (S6, part B)
        #
        # It is rendered beside the canonical block and is not part of it.
        # Both halves of that sentence are checked: the row set above is
        # still exactly thirteen, and this row still says something.
        diagnostic = report["diagnostics"][0]
        check("the diagnostic is one row, outside the canonical thirteen, "
              "with one cell per column",
              len(report["diagnostics"]) == 1
              and diagnostic["key"] == "production_coverage"
              and diagnostic["label"] == R.PRODUCTION_COVERAGE_LABEL
              and diagnostic["key"] not in {row["key"]
                                            for row in report["table"]}
              and len(diagnostic["cells"]) == len(report["columns"])
              and [row["key"] for row in report["table"]] == expected,
              str(diagnostic["key"]))
        check("a scored cell prints the covering passes over the same "
              "denominator the ladder rows use",
              diagnostic["cells"][0] == {
                  "status": "scored", "display": "100.0% (1/1)",
                  "number": 1.0, "count": 1, "denominator": 1,
                  "ladder_n": 1, "zero_production_lines": 0, "reason": None},
              str(diagnostic["cells"][0]))
        check("no pass, no coverage collected, and no merge are three "
              "DIFFERENT reasons, and none of them is a zero",
              diagnostic["cells"][3]["reason"] == NO_PASS
              and diagnostic["cells"][5]["reason"] == NOT_SCORED_COVERAGE
              and diagnostic["cells"][5]["zero_production_lines"] == 0
              and diagnostic["cells"][5]["not_collected"] == 1
              and diagnostic["cells"][4]["reason"] == UNMERGEABLE
              and all(cell["number"] is None
                      for cell in (diagnostic["cells"][index]
                                   for index in (3, 4, 5))),
              str([diagnostic["cells"][index] for index in (3, 4, 5)]))
        check("an incomplete population withholds the diagnostic too -- a "
              "surviving rate beside thirteen withheld ones reads as THE "
              "result",
              diagnostic["cells"][11]["status"] == "withheld"
              and diagnostic["cells"][11]["number"] is None
              and population_reason in diagnostic["cells"][11]["reason"],
              str(diagnostic["cells"][11]))

        text = render(report, "text")
        markdown = render(report, "markdown")
        payload = json.loads(render(report, "json"))
        check("all three formats carry the diagnostic, under a heading that "
              "says it is not canonical",
              DIAGNOSTIC_HEADING in text
              and DIAGNOSTIC_HEADING in markdown
              and DIAGNOSTIC_CAVEAT in text
              and R.PRODUCTION_COVERAGE_LABEL in markdown
              and payload["diagnostics"][0]["cells"][0]["number"] == 1.0
              and len(markdown.splitlines()[
                  markdown.splitlines().index(f"#### {DIAGNOSTIC_HEADING}")
                  + 3].split("|")) == len(report["columns"]) + 3,
              text)
        check("all three formats contain the complete campaign table",
              "n/a (unmergeable)" in text
              and "| mutation recall |" in markdown
              and explicit_quality in text
              and discovered_quality in markdown
              and payload["columns"][9]["provenance"]["prod_index"]
              == prod_index
              and "classified_n         1" in text
              and "withheld (" + reason + ")" in markdown
              and payload["columns"][10]["provenance"]["ladder_n"] == 2
              and payload["columns"][10]["provenance"]["classified_n"] == 1
              and payload["columns"][10]["provenance"]
                  ["ladder_withheld_reasons"] == [reason]
              and "ladder        withheld (" + population_reason + ")" in text
              and population_reason in markdown
              and len(markdown.splitlines()[3].split("|"))
                  == len(markdown.splitlines()[2].split("|"))
              and len(payload["table"]) == len(expected))

        from .. import cli
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = cli.main(["campaign-results", "--descriptor", yaml_path,
                           "--format", "json"])
        check("the CLI emits one parseable JSON document",
              rc == 0 and json.loads(stdout.getvalue())["schema"]
              == OUTPUT_SCHEMA)
        R.TQ.load_bound_test_quality = real_quality_loader

        duplicate = os.path.join(root, "duplicate.json")
        with open(duplicate, "w", encoding="utf-8") as fh:
            json.dump({"schema": DESCRIPTOR_SCHEMA,
                       "cells": [cells[0], cells[0]]}, fh)
        try:
            load_descriptor(duplicate)
            duplicate_refused = False
        except CampaignTableError as exc:
            duplicate_refused = "repeats cell label" in str(exc)
        check("duplicate column labels are refused", duplicate_refused)

        def input_refused(name: str, cell: dict, needle: str) -> bool:
            descriptor = os.path.join(root, name + ".json")
            with open(descriptor, "w", encoding="utf-8") as fh:
                json.dump({"schema": DESCRIPTOR_SCHEMA, "cells": [cell]}, fh)
            try:
                campaign_results(descriptor)
            except CampaignTableError as exc:
                return needle in str(exc)
            return False

        missing_profile = dict(cells[0], profile="absent-profile.yml")
        missing_boundary = dict(cells[0], boundary="absent-boundary.yml")
        invalid_run_path = os.path.join(root, "invalid.jsonl")
        with open(invalid_run_path, "w", encoding="utf-8") as fh:
            fh.write("{not json}\n")
        invalid_run = dict(cells[0], run="invalid.jsonl")
        check("missing profile and boundary inputs refuse without tracebacks",
              input_refused("missing-profile", missing_profile, "profile")
              and input_refused("missing-boundary", missing_boundary,
                                "boundary"))
        check("malformed run input refuses without a traceback",
              input_refused("invalid-run", invalid_run, "results inputs"))
        foreign_campaign_cell = dict(
            cells[0], campaign="foreign-campaign.json")
        check("an available cell opens and reconciles its explicit campaign "
              "input instead of silently ignoring a foreign digest",
              input_refused(
                  "foreign-campaign-cell", foreign_campaign_cell,
                  "differs from result rows"))
        wrong_project = dict(cells[0], profile=coreshop_profile,
                             boundary=coreshop_boundary)
        check("campaign results inherits the central run-to-boundary project "
              "binding instead of duplicating a partial check",
              input_refused("wrong-project", wrong_project,
                            "run project 'algorand-sdk' differs from "
                            "boundary project 'coreshop'"))

        _write_jsonl(os.path.join(root, "submitted.jsonl"), [{
            "item_id": "algorand-sdk/features/unit/example.feature:1",
            "outcome": "no_files_returned",
            "condition": "submitted",
            "adapter": "submitted:fixture",
        }])
        submitted_cell = dict(
            cells[0], run="submitted.jsonl", gold=None, test_quality=None,
            prod_index=None, mutation_capable=False)
        check("submitted rows never enter a campaign table",
              input_refused("submitted", submitted_cell,
                            "submitted-tier rows never enter a campaign"))

        # Benchmark 2.0 (BENCHMARK_V2_SPEC.md section 6), with a synthetic
        # list: protocol 9001 stands for a 2.0 protocol, and the listed
        # instance's row is collected but counted nowhere.
        from . import population as P
        listed_id = "algorand-sdk/features/unit/example.feature:2"
        _write_jsonl(os.path.join(root, "v2.jsonl"), [
            {"item_id": "algorand-sdk/features/unit/example.feature:1",
             "outcome": "passed", "protocol_version": 9001,
             "coverage_lines": {"src/main/java/Example.java": [1, 2]}},
            {"item_id": listed_id, "outcome": "failed",
             "protocol_version": 9001}])
        v2_list = os.path.join(root, "benchmark_2.0_population.yml")
        with open(v2_list, "w", encoding="utf-8") as fh:
            fh.write("schema: r2t.benchmark-population/1\n"
                     "benchmark_version: \"2.0\"\ncensus: selftest census\n"
                     "protocols: [9001]\nexcluded:\n"
                     f"  - instance_id: {listed_id}\n    reason: census_pass\n")
        v2_descriptor = os.path.join(root, "v2.json")
        with open(v2_descriptor, "w", encoding="utf-8") as fh:
            json.dump({"schema": DESCRIPTOR_SCHEMA, "cells": [
                dict(cells[0], label="v2", run="v2.jsonl",
                     release="release-two.jsonl")]}, fh)
        listed_path = P.BENCHMARK_POPULATION
        R.TQ.load_bound_test_quality = fixture_quality_loader
        try:
            before_report = campaign_results(yaml_path)
            P.BENCHMARK_POPULATION = v2_list
            v2_report = campaign_results(v2_descriptor)
            same_report = campaign_results(yaml_path)
        finally:
            P.BENCHMARK_POPULATION = listed_path
            R.TQ.load_bound_test_quality = real_quality_loader
        v2_provenance = v2_report["columns"][0]["provenance"]
        v2_text = render(v2_report, "text")
        v2_markdown = render(v2_report, "markdown")
        v2_payload = json.loads(render(v2_report, "json"))
        check("a 2.0 cell counts its population, and text, markdown and json "
              "each name the instance left out of it",
              v2_provenance["population_status"] == "complete"
              and v2_provenance["planned_n"] == 1
              and v2_provenance["observed_n"] == 1
              and v2_provenance["passed"] == 1
              and "2.0 excluded  1 instance(s) outside benchmark 2.0's "
                  "population" in v2_text and listed_id in v2_text
              and "- v2: 2.0 excluded: 1 instance(s)" in v2_markdown
              and listed_id in v2_markdown
              and v2_payload["columns"][0]["provenance"][
                  "population_exclusions"]["excluded"]
              == [{"item_id": listed_id, "reason": "census_pass"}],
              v2_text + v2_markdown)
        check("...while 1.x cells keep their bytes in every format with the "
              "2.0 list present",
              all(render(same_report, fmt) == render(before_report, fmt)
                  for fmt in FORMATS)
              and "population_exclusions" not in render(same_report, "json"))

    # ---------------------------- the shipped six-cell reporting surface
    #
    # Checked HERE and not only by a human running the CLI, because the whole
    # value of a descriptor that renders before any run exists is that a typo
    # in it is found now rather than after six paid sweeps have finished.
    six_cell = os.path.join(benchmark, "config",
                            "campaign_results_six_cell.yml")
    shipped = load_descriptor(six_cell)
    check("the shipped descriptor names the six target cells, in order",
          [cell["label"] for cell in shipped["cells"]]
          == ["coreshop-aider", "coreshop-openhands", "python-docx-aider",
              "python-docx-openhands", "algorand-aider",
              "algorand-openhands"],
          str([cell["label"] for cell in shipped["cells"]]))
    shipped_projects = [(load_profile(cell["profile"]).project,
                         load_boundary(cell["boundary"]).project)
                        for cell in shipped["cells"]]
    check("...and every cell's profile and boundary load and agree on one "
          "project, which is the binding a run would otherwise be refused on",
          shipped_projects == [("coreshop", "coreshop")] * 2
          + [("python-docx", "python-docx")] * 2
          + [("algorand-sdk", "algorand-sdk")] * 2, str(shipped_projects))
    shipped_report = campaign_results(six_cell)
    shipped_text = render(shipped_report, "text")
    check("...and it renders with no run at all: each cell degrades to a "
          "named unavailable column instead of aborting the table",
          [column["unavailable"] for column in shipped_report["columns"]]
          == [UNMERGEABLE] * 6
          and all(cell["display"] == f"n/a ({UNMERGEABLE})"
                  for row in shipped_report["table"]
                  + shipped_report["diagnostics"]
                  for cell in row["cells"])
          and all(label in shipped_text
                  for label in ("algorand-openhands", DIAGNOSTIC_HEADING)),
          shipped_text)

    print("\n" + ("ALL PASS (campaign_table)" if ok
                   else "FAILURES (campaign_table)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
