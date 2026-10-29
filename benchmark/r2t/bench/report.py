"""Read a run back: `python3 -m r2t.cli report --run <file.jsonl> ...`

v1 records raw outcomes, not scores (SPEC §6), so this reports and does
not grade.  It prints the outcome distribution, the partial-credit
picture (how far a run got through the scenario's steps before it
stopped), and — when more than one run file is given — a side-by-side, so
that a system is read against the `gold` upper bound and the `empty`
control rather than against an absolute number.

`passed` is the only outcome that means the scenario ran green.  The rest
are deliberately distinguished: a `container_error` (the wiring did not
resolve) and a `failed` (the test ran and disagreed) are different
findings about a system, and collapsing them into "did not pass" throws
away the most useful thing the harness measured.

**`non_vacuous_pass_at_1` is the number worth publishing, not `pass_at_1`.**
A pass means "the scenario ran green", and a submission that defines every
step with an empty body runs green on 422/422 items — so `pass_at_1` on its
own does not distinguish a test from a no-op, which is why §3.10 has an
anti-vacuity gate at all.  When a test-quality summary sits beside the run
(`<run>.test_quality.json`, written by `r2t.cli test-quality`), this also
prints the passes whose test was shown to kill what the reference test kills
— per item, over the full mutant population covering it.  That second line is
a capability claim; the first is an outcome tally, and the two are not
interchangeable.

It also reports what the run COST: wall time, tokens and money, totalled and
per item, plus **cost per PASS** -- total spend divided by passes, the number
agentic systems are actually compared on.  Two rules make that figure honest
rather than merely present:

* Rows that carry no agent stats are counted as `unaccounted`, never as
  zero-cost.  The eval100 sweep's 11 hard timeouts spent real money and
  recorded nothing; folding them in as zeros would understate the bill, and
  would flatter precisely the runs that failed hardest.
* Money is recomputed from the recorded tokens against `config/pricing.yml`
  rather than read off the row.  The SDK's own `accumulated_cost` was 0.0 on
  all 100 rows of that sweep -- litellm had no price entry for the model id --
  so trusting the row would publish a free run.  Where the API reported no
  cache split, or the table entry prices at bounding rates, the total is an
  UPPER BOUND and is labelled as one, with each reason named.
* And the AVERAGE is gated on both.  `cost per PASS` prints only when every
  row was accounted and priced; otherwise it prints as `>= $X` with the gap
  named, because a quoted average silently over-flatters a run in exactly
  proportion to how much of its spend went unrecorded.

Beside the cost it prints what the system DID -- writes, LLM calls, wall
time, trials used, recorded errors, and (diagnostically) how often repeated
items disagreed with themselves.  Two systems with one pass rate are not one
system, and none of those figures is a score or enters a denominator.

Three things it REFUSES to print rather than footnote (`ReportRefusal`): a
pooled total over rows from more than one project (ask for `--group-by
project` and get complete, separate project reports), and one
ranked table holding two `comparison_class` values -- a scaffold pinned to a
model version and a shipped product are not comparable, whichever wins -- or
a table mixing externally submitted candidates with a reviewed C2/C3 study
condition. Submitted measurements may be inspected only in their own tier.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import statistics
from collections import Counter
from typing import Optional

from . import draws
from . import population as P
from ..core.paths import BENCHMARK_ROOT, RELEASE_DIR

#: Roughly, how far the run got.  Ordered worst to best.
STAGE = {
    "adapter_error": "no output",
    "parse_error": "no output",
    "no_files_returned": "no output",
    "no_writable_files": "no output",
    "parse_or_compile_error": "did not build",
    "container_error": "did not build",
    "solution_error": "did not build",
    "no_scenario_ran": "did not run",
    "no_steps_ran": "did not run",
    "timeout": "did not run",
    "undefined_steps": "ran, steps undefined",
    "pending": "ran, steps pending",
    "failed": "ran, steps failed",
    "not_passed": "ran, steps failed",
    "passed_but_nonzero_exit": "DISAGREEMENT: steps passed, exit code did not",
    "passed": "passed",
}

#: The comparison classes a row may declare itself a member of.  A
#: `fixed_model_scaffold` is a prompt-and-harness built around ONE model at a
#: pinned version; a `product_system` is a shipped product whose internals
#: change under it.  Both are legitimate objects of study and neither can be
#: ranked against the other -- the first's number is reproducible and the
#: second's is a snapshot -- so a table holding both is refused rather than
#: footnoted.  Rows that declare nothing are grandfathered: every archived row
#: predates the field, and defaulting them into a class would invent the very
#: claim this check exists to protect.
COMPARISON_CLASSES = ("fixed_model_scaffold", "product_system")

#: The ONE verdict that counts a pass as non-vacuous: the candidate kills every
#: mutant the reference kills, on that item, over the full population covering
#: it.  A constant because the count (`non_vacuous`) and the per-item VECTOR
#: (`non_vacuous_view`) are read by different callers -- the second is what
#: `cli compare` pairs across two arms -- and a published count that disagreed
#: with the vector behind it would be the exact drift this file exists to stop.
#: `weaker`, `vacuous` and `not_scorable` are each their own category and none
#: of them is here; see `non_vacuous`'s docstring for why `not_scorable` in
#: particular is not a bad pass.
NON_VACUOUS_VERDICT = "equivalent_to_reference"
#: Honest human-facing name for the frozen verdict above.  The schema token
#: stays byte-for-byte compatible in sidecars; Slice 1 displays what was
#: actually established instead of using "equivalent", which can be read as
#: behavioural equivalence beyond the reference's own kill set.
NON_VACUOUS_DISPLAY = "reference-kill-complete"

#: Where a row would record an ENFORCEABLE per-item spend cap -- a limit the
#: harness itself would have stopped the item at, not an intention.  No
#: adapter writes one today, which is exactly why the cost UPPER bound below
#: is absent by construction: without a cap, an unaccounted row's spend has no
#: ceiling anybody can name, and an upper bound invented for it would be the
#: same lie as counting it as zero, in the other direction.  A future adapter
#: that enforces a cap need only stamp it here and the bound starts printing.
COST_CAP_FIELDS = ("cost_cap_usd", "max_cost_usd")

DEFAULT_DATASET_MANIFEST = os.path.join(RELEASE_DIR, "dataset_manifest.json")


def _agent_reader(name: str, where: str, field: str):
    """`r2t.<name>`, the agent module a row field's reader lives in, or the
    refusal a checkout without the agent component gives.

    A row carrying `field` was stamped by an agent arm, and only the agent
    component can say what the field owes -- its price table, its native
    knobs, its budget key.  A report over fixture and submitted rows never
    asks; one over agent rows asks, and refuses by name when the answer is
    not shipped.  Only the NAMED module (or a package above it) being absent
    is "not shipped"; any other import failure propagates as the bug it is.
    """
    import importlib
    dotted = f"{__package__.rsplit('.', 1)[0]}.{name}"
    try:
        return importlib.import_module(dotted)
    except ModuleNotFoundError as exc:
        if exc.name != dotted and not dotted.startswith(exc.name + "."):
            raise
        raise ReportRefusal(
            f"REFUSED: {where} carries {field}, which only r2t.{name} can "
            f"read; that is part of the agent component, which this checkout "
            f"does not ship (benchmark-only distribution).") from exc


class ReportRefusal(RuntimeError):
    """A report that would be misread if it were printed at all.

    Deliberately rare, and never used for a missing measurement: a gap
    degrades to a named string (see `format_cost_summary`), and only a
    structural claim the output would MAKE -- pooling two projects into one
    rate, ranking two comparison classes in one table -- is worth refusing to
    print over.  Messages start `REFUSED:` and say what the harm is.
    """


def project_of(row: dict) -> str:
    """The project an item belongs to: everything before the first `/`.

    Item ids are `<project>/features/domain/...`, so this is the id's own
    namespace rather than a mapping kept somewhere else that could go stale.
    """
    iid = row.get("item_id") or ""
    return iid.split("/")[0]


def check_comparison_class(rows: list[dict]) -> None:
    """Refuse a table that would rank two different kinds of system together.

    Absent is grandfathered; two DIFFERENT declared values are refused.  An
    unrecognised label counts as its own class rather than being ignored --
    the conservative reading, because a label nobody here knows is precisely
    the case where "these are the same kind of thing" is least defensible.
    """
    declared = sorted({r["comparison_class"] for r in rows
                       if r.get("comparison_class")})
    unknown = [d for d in declared if d not in COMPARISON_CLASSES]
    if len(declared) > 1:
        raise ReportRefusal(
            f"REFUSED: these rows declare {len(declared)} comparison classes "
            f"({', '.join(declared)}) and would be printed in one ranked "
            f"table. A fixed_model_scaffold is a prompt and harness pinned to "
            f"one model version, so its number is reproducible; a "
            f"product_system is a shipped product that changes under you, so "
            f"its number is a snapshot with a date. Ranking them together "
            f"reads as a claim about which is better when it is a claim about "
            f"which was measured on a Tuesday. Report them separately."
            + (f" ({', '.join(unknown)} is not a class this file knows -- the "
               f"vocabulary is {', '.join(COMPARISON_CLASSES)} -- and an "
               f"unknown label counts as its own class rather than being "
               f"ignored.)" if unknown else ""))


def check_single_project(rows: list[dict], group_by: str = "") -> list[str]:
    """The projects present; refuse pooled totals across more than one.

    A pass rate over two projects is a weighted average whose weights are how
    many items each project happened to contribute -- so a benchmark that
    sampled 90 items from one codebase and 10 from another publishes, mostly,
    a number about the first codebase while looking like a number about
    software. `--group-by project` is the way to ask for it: it partitions
    the rows first, then computes and prints one complete report per project.
    It deliberately emits no pooled total; the only cross-project headline is
    the preregistered EQUAL-WEIGHT macro over projects (SPEC §8 rule 2,
    restored by owner ruling §2.1), in which each project counts once whatever
    its item count -- which is the property a pooled rate lacks.
    """
    projects = sorted({project_of(r) for r in rows})
    if len(projects) > 1 and group_by != "project":
        raise ReportRefusal(
            f"REFUSED: these rows span {len(projects)} projects "
            f"({', '.join(projects)}) and a pooled total over them is a "
            f"weighted average whose weights are how many items each project "
            f"happened to contribute, not a property of any system. Pass "
            f"`--group-by project` for complete per-project reports; no "
            f"pooled total is produced, and the only cross-project headline "
            f"is the preregistered equal-weight macro over projects, in which "
            f"each project counts once.")
    return projects


def check_single_tier(rows: list[dict]) -> bool:
    """Whether all rows are submitted; refuse a submitted/non-submitted mix.

    ``condition: submitted`` names candidate bytes produced outside the
    benchmark's declared and reviewed generation protocols.  The resulting
    measurements remain inspectable, but putting them beside C2/C3 (or an
    older unstamped row) would make one ranked table imply a study comparison
    that was never authorised.  One input may contain either tier, never both.

    A row is submitted on EITHER of two marks: the ``condition`` stamp, or an
    ``adapter`` name under the ``submitted:`` prefix (which only
    `make_submitted_adapter` mints).  The second mark exists for laundering:
    a transport that re-serves submitted bytes and drops the condition still
    carries the generator's adapter name, because attribution is the one
    field no replay path may rewrite.
    """
    from ..core.constants import SUBMITTED_CONDITION

    def _submitted_row(r: dict) -> bool:
        return (r.get("condition") == SUBMITTED_CONDITION
                or str(r.get("adapter") or "").startswith("submitted:"))

    submitted = [r for r in rows if _submitted_row(r)]
    if submitted and len(submitted) != len(rows):
        other_conditions = sorted({
            str(r.get("condition")) if r.get("condition") is not None
            else "unstamped"
            for r in rows
            if not _submitted_row(r)
        })
        raise ReportRefusal(
            "REFUSED: submitted rows cannot share one table with "
            f"non-submitted rows ({', '.join(other_conditions)}). The "
            "submitted tier contains candidate bytes produced under an "
            "undeclared and unreviewed generation protocol, so placing it "
            "beside C2/C3 would manufacture a study comparison. Report the "
            "tiers separately.")
    return bool(submitted)


#: Printed above the first table whenever every row is submitted-tier.  A
#: label, not a refusal: submitted measurements may be inspected in their own
#: tier and `report` is that surface -- but a reader who pipes the tables
#: onward must meet the tier before the first number.
SUBMITTED_BANNER = ("SUBMITTED TIER: non-canonical, must not be published "
                    "or combined with study-condition results")


def environment_proven_label(rows: list[dict]) -> str:
    """Fold the per-row environment-proven stamp for display beside the tier.

    Every submitted row carries `environment_proven` (external-candidate
    amendment, decision 7), and one run stamps all of its rows alike, so a
    single-run input folds to `true` or `false`.  `mixed` names a multi-run
    input whose runs disagree, instead of hiding the unproven half behind
    either answer.  A row without the field (none is minted today, since the
    route opened stamped) reads as unproven, which is the claim its absence
    supports.
    """
    values = {row.get("environment_proven") is True for row in rows}
    return "mixed" if len(values) > 1 else str(values.pop()).lower()


def submitted_banner(rows: list[dict]) -> str:
    """The tier banner with the environment-proven stamp beside it."""
    return (f"{SUBMITTED_BANNER} "
            f"[environment_proven: {environment_proven_label(rows)}]")


def _load_capability_manifest_bytes(path: str, expected_sha256: str,
                                    expected_dataset_version: Optional[str]
                                    ) -> dict:
    """Validate already-authorised capability bytes (private core)."""
    from ..data import release

    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        doc = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportRefusal(
            f"REFUSED: capability manifest {path!r} is unreadable ({exc}). "
            f"The functional/reference eligible-set split cannot be inferred "
            f"from run sidecars.") from exc
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 \
            or actual_sha256 != expected_sha256:
        raise ReportRefusal(
            f"REFUSED: capability manifest {path!r} hashes to "
            f"{actual_sha256}, expected {expected_sha256!r}. Eligibility "
            f"requires reviewed, content-pinned bytes.")
    if not isinstance(doc, dict):
        raise ReportRefusal(
            f"REFUSED: capability manifest {path!r} is not a JSON object.")
    if expected_dataset_version is not None \
            and doc.get("dataset_version") != expected_dataset_version:
        raise ReportRefusal(
            f"REFUSED: capability manifest says dataset_version "
            f"{doc.get('dataset_version')!r}, while VERSIONS.yml pins "
            f"{expected_dataset_version!r}.")
    if not isinstance(doc, dict) or doc.get("schema") != release.MANIFEST_SCHEMA \
            or not isinstance(doc.get("projects"), dict):
        raise ReportRefusal(
            f"REFUSED: capability manifest {path!r} must use schema "
            f"{release.MANIFEST_SCHEMA!r} and carry a projects mapping; it "
            f"cannot define the reference-equivalent eligible set.")
    projects = doc["projects"]
    for project, block in sorted(projects.items()):
        caps = block.get("capabilities") if isinstance(block, dict) else None
        if not isinstance(caps, dict) or not isinstance(caps.get("mutation"),
                                                        bool):
            raise ReportRefusal(
                f"REFUSED: capability manifest project {project!r} does not "
                f"declare boolean capabilities.mutation. Missing is not "
                f"functional-only; it is unknown eligibility.")
    absolute = os.path.abspath(path)
    benchmark_root = BENCHMARK_ROOT
    try:
        inside_benchmark = (os.path.commonpath([absolute, benchmark_root])
                            == benchmark_root)
    except ValueError:                            # different Windows drives
        inside_benchmark = False
    label = (os.path.relpath(absolute, benchmark_root)
             if inside_benchmark else os.path.basename(absolute))
    return {"document": doc, "path": absolute, "label": label,
            "sha256": actual_sha256}


def load_capability_manifest() -> dict:
    """Load the one production capability authority registered in VERSIONS.

    Eligibility is a property of the released project, not of whether a
    sidecar happened to be passed to this command.  The dataset manifest is
    therefore the authority for `capabilities.mutation`; a missing project or
    a non-boolean declaration refuses the split instead of defaulting to the
    more flattering table.

    There is intentionally no path or digest argument.  A caller cannot make
    arbitrary bytes authoritative by supplying their freshly computed hash;
    production reporting accepts only the repository release that
    VERSIONS.yml names.  `_load_capability_fixture` is the private selftest
    seam and is never reachable through `report` or the CLI.
    """
    from ..data import versions

    try:
        dataset_component = versions.component("dataset")
    except versions.ManifestError as exc:
        raise ReportRefusal(
            f"REFUSED: VERSIONS.yml cannot authenticate the capability "
            f"manifest ({exc}).") from exc
    expected_sha256 = (dataset_component.get("files") or {}).get(
        "release/dataset_manifest.json")
    return _load_capability_manifest_bytes(
        DEFAULT_DATASET_MANIFEST, expected_sha256,
        dataset_component.get("version"))


def _load_capability_fixture(path: str, expected_sha256: str) -> dict:
    """Private, test-only loader for exact fixture bytes."""
    return _load_capability_manifest_bytes(path, expected_sha256, None)


def eligible_set_tables(grouped: dict, capability_doc: dict,
                        population_registry: Optional[dict] = None) -> dict:
    """Build separate functional and reference-eligible table rows.

    No cross-project reference-equivalent mean is computed.  The second table
    lists project-specific values over the manifest-defined eligible set, and
    it refuses unless every score-bearing row names a registered population
    from one generation.  Distinct project-specific population ids within a
    generation are expected; v1 and v2 in one table are not.
    """
    from ..data import versions

    projects_doc = capability_doc.get("projects")
    if not isinstance(projects_doc, dict):
        raise ReportRefusal(
            "REFUSED: capability document has no projects mapping; the "
            "eligible set is undefined.")
    if population_registry is None:
        try:
            population_registry = versions.populations()
        except versions.ManifestError as exc:
            raise ReportRefusal(f"REFUSED: population registry is invalid: "
                                f"{exc}") from exc

    functional = []
    reference = []
    eligible_projects = []
    functional_only = []
    bindings = []
    capabilities = {}

    for project, reports in sorted(grouped.items()):
        declaration = projects_doc.get(project)
        if not isinstance(declaration, dict):
            raise ReportRefusal(
                f"REFUSED: project {project!r} is absent from the capability "
                f"manifest. It cannot be silently assigned to the "
                f"functional-only or reference-equivalent table.")
        from .live_test_quality import (
            LiveTestQualityRefused, resolve_mutation_capability)
        try:
            mutation_capable = resolve_mutation_capability(
                project, declaration).supported
        except LiveTestQualityRefused as exc:
            raise ReportRefusal(str(exc)) from exc
        capabilities[project] = mutation_capable
        (eligible_projects if mutation_capable else functional_only).append(
            project)

        for name, rep in sorted(reports.items()):
            summary = rep["summary"]
            functional.append({
                "project": project, "run": name,
                "passed": summary["passed"], "n": summary["n"],
                "pass_at_1": summary["pass_rate"],
                "status": ("scored" if summary["pass_rate"] is not None
                           else "withheld"),
                "reason": (None if summary["pass_rate"] is not None else
                           "; ".join(summary.get(
                               "pass_rate_withheld_reasons") or
                                     ["population unavailable"])),
            })
            nv = rep.get("test_quality")
            if not mutation_capable:
                if nv is not None:
                    raise ReportRefusal(
                        f"REFUSED: {project}/{name} carries a test-quality "
                        f"summary but the reviewed dataset manifest declares "
                        f"capabilities.mutation: false. A reference-equivalent "
                        f"score cannot be hidden in the functional-only table; "
                        f"fix the capability release or remove the invalid "
                        f"score.")
                continue

            row = {"project": project, "run": name,
                   "population_id": None, "generation": None,
                   "verdict_basis": None, "hard_subset_digest": None,
                   "method": None,
                   "candidate_observation_count": None,
                   "reference_observation_count": None,
                   "reference_controls_digest": None,
                   "hard_recall_macro": None, "full_recall_macro": None,
                   "full_only_generated_macro": None,
                   "full_jaccard_macro": None,
                   "hard_n_scored": None, "hard_not_scorable_items": None,
                   "companion_n_scored": None,
                   "companion_not_scorable_items": None,
                   "reference_excluded_count": None,
                   "candidate_excluded_count": None,
                   "reference_omitted_items": None,
                   "reference_declared_reason": None,
                   "non_vacuous_passes": None, "n": summary["n"],
                   "passed": summary["passed"],
                   "non_vacuous_pass_at_1": None, "status": "not_scored",
                   "reason": "no test-quality summary"}
            if nv is not None:
                population_id = nv.get("population_id")
                if not isinstance(population_id, str) or not population_id:
                    raise ReportRefusal(
                        f"REFUSED: reference-eligible row {project}/{name} has "
                        f"a test-quality summary with no population_id. A "
                        f"macro table must be provably all-v1 or all-v2; "
                        f"engine@version cannot establish that because it is "
                        f"stable across population generations.")
                entry = population_registry.get(population_id)
                if not isinstance(entry, dict):
                    raise ReportRefusal(
                        f"REFUSED: reference-eligible row {project}/{name} "
                        f"names unknown population_id {population_id!r}.")
                if entry.get("project") != project:
                    raise ReportRefusal(
                        f"REFUSED: reference-eligible row {project}/{name} "
                        f"names population_id {population_id!r}, registered to "
                        f"project {entry.get('project')!r}. Population identity "
                        f"does not cross project boundaries.")
                generation = entry.get("generation")
                if not isinstance(generation, int) or isinstance(generation,
                                                                  bool) \
                        or generation < 1:
                    raise ReportRefusal(
                        f"REFUSED: population_id {population_id!r} has invalid "
                        f"generation {generation!r}.")
                row.update({
                    "population_id": population_id,
                    "generation": generation,
                    "verdict_basis": nv.get("verdict_basis"),
                    "hard_subset_digest": nv.get("hard_subset_digest"),
                    "method": nv.get("method"),
                    "candidate_observation_count": nv.get(
                        "candidate_observation_count"),
                    "reference_observation_count": nv.get(
                        "reference_observation_count"),
                    "reference_controls_digest": (
                        nv.get("reference_controls") or {}).get("digest"),
                    "hard_recall_macro": nv.get("hard_recall_macro"),
                    "full_recall_macro": nv.get("full_recall_macro"),
                    "full_only_generated_macro": nv.get(
                        "full_only_generated_macro"),
                    "full_jaccard_macro": nv.get("full_jaccard_macro"),
                    "hard_n_scored": nv.get("hard_n_scored"),
                    "hard_not_scorable_items": nv.get(
                        "hard_not_scorable_items"),
                    "companion_n_scored": nv.get("companion_n_scored"),
                    "companion_not_scorable_items": nv.get(
                        "companion_not_scorable_items"),
                    "reference_excluded_count": nv.get(
                        "reference_excluded_count"),
                    "candidate_excluded_count": nv.get(
                        "candidate_excluded_count"),
                    "reference_omitted_items": nv.get(
                        "reference_omitted_items"),
                    "reference_declared_reason": nv.get(
                        "reference_declared_reason"),
                    "non_vacuous_passes": nv.get("non_vacuous_passes"),
                    "non_vacuous_pass_at_1": nv.get(
                        "non_vacuous_pass_at_1"),
                })
                if nv.get("stale"):
                    row.update(status="withheld", reason="stale summary")
                elif not nv.get("publication_ready", True):
                    row.update(
                        status="withheld",
                        reason="; ".join(nv.get("withheld_reasons")
                                         or ["unqualified summary"]))
                else:
                    row.update(status="scored", reason=None)
                bindings.append({"project": project, "run": name,
                                 "population_id": population_id,
                                 "generation": generation,
                                 "verdict_basis": nv.get("verdict_basis"),
                                 "method": nv.get("method"),
                                 "reference_controls_digest": (
                                     nv.get("reference_controls") or {}).get(
                                         "digest"),
                                 "hard_subset_digest": nv.get(
                                     "hard_subset_digest")})
            reference.append(row)

    per_project_populations = {
        project: sorted({row["population_id"] for row in bindings
                         if row["project"] == project})
        for project in eligible_projects
    }
    multiple = {project: ids for project, ids
                in per_project_populations.items() if len(ids) > 1}
    if multiple:
        detail = ", ".join(f"{project}={ids}"
                           for project, ids in sorted(multiple.items()))
        raise ReportRefusal(
            f"REFUSED: one project appears under multiple population_id "
            f"values in the same reference-equivalent table ({detail}). "
            f"Render each population separately; same-generation labels do "
            f"not make two catalogues one project score.")

    for project in eligible_projects:
        project_bindings = [row for row in bindings
                            if row["project"] == project]
        # Both v1 and v2 name their basis `hard_subset`, but they are scored
        # against different artifacts over different pair universes, so a
        # table mixing them would compare two methods under one heading.
        methods = {row["method"] for row in project_bindings}
        if len(methods) > 1:
            raise ReportRefusal(
                f"REFUSED: project {project!r} mixes test-quality methods "
                f"{sorted(map(str, methods))} in one reference table.")
        bases = {row["verdict_basis"] for row in project_bindings}
        if len(bases) > 1:
            raise ReportRefusal(
                f"REFUSED: project {project!r} mixes legacy full-gold and "
                f"assertion-hard verdict bases in one table: "
                f"{sorted(map(str, bases))}. Render or rescore one basis.")
        if bases == {"hard_subset"} or methods == {"single_observation"}:
            single_observation = methods == {"single_observation"}
            digest_key = ("reference_controls_digest" if single_observation
                          else "hard_subset_digest")
            digests = {row[digest_key] for row in project_bindings}
            if None in digests or "" in digests or len(digests) != 1:
                label = ("reference-controls" if single_observation
                         else "hard-subset")
                raise ReportRefusal(
                    f"REFUSED: project {project!r} does not bind one {label} "
                    f"artifact across its rows: "
                    f"{sorted(map(str, digests))}.")

    generations = sorted({row["generation"] for row in bindings})
    if len(generations) > 1:
        detail = ", ".join(
            f"{row['project']}/{row['run']}={row['population_id']}"
            f"(v{row['generation']})" for row in bindings)
        raise ReportRefusal(
            f"REFUSED: the reference-equivalent macro table mixes population "
            f"generations {generations}: {detail}. Render all-v1 and all-v2 "
            f"tables separately; engine@version is intentionally unchanged "
            f"across these generations.")

    return {
        "functional": functional,
        "reference": reference,
        "eligible_projects": eligible_projects,
        "functional_only_projects": functional_only,
        "capabilities": capabilities,
        "population_generation": generations[0] if generations else None,
        "population_ids": sorted({row["population_id"] for row in bindings}),
    }


def _load(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def check_unique_item_ids(rows: list[dict], path: str) -> None:
    """Publication gate: one valid id and one row per item.

    `metrics.read_runs` intentionally implements last-row-wins for operational
    retry files.  A report, comparison, or canonical results table is a
    different boundary: silently collapsing or double-counting retry history
    changes its denominator.  Those publication readers call this gate on the
    uncollapsed JSONL first and refuse instead.
    """
    invalid = [(n, row.get("item_id")) for n, row in enumerate(rows, 1)
               if not isinstance(row.get("item_id"), str)
               or not row.get("item_id").strip()]
    if invalid:
        examples = ", ".join(f"record {n}: {value!r}"
                             for n, value in invalid[:3])
        more = (f" and {len(invalid) - 3} more" if len(invalid) > 3 else "")
        raise ReportRefusal(
            f"REFUSED: {os.path.basename(path)} has invalid item_id values "
            f"({examples}{more}). Every publication row must carry an "
            f"item_id that is a non-empty string; a missing, blank, or "
            f"non-string id cannot define a project or denominator.")

    counts = Counter(r["item_id"] for r in rows)
    duplicate = sorted((str(iid), n) for iid, n in counts.items() if n > 1)
    if duplicate:
        examples = ", ".join(f"{iid!r} ({n} rows)"
                             for iid, n in duplicate[:3])
        more = (f" and {len(duplicate) - 3} more" if len(duplicate) > 3
                else "")
        raise ReportRefusal(
            f"REFUSED: {os.path.basename(path)} contains duplicate item_id "
            f"values: {examples}{more}. Publication inputs require exactly "
            f"one row per item; preserve retry history in shards, then merge "
            f"one canonical survivor per item before reporting.")


def _step_denominator(row: dict) -> Optional[int]:
    """The scenario's OWN step count, taken from the item, not from the run.

    Behat records nothing after the first non-passing step — it stops
    dispatching `@AfterStep` once the scenario is skipping — so
    `len(per_step)` is not the scenario's length, it is however far this
    particular run got.  Using it as a denominator flatters whichever run
    got least far: over the same 25 items the do-nothing `empty` control
    reads 15/40 (37.5%) while `gold` reads 335/335, and the single-shot
    model's 42/46 outranks the agent's 59/80 even though the agent passed
    more steps.  Against the fixed denominator the same runs are 4.5%,
    12.5% and 17.6%, and the ordering is the other way round.

    `bench_meta` carries the item's step counts into every run record
    (`runner.py`), so the honest denominator is already on disk.
    """
    bm = row.get("bench_meta") or {}
    if "steps_removable" in bm and "steps_retained" in bm:
        return bm["steps_removable"] + bm["steps_retained"]
    return None


def _agent_stats(row: dict) -> dict:
    """The driver's accounting for this row, or `{}`.

    `.get` all the way down on purpose: `scenario_not_found` and
    `harness_error` rows carry no metadata at all, and the reader must not
    crash on the rows that most need reading.
    """
    md = row.get("metadata") or {}
    st = md.get("agent_stats")
    return st if isinstance(st, dict) else {}


def _num(xs: list) -> tuple:
    """(total, median) over the values that are actually present.

    Returns `(None, None)` for an empty list rather than `(0, 0)`.  A run
    where nothing was measured and a run that measured zero are different
    findings, and every aggregate in this file keeps them apart.
    """
    xs = [x for x in xs if isinstance(x, (int, float))]
    if not xs:
        return (None, None)
    return (round(sum(xs), 6), statistics.median(xs))


def per_item_cost_cap(row: dict) -> Optional[float]:
    """An ENFORCEABLE ceiling on what this item could have cost, or None.

    Read from the row, its metadata and its agent stats, in that order, so a
    future adapter can stamp it wherever it naturally lives.  Returns None for
    everything on disk today -- see `COST_CAP_FIELDS`.
    """
    md = row.get("metadata") or {}
    for source in (row, md, _agent_stats(row)):
        if not isinstance(source, dict):
            continue
        for field in COST_CAP_FIELDS:
            v = source.get(field)
            if isinstance(v, (int, float)) and not isinstance(v, bool) \
                    and v >= 0:
                return float(v)
    return None


#: Why a priced item's money is an UPPER bound, and the clause
#: `format_cost_summary` prints for each reason.  An item can have more than
#: one: a `deepseek-flash` row without a cache split is billed at the table's
#: peak rates AND with every prompt token at the uncached rate.
UPPER_BOUND_REASONS = {
    "no_cache_split":
        "reported no cache split, so every prompt token is billed at the "
        "uncached rate",
    "no_per_request_usage":
        "recorded no usage per request, so every request is billed at the "
        "long-context rates",
    "no_cached_rate_in_table":
        "reported cache hits that their table entry has no cached rate for, "
        "so the hits are billed at the uncached rate",
    "table_rates":
        "are priced at the bounding rates of a table entry marked "
        "cost_upper_bound (for example, peak or cache-write rates)",
}


def _upper_bound_reasons(breakdown: dict, table: dict) -> list[str]:
    """Every `UPPER_BOUND_REASONS` key behind one priced item's upper bound.

    `pricing` names the first three in the breakdown's `basis`; an attempt
    priced request by request keeps each request's basis under
    `requests.bases`.  The fourth is the table entry's own `cost_upper_bound`,
    which bounds the item whatever its basis.
    """
    bases = [breakdown.get("basis") or ""]
    bases += list((breakdown.get("requests") or {}).get("bases") or ())
    reasons = [reason for reason, marker in (
        ("no_cache_split", "no_cache_split_reported"),
        ("no_per_request_usage", "__total_at_long_context_rates"),
        ("no_cached_rate_in_table", "__no_cached_rate_in_table"))
        if any(marker in basis for basis in bases)]
    if table["models"][breakdown["model_key"]].get("cost_upper_bound"):
        reasons.append("table_rates")
    return reasons


def cost_summary(rows: list[dict], table: Optional[dict] = None,
                 allow_unverified: bool = False,
                 non_vacuous_passes: Optional[int] = None) -> dict:
    """Time, tokens and money for a run -- totals, medians, and per PASS.

    WHY THE MONEY IS RECOMPUTED RATHER THAN READ.  Every row of the eval100
    sweep carries `agent_stats.cost: 0.0`, because the OpenHands SDK asks
    litellm to price the response and litellm has no entry for this
    endpoint's model id; its telemetry then records a cost only when the
    lookup returned something non-zero, so a failed lookup and a free call
    are the same value.  Summing that column would report a 100-item sweep
    as costing nothing.  So each row is re-priced from its recorded TOKENS
    against `config/pricing.yml`, through the same `pricing.price_stats`
    the driver uses -- one arithmetic, so an old run re-priced today and a
    new run priced at write time remain comparable.

    THREE POPULATIONS, KEPT APART.  A row is

      * `accounted`   -- it has token counts and they could be priced;
      * `unpriced`    -- it has token counts but no price entry covers its
                        model.  Its tokens still count; its money is absent,
                        with the reason kept;
      * `unaccounted` -- it carries no agent stats at all.  The 11 hard
                        timeouts in the eval100 sweep are these: the agent
                        ran for the full budget, spent real money, and was
                        killed before anything was written down.

    Only `accounted` rows contribute to `cost_usd_total`, and the other two
    counts are printed beside it, because a total that quietly absorbed them
    would understate the spend by however much the worst runs cost -- which
    on a timeout-heavy sweep is not a small correction.

    AND THE EFFICIENCY FIGURES ARE GATED ON THAT.  Printing the counts beside
    the total is not enough once someone quotes `cost per pass`: the quote
    travels without the caveat, and a cost-per-pass computed over a total that
    is missing the eleven most expensive rows is not merely imprecise, it
    flatters exactly the run that failed hardest.  So `cost_fully_accounted`
    -- no unaccounted rows AND no unpriced rows -- decides whether an average
    is published at all.  Where it is false the same arithmetic is printed as
    a LOWER BOUND and labelled one, which is a true statement about the spend;
    the headline is withheld with its reason.  An UPPER bound would need every
    missing row to carry an enforceable cap (`per_item_cost_cap`), and no
    adapter records one, so it is absent by construction rather than guessed.

    The price table and the arithmetic are the agent component's
    (`pricing`), asked for at the first row that carries agent statistics:
    a report over rows that carry none -- every fixture and submitted row --
    never needs it, and one that does refuses by name without it.
    """
    n = len(rows)
    out: dict = {"n": n, "accounted": 0, "unaccounted": 0, "unpriced": 0,
                 "unpriced_reasons": [], "upper_bound_items": 0,
                 "upper_bound_reasons": {},
                 # Rows the wall-clock envelope cut short (`r2t.confined.terminate`).
                 # They ARE priced now -- that is what the evidence-
                 # preservation fix bought -- and their price is exact for
                 # the calls that completed and silent about the one that was
                 # in flight.  So each is a LOWER bound, and a total made of
                 # them is a lower bound too.  Counted separately from
                 # `unaccounted` on purpose: before the fix these rows had no
                 # stats at all and landed there, and reading "0 unaccounted"
                 # as "the total is exact" is precisely the mistake the fix
                 # would otherwise have introduced.
                 "terminated": 0,
                 "priced_models": {}, "price_as_of": None,
                 "price_table_error": None}

    pricing = None
    seconds, prompt, completion, money = [], [], [], []
    as_of, models = set(), Counter()
    reasons: Counter = Counter()
    bound_reasons: Counter = Counter()
    # The rows whose money is NOT in the total, kept so their caps (if any
    # future adapter enforces one) can bound what the total is missing.
    without_cost: list[dict] = []
    for row in rows:
        md = row.get("metadata") or {}
        # Wall time is stamped by the ADAPTER, so a row that died before the
        # driver could write anything still has one.  Aggregated over its own
        # population for exactly that reason: 100 of the sweep's 100 rows
        # have a time and only 89 have tokens, and forcing them onto one
        # denominator would lose whichever number was inconvenient.
        if isinstance(md.get("agent_seconds"), (int, float)):
            seconds.append(float(md["agent_seconds"]))

        st = _agent_stats(row)
        if not st:
            out["unaccounted"] += 1
            without_cost.append(row)
            continue
        if pricing is None:
            pricing = _agent_reader(
                "confined.pricing", f"row {row.get('item_id')!r}",
                "agent statistics")
            if table is None:
                # A missing or malformed table costs the MONEY column and
                # nothing else.  The wall time and the tokens below are the
                # measurement; the dollars are a multiplication of it, and a
                # reader must not lose the measurement to a failed
                # multiplication.
                try:
                    table = pricing.load_table()
                except Exception as e:                        # noqa: BLE001
                    out["price_table_error"] = f"{type(e).__name__}: {e}"
        if isinstance(st.get("termination"), dict):
            out["terminated"] += 1
        if isinstance(st.get("prompt_tokens"), (int, float)):
            prompt.append(st["prompt_tokens"])
        if isinstance(st.get("completion_tokens"), (int, float)):
            completion.append(st["completion_tokens"])

        if table is None:
            out["unpriced"] += 1
            without_cost.append(row)
            reasons[out["price_table_error"] or "no price table"] += 1
            continue
        p = pricing.price_stats(st, table, allow_unverified=allow_unverified)
        if not p["priced"]:
            # A row with stats but no usable price is NOT unaccounted -- we
            # know what it consumed, we just cannot say what it cost.  The
            # distinction is the whole difference between "fix the table" and
            # "the measurement is missing".
            if st.get("prompt_tokens") is None and \
                    st.get("completion_tokens") is None:
                out["unaccounted"] += 1
            else:
                out["unpriced"] += 1
                reasons[p["reason"]] += 1
            without_cost.append(row)
            continue
        out["accounted"] += 1
        money.append(p["cost_usd"])
        bd = p["breakdown"]
        models[bd.get("model_key")] += 1
        if bd.get("as_of"):
            as_of.add(bd["as_of"])
        if bd.get("upper_bound"):
            out["upper_bound_items"] += 1
            bound_reasons.update(_upper_bound_reasons(bd, table))

    out["agent_seconds_total"], out["agent_seconds_median"] = _num(seconds)
    out["agent_seconds_items"] = len(seconds)
    out["prompt_tokens_total"], out["prompt_tokens_median"] = _num(prompt)
    out["completion_tokens_total"], out["completion_tokens_median"] = \
        _num(completion)
    out["cost_usd_total"], out["cost_usd_median"] = _num(money)
    out["priced_models"] = dict(models)
    out["unpriced_reasons"] = [r for r, _ in reasons.most_common(3)]
    # Several `as_of` dates means the run was priced against a table edited
    # mid-flight, or against two models frozen at different times.  Reported
    # as a set rather than collapsed, because "which price produced this
    # figure" stops having an answer the moment it is collapsed.
    out["price_as_of"] = (sorted(as_of)[0] if len(as_of) == 1
                          else (sorted(as_of) or None))
    out["upper_bound"] = out["upper_bound_items"] > 0
    out["upper_bound_reasons"] = {reason: bound_reasons[reason]
                                  for reason in UPPER_BOUND_REASONS
                                  if bound_reasons[reason]}

    passed = sum(1 for r in rows if r.get("outcome") == "passed")
    out["passed"] = passed
    # THE number people compare -- and the one place a benchmark is most
    # likely to print `inf` or crash.  None, printed as "n/a": a run that
    # solved nothing did not achieve an infinitely cheap solution, it
    # achieved no solution, and the two must not look alike.
    out["cost_per_pass"] = (round(out["cost_usd_total"] / passed, 4)
                            if passed and out["cost_usd_total"] is not None
                            else None)
    out["seconds_per_pass"] = (round(out["agent_seconds_total"] / passed, 1)
                               if passed and out["agent_seconds_total"]
                               is not None else None)

    # THE GATE.  Everything above is a measurement; the two averages below are
    # comparisons, and a comparison drawn over a total that is missing rows is
    # the one output of this file that would actively mislead.
    out["cost_fully_accounted"] = (out["unaccounted"] == 0
                                   and out["unpriced"] == 0)
    # A terminated row is ACCOUNTED (it has stats, they are priced) and its
    # number is still short by whatever the in-flight call cost, so the total
    # is a lower bound even when nothing is missing.  `cost_fully_accounted`
    # keeps its own meaning -- no row is absent -- and the bound flag is the
    # one that widens, because "every row is priced" and "the total is exact"
    # stopped being the same sentence the moment a row could be cut short.
    out["cost_per_pass_is_lower_bound"] = (not out["cost_fully_accounted"]
                                           or out["terminated"] > 0)
    # `non_vacuous_passes` is None when nobody has scored the sweep -- which
    # is NOT zero non-vacuous passes, so the derived average stays None too
    # and prints its reason rather than a number.
    out["non_vacuous_passes"] = non_vacuous_passes
    out["cost_per_non_vacuous_pass"] = (
        round(out["cost_usd_total"] / non_vacuous_passes, 4)
        if non_vacuous_passes and out["cost_usd_total"] is not None else None)
    # The SAME flag under a matching name, because this is the figure that
    # travels: a reader who lifts `cost_per_non_vacuous_pass` out of the JSON
    # must find its qualifier beside it and not three keys away under a name
    # about a different denominator.  Assigned, never recomputed -- one
    # sentence about the total, spelled twice, cannot drift.
    out["cost_per_non_vacuous_pass_is_lower_bound"] = \
        out["cost_per_pass_is_lower_bound"]

    caps = [per_item_cost_cap(r) for r in without_cost]
    out["rows_without_cost"] = len(caps)
    out["rows_without_cost_capped"] = sum(1 for c in caps if c is not None)
    # None whenever ANY missing row is uncapped, which is every run on disk
    # today: a ceiling that covers all but one row is not a ceiling.
    out["cost_usd_upper_bound"] = (
        round((out["cost_usd_total"] or 0.0) + sum(caps), 4)
        if caps and all(c is not None for c in caps) else None)
    out["cost_per_pass_upper_bound"] = (
        round(out["cost_usd_upper_bound"] / passed, 4)
        if passed and out["cost_usd_upper_bound"] is not None else None)
    return out


def _money(x: Optional[float]) -> str:
    return "n/a" if x is None else f"${x:,.2f}"


def format_cost_summary(cs: dict) -> list[str]:
    """The cost block, as lines.  Returned rather than printed so the
    selftest can assert on what a reader will actually see -- an aggregate
    that is correct in the dict and wrong on the screen is still wrong.
    """
    def tok(total, med):
        return (f"{'n/a':>12}" if total is None
                else f"{total:>12,}") + (f"   median {med:>11,.0f}"
                                         if med is not None else "")

    lines = ["  cost accounting"]
    lines.append(f"    wall time      {(cs['agent_seconds_total'] or 0)/3600:>9.2f} h"
                 f"   median {(cs['agent_seconds_median'] or 0):>7.1f} s"
                 f"   ({cs['agent_seconds_items']}/{cs['n']} items)")
    lines.append("    prompt tok   " + tok(cs["prompt_tokens_total"],
                                           cs["prompt_tokens_median"]))
    lines.append("    output tok   " + tok(cs["completion_tokens_total"],
                                           cs["completion_tokens_median"]))
    stamp = cs["price_as_of"]
    stamp = ", ".join(stamp) if isinstance(stamp, list) else stamp
    models = ", ".join(f"{k} x{v}" for k, v in cs["priced_models"].items())
    lines.append(
        f"    cost         {_money(cs['cost_usd_total']):>12}"
        f"   median {_money(cs['cost_usd_median']):>11}"
        + (f"   [{models} @ prices of {stamp}]" if models else ""))
    # The comparison numbers, printed last so they read after their inputs,
    # printed as "n/a" when nothing passed rather than as a division, and
    # WITHHELD entirely when the total they divide is known to be missing
    # rows.  See the gate paragraph in `cost_summary`.
    gap = (f"{cs.get('unaccounted', 0)} rows unaccounted, "
           f"{cs.get('unpriced', 0)} unpriced")
    if cs.get("cost_fully_accounted", True):
        # ONE flag, both averages.  It is a property of the NUMERATOR -- the
        # total -- so every average drawn from that total inherits it, and
        # the line this file itself calls "the publishable denominator" is
        # the last one that may print bare while the total is a floor.  (It
        # did print bare for one review round: `cost per PASS` was widened
        # to cover terminated rows and its sibling three lines down was not,
        # so a run with seven cut-short rows quoted an exact-looking cost per
        # non-vacuous pass -- the very number A6 lifts into RESULTS.)
        bound = (">= " if cs.get("cost_per_pass_is_lower_bound") else "")
        lines.append(f"    cost per PASS  {bound}"
                     f"{_money(cs['cost_per_pass']):>10}"
                     f"   ({cs['passed']} pass(es)"
                     + (f", {cs['seconds_per_pass']/3600:.2f} h each"
                        if cs["seconds_per_pass"] else "") + ")")
        if cs.get("non_vacuous_passes") is None:
            lines.append(
                "    cost per NON-VACUOUS PASS       n/a   (no test-quality "
                "summary beside this run, so the non-vacuous passes are not "
                "KNOWN -- which is not the same as none)")
        else:
            lines.append(
                f"    cost per NON-VACUOUS PASS {bound}"
                f"{_money(cs['cost_per_non_vacuous_pass']):>9}"
                f"   ({cs['non_vacuous_passes']} non-vacuous pass(es) -- the "
                f"publishable denominator"
                + (", and a FLOOR: see the LOWER BOUND line below"
                   if bound else "") + ")")
    else:
        lines.append(
            f"    cost per PASS  withheld ({gap} — an average over an "
            f"understated total would flatter the system)")
        if cs["cost_per_pass"] is None:
            # No floor either: nothing was priced, so there is not even a
            # partial total to bound from below.  Said, rather than printed
            # as `>= n/a`, which reads like a number.
            lines.append(
                f"                   and no lower bound either: nothing in "
                f"this run could be priced ({gap})")
        else:
            lines.append(
                f"                   >= {_money(cs['cost_per_pass'])} "
                f"(lower bound: {gap})")
        if cs.get("cost_per_non_vacuous_pass") is not None:
            lines.append(
                f"    cost per NON-VACUOUS PASS  withheld; "
                f">= {_money(cs['cost_per_non_vacuous_pass'])} "
                f"(lower bound: {gap})")
        # Absent by construction today: no adapter stamps an enforceable
        # per-item cap, so `cost_usd_upper_bound` is None and nothing here
        # prints.  Wired now so that the day one does, the bound appears
        # rather than waiting to be remembered.
        if cs.get("cost_per_pass_upper_bound") is not None:
            lines.append(
                f"                   <= "
                f"{_money(cs['cost_per_pass_upper_bound'])} (upper bound: all "
                f"{cs['rows_without_cost']} missing row(s) carry an "
                f"enforceable per-item cap)")
    if cs.get("terminated"):
        lines.append(
            f"    LOWER BOUND    {cs['terminated']:>4} item(s) were cut short "
            f"at the wall-clock envelope; the tokens above are what COMPLETED "
            f"on them, so the total and the average are floors, not values")
    if cs["unaccounted"]:
        lines.append(
            f"    unaccounted    {cs['unaccounted']:>4} item(s) carry no agent "
            f"stats -- their spend is REAL and is NOT in the total above "
            f"(a driver killed before it could write one: see r2t.confined.terminate, "
            f"which is why this is no longer what a timeout does)")
    if cs["unpriced"]:
        lines.append(
            f"    unpriced       {cs['unpriced']:>4} item(s) have tokens but "
            f"no price entry; their tokens are counted, their money is not")
        for r in cs["unpriced_reasons"]:
            lines.append(f"                    {r[:150]}")
    if cs["upper_bound_items"]:
        # One line per reason under the count.  An item can have more than
        # one reason, so the reason counts can add up to more than the items.
        lines.append(
            f"    UPPER BOUND    {cs['upper_bound_items']:>4} item(s) are "
            f"priced as upper bounds; the real spend is at or below these "
            f"figures")
        for reason, count in cs["upper_bound_reasons"].items():
            lines.append(f"                   {count:>4} item(s) "
                         f"{UPPER_BOUND_REASONS[reason]}")
    if cs["price_table_error"]:
        lines.append(f"    NO PRICE TABLE  {cs['price_table_error']}")
    return lines


def _stat_line(label: str, values: list, unit: str = "", fmt: str = ".1f",
               n: int = 0) -> str:
    """`label  median X  max Y  (k/n items)` -- or the reason there is none."""
    vals = [v for v in values
            if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if not vals:
        return f"    {label:<16} not recorded on any of the {n} item(s)"
    return (f"    {label:<16} median {statistics.median(vals):>8{fmt}}{unit}"
            f"   max {max(vals):>8{fmt}}{unit}   ({len(vals)}/{n} items)")


def format_system_behaviour(rows: list[dict]) -> list[str]:
    """What the system DID, as lines -- the half of a run a score cannot show.

    Two runs with the same pass rate are not the same system if one wrote a
    file on seven items and the other on ninety, or if one used its whole
    iteration budget on every item and the other stopped after twenty calls.
    None of this is a score and none of it enters a denominator; it is the
    behavioural evidence that makes the score interpretable, and it lives
    beside the cost block for the same reason cost does.

    `outcome_unstable_rate` is DIAGNOSTIC and is stated as one.  When a row
    was run more than once and its repeats disagreed, the benchmark's own
    measurement is noisy on that item -- worth knowing, and emphatically not a
    correction to apply to the rate above: silently reweighting a denominator
    by how often a system was self-consistent would score stability under the
    name of capability.

    Returned rather than printed, like `format_cost_summary`, so a selftest
    can assert on what a reader actually sees.
    """
    n = len(rows)
    if not n:
        return ["  system behaviour", "    (no rows)"]
    stats = [_agent_stats(r) for r in rows]

    def answer_write(row: dict) -> Optional[bool]:
        """Whether the row records answer bytes, or None if it records none.

        The driver's `wrote_files` flag describes an internal observation and
        is demonstrably false on complete generated answers.  The row's
        `produced_files` / `written_files` are the persisted answer evidence,
        so telemetry is derived from those artifacts instead.
        """
        fields = [row.get(k) for k in ("produced_files", "written_files")
                  if k in row]
        return any(bool(v) for v in fields) if fields else None

    writes = [answer_write(r) for r in rows]
    wrote = sum(v is True for v in writes)
    have_write_evidence = sum(v is not None for v in writes)
    forced = sum(1 for r, v in zip(rows, writes)
                 if v is True and _agent_stats(r).get("forced_write_used"))
    run_errors = sum(1 for s in stats if s.get("run_errors"))
    trials_used = [((r.get("metadata") or {}).get("trials") or {}).get("used")
                   for r in rows]

    lines = ["  system behaviour"]
    if not have_write_evidence:
        lines.append(f"    answer writes    not recorded on any of the {n} "
                     f"item(s)")
    else:
        lines.append(
            f"    answer writes    {wrote:>4}/{have_write_evidence:<4} "
            f"item(s) record produced_files/written_files ({forced} of them "
            f"via the forced-write fallback)"
            + ("" if have_write_evidence == n
               else f"; {n - have_write_evidence} item(s) record neither "
                    f"answer-file field"))
    lines.append(_stat_line("llm calls", [s.get("llm_calls") for s in stats],
                            fmt=".0f", n=n))
    lines.append(_stat_line("agent seconds",
                            [(r.get("metadata") or {}).get("agent_seconds")
                             for r in rows], unit=" s", n=n))
    lines.append(_stat_line("trials used", trials_used, fmt=".0f", n=n))
    lines.append(
        f"    run errors       {run_errors:>4}/{n:<4} item(s) recorded a "
        f"driver or API error (an error is not automatically a failure to "
        f"generate -- see results.infrastructure_marker)")

    repeated = [r for r in rows if (r.get("repeats") or 1) > 1]
    if repeated:
        unstable = sum(1 for r in repeated
                       if len(set(r.get("outcomes_all_runs") or [])) > 1)
        lines.append(
            f"    outcome instability  {unstable}/{len(repeated)} repeated "
            f"item(s) disagreed between their own runs "
            f"({unstable / len(repeated) * 100:.1f}%) -- DIAGNOSTIC ONLY: the "
            f"rates above are unchanged by it, because reweighting a "
            f"denominator by self-consistency would score stability under the "
            f"name of capability")
    return lines


def summarise(rows: list[dict], non_vacuous_passes: Optional[int] = None
              ) -> dict:
    n = len(rows)
    outcomes = Counter(r["outcome"] for r in rows)
    denominators = [_step_denominator(r) for r in rows]
    steps_total = sum(d for d in denominators if d)
    steps_recorded = sum(len(r.get("per_step") or []) for r in rows)
    steps_passed = sum(1 for r in rows for s in (r.get("per_step") or [])
                       if s["result"] == "passed")
    # An item with no denominator must leave BOTH sides of the ratio, or
    # its passing steps inflate a fraction they are not counted under.
    steps_passed_scored = sum(
        1 for r, d in zip(rows, denominators) if d
        for s in (r.get("per_step") or []) if s["result"] == "passed")
    # Macro: every item weighs the same, so a 36-step scenario cannot
    # outvote a 3-step one.  It disagrees with micro often enough to be
    # worth printing (on the probe: micro 12.5 vs macro 11.0 for one
    # system, 17.6 vs 18.4 for another), so neither is quoted alone.
    per_item_credit = [
        sum(1 for s in (r.get("per_step") or []) if s["result"] == "passed") / d
        for r, d in zip(rows, denominators) if d]
    ran = [r for r in rows if r.get("per_step")]
    partial = [r for r in ran if r["outcome"] != "passed"
               and any(s["result"] == "passed" for s in r["per_step"])]
    gen = [r["generation_seconds"] for r in rows if r.get("generation_seconds")]
    ex = [r["execution_seconds"] for r in rows if r.get("execution_seconds")]
    return {
        "n": n,
        "passed": outcomes.get("passed", 0),
        "pass_rate": (outcomes.get("passed", 0) / n) if n else 0.0,
        "outcomes": dict(outcomes.most_common()),
        "stages": dict(Counter(STAGE.get(r["outcome"], r["outcome"])
                               for r in rows).most_common()),
        "steps_passed": steps_passed,
        "steps_passed_scored": steps_passed_scored,
        "steps_total": steps_total,
        "steps_recorded": steps_recorded,
        "step_credit_micro": ((steps_passed_scored / steps_total)
                              if steps_total else None),
        "step_credit_macro": (statistics.mean(per_item_credit)
                              if per_item_credit else None),
        "items_without_step_denominator": sum(1 for d in denominators if not d),
        "items_reaching_a_step": len(ran),
        "items_with_partial_credit": len(partial),
        "median_generation_seconds": round(statistics.median(gen), 1) if gen else None,
        "median_execution_seconds": round(statistics.median(ex), 1) if ex else None,
        # .get: `scenario_not_found` and `harness_error` rows carry no
        # n_files, and a reader must not crash on the rows that most need
        # reading.
        "files_produced_median": (statistics.median([r.get("n_files", 0)
                                                     for r in rows])
                                  if n else None),
        "rejected_path_attempts": sum(len(r.get("rejected_files") or [])
                                      for r in rows),
        # What the run cost, on the same footing as what it achieved.  Nested
        # under one key rather than spread across the summary so that the
        # spend can be quoted, stored and diffed as a unit -- and so that a
        # reader who takes `cost_usd_total` cannot pick it up without
        # `unaccounted` sitting next to it.
        "cost": cost_summary(rows, non_vacuous_passes=non_vacuous_passes),
    }


def load_test_quality(run_path: str,
                      summary_path: Optional[str] = None, *,
                      reference_controls_reader: object = None
                      ) -> Optional[dict]:
    """The test-quality summary beside a run, when one has been produced.

    Absence is not an error and must not read as a zero: it means nobody has
    run `r2t.cli test-quality` on this sweep yet, which is a different
    statement from "none of its passes tests anything".  The caller gets None
    and prints nothing rather than a 0%.

    V2 has no path-derived trust fallback.  Its caller supplies the generic
    `reference_controls_reader` obtained from the installed bundle; this
    function only forwards that callback to the summary validator.  Omitting
    it leaves v2 fail-closed and leaves every v1 call unchanged.
    """
    from . import test_quality as TQ
    try:
        kwargs = {"summary_path": summary_path}
        if reference_controls_reader is not None:
            kwargs["reference_controls_reader"] = reference_controls_reader
        return TQ.load_bound_test_quality(run_path, **kwargs)
    except TQ.TestQualityRefused as e:
        raise ReportRefusal(str(e)) from None


def non_vacuous(rows: list[dict], tq: Optional[dict]) -> Optional[dict]:
    """`pass_at_1` and `non_vacuous_pass_at_1`, over the SAME denominator.

    The second is the first minus the passes that were not shown to be tests:
    only `equivalent_to_reference` counts in the numerator.  Under C4 that
    means recall 1.0 over the population-pinned assertion-hard subset; legacy
    summaries retain their recorded full-gold meaning for byte-compatible
    historical rendering.  `weaker`, `vacuous` and `not_scorable` do not,
    and the last of those is the honest one to watch: it is not a bad pass, it
    is an *unverified* one (gold kills nothing there, so the item cannot
    separate a test from a no-op), and rolling it into either number would be
    a claim the measurement does not support.

    The denominator is the run's item count in both lines, deliberately.  A
    non-vacuity rate over the passes alone would rise as a system passed
    fewer items, which is the same reward-for-failing inversion §3.10's
    eligibility rule exists to remove, one level up.

    A sidecar whose scored items are not this run's passes is marked `stale`
    and the rate is withheld: a summary left over from an earlier sweep would
    otherwise publish a non-vacuity claim about a different set of passes,
    and every number in it would look perfectly reasonable.
    """
    from . import results as R
    from . import test_quality as TQ
    if not tq:
        return None
    passed = {r["item_id"] for r in rows if r["outcome"] == "passed"}
    single_observation = (
        tq.get("schema") == R.TEST_QUALITY_SUMMARY_SCHEMA_V2)
    if single_observation:
        required = {
            "method", "policy", "candidate_observation_count",
            "reference_observation_count", "verdict_basis", "companion_basis",
            "hard_recall_macro", "full_recall_macro",
            "full_only_generated_macro", "full_jaccard_macro", "per_item",
            "reference_excluded_count", "candidate_excluded_count",
        }
        missing = sorted(required - set(tq))
        if missing:
            raise ReportRefusal(
                "REFUSED: validated v2 test-quality summary is missing "
                f"field(s) {missing}.")
        if tq["method"] != R.SINGLE_OBSERVATION_METHOD \
                or tq["policy"] \
                != R.FULL_POPULATION_SINGLE_OBSERVATION_POLICY \
                or tq["candidate_observation_count"] != 1 \
                or tq["reference_observation_count"] != 1 \
                or (tq["verdict_basis"], tq["companion_basis"]) not in {("hard_subset", "full_gold"), ("full_gold", None)}:
            raise ReportRefusal(
                "REFUSED: validated v2 test-quality summary does not identify "
                "the reviewed one-candidate/one-reference-observation basis.")
    per_item = tq.get("per_item") or {}
    if single_observation and set(per_item) != passed:
        raise ReportRefusal(
            f"REFUSED: validated v2 test-quality summary scores "
            f"{len(per_item)} item(s) that are not this run's "
            f"{len(passed)} pass(es) -- it is stale.")
    verdicts = [v.get("verdict") for v in per_item.values()]
    # The two v2 estimands are eligible over different item sets, so each
    # publishes its own scored count rather than sharing one.
    hard_scored = sorted(
        iid for iid, value in per_item.items()
        if value.get("hard_recall") is not None) if single_observation else []
    companion_scored = sorted(
        iid for iid, value in per_item.items()
        if value.get("full_recall") is not None) if single_observation else []
    stale = set(per_item) != passed
    n = len(rows)
    n_equivalent = sum(1 for v in verdicts if v == NON_VACUOUS_VERDICT)
    qualifier = TQ.publication_qualifier(tq)
    return {
        "n": n,
        "passed": len(passed),
        "pass_at_1": (len(passed) / n) if n else 0.0,
        "non_vacuous_passes": n_equivalent,
        "non_vacuous_pass_at_1": (None if stale or not n
                                  else n_equivalent / n),
        "equivalent_to_reference": n_equivalent,
        "weaker": sum(1 for v in verdicts if v == "weaker"),
        "vacuous": sum(1 for v in verdicts if v == "vacuous"),
        "not_scorable": sum(1 for v in verdicts if v == "not_scorable"),
        "recall_macro": tq.get("recall_macro"),
        "verdict_basis": tq.get("verdict_basis"),
        "hard_recall_macro": tq.get("hard_recall_macro"),
        "full_recall_macro": tq.get("full_recall_macro"),
        "full_only_generated_macro": tq.get("full_only_generated_macro"),
        "full_jaccard_macro": tq.get("full_jaccard_macro"),
        "schema": tq.get("schema"),
        "method": tq.get("method"),
        "policy": tq.get("policy"),
        "candidate_observation_count": tq.get("candidate_observation_count"),
        "reference_observation_count": tq.get("reference_observation_count"),
        **({"reference_method": tq["reference_method"]}
           if "prestashop_reference_evidence" in tq else {}),
        # The labelled basis travels with every number derived from it
        # (specifications/SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md).
        **({"sensitivity": tq["sensitivity"],
            "inference_valid": tq["inference_valid"]}
           if single_observation and tq.get("sensitivity") is not None
           else {}),
        # So does a gold-killed slice of a hard-subset reference, whose scope
        # its basis does not imply (a full-gold-only basis always has it).
        **({"candidate_pair_scope": tq["candidate_pair_scope"],
            "withheld_measures": list(tq["withheld_measures"])}
           if single_observation and tq["verdict_basis"] == "hard_subset"
           and tq.get("candidate_pair_scope") is not None else {}),
        "companion_basis": tq.get("companion_basis"),
        "reference_controls": tq.get("reference_controls"),
        # The producer's own spelling, unchanged: both are COUNTS, and the
        # summary's `candidate_excluded_pairs` is the excluded pair LIST that
        # would render as a list of dicts inside the mandatory note.
        "reference_excluded_count": tq.get("reference_excluded_count"),
        "candidate_excluded_count": tq.get("candidate_excluded_count"),
        "reference_omitted_items": tq.get("reference_omitted_items"),
        "reference_declared_reason": tq.get("reference_declared_reason"),
        "hard_n_scored": len(hard_scored) if single_observation and tq["verdict_basis"] == "hard_subset" else None,
        "hard_not_scorable_items": (
            sorted(set(per_item) - set(hard_scored))
            if single_observation and tq["verdict_basis"] == "hard_subset" else None),
        "companion_n_scored": (len(companion_scored) if single_observation and tq["companion_basis"] is not None
                               else None),
        "companion_not_scorable_items": (
            sorted(set(per_item) - set(companion_scored))
            if single_observation and tq["companion_basis"] is not None else None),
        "hard_subset_digest": tq.get("hard_subset_digest"),
        "mutants_in_population": tq.get("mutants_in_population"),
        # The operator set the verdicts above are ABOUT.  Carried through so a
        # caller that pairs two runs' vectors can refuse a mix rather than
        # macro-average across two mutation engines -- see `non_vacuous_view`.
        # None on a summary written before the column existed, which is a
        # different fact from `r2t-mutate` and is left as one.
        "engine": tq.get("engine"),
        "engine_version": tq.get("engine_version"),
        # Stable catalogue generation, stronger than engine@version: the
        # first-party engine deliberately keeps 1.0 while populations evolve.
        # Absent on archived summaries written before the registry existed.
        "population_id": tq.get("population_id"),
        "stale": stale,
        "scored_items": sorted(per_item),
        # The COMPLETENESS QUALIFIER, threaded exactly as `engine` above is
        # and for the same reason: the evidence layer already records whether
        # the pair set behind this rate was complete, whether gold executed all
        # of it, and how much of it ended in the harness failing -- and until
        # R4 none of that reached the surface that publishes the number.  A
        # rate over a gold set that shrank for infrastructure reasons is higher
        # than the same system's rate over the full one, so the reader who is
        # not told cannot tell.  `publication_ready` here decides only whether
        # the RENDERED primary is withheld; the arithmetic is untouched and
        # stays in `--format json`.
        **qualifier,
    }


def non_vacuous_view(run_path: str, rows: list[dict],
                     summary_path: Optional[str] = None, *,
                     reference_controls_reader: object = None) -> dict:
    """The per-item NON-VACUOUS outcome vector for a run, or a refusal.

    `report` publishes the COUNT (`non_vacuous_pass_at_1`); a paired test needs
    the vector behind it, item by item, so that `cli compare` can ask which
    items the two arms disagree on.  Both come out of `non_vacuous` here rather
    than out of two readings of the sidecar, because the rule for when the
    number may be published at all is subtle and must not exist twice:

    * NO SIDECAR is not zero non-vacuous passes -- it is nobody having scored
      the sweep -- so there is no vector to return and this refuses;
    * a STALE sidecar (its scored items are not this run's passes) is a summary
      about a different set of passes, and every number in it would look
      perfectly reasonable;
    * and the vector is cross-checked against the count `report` prints, so a
      future edit that changed one and not the other is caught here instead of
      surfacing as a comparison nobody can reproduce from the printed table.

    V1 keeps its historical `hard_subset_digest` identity.  V2 instead returns
    `method` and `reference_controls_digest`: its hard subset is installed
    inside those authenticated controls and it deliberately has no standalone
    hard-subset artifact field.  The optional generic
    `reference_controls_reader` is forwarded unchanged to the bound-summary
    validator; this consumer never discovers or constructs bundle authority.

    The refusal is LOUD by construction: `ReportRefusal` propagates to the CLI
    as an exit, never as a silent fall back to functional pass.  A comparison
    that quietly reverted to `pass_at_1` would be the worst outcome available
    -- on the docx pair that is the difference between p = 0.0010 and a
    degenerate p = 1.0000, printed under the same command line.
    """
    tq = load_test_quality(
        run_path, summary_path,
        reference_controls_reader=reference_controls_reader)
    name = os.path.basename(run_path)
    if tq is None:
        raise ReportRefusal(
            f"REFUSED: {name} has no bound test-quality evidence, so its "
            f"non-vacuous passes are not KNOWN -- which is not the same as "
            f"none, and scoring them as none would hand the comparison to "
            f"whichever arm was left unscored.")
    nv = non_vacuous(rows, tq)
    if nv["stale"]:
        raise ReportRefusal(
            f"REFUSED: the test-quality summary beside {name} scores "
            f"{len(nv['scored_items'])} item(s) that are not this run's "
            f"{nv['passed']} pass(es) -- it is from another sweep. Its "
            f"verdicts are about other solutions; pairing them with this "
            f"run's items would compare two systems on a third one's tests.")
    per_item = tq.get("per_item") or {}
    outcomes = {
        r["item_id"]: (r.get("outcome") == "passed"
                       and (per_item.get(r["item_id"]) or {}).get("verdict")
                       == NON_VACUOUS_VERDICT)
        for r in rows}
    # The invariant that keeps the vector and the published count one claim.
    if sum(1 for v in outcomes.values() if v) != nv["non_vacuous_passes"]:
        raise ReportRefusal(                                # pragma: no cover
            f"REFUSED: {name}'s non-vacuous vector has "
            f"{sum(1 for v in outcomes.values() if v)} item(s) but its summary "
            f"publishes {nv['non_vacuous_passes']}. The number a table prints "
            f"and the number a comparison pairs have come apart; neither is "
            f"usable until they agree.")
    view = {"outcomes": outcomes, "summary": nv,
            "sidecar": find_sidecar_path(run_path),
            "engine": nv["engine"], "engine_version": nv["engine_version"],
            "population_id": nv["population_id"],
            "verdict_basis": nv["verdict_basis"]}
    if nv.get("method") == "single_observation":
        digest = (nv.get("reference_controls") or {}).get("digest")
        if not isinstance(digest, str) or not digest:
            raise ReportRefusal(
                f"REFUSED: {name}'s validated v2 summary has no installed "
                "reference-controls digest for comparison identity.")
        view.update(method=nv["method"], reference_controls_digest=digest)
    else:
        # Frozen v1 comparison identity.  Do not replace this key with the v2
        # reference-controls identity: historical callers compare it exactly.
        view["hard_subset_digest"] = nv["hard_subset_digest"]
    return view


def find_sidecar_path(run_path: str) -> Optional[str]:
    """The sidecar `load_test_quality` would read, for citing it."""
    from .test_quality import find_sidecar
    return find_sidecar(run_path)


def partition_test_quality(tq: dict, passed: set) -> dict:
    """A run's test-quality summary restricted to some of its passes.

    Used for a project partition and for benchmark 2.0's population
    exclusions (`results` uses it too), so both recompute alike.
    """
    from . import results as R
    per_item = {iid: value
                for iid, value in (tq.get("per_item") or {}).items()
                if iid in passed}
    tq = dict(tq, per_item=per_item)
    # Sidecar-level macros were computed over the whole run.  They
    # must be recomputed from the per-item evidence after partition,
    # just like pass rate and cost.  Population cardinality cannot be
    # recovered from per-item coverage counts (mutants can overlap),
    # so it becomes unknown instead of retaining a cross-project
    # total under a project heading.
    # v2 names its per-item measurements differently and has no
    # hard-basis Jaccard at all, so the partition macro reads the
    # hard recall and the full-population Jaccard by name.
    single_observation = (
        tq.get("schema") == R.TEST_QUALITY_SUMMARY_SCHEMA_V2)
    recall_key = (("full_recall" if tq.get("verdict_basis") == "full_gold" else "hard_recall") if single_observation else "recall")
    jaccard_key = ("full_jaccard" if single_observation
                   else "jaccard")
    recalls = [value.get(recall_key) for value in per_item.values()
               if isinstance(value.get(recall_key), (int, float))
               and not isinstance(value.get(recall_key), bool)]
    jaccards = [value.get(jaccard_key) for value in per_item.values()
                if isinstance(value.get(jaccard_key), (int, float))
                and not isinstance(value.get(jaccard_key), bool)]
    full_recalls = [value.get("full_recall")
                    for value in per_item.values()
                    if isinstance(value.get("full_recall"),
                                  (int, float))
                    and not isinstance(value.get("full_recall"), bool)]
    hard_recalls = [value.get("hard_recall")
                    for value in per_item.values()
                    if isinstance(value.get("hard_recall"),
                                  (int, float))
                    and not isinstance(value.get("hard_recall"), bool)]
    only_generated = [value.get("full_only_generated")
                      for value in per_item.values()
                      if isinstance(value.get("full_only_generated"),
                                    (int, float))
                      and not isinstance(
                          value.get("full_only_generated"), bool)]
    verdicts = Counter(value.get("verdict")
                       for value in per_item.values())
    tq.update({
        "n_passed": len(passed),
        "n_scorable": len(recalls),
        "recall_macro": (round(sum(recalls) / len(recalls), 6)
                         if recalls else None),
        "jaccard_macro": (round(sum(jaccards) / len(jaccards), 6)
                          if jaccards else None),
        "full_recall_macro": (
            round(sum(full_recalls) / len(full_recalls), 6)
            if full_recalls else None),
        "hard_recall_macro": (
            round(sum(hard_recalls) / len(hard_recalls), 6)
            if hard_recalls else None),
        **({
            "full_only_generated_macro": (
                round(sum(only_generated) / len(only_generated), 6)
                if only_generated else None),
            "full_jaccard_macro": (
                round(sum(jaccards) / len(jaccards), 6)
                if jaccards else None),
        } if single_observation else {}),
        "verdicts": dict(verdicts),
        "non_vacuous_passes": verdicts[NON_VACUOUS_VERDICT],
        "mutants_in_population": None,
        "pairs_expected": None,
        # Whole-run pair totals, which per-item evidence cannot split.
        "pairs_executed_gold": None,
        "pairs_executed_candidate": None,
    })
    if single_observation:
        # Section 5.1's run-side count is per pair, so it can follow the
        # partition.  The reference-side counts describe the reference
        # controls' own mapped population and stay as recorded.
        lost = [pair for pair in tq.get("candidate_excluded_pairs") or ()
                if pair["item_id"] in passed]
        tq.update(candidate_excluded_pairs=lost,
                  candidate_excluded_count=len(lost))
    return tq


def benchmark_population_rows(rows: list[dict], tq: Optional[dict] = None
                              ) -> tuple:
    """One run's rows and test quality within benchmark 2.0's population.

    For readers that take a run without resolving its planned population
    (`report --non-vacuous-out`).  Returns `(rows, tq, block)`: `block` is
    None for rows no 2.0 list governs, else the disclosure of the listed
    instances; their rows leave, and `tq` is recomputed without them as a
    report view does.
    """
    try:
        block = P.row_exclusions(rows)
    except P.PopulationRefusal as exc:
        raise ReportRefusal(str(exc)) from None
    if not block or not block["count"]:
        return rows, tq, block
    left = {entry["item_id"] for entry in block["excluded"]}
    rows = [row for row in rows if row["item_id"] not in left]
    if tq is not None:
        tq = partition_test_quality(
            tq, {row["item_id"] for row in rows
                 if row.get("outcome") == "passed"})
    return rows, tq, block


def _make_report_view(source: dict, rows: list[dict],
                      project: Optional[str] = None) -> dict:
    """One independently aggregated view of a run (whole or one project).

    Benchmark 2.0's excluded instances (`population.excluded_ids`) leave
    `rows` here, before any arithmetic: they are collected, never counted.
    """
    from . import results as R

    excluded = P.excluded_ids(source["population"])
    if excluded:
        rows = [row for row in rows if row["item_id"] not in excluded]
    ladder = R.ladder({row["item_id"]: row for row in rows})
    try:
        population = (P.scoped(source["population"], rows, project, ladder)
                      if project is not None else
                      P.with_ladder(source["population"], ladder))
    except P.PopulationRefusal as exc:
        raise ReportRefusal(str(exc)) from None
    tq = source["raw_test_quality"]
    source_nv = source["test_quality"]
    if tq is None:
        nv = None
    elif source_nv and source_nv["stale"]:
        # A stale whole-run sidecar cannot become current merely because a
        # partition happens to match part of it.  Preserve the refusal state
        # while making this block's denominator and pass count truthful.
        nv = dict(source_nv, n=len(rows),
                  passed=sum(r.get("outcome") == "passed" for r in rows),
                  pass_at_1=(sum(r.get("outcome") == "passed" for r in rows)
                             / len(rows) if rows else 0.0),
                  non_vacuous_pass_at_1=None)
    else:
        passed = {r["item_id"] for r in rows if r.get("outcome") == "passed"}
        if len(rows) != len(source["rows"]):
            tq = partition_test_quality(tq, passed)
        else:
            tq = dict(tq, per_item={
                iid: value
                for iid, value in (tq.get("per_item") or {}).items()
                if iid in passed})
        nv = non_vacuous(rows, tq)
    if nv is not None and ladder["withheld"]:
        # Issue #202 withholds the functional pass rate for an unknown
        # PRESENT row. Keep its gate independent of population admission and
        # do not disturb the separately qualified non-vacuity measurement.
        nv = dict(nv, pass_at_1=None)
    if nv is not None and not population["canonical_values_admitted"]:
        nv = dict(nv, non_vacuous_pass_at_1=None,
                  pass_at_1=None, recall_macro=None,
                  hard_recall_macro=None, full_recall_macro=None,
                  full_only_generated_macro=None,
                  full_jaccard_macro=None,
                  population_withheld=True,
                  publication_ready=False)
        reasons = list(nv.get("withheld_reasons") or ())
        reasons.extend(reason for reason in population["withheld_reasons"]
                       if reason not in reasons)
        nv["withheld_reasons"] = reasons
    nvp = (nv["non_vacuous_passes"]
           if nv and not nv["stale"]
           and population["canonical_values_admitted"] else None)
    summary = summarise(rows, non_vacuous_passes=nvp)
    primary_reasons = []
    if not population["canonical_values_admitted"]:
        primary_reasons.extend(population["withheld_reasons"])
    primary_reasons.extend(reason for reason in ladder["withheld_reasons"]
                           if reason not in primary_reasons)
    if primary_reasons:
        summary["pass_rate"] = None
        summary["pass_rate_withheld_reasons"] = primary_reasons
    summary["population"] = P.public_view(population)
    return {"summary": summary,
            "rows": rows, "path": source["path"], "test_quality": nv,
            "population": population, "ladder": ladder,
            # Computed before printing.  This is intentionally scoped to the
            # partition so its denominator is the table's denominator.
            "draws": draws.summarise(rows)}


def _v2_mutation_detail_lines(nv: dict) -> list[str]:
    """Human v2 disclosure: two estimands, two scored populations.

    Every number carries section 5.1's two excluded counts, because each of
    them is over the narrowed pair universe and not over the registered one.
    """
    from . import results as R

    if nv.get("reference_method") == "single_observation":
        return ["    method single_observation; one reference observation per role and one "
                "candidate observation; full_gold B100 development basis; reference rows "
                "reused; no repeat-stability claim"]
    if nv.get("method") != "single_observation":
        return []
    withheld = (nv.get("population_withheld")
                or nv.get("publication_ready") is False)
    excluded = R.excluded_pairs_note(nv.get("reference_excluded_count"),
                                     nv.get("candidate_excluded_count"),
                                     nv.get("reference_omitted_items"))

    def metric(value: object) -> str:
        return ("WITHHELD" if withheld else
                f"{value:.3f}" if isinstance(value, (int, float)) else "-")

    passed = nv["passed"]
    if nv.get("verdict_basis") == "full_gold":
        return [f"    method single_observation; one full-gold and one candidate observation",
                f"    full-gold recall (companion to NV) {metric(nv.get('full_recall_macro'))} {excluded}",
                "    gold-killed candidate scope; only-generated kills and Jaccard not measured",
                "    hard subset and stub gate not defined"]
    # A gold-killed slice never observed the pairs these two read, so they
    # say "not measured" rather than "-" or WITHHELD, which imply a number.
    from . import test_quality as TQ
    gold_killed = (nv.get("candidate_pair_scope")
                   == TQ.CANDIDATE_PAIRS_GOLD_KILLED)

    def companion(value: object) -> str:
        return "not measured" if gold_killed else metric(value)

    hard_excluded = len(nv.get("hard_not_scorable_items") or ())
    companion_excluded = len(nv.get("companion_not_scorable_items") or ())
    return [
        (f"    method {nv['method']}; candidate observations "
         f"{nv['candidate_observation_count']}; reference observations "
         f"{nv['reference_observation_count']}"),
        *([f"    LABELLED POST-HOC SENSITIVITY {nv['sensitivity']} "
           "(inference_valid: false)"] if nv.get("sensitivity") else []),
        *([f"    candidate pairs: gold-killed only; only-generated and "
           f"Jaccard {TQ.GOLD_KILLED_NOT_MEASURED}"] if gold_killed else []),
        (f"    PRIMARY hard-subset recall "
         f"{metric(nv.get('hard_recall_macro'))} {excluded}; n_scored "
         f"{nv['hard_n_scored']}/{passed}; excluded {hard_excluded} with an "
         "empty hard subset"),
        "    hard only-generated n/a; hard Jaccard n/a",
        (f"    COMPANION full-population {excluded}: recall "
         f"{metric(nv.get('full_recall_macro'))}; only-generated "
         f"{companion(nv.get('full_only_generated_macro'))}; Jaccard "
         f"{companion(nv.get('full_jaccard_macro'))}; n_scored "
         f"{nv['companion_n_scored']}/{passed}; excluded "
         f"{companion_excluded} with an empty full-gold reference kill set"),
        *([(f"    DECLARED REFERENCE SUBSET: "
            f"{nv['reference_omitted_items']} released item(s) omitted, "
            f"declared reason: "
            f"{nv.get('reference_declared_reason') or 'not recorded'}")]
          if nv.get("reference_omitted_items") else []),
    ]


def population_exclusions_text(block: dict) -> str:
    """Benchmark 2.0's excluded count and instances, for people."""
    return (f"{block['count']} instance(s) outside benchmark "
            f"{block['benchmark_version']}'s population: rows collected, "
            f"counted in no metric ({block['path']})"
            + "".join(f"; {entry['item_id']} ({entry['reason']})"
                      for entry in block["excluded"]))


def _render_reports(reports: dict, per_item: bool, only: str,
                    show_non_vacuous: bool = True) -> None:
    """Render already-validated views; this function never decides scope."""
    width = max(len(k) for k in reports) if reports else 10
    for name, report_view in reports.items():
        population = report_view["summary"]["population"]
        print(f"{name}: POPULATION {population['status'].upper()}")
        if population.get("inference_valid") is False:
            print("  inference_valid      false (descriptive only)")
            print("  inference_reason     " + population["inference_reason"])
            if population.get("source_run"):
                print("  original C run       " + population["source_run"]["path"])
        print(f"  planned_n            "
              f"{population['planned_n'] if population['planned_n'] is not None else '-'}")
        print(f"  observed_n           {population['observed_n']}")
        print(f"  ladder_n             {population['ladder_n']}")
        print(f"  classified_n         {population['classified_n']}")
        missing = population["missing_planned_ids"]
        print("  missing_planned_ids  "
              + ("unavailable" if missing is None else str(missing)))
        if population.get("population_exclusions") is not None:
            print("  2.0 excluded         "
                  + population_exclusions_text(
                      population["population_exclusions"]))
        if not population["canonical_values_admitted"]:
            print("  canonical values     WITHHELD ("
                  + "; ".join(population["withheld_reasons"]) + ")")
        print()
    print(f"{'run':<{width}}  {'n':>4} {'passed':>7} {'rate':>8} "
          f"{'steps ok':>14} {'micro':>6} {'macro':>6} "
          f"{'gen s':>6} {'exec s':>7}")
    for name, r in reports.items():
        s = r["summary"]
        # Denominator is the scenarios' own step count, so these fractions
        # ARE comparable between runs; `steps_recorded` (how far the run
        # got) is kept in the summary rather than printed, because it is
        # the number that invites a false ratio.
        steps = (f"{s['steps_passed_scored']}/{s['steps_total']}"
                 if s["steps_total"] else "-")
        micro = (f"{s['step_credit_micro']*100:.1f}%"
                 if s["step_credit_micro"] is not None else "-")
        macro = (f"{s['step_credit_macro']*100:.1f}%"
                 if s["step_credit_macro"] is not None else "-")
        rate = (f"{s['pass_rate']*100:.0f}%"
                if s["pass_rate"] is not None else "WITHHELD")
        print(f"{name:<{width}}  {s['n']:>4} {s['passed']:>7} "
              f"{rate:>8} {steps:>14} {micro:>6} {macro:>6} "
              f"{str(s['median_generation_seconds'] or '-'):>6} "
              f"{str(s['median_execution_seconds'] or '-'):>7}")

    stale = {k: v["summary"]["items_without_step_denominator"]
             for k, v in reports.items()
             if v["summary"]["items_without_step_denominator"]}
    if stale:
        print("\nWARNING: step credit is computed over a partial set — these runs "
              "have items with no bench_meta step counts, so their steps are "
              "excluded from both numerator and denominator:")
        for name, k in stale.items():
            print(f"  {k:>4} item(s) in {name}")

    for name, r in reports.items():
        s = r["summary"]
        nv = r["test_quality"]
        print(f"\n{name}: how far each item got")
        # Printed together, and in this order, so the weaker claim is never
        # read without the stronger one beside it.
        if s["pass_rate"] is None:
            print("  pass_at_1                -        (WITHHELD: "
                  + "; ".join(s["pass_rate_withheld_reasons"]) + ")")
        else:
            print(f"  pass_at_1              {s['passed']:>4}/{s['n']:<4} "
                  f"= {s['pass_rate']*100:.1f}%")
        if show_non_vacuous:
            if nv is None:
                print("  non_vacuous_pass_at_1    -        (no bound "
                      "test-quality evidence for this run)")
            elif nv["stale"]:
                print(f"  non_vacuous_pass_at_1    -        (WITHHELD: the "
                      f"test-quality summary scores "
                      f"{len(nv['scored_items'])} item(s) that are not this "
                      f"run's {s['passed']} pass(es) — it is from another "
                      f"sweep)")
            elif nv.get("population_withheld"):
                print("  non_vacuous_pass_at_1    -        (WITHHELD: "
                      + "; ".join(nv.get("withheld_reasons")
                                  or ["population incomplete"])
                      + ")")
            elif not nv.get("publication_ready", True):
                # R4 item 6.  The arithmetic is not discarded — `--format json`
                # on `results` still carries every number, and this run's own
                # summary still holds them — but the PRIMARY is not printed as
                # though it were publishable, because the qualifier says it is
                # not.
                print("  non_vacuous_pass_at_1    -        (WITHHELD: "
                      + "; ".join(nv.get("withheld_reasons")
                                  or ["unqualified"])
                      + ")")
                print(f"    sensitivity value, NOT a primary: "
                      f"{nv['non_vacuous_passes']}/{nv['n']} = "
                      f"{nv['non_vacuous_pass_at_1']*100:.1f}% over "
                      f"{nv.get('pairs_executed_gold')} executed gold pair(s) "
                      f"of {nv.get('pairs_expected')} expected")
            else:
                print(f"  non_vacuous_pass_at_1  "
                      f"{nv['non_vacuous_passes']:>4}/{nv['n']:<4} = "
                      f"{nv['non_vacuous_pass_at_1']*100:.1f}%  "
                      f"<- the publishable one")
                print(f"    of {s['passed']} pass(es): "
                      f"{nv['equivalent_to_reference']} "
                      f"{NON_VACUOUS_DISPLAY}, {nv['weaker']} weaker, "
                      f"{nv['vacuous']} vacuous, {nv['not_scorable']} not "
                      f"scorable"
                      + (f"; macro recall {nv['recall_macro']:.3f}"
                         if nv["recall_macro"] is not None else ""))
                if nv.get("verdict_basis") == "hard_subset" \
                        and nv.get("method") != "single_observation":
                    hard = nv.get("hard_recall_macro")
                    full = nv.get("full_recall_macro")
                    print("    verdict basis hard_subset"
                          + (f"; hard recall {hard:.3f}"
                             if hard is not None else "; hard recall -")
                          + (f"; full recall {full:.3f}"
                             if full is not None else "; full recall -")
                          + f"; artifact {nv.get('hard_subset_digest')}")
        # Outside the publishable branch: a v2 disclosure whose numbers are
        # WITHHELD is exactly the case a reader needs to see both estimands
        # and both excluded counts for.
        if show_non_vacuous and nv is not None:
            for line in _v2_mutation_detail_lines(nv):
                print(line)
        for stage, k in s["stages"].items():
            print(f"  {k:>4}  {stage}")
        if s["items_with_partial_credit"]:
            print(f"  ({s['items_with_partial_credit']} of the "
                  f"{s['items_reaching_a_step']} that reached a step passed "
                  f"some but not all of them)")
        if s["rejected_path_attempts"]:
            print(f"  ({s['rejected_path_attempts']} file(s) refused for "
                  f"writing outside the removable tree)")
        # Printed inside the same per-run block as the outcome tally, and
        # never on its own: cost per pass is only interpretable beside the
        # pass count it divides by.
        for line in format_cost_summary(s["cost"]):
            print(line)
        for line in format_system_behaviour(r["rows"]):
            print(line)
        # Beside the behaviour block and never inside a rate: a re-drawn item
        # is IN every number above, and this says which items those are and
        # why their prior attempt was thrown away.  Prints nothing at all when
        # every row is a first draw, which is every archived run.
        for line in draws.disclosure(r["draws"]):
            print(line)
    if per_item:
        for name, r in reports.items():
            print(f"\n{name}: per item")
            for row in r["rows"]:
                if only and row["outcome"] != only:
                    continue
                steps = row.get("per_step") or []
                ok = sum(1 for s in steps if s["result"] == "passed")
                short = row["item_id"].split("features/domain/")[-1]
                print(f"  {row['outcome']:<24} {ok:>3}/{len(steps):<3} steps "
                      f" files={row.get('n_files', 0):<2} {short}")


def _render_eligible_set_tables(tables: dict, manifest: dict) -> None:
    """Render the capability split; never compute a cross-project NV mean."""
    print("\nFUNCTIONAL-PASS TABLE — all projects")
    print("  project          run                    passed      pass_at_1")
    for row in tables["functional"]:
        result = (f"{row['pass_at_1']*100:>8.1f}%"
                  if row["status"] == "scored" else "WITHHELD")
        print(f"  {row['project']:<16} {row['run']:<22} "
              f"{row['passed']:>4}/{row['n']:<4} {result:>9}")
        if row["status"] == "withheld":
            print(f"    WITHHELD: {row['reason']}")

    eligible = tables["eligible_projects"]
    functional_only = tables["functional_only_projects"]
    print("\nREFERENCE-EQUIVALENT ELIGIBLE-SET TABLE")
    print(f"  metric: {NON_VACUOUS_DISPLAY} "
          f"(stored as non_vacuous_pass_at_1)")
    print(f"  eligible set: {len(eligible)} project(s) — "
          + (", ".join(eligible) if eligible else "none"))
    print("  functional-pass-only: "
          + (", ".join(functional_only) if functional_only else "none"))
    print(f"  capability authority: dataset "
          f"{manifest['document'].get('dataset_version')} "
          f"{manifest['sha256'][:16]} ({manifest['label']})")
    generation = tables["population_generation"]
    if generation is None:
        print("  population generation: not yet scored")
    else:
        print(f"  population generation: v{generation}; ids: "
              + ", ".join(tables["population_ids"]))
    print("  project          run                    result       population")
    if not tables["reference"]:
        print("  (no mutation-capable project in this table)")
    for row in tables["reference"]:
        if row["status"] == "scored":
            result = (f"{row['non_vacuous_passes']}/{row['n']}="
                      f"{row['non_vacuous_pass_at_1']*100:.1f}%")
        elif row["status"] == "withheld":
            result = "WITHHELD"
        else:
            result = "not scored"
        population = row["population_id"] or "-"
        print(f"  {row['project']:<16} {row['run']:<22} "
              f"{result:<12} {population}")
        if row["reason"]:
            print(f"    {row['project']}/{row['run']}: {row['reason']}")
        # The eligible-set row carries the same v2 key names the per-run
        # block does, so the same disclosure renders it: two consumers of one
        # fact must not print it two ways.
        if row["status"] == "scored":
            for line in _v2_mutation_detail_lines(row):
                print(line)
    print("  No cross-project reference-equivalent mean is produced; primary "
          "reference-equivalent results remain project-specific.")


#: The label the preregistered cross-project headline must always carry.
#:
#: Not decoration and not a caveat that could be dropped for space: SPEC §8
#: rule 2 makes the LABEL part of the estimand, because the same number read
#: as an ecosystem estimate is a claim about software the corpus was filtered
#: out of (§5 and §7 are the opposite of a random sample).  Printed on the
#: same line as the number, so a pasted headline carries its own reading.
EQUAL_WEIGHT_MACRO_LABEL = "a benchmark score, not an ecosystem estimate"

# System/configuration facts that must survive a cross-project macro.  Dataset,
# subset, prompt_digest and protocol identity are deliberately absent: the v3
# CoreShop and v4 python-docx protocols are project-specific renderings of the
# intended twin condition.  These fields describe the system and its enforced
# budget, not the corpus/profile it was run against.
MACRO_SYSTEM_FIELDS = (
    "comparison_class", "adapter_version", "agent_version", "model",
    "setting", "condition", "coverage", "repeats", "max_iterations",
    "max_tokens", "temperature", "trials", "sandboxed",
    "agent_timeout_seconds", "native_budget", "protocol_deviations",
)

# A fresh cross-project system headline needs enough row-level identity to
# prove the SPEC's same-system/configuration claim.  These fields are written
# deterministically by `_run_stamp` for a protocol run.  `adapter` is kept
# separate from the historical tuple above because exact adapter equality is
# stronger than `_system_name`'s deliberately coarse `name:model -> name`
# resolution.  `agent_version` is best-effort and `protocol_deviations` has a
# canonical clean value of []; `native_budget` is conditional on whether the
# named system has a native knob at all.
MACRO_OPTIONAL_SYSTEM_FIELDS = ("agent_version", "protocol_deviations")
MACRO_CONDITIONAL_SYSTEM_FIELDS = ("native_budget",)
MACRO_REQUIRED_SYSTEM_FIELDS = (
    "adapter", "agent_system",
    *(field for field in MACRO_SYSTEM_FIELDS
      if field not in MACRO_OPTIONAL_SYSTEM_FIELDS
      and field not in MACRO_CONDITIONAL_SYSTEM_FIELDS),
)


def _identity_token(value) -> str:
    """Stable equality token for scalar and structured stamp values."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)
    except (TypeError, ValueError):
        return repr(value)


_MACRO_STRING_FIELDS = {
    "adapter", "agent_system", "comparison_class", "adapter_version",
    "agent_version", "model", "setting", "condition",
}
_MACRO_POSITIVE_INTEGER_FIELDS = {
    "repeats", "max_iterations", "max_tokens", "agent_timeout_seconds",
}
_MACRO_BOOLEAN_FIELDS = {"coverage", "sandboxed"}


def _invalid_macro_value(where: str, field: str, value, expected: str):
    raise ReportRefusal(
        f"REFUSED: {where} carries malformed {field}={value!r}; {field} "
        f"must be {expected} before it can authenticate a cross-project "
        "system identity.")


def _normalise_macro_value(where: str, field: str, value):
    """Validate one producer stamp and return its canonical identity value."""
    if field in _MACRO_STRING_FIELDS:
        if not isinstance(value, str) or not value.strip():
            _invalid_macro_value(where, field, value, "a non-empty string")
        if value != value.strip():
            _invalid_macro_value(
                where, field, value,
                "an exact canonical string without surrounding whitespace")
        if field == "agent_system" and not re.fullmatch(
                r"[A-Za-z0-9_.-]+", value):
            _invalid_macro_value(
                where, field, value,
                "a canonical system name containing only letters, digits, "
                "dot, underscore, or hyphen")
        if field == "adapter_version" and not re.fullmatch(
                r"[A-Za-z0-9_.-]+@[1-9][0-9]*", value):
            _invalid_macro_value(
                where, field, value,
                "a canonical system@positive-integer registry revision")
        if field == "comparison_class" and value not in COMPARISON_CLASSES:
            _invalid_macro_value(
                where, field, value,
                "one of " + ", ".join(COMPARISON_CLASSES))
        return value
    if field in _MACRO_POSITIVE_INTEGER_FIELDS:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            _invalid_macro_value(where, field, value,
                                 "an integer greater than or equal to 1")
        return value
    if field in _MACRO_BOOLEAN_FIELDS:
        if not isinstance(value, bool):
            _invalid_macro_value(where, field, value, "true or false")
        return value
    if field == "temperature":
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or value < 0):
            _invalid_macro_value(where, field, value,
                                 "a finite number greater than or equal to 0")
        return value
    if field == "trials":
        from ..core.constants import UNBOUNDED
        if value != UNBOUNDED and (isinstance(value, bool)
                                   or not isinstance(value, int)
                                   or value < 0):
            _invalid_macro_value(
                where, field, value,
                f"a non-negative integer or {UNBOUNDED!r}")
        return value
    if field == "protocol_deviations":
        if (not isinstance(value, list)
                or any(not isinstance(item, str) or not item.strip()
                       for item in value)):
            _invalid_macro_value(
                where, field, value,
                "a list of non-empty deviation strings (or an empty list)")
        return value
    return value


def _normalise_native_budget(where: str, system: Optional[str], value):
    """Validate the exact native-budget shape emitted for a known system."""
    if not isinstance(value, dict) or not value:
        _invalid_macro_value(where, "native_budget", value,
                             "a non-empty mapping of native knob values")
    if any(not isinstance(key, str) or not key.strip() for key in value):
        _invalid_macro_value(where, "native_budget", value,
                             "a mapping with non-empty string knob names")

    _protocol = _agent_reader("agents.protocol", where, "native_budget")
    flags = _protocol.NATIVE_KNOB_FLAGS.get(system or "", ())
    expected = {key for key, dest, _flag in flags if dest is not None}
    if expected and set(value) != expected:
        _invalid_macro_value(
            where, "native_budget", value,
            "exactly the producer-defined knob set "
            + "{" + ", ".join(sorted(expected)) + "}")
    if expected:
        for key in expected:
            knob = value[key]
            if isinstance(knob, bool) or not isinstance(knob, int) or knob < 1:
                _invalid_macro_value(
                    where, "native_budget", value,
                    f"positive integer values for {', '.join(sorted(expected))}")
    else:
        # Unknown/future systems are still allowed to carry an authenticated
        # mapping, but an empty or non-JSON value is not a producer stamp.
        try:
            json.dumps(value, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError):
            _invalid_macro_value(where, "native_budget", value,
                                 "a non-empty JSON mapping")
    return value


def _system_name(row: dict, where: str) -> Optional[str]:
    """Resolve one row's agent system, and reject contradictory spellings."""
    candidates = []
    direct = row.get("agent_system")
    if isinstance(direct, str) and direct.strip():
        candidates.append(direct.strip())
    adapter_version = row.get("adapter_version")
    if isinstance(adapter_version, str) and adapter_version.strip():
        candidates.append(adapter_version.split("@", 1)[0].strip())
    adapter = row.get("adapter")
    if isinstance(adapter, str) and adapter.strip():
        candidates.append(adapter.split(":", 1)[0].strip())
    known = sorted(set(value for value in candidates if value))
    if len(known) > 1:
        raise ReportRefusal(
            f"REFUSED: {where} contradicts itself about agent system "
            f"({', '.join(known)}). A cross-project macro cannot decide "
            "which system this row belongs to from conflicting stamps.")
    return known[0] if known else None


def _macro_arm_identity(project: str, name: str, rows: list[dict]) -> dict:
    """Homogeneous, completeness-aware identity for one project/run arm."""
    where = f"cross-project arm {project}/{name}"

    def homogeneous(field: str, values: list, *, normalise=None) -> Optional[str]:
        canonical = []
        for value in values:
            if value is None or value == "":
                canonical.append(None)
            else:
                canonical.append((normalise or _normalise_macro_value)(
                    where, field, value))
        present = [value for value in canonical if value is not None]
        if not present:
            return None
        if len(present) != len(canonical):
            raise ReportRefusal(
                f"REFUSED: {where} carries {field} on only "
                f"{len(present)} of {len(values)} rows. Partial identity is "
                "not a system identity for a macro arm.")
        tokens = sorted({_identity_token(value) for value in present})
        if len(tokens) != 1:
            raise ReportRefusal(
                f"REFUSED: {where} mixes {field} values "
                f"({', '.join(tokens)}). One macro arm must be one system "
                "configuration before it can be averaged across projects.")
        return tokens[0]

    # Resolve every redundant spelling first so `agent_system=openhands`
    # beside `adapter=aider:...` is refused even if a later missing-field
    # decision withholds the macro.  Freshness still requires the DIRECT
    # agent_system stamp below; an inferred adapter prefix is not a substitute.
    resolved_systems = [_system_name(row, where) for row in rows]

    identity = {}
    for field in MACRO_REQUIRED_SYSTEM_FIELDS:
        identity[field] = homogeneous(field, [row.get(field) for row in rows])

    # These are producer invariants, not merely fields which happen to be
    # equal.  The agent registry refuses these combinations before launch;
    # accepting them at publication would let hand-edited rows describe a
    # condition which no producer can have run.
    from ..data.prompt import AGENT_CONDITIONS
    for row in rows:
        condition = row.get("condition")
        trials = row.get("trials")
        if condition is None or condition == "" or trials is None:
            continue
        condition = _normalise_macro_value(where, "condition", condition)
        trials = _normalise_macro_value(where, "trials", trials)
        if condition not in AGENT_CONDITIONS:
            _invalid_macro_value(
                where, "condition", condition,
                "one of " + ", ".join(AGENT_CONDITIONS))
        if condition in ("c2", "c2r") and trials:
            _invalid_macro_value(
                where, "trials", trials,
                f"0 when condition is {condition} (execution feedback is c3)")
        if condition == "c3" and not trials:
            _invalid_macro_value(
                where, "trials", trials,
                "a positive count or 'unlimited' when condition is c3")

    # A missing deviation stamp is the canonical clean state.  A non-empty
    # list in any row then becomes a normal completeness/equality check: it
    # cannot be pooled with a clean or missing sibling arm.
    identity["protocol_deviations"] = homogeneous(
        "protocol_deviations",
        [row.get("protocol_deviations", []) for row in rows])
    identity["agent_version"] = homogeneous(
        "agent_version", [row.get("agent_version") for row in rows])

    # The native-knob table and the budget key are the agent component's,
    # so they are asked for only when a system is named.  `_system_name`
    # reads `adapter` as well, so `gold` and `submitted:<name>` rows name a
    # system that owns no native knob: without the agent component they get
    # the answer they get with it.  Only a row that carries `agent_system`
    # is refused for the missing component here; `native_budget` refuses by
    # its own name when it is normalised below.
    systems = {system for system in resolved_systems if system is not None}
    native_system = next(iter(systems)) if len(systems) == 1 else None
    needs_native = False
    _agent = None
    if systems:
        try:
            _protocol = _agent_reader("agents.protocol", where, "agent_system")
            _agent = _agent_reader("confined.result_ledger_v2", where,
                                   "agent_system")
        except ReportRefusal:
            if any(row.get("agent_system") not in (None, "") for row in rows):
                raise
        else:
            needs_native = (
                native_system is not None
                and bool(_protocol.NATIVE_KNOB_FLAGS.get(native_system)))
    identity["native_budget"] = homogeneous(
        "native_budget", [row.get("native_budget") for row in rows],
        normalise=lambda macro_where, _field, value: _normalise_native_budget(
            macro_where, native_system, value))
    # The top-level budget is the SAME knob written twice for the one agent
    # whose native knob carries that name -- `agent_budget` joins it there and
    # nowhere else -- so that is the condition, not the agent's name.  Spelled
    # `== "openhands"` this was the right check on the shipped pair and the
    # wrong one for a third arm either way round: an agent that owns the
    # top-level knob would pool a contradiction unchecked, and one that does
    # not would be measured against a field its producer stamps null.
    from ..core.constants import TOP_LEVEL_BUDGET_KEY as top_level
    if needs_native:
        null_fields = ["max_tokens"]
        if _agent.NATIVE_BUDGET_KEY.get(native_system) != top_level:
            null_fields.append(top_level)
        for field in null_fields:
            # An explicit inapplicable budget is known identity, distinct
            # from an absent stamp. Mixed old/new values still refuse above
            # or at the cross-project equality check below.
            if all(field in row and row[field] is None for row in rows):
                identity[field] = _identity_token(None)
    if native_system is not None and _agent is not None \
            and _agent.NATIVE_BUDGET_KEY.get(native_system) == top_level:
        for row in rows:
            budget = row.get("native_budget")
            if (isinstance(budget, dict)
                    and row.get(top_level) not in (None, "")
                    and budget.get(top_level) != row.get(top_level)):
                _invalid_macro_value(
                    where, "native_budget", budget,
                    f"the same {top_level} value as the top-level stamp")
    identity["_native_budget_required"] = needs_native
    return identity


def _validate_macro_identities(grouped: dict) -> dict[str, str]:
    """Refuse conflicts; return reasons for safely withheld macro arms."""
    by_name: dict[str, list[tuple[str, dict]]] = {}
    for project, reports in grouped.items():
        for name, rep in reports.items():
            by_name.setdefault(name, []).append(
                (project, _macro_arm_identity(project, name, rep["rows"])))
    withheld = {}
    expected_projects = set(grouped)
    for name, arms in sorted(by_name.items()):
        observed_projects = {project for project, _identity in arms}
        if len(expected_projects) < 2:
            withheld[name] = (
                "a cross-project headline requires at least two projects")
            continue
        missing_projects = sorted(expected_projects - observed_projects)
        if missing_projects:
            withheld[name] = (
                "the run arm is absent from requested project(s) "
                + ", ".join(missing_projects)
                + "; project coverage may not change the macro denominator")
            continue
        required = list(MACRO_REQUIRED_SYSTEM_FIELDS)
        if any(identity["_native_budget_required"] for _, identity in arms):
            required.append("native_budget")
        missing_everywhere = []
        fields = (tuple(required) + MACRO_OPTIONAL_SYSTEM_FIELDS
                  + (() if "native_budget" in required
                     else ("native_budget",)))
        for field in fields:
            values = {project: identity[field]
                      for project, identity in arms}
            known = {value for value in values.values() if value is not None}
            if not known:
                if field in required:
                    missing_everywhere.append(field)
                continue
            if len(known) != 1 or any(value is None for value in values.values()):
                shown = ", ".join(
                    f"{project}={value if value is not None else 'unknown'}"
                    for project, value in sorted(values.items()))
                raise ReportRefusal(
                    f"REFUSED: cross-project headline {name!r} would average "
                    f"different or incompletely identified systems: {field} "
                    f"is {shown}. A repeated filename is a column label, not "
                    "proof that the projects measured the same system and "
                    "comparison class.")
        if missing_everywhere:
            fields = ", ".join(missing_everywhere)
            withheld[name] = (
                "required same-system identity is absent from every project "
                f"arm ({fields}); a repeated filename is not authentication")
    return withheld


def equal_weight_macros(grouped: dict, *, _withheld: Optional[dict] = None) -> dict:
    """The preregistered equal-weight `pass_at_1` macro, per run.

    EQUAL WEIGHT OVER PROJECTS, never over items.  A pooled rate is a weighted
    average whose weights are how many items each project happened to
    contribute -- 90 items from one codebase and 10 from another publishes,
    mostly, a number about the first -- so the mean is taken over the
    per-project rates and the pooled denominator is never formed at all.  That
    is why this returns `n_projects` and the per-project rates and NO summed
    item count: there is no cross-project `n` in this object for a renderer to
    print by accident.

    `pass_at_1` only.  §2.1 and SPEC §8 rule 2 both refuse a post-hoc
    cross-project `non_vacuous_pass_at_1` macro: primary non-vacuous results
    stay project-specific, and a macro over them would be a new estimand
    invented at render time.

    Deleted unreviewed in `760d128` and restored here under owner ruling
    §2.1 (PR M0), which is why the label above is a constant rather than a
    string in a format call.
    """
    withheld = _validate_macro_identities(grouped)
    for project, reports in grouped.items():
        for name, rep in reports.items():
            summary = rep["summary"]
            if summary["pass_rate"] is None:
                reason = "; ".join(summary.get(
                    "pass_rate_withheld_reasons") or
                                   ["population unavailable"])
                withheld[name] = (
                    f"project {project} has no admitted pass_at_1 ({reason})")
    if _withheld is not None:
        _withheld.update(withheld)
    per_run: dict = {}
    for project, reports in grouped.items():
        for name, rep in reports.items():
            summary = rep["summary"]
            per_run.setdefault(name, {})[project] = {
                "pass_at_1": summary["pass_rate"],
                "passed": summary["passed"],
                "n": summary["n"],
            }
    out = {}
    for name, projects in per_run.items():
        if name in withheld:
            continue
        rates = [block["pass_at_1"] for block in projects.values()]
        out[name] = {
            "label": EQUAL_WEIGHT_MACRO_LABEL,
            "estimand": "equal-weight macro average over projects",
            "metric": "pass_at_1",
            "n_projects": len(projects),
            "projects": projects,
            "pass_at_1_macro": (sum(rates) / len(rates)) if rates else None,
        }
    return out


def _render_equal_weight_macro(name: str, macro: dict) -> None:
    """Print one run's macro, with its label and its parts, never a pooled n."""
    print(f"\nCROSS-PROJECT HEADLINE — {name}")
    print(f"  pass_at_1 macro        {macro['pass_at_1_macro']*100:.1f}%  "
          f"({EQUAL_WEIGHT_MACRO_LABEL})")
    print(f"    equal-weight mean over {macro['n_projects']} project(s); "
          f"each project counts once, whatever its item count:")
    for project, block in sorted(macro["projects"].items()):
        print(f"    {block['pass_at_1']*100:>5.1f}%  "
              f"({block['passed']}/{block['n']})  {project}")
    print("    no pooled cross-project rate or denominator is produced, and "
          "no cross-project non_vacuous_pass_at_1 macro exists — primary "
          "non-vacuous results stay project-specific (SPEC §8 rule 2).")


def _render_withheld_macro(name: str, reason: str) -> None:
    print(f"\nCROSS-PROJECT HEADLINE WITHHELD — {name}")
    print(f"  no pass_at_1 macro: {reason}.")


def _report_impl(run_paths: list[str], per_item: bool = False,
                 only: str = "", group_by: str = "",
                 test_quality_paths: Optional[list[str]] = None,
                 release_paths: Optional[list[str]] = None,
                 capability_manifest: Optional[dict] = None,
                 reference_controls_reader: object = None,
                 publication: bool = False,
                 validated_population_scopes: Optional[list[dict]] = None) -> dict:
    if test_quality_paths is not None \
            and len(test_quality_paths) != len(run_paths):
        raise ReportRefusal(
            f"REFUSED: --test-quality was supplied "
            f"{len(test_quality_paths)} time(s) for {len(run_paths)} run(s). "
            "Supply one explicit summary per --run, in the same order, or "
            "omit all of them to use each run's unique sidecar.")
    if release_paths is not None and len(release_paths) != len(run_paths):
        raise ReportRefusal(
            f"REFUSED: --release was supplied {len(release_paths)} time(s) for "
            f"{len(run_paths)} run(s). Supply one explicit planned workset per "
            "--run, in the same order, or omit all of them.")
    if validated_population_scopes is not None \
            and len(validated_population_scopes) != len(run_paths):
        raise ReportRefusal(
            "REFUSED: validated population scope count differs from run count.")
    names = [os.path.basename(path).replace(".jsonl", "")
             for path in run_paths]
    duplicate_names = sorted(name for name, n in Counter(names).items()
                             if n > 1)
    if duplicate_names and group_by != "project":
        raise ReportRefusal(
            f"REFUSED: duplicate run basename(s) "
            f"{', '.join(repr(n) for n in duplicate_names)} would overwrite "
            f"one input in the report. Give each run a distinct basename so "
            f"every input has a visible column.")

    summaries = (test_quality_paths if test_quality_paths is not None
                 else [None] * len(run_paths))
    releases = (release_paths if release_paths is not None
                else [None] * len(run_paths))
    scopes = (validated_population_scopes
              if validated_population_scopes is not None
              else [None] * len(run_paths))
    sources = []
    for name, path, summary_path, release_path, scope in zip(
            names, run_paths, summaries, releases, scopes):
        rows = _load(path)
        check_unique_item_ids(rows, path)
        draws.check_campaign_pair(path)
        try:
            population = P.resolve(
                rows, os.path.abspath(path), explicit_release=release_path,
                validated_scope=scope)
        except P.PopulationRefusal as exc:
            raise ReportRefusal(str(exc)) from None
        # Publication-v3 refuses the ancillary sidecar outright: the
        # conventional path is not opened, whether or not it exists.
        tq = (None if publication else load_test_quality(
            path, summary_path,
            reference_controls_reader=reference_controls_reader))
        nv = non_vacuous(rows, tq)
        sources.append({"name": name, "rows": rows, "path": path,
                        "raw_test_quality": tq, "test_quality": nv,
                        "population": population})

    # BEFORE anything is printed: all refusal-capable validation and all view
    # construction.  A redirected report must be either complete or empty.
    if group_by == "project" and any(
            source["population"]["status"] == "count_only"
            for source in sources):
        raise ReportRefusal(
            "REFUSED: cannot partition a count-only checkpoint across "
            "projects; it retains no item IDs for the per-project planned "
            "counts")
    all_rows = [r for source in sources for r in source["rows"]]
    planned_projects = {
        item_id.split("/")[0]
        for source in sources
        for item_id in (source["population"].get("_planned_item_ids") or ())}
    projects = sorted(set(check_single_project(
        all_rows, group_by=group_by)) | planned_projects)
    if len(projects) > 1 and group_by != "project":
        raise ReportRefusal(
            f"REFUSED: the resolved report populations span {len(projects)} "
            f"projects ({', '.join(projects)}). Pass --group-by project; a "
            "pooled item-weighted total is not a supported report cell.")
    submitted = check_single_tier(all_rows)
    for source in sources:
        draws.summarise(source["rows"])

    if group_by == "project":
        # A sidecar binds one run to one mutation population.  Partitioning a
        # multi-project RUN is fine for functional outcomes, but partitioning
        # one test-quality binding would make it name several populations.
        multi_bound = [source for source in sources
                       if source["raw_test_quality"] is not None
                       and len({project_of(r) for r in source["rows"]}) > 1]
        if multi_bound:
            source = multi_bound[0]
            raise ReportRefusal(
                f"REFUSED: {os.path.basename(source['path'])} spans multiple "
                f"projects but carries one test-quality summary. One summary "
                f"binds one run and one population; supply separate "
                f"per-project run files before building the eligible-set "
                f"table.")

        # Repeated basenames are the intended cross-project system key, but a
        # repeated (project, basename) would still overwrite one arm.  Check
        # this before constructing or printing any view.
        source_keys = [(project, source["name"])
                       for source in sources
                       for project in (
                           {project_of(r) for r in source["rows"]}
                           | {item_id.split("/")[0] for item_id in
                              (source["population"].get(
                                  "_planned_item_ids") or ())})]
        duplicate_keys = sorted(key for key, n in Counter(source_keys).items()
                                if n > 1)
        if duplicate_keys:
            shown = ", ".join(f"{project}/{name}"
                              for project, name in duplicate_keys)
            raise ReportRefusal(
                f"REFUSED: duplicate project/run key(s) {shown} would "
                f"overwrite one report column. Repeated basenames are allowed "
                f"only across disjoint projects.")

        grouped: dict[str, dict] = {}
        for project in projects:
            project_rows = [r for r in all_rows if project_of(r) == project]
            check_comparison_class(project_rows)
            grouped[project] = {
                source["name"]: _make_report_view(
                    source,
                    [r for r in source["rows"] if project_of(r) == project],
                    project=project)
                for source in sources
                if (any(project_of(r) == project for r in source["rows"])
                    or any(item_id.split("/")[0] == project for item_id in
                           (source["population"].get(
                               "_planned_item_ids") or ())))
            }

        # Validate BOTH the same-system macro identity and the capability
        # authority before the first renderer is called.  In particular,
        # `equal_weight_macros` must not discover a mixed comparison class
        # after the eligible-set heading has already reached stdout.
        withheld_macros = {}
        macros = equal_weight_macros(grouped, _withheld=withheld_macros)
        capability_manifest = (capability_manifest
                               if capability_manifest is not None
                               else load_capability_manifest())
        tables = eligible_set_tables(
            grouped, capability_manifest["document"])
        # The banner is the FIRST line, and it prints only after every
        # refusal-capable validation above, so a redirected report is still
        # either complete or empty.
        if submitted:
            print(submitted_banner(all_rows))
        _render_eligible_set_tables(tables, capability_manifest)

        returned = {}
        for project, reports in grouped.items():
            print(f"\nPROJECT {project} (complete report; no pooled "
                  f"cross-project total)")
            _render_reports(
                reports, per_item=per_item, only=only,
                show_non_vacuous=tables["capabilities"][project])
            returned.update({f"{project}/{name}":
                             dict(rep["summary"],
                                  test_quality=rep["test_quality"])
                             for name, rep in reports.items()})
        # Rendered, not returned.  This mapping is `{run: summary}` and every
        # caller iterates it as such; a macro entry beside the summaries would
        # be a row with no `n`, which is precisely the pooled-denominator
        # confusion the macro exists to avoid.  `equal_weight_macros` is
        # public and pure for anyone who wants the object.
        for name, macro in sorted(macros.items()):
            _render_equal_weight_macro(name, macro)
        for name, reason in sorted(withheld_macros.items()):
            _render_withheld_macro(name, reason)
        return returned

    check_comparison_class(all_rows)
    # As above: after the last refusal, before the first table byte.
    if submitted:
        print(submitted_banner(all_rows))
    reports = {source["name"]: _make_report_view(source, source["rows"])
               for source in sources}
    _render_reports(reports, per_item=per_item, only=only)

    return {k: dict(v["summary"], test_quality=v["test_quality"])
            for k, v in reports.items()}


def report(run_paths: list[str], per_item: bool = False,
           only: str = "", group_by: str = "",
           test_quality_paths: Optional[list[str]] = None,
           release_paths: Optional[list[str]] = None,
           reference_controls_reader: object = None) -> dict:
    """Production report API; capability authority comes only from VERSIONS.

    For v2, `reference_controls_reader` is the caller-owned generic seam to
    authenticated installed controls.  It is forwarded unchanged to every
    bound-summary load; this consumer neither selects a bundle nor derives an
    authority from persisted summary fields.  V1 callers omit it.
    """
    return _report_impl(
        run_paths, per_item=per_item, only=only, group_by=group_by,
        test_quality_paths=test_quality_paths, release_paths=release_paths,
        reference_controls_reader=reference_controls_reader)


def publication_report(run_paths: list[str], *, per_item: bool,
                       population_scopes: list[dict]) -> dict:
    """Publication-v3 report: every row, no filter, no ancillary discovery."""
    return _report_impl(run_paths, per_item=per_item, only="", group_by="",
                        test_quality_paths=None, publication=True,
                        validated_population_scopes=population_scopes)


def _report_with_capability_fixture(
        run_paths: list[str], *, dataset_manifest_path: str,
        dataset_manifest_sha256: str, per_item: bool = False,
        only: str = "", group_by: str = "",
        test_quality_paths: Optional[list[str]] = None) -> dict:
    """Private selftest path; fixture injection is absent from `report`."""
    authority = _load_capability_fixture(
        dataset_manifest_path, dataset_manifest_sha256)
    return _report_impl(
        run_paths, per_item=per_item, only=only, group_by=group_by,
        test_quality_paths=test_quality_paths,
        capability_manifest=authority)


# --------------------------------------------------------------------------
def _fixture_run(path: str, rows: list[dict]) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    return path


def _fixture_sidecar(run_path: str, verdicts: dict, engine: str = "r2t-mutate",
                     version: str = "1.0", **qualifier) -> str:
    """A test-quality summary shaped exactly as `test-quality` writes one.

    Publication-ready by default, because that is what a real complete
    campaign writes; `**qualifier` is how a test asks for the degraded or
    short states instead, one named field at a time.
    """
    from . import test_quality as TQ
    return TQ.write_sidecar(
        {"_report_selftest_fixture": True,
         "engine": engine, "engine_version": version,
         "population_id": "coreshop-v1",
         "recall_macro": 0.9, "mutants_in_population": 40,
         **TQ.COMPLETE_QUALIFIER_FIXTURE, **qualifier,
         "per_item": {iid: (v if isinstance(v, dict) else {"verdict": v})
                      for iid, v in verdicts.items()}}, run_path)


def _fixture_gold(root: str, items: list[str]) -> str:
    """A gold sidecar tree where every item is a closure of its own."""
    os.makedirs(root, exist_ok=True)
    manifest = {}
    for n, iid in enumerate(items):
        name = f"{n:04x}.json"
        manifest[iid] = name
        with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
            json.dump({"files": [f"src/Ctx{n}.php"]}, fh)
    with open(os.path.join(root, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    return root


def selftest() -> int:
    """Run the checks with the producer module left exactly as it was found.

    `_selftest` installs a report-side fixture loader on `test_quality` for
    most of its length.  It used to put the real one back on its last line,
    which is no restore at all: any check that raised in between left the
    fixture installed in the interpreter, and every later `test_quality`
    read in that process -- another module's self-test in the same run --
    answered from this file's fixtures.
    """
    from . import test_quality as _TQ
    real_loader = _TQ.load_bound_test_quality
    try:
        return _selftest()
    finally:
        _TQ.load_bound_test_quality = real_loader


def _selftest() -> int:
    """The non-vacuity half of a run file, and who is allowed to publish it.

    Two things are pinned here that nothing else pins.  First: the per-item
    NON-VACUOUS vector and the count `report` prints come out of one rule, and
    the rule refuses -- loudly, never by falling back to functional pass --
    when the sidecar behind it is missing or stale.  Second, and end to end:
    `cli compare --metric non_vacuous_pass` actually pairs that vector, on a
    fixture where both arms pass every item and the functional test is
    therefore exactly the degenerate p = 1.0000 the python-docx cells produced.
    That second check is the defect in one line -- before it, the only
    comparison the verb could express was the uninformative one.
    """
    import io
    import tempfile
    from contextlib import redirect_stdout

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refuses(name, fn, *needles):
        try:
            fn()
        except (ReportRefusal, SystemExit) as e:
            missing = [n for n in needles if n not in str(e)]
            check(name, not missing, f"message lacks {missing}: {e}")
            return
        check(name, False, "did not refuse")

    def refuses_before_printing(name, fn, *needles):
        """Refuses, AND stdout is empty when it does.

        The distinction is the whole point: `r2t report > table.txt` sends the
        refusal to stderr, so a refusal raised after the table has been written
        leaves a complete-looking file on disk with the disclosure missing from
        it.  A check that only asserted the exception would pass on exactly
        that bug.
        """
        from .results import ResultsInputError
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                fn()
        except (ReportRefusal, SystemExit, draws.DrawRefusal,
                ResultsInputError) as e:
            missing = [n for n in needles if n not in str(e)]
            check(name, not missing and not buf.getvalue(),
                  (f"message lacks {missing}: {e}" if missing else
                   f"{len(buf.getvalue())} char(s) reached stdout first: "
                   f"{buf.getvalue()[:400]!r}"))
            return
        check(name, False, f"did not refuse; printed {buf.getvalue()[:200]!r}")

    def fixture_population_scope(path: str, extra_item_ids=()) -> dict:
        """An explicit complete workset for arithmetic-focused fixtures."""
        from . import result_ledger
        rows = _load(path)
        item_ids = (tuple(row["item_id"] for row in rows)
                    + tuple(extra_item_ids))
        return P.frozen_scope(
            item_ids=item_ids,
            workset={
                "item_count": len(item_ids),
                "ordered_item_ids_digest":
                    result_ledger.ordered_item_ids_digest(item_ids),
            }, source="selftest frozen workset")

    def pinned_report(paths: list[str], **kwargs) -> dict:
        return _report_impl(
            paths,
            validated_population_scopes=[fixture_population_scope(path)
                                         for path in paths],
            **kwargs)

    def with_v2_population(path: str, excluded: list, fn):
        """Run `fn` under a synthetic benchmark 2.0 list: protocol 9001."""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("schema: r2t.benchmark-population/1\n"
                     "benchmark_version: \"2.0\"\n"
                     "census: selftest census\n"
                     "protocols: [9001]\n"
                     "excluded:\n" + "".join(
                         f"  - instance_id: {iid}\n    reason: census_pass\n"
                         for iid in excluded))
        listed_path = P.BENCHMARK_POPULATION
        P.BENCHMARK_POPULATION = path
        try:
            return fn()
        finally:
            P.BENCHMARK_POPULATION = listed_path

    def pinned_capability_report(paths: list[str], *,
                                 dataset_manifest_path: str,
                                 dataset_manifest_sha256: str,
                                 **kwargs) -> dict:
        authority = _load_capability_fixture(
            dataset_manifest_path, dataset_manifest_sha256)
        return _report_impl(
            paths, capability_manifest=authority,
            validated_population_scopes=[fixture_population_scope(path)
                                         for path in paths],
            **kwargs)

    print("--- r2t.bench.report ---")

    # At least 20 independent closures: the inferential APIs intentionally
    # refuse smaller fixtures.  Twenty-five leaves room for the pinned-subset
    # probes below to remove items while remaining at the floor.
    ITEMS = [f"proj/features/domain/f{n}.feature:{n}" for n in range(25)]

    def rows_all_passing():
        return [{"item_id": iid, "outcome": "passed", "n_files": 1,
                 "comparison_class": "fixed_model_scaffold"} for iid in ITEMS]

    # Report's unit fixtures exercise rendering and paired statistics without
    # constructing a full mutation campaign.  Production loading remains the
    # fail-closed validator in test_quality; this local shim accepts only the
    # explicitly marked temporary fixtures and still checks their exact run
    # and generated-test binding.
    from . import test_quality as _TQ
    _real_tq_loader = _TQ.load_bound_test_quality

    fixture_reference_readers = []

    def _report_fixture_loader(run_path, summary_path=None, *,
                               reference_controls_reader=None):
        if reference_controls_reader is not None:
            fixture_reference_readers.append(reference_controls_reader)
        path = summary_path or _TQ.find_sidecar(run_path)
        if not path:
            return None
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if doc.get("_report_selftest_fixture") is not True:
            kwargs = {"summary_path": summary_path}
            if reference_controls_reader is not None:
                kwargs["reference_controls_reader"] = \
                    reference_controls_reader
            return _real_tq_loader(run_path, **kwargs)
        actual = _TQ.run_binding(run_path)
        if doc.get("binding") != actual:
            raise _TQ.TestQualityRefused(
                "REFUSED: test fixture sidecar is stale or tampered; "
                "run_sha256/generated_tests_sha256 disagree.")
        return doc

    _TQ.load_bound_test_quality = _report_fixture_loader

    with tempfile.TemporaryDirectory() as d:
        from . import results as _R
        # THE JOIN, report side.  Produced by `test_quality`, key set equal
        # to its closed field list, and never rewritten into this consumer's
        # vocabulary -- which is the only reason the three renderer defects
        # this block covers were ever invisible.  The last item is given an
        # empty hard subset by the builder, so the two v2 estimands keep
        # their different scored populations.
        v2_tq = _R._producer_shaped_single_observation_summary(
            list(ITEMS), population_id="coreshop-v1")
        for klass in ("development_unstamped", "fixture", None):
            development = dict(v2_tq, generation_provenance_class=klass)
            before = json.dumps(development, sort_keys=True)
            report_view = non_vacuous(rows_all_passing(), development)
            results_view = _R.mutation(development, set(ITEMS))
            check(f"native v2 {klass!r} provenance withholds both consumers "
                  "without changing arithmetic or evidence",
                  report_view["publication_ready"] is False
                  and results_view["publication_ready"] is False
                  and report_view["withheld_reasons"]
                      == results_view["withheld_reasons"]
                  and len(report_view["withheld_reasons"]) == 1
                  and "generation" in report_view["withheld_reasons"][0]
                  and report_view["hard_recall_macro"]
                      == v2_tq["hard_recall_macro"]
                  and results_view["values"]["recall"]
                      == v2_tq["hard_recall_macro"]
                  and before == json.dumps(development, sort_keys=True))
        check("native v2 qualification uses its own validated schema",
              _TQ.publication_ready(v2_tq) == (True, []))
        v2_per_item = v2_tq["per_item"]
        v2_nv = non_vacuous(rows_all_passing(), v2_tq)
        check("validated v2 report data carries the hard primary, exact "
              "full-population companions, method and observation counts",
              set(v2_tq) == _TQ._single_observation_summary_fields()
              and v2_nv["hard_recall_macro"] == v2_tq["hard_recall_macro"]
              and abs(v2_nv["hard_recall_macro"] - 12.5 / 24) < 1e-12
              and abs(v2_nv["full_recall_macro"] - 0.36) < 1e-12
              and abs(v2_nv["full_only_generated_macro"] - 0.01) < 1e-12
              and abs(v2_nv["full_jaccard_macro"] - 0.35) < 1e-12
              and v2_nv["method"] == "single_observation"
              and v2_nv["candidate_observation_count"] == 1
              and v2_nv["reference_observation_count"] == 1
              and v2_nv["hard_n_scored"] == 24
              and v2_nv["companion_n_scored"] == 25
              and v2_nv["reference_excluded_count"] == 131
              and v2_nv["candidate_excluded_count"] == 1,
              str(v2_nv))
        refuses("a stale validated v2 report summary refuses rather than "
                "publishing another sweep's arithmetic",
                lambda: non_vacuous(
                    rows_all_passing(),
                    dict(v2_tq, per_item={ITEMS[0]: v2_per_item[ITEMS[0]]})),
                "stale")
        refuses("a validated v2 report summary missing a companion value "
                "refuses rather than defaulting it",
                lambda: non_vacuous(
                    rows_all_passing(),
                    {key: value for key, value in v2_tq.items()
                     if key != "full_jaccard_macro"}),
                "missing", "full_jaccard_macro")
        refuses("a validated v2 report summary missing an excluded count "
                "refuses rather than printing a narrowed denominator as if "
                "it were the registered population",
                lambda: non_vacuous(
                    rows_all_passing(),
                    {key: value for key, value in v2_tq.items()
                     if key != "reference_excluded_count"}),
                "missing", "reference_excluded_count")
        # Benchmark 2.0 leaves instances out of a v2 summary through the same
        # partition.  The last item holds the run's one excluded pair.
        kept_items = list(ITEMS[:-1])
        partitioned = partition_test_quality(v2_tq, set(kept_items))
        producer_kept = _R._producer_shaped_single_observation_summary(
            list(ITEMS), candidate_items=kept_items,
            population_id="coreshop-v1")
        check("a v2 partition recomputes the macros as the producer would, "
              "drops the run's excluded pair of the item that left, and "
              "makes the whole-run pair totals unknown",
              partitioned["candidate_excluded_count"] == 0
              and partitioned["candidate_excluded_pairs"] == []
              and v2_tq["candidate_excluded_count"] == 1
              and partitioned["pairs_executed_gold"] is None
              and partitioned["reference_excluded_count"] == 131
              and partitioned["non_vacuous_passes"]
              == producer_kept["non_vacuous_passes"]
              and all((partitioned[key] is None) == (producer_kept[key] is None)
                      and (partitioned[key] is None
                           or abs(partitioned[key] - producer_kept[key]) < 1e-6)
                      for key in ("hard_recall_macro", "full_recall_macro",
                                  "full_only_generated_macro",
                                  "full_jaccard_macro")),
              str({key: (partitioned.get(key), producer_kept.get(key))
                   for key in ("candidate_excluded_count", "hard_recall_macro",
                               "full_recall_macro", "full_jaccard_macro")}))

        # A: non-vacuous on the first SEVEN items; B: on the first ONE.
        # Both pass all 25, so the functional comparison has nothing to say.
        a_verdicts = {iid: ("equivalent_to_reference" if n < 7 else "weaker")
                      for n, iid in enumerate(ITEMS)}
        b_verdicts = {iid: ("equivalent_to_reference" if n < 1 else "weaker")
                      for n, iid in enumerate(ITEMS)}
        run_a = _fixture_run(os.path.join(d, "a.jsonl"), rows_all_passing())
        run_b = _fixture_run(os.path.join(d, "b.jsonl"), rows_all_passing())
        submitted_run = _fixture_run(
            os.path.join(d, "submitted.jsonl"),
            [dict(row, condition="submitted")
             for row in rows_all_passing()])
        study_run = _fixture_run(
            os.path.join(d, "study.jsonl"),
            [dict(row, condition="c3") for row in rows_all_passing()])
        side_a = _fixture_sidecar(
            run_a, a_verdicts, population_id="coreshop-v1")
        _fixture_sidecar(
            run_b, b_verdicts, population_id="coreshop-v1")
        gold = _fixture_gold(os.path.join(d, "gold"), ITEMS)

        from . import campaign as campaign_module
        from . import result_ledger
        empty_checkpoint_run = _fixture_run(
            os.path.join(d, "empty-checkpoint.jsonl"), [])
        with open(empty_checkpoint_run + result_ledger.CHECKPOINT_SUFFIX,
                  "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        real_verify_checkpoint = result_ledger.verify_checkpoint

        def verified_empty_checkpoint(_path):
            return {
                "artifact_kind": "run_shard",
                "workset": {
                    "item_count": 1,
                    "ordered_item_ids_digest": "0" * 64,
                },
                "population_identity": {
                    "campaign_digest": "f" * 16,
                    "subset_id": None, "subset_digest": None,
                    "shard_rule": campaign_module.SHARD_RULE,
                    "shard_count": 1,
                },
                "release_path": os.path.abspath(empty_checkpoint_run),
                "verified": True,
            }

        try:
            result_ledger.verify_checkpoint = verified_empty_checkpoint
            refuses_before_printing(
                "an empty count-only checkpoint cannot disappear from a "
                "project-grouped report",
                lambda: _report_impl(
                    [empty_checkpoint_run], group_by="project"),
                "cannot partition a count-only checkpoint across projects")
        finally:
            result_ledger.verify_checkpoint = real_verify_checkpoint

        # PR-3 owns binding generation and validation; PR-4 owns consuming it.
        # Pin the seam even when this focused branch is tested before PR-3.
        from . import test_quality as TQ
        had_bound_loader = hasattr(TQ, "load_bound_test_quality")
        old_bound_loader = getattr(TQ, "load_bound_test_quality", None)
        bound_calls = []

        def fake_bound_loader(run_path, summary_path=None, *,
                              reference_controls_reader=None):
            bound_calls.append((run_path, summary_path,
                                reference_controls_reader))
            path = summary_path or TQ.find_sidecar(run_path)
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)

        TQ.load_bound_test_quality = fake_bound_loader
        reader = object()
        try:
            bound_summary = load_test_quality(run_a)
            load_test_quality(run_a, reference_controls_reader=reader)
        finally:
            if had_bound_loader:
                TQ.load_bound_test_quality = old_bound_loader
            else:
                del TQ.load_bound_test_quality
        check("report consumes PR-3's binding-aware sidecar loader when that "
              "capability is present",
              bound_calls == [(run_a, None, None), (run_a, None, reader)]
              and bound_summary["engine"] == "r2t-mutate",
              str(bound_calls))

        explicit = io.StringIO()
        with redirect_stdout(explicit):
            explicit_report = report(
                [run_a], test_quality_paths=[side_a],
                reference_controls_reader=reader)
        check("report forwards an explicit binding-aware test-quality path "
              "and the optional installed reference-controls reader",
              explicit_report["a"]["test_quality"]
              ["non_vacuous_passes"] == 7
              and fixture_reference_readers == [reader])
        refuses("an explicit summary list must align one-for-one with runs",
                lambda: report([run_a, run_b],
                               test_quality_paths=[side_a]),
                "1 time(s)", "2 run(s)")

        # ------------------------------------------------ the v2 entry point
        saved_guarded_loader = _TQ.load_bound_test_quality

        def guarded_v2_loader(_run_path, summary_path=None, *,
                              reference_controls_reader=None):
            if reference_controls_reader is None:
                raise _TQ.TestQualityRefused(
                    "REFUSED: a v2 summary requires its authenticated "
                    "installed ReferenceControls reader")
            return v2_tq

        fullgold_summary = _R._producer_shaped_single_observation_summary(
            list(v2_tq["per_item"]), full_gold=True)
        fullgold_nv = non_vacuous(rows_all_passing(), fullgold_summary)
        fullgold_text = "\n".join(_v2_mutation_detail_lines(fullgold_nv))
        check("fullgold reporting retains NV as lead and defines no hard or companion population",
              fullgold_nv["non_vacuous_passes"] == fullgold_summary["non_vacuous_passes"]
              and fullgold_nv["hard_n_scored"] is None
              and fullgold_nv["companion_n_scored"] is None
              and fullgold_nv["companion_not_scorable_items"] is None
              and "companion to NV" in fullgold_text
              and "not measured" in fullgold_text
              and "hard-subset recall" not in fullgold_text)

        _TQ.load_bound_test_quality = guarded_v2_loader
        try:
            refuses("the report entry point leaves v2 fail-closed without "
                    "its installed reference-controls reader",
                    lambda: load_test_quality(run_a),
                    "requires its authenticated installed ReferenceControls")
            v2_loaded = load_test_quality(
                run_a, reference_controls_reader=object())
            v2_view = non_vacuous_view(
                run_a, rows_all_passing(),
                reference_controls_reader=object())
            v2_scope = fixture_population_scope(
                run_a, ["proj/features/domain/v2-missing.feature:999"])
            v2_incomplete_buf = io.StringIO()
            with redirect_stdout(v2_incomplete_buf):
                _report_impl([run_a], reference_controls_reader=object(),
                             validated_population_scopes=[v2_scope])
            v2_complete_buf = io.StringIO()
            with redirect_stdout(v2_complete_buf):
                _report_impl(
                    [run_a], reference_controls_reader=object(),
                    validated_population_scopes=[
                        fixture_population_scope(run_a)])
        finally:
            _TQ.load_bound_test_quality = saved_guarded_loader
        check("the report entry point consumes a supplied authenticated v2 "
              "reference-controls reader",
              v2_loaded["schema"] == _R.TEST_QUALITY_SUMMARY_SCHEMA_V2)
        check("the v2 non-vacuous view exposes method plus installed "
              "reference-controls identity, never an absent v1 hard-subset "
              "digest",
              v2_view["method"] == "single_observation"
              and v2_view["reference_controls_digest"] == "a" * 64
              and "hard_subset_digest" not in v2_view,
              str(v2_view))
        check("the v2 report block discloses both estimands with their own "
              "scored populations and section 5.1's two excluded counts",
              "PRIMARY hard-subset recall 0.521 (excluded pairs: 131 "
              "reference, 1 run); n_scored 24/25"
              in v2_complete_buf.getvalue()
              and "hard only-generated n/a; hard Jaccard n/a"
              in v2_complete_buf.getvalue()
              and "COMPANION full-population (excluded pairs: 131 reference, "
              "1 run): recall 0.360" in v2_complete_buf.getvalue()
              and "n_scored 25/25" in v2_complete_buf.getvalue()
              and "gold kills nothing" not in v2_complete_buf.getvalue(),
              v2_complete_buf.getvalue())
        v2_incomplete_text = v2_incomplete_buf.getvalue()
        check("an incomplete report population clears every v2 companion "
              "aggregate and renders both disclosures as withheld",
              "PRIMARY hard-subset recall WITHHELD" in v2_incomplete_text
              and "COMPANION full-population (excluded pairs: 131 reference, "
              "1 run): recall WITHHELD; only-generated WITHHELD; Jaccard "
              "WITHHELD" in v2_incomplete_text,
              v2_incomplete_text)

        # ------------------------------------------------ the vector itself
        view = non_vacuous_view(run_a, rows_all_passing())
        check("the non-vacuous vector is per item, and a bare PASS is not in "
              "it", sum(1 for v in view["outcomes"].values() if v) == 7
              and view["outcomes"][ITEMS[0]] is True
              and view["outcomes"][ITEMS[9]] is False
              and "hard_subset_digest" in view
              and "method" not in view,
              json.dumps(view["outcomes"]))
        check("...and it agrees with the count `report` publishes",
              view["summary"]["non_vacuous_passes"] == 7
              and abs(view["summary"]["non_vacuous_pass_at_1"] - 0.28) < 1e-9)
        check("the sidecar's ENGINE travels with the vector, so a caller can "
              "refuse a mix rather than macro-average across two operator sets",
              view["engine"] == "r2t-mutate" and view["engine_version"] == "1.0")
        check("the stable population id travels with the vector even when "
              "engine@version stays fixed",
              view["population_id"] == "coreshop-v1",
              str(view["population_id"]))

        bare = _fixture_run(os.path.join(d, "bare.jsonl"), rows_all_passing())
        try:
            non_vacuous_view(bare, rows_all_passing())
        except ReportRefusal as e:
            bare_refusal = str(e)
        else:
            bare_refusal = ""
        check("a run with NO bound test-quality evidence refuses rather than "
              "scoring its non-vacuous passes as none or recommending a "
              "closed command",
              "no bound test-quality evidence" in bare_refusal
              and "not KNOWN" in bare_refusal
              and "not the same as none" in bare_refusal
              and "r2t.cli test-quality" not in bare_refusal,
              bare_refusal or "did not refuse")
        default_buf = io.StringIO()
        with redirect_stdout(default_buf):
            default_report = report([bare])
        default_text = default_buf.getvalue()
        check("the ordinary default report names the missing bound evidence "
              "without recommending a closed command",
              default_report["bare"]["test_quality"] is None
              and "no bound test-quality evidence for this run" in default_text
              and "r2t.cli test-quality" not in default_text,
              default_text)
        stale = _fixture_run(os.path.join(d, "stale.jsonl"),
                             rows_all_passing())
        _fixture_sidecar(stale, {ITEMS[0]: "equivalent_to_reference"})
        refuses("a STALE summary -- scored items that are not this run's "
                "passes -- refuses too",
                lambda: non_vacuous_view(stale, rows_all_passing()),
                "another sweep")

        # ------------------------------------------- the verb, end to end
        from . import cli

        # The OTHER half of the same join.  `--reference-controls` builds this
        # callback, and nothing network-free ever called it: it named a
        # two-argument public function that does not exist, so the whole v2
        # consumer path died with an AttributeError the moment an operator
        # supplied a real bundle.  Stub only the bundle read, then let the
        # callback run: reaching `test_quality`'s own refusal is proof it
        # reached the real one-argument seal.
        class _ReferenceArgs:
            """Exactly the `--reference-*` grammar the callback reads."""

            def __init__(self, reference_controls="/nonexistent/reference"):
                self.reference_controls = reference_controls
                self.boundary = _R.DEFAULT_BOUNDARY
                self.repo = None
                # The six paths the callback requires by name.  Their VALUES
                # are never read here -- the bundle read below is stubbed --
                # but they must be present, because a consumer that is handed
                # `--reference-controls` without them refuses by name rather
                # than passing `None` into `os.lstat`.  That refusal has its
                # own checks in `test_quality`'s selftest; this one is about
                # what the callback reaches once its grammar is complete.
                for name in ("validation", "manifest", "map", "release",
                             "gold_baseline", "attestation"):
                    setattr(self, f"reference_{name}", f"/nonexistent/{name}")
                self.reference_engine_source = None

        from . import reference_loader as _RL
        saved_native_loader = _RL.load_native_reference_controls
        try:
            _RL.load_native_reference_controls = (
                lambda *a, **kw: {"controls": {"digest": "a" * 64}})
            reader = cli._reference_controls_reader(_ReferenceArgs())
            try:
                # Through the production consumer of this callback, so a
                # missing call target comes back as a NAMED refusal instead
                # of a bare AttributeError with no failing check beside it.
                _TQ._read_single_observation_authority(
                    reader, {"schema": _R.TEST_QUALITY_SUMMARY_SCHEMA_V2})
                seal_refusal = ""
            except _TQ.TestQualityRefused as exc:
                seal_refusal = str(exc)
        finally:
            _RL.load_native_reference_controls = saved_native_loader
        check("the --reference-controls callback reaches test_quality's real "
              "one-argument scoring seal, which DERIVES the scoring view "
              "rather than being handed a second object beside the controls",
              cli._reference_controls_reader(_ReferenceArgs(
                  reference_controls=None)) is None
              and "authenticated reference controls" in seal_refusal,
              seal_refusal or "did not reach the seal")

        class _Args:
            def __init__(self, **kw):
                self.run = [run_a, run_b]
                self.gold_dir = gold
                self.items = None
                self.metric = "pass"
                self.__dict__.update(kw)

        def compared(**kw) -> str:
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli.cmd_compare(_Args(**kw))
            return buf.getvalue()

        check("C2 and C3 remain one study tier",
              check_single_tier([
                  dict(rows_all_passing()[0], condition="c2"),
                  dict(rows_all_passing()[1], condition="c3"),
              ]) is False)
        check("a pure submitted input remains inspectable on its own",
              check_single_tier([
                  dict(rows_all_passing()[0], condition="submitted"),
              ]) is True)
        refuses(
            "submitted and unstamped legacy rows are separate tiers too",
            lambda: check_single_tier([
                dict(rows_all_passing()[0], condition="submitted"),
                rows_all_passing()[1],
            ]),
            "submitted rows", "unstamped", "Report the tiers separately")
        refuses_before_printing(
            "report refuses submitted and C3 rows before any table bytes",
            lambda: report([submitted_run, study_run]),
            "submitted rows", "C2/C3", "Report the tiers separately")
        refuses_before_printing(
            "compare refuses a submitted arm against C3 before any statistic",
            lambda: compared(run=[submitted_run, study_run]),
            "submitted rows", "C2/C3", "Report the tiers separately")
        submitted_run_b = _fixture_run(
            os.path.join(d, "submitted_b.jsonl"),
            [dict(row, condition="submitted")
             for row in rows_all_passing()])
        refuses_before_printing(
            "compare refuses two pure submitted arms too -- the tier is "
            "never compared, only inspected",
            lambda: compared(run=[submitted_run, submitted_run_b]),
            "never compared", "decision 2", "descriptive inspection")
        laundered_run = _fixture_run(
            os.path.join(d, "laundered.jsonl"),
            [dict(row, adapter="submitted:external-system")
             for row in rows_all_passing()])
        refuses(
            "a submitted adapter name marks the tier even when a transport "
            "dropped the condition stamp",
            lambda: check_single_tier(
                [dict(rows_all_passing()[0],
                      adapter="submitted:external-system"),
                 dict(rows_all_passing()[1], condition="c3")]),
            "submitted rows", "Report the tiers separately")
        check("...and a pure laundered input is still one submitted tier",
              check_single_tier(_load(laundered_run)) is True)
        submitted_stdout = io.StringIO()
        with redirect_stdout(submitted_stdout):
            report([submitted_run])
        check("a pure submitted input is inspectable, and its report LEADS "
              "with the tier banner",
              submitted_stdout.getvalue().startswith(SUBMITTED_BANNER),
              submitted_stdout.getvalue()[:120])
        # Decision 7's stamp beside the tier label, in both states, and the
        # honest third answer when a multi-run input disagrees.
        proven_submitted_run = _fixture_run(
            os.path.join(d, "submitted_proven.jsonl"),
            [dict(row, condition="submitted", environment_proven=True)
             for row in rows_all_passing()])
        proven_stdout = io.StringIO()
        with redirect_stdout(proven_stdout):
            report([proven_submitted_run])
        mixed_stdout = io.StringIO()
        with redirect_stdout(mixed_stdout):
            report([submitted_run, proven_submitted_run])
        check("the banner displays the environment-proven stamp beside the "
              "tier label: false, true, and mixed when runs disagree",
              submitted_stdout.getvalue().splitlines()[0]
              == SUBMITTED_BANNER + " [environment_proven: false]"
              and proven_stdout.getvalue().splitlines()[0]
              == SUBMITTED_BANNER + " [environment_proven: true]"
              and mixed_stdout.getvalue().splitlines()[0]
              == SUBMITTED_BANNER + " [environment_proven: mixed]",
              submitted_stdout.getvalue().splitlines()[0] + " | "
              + proven_stdout.getvalue().splitlines()[0] + " | "
              + mixed_stdout.getvalue().splitlines()[0])

        functional = compared()
        check("FUNCTIONAL: two arms that pass everything are degenerate and "
              "the paired test says nothing -- this is the table A5 got",
              "passed 25/25 = 1.000" in functional
              and "b (A passed, B did not) = 0" in functional
              and "p = 1.0000" in functional, functional)
        nv = compared(metric="non_vacuous_pass")
        check("NON-VACUOUS: the same 25 items, the same two runs, and the "
              "comparison now carries information",
              "reference-kill-complete 7/25 = 0.280" in nv
              and "reference-kill-complete 1/25 = 0.040" in nv
              and "b (A reference-kill-complete, B did not) = 6" in nv
              and "c (B reference-kill-complete, A did not) = 0" in nv
              and "p = 0.0312" in nv, nv)
        check("...and it NAMES the metric and the engine in its own header, "
              "so a pasted comparison cannot be read as a pass rate",
              "metric  : non_vacuous_pass_at_1" in nv
              and "reference-kill-complete" in nv
              and "stored verdict 'equivalent_to_reference'" in nv
              and "engine  : r2t-mutate 1.0" in nv
              and "population: coreshop-v1" in nv, nv)
        from ..data import subsets as _subsets
        from ..toolkit import subset_writer as _subset_writer
        descriptive_pool = os.path.join(d, "items.jsonl")
        with open(descriptive_pool, "w", encoding="utf-8") as fh:
            for iid in ITEMS:
                fh.write(json.dumps({"item_id": iid}) + "\n")
        descriptive = _subsets.sample(
            descriptive_pool, gold, n=len(ITEMS), seed=17,
            allow_cluster_siblings=True)
        descriptive_items = os.path.join(d, "eval_descriptive.jsonl")
        _subset_writer.write_subset(descriptive, descriptive_items)
        descriptive_sidecar = os.path.join(
            d, "eval_descriptive.provenance.json")
        refuses_before_printing(
            "the compare CLI refuses a released descriptive-only subset even "
            "when it happens to contain 20 or more clusters",
            lambda: compared(items=descriptive_items),
            "descriptive-only", "inference_valid: false",
            "will not produce a bootstrap interval")
        with open(descriptive_sidecar, encoding="utf-8") as fh:
            descriptive_doc = json.load(fh)
        descriptive_doc["inference_valid"] = True
        _subset_writer.write_provenance(descriptive_sidecar, descriptive_doc)
        refuses_before_printing(
            "an edited inference declaration cannot reach an interval or "
            "ANY stdout; the sampler is replayed first",
            lambda: compared(items=descriptive_items),
            "replayed sampler", "Inference mode and selection are derived")
        descriptive_doc.pop("inference_valid")
        _subset_writer.write_provenance(descriptive_sidecar, descriptive_doc)
        refuses_before_printing(
            "deleting inference_valid is fail-closed before ANY stdout, not "
            "a default to inference-safe",
            lambda: compared(items=descriptive_items),
            "replayed sampler", "inference_valid")
        descriptive_doc["inference_valid"] = False
        _subset_writer.write_provenance(descriptive_sidecar, descriptive_doc)
        stashed_sidecar = descriptive_sidecar + ".stashed"
        os.replace(descriptive_sidecar, stashed_sidecar)
        refuses_before_printing(
            "deleting the sidecar from a named eval subset also withholds "
            "inference before ANY stdout",
            lambda: compared(items=descriptive_items),
            "no provenance sidecar", "cannot default")
        os.replace(stashed_sidecar, descriptive_sidecar)
        check("tiny positive exact p-values never render as the false zero "
              "0.0000",
              cli._format_p_value(2 ** -20) == "9.537e-07"
              and cli._format_p_value(0.03125) == "0.0312"
              and cli._format_p_value(0.0) == "0.0000")
        tiny_items = [f"proj/features/domain/t{n}.feature:{n}"
                      for n in range(20)]
        tiny_rows = [{"item_id": iid, "outcome": "passed", "n_files": 1,
                      "comparison_class": "fixed_model_scaffold"}
                     for iid in tiny_items]
        tiny_a = _fixture_run(os.path.join(d, "tiny-a.jsonl"), tiny_rows)
        tiny_b = _fixture_run(os.path.join(d, "tiny-b.jsonl"), tiny_rows)
        _fixture_sidecar(tiny_a, {iid: NON_VACUOUS_VERDICT
                                 for iid in tiny_items})
        _fixture_sidecar(tiny_b, {iid: "weaker" for iid in tiny_items})
        tiny_gold = _fixture_gold(os.path.join(d, "tiny-gold"), tiny_items)
        below_floor_items = [f"proj/features/domain/s{n}.feature:{n}"
                             for n in range(5)]
        below_floor_rows = [
            {"item_id": iid, "outcome": "passed", "n_files": 1,
             "comparison_class": "fixed_model_scaffold"}
            for iid in below_floor_items]
        below_a = _fixture_run(os.path.join(d, "below-a.jsonl"),
                               below_floor_rows)
        below_b = _fixture_run(os.path.join(d, "below-b.jsonl"),
                               below_floor_rows)
        below_gold = _fixture_gold(os.path.join(d, "below-gold"),
                                   below_floor_items)
        refuses_before_printing(
            "the compare CLI enforces the 20-cluster floor before one header "
            "line reaches stdout",
            lambda: compared(run=[below_a, below_b], gold_dir=below_gold),
            "at least 20", "got 5", "Descriptive")
        # ---------------------------------------- PC5: the qualifier PAIRS
        #
        # The two arms above are complete and publishable, so the comparison
        # runs.  Each case below changes ONE arm's qualifier and nothing else:
        # the vectors, the items, the engine and the gold tree are identical,
        # so what refuses is the completeness state and not a side effect.
        short_a = _fixture_run(os.path.join(d, "short-a.jsonl"),
                               rows_all_passing())
        short_b = _fixture_run(os.path.join(d, "short-b.jsonl"),
                               rows_all_passing())
        verdicts_a = {iid: NON_VACUOUS_VERDICT for iid in ITEMS[:7]}
        verdicts_a.update({iid: "weaker" for iid in ITEMS[7:]})
        verdicts_b = {iid: "weaker" for iid in ITEMS}
        _fixture_sidecar(short_a, verdicts_a, gold_rows_missing=3,
                         pairs_executed_gold=77)
        _fixture_sidecar(short_b, verdicts_b)
        short_gold = _fixture_gold(os.path.join(d, "short-gold"), list(ITEMS))
        refuses_before_printing(
            "PC5: FULL vs SHORT refuses -- an arm whose gold did not execute "
            "the whole pair set is not on the same scale as one that did",
            lambda: compared(run=[short_a, short_b], gold_dir=short_gold,
                             metric="non_vacuous_pass"),
            "arm A", "3 gold row(s) are missing", "not publication-ready")
        both_short_b = _fixture_run(os.path.join(d, "short-b2.jsonl"),
                                    rows_all_passing())
        _fixture_sidecar(both_short_b, verdicts_b, gold_rows_missing=3,
                         pairs_executed_gold=77)
        refuses_before_printing(
            "PC5: SHORT vs SHORT refuses too -- two arms short by the same "
            "count are still each measured over an unverified pair set",
            lambda: compared(run=[short_a, both_short_b],
                             gold_dir=short_gold, metric="non_vacuous_pass"),
            "arm A", "not publication-ready")
        degraded_a = _fixture_run(os.path.join(d, "degraded-a.jsonl"),
                                  rows_all_passing())
        _fixture_sidecar(degraded_a, verdicts_a,
                         gold_infrastructure_outcomes=2,
                         gold_infrastructure_pairs=[
                             {"item_id": ITEMS[0], "mutant_id": "m1",
                              "outcome": "container_error",
                              "gold_baseline_outcome": "passed"},
                             {"item_id": ITEMS[1], "mutant_id": "m2",
                              "outcome": "no_scenario_ran",
                              "gold_baseline_outcome": "passed"}],
                         gold_infrastructure_class="recorded_tolerance")
        refuses_before_printing(
            "PC5: a DEGRADED arm refuses -- gold that partly ended in the "
            "harness failing, with no recorded consent, is not a primary",
            lambda: compared(run=[degraded_a, short_b], gold_dir=short_gold,
                             metric="non_vacuous_pass"),
            "arm A", "2 infrastructure outcome(s)", "--allow-degraded-gold")
        consented_a = _fixture_run(os.path.join(d, "consented-a.jsonl"),
                                   rows_all_passing())
        _fixture_sidecar(consented_a, verdicts_a,
                         gold_infrastructure_outcomes=2,
                         gold_infrastructure_pairs=[
                             {"item_id": ITEMS[0], "mutant_id": "m1",
                              "outcome": "container_error",
                              "gold_baseline_outcome": "passed"},
                             {"item_id": ITEMS[1], "mutant_id": "m2",
                              "outcome": "no_scenario_ran",
                              "gold_baseline_outcome": "passed"}],
                         gold_infrastructure_class="recorded_tolerance",
                         allow_degraded_gold=True)
        consented = compared(run=[consented_a, short_b], gold_dir=short_gold,
                             metric="non_vacuous_pass")
        # The CONTROL, and it is what makes the three refusals above findings
        # rather than a blanket ban: ruling 2.6's tolerance really does admit
        # the number, once the consent AND the per-item disclosure are on the
        # summary.  Without this check, deleting the tolerance clause would
        # leave every check above green.
        check("PC5: ...and the ruling-2.6 CONTROL passes: the same degraded "
              "arm compares once the explicit consent and the per-item "
              "disclosure travel with it",
              "b (A reference-kill-complete, B did not) = 7" in consented,
              consented)
        # PC2, at the surface that consumes it: consent to a SHORT gold set is
        # not consent to a DEGRADED one, in either direction.
        incomplete_a = _fixture_run(os.path.join(d, "incomplete-a.jsonl"),
                                    rows_all_passing())
        _fixture_sidecar(incomplete_a, verdicts_a, require_complete=False,
                         completeness_checked=False)
        refuses_before_printing(
            "PC2: `--allow-incomplete` never implies `--allow-degraded-gold` "
            "-- an explicitly labelled sensitivity arm is still refused a "
            "paired primary",
            lambda: compared(run=[incomplete_a, short_b],
                             gold_dir=short_gold, metric="non_vacuous_pass"),
            "arm A", "sensitivity analysis, not a primary")

        # -------------------------- PC5, the RENDER-TIME half of item 6
        #
        # The refusals above are `compare`'s.  This is `report`'s, and it is
        # the surface F11 was actually about: the headline printed without the
        # qualifier its own evidence layer recorded.  Driven through the real
        # `report()` so deleting the withhold branch reddens a named check --
        # the R3 review recorded exactly this defect class (a correct property
        # with no red-on-delete witness) and it must not recur on R4's own
        # controlling mechanism.
        withheld_run = _fixture_run(os.path.join(d, "withheld.jsonl"),
                                    rows_all_passing())
        _fixture_sidecar(withheld_run, verdicts_a, gold_rows_missing=3,
                         pairs_executed_gold=77)
        buf = io.StringIO()
        with redirect_stdout(buf):
            pinned_report([withheld_run])
        withheld_text = buf.getvalue()
        check("PC5: `report` WITHHOLDS the primary when the qualifier says it "
              "is not publishable, and says which condition withheld it",
              "non_vacuous_pass_at_1    -        (WITHHELD:" in withheld_text
              and "3 gold row(s) are missing" in withheld_text
              and "= 28.0%  <- the publishable one" not in withheld_text,
              withheld_text)
        check("PC5: ...and the arithmetic is not destroyed -- the same number "
              "is printed beside it, labelled a sensitivity value over the "
              "gold pairs that DID execute",
              "sensitivity value, NOT a primary: 7/25 = 28.0% over 77 "
              "executed gold pair(s) of 80 expected" in withheld_text,
              withheld_text)
        ready_run = _fixture_run(os.path.join(d, "ready.jsonl"),
                                 rows_all_passing())
        _fixture_sidecar(ready_run, verdicts_a)
        buf = io.StringIO()
        with redirect_stdout(buf):
            pinned_report([ready_run])
        check("PC5: ...and the CONTROL renders exactly as it always did -- a "
              "publication-ready run is untouched by any of this",
              "<- the publishable one" in buf.getvalue()
              and "WITHHELD" not in buf.getvalue(), buf.getvalue())

        population_missing = "proj/features/domain/missing.feature:999"
        population_scope = fixture_population_scope(
            ready_run, [population_missing])
        buf = io.StringIO()
        with redirect_stdout(buf):
            population_report = _report_impl(
                [ready_run], validated_population_scopes=[population_scope])
        population_text = buf.getvalue()
        population_summary = population_report["ready"]
        check("an incomplete report cell exposes its exact population gap and "
              "withholds pass_at_1 without classifying the missing item",
              population_summary["population"]["status"] == "incomplete"
              and population_summary["population"]["planned_n"] == 26
              and population_summary["population"]["observed_n"] == 25
              and population_summary["population"]["missing_planned_ids"]
              == [population_missing]
              and population_summary["pass_rate"] is None
              and "POPULATION INCOMPLETE" in population_text
              and population_missing in population_text
              and "pass_at_1                -        (WITHHELD:" in
                  population_text, population_text)
        check("population incompleteness independently withholds "
              "non_vacuous_pass_at_1 and every observed-only test-quality "
              "aggregate",
              population_summary["test_quality"][
                  "non_vacuous_pass_at_1"] is None
              and population_summary["test_quality"]["pass_at_1"] is None
              and population_summary["test_quality"]["recall_macro"] is None
              and population_summary["test_quality"][
                  "hard_recall_macro"] is None
              and population_summary["test_quality"][
                  "full_recall_macro"] is None
              and population_summary["test_quality"]["population_withheld"]
              and "non_vacuous_pass_at_1    -        (WITHHELD:" in
                  population_text
              and "sensitivity value, NOT a primary" not in population_text,
              population_text)

        # Benchmark 2.0 (BENCHMARK_V2_SPEC.md section 6): two passes leave
        # every count, the non-vacuous one's test-quality evidence included.
        v2_run = _fixture_run(
            os.path.join(d, "v2-ready.jsonl"),
            [dict(row, protocol_version=9001) for row in rows_all_passing()])
        v2_sidecar = _fixture_sidecar(v2_run, verdicts_a)
        buf = io.StringIO()
        with redirect_stdout(buf):
            v2_report = with_v2_population(
                os.path.join(d, "benchmark_2.0_population.yml"),
                [ITEMS[0], ITEMS[10]], lambda: pinned_report([v2_run]))
        v2_text = buf.getvalue()
        v2_summary = v2_report["v2-ready"]
        check("a 2.0 report counts its population without the excluded "
              "instances and recomputes test quality without them",
              v2_summary["population"]["status"] == "complete"
              and v2_summary["population"]["planned_n"] == 23
              and v2_summary["population"]["observed_n"] == 23
              and v2_summary["population"]["ladder_n"] == 23
              and v2_summary["population"]["population_exclusions"]["count"]
              == 2
              and v2_summary["n"] == 23 and v2_summary["passed"] == 23
              and v2_summary["test_quality"]["non_vacuous_passes"] == 6
              and v2_summary["test_quality"]["n"] == 23,
              str(v2_summary))
        check("...and prints the excluded count and instances",
              "2.0 excluded         2 instance(s) outside benchmark 2.0's "
              "population" in v2_text
              and ITEMS[0] in v2_text and ITEMS[10] in v2_text, v2_text)
        v2_nv_path = os.path.join(d, "v2-non_vacuous.json")
        with redirect_stdout(io.StringIO()):
            with_v2_population(
                os.path.join(d, "benchmark_2.0_population.yml"),
                [ITEMS[0], ITEMS[10]],
                lambda: cli.main(["report", "--run", v2_run,
                                  "--test-quality", v2_sidecar,
                                  "--non-vacuous-out", v2_nv_path]))
        with open(v2_nv_path, encoding="utf-8") as fh:
            v2_block = json.load(fh)
        check("report --non-vacuous-out writes the block over the 2.0 "
              "population the printed report counts, and names who left it",
              v2_block["n"] == v2_summary["test_quality"]["n"] == 23
              and v2_block["non_vacuous_passes"]
              == v2_summary["test_quality"]["non_vacuous_passes"] == 6
              and v2_block["non_vacuous_pass_at_1"]
              == v2_summary["test_quality"]["non_vacuous_pass_at_1"]
              and v2_block["population_exclusions"]["count"] == 2,
              str(v2_block))
        v2_arms = []
        for name, verdicts in (("v2-a", a_verdicts), ("v2-b", b_verdicts)):
            arm = _fixture_run(
                os.path.join(d, name + ".jsonl"),
                [dict(row, protocol_version=9001)
                 for row in rows_all_passing()])
            _fixture_sidecar(arm, verdicts, population_id="coreshop-v1")
            v2_arms.append(arm)
        v2_compared = with_v2_population(
            os.path.join(d, "benchmark_2.0_population.yml"),
            [ITEMS[0], ITEMS[10]],
            lambda: compared(run=v2_arms, metric="non_vacuous_pass"))
        check("compare pairs two 2.0 arms over the 2.0 population and names "
              "the instances it left out",
              "items   : 23 " in v2_compared
              and "2.0 excluded: 2 instance(s) outside benchmark 2.0's "
                  "population" in v2_compared
              and ITEMS[0] in v2_compared and ITEMS[10] in v2_compared
              and "reference-kill-complete 6/23" in v2_compared
              and "reference-kill-complete 0/23" in v2_compared, v2_compared)

        unknown_rows = rows_all_passing()
        unknown_id = ITEMS[-1]
        unknown_rows[-1] = {
            **unknown_rows[-1], "outcome": "substrate_violation",
            "produced_files": [{"file_path": "tests/test_unknown.py",
                                "code": "def test_unknown(): pass\n"}],
        }
        unknown_run = _fixture_run(
            os.path.join(d, "unknown-population.jsonl"), unknown_rows)
        unknown_verdicts = dict(verdicts_a)
        unknown_verdicts.pop(unknown_id)
        _fixture_sidecar(unknown_run, unknown_verdicts)
        with redirect_stdout(io.StringIO()):
            unknown_report = pinned_report([unknown_run])
        unknown_summary = unknown_report["unknown-population"]
        check("a complete population with an issue #202 unknown present row "
              "withholds only the functional pass rate through both report "
              "machine views",
              unknown_summary["population"]["status"] == "complete"
              and unknown_summary["pass_rate"] is None
              and unknown_summary["test_quality"]["pass_at_1"] is None
              and unknown_summary["test_quality"][
                  "non_vacuous_pass_at_1"] is not None
              and not unknown_summary["test_quality"].get(
                  "population_withheld"),
              str(unknown_summary))

        # ---------------------------------------- PC6: the three real verbs
        two_project_rows = [
            {"item_id": "alpha/features/domain/a.feature:1",
             "outcome": "passed", "n_files": 1},
            {"item_id": "beta/features/domain/b.feature:2",
             "outcome": "passed", "n_files": 1},
        ]
        pooled = _fixture_run(os.path.join(d, "pooled.jsonl"),
                              two_project_rows)
        pooled_gold = _fixture_gold(
            os.path.join(d, "pooled-gold"),
            [r["item_id"] for r in two_project_rows])
        refuses_before_printing(
            "PC6: the real `report` entry point refuses pooled multi-project "
            "input before stdout",
            lambda: report([pooled]), "span 2 projects", "--group-by project")
        from . import results as RS
        refuses_before_printing(
            "PC6: the real `results` entry point refuses it too -- the "
            "canonical table has no --group-by to partition into",
            lambda: RS.results(pooled, artifacts=d), "span 2 projects")
        refuses_before_printing(
            "PC6: the real `compare` entry point refuses it before "
            "constructing its paired denominator",
            lambda: compared(run=[pooled, pooled], gold_dir=pooled_gold),
            "span 2 projects")

        tiny_output = compared(run=[tiny_a, tiny_b], gold_dir=tiny_gold,
                               metric="non_vacuous_pass")
        check("the end-to-end compare renderer switches a tiny positive exact "
              "p-value to scientific notation",
              "discordant = 20 of 20" in tiny_output
              and "p = 1.907e-06" in tiny_output
              and "p = 0.0000" not in tiny_output, tiny_output)
        check("the functional rendering is untouched: no metric line, no "
              "engine line, the same verb",
              "metric  :" not in functional and "engine  :" not in functional
              and "non-vacuous" not in functional, functional)

        refuses("a missing sidecar on ONE side refuses the comparison rather "
                "than quietly comparing functional pass",
                lambda: compared(metric="non_vacuous_pass",
                                 run=[run_a, bare]),
                "REFUSED", "not KNOWN")
        py = _fixture_run(os.path.join(d, "py.jsonl"), rows_all_passing())
        _fixture_sidecar(py, b_verdicts, engine="r2t-mutate-py")
        refuses("two different mutation ENGINES are refused: a PHP operator "
                "set and a Python one are not one non-vacuity scale",
                lambda: compared(metric="non_vacuous_pass", run=[run_a, py]),
                "ONE mutation engine", "r2t-mutate-py")
        unlabelled = _fixture_run(os.path.join(d, "un.jsonl"),
                                  rows_all_passing())
        _fixture_sidecar(unlabelled, b_verdicts, engine=None)
        refuses("an engine that is not named at all is refused, not assumed",
                lambda: compared(metric="non_vacuous_pass",
                                 run=[run_a, unlabelled]),
                "not fully identified")
        empty = _fixture_run(os.path.join(d, "empty.jsonl"),
                             rows_all_passing())
        _fixture_sidecar(empty, b_verdicts, engine="")
        refuses("...and so is one named the EMPTY STRING -- falsy is unnamed, "
                "and `is None` was not the test",
                lambda: compared(metric="non_vacuous_pass",
                                 run=[run_a, empty]), "not fully identified")
        # ENGINE IDENTITY IS THE PAIR.  `mutation.py` hashes engine_version
        # into every mutant id and `test_quality.run_slice` refuses when either
        # half disagrees with the manifest, so a version bump is a different
        # operator population by this project's own rule -- and the header line
        # says "both sides" about a pair, which makes checking only the name a
        # printed assurance about something unverified.
        skewed = _fixture_run(os.path.join(d, "skew.jsonl"),
                              rows_all_passing())
        _fixture_sidecar(skewed, b_verdicts, version="2.0")
        refuses("the same engine at a different VERSION is refused: one "
                "version's operators are not another's",
                lambda: compared(metric="non_vacuous_pass",
                                 run=[run_a, skewed]),
                "ONE mutation engine", "A=r2t-mutate 1.0", "B=r2t-mutate 2.0",
                "VERSION is half of that identity")
        unversioned = _fixture_run(os.path.join(d, "nover.jsonl"),
                                   rows_all_passing())
        _fixture_sidecar(unversioned, b_verdicts, version=None)
        refuses("an engine with no version at all is refused too -- two Nones "
                "are not evidence of one population",
                lambda: compared(metric="non_vacuous_pass",
                                 run=[run_a, unversioned]),
                "(unversioned)", "not fully identified")
        population_skew = _fixture_run(
            os.path.join(d, "population-skew.jsonl"), rows_all_passing())
        _fixture_sidecar(population_skew, b_verdicts,
                         population_id="python-docx-v1")
        refuses("the same engine@version with different population ids is "
                "refused -- generations deliberately do not bump the engine",
                lambda: compared(metric="non_vacuous_pass",
                                 run=[run_a, population_skew]),
                "ONE non-empty population_id", "coreshop-v1",
                "python-docx-v1", "Engine name and version are not enough")
        population_missing = _fixture_run(
            os.path.join(d, "population-missing.jsonl"), rows_all_passing())
        _fixture_sidecar(population_missing, b_verdicts, population_id=None)
        refuses("a missing population id is unknown, not inherited from the "
                "other arm",
                lambda: compared(metric="non_vacuous_pass",
                                 run=[run_a, population_missing]),
                "ONE non-empty population_id", "B=None")
        hard_a = _fixture_run(os.path.join(d, "hard-a.jsonl"),
                              rows_all_passing())
        hard_b = _fixture_run(os.path.join(d, "hard-b.jsonl"),
                              rows_all_passing())
        hard_c = _fixture_run(os.path.join(d, "hard-c.jsonl"),
                              rows_all_passing())
        full_gold_a = _fixture_run(
            os.path.join(d, "full-gold-a.jsonl"), rows_all_passing())
        _fixture_sidecar(
            full_gold_a, a_verdicts, verdict_basis="full_gold",
            hard_subset_digest=None, population_id="coreshop-v1")
        _fixture_sidecar(hard_a, a_verdicts, verdict_basis="hard_subset",
                         hard_subset_digest="1" * 64,
                         hard_recall_macro=0.9, full_recall_macro=0.95)
        _fixture_sidecar(hard_b, b_verdicts, verdict_basis="hard_subset",
                         hard_subset_digest="2" * 64,
                         hard_recall_macro=0.8, full_recall_macro=0.9)
        _fixture_sidecar(hard_c, b_verdicts, verdict_basis="hard_subset",
                         hard_subset_digest="1" * 64,
                         hard_recall_macro=0.8, full_recall_macro=0.9)
        refuses_before_printing(
            "a current full-gold sensitivity arm cannot be paired with an "
            "assertion-hard arm even when engine and population match",
            lambda: compared(metric="non_vacuous_pass",
                             run=[full_gold_a, hard_a]),
            "not publication-ready", "verdict_basis is 'full_gold'",
            "sensitivity result after C4")
        refuses_before_printing(
            "two assertion-hard arms bound to different artifacts cannot be "
            "paired",
            lambda: compared(metric="non_vacuous_pass",
                             run=[hard_a, hard_b]),
            "one non-empty hard-subset artifact digest", "1" * 64,
            "2" * 64)
        hard_output = compared(metric="non_vacuous_pass",
                               run=[hard_a, hard_c])
        check("matching assertion-hard basis and artifact digest compare",
              "reference-kill-complete 7/25 = 0.280" in hard_output
              and "reference-kill-complete 1/25 = 0.040" in hard_output,
              hard_output)
        check("...and the header's `both sides` claim is therefore about the "
              "PAIR that was checked, not the name alone",
              "engine  : r2t-mutate 1.0 (both sides, checked as a (name, "
              "version) pair" in nv, nv)

        # ------------------------------ a refusal that arrives before a table
        # A malformed stamp is the one state in which the disclosure is known
        # to be untrustworthy, so it is also the one in which a captured table
        # must not look finished.  `> table.txt` puts the refusal on stderr.
        hand_edited = rows_all_passing()
        hand_edited[2] = dict(hand_edited[2], draw={
            "n": 2, "reason": "rerun", "prior_outcomes": ["harness_error"]})
        bad = _fixture_run(os.path.join(d, "bad.jsonl"), hand_edited)
        _fixture_sidecar(bad, a_verdicts)
        refuses_before_printing(
            "`report` refuses a malformed stamp with NOTHING on stdout -- a "
            "redirected table would otherwise be complete-looking and silently "
            "missing the disclosure it was refusing about",
            lambda: report([bad]), "REFUSED", "benchmark_infrastructure")
        refuses_before_printing(
            "`compare` does the same: not one header line lands before the "
            "refusal",
            lambda: compared(run=[bad, run_b]), "REFUSED",
            "benchmark_infrastructure")
        refuses_before_printing(
            "...in the non-vacuous mode too, where the header carries the "
            "metric and the engine",
            lambda: compared(metric="non_vacuous_pass", run=[bad, run_b]),
            "REFUSED")

        # ------------------------- the campaign attestation, at READ time
        # `write_merged` has always left a `rows_digest` beside a merge so a
        # reader can check the pair; until this branch no reader did.  A
        # writer-side guard alone would protect the archive from ONE command
        # and leave a hand edit, a truncated copy or a half-finished merge
        # publishing clean under provenance describing other bytes.
        edited = _fixture_run(os.path.join(d, "edited.jsonl"),
                              rows_all_passing())
        with open(edited + draws.CAMPAIGN_SIDECAR_SUFFIX, "w",
                  encoding="utf-8") as fh:
            json.dump({"campaign_digest": "deadbeefdeadbeef", "n": 25,
                       "rows_digest": draws._rows_digest(edited)}, fh)
        buf = io.StringIO()
        with redirect_stdout(buf):
            report([edited])
        check("a merged run whose sidecar still describes it reports exactly "
              "as before -- the check is silent when the pair holds, which is "
              "every archived run",
              "pass_at_1" in buf.getvalue()
              and "REFUSED" not in buf.getvalue(), buf.getvalue()[:300])
        # Edited in place, same items and the same outcomes: the item-set and
        # comparison-class checks stay green, so what refuses below can only
        # be the digest.
        tampered = rows_all_passing()
        tampered[4] = dict(tampered[4], n_files=2)
        _fixture_run(edited, tampered)
        refuses_before_printing(
            "...and refuses, with NOTHING printed, once the rows are not the "
            "rows the campaign attested to",
            lambda: report([edited]), "REFUSED", "attests that",
            "rows being published")
        refuses_before_printing(
            "`compare` checks the same pair on both arms, also before its "
            "header", lambda: compared(run=[run_a, edited]), "REFUSED",
            "attests that")

        # ------------------------------------------------- repeat draws
        check("a run of first draws says nothing about draws -- every "
              "archived row is one, and a line on every page trains readers "
              "to skip it",
              "REPEAT DRAWS" not in functional, functional)
        redrawn = rows_all_passing()
        redrawn[3] = dict(redrawn[3], draw={
            "n": 2, "reason": "candidate_caused",
            "prior_outcomes": ["harness_error"], "evidence": []})
        run_c = _fixture_run(os.path.join(d, "c.jsonl"), redrawn)
        _fixture_sidecar(run_c, a_verdicts)
        text = compared(run=[run_c, run_b])
        check("a compared arm holding a repeat draw SAYS SO, with the count, "
              "the reason class and the item",
              "A REPEAT DRAWS: 1 of 25 item(s)" in text
              and "candidate_caused" in text
              and ITEMS[3] in text and "INCLUDED in every number" in text,
              text)
        buf = io.StringIO()
        with redirect_stdout(buf):
            report([run_c])
        check("`report` discloses it too, out of the same summary",
              "REPEAT DRAWS: 1 of 25 item(s)" in buf.getvalue()
              and "draw 2  candidate_caused" in buf.getvalue(),
              buf.getvalue())
        buf = io.StringIO()
        with redirect_stdout(buf):
            report([run_a])
        check("...and stays silent on a run with none",
              "REPEAT DRAWS" not in buf.getvalue())
        # A PINNED SUBSET IS THE TABLE.  Counting the file instead prints a
        # denominator this table does not have and calls an item it does not
        # contain "INCLUDED in every number above".
        pinned = os.path.join(d, "items.jsonl")
        with open(pinned, "w", encoding="utf-8") as fh:
            for iid in ITEMS:
                if iid != ITEMS[3]:
                    fh.write(json.dumps({"item_id": iid}) + "\n")
        text = compared(run=[run_c, run_b], items=pinned)
        check("with the re-drawn item pinned OUT, the comparison neither "
              "counts it nor names it -- 24 items, no disclosure",
              "items   : 24" in text and "REPEAT DRAWS" not in text
              and ITEMS[3] not in text, text)
        with open(pinned, "w", encoding="utf-8") as fh:
            for iid in ITEMS[:20]:
                fh.write(json.dumps({"item_id": iid}) + "\n")
        text = compared(run=[run_c, run_b], items=pinned)
        check("...and pinned IN, the denominator is the table's own",
              "A REPEAT DRAWS: 1 of 20 item(s)" in text and ITEMS[3] in text,
              text)
        # THE SPLIT, through the real print path (review finding 14; plan
        # section 3 PR R5 items 2-4).  The mixed fixture is Cell 4's exact
        # shape scaled to this suite's 25 items: one candidate_caused stamp
        # and two benchmark_infrastructure stamps.  Only the candidate redraw
        # may be described as not a first candidate observation; the two
        # restorations render as their own block, and no line collapses the
        # three into one count.
        bi_stamp = {"n": 2, "reason": "benchmark_infrastructure",
                    "prior_outcomes": ["harness_error"], "evidence": []}
        mixed = rows_all_passing()
        mixed[3] = dict(mixed[3], draw={
            "n": 2, "reason": "candidate_caused",
            "prior_outcomes": ["harness_error"], "evidence": []})
        mixed[5] = dict(mixed[5], draw=dict(bi_stamp))
        mixed[7] = dict(mixed[7], draw=dict(bi_stamp))
        run_m = _fixture_run(os.path.join(d, "m.jsonl"), mixed)
        _fixture_sidecar(run_m, a_verdicts)
        buf = io.StringIO()
        with redirect_stdout(buf):
            report([run_m])
        out = buf.getvalue()
        check("DD1: `report` prints the SPLIT disclosure for the Cell 4 "
              "shape -- one candidate redraw, two infrastructure "
              "restorations, never one collapsed count",
              "REPEAT DRAWS: 1 of 25 item(s)" in out
              and "INFRASTRUCTURE RESTORATIONS: 2 of 25 item(s)" in out
              and "3 of 10" not in out, out)
        check("DD1: ...and the restoration block states the discarded "
              "preflight made no model call and the retained row is the "
              "FIRST candidate observation",
              "made no model call" in out
              and "FIRST candidate observation" in out, out)
        infra_only = rows_all_passing()
        infra_only[4] = dict(infra_only[4], draw=dict(bi_stamp))
        run_i = _fixture_run(os.path.join(d, "i.jsonl"), infra_only)
        _fixture_sidecar(run_i, a_verdicts)
        buf = io.StringIO()
        with redirect_stdout(buf):
            report([run_i])
        out = buf.getvalue()
        check("DD2: infrastructure-only input prints NO candidate-redraw "
              "headline through `report` -- the restoration block renders "
              "alone",
              "REPEAT DRAWS" not in out and "NOT a first" not in out
              and "INFRASTRUCTURE RESTORATIONS: 1 of 25 item(s)" in out, out)
        # DD7's reporting half (finding 23; plan section 3 PR R5 item 7):
        # after the Cell 4 stamp, the archived run's preserved sidecar is
        # legacy evidence with no run-relative binding, and `report` REFUSES
        # it until section 4 step J2 regenerates the legacy-consistency
        # report and `test-quality-bind` produces the wrapper.  The refusal
        # is the gate working; the stamp script now says so instead of
        # prescribing a dead read-back.
        run_u = _fixture_run(os.path.join(d, "u.jsonl"), rows_all_passing())
        with open(os.path.join(d, "u.test_quality.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"engine": "r2t-mutate", "engine_version": "1.0",
                       "recall_macro": 0.9}, fh)
        refuses_before_printing(
            "DD7: an archived, unbound test-quality sidecar refuses "
            "`report` by name until legacy rebinding produces a wrapper -- "
            "reporting comes only after regeneration and rebinding",
            lambda: report([run_u]),
            "REFUSED", "test-quality-binding", "cannot publish")

        # ------------------------------------- publication-only uniqueness
        duplicate_rows = rows_all_passing() + [dict(rows_all_passing()[0],
                                                     outcome="failed")]
        duplicate = _fixture_run(os.path.join(d, "duplicate.jsonl"),
                                 duplicate_rows)
        refuses_before_printing(
            "`report` refuses duplicate item ids before one inflated row can "
            "reach stdout", lambda: report([duplicate]),
            "duplicate item_id", ITEMS[0])
        refuses_before_printing(
            "`compare` checks the uncollapsed file too, before its "
            "last-row-wins operational reader can hide the retry",
            lambda: compared(run=[duplicate, run_b]),
            "duplicate item_id", ITEMS[0])
        from . import metrics as M
        check("the retry reader itself remains last-row-wins; only publication "
              "entry points gained the uniqueness gate",
              len(M.read_runs(duplicate)) == 25
              and M.read_runs(duplicate)[ITEMS[0]]["outcome"] == "failed")

        for label, bad_id in (("a missing", None), ("an empty", ""),
                              ("a whitespace-only", "   "),
                              ("a non-string", 17)):
            row = {"outcome": "passed", "n_files": 1}
            if bad_id is not None:
                row["item_id"] = bad_id
            refuses(
                f"the shared publication gate rejects {label} item_id",
                lambda row=row: check_unique_item_ids([row], "bad.jsonl"),
                "non-empty string", "cannot define a project or denominator")

        invalid_rows = rows_all_passing()
        invalid_rows[0] = {k: v for k, v in invalid_rows[0].items()
                           if k != "item_id"}
        invalid = _fixture_run(os.path.join(d, "invalid-id.jsonl"),
                               invalid_rows)
        refuses_before_printing(
            "`report` applies the shared malformed-id gate before a blank "
            "project can reach stdout", lambda: report([invalid]),
            "invalid item_id", "non-empty string")
        refuses_before_printing(
            "`compare` applies that same gate before constructing its paired "
            "denominator", lambda: compared(run=[invalid, run_b]),
            "invalid item_id", "non-empty string")

        left = os.path.join(d, "left")
        right = os.path.join(d, "right")
        os.makedirs(left)
        os.makedirs(right)
        same_a = _fixture_run(os.path.join(left, "same.jsonl"),
                              rows_all_passing())
        same_b = _fixture_run(os.path.join(right, "same.jsonl"),
                              rows_all_passing())
        refuses_before_printing(
            "two paths with the same run basename refuse instead of silently "
            "overwriting one report column", lambda: report([same_a, same_b]),
            "duplicate run basename", "same")
        refuses_before_printing(
            "grouping still refuses the same basename twice INSIDE one "
            "project", lambda: report([same_a, same_b], group_by="project"),
            "duplicate project/run", "proj/same")

        # --------------------------------- why a priced cost is an upper bound
        #
        # A missing cache split is one reason among several.  `deepseek-flash`
        # is priced at the table's peak rates (`cost_upper_bound`) even when
        # its reported split is billed, and that row must not be described as
        # one that reported no split.
        try:
            from ..confined import pricing as _pricing
        except ImportError:
            print("  [SKIP] upper-bound reasons: the price table is the agent "
                  "component's, and this checkout has none")
        else:
            price_table = _pricing.load_table()

            def stats_row(n, model, **usage):
                return {"item_id": f"proj/features/cost.feature:{n}",
                        "outcome": "passed",
                        "metadata": {"agent_stats": {
                            "model": model, "prompt_tokens": 100_000,
                            "completion_tokens": 2_000, **usage}}}

            def priced(rows, table=price_table):
                cs = cost_summary(rows, table=table)
                return cs, "\n".join(format_cost_summary(cs))

            flash = price_table["models"]["deepseek-flash"]
            split_row = stats_row(1, "deepseek-flash",
                                  prompt_cache_hit_tokens=90_000,
                                  prompt_cache_miss_tokens=10_000)
            split_cs, split_text = priced([split_row])
            billed_split = (90_000 * flash["cached_input_per_mtok"]
                            + 10_000 * flash["input_per_mtok"]
                            + 2_000 * flash["output_per_mtok"]) / 1e6
            check("a peak-rate deepseek-flash row keeps its billed cache "
                  "split and is labelled by the table's bounding rates, not "
                  "as a row that reported no split",
                  abs(split_cs["cost_usd_total"] - billed_split) < 1e-9
                  and split_cs["upper_bound_items"] == 1
                  and split_cs.get("upper_bound_reasons") == {"table_rates": 1}
                  and "   1 item(s) are priced at the bounding rates of a "
                      "table entry marked cost_upper_bound" in split_text
                  and "no cache split" not in split_text,
                  split_text)

            bare_cs, bare_text = priced([stats_row(2, "deepseek-v4-pro")])
            check("a row with no split, priced from an exact table entry, "
                  "keeps the missing-split wording and nothing else",
                  bare_cs.get("upper_bound_reasons") == {"no_cache_split": 1}
                  and "   1 item(s) reported no cache split, so every prompt "
                      "token is billed at the uncached rate" in bare_text
                  and "cost_upper_bound" not in bare_text,
                  bare_text)

            mixed_cs, mixed_text = priced([
                split_row, stats_row(2, "deepseek-v4-pro"),
                stats_row(3, "deepseek-flash")])
            check("a mixed run counts each reason over its own items: 3 "
                  "bounded, 2 with no split, 2 at bounding table rates",
                  mixed_cs["upper_bound_items"] == 3
                  and mixed_cs["upper_bound"] is True
                  and mixed_cs.get("upper_bound_reasons")
                      == {"no_cache_split": 2, "table_rates": 2}
                  and "UPPER BOUND       3 item(s) are priced as upper "
                      "bounds" in mixed_text
                  and "   2 item(s) reported no cache split" in mixed_text
                  and "   2 item(s) are priced at the bounding rates"
                      in mixed_text,
                  mixed_text)

            calls = [{"prompt_tokens": 1_000, "completion_tokens": 10},
                     {"prompt_tokens": 300_000, "completion_tokens": 10}]
            per_request, _ = priced([stats_row(
                4, "gpt-6-luna", per_call_tokens=calls, llm_calls=2)])
            whole_total, _ = priced([stats_row(5, "gpt-6-luna")])
            pro = price_table["models"]["deepseek-v4-pro"]
            no_cached_rate = dict(price_table, models=dict(
                price_table["models"],
                **{"deepseek-v4-pro": dict(pro, cached_input_per_mtok=None)}))
            hits_uncached, _ = priced(
                [stats_row(6, "deepseek-v4-pro",
                           prompt_cache_hit_tokens=90_000,
                           prompt_cache_miss_tokens=10_000)],
                table=no_cached_rate)
            check("an attempt priced request by request is read through its "
                  "requests' bases, a total without per-request usage and "
                  "hits with no cached rate are each named",
                  per_request.get("upper_bound_reasons")
                  == {"no_cache_split": 1, "table_rates": 1}
                  and whole_total.get("upper_bound_reasons")
                  == {"no_cache_split": 1, "no_per_request_usage": 1,
                      "table_rates": 1}
                  and hits_uncached.get("upper_bound_reasons")
                  == {"no_cached_rate_in_table": 1},
                  str([per_request.get("upper_bound_reasons"),
                       whole_total.get("upper_bound_reasons"),
                       hits_uncached.get("upper_bound_reasons")]))

        # ---------- a macro arm no agent stamped, without the agent component
        #
        # `_system_name` reads `adapter` too, so `gold` and `submitted:<name>`
        # rows name a "system" although no agent arm stamped them.  The
        # benchmark-only mirror ships neither agent module the macro asks a
        # named system for; there, such rows must get the answer this checkout
        # gives them (no native knob, so the unstamped macro is withheld), and
        # only a row carrying an agent field may be refused for the absence.
        import sys
        from contextlib import contextmanager

        @contextmanager
        def agent_component_absent():
            root = __package__.rsplit(".", 1)[0]
            names = (f"{root}.agents.protocol",
                     f"{root}.confined.result_ledger_v2")
            saved = {name: sys.modules.get(name) for name in names}
            for name in names:
                sys.modules[name] = None    # import raises ModuleNotFoundError
            try:
                yield
            finally:
                for name, module in saved.items():
                    if module is None:
                        sys.modules.pop(name, None)
                    else:
                        sys.modules[name] = module

        def two_project_arm(**row):
            return {project: {"arm": {"rows": [dict(
                row, item_id=f"{project}/features/a.feature:1",
                outcome="passed")]}} for project in ("alpha", "beta")}

        for adapter in ("gold", "submitted:external-system"):
            shipped = _validate_macro_identities(
                two_project_arm(adapter=adapter))
            try:
                with agent_component_absent():
                    absent = _validate_macro_identities(
                        two_project_arm(adapter=adapter))
            except ReportRefusal as e:
                absent = str(e)
            check(f"adapter {adapter!r} rows without the agent component get "
                  "the same withheld macro, not a refusal over agent_system",
                  absent == shipped and "agent_system" in shipped["arm"],
                  f"shipped={shipped!r} absent={absent!r}")
        with agent_component_absent():
            refuses("...while a row that carries agent_system is still "
                    "refused by name without the agent component",
                    lambda: _validate_macro_identities(two_project_arm(
                        adapter="openhands", agent_system="openhands")),
                    "carries agent_system", "r2t.agents.protocol")
            refuses("...and one that carries only native_budget is refused "
                    "naming native_budget",
                    lambda: _validate_macro_identities(two_project_arm(
                        adapter="submitted:external-system",
                        native_budget={"max_iterations": 100})),
                    "carries native_budget", "r2t.agents.protocol")

        # -------------------------------- partition before every aggregation
        #
        # Every arm below is an AGENT arm: a cross-project macro is keyed on
        # `adapter`/`agent_system` (`MACRO_REQUIRED_SYSTEM_FIELDS`), and the
        # native-knob table and budget key a named system owes are the agent
        # component's, so a checkout without it refuses the whole section by
        # name rather than publishing an unauthenticated headline.
        try:
            from ..agents import protocol as _P_macro       # noqa: F401
            from ..confined import result_ledger_v2 as _agent
        except ImportError:
            print("  [SKIP] the cross-project macro legs: every macro arm "
                  "names an agent system, and this checkout has no agent "
                  "component")
        else:
            macro_identity = {
                "adapter": "openhands",
                "agent_system": "openhands",
                "adapter_version": "openhands@1",
                "comparison_class": "fixed_model_scaffold",
                "model": "fixture-model",
                "setting": "cold_start",
                "condition": "c3",
                "coverage": True,
                "repeats": 1,
                "max_iterations": 100,
                "max_tokens": 64000,
                "temperature": 0.0,
                "trials": "unlimited",
                "sandboxed": True,
                "agent_timeout_seconds": 3600,
                "native_budget": {"max_iterations": 100},
            }
            mixed_base = [
                {"item_id": "alpha/features/domain/a.feature:1",
                 "outcome": "passed", "n_files": 1,
                 "produced_files": [
                     {"file_path": "features/a.feature", "code": "Feature: a"}],
                 "comparison_class": "fixed_model_scaffold"},
                {"item_id": "alpha/features/domain/b.feature:2",
                 "outcome": "failed", "n_files": 1,
                 "written_files": ["features/b.feature"],
                 "comparison_class": "fixed_model_scaffold"},
                {"item_id": "beta/features/domain/c.feature:3",
                 "outcome": "passed", "n_files": 1,
                 "produced_files": [
                     {"file_path": "features/c.feature", "code": "Feature: c"}],
                 "comparison_class": "product_system"},
            ]
            mixed_rows = [dict(macro_identity, **row) for row in mixed_base]
            mixed = _fixture_run(os.path.join(d, "mixed.jsonl"), mixed_rows)

            def capability_fixture(name, declarations):
                from ..data.release import MANIFEST_SCHEMA as _MANIFEST_SCHEMA
                path = os.path.join(d, name)
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({
                        "schema": _MANIFEST_SCHEMA,
                        "dataset_version": "fixture",
                        "projects": {
                            project: {
                                "capabilities": {
                                    "mutation": mutation,
                                    "coverage": False,
                                    "api_similarity": False,
                                },
                                "capability_notes": {
                                    **({"mutation": "fixture has no mutation"}
                                       if not mutation else {}),
                                    "coverage": "fixture does not report coverage",
                                    "api_similarity":
                                        "fixture does not report API similarity",
                                },
                                **({"mutation_engine": "r2t-mutate"}
                                   if mutation else {}),
                            }
                            for project, mutation in declarations.items()
                        },
                    }, fh, sort_keys=True)
                with open(path, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
                return path, digest

            functional_manifest, functional_manifest_sha = capability_fixture(
                "functional-capabilities.json", {"alpha": False, "beta": False})
            refuses_before_printing(
                "cross-project macro refuses mixed comparison classes before "
                "ANY eligible-set or project heading reaches stdout",
                lambda: _report_with_capability_fixture(
                    [mixed], group_by="project",
                    dataset_manifest_path=functional_manifest,
                    dataset_manifest_sha256=functional_manifest_sha),
                "cross-project headline", "comparison_class",
                "fixed_model_scaffold", "product_system")

            mixed_system_rows = []
            for row in mixed_rows:
                system = ("system-a" if project_of(row) == "alpha"
                          else "system-b")
                mixed_system_rows.append(dict(
                    row, comparison_class="fixed_model_scaffold",
                    agent_system=system, adapter=system,
                    adapter_version=f"{system}@1"))
            mixed_system = _fixture_run(
                os.path.join(d, "mixed-system.jsonl"), mixed_system_rows)
            refuses_before_printing(
                "cross-project macro also refuses two agent systems before "
                "stdout, even when their comparison class agrees",
                lambda: _report_with_capability_fixture(
                    [mixed_system], group_by="project",
                    dataset_manifest_path=functional_manifest,
                    dataset_manifest_sha256=functional_manifest_sha),
                "cross-project headline", "adapter", "system-a", "system-b")

            # Same per-project outcomes, now genuinely one system/configuration.
            # Project-specific protocol/profile stamps may differ; the system and
            # budget facts that the macro claims to hold fixed may not.
            aligned_rows = []
            for row in mixed_rows:
                aligned_rows.append({**row, **macro_identity})
            mixed = _fixture_run(os.path.join(d, "aligned.jsonl"), aligned_rows)
            buf = io.StringIO()
            with redirect_stdout(buf):
                grouped = pinned_capability_report(
                    [mixed], group_by="project",
                    dataset_manifest_path=functional_manifest,
                    dataset_manifest_sha256=functional_manifest_sha)
            grouped_text = buf.getvalue()
            check("--group-by project partitions BEFORE summarising: the returned "
                  "denominators are 2 and 1, never the pooled 3",
                  sorted((r["n"], r["passed"]) for r in grouped.values())
                  == [(1, 1), (2, 1)]
                  and not any(r["n"] == 3 for r in grouped.values()),
                  str(grouped))
            check("each project gets a COMPLETE functional report, including cost "
                  "and behaviour blocks",
                  grouped_text.count(": how far each item got") == 2
                  and grouped_text.count("system behaviour") == 2
                  and grouped_text.count("cost") >= 2
                  and grouped["alpha/aligned"]["test_quality"] is None
                  and grouped["beta/aligned"]["test_quality"] is None,
                  grouped_text)
            check("the explicit split puts both mutation-false projects only in "
                  "the functional table",
                  "FUNCTIONAL-PASS TABLE" in grouped_text
                  and "REFERENCE-EQUIVALENT ELIGIBLE-SET TABLE" in grouped_text
                  and "eligible set: 0 project(s)" in grouped_text
                  and "functional-pass-only: alpha, beta" in grouped_text
                  and "PROJECT alpha" in grouped_text
                  and "PROJECT beta" in grouped_text
                  and "no test-quality summary beside" not in grouped_text,
                  grouped_text)
            # PC7.  alpha passes 1 of 2 and beta 1 of 1: the equal-weight macro is
            # (0.5 + 1.0)/2 = 75.0%, and the POOLED rate over the same rows would
            # be 2/3 = 66.7% on a denominator of 3.  Both wrong answers are named
            # here rather than left to "not equal to the right one", because it is
            # the pooled number specifically that this estimand exists to refuse.
            check("PC7: `--group-by project` prints complete project blocks plus "
                  "the labelled equal-weight macro -- 75.0%, never the pooled "
                  "66.7%",
                  "pass_at_1 macro        75.0%" in grouped_text
                  and EQUAL_WEIGHT_MACRO_LABEL in grouped_text
                  and "66.7%" not in grouped_text
                  and "/3 " not in grouped_text
                  and grouped_text.count(": how far each item got") == 2,
                  grouped_text)
            v2_grouped_run = _fixture_run(
                os.path.join(d, "aligned-v2.jsonl"),
                [dict(row, protocol_version=9001) for row in aligned_rows])
            buf = io.StringIO()
            with redirect_stdout(buf):
                v2_grouped = with_v2_population(
                    os.path.join(d, "benchmark_2.0_population.yml"),
                    ["alpha/features/domain/b.feature:2"],
                    lambda: pinned_capability_report(
                        [v2_grouped_run], group_by="project",
                        dataset_manifest_path=functional_manifest,
                        dataset_manifest_sha256=functional_manifest_sha))
            v2_grouped_text = buf.getvalue()
            alpha_v2 = v2_grouped["alpha/aligned-v2"]["population"]
            beta_v2 = v2_grouped["beta/aligned-v2"]["population"]
            check("a 2.0 run grouped by project leaves an excluded instance "
                  "out of its project's denominators and macro, and each "
                  "project block carries its own excluded count",
                  sorted((r["n"], r["passed"]) for r in v2_grouped.values())
                  == [(1, 1), (1, 1)]
                  and alpha_v2["planned_n"] == 1
                  and alpha_v2["population_exclusions"]["count"] == 1
                  and beta_v2["population_exclusions"]["count"] == 0
                  and "pass_at_1 macro        100.0%" in v2_grouped_text,
                  v2_grouped_text)
            check("PC7: ...and the macro names its parts, so the reader can see "
                  "each project counted ONCE whatever its item count",
                  "equal-weight mean over 2 project(s)" in grouped_text
                  and " 50.0%  (1/2)  alpha" in grouped_text
                  and "100.0%  (1/1)  beta" in grouped_text,
                  grouped_text)
            check("PC7: no cross-project non_vacuous macro is invented beside it "
                  "-- primary non-vacuous results stay project-specific",
                  "no cross-project non_vacuous_pass_at_1 macro exists"
                  in grouped_text
                  and sorted(equal_weight_macros(
                      {"alpha": {"aligned": {
                          "summary": {"pass_rate": 0.5, "passed": 1, "n": 2},
                          "rows": aligned_rows[:2]}},
                       "beta": {"aligned": {
                           "summary": {"pass_rate": 1.0, "passed": 1, "n": 1},
                           "rows": aligned_rows[2:]}}})
                      ["aligned"]) == ["estimand", "label", "metric",
                                        "n_projects", "pass_at_1_macro",
                                        "projects"],
                  grouped_text)
            check("comparison class and agent-system identity are validated "
                  "across, as well as inside, project blocks",
                  len(grouped) == 2 and "CROSS-PROJECT HEADLINE — aligned"
                  in grouped_text)

            def report_macro_rows(filename, rows):
                path = _fixture_run(os.path.join(d, filename), rows)
                return _report_with_capability_fixture(
                    [path], group_by="project",
                    dataset_manifest_path=functional_manifest,
                    dataset_manifest_sha256=functional_manifest_sha)

            def macro_identity_missing(rows):
                return _validate_macro_identities({
                    project: {"native": {"rows": [
                        row for row in rows if project_of(row) == project]}}
                    for project in ("alpha", "beta")})

            for native_system, iterations, budget in (
                    ("openhands", 100, {"max_iterations": 100}),
                    ("aider", None, {"max_reflections": 10})):
                native_rows = [dict(
                    row, adapter=native_system, agent_system=native_system,
                    adapter_version=f"{native_system}@1", max_tokens=None,
                    max_iterations=iterations, native_budget=budget)
                    for row in aligned_rows]
                native_missing = macro_identity_missing(native_rows)
                check(f"{native_system} explicit inapplicable budgets retain "
                      "the authenticated cross-project macro",
                      native_missing == {}, str(native_missing))
                for field in ("max_tokens", "max_iterations"):
                    erased_native = [
                        {key: value for key, value in row.items() if key != field}
                        for row in native_rows]
                    erased_missing = macro_identity_missing(erased_native)
                    check(f"{native_system} absent {field} remains unknown "
                          "rather than an explicit inapplicable budget",
                          field in erased_missing.get("native", ""),
                          str(erased_missing))
            mixed_cap_rows = [
                dict(row, max_tokens=None) if project_of(row) == "beta"
                else dict(row) for row in aligned_rows]
            refuses_before_printing(
                "legacy completion stamps cannot pool with corrected native nulls",
                lambda: report_macro_rows("mixed-completion-stamps.jsonl",
                                          mixed_cap_rows),
                "cross-project headline", "max_tokens")
            applicable_null_rows = [dict(row, max_iterations=None)
                                    for row in aligned_rows]
            applicable_missing = macro_identity_missing(applicable_null_rows)
            check("OpenHands still needs its applicable iteration budget",
                  "max_iterations" in applicable_missing.get("native", ""),
                  str(applicable_missing))

            whitespace_system = [dict(row, agent_system=" ")
                                 for row in aligned_rows]
            refuses_before_printing(
                "homogeneous whitespace cannot authenticate a required macro "
                "identity field",
                lambda: report_macro_rows(
                    "whitespace-system.jsonl", whitespace_system),
                "malformed agent_system", "non-empty string")
            zero_iterations = [dict(row, max_iterations=0)
                               for row in aligned_rows]
            refuses_before_printing(
                "homogeneous zero placeholders cannot authenticate a positive "
                "budget field",
                lambda: report_macro_rows(
                    "zero-iterations.jsonl", zero_iterations),
                "malformed max_iterations", "greater than or equal to 1")

            # Redundant system spellings are normalised for contradiction/native
            # lookup, but the producer stamp itself is exact. Padding cannot make
            # OpenHands look like an unknown system or compare equal as raw
            # identity.
            padded_without_native = []
            for row in aligned_rows:
                padded = dict(row, agent_system=" openhands ")
                padded.pop("native_budget", None)
                padded_without_native.append(padded)
            refuses_before_printing(
                "a padded OpenHands stamp cannot bypass its native-budget or "
                "exact-identity requirements",
                lambda: report_macro_rows(
                    "padded-without-native.jsonl", padded_without_native),
                "malformed agent_system", "surrounding whitespace")

            asymmetric_padding = [
                (dict(row, model=" fixture-model ")
                 if project_of(row) == "beta" else dict(row))
                for row in aligned_rows]
            refuses_before_printing(
                "asymmetric surrounding whitespace is not normalised into an "
                "equal model identity",
                lambda: report_macro_rows(
                    "padded-model.jsonl", asymmetric_padding),
                "malformed model", "surrounding whitespace")

            for label, changes, needles in (
                    ("revisionless-adapter", {"adapter_version": "openhands"},
                     ("malformed adapter_version", "system@positive-integer")),
                    ("empty-adapter-revision", {"adapter_version": "openhands@"},
                     ("malformed adapter_version", "system@positive-integer")),
                    ("c3-without-feedback", {"condition": "c3", "trials": 0},
                     ("malformed trials", "condition is c3")),
                    ("c2-with-feedback", {"condition": "c2",
                                          "trials": "unlimited"},
                     ("malformed trials", "condition is c2")),
                    ("unknown-condition", {"condition": "c4", "trials": 0},
                     ("malformed condition", "c1.5, c2, c3"))):
                impossible = [dict(row, **changes) for row in aligned_rows]
                refuses_before_printing(
                    f"producer-impossible {label} metadata cannot publish",
                    lambda label=label, rows=impossible: report_macro_rows(
                        f"bad-{label}.jsonl", rows),
                    *needles)

            for label, budget, needles in (
                    ("empty", {}, ("malformed native_budget", "non-empty")),
                    ("unknown-key", {"bogus": 7},
                     ("malformed native_budget", "max_iterations")),
                    ("wrong-value", {"max_iterations": 99},
                     ("malformed native_budget", "top-level stamp"))):
                bad_budget = [dict(row, native_budget=budget)
                              for row in aligned_rows]
                refuses_before_printing(
                    f"a homogeneous {label} native budget cannot publish a "
                    "same-configuration macro",
                    lambda label=label, rows=bad_budget: report_macro_rows(
                        f"bad-native-{label}.jsonl", rows),
                    *needles)

            # ...and that last check belongs to whichever agent's NATIVE knob IS
            # the top-level `max_iterations`, not to the name "openhands".  A
            # third agent is registered here both ways round and handed the SAME
            # contradictory bytes, so the only thing that can move the verdict is
            # `NATIVE_BUDGET_KEY`.  The pinned report is used because the answer
            # that matters on the not-refused side is a PUBLISHED headline: an
            # unchecked contradiction reaches the 75.0% macro like any other row.
            # Both shipped arms are read in every state -- openhands owns the
            # top-level knob and aider does not -- so neither answer may change
            # while a stranger is in the table.

            def macro_report(system, native_budget):
                path = _fixture_run(
                    os.path.join(d, f"native-key-{system}.jsonl"),
                    [dict(row, agent_system=system, adapter=system,
                          adapter_version=f"{system}@1",
                          native_budget=native_budget)
                     for row in aligned_rows])
                return pinned_capability_report(
                    [path], group_by="project",
                    dataset_manifest_path=functional_manifest,
                    dataset_manifest_sha256=functional_manifest_sha)

            def macro_verdict(system, native_budget):
                """`report`'s whole answer for one arm: its refusal, or its table.

                One string, so "unchanged" is asserted literally instead of as a
                list of properties that happen to agree.
                """
                buf = io.StringIO()
                try:
                    with redirect_stdout(buf):
                        macro_report(system, native_budget)
                except ReportRefusal as e:
                    return str(e)
                return buf.getvalue()

            # The top-level stamp in `macro_identity` is 100, so 99 contradicts it
            # and 100 does not.
            contradiction = {_agent.TOP_LEVEL_BUDGET_KEY: 99}
            agreement = {_agent.TOP_LEVEL_BUDGET_KEY: 100}
            PUBLISHED = "pass_at_1 macro        75.0%"

            def shipped_verdicts():
                return (macro_verdict("openhands", agreement),
                        macro_verdict("openhands", contradiction),
                        macro_verdict("aider", {"max_reflections": 7}))

            before = shipped_verdicts()
            check("the shipped pair: openhands owns the top-level knob, so its "
                  "contradiction refuses while its agreeing arm publishes; "
                  "aider's knob has a different name, so the top-level stamp is "
                  "not its business",
                  PUBLISHED in before[0]
                  and "malformed native_budget" in before[1]
                  and "top-level stamp" in before[1]
                  and PUBLISHED in before[2],
                  str(before)[:600])

            try:
                _agent.NATIVE_BUDGET_KEY["acme"] = _agent.TOP_LEVEL_BUDGET_KEY
                owning = macro_verdict("acme", contradiction)
                during = shipped_verdicts()
                refuses_before_printing(
                    "a third agent whose native knob IS the top-level key has "
                    "its contradiction refused before stdout, exactly as "
                    "openhands' is",
                    lambda: macro_report("acme", contradiction),
                    "malformed native_budget", "top-level stamp")

                _agent.NATIVE_BUDGET_KEY["acme"] = "max_reflections"
                foreign = macro_verdict("acme", contradiction)
                after_rekey = shipped_verdicts()
            finally:
                _agent.NATIVE_BUDGET_KEY.pop("acme", None)
            after = shipped_verdicts()

            check("the SAME third-agent rows refuse when its native knob is the "
                  "top-level key, and reach the headline when it is not -- the "
                  "registry decides, not the agent's name",
                  "malformed native_budget" in owning
                  and "top-level stamp" in owning
                  and PUBLISHED in foreign
                  and "malformed native_budget" not in foreign,
                  f"owning={owning[:400]!r} foreign={foreign[:400]!r}")
            check("registering, re-keying and de-registering a third agent "
                  "leaves both shipped arms' answers byte-identical",
                  before == during == after_rekey == after,
                  str([state for state, verdicts in
                       (("during", during), ("after_rekey", after_rekey),
                        ("after", after))
                       if verdicts != before]))

            malformed_deviations = [dict(row, protocol_deviations=" ")
                                    for row in aligned_rows]
            refuses_before_printing(
                "a malformed optional deviation stamp refuses atomically",
                lambda: report_macro_rows(
                    "bad-deviations.jsonl", malformed_deviations),
                "malformed protocol_deviations", "list of non-empty")
            malformed_versions = [dict(row, agent_version=7)
                                  for row in aligned_rows]
            refuses_before_printing(
                "a malformed optional agent version refuses atomically",
                lambda: report_macro_rows(
                    "bad-agent-version.jsonl", malformed_versions),
                "malformed agent_version", "non-empty string")

            # A coordinated deletion must never turn a correct refusal into a
            # publishable number.  When every arm lacks the same required field,
            # keep the useful project reports but withhold the unauthenticated
            # headline.  An asymmetric omission is still a structural conflict
            # and refuses before stdout.
            for field in ("agent_system", "model", "max_iterations"):
                erased_rows = [
                    {key: value for key, value in row.items() if key != field}
                    for row in aligned_rows]
                erased = _fixture_run(
                    os.path.join(d, f"erased-{field}.jsonl"), erased_rows)
                erased_buf = io.StringIO()
                with redirect_stdout(erased_buf):
                    erased_report = _report_with_capability_fixture(
                        [erased], group_by="project",
                        dataset_manifest_path=functional_manifest,
                        dataset_manifest_sha256=functional_manifest_sha)
                erased_text = erased_buf.getvalue()
                check(f"coordinated deletion of {field} withholds the macro "
                      "while preserving project reports",
                      len(erased_report) == 2
                      and "CROSS-PROJECT HEADLINE WITHHELD" in erased_text
                      and field in erased_text
                      and "pass_at_1 macro        " not in erased_text
                      and "PROJECT alpha" in erased_text
                      and "PROJECT beta" in erased_text,
                      erased_text)

            unstamped_rows = [
                {key: value for key, value in row.items()
                 if key not in set(MACRO_REQUIRED_SYSTEM_FIELDS)}
                for row in aligned_rows]
            unstamped = _fixture_run(
                os.path.join(d, "unstamped-macro.jsonl"), unstamped_rows)
            unstamped_buf = io.StringIO()
            with redirect_stdout(unstamped_buf):
                _report_with_capability_fixture(
                    [unstamped], group_by="project",
                    dataset_manifest_path=functional_manifest,
                    dataset_manifest_sha256=functional_manifest_sha)
            check("fully unstamped fresh arms cannot publish a macro",
                  "CROSS-PROJECT HEADLINE WITHHELD" in unstamped_buf.getvalue()
                  and "pass_at_1 macro        " not in unstamped_buf.getvalue(),
                  unstamped_buf.getvalue())

            partial_model_rows = [
                ({key: value for key, value in row.items() if key != "model"}
                 if project_of(row) == "alpha" else dict(row))
                for row in aligned_rows]
            partial_model = _fixture_run(
                os.path.join(d, "partial-model.jsonl"), partial_model_rows)
            refuses_before_printing(
                "an asymmetric required-field deletion still refuses before "
                "stdout",
                lambda: _report_with_capability_fixture(
                    [partial_model], group_by="project",
                    dataset_manifest_path=functional_manifest,
                    dataset_manifest_sha256=functional_manifest_sha),
                "cross-project headline", "model", "unknown")

            # ----------------------- actual capability split + repeated arm name
            # One file per project preserves one run/population binding.  Reusing
            # `arm.jsonl` across disjoint projects is how one cross-project system
            # column is represented; it was impossible while sources were keyed by
            # basename globally.
            arm_paths = []
            for directory in ("cs", "docx", "epub"):
                os.makedirs(os.path.join(d, directory))
            cs_rows = [dict(macro_identity, **row) for row in [
                {"item_id": "coreshop/features/domain/a.feature:1",
                 "outcome": "passed", "n_files": 1},
                {"item_id": "coreshop/features/domain/b.feature:2",
                 "outcome": "failed", "n_files": 1},
            ]]
            docx_rows = [dict(
                macro_identity, item_id="python-docx/features/a.feature:1",
                outcome="passed", n_files=1)]
            epub_rows = [dict(
                macro_identity, item_id="epubcheck/features/a.feature:1",
                outcome="failed", n_files=1)]
            for directory, rows in (("cs", cs_rows), ("docx", docx_rows),
                                    ("epub", epub_rows)):
                arm_paths.append(_fixture_run(
                    os.path.join(d, directory, "arm.jsonl"), rows))
            _fixture_sidecar(
                arm_paths[0], {cs_rows[0]["item_id"]: NON_VACUOUS_VERDICT},
                population_id="coreshop-v1")
            split_manifest, split_manifest_sha = capability_fixture(
                "split-capabilities.json",
                {"coreshop": True, "python-docx": True, "epubcheck": False})
            buf = io.StringIO()
            with redirect_stdout(buf):
                split_report = pinned_capability_report(
                    arm_paths, group_by="project",
                    dataset_manifest_path=split_manifest,
                    dataset_manifest_sha256=split_manifest_sha)
            split_text = buf.getvalue()
            check("one repeated arm basename across disjoint projects becomes one "
                  "three-project functional macro rather than overwriting inputs",
                  len(split_report) == 3
                  and "equal-weight mean over 3 project(s)" in split_text
                  and "pass_at_1 macro        50.0%" in split_text,
                  split_text)

            # A basename is the system-arm key, but it is not permission to
            # change that arm's project denominator. Missing one project must
            # withhold the headline while retaining every available project
            # report; two non-overlapping basenames are two withheld partial arms,
            # never two one-project "cross-project" headlines.
            cs_only = _fixture_run(
                os.path.join(d, "cs", "coreshop-only.jsonl"),
                [dict(macro_identity,
                      item_id="coreshop/features/domain/only.feature:1",
                      outcome="passed", n_files=1)])
            docx_only = _fixture_run(
                os.path.join(d, "docx", "docx-only.jsonl"),
                [dict(macro_identity,
                      item_id="python-docx/features/only.feature:1",
                      outcome="passed", n_files=1)])
            partial_buf = io.StringIO()
            with redirect_stdout(partial_buf):
                partial_report = pinned_capability_report(
                    arm_paths + [cs_only, docx_only], group_by="project",
                    dataset_manifest_path=split_manifest,
                    dataset_manifest_sha256=split_manifest_sha)
            partial_text = partial_buf.getvalue()
            check("partial and non-overlapping run basenames withhold their "
                  "cross-project macros without dropping project reports",
                  len(partial_report) == 5
                  and "CROSS-PROJECT HEADLINE WITHHELD — coreshop-only"
                  in partial_text
                  and "CROSS-PROJECT HEADLINE WITHHELD — docx-only"
                  in partial_text
                  and "CROSS-PROJECT HEADLINE — coreshop-only"
                  not in partial_text
                  and "CROSS-PROJECT HEADLINE — docx-only" not in partial_text
                  and "PROJECT coreshop" in partial_text
                  and "PROJECT python-docx" in partial_text
                  and "absent from requested project(s)" in partial_text,
                  partial_text)
            check("the reference table's eligible set comes from the capability "
                  "manifest, keeps an unscored eligible project, and excludes "
                  "the functional-only project",
                  "eligible set: 2 project(s) — coreshop, python-docx" in split_text
                  and "functional-pass-only: epubcheck" in split_text
                  and "coreshop-v1" in split_text
                  and "python-docx/arm: no test-quality summary" in split_text
                  and "population generation: v1" in split_text,
                  split_text)
            check("the grouped report also names missing bound evidence without "
                  "recommending a closed command",
                  "no bound test-quality evidence for this run" in split_text
                  and "r2t.cli test-quality" not in split_text,
                  split_text)
            epub_block = split_text.split("PROJECT epubcheck", 1)[1].split(
                "\nPROJECT ", 1)[0]
            check("a mutation-false project has no non-vacuous placeholder in its "
                  "project block; it appears only on the functional side",
                  "non_vacuous_pass_at_1" not in epub_block, epub_block)
            check("the split preserves the existing ban on a cross-project "
                  "reference-equivalent mean",
                  "no cross-project non_vacuous_pass_at_1 macro exists"
                  in split_text
                  and "No cross-project reference-equivalent mean is produced"
                  in split_text,
                  split_text)
            check("the capability authority is accepted only with its reviewed "
                  "content pin",
                  _load_capability_fixture(
                      split_manifest, split_manifest_sha)["sha256"]
                  == split_manifest_sha)
            refuses("an edited or mis-pinned capability manifest refuses",
                    lambda: _load_capability_fixture(split_manifest, "0" * 64),
                    "hashes to", "expected")
            try:
                report([mixed], group_by="project",
                       dataset_manifest_path=functional_manifest)  # type: ignore
                production_seam_absent = False
            except TypeError:
                production_seam_absent = True
            check("the production report API has no capability-path injection "
                  "seam; fixture authority is private and test-only",
                  production_seam_absent)
            default_capability = load_capability_manifest()
            from ..data import versions as _versions
            check("the production capability authority is VERSIONS-pinned and "
                  "prints a stable repository-relative label",
                  default_capability["sha256"]
                  == _versions.component("dataset")["files"]
                      ["release/dataset_manifest.json"]
                  and default_capability["label"]
                  == os.path.join("release", "dataset_manifest.json"),
                  str(default_capability))

        # --------------------- generation homogeneity, as a pure red-on-edit
        def table_view(population_id, verdict_basis=None,
                       hard_subset_digest=None):
            return {"summary": {"passed": 1, "n": 1, "pass_rate": 1.0},
                    "test_quality": {
                        "population_id": population_id,
                        "verdict_basis": verdict_basis,
                        "hard_subset_digest": hard_subset_digest,
                        "non_vacuous_passes": 1,
                        "non_vacuous_pass_at_1": 1.0,
                        "stale": False, "publication_ready": True}}

        def table_capability(mutation=True):
            return {
                "capabilities": {
                    "mutation": mutation,
                    "coverage": False,
                    "api_similarity": False,
                },
                "capability_notes": {
                    **({"mutation": "fixture has no mutation"}
                       if not mutation else {}),
                    "coverage": "fixture does not report coverage",
                    "api_similarity": "fixture does not report API similarity",
                },
                **({"mutation_engine": "r2t-mutate"}
                   if mutation else {}),
            }

        synthetic_grouped = {
            "p": {"arm": table_view("p-v1")},
            "q": {"arm": table_view("q-v1")},
        }
        synthetic_caps = {"projects": {
            "p": table_capability(),
            "q": table_capability(),
        }}
        same_generation = {
            "p-v1": {"project": "p", "generation": 1},
            "q-v1": {"project": "q", "generation": 1},
        }
        table = eligible_set_tables(
            synthetic_grouped, synthetic_caps, same_generation)
        check("distinct project population ids are allowed when their "
              "registered generation is the same",
              table["population_generation"] == 1
              and table["population_ids"] == ["p-v1", "q-v1"])
        v2_table_view = table_view("p-v1", "hard_subset")
        v2_table_view["test_quality"].update({
            "method": _R.SINGLE_OBSERVATION_METHOD,
            "candidate_observation_count": 1,
            "reference_observation_count": 1,
            "companion_basis": "full_gold",
            "hard_recall_macro": 0.75, "full_recall_macro": 0.5,
            "full_only_generated_macro": 0.1, "full_jaccard_macro": 0.45,
            "hard_n_scored": 1, "hard_not_scorable_items": [],
            "companion_n_scored": 1, "companion_not_scorable_items": [],
            "reference_excluded_count": 131, "candidate_excluded_count": 4,
            "reference_omitted_items": 6,
            "reference_declared_reason": "no gold row in the control run",
            "reference_controls": {"digest": "a" * 64},
        })
        v2_table = eligible_set_tables(
            {"p": {"arm": v2_table_view}},
            {"projects": {"p": table_capability()}},
            {"p-v1": {"project": "p", "generation": 1}})
        v2_table_buf = io.StringIO()
        with redirect_stdout(v2_table_buf):
            _render_eligible_set_tables(v2_table, {
                "document": {"dataset_version": "fixture"},
                "sha256": "b" * 64, "label": "fixture.json",
            })
        check("the v2 eligible-set row binds the installed controls, stays "
              "project-specific, and renders both estimands with section "
              "5.1's excluded counts",
              v2_table["reference"][0]["reference_controls_digest"] == "a" * 64
              and v2_table["reference"][0]["full_jaccard_macro"] == 0.45
              and "PRIMARY hard-subset recall 0.750 (excluded pairs: 131 "
              "reference, 4 run)" in v2_table_buf.getvalue()
              and "COMPANION full-population (excluded pairs: 131 reference, "
              "4 run)" in v2_table_buf.getvalue()
              and "candidate observations 1; reference observations 1"
              in v2_table_buf.getvalue()
              and "No cross-project reference-equivalent mean is produced"
              in v2_table_buf.getvalue(), v2_table_buf.getvalue())
        check("a declared reference subset's omitted-item count AND the "
              "operator's declared reason travel the same rendered path as "
              "section 5.1's excluded counts",
              v2_table["reference"][0]["reference_omitted_items"] == 6
              and "(excluded pairs: 131 reference, 4 run) (declared subset: "
              "6 item(s) omitted)" in v2_table_buf.getvalue()
              and "DECLARED REFERENCE SUBSET: 6 released item(s) omitted, "
              "declared reason: no gold row in the control run"
              in v2_table_buf.getvalue(),
              v2_table_buf.getvalue())
        refuses("one project's reference table cannot mix a v1 hard-subset "
                "row with a v2 single-observation one",
                lambda: eligible_set_tables(
                    {"p": {"v1": table_view("p-v1", "hard_subset", "c" * 64),
                           "v2": v2_table_view}},
                    {"projects": {"p": table_capability()}},
                    {"p-v1": {"project": "p", "generation": 1}}),
                "mixes test-quality methods")
        mixed_generation = dict(same_generation)
        mixed_generation["q-v1"] = {"project": "q", "generation": 2}
        refuses_before_printing(
            "changing one registered generation reddens the macro table before "
            "stdout", lambda: eligible_set_tables(
                synthetic_grouped, synthetic_caps, mixed_generation),
            "mixes population generations", "p/arm=p-v1(v1)",
            "q/arm=q-v1(v2)")
        unknown_grouped = {
            "p": {"arm": table_view("absent")},
        }
        refuses("an unknown population id is never parsed from its suffix",
                lambda: eligible_set_tables(
                    unknown_grouped,
                    {"projects": {"p": table_capability()}}, same_generation),
                "unknown population_id", "absent")
        wrong_project = dict(same_generation)
        wrong_project["p-v1"] = {"project": "q", "generation": 1}
        refuses("a registered population cannot cross project boundaries",
                lambda: eligible_set_tables(
                    {"p": {"arm": table_view("p-v1")}},
                    {"projects": {"p": table_capability()}}, wrong_project),
                "registered to project", "'q'")
        two_ids_one_project = {
            "p": {
                "arm-a": table_view("p-v1"),
                "arm-b": table_view("p-other-v1"),
            },
        }
        refuses("one project cannot occupy one table under two population ids "
                "even when both labels claim the same generation",
                lambda: eligible_set_tables(
                    two_ids_one_project,
                    {"projects": {"p": table_capability()}},
                    {"p-v1": {"project": "p", "generation": 1},
                     "p-other-v1": {"project": "p", "generation": 1}}),
                "multiple population_id", "p-other-v1")
        refuses("one project's reference table cannot mix legacy and hard "
                "verdict bases",
                lambda: eligible_set_tables(
                    {"p": {
                        "legacy": table_view("p-v1"),
                        "hard": table_view("p-v1", "hard_subset", "1" * 64),
                    }},
                    {"projects": {"p": table_capability()}},
                    {"p-v1": {"project": "p", "generation": 1}}),
                "mixes legacy full-gold", "assertion-hard")
        refuses("one project's hard reference table must bind one artifact",
                lambda: eligible_set_tables(
                    {"p": {
                        "hard-a": table_view(
                            "p-v1", "hard_subset", "1" * 64),
                        "hard-b": table_view(
                            "p-v1", "hard_subset", "2" * 64),
                    }},
                    {"projects": {"p": table_capability()}},
                    {"p-v1": {"project": "p", "generation": 1}}),
                "does not bind one hard-subset artifact", "1" * 64,
                "2" * 64)

    print("  report: OK" if ok else "  report: FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":                                  # pragma: no cover
    raise SystemExit(selftest())
