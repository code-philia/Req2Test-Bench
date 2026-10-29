"""Is this row a FIRST observation of the item, or a re-draw of it?

SPEC §8 rule 4 lets us re-run an item whose first attempt died of OUR fault --
a container that would not start, a tree one item tampered with under the next
one, a driver killed before it could write anything.  The denominator is fixed
before execution and a benchmark-infrastructure failure must not shrink it.

That permission has an edge, and A5 cell 4 walked straight onto it.  Item
`python-docx/features/doc-styles.feature:7` failed its first attempt because
the CANDIDATE fabricated two `.docx` fixtures into the retained substrate and
the guard aborted the run; the item was re-run and passed.  Re-running was the
right call -- attempt 1 produced no verdict of any kind, so dropping it would
have shrunk the denominator rule 4 forbids shrinking -- but the re-run is a
SECOND DRAW on an item the candidate had already had one go at, and that is not
what the infrastructure bullet is for.  Two draws of a stochastic system, best
one reported, is a measurably different claim from one draw.

The cell's own gate said so, in prose, and wrote that the flag "must appear
wherever it is published".  It did not appear anywhere a machine could see:
`attempt` was null, `repeats` was 1, `outcomes_all_runs` was `["passed"]`, and
`report`, `results` and `compare` printed the row exactly like the other 31.
A caveat that lives only in a markdown file beside the run is a caveat that
does not survive its first citation.

So this module gives the fact a FIELD, one vocabulary for WHY, one reader, and
one writer:

    "draw": {"n": 2, "reason": "candidate_caused",
             "prior_outcomes": ["harness_error"],
             "evidence": [{"path": ..., "kind": "file", "sha256": ...}, ...],
             "stamped_at": "2026-08-03T..."}

THE TWO REASONS ARE NOT ONE FACT.  `benchmark_infrastructure` is the rule-4
re-run: our harness failed the attempt BEFORE the candidate was ever invoked
-- the discarded preflight made no model call and produced no verdict -- so
the re-run restores a measurement that was owed, and the retained row is the
candidate's FIRST observation of the item.  `candidate_caused` is the
disclosable one: the prior attempt failed through the submission's own
behaviour, and the row that replaced it is draw 2 of 2.  Collapsing them into
"was re-run" would make the honest case look like the routine one, which is
the whole reason the field exists -- and it is why `summarise` carries the
split counts `n_candidate_redraw` and `n_infrastructure_restoration`
(`n_repeat` survives for compatibility only) and `disclosure` renders the two
classes as two blocks, never one collapsed headline (review finding 14).

ABSENT MEANS "NOT KNOWN TO BE A REPEAT", NEVER "IS ONE".  Every archived row
and every row of cells 1-4 predates the field.  `read` returns None for them
and every summary below counts them as first draws, because defaulting them
into a class would invent the claim this module exists to record.  A stamp that
is PRESENT and malformed is the opposite case -- it can only come from a hand
edit -- and is refused rather than ignored.

WHAT IS DERIVED AND WHAT IS DECLARED.  `stamp_run` reads the discarded attempt
off disk: how many prior rows there were, what they scored, and the digest of
the file holding them.  It refuses when that evidence does not support the
claim -- no prior row for the item, a prior row that PASSED (discarding a pass
and keeping a re-draw is choosing the better of two draws), a prior row from
another campaign.  The one thing it cannot derive is the reason class: nothing
on disk distinguishes the culprit of a tampering incident from its victims --
in cell 4 all three rows carry the same `SubstrateTampered` message -- so the
class is DECLARED, and declared with citations that are hashed into the stamp
so the declaration can be checked later rather than taken on trust.

THE RETROFIT, verbatim (cell 4, A5 slice 1):

    python3 -m r2t.cli stamp-draw \\
      --run       /data2/binhang/docx_bench/a5_cell4/runs/aider_c3.merged.jsonl \\
      --item      python-docx/features/doc-styles.feature:7 \\
      --discarded /data2/binhang/docx_bench/a5_cell4/runs/\\
QUARANTINE.aider_c3.shard1.substrate_tampered.jsonl \\
      --reason    candidate_caused \\
      --evidence  /data2/binhang/docx_bench/a5_cell4/tamper_evidence \\
      --evidence  /data2/binhang/docx_bench/a5_cell4/runs/\\
QUARANTINE.aider_c3.shard1.substrate_tampered.README.md \\
      --update-campaign-sidecar

That last flag is not a convenience.  Stamping rewrites one line of a merged
run, and `<run>.campaign.json` carries a digest OF THAT FILE which nothing
re-checks at read time; without the flag this refuses rather than leave the
attestation quietly false, and with it the superseded digest goes on record in
the sidecar and in the stamp.

The other two quarantined items (`hlk-props.feature:12`,
`img-characterize-image.feature:6`) are `benchmark_infrastructure`: their
preflight found the tree dirty and refused before they ever invoked the model,
so their failure is entirely a property of our state management.  Same command,
different `--reason`, and the difference is the point.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections import Counter
from typing import Iterable, Optional

#: The field a row carries the fact in.  One spelling, imported everywhere.
FIELD = "draw"

#: Why the PRIOR attempt was discarded.  Two values, deliberately, and neither
#: is a default: see the module docstring.
REASONS = {
    "benchmark_infrastructure":
        "the prior attempt failed through the BENCHMARK's fault before the "
        "candidate was ever invoked -- the discarded preflight made no model "
        "call and produced no verdict -- so SPEC 8 rule 4 requires the re-run "
        "rather than permitting it, and the retained row is the FIRST "
        "candidate observation of the item",
    "candidate_caused":
        "the prior attempt failed through the CANDIDATE's own behaviour, so "
        "this row is a SECOND DRAW and must be read as one",
}

#: Fields that must AGREE between a discarded attempt and the row that replaced
#: it.  They are the campaign's identity as `runner._run_stamp` writes it: two
#: rows that disagree on any of them are not two attempts at one measurement,
#: they are attempts at two different ones, and stamping the second as a
#: re-draw of the first would fabricate a history.  Compared only where BOTH
#: rows carry the key, so a row written before a field existed is not refused
#: for lacking it -- the same grandfathering rule the rest of this file keeps.
IDENTITY_FIELDS = ("item_id", "campaign_digest", "subset_id", "subset_digest",
                   "condition", "agent_system", "adapter", "adapter_version",
                   "model", "setting", "comparison_class", "protocol_digest",
                   "protocol_version", "prompt_digest", "dataset_version")


class DrawRefusal(ValueError):
    """A repeat draw that would be recorded or read as something it is not."""


# ------------------------------------------------------------------ reading
def read(row: dict) -> Optional[dict]:
    """The validated stamp on a row, or None when the row does not carry one.

    None is the grandfathered answer and the common one.  Everything that is
    not None has been checked far enough that a caller may print its `n` and
    its `reason` without re-validating them.
    """
    raw = row.get(FIELD)
    if raw is None:
        return None
    iid = row.get("item_id", "?")
    if not isinstance(raw, dict):
        raise DrawRefusal(
            f"REFUSED: {iid} carries a `{FIELD}` that is not an object "
            f"({type(raw).__name__}). A malformed stamp is not an absent one: "
            f"absence means 'not known to be a repeat' and is read that way "
            f"everywhere, so a stamp nobody can parse must stop the read "
            f"rather than quietly become a first draw.")
    n = raw.get("n")
    if not isinstance(n, int) or isinstance(n, bool) or n < 2:
        raise DrawRefusal(
            f"REFUSED: {iid} is stamped as draw {n!r}. A repeat draw is the "
            f"2nd or later attempt at an item; draw 1 is what every unstamped "
            f"row already claims, and stamping it would say nothing while "
            f"looking like it said something.")
    reason = raw.get("reason")
    if reason not in REASONS:
        raise DrawRefusal(
            f"REFUSED: {iid} is stamped with reason {reason!r}, which is not "
            f"one of {', '.join(sorted(REASONS))}. WHY the prior attempt was "
            f"discarded is the disclosable half of this field -- a rule-4 "
            f"infrastructure re-run and a second draw on a candidate's own "
            f"failure are different claims about the number, and an "
            f"unrecognised label cannot be read as either.")
    priors = raw.get("prior_outcomes")
    if not isinstance(priors, list) or not priors or \
            not all(isinstance(p, str) for p in priors):
        raise DrawRefusal(
            f"REFUSED: {iid} is stamped as a repeat draw but records "
            f"{priors!r} for what the discarded attempt(s) scored. A re-draw "
            f"with no prior outcome on it is an assertion with its evidence "
            f"removed.")
    if "passed" in priors:
        raise DrawRefusal(
            f"REFUSED: {iid} is stamped as a repeat draw whose discarded "
            f"attempt PASSED. Discarding a pass and publishing a later draw is "
            f"choosing between two draws of a stochastic system, which is not "
            f"a re-run under any reading of SPEC 8 rule 4.")
    return {"n": n, "reason": reason, "prior_outcomes": list(priors),
            "evidence": raw.get("evidence") or [],
            "stamped_at": raw.get("stamped_at")}


def is_attempt_row(row: dict) -> bool:
    """Could this row be ONE attempt at ONE item, so that a second one is a re-draw?

    THE IN-FILE DERIVATION NEEDS A DISCRIMINATOR, and this is it.  Reading a
    repeated `item_id` as a repeated attempt is true of a SOLUTION run file,
    which `runner` writes one row per item; it is false BY CONSTRUCTION of a
    mutation run file, which `mutation_run` writes one row per (item, mutant).
    `mut_gold_shard0.jsonl` carries 15 rows for `api-open-document.feature:13`
    and every one of them is a different mutant that is used, none is
    "surviving", and none is an attempt that was discarded.  Inferring 239
    re-draws out of a file's own shape would fabricate exactly the claim this
    module exists to record -- and would do it while rendering an archived
    artifact, which is the one thing the field is not allowed to change.

    So a row is an attempt only when it can be one:

      * it names an item.  A row with no `item_id` is not an attempt at an
        identifiable anything -- `*.quarantined.jsonl` sidecars hold
        `{egress, line, row}` envelopes, and two of those would otherwise
        collide on one `None` key and be disclosed as a re-draw of nothing;
      * it is not one cell of a mutation sweep.  A `mutant_id` says the row is
        one (item, mutant) pair, and the item's other rows are its siblings,
        not its predecessors.

    A row that fails this test is NOT silently ignored: `summarise` refuses a
    `draw` stamp on one, because a stamp there would be a claim about a row
    that cannot carry it, and `stamp_run` refuses to write one.
    """
    iid = row.get("item_id")
    return isinstance(iid, str) and bool(iid) and not row.get("mutant_id")


def summarise(all_rows: Iterable[dict],
              items: Optional[Iterable[str]] = None) -> dict:
    """What a table made of these rows has to disclose about its own draws.

    Takes EVERY line of the run file, not the collapsed `{item: row}` view,
    because the file itself is evidence: `--retry-failed` re-runs an item in
    place and leaves both rows, so a second occurrence of an item id IS a
    second draw whether or not anybody stamped it.  Those are reported as
    `unstamped` -- the fact is visible, the REASON is not, and the file cannot
    supply it -- which is a nudge to stamp rather than a claim about why.

    That inference is only made over rows that could BE an attempt at an item
    (`is_attempt_row`); a mutation sweep's dozens of rows per item are its
    design, not its history.

    The stamped case is the one the file cannot show: when the prior attempt
    was moved out of the run (quarantined), the surviving row is the only trace
    left, and `stamp_run` is what puts the trace back on it.

    `items` is the set the TABLE is over, when that is narrower than the file
    -- `compare --items` pins a subset, and a disclosure counted over the file
    would say "3 of 32 item(s) in this table" under a table of 31 and name a
    row the table does not contain as "INCLUDED in every number above".  Both
    halves of that sentence would be false, which is the same fault as reading
    a mutation sweep's shape as a history.  It scopes what is COUNTED and
    NAMED and nothing else: every row in the file is still validated, so a
    malformed stamp on an excluded item stops the read exactly as before.
    """
    rows = list(all_rows)
    attempts = [r for r in rows if is_attempt_row(r)]
    for r in rows:
        if r.get(FIELD) is not None and not is_attempt_row(r):
            raise DrawRefusal(
                f"REFUSED: a row that is not one attempt at one item carries a "
                f"`{FIELD}` stamp (item_id={r.get('item_id')!r}"
                + (f", mutant_id={r.get('mutant_id')!r}"
                   if r.get("mutant_id") else "")
                + f"). A mutation sweep's row is one (item, mutant) cell and a "
                f"row with no item is not an observation of one, so neither "
                f"can be the second DRAW of anything; the stamp is refused "
                f"rather than counted, because counting it would publish a "
                f"re-draw that never happened.")
    seen = Counter(r["item_id"] for r in attempts)
    last: dict[str, dict] = {}
    for r in attempts:
        last[r["item_id"]] = r

    scope = None if items is None else set(items)
    stamped, unstamped = [], []
    for iid in sorted(last):
        # Validated for EVERY item in the file, scoped or not: a stamp nobody
        # can parse is a reason to stop reading the file, not a row to leave
        # out of a count.
        stamp = read(last[iid])
        if scope is not None and iid not in scope:
            continue
        in_file = seen[iid]
        if stamp:
            stamped.append({"item_id": iid, "n": stamp["n"],
                            "reason": stamp["reason"],
                            "prior_outcomes": stamp["prior_outcomes"],
                            "rows_in_file": in_file})
        elif in_file > 1:
            unstamped.append({"item_id": iid, "n": in_file,
                              "reason": None, "rows_in_file": in_file})
    by_reason = Counter(s["reason"] for s in stamped)
    n_items = len(last) if scope is None else len(set(last) & scope)
    return {"n_items": n_items, "n_rows": len(rows),
            "stamped": stamped, "unstamped": unstamped,
            # The collapsed total, retained for COMPATIBILITY only: it counts
            # a rule-4 restoration and a candidate's second draw as one thing,
            # which is exactly the reading `disclosure` no longer prints
            # (review finding 14).  The split counts below are the honest
            # surface; new readers should use them.
            "n_repeat": len(stamped) + len(unstamped),
            "n_candidate_redraw": by_reason.get("candidate_caused", 0),
            "n_infrastructure_restoration":
                by_reason.get("benchmark_infrastructure", 0),
            "by_reason": dict(sorted(by_reason.items()))}


def disclosure(summary: dict, indent: str = "  ") -> list[str]:
    """The lines a table containing repeat draws must carry, or `[]`.

    Empty when every row is a first draw, which is every archived run: a table
    that says "0 repeat draws" on every page trains readers to skip the line
    that matters.  Never a filter -- the rows are IN every number above these
    lines, and the lines say so, because silently excluding a re-drawn item
    would move a denominator that was fixed before execution.

    THE TWO CLASSES RENDER AS TWO BLOCKS (review finding 14).  Only
    candidate-caused and unstamped repeats may be described as not a first
    candidate observation: a `benchmark_infrastructure` restoration's
    discarded preflight made no model call, so its retained row IS the first
    candidate observation, and the old single headline described it with the
    second draw's predicate -- which for Cell 4 would have published "3 of
    32" second draws where the evidence supports one.  The exact Cell 4 shape
    renders one candidate redraw and two infrastructure restorations, both
    classes named, both INCLUDED, with `REASONS` quoted verbatim so the
    disclosure carries its own reading.
    """
    if not summary.get("n_repeat"):
        return []
    redraws = [s for s in summary["stamped"]
               if s["reason"] == "candidate_caused"]
    restorations = [s for s in summary["stamped"]
                    if s["reason"] == "benchmark_infrastructure"]
    lines = []
    n_second = len(redraws) + len(summary["unstamped"])
    if n_second:
        lines.append(
            f"{indent}REPEAT DRAWS: {n_second} of "
            f"{summary['n_items']} item(s) in this table are NOT a first "
            f"candidate observation. They are INCLUDED in every number above "
            f"-- excluding them would shrink a denominator fixed before "
            f"execution -- and are named here because a re-drawn item is a "
            f"weaker observation than a first-draw one.")
        for s in redraws:
            lines.append(
                f"{indent}  draw {s['n']}  {s['reason']:<24} {s['item_id']} "
                f"(discarded: {', '.join(s['prior_outcomes'])})")
        k = len(redraws)
        if k:
            lines.append(
                f"{indent}  {k} of them {'is' if k == 1 else 'are'} "
                f"candidate_caused: {REASONS['candidate_caused']}.")
        for s in summary["unstamped"]:
            lines.append(
                f"{indent}  draw {s['n']}  {'REASON NOT RECORDED':<24} "
                f"{s['item_id']} ({s['rows_in_file']} rows for this item in "
                f"the run file; the surviving row is the last). Stamp it with "
                f"`r2t.cli stamp-draw` -- the file can show THAT it was "
                f"re-drawn and never WHY, and the why is the disclosable "
                f"half.")
    if restorations:
        lines.append(
            f"{indent}INFRASTRUCTURE RESTORATIONS: {len(restorations)} of "
            f"{summary['n_items']} item(s) in this table were re-run under "
            f"SPEC 8 rule 4 and remain FIRST candidate observations: "
            f"{REASONS['benchmark_infrastructure']}. They are INCLUDED in "
            f"every number above, and named here so the restoration is "
            f"checkable rather than silent.")
        for s in restorations:
            lines.append(
                f"{indent}  restoration  {s['reason']:<24} {s['item_id']} "
                f"(discarded preflight: {', '.join(s['prior_outcomes'])})")
    return lines


# ------------------------------------------------- the campaign attestation
#: What `campaign.write_merged` calls the sidecar it writes beside a merge.
CAMPAIGN_SIDECAR_SUFFIX = ".campaign.json"


def _rows_digest(path: str) -> str:
    """The digest `campaign.write_merged` records for a rows file.

    Same recipe, deliberately: `sha256` of the file's bytes, first 16 hex
    characters.  If the two ever disagreed, this module would be checking an
    attestation nobody makes.
    """
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()[:16]


def campaign_pair(run_path: str) -> Optional[dict]:
    """The `<run>.campaign.json` attestation beside a run, and whether it holds.

    `campaign.write_merged` writes that sidecar so that "a reader can check the
    pair rather than assume it": it carries the fingerprint, the worker
    manifests, and `rows_digest`, a digest OF THE ROWS FILE.  Nothing in this
    codebase re-verifies it at read time, which is exactly why a writer must:
    an attestation that silently becomes false is worse than no attestation,
    because the only thing it now does is make a reader confident.

    Returns None when there is no sidecar or it declares no digest -- shard
    files, hand-assembled runs and every file written before the sidecar
    existed -- and a `{path, doc, declared, actual}` view otherwise.
    """
    side = run_path + CAMPAIGN_SIDECAR_SUFFIX
    if not os.path.isfile(side):
        return None
    try:
        with open(side, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        raise DrawRefusal(
            f"REFUSED: {os.path.basename(side)} sits beside this run and "
            f"cannot be read ({e}). It is the attestation that says which "
            f"bytes the campaign produced; stamping a row while it is "
            f"unreadable would leave a claim nobody can check either way.")
    declared = doc.get("rows_digest")
    if not isinstance(declared, str) or not declared:
        return None
    return {"path": side, "doc": doc, "declared": declared,
            "actual": _rows_digest(run_path)}


def check_campaign_pair(run_path: str) -> Optional[dict]:
    """Refuse to PUBLISH from a merged run its campaign no longer describes.

    A digest nothing verifies is a comment.  `write_merged` has been writing
    `rows_digest` since the campaign verbs existed, with a comment saying it is
    there so "a reader can check the pair rather than assume it" -- and until
    now no reader did, on any path.  That was survivable while nothing rewrote
    an archived run; this module is the first thing that does, which is exactly
    why the check has to arrive with it.  Verifying only inside `stamp_run`
    would protect the archive from THIS command and from nothing else: a hand
    edit, a truncated copy, a half-finished merge would all still publish
    clean under a sidecar asserting bytes that no longer exist.

    So the three publication verbs -- `report`, `results`, `compare` -- call
    this before they render, and it is SILENT when the pair holds, which is
    every archived run today (all eleven sidecars under coreshop_bench and
    docx_bench were verified matching when this landed).  A table that says
    "digest OK" on every page trains readers to skip the line that matters,
    and a refusal that arrives after the table is a refusal somebody has
    already read past -- so this one is nothing, or it is a stop.

    Returns the `campaign_pair` view (or None when there is no attestation to
    check: shard files, hand-assembled runs, everything older than the
    sidecar) so a caller may cite the digest it just verified.
    """
    pair = campaign_pair(run_path)
    if pair is None or pair["declared"] == pair["actual"]:
        return pair
    raise DrawRefusal(
        f"REFUSED: {os.path.basename(pair['path'])} attests that "
        f"{os.path.basename(run_path)} hashes to {pair['declared']}, and it "
        f"hashes to {pair['actual']}. The rows being published are not the "
        f"rows the campaign produced, and the sidecar -- the fingerprint, the "
        f"worker manifests, the campaign digest -- describes bytes that are "
        f"no longer on disk, so every provenance claim beside this table is "
        f"about a different file. Something edited the run after the merge. "
        f"Find out what, or re-merge the shards; `r2t.cli stamp-draw "
        f"--update-campaign-sidecar` is the one edit that records itself, in "
        f"`rows_digest_history`, and it refuses a pair that was already "
        f"broken rather than laundering it.")


def _supersede_campaign_sidecar(pair: dict, run_path: str, item_id: str,
                                when: str) -> dict:
    """Carry the rows attestation forward, keeping the superseded one on record.

    The rows a campaign PRODUCED did not change; their disclosure did.  So the
    sidecar keeps asserting a digest of the file it describes -- the recomputed
    one -- and records the digest it used to assert, when, and why, so the
    chain from the merge to the published table stays walkable.  Replacing the
    digest silently would be the same failure as leaving it stale, one step
    later.
    """
    history = list(pair["doc"].get("rows_digest_history") or [])
    history.append({
        "digest": pair["declared"],
        "superseded_at": when,
        "by": "r2t.cli stamp-draw",
        "item_id": item_id,
        "why": "a repeat-draw stamp was added to one row: the rows this "
               "campaign produced did not change, what they DISCLOSE did",
    })
    doc = dict(pair["doc"])
    doc["rows_digest"] = _rows_digest(run_path)
    doc["rows_digest_history"] = history
    with open(pair["path"], "w", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, sort_keys=True, indent=2) + "\n")
    return {"path": pair["path"], "was": pair["declared"],
            "now": doc["rows_digest"]}


# ------------------------------------------------------------------ writing
def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_path(path: str) -> dict:
    """`{path, kind, sha256}` for a cited file or directory.

    A directory is hashed over its sorted `(relpath, sha256)` listing, so a
    preserved trajectory can be cited as one thing and still be checkable
    file by file later.  Cited evidence that cannot be hashed cannot be cited:
    a path that does not exist is refused here rather than recorded as a name.
    """
    if os.path.isfile(path):
        return {"path": os.path.abspath(path), "kind": "file",
                "sha256": _sha256_file(path)}
    if os.path.isdir(path):
        h = hashlib.sha256()
        for root, dirs, files in os.walk(path):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, path)
                h.update(rel.encode("utf-8") + b"\0"
                         + _sha256_file(full).encode("ascii") + b"\n")
        return {"path": os.path.abspath(path), "kind": "tree",
                "sha256": h.hexdigest()}
    raise DrawRefusal(
        f"REFUSED: cited evidence {path!r} does not exist. A stamp whose "
        f"citation cannot be hashed is a claim with a footnote to nowhere; the "
        f"point of recording the digest is that somebody can check it later.")


def _rows_of(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise DrawRefusal(
                    f"REFUSED: {path} line {n} is not JSON ({e}).") from None
    return out


def _identity_conflicts(prior: dict, kept: dict) -> list[str]:
    out = []
    for key in IDENTITY_FIELDS:
        if key in prior and key in kept and prior[key] != kept[key]:
            out.append(f"{key}: {prior[key]!r} vs {kept[key]!r}")
    return out


#: Where the checked-in legacy-consistency reports live, relative to this
#: module: `benchmark/release/legacy_consistency`.  Each report there pins its
#: evidence as `inputs.<key>.{path, sha256}`, and
#: `mutation_attestation._saved_report_paths` re-hashes every pinned input at
#: every read -- so a stamp that rewrites a pinned run turns the report into a
#: named refusal until the report is regenerated and re-pinned.
_LEGACY_CONSISTENCY_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), os.pardir,
    "release", "legacy_consistency")


def pinned_legacy_inputs(run_path: str,
                         release_dir: Optional[str] = None) -> list[dict]:
    """Every `(report, input key)` pinning this run's path or bytes, or `[]`.

    Review finding 21's second leg: the one operator script knew which
    attestation its stamp invalidates, and nothing protected a stamp issued
    any other way.  This scanner is that protection, in the writer itself --
    `stamp_run` calls it and warns -- so every future stamp inherits it.

    Path resolution mirrors `mutation_attestation._saved_report_paths`
    (absolute paths taken as-is; relative paths joined to the repository root
    the report's own `path_base` declares) minus the re-hash refusal, so the
    scanner cannot disagree with the validator about WHICH file a report
    names.  Matching is `realpath` equality on the path arm -- basenames
    collide across cells (`openhands_c3.merged.jsonl` is two different pinned
    runs) -- plus full-SHA-256 equality on the bytes arm, which also catches a
    pinned file that was copied or moved since the report was written.  A
    report that cannot be parsed is reported as unscannable rather than
    skipped: silence is the one wrong answer here.
    """
    root = _LEGACY_CONSISTENCY_DIR if release_dir is None else release_dir
    if not os.path.isdir(root):
        return []
    target = os.path.realpath(run_path)
    target_sha: Optional[str] = None
    hits = []
    for name in sorted(os.listdir(root)):
        if not name.endswith(".json"):
            continue
        report_path = os.path.abspath(os.path.join(root, name))
        try:
            with open(report_path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            hits.append({"report": report_path, "input_key": None,
                         "path": None, "sha256": None,
                         "matched": "unscannable"})
            continue
        inputs = doc.get("inputs") if isinstance(doc, dict) else None
        if not isinstance(inputs, dict):
            continue                # index.json and other non-report files
        base = doc.get("path_base")
        rel = base.get("relative_to_report") if isinstance(base, dict) else None
        report_root = None
        if isinstance(rel, str) and rel and not os.path.isabs(rel):
            report_root = os.path.realpath(os.path.join(
                os.path.dirname(report_path), rel))
        for key in sorted(inputs):
            ref = inputs[key]
            if not isinstance(ref, dict) \
                    or not isinstance(ref.get("path"), str) or not ref["path"]:
                continue
            recorded = ref["path"]
            if os.path.isabs(recorded):
                resolved = os.path.abspath(recorded)
            elif report_root is not None:
                resolved = os.path.abspath(
                    os.path.join(report_root, os.path.normpath(recorded)))
            else:
                continue
            arms = []
            if os.path.realpath(resolved) == target:
                arms.append("path")
            sha = ref.get("sha256")
            if isinstance(sha, str) and sha:
                if target_sha is None:
                    target_sha = _sha256_file(run_path)
                if sha == target_sha:
                    arms.append("bytes")
            if arms:
                hits.append({"report": report_path, "input_key": key,
                             "path": recorded, "sha256": ref.get("sha256"),
                             "matched": "+".join(arms)})
    return hits


def _pinned_warning(run_path: str, pins: list[dict]) -> str:
    named = []
    for p in pins:
        if p["matched"] == "unscannable":
            named.append(f"  {p['report']}: UNREADABLE -- cannot rule out a "
                         f"pin on this run")
        else:
            named.append(f"  {p['report']}: inputs.{p['input_key']} pins "
                         f"{p['matched']} (sha256 {p['sha256']})")
    return (
        f"WARNING: {os.path.basename(run_path)} appears as a pinned input of "
        f"{len(pins)} checked-in legacy-consistency record(s):\n"
        + "\n".join(named) + "\n"
        f"Stamping rewrites the run, so each report above stops validating -- "
        f"`mutation_attestation` re-hashes every pinned input at every read "
        f"-- and its entry in release/legacy_consistency/index.json goes "
        f"stale with it. Regenerate the affected report(s) with the reviewed "
        f"`r2t.cli mutants validate --legacy-consistency` command and re-pin "
        f"the index, dataset manifest and VERSIONS.yml before anything "
        f"reports over this run; test-quality rebinding "
        f"(`r2t.cli test-quality-bind`) comes only after that regeneration.")


def stamp_run(run_path: str, item_id: str, discarded_path: str, reason: str,
              evidence: Iterable[str] = (), now: Optional[str] = None,
              dry_run: bool = False,
              update_campaign_sidecar: bool = False,
              legacy_release_dir: Optional[str] = None) -> dict:
    """Stamp ONE item's surviving row as a repeat draw, from evidence on disk.

    Everything except the reason class is derived: how many attempts were
    discarded, what they scored, and the digest of the file they were moved
    into.  Everything derived is also CHECKED -- the refusals below are the
    module's contract, and each of them is a way the claim could be false.

    Rewrites exactly the one line that changes and copies every other line
    BYTE FOR BYTE.  A stamping pass must not re-serialise 31 rows it has
    nothing to say about: a run file is an archived artifact, and a diff that
    touches every line is a diff nobody can review.

    IT ALSO REWRITES THE FILE, which is a merged campaign's problem and not
    only this row's.  `campaign.write_merged` leaves `<run>.campaign.json`
    beside a merge carrying `rows_digest`, a digest of the rows file, so that
    "a reader can check the pair rather than assume it".  Changing one line
    makes that digest false, and nothing re-verifies it at read time -- an
    attestation that quietly stops holding is worse than none, because its only
    remaining effect is to make a reader confident.  So: when such a sidecar
    sits beside the run and still describes it, stamping REFUSES unless
    `update_campaign_sidecar` says to carry the attestation forward, and
    carrying it forward records the superseded digest in the sidecar and in the
    stamp rather than overwriting it.  A sidecar that ALREADY disagrees with
    the file is refused outright: layering a documented change on top of an
    undocumented one would launder the first.
    """
    if reason not in REASONS:
        raise DrawRefusal(
            f"REFUSED: reason {reason!r} is not one of "
            f"{', '.join(sorted(REASONS))}.")
    if os.path.abspath(run_path) == os.path.abspath(discarded_path):
        raise DrawRefusal(
            f"REFUSED: --run and --discarded are the same file. The discarded "
            f"attempt has to be somewhere the run is not, or there is nothing "
            f"to be a re-draw OF.")

    kept_rows = _rows_of(run_path)
    mine = [i for i, r in enumerate(kept_rows) if r.get("item_id") == item_id]
    if not mine:
        raise DrawRefusal(
            f"REFUSED: {run_path} has no row for {item_id}. A re-draw stamp "
            f"belongs on the row that SURVIVED; there is none here.")
    idx = mine[-1]
    kept = kept_rows[idx]
    if not is_attempt_row(kept):
        raise DrawRefusal(
            f"REFUSED: the row for {item_id} in {os.path.basename(run_path)} "
            f"is not one attempt at one item (it carries "
            f"mutant_id={kept.get('mutant_id')!r}), so it cannot be the second "
            f"DRAW of it. A mutation sweep holds one row per (item, mutant) by "
            f"design; stamping one of them would say the sweep re-ran an item "
            f"it merely mutated {len(mine)} ways.")

    priors = [r for r in _rows_of(discarded_path)
              if r.get("item_id") == item_id]
    if not priors:
        raise DrawRefusal(
            f"REFUSED: {os.path.basename(discarded_path)} holds no discarded "
            f"attempt at {item_id}, so nothing on disk supports calling the "
            f"surviving row a re-draw. The evidence is what makes this a "
            f"record rather than an assertion.")
    outcomes = [p.get("outcome") for p in priors]
    if "passed" in outcomes:
        raise DrawRefusal(
            f"REFUSED: a discarded attempt at {item_id} PASSED "
            f"({', '.join(str(o) for o in outcomes)}). Discarding a pass and "
            f"publishing a later draw is choosing the better of two draws, not "
            f"re-running a measurement that never happened.")
    if any(o is None for o in outcomes):
        raise DrawRefusal(
            f"REFUSED: a discarded attempt at {item_id} records no outcome at "
            f"all. What the prior attempt scored is half of what a re-draw "
            f"stamp is for.")
    for prior in priors:
        conflicts = _identity_conflicts(prior, kept)
        if conflicts:
            raise DrawRefusal(
                f"REFUSED: the discarded attempt at {item_id} and the "
                f"surviving row disagree on {'; '.join(conflicts)}. Two rows "
                f"that disagree on the campaign's identity are attempts at two "
                f"different measurements, and stamping one as a re-draw of the "
                f"other would fabricate a history.")
        if prior == kept:
            raise DrawRefusal(
                f"REFUSED: the discarded attempt at {item_id} is identical to "
                f"the surviving row. That is the same row in two files, not a "
                f"prior attempt at it.")

    # The campaign attestation, decided BEFORE the stamp is built and while
    # nothing has been written.  A row that already carries this exact claim is
    # left byte-identical below, so the file's digest only moves when the row
    # had no stamp at all -- which is what `existing is None` means here.
    existing = kept.get(FIELD)
    pair = campaign_pair(run_path) if existing is None else None
    supersedes = None
    if pair is not None:
        if pair["declared"] != pair["actual"]:
            raise DrawRefusal(
                f"REFUSED: {os.path.basename(pair['path'])} declares "
                f"rows_digest {pair['declared']} but "
                f"{os.path.basename(run_path)} hashes to {pair['actual']} -- "
                f"the pair is ALREADY broken, and something other than this "
                f"command broke it. Stamping now would layer a documented "
                f"change on an undocumented one and make the result look "
                f"consistent. Find out what edited the run file, or re-merge "
                f"the shards, before adding to it.")
        if not update_campaign_sidecar:
            raise DrawRefusal(
                f"REFUSED: {os.path.basename(run_path)} is a merged campaign "
                f"and {os.path.basename(pair['path'])} attests that its rows "
                f"hash to {pair['declared']}. Adding a stamp rewrites one line, "
                f"so that attestation would stop holding -- silently, because "
                f"nothing re-checks it at read time, which is the one failure "
                f"mode a benchmark selling checkable provenance cannot have. "
                f"Re-run with --update-campaign-sidecar to carry the "
                f"attestation forward: the new digest is recorded, the old one "
                f"is kept in `rows_digest_history` with the reason, and the "
                f"chain from the merge to the published table stays walkable.")
        supersedes = pair["declared"]

    # Review finding 21, second leg: when the target run is a pinned input of
    # a checked-in legacy-consistency report, SAY SO before anything is
    # written -- the stamp supersedes the pinned digest, and every reader of
    # that report refuses until it is regenerated and the test-quality
    # binding re-produced.  A warning and not a refusal, deliberately: the
    # sanctioned Cell 4 ceremony IS a stamp followed by regeneration, and a
    # refusal here would demand a bypass flag, which is how guards rot.  It
    # fires on dry runs and no-op re-applications too, because the operator
    # reading a preview is exactly the operator who needs it.
    pins = pinned_legacy_inputs(run_path, release_dir=legacy_release_dir)
    if pins:
        print(_pinned_warning(run_path, pins), file=sys.stderr)

    cited = [digest_path(discarded_path)]
    cited[0]["discarded_rows"] = len(priors)
    for path in evidence:
        cited.append(digest_path(path))

    stamp = {"n": len(mine) + len(priors), "reason": reason,
             "prior_outcomes": outcomes, "evidence": cited,
             "stamped_at": now or time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    if supersedes:
        # On the row as well as in the sidecar: the row is what gets copied
        # into a table, and this is the one line saying which merge digest it
        # was published under before the disclosure was added.
        stamp["supersedes_rows_digest"] = supersedes
    if existing is not None:
        was, now_ = read(kept), read(dict(kept, **{FIELD: stamp}))
        if (was["n"], was["reason"], was["prior_outcomes"]) != \
                (now_["n"], now_["reason"], now_["prior_outcomes"]):
            raise DrawRefusal(
                f"REFUSED: {item_id} is already stamped as draw {was['n']} "
                f"({was['reason']}) and this would make it draw {now_['n']} "
                f"({now_['reason']}). Re-stamping a row into a different claim "
                f"is an edit to a published record; move the row's history "
                f"straight or leave it alone.")
        # Same claim, restamped: keep the ORIGINAL stamp bytes, so a re-run of
        # the operator command is a no-op rather than a fresh timestamp on an
        # unchanged fact.
        stamp = existing

    updated = dict(kept)
    updated[FIELD] = stamp
    read(updated)                      # the writer obeys the reader's contract
    result = {"run": os.path.abspath(run_path), "item_id": item_id,
              "line": idx + 1, FIELD: stamp, "dry_run": bool(dry_run),
              "changed": kept.get(FIELD) != stamp}
    if pins:
        # In the machine-readable result as well as on stderr: the operator's
        # transcript of the stamp should carry which checked-in records it
        # superseded, not only a scrollback warning.
        result["pinned_legacy_inputs"] = pins
    if pair is not None:
        # Named in the result even on a dry run, so the operator reads what the
        # command is about to do to the attestation before it does it.
        result["campaign_sidecar"] = {"path": pair["path"],
                                      "was": pair["declared"]}
    if dry_run or not result["changed"]:
        return result

    with open(run_path, encoding="utf-8") as fh:
        lines = fh.readlines()
    # `idx` indexes NON-BLANK rows; map it back onto the file's own lines so a
    # trailing or embedded blank line cannot shift the rewrite onto a
    # neighbour.
    nth, target = -1, None
    for i, line in enumerate(lines):
        if line.strip():
            nth += 1
            if nth == idx:
                target = i
                break
    lines[target] = json.dumps(updated, sort_keys=True) + "\n"
    tmp = run_path + ".stamp-draw.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    os.replace(tmp, run_path)
    if pair is not None:
        # Last, and only after the rows file is on disk: a sidecar updated
        # first would attest to bytes that did not exist yet.
        result["campaign_sidecar"] = _supersede_campaign_sidecar(
            pair, run_path, item_id, stamp["stamped_at"])
    return result


# --------------------------------------------------------------------------
def selftest() -> int:
    """The field, its two reasons, and the refusals that keep it honest."""
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refuses(name, fn, *needles):
        try:
            fn()
        except DrawRefusal as e:
            missing = [n for n in needles if n not in str(e)]
            check(name, not missing, f"message lacks {missing}: {e}")
            return
        check(name, False, "did not refuse")

    print("--- r2t.bench.draws ---")

    base = {"item_id": "p/features/a.feature:1", "outcome": "passed",
            "campaign_digest": "cafe1234cafe1234", "condition": "c3",
            "agent_system": "aider", "comparison_class": "fixed_model_scaffold"}

    # ------------------------------------------------------- reading a stamp
    check("a row with no `draw` reads as None -- absent is 'not known to be a "
          "repeat', which is every archived row", read(dict(base)) is None)
    good = {"n": 2, "reason": "candidate_caused",
            "prior_outcomes": ["harness_error"], "evidence": []}
    check("a well-formed stamp reads back its draw number and reason",
          read(dict(base, draw=good)) == dict(good, stamped_at=None),
          str(read(dict(base, draw=good))))
    refuses("a stamp that is not an object is REFUSED, not treated as absent",
            lambda: read(dict(base, draw="second attempt")),
            "not an object", "malformed stamp is not an absent one")
    refuses("draw 1 is refused: it says nothing while looking like it does",
            lambda: read(dict(base, draw=dict(good, n=1))), "draw 1")
    refuses("an unknown reason is refused rather than counted as either class",
            lambda: read(dict(base, draw=dict(good, reason="rerun"))),
            "benchmark_infrastructure", "candidate_caused")
    refuses("a stamp with no prior outcome is an assertion with its evidence "
            "removed", lambda: read(dict(base, draw=dict(good,
                                                         prior_outcomes=[]))),
            "no prior outcome")
    refuses("a discarded attempt that PASSED is refused on READ too",
            lambda: read(dict(base, draw=dict(good,
                                              prior_outcomes=["passed"]))),
            "choosing between two draws")

    # --------------------------------------------------------- summarise
    rows = [dict(base, item_id=f"p/f.feature:{i}") for i in range(3)]
    s = summarise(rows)
    check("a run of first draws summarises to nothing to disclose",
          s["n_repeat"] == 0 and disclosure(s) == [], json.dumps(s))
    rows[1] = dict(rows[1], draw=dict(good, prior_outcomes=["harness_error"]))
    s = summarise(rows)
    check("one stamped row is counted, classed and named",
          s["n_repeat"] == 1 and s["by_reason"] == {"candidate_caused": 1}
          and s["stamped"][0]["item_id"] == "p/f.feature:1", json.dumps(s))
    text = "\n".join(disclosure(s))
    check("the disclosure states the count, the reason class and the item",
          "1 of 3 item(s)" in text and "candidate_caused" in text
          and "p/f.feature:1" in text and "INCLUDED in every number" in text,
          text)
    # The in-place case: two rows for one item in one file.
    dup = [dict(base, outcome="failed"), dict(base)]
    s2 = summarise(dup)
    check("two rows for one item in one file ARE a repeat draw, derived from "
          "the file with nothing stamped",
          s2["n_repeat"] == 1 and s2["unstamped"][0]["n"] == 2
          and s2["by_reason"] == {}, json.dumps(s2))
    check("...and the disclosure says the WHY is missing rather than guessing",
          "REASON NOT RECORDED" in "\n".join(disclosure(s2)),
          "\n".join(disclosure(s2)))

    # THE DERIVATION NEEDS A DISCRIMINATOR.  A mutation run file is one row per
    # (item, mutant) BY DESIGN -- `mut_gold_shard0.jsonl` holds 5025 rows over
    # 239 items -- and reading its shape as a history would print "draw 15
    # REASON NOT RECORDED" over an archived artifact, every clause of it false.
    mut = [dict(base, item_id=f"p/f.feature:{i}", outcome="failed",
                mutant_id=f"m{i}-{k}", engine="r2t-mutate-py")
           for i in range(3) for k in range(15)]
    s3 = summarise(mut)
    check("45 mutation rows over 3 items are 3 first draws, not 3 re-draws: "
          "one row per (item, mutant) is the file's design, not its history",
          s3["n_repeat"] == 0 and disclosure(s3) == [], json.dumps(s3))
    envelopes = [{"egress": "clean", "line": 4, "row": {}},
                 {"egress": "clean", "line": 9, "row": {}}]
    s4 = summarise(envelopes)
    check("two rows with no item_id are not a repeat draw of one phantom item "
          "-- a quarantine sidecar's envelopes would collide on `None`",
          s4["n_repeat"] == 0 and s4["n_items"] == 0, json.dumps(s4))
    refuses("a `draw` stamp on a MUTANT row is refused, not counted: a mutation "
            "cell cannot be the second draw of its item",
            lambda: summarise([dict(mut[0], draw=good)]),
            "not one attempt at one item", "mutant_id")
    refuses("...and a stamp on a row with no item at all, for the same reason",
            lambda: summarise([dict(envelopes[0], draw=good)]),
            "not one attempt at one item")

    # A TABLE OVER A SUBSET DISCLOSES OVER THAT SUBSET.  `compare --items`
    # pins the denominator; counting the file instead would print "1 of 3
    # item(s) in this table" under a table of two, and name a row the table
    # does not contain as included in every number in it.
    scoped = summarise(rows, items=["p/f.feature:0", "p/f.feature:2"])
    check("an item outside the compared set is neither counted nor named",
          scoped["n_items"] == 2 and scoped["n_repeat"] == 0
          and disclosure(scoped) == [], json.dumps(scoped))
    check("...and one inside it still is",
          summarise(rows, items=["p/f.feature:1"])["n_repeat"] == 1)
    refuses("but a malformed stamp OUTSIDE the compared set still stops the "
            "read: scoping is about what a table claims, not about which "
            "rows have to parse",
            lambda: summarise([dict(base, item_id="p/f.feature:0"),
                               dict(base, item_id="p/f.feature:1",
                                    draw=dict(good, reason="rerun"))],
                              items=["p/f.feature:0"]),
            "not one of")

    # ----------------------------------- DD1/DD2: the disclosure SPLIT (R5)
    # Review finding 14 legs 1-2; plan section 3 PR R5 items 1-4.  The mixed
    # shape is EXACTLY Cell 4's: one candidate_caused stamp and two
    # benchmark_infrastructure stamps over a 32-item run.  The pre-R5
    # headline printed "3 of 32 ... NOT a first observation", which is false
    # for the two restorations -- their discarded preflights never invoked
    # the model -- so the split renders one candidate redraw and two
    # infrastructure restorations, and the collapsed count survives only as
    # the compatibility field `n_repeat`.
    bi = {"n": 2, "reason": "benchmark_infrastructure",
          "prior_outcomes": ["harness_error"], "evidence": []}
    cell4 = [dict(base, item_id=f"python-docx/features/f{i:02d}.feature:1")
             for i in range(32)]
    cell4[3] = dict(cell4[3], draw=dict(good))
    cell4[7] = dict(cell4[7], draw=dict(bi))
    cell4[11] = dict(cell4[11], draw=dict(bi))
    sm = summarise(cell4)
    check("DD1: the mixed Cell 4 shape SPLITS the counts -- "
          "n_candidate_redraw 1, n_infrastructure_restoration 2, n_repeat 3 "
          "retained for compatibility only",
          sm["n_candidate_redraw"] == 1
          and sm["n_infrastructure_restoration"] == 2
          and sm["n_repeat"] == 3, json.dumps(sm))
    text = "\n".join(disclosure(sm))
    check("DD1: the mixed fixture prints ONE candidate redraw and TWO "
          "infrastructure restorations, with both reason texts verbatim",
          "REPEAT DRAWS: 1 of 32 item(s)" in text
          and "INFRASTRUCTURE RESTORATIONS: 2 of 32 item(s)" in text
          and REASONS["candidate_caused"] in text
          and REASONS["benchmark_infrastructure"] in text, text)
    check("DD1: no line renders the collapsed '3 of 32' headline finding 14 "
          "refutes",
          "3 of 32" not in text, text)
    check("DD1: the restoration text states the discarded preflight made no "
          "model call and the retained row is the FIRST candidate "
          "observation",
          "made no model call" in text
          and "FIRST candidate observation" in text, text)
    only_bi = [dict(base, item_id=f"p/f{i}.feature:1") for i in range(3)]
    only_bi[0] = dict(only_bi[0], draw=dict(bi))
    text2 = "\n".join(disclosure(summarise(only_bi)))
    check("DD2: infrastructure-only input prints NO candidate-redraw "
          "headline -- only the restoration block renders",
          "REPEAT DRAWS" not in text2 and "NOT a first" not in text2
          and "INFRASTRUCTURE RESTORATIONS: 1 of 3 item(s)" in text2, text2)
    check("DD2: ...and the restoration is still named and INCLUDED",
          "p/f0.feature:1" in text2 and "INCLUDED in every number" in text2,
          text2)

    # --------------------------------------------------------- stamp_run
    with tempfile.TemporaryDirectory() as d:
        def write(name, rows_):
            p = os.path.join(d, name)
            with open(p, "w", encoding="utf-8") as fh:
                for r in rows_:
                    fh.write(json.dumps(r, sort_keys=True) + "\n")
            return p

        iid = "p/features/a.feature:1"
        kept = [dict(base, item_id="p/features/z.feature:9"),
                dict(base, item_id=iid, outcome="passed", n_files=1)]
        prior = dict(base, item_id=iid, outcome="harness_error")
        run = write("run.jsonl", kept)
        disc = write("QUARANTINE.shard1.jsonl", [prior])
        before = open(run, encoding="utf-8").read()

        refuses("an unknown reason never reaches the file",
                lambda: stamp_run(run, iid, disc, "because"),
                "not one of")
        refuses("stamping an item the run file does not have is refused",
                lambda: stamp_run(run, "p/features/nope.feature:1", disc,
                                  "candidate_caused"), "no row for")
        refuses("stamping an item the DISCARDED file does not have is refused "
                "-- the evidence is what makes this a record",
                lambda: stamp_run(run, "p/features/z.feature:9", disc,
                                  "candidate_caused"),
                "holds no discarded attempt")
        refuses("--run and --discarded may not be the same file",
                lambda: stamp_run(run, iid, run, "candidate_caused"),
                "same file")
        passed_prior = write("passed.jsonl", [dict(prior, outcome="passed")])
        refuses("a discarded attempt that PASSED is refused: that is choosing "
                "the better of two draws",
                lambda: stamp_run(run, iid, passed_prior, "candidate_caused"),
                "better of two draws")
        other = write("other.jsonl",
                      [dict(prior, campaign_digest="0000111100001111")])
        refuses("a discarded attempt from another campaign is refused",
                lambda: stamp_run(run, iid, other, "candidate_caused"),
                "campaign_digest", "fabricate a history")
        # Its own pair of files: the identical-row check can only be reached
        # by a row that did NOT pass, because the discarded-a-pass refusal
        # above fires first (and should).
        twin = dict(base, item_id=iid, outcome="failed")
        run2 = write("run2.jsonl", [twin])
        same = write("same.jsonl", [dict(twin)])
        refuses("the same row in two files is not a prior attempt",
                lambda: stamp_run(run2, iid, same, "candidate_caused"),
                "identical to")
        refuses("evidence that does not exist cannot be cited",
                lambda: stamp_run(run, iid, disc, "candidate_caused",
                                  evidence=[os.path.join(d, "nope")]),
                "does not exist")
        check("...and NONE of those refusals touched the run file",
              open(run, encoding="utf-8").read() == before)

        dry = stamp_run(run, iid, disc, "candidate_caused", dry_run=True)
        check("--dry-run derives the stamp and writes nothing",
              dry[FIELD]["n"] == 2
              and dry[FIELD]["prior_outcomes"] == ["harness_error"]
              and open(run, encoding="utf-8").read() == before,
              json.dumps(dry[FIELD]))

        ev = os.path.join(d, "tamper_evidence")
        os.makedirs(ev)
        with open(os.path.join(ev, "a_styles_part.docx"), "wb") as fh:
            fh.write(b"PK\x03\x04fabricated")
        res = stamp_run(run, iid, disc, "candidate_caused", evidence=[ev])
        after = [json.loads(x) for x in open(run, encoding="utf-8")
                 if x.strip()]
        check("the stamp lands on the SURVIVING row and derives n=2 from the "
              "discarded attempt",
              read(after[1])["n"] == 2
              and read(after[1])["reason"] == "candidate_caused"
              and read(after[1])["prior_outcomes"] == ["harness_error"],
              json.dumps(after[1].get(FIELD)))
        check("the discarded file and the cited tree are both hashed into it",
              [e["kind"] for e in after[1][FIELD]["evidence"]]
              == ["file", "tree"]
              and after[1][FIELD]["evidence"][0]["discarded_rows"] == 1
              and all(len(e["sha256"]) == 64
                      for e in after[1][FIELD]["evidence"]),
              json.dumps(after[1][FIELD]["evidence"]))
        check("every OTHER line is byte-identical -- a stamping pass rewrites "
              "one row, not the archive",
              open(run, encoding="utf-8").readlines()[0]
              == before.splitlines(True)[0])
        check("the stamped row now discloses itself through summarise",
              summarise(after)["by_reason"] == {"candidate_caused": 1})

        again = stamp_run(run, iid, disc, "candidate_caused", evidence=[ev])
        check("re-running the same stamp is a no-op, not a fresh timestamp",
              again["changed"] is False
              and again[FIELD]["stamped_at"] == res[FIELD]["stamped_at"])
        refuses("re-stamping the row into a DIFFERENT claim is refused",
                lambda: stamp_run(run, iid, disc, "benchmark_infrastructure"),
                "already stamped", "published record")

        mut_run = write("mut.jsonl",
                        [dict(base, item_id=iid, outcome="failed",
                              mutant_id=f"m{k}") for k in range(3)])
        refuses("a MUTATION row is not a surviving attempt and cannot be "
                "stamped -- the writer refuses what the reader refuses",
                lambda: stamp_run(mut_run, iid, disc, "candidate_caused"),
                "not one attempt at one item", "mutated 3 ways")

    # ------------------------------------------- the campaign attestation
    # `campaign.write_merged` leaves `<run>.campaign.json` beside a merge with
    # a digest of the rows file, and nothing re-verifies it at read time.
    # Rewriting one line makes it false; making it false in SILENCE is the one
    # option that must not exist.
    with tempfile.TemporaryDirectory() as d:
        iid = "p/features/a.feature:1"
        run = os.path.join(d, "merged.jsonl")
        with open(run, "w", encoding="utf-8") as fh:
            for r in (dict(base, item_id="p/features/z.feature:9"),
                      dict(base, item_id=iid, outcome="passed")):
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        disc = os.path.join(d, "QUARANTINE.jsonl")
        with open(disc, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(base, item_id=iid,
                                     outcome="harness_error"),
                                sort_keys=True) + "\n")
        side_path = run + CAMPAIGN_SIDECAR_SUFFIX

        def write_side(digest):
            with open(side_path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"campaign": {"campaign_id": "c"},
                                     "campaign_digest": "deadbeefdeadbeef",
                                     "n": 2, "rows_path": "merged.jsonl",
                                     "rows_digest": digest},
                                    sort_keys=True, indent=2) + "\n")

        before = open(run, encoding="utf-8").read()
        write_side(_rows_digest(run))
        refuses("stamping a MERGED run refuses while its campaign sidecar "
                "still attests to the bytes -- a digest that silently stops "
                "holding is worse than no digest",
                lambda: stamp_run(run, iid, disc, "candidate_caused"),
                "attests that its rows hash to", "--update-campaign-sidecar")
        check("...and the refusal left the run file and the sidecar alone",
              open(run, encoding="utf-8").read() == before
              and json.load(open(side_path, encoding="utf-8"))["rows_digest"]
              == _rows_digest(run))
        dry = stamp_run(run, iid, disc, "candidate_caused", dry_run=True,
                        update_campaign_sidecar=True)
        check("a DRY RUN names the digest it would supersede and writes "
              "nothing", dry["campaign_sidecar"]["was"] == _rows_digest(run)
              and open(run, encoding="utf-8").read() == before)

        was = _rows_digest(run)
        done = stamp_run(run, iid, disc, "candidate_caused",
                         update_campaign_sidecar=True)
        side = json.load(open(side_path, encoding="utf-8"))
        check("carried forward, the sidecar describes the file it sits beside "
              "again", side["rows_digest"] == _rows_digest(run)
              and side["rows_digest"] != was,
              f"{side['rows_digest']} vs {_rows_digest(run)}")
        check("...and the SUPERSEDED digest is on record, with why and which "
              "item, in the sidecar and on the row",
              side["rows_digest_history"][-1]["digest"] == was
              and side["rows_digest_history"][-1]["item_id"] == iid
              and "DISCLOSE" in side["rows_digest_history"][-1]["why"]
              and done[FIELD]["supersedes_rows_digest"] == was,
              json.dumps(side.get("rows_digest_history")))
        check("the other keys of the sidecar are untouched -- the fingerprint "
              "it attests to did not change",
              side["campaign_digest"] == "deadbeefdeadbeef" and side["n"] == 2)
        noop = stamp_run(run, iid, disc, "candidate_caused")
        check("a second run is a no-op WITHOUT the flag: the row is unchanged, "
              "so the attestation is not at risk and nothing is demanded",
              noop["changed"] is False
              and json.load(open(side_path, encoding="utf-8"))["rows_digest"]
              == _rows_digest(run))

        # AND THE PAIR IS ACTUALLY CHECKED, which is what makes it an
        # attestation rather than a comment.  A writer that maintains a digest
        # no reader verifies protects the archive from ONE command; the harm
        # -- a table published beside provenance describing other bytes --
        # arrives the same way from a hand edit or a truncated copy.
        check("a run its sidecar still describes reads clean, and says which "
              "digest it verified",
              check_campaign_pair(run)["declared"] == _rows_digest(run))
        check("a run with no sidecar is not a run with a broken one: there is "
              "nothing to check and nothing to refuse",
              check_campaign_pair(disc) is None)
        hand = os.path.join(d, "hand.jsonl")
        with open(run, encoding="utf-8") as fh:
            body = fh.read()
        with open(hand, "w", encoding="utf-8") as fh:
            fh.write(body.replace('"outcome": "passed"', '"outcome": "failed"',
                                  1))
        with open(hand + CAMPAIGN_SIDECAR_SUFFIX, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"campaign_digest": "deadbeefdeadbeef",
                                 "rows_digest": _rows_digest(run)}) + "\n")
        refuses("a run edited by something OTHER than this command is refused "
                "at READ time -- the attestation beside the table would "
                "otherwise describe bytes that are not on disk",
                lambda: check_campaign_pair(hand),
                "attests that", "hashes to", "re-merge the shards")

        # A pair that is ALREADY broken is a different fact and gets a
        # different answer: laundering it under a documented change would
        # make an undocumented edit look accounted for.
        run2 = os.path.join(d, "other.jsonl")
        with open(run2, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(base, item_id=iid, outcome="passed"),
                                sort_keys=True) + "\n")
        with open(run2 + CAMPAIGN_SIDECAR_SUFFIX, "w",
                  encoding="utf-8") as fh:
            fh.write(json.dumps({"rows_digest": "0000000000000000"}) + "\n")
        refuses("a sidecar that ALREADY disagrees with its run file is refused "
                "even WITH the flag: this command documents its own change, "
                "not somebody else's",
                lambda: stamp_run(run2, iid, disc, "candidate_caused",
                                  update_campaign_sidecar=True),
                "ALREADY broken", "undocumented")

    # --------------------- DD4: the pinned-input warning (finding 21 leg 2)
    # `stamp_run` itself warns when its target run appears as a pinned input
    # under `benchmark/release/legacy_consistency/*.json`, so a stamp issued
    # outside the one operator script inherits the protection.  Probed
    # against a scratch release directory: the path arm (a pin names this
    # file), the bytes arm (a pin names these bytes at another path), and
    # silence when nothing pins the run.
    import io
    from contextlib import redirect_stderr
    with tempfile.TemporaryDirectory() as d:
        iid = "p/features/a.feature:1"
        run = os.path.join(d, "runs", "merged.jsonl")
        os.makedirs(os.path.dirname(run))
        with open(run, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(base, item_id=iid, outcome="failed"),
                                sort_keys=True) + "\n")
        disc = os.path.join(d, "QUARANTINE.jsonl")
        with open(disc, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(base, item_id=iid,
                                     outcome="harness_error"),
                                sort_keys=True) + "\n")
        ldir = os.path.join(d, "legacy_consistency")
        os.makedirs(ldir)

        def write_pin(name, path, sha):
            with open(os.path.join(ldir, name), "w", encoding="utf-8") as fh:
                json.dump({"path_base": {"kind": "repository_root",
                                         "relative_to_report": "../../.."},
                           "inputs": {"candidate_run":
                                      {"path": path, "sha256": sha}}}, fh)

        write_pin("cell_path_pin.json", run, "0" * 64)
        write_pin("cell_bytes_pin.json",
                  os.path.join(d, "elsewhere.jsonl"), _sha256_file(run))

        buf = io.StringIO()
        with redirect_stderr(buf):
            res = stamp_run(run, iid, disc, "candidate_caused", dry_run=True,
                            legacy_release_dir=ldir)
        err = buf.getvalue()
        check("DD4: `stamp_run` WARNS when its target run is a pinned "
              "legacy-consistency input, naming the report and the input key",
              "WARNING" in err and "cell_path_pin.json" in err
              and "inputs.candidate_run" in err, err[:500])
        check("DD4: the PATH arm and the BYTES arm both fire -- a pin on "
              "this path and a pin on these bytes at another path are each "
              "named",
              "cell_bytes_pin.json" in err
              and len(res.get("pinned_legacy_inputs") or []) == 2
              and {p["matched"] for p in res["pinned_legacy_inputs"]}
              == {"path", "bytes"},
              json.dumps(res.get("pinned_legacy_inputs")))
        check("DD4: the warning says what a stamp obligates -- regeneration "
              "of the report, its index.json entry, and test-quality "
              "rebinding",
              "regenerat" in err.lower() and "index.json" in err
              and "test-quality" in err, err[:500])
        check("DD4: ...and the hits are on the RESULT too, even on a dry "
              "run, so the operator's transcript carries them",
              res["dry_run"] is True and "pinned_legacy_inputs" in res)
        other_dir = os.path.join(d, "other_release")
        os.makedirs(other_dir)
        with open(os.path.join(other_dir, "cell_other.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"path_base": {"kind": "repository_root",
                                     "relative_to_report": "../../.."},
                       "inputs": {"candidate_run":
                                  {"path": os.path.join(d, "unrelated.jsonl"),
                                   "sha256": "1" * 64}}}, fh)
        buf2 = io.StringIO()
        with redirect_stderr(buf2):
            clean = stamp_run(run, iid, disc, "candidate_caused",
                              dry_run=True, legacy_release_dir=other_dir)
        check("DD4: an unpinned run stamps in SILENCE -- the scanner walks a "
              "real report whose pin names other bytes at another path, "
              "matches nothing, and neither warns nor keys the result",
              buf2.getvalue() == ""
              and "pinned_legacy_inputs" not in clean)
        check("DD4: a missing release directory yields no hits -- the in-repo "
              "directory always exists; documented so the early return is a "
              "recorded behaviour rather than an accident",
              pinned_legacy_inputs(run, release_dir=os.path.join(d, "gone"))
              == [])

    # ------------------ DD3/DD5/DD6/DD7: the operator script, post-R5 shape
    # THE SHAPE OF THESE CHECKS CHANGED AT R5 (plan section 3 PR R5 item 5;
    # section 5 scenario DD3).  From M0's merge through R4 this section
    # asserted the OPPOSITE of what it asserts now: `sh
    # scripts/stamp_a5_cell4_draws.sh` in apply mode had to exit 1 with
    # "REFUSED", because M0 installed an apply-mode block so the pre-R5
    # window -- when `disclosure` still printed the collapsed headline
    # finding 14 refutes -- was guarded by a refusal, never by ordering
    # discipline alone.  R5 landed the disclosure split above IN THE SAME PR
    # that lifted the block, so the guard is gone and apply mode must WORK;
    # the pre-R5 assertion is preserved by history, where it ran green on
    # every M0..R4 head.  What the post-R5 state asserts instead: dry-run
    # still changes no bytes (DD3), apply passes the lifted guard (DD3), the
    # first application stamps the intended rows and carries the campaign
    # chain (DD5), a second application is an exact no-op (DD6), and the
    # stamp supersedes any pinned candidate_run digest until regeneration
    # re-pins it (DD7).  All of it against a FIXTURE cell: the selftest never
    # touches the real /data2 archive -- J1's byte-backup ceremony guards
    # that one.
    import subprocess
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          os.pardir, "scripts", "stamp_a5_cell4_draws.sh")
    items3 = ("python-docx/features/doc-styles.feature:7",
              "python-docx/features/hlk-props.feature:12",
              "python-docx/features/img-characterize-image.feature:6")
    with tempfile.TemporaryDirectory() as gd:
        runs = os.path.join(gd, "runs")
        os.makedirs(runs)
        run_p = os.path.join(runs, "aider_c3.merged.jsonl")
        with open(run_p, "w", encoding="utf-8") as fh:
            for iid in items3 + ("python-docx/features/other.feature:1",):
                fh.write(json.dumps(dict(base, item_id=iid,
                                         outcome="passed"),
                                    sort_keys=True) + "\n")
        q_p = os.path.join(
            runs, "QUARANTINE.aider_c3.shard1.substrate_tampered.jsonl")
        with open(q_p, "w", encoding="utf-8") as fh:
            for iid in items3:
                fh.write(json.dumps(dict(base, item_id=iid,
                                         outcome="harness_error"),
                                    sort_keys=True) + "\n")
        readme = os.path.join(
            runs, "QUARANTINE.aider_c3.shard1.substrate_tampered.README.md")
        with open(readme, "w", encoding="utf-8") as fh:
            fh.write("fixture quarantine record\n")
        tamper = os.path.join(gd, "tamper_evidence")
        os.makedirs(tamper)
        with open(os.path.join(tamper, "a_styles_part.docx"), "wb") as fh:
            fh.write(b"PK\x03\x04fixture")
        side_p = run_p + CAMPAIGN_SIDECAR_SUFFIX
        first_digest = _rows_digest(run_p)
        with open(side_p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"campaign": {"campaign_id": "fixture"},
                                 "campaign_digest": "cafe1234cafe1234",
                                 "n": 4,
                                 "rows_path": "aider_c3.merged.jsonl",
                                 "rows_digest": first_digest},
                                sort_keys=True, indent=2) + "\n")
        env = {k: v for k, v in os.environ.items() if k != "R2T_DRY_RUN"}
        env.update(CELL=gd, PY=sys.executable, PYTHONDONTWRITEBYTECODE="1")
        before_run = open(run_p, "rb").read()
        before_side = open(side_p, "rb").read()

        r_dry = subprocess.run(["sh", script],
                               env=dict(env, R2T_DRY_RUN="1"),
                               capture_output=True, text=True)
        check("DD3: dry-run derives all three stamps against the fixture "
              "cell and changes NO bytes",
              r_dry.returncode == 0 and "REFUSED" not in r_dry.stderr
              and open(run_p, "rb").read() == before_run
              and open(side_p, "rb").read() == before_side,
              f"rc={r_dry.returncode} stderr={r_dry.stderr[-400:]!r}")
        check("DD3: ...and the dry-run output already names the attestation "
              "stamping invalidates, before anything is written",
              "legacy_consistency/cell4_python_docx_aider.json"
              in r_dry.stdout and "index.json" in r_dry.stdout,
              r_dry.stdout[:400])

        r1 = subprocess.run(["sh", script], env=env,
                            capture_output=True, text=True)
        check("DD3: apply mode passes the LIFTED M0 guard -- R5 landed the "
              "disclosure split in this same PR, so the refusal that stood "
              "from M0 through R4 is gone",
              r1.returncode == 0 and "REFUSED" not in r1.stderr,
              f"rc={r1.returncode} stderr={r1.stderr[-400:]!r}")
        rows_after = [json.loads(x) for x in open(run_p, encoding="utf-8")
                      if x.strip()]
        stamps = {row["item_id"]: read(row) for row in rows_after
                  if row.get(FIELD) is not None}
        side = json.load(open(side_p, encoding="utf-8"))
        check("DD5: the first application stamps the three intended rows -- "
              "one candidate_caused, two benchmark_infrastructure -- and no "
              "other",
              {i: s["reason"] for i, s in stamps.items()} == {
                  items3[0]: "candidate_caused",
                  items3[1]: "benchmark_infrastructure",
                  items3[2]: "benchmark_infrastructure"},
              json.dumps({i: s and s["reason"]
                          for i, s in stamps.items()}))
        # `.get` throughout: when a probe breaks the apply, the sidecar never
        # gains `rows_digest_history`, and this check must FAIL by name
        # rather than crash the suite with a KeyError before later checks
        # can print (found by mutation probes P7/P10).
        hist = side.get("rows_digest_history") or []
        check("DD5: ...and carries the campaign chain forward -- the "
              "sidecar describes the stamped file and every superseded "
              "digest is on record, chaining back to the merge",
              side.get("rows_digest") == _rows_digest(run_p)
              and len(hist) == 3
              and hist[0].get("digest") == first_digest,
              json.dumps(side.get("rows_digest_history")))
        s_mixed = summarise(rows_after)
        check("DD5: the stamped fixture now discloses the Cell 4 SHAPE -- "
              "one candidate redraw, two infrastructure restorations",
              s_mixed["n_candidate_redraw"] == 1
              and s_mixed["n_infrastructure_restoration"] == 2,
              json.dumps({k: s_mixed[k] for k in
                          ("n_candidate_redraw",
                           "n_infrastructure_restoration", "n_repeat")}))

        after_run = open(run_p, "rb").read()
        after_side = open(side_p, "rb").read()
        r2 = subprocess.run(["sh", script], env=env,
                            capture_output=True, text=True)
        check("DD6: a second application is an EXACT no-op -- rc 0, every "
              "stamp reports no change, run and sidecar byte-identical",
              r2.returncode == 0
              and open(run_p, "rb").read() == after_run
              and open(side_p, "rb").read() == after_side
              and r2.stdout.count("no change: the row already carries "
                                  "exactly this stamp.") == 3
              and '"changed": false' in r2.stdout,
              f"rc={r2.returncode} stdout={r2.stdout[-400:]!r}")

        # DD7's digest half, with the REAL validator primitive: the stamp
        # supersedes any pinned candidate_run digest, so a saved
        # legacy-consistency report pinning the pre-stamp bytes refuses at
        # read -- the exact refusal `_saved_report_paths` raises -- until
        # the report is regenerated with the post-stamp digest.  (The
        # reporting-side half -- an unbound sidecar refuses `report` until
        # test-quality rebinding -- is checked in `report`'s selftest.)
        from ..data import mutation_attestation as A
        pre_sha = hashlib.sha256(before_run).hexdigest()
        post_sha = hashlib.sha256(after_run).hexdigest()
        try:
            A.validate_preserved_file(run_p, pre_sha,
                                      "saved report input candidate_run")
            check("DD7: a pre-stamp candidate_run pin refuses after the "
                  "stamp", False, "did not refuse")
        except A.MutationAssetRefused as e:
            check("DD7: a pre-stamp candidate_run pin refuses after the "
                  "stamp -- legacy report regeneration is REQUIRED before "
                  "its readers succeed",
                  "SHA-256 is" in str(e) and pre_sha in str(e)
                  and post_sha in str(e), str(e))
        check("DD7: regeneration -- re-pinning the post-stamp digest -- is "
              "exactly what restores the read",
              A.validate_preserved_file(
                  run_p, post_sha,
                  "saved report input candidate_run") == post_sha)

    print("  draws: OK" if ok else "  draws: FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":                                  # pragma: no cover
    raise SystemExit(selftest())
