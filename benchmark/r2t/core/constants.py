"""Spellings shared across the component boundary, defined once.

Every name here is a value that TWO components compare by equality or write
to the same wire: the benchmark's campaign fingerprint against the agent's
run stamp, the benchmark's results tier against the adapter's condition, the
benchmark's attestation reader against the agent proxy's journal.  Each used
to live in the module that first needed it, which made the other side import
that module at module level -- and the module it imported was an agent
module, so a benchmark checkout without the agent package could not import
`campaign`, `adapters`, `campaign_table` or `egress_attestation` at all.

Core, and deliberately import-free: a constant that imports something is a
constant with a dependency, and the whole point of this file is that both
sides can read the same value without either reaching the other.  The
component table (`components.COMPONENT`) and its import-direction check are
what keep this honest.
"""
from __future__ import annotations

import sys

# --- the trial budget's wire vocabulary (`trials`, `adapters`, `campaign`) --
#
#: What `--trials` says when the agent's executions are bounded by its
#: ITERATION budget alone (see `trials`'s module docstring).
#:
#: A STRING, and not `None`, because this value has to survive three hops that
#: `None` does not: the command line, the per-row run stamp, and the campaign
#: fingerprint.  In all three a JSON null already means "nobody wrote this
#: field" -- `campaign._crosscheck_row` skips a `None` campaign value as an
#: absent constraint, and `runner._resume_set` treats an absent field as
#: unverifiable rather than as a value.  Spelling unbounded as null would
#: therefore make "this campaign let the agent run the scenario freely" and
#: "whoever wrote this campaign forgot to record the budget" the same bytes,
#: which is the one confusion the fingerprint exists to prevent.  A literal
#: `"unlimited"` is distinct from `0`, distinct from every count, and reads
#: correctly to a human looking at a run file a year from now.
#:
#: So there are exactly two vocabularies, and one converter between them:
#:
#:   the wire     `0` | a positive int | `UNBOUNDED`   (CLI, stamp, campaign)
#:   the budget   an int | `None`                      (`TrialBudget.k`)
#:
#: `None` never appears on the wire and `UNBOUNDED` never reaches `k`.
UNBOUNDED = "unlimited"


def is_unbounded(trials) -> bool:
    """Does this WIRE value mean "no ceiling"?

    Deliberately not true for `None`: at the argument layer `None` is a flag
    that was never passed, which is `--trials 0` -- the C2-equivalent control
    with no channel at all -- and the two must not collapse into each other.
    """
    return trials == UNBOUNDED


def budget_k(trials):
    """Wire value -> the `k` a `TrialBudget` takes (`None` when unbounded)."""
    return None if is_unbounded(trials) else int(trials)


def parse_trials(value):
    """Normalise anything that arrives as `--trials` into the wire vocabulary.

    Returns an int >= 0 or `UNBOUNDED` and nothing else, so every consumer
    downstream -- the prompt renderer, the adapter, the run stamp, the
    campaign crosscheck -- has two shapes to reason about instead of five.
    Used as argparse's `type=` in `cli`, and again by `runner` on the way to
    the stamp, because a run stamp read back off a row has to normalise to
    the same value the campaign fingerprint recorded or the merge compares
    two spellings of one configuration and refuses a run that was correct.
    Here rather than in `trials` because `cli` and `runner` are on the
    consumer route and `trials` is agent-owned.

    A missing flag (`None`) is 0, which is what `int(getattr(args, "trials",
    0) or 0)` meant before this function existed.  A NEGATIVE count is
    refused rather than read as a sentinel: the negative-number trick would
    have made the plumbing shorter and every message that quotes the value
    (`trial_budget=-1`) a small lie.
    """
    if value is None or value == "":
        return 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text == UNBOUNDED:
            return UNBOUNDED
        if not text.isdigit():
            raise ValueError(
                f"--trials takes a count or {UNBOUNDED!r}, not {value!r}. "
                f"0 means no execution channel at all (the C2-equivalent "
                f"control); {UNBOUNDED!r} means the agent may run the scenario "
                f"as often as it likes, bounded by --max-iterations like every "
                f"other tool call it makes.")
        value = int(text)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"--trials takes a count or {UNBOUNDED!r}, not "
                         f"{value!r}")
    if value < 0:
        raise ValueError(
            f"--trials must be >= 0 or {UNBOUNDED!r}, not {value!r}. A "
            f"negative count is not a budget, and using one as a sentinel "
            f"would put 'trial_budget=-1' into campaign files and refusal "
            f"messages that a reader has to be told how to decode.")
    return value


# --- the submitted tier (`adapters`, `results`, `report`, `campaign_table`) --
#
#: The separate, non-study tier used for externally produced candidates.
#: Deliberately absent from `prompt.AGENT_CONDITIONS`: those labels describe
#: the benchmark's own reviewed generation protocols, while submitted bytes
#: were produced under a protocol this repository does not declare or review.
SUBMITTED_CONDITION = "submitted"

# --- the egress proxy's journal (`egress_proxy`, `egress_attestation`) ------
#
#: Coordinator-owned evidence written after one item process exits.  The
#: journal lives inside the already-sealed trajectory tree, so the existing
#: item and shard inventories bind its bytes without another sidecar chain.
#: The proxy writes it; the attestation reads it back by this name.
JOURNAL_SCHEMA = "r2t.egress-proxy-journal/1"
JOURNAL_RELATIVE = "r2t-egress-proxy-journal.json"

# --- the agent producer's row and file spellings (`result_ledger_v2`,
# `campaign`, `report`) ------------------------------------------------------
#
#: The sealed egress attestation a strict-gate shard writes beside its out
#: file.  The agent producer writes it; `campaign`'s merge reads it back by
#: this suffix, and the merge is on the consumer route.
EGRESS_ATTESTATION_SUFFIX = ".agent-producer.egress.json"
#: The one native knob that is ALSO a top-level row field (`max_iterations`,
#: the OpenHands iteration budget).  The producer stamps both; `report`
#: refuses a row whose two spellings disagree.
TOP_LEVEL_BUDGET_KEY = "max_iterations"

# --- the production method index, by language (`toolkit.cli`, `results`) ----
#
#: Filenames used by `results` under a project's artifacts directory when
#: `--prod-index` is omitted. `index-prod` writes the PHP and Python files;
#: the Java operator stages `gate_java_direct_calls.py index --out` output
#: under its name. Index identity and profile activation remain separate
#: requirements; discovering a file does not enable a disabled profile.
PROD_INDEX_NAMES = {
    "php": "php_prod_index.json",
    "python": "py_prod_index.json",
    "java": "java_prod_index.json",
    "ruby": "rb_prod_index.json",
    "go": "go_prod_index.json",
}


def selftest() -> int:
    """The spellings are pinned: every archived stamp, campaign fingerprint,
    results row and proxy journal carries them as bytes."""
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail else ""))
        ok = ok and bool(condition)

    check("the wire spellings are the ones archived rows carry",
          UNBOUNDED == "unlimited" and SUBMITTED_CONDITION == "submitted"
          and JOURNAL_SCHEMA == "r2t.egress-proxy-journal/1"
          and JOURNAL_RELATIVE == "r2t-egress-proxy-journal.json")
    check("the wire -> budget converter: UNBOUNDED is k=None, 0 is k=0, "
          "a count is itself, and None is not unbounded",
          budget_k(UNBOUNDED) is None and budget_k(0) == 0
          and budget_k("3") == 3 and is_unbounded(UNBOUNDED)
          and not is_unbounded(0) and not is_unbounded(None))
    check("the trial parse: None and '' are 0, a count is itself, the "
          "sentinel is case- and space-insensitive",
          parse_trials(None) == 0 and parse_trials("") == 0
          and parse_trials("5") == 5 and parse_trials(0) == 0
          and parse_trials("unlimited") == UNBOUNDED
          and parse_trials(" UNLIMITED ") == UNBOUNDED)
    refused = []
    for bad in ("-1", -1, "five", True, 2.5, "unlimted"):
        try:
            parse_trials(bad)
        except ValueError as exc:
            refused.append(UNBOUNDED in str(exc))
        else:
            refused.append(False)
    check("a negative count, a non-count string, a bool and a float are "
          "refused naming the sentinel", all(refused),
          "" if all(refused) else str(refused))
    check("the agent producer's spellings are the ones archived campaigns "
          "and rows carry",
          EGRESS_ATTESTATION_SUFFIX == ".agent-producer.egress.json"
          and TOP_LEVEL_BUDGET_KEY == "max_iterations")
    check("the production index filenames are keyed by language",
          PROD_INDEX_NAMES == {"php": "php_prod_index.json",
                               "python": "py_prod_index.json",
                               "java": "java_prod_index.json",
                               "ruby": "rb_prod_index.json",
                               "go": "go_prod_index.json"},
          str(PROD_INDEX_NAMES))
    print("constants: OK" if ok else "constants: FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(selftest())
