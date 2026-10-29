"""Three-level campaign metadata and the strict K-way merge
(SPEC_C3_PARALLEL §3.6, §3.7, and the sharding half of H4).

Execution is serial today, and the one time it accidentally was not, 26 of
89 doubly-executed items (29%) came back with a DIFFERENT outcome for
byte-identical input and nothing noticed (§2.2, A.7).  K-way execution is
therefore only admissible if the *merge* can prove, after the fact, that
the K shards were one campaign: same image, same seed, same harness, same
budget — and K genuinely disjoint workers, not two processes sharing a
schema.

Spec v2 tried to prove that by requiring every run-stamp field to be
identical across shards.  But the run stamp also holds `finished_at` and
the per-worker identities, which are *required* to differ — so every valid
K-way run would have failed its own merge (review P1-3).  The fix is to
split the metadata into three levels and check each one for what it
actually claims:

  1. campaign fingerprint  identical across shards, hashed to one digest
  2. worker manifest       unique AS DECLARED — the merge refuses when two
                           workers name the same workspace/schema/out file
  3. per row               item id, timings, execution data; the rows are
                           the payload and are never rewritten by the merge

Nothing here executes anything or touches a database; it is metadata and
set arithmetic, which is why every check below is container-free.

One thing here is not only metadata, and it is worth saying at the top: the
agent-runtime manifest v2 binds is PUBLISHED beside the campaign, so every
environment control it records is published too.  `HTTP_PROXY` and its
siblings routinely carry `user:password@host`, so control values are
redacted of their userinfo by `agent_runtime_manifest` itself -- the
constructor, not the probe, because the constructor is the boundary a
hand-assembled document also has to cross.  This is `SecretInManifest`'s
rule one level out: a record that names a live credential is worse than one
that names none.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

# The one spelling of "the agent's executions were not rationed".  Imported
# rather than repeated because this module and `runner._run_stamp` compare
# their two values by EQUALITY: a second literal here is a second thing to
# keep in step, and the failure mode is a merge that refuses a campaign which
# was correct, hours after the sweep was paid for.  From `constants`, which
# imports nothing, so this module stays what its docstring says it is —
# metadata and set arithmetic, no database, no container, no agent code.
from ..core.constants import UNBOUNDED

#: What `database_dump_digest` carries for a stack that has no database
#: (plan decision D6).
#:
#: DECLARED, and never an absent key.  The digest hashes this field, so the
#: three states have to be three different campaigns: a real dump (64 hex
#: characters), "this stack has no database" (this sentinel), and "nobody
#: recorded the database" (`None`).  Collapse the last two and a campaign
#: whose seed was built without a dump by accident merges with one built
#: without a dump by design.
#:
#: It also has to be non-empty, because `cli.cmd_campaign` refuses a
#: fingerprint whose identity fields are falsy -- a seed that identifies
#: nothing.  A python library with no database is a perfectly identifiable
#: campaign, and it says so with a word rather than with a gap.
#:
#: Spelled HERE rather than in `seed`, and imported there, because this is
#: the module where the value becomes part of an identity; two literals of
#: one sentinel is two things to keep in step, and the failure mode is a
#: merge refused hours after the sweep was paid for.
NO_DATABASE = "no_database"

#: Level 1 (§3.6.1).  Order here is documentation only — the digest is
#: taken over canonical JSON with `sort_keys`, so reordering this tuple
#: can never change a campaign's identity and re-run comparisons survive
#: an edit to this file.
CAMPAIGN_FIELDS: tuple[str, ...] = (
    "campaign_id",
    "k_workers",
    "shard_rule",
    "trial_budget",
    "condition",
    "coverage",
    "harness_version",
    "config_digest",
    "model",
    "container_image_digest",
    "workspace_seed_digest",
    "database_dump_digest",
    "protocol_version",
    "protocol_digest",
    "agent_system",
)

#: Fields introduced AFTER the first campaigns were written to disk.
#:
#: `condition` names the experimental arm (c1.5 / c2 / c3).  Without it two
#: arms run at the same budget on the same image hash to the SAME digest, so
#: a C2 shard and a C3 shard both pass "one campaign, verified rather than
#: asserted" and merge into one result file — the comparison the whole
#: benchmark exists to make, silently concatenated.  It is therefore part of
#: the digest ALWAYS, `None` included: a control campaign (gold, stub) has no
#: arm and says so with a null, which is a different 16 hex characters from
#: `c3`.
#:
#: It is also the ONE field `campaign_fingerprint` defaults instead of
#: refusing, which is a deliberate exception to the rule its docstring
#: states.  The compensating control is that the default is applied at
#: CONSTRUCTION, so every fingerprint this module produces carries the key
#: and the digest covers it; the leniency is only for callers written before
#: the field existed.  `_validate_fingerprint` likewise tolerates the key's
#: ABSENCE in a fingerprint read back from disk — a campaign file written
#: last month must still re-hash to the digest its manifests recorded, and it
#: can only do that if nothing here rewrites it on the way in.
#: `protocol_version` and `protocol_digest` (WS1, 2026-08-02) join it, under
#: the same one-sided rule.
#:
#: The digest is the recipe's identity (`r2t/agents/protocol.py`): two campaigns that
#: agree on model, image, seed, database and budget but ran under different
#: protocol files are not one campaign, and before this field they hashed to
#: the same 16 characters.  It is a SCALAR -- the digest, not the document --
#: because `_validate_fingerprint` refuses a nested structure and because a
#: fingerprint's job is to make two configurations either equal or visibly
#: different, which a nested mapping does badly.
#:
#: `protocol_version` is beside it and is not redundant with it: the digest
#: answers "the same recipe?" and the version answers "which one?", and a
#: refusal that can only say `a1b2c3d4 != e5f6a7b8` sends an operator hunting
#: for a file rather than telling them they launched v1 against a v2 campaign.
#:
#: Both are ABSENT from a campaign written before WS1, and absence is the only
#: reason the archived sidecars under `artifacts/runs` still re-hash to the
#: digests their manifests record: `_validate_fingerprint` tolerates the keys
#: missing and NOTHING here fills them in on the way back from disk.  A
#: campaign written today that ran under no protocol carries them as `None`,
#: which is a different 16 characters from a campaign that ran under v2 --
#: which is the point.
#:
#: `agent_system` (Slice 1, 2026-08-02) joins them under the same one-sided
#: rule, and it closes a hole the protocol pair does not.  WHICH SYSTEM RAN is
#: not in the recipe -- `r2t/agents/protocol.py` deliberately does not know what a
#: model or a system is -- and it was not in the fingerprint either, so two
#: sweeps that agree on model, image, seed, budget and protocol hashed to the
#: SAME 16 characters whether an OpenHands scaffold or an aider one produced
#: them.  An aider shard could therefore be merged into an OpenHands campaign
#: and every check would pass, because the digest is what the merge trusts.
#: The row half already existed (`runner._identity_fields` stamps
#: `agent_system` from the adapter registry); this is the campaign half, and
#: `STAMP_CROSSCHECKS` is what makes the two meet.
CAMPAIGN_OPTIONAL_FIELDS: tuple[str, ...] = ("condition", "protocol_version",
                                             "protocol_digest",
                                             "agent_system")

#: Level 1, VERSION 2 (PR R3, 2026-08-05).  The schema string that makes a
#: fingerprint say which identity it is, so that a reader never has to infer
#: the version from which keys happen to be present.
#:
#: A v1 fingerprint has NO `schema` key at all, and that absence is load
#: bearing: every archived campaign on disk was written without one, and
#: `_validate_fingerprint` hashes those documents EXACTLY AS WRITTEN so their
#: manifests keep verifying against themselves.  Nothing here ever adds a key
#: to a document read back from disk.
GENERATION_CAMPAIGN_SCHEMA = "r2t.generation-campaign/v2"

#: The immutable runtime record whose digest v2 binds (plan §3, PR R3).
AGENT_RUNTIME_SCHEMA = "r2t.agent-runtime-manifest/v2"

#: What v2 adds to `CAMPAIGN_FIELDS`, and the realized collision each term
#: exists to make impossible.
#:
#: THE COLLISION THAT WAS ALREADY REAL (review finding 20).  The contaminated
#: Cell 3 attempt and its corrected re-run hashed to the SAME
#: `campaign_digest 971f1c00943040d5`: same campaign_id, model, image, seed,
#: database, budget, protocol and harness VERSION, differing only in the agent
#: environment (an open package channel to a gold-serving host, closed for the
#: re-run by a `sitecustomize.py`) and in the harness BYTES.  v1 had no term
#: for either, so two materially different generation environments were one
#: identity, and `merge_shards` would have blessed a shard mix across them.
#:
#: `attempt_id` — WHICH ATTEMPT, as opposed to which recipe.  A recipe is
#: reusable by design; an attempt is not.  This is the field that makes a
#: re-run a different campaign even when every recipe term is identical, and
#: it is why `cli.cmd_campaign` mints a fresh one per invocation rather than
#: deriving it from the arguments.
#:
#: `harness_commit` / `harness_source_sha256` — WHICH BYTES judged the run.
#: The commit answers it for a clean checkout and is `None` when git cannot
#: (a tarball export, no repository); the source digest answers it always, and
#: is what makes a dirty working tree a different campaign from the commit it
#: was edited from.  Both, because a commit alone can be a lie about the tree
#: and a tree digest alone is not citable in a bug report.
#:
#: `agent_runtime_sha256` — the SHA-256 of the immutable agent-runtime
#: manifest (interpreter, agent/dependency versions, environment controls,
#: network semantics).  The document, not the digest, is what a reader audits;
#: the digest is what the identity carries, because a fingerprint must stay
#: flat and scalar.
#:
#: `network_semantics` — first-class beside the digest that contains it, and
#: deliberately not only inside the manifest: "did an open channel to a
#: gold-serving host exist while this was generated?" is the question ruling
#: 2.7 makes every published Cells 1/2 number carry, and a reader must be able
#: to answer it from the fingerprint without opening a second file.
CAMPAIGN_FIELDS_V2_ADDED: tuple[str, ...] = (
    "schema",
    "attempt_id",
    "harness_commit",
    "harness_source_sha256",
    "agent_runtime_sha256",
    "network_semantics",
)

#: The complete v2 field set.  Order is documentation only, exactly as for
#: `CAMPAIGN_FIELDS`: the digest is taken over canonical JSON.
CAMPAIGN_FIELDS_V2: tuple[str, ...] = CAMPAIGN_FIELDS + CAMPAIGN_FIELDS_V2_ADDED

#: The environment variables an agent-runtime manifest records BY NAME, with
#: whatever value they carry (or `None` when unset).
#:
#: An ALLOWLIST rather than `os.environ`, for two reasons that both matter: a
#: manifest is published beside the rows, so a blanket dump would publish API
#: keys; and an identity that hashes the whole environment would make every
#: shell a different campaign, which is an identity nobody can reproduce.
#:
#: `LITELLM_LOCAL_MODEL_COST_MAP` is first because it is the control that
#: closed the Cells 1/2 contamination channel (ruling 2.7): unset, litellm
#: fetches its price map from `raw.githubusercontent.com` at import, and that
#: host serves this corpus's gold at the pinned commit.
RUNTIME_ENVIRONMENT_CONTROLS: tuple[str, ...] = (
    "LITELLM_LOCAL_MODEL_COST_MAP",
    "NO_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "PYTHONNOUSERSITE",
    "PYTHONHASHSEED",
    "R2T_DRY_RUN",
    "R2T_LLM_MODEL",
)

#: `(fingerprint field, per-row stamp field)` — what the merge cross-checks
#: (§3.7).  The digest on a row proves it was stamped BY this campaign; it
#: cannot prove the worker was LAUNCHED with the campaign's arguments, and
#: those are two different claims.  `runner._run_stamp` writes the row half
#: from the same `args` the worker actually ran with, so a shard started with
#: `--condition c2` under a c3 campaign, or with `--model` left at its
#: default, disagrees here and nowhere else.
#:
#: THE PROTOCOL PAIR IS HERE FOR THAT EXACT REASON.  Binding it into the
#: fingerprint makes two recipes hash differently; it does NOT make a shard
#: follow the one its campaign declares.  Without these two rows a campaign
#: could assert `protocol_version: 2` in its digest while every shard was
#: launched without `--protocol` — internally consistent, since all shards
#: would assert it equally, and false.  `runner._check_campaign_flags` carries
#: the same pair so the refusal comes at LAUNCH; this is the second half, at
#: merge, for rows that reached the file some other way.
#:
#: Both are one-sided in the direction that matters: `_crosscheck_row` skips a
#: campaign field that is `None`, so a campaign which declares no protocol
#: (every one written before WS1, and every one launched without the flag)
#: demands nothing — while a campaign that DOES declare one demands it on
#: every row, present and equal.
STAMP_CROSSCHECKS: tuple[tuple[str, str], ...] = (
    ("trial_budget", "trials"),
    ("model", "model"),
    ("coverage", "coverage"),
    ("condition", "condition"),
    ("protocol_version", "protocol_version"),
    ("protocol_digest", "protocol_digest"),
    ("agent_system", "agent_system"),
    ("agent_runtime_sha256", "agent_runtime_sha256"),
)

#: The campaign fields whose ABSENCE on a row is grandfathered instead of
#: refused.  `_crosscheck_row`'s default is the opposite -- an absent stamp
#: field is a refusal, because a row that says nothing about its model is
#: compatible with EVERY model -- and the exceptions are narrow on purpose.
#:
#: `agent_system` is here because it is younger than the rows: no row written
#: before it existed carries it, and every archived run file under
#: `artifacts/runs` is such a row (verified: zero of them carry the key).  Its
#: absence is UNVERIFIABLE, not WRONG, which is the same reading
#: `runner.STAMP_OPTIONAL_FIELDS` gives it one level up, and refusing on it
#: would kill a correct in-flight campaign that resumed an older out file.
#:
#: The half that matters is untouched: a row that DOES carry `agent_system`
#: must carry the campaign's, so an aider shard cannot merge into an OpenHands
#: campaign.  Every row a current shard writes carries it (the registry stamps
#: it for every non-fixture adapter), so the waiver applies to history and not
#: to anything being produced now.
#:
#: THE COMPENSATING CONTROL, because a waiver deserves one: a shard whose
#: system cannot be resolved would write rows with the key ABSENT, which this
#: waiver would then admit — and `runner._check_campaign_flags` refuses that
#: shard at LAUNCH, before item 1, precisely because an unresolvable system is
#: not the campaign's.  So the only rows the waiver can let through are rows
#: written before the field existed, which is what it is for.
#:
#: `agent_runtime_sha256` is the other additive field.  Existing v2 campaigns
#: bind it in their fingerprints but their released rows predate the row-side
#: link.  They stay readable without being restamped; every new campaign row
#: carries it, and a present disagreement is still refused.
#:
#: The protocol pair is deliberately NOT here even though it is equally young:
#: a campaign that declares a protocol is declaring that its shards FOLLOWED
#: one, and a shard launched without `--protocol` produces exactly the shape
#: this waiver would admit.  That refusal is the point of the pair.
CROSSCHECK_ABSENCE_GRANDFATHERED: frozenset = frozenset({
    "agent_system", "agent_runtime_sha256"})

#: Level 2 (§3.6.2).  `campaign_digest` is carried in the worker manifest
#: so a stray manifest file cannot be merged into a campaign it was not
#: part of just because it happens to sit in the same directory.
WORKER_FIELDS: tuple[str, ...] = (
    "shard",
    "workspace",
    "container",
    "schema",
    "credential",
    "out_path",
    "artifacts_root",
    "started_at",
    "finished_at",
    "campaign_digest",
)

#: The name the fingerprint records for the assignment function, and the only
#: rule `merge_shards` knows how to re-derive.  A campaign sharded some other
#: way is not wrong — it simply cannot have its placement re-checked, and the
#: merge says so by skipping that check rather than by silently passing it.
SHARD_RULE = "sha1_item_id_mod_k"

# Slice 3 preregisters placement by the item's position in its frozen ordered
# view.  Only its explicit capability opens this live rule, and the strict
# merge independently re-derives it from the frozen ordered release.
POSITIONAL_SHARD_RULE = "ordered_position_mod_k"

#: The subset of the worker manifest that §3.2 provisions per worker and
#: that preflight and the merge both require to be pairwise disjoint.  A
#: shared entry here is not a bookkeeping slip: two workers on one schema
#: purge each other's `var/classes` mid-scenario.
RESOURCE_FIELDS: tuple[str, ...] = (
    "workspace", "container", "schema", "credential",
    "out_path", "artifacts_root",
)

#: Filesystem resources collide by CONTAINMENT, not only by equality:
#: `artifacts_root=/art` and `/art/w1` are two different strings and one
#: worker still writes inside the other's tree.  They also collide ACROSS
#: fields — worker 1's workspace under worker 0's artifacts_root is the
#: same accident wearing a different field name.
_PATH_RESOURCES = ("workspace", "out_path", "artifacts_root")

#: The rest collide only by equality: `coreshop_bench_1` is not "inside"
#: `coreshop_bench_10`, and a container name has no hierarchy.
_EQ_RESOURCES = tuple(f for f in RESOURCE_FIELDS if f not in _PATH_RESOURCES)

#: The two legs of the §3.1 triple that a stack with NO DATABASE does not
#: have (a profile's `runtime.needs_database: false`, decision D6).
#:
#: `worker.plan_workers` leaves both EMPTY for such a stack — deliberately,
#: rather than deriving plausible names for a schema nobody creates and a
#: MySQL principal nobody grants, because a record naming a live grant that
#: does not exist is worse than one naming none — and `worker.resource_fields`
#: already drops them from preflight's disjointness check for exactly that
#: reason.  Level 2 did not know: `WorkerManifest` required every resource to
#: be a NON-EMPTY string and the merge compared all of them by equality, so a
#: behave campaign crashed at the one line that writes the record the merge
#: needs (after every item had been paid for), and would then have been
#: refused for K workers "sharing" the empty schema.  Named here so the two
#: places that must know agree, and so the exemption is the DECLARED absence
#: of a resource rather than a hole in the check: a non-empty value is
#: compared exactly as it always was.
DATABASE_RESOURCES: tuple[str, ...] = ("schema", "credential")

_SCALAR = (str, int, float, bool, type(None))


class SecretInManifest(ValueError):
    """Raised rather than persisting a DSN or password into a run stamp.

    §3.2: run stamps record a NON-SECRET credential identity (the user
    name, e.g. `bench_3`).  Manifests are written next to the merged rows
    and are the first thing a reader copies into a bug report, so a
    connection string that reaches one is published.
    """


# --------------------------------------------------------------------------
# Level 1 — the campaign fingerprint
# --------------------------------------------------------------------------

def _canonical(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def campaign_fingerprint(**kw) -> dict:
    """The K-way-invariant half of the metadata (§3.6.1).

    Every field must be supplied EXPLICITLY, even when there is nothing to
    say — `campaign_fingerprint(model=None, ...)` is required and
    `campaign_fingerprint()` with `model` left out is refused.  Defaulting
    a missing key to `None` would make "this campaign ran no model" and
    "whoever wrote this forgot to record the model" the same 16 hex
    characters, and the digest is the only thing standing between two
    unrelated sweeps being concatenated into one result file.

    The one exception is `CAMPAIGN_OPTIONAL_FIELDS`, which is defaulted to
    None rather than refused so that callers written before those fields
    existed keep working.  The result still CARRIES the key — the leniency is
    about what a caller must type, never about what the digest covers.

    THIS IS THE v1 CONSTRUCTOR, and it is retained for READING history: v1
    campaigns on disk must keep validating and re-hashing against themselves,
    and the archived-sidecar checks in this module's selftest are what prove
    they still do.  New campaigns are minted by `generation_fingerprint`
    (`r2t.generation-campaign/v2`), which is what `cli.cmd_campaign` writes;
    a v1 fingerprint records no attempt, no harness bytes and no runtime, and
    two attempts of one recipe under it are one identity (review finding 20).
    """
    missing = [f for f in CAMPAIGN_FIELDS
               if f not in kw and f not in CAMPAIGN_OPTIONAL_FIELDS]
    unknown = sorted(k for k in kw if k not in CAMPAIGN_FIELDS)
    if missing or unknown:
        raise SystemExit(
            "REFUSED: a campaign fingerprint must name exactly the "
            f"{len(CAMPAIGN_FIELDS)} fields of CAMPAIGN_FIELDS"
            + (f"; missing {missing}" if missing else "")
            + (f"; unknown {unknown}" if unknown else "")
            + ". Pass None for a field that does not apply — an absent key "
              "and a null value must not be confusable at merge time.")
    fp = {f: kw.get(f) for f in CAMPAIGN_FIELDS}
    _validate_fingerprint(fp)
    return fp


def fingerprint_version(fp: dict) -> str:
    """`"v1"` or `"v2"` — which identity this document IS, never a guess.

    A v1 fingerprint carries NO `schema` key, because none existed when the
    archived ones were written; a v2 one carries exactly
    `GENERATION_CAMPAIGN_SCHEMA`.  Anything else is refused rather than
    treated as one of the two: a document asserting an unknown identity
    version is not a campaign this harness can compare anything against.

    Read `"schema" not in fp` rather than `fp.get("schema") is None`, because
    an explicit `schema: null` is a THIRD thing — a v2-shaped document whose
    identity was blanked — and it must not read as "an old campaign".
    """
    if not isinstance(fp, dict):
        raise SystemExit(f"REFUSED: campaign fingerprint is {type(fp).__name__}, "
                         f"not a dict")
    if "schema" not in fp:
        return "v1"
    if fp["schema"] == GENERATION_CAMPAIGN_SCHEMA:
        return "v2"
    raise SystemExit(
        f"REFUSED: unsupported generation campaign schema {fp['schema']!r}; "
        f"this harness reads an unschema'd v1 fingerprint or "
        f"{GENERATION_CAMPAIGN_SCHEMA!r}, and never guesses between them")


def _validate_fingerprint(fp: dict) -> None:
    """Validate either identity version, and NEVER rewrite the document.

    Dispatch on the schema first: v1 and v2 have different field sets, so
    checking either shape against the other's list would refuse a correct
    document.  Everything the two versions share is checked identically by
    `_validate_shared_fields`, so a rule cannot hold for one version and drift
    for the other.
    """
    version = fingerprint_version(fp)
    if version == "v2":
        _validate_fingerprint_v2(fp)
        return
    # A field added after some campaigns were already on disk may be absent
    # HERE and must not be filled in: `campaign_digest` hashes the document
    # as given, so inserting `condition: None` into an old fingerprint on the
    # way in would change its digest and every manifest that recorded the old
    # one would then read as "the digest was copied, not computed".  Old
    # campaigns are history; they must keep verifying against themselves.
    missing = [f for f in CAMPAIGN_FIELDS
               if f not in fp and f not in CAMPAIGN_OPTIONAL_FIELDS]
    unknown = sorted(k for k in fp if k not in CAMPAIGN_FIELDS)
    if missing or unknown:
        raise SystemExit(
            "REFUSED: campaign fingerprint has the wrong shape"
            + (f"; missing {missing}" if missing else "")
            + (f"; unknown {unknown}" if unknown else ""))
    _validate_shared_fields(fp)


def _validate_shared_fields(fp: dict) -> None:
    # Only scalars: a nested object or list in a fingerprint would make
    # "identical across shards" depend on how each worker happened to
    # serialise it, which is precisely the ambiguity the digest removes.
    bad = sorted(k for k, v in fp.items() if not isinstance(v, _SCALAR))
    if bad:
        raise SystemExit(f"REFUSED: campaign fingerprint fields {bad} are not "
                         f"scalar; a fingerprint must be flat so that equality "
                         f"is unambiguous")
    if not isinstance(fp["campaign_id"], str) or not fp["campaign_id"].strip():
        raise SystemExit("REFUSED: campaign_id must be a non-empty string — it "
                         "is how a human names the run the digest identifies")
    if not isinstance(fp["shard_rule"], str) or not fp["shard_rule"].strip():
        raise SystemExit("REFUSED: shard_rule must name the assignment "
                         "function, e.g. 'sha1_item_id_mod_k'; two campaigns "
                         "sharded by different rules are not comparable")
    k = fp["k_workers"]
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise SystemExit(f"REFUSED: k_workers must be an int >= 1, got {k!r}")
    budget = fp["trial_budget"]
    # Three admissible shapes, and they mean three different things:
    #
    #   0            no execution channel at all (the C2-equivalent control,
    #                and what every gold/stub campaign records)
    #   a count      the rationed variant, `--trials k`
    #   UNBOUNDED    the shipped C3 arm: the agent's executions are bounded by
    #                its ITERATION budget, like every other tool call it makes
    #
    # `None` is tolerated because a campaign may legitimately assert nothing
    # about the budget and `_crosscheck_row` reads it that way — but it is NOT
    # how unbounded is spelled, and that is the whole reason the sentinel is a
    # string. Anything else is refused here, because a fingerprint's job is to
    # make two configurations either equal or visibly different: `-1`, `True`
    # and `"unlimted"` would each hash to something unique and mean nothing.
    if budget is not None and budget != UNBOUNDED and (
            isinstance(budget, bool) or not isinstance(budget, int)
            or budget < 0):
        raise SystemExit(
            f"REFUSED: trial_budget must be 0 (no execution channel), a "
            f"positive count, {UNBOUNDED!r} (bounded by the agent's iteration "
            f"budget instead), or None for a campaign that asserts nothing "
            f"about it — got {budget!r}")
    # The database half of the seed. Three admissible shapes, and the middle
    # one is the reason this check exists: `""` is what an unset shell
    # variable and a half-written seed manifest both look like, and it would
    # sail through `cli.cmd_campaign`'s falsy-field refusal as a campaign that
    # fingerprints an empty string. A stack with no database says
    # `NO_DATABASE`, which is a word, an identity, and a different digest.
    dump = fp.get("database_dump_digest")
    if dump is not None and (not isinstance(dump, str) or not dump.strip()):
        raise SystemExit(
            f"REFUSED: database_dump_digest must be the digest of the dump "
            f"this campaign was seeded from, {NO_DATABASE!r} for a stack that "
            f"has no database, or None for a campaign that asserts nothing "
            f"about it — got {dump!r}. A blank is none of the three and hashes "
            f"like a value.")
    cond = fp.get("condition")
    if cond is not None and (not isinstance(cond, str) or not cond.strip()):
        # `""` and `"  "` are the shapes an unset shell variable takes on the
        # way into a launcher (`--condition "$COND"`), and an empty string
        # compares equal to another empty string — so two arms whose
        # condition was never set would agree that they are one campaign.
        raise SystemExit(f"REFUSED: condition must name the experimental arm "
                         f"(e.g. 'c1.5', 'c2', 'c3') or be None for a control "
                         f"campaign, got {cond!r}")
    # The protocol pair. Both may be absent (a campaign file written before
    # WS1) or None (a campaign that ran under no protocol); anything present
    # must be the shape a protocol actually has, because the whole value of
    # binding them into the digest is that two recipes are either equal or
    # visibly different.
    pv = fp.get("protocol_version")
    if pv is not None and (isinstance(pv, bool) or not isinstance(pv, int)
                           or pv < 1):
        raise SystemExit(f"REFUSED: protocol_version must be a version number "
                         f">= 1, or None for a campaign that followed no "
                         f"protocol file, got {pv!r}")
    pd = fp.get("protocol_digest")
    if pd is not None and (not isinstance(pd, str) or len(pd) != 16
                           or any(c not in "0123456789abcdef" for c in pd)):
        raise SystemExit(f"REFUSED: protocol_digest must be the 16 hex "
                         f"characters `protocol.protocol_digest` returns, or "
                         f"None, got {pd!r} — a fingerprint records the "
                         f"recipe's IDENTITY, not the recipe")
    # WHICH SYSTEM. Same shape rule as `condition`, and for the identical
    # reason: `""` and `"  "` are what an unset shell variable looks like on
    # the way into a launcher (`--agent-system "$SYS"`), and two empty strings
    # compare equal — so two campaigns that never named their system would
    # agree that they are one campaign. None is the legitimate "this campaign
    # asserts nothing about which system ran it", which every control campaign
    # and every archived one is.
    sysname = fp.get("agent_system")
    if sysname is not None and (not isinstance(sysname, str)
                                or not sysname.strip()):
        raise SystemExit(f"REFUSED: agent_system must name the system under "
                         f"test as the adapter registry spells it (e.g. "
                         f"'openhands', 'aider') or be None for a campaign "
                         f"that asserts nothing about it, got {sysname!r}")
    if (pv is None) != (pd is None):
        # Half a record is worse than none: a version with no digest cannot
        # be checked against a file, and a digest with no version cannot be
        # reported to a human who has to go and read one.
        raise SystemExit(f"REFUSED: protocol_version and protocol_digest must "
                         f"be recorded together or not at all, got "
                         f"{pv!r} / {pd!r}")


def _is_sha256(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _validate_fingerprint_v2(fp: dict) -> None:
    """The v2 shape, on top of every rule v1 already carries."""
    missing = [f for f in CAMPAIGN_FIELDS_V2 if f not in fp]
    unknown = sorted(k for k in fp if k not in CAMPAIGN_FIELDS_V2)
    if missing or unknown:
        raise SystemExit(
            "REFUSED: generation campaign fingerprint (v2) has the wrong shape"
            + (f"; missing {missing}" if missing else "")
            + (f"; unknown {unknown}" if unknown else "")
            + ". v2 is not grandfathered: every one of its fields exists "
              "because an attempt identity that omits one has already "
              "collided (review finding 20).")
    _validate_shared_fields(fp)
    attempt = fp["attempt_id"]
    if not isinstance(attempt, str) or not attempt.strip():
        raise SystemExit(
            f"REFUSED: attempt_id must be a non-empty string naming THIS "
            f"attempt, got {attempt!r}. A recipe may be re-run; an attempt "
            f"may not, and the two Cell 3 attempts shared one identity "
            f"precisely because nothing here distinguished them.")
    commit = fp["harness_commit"]
    if commit is not None and (not isinstance(commit, str)
                               or len(commit) != 40
                               or any(c not in "0123456789abcdef"
                                      for c in commit)):
        raise SystemExit(
            f"REFUSED: harness_commit must be the FULL 40-hex commit of the "
            f"harness checkout, or None where git cannot answer (a tarball "
            f"export, no repository), got {commit!r}. The short form belongs "
            f"on a row, where it is a pointer; an identity carries the whole "
            f"name.")
    if not _is_sha256(fp["harness_source_sha256"]):
        raise SystemExit(
            f"REFUSED: harness_source_sha256 must be the SHA-256 over the "
            f"harness source bytes, got {fp['harness_source_sha256']!r}. It "
            f"is required even when the commit is present: a commit is a "
            f"claim about the tree, and a dirty tree is a different harness.")
    if not _is_sha256(fp["agent_runtime_sha256"]):
        raise SystemExit(
            f"REFUSED: agent_runtime_sha256 must be the SHA-256 of the "
            f"immutable {AGENT_RUNTIME_SCHEMA} manifest, got "
            f"{fp['agent_runtime_sha256']!r}.")
    semantics = fp["network_semantics"]
    if not isinstance(semantics, str) or not semantics.strip():
        raise SystemExit(
            f"REFUSED: network_semantics must state this attempt's network "
            f"posture as a non-empty label (e.g. "
            f"'closed_gold_host_channel', 'open_package_channel'), got "
            f"{semantics!r}. None is not admissible in v2: 'nobody recorded "
            f"it' is exactly the state ruling 2.7 had to disclose after the "
            f"fact.")


def generation_fingerprint(**kw) -> dict:
    """The v2 generation campaign identity (plan §3, PR R3).

    Every v2 field must be supplied explicitly — including `attempt_id`, the
    harness identity pair, the runtime digest and the network posture — for
    the reason `campaign_fingerprint` states about v1's fields: a defaulted
    identity term makes "this attempt had none" and "whoever wrote this
    forgot" the same 16 hex characters.  The four `CAMPAIGN_OPTIONAL_FIELDS`
    keep their v1 leniency about what a CALLER must type; the result still
    carries them, so the digest still covers them.
    """
    missing = [f for f in CAMPAIGN_FIELDS_V2
               if f not in kw and f not in CAMPAIGN_OPTIONAL_FIELDS
               and f != "schema"]
    unknown = sorted(k for k in kw if k not in CAMPAIGN_FIELDS_V2)
    if missing or unknown:
        raise SystemExit(
            "REFUSED: a v2 generation fingerprint must name exactly the "
            f"{len(CAMPAIGN_FIELDS_V2)} fields of CAMPAIGN_FIELDS_V2"
            + (f"; missing {missing}" if missing else "")
            + (f"; unknown {unknown}" if unknown else "")
            + ". Pass None for a field that does not apply — an absent key "
              "and a null value must not be confusable at merge time.")
    fp = {f: kw.get(f) for f in CAMPAIGN_FIELDS_V2}
    fp["schema"] = GENERATION_CAMPAIGN_SCHEMA
    _validate_fingerprint(fp)
    return fp


def campaign_digest(fp: dict) -> str:
    """sha256 over canonical JSON, first 16 hex characters.

    Truncated because it is quoted in refusal messages and file names; 16
    hex is 64 bits, which is not a collision risk over the handful of
    campaigns a benchmark ever runs, and a longer digest that nobody reads
    is not a stronger check.

    ONE function for both identity versions, deliberately.  A v1 document is
    hashed exactly as it was written — nothing here fills a key in, so every
    archived manifest keeps verifying against itself — and a v2 document
    hashes its own larger field set.  The two therefore cannot collide by
    accident and cannot be compared by accident either: a v1 and a v2
    fingerprint of the same recipe are different digests because they are
    different documents, and `merge_shards` refuses the mix BY NAME rather
    than leaving that to the digests.
    """
    _validate_fingerprint(fp)
    return hashlib.sha256(_canonical(fp).encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------
# The immutable agent-runtime manifest (v2)
# --------------------------------------------------------------------------

#: What replaces the credential half of a URL-shaped control value.
#:
#: A MANIFEST IS PUBLISHED.  It is written beside the campaign, its digest is
#: quoted in every row's identity, and it is the first file a reader copies
#: into a bug report -- the same reasoning `SecretInManifest` applies to a
#: worker credential, one level up.  `HTTP_PROXY` and `HTTPS_PROXY` routinely
#: carry `user:password@` in real deployments, so recording an environment
#: control VERBATIM publishes that password to everyone who reads the run.
#:
#: The host and port stay, because they are what the control MEANS for
#: identity: two campaigns proxied through different hosts are different
#: runtimes.  The userinfo is not identity -- rotating a proxy password does
#: not change what the agent could reach -- so replacing it with a fixed
#: marker keeps the digest stable across credential rotations, which is a
#: second reason to do it rather than a cost of doing it.
REDACTED_USERINFO = "REDACTED@"


def redact_control_value(value):
    """Strip the credential half of a URL-shaped control value.

    Applied to every recorded environment control, by the manifest
    constructor rather than by the probe, because the constructor is the
    publication boundary: a caller that assembles a manifest by hand must not
    be able to record a credential either.

    IDEMPOTENT, which the digest depends on: redacting an already-redacted
    value returns it unchanged, so a manifest read back from disk re-canon-
    icalises to itself.

    Deliberately crude, like `_check_credential_identity`: anything with an
    `@` in its authority is treated as carrying userinfo.  A false positive
    costs a host list one marker; a false negative publishes a password.
    """
    if not isinstance(value, str) or not value:
        return value
    scheme, sep, rest = value.partition("://")
    if not sep:
        scheme, rest = "", value
    authority, slash, tail = rest.partition("/")
    if "@" not in authority:
        return value
    host = authority.rpartition("@")[2]
    return f"{scheme}{'://' if sep else ''}{REDACTED_USERINFO}{host}{slash}{tail}"


def agent_runtime_manifest(*, interpreter: str, agent_versions: dict,
                           environment_controls: dict,
                           network_semantics: str) -> dict:
    """The runtime document a v2 fingerprint binds by digest.

    IMMUTABLE, in the same sense a protocol file is: it is written once beside
    the campaign it describes and never edited, because the fingerprint
    records its SHA-256 and an edit would leave every row asserting a runtime
    that no longer exists.

    Nested where the fingerprint is flat, and that asymmetry is the point.  A
    fingerprint has to make two configurations either equal or visibly
    different, which nested structures do badly; a runtime record has to be
    READ by a human deciding whether two sweeps are comparable, which a flat
    string does badly.  The digest is the bridge.
    """
    if not isinstance(interpreter, str) or not interpreter.strip():
        raise SystemExit(
            "REFUSED: an agent-runtime manifest must name its interpreter "
            "(implementation and version), which is what decides whether two "
            "identically-configured agents behaved identically")
    for label, mapping in (("agent_versions", agent_versions),
                           ("environment_controls", environment_controls)):
        if not isinstance(mapping, dict):
            raise SystemExit(
                f"REFUSED: agent-runtime {label} must be an object mapping "
                f"names to recorded values")
        for key, value in mapping.items():
            if not isinstance(key, str) or not key:
                raise SystemExit(
                    f"REFUSED: agent-runtime {label} has a non-string name")
            if not isinstance(value, _SCALAR):
                raise SystemExit(
                    f"REFUSED: agent-runtime {label}[{key!r}] is "
                    f"{type(value).__name__}, not a scalar; a runtime record "
                    f"is evidence, not a nested configuration dump")
    if not isinstance(network_semantics, str) or not network_semantics.strip():
        raise SystemExit(
            "REFUSED: an agent-runtime manifest must state its network "
            "semantics; see ruling 2.7 for what an unrecorded channel costs")
    return {
        "schema": AGENT_RUNTIME_SCHEMA,
        "interpreter": interpreter,
        "agent_versions": dict(agent_versions),
        # REDACTED HERE, at the one place a manifest is constructed, so no
        # caller and no probe can record a credentialed proxy URL.
        "environment_controls": {key: redact_control_value(value)
                                 for key, value in
                                 environment_controls.items()},
        "network_semantics": network_semantics,
    }


def agent_runtime_digest(doc: dict) -> str:
    """Full SHA-256 over the canonical runtime manifest.

    FULL, not truncated to 16 like `campaign_digest`: this one is never
    printed in a refusal message or a file name, and it is a content binding
    rather than a label, which is the same rule
    `mutation_run.CAMPAIGN_IDENTITY_FIELDS` follows.
    """
    if not isinstance(doc, dict) or doc.get("schema") != AGENT_RUNTIME_SCHEMA:
        raise SystemExit(
            f"REFUSED: not an {AGENT_RUNTIME_SCHEMA} document: "
            f"{(doc or {}).get('schema') if isinstance(doc, dict) else doc!r}")
    canonical = agent_runtime_manifest(
        interpreter=doc.get("interpreter"),
        agent_versions=doc.get("agent_versions"),
        environment_controls=doc.get("environment_controls"),
        network_semantics=doc.get("network_semantics"))
    if doc != canonical:
        # The only way to reach here is a hand-assembled document, and the
        # only field the constructor rewrites is a credentialed control
        # value.  Refused rather than silently hashed: hashing it would put
        # the password in the digest's preimage and leave it in the file.
        raise SystemExit(
            "REFUSED: this agent-runtime document is not the canonical form "
            "of its own fields; a URL-shaped environment control still "
            "carries userinfo. Build it with `agent_runtime_manifest`, which "
            "redacts credentials before they can be recorded.")
    return hashlib.sha256(_canonical(canonical).encode("utf-8")).hexdigest()


def harness_source_digest() -> str:
    """SHA-256 over this harness's own source bytes.

    Every `.py` under the package, sorted, hashed as `{relpath: sha256}` —
    so the answer is stable under file order and sensitive to one edited
    character.  `harness_commit` says which commit was checked out;
    this says what the tree actually held, and a dirty tree is a different
    harness no matter what the commit says.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = {}
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(names):
            if not name.endswith(".py"):
                continue
            path = os.path.join(base, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            files[rel] = h.hexdigest()
    return hashlib.sha256(_canonical(files).encode("utf-8")).hexdigest()


def harness_commit_identity() -> Optional[str]:
    """This checkout's FULL commit, or None — never a guess, never a short.

    `runner._harness_commit` returns the 7-character form for row stamps,
    where it is a pointer a human greps with.  An identity carries the whole
    name: a 7-hex prefix is a 28-bit space, and two attempts of one campaign
    are exactly the case where a near-collision would be invisible.
    """
    try:
        import subprocess
        cp = subprocess.run(
            ["git", "-C", os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
             "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10)
        out = (cp.stdout or "").strip()
        if cp.returncode != 0 or len(out) != 40 \
                or any(c not in "0123456789abcdef" for c in out):
            return None
        return out
    except Exception:                                       # noqa: BLE001
        return None


_AGENT_RUNTIME_PREFIX = "R2T_AGENT_RUNTIME="

# One program, one subprocess.  In particular, package metadata and
# `sitecustomize` are read by the interpreter that will run the agent, not by
# the coordinator which happened to launch `r2t campaign`.
_AGENT_RUNTIME_PROBE = r"""
import hashlib
import json
import os
import platform
import sys
from importlib import metadata

distributions = {}
for dist in metadata.distributions():
    name = dist.metadata.get("Name")
    if name:
        distributions[name] = dist.version

sitecustomize_sha256 = None
try:
    import sitecustomize
    path = getattr(sitecustomize, "__file__", None)
    if path and os.path.isfile(path):
        with open(path, "rb") as fh:
            sitecustomize_sha256 = hashlib.sha256(fh.read()).hexdigest()
except Exception:
    pass

controls = {name: os.environ.get(name) for name in %r}
payload = {
    "interpreter": "{} {} ({})".format(
        platform.python_implementation(), platform.python_version(),
        sys.version_info.releaselevel),
    "distributions": distributions,
    "sitecustomize_sha256": sitecustomize_sha256,
    "environment_controls": controls,
}
print(%r + json.dumps(payload, sort_keys=True))
""" % (RUNTIME_ENVIRONMENT_CONTROLS, _AGENT_RUNTIME_PREFIX)


def _distribution_name(name: str) -> str:
    """The spelling both requirements files and importlib metadata share."""
    return re.sub(r"[-_.]+", "-", name).lower()


def exact_requirements_lock(path: str) -> dict[str, str]:
    """Read an installable lock containing only exact `name==version` pins."""
    locked: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for number, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.count("==") != 1:
                raise SystemExit(
                    f"REFUSED: {path}:{number} is not an exact installable "
                    f"name==version pin: {line!r}")
            name, version = (part.strip() for part in line.split("==", 1))
            if not name or not version:
                raise SystemExit(
                    f"REFUSED: {path}:{number} is not an exact installable "
                    f"name==version pin: {line!r}")
            key = _distribution_name(name)
            if key in locked:
                raise SystemExit(
                    f"REFUSED: {path}:{number} pins {key!r} twice; an exact "
                    f"runtime lock names each distribution once")
            locked[key] = version
    if not locked:
        raise SystemExit(f"REFUSED: agent runtime lock {path} has no pins")
    return locked


def probe_agent_runtime(*, interpreter: str, network_semantics: str,
                        agent_system: Optional[str] = None,
                        requirements_lock: Optional[str] = None) -> dict:
    """Probe INTERPRETER once and validate its complete locked environment."""
    import subprocess

    env = os.environ.copy()
    env["PYTHONNOUSERSITE"] = "1"
    try:
        cp = subprocess.run(
            [interpreter, "-c", _AGENT_RUNTIME_PROBE],
            capture_output=True, text=True, timeout=30, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SystemExit(
            f"REFUSED: could not probe agent interpreter {interpreter!r}: "
            f"{type(e).__name__}: {e}")
    if cp.returncode != 0:
        detail = (cp.stderr or cp.stdout or "no diagnostic").strip()[-500:]
        raise SystemExit(
            f"REFUSED: agent interpreter {interpreter!r} runtime probe "
            f"exited {cp.returncode}: {detail}")
    encoded = next((line[len(_AGENT_RUNTIME_PREFIX):]
                    for line in reversed((cp.stdout or "").splitlines())
                    if line.startswith(_AGENT_RUNTIME_PREFIX)), None)
    if encoded is None:
        raise SystemExit(
            f"REFUSED: agent interpreter {interpreter!r} returned no "
            f"runtime probe record")
    try:
        observed = json.loads(encoded)
        actual = {_distribution_name(str(name)): str(version)
                  for name, version in observed["distributions"].items()}
        interpreter_identity = observed["interpreter"]
        controls = observed["environment_controls"]
        sitecustomize_sha256 = observed.get("sitecustomize_sha256")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as e:
        raise SystemExit(
            f"REFUSED: agent interpreter {interpreter!r} returned a malformed "
            f"runtime probe record: {e}")

    # SECTION 4.1 OF THE RESULT-V3 AGENT PRODUCER AMENDMENT, AND WHY IT DOES
    # NOT CLOSE THIS FUNCTION.  For an agent campaign the companion "is built
    # from this selected backend, never by probing the coordinator
    # interpreter" -- and even though this probe now interrogates the
    # SELECTED interpreter in a subprocess (the agent backend's own python
    # under its exact requirements lock, when the caller names one), its
    # output is still not that document: `result_ledger_v2.
    # build_agent_runtime_manifest` is the backend-built one, and it always
    # carries `agent_versions.agent_backend_runtime_digest`, which nothing
    # below can emit.  That difference is what the publication gate reads:
    # section 4.1's companion is rebuilt from the plan's backend and compared
    # whole (`result_ledger_v2.verify_campaign_agent_runtime`), so a probed
    # document is inadmissible there no matter which system named it.
    #
    # Refusing HERE instead would reach further than the amendment does.
    # Section 10 keeps campaign behavior unchanged "without explicit agent
    # publication mode", section 3 fixes that mode as `run --publication-v3
    # --adapter {openhands|aider}`, and this function's callers -- campaign
    # creation and the pre-Docker drift check of a campaign already on disk --
    # are never in it.  So `openhands` and `aider` stay probeable, exactly as
    # every other system is, and the amendment binds where it says it does.
    if requirements_lock is not None:
        locked = exact_requirements_lock(requirements_lock)
        # pip is the installer, not an agent dependency, and `pip freeze`
        # deliberately omits it.  Every other visible distribution is part of
        # the exact environment: adding one is as much a lock mismatch as
        # changing a version.
        installed = {name: version for name, version in actual.items()
                     if name != "pip"}
        missing = sorted(set(locked) - set(installed))
        unexpected = sorted(set(installed) - set(locked))
        mismatched = sorted(
            name for name in set(locked) & set(installed)
            if locked[name] != installed[name])
        if missing or unexpected or mismatched:
            details = []
            if missing:
                details.append("missing " + ", ".join(
                    f"{name}=={locked[name]}" for name in missing))
            if mismatched:
                details.append("version mismatch " + ", ".join(
                    f"{name}: installed {installed[name]}, "
                    f"lock requires {locked[name]}" for name in mismatched))
            if unexpected:
                details.append("not locked " + ", ".join(
                    f"{name}=={installed[name]}" for name in unexpected))
            raise SystemExit(
                f"REFUSED: agent interpreter {interpreter!r} does not exactly "
                f"match {requirements_lock}: " + "; ".join(details))

    versions: dict = dict(sorted(actual.items()))
    if agent_system:
        versions["agent_system"] = agent_system
    versions["sitecustomize_sha256"] = sitecustomize_sha256
    return agent_runtime_manifest(
        interpreter=interpreter_identity,
        agent_versions=versions,
        environment_controls=controls,
        network_semantics=network_semantics)


# --------------------------------------------------------------------------
# Registered legacy generation evidence
# --------------------------------------------------------------------------

#: The generation evidence that predates v2 and is admitted anyway, by name.
#:
#: WHY A REGISTRY AND NOT A FLAG.  A `--legacy` flag would admit any run file
#: an operator pointed it at.  This admits exactly the documents the owner
#: ruled on, bound to the exact bytes they name.  Every registered legacy
#: digest is recipe evidence whose schema cannot identify an attempt.  Cell 3
#: additionally records a realized collision: two different attempts really
#: did share its digest.  What identifies either admitted legacy input is the
#: pair of full SHA-256 values below, not the 16 hex characters.
#:
#: The Cell 3 entry, in the owner's words: the corrected candidate "is
#: admitted to phase B only as explicitly labelled `legacy_exact_bytes`
#: generation evidence bound to corrected run SHA-256 `6c5527e4…` and
#: generated-tests SHA-256 `ef4ebcc9…`, with generation digest
#: `971f1c00943040d5` recorded as known-nonunique legacy recipe evidence and
#: the historical 16-hex `12c5ad81f6561c70` a cross-check reproduced by
#: `mutation_attestation.solution_digest`, not an attempt identity."
#:
#: `historical_solution_digest` is therefore NOT an identity field anywhere.
#: It is here so that an operator holding the old 16-hex spelling (the one
#: `SLICE1_IMPLEMENTATION_REVIEW.md`'s phase-B gate was written in) can match
#: it to the 64-hex spelling a native campaign records, which is review
#: finding 13's misidentification window.
#:
#: The Cell 4 entry is the second exact input frozen by
#: `GATE_POPULATION_V2_DOCX.md`.  The owner's 2026-08-05 authorization for all
#: non-paid canonical work in that plan admits these bytes to C5 only as
#: `legacy_exact_bytes`: its v1 recipe digest cannot establish an attempt,
#: runtime, harness, or network identity.  The inherited row facts below are
#: cross-checks, not an upgrade of that evidence class.
#:
#: Keyed by RUN SHA-256, because that exact-byte identity is what a caller must
#: hold before scoring a candidate.  A generation digest may cross-check the
#: selected record, but can never select one: registry-local uniqueness is not
#: evidence that a v1 recipe digest identified one real-world attempt.
LEGACY_GENERATION_EVIDENCE: dict = {
    "6c5527e4ca6511c3db44eeadfeae10cfb162a578fad25076e79fcc55b6d2301c": {
        "schema": "r2t.legacy-generation-evidence/v1",
        "label": "a5_cell3_python_docx_openhands_corrected",
        "generation_campaign_digest": "971f1c00943040d5",
        "generation_campaign_digest_known_nonunique": True,
        "candidate_run_sha256":
            "6c5527e4ca6511c3db44eeadfeae10cfb162a578fad25076e79fcc55b6d2301c",
        "candidate_generated_tests_sha256":
            "ef4ebcc9d8fb66907f7672a45790490efb7a28b04ca9c9a8c9b4cd513e50517a",
        "historical_solution_digest": "12c5ad81f6561c70",
        "authority": "SLICE1_OWNER_RULINGS.md (PR M0) — approvals for "
                     "dependent implementation",
    },
    "03bab48c7cc4225eb45300cecaf16eb5c80518174cb1e523a01afe1da8eff1e0": {
        "schema": "r2t.legacy-generation-evidence/v1",
        "label": "a5_cell4_python_docx_aider",
        "generation_campaign_digest": "8c72ba3e579d4bad",
        "candidate_run_sha256":
            "03bab48c7cc4225eb45300cecaf16eb5c80518174cb1e523a01afe1da8eff1e0",
        "candidate_generated_tests_sha256":
            "e7f175c742a3a11af1ba1822f9607e6a4795be49d5700fc05f1917d45a8a66c2",
        "historical_solution_digest": "b151752f3241ffab",
        "generation_condition": "c3",
        "generation_protocol_version": 4,
        "generation_protocol_digest": "bda1d9bcb1852e92",
        "generation_native_budget": {"max_reflections": 10},
        "authority": "GATE_POPULATION_V2_DOCX.md — frozen Cell 4 exact-byte "
                     "authorization, 2026-08-05",
    },
}


def legacy_generation_evidence(*, run_sha256: Optional[str] = None,
                               generation_campaign_digest: Optional[str] = None
                               ) -> Optional[dict]:
    """The registered record for these exact bytes, or None.

    Never a partial match: a caller that supplies both a run digest and a
    generation digest gets a record only when the record agrees with BOTH.
    The whole point of an entry is that the 16-hex legacy generation digest
    cannot establish attempt identity.  Resolution therefore REQUIRES the
    full run SHA-256.  A supplied generation digest is only a second
    cross-check; registry-local cardinality can never turn a recipe digest
    into evidence that it uniquely identifies a real-world attempt.
    """
    record = (LEGACY_GENERATION_EVIDENCE.get(run_sha256)
              if run_sha256 is not None else None)
    if record is None:
        return None
    if generation_campaign_digest is not None \
            and record["generation_campaign_digest"] \
            != generation_campaign_digest:
        return None
    # Cell 4 carries a nested native-budget cross-check.  A shallow copy would
    # hand callers a reference into the registry and let an innocent-looking
    # local edit change which exact evidence later calls admit.
    return copy.deepcopy(record)


# --------------------------------------------------------------------------
# Level 2 — the worker manifest
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class WorkerManifest:
    """What worker *k* claims it was, and what it wrote (§3.6.2).

    Frozen because the merge compares these values against every other
    worker's: a manifest that could be edited after the disjointness check
    would make the check advisory.
    """

    shard: int
    workspace: str
    container: str
    schema: str
    credential: str
    out_path: str
    artifacts_root: str
    started_at: Optional[str]
    finished_at: Optional[str]
    campaign_digest: str

    def __post_init__(self) -> None:
        if isinstance(self.shard, bool) or not isinstance(self.shard, int) \
                or self.shard < 0:
            raise ValueError(f"shard must be an int >= 0, got {self.shard!r}")
        for f in ("workspace", "container", "out_path", "artifacts_root",
                  "campaign_digest"):
            v = getattr(self, f)
            if not isinstance(v, str) or not v.strip():
                raise ValueError(f"{f} must be a non-empty string, got {v!r}")
        # The database legs are the one pair that may be EMPTY, and empty
        # here MEANS "this stack has no such resource" (`DATABASE_RESOURCES`
        # above).  Still required to be strings, so a `None` that slipped in
        # from a hand-written manifest is still refused; and `merge_shards`
        # still refuses two workers that share a NON-empty one.
        for f in DATABASE_RESOURCES:
            v = getattr(self, f)
            if not isinstance(v, str):
                raise ValueError(
                    f"{f} must be a string — empty exactly where the stack "
                    f"declares no database (profile "
                    f"`runtime.needs_database: false`) — got {v!r}")
        for f in ("started_at", "finished_at"):
            v = getattr(self, f)
            if v is not None and not isinstance(v, str):
                raise ValueError(f"{f} must be an ISO timestamp string or None "
                                 f"(a manifest written at start has no finish "
                                 f"time yet), got {v!r}")
        d = self.campaign_digest
        if len(d) != 16 or any(c not in "0123456789abcdef" for c in d):
            # An empty or placeholder digest compares EQUAL to another
            # empty one, so the "same campaign" check would pass over two
            # manifests that record nothing at all.
            raise ValueError(f"campaign_digest must be 16 lowercase hex chars "
                             f"as produced by campaign_digest(), got {d!r}")
        _check_credential_identity(self.credential)
        # Relative paths are not identities: two workers started from
        # different working directories can both declare `runs/out.jsonl`,
        # pass the disjointness check, and append to the same file.
        for f in _PATH_RESOURCES:
            v = getattr(self, f)
            if not os.path.isabs(v):
                raise ValueError(f"{f} must be an absolute path, got {v!r}")
            object.__setattr__(self, f, os.path.normpath(v))

    def to_json(self) -> dict:
        return {f: getattr(self, f) for f in WORKER_FIELDS}

    @classmethod
    def from_json(cls, doc: dict) -> "WorkerManifest":
        missing = [f for f in WORKER_FIELDS if f not in doc]
        unknown = sorted(k for k in doc if k not in WORKER_FIELDS)
        if missing or unknown:
            raise ValueError(
                "worker manifest has the wrong shape"
                + (f"; missing {missing}" if missing else "")
                + (f"; unknown {unknown}" if unknown else ""))
        return cls(**{f: doc[f] for f in WORKER_FIELDS})


def _check_credential_identity(cred: str) -> None:
    """Refuse anything DSN-shaped reaching a run stamp (§3.2).

    Two shapes, because both have been typed into a config by someone who
    meant well: `mysql://bench_3:hunter2@db/coreshop_bench_3` (a URL) and
    `bench_3:hunter2` (a user:password pair pasted from a docker env
    file).  The rule is deliberately crude — a user name has no business
    containing `://` or a `:` at all.  `bench_3@localhost` is left alone
    because `user@host` is how MySQL names a principal and carries no
    secret; it is the colon that separates a name from a password.
    """
    low = cred.lower()
    if "://" in low:
        raise SecretInManifest(
            f"refusing credential {cred.split('://')[0]}://… as a worker "
            f"identity: a DSN carries the password and the manifest is "
            f"published next to the merged rows. Record the non-secret user "
            f"identity, e.g. 'bench_3' (SPEC_C3_PARALLEL §3.2).")
    colon = cred.find(":")
    if colon != -1:
        # An earlier form of this rule additionally demanded an `@` after
        # the colon, which accepted the exact string the docstring above
        # names as the second bad shape: `bench_3:hunter2` reached the
        # stamp with the password in it.  A colon anywhere is enough.
        raise SecretInManifest(
            f"refusing credential {cred[:colon]}:… as a worker identity: a "
            f"`:` separates a user name from a password, so this is a "
            f"connection string, not an identity. Record the non-secret user "
            f"identity, e.g. 'bench_3' (SPEC_C3_PARALLEL §3.2).")
    if any(c in cred for c in "\r\n\t"):
        raise SecretInManifest(
            f"refusing credential {cred.splitlines()[0][:32]!r}…: a worker "
            f"identity is one line, and a multi-line value is an env-file "
            f"fragment that probably carries a password "
            f"(SPEC_C3_PARALLEL §3.2).")


def write_worker_manifest(worker: WorkerManifest, campaign: dict,
                          path: str, *,
                          durable_no_clobber: bool = False) -> str:
    """Persist level 2 with the level-1 fingerprint it was produced under.

    The fingerprint is embedded rather than referenced because the merge
    has to verify the digest, not trust it: a worker that copied a digest
    string from another campaign's manifest would otherwise pass check 1.
    """
    digest = campaign_digest(campaign)
    if worker.campaign_digest != digest:
        raise SystemExit(
            f"REFUSED: worker {worker.shard} declares campaign_digest "
            f"{worker.campaign_digest} but the fingerprint it was given "
            f"hashes to {digest}; one of the two is from another campaign.")
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    doc = {"campaign": campaign, "campaign_digest": digest,
           "worker": worker.to_json()}
    payload = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode(
        "utf-8")
    if not durable_no_clobber:
        # Preserve the diagnostic command's historical replace-in-place
        # behavior.  Only explicit publication may opt into the stronger
        # evidence-creation contract below.
        with open(path, "wb") as handle:
            handle.write(payload)
        return path
    from . import result_ledger
    try:
        result_ledger.durable_create_bytes_no_clobber(
            os.path.abspath(path), payload, label="WorkerManifest")
    except result_ledger.ResultLedgerRefused as exc:
        raise SystemExit(str(exc)) from exc
    return path


# --------------------------------------------------------------------------
# H4 — deterministic sharding
# --------------------------------------------------------------------------

def shard_of(item_id: str, k: int) -> int:
    """Which worker owns `item_id` in a K-way campaign.

    CONTENT-based, not positional.  `enumerate(items) % K` would reassign
    roughly every item the moment one instance is added to or dropped from
    the release, so two campaigns run a week apart would execute different
    items on different workspaces while both claiming to be K-way runs of
    "the release" — and a per-worker effect (a stale `var/classes`, a
    slower disk) would move silently between them.  Hashing the item id
    means adding an item disturbs only that item's assignment.

    sha1 is a distribution function here, not a security claim; it matches
    `runner.item_key`, so a worker's shard and its artifact directory are
    derived from the same bytes.
    """
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise SystemExit(f"REFUSED: shard count must be an int >= 1, got {k!r}")
    return int(hashlib.sha1(item_id.encode("utf-8")).hexdigest(), 16) % k


def assign_shards(item_ids: Iterable[str], k: int) -> dict[int, list[str]]:
    """`{shard: [item_id, ...]}` with EVERY index 0..k-1 present.

    Empty shards are kept rather than dropped because the merge demands
    exactly one manifest per expected shard: if a small filtered release
    left shard 3 empty and this returned three keys, the coordinator would
    start three workers and the merge would then be checking a K it was
    never run at.

    Input order is preserved inside each shard so a worker executes the
    release in release order, which is what its resume logic assumes.
    """
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise SystemExit(f"REFUSED: shard count must be an int >= 1, got {k!r}")
    ids = list(item_ids)
    seen: set[str] = set()
    dupes = sorted({i for i in ids if i in seen or bool(seen.add(i))})
    if dupes:
        # A duplicated id would be executed twice on the same worker and
        # then trip the merge's no-duplicate check hours later; refusing
        # now costs nothing and names the real fault (the caller's list).
        raise SystemExit(f"REFUSED: {len(dupes)} item id(s) appear more than "
                         f"once in the input, e.g. {dupes[:3]}")
    out: dict[int, list[str]] = {i: [] for i in range(k)}
    for iid in ids:
        out[shard_of(iid, k)].append(iid)
    return out


def assign_ordered_shards(item_ids: Iterable[str], k: int
                          ) -> dict[int, list[str]]:
    """Partition a frozen ordered view by ``position % k``."""
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise SystemExit(f"REFUSED: shard count must be an int >= 1, got {k!r}")
    ids = list(item_ids)
    if len(ids) != len(set(ids)):
        raise SystemExit("REFUSED: ordered positional view has duplicate item ids")
    out = {index: [] for index in range(k)}
    for position, item_id in enumerate(ids):
        out[position % k].append(item_id)
    return out


# --------------------------------------------------------------------------
# Level 3 — the strict merge
# --------------------------------------------------------------------------

def _read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _read_rows(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit(f"REFUSED: {path}:{n} is not JSON ({e}); a "
                                 f"half-written row means the worker died "
                                 f"mid-write and its shard is incomplete")
            if not isinstance(row, dict) or not row.get("item_id"):
                raise SystemExit(f"REFUSED: {path}:{n} has no item_id, so it "
                                 f"cannot be attributed to a release item")
            rows.append(row)
    return rows


def _path_conflict(a: str, b: str) -> bool:
    """Do two declared paths name overlapping regions of one filesystem?

    `os.path.realpath` rather than the constructor's `normpath`: normpath
    is lexical, so a workspace declared as `/data/ws1` and another as
    `/data/alias` where `alias` is a symlink to `ws1` are two different
    strings and one directory — which is exactly the collision §3.1 says
    must never happen, dressed up to pass a string comparison.  realpath
    on a path that does not exist yet degrades to the lexical answer, so
    this is never worse than the old rule.
    """
    a_p = os.path.realpath(a).rstrip("/") + "/"
    b_p = os.path.realpath(b).rstrip("/") + "/"
    return a_p.startswith(b_p) or b_p.startswith(a_p)


def _crosscheck_row(campaign: dict, row: dict, shard: int) -> list[str]:
    """Did this row RUN the configuration its campaign asserts? (§3.7)

    The digest checks above prove a row was STAMPED by this campaign.  They
    cannot prove the worker was LAUNCHED with the campaign's arguments,
    because the stamp and the fingerprint are written from two different
    places: `runner._run_stamp` copies the worker's own `args`, while the
    fingerprint was written once by `cli.cmd_campaign` before any worker
    started.  A shard started with `--condition c2`, or with `--trials`
    forgotten, or against a second model, therefore produces rows that carry
    this campaign's digest and a different experiment — and every check
    before this one passes on them.
    """
    problems: list[str] = []
    for cfield, rfield in STAMP_CROSSCHECKS:
        null_is_asserted = cfield in {
            "condition", "protocol_version", "protocol_digest"}
        if null_is_asserted and cfield not in campaign:
            # Historical fingerprints predate these keys.  Absence is the
            # compatibility waiver; a present null in a current fingerprint
            # is a digest-bound assertion of control/no protocol.
            continue
        want = campaign.get(cfield)
        if want is None and not null_is_asserted:
            continue
        if want is None:
            if rfield in row and row[rfield] is not None:
                problems.append(
                    f"shard {shard}: {row.get('item_id')} carries "
                    f"{rfield}={row[rfield]!r}, but the campaign explicitly "
                    f"asserts {cfield}=None")
            continue
        if rfield not in row:
            # An ABSENT stamp field is a refusal, not an unknown, for the
            # same reason `_resume_set` treats it as a mismatch in campaign
            # mode: a row that says nothing about its model is compatible
            # with EVERY model, so admitting it is how a merge ends up
            # internally consistent and provenance-false.
            #
            # trial_budget == 0 is the single documented exception, and it is
            # a fact about the code rather than a convenience: `cli`'s
            # `campaign` subparser declares `--trials` with `default=0` and
            # writes `trial_budget=args.trials`, so every control campaign
            # (gold, stub — neither of which is ever passed --trials) records
            # 0; and `runner._run_stamp` does not put `trials` on a row at
            # all.  Enforcing presence at 0 would refuse every control merge
            # that has ever been made.  It is a waiver on PRESENCE only — a
            # row that does carry `trials` must still carry 0 — so a C3 row
            # cannot hide inside a C2 campaign, and the `condition` check
            # above catches that case regardless.
            #
            # The waiver is written `want == 0` and not `not want`, which
            # matters now that unbounded exists: `UNBOUNDED` is a non-empty
            # string and therefore truthy, so an unbounded campaign still
            # DEMANDS the field on every row.  It has to.  A row that says
            # nothing about its budget is compatible with every budget, and an
            # unbounded arm merging rows that might have been rationed is
            # exactly the substitution this crosscheck exists to catch.
            if cfield == "trial_budget" and want == 0:
                continue
            # The second waiver, and the only other one:
            # `CROSSCHECK_ABSENCE_GRANDFATHERED` holds the fields that are
            # YOUNGER THAN THE ROWS. No row could carry a field the harness
            # had not invented yet, so its absence is unverifiable rather than
            # wrong — the same reading `_resume_set` gives
            # `runner.STAMP_OPTIONAL_FIELDS`. PRESENT-and-different still
            # refuses below, which is the half that stops an aider shard from
            # merging into an OpenHands campaign.
            if cfield in CROSSCHECK_ABSENCE_GRANDFATHERED:
                continue
            problems.append(
                f"shard {shard}: {row.get('item_id')} carries no {rfield!r} "
                f"at all, while the campaign asserts {cfield}={want!r}")
            continue
        got = row[rfield]
        if got != want:
            problems.append(
                f"shard {shard}: {row.get('item_id')} carries {rfield}={got!r}, "
                f"but the campaign asserts {cfield}={want!r}")
    return problems


def _egress_problems(campaign: dict, worker: WorkerManifest) -> list[str]:
    """Refuse a shard whose sealed strict-egress verdict is absent or not clean.

    The quarantine amendment deliberately lets a CONTAMINATED shard seal --
    one fetched row may not take a whole cell down -- so
    `result_ledger_v2.verify_egress_attestation` records the verdict and says
    in as many words that it will not refuse on it.  That pushes the refusal
    outward, and until now it landed in exactly one place:
    `evaluation_execution._refuse_contaminated_campaign`, which only the
    `eval` route runs.  A plain merge read manifests and rows and never looked
    at the verdict at all, so the quarantined rows walked into the merged
    file -- and the merged file is what every metric reads.

    ABSENT IS A DELIBERATE SECOND ANSWER, AND IT TURNS ON WHETHER AN AGENT
    RAN.  The policy that settles it already exists and is not invented here:
    `egress.gate` takes `allow_unassessed`, defaults it to False, and
    `egress_attestation.build_attestation` hard-codes False and refuses to
    seal a run it could not read, so a sealed document always means "we
    looked", never "we did not look".  A merge that shrugged at a missing
    document would quietly convert the second into the first.  So a campaign
    whose fingerprint NAMES an `agent_system` owes a verdict for every shard,
    and a shard without one is refused.

    A campaign that names no system is the other answer.  Every gold,
    stripped and stub control is one: it ran no agent, wrote no trajectory,
    and therefore cannot be attested at all -- `build_attestation` refuses a
    run with `n_no_trajectory`, and there is no trajectory root for it to
    inventory.  Demanding a document that can never be produced would refuse
    every control merge forever, for evidence the gate was never able to
    write, so those proceed.
    """
    # The suffix is `constants`', shared with the agent producer that writes
    # the file: the merge is on the consumer route and must not import the
    # producer for one spelling.
    from ..core.constants import EGRESS_ATTESTATION_SUFFIX
    path = worker.out_path + EGRESS_ATTESTATION_SUFFIX
    system = campaign.get("agent_system")
    if not os.path.isfile(path):
        if not system:
            return []
        return [f"shard {worker.shard} ran {system!r} but has no sealed "
                f"egress attestation at {path}; the strict gate never "
                f"assessed it, and not assessed is not clean"]
    try:
        document = _read_json(path)
    except (OSError, ValueError) as e:
        return [f"shard {worker.shard}: cannot read the sealed egress "
                f"attestation {path}: {e}"]
    status = document.get("status")
    items = document.get("contaminated_items") or []
    if status == "clean" and not items:
        # A /1 document carries no `contaminated_items` key at all, and that
        # is not an omission: /1 sealed ONLY when the run was clean, so its
        # `status` already says everything a /2 item list would.
        return []
    named = ", ".join(sorted(str(item) for item in items)) \
        if isinstance(items, list) and items else "no item is named"
    return [f"shard {worker.shard} was refused by the strict egress gate "
            f"(status {status!r}): {named} -- {path}"]


def merge_shards(manifest_paths: list[str], expected_items: Iterable[str],
                 expected_shards: int) -> dict:
    """Combine K shards into one result, or refuse and say exactly why (§3.7).

    This is the only thing that makes a K-way number comparable to the
    serial numbers already published, so it refuses on any of the five
    conditions in §3.7 rather than merging what it can and noting the
    rest.  A merged file with a quietly missing shard is worse than no
    merged file: it looks like a complete sweep and reads 8 points low.

    Checks run in two stages — metadata first, rows second — so that a
    campaign with a missing shard reports "shard 2 missing" instead of
    "shard 2 missing AND 141 items missing", which is the same fault said
    twice.

    The row stage also reads each shard's sealed egress verdict, because a
    merged file is what every metric reads and this is the last place the
    quarantine can still stop a number; `_egress_problems` holds that check
    and the reasoning behind its absent case.
    """
    if expected_shards < 1:
        raise SystemExit(f"REFUSED: expected_shards must be >= 1, got "
                         f"{expected_shards}")
    if not manifest_paths:
        raise SystemExit("REFUSED: no worker manifests given; a merge with "
                         "nothing to merge is not an empty campaign, it is a "
                         "coordinator that lost its manifests")
    expected_is_ordered = not isinstance(expected_items, (set, frozenset))
    expected_order = list(expected_items)
    if len(expected_order) != len(set(expected_order)):
        raise SystemExit("REFUSED: expected release repeats an item id")
    expected_set = set(expected_order)

    docs: list[tuple[str, dict, WorkerManifest]] = []
    for p in manifest_paths:
        if not os.path.isfile(p):
            raise SystemExit(f"REFUSED: worker manifest {p} does not exist")
        doc = _read_json(p)
        try:
            worker = WorkerManifest.from_json(doc.get("worker") or {})
        except (ValueError, TypeError) as e:
            raise SystemExit(f"REFUSED: {p} does not hold a worker manifest: {e}")
        docs.append((p, doc, worker))

    problems: list[str] = []

    # 1. one campaign, verified rather than asserted.
    digests = {w.campaign_digest for _, _, w in docs}
    if len(digests) > 1:
        by_digest = {}
        for p, _, w in docs:
            by_digest.setdefault(w.campaign_digest, []).append(
                f"shard {w.shard} ({os.path.basename(p)})")
        problems.append("shards come from different campaigns: "
                        + "; ".join(f"{d} <- {', '.join(v)}"
                                    for d, v in sorted(by_digest.items())))
    for p, doc, w in docs:
        fp = doc.get("campaign")
        try:
            actual = campaign_digest(fp) if isinstance(fp, dict) else None
        except SystemExit as e:
            problems.append(f"{os.path.basename(p)}: {e}")
            continue
        if actual is None:
            problems.append(f"{os.path.basename(p)} embeds no campaign "
                            f"fingerprint, so its digest cannot be verified")
        elif actual != w.campaign_digest:
            problems.append(
                f"{os.path.basename(p)}: embedded fingerprint hashes to "
                f"{actual} but the manifest declares {w.campaign_digest} — the "
                f"digest was copied, not computed")

    # 1b. ONE IDENTITY VERSION, AND ONE ATTEMPT (PR R3).
    #
    # Both of these are already implied by check 1 — a v1 and a v2 document
    # hash differently, and so do two attempts — but "shards come from
    # different campaigns: 971f1c00943040d5 <- shard 0; 3e7c… <- shard 1" is
    # the wrong sentence for either fault.  An operator reading it goes
    # looking for a mismatched flag; the actual faults are "you are merging
    # evidence written under two identity versions" and "you are merging two
    # ATTEMPTS of one recipe", and only the second sentence tells them the
    # merge can never be made to work.
    #
    # The cross-attempt check is the merge-layer stop finding 20 found
    # missing: under v1 the two Cell 3 attempts hashed alike, so a chimeric
    # shard set (superseded worker0 + corrected worker1..7) merged cleanly
    # with `harness_commit` mixed {'10895b0': 26, 'ae9c751': 6}.
    versions: dict[str, list[str]] = {}
    attempts: dict[object, list[str]] = {}
    for p, doc, w in docs:
        fp = doc.get("campaign")
        if not isinstance(fp, dict):
            continue
        try:
            version = fingerprint_version(fp)
        except SystemExit as e:
            problems.append(f"{os.path.basename(p)}: {e}")
            continue
        where = f"shard {w.shard} ({os.path.basename(p)})"
        versions.setdefault(version, []).append(where)
        if version == "v2":
            attempts.setdefault(fp.get("attempt_id"), []).append(where)
    if len(versions) > 1:
        problems.append(
            "shards mix generation identity versions, which may never be "
            "merged: "
            + "; ".join(f"{v} <- {', '.join(w)}"
                        for v, w in sorted(versions.items()))
            + " — a v1 fingerprint records no attempt, no harness bytes and "
              "no runtime, so a v2 shard merged beside one would inherit "
              "identity it never had")
    if len(attempts) > 1:
        problems.append(
            "shards come from different ATTEMPTS of one recipe: "
            + "; ".join(f"{a!r} <- {', '.join(w)}"
                        for a, w in sorted(attempts.items(),
                                           key=lambda kv: str(kv[0])))
            + " — a re-run is a new campaign, not more of the old one; merge "
              "each attempt's shards among themselves")

    # 2. exactly one manifest per expected shard.  The fingerprint's own
    #    `k_workers` is checked against the K being merged: a campaign
    #    provisioned for 4 workers and merged as 3 would report "all
    #    shards present" over a quarter of the release that never ran.
    for _p, doc, _w in docs:
        fp_k = (doc.get("campaign") or {}).get("k_workers") \
            if isinstance(doc.get("campaign"), dict) else None
        if isinstance(fp_k, int) and fp_k != expected_shards:
            problems.append(f"the campaign fingerprint declares k_workers="
                            f"{fp_k} but this merge expects "
                            f"{expected_shards} shard(s)")
            break
    by_shard: dict[int, list[str]] = {}
    for p, _, w in docs:
        by_shard.setdefault(w.shard, []).append(os.path.basename(p))
    missing = sorted(s for s in range(expected_shards) if s not in by_shard)
    extra = sorted(s for s in by_shard if s >= expected_shards or s < 0)
    duplicated = sorted(s for s, v in by_shard.items() if len(v) > 1)
    if missing:
        problems.append(f"no manifest for shard(s) {missing} of "
                        f"K={expected_shards}; those items never ran")
    if extra:
        problems.append(f"manifest(s) for shard(s) {extra} outside "
                        f"0..{expected_shards - 1}")
    if duplicated:
        problems.append("; ".join(f"shard {s} has {len(by_shard[s])} manifests "
                                  f"({', '.join(by_shard[s])})"
                                  for s in duplicated))

    # 3. the workers really were disjoint (§3.1: the triple is provisioned
    #    and torn down together; sharing any leg of it re-creates the
    #    29%-disagreement failure the whole design exists to prevent).
    for i in range(len(docs)):
        for j in range(i + 1, len(docs)):
            a, b = docs[i][2], docs[j][2]
            for field in _EQ_RESOURCES:
                va, vb = getattr(a, field), getattr(b, field)
                # Two ABSENT database legs are not a shared one.  A stack
                # with no database gives every worker the empty schema and
                # the empty credential (`DATABASE_RESOURCES`), and two empty
                # strings compare equal — so this check would have refused
                # every K>1 behave campaign for sharing a resource that does
                # not exist.  The exemption is exactly "both are declared
                # absent": one empty against one named is still a mismatch
                # worth seeing, and two NAMED ones are compared unchanged,
                # which is what keeps CoreShop's refusals byte-identical.
                if field in DATABASE_RESOURCES and not va and not vb:
                    continue
                if va == vb:
                    problems.append(
                        f"shards {a.shard} and {b.shard} share {field}: "
                        f"{va!r} vs {vb!r}")
            # Path resources are compared ACROSS fields as well as within
            # them: worker 1's workspace sitting inside worker 0's
            # artifacts_root is not a naming coincidence, it means worker
            # 0's teardown deletes worker 1's checkout.  Same-worker
            # nesting (a worker's own out file under its own artifact
            # root) is fine and is never compared, because i < j.
            for fa in _PATH_RESOURCES:
                for fb in _PATH_RESOURCES:
                    va, vb = getattr(a, fa), getattr(b, fb)
                    if not _path_conflict(va, vb):
                        continue
                    if fa == fb:
                        problems.append(
                            f"shards {a.shard} and {b.shard} share {fa}: "
                            f"{va!r} vs {vb!r}")
                    else:
                        problems.append(
                            f"shard {a.shard}'s {fa} {va!r} overlaps shard "
                            f"{b.shard}'s {fb} {vb!r}; one worker writes "
                            f"inside the other's tree")
    if problems:
        raise SystemExit("REFUSED: cannot merge these shards into one "
                         "campaign:\n  - " + "\n  - ".join(problems))

    # Rows are taken VERBATIM: the merge adds no shard field, so a K-way
    # merged file and a K=1 file over the same release differ only in row
    # order, and every downstream metric reads both without knowing which
    # it has.
    rows: list[dict] = []
    origin: dict[str, list[int]] = {}
    unbound: list[str] = []
    misconfigured: list[str] = []
    for _, wdoc, w in sorted(docs, key=lambda d: d[2].shard):
        # The shard's OWN embedded fingerprint, not `docs[0]`'s: they have
        # all been proved to hash alike by now, so the two are the same
        # document, and reading the local one keeps the refusal message and
        # the evidence it names in the same file.
        camp = wdoc.get("campaign") or {}
        if not os.path.isfile(w.out_path):
            problems.append(f"shard {w.shard} declares out_path {w.out_path}, "
                            f"which does not exist")
            continue
        # Read HERE and not with the metadata, so that a shard whose out file
        # is missing reports that one fault and not also the absent
        # attestation that missing file guarantees.
        problems.extend(_egress_problems(camp, w))
        for row in _read_rows(w.out_path):
            # Every row must SAY which campaign it belongs to. Checking only
            # the manifest checks the claim, not the evidence.
            got = row.get("campaign_digest")
            if got != w.campaign_digest:
                unbound.append(
                    f"shard {w.shard}: {row.get('item_id')} carries "
                    f"campaign_digest {got!r}, not {w.campaign_digest}")
            if row.get("shard") not in (None, w.shard):
                unbound.append(
                    f"shard {w.shard}: {row.get('item_id')} was stamped by "
                    f"shard {row.get('shard')}")
            misconfigured.extend(_crosscheck_row(camp, row, w.shard))
            rows.append(row)
            origin.setdefault(row["item_id"], []).append(w.shard)
    if unbound:
        problems.append(
            f"{len(unbound)} row(s) are not bound to this campaign, e.g. "
            + "; ".join(unbound[:3])
            + " — run with --campaign so every row is stamped")
    if misconfigured:
        problems.append(
            f"{len(misconfigured)} row(s) did not run the configuration this "
            f"campaign asserts, e.g. " + "; ".join(misconfigured[:3])
            + " — the shard was launched with arguments the campaign it is "
              "being merged under does not describe, so merging would publish "
              "one arm's number under another arm's fingerprint")
    if problems:
        raise SystemExit("REFUSED: cannot merge these shards into one "
                         "campaign:\n  - " + "\n  - ".join(problems))

    dupes = sorted(i for i, v in origin.items() if len(v) > 1)
    if dupes:
        # Two shapes, and the message must not name the wrong one: an id
        # on two shards means the assignment was not a partition, while
        # an id twice on ONE shard means that worker executed it twice
        # (the resume path re-ran it) and neither row is the result.
        cross = [i for i in dupes if len(set(origin[i])) > 1]
        within = [i for i in dupes if len(set(origin[i])) == 1]
        if cross:
            problems.append(
                f"{len(cross)} item id(s) appear in more than one shard, e.g. "
                + "; ".join(f"{i} on shards {sorted(origin[i])}"
                            for i in cross[:3])
                + " — the shard assignment was not a partition, so the "
                  "duplicate rows are two different executions of one item")
        if within:
            problems.append(
                f"{len(within)} item id(s) appear more than once within a "
                "single shard, e.g. "
                + "; ".join(f"{i} x{len(origin[i])} on shard {origin[i][0]}"
                            for i in within[:3])
                + " — one worker emitted the same item twice, so which row "
                  "is the result is undefined")

    # Every row must be on the worker the SHARD RULE assigns it to.
    #
    # Set equality is not enough, and this is the gap it leaves: swap two
    # workers' `--shard` arguments in the launcher and the merge sees no
    # duplicates and exactly the expected set, so it passes — while each
    # worker executed the other's items.  That is invisible in a merged file
    # and it makes the campaign's own fingerprint a lie, since the
    # fingerprint records `shard_rule` precisely so this is checkable.
    #
    # Only checked for the rule the fingerprint actually names: a campaign
    # sharded some other way is not wrong, it is out of scope for this check.
    rule = (docs[0][1].get("campaign") or {}).get("shard_rule")
    if rule == SHARD_RULE:
        misplaced = [(i, origin[i][0], shard_of(i, expected_shards))
                     for i in sorted(origin)
                     if origin[i][0] != shard_of(i, expected_shards)]
        if misplaced:
            problems.append(
                f"{len(misplaced)} item(s) were executed by a worker the "
                f"shard rule {rule!r} does not assign them to, e.g. "
                + "; ".join(f"{i} ran on shard {was} but belongs to {want}"
                            for i, was, want in misplaced[:3])
                + " — two workers most likely swapped their --shard "
                  "arguments, which set equality cannot see")
    elif rule == POSITIONAL_SHARD_RULE:
        if not expected_is_ordered:
            problems.append(
                "positional shard verification requires the frozen ordered "
                "release, not an unordered item set")
        else:
            assigned = assign_ordered_shards(expected_order, expected_shards)
            owner = {item_id: shard for shard, item_ids in assigned.items()
                     for item_id in item_ids}
            misplaced = [(item_id, origin[item_id][0], owner[item_id])
                         for item_id in expected_order if item_id in origin
                         and origin[item_id][0] != owner[item_id]]
            if misplaced:
                problems.append(
                    f"{len(misplaced)} item(s) were executed by a worker the "
                    f"positional shard rule does not assign them to, e.g. "
                    + "; ".join(
                        f"{item_id} ran on shard {was} but belongs to {want}"
                        for item_id, was, want in misplaced[:3]))

    # A worker that has not finished is not a shard yet.
    #
    # `finished_at=None` is allowed at CONSTRUCTION, because a worker writes
    # its manifest when it starts and again when it stops.  It is not allowed
    # at MERGE: reading a still-growing out file produces a merge that happens
    # to line up, and it will not line up the same way a minute later.
    unfinished = sorted(w.shard for _, _, w in docs if not w.finished_at)
    if unfinished:
        problems.append(
            f"shard(s) {unfinished} have no finish time, so they were still "
            f"running when this merge read their out files")

    got = set(origin)
    absent = sorted(expected_set - got)
    unexpected = sorted(got - expected_set)
    if absent:
        problems.append(f"{len(absent)} expected item(s) that no shard "
                        f"produced, e.g. {absent[:3]}")
    if unexpected:
        problems.append(f"{len(unexpected)} item(s) in the rows that are not "
                        f"in the expected release, e.g. {unexpected[:3]}")
    if problems:
        raise SystemExit("REFUSED: cannot merge these shards into one "
                         "campaign:\n  - " + "\n  - ".join(problems))

    return {
        "campaign": docs[0][1]["campaign"],
        "campaign_digest": docs[0][2].campaign_digest,
        "workers": [w.to_json() for _, _, w in sorted(docs,
                                                      key=lambda d: d[2].shard)],
        # Sorted by item id, so merging the same shards in any argument
        # order gives a byte-identical file and two merges can be diffed.
        "rows": sorted(rows, key=lambda r: r["item_id"]),
        "n": len(rows),
    }


def write_merged(result: dict, out_path: str) -> str:
    """The merged rows, plus a sidecar saying what produced them.

    A merged JSONL is indistinguishable from a serial one by design, which
    means that on its own it cannot answer "which image, which seed, how
    many workers?".  `<out>.campaign.json` travels with it and carries the
    fingerprint and every worker manifest, plus a digest of the rows file
    so the pair can be checked rather than assumed to belong together.
    """
    for key in ("campaign", "campaign_digest", "workers", "rows"):
        if key not in result:
            raise SystemExit(f"REFUSED: merge result has no {key!r}; only the "
                             f"output of merge_shards may be written, because "
                             f"only it has been checked")
    _validate_fingerprint(result["campaign"])
    # The sidecar's whole job is to let a reader check the pair rather
    # than assume it; a digest copied in beside a different fingerprint
    # would make it assert something it never verified.  This is the same
    # rule `write_worker_manifest` applies at level 2.
    actual = campaign_digest(result["campaign"])
    if result["campaign_digest"] != actual:
        raise SystemExit(
            f"REFUSED: the result declares campaign_digest "
            f"{result['campaign_digest']!r} but its fingerprint hashes to "
            f"{actual}; the sidecar would publish a digest nothing produced")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    payload = "".join(json.dumps(r, sort_keys=True) + "\n"
                      for r in result["rows"])
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(payload)
    side = out_path + ".campaign.json"
    with open(side, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "campaign": result["campaign"],
            "campaign_digest": result["campaign_digest"],
            "workers": result["workers"],
            "n": len(result["rows"]),
            "rows_path": os.path.basename(out_path),
            "rows_digest": hashlib.sha256(
                payload.encode("utf-8")).hexdigest()[:16],
        }, sort_keys=True, indent=2) + "\n")
    return out_path


def _publication_merge_request(
        source_receipt_paths: Iterable[str], release_path: str,
        out_path: str, expected_shards: int) -> tuple[list[str], str, str, int]:
    """Validate only explicit merge identities; read no source evidence."""
    from . import result_ledger as ledger
    if not isinstance(expected_shards, int) \
            or isinstance(expected_shards, bool) or expected_shards < 1:
        raise ledger._refuse(
            "strict merge expected shard count must be an integer >= 1")
    paths = [
        ledger.canonical_absolute_path(
            path, "source receipt path", live=False)
        for path in source_receipt_paths]
    if not paths:
        raise ledger._refuse(
            "merge --publication-v3 requires explicit source receipts")
    if len(paths) != len(set(paths)):
        raise ledger._refuse(
            "merge --publication-v3 repeats a source receipt path")
    release = ledger.canonical_absolute_path(
        release_path, "strict merge release path", live=False)
    result = ledger.canonical_absolute_path(
        out_path, "merged result path", live=False)
    return paths, release, result, expected_shards


def _publication_merge_existing_matches(
        existing: dict, source_paths: list[str], release_path: str,
        expected_shards: int) -> dict:
    from . import result_ledger as ledger
    if set(existing.get("source_receipt_paths", ())) != set(source_paths) \
            or len(existing.get("source_receipt_paths", ())) \
            != len(source_paths):
        raise ledger._refuse(
            "existing merged receipt names different source receipts")
    if existing.get("release_path") != release_path:
        raise ledger._refuse(
            "existing merged receipt names a different release")
    if existing.get("worker_count") != expected_shards:
        raise ledger._refuse(
            "existing merged receipt names a different shard count")
    return {"already_complete": True, **existing}


def merge_publication_v3(
        source_receipt_paths: Iterable[str], *, release_path: str,
        out_path: str, expected_shards: int,
        fault: Optional[Callable[[str], None]] = None) -> dict:
    """Durably publish one strict merged result/sidecar/receipt tuple.

    This is deliberately separate from :func:`merge_shards` and
    :func:`write_merged`; the default diagnostic merge keeps its historical
    bytes, replacement behavior, and manifest-only trust boundary.
    """
    from . import result_ledger as ledger
    from . import runner
    try:
        source_paths, release_path, result_path, expected_shards = (
            _publication_merge_request(
                source_receipt_paths, release_path, out_path,
                expected_shards))
        receipt_path = result_path + ledger.RECEIPT_SUFFIX
        if os.path.lexists(receipt_path):
            # Validate role collisions recursively before the generic
            # receipt resolver is allowed to open/flock the derived lock.
            preliminary = ledger.verify_receipt(receipt_path)
            if preliminary["artifact_kind"] != "merged_run":
                raise ledger._refuse(
                    "result receipt artifact kind differs from merged_run")
            _publication_merge_existing_matches(
                preliminary, source_paths, release_path, expected_shards)
        existing = runner._publication_resolve_existing_receipt(
            result_path, expected_artifact_kind="merged_run")
        if existing is not None:
            return _publication_merge_existing_matches(
                existing, source_paths, release_path, expected_shards)

        # S0 requires all source and output bytes to be stable-read and
        # precomputed before output resolution under the result-scoped lock.
        plan = ledger.prepare_publication_merge(
            source_paths, release_path=release_path,
            result_path=result_path, expected_shards=expected_shards)
        lock_path = runner.publication_lock_path(result_path)
        if lock_path != plan.lock_path:
            raise ledger._refuse(
                "merge planner and producer derive different result locks")
        with runner._PublicationResultLock(result_path) as result_lock:
            existing = runner._publication_existing_receipt_under_lock(
                result_path, expected_artifact_kind="merged_run")
            if existing is not None:
                return _publication_merge_existing_matches(
                    existing, source_paths, release_path, expected_shards)
            result_lock.confirm()
            plan.confirm_sources()
            partial_paths = (
                plan.result_path,
                plan.sidecar_path,
                plan.result_path + ledger.CHECKPOINT_SUFFIX,
                plan.receipt_path,
            )
            if any(os.path.lexists(path) for path in partial_paths):
                raise ledger._refuse(
                    "partial merged result/sidecar/ledger tuple burns this "
                    "output path; choose a new result path")

            def seam(event: str) -> None:
                runner._publication_fault(fault, event)
                result_lock.confirm()
                plan.confirm_sources()

            seam("merge:before_result_create")
            ledger.durable_create_bytes_no_clobber(
                plan.result_path, plan.result_raw, label="merged result",
                fault=seam)
            seam("merge:after_result_create")
            ledger.durable_create_bytes_no_clobber(
                plan.sidecar_path, plan.sidecar_raw,
                label="merged campaign sidecar", fault=seam)
            seam("merge:after_sidecar_create")

            # The candidate receipt is verified twice while absent: once
            # before staging and once immediately before its no-clobber
            # commit.  Both traversals recursively reclose every source.
            ledger.verify_receipt_document(plan.receipt, plan.receipt_path)
            seam("merge:after_receipt_selfverify")
            ledger.verify_receipt_document(plan.receipt, plan.receipt_path)
            if plan.receipt_raw != runner._publication_document_bytes(
                    plan.receipt):
                raise ledger._refuse(
                    "precomputed merged receipt bytes changed")
            seam("merge:before_receipt_create")

            def receipt_seam(event: str) -> None:
                seam(event)
                if event == "merged result receipt:stage_fsync":
                    # Reclose the newly-created output pair after the receipt
                    # staging fsync and immediately before atomic visibility.
                    ledger.verify_receipt_document(
                        plan.receipt, plan.receipt_path)

            ledger.durable_create_bytes_no_clobber(
                plan.receipt_path, plan.receipt_raw,
                label="merged result receipt", fault=receipt_seam)
            seam("merge:after_receipt_create")
        return ledger.verify_receipt(plan.receipt_path)
    except ledger.ResultLedgerRefused as exc:
        raise SystemExit(str(exc)) from exc


def _ctor_ok(fn) -> bool:
    """Did a WorkerManifest constructor accept what it was given?"""
    try:
        fn()
    except (ValueError, TypeError):
        return False
    return True


def selftest() -> int:
    """Every negative case §3.7 names, plus the sharding invariants.

    Container-free and database-free: worker manifests and out files are
    written by hand into a temp directory, which is exactly the fidelity
    the merge needs — it has never seen a container either.
    """
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
        except SystemExit as e:
            msg = str(e)
            miss = [n for n in needles if n not in msg]
            check(name, not miss, f"message lacks {miss}: {msg[:300]}")
        except Exception as e:                             # noqa: BLE001
            check(name, False, f"raised {type(e).__name__}: {e}")
        else:
            check(name, False, "merged instead of refusing")

    def fp_of(**over) -> dict:
        base = dict(campaign_id="c3-pilot", k_workers=3,
                    shard_rule=SHARD_RULE, trial_budget=5,
                    coverage=False, harness_version="v1.4",
                    config_digest="cfg0123456789ab", model=None,
                    container_image_digest="sha256:aa",
                    workspace_seed_digest="ws0123456789abcd",
                    database_dump_digest="db0123456789abcd",
                    protocol_version=2,
                    protocol_digest="0123456789abcdef")
        base.update(over)
        return campaign_fingerprint(**base)

    fp = fp_of()
    check("a fingerprint holds exactly CAMPAIGN_FIELDS",
          tuple(sorted(fp)) == tuple(sorted(CAMPAIGN_FIELDS)), str(sorted(fp)))
    check("an unsupplied optional value is recorded as None, not dropped",
          "model" in fp and fp["model"] is None, str(fp))
    refuses("a fingerprint with a missing key is refused, never defaulted",
            lambda: campaign_fingerprint(
                **{f: "x" for f in CAMPAIGN_FIELDS if f != "model"}),
            "REFUSED", "missing", "model")
    refuses("an unknown fingerprint key is refused",
            lambda: campaign_fingerprint(**dict({f: "x" for f in CAMPAIGN_FIELDS},
                                                k_workers=1, gpu="a100")),
            "REFUSED", "unknown", "gpu")
    check("the digest is 16 hex chars",
          len(campaign_digest(fp)) == 16
          and all(c in "0123456789abcdef" for c in campaign_digest(fp)),
          campaign_digest(fp))
    check("the digest ignores key insertion order",
          campaign_digest(dict(reversed(list(fp.items())))) == campaign_digest(fp))
    # Every field, not a sample of two: an earlier version of this check
    # perturbed only `coverage` and `k_workers`, and a digest that
    # silently ignored `harness_version`, `workspace_seed_digest` and
    # `database_dump_digest` still reported ALL PASS — i.e. the merge
    # would have accepted two shards run against different database
    # dumps as one campaign, which is the single thing it exists to stop.
    # Every non-string-typed field needs an entry here: the perturbation below
    # substitutes `f"alt-{f}"` by default, which a validator that demands an
    # int (or 16 hex characters) refuses rather than hashes.
    _alt = {"k_workers": 99, "trial_budget": 7, "coverage": True,
            "protocol_version": 3, "protocol_digest": "fedcba9876543210"}
    unhashed = [f for f in CAMPAIGN_FIELDS
                if campaign_digest(fp_of(**{f: _alt.get(f, f"alt-{f}")}))
                == campaign_digest(fp)]
    check(f"every one of the {len(CAMPAIGN_FIELDS)} campaign fields changes "
          f"the digest", not unhashed, f"ignored by the digest: {unhashed}")

    # ---- the frozen digest vector -----------------------------------------
    #
    # Everything above tests the digest against ITSELF: that two different
    # fingerprints differ, that key order does not matter.  All of it would
    # still print PASS if `_canonical` gained a space, or the hash became
    # sha512, or `[:16]` became `[:12]` — and on that day every archived
    # campaign file would re-hash to something new, i.e. would read as "the
    # digest was copied, not computed", and the published eval100 numbers
    # would stop being verifiable at all.
    #
    # So this vector is a fingerprint literal whose digest was computed ONCE
    # (2026-08-02) and pinned as a constant.  It is SYNTHETIC on purpose: the
    # real-campaign checks at the end of this selftest only run where the
    # archived artifacts happen to be mounted, and canonicalisation has to be
    # nailed down on every machine — a fresh clone with no artifacts must
    # still catch a change to hashing.  If this check fails, the answer is
    # never to re-pin the literal: it means old campaigns no longer verify,
    # which is a release decision taken by a human.
    #
    # A field ADDED to CAMPAIGN_FIELDS later must NOT be added to this dict.
    # Optional-field semantics say a document is hashed exactly as written
    # (`_validate_fingerprint`), so this vector is precisely such an older
    # document and its digest must not move.  A new field earns a SECOND
    # entry in the list below, which is why this is a list: the coverage
    # check asks that the vectors between them exercise every field the
    # digest hashes today, so growth is served by appending, never by editing
    # a pin.
    FROZEN_VECTORS = (
        ("v1 (2026-08-02)", {
            "campaign_id": "r2t-digest-vector-v1",
            "k_workers": 4,
            "shard_rule": "sha1_item_id_mod_k",
            "trial_budget": UNBOUNDED,
            "condition": "c3",
            "coverage": True,
            "harness_version": 5,
            "config_digest": "0123456789abcdef",
            "model": "deepseek-v4-pro",
            "container_image_digest": "sha256:" + "11" * 32,
            "workspace_seed_digest": "22" * 32,
            "database_dump_digest": "33" * 32,
        }, "b8a9c60c8081b280"),
        # v2 (2026-08-02, WS1): the same document plus the protocol pair.
        # APPENDED, not edited: v1 above is a document written before those
        # fields existed and its digest is a promise to every campaign file
        # already on disk. This one exists so the coverage check below still
        # sees every field the digest hashes TODAY.
        ("v2 (2026-08-02, +protocol)", {
            "campaign_id": "r2t-digest-vector-v2",
            "k_workers": 4,
            "shard_rule": "sha1_item_id_mod_k",
            "trial_budget": UNBOUNDED,
            "condition": "c3",
            "coverage": True,
            "harness_version": 6,
            "config_digest": "0123456789abcdef",
            "model": "deepseek-v4-pro",
            "container_image_digest": "sha256:" + "11" * 32,
            "workspace_seed_digest": "22" * 32,
            "database_dump_digest": "33" * 32,
            "protocol_version": 2,
            "protocol_digest": "5b65bf1365b08baa",
        }, "b7b471f3a9eaf49b"),
        # v3 (2026-08-02, Slice 1): the same document plus `agent_system`.
        # APPENDED for the third time, and for the third time the two above
        # are left exactly as they are -- they are documents written before
        # this field existed, and their digests are promises to every campaign
        # file already on disk.
        ("v3 (2026-08-02, +agent_system)", {
            "campaign_id": "r2t-digest-vector-v3",
            "k_workers": 4,
            "shard_rule": "sha1_item_id_mod_k",
            "trial_budget": UNBOUNDED,
            "condition": "c3",
            "coverage": True,
            "harness_version": 6,
            "config_digest": "0123456789abcdef",
            "model": "deepseek-v4-pro",
            "container_image_digest": "sha256:" + "11" * 32,
            "workspace_seed_digest": "22" * 32,
            "database_dump_digest": "33" * 32,
            "protocol_version": 3,
            "protocol_digest": "e6ea6d2471996861",
            "agent_system": "aider",
        }, "a8bdf05c4c0a7be7"),
    )
    covered: set[str] = set()
    for label, vec, pinned in FROZEN_VECTORS:
        covered |= set(vec)
        try:
            got = campaign_digest(vec)
        except SystemExit as e:                                # noqa: BLE001
            got = f"refused: {e}"
        check(f"the frozen synthetic fingerprint {label} still hashes to its "
              f"pinned digest -- canonicalisation and hashing are unchanged",
              got == pinned, f"pinned {pinned}, computed {got}")
    check("the frozen vectors between them cover every field the digest hashes",
          covered == set(CAMPAIGN_FIELDS),
          f"vectors-only {sorted(covered - set(CAMPAIGN_FIELDS))}, "
          f"fields-only {sorted(set(CAMPAIGN_FIELDS) - covered)} -- a field "
          f"just ADDED earns a NEW vector appended above; the existing pins "
          f"are promises made to the archived campaigns and never change")

    # The condition is IN the digest, and a control is not merely "some
    # campaign without an arm".  Two sweeps that differ only in c2 vs c3
    # hashing alike is how a C2 shard and a C3 shard merge into one file.
    check("two experimental arms do not share a campaign digest",
          len({campaign_digest(fp_of(condition=c))
               for c in ("c1.5", "c2", "c3")}) == 3
          and campaign_digest(fp_of(condition="c3")) != campaign_digest(fp))
    check("a control campaign expresses its lack of an arm as a null",
          fp["condition"] is None and "condition" in fp)
    refuses("an empty condition is refused, not treated as a control",
            lambda: fp_of(condition="  "), "REFUSED", "condition must name")

    # ---- the no-database DECLARATION (D6) ---------------------------------
    #
    # Three states, three digests.  Everything a python library's campaign
    # records is real except the database, and the field that says so has to
    # say it rather than be missing: `cli.cmd_campaign` refuses a fingerprint
    # whose identity fields are falsy, so an absent or blank dump digest would
    # be indistinguishable from an unbuilt seed -- and a campaign that
    # fingerprints nothing is the one thing that check exists to prevent.
    declared = fp_of(database_dump_digest=NO_DATABASE)
    check("a stack with no database is a DECLARATION, and a truthy one",
          declared["database_dump_digest"] == NO_DATABASE
          and bool(NO_DATABASE) and NO_DATABASE != "unknown")
    check("declaring no database is a different campaign from recording no "
          "database and from recording one",
          len({campaign_digest(declared),
               campaign_digest(fp_of(database_dump_digest=None)),
               campaign_digest(fp)}) == 3)
    refuses("a blank dump digest is refused rather than hashed like a value",
            lambda: fp_of(database_dump_digest="  "),
            "REFUSED", "database_dump_digest", NO_DATABASE)
    refuses("a non-string dump digest is refused",
            lambda: fp_of(database_dump_digest=0),
            "REFUSED", "database_dump_digest")
    # ONE spelling of the sentinel, shared with the module that writes it into
    # the seed. A second literal is a second thing to keep in step, and the
    # failure mode is a merge refused hours after the sweep was paid for.
    from .seed import NO_DATABASE as SEED_NO_DATABASE
    check("the seed and the fingerprint spell the sentinel the same way",
          SEED_NO_DATABASE is NO_DATABASE)
    # A fingerprint written before `condition` existed must still re-hash to
    # the digest its manifests recorded — otherwise every archived campaign
    # reads as "the digest was copied, not computed" the day the field lands.
    legacy_fp = {k: v for k, v in fp.items() if k != "condition"}
    check("a fingerprint written before `condition` existed still hashes",
          len(campaign_digest(legacy_fp)) == 16
          and campaign_digest(legacy_fp) != campaign_digest(fp),
          campaign_digest(legacy_fp))
    check("an omitted condition is defaulted, but every other omission is not",
          campaign_fingerprint(**{f: v for f, v in fp.items()
                                  if f != "condition"}) == fp)
    # ---- the protocol pair (WS1) ------------------------------------------
    #
    # Same optional-field contract as `condition`, and it has to hold for the
    # same reason: `artifacts/runs/*.campaign.json` predates these keys, and
    # every one of those files must still re-hash to the digest its worker
    # manifests recorded.
    pre_ws1 = {k: v for k, v in fp.items()
               if k not in ("protocol_version", "protocol_digest")}
    check("a fingerprint written before the protocol pair existed still "
          "hashes, and to something OTHER than one that carries it",
          len(campaign_digest(pre_ws1)) == 16
          and campaign_digest(pre_ws1) != campaign_digest(fp),
          campaign_digest(pre_ws1))
    check("nothing fills the pair in on the way back from disk -- the "
          "document is hashed exactly as written",
          campaign_digest(dict(pre_ws1))
          == campaign_digest(json.loads(_canonical(pre_ws1))))
    check("two campaigns that differ ONLY in their protocol are two campaigns",
          campaign_digest(fp_of(protocol_digest="ffffffffffffffff"))
          != campaign_digest(fp))
    check("a campaign that followed no protocol says so with a null pair",
          fp_of(protocol_version=None, protocol_digest=None)["protocol_digest"]
          is None)
    refuses("a protocol_digest that is not the 16 hex a protocol has is "
            "refused, never fingerprinted",
            lambda: fp_of(protocol_digest="v2"),
            "REFUSED", "protocol_digest must be")
    refuses("the DOCUMENT is not an identity: a nested protocol is refused",
            lambda: fp_of(protocol_digest={"condition": "c3"}),
            "REFUSED", "not scalar")
    refuses("protocol_version 0 is refused rather than read as 'no protocol'",
            lambda: fp_of(protocol_version=0), "REFUSED", "protocol_version")
    refuses("half a protocol record is refused -- a digest nobody can name",
            lambda: fp_of(protocol_version=None),
            "REFUSED", "together or not at all")

    # ---- which system (Slice 1) -------------------------------------------
    #
    # The recipe says what a system is told and under which budgets; it does
    # NOT say which system. Two sweeps agreeing on model, image, seed, budget
    # and protocol hashed identically whether an OpenHands scaffold or an
    # aider one produced them, so an aider shard could merge into an OpenHands
    # campaign and every check would pass.
    check("two systems under one recipe are two campaigns, not one",
          campaign_digest(fp_of(agent_system="aider"))
          != campaign_digest(fp_of(agent_system="openhands"))
          and campaign_digest(fp_of(agent_system="openhands"))
          != campaign_digest(fp))
    check("a campaign that asserts nothing about its system says so with a "
          "null, and the key is still there to be hashed",
          fp["agent_system"] is None and "agent_system" in fp)
    refuses("an empty agent_system is refused, not read as 'no system' -- "
            "`--agent-system \"$SYS\"` with SYS unset is how two campaigns "
            "end up agreeing they are one",
            lambda: fp_of(agent_system="  "),
            "REFUSED", "agent_system must name")
    pre_slice1 = {k: v for k, v in fp.items() if k != "agent_system"}
    check("a fingerprint written before `agent_system` existed still hashes, "
          "and to something OTHER than one that carries it",
          len(campaign_digest(pre_slice1)) == 16
          and campaign_digest(pre_slice1) != campaign_digest(fp),
          campaign_digest(pre_slice1))
    check("an omitted agent_system is defaulted like the other optional "
          "fields, and nothing fills it in on the way back from disk",
          campaign_fingerprint(**{f: v for f, v in fp.items()
                                  if f != "agent_system"}) == fp
          and campaign_digest(dict(pre_slice1))
          == campaign_digest(json.loads(_canonical(pre_slice1))))

    check("the canonical form has no whitespace padding",
          ", " not in _canonical(fp) and '": ' not in _canonical(fp))
    refuses("a nested value in a fingerprint is refused",
            lambda: fp_of(model={"name": "deepseek", "temp": 0.0}),
            "REFUSED", "not scalar")
    refuses("a fingerprint with no campaign_id is refused",
            lambda: fp_of(campaign_id="  "), "REFUSED", "campaign_id")
    refuses("a fingerprint that does not name its shard rule is refused",
            lambda: fp_of(shard_rule=None), "REFUSED", "shard_rule")
    refuses("k_workers below 1 is refused in the fingerprint",
            lambda: fp_of(k_workers=0), "REFUSED", "k_workers must be an int")

    # ---- the trial budget's three meanings --------------------------------
    #
    # 0 is "no execution channel at all", a count is the rationed variant, and
    # UNBOUNDED is the shipped C3 arm, whose executions are bounded by the
    # agent's iteration budget instead.  All three must hash differently, or
    # the merge would accept a control shard and an unbounded shard as one
    # campaign — the single thing the fingerprint exists to prevent.
    check("0, a count and unlimited are three different campaigns",
          len({campaign_digest(fp_of(trial_budget=b))
               for b in (0, 5, UNBOUNDED)}) == 3)
    check("an unbounded budget survives the JSON round-trip as itself",
          json.loads(_canonical(fp_of(trial_budget=UNBOUNDED)))["trial_budget"]
          == UNBOUNDED)
    for bad in (-1, True, 2.5, "unlimted", "5"):
        refuses(f"trial_budget={bad!r} is refused rather than fingerprinted",
                lambda bad=bad: fp_of(trial_budget=bad),
                "REFUSED", "trial_budget must be")
    check("a campaign may still assert nothing about the budget",
          fp_of(trial_budget=None)["trial_budget"] is None)

    # ---- sharding ---------------------------------------------------------
    ids = [f"coreshop/features/domain/cart/c{i}.feature:{i}" for i in range(200)]
    a3 = assign_shards(ids, 3)
    check("assign_shards yields every index 0..k-1, even when a shard is empty",
          sorted(a3) == [0, 1, 2] and sorted(assign_shards(ids[:1], 4)) == [0, 1, 2, 3],
          str(sorted(a3)))
    flat = [i for s in sorted(a3) for i in a3[s]]
    check("every item is assigned exactly once",
          sorted(flat) == sorted(ids) and len(flat) == len(ids), str(len(flat)))
    check("assignment agrees with shard_of for every item",
          all(shard_of(i, 3) == s for s in a3 for i in a3[s]))
    check("input order is preserved inside a shard",
          all(a3[s] == [i for i in ids if shard_of(i, 3) == s] for s in a3))
    refuses("a duplicated item id is refused at assignment time",
            lambda: assign_shards(ids[:5] + [ids[0]], 3), "REFUSED", "more than once")
    refuses("k < 1 is refused", lambda: shard_of("x", 0), "REFUSED", ">= 1")

    # Content-based assignment means an added item cannot re-shuffle the
    # rest; a positional rule would move ~2/3 of them and quietly make two
    # campaigns incomparable.
    before = {i: s for s in a3 for i in a3[s]}
    grown = assign_shards(ids + ["coreshop/features/new.feature:1"], 3)
    after = {i: s for s in grown for i in grown[s]}
    check("shard_of is stable when the item set grows",
          all(after[i] == before[i] for i in ids),
          str([i for i in ids if after[i] != before[i]][:3]))
    check("growth disturbs only the new item",
          sum(len(v) for v in grown.values()) == len(ids) + 1
          and all(set(a3[s]) <= set(grown[s]) for s in a3))
    check("the split is not wildly lopsided at K=3 over 200 items",
          all(40 <= len(v) <= 100 for v in a3.values()),
          str({s: len(v) for s, v in a3.items()}))

    # ---- worker manifest --------------------------------------------------
    with tempfile.TemporaryDirectory() as root:

        def worker(shard: int, digest: Optional[str] = None, **over) -> WorkerManifest:
            kw = dict(shard=shard,
                      workspace=os.path.join(root, f"ws{shard}"),
                      container=f"coreshop_bench_php_{shard}",
                      schema=f"coreshop_bench_{shard}",
                      credential=f"bench_{shard}",
                      out_path=os.path.join(root, f"out{shard}.jsonl"),
                      artifacts_root=os.path.join(root, "art", f"w{shard}"),
                      started_at="2026-07-31T10:00:00+0000",
                      finished_at="2026-07-31T10:31:00+0000",
                      campaign_digest=digest or campaign_digest(fp))
            kw.update(over)
            return WorkerManifest(**kw)

        w0 = worker(0)
        check("to_json holds exactly WORKER_FIELDS",
              tuple(sorted(w0.to_json())) == tuple(sorted(WORKER_FIELDS)))
        check("a worker manifest round-trips exactly",
              WorkerManifest.from_json(w0.to_json()) == w0
              and WorkerManifest.from_json(w0.to_json()).to_json() == w0.to_json())
        check("finished_at may be absent while the worker is still running",
              worker(0, finished_at=None).finished_at is None)

        def dsn_refused(cred):
            try:
                worker(0, credential=cred)
            except SecretInManifest:
                return True
            return False

        check("a DSN-shaped credential is refused, not stamped",
              dsn_refused("mysql://bench_3:hunter2@db/coreshop_bench_3")
              and dsn_refused("bench_3:hunter2@127.0.0.1")
              and dsn_refused("mysql://db/coreshop_bench_3"))
        # The bare pair has no `@`, and an earlier rule that demanded one
        # accepted it — the password reached the stamp.
        check("a bare user:password pair is refused, @ or no @",
              dsn_refused("bench_3:hunter2") and dsn_refused("root:root"))
        check("a credential carrying a newline is refused",
              dsn_refused("bench_3\npassword=hunter2"))
        check("a plain non-secret identity is accepted",
              worker(0, credential="bench_3").credential == "bench_3"
              and worker(0, credential="bench_3@localhost").credential
              == "bench_3@localhost")
        check("a lexically messy absolute path is normalised, not stored raw",
              worker(0, workspace=os.path.join(root, "a", "..", "ws0")).workspace
              == os.path.join(root, "ws0"))
        check("a negative shard index is refused",
              not _ctor_ok(lambda: worker(-1)))
        check("a non-string timestamp is refused",
              not _ctor_ok(lambda: worker(0, started_at=17)))
        check("an unknown key in a worker manifest is refused",
              not _ctor_ok(lambda: WorkerManifest.from_json(
                  dict(w0.to_json(), gpu="a100"))))
        check("a relative resource path is refused as a non-identity",
              not _ctor_ok(lambda: worker(0, out_path="out.jsonl")))
        check("a placeholder campaign digest is refused",
              not _ctor_ok(lambda: worker(0, campaign_digest=""))
              and not _ctor_ok(lambda: worker(0, campaign_digest="not-hex-here!")))
        check("a manifest with a missing field is refused",
              not _ctor_ok(lambda: WorkerManifest.from_json(
                  {k: v for k, v in w0.to_json().items() if k != "schema"})))
        # D6: a stack with no database has no schema and no principal, and
        # `worker.plan_workers` records that as the empty string rather than
        # inventing names.  Level 2 must accept it — the alternative is what
        # it used to do, which is crash the shard at the line that writes the
        # record the merge needs, AFTER every item has been paid for.
        check("a worker of a stack with no database may declare no schema "
              "and no credential",
              worker(0, schema="", credential="").schema == ""
              and worker(0, schema="", credential="").credential == "")
        check("...but a non-string one is still refused, and every OTHER "
              "resource must still be named",
              not _ctor_ok(lambda: worker(0, schema=None))
              and not _ctor_ok(lambda: worker(0, credential=None))
              and not _ctor_ok(lambda: worker(0, container="")))

        refuses("writing a manifest under a fingerprint it does not match",
                lambda: write_worker_manifest(
                    worker(0, digest=campaign_digest(fp_of(k_workers=4))), fp,
                    os.path.join(root, "bad.json")),
                "REFUSED", "another campaign")

        # ---- the merge ----------------------------------------------------
        items = {f"item:{i}" for i in range(9)}

        def stamp_of(camp: dict) -> dict:
            """The half of `runner._run_stamp` the merge cross-checks.

            Written from the CAMPAIGN here because that is the case the
            fixture is for: a worker launched with the campaign's own
            arguments.  Every negative fixture below perturbs exactly one of
            these, which is the shape a mis-launched shard really has.

            DERIVED FROM `STAMP_CROSSCHECKS`, not listed.  A hand-written list
            falls behind the moment a pair is added -- when the protocol pair
            landed, this fixture went on describing a shard that had not
            existed since, and every positive merge check turned into a
            negative one.  Deriving it means the fixture is always "a worker
            launched with exactly the campaign's arguments", whatever that
            set currently is.
            """
            return {rfield: camp.get(cfield)
                    for cfield, rfield in STAMP_CROSSCHECKS}

        from ..core.constants import EGRESS_ATTESTATION_SUFFIX as EGRESS_SUF

        # What a shard the strict gate cleared seals beside its out file.
        # The fixture writes the two fields the MERGE reads; the document's
        # own closed schema is `egress_attestation.validate_attestation`'s to
        # enforce, and that has its own tests.
        CLEAN_EGRESS = {"schema": "r2t.egress-attestation/2",
                        "status": "clean", "contaminated_items": []}

        def build(dirname: str, workers: list[WorkerManifest],
                  rows_for, campaigns=None, stamp_override=None,
                  drop=(), egress=CLEAN_EGRESS) -> list[str]:
            d = os.path.join(root, dirname)
            os.makedirs(d, exist_ok=True)
            paths = []
            for i, w in enumerate(workers):
                camp = (campaigns or {}).get(w.shard, fp)
                # Only an agent campaign seals one, which is exactly the
                # condition the merge keys its absent case on; `egress=None`
                # is the fixture for a shard that sealed nothing.
                if egress and camp.get("agent_system"):
                    with open(w.out_path + EGRESS_SUF, "w",
                              encoding="utf-8") as fh:
                        fh.write(json.dumps(egress, sort_keys=True))
                with open(w.out_path, "w", encoding="utf-8") as fh:
                    for iid in rows_for(w):
                        row = {"item_id": iid, "outcome": "passed",
                               "shard_seen": w.shard,
                               "campaign_digest": w.campaign_digest,
                               "shard": w.shard}
                        row.update(stamp_of(camp))
                        row.update(stamp_override or {})
                        for k in drop:
                            row.pop(k, None)
                        fh.write(json.dumps(row, sort_keys=True) + "\n")
                p = os.path.join(d, f"manifest_{i}.json")
                doc = {"campaign": camp, "campaign_digest": w.campaign_digest,
                       "worker": w.to_json()}
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(doc, sort_keys=True, indent=2))
                paths.append(p)
            return paths

        def out_in(dirname: str, shard: int) -> str:
            os.makedirs(os.path.join(root, dirname), exist_ok=True)
            return os.path.join(root, dirname, f"out{shard}.jsonl")

        def trio(dirname: str, per_shard: Optional[dict] = None
                 ) -> list[WorkerManifest]:
            per_shard = per_shard or {}
            return [worker(s, out_path=out_in(dirname, s),
                           workspace=os.path.join(root, dirname, f"ws{s}"),
                           artifacts_root=os.path.join(root, dirname, f"art{s}"),
                           **per_shard.get(s, {}))
                    for s in range(3)]

        assign = assign_shards(sorted(items), 3)
        mine = lambda w: assign[w.shard]                    # noqa: E731

        clean = build("clean", trio("clean"), mine)
        res = merge_shards(clean, items, 3)
        check("a clean 3-shard merge succeeds and returns every item",
              res["n"] == len(items)
              and {r["item_id"] for r in res["rows"]} == items, str(res["n"]))
        positional_order = [f"position:{index}" for index in range(9)]
        positional_fp = fp_of(
            campaign_id="positional", k_workers=3,
            shard_rule=POSITIONAL_SHARD_RULE)
        positional_digest = campaign_digest(positional_fp)
        positional_workers = trio(
            "positional", {shard: {"digest": positional_digest}
                           for shard in range(3)})
        positional_assignments = assign_ordered_shards(positional_order, 3)
        positional_paths = build(
            "positional", positional_workers,
            lambda w: positional_assignments[w.shard],
            campaigns={shard: positional_fp for shard in range(3)})
        positional_result = merge_shards(
            positional_paths, positional_order, 3)
        check("the strict merge independently replays positional assignment "
              "from the frozen ordered release",
              positional_result["n"] == len(positional_order))
        refuses("a positional merge refuses an unordered denominator",
                lambda: merge_shards(
                    positional_paths, set(positional_order), 3),
                "REFUSED", "ordered release")
        check("the merge reports one campaign and three workers",
              res["campaign_digest"] == campaign_digest(fp)
              and [w["shard"] for w in res["workers"]] == [0, 1, 2])
        check("rows are sorted by item id",
              [r["item_id"] for r in res["rows"]]
              == sorted(r["item_id"] for r in res["rows"]))
        res_r = merge_shards(list(reversed(clean)), items, 3)
        check("the merge is row-order stable under argument order",
              res_r["rows"] == res["rows"] and res_r["workers"] == res["workers"])

        # ------------------------------------------------------- LI7 / LI8
        #
        # Generation identity v2: which ATTEMPT, which harness bytes, which
        # runtime.  The realized collision (review finding 20) was two Cell 3
        # attempts -- one with an open package channel to a gold-serving host,
        # one with it closed -- hashing to the same `971f1c00943040d5`,
        # because v1 had a term for neither the environment nor the attempt.
        def fp2_of(**over) -> dict:
            base = dict(
                campaign_id="a5_cell3_openhands_c3", k_workers=3,
                shard_rule=SHARD_RULE, trial_budget=UNBOUNDED,
                condition="c3", coverage=False, harness_version=6,
                config_digest="556cca9ff5fc3d39", model="deepseek",
                container_image_digest="sha256:" + "a" * 64,
                workspace_seed_digest="ws0123456789abcd",
                database_dump_digest=NO_DATABASE,
                protocol_version=4, protocol_digest="bda1d9bcb1852e92",
                agent_system="openhands",
                attempt_id="attempt-corrected",
                harness_commit="ae9c751" + "0" * 33,
                harness_source_sha256="1" * 64,
                agent_runtime_sha256="2" * 64,
                network_semantics="closed_gold_host_channel")
            base.update(over)
            return generation_fingerprint(**base)

        fp2 = fp2_of()
        check("LI7: a v2 fingerprint holds exactly CAMPAIGN_FIELDS_V2 and "
              "declares its schema",
              tuple(sorted(fp2)) == tuple(sorted(CAMPAIGN_FIELDS_V2))
              and fp2["schema"] == GENERATION_CAMPAIGN_SCHEMA, str(sorted(fp2)))
        contaminated = fp2_of(attempt_id="attempt-contaminated",
                              agent_runtime_sha256="3" * 64,
                              network_semantics="open_package_channel")
        recipe_only = {key: value for key, value in fp2.items()
                       if key in CAMPAIGN_FIELDS}
        recipe_only_contaminated = {key: value
                                    for key, value in contaminated.items()
                                    if key in CAMPAIGN_FIELDS}
        check("LI7: the two Cell 3 attempts are ONE recipe -- every v1 field "
              "is identical, which is why v1 gave them one digest",
              recipe_only == recipe_only_contaminated
              and campaign_digest(dict(recipe_only))
              == campaign_digest(dict(recipe_only_contaminated)))
        check("LI7: two generation attempts differing only in attempt and "
              "runtime identity are two different v2 identities",
              campaign_digest(fp2) != campaign_digest(contaminated))
        check("LI7: the attempt id alone is enough -- a re-run under an "
              "identical runtime is still a different campaign",
              campaign_digest(fp2_of(attempt_id="attempt-3"))
              != campaign_digest(fp2))
        check("LI7: so is one edited harness byte, with the commit unchanged",
              campaign_digest(fp2_of(harness_source_sha256="4" * 64))
              != campaign_digest(fp2))
        _alt2 = {"k_workers": 99, "trial_budget": 7, "coverage": True,
                 "protocol_version": 3, "protocol_digest": "fedcba9876543210",
                 "harness_commit": "b" * 40,
                 "harness_source_sha256": "5" * 64,
                 "agent_runtime_sha256": "6" * 64,
                 "database_dump_digest": "db0123456789abcd",
                 "container_image_digest": "sha256:" + "c" * 64}
        unhashed2 = [f for f in CAMPAIGN_FIELDS_V2 if f != "schema"
                     and campaign_digest(fp2_of(**{f: _alt2.get(f, f"alt-{f}")}))
                     == campaign_digest(fp2)]
        check(f"LI7: every one of the {len(CAMPAIGN_FIELDS_V2)} v2 campaign "
              f"fields changes the digest",
              not unhashed2, f"ignored by the digest: {unhashed2}")
        runtime_doc = agent_runtime_manifest(
            interpreter="CPython 3.11.9 (final)",
            agent_versions={"openhands-ai": "0.9.3", "litellm": "1.44.0"},
            environment_controls={"LITELLM_LOCAL_MODEL_COST_MAP": "1"},
            network_semantics="closed_gold_host_channel")
        open_channel = agent_runtime_manifest(
            interpreter="CPython 3.11.9 (final)",
            agent_versions={"openhands-ai": "0.9.3", "litellm": "1.44.0"},
            environment_controls={"LITELLM_LOCAL_MODEL_COST_MAP": None},
            network_semantics="open_package_channel")
        check("LI7: the runtime manifest digests the control that closed the "
              "Cells 1/2 contamination channel, so setting it is a different "
              "runtime identity",
              agent_runtime_digest(runtime_doc)
              != agent_runtime_digest(open_channel)
              and len(agent_runtime_digest(runtime_doc)) == 64)
        refuses("a runtime manifest with no network semantics is refused",
                lambda: agent_runtime_manifest(
                    interpreter="CPython 3.11.9", agent_versions={},
                    environment_controls={}, network_semantics=""),
                "REFUSED", "network semantics")
        # A MANIFEST IS PUBLISHED, so a credentialed proxy URL in an
        # environment control is a published password.  Redacted by the
        # CONSTRUCTOR, so neither the probe nor a hand-assembled document can
        # record one.
        credentialed = agent_runtime_manifest(
            interpreter="CPython 3.11.9 (final)", agent_versions={},
            environment_controls={
                "HTTPS_PROXY": "http://svc:S3CRETpw@proxy.example:3128/",
                "NO_PROXY": "localhost,127.0.0.1"},
            network_semantics="proxied")
        rotated = agent_runtime_manifest(
            interpreter="CPython 3.11.9 (final)", agent_versions={},
            environment_controls={
                "HTTPS_PROXY": "http://svc:a-different-pw@proxy.example:3128/",
                "NO_PROXY": "localhost,127.0.0.1"},
            network_semantics="proxied")
        check("LI7: a credentialed proxy value never reaches the published "
              "runtime manifest, host and port intact",
              "S3CRETpw" not in _canonical(credentialed)
              and credentialed["environment_controls"]["HTTPS_PROXY"]
              == "http://REDACTED@proxy.example:3128/"
              and credentialed["environment_controls"]["NO_PROXY"]
              == "localhost,127.0.0.1",
              _canonical(credentialed))
        check("LI7: ...and the runtime DIGEST is stable across equal-redacted "
              "values, so rotating a proxy password is not a new campaign",
              agent_runtime_digest(credentialed)
              == agent_runtime_digest(rotated)
              and "S3CRETpw" not in _canonical(credentialed))
        check("LI7: a proxy host that really differs is still a different "
              "runtime identity",
              agent_runtime_digest(credentialed) != agent_runtime_digest(
                  agent_runtime_manifest(
                      interpreter="CPython 3.11.9 (final)", agent_versions={},
                      environment_controls={
                          "HTTPS_PROXY": "http://svc:pw@other.example:3128/",
                          "NO_PROXY": "localhost,127.0.0.1"},
                      network_semantics="proxied")))
        refuses("LI7: a hand-assembled runtime document that still carries "
                "userinfo is refused rather than hashed",
                lambda: agent_runtime_digest(
                    {**credentialed, "environment_controls": {
                        "HTTPS_PROXY": "http://svc:S3CRETpw@proxy.example:3128/",
                        "NO_PROXY": "localhost,127.0.0.1"}}),
                "REFUSED", "still", "userinfo")
        # A REAL SUBPROCESS, but a tiny fixture interpreter: the hard-coded
        # identity proves the coordinator did not inspect itself, and the
        # echoed environment proves PYTHONNOUSERSITE was set on that one
        # process.  The fixture ignores the `-c` payload just as a broken
        # interpreter could; the probe contract is its prefixed JSON record.
        import sys
        fixture_python = os.path.join(root, "fixture-python")
        fixture_lock = os.path.join(root, "fixture-lock.txt")
        with open(fixture_python, "w", encoding="utf-8") as fh:
            fh.write(
                f"#!{sys.executable}\n"
                "import json, os\n"
                f"controls = {{name: os.environ.get(name) for name in "
                f"{RUNTIME_ENVIRONMENT_CONTROLS!r}}}\n"
                "payload = {'interpreter': 'FixturePython 9.9.0 (final)', "
                "'distributions': {'Fixture_Dist': '1.2.3'}, "
                "'sitecustomize_sha256': None, "
                "'environment_controls': controls}\n"
                f"print({_AGENT_RUNTIME_PREFIX!r} + "
                "json.dumps(payload, sort_keys=True))\n")
        os.chmod(fixture_python, 0o755)
        with open(fixture_lock, "w", encoding="utf-8") as fh:
            fh.write("fixture-dist==1.2.3\n")

        previous_proxy = os.environ.pop("HTTP_PROXY", None)
        try:
            probed = probe_agent_runtime(
                interpreter=fixture_python, network_semantics="fixture",
                agent_system="fixture-agent",
                requirements_lock=fixture_lock)
            os.environ["HTTP_PROXY"] = \
                "http://probe:PROBEpw@proxy.example:3128"
            probed_credentialed = probe_agent_runtime(
                interpreter=fixture_python, network_semantics="fixture",
                requirements_lock=fixture_lock)
        finally:
            os.environ.pop("HTTP_PROXY", None)
            if previous_proxy is not None:
                os.environ["HTTP_PROXY"] = previous_proxy
        check("the runtime probe executes the selected interpreter once with "
              "the user site disabled and records its complete inventory",
              probed["interpreter"] == "FixturePython 9.9.0 (final)"
              and probed["agent_versions"]["fixture-dist"] == "1.2.3"
              and probed["agent_versions"]["agent_system"]
              == "fixture-agent"
              and probed["environment_controls"]["PYTHONNOUSERSITE"] == "1",
              _canonical(probed))
        with open(fixture_lock, "w", encoding="utf-8") as fh:
            fh.write("fixture-dist==9.9.9\n")
        refuses("an exact-lock version mismatch refuses before a campaign is "
                "minted",
                lambda: probe_agent_runtime(
                    interpreter=fixture_python, network_semantics="fixture",
                    requirements_lock=fixture_lock),
                "REFUSED", "fixture-dist", "installed 1.2.3",
                "lock requires 9.9.9")
        check("LI7: the PROBE redacts too -- a credentialed proxy in this "
              "agent process is recorded by host and port only",
              "PROBEpw" not in _canonical(probed_credentialed)
              and probed_credentialed["environment_controls"]["HTTP_PROXY"]
              == "http://REDACTED@proxy.example:3128"
              and probed["environment_controls"]["HTTP_PROXY"] is None,
              _canonical(probed_credentialed))
        refuses("a v2 fingerprint with a blank attempt id is refused",
                lambda: fp2_of(attempt_id="  "), "REFUSED", "attempt_id")
        refuses("a v2 fingerprint carrying the 7-hex row spelling of the "
                "harness commit is refused",
                lambda: fp2_of(harness_commit="ae9c751"),
                "REFUSED", "FULL 40-hex")
        refuses("a fingerprint declaring an unknown schema is refused rather "
                "than read as either version",
                lambda: campaign_digest(dict(fp2, schema="r2t.generation-"
                                                         "campaign/v3")),
                "REFUSED", "unsupported generation campaign schema")
        check("LI8: a v1 fingerprint is still recognised BY ITS ABSENT "
              "schema and still hashes exactly as written",
              fingerprint_version(fp) == "v1"
              and fingerprint_version(fp2) == "v2"
              and campaign_digest(fp) == hashlib.sha256(
                  _canonical(fp).encode("utf-8")).hexdigest()[:16])

        v2_workers = trio("v2", {s: {"digest": campaign_digest(fp2)}
                                 for s in range(3)})
        v2_clean = build("v2", v2_workers, mine,
                         campaigns={s: fp2 for s in range(3)})
        check("LI8: three shards of one v2 attempt merge exactly as v1's do",
              merge_shards(v2_clean, items, 3)["n"] == len(items))
        cross_workers = trio("cross-attempt", {
            0: {"digest": campaign_digest(fp2)},
            1: {"digest": campaign_digest(fp2)},
            2: {"digest": campaign_digest(contaminated)}})
        cross = build("cross-attempt", cross_workers, mine,
                      campaigns={0: fp2, 1: fp2, 2: contaminated})
        refuses("LI8: a shard set spanning two generation ATTEMPTS of one "
                "recipe is refused, and the refusal says a re-run is a new "
                "campaign",
                lambda: merge_shards(cross, items, 3),
                "REFUSED", "different ATTEMPTS", "merge each attempt's shards")
        mixed_workers = trio("mixed-version", {
            0: {"digest": campaign_digest(fp2)},
            1: {"digest": campaign_digest(fp2)},
            2: {"digest": campaign_digest(fp)}})
        mixed_version = build("mixed-version", mixed_workers, mine,
                              campaigns={0: fp2, 1: fp2, 2: fp})
        refuses("LI8: a v1 shard and a v2 shard may never be merged into one "
                "campaign",
                lambda: merge_shards(mixed_version, items, 3),
                "REFUSED", "mix generation identity versions")

        # Set equality cannot see a shard swap: no duplicates, exactly the
        # expected items, and each worker executed the other's half.  This is
        # what fingerprinting `shard_rule` is FOR.
        swapped = build("swap", trio("swap"),
                        lambda w: assign[{0: 1, 1: 0, 2: 2}[w.shard]])
        refuses("two workers that swapped their --shard arguments are refused",
                lambda: merge_shards(swapped, items, 3),
                "REFUSED", "shard rule", "swapped")
        check("the swap fixture is otherwise a perfect merge",
              sorted(i for s in assign.values() for i in s) == sorted(items))

        # A worker still running has an out file that is still growing.
        running = build("running", trio("running", {1: {"finished_at": None}}),
                        mine)
        refuses("a shard with no finish time is not merged",
                lambda: merge_shards(running, items, 3),
                "REFUSED", "no finish time", "[1]")

        # P0-2: a row that does not say which campaign produced it cannot be
        # merged into one. A review merged a row holding only item_id+outcome
        # under a campaign with a different model, seed, image and budget.
        unstamped = build("unstamped", trio("unstamped"), mine,
                          stamp_override={"campaign_digest": None,
                                          "shard": None},
                          drop=("trials", "model", "coverage", "condition"))
        refuses("a row that names no campaign is refused",
                lambda: merge_shards(unstamped, items, 3),
                "REFUSED", "not bound to this campaign")
        wrongcamp = build("wrongcamp", trio("wrongcamp"), mine,
                          stamp_override={"campaign_digest":
                                          campaign_digest(fp_of(k_workers=9))})
        refuses("a row stamped by ANOTHER campaign is refused",
                lambda: merge_shards(wrongcamp, items, 3),
                "REFUSED", "not bound to this campaign")
        swapstamp = build("swapstamp", trio("swapstamp"), mine,
                          stamp_override={"shard": 2})
        refuses("a row stamped by a different shard than the one that holds it "
                "is refused",
                lambda: merge_shards(swapstamp, items, 3),
                "REFUSED", "was stamped by shard")

        # ---- the shards must have RUN what the campaign asserts ------------
        #
        # Everything above proves a row was STAMPED by this campaign; none of
        # it proves the worker was LAUNCHED with the campaign's arguments.  A
        # shard started with the wrong `--condition`, or with `--trials`
        # forgotten, or against a second model, carries this campaign's
        # digest and a different experiment — and merging it publishes one
        # arm's number under the other arm's fingerprint.
        def arm(dirname: str, camp: dict, **kw) -> list[str]:
            """Three shards that all declare, and embed, `camp`."""
            d = campaign_digest(camp)
            ws = trio(dirname, {s: {"campaign_digest": d} for s in range(3)})
            return build(dirname, ws, mine,
                         campaigns={s: camp for s in range(3)}, **kw)

        c3 = fp_of(condition="c3", model="deepseek-v3", trial_budget=3)
        check("a c3 campaign whose rows carry its arm, model and budget merges",
              merge_shards(arm("c3ok", c3), items, 3)["n"] == len(items))
        refuses("a row that ran a different trial budget is refused",
                lambda: merge_shards(
                    arm("c3trials", c3, stamp_override={"trials": 1}), items, 3),
                "REFUSED", "carries trials=1", "asserts trial_budget=3")
        refuses("a row that does not say which arm it ran is refused",
                lambda: merge_shards(
                    arm("c3nocond", c3, drop=("condition",)), items, 3),
                "REFUSED", "carries no 'condition'", "asserts condition='c3'")
        refuses("a row that ran the WRONG arm is refused",
                lambda: merge_shards(
                    arm("c3c2", c3, stamp_override={"condition": "c2"}),
                    items, 3),
                "REFUSED", "carries condition='c2'", "asserts condition='c3'")
        refuses("a row produced by another model is refused",
                lambda: merge_shards(
                    arm("c3model", c3, stamp_override={"model": "gpt-4o"}),
                    items, 3),
                "REFUSED", "carries model='gpt-4o'", "deepseek-v3")
        refuses("a row that ran with coverage the campaign does not claim is "
                "refused",
                lambda: merge_shards(
                    arm("c3cov", c3, stamp_override={"coverage": True}),
                    items, 3),
                "REFUSED", "carries coverage=True", "asserts coverage=False")
        refuses("a row missing the model the campaign names is refused",
                lambda: merge_shards(
                    arm("c3nomodel", c3, drop=("model",)), items, 3),
                "REFUSED", "carries no 'model'", "deepseek-v3")

        # The immutable agent-runtime digest is the row's additive link back
        # to the validated interpreter manifest.  A present disagreement is
        # always wrong; absence is grandfathered only because released rows
        # predate the field and are never restamped.
        refuses("a row carrying another agent runtime cannot merge into this "
                "campaign",
                lambda: merge_shards(
                    arm("runtimewrong", fp2,
                        stamp_override={"agent_runtime_sha256": "d" * 64}),
                    items, 3),
                "REFUSED", "agent_runtime_sha256", "asserts")
        check("a released row without the additive runtime field still "
              "merges without being restamped",
              merge_shards(
                  arm("runtimeold", fp2, drop=("agent_runtime_sha256",)),
                  items, 3)["n"] == len(items))

        # The `trial_budget == 0` waiver, and its limit.  Controls really do
        # write 0 (cli's `campaign` subparser: `--trials` default 0), and
        # their rows really do carry no `trials` at all, so presence cannot
        # be demanded there — but a row that DID run trials is still not a
        # control, and says so.
        ctrl = fp_of(trial_budget=0)
        check("a control campaign merges rows that carry no trials field",
              merge_shards(arm("ctrl", ctrl, drop=("trials",)),
                           items, 3)["n"] == len(items))
        refuses("a row that ran trials cannot hide inside a control campaign",
                lambda: merge_shards(
                    arm("ctrl3", ctrl, stamp_override={"trials": 3}), items, 3),
                "REFUSED", "carries trials=3", "asserts trial_budget=0")

        # The UNBOUNDED arm, merged end to end.  The waiver above is written
        # `want == 0`, so it does not extend here: `"unlimited"` is truthy,
        # and a row that says nothing about its budget is compatible with
        # every budget — including a rationed one.
        unl = fp_of(condition="c3", trial_budget=UNBOUNDED)
        check("an unbounded C3 campaign merges rows that ran unbounded",
              merge_shards(arm("unl", unl), items, 3)["n"] == len(items))
        refuses("a rationed row cannot merge into an unbounded campaign",
                lambda: merge_shards(
                    arm("unl5", unl, stamp_override={"trials": 5}), items, 3),
                "REFUSED", "carries trials=5", "asserts trial_budget='unlimited'")
        refuses("nor can a row that ran no trials at all",
                lambda: merge_shards(
                    arm("unl0", unl, stamp_override={"trials": 0}), items, 3),
                "REFUSED", "carries trials=0")
        refuses("nor can a row that does not say what its budget was",
                lambda: merge_shards(
                    arm("unlnone", unl, drop=("trials",)), items, 3),
                "REFUSED", "carries no 'trials'")
        refuses("and an unbounded row cannot hide inside a counted campaign",
                lambda: merge_shards(
                    arm("c3unl", c3, stamp_override={"trials": UNBOUNDED}),
                    items, 3),
                "REFUSED", "carries trials='unlimited'",
                "asserts trial_budget=3")

        # THE PROTOCOL PAIR, at the merge.  Fingerprinting the recipe makes
        # two protocols hash differently; it does not make a shard FOLLOW the
        # one its campaign declares, and every shard asserting the same lie
        # agrees with every other one.  So the pair is crosschecked like the
        # arm and the budget: present, and equal, on every row.
        p2 = fp_of(protocol_version=2, protocol_digest="0123456789abcdef")
        check("a campaign that declares a protocol merges rows that followed "
              "it", merge_shards(arm("p2ok", p2), items, 3)["n"] == len(items))
        refuses("a row that says nothing about its recipe is refused, not "
                "admitted as unknown",
                lambda: merge_shards(
                    arm("p2none", p2, drop=("protocol_version",)), items, 3),
                "REFUSED", "carries no 'protocol_version'",
                "asserts protocol_version=2")
        refuses("a row that followed ANOTHER recipe is refused by digest",
                lambda: merge_shards(
                    arm("p2other", p2,
                        stamp_override={"protocol_digest": "fedcba9876543210"}),
                    items, 3),
                "REFUSED", "carries protocol_digest='fedcba9876543210'",
                "asserts protocol_digest='0123456789abcdef'")
        # ...and the grandfather half, which is the ONLY reason the six
        # archived sidecars under `artifacts/runs` still merge: they carry
        # neither key, so the campaign asserts nothing and the rows are not
        # asked.  Checked with the keys DELETED rather than nulled, because
        # that is the shape on disk.
        nop = {k: v for k, v in fp.items()
               if k not in ("protocol_version", "protocol_digest")}
        check("a campaign written before the protocol pair existed still "
              "merges protocol-less rows",
              merge_shards(arm("noproto", nop,
                               drop=("protocol_version", "protocol_digest")),
                           items, 3)["n"] == len(items))

        # WHICH SYSTEM, at the merge.  The digest makes two systems two
        # campaigns; it does not stop a shard of the OTHER system from being
        # merged into this one, because the merge trusts the digest and every
        # shard of a mis-launched pair would carry it.  Proven BOTH ways: the
        # refusal that matters, and the grandfathering that keeps history
        # mergeable.
        oh = fp_of(agent_system="openhands")
        check("a campaign that names its system merges rows that ran it",
              merge_shards(arm("sysok", oh), items, 3)["n"] == len(items))
        refuses("an aider shard cannot merge into an openhands campaign",
                lambda: merge_shards(
                    arm("sysmix", oh,
                        stamp_override={"agent_system": "aider"}), items, 3),
                "REFUSED", "carries agent_system='aider'",
                "asserts agent_system='openhands'")
        # ...and the grandfather half. No archived row carries `agent_system`
        # (checked: zero of the six run files on disk), so demanding presence
        # would refuse every resume into one. Absence is unverifiable, not
        # wrong; PRESENT-and-different is what refuses, above.
        check("a campaign that names its system still merges rows written "
              "before the field existed -- absence is unverifiable, not wrong",
              merge_shards(arm("sysold", oh, drop=("agent_system",)),
                           items, 3)["n"] == len(items))
        check("...and the waiver is NARROW: only the two additive identity "
              "fields are forgiven when absent",
              CROSSCHECK_ABSENCE_GRANDFATHERED == frozenset(
                  {"agent_system", "agent_runtime_sha256"}),
              str(sorted(CROSSCHECK_ABSENCE_GRANDFATHERED)))
        check("a campaign that names no system constrains nothing -- every "
              "archived campaign is one, and they must keep merging",
              merge_shards(arm("sysnone",
                               {k: v for k, v in fp.items()
                                if k != "agent_system"},
                               stamp_override={"agent_system": "aider"}),
                           items, 3)["n"] == len(items))

        # THE EGRESS VERDICT, AT THE MERGE.  A shard the strict gate refused
        # SEALS ANYWAY -- the quarantine amendment is what keeps one fetched
        # row from taking a whole cell down -- so the merge is the last place
        # that verdict can still stop a number, and it never read it.  The
        # realized shape: the wave5 algorand OpenHands cell merged n=111 with
        # five rows its own sealed attestations named as contaminated.
        check("an agent campaign whose shards all sealed clean merges",
              merge_shards(arm("egressok", oh), items, 3)["n"] == len(items))
        refuses("a shard the strict egress gate refused may not enter a "
                "merged run, and the refusal NAMES the contaminated items so "
                "an operator can see what and why",
                lambda: merge_shards(
                    arm("egressbad", oh, egress={
                        "schema": "r2t.egress-attestation/2",
                        "status": "contaminated",
                        "contaminated_items": ["sdk/unit/offline.feature:47",
                                               "sdk/unit/abijson.feature:44"]}),
                    items, 3),
                "REFUSED", "refused by the strict egress gate",
                "sdk/unit/offline.feature:47", "sdk/unit/abijson.feature:44")
        refuses("an agent shard that sealed NO verdict is refused: the gate's "
                "own `allow_unassessed` default is what says not assessed is "
                "not clean",
                lambda: merge_shards(arm("egressgone", oh, egress=None),
                                     items, 3),
                "REFUSED", "no sealed egress attestation",
                "not assessed is not clean")
        check("a /1 document carries no item list -- /1 sealed only when the "
              "run was clean -- and its shards still merge",
              merge_shards(arm("egressv1", oh, egress={
                  "schema": "r2t.egress-attestation/1",
                  "status": "clean"}), items, 3)["n"] == len(items))
        # The other half of the absent case, and the reason it is not simply
        # "refuse": a control ran no agent and wrote no trajectory, so
        # `build_attestation` could never seal one for it.  Refusing here
        # would refuse every gold/stripped/stub merge forever.
        no_agent = {k: v for k, v in fp.items() if k != "agent_system"}
        # Built BEFORE the assertion, or "no attestation on disk" would be
        # true only because nothing had been written yet.
        ctrl_paths = arm("egressctrl", no_agent)
        check("a campaign that names no agent system merges with no verdict "
              "at all, and the fixture really has none on disk",
              not any(os.path.exists(out_in("egressctrl", s) + EGRESS_SUF)
                      for s in range(3))
              and merge_shards(ctrl_paths, items, 3)["n"] == len(items))

        # A campaign file written before `condition` existed asserts nothing
        # about the arm and must still merge — reading it must not crash on
        # the absent key, and re-hashing it must still reproduce the digest
        # its manifests recorded.
        legacy_camp = {k: v for k, v in fp.items() if k != "condition"}
        check("a campaign written before `condition` existed still merges",
              merge_shards(arm("legacy", legacy_camp, drop=("condition",)),
                           items, 3)["n"] == len(items))

        merged_path = write_merged(res, os.path.join(root, "merged", "all.jsonl"))
        side = json.load(open(merged_path + ".campaign.json", encoding="utf-8"))
        with open(merged_path, encoding="utf-8") as fh:
            body = fh.read()
        check("write_merged writes one JSONL row per item",
              len([l for l in body.splitlines() if l.strip()]) == len(items))
        check("the sidecar carries the fingerprint and every worker manifest",
              side["campaign"] == fp and side["campaign_digest"] == campaign_digest(fp)
              and len(side["workers"]) == 3 and side["n"] == len(items))
        check("the sidecar's row digest matches the file it describes",
              side["rows_digest"]
              == hashlib.sha256(body.encode("utf-8")).hexdigest()[:16])
        refuses("write_merged refuses anything but a checked merge result",
                lambda: write_merged({"rows": []}, os.path.join(root, "x.jsonl")),
                "REFUSED", "merge_shards")

        # The writer, end to end: a manifest it produced must merge.
        fp1 = fp_of(k_workers=1)
        solo = worker(0, digest=campaign_digest(fp1),
                      out_path=out_in("solo", 0),
                      workspace=os.path.join(root, "solo", "ws0"),
                      artifacts_root=os.path.join(root, "solo", "art0"))
        with open(solo.out_path, "w", encoding="utf-8") as fh:
            for iid in sorted(items):
                fh.write(json.dumps(dict(stamp_of(fp1),
                                         item_id=iid, outcome="passed",
                                         campaign_digest=solo.campaign_digest,
                                         shard=solo.shard)) + "\n")
        sp = write_worker_manifest(solo, fp1,
                                   os.path.join(root, "solo", "manifest.json"))
        check("a manifest written by write_worker_manifest merges as K=1",
              merge_shards([sp], items, 1)["n"] == len(items))
        refuses("a K=1 campaign merged as if it were K=3 is refused",
                lambda: merge_shards([sp], items, 3),
                "REFUSED", "declares k_workers=1")

        # §3.7 negative test: missing shard.
        refuses("a missing shard is refused, not silently merged",
                lambda: merge_shards(clean[:2], items, 3),
                "REFUSED", "no manifest for shard(s) [2]", "never ran")

        # §3.7 negative test: duplicate item across two shards — the shape
        # the accidental K=2 took (A.7), where 89 items ran twice and the
        # append-only out file showed nothing.
        stolen = "item:0"
        thief = (shard_of(stolen, 3) + 1) % 3
        dup = build("dup", trio("dup"),
                    lambda w: assign[w.shard] + ([stolen] if w.shard == thief
                                                 else []))
        refuses("an item produced by two shards is refused",
                lambda: merge_shards(dup, items, 3),
                "REFUSED", "more than one shard", "item:0")

        # §3.7 negative test: a manifest from a different campaign.
        other = fp_of(container_image_digest="sha256:bb")
        odd_w = trio("odd")
        odd_w[2] = worker(2, digest=campaign_digest(other),
                          out_path=out_in("odd", 2),
                          workspace=os.path.join(root, "odd", "ws2"),
                          artifacts_root=os.path.join(root, "odd", "art2"))
        odd = build("odd", odd_w, mine, campaigns={2: other})
        refuses("a shard from a different campaign is refused",
                lambda: merge_shards(odd, items, 3),
                "REFUSED", "different campaigns", campaign_digest(other))

        # ... and the same digest copied onto a different fingerprint.
        tam = build("tam", trio("tam"), mine)
        doc = json.load(open(tam[1], encoding="utf-8"))
        doc["campaign"] = other
        with open(tam[1], "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, sort_keys=True))
        refuses("a copied digest is caught by re-hashing the fingerprint",
                lambda: merge_shards(tam, items, 3),
                "REFUSED", "was copied, not computed")

        # §3.7 negative tests: reused resources.
        sch = build("sch", trio("sch", {1: {"schema": "coreshop_bench_0"}}), mine)
        refuses("two workers naming the same schema are refused",
                lambda: merge_shards(sch, items, 3),
                "REFUSED", "share schema", "coreshop_bench_0")

        # ...and the D6 exemption, which is the OTHER half of that check:
        # three behave workers all declare the empty schema and the empty
        # credential, because the stack has neither, and refusing them for
        # "sharing" a resource that does not exist would make every K>1
        # python-docx campaign unmergeable after it had been paid for.
        nodb = build("nodb", trio("nodb", {s: {"schema": "", "credential": ""}
                                           for s in range(3)}), mine)
        check("three workers of a stack with no database merge -- an absent "
              "schema is not a shared one",
              merge_shards(nodb, items, 3)["n"] == len(items))
        # The exemption is "both declared absent", not "ignore this field":
        # one named schema against two empty ones is still two workers whose
        # provisioning disagrees, and the two NAMED ones still collide.
        half = build("half", trio("half", {0: {"schema": "", "credential": ""},
                                           1: {"schema": "docx_bench_x"},
                                           2: {"schema": "docx_bench_x"}}),
                     mine)
        refuses("two NAMED schemas still collide beside an absent one",
                lambda: merge_shards(half, items, 3),
                "REFUSED", "share schema", "docx_bench_x")

        ws = trio("ws")
        ws[1] = worker(1, workspace=ws[0].workspace, out_path=out_in("ws", 1),
                       artifacts_root=os.path.join(root, "ws", "art1"))
        refuses("two workers naming the same workspace are refused",
                lambda: merge_shards(build("ws", ws, mine), items, 3),
                "REFUSED", "share workspace")

        nest = trio("nest")
        nest[1] = worker(1, artifacts_root=os.path.join(nest[0].artifacts_root,
                                                        "inner"),
                         out_path=out_in("nest", 1),
                         workspace=os.path.join(root, "nest", "ws1"))
        refuses("one worker's artifact root nested inside another's is refused",
                lambda: merge_shards(build("nest", nest, mine), items, 3),
                "REFUSED", "share artifacts_root")

        same_out = trio("sout")
        shared = out_in("sout", 0)
        same_out[1] = worker(1, out_path=shared,
                             workspace=os.path.join(root, "sout", "ws1"),
                             artifacts_root=os.path.join(root, "sout", "art1"))
        refuses("two workers writing the same out file are refused",
                lambda: merge_shards(build("sout", same_out, mine), items, 3),
                "REFUSED", "share out_path")

        cred = build("cred", trio("cred", {2: {"credential": "bench_0"}}), mine)
        refuses("two workers sharing a database principal are refused",
                lambda: merge_shards(cred, items, 3),
                "REFUSED", "share credential")

        con = build("con", trio("con", {2: {"container": "coreshop_bench_php_1"}}),
                    mine)
        refuses("two workers naming the same container are refused",
                lambda: merge_shards(con, items, 3),
                "REFUSED", "share container")

        # §3.7 negative test: an unexpected item in the rows.
        extra = build("extra", trio("extra"),
                      lambda w: assign[w.shard] + (["item:99"] if w.shard == 0
                                                   else []))
        refuses("an item that is not in the expected release is refused",
                lambda: merge_shards(extra, items, 3),
                "REFUSED", "not in the expected release", "item:99")

        # §3.7 negative test: an expected item nobody produced.
        short = build("short", trio("short"),
                      lambda w: [i for i in assign[w.shard] if i != "item:5"])
        refuses("an expected item that no shard produced is refused",
                lambda: merge_shards(short, items, 3),
                "REFUSED", "no shard produced", "item:5")
        # Reported SEPARATELY, proved on a fixture that has both at once:
        # shard 0 drops `item:5` and emits `item:99` instead, so the two
        # faults must appear as two problem lines.  Asserting the absence
        # of the "unexpected" wording on a fixture with no unexpected
        # items — as this check used to — holds even if the unexpected
        # branch is deleted outright.
        both = build("both", trio("both"),
                     lambda w: [i for i in assign[w.shard] if i != "item:5"]
                     + (["item:99"] if w.shard == 0 else []))
        try:
            merge_shards(both, items, 3)
            check("missing and unexpected are reported separately", False,
                  "merged instead of refusing")
        except SystemExit as e:
            lines = [l for l in str(e).splitlines() if l.strip().startswith("- ")]
            check("missing and unexpected are reported separately",
                  len(lines) == 2
                  and any("no shard produced" in l and "item:5" in l for l in lines)
                  and any("not in the expected release" in l and "item:99" in l
                          for l in lines), str(e)[:300])

        # A duplicated shard index (two manifests claiming shard 1).
        twice = trio("twice")
        twice[2] = worker(1, out_path=out_in("twice", 2),
                          workspace=os.path.join(root, "twice", "ws2"),
                          artifacts_root=os.path.join(root, "twice", "art2"),
                          container="coreshop_bench_php_x",
                          schema="coreshop_bench_x", credential="bench_x")
        refuses("two manifests for one shard index are refused",
                lambda: merge_shards(build("twice", twice, mine), items, 3),
                "REFUSED", "shard 1 has 2 manifests")
        refuses("a manifest outside 0..K-1 is refused",
                lambda: merge_shards(clean, items, 2),
                "REFUSED", "outside 0..1")

        # A worker that never wrote its out file at all.
        gone = build("gone", trio("gone"), mine)
        os.remove(trio("gone")[1].out_path)
        refuses("a declared out file that does not exist is refused",
                lambda: merge_shards(gone, items, 3),
                "REFUSED", "does not exist")

        refuses("a merge with no manifests at all is refused",
                lambda: merge_shards([], items, 3), "REFUSED", "lost its manifests")
        refuses("expected_shards below 1 is refused",
                lambda: merge_shards(clean, items, 0), "REFUSED", ">= 1")

        # Two names, one directory.  A lexical comparison sees two
        # different absolute strings; the workers still purge each
        # other's `var/classes` (§3.1).
        link = trio("link")
        os.symlink(link[0].workspace, os.path.join(root, "link", "alias"))
        link[1] = worker(1, workspace=os.path.join(root, "link", "alias"),
                         out_path=out_in("link", 1),
                         artifacts_root=os.path.join(root, "link", "art1"))
        refuses("two workspaces that are one directory via a symlink are refused",
                lambda: merge_shards(build("link", link, mine), items, 3),
                "REFUSED", "share workspace")

        # Cross-FIELD overlap: worker 1's workspace inside worker 0's
        # artifact root.  Same-field comparison alone calls this disjoint,
        # and then worker 0's teardown removes worker 1's checkout.
        cross = trio("cross")
        cross[1] = worker(1,
                          workspace=os.path.join(cross[0].artifacts_root, "ws1"),
                          out_path=out_in("cross", 1),
                          artifacts_root=os.path.join(root, "cross", "art1"))
        refuses("one worker's workspace inside another's artifact root is refused",
                lambda: merge_shards(build("cross", cross, mine), items, 3),
                "REFUSED", "overlaps", "inside the other's tree")

        # Row-level integrity: the merge reads these files as evidence, so
        # a row it cannot attribute is a refusal, not a skip.
        noid = build("noid", trio("noid"), mine)
        with open(trio("noid")[0].out_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"outcome": "passed"}) + "\n")
        refuses("a row with no item_id is refused, not dropped",
                lambda: merge_shards(noid, items, 3), "REFUSED", "no item_id")

        half = build("half", trio("half"), mine)
        with open(trio("half")[0].out_path, "a", encoding="utf-8") as fh:
            fh.write('{"item_id": "item:3", "outcome": "pas')
        refuses("a half-written row is refused, not skipped",
                lambda: merge_shards(half, items, 3),
                "REFUSED", "is not JSON", "died")

        twice_row = build("twicerow", trio("twicerow"), mine)
        w_first = trio("twicerow")[0]
        with open(w_first.out_path, "a", encoding="utf-8") as fh:
            # Stamped like a real row: the point of this fixture is the
            # DUPLICATE, not an unbound row, and an unstamped one would trip
            # the campaign-binding check first and report the wrong fault.
            fh.write(json.dumps(dict(stamp_of(fp),
                                     item_id=assign[0][0], outcome="failed",
                                     campaign_digest=w_first.campaign_digest,
                                     shard=w_first.shard)) + "\n")
        refuses("one shard emitting the same item twice is refused, and named "
                "as a within-shard repeat",
                lambda: merge_shards(twice_row, items, 3),
                "REFUSED", "within a single shard", assign[0][0])

        nofp = build("nofp", trio("nofp"), mine)
        doc = json.load(open(nofp[1], encoding="utf-8"))
        del doc["campaign"]
        with open(nofp[1], "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, sort_keys=True))
        refuses("a manifest with no embedded fingerprint cannot be verified",
                lambda: merge_shards(nofp, items, 3),
                "REFUSED", "embeds no campaign")

        refuses("write_merged refuses a digest its own fingerprint does not "
                "produce",
                lambda: write_merged(dict(res, campaign_digest="0" * 16),
                                     os.path.join(root, "forged.jsonl")),
                "REFUSED", "hashes to", "nothing produced")

    # ---- the archived campaigns.  Skipped, loudly, when absent. -----------
    #
    # The synthetic vector proves the hashing did not move.  These prove the
    # published campaigns still verify against it: every sidecar on disk is
    # re-hashed from its own stored fingerprint, and the four whose digests
    # were quoted in results are additionally pinned here by literal.  The two
    # checks catch different accidents -- re-hashing catches a fingerprint
    # edited on disk, the literal catches a sidecar REPLACED wholesale (both
    # halves rewritten, self-consistent, and no longer the run that was
    # published).  Skipped rather than failed off-machine: the artifacts are
    # not in the repository, and a check that cannot run must say so rather
    # than report a pass it did not earn.
    runs_root = "/data2/binhang/coreshop_bench/artifacts/runs"
    published = {
        # THE published headline run.
        "eval100_std.merged.jsonl.campaign.json": "6a30c74eae15dba1",
        "eval100_openhands_c15.merged.jsonl.campaign.json": "c39d2394c4de3d5f",
        "eval100_openhands_c2.merged.jsonl.campaign.json": "db0cefe2c528c5f7",
        "eval100_openhands_c3.merged_v3.jsonl.campaign.json": "7026ab59cdb944ea",
    }
    if os.path.isdir(runs_root):
        found = set()
        for name in sorted(os.listdir(runs_root)):
            if not name.endswith(".campaign.json"):
                continue
            try:
                side = _read_json(os.path.join(runs_root, name))
                actual = campaign_digest(side["campaign"])
            except (SystemExit, KeyError, ValueError, OSError) as e:  # noqa: BLE001
                check(f"{name}: re-hashes from its own fingerprint", False,
                      f"{type(e).__name__}: {e}")
                continue
            check(f"{name}: the digest it carries is the one its fingerprint "
                  f"produces", actual == side.get("campaign_digest"),
                  f"stored {side.get('campaign_digest')}, recomputed {actual}")
            if name in published:
                found.add(name)
                check(f"{name}: still hashes to the digest it was published "
                      f"under", actual == published[name],
                      f"published {published[name]}, recomputed {actual}")
        check("every published campaign sidecar is present in the archive",
              found == set(published),
              f"absent: {sorted(set(published) - found)}")
    else:
        print(f"  [SKIP] archived-campaign check: {runs_root} is not on this "
              f"machine")

    print("\n" + ("ALL PASS (campaign)" if ok else "FAILURES (campaign)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
