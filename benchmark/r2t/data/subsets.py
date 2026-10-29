"""Committed subset sampling, and a sidecar for every subset we publish.

`release/eval100.jsonl` is the 100 items behind the published pass@1.  Its
sampling rule was written down in prose, in a scratch artifact, and never
committed as code — so for a reader the subset was a bag of 100 item ids
with a story attached.  This module is the correction, in two halves.

The first half is a sampler that runs from the PUBLIC release alone
(`items_v1.jsonl` + the published `closure_clusters.json` map), so a
future subset is drawn by code that ships with the benchmark and writes
down what it did.

The second half is a rule about publishing: every `eval*.jsonl` under
`release/` must carry a provenance sidecar whose digests match the file's
actual bytes, or be a declared annotated companion of such a subset.
Companions preserve the original ordered rows except `target_interfaces`;
their selection facts come from validating the ORIGINAL bytes and sidecar.
`selftest` refuses otherwise.  A sidecar that no longer
describes the file next to it is worse than no sidecar, because it reads
as an audit that happened.

**We do not regenerate eval100.**  It is frozen BY CONTENT: the published
5/100 was measured on those exact items, and a script that produced a
different 100 would silently invalidate the number rather than explain
it.  `release/v1/eval100.provenance.json` is therefore a POST-HOC record
— it quotes the rule as we found it, freezes the content digest, and says
plainly that no sampler existed when the draw was made.

It also records an honest mismatch.  The recorded rule deduplicated by
"distinct step-definition set", and the finest such key lives in the
extraction artifacts (`closures.json`, per-step `definition` records),
which the release does not ship.  What the release publishes is each
item's closure FILE-SET cluster (`closure_clusters.json`, computed from
the gold `files` lists that now ship in the gated scoring bundle), a
coarser key: under it the 100 items fall into 77 clusters, not 100.  So
this sampler's clusters are not the clusters eval100 was drawn against,
and it could not reproduce eval100 even with the recorded seed.  That is
the whole reason the sidecar says `reconstructed: true`.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
from typing import Iterable, Optional
from ..core.paths import BENCHMARK_ROOT

#: Bumped whenever the selection ARITHMETIC changes — a subset drawn under
#: version 1 and one drawn under version 2 are not comparable draws, and the
#: sidecar has to make that visible without anyone diffing this file.
#:
#: 2: `_allocate` distributes the seats above the floor by largest remainder,
#:    as it always claimed to.  Version 1 walked the families in a loop that
#:    handed +1 to EVERY family with capacity left on each pass, which is a
#:    levelling rule, not a proportional one: it drew {a: 5, b: 5} from a 90:10
#:    pool at n=10 where the quotas are 9 and 1.  No published subset was drawn
#:    under version 1 (`release/eval100.jsonl` predates this module entirely
#:    and carries no algorithm_version), but any scratch draw made from it is
#:    a different rule and the number says so.
ALGORITHM_VERSION = 2
CLOSURE_MAP_NAME = "closure_clusters.json"

# Fresh sidecars use /2.  Version 1 recorded output digests and sampler knobs,
# but an inferential reader trusted those declarations: deleting
# `inference_valid`, or flipping the sibling mode together with it, could make
# the same subset look inference-safe.  /2 pins the closure map as an input and
# is replayed from the pinned pool + closure-map bytes (or, for an
# operator-built release, the bundle's gold sidecars) before its inference mode
# is believed.  The two shipped /1 sidecars are permanent historical artifacts;
# they are accepted only when the VERSIONS-authenticated dataset manifest pins
# their exact bytes (see `_authenticated_legacy_sidecar`).
LEGACY_SCHEMA = "r2t.subset_provenance/1"
SCHEMA = "r2t.subset_provenance/2"

#: A subset file is recognised by NAME.  This is a nominal rule, not a
#: structural one: `items_v1.jsonl` is the full pool (its selection is
#: already audited by `release/exclusions.csv` + `summary.json`, which is a
#: different artifact from a subset sidecar), and a subset published under
#: some other basename would slip past this check.  The rule is written down
#: here so that the next name is chosen to be caught.
SUBSET_PREFIX = "eval"

#: The pool a published subset must be a subset OF.  Named here because the
#: membership check needs a file to check against, and the release ships
#: exactly one pool.
POOL_NAME = "items_v1.jsonl"

#: ...until it shipped two.  A per-project release (`release/python-docx/`)
#: carries its own pool and its own closure map, because a docx item is not in
#: CoreShop's `items_v1.jsonl` and never will be; checking one project's
#: subset against another project's pool would report every id as invented.
#: So the pool is resolved NEAREST FIRST — the subset's own directory, then
#: the release root — and both names are accepted, `items_v1.jsonl` because
#: v1's bytes are frozen under it and `items.jsonl` because a second pool
#: under the same name would collide with a digest `VERSIONS.yml` pins.
#:
#: This is a rule about WHICH POOL, not a relaxation of the membership check:
#: a subset with no pool anywhere above it is still a problem, and it is
#: still an id-by-id comparison.
POOL_NAMES = (POOL_NAME, "items.jsonl")


class SubsetRefused(RuntimeError):
    """Raised instead of guessing.  Messages start with `REFUSED:`."""


def _refuse(message: str) -> "SubsetRefused":
    return SubsetRefused("REFUSED: " + message)


# ---------------------------------------------------------------- digests

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return sha256_bytes(fh.read())


def id_list_digest(item_ids: Iterable[str]) -> str:
    """Digest of the SET of ids, independent of the file's line order.

    Sorted and newline-joined, so a subset that is re-serialised or
    re-ordered still digests the same — the claim being frozen is "these
    100 items", not "this byte layout".  The byte layout has its own
    digest (`content_sha256`) next to it.
    """
    return sha256_bytes("\n".join(sorted(item_ids)).encode("utf-8"))


# ------------------------------------------------------------- item files

def read_items(items_path: str) -> list[tuple[str, str]]:
    """[(item_id, raw line)] — the raw line is kept deliberately.

    A subset writes back the SOURCE bytes of each line it selected, so the
    subset is a literal subset of the pool file rather than a re-encoding
    of it that happens to carry the same fields.
    """
    if not os.path.isfile(items_path):
        raise _refuse(f"no items file at {items_path}. A subset cannot be "
                      f"drawn from a pool that is not there.")
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    with open(items_path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise _refuse(f"{items_path}:{lineno} is not JSON ({exc}). "
                              f"Half a pool is not a pool.") from exc
            iid = row.get("item_id")
            if not iid:
                raise _refuse(f"{items_path}:{lineno} has no item_id; items "
                              f"without an identity cannot be sampled or "
                              f"cited.")
            if iid in seen:
                raise _refuse(f"{items_path} contains {iid} twice. A "
                              f"duplicated item would weight the draw "
                              f"silently.")
            seen.add(iid)
            out.append((iid, line if line.endswith("\n") else line + "\n"))
    if not out:
        raise _refuse(f"{items_path} is empty.")
    return out


# ------------------------------------------------------------------ strata

def feature_family(item_id: str) -> str:
    """The directory that immediately contains the .feature file.

    Item ids are `project/relative/path/to/x.feature:<line>`, e.g.

        coreshop/features/domain/cart/create_cart.feature:27      -> cart
        coreshop/features/domain/cart/rules/store_condition...    -> rules
        coreshop/features/domain/cart/rules/cart_item/amount...   -> cart_item

    So the family is the LAST path segment before the filename — nested
    rule directories are their own family rather than folding into their
    parent.  That is the rule the recorded eval100 prose implies and it is
    the one we keep; it is a shallow rule, and a repository that nests
    differently would need a different one.
    """
    head, _, line = item_id.rpartition(":")
    if not head or not line.isdigit():
        raise _refuse(f"item_id {item_id!r} is not 'path/to/x.feature:<line>'; "
                      f"the feature family cannot be derived from it.")
    if not head.endswith(".feature"):
        raise _refuse(f"item_id {item_id!r} does not name a .feature file; "
                      f"the feature family cannot be derived from it.")
    family = os.path.basename(os.path.dirname(head))
    if not family:
        raise _refuse(f"item_id {item_id!r} has no directory above the "
                      f"feature file, so it has no family.")
    return family


# ---------------------------------------------------------------- clusters

def _closure_clusters(gold_dir: str) -> dict[str, str]:
    """item_id -> a digest of its closure's FILE SET.

    Two items land in the same cluster when the reference solution removes
    and restores exactly the same files, i.e. solving one is close to
    solving the other.  Released projects publish the resulting map beside
    their pool.  A bundle or freshly built release may instead provide its
    gold directory, in which case the map is reconstructed from sidecars.

    (`release.closure_clusters` computes the same partition; the
    duplication is accepted deliberately — the two induce
    the byte-identical 77-cluster partition on eval100, their ids are never
    serialized side by side, and this module staying importable without
    release.py is worth one duplicated join.)
    """
    map_path = os.path.join(gold_dir, CLOSURE_MAP_NAME)
    if os.path.isfile(map_path):
        with open(map_path, encoding="utf-8") as fh:
            return json.load(fh)
    if not os.path.isdir(gold_dir):
        raise _refuse(f"no project release or gold directory at {gold_dir}. "
                      f"Without a published closure map or gold sidecars, "
                      f"items cannot be clustered and a 'one per cluster' "
                      f"subset cannot be claimed.")
    sidecar_dir = gold_dir
    manifest_path = os.path.join(sidecar_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        sidecar_dir = os.path.join(gold_dir, "gold")
        manifest_path = os.path.join(sidecar_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        raise _refuse(f"no published closure map or gold manifest under "
                      f"{gold_dir}; no source says which closure belongs to "
                      f"which item.")
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)

    clusters: dict[str, str] = {}
    for iid in sorted(manifest):
        path = os.path.join(sidecar_dir, manifest[iid])
        if not os.path.isfile(path):
            raise _refuse(f"gold sidecar {manifest[iid]} for {iid} is listed "
                          f"in the manifest but missing from {sidecar_dir}.")
        with open(path, encoding="utf-8") as fh:
            gold = json.load(fh)
        files = gold.get("files")
        if not files:
            raise _refuse(f"gold sidecar for {iid} has no 'files'; its "
                          f"closure is unknown, so it cannot be clustered.")
        joined = "\n".join(sorted(files))
        clusters[iid] = hashlib.sha1(joined.encode("utf-8")).hexdigest()[:12]
    return clusters


def _closure_map_digest(clusters: dict[str, str]) -> str:
    """Digest the complete item -> closure partition used by the sampler.

    A manifest digest alone would pin only the sidecar filenames, while a
    count would let membership move between clusters.  This canonical map is
    the exact sampler input: changing any gold closure changes the digest even
    when the number of clusters stays constant.
    """
    encoded = "".join(f"{iid}\t{clusters[iid]}\n" for iid in sorted(clusters))
    return sha256_bytes(encoded.encode("utf-8"))


# ----------------------------------------------------------- allocation

def _allocate(sizes: dict[str, int], n: int) -> dict[str, int]:
    """Largest-remainder proportional allocation, floor 1 per stratum.

    A family's fair share is its quota `size * n / total`.  Each family is
    seated at `floor(quota)`, then raised to its floor of `min(1, size)` and
    lowered to its cap of `size` — the cap because a family cannot yield more
    representatives than it has, the floor because a subset that silently
    omits a family is a different sampling rule wearing the same name.

    Those two bounds move seats around, so the balance is settled by the
    same proportional rule that placed the rest: a seat still to place goes
    to the family furthest BELOW its quota, a seat over budget is taken back
    from the family furthest ABOVE it.  With no bound binding, that is
    exactly largest remainder — every family sits on `floor(quota)` and the
    spare seats land on the largest fractional remainders, at most one each.

    The comparison is integer arithmetic (`size*n - alloc*total`, the quota
    deficit scaled by `total`) so no allocation turns on a float rounding,
    and ties break on family name, so the result depends on nothing but the
    inputs.  Refuses rather than dropping a stratum when `n` is smaller than
    the number of strata.
    """
    families = sorted(sizes)
    if n < len(families):
        raise _refuse(f"n={n} with a floor of 1 per family and "
                      f"{len(families)} families: some family would get "
                      f"zero. Ask for n >= {len(families)}, or say plainly "
                      f"that the subset is not stratified.")
    total = sum(sizes.values())
    if n > total:
        raise _refuse(f"n={n} exceeds the {total} cluster representatives "
                      f"available to draw from. The pool holds more items "
                      f"than that, but items sharing a closure cluster are "
                      f"represented once, and a subset cannot seat a "
                      f"representative twice.")

    floors = {f: min(1, sizes[f]) for f in families}
    alloc = {f: max(floors[f], min(sizes[f], (sizes[f] * n) // total))
             for f in families}

    # quota - allocated, scaled by `total` so the comparison stays integral.
    def deficit(f: str) -> int:
        return sizes[f] * n - alloc[f] * total

    placed = sum(alloc.values())
    while placed < n:
        below = [f for f in families if alloc[f] < sizes[f]]
        if not below:  # pragma: no cover - guarded by n > total above
            raise _refuse(f"cannot place {n - placed} more items: every "
                          f"family is exhausted.")
        pick = min(below, key=lambda f: (-deficit(f), f))
        alloc[pick] += 1
        placed += 1
    while placed > n:
        above = [f for f in families if alloc[f] > floors[f]]
        if not above:  # pragma: no cover - guarded by n < len above
            raise _refuse(f"cannot place {placed} items in a subset of "
                          f"{n}: every family is already at its floor.")
        pick = min(above, key=lambda f: (deficit(f), f))
        alloc[pick] -= 1
        placed -= 1
    return alloc


def _allocate_unfloored(sizes: dict[str, int], n: int) -> dict[str, int]:
    """`_allocate` without the floor, for an item spanning more files than B.

    With more files than seats, a floor of one per file is arithmetically
    impossible; dropping the floor is the only alternative to dropping the
    item, and 321 of CoreShop's 422 items are in that position, so this is
    the ordinary case rather than a corner.  What is kept is the rest of the
    rule -- integer largest remainder over the same `size*n - alloc*total`
    deficit, ties by file name -- so the two branches differ in exactly one
    thing and the difference is recorded per item in `unfloored_items`.

    Caller's precondition (the only branch that reaches it): `n < total`, so
    every seat can be placed and no file ever needs one taken back.
    """
    files = sorted(sizes)
    total = sum(sizes.values())
    alloc = {f: min(sizes[f], (sizes[f] * n) // total) for f in files}

    def deficit(f: str) -> int:
        return sizes[f] * n - alloc[f] * total

    placed = sum(alloc.values())
    while placed < n:
        below = [f for f in files if alloc[f] < sizes[f]]
        pick = min(below, key=lambda f: (-deficit(f), f))
        alloc[pick] += 1
        placed += 1
    return alloc


# ------------------------------------------------------------- the sampler

def sample(items_path: str, gold_dir: str, n: int, seed: int,
           strata_key: str = "feature_family",
           allow_cluster_siblings: bool = False) -> dict:
    """Draw a subset, and describe the draw well enough to repeat it.

    (a) items are clustered by closure file set; (b) by default at most one
    item per cluster survives, the lexicographically first item_id, so the
    subset cannot spend ten of its seats on ten spellings of one problem;
    (c) the survivors are stratified by feature family and allocated
    proportionally with a floor of 1; (d) the within-family draws come
    from a single `random.Random(seed)` walked over families in sorted
    order, and the output is sorted by item_id.

    Determinism is per (pool, n, seed): the same inputs give byte-identical
    output forever.  It is NOT stable under a changing pool — adding items
    shifts the family sizes and the shared RNG stream, so a later draw with
    the same seed is a different subset.  That is why the sidecar digests
    the source pool as well as the result.

    `allow_cluster_siblings=True` is a deliberately different, descriptive
    mode.  It samples from every item rather than one representative per
    closure, which permits a larger table but does not manufacture additional
    independent observations.  Its sidecar therefore records
    `inference_valid: false`; inferential consumers must not reinterpret its
    item count as a cluster count.

    Returns a dict with `lines` (source bytes of the selected items),
    `item_ids`, and a complete `provenance` document.
    """
    if strata_key != "feature_family":
        raise _refuse(f"strata_key={strata_key!r} is not implemented; only "
                      f"'feature_family' is, and inventing a stratification "
                      f"here would put a name on a draw nobody designed.")
    if n <= 0:
        raise _refuse(f"n={n} is not a subset.")

    items = read_items(items_path)
    clusters = _closure_clusters(gold_dir)

    missing = [iid for iid, _ in items if iid not in clusters]
    if missing:
        raise _refuse(f"{len(missing)} items have no gold sidecar (first: "
                      f"{missing[0]}). Their closure is unknown, so a "
                      f"'one per cluster' claim would cover items nobody "
                      f"clustered.")

    by_cluster: dict[str, list[str]] = {}
    for iid, _line in items:
        by_cluster.setdefault(clusters[iid], []).append(iid)
    representatives = sorted(min(group) for group in by_cluster.values())
    candidates = (sorted(iid for iid, _line in items)
                  if allow_cluster_siblings else representatives)
    if allow_cluster_siblings and n > len(candidates):
        raise _refuse(f"n={n} exceeds the {len(candidates)} individual items "
                      f"available in descriptive sibling-permitted mode.")

    sizes: dict[str, int] = {}
    family_of = {iid: feature_family(iid) for iid in candidates}
    for iid in candidates:
        fam = family_of[iid]
        sizes[fam] = sizes.get(fam, 0) + 1
    alloc = _allocate(sizes, n)

    rng = random.Random(seed)
    chosen: list[str] = []
    for fam in sorted(alloc):
        pool = sorted(iid for iid in candidates if family_of[iid] == fam)
        chosen.extend(rng.sample(pool, alloc[fam]))
    chosen.sort()

    line_of = dict(items)
    lines = [line_of[iid] for iid in chosen]
    content = "".join(lines)
    strata = {}
    for iid in chosen:
        fam = family_of[iid]
        strata[fam] = strata.get(fam, 0) + 1

    provenance = {
        "schema": SCHEMA,
        "algorithm_version": ALGORITHM_VERSION,
        "seed": seed,
        "n": len(chosen),
        "strata_key": strata_key,
        "strata": dict(sorted(strata.items())),
        "source_items": os.path.basename(items_path),
        "source_items_sha256": sha256_file(items_path),
        "closure_map_sha256": _closure_map_digest(clusters),
        "item_id_list_digest": id_list_digest(chosen),
        "content_sha256": sha256_bytes(content.encode("utf-8")),
        "clusters": {
            "total": len(by_cluster),
            "represented": len({clusters[iid] for iid in chosen}),
        },
        "allow_cluster_siblings": bool(allow_cluster_siblings),
        "inference_valid": not allow_cluster_siblings,
        # A CENSUS is not a small sample, and the difference has to be on the
        # sidecar rather than inferred from two equal numbers.  When n equals
        # the number of clusters, every cluster's representative is seated:
        # the seed selected nothing, the allocation chose nothing, and a
        # reader who takes `seed: 20260802` for evidence of random sampling
        # would be reading a draw that had no choices to make.  It is also
        # the difference between "these 32 stand for the corpus" and "these
        # 32 ARE the corpus, one item per distinct closure".
        "census": (not allow_cluster_siblings
                   and len({clusters[iid] for iid in chosen})
                   == len(by_cluster)),
        "generated_by": "scripts/sample_subset.py",
        "reconstructed": False,
    }
    if allow_cluster_siblings:
        provenance["inference_reason"] = (
            "closure-cluster siblings are permitted; item rows are "
            "descriptive and are not independent units of inference")
    return {"item_ids": chosen, "lines": lines, "provenance": provenance}



# ------------------------------------------------- the headroom filter

#: `r2t.headroom_subset/1` is a different document from a subset provenance
#: sidecar, not a version of it: nothing in it replays a stratified draw, and
#: the identity it pins is six run files and a boundary rather than a pool and
#: a closure map.  `ALGORITHM_VERSION` above therefore does not move with it.
HEADROOM_SCHEMA = "r2t.headroom_subset/1"
HEADROOM_ALGORITHM_VERSION = 1

#: The output's basename prefix.  Deliberately NOT `eval`: `subset_files` and
#: the release gate walk `eval*.jsonl`, and a headroom subset is an
#: agent-relative filter that no inferential reader may pick up.
HEADROOM_PREFIX = "headroom"

#: Not a parameter (HEADROOM_SUBSET_AND_BUDGETED_SAMPLE_SPEC.md section 1):
#: the control slice is what measures the filter, and a fraction an operator
#: may turn down is a control that can be turned off.
CONTROL_FRACTION = 0.20

#: The section 1 sentence, written into every sidecar, so that a reader
#: holding the subset does not have to hold the specification too.
HEADROOM_SELECTION_RULE = (
    "An item is IN the headroom subset when it was not solved non-vacuously "
    "by both agents in every sample in which it was run; solved "
    "non-vacuously means the item's row in that run's merged.jsonl has "
    "outcome == 'passed' AND the row lands in the covering bucket of "
    "r2t.bench.results.production_coverage. Added to it is a random 20 "
    "percent control slice of the items solved non-vacuously by both agents "
    "in all three samples, drawn with a recorded seed, which measures what "
    "the filter did.")

#: Why a headroom subset can never be read as an independent sample.
HEADROOM_INFERENCE_REASON = (
    "the selection is agent-relative: it is curated against the failures of "
    "the same two agents it is later used to compare, so a level-2 number "
    "over it regresses to the mean and is reported only beside the level-1 "
    "number over the full satisfied set")


def _headroom_runs(runs: Iterable[tuple]) -> dict[str, dict[int, str]]:
    """The six labelled runs, or the refusal that says which six are needed."""
    runs = [tuple(entry) for entry in runs]
    if len(runs) != 6:
        raise _refuse(f"{len(runs)} run file(s): the filter is defined over "
                      f"exactly six, two agents x three samples. Fewer is a "
                      f"weaker condition than 'solved in every sample it was "
                      f"run in' wearing the same name.")
    by_agent: dict[str, dict[int, str]] = {}
    for agent, sample_no, path in runs:
        by_agent.setdefault(agent, {})[int(sample_no)] = path
    if len(by_agent) != 2 or any(set(samples) != {1, 2, 3}
                                 for samples in by_agent.values()):
        seen = "; ".join(f"{agent}={sorted(samples)}"
                         for agent, samples in sorted(by_agent.items()))
        raise _refuse(
            f"the six runs are {seen}; the filter needs exactly two agents, "
            f"each with samples 1, 2 and 3. Three samples are what keep a "
            f"noisy pass@1 from selecting itself.")
    for _agent, _sample_no, path in runs:
        if not os.path.isfile(path):
            raise _refuse(f"no run file at {path}. An item cannot be called "
                          f"unsolved on the strength of a run that is not "
                          f"there.")
    return {agent: dict(sorted(samples.items()))
            for agent, samples in sorted(by_agent.items())}


def headroom_subset(items_path: str, runs: Iterable[tuple],
                    boundary_path: str, control_seed: int) -> dict:
    """Every item the two agents did not both solve non-vacuously, every time.

    An item-level FILTER over a level-1 census, not a draw: nothing is
    sampled except the control slice, so there is no `n` and no stratum.
    What it removes is the saturated part of the census -- the items where a
    level-2 comparison has nothing left to measure -- and what it adds back
    is a 20 percent control slice of the items solved in all three samples,
    because a filter curated against the same two agents it later compares
    regresses to the mean and the control is the only thing that can show it.

    The census is run ADAPTIVELY (PLAN 6a): sample 1 covers every item, and a
    later sample is run only on what that agent had still solved.  So the
    criterion is over the samples an item was actually run in, and the
    containment that makes that criterion mean anything -- sample 1 is the
    whole file, each later sample is inside what survived -- is checked here
    rather than assumed of the operator who launched the runs.

    "Solved non-vacuously" is not restated: it is `production_coverage`'s
    `covering` bucket over the run's passed rows, asked of `bench` rather
    than copied, so this filter and the diagnostic cannot drift into
    disagreeing about which passes touched production code.  A PASSED row
    whose coverage was never collected refuses the whole draw: it is a run
    launched without `--coverage`, and treating it either way would be
    reading a harness setting as evidence about an item.

    Returns `lines`, `item_ids`, a complete `provenance` and the `name` the
    artifact must be written under.
    """
    # `data` imports `core` at module level and reaches `bench` only through
    # a function-local edge (core/components.py fact (c),
    # `KNOWN_DATA_ROUTE_EDGES`).  Both edges are here because this filter is
    # DEFINED by the two readers below rather than merely helped by them.
    from ..bench import metrics as M
    from ..bench import results as R
    from ..core.boundary import load_boundary
    from .profile import config_stem

    if control_seed is None:
        raise _refuse("a headroom subset without a control seed cannot be "
                      "redrawn, and its control slice is the only evidence "
                      "of what the filter removed.")
    by_agent = _headroom_runs(runs)
    items = read_items(items_path)
    pool_ids = {iid for iid, _line in items}
    boundary = load_boundary(boundary_path)

    source_runs = []
    covering_by_run: dict[tuple, set] = {}
    ran_by_run: dict[tuple, set] = {}
    for agent, samples in by_agent.items():
        for sample_no, path in samples.items():
            rows = M.read_runs(path)
            passed = {iid for iid, row in rows.items()
                      if row.get("outcome") == "passed"}
            block = R.production_coverage(rows, passed, boundary, len(rows))
            if block["not_collected_items"]:
                raise _refuse(
                    f"{path} has {block['n_not_collected']} passed row(s) "
                    f"whose coverage was never collected (e.g. "
                    f"{block['not_collected_items'][0]}). That is a run "
                    f"launched without --coverage, not evidence that the "
                    f"item was or was not solved; re-run it with coverage.")
            # Containment (section 1).  Sample 1 is the whole census; a later
            # sample may only revisit what that agent had still solved, and a
            # run that widens instead makes "in every sample it was run in" a
            # different condition for different items.
            if sample_no == 1:
                if set(rows) != pool_ids:
                    raise _refuse(
                        f"{agent} sample 1 scores {len(rows)} item(s), not "
                        f"the {len(pool_ids)} of "
                        f"{os.path.basename(items_path)}. Sample 1 is the "
                        f"level-1 census itself.")
            else:
                allowed = set(pool_ids)
                for earlier in range(1, sample_no):
                    allowed &= covering_by_run[(agent, earlier)]
                widened = sorted(set(rows) - allowed)
                if widened:
                    raise _refuse(
                        f"{agent} sample {sample_no} scores "
                        f"{len(widened)} item(s) that {agent} had not solved "
                        f"non-vacuously in every earlier sample (e.g. "
                        f"{widened[0]}). The census is run adaptively, and a "
                        f"later sample that widens the set makes 'solved in "
                        f"every sample it was run in' mean something "
                        f"different for every item.")
            covering_by_run[(agent, sample_no)] = set(block["covering_items"])
            ran_by_run[(agent, sample_no)] = set(rows)
            source_runs.append({
                "agent": agent, "sample": sample_no, "path": path,
                "sha256": sha256_file(path),
                "n_items": len(rows), "n_passed": block["n_passed"],
                "n_covering": block["n_covering"],
                "n_zero": block["n_zero_production_lines"],
                "n_not_collected": block["n_not_collected"],
            })

    # An item is out of the subset when every run that CONTAINED it solved it
    # non-vacuously; the adaptive census means that is a different number of
    # runs for different items, which is why both are counted per item.
    ran_in = {iid: 0 for iid in pool_ids}
    solved_in = {iid: 0 for iid in pool_ids}
    for key, ran in ran_by_run.items():
        for iid in ran:
            ran_in[iid] += 1
        for iid in covering_by_run[key]:
            solved_in[iid] += 1

    headroom = sorted(iid for iid in pool_ids
                      if solved_in[iid] < ran_in[iid])
    solved_all = sorted(iid for iid in pool_ids
                        if solved_in[iid] == len(covering_by_run))
    # Integer ceiling, no float arithmetic: two implementations of `0.2 * n`
    # disagree on where the rounding goes, and the slice is a published count.
    k = (len(solved_all) + 4) // 5
    control = sorted(random.Random(control_seed).sample(solved_all, k))
    chosen = sorted(headroom + control)

    line_of = dict(items)
    lines = [line_of[iid] for iid in chosen]
    content = "".join(lines)
    labelled = {iid: "control" for iid in control}
    labelled.update({iid: "headroom" for iid in headroom})

    provenance = {
        "schema": HEADROOM_SCHEMA,
        "algorithm_version": HEADROOM_ALGORITHM_VERSION,
        "source_runs": source_runs,
        "level1_item_count": len(pool_ids),
        "solved_by_both_all_samples": len(solved_all),
        "headroom": len(headroom),
        "control_fraction": CONTROL_FRACTION,
        "control_seed": control_seed,
        "control": len(control),
        # Which of the two reasons put each item here.  A level-2 number over
        # the whole file is a number over two populations; the labels are
        # what let the control be read as the control.
        "items": dict(sorted(labelled.items())),
        "selection_rule": HEADROOM_SELECTION_RULE,
        "boundary_sha256": sha256_file(boundary_path),
        "inference_valid": False,
        "inference_reason": HEADROOM_INFERENCE_REASON,
        "source_items": os.path.basename(items_path),
        "source_items_sha256": sha256_file(items_path),
        "item_id_list_digest": id_list_digest(chosen),
        "content_sha256": sha256_bytes(content.encode("utf-8")),
    }
    return {"item_ids": chosen, "lines": lines, "provenance": provenance,
            "name": f"{HEADROOM_PREFIX}_{config_stem(boundary.project)}",
            "replay_context": {"items": os.path.abspath(items_path),
                               "boundary": os.path.abspath(boundary_path)}}


def headroom_boundary_path(items_path: str) -> str:
    return os.path.splitext(items_path)[0] + ".boundary.yml"


def replay_headroom(items_path: str) -> dict:
    """Recompute W4 from the preserved census, exact boundary and six runs."""
    path = os.path.abspath(items_path)
    sidecar = os.path.splitext(path)[0] + ".provenance.json"
    try:
        with open(sidecar, encoding="utf-8") as handle:
            document = json.load(handle)
        if document.get("schema") != HEADROOM_SCHEMA:
            raise _refuse("headroom replay requires its own provenance schema")
        source = document.get("source_items")
        if not isinstance(source, str) or not source or os.path.basename(source) != source:
            raise _refuse("headroom source_items must be the preserved census basename")
        source_path = os.path.join(os.path.dirname(path), source)
        if source_path == path:
            raise _refuse("headroom cannot name itself as its source census")
        if source.startswith(SUBSET_PREFIX):
            # A named current census retains its own original selection proof.
            identify_for_inference(source_path)
        boundary = headroom_boundary_path(path)
        if sha256_file(source_path) != document.get("source_items_sha256"):
            raise _refuse("headroom census bytes changed")
        if sha256_file(boundary) != document.get("boundary_sha256"):
            raise _refuse("headroom boundary bytes differ from the recorded coverage classification")
        runs = [(row["agent"], row["sample"], row["path"])
                for row in document["source_runs"]]
        expected = headroom_subset(source_path, runs, boundary, document["control_seed"])
        with open(path, "rb") as handle:
            raw = handle.read()
        if expected["provenance"] != document or raw != "".join(expected["lines"]).encode("utf-8"):
            raise _refuse("headroom bytes/provenance do not rederive from the exact census, boundary and source runs")
        if os.path.basename(path) != expected["name"] + ".jsonl":
            raise _refuse("headroom file does not retain its project name")
        return {"provenance": document, "items": path, "sidecar": sidecar,
                "source_items": source_path, "boundary": boundary,
                "item_ids": expected["item_ids"]}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        if isinstance(exc, SubsetRefused):
            raise
        raise _refuse(f"cannot replay headroom input {path}: {exc}") from exc


# ----------------------------------------------- the per-item mutant budget

#: The sidecar beside the DERIVED MAP.  The map is the population every leg
#: runs (`mutation-run --map`); this document is what says the map is a
#: budgeted draw, from which parent, under which seed.
BUDGETED_SCHEMA = "r2t.budgeted_sample/1"
#: The word this basis is called, written once and used twice: the sidecar's
#: own `basis` field, and the `population_basis` a consumer stamps on a leg's
#: campaign identity.  Nothing compares the two -- which document a sidecar
#: is has already been decided by its `BUDGETED_SCHEMA` pin, and a second
#: comparison against a field the same module wrote would prove nothing --
#: so this exists to keep one word out of two literals.
BUDGETED_BASIS = "budgeted_sample"


def _read_json(path: str, what: str) -> dict:
    if not os.path.isfile(path):
        raise _refuse(f"no {what} at {path}.")
    try:
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
    except json.JSONDecodeError as exc:
        raise _refuse(f"{path} is not JSON ({exc}); half a {what} is not a "
                      f"{what}.") from exc
    if not isinstance(document, dict):
        # The enumerator's raw output is a JSON LIST and lives next to both
        # of these files, so naming the wrong one is a slip that would
        # otherwise surface as an attribute error.
        raise _refuse(f"{path} is a {type(document).__name__}, not a {what}.")
    return document


def budgeted_sample(items_path: str, map_path: str, manifest_path: str,
                    per_item: int, seed: int) -> dict:
    """B mutants per item, realised as a derived `r2t.mutant-map/1` map.

    The draw is not a scoring-time pin: it is the POPULATION every leg of the
    project executes.  So it is written as a second map of the same schema as
    its parent, built by `mutation_attestation.build_map_artifact`, and each
    leg's campaign identity binds that map's digest -- which is what makes a
    leg run against any other map a different population rather than a
    footnote.  The parent's `coverage_sha256` and `release_sha256` travel
    into it unchanged, because the derived map is a restriction of the same
    join over the same coverage run and release, and inventing new ones would
    claim evidence this draw never touched.

    Three shapes of item, all ordinary (section 2, measured on CoreShop's
    422): an item mapping at most B mutants takes all of them
    (`short_items`); an item spanning at most B files is allocated with
    `_allocate`'s floor of one seat per file; an item spanning more files
    than B is allocated without the floor (`unfloored_items`).  Each item
    draws from its own `random.Random(f"{seed}:{item_id}")`, so adding an
    item to the level-2 set changes no other item's draw -- unlike the
    shared stream of `sample()`, which is a draw over one fixed pool.
    """
    from . import mutation_attestation as A

    if seed is None:
        raise _refuse("an unseeded budgeted sample cannot be reproduced, so "
                      "the derived map would declare a population that no "
                      "rerun can reconstruct.")
    if not isinstance(per_item, int) or isinstance(per_item, bool) \
            or per_item < 1:
        raise _refuse(f"per_item={per_item!r} is not a budget; B is the "
                      f"number of mutants declared for each item and must be "
                      f"a positive integer.")

    items = read_items(items_path)
    parent = _read_json(map_path, "mutant map")
    manifest = _read_json(manifest_path, "mutant manifest")
    if parent.get("schema") != A.MAP_SCHEMA:
        raise _refuse(
            f"{map_path} is a {parent.get('schema')!r} document, not the "
            f"{A.MAP_SCHEMA} artifact `mutants map --release` writes. A "
            f"budgeted population is derived from an identified one; the "
            f"compatibility {{by_mutant, uncovered}} shape identifies "
            f"nothing to derive from.")
    if parent.get("manifest_digest") != manifest.get("digest"):
        raise _refuse(
            f"the map names manifest {parent.get('manifest_digest')!r} and "
            f"{os.path.basename(manifest_path)} digests to "
            f"{manifest.get('digest')!r}; the two are not one population.")
    try:
        A.validate_map(parent, manifest)
    except A.MutationAssetRefused as exc:
        raise _refuse(f"the parent map at {map_path} does not validate: "
                      f"{str(exc).removeprefix('REFUSED: ')}") from exc

    file_of = {mutant["id"]: mutant["file"] for mutant in manifest["mutants"]}
    eligible: dict[str, list[str]] = {}
    for mutant_id, mapped_items in sorted(parent["by_mutant"].items()):
        for iid in mapped_items:
            eligible.setdefault(iid, []).append(mutant_id)

    # An item the parent map knows nothing about is not a short item: it is
    # an item this map is not about (a stale map, or another project's), and
    # a sidecar that listed it under `short_items` with an empty draw would
    # be the silent narrowing section 5 forbids.
    unmapped = sorted(iid for iid, _line in items if not eligible.get(iid))
    if unmapped:
        raise _refuse(
            f"{len(unmapped)} item(s) in {os.path.basename(items_path)} have "
            f"no mutant in {os.path.basename(map_path)} (e.g. {unmapped[0]}); "
            "an item with no mapped mutant is not a short item, it is an item "
            "this map is not about.")
    allocation: dict[str, list[str]] = {}
    short_items: list[str] = []
    unfloored_items: list[str] = []
    for iid, _line in sorted(items):
        ids = eligible[iid]
        rng = random.Random(f"{seed}:{iid}")
        if len(ids) <= per_item:
            # Not a refusal (revision 2): 36 of CoreShop's 422 items map
            # fewer than 100 mutants, and an item that has fewer than its
            # budget has already declared its whole population.
            allocation[iid] = sorted(ids)
            short_items.append(iid)
            continue
        sizes: dict[str, int] = {}
        for mutant_id in ids:
            path = file_of[mutant_id]
            sizes[path] = sizes.get(path, 0) + 1
        if len(sizes) <= per_item:
            # Neither of `_allocate`'s refusals can fire here: this branch is
            # `len(sizes) <= per_item`, and `per_item < len(ids)` is the sum.
            seats = _allocate(sizes, per_item)
        else:
            seats = _allocate_unfloored(sizes, per_item)
            unfloored_items.append(iid)
        chosen: list[str] = []
        for path in sorted(seats):
            pool = sorted(mutant_id for mutant_id in ids
                          if file_of[mutant_id] == path)
            chosen.extend(rng.sample(pool, seats[path]))
        allocation[iid] = sorted(chosen)

    drawn: dict[str, list[str]] = {}
    for iid in sorted(allocation):
        for mutant_id in allocation[iid]:
            drawn.setdefault(mutant_id, []).append(iid)
    uncovered = sorted(set(file_of) - set(drawn))
    derived = A.build_map_artifact(
        manifest, drawn, uncovered,
        coverage_sha256=parent["coverage_sha256"],
        release_sha256=parent["release_sha256"])

    sidecar = {
        "schema": BUDGETED_SCHEMA,
        "basis": BUDGETED_BASIS,
        "per_item": per_item,
        "seed": seed,
        "parent_map_sha256": sha256_file(map_path),
        "parent_map_digest": parent["digest"],
        "derived_map_digest": derived["digest"],
        "manifest_digest": manifest["digest"],
        "stratify_by": "file",
        "allocation": dict(sorted(allocation.items())),
        "short_items": sorted(short_items),
        "unfloored_items": sorted(unfloored_items),
        "totals": {
            "items": len(allocation),
            "pairs": sum(len(ids) for ids in allocation.values()),
            "files": len({file_of[mutant_id]
                          for ids in allocation.values()
                          for mutant_id in ids}),
        },
    }
    return {"sidecar": sidecar, "derived_map": derived}


def verify_budgeted_sample(sidecar_path: str, parent_map_path: str) -> dict:
    """Read a budgeted sidecar against the parent map it is applied to.

    THE check every consumer makes before using a derived map: the
    allocation's mutant ids mean something only in the map they were drawn
    from, so a sidecar reused across two maps renames the population while
    every count downstream stays plausible.  Both halves of the parent's
    identity are compared -- the file's bytes and the artifact's own digest
    -- because a reserialised map is a different file and a mutated one is a
    different population, and only checking both tells those apart.
    """
    document = _read_json(sidecar_path, "budgeted sample sidecar")
    if document.get("schema") != BUDGETED_SCHEMA:
        raise _refuse(f"{sidecar_path} is a {document.get('schema')!r} "
                      f"document, not a {BUDGETED_SCHEMA}.")
    parent = _read_json(parent_map_path, "mutant map")
    actual_bytes = sha256_file(parent_map_path)
    if document.get("parent_map_sha256") != actual_bytes \
            or document.get("parent_map_digest") != parent.get("digest"):
        raise _refuse(
            f"{os.path.basename(sidecar_path)} was drawn from parent map "
            f"{document.get('parent_map_digest')} (file "
            f"{document.get('parent_map_sha256')}), and {parent_map_path} is "
            f"{parent.get('digest')} (file {actual_bytes}). The same mutant "
            f"ids under a different map are a different population.")
    return document


def admit_budgeted_derived_map(sidecar_path: str, parent_map_path: str,
                               derived_map_path: str, manifest: dict, *,
                               release_ids: Optional[set] = None) -> dict:
    """Admit a derived map as the budgeted restriction its sidecar declares.

    The consumer half of `budgeted_sample`, and the whole of what section 2
    means by "its membership re-derives from the parent map and the sidecar".
    A leg on a budgeted basis executes the DERIVED map, so the parent's byte
    pin cannot authenticate the file that leg runs; what authenticates it is
    this re-derivation.

    Nothing is re-drawn here.  The sidecar records `seed` and `per_item`, so
    anyone can redraw the sample offline and compare; a consumer that redrew
    it at execution time would be re-deciding the population at the moment of
    using it, which is exactly what a preregistered basis is not.  What is
    checked is that this map IS the draw the sidecar declares (its membership
    is the sidecar's `allocation`, and its own `digest` is the one the
    sidecar names) and that the draw is a restriction of the parent's join
    (the same items, no pair the parent does not have).

    The derived map is never validated against coverage rows (section 2): it
    is a restriction of an existing join, not a new one, so `validate_map` is
    called here exactly as every campaign consumer calls it -- with the
    release ids and without `coverage_by_item`.
    """
    from . import mutation_attestation as A

    sidecar = verify_budgeted_sample(sidecar_path, parent_map_path)
    parent = _read_json(parent_map_path, "mutant map")
    derived = _read_json(derived_map_path, "derived mutant map")
    if sidecar.get("manifest_digest") != manifest.get("digest"):
        raise _refuse(
            f"{os.path.basename(sidecar_path)} was drawn over manifest "
            f"{sidecar.get('manifest_digest')!r} and this campaign's manifest "
            f"digests to {manifest.get('digest')!r}; the budget was taken "
            f"over another population's mutants.")
    try:
        facts = A.validate_map(derived, manifest, release_ids=release_ids)
    except A.MutationAssetRefused as exc:
        raise _refuse(
            f"the derived map at {derived_map_path} does not validate: "
            f"{str(exc).removeprefix('REFUSED: ')}") from exc
    if sidecar.get("derived_map_digest") != derived.get("digest"):
        raise _refuse(
            f"{os.path.basename(sidecar_path)} declares derived map "
            f"{sidecar.get('derived_map_digest')} and {derived_map_path} is "
            f"{derived.get('digest')}; the sidecar describes a draw this map "
            f"is not.")

    def by_item(document: dict) -> dict:
        items: dict[str, set] = {}
        for mutant_id, mapped in document["by_mutant"].items():
            for iid in mapped:
                items.setdefault(iid, set()).add(mutant_id)
        return items

    declared = {iid: set(ids)
                for iid, ids in (sidecar.get("allocation") or {}).items()}
    drawn = by_item(derived)
    if drawn != declared:
        differing = sorted(set(drawn) ^ set(declared)) or sorted(
            iid for iid in drawn if drawn[iid] != declared[iid])
        raise _refuse(
            f"the derived map's membership is not the sidecar's allocation: "
            f"{len(differing)} item(s) differ (e.g. {differing[0]}). The "
            f"allocation is what says which mutants B drew for each item, so "
            f"a map that pairs others executes an undeclared population.")
    parent_items = by_item(parent)
    dropped = sorted(set(parent_items) - set(drawn))
    added = sorted(set(drawn) - set(parent_items))
    if dropped or added:
        raise _refuse(
            f"the derived map covers {len(drawn)} item(s) and its parent "
            f"{len(parent_items)}: {len(dropped)} dropped (e.g. "
            f"{dropped[0] if dropped else '-'}), {len(added)} added (e.g. "
            f"{added[0] if added else '-'}). A budget restricts each item's "
            f"mutants and never the item set -- every item the parent covers "
            f"draws at least one mutant -- so an item that appeared or "
            f"vanished is a different population, not a budget.")
    outside = {iid: sorted(ids - parent_items[iid])
               for iid, ids in drawn.items() if not ids <= parent_items[iid]}
    if outside:
        iid = sorted(outside)[0]
        raise _refuse(
            f"the derived map pairs item {iid} with {len(outside[iid])} "
            f"mutant(s) its parent does not (e.g. {outside[iid][0]}); a "
            f"budgeted population is a restriction of its parent's join, so "
            f"a pair the parent never had is evidence about no map.")
    return {"sidecar": sidecar, "parent_map": parent, "derived_map": derived,
            "derived_map_facts": facts}


# ------------------------------------------------- the publishing refusal

def subset_files(release_dir: str) -> list[str]:
    """Every published subset file, by the nominal rule (`eval*.jsonl`)."""
    found = []
    for root, _dirs, names in os.walk(release_dir):
        for name in sorted(names):
            if name.startswith(SUBSET_PREFIX) and name.endswith(".jsonl"):
                found.append(os.path.join(root, name))
    return sorted(found)


def sidecar_candidates(release_dir: str, subset_path: str) -> list[str]:
    """Sibling first, then `release/v1/<name>.provenance.json`.

    Two locations because they mean different things: a sidecar written
    beside a file was written WITH it, while one under `v1/` is a record
    added afterwards for a file that predates the sampler.
    """
    name = os.path.basename(subset_path)[:-len(".jsonl")]
    return [os.path.join(os.path.dirname(subset_path),
                         name + ".provenance.json"),
            os.path.join(release_dir, "v1", name + ".provenance.json")]


def pool_for(release_dir: str, subset_path: str) -> Optional[str]:
    """The pool file a subset is checked against, nearest first.

    The subset's own directory before the release root, so a per-project
    release is self-contained: `release/python-docx/evaldocx32.jsonl` is
    checked against `release/python-docx/items.jsonl`, not against CoreShop's
    422 items sitting one level up.
    """
    for directory in (os.path.dirname(os.path.abspath(subset_path)),
                      os.path.abspath(release_dir)):
        for name in POOL_NAMES:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def _authenticated_legacy_sidecar(subset_path: str, sidecar_path: str,
                                  doc: dict) -> None:
    """Accept historical /1 bytes only through the release's trust chain.

    `VERSIONS.yml` pins `dataset_manifest.json`; that manifest's inventory
    pins both the subset and its sidecar.  Merely copying a /1 schema token
    into an ad-hoc sidecar therefore cannot opt out of /2 replay validation.
    """
    from . import versions

    benchmark_root = BENCHMARK_ROOT
    release_root = os.path.join(benchmark_root, "release")
    manifest_path = os.path.join(release_root, "dataset_manifest.json")
    try:
        component = versions.component("dataset")
        manifest_pin = (component.get("files") or {}).get(
            "release/dataset_manifest.json")
        with open(manifest_path, "rb") as fh:
            raw = fh.read()
        manifest = json.loads(raw)
    except (OSError, ValueError, versions.ManifestError,
            json.JSONDecodeError) as exc:
        raise _refuse(
            f"legacy subset provenance cannot be authenticated through "
            f"VERSIONS.yml and dataset_manifest.json ({exc}).") from exc
    from .release import MANIFEST_SCHEMA
    actual_manifest = sha256_bytes(raw)
    if not isinstance(manifest_pin, str) or len(manifest_pin) != 64 \
            or actual_manifest != manifest_pin \
            or manifest.get("schema") != MANIFEST_SCHEMA \
            or manifest.get("dataset_version") != component.get("version"):
        raise _refuse(
            "legacy subset provenance is not backed by the exact "
            "VERSIONS-registered dataset manifest.")

    inventory = (manifest.get("release_inventory") or {}).get("files")
    if not isinstance(inventory, dict):
        raise _refuse(
            "the VERSIONS-registered dataset manifest has no release "
            "inventory with which to authenticate legacy subset bytes.")

    def released(path: str, label: str) -> tuple[str, str]:
        absolute = os.path.abspath(path)
        try:
            inside = os.path.commonpath([absolute, release_root]) \
                == os.path.abspath(release_root)
        except ValueError:
            inside = False
        if not inside or os.path.islink(path) or not os.path.isfile(path):
            raise _refuse(
                f"legacy {label} {path!r} is not a regular, non-symlink "
                f"artifact under the registered release root.")
        return os.path.relpath(absolute, release_root), sha256_file(path)

    subset_rel, subset_sha = released(subset_path, "subset")
    sidecar_rel, sidecar_sha = released(sidecar_path, "sidecar")
    if inventory.get(subset_rel) != subset_sha \
            or inventory.get(sidecar_rel) != sidecar_sha:
        raise _refuse(
            f"legacy subset provenance is not the exact authenticated "
            f"release pair: inventory has {subset_rel}="
            f"{inventory.get(subset_rel)!r}, {sidecar_rel}="
            f"{inventory.get(sidecar_rel)!r}.")
    if doc.get("content_sha256") != subset_sha:
        raise _refuse(
            "authenticated legacy sidecar and subset content digest "
            "disagree; the release trust chain is internally inconsistent.")


def _replay_current_sidecar(subset_path: str, sidecar_path: str,
                            doc: dict) -> dict:
    """Replay a /2 draw and return its trusted inference declarations."""
    if doc.get("schema") != SCHEMA:
        raise _refuse(f"subset provenance schema is {doc.get('schema')!r}, "
                      f"expected current {SCHEMA!r}.")
    n, seed = doc.get("n"), doc.get("seed")
    if not isinstance(n, int) or isinstance(n, bool) or n <= 0:
        raise _refuse(f"current subset provenance has invalid n={n!r}.")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise _refuse(f"current subset provenance has invalid seed={seed!r}.")
    if doc.get("algorithm_version") != ALGORITHM_VERSION:
        raise _refuse(
            f"current subset provenance names algorithm_version "
            f"{doc.get('algorithm_version')!r}; this reader implements "
            f"{ALGORITHM_VERSION}. A draw is not replayable under a different "
            f"selection arithmetic.")
    if doc.get("reconstructed") is not False:
        raise _refuse(
            "current subset provenance must be a forward, replayable draw "
            "with reconstructed: false.")
    mode = doc.get("allow_cluster_siblings")
    if not isinstance(mode, bool):
        raise _refuse(
            "current subset provenance must declare boolean "
            "allow_cluster_siblings; absence cannot default to the "
            "inference-safe mode.")
    source_name = doc.get("source_items")
    if not isinstance(source_name, str) or not source_name \
            or os.path.basename(source_name) != source_name:
        raise _refuse(
            f"current subset provenance has unsafe or missing source_items "
            f"{source_name!r}.")
    source_path = os.path.join(os.path.dirname(os.path.abspath(subset_path)),
                               source_name)
    cluster_source = os.path.dirname(os.path.abspath(subset_path))
    if not os.path.isfile(source_path):
        raise _refuse(
            f"current subset provenance names missing pinned pool "
            f"{source_path!r}.")
    if doc.get("source_items_sha256") != sha256_file(source_path):
        raise _refuse(
            "current subset provenance source_items_sha256 does not match "
            "the pool bytes beside the subset.")
    clusters = _closure_clusters(cluster_source)
    if doc.get("closure_map_sha256") != _closure_map_digest(clusters):
        raise _refuse(
            "current subset provenance closure_map_sha256 does not match "
            "the complete item-to-closure partition beside the subset.")
    expected = sample(
        source_path, cluster_source, n=n, seed=seed,
        strata_key=doc.get("strata_key"),
        allow_cluster_siblings=mode)
    if expected["provenance"] != doc:
        differing = sorted(set(expected["provenance"]) ^ set(doc))
        if not differing:
            differing = sorted(k for k in doc
                               if doc[k] != expected["provenance"].get(k))
        raise _refuse(
            "current subset provenance differs from the replayed sampler "
            f"result (fields: {', '.join(differing) or 'unknown'}). "
            "Inference mode and selection are derived, never trusted from "
            "the sidecar.")
    expected_bytes = "".join(expected["lines"]).encode("utf-8")
    with open(subset_path, "rb") as fh:
        actual_bytes = fh.read()
    if actual_bytes != expected_bytes:
        raise _refuse(
            "subset bytes are not the exact selection replayed from their "
            "pinned pool, closure map, seed, and sampling mode.")
    return {
        "inference_valid": doc["inference_valid"],
        "allow_cluster_siblings": mode,
    }


def _validated_sidecar_identity(subset_path: str, sidecar_path: str,
                                doc: dict) -> dict:
    """Validate one sidecar and return inference facts safe to consume."""
    from . import step_definition_census as census
    schema = doc.get("schema")
    if schema == census.SCHEMA:
        inference = census.replay(subset_path, doc)
    elif schema == HEADROOM_SCHEMA:
        replay_headroom(subset_path)
        inference = {"inference_valid": False, "allow_cluster_siblings": False,
                     "inference_reason": doc["inference_reason"]}
    elif schema == SCHEMA:
        inference = _replay_current_sidecar(subset_path, sidecar_path, doc)
    elif schema == LEGACY_SCHEMA:
        _authenticated_legacy_sidecar(subset_path, sidecar_path, doc)
        # The forward v1 sampler predated the sibling-permitted mode, so its
        # exact authenticated fresh output was one-per-cluster.  The
        # reconstructed eval100 record cannot support either declaration and
        # remains grandfathered-unknown; its 77 actual clusters still govern
        # the independent inference floor.
        if doc.get("reconstructed") is False \
                and doc.get("algorithm_version") == ALGORITHM_VERSION:
            inference = {"inference_valid": True,
                         "allow_cluster_siblings": False}
        else:
            inference = {"inference_valid": None,
                         "allow_cluster_siblings": None}
    else:
        raise _refuse(
            f"subset provenance schema is {schema!r}; only replayable "
            f"{SCHEMA!r} or exact VERSIONS-authenticated legacy "
            f"{LEGACY_SCHEMA!r} bytes are accepted.")
    actual = sha256_file(subset_path)
    if doc.get("content_sha256") != actual:
        raise _refuse(
            f"subset sidecar content_sha256 {doc.get('content_sha256')!r} "
            f"does not match {subset_path!r} ({actual}).")
    return {
        "subset_id": os.path.basename(subset_path)[:-len(".jsonl")],
        "subset_digest": actual[:16],
        "sidecar": sidecar_path,
        **inference,
    }


def _annotated_subset_sources(release_dir: str, *,
                              items_path: Optional[str] = None) \
        -> dict[str, str]:
    """Exact declared companion paths, each mapped to its frozen subset.

    Discovery reads the generated manifest's exact path declarations.  The
    shared release validator checks the complete declared companion set,
    including its pool; a matching basename alone grants no relationship.
    """
    from .release import (MANIFEST_NAME, ManifestRefused,
                          validate_annotated_release)

    manifest_path = os.path.join(release_dir, MANIFEST_NAME)
    if not os.path.isfile(manifest_path):
        return {}
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        projects = manifest.get("projects")
        if not isinstance(projects, dict):
            raise _refuse(f"{manifest_path} has no project declarations.")
        wanted = (os.path.relpath(os.path.abspath(items_path),
                                  os.path.abspath(release_dir))
                  if items_path is not None else None)
        sources = {}
        for block in projects.values():
            annotated = block.get("annotated_release")
            if annotated is None:
                continue
            if wanted is not None:
                declared = (annotated.get("subsets")
                            if isinstance(annotated, dict) else None)
                if not isinstance(declared, dict) \
                        or wanted not in declared.values():
                    continue
            pairs = validate_annotated_release(release_dir, block)
            inventory = (manifest.get("release_inventory") or {}).get("files")
            if not isinstance(inventory, dict):
                raise _refuse(
                    "annotated subsets require the manifest's release "
                    "inventory to bind their declared bytes.")
            for relative in sorted(set(pairs) | set(pairs.values())):
                actual = sha256_file(os.path.join(release_dir, relative))
                if inventory.get(relative) != actual:
                    raise _refuse(
                        f"annotated release file {relative!r} disagrees "
                        "with its dataset manifest release inventory.")
            for relative in annotated["subsets"].values():
                sources[os.path.abspath(os.path.join(release_dir, relative))] = \
                    os.path.abspath(os.path.join(release_dir, pairs[relative]))
        return sources
    except (OSError, ValueError, AttributeError, ManifestRefused) as exc:
        raise _refuse(
            f"annotated subset declaration in {manifest_path!r} is invalid "
            f"({exc}).") from exc


def verify_release_subsets(release_dir: str) -> list[str]:
    """Problems, one string each; empty means every subset is accounted for.

    A sidecar has to MATCH: we recompute the content digest and the id-list
    digest from the file on disk and compare. A sidecar that describes an
    older version of the subset is the failure this check exists for — it
    is the one that reads like provenance while being fiction.

    Matching digests are not enough on their own, because they only say the
    sidecar and the file agree with each other.  Every id must also EXIST in
    `items_v1.jsonl`: a subset of invented or stale ids digests perfectly
    and still cites items the release does not ship, which is the same
    fiction one level down.
    """
    problems: list[str] = []
    subsets = subset_files(release_dir)
    pools: dict[str, Optional[set[str]]] = {}
    try:
        annotated_sources = _annotated_subset_sources(release_dir)
    except SubsetRefused as exc:
        problems.append(str(exc))
        annotated_sources = {}

    def ids_of_pool(subset_path: str) -> tuple:
        """`(pool path, ids)` for ONE subset; each pool file is read once."""
        pool_path = pool_for(release_dir, subset_path)
        if pool_path is None:
            problems.append(
                f"{os.path.relpath(subset_path, release_dir)}: no pool file "
                f"({' or '.join(POOL_NAMES)}) beside it or in the release "
                f"root, so it cannot be checked against the pool it claims "
                f"to be drawn from.")
            return None, None
        if pool_path not in pools:
            try:
                pools[pool_path] = {iid for iid, _ in read_items(pool_path)}
            except SubsetRefused as exc:
                problems.append(
                    f"{os.path.relpath(pool_path, release_dir)}: {exc}")
                pools[pool_path] = None
        return pool_path, pools[pool_path]

    for path in subsets:
        rel = os.path.relpath(path, release_dir)
        # Validate the frozen sidecar on the bytes it actually pins.  The
        # declaration above already established the annotated row relation;
        # no new sampler sidecar is invented for that representation.
        path = annotated_sources.get(os.path.abspath(path), path)
        pool_path, pool_ids = ids_of_pool(path)
        candidates = sidecar_candidates(release_dir, path)
        found = [c for c in candidates if os.path.isfile(c)]
        if not found:
            problems.append(
                f"{rel}: no provenance sidecar (looked for "
                + ", ".join(os.path.relpath(c, release_dir)
                            for c in candidates)
                + "). A published subset with no record of how it was drawn "
                  "cannot be cited.")
            continue
        sidecar = found[0]
        srel = os.path.relpath(sidecar, release_dir)
        try:
            with open(sidecar, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"{srel}: unreadable ({exc}).")
            continue
        try:
            _validated_sidecar_identity(path, sidecar, doc)
        except SubsetRefused as exc:
            problems.append(f"{srel}: {exc}")
        actual_content = sha256_file(path)
        if doc.get("content_sha256") != actual_content:
            problems.append(
                f"{srel}: content_sha256 {doc.get('content_sha256')} does not "
                f"match {rel} ({actual_content}). The sidecar describes a "
                f"file that is no longer there.")
        try:
            ids = [iid for iid, _ in read_items(path)]
        except SubsetRefused as exc:
            problems.append(f"{rel}: {exc}")
            continue
        actual_ids = id_list_digest(ids)
        if doc.get("item_id_list_digest") != actual_ids:
            problems.append(
                f"{srel}: item_id_list_digest "
                f"{doc.get('item_id_list_digest')} does not match the "
                f"{len(ids)} ids in {rel} ({actual_ids}).")
        if doc.get("n") != len(ids):
            problems.append(f"{srel}: says n={doc.get('n')}, file has "
                            f"{len(ids)} items.")
        if pool_ids is not None:
            strangers = [iid for iid in ids if iid not in pool_ids]
            if strangers:
                problems.append(
                    f"{rel}: {len(strangers)} of its {len(ids)} ids are not "
                    f"in {os.path.relpath(pool_path, release_dir)} (first: "
                    f"{strangers[0]}). A fresh sidecar does not make an "
                    f"invented or stale id part of the release.")
    return problems


def require_release_subsets(release_dir: str) -> None:
    problems = verify_release_subsets(release_dir)
    if problems:
        raise _refuse("published subsets are missing or misdescribed by "
                      "their provenance sidecars:\n  - "
                      + "\n  - ".join(problems))


# ------------------------------------------------- WHICH subset a run ran on

def _identify(items_path: str, *, strict_inference: bool) -> Optional[dict]:
    """Implementation shared by best-effort stamping and inferential reads."""
    if not os.path.isfile(items_path):
        return None
    name = os.path.basename(items_path)
    if not name.endswith(".jsonl"):
        return None
    from . import sylius_selection as Y
    if Y.is_selection(items_path):
        try:
            return Y.identify(items_path)
        except Y.SelectionRefused as exc:
            raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    from ..ruby import evaluation_selection as R
    if R.is_selection(items_path):
        try:
            return R.identify(items_path)
        except R.SelectionRefused as exc:
            raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    if name == "kapua-pilot.jsonl" or os.path.lexists(str(items_path) + ".pilot.json"):
        from ..java import kapua_pilot as K
        return K.identify(items_path)
    from ..java import kapua_census as KC
    if KC.is_selection(items_path):
        try:
            return KC.identify(items_path)
        except KC.SelectionRefused as exc:
            raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    here = os.path.dirname(os.path.abspath(items_path))
    candidates: list[str] = []
    for release_dir in (here, os.path.dirname(here)):
        try:
            source = _annotated_subset_sources(
                release_dir, items_path=items_path).get(
                    os.path.abspath(items_path))
            if source is not None:
                original = _identify(source, strict_inference=True)
                if original is None:
                    raise _refuse(
                        f"annotated subset {items_path!r} has no validated "
                        f"source selection at {source!r}.")
                return {
                    "subset_id": original["subset_id"],
                    "subset_digest": sha256_file(items_path)[:16],
                    "sidecar": None,
                    "inference_valid": original["inference_valid"],
                    "allow_cluster_siblings": original[
                        "allow_cluster_siblings"],
                    **{key: original[key] for key in ("selection_unit", "inference_unit")
                       if key in original},
                    "source_selection": {
                        "file": source,
                        "subset_id": original["subset_id"],
                        "subset_digest": original["subset_digest"],
                        "sidecar": original["sidecar"],
                    },
                }
        except SubsetRefused:
            if strict_inference:
                raise
            return None
        for cand in sidecar_candidates(release_dir, items_path):
            if cand not in candidates:
                candidates.append(cand)
    found = [cand for cand in candidates if os.path.isfile(cand)]
    if not found:
        if strict_inference and name.startswith(SUBSET_PREFIX):
            raise _refuse(
                f"{items_path} has a published-subset name but no provenance "
                "sidecar. An inferential reader cannot default an unrecorded "
                "selection to inference-safe.")
        return None
    sidecar = found[0]
    try:
        with open(sidecar, encoding="utf-8") as fh:
            doc = json.load(fh)
        return _validated_sidecar_identity(items_path, sidecar, doc)
    except (OSError, ValueError, SubsetRefused) as exc:
        if strict_inference:
            if isinstance(exc, SubsetRefused):
                raise
            raise _refuse(
                f"subset provenance {sidecar!r} is unreadable ({exc}).") \
                from exc
        return None


def identify(items_path: str) -> Optional[dict]:
    """Best-effort subset identity for a run stamp, or None.

    WHY None RATHER THAN A BEST GUESS.  Every run has an items file, but only
    a file with a provenance sidecar has an IDENTITY -- a record of how those
    items were chosen that a reader can check.  A run over an ad-hoc slice, or
    over the full pool, or over a subset whose sidecar has drifted out of
    agreement with its bytes, has no subset identity to stamp, and stamping
    the basename anyway would put a citable-looking label
    (`req2test D1.0(eval100)`) on rows that were measured over something else.
    The citation prints `?` instead, which is the honest reading of "nobody
    recorded this".

    The digest is recomputed from the FILE, never copied out of the sidecar.
    A declared annotated companion has its own digest and carries the
    validated original identity under `source_selection`; its top-level
    `sidecar` is None because no sampler sidecar pins annotated bytes.
    For ordinary subsets the sidecar's `content_sha256` must agree. A sidecar
    that describes an older version of the subset is the failure `verify_release_
    subsets` exists for, and this function must not launder it into an
    identity: two runs quoting `eval100` over different bytes is exactly the
    confusion the digest is here to prevent.

    Truncated to 16 hex for the same reason `campaign_digest` is -- it is
    quoted in a one-line citation beside three other digests.

    Generation remains possible when a sidecar is unreadable: the row is left
    unlabelled rather than stamped with a guessed identity.  Inferential
    consumers must call `identify_for_inference`, whose failure is terminal.
    """
    return _identify(items_path, strict_inference=False)


def identify_for_inference(items_path: str) -> Optional[dict]:
    """Validated subset identity for intervals/tests, or a loud refusal.

    A full pool or intentionally ad-hoc file (a name other than `eval*`) may
    have no subset sidecar and returns None; its actual closure count still
    governs inference.  A named released subset with missing, edited, or
    declaration-only provenance refuses instead of silently becoming ad hoc.
    """
    return _identify(items_path, strict_inference=True)


# ------------------------------------------------------------------ selftest

def _fixture(root: str, spec: list[tuple[str, str]]) -> tuple[str, str]:
    """Build a tiny pool: spec is [(item_id, cluster-label)]."""
    items_path = os.path.join(root, "items.jsonl")
    gold_dir = os.path.join(root, "gold")
    os.makedirs(gold_dir, exist_ok=True)
    manifest = {}
    with open(items_path, "w", encoding="utf-8") as fh:
        for index, (iid, label) in enumerate(spec):
            fh.write(json.dumps({"item_id": iid, "task": "t"},
                                sort_keys=True) + "\n")
            name = f"g{index:03d}.json"
            manifest[iid] = name
            with open(os.path.join(gold_dir, name), "w",
                      encoding="utf-8") as gh:
                json.dump({"item_id": iid,
                           "files": [f"src/{label}/A.php",
                                     f"src/{label}/B.php"]}, gh)
    with open(os.path.join(gold_dir, "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, sort_keys=True)
    return items_path, gold_dir


def selftest() -> int:
    import collections
    import shutil
    import tempfile

    # The writers are the builder's (wave M5); a data module's self-test may
    # reach the toolkit, its code may not.
    from ..toolkit.subset_writer import (write_budgeted_sample,
                                         write_provenance,
                                         write_subset)

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refused(fn) -> Optional[str]:
        try:
            fn()
            return None
        except SubsetRefused as exc:
            return str(exc)

    check("the family is the directory holding the .feature file",
          feature_family("coreshop/features/domain/cart/create_cart"
                         ".feature:27") == "cart")
    check("...and a nested rule directory is its own family",
          feature_family("coreshop/features/domain/cart/rules/cart_item/"
                         "amount_condition.feature:34") == "cart_item")
    msg = refused(lambda: feature_family("coreshop/features/cart"))
    check("an id that is not path.feature:<line> is refused, not guessed",
          msg is not None and msg.startswith("REFUSED:"), str(msg))

    check("floor 1 reaches every family before proportionality does",
          _allocate({"a": 10, "b": 1, "c": 1}, 4) == {"a": 2, "b": 1, "c": 1},
          str(_allocate({"a": 10, "b": 1, "c": 1}, 4)))
    check("...and a family is never allocated more items than it has",
          _allocate({"a": 10, "b": 1, "c": 1}, 12)
          == {"a": 10, "b": 1, "c": 1})
    # The allocation is PROPORTIONAL, not "one more each until we run out".
    # A round-robin over families with capacity left passes an equal-sized
    # fixture and converges to uniform on an unequal one, so both shapes are
    # pinned here: a 9:1 pool must draw 9:1, not 5:5.
    check("a lopsided pool is allocated by quota, not levelled out",
          _allocate({"a": 90, "b": 10}, 10) == {"a": 9, "b": 1},
          str(_allocate({"a": 90, "b": 10}, 10)))
    check("...and with n well above the family count it stays proportional",
          _allocate({"a": 80, "b": 10, "c": 10}, 20)
          == {"a": 16, "b": 2, "c": 2},
          str(_allocate({"a": 80, "b": 10, "c": 10}, 20)))
    check("...the spare seat goes to the largest remainder, ties by name",
          _allocate({"a": 5, "b": 3, "c": 2}, 6) == {"a": 3, "b": 2, "c": 1},
          str(_allocate({"a": 5, "b": 3, "c": 2}, 6)))
    check("every family is seated and the seats sum to n, always",
          all(sum(_allocate({"a": 47, "b": 11, "c": 5, "d": 1}, k).values())
              == k
              and min(_allocate({"a": 47, "b": 11, "c": 5, "d": 1},
                                k).values()) >= 1
              for k in range(4, 65)))
    msg = refused(lambda: _allocate({"a": 5, "b": 5, "c": 5}, 2))
    check("n below the family count is refused rather than dropping families",
          msg is not None and msg.startswith("REFUSED:"), str(msg))

    tmp = tempfile.mkdtemp(prefix="r2t_subsets_")
    try:
        # Six clusters, two families; cluster "dup" holds three items whose
        # closure is identical, so at most one of them may be drawn.
        spec = [("p/f/cart/a.feature:1", "dup"),
                ("p/f/cart/b.feature:1", "dup"),
                ("p/f/cart/c.feature:1", "dup"),
                ("p/f/cart/d.feature:1", "d"),
                ("p/f/cart/e.feature:1", "e"),
                ("p/f/rules/f.feature:1", "f"),
                ("p/f/rules/g.feature:1", "g"),
                ("p/f/rules/h.feature:1", "h")]
        items_path, gold_dir = _fixture(tmp, spec)

        drawn = sample(items_path, gold_dir, n=4, seed=7)
        ids = drawn["item_ids"]
        check("the draw returns exactly n items", len(ids) == 4, str(ids))
        check("at most one item per closure cluster",
              len([i for i in ids if i in ("p/f/cart/a.feature:1",
                                           "p/f/cart/b.feature:1",
                                           "p/f/cart/c.feature:1")]) <= 1,
              str(ids))
        check("...and the representative is the lexicographically first id",
              "p/f/cart/b.feature:1" not in ids
              and "p/f/cart/c.feature:1" not in ids, str(ids))
        check("every family keeps at least one seat",
              {feature_family(i) for i in ids} == {"cart", "rules"}, str(ids))
        check("output is sorted by item_id", ids == sorted(ids), str(ids))
        check("the sidecar counts the clusters it drew from",
              drawn["provenance"]["clusters"] == {"total": 6, "represented": 4},
              json.dumps(drawn["provenance"]["clusters"]))
        check("a fresh draw records reconstructed: false, and its version",
              drawn["provenance"]["reconstructed"] is False
              and drawn["provenance"]["algorithm_version"]
              == ALGORITHM_VERSION
              and drawn["provenance"]["allow_cluster_siblings"] is False
              and drawn["provenance"]["inference_valid"] is True)
        check("a draw that leaves clusters unseated is NOT a census",
              drawn["provenance"]["census"] is False,
              json.dumps(drawn["provenance"]["clusters"]))
        whole = sample(items_path, gold_dir, n=6, seed=7)
        check("...and one that seats every cluster says so, so `seed` is "
              "never read as evidence of a choice nobody made",
              whole["provenance"]["census"] is True
              and whole["provenance"]["clusters"]
              == {"total": 6, "represented": 6},
              json.dumps(whole["provenance"]["clusters"]))

        descriptive = sample(items_path, gold_dir, n=len(spec), seed=7,
                             allow_cluster_siblings=True)
        check("descriptive mode can seat closure siblings instead of lying "
              "that the cluster representatives are the whole pool",
              len(descriptive["item_ids"]) == len(spec)
              and descriptive["provenance"]["clusters"]
              == {"total": 6, "represented": 6})
        check("...and its sidecar makes inference mechanically unavailable",
              descriptive["provenance"]["allow_cluster_siblings"] is True
              and descriptive["provenance"]["inference_valid"] is False
              and "descriptive" in
              descriptive["provenance"]["inference_reason"],
              json.dumps(descriptive["provenance"], sort_keys=True))
        msg = refused(lambda: sample(items_path, gold_dir, n=len(spec), seed=7))
        check("the default remains inference-safe and refuses an n that would "
              "require cluster siblings",
              msg is not None and "cluster representatives" in msg, str(msg))

        again = sample(items_path, gold_dir, n=4, seed=7)
        check("the same seed draws the same items",
              again["item_ids"] == ids)
        out_a = write_subset(drawn, os.path.join(tmp, "out_a"))
        out_b = write_subset(again, os.path.join(tmp, "out_b"))
        same = [sha256_file(a) == sha256_file(b)
                for a, b in zip(out_a, out_b)]
        check("...byte-identical, subset and sidecar alike (no timestamps)",
              all(same), str(same))
        check("the written subset is a literal subset of the pool's lines",
              set(open(out_a[0], encoding="utf-8").read().splitlines())
              <= set(open(items_path, encoding="utf-8").read().splitlines()))
        with open(out_a[1], encoding="utf-8") as fh:
            doc = json.load(fh)
        check("the written sidecar's digests describe the written subset",
              doc["content_sha256"] == sha256_file(out_a[0])
              and doc["item_id_list_digest"] == id_list_digest(ids))

        msg = refused(lambda: sample(items_path,
                                     os.path.join(tmp, "no_such_gold"),
                                     n=4, seed=7))
        check("a missing gold directory is refused",
              msg is not None and msg.startswith("REFUSED:"), str(msg))

        orphan = os.path.join(tmp, "orphan")
        os.makedirs(orphan, exist_ok=True)
        orphan_items, orphan_gold = _fixture(orphan, spec)
        man_path = os.path.join(orphan_gold, "manifest.json")
        with open(man_path, encoding="utf-8") as fh:
            man = json.load(fh)
        man.pop("p/f/rules/h.feature:1")
        with open(man_path, "w", encoding="utf-8") as fh:
            json.dump(man, fh, sort_keys=True)
        msg = refused(lambda: sample(orphan_items, orphan_gold, n=4, seed=7))
        check("an item with no gold sidecar is refused, not skipped",
              msg is not None and "no gold sidecar" in msg, str(msg))

        # END TO END on an UNEQUAL pool.  The fixture above has two families
        # of equal size, where a levelling allocation and a proportional one
        # agree; this one is 16:2:2, where they do not.  At n=10 the quotas
        # are 8, 1, 1 exactly, so the strata the sidecar publishes are a
        # direct read of the allocation.
        skew = os.path.join(tmp, "skew")
        os.makedirs(skew, exist_ok=True)
        skew_spec = ([(f"p/f/cart/c{i:02d}.feature:1", f"c{i:02d}")
                      for i in range(16)]
                     + [(f"p/f/rules/r{i:02d}.feature:1", f"r{i:02d}")
                        for i in range(2)]
                     + [(f"p/f/seo/s{i:02d}.feature:1", f"s{i:02d}")
                        for i in range(2)])
        skew_items, skew_gold = _fixture(skew, skew_spec)
        skewed = sample(skew_items, skew_gold, n=10, seed=3)
        check("a 16:2:2 pool draws 8:1:1 -- the strata track the quotas",
              skewed["provenance"]["strata"]
              == {"cart": 8, "rules": 1, "seo": 1},
              json.dumps(skewed["provenance"]["strata"]))
        check("...and the drawn ids agree with the published strata",
              sorted(feature_family(i) for i in skewed["item_ids"])
              == ["cart"] * 8 + ["rules"] + ["seo"],
              str(skewed["item_ids"]))

        # The publishing refusal, on a fake release tree.
        fake = os.path.join(tmp, "release")
        os.makedirs(fake, exist_ok=True)
        shutil.copyfile(items_path, os.path.join(fake, "items.jsonl"))
        shutil.copytree(gold_dir, os.path.join(fake, "gold"))
        subset_path = os.path.join(fake, "eval4.jsonl")
        write_subset(drawn, subset_path)
        check("a subset published with a matching sidecar passes",
              verify_release_subsets(fake) == [],
              str(verify_release_subsets(fake)))
        desc_path = os.path.join(fake, "eval_descriptive.jsonl")
        write_subset(descriptive, desc_path)
        check("a published descriptive subset passes only with its explicit "
              "inference-invalid declaration",
              verify_release_subsets(fake) == [],
              str(verify_release_subsets(fake)))
        desc_sidecar = os.path.join(fake, "eval_descriptive.provenance.json")
        with open(desc_sidecar, encoding="utf-8") as fh:
            desc_doc = json.load(fh)
        desc_doc["inference_valid"] = True
        write_provenance(desc_sidecar, desc_doc)
        check("flipping the descriptive sidecar to inference-valid reddens "
              "the publication gate",
              any("replayed sampler" in p
                  for p in verify_release_subsets(fake)))
        msg = refused(lambda: identify_for_inference(desc_path))
        check("...and an inferential reader refuses the edited declaration",
              msg is not None and "replayed sampler" in msg, str(msg))
        desc_doc.pop("inference_valid")
        write_provenance(desc_sidecar, desc_doc)
        msg = refused(lambda: identify_for_inference(desc_path))
        check("deleting inference_valid cannot default a current sidecar to "
              "inference-safe",
              msg is not None and "replayed sampler" in msg, str(msg))
        desc_doc["inference_valid"] = False
        write_provenance(desc_sidecar, desc_doc)
        desc_identity = identify(desc_path)
        check("the descriptive inference refusal travels with subset identity",
              desc_identity is not None
              and desc_identity["inference_valid"] is False
              and desc_identity["allow_cluster_siblings"] is True,
              str(desc_identity))
        os.replace(os.path.join(fake, "eval4.provenance.json"),
                   os.path.join(tmp, "stashed.json"))
        check("...a subset with NO sidecar is a problem",
              any("no provenance sidecar" in p
                  for p in verify_release_subsets(fake)))
        os.makedirs(os.path.join(fake, "v1"), exist_ok=True)
        os.replace(os.path.join(tmp, "stashed.json"),
                   os.path.join(fake, "v1", "eval4.provenance.json"))
        check("...and release/v1/ is an accepted home for a post-hoc one",
              verify_release_subsets(fake) == [])
        with open(subset_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "p/f/cart/z.feature:9"}) + "\n")
        problems = verify_release_subsets(fake)
        check("a STALE sidecar is as bad as none",
              any("content_sha256" in p for p in problems)
              and any("item_id_list_digest" in p for p in problems),
              str(problems))
        msg = refused(lambda: require_release_subsets(fake))
        check("...and the gate refuses on it",
              msg is not None and msg.startswith("REFUSED:"), str(msg))

        # A subset of ids the release does not ship, with a sidecar that is
        # PERFECTLY fresh: every digest agrees, because the digests only
        # compare the file with its own description.  Membership in the pool
        # is the check that catches it.
        invented = os.path.join(tmp, "invented")
        os.makedirs(invented, exist_ok=True)
        shutil.copyfile(items_path, os.path.join(invented, "items.jsonl"))
        shutil.copytree(gold_dir, os.path.join(invented, "gold"))
        ghost = json.dumps({"item_id": "p/f/cart/ghost.feature:1",
                            "task": "t"}, sort_keys=True) + "\n"
        ghost_lines = drawn["lines"][:-1] + [ghost]
        ghost_ids = sorted(json.loads(line)["item_id"]
                           for line in ghost_lines)
        ghost_doc = dict(drawn["provenance"],
                         n=len(ghost_ids),
                         item_id_list_digest=id_list_digest(ghost_ids),
                         content_sha256=sha256_bytes(
                             "".join(ghost_lines).encode("utf-8")))
        write_subset({"item_ids": ghost_ids, "lines": ghost_lines,
                      "provenance": ghost_doc},
                     os.path.join(invented, "eval4.jsonl"))
        problems = verify_release_subsets(invented)
        check("an id the pool never had is caught though the sidecar is fresh",
              any("not in items.jsonl" in p for p in problems),
              str(problems))
        check("...and sampler replay independently catches the post-hoc "
              "selection even though its output digests were recomputed",
              any("replayed sampler" in p for p in problems), str(problems))
        os.remove(os.path.join(invented, "items.jsonl"))
        check("with no pool file the subsets cannot be checked, and it says so",
              any("no pool file" in p
                  for p in verify_release_subsets(invented)),
              str(verify_release_subsets(invented)))

        # ---- TWO projects in one release.  The second project's subset sits
        # in its own directory beside its own pool, and its ids are in
        # neither `items_v1.jsonl` nor any other project's pool -- which is
        # not a fault, it is what a second project IS.  The pool is therefore
        # resolved nearest-first, and the membership check still bites.
        two = os.path.join(tmp, "two_projects")
        os.makedirs(two, exist_ok=True)
        shutil.copyfile(items_path, os.path.join(two, "items.jsonl"))
        shutil.copytree(gold_dir, os.path.join(two, "gold"))
        write_subset(drawn, os.path.join(two, "eval4.jsonl"))
        proj = os.path.join(two, "python-docx")
        os.makedirs(proj, exist_ok=True)
        proj_spec = [(f"docx/features/f{i:02d}.feature:{i}", f"c{i:02d}")
                     for i in range(6)]
        proj_items, proj_gold = _fixture(proj, proj_spec)
        os.replace(proj_items, os.path.join(proj, "items.jsonl"))
        proj_drawn = sample(os.path.join(proj, "items.jsonl"), proj_gold,
                            n=4, seed=11)
        write_subset(proj_drawn, os.path.join(proj, "evaldocx4.jsonl"))
        check("a per-project subset is checked against its OWN pool, not the "
              "release root's",
              verify_release_subsets(two) == [], str(verify_release_subsets(two)))
        check("...and `pool_for` says which pool that was",
              pool_for(two, os.path.join(proj, "evaldocx4.jsonl"))
              == os.path.join(proj, "items.jsonl")
              and pool_for(two, os.path.join(two, "eval4.jsonl"))
              == os.path.join(two, "items.jsonl"))
        with open(os.path.join(proj, "evaldocx4.jsonl"), "a",
                  encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "docx/features/ghost.feature:1"})
                     + "\n")
        problems = verify_release_subsets(two)
        check("...and an id that project's pool never had is still caught",
              any("items.jsonl" in p and "not in" in p for p in problems),
              str(problems))

        # Annotated companions retain the original selection evidence and
        # get an identity for their own bytes, even with the same basename.
        from . import release as release_data, versions
        from ..bench import population
        from unittest.mock import patch
        import sys

        layout = os.path.join(tmp, "annotated", "release")
        os.makedirs(layout)
        layout_pool, layout_gold = _fixture(layout, spec)
        layout_draw = sample(layout_pool, layout_gold, n=4, seed=7)
        layout_desc = sample(layout_pool, layout_gold, n=len(spec), seed=7,
                             allow_cluster_siblings=True)
        original_path = os.path.join(layout, "eval4.jsonl")
        write_subset(layout_draw, original_path)
        write_subset(layout_desc, os.path.join(layout, "eval_descriptive.jsonl"))
        os.makedirs(os.path.join(layout, "coreshop"))
        annotated_bytes = {}
        for name in ("items.jsonl", "eval4.jsonl", "eval_descriptive.jsonl"):
            annotated_path = os.path.join(layout, "coreshop", name)
            with open(annotated_path, "w", encoding="utf-8") as fh:
                for _iid, line in read_items(os.path.join(layout, name)):
                    row = json.loads(line)
                    row["target_interfaces"] = {"behaviour": [], "setup": []}
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
            with open(annotated_path, "rb") as fh:
                annotated_bytes[annotated_path] = fh.read()
        companion = os.path.join(layout, "coreshop", "eval4.jsonl")
        declaration = {
            "items": "coreshop/items.jsonl",
            "subsets": {name: f"coreshop/{name}.jsonl"
                        for name in ("eval4", "eval_descriptive")},
        }
        layout_block = {
            "items": "items.jsonl",
            "subsets": {name: {"file": f"{name}.jsonl"}
                        for name in ("eval4", "eval_descriptive")},
            "annotated_release": declaration,
        }
        manifest_path = os.path.join(layout, "dataset_manifest.json")
        layout_manifest = {
            "schema": release_data.MANIFEST_SCHEMA,
            "dataset_version": "fixture",
            "projects": {"coreshop": layout_block},
        }

        def save_layout_manifest():
            layout_manifest["release_inventory"] = \
                release_data.release_inventory(layout)
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump(layout_manifest, fh, sort_keys=True)

        def restore_annotations():
            for path, raw in annotated_bytes.items():
                with open(path, "wb") as fh:
                    fh.write(raw)

        save_layout_manifest()
        check("declared original and annotated subsets both pass publication",
              verify_release_subsets(layout) == [],
              str(verify_release_subsets(layout)))
        original = identify_for_inference(original_path)
        annotated = identify_for_inference(companion)
        check("annotated identity names its own bytes and the original selection",
              annotated is not None and original is not None
              and annotated["subset_id"] == original["subset_id"] == "eval4"
              and annotated["subset_digest"] == sha256_file(companion)[:16]
              and annotated["subset_digest"] != original["subset_digest"]
              and annotated["sidecar"] is None
              and annotated["inference_valid"] is True
              and annotated["allow_cluster_siblings"] is False
              and annotated["source_selection"] == {
                  "file": original_path, "subset_id": original["subset_id"],
                  "subset_digest": original["subset_digest"],
                  "sidecar": original["sidecar"]}, str(annotated))
        check("population resolves frozen and annotated equal basenames distinctly",
              population._resolve_subset(original, [layout])[0] == original_path
              and population._resolve_subset(annotated, [layout])[0] == companion)
        annotated_desc = identify_for_inference(os.path.join(
            layout, "coreshop", "eval_descriptive.jsonl"))
        check("annotation preserves the original descriptive inference refusal",
              annotated_desc["inference_valid"] is False
              and annotated_desc["allow_cluster_siblings"] is True)

        layout_block.pop("annotated_release")
        save_layout_manifest()
        msg = refused(lambda: identify_for_inference(companion))
        check("an undeclared same-basename companion has no subset identity",
              msg is not None and "no provenance sidecar" in msg
              and identify(companion) is None
              and bool(verify_release_subsets(layout)), str(msg))
        layout_block["annotated_release"] = declaration
        save_layout_manifest()

        for label, changed in (
                ("task content", lambda rows: rows[0].update(task="different")),
                ("row order", lambda rows: rows.reverse()),
                ("malformed annotation", lambda rows: rows[0].update(
                    target_interfaces={"behaviour": "bad", "setup": []}))):
            rows = [json.loads(line) for line in
                    annotated_bytes[companion].decode("utf-8").splitlines()]
            changed(rows)
            with open(companion, "w", encoding="utf-8") as fh:
                fh.write("".join(json.dumps(row) + "\n" for row in rows))
            save_layout_manifest()
            msg = refused(lambda: identify_for_inference(companion))
            check(f"annotated {label} drift refuses even with refreshed inventory",
                  msg is not None and identify(companion) is None
                  and bool(verify_release_subsets(layout)), str(msg))
            restore_annotations()
        save_layout_manifest()

        # Keep the annotation relationship valid while making the saved
        # inventory stale, so this specifically exercises its existing pin.
        for path in annotated_bytes:
            rows = [json.loads(line) for line in
                    annotated_bytes[path].decode("utf-8").splitlines()]
            for row in rows:
                row["target_interfaces"]["behaviour"] = ["Example\\Type"]
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("".join(json.dumps(row) + "\n" for row in rows))
        msg = refused(lambda: identify_for_inference(companion))
        check("valid annotations edited after manifest generation refuse",
              msg is not None and "release inventory" in msg, str(msg))
        restore_annotations()

        annotated_pool = os.path.join(layout, "coreshop", "items.jsonl")
        pool_rows = [json.loads(line) for line in
                     annotated_bytes[annotated_pool].decode("utf-8").splitlines()]
        unselected = next(row for row in pool_rows
                          if row["item_id"] not in layout_draw["item_ids"])
        unselected["task"] = "changed outside the subset"
        with open(annotated_pool, "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(row) + "\n" for row in pool_rows))
        save_layout_manifest()
        check("subset identity validates its declared full-pool companion too",
              refused(lambda: identify_for_inference(companion)) is not None)
        restore_annotations()

        original_sidecar = os.path.join(layout, "eval4.provenance.json")
        invalid_source = dict(layout_draw["provenance"], inference_valid=False)
        write_provenance(original_sidecar, invalid_source)
        save_layout_manifest()
        msg = refused(lambda: identify_for_inference(companion))
        check("annotated identity refuses an invalid original sampler sidecar",
              msg is not None and "replayed sampler" in msg, str(msg))

        legacy_source = dict(layout_draw["provenance"],
                             schema=LEGACY_SCHEMA, reconstructed=True)
        write_provenance(original_sidecar, legacy_source)
        save_layout_manifest()
        component = {"version": "fixture", "files": {
            "release/dataset_manifest.json": sha256_file(manifest_path)}}
        with patch.object(sys.modules[__name__], "BENCHMARK_ROOT",
                          os.path.dirname(layout)), \
                patch.object(versions, "component", return_value=component):
            unknown = identify_for_inference(companion)
            check("annotation cannot upgrade authenticated legacy-unknown inference",
                  unknown["inference_valid"] is None
                  and unknown["allow_cluster_siblings"] is None
                  and unknown["subset_digest"] == sha256_file(companion)[:16]
                  and verify_release_subsets(layout) == [])

        # ---- `identify`: what a RUN stamps about the items it ran over.
        #
        # `fake/` above ends with a subset whose sidecar is STALE (a line was
        # appended after it was written) and `invented/` with one whose
        # sidecar is fresh -- which is exactly the pair this needs.
        fresh = out_a[0]
        ident = identify(fresh)
        check("a subset with a matching sidecar has an identity to stamp",
              ident and ident["subset_id"] == "out_a"
              and ident["subset_digest"] == sha256_file(fresh)[:16]
              and ident["inference_valid"] is True
              and ident["allow_cluster_siblings"] is False,
              str(ident))
        check("the digest is recomputed from the FILE, not copied out of the "
              "sidecar",
              ident and len(ident["subset_digest"]) == 16
              and sha256_file(fresh).startswith(ident["subset_digest"]))
        check("a subset whose sidecar has drifted has NO identity -- an "
              "unlabelled row beats a citable-looking wrong label",
              identify(os.path.join(fake, "eval4.jsonl")) is None,
              str(identify(os.path.join(fake, "eval4.jsonl"))))
        check("the full pool is not a subset and is not labelled as one",
              identify(os.path.join(invented, "eval4.jsonl.nope")) is None
              and identify(items_path) is None)
        check("a missing file is None rather than an exception on a run path",
              identify(os.path.join(tmp, "gone.jsonl")) is None)


        # ---- headroom mode: an item-level FILTER over an ADAPTIVE census.
        #
        # Eleven items over six runs.  Sample 1 covers the whole census; a
        # later sample runs only on what that agent had still solved, so an
        # item is judged on the samples it was actually run in.  Five items
        # are solved everywhere they ran, five fail the condition somewhere
        # (once per way of failing it), and one is solved in both sample-1
        # runs and never re-run -- which is neither headroom nor control, and
        # is the case a criterion written over "all six runs" would get wrong.
        hr = os.path.join(tmp, "headroom")
        os.makedirs(hr, exist_ok=True)
        hr_ids = [f"proj/features/cart/i{i:02d}.feature:{10 + i}"
                  for i in range(11)]
        hr_items = os.path.join(hr, "level1.jsonl")
        with open(hr_items, "w", encoding="utf-8") as fh:
            for iid in hr_ids:
                fh.write(json.dumps({"item_id": iid, "task": "t"},
                                    sort_keys=True) + "\n")
        boundary_path = os.path.join(hr, "boundary_fixture_proj.yml")
        with open(boundary_path, "w", encoding="utf-8") as fh:
            # JSON is YAML, and `load_boundary` keeps an absolute repo_root
            # as given, so the fixture needs no data root.
            json.dump({"version": 1, "project": "fixture-proj",
                       "repo_root": os.path.join(hr, "repo"),
                       "removable": [{"path": "src/Test/",
                                      "why": "generated test code"}],
                       "retained": []}, fh)

        def hr_run(name, item_ids, covering, zero=(), unmeasured=(),
                   off=()):
            path = os.path.join(hr, name)
            with open(path, "w", encoding="utf-8") as fh:
                for iid in item_ids:
                    row = {"item_id": iid, "outcome": "passed",
                           "coverage_lines": {"src/Prod/Cart.php": [10, 11]}}
                    if iid in zero:
                        row["coverage_lines"] = {"src/Test/Gen.php": [1]}
                    elif iid in unmeasured:
                        row.pop("coverage_lines")
                    elif iid in off:
                        row["coverage"] = False
                    elif iid not in covering:
                        row["outcome"] = "failed"
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
            return path

        a1 = hr_run("aider-s1.jsonl", hr_ids, hr_ids[:8] + [hr_ids[10]],
                    zero={hr_ids[8]})
        a2 = hr_run("aider-s2.jsonl", hr_ids[:8], hr_ids[:6],
                    zero={hr_ids[7]})
        a3 = hr_run("aider-s3.jsonl", hr_ids[:6], hr_ids[:5])
        o1 = hr_run("openhands-s1.jsonl", hr_ids, hr_ids[:7] + [hr_ids[10]],
                    zero={hr_ids[7], hr_ids[8]})
        o2 = hr_run("openhands-s2.jsonl", hr_ids[:7], hr_ids[:5],
                    zero={hr_ids[5]})
        o3 = hr_run("openhands-s3.jsonl", hr_ids[:5], hr_ids[:5])
        hr_runs = [("aider", 1, a1), ("aider", 2, a2), ("aider", 3, a3),
                   ("openhands", 1, o1), ("openhands", 2, o2),
                   ("openhands", 3, o3)]

        hr_drawn = headroom_subset(hr_items, hr_runs, boundary_path, 4242)
        hr_prov = hr_drawn["provenance"]
        solved_ids = sorted(hr_ids[:5])
        expected_k = (len(solved_ids) + 4) // 5
        expected_control = sorted(
            random.Random(4242).sample(solved_ids, expected_k))
        check("the subset is every item not solved non-vacuously in every "
              "sample it was RUN in, plus the control slice",
              hr_drawn["item_ids"] == sorted(hr_ids[5:10] + expected_control),
              str(hr_drawn["item_ids"]))
        check("...and an item both agents solved in sample 1 and never re-ran "
              "is neither: it never failed the condition, and it is not "
              "eligible for a control slice drawn from all three samples",
              hr_ids[10] not in hr_drawn["item_ids"]
              and hr_ids[10] not in hr_prov["items"],
              str(hr_prov["items"]))
        check("each way of not being solved reaches the subset by itself: a "
              "vacuous pass, a fail, and a later sample that stopped solving "
              "an item it had solved before",
              set(hr_ids[5:10]) <= set(hr_drawn["item_ids"]))
        check("the control slice is the integer ceiling of a fifth of the "
              "items solved by both agents in all three samples",
              hr_prov["solved_by_both_all_samples"] == 5
              and hr_prov["headroom"] == 5
              and hr_prov["control"] == expected_k == 1
              and hr_prov["control_fraction"] == 0.2
              and hr_prov["level1_item_count"] == 11,
              json.dumps({k: hr_prov[k] for k in
                          ("solved_by_both_all_samples", "headroom",
                           "control", "control_fraction",
                           "level1_item_count")}))
        check("every emitted item is labelled with the reason it is here, so "
              "a level-2 number is never read over the two populations at "
              "once",
              sorted(iid for iid, label in hr_prov["items"].items()
                     if label == "control") == expected_control
              and sorted(iid for iid, label in hr_prov["items"].items()
                         if label == "headroom") == sorted(hr_ids[5:10]),
              json.dumps(hr_prov["items"], sort_keys=True))
        check("each source run reports what was looked at, not only its "
              "digest: items, passes, covering, zero, not collected",
              hr_prov["source_runs"][0] == {
                  "agent": "aider", "sample": 1, "path": a1,
                  "sha256": sha256_file(a1), "n_items": 11, "n_passed": 10,
                  "n_covering": 9, "n_zero": 1, "n_not_collected": 0},
              json.dumps(hr_prov["source_runs"][0], sort_keys=True))
        check("the sidecar names exactly the fields section 6 names",
              set(hr_prov) == {
                  "schema", "algorithm_version", "source_runs",
                  "level1_item_count", "solved_by_both_all_samples",
                  "headroom", "control_fraction", "control_seed", "control",
                  "items", "selection_rule", "boundary_sha256",
                  "inference_valid", "inference_reason", "source_items",
                  "source_items_sha256", "item_id_list_digest",
                  "content_sha256"}
              and hr_prov["schema"] == HEADROOM_SCHEMA
              and hr_prov["algorithm_version"] == 1
              and all(set(entry) == {"agent", "sample", "path", "sha256",
                                     "n_items", "n_passed", "n_covering",
                                     "n_zero", "n_not_collected"}
                      for entry in hr_prov["source_runs"])
              and len(hr_prov["source_runs"]) == 6
              and hr_prov["boundary_sha256"] == sha256_file(boundary_path),
              str(sorted(hr_prov)))
        check("an agent-relative filter declares itself uninferable, and is "
              "named outside the eval* prefix the release gate walks",
              hr_prov["inference_valid"] is False
              and "agent-relative" in hr_prov["inference_reason"]
              and hr_drawn["name"] == "headroom_fixture_proj"
              and not hr_drawn["name"].startswith(SUBSET_PREFIX),
              str(hr_drawn["name"]))
        hr_again = headroom_subset(hr_items, hr_runs, boundary_path, 4242)
        hr_other = headroom_subset(hr_items, hr_runs, boundary_path, 5)
        check("the same control seed selects the same items; another seed "
              "selects another control slice from the same solved set",
              hr_again["item_ids"] == hr_drawn["item_ids"]
              and hr_again["provenance"] == hr_prov
              and hr_other["item_ids"] != hr_drawn["item_ids"]
              and hr_other["provenance"]["headroom"] == 5,
              str(hr_other["item_ids"]))
        hr_out_a = write_subset(hr_drawn,
                                os.path.join(hr, hr_drawn["name"]))
        hr_out_b = write_subset(hr_again, os.path.join(hr, "again"))
        check("the same writer puts it on disk, byte-identical twice, and "
              "the subset is a literal subset of the census lines",
              all(sha256_file(a) == sha256_file(b)
                  for a, b in zip(hr_out_a, hr_out_b))
              and set(open(hr_out_a[0], encoding="utf-8").read().splitlines())
              <= set(open(hr_items, encoding="utf-8").read().splitlines()))

        replayed_headroom = replay_headroom(hr_out_a[0])
        identified_headroom = identify_for_inference(hr_out_a[0])
        check("a written headroom replays its exact census/boundary/runs and remains descriptive",
              replayed_headroom["provenance"] == hr_prov
              and identified_headroom["inference_valid"] is False
              and identified_headroom["subset_digest"] == sha256_file(hr_out_a[0])[:16])
        staged_boundary = headroom_boundary_path(hr_out_a[0])
        with open(staged_boundary, "rb") as handle:
            original_boundary = handle.read()
        with open(staged_boundary, "ab") as handle:
            handle.write(b" ")
        check("changed staged boundary refuses before coverage selection can be reinterpreted",
              refused(lambda: replay_headroom(hr_out_a[0])) is not None)
        with open(staged_boundary, "wb") as handle:
            handle.write(original_boundary)

        def headroom_with(runs, seed=4242):
            return lambda: headroom_subset(hr_items, runs, boundary_path,
                                           seed)

        msg = refused(headroom_with(hr_runs[:5]))
        check("five runs cannot say an item was solved in every sample it "
              "was run in", msg is not None and "exactly six" in msg,
              str(msg))
        msg = refused(headroom_with(
            [("aider", n, hr_runs[n - 1][2]) for n in range(1, 7)]))
        check("six runs of ONE agent are not two agents x three samples",
              msg is not None and "exactly two agents" in msg, str(msg))
        msg = refused(headroom_with(
            [(agent, 4 if n == 3 else n, path) for agent, n, path in hr_runs]))
        check("...and samples 1, 2, 4 are not the three the design asks for",
              msg is not None and "samples 1, 2" in msg, str(msg))
        msg = refused(headroom_with(hr_runs, seed=None))
        check("an unseeded control slice is refused: it is the only evidence "
              "of what the filter removed",
              msg is not None and "control seed" in msg, str(msg))
        msg = refused(headroom_with(
            [(a, s, os.path.join(hr, "gone.jsonl") if s == 1 and a == "aider"
              else p) for a, s, p in hr_runs]))
        check("an item is not called unsolved on the strength of a run file "
              "that is not there",
              msg is not None and "no run file at" in msg, str(msg))
        for label, kind in (("no coverage block", "unmeasured"),
                            ("a coverage=false stamp", "off")):
            bad = hr_run(f"bad-{kind}.jsonl", hr_ids,
                         hr_ids[:8] + [hr_ids[10]], zero={hr_ids[8]},
                         **{kind: {hr_ids[0]}})
            msg = refused(headroom_with(
                [(a, s, bad if (a, s) == ("aider", 1) else p)
                 for a, s, p in hr_runs]))
            check(f"a passed row with {label} refuses the whole draw: that is "
                  f"a run launched without --coverage, not evidence about an "
                  f"item",
                  msg is not None and "without --coverage" in msg, str(msg))
        short_census = hr_run("short-s1.jsonl", hr_ids[:10], hr_ids[:8])
        msg = refused(headroom_with(
            [(a, s, short_census if (a, s) == ("aider", 1) else p)
             for a, s, p in hr_runs]))
        check("sample 1 IS the census: a sample-1 run over fewer items is "
              "refused, not silently intersected",
              msg is not None and "Sample 1 is the level-1 census" in msg,
              str(msg))
        widened = hr_run("widened-s2.jsonl", hr_ids[:9], hr_ids[:6],
                         zero={hr_ids[7]})
        msg = refused(headroom_with(
            [(a, s, widened if (a, s) == ("aider", 2) else p)
             for a, s, p in hr_runs]))
        check("a later sample that runs an item the agent had NOT solved "
              "breaks the adaptive containment and is refused",
              msg is not None and "not solved" in msg
              and "adaptively" in msg, str(msg))

        # ---- budgeted mode: B mutants per item, as a DERIVED MAP.
        #
        # The parent is a real `r2t.mutant-map/1` artifact over a real
        # manifest, because both are validated by their own module here and a
        # hand-shaped stand-in would only prove that the stand-in parses.
        from . import mutation as MUT
        from . import mutation_attestation as ATT
        bd = os.path.join(tmp, "budgeted")
        os.makedirs(bd, exist_ok=True)
        raw_mutants = []
        for prod_file, count in (("src/Prod/A.php", 60),
                                 ("src/Prod/B.php", 30),
                                 ("src/Prod/C.php", 8),
                                 ("src/Prod/D.php", 2)):
            for line in range(count):
                raw_mutants.append({"file": prod_file,
                                    "operator": "NegateConditional",
                                    "start_line": 100 + line, "start_col": 1,
                                    "original": ">", "mutated": ">="})
        manifest = MUT.build_manifest(raw_mutants, parser_version="fixture-1",
                                      exclusions=())
        manifest_path = os.path.join(bd, "manifest.json")
        write_provenance(manifest_path, manifest)
        level2_items = write_subset(
            hr_drawn, os.path.join(bd, hr_drawn["name"]))[0]
        level2_ids = hr_drawn["item_ids"]
        file_of = {m["id"]: m["file"] for m in manifest["mutants"]}
        by_file = {}
        for mutant in manifest["mutants"]:
            by_file.setdefault(mutant["file"], []).append(mutant["id"])
        short_item = level2_ids[0]
        # 15 mutants over two files for one item; everything for the rest.
        short_set = set(by_file["src/Prod/C.php"][:7]
                        + by_file["src/Prod/A.php"][:8])
        parent_by_mutant = {}
        for mutant_id in file_of:
            covering = [i for i in level2_ids if i != short_item]
            if mutant_id in short_set:
                covering.append(short_item)
            parent_by_mutant[mutant_id] = sorted(covering)
        parent_map = ATT.build_map_artifact(
            manifest, parent_by_mutant, [],
            coverage_sha256=sha256_file(a1),
            release_sha256=sha256_file(level2_items))
        map_path = os.path.join(bd, "mutant_map.json")
        write_provenance(map_path, parent_map)

        drawn = budgeted_sample(level2_items, map_path, manifest_path, 20, 7)
        budget, derived = drawn["sidecar"], drawn["derived_map"]
        alloc = budget["allocation"]
        check("an item that maps at most B mutants declares all of them and "
              "says so, rather than refusing a draw it cannot shrink",
              budget["short_items"] == [short_item]
              and alloc[short_item] == sorted(short_set)
              and len(alloc[short_item]) == 15,
              str(budget["short_items"]))
        wide = [iid for iid in level2_ids if iid != short_item]
        check("an item spanning at most B files is allocated with the floor "
              "of one seat per file, by quota",
              budget["unfloored_items"] == []
              and all(len(alloc[iid]) == 20 for iid in wide)
              and all(sorted(collections.Counter(
                  file_of[m] for m in alloc[iid]).items())
                  == [("src/Prod/A.php", 12), ("src/Prod/B.php", 6),
                      ("src/Prod/C.php", 1), ("src/Prod/D.php", 1)]
                  for iid in wide),
              str(sorted(collections.Counter(
                  file_of[m] for m in alloc[wide[0]]).items())))
        check("every item's ids are sorted and drawn from its own mapped "
              "set, and the items are sorted by item id",
              list(alloc) == sorted(level2_ids)
              and all(ids == sorted(ids)
                      and all(iid in parent_by_mutant[m] for m in ids)
                      for iid, ids in alloc.items()))
        check("the totals count what the sidecar declares",
              budget["totals"] == {
                  "items": 6, "pairs": 15 + 5 * 20,
                  "files": 4},
              json.dumps(budget["totals"]))
        check("the sidecar names exactly the fields section 6 names",
              set(budget) == {"schema", "basis", "per_item", "seed",
                              "parent_map_sha256", "parent_map_digest",
                              "derived_map_digest", "manifest_digest",
                              "stratify_by", "allocation", "short_items",
                              "unfloored_items", "totals"}
              and budget["schema"] == BUDGETED_SCHEMA
              and budget["basis"] == "budgeted_sample"
              and budget["stratify_by"] == "file"
              and budget["per_item"] == 20 and budget["seed"] == 7
              and budget["parent_map_sha256"] == sha256_file(map_path)
              and budget["parent_map_digest"] == parent_map["digest"]
              and budget["derived_map_digest"] == derived["digest"]
              and budget["manifest_digest"] == manifest["digest"],
              str(sorted(budget)))
        drawn_pairs = {(iid, m) for iid, ids in alloc.items() for m in ids}
        check("the DERIVED MAP is the draw: a map of the same schema whose "
              "by_mutant is exactly the drawn pairs, with everything drawn "
              "for nobody in uncovered -- so a leg run on it executes the "
              "declared population and nothing else",
              derived["schema"] == ATT.MAP_SCHEMA
              and {(iid, m) for m, items in derived["by_mutant"].items()
                   for iid in items} == drawn_pairs
              and set(derived["uncovered"])
              == set(file_of) - {m for _iid, m in drawn_pairs}
              and derived["n_pairs"] == budget["totals"]["pairs"]
              and ATT.validate_map(derived, manifest)["legacy_format"]
              is False,
              str({"n_pairs": derived["n_pairs"],
                   "uncovered": len(derived["uncovered"])}))
        check("...and it carries the parent's coverage and release identity "
              "unchanged, because it is a restriction of the same join",
              derived["coverage_sha256"] == parent_map["coverage_sha256"]
              and derived["release_sha256"] == parent_map["release_sha256"]
              and derived["manifest_digest"] == manifest["digest"]
              and derived["digest"] != parent_map["digest"])

        tight = budgeted_sample(level2_items, map_path, manifest_path, 3, 7)
        tight_alloc = tight["sidecar"]["allocation"]
        check("an item spanning MORE files than B drops the floor rather "
              "than the item, and is named in unfloored_items",
              tight["sidecar"]["unfloored_items"] == sorted(wide)
              and tight["sidecar"]["short_items"] == []
              and all(sorted(collections.Counter(
                  file_of[m] for m in tight_alloc[iid]).items())
                  == [("src/Prod/A.php", 2), ("src/Prod/B.php", 1)]
                  for iid in wide)
              and sorted(collections.Counter(
                  file_of[m] for m in tight_alloc[short_item]).items())
              == [("src/Prod/A.php", 2), ("src/Prod/C.php", 1)],
              str({iid.split("/")[-1]: sorted(collections.Counter(
                  file_of[m] for m in ids).items())
                  for iid, ids in tight_alloc.items()}))

        same = budgeted_sample(level2_items, map_path, manifest_path, 20, 7)
        other = budgeted_sample(level2_items, map_path, manifest_path, 20, 8)
        fewer_path = os.path.join(bd, "fewer.jsonl")
        with open(level2_items, encoding="utf-8") as fh:
            kept = [line for line in fh
                    if json.loads(line)["item_id"] != short_item]
        with open(fewer_path, "w", encoding="utf-8") as fh:
            fh.write("".join(kept))
        fewer = budgeted_sample(fewer_path, map_path, manifest_path, 20, 7)
        check("the same seed draws the same mutants, another seed draws "
              "others, and a per-item RNG means changing the item set leaves "
              "every other item's draw exactly where it was",
              same == drawn and other["sidecar"]["allocation"] != alloc
              and all(fewer["sidecar"]["allocation"][iid] == alloc[iid]
                      for iid in wide),
              str(sorted(other["sidecar"]["allocation"]) == sorted(alloc)))

        def budgeted_with(map_file=None, manifest_file=None, per_item=20,
                          seed=7):
            return lambda: budgeted_sample(
                level2_items, map_file or map_path,
                manifest_file or manifest_path, per_item, seed)

        bare_map = os.path.join(bd, "bare_map.json")
        write_provenance(bare_map, {"by_mutant": parent_by_mutant,
                                    "uncovered": []})
        msg = refused(budgeted_with(map_file=bare_map))
        check("the compatibility {by_mutant, uncovered} map identifies "
              "nothing to derive from and is refused",
              msg is not None and "identifies nothing" in msg, str(msg))
        stranger_path = os.path.join(bd, "stranger_items.jsonl")
        with open(level2_items, encoding="utf-8") as fh:
            kept = fh.read()
        with open(stranger_path, "w", encoding="utf-8") as fh:
            fh.write(kept + json.dumps({"item_id": "other/features/x.feature:1",
                                        "scenario": "stranger"}) + "\n")
        msg = refused(lambda: budgeted_sample(
            stranger_path, map_path, manifest_path, 20, 7))
        check("an item the parent map does not cover is refused, never a "
              "zero-pair short item",
              msg is not None and "not about" in msg
              and "other/features/x.feature:1" in msg, str(msg))
        other_manifest = MUT.build_manifest(
            raw_mutants[:-1], parser_version="fixture-1", exclusions=())
        other_manifest_path = os.path.join(bd, "other_manifest.json")
        write_provenance(other_manifest_path, other_manifest)
        msg = refused(budgeted_with(manifest_file=other_manifest_path))
        check("a map and a manifest that are not one population are refused "
              "before anything is drawn",
              msg is not None and "not one population" in msg, str(msg))
        tampered = os.path.join(bd, "tampered_map.json")
        write_provenance(tampered, dict(parent_map, n_pairs=1))
        msg = refused(budgeted_with(map_file=tampered))
        check("...and a parent map that does not validate is refused in its "
              "own validator's words",
              msg is not None and "does not validate" in msg, str(msg))
        msg = refused(budgeted_with(seed=None))
        check("an unseeded budgeted draw cannot be reproduced and is refused",
              msg is not None and "unseeded" in msg, str(msg))
        msg = refused(budgeted_with(per_item=0))
        check("...and B=0 is not a budget",
              msg is not None and "not a budget" in msg, str(msg))

        map_out, sidecar_out = write_budgeted_sample(
            drawn, os.path.join(bd, "budgeted_sample"))
        again_out = write_budgeted_sample(same, os.path.join(bd, "again"))
        check("both files are written under <out>.map.json and <out>.json, "
              "byte-identically twice (no timestamps)",
              map_out.endswith("budgeted_sample.map.json")
              and sidecar_out.endswith("budgeted_sample.json")
              and all(sha256_file(a) == sha256_file(b)
                      for a, b in zip((map_out, sidecar_out), again_out)))
        check("`verify_budgeted_sample` hands back the document when the "
              "sidecar is applied to the parent it was drawn from",
              verify_budgeted_sample(sidecar_out, map_path) == budget)
        reserialised = os.path.join(bd, "reserialised_map.json")
        with open(reserialised, "w", encoding="utf-8") as fh:
            json.dump(parent_map, fh, sort_keys=True)
        msg = refused(lambda: verify_budgeted_sample(sidecar_out,
                                                     reserialised))
        check("...and refuses a parent map whose BYTES are not the ones the "
              "draw was taken from, even at the same artifact digest",
              msg is not None and "different population" in msg, str(msg))
        second_parent = ATT.build_map_artifact(
            manifest, {m: sorted(level2_ids) for m in file_of}, [],
            coverage_sha256=sha256_file(a1),
            release_sha256=sha256_file(level2_items))
        second_path = os.path.join(bd, "second_map.json")
        write_provenance(second_path, second_parent)
        msg = refused(lambda: verify_budgeted_sample(sidecar_out,
                                                     second_path))
        check("...and refuses the same sidecar under a second map, which "
              "would rename the population and keep every count plausible",
              msg is not None and "different population" in msg, str(msg))

        # ---- the CONSUMER: what a leg checks before running a derived map.
        release_ids = set(level2_ids)

        def admitted(sidecar=None, derived=None, parent=None,
                     manifest_doc=None):
            return lambda: admit_budgeted_derived_map(
                sidecar or sidecar_out, parent or map_path,
                derived or map_out, manifest_doc or manifest,
                release_ids=release_ids)

        admission = admitted()()
        check("the consumer admits the derived map its sidecar declares, "
              "against the parent the report pins, and hands back both maps "
              "and the sidecar",
              admission["sidecar"] == budget
              and admission["derived_map"] == derived
              and admission["parent_map"] == parent_map
              and admission["derived_map_facts"]["digest"]
              == derived["digest"]
              and admission["derived_map_facts"]["n_pairs"]
              == budget["totals"]["pairs"])
        try:
            ATT.validate_map(derived, manifest, release_ids=release_ids,
                             coverage_by_item={iid: {"src/Prod/A.php": [1]}
                                               for iid in level2_ids})
            coverage_refused = None
        except ATT.MutationAssetRefused as exc:
            coverage_refused = str(exc)
        check("...and it is admitted WITHOUT coverage rows: a restriction of "
              "an existing join does not re-derive from coverage, which is "
              "why a budgeted leg runs without --coverage-run and why a "
              "budgeted project cannot bind a frozen mutation index",
              coverage_refused is not None
              and "does not rederive from coverage" in coverage_refused,
              str(coverage_refused))
        msg = refused(admitted(parent=second_path))
        check("a sidecar checked against a parent it was not drawn from is "
              "refused by `verify_budgeted_sample`, before any membership is "
              "compared",
              msg is not None and "different population" in msg, str(msg))
        other_sidecar = os.path.join(bd, "other_sidecar")
        _other_map_out, other_sidecar_out = write_budgeted_sample(
            other, other_sidecar)
        msg = refused(admitted(sidecar=other_sidecar_out))
        check("a sidecar of ANOTHER draw over the same parent is refused: "
              "same parent, same B, another seed, another map",
              msg is not None
              and "describes a draw this map is not" in msg, str(msg))
        extra = os.path.join(bd, "extra_pair.map.json")
        wide_item = sorted(iid for iid in level2_ids if iid != short_item)[0]
        spare = sorted(set(parent_by_mutant) - set(derived["by_mutant"]))[0]
        with_extra = {m: list(items)
                      for m, items in derived["by_mutant"].items()}
        with_extra[spare] = [wide_item]
        extra_map = ATT.build_map_artifact(
            manifest, with_extra, sorted(set(file_of) - set(with_extra)),
            coverage_sha256=parent_map["coverage_sha256"],
            release_sha256=parent_map["release_sha256"])
        write_provenance(extra, extra_map)
        extra_sidecar = os.path.join(bd, "extra_sidecar.json")
        write_provenance(extra_sidecar,
                         dict(budget, derived_map_digest=extra_map["digest"]))
        msg = refused(admitted(sidecar=extra_sidecar, derived=extra))
        check("a derived map carrying one pair more than the ALLOCATION is "
              "refused even when it is stamped as this map and the extra "
              "pair IS in the parent's join",
              msg is not None
              and "not the sidecar's allocation" in msg, str(msg))
        outside = os.path.join(bd, "outside_parent.map.json")
        stranger = sorted(set(parent_by_mutant) - set(short_set))[0]
        beyond = {m: list(items)
                  for m, items in derived["by_mutant"].items()}
        beyond[stranger] = sorted(set(beyond.get(stranger, []))
                                  | {short_item})
        beyond_alloc = dict(budget["allocation"])
        beyond_alloc[short_item] = sorted(
            set(beyond_alloc[short_item]) | {stranger})
        beyond_map = ATT.build_map_artifact(
            manifest, beyond, sorted(set(file_of) - set(beyond)),
            coverage_sha256=parent_map["coverage_sha256"],
            release_sha256=parent_map["release_sha256"])
        write_provenance(outside, beyond_map)
        beyond_sidecar = os.path.join(bd, "beyond_sidecar.json")
        write_provenance(beyond_sidecar, dict(
            budget, allocation=beyond_alloc,
            derived_map_digest=beyond_map["digest"]))
        msg = refused(admitted(sidecar=beyond_sidecar, derived=outside))
        check("a derived map and a sidecar that agree with each other but "
              "pair an item with a mutant the PARENT never mapped are "
              "refused: a budget restricts a join, it does not add to one",
              msg is not None and "its parent does not" in msg
              and short_item in msg, str(msg))
        narrowed = os.path.join(bd, "narrowed.map.json")
        narrow_alloc = {iid: ids for iid, ids in budget["allocation"].items()
                        if iid != short_item}
        narrow_by = {}
        for iid, ids in narrow_alloc.items():
            for mutant_id in ids:
                narrow_by.setdefault(mutant_id, []).append(iid)
        narrow_map = ATT.build_map_artifact(
            manifest, {m: sorted(v) for m, v in narrow_by.items()},
            sorted(set(file_of) - set(narrow_by)),
            coverage_sha256=parent_map["coverage_sha256"],
            release_sha256=parent_map["release_sha256"])
        write_provenance(narrowed, narrow_map)
        narrow_sidecar = os.path.join(bd, "narrow_sidecar.json")
        write_provenance(narrow_sidecar, dict(
            budget, allocation=narrow_alloc,
            derived_map_digest=narrow_map["digest"],
            totals=dict(budget["totals"], items=len(narrow_alloc))))
        msg = refused(admitted(sidecar=narrow_sidecar, derived=narrowed))
        check("a derived map that drops an ITEM is refused: every item the "
              "parent covers draws at least one mutant, so a vanished item "
              "is a narrower population wearing a budget's clothes",
              msg is not None and "dropped" in msg
              and short_item in msg, str(msg))
        restamped = os.path.join(bd, "restamped_sidecar.json")
        write_provenance(restamped, dict(budget,
                                         derived_map_digest="0" * 64))
        msg = refused(admitted(sidecar=restamped))
        check("a sidecar whose derived_map_digest is not this map's own "
              "digest is refused before its membership is believed",
              msg is not None and "describes a draw this map is not" in msg,
              str(msg))
        msg = refused(admitted(manifest_doc=other_manifest))
        check("a sidecar drawn over another manifest is refused: the budget "
              "was taken over another population's mutants",
              msg is not None
              and "another population's mutants" in msg, str(msg))

        # ---- the shim.  Three modes dispatch from one argv, and the default
        # draw's bytes are still the sampler's own.
        import contextlib
        import importlib.util
        import io as _io
        script_path = os.path.join(BENCHMARK_ROOT, "scripts",
                                   "sample_subset.py")
        module_spec = importlib.util.spec_from_file_location(
            "r2t_sample_subset_shim", script_path)
        shim = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(shim)

        def run_shim(argv):
            out = _io.StringIO()
            err = _io.StringIO()
            try:
                with contextlib.redirect_stdout(out), \
                        contextlib.redirect_stderr(err):
                    code = shim.main(argv)
            except SystemExit as exc:
                code = exc.code
            return code, out.getvalue() + err.getvalue()

        cli_dir = os.path.join(tmp, "shim")
        os.makedirs(cli_dir, exist_ok=True)
        code, _text = run_shim(["--items", items_path, "--gold", gold_dir,
                                "--n", "4", "--seed", "7",
                                "--out", os.path.join(cli_dir, "eval4")])
        direct = write_subset(sample(items_path, gold_dir, n=4, seed=7),
                              os.path.join(cli_dir, "direct"))
        check("the default draw still goes through the sampler unchanged: "
              "same bytes, subset and sidecar alike",
              code == 0
              and sha256_file(os.path.join(cli_dir, "eval4.jsonl"))
              == sha256_file(direct[0])
              and sha256_file(os.path.join(cli_dir, "eval4.provenance.json"))
              == sha256_file(direct[1]))
        headroom_argv = (
            ["--mode", "headroom", "--items", hr_items,
             "--boundary", boundary_path, "--control-seed", "4242"]
            + [f"--run={agent}={sample_no}={path}"
               for agent, sample_no, path in hr_runs])
        code, _text = run_shim(
            headroom_argv
            + ["--out", os.path.join(cli_dir, "headroom_fixture_proj")])
        check("--mode headroom writes the filter's own subset and sidecar",
              code == 0
              and sha256_file(os.path.join(
                  cli_dir, "headroom_fixture_proj.jsonl"))
              == sha256_file(hr_out_a[0])
              and sha256_file(os.path.join(
                  cli_dir, "headroom_fixture_proj.provenance.json"))
              == sha256_file(hr_out_a[1]))
        code, text = run_shim(headroom_argv
                              + ["--out", os.path.join(cli_dir, "eval_h")])
        check("...and refuses an --out that would publish it under another "
              "name, naming the one the project's boundary implies",
              code == 2 and "headroom_fixture_proj.jsonl" in text,
              text[-200:])
        code, _text = run_shim(["--mode", "budgeted", "--items", level2_items,
                                "--map", map_path, "--manifest",
                                manifest_path, "--per-item", "20", "--seed",
                                "7", "--out",
                                os.path.join(cli_dir, "budgeted_sample")])
        check("--mode budgeted writes the derived map and its sidecar",
              code == 0
              and sha256_file(os.path.join(
                  cli_dir, "budgeted_sample.map.json"))
              == sha256_file(map_out)
              and sha256_file(os.path.join(cli_dir, "budgeted_sample.json"))
              == sha256_file(sidecar_out))
        code, text = run_shim(["--mode", "budgeted", "--items", level2_items,
                               "--map", map_path, "--manifest", manifest_path,
                               "--per-item", "20", "--seed", "7",
                               "--out", os.path.join(cli_dir, "never"),
                               "--verify-release", cli_dir])
        check("--verify-release stands alone: beside a mode's draw it is a "
              "usage error, and the draw is not silently skipped",
              code == 2 and "stands alone" in text
              and not os.path.lexists(os.path.join(cli_dir, "never.json")),
              text[-200:])
        code, text = run_shim(["--mode", "headroom", "--items", hr_items,
                               "--boundary", boundary_path, "--gold",
                               gold_dir, "--control-seed", "4242",
                               "--out", os.path.join(cli_dir, "x")]
                              + [f"--run={a}={s}={p}" for a, s, p in hr_runs])
        check("a flag a mode does not use is a usage error, not a no-op: the "
              "headroom filter reads no closure map",
              code == 2 and "does not use --gold" in text, text[-200:])
        code, text = run_shim(["--mode", "budgeted", "--items", level2_items,
                               "--out", os.path.join(cli_dir, "y")])
        check("...and a mode that is missing its own inputs names them",
              code == 2 and "missing required argument(s)" in text
              and "--map" in text and "--per-item" in text, text[-200:])
        code, text = run_shim(["--items", items_path, "--gold", gold_dir,
                               "--n", "4", "--seed", "7", "--boundary",
                               boundary_path,
                               "--out", os.path.join(cli_dir, "z")])
        check("the default mode refuses the new flags too, so a headroom "
              "input cannot silently produce a stratified draw",
              code == 2 and "does not use --boundary" in text, text[-200:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- the real release.  This is the check that guards publication.
    here = BENCHMARK_ROOT
    release_dir = os.path.join(here, "release")
    if os.path.isdir(release_dir):
        problems = verify_release_subsets(release_dir)
        check("every eval*.jsonl in release/ has a matching sidecar",
              problems == [], "\n      ".join(problems))
        prov = os.path.join(release_dir, "v1", "eval100.provenance.json")
        if os.path.isfile(prov):
            with open(prov, encoding="utf-8") as fh:
                doc = json.load(fh)
            check("the eval100 sidecar admits it is post-hoc",
                  doc.get("reconstructed") is True
                  and doc.get("algorithm_committed_at_sampling_time") is False,
                  json.dumps({k: doc.get(k) for k in
                              ("reconstructed",
                               "algorithm_committed_at_sampling_time")}))
            check("...and quotes a rule and a seed rather than paraphrasing",
                  bool(doc.get("rule_as_recorded"))
                  and doc.get("seed_as_recorded") == "20260731")
            real = identify(os.path.join(release_dir, "eval100.jsonl"))
            check("the published eval100 is identifiable, and its digest is "
                  "the sidecar's content digest",
                  real and real["subset_id"] == "eval100"
                  and doc["content_sha256"].startswith(real["subset_digest"]),
                  str(real))
            clusters = _closure_clusters(release_dir)
            ids = [iid for iid, _ in
                   read_items(os.path.join(release_dir, "eval100.jsonl"))]
            total = len({clusters[i] for i in ids})
            check("...and its closure-cluster count is the real one",
                  doc.get("closure_clusters") == total,
                  f"sidecar {doc.get('closure_clusters')} vs {total}")
        else:
            check("release/v1/eval100.provenance.json exists", False, prov)
    else:
        print(f"  [SKIP] real-release check: {release_dir} is not here")

    print("\n" + ("ALL PASS (subsets)" if ok else "FAILURES (subsets)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
