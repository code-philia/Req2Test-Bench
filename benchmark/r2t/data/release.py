"""S7 — the released dataset's contract: what a release IS and how it is read.

Following the v8 strategy of one comprehensive pool with derived subsets:
extraction records fields, release applies the rule.  Nothing is dropped
from the pool; every excluded item is written out with the rule that
excluded it, so the exclusion list is auditable and the thresholds can be
moved without re-running anything.  The rule is APPLIED by
`toolkit/release_build.py` (`build_release`, `build_dataset_manifest`),
which imports this module; this module holds the vocabulary both share and
everything a consumer reads -- the task view and contract, the gold loader,
the closure clusters, the manifest schema and capability table, the
inventory and provenance readers.

The rule (SPEC §7):

  1. round-trip fail-then-pass passes (§5)
  2. it has resolvable step definitions
  3. it has an oracle
  4. it is not disabled/commented-out
  5. it is not trivially thin — D3: fewer than 3 live BODY steps is out

`dependency_profile` labels subsets rather than excluding.

Two files are written.  `items_v1.jsonl` is what a system under test
sees: requirement, criterion, and nothing about the answer — not the
closure's file names, not its size.  `gold/<n>.json` holds the reference
solution and is read only by the harness.

This module also owns the CLOSURE CLUSTER, which is what a variance over
items has to be computed against.  See `closure_clusters`.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Iterable, Optional

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)
#: Where `cli release` writes by default, and where the public closure map
#: for the root project lives.
DEFAULT_RELEASE = os.path.join(BENCHMARK, "release")
DEFAULT_GOLD_DIR = DEFAULT_RELEASE

TASK_FIELDS = ("item_id", "task", "project", "language", "framework",
               "provenance", "requirement", "criterion", "expected_output",
               # TARGET_INTERFACES_SPEC: the sorted list of first-party
               # production type names the item's reference step definitions
               # declare they interact through.  Part of the task view, so it
               # reaches the system; rendered only by a profile that
               # discloses it (`data.prompt.target_interfaces_block`).
               "target_interfaces",
               # TARGET_INTERFACES_V2_SPEC: the v2 disclosure, BESIDE the v1
               # one rather than instead of it (review A1).  `{"checked":
               # [{"key": [...], "declaration": ...}, ...], "empty_reason":
               # null | "no_action_or_check_call"}` -- the product methods
               # the item's reference test calls directly from its own action
               # and check steps.  Rendered only by a profile that discloses
               # it (`data.prompt.checked_interfaces_block`).
               "checked_interfaces", "go_suite", "files")

#: What the pool file is called.  A DEFAULT rather than a constant since the
#: release grew a second project: `release/items_v1.jsonl` is CoreShop's and
#: is frozen by content in `VERSIONS.yml`, so a per-project release writes
#: `release/<project>/items.jsonl` beside it and the v1 bytes never move.
#: `subsets.POOL_NAMES` accepts both, nearest first.
DEFAULT_ITEMS_NAME = "items_v1.jsonl"

#: The public item-to-closure map written beside a project's task rows.
CLOSURE_MAP_NAME = "closure_clusters.json"


def pre_execution_policy(project: Optional[str],
                         items_path: Optional[str] = None) -> Optional[dict]:
    """Return this project's checked-in pre-execution exclusion policy."""
    if project != "algorand-sdk":
        return None
    from ..java.algorand import DEFAULT_ITEMS, load_exclusion_policy
    return load_exclusion_policy(items_path or DEFAULT_ITEMS)


def admit_pre_execution(items: Iterable[dict], project: Optional[str],
                        requested: Optional[Iterable[str]] = None) \
        -> tuple[list[dict], Optional[dict]]:
    """Subtract project exclusions, refusing an explicitly blocked item."""
    rows = list(items)
    if project != "algorand-sdk":
        return rows, None
    from ..java.algorand import admit_before_contact
    return admit_before_contact(
        rows, item_id=lambda row: row["item_id"], requested=requested or ())


def _summary_ref(path: str) -> str:
    """A path written into a release summary, relative to `benchmark/`."""
    return os.path.relpath(os.path.abspath(path), BENCHMARK)


def _load_jsonl(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def cluster_id(files: Iterable[str]) -> str:
    """The identity of a gold closure FILE SET, stable across runs.

    sha1 of the sorted file list, truncated: we need a key that two
    different releases (or a release and an analysis script) compute
    identically from the same files, and that says nothing about which
    item produced it.  Sorted because the extractor's emission order is
    incidental; truncated to 12 hex because this is a grouping key, not a
    security claim.
    """
    return hashlib.sha1("\n".join(sorted(files)).encode()).hexdigest()[:12]


def closure_clusters(source_dir: str) -> dict[str, str]:
    """{item_id: cluster_id} — the unit an item-level variance is really over.

    Per-item outcomes on this benchmark are NOT independent, and the
    correlation is not the duplicate-signature one `build_release` already
    counts.  Many distinct scenarios are solved by removing (and therefore
    by restoring) exactly the SAME set of files: one context class serves
    twenty criteria.  A system that can write that context passes all
    twenty; a system that cannot fails all twenty.  The outcomes move
    together, so a confidence interval computed over items counts twenty
    coin flips where the corpus only ever offered one.

    On the v1 release that is not a rounding error: 422 items fall into
    142 distinct closure file-sets, 370 of them in a group with at least
    one sibling, the largest group holding 21 items.  Anything reporting
    a variance, an interval or a significance test must resample THESE.  A
    released project publishes the resulting map beside its task rows.  An
    operator-built release or installed bundle may instead supply the gold
    directory, from which this function retains the sidecar fallback.

    `bench_meta.signature` is emphatically not this key: all 100 eval100
    signatures are distinct while those same items form 77 clusters.
    """
    map_path = os.path.join(source_dir, CLOSURE_MAP_NAME)
    if os.path.isfile(map_path):
        with open(map_path, encoding="utf-8") as fh:
            return json.load(fh)

    sidecar_dir = source_dir
    manifest_path = os.path.join(sidecar_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        sidecar_dir = os.path.join(source_dir, "gold")
        manifest_path = os.path.join(sidecar_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        raise FileNotFoundError(
            f"REFUSED: no published closure map at {map_path} and no gold "
            f"manifest under {source_dir}, so no item can be assigned a "
            f"closure cluster. Without either source, a variance over items "
            f"would silently be computed as if the items were independent.")
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    out: dict[str, str] = {}
    for iid, name in manifest.items():
        with open(os.path.join(sidecar_dir, name), encoding="utf-8") as fh:
            out[iid] = cluster_id(json.load(fh)["files"])
    return out


def cluster_stats(clusters: dict[str, str]) -> dict:
    """The three numbers a release has to publish about its own correlation.

    `effective_closure_cardinality` is the honest sample size for anything
    that treats items as independent draws: 422 items over 142 distinct
    closures is a 142-point corpus wearing a 422-point denominator.
    """
    sizes: dict[str, int] = {}
    for cid in clusters.values():
        sizes[cid] = sizes.get(cid, 0) + 1
    return {
        "effective_closure_cardinality": len(sizes),
        "items_in_closure_clusters": sum(n for n in sizes.values() if n > 1),
        "largest_closure_cluster": max(sizes.values()) if sizes else 0,
    }


# --------------------------------------------------------------------------
# the dataset manifest (slice-1 D11)

#: /2 adds three things /1 could not express: an exhaustive inventory of every
#: released file, a digest over each project's gold sidecars, and a per-project
#: subset attribution that is decided once rather than re-walked per project.
#: /3 adds the one GitHub Release asset and its data-root-relative logical
#: contents for each project.  The schema describes how much of the release
#: the manifest covers; the dataset version records changes to released data.
#: Dataset 1.2 keeps its population while gaining a reproducible delivery
#: channel.
MANIFEST_SCHEMA = "r2t.dataset_manifest/3"
MANIFEST_NAME = "dataset_manifest.json"

#: THE MANIFEST IS A FUNCTION OF EVERY BYTE BELOW `release/`.
#:
#: `release_inventory` digests every nonsymlink regular file under the release
#: root except this one, so the manifest's own sha256 -- the single pin
#: `VERSIONS.yml` carries for the dataset -- now moves whenever ANY released
#: file moves.  Two of those files are rewritten by ordinary operator steps:
#: `release/slice1_mutation_assets.json` (each materialisation audit completes
#: an index entry and removes its blocker) and `release/legacy_consistency/**`
#: (reports and index pins regenerate whenever their inputs do).  Every operator
#: step that rewrites either MUST regenerate this manifest and re-pin it in
#: `VERSIONS.yml` in the same change, or `--check` lands red on the next commit
#: that touches anything.  The remediation plan's §4 carries those sub-steps
#: (lane A step A2, lane B step B4, join steps J2/J5), and two regeneration
#: rounds are expected, one per lane.
#:
#: Only the manifest itself is excluded, and only at the release ROOT: a
#: `dataset_manifest.json` nested inside a project directory is somebody else's
#: file and is digested like any other.  The exclusion exists to avoid a
#: self-referential digest, not to create a place where files can hide.
INVENTORY_EXCLUDED = (MANIFEST_NAME,)

#: The three capabilities a project is described by, and the reason the list
#: is CLOSED.  `report`/`results` print a quality row per capability, and a
#: reader seeing no `api f1` row has to be able to tell "this project cannot
#: be scored that way" from "nobody got round to it".  An undeclared
#: capability is therefore a refusal, not a default — the default would be
#: whichever answer flatters the release.
CAPABILITIES = ("mutation", "coverage", "api_similarity")

#: The installed reference roles each declared metric consumes.  This is the
#: capability/readiness join: producers and bundle versions can grow behind
#: these roles without teaching preflight about project names.  Candidate
#: outputs are deliberately absent because they do not exist before a paid
#: generation campaign starts.
CAPABILITY_REQUIRED_ROLES = {
    "mutation": (
        "mutation_validation", "scored_manifest", "mutation_map",
        "gold_baseline", "gold_results", "gold_results_attestation",
    ),
    "coverage": ("gold_baseline",),
    "api_similarity": ("production_index",),
}

#: The bundle roles that exist only because a project shipped a preserved v1
#: mutation sweep: the five operator-supplied legacy inputs, the asset index
#: and engine source they are validated against, and the four artifacts
#: `toolkit.bundle_build` derives from them.  The coverage oracle
#: (`coverage_run`, archived as `gold_baseline`) is not one of them: it is the
#: coverage capability's own role below, collectable for any project.  A
#: project declares all of these or none of them; a project onboarded after
#: Slice 1 declares none and names the release pool its bundle ships instead.
LEGACY_EVIDENCE_ROLES = (
    "raw_manifest", "legacy_map", "candidate_run", "candidate_results",
    "gold_results", "mutation_asset_index", "engine_source",
    "scored_manifest", "mutation_map", "gold_results_attestation",
    "mutation_validation",
)
GOLD_IDENTITY_FIELDS = frozenset({
    "n_gold_sidecars", "gold_manifest_sha256", "gold_sidecars_sha256"})

#: Provenance fields every released item must carry for a project to claim
#: `provenance_verified`.  `repo_url` + `commit` identify the tree, the
#: `file_*` pair identifies the revision the item's own feature file was read
#: at, and `file_path`/`line` are what makes an item_id resolvable back to a
#: line of somebody's repository.  Checked rather than declared: two of the
#: five corpora extracted for this benchmark carried provenance that pointed
#: at a wrapper repository, and it read exactly like the real thing.
_PROVENANCE_REQUIRED = ("repo_url", "commit", "file_commit", "file_date",
                        "file_path", "line")


class ManifestRefused(RuntimeError):
    """A manifest that would describe the release wrongly.  `REFUSED:` first."""


def _refuse_manifest(message: str) -> "ManifestRefused":
    return ManifestRefused("REFUSED: " + message)


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def provenance_report(items: list[dict]) -> dict:
    """Is every released item traceable to a line of a real repository?

    Returns the verdict AND the tree it agrees on, because "verified" with no
    commit beside it is a claim a reader cannot check.  Items disagreeing
    about `(repo_url, commit)` fail the check rather than being summarised:
    a pool assembled from two checkouts has no single upstream, and a manifest
    that printed one of them would be naming the wrong answer key.
    """
    missing: dict[str, list] = {}
    trees: set = set()
    for item in items:
        prov = item.get("provenance") or {}
        absent = [k for k in _PROVENANCE_REQUIRED if not prov.get(k)]
        if absent:
            missing.setdefault(",".join(absent), []).append(item["item_id"])
        trees.add((prov.get("repo_url"), prov.get("commit")))
    one_tree = len(trees) == 1
    repo_url, commit = (sorted(trees)[0] if one_tree else (None, None))
    return {
        "verified": not missing and one_tree and bool(repo_url and commit),
        "n_items": len(items),
        "repo_url": repo_url,
        "commit": commit,
        "distinct_trees": len(trees),
        "items_missing_fields": {k: v[:3] for k, v in missing.items()},
        "required_fields": list(_PROVENANCE_REQUIRED),
    }


def _release_files(release_dir: str) -> list[str]:
    """Every nonsymlink regular file below the release root, relative, sorted.

    REFUSES rather than skips, in both directions a walk can be lied to:

    * a SYMLINK -- file or directory -- is refused, because a digest taken
      through one describes whatever the link pointed at when the manifest ran.
      A released tree is a set of bytes; a pointer to bytes is not one.
    * anything that is neither a directory nor a regular file (a fifo, a
      socket, a device) is refused for the same reason: `sha256_file` would
      either block or invent a digest for something that has none.
    * a path that resolves outside the release root is refused as a
      belt-and-braces check on the two above.

    Refusing is the whole point of the function: an inventory that quietly
    skipped what it could not digest would publish a shorter list and read
    exactly like a complete one.
    """
    root = os.path.realpath(release_dir)
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(release_dir):
        dirnames.sort()
        for name in list(dirnames):
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                raise _refuse_manifest(
                    f"{os.path.relpath(path, release_dir)} is a symbolic link "
                    f"to a directory. The inventory digests bytes; a link's "
                    f"target can be replaced without the release changing.")
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, release_dir)
            if os.path.islink(path):
                raise _refuse_manifest(
                    f"{rel} is a symbolic link. The inventory digests bytes; a "
                    f"link's target can be replaced without the release "
                    f"changing, so a link cannot be pinned by digesting it.")
            if not os.path.isfile(path):
                raise _refuse_manifest(
                    f"{rel} is not a regular file. Every released path must be "
                    f"bytes this manifest can digest.")
            if os.path.realpath(path) != os.path.join(root, rel) and \
                    not os.path.realpath(path).startswith(root + os.sep):
                raise _refuse_manifest(
                    f"{rel} resolves outside the release root {root}.")
            out.append(rel)
    return sorted(out)


def release_inventory(release_dir: str) -> dict:
    """The authoritative digest of everything the release ships.

    Finding 17: `project_block` digested a fixed six-label list, so any file
    outside that list shipped unpinned BY CONSTRUCTION -- including two
    published results documents, one of which nothing in the repository read.
    An enumeration cannot have that shape of hole: whatever is under the root
    is in here with its sha256, and the only exception is this file itself.
    """
    entries = {}
    for rel in _release_files(release_dir):
        if rel in INVENTORY_EXCLUDED:
            continue
        entries[rel] = sha256_file(os.path.join(release_dir, rel))
    return {
        "n_files": len(entries),
        "excluded": list(INVENTORY_EXCLUDED),
        "regeneration": (
            "This inventory makes the manifest a function of every byte below "
            "release/, including slice1_mutation_assets.json and "
            "legacy_consistency/**. Every operator step that rewrites those "
            "files must regenerate this manifest and re-pin its sha256 in "
            "VERSIONS.yml in the same change."),
        "files": entries,
    }


def _inside(root: str, path: str) -> bool:
    """True when `path` is `root` itself or lies below it, after symlinks.

    The rule `result_ledger._contained_path` applies to ledger paths, written
    out here rather than imported: `release` has no dependency on the ledger.
    """
    root = os.path.realpath(root)
    resolved = os.path.realpath(path)
    return resolved == root or resolved.startswith(root + os.sep)


def _check_capabilities(project: str, declaration: dict) -> dict:
    caps = declaration.get("capabilities")
    if not isinstance(caps, dict) or set(caps) != set(CAPABILITIES):
        raise _refuse_manifest(
            f"{project} declares capabilities {sorted(caps or [])}, and the "
            f"list is exactly {list(CAPABILITIES)}. A missing capability is "
            f"read by a table as an absent row, and an absent row cannot say "
            f"whether the measurement is impossible here or merely undone.")
    notes = declaration.get("capability_notes") or {}
    unexplained = [k for k, v in caps.items() if not v and not notes.get(k)]
    if unexplained:
        raise _refuse_manifest(
            f"{project} declares {unexplained} false with no note saying why. "
            f"A capability this dataset does not have is a finding about the "
            f"dataset; publishing it as a bare `false` leaves the reader to "
            f"guess whether it is a gap or a decision.")
    if caps["mutation"]:
        engine = declaration.get("mutation_engine")
        known = _known_engines()
        if engine not in known:
            raise _refuse_manifest(
                f"{project} claims mutation scoring with engine "
                f"{engine!r}, which this benchmark does not have "
                f"({sorted(known)}). Mutant ids hash the engine name, so a "
                f"claim naming an engine nothing implements cannot be "
                f"executed by anything.")
    return caps


def _known_engines() -> dict:
    """`{engine name: version}` — the engines whose ids this tree can execute.

    Read out of `mutation_run.engines`, which is also what binds each engine
    to its applier: the engines a release may CLAIM and the engines a
    campaign can EXECUTE are then the same list by construction, rather than
    two lists that happen to match.
    """
    from ..bench.mutation_run import engines
    return {name: engine.version for name, engine in engines().items()}


def _project_dirs(release_dir: str) -> list[str]:
    """Directories under `release/` that hold a pool: '.' plus subdirectories.

    `v1/` is not one of them — it holds post-hoc records about the root pool,
    not a pool of its own — and it is excluded BY THE POOL FILE rather than
    by name, so a future `v2/` needs no rule here.
    """
    from . import subsets as SS

    out = []
    for name in [".", *sorted(os.listdir(release_dir))]:
        path = os.path.join(release_dir, name)
        if not os.path.isdir(path):
            continue
        if any(os.path.isfile(os.path.join(path, pool))
               for pool in SS.POOL_NAMES):
            out.append(name)
    return out


def annotated_release_declaration(block: dict) -> Optional[dict]:
    """Exact companion files; no implicit ownership of their directory."""
    annotation = block.get("annotated_release")
    if annotation is None:
        return None
    if not isinstance(annotation, dict) \
            or set(annotation) != {"items", "subsets"} \
            or not isinstance(annotation["subsets"], dict) \
            or not all(isinstance(name, str) and name
                       for name in annotation["subsets"]):
        raise _refuse_manifest(
            "annotated_release must declare items and a subsets name/path map")
    paths = [annotation["items"], *annotation["subsets"].values()]
    for path in paths:
        if not isinstance(path, str) or not path or os.path.isabs(path) \
                or os.path.normpath(path).startswith(".."):
            raise _refuse_manifest(
                "annotated release files must be release-root-relative paths")
    if len({os.path.normpath(path) for path in paths}) != len(paths):
        raise _refuse_manifest("annotated release roles must name distinct files")
    for name, path in annotation["subsets"].items():
        if os.path.basename(path) != name + ".jsonl":
            raise _refuse_manifest("an annotated subset must retain its frozen subset name")
    return {"items": os.path.normpath(annotation["items"]),
            "subsets": {name: os.path.normpath(path)
                        for name, path in annotation["subsets"].items()}}


def validate_annotated_release(release_root: str, block: dict) -> dict[str, str]:
    """Return companion -> frozen file after validating the ordered tasks.

    Counts, gold and sampling facts stay with the primary release. Annotation
    identities use the existing release inventory, checked by its readers.
    """
    from .profile import ProfileError
    from .prompt import ANNOTATION_BLOCKS, validate_annotation

    annotation = annotated_release_declaration(block)
    if annotation is None:
        return {}
    originals = block.get("subsets") or {}
    pairs = {annotation["items"]: block["items"]}
    for name, path in annotation["subsets"].items():
        if name not in originals:
            raise _refuse_manifest(
                f"annotated subset {name!r} names no frozen project subset")
        pairs[path] = originals[name]["file"]
    frozen_paths = {os.path.normpath(block["items"]),
                    *(os.path.normpath(row["file"]) for row in originals.values())}
    pool = {}
    for companion, original in pairs.items():
        if os.path.normpath(companion) in frozen_paths:
            raise _refuse_manifest("an annotated file cannot replace a frozen release file")
        loaded = []
        for rel in (companion, original):
            path = os.path.join(release_root, rel)
            if not _inside(release_root, path) or not os.path.isfile(path):
                raise _refuse_manifest(f"annotated release input {rel!r} is not a file "
                                      "inside the release root")
            try:
                loaded.append(_load_jsonl(path))
            except (OSError, ValueError) as exc:
                raise _refuse_manifest(f"cannot read annotated release input {rel!r}: {exc}") from exc
        new_rows, old_rows = loaded
        if len(new_rows) != len(old_rows):
            raise _refuse_manifest(f"{companion} changes the frozen task count")
        for new, old in zip(new_rows, old_rows):
            if not isinstance(new, dict) or not isinstance(old, dict) \
                    or {k: v for k, v in new.items() if k not in ANNOTATION_BLOCKS} \
                    != {k: v for k, v in old.items() if k not in ANNOTATION_BLOCKS}:
                raise _refuse_manifest(f"{companion} changes frozen tasks or their order")
            try:
                validate_annotation(new, companion)
            except ProfileError as exc:
                raise _refuse_manifest(str(exc).removeprefix("REFUSED: ")) from exc
            if companion == annotation["items"]:
                pool[new["item_id"]] = new
            elif pool.get(new["item_id"]) != new:
                raise _refuse_manifest(
                    f"{companion} differs from its annotated pool for {new['item_id']!r}")
    return pairs


#: Provenance fields that are a retrieval shortcut rather than context.
_PROVENANCE_WITHHELD = ("repo_url", "commit", "commit_date", "file_commit",
                        "file_date")


def task_view(item: dict) -> dict:
    """Exactly what a system under test is given.

    `TASK_FIELDS` owns the outer surface, so analysis-only `bench_meta`,
    source `reference_scenarios`, and unknown release fields do not become
    task inputs.  Within the admitted provenance field, the upstream
    `repo_url` + `commit` are withheld because together they ARE the answer:
    `git clone && git checkout 05bf7af` retrieves every removed file from a
    public repository, which would make the whole removal exercise decorative.
    The fields stay in the release for analysis; they simply do not reach the
    system.
    """
    from ..go.context import is_go, validate_context
    context = validate_context(item) if is_go(item) else None
    view = {key: item[key] for key in TASK_FIELDS
            if key in item and (key != "files" or context is not None)}
    if context is not None:
        from ..go.context import answer_paths
        view["go_suite"] = context
        view["files"] = list(answer_paths(item))
    prov = view.get("provenance")
    if isinstance(prov, dict):
        view["provenance"] = {k: v for k, v in prov.items()
                              if k not in _PROVENANCE_WITHHELD}
    return view


def task_contract(project: str, profile_path: Optional[str] = None) -> dict:
    """What the study's own arms are told about ANSWERING, in one document.

    A task view is the question and nothing else: `expected_output:
    ["step_definitions"]` is the whole of its output guidance.  Where a file
    is accepted, what a submission is recognised as on disk, and the DI
    fragment CoreShop's contexts need are not withheld secrets -- this
    benchmark's own agent arms are handed all three in their prompt -- but
    they live in `config/profile_<project>.yml`, which nothing tells an
    external submitter to read.  So the same facts are exported here, from
    the same file the arms render from.

    `agent_prompt_base` and NOT `agent_prompt_for(condition)`: the base is
    the string the profile's conditions share, and the four `{...}` slots
    left open in it are exactly the per-condition affordances -- the item,
    what the agent may see, what it may run, the harness's return instructions.
    Filling them would hand a submitter one of this study's protocols, and
    a submitted result declares no protocol at all
    (EXTERNAL_CANDIDATE_SUBMISSION_AMENDMENT.md).

    The four placement fields are the profile's `submission:` block minus its
    copy example.  `acceptance_root` is repository-relative because a
    candidate's `file_path` is (`harness.install_solution` classifies it
    against the boundary), while the prompt shows the agent the same tree
    under its workspace prefix `repo/`.

    `environment_facts` separately supplies the selected profile's framework
    and visibility guidance, using the same renderer as the study prompts.
    It leaves all base slots open and attests to no external generation.
    `profile_path` selects the profile for both strings; absent means the
    project's ordinary profile. It must describe the task project. Both
    renderers use the reviewed profile whose complete prompts `load_profile`
    re-freezes against `prompt_digest` on every load.
    """
    from .prompt import agent_prompt_base, environment_facts
    from .profile import load_profile, profile_path_for
    # No `--boundary` on this command and none wanted: a consumer exporting
    # tasks has the config directory of the clone, and that is where the
    # profile the arms used sits.
    path = profile_path or profile_path_for(None, project)
    prof = load_profile(path)
    if prof.project != project:
        raise ValueError(
            f"task source is project {project!r} but profile {path} "
            f"declares {prof.project!r}")
    contract = {
        "project": prof.project,
        "profile": _summary_ref(path),
        "agent_prompt_base": agent_prompt_base(prof),
        "environment_facts": environment_facts(prof),
        "acceptance_root": prof.acceptance_root,
        "placement_hint": prof.placement_hint,
        "suffixes": list(prof.suffixes),
        "extra_names": list(prof.extra_names),
    }
    if prof.acceptance_mode == "item_path":
        del contract["acceptance_root"]
        contract.update(acceptance_mode="item_path", acceptance_path="files")
    return contract


def export_tasks(release_path: str, out_path: str,
                 contract_path: Optional[str] = None, *,
                 profile_path: Optional[str] = None) -> int:
    """Write the admitted release questions, withholding answer provenance.

    `contract_path` adds ONE file per export, never a per-item field: the
    task rows are written by the same loop with the flag and without it, so
    an export made for a submitter and an export made for this harness are
    the same bytes.  The contract is rendered BEFORE the rows are opened, so
    a project whose profile is missing refuses without leaving a half-made
    export beside a failed contract. An explicitly selected profile is also
    validated when no contract is requested; it never changes the task rows.
    """
    items = _load_jsonl(release_path)
    if not items:
        raise ValueError(f"task source {release_path} is empty")
    missing_project = next(
        (line for line, item in enumerate(items, 1) if not item.get("project")),
        None)
    if missing_project is not None:
        raise ValueError(
            f"task source {release_path} row {missing_project} has no project")
    projects = {item["project"] for item in items}
    if len(projects) != 1:
        raise ValueError(
            f"task source {release_path} mixes projects: "
            + ", ".join(sorted(projects)))
    project = next(iter(projects))
    items, _policy = admit_pre_execution(items, project)
    contract = (task_contract(project, profile_path)
                if contract_path or profile_path else None)
    views = [task_view(item) for item in items]
    with open(out_path, "w", encoding="utf-8") as fh:
        for view in views:
            fh.write(json.dumps(view, sort_keys=True) + "\n")
    if contract_path:
        with open(contract_path, "w", encoding="utf-8") as fh:
            json.dump(contract, fh, indent=1, sort_keys=True)
            fh.write("\n")
    return len(items)


def load_gold(release_dir: str, item_id: str) -> Optional[dict]:
    manifest_path = os.path.join(release_dir, "gold", "manifest.json")
    if not os.path.isfile(manifest_path):
        return None
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    name = manifest.get(item_id)
    if not name:
        return None
    with open(os.path.join(release_dir, "gold", name), encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------
# selftest

def _write_gold_fixture(gold_dir: str, closures: dict[str, list[str]]) -> None:
    """A gold directory with the same shape `build_release` writes."""
    os.makedirs(gold_dir, exist_ok=True)
    manifest = {}
    for iid, files in closures.items():
        name = hashlib.sha1(iid.encode()).hexdigest()[:16] + ".json"
        with open(os.path.join(gold_dir, name), "w", encoding="utf-8") as fh:
            json.dump({"item_id": iid, "files": files}, fh, sort_keys=True)
        manifest[iid] = name
    with open(os.path.join(gold_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)


def selftest() -> int:
    import contextlib
    import io
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    check("the release validator knows every implemented mutation id space, "
          "including Java without asserting a project capability",
          _known_engines().get("r2t-mutate-java") == "1.0")
    check("every release capability has one generic installed-role mapping",
          tuple(CAPABILITY_REQUIRED_ROLES) == CAPABILITIES
          and CAPABILITY_REQUIRED_ROLES == {
              "mutation": (
                  "mutation_validation", "scored_manifest", "mutation_map",
                  "gold_baseline", "gold_results",
                  "gold_results_attestation",
              ),
              "coverage": ("gold_baseline",),
              "api_similarity": ("production_index",),
          })

    check("a cluster id is order-independent",
          cluster_id(["b.php", "a.php"]) == cluster_id(["a.php", "b.php"]))
    check("a cluster id is a 12-hex grouping key",
          len(cluster_id(["a.php"])) == 12
          and all(c in "0123456789abcdef" for c in cluster_id(["a.php"])))
    check("different file sets are different clusters",
          cluster_id(["a.php"]) != cluster_id(["a.php", "b.php"]))
    check("release summary paths are benchmark-relative",
          _summary_ref(os.path.join(DEFAULT_RELEASE, "items_v1.jsonl"))
          == os.path.join("release", "items_v1.jsonl"))

    with tempfile.TemporaryDirectory() as d:
        release_path = os.path.join(d, "items.jsonl")
        out_path = os.path.join(d, "tasks.jsonl")
        item = {
            "item_id": "project/features/example.feature:7",
            "task": "criterion_to_test",
            "project": "coreshop",
            "language": "php",
            "framework": "behat",
            "provenance": {
                "repo_url": "https://example.invalid/project.git",
                "commit": "answer-commit",
                "commit_date": "2026-08-24",
                "file_commit": "answer-file-commit",
                "file_date": "2026-08-23",
                "file_path": "features/example.feature",
                "line": 7,
            },
            "requirement": {"feature_title": "Example"},
            "criterion": {"scenario_title": "Works"},
            "expected_output": ["step_definitions"],
            "target_interfaces": {"behaviour": ["Project\\Model\\ExampleInterface"],
                                  "setup": []},
            "bench_meta": {"n_closure_files": 1},
            "reference_scenarios": [{"line": 12, "title": "Reference"}],
            "unknown_answer_hint": "must not become part of the task view",
        }
        with open(release_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(item, sort_keys=True) + "\n")
        from .. import cli as _cli
        with contextlib.redirect_stdout(io.StringIO()):
            rc = _cli.main(["tasks", "--release", release_path,
                            "--out", out_path])
        with open(out_path, "rb") as fh:
            actual = fh.read()
        expected = (json.dumps(task_view(item), sort_keys=True) + "\n").encode()
        exported = json.loads(actual)
        withheld = {"bench_meta", *_PROVENANCE_WITHHELD}
        check("tasks: the CLI writes task_view(item) byte for byte",
              rc == 0 and actual == expected)
        check("tasks: analysis and retrieval provenance are withheld",
              "bench_meta" not in exported
              and withheld.isdisjoint(exported["provenance"]))
        check("tasks: TASK_FIELDS is the outer allowlist, so reference and "
              "unknown fields do not reach the system",
              set(exported) == set(TASK_FIELDS) & set(item)
              and "reference_scenarios" not in exported
              and "unknown_answer_hint" not in exported)

        from .prompt import agent_prompt_base, environment_facts
        from .profile import load_profile, profile_path_for
        contract_path = os.path.join(d, "contract.json")
        contract_out = os.path.join(d, "tasks-with-contract.jsonl")
        with contextlib.redirect_stdout(io.StringIO()):
            contract_rc = _cli.main(["tasks", "--release", release_path,
                                     "--out", contract_out,
                                     "--contract", contract_path])
        with open(contract_out, "rb") as fh:
            rows_with_contract = fh.read()
        with open(contract_path, encoding="utf-8") as fh:
            contract = json.load(fh)
        profile_path = profile_path_for(None, item["project"])
        prof = load_profile(profile_path)
        check("tasks: --contract moves no task byte",
              contract_rc == 0 and rows_with_contract == actual)
        # Equality rather than a leakage scan: the contract cannot carry an
        # answer-bearing field it was never given one to carry.  Its whole
        # content is the arms' own prompt base and facts plus fields of the
        # reviewed profile, and this says so exhaustively -- an added key
        # fails here, which is the point at which someone would have to
        # justify it.
        check("tasks: the contract is the arms' own prompt and facts plus the "
              "profile's placement fields, and nothing else",
              contract == {
                  "project": prof.project,
                  "profile": _summary_ref(profile_path),
                  "agent_prompt_base": agent_prompt_base(prof),
                  "environment_facts": environment_facts(prof),
                  "acceptance_root": prof.acceptance_root,
                  "placement_hint": prof.placement_hint,
                  "suffixes": list(prof.suffixes),
                  "extra_names": list(prof.extra_names)},
              str(sorted(contract)))
        check("tasks: the contract states the placement, the discard rule "
              "and the DI channel that no task row mentions",
              prof.acceptance_prefix() in contract["agent_prompt_base"]
              and "is discarded" in contract["agent_prompt_base"]
              and prof.wiring_channel.name in contract["agent_prompt_base"]
              and prof.wiring_channel.name in contract["extra_names"]
              and prof.acceptance_root not in actual.decode("utf-8"))

        # A distinct frozen prompt proves --profile changes the rendered
        # contract, rather than merely recording a different file name.
        import shutil
        import yaml
        from .prompt import prompt_digests
        selected_path = os.path.join(d, "profile_selected.yml")
        shutil.copyfile(prof.boundary_path, os.path.join(
            d, os.path.basename(prof.boundary_path)))
        with open(profile_path, encoding="utf-8") as fh:
            selected_doc = yaml.safe_load(fh)
        selected_doc["project_label"] = "CoreShop contract fixture"
        selected_doc["facts"].append("Selected-profile fixture guidance.")
        with open(selected_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(selected_doc, fh)
        selected_doc["prompt_digest"] = prompt_digests(load_profile(
            selected_path, verify_digests=False))
        with open(selected_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(selected_doc, fh)
        selected_prof = load_profile(selected_path)
        with contextlib.redirect_stdout(io.StringIO()):
            selected_rc = _cli.main([
                "tasks", "--release", release_path, "--out", contract_out,
                "--profile", selected_path, "--contract", contract_path])
        with open(contract_out, "rb") as fh:
            selected_rows = fh.read()
        with open(contract_path, encoding="utf-8") as fh:
            selected_contract = json.load(fh)
        check("tasks: --profile renders that profile's frozen prompt base "
              "without changing task bytes",
              selected_rc == 0 and selected_rows == actual
              and selected_contract == dict(
                  contract, profile=_summary_ref(selected_path),
                  agent_prompt_base=agent_prompt_base(selected_prof),
                  environment_facts=environment_facts(selected_prof))
              and selected_contract["agent_prompt_base"]
                  != contract["agent_prompt_base"])
        check("tasks: selected frozen facts are separate from the open template",
              "Selected-profile fixture guidance." in selected_contract["environment_facts"]
              and "Selected-profile fixture guidance." not in contract["environment_facts"]
              and all("{" + slot + "}" in selected_contract["agent_prompt_base"]
                      for slot in ("task", "repo_clause", "trial_clause", "instructions")))
        with contextlib.redirect_stdout(io.StringIO()):
            no_contract_rc = _cli.main([
                "tasks", "--release", release_path, "--out", contract_out,
                "--profile", selected_path])
        with open(contract_out, "rb") as fh:
            selected_rows_only = fh.read()
        check("tasks: an explicit profile also permits a source-only export "
              "without a contract",
              no_contract_rc == 0 and selected_rows_only == actual)

        # Exercise the real visibility profiles when their owning component
        # ships them. Their bases deliberately match the ordinary base; the
        # scope, supplement and final-only guidance must travel in the facts.
        from pathlib import Path
        from .profile import CONFIG_DIR
        from ..go.context import canonical_item
        # Selected by what the profile DECLARES, not by its filename: the v2
        # family is named `profile_*_checked_interfaces_*.yml`, and a glob on
        # the v1 name would have left all 18 of them -- including the
        # coddy-agent trio, which is nobody's byte-copy -- unexercised.
        for visibility_path in sorted(Path(CONFIG_DIR).glob("profile_*.yml")):
            visibility_profile = load_profile(str(visibility_path))
            if visibility_profile.source_visibility is None:
                continue
            # The Go stack's task view carries a validated `go_suite`, so the
            # generic behat row cannot stand in for a coddy-agent profile.
            base = item if visibility_profile.language != "go" else dict(
                canonical_item(),
                requirement=item["requirement"], criterion=item["criterion"],
                expected_output=item["expected_output"],
                target_interfaces=item["target_interfaces"])
            visibility_item = dict(base, project=visibility_profile.project,
                                   language=visibility_profile.language,
                                   framework=visibility_profile.framework)
            visibility_source = os.path.join(d, "visibility-source.jsonl")
            with open(visibility_source, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(visibility_item) + "\n")
            with contextlib.redirect_stdout(io.StringIO()):
                visibility_rc = _cli.main([
                    "tasks", "--release", visibility_source, "--out", contract_out,
                    "--profile", str(visibility_path), "--contract", contract_path])
            with open(contract_out, "rb") as fh:
                visibility_tasks = fh.read()
            with open(contract_path, encoding="utf-8") as fh:
                visibility_contract = json.load(fh)
            check(f"tasks: {visibility_path.name} exports issued guidance and unchanged questions",
                  visibility_rc == 0
                  and visibility_tasks == (json.dumps(task_view(visibility_item), sort_keys=True)
                                            + "\n").encode()
                  and visibility_contract["environment_facts"] == environment_facts(visibility_profile)
                  and all(marker in visibility_contract["environment_facts"] for marker in (
                      "Implementation visibility:", "TARGET_CONTRACTS.md",
                      "You receive no harness execution"))
                  and visibility_contract["agent_prompt_base"] == agent_prompt_base(visibility_profile)
                  and all("{" + slot + "}" in visibility_contract["agent_prompt_base"]
                          for slot in ("task", "repo_clause", "trial_clause", "instructions")))

        # Supported user errors must refuse before touching either output.
        # Use the CLI so a project mismatch is a refusal, not a traceback.
        selected_doc["project_label"] = "an unfrozen change"
        with open(selected_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(selected_doc, fh)
        for label, bad_path, message in (
                ("another project's profile", profile_path_for(
                    None, "python-docx"), "declares 'python-docx'"),
                ("a missing profile", os.path.join(d, "absent.yml"),
                 "no task profile at"),
                ("an unfrozen prompt", selected_path,
                 "not the prompts it was frozen with")):
            for wants_contract in (False, True):
                refused_out = os.path.join(d, "refused-tasks.jsonl")
                refused_contract = os.path.join(d, "refused-contract.json")
                for path in (refused_out, refused_contract):
                    with open(path, "wb") as fh:
                        fh.write(b"earlier export\n")
                argv = ["tasks", "--release", release_path,
                        "--out", refused_out, "--profile", bad_path]
                if wants_contract:
                    argv += ["--contract", refused_contract]
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        _cli.main(argv)
                    refusal = ""
                except SystemExit as exc:
                    refusal = str(exc)
                with open(refused_out, "rb") as fh:
                    kept_tasks = fh.read()
                with open(refused_contract, "rb") as fh:
                    kept_contract = fh.read()
                check(f"tasks: {label} refuses before output writes "
                      f"(contract={wants_contract})",
                      refusal.startswith("REFUSED: ")
                      and message in refusal
                      and kept_tasks == kept_contract == b"earlier export\n",
                      refusal)

        unprofiled_source = os.path.join(d, "unprofiled.jsonl")
        with open(unprofiled_source, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(item, project="unprofiled-project"),
                                sort_keys=True) + "\n")
        unprofiled_out = os.path.join(d, "unprofiled-tasks.jsonl")
        unprofiled_contract = os.path.join(d, "unprofiled-contract.json")
        kept = b"an earlier export, which a failed contract must not eat\n"
        with open(unprofiled_out, "wb") as fh:
            fh.write(kept)
        try:
            export_tasks(unprofiled_source, unprofiled_out,
                         contract_path=unprofiled_contract)
            profile_refusal = None
        except SystemExit as exc:
            profile_refusal = str(exc)
        with open(unprofiled_out, "rb") as fh:
            after_unprofiled = fh.read()
        check("tasks: a project with no profile refuses before either file "
              "is opened",
              profile_refusal is not None
              and profile_refusal.startswith("REFUSED: ")
              and "no task profile at" in profile_refusal
              and after_unprofiled == kept
              and not os.path.exists(unprofiled_contract),
              str((profile_refusal, after_unprofiled)))

        from ..java.algorand import DEFAULT_ITEMS as _ALGORAND_ITEMS
        real_pool = _load_jsonl(str(_ALGORAND_ITEMS))

        def task_cli_refusal(source: str) -> tuple[Optional[str], str, str]:
            stdout, stderr = io.StringIO(), io.StringIO()
            try:
                with contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    _cli.main(["tasks", "--release", source,
                               "--out", out_path])
            except SystemExit as exc:
                return str(exc.code), stdout.getvalue(), stderr.getvalue()
            except Exception as exc:  # A refusal must not escape as a traceback.
                return (f"{type(exc).__name__}: {exc}", stdout.getvalue(),
                        stderr.getvalue())
            return None, stdout.getvalue(), stderr.getvalue()

        empty_path = os.path.join(d, "empty.jsonl")
        with open(empty_path, "w", encoding="utf-8"):
            pass
        missing_project_path = os.path.join(d, "missing-project.jsonl")
        with open(missing_project_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(
                {key: value for key, value in item.items() if key != "project"},
                sort_keys=True) + "\n")
        missing_path = os.path.join(d, "absent.jsonl")
        refusal_sources = (
            ("missing", missing_path, "No such file"),
            ("empty", empty_path, "is empty"),
            ("missing-project", missing_project_path, "has no project"),
            ("the repository's real mixed pool", str(_ALGORAND_ITEMS),
             "mixes projects"),
        )
        for label, source, expected_message in refusal_sources:
            sentinel = f"keep output for {label}\n".encode()
            with open(out_path, "wb") as fh:
                fh.write(sentinel)
            refusal, stdout, stderr = task_cli_refusal(source)
            with open(out_path, "rb") as fh:
                after = fh.read()
            check(f"tasks: {label} source is refused before output opens",
                  refusal is not None and refusal.startswith("REFUSED: ")
                  and expected_message in refusal and not stdout and not stderr
                  and after == sentinel,
                  str((refusal, stdout, stderr, after)))

        algorand = [row for row in real_pool
                    if row.get("project") == "algorand-sdk"]
        with open(release_path, "w", encoding="utf-8") as fh:
            for row in algorand:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        exported_count = export_tasks(release_path, out_path)
        exported_ids = {row["item_id"] for row in _load_jsonl(out_path)}
        policy = pre_execution_policy("algorand-sdk")
        check("tasks: export contains exactly the pre-execution admitted set",
              len(algorand) == 210 and len(policy["item_ids"]) == 51
              and exported_count == 159
              and exported_ids
              == {row["item_id"] for row in algorand}
              - set(policy["item_ids"]))

    with open(os.path.join(DEFAULT_RELEASE, "summary.json"),
              encoding="utf-8") as fh:
        shipped_summary = json.load(fh)
    check("the historical CoreShop release-build summary contains no host "
          "paths",
          shipped_summary.get("items") == "release/items_v1.jsonl"
          and shipped_summary.get("gold") == "release/gold"
          and shipped_summary.get("exclusions") == "release/exclusions.csv",
          str({k: shipped_summary.get(k)
               for k in ("items", "gold", "exclusions")}))

    with tempfile.TemporaryDirectory() as d:
        gold = os.path.join(d, "gold")
        _write_gold_fixture(gold, {
            "i1": ["src/A.php", "src/B.php"],
            # The SAME set written in the other order: the extractor's order is
            # incidental and must not split a cluster in two.
            "i2": ["src/B.php", "src/A.php"],
            "i3": ["src/A.php", "src/B.php"],
            "i4": ["src/C.php"],
        })
        cl = closure_clusters(gold)
        check("every item is assigned a cluster", set(cl) == {"i1", "i2", "i3", "i4"})
        check("items sharing a closure file-set share a cluster id",
              cl["i1"] == cl["i2"] == cl["i3"] and cl["i4"] != cl["i1"], str(cl))
        check("the map is stable across calls (no run-to-run identity)",
              closure_clusters(gold) == cl)
        st = cluster_stats(cl)
        check("cluster stats: 4 items, 2 closures, 3 in a group, largest 3",
              st == {"effective_closure_cardinality": 2,
                     "items_in_closure_clusters": 3,
                     "largest_closure_cluster": 3}, str(st))
        check("no items is 0 clusters, not a crash",
              cluster_stats({}) == {"effective_closure_cardinality": 0,
                                    "items_in_closure_clusters": 0,
                                    "largest_closure_cluster": 0})
        # The layout a released project actually ships, and the one the S6
        # gate reads: the published map beside the pool, no gold subtree
        # anywhere under it.  Passing the project directory has to resolve to
        # that map, because after the relocation the gate has no other source.
        released_dir = os.path.join(d, "released")
        os.makedirs(released_dir)
        with open(os.path.join(released_dir, CLOSURE_MAP_NAME), "w",
                  encoding="utf-8") as fh:
            json.dump(cl, fh, indent=1, sort_keys=True)
            fh.write("\n")
        check("a project directory publishing its map with no gold subtree "
              "still clusters, and to the same labels",
              closure_clusters(released_dir) == cl)
        try:
            closure_clusters(os.path.join(d, "absent"))
            check("a missing closure source refuses", False, "no exception")
        except FileNotFoundError as e:
            check("a missing closure source refuses rather than clustering "
                  "nothing",
                  str(e).startswith("REFUSED:"), str(e))

    # Real public cluster maps.  Guarded because a checkout without the release
    # still has to pass its selftest; when present, these are the populations
    # every interval in the paper depends on.
    if os.path.isfile(os.path.join(DEFAULT_RELEASE, CLOSURE_MAP_NAME)):
        from . import subsets as _subsets

        real = closure_clusters(DEFAULT_RELEASE)
        sampler_real = _subsets._closure_clusters(DEFAULT_RELEASE)
        with open(os.path.join(DEFAULT_RELEASE, "closure_clusters.json"),
                  encoding="utf-8") as fh:
            published = json.load(fh)
        st = cluster_stats(real)
        check("both public-map readers return the published v1 labels",
              published == sampler_real == real)
        # A digest check against the sampler used to compare the published map
        # with one recomputed from the release's own gold sidecars; those moved
        # to the scoring bundle, so both sides now read this one file and the
        # comparison could no longer fail.  Deleted rather than re-pinned: no
        # independent source of that digest ships in this repository, and a
        # check that cannot fail is worse than none.
        check("v1 release: 422 items over 142 distinct closures",
              len(published) == len(real) == 422
              and len(set(published.values())) == 142
              and st["effective_closure_cardinality"] == 142,
              f"{len(real)} items, {st}")
        check("v1 release: 370 items sit in a closure group, largest 21",
              st["items_in_closure_clusters"] == 370
              and st["largest_closure_cluster"] == 21, str(st))
        eval100 = os.path.join(DEFAULT_RELEASE, "eval100.jsonl")
        if os.path.isfile(eval100):
            rows = _load_jsonl(eval100)
            ids = [r["item_id"] for r in rows]
            sub = {i: real[i] for i in ids}
            check("eval100: 100 items over 77 distinct closures",
                  len(ids) == 100
                  and len({published[i] for i in ids}) == 77
                  and len(set(sub.values())) == 77,
                  f"{len(ids)} items, {len(set(sub.values()))} clusters")
            # The claim `closure_clusters` is written against: the field that
            # LOOKS like a duplicate key is not one.
            sigs = {r["bench_meta"].get("signature") for r in rows}
            check("bench_meta.signature is not the cluster key",
                  len(sigs) == 100 and len(set(sub.values())) == 77,
                  f"{len(sigs)} signatures vs {len(set(sub.values()))} clusters")

        docx_release = os.path.join(DEFAULT_RELEASE, "python-docx")
        with open(os.path.join(docx_release, "closure_clusters.json"),
                  encoding="utf-8") as fh:
            published_docx = json.load(fh)
        sampler_docx = _subsets._closure_clusters(docx_release)
        release_docx = closure_clusters(docx_release)
        # Same deletion as above, for the same reason: the digest conjunct that
        # stood here compared this file's map with itself.  The population pins
        # below are what still holds this check to a falsifiable claim.
        check("both public-map readers return the published python-docx "
              "labels, 239 items over 32 closures",
              published_docx == sampler_docx == release_docx
              and len(published_docx) == 239
              and len(set(published_docx.values())) == 32)
        check("the repository release contains public cluster maps but no "
              "answer-key trees",
              not os.path.exists(os.path.join(DEFAULT_RELEASE, "gold"))
              and not os.path.exists(os.path.join(docx_release, "gold")))

    print("\n" + ("ALL PASS (release)" if ok else "FAILURES (release)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
