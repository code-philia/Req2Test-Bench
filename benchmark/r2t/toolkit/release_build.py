"""Apply the inclusion rule and write the release; build the dataset manifest.

The writer half of `data/release.py` (wave M5).  `build_release` applies
the rule (SPEC section 7) and writes `items_v1.jsonl`, the auditable
exclusion list and `gold/<n>.json`; `build_dataset_manifest` joins the
measured facts recomputed from the released files with the declared facts
a person is answerable for, and refuses wherever the two could silently
disagree.  The vocabulary both sides share (the manifest schema, the
capability table, the task fields, the cluster arithmetic) and everything
a consumer reads stay in `data/release.py`, which this module imports;
nothing there imports this.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
from typing import Iterable, Mapping, Optional

from ..data.release import (CLOSURE_MAP_NAME, DEFAULT_ITEMS_NAME,
                             LEGACY_EVIDENCE_ROLES,
                             GOLD_IDENTITY_FIELDS, MANIFEST_SCHEMA,
                             TASK_FIELDS, _check_capabilities, _inside,
                             annotated_release_declaration,
                             _known_engines, _load_jsonl, _project_dirs,
                             _refuse_manifest, _summary_ref,
                             closure_clusters, cluster_id, cluster_stats,
                             pre_execution_policy, provenance_report,
                             release_inventory, sha256_file,
                             validate_annotated_release)

#: The line terminator every CSV this module writes ends its rows with, stated
#: rather than inherited.  `csv.writer`'s default already IS "\r\n", so this
#: constant changes no byte -- what it changes is that the release's line
#: endings are now a decision with a name, instead of a library default nobody
#: reading `release.py` could see.  The released CSVs are digest-pinned, so a
#: future reader who thinks the CRs are an accident and strips them breaks the
#: pin (which is exactly what happened to `python-docx/exclusions.csv` in PR
#: #7); `.gitattributes` keeps git from doing it silently, and this keeps the
#: producer from doing it by upgrade.
CSV_LINETERMINATOR = "\r\n"

#: The exclusion list's columns, in order.  Named because `write_csv` is now
#: the single writing path and its callers should not each retype the header.
EXCLUSIONS_HEADER = ("item_id", "reasons", "n_closure_files", "live_step_count")


def write_csv(path: str, header: Iterable[str],
              rows: Iterable[Iterable]) -> None:
    """Write one released CSV, terminators and all, in one place.

    Every CSV the release publishes goes through here, so "what the producer
    writes" is a function with a test (RI1) rather than a `csv.writer` call
    repeated per artifact.  `newline=""` hands the terminator to the csv module
    (otherwise the platform would translate the CRs again on the way out), and
    the terminator itself is `CSV_LINETERMINATOR`.
    """
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator=CSV_LINETERMINATOR)
        writer.writerow(list(header))
        for row in rows:
            writer.writerow(list(row))


def _interfaces_by_item(interfaces_path: Optional[str]) -> Optional[dict]:
    """item_id -> `target_interfaces` from an `interfaces.json`, or None when
    the stack mints no list (D2/D4).  Given a path, a missing artifact is
    refused rather than released with the field absent: an absent field
    would make every item unrunnable under a disclosing profile while
    looking, in the items file, like a complete release."""
    if interfaces_path is None:
        return None
    if not os.path.isfile(interfaces_path):
        raise ValueError(
            f"no interfaces.json at {interfaces_path}; run `interfaces` "
            f"over this extraction before releasing (TARGET_INTERFACES_SPEC)")
    with open(interfaces_path, encoding="utf-8") as fh:
        return {i["item_id"]: i["target_interfaces"]
                for i in json.load(fh)["items"]}


def _attach_interfaces(row: dict, iid: str, interfaces: Optional[dict]) -> None:
    """Copy the item's two lists onto the released row, unchanged.  The
    extractor already sorted, deduplicated and disjoined them; the prompt
    renderer refuses anything else, so nothing is repaired here."""
    if interfaces is None:
        return
    if iid not in interfaces:
        raise ValueError(
            f"{iid}: released item has no entry in interfaces.json; "
            f"the extraction and the items file were not built together")
    row["target_interfaces"] = {k: list(v) for k, v in interfaces[iid].items()}


#: What the `checked-interfaces` derivation writes (TARGET_INTERFACES_V2_SPEC
#: section 14 step 2).  Named here because this is where the file is read.
CHECKED_INTERFACES_SCHEMA = "r2t.checked-interfaces/1"


def _checked_interfaces_by_item(checked_path: Optional[str]) -> Optional[dict]:
    """item_id -> the v2 `checked_interfaces` object, or None when the release
    carries no v2 list.  Given a path, a missing or wrongly-schema'd artifact
    is refused rather than released with the field absent, for the same reason
    the v1 reader refuses: an absent field makes every item unrunnable under a
    disclosing profile while looking like a complete release."""
    if checked_path is None:
        return None
    if not os.path.isfile(checked_path):
        raise ValueError(
            f"no checked_interfaces.json at {checked_path}; run "
            f"`checked-interfaces` over this project's gold rows before "
            f"releasing (TARGET_INTERFACES_V2_SPEC)")
    with open(checked_path, encoding="utf-8") as fh:
        document = json.load(fh)
    schema = document.get("schema") if isinstance(document, dict) else None
    if schema != CHECKED_INTERFACES_SCHEMA:
        raise ValueError(
            f"{checked_path}: schema is {schema!r}, expected "
            f"{CHECKED_INTERFACES_SCHEMA!r}")
    return dict(document["items"])


def _attach_checked_interfaces(row: dict, iid: str,
                               checked: Optional[dict]) -> None:
    """Copy the item's v2 object onto the released row, verbatim.  The
    derivation already sorted and de-duplicated the entries and recorded the
    empty reason; the prompt renderer refuses anything else, so nothing is
    repaired here."""
    if checked is None:
        return
    if iid not in checked:
        raise ValueError(
            f"{iid}: released item has no entry in checked_interfaces.json; "
            f"the derivation and the items file were not built together")
    from types import SimpleNamespace
    from ..data.profile import ProfileError
    from ..data.prompt import checked_interfaces_block
    entry = checked[iid]
    row["checked_interfaces"] = json.loads(json.dumps(entry))
    # The prompt renderer is the shape authority for this field, and it is
    # the ONLY reader of it.  Running it here turns a malformed derivation
    # output into a named refusal while the release is being built, instead
    # of into an item that looks complete and refuses at prompt time.
    try:
        checked_interfaces_block(row, SimpleNamespace(path="checked_interfaces.json"))
    except ProfileError as exc:
        raise ValueError(str(exc).removeprefix("REFUSED: ")) from exc


def build_release(artifacts: str, items_path: str, out_dir: str,
                  min_live_steps: int = 3,
                  validation_name: str = "validation.jsonl",
                  project: Optional[str] = None,
                  items_name: str = DEFAULT_ITEMS_NAME, *,
                  closures_path: Optional[str] = None,
                  quality_path: Optional[str] = None,
                  interfaces_path: Optional[str] = None,
                  checked_interfaces_path: Optional[str] = None,
                  validation_path: Optional[str] = None,
                  portable_paths: bool = False,
                  item_dispositions: Optional[Mapping[str, dict]] = None) \
        -> dict:
    policy = pre_execution_policy(project, items_path)
    policy_ids = set(policy["item_ids"]) if policy is not None else set()
    closures_path = closures_path or os.path.join(artifacts, "closures.json")
    quality_path = quality_path or os.path.join(artifacts, "quality.json")
    validation_path = validation_path or os.path.join(
        artifacts, validation_name)
    from ..go.context import ContextRefused, compare_context, is_go
    with open(closures_path, encoding="utf-8") as fh:
        closures = {}
        for closure in json.load(fh):
            iid = closure["item_id"]
            if is_go(closure) and iid in closures:
                raise ContextRefused(f"REFUSED: duplicate Go closure {iid}")
            closures[iid] = closure
    with open(quality_path, encoding="utf-8") as fh:
        quality = json.load(fh)
    # TARGET_INTERFACES_SPEC section 6: a released item carries its
    # `target_interfaces` list wherever the stack has an extractor -- the
    # `release` verb passes the path for those stacks (behat today) and None
    # for the stacks D2/D4 withhold.  Given a path, an extraction without the
    # artifact is refused rather than released with the field absent: an
    # absent field would make every item unrunnable under a disclosing
    # profile while looking, in the items file, like a complete release.
    interfaces = _interfaces_by_item(interfaces_path)
    # TARGET_INTERFACES_V2_SPEC section 5: the v2 field, from the
    # `checked-interfaces` derivation, for every stack including Java
    # cucumber -- the v1 D4 withholding was about an EXTRACTOR that Java
    # never had, and the v2 list is recorded by the harness instead.
    checked_interfaces = _checked_interfaces_by_item(checked_interfaces_path)
    unreleased_checked = set(checked_interfaces or ())
    validation = {v["item_id"]: v
                  for v in _load_jsonl(validation_path)}

    os.makedirs(out_dir, exist_ok=True)
    gold_dir = os.path.join(out_dir, "gold")
    os.makedirs(gold_dir, exist_ok=True)

    included, excluded = [], []
    skipped_other_project = 0
    for item in _load_jsonl(items_path):
        if project and item.get("project") != project:
            # Other corpora are extracted but have no executable harness
            # yet (the ART expansion).  They are not exclusions from THIS
            # release, so they are counted rather than given a reason.
            skipped_other_project += 1
            continue
        iid = item["item_id"]
        decision = (item_dispositions.get(iid)
                    if item_dispositions is not None else None)
        if decision is not None:
            if not isinstance(decision, dict) \
                    or set(decision) != {"stage", "reasons"} \
                    or not isinstance(decision["stage"], str) \
                    or not isinstance(decision["reasons"], list) \
                    or any(not isinstance(reason, str) or not reason
                           for reason in decision["reasons"]):
                raise ValueError(f"malformed disposition for {iid}")
            if decision["stage"] != "released":
                cl = closures.get(iid, {})
                q = quality.get(iid, {})
                excluded.append((
                    iid, list(decision["reasons"]),
                    {"n_closure_files": len(cl.get("files", [])),
                     "live_step_count": q.get("live_step_count")}))
                continue
        if iid in policy_ids:
            excluded.append((
                iid, [policy["reason"]],
                {"n_closure_files": 0, "live_step_count": None}))
            continue
        if iid not in closures:
            # `requirement_to_test` items are keyed per FEATURE, not per
            # scenario, so they have no closure.  Recording them as an
            # explicit exclusion is the point: v1 is criterion-only, and a
            # reader of the release must be able to see that the second
            # task was deferred rather than silently scored zero.
            reason = ("requirement_task_deferred_in_v1"
                      if item.get("task") == "requirement_to_test"
                      else "no_closure_extracted")
            excluded.append((iid, [reason],
                             {"n_closure_files": 0, "live_step_count": None}))
            continue
        q = quality.get(iid, {})
        cl = closures[iid]
        if is_go(item) or is_go(cl):
            compare_context(item, cl)
        v = validation.get(iid)

        reasons = []
        dispositions = isinstance(cl.get("admitted"), bool) \
            and isinstance(q.get("admitted"), bool)
        if dispositions:
            # Research-minimal has already closed the complete admitted
            # population with explicit per-ID decisions.  Do not add
            # ``not_validated`` to an item deliberately stopped before N=3.
            if not cl["admitted"]:
                reasons.append("closure." + cl["reason"])
            if not q["admitted"]:
                reasons.append("quality." + q["reason"])
            if not reasons:
                if v is None:
                    reasons.append("not_validated")
                elif not v["admitted"]:
                    reasons.append("round_trip:" + v["reason"])
        else:
            if v is None:
                reasons.append("not_validated")
            elif not v["admitted"]:
                reason = v["reason"]
                # A gold closure that fails for a scenario CoreShop's own CI
                # never runs is evidence about the SCENARIO, not about the
                # closure extractor.  SPEC §9.2 reads the closure_incomplete
                # rate as the extractor's honest error rate, so the two must
                # not share a bucket: 24 of the 545 domain scenarios are
                # selected by no suite (14 files carry no `@domain`, one is
                # `@wip`) and their step definitions have never executed.
                if reason == "closure_incomplete" and q.get(
                        "upstream_selected") is False:
                    reason = "never_run_upstream"
                reasons.append(f"round_trip:{reason}")
            if cl["counts"]["steps_unmatched"]:
                reasons.append("unresolvable_step_definitions")
            if not q.get("has_oracle", False):
                reasons.append("no_oracle")
            if q.get("commented_out", False):
                reasons.append("commented_out")
            # D3 revision (2026-08-12, owner): the bar is unchanged at 3, but
            # it counts the steps the runner EXECUTES -- scenario body plus
            # Background -- rather than the body alone.  The reason string
            # moves with the predicate so an exclusions CSV can never read as
            # if the old rule produced it.  A quality record that EXISTS but
            # predates the field is a refusal rather than a silent zero --
            # reading the absent count as 0 would mark a whole population
            # thin without saying so.  An absent record keeps its old
            # meaning (no oracle, thin), because that is what it meant
            # before this revision too.
            if q and "live_effective_step_count" not in q:
                raise ValueError(
                    f"{iid}: quality record has no live_effective_step_count; "
                    "rebuild the quality artifacts before releasing under the "
                    "effective-step rule")
            if q.get("live_effective_step_count", 0) < min_live_steps:
                reasons.append(
                    f"thin_scenario_lt_{min_live_steps}_effective_steps")

        row = {k: item[k] for k in TASK_FIELDS
               if k in item and (k != "files" or is_go(item))}
        if is_go(item):
            from ..go.context import answer_paths
            row["files"] = list(answer_paths(cl))
        _attach_interfaces(row, iid, interfaces)
        row["bench_meta"] = {
            "n_closure_files": len(cl["files"]),
            "n_closure_contexts": len(cl.get("context_classes", [])),
            "live_step_count": q.get("live_step_count"),
            "live_background_step_count": q.get("live_background_step_count"),
            "n_oracle_steps": q.get("n_oracle_steps"),
            "steps_removable": q.get("steps_removable"),
            "steps_retained": q.get("steps_retained"),
            "dependency_profile": q.get("dependency_profile"),
            "tags": q.get("tags"),
            "round_trip_seconds": (None if v is None else
                                   v.get("seconds") if dispositions else
                                   v["seconds"]),
            "upstream_selected": q.get("upstream_selected"),
            "signature": q.get("signature"),
        }
        if reasons:
            excluded.append((iid, reasons, row["bench_meta"]))
            continue
        # After the exclusion branch, because the derivation is built from a
        # RELEASED items file: it has no entry for an item this build drops,
        # and `_attach_checked_interfaces` refuses an item it cannot find.
        # Attaching before the branch would kill a CoreShop or Sylius re-mint
        # on the first thin_scenario item.
        _attach_checked_interfaces(row, iid, checked_interfaces)
        unreleased_checked.discard(iid)
        included.append(row)

    if unreleased_checked:
        raise ValueError(
            f"checked_interfaces.json names {len(unreleased_checked)} items "
            f"this release does not include, e.g. "
            f"{sorted(unreleased_checked)[:3]}; the derivation and the items "
            f"file were not built together")

    items_out = os.path.join(out_dir, items_name)
    with open(items_out, "w", encoding="utf-8") as fh:
        for row in included:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    manifest = {}
    for row in included:
        cl = closures[row["item_id"]]
        name = hashlib.sha1(row["item_id"].encode()).hexdigest()[:16] + ".json"
        with open(os.path.join(gold_dir, name), "w", encoding="utf-8") as fh:
            sidecar = {"item_id": row["item_id"], "files": cl["files"],
                       "di_fragment": cl["di_fragment"],
                       "context_classes": cl["context_classes"],
                       "feature_file": cl["feature_file"],
                       "scenario_line": cl["scenario_line"]}
            if is_go(row):
                sidecar["go_suite"] = compare_context(row, cl)
            json.dump(sidecar, fh, indent=1, sort_keys=True)
        manifest[row["item_id"]] = name
    with open(os.path.join(gold_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)

    excl_out = os.path.join(out_dir, "exclusions.csv")
    write_csv(excl_out, EXCLUSIONS_HEADER,
              ([iid, ";".join(reasons), meta["n_closure_files"],
                meta["live_step_count"]] for iid, reasons, meta in excluded))

    tally: dict[str, int] = {}
    for _iid, reasons, _m in excluded:
        for r in reasons:
            tally[r] = tally.get(r, 0) + 1

    sigs: dict[str, int] = {}
    for row in included:
        sig = row["bench_meta"].get("signature")
        if sig:
            sigs[sig] = sigs.get(sig, 0) + 1
    dup_groups = {k: n for k, n in sigs.items() if n > 1}

    # The stronger correlation, computed from the closures we just wrote
    # rather than re-read from disk.  Byte-identical scenarios (above) are a
    # handful; scenarios sharing a closure file-set are most of the corpus,
    # and it is THIS number that bounds what an interval over items can mean.
    clusters = {row["item_id"]:
                cluster_id(closures[row["item_id"]]["files"])
                for row in included}
    with open(os.path.join(out_dir, CLOSURE_MAP_NAME), "w",
              encoding="utf-8") as fh:
        json.dump(clusters, fh, indent=1, sort_keys=True)
        fh.write("\n")

    info = {
        "pool": len(included) + len(excluded),
        "included": len(included),
        "excluded": len(excluded),
        # Not an exclusion: byte-identical scenarios are real scenarios in
        # the repository.  But per-item outcomes on them are correlated, so
        # anything computing a variance over items has to know.
        "duplicate_signature_groups": len(dup_groups),
        "items_in_duplicate_groups": sum(dup_groups.values()),
        # The effective sample size (`closure_clusters`).  Published in the
        # release summary so a reader never has to take the item count as the
        # number of independent observations.
        **cluster_stats(clusters),
        "upstream_selected_included": sum(
            1 for r in included if r["bench_meta"].get("upstream_selected")),
        "exclusion_reasons": dict(sorted(tally.items(), key=lambda kv: -kv[1])),
        "min_live_steps": min_live_steps,
        "project": project,
        "items_from_other_projects_not_in_scope": skipped_other_project,
        "items": items_name if portable_paths else _summary_ref(items_out),
        "gold": "gold" if portable_paths else _summary_ref(gold_dir),
        "exclusions": ("exclusions.csv" if portable_paths
                       else _summary_ref(excl_out)),
    }
    if policy is not None:
        info["pre_execution_exclusion"] = {
            "count": len(policy["item_ids"]),
            "reason": policy["reason"],
            "caption": policy["caption"],
        }
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=1, sort_keys=True)
    return info


def _declared_gold_binding(project: str, project_dir: str, items: list[dict],
                           declaration: dict) -> tuple[dict, dict]:
    """Resolve relocated answer-key identity and the public closure map."""
    identity = declaration.get("release_gold_identity")
    if not isinstance(identity, dict) or set(identity) != GOLD_IDENTITY_FIELDS:
        present = set(identity) if isinstance(identity, dict) else set()
        raise _refuse_manifest(
            f"{project} has no checked-in gold directory and its "
            f"release_gold_identity is not exactly the closed fields "
            f"{sorted(GOLD_IDENTITY_FIELDS)} (missing "
            f"{sorted(GOLD_IDENTITY_FIELDS - present)}, unknown "
            f"{sorted(present - GOLD_IDENTITY_FIELDS)}).")
    if identity["n_gold_sidecars"] != len(items):
        raise _refuse_manifest(
            f"{project} declares {identity['n_gold_sidecars']} relocated gold "
            f"sidecars for {len(items)} released items. The declaration and "
            f"pool must describe the same answer-key membership.")
    try:
        clusters = closure_clusters(project_dir)
    except FileNotFoundError as exc:
        raise _refuse_manifest(str(exc).removeprefix("REFUSED: ")) from exc
    pool_ids = {item["item_id"] for item in items}
    if set(clusters) != pool_ids:
        missing = sorted(pool_ids - set(clusters))
        extra = sorted(set(clusters) - pool_ids)
        raise _refuse_manifest(
            f"{project}'s published closure map differs from its pool "
            f"membership (missing {missing[:1]}, extra {extra[:1]}).")
    record = {field: identity[field]
              for field in sorted(GOLD_IDENTITY_FIELDS)}
    return record, clusters


def _gold_binding(release_dir: str, project: str, project_dir: str,
                  items: list[dict], declaration: dict) -> tuple[dict, dict]:
    """`(the manifest's gold record, {item_id: cluster_id})`.

    The answer key was the one part of the release with no content digest at
    all (finding 3): the gold manifest's own bytes were pinned, and the 661
    sidecars it names -- the files that say which production files a solution
    must restore -- were pinned by nothing.  A tamper inside a sidecar in a
    closure cluster of size two or more left every gate in the repository green
    and every published statistic unchanged, because the cluster arithmetic
    reads the file SET and not the file NAMES.

    So three claims are checked here and one digest is published:

    * pool, gold manifest and the sidecar files on disk have the SAME item-ID
      membership -- an unmentioned sidecar is as much of a problem as a missing
      one, because the digest below has to be over a known set;
    * each sidecar's own `item_id` equals the id the manifest filed it under;
    * where the released item carries `bench_meta.n_closure_files` /
      `n_closure_contexts`, they equal the sidecar's actual array lengths.
      This is the cheap cross-check the review asked for: the pool file is
      pinned in `VERSIONS.yml` by content, so its counts are an independent
      witness to the sidecars' shape.
    """
    gold_dir = os.path.join(project_dir, "gold")
    if not os.path.exists(gold_dir):
        return _declared_gold_binding(project, project_dir, items, declaration)
    manifest_path = os.path.join(gold_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        raise _refuse_manifest(
            f"{project} ships no gold manifest at "
            f"{os.path.relpath(manifest_path, release_dir)}. Without it no "
            f"item has a reference solution and no closure cluster can be "
            f"computed.")
    with open(manifest_path, encoding="utf-8") as fh:
        gold_manifest = json.load(fh)

    on_disk = {name for name in os.listdir(gold_dir)
               if name != "manifest.json"
               and os.path.isfile(os.path.join(gold_dir, name))}
    named = set(gold_manifest.values())
    orphans = sorted(on_disk - named)
    if orphans:
        raise _refuse_manifest(
            f"{project}: {len(orphans)} file(s) in {gold_dir} that the gold "
            f"manifest does not name (first {orphans[0]}). A sidecar nothing "
            f"names is a reference answer nothing accounts for, and the "
            f"sidecar digest below would not cover it.")
    absent = sorted(named - on_disk)
    if absent:
        raise _refuse_manifest(
            f"{project}: the gold manifest names {len(absent)} sidecar(s) that "
            f"are not on disk (first {absent[0]}). The answer key is "
            f"incomplete.")

    pool_ids = {item["item_id"] for item in items}
    strangers = sorted(pool_ids - set(gold_manifest))
    if strangers:
        raise _refuse_manifest(
            f"{project}: {len(strangers)} released items have no gold sidecar "
            f"(first {strangers[0]}). The cluster statistics below would be "
            f"computed over a different set from the one published.")
    unshipped = sorted(set(gold_manifest) - pool_ids)
    if unshipped:
        raise _refuse_manifest(
            f"{project}: the gold manifest carries {len(unshipped)} items the "
            f"pool does not ship (first {unshipped[0]}). Pool, gold manifest "
            f"and sidecars must have one membership, or 'the answer key' names "
            f"a different corpus from the one under test.")

    item_by_id = {item["item_id"]: item for item in items}
    bench_meta = {item["item_id"]: (item.get("bench_meta") or {})
                  for item in items}
    clusters: dict[str, str] = {}
    entries: list[dict] = []
    for iid in sorted(gold_manifest):
        name = gold_manifest[iid]
        path = os.path.join(gold_dir, name)
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if doc.get("item_id") != iid:
            raise _refuse_manifest(
                f"{project}: {os.path.relpath(path, release_dir)} is filed "
                f"under {iid} and calls itself {doc.get('item_id')!r}. One of "
                f"the two names the wrong answer key for an item.")
        from ..go.context import compare_context, is_go
        if is_go(item_by_id[iid]) or is_go(doc):
            compare_context(item_by_id[iid], doc)
        for field, array in (("n_closure_files", "files"),
                             ("n_closure_contexts", "context_classes")):
            claimed = bench_meta.get(iid, {}).get(field)
            if claimed is None:
                continue
            actual = len(doc.get(array) or [])
            if claimed != actual:
                raise _refuse_manifest(
                    f"{project}: {iid} publishes bench_meta.{field}={claimed} "
                    f"while its sidecar's `{array}` holds {actual}. The pinned "
                    f"pool file and the answer key disagree about the shape of "
                    f"the same item's closure.")
        clusters[iid] = cluster_id(doc.get("files") or [])
        entries.append({"path": os.path.relpath(path, release_dir),
                        "sha256": sha256_file(path)})

    entries.sort(key=lambda e: e["path"])
    canonical = json.dumps(entries, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    record = {
        "n_gold_sidecars": len(entries),
        # The digest that closes finding 3: over the sidecars' own bytes, keyed
        # by path, so a rename and an edit are both visible.
        "gold_sidecars_sha256": hashlib.sha256(canonical).hexdigest(),
        # Compatibility: the digest /1 published, of the gold manifest's own
        # bytes.  Kept so a reader or tool pinned to the old field still
        # resolves -- it is the index, not the answers.
        "gold_manifest_sha256": sha256_file(manifest_path),
    }
    if "release_gold_identity" in declaration \
            and declaration["release_gold_identity"] != record:
        raise _refuse_manifest(
            f"{project}'s declared release_gold_identity disagrees with the "
            "identity measured from its on-disk gold.")
    return record, clusters


def _subset_records(release_dir: str, subset_paths: Iterable[str]) -> dict:
    """The named subsets of ONE project's pool, with each sidecar's facts.

    Takes the paths it is GIVEN.  It used to walk the project directory, and
    since CoreShop's directory is the release root that walk descended into
    `release/python-docx/` and published the docx census under CoreShop
    (finding 5).  Assignment is now decided once, in `build_dataset_manifest`.

    Read through `subsets` so the manifest quotes the same sidecar the
    publishing gate checks, rather than a second opinion about it.
    """
    from ..data import subsets as SS

    out: dict = {}
    for path in subset_paths:
        name = os.path.basename(path)[: -len(".jsonl")]
        record = {"file": os.path.relpath(path, release_dir),
                  "content_sha256": SS.sha256_file(path)}
        for cand in SS.sidecar_candidates(release_dir, path):
            if os.path.isfile(cand):
                with open(cand, encoding="utf-8") as fh:
                    doc = json.load(fh)
                record.update({
                    "sidecar": os.path.relpath(cand, release_dir),
                    "sidecar_sha256": SS.sha256_file(cand),
                    "n": doc.get("n"),
                    "seed": doc.get("seed"),
                    "census": doc.get("census"),
                    "reconstructed": doc.get("reconstructed"),
                    "closure_clusters": (doc.get("clusters") or {}).get(
                        "total", doc.get("closure_clusters")),
                })
                break
        out[name] = record
    return out


def _project_dir(release_dir: str, project: str, rel_dir: str) -> str:
    """Where a declared project's bytes are -- and it is inside the release.

    #284.  `os.path.join` drops `release_dir` entirely when `dir` is absolute
    and walks out of it when `dir` climbs with `..`, and nothing downstream
    notices: `_project_dirs` lists only subdirectories of the root and
    `release_inventory` digests only what `_release_files` walks under it, so
    an escaping project contributes nothing for either to catch.  It would
    still publish a block -- counts, clusters, digests, provenance -- for
    bytes the inventory does not cover, which is exactly the property the
    inventory claims to have.

    An absolute `dir` is refused whether or not it lands inside the root:
    containment alone would accept one that does, and it would then publish a
    machine path as the project's `dir` and slip past the shared-directory
    refusal, which compares release-relative paths -- two blocks, two digests,
    one set of bytes.

    How such a project SHOULD be declared, when one legitimately lives outside
    the repository, is an open question (#284); this only refuses the escape.
    """
    if os.path.isabs(rel_dir):
        raise _refuse_manifest(
            f"{project} declares the absolute directory {rel_dir!r}. A "
            f"released project's directory is stated relative to the release "
            f"root; an absolute one publishes a path that means nothing on "
            f"another machine, and names bytes that the release-relative "
            f"checks around it -- shared directory, undeclared directory, "
            f"subset ownership -- cannot recognise as the ones they hold.")
    project_dir = os.path.join(release_dir, rel_dir)
    if not _inside(release_dir, project_dir):
        raise _refuse_manifest(
            f"{project} declares directory {rel_dir!r}, which resolves to "
            f"{os.path.realpath(project_dir)} -- outside the release root "
            f"{os.path.realpath(release_dir)}. The release inventory digests "
            f"only what lies below that root, so a project pointed out of it "
            f"would publish counts and digests for bytes no inventory covers.")
    return project_dir


def project_block(release_dir: str, declaration: dict,
                  subset_paths: Iterable[str] = ()) -> dict:
    """The MEASURED half of one project's entry, from the files on disk.

    `subset_paths` is passed IN rather than discovered here: which project a
    subset belongs to is a question about the whole release, and answering it
    per project from inside a directory walk is what mis-attributed the
    python-docx census to CoreShop.
    """
    project = declaration["project"]
    rel_dir = declaration.get("dir") or "."
    project_dir = _project_dir(release_dir, project, rel_dir)
    items_name = declaration.get("items", DEFAULT_ITEMS_NAME)
    items_path = os.path.join(project_dir, items_name)
    if not _inside(project_dir, items_path):
        raise _refuse_manifest(
            f"{project} declares the pool {items_name!r}, which resolves "
            f"outside its own directory {rel_dir!r}. The block would publish "
            f"counts, digests and provenance for a file the release inventory "
            f"never walked, while the pool that inventory does digest under "
            f"that directory is not the one described.")
    if not os.path.isfile(items_path):
        raise _refuse_manifest(
            f"{project} declares {os.path.join(rel_dir, items_name)}, which "
            f"is not there. A manifest entry for a pool nobody shipped is a "
            f"citation that resolves to nothing.")
    items = _load_jsonl(items_path)
    gold, clusters = _gold_binding(
        release_dir, project, project_dir, items, declaration)

    # Every file the project ships that a reader might quote.  Optional ones
    # are digested WHEN PRESENT rather than required: v1 shipped neither its
    # validation records nor its anti-vacuity summary, and demanding them
    # here would make the manifest refuse to describe the release it has.
    digests = {}
    for label, name in (("items", items_name),
                        ("gold_manifest", "gold/manifest.json"),
                        ("exclusions", "exclusions.csv"),
                        ("summary", "summary.json"),
                        ("validation", "validation.jsonl"),
                        ("anti_vacuity", "anti_vacuity.json")):
        path = os.path.join(project_dir, name)
        if os.path.isfile(path):
            digests[label] = sha256_file(path)
    summary_path = os.path.join(project_dir, "summary.json")
    summary = {}
    if os.path.isfile(summary_path):
        with open(summary_path, encoding="utf-8") as fh:
            summary = json.load(fh)

    block = {
        "dir": rel_dir,
        "items": os.path.relpath(items_path, release_dir),
        "n_items": len(items),
        "digests": digests,
        **gold,
        **cluster_stats({i["item_id"]: clusters[i["item_id"]] for i in items}),
        "provenance": provenance_report(items),
        "subsets": _subset_records(release_dir, subset_paths),
        "inclusion_rule": {
            "min_live_steps": summary.get("min_live_steps"),
            "pool": summary.get("pool"),
            "excluded": summary.get("excluded"),
            "exclusion_reasons": summary.get("exclusion_reasons") or {},
        },
    }
    block["provenance_verified"] = block["provenance"]["verified"]
    return block


def _bundle_block(release_dir: str, project: str,
                  declaration: dict) -> dict:
    """Measure the checked-in evidence named by one bundle declaration."""
    bundle = declaration.get("bundle")
    if not isinstance(bundle, dict):
        raise _refuse_manifest(f"{project} has no bundle declaration")
    required = {"version", "asset", "artifacts", "worker_plan",
                "seed_manifest_sha256", "production_index_sha256"}
    # `std_arm` is optional because only CoreShop publishes a byte-pinned
    # table an asset can be required to reproduce; every other project's
    # bundle declaration is unchanged by roadmap D5.
    optional = {"std_arm", "scoring_gold_sha256", "annotated_release",
                "release_pool", "coverage_run_sha256"}
    if not required <= set(bundle) or set(bundle) - required - optional:
        raise _refuse_manifest(
            f"{project} bundle fields differ; missing="
            f"{sorted(required - set(bundle))}, unknown="
            f"{sorted(set(bundle) - required - optional)}")

    def digest(value, label: str, *, nullable: bool = False):
        if nullable and value is None:
            return None
        if not isinstance(value, str) or len(value) != 64:
            raise _refuse_manifest(f"{project} bundle {label} is not SHA-256")
        try:
            int(value, 16)
        except ValueError:
            raise _refuse_manifest(
                f"{project} bundle {label} is not SHA-256") from None
        return value

    version = bundle["version"]
    asset = bundle["asset"]
    if not isinstance(asset, dict) or set(asset) != {"name", "sha256"}:
        raise _refuse_manifest(f"{project} bundle asset fields differ")
    asset_name = asset["name"]
    asset_sha256 = digest(asset["sha256"], "asset sha256", nullable=True)
    if not isinstance(version, str) or not version.startswith("v"):
        raise _refuse_manifest(f"{project} bundle version is invalid")
    if asset_name != f"r2t-{version}-{project}.tar.gz":
        raise _refuse_manifest(
            f"{project} bundle asset name does not match its version")
    artifacts = bundle["artifacts"]
    if not isinstance(artifacts, dict):
        raise _refuse_manifest(f"{project} bundle artifacts are not an object")
    required_artifacts = {
        "release_items", "release_gold", "gold", "profile", "boundary",
        "mutation_asset_index", "mutation_validation",
        "gold_results_attestation",
        "raw_manifest", "scored_manifest", "mutation_map", "legacy_map",
        "coverage_run", "gold_baseline", "gold_results", "candidate_run",
        "candidate_results", "engine_source", "seed", "worker_plan",
        "production_index", "audit_attestation", "alias_table",
        "autowirable_types",
    }
    optional_artifacts = {"scoring_gold", "annotated_release_items"}
    if not required_artifacts <= set(artifacts) \
            or set(artifacts) - required_artifacts - optional_artifacts:
        raise _refuse_manifest(
            f"{project} bundle artifact roles differ; missing="
            f"{sorted(required_artifacts - set(artifacts))}, unknown="
            f"{sorted(set(artifacts) - required_artifacts - optional_artifacts)}")
    # Preserved v1 mutation evidence is declared whole or not at all: a
    # project onboarded after Slice 1 nulls every one of its roles and names
    # the release pool its bundle ships instead (`data.bundle` reads both).
    legacy_null = {role for role in LEGACY_EVIDENCE_ROLES
                   if artifacts.get(role) is None}
    if legacy_null and legacy_null != set(LEGACY_EVIDENCE_ROLES):
        raise _refuse_manifest(
            f"{project} bundle declares legacy mutation evidence for some "
            f"roles and not others (null: {sorted(legacy_null)})")
    nullable = {"production_index", "audit_attestation", "alias_table",
                "autowirable_types", "annotated_release_items"}
    if legacy_null:
        nullable |= set(LEGACY_EVIDENCE_ROLES)
        if artifacts["audit_attestation"] is not None:
            raise _refuse_manifest(
                f"{project} bundle declares an audit attestation with no "
                "mutation evidence to attest")
    for role, path in artifacts.items():
        if path is None and role in nullable:
            continue
        if not isinstance(path, str) or not path or os.path.isabs(path) \
                or os.path.normpath(path).startswith(".."):
            raise _refuse_manifest(
                f"{project} bundle artifact {role} is not data-root-relative")
    if artifacts["coverage_run"] != artifacts["gold_baseline"]:
        raise _refuse_manifest(
            f"{project} bundle must not duplicate its coverage/gold baseline")
    pool_source = bundle.get("release_pool")
    if (pool_source is None) != (not legacy_null):
        raise _refuse_manifest(
            f"{project} bundle names a release pool exactly when it declares "
            "no legacy mutation evidence")
    release_pool = None
    if pool_source is not None:
        if not isinstance(pool_source, str) or not pool_source \
                or os.path.isabs(pool_source) \
                or os.path.normpath(pool_source).startswith(".."):
            raise _refuse_manifest(
                f"{project} bundle release pool is not release-root-relative")
        pool_path = os.path.join(release_dir, pool_source)
        if not _inside(release_dir, pool_path) \
                or not os.path.isfile(pool_path):
            raise _refuse_manifest(
                f"{project} bundle release pool {pool_source!r} is not a "
                "file inside the release root")
        release_pool = {"file": pool_source, "sha256": sha256_file(pool_path)}
    # The coverage oracle is not a release-tree file, so its digest is declared
    # (like the seed manifest's) rather than measured here; the bundle builder
    # and the installed-bundle validator check the file against it.
    coverage_sha = digest(bundle.get("coverage_run_sha256"),
                          "coverage_run_sha256", nullable=True)
    if (coverage_sha is None) != (not legacy_null):
        raise _refuse_manifest(
            f"{project} bundle declares its coverage oracle's SHA-256 exactly "
            "when it declares no legacy mutation evidence")

    # The source belongs to the release root, independently of the historical
    # pool's directory. The installed role is always a companion file; the
    # preserved evidence continues to bind release_items alone.
    annotated_source = bundle.get("annotated_release")
    annotated_role = artifacts.get("annotated_release_items")
    if (annotated_source is None) != (annotated_role is None):
        raise _refuse_manifest(
            f"{project} bundle annotated release source/role disagree")
    annotated_release = None
    if annotated_source is not None:
        expected = (f"projects/{project}/artifacts/release/"
                    "annotated_items.jsonl")
        if annotated_role != expected:
            raise _refuse_manifest(
                f"{project} annotated release needs its own {expected} role")
        if not isinstance(annotated_source, str) or not annotated_source \
                or os.path.isabs(annotated_source) \
                or os.path.normpath(annotated_source).startswith(".."):
            raise _refuse_manifest(
                f"{project} bundle annotated release source is not "
                "release-root-relative")
        annotated_path = os.path.join(release_dir, annotated_source)
        if not _inside(release_dir, annotated_path) \
                or not os.path.isfile(annotated_path):
            raise _refuse_manifest(
                f"{project} bundle annotated release source "
                f"{annotated_source!r} is not a file inside the release root")
        annotated_release = {"file": annotated_source,
                             "sha256": sha256_file(annotated_path)}

    worker_plan = bundle["worker_plan"]
    if not isinstance(worker_plan, dict) \
            or set(worker_plan) != {"k", "workdir", "container_kind"} \
            or not isinstance(worker_plan["k"], int) \
            or isinstance(worker_plan["k"], bool) \
            or worker_plan["k"] < 1 \
            or not all(isinstance(worker_plan[key], str) and worker_plan[key]
                       for key in ("workdir", "container_kind")):
        raise _refuse_manifest(f"{project} bundle worker plan is invalid")

    production_sha = digest(
        bundle["production_index_sha256"], "production_index_sha256",
        nullable=True)
    if (artifacts["production_index"] is None) != (production_sha is None):
        raise _refuse_manifest(
            f"{project} bundle production index path/digest disagree")
    scoring_gold = None
    if "scoring_gold" in artifacts or "scoring_gold_sha256" in bundle:
        expected = f"projects/{project}/artifacts/runs/gold_direct.jsonl"
        if artifacts.get("scoring_gold") != expected or production_sha is None:
            raise _refuse_manifest(
                f"{project} scoring gold needs its own {expected} role "
                "and a production method index")
        scoring_gold = {"sha256": digest(
            bundle.get("scoring_gold_sha256"), "scoring_gold_sha256")}

    block = {
        "version": version,
        "asset": {"name": asset_name, "sha256": asset_sha256},
        "artifacts": artifacts,
        "worker_plan": worker_plan,
        "seed": {"manifest_sha256": digest(
            bundle["seed_manifest_sha256"], "seed_manifest_sha256")},
        "production_index": (
            None if production_sha is None else {"sha256": production_sha}),
        "annotated_release": annotated_release,
    }
    std_arm = bundle.get("std_arm")
    if std_arm is not None:
        block["std_arm"] = _std_arm_block(project, std_arm, digest)
    if scoring_gold is not None:
        block["scoring_gold"] = scoring_gold
    if release_pool is not None:
        block["release_pool"] = release_pool
    if coverage_sha is not None:
        block["coverage_run"] = {"sha256": coverage_sha}
    return block


def _std_arm_block(project: str, std_arm: object, digest) -> dict:
    """Validate one published-arm declaration (roadmap D5).

    The declaration says which asset version first ships the arm and which
    ceremony's records the bundle joins its roles to.  It carries exactly two
    digests: the ceremony's shipping list, which enumerates every consumed
    input, and its report.  Every other digest the arm is checked against
    comes out of those documents, so a second ceremony changes two lines here
    and nothing else.
    """
    if not isinstance(std_arm, dict) \
            or set(std_arm) != {"asset_version", "ceremony"}:
        raise _refuse_manifest(
            f"{project} bundle std_arm fields differ; expected "
            "{asset_version, ceremony}, got "
            f"{sorted(std_arm) if isinstance(std_arm, dict) else std_arm!r}")
    version = std_arm["asset_version"]
    if not isinstance(version, str) or not version.startswith("v"):
        raise _refuse_manifest(
            f"{project} bundle std_arm asset version is invalid")
    ceremony = std_arm["ceremony"]
    fields = {"tag", "commit", "report", "report_sha256", "shipping_list",
              "shipping_list_sha256"}
    if not isinstance(ceremony, dict) or set(ceremony) != fields:
        raise _refuse_manifest(
            f"{project} bundle std_arm ceremony fields differ; missing="
            f"{sorted(fields - set(ceremony or ()))}, unknown="
            f"{sorted(set(ceremony or ()) - fields)}")
    if not isinstance(ceremony["tag"], str) or not ceremony["tag"]:
        raise _refuse_manifest(
            f"{project} bundle std_arm names no ceremony tag")
    commit = ceremony["commit"]
    if not isinstance(commit, str) or len(commit) != 40 \
            or any(character not in "0123456789abcdef" for character in commit):
        raise _refuse_manifest(
            f"{project} bundle std_arm ceremony commit is not a commit id")
    # Both documents are read from beside the shipping list at build time, so
    # a separator here would name a file outside the evidence directory.
    for key in ("report", "shipping_list"):
        if not isinstance(ceremony[key], str) or not ceremony[key] \
                or os.path.basename(ceremony[key]) != ceremony[key]:
            raise _refuse_manifest(
                f"{project} bundle std_arm {key} is not a plain file name")
    return {
        "asset_version": version,
        "ceremony": {
            "tag": ceremony["tag"], "commit": commit,
            "report": ceremony["report"],
            "report_sha256": digest(ceremony["report_sha256"],
                                    "std_arm report sha256"),
            "shipping_list": ceremony["shipping_list"],
            "shipping_list_sha256": digest(ceremony["shipping_list_sha256"],
                                           "std_arm shipping list sha256"),
        },
    }


def _declared_dirs(declared: dict) -> dict[str, str]:
    """`{normalised release-relative dir: project}`, refusing a shared dir."""
    dirs: dict[str, str] = {}
    for project in sorted(declared):
        rel = os.path.normpath(declared[project].get("dir") or ".")
        if rel in dirs:
            raise _refuse_manifest(
                f"{project} and {dirs[rel]} both declare directory {rel!r}. "
                f"Two projects sharing a directory have no separable subsets, "
                f"pools or gold, so nothing could be attributed to either.")
        dirs[rel] = project
    return dirs


def _assign_subsets(release_dir: str, declared: dict) -> dict[str, list[str]]:
    """Which project publishes which subset -- decided ONCE, for the release.

    Finding 5.  `subsets.subset_files` is a recursive walk, and a project whose
    directory is the release root (`dir: "."`, which CoreShop's is) therefore
    saw every nested project's subsets as its own: the published manifest filed
    python-docx's 32-item census under `projects.coreshop.subsets`, with zero
    id overlap with CoreShop's pool, and the mis-attribution was frozen into a
    pinned artifact.

    The rule here is the one a reader would assume: a subset belongs to the
    DEEPEST declared directory that contains it.  Enumerated once so no two
    projects can both claim a file, and refused rather than guessed when a
    subset sits under no declared project at all -- an unowned published subset
    is a number with no capability statement behind it.

    One narrowing, and it is the whole content of the fix: for a project whose
    directory IS the release root, containment is not a claim about anything --
    every path in the tree is contained in ".".  So the root project owns what
    sits DIRECTLY in the root, and a subset in some undeclared subdirectory is
    refused rather than falling to it by proximity.  Without that, the deepest
    match rule alone would still hand `release/anything/evalX.jsonl` to
    CoreShop, which is finding 5 one directory further down.
    """
    from ..data import subsets as SS

    annotated_subsets = {
        os.path.normpath(os.path.join(release_dir, path))
        for declaration in declared.values()
        for annotation in [annotated_release_declaration(declaration)]
        if annotation is not None
        for path in annotation["subsets"].values()
    }
    dirs = _declared_dirs(declared)
    # A declared annotation is the bundle's same-task companion, not a new
    # sampled subset. Exclude that exact source without handing its directory
    # (or any neighbouring pool/subset) to the historical project.
    annotated_sources = {
        os.path.normpath(os.path.join(release_dir, source))
        for declaration in declared.values()
        if isinstance(declaration.get("bundle"), dict)
        for source in [declaration["bundle"].get("annotated_release")]
        if isinstance(source, str)
    }
    out: dict[str, list[str]] = {project: [] for project in declared}
    for path in SS.subset_files(release_dir):
        if os.path.normpath(path) in annotated_sources:
            continue
        holder = os.path.normpath(os.path.relpath(os.path.dirname(path),
                                                  release_dir))
        if os.path.normpath(path) in annotated_subsets:
            continue
        owners = [(0 if d == "." else d.count(os.sep) + 1, d, project)
                  for d, project in dirs.items()
                  if holder == d
                  or (d != "." and holder.startswith(d + os.sep))]
        if not owners:
            raise _refuse_manifest(
                f"{os.path.relpath(path, release_dir)} is a published subset "
                f"in no declared project directory {sorted(dirs)}. A subset "
                f"nobody owns is a published number with no capability "
                f"statement, no pool and no gold behind it -- and attributing "
                f"it to the root project would be proximity, not membership.")
        owners.sort(reverse=True)
        if len(owners) > 1 and owners[0][0] == owners[1][0]:
            raise _refuse_manifest(
                f"{os.path.relpath(path, release_dir)} sits equally deep under "
                f"{owners[0][1]!r} and {owners[1][1]!r}; ownership must be "
                f"unique or the same subset is published twice.")
        out[owners[0][2]].append(path)
    return {project: sorted(paths) for project, paths in out.items()}


def build_dataset_manifest(release_dir: str, declarations: dict,
                           out_path: Optional[str] = None) -> dict:
    """Join what the release DECLARES with what its files MEASURE.

    D11.  The declared half — which capabilities a project supports, what was
    evaluated and left out, which caveats travel with the numbers — is
    committed prose that a human is answerable for; the measured half —
    counts, digests, cluster cardinality, provenance — is recomputed here
    from the bytes on disk every time.  Neither is trusted for the other's
    job, and the join refuses when they disagree:

    * a project directory holding a pool that nothing declares is REFUSED
      (it would ship with no capability statement at all, which a reader
      would fill in with whatever the other project's says);
    * a declaration whose files are absent is REFUSED;
    * capabilities are a closed list, a `false` one needs a reason, and a
      mutation claim must name an engine that exists.
    """
    declared = {d["project"]: d for d in declarations.get("projects", [])}
    if not declared:
        raise _refuse_manifest("no projects declared; an empty manifest "
                               "describes the release as if it were empty.")
    on_disk = _project_dirs(release_dir)
    primary_dirs = {os.path.normpath(d.get("dir") or ".")
                    for d in declared.values()}
    owned_dirs = set(primary_dirs)
    companion_pools = set()
    for declaration in declared.values():
        annotation = annotated_release_declaration(declaration)
        if annotation is not None:
            companion_pools.add(annotation["items"])
            owned_dirs.add(os.path.dirname(annotation["items"]) or ".")
    undeclared = sorted(set(on_disk) - owned_dirs)
    if undeclared:
        raise _refuse_manifest(
            f"{undeclared} under {release_dir} hold a released pool that no "
            f"declaration covers. Every shipped project states its "
            f"capabilities or none of them can be read.")

    from ..data.subsets import POOL_NAMES
    for directory in sorted(owned_dirs - primary_dirs):
        for name in POOL_NAMES:
            relative = os.path.normpath(os.path.join(directory, name))
            if os.path.isfile(os.path.join(release_dir, relative)) \
                    and relative not in companion_pools:
                raise _refuse_manifest(
                    f"{relative} is an undeclared pool beside an annotated "
                    "companion; its directory does not grant it ownership")

    assigned = _assign_subsets(release_dir, declared)

    projects = {}
    for project in sorted(declared):
        decl = declared[project]
        block = project_block(release_dir, decl, assigned[project])
        annotation = annotated_release_declaration(decl)
        if annotation is not None:
            block["annotated_release"] = annotation
            validate_annotated_release(release_dir, block)
        block["capabilities"] = _check_capabilities(project, decl)
        block["capability_notes"] = decl.get("capability_notes") or {}
        if decl.get("bundle") is not None:
            block["bundle"] = _bundle_block(release_dir, project, decl)
            if block["capabilities"]["mutation"] and any(
                    block["bundle"]["artifacts"][role] is None
                    for role in LEGACY_EVIDENCE_ROLES):
                raise _refuse_manifest(
                    f"{project} claims mutation scoring with no mutation "
                    "evidence in its bundle")
        if decl.get("mutation_engine"):
            block["mutation_engine"] = decl["mutation_engine"]
            block["mutation_engine_version"] = _known_engines()[
                decl["mutation_engine"]]
        for key in ("framework", "language", "harness_image", "corpus",
                    "notes"):
            if decl.get(key) is not None:
                block[key] = decl[key]
        projects[project] = block

    doc = {
        "schema": MANIFEST_SCHEMA,
        "dataset_version": declarations["dataset_version"],
        "changelog": declarations.get("changelog") or [],
        "projects": projects,
        # Last of the measured halves, and the one that makes the other three
        # unforgeable: every released byte, digested.  See INVENTORY_EXCLUDED
        # for the regeneration obligation this creates on operator steps.
        "release_inventory": release_inventory(release_dir),
        "evaluated_and_excluded": declarations.get("evaluated_and_excluded")
        or [],
        "caveats": declarations.get("caveats") or [],
    }
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(render_manifest(doc))
    return doc


def render_manifest(doc: dict) -> str:
    """The manifest's bytes, from the document.

    One function, so that what `--check` compares against the file on disk is
    literally what was written there -- and so a test can assert "this tamper
    fails `--check`" without re-deriving the serialisation and hoping it
    matches.
    """
    return json.dumps(doc, indent=1, sort_keys=True) + "\n"


def selftest() -> int:
    import copy
    import contextlib
    import io
    import shutil
    import tempfile
    from ..data.release import (BENCHMARK, DEFAULT_RELEASE, MANIFEST_NAME,
                                 ManifestRefused, _release_files,
                                 _write_gold_fixture)

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    # ---------------------------------------------------- the dataset manifest
    #
    # The join is the whole content: measured facts recomputed from the files,
    # declared facts a person is answerable for, and a refusal wherever the
    # two could silently disagree.
    with tempfile.TemporaryDirectory() as d:
        rel = os.path.join(d, "release")
        os.makedirs(rel, exist_ok=True)
        proj = os.path.join(rel, "second")
        os.makedirs(proj, exist_ok=True)

        def write_pool(directory, name, ids, prov=True):
            with open(os.path.join(directory, name), "w",
                      encoding="utf-8") as fh:
                for iid in ids:
                    row = {"item_id": iid}
                    if prov:
                        row["provenance"] = {
                            "repo_url": "https://example.invalid/r.git",
                            "commit": "c" * 40, "file_commit": "c" * 40,
                            "file_date": "2026-01-01T00:00:00+00:00",
                            "file_path": iid.split(":")[0], "line": 1}
                    fh.write(json.dumps(row, sort_keys=True) + "\n")

        write_pool(rel, "items_v1.jsonl", ["p/f/a.feature:1", "p/f/b.feature:1"])
        _write_gold_fixture(os.path.join(rel, "gold"),
                            {"p/f/a.feature:1": ["src/A.php"],
                             "p/f/b.feature:1": ["src/A.php"]})
        write_pool(proj, "items.jsonl", ["q/f/c.feature:1"])
        _write_gold_fixture(os.path.join(proj, "gold"),
                            {"q/f/c.feature:1": ["src/c.py"]})

        base = {"dataset_version": "9.9", "projects": [
            {"project": "one", "dir": ".", "items": "items_v1.jsonl",
             "mutation_engine": "r2t-mutate",
             "capabilities": {"mutation": True, "coverage": True,
                              "api_similarity": True}},
            {"project": "two", "dir": "second", "items": "items.jsonl",
             "mutation_engine": "r2t-mutate-py",
             "capabilities": {"mutation": True, "coverage": True,
                              "api_similarity": False},
             "capability_notes": {"api_similarity": "no python prod index"}},
        ]}
        doc = build_dataset_manifest(rel, base)
        check("the manifest measures each project's items and clusters from "
              "the files, not from the declaration",
              doc["projects"]["one"]["n_items"] == 2
              and doc["projects"]["one"]["effective_closure_cardinality"] == 1
              and doc["projects"]["two"]["n_items"] == 1,
              json.dumps({k: v["n_items"] for k, v in
                          doc["projects"].items()}))
        check("...and digests the pool it just described",
              doc["projects"]["two"]["digests"]["items"]
              == sha256_file(os.path.join(proj, "items.jsonl")))
        # The `release` verb's operator-named exclusions: a disposition file
        # is accepted when every key is an item of the pool and refused when
        # one names nothing, so an exclusion cannot silently miss its item.
        from .cli import _load_item_dispositions
        # A pool of two projects, the way the default `benchmark/items.jsonl`
        # is: the loader must scope its "every key names a pool item" rule to
        # the release's own project, because `build_release` skips the other
        # projects' items before it consults the mapping.
        pool_path = os.path.join(rel, "dispositions_pool.jsonl")
        with open(pool_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "one/f/a.feature:1",
                                 "project": "one"}) + "\n")
            fh.write(json.dumps({"item_id": "two/f/b.feature:1",
                                 "project": "two"}) + "\n")
        decisions = os.path.join(rel, "dispositions.json")

        def dispositions_refusal(document, project="one"):
            with open(decisions, "w", encoding="utf-8") as fh:
                fh.write(document if isinstance(document, str)
                         else json.dumps(document))
            try:
                _load_item_dispositions(decisions, pool_path, project)
                return None
            except SystemExit as exc:
                return str(exc)

        with open(decisions, "w", encoding="utf-8") as fh:
            json.dump({"one/f/a.feature:1": {
                "stage": "excluded", "reasons": ["employee_suite"]}}, fh)
        loaded = _load_item_dispositions(decisions, pool_path, "one")
        stray = dispositions_refusal({"one/f/zzz.feature:9": {
            "stage": "excluded", "reasons": ["typo"]}})
        foreign = dispositions_refusal({"two/f/b.feature:1": {
            "stage": "excluded", "reasons": ["x"]}})
        malformed = dispositions_refusal({"one/f/a.feature:1": {
            "stage": "excluded"}})
        unreadable = dispositions_refusal("{not json")
        check("release --item-dispositions accepts a file keyed by this "
              "project's pool items and refuses an unknown id, another "
              "project's id, a malformed entry and an unreadable file",
              loaded == {"one/f/a.feature:1": {
                  "stage": "excluded", "reasons": ["employee_suite"]}}
              and all(r is not None and r.startswith("REFUSED:")
                      for r in (stray, foreign, malformed, unreadable))
              and "one/f/zzz.feature:9" in stray
              and "two/f/b.feature:1" in foreign and "'one' item" in foreign
              and "malformed disposition" in malformed
              and "cannot read" in unreadable,
              str((stray, foreign, malformed, unreadable)))
        check("a project whose every item carries full provenance is verified, "
              "with the tree named",
              doc["projects"]["one"]["provenance_verified"] is True
              and doc["projects"]["one"]["provenance"]["commit"] == "c" * 40)

        def refused(fn) -> Optional[str]:
            try:
                fn()
                return None
            except ManifestRefused as exc:
                return str(exc)

        with tempfile.TemporaryDirectory() as annotation_tmp:
            annotated_root = os.path.join(annotation_tmp, "release")
            shutil.copytree(rel, annotated_root)
            write_pool(annotated_root, "eval100.jsonl", ["p/f/a.feature:1"])
            declaration = copy.deepcopy(base)
            bundle = declaration["projects"][0]["bundle"] = {
                "version": "v9", "asset": {
                    "name": "r2t-v9-one.tar.gz", "sha256": None},
                "seed_manifest_sha256": "a" * 64,
                "production_index_sha256": None,
                "worker_plan": {"k": 1, "workdir": "/work",
                                "container_kind": "php"},
                "artifacts": {
                    role: f"projects/one/{role}" for role in (
                        "release_items", "release_gold", "gold", "profile",
                        "boundary", "mutation_asset_index",
                        "mutation_validation", "gold_results_attestation",
                        "raw_manifest", "scored_manifest", "mutation_map",
                        "legacy_map", "coverage_run", "gold_baseline",
                        "gold_results", "candidate_run", "candidate_results",
                        "engine_source", "seed", "worker_plan",
                        "audit_attestation", "alias_table", "autowirable_types")},
            }
            bundle["artifacts"].update(
                production_index=None, coverage_run="projects/one/gold_baseline")
            absent = build_dataset_manifest(annotated_root, declaration)
            check("an absent annotation declaration emits null and no role",
                  absent["projects"]["one"]["bundle"]["annotated_release"]
                  is None and "annotated_release_items" not in
                  absent["projects"]["one"]["bundle"]["artifacts"])
            bundle["annotated_release"] = None
            bundle["artifacts"]["annotated_release_items"] = None
            unannotated = build_dataset_manifest(annotated_root, declaration)
            check("an explicit null annotation emits null source and role",
                  unannotated["projects"]["one"]["bundle"]["annotated_release"]
                  is None and unannotated["projects"]["one"]["bundle"]
                  ["artifacts"]["annotated_release_items"] is None)

            lean = copy.deepcopy(declaration)
            lean_bundle = lean["projects"][0]["bundle"]
            for role in LEGACY_EVIDENCE_ROLES:
                lean_bundle["artifacts"][role] = None
            lean_bundle["artifacts"]["audit_attestation"] = None
            check("a bundle with every legacy role null must name its "
                  "release pool",
                  "exactly when" in (refused(lambda: build_dataset_manifest(
                      annotated_root, lean)) or ""))
            lean_bundle["release_pool"] = "items_v1.jsonl"
            check("...and declare its coverage oracle's SHA-256",
                  "coverage oracle" in (refused(lambda: build_dataset_manifest(
                      annotated_root, lean)) or ""))
            lean_bundle["coverage_run_sha256"] = "b" * 64
            check("...and cannot claim mutation scoring with no evidence",
                  "no mutation evidence" in (refused(
                      lambda: build_dataset_manifest(annotated_root, lean))
                      or ""))
            lean["projects"][0]["capabilities"]["mutation"] = False
            lean["projects"][0].setdefault("capability_notes", {})["mutation"] = \
                "no preserved mutation evidence"
            rendered = build_dataset_manifest(
                annotated_root, lean)["projects"]["one"]["bundle"]
            check("a bundle without legacy evidence renders its null roles, "
                  "the measured release pool and the declared oracle digest, "
                  "and a legacy bundle renders neither key",
                  all(rendered["artifacts"][role] is None
                      for role in LEGACY_EVIDENCE_ROLES)
                  and rendered["artifacts"]["coverage_run"]
                  == "projects/one/gold_baseline"
                  and rendered["release_pool"] == {
                      "file": "items_v1.jsonl",
                      "sha256": sha256_file(os.path.join(
                          annotated_root, "items_v1.jsonl"))}
                  and rendered["coverage_run"] == {"sha256": "b" * 64}
                  and "release_pool" not in
                  unannotated["projects"]["one"]["bundle"]
                  and "coverage_run" not in
                  unannotated["projects"]["one"]["bundle"])
            partial = copy.deepcopy(lean)
            partial["projects"][0]["bundle"]["artifacts"]["scored_manifest"] = \
                "projects/one/scored_manifest"
            audited = copy.deepcopy(lean)
            audited["projects"][0]["bundle"]["artifacts"]["audit_attestation"] = \
                "projects/one/audit_attestation"
            pooled = copy.deepcopy(declaration)
            pooled["projects"][0]["bundle"]["release_pool"] = "items_v1.jsonl"
            pooled["projects"][0]["bundle"]["coverage_run_sha256"] = "b" * 64
            outcomes = {
                "partial": refused(
                    lambda: build_dataset_manifest(annotated_root, partial)),
                "audited": refused(
                    lambda: build_dataset_manifest(annotated_root, audited)),
                "pooled": refused(
                    lambda: build_dataset_manifest(annotated_root, pooled))}
            check("a partial legacy declaration, an attestation with nothing "
                  "to attest, and a pool beside legacy evidence are refused",
                  "some roles and not others" in (outcomes["partial"] or "")
                  and "no mutation evidence to attest" in (outcomes["audited"] or "")
                  and "exactly when" in (outcomes["pooled"] or ""),
                  str(outcomes))

            os.mkdir(os.path.join(annotated_root, "coreshop"))
            annotation = os.path.join(annotated_root, "coreshop", "eval100.jsonl")
            with open(annotation, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"item_id": "p/f/a.feature:1",
                                     "target_interfaces": {
                                         "behaviour": ["Example"], "setup": []}})
                         + "\n")
            bundle["annotated_release"] = "coreshop/eval100.jsonl"
            bundle["artifacts"]["annotated_release_items"] = \
                "projects/one/artifacts/release/annotated_items.jsonl"
            projected = build_dataset_manifest(annotated_root, declaration)
            projected_one = projected["projects"]["one"]
            check("an annotated source is measured beside the historical "
                  "pool, without changing historical subset ownership",
                  projected_one["bundle"]["annotated_release"] == {
                      "file": "coreshop/eval100.jsonl",
                      "sha256": sha256_file(annotation)}
                  and projected_one["items"] == "items_v1.jsonl"
                  and projected_one["subsets"] ==
                  unannotated["projects"]["one"]["subsets"]
                  and sorted(projected_one["subsets"]) == ["eval100"]
                  and all(projected_one["bundle"]["artifacts"][role] == path
                          for role, path in absent["projects"]["one"]
                          ["bundle"]["artifacts"].items()))
            for name, change in (
                    ("missing source", lambda b: b.pop("annotated_release")),
                    ("missing role", lambda b: b["artifacts"].pop(
                        "annotated_release_items")),
                    ("historical role alias", lambda b: b["artifacts"].update(
                        annotated_release_items=b["artifacts"]["release_items"])),
                    ("absent file", lambda b: b.update(
                        annotated_release="one/absent.jsonl")),
                    ("absolute source", lambda b: b.update(
                        annotated_release=annotation)),
                    ("source outside release", lambda b: b.update(
                        annotated_release="../outside.jsonl"))):
                bad = copy.deepcopy(declaration["projects"][0])
                change(bad["bundle"])
                check(f"an annotated-release declaration with {name} refuses",
                      refused(lambda: _bundle_block(
                          annotated_root, "one", bad)) is not None)
            write_pool(os.path.dirname(annotation), "evalother.jsonl",
                       ["p/f/a.feature:1"])
            msg = refused(lambda: build_dataset_manifest(
                annotated_root, declaration))
            check("an annotated source does not grant ownership of "
                  "neighbouring subsets",
                  msg is not None and "in no declared project" in msg, str(msg))

        declared_and_shipped = json.loads(json.dumps(base))
        for entry in declared_and_shipped["projects"]:
            measured = doc["projects"][entry["project"]]
            entry["release_gold_identity"] = {
                field: measured[field] for field in GOLD_IDENTITY_FIELDS}
        check("matching declared and on-disk gold identities are accepted",
              build_dataset_manifest(rel, declared_and_shipped)["projects"]
              ["one"]["gold_manifest_sha256"]
              == doc["projects"]["one"]["gold_manifest_sha256"])
        disagreeing = json.loads(json.dumps(declared_and_shipped))
        disagreeing["projects"][0]["release_gold_identity"] \
            ["gold_manifest_sha256"] = "0" * 64
        msg = refused(lambda: build_dataset_manifest(rel, disagreeing))
        check("a declared gold identity that disagrees with gold on disk "
              "refuses",
              msg is not None and "declared release_gold_identity" in msg
              and "on-disk gold" in msg, str(msg))

        third = os.path.join(rel, "third")
        os.makedirs(third, exist_ok=True)
        write_pool(third, "items.jsonl", ["r/f/d.feature:1"])
        msg = refused(lambda: build_dataset_manifest(rel, base))
        check("a shipped project nothing declares is refused, not skipped",
              msg is not None and "third" in msg, str(msg))
        import shutil as _sh
        _sh.rmtree(third)

        # Annotated companions own exact new files, while every primary fact
        # remains about the frozen pool and its original sampled subset.
        from ..data import subsets as SS
        annotated_root = os.path.join(d, "annotated")
        _sh.copytree(rel, annotated_root)
        sampled = SS.sample(os.path.join(annotated_root, "items_v1.jsonl"),
                            annotated_root, n=1, seed=7)
        with open(os.path.join(annotated_root, "eval100.jsonl"), "w") as fh:
            fh.writelines(sampled["lines"])
        with open(os.path.join(annotated_root, "eval100.provenance.json"), "w") as fh:
            json.dump(sampled["provenance"], fh)
        frozen = build_dataset_manifest(annotated_root, base)
        frozen_bytes = {name: open(os.path.join(annotated_root, name), "rb").read()
                        for name in ("items_v1.jsonl", "eval100.jsonl",
                                     "eval100.provenance.json")}
        os.makedirs(os.path.join(annotated_root, "coreshop"))
        annotation = {"items": "coreshop/items.jsonl", "subsets": {
            "eval100": "coreshop/eval100.jsonl"}}
        annotated_decl = json.loads(json.dumps(base))
        annotated_decl["projects"][0]["annotated_release"] = annotation
        annotated_rows = {}
        for original, target in (("items_v1.jsonl", annotation["items"]),
                                 ("eval100.jsonl", annotation["subsets"]["eval100"])):
            rows = [dict(row, target_interfaces={"behaviour": ["Example.Reader"],
                                                "setup": []})
                    for row in _load_jsonl(os.path.join(annotated_root, original))]
            annotated_rows[target] = rows
            with open(os.path.join(annotated_root, target), "w") as fh:
                for row in rows:
                    fh.write(json.dumps(row) + "\n")
        annotated_manifest = build_dataset_manifest(annotated_root, annotated_decl)
        annotated_block = dict(annotated_manifest["projects"]["one"])
        emitted = annotated_block.pop("annotated_release")
        check("annotated layout preserves all frozen counts, gold and subset facts",
              annotated_block == frozen["projects"]["one"]
              and annotated_manifest["projects"]["two"] == frozen["projects"]["two"]
              and emitted == annotation)
        check("the existing release inventory covers both companions and unchanged originals",
              all(name in annotated_manifest["release_inventory"]["files"]
                  for name in (annotation["items"], annotation["subsets"]["eval100"]))
              and all(open(os.path.join(annotated_root, name), "rb").read() == raw
                      for name, raw in frozen_bytes.items()))
        build_dataset_manifest(annotated_root, annotated_decl,
                               out_path=os.path.join(annotated_root, MANIFEST_NAME))
        problems = SS.verify_release_subsets(annotated_root)
        check("the generated annotated layout passes the ordinary release-subset gate",
              problems == [], str(problems))
        dotted = json.loads(json.dumps(annotated_decl))
        dotted["projects"][0]["annotated_release"] = {
            "items": "./coreshop/items.jsonl", "subsets": {
                "eval100": "./coreshop/eval100.jsonl"}}
        normalized = build_dataset_manifest(annotated_root, dotted,
            out_path=os.path.join(annotated_root, MANIFEST_NAME))
        check("relative-dot declarations emit the same paths and readable subset identity",
              normalized == annotated_manifest
              and SS.verify_release_subsets(annotated_root) == []
              and SS.identify_for_inference(os.path.join(
                  annotated_root, "coreshop/eval100.jsonl"))["subset_id"] == "eval100")
        extra_pool = os.path.join(annotated_root, "coreshop", "items_v1.jsonl")
        _sh.copyfile(os.path.join(annotated_root, "items_v1.jsonl"), extra_pool)
        msg = refused(lambda: build_dataset_manifest(annotated_root, annotated_decl))
        check("the default release filename is not silently admitted beside a companion",
              msg is not None and "coreshop/items_v1.jsonl is an undeclared pool" in msg)
        os.unlink(extra_pool)
        msg = refused(lambda: build_dataset_manifest(annotated_root, base))
        check("an undeclared companion pool still refuses", msg is not None and "coreshop" in msg)
        neighbour = os.path.join(annotated_root, "coreshop", "evalother.jsonl")
        _sh.copyfile(os.path.join(annotated_root, "eval100.jsonl"), neighbour)
        msg = refused(lambda: build_dataset_manifest(annotated_root, annotated_decl))
        check("a companion declaration grants no neighbouring subset ownership",
              msg is not None and "in no declared project" in msg)
        os.unlink(neighbour)

        pool_path = os.path.join(annotated_root, annotation["items"])
        good_rows = annotated_rows[annotation["items"]]
        for label, rows, reason in (
                ("changed task", [dict(good_rows[0], task="different"), good_rows[1]], "tasks"),
                ("changed order", list(reversed(good_rows)), "order"),
                ("changed count", good_rows[:1], "count"),
                ("missing annotations", _load_jsonl(os.path.join(annotated_root, "items_v1.jsonl")),
                 "target_interfaces"),
                ("malformed annotations", [dict(good_rows[0], target_interfaces=[]), good_rows[1]],
                 "mapping")):
            with open(pool_path, "w") as fh:
                for row in rows:
                    fh.write(json.dumps(row) + "\n")
            msg = refused(lambda: build_dataset_manifest(annotated_root, annotated_decl))
            check(f"annotated layout refuses {label}", msg is not None and reason in msg, str(msg))
        with open(pool_path, "w") as fh:
            for row in good_rows:
                fh.write(json.dumps(row) + "\n")

        # THE V2 ANNOTATION (TARGET_INTERFACES_V2_SPEC section 5).  The same
        # companion route carries `checked_interfaces`, and the v2 renderer is
        # what admits or refuses it -- the identical function the prompt uses,
        # so a companion the release admits is one a prompt can render.
        def write_companions(rows_by_target):
            for target, target_rows in rows_by_target.items():
                with open(os.path.join(annotated_root, target), "w") as fh:
                    for row in target_rows:
                        fh.write(json.dumps(row) + "\n")

        def with_v2(field):
            return {target: [dict(row, checked_interfaces=field)
                             for row in target_rows]
                    for target, target_rows in annotated_rows.items()}

        write_companions(with_v2({
            "checked": [{"key": ["Example\\Reader", "read"],
                         "declaration": "public function read(string $p): string;"}],
            "empty_reason": None}))
        check("an annotated layout carrying the v2 field beside the v1 lists "
              "builds",
              refused(lambda: build_dataset_manifest(
                  annotated_root, annotated_decl)) is None)
        write_companions(with_v2({"checked": [], "empty_reason": None}))
        msg = refused(lambda: build_dataset_manifest(annotated_root, annotated_decl))
        check("...and an empty v2 list with no reason is refused there too",
              msg is not None and "never an omission" in msg, str(msg))
        write_companions(annotated_rows)

        bad_block = dict(annotated_manifest["projects"]["one"], annotated_release={
            "items": "items_v1.jsonl", "subsets": {}})
        msg = refused(lambda: validate_annotated_release(annotated_root, bad_block))
        check("annotation cannot replace the frozen primary file",
              msg is not None and "cannot replace" in msg)
        bad_block["annotated_release"] = {"items": annotation["items"], "subsets": {
            "unknown": "coreshop/unknown.jsonl"}}
        msg = refused(lambda: validate_annotated_release(annotated_root, bad_block))
        check("annotation cannot invent a sampled subset",
              msg is not None and "no frozen project subset" in msg)
        bad_block["annotated_release"]["subsets"] = {"eval100": "coreshop/renamed.jsonl"}
        msg = refused(lambda: validate_annotated_release(annotated_root, bad_block))
        check("annotated subsets retain the name used by population resolution",
              msg is not None and "retain its frozen subset name" in msg)
        subset_path = os.path.join(annotated_root, annotation["subsets"]["eval100"])
        with open(subset_path, "w") as fh:
            fh.write(json.dumps(dict(annotated_rows[annotation["subsets"]["eval100"]][0],
                target_interfaces={"behaviour": ["Other.Reader"], "setup": []})) + "\n")
        msg = refused(lambda: build_dataset_manifest(annotated_root, annotated_decl))
        check("the subset annotation must agree with its annotated full pool",
              msg is not None and "differs from its annotated pool" in msg)

        relocated = os.path.join(d, "relocated")
        _sh.copytree(rel, relocated)
        relocated_decl = json.loads(json.dumps(base))
        for entry in relocated_decl["projects"]:
            name = entry["project"]
            directory = os.path.join(relocated, entry.get("dir") or ".")
            clusters = closure_clusters(directory)
            with open(os.path.join(directory, CLOSURE_MAP_NAME), "w",
                      encoding="utf-8") as fh:
                json.dump(clusters, fh, indent=1, sort_keys=True)
                fh.write("\n")
            entry["release_gold_identity"] = {
                field: doc["projects"][name][field]
                for field in GOLD_IDENTITY_FIELDS}
            _sh.rmtree(os.path.join(directory, "gold"))
        relocated_doc = build_dataset_manifest(relocated, relocated_decl)
        check("a release without checked-in gold retains the collected gold "
              "identity and derives cluster statistics from its public maps",
              all(relocated_doc["projects"][name]["n_gold_sidecars"]
                  == doc["projects"][name]["n_gold_sidecars"]
                  for name in ("one", "two"))
              and relocated_doc["projects"]["one"]
              ["effective_closure_cardinality"] == 1
              and "gold_manifest" not in relocated_doc["projects"]["one"]
              ["digests"])
        bad_identity = json.loads(json.dumps(relocated_decl))
        bad_identity["projects"][0]["release_gold_identity"]["unknown"] = True
        msg = refused(lambda: build_dataset_manifest(relocated, bad_identity))
        check("a relocated gold declaration is closed rather than ignoring "
              "unknown identity fields",
              msg is not None and "unknown" in msg, str(msg))
        map_path = os.path.join(relocated, CLOSURE_MAP_NAME)
        with open(map_path, encoding="utf-8") as fh:
            incomplete_map = json.load(fh)
        incomplete_map.pop("p/f/a.feature:1")
        with open(map_path, "w", encoding="utf-8") as fh:
            json.dump(incomplete_map, fh, indent=1, sort_keys=True)
            fh.write("\n")
        msg = refused(lambda: build_dataset_manifest(relocated, relocated_decl))
        check("a public closure map whose membership differs from the pool "
              "refuses",
              msg is not None and "membership" in msg, str(msg))

        def one_changed(**over) -> dict:
            """The same two-project declaration with ONE field moved.

            Both projects stay declared: the undeclared-project refusal fires
            before any per-project check, so a fixture that dropped the second
            entry would prove that refusal four more times instead of the
            four it is meant to prove.
            """
            return {"dataset_version": "9.9",
                    "projects": [dict(base["projects"][0], **over),
                                 base["projects"][1]]}

        msg = refused(lambda: build_dataset_manifest(
            rel, one_changed(capabilities={"mutation": True})))
        check("a capability list that is not the closed three is refused",
              msg is not None and "exactly" in msg, str(msg))
        msg = refused(lambda: build_dataset_manifest(
            rel, one_changed(capabilities={"mutation": True, "coverage": True,
                                           "api_similarity": False})))
        check("a `false` capability with no reason is refused -- a bare false "
              "cannot say whether it is a gap or a decision",
              msg is not None and "no note saying why" in msg, str(msg))
        msg = refused(lambda: build_dataset_manifest(
            rel, one_changed(mutation_engine="r2t-mutate-rust")))
        check("a mutation claim naming an engine nothing implements is refused",
              msg is not None and "does not have" in msg, str(msg))
        msg = refused(lambda: build_dataset_manifest(
            rel, one_changed(items="absent.jsonl")))
        check("a declaration whose pool is not on disk is refused",
              msg is not None and "not there" in msg, str(msg))

        # #284.  A pool complete in every other way, sitting outside the
        # release root.  Nothing under the root changes, so neither the
        # undeclared-directory check nor the inventory has anything to see.
        outside = os.path.join(d, "outside_pool")
        os.makedirs(outside, exist_ok=True)
        write_pool(outside, "items.jsonl", ["s/f/e.feature:1"])
        _write_gold_fixture(os.path.join(outside, "gold"),
                            {"s/f/e.feature:1": ["src/e.py"]})

        def escaping(rel_dir: str) -> dict:
            """`base` plus a third project pointed out of the release root."""
            return {"dataset_version": "9.9", "projects": [
                *base["projects"],
                {"project": "three", "dir": rel_dir, "items": "items.jsonl",
                 "mutation_engine": "r2t-mutate-py",
                 "capabilities": {"mutation": True, "coverage": True,
                                  "api_similarity": False},
                 "capability_notes": {"api_similarity": "no python prod "
                                                        "index"}}]}

        msg = refused(lambda: build_dataset_manifest(rel, escaping(outside)))
        check("an absolute declared directory is refused rather than "
              "discarding the release root that `join` drops",
              msg is not None and "absolute directory" in msg, str(msg))
        msg = refused(lambda: build_dataset_manifest(
            rel, escaping(os.path.join(rel, "second"))))
        check("...and an absolute directory that lands INSIDE the root is "
              "refused too -- containment would accept it, and `second` would "
              "then be published twice under two names",
              msg is not None and "absolute directory" in msg, str(msg))
        msg = refused(lambda: build_dataset_manifest(
            rel, escaping(os.path.relpath(outside, rel))))
        check("a declared directory that climbs out of the release root is "
              "refused -- its bytes are in no inventory",
              msg is not None and "outside the release root" in msg, str(msg))

        # `items` is joined onto the project directory the same way, so an
        # in-root `dir` with an escaping `items` escaped through the field the
        # first fix does not touch -- and less visibly, because the directory's
        # real pool IS inventoried, just not the one the block describes.
        write_pool(d, "escaped_items.jsonl",
                   ["p/f/a.feature:1", "p/f/b.feature:1"])
        msg = refused(lambda: build_dataset_manifest(
            rel, one_changed(items="../escaped_items.jsonl")))
        check("a declared pool outside its own project directory is refused, "
              "even where the directory itself is in the root",
              msg is not None and "outside its own directory" in msg, str(msg))

        # Provenance is CHECKED. Two of the five corpora extracted for this
        # benchmark carried provenance pointing at a wrapper repository, and
        # it read exactly like the real thing.
        write_pool(proj, "items.jsonl", ["q/f/c.feature:1"], prov=False)
        doc = build_dataset_manifest(rel, base)
        check("an item with no provenance makes the project unverified, and "
              "the missing fields are named",
              doc["projects"]["two"]["provenance_verified"] is False
              and doc["projects"]["two"]["provenance"]["items_missing_fields"],
              json.dumps(doc["projects"]["two"]["provenance"]))

    # ------------------------------------------------------ RELEASE INTEGRITY
    #
    # RI1-RI6, the adversarial scenarios of the Slice 1 remediation plan §5.
    # Each name is cited by the requirement-disposition table, so the names are
    # part of the interface: reproduce any of them with
    #
    #     PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=benchmark python3 -m r2t.toolkit.release_build
    #
    # and grep for the tag.  What they are FOR: the review demonstrated that a
    # fabricated gold sidecar, a rewritten published results document and a
    # CR-stripped digest-pinned CSV all left every gate in this repository
    # green.  These are the tests that fail on each of those.
    import shutil as _shutil

    def _ri_fixture(root: str) -> tuple[str, dict]:
        """A two-project release: pools, gold, subsets, a written CSV.

        Shaped like the real one in the way that matters -- the first project's
        directory IS the release root, and the second is nested inside it,
        which is the geometry that mis-attributed the docx census.
        """
        rel = os.path.join(root, "release")
        second = os.path.join(rel, "second")
        os.makedirs(second)

        def pool(directory, name, rows):
            with open(os.path.join(directory, name), "w",
                      encoding="utf-8") as fh:
                for iid, files, contexts in rows:
                    fh.write(json.dumps({
                        "item_id": iid,
                        "provenance": {
                            "repo_url": "https://example.invalid/r.git",
                            "commit": "c" * 40, "file_commit": "c" * 40,
                            "file_date": "2026-01-01T00:00:00+00:00",
                            "file_path": iid.split(":")[0], "line": 1},
                        "bench_meta": {"n_closure_files": len(files),
                                       "n_closure_contexts": len(contexts)},
                    }, sort_keys=True) + "\n")

        def gold(directory, rows):
            os.makedirs(os.path.join(directory, "gold"), exist_ok=True)
            manifest = {}
            for iid, files, contexts in rows:
                name = hashlib.sha1(iid.encode()).hexdigest()[:16] + ".json"
                with open(os.path.join(directory, "gold", name), "w",
                          encoding="utf-8") as fh:
                    json.dump({"item_id": iid, "files": files,
                               "context_classes": contexts}, fh, indent=1,
                              sort_keys=True)
                manifest[iid] = name
            with open(os.path.join(directory, "gold", "manifest.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(manifest, fh, indent=1, sort_keys=True)

        def subset(path, iids):
            with open(path, "w", encoding="utf-8") as fh:
                for iid in iids:
                    fh.write(json.dumps({"item_id": iid}, sort_keys=True) + "\n")

        # Two items sharing one closure file-set, so a tamper inside the
        # cluster is the RI3 scenario, plus a third in its own.
        first_rows = [("p/f/a.feature:1", ["src/A.php", "src/B.php"], ["Ctx"]),
                      ("p/f/b.feature:1", ["src/B.php", "src/A.php"], ["Ctx"]),
                      ("p/f/c.feature:1", ["src/C.php"], ["Ctx", "Ctx2"])]
        second_rows = [("q/f/d.feature:1", ["src/d.py"], ["DCtx"])]
        pool(rel, "items_v1.jsonl", first_rows)
        gold(rel, first_rows)
        subset(os.path.join(rel, "evalfirst.jsonl"), ["p/f/a.feature:1"])
        pool(second, "items.jsonl", second_rows)
        gold(second, second_rows)
        subset(os.path.join(second, "evalsecond.jsonl"), ["q/f/d.feature:1"])
        write_csv(os.path.join(rel, "exclusions.csv"), EXCLUSIONS_HEADER,
                  [["p/f/z.feature:1", "no_oracle", 0, None]])
        declarations = {"dataset_version": "9.9", "projects": [
            {"project": "first", "dir": ".", "items": "items_v1.jsonl",
             "mutation_engine": "r2t-mutate",
             "capabilities": {"mutation": True, "coverage": True,
                              "api_similarity": True}},
            {"project": "second", "dir": "second", "items": "items.jsonl",
             "mutation_engine": "r2t-mutate-py",
             "capabilities": {"mutation": True, "coverage": True,
                              "api_similarity": True}},
        ]}
        return rel, declarations

    with tempfile.TemporaryDirectory() as d:
        pristine = os.path.join(d, "pristine")
        os.makedirs(pristine)
        rel, decl = _ri_fixture(pristine)
        base_doc = build_dataset_manifest(rel, decl)
        base_render = render_manifest(base_doc)

        n = [0]

        def variant() -> str:
            """A private copy of the pristine fixture; returns its release dir."""
            n[0] += 1
            root = os.path.join(d, f"v{n[0]}")
            _shutil.copytree(pristine, root)
            return os.path.join(root, "release")

        def rebuilt(release_dir: str) -> Optional[str]:
            """The rendered manifest, or None if the build refused."""
            try:
                return render_manifest(
                    build_dataset_manifest(release_dir, decl))
            except ManifestRefused:
                return None

        def refusal(release_dir: str) -> Optional[str]:
            try:
                build_dataset_manifest(release_dir, decl)
                return None
            except ManifestRefused as exc:
                return str(exc)

        # -- RI1 -------------------------------------------------------------
        # The producer's own writing path, on fixture data.  `build_release`
        # itself needs extraction artifacts this selftest has no honest way to
        # fabricate, so RI1 exercises `write_csv` -- which IS the code
        # `build_release` writes every released CSV through -- and then proves
        # the released bytes are what that code produces (second leg, below).
        csv_a = os.path.join(d, "ri1_a.csv")
        csv_b = os.path.join(d, "ri1_b.csv")
        rows = [["p/f/x.feature:1", "no_oracle;commented_out", 3, 7],
                ["p/f/y.feature:2", "thin_scenario_lt_3_effective_steps",
                 0, None]]
        write_csv(csv_a, EXCLUSIONS_HEADER, rows)
        write_csv(csv_b, EXCLUSIONS_HEADER, rows)
        raw_a = open(csv_a, "rb").read()
        check("RI1: rebuilding an exclusions CSV is byte-stable",
              raw_a == open(csv_b, "rb").read()
              and sha256_file(csv_a) == sha256_file(csv_b))
        check("RI1: every released CSV row ends CRLF, by explicit terminator",
              raw_a.endswith(b"\r\n")
              and raw_a.count(b"\r\n") == len(rows) + 1
              and b"\n" not in raw_a.replace(b"\r\n", b""),
              repr(raw_a[:60]))

        # -- RI2 / RI3 / RI4 / RI5 / RI6 on the fixture ----------------------
        tampered = variant()
        with open(os.path.join(tampered, "exclusions.csv"), "r+b") as fh:
            fh.seek(0)
            first = fh.read(1)
            fh.seek(0)
            fh.write(b"I" if first != b"I" else b"J")
        check("RI2: a one-byte edit to a released CSV fails the manifest check",
              rebuilt(tampered) != base_render)
        check("RI2: ...and the failure names the file, in the inventory",
              build_dataset_manifest(tampered, decl)["release_inventory"]
              ["files"]["exclusions.csv"]
              != base_doc["release_inventory"]["files"]["exclusions.csv"])

        same_cluster = variant()
        sidecar = os.path.join(
            same_cluster, "gold",
            hashlib.sha1(b"p/f/a.feature:1").hexdigest()[:16] + ".json")
        with open(sidecar, encoding="utf-8") as fh:
            doc_a = json.load(fh)
        doc_a["files"] = list(reversed(doc_a["files"]))
        with open(sidecar, "w", encoding="utf-8") as fh:
            json.dump(doc_a, fh, indent=1, sort_keys=True)
        edited = build_dataset_manifest(same_cluster, decl)
        NEW = ("n_gold_sidecars", "gold_sidecars_sha256", "gold_manifest_sha256")
        old_block = {k: v for k, v in base_doc["projects"]["first"].items()
                     if k not in NEW}
        new_block = {k: v for k, v in edited["projects"]["first"].items()
                     if k not in NEW}
        check("RI3: a same-cluster gold-sidecar edit is invisible to every "
              "statistic schema 1 published",
              old_block == new_block)
        check("RI3: ...and moves the aggregate sidecar digest",
              edited["projects"]["first"]["gold_sidecars_sha256"]
              != base_doc["projects"]["first"]["gold_sidecars_sha256"]
              and edited["projects"]["first"]["gold_manifest_sha256"]
              == base_doc["projects"]["first"]["gold_manifest_sha256"])

        mismatch = variant()
        sidecar = os.path.join(
            mismatch, "gold",
            hashlib.sha1(b"p/f/c.feature:1").hexdigest()[:16] + ".json")
        with open(sidecar, encoding="utf-8") as fh:
            doc_c = json.load(fh)
        doc_c["item_id"] = "p/f/somebody_else.feature:9"
        with open(sidecar, "w", encoding="utf-8") as fh:
            json.dump(doc_c, fh, indent=1, sort_keys=True)
        msg = refusal(mismatch)
        check("RI4: a sidecar filed under one item and naming another refuses",
              msg is not None and "calls itself" in msg, str(msg))

        lengths = variant()
        sidecar = os.path.join(
            lengths, "gold",
            hashlib.sha1(b"p/f/c.feature:1").hexdigest()[:16] + ".json")
        with open(sidecar, encoding="utf-8") as fh:
            doc_c = json.load(fh)
        doc_c["files"] = doc_c["files"] + ["src/EXTRA.php"]
        with open(sidecar, "w", encoding="utf-8") as fh:
            json.dump(doc_c, fh, indent=1, sort_keys=True)
        msg = refusal(lengths)
        check("RI4: a closure-length disagreement between the pinned pool and "
              "the answer key refuses",
              msg is not None and "n_closure_files" in msg
              and "disagree about the shape" in msg, str(msg))

        # The SECOND array item 7 cross-checks.  Written as its own leg because
        # one leg per compared field is the only shape that fails when a field
        # is dropped from the comparison: with only the `files` leg, deleting
        # the ("n_closure_contexts", "context_classes") tuple from
        # `_gold_binding` left this suite entirely green.
        contexts = variant()
        sidecar = os.path.join(
            contexts, "gold",
            hashlib.sha1(b"p/f/c.feature:1").hexdigest()[:16] + ".json")
        with open(sidecar, encoding="utf-8") as fh:
            doc_c = json.load(fh)
        doc_c["context_classes"] = doc_c["context_classes"][:-1]
        with open(sidecar, "w", encoding="utf-8") as fh:
            json.dump(doc_c, fh, indent=1, sort_keys=True)
        msg = refusal(contexts)
        check("RI4: a context-class disagreement between the pinned pool and "
              "the answer key refuses",
              msg is not None and "n_closure_contexts" in msg
              and "disagree about the shape" in msg, str(msg))

        missing = variant()
        os.remove(os.path.join(
            missing, "gold",
            hashlib.sha1(b"p/f/c.feature:1").hexdigest()[:16] + ".json"))
        msg = refusal(missing)
        check("RI4: a gold manifest naming a sidecar that is not on disk "
              "refuses",
              msg is not None and "not on disk" in msg, str(msg))

        unshipped = variant()
        gold_manifest_path = os.path.join(unshipped, "gold", "manifest.json")
        with open(gold_manifest_path, encoding="utf-8") as fh:
            gm = json.load(fh)
        gm.pop("p/f/c.feature:1")
        with open(gold_manifest_path, "w", encoding="utf-8") as fh:
            json.dump(gm, fh, indent=1, sort_keys=True)
        msg = refusal(unshipped)
        check("RI4: a sidecar the gold manifest does not name refuses "
              "(no unaccounted answer key)",
              msg is not None and "does not name" in msg, str(msg))

        orphan_item = variant()
        with open(os.path.join(orphan_item, "items_v1.jsonl"),
                  encoding="utf-8") as fh:
            kept = [ln for ln in fh if "p/f/c.feature:1" not in ln]
        with open(os.path.join(orphan_item, "items_v1.jsonl"), "w",
                  encoding="utf-8") as fh:
            fh.writelines(kept)
        msg = refusal(orphan_item)
        check("RI4: a gold entry for an item the pool does not ship refuses",
              msg is not None and "the pool does not ship" in msg, str(msg))

        no_sidecar = variant()
        gold_manifest_path = os.path.join(no_sidecar, "gold", "manifest.json")
        with open(gold_manifest_path, encoding="utf-8") as fh:
            gm = json.load(fh)
        name = gm.pop("p/f/c.feature:1")
        with open(gold_manifest_path, "w", encoding="utf-8") as fh:
            json.dump(gm, fh, indent=1, sort_keys=True)
        os.remove(os.path.join(no_sidecar, "gold", name))
        msg = refusal(no_sidecar)
        check("RI4: a released item with no gold sidecar at all refuses",
              msg is not None and "have no gold sidecar" in msg, str(msg))

        linked = variant()
        os.symlink(os.path.join(linked, "items_v1.jsonl"),
                   os.path.join(linked, "items_link.jsonl"))
        msg = refusal(linked)
        check("RI4: a file symlink in the release tree refuses rather than "
              "being digested through",
              msg is not None and "symbolic link" in msg, str(msg))

        # A DIRECTORY symlink is the dangerous half and needs its own leg:
        # `os.walk` does not follow it, so with the dirnames guard removed a
        # planted directory link is not digested, not refused, and `--check`
        # exits 0 over a release with a mounted-in subtree nobody pinned.
        linked_dir = variant()
        os.symlink(os.path.join(linked_dir, "gold"),
                   os.path.join(linked_dir, "gold_mirror"))
        msg = refusal(linked_dir)
        check("RI4: a directory symlink in the release tree refuses, which "
              "os.walk alone would have stepped straight over",
              msg is not None and "symbolic link to a directory" in msg,
              str(msg))

        # Not a directory, not a regular file.  Run in a thread with a join
        # deadline, because THE FAILURE MODE THIS GUARD PREVENTS IS A HANG:
        # without it `sha256_file` opens the fifo and blocks for want of a
        # writer, so a suite that called it directly would stall instead of
        # reporting.  The deadline turns that into an ordinary [FAIL].
        if hasattr(os, "mkfifo"):
            import threading

            fifo = variant()
            os.mkfifo(os.path.join(fifo, "published_pipe"))
            outcome: list = []
            worker = threading.Thread(target=lambda: outcome.append(
                refusal(fifo)), daemon=True)
            worker.start()
            worker.join(30)
            check("RI4: a released path that is not a regular file refuses",
                  not worker.is_alive() and outcome
                  and outcome[0] is not None
                  and "not a regular file" in outcome[0],
                  "digesting the fifo blocked" if worker.is_alive()
                  else str(outcome))

        added = variant()
        with open(os.path.join(added, "extra_results.json"), "w",
                  encoding="utf-8") as fh:
            fh.write('{"n_passed": 25}\n')
        check("RI4: an arbitrary new release file changes the manifest, so "
              "--check refuses it",
              rebuilt(added) != base_render
              and "extra_results.json"
              in build_dataset_manifest(added, decl)["release_inventory"]["files"])

        removed = variant()
        os.remove(os.path.join(removed, "exclusions.csv"))
        check("RI4: removing a released file changes the manifest, so --check "
              "refuses it", rebuilt(removed) != base_render)

        renamed = variant()
        os.rename(os.path.join(renamed, "exclusions.csv"),
                  os.path.join(renamed, "exclusions_old.csv"))
        renamed_doc = build_dataset_manifest(renamed, decl)
        check("RI4: renaming a released file changes the manifest even though "
              "its bytes did not move",
              rebuilt(renamed) != base_render
              and renamed_doc["release_inventory"]["files"]
              .get("exclusions_old.csv")
              == base_doc["release_inventory"]["files"]["exclusions.csv"])

        # -- RI5 -------------------------------------------------------------
        nested = variant()
        with open(os.path.join(nested, "second", MANIFEST_NAME), "w",
                  encoding="utf-8") as fh:
            fh.write("{}\n")
        nested_doc = build_dataset_manifest(nested, decl)
        on_disk_files = set()
        for dirpath, _dirs, names in os.walk(nested):
            for nm in names:
                on_disk_files.add(os.path.relpath(os.path.join(dirpath, nm),
                                                  nested))
        check("RI5: the inventory covers every file on disk except the "
              "manifest itself",
              set(nested_doc["release_inventory"]["files"]) | {MANIFEST_NAME}
              == on_disk_files | {MANIFEST_NAME}
              and MANIFEST_NAME not in nested_doc["release_inventory"]["files"],
              str(sorted(on_disk_files
                         - set(nested_doc["release_inventory"]["files"]))))
        check("RI5: the exclusion is the release root's manifest only -- a "
              "nested dataset_manifest.json is digested like any other file",
              os.path.join("second", MANIFEST_NAME)
              in nested_doc["release_inventory"]["files"])

        # -- RI6 -------------------------------------------------------------
        check("RI6: a nested project owns its own subset and the root project "
              "does not absorb it",
              sorted(base_doc["projects"]["first"]["subsets"]) == ["evalfirst"]
              and sorted(base_doc["projects"]["second"]["subsets"])
              == ["evalsecond"],
              json.dumps({p: sorted(b["subsets"])
                          for p, b in base_doc["projects"].items()}))
        check("RI6: subset attribution names the file each project actually "
              "published",
              base_doc["projects"]["second"]["subsets"]["evalsecond"]["file"]
              == os.path.join("second", "evalsecond.jsonl"))
        unowned = variant()
        os.makedirs(os.path.join(unowned, "third"))
        _shutil.copy(os.path.join(unowned, "evalfirst.jsonl"),
                     os.path.join(unowned, "third", "evalthird.jsonl"))
        msg = refusal(unowned)
        check("RI6: a published subset in an undeclared subdirectory refuses "
              "rather than falling to the root project",
              msg is not None and "in no declared project" in msg, str(msg))

    # RI1's second leg and RI5/RI6 against the release this repository actually
    # ships.  Guarded like the cluster pins below: a checkout without the
    # release still has to pass its selftest.
    _real_manifest = os.path.join(DEFAULT_RELEASE, MANIFEST_NAME)
    if os.path.isfile(_real_manifest):
        import csv as _csv
        import io as _io

        with open(_real_manifest, encoding="utf-8") as fh:
            shipped = json.load(fh)
        for _project, _csv_rel in (("coreshop", "exclusions.csv"),
                                   ("python-docx",
                                    "python-docx/exclusions.csv")):
            path = os.path.join(DEFAULT_RELEASE, _csv_rel)
            if not os.path.isfile(path):                    # pragma: no cover
                continue
            raw = open(path, "rb").read()
            with tempfile.TemporaryDirectory() as _d:
                out = os.path.join(_d, "exclusions.csv")
                parsed = list(_csv.reader(
                    _io.StringIO(raw.decode("utf-8"), newline="")))
                write_csv(out, parsed[0], parsed[1:])
                same = open(out, "rb").read() == raw
            check(f"RI1: the shipped {_project} exclusions.csv is byte-for-byte "
                  f"what write_csv produces from its own rows", same,
                  f"{_csv_rel} would be rewritten by its own producer")
            check(f"RI1: the shipped {_project} exclusions.csv matches the "
                  f"digest the checked-in manifest records",
                  sha256_file(path)
                  == shipped["projects"][_project]["digests"]["exclusions"],
                  f"{sha256_file(path)} vs "
                  f"{shipped['projects'][_project]['digests'].get('exclusions')}")

    if os.path.isfile(_real_manifest):
        import yaml as _yaml

        _decl_path = os.path.join(BENCHMARK, "config", "dataset_manifest.yml")
        if os.path.isfile(_decl_path):
            with open(_decl_path, encoding="utf-8") as fh:
                _declarations = _yaml.safe_load(fh)
            _real = build_dataset_manifest(DEFAULT_RELEASE, _declarations)
            check("RI6: on the shipped release CoreShop owns exactly eval100 "
                  "and python-docx exactly evaldocx32",
                  sorted(_real["projects"]["coreshop"]["subsets"]) == ["eval100"]
                  and sorted(_real["projects"]["python-docx"]["subsets"])
                  == ["evaldocx32"],
                  json.dumps({p: sorted(b["subsets"])
                              for p, b in _real["projects"].items()}))
            check("RI3: the manifest retains the collected identities for "
                  "422 + 239 relocated gold sidecars",
                  _real["projects"]["coreshop"]["n_gold_sidecars"] == 422
                  and _real["projects"]["python-docx"]["n_gold_sidecars"] == 239,
                  json.dumps({p: b["n_gold_sidecars"]
                              for p, b in _real["projects"].items()}))
            core_bundle = _real["projects"]["coreshop"].get("bundle") or {}
            docx_bundle = _real["projects"]["python-docx"].get("bundle") or {}
            declared_versions = {
                entry["project"]: entry["bundle"]["version"]
                for entry in _declarations["projects"]
                if entry.get("bundle") is not None}
            check("schema 3 retains both project bundle declarations with "
                  "one shared coverage/baseline path",
                  _real["schema"] == "r2t.dataset_manifest/3"
                  and core_bundle.get("version") == declared_versions["coreshop"]
                  and docx_bundle.get("version") == declared_versions["python-docx"]
                  and all(bundle["artifacts"]["coverage_run"]
                          == bundle["artifacts"]["gold_baseline"]
                          for bundle in (core_bundle, docx_bundle))
                  and core_bundle.get("production_index") is not None
                  and docx_bundle.get("production_index") is not None
                  and core_bundle["artifacts"]["alias_table"] is not None
                  and core_bundle["artifacts"]["autowirable_types"] is not None
                  and docx_bundle["artifacts"]["alias_table"] is None
                  and docx_bundle["artifacts"]["autowirable_types"] is None,
                  json.dumps({"coreshop": core_bundle,
                              "python-docx": docx_bundle}, sort_keys=True))
            check("only the project with a byte-pinned published table "
                  "declares the eval100-std arm, and the declared asset "
                  "version is now the one that ships it",
                  core_bundle["std_arm"]["asset_version"]
                  == core_bundle["version"]
                  and core_bundle["std_arm"]["ceremony"]["tag"]
                  and "std_arm" not in docx_bundle,
                  json.dumps(core_bundle.get("std_arm"), sort_keys=True))

            import copy
            scoring_declaration = copy.deepcopy(next(
                entry for entry in _declarations["projects"]
                if entry["project"] == "coreshop"))
            declared = scoring_declaration["bundle"]
            declared["scoring_gold_sha256"] = "a" * 64
            declared["artifacts"]["scoring_gold"] = \
                "projects/coreshop/artifacts/runs/gold_direct.jsonl"
            projected = _bundle_block(
                DEFAULT_RELEASE, "coreshop", scoring_declaration)
            check("an optional scoring-gold role leaves every historical "
                  "bundle role and std-arm declaration intact",
                  projected["scoring_gold"] == {"sha256": "a" * 64}
                  and projected["std_arm"] == core_bundle["std_arm"]
                  and all(projected["artifacts"][role] == path
                          for role, path in core_bundle["artifacts"].items()))
            for name, change in (
                    ("missing pin", lambda b: b.pop("scoring_gold_sha256")),
                    ("missing role", lambda b: b["artifacts"].pop("scoring_gold")),
                    ("historical role alias", lambda b: b["artifacts"].update(
                        scoring_gold=b["artifacts"]["gold_baseline"])),
                    ("missing index", lambda b: b.update(
                        production_index_sha256=None))):
                bad = copy.deepcopy(scoring_declaration)
                change(bad["bundle"])
                check(f"a scoring-gold declaration with {name} refuses",
                      refused(lambda: _bundle_block(
                          DEFAULT_RELEASE, "coreshop", bad)) is not None)

            def std_declaration(**over):
                """The shipped CoreShop declaration with ONE arm field moved."""
                projects = []
                for entry in _declarations["projects"]:
                    entry = dict(entry)
                    if entry["project"] == "coreshop":
                        bundle = dict(entry["bundle"])
                        arm = dict(bundle["std_arm"])
                        arm["ceremony"] = dict(arm["ceremony"], **over)
                        bundle["std_arm"] = arm
                        entry["bundle"] = bundle
                    projects.append(entry)
                return dict(_declarations, projects=projects)

            msg = refused(lambda: build_dataset_manifest(
                DEFAULT_RELEASE, std_declaration(commit="not-a-commit")))
            check("an arm declaration that does not name the ceremony's "
                  "exact commit is refused",
                  msg is not None and "not a commit id" in msg, str(msg))
            msg = refused(lambda: build_dataset_manifest(
                DEFAULT_RELEASE,
                std_declaration(shipping_list="../elsewhere/list.json")))
            check("an arm document read from beside the shipping list must "
                  "be a plain file name, not a path out of the evidence "
                  "directory",
                  msg is not None and "not a plain file name" in msg, str(msg))
            msg = refused(lambda: build_dataset_manifest(
                DEFAULT_RELEASE, std_declaration(rerun="2026-08-20")))
            check("an arm declaration carrying a field the join does not "
                  "read is refused, not ignored",
                  msg is not None and "ceremony fields differ" in msg,
                  str(msg))
            _inv = _real["release_inventory"]["files"]
            _on_disk = set(_release_files(DEFAULT_RELEASE))
            check("RI5: on the shipped release the manifest is the only file "
                  "the inventory leaves out",
                  set(_inv) == _on_disk - {MANIFEST_NAME}
                  and _real["release_inventory"]["n_files"] == len(_inv),
                  str(sorted(_on_disk - set(_inv))))

    # ---------------------------------------- target_interfaces wiring (spec 6)
    with tempfile.TemporaryDirectory() as d:
        check("no interfaces path: the release carries no field and nothing "
              "is refused",
              _interfaces_by_item(None) is None)
        missing = os.path.join(d, "interfaces.json")
        try:
            _interfaces_by_item(missing)
            check("a behat release without interfaces.json is refused", False)
        except ValueError as e:
            check("a behat release without interfaces.json is refused",
                  "interfaces.json" in str(e) and "TARGET_INTERFACES_SPEC" in str(e))
        with open(missing, "w", encoding="utf-8") as fh:
            json.dump({"schema": "r2t.interfaces/1", "items": [
                {"item_id": "p/f/a.feature:1",
                 "target_interfaces": {"behaviour": ["A\\B", "A\\C"],
                                       "setup": ["A\\D"]}}]}, fh)
        table = _interfaces_by_item(missing)
        row = {"item_id": "p/f/a.feature:1"}
        _attach_interfaces(row, "p/f/a.feature:1", table)
        check("the two lists reach the released row unchanged, as lists",
              row["target_interfaces"] == {"behaviour": ["A\\B", "A\\C"],
                                           "setup": ["A\\D"]}
              and all(isinstance(v, list)
                      for v in row["target_interfaces"].values()))
        try:
            _attach_interfaces({}, "p/f/b.feature:1", table)
            check("a released item absent from interfaces.json is refused", False)
        except ValueError as e:
            check("a released item absent from interfaces.json is refused",
                  "p/f/b.feature:1" in str(e) and "not built together" in str(e))
        untouched = {"item_id": "x"}
        _attach_interfaces(untouched, "x", None)
        check("a stack that mints no list leaves the row without the field",
              "target_interfaces" not in untouched)

    # -------------------------------- checked_interfaces wiring (v2 spec 5)
    with tempfile.TemporaryDirectory() as d:
        check("no derivation path: the release carries no v2 field and "
              "nothing is refused",
              _checked_interfaces_by_item(None) is None)
        derived = os.path.join(d, "checked_interfaces.json")
        try:
            _checked_interfaces_by_item(derived)
            check("a release pointed at an absent derivation is refused", False)
        except ValueError as e:
            check("a release pointed at an absent derivation is refused",
                  "checked_interfaces.json" in str(e)
                  and "TARGET_INTERFACES_V2_SPEC" in str(e))
        entry = {"key": ["A\\B", "getThing"],
                 "declaration": "public function getThing(): Thing;"}
        document = {"schema": CHECKED_INTERFACES_SCHEMA, "project": "p",
                    "items": {"p/f/a.feature:1": {"checked": [entry],
                                                  "empty_reason": None},
                              "p/f/b.feature:1": {
                                  "checked": [],
                                  "empty_reason": "no_action_or_check_call"}}}
        with open(derived, "w", encoding="utf-8") as fh:
            json.dump(dict(document, schema="r2t.interfaces/1"), fh)
        try:
            _checked_interfaces_by_item(derived)
            check("a derivation of the wrong schema is refused", False)
        except ValueError as e:
            check("a derivation of the wrong schema is refused",
                  CHECKED_INTERFACES_SCHEMA in str(e))
        with open(derived, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        table = _checked_interfaces_by_item(derived)
        row = {"item_id": "p/f/a.feature:1"}
        _attach_checked_interfaces(row, "p/f/a.feature:1", table)
        empty_row = {"item_id": "p/f/b.feature:1"}
        _attach_checked_interfaces(empty_row, "p/f/b.feature:1", table)
        check("the item's object reaches the released row verbatim, populated "
              "and empty-with-reason alike",
              row["checked_interfaces"] == document["items"]["p/f/a.feature:1"]
              and empty_row["checked_interfaces"]
              == document["items"]["p/f/b.feature:1"]
              and row["checked_interfaces"]["checked"][0] is not entry)
        try:
            _attach_checked_interfaces({}, "p/f/c.feature:1", table)
            check("a released item absent from the derivation is refused", False)
        except ValueError as e:
            check("a released item absent from the derivation is refused",
                  "p/f/c.feature:1" in str(e) and "not built together" in str(e))
        # The renderer is the shape authority, and it runs while the release
        # is being built: a derivation that emits an unsorted list makes an
        # item that refuses at prompt time, which is too late to fix it.
        with open(derived, "w", encoding="utf-8") as fh:
            json.dump(dict(document, items={"p/f/a.feature:1": {
                "checked": [dict(entry, key=["z\\Late", "m"]), entry],
                "empty_reason": None}}), fh)
        try:
            _attach_checked_interfaces({"item_id": "p/f/a.feature:1"},
                                       "p/f/a.feature:1",
                                       _checked_interfaces_by_item(derived))
            check("a malformed derivation is refused at release time", False)
        except ValueError as e:
            check("a malformed derivation is refused at release time",
                  "not sorted" in str(e), str(e))
        untouched = {"item_id": "x"}
        _attach_checked_interfaces(untouched, "x", None)
        check("a release built without a derivation leaves the row without "
              "the v2 field",
              "checked_interfaces" not in untouched)

    # ------------- the v2 field is attached to RELEASED rows, not to the pool
    # The derivation reads a released items file, so it has no entry for an
    # item the build excludes.  A pool holding one excluded item (CoreShop's
    # real shape: 123 of its items are dropped for thin_scenario and friends
    # AFTER the row builder) must therefore still build.
    with tempfile.TemporaryDirectory() as d:
        kept, dropped = "p/f/kept.feature:3", "p/f/thin.feature:7"

        def _pool_item(iid):
            return {"item_id": iid, "task": "criterion_to_test",
                    "project": "p", "language": "php", "framework": "behat",
                    "provenance": {"repo": "p"}, "requirement": "r",
                    "criterion": "c", "expected_output": "o"}

        def _closure(iid):
            return {"item_id": iid, "files": ["ctx/" + iid.split("/")[-1]],
                    "di_fragment": "", "context_classes": ["A\\Ctx"],
                    "feature_file": iid.split(":")[0],
                    "scenario_line": int(iid.split(":")[1]),
                    "counts": {"steps_unmatched": 0}}

        artifacts = os.path.join(d, "artifacts")
        os.makedirs(artifacts)
        pool = os.path.join(d, "pool.jsonl")
        with open(pool, "w", encoding="utf-8") as fh:
            for iid in (kept, dropped):
                fh.write(json.dumps(_pool_item(iid)) + "\n")
        with open(os.path.join(artifacts, "closures.json"), "w",
                  encoding="utf-8") as fh:
            json.dump([_closure(kept), _closure(dropped)], fh)
        with open(os.path.join(artifacts, "quality.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({kept: {"has_oracle": True, "live_step_count": 5,
                              "live_effective_step_count": 5},
                       dropped: {"has_oracle": True, "live_step_count": 1,
                                 "live_effective_step_count": 1}}, fh)
        with open(os.path.join(artifacts, "validation.jsonl"), "w",
                  encoding="utf-8") as fh:
            for iid in (kept, dropped):
                fh.write(json.dumps({"item_id": iid, "admitted": True,
                                     "reason": "ok", "seconds": 1.0}) + "\n")
        entry = {"key": ["A\\Svc", "place"],
                 "declaration": "public function place(): void;"}
        released_only = os.path.join(d, "checked_interfaces.json")
        with open(released_only, "w", encoding="utf-8") as fh:
            json.dump({"schema": CHECKED_INTERFACES_SCHEMA, "project": "p",
                       "items": {kept: {"checked": [entry],
                                        "empty_reason": None}}}, fh)
        out = os.path.join(d, "out")
        info = build_release(artifacts, pool, out, project="p",
                             items_name="items.jsonl",
                             checked_interfaces_path=released_only)
        released = _load_jsonl(os.path.join(out, "items.jsonl"))
        with open(os.path.join(out, "exclusions.csv"), encoding="utf-8") as fh:
            exclusions = fh.read()
        check("a pool item excluded after the row builder does not need a "
              "derivation entry: the release still builds",
              info["included"] == 1 and info["excluded"] == 1
              and [r["item_id"] for r in released] == [kept]
              and released[0]["checked_interfaces"]["checked"] == [entry]
              and dropped in exclusions
              and "thin_scenario_lt_3_effective_steps" in exclusions)

        # And the guard still bites the real disagreement: an entry for an
        # item this release does not include means the derivation and the
        # items file were not built together.
        both = os.path.join(d, "checked_both.json")
        with open(both, "w", encoding="utf-8") as fh:
            json.dump({"schema": CHECKED_INTERFACES_SCHEMA, "project": "p",
                       "items": {kept: {"checked": [entry],
                                        "empty_reason": None},
                                 dropped: {"checked": [],
                                           "empty_reason":
                                           "no_action_or_check_call"}}}, fh)
        try:
            build_release(artifacts, pool, os.path.join(d, "out2"),
                          project="p", items_name="items.jsonl",
                          checked_interfaces_path=both)
            check("a derivation naming an item the release excludes is "
                  "refused", False)
        except ValueError as e:
            check("a derivation naming an item the release excludes is "
                  "refused",
                  "does not include" in str(e) and dropped in str(e), str(e))

    print("\n" + ("ALL PASS (release_build)" if ok else "FAILURES (release_build)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
