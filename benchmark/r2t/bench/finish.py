"""Finish one complete result-v3 campaign into a merged run and table."""
from __future__ import annotations

import json
import os
import re


CAMPAIGN_NAME = "campaign.json"
MANIFEST_NAME = re.compile(r"worker\d+\.manifest\.json")
MERGED_NAME = "merged.jsonl"
RESULTS_NAME = "results.md"


def _load_json(path: str, label: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"REFUSED: cannot read {label} {path}: {exc}") \
            from exc
    if not isinstance(document, dict):
        raise SystemExit(f"REFUSED: {label} {path} is not a JSON object")
    return document


def _manifest_entries(campaign_dir: str, campaign_document: dict,
                      campaign_digest: str) -> list[tuple[str, object]]:
    from .campaign import WorkerManifest, campaign_digest as digest

    paths = sorted(
        os.path.join(campaign_dir, name)
        for name in os.listdir(campaign_dir)
        if MANIFEST_NAME.fullmatch(name))
    entries = []
    for path in paths:
        document = _load_json(path, "worker manifest")
        if set(document) != {"campaign", "campaign_digest", "worker"}:
            raise SystemExit(
                f"REFUSED: worker manifest {path} has the wrong outer shape")
        try:
            embedded_digest = digest(document["campaign"])
            worker = WorkerManifest.from_json(document["worker"])
        except (SystemExit, ValueError) as exc:
            raise SystemExit(f"REFUSED: invalid worker manifest {path}: "
                             f"{exc}") from exc
        if embedded_digest != campaign_digest \
                or document["campaign_digest"] != campaign_digest \
                or worker.campaign_digest != campaign_digest \
                or document["campaign"] != campaign_document:
            raise SystemExit(
                f"REFUSED: worker manifest {path} belongs to another "
                "campaign")
        entries.append((path, worker))
    return entries


def _campaign_inputs(campaign_dir: str) -> dict:
    from . import result_ledger as ledger
    from .campaign import campaign_digest

    campaign_path = os.path.join(campaign_dir, CAMPAIGN_NAME)
    campaign_document = _load_json(campaign_path, "campaign")
    digest = campaign_digest(campaign_document)
    workers = campaign_document["k_workers"]
    entries = _manifest_entries(campaign_dir, campaign_document, digest)
    present = {worker.shard for _path, worker in entries}
    missing = sorted(set(range(workers)) - present)
    if missing:
        raise SystemExit(
            f"REFUSED: campaign {campaign_dir} has no worker manifest for "
            f"shard(s) {missing} of K={workers}; finish never seals or "
            "creates manifests")

    receipts = []
    unsealed = []
    receipt_documents = []
    for manifest_path, worker in entries:
        receipt_path = worker.out_path + ledger.RECEIPT_SUFFIX
        if worker.finished_at is None or not os.path.isfile(receipt_path):
            unsealed.append(worker.shard)
            continue
        receipt = _load_json(receipt_path, "result-v3 receipt")
        plan = receipt.get("plan")
        if not isinstance(plan, dict) \
                or plan.get("worker_manifest_path") != manifest_path:
            raise SystemExit(
                f"REFUSED: shard {worker.shard} receipt does not bind its "
                f"discovered worker manifest {manifest_path}")
        receipts.append(receipt_path)
        receipt_documents.append(receipt)
    if unsealed:
        raise SystemExit(
            f"REFUSED: campaign {campaign_dir} shard(s) {sorted(unsealed)} "
            "are not sealed; finish requires a finished worker manifest and "
            "its adjacent result-v3 receipt, and never creates either")
    try:
        first_plan = receipt_documents[0]["plan"]
        release_path = first_plan["release"]["path"]
        boundary_path = first_plan["boundary"]["path"]
        profile_path = first_plan["profile"]["path"]
    except (IndexError, KeyError, TypeError) as exc:
        raise SystemExit(
            "REFUSED: sealed shard receipt does not name its release, "
            "boundary, and profile") from exc
    return {
        "campaign_path": campaign_path, "workers": workers,
        "receipts": receipts, "release_path": release_path,
        "boundary_path": boundary_path, "profile_path": profile_path,
    }


def _render_results(merged_path: str, boundary_path: str,
                    profile_path: str) -> bytes:
    from . import results as result_table
    from ..core.boundary import load_boundary
    from ..data.profile import load_profile

    boundary = load_boundary(boundary_path)
    profile = load_profile(profile_path)
    try:
        table = result_table._results_impl(
            merged_path, gold_path="", test_quality_path=None,
            prod_index_path="", boundary=boundary, artifacts="",
            api_scoring=profile.api_scoring, publication=True)
        return result_table.render(table, "markdown").encode("utf-8")
    except result_table.ResultsInputError as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc


def inspect_finished_campaign(campaign_dir: str) -> str:
    """Return absent or complete for fixed finish roles without writing."""
    from . import result_ledger as ledger
    from . import campaign, runner

    campaign_dir = os.path.abspath(campaign_dir)
    merged = os.path.join(campaign_dir, MERGED_NAME)
    roles = (
        merged, merged + ".campaign.json",
        merged + ledger.CHECKPOINT_SUFFIX,
        merged + ledger.RECEIPT_SUFFIX,
        runner.publication_lock_path(merged),
        os.path.join(campaign_dir, RESULTS_NAME),
    )
    present = [path for path in roles if os.path.lexists(path)]
    if not present:
        return "absent"
    expected = set(roles) - {merged + ledger.CHECKPOINT_SUFFIX}
    if set(present) != expected:
        raise SystemExit(
            f"REFUSED: finished campaign roles are partial: {present}")
    inputs = _campaign_inputs(campaign_dir)
    receipt = ledger.verify_receipt(merged + ledger.RECEIPT_SUFFIX)
    if receipt.get("artifact_kind") != "merged_run":
        raise SystemExit("REFUSED: finished campaign receipt is not merged_run")
    campaign._publication_merge_existing_matches(
        receipt, inputs["receipts"], inputs["release_path"],
        inputs["workers"])
    rendered = _render_results(
        merged, inputs["boundary_path"], inputs["profile_path"])
    if ledger.read_trusted_bytes(
            os.path.join(campaign_dir, RESULTS_NAME),
            label="finished campaign results") != rendered:
        raise SystemExit(
            "REFUSED: existing finished campaign results differ")
    return "complete"


def finish_campaign(campaign_dir: str) -> dict:
    """Finish a complete, sealed result-v3 campaign without repairing it."""
    from . import result_ledger as ledger
    from .campaign import merge_publication_v3

    campaign_dir = os.path.abspath(campaign_dir)
    if not os.path.isdir(campaign_dir):
        raise SystemExit(
            f"REFUSED: --campaign must name a campaign directory: "
            f"{campaign_dir}")
    inputs = _campaign_inputs(campaign_dir)
    campaign_path = inputs["campaign_path"]
    workers = inputs["workers"]

    merged_path = os.path.join(campaign_dir, MERGED_NAME)
    merge_info = merge_publication_v3(
        inputs["receipts"], release_path=inputs["release_path"],
        out_path=merged_path,
        expected_shards=workers)
    results_path = os.path.join(campaign_dir, RESULTS_NAME)
    rendered_raw = _render_results(
        merged_path, inputs["boundary_path"], inputs["profile_path"])
    if os.path.lexists(results_path):
        existing = ledger.read_trusted_bytes(
            results_path, label="finished campaign results")
        if existing != rendered_raw:
            raise SystemExit(
                "REFUSED: existing finished campaign results differ; "
                "finish never overwrites them")
    else:
        ledger.durable_create_bytes_no_clobber(
            results_path, rendered_raw, label="finished campaign results")

    return {
        "campaign": campaign_path,
        "merged": merged_path,
        "results": results_path,
        "workers": workers,
        "already_complete": bool(merge_info.get("already_complete")),
    }
