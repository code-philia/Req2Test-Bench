"""Network-free checks for the one-command result-v3 campaign finish."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shlex
import sys
from types import SimpleNamespace

from . import campaign
from .. import cli
from . import cli as bench_cli
from . import finish
from . import result_ledger as ledger
from . import runner
from .result_ledger_i4_selftest import _fixture, _read, _write


def _colocate_manifests(fixture: dict, indexes=(0, 1)) -> None:
    """Put fixture manifests in the layout the finish command discovers."""
    for index in indexes:
        old_path = fixture["manifest_paths"][index]
        document = ledger.loads_exact_json(
            _read(old_path), label="finish fixture WorkerManifest")
        path = fixture["root"] + f"/worker{index}.manifest.json"
        raw = _write(path, document, indent=1)

        receipt = copy.deepcopy(fixture["source_documents"][index])
        receipt["plan"]["worker_manifest_path"] = path
        receipt["plan"]["digest"] = ledger.semantic_digest(receipt["plan"])
        receipt["worker_manifest"] = {
            "path": path, "file_sha256": ledger.raw_sha256(raw)}
        receipt["digest"] = ledger.semantic_digest(receipt)
        _write(fixture["source_paths"][index], receipt, indent=1)
        fixture["source_documents"][index] = receipt
        fixture["manifest_paths"][index] = path


def _refusal(callable_) -> str:
    try:
        callable_()
    except SystemExit as exc:
        return str(exc)
    return ""


def _outputs(root: str) -> tuple[str, ...]:
    merged = root + "/merged.jsonl"
    return (merged, merged + ".campaign.json",
            merged + ledger.RECEIPT_SUFFIX, root + "/results.md")


def _campaign_layout(
        root: str, campaign_document: dict, shards: tuple[int, ...], *,
        embedded: dict | None = None) -> None:
    os.makedirs(root, mode=0o700)
    _write(root + "/campaign.json", campaign_document, indent=1)
    manifest_campaign = embedded or campaign_document
    digest = campaign.campaign_digest(manifest_campaign)
    for shard in shards:
        worker = campaign.WorkerManifest(
            shard=shard, workspace=root + f"/workspace{shard}",
            container=f"fixture_worker_{shard}", schema="", credential="",
            out_path=root + f"/shard{shard}.jsonl",
            artifacts_root=root + f"/artifacts{shard}",
            started_at="2026-08-16T00:00:00Z",
            finished_at="2026-08-16T00:01:00Z",
            campaign_digest=digest)
        _write(root + f"/worker{shard}.manifest.json", {
            "campaign": manifest_campaign,
            "campaign_digest": digest,
            "worker": worker.to_json(),
        }, indent=1)


def _selftest() -> int:
    failures = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"  [PASS] {name}")
        else:
            failures.append(name + (f": {detail}" if detail else ""))
            print(f"  [FAIL] {name}" + (f" -- {detail}" if detail else ""))

    complete = _fixture()
    campaign_four = copy.deepcopy(complete["campaign"])
    campaign_four["campaign_id"] = "finish-missing-four"
    campaign_four["k_workers"] = 4

    missing_three_root = complete["root"] + "/missing-three"
    _campaign_layout(missing_three_root, campaign_four, (0,))
    missing_three = _refusal(
        lambda: finish.finish_campaign(missing_three_root))
    check(
        "finish names shards 1, 2, and 3 when only K=4 shard 0 exists",
        "shard(s) [1, 2, 3] of K=4" in missing_three
        and "finish never seals or creates manifests" in missing_three
        and not any(os.path.lexists(path)
                    for path in _outputs(missing_three_root)),
        missing_three)

    missing_one_root = complete["root"] + "/missing-one"
    _campaign_layout(missing_one_root, campaign_four, (0, 2, 3))
    missing_one = _refusal(lambda: finish.finish_campaign(missing_one_root))
    check(
        "finish names shard 1 when K=4 shards 0, 2, and 3 exist",
        "shard(s) [1] of K=4" in missing_one
        and not any(os.path.lexists(path)
                    for path in _outputs(missing_one_root)),
        missing_one)

    mismatch_root = complete["root"] + "/campaign-mismatch"
    another_campaign = copy.deepcopy(complete["campaign"])
    another_campaign["campaign_id"] = "another-finish-campaign"
    _campaign_layout(
        mismatch_root, complete["campaign"], (0,),
        embedded=another_campaign)
    mismatch = _refusal(lambda: finish.finish_campaign(mismatch_root))
    check(
        "a manifest with another embedded campaign refuses before merge",
        "belongs to another campaign" in mismatch
        and not any(os.path.lexists(path)
                    for path in _outputs(mismatch_root)),
        mismatch)

    unsealed = _fixture()
    _colocate_manifests(unsealed)
    os.unlink(unsealed["source_paths"][1])
    unsealed_message = _refusal(
        lambda: finish.finish_campaign(unsealed["root"]))
    check(
        "finish refuses an unsealed shard and never falls back to manifests",
        "shard(s) [1] are not sealed" in unsealed_message
        and not any(os.path.lexists(path)
                    for path in _outputs(unsealed["root"])),
        unsealed_message)

    _colocate_manifests(complete)
    inferred_sidecar = complete["root"] + "/merged.test_quality.json"
    _write(inferred_sidecar, b"not a bound mutation summary\n", raw=True)
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = cli.main(["finish", "--campaign", complete["root"]])
    payload = json.loads(stdout.getvalue())
    output_paths = _outputs(complete["root"])
    first_bytes = {path: _read(path) for path in output_paths}
    check(
        "finish resolves the receipt-pinned release, merges, and writes the "
        "markdown table beside the campaign",
        code == 0 and payload == {
            "already_complete": False,
            "campaign": complete["root"] + "/campaign.json",
            "merged": complete["root"] + "/merged.jsonl",
            "results": complete["root"] + "/results.md",
            "workers": 2,
        }
        and all(os.path.isfile(path) for path in output_paths)
        and b"| metric | value |" in first_bytes[output_paths[-1]]
        and b"not scored (no bound test-quality evidence)" \
            in first_bytes[output_paths[-1]]
        and b"r2t.cli test-quality" not in first_bytes[output_paths[-1]]
        and _read(inferred_sidecar) == b"not a bound mutation summary\n"
        and ledger.verify_receipt(
            complete["root"] + "/merged.jsonl"
            + ledger.RECEIPT_SUFFIX)["complete"]
        and finish.inspect_finished_campaign(complete["root"]) == "complete")

    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        repeat_code = cli.main(["finish", "--campaign", complete["root"]])
    repeat = json.loads(stdout.getvalue())
    check(
        "a repeated finish is successful and leaves the same output bytes",
        repeat_code == 0 and repeat["already_complete"] is True
        and all(_read(path) == first_bytes[path] for path in output_paths))

    results_path = complete["root"] + "/results.md"
    _write(results_path, b"different finished table\n", raw=True)
    mismatch_message = _refusal(
        lambda: finish.finish_campaign(complete["root"]))
    inspect_mismatch = _refusal(
        lambda: finish.inspect_finished_campaign(complete["root"]))
    check(
        "finish accepts identical results but refuses to overwrite a "
        "different existing table",
        "existing finished campaign results differ" in mismatch_message
        and "existing finished campaign results differ" in inspect_mismatch
        and _read(results_path) == b"different finished table\n",
        mismatch_message + " / " + inspect_mismatch)
    _write(results_path, first_bytes[results_path], raw=True)

    old_kind = runner.publication_adapter_kind
    old_run = runner.run_publication_v3
    publication_calls = []
    runner.publication_adapter_kind = lambda _args: "empty"
    runner.run_publication_v3 = lambda *_args, **_kwargs: (
        publication_calls.append(True) or {
            "out": complete["root"] + "/shard.jsonl", "complete": True})
    try:
        nondefault_runs = []
        for campaign_path, manifest_path in (
                (complete["root"] + "/campaign-not-default.json",
                 complete["root"] + "/worker0.manifest.json"),
                (complete["root"] + "/campaign.json",
                 complete["root"] + "/nested/worker0.manifest.json")):
            nondefault_args = SimpleNamespace(
                publication_v3=True, _agent_publication_argv=None,
                campaign=campaign_path, worker_manifest=manifest_path)
            nondefault_stdout = io.StringIO()
            with contextlib.redirect_stdout(nondefault_stdout):
                nondefault_code = bench_cli.cmd_run(nondefault_args)
            nondefault_runs.append(
                (nondefault_code, json.loads(nondefault_stdout.getvalue())))

        run_stdout = io.StringIO()
        args = SimpleNamespace(
            publication_v3=True, _agent_publication_argv=None,
            campaign=complete["root"] + "/campaign.json",
            worker_manifest=complete["root"] + "/worker0.manifest.json")
        with contextlib.redirect_stdout(run_stdout):
            run_code = bench_cli.cmd_run(args)
    finally:
        runner.publication_adapter_kind = old_kind
        runner.run_publication_v3 = old_run
    run_payload = json.loads(run_stdout.getvalue())
    expected_hint = f"PYTHONPATH={shlex.quote(bench_cli.BENCHMARK)} " \
        + shlex.join([
        sys.executable, "-m", "r2t.cli", "finish", "--campaign",
        complete["root"]])
    check(
        "non-default publication-v3 layouts still run and omit an unusable "
        "finish hint",
        len(nondefault_runs) == 2
        and all(code == 0 and "finish" not in payload
                for code, payload in nondefault_runs)
        and publication_calls == [True, True, True])
    check(
        "a successful result-v3 shard prints the exact finish invocation in "
        "its one JSON document",
        run_code == 0 and run_payload["finish"] == expected_hint
        and run_payload["out"] == complete["root"] + "/shard.jsonl"
        and publication_calls == [True, True, True])

    def print_info(info: dict) -> dict:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            bench_cli._print_run_info(args, info)
        return json.loads(stdout.getvalue())

    incomplete = print_info({"out": complete["root"] + "/shard.jsonl",
                             "complete": False})
    resumed = print_info({"out": complete["root"] + "/shard.jsonl",
                          "already_complete": True})
    check("an incomplete shard omits a finish command that must refuse",
          "finish" not in incomplete)
    check("an already-complete resume remains finishable without inventing a "
          "complete field",
          resumed["finish"] == expected_hint
          and "complete" not in resumed)

    diagnostic_stdout = io.StringIO()
    with contextlib.redirect_stdout(diagnostic_stdout):
        bench_cli._print_run_info(SimpleNamespace(
            publication_v3=False,
            campaign=complete["root"] + "/campaign.json",
            worker_manifest=complete["root"] + "/worker0.manifest.json"),
            {"out": "/diagnostic.jsonl"})
    check(
        "the result-v3 finish hint is absent from a diagnostic run",
        "finish" not in json.loads(diagnostic_stdout.getvalue()))

    if failures:
        print("\nFAILURES (finish):")
        for failure in failures:
            print(" - " + failure)
        return 1
    print("\nALL PASS (finish)")
    return 0


def selftest() -> int:
    # The command sandbox presents `/` as uid 65534. Production correctly
    # refuses that owner; this source-only fixture needs only to skip the
    # synthetic mount owner while exercising finish's orchestration.
    secure_chain = ledger._secure_directory_chain
    ledger._secure_directory_chain = lambda *_args, **_kwargs: None
    try:
        return _selftest()
    finally:
        ledger._secure_directory_chain = secure_chain


if __name__ == "__main__":
    raise SystemExit(selftest())
