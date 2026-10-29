"""Source-only adversarial checks for the result-ledger I3 producer.

All fixtures live below owner-private temporary directories.  The checks use
only offline runtime-v3 evidence and injected live-validation seams; they do
not contact Docker, a daemon, a model, a pool, or the network.
"""
from __future__ import annotations

import builtins
import contextlib
import copy
import io
import json
import os
from types import SimpleNamespace

from . import cli as bench_cli
from ..toolkit import cli as toolkit_cli
from .. import docker_authority
from . import result_ledger as ledger
from . import result_ledger_i2_selftest as i2
from . import runner
from . import validate as validation
from . import worker


def _validation_args(fixture: dict) -> SimpleNamespace:
    source = fixture["args"]
    return SimpleNamespace(
        cmd="validate", publication_v3=True,
        worker=fixture["spec_path"],
        repo=fixture["root"] + "/workspace",
        container="fixture_worker_0", workdir="/work",
        artifacts=fixture["root"] + "/artifacts",
        gold=fixture["root"] + "/gold",
        boundary=source.boundary, profile=source.profile,
        out="validation.jsonl", item=None, limit=None,
        repeats=2, timeout=61, no_resume=False, retry_failed=False,
    )


def _make(*, count: int = 1, framework: str = "behave",
          autowire: bool = False) -> dict:
    fixture = i2._make(
        "stripped-gold", count=count, framework=framework,
        autowire=autowire)
    closures_path = fixture["root"] + "/artifacts/closures.json"
    closures = ledger.loads_exact_json(
        ledger.read_trusted_bytes(closures_path, label="validation closures"),
        label="validation closures")
    for closure in closures:
        closure.update({
            "scenario_line": 2,
            "di_fragment": closure.get("di_fragment", {}),
            "context_classes": closure.get("context_classes", []),
        })
    i2._write(closures_path, closures)
    args = _validation_args(fixture)
    bundle = validation.construct_publication_validation_plan(args)
    fixture.update({
        "validation_args": args,
        "validation_bundle": bundle,
        "validation_result_path": bundle.result_path,
        "validation_checkpoint_path": bundle.checkpoint_path,
        "validation_receipt_path": bundle.receipt_path,
    })
    return fixture


def _clear(fixture: dict) -> None:
    bundle = fixture["validation_bundle"]
    for path in (
            bundle.receipt_path, bundle.checkpoint_path, bundle.result_path,
            runner.publication_lock_path(bundle.result_path)):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _row(bundle, ordinal: int, **changes) -> dict:
    value = {
        "item_id": bundle.item_ids[ordinal],
        "admitted": True,
        "reason": None,
        **bundle.row_identity,
    }
    value.update(changes)
    return value


def _row_bytes(row: dict) -> bytes:
    return (json.dumps(
        row, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False) + "\n").encode("utf-8")


def _running(fixture: dict, *, fault=None) -> validation._ValidationLedger:
    state = validation._ValidationLedger(
        fixture["validation_bundle"], fault=fault)
    state.resolve()
    state.transition("running")
    return state


def _live(bundle, calls: list | None = None) -> dict:
    if calls is not None:
        calls.append("live")
    return {"publication_runtime_reference": bundle.execution["runtime"]}


def _resign_plan(plan: dict) -> None:
    plan["invocation_digest"] = ledger.domain_digest(
        ledger.VALIDATION_INVOCATION_SCHEMA, plan["invocation"])
    plan["digest"] = ledger.semantic_digest(plan)


def _refused(callable_) -> bool:
    try:
        callable_()
    except (SystemExit, ledger.ResultLedgerRefused, ValueError, RuntimeError,
            OSError, KeyError, TypeError):
        return True
    return False


def _rehydrate(bundle, plan: dict):
    return validation._publication_validation_bundle_from_documents(
        bundle.execution, plan, bundle.result_path)


def _completed_state(fixture: dict) -> validation._ValidationLedger:
    _clear(fixture)
    state = _running(fixture)
    for ordinal in range(len(fixture["validation_bundle"].item_ids)):
        state.append(_row(fixture["validation_bundle"], ordinal))
    state.final_result()
    return state


class _FrozenHarness:
    """Small harness double that emits one identified scenario record."""

    def __init__(self, root: str):
        self.root = root

    def run_solution(self, feature, scenario, solution, *, timeout, repeats):
        del feature, timeout
        outcome = "passed" if solution.files else "failed"
        result = "passed" if outcome == "passed" else "failed"
        run = {
            "outcome": outcome,
            "exit_code": 0,
            "wall_seconds": 0.0,
            "records": [{
                "scenario_line": scenario.line,
                "steps": [{"result": result, "text": "fixture"}],
            }],
            "expected_line": scenario.line,
            "expected_lines": None,
            "stdout_tail": "",
        }
        return {"runs": [copy.deepcopy(run) for _ in range(repeats)]}


def selftest() -> int:
    ok = True

    def check(name: str, condition: object, detail: str = "") -> None:
        nonlocal ok
        passed = bool(condition)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not passed else ""))
        ok = ok and passed

    # ------------------------------------------------ exact projections
    behave = _make(count=3)
    args = behave["validation_args"]
    ids = list(behave["validation_bundle"].context.closures)
    source_ids = [item["item_id"] for item in ids]
    args.limit = 2
    args.item = [source_ids[2], source_ids[0]]
    args.repeats = 4
    args.timeout = 73
    selected = validation.construct_publication_validation_plan(args)
    inputs = selected.plan["invocation"]["harness_inputs"]
    check("validation selector applies positive limit before requested IDs",
          selected.item_ids == [source_ids[0]]
          and selected.plan["invocation"]["selection"] == {
              "limit": 2, "requested_item_ids": sorted(args.item)})
    check("Behave projection binds exact gold/feature/strip/runtime joins",
          inputs["alias_table"] is None
          and inputs["autowirable_types"] is None
          and len(inputs["feature_inputs"]) == 1
          and len(selected.plan["gold_inputs"]) == 1
          and selected.plan["repeats"] == 4
          and selected.plan["timeout_seconds"] == 73
          and selected.plan["harness_version"] == validation.HARNESS_VERSION
          and selected.plan["invocation_digest"] == ledger.domain_digest(
              ledger.VALIDATION_INVOCATION_SCHEMA,
              selected.plan["invocation"])
          and selected.result_path
              != selected.runtime.worker.out_path)
    duplicate = copy.copy(args)
    duplicate.item = [source_ids[0], source_ids[0]]
    unknown = copy.copy(args)
    unknown.item = ["unknown/item:1"]
    invalid_limits = all(_refused(
        lambda value=value: validation.construct_publication_validation_plan(
            SimpleNamespace(**{**vars(args), "limit": value})))
        for value in (0, -1, True))
    check("duplicate/unknown selectors and nonpositive limits refuse",
          _refused(lambda: validation.construct_publication_validation_plan(
              duplicate))
          and _refused(lambda: validation.construct_publication_validation_plan(
              unknown))
          and invalid_limits)
    relative_ok = selected.result_path == (
        behave["root"] + "/artifacts/validation.jsonl")
    absolute_args = copy.copy(args)
    absolute_args.out = behave["root"] + "/runs/validation-absolute.jsonl"
    absolute_ok = validation.construct_publication_validation_plan(
        absolute_args).result_path == absolute_args.out
    aliases_refuse = all(_refused(
        lambda out=out: validation._publication_validation_result_path(
            SimpleNamespace(artifacts=args.artifacts, out=out)))
        for out in ("../validation.jsonl", "./validation.jsonl",
                    behave["root"] + "/runs/../runs/validation.jsonl"))
    check("validation output keeps historical join but refuses path aliases",
          relative_ok and absolute_ok and aliases_refuse)
    behave["temporary"].cleanup()

    behat_absent = _make(framework="behat", autowire=False)
    absent_inputs = behat_absent["validation_bundle"].plan[
        "invocation"]["harness_inputs"]
    behat_present = _make(framework="behat", autowire=True)
    present_inputs = behat_present["validation_bundle"].plan[
        "invocation"]["harness_inputs"]
    check("Behat projection binds alias and optional-autowire absence",
          absent_inputs["alias_table"]["path"].endswith(
              "/alias_table.json")
          and absent_inputs["autowirable_types"] is None
          and (behat_absent["root"] +
               "/artifacts/autowirable_types.json")
              in behat_absent["validation_bundle"].absent_paths)
    check("Behat projection binds optional-autowire presence exactly",
          present_inputs["alias_table"]["path"].endswith(
              "/alias_table.json")
          and present_inputs["autowirable_types"]["path"].endswith(
              "/autowirable_types.json"))
    absent_collision_args = copy.copy(behat_absent["validation_args"])
    absent_collision_args.out = (
        behat_absent["root"] + "/artifacts/autowirable_types.json")
    check("result evidence cannot occupy an absence-bound autowire path",
          _refused(lambda:
              validation.construct_publication_validation_plan(
                  absent_collision_args)))
    absence_path = absent_collision_args.out
    check("rehydration also rejects absence-bound result evidence",
          _refused(lambda:
              validation._publication_validation_bundle_from_documents(
                  behat_absent["validation_bundle"].execution,
                  behat_absent["validation_bundle"].plan,
                  absence_path)))
    absence_checkpoint = absence_path + ledger.CHECKPOINT_SUFFIX
    absence_empty = runner._publication_result_binding(
        absence_path, b"", 0)
    i2._write(
        absence_checkpoint,
        validation._validation_checkpoint_document_values(
            behat_absent["validation_bundle"].execution,
            behat_absent["validation_bundle"].plan,
            "draft", absence_empty, None))
    resume_callbacks = []
    try:
        resume_refused = _refused(lambda: validation.run_publication_v3(
            absent_collision_args,
            harness_factory=lambda: resume_callbacks.append("harness"),
            live_validator=lambda: resume_callbacks.append("live"),
            row_producer=lambda closure:
                resume_callbacks.append(closure["item_id"])))
    finally:
        for path in (
                absence_checkpoint,
                runner.publication_lock_path(absence_path)):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
    check("resume route rejects absence-bound result before callbacks",
          resume_refused and not os.path.lexists(absence_path)
          and resume_callbacks == [])

    # The CLI live gate must use the frozen validation profile/runtime and
    # protect coordinator/gold/result evidence without treating authenticated
    # workspace feature inputs as answer paths.
    live_args = behat_present["validation_args"]
    live_args._publication_validation_plan = (
        behat_present["validation_bundle"])
    live_args._publication_protected_paths = (
        validation._publication_validation_protected_paths(
            behat_present["validation_bundle"]))
    captured_live = {}
    original_live = worker.validate_live_worker_runtime
    worker.validate_live_worker_runtime = lambda *pos, **kw: (
        captured_live.update({"pos": pos, "kw": kw}) or {
            "publication_runtime_reference":
            behat_present["validation_bundle"].execution["runtime"]})
    try:
        bench_cli._require_bound_live_worker(live_args)
    finally:
        worker.validate_live_worker_runtime = original_live
    feature_paths = {
        entry["path"] for entry in present_inputs["feature_inputs"]}
    protected_paths = set(captured_live["pos"][4])
    check("CLI live validation uses frozen noDB pool and safe protected paths",
          captured_live["pos"][1]
              == behat_present["validation_bundle"].runtime.worker
          and captured_live["pos"][3] is False
          and captured_live["kw"]["expected_pool_size"]
              == len(behat_present["validation_bundle"].runtime.pool[
                  "workers"])
          and not (feature_paths & protected_paths)
          and behat_present["validation_bundle"].result_path
              in protected_paths
          and present_inputs["alias_table"]["path"] in protected_paths)

    # The actual stack constructors consume the frozen coordinator bytes.
    for fixture in (behat_absent, behat_present):
        validation._install_publication_validation_harness_context(
            fixture["validation_bundle"], fixture["validation_args"])
        original_open = builtins.open
        try:
            builtins.open = lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("dynamic coordinator reopen"))
            harness, boundary, manifest = bench_cli._harness(
                fixture["validation_args"])
            validation._verify_publication_validation_harness(
                fixture["validation_bundle"], harness, boundary, manifest)
        except AssertionError:
            coordinator_frozen = False
            break
        finally:
            builtins.open = original_open
    else:
        coordinator_frozen = True
    check("Behat harness construction never dynamically reopens coordinator",
          coordinator_frozen)
    behat_absent["temporary"].cleanup()

    legacy_validation_ok = []
    for project in ("python-docx", "coreshop"):
        fixture = _make(
            framework="behat" if project == "coreshop" else "behave")
        document = ledger.loads_exact_json(
            ledger.read_trusted_bytes(
                fixture["strip_path"], label="legacy validation strip"))
        missing = ({"build_roots"} if project == "python-docx" else {
            "substrate_roots", "substrate_volatile",
            "bytecode_roots", "build_roots"})
        for name in missing:
            del document[name]
        document["gold_root"] = {
            "python-docx": "/data2/binhang/req2test_docx_bench/gold",
            "coreshop": "/data2/binhang/coreshop_bench/gold",
        }[project]
        i2._write(fixture["strip_path"], document)
        fresh = validation.construct_publication_validation_plan(
            fixture["validation_args"])
        replayed = validation._publication_validation_bundle_from_documents(
            fresh.execution, fresh.plan, fresh.result_path)
        built = []
        for bundle in (fresh, replayed):
            validation._install_publication_validation_harness_context(
                bundle, fixture["validation_args"])
            harness, boundary, manifest = bench_cli._harness(
                fixture["validation_args"])
            validation._verify_publication_validation_harness(
                bundle, harness, boundary, manifest)
            built.append((manifest.gold_root, manifest.build_roots,
                          bundle.strip_document
                          == bundle.context.strip_document))
        legacy_validation_ok.append(
            built == [(fixture["root"] + "/gold", [], True)] * 2)
        fixture["temporary"].cleanup()
    check("validation and its checkpoint replay consume each verified legacy "
          "strip document",
          all(legacy_validation_ok))

    # ------------------------------------------------ input closure attacks
    maximal = behat_present
    bundle = maximal["validation_bundle"]
    base = bundle.plan
    all_missing_refuse = True
    for field, values in (
            ("gold_inputs", base["gold_inputs"]),
            ("feature_inputs", base["invocation"]["harness_inputs"][
                "feature_inputs"])):
        for index in range(len(values)):
            mutant = copy.deepcopy(base)
            target = (mutant[field] if field == "gold_inputs" else
                      mutant["invocation"]["harness_inputs"][field])
            target.pop(index)
            _resign_plan(mutant)
            all_missing_refuse = all_missing_refuse and _refused(
                lambda candidate=mutant: _rehydrate(bundle, candidate))
    missing_alias = copy.deepcopy(base)
    missing_alias["invocation"]["harness_inputs"]["alias_table"] = None
    _resign_plan(missing_alias)
    all_missing_refuse = all_missing_refuse and _refused(
        lambda: _rehydrate(bundle, missing_alias))
    missing_autowire = copy.deepcopy(base)
    missing_autowire["invocation"]["harness_inputs"][
        "autowirable_types"] = None
    _resign_plan(missing_autowire)
    all_missing_refuse = all_missing_refuse and _refused(
        lambda: _rehydrate(bundle, missing_autowire))

    extra_path = maximal["root"] + "/gold/extra.py"
    i2._write(extra_path, b"extra\n", raw=True)
    extra_gold = copy.deepcopy(base)
    extra_gold["gold_inputs"].append({
        "relative_path": "extra.py", "path": extra_path,
        "byte_length": 6,
        "file_sha256": ledger.raw_sha256(b"extra\n"),
    })
    extra_gold["gold_inputs"].sort(
        key=lambda entry: (entry["relative_path"], entry["path"]))
    _resign_plan(extra_gold)
    wrong_gold_path = maximal["root"] + "/gold/wrong.py"
    wrong_gold_raw = i2._write(wrong_gold_path, b"wrong\n", raw=True)
    rebound_gold = copy.deepcopy(base)
    rebound_gold["gold_inputs"][0].update({
        "path": wrong_gold_path,
        "byte_length": len(wrong_gold_raw),
        "file_sha256": ledger.raw_sha256(wrong_gold_raw),
    })
    _resign_plan(rebound_gold)
    wrong_feature = maximal["root"] + "/workspace/features/wrong.feature"
    wrong_feature_raw = i2._write(
        wrong_feature, b"Feature: wrong\n", raw=True)
    rebound_feature = copy.deepcopy(base)
    rebound_feature["invocation"]["harness_inputs"]["feature_inputs"][0] = {
        "path": wrong_feature,
        "file_sha256": ledger.raw_sha256(wrong_feature_raw),
    }
    _resign_plan(rebound_feature)
    wrong_alias = maximal["root"] + "/artifacts/other-alias.json"
    wrong_alias_raw = i2._write(wrong_alias, {})
    rebound_alias = copy.deepcopy(base)
    rebound_alias["invocation"]["harness_inputs"]["alias_table"] = {
        "path": wrong_alias,
        "file_sha256": ledger.raw_sha256(wrong_alias_raw),
    }
    _resign_plan(rebound_alias)
    unsafe_relative = copy.deepcopy(base)
    unsafe_relative["gold_inputs"][0]["relative_path"] = "../steps.py"
    _resign_plan(unsafe_relative)
    wrong_harness = copy.deepcopy(base)
    wrong_harness["harness_version"] = validation.HARNESS_VERSION + 1
    _resign_plan(wrong_harness)
    check("every selected input is exact; missing/extra/rebound inputs refuse",
          all_missing_refuse
          and _refused(lambda: _rehydrate(bundle, extra_gold))
          and _refused(lambda: _rehydrate(bundle, rebound_gold))
          and _refused(lambda: _rehydrate(bundle, rebound_feature))
          and _refused(lambda: _rehydrate(bundle, rebound_alias))
          and _refused(lambda: _rehydrate(bundle, unsafe_relative))
          and _refused(lambda: _rehydrate(bundle, wrong_harness)))

    # Feature and gold execution receives the exact plan-time bytes even if
    # ordinary Python file reopening is made fatal.
    harness = _FrozenHarness(bundle.runtime.worker.workspace)
    original_open = builtins.open
    try:
        builtins.open = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("dynamic validation input reopen"))
        frozen_row = validation._publication_validation_row(
            bundle, harness, bundle.selected_closures[0])
        frozen_execution = frozen_row["admitted"] is True
    except AssertionError:
        frozen_execution = False
    finally:
        builtins.open = original_open
    check("validation execution consumes frozen feature and gold bytes only",
          frozen_execution)

    # Appearance of an optional file frozen as absent is part of the final
    # companion snapshot, not an ignored convenience.
    absent = _make(framework="behat", autowire=False)
    absent_state = _completed_state(absent)
    appeared_path = absent["root"] + "/artifacts/autowirable_types.json"
    i2._write(appeared_path, [])
    absent_appearance_refused = _refused(lambda:
        validation._seal_publication_validation(
            absent["validation_bundle"], absent_state,
            live_validator=lambda: _live(absent["validation_bundle"]),
            fault=None))
    check("optional autowire absence is enforced through sealing",
          absent_appearance_refused
          and not os.path.lexists(absent["validation_receipt_path"]))
    absent["temporary"].cleanup()

    # Wrong coordinator JSON shapes are rejected independently of their raw
    # hashes, closing an omitted semantic binding mutation.
    alias_path = present_inputs["alias_table"]["path"]
    alias_original = ledger.read_trusted_bytes(alias_path, label="alias")
    i2._write(alias_path, [])
    malformed_alias_refused = _refused(lambda:
        validation.construct_publication_validation_plan(
            maximal["validation_args"]))
    i2._write(alias_path, alias_original, raw=True)
    auto_path = present_inputs["autowirable_types"]["path"]
    auto_original = ledger.read_trusted_bytes(auto_path, label="autowire")
    i2._write(auto_path, ["ok", 3])
    malformed_auto_refused = _refused(lambda:
        validation.construct_publication_validation_plan(
            maximal["validation_args"]))
    i2._write(auto_path, auto_original, raw=True)
    check("coordinator JSON shape is semantically closed",
          malformed_alias_refused and malformed_auto_refused)

    # ------------------------------------------------ lifecycle creation
    initial_events = (
        "initial:before_draft", "result checkpoint:stage_fsync",
        "result checkpoint:commit", "result checkpoint:directory_fsync",
        "initial:after_draft", "initial:before_empty_result",
        "publication empty validation result:stage_fsync",
        "publication empty validation result:commit",
        "publication empty validation result:directory_fsync",
        "initial:after_empty_result",
    )
    initial_recovery = True
    for event in initial_events:
        fixture = _make()
        _clear(fixture)
        def crash(value, target=event):
            if value == target:
                raise RuntimeError(target)
        state = validation._ValidationLedger(
            fixture["validation_bundle"], fault=crash)
        try:
            state.resolve()
        except BaseException:
            pass
        try:
            recovered = validation._ValidationLedger(
                fixture["validation_bundle"])
            document = recovered.resolve()
            initial_recovery = initial_recovery \
                and document["state"] == "draft" \
                and ledger.read_trusted_bytes(
                    fixture["validation_result_path"], label="result") == b""
        except BaseException:
            initial_recovery = False
        fixture["temporary"].cleanup()
    check("every validation draft/empty-result crash window recovers",
          initial_recovery)

    initial_race_refusal = True
    for event in ("initial:after_draft", "initial:before_empty_result"):
        fixture = _make()
        _clear(fixture)
        def create_racing_empty(value, target=event, current=fixture):
            if value == target:
                i2._write(current["validation_result_path"], b"", raw=True)
        try:
            validation._ValidationLedger(
                fixture["validation_bundle"],
                fault=create_racing_empty).resolve()
            initial_race_refusal = False
        except ledger.ResultLedgerRefused:
            pass
        initial_race_refusal = initial_race_refusal and os.path.lexists(
            fixture["validation_checkpoint_path"])
        fixture["temporary"].cleanup()
    check("fresh empty-result creation stays exclusive across TOCTOU",
          initial_race_refusal)

    unbound = _make()
    _clear(unbound)
    i2._write(unbound["validation_result_path"], b"", raw=True)
    check("an uncheckpointed validation result is never post-hoc upgraded",
          _refused(lambda: validation._ValidationLedger(
              unbound["validation_bundle"]).resolve()))
    unbound["temporary"].cleanup()

    # ------------------------------------------------ append and adoption
    append_events = (
        "append:before_write", "append:after_write",
        "append:after_result_fsync", "append:before_checkpoint",
        "result checkpoint:stage_fsync", "result checkpoint:replace",
        "result checkpoint:directory_fsync", "append:after_checkpoint",
    )
    append_recovery = True
    append_no_truncation = True
    for event in append_events:
        fixture = _make()
        _clear(fixture)
        state = _running(fixture)
        def crash(value, target=event):
            if value == target:
                raise RuntimeError(target)
        state.fault = crash
        try:
            state.append(_row(fixture["validation_bundle"], 0))
        except BaseException:
            pass
        before = ledger.read_trusted_bytes(
            fixture["validation_result_path"], label="crash result")
        try:
            recovered = validation._ValidationLedger(
                fixture["validation_bundle"])
            recovered.resolve()
            recovered.adopt_pending_suffix()
            expected = 0 if event == "append:before_write" else 1
            append_recovery = append_recovery and (
                recovered.document["result_prefix"]["row_count"] == expected)
            append_no_truncation = append_no_truncation and (
                ledger.read_trusted_bytes(
                    fixture["validation_result_path"], label="result")
                == before)
        except BaseException:
            append_recovery = False
        fixture["temporary"].cleanup()
    check("every validation append/checkpoint crash window recovers",
          append_recovery and append_no_truncation)

    adoption_events = (
        "adoption:after_result_fsync", "adoption:before_checkpoint",
        "result checkpoint:stage_fsync", "result checkpoint:replace",
        "result checkpoint:directory_fsync", "adoption:after_checkpoint",
    )
    adoption_recovery = True
    for event in adoption_events:
        fixture = _make()
        _clear(fixture)
        _running(fixture)
        with open(fixture["validation_result_path"], "ab") as handle:
            handle.write(_row_bytes(_row(fixture["validation_bundle"], 0)))
            handle.flush()
            os.fsync(handle.fileno())
        def crash(value, target=event):
            if value == target:
                raise RuntimeError(target)
        recovered = validation._ValidationLedger(
            fixture["validation_bundle"], fault=crash)
        try:
            recovered.resolve()
            recovered.adopt_pending_suffix()
        except BaseException:
            pass
        try:
            final = validation._ValidationLedger(
                fixture["validation_bundle"])
            final.resolve()
            final.adopt_pending_suffix()
            adoption_recovery = adoption_recovery and (
                final.document["result_prefix"]["row_count"] == 1)
        except BaseException:
            adoption_recovery = False
        fixture["temporary"].cleanup()
    check("every stale-running adoption crash window recovers exactly",
          adoption_recovery)

    # Complete JSONL grammar, order, prefix and identity are checked before a
    # suffix can be adopted.  This named matrix kills the torn-suffix mutant.
    suffix_refusals = []
    for payload in (
            b'{"item_id":"torn"}', b"\n",
            b'{"item_id":"x","item_id":"y"}\n',
            b'{"item_id":"x","seconds":NaN}\n'):
        fixture = _make()
        _clear(fixture)
        _running(fixture)
        with open(fixture["validation_result_path"], "ab") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        suffix_refusals.append(_refused(lambda fixture=fixture:
            validation._ValidationLedger(
                fixture["validation_bundle"]).resolve()))
        fixture["temporary"].cleanup()

    identity_refusals = True
    for field in ledger.VALIDATION_ROW_IDENTITY_FIELDS:
        fixture = _make()
        _clear(fixture)
        _running(fixture)
        mutant = _row(fixture["validation_bundle"], 0)
        if field in ("repeats", "timeout_seconds"):
            mutant[field] += 1
        else:
            mutant[field] = "wrong"
        with open(fixture["validation_result_path"], "ab") as handle:
            handle.write(_row_bytes(mutant))
            handle.flush()
            os.fsync(handle.fileno())
        identity_refusals = identity_refusals and _refused(
            lambda fixture=fixture: validation._ValidationLedger(
                fixture["validation_bundle"]).resolve())
        fixture["temporary"].cleanup()
    check("torn/malformed suffixes and every wrong row identity refuse",
          all(suffix_refusals) and identity_refusals)

    drift = _make(count=2)
    _clear(drift)
    state = _running(drift)
    missing_identity = _row(drift["validation_bundle"], 0)
    missing_identity.pop("validation_plan_digest")
    missing_refused = _refused(lambda: state.append(missing_identity))
    wrong_order_refused = _refused(lambda:
        state.append(_row(drift["validation_bundle"], 1)))
    state.append(_row(drift["validation_bundle"], 0))
    with open(drift["validation_result_path"], "r+b") as handle:
        handle.truncate(1)
        handle.flush()
        os.fsync(handle.fileno())
    shortened_refused = _refused(lambda:
        validation._ValidationLedger(
            drift["validation_bundle"]).resolve())
    check("missing identity, wrong order, and shortened committed results refuse",
          missing_refused and wrong_order_refused and shortened_refused)
    drift["temporary"].cleanup()

    prefix = _make(count=2)
    _clear(prefix)
    state = _running(prefix)
    state.append(_row(prefix["validation_bundle"], 0))
    prefix_raw = ledger.read_trusted_bytes(
        prefix["validation_result_path"], label="result")
    changed_prefix = prefix_raw.replace(
        b'"timeout_seconds":61', b'"timeout_seconds":62', 1)
    i2._write(prefix["validation_result_path"], changed_prefix, raw=True)
    prefix_refused = _refused(lambda: validation._ValidationLedger(
        prefix["validation_bundle"]).resolve())
    i2._write(prefix["validation_result_path"], prefix_raw, raw=True)
    with open(prefix["validation_result_path"], "ab") as handle:
        handle.write(_row_bytes(_row(prefix["validation_bundle"], 0)))
        handle.flush()
        os.fsync(handle.fileno())
    duplicate_refused = _refused(lambda: validation._ValidationLedger(
        prefix["validation_bundle"]).resolve())
    check("committed-prefix drift and duplicate suffix rows refuse",
          changed_prefix != prefix_raw and prefix_refused and duplicate_refused)
    prefix["temporary"].cleanup()

    for stopped_state in ("draft", "interrupted", "failed"):
        fixture = _make(count=2)
        _clear(fixture)
        if stopped_state == "draft":
            state = validation._ValidationLedger(
                fixture["validation_bundle"])
            state.resolve()
        else:
            state = _running(fixture)
            state.transition(stopped_state, reason="fixture stop")
        with open(fixture["validation_result_path"], "ab") as handle:
            handle.write(_row_bytes(_row(fixture["validation_bundle"], 0)))
            handle.flush()
            os.fsync(handle.fileno())
        illegal = _refused(lambda fixture=fixture:
            validation._ValidationLedger(
                fixture["validation_bundle"]).resolve())
        check(f"suffix adoption from {stopped_state} is forbidden", illegal)
        fixture["temporary"].cleanup()

    transition = _make(count=2)
    _clear(transition)
    state = _running(transition)
    state.append(_row(transition["validation_bundle"], 0))
    state.transition("interrupted", reason="operator interrupt")
    resumed = validation._ValidationLedger(transition["validation_bundle"])
    resumed.resolve()
    resumed.transition("running")
    resumed.append(_row(transition["validation_bundle"], 1))
    exact_resume = len(resumed.final_result()[2]) == 2
    resumed.transition("failed", reason="terminal fixture failure")
    check("interrupted resumes exact prefix while failed is terminal",
          exact_resume
          and _refused(lambda: resumed.transition("running"))
          and _refused(lambda: resumed.append(
              _row(transition["validation_bundle"], 0))))
    transition["temporary"].cleanup()

    transition_events = (
        "before", "result checkpoint:stage_fsync",
        "result checkpoint:replace",
        "result checkpoint:directory_fsync", "after",
    )
    transition_recovery = True
    for target_state in ("running", "interrupted", "failed"):
        for event in transition_events:
            fixture = _make()
            _clear(fixture)
            state = validation._ValidationLedger(
                fixture["validation_bundle"])
            state.resolve()
            source_state = "draft"
            reason = None
            if target_state != "running":
                state.transition("running")
                source_state = "running"
                reason = "transition crash fixture"
            named_event = (f"transition:{source_state}:{event}:"
                           f"{target_state}" if event in {"before", "after"}
                           else event)
            def crash(value, target=named_event):
                if value == target:
                    raise RuntimeError(target)
            state.fault = crash
            try:
                state.transition(target_state, reason=reason)
            except BaseException:
                pass
            try:
                report = ledger.verify_checkpoint(
                    fixture["validation_checkpoint_path"])
                allowed = {source_state, target_state}
                transition_recovery = transition_recovery \
                    and report["state"] in allowed
                if report["state"] != "failed":
                    recovered = validation._ValidationLedger(
                        fixture["validation_bundle"])
                    recovered.resolve()
                    if report["state"] == "draft":
                        recovered.transition("running")
                    elif report["state"] == "interrupted":
                        recovered.transition("running")
            except BaseException:
                transition_recovery = False
            fixture["temporary"].cleanup()
    check("every validation state-transition checkpoint crash is recoverable",
          transition_recovery)

    # Mutation of the result during the pre-replace result fsync cannot move
    # the checkpoint over bytes it did not bind.
    checkpoint_guard = _make()
    _clear(checkpoint_guard)
    state = _running(checkpoint_guard)
    def mutate_result(event):
        if event == "result checkpoint:stage_fsync":
            with open(checkpoint_guard["validation_result_path"], "r+b") \
                    as handle:
                handle.truncate(0)
                handle.flush()
                os.fsync(handle.fileno())
    state.fault = mutate_result
    guarded = _refused(lambda:
        state.append(_row(checkpoint_guard["validation_bundle"], 0)))
    guard_document = ledger.loads_exact_json(ledger.read_trusted_bytes(
        checkpoint_guard["validation_checkpoint_path"], label="checkpoint"))
    check("checkpoint advancement guards the exact fsynced result",
          guarded and guard_document["result_prefix"]["row_count"] == 0)
    checkpoint_guard["temporary"].cleanup()

    # ------------------------------------------------ finalization / receipt
    final = _make(count=2)
    state = _completed_state(final)
    live_calls = []
    complete = validation._seal_publication_validation(
        final["validation_bundle"], state,
        live_validator=lambda: _live(final["validation_bundle"], live_calls),
        fault=None)
    receipt_raw = ledger.read_trusted_bytes(
        final["validation_receipt_path"], label="validation receipt")
    receipt_document = ledger.loads_exact_json(
        receipt_raw, label="validation receipt")
    check("validation finalization seals exact complete workset without manifest",
          complete["complete"] is True
          and complete["artifact_kind"] == "validation"
          and "worker_manifest" not in receipt_document
          and len(live_calls) == 1
          and ledger.verify_receipt(
              final["validation_receipt_path"])["complete"] is True)
    before = receipt_raw
    no_clobber = _refused(lambda: ledger.durable_create_bytes_no_clobber(
        final["validation_receipt_path"], b"replacement",
        label="replacement validation receipt"))
    check("validation receipt creation is durable no-clobber",
          no_clobber and ledger.read_trusted_bytes(
              final["validation_receipt_path"], label="receipt") == before)

    counters = {"harness": 0, "live": 0, "uuid": 0}
    original_uuid = validation.uuid.uuid4
    validation.uuid.uuid4 = lambda: (
        counters.__setitem__("uuid", counters["uuid"] + 1)
        or original_uuid())
    try:
        already = validation.run_publication_v3(
            final["validation_args"],
            harness_factory=lambda: counters.__setitem__(
                "harness", counters["harness"] + 1),
            live_validator=lambda: counters.__setitem__(
                "live", counters["live"] + 1))
    finally:
        validation.uuid.uuid4 = original_uuid
    check("valid validation receipt is idempotent before UUID/live/harness",
          already["already_complete"] is True
          and counters == {"harness": 0, "live": 0, "uuid": 0})

    # A validation receipt can never satisfy the run producer, nor vice
    # versa; positive I3 verification must not create cross-kind fallback.
    validation_as_run = _refused(lambda: runner._publication_existing_receipt(
        final["validation_result_path"],
        expected_artifact_kind="run_shard"))
    run_fixture = ledger._build_selftest_fixture(
        final["root"] + "/cross-kind-run")
    run_as_validation = _refused(lambda:
        runner._publication_existing_receipt(
            run_fixture["result_path"], expected_artifact_kind="validation"))
    check("receipt-first resolution refuses cross-kind receipts both ways",
          validation_as_run and run_as_validation)

    with open(final["validation_receipt_path"], "r+b") as handle:
        handle.seek(0)
        handle.write(b"!")
        handle.flush()
        os.fsync(handle.fileno())
    stale_bytes = ledger.read_trusted_bytes(
        final["validation_receipt_path"], label="stale receipt")
    contact = {"harness": 0, "live": 0}
    stale_refused = _refused(lambda: validation.run_publication_v3(
        final["validation_args"],
        harness_factory=lambda: contact.__setitem__(
            "harness", contact["harness"] + 1),
        live_validator=lambda: contact.__setitem__(
            "live", contact["live"] + 1)))
    check("stale validation receipt refuses without checkpoint fallback",
          stale_refused and contact == {"harness": 0, "live": 0}
          and ledger.read_trusted_bytes(
              final["validation_receipt_path"], label="stale receipt")
              == stale_bytes)
    final["temporary"].cleanup()

    receipt_events = (
        "finalization:before_live_revalidation",
        "finalization:after_live_revalidation",
        "finalization:before_receipt_selfverify",
        "finalization:after_receipt_selfverify",
        "finalization:before_receipt_create",
        "result receipt:stage_fsync", "result receipt:commit",
        "result receipt:directory_fsync",
        "finalization:after_receipt_create",
    )
    receipt_recovery = True
    for event in receipt_events:
        fixture = _make()
        state = _completed_state(fixture)
        def crash(value, target=event):
            if value == target:
                raise RuntimeError(target)
        try:
            validation._seal_publication_validation(
                fixture["validation_bundle"], state,
                live_validator=lambda fixture=fixture:
                    _live(fixture["validation_bundle"]), fault=crash)
        except BaseException:
            pass
        try:
            if os.path.lexists(fixture["validation_receipt_path"]):
                recovered = runner._publication_resolve_existing_receipt(
                    fixture["validation_result_path"],
                    expected_artifact_kind="validation")
            else:
                recovered = validation._seal_publication_validation(
                    fixture["validation_bundle"], state,
                    live_validator=lambda fixture=fixture:
                        _live(fixture["validation_bundle"]), fault=None)
            receipt_recovery = receipt_recovery and recovered["complete"]
        except BaseException:
            receipt_recovery = False
        fixture["temporary"].cleanup()
    check("every validation finalization/receipt crash window recovers",
          receipt_recovery)

    incomplete = _make(count=2)
    _clear(incomplete)
    state = _running(incomplete)
    state.append(_row(incomplete["validation_bundle"], 0))
    check("incomplete validation workset cannot be sealed",
          _refused(state.final_result)
          and _refused(lambda: validation._seal_publication_validation(
              incomplete["validation_bundle"], state,
              live_validator=lambda: _live(
                  incomplete["validation_bundle"]), fault=None))
          and not os.path.lexists(incomplete["validation_receipt_path"]))
    incomplete["temporary"].cleanup()

    # A late final-companion mutation is rejected by the second complete
    # self-verification and cannot mint a stale receipt.
    toctou = _make()
    state = _completed_state(toctou)
    feature_path = toctou["validation_bundle"].plan["invocation"][
        "harness_inputs"]["feature_inputs"][0]["path"]
    mutated = False
    def mutate_companion(event):
        nonlocal mutated
        if event == "finalization:before_receipt_create" and not mutated:
            mutated = True
            i2._write(feature_path, b"Feature: changed\n", raw=True)
    companion_refused = _refused(lambda:
        validation._seal_publication_validation(
            toctou["validation_bundle"], state,
            live_validator=lambda: _live(toctou["validation_bundle"]),
            fault=mutate_companion))
    check("final validation companion TOCTOU refuses before receipt commit",
          companion_refused and mutated
          and not os.path.lexists(toctou["validation_receipt_path"]))
    toctou["temporary"].cleanup()

    staged_toctou = _make()
    state = _completed_state(staged_toctou)
    staged_feature = staged_toctou["validation_bundle"].plan[
        "invocation"]["harness_inputs"]["feature_inputs"][0]["path"]
    staged_mutation = False
    def mutate_while_staged(event):
        nonlocal staged_mutation
        if event == "result receipt:stage_fsync" and not staged_mutation:
            staged_mutation = True
            i2._write(staged_feature, b"Feature: staged race\n", raw=True)
    staged_refused = _refused(lambda:
        validation._seal_publication_validation(
            staged_toctou["validation_bundle"], state,
            live_validator=lambda: _live(
                staged_toctou["validation_bundle"]),
            fault=mutate_while_staged))
    check("staged receipt recloses companions immediately before no-clobber",
          staged_refused and staged_mutation
          and not os.path.lexists(staged_toctou[
              "validation_receipt_path"]))
    staged_toctou["temporary"].cleanup()

    # ------------------------------------------------ orchestration / resume
    orchestration = _make(count=2)
    _clear(orchestration)
    live_count = []
    def orchestration_live():
        return _live(
            orchestration["validation_args"]._publication_validation_plan,
            live_count)
    with contextlib.redirect_stdout(io.StringIO()):
        outcome = validation.run_publication_v3(
            orchestration["validation_args"],
            harness_factory=lambda: bench_cli._harness(
                orchestration["validation_args"]),
            live_validator=orchestration_live,
            row_producer=lambda closure: {
                "item_id": closure["item_id"], "admitted": True})
    rows = ledger._json_lines(ledger.read_trusted_bytes(
        orchestration["validation_result_path"], label="result"), "result")
    executed_bundle = getattr(
        orchestration["validation_args"], "_publication_validation_plan")
    check("explicit validation orchestration validates live at start and seal",
          outcome["receipt"]["complete"]
          and len(live_count) == 2
          and [row["item_id"] for row in rows]
              == executed_bundle.item_ids
          and all(all(row[name]
                      == executed_bundle.row_identity[name]
                      for name in ledger.VALIDATION_ROW_IDENTITY_FIELDS)
                  for row in rows))
    orchestration["temporary"].cleanup()

    resume = _make(count=3)
    _clear(resume)
    first_calls = 0
    def interrupt_after_one(closure):
        nonlocal first_calls
        first_calls += 1
        if first_calls == 2:
            raise KeyboardInterrupt()
        return {"item_id": closure["item_id"], "admitted": True}
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            validation.run_publication_v3(
                resume["validation_args"],
                harness_factory=lambda: bench_cli._harness(
                    resume["validation_args"]),
                live_validator=lambda: _live(
                    resume["validation_args"]._publication_validation_plan),
                row_producer=interrupt_after_one)
    except KeyboardInterrupt:
        pass
    frozen_document = ledger.loads_exact_json(ledger.read_trusted_bytes(
        resume["validation_checkpoint_path"], label="checkpoint"))
    frozen_attempt = frozen_document["execution"]["attempt_id"]
    frozen_plan = copy.deepcopy(frozen_document["plan"])
    resume["validation_args"].item = ["fresh-selector-must-not-open"]
    resume["validation_args"].limit = 999
    resume["validation_args"].repeats = 99
    resume["validation_args"].timeout = 999
    with contextlib.redirect_stdout(io.StringIO()):
        resumed_outcome = validation.run_publication_v3(
            resume["validation_args"],
            harness_factory=lambda: bench_cli._harness(
                resume["validation_args"]),
            live_validator=lambda: _live(
                resume["validation_args"]._publication_validation_plan),
            row_producer=lambda closure: {
                "item_id": closure["item_id"], "admitted": True})
    resumed_receipt = ledger.loads_exact_json(ledger.read_trusted_bytes(
        resume["validation_receipt_path"], label="receipt"))
    check("resume preserves frozen UUID/plan/workset despite fresh CLI knobs",
          resumed_outcome["receipt"]["complete"]
          and resumed_receipt["execution"]["attempt_id"] == frozen_attempt
          and ledger._same_json_value(resumed_receipt["plan"], frozen_plan)
          and resumed_receipt["plan"]["repeats"] == 2
          and resumed_receipt["plan"]["timeout_seconds"] == 61)
    resume["temporary"].cleanup()

    bound = _make()
    _clear(bound)
    i2._write(bound["validation_result_path"], b"", raw=True)
    callbacks = {"harness": 0, "live": 0}
    bound_flags = True
    for flag in ("no_resume", "retry_failed"):
        setattr(bound["validation_args"], flag, True)
        bound_flags = bound_flags and _refused(lambda:
            validation.run_publication_v3(
                bound["validation_args"],
                harness_factory=lambda: callbacks.__setitem__(
                    "harness", callbacks["harness"] + 1),
                live_validator=lambda: callbacks.__setitem__(
                    "live", callbacks["live"] + 1)))
        setattr(bound["validation_args"], flag, False)
    check("bound validation refuses no-resume/retry flags pre-contact",
          bound_flags and callbacks == {"harness": 0, "live": 0})
    bound["temporary"].cleanup()

    rebound = _make()
    _clear(rebound)
    state = _running(rebound)
    state.transition("interrupted", reason="resume fixture")
    other_gold = rebound["root"] + "/other-gold"
    os.makedirs(other_gold, mode=0o700)
    other_boundary = rebound["root"] + "/other-boundary.yml"
    i2._write(other_boundary, b"project: other\n", raw=True)
    other_profile = rebound["root"] + "/other-profile.yml"
    i2._write(other_profile, b"project: other\n", raw=True)
    other_worker = rebound["root"] + "/other-worker.json"
    i2._write(other_worker, {})
    rebound_callbacks = {"harness": 0, "live": 0}
    rebound_refusals = True
    for field, value in (
            ("gold", other_gold), ("boundary", other_boundary),
            ("profile", other_profile), ("worker", other_worker)):
        args_copy = copy.copy(rebound["validation_args"])
        setattr(args_copy, field, value)
        rebound_refusals = rebound_refusals and _refused(lambda args=args_copy:
            validation.run_publication_v3(
                args,
                harness_factory=lambda: rebound_callbacks.__setitem__(
                    "harness", rebound_callbacks["harness"] + 1),
                live_validator=lambda: rebound_callbacks.__setitem__(
                    "live", rebound_callbacks["live"] + 1)))
    check("resume refuses rebound worker/gold/boundary/profile pre-contact",
          rebound_refusals
          and rebound_callbacks == {"harness": 0, "live": 0})
    rebound["temporary"].cleanup()

    # ------------------------------------------------ lock / filesystem trust
    locking = _make()
    _clear(locking)
    lock_path = runner.publication_lock_path(
        locking["validation_result_path"])
    first_lock = runner._PublicationResultLock(
        locking["validation_result_path"])
    first_lock.__enter__()
    try:
        competing_refused = _refused(lambda:
            runner._PublicationResultLock(
                locking["validation_result_path"]).__enter__())
        exact_lock = lock_path == (
            locking["validation_result_path"] + ".result-v3.lock")
    finally:
        first_lock.__exit__(None, None, None)
    check("canonical result-derived lock excludes competing writers",
          competing_refused and exact_lock)

    lock_replaced = False
    def replace_lock(event):
        nonlocal lock_replaced
        if event == "finalization:before_receipt_create" \
                and not lock_replaced:
            lock_replaced = True
            replacement = lock_path + ".replacement"
            i2._write(replacement, b"", raw=True)
            os.replace(replacement, lock_path)
    _clear(locking)
    lock_loss_refused = _refused(lambda:
        validation.run_publication_v3(
            locking["validation_args"],
            harness_factory=lambda: bench_cli._harness(
                locking["validation_args"]),
            live_validator=lambda: _live(
                locking["validation_args"]._publication_validation_plan),
            row_producer=lambda closure: {
                "item_id": closure["item_id"], "admitted": True},
            fault=replace_lock))
    check("receipt commit refuses changed canonical lock identity",
          lock_replaced and lock_loss_refused
          and not os.path.lexists(locking["validation_receipt_path"]))
    locking["temporary"].cleanup()

    attacks = _make()
    source_path = attacks["validation_bundle"].plan["gold_inputs"][0]["path"]
    alias = source_path + ".hardlink"
    os.link(source_path, alias)
    hardlink_refused = _refused(lambda:
        validation.construct_publication_validation_plan(
            attacks["validation_args"]))
    os.unlink(alias)
    unsafe_mode = os.stat(attacks["root"] + "/gold").st_mode & 0o777
    os.chmod(attacks["root"] + "/gold", 0o777)
    unsafe_refused = _refused(lambda:
        validation.construct_publication_validation_plan(
            attacks["validation_args"]))
    os.chmod(attacks["root"] + "/gold", unsafe_mode)
    original_acl = docker_authority._acl_absent
    docker_authority._acl_absent = lambda *a, **k: False
    try:
        acl_refused = _refused(lambda:
            validation.construct_publication_validation_plan(
                attacks["validation_args"]))
    finally:
        docker_authority._acl_absent = original_acl
    symlink_args = copy.copy(attacks["validation_args"])
    symlink_root = attacks["root"] + "/gold-link"
    os.symlink(attacks["root"] + "/gold", symlink_root)
    symlink_args.gold = symlink_root
    symlink_refused = _refused(lambda:
        validation.construct_publication_validation_plan(symlink_args))
    check("gold inputs refuse hardlinks, unsafe directories, ACLs, and symlinks",
          hardlink_refused and unsafe_refused and acl_refused
          and symlink_refused)

    evidence = _make()
    _clear(evidence)
    state = validation._ValidationLedger(evidence["validation_bundle"])
    state.resolve()
    result_alias = evidence["validation_result_path"] + ".hardlink"
    os.link(evidence["validation_result_path"], result_alias)
    result_hardlink_refused = _refused(lambda:
        validation._ValidationLedger(
            evidence["validation_bundle"]).resolve())
    os.unlink(result_alias)
    checkpoint_saved = evidence["validation_checkpoint_path"] + ".saved"
    os.replace(evidence["validation_checkpoint_path"], checkpoint_saved)
    os.symlink(checkpoint_saved, evidence["validation_checkpoint_path"])
    checkpoint_symlink_refused = _refused(lambda:
        validation._ValidationLedger(
            evidence["validation_bundle"]).resolve())
    os.unlink(evidence["validation_checkpoint_path"])
    os.replace(checkpoint_saved, evidence["validation_checkpoint_path"])
    receipt_target = evidence["root"] + "/empty-receipt-target"
    i2._write(receipt_target, b"{}\n", raw=True)
    os.symlink(receipt_target, evidence["validation_receipt_path"])
    receipt_symlink_refused = _refused(lambda:
        runner._publication_resolve_existing_receipt(
            evidence["validation_result_path"],
            expected_artifact_kind="validation"))
    check("validation result/checkpoint/receipt reject hardlink and symlink aliases",
          result_hardlink_refused and checkpoint_symlink_refused
          and receipt_symlink_refused)
    evidence["temporary"].cleanup()

    feature_path = attacks["validation_bundle"].plan["invocation"][
        "harness_inputs"]["feature_inputs"][0]["path"]
    feature_original = ledger.read_trusted_bytes(
        feature_path, label="feature")
    original_confirm = ledger._LiveReader.confirm
    changed = False
    def racing_confirm(reader):
        nonlocal changed
        if feature_path in reader.raw_by_path and not changed:
            changed = True
            i2._write(feature_path, b"Feature: raced\n", raw=True)
        return original_confirm(reader)
    ledger._LiveReader.confirm = racing_confirm
    try:
        plan_toctou = _refused(lambda:
            validation.construct_publication_validation_plan(
                attacks["validation_args"]))
    finally:
        ledger._LiveReader.confirm = original_confirm
        i2._write(feature_path, feature_original, raw=True)
    check("plan construction stable-read rejects feature TOCTOU",
          changed and plan_toctou)
    attacks["temporary"].cleanup()

    # ------------------------------------------------ legacy CLI isolation
    default_fixture = _make()
    diagnostic = default_fixture["root"] + "/artifacts/diagnostic.jsonl"
    default_args = copy.copy(default_fixture["validation_args"])
    default_args.publication_v3 = False
    default_args.out = "diagnostic.jsonl"
    default_args.limit = 1
    default_args.item = [default_fixture["validation_bundle"].item_ids[0]]
    events = []
    original_require = bench_cli._require_bound_live_worker
    original_harness = bench_cli._harness
    original_validate_all = validation.validate_all
    original_summarise = validation.summarise
    bench_cli._require_bound_live_worker = lambda value: events.append(
        "worker")
    bench_cli._harness = lambda value: (events.append("harness") or
                                  (object(), object(), object()))
    def diagnostic_validate(harness, gold, closures, out_path, **kwargs):
        del harness
        events.append(("validate", gold,
                       [row["item_id"] for row in closures], out_path,
                       kwargs))
        i2._write(out_path, b'{"item_id":"diagnostic"}\n', raw=True)
        return {}
    validation.validate_all = diagnostic_validate
    validation.summarise = lambda path: (
        events.append(("summary", path)) or {"total": 1})
    default_stdout = io.StringIO()
    try:
        with contextlib.redirect_stdout(default_stdout):
            toolkit_cli.cmd_validate(default_args)
    finally:
        bench_cli._require_bound_live_worker = original_require
        bench_cli._harness = original_harness
        validation.validate_all = original_validate_all
        validation.summarise = original_summarise
    sidecars_absent = not any(os.path.lexists(diagnostic + suffix)
                              for suffix in (
                                  ledger.CHECKPOINT_SUFFIX,
                                  ledger.RECEIPT_SUFFIX,
                                  ".result-v3.lock"))
    check("default validate preserves diagnostic order and creates no ledger",
          events[0:2] == ["worker", "harness"]
          and events[2][0] == "validate"
          and events[2][3] == diagnostic
          and events[2][4] == {
              "repeats": default_args.repeats,
              "timeout": default_args.timeout,
              "resume": True}
          and events[3] == ("summary", diagnostic)
          and sidecars_absent
          and "verified" not in default_stdout.getvalue().lower()
          and "result-v3" not in default_stdout.getvalue().lower())
    default_fixture["temporary"].cleanup()

    print("\n" + ("ALL PASS" if ok else "SELFTEST FAILED")
          + " (result_ledger_i3)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
