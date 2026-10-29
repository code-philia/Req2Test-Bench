"""Source-only adversarial checks for the result-ledger I2 producer.

Every fixture lives below a private temporary directory.  This module never
contacts Docker, a daemon, a model, a pool, or the network and never writes a
canonical benchmark artifact.
"""
from __future__ import annotations

import builtins
import contextlib
import copy
import hashlib
import io
import json
import os
import tempfile
from types import SimpleNamespace

from . import campaign
from . import result_ledger as ledger
from ..core import ledger_primitives as primitives
from . import runner
from ..core.paths import BENCHMARK_ROOT


def _write(path: str, value, *, raw: bool = False) -> bytes:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    payload = value if raw else (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    with open(path, "wb") as handle:
        handle.write(payload)
    os.chmod(path, 0o600)
    return payload


def _args(fixture: dict, *, adapter: str = "empty") -> SimpleNamespace:
    plan = fixture["receipt"]["plan"]
    worker = fixture["receipt"]["execution"]["runtime"]["identity"]
    return SimpleNamespace(
        cmd="run", publication_v3=True, adapter=adapter,
        keep_artifacts=None, no_resume=False, retry_failed=False,
        repeats=1, timeout=60, repro_check=0,
        worker=fixture["spec_path"], campaign=fixture["campaign_path"],
        worker_manifest=fixture["worker_manifest_path"],
        out=fixture["result_path"], release=plan["release"]["path"],
        boundary=plan["boundary"]["path"], profile=plan["profile"]["path"],
        gold=fixture["root"] + "/gold",
        artifacts=fixture["root"] + "/artifacts",
        repo=fixture["root"] + "/workspace",
        container="fixture_worker_0", workdir="/work",
        item=None, limit=None, shard=worker["worker_index"], of=1,
        coverage=False, trials=0, condition=None, model=None,
        protocol=None, protocol_version=None, protocol_digest=None,
        llm_config=None, replay=None, trajectory_dir=None,
    )


def _release_rows(fixture: dict, count: int, *, project: str = "python-docx",
                  language: str = "python", framework: str = "behave") \
        -> list[dict]:
    rows = []
    workspace = fixture["root"] + "/workspace"
    for number in range(count):
        relative = f"features/example{number}.feature"
        _write(
            workspace + "/" + relative,
            b"Feature: fixture\n  Scenario: one\n    Given a fixture\n",
            raw=True)
        rows.append({
            "item_id": f"{project}/{relative}:2",
            "task": "criterion_to_test", "project": project,
            "language": language, "framework": framework,
            "provenance": {"file_path": relative, "line": 2},
        })
    raw = b"".join(
        (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        .encode("utf-8") for row in rows)
    _write(fixture["receipt"]["plan"]["release"]["path"], raw, raw=True)
    return rows


def _fixture_inputs(fixture: dict, rows: list[dict], kind: str) -> None:
    root = fixture["root"]
    if kind == "gold":
        manifest = {}
        for number, row in enumerate(rows):
            name = f"record{number}.json"
            manifest[row["item_id"]] = name
            _write(root + "/gold/" + name, {
                "item_id": row["item_id"], "files": ["steps.py"],
                "di_fragment": {}, "context_classes": [],
                "feature_file": row["provenance"]["file_path"],
                "scenario_line": 2,
            })
        _write(root + "/gold/manifest.json", manifest)
        _write(root + "/gold/steps.py", b"def fixture():\n    pass\n", raw=True)
    elif kind in {"stripped-gold", "stub"}:
        closures = [{
            "item_id": row["item_id"], "files": ["steps.py"],
            "feature_file": row["provenance"]["file_path"],
            "steps": [], "di_fragment": {},
        } for row in rows]
        _write(root + "/artifacts/closures.json", closures)
        if kind == "stripped-gold":
            _write(
                root + "/gold/steps.py",
                b"def fixture():\n    pass\n", raw=True)


def _behat(fixture: dict, rows: list[dict], *, autowire: bool) -> None:
    benchmark = BENCHMARK_ROOT
    config = fixture["root"] + "/config-behat"
    os.makedirs(config, mode=0o700, exist_ok=True)
    boundary_path = config + "/boundary_coreshop.yml"
    profile_path = config + "/profile_coreshop.yml"
    with open(benchmark + "/config/boundary_coreshop.yml", "rb") as handle:
        boundary_raw = handle.read()
    with open(benchmark + "/config/profile_coreshop.yml", "rb") as handle:
        profile_raw = handle.read()
    profile_raw += b"\nruntime:\n  needs_database: false\n"
    _write(boundary_path, boundary_raw, raw=True)
    _write(profile_path, profile_raw, raw=True)
    fixture["receipt"]["plan"]["boundary"]["path"] = boundary_path
    fixture["receipt"]["plan"]["profile"]["path"] = profile_path
    args = fixture["args"]
    args.boundary = boundary_path
    args.profile = profile_path

    from ..core.boundary import load_boundary
    boundary = load_boundary(boundary_path)
    strip = ledger.loads_exact_json(
        ledger.read_trusted_bytes(fixture["strip_path"], label="strip"))
    # The old line here assigned `strip["repo_root"] = boundary.repo_root` --
    # fixture surgery whose only purpose was to satisfy the path equality
    # `_strip_manifest` no longer performs (no real pair ever satisfied it).
    # The join is now structural: `moved` must classify removable under the
    # boundary in force, so this CoreShop fixture carries a CoreShop path.
    strip["moved"] = ["src/CoreShop/Behat/Fixture/FixtureContext.php"]
    _write(fixture["strip_path"], strip)
    _write(fixture["root"] + "/artifacts/alias_table.json", {})
    auto_path = fixture["root"] + "/artifacts/autowirable_types.json"
    if autowire:
        _write(auto_path, ["Fixture\\Service"])
    elif os.path.lexists(auto_path):
        os.unlink(auto_path)

    for row in rows:
        row.update({"project": "coreshop", "language": "php",
                    "framework": "behat"})
        row["item_id"] = row["item_id"].replace("python-docx/", "coreshop/")
    release_raw = b"".join(
        (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        .encode("utf-8") for row in rows)
    _write(args.release, release_raw, raw=True)

    campaign_doc = ledger.loads_exact_json(
        ledger.read_trusted_bytes(args.campaign, label="campaign"))
    campaign_doc["config_digest"] = ledger.raw_sha256(boundary_raw)[:16]
    _write(args.campaign, campaign_doc)


def _make(kind: str = "empty", *, count: int = 1,
          framework: str = "behave", autowire: bool = False):
    temporary = tempfile.TemporaryDirectory(prefix="r2t-ledger-i2-")
    fixture = ledger._build_selftest_fixture(temporary.name)
    fixture["args"] = _args(fixture, adapter=kind)
    rows = _release_rows(fixture, count)
    if framework == "behat":
        _behat(fixture, rows, autowire=autowire)
    else:
        from . import repo
        strip = ledger.loads_exact_json(
            ledger.read_trusted_bytes(fixture["strip_path"], label="strip"))
        strip["substrate_roots"] = list(repo.BEHAVE_SUBSTRATE_ROOTS)
        strip["substrate_volatile"] = sorted(repo.BEHAVE_SUBSTRATE_VOLATILE)
        strip["bytecode_roots"] = list(repo.BEHAVE_BYTECODE_ROOTS)
        _write(fixture["strip_path"], strip)
    _fixture_inputs(fixture, rows, kind)
    bundle = runner.construct_publication_run_plan(fixture["args"])
    fixture.update({"temporary": temporary, "rows": rows,
                    "bundle": bundle})
    return fixture


def _clear_run_evidence(fixture: dict, *, manifest: bool = True) -> None:
    paths = [fixture["receipt_path"], fixture["checkpoint_path"],
             fixture["result_path"]]
    if manifest:
        paths.append(fixture["worker_manifest_path"])
    paths.append(runner.publication_lock_path(fixture["result_path"]))
    for path in paths:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _row(bundle, ordinal: int, **changes) -> dict:
    value = {"item_id": bundle.item_ids[ordinal], "outcome": "passed",
             **bundle.stamp}
    value.update(changes)
    return value


def _resign_plan(plan: dict) -> None:
    plan["invocation_digest"] = ledger.domain_digest(
        ledger.RUN_INVOCATION_SCHEMA, plan["invocation"])
    plan["digest"] = ledger.semantic_digest(plan)


def _refused(callable_) -> bool:
    try:
        callable_()
    except (SystemExit, ledger.ResultLedgerRefused, ValueError, RuntimeError):
        return True
    return False


def _running(fixture: dict, *, fault=None):
    state = runner._RunShardLedger(fixture["bundle"], fault=fault)
    state.resolve()
    state.transition("running")
    return state


def _raw_projection(path: str) -> dict:
    with open(path, "rb") as handle:
        raw = handle.read()
    return {"path": path, "file_sha256": hashlib.sha256(raw).hexdigest()}


def _input_projection(role: str, logical_path: str, path: str) -> dict:
    with open(path, "rb") as handle:
        raw = handle.read()
    return {
        "role": role, "logical_path": logical_path, "path": path,
        "byte_length": len(raw),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _named_projection(values: dict) -> list[dict]:
    return [{
        "name": name,
        "value_json": json.dumps(
            values[name], sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False),
    } for name in sorted(values)]


def _complete_projection_matches(fixture: dict, adapter_name: str) -> bool:
    """Independently spell the entire one-row fixture run-plan projection."""
    bundle = fixture["bundle"]
    args = fixture["args"]
    plan = bundle.plan
    with open(args.campaign, "rb") as handle:
        campaign_raw = handle.read()
    campaign_doc = json.loads(campaign_raw)
    campaign_ref = _raw_projection(args.campaign)
    campaign_ref.update({
        "campaign_digest": campaign.campaign_digest(campaign_doc),
        "semantic_digest": ledger.semantic_digest(campaign_doc),
    })
    runtime_path = args.campaign + ".agent_runtime.json"
    with open(runtime_path, "rb") as handle:
        runtime_doc = json.load(handle)
    agent_runtime_ref = _raw_projection(runtime_path)
    agent_runtime_ref["agent_runtime_sha256"] = (
        campaign.agent_runtime_digest(runtime_doc))

    selected_ids = [fixture["rows"][0]["item_id"]]
    feature_relative = fixture["rows"][0]["provenance"]["file_path"]
    files = [
        _input_projection(
            "harness_strip_manifest", "strip_manifest.json",
            fixture["strip_path"]),
        _input_projection(
            "harness_feature", feature_relative,
            fixture["root"] + "/workspace/" + feature_relative),
    ]
    public_configuration = {}
    internal_kind = {
        "empty": "empty", "gold": "gold",
        "stripped-gold": "stripped_gold", "stub": "stub",
    }[adapter_name]
    if adapter_name == "gold":
        public_configuration["gold_root"] = fixture["root"] + "/gold"
        manifest_path = fixture["root"] + "/gold/manifest.json"
        with open(manifest_path, "rb") as handle:
            manifest = json.load(handle)
        record_name = manifest[selected_ids[0]]
        record_path = fixture["root"] + "/gold/" + record_name
        with open(record_path, "rb") as handle:
            record = json.load(handle)
        files.extend([
            _input_projection(
                "release_gold_manifest", "gold/manifest.json",
                manifest_path),
            _input_projection(
                "release_gold_record", "gold/" + record_name, record_path),
        ])
        for relative in sorted(set(record["files"])):
            files.append(_input_projection(
                "gold_source", relative,
                fixture["root"] + "/gold/" + relative))
    elif adapter_name in {"stripped-gold", "stub"}:
        files.append(_input_projection(
            "fixture_closures", "closures.json",
            fixture["root"] + "/artifacts/closures.json"))
        if adapter_name == "stripped-gold":
            public_configuration["gold_root"] = fixture["root"] + "/gold"
            files.append(_input_projection(
                "gold_source", "steps.py",
                fixture["root"] + "/gold/steps.py"))
    files.sort(key=lambda entry: (
        entry["role"], entry["logical_path"], entry["path"]))

    expected_runtime = fixture["receipt"]["execution"]["runtime"]
    harness = expected_runtime["identity"]["harness"]
    stamp = {
        "adapter": adapter_name,
        "adapter_version": None,
        "agent_system": None,
        "agent_timeout_seconds": None,
        "agent_version": None,
        "campaign_digest": campaign_ref["campaign_digest"],
        "comparison_class": None,
        "condition": campaign_doc["condition"],
        "coverage": campaign_doc["coverage"],
        "dataset_version": None,
        "execution_timeout_seconds": 60,
        "harness_commit": (
            None if harness["git_commit"] is None
            else harness["git_commit"][:7]),
        "harness_version": harness["version"],
        "keep_artifacts": None,
        "max_iterations": None,
        "max_tokens": None,
        "model": None,
        "native_budget": None,
        "of": 1,
        "prompt_digest": None,
        "protocol_deviations": None,
        "protocol_digest": campaign_doc["protocol_digest"],
        "protocol_version": campaign_doc["protocol_version"],
        "repeats": 1,
        "repro_check_count": 0,
        "sandboxed": False,
        "setting": None,
        "shard": 0,
        "subset_digest": None,
        "subset_id": None,
        "temperature": None,
        "trials": campaign_doc["trial_budget"],
    }
    invocation = {
        "schema": "r2t.run-invocation/v1",
        "selection": {"limit": None, "requested_item_ids": None},
        "effective_run_stamp": _named_projection(stamp),
        "adapter": {
            "kind": internal_kind,
            "name": adapter_name,
            "public_configuration": _named_projection(public_configuration),
            "secret_inputs": [],
            "files": files,
        },
        "resume": {
            "checkpoint_resume": True,
            "stale_running_suffix_adoption": True,
            "no_resume": False,
            "retry_failed": False,
        },
    }
    expected_plan = {
        "schema": "r2t.run-plan/v1",
        "campaign": campaign_ref,
        "campaign_agent_runtime": agent_runtime_ref,
        "release": _raw_projection(args.release),
        "boundary": _raw_projection(args.boundary),
        "profile": _raw_projection(args.profile),
        "protocol": None,
        "worker_manifest_path": fixture["worker_manifest_path"],
        "shard_index": 0,
        "shard_count": 1,
        "shard_rule": "sha1_item_id_mod_k",
        "workset": {
            "item_count": 1,
            "ordered_item_ids_digest": ledger.domain_digest(
                "r2t.ordered-item-ids/v1", selected_ids),
        },
        "invocation": invocation,
        "invocation_digest": ledger.domain_digest(
            "r2t.run-invocation/v1", invocation),
        "digest": "0" * 64,
    }
    expected_plan["digest"] = ledger.semantic_digest(expected_plan)
    expected_execution = {
        "attempt_id": campaign_doc["attempt_id"],
        "runtime": expected_runtime,
    }
    return plan == expected_plan and bundle.execution == expected_execution


def selftest() -> int:
    ok = True

    def check(name: str, condition: object, detail: str = "") -> None:
        nonlocal ok
        passed = bool(condition)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not passed else ""))
        ok = ok and passed

    # ------------------------------------ strip-substrate join (Java pairs)
    # Direct probes on `_verify_strip_substrate` with the two REAL released
    # moved-path sets (literals transcribed from the provided releases)
    # against the two in-repo boundaries.  The retired path equality refused
    # both real pairs and was satisfied only by fixtures built to satisfy
    # it; the structural join must VERIFY both and refuse every
    # cross-project pairing, the empty manifest, and a smuggled production
    # path.
    from ..core.boundary import load_boundary as _load_boundary_for_join
    _cfg_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "config")
    _alg_boundary = _load_boundary_for_join(
        os.path.join(_cfg_dir, "boundary_algorand.yml"))
    _epub_boundary = _load_boundary_for_join(
        os.path.join(_cfg_dir, "boundary_epubcheck.yml"))
    _alg_moved = [
        "src/test/java/com/algorand/algosdk/unit/ABIJson.java",
        "src/test/java/com/algorand/algosdk/unit/AlgodPaths.java",
        "src/test/java/com/algorand/algosdk/unit/AlgodResponses.java",
        "src/test/java/com/algorand/algosdk/unit/AtomicTxnComposer.java",
        "src/test/java/com/algorand/algosdk/unit/Base.java",
        "src/test/java/com/algorand/algosdk/unit/IndexerPaths.java",
        "src/test/java/com/algorand/algosdk/unit/IndexerResponses.java",
        "src/test/java/com/algorand/algosdk/unit/PathsShared.java",
        "src/test/java/com/algorand/algosdk/unit/ProgramSanityCheck.java",
        "src/test/java/com/algorand/algosdk/unit/Rekeying.java",
        "src/test/java/com/algorand/algosdk/unit/ResponsesShared.java",
        "src/test/java/com/algorand/algosdk/unit/TealSign.java",
        "src/test/java/com/algorand/algosdk/unit/TestSourceMap.java",
        "src/test/java/com/algorand/algosdk/integration/Applications.java",
        "src/test/java/com/algorand/algosdk/integration/AtomicTxnComposer.java",
        "src/test/java/com/algorand/algosdk/integration/Stepdefs.java",
        "src/test/java/com/algorand/algosdk/integration/TransientAccount.java",
        "src/test/java/com/algorand/algosdk/cucumber/shared/TransactionSteps.java",
    ]
    _epub_moved = [
        "src/test/java/org/w3c/epubcheck/container/FilenameCheckerSteps.java",
        "src/test/java/org/w3c/epubcheck/test/AssertionSteps.java",
        "src/test/java/org/w3c/epubcheck/test/CLISteps.java",
        "src/test/java/org/w3c/epubcheck/test/ExecutionSteps.java",
        "src/test/java/org/w3c/epubcheck/test/JSONReportAssertionSteps.java",
        "src/test/java/org/w3c/epubcheck/test/XMLReportAssertionSteps.java",
        "src/test/java/org/w3c/epubcheck/util/microsyntax/ViewportSteps.java",
        "src/test/java/org/w3c/epubcheck/url/URLFragmentSteps.java",
        "src/test/java/org/w3c/epubcheck/SharedParameterTypes.java",
    ]

    def _join_verifies(boundary, moved) -> bool:
        document = {
            "moved": list(moved),
            "moved_config": ["src/test/resources/cucumber.properties"],
        }
        try:
            ledger._verify_strip_substrate(document, boundary)
            return True
        except Exception:
            return False

    check("algorand boundary verifies its own released moved set",
          _join_verifies(_alg_boundary, _alg_moved))
    check("epubcheck boundary verifies its own released moved set",
          _join_verifies(_epub_boundary, _epub_moved))
    check("algorand boundary refuses epubcheck's moved set",
          not _join_verifies(_alg_boundary, _epub_moved))
    check("epubcheck boundary refuses algorand's moved set",
          not _join_verifies(_epub_boundary, _alg_moved))
    check("an empty moved list is refused -- the join cannot hold vacuously",
          not _join_verifies(_alg_boundary, []))
    check("a production path smuggled into moved is refused",
          not _join_verifies(_alg_boundary, _alg_moved + ["pom.xml"]))

    # ------------------------------------------------ closed projections
    expected_roles = {
        "empty": {"harness_feature", "harness_strip_manifest"},
        "gold": {"harness_feature", "harness_strip_manifest",
                 "release_gold_manifest", "release_gold_record",
                 "gold_source"},
        "stripped-gold": {"harness_feature", "harness_strip_manifest",
                           "fixture_closures", "gold_source"},
        "stub": {"harness_feature", "harness_strip_manifest",
                 "fixture_closures"},
    }
    projection_ok = True
    dynamic_ok = True
    for kind, wanted_roles in expected_roles.items():
        fixture = _make(kind)
        bundle = fixture["bundle"]
        adapter = bundle.plan["invocation"]["adapter"]
        roles = {entry["role"] for entry in adapter["files"]}
        projection_ok = projection_ok and roles == wanted_roles \
            and adapter["secret_inputs"] == [] \
            and bundle.plan["workset"]["item_count"] == 1 \
            and _complete_projection_matches(fixture, kind)
        built = runner._build_publication_adapter(bundle, fixture["args"])
        original_open = builtins.open
        try:
            builtins.open = lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("dynamic adapter read"))
            built(runner.task_view(bundle.selected_items[0]))
        except AssertionError:
            dynamic_ok = False
        finally:
            builtins.open = original_open
        fixture["temporary"].cleanup()
    check("all admitted fixture kinds pin the complete exact closed projection",
          projection_ok)
    check("all admitted fixture adapters execute from frozen bytes only",
          dynamic_ok)

    # A cucumber profile is admitted, but the publication route has no
    # frozen-bytes Java stub or strip producer: those two fixtures must
    # refuse at plan construction rather than hand back the PHP fixture.
    def cucumber_plan_refusal(kind: str) -> str:
        fixture = _make(kind)
        try:
            with open(fixture["args"].profile, "rb") as handle:
                profile_raw = handle.read()
            _write(fixture["args"].profile, profile_raw.replace(
                b"\nframework: behave\n", b"\nframework: cucumber\n"),
                raw=True)
            for row in fixture["rows"]:
                row["framework"] = "cucumber"
            _write(fixture["args"].release, b"".join(
                (json.dumps(row, sort_keys=True, separators=(",", ":"))
                 + "\n").encode("utf-8") for row in fixture["rows"]),
                raw=True)
            runner.construct_publication_run_plan(fixture["args"])
            return ""
        except (SystemExit, ledger.ResultLedgerRefused) as exc:
            return str(exc)
        finally:
            fixture["temporary"].cleanup()

    cucumber = {kind: cucumber_plan_refusal(kind)
                for kind in ("empty", "gold", "stub", "stripped-gold")}
    check("a cucumber publication plan admits empty and gold but refuses "
          "stub and stripped-gold",
          cucumber["empty"] == "" and cucumber["gold"] == ""
          and all("no frozen-bytes producer for framework 'cucumber'"
                  in cucumber[kind] for kind in ("stub", "stripped-gold")),
          repr(cucumber)[:400])

    shared_feature = _make("empty", count=2)
    shared_relative = shared_feature["rows"][0]["provenance"]["file_path"]
    shared_feature["rows"][1]["provenance"] = {
        "file_path": shared_relative, "line": 3}
    shared_feature["rows"][1]["item_id"] = (
        "python-docx/" + shared_relative + ":3")
    shared_raw = b"".join(
        (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        .encode("utf-8") for row in shared_feature["rows"])
    _write(shared_feature["args"].release, shared_raw, raw=True)
    shared_bundle = runner.construct_publication_run_plan(
        shared_feature["args"])
    shared_inputs = [
        entry for entry in shared_bundle.plan["invocation"]["adapter"]["files"]
        if entry["role"] == "harness_feature"]
    check("several selected scenarios bind one shared feature byte stream once",
          len(shared_bundle.item_ids) == 2 and len(shared_inputs) == 1
          and shared_inputs[0]["logical_path"] == shared_relative)
    shared_feature["temporary"].cleanup()

    behat_absent = _make("empty", framework="behat", autowire=False)
    absent_adapter = behat_absent["bundle"].plan["invocation"]["adapter"]
    absent_roles = {entry["role"] for entry in absent_adapter["files"]}
    absent_config = ledger._named_canonical_values(
        absent_adapter["public_configuration"], "test config")
    behat_present = _make("empty", framework="behat", autowire=True)
    present_adapter = behat_present["bundle"].plan["invocation"]["adapter"]
    present_roles = {entry["role"] for entry in present_adapter["files"]}
    present_config = ledger._named_canonical_values(
        present_adapter["public_configuration"], "test config")
    behave = _make("empty")
    behave_adapter = behave["bundle"].plan["invocation"]["adapter"]
    check("Behat binds alias and exact optional-autowire presence/absence",
          "harness_alias_table" in absent_roles
          and "harness_autowirable_types" not in absent_roles
          and absent_config == {"harness_autowirable_types_present": False}
          and "harness_autowirable_types" in present_roles
          and present_config == {"harness_autowirable_types_present": True})
    check("Behave carries no coordinator input or coordinator configuration",
          not ({"harness_alias_table", "harness_autowirable_types"}
               & {entry["role"] for entry in behave_adapter["files"]})
          and behave_adapter["public_configuration"] == [])
    behat_absent["temporary"].cleanup()
    behat_present["temporary"].cleanup()
    behave["temporary"].cleanup()

    maximal = _make("gold", framework="behat", autowire=True)
    base_execution = maximal["bundle"].execution
    base_plan = maximal["bundle"].plan
    every_missing_refuses = True
    for index in range(len(base_plan["invocation"]["adapter"]["files"])):
        mutant = copy.deepcopy(base_plan)
        mutant["invocation"]["adapter"]["files"].pop(index)
        _resign_plan(mutant)
        every_missing_refuses = every_missing_refuses and _refused(
            lambda m=mutant: runner._publication_bundle_from_documents(
                base_execution, m))
    extra = copy.deepcopy(base_plan)
    entry = copy.deepcopy(extra["invocation"]["adapter"]["files"][0])
    entry.update({"role": "unexpected", "logical_path": "unexpected.json"})
    extra["invocation"]["adapter"]["files"].append(entry)
    extra["invocation"]["adapter"]["files"].sort(
        key=lambda value: (value["role"], value["logical_path"], value["path"]))
    _resign_plan(extra)
    rebound = copy.deepcopy(base_plan)
    rebound_entry = next(
        value for value in rebound["invocation"]["adapter"]["files"]
        if value["path"] != maximal["root"] + "/gold/steps.py")
    rebound_entry["path"] = maximal["root"] + "/gold/steps.py"
    _resign_plan(rebound)
    check("every bound adapter input is required; extra and rebound inputs refuse",
          every_missing_refuses
          and _refused(lambda: runner._publication_bundle_from_documents(
              base_execution, extra))
          and _refused(lambda: runner._publication_bundle_from_documents(
              base_execution, rebound)))
    maximal["temporary"].cleanup()

    # ------------------------------------------------ selection / admission
    selection = _make("empty", count=3)
    args = selection["args"]
    args.item = [selection["rows"][2]["item_id"],
                 selection["rows"][0]["item_id"]]
    args.limit = 1
    selected = runner.construct_publication_run_plan(args)
    check("selector replay sorts its preimage but preserves release/shard order",
          selected.plan["invocation"]["selection"]["requested_item_ids"]
          == sorted(args.item)
          and selected.item_ids == [selection["rows"][0]["item_id"]])
    duplicate_args = copy.copy(args)
    duplicate_args.item = [args.item[0], args.item[0]]
    unknown_args = copy.copy(args)
    unknown_args.item = ["unknown:item"]
    limits_refuse = all(_refused(lambda value=value: (
        setattr(args, "limit", value), runner.construct_publication_run_plan(args)
    )) for value in (0, -1, True))
    check("duplicate/unknown selectors and nonpositive limits refuse",
          _refused(lambda: runner.construct_publication_run_plan(duplicate_args))
          and _refused(lambda: runner.construct_publication_run_plan(unknown_args))
          and limits_refuse)
    selection["temporary"].cleanup()

    contact = {"worker": 0, "harness": 0}
    from .. import cli
    from . import cli as bench_cli
    old_worker = bench_cli._require_bound_live_worker
    old_harness = bench_cli._harness
    bench_cli._require_bound_live_worker = lambda value: contact.__setitem__(
        "worker", contact["worker"] + 1)
    bench_cli._harness = lambda value: contact.__setitem__(
        "harness", contact["harness"] + 1)
    try:
        reserved_refuse = all(_refused(lambda name=name: bench_cli.cmd_run(
            SimpleNamespace(publication_v3=True, adapter=name)))
            for name in ("replay", "submitted", "openai", "openhands",
                         "aider"))
        parser_refuses = all(_refused(lambda name=name: cli.main(
            ["run", "--publication-v3", "--adapter", name]))
            for name in ("replay", "submitted"))
    finally:
        bench_cli._require_bound_live_worker = old_worker
        bench_cli._harness = old_harness
    check("every reserved adapter refuses before worker/harness contact",
          reserved_refuse and parser_refuses
          and contact == {"worker": 0, "harness": 0})

    # ------------------------------ section 16: the campaign static gate
    # Minted exactly as `cli` mints a v2 campaign, probe-built companion
    # beside it, so the coordinator re-probe reports no difference and the
    # only identities left for the gate are the recipe and the harness pair.
    import sys
    from .campaign import (
        NO_DATABASE, SHARD_RULE, agent_runtime_digest,
        generation_fingerprint, harness_commit_identity,
        harness_source_digest, probe_agent_runtime)
    from .validate import HARNESS_VERSION
    gate = _make("empty")
    with open(gate["args"].boundary, "rb") as handle:
        gate_config_digest = hashlib.sha256(handle.read()).hexdigest()[:16]
    gate_runtime = probe_agent_runtime(
        interpreter=sys.executable, network_semantics="fixture_no_egress",
        agent_system=None)
    gate_campaign = generation_fingerprint(
        campaign_id="gate", k_workers=1, shard_rule=SHARD_RULE,
        trial_budget=0, condition=None, coverage=False,
        harness_version=HARNESS_VERSION, config_digest=gate_config_digest,
        model=None, container_image_digest="sha256:" + "a" * 64,
        workspace_seed_digest="b" * 64, database_dump_digest=NO_DATABASE,
        protocol_version=None, protocol_digest=None, agent_system=None,
        attempt_id="gate-attempt",
        harness_commit=harness_commit_identity(),
        harness_source_sha256=harness_source_digest(),
        agent_runtime_sha256=agent_runtime_digest(gate_runtime),
        network_semantics="fixture_no_egress")

    def gate_campaign_file(name: str, document: dict) -> str:
        path = gate["root"] + "/" + name
        _write(path + ".agent_runtime.json", gate_runtime)
        _write(path, document)
        return path

    def gate_outcome(path: str, *, of: int) -> tuple:
        args = SimpleNamespace(
            cmd="run", shard=0, worker=gate["spec_path"], campaign=path,
            of=of, trials=0, coverage=False, condition=None, model=None,
            adapter="gold", protocol_version=None, protocol_digest=None,
            boundary=gate["args"].boundary, profile=gate["args"].profile,
            gold=gate["root"] + "/gold",
            artifacts=gate["root"] + "/artifacts")
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                bench_cli._require_bound_live_worker(args)
        except SystemExit as exc:
            return str(exc), stderr.getvalue()
        return "", stderr.getvalue()

    config_message, config_notes = gate_outcome(
        gate_campaign_file("gate-config.json",
                           {**gate_campaign, "config_digest": "0" * 16}),
        of=1)
    version_message, _version_notes = gate_outcome(
        gate_campaign_file("gate-version.json",
                           {**gate_campaign,
                            "harness_version": HARNESS_VERSION + 1}),
        of=1)
    # `--of 2` against `k_workers=1` is refused by `_check_campaign_flags`,
    # which runs AFTER the static gate and before any worker or Docker
    # contact: reaching it proves the gate was passed.
    drifted_message, drifted_notes = gate_outcome(
        gate_campaign_file("gate-drifted.json",
                           {**gate_campaign, "harness_commit": "f" * 40,
                            "harness_source_sha256": "f" * 64}),
        of=2)
    same_message, same_notes = gate_outcome(
        gate_campaign_file("gate-campaign.json", gate_campaign), of=2)
    check("the campaign static gate refuses a changed config_digest or "
          "harness version before Docker contact and names it",
          "campaign static execution identity differs" in config_message
          and "config_digest" in config_message
          and "harness" not in config_message
          and "campaign static execution identity differs" in version_message
          and "harness_version" in version_message,
          (config_message + " / " + version_message)[:300])
    check("a campaign minted at another commit and source passes the static "
          "gate with one drift note and reaches the flag crosscheck",
          "static execution identity" not in drifted_message
          and "k_workers=1" in drifted_message
          and drifted_notes.count("note: harness recorded at") == 1,
          (drifted_message + " / " + drifted_notes)[:300])
    check("the campaign minted by this tree reaches the same crosscheck "
          "without a note",
          "k_workers=1" in same_message and same_notes == "",
          (same_message + " / " + same_notes)[:300])
    gate["temporary"].cleanup()

    # --------------------------------------- shipped legacy strip documents
    def legacy_strip_fixture(project: str, *, count: int = 1):
        framework = "behat" if project == "coreshop" else "behave"
        fixture = _make("empty", count=count, framework=framework)
        document = ledger.loads_exact_json(
            ledger.read_trusted_bytes(
                fixture["strip_path"], label="legacy strip fixture"))
        missing = ({"build_roots"} if project == "python-docx" else {
            "substrate_roots", "substrate_volatile",
            "bytecode_roots", "build_roots"})
        for name in missing:
            del document[name]
        document["gold_root"] = {
            "python-docx": "/data2/binhang/req2test_docx_bench/gold",
            "coreshop": "/data2/binhang/coreshop_bench/gold",
        }[project]
        _write(fixture["strip_path"], document)
        fixture["bundle"] = runner.construct_publication_run_plan(
            fixture["args"])
        return fixture

    legacy_harnesses = []
    legacy_rehydrated = []
    for project in ("python-docx", "coreshop"):
        fixture = legacy_strip_fixture(project)
        bundle = fixture["bundle"]
        runner._install_publication_harness_context(bundle, fixture["args"])
        harness, boundary, manifest = bench_cli._harness(fixture["args"])
        legacy_harnesses.append(
            harness.root == fixture["root"] + "/workspace"
            and boundary.project == project
            and manifest.gold_root == fixture["root"] + "/gold"
            and manifest.build_roots == [])
        if project == "coreshop":
            from . import repo
            legacy_harnesses[-1] = (
                legacy_harnesses[-1]
                and manifest.substrate_roots == []
                and manifest.substrate_volatile == []
                and manifest.bytecode_roots == []
                and manifest.roots() == repo.SUBSTRATE_ROOTS
                and manifest.volatile() == repo.SUBSTRATE_VOLATILE)

        replayed = runner._publication_bundle_from_documents(
            bundle.execution, bundle.plan)
        runner._install_publication_harness_context(
            replayed, fixture["args"])
        replay_harness, replay_boundary, replay_manifest = bench_cli._harness(
            fixture["args"])
        legacy_rehydrated.append(
            replay_harness.root == harness.root
            and replay_boundary.project == boundary.project
            and replay_manifest == manifest
            and replayed.strip_document
            == replayed.context.strip_document)
        fixture["temporary"].cleanup()
    check("both shipped legacy shapes build the actual relocated harness",
          all(legacy_harnesses))
    check("checkpoint rehydration consumes the same verified strip document",
          all(legacy_rehydrated))

    resumed = legacy_strip_fixture("python-docx", count=2)
    _clear_run_evidence(resumed)
    built_manifests = []

    def resumed_harness():
        value = bench_cli._harness(resumed["args"])
        built_manifests.append(copy.deepcopy(value[2]))
        return value

    def resumed_live():
        return {"publication_runtime_reference":
                resumed["args"]._publication_run_plan.execution["runtime"]}

    generated = []

    def interrupt_after_one(item):
        if not generated:
            generated.append(item["item_id"])
            return {"item_id": item["item_id"], "outcome": "passed"}
        raise KeyboardInterrupt("source-only resume probe")

    interrupted = False
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_publication_v3(
                resumed["args"], harness_factory=resumed_harness,
                live_validator=resumed_live,
                row_producer=interrupt_after_one)
    except KeyboardInterrupt:
        interrupted = True
    with contextlib.redirect_stdout(io.StringIO()):
        completed = runner.run_publication_v3(
            resumed["args"], harness_factory=resumed_harness,
            live_validator=resumed_live,
            row_producer=lambda item: {
                "item_id": item["item_id"], "outcome": "passed"})
    check("an interrupted shard resumes with the resolved legacy manifest",
          interrupted and completed["receipt"]["complete"]
          and len(built_manifests) == 2
          and all(value.gold_root == resumed["root"] + "/gold"
                  and value.build_roots == []
                  for value in built_manifests))
    resumed["temporary"].cleanup()

    # ------------------------------- section 16.5, option B: the tree moved
    # A shard paused after one row, then the checkpoint's recorded harness
    # pair rewritten and re-signed to another well-formed pair (what a merge
    # under the paused shard does to the live pair), and the resuming
    # process's own short commit changed: the resume adopts the recorded
    # identity, the two rows keep their own commits, the receipt lists both.
    moved = _make("empty", count=2)
    _clear_run_evidence(moved)

    def moved_live():
        return {"publication_runtime_reference":
                moved["args"]._publication_run_plan.execution["runtime"]}

    moved_produced = []

    def moved_interrupt_after_one(item):
        if not moved_produced:
            moved_produced.append(item["item_id"])
            return {"item_id": item["item_id"], "outcome": "passed"}
        raise KeyboardInterrupt("section 16.5 resume probe")

    moved_interrupted = False
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_publication_v3(
                moved["args"],
                harness_factory=lambda: bench_cli._harness(moved["args"]),
                live_validator=moved_live,
                row_producer=moved_interrupt_after_one)
    except KeyboardInterrupt:
        moved_interrupted = True
    moved_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            moved["checkpoint_path"], label="moved checkpoint"),
        label="moved checkpoint")
    moved_identity = moved_checkpoint["execution"]["runtime"]["identity"]
    recorded_pair = moved_identity["harness"]
    # The plan's 7-hex stamp is a within-plan prefix of the recorded commit.
    moved_identity["harness"] = {
        **recorded_pair,
        "git_commit": (None if recorded_pair["git_commit"] is None
                       else recorded_pair["git_commit"][:7] + "f" * 33),
        "source_sha256": "f" * 64,
    }
    moved_identity["digest"] = ledger.semantic_digest(moved_identity)
    moved_checkpoint["digest"] = ledger.semantic_digest(moved_checkpoint)
    _write(moved["checkpoint_path"], moved_checkpoint)
    original_harness_commit = runner._harness_commit
    runner._harness_commit = lambda: "fffffff"
    moved_stderr = io.StringIO()
    try:
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(moved_stderr):
            moved_completed = runner.run_publication_v3(
                moved["args"],
                harness_factory=lambda: bench_cli._harness(moved["args"]),
                live_validator=moved_live,
                row_producer=lambda item: {
                    "item_id": item["item_id"], "outcome": "passed"})
    finally:
        runner._harness_commit = original_harness_commit
    moved_rows = ledger._json_lines(
        ledger.read_trusted_bytes(moved["result_path"], label="moved rows"),
        "moved rows")
    first_commit = original_harness_commit()
    expected_commits = sorted({first_commit, "fffffff"} - {None})
    verify_stderr = io.StringIO()
    with contextlib.redirect_stderr(verify_stderr):
        moved_verified = ledger.verify_receipt(moved["receipt_path"])
    check("a paused shard resumes after its recorded harness pair moved, "
          "adopting the checkpoint's identity with one drift note",
          moved_interrupted and moved_completed["receipt"]["complete"]
          and moved_stderr.getvalue().count("note: harness recorded at") == 1,
          moved_stderr.getvalue()[:300])
    # The seal's own verification already said it once for this receipt, so
    # the re-verification above adds nothing: one note per process and path.
    row_notes = (moved_stderr.getvalue() + verify_stderr.getvalue()).count(
        "rows carry 2 harness commits")
    check("its rows keep the commit each was produced under, and the "
          "receipt verifier lists every distinct row commit, noted once",
          [row["harness_commit"] for row in moved_rows]
          == [first_commit, "fffffff"]
          and moved_verified["verified"]
          and moved_verified["row_harness_commits"] == expected_commits
          and row_notes == (1 if len(expected_commits) == 2 else 0),
          repr(([row["harness_commit"] for row in moved_rows],
                moved_verified["row_harness_commits"], row_notes))[:400])
    moved["temporary"].cleanup()

    def malformed_strip_refuses(project: str, missing: set[str], *,
                                extra: bool = False,
                                gold_root: str = "/build/project/gold") -> bool:
        framework = "behat" if project == "coreshop" else "behave"
        fixture = _make("empty", framework=framework)
        document = ledger.loads_exact_json(
            ledger.read_trusted_bytes(
                fixture["strip_path"], label="malformed strip fixture"))
        for name in missing:
            del document[name]
        if extra:
            document["future_roots"] = []
        document["gold_root"] = gold_root
        _write(fixture["strip_path"], document)
        refused = _refused(
            lambda: runner.construct_publication_run_plan(fixture["args"]))
        fixture["temporary"].cleanup()
        return refused

    check("nearby missing-field shapes and unknown fields still refuse",
          malformed_strip_refuses(
              "python-docx", {"build_roots", "bytecode_roots"})
          and malformed_strip_refuses("coreshop", {"build_roots"})
          and malformed_strip_refuses(
              "python-docx", {"build_roots"}, extra=True))
    check("a different or relative recorded gold directory still refuses",
          malformed_strip_refuses(
              "python-docx", {"build_roots"},
              gold_root="/build/project/not-gold")
          and malformed_strip_refuses(
              "python-docx", {"build_roots"},
              gold_root="relative/gold"))

    keep = SimpleNamespace(adapter="empty", keep_artifacts="",
                           no_resume=False, retry_failed=False,
                           repeats=1, timeout=1, repro_check=0)
    check("publication refuses --keep-artifacts even with an empty spelling",
          _refused(lambda: runner.construct_publication_run_plan(keep)))

    collisions = _make("empty")
    collision_refusal = True
    for path in (
            collisions["result_path"], collisions["checkpoint_path"],
            collisions["receipt_path"],
            runner.publication_lock_path(collisions["result_path"])):
        collision_args = copy.copy(collisions["args"])
        collision_args.worker_manifest = path
        collision_refusal = collision_refusal and _refused(
            lambda value=collision_args:
            runner.construct_publication_run_plan(value))
    check("WorkerManifest refuses every result/checkpoint/receipt/lock collision",
          collision_refusal)
    collisions["temporary"].cleanup()

    # ------------------------------------------------ initial crash windows
    initial_events = (
        "initial:before_draft", "result checkpoint:stage_fsync",
        "result checkpoint:commit", "result checkpoint:directory_fsync",
        "initial:after_draft", "initial:before_empty_result",
        "publication empty result:stage_fsync",
        "publication empty result:commit",
        "publication empty result:directory_fsync",
        "initial:after_empty_result",
    )
    initial_recovery = True
    for event in initial_events:
        fixture = _make("empty")
        _clear_run_evidence(fixture)
        def crash(value, target=event):
            if value == target:
                raise RuntimeError(target)
        state = runner._RunShardLedger(fixture["bundle"], fault=crash)
        try:
            state.resolve()
        except BaseException:
            pass
        recovered = runner._RunShardLedger(fixture["bundle"])
        try:
            document = recovered.resolve()
            initial_recovery = initial_recovery \
                and document["state"] == "draft" \
                and ledger.read_trusted_bytes(
                    fixture["result_path"], label="result") == b""
        except BaseException:
            initial_recovery = False
        fixture["temporary"].cleanup()
    check("every draft/empty-result crash window recovers without clobber",
          initial_recovery)

    fixture = _make("empty")
    _clear_run_evidence(fixture)
    _write(fixture["result_path"], b"", raw=True)
    check("an existing result without a checkpoint is never auto-bound",
          _refused(lambda: runner._RunShardLedger(
              fixture["bundle"]).resolve()))
    fixture["temporary"].cleanup()

    # -------------------------------- append ordering and stale adoption
    append_events = (
        "append:before_write", "append:after_write",
        "append:after_result_fsync", "append:before_checkpoint",
        "result checkpoint:stage_fsync", "result checkpoint:replace",
        "result checkpoint:directory_fsync", "append:after_checkpoint",
    )
    append_recovery = True
    no_truncation = True
    for event in append_events:
        fixture = _make("empty")
        _clear_run_evidence(fixture)
        state = _running(fixture)
        def crash(value, target=event):
            if value == target:
                raise RuntimeError(target)
        state.fault = crash
        try:
            state.append(_row(fixture["bundle"], 0))
        except BaseException:
            pass
        before = ledger.read_trusted_bytes(
            fixture["result_path"], label="crash result")
        try:
            recovered = runner._RunShardLedger(fixture["bundle"])
            document = recovered.resolve()
            recovered.adopt_pending_suffix()
            document = recovered.document
            expected = 0 if event == "append:before_write" else 1
            append_recovery = append_recovery \
                and document["result_prefix"]["row_count"] == expected
            no_truncation = no_truncation and ledger.read_trusted_bytes(
                fixture["result_path"], label="recovered result") == before
        except BaseException:
            append_recovery = False
        fixture["temporary"].cleanup()
    check("every append/fsync/checkpoint crash window resumes deterministically",
          append_recovery)
    check("crash recovery never truncates result bytes", no_truncation)

    ordering = _make("empty")
    _clear_run_evidence(ordering)
    state = _running(ordering)
    observed = []
    state.fault = observed.append
    state.append(_row(ordering["bundle"], 0))
    check("durable append orders result fsync before checkpoint staging",
          observed.index("append:after_result_fsync")
          < observed.index("append:before_checkpoint")
          < observed.index("result checkpoint:stage_fsync")
          < observed.index("result checkpoint:replace"))
    ordering["temporary"].cleanup()

    adoption_order = _make("empty")
    _clear_run_evidence(adoption_order)
    state = _running(adoption_order)
    row_bytes = (json.dumps(
        _row(adoption_order["bundle"], 0), sort_keys=True,
        separators=(",", ":")) + "\n").encode("utf-8")
    with open(adoption_order["result_path"], "ab") as handle:
        handle.write(row_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        runner.run_publication_v3(
            adoption_order["args"],
            harness_factory=lambda: bench_cli._harness(adoption_order["args"]),
            live_validator=lambda: (_ for _ in ()).throw(
                RuntimeError("live validation failed")),
            row_producer=lambda item: {})
    except RuntimeError:
        pass
    checkpoint = ledger.loads_exact_json(ledger.read_trusted_bytes(
        adoption_order["checkpoint_path"], label="checkpoint"))
    check("stale-running suffix adoption waits for complete live revalidation",
          checkpoint["state"] == "running"
          and checkpoint["result_prefix"]["row_count"] == 0
          and ledger.read_trusted_bytes(
              adoption_order["result_path"], label="result") == row_bytes)
    adoption_order["temporary"].cleanup()

    live_interrupt = _make("empty")
    _clear_run_evidence(live_interrupt)
    _running(live_interrupt)
    interrupted = False
    try:
        runner.run_publication_v3(
            live_interrupt["args"],
            harness_factory=lambda: bench_cli._harness(live_interrupt["args"]),
            live_validator=lambda: (_ for _ in ()).throw(
                KeyboardInterrupt()))
    except KeyboardInterrupt:
        interrupted = True
    interrupted_document = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            live_interrupt["checkpoint_path"], label="checkpoint"),
        label="checkpoint")
    check("KeyboardInterrupt during initial live validation becomes interrupted",
          interrupted and interrupted_document["state"] == "interrupted")
    live_interrupt["temporary"].cleanup()

    adoption_guard = _make("empty")
    _clear_run_evidence(adoption_guard)
    state = _running(adoption_guard)
    with open(adoption_guard["result_path"], "ab") as handle:
        handle.write((json.dumps(
            _row(adoption_guard["bundle"], 0), sort_keys=True,
            separators=(",", ":")) + "\n").encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
    recovered = runner._RunShardLedger(adoption_guard["bundle"])
    recovered.resolve()
    with open(adoption_guard["result_path"], "r+b") as handle:
        handle.truncate(0)
        handle.flush()
        os.fsync(handle.fileno())
    cached_refused = _refused(recovered.adopt_pending_suffix)
    unchanged_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            adoption_guard["checkpoint_path"], label="checkpoint"),
        label="checkpoint")["result_prefix"]["row_count"] == 0

    _clear_run_evidence(adoption_guard)
    state = _running(adoption_guard)
    with open(adoption_guard["result_path"], "ab") as handle:
        handle.write((json.dumps(
            _row(adoption_guard["bundle"], 0), sort_keys=True,
            separators=(",", ":")) + "\n").encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
    recovered = runner._RunShardLedger(adoption_guard["bundle"])
    recovered.resolve()
    adoption_events = []
    def adoption_race(event):
        adoption_events.append(event)
        if event == "result checkpoint:stage_fsync":
            with open(adoption_guard["result_path"], "r+b") as handle:
                handle.truncate(0)
                handle.flush()
                os.fsync(handle.fileno())
    recovered.fault = adoption_race
    race_refused = _refused(recovered.adopt_pending_suffix)
    guarded_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            adoption_guard["checkpoint_path"], label="checkpoint"),
        label="checkpoint")["result_prefix"]["row_count"] == 0
    check("suffix adoption re-reads/fsyncs result and guards checkpoint commit",
          cached_refused and unchanged_checkpoint and race_refused
          and guarded_checkpoint
          and adoption_events.index("adoption:after_result_fsync")
          < adoption_events.index("result checkpoint:stage_fsync"))
    adoption_guard["temporary"].cleanup()

    # ------------------------------------------------ suffix grammar attacks
    suffix_fixture = _make("empty", count=3)
    bundle = suffix_fixture["bundle"]
    canonical = _publication_row_bytes = lambda value: (
        json.dumps(value, sort_keys=True, separators=(",", ":"),
                   allow_nan=False) + "\n").encode("utf-8")
    first = canonical(_row(bundle, 0))
    wrong_stamp = _row(bundle, 0, adapter="gold")
    unknown = _row(bundle, 0, item_id="unknown:item")
    second_first = canonical(_row(bundle, 1))
    duplicate_key = first.replace(
        b'{', (b'{"item_id":"' + bundle.item_ids[0].encode()
               + b'",'), 1)
    nan_line = first.replace(b'"adapter":"empty"',
                             b'"adapter":"empty","probe":NaN')
    infinity_line = first.replace(b'"adapter":"empty"',
                                  b'"adapter":"empty","probe":Infinity')
    bad_suffixes = (
        b"{", first[:-1] + b"\r\n", b"\n", b"{]\n", duplicate_key,
        nan_line, infinity_line, canonical(wrong_stamp), canonical(unknown),
        first + first, second_first,
    )
    suffix_refusal = True
    suffix_preserved = True
    for raw in bad_suffixes:
        _clear_run_evidence(suffix_fixture)
        state = _running(suffix_fixture)
        with open(bundle.result_path, "ab") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        before = ledger.read_trusted_bytes(bundle.result_path, label="suffix")
        suffix_refusal = suffix_refusal and _refused(
            lambda: runner._RunShardLedger(bundle).resolve())
        suffix_preserved = suffix_preserved and ledger.read_trusted_bytes(
            bundle.result_path, label="suffix after refusal") == before
    check("partial/CRLF/blank/malformed/duplicate/nonfinite/wrong rows refuse",
          suffix_refusal)
    check("torn or invalid suffixes are preserved exactly, never repaired",
          suffix_preserved)

    _clear_run_evidence(suffix_fixture)
    state = _running(suffix_fixture)
    state.append(_row(bundle, 0))
    with open(bundle.result_path, "r+b") as handle:
        handle.truncate(max(0, state.document["result_prefix"]["byte_length"] - 1))
        handle.flush()
        os.fsync(handle.fileno())
    shortened = _refused(lambda: runner._RunShardLedger(bundle).resolve())
    _clear_run_evidence(suffix_fixture)
    state = _running(suffix_fixture)
    state.append(_row(bundle, 0))
    with open(bundle.result_path, "r+b") as handle:
        byte = handle.read(1)
        handle.seek(0)
        handle.write(b"[" if byte != b"[" else b"{")
        handle.flush()
        os.fsync(handle.fileno())
    drifted = _refused(lambda: runner._RunShardLedger(bundle).resolve())
    check("shortened results and committed-prefix drift refuse", shortened and drifted)

    nonrunning_suffix = True
    for stopped in ("draft", "interrupted", "failed"):
        _clear_run_evidence(suffix_fixture)
        state = runner._RunShardLedger(bundle)
        state.resolve()
        if stopped != "draft":
            state.transition("running")
            if stopped == "interrupted":
                state.transition("interrupted", reason="stop")
            else:
                state.transition("failed", reason="failure")
        with open(bundle.result_path, "ab") as handle:
            handle.write(first)
            handle.flush()
            os.fsync(handle.fileno())
        nonrunning_suffix = nonrunning_suffix and _refused(
            lambda: runner._RunShardLedger(bundle).resolve())
    check("suffixes from draft/interrupted/failed states all refuse",
          nonrunning_suffix)

    _clear_run_evidence(suffix_fixture)
    state = _running(suffix_fixture)
    state.transition("interrupted", reason="operator stop")
    resumed = runner._RunShardLedger(bundle)
    resumed.resolve()
    resumed.transition("running")
    state_ok = resumed.document["state"] == "running"
    resumed.transition("failed", reason="terminal producer failure")
    check("clean interrupted resumes, while failed is terminal",
          state_ok
          and _refused(lambda: runner._RunShardLedger(bundle).resolve())
          and _refused(lambda: resumed.append(_row(bundle, 0))))

    # Terminal is a WRITER rule, and only a writer rule.  Reading the state
    # back has to answer "failed" rather than raise, because the shard
    # inspector above `_RunShardLedger` classifies one shard at a time on
    # behalf of a coordinator that must still be able to see -- and reuse --
    # the shards beside it that sealed.  Every writer is checked here in the
    # same breath so that "the read now answers" can never quietly become
    # "the write now succeeds".
    try:
        terminal_read = runner._RunShardLedger(bundle).inspect_existing()
    except (SystemExit, ledger.ResultLedgerRefused) as exc:
        terminal_read = {"state": f"{type(exc).__name__}: {exc}",
                         "reason": None}
    check("a terminal failed checkpoint reads back as failed while resolve, "
          "append and transition all still refuse it",
          terminal_read["state"] == "failed"
          and terminal_read["reason"] == "terminal producer failure"
          and _refused(lambda: runner._RunShardLedger(bundle).resolve())
          and _refused(lambda: resumed.append(_row(bundle, 0)))
          and _refused(lambda: resumed.transition("running")),
          str(terminal_read["state"])[:120])
    suffix_fixture["temporary"].cleanup()

    terminal_seal = _make("empty")
    _clear_run_evidence(terminal_seal)
    state = _running(terminal_seal)
    state.append(_row(terminal_seal["bundle"], 0))
    state.transition("interrupted", reason="stop")
    interrupted_seal = _refused(lambda: runner._publication_seal(
        terminal_seal["bundle"], state, started_at="s", finished_at="f",
        live_validator=lambda: {"publication_runtime_reference":
                                terminal_seal["bundle"].execution["runtime"]},
        fault=None))
    state.transition("running")
    state.transition("failed", reason="terminal")
    failed_seal = _refused(lambda: runner._publication_seal(
        terminal_seal["bundle"], state, started_at="s", finished_at="f",
        live_validator=lambda: {"publication_runtime_reference":
                                terminal_seal["bundle"].execution["runtime"]},
        fault=None))
    check("only running checkpoints can seal; interrupted/failed are terminal",
          interrupted_seal and failed_seal
          and not os.path.lexists(terminal_seal["receipt_path"])
          and not os.path.lexists(terminal_seal["worker_manifest_path"]))
    terminal_seal["temporary"].cleanup()

    # ------------------------------------------------ lock / retry / default
    lock_fixture = _make("empty")
    _clear_run_evidence(lock_fixture)
    first_lock = runner._PublicationResultLock(lock_fixture["result_path"])
    first_lock.__enter__()
    try:
        competing = _refused(lambda: runner._PublicationResultLock(
            lock_fixture["result_path"]).__enter__())
    finally:
        first_lock.__exit__(None, None, None)
    alias_refuses = _refused(lambda: runner.publication_lock_path(
        os.path.dirname(lock_fixture["result_path"]) + "/./"
        + os.path.basename(lock_fixture["result_path"])))
    check("canonical result lock identity excludes aliases and competing writers",
          competing and alias_refuses)

    # ----------------------------------------- finalization / no-clobber
    final = _make("empty")
    _clear_run_evidence(final)
    state = _running(final)
    state.append(_row(final["bundle"], 0))
    live_calls = []
    def live():
        live_calls.append("live")
        return {"publication_runtime_reference":
                final["bundle"].execution["runtime"]}
    sealed = runner._publication_seal(
        final["bundle"], state,
        started_at="2026-08-07T00:00:00Z",
        finished_at="2026-08-07T00:01:00Z",
        live_validator=live, fault=None)
    manifest_info = os.lstat(final["worker_manifest_path"])
    manifest_before = ledger.read_trusted_bytes(
        final["worker_manifest_path"], label="WorkerManifest")
    manifest_record = campaign.WorkerManifest(
        shard=0, workspace=final["root"] + "/workspace",
        container="fixture_worker_0", schema="", credential="",
        out_path=final["result_path"],
        artifacts_root=final["root"] + "/artifacts",
        started_at="s", finished_at="f",
        campaign_digest=final["bundle"].plan["campaign"][
            "campaign_digest"])
    overwrite_manifest = _refused(lambda: campaign.write_worker_manifest(
        manifest_record, final["bundle"].context.campaign,
        final["worker_manifest_path"], durable_no_clobber=True))
    check("WorkerManifest creation is durable, owner-private, and no-clobber",
          sealed["complete"] and manifest_info.st_nlink == 1
          and (manifest_info.st_mode & 0o777) == 0o600
          and overwrite_manifest
          and ledger.read_trusted_bytes(
              final["worker_manifest_path"], label="WorkerManifest")
          == manifest_before)

    diagnostic_manifest = final["root"] + "/runs/diagnostic-worker.json"
    campaign.write_worker_manifest(
        manifest_record, final["bundle"].context.campaign,
        diagnostic_manifest)
    first_diagnostic = ledger.read_trusted_bytes(
        diagnostic_manifest, label="diagnostic WorkerManifest")
    changed_record = campaign.WorkerManifest(
        **{**manifest_record.__dict__, "finished_at": "later"})
    campaign.write_worker_manifest(
        changed_record, final["bundle"].context.campaign,
        diagnostic_manifest)
    check("diagnostic WorkerManifest writing preserves historical replacement",
          ledger.read_trusted_bytes(
              diagnostic_manifest, label="diagnostic WorkerManifest")
          != first_diagnostic)

    receipt_before = ledger.read_trusted_bytes(
        final["receipt_path"], label="receipt")
    receipt_overwrite = _refused(
        lambda: ledger.durable_create_bytes_no_clobber(
            final["receipt_path"], b"replacement",
            label="replacement receipt"))
    check("receipt publication is kernel no-clobber and preserves the winner",
          receipt_overwrite and ledger.read_trusted_bytes(
              final["receipt_path"], label="receipt") == receipt_before)

    counters = {"harness": 0, "live": 0}
    lock_before = os.path.lexists(runner.publication_lock_path(
        final["result_path"]))
    already = runner.run_publication_v3(
        final["args"],
        harness_factory=lambda: counters.__setitem__(
            "harness", counters["harness"] + 1),
        live_validator=lambda: counters.__setitem__(
            "live", counters["live"] + 1))
    check("an already-valid receipt is idempotent and read-only pre-contact",
          already["already_complete"] is True
          and counters == {"harness": 0, "live": 0}
          and not lock_before
          and not os.path.lexists(runner.publication_lock_path(
              final["result_path"])))

    active_lock = runner._PublicationResultLock(final["result_path"])
    active_lock.__enter__()
    try:
        in_flight_refused = _refused(lambda: runner.run_publication_v3(
            final["args"], harness_factory=lambda: None,
            live_validator=lambda: None))
    finally:
        active_lock.__exit__(None, None, None)
    check("a visible receipt is not accepted while another writer owns the lock",
          in_flight_refused)

    # A present stale receipt is authoritative failure, never checkpoint
    # fallback. Preserve the exact invalid bytes after the refusal.
    with open(final["receipt_path"], "r+b") as handle:
        handle.seek(0)
        handle.write(b"!")
        handle.flush()
        os.fsync(handle.fileno())
    stale = ledger.read_trusted_bytes(final["receipt_path"], label="stale")
    stale_refused = _refused(lambda: runner._publication_existing_receipt(
        final["result_path"]))
    check("lexically present stale receipt hard-refuses without fallback",
          stale_refused and ledger.read_trusted_bytes(
              final["receipt_path"], label="stale") == stale)
    final["temporary"].cleanup()

    # `--out` is pinned to the authenticated WorkerSpec.out_path, so the next
    # cell run on the same pool arrives at the same result path.  Receipt-first
    # resume must stay idempotent for the SAME cell and must never answer a
    # DIFFERENT one with the resident cell's sealed rows.
    occupied = _make("empty", count=2)
    _clear_run_evidence(occupied)
    occupied_args = occupied["args"]

    def occupied_run():
        return runner.run_publication_v3(
            occupied_args,
            harness_factory=lambda: bench_cli._harness(occupied_args),
            live_validator=lambda: {
                "publication_runtime_reference":
                occupied_args._publication_run_plan.execution["runtime"]},
            row_producer=lambda item: {"item_id": item["item_id"],
                                       "outcome": "passed"})

    occupied_args.item = [occupied["rows"][0]["item_id"]]
    with contextlib.redirect_stdout(io.StringIO()):
        sealed = occupied_run()
    first_plan = occupied_args._publication_run_plan.plan["digest"]
    resumed_same = occupied_run()
    occupied_args.item = [occupied["rows"][1]["item_id"]]
    second_plan = runner.construct_publication_run_plan(
        occupied_args).plan["digest"]
    try:
        occupied_run()
        different_cell = ""
    except (SystemExit, ledger.ResultLedgerRefused) as exc:
        different_cell = str(exc)
    with open(occupied["result_path"], encoding="utf-8") as handle:
        resident = [json.loads(line)["item_id"] for line in handle]
    check("a sealed cell resumes idempotently and refuses a different cell at "
          "the same result path, naming both plans",
          sealed["completed"] == 1
          and resumed_same["already_complete"] is True
          and first_plan != second_plan
          and first_plan in different_cell
          and second_plan in different_cell
          and resident == [occupied["rows"][0]["item_id"]],
          different_cell[:160])
    occupied["temporary"].cleanup()

    crash_manifest = _make("empty")
    _clear_run_evidence(crash_manifest)
    state = _running(crash_manifest)
    state.append(_row(crash_manifest["bundle"], 0))
    def crash_after_manifest(event):
        if event == "finalization:after_worker_manifest":
            raise RuntimeError(event)
    crashed = False
    try:
        runner._publication_seal(
            crash_manifest["bundle"], state,
            started_at="2026-08-07T00:00:00Z",
            finished_at="2026-08-07T00:01:00Z",
            live_validator=lambda: {
                "publication_runtime_reference":
                crash_manifest["bundle"].execution["runtime"]},
            fault=crash_after_manifest)
    except runner._PublicationInjectedCrash:
        crashed = True
    saved_manifest = ledger.read_trusted_bytes(
        crash_manifest["worker_manifest_path"], label="crash manifest")
    recovered = runner._publication_seal(
        crash_manifest["bundle"], state,
        started_at="different-diagnostic-start",
        finished_at="different-diagnostic-finish",
        live_validator=lambda: {
            "publication_runtime_reference":
            crash_manifest["bundle"].execution["runtime"]},
        fault=None)
    check("crash-after-manifest reuses the exact joined durable bytes",
          crashed and recovered["complete"]
          and ledger.read_trusted_bytes(
              crash_manifest["worker_manifest_path"],
              label="reused manifest") == saved_manifest)
    crash_manifest["temporary"].cleanup()

    receipt_crashes = True
    for crash_event, expect_receipt in (
            ("finalization:before_receipt_create", False),
            ("finalization:after_receipt_create", True)):
        fixture = _make("empty")
        _clear_run_evidence(fixture)
        state = _running(fixture)
        state.append(_row(fixture["bundle"], 0))
        def crash(event, target=crash_event):
            if event == target:
                raise RuntimeError(target)
        try:
            runner._publication_seal(
                fixture["bundle"], state,
                started_at="s", finished_at="f",
                live_validator=lambda: {
                    "publication_runtime_reference":
                    fixture["bundle"].execution["runtime"]}, fault=crash)
        except runner._PublicationInjectedCrash:
            pass
        present = os.path.lexists(fixture["receipt_path"])
        receipt_crashes = receipt_crashes and present is expect_receipt
        if present:
            receipt_crashes = receipt_crashes \
                and ledger.verify_receipt(fixture["receipt_path"])["complete"]
        else:
            receipt_crashes = receipt_crashes \
                and runner._publication_seal(
                    fixture["bundle"], state,
                    started_at="other", finished_at="other",
                    live_validator=lambda: {
                        "publication_runtime_reference":
                        fixture["bundle"].execution["runtime"]},
                    fault=None)["complete"]
        fixture["temporary"].cleanup()
    check("crashes immediately before/after receipt creation recover exactly",
          receipt_crashes)

    commit_crash = _make("empty")
    _clear_run_evidence(commit_crash)
    def commit_live():
        return {"publication_runtime_reference":
                commit_crash["args"]._publication_run_plan.execution[
                    "runtime"]}
    def crash_at_receipt_commit(event):
        if event == "result receipt:commit":
            raise RuntimeError(event)
    committed_then_crashed = False
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_publication_v3(
                commit_crash["args"],
                harness_factory=lambda: bench_cli._harness(
                    commit_crash["args"]),
                live_validator=commit_live,
                row_producer=lambda item: {
                    "item_id": item["item_id"], "outcome": "passed"},
                fault=crash_at_receipt_commit)
    except runner._PublicationInjectedCrash:
        committed_then_crashed = True
    recovery_calls = []
    original_receipt_fsync = runner._publication_fsync_existing_receipt
    def record_receipt_fsync(path):
        recovery_calls.append(path)
        return original_receipt_fsync(path)
    runner._publication_fsync_existing_receipt = record_receipt_fsync
    try:
        recovered_commit = runner.run_publication_v3(
            commit_crash["args"], harness_factory=lambda: None,
            live_validator=lambda: None)
    finally:
        runner._publication_fsync_existing_receipt = original_receipt_fsync
    check("receipt commit crash is file/directory-fsynced before idempotent return",
          committed_then_crashed
          and os.path.lexists(commit_crash["receipt_path"])
          and recovered_commit["already_complete"] is True
          and recovery_calls == [commit_crash["receipt_path"]])

    # Force the schedule where the pre-lock probe saw no receipt but the main
    # lock branch sees one committed by the preceding owner.
    original_pre_resolve = runner._publication_resolve_existing_receipt
    main_branch_fsync = []
    runner._publication_resolve_existing_receipt = lambda path: None
    runner._publication_fsync_existing_receipt = (
        lambda path: (main_branch_fsync.append(path),
                      original_receipt_fsync(path))[1])
    try:
        raced_commit = runner.run_publication_v3(
            commit_crash["args"], harness_factory=lambda: None,
            live_validator=lambda: None)
    finally:
        runner._publication_resolve_existing_receipt = original_pre_resolve
        runner._publication_fsync_existing_receipt = original_receipt_fsync
    check("main-lock receipt race also completes durability before return",
          raced_commit["already_complete"] is True
          and main_branch_fsync == [commit_crash["receipt_path"]])
    commit_crash["temporary"].cleanup()

    incomplete = _make("empty", count=2)
    _clear_run_evidence(incomplete)
    state = _running(incomplete)
    state.append(_row(incomplete["bundle"], 0))
    check("an incomplete workset cannot be sealed as a full claim",
          _refused(state.final_result)
          and not os.path.lexists(incomplete["receipt_path"]))
    wrong_order_append = _refused(
        lambda: state.append(_row(incomplete["bundle"], 0)))
    check("publication append enforces exact unique workset order",
          wrong_order_append)

    # Every non-time WorkerManifest join is checked on recovery, as is the
    # campaign document embedded beside it.
    result = _publication_result = runner._publication_result_binding(
        incomplete["result_path"],
        ledger.read_trusted_bytes(incomplete["result_path"], label="result"),
        1)
    base_worker = {
        "shard": 0, "workspace": incomplete["root"] + "/workspace",
        "container": "fixture_worker_0", "schema": "", "credential": "",
        "out_path": incomplete["result_path"],
        "artifacts_root": incomplete["root"] + "/artifacts",
        "started_at": "s", "finished_at": "f",
        "campaign_digest": incomplete["bundle"].plan["campaign"][
            "campaign_digest"],
    }
    manifest_join_refusal = True
    mutations = {
        "shard": 1,
        "workspace": incomplete["root"] + "/other-workspace",
        "container": "other-container", "schema": "other-schema",
        "credential": "other-user",
        "out_path": incomplete["root"] + "/runs/other.jsonl",
        "artifacts_root": incomplete["root"] + "/other-artifacts",
        "campaign_digest": "f" * 16,
        "finished_at": None,
    }
    for name, value in mutations.items():
        worker_value = dict(base_worker)
        worker_value[name] = value
        document = {
            "campaign": incomplete["bundle"].context.campaign,
            "campaign_digest": base_worker["campaign_digest"],
            "worker": worker_value,
        }
        _write(incomplete["worker_manifest_path"], document)
        manifest_join_refusal = manifest_join_refusal and _refused(
            lambda: runner._publication_verify_manifest(
                incomplete["bundle"], result))
        os.unlink(incomplete["worker_manifest_path"])
    wrong_campaign = copy.deepcopy(incomplete["bundle"].context.campaign)
    wrong_campaign["campaign_id"] = "other"
    _write(incomplete["worker_manifest_path"], {
        "campaign": wrong_campaign,
        "campaign_digest": base_worker["campaign_digest"],
        "worker": base_worker,
    })
    manifest_join_refusal = manifest_join_refusal and _refused(
        lambda: runner._publication_verify_manifest(
            incomplete["bundle"], result))
    check("every WorkerManifest runtime/result/campaign join refuses drift",
          manifest_join_refusal)
    incomplete["temporary"].cleanup()

    # ------------------------------------------------ storage attacks
    attacks = _make("empty")
    _clear_run_evidence(attacks)
    lock_path = runner.publication_lock_path(attacks["result_path"])
    sentinel = attacks["root"] + "/runs/sentinel"
    _write(sentinel, b"sentinel", raw=True)
    os.symlink(sentinel, lock_path)
    symlink_refused = _refused(lambda: runner._PublicationResultLock(
        attacks["result_path"]).__enter__())
    os.unlink(lock_path)
    os.link(sentinel, lock_path)
    hardlink_refused = _refused(lambda: runner._PublicationResultLock(
        attacks["result_path"]).__enter__())
    os.unlink(lock_path)

    unsafe = attacks["root"] + "/unsafe"
    os.makedirs(unsafe, mode=0o700)
    os.chmod(unsafe, 0o777)
    unsafe_refused = _refused(lambda: runner._PublicationResultLock(
        unsafe + "/result.jsonl").__enter__())
    os.chmod(unsafe, 0o700)

    from .. import docker_authority
    old_acl = docker_authority._acl_absent
    docker_authority._acl_absent = lambda *a, **k: False
    try:
        acl_refused = _refused(lambda: runner._PublicationResultLock(
            attacks["result_path"]).__enter__())
    finally:
        docker_authority._acl_absent = old_acl
    check("result locks reject symlink, hardlink, unsafe-directory, and ACL attacks",
          symlink_refused and hardlink_refused and unsafe_refused and acl_refused)

    target = attacks["root"] + "/runs/no-clobber.json"
    original_rename = primitives._rename_noreplace
    def racing_rename(parent_fd, source, destination, label):
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o600, dir_fd=parent_fd)
        os.write(fd, b"winner")
        os.fsync(fd)
        os.close(fd)
        return original_rename(parent_fd, source, destination, label)
    primitives._rename_noreplace = racing_rename
    try:
        race_refused = _refused(
            lambda: ledger.durable_create_bytes_no_clobber(
                target, b"loser", label="race target"))
    finally:
        primitives._rename_noreplace = original_rename
    check("no-clobber commit loses a TOCTOU race without overwriting winner",
          race_refused and ledger.read_trusted_bytes(
              target, label="race winner") == b"winner")

    _clear_run_evidence(attacks)
    state = _running(attacks)
    original_checkpoint = ledger.read_trusted_bytes(
        attacks["checkpoint_path"], label="checkpoint")
    changed = False
    def checkpoint_race(event):
        nonlocal changed
        if event == "result checkpoint:stage_fsync" and not changed:
            changed = True
            replacement = attacks["checkpoint_path"] + ".attacker"
            _write(replacement, original_checkpoint, raw=True)
            os.replace(replacement, attacks["checkpoint_path"])
    state.fault = checkpoint_race
    checkpoint_toctou = _refused(
        lambda: state.transition("interrupted", reason="stop"))
    check("checkpoint atomic replacement detects target-identity TOCTOU",
          checkpoint_toctou and state.document["state"] == "running")

    checkpoint_result_guard = _make("empty")
    _clear_run_evidence(checkpoint_result_guard)
    state = _running(checkpoint_result_guard)
    def erase_result_at_checkpoint(event):
        if event == "result checkpoint:stage_fsync":
            with open(checkpoint_result_guard["result_path"], "r+b") as handle:
                handle.truncate(0)
                handle.flush()
                os.fsync(handle.fileno())
    state.fault = erase_result_at_checkpoint
    append_result_race = _refused(
        lambda: state.append(_row(checkpoint_result_guard["bundle"], 0)))
    checkpoint_document = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            checkpoint_result_guard["checkpoint_path"], label="checkpoint"),
        label="checkpoint")

    _clear_run_evidence(checkpoint_result_guard)
    state = _running(checkpoint_result_guard)
    def extend_result_at_checkpoint(event):
        if event == "result checkpoint:stage_fsync":
            with open(checkpoint_result_guard["result_path"], "ab") as handle:
                handle.write(b"x")
                handle.flush()
                os.fsync(handle.fileno())
    state.fault = extend_result_at_checkpoint
    transition_result_race = _refused(
        lambda: state.transition("interrupted", reason="stop"))
    transition_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            checkpoint_result_guard["checkpoint_path"], label="checkpoint"),
        label="checkpoint")
    check("every checkpoint replacement guards the exact fsynced result",
          append_result_race
          and checkpoint_document["result_prefix"]["row_count"] == 0
          and transition_result_race
          and transition_checkpoint["state"] == "running")
    checkpoint_result_guard["temporary"].cleanup()

    # Mutating a final companion at the explicit pre-create seam is caught by
    # the second complete self-verification, so no stale receipt is minted.
    _clear_run_evidence(attacks)
    state = _running(attacks)
    state.append(_row(attacks["bundle"], 0))
    feature_entry = next(
        entry for entry in attacks["bundle"].plan["invocation"]["adapter"][
            "files"] if entry["role"] == "harness_feature")
    mutated = False
    def companion_race(event):
        nonlocal mutated
        if event == "finalization:before_receipt_create" and not mutated:
            mutated = True
            _write(feature_entry["path"], b"Feature: changed\n", raw=True)
    companion_toctou = _refused(lambda: runner._publication_seal(
        attacks["bundle"], state, started_at="s", finished_at="f",
        live_validator=lambda: {"publication_runtime_reference":
                                attacks["bundle"].execution["runtime"]},
        fault=companion_race))
    check("final companion TOCTOU refuses before receipt creation",
          companion_toctou and not os.path.lexists(attacks["receipt_path"]))
    attacks["temporary"].cleanup()

    lock_loss = _make("empty")
    _clear_run_evidence(lock_loss)
    replaced_lock = False
    def replace_owned_lock(event):
        nonlocal replaced_lock
        if event == "finalization:before_receipt_create" \
                and not replaced_lock:
            replaced_lock = True
            lock_path = runner.publication_lock_path(lock_loss["result_path"])
            replacement = lock_path + ".replacement"
            _write(replacement, b"", raw=True)
            os.replace(replacement, lock_path)
    def lock_loss_live():
        return {"publication_runtime_reference":
                lock_loss["args"]._publication_run_plan.execution["runtime"]}
    lock_loss_refused = _refused(lambda: runner.run_publication_v3(
        lock_loss["args"],
        harness_factory=lambda: bench_cli._harness(lock_loss["args"]),
        live_validator=lock_loss_live,
        row_producer=lambda item: {
            "item_id": item["item_id"], "outcome": "passed"},
        fault=replace_owned_lock))
    check("receipt commit refuses if canonical result-lock ownership is lost",
          replaced_lock and lock_loss_refused
          and not os.path.lexists(lock_loss["receipt_path"]))
    lock_loss["temporary"].cleanup()

    substrate = _make("empty", count=2)
    _clear_run_evidence(substrate)
    substrate_calls = []
    substrate_prepares = []
    substrate_verifies = []
    substrate_clears = []
    changed_relative = substrate["rows"][0]["provenance"]["file_path"]
    missing_relative = substrate["rows"][1]["provenance"]["file_path"]
    added_relative = "features/steps/generated.py"
    substrate_report = {
        "changed": [changed_relative],
        "missing": [missing_relative],
        "added": [added_relative],
    }
    changed_probe = substrate["root"] + "/workspace/" + changed_relative
    missing_probe = substrate["root"] + "/workspace/" + missing_relative
    removable_probe = substrate["root"] + "/workspace/" + added_relative

    class SubstrateHarness:
        def __init__(self, base, *, dirty_resume=False):
            self.root = base.root
            self.man = base.man
            self.boundary = base.boundary
            self.dirty_resume = dirty_resume

        def prepare_for_generation(self):
            substrate_prepares.append("prepare")
            if self.dirty_resume:
                from .repo import SubstrateTampered
                raise SubstrateTampered(copy.deepcopy(substrate_report))
            raise AssertionError("row producer unexpectedly called harness")

        def verify_substrate(self):
            substrate_verifies.append("verify")
            raise AssertionError(
                "known-dirty substrate stop reached post-loop verification")

        def clear_registration(self):
            substrate_clears.append("clear")

    dirty_resume = [False]

    def substrate_harness_factory():
        base, boundary, manifest = bench_cli._harness(substrate["args"])
        return (SubstrateHarness(base, dirty_resume=dirty_resume[0]),
                boundary, manifest)

    def substrate_live():
        return {"publication_runtime_reference":
                substrate["args"]._publication_run_plan.execution["runtime"]}

    def substrate_row(item):
        substrate_calls.append(item["item_id"])
        _write(
            changed_probe,
            ledger.read_trusted_bytes(
                changed_probe, label="selected feature before substrate dirt")
            + b"# retained feature change\n",
            raw=True)
        os.unlink(missing_probe)
        _write(removable_probe, b"retained for diagnosis\n", raw=True)
        return {
            "item_id": item["item_id"],
            "outcome": "substrate_violation",
            "substrate_violation": copy.deepcopy(substrate_report),
        }

    with contextlib.redirect_stdout(io.StringIO()):
        substrate_result = runner.run_publication_v3(
            substrate["args"],
            harness_factory=substrate_harness_factory,
            live_validator=substrate_live,
            row_producer=substrate_row)
    substrate_rows = ledger._json_lines(
        ledger.read_trusted_bytes(
            substrate["result_path"], label="substrate-stop result"),
        "substrate-stop result")
    substrate_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            substrate["checkpoint_path"], label="substrate-stop checkpoint"),
        label="substrate-stop checkpoint")
    substrate_reason = (
        "substrate violation after " + substrate["rows"][0]["item_id"]
        + ": " + json.dumps(
            substrate_report, sort_keys=True, separators=(",", ":")))
    check("a durable substrate row interrupts before the next publication item",
          substrate_calls == [substrate["rows"][0]["item_id"]]
          and len(substrate_rows) == 1
          and substrate_rows[0]["outcome"] == "substrate_violation"
          and substrate_rows[0]["substrate_violation"] == substrate_report
          and substrate_result["complete"] is False
          and substrate_result["completed"] == 1
          and substrate_result["missing"]
          == [substrate["rows"][1]["item_id"]]
          and substrate_result["outcomes"] == {"substrate_violation": 1}
          and substrate_result["receipt"] is None)
    check("the substrate stop retains its exact report and diagnostic state",
          substrate_result["terminal_reason"] == substrate_reason
          and substrate_checkpoint["state"] == "interrupted"
          and substrate_checkpoint["reason"] == substrate_reason
          and substrate_checkpoint["result_prefix"]["row_count"] == 1)
    check("substrate stop skips cleanup, reproduction, verification and seal",
          substrate_result["repro_check"] == {
              "checked": 0,
              "skipped": "substrate violation retained workspace",
          }
          and os.path.isfile(removable_probe)
          and os.path.isfile(changed_probe)
          and not os.path.lexists(missing_probe)
          and substrate_verifies == [] and substrate_clears == []
          and not os.path.lexists(substrate["receipt_path"])
          and not os.path.lexists(substrate["worker_manifest_path"]))

    dirty_resume[0] = True
    resumed_substrate = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_publication_v3(
                substrate["args"],
                harness_factory=substrate_harness_factory,
                live_validator=substrate_live)
    except BaseException as exc:
        resumed_substrate = exc
    resumed_rows = ledger._json_lines(
        ledger.read_trusted_bytes(
            substrate["result_path"], label="resumed substrate-stop result"),
        "resumed substrate-stop result")
    resumed_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            substrate["checkpoint_path"],
            label="resumed substrate-stop checkpoint"),
        label="resumed substrate-stop checkpoint")
    from .repo import SubstrateTampered
    check("dirty resume surfaces substrate diagnosis without a phantom row",
          isinstance(resumed_substrate, SubstrateTampered)
          and "evidence chain" not in str(resumed_substrate)
          and all(path in str(resumed_substrate)
                  for paths in substrate_report.values() for path in paths)
          and substrate_prepares == []
          and len(resumed_rows) == 1
          and resumed_checkpoint["state"] == "interrupted"
          and resumed_checkpoint["reason"] == substrate_reason
          and resumed_checkpoint["result_prefix"]["row_count"] == 1
          and not os.path.lexists(substrate["receipt_path"]))
    substrate["temporary"].cleanup()

    transition_stop = _make("empty", count=2)
    _clear_run_evidence(transition_stop)
    transition_calls = []
    transition_feature = (
        transition_stop["root"] + "/workspace/"
        + transition_stop["rows"][0]["provenance"]["file_path"])
    transition_report = {
        "changed": [transition_stop["rows"][0]["provenance"]["file_path"]],
        "missing": [], "added": [],
    }

    def transition_live():
        return {"publication_runtime_reference":
                transition_stop[
                    "args"]._publication_run_plan.execution["runtime"]}

    def transition_row(item):
        transition_calls.append(item["item_id"])
        _write(
            transition_feature,
            ledger.read_trusted_bytes(
                transition_feature,
                label="feature before transition-uncertainty dirt")
            + b"# transition uncertainty dirt\n",
            raw=True)
        return {
            "item_id": item["item_id"],
            "outcome": "substrate_violation",
            "substrate_violation": copy.deepcopy(transition_report),
        }

    transition_fault = {"armed": False, "fired": False}

    def fail_substrate_transition(event):
        if event == "transition:running:before:interrupted":
            transition_fault["armed"] = True
        elif transition_fault["armed"] \
                and not transition_fault["fired"] \
                and event == "result checkpoint:stage_fsync":
            transition_fault["fired"] = True
            raise OSError("one-shot interrupted checkpoint failure")

    transition_error = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_publication_v3(
                transition_stop["args"],
                harness_factory=lambda: bench_cli._harness(
                    transition_stop["args"]),
                live_validator=transition_live,
                row_producer=transition_row,
                fault=fail_substrate_transition)
    except BaseException as exc:
        transition_error = exc
    uncertain_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            transition_stop["checkpoint_path"],
            label="uncertain substrate transition checkpoint"),
        label="uncertain substrate transition checkpoint")
    transition_resume_error = None
    try:
        runner.run_publication_v3(
            transition_stop["args"],
            harness_factory=lambda: bench_cli._harness(
                transition_stop["args"]),
            live_validator=transition_live,
            row_producer=lambda item: transition_calls.append(item["item_id"]))
    except BaseException as exc:
        transition_resume_error = exc
    recovered_transition_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            transition_stop["checkpoint_path"],
            label="recovered substrate transition checkpoint"),
        label="recovered substrate transition checkpoint")
    transition_rows = ledger._json_lines(
        ledger.read_trusted_bytes(
            transition_stop["result_path"],
            label="transition-uncertain substrate result"),
        "transition-uncertain substrate result")
    transition_reason = (
        "substrate violation after " + transition_stop["rows"][0]["item_id"]
        + ": " + json.dumps(
            transition_report, sort_keys=True, separators=(",", ":")))
    check("a substrate transition write failure preserves stale running for "
          "diagnostic recovery instead of demoting the prefix to failed",
          transition_fault["fired"]
          and isinstance(
              transition_error,
              runner._PublicationSubstrateTransitionUncertain)
          and uncertain_checkpoint["state"] == "running"
          and uncertain_checkpoint["result_prefix"]["row_count"] == 1
          and isinstance(transition_resume_error, SubstrateTampered)
          and all(path in str(transition_resume_error)
                  for paths in transition_report.values() for path in paths)
          and recovered_transition_checkpoint["state"] == "interrupted"
          and recovered_transition_checkpoint["reason"] == transition_reason
          and recovered_transition_checkpoint["result_prefix"]["row_count"]
          == 1
          and len(transition_rows) == 1
          and transition_calls == [transition_stop["rows"][0]["item_id"]]
          and not os.path.lexists(transition_stop["receipt_path"]))
    transition_stop["temporary"].cleanup()

    def make_stale_substrate_stop():
        value = _make("empty", count=2)
        _clear_run_evidence(value)
        calls = []
        feature = (
            value["root"] + "/workspace/"
            + value["rows"][0]["provenance"]["file_path"])
        feature_raw = ledger.read_trusted_bytes(
            feature, label="feature before stale-running substrate stop")
        report = {
            "changed": [
                value["rows"][0]["provenance"]["file_path"]],
            "missing": [], "added": [],
        }

        def live():
            return {"publication_runtime_reference":
                    value[
                        "args"]._publication_run_plan.execution["runtime"]}

        def row(item):
            calls.append(item["item_id"])
            _write(
                feature,
                feature_raw + b"# stale-running substrate dirt\n",
                raw=True)
            return {
                "item_id": item["item_id"],
                "outcome": "substrate_violation",
                "substrate_violation": copy.deepcopy(report),
            }

        def crash_after_checkpoint(event):
            if event == "append:after_checkpoint":
                raise RuntimeError(event)

        error = None
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                runner.run_publication_v3(
                    value["args"],
                    harness_factory=lambda: bench_cli._harness(value["args"]),
                    live_validator=live,
                    row_producer=row,
                    fault=crash_after_checkpoint)
        except BaseException as exc:
            error = exc
        checkpoint = ledger.loads_exact_json(
            ledger.read_trusted_bytes(
                value["checkpoint_path"],
                label="stale-running substrate checkpoint"),
            label="stale-running substrate checkpoint")
        reason = (
            "substrate violation after " + value["rows"][0]["item_id"]
            + ": " + json.dumps(
                report, sort_keys=True, separators=(",", ":")))
        return {
            "value": value, "calls": calls, "feature": feature,
            "feature_raw": feature_raw, "report": report, "live": live,
            "error": error, "checkpoint": checkpoint, "reason": reason,
        }

    stale_stop = make_stale_substrate_stop()
    _write(stale_stop["feature"], stale_stop["feature_raw"], raw=True)
    stale_resume_calls = []

    def unexpected_stale_resume_row(item):
        stale_resume_calls.append(item["item_id"])
        return {"item_id": item["item_id"], "outcome": "passed"}

    with contextlib.redirect_stdout(io.StringIO()):
        stale_result = runner.run_publication_v3(
            stale_stop["value"]["args"],
            harness_factory=lambda: bench_cli._harness(
                stale_stop["value"]["args"]),
            live_validator=stale_stop["live"],
            row_producer=unexpected_stale_resume_row)
    stale_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            stale_stop["value"]["checkpoint_path"],
            label="recovered stale-running substrate checkpoint"),
        label="recovered stale-running substrate checkpoint")
    check("a stale-running substrate append completes its interrupted "
          "transition before a cleaned workspace can launch the suffix",
          isinstance(
              stale_stop["error"], runner._PublicationAppendUncertain)
          and stale_stop["checkpoint"]["state"] == "running"
          and stale_stop["checkpoint"]["result_prefix"]["row_count"] == 1
          and stale_stop["calls"]
          == [stale_stop["value"]["rows"][0]["item_id"]]
          and stale_resume_calls == []
          and stale_result["complete"] is False
          and stale_result["completed"] == 1
          and stale_result["missing"]
          == [stale_stop["value"]["rows"][1]["item_id"]]
          and stale_result["terminal_reason"] == stale_stop["reason"]
          and stale_result["receipt"] is None
          and stale_checkpoint["state"] == "interrupted"
          and stale_checkpoint["reason"] == stale_stop["reason"]
          and not os.path.lexists(stale_stop["value"]["receipt_path"]))
    stale_stop["value"]["temporary"].cleanup()

    stale_interrupt = make_stale_substrate_stop()
    _write(
        stale_interrupt["feature"], stale_interrupt["feature_raw"],
        raw=True)
    original_prior_substrate_stop = runner._publication_prior_substrate_stop
    recovery_interrupt = {"fired": False}

    def interrupt_during_stale_recovery(state):
        stop = original_prior_substrate_stop(state)
        if not recovery_interrupt["fired"]:
            recovery_interrupt["fired"] = True
            raise KeyboardInterrupt("signal during stale substrate recovery")
        return stop

    stale_recovery_error = None
    stale_recovery_calls = []
    runner._publication_prior_substrate_stop = \
        interrupt_during_stale_recovery
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_publication_v3(
                stale_interrupt["value"]["args"],
                harness_factory=lambda: bench_cli._harness(
                    stale_interrupt["value"]["args"]),
                live_validator=stale_interrupt["live"],
                row_producer=lambda item: stale_recovery_calls.append(
                    item["item_id"]))
    except BaseException as exc:
        stale_recovery_error = exc
    finally:
        runner._publication_prior_substrate_stop = \
            original_prior_substrate_stop
    stale_interrupt_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            stale_interrupt["value"]["checkpoint_path"],
            label="interrupted stale-recovery checkpoint"),
        label="interrupted stale-recovery checkpoint")
    stale_interrupt_rows = ledger._json_lines(
        ledger.read_trusted_bytes(
            stale_interrupt["value"]["result_path"],
            label="interrupted stale-recovery result"),
        "interrupted stale-recovery result")
    check("a signal during stale-running substrate recovery cannot replace "
          "the authenticated substrate reason",
          isinstance(stale_recovery_error, KeyboardInterrupt)
          and recovery_interrupt["fired"]
          and stale_recovery_calls == []
          and len(stale_interrupt_rows) == 1
          and stale_interrupt_checkpoint["state"] == "interrupted"
          and stale_interrupt_checkpoint["reason"]
          == stale_interrupt["reason"]
          and not os.path.lexists(
              stale_interrupt["value"]["receipt_path"]))
    stale_interrupt["value"]["temporary"].cleanup()

    live_failure_recovery = True
    for failure in (
            KeyboardInterrupt("signal during live revalidation"),
            RuntimeError("live revalidation failed")):
        stale_live_failure = make_stale_substrate_stop()
        _write(
            stale_live_failure["feature"],
            stale_live_failure["feature_raw"], raw=True)
        live_failure_calls = []

        def fail_live(error=failure):
            raise error

        live_failure_error = None
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                runner.run_publication_v3(
                    stale_live_failure["value"]["args"],
                    harness_factory=lambda value=stale_live_failure: (
                        bench_cli._harness(value["value"]["args"])),
                    live_validator=fail_live,
                    row_producer=lambda item: live_failure_calls.append(
                        item["item_id"]))
        except BaseException as exc:
            live_failure_error = exc
        live_failure_checkpoint = ledger.loads_exact_json(
            ledger.read_trusted_bytes(
                stale_live_failure["value"]["checkpoint_path"],
                label="live-failure stale substrate checkpoint"),
            label="live-failure stale substrate checkpoint")
        live_failure_rows = ledger._json_lines(
            ledger.read_trusted_bytes(
                stale_live_failure["value"]["result_path"],
                label="live-failure stale substrate result"),
            "live-failure stale substrate result")
        live_failure_recovery = live_failure_recovery and (
            isinstance(
                stale_live_failure["error"],
                runner._PublicationAppendUncertain)
            and isinstance(live_failure_error, type(failure))
            and live_failure_calls == []
            and len(live_failure_rows) == 1
            and live_failure_checkpoint["state"] == "interrupted"
            and live_failure_checkpoint["reason"]
            == stale_live_failure["reason"]
            and not os.path.lexists(
                stale_live_failure["value"]["receipt_path"]))
        stale_live_failure["value"]["temporary"].cleanup()
    check("a live-revalidation failure cannot replace a stale-running "
          "substrate stop or launch its suffix", live_failure_recovery)

    interrupted_stop = _make("empty", count=2)
    _clear_run_evidence(interrupted_stop)
    interrupted_calls = []
    interrupted_feature = (
        interrupted_stop["root"] + "/workspace/"
        + interrupted_stop["rows"][0]["provenance"]["file_path"])
    interrupted_feature_raw = ledger.read_trusted_bytes(
        interrupted_feature, label="feature before post-append interruption")
    interrupted_report = {
        "changed": [
            interrupted_stop["rows"][0]["provenance"]["file_path"]],
        "missing": [], "added": [],
    }

    def interrupted_live():
        return {"publication_runtime_reference":
                interrupted_stop[
                    "args"]._publication_run_plan.execution["runtime"]}

    def interrupted_row(item):
        interrupted_calls.append(item["item_id"])
        _write(
            interrupted_feature,
            interrupted_feature_raw + b"# post-append interruption dirt\n",
            raw=True)
        return {
            "item_id": item["item_id"],
            "outcome": "substrate_violation",
            "substrate_violation": copy.deepcopy(interrupted_report),
        }

    original_append = runner._RunShardLedger.append

    def interrupt_after_append(state, row):
        original_append(state, row)
        if row["outcome"] == "substrate_violation":
            raise KeyboardInterrupt("signal after durable substrate append")

    post_append_interrupt = None
    runner._RunShardLedger.append = interrupt_after_append
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_publication_v3(
                interrupted_stop["args"],
                harness_factory=lambda: bench_cli._harness(
                    interrupted_stop["args"]),
                live_validator=interrupted_live,
                row_producer=interrupted_row)
    except BaseException as exc:
        post_append_interrupt = exc
    finally:
        runner._RunShardLedger.append = original_append
    interrupted_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            interrupted_stop["checkpoint_path"],
            label="post-append interrupt checkpoint"),
        label="post-append interrupt checkpoint")
    interrupted_rows = ledger._json_lines(
        ledger.read_trusted_bytes(
            interrupted_stop["result_path"],
            label="post-append interrupt result"),
        "post-append interrupt result")
    interrupted_reason = (
        "substrate violation after "
        + interrupted_stop["rows"][0]["item_id"] + ": "
        + json.dumps(
            interrupted_report, sort_keys=True, separators=(",", ":")))
    interrupted_resume_error = None
    try:
        runner.run_publication_v3(
            interrupted_stop["args"],
            harness_factory=lambda: bench_cli._harness(
                interrupted_stop["args"]),
            live_validator=interrupted_live,
            row_producer=lambda item: interrupted_calls.append(item["item_id"]))
    except BaseException as exc:
        interrupted_resume_error = exc
    resumed_interrupted_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            interrupted_stop["checkpoint_path"],
            label="resumed post-append interrupt checkpoint"),
        label="resumed post-append interrupt checkpoint")
    check("an interrupt after the durable substrate append keeps the "
          "substrate report instead of a generic signal reason",
          isinstance(post_append_interrupt, KeyboardInterrupt)
          and len(interrupted_rows) == 1
          and interrupted_rows[0]["substrate_violation"]
          == interrupted_report
          and interrupted_checkpoint["state"] == "interrupted"
          and interrupted_checkpoint["reason"] == interrupted_reason
          and isinstance(interrupted_resume_error, SubstrateTampered)
          and "evidence chain" not in str(interrupted_resume_error)
          and resumed_interrupted_checkpoint["state"] == "interrupted"
          and resumed_interrupted_checkpoint["reason"]
          == interrupted_reason
          and interrupted_calls
          == [interrupted_stop["rows"][0]["item_id"]]
          and not os.path.lexists(interrupted_stop["receipt_path"]))

    _write(interrupted_feature, interrupted_feature_raw, raw=True)

    def interrupt_before_next_append(state, row):
        if row["item_id"] == interrupted_stop["rows"][1]["item_id"]:
            raise KeyboardInterrupt("signal before next item append")
        original_append(state, row)

    clean_resume_interrupt = None
    runner._RunShardLedger.append = interrupt_before_next_append
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_publication_v3(
                interrupted_stop["args"],
                harness_factory=lambda: bench_cli._harness(
                    interrupted_stop["args"]),
                live_validator=interrupted_live,
                row_producer=lambda item: (
                    interrupted_calls.append(item["item_id"])
                    or {"item_id": item["item_id"],
                        "outcome": "passed"}))
    except BaseException as exc:
        clean_resume_interrupt = exc
    finally:
        runner._RunShardLedger.append = original_append
    clean_resume_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            interrupted_stop["checkpoint_path"],
            label="clean-resume interrupt checkpoint"),
        label="clean-resume interrupt checkpoint")
    clean_resume_rows = ledger._json_lines(
        ledger.read_trusted_bytes(
            interrupted_stop["result_path"],
            label="clean-resume interrupt result"),
        "clean-resume interrupt result")
    check("an interrupt before a repaired resume appends its next row does "
          "not resurrect the prior substrate reason",
          isinstance(clean_resume_interrupt, KeyboardInterrupt)
          and clean_resume_checkpoint["state"] == "interrupted"
          and clean_resume_checkpoint["reason"]
          == "signal before next item append"
          and len(clean_resume_rows) == 1
          and interrupted_calls == [
              interrupted_stop["rows"][0]["item_id"],
              interrupted_stop["rows"][1]["item_id"],
          ]
          and not os.path.lexists(interrupted_stop["receipt_path"]))
    interrupted_stop["temporary"].cleanup()

    terminal_substrate = _make("empty")
    _clear_run_evidence(terminal_substrate)
    terminal_report = {
        "changed": ["src/final.py"], "missing": [], "added": [],
    }
    terminal_verifies = []
    terminal_clears = []

    class TerminalHarness:
        def __init__(self, base, *, dirty=False):
            self.root = base.root
            self.man = base.man
            self.boundary = base.boundary
            self.base = base
            self.dirty = dirty

        def clear_registration(self):
            terminal_clears.append("clear")
            return self.base.clear_registration()

        def verify_substrate(self):
            terminal_verifies.append("dirty" if self.dirty else "clean")
            if self.dirty:
                raise SubstrateTampered(copy.deepcopy(terminal_report))
            return self.base.verify_substrate()

    def terminal_harness_factory(*, dirty=False):
        base, boundary, manifest = bench_cli._harness(
            terminal_substrate["args"])
        return (TerminalHarness(base, dirty=dirty), boundary, manifest)

    def terminal_live():
        return {"publication_runtime_reference":
                terminal_substrate[
                    "args"]._publication_run_plan.execution["runtime"]}

    def terminal_row(item):
        return {
            "item_id": item["item_id"],
            "outcome": "substrate_violation",
            "substrate_violation": copy.deepcopy(terminal_report),
        }

    def crash_after_terminal_checkpoint(event):
        if event == "append:after_checkpoint":
            raise RuntimeError(event)

    terminal_crash = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_publication_v3(
                terminal_substrate["args"],
                harness_factory=terminal_harness_factory,
                live_validator=terminal_live,
                row_producer=terminal_row,
                fault=crash_after_terminal_checkpoint)
    except BaseException as exc:
        terminal_crash = exc
    crash_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            terminal_substrate["checkpoint_path"],
            label="terminal substrate crash checkpoint"),
        label="terminal substrate crash checkpoint")
    terminal_second_calls = []

    def unexpected_terminal_row(item):
        terminal_second_calls.append(item["item_id"])
        raise AssertionError("completed workset launched another item")

    with contextlib.redirect_stdout(io.StringIO()):
        terminal_result = runner.run_publication_v3(
            terminal_substrate["args"],
            harness_factory=terminal_harness_factory,
            live_validator=terminal_live,
            row_producer=unexpected_terminal_row)
    terminal_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            terminal_substrate["checkpoint_path"],
            label="recovered terminal substrate checkpoint"),
        label="recovered terminal substrate checkpoint")
    terminal_result_raw = ledger.read_trusted_bytes(
        terminal_substrate["result_path"],
        label="recovered terminal substrate result")
    terminal_reason = (
        "substrate violation after "
        + terminal_substrate["rows"][0]["item_id"] + ": "
        + json.dumps(
            terminal_report, sort_keys=True, separators=(",", ":")))
    check("a crash after the final substrate append cannot seal on resume",
          isinstance(terminal_crash, runner._PublicationAppendUncertain)
          and crash_checkpoint["state"] == "running"
          and crash_checkpoint["result_prefix"]["row_count"] == 1
          and terminal_second_calls == []
          and terminal_result["complete"] is False
          and terminal_result["completed"] == 1
          and terminal_result["missing"] == []
          and terminal_result["terminal_reason"] == terminal_reason
          and terminal_result["receipt"] is None
          and terminal_checkpoint["state"] == "interrupted"
          and terminal_checkpoint["reason"] == terminal_reason
          and terminal_verifies == []
          and terminal_clears == []
          and not os.path.lexists(terminal_substrate["receipt_path"]))

    terminal_dirty_error = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_publication_v3(
                terminal_substrate["args"],
                harness_factory=lambda: terminal_harness_factory(dirty=True),
                live_validator=terminal_live,
                row_producer=unexpected_terminal_row)
    except BaseException as exc:
        terminal_dirty_error = exc
    dirty_terminal_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            terminal_substrate["checkpoint_path"],
            label="dirty terminal substrate checkpoint"),
        label="dirty terminal substrate checkpoint")
    check("a still-dirty invocation after a final substrate violation "
          "reruns verification and remains interrupted without a launch",
          isinstance(terminal_dirty_error, SubstrateTampered)
          and terminal_second_calls == []
          and terminal_verifies == ["dirty"]
          and terminal_clears == []
          and dirty_terminal_checkpoint["state"] == "interrupted"
          and dirty_terminal_checkpoint["reason"] == terminal_reason
          and dirty_terminal_checkpoint["result_prefix"]["row_count"] == 1
          and ledger.read_trusted_bytes(
              terminal_substrate["result_path"],
              label="dirty terminal substrate result") == terminal_result_raw
          and not os.path.lexists(terminal_substrate["receipt_path"])
          and not os.path.lexists(
              terminal_substrate["worker_manifest_path"]))

    with contextlib.redirect_stdout(io.StringIO()):
        sealed_terminal_result = runner.run_publication_v3(
            terminal_substrate["args"],
            harness_factory=terminal_harness_factory,
            live_validator=terminal_live,
            row_producer=unexpected_terminal_row)
    sealed_terminal_checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            terminal_substrate["checkpoint_path"],
            label="sealed terminal substrate checkpoint"),
        label="sealed terminal substrate checkpoint")
    check("operator cleanup after a final substrate violation reruns "
          "verification and seals without relaunching the completed item",
          terminal_second_calls == []
          and terminal_verifies == ["dirty", "clean", "clean"]
          and terminal_clears == ["clear"]
          and sealed_terminal_result["complete"] is True
          and sealed_terminal_result["completed"] == 1
          and sealed_terminal_result["missing"] == []
          and sealed_terminal_result["terminal_reason"] is None
          and sealed_terminal_result["receipt"]["complete"] is True
          and sealed_terminal_checkpoint["state"] == "running"
          and ledger.read_trusted_bytes(
              terminal_substrate["result_path"],
              label="sealed terminal substrate result") == terminal_result_raw
          and os.path.isfile(terminal_substrate["worker_manifest_path"])
          and ledger.verify_receipt(
              terminal_substrate["receipt_path"])["complete"] is True)
    terminal_substrate["temporary"].cleanup()

    orchestration = _make("empty")
    _clear_run_evidence(orchestration)
    live_count = []
    def orchestration_live():
        live_count.append("live")
        return {"publication_runtime_reference":
                orchestration["args"]._publication_run_plan.execution[
                    "runtime"]}
    with contextlib.redirect_stdout(io.StringIO()):
        complete = runner.run_publication_v3(
            orchestration["args"],
            harness_factory=lambda: bench_cli._harness(orchestration["args"]),
            live_validator=orchestration_live,
            row_producer=lambda item: {
                "item_id": item["item_id"], "outcome": "passed"})
    check("explicit run orchestration validates live at start and seal",
          complete["receipt"]["complete"] and len(live_count) == 2
          and ledger.verify_receipt(
              orchestration["receipt_path"])["complete"]
          and ledger.verify_checkpoint(
              orchestration["checkpoint_path"])["state"] == "running")
    orchestration["temporary"].cleanup()

    _clear_run_evidence(lock_fixture)
    _write(lock_fixture["result_path"], b"", raw=True)
    callbacks = {"harness": 0, "live": 0}
    for flag in ("no_resume", "retry_failed"):
        setattr(lock_fixture["args"], flag, True)
        refused_bound = _refused(lambda: runner.run_publication_v3(
            lock_fixture["args"],
            harness_factory=lambda: callbacks.__setitem__(
                "harness", callbacks["harness"] + 1),
            live_validator=lambda: callbacks.__setitem__(
                "live", callbacks["live"] + 1)))
        check(f"bound publication refuses --{flag.replace('_', '-')}",
              refused_bound and callbacks == {"harness": 0, "live": 0})
        setattr(lock_fixture["args"], flag, False)

    old_require = bench_cli._require_bound_live_worker
    old_harness = bench_cli._harness
    old_run = runner.run_adapter
    diagnostic_result = lock_fixture["root"] + "/runs/diagnostic.jsonl"
    bench_cli._require_bound_live_worker = lambda value: {}
    bench_cli._harness = lambda value: (object(), object(), object())
    runner.run_adapter = lambda h, value, artifacts: {
        "adapter": "empty", "out": diagnostic_result,
        "repro_check": {}, "n": 0, "outcomes": {}, "artifacts": None,
        "shard": None, "of": None, "started_at": "s",
        "finished_at": "f", "seconds": 0.0,
    }
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            bench_cli.cmd_run(SimpleNamespace(
                publication_v3=False, artifacts=lock_fixture["root"],
                worker_manifest=None))
    finally:
        bench_cli._require_bound_live_worker = old_require
        bench_cli._harness = old_harness
        runner.run_adapter = old_run
    check("default run creates no checkpoint, receipt, result lock, or v3 status",
          not any(os.path.lexists(diagnostic_result + suffix) for suffix in (
              ledger.CHECKPOINT_SUFFIX, ledger.RECEIPT_SUFFIX,
              ".result-v3.lock")))
    lock_fixture["temporary"].cleanup()

    print("\n" + ("ALL PASS" if ok else "SELFTEST FAILED")
          + " (result_ledger_i2)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
