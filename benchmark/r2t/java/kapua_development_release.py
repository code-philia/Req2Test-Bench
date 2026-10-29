"""Kapua development N=3 preparation, exact worker union, and release assembly.

This is not the legacy research-minimal image chain or a publication approval.
Only ``validate-worker`` executes subjects; the other commands consume retained
inputs. Operator gates (reviewed tag, worker provisioning) still apply.
An escaping compiler timeout aborts its authenticated worker before host cleanup.
Source-only tests do not qualify a live run or bypass the operator gates.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

from . import kapua as K, kapua_runtime as KR, release_validation as RV
from ..bench.validate import HARNESS_VERSION
from ..bench.metrics import MIN_INFERENCE_CLUSTERS
from ..core.gherkin import parse_feature_file, standalone_feature

SCHEMA = "r2t.kapua-development-validation/1"
WORKERS, REPEATS, TIMEOUT, MIN_STEPS = 16, 3, 600, 2
MIN_CLUSTERS = MIN_INFERENCE_CLUSTERS


def require(condition, reason):
    if not condition:
        raise ValueError("REFUSED: Kapua development release " + reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def read(path):
    return json.loads(Path(path).read_bytes())


def reference(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def checked(ref):
    require(reference(ref["path"]) == ref, "input bytes changed: " + ref["path"])
    return Path(ref["path"])


def write(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def unique(rows, label):
    require(isinstance(rows, list) and all(isinstance(r, dict) for r in rows),
            label + " is not a row array")
    ids = [r.get("item_id") for r in rows]
    require(all(isinstance(i, str) and i.startswith("kapua/") for i in ids)
            and len(set(ids)) == len(ids), label + " has missing, duplicate or foreign IDs")
    return dict(zip(ids, rows))


def jsonl(path):
    return [json.loads(line) for line in Path(path).read_bytes().splitlines() if line.strip()]


def source_decisions(items, closures, quality):
    """The existing release predicates, evaluated before spending six runs."""
    ids = list(unique(items, "items"))
    by_id = unique(closures, "closures")
    require(set(by_id) == set(quality) and set(by_id) <= set(ids), "source controls omit or add native candidate IDs")
    decisions = {}
    item_map = {row["item_id"]: row for row in items}
    for iid in ids:
        if iid not in by_id:
            reason = ("requirement_task_deferred_in_v1" if item_map[iid]["task"] == "requirement_to_test"
                      else "outside_admitted_native_scope")
            decisions[iid] = {"stage": "source_excluded", "reasons": [reason]}
            continue
        cl, q = by_id[iid], quality[iid]
        require(isinstance(cl.get("files"), list)
                and len(cl["files"]) == len(set(cl["files"])), "closure files malformed")
        require(isinstance(q.get("live_effective_step_count"), int)
                and not isinstance(q["live_effective_step_count"], bool),
                "quality lacks measured effective steps")
        reasons = []
        if not cl["files"]:
            reasons.append("empty_closure")
        if cl["counts"]["steps_unmatched"]:
            reasons.append("unresolvable_step_definitions")
        if not q.get("has_oracle", False):
            reasons.append("no_oracle")
        if q.get("commented_out", False):
            reasons.append("commented_out")
        if q["live_effective_step_count"] < MIN_STEPS:
            reasons.append("thin_scenario_lt_2_effective_steps")
        decisions[iid] = {"stage": "source_excluded" if reasons else "validation",
                          "reasons": reasons}
    return decisions


def partitions(ids):
    require(len(ids) == len(set(ids)), "partition input repeats an ID")
    ordered = sorted(ids)
    return [ordered[index::WORKERS] for index in range(WORKERS)]


def projection_spec(source_root, closure):
    """Map the complete generated feature, including setup, to native source."""
    from ..bench.harness import Harness
    from ..stacks.cucumber import FEATURE_REL
    rel = closure["feature_file"]
    path = Path(source_root) / rel
    require(path.resolve().is_relative_to(Path(source_root).resolve()), "feature escapes source")
    feature = parse_feature_file(str(path), allow_tag_gaps=True)
    scenario = feature.scenario_at(closure["scenario_line"])
    require(scenario is not None, "source scenario is absent")
    text = standalone_feature(feature, scenario, prerequisite_tag="@setup", allow_tag_gaps=True)
    generated = parse_feature_file(FEATURE_REL, text=text, allow_tag_gaps=True)
    originals = [s for s in feature.scenarios if "@setup" in s.tags and s.line != scenario.line] + [scenario]
    require(len(generated.scenarios) == len(originals), "generated scenario membership differs")
    pairs = []
    for original, block in zip(originals, generated.scenarios):
        require(block.title == original.title and block.tags == original.tags,
                "generated scenario title/tags differ")
        old_lines = Harness._example_row_lines("\n".join(feature.lines), original.line) or [original.line]
        new_lines = Harness._example_row_lines(text, block.line) or [block.line]
        require(len(old_lines) == len(new_lines), "generated examples membership differs")
        pairs.extend({"observed": f"{FEATURE_REL}:{new}", "intended": f"{rel}:{old}",
                      "title": block.title} for old, new in zip(old_lines, new_lines))
    return {"feature_text": text, "pairs": sorted(pairs, key=lambda p: p["observed"]),
            "selected_line": generated.scenarios[-1].line,
            "expected_lines": [generated.scenarios[-1].line] + Harness._example_row_lines(text, generated.scenarios[-1].line)}


def runtime_projection(evidence, spec):
    """Re-derive identity from raw records; never replace records with census IDs."""
    from .closure_java import normalize_uri
    records = evidence.get("records")
    require(isinstance(records, list), "raw run has no records")
    observed = []
    titles = {}
    for r in records:
        require(isinstance(r, dict) and isinstance(r.get("scenario_line"), int), "malformed raw scenario")
        key = normalize_uri(r["feature_file"], "src/test/resources", "N3 feature") + ":" + str(r["scenario_line"])
        require(key not in titles, "raw run repeats a scenario")
        observed.append(key)
        titles[key] = r.get("scenario_title")
    observed.sort()
    expected = [p["observed"] for p in spec["pairs"]]
    matches = observed == expected and all(titles[p["observed"]] == p["title"] for p in spec["pairs"])
    require(evidence.get("expected_line") == spec["selected_line"]
            and evidence.get("expected_lines") == spec["expected_lines"], "selected generated lines differ")
    return {"pickle_ids": observed, "expected_pickle_ids": expected,
            "pickle_projection": [{k: p[k] for k in ("observed", "intended")} for p in spec["pairs"]] if matches else []}


def validate_source_population(source_root, rows, closures):
    from ..toolkit.extract import iter_feature_files, parse_feature
    original = {}
    for path in iter_feature_files(source_root):
        feature = parse_feature(Path(path).read_text(encoding="utf-8", errors="replace"))
        if not feature or not feature["scenarios"]:
            continue
        rel = str(Path(path).relative_to(source_root))
        original["kapua/" + rel] = "requirement_to_test"
        original.update((f"kapua/{rel}:{s['line']}", "criterion_to_test") for s in feature["scenarios"])
    require({r["item_id"]: r.get("task") for r in rows} == original
            and all(r.get("project") == "kapua" for r in rows),
            "items do not preserve the complete original Kapua extraction")
    native = {i: (f, s) for i, f, s in K.feature_items(source_root)}
    require(set(unique(closures, "closures")) == set(native), "closures are not the exact native624 candidates")
    for cl in closures:
        feature, scenario = native[cl["item_id"]]
        require(cl["feature_file"] == str(Path(feature.path).relative_to(source_root))
                and cl["scenario_line"] == scenario.line, "closure source identity differs")


def validate_gold(source_root, boundary, gold_root, closures):
    from ..core.boundary import REMOVABLE
    gold_root = Path(gold_root).resolve()
    strip = read(gold_root / "strip_manifest.json")
    require(isinstance(strip.get("digests"), dict) and strip["digests"], "strip lacks a substrate baseline")
    removed = {rel for rel in KR.source_inventory(source_root) if boundary.classify(rel) == REMOVABLE}
    require(set(strip["moved"]) == removed and len(strip["moved"]) == len(removed)
            and strip["moved_config"] == [] and removed,
            "gold strip differs from the original removable boundary")
    refs = {str(p.relative_to(gold_root)): reference(p) for p in sorted(gold_root.rglob("*")) if p.is_file()}
    require(set(refs) == removed | {"strip_manifest.json"}, "gold tree differs from exact strip membership")
    for rel in removed:
        require(refs[rel]["sha256"] == reference(Path(source_root) / rel)["sha256"],
                "gold bytes differ from original source")
    require(all(set(cl["files"]) <= removed for cl in closures), "closure includes a source absent from gold")
    return refs


def validate_profile(path):
    from ..data.profile import load_profile
    profile = load_profile(path)
    require(profile.project == "kapua" and profile.framework == "cucumber" and not profile.needs_database,
            "profile is not Kapua no-database Cucumber")
    return profile


def prepare(*, items, closures, quality, source_root, boundary, profile, native_capture, gold, out):
    from ..core.boundary import load_boundary
    b = load_boundary(boundary, repo_root=source_root)
    require(b.project == "kapua", "boundary is not Kapua")
    capture = KR.load_capture(native_capture, source_root=source_root, boundary=b)
    source_root = str(Path(source_root).resolve())
    rows, cls, q = jsonl(items), read(closures), read(quality)
    decisions = source_decisions(rows, cls, q)
    validate_source_population(source_root, rows, cls)
    gold_root = Path(gold).resolve()
    gold_refs = validate_gold(source_root, b, gold_root, cls)
    validate_profile(profile)
    plan = {"schema": SCHEMA, "kind": "plan", "project": "kapua", "route": "development",
            "workers": WORKERS, "repeats": REPEATS, "timeout_seconds": TIMEOUT,
            "min_live_steps": MIN_STEPS, "minimum_clusters": MIN_CLUSTERS,
            "source_root": str(Path(source_root).resolve()), "native_capture": str(Path(native_capture).resolve()),
            "capture_receipt": reference(Path(native_capture) / "receipt.json"),
            "image_id": capture["build"]["image_id"],
            "inputs": {name: reference(path) for name, path in {"items": items, "closures": closures,
                        "quality": quality, "boundary": boundary, "profile": profile}.items()},
            "gold_root": str(gold_root), "gold_files": gold_refs,
            "item_ids": [r["item_id"] for r in rows], "dispositions": decisions,
            "partitions": partitions([i for i, d in decisions.items() if d["stage"] == "validation"])}
    write(out, encoded(plan))
    return plan


def load_plan(path):
    plan = read(path)
    require(plan.get("schema") == SCHEMA and plan.get("kind") == "plan"
            and (plan["workers"], plan["repeats"], plan["timeout_seconds"], plan["min_live_steps"], plan["minimum_clusters"])
            == (WORKERS, REPEATS, TIMEOUT, MIN_STEPS, MIN_CLUSTERS), "plan contract differs")
    for ref in list(plan["inputs"].values()) + list(plan["gold_files"].values()) + [plan["capture_receipt"]]:
        checked(ref)
    rows = jsonl(plan["inputs"]["items"]["path"])
    decisions = source_decisions(rows, read(plan["inputs"]["closures"]["path"]), read(plan["inputs"]["quality"]["path"]))
    require(plan["item_ids"] == [r["item_id"] for r in rows] and plan["dispositions"] == decisions
            and plan["partitions"] == partitions([i for i, d in decisions.items() if d["stage"] == "validation"]),
            "plan population/partition differs")
    from ..core.boundary import load_boundary
    boundary = load_boundary(plan["inputs"]["boundary"]["path"], repo_root=plan["source_root"])
    require(boundary.project == "kapua", "plan boundary differs")
    validate_profile(plan["inputs"]["profile"]["path"])
    capture = KR.load_capture(plan["native_capture"], source_root=plan["source_root"], boundary=boundary)
    require(plan["capture_receipt"] == reference(Path(plan["native_capture"]) / "receipt.json"),
            "capture receipt routing differs")
    require(plan["gold_files"] == validate_gold(plan["source_root"], boundary, plan["gold_root"],
                                               read(plan["inputs"]["closures"]["path"])),
            "planned gold inventory differs")
    require(plan["image_id"] == capture["build"]["image_id"], "plan image differs")
    validate_source_population(plan["source_root"], rows, read(plan["inputs"]["closures"]["path"]))
    return plan, capture


class N3Executor:
    """Use the real harness's cleanup and timeout paths, retaining complete legs."""
    def __init__(self, harness, gold_root, *, worker_container):
        require(harness.runner.container == worker_container,
                "harness does not target the authenticated worker")
        self.harness, self.gold_root = harness, gold_root
        self.container = worker_container
        self.docker_group = harness.runner.docker_group
        self.compiler_timed_out = False
        self.cleanup_report = {}

    def execute(self, closure, observer):
        from ..bench.validate import validate_item
        observed = {}
        harness = self.harness

        class FullLogs:
            root = harness.root

            def run_solution(self, *args, **kwargs):
                result = harness.run_solution(*args, **kwargs, keep_stdout=True)
                for run in result["runs"]:
                    run["substrate_violation"] = result.get("substrate_violation")
                return result

        def observe(leg, runs):
            observed[leg] = runs
            observer(leg, runs)

        try:
            validate_item(FullLogs(), self.gold_root, closure, repeats=REPEATS, timeout=TIMEOUT,
                          complete_legs=True, run_observer=observe)
        except subprocess.TimeoutExpired as error:
            from ..stacks.cucumber import COMPILE_TIMEOUT
            # index_paths is the only 900-second operation in run_solution.
            # Test timeouts have the separate 600-second PID-cleanup path.
            self.compiler_timed_out = error.timeout == COMPILE_TIMEOUT
            raise
        return observed

    def close(self):
        from ..bench import repo
        if self.compiler_timed_out:
            self._abort_compiler()
            return
        repo.clean_workspace(self.harness.man, self.harness.boundary)
        self.harness.clear_registration()
        self.harness._remove_compiled_candidate_glue()
        self.harness.verify_substrate()

    def _abort_compiler(self):
        from ..bench import repo, worker
        from ..stacks.cucumber import TEST_OUTPUT_DIR
        report = self.cleanup_report = {
            "mode": "compile_timeout_worker_abort", "container": self.container,
            "worker_reusable": False, "container_absent": False,
            "host_cleanup_started": False,
        }
        report["termination_attempted"] = True
        report["removal_succeeded"] = worker.remove_container(
            self.container, docker_group=self.docker_group)
        require(report["removal_succeeded"], "timed-out worker removal failed")
        report["absence_check_attempted"] = True
        worker.require_container_absent(self.container, docker_group=self.docker_group)
        report["container_absent"] = True
        # The container is gone, including its private Maven cache. Only
        # host-visible worker files may be touched from this point onward.
        # clear_registration resets Liquibase through Docker: never call it.
        report["host_cleanup_started"] = True
        report["removed_sources"] = repo.clean_workspace(self.harness.man, self.harness.boundary)
        report["removed_run_files"] = self.harness._remove(
            list(K.FEATURE_PATHS) + self.harness._output_paths())
        report["removed_compiled_directories"] = []
        outputs = [rel.removesuffix("/src/main/java") + "/target" for rel in K.STEP_SOURCE_ROOTS]
        outputs += [module + "/" + TEST_OUTPUT_DIR for module in K.TEST_MODULES]
        for rel in outputs:
            path = Path(self.harness.root) / rel
            if path.exists():
                shutil.rmtree(path)
                report["removed_compiled_directories"].append(rel)
            require(not path.exists(), "compiled candidate output survived worker abort")
        self.harness.verify_substrate()


def exception_record(error):
    record = {"error": str(error), "type": type(error).__name__}
    if isinstance(error, subprocess.TimeoutExpired):
        record.update(command=error.cmd, timeout_seconds=error.timeout)
        for label, value in (("stdout", error.output), ("stderr", error.stderr)):
            # subprocess preserves timeout output as bytes even in text mode.
            record[label] = ({"base64": base64.b64encode(value).decode("ascii")}
                             if isinstance(value, bytes) else value)
    return record


def derive_row(iid, batches, spec, substrate):
    require(set(batches) == {"fail", "pass"} and all(len(batches[k]) == REPEATS for k in batches),
            iid + " lacks six raw executions")
    outcomes, projections, substrates = {}, [], []
    seconds = 0.0
    for leg in ("fail", "pass"):
        outcomes[leg] = []
        for run in batches[leg]:
            require(isinstance(run.get("outcome"), str), "raw outcome absent")
            require(not (run.get("timed_out") or run["outcome"] == "timeout")
                    or run.get("timeout_cleanup") == "killed", "timeout lacks killed cleanup")
            projection = runtime_projection(run, spec)
            projections.append(projection)
            substrates.append("changed" if run.get("substrate_violation") else substrate)
            outcomes[leg].append(run["outcome"])
            seconds += run.get("wall_seconds", 0)
    row = {"item_id": iid, "harness_version": HARNESS_VERSION,
           "fail_leg": {"outcome": outcomes["fail"][0], "outcomes_all_runs": outcomes["fail"]},
           "pass_leg": [{"outcome": o} for o in outcomes["pass"]], "seconds": seconds}
    row["admitted"], row["reason"] = RV._evidence_verdict(
        row, [p["pickle_ids"] for p in projections], [p["expected_pickle_ids"] for p in projections],
        [p["pickle_projection"] for p in projections], substrates, [p["intended"] for p in spec["pairs"]])
    if any(r.get("substrate_violation") for leg in batches.values() for r in leg):
        row["admitted"], row["reason"] = False, "altered_substrate"
    return row


def _produce_worker(plan_path, slot, root, *, executor, worker_identity):
    """Executor seam for the authenticated CLI; synthetic executors belong in tests."""
    plan, _ = load_plan(plan_path)
    require(type(slot) is int and 0 <= slot < WORKERS, "slot is outside 0..15")
    require(worker_identity["index"] == slot, "worker differs from assigned slot")
    cls = unique(read(plan["inputs"]["closures"]["path"]), "closures")
    rows, refs = [], {}
    for ordinal, iid in enumerate(plan["partitions"][slot]):
        refs[iid] = {}

        def persist(leg, runs):
            require(leg in ("fail", "pass") and leg not in refs[iid], "duplicate/foreign observed leg")
            refs[iid][leg] = []
            for repeat, run in enumerate(runs):
                path = root / "records" / f"{ordinal:06d}" / f"{leg}-{repeat}.json"
                write(path, encoded({"item_id": iid, "leg": leg, "repeat": repeat, "evidence": run}))
                ref = reference(path)
                ref["path"] = str(path.relative_to(root))
                refs[iid][leg].append(ref)

        # Each completed leg is durable before validate_item begins its next
        # leg. A later exception cannot discard the first three actual runs.
        batches = executor.execute(cls[iid], persist)
        require(set(refs[iid]) == set(batches), "executor did not preserve observed legs")
        row = derive_row(iid, batches, projection_spec(plan["source_root"], cls[iid]), worker_identity["substrate_sha256"])
        rows.append(row)
        print(f"worker {slot}: {ordinal + 1}/{len(plan['partitions'][slot])} {iid}: {row['reason'] or 'admitted'}", flush=True)
    write(root / "validation.jsonl", b"".join(encoded(r).replace(b'\n', b'') + b'\n' for r in rows))
    receipt = {"schema": SCHEMA, "kind": "worker", "plan": reference(plan_path), "slot": slot,
               "worker": worker_identity, "records": refs, "ledger_sha256": reference(root / "validation.jsonl")["sha256"]}
    return receipt


def produce_worker(plan_path, slot, out, *, executor, worker_identity):
    root = Path(out)
    root.mkdir(exist_ok=False)
    receipt, failure = None, None
    try:
        receipt = _produce_worker(plan_path, slot, root, executor=executor, worker_identity=worker_identity)
    except BaseException as error:
        failure = error
        write(root / "failure.json", encoded(exception_record(error)))
        raise
    finally:
        try:
            executor.close()
        except BaseException as error:
            write(root / "cleanup.json", encoded({**getattr(executor, "cleanup_report", {}),
                  "verified": False, **exception_record(error)}))
            # The original execution exception remains the raised failure;
            # cleanup failure has its own retained record and cannot admit it.
            if failure is None:
                raise
        else:
            write(root / "cleanup.json", encoded({**getattr(executor, "cleanup_report", {}),
                                                   "verified": True}))
    receipt["cleanup_sha256"] = reference(root / "cleanup.json")["sha256"]
    write(root / "receipt.json", encoded(receipt))
    return receipt


def validate_worker_identity(plan, identity):
    from ..bench import worker as W
    selected = W.validate_worker_runtime_v3(str(checked(identity["worker_spec"])),
                                            harness_version=HARNESS_VERSION, needs_database=False)
    spec = selected["worker"]
    require(identity["runtime"] == selected["runtime"] and identity["binding"] == selected["binding"]
            and identity["index"] == spec.index and identity["workspace"] == spec.workspace
            and identity["container"] == spec.container and spec.workdir == "/work"
            and identity["pool_digest"] == selected["binding"]["pool"]["digest"]
            and len(selected["binding"]["pool"]["workers"]) == WORKERS,
            "recorded worker differs from authenticated v3 inputs")
    capture = read(checked(plan["capture_receipt"]))
    KR.validate_live_runtime(capture, {"selected": selected})
    require(isinstance(identity["harness_commit"], str) and len(identity["harness_commit"]) == 40
            and isinstance(identity["harness_source_sha256"], str) and len(identity["harness_source_sha256"]) == 64
            and isinstance(identity["substrate_sha256"], str) and len(identity["substrate_sha256"]) == 64,
            "worker lacks producer/substrate identity")


def validate_worker(plan, plan_path, root):
    root = Path(root)
    receipt = read(root / "receipt.json")
    slot = receipt.get("slot")
    require(receipt.get("schema") == SCHEMA and receipt.get("kind") == "worker"
            and receipt["plan"] == reference(plan_path) and type(slot) is int and 0 <= slot < WORKERS,
            "worker receipt has another plan/slot")
    require(receipt["worker"]["index"] == slot and receipt["worker"]["image_id"] == plan["image_id"],
            "worker identity differs")
    require(reference(root / "cleanup.json")["sha256"] == receipt["cleanup_sha256"]
            and read(root / "cleanup.json") == {"verified": True}, "worker cleanup was not verified")
    validate_worker_identity(plan, receipt["worker"])
    rows = jsonl(root / "validation.jsonl")
    ids = list(unique(rows, "worker ledger"))
    require(ids == plan["partitions"][slot] and set(receipt["records"]) == set(ids),
            "worker ledger is not its exact ordered partition")
    require(reference(root / "validation.jsonl")["sha256"] == receipt["ledger_sha256"], "worker ledger bytes changed")
    cls = unique(read(plan["inputs"]["closures"]["path"]), "closures")
    seen = set()
    for row in rows:
        iid = row["item_id"]
        refs = receipt["records"][iid]
        require(set(refs) == {"fail", "pass"} and all(len(refs[k]) == REPEATS for k in refs), "raw references lack six runs")
        batches = {}
        for leg in ("fail", "pass"):
            batches[leg] = []
            for repeat, ref in enumerate(refs[leg]):
                path = Path(RV._regular_beneath(str(root / "records"), str(Path(ref["path"]).relative_to("records"))))
                require(str(path) not in seen, "raw record reused")
                seen.add(str(path))
                require(reference(path)["sha256"] == ref["sha256"], "raw record changed")
                record = read(path)
                require((record["item_id"], record["leg"], record["repeat"]) == (iid, leg, repeat), "raw record routing differs")
                batches[leg].append(record["evidence"])
        require(row == derive_row(iid, batches, projection_spec(plan["source_root"], cls[iid]),
                                  receipt["worker"]["substrate_sha256"]), "ledger disagrees with six raw runs")
    require({str(p) for p in (root / "records").rglob("*.json")} == seen, "unreferenced raw records")
    return receipt, rows


def collect_union(plan, plan_path, worker_dirs):
    require(len(worker_dirs) == WORKERS, "merge requires all 16 worker outputs")
    slots, rows, refs, identities = set(), {}, [], []
    for directory in worker_dirs:
        receipt, shard = validate_worker(plan, plan_path, directory)
        require(receipt["slot"] not in slots, "duplicate worker slot")
        slots.add(receipt["slot"])
        require(not set(rows).intersection(r["item_id"] for r in shard), "duplicate worker results")
        rows.update((r["item_id"], r) for r in shard)
        refs.append(reference(Path(directory) / "receipt.json"))
        identities.append(receipt["worker"])
    require(slots == set(range(WORKERS)), "worker union incomplete")
    require(len({w["pool_digest"] for w in identities}) == 1
            and len({w["harness_source_sha256"] for w in identities}) == 1
            and len({w["harness_commit"] for w in identities}) == 1,
            "workers have mixed pool or harness identities")
    require(len({w["workspace"] for w in identities}) == WORKERS
            and len({w["container"] for w in identities}) == WORKERS, "workers reuse a workspace/container")
    return [rows[i] for i in plan["item_ids"] if i in rows], refs


def merge(plan_path, worker_dirs, out):
    plan, _ = load_plan(plan_path)
    ordered, refs = collect_union(plan, plan_path, worker_dirs)
    root = Path(out)
    root.mkdir(exist_ok=False)
    write(root / "validation.jsonl", b"".join(json.dumps(r, sort_keys=True).encode() + b"\n" for r in ordered))
    doc = {"schema": SCHEMA, "kind": "complete-union", "plan": reference(plan_path), "workers": refs,
           "ledger_sha256": reference(root / "validation.jsonl")["sha256"]}
    write(root / "receipt.json", encoded(doc))
    return doc


def assemble(plan_path, merged, out):
    from ..toolkit.release_build import build_release
    from .kapua_population import release_file_manifest
    plan, _ = load_plan(plan_path)
    merged = Path(merged)
    union = read(merged / "receipt.json")
    require(union.get("schema") == SCHEMA and union.get("kind") == "complete-union"
            and union["plan"] == reference(plan_path), "assembly lacks complete union")
    # Re-read original raw evidence, not merely its merged summary.
    worker_dirs = [checked(ref).parent for ref in union["workers"]]
    expected, _ = collect_union(plan, plan_path, worker_dirs)
    rows = {row["item_id"]: row for row in expected}
    require(jsonl(merged / "validation.jsonl") == expected
            and reference(merged / "validation.jsonl")["sha256"] == union["ledger_sha256"],
            "merged ledger differs from worker union")
    decisions = json.loads(json.dumps(plan["dispositions"]))
    for iid, row in rows.items():
        decisions[iid] = {"stage": "released" if row["admitted"] else "validation_excluded",
                          "reasons": [] if row["admitted"] else ["round_trip:" + row["reason"]]}
    root = Path(out)
    root.mkdir(exist_ok=False)
    release = root / "release"
    info = build_release(str(merged), plan["inputs"]["items"]["path"], str(release), min_live_steps=MIN_STEPS,
                         project="kapua", items_name="items.jsonl", portable_paths=True,
                         closures_path=plan["inputs"]["closures"]["path"], quality_path=plan["inputs"]["quality"]["path"],
                         validation_path=str(merged / "validation.jsonl"), item_dispositions=decisions)
    controls = release / "control-artifacts"
    for name in ("items", "closures", "quality", "boundary", "profile"):
        suffix = Path(plan["inputs"][name]["path"]).suffix
        write(controls / ("source-" + name + suffix), checked(plan["inputs"][name]).read_bytes())
    # Original extraction bytes remain source-closures.json; this explicit
    # derived admission field is needed by the population consumer.
    closures = read(plan["inputs"]["closures"]["path"])
    for cl in closures:
        cl["admitted"] = decisions[cl["item_id"]]["stage"] == "released"
    write(controls / "closures.json", encoded(closures))
    write(controls / "validation.jsonl", (merged / "validation.jsonl").read_bytes())
    write(controls / "dispositions.json", encoded(decisions))
    write(controls / "validation-plan.json", Path(plan_path).read_bytes())
    write(controls / "validation-union.json", (merged / "receipt.json").read_bytes())
    for ref in union["workers"]:
        folder = checked(ref).parent
        slot = read(ref["path"])["slot"]
        shutil.copytree(folder, controls / "workers" / f"{slot:02d}")
    for rel, ref in plan["gold_files"].items():
        write(release / "reference-gold" / rel, checked(ref).read_bytes())
    ids = [r["item_id"] for r in jsonl(release / "items.jsonl")]
    require(ids == [i for i in plan["item_ids"] if decisions[i]["stage"] == "released"], "release IDs differ")
    manifest = release_file_manifest(release)
    manifest["released_item_ids"] = ids
    write(root / "release-manifest.json", encoded(manifest))
    passed = info["effective_closure_cardinality"] >= MIN_CLUSTERS
    receipt = {"schema": SCHEMA, "kind": "assembly", "status": "development_candidate_awaiting_review" if passed else "rejected_cluster_floor",
               "plan": reference(plan_path), "union": reference(merged / "receipt.json"),
               "release_manifest": reference(root / "release-manifest.json"), "summary": info,
               "cluster_floor_passed": passed, "approval_created": False}
    write(root / "assembly-receipt.json", encoded(receipt))
    return receipt


def run_worker(plan_path, worker_path, out, docker_authority):
    from ..core import docker_cli
    docker_cli.configure(authority_path=docker_authority)
    from ..bench import worker as W, campaign, repo
    from ..core.boundary import load_boundary
    from ..stacks.cucumber import make_harness
    plan, capture = load_plan(plan_path)
    spec = W.load_worker_spec(worker_path)
    profile = validate_profile(plan["inputs"]["profile"]["path"])
    require(profile.framework == "cucumber" and not profile.needs_database and spec.workdir == "/work", "worker/profile is not /work no-database Cucumber")
    args = SimpleNamespace(boundary=plan["inputs"]["boundary"]["path"], repo=spec.workspace,
                           gold=plan["gold_root"], workdir=spec.workdir, container=spec.container)
    boundary = load_boundary(args.boundary, repo_root=spec.workspace)
    runtime = W.validate_live_worker_runtime(worker_path, spec, HARNESS_VERSION, False,
                [plan_path, out, plan["gold_root"], *(r["path"] for r in plan["inputs"].values())],
                expected_pool_size=WORKERS, behat=repo.behat_project(boundary))
    KR.validate_live_runtime(capture, runtime)
    harness, _, man = make_harness(args)
    harness.verify_substrate()
    identity = {"index": spec.index, "workspace": spec.workspace, "container": spec.container,
                "image_id": plan["image_id"], "pool_digest": runtime["docker_execution_pool_digest"],
                "worker_spec": reference(worker_path),
                "harness_commit": campaign.harness_commit_identity(), "harness_source_sha256": campaign.harness_source_digest(),
                "substrate_sha256": hashlib.sha256(encoded(man.digests)).hexdigest(),
                "runtime": runtime["selected"]["runtime"], "binding": runtime["selected"]["binding"]}
    return produce_worker(plan_path, spec.index, out, executor=N3Executor(harness, args.gold, worker_container=spec.container), worker_identity=identity)


def selftest():
    """Explicitly synthetic artifacts; no subject, authority, pool or Docker."""
    import copy
    import csv
    import tempfile
    from unittest.mock import patch

    def refuses(fn, phrase):
        try:
            fn()
        except (ValueError, RV.JavaReleaseValidationRefused) as error:
            assert phrase in str(error), (phrase, str(error))
        else:
            raise AssertionError("accepted " + phrase)

    with tempfile.TemporaryDirectory(prefix="kapua-development-release-") as tmp:
        root = Path(tmp)
        source = root / "source"
        source.mkdir()
        text = "Feature: synthetic\n\n  @setup\n\n  Scenario: setup\n    Given retained setup\n\n  @target\n\n  Scenario: selected\n    When behavior\n    Then assertion\n\n  @teardown\n  Scenario: teardown\n    Then cleanup\n"
        feature = source / "item.feature"
        feature.write_text(text)
        closure = {"item_id": "kapua/item.feature:10", "feature_file": "item.feature", "scenario_line": 10,
                   "files": ["gold.java"], "di_fragment": {}, "context_classes": [], "counts": {"steps_unmatched": 0}}
        spec = projection_spec(source, closure)
        assert [p["intended"] for p in spec["pairs"]] == ["item.feature:5", "item.feature:10"]
        assert "teardown" not in spec["feature_text"]

        def raw(outcome="passed", which=spec):
            return {"outcome": outcome, "expected_line": which["selected_line"], "expected_lines": which["expected_lines"],
                    "wall_seconds": 1.0, "exit_code": 0 if outcome == "passed" else 1,
                    "records": [{"feature_file": "classpath:" + p["observed"].rsplit(":", 1)[0].removeprefix("src/test/resources/"), "scenario_line": int(p["observed"].rsplit(":", 1)[1]),
                                 "scenario_title": p["title"], "scenario_result": "passed" if outcome == "passed" else "not-passed"}
                                for p in which["pairs"]]}

        projection = runtime_projection(raw(), spec)
        assert [p["intended"] for p in projection["pickle_projection"]] == ["item.feature:5", "item.feature:10"]
        batches = {"fail": [raw("undefined_steps") for _ in range(3)], "pass": [raw() for _ in range(3)]}
        assert derive_row(closure["item_id"], batches, spec, "a" * 64)["admitted"]
        malformed = copy.deepcopy(batches)
        malformed["pass"].pop()
        refuses(lambda: derive_row(closure["item_id"], malformed, spec, "a" * 64), "six raw")
        flaky = copy.deepcopy(batches)
        flaky["pass"][1]["outcome"] = "failed"
        assert derive_row(closure["item_id"], flaky, spec, "a" * 64)["reason"] == "flaky"
        foreign = copy.deepcopy(batches)
        for run in foreign["pass"]:
            run["records"][0]["scenario_title"] = "foreign"
        assert derive_row(closure["item_id"], foreign, spec, "a" * 64)["reason"] == "foreign_pickle"
        missing = copy.deepcopy(batches)
        for run in missing["pass"]:
            run["records"] = []
        assert derive_row(closure["item_id"], missing, spec, "a" * 64)["reason"] == "missing_scenario"
        timeout = copy.deepcopy(batches)
        timeout["pass"][0].update(outcome="timeout", timed_out=True)
        refuses(lambda: derive_row(closure["item_id"], timeout, spec, "a" * 64), "killed cleanup")
        timeout["pass"][0]["timeout_cleanup"] = "killed"
        assert not derive_row(closure["item_id"], timeout, spec, "a" * 64)["admitted"]
        changed = copy.deepcopy(batches)
        for runs in changed.values():
            for run in runs:
                run["substrate_violation"] = {"changed": ["production.java"]}
        assert derive_row(closure["item_id"], changed, spec, "a" * 64)["reason"] == "altered_substrate"
        print("PASS exact setup mapping, foreign/empty identity, flaky and timeout controls")

        # The real validate_item must call BOTH legs even when the empty leg passes.
        gold = root / "gold"
        gold.mkdir()
        (gold / "gold.java").write_text("// synthetic gold\n")
        (source / "gold.java").write_bytes((gold / "gold.java").read_bytes())
        (gold / "strip_manifest.json").write_bytes(encoded({"moved": ["gold.java"], "moved_config": [], "digests": {"item.feature": "synthetic"}}))
        boundary = SimpleNamespace(classify=lambda rel: "removable" if rel == "gold.java" else "production")
        assert set(validate_gold(source, boundary, gold, [closure])) == {"gold.java", "strip_manifest.json"}
        (gold / "extra.java").write_text("// extra\n")
        refuses(lambda: validate_gold(source, boundary, gold, [closure]), "exact strip membership")
        (gold / "extra.java").unlink()
        calls = []

        class FakeHarness:
            root = str(source)
            runner = SimpleNamespace(container="synthetic-worker", docker_group=False)

            def run_solution(self, feature, scenario, solution, **kwargs):
                calls.append((len(solution.files), kwargs))
                return {"runs": [raw() for _ in range(kwargs["repeats"])], "substrate_violation": None}

        observed = N3Executor(FakeHarness(), str(gold), worker_container="synthetic-worker").execute(closure, lambda _leg, _runs: None)
        assert set(observed) == {"fail", "pass"} and len(calls) == 2
        assert calls[0][0] == 0 and calls[1][0] == 1
        assert all(c[1] == {"timeout": 600, "repeats": 3, "keep_stdout": True} for c in calls)
        print("PASS real validate_item retains full logs and both N3 legs on empty-pass exclusion")
        # 32 eligible synthetic criteria, one empty native candidate, plus held
        # and requirement rows. All35 rows must survive as included or excluded.
        rows, closures, quality = [], [], {}
        for i in range(33):
            rel = f"f{i:02d}.feature"
            (source / rel).write_text(text)
            iid = "kapua/" + rel + ":10"
            rows.append({"item_id": iid, "project": "kapua", "task": "criterion_to_test"})
            cl = dict(closure, item_id=iid, feature_file=rel, files=[f"gold{i}.java"] if i < 32 else [])
            closures.append(cl)
            quality[iid] = {"has_oracle": i < 32, "commented_out": False, "live_effective_step_count": 2 if i < 32 else 0,
                            "live_step_count": 2, "signature": str(i)}
        rows += [{"item_id": "kapua/held.feature:10", "project": "kapua", "task": "criterion_to_test"},
                 {"item_id": "kapua/f00.feature", "project": "kapua", "task": "requirement_to_test"}]
        controls = root / "inputs"
        controls.mkdir()
        (controls / "items.jsonl").write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in rows))
        for name, doc in (("closures", closures), ("quality", quality), ("boundary", {}), ("profile", {})):
            (controls / (name + ".json")).write_bytes(encoded(doc))
        decisions = source_decisions(rows, closures, quality)
        assert decisions[rows[-1]["item_id"]]["reasons"] == ["requirement_task_deferred_in_v1"]
        assert decisions[rows[-2]["item_id"]]["reasons"] == ["outside_admitted_native_scope"]
        slots = partitions([i for i, d in decisions.items() if d["stage"] == "validation"])
        assert len(slots) == 16 and all(len(slot) == 2 for slot in slots)
        assert slots == partitions(list(reversed([i for slot in slots for i in slot])))
        refuses(lambda: source_decisions(rows + [rows[0]], closures, quality), "duplicate")
        plan = {"schema": SCHEMA, "kind": "plan", "image_id": "sha256:" + "a" * 64,
                "source_root": str(source), "partitions": slots, "item_ids": [r["item_id"] for r in rows],
                "inputs": {name: reference(controls / (name + (".jsonl" if name == "items" else ".json")))
                           for name in ("items", "closures", "quality", "boundary", "profile")},
                "gold_files": {"gold.java": reference(gold / "gold.java")}, "dispositions": decisions}
        plan_path = root / "synthetic-plan.json"
        plan_path.write_bytes(encoded(plan))

        class Executor:
            def execute(self, cl, observer):
                selected = projection_spec(source, cl)
                batches = {"fail": [raw("undefined_steps", selected) for _ in range(3)],
                           "pass": [raw("passed", selected) for _ in range(3)]}
                for leg, runs in batches.items():
                    observer(leg, runs)
                return batches

            def close(self):
                pass

        def identity(slot):
            return {"index": slot, "image_id": plan["image_id"], "substrate_sha256": "b" * 64,
                    "pool_digest": "synthetic-pool", "workspace": f"synthetic-workspace-{slot}",
                    "container": f"synthetic-container-{slot}", "harness_commit": "c" * 40,
                    "harness_source_sha256": "d" * 64}

        # Only native/worker authentication is mocked: six-run writing, parsing,
        # union checks and generic release assembly are real production functions.
        with patch(__name__ + ".load_plan", return_value=(plan, {})), \
                patch(__name__ + ".validate_worker_identity"):
            dirs = [root / f"worker-{slot}" for slot in range(16)]
            for slot, directory in enumerate(dirs):
                produce_worker(plan_path, slot, directory, executor=Executor(), worker_identity=identity(slot))
            refuses(lambda: merge(plan_path, dirs[:-1], root / "incomplete"), "all 16")
            refuses(lambda: merge(plan_path, dirs[:-1] + dirs[:1], root / "duplicate"), "duplicate worker slot")
            ledger_path = dirs[0] / "validation.jsonl"
            saved_ledger = ledger_path.read_bytes()
            ledger_rows = jsonl(ledger_path)
            ledger_path.write_bytes(json.dumps(ledger_rows[0]).encode() + b"\n")
            refuses(lambda: merge(plan_path, dirs, root / "omitted-row"), "exact ordered partition")
            ledger_rows[0]["item_id"] = "kapua/foreign.feature:1"
            ledger_path.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in ledger_rows))
            refuses(lambda: merge(plan_path, dirs, root / "foreign-row"), "exact ordered partition")
            ledger_path.write_bytes(saved_ledger)
            receipt_path = dirs[0] / "receipt.json"
            original_receipt = receipt_path.read_bytes()
            doc = read(receipt_path)
            doc["worker"]["pool_digest"] = "other-pool"
            receipt_path.write_bytes(encoded(doc))
            refuses(lambda: merge(plan_path, dirs, root / "mixed"), "mixed pool")
            receipt_path.write_bytes(original_receipt)
            record = next((dirs[0] / "records").rglob("*.json"))
            original_record = record.read_bytes()
            record.write_bytes(original_record + b" ")
            refuses(lambda: merge(plan_path, dirs, root / "changed"), "raw record changed")
            record.write_bytes(original_record)
            merged = root / "merged"
            merge(plan_path, list(reversed(dirs)), merged)
            result = assemble(plan_path, merged, root / "assembled")
            assert result["status"] == "development_candidate_awaiting_review"
            assert result["summary"]["included"] == 32 and result["summary"]["excluded"] == 3
            release = root / "assembled/release"
            excluded = list(csv.DictReader((release / "exclusions.csv").open()))
            assert {r["item_id"] for r in jsonl(release / "items.jsonl")} | {r["item_id"] for r in excluded} == set(plan["item_ids"])
            assert (release / "control-artifacts/source-closures.json").read_bytes() == (controls / "closures.json").read_bytes()
            assert not any("target_interfaces" in r for r in jsonl(release / "items.jsonl"))
            manifest = read(root / "assembled/release-manifest.json")
            from .kapua_population import release_file_manifest
            assert {k: v for k, v in manifest.items() if k != "released_item_ids"} == release_file_manifest(release)
            assert not (root / "assembled/approval.json").exists()
            # A changed receipt is re-read by assembly, not trusted via thin union.
            doc = read(receipt_path)
            doc["worker"]["pool_digest"] = "other-pool"
            receipt_path.write_bytes(encoded(doc))
            refuses(lambda: assemble(plan_path, merged, root / "changed-assembly"), "input bytes changed")
            receipt_path.write_bytes(original_receipt)
            with patch(__name__ + ".MIN_CLUSTERS", 33):
                low = assemble(plan_path, merged, root / "below-floor")
                assert low["status"] == "rejected_cluster_floor" and not low["cluster_floor_passed"]
            class PassRaises(Executor):
                def execute(self, cl, observer):
                    observer("fail", [raw("undefined_steps", projection_spec(source, cl)) for _ in range(3)])
                    raise ValueError("synthetic pass-leg exception")
            partial = root / "partial-evidence"
            refuses(lambda: produce_worker(plan_path, 0, partial, executor=PassRaises(), worker_identity=identity(0)), "pass-leg exception")
            assert len(list((partial / "records").rglob("fail-*.json"))) == 3
            assert not list((partial / "records").rglob("pass-*.json"))
            assert not (partial / "receipt.json").exists()
            # Cleanup failure preserves raw evidence but never creates a completed receipt.
            class BadCleanup(Executor):
                def close(self):
                    raise ValueError("synthetic cleanup failure")
            bad = root / "bad-cleanup"
            refuses(lambda: produce_worker(plan_path, 0, bad, executor=BadCleanup(), worker_identity=identity(0)), "cleanup failure")
            assert read(bad / "cleanup.json")["verified"] is False and not (bad / "receipt.json").exists()
        (gold / "gold0.java").write_text("// synthetic timeout-fixture gold\n")
        # Exercise the real compile/index and host-cleanup implementations.
        # Docker calls alone are synthetic; every sentinel is an actual file.
        from ..stacks import cucumber as C
        from ..bench import worker as W
        for outcome in ("absent", "removal_failed", "absence_failed", "host_cleanup_failed"):
            events = []
            workspace = root / ("abort-workspace-" + outcome)
            workspace.mkdir()
            (workspace / "f00.feature").write_text(text)
            candidate = workspace / K.STEP_SOURCE_ROOTS[0] / "Synthetic.java"
            generated = workspace / K.FEATURE_PATHS[0]
            compiled = workspace / K.STEP_SOURCE_ROOTS[0].removesuffix("/src/main/java") / "target/Synthetic.class"
            retained = workspace / "production.java"
            for path in (candidate, generated, compiled, retained):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic sentinel")
            original = subprocess.TimeoutExpired(["synthetic-docker", "exec", identity(0)["container"], "mvn"],
                                                  C.COMPILE_TIMEOUT, output=b"compile stdout\x00", stderr=b"compile stderr")

            def compile_timeout(command, *, timeout):
                assert timeout == 900 and "mvn" in command and "-DskipTests" in command
                events.append("compile_timeout")
                raise original

            class TimeoutHarness:
                root = str(workspace)
                workdir_root = "/work"
                runner = SimpleNamespace(container=identity(0)["container"], docker_group=False, run=compile_timeout)
                boundary = SimpleNamespace(project="kapua", removable=[(K.STEP_SOURCE_ROOTS[0], "steps")],
                          classify=lambda rel: "removable" if rel.startswith(K.STEP_SOURCE_ROOTS[0] + "/") else "production")
                man = SimpleNamespace(repo_root=str(workspace))
                quirks = C.quirks_for("kapua")
                index_paths = C.CucumberHarness.index_paths
                _output_paths = C.CucumberHarness._output_paths
                _remove = C.CucumberHarness._remove

                def _abs(self, rel):
                    return str(workspace / rel)

                def run_solution(self, feature, scenario, solution, **kwargs):
                    assert kwargs == {"timeout": 600, "repeats": 3, "keep_stdout": True}
                    if solution.files:
                        self.index_paths([candidate.relative_to(workspace).as_posix()])
                    return {"runs": [raw("undefined_steps") for _ in range(3)], "substrate_violation": None}

                def clear_registration(self):
                    raise AssertionError("in-container cleanup after compiler abort")

                def _remove_compiled_candidate_glue(self):
                    raise AssertionError("in-container compiled cleanup after compiler abort")

                def verify_substrate(self):
                    events.append("host_cleanup_verified")
                    assert not candidate.exists() and not generated.exists() and not compiled.exists()
                    assert retained.read_text() == "synthetic sentinel"
                    if outcome == "host_cleanup_failed":
                        raise ValueError("synthetic host cleanup failure")

            harness = TimeoutHarness()
            refuses(lambda: N3Executor(harness, str(gold), worker_container="other-worker"), "authenticated worker")
            executor = N3Executor(harness, str(gold), worker_container=identity(0)["container"])

            def remove(name, *, docker_group):
                assert (name, docker_group) == (identity(0)["container"], False)
                assert candidate.exists() and generated.exists() and compiled.exists()
                events.append("removed")
                return outcome != "removal_failed"

            def absent(name, *, docker_group):
                assert (name, docker_group) == (identity(0)["container"], False)
                assert events == ["compile_timeout", "removed"]
                assert candidate.exists() and generated.exists() and compiled.exists()
                events.append("absence_checked")
                if outcome == "absence_failed":
                    raise W.WorkerRefused("synthetic cannot prove absent")

            aborted = root / ("abort-records-" + outcome)
            with patch(__name__ + ".load_plan", return_value=(plan, {})), \
                    patch.object(W, "remove_container", side_effect=remove) as removals, \
                    patch.object(W, "require_container_absent", side_effect=absent) as absence_checks:
                try:
                    produce_worker(plan_path, 0, aborted, executor=executor, worker_identity=identity(0))
                except subprocess.TimeoutExpired as error:
                    assert error is original
                else:
                    raise AssertionError("compiler timeout did not abort")
            assert removals.call_count == 1
            assert absence_checks.call_count == (0 if outcome == "removal_failed" else 1)
            assert len(list((aborted / "records").rglob("fail-*.json"))) == 3
            assert not list((aborted / "records").rglob("pass-*.json"))
            assert not (aborted / "receipt.json").exists() and not (aborted / "validation.jsonl").exists()
            failure = read(aborted / "failure.json")
            assert failure["command"] == original.cmd and failure["timeout_seconds"] == 900
            assert base64.b64decode(failure["stdout"]["base64"]) == original.output
            assert base64.b64decode(failure["stderr"]["base64"]) == original.stderr
            cleanup = read(aborted / "cleanup.json")
            assert cleanup["container"] == identity(0)["container"] and not cleanup["worker_reusable"]
            if outcome in ("removal_failed", "absence_failed"):
                assert not cleanup["verified"] and not cleanup["container_absent"] and not cleanup["host_cleanup_started"]
                assert candidate.exists() and generated.exists() and compiled.exists()
                assert "host_cleanup_verified" not in events
            else:
                assert cleanup["container_absent"] and cleanup["host_cleanup_started"]
                assert cleanup["verified"] == (outcome == "absent")
                assert events == ["compile_timeout", "removed", "absence_checked", "host_cleanup_verified"]
            assert retained.read_text() == "synthetic sentinel"
        # Successful cleanup still uses the normal harness methods, including
        # the compiled-glue purge, without removing the worker container.
        normal_events = []
        normal = SimpleNamespace(runner=SimpleNamespace(container="normal", docker_group=False), man=None, boundary=None,
                  clear_registration=lambda: normal_events.append("registration"),
                  _remove_compiled_candidate_glue=lambda: normal_events.append("compiled"),
                  verify_substrate=lambda: normal_events.append("verified"))
        with patch("r2t.bench.repo.clean_workspace", side_effect=lambda *a: normal_events.append("sources")), \
                patch.object(W, "remove_container", side_effect=AssertionError("normal worker removed")):
            N3Executor(normal, str(gold), worker_container="normal").close()
        assert normal_events == ["sources", "registration", "compiled", "verified"]
        print("PASS compiler abort exact targeting, absence-before-cleanup, original exception/raw preservation and normal cleanup")
        print("PASS complete16 union, raw tampering, full extraction exclusions, manifest, cluster floor and cleanup failure")
    print("ALL PASS (kapua_development_release; synthetic fixtures)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    for name in ("items", "closures", "quality", "source-root", "boundary", "profile", "native-capture", "gold", "out"):
        prep.add_argument("--" + name, required=True)
    worker = commands.add_parser("validate-worker")
    for name in ("plan", "worker", "out", "docker-authority"):
        worker.add_argument("--" + name, required=True)
    merged = commands.add_parser("merge")
    merged.add_argument("--plan", required=True)
    merged.add_argument("--worker-output", action="append", required=True)
    merged.add_argument("--out", required=True)
    assembly = commands.add_parser("assemble")
    for name in ("plan", "merged", "out"):
        assembly.add_argument("--" + name, required=True)
    args = vars(parser.parse_args(argv))
    command = args.pop("command")
    if command == "prepare":
        result = prepare(**args)
    elif command == "validate-worker":
        result = run_worker(args["plan"], args["worker"], args["out"], args["docker_authority"])
    elif command == "merge":
        result = merge(args["plan"], args["worker_output"], args["out"])
    else:
        result = assemble(args["plan"], args["merged"], args["out"])
    print(json.dumps(result, indent=2))
    return 1 if result.get("status") == "rejected_cluster_floor" else 0


if __name__ == "__main__":
    raise SystemExit(main())
