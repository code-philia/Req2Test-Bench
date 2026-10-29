"""The Slice-3 test-quality join: score the two published algorand-sdk cells.

`benchmark/SLICE3_TEST_QUALITY_SPEC.md` §2 is the authority for everything
here.  The join is Docker-free: run 1 (and run 2 where the D4 rule demanded
one) already executed inside the frozen Java20 seam and their bytes are
preserved; what this module does is re-derive the frozen hard-pair basis from
the six control observations, join the published run to its candidate
mutation evidence byte-exactly, classify exactly the run's passed items, and
emit the standard per-solution sidecar `report.non_vacuous`, `cli compare`
and `campaign-results` already consume.

The trust anchor is a specification-pinned digest standing in for a
VERSIONS.yml pin (spec §2.5 item 1): the frozen execution-binding digest the
spec records in §1/§4, and the SHA-256 of the frozen six-gate eligibility
document.  Everything else is re-derived from the preserved bytes and
compared, never merely read back.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os

from .slice3_evidence import (CANDIDATE_TERMINAL_OUTCOMES, OBSERVATION_ROLES,
                              Slice3Refused, _load_bound_mutation_observation,
                              authorize_mutation_job, validate_six_observations)
from .test_quality import (EQUIVALENT, NOT_SCORABLE,
                           TEST_QUALITY_SUMMARY_SCHEMA, TestQualityRefused,
                           VERDICTS, _load_json_object, load_jsonl,
                           passed_solutions, refuse_unpublishable_generation,
                           verdict_for)

PROJECT = "algorand-sdk"
ARMS = ("aider", "openhands")

#: The discriminator (spec §2.5): a sidecar carrying this key takes the
#: Slice-3 acceptance path through `_validate_native_summary`; every sidecar
#: without it takes the unchanged docx/CoreShop path.
JOIN_KEY = "slice3_mutation_join"
JOIN_SCHEMA = "r2t.slice3-test-quality-join/1"

ELIGIBILITY_NAME = "six-gate-eligibility.json"

#: The frozen `r2t.slice3-java20-execution-binding/1` digest, recorded in
#: SLICE3_TEST_QUALITY_SPEC.md §1 and §4 item 2.
FROZEN_EXECUTION_BINDING_DIGEST = \
    "0b62adf3c07671d2ef58942612c6d3fbe99700f35ba53cc8ceb15e95add517f6"

#: SHA-256 of the frozen `six-gate-eligibility.json` bytes — the document
#: spec §1 describes (schema r2t.slice3-six-observation-eligibility/1,
#: 9 hard pairs over 8 eligible items of 111, the six observation ids) and
#: §2.5 item 1 pins by digest.  Spec §1 now prints this same value; this
#: constant is that value, computed from the preserved document whose every
#: recorded fact matches §1.
FROZEN_ELIGIBILITY_SHA256 = \
    "e7a7511858d8fe0609b8b72b7343cb2eeb7fd20c72f06dfac8af832f98dfdc93"


def _refuse(message: str) -> TestQualityRefused:
    return TestQualityRefused(f"REFUSED: {message}")


def _wrap(exc: Exception) -> TestQualityRefused:
    text = str(exc)
    if not text.startswith("REFUSED"):
        text = f"REFUSED: {text}"
    return TestQualityRefused(text)


def eligibility_bytes(document: dict) -> bytes:
    """The frozen eligibility document's exact serialization."""
    return json.dumps(document, indent=1, sort_keys=True).encode("utf-8")


def _single_shard(directory: str, label: str) -> str:
    paths = sorted(glob.glob(os.path.join(directory, "*.jsonl")))
    if len(paths) != 1 or os.path.islink(paths[0]) \
            or not os.path.isfile(paths[0]):
        raise _refuse(f"{label} must hold exactly one mutation shard: "
                      f"{directory}")
    return paths[0]


def build_summary(run_path: str, *, observations_dir: str,
                  bundle_path: str) -> dict:
    """Re-derive the Slice-3 test-quality summary from preserved bytes.

    One function serves both the producer (`test-quality
    --slice3-observations`) and the validator (§2.5): the acceptance path is
    re-derive-and-compare, the same shape `_validate_native_summary` uses for
    the legacy wrapper, so a sidecar that could not have been produced from
    the evidence it names cannot be read either.
    """
    from .mutation_run import (MutationAborted, candidate_digest,
                               completed_pairs, pair_set_digest,
                               provenance_path, sha256_file)

    observations_dir = os.path.abspath(observations_dir)
    run_rows = load_jsonl(run_path)
    passed = passed_solutions(run_rows)
    projects = {row["item_id"].split("/", 1)[0] for row in run_rows}
    if projects != {PROJECT}:
        raise _refuse(
            f"the Slice-3 join scores only the two published {PROJECT} "
            f"cells; this run is over project(s) {sorted(projects)} "
            "(epubcheck is functional-only in this freeze, and docx/CoreShop "
            "take the existing test-quality path)")
    arms = {row.get("agent_system") for row in run_rows}
    arm = arms.pop() if len(arms) == 1 else None
    if arm not in ARMS:
        raise _refuse(
            f"the Slice-3 join scores only the published {' and '.join(ARMS)}"
            f" arms; this run claims agent_system "
            f"{sorted(arms | {arm}, key=repr)}")

    bundle = _load_json_object(bundle_path, "Slice-3 source bundle")
    binding = bundle.get("mutation_execution_binding")
    if not isinstance(binding, dict) \
            or binding.get("digest") != FROZEN_EXECUTION_BINDING_DIGEST:
        raise _refuse(
            "the source bundle does not carry the frozen Slice-3 execution "
            f"binding {FROZEN_EXECUTION_BINDING_DIGEST}")
    project_binding = (binding.get("projects") or {}).get(PROJECT)
    if not isinstance(project_binding, dict):
        raise _refuse(f"the frozen execution binding has no {PROJECT} view")
    frozen_pairs = [tuple(pair) for pair in project_binding["ordered_pairs"]]
    control_ids = {row["role"]: row["observation_id"]
                   for row in project_binding["control_observations"]}
    capability = {"mutation_execution_binding": binding}

    eligibility_path = os.path.join(observations_dir, ELIGIBILITY_NAME)
    if os.path.islink(eligibility_path) \
            or not os.path.isfile(eligibility_path):
        raise _refuse(
            f"no frozen six-gate eligibility document at {eligibility_path}")
    with open(eligibility_path, "rb") as fh:
        frozen_raw = fh.read()
    if hashlib.sha256(frozen_raw).hexdigest() != FROZEN_ELIGIBILITY_SHA256:
        raise _refuse(
            f"{eligibility_path} is not the frozen six-gate basis "
            f"{FROZEN_ELIGIBILITY_SHA256} this join is pinned to")
    frozen_doc = json.loads(frozen_raw)
    try:
        item_ids = list(frozen_doc["projects"][PROJECT]["items"])
    except (KeyError, TypeError):
        raise _refuse("the six-gate eligibility document does not describe "
                      f"{PROJECT}") from None

    controls = {}
    observations = {}
    for role in OBSERVATION_ROLES:
        shard = _single_shard(os.path.join(observations_dir, role),
                              f"control observation {role}")
        try:
            observations[role] = _load_bound_mutation_observation(
                shard, bundle=capability, project=PROJECT, role=role,
                observation_id=control_ids.get(role))
        except (Slice3Refused, MutationAborted) as exc:
            raise _wrap(exc) from exc
        controls[role] = {
            "path": shard,
            "observation_id": control_ids[role],
            "rows_sha256": sha256_file(shard),
        }
    selected = [{"project": PROJECT, "item_id": item_id,
                 "mutant_id": mutant_id}
                for item_id, mutant_id in frozen_pairs]
    derived = validate_six_observations(selected, observations,
                                        {PROJECT: item_ids})
    if eligibility_bytes(derived) != frozen_raw:
        raise _refuse(
            "the six-gate eligibility document does not re-derive "
            "byte-identical from the six preserved observations")
    hard_by_item: dict[str, set] = {}
    for pair in derived["projects"][PROJECT]["hard_pairs"]:
        hard_by_item.setdefault(pair["item_id"], set()).add(
            (pair["item_id"], pair["mutant_id"]))

    run1_dir = os.path.join(observations_dir, f"candidate_run1_{arm}")
    if not os.path.isdir(run1_dir):
        raise _refuse(
            f"no preserved candidate mutation evidence for the published "
            f"{arm} cell at {run1_dir}; scoring without the frozen Java20 "
            "run-1 output is not defined")
    run1_path = _single_shard(run1_dir, f"candidate run 1 ({arm})")
    try:
        rows1 = _load_bound_mutation_observation(
            run1_path, bundle=capability, project=PROJECT,
            role=f"candidate_run1:{arm}", eligibility=derived)
    except (Slice3Refused, MutationAborted) as exc:
        raise _wrap(exc) from exc
    outcome1 = {(row["item_id"], row["mutant_id"]): row["outcome"]
                for row in rows1}
    if pair_set_digest(list(outcome1)) != project_binding["pair_set_digest"]:
        raise _refuse("candidate run 1 rows do not hash to the frozen "
                      "pair-set digest")
    prov1 = _load_json_object(provenance_path(run1_path),
                              "candidate run-1 provenance")
    identity1 = prov1["campaign_identity"]

    # The byte-exact join (spec §2.1): the run being scored must hash to the
    # candidate_run_sha256 its mutation evidence recorded.
    run_sha = sha256_file(run_path)
    if identity1.get("candidate_run_sha256") != run_sha:
        raise _refuse(
            f"{run_path} does not hash to the candidate_run_sha256 its "
            f"preserved mutation evidence recorded ({run_sha} != "
            f"{identity1.get('candidate_run_sha256')}); this run is a "
            "different solution and has no Slice-3 mutation evidence")
    try:
        generated = candidate_digest(
            {row["item_id"]: row.get("produced_files") or []
             for row in run_rows})
    except MutationAborted as exc:
        raise _wrap(exc) from exc
    if identity1.get("candidate_generated_tests_sha256") != generated:
        raise _refuse(
            "the run's generated tests do not hash to the "
            "candidate_generated_tests_sha256 its preserved mutation "
            "evidence recorded")
    refuse_unpublishable_generation(
        identity1.get("generation_provenance_class"),
        f"the Slice-3 candidate mutation evidence {run1_path}")

    # D4 qualification over ALL terminal outcomes, kill = failed only
    # (spec §2.2); `authorize_mutation_job` computes the same rule when a
    # run 2 is bound below.
    qualifying = sorted(
        item_id for item_id, pairs in hard_by_item.items()
        if all(outcome1[pair] == "failed" for pair in pairs))

    run2_block = None
    outcome2 = None
    if qualifying:
        run2_dir = os.path.join(observations_dir, f"candidate_run2_{arm}")
        if not os.path.isdir(run2_dir):
            raise _refuse(
                f"run 1 leaves D4-qualifying item(s) {qualifying[:3]} and "
                f"no confirming run 2 exists at {run2_dir}; the sidecar is "
                "withheld rather than degraded to a run-1-only claim")
        run2_path = _single_shard(run2_dir, f"candidate run 2 ({arm})")
        prov2 = _load_json_object(provenance_path(run2_path),
                                  "candidate run-2 provenance")
        identity2 = prov2.get("campaign_identity")
        if not isinstance(identity2, dict):
            raise _refuse(
                "candidate run-2 provenance carries no campaign identity")
        try:
            job2 = authorize_mutation_job(
                binding, project=PROJECT, role=f"candidate_run2:{arm}",
                observation_id=prov2.get("observation_id"),
                eligibility=derived, run1_rows=rows1)
        except Slice3Refused as exc:
            raise _wrap(exc) from exc
        if prov2.get("slice3_execution_binding_digest") != binding["digest"] \
                or prov2.get("slice3_mutation_job_digest") != job2["digest"]:
            raise _refuse(
                "candidate run 2 was not produced by its bound frozen job")
        planned2 = {tuple(pair) for pair in job2["planned_pairs"]}
        try:
            completed_pairs(run2_path, identity2, expected_pairs=planned2,
                            require_complete=True)
        except MutationAborted as exc:
            raise _wrap(exc) from exc
        rows2 = load_jsonl(run2_path)
        for row in rows2:
            if row.get("outcome") not in CANDIDATE_TERMINAL_OUTCOMES:
                raise _refuse("candidate run 2 contains a non-terminal "
                              f"outcome {row.get('outcome')!r}")
        if pair_set_digest([(row["item_id"], row["mutant_id"])
                            for row in rows2]) != job2["pair_set_digest"]:
            raise _refuse("candidate run 2 rows do not hash to their "
                          "authorized pair-set digest")
        # Spec §4: run 2 runs the same image, engine and per-pair timeout as
        # run 1, through the same identity shape; a mix refuses.
        mixed = sorted(key for key in (
            "schema", "engine", "engine_version", "container_image_digest",
            "timeout_seconds", "candidate_run_sha256",
            "candidate_generated_tests_sha256")
            if identity2.get(key) != identity1.get(key))
        if mixed:
            raise _refuse(
                f"candidate run 2 changed execution identity field(s) "
                f"{mixed} from run 1; scoring refuses a mixed shape")
        outcome2 = {(row["item_id"], row["mutant_id"]): row["outcome"]
                    for row in rows2}
        run2_block = {
            "path": run2_path,
            "observation_id": prov2.get("observation_id"),
            "rows_sha256": sha256_file(run2_path),
            "pair_set_digest": job2["pair_set_digest"],
        }

    # ------------------------------------------------------- the verdicts
    covering: dict[str, set] = {}
    for item_id, mutant_id in frozen_pairs:
        covering.setdefault(item_id, set()).add(mutant_id)
    per_item: dict[str, dict] = {}
    counts = {verdict: 0 for verdict in VERDICTS}
    recalls = []
    for item_id in sorted(passed):
        hard = hard_by_item.get(item_id, set())
        recall = None
        reason = None
        killed = 0
        if not hard:
            reason = ("no hard pair in the frozen six-gate basis covers "
                      "this item -- d3_empty_hard_subset requires "
                      "not_scorable and forbids a full-gold fallback")
        else:
            killed1 = {pair for pair in hard if outcome1[pair] == "failed"}
            if len(killed1) == len(hard):
                # Initial recall 1.0: equivalence needs twin confirmation;
                # the item scores on the run-1/run-2 intersection.
                killed = sum(1 for pair in killed1
                             if outcome2 is not None
                             and outcome2.get(pair) == "failed")
            else:
                killed = len(killed1)
            recall = killed / len(hard)
            recalls.append(recall)
        verdict = verdict_for(len(hard), recall)
        counts[verdict] += 1
        per_item[item_id] = {
            "mutants_covering": len(covering.get(item_id, ())),
            "gold_killed": len(hard),
            "candidate_killed": killed,
            "denominator": len(hard),
            "recall": recall,
            "verdict": verdict,
            "not_scorable_reason": reason,
        }
    macro = round(sum(recalls) / len(recalls), 6) if recalls else None

    block = {
        "schema": JOIN_SCHEMA,
        "project": PROJECT,
        "agent_system": arm,
        "observations": observations_dir,
        "source_bundle": os.path.abspath(bundle_path),
        "execution_binding_digest": binding["digest"],
        "eligibility": eligibility_path,
        "eligibility_sha256": FROZEN_ELIGIBILITY_SHA256,
        "control_observations": controls,
        "candidate_run1": {
            "path": run1_path,
            "observation_id": prov1.get("observation_id"),
            "rows_sha256": sha256_file(run1_path),
            "pair_set_digest": project_binding["pair_set_digest"],
        },
        "candidate_run2": run2_block,
        "d4_qualifying_items": qualifying,
        "candidate_generated_tests_sha256": generated,
    }
    return {
        "schema": TEST_QUALITY_SUMMARY_SCHEMA,
        JOIN_KEY: block,
        "run": os.path.abspath(run_path),
        "verdict_basis": "hard_subset",
        "hard_subset_digest": FROZEN_ELIGIBILITY_SHA256,
        "candidate_run_sha256": run_sha,
        "engine": identity1.get("engine"),
        "engine_version": identity1.get("engine_version"),
        "container_image_digest": identity1.get("container_image_digest"),
        "mutants_in_population": len({m for _i, m in frozen_pairs}),
        "pairs_expected": len(frozen_pairs),
        "hard_pairs": sum(len(pairs) for pairs in hard_by_item.values()),
        "n_passed": len(passed),
        "n_scorable": len(recalls),
        "recall_macro": macro,
        "hard_recall_macro": macro,
        "verdicts": counts,
        "non_vacuous_passes": counts[EQUIVALENT],
        "per_item": per_item,
        # The six complete, infrastructure-free control observations perform,
        # collectively, the role a single gold run performs for docx and
        # CoreShop (spec §2.5 item 3); their completeness and cleanliness
        # were just proved above, so these are measured facts, not defaults.
        "require_complete": True,
        "completeness_checked": True,
        "gold_rows_missing": 0,
        "gold_infrastructure_outcomes": 0,
    }


def validate_summary(summary: dict, summary_path: str,
                     run_path: str) -> None:
    """Spec §2.5: the Slice-3 acceptance path, re-derive-and-compare.

    Reachable only from `_validate_native_summary` when the sidecar carries
    the join block; the docx/CoreShop paths through that function never do.
    `build_summary` fires every named refusal (frozen digests, byte-exact
    run join, completeness, required run 2); what remains here is that the
    sidecar equals the summary those bytes re-derive.
    """
    block = summary.get(JOIN_KEY)
    if not isinstance(block, dict) or block.get("schema") != JOIN_SCHEMA:
        raise _refuse(f"{summary_path} carries a malformed Slice-3 join "
                      "block")
    observations_dir = block.get("observations")
    bundle_path = block.get("source_bundle")
    if not isinstance(observations_dir, str) or not observations_dir \
            or not isinstance(bundle_path, str) or not bundle_path:
        raise _refuse(f"{summary_path} does not name its preserved Slice-3 "
                      "evidence")
    try:
        expected = build_summary(run_path, observations_dir=observations_dir,
                                 bundle_path=bundle_path)
    except OSError as exc:
        raise _wrap(exc) from exc
    body = {key: value for key, value in summary.items() if key != "binding"}
    if body != expected:
        changed = sorted(key for key in set(body) | set(expected)
                         if body.get(key) != expected.get(key))
        raise _refuse(
            f"{summary_path} differs from the summary re-derived from its "
            f"preserved Slice-3 evidence in field(s) {changed[:10]}")


def print_summary(summary: dict) -> None:
    """The short human version of a Slice-3 summary."""
    block = summary[JOIN_KEY]
    macro = summary["recall_macro"]
    print(f"\nSlice-3 test quality ({block['project']} / "
          f"{block['agent_system']}): {summary['n_passed']} passed item(s), "
          f"{summary['n_scorable']} scorable, macro recall "
          f"{'-' if macro is None else format(macro, '.3f')} over "
          f"{summary['hard_pairs']} hard pair(s) / "
          f"{summary['mutants_in_population']} mutant(s)")
    print("  verdict basis: hard_subset, pinned to six-gate eligibility "
          f"{summary['hard_subset_digest']}")
    print("  D4: " + (f"{len(block['d4_qualifying_items'])} qualifying "
                      "item(s), run 2 consumed"
                      if block["candidate_run2"] else
                      "no qualifying item; run 2 not required"))
    for verdict in VERDICTS:
        note = ("  <- non_vacuous_pass_at_1 counts these"
                if verdict == EQUIVALENT else "")
        print(f"  {verdict:<24} {summary['verdicts'][verdict]:>4}{note}")
    for item_id, item in sorted(summary["per_item"].items()):
        if item["verdict"] == NOT_SCORABLE:
            continue
        print(f"  {item['verdict']:<24} {item['candidate_killed']:>3}/"
              f"{item['gold_killed']:<3} recall "
              f"{format(item['recall'], '.3f'):>5}  {item_id}")


# ----------------------------------------------------------------- selftest
def selftest() -> int:  # noqa: C901
    """The join, the acceptance path and the refusal surface, on fixtures.

    No Docker, no network, no preserved corpus: a synthetic evidence tree is
    built through the real producers (`build_mutation_execution_binding`,
    `authorize_mutation_job`, `write_shard_provenance`,
    `validate_six_observations`), and the module's two frozen digests are
    re-pinned to the fixture's own for the duration — the pin MECHANISM is
    under test; the production values are facts about /data2 bytes.
    """
    global FROZEN_EXECUTION_BINDING_DIGEST, FROZEN_ELIGIBILITY_SHA256
    import shutil
    import tempfile
    from contextlib import redirect_stdout
    from io import StringIO

    from .mutation_run import (build_campaign_identity,
                               campaign_identity_digest, sha256_file,
                               write_shard_provenance, row_identity_stamp)
    from .slice3_evidence import _digest, build_mutation_execution_binding

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refused(fn, needle=""):
        try:
            fn()
        except (TestQualityRefused, Slice3Refused, SystemExit) as e:
            return needle in str(e)
        return False

    def item(name, line):
        return f"{PROJECT}/features/unit/{name}.feature:{line}"

    i_weak, i_vac, i_nohard, i_fail, i_full = (
        item("a", 1), item("b", 2), item("c", 3), item("d", 4), item("e", 5))
    pairs = [(i_weak, "m00"), (i_weak, "m01"), (i_vac, "m02"),
             (i_full, "m03"), (i_nohard, "m04")]
    hard_design = {(i_weak, "m00"), (i_weak, "m01"), (i_vac, "m02"),
                   (i_full, "m03")}
    view = {"project": PROJECT, "count": 20,
            "ordered_mutant_ids": [f"m{i:02d}" for i in range(20)],
            "ordered_pairs": [{"item_id": i, "mutant_id": m}
                              for i, m in pairs]}
    view["digest"] = _digest(view)
    views = {"schema": "r2t.slice3-java20-mutant-views/1",
             "projects": {PROJECT: view}}
    views["view_digest"] = _digest(views)
    control_oids = {role: hashlib.sha256(role.encode()).hexdigest()[:32]
                    for role in OBSERVATION_ROLES}
    binding = build_mutation_execution_binding(views, {PROJECT: control_oids})

    def run_row(item_id, outcome):
        return {"item_id": item_id, "outcome": outcome,
                "agent_system": "aider",
                "produced_files": [{"file_path": f"{item_id}.java",
                                    "code": "x"}]}

    def identity_for(side, run_sha, tests_sha, pair_list):
        return build_campaign_identity(
            asset_index_sha256="a" * 64, asset_project=PROJECT,
            mutation_validation_sha256="b" * 64,
            mutation_validation_class="native",
            manifest_sha256="c" * 64, map_sha256="d" * 64,
            release_sha256="e" * 64,
            candidate_run_sha256=run_sha,
            solution_generated_tests_sha256=tests_sha,
            candidate_generated_tests_sha256=tests_sha,
            substrate_baseline_sha256="f" * 64,
            worker_resources_sha256="1" * 64,
            harness_version=7,
            container_image_digest="sha256:" + "2" * 64,
            workspace_seed_digest="3" * 64,
            database_dump_digest="no_database",
            expected_pairs=pair_list,
            engine="r2t-mutate-java", engine_version="1.0",
            parser="javac 11 (fixture)",
            side=side, shard=0, of=1, timeout=600,
            generation_provenance_class="native_v2",
            generation_attempt_id="fixture-attempt",
            generation_campaign_digest="0123456789abcdef",
            generation_agent_runtime_sha256="4" * 64,
            generation_network_semantics="fixture_closed",
            generation_condition="c3",
            generation_protocol_version=8,
            generation_protocol_digest="89abcdef01234567",
            generation_native_budget={"max_reflections": 10},
            manifest_digest="5" * 64,
            applier_sha256="6" * 64,
        )

    def write_shard(dirpath, name, rows, identity, oid, job_digest):
        os.makedirs(dirpath, exist_ok=True)
        out = os.path.join(dirpath, name)
        digest = campaign_identity_digest(identity)
        with open(out, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(
                    {**row, **row_identity_stamp(identity, digest)},
                    sort_keys=True) + "\n")
        extra = {"observation_id": oid,
                 "slice3_execution_binding_digest": binding["digest"],
                 "slice3_mutation_job_digest": job_digest}
        write_shard_provenance(out, identity, "running", provenance=extra)
        write_shard_provenance(out, identity, "complete", provenance=extra)
        return out

    def control_outcome(role, pair):
        if role.startswith("full_gold"):
            return "failed" if pair in hard_design else "passed"
        return "passed"

    def build_tree(root, *, item_universe, run1_outcomes, run2_outcomes,
                   run_outcomes):
        """One coherent fixture evidence tree; returns its paths."""
        obs = os.path.join(root, "observations")
        os.makedirs(obs)
        bundle_path = os.path.join(root, "bundle.json")
        with open(bundle_path, "w", encoding="utf-8") as fh:
            json.dump({"mutation_execution_binding": binding}, fh)
        run_path = os.path.join(root, "run.jsonl")
        with open(run_path, "w", encoding="utf-8") as fh:
            for item_id, outcome in run_outcomes:
                fh.write(json.dumps(run_row(item_id, outcome)) + "\n")
        run_sha = sha256_file(run_path)
        from .mutation_run import candidate_digest
        tests_sha = candidate_digest(
            {item_id: run_row(item_id, "x")["produced_files"]
             for item_id, _outcome in run_outcomes})
        observations = {}
        for role in OBSERVATION_ROLES:
            job = authorize_mutation_job(binding, project=PROJECT, role=role,
                                         observation_id=control_oids[role])
            rows = [{"item_id": i, "mutant_id": m,
                     "outcome": control_outcome(role, (i, m))}
                    for i, m in pairs]
            write_shard(os.path.join(obs, role), "gold.w0.jsonl", rows,
                        identity_for("gold", "9" * 64, "8" * 64, pairs),
                        control_oids[role], job["digest"])
            observations[role] = [
                {"project": PROJECT, "item_id": i, "mutant_id": m,
                 "outcome": control_outcome(role, (i, m)),
                 "observation_id": control_oids[role]}
                for i, m in pairs]
        selected = [{"project": PROJECT, "item_id": i, "mutant_id": m}
                    for i, m in pairs]
        derived = validate_six_observations(selected, observations,
                                            {PROJECT: item_universe})
        raw = eligibility_bytes(derived)
        with open(os.path.join(obs, ELIGIBILITY_NAME), "wb") as fh:
            fh.write(raw)
        oid1 = "5" * 32
        job1 = authorize_mutation_job(binding, project=PROJECT,
                                      role="candidate_run1:aider",
                                      observation_id=oid1,
                                      eligibility=derived)
        rows1 = [{"item_id": i, "mutant_id": m,
                  "outcome": run1_outcomes[(i, m)]} for i, m in pairs]
        write_shard(os.path.join(obs, "candidate_run1_aider"),
                    "candidate.w0.jsonl", rows1,
                    identity_for("candidate", run_sha, tests_sha, pairs),
                    oid1, job1["digest"])
        if run2_outcomes is not None:
            oid2 = "6" * 32
            run1_projected = [dict(row, project=PROJECT,
                                   observation_id=oid1) for row in rows1]
            job2 = authorize_mutation_job(binding, project=PROJECT,
                                          role="candidate_run2:aider",
                                          observation_id=oid2,
                                          eligibility=derived,
                                          run1_rows=run1_projected)
            planned = [tuple(pair) for pair in job2["planned_pairs"]]
            rows2 = [{"item_id": i, "mutant_id": m,
                      "outcome": run2_outcomes[(i, m)]} for i, m in planned]
            write_shard(os.path.join(obs, "candidate_run2_aider"),
                        "candidate.w0.jsonl", rows2,
                        identity_for("candidate", run_sha, tests_sha,
                                     planned),
                        oid2, job2["digest"])
        return obs, bundle_path, run_path, raw

    universe = [i_weak, i_vac, i_nohard, i_fail, i_full]
    run_outcomes = [(i_weak, "passed"), (i_vac, "passed"),
                    (i_nohard, "passed"), (i_fail, "failed"),
                    (i_full, "passed")]
    # Run 1 carries the two terminal survivals the preserved aider run
    # proves real (the §2.2 seam); i_weak and i_full reach recall 1.0 and
    # qualify for D4, i_vac's hard mutant survives as undefined_steps.
    run1_outcomes = {(i_weak, "m00"): "failed", (i_weak, "m01"): "failed",
                     (i_vac, "m02"): "undefined_steps",
                     (i_full, "m03"): "failed",
                     (i_nohard, "m04"): "parse_or_compile_error"}
    # Run 2 confirms i_full entirely (equivalent) and only half of i_weak
    # (twin intersection -> weaker).
    run2_outcomes = {(i_weak, "m00"): "failed", (i_weak, "m01"): "passed",
                     (i_full, "m03"): "failed"}

    saved = (FROZEN_EXECUTION_BINDING_DIGEST, FROZEN_ELIGIBILITY_SHA256)
    tmp = tempfile.mkdtemp(prefix="slice3-tq-")
    try:
        obs, bundle_path, run_path, elig_raw = build_tree(
            os.path.join(tmp, "a"), item_universe=universe,
            run1_outcomes=run1_outcomes, run2_outcomes=run2_outcomes,
            run_outcomes=run_outcomes)
        FROZEN_EXECUTION_BINDING_DIGEST = binding["digest"]
        FROZEN_ELIGIBILITY_SHA256 = hashlib.sha256(elig_raw).hexdigest()

        # ------------------------------------------------- the happy path
        summary = build_summary(run_path, observations_dir=obs,
                                bundle_path=bundle_path)
        check("the join classifies exactly the run's passes under the "
              "frozen hard basis",
              summary["verdicts"] == {"equivalent_to_reference": 1,
                                      "weaker": 1, "vacuous": 1,
                                      "not_scorable": 1}
              and summary["per_item"][i_full]["verdict"] == EQUIVALENT
              and summary["per_item"][i_weak]["recall"] == 0.5
              and summary["per_item"][i_vac]["verdict"] == "vacuous"
              and summary["per_item"][i_nohard]["verdict"] == NOT_SCORABLE
              and i_fail not in summary["per_item"]
              and summary["recall_macro"] == 0.5
              and summary["n_passed"] == 4 and summary["n_scorable"] == 3,
              json.dumps(summary["verdicts"]))
        check("D4 qualification is computed over all terminal outcomes with "
              "the kill rule failed-only",
              summary[JOIN_KEY]["d4_qualifying_items"] == sorted(
                  [i_weak, i_full])
              and summary[JOIN_KEY]["candidate_run2"] is not None)
        check("a non-terminal run-1 outcome still refuses authorization",
              refused(lambda: authorize_mutation_job(
                  binding, project=PROJECT, role="candidate_run2:aider",
                  observation_id="7" * 32,
                  eligibility=json.loads(elig_raw),
                  run1_rows=[{"item_id": i, "mutant_id": m,
                              "outcome": "harness_error"}
                             for i, m in pairs]),
                  "duplicate or incomplete"))

        from . import report as R
        from . import test_quality as TQ
        sidecar = TQ.write_sidecar(summary, run_path)
        loaded = TQ.load_bound_test_quality(run_path)
        nv = R.non_vacuous(load_jsonl(run_path), loaded)
        ready, reasons = TQ.publication_ready(loaded)
        check("the sidecar round-trips through the one existing entry point "
              "and report's arithmetic",
              os.path.isfile(sidecar)
              and {k: v for k, v in loaded.items() if k != "binding"}
              == summary
              and nv["non_vacuous_pass_at_1"] == 0.2
              and nv["stale"] is False and ready, "; ".join(reasons))

        # ------------------------------------------------ the CLI branch
        from .. import cli
        from . import cli as bench_cli

        class _Args:
            run = run_path
            slice3_observations = obs
            slice3_bundle = bundle_path
            no_sidecar = False

        check("a second production refuses to overwrite the sidecar",
              refused(lambda: bench_cli.cmd_test_quality(_Args()),
                      "already has test-quality sidecar"))
        buf = StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["test-quality", "--run", run_path,
                           "--slice3-observations", obs,
                           "--slice3-bundle", bundle_path, "--no-sidecar"])
        check("the CLI branch parses, scores and prints without the live "
              "workload arguments",
              rc == 0 and "Slice-3 test quality" in buf.getvalue()
              and "run 2 consumed" in buf.getvalue(), buf.getvalue())

        class _LiveArgs:
            slice3_observations = None
            slice3_bundle = None

        check("without the Slice-3 options the live path stays closed at "
              "its capability gate",
              refused(lambda: bench_cli.cmd_test_quality(_LiveArgs()),
                      "no reviewed"))

        # --------------------------------------------- the refusal surface
        with open(sidecar, encoding="utf-8") as fh:
            edited = json.load(fh)
        edited["per_item"][i_full]["verdict"] = "weaker"
        tampered_path = sidecar + ".tampered"
        os.rename(sidecar, tampered_path)
        with open(sidecar, "w", encoding="utf-8") as fh:
            json.dump(edited, fh)
        check("a sidecar failing the acceptance path refuses: an edited "
              "verdict is not the arithmetic over the preserved rows",
              refused(lambda: TQ.load_bound_test_quality(run_path),
                      "re-derived"))
        os.replace(tampered_path, sidecar)
        check("the intact sidecar still validates after the tamper probe",
              TQ.load_bound_test_quality(run_path) is not None)

        docx_shaped = TQ.bind_summary(
            {"schema": TEST_QUALITY_SUMMARY_SCHEMA,
             "verdict_basis": "hard_subset"}, run_path)
        check("a sidecar without the discriminator still takes the "
              "unchanged docx/CoreShop validation path",
              refused(lambda: TQ._validate_native_summary(
                  docx_shaped, sidecar, run_path), "omits evidence path"))

        epub_run = os.path.join(tmp, "epub.jsonl")
        with open(epub_run, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(
                run_row("epubcheck/src/x.feature:1", "passed"))) + "\n")
        check("an out-of-scope project refuses by name",
              refused(lambda: build_summary(
                  epub_run, observations_dir=obs, bundle_path=bundle_path),
                  "functional-only"))
        foreign_run = os.path.join(tmp, "foreign.jsonl")
        with open(foreign_run, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(run_row(i_weak, "passed"),
                                     agent_system="sweagent")) + "\n")
        check("an unpublished agent arm refuses by name",
              refused(lambda: build_summary(
                  foreign_run, observations_dir=obs,
                  bundle_path=bundle_path), "published"))
        other_run = os.path.join(tmp, "other.jsonl")
        with open(other_run, "w", encoding="utf-8") as fh:
            for item_id, outcome in run_outcomes:
                fh.write(json.dumps(run_row(item_id, outcome)) + "\n")
            fh.write(json.dumps(run_row(item("f", 6), "passed")) + "\n")
        check("a run whose bytes are not the candidate evidence's is a "
              "different solution and refuses",
              refused(lambda: build_summary(
                  other_run, observations_dir=obs, bundle_path=bundle_path),
                  "different solution"))

        elig_path = os.path.join(obs, ELIGIBILITY_NAME)
        with open(elig_path, "r+b") as fh:
            raw = bytearray(fh.read())
            raw[-2:] = b"]}"        # still JSON-shaped damage
            fh.seek(0)
            fh.write(bytes(raw))
        check("a tampered eligibility document refuses on the frozen pin",
              refused(lambda: build_summary(
                  run_path, observations_dir=obs, bundle_path=bundle_path),
                  "pinned"))
        with open(elig_path, "wb") as fh:
            fh.write(elig_raw)

        run2_dir = os.path.join(obs, "candidate_run2_aider")
        shutil.move(run2_dir, run2_dir + ".aside")
        check("a required-but-missing run 2 withholds the sidecar",
              refused(lambda: build_summary(
                  run_path, observations_dir=obs, bundle_path=bundle_path),
                  "withheld"))
        shutil.move(run2_dir + ".aside", run2_dir)

        run1_dir = os.path.join(obs, "candidate_run1_aider")
        shutil.move(run1_dir, run1_dir + ".aside")
        check("a cell without preserved candidate evidence refuses by name",
              refused(lambda: build_summary(
                  run_path, observations_dir=obs, bundle_path=bundle_path),
                  "no preserved candidate mutation evidence"))
        shutil.move(run1_dir + ".aside", run1_dir)

        # A coherent tree over a DIFFERENT item universe re-derives its own
        # eligibility byte-identically but is not the frozen basis: only the
        # specification pin refuses it.
        obs_b, bundle_b, run_b, _raw_b = build_tree(
            os.path.join(tmp, "b"),
            item_universe=universe + [item("z", 9)],
            run1_outcomes=run1_outcomes, run2_outcomes=run2_outcomes,
            run_outcomes=run_outcomes)
        check("a coherent but unfrozen basis refuses on the specification "
              "pin alone",
              refused(lambda: build_summary(
                  run_b, observations_dir=obs_b, bundle_path=bundle_b),
                  "pinned"))
    finally:
        FROZEN_EXECUTION_BINDING_DIGEST, FROZEN_ELIGIBILITY_SHA256 = saved
        shutil.rmtree(tmp, ignore_errors=True)

    print("  " + ("ALL PASS" if ok else "FAILURES above"))
    return 0 if ok else 1


if __name__ == "__main__":
    import sys

    # Delegate to the canonical module so the pins the selftest re-points
    # are the ones `test_quality`'s validator dispatch imports.
    from r2t.bench.slice3_test_quality import selftest as _canonical_selftest
    sys.exit(_canonical_selftest())
