"""Synthetic native evaluation builds, relocation and content admission."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import copy
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
from unittest.mock import patch

from ..data import bundle as B, evaluation_bundle as E, versions
from ..data import mutation_attestation as A
from . import bundle_build as BUILD


def _write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(E.canonical_bytes(value) + b"\n")
    return str(path)


def fixture_evaluation_bundle_inputs(root, *, project="python-docx", harness_version=None, full_gold=False):
    """Complete real-native input descriptor for bundle and CLI fixtures.

    Enter the returned patch_context and patch PROJECT_SCOPES[python-docx]
    to project_scope while using these deliberately small registered facts.
    """
    root = Path(root)
    from ..bench.evaluation_reference_selftest import fixture_evaluation_inputs
    kwargs = {"project": project,
              "harness_version": (versions.component("harness")["version"] if project == "coddy-agent" else
                  18 if project == "coreshop" else 12)
                  if harness_version is None else harness_version}
    if project == "coreshop":
        kwargs["seed_workspace_files"] = {
            name: b"x" * size for name, size in E.CORESHOP_CAPTURES.items()}
    fixture = fixture_evaluation_inputs(str(root), **kwargs)
    sources = fixture["role_sources"]
    if full_gold:
        assert project == "coddy-agent"
        from ..bench import evaluation_reference as ER
        args = fixture["reference_args"]
        for role in ("stripped_gold", "stub"):
            shutil.rmtree(Path(args["reference_inputs_root"]) / role)
            shutil.rmtree(Path(args["reference_controls_root"]) / role)
            (Path(args["reference_recipes_root"]) / (role + ".json")).unlink()
        attestation = sources["gold_results_attestation"]
        Path(attestation).unlink()
        with fixture["patch_context"]():
            fixture["loaded"] = ER.seal_evaluation_reference(
                out=attestation, reference_basis="full_gold", **args)
        fixture["scope"]["reference_attestation_sha256"] = B._sha256_file(attestation)
    version = 8 if project == "algorand-sdk" else E.RELEASE_TAG
    selected = E.layout(project, version)
    profile_name = Path(selected["files"]["profile"]).name
    sources["profile"] = str(root / profile_name)
    shutil.copyfile(Path(B.BENCHMARK, "config", profile_name), sources["profile"])
    sources["worker_plan"] = _write(root / "worker-plan.json", {
        "schema": "r2t.worker-plan/1", "project": project, "k": 1,
        "workdir": "/var/www/html" if project == "coreshop" else "/work",
        "container_kind": {"coreshop": "php", "python-docx": "py",
                           "algorand-sdk": "java", "coddy-agent": "go"}[project]})
    if project != "coddy-agent":
        sources["production_index"] = _write(root / "production-index.json", {
            "methods": {}, "classes": {}})
        _write(Path(sources["gold"], "strip_manifest.json"), {"schema": "fixture-strip/1"})
    seed_pins = None
    if project == "coreshop":
        for role in ("alias_table", "autowirable_types"):
            sources[role] = _write(root / (role + ".json"), {})
        seed_pins = {name: B._sha256_file(Path(sources["seed"], name))
                     for name in E.CORESHOP_SEED_PINS}
        Path(sources["provenance"], "coreshop-seed-disclosure.md").write_text(
            "\n".join([E.CORESHOP_DISCLOSURE_REVISION, *seed_pins.values(),
                        *(Path(name).name for name in E.CORESHOP_CAPTURES),
                        "evaluation-only", "legacy_consistency"]) + "\n")
    if project == "algorand-sdk":
        # Only the common bundle contract is tested here. S3's instrumented
        # leaf below owns qualification of these Java-specific role bytes.
        for role in ("execution_view", "closures", "protocol", "oci_image"):
            sources[role] = _write(root / (role + ".json"), {"fixture_role": role})
        from .algorand_bundle import EVALUATION_PROVENANCE
        for name in EVALUATION_PROVENANCE.values():
            _write(Path(sources["provenance"], name), {"fixture_role": name})
        agent = root / "direct-calls-agent.jar"
        agent.write_bytes(b"synthetic Java-leaf fixture; not a qualified runtime\n")
        sources["direct_call_agent"] = str(agent)
    if project == "coddy-agent":
        from ..core.source_view import qualify_source_seed
        from ..data.profile import load_profile
        from ..go import assertion_strip, controls
        sources["oci_image"] = _write(root / "oci-image.json", {
            "config_image_id": fixture["loaded"]["controls"]["authority"]["container_image_digest"]})
        source = root / "source-projection"
        source.mkdir()
        profile = load_profile(sources["profile"])
        for relative in profile.readable_paths:
            original = root / "source" / relative
            if original.is_dir():
                shutil.copytree(original, source / relative)
            else:
                shutil.copyfile(original, source / relative)
        sources["source"] = str(source)
        seed = json.loads(Path(sources["seed"], "seed.json").read_text())
        source_seed = qualify_source_seed(root=str(source), project=project,
            runtime_seed_digest=seed["workspace"]["digest"], readable_paths=profile.readable_paths)
        sources["source_view_map"] = _write(root / "source-map.json", {
            "schema": "r2t.target-body-map/v2", "project": project,
            "runtime_seed_digest": source_seed.runtime_seed_digest,
            "source_files_digest": source_seed.files_digest,
            "items": [{"item_id": fixture["item_id"]}]})
        planner_root = root / "planners"
        planner_root.mkdir()
        for module, name in ((assertion_strip, "assertion_strip.go"), (controls, "controls.go")):
            shutil.copyfile(Path(module.__file__).parent / "support" / name, planner_root / name)
        sources["go_control_sources"] = str(planner_root)
        toolchain = root / "toolchain"
        (toolchain / "bin").mkdir(parents=True)
        (toolchain / "VERSION").write_text("go1.25.0\n")
        (toolchain / "bin/go").write_text("#!/bin/sh\nexit 99\n")
        (toolchain / "bin/go").chmod(0o755)
        sources["go_toolchain"] = str(toolchain)
    report_roles = {
        "raw_manifest": "raw_manifest", "manifest": "scored_manifest",
        "map": "mutation_map", "coverage_run": "coverage_run",
        "release": "map_release", "asset_index": "mutation_asset_index",
        "boundary": "boundary", "engine_source": "engine_source",
        "audit_attestation": "audit_attestation",
    }
    _write(Path(sources["mutation_validation"], "inputs.json"), {
        "schema": E.INPUT_MAP_SCHEMA, "report": "report.json",
        "inputs": {label: selected["files"][role] for label, role in report_roles.items()}})
    trees = {role: E.tree_paths(sources[role], role) for role in selected["trees"]}
    trees["provenance"] = sorted([*trees["provenance"], "payload-admission.json"])
    members = sorted(E._workspace_members(Path(sources["seed"], "workspace.tar")))
    admission = {"schema": E.ADMISSION_SCHEMA, "trees": trees,
                 "seed_workspace_members": members}
    admission_path = _write(Path(sources["provenance"], "payload-admission.json"), admission)
    descriptor = {"schema": E.INPUT_SCHEMA, "project": project,
                  "version": version,
                  "producer": {"tag": "fixture-reviewed-bundle", "commit": "1" * 40},
                  "scope": fixture["scope"], "sources": sources,
                  "admitted_trees": trees, "seed_workspace_members": members}
    descriptor_path = _write(root / "inputs.json", descriptor)
    project_scope = {**fixture["scope"], "items": 1}

    @contextmanager
    def bundle_patch_context():
        with ExitStack() as stack:
            stack.enter_context(fixture["patch_context"]())
            stack.enter_context(patch.dict(E.PROJECT_SCOPES, {project: project_scope}))
            if seed_pins is not None:
                stack.enter_context(patch.dict(E.CORESHOP_SEED_PINS, seed_pins, clear=True))
            yield

    return {**fixture, "selected": selected, "descriptor": descriptor,
            "descriptor_path": descriptor_path, "admission": admission,
            "admission_path": admission_path, "project_scope": project_scope,
            "bundle_patch_context": bundle_patch_context}


def selftest():
    ok = True

    def check(name, condition):
        nonlocal ok
        ok = ok and bool(condition)
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}")

    def refuses(fn, needle):
        try:
            fn()
        except (B.BundleRefused, A.MutationAssetRefused, ValueError) as exc:
            return needle in str(exc)
        return False

    from ..bench.evaluation_reference import _project_declaration
    declared = _project_declaration("coreshop")
    frozen = "19678c89808b13cb2c9cf0a8d3758670e9085e5286c6d51942357fb750797087"
    fields = ("task_items_sha256", "map_release_sha256")
    check("CoreShop bundle, collection declaration and template retain the collected release bytes",
          all(authority[field] == frozen for field in fields for authority in (
              E.PROJECT_SCOPES["coreshop"], declared, declared["scope_template"]["scope"])))
    scope = {**declared["scope_template"]["scope"],
             "mutation_map_sha256": "1" * 64, "reference_attestation_sha256": "2" * 64}
    check("collected CoreShop release admits independently of the latest dataset companion",
          E._scope(scope, "coreshop") == scope)
    substituted = {**scope, **{field:
        "cb4d0f2a313d23e323e052ba68da7fff87beced7a136a1a85bc31f555a679975"
        for field in fields}}
    check("later annotation bytes cannot replace the already collected mutation release",
          refuses(lambda: E._scope(substituted, "coreshop"), "approved project scope"))

    coddy = E.layout("coddy-agent", E.RELEASE_TAG)
    coddy_declaration = _project_declaration("coddy-agent")
    check("Coddy prospective full282 scope has its separate saved-plan tree and no measured count",
          coddy["trees"]["go_control_plans"].endswith("/go-control-plans")
          and {coddy["files"][role].rsplit("/", 1)[0] for role in (
              "closures", "production_index", "go_interface_attribution")} == {
                  "projects/coddy-agent/artifacts"}
          and coddy_declaration["n_items"] == 282
          and "n_scored_mutants" not in coddy_declaration
          and coddy["asset"] == "r2t-v1.0.0-rc.10-coddy-agent.tar.gz"
          and "go_control_plans" not in E.layout("python-docx", E.RELEASE_TAG)["trees"])

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        # These are real refusal paths, so old Algorand routing or legacy
        # dataset authority cannot accidentally absorb a new native layout.
        for project in ("python-docx", "coreshop", "algorand-sdk"):
            version = "8" if project == "algorand-sdk" else E.RELEASE_TAG
            missing_index = str(root / f"missing-{project}-index.json")
            with patch.object(B, "_download_asset", side_effect=AssertionError("network reached")):
                check(f"{project} evaluation validate/install/fetch all require the measured native index",
                      all(refuses(call, "evaluation release index is not a regular file")
                          for call in (
                              lambda: B.validate_installed_bundle(project, version,
                                  root=str(root / "absent"), release_index_path=missing_index),
                              lambda: B.install_bundle(project=project, version=version,
                                  archive="absent", root=str(root / "absent"),
                                  release_index_path=missing_index),
                              lambda: B.fetch_bundle(project=project, version=version,
                                  root=str(root / "absent"), release_index_path=missing_index))))
            check(f"{project} native build refuses historical inputs before opening their reports",
                  refuses(lambda: BUILD.build_bundle(project=project, version=version,
                      out="absent", candidate_run="absent", std_arm="absent"),
                      "incompatible inputs")
                  and refuses(lambda: BUILD.build_bundle(project=project,
                      version=version, out="absent"), "requires --inputs"))
        source = root / "sources"
        fixture = fixture_evaluation_bundle_inputs(source)
        selected = fixture["selected"]
        descriptor = fixture["descriptor"]
        inputs_path = fixture["descriptor_path"]
        sources = fixture["role_sources"]
        first = root / "first" / selected["asset"]
        second = root / "second" / selected["asset"]
        first.parent.mkdir()
        second.parent.mkdir()
        original_report = Path(sources["mutation_validation"], "report.json").read_bytes()

        # A source descriptor may select a validation-only copy for its
        # report input. That must still equal the role it will emit.
        resolved_sources = dict(fixture["validation_input_paths"])
        coverage_copy = root / "validation-coverage-copy.jsonl"
        shutil.copyfile(resolved_sources["coverage_run"], coverage_copy)
        resolved_sources["coverage_run"] = str(coverage_copy)
        check("source-stage native role admission accepts an exact validation-only coverage copy",
              E.validate_native_input_roles(resolved_sources, sources) is None)
        wrong_coverage = _write(root / "wrong-coverage.jsonl", {"different": "coverage"})
        check("a correct native coverage input cannot authorize a different emitted coverage role",
              refuses(lambda: E.validate_native_input_roles(resolved_sources,
                  {**sources, "coverage_run": wrong_coverage}),
                  "coverage_run differs from the installed coverage_run role"))
        runtime_applier = root / "runtime-applier.py"
        runtime_applier.write_text("# independently bound runtime applier\n")
        check("source role admission keeps the catalog enumerator separate from the runtime applier",
              E.validate_native_input_roles(resolved_sources,
                  {**sources, "engine_source": str(runtime_applier)}) is None)

        def build(out=first):
            return BUILD.build_bundle(project="python-docx", version=E.RELEASE_TAG,
                                      inputs_path=inputs_path, out=str(out))

        with fixture["patch_context"](), patch.dict(
                E.PROJECT_SCOPES, {"python-docx": fixture["project_scope"]}):
            with patch.object(BUILD, "_historical_report", side_effect=AssertionError(
                    "historical candidate evidence read")), patch.object(
                    BUILD, "_std_arm", side_effect=AssertionError("study arm read")):
                built = build()
                again = build(second)
                check("native builds need no historical candidate/report/study inputs and are deterministic",
                      first.read_bytes() == second.read_bytes()
                      and built["sha256"] == again["sha256"])
                for option in ("candidate_run", "candidate_results", "std_arm", "legacy_report"):
                    check(f"evaluation dispatch rejects {option} before historical processing",
                          refuses(lambda option=option: BUILD.build_bundle(
                              project="python-docx", version=E.RELEASE_TAG,
                              inputs_path=inputs_path, out=str(root / "never.tar.gz"),
                              **{option: "absent"}), "incompatible inputs"))
            with tarfile.open(first) as archive:
                names = archive.getnames()
                check("only authenticated stripped/stub observations carry candidate shard filenames",
                      sum(name.endswith("/candidate.w0.jsonl") for name in names) == 2
                      and not any("candidate_results" in name or "std_arm" in name for name in names))

            private_index = root / "private-release.json"
            measured = E.measure_evaluation_release(
                archive=str(first), manifest=built["manifest"], out=str(private_index))
            check("private index measures actual archive and manifest before publication",
                  measured["asset"]["sha256"] == B._sha256_file(first)
                  and measured["bundle_manifest_sha256"] == B._sha256_file(built["manifest"])
                  and measured["producer"] == descriptor["producer"])

            # These are the files the report originally names, and every
            # resource path its observations recorded. Remove all of them.
            source.rename(root / "producer-unavailable")
            installed = root / "installed"
            with patch.object(B, "_download_asset", side_effect=AssertionError("network reached")):
                report = B.install_bundle(project="python-docx", version=E.RELEASE_TAG,
                    archive=str(first), root=str(installed), release_index_path=str(private_index))
            relocated = root / "relocated"
            installed.rename(relocated)
            verified = B.validate_installed_bundle("python-docx", E.RELEASE_TAG,
                root=str(relocated), release_index_path=str(private_index))
            check("local installation and full native rederivation survive unavailable producer and installation paths",
                  report["release_ready"] and verified["release_ready"]
                  and verified["reference"]["digest"] == fixture["loaded"]["controls"]["digest"]
                  and Path(verified["role_paths"]["mutation_validation"], "report.json")
                      .read_bytes() == original_report)
            check("later bundle producer preserves the earlier reference source identity",
                  measured["producer"]["tag"] == "fixture-reviewed-bundle"
                  and json.loads(Path(verified["role_paths"]["gold_results_attestation"])
                                 .read_text())["authority"]["reference_source_tag"]
                      == "fixture-reviewed-reference")
            check("installed profile keeps its literal original boundary sibling",
                  Path(verified["role_paths"]["profile"]).name == "profile_python_docx.yml"
                  and Path(verified["role_paths"]["boundary"]).name == "boundary_python_docx.yml")
            defaults = root / "default-authority"
            default_index = defaults / "release/evaluation/python-docx.json"
            _write(default_index, measured)
            with patch.object(B, "BENCHMARK", str(defaults)):
                default_validated = B.validate_installed_bundle(
                    "python-docx", E.RELEASE_TAG, root=str(relocated))
                check("default installed validation resolves the complete per-project release index",
                      default_validated["reference"] == verified["reference"])
                changed_index = copy.deepcopy(measured)
                changed_index["producer"]["commit"] = "2" * 40
                _write(default_index, changed_index)
                check("default installed validation refuses a different recorded producer",
                      refuses(lambda: B.validate_installed_bundle(
                          "python-docx", E.RELEASE_TAG, root=str(relocated)),
                          "differ from the release index"))
                default_index.unlink()
                check("installed validation never falls back to unpinned staging when its index is absent",
                      refuses(lambda: B.validate_installed_bundle(
                          "python-docx", E.RELEASE_TAG, root=str(relocated)),
                          "evaluation release index is not a regular file"))
            from ..bench.evaluation_reference_selftest import score_fixture_candidate
            summary = score_fixture_candidate(root / "private-acceptance",
                role_paths=verified["role_paths"], reference_reader=lambda: E._reference(
                    "python-docx", verified["role_paths"], fixture["scope"],
                    verified["validation_input_paths"]))
            check("a private candidate scores against the relocated archive with zero reference execution jobs",
                  summary["generation_provenance_class"] == "development_unstamped"
                  and summary["slices"]
                  and {row["side"] for row in summary["slices"]} == {"candidate"}
                  and not (relocated / "private-acceptance").exists())
            downloads = []

            def download(**kwargs):
                downloads.append(kwargs)
                shutil.copyfile(first, kwargs["destination"])

            with patch.object(B, "_download_asset", side_effect=download), patch.object(
                    B, "_authority", side_effect=AssertionError("historical authority reached")):
                fetched = B.fetch_bundle(project="python-docx", version=E.RELEASE_TAG,
                    root=str(root / "fetched"), release_index_path=str(private_index))
            check("generic fetch selects the evaluation index and all public reports are JSON-friendly",
                  len(downloads) == 1 and downloads[0]["version"] == E.RELEASE_TAG
                  and fetched["sha256"] == report["sha256"]
                  and all(json.loads(json.dumps(value))["project"] == "python-docx"
                          for value in (built, measured, report, verified, fetched)))
            check("a measured private index cannot install an occupied project",
                  refuses(lambda: B.install_bundle(project="python-docx", version=E.RELEASE_TAG,
                      archive="absent", root=str(relocated), release_index_path=str(private_index)),
                      "destination already exists"))
            bad_index = copy.deepcopy(measured)
            bad_index["asset"]["sha256"] = None
            _write(root / "null-index.json", bad_index)
            check("a reservation with a null archive pin cannot authorize local installation",
                  refuses(lambda: B.install_bundle(project="python-docx", version=E.RELEASE_TAG,
                      archive="absent", root=str(root / "null-install"),
                      release_index_path=str(root / "null-index.json")), "not a SHA-256"))
            bad_index = copy.deepcopy(measured)
            bad_index["bundle_manifest_sha256"] = "0" * 64
            _write(root / "wrong-index.json", bad_index)
            check("a matching archive still needs the exact measured manifest pin",
                  refuses(lambda: B.install_bundle(project="python-docx", version=E.RELEASE_TAG,
                      archive=str(first), root=str(root / "wrong-install"),
                      release_index_path=str(root / "wrong-index.json")), "differ from the release index")
                  and not (root / "wrong-install/projects/python-docx").exists())

            # Restore our own synthetic source fixture for rejection builds.
            (root / "producer-unavailable").rename(source)
            worker_plan_path = Path(sources["worker_plan"])
            worker_plan_bytes = worker_plan_path.read_bytes()
            for field, value in (("container_kind", "php"),
                                 ("workdir", "/wrong-runtime-root")):
                wrong_plan = json.loads(worker_plan_bytes)
                wrong_plan[field] = value
                _write(worker_plan_path, wrong_plan)
                check(f"evaluation worker {field} must match the project's runtime contract",
                      refuses(lambda: build(second.parent / "new" / selected["asset"]),
                              "profile/runtime contract"))
            varying_k = json.loads(worker_plan_bytes)
            varying_k["k"] = 2
            _write(worker_plan_path, varying_k)
            different_k = root / "different-worker-count"
            different_k.mkdir()
            check("the project runtime contract permits a different positive worker count",
                  build(different_k / selected["asset"])["release_ready"])
            worker_plan_path.write_bytes(worker_plan_bytes)

            injected = Path(sources["provenance"], "private/candidate_results.jsonl")
            _write(injected, {"private_candidate_result": "must not ship"})
            expanded = copy.deepcopy(descriptor)
            expanded["admitted_trees"]["provenance"] = sorted([
                *expanded["admitted_trees"]["provenance"], "private/candidate_results.jsonl"])
            expanded_admission = copy.deepcopy(fixture["admission"])
            expanded_admission["trees"] = expanded["admitted_trees"]
            _write(inputs_path, expanded)
            _write(fixture["admission_path"], expanded_admission)
            check("expanding both admission lists cannot authorize candidate results as provenance",
                  refuses(lambda: build(second.parent / "new" / selected["asset"]),
                          "provenance differs from the project source-role contract"))
            injected.unlink()
            injected.parent.rmdir()
            incomplete = copy.deepcopy(descriptor)
            incomplete["admitted_trees"]["provenance"].remove("reference-recipes/stub.json")
            incomplete_admission = copy.deepcopy(fixture["admission"])
            incomplete_admission["trees"] = incomplete["admitted_trees"]
            _write(inputs_path, incomplete)
            _write(fixture["admission_path"], incomplete_admission)
            check("shrinking both admission lists cannot omit required control source provenance",
                  refuses(lambda: build(second.parent / "new" / selected["asset"]),
                          "provenance differs from the project source-role contract"))
            _write(inputs_path, descriptor)
            _write(fixture["admission_path"], fixture["admission"])
            extra = Path(sources["gold"], "private/candidate_results.jsonl")
            extra.parent.mkdir()
            extra.write_text("{}\n")
            check("nested candidate results cannot enter a permitted gold tree",
                  refuses(lambda: build(root / "never.tar.gz"), "outside its admitted inputs"))
            extra.unlink()
            extra.parent.rmdir()
            bad_descriptor = copy.deepcopy(descriptor)
            bad_descriptor["sources"]["candidate_results"] = "absent"
            _write(inputs_path, bad_descriptor)
            check("generated candidate evidence is not an optional evaluation source role",
                  refuses(lambda: build(root / "never.tar.gz"), "source roles"))
            _write(inputs_path, descriptor)

            input_map_path = Path(sources["mutation_validation"], "inputs.json")
            saved_map = input_map_path.read_bytes()
            location_map = json.loads(saved_map)
            location_map["inputs"]["map"] = "private/candidate-results.jsonl"
            _write(input_map_path, location_map)
            check("native validation locations cannot resolve outside the closed inventory",
                  refuses(lambda: build(second.parent / "new" / selected["asset"]),
                          "outside the closed bundle inventory"))
            input_map_path.write_bytes(saved_map)

            seed_path = Path(sources["seed"], "workspace.tar")
            seed_manifest = Path(sources["seed"], "seed.json")
            saved_seed, saved_seed_manifest = seed_path.read_bytes(), seed_manifest.read_bytes()
            with tarfile.open(seed_path, "a") as archive:
                payload = b"private generated output\n"
                info = tarfile.TarInfo("private/candidate-results.jsonl")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            manifest = json.loads(saved_seed_manifest)
            manifest["workspace"]["digest"] = B._sha256_file(seed_path)
            manifest["workspace_seed_digest"] = manifest["workspace"]["digest"]
            _write(seed_manifest, manifest)
            check("a valid outer seed manifest cannot hide an unadmitted nested payload",
                  refuses(lambda: build(second.parent / "new" / selected["asset"]),
                          "admitted member set"))
            modified = copy.deepcopy(descriptor)
            modified["seed_workspace_members"] = sorted(E._workspace_members(seed_path))
            admission = copy.deepcopy(fixture["admission"])
            admission["seed_workspace_members"] = modified["seed_workspace_members"]
            _write(inputs_path, modified)
            _write(fixture["admission_path"], admission)
            check("a caller's expanded member list cannot replace the reference's authenticated seed identity",
                  refuses(lambda: build(second.parent / "new" / selected["asset"]),
                          "differs from the installed seed"))
            seed_path.write_bytes(saved_seed)
            seed_manifest.write_bytes(saved_seed_manifest)
            _write(inputs_path, descriptor)
            _write(fixture["admission_path"], fixture["admission"])

            # The complete native/report/control path is real above. This
            # deliberately wrong scope must fail before accepting any score.
            wrong_scope = copy.deepcopy(descriptor)
            wrong_scope["scope"]["mutation_map_sha256"] = "0" * 64
            _write(inputs_path, wrong_scope)
            check("a wrong final map scope refuses despite otherwise complete native input closure",
                  refuses(lambda: build(second.parent / "new" / selected["asset"]),
                          "mutation_map_sha256 differs"))
            _write(inputs_path, descriptor)

        with patch.object(BUILD, "_authority", side_effect=B.BundleRefused("legacy authority reached")):
            check("historical builds still select their existing authority",
                  refuses(lambda: BUILD.build_bundle(project="python-docx", version="old",
                      out="unused", seed_dir="seed", gold_dir="gold", release_gold="release-gold",
                      raw_manifest="raw", legacy_map="map", coverage_run="coverage",
                      candidate_run="candidate", candidate_results="results", gold_results="gold-results"),
                      "legacy authority reached"))
        check("all three approved layouts retain their distinct roots and original config basenames",
              E.layout("coreshop", E.RELEASE_TAG)["files"]["boundary"].endswith("boundary_coreshop.yml")
              and E.layout("algorand-sdk", "8")["bundle_root"] == "bundles/v8/algorand-sdk"
              and E.layout("algorand-sdk", 8)["version"] == 8
              and not E.is_evaluation_bundle("algorand-sdk", "5"))
        _seed_disclosure_checks(root, check, refuses)
        for project in ("coreshop", "algorand-sdk", "coddy-agent"):
            _project_roundtrip(root / project, project, check, refuses)
        _project_roundtrip(root / "coddy-fullgold", "coddy-agent", check, refuses, full_gold=True)
        withdrawn = fixture_evaluation_bundle_inputs(
            root / "withdrawn-coreshop", project="coreshop", harness_version=12)
        with withdrawn["bundle_patch_context"]():
            check("internally consistent withdrawn H12 CoreShop references cannot build a bundle",
                  refuses(lambda: BUILD.build_evaluation_bundle(
                      inputs_path=withdrawn["descriptor_path"],
                      out=str(root / "withdrawn-coreshop" / withdrawn["selected"]["asset"])),
                      "reference harness 12 is incompatible"))
        qualified = _qualified_v8_roundtrip(root / "qualified-v8")
        check("V8 uses real Java qualification through build, private install, relocation and candidate-only scoring",
              qualified["release_items"] == 117 and qualified["execution_items"] == 111
              and qualified["mapped_pairs"] == 117 and qualified["reference_pairs"] == 111
              and qualified["candidate_slices"] == 1 and qualified["reference_jobs"] == 0)

    print("\n" + ("ALL PASS (evaluation_bundle)" if ok else "FAILURES (evaluation_bundle)"))
    return 0 if ok else 1


def _project_roundtrip(root, project, check, refuses, *, full_gold=False):
    """Real native reference chain for CoreShop and the shared V8 layout."""
    from ..bench.evaluation_reference_selftest import score_fixture_candidate
    from . import algorand_bundle

    root.mkdir()
    source = root / "source"
    fixture = fixture_evaluation_bundle_inputs(source, project=project, full_gold=full_gold)
    selected = fixture["selected"]
    version = selected["version"]
    output = root / selected["asset"]
    original_report = Path(fixture["role_sources"]["mutation_validation"], "report.json").read_bytes()
    java_calls = []

    def java_leaf(*, role_paths, producer):
        java_calls.append((role_paths, producer))
        assert producer == fixture["descriptor"]["producer"]
        assert all(Path(role_paths[role]).is_file() for role in (
            "execution_view", "closures", "protocol", "oci_image", "direct_call_agent"))
        return {"fixture_leaf": True,
                "boundary_approval": {"fixture_leaf": True}}

    with fixture["bundle_patch_context"](), ExitStack() as stack:
        if project == "algorand-sdk":
            # Runtime/source/image qualification is S3's separate leaf.
            # Native Java catalog/report/control derivation stays real.
            stack.enter_context(patch.object(algorand_bundle,
                "validate_evaluation_roles", side_effect=java_leaf, create=True))
        if project in {"coddy-agent", "algorand-sdk"}:
            wrong_roles = copy.deepcopy(fixture["descriptor"])
            if project == "coddy-agent":
                check("Coddy native inputs do not require a singular protocol",
                      "protocol" not in selected["files"]
                      and "protocol" not in wrong_roles["sources"])
                wrong_roles["sources"]["protocol"] = _write(
                    root / "unrelated-protocol.json", {"fixture": "unrelated"})
                label = "Coddy rejects an unrelated protocol role"
            else:
                wrong_roles["sources"].pop("protocol")
                label = "Algorand still requires its protocol role"
            wrong_path = _write(root / "wrong-protocol-roles.json", wrong_roles)
            check(label, refuses(lambda: BUILD.build_evaluation_bundle(
                inputs_path=wrong_path, out=str(root / "rejected.tar.gz")),
                "evaluation build source roles"))
        built = BUILD.build_evaluation_bundle(
            inputs_path=fixture["descriptor_path"], out=str(output))
        if project == "coddy-agent":
            second_dir = root / "second-build"
            second_dir.mkdir()
            second = BUILD.build_evaluation_bundle(
                inputs_path=fixture["descriptor_path"], out=str(second_dir / selected["asset"]))
            check("Coddy repeated builds preserve identical bytes and executable compiler modes",
                  output.read_bytes() == Path(second["out"]).read_bytes())
        private_index = root / "private-index.json"
        E.measure_evaluation_release(archive=str(output), manifest=built["manifest"],
                                     out=str(private_index))
        if project == "coddy-agent":
            stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError(
                "installed validation or scoring launched a compiler/reference process")))
        source.rename(root / "source-unavailable")
        installed = root / "installed"
        B.install_bundle(project=project, version=version, archive=str(output),
                         root=str(installed), release_index_path=str(private_index))
        relocated = root / "relocated"
        installed.rename(relocated)
        verified = B.validate_installed_bundle(project, version, root=str(relocated),
                                               release_index_path=str(private_index))
        check(f"{project} shared native bundle builds without candidates and rederives after installation relocation",
              verified["release_ready"]
              and verified["reference"]["digest"] == fixture["loaded"]["controls"]["digest"]
              and Path(verified["role_paths"]["mutation_validation"], "report.json")
                  .read_bytes() == original_report)
        if project == "coddy-agent":
            _coddy_original_roundtrip(root, verified, check, refuses)
            if full_gold:
                provenance = Path(verified["role_paths"]["provenance"])
                check("fullgold Coddy bundle reopens after producer removal with no stripped/stub mutation evidence",
                      set(E.tree_paths(str(provenance / "reference-recipes"), "recipes")) == {"full_gold.json"}
                      and set(Path(verified["role_paths"]["gold_results"]).iterdir()) ==
                          {Path(verified["role_paths"]["gold_results"]) / "full_gold"})
        summary = score_fixture_candidate(root / "private-candidate",
            role_paths=verified["role_paths"], reference_reader=lambda: E._reference(
                project, verified["role_paths"], fixture["scope"],
                verified["validation_input_paths"]))
        check(f"{project} installed native reference supports candidate-only scoring without reference jobs",
              {row["side"] for row in summary["slices"]} == {"candidate"}
              and summary["generation_provenance_class"] == "development_unstamped")
        if project == "coreshop":
            check("CoreShop round trip retains its eight disclosed captures and database seed identity",
                  verified["worker_plan"]["container_kind"] == "php"
                  and Path(verified["role_paths"]["provenance"], "coreshop-seed-disclosure.md").is_file()
                  and len([path for path in E._workspace_members(Path(
                      verified["role_paths"]["seed"], "workspace.tar"))
                      if path in E.CORESHOP_CAPTURES]) == 8)
        elif project == "algorand-sdk":
            check("shared V8 preserves its authenticated item declaration and delegates each Java qualification",
                  len(java_calls) == 4
                  and verified["boundary_approval"] == {"fixture_leaf": True}
                  and verified["reference"]["declared_subset"]["declared_items"] == 1
                  and verified["reference"]["declared_subset"]["release_items"] == 2)
            with patch.object(algorand_bundle, "validate_evaluation_roles",
                              side_effect=B.BundleRefused("Java qualification refused")):
                check("the shared V8 validator propagates S3 qualification refusal",
                      refuses(lambda: B.validate_installed_bundle(project, version,
                          root=str(relocated), release_index_path=str(private_index)),
                          "Java qualification refused"))


def _coddy_original_roundtrip(root, verified, check, refuses):
    """Installed files reach the live original reader with the producer absent."""
    from types import SimpleNamespace
    from unittest.mock import Mock
    from ..core.boundary import load_boundary
    from ..go import mutation_runtime as runtime
    from ..go.context import ContextTable
    paths = verified["role_paths"]
    image_id = json.loads(Path(paths["oci_image"]).read_text())["config_image_id"]
    attribution_path = Path(paths["go_interface_attribution"])
    original = attribution_path.read_bytes()
    attribution = json.loads(original)
    check("Coddy attribution keeps its historical producer label after relocation",
          not Path(attribution["source_root"]).exists()
          and E._coddy_originals(paths, image_id) is None)
    missing = attribution_path.with_suffix(".absent")
    attribution_path.rename(missing)
    check("Coddy installed original admission refuses missing attribution",
          refuses(lambda: E._coddy_originals(paths, image_id), "Coddy original attribution"))
    missing.rename(attribution_path)
    changes = [
        ("source identity", lambda value: value.update(source_root="/different-source")),
        ("image identity", lambda value: value.update(image_id="sha256:" + "0" * 64)),
        ("context membership", lambda value: value["contexts"][0].update(files=[])),
        ("compiled package", lambda value: value["partitions"][0].update(compiled_package_name="other")),
        ("compiled source hash", lambda value: value["partitions"][0]["source_files"].update(
            {next(iter(value["partitions"][0]["source_files"])): "0" * 64})),
        ("source outside readable projection", lambda value: value["source_inventory"]["pkg/resource.txt"].update(sha256="0" * 64)),
        ("unselected gold source", lambda value: value["source_inventory"][
            "cmd/coddy/bdd_sessions_export_test.go"].update(sha256="0" * 64)),
    ]
    for label, change in changes:
        altered = copy.deepcopy(attribution)
        change(altered)
        _write(attribution_path, altered)
        check("Coddy offline attribution refuses changed " + label,
              refuses(lambda: E._coddy_originals(paths, image_id), "REFUSED"))
    attribution_path.write_bytes(original)

    with patch.object(runtime.M, "GO_SOURCE", root / "absent-checkout-builder.go"):
        check("Coddy bundle binds its seed to the shipped runtime applier, not this checkout's builder",
              E._coddy_originals(paths, image_id) is None)
    engine = Path(paths["engine_source"])
    shipped = engine.read_bytes()
    engine.write_bytes(shipped + b"\n// another runtime applier\n")
    check("Coddy bundle refuses a runtime applier other than the seed-installed one",
          refuses(lambda: E._coddy_originals(paths, image_id),
                  "differs from preserved seed: " + runtime.ENGINE_PATH))
    engine.write_bytes(shipped)

    workspace = root / "bound-worker"
    workspace.mkdir()
    with tarfile.open(Path(paths["seed"], "workspace.tar")) as archive:
        for member in archive:
            target = workspace / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
    artifacts = root / "bound-worker-artifacts"
    artifacts.mkdir()
    for role in ("closures", "production_index", "go_interface_attribution"):
        shutil.copyfile(paths[role], artifacts / Path(paths[role]).name)
    closures = json.loads(Path(paths["closures"]).read_text())
    boundary = load_boundary(paths["boundary"])
    table = ContextTable(closures, boundary=boundary, project="coddy-agent")
    strip = json.loads(Path(paths["gold"], "strip_manifest.json").read_text())
    harness = SimpleNamespace(root=str(workspace), boundary=boundary, contexts=table,
        expected_mutations={}, manifest=SimpleNamespace(gold_root=paths["gold"], moved=strip["moved"]),
        copy=SimpleNamespace(_state="idle", original_inventory={
            path.relative_to(workspace).as_posix(): B._sha256_file(path)
            for path in workspace.rglob("*") if path.is_file()}),
        check_context=table.check_context, verify_substrate=Mock())
    manifest = json.loads(Path(paths["scored_manifest"]).read_text())
    authority = runtime.prepare_original(harness, manifest, artifacts, image_id=image_id)
    check("relocated Coddy bundle provisions the three worker artifacts for real Go original preparation",
          authority.original_root == attribution["source_root"]
          and "pkg/resource.txt" in authority.reference_files
          and "cmd/coddy/bdd_sessions_export_test.go" in authority.reference_files
          and not Path(paths["source"], "pkg/resource.txt").exists()
          and harness.verify_substrate.call_count == 1)


def _qualified_v8_roundtrip(root):
    """Build, install, relocate and score with S3's real qualification leaf.

    This requires S3's composable evaluation fixture. Only its synthetic
    registry/runtime pins are substituted; qualification, native reports,
    source derivation, installed validation and candidate scoring stay real.
    """
    from ..bench.evaluation_reference_selftest import (
        fixture_from_algorand_roles, score_fixture_candidate)
    from . import algorand_bundle

    root = Path(root)
    root.mkdir()
    producer_root = root / "producer"
    producer_root.mkdir()
    s3_root = producer_root / "s3"
    s3_root.mkdir()
    roles, pins = algorand_bundle._fixture_evaluation_roles(str(s3_root))
    producer = {"tag": "v1.0.0-fixture", "commit": "1" * 40}
    fixture = fixture_from_algorand_roles(producer_root / "native", roles, producer)
    sources = fixture["role_sources"]
    selected = E.layout("algorand-sdk", 8)
    report_roles = {
        "raw_manifest": "raw_manifest", "manifest": "scored_manifest",
        "map": "mutation_map", "coverage_run": "coverage_run",
        "release": "map_release", "asset_index": "mutation_asset_index",
        "boundary": "boundary", "engine_source": "engine_source",
        "audit_attestation": "audit_attestation",
    }
    _write(Path(sources["mutation_validation"], "inputs.json"), {
        "schema": E.INPUT_MAP_SCHEMA, "report": "report.json",
        "inputs": {label: selected["files"][role] for label, role in report_roles.items()}})
    admitted = {role: E.tree_paths(sources[role], role) for role in selected["trees"]}
    admitted["provenance"] = sorted([*admitted["provenance"], "payload-admission.json"])
    members = sorted(E._workspace_members(Path(sources["seed"], "workspace.tar")))
    _write(Path(sources["provenance"], "payload-admission.json"), {
        "schema": E.ADMISSION_SCHEMA, "trees": admitted,
        "seed_workspace_members": members})
    descriptor = _write(producer_root / "bundle-inputs.json", {
        "schema": E.INPUT_SCHEMA, "project": "algorand-sdk", "version": 8,
        "producer": producer, "scope": fixture["scope"], "sources": sources,
        "admitted_trees": admitted, "seed_workspace_members": members})
    report_bytes = Path(sources["mutation_validation"], "report.json").read_bytes()
    archive = root / selected["asset"]
    private_index = root / "private-index.json"
    installed, relocated = root / "installed", root / "relocated"
    with fixture["patch_context"](), patch.dict(E.PROJECT_SCOPES, {
            "algorand-sdk": {**fixture["scope"], "items": 111}}), patch.object(
            algorand_bundle, "_evaluation_runtime_pins", return_value=pins):
        built = algorand_bundle.build_bundle(inputs_path=descriptor,
                                             out=str(archive), version="8")
        index = E.measure_evaluation_release(archive=str(archive),
            manifest=built["manifest"], out=str(private_index))
        producer_root.rename(root / "producer-unavailable")
        B.install_bundle(project="algorand-sdk", version="8", archive=str(archive),
                         root=str(installed), release_index_path=str(private_index))
        installed.rename(relocated)
        verified = B.validate_installed_bundle("algorand-sdk", "8",
            root=str(relocated), release_index_path=str(private_index))
        summary = score_fixture_candidate(root / "private-candidate",
            role_paths=verified["role_paths"], reference_reader=lambda: E._reference(
                "algorand-sdk", verified["role_paths"], fixture["scope"],
                verified["validation_input_paths"]))
        declaration = verified["reference"]["declared_subset"]
        assert declaration["declared_items"] == 111 and declaration["release_items"] == 117
        assert verified["reference"]["digest"] == fixture["loaded"]["controls"]["digest"]
        assert Path(verified["role_paths"]["mutation_validation"], "report.json").read_bytes() == report_bytes
        # This fixture packages the reviewed boundary, so the disclosure the
        # consumer reads after install and relocation states no difference.
        assert verified["boundary_approval"]["difference"] is None
        assert {row["side"] for row in summary["slices"]} == {"candidate"}
        assert summary["generation_provenance_class"] == "development_unstamped"
        assert not producer_root.exists() and not installed.exists()
    return {"project": "algorand-sdk", "release_items": 117, "execution_items": 111,
            "catalog_mutants": fixture["manifest"]["n"],
            "mapped_pairs": fixture["map"]["n_pairs"],
            "reference_pairs": verified["reference"]["pairs"]["count"],
            "candidate_slices": len(summary["slices"]), "reference_jobs": 0,
            "reference_digest": verified["reference"]["digest"],
            "archive_sha256": index["asset"]["sha256"]}


def _seed_disclosure_checks(root, check, refuses):
    """Tiny registered seed identity substitutes only the approved byte pins."""
    seed = root / "disclosed-seed"
    provenance = root / "disclosed-provenance"
    seed.mkdir()
    provenance.mkdir()
    with tarfile.open(seed / "workspace.tar", "w") as archive:
        for name, size in E.CORESHOP_CAPTURES.items():
            info = tarfile.TarInfo(name)
            info.size = size
            archive.addfile(info, io.BytesIO(b"x" * size))
    (seed / "database.sql").write_bytes(b"-- synthetic frozen database\n")
    _write(seed / "seed.json", {"format": 1, "seed_key": "synthetic-disclosed-seed",
        "needs_database": True,
        "workspace": {"digest": B._sha256_file(seed / "workspace.tar")},
        "database": {"digest": B._sha256_file(seed / "database.sql")}})
    pins = {name: B._sha256_file(seed / name) for name in E.CORESHOP_SEED_PINS}
    disclosure = provenance / "coreshop-seed-disclosure.md"
    disclosure.write_text("\n".join([
        E.CORESHOP_DISCLOSURE_REVISION, *pins.values(),
        *(Path(name).name for name in E.CORESHOP_CAPTURES),
        "evaluation-only", "legacy_consistency"]) + "\n")
    admission = {"trees": {"seed": sorted(pins)},
                 "seed_workspace_members": sorted(E.CORESHOP_CAPTURES)}
    paths = {"seed": str(seed), "provenance": str(provenance)}
    with patch.dict(E.CORESHOP_SEED_PINS, pins, clear=True):
        facts = E._seed("coreshop", paths, admission)
        check("the exact eight historical captures are retained under an external disclosure",
              facts["artifacts_ok"] and B._sha256_file(seed / "workspace.tar") == pins["workspace.tar"])
        disclosure.unlink()
        check("the retained CoreShop seed cannot omit its external disclosure",
              refuses(lambda: E._seed("coreshop", paths, admission), "external disclosure"))
        (seed / "database.sql").write_bytes(b"-- replacement\n")
        check("the seed disposition grants no exemption to replacement seed bytes",
              refuses(lambda: E._seed("coreshop", paths, admission), "does not verify"))


if __name__ == "__main__":
    raise SystemExit(selftest())
