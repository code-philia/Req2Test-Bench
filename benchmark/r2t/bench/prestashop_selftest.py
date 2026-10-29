"""Focused PrestaShop runtime fixtures; no corpus, Docker or database required."""
from __future__ import annotations

from contextlib import redirect_stdout
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import mock

import yaml

from ..core.boundary import Boundary
from ..core.gherkin import parse_feature_file
from . import repo, seed, worker
from .harness import Harness, RunResult, Solution
from ..toolkit.behat_suites import load_suite_map, select_suite

PHP_DIR = Path(__file__).resolve().parents[1] / "php"
CONTEXT = "tests/Integration/Behaviour/Features/Context"
NAMESPACE = "Tests\\Integration\\Behaviour\\Features\\Context"
BENCH = "tests/Integration/Behaviour/Bench"


def fixture_boundary(root: str) -> Boundary:
    return Boundary(
        version=1, project="prestashop", repo_root=root,
        removable=[(CONTEXT + "/", ""), ("tests/Integration/Behaviour/behat.yml", "")],
        retained=[(CONTEXT + "/CommonFeatureContext.php", ""),
                  ("tests/Integration/Behaviour/Features/Transform/", ""), (BENCH + "/", "")],
        removable_config=["tests/Integration/Behaviour/behat.yml"],
        retained_contexts=[NAMESPACE + "\\CommonFeatureContext"],
        raw={"behat": {
            "config_dir": "tests/Integration/Behaviour", "services_entry": None,
            "hook_services": None, "suites_entry": "behat.yml", "test_config": None,
            "original_services_import": None, "bench_services_import": None,
            "suite_root": "tests/Integration/Behaviour/Features/Scenario",
            "recorder_rel": BENCH + "/BenchRecorderHook.php",
            "recorder_namespace": "Tests\\Integration\\Behaviour\\Bench",
            "psr4": {"Tests\\": "tests/"}, "extensions": [], "bootstrap": None,
            "suite_scoped": True, "db_dsn_env": "DATABASE_URL", "db_install_vars": False,
            "worker_init": "prestashop", "coverage_roots": ["src", "classes", "controllers"],
            "trace_roots": ["src", "classes", "controllers", "tests/Integration/Behaviour"],
            "callee_roots": ["src", "classes", "controllers"],
            "reset_program": "prestashop", "reset_marker_table": "ps_configuration",
            "reset_context_rel": CONTEXT + "/Domain/R2tResetProbeContext.php",
            "stub_namespace": NAMESPACE + "\\Domain", "stub_dir": CONTEXT + "/Domain",
        }})


def selftest() -> int:
    failures = []

    def check(label, condition):
        print(f"  [{'PASS' if condition else 'FAIL'}] {label}")
        if not condition:
            failures.append(label)

    bp = repo.behat_project(fixture_boundary("/fixture"))
    template = (PHP_DIR / "BenchRecorderHook.php").read_text()
    rendered = repo.recorder_source(template, bp)
    check("CoreShop recorder bytes remain unchanged", repo.recorder_source(template, repo.CORESHOP_BEHAT) == template)
    check("coverage includes all three production roots but no test root",
          all(f'$filter->includeDirectory(self::$root . "/{p}")' in rendered
              for p in ("src", "classes", "controllers"))
          and '$filter->includeDirectory(self::$root . "/tests' not in rendered)
    check("trace collects glue call sites and reducer accepts legacy callee roots",
          'self::$root . "/tests/Integration/Behaviour/"' in rendered
          and '$root . "/classes/"' in rendered and '$root . "/controllers/"' in rendered)
    check("seed policy retains native dumps and resource backups and prunes no table",
          seed.rules_for("behat", "prestashop") is seed.PRESTASHOP_RULES
          and not seed.PRESTASHOP_RULES.prune_tables
          and not seed.PRESTASHOP_RULES.excluded("var/r2t-db-dumps/ps_dump_test_seed_9.3.0.sql")
          and not seed.PRESTASHOP_RULES.excluded("var/r2t-db-dumps/ps_backup_test_modules/example.php"))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "app"
        gold = Path(tmp) / "gold"
        common = NAMESPACE + "\\CommonFeatureContext"
        cms = NAMESPACE + "\\Domain\\CmsPageFeatureContext"
        transform = "Tests\\Integration\\Behaviour\\Features\\Transform\\StringToBoolTransformContext"
        beh = root / "tests/Integration/Behaviour"
        (beh / "Features/Scenario/CmsPage").mkdir(parents=True)
        (beh / "Features/Context/Domain").mkdir(parents=True)
        (beh / "Features/Transform").mkdir()
        (beh / "Features/Context/CommonFeatureContext.php").write_text("<?php // retained hook\n")
        (beh / "Features/Context/Domain/CmsPageFeatureContext.php").write_text("<?php // removable gold\n")
        (beh / "Features/Transform/StringToBoolTransformContext.php").write_text("<?php // retained transform\n")
        (beh / "behat.yml").write_text(yaml.safe_dump({"default": {"suites": {
            "cms_page": {"paths": ["%paths.base%/Features/Scenario/CmsPage"], "contexts": [common, cms]},
            "customer": {"paths": ["%paths.base%/Features/Scenario/Customer"],
                         "filters": {"tags": "@search-customers"}, "contexts": [common, cms]},
            "product": {"paths": ["%paths.base%/Features/Scenario/Product"],
                        "filters": {"tags": "~@legacy-product-type"}, "contexts": [common, transform]},
            "legacy_product": {"paths": ["%paths.base%/Features/Scenario/Product"],
                               "filters": {"tags": "@legacy-product-type"}, "contexts": [common]},
        }}}))
        boundary = fixture_boundary(str(root))
        manifest = repo.strip_repo(boundary, str(gold), str(PHP_DIR))
        m = load_suite_map(str(gold / "suite_map.json"))
        selected = select_suite(m, [], "tests/Integration/Behaviour/Features/Scenario/CmsPage/cms_page_management.feature")
        h = Harness(manifest, boundary, mock.Mock())
        contexts = h.write_behat_config([cms], suite=selected)
        document = yaml.safe_load((root / bp.bench_config).read_text())["bench"]
        check("CMS original suite does not gain the enable-to-bool transform",
              selected == "cms_page" and transform not in contexts
              and contexts == [common, cms, bp.recorder_namespace + "\\BenchRecorderHook"])
        check("direct-class Behat has no Symfony extension and initializer is retained",
              document["extensions"] == {} and (root / BENCH / "prestashop_worker_init.php").is_file()
              and not (root / "_bench/suite_map.json").exists())
        feature = "tests/Integration/Behaviour/Features/Scenario/Product/example.feature"
        check("overlapping product paths still obey original tags",
              select_suite(m, ["@legacy-product-type"], feature) == "legacy_product"
              and select_suite(m, [], feature) == "product")
        # Exact native Customer/search_customers.feature header layout: the
        # blank on line 5 must not discard reset/cache hooks before Feature.
        customer_text = """# ./vendor/bin/behat -c tests/Integration/Behaviour/behat.yml -s customer --tags search-customers
@restore-all-tables-before-feature
@clear-cache-before-feature
@search-customers

Feature: Search customers given a search term (BO)
  As a BO user
  I want to get a list of customers for a given search term

  Scenario: I search for existing customers
    When I create a customer
"""
        customer_path = str(beh / "Features/Scenario/Customer/search_customers.feature")
        legacy = parse_feature_file(customer_path, customer_text)
        native = parse_feature_file(customer_path, customer_text, allow_tag_gaps=True)
        hook_tags = ["@restore-all-tables-before-feature", "@clear-cache-before-feature", "@search-customers"]
        check("native blank-gap tags preserve the Customer source identity",
              legacy.tags == [] and native.tags == hook_tags
              and legacy.scenarios[0].line == native.scenarios[0].line == 10
              and legacy.scenarios[0].title == native.scenarios[0].title)
        observed_tags = []

        def observe_execution(**kwargs):
            emitted = parse_feature_file(str(root / "_bench/item.feature"), allow_tag_gaps=True)
            observed_tags.append(emitted.tags)
            check("each repeat emits exactly the original selected scenario",
                  len(emitted.scenarios) == 1 and emitted.scenarios[0].title == native.scenarios[0].title)
            return RunResult(exit_code=1, stdout="", wall_seconds=0.01)

        with mock.patch.object(h, "verify_substrate"), \
                mock.patch.object(h, "index_paths", return_value={"files": {}, "errors": {}}), \
                mock.patch.object(h, "execute", side_effect=observe_execution):
            result = h.run_solution(legacy, legacy.scenarios[0], Solution(), repeats=3)
        check("runtime recovers native tags before original-suite selection",
              result["suite"] == "customer" and common in result["suite_contexts"])
        check("native database/cache hooks survive every repeated execution",
              observed_tags == [hook_tags] * 3)
        from ..toolkit.closure import ClosureExtractor
        closure = ClosureExtractor({"files": {}}, {"steps": {}}, boundary, suite_map=m).closure_for(
            "prestashop/Customer/search_customers.feature:10", native, native.scenarios[0])
        check("native parsing selects the same tagged closure suite", closure.suite == "customer")
        from ..core.gherkin import standalone_feature
        legacy_output = standalone_feature(legacy, legacy.scenarios[0])
        check("other projects retain their existing contiguous-tag default",
              parse_feature_file("legacy.feature", legacy_output).tags == [])
        scenario_gap = customer_text.replace("  Scenario:", "  @reset-all-tables-before-scenario\n  # native hook\n\n  Scenario:")
        old_scenario = parse_feature_file(customer_path, scenario_gap)
        emitted, _, _ = h.write_feature(old_scenario, old_scenario.scenarios[0])
        roundtrip = parse_feature_file("emitted.feature", emitted, allow_tag_gaps=True)
        check("scenario hooks survive comments and blank gaps too",
              roundtrip.tags == hook_tags and roundtrip.scenarios[0].tags == ["@reset-all-tables-before-scenario"])

        program = worker.reset_program_for(bp)
        check("native reset travels an existing suite and actual restore tag",
              select_suite(m, program.feature_tags, program.feature_path) == "cms_page"
              and program.feature_tags == ("@restore-all-tables-before-feature",))

    with tempfile.TemporaryDirectory() as tmp:
        from .cli import main as cli_main
        config_dir = Path(__file__).resolve().parents[2] / "config"
        with redirect_stdout(io.StringIO()):
            rc = cli_main([
                "worker", "plan", "--profile", str(config_dir / "profile_prestashop.yml"),
                "--workers-root", tmp, "--k", "2", "--name", "r1",
                "--workdir", "/var/www/html"])
        planned = worker.load_worker_pool(tmp, 2)
        check("CLI defaults produce the test-prefixed schemas native provisioning needs",
              rc == 0 and [w.schema for w in planned]
              == ["test_prestashop_r1_0", "test_prestashop_r1_1"])

        for project, explicit, expected_schema, expected_container in (
                ("prestashop", "chosen", "chosen_r1_0", "chosen_r1_php_0"),
                ("coreshop", None, "coreshop_r1_0", "coreshop_r1_php_0"),
                ("python-docx", None, "", "python_docx_r1_php_0")):
            other_root = str(Path(tmp) / project)
            args = ["worker", "plan", "--profile",
                    str(config_dir / f"profile_{project.replace('-', '_')}.yml"),
                    "--workers-root", other_root, "--k", "1", "--name", "r1"]
            if explicit is not None:
                args += ["--prefix", explicit]
            with redirect_stdout(io.StringIO()):
                rc = cli_main(args)
            other = worker.load_worker_pool(other_root, 1)[0]
            check(f"CLI preserves {project} {'explicit' if explicit else 'default'} identities",
                  rc == 0 and other.schema == expected_schema
                  and other.container == expected_container)
        events = []
        for w in planned:
            db = mock.Mock(container="prestashop_db")
            db.table_bytes.return_value = {"ps_configuration": 10}
            def docker(argv, **kwargs):
                events.append((w.index, argv))
                report = {"schema": w.schema, "principal": w.credential, "tables": 1, "private_tmp": True}
                return subprocess.CompletedProcess(argv, 0, json.dumps(report), "")
            with mock.patch.object(seed, "verify_seed", return_value={"artifacts_ok": True, "needs_database": True, "seed_key": "fixture"}), \
                    mock.patch.object(seed, "read_seed", return_value={"source_schema": "test_prestashop_bench"}), \
                    mock.patch.object(worker, "require_container_absent"), \
                    mock.patch.object(worker, "unpack_workspace", return_value={}), \
                    mock.patch.object(worker, "dump_table_count", return_value=1), \
                    mock.patch.object(worker, "_docker", side_effect=docker), \
                    mock.patch.object(worker, "capture_prestashop_memory",
                                      return_value={"memory": "observed", "oom_counters": {}}) as memory_probe, \
                    mock.patch.object(worker, "mounts_of", return_value={}) as mounts:
                result = worker.provision(w, tmp, db, overrides={}, behat=bp)
                check(f"worker {w.index} init returns only its own identity before acceptance",
                      result["initialization"]["schema"] == w.schema and mounts.called)
                launch = next(argv for index, argv in reversed(events)
                              if index == w.index and argv[0] == "run")
                check(f"worker {w.index} installs the fixed RAM/zero-swap limits and observes enforcement",
                      launch[launch.index("--memory") + 1] == "4294967296"
                      and launch[launch.index("--memory-swap") + 1] == "4294967296"
                      and launch[launch.index("--pids-limit") + 1] == "1024"
                      and memory_probe.called and result["memory_observation"]["memory"] == "observed")
                if w.index == 0:
                    mounts.reset_mock()
                    with mock.patch.object(worker, "initialize_prestashop_worker",
                                           side_effect=worker.WorkerRefused("fixture initialization failed")):
                        try:
                            worker.provision(w, tmp, db, overrides={}, behat=bp)
                            returned = True
                        except worker.WorkerRefused:
                            returned = False
                    check("initialization failure cannot return provision evidence to attestation",
                          not returned and not mounts.called)
            env = Path(w.env_file).read_text()
            check(f"worker {w.index} DSN uses its own schema/principal and real DB host",
                  f"@prestashop_db:3306/{w.schema}" in env
                  and f"mysql://{w.credential}:" in env and "PIMCORE" not in env)
        check("both initializers address distinct containers and pass no password argv",
              [e[1][-2:] for e in events if e[1][:2] == ["exec", "--workdir"]]
              == [[w.schema, w.credential] for w in planned])
        with mock.patch.object(seed, "read_seed", return_value={"source_schema": "test_prestashop_bench"}), \
                mock.patch.object(worker, "_docker", return_value=subprocess.CompletedProcess([], 1, "", "secret-bearing failure")):
            try:
                worker.initialize_prestashop_worker(planned[0], tmp)
                failed = False
            except worker.WorkerRefused as error:
                failed = "no worker attestation" in str(error) and "secret-bearing" not in str(error)
            check("failed initialization refuses without returning secret-bearing output", failed)

    program = worker.reset_program_for(bp)
    marker = lambda present: {"ok": True, "present": present, "error_class": None}
    report = {"worker": 0, "own_schema": "test_prestashop_r1_0", "nonce": "abc",
              "leg_a": {"outcome": "passed", "report": {"baseline": {"configuration_rows": 5},
                  "wrote": {k: {"ok": True} for k in program.expected_in_leg_b},
                  "markers": {k: marker(True) for k in program.expected_in_leg_b}}},
              "leg_b": {"outcome": "passed", "report": {"baseline": {"configuration_rows": 5},
                  "markers": {k: marker(v) for k, v in program.expected_in_leg_b.items()}}},
              "cleanup": {"deleted": 1, "remaining": 0}}
    check("native reset accepts restored row plus durable private-file control", worker.reset_report(report, bp)["pass"])
    report["leg_b"]["report"]["markers"]["restored_row"] = marker(True)
    check("native reset rejects row surviving the pair boundary",
          worker.reset_report(report, bp)["failure_class"] == "state_crossed_the_pair_boundary")
    report["leg_b"]["report"]["markers"]["unpurged_file"] = marker(False)
    check("native reset refuses an absent durable control even when markers survive",
          worker.reset_report(report, bp)["failure_class"] == "probe_observed_nothing")

    php = shutil.which("php")
    if php:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "recorder.php").write_text(rendered)
            (root / "reset.php").write_text(program.context_php(bp))
            for p in (root / "recorder.php", root / "reset.php", PHP_DIR / "prestashop_worker_init.php"):
                cp = subprocess.run([php, "-l", str(p)], capture_output=True, text=True)
                check("PHP syntax: " + p.name, cp.returncode == 0)
            class_paths = []
            for i, directory in enumerate(("src", "classes", "controllers", "vendor", "tests")):
                path = root / directory / f"Production{i}.php"
                path.parent.mkdir(exist_ok=True)
                path.write_text(f"<?php class Production{i} {{ public function hit() {{}} }}")
                class_paths.append(path)
            caller = root / "tests/Integration/Behaviour/Features/Context/Domain/CmsPageFeatureContext.php"
            trace = root / "calls.xt"
            trace.write_text("".join("\t".join(["1", str(i), "0", "0", "0", f"Production{i}->hit", "1", "", str(caller), "1"]) + "\n"
                                     for i in range(len(class_paths))))
            code = "namespace Behat\\Behat\\Context { interface Context {} } namespace { "
            code += "require " + json.dumps(str(root / "recorder.php")) + "; "
            code += " ".join("require " + json.dumps(str(path)) + ";" for path in class_paths)
            code += ("echo json_encode(\\Tests\\Integration\\Behaviour\\Bench\\BenchRecorderHook::directCallsFromTrace("
                     + json.dumps(str(trace)) + ", " + json.dumps(str(root)) + ")); }")
            cp = subprocess.run([php, "-r", code], capture_output=True, text=True)
            calls = json.loads(cp.stdout) if cp.returncode == 0 else []
            check("real PHP reducer keeps all production roots and fences vendor/test callees",
                  [row["callee_file"].split("/")[0] for row in calls] == ["classes", "controllers", "src"]
                  and all(row["caller_file"] == str(caller.relative_to(root)) for row in calls))
            native = root / "native"
            target = native / "modules/ps_apiresources"
            target.mkdir(parents=True)
            (target / "module.php").write_text("<?php // native module")
            links = [native / "tests/Resources/modules/ps_apiresources",
                     native / "var/r2t-db-dumps/ps_backup_test_modules/ps_apiresources"]
            for link in links:
                link.parent.mkdir(parents=True)
            relative = "../../../modules/ps_apiresources"
            initialize_links = (f"require {json.dumps(str(PHP_DIR / 'prestashop_worker_init.php'))}; "
                                f"prestashopRestoreNativeModuleLinks({json.dumps(str(native))});")

            def run_links():
                return subprocess.run([php, "-r", initialize_links], capture_output=True, text=True)

            for repeat in range(2):
                cp = run_links()
                check(f"real PHP restores both exact native module links, repeat {repeat}",
                      cp.returncode == 0 and all(link.is_symlink() and os.readlink(link) == relative
                                                and link.resolve() == target for link in links))
            links[1].unlink()
            os.symlink("../../../modules/wrong", links[1])
            check("real PHP refuses a conflicting native backup link without replacing it",
                  run_links().returncode != 0 and os.readlink(links[1]) == "../../../modules/wrong")
            links[1].unlink()
            links[1].write_text("not a link")
            check("real PHP refuses a regular file in the native link position",
                  run_links().returncode != 0 and links[1].read_text() == "not a link")
            links[1].unlink()
            links[0].unlink()
            target.rename(target.with_name("saved"))
            check("real PHP refuses a missing module before creating either link",
                  run_links().returncode != 0 and not any(os.path.lexists(link) for link in links))
            os.symlink(target.with_name("saved"), target)
            check("real PHP refuses a redirected module target",
                  run_links().returncode != 0 and not any(os.path.lexists(link) for link in links))
            target.unlink()
            target.with_name("saved").rename(target)
            check("real PHP restores links after valid source is present", run_links().returncode == 0)

            src = root / "inputs"
            src.mkdir()
            for name in ("ps_backup_test_img", "ps_backup_test_download", "ps_backup_test_modules"):
                (src / name).mkdir()
                (src / name / "fixture.txt").write_text("same resource bytes")
            os.symlink(relative, src / "ps_backup_test_modules/ps_apiresources")
            for name in ("ps_dump_test_seed_9.3.0.sql", "ps_dump_test_seed_9.3.0_ps_configuration.sql", "ps_dump_test_seed_9.3.0_ps_configuration.md5"):
                (src / name).write_text("preserved bytes")
            for i in range(2):
                dst = root / f"tmp{i}"
                dst.mkdir()
                code = f"require {json.dumps(str(PHP_DIR / 'prestashop_worker_init.php'))}; echo prestashopCopyRestoreInputs({json.dumps(str(src))}, {json.dumps(str(dst))}, 'test_seed', 'test_worker_{i}', '9.3.0');"
                cp = subprocess.run([php, "-r", code], capture_output=True, text=True)
                check(f"real PHP initializes worker {i} private dump names and all backups",
                      cp.returncode == 0 and cp.stdout == "1"
                      and (dst / f"ps_dump_test_worker_{i}_9.3.0_ps_configuration.md5").read_text() == "preserved bytes"
                      and (dst / "ps_backup_test_modules/fixture.txt").read_text() == "same resource bytes"
                      and (dst / "ps_backup_test_modules/ps_apiresources").is_symlink()
                      and os.readlink(dst / "ps_backup_test_modules/ps_apiresources") == relative
                      and not (dst / "ps_dump_test_seed_9.3.0.sql").exists())
    else:
        print("  [NOT RUN] optional local PHP syntax/filesystem fixtures: php unavailable")
    print("\n" + ("FAILURES" if failures else "ALL PASS") + " (prestashop runtime)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(selftest())
