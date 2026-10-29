"""Offline tests for req2test.env (no Docker, no kits needed).

    python -m unittest discover -s tests

Set REQ2TEST_TEST_HOME=<a REQ2TEST_HOME with all 8 kits installed> to also
check every descriptor path against the installed kits.
"""
from __future__ import annotations

import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from req2test import ENGINE_ROOT, env


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class DescriptorTests(unittest.TestCase):

    def test_every_project_has_exactly_the_descriptor_fields(self):
        self.assertEqual(len(env.PROJECTS), 8)
        for project, d in env.PROJECTS.items():
            with self.subTest(project=project):
                self.assertEqual(set(d), set(env.DESCRIPTOR_KEYS))
                self.assertIn(d["kind"], {"py", "java", "go", "php", "ruby"})
                self.assertTrue(d["gold_control"].startswith(project + "/"))
                self.assertGreaterEqual(d["k_default"], 1)
                self.assertEqual(set(d["profiles"]), {"th", "ah"})

    def test_profiles_are_the_engine_config_files(self):
        config = ENGINE_ROOT / "config"
        for project, d in env.PROJECTS.items():
            for rel in [d["profile"], d["boundary"], *d["profiles"].values()]:
                with self.subTest(project=project, rel=rel):
                    self.assertTrue((config / Path(rel).name).is_file(), rel)

    def test_database_projects_name_engine_template_producers(self):
        expected = {"coreshop", "sylius", "prestashop"}
        self.assertEqual({p for p, d in env.PROJECTS.items() if d["database"]},
                         expected)
        for project in expected:
            db = env.PROJECTS[project]["database"]
            produce = env._resolve_callable(db["template_env"])
            self.assertTrue(callable(produce))
        # The engine's environment layer refuses any alias but coreshop_db
        # for the alias-addressed projects; PrestaShop uses the container.
        self.assertEqual(env.PROJECTS["coreshop"]["database"]["alias"], "coreshop_db")
        self.assertEqual(env.PROJECTS["sylius"]["database"]["alias"], "coreshop_db")
        self.assertIsNone(env.PROJECTS["prestashop"]["database"]["alias"])

    def test_prestashop_template_env_matches_its_provisioner(self):
        db = env.PROJECTS["prestashop"]["database"]
        values = env._resolve_callable(db["template_env"])()
        self.assertEqual(values["APP_ENV"], "test")
        self.assertIn("DATABASE_URL", values)
        self.assertIsNone(db["template_command"])

    def test_coreshop_template_env_needs_a_defuse_key(self):
        produce = env._resolve_callable(
            env.PROJECTS["coreshop"]["database"]["template_env"])
        values = produce("def" + "0" * 133)
        self.assertEqual(values["PIMCORE_SECRET"], "def" + "0" * 133)
        with self.assertRaises(Exception):
            produce("not-a-key")

    def test_memory_caps_are_the_engine_policies(self):
        caps = {p: d["memory_bytes"] for p, d in env.PROJECTS.items()
                if d["memory_bytes"]}
        self.assertEqual(caps, {"coddy-agent": 16 * env.GIB,
                                "prestashop": 4 * env.GIB})

    @unittest.skipUnless(os.environ.get("REQ2TEST_TEST_HOME"),
                         "REQ2TEST_TEST_HOME (a home with all 8 kits) not set")
    def test_descriptor_paths_exist_in_installed_kits(self):
        from req2test import kits
        home = Path(os.environ["REQ2TEST_TEST_HOME"])
        for project, d in env.PROJECTS.items():
            kit = kits.load_kit(project, home=home)
            worker, db = env.kit_images(kit)
            self.assertTrue(kit.path(worker["file"]).is_file())
            self.assertEqual(bool(db), bool(d["database"]))
            sources = [d["profile"], d["boundary"], *d["profiles"].values(),
                       d["seed"], d["release_items"], d["agent_jar"],
                       d["artifacts"], d["gold"], d["sidecars"]]
            for source in filter(None, sources):
                rel = source if isinstance(source, str) else source["tar"]
                with self.subTest(project=project, rel=rel):
                    self.assertTrue(kit.path(rel).exists(), rel)
            items = env._read_jsonl_ids(kit.path(d["release_items"]))
            self.assertIn(d["gold_control"], items)


class StagingTests(unittest.TestCase):
    """stage_inputs builds the engine layout and relocates recorded paths."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp))
        kit = self.tmp / "kit"
        write(kit / "kit.json", json.dumps({
            "schema": "req2test.kit/1", "project": "toy", "kit_version": "1.0",
            "exec_env": {"images": [{"file": "exec/images/x.tar",
                                     "config_digest": "sha256:" + "a" * 64}],
                         "db_image": None}}))
        write(kit / "exec/seed/seed.json", json.dumps({
            "workspace": {"path": "/build/host/seed/workspace.tar",
                          "digest": "b" * 64},
            "database": {"declared": "no_database", "path": None}}))
        write(kit / "exec/seed/workspace.tar", "tar bytes")
        write(kit / "exec/seed/receipt.json", "{}")
        write(kit / "exec/items.jsonl",
              json.dumps({"item_id": "toy/a.feature:1"}) + "\n")
        write(kit / "exec/sidecars/manifest.json",
              json.dumps({"toy/a.feature:1": "0.json"}))
        write(kit / "exec/sidecars/0.json", "{}")
        # The gold tree ships as an archive with a top-level member.
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            for name, text in (("gold-v1/strip_manifest.json",
                                json.dumps({"gold_root": "/build/host/gold",
                                            "repo_root": "/build/ws"})),
                               ("gold-v1/features/steps.py", "pass\n")):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        (kit / "exec/gold.tar").write_bytes(buffer.getvalue())
        self.kit = env.kit_from_dir(kit)
        self.descriptor = dict(env.PROJECTS["python-docx"],
                               seed="exec/seed", release_items="exec/items.jsonl",
                               sidecars="exec/sidecars",
                               gold={"tar": "exec/gold.tar", "member": "gold-v1"},
                               artifacts=None, agent_jar=None)
        patcher = mock.patch.dict(env.PROJECTS, {"toy": self.descriptor})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_layout_and_relocation(self):
        staged = env.stage_inputs(self.kit, self.tmp / "engine")
        self.assertEqual(staged.parent, self.tmp / "engine/inputs/toy")
        self.assertRegex(staged.name, r"^1\.0-[0-9a-f]{12}$")
        self.assertEqual(sorted(p.name for p in (staged / "seed").iterdir()),
                         ["seed.json", "workspace.tar"])
        seed = json.loads((staged / "seed/seed.json").read_text())
        self.assertEqual(seed["workspace"]["path"],
                         str(staged / "seed/workspace.tar"))
        self.assertIsNone(seed["database"]["path"])
        strip = json.loads((staged / "gold/strip_manifest.json").read_text())
        self.assertEqual(strip["gold_root"], str(staged / "gold"))
        self.assertEqual(strip["repo_root"], "/build/ws")
        self.assertTrue((staged / "artifacts/release/gold/manifest.json").is_file())
        self.assertTrue((staged / "artifacts/release/items.jsonl").is_file())
        record = json.loads((staged / "inputs.json").read_text())
        self.assertEqual(record["relocated"], {
            "seed.json:workspace.path": "/build/host/seed/workspace.tar",
            "strip_manifest.json:gold_root": "/build/host/gold"})
        # Single-link copies: the engine refuses hard-linked inputs.
        self.assertEqual((staged / "seed/workspace.tar").stat().st_nlink, 1)
        # Staged once per kit; a changed kit.json is staged afresh.
        self.assertEqual(env.stage_inputs(self.kit, self.tmp / "engine"), staged)
        meta = dict(self.kit.meta, note="re-released")
        write(self.kit.root / "kit.json", json.dumps(meta))
        other = env.stage_inputs(env.kit_from_dir(self.kit.root),
                                 self.tmp / "engine")
        self.assertNotEqual(other, staged)

    def test_release_items_without_sidecars_are_refused(self):
        write(self.kit.root / "exec/items.jsonl",
              json.dumps({"item_id": "toy/a.feature:1"}) + "\n"
              + json.dumps({"item_id": "toy/b.feature:2"}) + "\n")
        with self.assertRaises(env.EnvError):
            env.stage_inputs(self.kit, self.tmp / "engine")
        self.assertEqual(list((self.tmp / "engine/inputs/toy").iterdir()), [])


class HandleTests(unittest.TestCase):

    @staticmethod
    def handle(_self, tmp: Path, kind: str) -> env.EnvHandle:
        specs = []
        for i in range(2):
            path = tmp / f"worker{i}.json"
            path.write_text(json.dumps({"artifacts_root": f"/a/shard{i}"}))
            specs.append(str(path))
        return env.EnvHandle(
            project="toy", nonce="e1234", env_dir=str(tmp),
            record_path=str(tmp / "env.json"), kit_root="/kit",
            kit_version="1.0", k=2, authority_path="/auth.json",
            docker_socket="/s", data_root=str(tmp), workers_root=str(tmp),
            worker_specs=specs, worker_ids=[0, 1], workdir="/work",
            container_kind=kind, prefix=None, image_id="sha256:" + "a" * 64,
            profile="/p.yml", boundary="/b.yml", profiles={}, seed_dir="/s",
            gold_root="/g", artifacts="/art", release_items="/art/release/items.jsonl",
            agent_jar=None, extra_global_args=["--features", "features"],
            database={"container": "db", "network": "net"})

    def test_global_args_and_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            handle = self.handle(self, tmp, "go")
            args = handle.global_args(1)
            self.assertEqual(args[args.index("--artifacts") + 1], "/a/shard1")
            self.assertEqual(args[args.index("--worker") + 1], handle.worker_specs[1])
            self.assertEqual(args[-2:], ["--features", "features"])
            php = self.handle(self, tmp, "php").global_args(0)
            self.assertEqual(php[php.index("--artifacts") + 1], "/art")
            self.assertEqual(handle.pool_args()[-4:], [
                "--db-container", "db", "--internal-network", "net"])
            env._save(handle, qualification={"ok": True})
            self.assertEqual(env.EnvHandle.load(handle.record_path), handle)
            self.assertEqual(os.stat(handle.record_path).st_mode & 0o777, 0o600)


class RecordTests(unittest.TestCase):
    """Selection for `env down` and the monotonic record."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.home))
        patcher = mock.patch.dict(os.environ, {"REQ2TEST_HOME": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def record(self, nonce: str, state: str) -> env.EnvHandle:
        env_dir = self.home / "envs" / "python-docx" / nonce
        env_dir.mkdir(parents=True)
        handle = HandleTests.handle(None, env_dir, "py")
        handle.project, handle.nonce, handle.state = "python-docx", nonce, state
        handle.record_path = str(env_dir / "env.json")
        env._save(handle)
        return handle

    def test_down_needs_nonce_or_all_when_several_are_live(self):
        self.record("e1", "up")
        self.record("e2", "failed")
        self.record("e3", "down")
        with self.assertRaises(env.EnvError) as caught:
            env.select_for_down("python-docx", None, False)
        self.assertIn("e1", str(caught.exception))
        self.assertIn("e2", str(caught.exception))
        self.assertEqual([h.nonce for h in env.select_for_down(
            "python-docx", "e2", False)], ["e2"])
        self.assertEqual([h.nonce for h in env.select_for_down(
            "python-docx", None, True)], ["e1", "e2"])
        with self.assertRaises(env.EnvError):
            env.select_for_down("python-docx", "e3", False)   # already down
        with self.assertRaises(env.EnvError):
            env.select_for_down("python-docx", "e1", True)

    def test_down_without_nonce_takes_the_only_live_one(self):
        self.record("e1", "up")
        self.record("e3", "down")
        self.assertEqual([h.nonce for h in env.select_for_down(
            "python-docx", None, False)], ["e1"])

    def test_a_retired_record_is_never_rewritten(self):
        stale = self.record("e1", "up")
        retired = env.EnvHandle.load(stale.record_path)
        retired.state = "down"
        self.assertTrue(env._save(retired, torn_down_at="t"))
        before = Path(stale.record_path).read_bytes()
        stale.state = "failed"
        self.assertFalse(env._save(stale, error={"step": "x"}))
        self.assertEqual(Path(stale.record_path).read_bytes(), before)
        self.assertEqual(stale.state, "down")
        # down() reads the record, so a stale in-memory handle is a no-op
        # (no Docker contact: the authority path does not exist).
        stale.state = "up"
        self.assertEqual(env.down(stale)["note"], "already down")

    def test_own_daemon_is_restarted_only_for_its_own_pools(self):
        handle = self.record("e1", "up")
        with mock.patch.object(env, "ensure_daemon") as ensure:
            handle.docker_socket = "/run/other/docker.sock"
            env._ensure_own_daemon(handle)
            ensure.assert_not_called()
            handle.docker_socket = str(env.daemon_socket(self.home))
            env._ensure_own_daemon(handle)
            ensure.assert_called_once_with(self.home)


    def systemctl(self, active: str):
        calls = []

        def run(*args, check=False):
            calls.append(args)
            out = active if args[0] == "is-active" else ""
            return __import__("subprocess").CompletedProcess(
                ["systemctl", "--user", *args], 0, stdout=out + "\n",
                stderr="")
        return calls, mock.patch.object(env, "_systemctl_user",
                                        side_effect=run)

    def test_stop_daemon_refuses_while_an_environment_is_not_down(self):
        self.record("e1", "failed")
        self.record("e2", "down")
        calls, patch = self.systemctl("active")
        with patch, self.assertRaises(env.EnvError) as caught:
            env.stop_daemon()
        text = str(caught.exception)
        self.assertIn("python-docx e1 (state failed)", text)
        self.assertNotIn("python-docx e2", text)   # the unit name is hex
        # The hint is the concrete command for each environment.
        self.assertIn("req2test env down --project python-docx --nonce e1",
                      text)
        self.assertNotIn("--project P", text)
        self.assertEqual(calls, [])

    def test_down_with_no_live_environment_says_so(self):
        self.record("e3", "down")
        out = io.StringIO()
        with mock.patch.object(env, "down") as down, \
                mock.patch("sys.stdout", out):
            self.assertEqual(env.main(["down", "--project", "python-docx"]),
                             0)
        down.assert_not_called()
        self.assertEqual(out.getvalue(),
                         "no live environment for python-docx\n")

    def test_stop_daemon_stops_this_homes_unit(self):
        self.record("e2", "down")
        name = env.daemon_name(env.req2test_home())
        calls, patch = self.systemctl("active")
        with patch:
            report = env.stop_daemon()
        self.assertEqual(calls, [("is-active", name), ("stop", name)])
        self.assertTrue(report["stopped"])
        calls, patch = self.systemctl("inactive")
        with patch:
            report = env.stop_daemon()
        self.assertEqual(calls, [("is-active", name)])
        self.assertEqual(report["note"], "not running")

    def test_stop_daemon_verb(self):
        args = env.build_parser().parse_args(["stop-daemon"])
        self.assertEqual(args.action, "stop-daemon")
        with mock.patch.object(env, "stop_daemon",
                               return_value={"daemon": "d"}) as stop, \
                mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(env.main(["stop-daemon"]), 0)
        stop.assert_called_once_with()


class CleanCloneTests(unittest.TestCase):
    """The clean-clone check `env up`, `evaluate` and `validate` run first."""

    def setUp(self):
        import subprocess
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root))
        self.git = lambda *a: subprocess.run(
            ["git", "-C", str(self.root), "-c", "user.name=t",
             "-c", "user.email=t@example.invalid", *a],
            check=True, capture_output=True)
        self.git("init", "-q")
        write(self.root / "benchmark" / "r2t.py", "x\n")
        write(self.root / ".gitignore", "/work/\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "init")
        self.engine = self.root / "benchmark"

    def test_clean_clone_and_work_dir_pass(self):
        write(self.root / "work" / "predictions.jsonl", "{}\n")
        write(self.root / "work" / "repo" / "a.py", "")
        env.check_clean_clone(self.engine)

    def test_untracked_files_are_refused_with_paths_and_hint(self):
        write(self.root / "tasks.jsonl", "")
        for i in range(11):
            write(self.root / "repo" / f"f{i:02}.py", "")
        write(self.root / "benchmark" / "r2t.py", "changed\n")
        with self.assertRaises(env.EnvError) as caught:
            env.check_clean_clone(self.engine)
        text = str(caught.exception)
        self.assertIn(f"the clone {self.root.resolve()} is not clean "
                      "(13 changed or untracked path(s))", text)
        self.assertIn(" M benchmark/r2t.py", text)
        self.assertIn("?? repo/f00.py", text)
        self.assertIn("... and 3 more", text)
        self.assertTrue(text.endswith(
            "keep tasks, views and predictions outside the clone "
            "(e.g. ~/r2t-work) or under ./work/"))

    def test_not_a_git_clone_is_left_to_the_engine(self):
        plain = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(plain))
        self.assertEqual(env.dirty_clone_paths(plain), (None, []))

    def test_this_clone_ignores_work(self):
        import subprocess
        probe = subprocess.run(
            ["git", "-C", str(ENGINE_ROOT.parent), "check-ignore", "-q",
             "work/predictions.jsonl"])
        self.assertEqual(probe.returncode, 0)

    def test_a_refused_docker_command_names_a_dirty_clone(self):
        class Refused(Exception):
            pass

        def refuse(argv):
            raise Refused("REFUSED: verifier worktree is not clean")
        docker = object.__new__(env._Docker)
        docker.DC = mock.Mock(DockerEndpointRefused=Refused,
                              docker_argv=refuse)
        write(self.root / "predictions.jsonl", "")
        with mock.patch.object(env, "ENGINE_ROOT", self.engine):
            with self.assertRaisesRegex(env.EnvError,
                                        r"\?\? predictions.jsonl"):
                docker.argv(["ps"])
            (self.root / "predictions.jsonl").unlink()
            with self.assertRaisesRegex(env.EnvError,
                                        "^Docker authority refused"):
                docker.argv(["ps"])

    def test_env_up_checks_before_anything_else(self):
        with mock.patch.object(env, "check_clean_clone",
                               side_effect=env.EnvError("dirty")), \
                mock.patch.object(env, "_up") as up:
            with self.assertRaisesRegex(env.EnvError, "dirty"):
                env.up(object())
        up.assert_not_called()


class HostCheckTests(unittest.TestCase):

    def test_daemon_unit_path_names_the_resolved_tools_first(self):
        calls = []

        def run(argv, **kw):
            calls.append(argv)
            return __import__("subprocess").CompletedProcess(
                argv, 1, stdout="inactive\n", stderr="refused")
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(env.shutil, "which",
                                  side_effect=lambda t: f"/opt/dk/bin/{t}"
                                  if t != "newuidmap" else "/usr/bin/newuidmap"), \
                mock.patch.object(env.subprocess, "run", side_effect=run):
            with self.assertRaises(env.EnvError):
                env.ensure_daemon(Path(tmp) / "home")
        started = next(c for c in calls if c[0] == "systemd-run")
        self.assertIn("--setenv=PATH=/opt/dk/bin:/usr/bin:/usr/sbin:/bin:/sbin",
                      started)
        self.assertIn("/opt/dk/bin/dockerd-rootless.sh", started)

    def test_daemon_name_is_per_home(self):
        a = env.daemon_name(Path("/home/u/.req2test"))
        self.assertEqual(a, env.daemon_name(Path("/home/u/.req2test")))
        self.assertNotEqual(a, env.daemon_name(Path("/srv/other")))
        self.assertRegex(a, r"^req2test-docker-[0-9a-f]{8}$")

    def test_private_dir_fixes_what_it_creates_and_refuses_peer_writable(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.umask(0o002)
            try:
                made = env._private_dir(Path(tmp) / "a" / "b")
            finally:
                os.umask(old)
            for path in (made, made.parent):
                self.assertEqual(path.stat().st_mode & 0o022, 0)
            shared = Path(tmp) / "shared"
            shared.mkdir()
            os.chmod(shared, 0o775)
            with self.assertRaises(env.EnvError):
                env._private_dir(shared / "home")
            self.assertEqual(shared.stat().st_mode & 0o777, 0o775)

    def test_key_quota(self):
        uid = os.geteuid()
        roomy = f"    0:    75 74/74 48/1000000 957/25000000\n {uid}:    20 20/20 20/1000 1166/100000\n"
        full = f" {uid}:   990 990/990 990/1000 99000/100000\n"
        self.assertIsNone(env._key_quota_problem(26, roomy))
        self.assertIn("kernel key quota", env._key_quota_problem(26, full))
        self.assertIsNone(env._key_quota_problem(26, ""))

    def test_memory_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "provision.json"

            def observed(memory, swap):
                return {"at_attestation": {"memory": {
                    "effective_memory_bytes": memory,
                    "effective_swap_bytes": swap}}}
            report.write_text(json.dumps({"memory_observations": [
                dict(observed(4 * env.GIB, 0), worker=0),
                dict(observed(4 * env.GIB, 0), worker=1)]}))
            self.assertIsNone(env._check_memory(report, 4 * env.GIB, 2))
            self.assertIsNone(env._check_memory(report, None, 2))
            self.assertIn("not effective", env._check_memory(report, 4 * env.GIB, 3))
            report.write_text(json.dumps({"memory_observations": [
                dict(observed(4 * env.GIB, 1024), worker=0)]}))
            self.assertIn("not effective", env._check_memory(report, 4 * env.GIB, 1))


class CliTests(unittest.TestCase):

    def test_parser(self):
        args = env.build_parser().parse_args(
            ["up", "--project", "prestashop", "--workers", "2"])
        self.assertEqual((args.action, args.project, args.workers),
                         ("up", "prestashop", 2))
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", io.StringIO()):
            env.build_parser().parse_args(["up", "--project", "nope"])

    def test_req2test_dispatches_env(self):
        from req2test import cli
        with mock.patch.object(env, "main", return_value=7) as main:
            self.assertEqual(cli.main(["env", "status", "--project", "kapua"]), 7)
        main.assert_called_once_with(["status", "--project", "kapua"])


class DatabaseHealthWaitTests(unittest.TestCase):
    """`env._wait_healthy`: MySQL's slow first start is waited out."""

    def wait(self, answers, deadline=100):
        now = [0.0]
        calls = []

        def docker(args, timeout=None):
            calls.append(args)
            out = answers[min(len(calls), len(answers)) - 1]
            return mock.Mock(stdout=out + "\n")

        def sleep(seconds):
            now[0] += seconds

        env._wait_healthy(docker, "db", deadline=deadline,
                          clock=lambda: now[0], sleep=sleep)
        return calls

    def test_starting_until_healthy(self):
        calls = self.wait(["running starting"] * 30 + ["running healthy"])
        self.assertEqual(len(calls), 31)
        self.assertEqual(calls[0][-1], "db")

    def test_unhealthy_refuses(self):
        with self.assertRaisesRegex(env.EnvError, r"\(unhealthy, running\)"):
            self.wait(["running unhealthy"])

    def test_a_stopped_container_refuses_at_once(self):
        with self.assertRaisesRegex(env.EnvError, r"\(starting, exited\)"):
            self.wait(["running starting", "exited starting"])

    def test_the_deadline_refuses(self):
        with self.assertRaisesRegex(env.EnvError, r"\(starting, running\)"):
            self.wait(["running starting"], deadline=10)

    def test_the_start_period_fits_inside_the_deadline(self):
        self.assertLess(env.DB_HEALTH_START_PERIOD, env.DB_HEALTH_DEADLINE)


if __name__ == "__main__":
    unittest.main()
