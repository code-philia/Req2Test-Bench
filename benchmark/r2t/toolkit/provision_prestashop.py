"""Build PrestaShop's pinned onboarding source, database template and seed.

The image prepares locked dependencies, classic theme assets and translation
packs before this recipe installs the test database on an internal network.
This module is one project recipe; admission and worker integration remain
separate gates. Run ``python -m r2t.toolkit.provision_prestashop --stage install``
first, index the installed unstripped workspace through the normal toolkit
verbs, then run ``--stage seed`` to strip it and freeze the seed. Both stages
require the same explicit data root and immutable image ID.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from unittest import mock

import yaml

from ..core.paths import DATA_ROOT_ENV


SOURCE_URL = "https://github.com/PrestaShop/PrestaShop.git"
SOURCE_COMMIT = "2961c63ece3c09a443daae38149ca92ffaaad2d8"
MYSQL_IMAGE = (
    "mysql:8.0@sha256:"
    "7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b")
TEMPLATE_COMMAND = ("composer", "create-test-db")
NETWORK = "prestashop_net"
MYSQL_CONTAINER = "prestashop_db"
PHP_CONTAINER = "prestashop_bench_php"
SETUP_CONTAINER = "prestashop_bench_setup"
DATABASE_NAME = "prestashop_bench"
# Both legacy config/bootstrap.php and Doctrine's config_test.yml add test_.
SCHEMA = "test_prestashop_bench"
WORKDIR = "/var/www/html"

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)
DOCKER_DIR = os.path.join(BENCHMARK, "docker", "prestashop")
DOCKERFILE = os.path.join(DOCKER_DIR, "Dockerfile")
COMPOSER_LOCK = os.path.join(DOCKER_DIR, "composer.lock")
BOUNDARY = os.path.join(BENCHMARK, "config", "boundary_prestashop.yml")
PHP_HARNESS = os.path.join(HERE, "php")


class ProvisionRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class Layout:
    data_root: str
    source: str
    workspace: str
    build_source: str
    gold: str
    seed: str
    composer_cache: str

    @classmethod
    def under(cls, root: str) -> "Layout":
        root = os.path.abspath(root)
        project = os.path.join(root, "projects", "prestashop")
        source = os.path.join(project, "source")
        workspace = os.path.join(project, "workspace")
        return cls(root, source, workspace, workspace + ".provisioning",
                   os.path.join(project, "gold"),
                   os.path.join(project, "seed", "v1"),
                   os.path.join(root, "cache", "composer"))


def _run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    if argv[0] == "docker":
        from ..core.docker_cli import docker_command
        argv = docker_command(argv[1:], environ=kwargs.get("env"))
    return subprocess.run(argv, text=True, **kwargs)


def _checked(argv: list[str], *, capture_output: bool = False,
             env: dict | None = None, timeout: int = 3600
             ) -> subprocess.CompletedProcess:
    cp = _run(argv, capture_output=capture_output, env=env, timeout=timeout)
    if cp.returncode:
        detail = (cp.stderr or cp.stdout or "").strip()[-500:]
        raise ProvisionRefused(
            f"REFUSED: command failed ({cp.returncode}): "
            f"{shlex.join(argv)}" + (f": {detail}" if detail else ""))
    return cp


def _require_absent(kind: str, name: str) -> None:
    cp = _run(["docker", kind, "inspect", name], capture_output=True,
              timeout=60)
    if cp.returncode == 0:
        raise ProvisionRefused(
            f"REFUSED: Docker {kind} {name!r} already exists. This recipe "
            "only provisions a fresh environment; inspect and retire your "
            "own old resource before retrying.")
    detail = (cp.stderr or cp.stdout or "").lower()
    if "no such" not in detail and "not found" not in detail:
        raise ProvisionRefused(
            f"REFUSED: could not establish that Docker {kind} {name!r} "
            f"is absent: {detail.strip()[-500:]}")


def _preflight(layout: Layout, image: str, stage: str) -> None:
    if stage not in ("install", "seed"):
        raise ProvisionRefused("REFUSED: --stage must be install or seed")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image or "") is None:
        raise ProvisionRefused(
            "REFUSED: --image must be the immutable sha256 image ID "
            "verified by the image round-trip gate, not a mutable tag.")
    destinations = [("workspace", layout.workspace),
                    ("gold", layout.gold), ("seed", layout.seed)]
    if stage == "install":
        destinations.append(("provisioning source", layout.build_source))
    elif not os.path.isdir(layout.build_source):
        raise ProvisionRefused(
            "REFUSED: seed stage needs the installed unstripped workspace: "
            f"{layout.build_source}. Complete --stage install and extraction first.")
    if stage == "seed":
        _seed_rules()
    for label, path in destinations:
        if os.path.lexists(path):
            raise ProvisionRefused(
                f"REFUSED: PrestaShop {label} destination already exists: "
                f"{path}. Provisioning never overwrites an existing tree.")
    for path in (DOCKERFILE, COMPOSER_LOCK, BOUNDARY):
        if not os.path.isfile(path):
            raise ProvisionRefused(
                f"REFUSED: required PrestaShop recipe input is missing: "
                f"{path}. Use the reviewed train checkout containing the "
                "PrestaShop image, boundary and Behat integration.")
    if os.path.lexists(layout.source):
        _verify_corpus(layout.source)
    if stage == "install":
        for name in (SETUP_CONTAINER, PHP_CONTAINER, MYSQL_CONTAINER):
            _require_absent("container", name)
        _require_absent("network", NETWORK)
    else:
        _require_absent("container", PHP_CONTAINER)
        _verify_installed_resources(layout, image)


def _inspect(kind: str, name: str) -> dict:
    cp = _checked(["docker", kind, "inspect", name], capture_output=True,
                  timeout=60)
    try:
        [document] = json.loads(cp.stdout)
        if not isinstance(document, dict):
            raise ValueError("not one object")
    except (ValueError, TypeError) as exc:
        raise ProvisionRefused(
            f"REFUSED: invalid Docker {kind} inspection for {name}") from exc
    return document


def _verify_installed_resources(layout: Layout, image: str) -> None:
    """Resume only the installed source and live resources of this recipe."""
    setup = _inspect("container", SETUP_CONTAINER)
    mounts = {m.get("Destination"): m for m in setup.get("Mounts", [])}
    if (setup.get("Image") != image
            or not setup.get("State", {}).get("Running")
            or set(setup.get("NetworkSettings", {}).get("Networks", {})) != {NETWORK}
            or mounts.get(WORKDIR, {}).get("Source") != layout.build_source
            or mounts.get(WORKDIR, {}).get("Type") != "bind"
            or mounts.get(WORKDIR, {}).get("RW") is not True
            or mounts.get("/composer-cache", {}).get("Source") != layout.composer_cache):
        raise ProvisionRefused(
            "REFUSED: seed stage setup container does not match the installed "
            "workspace, immutable image and internal network; no resource was changed.")
    database = _inspect("container", MYSQL_CONTAINER)
    if (database.get("Config", {}).get("Image") != MYSQL_IMAGE
            or not database.get("State", {}).get("Running")
            or database.get("State", {}).get("Health", {}).get("Status") != "healthy"
            or set(database.get("NetworkSettings", {}).get("Networks", {})) != {NETWORK}):
        raise ProvisionRefused(
            "REFUSED: seed stage needs this recipe's healthy pinned MySQL "
            "container on its internal network; no resource was changed.")
    if _inspect("network", NETWORK).get("Internal") is not True:
        raise ProvisionRefused(
            "REFUSED: seed stage network is not internal; no resource was changed.")


def _verify_corpus(source: str) -> None:
    """An existing T0 extraction corpus must still be the pinned checkout."""
    facts = {}
    for name, command in (
            ("root", ["rev-parse", "--show-toplevel"]),
            ("origin", ["remote", "get-url", "origin"]),
            ("commit", ["rev-parse", "HEAD"]),
            ("dirty", ["status", "--porcelain"])):
        facts[name] = _checked(["git", "-C", source, *command],
                               capture_output=True).stdout.strip()
    if (facts["root"] != source or facts["origin"] != SOURCE_URL
            or facts["commit"] != SOURCE_COMMIT or facts["dirty"]):
        raise ProvisionRefused(
            "REFUSED: existing PrestaShop corpus must be a clean Git "
            f"toplevel at {SOURCE_URL} @ {SOURCE_COMMIT}: {source}. "
            "Provisioning does not repair or overwrite corpus inputs.")


def _clone_source(layout: Layout) -> None:
    os.makedirs(os.path.dirname(layout.source), exist_ok=True)
    if not os.path.lexists(layout.source):
        _checked(["git", "clone", "--no-checkout", SOURCE_URL, layout.source])
        _checked(["git", "-C", layout.source, "checkout", "--detach",
                  SOURCE_COMMIT])
    # The extraction corpus remains intact, including .git and every gold
    # context. Only this separate copy receives installed files and stripping.
    shutil.copytree(layout.source, layout.build_source, symlinks=True)
    shutil.copyfile(COMPOSER_LOCK,
                    os.path.join(layout.build_source, "composer.lock"))


def _install_dependencies(layout: Layout, image: str) -> None:
    # Copy the image's prepared checkout over the same pinned source. The
    # image omits .git, preserving the copy's upstream provenance. There is
    # no second source copy in the image outside the later workspace mount.
    _checked(["docker", "create", "--name", SETUP_CONTAINER,
              "--network", "none", image])
    _checked(["docker", "cp", f"{SETUP_CONTAINER}:{WORKDIR}/.",
              layout.build_source])
    _checked(["docker", "container", "rm", SETUP_CONTAINER], timeout=60)


def _configure_application(layout: Layout) -> None:
    # Use the upstream CI configuration, including its deliberately public
    # test keys. Environment DB_HOST variables are not read by PrestaShop.
    parameters = {
        "database_host": MYSQL_CONTAINER,
        "database_port": "3306",
        "database_name": DATABASE_NAME,
        "database_user": "root",
        "database_password": "root",
    }
    source = os.path.join(layout.build_source, ".github", "workflows", "phpunit")
    destination = os.path.join(layout.build_source, "app", "config")
    shutil.copyfile(os.path.join(source, "parameters.php"),
                    os.path.join(destination, "parameters.php"))
    with open(os.path.join(source, "parameters.yml"), encoding="utf-8") as fh:
        document = yaml.safe_load(fh)
    document["parameters"].update(parameters)
    with open(os.path.join(destination, "parameters.yml"), "w",
              encoding="utf-8") as fh:
        yaml.safe_dump(document, fh, sort_keys=False)
    # Updating through PHP keeps the CI key material and PHP serialization
    # intact. These are public isolated-fixture credentials, not user inputs.
    patch = (
        "$p = require 'app/config/parameters.php'; "
        f"$v = json_decode({json.dumps(json.dumps(parameters))}, true); "
        "$p['parameters'] = array_replace($p['parameters'], $v); "
        "file_put_contents('app/config/parameters.php', "
        "'<?php return ' . var_export($p, true) . ';');"
    )
    _exec_php(SETUP_CONTAINER, ["php", "-r", patch])


# Both legacy config/bootstrap.php and Symfony's set_parameters.php require
# this generated file. The URL carries the actual test_ schema while upstream
# adds that prefix to the base database_name, so remove it exactly once here.
DATABASE_PARAMETERS_BRIDGE = r"""
$dsn = getenv('DATABASE_URL');
$parts = is_string($dsn) ? parse_url($dsn) : false;
if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'mysql'
    || empty($parts['host']) || !isset($parts['user'], $parts['pass'], $parts['path'])) {
    throw new RuntimeException('R2T PrestaShop requires its assigned DATABASE_URL');
}
$schema = rawurldecode(substr($parts['path'], 1));
if (!preg_match('/^test_[A-Za-z][A-Za-z0-9_]*$/D', $schema)) {
    throw new RuntimeException('R2T PrestaShop schema must have one test_ prefix');
}
$config['parameters']['database_host'] = $parts['host'];
$config['parameters']['database_port'] = (string) ($parts['port'] ?? 3306);
$config['parameters']['database_name'] = substr($schema, 5);
$config['parameters']['database_user'] = rawurldecode($parts['user']);
$config['parameters']['database_password'] = rawurldecode($parts['pass']);
return $config;
"""


def _runtime_configuration(installed: str) -> str:
    # _configure_application writes a single var_export return, without a
    # closing PHP tag. Keep every non-database installed parameter unchanged.
    if not installed.startswith("<?php"):
        raise ProvisionRefused("REFUSED: installed PrestaShop parameters are not PHP")
    return ("<?php\n$config = (static function () {\n"
            + installed[len("<?php"):]
            + "\n})();\n" + DATABASE_PARAMETERS_BRIDGE)


def _install_runtime_configuration(layout: Layout) -> None:
    path = os.path.join(layout.build_source, "app", "config", "parameters.php")
    with open(path, encoding="utf-8") as fh:
        configured = _runtime_configuration(fh.read())
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(configured)
    # Legacy bootstrap caches the evaluated parameters. Workers get an empty
    # cache from the seed; the installed indexing container must clear it too.
    _exec_php(SETUP_CONTAINER, ["rm", "-rf", f"{WORKDIR}/var/cache"])


def runtime_env(_template_output: str = "") -> dict[str, str]:
    """The installer returns logs; unlike CoreShop it generates no key."""
    return {"APP_ENV": "test", "COMPOSER_CACHE_DIR": "/composer-cache",
            "COMPOSER_PROCESS_TIMEOUT": "600", "XDEBUG_MODE": "off",
            "SYMFONY_DEPRECATIONS_HELPER": "disabled",
            "DATABASE_URL": f"mysql://root:root@{MYSQL_CONTAINER}:3306/{SCHEMA}"}


def _seed_rules():
    from ..bench.seed import RULES_BY_PROJECT, rules_for

    # Missing project registration falls back to CoreShop in the shared API.
    # Refuse it before stripping: those rules prune tables PrestaShop lacks,
    # and a local replacement would fail the worker's seed-policy check.
    if "prestashop" not in RULES_BY_PROJECT:
        raise ProvisionRefused(
            "REFUSED: PrestaShop seed rules are not registered; use the "
            "reviewed checkout containing its runtime integration before --stage seed")
    return rules_for("behat", "prestashop")


def _wait_for_mysql() -> None:
    deadline = time.monotonic() + 180
    while True:
        cp = _checked(
            ["docker", "container", "inspect", "--format",
             "{{.State.Health.Status}}", MYSQL_CONTAINER],
            capture_output=True, timeout=60)
        status = cp.stdout.strip()
        if status == "healthy":
            return
        if status == "unhealthy" or time.monotonic() >= deadline:
            raise ProvisionRefused(
                f"REFUSED: {MYSQL_CONTAINER} did not become healthy "
                f"(last status {status!r}).")
        time.sleep(2)


def _exec_php(container: str, command: list[str]) -> None:
    _checked(["docker", "exec", "--env", "XDEBUG_MODE=off",
              container, *command])


def _build_seed(layout: Layout) -> dict:
    from ..core.boundary import load_boundary
    from ..bench.dbadmin import MySQL
    from ..bench.repo import baseline_substrate, strip_repo
    from ..bench.seed import build_seed, verify_seed

    rules = _seed_rules()

    # Cache removal happens under the same container ownership as install.
    # Keep var/r2t-db-dumps: templates/workers copy these inputs into /tmp
    # for the retained DatabaseDump hooks.
    _exec_php(SETUP_CONTAINER, ["rm", "-rf", f"{WORKDIR}/var/cache",
                               f"{WORKDIR}/var/log", f"{WORKDIR}/var/logs"])
    boundary = load_boundary(BOUNDARY, repo_root=layout.build_source)
    try:
        manifest = strip_repo(boundary, layout.gold, PHP_HARNESS)
    except SystemExit as exc:
        raise ProvisionRefused(
            "REFUSED: PrestaShop's Behat strip integration must be present "
            f"before seed construction: {exc}") from exc
    _exec_php(SETUP_CONTAINER, ["composer", "dump-autoload", "--optimize",
                               "--no-interaction"])
    _checked(["docker", "container", "rm", "--force", SETUP_CONTAINER],
             timeout=60)
    os.rename(layout.build_source, layout.workspace)
    manifest.repo_root = layout.workspace
    manifest.gold_root = layout.gold
    boundary = load_boundary(BOUNDARY, repo_root=layout.workspace)
    baseline_substrate(manifest, boundary,
                       os.path.join(layout.gold, "strip_manifest.json"))
    with MySQL(container=MYSQL_CONTAINER) as db:
        build_seed(layout.workspace, boundary, layout.seed, SCHEMA,
                   db, manifest=manifest, rules=rules)
    verification = verify_seed(layout.seed, layout.workspace)
    if not verification["artifacts_ok"] or verification["stale"]:
        raise ProvisionRefused(
            "REFUSED: newly built PrestaShop seed failed verification: "
            f"{json.dumps(verification, sort_keys=True)}")
    return verification


def _install(layout: Layout, image: str) -> dict:
    _clone_source(layout)
    os.makedirs(layout.composer_cache, exist_ok=True)
    _install_dependencies(layout, image)
    _checked(["docker", "network", "create", "--internal", NETWORK], timeout=60)
    mysql_env = dict(os.environ)
    mysql_env.update(MYSQL_ROOT_PASSWORD="root", MYSQL_DATABASE=SCHEMA)
    _checked([
        "docker", "run", "--detach", "--name", MYSQL_CONTAINER,
        "--network", NETWORK,
        "--health-cmd", "mysqladmin ping -h 127.0.0.1 --silent",
        "--health-interval", "2s", "--health-timeout", "2s",
        "--health-retries", "90", "--env", "MYSQL_ROOT_PASSWORD",
        "--env", "MYSQL_DATABASE", MYSQL_IMAGE,
    ], env=mysql_env)
    _wait_for_mysql()
    child_env = dict(os.environ)
    runtime = runtime_env()
    child_env.update(runtime)
    env_args = [part for name in runtime for part in ("--env", name)]
    _checked([
        "docker", "run", "--detach", "--rm", "--name", SETUP_CONTAINER,
        "--network", NETWORK, "--volume", f"{layout.build_source}:{WORKDIR}",
        "--volume", f"{layout.composer_cache}:/composer-cache",
        *env_args, image,
    ], env=child_env)
    _configure_application(layout)
    _exec_php(SETUP_CONTAINER, ["rm", "-rf", f"{WORKDIR}/var/cache"])
    _exec_php(SETUP_CONTAINER, ["mkdir", "-p", f"{WORKDIR}/var/r2t-db-dumps"])
    # Only installation persists sys_get_temp_dir()'s restore dumps in the
    # seed. Normal runtime /tmp must remain outside the measured workspace.
    _checked(["docker", "exec", "--env", "XDEBUG_MODE=off",
              "--env", f"TMPDIR={WORKDIR}/var/r2t-db-dumps",
              SETUP_CONTAINER, *TEMPLATE_COMMAND])
    _install_runtime_configuration(layout)
    _exec_php(SETUP_CONTAINER, ["cp", "-a",
                               f"{WORKDIR}/var/r2t-db-dumps/.", "/tmp/"])
    return {
        "stage": "install", "source": {"url": SOURCE_URL,
            "commit": SOURCE_COMMIT, "path": layout.source},
        "workspace": layout.build_source, "image": image,
        "setup_container": SETUP_CONTAINER, "workdir": WORKDIR,
        "database_container": MYSQL_CONTAINER, "schema": SCHEMA,
        "next": "Run index, index-prod and closures before --stage seed.",
    }


def _seed(layout: Layout, image: str) -> dict:
    # Stripping removes the setup container. Keep MySQL alone on its internal
    # bridge: worker provision requires that exclusive starting topology.
    seed = _build_seed(layout)
    child_env = dict(os.environ)
    runtime = runtime_env()
    child_env.update(runtime)
    env_args = [part for name in runtime for part in ("--env", name)]
    _checked([
        "docker", "run", "--detach", "--name", PHP_CONTAINER,
        "--network", "none", "--volume", f"{layout.workspace}:{WORKDIR}",
        "--volume", f"{layout.composer_cache}:/composer-cache",
        *env_args, image,
    ], env=child_env)
    _exec_php(PHP_CONTAINER, ["cp", "-a",
                             f"{WORKDIR}/var/r2t-db-dumps/.", "/tmp/"])
    return {
        "stage": "seed", "source": {"url": SOURCE_URL,
            "commit": SOURCE_COMMIT, "path": layout.source},
        "workspace": layout.workspace,
        "image": image, "mysql_image": MYSQL_IMAGE,
        "template_container": PHP_CONTAINER,
        "database_container": MYSQL_CONTAINER, "schema": SCHEMA,
        "gold": layout.gold, "seed_path": layout.seed, "seed": seed,
    }


def provision(data_root: str, image: str, *, stage: str) -> dict:
    """Provision below one explicit root, including lazy config defaults."""
    layout = Layout.under(data_root)
    saved = os.environ.get(DATA_ROOT_ENV)
    os.environ[DATA_ROOT_ENV] = layout.data_root
    try:
        _preflight(layout, image, stage)
        return _install(layout, image) if stage == "install" else _seed(layout, image)
    finally:
        if saved is None:
            os.environ.pop(DATA_ROOT_ENV, None)
        else:
            os.environ[DATA_ROOT_ENV] = saved


def selftest() -> int:
    failures = []

    def check(name, condition):
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}")
        if not condition:
            failures.append(name)

    module = __import__(__name__, fromlist=["x"])
    events = []
    bound_roots = []
    from ..bench import seed as seed_module
    fixture_rules = seed_module.SeedRules(
        prune_tables=(), prune_paths=(),
        exclude_paths=("var/cache", "var/log", "var/logs", ".r2t-exec.lock", ".git"),
        keep_empty=("var/cache", "var/log", "var/logs"))
    image = "sha256:" + "a" * 64

    def fake_run(argv, **kwargs):
        events.append((list(argv), kwargs))
        if argv[:3] == ["docker", "container", "inspect"]:
            if "--format" in argv:
                return subprocess.CompletedProcess(argv, 0, "healthy\n", "")
            return subprocess.CompletedProcess(argv, 1, "", "No such object")
        if argv[:3] == ["docker", "network", "inspect"]:
            return subprocess.CompletedProcess(argv, 1, "", "not found")
        if argv[:3] == ["git", "clone", "--no-checkout"]:
            os.makedirs(argv[-1])
        return subprocess.CompletedProcess(argv, 0, "", "")

    def fake_seed(layout):
        bound_roots.append(os.environ.get(DATA_ROOT_ENV))
        os.rename(layout.build_source, layout.workspace)
        return {"artifacts_ok": True, "stale": False}

    saved_root = os.environ.get(DATA_ROOT_ENV)
    with tempfile.TemporaryDirectory() as root, \
            mock.patch.object(module, "_run", side_effect=fake_run), \
            mock.patch.object(module, "_configure_application"), \
            mock.patch.object(module, "_install_runtime_configuration"), \
            mock.patch.object(module, "_build_seed", side_effect=fake_seed), \
            mock.patch.object(module.os.path, "isfile", return_value=True), \
            mock.patch.object(module.shutil, "copyfile"):
        installed = provision(root, image, stage="install")
        check("install stops before strip and seed, exposing the unstripped setup workspace",
              installed["stage"] == "install" and not bound_roots
              and installed["workspace"] == Layout.under(root).build_source
              and installed["setup_container"] == SETUP_CONTAINER
              and not os.path.exists(Layout.under(root).workspace))
        with mock.patch.object(module, "_verify_corpus"), \
                mock.patch.dict(seed_module.RULES_BY_PROJECT, {"prestashop": fixture_rules}), \
                mock.patch.object(module, "_verify_installed_resources"):
            report = provision(root, image, stage="seed")
    commands = [argv for argv, _kwargs in events]
    check("source clone is checked out at the pinned upstream commit",
          ["git", "-C", report["source"]["path"],
           "checkout", "--detach", SOURCE_COMMIT] in commands)
    check("explicit data root binds seed construction and is restored",
          bound_roots == [root]
          and os.environ.get(DATA_ROOT_ENV) == saved_root)
    check("database uses the fixed internal network and test-prefixed schema",
          ["docker", "network", "create", "--internal", NETWORK] in commands
          and SCHEMA == "test_" + DATABASE_NAME)
    mysql = [(a, k) for a, k in events if MYSQL_IMAGE in a]
    check("only the pinned database image runs; credentials use environment",
          len(mysql) == 1 and mysql[0][0][-1] == MYSQL_IMAGE
          and "root" not in mysql[0][0]
          and mysql[0][1]["env"]["MYSQL_DATABASE"] == SCHEMA)
    install = ["docker", "exec", "--env", "XDEBUG_MODE=off",
               "--env", f"TMPDIR={WORKDIR}/var/r2t-db-dumps",
               SETUP_CONTAINER, *TEMPLATE_COMMAND]
    template = next(argv for argv in commands
                    if argv[:3] == ["docker", "run", "--detach"]
                    and PHP_CONTAINER in argv)
    check("install-and-dump runs before the canonical template starts",
          install in commands
          and commands.index(install) < commands.index(template)
          and f"{report['workspace']}:{WORKDIR}" in template)
    check("final template is an offline env carrier, leaving MySQL for worker provisioning",
          template[template.index("--network") + 1] == "none")
    check("template restores its saved hook dumps to ordinary runtime /tmp",
          commands[-1] == ["docker", "exec", "--env", "XDEBUG_MODE=off",
                           PHP_CONTAINER, "cp", "-a",
                           f"{WORKDIR}/var/r2t-db-dumps/.", "/tmp/"])
    used_images = [argv[-1] for argv in commands
                   if argv[:2] == ["docker", "create"]
                   or (argv[:3] == ["docker", "run", "--detach"]
                       and MYSQL_IMAGE not in argv)]
    check("export, setup and template consume the same verified image without rebuild",
          used_images == [image, image, image] and report["image"] == image
          and not any(argv[:2] == ["docker", "build"] for argv in commands))
    check("restore dump TMPDIR applies only to installation, not runtime",
          "TMPDIR" not in runtime_env()
          and sum(any(arg.startswith("TMPDIR=") for arg in argv)
                  for argv in commands) == 1)
    check("prepared source is exported from only the workspace image path",
          ["docker", "cp", f"{SETUP_CONTAINER}:{WORKDIR}/.",
           report["workspace"] + ".provisioning"] in commands
          and not any("/opt/r2t" in arg for argv in commands for arg in argv))

    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        os.makedirs(os.path.join(layout.source, ".git"))
        with open(os.path.join(layout.source, ".git", "HEAD"), "w") as fh:
            fh.write(SOURCE_COMMIT)
        with open(os.path.join(layout.source, "gold-context.php"), "w") as fh:
            fh.write("upstream gold bytes")

        def existing_run(argv, **kwargs):
            if argv[:3] == ["git", "-C", layout.source]:
                value = {("rev-parse", "--show-toplevel"): layout.source,
                         ("remote", "get-url", "origin"): SOURCE_URL,
                         ("rev-parse", "HEAD"): SOURCE_COMMIT,
                         ("status", "--porcelain"): ""}[tuple(argv[3:])]
                return subprocess.CompletedProcess(argv, 0, value, "")
            return fake_run(argv, **kwargs)

        def stripping_seed(layout):
            os.remove(os.path.join(layout.build_source, "gold-context.php"))
            shutil.rmtree(os.path.join(layout.build_source, ".git"))
            return fake_seed(layout)

        fixture_lock = os.path.join(root, "accepted.lock")
        with open(fixture_lock, "w") as fh:
            fh.write("{}")
        with mock.patch.object(module, "_run", side_effect=existing_run), \
                mock.patch.object(module, "_configure_application"), \
            mock.patch.object(module, "_install_runtime_configuration"), \
                mock.patch.object(module, "_build_seed", side_effect=stripping_seed), \
                mock.patch.object(module.os.path, "isfile", return_value=True), \
                mock.patch.object(module, "COMPOSER_LOCK", fixture_lock):
            installed = provision(root, image, stage="install")
            with open(os.path.join(installed["workspace"], "gold-context.php")) as fh:
                indexed_gold = fh.read()
            check("indexing interval still sees the original gold context",
                  indexed_gold == "upstream gold bytes")
            with mock.patch.object(module, "_verify_installed_resources"), \
                    mock.patch.dict(seed_module.RULES_BY_PROJECT, {"prestashop": fixture_rules}):
                report = provision(root, image, stage="seed")
        with open(os.path.join(layout.source, ".git", "HEAD")) as fh:
            corpus_commit = fh.read()
        with open(os.path.join(layout.source, "gold-context.php")) as fh:
            corpus_gold = fh.read()
        check("T0 corpus survives T3 install and strip in a separate workspace",
              corpus_commit == SOURCE_COMMIT and corpus_gold == "upstream gold bytes"
              and report["source"]["path"] != report["workspace"]
              and not os.path.exists(os.path.join(layout.workspace, "gold-context.php")))

    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        os.makedirs(layout.source)
        facts = {
            ("rev-parse", "--show-toplevel"): layout.source,
            ("remote", "get-url", "origin"): SOURCE_URL,
            ("rev-parse", "HEAD"): SOURCE_COMMIT,
            ("status", "--porcelain"): " M tracked-context.php",
        }
        with mock.patch.object(module.os.path, "isfile", return_value=True), \
                mock.patch.object(module, "_run", side_effect=lambda argv, **kwargs:
                                  subprocess.CompletedProcess(
                                      argv, 0, facts[tuple(argv[3:])], "")) as run:
            try:
                provision(root, image, stage="install")
                refusal = ""
            except ProvisionRefused as exc:
                refusal = str(exc)
        check("modified extraction corpus refuses without invoking Docker or copying it",
              "clean Git toplevel" in refusal
              and all(call.args[0][0] == "git" for call in run.call_args_list)
              and not os.path.exists(layout.build_source))

    with tempfile.TemporaryDirectory() as root, \
            mock.patch.object(module, "_run") as run:
        try:
            provision(root, "r2t-prestashop:mutable", stage="install")
            refusal = ""
        except ProvisionRefused as exc:
            refusal = str(exc)
        check("mutable image refuses before any subprocess or filesystem mutation",
              "immutable sha256 image ID" in refusal and not run.called
              and not os.listdir(root))

    with tempfile.TemporaryDirectory() as root, \
            mock.patch.object(module, "_run") as run:
        try:
            provision(root, image, stage="seed")
            refusal = ""
        except ProvisionRefused as exc:
            refusal = str(exc)
        check("seed stage refuses before installation without contacting Docker",
              "Complete --stage install" in refusal and not run.called)

    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        original = {
            SETUP_CONTAINER: {
                "Image": image, "State": {"Running": True},
                "NetworkSettings": {"Networks": {NETWORK: {}}},
                "Mounts": [{"Type": "bind", "Source": layout.build_source,
                            "Destination": WORKDIR, "RW": True},
                           {"Type": "bind", "Source": layout.composer_cache,
                            "Destination": "/composer-cache", "RW": True}],
            },
            MYSQL_CONTAINER: {
                "Config": {"Image": MYSQL_IMAGE},
                "State": {"Running": True, "Health": {"Status": "healthy"}},
                "NetworkSettings": {"Networks": {NETWORK: {}}},
            },
            NETWORK: {"Internal": True},
        }
        for fault in (None, "image", "workspace", "database", "network"):
            documents = json.loads(json.dumps(original))
            if fault == "image":
                documents[SETUP_CONTAINER]["Image"] = "sha256:" + "b" * 64
            elif fault == "workspace":
                documents[SETUP_CONTAINER]["Mounts"][0]["Source"] = root + "/other"
            elif fault == "database":
                documents[MYSQL_CONTAINER]["State"]["Health"]["Status"] = "unhealthy"
            elif fault == "network":
                documents[NETWORK]["Internal"] = False
            calls = []

            def inspect_run(argv, **kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps([documents[argv[-1]]]), "")

            with mock.patch.object(module, "_run", side_effect=inspect_run):
                try:
                    _verify_installed_resources(layout, image)
                    refused = False
                except ProvisionRefused:
                    refused = True
            check("seed resume requires its own installed live resources: " + str(fault),
                  refused == (fault is not None)
                  and all(argv[0] == "docker" and argv[2] == "inspect"
                          for argv in calls))

    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        os.makedirs(layout.build_source)
        with mock.patch.dict(seed_module.RULES_BY_PROJECT, {}, clear=True), \
                mock.patch.object(module, "_run") as run:
            try:
                provision(root, image, stage="seed")
                refusal = ""
            except ProvisionRefused as exc:
                refusal = str(exc)
        check("missing project seed policy refuses before strip or Docker",
              "seed rules are not registered" in refusal and not run.called)

    with mock.patch.dict(seed_module.RULES_BY_PROJECT, {"prestashop": fixture_rules}), \
            mock.patch.object(seed_module, "rules_for", return_value=fixture_rules) as resolve:
        check("seed construction resolves the worker's registered project policy",
              _seed_rules() is fixture_rules
              and resolve.call_args.args == ("behat", "prestashop"))

    php = shutil.which("php")
    if php:
        with tempfile.TemporaryDirectory() as root:
            layout = Layout.under(root)
            parameters = os.path.join(layout.build_source, "app", "config", "parameters.php")
            os.makedirs(os.path.dirname(parameters))
            with open(parameters, "w") as fh:
                fh.write("<?php return ['parameters' => ['database_name' => 'prestashop_bench', "
                         "'database_user' => 'root', 'database_password' => 'root', "
                         "'cookie_key' => 'public-fixture-key']];")
            with mock.patch.object(module, "_exec_php") as execute:
                _install_runtime_configuration(layout)
            check("writing the bridge invalidates evaluated installer parameters",
                  execute.call_args.args == (SETUP_CONTAINER,
                      ["rm", "-rf", f"{WORKDIR}/var/cache"]))
            for schema, user, password in ((SCHEMA, "root", "root"),
                                          ("test_prestashop_pool_0", "bench_0", "pass@:/%")):
                from urllib.parse import quote
                env = dict(os.environ)
                env["DATABASE_URL"] = (f"mysql://{user}:{quote(password, safe='')}"
                                       f"@prestashop_db:3306/{schema}")
                cp = subprocess.run([php, "-n", "-r",
                                     "echo json_encode(require $argv[1]);", parameters],
                                    env=env, text=True, capture_output=True)
                actual = json.loads(cp.stdout).get("parameters", {}) if cp.returncode == 0 else {}
                check("real PHP bridge resolves assigned install/worker parameters: " + schema,
                      cp.returncode == 0 and actual.get("database_name") == schema[5:]
                      and actual.get("database_host") == MYSQL_CONTAINER
                      and actual.get("database_port") == "3306"
                      and actual.get("database_user") == user
                      and actual.get("database_password") == password
                      and actual.get("cookie_key") == "public-fixture-key")
            # Run the real initializer against this real generated bridge.
            # A namespaced PDO sentinel stops at the connection boundary, so
            # the fixture needs no driver, database or external connection.
            with open(os.path.join(PHP_HARNESS, "prestashop_worker_init.php"),
                      encoding="utf-8") as fh:
                init_source = fh.read()
            assert init_source.count("declare(strict_types=1);") == 1
            init_source = init_source.replace(
                "declare(strict_types=1);",
                "declare(strict_types=1);\nnamespace R2TConfigScope;\nuse RuntimeException;", 1)
            init_path = os.path.join(root, "worker-init-scope.php")
            with open(init_path, "w", encoding="utf-8") as fh:
                fh.write(init_source)
            probe = r"""namespace R2TConfigScope {
                final class PDO {
                    public const ATTR_ERRMODE = 1;
                    public const ERRMODE_EXCEPTION = 2;
                    public function __construct($dsn, $user, $password, $options) {
                        throw new \LogicException(json_encode([$dsn, $user, $password]));
                    }
                }
                require $argv[1];
                try {
                    prestashopWorkerInit(['scope', 'test_prestashop_bench',
                        'test_prestashop_pool_0', 'bench_0']);
                } catch (\LogicException $reachedConnection) {
                    echo $reachedConnection->getMessage();
                } catch (\Throwable $error) {
                    fwrite(STDERR, get_class($error));
                    exit(1);
                }
            }"""
            cp = subprocess.run([php, "-n", "-r", probe, init_path],
                                cwd=layout.build_source, env=env,
                                text=True, capture_output=True)
            connection = json.loads(cp.stdout) if cp.returncode == 0 else None
            check("real initializer preserves its parsed DSN while including the generated bridge",
                  cp.returncode == 0 and connection == [
                      "mysql:host=prestashop_db;port=3306;dbname=test_prestashop_pool_0",
                      "bench_0", "pass@:/%"])
            for dsn in (None, "mysql://bench_0:private@prestashop_db/prestashop_pool_0"):
                env = dict(os.environ)
                env.pop("DATABASE_URL", None)
                if dsn is not None:
                    env["DATABASE_URL"] = dsn
                cp = subprocess.run([php, "-n", "-r", "require $argv[1];", parameters],
                                    env=env, text=True, capture_output=True)
                check("real PHP refuses missing/mis-prefixed DSN without installer fallback",
                      cp.returncode != 0 and "private" not in cp.stdout + cp.stderr)
    else:
        print("  [NOT RUN] real PHP bridge fixture requires PHP on PATH")

    from ..core import docker_cli
    with mock.patch.object(docker_cli, "docker_command",
                           return_value=["verified-docker", "inspect"]) as route, \
            mock.patch.object(subprocess, "run") as run:
        _run(["docker", "inspect"], capture_output=True)
        check("every Docker subprocess goes through the authority route",
              route.call_args.args == (["inspect"],)
              and run.call_args.args == (["verified-docker", "inspect"],))

    for attribute in ("workspace", "build_source", "gold", "seed"):
        with tempfile.TemporaryDirectory() as root:
            layout = Layout.under(root)
            os.makedirs(getattr(layout, attribute))
            with mock.patch.object(module, "_run") as run:
                try:
                    provision(root, image, stage="install")
                    refusal = ""
                except ProvisionRefused as exc:
                    refusal = str(exc)
            check(f"existing {attribute} refuses before subprocesses",
                  "already exists" in refusal and not run.called)
    with tempfile.TemporaryDirectory() as root, \
            mock.patch.object(module.os.path, "isfile", return_value=True), \
            mock.patch.object(module, "_run", return_value=
                              subprocess.CompletedProcess([], 0, "{}", "")) as run:
        try:
            provision(root, image, stage="install")
            refusal = ""
        except ProvisionRefused as exc:
            refusal = str(exc)
        check("occupied Docker name refuses before mutation",
              "already exists" in refusal and run.call_count == 1)
    with tempfile.TemporaryDirectory() as root, \
            mock.patch.object(module.os.path, "isfile", return_value=False), \
            mock.patch.object(module, "_run") as run:
        try:
            provision(root, image, stage="install")
            refusal = ""
        except ProvisionRefused as exc:
            refusal = str(exc)
        check("unmerged recipe inputs refuse before subprocesses",
              "reviewed train checkout" in refusal and not run.called)

    from ..core import boundary as boundary_module
    from ..bench import dbadmin as dbadmin_module
    from ..bench import repo as repo_module
    from ..bench import seed as seed_module

    with tempfile.TemporaryDirectory() as root:
        workspace = os.path.join(root, "workspace")
        gold = os.path.join(root, "gold")
        os.makedirs(os.path.join(workspace, "_bench"))
        for name in ("php_index.json", "matches.json", "steps.json"):
            with open(os.path.join(workspace, "_bench", name), "w") as fh:
                fh.write("original extraction answer data")
        repo_module.sanitise_repo(workspace, gold)
        check("existing strip sanitisation moves original index answers outside the seed tree",
              all(not os.path.exists(os.path.join(workspace, "_bench", name))
                  and os.path.isfile(os.path.join(gold, "_extraction", name))
                  for name in ("php_index.json", "matches.json", "steps.json")))

    for verification in ({"artifacts_ok": True, "stale": False},
                         {"artifacts_ok": False, "stale": False},
                         {"artifacts_ok": True, "stale": True}):
        with tempfile.TemporaryDirectory() as root:
            layout = Layout.under(root)
            os.makedirs(layout.build_source)
            manifest = mock.Mock()
            with mock.patch.object(boundary_module, "load_boundary"), \
                    mock.patch.dict(seed_module.RULES_BY_PROJECT, {"prestashop": fixture_rules}), \
                    mock.patch.object(repo_module, "strip_repo",
                                      return_value=manifest), \
                    mock.patch.object(repo_module, "baseline_substrate") as baseline, \
                    mock.patch.object(dbadmin_module, "MySQL") as mysql, \
                    mock.patch.object(seed_module, "build_seed") as build, \
                    mock.patch.object(seed_module, "verify_seed",
                                      return_value=verification) as verify, \
                    mock.patch.object(module, "_checked"), \
                    mock.patch.object(module, "_exec_php"):
                try:
                    result = _build_seed(layout)
                    refused = False
                except ProvisionRefused:
                    result = None
                    refused = True
            valid = verification["artifacts_ok"] and not verification["stale"]
            check("only a complete current seed is accepted: " + str(verification),
                  refused is not valid and (not valid or result == verification))
            if valid:
                rules = build.call_args.kwargs["rules"]
                check("seed uses the test schema, retains restore dumps and prunes no DB tables",
                      build.call_args.args[2:4] == (layout.seed, SCHEMA)
                      and rules is fixture_rules
                      and rules.prune_tables == ()
                      and "var/r2t-db-dumps" not in rules.exclude_paths
                      and "var/logs" in rules.exclude_paths)
                check("baseline and verification use the final source and preserved gold",
                      manifest.repo_root == layout.workspace
                      and manifest.gold_root == layout.gold
                      and baseline.call_args.args[2]
                      == os.path.join(layout.gold, "strip_manifest.json")
                      and verify.call_args.args == (layout.seed, layout.workspace)
                      and mysql.call_args.kwargs == {"container": MYSQL_CONTAINER})

    print("\n" + ("FAILURES" if failures else "ALL PASS")
          + " (provision_prestashop)")
    return 1 if failures else 0


def main(argv=None) -> int:
    from ..core.docker_cli import (DockerEndpointRefused, add_cli_arguments,
                                  configure_from_args)
    from ..core.paths import data_root

    parser = argparse.ArgumentParser(description=__doc__)
    add_cli_arguments(parser)
    parser.add_argument("--data-root", help="new project layout under R2T_DATA_ROOT")
    parser.add_argument("--image", help="immutable sha256 image ID after T2 round trip")
    parser.add_argument("--stage", choices=("install", "seed"),
                        help="install first; seed only after index/index-prod/closures")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.stage is None:
        parser.error("--stage install or --stage seed is required")
    configure_from_args(args)
    try:
        report = provision(args.data_root or data_root(), args.image, stage=args.stage)
    except (ProvisionRefused, DockerEndpointRefused) as exc:
        parser.exit(1, str(exc) + "\n")
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
