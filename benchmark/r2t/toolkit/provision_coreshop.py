"""Build the disclosed CoreShop v1 environment beside the shipped seed.

This is deliberately one project recipe, not a provisioning framework.  The
source commit, image digests, service names and fixed data layout are the
benchmark identity; making them flags would let two different environments
both call themselves CoreShop v1.
"""
from __future__ import annotations

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

from ..core.paths import DATA_ROOT_ENV
from ..bench.worker import DEFAULT_IMAGE as HARNESS_IMAGE


SOURCE_URL = "https://github.com/coreshop/CoreShop.git"
SOURCE_COMMIT = "05bf7af946c919896d0807e4f0c7af37f446653b"
MYSQL_IMAGE = (
    "mysql:8@sha256:"
    "563602a18ffd5be220968e8508d84c9dcd80fbffe69e28af51572db29e3285b2")
TEMPLATE_COMMAND = ("vendor/bin/generate-defuse-key",)
DEFUSE_KEY = re.compile(r"def[0-9a-f]{133}")

NETWORK = "coreshop_net"
MYSQL_CONTAINER = "coreshop_db"
PHP_CONTAINER = "coreshop_bench_php"
SETUP_CONTAINER = "coreshop_bench_setup"
SCHEMA = "coreshop_bench"

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)
DOCKER_DIR = os.path.join(BENCHMARK, "docker", "coreshop")
DOCKERFILE = os.path.join(DOCKER_DIR, "Dockerfile")
COMPOSER_LOCK = os.path.join(DOCKER_DIR, "composer.lock")
LICENSE_PATCH = os.path.join(DOCKER_DIR, "pimcore-license-gates.patch")
BOUNDARY = os.path.join(BENCHMARK, "config", "boundary_coreshop.yml")
PHP_HARNESS = os.path.join(HERE, "php")


class ProvisionRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class Layout:
    data_root: str
    source: str
    build_source: str
    gold: str
    seed: str
    composer_cache: str

    @classmethod
    def under(cls, root: str) -> "Layout":
        root = os.path.abspath(root)
        project = os.path.join(root, "projects", "coreshop")
        source = os.path.join(project, "source")
        return cls(root, source, source + ".provisioning",
                   os.path.join(project, "gold"),
                   os.path.join(project, "seed", "v1"),
                   os.path.join(root, "cache", "composer"))


def _run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(argv, text=True, **kwargs)


def _checked(argv: list[str], *, capture_output: bool = False,
             env: dict | None = None, timeout: int = 3600
             ) -> subprocess.CompletedProcess:
    cp = _run(argv, capture_output=capture_output, env=env, timeout=timeout)
    if cp.returncode:
        detail = (cp.stderr or cp.stdout or "").strip()[-500:]
        suffix = f": {detail}" if detail else ""
        raise ProvisionRefused(
            f"REFUSED: command failed ({cp.returncode}): "
            f"{shlex.join(argv)}{suffix}")
    return cp


def _require_absent(kind: str, name: str) -> None:
    cp = _run(["docker", kind, "inspect", name], capture_output=True,
              timeout=60)
    if cp.returncode == 0:
        raise ProvisionRefused(
            f"REFUSED: Docker {kind} {name!r} already exists. This command "
            "only provisions a fresh fixed-name environment; inspect and "
            "remove the old resource deliberately before retrying.")
    detail = (cp.stderr or cp.stdout or "").lower()
    absent = "no such" in detail or "not found" in detail
    if not absent:
        raise ProvisionRefused(
            f"REFUSED: could not establish that Docker {kind} {name!r} is "
            f"absent: {(cp.stderr or cp.stdout or '').strip()[-500:]}")


def _preflight(layout: Layout) -> None:
    for label, path in (("source", layout.source),
                        ("provisioning source", layout.build_source)):
        if os.path.lexists(path):
            raise ProvisionRefused(
                f"REFUSED: CoreShop {label} destination already exists: "
                f"{path}. Provisioning never merges with or overwrites an "
                "existing benchmark tree.")
    for label, path in (("gold", layout.gold), ("seed", layout.seed)):
        if not os.path.isdir(path):
            raise ProvisionRefused(
                f"REFUSED: bundled CoreShop {label} is missing: {path}. "
                "Fetch the CoreShop bundle before provisioning its source "
                "and runtime.")
    for name in (SETUP_CONTAINER, PHP_CONTAINER, MYSQL_CONTAINER):
        _require_absent("container", name)
    _require_absent("network", NETWORK)


def _clone_source(layout: Layout) -> None:
    os.makedirs(os.path.dirname(layout.build_source), exist_ok=True)
    _checked(["git", "clone", "--no-checkout", SOURCE_URL,
              layout.build_source])
    _checked(["git", "-C", layout.build_source, "checkout", "--detach",
              SOURCE_COMMIT])
    shutil.copyfile(COMPOSER_LOCK,
                    os.path.join(layout.build_source, "composer.lock"))


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


def _setup_argv(layout: Layout, command: list[str], *, patch=False) -> list[str]:
    argv = [
        "docker", "run", "--rm", "--name", SETUP_CONTAINER,
        "--network", NETWORK,
        "--volume", f"{layout.build_source}:/var/www/html",
        "--volume", f"{layout.composer_cache}:/composer-cache",
        "--env", "COMPOSER_CACHE_DIR=/composer-cache",
    ]
    if patch:
        argv += ["--volume", f"{LICENSE_PATCH}:/r2t/license.patch:ro"]
    return [*argv, HARNESS_IMAGE, *command]


def _install_dependencies(layout: Layout) -> str:
    _checked(_setup_argv(layout, [
        "composer", "install", "--prefer-dist", "--optimize-autoloader",
        "--no-interaction", "--no-progress",
    ]))

    patch_argv = ["patch", "--batch", "--forward", "--strip=1"]
    _checked(_setup_argv(layout, [*patch_argv, "--dry-run",
                                  "--input=/r2t/license.patch"], patch=True))
    _checked(_setup_argv(layout, [*patch_argv,
                                  "--input=/r2t/license.patch"], patch=True))

    cp = _checked(_setup_argv(
        layout, list(TEMPLATE_COMMAND)),
        capture_output=True)
    lines = [line.strip() for line in cp.stdout.splitlines() if line.strip()]
    key = lines[-1] if lines else ""
    if DEFUSE_KEY.fullmatch(key) is None:
        raise ProvisionRefused(
            "REFUSED: vendor/bin/generate-defuse-key did not return a valid "
            "Defuse key.")
    return key


def runtime_env(defuse_key: str) -> dict[str, str]:
    if DEFUSE_KEY.fullmatch(defuse_key) is None:
        raise ProvisionRefused(
            "REFUSED: CoreShop template input is not a valid Defuse key.")
    return {
        "COMPOSER_CACHE_DIR": "/composer-cache",
        "APP_ENV": "test",
        "CORESHOP_SKIP_DB_SETUP": "1",
        "PIMCORE_KERNEL_CLASS": "Kernel",
        "PIMCORE_SECRET": defuse_key,
        "PIMCORE_INSTALL_ENCRYPTION_SECRET": defuse_key,
        "PIMCORE_INSTANCE_IDENTIFIER": "coreshop-benchmark-v1",
        "PIMCORE_INSTALL_INSTANCE_IDENTIFIER": "coreshop-benchmark-v1",
        "PIMCORE_PRODUCT_KEY": "R2T_OFFLINE_BENCHMARK",
        "PIMCORE_INSTALL_PRODUCT_KEY": "R2T_OFFLINE_BENCHMARK",
        "PIMCORE_TEST_DB_DSN":
            f"mysql://root:root@{MYSQL_CONTAINER}:3306/{SCHEMA}",
        "PIMCORE_INSTALL_MYSQL_HOST_SOCKET": MYSQL_CONTAINER,
        "PIMCORE_INSTALL_MYSQL_USERNAME": "root",
        "PIMCORE_INSTALL_MYSQL_PASSWORD": "root",
        "PIMCORE_INSTALL_MYSQL_DATABASE": SCHEMA,
        "PIMCORE_INSTALL_MYSQL_PORT": "3306",
        "PIMCORE_INSTALL_ADMIN_USERNAME": "admin",
        "PIMCORE_INSTALL_ADMIN_PASSWORD": "admin",
    }


def _exec_php(container: str, command: list[str]) -> None:
    _checked(["docker", "exec", "--env", "XDEBUG_MODE=off",
              container, *command])


def _build_seed(layout: Layout) -> dict:
    from ..core.boundary import load_boundary
    from ..bench.dbadmin import MySQL
    from ..bench.repo import baseline_substrate, strip_repo
    from ..bench.seed import build_seed, unpack_workspace, verify_seed

    # The install created root-owned cache entries on the bind mount.  They
    # are disposable state and the existing strip path removes them anyway;
    # clearing them inside their owning container lets that path run without
    # hidden sudo on the host.
    _checked(["docker", "exec", SETUP_CONTAINER, "rm", "-rf",
              "/var/www/html/var/cache", "/var/www/html/var/log"])

    project_root = os.path.dirname(layout.source)
    with tempfile.TemporaryDirectory(
            prefix=".provision-proof-", dir=project_root) as proof:
        proof_gold = os.path.join(proof, "gold")
        proof_seed = os.path.join(proof, "seed")
        boundary = load_boundary(BOUNDARY, repo_root=layout.build_source)
        manifest = strip_repo(boundary, proof_gold, PHP_HARNESS)
        _exec_php(SETUP_CONTAINER, ["composer", "dump-autoload", "--optimize",
                                    "--no-interaction"])
        _checked(["docker", "container", "rm", "--force", SETUP_CONTAINER],
                 timeout=60)
        os.rename(layout.build_source, layout.source)
        manifest.repo_root = layout.source
        manifest.gold_root = proof_gold
        boundary = load_boundary(BOUNDARY, repo_root=layout.source)
        baseline_substrate(
            manifest, boundary,
            os.path.join(proof_gold, "strip_manifest.json"))
        with MySQL(container=MYSQL_CONTAINER) as db:
            build_seed(layout.source, boundary, proof_seed, SCHEMA,
                       db, manifest=manifest)
        recipe_verification = verify_seed(proof_seed, layout.source)
        if not recipe_verification["artifacts_ok"] \
                or recipe_verification["stale"]:
            raise ProvisionRefused(
                "REFUSED: the clean-recipe CoreShop proof seed failed its "
                "existing verification: "
                f"{json.dumps(recipe_verification, sort_keys=True)}")

    unpack_workspace(layout.seed, layout.source, force=True)
    canonical_verification = verify_seed(layout.seed, layout.source)
    if not canonical_verification["artifacts_ok"] \
            or canonical_verification["stale"]:
        raise ProvisionRefused(
            "REFUSED: the installed canonical CoreShop workspace failed its "
            "existing seed verification: "
            f"{json.dumps(canonical_verification, sort_keys=True)}")
    return {"recipe_proof": recipe_verification,
            "installed_canonical": canonical_verification}


def _provision(layout: Layout) -> dict:
    _preflight(layout)
    _clone_source(layout)
    os.makedirs(layout.composer_cache, exist_ok=True)
    _checked(["docker", "build", "--tag", HARNESS_IMAGE,
              "--file", DOCKERFILE, DOCKER_DIR])
    # Composer needs the ordinary bridge network to fetch the locked
    # packages; MySQL is started first so every later install command sees the
    # final service topology.
    _checked(["docker", "network", "create", NETWORK], timeout=60)
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
    key = _install_dependencies(layout)

    runtime = runtime_env(key)
    child_env = dict(os.environ)
    child_env.update(runtime)
    env_args = [part for name in runtime for part in ("--env", name)]
    _checked([
        "docker", "run", "--detach", "--rm", "--name", SETUP_CONTAINER,
        "--network", NETWORK,
        "--volume", f"{layout.build_source}:/var/www/html",
        "--volume", f"{layout.composer_cache}:/composer-cache",
        *env_args, HARNESS_IMAGE,
    ], env=child_env)
    _exec_php(SETUP_CONTAINER,
              ["bin/console", "cache:clear", "--env=test"])
    _exec_php(SETUP_CONTAINER,
              ["bin/console", "assets:install", "--symlink", "--env=test"])
    _exec_php(SETUP_CONTAINER,
              ["vendor/bin/pimcore-install", "--env=test",
               "--skip-database-config", "--skip-product-registration-config",
               "--no-interaction"])
    _exec_php(SETUP_CONTAINER,
              ["bin/console", "coreshop:install", "--env=test",
               "--no-interaction"])

    seed = _build_seed(layout)
    _checked([
        "docker", "run", "--detach", "--name", PHP_CONTAINER,
        "--network", NETWORK,
        "--volume", f"{layout.source}:/var/www/html",
        "--volume", f"{layout.composer_cache}:/composer-cache",
        *env_args, HARNESS_IMAGE,
    ], env=child_env)
    return {
        "source": {"url": SOURCE_URL, "commit": SOURCE_COMMIT,
                   "path": layout.source},
        "image": HARNESS_IMAGE,
        "mysql_image": MYSQL_IMAGE,
        "template_container": PHP_CONTAINER,
        "database_container": MYSQL_CONTAINER,
        "seed": seed,
    }


def provision(data_root: str) -> dict:
    """Provision below one explicit root, including lazy config defaults."""
    layout = Layout.under(data_root)
    saved = os.environ.get(DATA_ROOT_ENV)
    os.environ[DATA_ROOT_ENV] = layout.data_root
    try:
        return _provision(layout)
    finally:
        if saved is None:
            os.environ.pop(DATA_ROOT_ENV, None)
        else:
            os.environ[DATA_ROOT_ENV] = saved


def selftest() -> int:
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        ok = ok and bool(condition)
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))

    with open(DOCKERFILE, encoding="utf-8") as fh:
        dockerfile = fh.read()
    check("PHP base is digest-pinned",
          "FROM ghcr.io/cors-gmbh/pimcore-docker/php-fpm-debug:"
          "8.3-alpine3.21-7.1.0@sha256:" in dockerfile)
    check("ext-sockets is part of the image build",
          "docker-php-ext-install sockets" in dockerfile)
    check("the image carries the utility that applies the reviewed patch",
          "apk add --no-cache patch" in dockerfile)
    check("MySQL is digest-pinned", MYSQL_IMAGE.startswith("mysql:8@sha256:"))

    with open(LICENSE_PATCH, encoding="utf-8") as fh:
        patch_text = fh.read()
    check("one patch edits exactly the two accepted Pimcore files",
          patch_text.count("diff --git ") == 2
          and "PimcoreCoreExtension.php" in patch_text
          and "InstallCommand.php" in patch_text)
    check("the patch disables exactly two validation calls",
          len(re.findall(r"^-\s+.*validateProductKey", patch_text,
                         re.MULTILINE)) == 2)

    with open(COMPOSER_LOCK, encoding="utf-8") as fh:
        lock = json.load(fh)
    pimcore = [p for p in lock["packages"] if p["name"] == "pimcore/pimcore"]
    check("accepted lock pins Pimcore 12.3.9 at its accepted source ref",
          len(pimcore) == 1 and pimcore[0]["version"] == "v12.3.9"
          and pimcore[0]["source"]["reference"]
          == "355ac351e1a672e92246b2cd54763bfa59158cb4")

    events: list[tuple[list[str], dict]] = []

    def fake_run(argv, **kwargs):
        argv = list(argv)
        events.append((argv, kwargs))
        if argv[:3] == ["docker", "container", "inspect"]:
            if "--format" in argv:
                return subprocess.CompletedProcess(argv, 0, "healthy\n", "")
            return subprocess.CompletedProcess(argv, 1, "", "No such object")
        if argv[:3] == ["docker", "network", "inspect"]:
            return subprocess.CompletedProcess(argv, 1, "", "not found")
        if argv[:3] == ["git", "clone", "--no-checkout"]:
            os.makedirs(argv[-1])
        if argv[-1:] == ["vendor/bin/generate-defuse-key"]:
            return subprocess.CompletedProcess(argv, 0,
                                               "def" + "0" * 133 + "\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    bound_roots = []

    def fake_build_seed(layout):
        bound_roots.append(os.environ.get(DATA_ROOT_ENV))
        os.rename(layout.build_source, layout.source)
        return {
            "recipe_proof": {"seed_key": "recipe-fixture",
                             "source_key_now": "recipe-fixture",
                             "artifacts_ok": True, "stale": False},
            "installed_canonical": {"seed_key": "canonical-fixture",
                                    "source_key_now": "canonical-fixture",
                                    "artifacts_ok": True, "stale": False},
        }

    saved_data_root = os.environ.get(DATA_ROOT_ENV)
    with tempfile.TemporaryDirectory() as root, \
            mock.patch.object(__import__(__name__, fromlist=["x"]),
                              "_run", side_effect=fake_run), \
            mock.patch.object(__import__(__name__, fromlist=["x"]),
                              "_build_seed",
                              side_effect=fake_build_seed):
        layout = Layout.under(root)
        os.makedirs(layout.gold)
        os.makedirs(layout.seed)
        report = provision(root)

    commands = [argv for argv, _kwargs in events]
    rendered = [shlex.join(argv) for argv in commands]
    check("the command checks out the one corpus commit",
          ["git", "-C", report["source"]["path"] + ".provisioning",
           "checkout", "--detach", SOURCE_COMMIT] in commands)
    check("an explicit data root binds lazy config during provisioning and "
          "is restored afterwards",
          bound_roots == [root]
          and os.environ.get(DATA_ROOT_ENV) == saved_data_root,
          str(bound_roots))
    check("installation uses the unprotected sibling, while the template "
          "mounts the canonical stripped source",
          any(f"{report['source']['path']}.provisioning:/var/www/html" in argv
              and SETUP_CONTAINER in argv for argv in commands)
          and any(f"{report['source']['path']}:/var/www/html" in argv
                  and PHP_CONTAINER in argv for argv in commands))
    check("the image build names the disclosed successor",
          any(argv[:4] == ["docker", "build", "--tag", HARNESS_IMAGE]
              for argv in commands))
    mysql_runs = [pair for pair in events
                  if pair[0][:3] == ["docker", "run", "--detach"]
                  and MYSQL_IMAGE in pair[0]]
    check("the composed MySQL run uses only the digest-pinned image",
          len(mysql_runs) == 1 and mysql_runs[0][0][-1] == MYSQL_IMAGE)
    check("database credentials are inherited, not exposed in Docker argv",
          len(mysql_runs) == 1 and "root" not in mysql_runs[0][0]
          and mysql_runs[0][1]["env"]["MYSQL_ROOT_PASSWORD"] == "root")
    check("Composer installs the accepted lock and never updates it",
          any("composer install" in line for line in rendered)
          and not any("composer update" in line for line in rendered))
    check("both licence-patch check and application are composed",
          sum("patch --batch --forward --strip=1" in line
              for line in rendered) == 2
          and any("--dry-run --input=/r2t/license.patch" in line
                  for line in rendered))
    check("Pimcore and CoreShop install precede the seed builder",
          any("vendor/bin/pimcore-install" in line for line in rendered)
          and any("bin/console coreshop:install" in line for line in rendered)
          and report["seed"]["recipe_proof"]["artifacts_ok"]
          and report["seed"]["installed_canonical"]["artifacts_ok"])
    check("pilot coverage behavior is absent from provisioning",
          not any("BEHAT_ALLOW_XDEBUG" in line or "xdebug.mode=coverage" in line
                  or "CoverageHook" in line for line in rendered))

    from ..core import boundary as boundary_module
    from ..bench import dbadmin as dbadmin_module
    from ..bench import repo as repo_module
    from ..bench import seed as seed_module

    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        os.makedirs(layout.build_source)
        os.makedirs(layout.seed)
        recipe = {"seed_key": "recipe-key", "source_key_now": "recipe-key",
                  "artifacts_ok": True, "stale": False}
        canonical = {"seed_key": "canonical-key",
                     "source_key_now": "canonical-key",
                     "artifacts_ok": True, "stale": False}
        actions = []

        def verify(seed_dir, source_root):
            canonical_seed = seed_dir == layout.seed
            actions.append(("verify", canonical_seed, source_root))
            return canonical if canonical_seed else recipe

        def unpack(seed_dir, destination, force=False):
            actions.append(("unpack", seed_dir == layout.seed,
                            destination, force))

        mysql = mock.MagicMock()
        with mock.patch.object(boundary_module, "load_boundary",
                               return_value=object()), \
                mock.patch.object(repo_module, "strip_repo",
                                  return_value=mock.Mock()), \
                mock.patch.object(repo_module, "baseline_substrate"), \
                mock.patch.object(dbadmin_module, "MySQL",
                                  return_value=mysql), \
                mock.patch.object(seed_module, "build_seed",
                                  return_value=recipe), \
                mock.patch.object(seed_module, "unpack_workspace",
                                  unpack), \
                mock.patch.object(seed_module, "verify_seed",
                                  verify), \
                mock.patch.object(__import__(__name__, fromlist=["x"]),
                                  "_checked"), \
                mock.patch.object(__import__(__name__, fromlist=["x"]),
                                  "_exec_php"):
            seed_report = _build_seed(layout)

        check("the clean recipe proof is followed by a forced canonical "
              "workspace install and verification",
              actions == [("verify", False, layout.source),
                          ("unpack", True, layout.source, True),
                          ("verify", True, layout.source)]
              and seed_report == {"recipe_proof": recipe,
                                  "installed_canonical": canonical})

    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        os.makedirs(layout.gold)
        os.makedirs(layout.seed)
        os.makedirs(layout.source)
        called = []
        with mock.patch.object(__import__(__name__, fromlist=["x"]), "_run",
                               side_effect=lambda *a, **k: called.append(a)):
            try:
                provision(root)
                refusal = ""
            except ProvisionRefused as exc:
                refusal = str(exc)
        check("an existing source refuses before any subprocess",
              "destination already exists" in refusal and not called,
              refusal)

    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        os.makedirs(layout.gold)
        os.makedirs(layout.seed)
        occupied = []

        def occupied_run(argv, **kwargs):
            occupied.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, "{}", "")

        with mock.patch.object(__import__(__name__, fromlist=["x"]), "_run",
                               side_effect=occupied_run):
            try:
                provision(root)
                refusal = ""
            except ProvisionRefused as exc:
                refusal = str(exc)
        check("an occupied fixed Docker name refuses before mutation",
              "already exists" in refusal and len(occupied) == 1
              and occupied[0][:3] == ["docker", "container", "inspect"],
              refusal)

    with tempfile.TemporaryDirectory() as root:
        try:
            provision(root)
            refusal = ""
        except ProvisionRefused as exc:
            refusal = str(exc)
        check("provisioning requires the fetched canonical gold and seed "
              "before any subprocess",
              "Fetch the CoreShop bundle" in refusal, refusal)

    print("\n" + ("ALL PASS (provision_coreshop)" if ok
                   else "FAILURES (provision_coreshop)"))
    return 0 if ok else 1
