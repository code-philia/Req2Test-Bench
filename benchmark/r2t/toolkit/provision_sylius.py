"""Build the disclosed Sylius API-arm environment beside its seed.

This is one project recipe, not a provisioning framework, for the reason
`provision_coreshop` gives: the source commit, image digests, service names
and fixed data layout ARE the environment's identity, and turning them into
flags would let two different environments both call themselves Sylius v1.

What differs from CoreShop's recipe, and why:

* the build tree is cloned from the CORPUS checkout rather than from the
  network -- the corpus is the pinned tree every extracted item was read
  from -- and its `origin` is then re-pointed upstream, so the clone records
  the same provenance a network clone would.
* the schema is created inside the DATABASE container.  The alpine MariaDB
  client refuses MySQL 8.4's self-signed TLS, and `doctrine:database:create`
  cannot run under `test_cached` at all: the console boots services that
  connect with the dbname before the schema exists.  `sylius:install` then
  migrates the empty schema.  No fixtures are loaded -- upstream's API job
  loads none, and the ORM purger empties the data per scenario.
* `index`, `index-prod` and `closures` read the Api contexts that the strip
  removes, so `--stop-after-install` stops with the installed tree and the
  setup container up, and `--resume-seed` finishes from there.
"""
from __future__ import annotations

import contextlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from unittest import mock

from ..core import docker_cli
from ..core.paths import DATA_ROOT_ENV


SOURCE_URL = "https://github.com/Sylius/Sylius.git"
SOURCE_COMMIT = "70cf6ca686ec3efa4635a451bdd2b1358ab71d42"
#: MySQL 8.4.10, the server Sylius's own CI tests against; the same
#: digest-pinned image the CoreShop environment runs.
MYSQL_IMAGE = (
    "mysql:8@sha256:"
    "563602a18ffd5be220968e8508d84c9dcd80fbffe69e28af51572db29e3285b2")
IMAGE = "sylius_bench_img:repro-v1"

#: Sylius needs no generated secret -- `APP_SECRET` is committed in
#: `.env.test_cached` -- but `environment.Bringup` runs a template command in
#: the seed and feeds its last stdout line to `template_env`.  This is that
#: command, and `runtime_env` accepts nothing but its literal output, so
#: `environment up` validates the template exactly as it validates
#: CoreShop's Defuse key.
TEMPLATE_COMMAND = ("php", "-r", "echo 'sylius-v1';")
TEMPLATE_TOKEN = "sylius-v1"

NETWORK = "sylius_net"
MYSQL_CONTAINER = "sylius_db"
PHP_CONTAINER = "sylius_bench_php"
SETUP_CONTAINER = "sylius_bench_setup"
#: `sylius_%kernel.environment%` under `APP_ENV=test_cached`.
SCHEMA = "sylius_test_cached"
APP_ENV = "test_cached"

#: The six `sync://` transports `.env.test_cached` declares, restated as
#: real environment variables.  `worker provision --template-container`
#: bakes the TEMPLATE'S ENVIRONMENT into every worker, so what the arm runs
#: with is stated here rather than left to whichever dotenv file a stripped
#: workspace kept; Symfony's Dotenv does not overwrite a variable that is
#: already set, so the two agree.
MESSENGER_TRANSPORTS = (
    "SYLIUS_MESSENGER_TRANSPORT_MAIN_DSN",
    "SYLIUS_MESSENGER_TRANSPORT_MAIN_FAILED_DSN",
    "SYLIUS_MESSENGER_TRANSPORT_CATALOG_PROMOTION_REMOVAL_DSN",
    "SYLIUS_MESSENGER_TRANSPORT_CATALOG_PROMOTION_REMOVAL_FAILED_DSN",
    "SYLIUS_MESSENGER_TRANSPORT_PAYMENT_REQUEST_DSN",
    "SYLIUS_MESSENGER_TRANSPORT_PAYMENT_REQUEST_FAILED_DSN",
)

#: The webpack manifests the API arm needs and no Node writes.  Upstream's
#: API job stubs exactly these four with `{}`; `webpack_encore.strict_mode`
#: is false under `test_cached`, so an empty manifest is enough and a Node
#: toolchain is not part of this image.
STUB_MANIFESTS = ("public/build/admin/manifest.json",
                  "public/build/shop/manifest.json",
                  "public/build/app/admin/manifest.json",
                  "public/build/app/shop/manifest.json")

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)
DOCKER_DIR = os.path.join(BENCHMARK, "docker", "sylius")
DOCKERFILE = os.path.join(DOCKER_DIR, "Dockerfile")
COMPOSER_LOCK = os.path.join(DOCKER_DIR, "composer.lock")
BOUNDARY = os.path.join(BENCHMARK, "config", "boundary_sylius.yml")
PHP_HARNESS = os.path.join(HERE, "php")


class ProvisionRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class Layout:
    data_root: str
    source: str
    build: str
    gold: str
    seed: str
    composer_cache: str

    @classmethod
    def under(cls, root: str) -> "Layout":
        root = os.path.abspath(root)
        project = os.path.join(root, "projects", "sylius")
        return cls(root,
                   os.path.join(project, "source"),
                   os.path.join(project, "build"),
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


def _docker(argv: list[str], *, check: bool = True,
            capture_output: bool = False, env: dict | None = None,
            timeout: int = 3600) -> subprocess.CompletedProcess:
    """Run one Docker command through the configured execution authority.

    A bare `docker ...` argv reaches whatever daemon the ambient environment
    points at -- on the benchmark hosts the ROOTFUL one -- while the worker
    pool this environment is provisioned for lives on the daemon named by
    `--docker-authority`.  `docker_cli.docker_command` is the only route to
    that daemon: it revalidates the authority artifact, binds the exact
    client and endpoint, and refuses an ambient `DOCKER_HOST`.  Without an
    authority this recipe has no daemon to build on, so it refuses rather
    than building the image, the database and the containers somewhere the
    pool will never see them.
    """
    if docker_cli.configured_authority_path() is None:
        raise ProvisionRefused(
            "REFUSED: provision-sylius is a live Docker workload; name the "
            "verified authority artifact with --docker-authority. No Docker "
            "command was run.")
    composed = docker_cli.docker_command(argv, environ=env)
    run = _checked if check else _run
    return run(composed, capture_output=capture_output, env=env,
               timeout=timeout)


def _require_absent(kind: str, name: str) -> None:
    cp = _docker([kind, "inspect", name], check=False, capture_output=True,
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


def _require_present(kind: str, name: str) -> None:
    cp = _docker([kind, "inspect", name], check=False, capture_output=True,
                 timeout=60)
    if cp.returncode != 0:
        raise ProvisionRefused(
            f"REFUSED: Docker {kind} {name!r} is gone. --resume-seed strips "
            "the build tree and dumps the database, so it needs the "
            "environment --stop-after-install left running; recreate it (or "
            "provision from scratch into an empty root) before retrying.")


def _preflight(layout: Layout, *, resume: bool) -> None:
    """The path questions first: an occupied tree refuses before any run."""
    for label, path in (("gold", layout.gold), ("seed", layout.seed)):
        if os.path.lexists(path):
            raise ProvisionRefused(
                f"REFUSED: Sylius {label} destination already exists: "
                f"{path}. Provisioning never merges with or overwrites an "
                "existing benchmark tree.")
    if resume:
        if not os.path.isdir(layout.build):
            raise ProvisionRefused(
                f"REFUSED: --resume-seed needs the installed build tree at "
                f"{layout.build}, which is absent. Run provision-sylius "
                "--stop-after-install first.")
    elif os.path.lexists(layout.build):
        raise ProvisionRefused(
            f"REFUSED: Sylius build destination already exists: "
            f"{layout.build}. Provisioning never merges with or overwrites "
            "an existing benchmark tree.")
    if not os.path.isdir(layout.source):
        raise ProvisionRefused(
            f"REFUSED: the Sylius corpus checkout is missing: "
            f"{layout.source}. The provisioner clones its build tree from "
            "the corpus and never writes into it.")
    head = _checked(["git", "-C", layout.source, "rev-parse", "HEAD"],
                    capture_output=True, timeout=60).stdout.strip()
    origin = _checked(["git", "-C", layout.source, "config", "--get",
                       "remote.origin.url"],
                      capture_output=True, timeout=60).stdout.strip()
    if head != SOURCE_COMMIT or origin != SOURCE_URL:
        raise ProvisionRefused(
            f"REFUSED: {layout.source} is at {head or 'no commit'} of "
            f"{origin or 'no origin'}; this recipe is the environment for "
            f"{SOURCE_COMMIT} of {SOURCE_URL}.")
    if resume:
        _require_absent("container", PHP_CONTAINER)
        # The two stages are separated by the operator's index run, and the
        # setup container is `--rm`: a daemon restart in that window takes
        # it away.  The strip is the first thing --resume-seed does and it
        # MOVES the Api contexts into gold, so a container that is missing
        # has to be found here, before that, or the retry meets its own
        # half-finished gold tree.
        for kind, name in (("container", SETUP_CONTAINER),
                           ("container", MYSQL_CONTAINER),
                           ("network", NETWORK)):
            _require_present(kind, name)
        return
    for name in (SETUP_CONTAINER, PHP_CONTAINER, MYSQL_CONTAINER):
        _require_absent("container", name)
    _require_absent("network", NETWORK)


def _clone_source(layout: Layout) -> None:
    """Clone the corpus checkout, then say upstream where it came from.

    A clone rather than `git archive`: Sylius export-ignores `config/`,
    `bin/`, `public/` and the dotenv files, so a Composer install into an
    exported tree lets Flex re-apply every recipe and produces a different
    application.

    `--no-hardlinks` because the source is a LOCAL path, and a local clone
    hard-links `.git/objects/pack/*` into the new tree instead of copying
    it.  `sanitise_repo` then moves `.git` into `gold/_git`, and those pack
    files reach the pool as answer-bearing input with a link count above
    one -- which `worker.preflight` refuses ("contains regular file(s) with
    hard-link aliases"), because a file that is also reachable outside the
    input is not pinned by it.
    """
    os.makedirs(os.path.dirname(layout.build), exist_ok=True)
    _checked(["git", "clone", "--no-checkout", "--no-hardlinks",
              layout.source, layout.build])
    _checked(["git", "-C", layout.build, "remote", "set-url", "origin",
              SOURCE_URL])
    _checked(["git", "-C", layout.build, "checkout", "--detach",
              SOURCE_COMMIT])
    shutil.copyfile(COMPOSER_LOCK,
                    os.path.join(layout.build, "composer.lock"))


def _wait_for_mysql() -> None:
    deadline = time.monotonic() + 180
    while True:
        cp = _docker(
            ["container", "inspect", "--format",
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


def _setup_argv(layout: Layout, command: list[str]) -> list[str]:
    return [
        "run", "--rm", "--name", SETUP_CONTAINER,
        "--network", NETWORK,
        "--volume", f"{layout.build}:/var/www/html",
        "--volume", f"{layout.composer_cache}:/composer-cache",
        "--env", "COMPOSER_CACHE_DIR=/composer-cache",
        IMAGE, *command,
    ]


def _install_dependencies(layout: Layout) -> None:
    """Install the accepted lock.  `--no-scripts` because the recipe's
    claim is that this tree is the corpus commit plus this lock, and with
    the scripts (Flex recipes, asset install) `git status` does not come
    back clean."""
    _docker(_setup_argv(layout, [
        "composer", "install", "--prefer-dist", "--optimize-autoloader",
        "--no-interaction", "--no-progress", "--no-scripts",
    ]))


def runtime_env(token: str) -> dict[str, str]:
    if token != TEMPLATE_TOKEN:
        raise ProvisionRefused(
            "REFUSED: Sylius template input is not this environment's "
            f"token ({token!r}).")
    values = {
        "COMPOSER_CACHE_DIR": "/composer-cache",
        "APP_ENV": APP_ENV,
        "APP_DEBUG": "0",
        # The host is this environment's own DB container.  NOTE for the
        # branch that adds Sylius's `environment.Bringup` descriptor:
        # `environment up` publishes the database under
        # `descriptor.database.alias` and `environment_lifecycle._descriptor`
        # today refuses any alias but `worker.DEFAULT_DB_CONTAINER`
        # ("coreshop_db"), so that branch has to either widen the alias or
        # rewrite this host per worker (design section 2 row 7).
        "DATABASE_URL": f"mysql://root:root@{MYSQL_CONTAINER}:3306/{SCHEMA}"
                        "?charset=utf8mb4",
        "XDEBUG_MODE": "off",
        "MAILER_DSN": "null://null",
    }
    values.update({name: "sync://" for name in MESSENGER_TRANSPORTS})
    return values


def _runtime_args(runtime: dict[str, str]) -> tuple[list[str], dict]:
    """Pass every runtime variable BY NAME, with the value inherited."""
    child_env = dict(os.environ)
    child_env.update(runtime)
    return ([part for name in sorted(runtime) for part in ("--env", name)],
            child_env)


def _exec_php(container: str, command: list[str]) -> None:
    _docker(["exec", "--env", "XDEBUG_MODE=off", container, *command])


def _write_stub_manifests(layout: Layout) -> None:
    for rel in STUB_MANIFESTS:
        path = os.path.join(layout.build, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{}\n")


def _create_schema() -> None:
    """Create the empty schema from inside the database container.

    Not from the PHP image, which for this reason carries no MySQL client
    at all: the alpine MariaDB client refuses MySQL 8.4's self-signed TLS.
    Not `doctrine:database:create` either: under `test_cached` the console
    boots services that connect with the dbname, which does not yet exist.
    """
    from ..bench.dbadmin import MySQL

    with MySQL(container=MYSQL_CONTAINER, password="root") as db:
        db.create_schema(SCHEMA)


def _install(layout: Layout) -> dict[str, str]:
    """Everything up to an installed application: image, database, vendor,
    schema, `sylius:install`.  Returns the runtime environment."""
    _clone_source(layout)
    os.makedirs(layout.composer_cache, exist_ok=True)
    _docker(["build", "--tag", IMAGE, "--file", DOCKERFILE, DOCKER_DIR])
    # The build is an image mutation AND BuildKit writes its state into the
    # isolated client configuration, which every later command requires
    # empty.  End the phase, exactly as `environment_lifecycle._build_image`
    # does, so the next Docker boundary gets a fresh empty configuration and
    # repeats the live authority proof.
    docker_cli.reset_phase()
    # Composer needs the ordinary bridge network to fetch the locked
    # packages; MySQL is started first so every later install command sees
    # the final service topology.
    _docker(["network", "create", NETWORK], timeout=60)
    mysql_env = dict(os.environ)
    mysql_env["MYSQL_ROOT_PASSWORD"] = "root"
    _docker([
        "run", "--detach", "--name", MYSQL_CONTAINER,
        "--network", NETWORK,
        "--health-cmd", "mysqladmin ping -h 127.0.0.1 --silent",
        "--health-interval", "2s", "--health-timeout", "2s",
        "--health-retries", "90", "--env", "MYSQL_ROOT_PASSWORD",
        MYSQL_IMAGE,
    ], env=mysql_env)
    _wait_for_mysql()
    # End of the direct-resource phase (network, database container), as
    # `environment_lifecycle` ends `_create_database_resources`.
    docker_cli.reset_phase()
    _install_dependencies(layout)

    runtime = runtime_env(TEMPLATE_TOKEN)
    env_args, child_env = _runtime_args(runtime)
    _docker([
        "run", "--detach", "--rm", "--name", SETUP_CONTAINER,
        "--network", NETWORK,
        "--volume", f"{layout.build}:/var/www/html",
        "--volume", f"{layout.composer_cache}:/composer-cache",
        *env_args, IMAGE,
    ], env=child_env)
    _write_stub_manifests(layout)
    _create_schema()
    # `sylius:install` prints a requirements table first and flags
    # `logs ERROR!` when `var/log` is not there yet; it then runs everything
    # it was going to run and STILL exits 1, with "Sylius has been
    # installed, but some error occurred".  Upstream's own API job creates
    # the directory before installing ("Fix permissions for Symfony logs
    # directory"), which is what this is -- run in the container that owns
    # the bind mount, so the entries it makes are the same root-owned ones
    # `_build_seed` already clears from inside.
    _exec_php(SETUP_CONTAINER, ["mkdir", "-p", "var/log", "var/cache"])
    # On the EMPTY existing schema this runs the migrations, the
    # non-interactive setup (default channel, currency, locale, admin) and
    # `assets:install`.  `sylius:fixtures:load` is deliberately not run.
    _exec_php(SETUP_CONTAINER,
              ["bin/console", "sylius:install", "--no-interaction"])
    _exec_php(SETUP_CONTAINER,
              ["bin/console", "cache:clear", f"--env={APP_ENV}"])
    # End of the install phase: the application is installed and the setup
    # container is up.
    docker_cli.reset_phase()
    return runtime


def _build_seed(layout: Layout) -> dict:
    from ..core.boundary import load_boundary
    from ..bench.dbadmin import MySQL
    from ..bench.repo import baseline_substrate, strip_repo
    from ..bench.seed import build_seed, rules_for, verify_seed

    # `sylius:install` and `cache:clear` wrote root-owned entries under
    # `var/` on the bind mount.  The strip clears both directories from the
    # HOST with `ignore_errors=True`, which on those entries neither removes
    # them nor reports that it failed to; clearing them inside their owning
    # container is what makes that manifest line true.
    _docker(["exec", SETUP_CONTAINER, "rm", "-rf",
             "/var/www/html/var/cache", "/var/www/html/var/log"])

    boundary = load_boundary(BOUNDARY, repo_root=layout.build)
    manifest = strip_repo(boundary, layout.gold, PHP_HARNESS)
    # The stripped tree's autoload map still names the removed Api context
    # classes until it is rebuilt.
    _exec_php(SETUP_CONTAINER, ["composer", "dump-autoload", "--optimize",
                                "--no-interaction"])
    _docker(["container", "rm", "--force", SETUP_CONTAINER], timeout=60)
    # End of the strip phase: the setup container that owned the build tree
    # is gone, and the seed's own database work is the next boundary.
    docker_cli.reset_phase()
    baseline_substrate(manifest, boundary,
                       os.path.join(layout.gold, "strip_manifest.json"))
    # The per-project row, not the framework default: `DEFAULT_RULES`
    # prunes `versions` and `messenger_messages`, and Sylius's schema has
    # neither, so the dump came back
    # `mysqldump: Couldn't find table: "versions"` and the seed was never
    # written.
    rules = rules_for("behat", "sylius")
    with MySQL(container=MYSQL_CONTAINER, password="root") as db:
        build_seed(layout.build, boundary, layout.seed, SCHEMA, db,
                   manifest=manifest, rules=rules)
    verification = verify_seed(layout.seed, layout.build)
    if not verification["artifacts_ok"] or verification["stale"]:
        raise ProvisionRefused(
            "REFUSED: the Sylius seed failed its existing verification: "
            f"{json.dumps(verification, sort_keys=True)}")
    return verification


def _provision(layout: Layout, *, stop_after_install: bool,
               resume_seed: bool) -> dict:
    _preflight(layout, resume=resume_seed)
    source = {"url": SOURCE_URL, "commit": SOURCE_COMMIT,
              "path": layout.source}
    if resume_seed:
        runtime = runtime_env(TEMPLATE_TOKEN)
    else:
        runtime = _install(layout)
        if stop_after_install:
            return {
                "source": source,
                "build": layout.build,
                "image": IMAGE,
                "mysql_image": MYSQL_IMAGE,
                "database_container": MYSQL_CONTAINER,
                "setup_container": SETUP_CONTAINER,
                "stopped_after": "install",
                "next": "run index/index-prod/closures against "
                        f"{SETUP_CONTAINER}, then provision-sylius "
                        "--resume-seed",
            }

    seed = _build_seed(layout)
    env_args, child_env = _runtime_args(runtime)
    _docker([
        "run", "--detach", "--name", PHP_CONTAINER,
        "--network", NETWORK,
        "--volume", f"{layout.build}:/var/www/html",
        "--volume", f"{layout.composer_cache}:/composer-cache",
        *env_args, IMAGE,
    ], env=child_env)
    return {
        "source": source,
        "build": layout.build,
        "gold": layout.gold,
        "image": IMAGE,
        "mysql_image": MYSQL_IMAGE,
        "template_container": PHP_CONTAINER,
        "database_container": MYSQL_CONTAINER,
        "seed": seed,
    }


def provision(data_root: str, *, stop_after_install: bool = False,
              resume_seed: bool = False) -> dict:
    """Provision below one explicit root, including lazy config defaults."""
    layout = Layout.under(data_root)
    saved = os.environ.get(DATA_ROOT_ENV)
    os.environ[DATA_ROOT_ENV] = layout.data_root
    try:
        return _provision(layout, stop_after_install=stop_after_install,
                          resume_seed=resume_seed)
    finally:
        if saved is None:
            os.environ.pop(DATA_ROOT_ENV, None)
        else:
            os.environ[DATA_ROOT_ENV] = saved


# ------------------------------------------------------------------ selftest
class _FakeMySQL:
    """The admin route, recorded: which container, and which schema."""

    opened: list = []
    created: list = []

    def __init__(self, **kwargs):
        _FakeMySQL.opened.append(kwargs)

    def __enter__(self) -> "_FakeMySQL":
        return self

    def __exit__(self, *exc) -> None:
        return None

    def create_schema(self, name: str) -> None:
        _FakeMySQL.created.append(name)


#: The seam composes every Docker argv through `docker_cli.docker_command`,
#: which prefixes the exact client, an isolated config and the authority's
#: endpoint.  The selftest stands in a fixed prefix of that shape: the argv
#: the fake `_run` records are then the real ones minus the authority, so a
#: command that went back to bare `docker` is visible rather than identical.
_FAKE_AUTHORITY = "/fake/docker-authority.json"
_COMPOSED_PREFIX = ["docker", "--config", "/fake/client-config",
                    "--host", "unix:///fake/rootless/docker.sock"]
#: Recorded in the same order as the commands, so a phase boundary can be
#: asserted to fall where the mutation is.
_RESET_MARKER = "<phase-reset>"


def _fake_docker_command(argv, **kwargs) -> list[str]:
    return [*_COMPOSED_PREFIX, *list(argv)]


def _sub_argv(argv: list[str]) -> list[str]:
    """The `docker <sub-command>` an authority-composed argv carries."""
    width = len(_COMPOSED_PREFIX)
    return ["docker", *argv[width:]] if argv[:width] == _COMPOSED_PREFIX \
        else argv


@contextlib.contextmanager
def _fake_authority(events: list):
    """Configure the seam's authority without a daemon, recording resets."""
    with mock.patch.object(docker_cli, "configured_authority_path",
                           return_value=_FAKE_AUTHORITY), \
            mock.patch.object(docker_cli, "docker_command",
                              side_effect=_fake_docker_command), \
            mock.patch.object(docker_cli, "reset_phase",
                              side_effect=lambda: events.append(
                                  ([_RESET_MARKER], {}))):
        yield


def _fake_run(events: list, present: tuple = ()):
    def run(argv, **kwargs):
        argv = list(argv)
        events.append((argv, kwargs))
        argv = _sub_argv(argv)
        if argv[:3] == ["docker", "container", "inspect"]:
            if "--format" in argv:
                return subprocess.CompletedProcess(argv, 0, "healthy\n", "")
            if argv[-1] in present:
                return subprocess.CompletedProcess(argv, 0, "[{}]", "")
            return subprocess.CompletedProcess(argv, 1, "", "No such object")
        if argv[:3] == ["docker", "network", "inspect"]:
            if argv[-1] in present:
                return subprocess.CompletedProcess(argv, 0, "[{}]", "")
            return subprocess.CompletedProcess(argv, 1, "", "not found")
        if argv[:2] == ["git", "-C"] and argv[3:] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, SOURCE_COMMIT + "\n",
                                               "")
        if argv[3:] == ["config", "--get", "remote.origin.url"]:
            return subprocess.CompletedProcess(argv, 0, SOURCE_URL + "\n", "")
        if argv[:3] == ["git", "clone", "--no-checkout"]:
            os.makedirs(argv[-1])
        return subprocess.CompletedProcess(argv, 0, "", "")
    return run


def selftest() -> int:
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        ok = ok and bool(condition)
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))

    module = __import__(__name__, fromlist=["x"])

    with open(DOCKERFILE, encoding="utf-8") as fh:
        dockerfile = fh.read()
    check("the PHP base is digest-pinned",
          "FROM ghcr.io/sylius/sylius-php:8.3-fixuid-xdebug-alpine@sha256:"
          in dockerfile)
    check("the image carries no MySQL client, because the schema work goes "
          "through the database container",
          "mysql-client" not in dockerfile
          and "apk add --no-cache git" in dockerfile)
    check("MySQL is digest-pinned", MYSQL_IMAGE.startswith("mysql:8@sha256:"))

    with open(COMPOSER_LOCK, encoding="utf-8") as fh:
        lock = json.load(fh)
    locked = {package["name"]: package["version"]
              for section in ("packages", "packages-dev")
              for package in lock[section]}
    check("the accepted lock pins the Behat 4 stack the suites are written "
          "against",
          locked.get("behat/behat") == "v4.0.0-alpha1"
          and "friends-of-behat/symfony-extension" in locked
          and "friends-of-behat/variadic-extension" in locked
          and "sylius-labs/suite-tags-extension" in locked,
          str({name: locked.get(name) for name in (
              "behat/behat", "friends-of-behat/symfony-extension")}))

    events: list = []
    bound_roots: list = []

    def fake_build_seed(layout):
        bound_roots.append(os.environ.get(DATA_ROOT_ENV))
        return {"seed_key": "sylius-fixture",
                "source_key_now": "sylius-fixture",
                "artifacts_ok": True, "stale": False}

    _FakeMySQL.opened, _FakeMySQL.created = [], []
    saved_data_root = os.environ.get(DATA_ROOT_ENV)
    from ..bench import dbadmin as dbadmin_module
    with tempfile.TemporaryDirectory() as root, \
            _fake_authority(events), \
            mock.patch.object(module, "_run",
                              side_effect=_fake_run(events)), \
            mock.patch.object(module, "_build_seed",
                              side_effect=fake_build_seed), \
            mock.patch.object(dbadmin_module, "MySQL", _FakeMySQL):
        layout = Layout.under(root)
        os.makedirs(layout.source)
        report = provision(root)
        stubs = {rel: open(os.path.join(layout.build, *rel.split("/")),
                           encoding="utf-8").read()
                 for rel in STUB_MANIFESTS}

    routed = [(_sub_argv(argv), kwargs) for argv, kwargs in events]
    commands = [argv for argv, _kwargs in routed]
    rendered = [shlex.join(argv) for argv in commands]
    bare = [argv for argv, _kwargs in events
            if argv[0] == "docker"
            and argv[:len(_COMPOSED_PREFIX)] != _COMPOSED_PREFIX]
    check("every Docker command is composed through the execution "
          "authority, and none is a bare `docker` argv aimed at whichever "
          "daemon the ambient environment names",
          not bare and any(argv[0] == "docker" for argv, _kw in events),
          str(bare))
    builds = [index for index, argv in enumerate(commands)
              if argv[:2] == ["docker", "build"]]
    check("the image build ends its phase, so the next Docker command gets "
          "a fresh empty client configuration after BuildKit wrote into it",
          len(builds) == 1 and commands[builds[0] + 1] == [_RESET_MARKER],
          str(commands[builds[0]:builds[0] + 2]) if builds else "no build")
    check("the build tree is a clone of the corpus checkout, re-pointed at "
          "upstream and detached at the one pinned commit, with the local "
          "clone's pack files COPIED rather than hard-linked -- an alias "
          "into the corpus checkout is what `worker.preflight` refuses in "
          "the gold tree the strip writes",
          ["git", "clone", "--no-checkout", "--no-hardlinks",
           layout.source, layout.build] in commands
          and ["git", "-C", layout.build, "remote", "set-url", "origin",
               SOURCE_URL] in commands
          and ["git", "-C", layout.build, "checkout", "--detach",
               SOURCE_COMMIT] in commands)
    check("an explicit data root binds lazy config during provisioning and "
          "is restored afterwards",
          bound_roots == [root]
          and os.environ.get(DATA_ROOT_ENV) == saved_data_root,
          str(bound_roots))
    check("the setup container and the template container both mount the "
          "build tree",
          any(f"{layout.build}:/var/www/html" in argv
              and SETUP_CONTAINER in argv for argv in commands)
          and any(f"{layout.build}:/var/www/html" in argv
                  and PHP_CONTAINER in argv for argv in commands))
    check("the image build names this environment's tag",
          any(argv[:4] == ["docker", "build", "--tag", IMAGE]
              for argv in commands))
    mysql_runs = [pair for pair in routed
                  if pair[0][:3] == ["docker", "run", "--detach"]
                  and MYSQL_IMAGE in pair[0]]
    check("the composed MySQL run uses only the digest-pinned image",
          len(mysql_runs) == 1 and mysql_runs[0][0][-1] == MYSQL_IMAGE)
    check("database credentials are inherited, not exposed in Docker argv",
          len(mysql_runs) == 1 and "root" not in mysql_runs[0][0]
          and mysql_runs[0][1]["env"]["MYSQL_ROOT_PASSWORD"] == "root")
    check("Composer installs the accepted lock, without scripts, and never "
          "updates it",
          any("composer install" in line and "--no-scripts" in line
              for line in rendered)
          and not any("composer update" in line for line in rendered))
    check("the schema is created through the database container",
          _FakeMySQL.created == [SCHEMA]
          and _FakeMySQL.opened == [{"container": MYSQL_CONTAINER,
                                     "password": "root"}],
          str(_FakeMySQL.opened))
    execs = [argv for argv in commands if argv[:2] == ["docker", "exec"]]
    check("no command runs a MySQL client inside the PHP image",
          not any(part.startswith("mysql") for argv in execs
                  for part in argv))
    check("the four webpack manifests are stubbed, as upstream's API job "
          "stubs them",
          stubs == {rel: "{}\n" for rel in STUB_MANIFESTS}, str(stubs))
    check("the installer runs on the empty schema, and no fixtures and no "
          "doctrine:database:create are ever composed",
          any("bin/console sylius:install --no-interaction" in line
              for line in rendered)
          and any(f"bin/console cache:clear --env={APP_ENV}" in line
                  for line in rendered)
          and not any("fixtures:load" in line or "database:create" in line
                      for line in rendered))

    def first_line(needle: str) -> int:
        return next((i for i, line in enumerate(rendered) if needle in line),
                    -1)

    mkdir_at = first_line("mkdir -p var/log var/cache")
    install_at = first_line("bin/console sylius:install")
    check("the Symfony log directory is made BEFORE the installer reads its "
          "requirements table -- without it `sylius:install` flags "
          "`logs ERROR!` and exits 1 having already done the work",
          0 <= mkdir_at < install_at,
          f"mkdir at {mkdir_at}, sylius:install at {install_at}")
    template_runs = [pair for pair in routed
                     if PHP_CONTAINER in pair[0] and "run" in pair[0]]
    check("the template container carries the API arm's runtime environment "
          "by name, with the values inherited",
          len(template_runs) == 1
          and "DATABASE_URL" in template_runs[0][0]
          and "mysql://root:root" not in shlex.join(template_runs[0][0])
          and template_runs[0][1]["env"]["APP_ENV"] == APP_ENV
          and template_runs[0][1]["env"]["DATABASE_URL"]
          == f"mysql://root:root@{MYSQL_CONTAINER}:3306/{SCHEMA}"
             "?charset=utf8mb4",
          str(template_runs[0][0]) if template_runs else "no run")
    check("the report names the seed verification and the fixed names",
          report["seed"]["artifacts_ok"]
          and report["template_container"] == PHP_CONTAINER
          and report["database_container"] == MYSQL_CONTAINER
          and report["source"]["commit"] == SOURCE_COMMIT)

    try:
        runtime_env("sylius-v2")
        refusal = ""
    except ProvisionRefused as exc:
        refusal = str(exc)
    check("a template output that is not this environment's token refuses",
          "not this environment's token" in refusal, refusal)

    # `--stop-after-install` and `--resume-seed`, the two halves the
    # un-stripped index needs.
    stopped_events: list = []
    _FakeMySQL.opened, _FakeMySQL.created = [], []
    with tempfile.TemporaryDirectory() as root, \
            _fake_authority(stopped_events), \
            mock.patch.object(module, "_run",
                              side_effect=_fake_run(stopped_events)), \
            mock.patch.object(module, "_build_seed",
                              side_effect=fake_build_seed), \
            mock.patch.object(dbadmin_module, "MySQL", _FakeMySQL):
        layout = Layout.under(root)
        os.makedirs(layout.source)
        stopped = provision(root, stop_after_install=True)
        stopped_rendered = [shlex.join(_sub_argv(argv))
                            for argv, _kw in stopped_events]
        stage1 = (SETUP_CONTAINER, MYSQL_CONTAINER, NETWORK)
        resumed_events: list = []
        with _fake_authority(resumed_events), \
                mock.patch.object(module, "_run",
                                  side_effect=_fake_run(resumed_events,
                                                        present=stage1)):
            resumed = provision(root, resume_seed=True)
        resumed_rendered = [shlex.join(_sub_argv(argv))
                            for argv, _kw in resumed_events]
        # The same resume, with the setup container gone the way a daemon
        # restart takes a `--rm` container away.
        torn_events: list = []
        torn_seeds: list = []
        with _fake_authority(torn_events), \
                mock.patch.object(module, "_run",
                                  side_effect=_fake_run(
                                      torn_events,
                                      present=(MYSQL_CONTAINER, NETWORK))), \
                mock.patch.object(module, "_build_seed",
                                  side_effect=lambda *a: torn_seeds.append(a)):
            try:
                provision(root, resume_seed=True)
                torn_refusal = ""
            except ProvisionRefused as exc:
                torn_refusal = str(exc)

    check("--stop-after-install leaves the installed tree and the setup "
          "container up, and builds no seed",
          stopped["stopped_after"] == "install"
          and stopped["setup_container"] == SETUP_CONTAINER
          and stopped["build"] == layout.build
          and "seed" not in stopped
          and any("sylius:install" in line for line in stopped_rendered),
          json.dumps(stopped, sort_keys=True))
    check("--resume-seed installs nothing again and starts the template "
          "container over the tree that is already there",
          not any("composer install" in line or "docker build" in line
                  or "sylius:install" in line for line in resumed_rendered)
          and resumed["seed"]["artifacts_ok"]
          and any(PHP_CONTAINER in argv for argv, _kw in resumed_events),
          str(resumed_rendered))
    check("--resume-seed refuses when the stage-1 environment it strips "
          "into is gone, before the strip moves anything",
          f"{SETUP_CONTAINER!r} is gone" in torn_refusal
          and not torn_seeds
          and not any(_sub_argv(argv)[:2] == ["docker", "run"]
                      for argv, _kw in torn_events),
          torn_refusal)

    for label, existing in (("build", "build"), ("gold", "gold"),
                            ("seed", "seed")):
        with tempfile.TemporaryDirectory() as root:
            layout = Layout.under(root)
            os.makedirs(layout.source)
            os.makedirs(getattr(layout, existing))
            called = []
            with mock.patch.object(
                    module, "_run",
                    side_effect=lambda *a, **k: called.append(a)):
                try:
                    provision(root)
                    refusal = ""
                except ProvisionRefused as exc:
                    refusal = str(exc)
            check(f"an existing {label} tree refuses before any subprocess",
                  "already exists" in refusal and not called, refusal)

    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        called = []
        with mock.patch.object(module, "_run",
                               side_effect=lambda *a, **k: called.append(a)):
            try:
                provision(root)
                refusal = ""
            except ProvisionRefused as exc:
                refusal = str(exc)
        check("a missing corpus checkout refuses before any subprocess",
              "corpus checkout is missing" in refusal and not called, refusal)

    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        os.makedirs(layout.source)
        moved = []

        def moved_source(argv, **kwargs):
            moved.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, "0" * 40 + "\n", "")

        with mock.patch.object(module, "_run", side_effect=moved_source):
            try:
                provision(root)
                refusal = ""
            except ProvisionRefused as exc:
                refusal = str(exc)
        check("a corpus checkout that is not the pinned commit refuses "
              "before Docker is touched",
              SOURCE_COMMIT in refusal
              and all(argv[0] == "git" for argv in moved), refusal)

    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        os.makedirs(layout.source)
        occupied = []

        def occupied_run(argv, **kwargs):
            occupied.append(list(argv))
            if argv[:2] == ["git", "-C"]:
                return subprocess.CompletedProcess(
                    argv, 0,
                    (SOURCE_COMMIT if argv[3] == "rev-parse" else SOURCE_URL)
                    + "\n", "")
            return subprocess.CompletedProcess(argv, 0, "{}", "")

        with _fake_authority([]), \
                mock.patch.object(module, "_run", side_effect=occupied_run):
            try:
                provision(root)
                refusal = ""
            except ProvisionRefused as exc:
                refusal = str(exc)
        occupied = [_sub_argv(argv) for argv in occupied]
        check("an occupied fixed Docker name refuses before mutation",
              "already exists" in refusal
              and occupied[-1][:3] == ["docker", "container", "inspect"]
              and not any(argv[:2] == ["docker", "run"]
                          for argv in occupied),
              refusal)

    # No authority, no daemon this recipe is entitled to build on.
    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        os.makedirs(layout.source)
        unauthorised: list = []
        with mock.patch.object(docker_cli, "configured_authority_path",
                               return_value=None), \
                mock.patch.object(module, "_run",
                                  side_effect=_fake_run(unauthorised)):
            try:
                provision(root)
                refusal = ""
            except ProvisionRefused as exc:
                refusal = str(exc)
        check("with no Docker execution authority configured, provisioning "
              "refuses at its first Docker command, having run nothing but "
              "the read-only source preflight",
              "--docker-authority" in refusal
              and "No Docker command was run" in refusal
              and all(argv[0] == "git" for argv, _kw in unauthorised),
              refusal + " " + str([argv for argv, _kw in unauthorised]))

    # `_build_seed`'s own order, over the real function with its collaborators
    # replaced: strip, rebuild the autoload map, drop the setup container,
    # baseline, seed, verify.
    from ..core import boundary as boundary_module
    from ..bench import repo as repo_module
    from ..bench import seed as seed_module

    _FakeMySQL.opened, _FakeMySQL.created = [], []
    with tempfile.TemporaryDirectory() as root:
        layout = Layout.under(root)
        actions: list = []
        seeded: dict = {}
        verification = {"seed_key": "k", "source_key_now": "k",
                        "artifacts_ok": True, "stale": False}

        def build(root_, boundary_, out_dir, schema, db, manifest=None,
                  rules=None, **kwargs):
            actions.append("build_seed")
            seeded.update(root=root_, out_dir=out_dir, schema=schema,
                          rules=rules, db=db)
            return {}

        with mock.patch.object(boundary_module, "load_boundary",
                               return_value=object()), \
                mock.patch.object(repo_module, "strip_repo",
                                  side_effect=lambda *a, **k: (
                                      actions.append("strip_repo")
                                      or mock.Mock())), \
                mock.patch.object(repo_module, "baseline_substrate",
                                  side_effect=lambda *a, **k: actions.append(
                                      "baseline_substrate")), \
                mock.patch.object(dbadmin_module, "MySQL", _FakeMySQL), \
                mock.patch.object(seed_module, "build_seed", build), \
                mock.patch.object(seed_module, "verify_seed",
                                  side_effect=lambda *a, **k: (
                                      actions.append("verify_seed")
                                      or verification)), \
                mock.patch.object(module, "_docker",
                                  side_effect=lambda argv, **k: actions.append(
                                      "docker " + shlex.join(argv))), \
                mock.patch.object(module, "_exec_php",
                                  side_effect=lambda c, cmd: actions.append(
                                      " ".join(cmd))):
            report = _build_seed(layout)

        check("the seed is built from the stripped build tree, under "
              "SYLIUS's own rules and not the framework default -- whose "
              "prune tables `versions` and `messenger_messages` this schema "
              "does not have, so the dump refused and no seed was written "
              "-- after the container-owned cache is purged, the autoload "
              "map is rebuilt and the setup container is gone",
              actions == [f"docker exec {SETUP_CONTAINER} rm -rf "
                          "/var/www/html/var/cache /var/www/html/var/log",
                          "strip_repo",
                          "composer dump-autoload --optimize --no-interaction",
                          f"docker container rm --force {SETUP_CONTAINER}",
                          "baseline_substrate", "build_seed",
                          "verify_seed"]
              and seeded["root"] == layout.build
              and seeded["out_dir"] == layout.seed
              and seeded["schema"] == SCHEMA
              and seeded["rules"] is seed_module.rules_for("behat", "sylius")
              and seeded["rules"].prune_tables == ()
              and isinstance(seeded["db"], _FakeMySQL)
              and _FakeMySQL.opened == [{"container": MYSQL_CONTAINER,
                                         "password": "root"}]
              and report == verification,
              str(actions))

    print("\n" + ("ALL PASS (provision_sylius)" if ok
                   else "FAILURES (provision_sylius)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
