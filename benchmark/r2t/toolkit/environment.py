"""Offline descriptors for the projects whose environments R2T can bring up.

The dataset manifest already owns bundle versions, artifact locations,
frameworks, harness images and worker-plan shapes.  This module reads those
facts instead of copying them into the environment table.  ``PROJECTS`` holds
only the bring-up facts that the manifest does not describe.

``PROJECTS`` therefore covers exactly the descriptor-driven projects, and
algorand-sdk is intentionally absent: its bring-up is bundle-and-image driven
rather than Dockerfile-and-descriptor driven, and it lives in
``runbooks/RUNBOOK_ALGORAND.md``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlsplit

from ..data import bundle as B
from .provision_coreshop import (DOCKER_DIR as CORESHOP_DOCKER_DIR,
                                 MYSQL_CONTAINER, MYSQL_IMAGE,
                                 ProvisionRefused, TEMPLATE_COMMAND,
                                 runtime_env)
from .provision_sylius import (DOCKER_DIR as SYLIUS_DOCKER_DIR,
                               MYSQL_IMAGE as SYLIUS_MYSQL_IMAGE,
                               TEMPLATE_COMMAND as SYLIUS_TEMPLATE_COMMAND,
                               runtime_env as sylius_runtime_env)


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)


@dataclass(frozen=True)
class Database:
    image: str       # digest-pinned
    alias: str       # the host worker.write_env_file bakes into the DSN
    root_password: str


@dataclass(frozen=True)
class Bringup:
    dockerfile_dir: str
    database: Optional[Database]
    template_command: Optional[tuple[str, ...]]
    template_env: Optional[Callable[[str], dict]]
    composer_cache: bool
    gold_control_item: str


# python-docx comes first deliberately: it is the cheapest environment and
# its lack of a database is the branch that prevents this descriptor from
# becoming a CoreShop recipe with optional flags bolted on.
PROJECTS: dict[str, Bringup] = {
    "python-docx": Bringup(
        dockerfile_dir=os.path.join(BENCHMARK, "docker", "python_docx"),
        database=None,
        template_command=None,
        template_env=None,
        composer_cache=False,
        gold_control_item="python-docx/features/api-open-document.feature:13",
    ),
    "coreshop": Bringup(
        dockerfile_dir=CORESHOP_DOCKER_DIR,
        database=Database(
            image=MYSQL_IMAGE,
            alias=MYSQL_CONTAINER,
            root_password="root",
        ),
        template_command=TEMPLATE_COMMAND,
        template_env=runtime_env,
        composer_cache=True,
        gold_control_item=(
            "coreshop/features/domain/cart/"
            "cart_base_item_taxes.feature:56"),
    ),
    "sylius": Bringup(
        dockerfile_dir=SYLIUS_DOCKER_DIR,
        database=Database(
            # Byte-identical to CoreShop's pin (MySQL 8.4.10), declared by
            # the Sylius provisioner so that provisioner stays the authority
            # for its own environment.
            image=SYLIUS_MYSQL_IMAGE,
            # THE SHARED ALIAS, and it is `provision_coreshop`'s constant on
            # purpose.  `environment_lifecycle._descriptor` refuses any alias
            # but `worker.DEFAULT_DB_CONTAINER`, and `worker.write_env_file`
            # bakes that host into every worker's DSN, so a second alias would
            # need a second worker administration surface.  The pool database
            # is published under this network alias; the per-worker
            # `DATABASE_URL` that replaces the template's names it, which is
            # why no Sylius analogue of CoreShop's template-DSN check belongs
            # below: `provision_sylius.runtime_env` builds its DSN from that
            # provisioner's own `sylius_db`, the template container runs on
            # `--network none` and never reaches a database, and
            # `worker.write_env_file` replaces the host per worker.
            alias=MYSQL_CONTAINER,
            root_password="root",
        ),
        template_command=SYLIUS_TEMPLATE_COMMAND,
        template_env=sylius_runtime_env,
        composer_cache=True,
        gold_control_item=(
            "sylius/features/admin/currency/managing_currencies/"
            "browsing_currencies.feature:12"),
    ),
    "coddy-agent": Bringup(
        dockerfile_dir=os.path.join(BENCHMARK, "docker", "coddy_agent"),
        database=None,
        template_command=None,
        template_env=None,
        composer_cache=False,
        gold_control_item="coddy-agent/features/hooks_subagents.feature:18",
    ),
}


def bringup(project: str) -> Bringup:
    """Return the repository-owned bring-up facts for ``project``."""
    return PROJECTS[project]


def _manifest_block(project: str, manifest_path: str) -> dict:
    """Resolve one block through the bundle module's existing authority."""
    document = B._read_json(manifest_path, "dataset manifest")
    block = (document.get("projects") or {}).get(project)
    if not isinstance(block, dict) or not isinstance(block.get("bundle"),
                                                      dict):
        B._refuse(f"dataset manifest has no bundle for project {project!r}")
    version = block["bundle"].get("version")
    _document, authoritative = B._authority(
        project, version, manifest_path=manifest_path)
    return authoritative


def manifest_facts(project: str, *,
                   manifest_path: str = B.DATASET_MANIFEST) -> dict:
    """Derive the manifest-owned part of one environment descriptor."""
    block = _manifest_block(project, manifest_path)
    return {
        "version": block["bundle"]["version"],
        "framework": block["framework"],
        "harness_image": block["harness_image"],
        "worker_plan": dict(block["bundle"]["worker_plan"]),
    }


def artifact_paths(project: str, root: str, *,
                   manifest_path: str = B.DATASET_MANIFEST
                   ) -> dict[str, Optional[str]]:
    """Resolve every manifest artifact role below an installed bundle root."""
    block = _manifest_block(project, manifest_path)
    return {
        role: B._artifact_path(root, block, role)
        for role in block["bundle"]["artifacts"]
    }


def selftest() -> int:
    import json

    failures = []

    def check(name, condition, detail=""):
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        if not condition:
            failures.append(name)

    with open(B.DATASET_MANIFEST, encoding="utf-8") as handle:
        manifest = json.load(handle)
    bundled = {name for name, project in manifest["projects"].items()
               if project.get("bundle") is not None}
    check("the environment table covers exactly the shipped project bundles",
          set(PROJECTS) == bundled,
          str({"descriptors": sorted(PROJECTS),
               "manifest": sorted(bundled)}))

    fixture_root = "/fixture/r2t-data"
    for project in PROJECTS:
        block = manifest["projects"][project]
        expected_facts = {
            "version": block["bundle"]["version"],
            "framework": block["framework"],
            "harness_image": block["harness_image"],
            "worker_plan": block["bundle"]["worker_plan"],
        }
        facts = manifest_facts(project)
        check(f"{project} manifest-owned environment facts are derived",
              facts == expected_facts, str(facts))

        expected_paths = {
            role: (None if relative is None else
                   os.path.join(fixture_root, *relative.split("/")))
            for role, relative in block["bundle"]["artifacts"].items()
        }
        paths = artifact_paths(project, fixture_root)
        check(f"{project} artifact paths are the manifest roles",
              paths == expected_paths, str(paths))

        dockerfile = os.path.join(PROJECTS[project].dockerfile_dir,
                                  "Dockerfile")
        check(f"{project} descriptor names a shipped Dockerfile",
              os.path.isfile(dockerfile), dockerfile)

        # DOCKER_EXECUTION_AUTHORITY makes this descriptor authoritative for
        # WHICH directory `up` builds from, because the directory name is not
        # derivable from the project name (`python-docx` builds from
        # `docker/python_docx`).  What survives as a location CONTRACT is the
        # tree, so that is what is asserted: a descriptor pointing anywhere but
        # directly below `benchmark/docker/` would authorize a build from a
        # Dockerfile outside the reviewed set, and the doc would be describing
        # a boundary nothing holds.
        check(f"{project} builds from a directory directly under "
              "benchmark/docker/",
              os.path.dirname(PROJECTS[project].dockerfile_dir)
              == os.path.join(BENCHMARK, "docker"),
              PROJECTS[project].dockerfile_dir)

        items_path = os.path.join(
            os.path.dirname(B.DATASET_MANIFEST), *block["items"].split("/"))
        with open(items_path, encoding="utf-8") as handle:
            item_ids = {
                json.loads(line)["item_id"] for line in handle if line.strip()
            }
        check(f"{project} gold control names a shipped criterion item",
              PROJECTS[project].gold_control_item in item_ids,
              PROJECTS[project].gold_control_item)

    coreshop = bringup("coreshop")
    from ..bench import worker as W
    runtime = coreshop.template_env("def" + "0" * 133)
    check("CoreShop describes its database-backed environment",
          coreshop.database is not None
          and coreshop.database.image == MYSQL_IMAGE
          and coreshop.template_command == TEMPLATE_COMMAND
          and coreshop.template_env is runtime_env
          and coreshop.composer_cache)
    check("CoreShop's template DSN uses the worker's baked-in database host",
          coreshop.database is not None
          and coreshop.database.alias == W.DEFAULT_DB_CONTAINER
          and urlsplit(runtime["PIMCORE_TEST_DB_DSN"]).hostname
          == W.DEFAULT_DB_CONTAINER
          and urlsplit(runtime["PIMCORE_TEST_DB_DSN"]).password
          == coreshop.database.root_password,
          runtime["PIMCORE_TEST_DB_DSN"])
    try:
        coreshop.template_env("not-a-defuse-key")
    except ProvisionRefused:
        invalid_template_refused = True
    else:
        invalid_template_refused = False
    check("CoreShop's stack adapter validates template-command output",
          invalid_template_refused)

    docx = bringup("python-docx")
    check("python-docx describes a no-database environment",
          docx.database is None
          and docx.template_command is None
          and docx.template_env is None
          and not docx.composer_cache)

    print("\n" + ("ALL PASS (project environments)" if not failures
                   else "FAILURES (project environments)"))
    return 0 if not failures else 1
