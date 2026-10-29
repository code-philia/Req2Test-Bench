"""Preflight a reference-host benchmark installation without changing it."""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from importlib import metadata
from typing import Optional

from ..data import bundle as B


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)
COORDINATOR_REQUIREMENTS = os.path.join(
    BENCHMARK, "requirements-coordinator.txt")
REFERENCE = {
    "os": "Ubuntu 22.04",
    "machine": "x86_64",
    "coordinator_python": "3.10.12",
    "docker": "29.1.4",
    "bubblewrap": "0.6.1",
    "agent_python": "3.12.13",
}


def _manifest_projects(manifest_path: str = B.DATASET_MANIFEST
                       ) -> tuple[str, ...]:
    """The projects the reviewed dataset manifest declares a bundle for.

    Read, not restated.  Admitting a project to the manifest is what admits
    it to `doctor --project` and to the bundle commands, so registering one
    stays a data change instead of an edit spread over every enum that used
    to name each project by hand.  ``environment.manifest_facts`` resolves
    per-project manifest blocks through the same bundle-module reader; this
    is the same authority asked which projects exist at all.
    """
    document = B._read_json(manifest_path, "dataset manifest")
    return tuple(sorted(document.get("projects") or {}))


#: The projects with a manifest-declared scoring bundle, sorted by name.
#: This is exactly what `bundle build` can rebuild from preserved release
#: evidence.
MANIFEST_PROJECTS = _manifest_projects()
#: Consumer routes the dataset manifest cannot declare, each named with its
#: reason.  algorand-sdk's scoring bundle is native: it is built from approved
#: inputs and published with its own Algorand release index, which is what
#: `_project_boundary` reads for it, so it has no `projects` block in the
#: dataset manifest.  Deriving the enums from the manifest alone would
#: therefore stop `doctor --project algorand-sdk` and `bundle fetch --project
#: algorand-sdk` from being accepted at all, so the residual is named here
#: rather than dropped.
RESIDUAL_PROJECTS = ("algorand-sdk",)
#: Every project with a current consumer route.
SUPPORTED_PROJECTS = MANIFEST_PROJECTS + RESIDUAL_PROJECTS

ALGORAND_ROUTE_VERSION = "2"
MUTATION_READINESS_ROW = "mutation readiness"
COVERAGE_READINESS_ROW = "coverage readiness"
GENERATION_READINESS_ROWS = frozenset({
    MUTATION_READINESS_ROW,
    COVERAGE_READINESS_ROW,
    "production method index",
})
_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")
_WORKER_MANIFEST = re.compile(r"^worker([0-9]+)\.json$")
#: A `git clone` without `git lfs pull` leaves each LFS-tracked release file
#: replaced by a small pointer text file starting with this line.  Reading it
#: as the mutant catalogue it stands in for would otherwise fail far
#: downstream as an opaque JSON or digest error.
_LFS_POINTER_HEADER = b"version https://git-lfs.github.com/spec/v1"
#: Two host resources a cell exhausts mid-run today with no warning at all.
#: Neither is a refusal.  How much of either a cell needs depends on K and on
#: how many items it executes, so the honest report is a warning an operator
#: can act on before spending money, not a gate with an invented minimum.
#:
#: The free-space floor is round operator headroom, not a measured
#: requirement: a prepared CoreShop runtime root on the reference host
#: measured about 7 GiB before any run, and the Docker root additionally
#: holds the harness image and K worker container layers.
FREE_SPACE_FLOOR = 20 * 1024 ** 3
#: The per-UID kernel keyring quota.  Docker reports its exhaustion as
#: "disk quota exceeded", which sends an operator to `df` on a host whose
#: disk is healthy; the reference host reached it at the kernel default of
#: 200 while a few dozen pool containers were live.
MAXKEYS_PATH = "/proc/sys/kernel/keys/maxkeys"
MAXKEYS_FLOOR = 1000


class DoctorRefused(RuntimeError):
    pass


def _normalise_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _is_lfs_pointer(path: str) -> bool:
    with open(path, "rb") as fh:
        return fh.read(len(_LFS_POINTER_HEADER)) == _LFS_POINTER_HEADER


def _requirement_pins(path: str) -> dict[str, str]:
    if not os.path.isfile(path):
        raise DoctorRefused(f"no requirements lock at {path}")
    pins: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = _PIN.fullmatch(line)
            if not match:
                raise DoctorRefused(
                    f"{path}:{lineno} is not an exact NAME==VERSION pin: "
                    f"{line!r}")
            name = _normalise_distribution(match.group(1))
            if name in pins:
                raise DoctorRefused(f"{path} pins {name} more than once")
            pins[name] = match.group(2)
    if not pins:
        raise DoctorRefused(f"requirements lock is empty: {path}")
    return pins


def _compare_pins(expected: dict[str, str], installed: dict[str, str], *,
                  exact: bool) -> tuple[bool, str]:
    missing = sorted(name for name in expected if name not in installed)
    mismatched = sorted(
        f"{name}=={installed[name]} (need {version})"
        for name, version in expected.items()
        if name in installed and installed[name] != version)
    unexpected = sorted(name for name in installed if name not in expected) \
        if exact else []
    ok = not (missing or mismatched or unexpected)
    if ok:
        return True, f"{len(expected)} exact package pin(s) satisfied"
    parts = []
    if missing:
        parts.append(f"missing={missing[:12]}")
    if mismatched:
        parts.append(f"mismatched={mismatched[:12]}")
    if unexpected:
        parts.append(f"unexpected={unexpected[:12]}")
    return False, "; ".join(parts)


def _coordinator_requirements() -> tuple[bool, str]:
    try:
        pins = _requirement_pins(COORDINATOR_REQUIREMENTS)
        import yaml
        installed = {}
        for name in pins:
            installed[name] = metadata.version(name)
        ok, detail = _compare_pins(pins, installed, exact=False)
        if _normalise_distribution("PyYAML") in pins \
                and not getattr(yaml, "__version__", None):
            return False, "PyYAML imported without a version"
        return ok, detail
    except (DoctorRefused, ImportError, metadata.PackageNotFoundError) as e:
        return False, str(e)


def _os_release(path: str = "/etc/os-release") -> dict[str, str]:
    values = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                if "=" not in raw:
                    continue
                key, value = raw.rstrip("\n").split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values


def _current_umask() -> int:
    """Read the process umask while restoring it immediately."""
    value = os.umask(0)
    os.umask(value)
    return value


def _umask_preflight(value: int) -> tuple[bool, str]:
    text = f"{value:04o}"
    if value & 0o022 == 0o022:
        return True, text
    return False, (
        f"{text} permits group/other writes; run `umask 022` before planning "
        "or provisioning workers")


def _authority_docker_root() -> tuple[Optional[str], str]:
    """Where the configured authority's daemon stores images and layers.

    Read from the authority artifact rather than from `docker info`, so this
    costs no subprocess and works on the legacy branch below, which never
    loads the authority document itself.
    """
    from ..core import docker_cli as DC
    try:
        document, _reference = DC.authority_reference(live=False)
        return document["daemon"]["docker_root_dir"], ""
    except (DC.DockerEndpointRefused, KeyError, TypeError) as e:
        return None, str(e)


def _free_space_row(data_root: Optional[str]) -> tuple[str, str]:
    """Report free space on the two filesystems a cell silently fills."""
    docker_root, docker_error = _authority_docker_root()
    parts, concerns = [], []
    for label, path, why in (
            ("data root", data_root, "no usable data root"),
            ("Docker root", docker_root, docker_error)):
        if path is None:
            parts.append(f"{label}: unknown ({why})")
            concerns.append(f"{label} free space is unknown")
            continue
        try:
            free = shutil.disk_usage(path).free
        except OSError as e:
            parts.append(f"{label} {path}: unreadable ({e})")
            concerns.append(f"{label} free space is unreadable")
            continue
        parts.append(f"{label} {path}: {free / 1024 ** 3:.1f} GiB free")
        if free < FREE_SPACE_FLOOR:
            concerns.append(
                f"{label} is below the {FREE_SPACE_FLOOR // 1024 ** 3} GiB "
                "headroom this row warns at")
    if concerns:
        return "warn", "; ".join(parts + concerns)
    return "pass", "; ".join(parts)


def _keyring_capacity_row(path: str = MAXKEYS_PATH) -> tuple[str, str]:
    """Report the per-UID key quota whose exhaustion Docker misnames."""
    try:
        with open(path, encoding="utf-8") as fh:
            maxkeys = int(fh.read().strip())
    except (OSError, ValueError) as e:
        return "warn", f"cannot read {path}: {e}"
    if maxkeys >= MAXKEYS_FLOOR:
        return "pass", f"{path}={maxkeys}"
    return "warn", (
        f"{path}={maxkeys}; a pool of live containers exhausts this quota "
        'and Docker reports the exhaustion as "disk quota exceeded" on a '
        "host whose disk is healthy. Raise it (`sysctl -w "
        f"kernel.keys.maxkeys={MAXKEYS_FLOOR}`) before provisioning.")


def _project_boundary(project: str) -> tuple[dict, str]:
    """Return one project's declaration and selected bundle version."""
    if project == "algorand-sdk":
        from . import algorand_bundle as A
        selected = A.layout(ALGORAND_ROUTE_VERSION)
        try:
            declaration = A._release_index(
                selected.release_index, selected=selected)
        except (A.AlgorandBundleRefused, OSError) as e:
            raise DoctorRefused(
                f"cannot read Algorand v{ALGORAND_ROUTE_VERSION} release "
                f"index {selected.release_index}: {e}") from e
        return declaration, selected.version

    path = os.path.join(BENCHMARK, "release", "dataset_manifest.json")
    try:
        with open(path, encoding="utf-8") as fh:
            projects = (json.load(fh).get("projects") or {})
    except (OSError, ValueError) as e:
        raise DoctorRefused(f"cannot read dataset manifest {path}: {e}") from e
    declaration = projects.get(project)
    if not isinstance(declaration, dict):
        raise DoctorRefused(
            f"unknown project {project!r}; released projects are "
            f"{sorted(projects)}")
    bundle = declaration.get("bundle")
    version = bundle.get("version") if isinstance(bundle, dict) else None
    if not isinstance(version, str) or not version:
        raise DoctorRefused(
            f"project {project!r} has no declared bundle version")
    return declaration, version


def _project_behat(profile):
    """The project's Behat row, read from the boundary beside its profile.

    The live worker preflight compares each container's environment against
    the row, so without it a Sylius pool is reported as failing for not
    carrying CoreShop's `PIMCORE_TEST_DB_DSN`.  A profile NAMES its own
    boundary, and `load_profile` has already checked that the two agree, so
    there is nothing here to resolve or guess.  A boundary with no `behat:`
    block is `CORESHOP_BEHAT`, which is what every CoreShop report was
    written against.
    """
    from ..bench.repo import behat_project
    from ..core.boundary import load_boundary
    return behat_project(load_boundary(profile.boundary_path))


def _project_profile(project: str, path: Optional[str] = None):
    from ..data.profile import load_profile, profile_stem
    if path is None:
        path = os.path.join(BENCHMARK, "config",
                            f"profile_{profile_stem(project)}.yml")
    profile = load_profile(path)
    if profile.project != project:
        raise DoctorRefused(
            f"profile {path} declares {profile.project!r}, not {project!r}")
    return profile


def _layout(project: str) -> dict[str, str]:
    from ..core.paths import project_path
    return {
        "project_root": os.fspath(project_path(project)),
        "source": os.fspath(project_path(project, "source")),
        "gold": os.fspath(project_path(project, "gold")),
        "artifacts": os.fspath(project_path(project, "artifacts")),
        "seed": os.fspath(project_path(project, "seed", "v1")),
        "workers": os.fspath(project_path(project, "workers")),
    }


def _runtime_image(project: str, declaration: dict) -> str:
    if project == "coreshop":
        from .provision_coreshop import HARNESS_IMAGE
        return HARNESS_IMAGE
    return declaration["harness_image"]


def _load_worker_manifests(root: str, expected_workdir: str):
    from ..bench.worker import WorkerRefused, load_worker_pool
    try:
        names = os.listdir(root)
    except OSError as e:
        raise DoctorRefused(f"cannot read saved worker manifests in {root}: {e}") \
            from e
    numbered = sorted((int(match.group(1)), name)
                      for name in names
                      for match in [_WORKER_MANIFEST.fullmatch(name)] if match)
    if not numbered:
        raise DoctorRefused(
            f"no saved worker manifests in {root}; bring the project "
            "environment up with `r2t environment up` first")
    indices = [index for index, _name in numbered]
    if indices != list(range(len(numbered))):
        raise DoctorRefused(
            f"saved worker manifests are not exactly worker0.json.."
            f"worker{len(numbered) - 1}.json: found {indices}")
    paths = [os.path.join(root, name) for _index, name in numbered]
    try:
        workers = load_worker_pool(root, len(numbered))
    except WorkerRefused as e:
        raise DoctorRefused(str(e)) from e
    for path, worker in zip(paths, workers):
        if worker.workdir != expected_workdir:
            raise DoctorRefused(
                f"{path} mounts at {worker.workdir!r}; project requires "
                f"{expected_workdir!r}. Re-run `r2t worker plan` for this "
                "project before provisioning.")
    return paths, workers


def _daemon_route_preflight(authority: dict) -> str:
    """Describe the route already validated by authority_reference."""
    socket_path = authority["adapter"]["resolved_socket_path"]
    return (
        f"rootless daemon at {socket_path}; live facts match the explicit "
        "authority")


def _storage_driver_preflight(authority: dict) -> tuple[bool, str]:
    driver = authority["daemon"]["storage_driver"]
    if driver != "overlay2":
        return False, (
            f"found {driver}; the Algorand v{ALGORAND_ROUTE_VERSION} image "
            "route requires the classic overlay2 store")
    return True, driver


def _daemon_inventory_preflight(runner=None) -> tuple[str, str]:
    """Report selected-daemon inventory without inferring route stage."""
    if runner is None:
        from ..core import docker_cli as DC

        def runner(argv, *, timeout):
            try:
                command = DC.docker_command(argv)
                return subprocess.run(
                    command, capture_output=True, text=True, timeout=timeout)
            except (DC.DockerEndpointRefused, OSError,
                    subprocess.TimeoutExpired) as e:
                return subprocess.CompletedProcess(argv, 127, "", str(e))

    inventories = {}
    commands = {
        "containers": ("container", "ls", "--all", "--quiet"),
        "images": ("image", "ls", "--all", "--quiet", "--no-trunc"),
        "volumes": ("volume", "ls", "--quiet"),
    }
    for label, argv in commands.items():
        result = runner(argv, timeout=30)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or
                      f"Docker {label} inventory failed")[-400:].strip()
            return "fail", f"cannot inspect {label}: {detail}"
        inventories[label] = [
            line for raw in (result.stdout or "").splitlines()
            if (line := raw.strip())]
    nonempty = {name: len(values) for name, values in inventories.items()
                if values}
    if nonempty:
        return "warn", f"selected daemon inventory: {nonempty}"
    return "pass", "no containers, images, or volumes"


def _registry_package_preflight(project: str, probe=None):
    """Check only routes whose consumer procedure reads a registry package."""
    if project != "algorand-sdk":
        return None
    if probe is None:
        from .algorand_image import preflight_public_registry
        probe = preflight_public_registry
    try:
        facts = probe()
    except (OSError, RuntimeError, ValueError) as e:
        return False, (
            f"Algorand v{ALGORAND_ROUTE_VERSION} requires credential-free "
            f"package access, but the anonymous registry probe failed: {e}")
    return True, (
        f"{facts['repository']}@{facts['manifest_digest']} is readable "
        "without client credentials")


_AGENT_PROBE = r"""
import json, platform
from importlib import metadata
packages = []
for dist in metadata.distributions():
    name = dist.metadata.get('Name')
    if name and name.lower() != 'pip':
        packages.append([name, dist.version])
print(json.dumps({
    'implementation': platform.python_implementation(),
    'version': platform.python_version(),
    'packages': packages,
}, sort_keys=True))
"""


def _agent_environment(interpreter: str) -> dict:
    env = dict(os.environ)
    env["PYTHONNOUSERSITE"] = "1"
    try:
        cp = subprocess.run(
            [interpreter, "-c", _AGENT_PROBE], capture_output=True, text=True,
            env=env, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DoctorRefused(f"cannot run agent interpreter {interpreter}: {e}") \
            from e
    if cp.returncode != 0:
        raise DoctorRefused(
            f"agent interpreter {interpreter} failed: "
            f"{(cp.stderr or cp.stdout or '')[-400:]}")
    try:
        doc = json.loads(cp.stdout)
        pairs = doc["packages"]
        installed = {_normalise_distribution(name): version
                     for name, version in pairs}
    except (ValueError, KeyError, TypeError) as e:
        raise DoctorRefused(
            f"agent interpreter {interpreter} returned an invalid package "
            f"inventory: {e}") from e
    doc["installed"] = installed
    return doc


def _add(checks: list[dict], name: str, status: str, detail: str) -> None:
    checks.append({"name": name, "status": status, "detail": detail})


def _metric_readiness(project: str, bundle_version: Optional[str],
                      declaration: Optional[dict], profile,
                      installed_bundle: object, *,
                      live_mutation_binding: object = None) -> list[dict]:
    """Map declared capabilities and validated installed roles into rows.

    The row shape and statuses are the existing doctor contract.  Details use
    the campaign table's stable reason tokens so the pre-paid decision and a
    later unscored cell describe the same condition without another readiness
    vocabulary.  Artifact bytes are the installed-bundle validator's concern;
    this mapper checks only that its fact belongs to this declaration and that
    each capability names the roles from the one closed generic vocabulary.
    """
    from ..bench.campaign_table import (NO_GOLD_RUN, NO_MUTANTS, NOT_MEASURED_API,
                                 NOT_SCORED_API, NOT_SCORED_COVERAGE,
                                 NOT_SCORED_MUTATION)
    from ..data.profile import API_SCORING_METHOD_INDEX, API_SCORING_NONE
    from ..data.release import (CAPABILITY_REQUIRED_ROLES, ManifestRefused,
                          _check_capabilities)

    specs = (
        (MUTATION_READINESS_ROW, "mutation",
         NOT_SCORED_MUTATION, NO_MUTANTS, NOT_SCORED_MUTATION),
        (COVERAGE_READINESS_ROW, "coverage",
         NOT_SCORED_COVERAGE, NOT_SCORED_COVERAGE, NO_GOLD_RUN),
        ("production method index", "api_similarity",
         NOT_SCORED_API, NOT_MEASURED_API, NOT_SCORED_API),
    )
    api_route_open = (profile is not None
                      and profile.api_scoring == API_SCORING_METHOD_INDEX)
    bundle_limitation = None
    if not isinstance(installed_bundle, dict):
        bundle_limitation = (
            f"installed bundle validation refused: {installed_bundle}")
    elif installed_bundle.get("project") != project:
        bundle_limitation = (
            "validated installed bundle fact names project "
            f"{installed_bundle.get('project')!r}, not {project!r}")
    elif installed_bundle.get("version") != bundle_version:
        bundle_limitation = (
            "validated installed bundle fact names version "
            f"{installed_bundle.get('version')!r}, not {bundle_version!r}")
    raw = declaration.get("capabilities") \
        if isinstance(declaration, dict) else None
    if not isinstance(raw, dict):
        return [
            {"name": name, "status": "fail",
             "detail": (f"{unready}: {project} {capability} capability is "
                        "undeclared")}
            for name, capability, unready, _disabled, _missing in specs
        ]
    try:
        capabilities = _check_capabilities(project, declaration)
    except ManifestRefused as exc:
        return [
            {"name": name, "status": "fail",
             "detail": f"{unready}: {exc}"}
            for name, _capability, unready, _disabled, _missing in specs
        ]

    bundle = declaration.get("bundle")
    artifacts = bundle.get("artifacts") if isinstance(bundle, dict) else None
    rows = []
    for name, capability, unready, disabled, missing_reason in specs:
        if capability == "mutation":
            from ..bench.live_test_quality import (
                LIVE_CAPABLE, UNSUPPORTED, LiveTestQualityRefused,
                resolve_mutation_readiness)
            try:
                readiness = resolve_mutation_readiness(
                    project, bundle_version, declaration, installed_bundle,
                    live_mutation_binding)
            except LiveTestQualityRefused as exc:
                rows.append({
                    "name": name, "status": "fail",
                    "detail": f"{missing_reason}: {exc}",
                })
            else:
                reason = (disabled if readiness.state == UNSUPPORTED
                          else missing_reason)
                rows.append({
                    "name": name,
                    "status": ("pass" if readiness.state == LIVE_CAPABLE
                               else "fail"),
                    "detail": (
                        readiness.detail if readiness.state == LIVE_CAPABLE
                        else f"{reason}: {readiness.state}: "
                             f"{readiness.detail}"),
                    # Carried so `_host_metric_readiness` can tell the one
                    # state a host cannot discharge from the ones it can.
                    "readiness": readiness.state,
                })
            continue

        if not capabilities[capability]:
            note = (declaration.get("capability_notes") or {}).get(capability)
            if capability == "api_similarity" and profile is not None \
                    and profile.api_scoring == API_SCORING_NONE:
                rows.append({
                    "name": name,
                    "status": "pass",
                    "detail": (f"{disabled}: {project} declares API "
                               f"similarity not measurable: {note}"),
                })
            else:
                rows.append({
                    "name": name,
                    "status": "fail",
                    "detail": (f"{disabled}: {project} declares "
                               f"{capability} disabled: {note}"),
                })
            continue

        missing = []
        declared = []
        for role in CAPABILITY_REQUIRED_ROLES[capability]:
            relative = artifacts.get(role) if isinstance(artifacts, dict) \
                else None
            if not isinstance(relative, str) or not relative:
                missing.append(f"{role} (undeclared)")
            else:
                declared.append(f"{role}={relative}")

        limitations = []
        if missing:
            limitations.append("missing installed role(s): "
                               + ", ".join(missing))
        if bundle_limitation is not None:
            limitations.append(bundle_limitation)
        if capability == "api_similarity" and not api_route_open:
            mode = profile.api_scoring if profile is not None else "missing"
            limitations.append(
                f"profile api_scoring={mode!r} does not open API similarity")
        if limitations:
            rows.append({"name": name, "status": "fail",
                         "detail": f"{missing_reason}: "
                         + "; ".join(limitations)})
        else:
            rows.append({
                "name": name,
                "status": "pass",
                "detail": (f"{project} bundle {bundle_version} validated; "
                           f"declared {capability} role(s): "
                           f"{', '.join(declared)}"),
            })
    return rows


def _host_metric_readiness(rows: list[dict]) -> list[dict]:
    """Regrade the one metric row a host cannot possibly discharge.

    `resolve_mutation_readiness` reaches `live-capable` only with an admitted
    live producer binding, and such a binding is minted during paid
    generation from adapter material.  Preflighting a host cannot produce
    one, so `_metric_readiness`'s FAIL -- correct at the paid boundary -- is
    not a statement about the host.  Reporting it as a host failure made
    `doctor` unable to exit 0 on any host for any project, contradicting
    `docs/OPERATOR.md`.  It becomes a WARN here, exactly as `environment
    up`'s host preflight already skips this row saying paid generation, not
    environment bring-up, owns the gate.  `generation_readiness_checks`
    restores the FAIL for the boundary that does own it.
    """
    from ..bench.live_test_quality import PRESERVED_EVIDENCE_ONLY
    return [dict(row, status="warn")
            if row.get("readiness") == PRESERVED_EVIDENCE_ONLY else row
            for row in rows]


def generation_readiness_checks(report: dict) -> list[dict]:
    """Select the doctor rows that gate paid generation, at full strength.

    Paid generation needs each metric READY, so anything short of `pass` --
    including the host-preflight warning above -- is a failure here.
    """
    rows = [dict(row, status="fail") if row["status"] != "pass" else row
            for row in report["checks"]
            if row["name"] in GENERATION_READINESS_ROWS]
    counts = {name: sum(row["name"] == name for row in rows)
              for name in GENERATION_READINESS_ROWS}
    if any(count != 1 for count in counts.values()):
        raise DoctorRefused(
            "generation doctor report needs exactly one row for each of "
            f"{sorted(GENERATION_READINESS_ROWS)}; counts={counts}")
    return rows


def _docker(worker_module, argv: list[str], timeout: int = 30):
    """Run one Docker probe, representing an absent CLI as a failed probe."""
    try:
        return worker_module._docker(argv, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 127, "", str(e))


def _environment_records(project: str) -> tuple[list, Optional[str]]:
    """Read this project's saved `environment up` records once.

    Both the submitted-route row and the worker pool below are answered from
    the same records, and a malformed record is a diagnosis rather than a
    reason to abandon the whole report, so the refusal is returned instead of
    raised.
    """
    from .environment_lifecycle import _saved_records
    try:
        return _saved_records(project), None
    except SystemExit as e:
        return [], str(e)


def _resolved_pool(records: list) -> tuple[Optional[dict], Optional[str]]:
    """The worker pool doctor should inspect, or why it cannot name one.

    `environment up` writes each pool to
    `projects/<p>/environments/<nonce>/workers` and names that environment's
    own database `r2t_<nonce>_database`.  The older `worker plan` route wrote
    one pool directly to `projects/<p>/workers` beside a single fixed-name
    `coreshop_db`.  Both layouts exist on real hosts, so doctor reads the
    saved record when there is one; `(None, None)` means the legacy layout is
    the only one this host has.
    """
    up = [record for _nonce, _path, record in records
          if record["state"] == "up"]
    if len(up) <= 1:
        return (up[0] if up else None), None
    project = up[0]["project"]
    return None, (
        f"{len(up)} environments are up for {project} "
        f"({[record['nonce'] for record in up]}); doctor inspects one pool, "
        f"so retire the ones this host has finished with using `environment "
        f"down --project {project} --nonce NONCE`")


def _submitted_environment_row(records: list,
                               error: Optional[str],
                               project: str) -> tuple[str, str]:
    """Status and detail for the submitted-route environment row.

    Decision 7 of `EXTERNAL_CANDIDATE_SUBMISSION_AMENDMENT.md` made the
    bring-up gate a stamp: `run --adapter submitted` never refuses on
    proof-absence, and every row records `environment_proven`.  This row is
    the recommended-guidance half -- run `environment up --project
    <project>` before a submitted run so the stamp reads true.  It is never
    a FAIL: nothing refuses on a missing record, and `environment up`'s own
    host preflight reads this report, so a fail here would gate the very
    command that discharges it.
    """
    if error is not None:
        return "warn", error
    accepted = [nonce for nonce, _path, record in records
                if record["state"] == "up"
                and record["gold_control"]["passed"] is True]
    if accepted:
        return "pass", (
            f"accepted r2t.project-environment/v1 record(s): "
            f"{', '.join(accepted)}; a submitted run bound to such a pool "
            f"stamps environment_proven: true")
    return "warn", (
        "no accepted r2t.project-environment/v1 record; a submitted run "
        "proceeds but stamps environment_proven: false -- run "
        f"`environment up --project {project}` first")


def _agent_backends() -> Optional[dict]:
    """The agent arms this checkout ships, or None without the agent component.

    The arms' readiness rows -- bubblewrap, the backend interpreters and
    their locks -- are asked only when there is an arm to launch; a
    benchmark-only checkout runs the fixture and submitted adapters, which
    need none of them.
    """
    try:
        from ..agents.backends import AGENT_BACKENDS
    except ImportError:
        return None
    return AGENT_BACKENDS


def doctor(*, project: str, agent: Optional[str] = None,
           profile_path: Optional[str] = None,
           llm_config: Optional[str] = None) -> dict:
    """Run the read-only host and project probes and return one report."""
    checks: list[dict] = []

    implementation = platform.python_implementation()
    python_version = platform.python_version()
    _add(checks, "coordinator interpreter",
         "pass" if implementation == "CPython" else "warn",
         f"{implementation} {python_version}")
    if python_version != REFERENCE["coordinator_python"]:
        _add(checks, "reference coordinator version", "warn",
             f"found {python_version}; reference is "
             f"CPython {REFERENCE['coordinator_python']} (untested)")

    requirement_ok, requirement_detail = _coordinator_requirements()
    _add(checks, "coordinator requirements",
         "pass" if requirement_ok else "fail", requirement_detail)

    release = _os_release()
    os_identity = f"{release.get('NAME', platform.system())} " \
                  f"{release.get('VERSION_ID', platform.release())}"
    os_matches = release.get("ID") == "ubuntu" \
        and release.get("VERSION_ID") == "22.04"
    _add(checks, "host operating system", "pass" if os_matches else "warn",
         os_identity if os_matches else
         f"{os_identity}; reference is {REFERENCE['os']} (untested)")
    machine = platform.machine()
    _add(checks, "host architecture",
         "pass" if machine == REFERENCE["machine"] else "warn",
         machine if machine == REFERENCE["machine"] else
         f"{machine}; reference is {REFERENCE['machine']} (untested)")

    from ..bench import confine as C
    agent_backends = _agent_backends()
    if agent_backends is not None:
        # Bubblewrap confines an AGENT launch; a checkout with no agent arm
        # to launch has nothing for it to confine.
        bwrap = C.bwrap_probe()
        _add(checks, "bubblewrap usable",
             "pass" if bwrap["usable"] else "fail",
             bwrap.get("version") or bwrap.get("error") or "unusable")
        bwrap_version = (bwrap.get("version") or "").removeprefix(
            "bubblewrap ")
        if bwrap["usable"] and bwrap_version != REFERENCE["bubblewrap"]:
            _add(checks, "reference bubblewrap version", "warn",
                 f"found {bwrap_version}; reference is "
                 f"{REFERENCE['bubblewrap']} (untested)")

    umask_ok, umask_detail = _umask_preflight(_current_umask())
    _add(checks, "process umask", "pass" if umask_ok else "fail",
         umask_detail)

    try:
        declaration, bundle_version = _project_boundary(project)
    except (DoctorRefused, SystemExit, OSError, ValueError) as e:
        declaration = None
        bundle_version = None
        profile = None
        _add(checks, "project configuration", "fail", str(e))
    else:
        try:
            profile = _project_profile(project, profile_path)
        except (DoctorRefused, SystemExit, OSError, ValueError) as e:
            profile = None
            _add(checks, "project configuration", "fail", str(e))
        else:
            _add(checks, "project configuration", "pass",
                 f"{project}: {profile.framework}, "
                 f"needs_database={profile.needs_database}")

    from ..data.mutation import ARCHIVED_MANIFESTS
    catalogue = ARCHIVED_MANIFESTS.get(project)
    if catalogue is not None and os.path.isfile(catalogue):
        pointer = _is_lfs_pointer(catalogue)
        _add(checks, "mutant catalogue fetched", "fail" if pointer else "pass",
             f"{catalogue} is a Git LFS pointer file, not the mutant "
             "catalogue; run `git lfs install && git lfs pull`"
             if pointer else catalogue)

    legacy_project = project != "algorand-sdk"
    installed_bundle: object = B.BundleRefused(
        "REFUSED: installed bundle validation requires a valid project "
        "configuration and data root")
    from ..core.paths import data_root as shared_data_root
    try:
        resolved_root = shared_data_root()
    except (RuntimeError, SystemExit) as e:
        resolved_root = None
        root_error = str(e)
    layout = None
    records: list = []
    records_error = None
    pool_record = pool_error = None
    if not resolved_root:
        _add(checks, "data root", "fail",
             root_error or
             "R2T_DATA_ROOT is unset; export it before running doctor")
    elif not os.path.isdir(resolved_root):
        _add(checks, "data root", "fail",
             f"not a directory: {os.path.abspath(resolved_root)}")
    else:
        resolved_root = os.path.abspath(resolved_root)
        _add(checks, "data root", "pass", resolved_root)
        if declaration is not None and bundle_version is not None:
            try:
                installed_bundle = B.validate_installed_bundle(
                    project, bundle_version, resolved_root)
            except B.BundleRefused as exc:
                installed_bundle = exc
        if legacy_project:
            layout = _layout(project)
            missing_dirs = [path for name, path in layout.items()
                            if name in ("gold", "artifacts")
                            and not os.path.isdir(path)]
            _add(checks, "project data directories",
                 "pass" if not missing_dirs else "fail",
                 f"gold and artifacts present for {project}"
                 if not missing_dirs else f"missing={missing_dirs}")
            records, records_error = _environment_records(project)
            pool_record, pool_error = _resolved_pool(records)
        from ..bench.runner import SUBMITTED_ADMITTED_PROJECTS
        if project in SUBMITTED_ADMITTED_PROJECTS:
            row_status, row_detail = _submitted_environment_row(
                records, records_error, project)
            _add(checks, "submitted-route environment", row_status,
                 row_detail)

    free_status, free_detail = _free_space_row(resolved_root or None)
    _add(checks, "free disk space", free_status, free_detail)
    keys_status, keys_detail = _keyring_capacity_row()
    _add(checks, "kernel keyring capacity", keys_status, keys_detail)

    from ..bench import worker as W
    from ..core import docker_cli as DC
    if legacy_project:
        # A host that never minted an authority refuses at the first Docker
        # argv, before any subprocess.  Record that refusal as this row, the
        # way the Algorand branch below already does: an unauthorized host is
        # exactly the host whose remaining local checks are worth reporting,
        # and letting the refusal escape would replace the whole report with
        # one line.
        info_argv = ["info", "--format", "{{.ServerVersion}}"]
        try:
            docker = _docker(W, info_argv)
        except DC.DockerEndpointRefused as e:
            docker = subprocess.CompletedProcess(info_argv, 127, "", str(e))
        docker_version = (docker.stdout or "").strip()
        docker_ok = docker.returncode == 0 and bool(docker_version)
        _add(checks, "Docker daemon access", "pass" if docker_ok else "fail",
             docker_version if docker_ok else
             (docker.stderr or docker.stdout or "docker info failed")[-400:])
        if docker_ok and docker_version != REFERENCE["docker"]:
            _add(checks, "reference Docker version", "warn",
                 f"found {docker_version}; reference is "
                 f"{REFERENCE['docker']} (untested)")
    else:
        docker_ok = False
        try:
            authority, _authority_reference = DC.authority_reference(live=True)
        except DC.DockerEndpointRefused as e:
            docker_version = None
            _add(checks, "Docker daemon access", "fail", str(e))
        else:
            docker_version = authority["daemon"]["server_version"]
            _add(checks, "Docker daemon access", "pass", docker_version)
            _add(checks, "Docker daemon route", "pass",
                 _daemon_route_preflight(authority))
            storage_ok, storage_detail = _storage_driver_preflight(authority)
            _add(checks, "Docker storage driver",
                 "pass" if storage_ok else "fail", storage_detail)
            inventory_status, inventory_detail = \
                _daemon_inventory_preflight()
            _add(checks, "Docker daemon inventory", inventory_status,
                 inventory_detail)
            # The anonymous registry read is doctor's ONLY external-network
            # contact, so it belongs last and inside this branch.  Doctor
            # never early-exits -- a refusal becomes a row -- so running the
            # probe anywhere in the common prefix reaches the network even on
            # a host whose Docker authority does not validate, and moving it
            # without gating would only make that traffic later.  Here it is
            # reached only after every local check is recorded and only once
            # `authority_reference(live=True)` has accepted this host's
            # explicit authority.  The cost is that an authority-refused host
            # has no `registry package read` row at all; that host already
            # fails closed on `Docker daemon access`.
            registry = _registry_package_preflight(project)
            if registry is not None:
                registry_ok, registry_detail = registry
                _add(checks, "registry package read",
                     "pass" if registry_ok else "fail", registry_detail)
        if docker_version and docker_version != REFERENCE["docker"]:
            _add(checks, "reference Docker version", "warn",
                 f"found {docker_version}; reference is "
                 f"{REFERENCE['docker']} (untested)")

    expected_image_id = None
    if docker_ok and declaration is not None:
        image = _runtime_image(project, declaration)
        inspected = _docker(
            W, ["image", "inspect", image, "--format", "{{.Id}}"])
        expected_image_id = (inspected.stdout or "").strip()
        image_ok = inspected.returncode == 0 and bool(expected_image_id)
        _add(checks, "project image", "pass" if image_ok else "fail",
             f"{image} -> {expected_image_id}" if image_ok else
             f"{image}: "
             f"{(inspected.stderr or inspected.stdout or 'not found')[-400:]}")

    if docker_ok and profile is not None and profile.needs_database:
        # `environment up` gives each environment its own nonce-named
        # database container; only the in-container network alias stayed
        # `coreshop_db`, so inspecting the alias finds nothing on a host
        # brought up by the current verb.
        db_container = (pool_record["database"]["container"]
                        if pool_record is not None
                        and pool_record["database"] is not None
                        else W.DEFAULT_DB_CONTAINER)
        inspected = _docker(
            W, ["inspect", db_container, "--format", "{{.State.Running}}"])
        db_running = inspected.returncode == 0 \
            and (inspected.stdout or "").strip() == "true"
        _add(checks, "project database", "pass" if db_running else "fail",
             f"{db_container} is running" if db_running else
             f"{db_container}: "
             f"{(inspected.stderr or inspected.stdout or 'not running')[-400:]}")
    elif legacy_project and profile is not None and not profile.needs_database:
        _add(checks, "project database", "pass",
             f"{project} declares no database")

    paths = workers = None
    runtime = None
    if layout is not None and profile is not None:
        expected_workdir = ("/work" if profile.framework in {"behave", "godog"}
                            else "/var/www/html")
        workers_root = (pool_record["workers_root"] if pool_record is not None
                        else layout["workers"])
        origin = (f"environment {pool_record['nonce']}"
                  if pool_record is not None else "legacy worker plan")
        try:
            if pool_error is not None:
                raise DoctorRefused(pool_error)
            paths, workers = _load_worker_manifests(
                workers_root, expected_workdir)
            _add(checks, "saved worker manifests", "pass",
                 f"loaded worker0.json..worker{len(workers) - 1}.json from "
                 f"{workers_root} ({origin}); workdir={expected_workdir}")
        except DoctorRefused as e:
            _add(checks, "saved worker manifests", "fail", str(e))

    answers = None
    if workers is not None and layout is not None and profile is not None:
        answers = W.default_answer_paths(
            layout["gold"], layout["artifacts"],
            os.path.join(layout["artifacts"], "release"))
        # This probe and the two below each issue their own Docker argvs, so
        # each refuses -- before any subprocess -- on the host that reached
        # here with saved manifests but no usable authority: a prepared legacy
        # host invoked without `--docker-authority`, which is exactly the
        # diagnosis this command exists for.  Record those refusals as rows
        # for the same reason `Docker daemon access` above does; one escaping
        # exception discards the whole local report.  The runtime probe below
        # re-raises the missing-authority case as `WorkerRefused`, but still
        # reaches the argv layer afterwards, where an ambient `DOCKER_HOST`
        # refuses unwrapped.
        try:
            live = W.preflight(workers, answers, live=True,
                               needs_database=profile.needs_database,
                               behat=_project_behat(profile))
            _add(checks, "live worker preflight", "pass",
                 f"{live['workers']} worker(s) inspected")
        except (W.WorkerRefused, DC.DockerEndpointRefused, OSError,
                subprocess.SubprocessError) as e:
            _add(checks, "live worker preflight", "fail", str(e))

        try:
            from ..bench.validate import HARNESS_VERSION
            runtime = W.validate_mutation_runtime(
                paths, workers, layout["seed"], HARNESS_VERSION,
                profile.needs_database)
            _add(checks, "saved runtime and verified seed", "pass",
                 f"workspace seed {runtime['workspace_seed_digest']}; "
                 f"database {runtime['database_dump_digest']}")
        except (W.WorkerRefused, DC.DockerEndpointRefused, OSError,
                subprocess.SubprocessError) as e:
            _add(checks, "saved runtime and verified seed", "fail", str(e))
    elif layout is not None and profile is not None:
        # Runtime validation already invokes this primitive when manifests are
        # available.  Only take the standalone path when they are not, avoiding
        # a second read of a large seed archive in the successful case.
        try:
            seed = W.verified_seed_identity(
                layout["seed"], profile.needs_database)
            _add(checks, "verified seed", "pass",
                 seed["workspace_seed_digest"])
        except W.WorkerRefused as e:
            _add(checks, "verified seed", "fail", str(e))

    if runtime is not None and expected_image_id:
        same_image = runtime["container_image_digest"] == expected_image_id
        _add(checks, "worker image agreement",
             "pass" if same_image else "fail",
             runtime["container_image_digest"] if same_image else
             f"workers use {runtime['container_image_digest']}; configured "
             f"image resolves to {expected_image_id}")

    if workers is not None and answers is not None and profile is not None:
        verdicts, probe_errors = [], []
        expected = [f"executor[{worker.index}]" for worker in workers]
        for worker in workers:
            others = [other.workspace for other in workers
                      if other.index != worker.index]
            spec = C.executor_spec(
                answers, others,
                db_host=f"{W.DEFAULT_DB_CONTAINER}:3306")
            if not profile.needs_database:
                spec.control_host = None
            spec.name = f"executor[{worker.index}]"
            try:
                runner = worker.runner()
                doc = C.probe(
                    spec, lambda script, runner=runner:
                    (runner.run(script, timeout=300).stdout or ""))
                verdicts.append(C.verdict(spec, doc))
            except (C.NotConfined, DC.DockerEndpointRefused, OSError,
                    ValueError, subprocess.SubprocessError) as e:
                probe_errors.append(f"{spec.name}: {e}")
        certificate = C.certify(verdicts, expected=expected)
        certified = certificate["certified"] and not probe_errors
        detail = (f"{len(expected)} executor namespace(s) certified"
                  if certified else
                  (("; ".join(probe_errors) + "; ") if probe_errors else "")
                  + json.dumps(certificate, sort_keys=True))
        _add(checks, "worker confinement certificate",
             "pass" if certified else "fail", detail[:1000])

    checks.extend(_host_metric_readiness(_metric_readiness(
        project, bundle_version, declaration, profile, installed_bundle)))

    if agent and agent_backends is None:
        _add(checks, "agent selection", "fail",
             f"agent arms are not shipped in this checkout; {agent!r} "
             f"cannot be checked")
    elif agent:
        from ..bench.adapters import resolve_llm_config
        backend = agent_backends.get(agent)
        if backend is None:
            _add(checks, "agent selection", "fail",
                 f"unknown agent {agent!r}; choose "
                 f"{sorted(agent_backends)}")
        else:
            _add(checks, "agent selection", "pass", agent)

            # The default is inside the checkout, and writing credentials
            # into the checkout dirties the tree that the Docker execution
            # authority attests.  `--llm-config` names the private file the
            # campaign itself uses instead.
            config_path = llm_config or os.path.join(
                BENCHMARK, "llm_config.json")
            try:
                if llm_config and not os.path.isfile(llm_config):
                    raise DoctorRefused(
                        f"no model configuration at {llm_config}")
                cfg = resolve_llm_config(
                    config_path, explicit_model=None, require_credentials=False)
                resolved_model = cfg["model"]
                _add(checks, "resolved model agreement", "pass",
                     f"{resolved_model} (from {config_path})")
            except (DoctorRefused, SystemExit, OSError, ValueError) as e:
                _add(checks, "resolved model agreement", "fail", str(e))

            interpreter = backend.python() if resolved_root else None
            if interpreter is None:
                _add(checks, "agent environment lock", "fail",
                     "cannot resolve the agent interpreter without a data "
                     "root")
            else:
                try:
                    env_doc = _agent_environment(interpreter)
                    if env_doc.get("implementation") != "CPython":
                        _add(checks, "agent interpreter identity", "warn",
                             f"{env_doc.get('implementation')} "
                             f"{env_doc.get('version')} (untested)")
                    elif env_doc.get("version") != REFERENCE["agent_python"]:
                        _add(checks, "agent interpreter identity", "warn",
                             f"CPython {env_doc.get('version')}; reference is "
                             f"{REFERENCE['agent_python']} (untested)")
                    else:
                        _add(checks, "agent interpreter identity", "pass",
                             f"CPython {env_doc['version']}")
                    # The lock is the backend's own field, not a second
                    # table keyed by agent name: doctor resolved `backend`
                    # three checks ago, and the campaign, the worker
                    # provisioner and the probe all compare against that
                    # field.  A doctor with its own copy could pass while
                    # the run compared against a different file.
                    pins = _requirement_pins(backend.requirements_lock)
                    lock_ok, lock_detail = _compare_pins(
                        pins, env_doc["installed"], exact=True)
                    _add(checks, "agent environment lock",
                         "pass" if lock_ok else "fail", lock_detail)
                except DoctorRefused as e:
                    _add(checks, "agent environment lock", "fail", str(e))

    return {
        "schema": "r2t.doctor/v1",
        "project": project,
        "agent": agent,
        "ok": not any(check["status"] == "fail" for check in checks),
        "checks": checks,
    }


def render(report: dict) -> str:
    lines = []
    for check in report["checks"]:
        lines.append(f"{check['status'].upper():4}  {check['name']}: "
                     f"{check['detail']}")
    lines.append("DOCTOR PASS" if report["ok"] else "DOCTOR FAIL")
    return "\n".join(lines) + "\n"


def selftest() -> int:
    import tempfile
    from ..bench.worker import WorkerSpec

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    check("the coordinator requirements are the exact runtime dependencies",
          _requirement_pins(COORDINATOR_REQUIREMENTS)
          == {"pyyaml": "6.0.2", "jsonschema": "4.26.0",
              "httpx": "0.28.1",
              "tree-sitter": "0.25.2", "tree-sitter-php": "0.24.1",
              "tree-sitter-ruby": "0.23.1"})
    same, _detail = _compare_pins(
        {"a": "1", "b": "2"}, {"a": "1", "b": "2"}, exact=True)
    extra, extra_detail = _compare_pins(
        {"a": "1"}, {"a": "1", "b": "2"}, exact=True)
    check("an exact agent lock accepts equality and refuses extra packages",
          same and not extra and "unexpected=['b']" in extra_detail,
          extra_detail)
    # The lock file doctor reports is the registered backend's own field.
    # There is no second table here to fall out of step with it, and this
    # says so by reading each shipped lock through the registry: what the
    # preflight compares against is what the campaign and the worker
    # provisioner install from.
    from ..agents.backends import AGENT_BACKENDS
    agent_locks = {name: backend.requirements_lock
                   for name, backend in AGENT_BACKENDS.items()}
    check("every registered agent's environment lock is the backend's own, "
          "and it is shipped",
          bool(agent_locks)
          and all(os.path.isfile(path) and _requirement_pins(path)
                  for path in agent_locks.values())
          and len(set(agent_locks.values())) == len(agent_locks),
          str(agent_locks))
    safe_umasks = (0o022, 0o027, 0o077)
    unsafe_umasks = (0o000, 0o002)
    check("umask preflight accepts private defaults and rejects leaked 0002",
          all(_umask_preflight(value)[0] for value in safe_umasks)
          and all(not _umask_preflight(value)[0] for value in unsafe_umasks)
          and "umask 022" in _umask_preflight(0o002)[1])
    with tempfile.TemporaryDirectory() as tmp:
        for index in range(2):
            worker = WorkerSpec(
                index=index,
                workspace=os.path.join(tmp, f"worker{index}", "app"),
                container=f"c_{index}", schema=f"s_{index}",
                credential=f"u_{index}",
                env_file=os.path.join(tmp, ".secrets", f"worker{index}.env"),
                workdir="/work", out_path=os.path.join(tmp, f"{index}.jsonl"),
                artifacts_root=os.path.join(tmp, f"artifacts{index}"))
            with open(os.path.join(tmp, f"worker{index}.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(worker.to_json(), fh)
        paths, workers = _load_worker_manifests(tmp, "/work")
        check("saved manifests are loaded in exact numeric order",
              [worker.index for worker in workers] == [0, 1]
              and [os.path.basename(path) for path in paths]
              == ["worker0.json", "worker1.json"])
        try:
            _load_worker_manifests(tmp, "/var/www/html")
            wrong_workdir = ""
        except DoctorRefused as e:
            wrong_workdir = str(e)
        check("a project's workdir must agree before live probes",
              "project requires" in wrong_workdir, wrong_workdir)

    with tempfile.TemporaryDirectory() as tmp:
        # Both floors are patched rather than compared against whatever this
        # machine happens to have free, so the row's grading is what is under
        # test and not the host running the self-test.
        saved_free_floor = globals()["FREE_SPACE_FLOOR"]
        saved_docker_root = globals()["_authority_docker_root"]
        try:
            globals()["_authority_docker_root"] = lambda: (tmp, "")
            globals()["FREE_SPACE_FLOOR"] = 0
            ample_status, ample_detail = _free_space_row(tmp)
            globals()["FREE_SPACE_FLOOR"] = 1 << 60
            tight_status, tight_detail = _free_space_row(tmp)
            unknown_status, unknown_detail = _free_space_row(None)
            globals()["_authority_docker_root"] = lambda: (
                None, "REFUSED: no --docker-authority")
            no_authority_status, no_authority_detail = _free_space_row(tmp)
        finally:
            globals()["_authority_docker_root"] = saved_docker_root
            globals()["FREE_SPACE_FLOOR"] = saved_free_floor
        check("free space is reported for the data root and the authority's "
              "Docker root, and warns -- never fails -- when either is short "
              "or unknown",
              ample_status == "pass"
              and ample_detail.count("GiB free") == 2
              and f"data root {tmp}" in ample_detail
              and f"Docker root {tmp}" in ample_detail
              and tight_status == "warn"
              and "data root is below" in tight_detail
              and "Docker root is below" in tight_detail
              and unknown_status == "warn"
              and "no usable data root" in unknown_detail
              and no_authority_status == "warn"
              and "Docker root: unknown (REFUSED: no --docker-authority)"
              in no_authority_detail,
              str((ample_detail, tight_detail, unknown_detail,
                   no_authority_detail)))

        maxkeys_path = os.path.join(tmp, "maxkeys")
        with open(maxkeys_path, "w", encoding="utf-8") as fh:
            fh.write("200\n")
        default_status, default_detail = _keyring_capacity_row(maxkeys_path)
        with open(maxkeys_path, "w", encoding="utf-8") as fh:
            fh.write(f"{MAXKEYS_FLOOR}\n")
        raised_status, raised_detail = _keyring_capacity_row(maxkeys_path)
        absent_keys = _keyring_capacity_row(
            os.path.join(tmp, "no-such-maxkeys"))
        check("the kernel key quota is read and its misleading Docker "
              "symptom is named when it is left at the default",
              default_status == "warn"
              and "disk quota exceeded" in default_detail
              and f"kernel.keys.maxkeys={MAXKEYS_FLOOR}" in default_detail
              and raised_status == "pass"
              and raised_detail.endswith(f"={MAXKEYS_FLOOR}")
              and absent_keys[0] == "warn"
              and "cannot read" in absent_keys[1],
              str((default_detail, raised_detail, absent_keys)))

        pointer_path = os.path.join(tmp, "mutants_v1.json")
        with open(pointer_path, "wb") as fh:
            fh.write(_LFS_POINTER_HEADER + b"\n"
                     b"oid sha256:" + b"0" * 64 + b"\nsize 1234\n")
        check("an unpulled Git LFS pointer file is detected as one",
              _is_lfs_pointer(pointer_path))
        with open(pointer_path, "wb") as fh:
            fh.write(b'{"engine": "r2t-mutate", "mutants": []}')
        check("a real mutant catalogue is not mistaken for a pointer file",
              not _is_lfs_pointer(pointer_path))

    from .. import docker_authority as DA
    authority = DA._fixture_authority()
    route_detail = _daemon_route_preflight(authority)
    check("daemon route reports facts already validated by its authority",
          "rootless daemon" in route_detail
          and authority["adapter"]["resolved_socket_path"] in route_detail)
    overlay_ok, _overlay_detail = _storage_driver_preflight(authority)
    overlayfs = json.loads(json.dumps(authority))
    overlayfs["daemon"]["storage_driver"] = "overlayfs"
    overlayfs_ok, overlayfs_detail = _storage_driver_preflight(overlayfs)
    check("the Algorand image route requires classic overlay2",
          overlay_ok and not overlayfs_ok
          and "requires the classic overlay2" in overlayfs_detail)

    inventory_calls = []

    def empty_inventory(argv, *, timeout):
        inventory_calls.append((tuple(argv), timeout))
        return subprocess.CompletedProcess(argv, 0, "", "")

    empty_status, empty_detail = _daemon_inventory_preflight(empty_inventory)

    def post_provision_inventory(argv, *, timeout):
        del timeout
        stdout = ""
        if tuple(argv[:2]) == ("container", "ls"):
            stdout = "\n".join(f"worker-{index}" for index in range(4))
        elif tuple(argv[:2]) == ("image", "ls"):
            stdout = "sha256:fixture-image\n"
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    provisioned_status, provisioned_detail = _daemon_inventory_preflight(
        post_provision_inventory)

    def failed_inventory(argv, *, timeout):
        del timeout
        return subprocess.CompletedProcess(
            argv, 1, "", "daemon unavailable")

    failed_status, failed_detail = _daemon_inventory_preflight(
        failed_inventory)
    check("daemon inventory is pass when empty, warning when provisioned, "
          "and failure only when unreadable",
          empty_status == "pass"
          and empty_detail == "no containers, images, or volumes"
          and provisioned_status == "warn"
          and "'containers': 4" in provisioned_detail
          and "'images': 1" in provisioned_detail
          and failed_status == "fail"
          and "cannot inspect containers" in failed_detail
          and inventory_calls == [
              (("container", "ls", "--all", "--quiet"), 30),
              (("image", "ls", "--all", "--quiet", "--no-trunc"), 30),
              (("volume", "ls", "--quiet"), 30)])

    registry_calls = []

    def readable_registry():
        registry_calls.append("read")
        return {"repository": "ghcr.io/example/image",
                "manifest_digest": "sha256:" + "a" * 64}

    registry_ok, registry_detail = _registry_package_preflight(
        "algorand-sdk", readable_registry)
    no_registry = _registry_package_preflight(
        "coreshop", lambda: registry_calls.append("wrong"))

    def denied_registry():
        raise ValueError("HTTP 403")

    denied, denied_detail = _registry_package_preflight(
        "algorand-sdk", denied_registry)
    check("registry-read preflight is limited to the anonymous image route",
          registry_ok and "without client credentials" in registry_detail
          and no_registry is None and registry_calls == ["read"]
          and not denied and "credential-free" in denied_detail)

    with open(B.DATASET_MANIFEST, encoding="utf-8") as handle:
        declared = set(json.load(handle)["projects"])
    algorand, algorand_version = _project_boundary("algorand-sdk")
    # Not an exact tuple: pinning the literal here made admitting a project
    # break this gate until someone edited the gate too, which is a
    # disincentive rather than a check.  What the routes have to satisfy is
    # that they are the manifest's projects plus the named residuals and
    # nothing else, and that each route can actually be preflighted.  A
    # residual that the manifest later declares itself is a duplicate the
    # set comparison would not see, so it is refused separately: the fix is
    # to delete that name from RESIDUAL_PROJECTS.
    check("doctor's consumer routes are the manifest's projects plus the "
          "named residuals",
          set(SUPPORTED_PROJECTS) == declared | set(RESIDUAL_PROJECTS)
          and not declared & set(RESIDUAL_PROJECTS)
          and set(MANIFEST_PROJECTS) == declared
          and algorand["project"] == "algorand-sdk"
          and algorand["bundle_version"] == 2
          and algorand_version == "2"
          and all(_project_profile(project).project == project
                  for project in SUPPORTED_PROJECTS),
          str({"routes": SUPPORTED_PROJECTS, "declared": sorted(declared)}))

    with tempfile.TemporaryDirectory() as manifest_dir:
        other = os.path.join(manifest_dir, "dataset_manifest.json")
        with open(other, "w", encoding="utf-8") as handle:
            json.dump({"projects": {"zeta": {}, "alpha": {}}}, handle)
        derived = _manifest_projects(other)
    check("the project enums are derived from the manifest they are given",
          derived == ("alpha", "zeta"), str(derived))

    check("both bundle-backed projects require a production method index",
          _project_profile("coreshop").api_scoring == "method_index"
          and _project_profile("python-docx").api_scoring == "method_index")

    declaration, readiness_version = _project_boundary("coreshop")
    declaration = json.loads(json.dumps(declaration))
    readiness_profile = _project_profile("coreshop")
    validated_fact = {
        "project": "coreshop", "version": readiness_version}
    ready_rows = {row["name"]: row for row in _metric_readiness(
        "coreshop", readiness_version, declaration, readiness_profile,
        validated_fact)}
    check("a matching validated-bundle fact leaves mutation preserved-only "
          "while the non-mutation enabled metrics are ready",
          ready_rows[MUTATION_READINESS_ROW]["status"] == "fail"
          and "preserved-evidence-only" in ready_rows[
              MUTATION_READINESS_ROW]["detail"]
          and all(ready_rows[name]["status"] == "pass"
                  for name in (COVERAGE_READINESS_ROW,
                               "production method index")),
          str(ready_rows))

    disabled = json.loads(json.dumps(declaration))
    disabled["capabilities"]["mutation"] = False
    disabled["capabilities"]["coverage"] = False
    disabled["capability_notes"]["mutation"] = \
        "fixture deliberately disables mutation"
    disabled["capability_notes"]["coverage"] = \
        "fixture deliberately disables coverage"
    disabled_rows = {row["name"]: row for row in _metric_readiness(
        "coreshop", readiness_version, disabled, readiness_profile,
        validated_fact)}
    check("disabled capabilities fail with their declared note and stable "
          "campaign reason",
          disabled_rows[MUTATION_READINESS_ROW]["status"] == "fail"
          and "no_mutants" in disabled_rows[
              MUTATION_READINESS_ROW]["detail"]
          and "deliberately disables mutation" in disabled_rows[
              MUTATION_READINESS_ROW]["detail"]
          and disabled_rows[COVERAGE_READINESS_ROW]["status"] == "fail"
          and "not_scored_coverage" in disabled_rows[
              COVERAGE_READINESS_ROW]["detail"],
          str(disabled_rows))

    closed_rows = {row["name"]: row for row in _metric_readiness(
        "coreshop", readiness_version, declaration, readiness_profile,
        validated_fact)}
    check("the current closed live producer fails mutation readiness without "
          "hiding ready coverage or API similarity",
          closed_rows[MUTATION_READINESS_ROW]["status"] == "fail"
          and "preserved-evidence-only" in closed_rows[
              MUTATION_READINESS_ROW]["detail"]
          and closed_rows[COVERAGE_READINESS_ROW]["status"] == "pass"
          and closed_rows["production method index"]["status"] == "pass",
          str(closed_rows))

    missing_declaration = json.loads(json.dumps(declaration))
    missing_declaration["bundle"]["artifacts"].pop("gold_baseline")
    missing_declaration_rows = {
        row["name"]: row for row in _metric_readiness(
            "coreshop", readiness_version, missing_declaration,
            readiness_profile, validated_fact)}
    check("an undeclared metric role fails by metric and names the role",
          all(missing_declaration_rows[name]["status"] == "fail"
              for name in (MUTATION_READINESS_ROW,
                           COVERAGE_READINESS_ROW))
          and "['gold_baseline']" in missing_declaration_rows[
              MUTATION_READINESS_ROW]["detail"]
          and "gold_baseline (undeclared)" in missing_declaration_rows[
              COVERAGE_READINESS_ROW]["detail"]
          and "no_gold_run" in missing_declaration_rows[
              COVERAGE_READINESS_ROW]["detail"],
          str(missing_declaration_rows))

    wrong_project_rows = {row["name"]: row for row in _metric_readiness(
        "coreshop", readiness_version, declaration, readiness_profile,
        {"project": "python-docx", "version": readiness_version})}
    wrong_version_rows = {row["name"]: row for row in _metric_readiness(
        "coreshop", readiness_version, declaration, readiness_profile,
        {"project": "coreshop", "version": "another-version"})}
    check("validated-bundle facts cannot cross project or version identity",
          all(wrong_project_rows[name]["status"] == "fail"
              and "names project 'python-docx'" in
              wrong_project_rows[name]["detail"]
              for name in GENERATION_READINESS_ROWS)
          and all(wrong_version_rows[name]["status"] == "fail"
                  and "names version 'another-version'" in
                  wrong_version_rows[name]["detail"]
                  for name in GENERATION_READINESS_ROWS),
          str((wrong_project_rows, wrong_version_rows)))

    from ..bench import seed as S
    with tempfile.TemporaryDirectory() as readiness_root:
        artifacts = declaration["bundle"]["artifacts"]
        directory_roles = {"gold", "release_gold", "seed"}
        for role, relative in artifacts.items():
            if relative is None:
                continue
            path = os.path.join(readiness_root, relative)
            if role in directory_roles:
                os.makedirs(path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("{}\n")
        seed_manifest = os.path.join(
            readiness_root, artifacts["seed"], S.SEED_MANIFEST)
        with open(seed_manifest, "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        all_roles_present = all(
            (os.path.isdir if role in directory_roles else os.path.isfile)(
                os.path.join(readiness_root, relative))
            for role, relative in artifacts.items() if relative is not None)
        try:
            B.validate_installed_bundle(
                "coreshop", readiness_version, readiness_root)
        except B.BundleRefused as exc:
            corrupt_refusal = exc
        else:
            corrupt_refusal = None
        corrupt_rows = {row["name"]: row for row in _metric_readiness(
            "coreshop", readiness_version, declaration, readiness_profile,
            corrupt_refusal)}
    check("present declared paths cannot substitute for installed-bundle "
          "validation",
          all_roles_present
          and isinstance(corrupt_refusal, B.BundleRefused)
          and "seed manifest differs" in str(corrupt_refusal)
          and all(corrupt_rows[name]["status"] == "fail"
                  and "installed bundle validation refused" in
                  corrupt_rows[name]["detail"]
                  for name in GENERATION_READINESS_ROWS),
          str((corrupt_refusal, corrupt_rows)))

    undeclared_rows = _metric_readiness(
        "algorand-sdk", algorand_version, algorand,
        _project_profile("algorand-sdk"),
        {"project": "algorand-sdk", "version": algorand_version})
    check("the current Algorand release index remains capability-undeclared",
          all(row["status"] == "fail"
              and "algorand-sdk" in row["detail"]
              and "undeclared" in row["detail"]
              for row in undeclared_rows),
          str(undeclared_rows))

    check("doctor checks the reproducible CoreShop successor without "
          "rewriting the historical measured image",
          _runtime_image("coreshop", {"harness_image": "historical"})
          == "coreshop_bench_img:repro-v1"
          and _runtime_image("python-docx", {
              "harness_image": "r2t_docx_img:base"})
          == "r2t_docx_img:base")

    from . import algorand_image as AI
    from ..bench import confine as C
    from ..core import docker_cli as DC
    saved_root = os.environ.get("R2T_DATA_ROOT")
    saved_umask = os.umask(0o022)
    saved_registry_probe = AI.preflight_public_registry
    saved_bwrap_probe = C.bwrap_probe
    saved_authority_reference = DC.authority_reference
    saved_coordinator_probe = globals()["_coordinator_requirements"]
    saved_inventory_probe = globals()["_daemon_inventory_preflight"]
    saved_bundle_validator = B.validate_installed_bundle
    bundle_validation_calls = []
    bundle_calls_per_doctor = []
    bundle_validation_refusal = {"value": None}

    def installed_bundle_validator(project, version, root):
        bundle_validation_calls.append((project, version, root))
        if bundle_validation_refusal["value"] is not None:
            raise B.BundleRefused(
                "REFUSED: " + bundle_validation_refusal["value"])
        return {"project": project, "version": version}

    def doctor_counting_bundle(*, project, profile_path=None, **kwargs):
        before = len(bundle_validation_calls)
        report = doctor(project=project, profile_path=profile_path, **kwargs)
        bundle_calls_per_doctor.append(len(bundle_validation_calls) - before)
        return report

    try:
        AI.preflight_public_registry = readable_registry
        C.bwrap_probe = lambda: {
            "usable": True, "version": "bubblewrap 0.6.1"}
        DC.authority_reference = lambda *, live: (authority, "fixture")
        B.validate_installed_bundle = installed_bundle_validator
        globals()["_coordinator_requirements"] = lambda: (
            True, "fixture coordinator requirements")
        with tempfile.TemporaryDirectory() as data_root:
            os.environ["R2T_DATA_ROOT"] = data_root
            globals()["_daemon_inventory_preflight"] = lambda: (
                saved_inventory_probe(empty_inventory))
            empty_report = doctor_counting_bundle(project="algorand-sdk")
            globals()["_daemon_inventory_preflight"] = lambda: (
                saved_inventory_probe(post_provision_inventory))
            provisioned_report = doctor_counting_bundle(
                project="algorand-sdk")

            # The external edge, counted.  `external_reads` is the wire:
            # every entry is one anonymous registry contact doctor made.
            external_reads = []

            def counted_registry():
                external_reads.append("read")
                return readable_registry()

            AI.preflight_public_registry = counted_registry
            authorized_report = doctor_counting_bundle(
                project="algorand-sdk")
            authorized_reads = len(external_reads)

            def refused_authority(*, live):
                del live
                raise DC.DockerEndpointRefused(
                    "REFUSED: the explicit authority does not validate on "
                    "this host")

            DC.authority_reference = refused_authority
            unauthorized_report = doctor_counting_bundle(
                project="algorand-sdk")
            unauthorized_reads = len(external_reads) - authorized_reads

            # A legacy route on a host that never minted an authority: the
            # first Docker argv refuses and the report has to survive it.
            saved_authority_path = DC.configured_authority_path()
            try:
                DC.configure(authority_path=None)
                bundle_validation_refusal["value"] = \
                    "fixture installed bundle bytes are corrupt"
                no_authority_report = doctor_counting_bundle(
                    project="coreshop")
                bundle_validation_refusal["value"] = None
                mismatched_profile_report = doctor_counting_bundle(
                    project="coreshop",
                    profile_path=os.path.join(
                        BENCHMARK, "config", "profile_python_docx.yml"))

                # The same host after `r2t worker plan`: saved manifests carry
                # doctor past the daemon row into the live worker, runtime and
                # confinement probes, each of which issues its own Docker argv
                # and therefore refuses again.  This is the documented
                # diagnosis target -- a prepared host invoked without
                # `--docker-authority` -- so it, too, owes a full report.
                workers_dir = os.path.join(
                    data_root, "projects", "coreshop", "workers")
                os.makedirs(workers_dir)
                for name in ("gold", "artifacts"):
                    os.makedirs(os.path.join(
                        data_root, "projects", "coreshop", name))
                for index in range(2):
                    prepared = WorkerSpec(
                        index=index,
                        workspace=os.path.join(
                            data_root, f"worker{index}", "app"),
                        container=f"c_{index}", schema=f"s_{index}",
                        credential=f"u_{index}",
                        env_file=os.path.join(
                            data_root, ".secrets", f"worker{index}.env"),
                        workdir="/var/www/html",
                        out_path=os.path.join(data_root, f"{index}.jsonl"),
                        artifacts_root=os.path.join(
                            data_root, f"artifacts{index}"))
                    with open(os.path.join(workers_dir, f"worker{index}.json"),
                              "w", encoding="utf-8") as fh:
                        json.dump(prepared.to_json(), fh)
                prepared_report = doctor_counting_bundle(project="coreshop")

                # A Go workspace uses /work just like the reviewed image.
                # Supply only the future bundle boundary here: the actual Go
                # profile, saved manifest reader and doctor route stay real.
                from dataclasses import replace
                from unittest.mock import patch
                go_layout = _layout("coddy-agent")
                for name in ("workers", "gold", "artifacts"):
                    os.makedirs(go_layout[name])
                go_worker = replace(
                    prepared, index=0, workdir="/work",
                    workspace=os.path.join(go_layout["project_root"], "worker0", "app"))
                go_manifest = os.path.join(go_layout["workers"], "worker0.json")
                with open(go_manifest, "w", encoding="utf-8") as fh:
                    json.dump(go_worker.to_json(), fh)
                with patch.dict(globals(), {"_project_boundary": lambda project: (None, None)}):
                    go_report = doctor(project="coddy-agent")
                    with open(go_manifest, "w", encoding="utf-8") as fh:
                        json.dump(replace(go_worker, workdir="/var/www/html").to_json(), fh)
                    go_wrong_report = doctor(project="coddy-agent")
                go_rows = {row["name"]: row for row in go_report["checks"]}
                go_wrong_rows = {row["name"]: row for row in go_wrong_report["checks"]}
                check("Go doctor accepts its /work worker and refuses a PHP workdir",
                      go_rows["saved worker manifests"]["status"] == "pass"
                      and go_rows["project database"]["status"] == "pass"
                      and go_wrong_rows["saved worker manifests"]["status"] == "fail"
                      and "project requires '/work'" in
                      go_wrong_rows["saved worker manifests"]["detail"],
                      str((go_rows["saved worker manifests"],
                           go_wrong_rows["saved worker manifests"])))

                # The same host after `environment up`.  That verb writes the
                # pool to environments/<nonce>/workers and names the database
                # r2t_<nonce>_database, so a doctor that reads the legacy
                # directory and the fixed alias reports FAIL on a host that
                # was just brought up successfully.  Docker is faked here
                # only so the two rows that need a live daemon -- project
                # image and project database -- are reached at all.
                from .environment import PROJECTS as ENVIRONMENTS
                from .environment_lifecycle import _database_resources
                from .environment_lifecycle import _write_record as _write_env
                from .environment_lifecycle import record_path as env_record

                nonce = "efixture01"
                environment_workers = os.path.join(
                    data_root, "projects", "coreshop", "environments",
                    nonce, "workers")
                os.makedirs(environment_workers)
                for index in range(2):
                    provisioned = WorkerSpec(
                        index=index,
                        workspace=os.path.join(
                            data_root, nonce, f"worker{index}", "app"),
                        container=f"{nonce}_{index}", schema=f"s_{index}",
                        credential=f"u_{index}",
                        env_file=os.path.join(
                            data_root, ".secrets", f"{nonce}{index}.env"),
                        workdir="/var/www/html",
                        out_path=os.path.join(data_root, f"{nonce}{index}.jsonl"),
                        artifacts_root=os.path.join(
                            data_root, f"artifacts-{nonce}{index}"))
                    with open(os.path.join(environment_workers,
                                           f"worker{index}.json"),
                              "w", encoding="utf-8") as fh:
                        json.dump(provisioned.to_json(), fh)
                _write_env(env_record("coreshop", nonce), {
                    "schema": "r2t.project-environment/v1",
                    "project": "coreshop", "nonce": nonce,
                    "created_at": "2026-08-25T00:00:00Z", "state": "up",
                    "k": 2, "workers_root": environment_workers,
                    "workdir": "/var/www/html", "container_kind": "php",
                    "image": {"tag": "coreshop_bench_img:repro-v1",
                              "id": "sha256:" + "c" * 64},
                    "docker_execution_authority": {
                        "path": "/private/authority.json",
                        "file_sha256": "e" * 64, "digest": "f" * 64},
                    "database": _database_resources(
                        ENVIRONMENTS["coreshop"], nonce, 2),
                    "gold_control": {
                        "item": "coreshop/features/fixture.feature:1",
                        "out": os.path.join(data_root, "gold-control.jsonl"),
                        "outcome": "passed", "passed": True},
                })

                docker_probes = []

                def fake_worker_docker(argv, **kwargs):
                    del kwargs
                    docker_probes.append(tuple(argv))
                    if argv[0] == "info":
                        return subprocess.CompletedProcess(
                            argv, 0, REFERENCE["docker"], "")
                    if argv[:2] == ["image", "inspect"]:
                        return subprocess.CompletedProcess(
                            argv, 0, "sha256:" + "c" * 64, "")
                    if argv[0] == "inspect":
                        return subprocess.CompletedProcess(argv, 0, "true", "")
                    return subprocess.CompletedProcess(
                        argv, 1, "", "fixture daemon has no such object")

                from ..bench import worker as W_module
                saved_worker_docker = W_module._docker
                try:
                    W_module._docker = fake_worker_docker
                    environment_report = doctor_counting_bundle(
                        project="coreshop")
                finally:
                    W_module._docker = saved_worker_docker

                # `--llm-config` names a private file; the default is inside
                # the checkout, where writing credentials dirties the tree
                # the Docker execution authority attests.
                absent_config = os.path.join(data_root, "absent-model.json")
                missing_config_report = doctor_counting_bundle(
                    project="coreshop", agent="aider",
                    llm_config=absent_config)
                named_config = os.path.join(data_root, "model-config.json")
                with open(named_config, "w", encoding="utf-8") as fh:
                    json.dump({"model": "fixture-model"}, fh)
                named_config_report = doctor_counting_bundle(
                    project="coreshop", agent="aider",
                    llm_config=named_config)
            finally:
                DC.configure(authority_path=saved_authority_path)
    finally:
        globals()["_daemon_inventory_preflight"] = saved_inventory_probe
        globals()["_coordinator_requirements"] = saved_coordinator_probe
        B.validate_installed_bundle = saved_bundle_validator
        DC.authority_reference = saved_authority_reference
        C.bwrap_probe = saved_bwrap_probe
        AI.preflight_public_registry = saved_registry_probe
        os.umask(saved_umask)
        if saved_root is None:
            os.environ.pop("R2T_DATA_ROOT", None)
        else:
            os.environ["R2T_DATA_ROOT"] = saved_root

    empty_rows = {row["name"]: row for row in empty_report["checks"]}
    provisioned_rows = {
        row["name"]: row for row in provisioned_report["checks"]}
    check("Algorand doctor reports undeclared metric readiness while retaining "
          "empty or post-provision inventory diagnostics",
          not empty_report["ok"] and not provisioned_report["ok"]
          and all(empty_rows[name]["status"] == "fail"
                  and "undeclared" in empty_rows[name]["detail"]
                  for name in (MUTATION_READINESS_ROW,
                               COVERAGE_READINESS_ROW))
          and empty_rows["Docker daemon inventory"]["status"] == "pass"
          and provisioned_rows[
              "Docker daemon inventory"]["status"] == "warn",
          render(empty_report) + render(provisioned_report))

    # The local checks every host is entitled to see, whatever its Docker
    # authority turns out to be.
    local_names = ("coordinator interpreter", "coordinator requirements",
                   "host operating system", "host architecture",
                   "bubblewrap usable", "process umask",
                   "project configuration", "data root")
    authorized_names = [row["name"] for row in authorized_report["checks"]]
    unauthorized_rows = {
        row["name"]: row for row in unauthorized_report["checks"]}
    check("the registry read happens once, after every local check, and only "
          "under a validated authority",
          authorized_reads == 1 and unauthorized_reads == 0
          and authorized_names.index("registry package read")
          > authorized_names.index("Docker daemon inventory")
          and all(authorized_names.index("registry package read")
                  > authorized_names.index(name) for name in local_names)
          and "registry package read" not in unauthorized_rows
          and all(name in unauthorized_rows for name in local_names)
          and unauthorized_rows["Docker daemon access"]["status"] == "fail"
          and not unauthorized_report["ok"],
          render(authorized_report) + render(unauthorized_report))

    no_authority_rows = {
        row["name"]: row for row in no_authority_report["checks"]}
    check("a host with no minted authority still gets the whole local report",
          all(name in no_authority_rows for name in local_names)
          and no_authority_rows["Docker daemon access"]["status"] == "fail"
          and "requires --docker-authority"
          in no_authority_rows["Docker daemon access"]["detail"]
          and not no_authority_report["ok"],
          render(no_authority_report))
    expected_bundle_calls = [
        ("algorand-sdk", algorand_version, data_root),
        ("algorand-sdk", algorand_version, data_root),
        ("algorand-sdk", algorand_version, data_root),
        ("algorand-sdk", algorand_version, data_root),
        ("coreshop", readiness_version, data_root),
        ("coreshop", readiness_version, data_root),
        ("coreshop", readiness_version, data_root),
        ("coreshop", readiness_version, data_root),
        ("coreshop", readiness_version, data_root),
        ("coreshop", readiness_version, data_root),
    ]
    mismatched_profile_rows = {
        row["name"]: row for row in mismatched_profile_report["checks"]}
    check("doctor validates exactly one installed bundle at each completed "
          "project/data-root boundary and maps its refusal",
          bundle_calls_per_doctor == [1] * len(expected_bundle_calls)
          and bundle_validation_calls == expected_bundle_calls
          and no_authority_rows[COVERAGE_READINESS_ROW]["status"] == "fail"
          and "fixture installed bundle bytes are corrupt" in
          no_authority_rows[COVERAGE_READINESS_ROW]["detail"]
          and mismatched_profile_rows[
              "project configuration"]["status"] == "fail"
          and "python-docx" in mismatched_profile_rows[
              "project configuration"]["detail"],
          str((bundle_calls_per_doctor, bundle_validation_calls,
               no_authority_rows[COVERAGE_READINESS_ROW],
               mismatched_profile_rows["project configuration"])))

    prepared_rows = {row["name"]: row for row in prepared_report["checks"]}
    live_probes = ("live worker preflight", "saved runtime and verified seed",
                   "worker confinement certificate")
    check("a prepared host with no minted authority reports its live probes "
          "as rows rather than raising out of doctor",
          all(name in prepared_rows for name in local_names)
          and prepared_rows["saved worker manifests"]["status"] == "pass"
          and all(prepared_rows[name]["status"] == "fail"
                  for name in live_probes)
          and all("requires --docker-authority"
                  in prepared_rows[name]["detail"]
                  for name in ("live worker preflight",
                               "worker confinement certificate"))
          and not prepared_report["ok"],
          render(prepared_report))

    environment_rows = {row["name"]: row
                        for row in environment_report["checks"]}
    check("doctor inspects the pool `environment up` actually created: its "
          "nonce workers root and its nonce database container",
          environment_rows["saved worker manifests"]["status"] == "pass"
          and environment_workers
          in environment_rows["saved worker manifests"]["detail"]
          and f"environment {nonce}"
          in environment_rows["saved worker manifests"]["detail"]
          and environment_rows["project database"]["status"] == "pass"
          and f"r2t_{nonce}_database"
          in environment_rows["project database"]["detail"]
          and not any(W_module.DEFAULT_DB_CONTAINER in argv
                      for argv in docker_probes),
          render(environment_report) + str(docker_probes))

    check("free disk space and kernel keyring capacity are reported on every "
          "host, and neither can fail the report",
          all(name in rows for name in ("free disk space",
                                        "kernel keyring capacity")
              for rows in (environment_rows, no_authority_rows,
                           {row["name"]: row
                            for row in empty_report["checks"]}))
          and all(row["status"] in ("pass", "warn")
                  for report in (environment_report, empty_report,
                                 unauthorized_report)
                  for row in report["checks"]
                  if row["name"] in ("free disk space",
                                     "kernel keyring capacity")),
          render(environment_report))

    # Defect (a): `resolve_mutation_readiness` needs an admitted live
    # producer binding, which only paid generation can mint.  Grading its
    # absence as a host failure made `doctor` unable to exit 0 anywhere,
    # against `docs/OPERATOR.md`.  It is a host WARN and a paid-boundary
    # FAIL, and the three rows still failing below are the live pool probes
    # this in-process fixture cannot satisfy -- not metric readiness.
    escalated = {row["name"]: row for row
                 in generation_readiness_checks(environment_report)}
    check("preserved-evidence-only mutation readiness warns the host and "
          "still refuses paid generation",
          environment_rows[MUTATION_READINESS_ROW]["status"] == "warn"
          and "preserved-evidence-only"
          in environment_rows[MUTATION_READINESS_ROW]["detail"]
          and escalated[MUTATION_READINESS_ROW]["status"] == "fail"
          and escalated[MUTATION_READINESS_ROW]["detail"]
          == environment_rows[MUTATION_READINESS_ROW]["detail"]
          and escalated[COVERAGE_READINESS_ROW]["status"] == "pass"
          and sorted(row["name"] for row in environment_report["checks"]
                     if row["status"] == "fail") == sorted(live_probes),
          render(environment_report))

    check("a corrupt installed bundle still fails mutation readiness on the "
          "host, because that one is a host defect",
          no_authority_rows[MUTATION_READINESS_ROW]["status"] == "fail"
          and "fixture installed bundle bytes are corrupt"
          in no_authority_rows[MUTATION_READINESS_ROW]["detail"],
          str(no_authority_rows[MUTATION_READINESS_ROW]))

    missing_config_rows = {row["name"]: row
                           for row in missing_config_report["checks"]}
    named_config_rows = {row["name"]: row
                         for row in named_config_report["checks"]}
    check("the model row reads the named private configuration and refuses a "
          "path that is not there",
          missing_config_rows["resolved model agreement"]["status"] == "fail"
          and f"no model configuration at {absent_config}"
          in missing_config_rows["resolved model agreement"]["detail"]
          and named_config_rows[
              "resolved model agreement"]["status"] == "pass"
          and f"(from {named_config})"
          in named_config_rows["resolved model agreement"]["detail"],
          str((missing_config_rows["resolved model agreement"],
               named_config_rows["resolved model agreement"])))

    # The generation integration seam is entirely in-process.  Every expensive
    # or external dependency is replaced before cmd_generate resolves it, so
    # this proves call order and refusal without contacting a model, Docker,
    # the database, or the network.
    import contextlib
    import importlib
    import io
    from types import SimpleNamespace
    from .. import cli as CLI
    from ..bench import cli as bench_cli
    from ..bench import generate as G
    from ..data import release as REL
    from ..bench import runner as RUN
    doctor_module = importlib.import_module(f"{__package__}.doctor")

    generation_events = []
    generation_report = {"value": None}
    generation_stderr = {"value": None}
    limitation_before_launch = {"value": False}
    generation_profile_paths = []
    generation_model_failure = {"value": None}

    def fake_load_release(_path):
        generation_events.append("load")
        return [{"item_id": "fixture:1"}]

    def fake_boundary(_args):
        generation_events.append("boundary")
        return SimpleNamespace(project="fixture")

    def fake_admit(items, project, selected):
        generation_events.append("admit")
        return items, {"project": project, "selected": tuple(selected)}

    def fake_harness(_args):
        generation_events.append("harness")
        return object(), object(), object()

    def fake_build_adapter(_args, _harness):
        generation_events.append("adapter")

        def paid_adapter(_item):
            generation_events.append("paid adapter")
            return {}

        return paid_adapter

    def fake_run_stamp(_args, _adapter):
        generation_events.append("stamp")
        return {"fixture": True}

    def fake_generation_doctor(*, project, agent=None, profile_path=None):
        del project, agent
        generation_events.append("doctor")
        generation_profile_paths.append(profile_path)
        return generation_report["value"]

    def fake_agent_model_readiness(_args):
        generation_events.append("model readiness")
        if generation_model_failure["value"] is not None:
            raise SystemExit(generation_model_failure["value"])

    def fake_generate_all(_adapter, _items, _out, *, workers, stamp,
                          retry_failed):
        del workers, stamp, retry_failed
        generation_events.append("generate")
        limitation_before_launch["value"] = (
            "LIMITATION: --functional-only" in
            generation_stderr["value"].getvalue())
        return {"generated": 1}

    def fake_require_worker(_args):
        generation_events.append("worker")

    def fake_run_adapter(_harness, args, *, artifacts, adapter=None):
        del artifacts, adapter
        generation_events.append("run")
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write("fixture\n")
        return {"n": 0}

    saved_generation = {
        "boundary": bench_cli._boundary,
        "harness": bench_cli._harness,
        "generate_all": G.generate_all,
        "load_release": RUN._load_release,
        "run_stamp": RUN._run_stamp,
        "build_adapter": RUN.build_adapter,
        "admit": REL.admit_pre_execution,
        "doctor": doctor_module.doctor,
        "model_readiness": bench_cli._agent_model_readiness_boundary,
        "require_worker": bench_cli._require_bound_live_worker,
        "run_adapter": RUN.run_adapter,
    }

    def drive_generation(report, *, functional_only, coverage=True):
        generation_events.clear()
        generation_profile_paths.clear()
        limitation_before_launch["value"] = False
        generation_report["value"] = report
        stderr = io.StringIO()
        generation_stderr["value"] = stderr
        args = SimpleNamespace(
            release="fixture-items.jsonl", item=(), limit=None,
            out="fixture-output.jsonl", workers=1, retry_failed=False,
            functional_only=functional_only, coverage=coverage, profile=None,
            boundary="/tmp/fixture-config/boundary_fixture.yml",
            adapter="openhands", llm_config="/fixture/model-config.json",
            model="deepseek-v4-flash")
        message = ""
        rc = None
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(stderr):
            try:
                rc = bench_cli.cmd_generate(args)
            except SystemExit as exc:
                message = str(exc)
        return (rc, message, stderr.getvalue(), list(generation_events),
                limitation_before_launch["value"],
                list(generation_profile_paths))

    def drive_run(*, model_failure):
        generation_events.clear()
        generation_model_failure["value"] = model_failure
        with tempfile.TemporaryDirectory(prefix="r2t-readiness-run-") as root:
            out = os.path.join(root, "run.jsonl")
            args = SimpleNamespace(
                publication_v3=False, adapter="openhands", candidates=None,
                artifacts=root, out=out)
            with contextlib.redirect_stdout(io.StringIO()):
                try:
                    bench_cli.cmd_run(args)
                except SystemExit as exc:
                    message = str(exc)
                else:
                    message = ""
            return message, list(generation_events), os.path.lexists(out)

    ready_report = {"checks": [
        {"name": MUTATION_READINESS_ROW, "status": "pass",
         "detail": "fixture mutation ready"},
        {"name": COVERAGE_READINESS_ROW, "status": "pass",
         "detail": "fixture coverage ready"},
        {"name": "production method index", "status": "pass",
         "detail": "fixture API ready"},
    ]}
    closed_report = {"checks": [
        {"name": MUTATION_READINESS_ROW, "status": "fail",
         "detail": "not_scored_mutation: route closed"},
        {"name": COVERAGE_READINESS_ROW, "status": "pass",
         "detail": "fixture coverage ready"},
        {"name": "production method index", "status": "pass",
         "detail": "fixture API ready"},
    ]}
    try:
        bench_cli._boundary = fake_boundary
        bench_cli._harness = fake_harness
        G.generate_all = fake_generate_all
        RUN._load_release = fake_load_release
        RUN._run_stamp = fake_run_stamp
        RUN.build_adapter = fake_build_adapter
        REL.admit_pre_execution = fake_admit
        doctor_module.doctor = fake_generation_doctor
        bench_cli._agent_model_readiness_boundary = fake_agent_model_readiness
        bench_cli._require_bound_live_worker = fake_require_worker
        RUN.run_adapter = fake_run_adapter

        ready_generation = drive_generation(
            ready_report, functional_only=False)
        refused_generation = drive_generation(
            closed_report, functional_only=False)
        uncovered_generation = drive_generation(
            ready_report, functional_only=False, coverage=False)
        missing_row_generation = drive_generation(
            {"checks": ready_report["checks"][:-1]},
            functional_only=False)
        functional_generation = drive_generation(
            closed_report, functional_only=True, coverage=False)
        refused_run = drive_run(
            model_failure="REFUSED: invalid reasoning-history config")
        admitted_run = drive_run(model_failure=None)
    finally:
        bench_cli._boundary = saved_generation["boundary"]
        bench_cli._harness = saved_generation["harness"]
        G.generate_all = saved_generation["generate_all"]
        RUN._load_release = saved_generation["load_release"]
        RUN._run_stamp = saved_generation["run_stamp"]
        RUN.build_adapter = saved_generation["build_adapter"]
        REL.admit_pre_execution = saved_generation["admit"]
        doctor_module.doctor = saved_generation["doctor"]
        bench_cli._agent_model_readiness_boundary = \
            saved_generation["model_readiness"]
        bench_cli._require_bound_live_worker = \
            saved_generation["require_worker"]
        RUN.run_adapter = saved_generation["run_adapter"]

    check("ready generation calls doctor once at the final pre-paid boundary",
          ready_generation[0] == 0
          and ready_generation[3][-4:]
          == ["stamp", "doctor", "model readiness", "generate"]
          and ready_generation[3].count("doctor") == 1
          and ready_generation[3].count("model readiness") == 1
          and "paid adapter" not in ready_generation[3],
          str(ready_generation))
    check("an explicit boundary and omitted profile give doctor the same "
          "adjacent profile that generation uses",
          ready_generation[5]
          == ["/tmp/fixture-config/profile_fixture.yml"],
          str(ready_generation))
    check("default generation refuses unavailable full metric readiness "
          "before generate_all",
          refused_generation[0] is None
          and "full metric readiness is unavailable" in refused_generation[1]
          and refused_generation[3][-2:] == ["stamp", "doctor"]
          and "generate" not in refused_generation[3],
          str(refused_generation))
    check("full generation requires the selected plan to record coverage",
          uncovered_generation[0] is None
          and "not_scored_coverage" in uncovered_generation[1]
          and "--coverage" in uncovered_generation[1]
          and "generate" not in uncovered_generation[3],
          str(uncovered_generation))
    check("a malformed doctor report cannot omit one metric and reach launch",
          missing_row_generation[0] is None
          and "exactly one row" in missing_row_generation[1]
          and "production method index" in missing_row_generation[1]
          and "generate" not in missing_row_generation[3],
          str(missing_row_generation))
    check("functional-only prints its limitation before the one launch",
          functional_generation[0] == 0
          and functional_generation[4]
          and "LIMITATION: --functional-only" in functional_generation[2]
          and functional_generation[3][-4:]
          == ["stamp", "doctor", "model readiness", "generate"],
          str(functional_generation))
    check("ordinary run crosses the same model-readiness boundary before "
          "worker, harness, output, resume, item, or provider contact",
          refused_run == (
              "REFUSED: invalid reasoning-history config",
              ["model readiness"], False)
          and admitted_run[1:] == (
              ["model readiness", "worker", "harness", "run"], True),
          repr((refused_run, admitted_run)))

    help_output = io.StringIO()
    with contextlib.redirect_stdout(help_output), \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            CLI.main(["generate", "--help"])
            help_rc = None
        except SystemExit as exc:
            help_rc = exc.code
    check("generate exposes exactly the functional-only readiness override",
          help_rc == 0 and "--functional-only" in help_output.getvalue())

    doctor_help = io.StringIO()
    with contextlib.redirect_stdout(doctor_help), \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            CLI.main(["doctor", "--help"])
            doctor_help_rc = None
        except SystemExit as exc:
            doctor_help_rc = exc.code
    check("doctor offers the private model configuration on the command line",
          doctor_help_rc == 0 and "--llm-config" in doctor_help.getvalue())

    warning_only = {"checks": [
        {"status": "pass", "name": "functional", "detail": "ok"},
        {"status": "warn", "name": "identity", "detail": "untested"}],
        "ok": True}
    check("an untested identity warns without becoming a functional failure",
          "DOCTOR PASS" in render(warning_only))

    # The submitted-route environment row (amendment decision 7's guidance
    # half): a WARN with the `environment up` recommendation when no
    # accepted record exists -- never a FAIL, or `environment up`'s own
    # host preflight would refuse the command that discharges it -- and a
    # PASS naming the accepted nonce when one does.
    from .environment_lifecycle import _write_record, record_path
    saved_env_data_root = os.environ.get("R2T_DATA_ROOT")

    def docx_record(nonce, root):
        return {
            "schema": "r2t.project-environment/v1",
            "project": "python-docx", "nonce": nonce,
            "created_at": "2026-08-25T00:00:00Z", "state": "up", "k": 1,
            "workers_root": os.path.join(root, "projects", "python-docx",
                                         "environments", nonce, "workers"),
            "workdir": "/work", "container_kind": "py",
            "image": {"tag": "fixture:base",
                      "id": "sha256:" + "d" * 64},
            "docker_execution_authority": {
                "path": "/private/authority.json",
                "file_sha256": "e" * 64, "digest": "f" * 64},
            "database": None,
            "gold_control": {
                "item": "python-docx/features/api.feature:1",
                "out": os.path.join(root, "gold-control.jsonl"),
                "outcome": "passed", "passed": True},
        }

    with tempfile.TemporaryDirectory() as tmp:
        try:
            os.environ["R2T_DATA_ROOT"] = tmp
            empty_records, empty_records_error = _environment_records(
                "python-docx")
            absent_status, absent_detail = _submitted_environment_row(
                empty_records, empty_records_error, "python-docx")
            legacy_pool, legacy_pool_error = _resolved_pool(empty_records)
            _write_record(record_path("python-docx", "edoc1"),
                          docx_record("edoc1", tmp))
            one_records, one_error = _environment_records("python-docx")
            present_status, present_detail = _submitted_environment_row(
                one_records, one_error, "python-docx")
            one_pool, one_pool_error = _resolved_pool(one_records)
            _write_record(record_path("python-docx", "edoc2"),
                          docx_record("edoc2", tmp))
            two_records, _two_error = _environment_records("python-docx")
            two_pool, two_pool_error = _resolved_pool(two_records)
        finally:
            if saved_env_data_root is None:
                os.environ.pop("R2T_DATA_ROOT", None)
            else:
                os.environ["R2T_DATA_ROOT"] = saved_env_data_root
    check("the submitted-route environment row warns with the "
          "`environment up` recommendation, and passes naming the accepted "
          "record",
          absent_status == "warn"
          and "environment up --project python-docx" in absent_detail
          and "environment_proven: false" in absent_detail
          and present_status == "pass"
          and "edoc1" in present_detail
          and "environment_proven: true" in present_detail,
          f"{absent_status}: {absent_detail} | "
          f"{present_status}: {present_detail}")
    check("the inspected pool is the saved environment's, the legacy layout "
          "only when no environment is saved, and neither when two are up",
          (legacy_pool, legacy_pool_error) == (None, None)
          and one_pool_error is None
          and one_pool["workers_root"].endswith(
              os.path.join("environments", "edoc1", "workers"))
          and two_pool is None
          and "2 environments are up" in two_pool_error
          and "'edoc1', 'edoc2'" in two_pool_error
          and "environment down --project python-docx" in two_pool_error,
          str((legacy_pool, one_pool, two_pool_error)))

    print("\n" + ("ALL PASS (doctor)" if ok else "FAILURES (doctor)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
