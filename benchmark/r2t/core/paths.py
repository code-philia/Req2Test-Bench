"""Portable runtime paths below the operator-owned data root."""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass


#: The `benchmark/` directory this package is installed under, and the asset
#: directories below it.  Centralised here so that how deep a module sits
#: below `benchmark/` is stated once instead of in every `dirname(__file__)`
#: chain that wants an asset.
BENCHMARK_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CONFIG_DIR = os.path.join(BENCHMARK_ROOT, "config")
RELEASE_DIR = os.path.join(BENCHMARK_ROOT, "release")
PROTOCOL_DIR = os.path.join(BENCHMARK_ROOT, "protocol")
SCHEMAS_DIR = os.path.join(BENCHMARK_ROOT, "schemas")


DATA_ROOT_ENV = "R2T_DATA_ROOT"


def data_root() -> str:
    """The configured data root, required only when a default is used."""
    root = os.environ.get(DATA_ROOT_ENV)
    if not root:
        raise SystemExit(
            "REFUSED: set R2T_DATA_ROOT to the benchmark data directory, "
            "or pass the path explicitly.")
    return os.path.abspath(root)


@dataclass(frozen=True)
class DataPath(os.PathLike):
    """A path that does not consult ``R2T_DATA_ROOT`` until materialized."""

    parts: tuple[str, ...]

    def __fspath__(self) -> str:
        return os.path.join(data_root(), *self.parts)

    def __str__(self) -> str:
        return os.fspath(self)

    def __repr__(self) -> str:
        return f"DataPath({os.path.join(*self.parts)!r})"


def data_path(*parts: str) -> DataPath:
    return DataPath(tuple(parts))


def project_path(project: str, *parts: str) -> DataPath:
    return data_path("projects", project, *parts)


def agent_python(agent: str) -> DataPath:
    return data_path("envs", agent, "bin", "python")


def resolve_config_path(path: str):
    """Resolve a recorded data-root-relative path; keep explicit absolutes."""
    return path if os.path.isabs(path) else data_path(*path.split("/"))


#: Released evidence can name the collection host's absolute paths.  This
#: operator setting says where those recorded directories are on this host:
#: `RECORDED=LOCAL` pairs separated by `:`.  RELEASE_ENGINEERING.md
#: ("Read recorded paths on another host") owns the procedure.
RECORDED_ROOTS_ENV = "R2T_RECORDED_ROOTS"


def recorded_roots() -> dict:
    """The declared `{RECORDED: LOCAL}` prefixes; malformed or nested refuses."""
    raw = os.environ.get(RECORDED_ROOTS_ENV, "")
    roots: dict = {}
    for entry in raw.split(os.pathsep) if raw else ():
        recorded, separator, local = entry.partition("=")
        if not separator or not all(
                os.path.isabs(p) and os.path.normpath(p) == p and p != "/"
                for p in (recorded, local)):
            raise ValueError(f"{RECORDED_ROOTS_ENV} entry {entry!r} is not an "
                             f"absolute, normalized RECORDED=LOCAL pair")
        if any(recorded == other or recorded.startswith(other + "/")
               or other.startswith(recorded + "/") for other in roots):
            raise ValueError(f"{RECORDED_ROOTS_ENV} repeats or nests recorded "
                             f"root {recorded!r}")
        roots[recorded] = local
    return roots


def locate_recorded(path: str) -> tuple:
    """Where a recorded absolute path is read on this host: `(path, used)`.

    The recorded path itself when it exists, with `used == {}`.  Otherwise the
    one declared recorded root containing it, rewritten below its local root,
    with `used == {RECORDED: LOCAL}`.  Nothing is searched for.  Callers verify
    the bytes they read exactly as at the recorded path, so a mapping changes
    only where evidence is found; a missing mapped file fails in that read.
    """
    roots = recorded_roots()
    if os.path.exists(path):
        return path, {}
    for recorded, local in roots.items():
        if path == recorded or path.startswith(recorded + "/"):
            return local + path[len(recorded):], {recorded: local}
    return path, {}


def selftest() -> int:
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        ok = ok and bool(condition)
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))

    saved = os.environ.pop(DATA_ROOT_ENV, None)
    try:
        lazy = project_path("p", "gold")
        check("constructing a default is lazy", isinstance(lazy, DataPath))
        try:
            os.fspath(lazy)
            refused = ""
        except SystemExit as exc:
            refused = str(exc)
        check("materializing a default requires R2T_DATA_ROOT",
              "set R2T_DATA_ROOT" in refused, refused)

        with tempfile.TemporaryDirectory() as root:
            os.environ[DATA_ROOT_ENV] = root
            check("the fixed project layout resolves below the data root",
                  os.fspath(lazy)
                  == os.path.join(root, "projects", "p", "gold"),
                  os.fspath(lazy))
            explicit = "/operator/chosen/path"
            check("an explicit absolute config path bypasses the resolver",
                  resolve_config_path(explicit) == explicit)
            from types import SimpleNamespace
            from ..bench import cli
            boundary = os.path.join(CONFIG_DIR, "boundary_python_docx.yml")
            args = SimpleNamespace(
                boundary=boundary, profile=None, artifacts=explicit,
                gold=cli.DEFAULT_GOLD, seed=cli.DEFAULT_SEED,
                workers_root=cli.DEFAULT_WORKERS)
            cli._bind_data_defaults(args)
            check("an explicit CLI path overrides its project default",
                  args.artifacts == explicit)
            check("remaining CLI defaults follow the selected project",
                  os.fspath(args.gold) == os.path.join(
                      root, "projects", "python-docx", "gold"),
                  os.fspath(args.gold))
    finally:
        if saved is None:
            os.environ.pop(DATA_ROOT_ENV, None)
        else:
            os.environ[DATA_ROOT_ENV] = saved

    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as here:
        recorded = os.path.join(here, "collection")
        local = os.path.join(here, "local")
        os.makedirs(os.path.join(local, "rows"))
        evidence = os.path.join(recorded, "rows", "view.json")
        with patch.dict(os.environ, {RECORDED_ROOTS_ENV: f"{recorded}={local}"}):
            check("a missing recorded path is read below its declared local root",
                  locate_recorded(evidence)
                  == (os.path.join(local, "rows", "view.json"), {recorded: local}))
            check("an undeclared missing path is returned unchanged, not searched",
                  locate_recorded("/elsewhere/view.json") == ("/elsewhere/view.json", {}))
            os.makedirs(os.path.dirname(evidence))
            open(evidence, "w").close()
            check("an existing recorded path is read in place, never remapped",
                  locate_recorded(evidence) == (evidence, {}))
        for bad in ("relative=/b", "/a=relative", "/a", "/a/=/b", "/=/b",
                    "/a=/b:", f"/a=/b{os.pathsep}/a=/c", f"/a=/b{os.pathsep}/a/x=/c"):
            with patch.dict(os.environ, {RECORDED_ROOTS_ENV: bad}):
                try:
                    locate_recorded(evidence)
                    refused = ""
                except ValueError as exc:
                    refused = str(exc)
            check(f"a malformed or ambiguous mapping {bad!r} refuses, even for "
                  f"an existing path", RECORDED_ROOTS_ENV in refused, refused)

    print("\n" + ("ALL PASS (paths)" if ok else "FAILURES (paths)"))
    return 0 if ok else 1
