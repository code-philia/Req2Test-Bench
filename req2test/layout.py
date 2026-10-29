"""Where the front-end keeps its files, and where a kit keeps its inputs.

Everything the harness writes lives under one work root, never inside the git
clone (the engine's Docker-authority verifier refuses outputs there):

    $REQ2TEST_HOME (default ~/.req2test)
      data/dataset-v1.0/                 dataset (REQ2TEST_DATA_DIR overrides)
      kits/<project>/<kit_version>/      evaluation kits (kit.json + files)
      envs/<project>/<nonce>/            execution environments (req2test.env)
      engine/                            the engine's data root (staged inputs)
      runs/<run_id>/<project>/<view>/    one evaluation's outputs
      runs/<run_id>/summary.json, report.md

Kits are loaded with `req2test.kits.load_kit`.  `kit_inputs` names the kit
files the front-end reads: the execution inputs from `req2test.env`'s
per-project descriptor, and the behaviour and mutation references from
`kit.json` (falling back to the KIT_SPEC layout), so a caller never parses
kit.json itself.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .kits import Kit, load_kit

__all__ = ["Kit", "KitInputs", "load_kit", "kit_inputs", "home", "data_dir",
           "run_root", "run_dir", "open_text", "read_json",
           "iter_jsonl", "decompressed", "extract_tree"]


def home() -> Path:
    from .kits import req2test_home
    return req2test_home()


def data_dir() -> Path:
    from .dataset import default_data_dir
    return default_data_dir()


def runs_root() -> Path:
    return home() / "runs"


def run_root(run_id: str) -> Path:
    if not run_id or "/" in run_id or run_id in (".", ".."):
        raise ValueError(f"invalid run id {run_id!r}")
    return runs_root() / run_id


def run_dir(run_id: str, project: str, view: str) -> Path:
    return run_root(run_id) / project / view


# ---------------------------------------------------------- kit inputs
def _first(*values):
    for value in values:
        if value:
            return value
    return None


def _file_of(value) -> Optional[str]:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("file") or value.get("path")
    return None


@dataclass
class KitInputs:
    """The kit files the front-end reads beside the execution environment.

    Execution inputs (seed, gold tree, release, worker profile) are
    `req2test.env`'s per-project descriptor; this adds the behaviour
    references, the mutation reference and the task profiles.
    """
    kit: Kit
    release_items: Path
    boundary: Path
    worker_profile: Path
    view_profiles: dict
    needs_database: bool
    max_k_hint: Optional[int]
    timeout: int
    gold_run: Optional[Path]
    prod_index: Optional[Path]
    api_profile: Optional[Path]
    i_api: Optional[Path]
    i_cov: Optional[Path]
    mutation: dict = field(default_factory=dict)

    def view_profile(self, view: str) -> Path:
        if view not in self.view_profiles:
            raise KeyError(f"kit {self.kit.project} names no {view} profile")
        return self.view_profiles[view]


def kit_inputs(kit: Kit) -> KitInputs:
    from .env import descriptor
    d = descriptor(kit.project)
    meta = kit.meta
    ex = meta.get("exec_env") or {}
    worker = ex.get("worker") or {}
    beh = meta.get("behaviour") or {}
    mut = meta.get("mutation") or {}
    mfiles = mut.get("files") or {}
    p = kit.path

    def opt(value):
        return p(value) if value else None

    def default(rel_path):
        return rel_path if (kit.root / rel_path).exists() else None

    mutation = {
        "engine": mut.get("engine"),
        "manifest": opt(_first(mfiles.get("manifest"),
                               default("mutation/manifest.json.zst"))),
        "pools": opt(_first(mfiles.get("pools"),
                            default("mutation/pools.jsonl.zst"))),
        "reference_excluded": opt(_first(
            mfiles.get("reference_excluded"),
            default("mutation/reference_excluded.jsonl"))),
        "rules": opt(_first(mfiles.get("rules"),
                            default("mutation/rules.json"))),
        "sample": opt(_first(mfiles.get("sample"),
                             default("mutation/sample.json"))),
        "java_analysis_root": opt(_file_of(mut.get("java_analysis_root"))),
        # Go mutation preparation reads closures.json, go_prod_index.json and
        # go_interface_attribution.json beside each worker's artifacts.
        "go_artifacts": opt(_first(mfiles.get("go_artifacts"),
                                   default("mutation/go"))),
        # A gold-tree strip manifest the mutation route uses instead of the
        # execution one (e-petitions r2: the mutation root's 1,370 substrate
        # digests; the execution gold tree records none).
        "strip_manifest": opt(_first(
            mfiles.get("strip_manifest"),
            default("mutation/engine/strip_manifest.json"))),
    }
    return KitInputs(
        kit=kit,
        release_items=p(d["release_items"]),
        boundary=p(d["boundary"]),
        worker_profile=p(d["profile"]),
        view_profiles={view: p(rel) for view, rel in d["profiles"].items()},
        needs_database=d["database"] is not None,
        max_k_hint=worker.get("max_k_hint"),
        timeout=int(ex.get("timeout_seconds") or worker.get("timeout_seconds")
                    or mut.get("timeout_seconds") or 600),
        gold_run=opt(_first(_file_of(beh.get("gold_run")),
                            default("behaviour/gold_run.jsonl.zst"))),
        prod_index=opt(_first(_file_of(beh.get("prod_index")),
                              default("behaviour/prod_index.json"),
                              default("behaviour/prod_index.json.zst"))),
        api_profile=opt(_first(_file_of(beh.get("api_profile")),
                               default("behaviour/api_profile.yml"))),
        i_api=opt(_first(_file_of(beh.get("I_api")),
                         default("behaviour/I_api.json"))),
        i_cov=opt(_first(_file_of(beh.get("I_cov")),
                         default("behaviour/I_cov.json"))),
        mutation=mutation,
    )


def release_item_ids(kit: Kit) -> set:
    """The instance ids the kit's execution release can run."""
    release = kit_inputs(kit).release_items
    return {row["item_id"] for row in iter_jsonl(release)}


#: The refusal of `--split full` where the kit cannot execute all of it.
DATA_ONLY = "the full split is data-only for {project}; use --split eval"
#: The projects whose `--split full` executes: the kit's execution release
#: and the source views cover every full instance (python-docx, 239 of
#: 239).  Elsewhere the full split is data only; CoreShop's kit, for
#: example, has gold for 334 of its 422, and coddy-agent's views cover 274
#: of its 282.
FULL_SPLIT_PROJECTS = frozenset({"python-docx"})


def check_split(project: str, split: str) -> None:
    """Refuse `--split full` outside `FULL_SPLIT_PROJECTS` (`tasks` and
    `evaluate` alike, whatever part of the split is chosen)."""
    if split == "full" and project not in FULL_SPLIT_PROJECTS:
        raise ValueError(DATA_ONLY.format(project=project))


# --------------------------------------------------------------- helpers
def open_text(path: Path):
    """A text reader for `path`, decompressing a `.zst` file."""
    path = Path(path)
    if path.suffix != ".zst":
        return open(path, encoding="utf-8")
    import io
    try:
        import zstandard
    except ImportError:
        import subprocess
        out = subprocess.run(["zstd", "-dc", str(path)], check=True,
                             capture_output=True).stdout
        return io.StringIO(out.decode("utf-8"))
    raw = open(path, "rb")
    reader = zstandard.ZstdDecompressor().stream_reader(raw, closefd=True)
    return io.TextIOWrapper(reader, encoding="utf-8")


def read_json(path: Path):
    with open_text(path) as fh:
        return json.load(fh)


def iter_jsonl(path: Path):
    with open_text(path) as fh:
        for number, line in enumerate(fh, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{number}: not JSON: {exc}") \
                        from exc


def decompressed(path: Path, out_dir: Path) -> Path:
    """`path` itself, or a decompressed copy of a `.zst` file in `out_dir`.

    The engine opens its inputs by path with plain `open`, so compressed kit
    files are expanded once beside the run or environment that reads them.
    """
    path = Path(path)
    if path.suffix != ".zst":
        return path
    target = Path(out_dir) / path.name[:-len(".zst")]
    stamp = target.with_name(target.name + ".source")
    source_id = f"{path}:{path.stat().st_size}:{path.stat().st_mtime_ns}"
    if target.exists() and stamp.exists() \
            and stamp.read_text(encoding="utf-8") == source_id:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    with open_text(path) as src, open(tmp, "w", encoding="utf-8") as dst:
        for block in iter(lambda: src.read(1 << 20), ""):
            dst.write(block)
    os.replace(tmp, target)
    stamp.write_text(source_id, encoding="utf-8")
    return target


def extract_tree(archive: Path, target: Path, inner: Optional[str] = None) -> Path:
    """Unpack a kit `.tar`/`.tar.zst` once into `target`; return the tree.

    The tree is `target/<inner>` when the kit names an inner directory, else
    the archive's single top-level directory when it has exactly one and no
    files beside it, else `target`.
    """
    import subprocess
    import tarfile
    archive, target = Path(archive), Path(target)
    marker = target.with_name(target.name + ".extracted")
    if not marker.is_file():
        tmp = target.with_name(target.name + ".tmp")
        if tmp.exists():
            import shutil
            shutil.rmtree(tmp)
        tmp.mkdir(parents=True)
        if archive.name.endswith(".zst"):
            unz = subprocess.Popen(["zstd", "-dc", str(archive)],
                                   stdout=subprocess.PIPE)
            tar = tarfile.open(fileobj=unz.stdout, mode="r|")
        else:
            unz, tar = None, tarfile.open(archive)
        with tar:
            if hasattr(tarfile, "data_filter"):
                tar.extractall(tmp, filter="data")
            else:                                      # Python < 3.10.12
                tar.extractall(tmp)
        if unz is not None and unz.wait() != 0:
            raise RuntimeError(f"zstd failed on {archive}")
        tmp.rename(target)
        marker.write_text(str(archive) + "\n", encoding="utf-8")
    if inner:
        return target / inner
    entries = list(target.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return target
