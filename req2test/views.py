"""Target-hidden (TH) source views.

A source view is the read-only copy of a project that a test-generation system
sees: the project's readable files, with the reviewed implementation bodies of
the instance's targets replaced, some files omitted, and the contract
supplements (`TARGET_CONTRACTS.md` and the others the map names) added.  The engine's builder
(`r2t.toolkit.source_views`, `r2t.core.source_view`) defines the views and
their manifests; this module ships them prebuilt.

Per project, under `<views dir>/<project>/` (default
`$REQ2TEST_HOME/views/<project>/`):

    views.json            header: inputs, shared manifest bindings, archive
                          sizes, the build's checks, the transformer and the
                          repair counts
    manifests.jsonl       one row per instance: manifest digest, files
                          digest, per-instance manifest fields, the overlay
                          id and the applied repairs as `[path, rule]`
    base.tar.zst          readable projection of the seed plus contract files
    th_overlays.tar.zst   blobs/<sha256> (changed files) and
                          overlays/<id>.json (changed paths, omitted paths);
                          an overlay id is the sha256 of its JSON bytes

`req2test views materialize` copies the base tree, applies the instance's
overlay, rebuilds the engine manifest from the files on disk and
checks its digest against `manifests.jsonl`.  It needs the `zstd` command and
no JDK, Go or tree-sitter.  `req2test views build --maintainer` builds the
TH archive set with the engine's
builder from the seed, the target-body map, the `_exec` profile, the c2r
protocol and the project's reviewed repairs; it needs the toolchains the
engine's source-view parsers use.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import ENGINE_ROOT, REPO_ROOT

SCHEMA = "req2test.views/1"
VIEWS = {"th": "target_hidden"}
#: Prefix of the unpacked overlay cache `materialize` keeps beside the archives.
OVERLAY_CACHE = ".th_overlays-"
#: Manifest keys that differ between the instances of one view.
PER_ITEM_KEYS = ("item_id", "generated_operation_judgments",
                 "zero_body_treatment")
#: Manifest keys computed from the files on disk or from the selection.
TREE_KEYS = ("files", "files_digest", "hidden_bodies", "omitted_paths",
             "digest")


class ViewError(RuntimeError):
    """A view archive, input or materialized tree disagrees with its record."""


def _engine():
    """Import the vendored engine's source-view core (stdlib only)."""
    root = str(ENGINE_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from r2t.core import source_view
    return source_view


def views_home() -> Path:
    """`$REQ2TEST_HOME/views` (default `~/.req2test/views`)."""
    from .kits import req2test_home
    return req2test_home() / "views"


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------- zstd + tar

def _zstd() -> str:
    exe = shutil.which("zstd")
    if exe is None:
        raise ViewError("the `zstd` command is required (apt install zstd)")
    return exe


@contextlib.contextmanager
def _zstd_reader(path):
    """A stream of the decompressed bytes of `path` (the `zstd` command)."""
    # zstd's own complaint about a damaged file is replaced by the ViewError
    # the caller raises, which says what to do about it.
    proc = subprocess.Popen([_zstd(), "-q", "-d", "-c", "--", str(path)],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    ok = False
    try:
        yield proc.stdout
        # A tar reader stops at the end-of-archive marker; drain the
        # padding so zstd does not fail writing to a closed pipe.
        while proc.stdout.read(1 << 16):
            pass
        ok = True
    finally:
        if not ok:
            proc.kill()
        proc.stdout.close()
        if proc.wait() != 0 and ok:
            raise ViewError(f"zstd failed to decompress {path}; re-fetch the views")


@contextlib.contextmanager
def _zstd_writer(path, level=19):
    """A stream compressed into `path` (the `zstd` command)."""
    proc = subprocess.Popen([_zstd(), "-q", "-f", "-T0", f"-{level}",
                             "-o", str(path)], stdin=subprocess.PIPE)
    ok = False
    try:
        yield proc.stdin
        ok = True
    finally:
        if not ok:
            proc.kill()
        try:
            proc.stdin.close()
        except BrokenPipeError:
            pass
        if proc.wait() != 0 and ok:
            raise ViewError(f"zstd failed to compress {path}")


def write_archive(path, files) -> dict:
    """Write `{relative path: bytes}` as a deterministic `.tar.zst`.

    Regular files only, sorted, mode 0644, mtime 0, no owner names: the same
    files give the same tar bytes.  Returns the archive's size facts.
    """
    raw_bytes = 0
    with _zstd_writer(path) as out:
        with tarfile.open(fileobj=out, mode="w|",
                          format=tarfile.PAX_FORMAT) as tar:
            for rel in sorted(files):
                data = files[rel]
                info = tarfile.TarInfo(rel)
                info.size, info.mode, info.mtime = len(data), 0o644, 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                tar.addfile(info, io.BytesIO(data))
                raw_bytes += len(data)
    return {"sha256": _sha256_file(path), "bytes": os.path.getsize(path),
            "files": len(files), "raw_bytes": raw_bytes}


def _each_member(path, use) -> int:
    """Call `use(relative path, file object)` for each member of `path`.

    Regular files only.  A damaged archive (truncated, corrupt) raises
    `ViewError`, also when the damage shows while `use` reads a member.
    """
    sv = _engine()
    count = 0
    try:
        with _zstd_reader(path) as stream:
            with tarfile.open(fileobj=stream, mode="r|") as tar:
                for member in tar:
                    if not member.isfile():
                        raise ViewError(f"{path}: non-regular member {member.name!r}")
                    try:
                        sv._path(member.name)
                    except sv.ViewRefused as exc:
                        raise ViewError(f"{path}: {exc}") from exc
                    use(member.name, tar.extractfile(member))
                    count += 1
    except (tarfile.TarError, EOFError) as exc:
        raise ViewError(f"{path} is damaged ({exc}); re-fetch the views") from exc
    return count


def extract_archive(path, dest: Path) -> int:
    """Extract every member of `path` under `dest` (no clobber); file count."""
    def use(rel, fh):
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "xb") as out:
            shutil.copyfileobj(fh, out)
    return _each_member(path, use)


def read_archive(path) -> dict:
    files = {}
    _each_member(path, lambda rel, fh: files.__setitem__(rel, fh.read()))
    return files


# ------------------------------------------------------------- user side

def _project_dir(project: str, views_dir=None) -> Path:
    root = Path(views_dir).expanduser() if views_dir else views_home()
    pdir = root / project
    if not (pdir / "views.json").is_file():
        raise ViewError(f"no views for {project} under {root}: expected "
                        f"{pdir}/views.json (run `req2test fetch --views-only "
                        f"--project {project}`, or pass --views-dir)")
    return pdir


def load_header(project: str, views_dir=None) -> dict:
    pdir = _project_dir(project, views_dir)
    header = json.loads((pdir / "views.json").read_text(encoding="utf-8"))
    if header.get("schema") != SCHEMA or header.get("project") != project:
        raise ViewError(f"{pdir}/views.json is not a {SCHEMA} header for "
                        f"{project}")
    return header


def load_manifest_row(project: str, view: str, instance_id: str,
                      views_dir=None) -> dict:
    pdir = _project_dir(project, views_dir)
    with open(pdir / "manifests.jsonl", encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            if row["instance_id"] == instance_id and row["view"] == view:
                return row
    raise ViewError(f"{project} has no {view} view for instance "
                    f"{instance_id!r}")


def _overlay_store(pdir: Path, header: dict) -> Path:
    """`th_overlays.tar.zst` unpacked once beside it, keyed by its sha256."""
    digest = header["archives"]["th_overlays.tar.zst"]["sha256"]
    store = pdir / f"{OVERLAY_CACHE}{digest[:16]}"
    if store.is_dir():
        return store
    archive = pdir / "th_overlays.tar.zst"
    if _sha256_file(archive) != digest:
        raise ViewError(f"{archive}: sha256 is not the {digest} views.json "
                        f"records; re-fetch the views")
    staging = Path(tempfile.mkdtemp(prefix=".th_overlays.", dir=pdir))
    try:
        extract_archive(archive, staging)
        os.rename(staging, store)
    except BaseException as exc:
        shutil.rmtree(staging, ignore_errors=True)
        if isinstance(exc, OSError) and store.is_dir():
            return store  # another process filled the cache first
        raise
    return store


def apply_overlay(root: Path, overlay: dict, blob) -> None:
    """Remove the omitted paths and write the changed files under `root`."""
    sv = _engine()
    for rel in overlay["omitted_paths"]:
        target = root / sv._path(rel)
        if not target.is_file():
            raise ViewError(f"overlay omits {rel}, which the base lacks")
        target.unlink()
    for rel, digest in overlay["files"]:
        data = blob(digest)
        if _sha256(data) != digest:
            raise ViewError(f"overlay blob {digest} has other bytes")
        target = root / sv._path(rel)
        if not target.is_file():
            raise ViewError(f"overlay changes {rel}, which the base lacks")
        target.write_bytes(data)
    # Directories the omissions emptied are not part of a view.
    for rel in sorted({str(Path(p).parent) for p in overlay["omitted_paths"]},
                      key=len, reverse=True):
        current = root / rel
        while current != root and current.is_dir() and not any(current.iterdir()):
            current.rmdir()
            current = current.parent


def view_manifest(header: dict, row: dict, root: Path) -> dict:
    """The engine manifest (`r2t.agent-view/v1`) of the tree at `root`."""
    sv = _engine()
    from r2t.core.ledger_primitives import semantic_digest
    view = row["view"]
    shared = header["views"][view]
    files = [{"path": r.path, "byte_length": r.byte_length,
              "file_sha256": r.file_sha256} for r in sv.inventory(str(root))]
    selection = row if view == "th" else shared
    manifest = {**shared["bindings"],
                "item_id": row["instance_id"],
                "generated_operation_judgments": row["generated_operation_judgments"],
                "zero_body_treatment": row["zero_body_treatment"],
                "files": files, "files_digest": sv.file_tree_digest(files),
                "hidden_bodies": selection["hidden_bodies"],
                "omitted_paths": selection["omitted_paths"]}
    manifest["digest"] = semantic_digest(manifest)
    return manifest


def materialize(project: str, view: str, instance_id: str, out_dir,
                *, views_dir=None, manifest_path=None) -> Path:
    """Write the instance's TH view to `out_dir` and check its digest.

    `out_dir` must not exist.  The view is checked against its recorded
    manifest digest; on any mismatch it is removed and `ViewError` raised.
    With `manifest_path`, the engine manifest is written there (outside the
    view).
    """
    if view not in VIEWS:
        raise ViewError(f"unknown view {view!r}; expected th")
    pdir = _project_dir(project, views_dir)
    header = load_header(project, views_dir)
    if view not in header["views"]:
        raise ViewError(f"the {project} views under {pdir.parent} have no "
                        f"{view} view")
    row = load_manifest_row(project, view, instance_id, views_dir)
    out = Path(out_dir).absolute()
    if os.path.lexists(out):
        raise ViewError(f"{out} already exists")
    if manifest_path is not None:
        manifest_path = Path(manifest_path).absolute()
        if manifest_path == out or out in manifest_path.parents:
            raise ViewError("the manifest must be written outside the view")
    try:
        out.mkdir(parents=True)
        extract_archive(pdir / "base.tar.zst", out)
        store = _overlay_store(pdir, header)
        overlay_raw = (store / "overlays" / f"{row['overlay']}.json").read_bytes()
        if _sha256(overlay_raw) != row["overlay"]:
            raise ViewError(f"overlay {row['overlay']} has other bytes")
        apply_overlay(out, json.loads(overlay_raw),
                      lambda d: (store / "blobs" / d).read_bytes())
        manifest = view_manifest(header, row, out)
        if manifest["files_digest"] != row["files_digest"] \
                or manifest["digest"] != row["digest"]:
            raise ViewError(
                f"{project} {view} {instance_id}: materialized view digest "
                f"{manifest['digest']} is not the recorded {row['digest']}")
        sv = _engine()
        sv.verify_agent_view(str(out), manifest)
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)
        raise
    if manifest_path is not None:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_path, "x", encoding="utf-8") as fh:
            json.dump(manifest, fh, sort_keys=True, indent=1)
            fh.write("\n")
    return out


# --------------------------------------------------------- maintainer side

@dataclass(frozen=True)
class Recipe:
    """The inputs of one project's benchmark 1.1 TH views.

    `map_sha256` and `seed_digest` are the `map_file_sha256` and
    `runtime_seed_digest` every recorded generation row of the project
    carries.
    `profile` names the `_exec` prompt profile,
    `config/profile_<profile>_checked_interfaces_target_hidden_exec.yml`, and
    `protocol` the project's c2r protocol (401-408), whose sha256 enters the
    view policy.  The project's reviewed repairs
    are read from `maps/<project>/th-view-repairs/` of the `--research`
    checkout (`r2t.toolkit.source_views.load_repairs`), and so is
    `go_release`, the release whose rows carry the Go suite contexts, unless
    `--release` names it.
    """
    profile: str
    protocol: int
    map: str
    map_sha256: str
    seed_digest: str
    go_release: str | None = None
    #: Readable files a provisioned worker workspace holds with other bytes
    #: than the seed archive (path -> sha256).  The recorded views were cut
    #: from provisioned workspaces, so the build adds these to the extracted
    #: seed; `prepare_view` then checks the whole projection against the
    #: map's `source_files_digest`.
    provisioned: dict = field(default_factory=dict)


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

RECIPES = {
    "python-docx": Recipe(
        "python_docx", 401,
        "git:maps/python-docx/target-map.v2.json",
        "c97f98a260cf137e68b9a267a2b407032035a44998e70bd7839e470c1890e285",
        "ce15261393e4f524c42d208db010097a8a7f532e6b0b700b1803712529424619"),
    "coreshop": Recipe(
        "coreshop", 402,
        "git:maps/coreshop/target_body_map.v2.json",
        "1c21524e680b4e0ac1e258cf666ea95875bf6ec39085e552a68d5d7245ce2fcb",
        "ef53d7bdb442948f32240e0a895e02027dd3ca3b9907bfd7bb3bc2cc4f2240d1",
        # Symfony regenerates it when a worker is provisioned
        # (maps/coreshop/README.md, "For the later re-validation gate").
        provisioned={"config/reference.php":
                     "54cf57845de4af28d9a95d9d6b03c428313efc5a87fc9db947ee281b876a93fe"}),
    "sylius": Recipe(
        "sylius", 404,
        "git:maps/sylius/target_body_map.checked_v2.json",
        "6989205a5a135d3a52becd8170494475077a9e652029e7d7357bbb103a056dcd",
        "4684969ad20842711c1d8a4150f3d8b1d195ae9eee597739663cc8313ced098a"),
    "coddy-agent": Recipe(
        "coddy_agent", 406,
        # The recorded rows bind this 274-item map, not maps/coddy-agent/full282.
        "git:maps/coddy-agent/target_body_map.checked_v2.json",
        "9a890527a142a6f7a3f069d0df24350988ecc9ebf448d33acd83ae1f6682896b",
        "a0314b326e3fdb52b3b93e0c829a634fab262267caab2ce7c9a8de25722ee655",
        go_release="benchmark/release/coddy-agent/items.jsonl"),
    "e-petitions": Recipe(
        "e_petitions", 408,
        "git:maps/e-petitions/target_body_map_v2_r2.json",
        "a8dbb2745c26a91af9a36452fa56a0c74d5019ea7f73f38050d2702a8e5a129a",
        "6c12a83d1bed090a69c170f703f59674ad3b453d3e3c5308b2d76e8a82eb388a",
        # The seed keeps `app/assets/builds` as an empty directory; the
        # provisioned workspace has upstream's empty `.keep` in it.
        provisioned={"app/assets/builds/.keep": EMPTY_SHA256}),
    "kapua": Recipe(
        "kapua", 405,
        "git:maps/kapua/census334/target_body_map.census330_v2.json",
        "c84a73f6d847b7cdc7c5ccbe6d81ba7c89ce353fd609249ab402c2602d5d9bdd",
        "15870dabe51f63feee87af57b4f0b53d747d23790f9133c4941914a1ea4d7bbf"),
    "algorand-sdk": Recipe(
        "algorand", 403,
        "release:algorand-sdk_source-view_maps_v1/map.v2.json",
        "0ef0d7d649a8da67d8ea819d2345ee8301b7b615a94125b1f250f2bcf22f930d",
        "2fb3b2747ef2b975e724f04ed877ec4ec057c1ade99eaa8917125c0704a6a24e"),
    "prestashop": Recipe(
        "prestashop", 407,
        "kit:prestashop/notes/target-map-draft/DRAFT-target_body_map.v2.json",
        "72b7229d962283702399ac62148d37dae6230d9739c03c55bbf28bb18faef766",
        "3928dce4faa9b733785c5e7a8fdd66593211e60c4babc79f359e2ca6dc00f827"),
}


@dataclass
class ViewInputs:
    """Resolved inputs of one project's TH view."""
    scope: str
    readable_paths: tuple
    profile_digest: str
    protocol_digest: str
    boundary_digest: str
    provenance: dict


def recipe_inputs(project: str) -> ViewInputs:
    """The recipe's `_exec` profile and c2r protocol, checked to agree on a
    final-only TH view."""
    _engine()
    from r2t.bench import protocol_file
    from r2t.data.profile import load_profile
    recipe = RECIPES[project]
    rel = f"config/profile_{recipe.profile}_checked_interfaces_target_hidden_exec.yml"
    profile = load_profile(str(ENGINE_ROOT / rel))
    protocol_path = protocol_file.path_for(recipe.protocol)
    protocol = protocol_file.load(protocol_path)
    if profile.project != project or profile.source_visibility != "target_hidden" \
            or protocol.get("visibility") != profile.raw.get("visibility") \
            or protocol["prompt_profile"]["prompt_digest"] != profile.prompt_digest \
            or protocol["condition"] != "c2r" or protocol.get("trials") != 0:
        raise ViewError(f"{project}: profile {rel} and protocol {recipe.protocol} "
                        f"do not agree on a final-only c2r target_hidden view")
    return ViewInputs(
        scope="target_hidden", readable_paths=tuple(profile.readable_paths),
        profile_digest=profile.digest,
        protocol_digest=_sha256_file(protocol_path),
        boundary_digest=_sha256_file(profile.boundary_path),
        provenance={"profile": f"benchmark/{rel}", "protocol": recipe.protocol,
                    "boundary": "benchmark/config/"
                                + os.path.basename(profile.boundary_path)})


def resolve_inputs(project: str, seed_dir, research=None, map_path=None):
    """Recipe inputs, checked: (map path, runtime seed digest, TH ViewInputs)."""
    recipe = RECIPES[project]
    if map_path is None:
        if not recipe.map.startswith("git:") or research is None:
            raise ViewError(f"{project}: pass --map ({recipe.map}), or "
                            f"--research <checkout> for a git map")
        map_path = Path(research) / recipe.map[len("git:"):]
    map_path = Path(map_path).absolute()
    if _sha256_file(map_path) != recipe.map_sha256:
        raise ViewError(f"{map_path}: sha256 is not the recorded map "
                        f"{recipe.map_sha256}")
    seed_dir = Path(seed_dir)
    doc = json.loads((seed_dir / "seed.json").read_text(encoding="utf-8"))
    if doc.get("workspace_seed_digest") != recipe.seed_digest \
            or _sha256_file(seed_dir / "workspace.tar") != recipe.seed_digest:
        raise ViewError(f"{seed_dir}: workspace.tar is not the recorded seed "
                        f"{recipe.seed_digest}")
    return map_path, recipe.seed_digest, recipe_inputs(project)


# Fork-shared state of one build (set before the worker pool forks).
_BUILD = {}


def _task(item_id):
    prepared = _BUILD["prepared"]
    task = {"item_id": item_id,
            prepared.annotation_field: prepared.annotations[item_id]}
    if _BUILD.get("go_suites") is not None:
        task["go_suite"] = _BUILD["go_suites"][item_id]
    return task


def _strip(manifest):
    return {k: v for k, v in manifest.items() if k != "files"}


def _build_item(item_id):
    """TH overlay, manifest (without file list) and applied repairs of one item."""
    scratch = Path(tempfile.mkdtemp(prefix="item.", dir=_BUILD["scratch"]))
    try:
        applied = []
        th = _BUILD["prepared"].materialize(_task(item_id), str(scratch / "th"),
                                            applied=applied)
        base = _BUILD["base_records"]
        records = {f["path"]: f for f in th["files"]}
        changed = {p: (scratch / "th" / p).read_bytes() for p, f in records.items()
                   if base.get(p) != f}
        # A file a repair adds sits at a path the map omitted, which the base
        # holds, so the overlay lists it as a changed file.
        if not set(changed) <= set(base):
            raise ViewError(f"{item_id}: TH view adds files the base lacks: "
                            f"{sorted(set(changed) - set(base))[:5]}")
        omitted = sorted(set(base) - set(records))
        return (item_id, _strip(th), changed, omitted,
                [(e.path, e.th_sha256, e.rule) for e in applied])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _check_item(args):
    """Materialize one (item, view) from the written archives; digest equal?"""
    item_id, view = args
    out = Path(tempfile.mkdtemp(prefix="check.", dir=_BUILD["scratch"])) / "v"
    try:
        materialize(_BUILD["project"], view, item_id, out,
                    views_dir=_BUILD["views_dir"])
        return item_id, view, None
    except Exception as exc:  # reported, not raised: the report lists all
        return item_id, view, f"{type(exc).__name__}: {exc}"
    finally:
        shutil.rmtree(out.parent, ignore_errors=True)


def _pool(jobs):
    import multiprocessing
    return multiprocessing.get_context("fork").Pool(jobs)


def repair_counts(prepared, results, eval_ids) -> dict:
    """What the project's repairs did in this build, for `views.json`.

    `results` are `_build_item`'s; `eval_ids` the eval split's instance ids.
    Raises `ViewError` when the build holds the whole eval split and an entry
    applied to none of its views: the map or
    the seed drifted away from the reviewed data.
    """
    eval_ids = set(eval_ids)
    applied, eval_applied = set(), set()
    views_repaired = eval_views_repaired = 0
    for item_id, _m, _c, _o, entries in results:
        keys = {(path, th) for path, th, _rule in entries}
        applied |= keys
        views_repaired += bool(keys)
        if item_id in eval_ids:
            eval_applied |= keys
            eval_views_repaired += bool(keys)
    built = {r[0] for r in results}
    counts = {"index_sha256": prepared.repair_index_sha256,
              "entries": len(prepared.repairs),
              "entries_applied": len(applied), "views_repaired": views_repaired,
              "eval_split_built": eval_ids <= built,
              "eval_views": len(eval_ids & built),
              "eval_entries_applied": len(eval_applied),
              "eval_views_repaired": eval_views_repaired}
    unapplied = [(e.path, e.rule) for e in prepared.repairs
                 if (e.path, e.th_sha256) not in eval_applied]
    if counts["eval_split_built"] and unapplied:
        raise ViewError(f"{prepared.policy.project}: {len(unapplied)} repair entries "
                        f"apply to no view of the eval split, e.g. {unapplied[:3]}; "
                        f"the map or seed differs from the reviewed repair data")
    return counts


def build_views(*, project, source_root, runtime_seed_digest, map_path,
                inputs, out_dir, scratch, eval_ids, item_ids=None, java=None,
                javac=None, go=None, go_suites=None, jobs=1, provenance=None,
                log=None) -> dict:
    """Build the 1.1 TH archive set of one project into `out_dir/<project>/`.

    `inputs` is the TH view's `ViewInputs`; `eval_ids` the eval split's
    instance ids of the project (`repair_counts`).  `go_suites` maps each map
    item to its released `go_suite` context (Go projects).  Every view is
    built by `PreparedView.materialize` (it applies the project's repairs and
    parses the transformed files), then materialized again from the written
    archives and its digest compared.  Returns the header written to
    `views.json`.
    """
    sv = _engine()
    from r2t.toolkit.source_views import prepare_view
    if log is None:
        def log(message):
            print(message, file=sys.stderr, flush=True)
    out = Path(out_dir) / project
    if os.path.lexists(out):
        raise ViewError(f"{out} already exists")
    scratch = Path(tempfile.mkdtemp(prefix=f"views-{project}.", dir=scratch))
    try:
        go_scratch = str(scratch / "go") if go_suites is not None else None
        log(f"[{project}] prepare th ({inputs.scope})")
        th = prepare_view(
            source_root=str(source_root), readable_paths=inputs.readable_paths,
            project=project, runtime_seed_digest=runtime_seed_digest,
            map_path=str(map_path), scope=inputs.scope,
            profile_digest=inputs.profile_digest, protocol_digest=inputs.protocol_digest,
            boundary_digest=inputs.boundary_digest, java=java, javac=javac, go=go,
            go_contexts=go_suites, go_scratch=go_scratch)
        map_items = [i.item_id for i in th.mapping.items]
        item_ids = list(map_items if item_ids is None else item_ids)
        missing = sorted(set(item_ids) - set(map_items))
        if missing:
            raise ViewError(f"{project}: {len(missing)} instances are not in the "
                            f"map, e.g. {missing[:3]}")
        _BUILD.clear()
        _BUILD.update(project=project, prepared=th, go_suites=go_suites,
                      scratch=str(scratch))
        # Base: the 'full' scope of the same map -- every readable file, no body
        # replaced, contracts added, no repair.
        full = sv.plan_agent_view(source_seed=th.seed, item_id=item_ids[0],
                                  policy=replace(th.policy, scope="full"),
                                  target_map=th.mapping)
        base_manifest = sv.build_agent_view(full, destination=str(scratch / "base"))
        _BUILD["base_records"] = {f["path"]: f for f in base_manifest["files"]}
        log(f"[{project}] base {len(base_manifest['files'])} files, "
            f"{len(th.repairs)} repair entries; building {len(item_ids)} instances")
        results = []
        with _pool(jobs) as pool:
            for n, result in enumerate(pool.imap(_build_item, item_ids, chunksize=1), 1):
                results.append(result)
                if n % 50 == 0 or n == len(item_ids):
                    log(f"[{project}] built {n}/{len(item_ids)}")
        repairs = repair_counts(th, results, eval_ids)
        # Shared bindings; per-item keys and tree keys go to the rows.
        sets = {json.dumps({k: v for k, v in r[1].items()
                            if k not in PER_ITEM_KEYS + TREE_KEYS}, sort_keys=True)
                for r in results}
        if len(sets) != 1:
            raise ViewError(f"{project} th: manifests disagree on shared bindings")
        shared = {"th": {"bindings": json.loads(sets.pop()),
                         "inputs": inputs.provenance}}
        # Archives.
        out.mkdir(parents=True)
        blobs, overlays, rows = {}, {}, []
        for item_id, m, changed, omitted, applied in results:
            files = []
            for rel, data in sorted(changed.items()):
                digest = _sha256(data)
                blobs[f"blobs/{digest}"] = data
                files.append([rel, digest])
            overlay_raw = _canonical({"files": files, "omitted_paths": omitted})
            overlay_id = _sha256(overlay_raw)
            overlays[f"overlays/{overlay_id}.json"] = overlay_raw
            rows.append({"instance_id": item_id, "view": "th", "digest": m["digest"],
                         "files_digest": m["files_digest"],
                         "generated_operation_judgments": m["generated_operation_judgments"],
                         "zero_body_treatment": m["zero_body_treatment"],
                         "overlay": overlay_id, "hidden_bodies": m["hidden_bodies"],
                         "omitted_paths": m["omitted_paths"],
                         "repairs": [[path, rule] for path, _th, rule in applied]})

        archives = {
            "base.tar.zst": write_archive(
                out / "base.tar.zst",
                {f["path"]: (scratch / "base" / f["path"]).read_bytes()
                 for f in base_manifest["files"]}),
            "th_overlays.tar.zst": write_archive(out / "th_overlays.tar.zst",
                                                 {**blobs, **overlays}),
        }
        with open(out / "manifests.jsonl", "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        header = {
            "schema": SCHEMA, "project": project,
            "instances": len(item_ids), "map_items": len(map_items),
            "transformer": th.policy.transformer,
            "views": shared,
            "visibility_run": {"th": th.identity},
            "base": {"files": len(base_manifest["files"]),
                     "files_digest": base_manifest["files_digest"]},
            "archives": archives,
            "overlays": {"distinct": len(overlays), "blobs": len(blobs)},
            "repairs": repairs,
            # PreparedView.materialize parsed every transformed file of every
            # TH view; a parse failure would have stopped the build.
            "parse_check": {
                "th_files_parsed": sum(len({b["path"] for b in r[1]["hidden_bodies"]})
                                       for r in results)},
            "provenance": provenance or {},
        }
        (out / "views.json").write_text(json.dumps(header, indent=1, sort_keys=True,
                                                   ensure_ascii=False) + "\n",
                                        encoding="utf-8")
        # Every view, materialized the user's way from the written archives.
        _BUILD["views_dir"] = str(out_dir)
        jobs_list = [(r["instance_id"], r["view"]) for r in rows]
        failures = []
        with _pool(jobs) as pool:
            for item_id, view, error in pool.imap_unordered(_check_item, jobs_list, chunksize=4):
                if error:
                    failures.append({"instance_id": item_id, "view": view, "error": error})
        for cache in out.glob(OVERLAY_CACHE + "*"):
            shutil.rmtree(cache)
        log(f"[{project}] materialize check: {len(jobs_list) - len(failures)}/"
            f"{len(jobs_list)} views reproduce their digest")
        header["materialize_check"] = {"views": len(jobs_list), "failures": failures}
        (out / "views.json").write_text(json.dumps(header, indent=1, sort_keys=True,
                                                   ensure_ascii=False) + "\n",
                                        encoding="utf-8")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return header


def _go_suites(project, item_ids, release=None, research=None):
    recipe = RECIPES[project]
    if recipe.go_release is None:
        return None
    if not release and research is None:
        raise ViewError(f"{project}: pass --release ({recipe.go_release}), "
                        f"or --research <checkout>")
    path = Path(release) if release else Path(research) / recipe.go_release
    rows = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            rows[row["item_id"]] = row.get("go_suite")
    missing = [i for i in item_ids if i not in rows]
    if missing:
        raise ViewError(f"{path} lacks Go suite contexts for {missing[:3]}")
    return {i: rows[i] for i in item_ids}


def build_maintainer(args) -> int:
    """`req2test views build --maintainer`."""
    _engine()
    project = args.project
    if project not in RECIPES:
        raise ViewError(f"unknown project {project!r}")
    from . import dataset
    if args.research:
        # The reviewed repair sets live beside the git-kept maps.
        from r2t.toolkit import source_views
        source_views.REPAIRS_ROOT = Path(args.research).absolute() / "maps"
    map_path, seed_digest, inputs = resolve_inputs(
        project, args.seed, research=args.research, map_path=args.map)
    scratch = Path(args.scratch or tempfile.gettempdir()).absolute()
    scratch.mkdir(parents=True, exist_ok=True)
    source = Path(tempfile.mkdtemp(prefix=f"seed-{project}.", dir=scratch))
    try:
        subprocess.run(["tar", "-C", str(source), "-xf",
                        str(Path(args.seed) / "workspace.tar")], check=True)
        add_provisioned(project, source, args.provisioned_from)
        doc = json.loads(Path(map_path).read_text(encoding="utf-8"))
        map_items = [item["item_id"] for item in doc["items"]]
        item_ids = map_items
        if args.instances:
            wanted = set(Path(args.instances).read_text().split())
            item_ids = [i for i in map_items if i in wanted]
        java = javac = None
        if project in ("algorand-sdk", "kapua"):
            home = args.java_home or os.environ.get("JAVA_HOME")
            if not home:
                raise ViewError(f"{project}: Java views need --java-home or JAVA_HOME")
            java, javac = str(Path(home) / "bin/java"), str(Path(home) / "bin/javac")
        go = None
        go_suites = _go_suites(project, map_items, args.release, args.research)
        try:
            eval_ids = [row["instance_id"] for row in
                        dataset.load_instances("eval", project, args.data_dir)]
        except FileNotFoundError as exc:
            raise ViewError(f"the eval split is needed to check the repairs: {exc}") from exc
        if go_suites is not None:
            go = args.go or os.environ.get("R2T_SOURCE_VIEW_GO") or shutil.which("go")
            if not go:
                raise ViewError(f"{project}: Go views need --go")
            go = str(Path(go).absolute())
        recipe = RECIPES[project]
        provenance = {
            "map": {"source": recipe.map, "sha256": recipe.map_sha256},
            "seed": {"workspace_seed_digest": seed_digest,
                     "provisioned": RECIPES[project].provisioned,
                     "provisioned_from": (
                         f"{socket.gethostname()}:{Path(args.provisioned_from).absolute()}"
                         if args.provisioned_from else None)},
            "engine": json.loads((REPO_ROOT / "engine" / "UPSTREAM.json")
                                 .read_text())["source_commit"],
            "toolchains": _toolchains(java, go),
        }
        if go_suites is not None:
            provenance["go_release"] = args.release or recipe.go_release
        build_views(project=project, source_root=source,
                    runtime_seed_digest=seed_digest, map_path=map_path,
                    inputs=inputs, out_dir=args.out, scratch=scratch,
                    eval_ids=eval_ids, item_ids=item_ids, java=java, javac=javac,
                    go=go, go_suites=go_suites, jobs=args.jobs,
                    provenance=provenance)
    finally:
        shutil.rmtree(source, ignore_errors=True)
    header = json.loads((Path(args.out) / project / "views.json").read_text())
    print(json.dumps(summarize(header), indent=1, sort_keys=True))
    return 1 if header["materialize_check"]["failures"] else 0


def add_provisioned(project, source: Path, provisioned_from=None) -> None:
    """Write the recipe's provisioned files into the extracted seed."""
    for rel, digest in sorted(RECIPES[project].provisioned.items()):
        if digest == EMPTY_SHA256:
            data = b""
        elif provisioned_from is None:
            raise ViewError(f"{project}: {rel} differs in a provisioned workspace; "
                            f"pass --provisioned-from <provisioned workspace or "
                            f"agent seed snapshot>")
        else:
            data = (Path(provisioned_from) / rel).read_bytes()
        if _sha256(data) != digest:
            raise ViewError(f"{project}: provisioned {rel} is not {digest}")
        target = source / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def _toolchains(java, go):
    from importlib import metadata
    found = {"python": sys.version.split()[0]}
    for package in ("tree-sitter", "tree-sitter-php", "tree-sitter-ruby"):
        try:
            found[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            pass
    if java:
        out = subprocess.run([java, "-version"], capture_output=True, text=True)
        found["java"] = (out.stderr or out.stdout).splitlines()[0]
    if go:
        out = subprocess.run([go, "version"], capture_output=True, text=True)
        found["go"] = out.stdout.strip()
    return found


def summarize(header: dict) -> dict:
    """The facts a build report needs: counts, sizes, check results."""
    return {"project": header["project"], "instances": header["instances"],
            "transformer": header["transformer"],
            "base_files": header["base"]["files"],
            "overlays": header["overlays"],
            "repairs": header["repairs"],
            "archives": {k: {"bytes": v["bytes"], "raw_bytes": v["raw_bytes"],
                             "files": v["files"]}
                         for k, v in header["archives"].items()},
            "materialize_check": {
                "views": header["materialize_check"]["views"],
                "failures": len(header["materialize_check"]["failures"])}}


# ------------------------------------------------------------------- CLI

def add_arguments(parser: argparse.ArgumentParser) -> None:
    """The `views` verb's actions, on the `req2test views` subparser."""
    sub = parser.add_subparsers(dest="action", metavar="ACTION")
    sub.required = True
    mat = sub.add_parser("materialize", help="write one instance's view",
                         description="Write one instance's TH view and "
                                     "check its manifest digest.")
    mat.add_argument("--project", required=True)
    mat.add_argument("--view", default="th", choices=sorted(VIEWS),
                     help="th, the target-hidden view (the default)")
    mat.add_argument("--instance", required=True, help="instance_id")
    mat.add_argument("--out", required=True, help="new directory for the view")
    mat.add_argument("--views-dir", help="default $REQ2TEST_HOME/views")
    mat.add_argument("--manifest", help="also write the engine manifest here")
    bld = sub.add_parser("build", help="maintainers: build a project's archives",
                         description="Build a project's TH view archives with "
                                     "the engine's source-view builder.")
    bld.add_argument("--maintainer", action="store_true", required=True,
                     help="confirm: needs the seed, the map and the toolchains")
    bld.add_argument("--project", required=True, choices=sorted(RECIPES))
    bld.add_argument("--seed", required=True,
                     help="seed directory (seed.json, workspace.tar), e.g. a kit's exec/seed")
    bld.add_argument("--provisioned-from",
                     help="a provisioned workspace (or agent seed snapshot) to copy "
                          "the recipe's provisioned files from (CoreShop)")
    bld.add_argument("--out", required=True, help="views directory to create <project>/ in")
    bld.add_argument("--research", help="checkout that holds the git-kept "
                                         "target-body maps and the reviewed "
                                         "TH-view repairs (maintainers)")
    bld.add_argument("--map", help="target-body map file (overrides the recipe path)")
    bld.add_argument("--release", help="Go release JSONL (coddy-agent go_suite contexts; "
                                       "default: the recipe's file in --research)")
    bld.add_argument("--instances", help="file of instance ids to build (default: every map item)")
    bld.add_argument("--data-dir", help="dataset directory holding eval.jsonl, for the "
                                        "repair check (default: the installed dataset)")
    bld.add_argument("--java-home")
    bld.add_argument("--go", help="absolute go executable")
    bld.add_argument("--scratch", help="scratch directory (tmpfs recommended)")
    bld.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))


def main(args: argparse.Namespace) -> int:
    """Run `req2test views ACTION` with the parsed arguments; a `ViewError`
    propagates to `req2test.cli.main`, which prints it."""
    if args.action == "materialize":
        out = materialize(args.project, args.view, args.instance, args.out,
                          views_dir=args.views_dir,
                          manifest_path=args.manifest)
        row = load_manifest_row(args.project, args.view, args.instance,
                                args.views_dir)
        print(json.dumps({"instance_id": args.instance, "view": args.view,
                          "out": str(out), "digest": row["digest"]}))
        return 0
    return build_maintainer(args)
