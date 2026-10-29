"""Evaluation kits, source views and the dataset: package, fetch, verify,
install, load.

Kits, views, runtime packs and the dataset ship as release folders of the
Hugging Face dataset repository `code-philia/Req2Test-Bench`
(`releases/<tag>/`), never in this repository.  One release per item:

    dataset-v1.1          eval.jsonl.zst, full.jsonl.zst, gt_tests.tar.zst,
                          SCHEMA.md, SHA256SUMS
    kit-<project>-v<ver>  kit.json, <project>-<part>.tar.zst, SHA256SUMS;
                          <ver> is the project's current kit version
                          (`KIT_VERSIONS`: 1.1; coddy-agent, coreshop and
                          prestashop 1.2)
    kit-shared-v1.0       files several kits share (the MySQL image of
                          CoreShop and Sylius): shared.json, shared-*.tar.zst,
                          SHA256SUMS
    views-<project>-v2.0  the prebuilt target-hidden (TH) source views
                          (`req2test.views`): views.json, manifests.jsonl,
                          base.tar.zst, th_overlays.tar.zst, SHA256SUMS
    runtime-<project>-v<ver>
                          the project's runtime pack (`req2test.packs`):
                          pack.json, pack.tar.zst, SHA256SUMS; <ver> and
                          the pack's manifest_sha256 are pinned in
                          `RUNTIME_PACKS`

A kit's files (KIT_SPEC: `kit.json`, `SHA256SUMS`, `exec/`, `behaviour/`,
`mutation/`, ...) are packed into one `.tar.zst` archive per part: `images`
(`exec/images/`), one per other top-level directory, and `root` (the files at
the kit root, `kit.json` and `SHA256SUMS`).  `kit.json` also ships on its own,
so a fetch can see what a release holds before downloading it.  An archive
over 1.9 GiB would ship as `<archive>.part-NN` pieces of at most 1.9 GiB each
(no current archive is that large).

A release's `SHA256SUMS` lists every file, every split archive under its
reassembled name and, for the dataset, every installed file.  The sha256 of
each published release's `SHA256SUMS` is pinned here (`RELEASE_SUMS`), so a
file changed under the same tag, or a release this version does not know,
fails closed.  A fetch downloads anonymously over HTTPS: for each release it
first gets `releases/<tag>/SHA256SUMS` and checks it against its pin, then
each file it needs, checked against that list.  It checks each reassembled
archive and each installed file the same way, every installed kit file
against `kit.json` and the kit's own `SHA256SUMS`, and every view archive
against `views.json`.  Installs never overwrite: an installed kit (views)
with the same `kit.json` (`views.json`) is kept, a different one is an error.

Installed layout (`$REQ2TEST_HOME`, default `~/.req2test`):

    data/dataset-v1.1/{eval.jsonl, full.jsonl, gt_tests/<project>.jsonl, SCHEMA.md}
    kits/<project>/<kit_version>/   kit.json and the kit's files
    kits/shared/<kit_version>/      shared.json and the shared files
    kits/<project>/shared -> ../shared/<kit_version>
                                    for kits whose kit.json names
                                    `../shared/...` paths
    views/<project>/                the four view files, as released
                                    (`req2test.views` reads them there)
    runtime-packs/<project>/        the extracted runtime pack and its
                                    pack.json (`req2test.packs`)

Archives are compressed and decompressed with the `zstd` command.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import email.utils
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable, Optional

from .dataset import DATASET_VERSION, PROJECTS

#: The Hugging Face dataset repository that holds the release folders.
HF_REPO = "code-philia/Req2Test-Bench"
#: The repository revision the release folders are read from: the commit of
#: the release's upload (the repository has no tags).  The release-day
#: procedure replaces the placeholder below with that 40-character commit
#: hash, which `upload_hf.sh` prints; until then a download with the default
#: revision stops (`Remote.url`).  `RELEASE_SUMS` fails closed on any changed
#: byte either way.
HF_REVISION = "0dfb049d5c9bfd0d8c98d23c22af7d02ee6865a3"
#: `HF_REVISION` before the release-day procedure fills it.
HF_REVISION_UNFILLED = "{{HF_UPLOAD_COMMIT}}"
#: Used when neither `--endpoint` nor `$HF_ENDPOINT` names a mirror.
HF_DEFAULT_ENDPOINT = "https://huggingface.co"
#: The folder of the repository that holds one subfolder per release tag.
RELEASES_DIR = "releases"
USER_AGENT = "req2test-fetch"
KIT_VERSION = "1.0"
#: Each project's current kit version, the one `req2test fetch` installs.
#: coddy-agent 1.2 includes the Go mutation artifacts (`mutation/go/`);
#: coreshop 1.2 lists the non-deterministic mutant 96e02276fdb04ae5 in
#: `known_host_dependent` (`mutation/rules.json`); prestashop 1.2 lists the
#: order-dependent mutants 856b05bc46ec63d9 and 8e08150ac4bed473 there.
KIT_VERSIONS = {"algorand-sdk": "1.1", "coddy-agent": "1.2", "coreshop": "1.2",
                "e-petitions": "1.1", "kapua": "1.1", "prestashop": "1.2",
                "python-docx": "1.1", "sylius": "1.1"}
KIT_SCHEMA = "req2test.kit/1"
SHARED = "shared"
#: Archives over this size ship as `.part-NN` pieces of at most this size
#: (a limit the release format keeps from its first host; no current archive
#: reaches it).
PART_BYTES = int(1.9 * 2**30)
SUMS = "SHA256SUMS"
META_NAMES = ("kit.json", "shared.json")
#: The views version of every project.
VIEWS_VERSION = "2.0"
VIEWS_SCHEMA = "req2test.views/1"
#: The files of one project's views release, installed as they are.
VIEW_FILES = ("views.json", "manifests.jsonl", "base.tar.zst",
              "th_overlays.tar.zst")
#: The runtime packs: project -> (pack version, the pack's pinned
#: manifest_sha256).  `req2test fetch` installs `runtime-<project>-v<version>`
#: and refuses a pack whose manifest is not the pinned one; `req2test runtime
#: setup` and `runtime preflight` refuse an installed pack whose pack.json
#: records another.
RUNTIME_PACKS = {
    "algorand-sdk": ("1.1", "ec7afa2a5da180ed667af4885d1d7dc8bdd7a01cd7d8342ffed98864d6d1eff6"),
    "coddy-agent": ("1.1", "72ab71b10404d2e917015a2a029e394dcf4909111777095d76d540bbe36258ec"),
    "coreshop": ("1.1", "635c1c1458fa5a2f6db0d8d555c07b50a741739b629d629f48d3ac0e12fa2203"),
    "e-petitions": ("1.1", "05b78da686b803afe813e5977bba52d44782ba911f35fa37465afbd62a38857b"),
    "kapua": ("1.1", "c6269548979c84e78c15bdad1385d8066d759cfd515f52f77cfa24f59394fd20"),
    "prestashop": ("1.1", "30d975531ece24c9b2583992732551adc153b500c0ab184fd30695f207575d56"),
    "python-docx": ("1.1", "5560c4074f14b65528fb439e8448da46107e32f8c84ee51139d5f028860cf73c"),
    "sylius": ("1.1", "6609730962cba0852a0bf560499ec7d04bca9fc9278413ac25b85b60d04d68b5"),
}
DATASET_SPLIT_FILES = {"eval": ("eval.jsonl",),
                       "full": ("full.jsonl", "eval.jsonl")}
#: sha256 of each published release's `SHA256SUMS` (release identity).  A
#: new release, or a changed one, needs a new entry here.
RELEASE_SUMS = {
    "dataset-v1.1":
        "f7a8a1041e4176416d61351f532dfb8519506d8b267bc62e8824400e3f8a7b60",
    "kit-algorand-sdk-v1.1":
        "a1a5bf3e39de8a6a06d90d5492c2a29761c182ba443c884f1ffd0345e2fac00a",
    "kit-coddy-agent-v1.2":
        "e430020503e4be9818aeda25af9b5dabf9949485a2cf180155bb6e38a85b088d",
    "kit-coreshop-v1.2":
        "b61ec346329092728da982845900e870bc3b8face4e2975fd3cc07c36f0b71fa",
    "kit-e-petitions-v1.1":
        "d4959a99ddf8d9695f5dc963d7e9f70f2da19128e1906c4a458adc6fc6951a89",
    "kit-kapua-v1.1":
        "57a5ff0f4b4a1fede96f5eff75eba4d5d1845cb66aa7fee4acb837d56cbcf03d",
    "kit-prestashop-v1.2":
        "9d0a168259bd2abc28a95792ba9ea800fcda8c7004bb35c1fa0ae6038ab53027",
    "kit-python-docx-v1.1":
        "b5f2bea6bb642f1637ce322c042cfcb78439953726a1bab61f350df9513f6a5e",
    "kit-shared-v1.0":
        "985da55e45649be4ffcd48c3dd3a6250faadf64b120f5712e7c057a1f74cd837",
    "kit-sylius-v1.1":
        "6df3d18c5f4d53292dea6d34531b201f06f1ba2b1bd96631451eae45560d8ba6",
    "runtime-algorand-sdk-v1.1":
        "de27c1c003182f36c75ffebae275eeeed0dd427b9506c73e50e0f952a6cbb79c",
    "runtime-coddy-agent-v1.1":
        "880896c1ee10caa49e4f97a6266d0ba609c7abc5c99d94ffa8e0976d7defca43",
    "runtime-coreshop-v1.1":
        "24384c397cce6f59b11233c8a75b63f8b9ea54a5cd3cb8123d6bb968f0551564",
    "runtime-e-petitions-v1.1":
        "459b44fad43a336a865177df5c9402e80eab1016779ce0804db0726a620f1bdb",
    "runtime-kapua-v1.1":
        "9acb86b021a6a7518aeca350723475185af18fbdb61802e9e98e65bc73691312",
    "runtime-prestashop-v1.1":
        "f3a0e11ec0be0ad4ebabea225e47b4774c54add441a32a7417858d9c438c1b90",
    "runtime-python-docx-v1.1":
        "ede75d52bda5e8188117a3d04350a7f2b9e8bd05a01b94335d53c4bce2855373",
    "runtime-sylius-v1.1":
        "a4923b0897818665809f12172f66352c1cb82adfed49abe275dba993d0ae0242",
    "views-algorand-sdk-v2.0":
        "3914df8f8d39cde2ed6ff0d1051200187ad46521a4865b9372202ce89248bcfb",
    "views-coddy-agent-v2.0":
        "6d7564e97e9aed9ac071e8400a67960b45c2039449e2a5aa5763ff68d2c8dd0f",
    "views-coreshop-v2.0":
        "32a59f0093a2ad74cb7dee01287c5900c1070e5c2164a0e71ff6cc10f323e7b8",
    "views-e-petitions-v2.0":
        "32cc9cc12df8f8ed4ed9babc2de72674d5a433fe317c295628e0392d2a5bd322",
    "views-kapua-v2.0":
        "1646ae1318d3861adf42933bf5ccc1efcc9481d6032e7da734d59f40e29b2f53",
    "views-prestashop-v2.0":
        "622f19a6387c293b013c3865dfd7be9dbeb1ad7f31b67a02ce02304055891973",
    "views-python-docx-v2.0":
        "1d057c7d9d6151ce1487cd4d375a33e5288c010bd456737b7ba0ef7243d911df",
    "views-sylius-v2.0":
        "ab61febc95c3f27600ccaed44790c7afa0470e1357d01a6b2c4a9bcdf1c33bf0",
}
#: Leftover install directories older than this are removed.
STALE_SECONDS = 86400
_PART_RE = re.compile(r"^(?P<base>.+)\.part-(?P<n>\d{2})$")
_CHUNK = 1 << 20


class KitError(Exception):
    """A release, download or installation is missing, damaged or clashes."""


# --------------------------------------------------------------------------
# Paths and loading


def req2test_home() -> Path:
    """The work root: `$REQ2TEST_HOME`, else `~/.req2test`."""
    env = os.environ.get("REQ2TEST_HOME")
    return Path(env).expanduser() if env else Path("~/.req2test").expanduser()


def kits_root(home=None) -> Path:
    return Path(home or req2test_home()) / "kits"


def dataset_dir(home=None) -> Path:
    return Path(home or req2test_home()) / "data" / DATASET_VERSION


def kit_version(name: str) -> str:
    """The current kit version of a project, or of the shared kit."""
    return KIT_VERSIONS.get(name, KIT_VERSION)


def kit_tag(project: str, version: Optional[str] = None) -> str:
    return f"kit-{project}-v{version or kit_version(project)}"


def views_root(home=None) -> Path:
    """`$REQ2TEST_HOME/views`, the directory `req2test.views` reads."""
    return Path(home or req2test_home()) / "views"


def views_version(project: str) -> str:
    """The views version of a project."""
    return VIEWS_VERSION


def views_tag(project: str, version: Optional[str] = None) -> str:
    return f"views-{project}-v{version or views_version(project)}"


def packs_root(home=None) -> Path:
    """`$REQ2TEST_HOME/runtime-packs`, one pack per project below it."""
    return Path(home or req2test_home()) / "runtime-packs"


def pack_tag(project: str) -> str:
    """The release of the project's pinned runtime pack."""
    return f"runtime-{project}-v{RUNTIME_PACKS[project][0]}"


def _select_projects(projects) -> list:
    """`projects` without repeats, or all of them when none are named."""
    selected = list(PROJECTS) if not projects else list(dict.fromkeys(projects))
    for project in selected:
        if project not in PROJECTS:
            raise ValueError(f"unknown project {project!r}")
    return selected


@dataclasses.dataclass(frozen=True)
class Kit:
    """An installed evaluation kit (KIT_SPEC `req2test.kit/1`)."""

    project: str
    version: str
    root: Path
    meta: dict

    def path(self, rel: str) -> Path:
        """Absolute path of a kit file named relative to the kit root.

        `../shared/...` names (CoreShop and Sylius) resolve through the
        installed `kits/<project>/shared` link to the shared kit.
        """
        if os.path.isabs(rel):
            raise ValueError(f"kit path {rel!r} is absolute")
        joined = Path(os.path.normpath(self.root / rel))
        top = Path(os.path.normpath(self.root.parent.parent))
        if top != joined and top not in joined.parents:
            raise ValueError(f"kit path {rel!r} leaves {top}")
        return joined


def installed_versions(project: str, home=None) -> list:
    base = kits_root(home) / project
    if not base.is_dir():
        return []
    found = [p.name for p in base.iterdir()
             if p.is_dir() and not p.is_symlink()
             and not p.name.startswith(".") and (p / "kit.json").is_file()]
    return sorted(found, key=_version_key)


def load_kit(project: str, version: Optional[str] = None, home=None) -> Kit:
    """The installed kit of `project` (its highest version when not named)."""
    if project not in PROJECTS:
        raise ValueError(f"unknown project {project!r}; expected one of "
                         f"{', '.join(PROJECTS)}")
    if version is None:
        versions = installed_versions(project, home)
        if not versions:
            raise FileNotFoundError(
                f"no {project} kit under {kits_root(home) / project}; run "
                f"`req2test fetch --project {project}`")
        version = versions[-1]
    root = kits_root(home) / project / version
    meta_path = root / "kit.json"
    if not meta_path.is_file():
        raise FileNotFoundError(
            f"{meta_path} does not exist; run `req2test fetch --project "
            f"{project}`")
    with open(meta_path, encoding="utf-8") as fh:
        meta = json.load(fh)
    if meta.get("schema") != KIT_SCHEMA or meta.get("project") != project:
        raise KitError(f"{meta_path}: schema {meta.get('schema')!r}, project "
                       f"{meta.get('project')!r}; expected {KIT_SCHEMA!r}, "
                       f"{project!r}")
    warn_if_stale(project, version)
    return Kit(project=project, version=version, root=root, meta=meta)


def _version_key(version: str):
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"[.-]",
                                                                 version))


def stale_kit_message(project: str, version: str) -> Optional[str]:
    """Why an installed kit `version` is behind the current one, or None."""
    current = kit_version(project)
    try:
        older = _version_key(version) < _version_key(current)
    except TypeError:                  # a non-numeric (test) version
        older = False
    if not older:
        return None
    return (f"the installed {project} kit is {version}, older than the "
            f"current {current}; install it with `req2test fetch "
            f"--kits-only --project {project}`")


#: (project, version) pairs already warned about in this process.
_WARNED: set = set()


def warn_if_stale(project: str, version: str) -> None:
    """Warn once per process when a loaded kit is older than the current."""
    message = stale_kit_message(project, version)
    if message and (project, version) not in _WARNED:
        _WARNED.add((project, version))
        print(f"req2test: warning: {message}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Checksums, splitting and zstd


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def read_sums(path) -> dict:
    """`{name: sha256}` from a `sha256sum`-format file."""
    sums = {}
    with open(path, encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
            if not match:
                raise KitError(f"{path}:{number}: not a sha256sum line")
            digest, name = match.groups()
            if sums.get(name, digest) != digest:
                raise KitError(f"{path}: {name} listed twice with different "
                               f"sha256")
            sums[name] = digest
    return sums


def write_sums(path, sums: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for name in sorted(sums):
            fh.write(f"{sums[name]}  {name}\n")


def split_file(path, part_bytes: int = PART_BYTES) -> list:
    """Cut `path` into `<path>.part-00`, `.part-01`, ... and remove it.

    Each piece holds at most `part_bytes` bytes.  Returns the pieces.
    """
    path = Path(path)
    size = path.stat().st_size
    count = max(1, -(-size // part_bytes))
    if count > 100:
        raise KitError(f"{path}: {count} parts exceed the .part-NN range")
    parts = []
    with open(path, "rb") as src:
        for index in range(count):
            part = path.with_name(f"{path.name}.part-{index:02d}")
            remaining = min(part_bytes, size - index * part_bytes)
            with open(part, "wb") as dst:
                while remaining:
                    block = src.read(min(_CHUNK, remaining))
                    if not block:
                        raise KitError(f"{path}: shorter than its size")
                    dst.write(block)
                    remaining -= len(block)
            parts.append(part)
    path.unlink()
    return parts


def join_parts(parts: Iterable, dest) -> str:
    """Concatenate `parts` in order into `dest`; the sha256 of the result."""
    digest = hashlib.sha256()
    tmp = Path(f"{dest}.joining")
    with open(tmp, "wb") as out:
        for part in parts:
            with open(part, "rb") as src:
                for block in iter(lambda: src.read(_CHUNK), b""):
                    digest.update(block)
                    out.write(block)
    os.replace(tmp, dest)
    return digest.hexdigest()


def _zstd() -> str:
    exe = shutil.which("zstd")
    if exe is None:
        raise KitError("the `zstd` command is required (apt install zstd)")
    return exe


class _Zstd:
    """`zstd` compressing into, or decompressing out of, a file."""

    def __init__(self, path, mode: str, level: int = 3, long: bool = False):
        self.path = path
        if mode == "w":
            argv = [_zstd(), "-q", "-f", "-T0", f"-{level}"]
            if level > 19:
                argv.insert(1, "--ultra")
            if long:
                argv.append("--long=27")
            argv += ["-o", str(path)]
            self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE)
            self.stream = self.proc.stdin
        else:
            argv = [_zstd(), "-q", "-d", "-c", "--", str(path)]
            self.proc = subprocess.Popen(argv, stdout=subprocess.PIPE)
            self.stream = self.proc.stdout

    def close(self, ok: bool = True) -> None:
        if not ok:
            self.proc.kill()
        elif self.proc.stdout is not None:
            # A tar reader stops at the end-of-archive marker; drain the
            # padding so zstd does not fail writing to a closed pipe.
            while self.stream.read(_CHUNK):
                pass
        try:
            self.stream.close()
        except BrokenPipeError:
            pass
        code = self.proc.wait()
        if ok and code != 0:
            raise KitError(f"zstd failed (exit {code}) on {self.path}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close(ok=exc_type is None)


class _HashingReader:
    def __init__(self, fh):
        self.fh = fh
        self.digest = hashlib.sha256()
        self.bytes = 0

    def read(self, size=-1):
        block = self.fh.read(size)
        self.digest.update(block)
        self.bytes += len(block)
        return block


# --------------------------------------------------------------------------
# Packaging (maintainers)


def _kit_part(rel: str) -> str:
    pieces = rel.split("/")
    if len(pieces) == 1:
        return "root"
    if pieces[0] == "exec" and len(pieces) > 2 and pieces[1] == "images":
        return "images"
    return pieces[0]


def _check_member_name(rel: str) -> None:
    if (not rel or rel.startswith("/") or "\\" in rel
            or any(p in ("", ".", "..") for p in rel.split("/"))):
        raise KitError(f"unsafe path {rel!r}")


def _write_tar_zst(archive: Path, src_root: Path, members: list,
                   expected: dict, level: int, long: bool = False) -> None:
    """Pack `members` (relative paths) of `src_root` reproducibly; each
    file's sha256 must equal `expected[rel]` (checked while packing)."""
    with _Zstd(archive, "w", level=level, long=long) as z:
        with tarfile.open(fileobj=z.stream, mode="w|",
                          format=tarfile.PAX_FORMAT) as tar:
            for rel in sorted(members):
                src = src_root / rel
                st = src.stat()
                info = tarfile.TarInfo(rel)
                info.size = st.st_size
                info.mode = 0o755 if st.st_mode & 0o111 else 0o644
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with open(src, "rb") as fh:
                    reader = _HashingReader(fh)
                    tar.addfile(info, reader)
                if reader.bytes != st.st_size:
                    raise KitError(f"{src}: changed while packing")
                if reader.digest.hexdigest() != expected[rel]:
                    raise KitError(f"{src}: sha256 {reader.digest.hexdigest()}"
                                   f" is not the listed {expected[rel]}")


def _finish_release(out: Path, archives: list, part_bytes: int,
                    sums: dict) -> dict:
    """Split oversized archives; record every asset in `out/SHA256SUMS`."""
    for archive in archives:
        sums[archive.name] = sha256_file(archive)
        if archive.stat().st_size > part_bytes:
            for part in split_file(archive, part_bytes):
                sums[part.name] = sha256_file(part)
    write_sums(out / SUMS, sums)
    return sums


def pack_kit(src, out, *, part_bytes: int = PART_BYTES,
             level: int = 3) -> dict:
    """Package the kit directory `src` as release assets in `out`.

    The kit is the files its `SHA256SUMS` lists, plus that file.  Each listed
    file is checked against its line while it is packed, and `kit.json`
    (`shared.json` for the shared kit) must list the same sha256 for every
    file it names.  Files on disk the kit does not list are reported and left
    out.  Returns `{asset: sha256}` of `out/SHA256SUMS`.
    """
    src, out = Path(src), Path(out)
    kit_sums = read_sums(src / SUMS)
    meta_name = next((n for n in META_NAMES if n in kit_sums), None)
    if meta_name is None:
        raise KitError(f"{src / SUMS} lists neither kit.json nor shared.json")
    with open(src / meta_name, encoding="utf-8") as fh:
        meta = json.load(fh)
    name = SHARED if meta_name == "shared.json" else meta["project"]
    for rel, entry in meta.get("files", {}).items():
        if kit_sums.get(rel) != entry.get("sha256"):
            raise KitError(f"{meta_name} lists {rel} with sha256 "
                           f"{entry.get('sha256')}, {SUMS} with "
                           f"{kit_sums.get(rel)}")
    members = {}
    for rel in kit_sums:
        _check_member_name(rel)
        members.setdefault(_kit_part(rel), []).append(rel)
    members.setdefault("root", []).append(SUMS)
    expected = dict(kit_sums)
    expected[SUMS] = sha256_file(src / SUMS)
    on_disk = {p.relative_to(src).as_posix() for p in src.rglob("*")
               if p.is_file()}
    unlisted = sorted(on_disk - set(expected))
    if unlisted:
        print(f"{name}: {len(unlisted)} file(s) on disk are not in {SUMS} "
              f"and are left out, e.g. {unlisted[:3]}", file=sys.stderr)
    out.mkdir(parents=True, exist_ok=True)
    archives = []
    for part in sorted(members):
        archive = out / f"{name}-{part}.tar.zst"
        _write_tar_zst(archive, src, members[part], expected, level)
        archives.append(archive)
    shutil.copyfile(src / meta_name, out / meta_name)
    sums = {meta_name: kit_sums[meta_name]}
    return _finish_release(out, archives, part_bytes, sums)


def pack_dataset(src, out, *, schema=None, part_bytes: int = PART_BYTES,
                 level: int = 19) -> dict:
    """Package a dataset directory (`eval.jsonl`, `full.jsonl`,
    `gt_tests/<project>.jsonl`) as release assets in `out`.

    `SHA256SUMS` lists the assets and the uncompressed files they install.
    """
    src, out = Path(src), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    sums = {}
    files = ["eval.jsonl", "full.jsonl"]
    gt = sorted(p.relative_to(src).as_posix()
                for p in (src / "gt_tests").glob("*.jsonl"))
    if not gt:
        raise KitError(f"{src / 'gt_tests'} holds no <project>.jsonl")
    for rel in files + gt:
        sums[rel] = sha256_file(src / rel)
    archives = []
    for rel in files:
        archive = out / f"{rel}.zst"
        with _Zstd(archive, "w", level=level, long=True) as z, \
                open(src / rel, "rb") as fh:
            shutil.copyfileobj(fh, z.stream, _CHUNK)
        archives.append(archive)
    archive = out / "gt_tests.tar.zst"
    _write_tar_zst(archive, src, gt, sums, level, long=True)
    archives.append(archive)
    if schema is not None:
        shutil.copyfile(schema, out / "SCHEMA.md")
        sums["SCHEMA.md"] = sha256_file(out / "SCHEMA.md")
    return _finish_release(out, archives, part_bytes, sums)


def _check_views_header(header: dict, sums: dict, project: str,
                        where: str) -> None:
    """`views.json` is the project's header and records the archives'
    sha256 as `sums` lists them."""
    if header.get("schema") != VIEWS_SCHEMA or header.get("project") != project:
        raise KitError(f"{where}: views.json is not a {VIEWS_SCHEMA} header "
                       f"for {project}")
    archives = header.get("archives", {})
    for name in (n for n in VIEW_FILES if n.endswith(".tar.zst")):
        record = archives.get(name)
        if record is None:
            raise KitError(f"{where}: views.json does not record {name}")
        if sums.get(name) != record.get("sha256"):
            raise KitError(f"{where}: views.json records {name} with sha256 "
                           f"{record.get('sha256')}, the release has "
                           f"{sums.get(name)}")


def pack_views(src, out, *, project: str) -> dict:
    """Package one project's view directory (`VIEW_FILES`) as release assets
    in `out`: the files as they are, plus `SHA256SUMS`.  Each archive must
    have the sha256 `views.json` records.  Returns `{asset: sha256}`."""
    src, out = Path(src), Path(out)
    with open(src / "views.json", encoding="utf-8") as fh:
        header = json.load(fh)
    sums = {}
    for name in VIEW_FILES:
        if (src / name).stat().st_size > PART_BYTES:
            raise KitError(f"{src / name} is over {PART_BYTES} bytes")
        sums[name] = sha256_file(src / name)
    _check_views_header(header, sums, project, str(src))
    out.mkdir(parents=True, exist_ok=True)
    for name in VIEW_FILES:
        if _copy_hashed(src / name, out / name) != sums[name]:
            raise KitError(f"{src / name}: changed while packing")
    write_sums(out / SUMS, sums)
    return sums


def _copy_hashed(src: Path, dest: Path) -> str:
    """Copy `src` to `dest`; the sha256 of the bytes written."""
    digest = hashlib.sha256()
    with open(src, "rb") as fin, open(dest, "wb") as fout:
        for block in iter(lambda: fin.read(_CHUNK), b""):
            digest.update(block)
            fout.write(block)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Download from the Hugging Face dataset repository


def hf_endpoint(endpoint: Optional[str] = None) -> str:
    """`endpoint`, else `$HF_ENDPOINT`, else `HF_DEFAULT_ENDPOINT`."""
    chosen = endpoint or os.environ.get("HF_ENDPOINT") or HF_DEFAULT_ENDPOINT
    return chosen.rstrip("/")


@dataclasses.dataclass(frozen=True)
class Remote:
    """Where release folders are downloaded from: a dataset repository at
    one revision, served by one endpoint."""

    repo: str = HF_REPO
    revision: str = HF_REVISION
    endpoint: Optional[str] = None

    def url(self, tag: str, name: str) -> str:
        """`{endpoint}/datasets/{repo}/resolve/{revision}/releases/{tag}/{name}`."""
        if self.revision == HF_REVISION_UNFILLED:
            raise KitError(f"HF_REVISION in req2test/kits.py is still the "
                           f"placeholder {HF_REVISION_UNFILLED}, not the "
                           f"commit of the release upload; pass --revision "
                           f"<commit>")
        quote = urllib.parse.quote
        return (f"{hf_endpoint(self.endpoint)}/datasets/{self.repo}/resolve/"
                f"{quote(self.revision, safe='')}/{RELEASES_DIR}/"
                f"{quote(tag)}/{quote(name)}")

    def describe(self) -> str:
        return f"{self.repo}@{self.revision} ({hf_endpoint(self.endpoint)})"


#: Download attempts per file; HTTP 429 and 5xx answers and broken
#: connections are retried, other answers are not.
ATTEMPTS = 5
#: The longest wait honoured from a `Retry-After` header, in seconds.
MAX_RETRY_AFTER = 300
_sleep = time.sleep


def _retry_after(headers, default: float) -> float:
    """Seconds a 429/503 answer asks to wait (`Retry-After` as seconds or an
    HTTP date, or the reset time of a `RateLimit` header), else `default`;
    at most `MAX_RETRY_AFTER`."""
    if headers is None:
        return default
    value = (headers.get("Retry-After") or "").strip()
    if value.isdigit():
        return min(float(value), MAX_RETRY_AFTER)
    if value:
        try:
            when = email.utils.parsedate_to_datetime(value).timestamp()
            return min(max(0.0, when - time.time()), MAX_RETRY_AFTER)
        except (TypeError, ValueError, OverflowError):
            pass
    # Hugging Face also states the reset time as `RateLimit: ...;t=<s>`.
    reset = re.search(r"\bt=(\d+)", headers.get("RateLimit") or "")
    if reset:
        return min(float(reset.group(1)), MAX_RETRY_AFTER)
    return default


def _download(remote: Remote, tag: str, name: str, dest: Path,
              expected: str, what: str = "listed",
              attempts: int = ATTEMPTS) -> None:
    """Download `releases/<tag>/<name>` of `remote` to `dest`.

    The bytes stream into `<dest>.download`, which becomes `dest` only when
    their count equals the answer's Content-Length and their sha256 equals
    `expected` (`what` names where that digest comes from: the pin or the
    release's SHA256SUMS).  An existing `dest` with that sha256 is kept.  No
    credentials are sent.
    """
    if dest.is_file() and sha256_file(dest) == expected:
        return
    url = remote.url(tag, name)
    tmp = dest.with_name(dest.name + ".download")
    for attempt in range(1, attempts + 1):
        wait = 2.0 ** attempt
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=60) as resp:
                length = resp.headers.get("Content-Length")
                digest = hashlib.sha256()
                size = 0
                with open(tmp, "wb") as out:
                    for block in iter(lambda: resp.read(_CHUNK), b""):
                        digest.update(block)
                        out.write(block)
                        size += len(block)
            if length is not None and length.isdigit() and size != int(length):
                raise http.client.IncompleteRead(b"", int(length) - size)
            if digest.hexdigest() != expected:
                tmp.unlink(missing_ok=True)
                raise KitError(f"{tag}/{name}: sha256 {digest.hexdigest()} "
                               f"is not the {what} {expected}")
            os.replace(tmp, dest)
            return
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 404:
                tmp.unlink(missing_ok=True)
                raise KitError(f"{tag}/{name} not found (HTTP 404) in "
                               f"{remote.describe()}: {url}") from None
            if exc.code != 429 and exc.code < 500:
                tmp.unlink(missing_ok=True)
                raise KitError(f"{tag}/{name}: HTTP {exc.code} from "
                               f"{url}") from None
            failure = f"HTTP {exc.code}"
            wait = _retry_after(exc.headers, wait)
        except (OSError, http.client.HTTPException) as exc:
            failure = str(exc) or type(exc).__name__
        if attempt == attempts:
            tmp.unlink(missing_ok=True)
            raise KitError(f"{tag}/{name}: download failed after {attempts} "
                           f"attempts ({failure}): {url}")
        _log(f"{tag}/{name}: {failure}; retrying in {wait:.0f} s")
        _sleep(wait)


# --------------------------------------------------------------------------
# Release sources: the Hugging Face repository or a local directory


def local_release_dir(from_dir: Path, tag: str) -> Path:
    """The folder of release `tag` under `from_dir`: `from_dir/<tag>/`, or
    `from_dir/releases/<tag>/` (a local copy of the dataset repository)."""
    direct = from_dir / tag
    nested = from_dir / RELEASES_DIR / tag
    if not direct.is_dir() and nested.is_dir():
        return nested
    return direct


class _Source:
    """The files of one release, from the remote repository or from a local
    directory."""

    def __init__(self, tag: str, remote: Remote, workdir: Path,
                 from_dir: Optional[Path]):
        self.tag = tag
        self.remote = remote
        self.local = from_dir is not None
        if self.local:
            self.dir = local_release_dir(from_dir, tag)
            if not self.dir.is_dir():
                raise KitError(
                    f"neither {from_dir / tag} nor "
                    f"{from_dir / RELEASES_DIR / tag} exists (expected the "
                    f"files of release {tag})")
            if not (self.dir / SUMS).is_file():
                raise KitError(f"release {tag} has no {SUMS} in {self.dir}")
        else:
            self.dir = workdir / tag
            self.dir.mkdir(parents=True, exist_ok=True)
        self.sums = None

    def size(self, name: str) -> Optional[int]:
        """Bytes of a local file, None before a download."""
        path = self.dir / name
        return path.stat().st_size if path.is_file() else None

    def get(self, names: Iterable[str]) -> None:
        """Make `names` present in `self.dir`, checked against SHA256SUMS."""
        names = list(names)
        if self.sums is None:
            pinned = RELEASE_SUMS.get(self.tag)
            if pinned is None:
                raise KitError(f"release {self.tag} is not pinned in "
                               f"req2test.kits.RELEASE_SUMS; this version "
                               f"of req2test cannot verify it")
            if not self.local:
                _download(self.remote, self.tag, SUMS, self.dir / SUMS,
                          pinned, what="pinned")
            actual = sha256_file(self.dir / SUMS)
            if actual != pinned:
                raise KitError(f"{self.dir / SUMS}: sha256 {actual} is not "
                               f"the pinned {pinned} of release {self.tag}")
            self.sums = read_sums(self.dir / SUMS)
        for name in names:
            if name not in self.sums:
                raise KitError(f"{self.tag}: {name} is not in {SUMS}")
        for name in names:
            if not (self.dir / name).is_file():
                raise KitError(f"{self.dir} lacks {name}")
            if not self.local:
                continue            # checked as it was downloaded
            actual = sha256_file(self.dir / name)
            if actual != self.sums[name]:
                raise KitError(f"{self.dir / name}: sha256 {actual} is "
                               f"not the listed {self.sums[name]}")

    def download_jobs(self, names: Iterable[str]) -> list:
        """`(callable)` jobs that download `names` (none for a local dir)."""
        if self.local:
            return []
        missing = [n for n in names if n not in self.sums]
        if missing:
            raise KitError(f"{self.tag}: {missing} not in {SUMS}")
        return [(lambda n=n: _download(self.remote, self.tag, n, self.dir / n,
                                       self.sums[n]))
                for n in names]

    def archive_assets(self, archive: str) -> list:
        """The asset names that carry `archive`: itself or its parts."""
        parts = sorted((n for n in self.sums
                        if (m := _PART_RE.match(n)) and m["base"] == archive),
                       key=lambda n: int(_PART_RE.match(n)["n"]))
        if not parts:
            return [archive]
        numbers = [int(_PART_RE.match(n)["n"]) for n in parts]
        if numbers != list(range(len(parts))):
            raise KitError(f"{self.tag}: parts of {archive} are not "
                           f"numbered 00..{len(parts) - 1:02d}: {parts}")
        return parts

    def open_archive(self, archive: str, joindir: Path) -> Path:
        """Path of `archive`, reassembled from its parts when split."""
        names = self.archive_assets(archive)
        if names == [archive]:
            return self.dir / archive
        joindir.mkdir(parents=True, exist_ok=True)
        dest = joindir / archive
        digest = join_parts([self.dir / n for n in names], dest)
        if digest != self.sums[archive]:
            dest.unlink()
            raise KitError(f"{self.tag}: {archive} reassembled from "
                           f"{len(names)} parts has sha256 {digest}, not the "
                           f"listed {self.sums[archive]}")
        return dest

    def cleanup(self, keep: bool) -> None:
        if not self.local and not keep:
            shutil.rmtree(self.dir, ignore_errors=True)


def _run_jobs(jobs: list, workers: int) -> None:
    if not jobs:
        return
    pool = concurrent.futures.ThreadPoolExecutor(max(1, workers))
    errors = []
    try:
        futures = [pool.submit(job) for job in jobs]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except KitError as exc:
                errors.append(str(exc))
    except BaseException:
        # Ctrl-C or an unexpected error: drop the queued downloads.
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown()
    if errors:
        raise KitError("; ".join(sorted(errors)))


# --------------------------------------------------------------------------
# Extraction and installation


def _extract(archive: Path, dest: Path, wanted=None) -> dict:
    """Extract regular-file members of a `.tar.zst` into `dest`.

    Returns `{relative path: (sha256, bytes)}`, hashed while writing.  Only
    regular files and directories with safe relative names are accepted.
    `wanted(name)` selects members (default: all).
    """
    records = {}
    with _Zstd(archive, "r") as z:
        with tarfile.open(fileobj=z.stream, mode="r|") as tar:
            for member in tar:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise KitError(f"{archive.name}: {member.name} is not a "
                                   f"regular file")
                _check_member_name(member.name)
                if wanted is not None and not wanted(member.name):
                    continue
                target = dest / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                src = tar.extractfile(member)
                digest = hashlib.sha256()
                with open(target, "wb") as out:
                    for block in iter(lambda: src.read(_CHUNK), b""):
                        digest.update(block)
                        out.write(block)
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
                records[member.name] = (digest.hexdigest(), member.size)
    return records


def _meta_shared_paths(meta) -> set:
    """Every `../shared/...` path a kit.json names."""
    found = set()
    stack = [meta]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.keys())
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str) and node.startswith(f"../{SHARED}/"):
            found.add(node)
    return found


def _verify_kit_tree(name: str, records: dict, kit_sums: dict, meta: dict,
                     meta_name: str) -> None:
    """Every extracted file is listed, and matches kit.json and SHA256SUMS."""
    problems = []
    listed = {meta_name, SUMS}
    for rel, entry in meta.get("files", {}).items():
        listed.add(rel)
        got = records.get(rel)
        if got is None:
            problems.append(f"{rel}: in {meta_name} but not in the release")
        elif got != (entry.get("sha256"), entry.get("bytes", got[1])):
            problems.append(f"{rel}: sha256/bytes {got} differ from "
                            f"{meta_name}")
    for rel, digest in kit_sums.items():
        listed.add(rel)
        got = records.get(rel)
        if got is None:
            problems.append(f"{rel}: in {SUMS} but not in the release")
        elif got[0] != digest:
            problems.append(f"{rel}: sha256 {got[0]} differs from {SUMS}")
    for rel in sorted(set(records) - listed):
        problems.append(f"{rel}: in the release but listed nowhere")
    if problems:
        raise KitError(f"{name}: {len(problems)} problem(s): "
                       + "; ".join(problems[:10]))


def _remove_stale(parent: Path, pattern: str) -> None:
    """Remove `parent/pattern` leftovers of interrupted installs that are
    older than STALE_SECONDS (a running install's are younger)."""
    if not parent.is_dir():
        return
    cutoff = time.time() - STALE_SECONDS
    for path in parent.glob(pattern):
        try:
            if path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


def _install_kit(source: _Source, name: str, version: str, home: Path,
                 meta_name: str) -> tuple:
    """Extract, verify and move a downloaded kit into place.

    Returns `(installed root, meta, records)`.
    """
    final = kits_root(home) / name / version
    stage = final.with_name(f".{version}.partial-{os.getpid()}")
    joindir = Path(home) / "tmp" / f"join-{os.getpid()}"
    _remove_stale(final.parent, ".*.partial-*")
    _remove_stale(joindir.parent, "join-*")
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    try:
        records = {}
        archives = sorted(n for n in source.sums
                          if n.endswith(".tar.zst") and n.startswith(f"{name}-"))
        if not archives:
            raise KitError(f"{source.tag}: {SUMS} lists no {name}-*.tar.zst")
        for archive in archives:
            path = source.open_archive(archive, joindir)
            got = _extract(path, stage)
            if path.parent == joindir:
                path.unlink()
            clash = set(got) & set(records)
            if clash:
                raise KitError(f"{archive}: {sorted(clash)[:3]} also in "
                               f"another archive")
            records.update(got)
        if records.get(meta_name, ("",))[0] != source.sums[meta_name]:
            raise KitError(f"{source.tag}: the archived {meta_name} is not "
                           f"the released {meta_name}")
        with open(stage / meta_name, encoding="utf-8") as fh:
            meta = json.load(fh)
        if meta_name == "kit.json" and (
                meta.get("project") != name
                or str(meta.get("kit_version")) != version):
            raise KitError(f"{source.tag}: kit.json says project "
                           f"{meta.get('project')!r} version "
                           f"{meta.get('kit_version')!r}")
        _verify_kit_tree(source.tag, records, read_sums(stage / SUMS), meta,
                         meta_name)
        if final.exists():
            raise KitError(f"{final} appeared during the install; not "
                           f"overwriting it")
        os.rename(stage, final)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(joindir, ignore_errors=True)
    return final, meta, records


def _installed_state(final: Path, meta_name: str, digest: str) -> str:
    """`absent`, `same` (installed with this metadata) or `different`."""
    if not final.exists():
        return "absent"
    meta = final / meta_name
    if meta.is_file() and sha256_file(meta) == digest:
        return "same"
    return "different"


def _log(message: str) -> None:
    print(f"req2test fetch: {message}", file=sys.stderr, flush=True)


def _human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


def _plan_line(from_dir, what: str, plan: list) -> str:
    """`checking N release(s), SIZE` for a local directory (sizes known),
    `downloading N release(s), F file(s)` otherwise."""
    if from_dir:
        total = sum(source.size(n) or 0 for source, names in plan
                    for n in names)
        return f"checking {len(plan)} {what}, {_human(total)}"
    files = sum(len(names) for _source, names in plan)
    return f"downloading {len(plan)} {what}, {files} file(s)"


def _downloaded(source: "_Source", names: list) -> dict:
    """One release a `--download-only` fetch left in `source.dir`: its
    tag, and the files (`names` and SHA256SUMS) with their total size."""
    files = [SUMS, *(n for n in names if n != SUMS)]
    return {"tag": source.tag, "files": len(files),
            "bytes": sum((source.dir / n).stat().st_size for n in files),
            "dir": str(source.dir)}


def describe_downloaded(release: dict) -> str:
    """`downloaded TAG: N file(s), SIZE in DIR`."""
    return (f"downloaded {release['tag']}: {release['files']} file(s), "
            f"{_human(release['bytes'])} in {release['dir']}")


def fetch_kits(projects=None, remote: Optional[Remote] = None, *,
               version: Optional[str] = None,
               home=None, from_dir=None, download_dir=None,
               download_only: bool = False, jobs: int = 4,
               keep_downloads: bool = False) -> list:
    """Download, verify and install the kits of `projects` (default: all).

    Files come from the release folders `releases/kit-<project>-v<version>/`
    of `remote` (default: `Remote()`), or from `from_dir/<tag>/` or
    `from_dir/releases/<tag>/` (as `download_only` or a local copy of the
    repository leaves them); `version` defaults to each project's current
    version (`kit_version`).  A
    kit whose kit.json names `../shared/...` paths also gets the shared kit
    (always at its own current version) and a `kits/<project>/shared` link
    to it.  Returns the installed `Kit`s,
    or with `download_only` one `_downloaded` record per release.
    """
    home = Path(home or req2test_home())
    projects = _select_projects(projects)
    from_dir = Path(from_dir) if from_dir else None
    workdir = Path(download_dir) if download_dir else home / "downloads"
    remote = remote or Remote()

    def ver(name):          # `version` is a project kit's; shared keeps its own
        return kit_version(name) if name == SHARED else (
            version or kit_version(name))

    def open_source(name):
        return _Source(kit_tag(name, ver(name)), remote, workdir, from_dir)

    sources = {p: open_source(p) for p in projects}
    metas = {}
    for project, source in sources.items():
        source.get([])
        if "kit.json" not in source.sums:
            raise KitError(f"{source.tag}: {SUMS} lists no kit.json")
        if not source.local:
            _run_jobs(source.download_jobs(["kit.json"]), 1)
        source.get(["kit.json"])
        with open(source.dir / "kit.json", encoding="utf-8") as fh:
            metas[project] = json.load(fh)
    needs_shared = [p for p in projects if _meta_shared_paths(metas[p])]
    if needs_shared:
        sources[SHARED] = open_source(SHARED)
        sources[SHARED].get([])
    plan, download = {}, []
    for name, source in sources.items():
        meta_name = "shared.json" if name == SHARED else "kit.json"
        final = kits_root(home) / name / ver(name)
        state = "absent" if download_only else _installed_state(
            final, meta_name, source.sums[meta_name])
        if state == "different":
            raise KitError(f"{final} holds a different kit; not overwriting "
                           f"it (remove it to reinstall)")
        if state == "same":
            _log(f"{source.tag}: already installed at {final}")
            source.cleanup(keep_downloads)
            continue
        names = [meta_name] + [
            asset for archive in sorted(source.sums)
            if archive.endswith(".tar.zst") and archive.startswith(f"{name}-")
            for asset in source.archive_assets(archive)]
        plan[name] = (source, meta_name, names)
        download += source.download_jobs(
            [n for n in names if n != meta_name or name == SHARED])
    if plan:
        _log(_plan_line(from_dir, "release(s)",
                        [(s, names) for s, _, names in plan.values()]))
    _run_jobs(download, jobs)
    for name, (source, meta_name, names) in plan.items():
        source.get(names)
        _log(f"{source.tag}: {len(names)} file(s) match {SUMS}")
    installed = []
    if download_only:
        return [_downloaded(source, names)
                for source, _meta, names in plan.values()]
    order = sorted(plan, key=lambda n: n != SHARED)
    for name in order:
        source, meta_name, names = plan[name]
        final, meta, records = _install_kit(source, name, ver(name), home,
                                            meta_name)
        _log(f"{source.tag}: installed {len(records)} files at {final}, "
             f"each checked against {meta_name} and {SUMS}")
        source.cleanup(keep_downloads)
    if needs_shared:
        _link_shared(needs_shared, metas, ver(SHARED), home)
    for project in projects:
        installed.append(load_kit(project, ver(project), home))
    return installed


def _link_shared(projects: list, metas: dict, version: str, home) -> None:
    """Link `kits/<project>/shared` to the shared kit and check every
    `../shared/...` file a kit names against the shared kit's record,
    and its DB image's sha256 against the shared kit's."""
    shared_root = kits_root(home) / SHARED / version
    with open(shared_root / "shared.json", encoding="utf-8") as fh:
        shared_files = json.load(fh).get("files", {})
    for project in projects:
        link = kits_root(home) / project / SHARED
        target = os.path.join("..", SHARED, version)
        if link.is_symlink() or link.exists():
            if not (link.is_symlink() and os.readlink(link) == target):
                raise KitError(f"{link} exists and is not a link to {target}")
        else:
            os.symlink(target, link)
        for path in sorted(_meta_shared_paths(metas[project])):
            if path[len(f"../{SHARED}/"):] not in shared_files:
                raise KitError(f"{project} kit.json names {path}, which the "
                               f"shared kit does not hold")
        db = metas[project].get("exec_env", {}).get("db_image") or {}
        if str(db.get("file", "")).startswith(f"../{SHARED}/"):
            held = shared_files[db["file"][len(f"../{SHARED}/"):]]["sha256"]
            if db.get("sha256") != held:
                raise KitError(f"{project} kit.json lists db_image "
                               f"{db['file']} with sha256 {db.get('sha256')}, "
                               f"the shared kit holds {held}")
        _log(f"{project}: {link} -> {target}")


def _dataset_asset(rel: str) -> str:
    """The dataset release asset that carries installed file `rel`."""
    if rel.startswith("gt_tests/"):
        return "gt_tests.tar.zst"
    if rel == "SCHEMA.md":
        return rel
    return f"{rel}.zst"


def fetch_dataset(split: str = "eval", projects=None,
                  remote: Optional[Remote] = None, *,
                  home=None, from_dir=None, download_dir=None,
                  download_only: bool = False, jobs: int = 4,
                  keep_downloads: bool = False) -> Path:
    """Download, verify and install `DATASET_VERSION` (`dataset-v1.1`); its
    installed directory.

    Installs `eval.jsonl` (and `full.jsonl` for `split="full"`),
    `gt_tests/<project>.jsonl` for `projects` (default: all) and `SCHEMA.md`.
    Each file is checked against the release's SHA256SUMS; an existing file
    with the listed sha256 is kept, any other existing file is an error.
    With `download_only`, returns the release's `_downloaded` record instead.
    """
    if split not in DATASET_SPLIT_FILES:
        raise ValueError(f"unknown split {split!r}")
    home = Path(home or req2test_home())
    projects = _select_projects(projects)
    from_dir = Path(from_dir) if from_dir else None
    workdir = Path(download_dir) if download_dir else home / "downloads"
    source = _Source(DATASET_VERSION, remote or Remote(), workdir, from_dir)
    source.get([])
    dest = dataset_dir(home)
    files = list(DATASET_SPLIT_FILES[split]) + [
        f"gt_tests/{p}.jsonl" for p in projects] + ["SCHEMA.md"]
    for rel in files:
        if rel not in source.sums:
            raise KitError(f"{DATASET_VERSION}: {SUMS} does not list {rel}")
    todo = []
    for rel in files:
        target = dest / rel
        if target.exists() and not download_only:
            if sha256_file(target) != source.sums[rel]:
                raise KitError(f"{target} differs from {DATASET_VERSION}; "
                               f"not overwriting it")
            continue
        todo.append(rel)
    if not todo:
        _log(f"{DATASET_VERSION}: already installed at {dest}")
        source.cleanup(keep_downloads)
        return dest
    archives = sorted({_dataset_asset(rel) for rel in todo})
    names = [a for archive in archives for a in source.archive_assets(archive)]
    if not source.local:
        _log(f"downloading {DATASET_VERSION}: {', '.join(names)}")
        _run_jobs(source.download_jobs(names), jobs)
    source.get(names)
    if download_only:
        return _downloaded(source, names)
    stage = dest.parent / f".{dest.name}.partial-{os.getpid()}"
    joindir = home / "tmp" / f"join-{os.getpid()}"
    _remove_stale(dest.parent, ".*.partial-*")
    _remove_stale(joindir.parent, "join-*")
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    try:
        records = {}
        for archive in archives:
            path = source.open_archive(archive, joindir)
            if archive == "SCHEMA.md":
                shutil.copyfile(path, stage / "SCHEMA.md")
                records["SCHEMA.md"] = (sha256_file(stage / "SCHEMA.md"), 0)
            elif archive.endswith(".tar.zst"):
                records.update(_extract(path, stage,
                                        wanted=lambda n: n in todo))
            else:
                rel = archive[:-len(".zst")]
                digest = hashlib.sha256()
                with _Zstd(path, "r") as z, open(stage / rel, "wb") as out:
                    for block in iter(lambda: z.stream.read(_CHUNK), b""):
                        digest.update(block)
                        out.write(block)
                records[rel] = (digest.hexdigest(), 0)
            if path.parent == joindir:
                path.unlink()
        for rel in todo:
            got = records.get(rel)
            if got is None:
                raise KitError(f"{DATASET_VERSION}: {rel} is in no asset")
            if got[0] != source.sums[rel]:
                raise KitError(f"{DATASET_VERSION}: installed {rel} has "
                               f"sha256 {got[0]}, not the listed "
                               f"{source.sums[rel]}")
        for rel in todo:
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise KitError(f"{target} appeared during the install")
            os.replace(stage / rel, target)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(joindir, ignore_errors=True)
    _log(f"{DATASET_VERSION}: installed {len(todo)} file(s) at {dest}, each "
         f"checked against {SUMS}")
    source.cleanup(keep_downloads)
    return dest


def fetch_views(projects=None, remote: Optional[Remote] = None, *,
                version: Optional[str] = None, home=None, from_dir=None,
                download_dir=None, download_only: bool = False,
                jobs: int = 4, keep_downloads: bool = False) -> list:
    """Download, verify and install the source views of `projects`.

    Files come from the release folders `releases/views-<project>-v<version>/`
    of `remote` (default: `Remote()`), or from `from_dir/<tag>/` or
    `from_dir/releases/<tag>/`.  Each file is checked against the
    pinned release `SHA256SUMS` when it is downloaded and again as it is
    installed, and each archive against `views.json`.  Returns the installed
    `views/<project>` directories, or with `download_only` one `_downloaded`
    record per release.
    """
    home = Path(home or req2test_home())
    projects = _select_projects(projects)
    from_dir = Path(from_dir) if from_dir else None
    workdir = Path(download_dir) if download_dir else home / "downloads"
    remote = remote or Remote()
    plan, download = {}, []
    for project in projects:
        source = _Source(views_tag(project, version), remote, workdir,
                         from_dir)
        source.get([])
        missing = [n for n in VIEW_FILES if n not in source.sums]
        if missing:
            raise KitError(f"{source.tag}: {SUMS} does not list {missing}")
        final = views_root(home) / project
        state = "absent" if download_only else _installed_state(
            final, "views.json", source.sums["views.json"])
        if state == "different":
            raise KitError(f"{final} holds other views; not overwriting them "
                           f"(remove the directory to reinstall)")
        if state == "same":
            _log(f"{source.tag}: already installed at {final}")
            source.cleanup(keep_downloads)
            continue
        plan[project] = source
        download += source.download_jobs(VIEW_FILES)
    if plan:
        _log(_plan_line(from_dir, "views release(s)",
                        [(s, VIEW_FILES) for s in plan.values()]))
    _run_jobs(download, jobs)
    for source in plan.values():
        source.get(VIEW_FILES)
    if download_only:
        return [_downloaded(source, VIEW_FILES) for source in plan.values()]
    for project, source in plan.items():
        final = views_root(home) / project
        stage = final.with_name(f".{project}.partial-{os.getpid()}")
        _remove_stale(final.parent, ".*.partial-*")
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True)
        try:
            for name in VIEW_FILES:
                digest = _copy_hashed(source.dir / name, stage / name)
                if digest != source.sums[name]:
                    raise KitError(f"{source.tag}: installed {name} has "
                                   f"sha256 {digest}, not the listed "
                                   f"{source.sums[name]}")
            with open(stage / "views.json", encoding="utf-8") as fh:
                _check_views_header(json.load(fh), source.sums, project,
                                    source.tag)
            if final.exists():
                raise KitError(f"{final} appeared during the install; not "
                               f"overwriting it")
            os.rename(stage, final)
        finally:
            shutil.rmtree(stage, ignore_errors=True)
        _log(f"{source.tag}: installed {len(VIEW_FILES)} files at {final}, "
             f"each checked against {SUMS} and views.json")
        source.cleanup(keep_downloads)
    return [views_root(home) / p for p in projects]


# --------------------------------------------------------------------------
# `req2test fetch`


def add_fetch_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--split", choices=sorted(DATASET_SPLIT_FILES),
                        default="eval",
                        help="dataset split to install (full also installs "
                             "eval); default eval")
    parser.add_argument("--project", action="append", choices=PROJECTS,
                        metavar="PROJECT",
                        help="project whose ground-truth tests, kit, views "
                             "and runtime pack to fetch; repeatable; default "
                             "all eight")
    what = parser.add_mutually_exclusive_group()
    what.add_argument("--dataset-only", action="store_true",
                      help="fetch the dataset only (default: the dataset, "
                           "the kits, the source views and the runtime "
                           "packs)")
    what.add_argument("--kits-only", action="store_true",
                      help="fetch the evaluation kits only")
    what.add_argument("--views-only", action="store_true",
                      help="fetch the TH source views only")
    what.add_argument("--packs-only", action="store_true",
                      help="fetch the runtime packs only")
    parser.add_argument("--hf-repo", default=HF_REPO, metavar="REPO",
                        help=f"Hugging Face dataset repository that holds "
                             f"the release folders (default {HF_REPO})")
    parser.add_argument("--revision", default=HF_REVISION,
                        help=f"revision (commit hash) of that repository "
                             f"(default {HF_REVISION}, the commit of the "
                             f"release upload)")
    parser.add_argument("--endpoint", default=None, metavar="URL",
                        help=f"Hugging Face endpoint or mirror (default "
                             f"$HF_ENDPOINT, else {HF_DEFAULT_ENDPOINT})")
    parser.add_argument("--kit-version", default=None,
                        help="project kit version (default: each "
                             "project's current version, KIT_VERSIONS; the "
                             "shared kit always uses its own)")
    where = parser.add_mutually_exclusive_group()
    where.add_argument("--from-dir", metavar="DIR",
                       help="install from release files already in "
                            "DIR/<tag>/ or DIR/releases/<tag>/ (no "
                            "network): a directory --download-only filled, "
                            "or a local copy of the dataset repository")
    where.add_argument("--download-only", metavar="DIR",
                       help="download and check the release files into "
                            "DIR/<tag>/ and install nothing")
    parser.add_argument("-j", "--jobs", type=int, default=4,
                        help="parallel downloads (default 4)")
    parser.add_argument("--keep-downloads", action="store_true",
                        help="keep the downloaded files under "
                             "$REQ2TEST_HOME/downloads after installing")


def run_fetch(args) -> int:
    remote = Remote(repo=args.hf_repo, revision=args.revision,
                    endpoint=args.endpoint)
    common = dict(remote=remote, from_dir=args.from_dir,
                  download_dir=args.download_only,
                  download_only=bool(args.download_only), jobs=args.jobs,
                  keep_downloads=args.keep_downloads)
    only = [k for k in ("dataset", "kits", "views", "packs")
            if getattr(args, f"{k}_only")]
    wanted = set(only or ("dataset", "kits", "views", "packs"))
    from . import packs
    # A KitError propagates to `req2test.cli.main`, which prints it.
    if args.download_only:
        # One line per release downloaded: tag, files, size.
        releases = []
        if "dataset" in wanted:
            releases.append(fetch_dataset(args.split, args.project,
                                          **common))
        if "kits" in wanted:
            releases += fetch_kits(args.project, version=args.kit_version,
                                   **common)
        if "views" in wanted:
            releases += fetch_views(args.project, **common)
        if "packs" in wanted:
            releases += packs.fetch_packs(args.project, **common)
        for release in releases:
            print(describe_downloaded(release))
        print(f"files: {Path(args.download_only).resolve()}")
        return 0
    if "dataset" in wanted:
        path = fetch_dataset(args.split, args.project, **common)
        print(f"dataset: {path}")
    if "kits" in wanted:
        kits = fetch_kits(args.project, version=args.kit_version,
                          **common)
        for kit in kits:
            print(f"kit {kit.project} {kit.version}: {kit.root}")
    if "views" in wanted:
        for path in fetch_views(args.project, **common):
            print(f"views {path.name}: {path}")
    if "packs" in wanted:
        for path in packs.fetch_packs(args.project, **common):
            print(f"runtime pack {path.name}: {path}")
    # A home that kept an older kit (a fetch before the current kit was
    # published, or --dataset-only/--views-only/--packs-only) is told so.
    for project in _select_projects(args.project):
        versions = installed_versions(project)
        if versions:
            warn_if_stale(project, versions[-1])
    return 0
