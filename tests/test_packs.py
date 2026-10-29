"""`req2test.packs`: the runtime pack archive, its extractor, the
pinned-manifest fetch and `req2test runtime setup`.

Network-free: synthetic packs are packed into a local release directory and
installed with `from_dir`, the release and manifest pins patched for the
test.  They need the `zstd` command.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest
from kitfixture import bwrap_usable

from req2test import cli, kits, packs
from req2test.kits import KitError

pytestmark = pytest.mark.skipif(shutil.which("zstd") is None,
                                reason="needs the zstd command")

SYLIUS = "sylius/features/admin/x.feature:3"
DOCX = "python-docx/features/a.feature:1"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rp():
    return packs._runtime_pack()


def write(path: Path, data, mode=0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(mode)


def make_pack(root: Path, project: str = "python-docx", *, alias=None,
              instance=None, home=False) -> Path:
    """A small pack with what real packs hold: wrappers, a userland with a
    link to a directory, an absolute link that dangles on the host and an
    empty directory, remainder (with a link), repairs, a state template and,
    for `instance`, an instance file; with `home`, an `rt/home/.m2` as the
    1.1 Kapua and Algorand SDK packs have."""
    pack = root / project
    write(pack / "rt" / "bin" / "behave", "#!/bin/sh\nexec run behave\n",
          0o755)
    write(pack / "rt" / "env", "PYTHONPATH=/r2t-rt/x\n")
    rootfs = pack / "rt" / "rootfs"
    write(rootfs / "usr" / "bin" / "python3", os.urandom(6000), 0o755)
    os.symlink("usr/bin", rootfs / "bin")
    os.symlink("/usr/bin/which.debianutils", rootfs / "usr" / "bin" / "which")
    (rootfs / "tmp").mkdir()
    if alias:
        write(pack / "rt" / "workdir_alias", alias + "\n")
    if home:
        (pack / "rt" / "home" / ".m2").mkdir(parents=True)
        os.symlink("/r2t-rt/rootfs/opt/m2",
                   pack / "rt" / "home" / ".m2" / "repository")
    write(pack / "remainder" / "bin" / "setup", "remainder\n", 0o755)
    os.symlink("/r2t-rt/rootfs/vendor", pack / "remainder" / "vendor")
    blobs = pack / "repairs" / "blobs"
    write(blobs / sha(b"repaired\n"), b"repaired\n")
    write(blobs / sha(b"added\n"), b"added\n")
    write(pack / "repairs" / "index.json", json.dumps([
        {"path": "src/a.py", "th_sha256": sha(b"hidden\n"),
         "repaired_sha256": sha(b"repaired\n"), "rule": "test"},
        {"path": "src/added.py", "th_sha256": None,
         "repaired_sha256": sha(b"added\n"), "rule": "test"},
        {"path": "src/other.py", "th_sha256": sha(b"another view\n"),
         "repaired_sha256": sha(b"repaired\n"), "rule": "test"}]))
    write(pack / "state-template" / "db" / "ibdata", b"db")
    if instance:
        write(pack / "instances" / (sha(instance.encode()) + ".json"),
              json.dumps({"suite": "x", "contexts": ["a"]}))
    write(pack / "build.sh", "# names a host path\n")
    write(pack / "pack.json", json.dumps({
        "project": project, "audit": {"passed": True},
        "manifest_sha256": rp().manifest_sha256(str(pack))}))
    return pack


def manifest_of(pack: Path) -> str:
    return json.loads((pack / "pack.json").read_text())["manifest_sha256"]


@pytest.fixture
def pins(monkeypatch):
    """RELEASE_SUMS and RUNTIME_PACKS as the test sets them."""
    monkeypatch.setattr(kits, "RELEASE_SUMS", dict(kits.RELEASE_SUMS))
    monkeypatch.setattr(kits, "RUNTIME_PACKS", dict(kits.RUNTIME_PACKS))


def release(tmp_path: Path, src: Path, project: str, **kw) -> tuple:
    """Package `src` as the project's runtime release and pin it."""
    from_dir = tmp_path / "assets"
    out = from_dir / kits.pack_tag(project)
    packs.pack_runtime(src, out, project=project, **kw)
    kits.RELEASE_SUMS[out.name] = kits.sha256_file(out / kits.SUMS)
    return from_dir, out


def quiet(fn, *args, **kwargs):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        result = fn(*args, **kwargs)
    return result, err.getvalue()


def raw_archive(path: Path, members) -> None:
    """A `.tar.zst` of `(TarInfo, bytes or None)` exactly as given."""
    with kits._Zstd(path, "w") as z:
        with tarfile.open(fileobj=z.stream, mode="w|",
                          format=tarfile.PAX_FORMAT) as tar:
            for info, data in members:
                if data is not None:
                    info.size = len(data)
                tar.addfile(info, io.BytesIO(data) if data is not None
                            else None)


def member(name, kind=tarfile.REGTYPE, linkname=""):
    info = tarfile.TarInfo(name)
    info.type, info.linkname, info.mode = kind, linkname, 0o644
    return info


# ----------------------------------------------------------------- format

def test_archive_round_trip_keeps_links_directories_and_modes(tmp_path):
    src = make_pack(tmp_path / "src")
    archive = tmp_path / "pack.tar.zst"
    count = packs.write_archive(src, archive)
    out = tmp_path / "out"
    out.mkdir()
    assert packs.extract_archive(archive, out) == count
    # The pack's identity: every file and link, pack.json excepted.
    assert rp().manifest_sha256(str(out)) == manifest_of(src)
    assert not (out / "pack.json").exists()
    rootfs = out / "rt" / "rootfs"
    assert os.readlink(rootfs / "bin") == "usr/bin"
    assert os.readlink(rootfs / "usr" / "bin" / "which") \
        == "/usr/bin/which.debianutils"
    assert os.readlink(out / "remainder" / "vendor") == "/r2t-rt/rootfs/vendor"
    assert (rootfs / "tmp").is_dir() and not any((rootfs / "tmp").iterdir())
    for rel in ("rt/bin/behave", "rt/env", "rt/rootfs/usr/bin/python3",
                "remainder/bin/setup", "rt/rootfs/tmp"):
        assert stat.S_IMODE(os.lstat(out / rel).st_mode) \
            == stat.S_IMODE(os.lstat(src / rel).st_mode), rel
    # Sorted members, no times or owners: the same pack, the same bytes.
    again = tmp_path / "again.tar.zst"
    packs.write_archive(src, again)
    assert kits.sha256_file(again) == kits.sha256_file(archive)


def test_extractor_never_writes_through_a_link(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    cases = {
        "through a link": [
            (member("a", tarfile.SYMTYPE, str(outside)), None),
            (member("a/evil"), b"evil")],
        "over a link": [
            (member("a", tarfile.SYMTYPE, str(outside / "evil")), None),
            (member("a"), b"evil")],
        "before its directory": [(member("d/f"), b"x")],
        "a hard link": [(member("f"), b"x"),
                        (member("g", tarfile.LNKTYPE, "f"), None)],
        "an escaping name": [(member("../evil"), b"evil")],
    }
    for label, members in cases.items():
        archive = tmp_path / f"{label}.tar.zst"
        raw_archive(archive, members)
        dest = tmp_path / label
        dest.mkdir()
        with pytest.raises(KitError):
            packs.extract_archive(archive, dest)
        assert list(outside.iterdir()) == [], label
        assert not (tmp_path / "evil").exists(), label


def test_packaging_refuses_a_pack_its_record_does_not_describe(tmp_path):
    src = make_pack(tmp_path / "src")
    with pytest.raises(KitError, match="names project 'python-docx', not "
                                       "'kapua'"):
        packs.pack_runtime(src, tmp_path / "out", project="kapua")
    (src / "rt" / "env").write_text("changed after the record\n")
    with pytest.raises(KitError, match="but pack.json records"):
        packs.pack_runtime(src, tmp_path / "out", project="python-docx")


# ------------------------------------------------------------------ fetch

def test_fetch_installs_the_pinned_pack_from_its_parts(tmp_path, pins):
    src = make_pack(tmp_path / "src")
    kits.RUNTIME_PACKS["python-docx"] = ("1.0", manifest_of(src))
    from_dir, out = release(tmp_path, src, "python-docx", part_bytes=4096)
    assert (out / "pack.tar.zst.part-01").is_file()
    assert not (out / "pack.tar.zst").exists()
    home = tmp_path / "home"
    installed, err = quiet(packs.fetch_packs, ["python-docx"], home=home,
                           from_dir=from_dir)
    root = home / "runtime-packs"
    assert installed == [root / "python-docx"]
    assert "as pinned" in err
    assert rp().manifest_sha256(str(root / "python-docx")) == manifest_of(src)
    assert (root / "python-docx" / "pack.json").read_bytes() \
        == (src / "pack.json").read_bytes()
    assert rp().load_pack(str(root), "python-docx").manifest_sha256 \
        == manifest_of(src)
    assert sorted(os.listdir(root)) == ["python-docx"]
    _, err = quiet(packs.fetch_packs, ["python-docx"], home=home,
                   from_dir=from_dir)
    assert "already installed" in err


def test_fetch_cli_packs_only(tmp_path, pins, monkeypatch):
    src = make_pack(tmp_path / "src")
    kits.RUNTIME_PACKS["python-docx"] = ("1.0", manifest_of(src))
    from_dir, _ = release(tmp_path, src, "python-docx")
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path / "home"))
    out = io.StringIO()
    with contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(io.StringIO()):
        assert cli.main(["fetch", "--packs-only", "--project", "python-docx",
                         "--from-dir", str(from_dir)]) == 0
    assert out.getvalue() == (f"runtime pack python-docx: "
                              f"{tmp_path / 'home' / 'runtime-packs' / 'python-docx'}\n")


def test_fetch_downloads_the_pack_from_the_hub(tmp_path, pins,
                                               monkeypatch):
    """Every file comes from the dataset repository's release folder at the
    given revision, and the installed pack is the pinned one."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_kits import FakeHub
    src = make_pack(tmp_path / "src")
    kits.RUNTIME_PACKS["python-docx"] = ("1.1", manifest_of(src))
    from_dir, out = release(tmp_path, src, "python-docx", part_bytes=4096)
    remote = kits.Remote(revision="ab" * 20)
    hub = FakeHub(from_dir, remote)
    monkeypatch.setattr(kits.urllib.request, "urlopen", hub)
    home = tmp_path / "home"
    installed, _ = quiet(packs.fetch_packs, ["python-docx"], remote,
                         home=home)
    assert installed == [home / "runtime-packs" / "python-docx"]
    assert rp().manifest_sha256(str(installed[0])) == manifest_of(src)
    prefix = ("https://huggingface.co/datasets/code-philia/Req2Test-Bench/"
              "resolve/" + "ab" * 20 + "/releases/runtime-python-docx-v1.1/")
    urls = hub.urls()
    assert urls and all(u.startswith(prefix) for u in urls)
    assert sorted(u[len(prefix):] for u in urls) == sorted(
        p.name for p in out.iterdir())


def test_a_tampered_pack_is_refused(tmp_path, pins):
    src = make_pack(tmp_path / "src")
    kits.RUNTIME_PACKS["python-docx"] = ("1.0", manifest_of(src))
    from_dir, out = release(tmp_path, src, "python-docx")
    home = tmp_path / "home"
    # An asset changed after its release was pinned.
    with open(out / "pack.json", "a") as fh:
        fh.write(" ")
    with pytest.raises(KitError, match="is not the listed"):
        quiet(packs.fetch_packs, ["python-docx"], home=home,
              from_dir=from_dir)
    # Other bytes under an intact record, in a release whose SHA256SUMS is
    # pinned to them: the manifest check alone refuses the pack.
    shutil.rmtree(from_dir)
    out.mkdir(parents=True)
    (src / "rt" / "env").write_text("PYTHONPATH=/elsewhere\n")
    packs.write_archive(src, out / packs.PACK_ARCHIVE)
    shutil.copyfile(src / "pack.json", out / "pack.json")
    kits.write_sums(out / kits.SUMS, {n: kits.sha256_file(out / n)
                                      for n in packs.PACK_FILES})
    kits.RELEASE_SUMS[out.name] = kits.sha256_file(out / kits.SUMS)
    with pytest.raises(KitError, match="the extracted pack has manifest "
                                       ".*, not the pinned"):
        quiet(packs.fetch_packs, ["python-docx"], home=home,
              from_dir=from_dir)
    assert os.listdir(home / "runtime-packs") == []


def test_a_pack_of_another_version_is_refused(tmp_path, pins):
    src = make_pack(tmp_path / "src")
    from_dir, _ = release(tmp_path, src, "python-docx")
    home = tmp_path / "home"
    # This req2test pins another pack (a rebuilt pack is a new version).
    version = kits.RUNTIME_PACKS["python-docx"][0]
    kits.RUNTIME_PACKS["python-docx"] = (version, "0" * 64)
    with pytest.raises(KitError, match="this req2test pins python-docx "
                                       "0000"):
        quiet(packs.fetch_packs, ["python-docx"], home=home,
              from_dir=from_dir)
    assert os.listdir(home / "runtime-packs") == []
    # Installed by hand, it is refused before any attempt is set up.
    shutil.copytree(src, home / "runtime-packs" / "python-docx",
                    symlinks=True)
    ws = tmp_path / "ws"
    (ws / "repo").mkdir(parents=True)
    with pytest.raises(KitError, match="records manifest .*; this req2test "
                                       "pins 0000"):
        packs.setup_attempt("python-docx", DOCX, ws,
                            packs_dir=home / "runtime-packs")
    assert not Path(f"{ws}.rt").exists()
    # And fetch does not overwrite a home that holds another pack.
    kits.RUNTIME_PACKS["python-docx"] = (version, manifest_of(src))
    (home / "runtime-packs" / "python-docx" / "pack.json").write_text("{}")
    with pytest.raises(KitError, match="holds another runtime pack"):
        quiet(packs.fetch_packs, ["python-docx"], home=home,
              from_dir=from_dir)


def test_every_project_has_a_pinned_pack():
    assert sorted(kits.RUNTIME_PACKS) == sorted(kits.PROJECTS)
    for project, (version, digest) in kits.RUNTIME_PACKS.items():
        assert kits.pack_tag(project) == f"runtime-{project}-v{version}"
        assert len(digest) == 64 and int(digest, 16) >= 0
        assert kits.pack_tag(project) in kits.RELEASE_SUMS


# ---------------------------------------------------------- runtime setup

def test_runtime_setup_applies_the_pack_in_init_attempt_order(
        tmp_path, pins, monkeypatch):
    src = make_pack(tmp_path / "src", "sylius", alias="/var/www/html",
                    instance=SYLIUS)
    manifest = manifest_of(src)
    kits.RUNTIME_PACKS["sylius"] = ("1.0", manifest)
    from_dir, _ = release(tmp_path, src, "sylius")
    home = tmp_path / "home"
    quiet(packs.fetch_packs, ["sylius"], home=home, from_dir=from_dir)
    monkeypatch.setenv("REQ2TEST_HOME", str(home))
    ws = tmp_path / "ws" / "0000"
    repo = ws / "repo"
    write(repo / "src" / "a.py", b"hidden\n", 0o600)
    write(repo / "bin" / "setup", "the view's\n")

    def run(argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    argv = ["runtime", "setup", "--project", "sylius", "--instance", SYLIUS,
            "--workspace", str(ws)]
    code, out, _ = run(argv)
    assert code == 0
    result = json.loads(out)
    pack_dir = home / "runtime-packs" / "sylius"
    state = Path(f"{ws}.rt")
    # Repairs: a view file with the entry's th_sha256 is replaced, keeping
    # its mode; a missing path is added (0644); another view's entry is not.
    assert (repo / "src" / "a.py").read_bytes() == b"repaired\n"
    assert stat.S_IMODE((repo / "src" / "a.py").stat().st_mode) == 0o600
    assert (repo / "src" / "added.py").read_bytes() == b"added\n"
    assert stat.S_IMODE((repo / "src" / "added.py").stat().st_mode) == 0o644
    assert not (repo / "src" / "other.py").exists()
    # Remainder: copied, never over a view file, links as links.
    assert (repo / "bin" / "setup").read_text() == "the view's\n"
    assert os.readlink(repo / "vendor") == "/r2t-rt/rootfs/vendor"
    # State: the template, the instance file, home and attempt.env.
    assert (state / "db" / "ibdata").read_bytes() == b"db"
    assert json.loads((state / "instance.json").read_text()) \
        == {"suite": "x", "contexts": ["a"]}
    assert (state / "home").is_dir()
    assert (state / "attempt.env").read_text() == f"WS={ws}\nREPO={repo}\n"
    assert result["binds"] == [
        {"source": str(ws), "target": str(ws), "writable": True},
        {"source": str(pack_dir / "rt"), "target": "/r2t-rt",
         "writable": False},
        {"source": str(state), "target": "/r2t-state", "writable": True},
        {"source": str(repo), "target": "/var/www/html", "writable": True}]
    assert result["path_prepend"] == "/r2t-rt/bin"
    # The same binds for an agent in a container, at the same paths.
    assert result["docker_args"] == list(packs.DOCKER_SECURITY) + [
        "-v", f"{ws}:{ws}", "-v", f"{pack_dir / 'rt'}:/r2t-rt:ro",
        "-v", f"{state}:/r2t-state", "-v", f"{repo}:/var/www/html",
        "-w", str(ws), "-e", f"PATH=/r2t-rt/bin:{packs.DOCKER_PATH}"]
    assert result["home_links"] == []
    assert result["remainder_added"] == 1
    assert result["runtime_pack"] == {
        "project": "sylius", "manifest_sha256": manifest,
        "pack_json_sha256": sha((src / "pack.json").read_bytes()),
        "repaired": ["src/a.py", "src/added.py"], "instance_file": True}
    # One state per attempt; an instance the pack has no file for is refused
    # before anything is written.
    code, _, err = run(argv)
    assert code == 2 and "already exists" in err
    other = tmp_path / "ws" / "0001"
    (other / "repo").mkdir(parents=True)
    code, _, err = run(["runtime", "setup", "--project", "sylius",
                        "--instance", "sylius/features/y.feature:9",
                        "--workspace", str(other)])
    assert code == 2 and "but no file for sylius/features/y.feature:9" in err
    assert not Path(f"{other}.rt").exists()


def test_runtime_setup_names_the_pack_home_entries(tmp_path, pins):
    # Each entry of a pack's rt/home/ (the Kapua and Algorand SDK packs'
    # .m2) is linked into the agent's home, so setup names them by their
    # in-sandbox paths.
    src = make_pack(tmp_path / "packs", home=True)
    kits.RUNTIME_PACKS["python-docx"] = ("1.0", manifest_of(src))
    ws = tmp_path / "ws"
    (ws / "repo").mkdir(parents=True)
    result = packs.setup_attempt("python-docx", DOCX, ws,
                                 packs_dir=tmp_path / "packs")
    assert result["home_links"] == [{"name": ".m2",
                                     "target": "/r2t-rt/home/.m2"}]


@pytest.mark.parametrize("options, user", [
    ('["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]', []),
    ('["name=apparmor","name=seccomp,profile=builtin","name=cgroupns"]',
     ["--user", f"{os.getuid()}:{os.getgid()}"])])
def test_a_container_runs_as_you_on_a_rootful_daemon(options, user,
                                                     monkeypatch):
    # A rootless daemon's root already is you; a rootful one's is not, so
    # the files the agent writes in the workspace would be root's.
    monkeypatch.setattr(packs.subprocess, "run", lambda *a, **k:
                        subprocess.CompletedProcess(a, 0, options + "\n", ""))
    assert packs.docker_user() == user


def test_a_container_runs_its_command_as_you_on_a_rootless_daemon():
    # Its root is you on the host, but the packs' databases refuse to run as
    # root: the command runs as your IDs in a user namespace of its own.
    assert packs.unprivileged([]) == [
        "bwrap", "--die-with-parent", "--unshare-user", "--uid", str(os.getuid()),
        "--gid", str(os.getgid()), "--dev-bind", "/", "/", "--"]
    assert packs.unprivileged(["--user", "5:5"]) == []


def test_no_docker_daemon_is_an_error(monkeypatch):
    # `docker info --format` prints null and exits 0 when it cannot reach
    # the daemon; that is not a rootful daemon.
    monkeypatch.setattr(packs.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, 0, "null\n", "Cannot connect to the Docker daemon at unix:///x.sock.\n"))
    with pytest.raises(ValueError, match="Cannot connect to the Docker daemon"):
        packs.docker_user()


# ------------------------------------------------------ runtime preflight

#: The shape of a pack's runner (`rt/libexec/run`) reduced to the probe: the
#: tool from the pack's userland in a nested bubblewrap, every top-level
#: entry of the userland bound read-only before the workspace, one log line.
RUNNER = """#!/bin/sh
. /r2t-state/attempt.env
tool=$1; shift
target=$(cat /r2t-rt/tools/$tool)
binds=
for e in /r2t-rt/rootfs/*; do binds="$binds --ro-bind $e /${e##*/}"; done
bwrap --unshare-user --unshare-pid --die-with-parent $binds --dev /dev \\
  --proc /proc --bind "$WS" "$WS" --bind /r2t-state /r2t-state \\
  --chdir "$(pwd)" --clearenv --setenv PATH /bin -- "$target" "$@"
rc=$?
printf '{"tool":"%s","argv":[],"seconds":0.01,"exit":%d}\\n' "$tool" "$rc" \\
  >> /r2t-state/runs.jsonl
exit $rc
"""


def runnable_pack(root: Path, top=None) -> Path:
    """A python-docx pack whose `fixture-sh` wrapper runs through `RUNNER`
    in a userland of the host's shell and its libraries; `top` adds that
    top-level directory to the userland."""
    pack = root / "python-docx"
    rootfs = pack / "rt" / "rootfs"
    shell = os.path.realpath("/bin/sh")
    listed = subprocess.run(["ldd", shell], capture_output=True,
                            text=True).stdout.split()
    for source in [shell] + [t for t in listed
                             if t.startswith("/") and os.path.isfile(t)]:
        target = rootfs / ("bin/sh" if source == shell else source.lstrip("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    if top:
        (rootfs / top).mkdir()
    write(pack / "rt" / "tools" / "sh", "/bin/sh\n")
    write(pack / "rt" / "bin" / "fixture-sh",
          '#!/bin/sh\nexec /r2t-rt/libexec/run sh "$@"\n', 0o755)
    write(pack / "rt" / "libexec" / "run", RUNNER, 0o755)
    write(pack / "pack.json", json.dumps({
        "project": "python-docx", "audit": {"passed": True},
        "manifest_sha256": rp().manifest_sha256(str(pack))}))
    return pack


@pytest.mark.skipif(shutil.which("ldd") is None or not bwrap_usable(),
                    reason="needs ldd and a bubblewrap that makes namespaces")
def test_runtime_preflight_probes_the_pack_where_the_workspaces_will_be(
        tmp_path, pins, monkeypatch):
    monkeypatch.setitem(rp().PROBES, "python-docx",
                        ("fixture-sh", "-c", "exit 0"))
    # The eval split, whose first python-docx instance is the default.
    data = tmp_path / "data"
    write(data / "eval.jsonl", "".join(
        json.dumps({"project": project,
                    "instance_id": f"{project}/features/{n}.feature:1"}) + "\n"
        for project, n in (("sylius", "s"), ("python-docx", "first"),
                           ("python-docx", "second"))))
    monkeypatch.setenv("REQ2TEST_DATA_DIR", str(data))
    root = tmp_path / "ws"
    root.mkdir()
    top = str(root).split("/")[1]

    def preflight(name, colliding, *instance):
        src = runnable_pack(tmp_path / name, top if colliding else None)
        kits.RUNTIME_PACKS["python-docx"] = ("1.0", manifest_of(src))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["runtime", "preflight",
                             "--project", "python-docx",
                             "--workspace-root", str(root), *instance,
                             "--packs-dir", str(tmp_path / name)])
        # The probe attempt is gone, its state too.
        assert os.listdir(root) == []
        return code, json.loads(out.getvalue()), err.getvalue(), src

    code, record, _err, src = preflight("good", False)
    assert code == 0 and record["ok"], record
    assert record["instance_id"] == "python-docx/features/first.feature:1"
    assert record["probe"] == ["fixture-sh", "-c", "exit 0"]
    assert [run["exit"] for run in record["runs"]] == [0]
    assert record["workspace"].startswith(str(root / "r2t-preflight-"))
    assert record["runtime_pack"]["manifest_sha256"] == manifest_of(src)
    # A userland with the top-level directory the workspaces are under: the
    # runner cannot mount the workspace, as on the GPT-6.1 Sol 1.1 cells.
    code, record, err, _src = preflight("colliding", True, "--instance", DOCX)
    assert code == 1 and not record["ok"] and record["instance_id"] == DOCX
    assert "Can't mkdir parents" in record["stderr_tail"]
    assert err.startswith(f"req2test runtime preflight: FAILED: the probe "
                          f"exited 1; the workspace is under /{top}"), err
    with pytest.raises(ValueError, match="is not a directory"):
        packs.preflight_runtime("python-docx", tmp_path / "absent",
                                packs_dir=tmp_path / "good")
    write(data / "eval.jsonl", json.dumps(
        {"project": "sylius", "instance_id": SYLIUS}) + "\n")
    with pytest.raises(ValueError, match="has no python-docx instance"):
        packs.preflight_runtime("python-docx", root,
                                packs_dir=tmp_path / "good")
