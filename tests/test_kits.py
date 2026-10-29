"""Tests of `req2test.kits`: packaging, splitting, verified install, loading.

Network-free: releases are packed into a temporary directory and installed
with `from_dir`, or served from it by a fake `urlopen` (`RemoteFetch`).  They need the `zstd` command.  The two >2 GiB tests write
about 18 GiB and run only with `REQ2TEST_BIG_TESTS=1` (put them on a large
disk with `REQ2TEST_BIG_TMP=DIR`).

    python3 -m unittest tests.test_kits -v
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

from req2test import kits, packs
from req2test.kits import KitError

HAVE_ZSTD = shutil.which("zstd") is not None


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pin(release_dir: Path) -> None:
    """Pin a test release's SHA256SUMS (inside a patched RELEASE_SUMS)."""
    kits.RELEASE_SUMS[release_dir.name] = kits.sha256_file(
        release_dir / "SHA256SUMS")


def patch_pins(test: unittest.TestCase) -> None:
    """Let `test` change RELEASE_SUMS; restored when it ends."""
    patcher = mock.patch.dict(kits.RELEASE_SUMS)
    patcher.start()
    test.addCleanup(patcher.stop)


def write_kit(root: Path, project: str, files: dict, extra_meta=None) -> None:
    """A minimal kit: `files` plus kit.json and SHA256SUMS over them."""
    root.mkdir(parents=True)
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    meta = {"schema": kits.KIT_SCHEMA, "project": project,
            "kit_version": kits.kit_version(project),
            "files": {rel: {"sha256": sha(d), "bytes": len(d),
                            "provenance": "test"}
                      for rel, d in files.items()}}
    meta.update(extra_meta or {})
    (root / "kit.json").write_text(json.dumps(meta, indent=1))
    sums = {rel: sha(d) for rel, d in files.items()}
    sums["kit.json"] = kits.sha256_file(root / "kit.json")
    kits.write_sums(root / "SHA256SUMS", sums)


def write_shared(root: Path, files: dict) -> None:
    root.mkdir(parents=True)
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    meta = {"schema": "req2test.kit-shared/1",
            "files": {rel: {"sha256": sha(d), "bytes": len(d)}
                      for rel, d in files.items()}}
    (root / "shared.json").write_text(json.dumps(meta))
    sums = {rel: sha(d) for rel, d in files.items()}
    sums["shared.json"] = kits.sha256_file(root / "shared.json")
    kits.write_sums(root / "SHA256SUMS", sums)


KIT_FILES = {
    "exec/images/app.docker.tar.zst": os.urandom(5000),
    "exec/seed/workspace.tar": b"seed" * 300,
    "exec/release/gold/a.json": b'{"a": 1}\n',
    "behaviour/gold_run.jsonl.zst": os.urandom(700),
    "mutation/rules.json": b'{"candidate_timeout": "kill"}\n',
}


@unittest.skipUnless(HAVE_ZSTD, "needs the zstd command")
class KitRoundTrip(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r2t-kits-test-"))
        self.home = self.tmp / "home"
        self.assets = self.tmp / "assets"
        patch_pins(self)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def pack(self, project="python-docx", files=KIT_FILES, part_bytes=2048,
             extra_meta=None):
        src = self.tmp / "src" / project
        write_kit(src, project, files, extra_meta)
        out = self.assets / kits.kit_tag(project)
        sums = kits.pack_kit(src, out, part_bytes=part_bytes)
        pin(out)
        return sums, out

    def test_pack_splits_and_install_verifies(self):
        sums, out = self.pack()
        names = sorted(p.name for p in out.iterdir())
        self.assertIn("kit.json", names)
        self.assertIn("python-docx-images.tar.zst", sums)
        self.assertNotIn("python-docx-images.tar.zst", names)
        parts = [n for n in names if ".part-" in n]
        self.assertTrue(parts and all(
            (out / n).stat().st_size <= 2048 for n in parts))
        installed = kits.fetch_kits(["python-docx"], home=self.home,
                                    from_dir=self.assets)
        kit = installed[0]
        self.assertEqual(kit.root,
                         self.home / "kits" / "python-docx" /
                         kits.kit_version("python-docx"))
        for rel, data in KIT_FILES.items():
            self.assertEqual(kit.path(rel).read_bytes(), data)
        self.assertTrue((kit.root / "SHA256SUMS").is_file())
        self.assertEqual(kits.load_kit("python-docx", home=self.home).meta,
                         kit.meta)
        self.assertEqual(sorted(p.name for p in out.iterdir()), names,
                         "a --from-dir install must not change its source")
        # A second fetch keeps the installed kit.
        kits.fetch_kits(["python-docx"], home=self.home, from_dir=self.assets)

    def test_download_only_records_each_release(self):
        _, out = self.pack()
        (release,) = kits.fetch_kits(["python-docx"], home=self.home,
                                     from_dir=self.assets,
                                     download_only=True)
        on_disk = list(out.iterdir())
        self.assertEqual(release, {
            "tag": kits.kit_tag("python-docx"), "files": len(on_disk),
            "bytes": sum(p.stat().st_size for p in on_disk),
            "dir": str(out)})
        self.assertFalse((self.home / "kits").exists())
        self.assertRegex(kits.describe_downloaded(release),
                         r"^downloaded kit-python-docx-v1\.1: \d+ file\(s\), "
                         r"[\d.]+ (B|KiB|MiB) in ")

    def test_tampered_part_is_rejected(self):
        _, out = self.pack()
        part = sorted(out.glob("python-docx-images.tar.zst.part-*"))[0]
        data = bytearray(part.read_bytes())
        data[100] ^= 0xFF
        part.write_bytes(bytes(data))
        with self.assertRaisesRegex(KitError, "sha256"):
            kits.fetch_kits(["python-docx"], home=self.home,
                            from_dir=self.assets)
        self.assertFalse((self.home / "kits" / "python-docx" /
                          kits.kit_version("python-docx")).exists())

    def test_missing_part_is_rejected(self):
        _, out = self.pack()
        sorted(out.glob("python-docx-images.tar.zst.part-*"))[-1].unlink()
        with self.assertRaisesRegex(KitError, "lacks"):
            kits.fetch_kits(["python-docx"], home=self.home,
                            from_dir=self.assets)

    def test_kit_file_differing_from_kit_json_is_rejected(self):
        """A release whose archive disagrees with kit.json fails install."""
        src = self.tmp / "src" / "python-docx"
        write_kit(src, "python-docx", KIT_FILES)
        out = self.assets / kits.kit_tag("python-docx")
        kits.pack_kit(src, out)
        # Rebuild the mutation archive with other bytes, re-sum the asset:
        # only the kit.json/SHA256SUMS check inside can catch it.
        (src / "mutation/rules.json").write_bytes(b"{}\n")
        archive = out / "python-docx-mutation.tar.zst"
        kits._write_tar_zst(archive, src, ["mutation/rules.json"],
                            {"mutation/rules.json": sha(b"{}\n")}, 3)
        sums = kits.read_sums(out / "SHA256SUMS")
        sums[archive.name] = kits.sha256_file(archive)
        kits.write_sums(out / "SHA256SUMS", sums)
        pin(out)
        with self.assertRaisesRegex(KitError, "mutation/rules.json"):
            kits.fetch_kits(["python-docx"], home=self.home,
                            from_dir=self.assets)

    def test_no_clobber(self):
        self.pack()
        kits.fetch_kits(["python-docx"], home=self.home, from_dir=self.assets)
        shutil.rmtree(self.assets)
        shutil.rmtree(self.tmp / "src")
        files = dict(KIT_FILES, **{"mutation/rules.json": b"{}\n"})
        self.pack(files=files)
        with self.assertRaisesRegex(KitError, "not overwriting"):
            kits.fetch_kits(["python-docx"], home=self.home,
                            from_dir=self.assets)
        kit = kits.load_kit("python-docx", home=self.home)
        self.assertEqual(kit.path("mutation/rules.json").read_bytes(),
                         KIT_FILES["mutation/rules.json"])

    def test_unpinned_release_fails_closed(self):
        _, out = self.pack()
        del kits.RELEASE_SUMS[out.name]
        with self.assertRaisesRegex(KitError, "not pinned"):
            kits.fetch_kits(["python-docx"], home=self.home,
                            from_dir=self.assets)

    def test_reuploaded_release_fails_closed(self):
        """Self-consistent new assets under a pinned tag are refused."""
        _, out = self.pack()
        pinned = kits.RELEASE_SUMS[out.name]
        shutil.rmtree(self.assets)
        shutil.rmtree(self.tmp / "src")
        self.pack(files=dict(KIT_FILES, **{"mutation/rules.json": b"{}\n"}))
        kits.RELEASE_SUMS[out.name] = pinned
        with self.assertRaisesRegex(KitError, "pinned"):
            kits.fetch_kits(["python-docx"], home=self.home,
                            from_dir=self.assets)
        self.assertFalse((self.home / "kits" / "python-docx").exists())

    def test_current_kit_versions(self):
        self.assertEqual(kits.kit_version("coddy-agent"), "1.2")
        self.assertEqual(kits.kit_tag("coddy-agent"), "kit-coddy-agent-v1.2")
        self.assertEqual(kits.kit_tag("coddy-agent", "1.1"),
                         "kit-coddy-agent-v1.1")
        self.assertEqual(kits.kit_version("coreshop"), "1.2")
        self.assertEqual(kits.kit_tag("coreshop"), "kit-coreshop-v1.2")
        self.assertEqual(kits.kit_tag("coreshop", "1.0"), "kit-coreshop-v1.0")
        self.assertEqual(kits.kit_version("prestashop"), "1.2")
        self.assertEqual(kits.kit_tag("prestashop"), "kit-prestashop-v1.2")
        self.assertEqual(kits.kit_version("python-docx"), "1.1")
        self.assertEqual(kits.kit_tag("python-docx", "1.0"),
                         "kit-python-docx-v1.0")
        self.assertEqual(kits.kit_version(kits.SHARED), kits.KIT_VERSION)

    def test_current_views_versions(self):
        for project in kits.PROJECTS:
            self.assertEqual(kits.views_version(project), "2.0", project)
            self.assertEqual(kits.views_tag(project),
                             f"views-{project}-v2.0")

    def test_runtime_packs_are_pinned(self):
        """Every project's runtime pack v1.1, and its manifest."""
        for project in kits.PROJECTS:
            self.assertEqual(kits.RUNTIME_PACKS[project][0], "1.1", project)
            self.assertEqual(kits.pack_tag(project),
                             f"runtime-{project}-v1.1")
            self.assertRegex(kits.RELEASE_SUMS[kits.pack_tag(project)],
                             "^[0-9a-f]{64}$")
            self.assertRegex(kits.RUNTIME_PACKS[project][1], "^[0-9a-f]{64}$")
        self.assertTrue(kits.RUNTIME_PACKS["kapua"][1].startswith("c6269548"))
        self.assertTrue(
            kits.RUNTIME_PACKS["algorand-sdk"][1].startswith("ec7afa2a"))

    def test_protocols_pin_the_released_packs(self):
        """Protocols 427-434 pin the packs this package installs and admits,
        and the population file lists them."""
        from req2test import score  # noqa: F401  (puts the engine on sys.path)
        from r2t.bench import population, protocol_file
        listed = population.load_benchmark_population()["protocols"]
        for version in range(427, 435):
            pack = protocol_file.load(version)["runtime_pack"]
            self.assertEqual(pack["manifest_sha256"],
                             kits.RUNTIME_PACKS[pack["project"]][1], version)
            self.assertIn(version, listed)

    def test_only_the_published_releases_are_pinned(self):
        current = {kits.DATASET_VERSION}
        current |= {kits.kit_tag(p) for p in kits.PROJECTS + (kits.SHARED,)}
        current |= {kits.views_tag(p) for p in kits.PROJECTS}
        current |= {kits.pack_tag(p) for p in kits.PROJECTS}
        self.assertEqual(len(current), 26)
        self.assertEqual(set(kits.RELEASE_SUMS), current)

    def test_published_releases_are_pinned(self):
        for project in kits.PROJECTS + (kits.SHARED,):
            self.assertRegex(kits.RELEASE_SUMS[kits.kit_tag(project)],
                             "^[0-9a-f]{64}$")
        self.assertIn(kits.DATASET_VERSION, kits.RELEASE_SUMS)

    def test_pack_refuses_a_file_that_differs_from_its_sum(self):
        src = self.tmp / "src" / "python-docx"
        write_kit(src, "python-docx", KIT_FILES)
        (src / "exec/seed/workspace.tar").write_bytes(b"changed")
        with self.assertRaisesRegex(KitError, "workspace.tar"):
            kits.pack_kit(src, self.tmp / "out")

    def test_unsafe_member_is_rejected(self):
        archive = self.tmp / "evil.tar.zst"
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tar:
            info = tarfile.TarInfo("../evil")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        subprocess.run(["zstd", "-q", "-o", str(archive)], input=raw.getvalue(),
                       check=True)
        dest = self.tmp / "dest" / "inner"
        dest.mkdir(parents=True)
        with self.assertRaisesRegex(KitError, "unsafe"):
            kits._extract(archive, dest)
        self.assertFalse((self.tmp / "dest" / "evil").exists())

    def pack_shared(self, mysql: bytes) -> None:
        write_shared(self.tmp / "src" / "shared",
                     {"images/mysql.docker.tar.zst": mysql})
        out = self.assets / kits.kit_tag("shared")
        kits.pack_kit(self.tmp / "src" / "shared", out, part_bytes=1024)
        pin(out)

    def test_shared_kit_is_fetched_and_linked(self):
        mysql = os.urandom(3000)
        self.pack_shared(mysql)
        meta = {"exec_env": {"db_image": {
            "file": "../shared/images/mysql.docker.tar.zst",
            "sha256": sha(mysql)}}}
        self.pack(project="coreshop", extra_meta=meta)
        kit = kits.fetch_kits(["coreshop"], home=self.home,
                              from_dir=self.assets)[0]
        db = kit.meta["exec_env"]["db_image"]["file"]
        self.assertEqual(kit.path(db).read_bytes(), mysql)
        self.assertEqual((kit.root / db).read_bytes(), mysql)
        self.assertTrue((self.home / "kits" / "shared" / "1.0" /
                         "shared.json").is_file())
        # A project kit version does not move the shared kit's version.
        kit = kits.fetch_kits(["coreshop"], home=self.home,
                              from_dir=self.assets,
                              version=kits.kit_version("coreshop"))[0]
        self.assertEqual(kit.path(db).read_bytes(), mysql)

    def test_shared_db_image_sha256_must_match(self):
        self.pack_shared(os.urandom(3000))
        meta = {"exec_env": {"db_image": {
            "file": "../shared/images/mysql.docker.tar.zst",
            "sha256": sha(b"another image")}}}
        self.pack(project="sylius", extra_meta=meta)
        with self.assertRaisesRegex(KitError, "db_image"):
            kits.fetch_kits(["sylius"], home=self.home, from_dir=self.assets)

    def test_kit_path_stays_inside_kits(self):
        kit = kits.Kit("coreshop", "1.0", self.home / "kits/coreshop/1.0", {})
        self.assertEqual(kit.path("../shared/x"),
                         self.home / "kits/coreshop/shared/x")
        with self.assertRaises(ValueError):
            kit.path("../../../etc/passwd")
        with self.assertRaises(ValueError):
            kit.path("/etc/passwd")


@unittest.skipUnless(HAVE_ZSTD, "needs the zstd command")
class DatasetRoundTrip(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r2t-ds-test-"))
        src = self.tmp / "src"
        (src / "gt_tests").mkdir(parents=True)
        self.files = {
            "eval.jsonl": b'{"instance_id": "a"}\n',
            "full.jsonl": b'{"instance_id": "a"}\n{"instance_id": "b"}\n',
            "gt_tests/kapua.jsonl": b'{"instance_id": "k"}\n' * 50,
            "gt_tests/sylius.jsonl": b'{"instance_id": "s"}\n' * 50,
        }
        for rel, data in self.files.items():
            (src / rel).write_bytes(data)
        schema = self.tmp / "SCHEMA.md"
        schema.write_text("# schema\n")
        self.assets = self.tmp / "assets"
        kits.pack_dataset(src, self.assets / kits.DATASET_VERSION, schema=schema,
                          part_bytes=64)
        patch_pins(self)
        pin(self.assets / kits.DATASET_VERSION)
        self.home = self.tmp / "home"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_install_selected_project(self):
        dest = kits.fetch_dataset("eval", ["kapua"], home=self.home,
                                  from_dir=self.assets)
        self.assertEqual(dest, self.home / "data" / kits.DATASET_VERSION)
        got = sorted(p.relative_to(dest).as_posix()
                     for p in dest.rglob("*") if p.is_file())
        self.assertEqual(got, ["SCHEMA.md", "eval.jsonl",
                               "gt_tests/kapua.jsonl"])
        for rel in ("eval.jsonl", "gt_tests/kapua.jsonl"):
            self.assertEqual((dest / rel).read_bytes(), self.files[rel])
        # Adding the full split and another project keeps what is there.
        kits.fetch_dataset("full", ["kapua", "sylius"], home=self.home,
                           from_dir=self.assets)
        self.assertEqual((dest / "full.jsonl").read_bytes(),
                         self.files["full.jsonl"])
        self.assertTrue((dest / "gt_tests/sylius.jsonl").is_file())

    def test_download_only_records_the_release(self):
        release = kits.fetch_dataset("full", ["kapua"], home=self.home,
                                     from_dir=self.assets, download_only=True)
        self.assertEqual(release["tag"], kits.DATASET_VERSION)
        self.assertEqual(release["dir"], str(self.assets / kits.DATASET_VERSION))
        self.assertGreater(release["files"], 1)
        self.assertFalse((self.home / "data").exists())

    def test_repeated_project_is_installed_once(self):
        dest = kits.fetch_dataset("eval", ["kapua", "kapua"], home=self.home,
                                  from_dir=self.assets)
        self.assertEqual((dest / "gt_tests/kapua.jsonl").read_bytes(),
                         self.files["gt_tests/kapua.jsonl"])

    def test_existing_different_file_is_not_overwritten(self):
        dest = self.home / "data" / kits.DATASET_VERSION
        dest.mkdir(parents=True)
        (dest / "eval.jsonl").write_bytes(b"local edit\n")
        with self.assertRaisesRegex(KitError, "not overwriting"):
            kits.fetch_dataset("eval", ["kapua"], home=self.home,
                               from_dir=self.assets)


def write_views(root: Path, project: str, archives: dict = None) -> Path:
    """A project's four view files; `views.json` records the archives."""
    pdir = root / project
    pdir.mkdir(parents=True)
    data = {name: os.urandom(900) for name in kits.VIEW_FILES
            if name.endswith(".tar.zst")}
    data.update(archives or {})
    for name, raw in data.items():
        (pdir / name).write_bytes(raw)
    (pdir / "manifests.jsonl").write_text('{"instance_id": "x"}\n')
    header = {"schema": kits.VIEWS_SCHEMA, "project": project,
              "archives": {n: {"sha256": sha(d), "bytes": len(d)}
                           for n, d in data.items()}}
    (pdir / "views.json").write_text(json.dumps(header))
    return pdir


@unittest.skipUnless(HAVE_ZSTD, "needs the zstd command")
class ViewsRelease(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r2t-views-test-"))
        self.home = self.tmp / "home"
        self.assets = self.tmp / "assets"
        patch_pins(self)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def pack(self, project="kapua", src=None):
        src = src or write_views(self.tmp / "src", project)
        out = self.assets / kits.views_tag(project)
        kits.pack_views(src, out, project=project)
        pin(out)
        return src, out

    def fetch(self, project="kapua"):
        return kits.fetch_views([project], home=self.home,
                                from_dir=self.assets)

    def test_install_checks_and_keeps(self):
        files = kits.VIEW_FILES
        self.assertEqual(files, ("views.json", "manifests.jsonl",
                                 "base.tar.zst", "th_overlays.tar.zst"))
        src, out = self.pack()
        self.assertEqual(out.name, "views-kapua-v2.0")
        self.assertEqual(sorted(p.name for p in out.iterdir()),
                         sorted(files + (kits.SUMS,)))
        installed = self.fetch()
        self.assertEqual(installed, [self.home / "views" / "kapua"])
        for name in files:
            self.assertEqual((installed[0] / name).read_bytes(),
                             (src / name).read_bytes())
        self.assertEqual(sorted(p.name for p in installed[0].iterdir()),
                         sorted(files))
        self.fetch()  # installed with the same views.json: kept

    def test_other_views_are_not_overwritten(self):
        self.pack()
        self.fetch()
        shutil.rmtree(self.assets)
        shutil.rmtree(self.tmp / "src")
        self.pack()
        with self.assertRaisesRegex(KitError, "not overwriting"):
            self.fetch()

    def test_tampered_asset_is_rejected(self):
        _, out = self.pack()
        (out / "base.tar.zst").write_bytes(b"other bytes")
        with self.assertRaisesRegex(KitError, "sha256"):
            self.fetch()
        self.assertFalse((self.home / "views" / "kapua").exists())

    def test_pack_refuses_archives_views_json_does_not_record(self):
        src = write_views(self.tmp / "src", "kapua")
        (src / "base.tar.zst").write_bytes(b"rebuilt")
        with self.assertRaisesRegex(KitError, "base.tar.zst"):
            kits.pack_views(src, self.tmp / "out", project="kapua")
        with self.assertRaisesRegex(KitError, "header for sylius"):
            kits.pack_views(src, self.tmp / "out2", project="sylius")

    def test_release_disagreeing_with_views_json_is_refused(self):
        """A pinned, self-consistent release whose views.json does not
        record its archives fails install."""
        _, out = self.pack()
        header = json.loads((out / "views.json").read_text())
        header["archives"]["base.tar.zst"]["sha256"] = "0" * 64
        (out / "views.json").write_text(json.dumps(header))
        sums = kits.read_sums(out / kits.SUMS)
        sums["views.json"] = kits.sha256_file(out / "views.json")
        kits.write_sums(out / kits.SUMS, sums)
        pin(out)
        with self.assertRaisesRegex(KitError, "views.json records base.tar.zst"):
            self.fetch()
        self.assertFalse((self.home / "views" / "kapua").exists())

    def test_missing_asset_in_from_dir_is_a_clean_error(self):
        _, out = self.pack()
        (out / "base.tar.zst").unlink()
        with self.assertRaisesRegex(KitError, "lacks base.tar.zst"):
            self.fetch()
        self.assertFalse((self.home / "views" / "kapua").exists())

    def test_views_json_must_record_every_archive(self):
        _, out = self.pack()
        header = json.loads((out / "views.json").read_text())
        del header["archives"]["th_overlays.tar.zst"]
        (out / "views.json").write_text(json.dumps(header))
        sums = kits.read_sums(out / kits.SUMS)
        sums["views.json"] = kits.sha256_file(out / "views.json")
        kits.write_sums(out / kits.SUMS, sums)
        pin(out)
        with self.assertRaisesRegex(KitError,
                                    "does not record th_overlays.tar.zst"):
            self.fetch()

    def test_unpinned_views_release_fails_closed(self):
        _, out = self.pack()
        del kits.RELEASE_SUMS[out.name]
        with self.assertRaisesRegex(KitError, "not pinned"):
            self.fetch()

    def test_published_views_are_pinned(self):
        for project in kits.PROJECTS:
            self.assertRegex(kits.RELEASE_SUMS[kits.views_tag(project)],
                             "^[0-9a-f]{64}$")

    def test_cli_views_only(self):
        from req2test import cli
        self.pack()
        with mock.patch.dict(os.environ, {"REQ2TEST_HOME": str(self.home)}), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["fetch", "--views-only", "--project", "kapua",
                             "--from-dir", str(self.assets)])
        self.assertEqual(code, 0)
        self.assertEqual(sorted(p.name for p in self.home.iterdir()),
                         ["views"])
        self.assertEqual(
            sorted(p.name for p in (self.home / "views" / "kapua").iterdir()),
            sorted(kits.VIEW_FILES))

    def test_fetched_views_materialize(self):
        """A real archive set (the views tests' fixture) fetched into
        $REQ2TEST_HOME/views materializes with its digest check."""
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import test_views as tv
        from req2test import views
        root = self.tmp / "build"
        root.mkdir()
        map_path = tv.write_fixture(root)
        (root / "scratch").mkdir()
        with tv.write_repairs(root, map_path):
            tv.build(root, map_path, root / "views", jobs=1)
        self.pack("python-docx", src=root / "views" / "python-docx")
        out = self.tmp / "view"
        with mock.patch.dict(os.environ, {"REQ2TEST_HOME": str(self.home)}):
            kits.fetch_views(["python-docx"], from_dir=self.assets)
            views.materialize("python-docx", "th", tv.FIRST, out)
        self.assertTrue((out / "TARGET_CONTRACTS.md").is_file())
        self.assertIn(b"REPAIRED", (out / "src" / "api.py").read_bytes())


class RunJobs(unittest.TestCase):

    def test_unexpected_error_drops_queued_jobs(self):
        started = []
        lock = threading.Lock()

        def boom():
            raise RuntimeError("boom")

        def slow():
            with lock:
                started.append(1)
            time.sleep(0.2)

        with self.assertRaisesRegex(RuntimeError, "boom"):
            kits._run_jobs([boom] + [slow] * 20, 1)
        self.assertLess(len(started), 20)

    def test_kit_errors_are_collected(self):
        def bad(n):
            raise KitError(f"bad {n}")
        with self.assertRaisesRegex(KitError, "bad 1; bad 2"):
            kits._run_jobs([lambda: bad(2), lambda: bad(1)], 2)


class SplitJoin(unittest.TestCase):

    def test_small(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blob"
            data = os.urandom(10_000)
            path.write_bytes(data)
            parts = kits.split_file(path, 4096)
            self.assertEqual([p.name for p in parts],
                             ["blob.part-00", "blob.part-01", "blob.part-02"])
            self.assertEqual([p.stat().st_size for p in parts],
                             [4096, 4096, 1808])
            self.assertFalse(path.exists())
            self.assertEqual(kits.join_parts(parts, path), sha(data))
            self.assertEqual(path.read_bytes(), data)

    @unittest.skipUnless(os.environ.get("REQ2TEST_BIG_TESTS") == "1",
                         "set REQ2TEST_BIG_TESTS=1 (writes about 7 GiB)")
    def test_over_two_gib(self):
        """A 2.1 GiB file splits into GitHub-sized parts and joins back."""
        size = int(2.1 * 2**30)
        base = os.environ.get("REQ2TEST_BIG_TMP") or None
        with tempfile.TemporaryDirectory(dir=base) as tmp:
            path = Path(tmp) / "big.tar.zst"
            digest = hashlib.sha256()
            block = os.urandom(1 << 20)
            with open(path, "wb") as fh:
                written = 0
                while written < size:
                    # Number each MiB so a misordered join changes the hash.
                    chunk = written.to_bytes(8, "big") + block[8:]
                    chunk = chunk[:size - written]
                    fh.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
            parts = kits.split_file(path)
            self.assertEqual(len(parts), 2)
            self.assertEqual(parts[0].stat().st_size, kits.PART_BYTES)
            self.assertLess(parts[0].stat().st_size, 2 * 2**30)
            self.assertEqual(parts[1].stat().st_size, size - kits.PART_BYTES)
            self.assertEqual(kits.join_parts(parts, path), digest.hexdigest())
            self.assertEqual(path.stat().st_size, size)

    @unittest.skipUnless(HAVE_ZSTD and
                         os.environ.get("REQ2TEST_BIG_TESTS") == "1",
                         "set REQ2TEST_BIG_TESTS=1 (writes about 11 GiB)")
    def test_kit_with_archive_over_two_gib(self):
        """pack -> .part-NN assets under 2 GiB -> reassembled, verified install."""
        base = os.environ.get("REQ2TEST_BIG_TMP") or None
        with tempfile.TemporaryDirectory(dir=base) as tmp:
            tmp = Path(tmp)
            src = tmp / "src" / "kapua"
            image = src / "exec/images/big.docker.tar.zst"
            image.parent.mkdir(parents=True)
            digest = hashlib.sha256()
            size = int(2.1 * 2**30)
            with open(image, "wb") as fh:
                for _ in range(size >> 20):
                    block = os.urandom(1 << 20)  # incompressible
                    fh.write(block)
                    digest.update(block)
            meta = {"schema": kits.KIT_SCHEMA, "project": "kapua",
                    "kit_version": kits.KIT_VERSION,
                    "files": {"exec/images/big.docker.tar.zst": {
                        "sha256": digest.hexdigest(),
                        "bytes": image.stat().st_size}}}
            (src / "kit.json").write_text(json.dumps(meta))
            kits.write_sums(src / "SHA256SUMS", {
                "exec/images/big.docker.tar.zst": digest.hexdigest(),
                "kit.json": kits.sha256_file(src / "kit.json")})
            out = tmp / "assets" / kits.kit_tag("kapua")
            kits.pack_kit(src, out)
            patch_pins(self)
            pin(out)
            parts = sorted(out.glob("kapua-images.tar.zst.part-*"))
            self.assertEqual(len(parts), 2)
            self.assertTrue(all(p.stat().st_size <= kits.PART_BYTES
                                for p in parts))
            shutil.rmtree(tmp / "src")
            kit = kits.fetch_kits(["kapua"], home=tmp / "home",
                                  from_dir=tmp / "assets")[0]
            installed = kit.path("exec/images/big.docker.tar.zst")
            self.assertEqual(kits.sha256_file(installed), digest.hexdigest())



class StaleKitWarning(unittest.TestCase):
    """A home that kept an older kit than the current one is told so."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home)
        patcher = mock.patch.dict(os.environ,
                                  {"REQ2TEST_HOME": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        warned = mock.patch.object(kits, "_WARNED", set())
        warned.start()
        self.addCleanup(warned.stop)

    def install(self, project, version):
        root = self.home / "kits" / project / version
        root.mkdir(parents=True)
        (root / "kit.json").write_text(json.dumps({
            "schema": kits.KIT_SCHEMA, "project": project,
            "kit_version": version}))

    def test_load_kit_warns_once_for_an_older_kit(self):
        self.install("coddy-agent", "1.0")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(kits.load_kit("coddy-agent").version, "1.0")
            kits.load_kit("coddy-agent")
        self.assertEqual(err.getvalue(), (
            "req2test: warning: the installed coddy-agent kit is 1.0, older "
            "than the current 1.2; install it with `req2test fetch "
            "--kits-only --project coddy-agent`\n"))
        self.install("coddy-agent", "1.2")
        self.install("python-docx", "1.1")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(kits.load_kit("coddy-agent").version, "1.2")
            kits.load_kit("python-docx")
        self.assertEqual(err.getvalue(), "")

    def test_fetch_warns_about_a_kit_it_did_not_replace(self):
        self.install("coreshop", "1.0")
        args = mock.Mock(hf_repo=kits.HF_REPO,
                         revision=kits.HF_REVISION, endpoint=None, from_dir=None, download_only=None,
                         jobs=1, keep_downloads=False, dataset_only=False,
                         kits_only=False, views_only=True,
                         packs_only=False, project=["coreshop"])
        err = io.StringIO()
        with mock.patch.object(kits, "fetch_views", return_value=[]), \
                contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(kits.run_fetch(args), 0)
        self.assertIn("`req2test fetch --kits-only --project coreshop`",
                      err.getvalue())

    def test_download_only_prints_one_line_per_release(self):
        args = mock.Mock(hf_repo=kits.HF_REPO,
                         revision=kits.HF_REVISION, endpoint=None, from_dir=None, download_only="/dl",
                         jobs=1, keep_downloads=False, dataset_only=False,
                         kits_only=False, views_only=False,
                         packs_only=False, split="eval",
                         kit_version=None, project=["kapua"])

        def record(tag, files, size):
            return {"tag": tag, "files": files, "bytes": size,
                    "dir": f"/dl/{tag}"}
        out = io.StringIO()
        with mock.patch.object(kits, "fetch_dataset", return_value=record(
                "dataset-v1.0", 4, 2048)), \
                mock.patch.object(kits, "fetch_kits", return_value=[
                    record("kit-kapua-v1.0", 6, 3 << 30)]), \
                mock.patch.object(kits, "fetch_views", return_value=[
                    record("views-kapua-v2.0", 3, 5 << 20)]), \
                mock.patch.object(packs, "fetch_packs", return_value=[
                    record("runtime-kapua-v1.1", 3, 400 << 20)]), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(kits.run_fetch(args), 0)
        self.assertEqual(out.getvalue().splitlines()[:4], [
            "downloaded dataset-v1.0: 4 file(s), 2.0 KiB in /dl/dataset-v1.0",
            "downloaded kit-kapua-v1.0: 6 file(s), 3.0 GiB in "
            "/dl/kit-kapua-v1.0",
            "downloaded views-kapua-v2.0: 3 file(s), 5.0 MiB in "
            "/dl/views-kapua-v2.0",
            "downloaded runtime-kapua-v1.1: 3 file(s), 400.0 MiB in "
            "/dl/runtime-kapua-v1.1"])

    def test_non_numeric_versions_are_not_compared(self):
        self.assertIsNone(kits.stale_kit_message("kapua", "test"))

class FakeHub:
    """A fake `urllib.request.urlopen` serving `root/<tag>/<file>` at the
    Hugging Face resolve URLs of one remote; records every request."""

    def __init__(self, root: Path, remote=None):
        self.root = root
        self.remote = remote or kits.Remote()
        self.requests = []
        self.override = {}          # url -> list of answers, used in order

    def __call__(self, request, timeout=None):
        url = request.full_url
        self.requests.append(request)
        queued = self.override.get(url)
        if queued:
            answer = queued.pop(0)
            if isinstance(answer, Exception):
                raise answer
            if isinstance(answer, tuple):       # (body, Content-Length)
                return self._response(url, *answer)
            return self._response(url, answer)
        prefix = (f"{kits.hf_endpoint(self.remote.endpoint)}/datasets/"
                  f"{self.remote.repo}/resolve/"
                  f"{urllib.parse.quote(self.remote.revision, safe='')}/"
                  f"releases/")
        if not url.startswith(prefix):
            raise self.http_error(url, 404)
        path = self.root / url[len(prefix):]
        if not path.is_file():
            raise self.http_error(url, 404)
        return self._response(url, path.read_bytes())

    @staticmethod
    def http_error(url, code, headers=None):
        import email.message
        msg = email.message.Message()
        for key, value in (headers or {}).items():
            msg[key] = value
        return urllib.error.HTTPError(url, code, f"HTTP {code}", msg,
                                      io.BytesIO(b""))

    @staticmethod
    def _response(url, data, length=None):
        resp = io.BytesIO(data)
        resp.headers = {"Content-Length": str(len(data) if length is None
                                              else length)}
        resp.url = url
        return resp

    def urls(self):
        return [r.full_url for r in self.requests]


@unittest.skipUnless(HAVE_ZSTD, "needs the zstd command")
class RemoteFetch(unittest.TestCase):
    """`req2test fetch` against a fake Hugging Face endpoint."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r2t-remote-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / "home"
        self.assets = self.tmp / "assets"
        patch_pins(self)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("HF_ENDPOINT", None)
        self.hub = FakeHub(self.assets)
        opener = mock.patch.object(kits.urllib.request, "urlopen", self.hub)
        opener.start()
        self.addCleanup(opener.stop)
        self.sleeps = []
        sleeper = mock.patch.object(kits, "_sleep", self.sleeps.append)
        sleeper.start()
        self.addCleanup(sleeper.stop)
        # As after the release-day procedure has filled HF_REVISION.
        filled = mock.patch.object(kits, "HF_REVISION_UNFILLED", "<filled>")
        filled.start()
        self.addCleanup(filled.stop)
        self.rev = urllib.parse.quote(kits.HF_REVISION, safe="")

    def pack_kit(self, project="python-docx"):
        src = self.tmp / "src" / project
        write_kit(src, project, KIT_FILES)
        out = self.assets / kits.kit_tag(project)
        kits.pack_kit(src, out, part_bytes=2048)
        pin(out)
        return out

    def quiet(self):
        return contextlib.redirect_stderr(io.StringIO())

    def test_default_url(self):
        self.assertEqual(
            kits.Remote().url("kit-kapua-v1.1", "kapua-images.tar.zst"),
            "https://huggingface.co/datasets/code-philia/Req2Test-Bench/"
            f"resolve/{self.rev}/releases/kit-kapua-v1.1/kapua-images.tar.zst")

    def test_unfilled_default_revision_stops_a_download(self):
        with mock.patch.object(kits, "HF_REVISION_UNFILLED",
                               kits.HF_REVISION):
            with self.assertRaisesRegex(kits.KitError, "placeholder"):
                kits.Remote().url("dataset-v1.1", "SHA256SUMS")
            # An explicit --revision still works.
            self.assertIn("/resolve/" + "ab" * 20 + "/", kits.Remote(
                revision="ab" * 20).url("dataset-v1.1", "SHA256SUMS"))

    def test_hf_endpoint_revision_and_endpoint_override(self):
        os.environ["HF_ENDPOINT"] = "https://hf-mirror.example/"
        self.assertEqual(
            kits.Remote().url("dataset-v1.1", "SHA256SUMS"),
            "https://hf-mirror.example/datasets/code-philia/Req2Test-Bench/"
            f"resolve/{self.rev}/releases/dataset-v1.1/SHA256SUMS")
        remote = kits.Remote(repo="org/other", revision="0123abcd" * 5,
                             endpoint="http://localhost:8080")
        self.assertEqual(
            remote.url("dataset-v1.1", "SHA256SUMS"),
            "http://localhost:8080/datasets/org/other/resolve/"
            + "0123abcd" * 5 + "/releases/dataset-v1.1/SHA256SUMS")

    def test_cli_flags_reach_the_remote(self):
        parser = argparse.ArgumentParser()
        kits.add_fetch_arguments(parser)
        args = parser.parse_args(["--dataset-only", "--hf-repo", "org/r",
                                  "--revision", "abc", "--endpoint",
                                  "http://mirror"])
        seen = {}

        def fake(split, projects, **kw):
            seen.update(kw)
            return Path("/x")
        with mock.patch.object(kits, "fetch_dataset", fake), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(kits.run_fetch(args), 0)
        self.assertEqual(seen["remote"], kits.Remote("org/r", "abc",
                                                     "http://mirror"))
        defaults = parser.parse_args([])
        self.assertEqual((defaults.hf_repo, defaults.revision,
                          defaults.endpoint),
                         (kits.HF_REPO, kits.HF_REVISION, None))

    def test_remote_install_fetches_the_pinned_list_first(self):
        out = self.pack_kit()
        with self.quiet():
            (kit,) = kits.fetch_kits(["python-docx"], home=self.home)
        for rel, data in KIT_FILES.items():
            self.assertEqual(kit.path(rel).read_bytes(), data)
        urls = self.hub.urls()
        self.assertTrue(urls[0].endswith(f"/{out.name}/SHA256SUMS"), urls[0])
        listed = kits.read_sums(out / "SHA256SUMS")
        requested = {u.rsplit("/", 1)[1] for u in urls}
        self.assertLessEqual(requested, set(listed) | {"SHA256SUMS"})
        for request in self.hub.requests:
            self.assertIsNone(request.get_header("Authorization"))
        self.assertFalse((self.home / "downloads" / out.name).exists(),
                         "downloads are removed after the install")

    def test_download_only_then_from_dir(self):
        out = self.pack_kit()
        dl = self.tmp / "dl"
        with self.quiet():
            (record,) = kits.fetch_kits(["python-docx"], home=self.home,
                                        download_dir=dl, download_only=True)
        self.assertEqual(record["dir"], str(dl / out.name))
        self.assertEqual(sorted(p.name for p in (dl / out.name).iterdir()),
                         sorted(p.name for p in out.iterdir()))
        self.hub.requests.clear()
        with self.quiet():
            kits.fetch_kits(["python-docx"], home=self.home, from_dir=dl)
        self.assertEqual(self.hub.requests, [])

    def test_changed_sha256sums_is_refused_against_the_pin(self):
        out = self.pack_kit()
        kits.RELEASE_SUMS[out.name] = "0" * 64
        with self.assertRaisesRegex(KitError, "SHA256SUMS: sha256 [0-9a-f]+ "
                                              "is not the pinned 0{64}"):
            kits.fetch_kits(["python-docx"], home=self.home)
        self.assertEqual(len(self.hub.requests), 1)
        self.assertFalse(list((self.home / "downloads").rglob("SHA256SUMS*")))

    def test_file_with_wrong_sha256_is_refused(self):
        out = self.pack_kit()
        url = kits.Remote().url(out.name, "kit.json")
        self.hub.override[url] = [b'{"tampered": true}']
        with self.assertRaisesRegex(KitError, r"kit\.json: sha256 [0-9a-f]+ "
                                              r"is not the listed"):
            kits.fetch_kits(["python-docx"], home=self.home)
        self.assertEqual(self.hub.urls().count(url), 1,
                         "a wrong sha256 is not retried")
        self.assertFalse(list((self.home / "downloads").rglob("*.download")))
        self.assertFalse((self.home / "kits").exists())

    def test_missing_release_names_the_url_and_revision(self):
        with self.assertRaisesRegex(
                KitError, r"kit-python-docx-v1\.1/SHA256SUMS not found "
                          r"\(HTTP 404\) in code-philia/Req2Test-Bench@"
                          + re.escape(kits.HF_REVISION) +
                          r" \(https://huggingface\.co\): https://"):
            kits.fetch_kits(["python-docx"], home=self.home)
        self.assertEqual(len(self.hub.requests), 1, "a 404 is not retried")

    def test_rate_limit_waits_for_retry_after(self):
        out = self.pack_kit()
        url = kits.Remote().url(out.name, "SHA256SUMS")
        self.hub.override[url] = [
            FakeHub.http_error(url, 429, {"Retry-After": "7"}),
            FakeHub.http_error(url, 503, {}),
            (out / "SHA256SUMS").read_bytes()]
        with self.quiet():
            kits.fetch_kits(["python-docx"], home=self.home)
        self.assertEqual(self.sleeps[:2], [7.0, 4.0])
        self.assertEqual(self.hub.urls().count(url), 3)

    def test_short_body_is_retried_then_fails(self):
        out = self.pack_kit()
        url = kits.Remote().url(out.name, "SHA256SUMS")
        data = (out / "SHA256SUMS").read_bytes()
        self.hub.override[url] = [(data[:10], len(data))] * kits.ATTEMPTS
        with self.quiet(), self.assertRaisesRegex(
                KitError, f"download failed after {kits.ATTEMPTS} attempts"):
            kits.fetch_kits(["python-docx"], home=self.home)
        self.assertEqual(len(self.sleeps), kits.ATTEMPTS - 1)
        self.assertFalse(list((self.home / "downloads").rglob("*.download")))

    def test_from_dir_accepts_a_local_copy_of_the_repository(self):
        out = self.pack_kit()
        copy = self.tmp / "hf-copy"
        shutil.copytree(out, copy / "releases" / out.name)
        with self.quiet():
            (kit,) = kits.fetch_kits(["python-docx"], home=self.home,
                                     from_dir=copy)
        self.assertEqual(kit.path("mutation/rules.json").read_bytes(),
                         KIT_FILES["mutation/rules.json"])
        self.assertEqual(self.hub.requests, [])

    def test_from_dir_without_the_release_names_both_places(self):
        with self.assertRaisesRegex(KitError, "neither .*kit-python-docx-v1.1"
                                              " nor .*releases/kit-python"):
            kits.fetch_kits(["python-docx"], home=self.home,
                            from_dir=self.tmp)

    def test_retry_after_forms(self):
        self.assertEqual(kits._retry_after({"Retry-After": "12"}, 1), 12.0)
        self.assertEqual(kits._retry_after({"Retry-After": "99999"}, 1),
                         kits.MAX_RETRY_AFTER)
        self.assertEqual(kits._retry_after(
            {"RateLimit": '"resolvers";r=0;t=30'}, 1), 30.0)
        self.assertEqual(kits._retry_after({}, 3), 3)


class Revision(unittest.TestCase):
    """The repository has no tags: the default revision is the upload's
    commit, filled on release day, and the offline guide downloads the same one."""

    def test_default_revision_is_a_commit_or_the_placeholder(self):
        self.assertTrue(kits.HF_REVISION == kits.HF_REVISION_UNFILLED
                        or re.fullmatch(r"[0-9a-f]{40}", kits.HF_REVISION),
                        kits.HF_REVISION)

    def test_offline_guide_downloads_the_default_revision(self):
        guide = (Path(__file__).resolve().parents[1] / "docs" / "kits.md").read_text()
        revisions = re.findall(r"^\s*hf download .*--revision (\S+)", guide,
                               re.M)
        self.assertEqual(revisions, [kits.HF_REVISION])


if __name__ == "__main__":
    unittest.main()
