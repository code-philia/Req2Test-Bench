"""`req2test.views`: build a 1.1 archive set from a fixture, materialize it back.

Run from the repository root:

    python -m unittest discover -s tests -p 'test_views.py'

Uses the engine's own Python source-view fixture (`fixture_map`) with a
synthetic repair set, so it needs no JDK, Go, tree-sitter, seed or map
download.
"""
import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from req2test import ENGINE_ROOT, views

sys.path.insert(0, str(ENGINE_ROOT))
from r2t.core.source_view import qualify_source_seed  # noqa: E402
from r2t.toolkit.source_views import prepare_view  # noqa: E402
from r2t.toolkit.source_views_selftest import (  # noqa: E402
    fixture_map, repair_data, write_repair_set)

SEED = "a" * 64
DIGEST = "b" * 64
READABLE = ("src", "features")
FIRST, SECOND = "fixture/example.feature:1", "fixture/example.feature:9"


def write_fixture(root: Path) -> Path:
    """The engine's Python fixture plus a data file one item omits."""
    source = root / "source"
    source.mkdir()
    doc = fixture_map(source)
    (source / "src" / "schema.json").write_text('{"valid": "value > 0"}\n')
    (source / "features").mkdir()
    (source / "features" / "x.feature").write_text("Feature: x\n")
    seed = qualify_source_seed(root=str(source), project="python-docx",
                               runtime_seed_digest=SEED, readable_paths=READABLE)
    first = doc["items"][0]
    second = {**first, "item_id": SECOND, "bodies": first["bodies"][1:],
              "omitted_paths": ["src/schema.json"]}
    doc.update(source_files_digest=seed.files_digest,
               subject_paths=["src/api.py", "src/schema.json"],
               items=[first, second],
               all_file_rules=[{"path": "src/schema.json",
                                "contract_paths": ["TARGET_CONTRACTS.md"]}])
    map_path = root / "map.json"
    map_path.write_text(json.dumps(doc))
    return map_path


def inputs(scope="target_hidden"):
    return views.ViewInputs(scope=scope, readable_paths=READABLE,
                            profile_digest=DIGEST, protocol_digest=DIGEST,
                            boundary_digest=DIGEST, provenance={})


def engine_manifest(root, map_path, item_id, scope="target_hidden"):
    """The engine's own view of one item, built directly."""
    prepared = prepare_view(
        source_root=str(root / "source"), readable_paths=READABLE,
        project="python-docx", runtime_seed_digest=SEED, map_path=str(map_path),
        scope=scope, profile_digest=DIGEST, protocol_digest=DIGEST,
        boundary_digest=DIGEST)
    task = {"item_id": item_id,
            prepared.annotation_field: prepared.annotations[item_id]}
    out = Path(tempfile.mkdtemp(dir=root)) / "v"
    return prepared.materialize(task, str(out)), out


def tree(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


PLACEHOLDER = b'{"implementation": "hidden"}\n'


def write_repairs(root: Path, map_path: Path, name="repairs-data", extra=()):
    """A synthetic repair set for the fixture: FIRST's hidden `src/api.py`
    gets a line, and the `src/schema.json` SECOND omits is added back as a
    placeholder.  Returns the `repair_data` patch that reads it."""
    data = root / name
    with repair_data(data, {}):
        _, unrepaired = engine_manifest(root, map_path, FIRST)
    th = (unrepaired / "src" / "api.py").read_bytes()
    pin = write_repair_set(data, "python-docx", [
        ("src/api.py", th, th + b"REPAIRED = True\n", "fixture-replace"),
        ("src/schema.json", None, PLACEHOLDER, "fixture-add"), *extra])
    return repair_data(data, {"python-docx": pin})


def build(root, map_path, out, eval_ids=(FIRST, SECOND), jobs=2, **kwargs):
    return views.build_views(
        project="python-docx", source_root=root / "source",
        runtime_seed_digest=SEED, map_path=map_path, inputs=inputs(),
        out_dir=out, scratch=root / "scratch", eval_ids=eval_ids, jobs=jobs,
        log=lambda *a: None, **kwargs)


class ViewsTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="req2test-views-test."))
        self.map_path = write_fixture(self.root)
        (self.root / "scratch").mkdir()
        self.repairs = write_repairs(self.root, self.map_path)
        self.repairs.start()
        self.addCleanup(self.repairs.stop)
        self.header = build(self.root, self.map_path, self.root / "views")
        self.views_dir = self.root / "views"

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_materialized_views_equal_the_engine_views(self):
        self.assertEqual(self.header["materialize_check"]["failures"], [])
        self.assertEqual(self.header["instances"], 2)
        for item_id in (FIRST, SECOND):
            with self.subTest(item=item_id):
                expected, expected_root = engine_manifest(self.root, self.map_path, item_id)
                out = self.root / f"out-th-{item_id.rsplit(':', 1)[1]}"
                manifest_path = self.root / f"{out.name}.json"
                views.materialize("python-docx", "th", item_id, out,
                                  views_dir=self.views_dir,
                                  manifest_path=manifest_path)
                self.assertEqual(json.loads(manifest_path.read_text()), expected)
                self.assertEqual(tree(out), tree(expected_root))

    def test_repairs_are_in_the_views_and_recorded(self):
        """The transformer, the index
        sha256 and the applied counts in views.json, each view's applied
        repairs in manifests.jsonl, and an added file shipped as a changed
        file of the overlay."""
        header = self.header
        # The fixture's map approves all-hidden, so the policy names both.
        self.assertEqual(header["transformer"],
                         "r2t.target-source-view/v2+r2t.all-production-source-view/v1")
        self.assertEqual(sorted(header["views"]), ["th"])
        self.assertNotIn("ah.tar.zst", header["archives"])
        self.assertEqual(sorted(p.name for p in (self.views_dir / "python-docx").iterdir()),
                         sorted(views_files_2_0()))
        repairs = dict(header["repairs"])
        self.assertRegex(repairs.pop("index_sha256"), "^[0-9a-f]{64}$")
        self.assertEqual(repairs, {"entries": 2, "entries_applied": 2, "views_repaired": 2,
                                   "eval_split_built": True, "eval_views": 2,
                                   "eval_entries_applied": 2, "eval_views_repaired": 2})
        rows = {row["instance_id"]: row for row in map(json.loads, (
            self.views_dir / "python-docx" / "manifests.jsonl").read_text().splitlines())}
        self.assertEqual({k: r["repairs"] for k, r in rows.items()},
                         {FIRST: [["src/api.py", "fixture-replace"]],
                          SECOND: [["src/schema.json", "fixture-add"]]})
        self.assertEqual(rows[SECOND]["omitted_paths"], ["src/schema.json"])
        first, second = self.root / "first", self.root / "second-repaired"
        views.materialize("python-docx", "th", FIRST, first, views_dir=self.views_dir)
        views.materialize("python-docx", "th", SECOND, second, views_dir=self.views_dir)
        self.assertTrue((first / "src" / "api.py").read_bytes().endswith(b"REPAIRED = True\n"))
        self.assertNotIn(b"REPAIRED", (second / "src" / "api.py").read_bytes())
        self.assertEqual((second / "src" / "schema.json").read_bytes(), PLACEHOLDER)

    def test_an_entry_no_eval_view_takes_stops_the_build(self):
        self.repairs.stop()
        stray = write_repairs(self.root, self.map_path, "stray", extra=[
            ("src/api.py", b"a view that drifted\n", b"never\n", "fixture-stray")])
        with stray:
            with self.assertRaisesRegex(views.ViewError, "1 repair entries apply to no view"):
                build(self.root, self.map_path, self.root / "stopped")
            self.assertFalse((self.root / "stopped").exists())
            # A build without the whole eval split records the counts instead.
            header = build(self.root, self.map_path, self.root / "partial", jobs=1,
                           eval_ids=(FIRST, SECOND, "fixture/not-built.feature:1"))
        self.repairs.start()
        self.assertFalse(header["repairs"]["eval_split_built"])
        self.assertEqual((header["repairs"]["entries"], header["repairs"]["eval_entries_applied"]),
                         (3, 2))

    def test_only_the_th_view_is_offered(self):
        with self.assertRaisesRegex(views.ViewError, "unknown view 'ah'"):
            views.materialize("python-docx", "ah", FIRST, self.root / "ah",
                              views_dir=self.views_dir)

    def test_overlay_hides_and_adds_the_repaired_file(self):
        out = self.root / "second"
        views.materialize("python-docx", "th", SECOND, out, views_dir=self.views_dir)
        self.assertEqual((out / "src" / "schema.json").read_bytes(), PLACEHOLDER)
        self.assertTrue((out / "TARGET_CONTRACTS.md").is_file())
        source = (self.root / "source" / "src" / "api.py").read_text()
        hidden = (out / "src" / "api.py").read_text()
        self.assertIn("hidden checker algorithm", source)
        self.assertNotIn("hidden checker algorithm", hidden)
        self.assertIn("return Checker().valid(value)", hidden)

    def test_tampered_base_is_refused_and_removed(self):
        base = self.views_dir / "python-docx" / "base.tar.zst"
        files = views.read_archive(base)
        files["features/x.feature"] += b"# changed\n"
        base.unlink()
        views.write_archive(base, files)
        out = self.root / "tampered"
        with self.assertRaises(views.ViewError):
            views.materialize("python-docx", "th", FIRST, out, views_dir=self.views_dir)
        self.assertFalse(out.exists())

    def test_cli_materializes_and_prints_the_digest(self):
        from req2test import cli
        out = self.root / "cli-view"
        argv = ["views", "materialize", "--project", "python-docx", "--view", "th",
                "--instance", SECOND, "--out", str(out),
                "--views-dir", str(self.views_dir)]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(cli.main(argv), 0)
        printed = json.loads(buffer.getvalue())
        row = views.load_manifest_row("python-docx", "th", SECOND, self.views_dir)
        self.assertEqual(printed["digest"], row["digest"])
        self.assertTrue((out / "src" / "api.py").is_file())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(argv), 2)  # the view now exists

    def _damage_overlays(self, record_sha=True):
        """Cut th_overlays.tar.zst in half."""
        pdir = self.views_dir / "python-docx"
        archive = pdir / "th_overlays.tar.zst"
        raw = archive.read_bytes()
        archive.write_bytes(raw[:len(raw) // 2])
        if record_sha:  # views.json agrees with the damaged bytes
            header = json.loads((pdir / "views.json").read_text())
            header["archives"]["th_overlays.tar.zst"]["sha256"] = \
                views._sha256_file(archive)
            (pdir / "views.json").write_text(json.dumps(header))
        return pdir

    def _assert_refused_cleanly(self, pdir, needle):
        out = self.root / "damaged"
        with self.assertRaises(views.ViewError) as caught:
            views.materialize("python-docx", "th", FIRST, out, views_dir=self.views_dir)
        self.assertIn(needle, str(caught.exception))
        self.assertFalse(out.exists())
        self.assertEqual([p.name for p in pdir.iterdir() if p.name.startswith(".th_overlays")], [])

    def test_truncated_overlay_archive_is_a_view_error(self):
        pdir = self._damage_overlays()
        self._assert_refused_cleanly(pdir, "re-fetch the views")

    def test_overlay_archive_must_match_views_json(self):
        pdir = self._damage_overlays(record_sha=False)
        self._assert_refused_cleanly(pdir, "sha256 is not")

    def test_damaged_base_is_a_view_error(self):
        base = self.views_dir / "python-docx" / "base.tar.zst"
        raw = base.read_bytes()
        base.write_bytes(raw[:len(raw) // 2])
        out = self.root / "damaged-base"
        with self.assertRaises(views.ViewError) as caught:
            views.materialize("python-docx", "th", FIRST, out,
                              views_dir=self.views_dir)
        self.assertIn("re-fetch the views", str(caught.exception))
        self.assertFalse(out.exists())

    def test_refuses_existing_destination(self):
        out = self.root / "exists"
        out.mkdir()
        with self.assertRaisesRegex(views.ViewError, "already exists"):
            views.materialize("python-docx", "th", FIRST, out, views_dir=self.views_dir)

    def test_archives_are_deterministic(self):
        files = {"b/x.txt": b"x", "a.txt": b"a" * 1000}
        first = views.write_archive(self.root / "one.tar.zst", files)
        second = views.write_archive(self.root / "two.tar.zst", dict(reversed(files.items())))
        self.assertEqual(first, second)
        self.assertEqual(views.read_archive(self.root / "one.tar.zst"), files)


class RecipeTest(unittest.TestCase):
    def test_recipes_are_the_c2r_exec_inputs(self):
        """The views build from each project's `_exec` profile and its c2r
        protocol, 401-408."""
        protocols = {}
        for project in views.RECIPES:
            vi = views.recipe_inputs(project)
            self.assertEqual(vi.scope, "target_hidden")
            self.assertTrue(vi.provenance["profile"].endswith("_target_hidden_exec.yml"))
            protocols[project] = vi.provenance["protocol"]
        self.assertEqual(sorted(protocols.values()), list(range(401, 409)))


def views_files_2_0():
    from req2test import kits
    return kits.VIEW_FILES


if __name__ == "__main__":
    unittest.main()
