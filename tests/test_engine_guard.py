"""The scoring-set guard (`req2test.engine.check_scoring_set`) and the
self-test selection of `selftest --engine`."""
import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from req2test import engine
from req2test.engine import check_scoring_set

REL = "benchmark/r2t/bench/harness.py"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch(pid, before, after):
    return {"id": pid, "files": [REL], "sha256_before": {REL: before},
            "sha256_after": {REL: after}, "reason": "test"}


class ScoringSetGuard(unittest.TestCase):
    def check(self, current: bytes, patches: list) -> list:
        with TemporaryDirectory() as root:
            path = Path(root, REL)
            path.parent.mkdir(parents=True)
            path.write_bytes(current)
            upstream = {"scoring_set": {REL: sha(b"v0")}, "patches": patches}
            return check_scoring_set(Path(root), upstream)

    def test_upstream_bytes_pass_and_unlisted_changes_fail(self):
        self.assertEqual(self.check(b"v0", []), [])
        self.assertIn("no listed patch declares it", self.check(b"v1", [])[0])

    def test_one_patch(self):
        self.assertEqual(self.check(b"v1", [patch("A", sha(b"v0"), sha(b"v1"))]), [])
        problems = self.check(b"v0", [patch("A", sha(b"v0"), sha(b"v1"))])
        self.assertEqual(len(problems), 1)
        self.assertIn("is not patch A sha256_after", problems[0])

    def test_patches_chain_in_list_order(self):
        chain = [patch("A", sha(b"v0"), sha(b"v1")),
                 patch("B", sha(b"v1"), sha(b"v2"))]
        self.assertEqual(self.check(b"v2", chain), [])
        # The file must be the LAST patch's bytes, not an intermediate one.
        self.assertIn("is not patch B sha256_after", self.check(b"v1", chain)[0])

    def test_a_broken_chain_is_named(self):
        # B claims to start from upstream, but A already changed the file.
        chain = [patch("A", sha(b"v0"), sha(b"v1")),
                 patch("B", sha(b"v0"), sha(b"v2"))]
        problems = self.check(b"v2", chain)
        self.assertEqual(len(problems), 1)
        self.assertIn("patch B sha256_before", problems[0])
        self.assertIn("is not patch A sha256_after", problems[0])
        # And a first patch must start from the upstream bytes.
        problems = self.check(b"v2", [patch("A", sha(b"vX"), sha(b"v2"))])
        self.assertIn("is not the upstream", problems[0])


class SelftestSelection(unittest.TestCase):
    def test_every_skipped_module_is_a_module_of_a_run_component(self):
        from r2t.core.components import component_modules
        run = {m for c in engine.SELFTEST_COMPONENTS
               for m in component_modules(c)}
        self.assertEqual(sorted(set(engine.SELFTEST_SKIPPED) - run), [])

    def test_skipped_modules_are_left_out_and_core_stays(self):
        for component in engine.SELFTEST_COMPONENTS:
            modules = engine.selftest_modules(component)
            self.assertFalse(set(modules) & set(engine.SELFTEST_SKIPPED))
            self.assertIn("core.paths", modules)
        self.assertIn("stacks.behave", engine.selftest_modules("bench"))


if __name__ == "__main__":
    unittest.main()
