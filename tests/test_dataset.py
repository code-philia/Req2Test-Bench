"""Tests of `req2test.dataset`: where the dataset is read from.

    python3 -m unittest tests.test_dataset -v
"""
from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from req2test import dataset, kits


class DefaultDataDir(unittest.TestCase):

    def resolve(self, **env):
        clean = {k: v for k, v in os.environ.items()
                 if k not in ("REQ2TEST_DATA_DIR", "REQ2TEST_HOME")}
        clean.update(env)
        with mock.patch.dict(os.environ, clean, clear=True):
            return dataset.default_data_dir()

    def test_data_dir_wins(self):
        self.assertEqual(self.resolve(REQ2TEST_DATA_DIR="/d",
                                      REQ2TEST_HOME="/h"), Path("/d"))

    def test_home_next(self):
        self.assertEqual(self.resolve(REQ2TEST_HOME="/h"),
                         Path("/h/data/dataset-v1.1"))

    def test_default_last(self):
        self.assertEqual(self.resolve(),
                         Path("~/.req2test/data/dataset-v1.1").expanduser())

    def test_fetch_installs_where_the_loader_reads(self):
        with mock.patch.dict(os.environ, {"REQ2TEST_HOME": "/h"}):
            os.environ.pop("REQ2TEST_DATA_DIR", None)
            self.assertEqual(kits.dataset_dir(), dataset.default_data_dir())


if __name__ == "__main__":
    unittest.main()
