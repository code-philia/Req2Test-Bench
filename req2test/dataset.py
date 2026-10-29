"""Load the Req2Test-Bench dataset from a local directory.

The dataset ships as the release `dataset-v1.1` of the Hugging Face dataset
repository (installed by `req2test fetch`), not in this repository.  Its
layout, documented in `docs/dataset.md`:

    <data_dir>/eval.jsonl              the evaluated instances
    <data_dir>/full.jsonl              every execution-validated instance
    <data_dir>/gt_tests/<project>.jsonl  ground-truth test file contents

`data_dir` defaults to `$REQ2TEST_DATA_DIR`, else
`$REQ2TEST_HOME/data/dataset-v1.1` (where `req2test fetch` installs it), else
`~/.req2test/data/dataset-v1.1`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator, Optional

DATASET_VERSION = "dataset-v1.1"
SPLITS = ("eval", "full")
PROJECTS = ("algorand-sdk", "coddy-agent", "coreshop", "e-petitions",
            "kapua", "prestashop", "python-docx", "sylius")


def default_data_dir() -> Path:
    env = os.environ.get("REQ2TEST_DATA_DIR")
    if env:
        return Path(env).expanduser()
    home = os.environ.get("REQ2TEST_HOME") or "~/.req2test"
    return Path(home).expanduser() / "data" / DATASET_VERSION


def _resolve(data_dir) -> Path:
    root = default_data_dir() if data_dir is None else Path(data_dir).expanduser()
    if not root.is_dir():
        raise FileNotFoundError(
            f"dataset directory {root} does not exist; download the "
            f"{DATASET_VERSION} release with `req2test fetch`, or pass its "
            f"location (data_dir or REQ2TEST_DATA_DIR)")
    return root


def _check_project(project: Optional[str]) -> None:
    if project is not None and project not in PROJECTS:
        raise ValueError(f"unknown project {project!r}; expected one of "
                         f"{', '.join(PROJECTS)}")


def iter_jsonl(path: Path) -> Iterator[dict]:
    with open(path, encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: not JSON: {exc}") from exc


def fetch_hint(split: str) -> str:
    """How to install `<split>.jsonl`, on a host with Internet access and on
    one without (`req2test fetch` installs eval only; full needs `--split
    full`)."""
    fetch = ("req2test fetch --split full --dataset-only" if split == "full"
             else "req2test fetch --dataset-only")
    return (f"run `{fetch}`; on a host without Internet access, run "
            f"`{fetch} --download-only DIR` on one that has it, copy DIR "
            f"here and run `{fetch} --from-dir DIR`")


def iter_instances(split: str = "eval", project: Optional[str] = None,
                   data_dir=None) -> Iterator[dict]:
    """Rows of `<split>.jsonl`, optionally one project's only."""
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}; expected one of "
                         f"{', '.join(SPLITS)}")
    _check_project(project)
    path = _resolve(data_dir) / f"{split}.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"{path} does not exist; {fetch_hint(split)}")
    for row in iter_jsonl(path):
        if project is None or row["project"] == project:
            yield row


def load_instances(split: str = "eval", project: Optional[str] = None,
                   data_dir=None) -> list:
    """All rows of `<split>.jsonl` (in file order), optionally one project's."""
    return list(iter_instances(split, project, data_dir))


def iter_gt_tests(project: str, data_dir=None) -> Iterator[dict]:
    """Rows of `gt_tests/<project>.jsonl`: `instance_id`, `files`, ..."""
    _check_project(project)
    if project is None:
        raise ValueError("ground-truth tests are stored per project; name one")
    yield from iter_jsonl(_resolve(data_dir) / "gt_tests" / f"{project}.jsonl")


def load_gt_tests(project: str, instance_ids=None, data_dir=None) -> dict:
    """`{instance_id: row}` for one project, optionally only `instance_ids`.

    A project's file can be large (PrestaShop's is about 150 MB), so pass
    `instance_ids` when only a few rows are needed.
    """
    wanted = None if instance_ids is None else set(instance_ids)
    rows = {}
    for row in iter_gt_tests(project, data_dir):
        if wanted is None or row["instance_id"] in wanted:
            rows[row["instance_id"]] = row
    if wanted is not None and wanted - set(rows):
        missing = sorted(wanted - set(rows))
        raise KeyError(f"{len(missing)} instance(s) have no ground-truth "
                       f"tests in {project}: {missing[:5]}")
    return rows
