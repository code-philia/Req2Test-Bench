"""Predictions: the generated tests a user submits for evaluation.

Schema `req2test.predictions/1`, one JSON object per line:

    {"instance_id": "...", "model_name_or_path": "...",
     "view": "th" (optional),
     "benchmark_version": "1.1" (optional),
     "files": [{"path": "features/steps/x.py", "content": "..."}],
     "status": "ok|no_output" (optional)}

`benchmark_version` is the task row's: the benchmark whose tasks the system
answered (`BENCHMARK_VERSIONS`).  A row may leave it out; the run's summary
and report record the version evaluated.

A missing row, an empty `files` list, or `status: no_output` is a generation
failure: the instance stays in the denominator with the engine's own
`no_files_returned` outcome, written without executing it
(`req2test.execute.generation_failure_row`).

Paths are relative to the repository root.  The task's `placement.path` and
prompt name the agent's tree `repo/`, so a leading `repo/` is removed, with
one warning per instance (`repo/features/steps/x.py` is
`features/steps/x.py`).  The warning is kept on the prediction (`notes`), so
`evaluate` prints it only for the instances it selects (`warn_notes`).

`to_engine` turns a prediction into the engine's `produced_files`
(`[{file_path, code}]`), the shape every engine adapter returns.
`from_gt` builds predictions from the dataset's ground-truth tests, exactly as
the engine's gold adapter assembles them (`bench/fixtures.py`
`make_gold_adapter`), including the `behat_services.yml` fragment CoreShop and
Sylius contexts need.
"""
from __future__ import annotations

import base64
import json
import posixpath
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

SCHEMA = "req2test.predictions/1"
STATUSES = ("ok", "no_output")
VIEWS = ("th",)
#: The benchmark versions this package evaluates: 1.1, the target-hidden
#: setting with a runnable application runtime.
BENCHMARK_VERSIONS = ("1.1",)
#: The name the engine's gold adapter gives the DI fragment it writes.
SERVICES_FILE = "behat_services.yml"
#: The agent's name for the repository root (`placement.path`, the prompt).
REPO_PREFIX = "repo/"
_KEYS = {"instance_id", "model_name_or_path", "view", "benchmark_version",
         "files", "status"}


class PredictionError(ValueError):
    pass


@dataclass
class Prediction:
    instance_id: str
    model_name_or_path: str
    files: list = field(default_factory=list)   # [{"path", "content"}]
    view: Optional[str] = None
    status: Optional[str] = None
    benchmark_version: Optional[str] = None
    #: Warnings about the row (a removed `repo/` prefix); not part of it.
    notes: list = field(default_factory=list, compare=False, repr=False)
    #: Set by `from_gt` only: the files are the instance's ground-truth test,
    #: which the engine runs as gold (`req2test.execute.make_adapter`).
    ground_truth: bool = field(default=False, compare=False, repr=False)

    @property
    def generation_failure(self) -> bool:
        return self.status == "no_output" or not self.files

    def to_json(self) -> dict:
        row = {"instance_id": self.instance_id,
               "model_name_or_path": self.model_name_or_path,
               "files": self.files}
        if self.view is not None:
            row["view"] = self.view
        if self.benchmark_version is not None:
            row["benchmark_version"] = self.benchmark_version
        if self.status is not None:
            row["status"] = self.status
        return row


def _check_path(path, where: str) -> str:
    if not isinstance(path, str) or not path:
        raise PredictionError(f"{where}: path must be a nonempty string")
    if "\\" in path or "\x00" in path:
        raise PredictionError(f"{where}: path {path!r} has a backslash or NUL")
    norm = posixpath.normpath(path)
    if path.startswith("/") or norm != path or norm.startswith("../") \
            or norm == "..":
        raise PredictionError(
            f"{where}: path {path!r} must be relative to the repository root, "
            f"normalized, and stay inside it")
    return path


def validate_row(row: dict, where: str,
                 warn: Optional[Callable[[str], None]] = None) -> Prediction:
    """One predictions row, checked; raises `PredictionError`.

    A leading `repo/` is removed from file paths, with one message per row
    that had one, kept in the prediction's `notes` and given to `warn` (if
    given).
    """
    if not isinstance(row, dict):
        raise PredictionError(f"{where}: not a JSON object")
    unknown = sorted(set(row) - _KEYS)
    if unknown:
        raise PredictionError(f"{where}: unknown keys {unknown}")
    iid = row.get("instance_id")
    if not isinstance(iid, str) or not iid:
        raise PredictionError(f"{where}: instance_id must be a nonempty string")
    model = row.get("model_name_or_path")
    if not isinstance(model, str) or not model.strip():
        raise PredictionError(
            f"{where}: model_name_or_path must be a nonempty string")
    view = row.get("view")
    if view is not None and view not in VIEWS:
        raise PredictionError(f"{where}: view must be one of {VIEWS}")
    status = row.get("status")
    if status is not None and status not in STATUSES:
        raise PredictionError(f"{where}: status must be one of {STATUSES}")
    version = row.get("benchmark_version")
    if version is not None and version not in BENCHMARK_VERSIONS:
        raise PredictionError(f"{where}: benchmark_version must be one of "
                              f"{BENCHMARK_VERSIONS}")
    files = row.get("files", [])
    if not isinstance(files, list):
        raise PredictionError(f"{where}: files must be a list")
    seen = set()
    clean = []
    stripped = []
    for n, entry in enumerate(files, 1):
        at = f"{where} files[{n}]"
        if not isinstance(entry, dict) or set(entry) != {"path", "content"}:
            raise PredictionError(
                f"{at}: each file is exactly {{path, content}}")
        path = _check_path(entry["path"], at)
        if path.startswith(REPO_PREFIX):
            stripped.append(path)
            path = path[len(REPO_PREFIX):]
        if not isinstance(entry["content"], str):
            raise PredictionError(f"{at}: content must be a string")
        if path in seen:
            raise PredictionError(f"{at}: duplicate path {path!r}")
        seen.add(path)
        clean.append({"path": path, "content": entry["content"]})
    notes = []
    if stripped:
        notes.append(
            f"{where}: {iid}: removed the leading {REPO_PREFIX!r} from "
            f"{len(stripped)} file path(s), e.g. {stripped[0]!r} -> "
            f"{stripped[0][len(REPO_PREFIX):]!r}; prediction paths are "
            f"relative to the repository root")
    if warn is not None:
        for note in notes:
            warn(note)
    return Prediction(iid, model, clean, view, status, version, notes)


def _warn(message: str) -> None:
    print(f"req2test: warning: {message}", file=sys.stderr, flush=True)


def warn_notes(predictions: dict,
               warn: Callable[[str], None] = _warn) -> None:
    """Give `warn` the `notes` of `predictions`, in their order."""
    for pred in predictions.values():
        for note in pred.notes:
            warn(note)


def load(path, *, project: Optional[str] = None,
         view: Optional[str] = None,
         warn: Optional[Callable[[str], None]] = _warn) -> dict:
    """`{instance_id: Prediction}` from a predictions JSONL file.

    Refuses malformed rows and duplicate ids.  With `project`, rows of other
    projects are skipped (a file may hold several projects); with `view`, a
    row that names a different view is refused.  `warn` gets the warnings
    of the rows kept (a removed `repo/` prefix); with `warn=None` they stay
    in each prediction's `notes` for the caller (`warn_notes`).
    """
    out: dict = {}
    with open(path, encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            where = f"{path}:{number}"
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PredictionError(f"{where}: not JSON: {exc.msg}") from exc
            pred = validate_row(row, where)
            if project is not None \
                    and not pred.instance_id.startswith(project + "/"):
                continue
            if view is not None and pred.view not in (None, view):
                raise PredictionError(
                    f"{where}: row is for view {pred.view!r}, but this "
                    f"evaluation is view {view!r}")
            if pred.instance_id in out:
                raise PredictionError(
                    f"{where}: duplicate instance_id {pred.instance_id!r}")
            if warn is not None:
                warn_notes({pred.instance_id: pred}, warn)
            out[pred.instance_id] = pred
    return out


def dump(predictions: Iterable[Prediction], path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for pred in predictions:
            fh.write(json.dumps(pred.to_json(), ensure_ascii=False,
                                sort_keys=True) + "\n")


def to_engine(pred: Optional[Prediction]) -> list:
    """The engine's `produced_files` for one prediction (empty on failure)."""
    if pred is None or pred.status == "no_output":
        return []
    return [{"file_path": f["path"], "code": f["content"]}
            for f in pred.files]


def services_fragment(di_fragment: dict) -> str:
    """`behat_services.yml` for a DI fragment, as `make_gold_adapter` writes it.

    Same keys, same order, same `yaml.safe_dump(..., sort_keys=False)`, so a
    ground-truth prediction is byte-identical to the engine's gold control.
    """
    import yaml
    frag = {"services": {}}
    for sid, body in di_fragment.items():
        entry = {"class": body["class"]}
        if body.get("arguments"):
            entry["arguments"] = body["arguments"]
        if body.get("tags"):
            entry["tags"] = body["tags"]
        frag["services"][sid] = entry
    return yaml.safe_dump(frag, sort_keys=False)


def _gt_content(entry: dict, where: str) -> str:
    if isinstance(entry.get("content"), str):
        return entry["content"]
    if entry.get("content_base64") is not None:
        try:
            return base64.b64decode(entry["content_base64"]).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise PredictionError(
                f"{where}: {entry.get('path')} is not UTF-8 text; the engine "
                f"executes text files only") from exc
    raise PredictionError(f"{where}: {entry.get('path')} has no content")


def from_gt(project: str, ids: Optional[Iterable[str]] = None, *,
            data_dir=None, model_name: str = "ground-truth",
            view: Optional[str] = None) -> dict:
    """Predictions made from `gt_tests/<project>.jsonl` (the smoke check).

    The files are the instance's ground-truth Test Implementation in dataset
    order; a CoreShop/Sylius `di_fragment` adds `behat_services.yml` last,
    which is the order `make_gold_adapter` returns them in.  Each is marked
    `ground_truth`, so the engine runs it as the gold run it is, without
    the answer-handling rules of candidate runs (docs/agents.md, "What the
    harness does with the answer").
    """
    from . import dataset
    from .layout import data_dir as default_data_dir
    rows = dataset.load_gt_tests(project, instance_ids=ids,
                                 data_dir=data_dir or default_data_dir())
    out = {}
    for iid in (sorted(rows) if ids is None else list(ids)):
        row = rows[iid]
        files = [{"path": entry["path"],
                  "content": _gt_content(entry, iid)}
                 for entry in row["files"]]
        if row.get("di_fragment"):
            files.append({"path": SERVICES_FILE,
                          "content": services_fragment(row["di_fragment"])})
        out[iid] = validate_row({"instance_id": iid,
                                 "model_name_or_path": model_name,
                                 "files": files,
                                 **({"view": view} if view else {})},
                                f"gt_tests/{project}.jsonl {iid}")
        out[iid].ground_truth = True
    return out


def digest(predictions: dict) -> str:
    """sha256 over the canonical JSON of the predictions, by instance id."""
    import hashlib
    payload = json.dumps([predictions[k].to_json() for k in sorted(predictions)],
                         ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def write_normalized(predictions: dict, ids: Iterable[str], path: Path) -> None:
    """`predictions.norm.jsonl`: one engine-shaped row per evaluated instance.

    Every instance in `ids` gets a row; a missing prediction is written as a
    generation failure, so the file states the whole population.
    """
    with open(path, "w", encoding="utf-8") as fh:
        for iid in ids:
            pred = predictions.get(iid)
            row = {"instance_id": iid,
                   "model_name_or_path": pred.model_name_or_path if pred else None,
                   "generation_failure": pred is None or pred.generation_failure,
                   "produced_files": to_engine(pred)}
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
