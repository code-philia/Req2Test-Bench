"""Per-instance mutation scoring under a kit's rule table.

Harness plan A.3 items 6, 7, 8 and 10 and section B ("Rule table").

The scored set of instance i is its GT kill set

    G_i = kit pool pairs of i with `gold_outcome == "killed"`,
          minus the kit's `reference_excluded` pairs,
          minus every pair of a mutant on the engine's reviewed
          nondeterministic list (`benchmark/config/nondeterministic_mutants.yml`),

and each candidate row on a G_i pair is a kill, a survivor or a drop:

* single-observation family (python-docx, Algorand, CoreShop, Sylius, coddy;
  `rules.candidate_timeout == "drop"`): a kill is the literal `failed`; a
  candidate `timeout` or infrastructure outcome drops the pair from this
  test's own G_i (`bench/test_quality.py` `_single_observation_candidate_
  outcomes`);
* native family (Kapua, PrestaShop, e-petitions; `candidate_timeout ==
  "kill"`): `failed` or `timeout` is a kill (`data/mutation.py`
  `classify_outcome` under a passing baseline); infrastructure drops.

`rules.crash_kill` (coddy): a mutant-induced Go crash is a kill.  The engine
already records it as `failed` with a `crash` label (`bench/harness.py`
`RunResult.crash`); the label is counted in `n_crash_kills`.  Where
`crash_kill` is false such a row is dropped instead.

    recall        = killed / scored,  scored = |G_i| - dropped
    kill_complete = passed and scored > 0 and killed == scored

Every G_i pair of a scored pass needs its candidate row: a pass with some but
not all of them is an incomplete mutation run and is refused (resume it
first), as the paper's scorers refused missing pairs (`score_single_
observation`; `recall(..., expected_pairs=...)`).  A passing instance with no
candidate row at all is `unscored`, and one whose scored set is empty is
`not_scorable`; neither is kill-complete and neither has a recall.  The
strict companion also counts a pass with any dropped pair as
kill-incomplete.

The outcome vocabulary is the engine's own (`r2t.data.mutation`).
"""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator, Optional

from . import ENGINE_ROOT

if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))

from r2t.data.mutation import (  # noqa: E402  (engine on sys.path first)
    INFRASTRUCTURE_OUTCOMES as ENGINE_INFRASTRUCTURE_OUTCOMES,
    KILL_OUTCOMES as ENGINE_KILL_OUTCOMES,
    SURVIVED_OUTCOMES as ENGINE_SURVIVED_OUTCOMES,
    nondeterministic_mutants,
)

#: Instance outcomes of `instances.jsonl` (INTERFACES.md), ladder order.
OUTCOMES = ("generation_failure", "compilation_failure", "binding_failure",
            "execution_failure", "assertion_failure", "pass",
            "infrastructure_excluded")
PASS = "pass"
EXCLUDED = "infrastructure_excluded"

#: `mutation_status` of a scored instance row.
SCORED = "scored"
NOT_PASSED = "not_passed"
UNSCORED = "unscored"
NOT_SCORABLE = "not_scorable"
NOT_RUN = "not_run"

#: Recall threshold of the KillComplete companion (harness plan E.4).
RECALL_95 = 0.95

KILL, SURVIVED, DROPPED = "kill", "survived", "dropped"


class Rules:
    """The scoring rules of one project (kit `mutation/rules.json`)."""

    __slots__ = ("candidate_timeout", "crash_kill", "known_host_dependent")

    def __init__(self, candidate_timeout: str, crash_kill: bool = False,
                 known_host_dependent: Iterable[str] = ()):
        if candidate_timeout not in ("kill", "drop"):
            raise ValueError(f"rules.candidate_timeout must be 'kill' or "
                             f"'drop', not {candidate_timeout!r}")
        self.candidate_timeout = candidate_timeout
        self.crash_kill = bool(crash_kill)
        self.known_host_dependent = tuple(known_host_dependent)

    @classmethod
    def from_json(cls, doc: dict) -> "Rules":
        return cls(doc["candidate_timeout"], doc.get("crash_kill", False),
                   doc.get("known_host_dependent") or ())

    @property
    def family(self) -> str:
        return "native" if self.candidate_timeout == "kill" else \
            "single_observation"

    def to_json(self) -> dict:
        return {"family": self.family,
                "candidate_timeout": self.candidate_timeout,
                "crash_kill": self.crash_kill,
                "known_host_dependent": list(self.known_host_dependent)}


def classify(row: dict, rules: Rules) -> str:
    """`kill`, `survived` or `dropped` for one candidate row on a G_i pair."""
    outcome = row.get("outcome")
    if outcome in ENGINE_KILL_OUTCOMES:
        if row.get("crash") and not rules.crash_kill:
            return DROPPED
        return KILL
    if outcome == "timeout":
        return KILL if rules.candidate_timeout == "kill" else DROPPED
    if outcome in ENGINE_SURVIVED_OUTCOMES:
        return SURVIVED
    if outcome in ENGINE_INFRASTRUCTURE_OUTCOMES:
        return DROPPED
    raise ValueError(f"unknown candidate mutation outcome {outcome!r} for "
                     f"{row.get('instance_id') or row.get('item_id')} / "
                     f"{row.get('mutant_id')}")


# ------------------------------------------------------------ kit reference
def _kit_root(kit) -> Path:
    """The kit directory of a `req2test.kits.Kit` (its `root`) or a path."""
    if isinstance(kit, (str, os.PathLike)):
        return Path(kit)
    return Path(kit.root)


def read_text_lines(path: Path) -> Iterator[str]:
    """Lines of a text file, transparently decompressing `.zst`."""
    path = Path(path)
    if path.suffix != ".zst":
        with open(path, encoding="utf-8") as fh:
            yield from fh
        return
    try:
        import zstandard
    except ImportError:
        zstd = shutil.which("zstd")
        if zstd is None:
            raise RuntimeError(f"reading {path} needs the `zstandard` Python "
                               f"package or the `zstd` command") from None
        out = subprocess.run([zstd, "-dc", "--long=31", str(path)],
                             check=True, capture_output=True).stdout
        yield from io.StringIO(out.decode("utf-8"))
        return
    with open(path, "rb") as fh:
        reader = zstandard.ZstdDecompressor(max_window_size=1 << 31) \
            .stream_reader(fh)
        yield from io.TextIOWrapper(reader, encoding="utf-8")


def _first_existing(root: Path, *rels: str) -> Path:
    for rel in rels:
        if (root / rel).exists():
            return root / rel
    raise FileNotFoundError(f"kit {root} has none of {rels}")


class Reference:
    """A kit's mutation reference: the rules and every instance's G_i."""

    def __init__(self, project: str, rules: Rules, gold: dict,
                 n_pool_pairs: int, n_reference_excluded: int,
                 nondeterministic: Iterable[str] = ()):
        self.project = project
        self.rules = rules
        self.gold = gold
        self.n_pool_pairs = n_pool_pairs
        self.n_reference_excluded = n_reference_excluded
        #: The listed nondeterministic mutants this kit's G_i lost, sorted.
        self.nondeterministic = tuple(sorted(nondeterministic))

    def gold_set(self, instance_id: str) -> frozenset:
        return self.gold.get(instance_id, frozenset())

    @classmethod
    def from_kit(cls, kit) -> "Reference":
        """Read `mutation/{rules.json,pools.jsonl.zst,reference_excluded.jsonl}`."""
        root = _kit_root(kit)
        meta_path = root / "kit.json"
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        project = meta.get("project") or root.name
        rules = Rules.from_json(json.loads(
            (root / "mutation/rules.json").read_text()))
        excluded = set()
        for line in read_text_lines(_first_existing(
                root, "mutation/reference_excluded.jsonl",
                "mutation/reference_excluded.jsonl.zst")):
            if line.strip():
                row = json.loads(line)
                excluded.add((row["item_id"], row["mutant_id"]))
        killed: dict = {}
        n_pairs = 0
        unscored, dropped = nondeterministic_mutants(), set()
        for line in read_text_lines(_first_existing(
                root, "mutation/pools.jsonl.zst", "mutation/pools.jsonl")):
            if not line.strip():
                continue
            row = json.loads(line)
            n_pairs += 1
            if row["gold_outcome"] != "killed":
                continue
            if (row["item_id"], row["mutant_id"]) in excluded:
                continue
            if row["mutant_id"] in unscored:
                dropped.add(row["mutant_id"])
                continue
            killed.setdefault(row["item_id"], set()).add(row["mutant_id"])
        gold = {iid: frozenset(mids) for iid, mids in killed.items()}
        return cls(project, rules, gold, n_pairs, len(excluded), dropped)


@lru_cache(maxsize=16)
def _reference_at(root: str) -> Reference:
    return Reference.from_kit(Path(root))


def reference(kit) -> Reference:
    """The kit's `Reference`, read once per kit directory."""
    if isinstance(kit, Reference):
        return kit
    return _reference_at(str(_kit_root(kit).resolve()))


# ------------------------------------------------------------ exec outcome
def instance_id_of(row: dict) -> str:
    iid = row.get("instance_id") or row.get("item_id")
    if not iid:
        raise ValueError(f"row has no instance_id/item_id: {row!r}")
    return iid


#: Why an instance is `infrastructure_excluded`.
INFRASTRUCTURE = "infrastructure"     # the harness failed (engine marker)
OUTSIDE_LADDER = "outside_ladder"     # an engine outcome the ladder lacks


def classify_exec(exec_row: dict) -> tuple:
    """`(instance outcome, exclusion)` of one execution row.

    A row already in the instance vocabulary passes through.  An engine row
    (`outcome` in the engine's vocabulary) is placed by the engine's ladder
    (`r2t.bench.results.classify_row`): infrastructure markers are
    `infrastructure_excluded` (`INFRASTRUCTURE`); `parse_error` and
    `no_writable_files` are generation failures for submitted predictions
    (harness plan A.2, G.5(d)); an outcome outside the ladder is excluded
    (`OUTSIDE_LADDER`), as the paper's exception rule excluded it
    (`req2test/data/attempt_exclusions.json`).  `exclusion` is None unless
    the outcome is `infrastructure_excluded`.
    """
    outcome = exec_row.get("outcome")
    if outcome in OUTCOMES:
        return outcome, INFRASTRUCTURE if outcome == EXCLUDED else None
    from r2t.bench import results as R
    bucket, _marker = R.classify_row(exec_row)
    if bucket == "pass_rate":
        return PASS, None
    if bucket in OUTCOMES:
        return bucket, None
    if bucket == R.UNCLASSIFIED:
        return "generation_failure", None
    if bucket == R.INFRASTRUCTURE:
        return EXCLUDED, INFRASTRUCTURE
    return EXCLUDED, OUTSIDE_LADDER


def instance_outcome(exec_row: dict) -> str:
    """The instance outcome (`OUTCOMES`) of one execution row."""
    return classify_exec(exec_row)[0]


# ------------------------------------------------------------- scoring
def score_instance(kit, exec_row: dict,
                   mutation_rows: Optional[Iterable[dict]]) -> dict:
    """Mutation score of one instance.

    `kit` is a `req2test.kits.Kit`, a kit directory, or a loaded
    `Reference`.  `exec_row` is the instance's execution row (engine or
    instance vocabulary).  `mutation_rows` are its candidate rows
    `{instance_id|item_id, mutant_id, outcome[, crash]}`; rows of other
    instances and of pairs outside G_i are ignored.  None means the run did
    not score mutation at all (`--metrics exec`): every instance, passing or
    not, is then `not_run`, so the cell's mutation measures read as not
    measured rather than 0.
    """
    ref = reference(kit)
    iid = instance_id_of(exec_row)
    outcome, exclusion = classify_exec(exec_row)
    passed = outcome == PASS
    gold = ref.gold_set(iid)
    raw = exec_row.get("outcome")
    result = {
        "instance_id": iid, "outcome": outcome, "passed": passed,
        "excluded": outcome == EXCLUDED, "exclusion": exclusion,
        "engine_outcome": None if raw in OUTCOMES else raw,
        "mutation_status": NOT_PASSED, "recall": None,
        "kill_complete": False, "kill_complete_strict": False,
        "kill_complete_95": False,
        "n_gt_kills": len(gold), "n_scored": 0, "n_killed": 0,
        "n_dropped": 0, "n_crash_kills": 0,
        "n_timeout_kills": 0, "dropped_outcomes": {},
    }
    if mutation_rows is None:
        result["mutation_status"] = NOT_RUN
        return result
    if not passed:
        return result

    by_mutant: dict = {}
    seen_any = False
    for row in mutation_rows:
        if instance_id_of(row) != iid:
            continue
        seen_any = True
        mid = row["mutant_id"]
        if mid in by_mutant:
            raise ValueError(f"two candidate rows for {iid} / {mid} "
                             f"({by_mutant[mid].get('outcome')!r} and "
                             f"{row.get('outcome')!r}); resolve the retry "
                             f"before scoring")
        by_mutant[mid] = row
    if not seen_any:
        result["mutation_status"] = UNSCORED if gold else NOT_SCORABLE
        return result

    missing = sorted(gold - set(by_mutant))
    if missing:
        raise ValueError(
            f"incomplete mutation run; resume before scoring: {iid} has "
            f"{len(gold) - len(missing)} of its {len(gold)} G_i rows "
            f"(missing e.g. {missing[:3]})")
    killed = dropped = crash = timeout = 0
    dropped_outcomes: Counter = Counter()
    for mid in gold:
        row = by_mutant[mid]
        verdict = classify(row, ref.rules)
        if verdict == KILL:
            killed += 1
            crash += bool(row.get("crash"))
            timeout += row.get("outcome") == "timeout"
        elif verdict == DROPPED:
            dropped += 1
            dropped_outcomes[row.get("outcome")] += 1
    scored = len(gold) - dropped
    result.update({
        "n_scored": scored, "n_killed": killed, "n_dropped": dropped,
        "n_crash_kills": crash,
        "n_timeout_kills": timeout,
        "dropped_outcomes": dict(sorted(dropped_outcomes.items())),
    })
    if scored == 0:
        result["mutation_status"] = NOT_SCORABLE
        return result
    recall = killed / scored
    result.update({
        "mutation_status": SCORED, "recall": recall,
        "kill_complete": killed == scored,
        "kill_complete_strict": killed == scored and not dropped,
        "kill_complete_95": recall >= RECALL_95,
    })
    return result


def group_by_instance(rows: Iterable[dict]) -> dict:
    """`{instance_id: [rows]}` of candidate mutation rows."""
    grouped: dict = {}
    for row in rows:
        grouped.setdefault(instance_id_of(row), []).append(row)
    return grouped


def score_instances(kit, exec_rows: Iterable[dict],
                    mutation_rows: Optional[Iterable[dict]]) -> list:
    """`score_instance` for every execution row, mutation rows grouped once."""
    ref = reference(kit)
    if mutation_rows is None:
        return [score_instance(ref, row, None) for row in exec_rows]
    grouped = group_by_instance(mutation_rows)
    return [score_instance(ref, row, grouped.get(instance_id_of(row), ()))
            for row in exec_rows]
