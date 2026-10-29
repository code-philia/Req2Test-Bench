"""The fixtures: the controls and the transports, and how a run builds them.

Six of the names `--adapter` accepts are not systems under test at all.
`gold`, `stripped-gold`, `empty` and `stub` are controls -- the harness's
own upper bound, its de-saturation control, its nothing-at-all control and
its anti-vacuity floor -- and `replay` and `submitted` are transports that
re-serve bytes something else produced.  They are what the consumer route
runs on: a checkout with no agent package at all builds every one of them,
and `runner.build_adapter` resolves them HERE before it asks the agent
registry about anything.

What this module holds is therefore everything a fixture needs and nothing
an agent does: the `Adapter` record every builder returns, the `AdapterSpec`
record the menu is written in (the six fixture rows below are instances of
it, and so are the agent registry's), the four fixture adapter bodies, and
the six `build` functions the runner calls with `(args, harness)`.  Each
`build` is the body of the matching branch of `runner.build_adapter`
argument for argument, and the refusals are the same strings.

The stub and assertion-stripped gold use the framework-specific factories.
Go empty controls also need their explicit coordinator-owned factory, because
retained tests require declaration-only support after removing the glue.
These factories dispatch through the checked profile, and read
the profile whole -- digests verified -- for `cli._stack`'s reason: a
profile whose prompts have moved under it is not a profile this benchmark
may act on, whichever field is being read out of it.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from ..core.constants import SUBMITTED_CONDITION


#: The three kinds of thing this harness can evaluate.
#:
#:   prompt    a model behind a prompt: one call, no repository, no tools.
#:   agent     a system that acts — reads the tree, runs commands, iterates.
#:   fixture   not a system under test at all: gold, stripped-gold, empty,
#:             stub and replay are controls/transports, and metrics treat
#:             them so.
#:
#: The distinction is load-bearing rather than descriptive: `runner`'s
#: reproducibility check re-invokes only what cannot generate, and the ladder
#: reports a fixture's number as a bound rather than as a result.
ADAPTER_KINDS = ("prompt", "agent", "fixture")


@dataclass(frozen=True)
class AdapterSpec:
    """One evaluable system, and how to construct it from a run's flags.

    `build` takes `(args, harness)` — the same two things `build_adapter`
    was handed — and returns an `Adapter`.  It may refuse: a spec
    whose flags contradict each other raises `SystemExit` with a REFUSED
    message, and it does so BEFORE anything expensive, because the refusals
    exist to stop a paid sweep rather than to annotate one.
    """
    name: str
    version: int
    kind: str
    build: Callable
    trajectory_format: Optional[str] = None
    sandbox: Optional[str] = None
    #: Which results this system's rows may be POOLED with (`r2t/bench/report.py`,
    #: `r2t/metrics.comparison_class`).
    #:
    #: On the spec rather than derived from `kind` at the point of use,
    #: because it is a claim about comparability and not a description of the
    #: implementation: `openhands` and `openai` are both a fixed model behind
    #: a fixed scaffold -- a table may hold both -- while a hypothetical
    #: product system that chooses its own model and its own budget is a
    #: different population wearing the same table's denominator.
    #:
    #: `None` for the fixtures, deliberately.  `gold`, `stripped-gold`,
    #: `empty`, `stub` and `replay` are controls and transports, not systems
    #: under test; giving them a class would let a control's rows pool with a
    #: system's, and the metrics already grandfather a row that carries no
    #: class rather than defaulting it into one.
    comparison_class: Optional[str] = None
    #: The native-manifest schema this system's rows OWE, or None.
    #:
    #: Set (to `agents.scanners.MANIFEST_SCHEMA`) for a system whose driver
    #: preserves the framework's own artifacts as a second recorder (plan
    #: D8b): trajectory validation then treats an attempt of this system
    #: WITHOUT a readable, validating `native_manifest.json` as not intact,
    #: because
    #: the driver survives a failed preservation on purpose (the run must
    #: not be discarded by bookkeeping) and the only honest place for that
    #: loss to surface is validation.  On the SPEC rather than as a string in
    #: the validator so that which systems owe a manifest is declared
    #: exactly where the systems are, and archived systems that never
    #: promised one (openhands@1) keep their path untouched.
    native_manifest: Optional[str] = None

    def __post_init__(self) -> None:
        if self.kind not in ADAPTER_KINDS:
            raise ValueError(
                f"adapter {self.name!r} has kind {self.kind!r}, which is not "
                f"one of {ADAPTER_KINDS}")
        # A fixture that claimed a comparison class would be a control that
        # can be added to a system's table -- the exact pooling error
        # `report.check_comparison_class` exists to refuse, introduced one
        # level below where it looks.
        if self.kind == "fixture" and self.comparison_class is not None:
            raise ValueError(
                f"adapter {self.name!r} is a fixture and may not declare a "
                f"comparison_class ({self.comparison_class!r}): a control is "
                f"not a population a system's rows may be pooled with")

    @property
    def qualified(self) -> str:
        """`openhands@1` — the name a result should be attributed to."""
        return f"{self.name}@{self.version}"


@dataclass
class Adapter:
    name: str
    fn: Callable[[dict], dict]
    config: dict = field(default_factory=dict)

    def __call__(self, task: dict) -> dict:
        return self.fn(task)


# --------------------------------------------------------------- built-ins
def make_empty_adapter() -> Adapter:
    return Adapter("empty", lambda task: {"files": [], "metadata": {}})


def make_gold_adapter(release_dir: str, gold_root: str, *,
                      context_check=None, items=None) -> Adapter:
    from ..data.release import load_gold

    manifest_path = os.path.join(release_dir, "gold", "manifest.json")
    if not os.path.isfile(manifest_path):
        raise SystemExit(
            f"REFUSED: gold adapter requires {manifest_path}; no item was "
            "run. Install the project's scoring bundle and pass its release "
            "items with --release.")

    # Go sidecars are bound before a run opens output or enters adapter error
    # folding. Retain the exact checked metadata; source bytes are read below.
    snapshot = None
    if context_check is not None:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        snapshot = {}
        for iid in manifest:
            gold = load_gold(release_dir, iid)
            context_check(gold)
            if gold["item_id"] != iid:
                from ..go.context import ContextRefused
                raise ContextRefused("REFUSED: gold sidecar item identity mismatch")
            snapshot[iid] = gold
        if items is not None:
            from ..go.context import ContextRefused, compare_context
            for item in items:
                context_check(item)
                if item["item_id"] not in snapshot:
                    raise ContextRefused(
                        f"REFUSED: Go item {item['item_id']} has no gold sidecar")
                compare_context(item, snapshot[item["item_id"]])

    def run(task: dict) -> dict:
        gold = (snapshot.get(task["item_id"]) if snapshot is not None else
                load_gold(release_dir, task["item_id"]))
        if gold is None:
            return {"files": [], "metadata": {"error": "no gold for item"}}
        from ..go.context import compare_context, is_go
        if is_go(task) or is_go(gold):
            compare_context(task, gold)
        files = []
        for rel in gold["files"]:
            with open(os.path.join(gold_root, rel), encoding="utf-8") as fh:
                files.append({"file_path": rel, "code": fh.read()})
        if gold.get("di_fragment"):
            frag = {"services": {}}
            for sid, body in gold["di_fragment"].items():
                entry = {"class": body["class"]}
                if body.get("arguments"):
                    entry["arguments"] = body["arguments"]
                if body.get("tags"):
                    entry["tags"] = body["tags"]
                frag["services"][sid] = entry
            import yaml
            files.append({"file_path": "behat_services.yml",
                          "code": yaml.safe_dump(frag, sort_keys=False)})
        return {"files": files, "metadata": {"source": "gold"}}

    return Adapter("gold", run, {"release": release_dir})


# The generator's identity and allowances survive re-execution. Execution
# coverage, repeats, harness/worker identity and outcomes belong to the new run.
REPLAY_GENERATION_FIELDS = (
    "condition", "model", "temperature", "max_tokens", "max_iterations",
    "trials", "sandboxed", "prompt_digest", "agent_system", "adapter_version",
    "comparison_class", "agent_version", "agent_runtime_sha256",
    "agent_command_mode", "protocol_version", "protocol_digest",
    "protocol_deviations", "setting", "agent_timeout_seconds", "native_budget",
)


def make_replay_adapter(cache_path: str) -> Adapter:
    """Re-serve a previous generation, so execution can be repeated for free.

    The system under test is still whatever produced the cache — the
    adapter takes ITS name so a replayed row stamps identically and the
    resume/refusal logic keeps working.  Replay is a transport detail and is
    recorded as `replayed_from`, not as a different system.

    This is what makes a harness fix or a metric invented later re-scorable:
    a 100-item agent sweep costs hours and real money to generate and about
    half an hour to execute, so the expensive half must never have to be
    repeated for a reason that has nothing to do with the model.
    """
    from .generate import load_cache
    cache = load_cache(cache_path)
    if not cache:
        raise SystemExit(f"no generation cache at {cache_path}")
    # Replay is the INTERNAL-cache mechanism, never the submitted-consumer
    # route.  A submitted run file replays byte-perfectly, but the replayed
    # rows would be stamped with THIS run's labels -- and this run has no
    # `condition: submitted`, so the tier would be dropped in transit and the
    # laundered rows would re-enter every canonical path.  Refused at the
    # entry, before any row is served.
    submitted = sorted(item_id for item_id, r in cache.items()
                       if r.get("condition") == SUBMITTED_CONDITION)
    if submitted:
        raise SystemExit(
            f"REFUSED: {cache_path} holds submitted-tier rows (e.g. "
            f"{submitted[0]}). Replay re-serves this harness's own "
            f"generations; re-serving submitted bytes would drop their tier "
            f"label. External candidates go through `--adapter submitted "
            f"--candidates`, which re-validates and re-stamps them.")
    names = {r.get("adapter") for r in cache.values() if r.get("adapter")}
    if len(names) > 1:
        raise SystemExit(
            f"REFUSED: {cache_path} mixes generations from {sorted(names)}. "
            f"A replayed run must be attributable to one system.")
    name = (names.pop() if names else "replay")
    generation_stamp = {
        key: value for key, value in next(iter(cache.values())).items()
        if key in REPLAY_GENERATION_FIELDS}
    if any({key: row[key] for key in REPLAY_GENERATION_FIELDS if key in row}
           != generation_stamp for row in cache.values()):
        raise SystemExit("REFUSED: replay cache mixes generation identity or budgets")
    visibility = next(iter(cache.values())).get("visibility")
    if any(row.get("visibility") != visibility for row in cache.values()):
        raise SystemExit("REFUSED: replay cache mixes or omits source-view identity")
    # Which R2T_RECORDED_ROOTS entry, if any, each row's view evidence was
    # read through; the replayed row records it beside `replay_source_path`.
    recorded_roots: dict[str, dict] = {}
    if visibility is not None:
        from ..core.source_view import verify_recorded_view, ViewRefused
        for item_id, row in cache.items():
            try:
                recorded_roots[item_id] = verify_recorded_view(row)
            except ViewRefused as exc:
                raise SystemExit(f"REFUSED: replay source-view evidence: {exc}") from exc

    def run(task: dict) -> dict:
        row = cache.get(task["item_id"])
        if row is None:
            # RAISE rather than return an empty result.  A miss means the cache
            # has nothing to SAY about this item; `{"files": []}` is a valid
            # answer meaning the system said nothing — a different claim, and
            # the wrong one to make on a system's behalf.  Hand-writing the
            # runner's `metadata.adapter_error` key alongside it does not undo
            # that: the result is still shaped like an answer, and every
            # consumer that reads `files` without also remembering to read that
            # one string key sees a system that produced nothing.
            #
            # Both callers (`runner.run_one`, `generate`) already wrap adapter
            # exceptions into exactly that key, so raising puts the
            # classification in the one place that owns it and leaves an
            # adapter unable to fabricate an answer it does not have.
            raise RuntimeError(
                f"replay cache {cache_path} has no row for {task['item_id']}")
        meta = dict(row.get("metadata") or {})
        meta["replayed_from"] = os.path.basename(cache_path)
        meta["replay_source_path"] = os.path.abspath(cache_path)
        meta["generation_seconds_original"] = row.get("generation_seconds")
        meta.pop("recorded_roots", None)  # describes this replay, not an earlier one
        if recorded_roots.get(task["item_id"]):
            meta["recorded_roots"] = recorded_roots[task["item_id"]]
        return {"files": row.get("produced_files") or [], "metadata": meta}

    config = {"replay": cache_path, "n_cached": len(cache)}
    if generation_stamp:
        config["generation_stamp"] = generation_stamp
    if visibility is not None:
        config["visibility"] = visibility
    return Adapter(name, run, config)


def make_submitted_adapter(candidates_path: str,
                           admitted_item_ids: Iterable[str]) -> Adapter:
    """Serve an external candidate file over its admitted full item set.

    Unlike a replay cache, absence is meaningful here: the candidate file is
    the submitter's declared coverage set, so an item with no row is an empty
    answer rather than missing harness evidence.  Validate the whole file up
    front so a late malformed row cannot leave a half-scored submission.
    """
    if not isinstance(candidates_path, str) or not candidates_path \
            or not os.path.isfile(candidates_path):
        raise SystemExit(
            "REFUSED: --adapter submitted requires --candidates to name a "
            f"nonempty regular JSONL file; got {candidates_path!r}")

    allowed = {"item_id", "produced_files", "adapter", "metadata"}
    required = {"item_id", "produced_files", "adapter"}
    admitted_ids = set(admitted_item_ids)
    rows: dict[str, dict] = {}
    submitter = None

    try:
        handle = open(candidates_path, encoding="utf-8")
    except OSError as exc:
        raise SystemExit(
            f"REFUSED: cannot read --candidates {candidates_path}: {exc}") \
            from exc
    with handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"REFUSED: --candidates {candidates_path} line "
                    f"{line_number} is not valid JSON: {exc.msg}") from exc
            if not isinstance(row, dict):
                raise SystemExit(
                    f"REFUSED: --candidates {candidates_path} line "
                    f"{line_number} is not a JSON object")

            keys = set(row)
            missing = sorted(required - keys)
            unknown = sorted(keys - allowed)
            if missing or unknown:
                details = []
                if missing:
                    details.append(f"missing keys {missing}")
                if unknown:
                    details.append(f"unknown keys {unknown}")
                raise SystemExit(
                    f"REFUSED: --candidates {candidates_path} line "
                    f"{line_number} has " + " and ".join(details))

            item_id = row["item_id"]
            if not isinstance(item_id, str) or not item_id:
                raise SystemExit(
                    f"REFUSED: --candidates {candidates_path} line "
                    f"{line_number} item_id must be a nonempty string")
            if item_id not in admitted_ids:
                raise SystemExit(
                    f"REFUSED: submitted item_id {item_id!r} on "
                    f"--candidates line {line_number} is not in the admitted "
                    "population")
            if item_id in rows:
                raise SystemExit(
                    f"REFUSED: --candidates {candidates_path} duplicates "
                    f"item_id {item_id!r} on line {line_number}")

            files = row["produced_files"]
            if not isinstance(files, list):
                raise SystemExit(
                    f"REFUSED: --candidates {candidates_path} line "
                    f"{line_number} produced_files must be a list")
            for file_number, produced in enumerate(files, 1):
                if not isinstance(produced, dict):
                    raise SystemExit(
                        f"REFUSED: --candidates {candidates_path} line "
                        f"{line_number} produced_files entry {file_number} "
                        "must be an object")
                file_keys = set(produced)
                if file_keys != {"file_path", "code"}:
                    missing_file = sorted(
                        {"file_path", "code"} - file_keys)
                    unknown_file = sorted(
                        file_keys - {"file_path", "code"})
                    details = []
                    if missing_file:
                        details.append(f"missing keys {missing_file}")
                    if unknown_file:
                        details.append(f"unknown keys {unknown_file}")
                    raise SystemExit(
                        f"REFUSED: --candidates {candidates_path} line "
                        f"{line_number} produced_files entry {file_number} "
                        "has " + " and ".join(details))
                if not all(isinstance(produced[key], str)
                           for key in ("file_path", "code")):
                    raise SystemExit(
                        f"REFUSED: --candidates {candidates_path} line "
                        f"{line_number} produced_files entry {file_number} "
                        "file_path and code must be strings")

            name = row["adapter"]
            if not isinstance(name, str) or not name.strip():
                raise SystemExit(
                    f"REFUSED: --candidates {candidates_path} line "
                    f"{line_number} adapter must be a nonempty string")
            if submitter is None:
                submitter = name
            elif name != submitter:
                raise SystemExit(
                    f"REFUSED: --candidates {candidates_path} line "
                    f"{line_number} names adapter {name!r}, but earlier rows "
                    f"name {submitter!r}")

            metadata = row.get("metadata", {})
            if not isinstance(metadata, dict):
                raise SystemExit(
                    f"REFUSED: --candidates {candidates_path} line "
                    f"{line_number} metadata must be an object")
            rows[item_id] = {"produced_files": files, "metadata": metadata}

    if not rows:
        raise SystemExit(
            f"REFUSED: --candidates {candidates_path} contains no candidate "
            "rows")

    def run(task: dict) -> dict:
        row = rows.get(task["item_id"])
        if row is None:
            return {"files": [], "metadata": {"submitted": False}}
        return {
            "files": row["produced_files"],
            "metadata": {
                "submitted": True,
                "submitted_metadata": row["metadata"],
            },
        }

    return Adapter(
        f"submitted:{submitter}", run,
        {"candidates": candidates_path, "n_submitted": len(rows)})


# --------------------------------------------------------------- builders
#
# Each of these is `runner.build_adapter`'s branch, unchanged.  The imports
# of `profile`, `stacks`, `release`, `generate` and the toolkit factories are
# function-local so this module has no r2t import beyond `constants` at
# module scope: the runner reads it before anything else is built.

def _build_replay(args, harness):
    # `_check_replay_labels` is deliberately NOT here: it compares the cache
    # against THIS RUN's labels, which is the runner's business, and it must
    # run after the adapter has been built (the adapter is what refuses a
    # cache that mixes generators).  See `runner.build_adapter`.
    return make_replay_adapter(args.replay)


def _build_submitted(args, harness):
    if getattr(args, "condition", None) is not None:
        raise SystemExit(
            "REFUSED: --adapter submitted fixes condition to 'submitted'; "
            "--condition cannot relabel external candidate bytes")
    admitted_item_ids = getattr(
        args, "_submitted_admitted_item_ids", None)
    if admitted_item_ids is None:
        raise SystemExit(
            "REFUSED: --adapter submitted requires its admitted population "
            "to be resolved before candidate bytes are read")
    adapter = make_submitted_adapter(
        getattr(args, "candidates", None), admitted_item_ids)
    args.condition = SUBMITTED_CONDITION
    return adapter


def _build_empty(args, harness):
    profile_path = getattr(args, "profile", None)
    if profile_path:
        from ..data.profile import load_profile
        if load_profile(profile_path).framework == "godog":
            from ..stacks import for_framework, verb
            stack = for_framework("godog")
            closures = os.path.join(os.path.abspath(args.artifacts), "closures.json")
            return verb(stack, "make_empty_adapter")(
                harness=harness, closures_path=closures)
    return make_empty_adapter()


def _build_gold(args, harness):
    release_dir = os.path.dirname(os.path.abspath(args.release))
    check = getattr(harness, "check_context", None)
    if check is not None:
        from .runner import _load_release
        return make_gold_adapter(release_dir, getattr(args, "gold", ""),
                                 context_check=check, items=_load_release(args.release))
    return make_gold_adapter(release_dir, getattr(args, "gold", ""))


def _stub_maker(args):
    """`make_stub_adapter` for the stack this run is against.

    Gold and replay preserve their supplied bytes. Go empty controls use
    their separate declaration-only preparation; the stub WRITES
    STEP DEFINITIONS, and a PHP context class installed into a behave
    workspace defines nothing at all — every step would come out `undefined`,
    the item would score zero, and the measured vacuous floor would read 0.00
    for a reason that has nothing to do with vacuity.  That is the one
    direction of error the ≤ 0.02 gate cannot survive, so the dispatch is
    here rather than left to whoever runs the sweep.

    Dispatched exactly as `cli._other_stack` dispatches the four
    language-bound verbs: no `--profile` means behat, which is every CoreShop
    invocation in every runbook and archived log, and those keep building the
    adapter they have always built.  A profile that IS passed is loaded whole
    — digests verified, boundary cross-checked — for `cli._stack`'s reason
    and not only for its `framework:` field: a profile whose prompts have
    moved under it is not a profile this benchmark may act on, whichever
    field is being read out of it.
    """
    path = getattr(args, "profile", None)
    if path:
        from ..data.profile import load_profile
        from ..stacks import for_framework, verb
        stack = for_framework(load_profile(path).framework)
        if stack.FRAMEWORK != "behat":
            return verb(stack, "make_stub_adapter"), stack.FRAMEWORK
    from ..toolkit.stub import make_stub_adapter
    return make_stub_adapter, "behat"


#: The stacks whose stub factory also needs the CORPUS, not only the
#: closures.  cucumber alone, and for a reason that is a property of its
#: closure producer rather than of the language: `closure_java.py` reads
#: cucumber's registry, which reports which method matched a step and never
#: what followed it, so whether a step carries a DocString or a DataTable —
#: which decides the arity of the method the stub must emit — is only in the
#: .feature bytes.  behat keys on the pattern and behave's closures carry
#: the shape already, so neither is handed a second argument and neither
#: builds a different adapter than it built before.
_STUB_NEEDS_CORPUS = frozenset({"cucumber"})


def _build_stub(args, harness):
    # The anti-vacuity floor (§3.10).  It reads `closures.json` because
    # only that says which steps a RETAINED context already defines, and
    # redefining one of those makes Behat's definition search ambiguous
    # rather than merely redundant (behave calls the same failure
    # `AmbiguousStep` and raises it at import).  That file is
    # coordinator-only, like gold's — the stub is a control, not a system
    # under test.
    maker, framework = _stub_maker(args)
    closures = os.path.join(
        os.path.abspath(getattr(args, "artifacts", ".")), "closures.json")
    if framework == "godog":
        return maker(closures, harness=harness, go_control_plans_root=
            getattr(args, 'go_control_plans_root', None) or os.path.join(
                os.path.dirname(closures), 'go-control-plans'))
    if framework == "behat" and harness is not None:
        from .repo import behat_project
        project = behat_project(harness.boundary)
        options = {}
        if harness.boundary.project == "sylius":
            from ..toolkit.stub import SYLIUS_ADAPTER_VERSION
            options["adapter_version"] = SYLIUS_ADAPTER_VERSION
        return maker(closures, namespace=project.stub_namespace,
                     dir_=project.stub_dir, **options)
    if framework not in _STUB_NEEDS_CORPUS:
        return maker(closures)
    # `harness.root` and not `args.repo`: the harness constructor is what
    # refuses a boundary and a manifest that name different workspaces, so
    # it is the one value in this process that has been checked to be the
    # workspace this run classifies against, writes into and executes in.
    return maker(closures, harness.root)


def _strip_maker(args):
    """The framework-specific assertion-stripped-gold adapter factory."""
    path = getattr(args, "profile", None)
    if path:
        from ..data.profile import load_profile
        from ..stacks import for_framework, verb
        stack = for_framework(load_profile(path).framework)
        if stack.FRAMEWORK != "behat":
            return verb(stack, "make_strip_adapter")
    from ..toolkit.strip import make_strip_adapter
    return make_strip_adapter


def _build_stripped_gold(args, harness):
    closures = os.path.join(
        os.path.abspath(getattr(args, "artifacts", ".")), "closures.json")
    policy = getattr(args, "assertion_selection_policy", None)
    profile_path = getattr(args, "profile", None)
    if profile_path:
        from ..data.profile import load_profile
        if load_profile(profile_path).framework == "godog":
            from ..go.assertion_strip import make_strip_adapter
            return make_strip_adapter(os.path.abspath(getattr(args, "gold", "")),
                closures, harness=harness, control_policy=policy,
                go_control_plans_root=getattr(args, 'go_control_plans_root', None)
                    or os.path.join(os.path.dirname(closures), 'go-control-plans'))
    if policy is not None:
        from ..data.profile import load_profile
        from .reference_workloads import make_reviewed_strip_adapter
        profile_path = getattr(args, "profile", None)
        profile = load_profile(profile_path) if profile_path else load_profile()
        return make_reviewed_strip_adapter(
            project=profile.project,
            gold_root=os.path.abspath(getattr(args, "gold", "")),
            closures_path=closures, control_policy=policy)
    maker = _strip_maker(args)
    gold = os.path.abspath(getattr(args, "gold", ""))
    return maker(gold, closures)


# ---------------------------------------------------------------- the menu
SPECS = (
    AdapterSpec(name="replay", version=1, kind="fixture", build=_build_replay),
    AdapterSpec(name="submitted", version=1, kind="fixture",
                build=_build_submitted),
    AdapterSpec(name="empty", version=1, kind="fixture", build=_build_empty),
    AdapterSpec(name="gold", version=1, kind="fixture", build=_build_gold),
    AdapterSpec(name="stub", version=1, kind="fixture", build=_build_stub),
    AdapterSpec(name="stripped-gold", version=1, kind="fixture",
                build=_build_stripped_gold),
)

#: `--adapter` name -> its spec, for the six fixtures.  The agent registry's
#: `known_names` lists these beside the agents, so an unknown name is still
#: refused with the whole menu; a checkout without that registry still
#: builds every one of these.
FIXTURES = {spec.name: spec for spec in SPECS}


def selftest() -> int:
    import sys
    import tempfile
    from types import SimpleNamespace

    from .runner import _PUBLICATION_ADAPTER_KINDS, build_adapter

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))

    def refuses(name, fn, *needles):
        try:
            fn()
        except SystemExit as e:
            miss = [x for x in needles if x not in str(e)]
            check(name, not miss, f"message lacks {miss}: {str(e)[:300]}")
        except Exception as e:                                # noqa: BLE001
            check(name, False, f"raised {type(e).__name__}: {e}")
        else:
            check(name, False, "did not refuse")

    def fake_args(**over):
        base_args = dict(adapter="gold", condition=None, model=None,
                         coverage=False, repeats=1, max_iterations=30,
                         max_reflections=3,
                         max_tokens=64000, temperature=0.0, trials=None,
                         artifacts=".", replay=None,
                         candidates=None,
                         llm_config=None, agent_timeout=3600,
                         trajectory_dir=None, agent_command=None,
                         release="release/release.jsonl")
        base_args.update(over)
        return SimpleNamespace(**base_args)

    check("the controls and the transports are fixtures, not systems under "
          "test, and the menu holds exactly them",
          all(s.kind == "fixture" and s.version == 1 for s in SPECS)
          and set(FIXTURES)
          == set(_PUBLICATION_ADAPTER_KINDS) | {"replay", "submitted"},
          str(sorted(FIXTURES)))
    try:
        AdapterSpec(name="gold", version=1, kind="fixture",
                    build=_build_gold, comparison_class="fixed_model_scaffold")
        classed = ""
    except ValueError as e:
        classed = str(e)
    check("a fixture may not declare a comparison class: a control is not "
          "a population a system's rows may be pooled with",
          "may not declare a comparison_class" in classed, classed)
    try:
        AdapterSpec(name="x", version=1, kind="control", build=_build_gold)
        kinded = ""
    except ValueError as e:
        kinded = str(e)
    check("a spec's kind is one of the three",
          "not one of" in kinded and "control" in kinded, kinded)

    # -- the runner resolves a fixture without the agent registry, and
    #    refuses an agent arm BY NAME when that registry is not shipped.
    blocked = {name: sys.modules.get(name)
               for name in ("r2t.agents", "r2t.agents.registry")}
    for name in blocked:
        sys.modules[name] = None
    try:
        with tempfile.TemporaryDirectory() as root:
            rel = os.path.join(root, "release.jsonl")
            with open(rel, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"item_id": "i0"}) + "\n")
            unshipped = build_adapter(
                fake_args(adapter="empty", release=rel), None)
            check("with the agent registry unimportable, a fixture still "
                  "builds through the runner's single entry point",
                  unshipped.name == "empty"
                  and unshipped.config.get("adapter_version") == 1)
            refuses("...and an agent arm is refused by name as not shipped, "
                    "with the fixtures on the message",
                    lambda: build_adapter(
                        fake_args(adapter="aider", release=rel), None),
                    "REFUSED", "agent arm 'aider' is not shipped in this "
                    "checkout", "gold", "stripped-gold", "replay",
                    "Nothing was built")
    finally:
        for name, module in blocked.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    # -- the fixtures build, and keep the names the runner stamps rows with.
    with tempfile.TemporaryDirectory() as root:
        rel = os.path.join(root, "release.jsonl")
        with open(rel, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i0"}) + "\n")
        empty = build_adapter(fake_args(adapter="empty", release=rel), None)
        check("the empty control builds and keeps its name",
              empty.name == "empty" and empty({"item_id": "x"})["files"] == [])
        refuses("the gold control refuses the whole run when its manifest is "
                "absent",
                lambda: build_adapter(
                    fake_args(adapter="gold", release=rel), None),
                "REFUSED:", "gold/manifest.json", "no item was run")
        os.makedirs(os.path.join(root, "gold"))
        with open(os.path.join(root, "gold", "manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({}, fh)
        gold = build_adapter(fake_args(adapter="gold", release=rel), None)
        check("the gold control builds against the release directory",
              gold.name == "gold" and gold.config["release"] == root,
              str(gold.config))
        check("a fixture carries its version too",
              gold.config.get("adapter_version") == 1)

        closures = os.path.join(root, "closures.json")
        with open(closures, "w", encoding="utf-8") as fh:
            json.dump([], fh)
        stub = build_adapter(fake_args(adapter="stub", release=rel,
                                       artifacts=root), None)
        check("the anti-vacuity floor builds from the coordinator's closures",
              stub.name == "stub" and stub.config["closures"] == closures)
        check("PHP stub's producer version overrides the cross-framework default",
              stub.config["adapter_version"] == 2)
        # Exercise the ordinary adapter through the real install boundary;
        # a correct stub body at another project's path is not a control.
        from ..core.boundary import load_boundary, REMOVABLE
        from .harness import Harness, Solution
        from ..toolkit.stub import stub_solution
        from pathlib import Path
        benchmark = Path(__file__).resolve().parents[2]
        item = {"item_id": "prestashop/fixture.feature:3",
                "scenario": "Scenario: fixture\n  Given a value exists"}
        closure = {"item_id": item["item_id"], "steps": []}
        with open(closures, "w", encoding="utf-8") as fh:
            json.dump([closure], fh)
        for project in ("prestashop", "coreshop", "sylius"):
            boundary = load_boundary(str(benchmark / "config" /
                f"boundary_{project}.yml"), repo_root=root)
            harness = object.__new__(Harness)
            harness.root, harness.boundary = root, boundary
            routed = build_adapter(fake_args(adapter="stub", release=rel,
                artifacts=root, profile=str(benchmark / "config" /
                    f"profile_{project}.yml")), harness)(item)
            written, rejected = harness.install_solution(Solution.from_json(routed))
            check(f"{project} ordinary stub uses its own removable namespace/path",
                  len(written) == 1 and not rejected
                  and boundary.classify(written[0]) == REMOVABLE
                  and (project != "prestashop" or
                       "namespace Tests\\Integration\\Behaviour\\Features\\Context\\Domain;"
                       in routed["files"][0]["code"]), str(rejected))
            if project == "sylius":
                check("Sylius ordinary stub selects the attribute producer",
                      "@Given" not in routed["files"][0]["code"]
                      and "namespace Sylius\\Behat\\Context\\Api;" in routed["files"][0]["code"])
            if project == "coreshop":
                check("CoreShop ordinary stub output preserves its existing defaults",
                      routed == stub_solution(item, closure))
            for path in written:
                os.unlink(os.path.join(root, path))
        stripped = build_adapter(fake_args(
            adapter="stripped-gold", release=rel, artifacts=root,
            gold=root), None)
        check("assertion-stripped gold builds from gold plus closures",
              stripped.name == "stripped-gold"
              and stripped.config.get("gold") == root
              and stripped.config.get("closures") == closures
              and stripped.config.get("adapter_version") == 1,
              str(stripped.config))

        candidates = os.path.join(root, "candidates.jsonl")
        with open(candidates, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "item_id": "i0", "adapter": "outside-system",
                "produced_files": [{"file_path": "tests/T.php",
                                    "code": "<?php"}],
                "metadata": {"driver_error": "submitter-owned note"},
            }) + "\n")
        submitted_args = fake_args(
            adapter="submitted", condition=None, release=rel,
            candidates=candidates,
            _submitted_admitted_item_ids=frozenset({"i0"}))
        submitted = build_adapter(submitted_args, None)
        hit = submitted({"item_id": "i0"})
        miss = submitted({"item_id": "i1"})
        check("the submitted fixture stamps its fixed tier and keeps external "
              "metadata nested",
              submitted.name == "submitted:outside-system"
              and submitted_args.condition == SUBMITTED_CONDITION
              and submitted.config.get("adapter_version") == 1
              and hit["metadata"] == {
                  "submitted": True,
                  "submitted_metadata": {
                      "driver_error": "submitter-owned note"},
              }
              and miss == {"files": [],
                           "metadata": {"submitted": False}},
              f"{submitted.name} {submitted.config} {hit} {miss}")
        refuses("a supplied condition cannot relabel submitted bytes",
                lambda: build_adapter(fake_args(
                    adapter="submitted", condition="c3", release=rel,
                    candidates=candidates), None),
                "REFUSED", "condition", "submitted")

        # -- replay adopts the name of whatever GENERATED the cache, which is
        #    what keeps a replayed row attributable to the system under test
        #    rather than to the transport.
        cache = os.path.join(root, "cache.jsonl")
        with open(cache, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i0", "adapter": "openhands",
                                 "condition": "c2", "produced_files": []})
                     + "\n")
        rp = build_adapter(fake_args(adapter="replay", release=rel,
                                     replay=cache, condition="c2"), None)
        check("replay wears the name of the system that generated the cache",
              rp.name == "openhands" and rp.config["replay"] == cache,
              str(rp.name))
        refuses("and the runner still refuses to relabel that cache",
                lambda: build_adapter(fake_args(adapter="replay", release=rel,
                                                replay=cache,
                                                condition="c3"), None),
                "REFUSED", "condition")
        refuses("a replay of a cache that does not exist is refused",
                lambda: build_adapter(fake_args(
                    adapter="replay", release=rel,
                    replay=os.path.join(root, "nope.jsonl")), None),
                "no generation cache")

        # The same rule for the second agent's caches, checked rather than
        # assumed: `replay` is a transport, and a re-executed aider generation
        # has to keep saying `aider` or the row would attribute aider's answer
        # to whatever the replay run's `--adapter` happened to be.
        a_cache = os.path.join(root, "aider_cache.jsonl")
        with open(a_cache, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i0", "adapter": "aider",
                                 "condition": "c2", "produced_files": []})
                     + "\n")
        a_rp = build_adapter(fake_args(adapter="replay", release=rel,
                                       replay=a_cache, condition="c2"), None)
        check("a replayed aider cache still wears aider's name",
              a_rp.name == "aider" and a_rp.config["replay"] == a_cache,
              str(a_rp.name))

    with tempfile.TemporaryDirectory() as bundle_root:
        release_dir = os.path.join(bundle_root, "artifacts", "release")
        bundled_gold = os.path.join(release_dir, "gold")
        removed_code = os.path.join(bundle_root, "removed-code")
        os.makedirs(bundled_gold)
        os.makedirs(os.path.join(removed_code, "src"))
        with open(os.path.join(release_dir, "items.jsonl"), "w",
                  encoding="utf-8") as fh:
            fh.write('{"item_id":"bundle-item"}\n')
        with open(os.path.join(bundled_gold, "manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"bundle-item": "answer.json"}, fh)
        with open(os.path.join(bundled_gold, "answer.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"item_id": "bundle-item", "files": ["src/A.php"]},
                      fh)
        with open(os.path.join(removed_code, "src", "A.php"), "w",
                  encoding="utf-8") as fh:
            fh.write("<?php final class A {}\n")
        answer = make_gold_adapter(release_dir, removed_code)(
            {"item_id": "bundle-item"})
        check("the gold adapter resolves answer sidecars beside a bundle's "
              "release items and reads code from the separate removed tree",
              answer == {"files": [{"file_path": "src/A.php",
                                     "code": "<?php final class A {}\n"}],
                         "metadata": {"source": "gold"}}, str(answer))
        missing = make_gold_adapter(release_dir, removed_code)(
            {"item_id": "not-in-manifest"})
        check("a present gold manifest still distinguishes one missing item",
              missing == {"files": [],
                          "metadata": {"error": "no gold for item"}},
              str(missing))

    with tempfile.TemporaryDirectory() as tmp:
        # Replay must never answer for an item it has no row for.  A miss used
        # to come back as `{"files": []}`, which is a legitimate answer meaning
        # the system said nothing — so replaying a cache built from a partial
        # sweep silently scored the missing items as failures of the system
        # whose name the replay adapter is wearing.
        cache_path = os.path.join(tmp, "gen_cache.jsonl")
        with open(cache_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(
                {"item_id": "p/f.feature:3", "adapter": "openhands",
                 "produced_files": [{"file_path": "a.php", "code": "<?php"}],
                 "metadata": {"condition": "c2"},
                 "generation_seconds": 1.0}) + "\n")
        rp = make_replay_adapter(cache_path)
        check("replay serves a cached row under the ORIGINAL system's name",
              rp.name == "openhands"
              and len(rp({"item_id": "p/f.feature:3"})["files"]) == 1)
        try:
            rp({"item_id": "p/f.feature:404"})
            missed = ""
        except RuntimeError as e:
            missed = str(e)
        check("a replay cache MISS is an error, not an empty answer",
              "no row for p/f.feature:404" in missed and cache_path in missed,
              missed)

        # H12 execution of a saved Codex answer must retain the actual
        # generation recipe, rather than the replay CLI's unused LLM defaults.
        from unittest.mock import patch
        from .runner import _record, _run_stamp
        original = {
            "item_id": "python-docx/fixture:1", "adapter": "codex:deepseek-v4-flash",
            "condition": "c2", "model": "deepseek-v4-flash", "temperature": None,
            "max_tokens": None, "max_iterations": None, "trials": 0,
            "sandboxed": True, "prompt_digest": "original-prompt",
            "agent_system": "codex", "adapter_version": "codex@1",
            "comparison_class": "fixed_model_scaffold", "agent_version": "0.153.4",
            "agent_command_mode": "builtin", "agent_runtime_sha256": "a" * 64,
            "protocol_version": 35, "protocol_digest": "original-protocol",
            "setting": "cold_start", "agent_timeout_seconds": 1200,
            "native_budget": {"max_model_calls": 200},
            "produced_files": [{"file_path": "tests/test_generated.py",
                                "code": "def test_generated(): assert True\n"}],
            "metadata": {"agent_stats": {"llm_calls": 3}},
            "generation_seconds": 12.5, "outcome": "failed", "coverage": False,
            "repeats": 1, "harness_commit": "original-harness",
            "harness_version": "original-version", "execution_timeout_seconds": 999,
            "worker_runtime": {"generation": "worker"}, "execution_seconds": 9,
        }
        modern_cache = os.path.join(tmp, "codex-source.jsonl")
        with open(modern_cache, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(original) + "\n")
            fh.write(json.dumps(dict(original, item_id="python-docx/fixture:2",
                                     outcome="passed")) + "\n")
        with open(modern_cache, "rb") as fh:
            original_bytes = fh.read()
        replay = make_replay_adapter(modern_cache)
        args = fake_args(adapter="replay", model=original["model"], condition="c2",
                         coverage=True, repeats=2, timeout=30)
        with patch("r2t.bench.runner._harness_commit", return_value="h12-harness"):
            replay_stamp = _run_stamp(args, replay)
        check("Codex replay retains every recorded generation setting including null sampling",
              {key: replay_stamp.get(key) for key in REPLAY_GENERATION_FIELDS
               if key in original} == replay.config["generation_stamp"])
        produced = replay({"item_id": original["item_id"]})
        fresh = _record(original["item_id"], {}, produced, 0.01,
                        {"runs": [{"outcome": "passed", "wall_seconds": 1.25, "exit_code": 0,
                                   "records": [], "stdout_tail": "H12 passed"}],
                         "written_files": ["tests/test_generated.py"]}, coverage=True)
        fresh.update(replay_stamp)
        check("replay records fresh H12 execution rather than copying source execution",
              fresh["harness_commit"] == "h12-harness"
              and fresh["harness_version"] != original["harness_version"]
              and fresh["coverage"] is True and fresh["repeats"] == 2
              and fresh["outcome"] == "passed" and fresh["execution_seconds"] == 1.25
              and "worker_runtime" not in replay_stamp
              and "execution_timeout_seconds" not in replay_stamp)
        check("replay preserves candidate bytes and links the original generation evidence",
              produced["files"] == original["produced_files"]
              and produced["metadata"]["agent_stats"] == original["metadata"]["agent_stats"]
              and produced["metadata"]["replayed_from"] == "codex-source.jsonl"
              and produced["metadata"]["replay_source_path"] == os.path.abspath(modern_cache)
              and produced["metadata"]["generation_seconds_original"] == 12.5)
        with open(modern_cache, "rb") as fh:
            check("replay leaves the archived source rows byte-identical",
                  fh.read() == original_bytes)
        for different in (dict(original, native_budget={"max_model_calls": 201}),
                          {key: value for key, value in original.items()
                           if key != "temperature"}):
            with open(modern_cache, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(original) + "\n")
                fh.write(json.dumps(dict(different, item_id="python-docx/fixture:2")) + "\n")
            refuses("replay refuses mixed generation allowances or missing-versus-null fields",
                    lambda: make_replay_adapter(modern_cache),
                    "REFUSED", "generation identity or budgets")
        legacy_stamp = _run_stamp(fake_args(adapter="replay"), rp)
        check("legacy replay keeps its prior fallback without inventing source identity",
              "generation_stamp" not in rp.config
              and "agent_system" not in legacy_stamp
              and "adapter_version" not in legacy_stamp
              and legacy_stamp["temperature"] == 0.0
              and legacy_stamp["max_tokens"] == 64000
              and legacy_stamp["sandboxed"] is False)

        # A submitted RUN file is shaped exactly like a generation cache, so
        # without this refusal `run --adapter replay --replay submitted.jsonl`
        # re-served the bytes minus their tier stamp.
        laundering_path = os.path.join(tmp, "submitted_run.jsonl")
        with open(laundering_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(
                {"item_id": "p/f.feature:3",
                 "adapter": "submitted:external-system",
                 "condition": "submitted",
                 "produced_files": [{"file_path": "tests/T.php",
                                     "code": "<?php"}]}) + "\n")
        try:
            make_replay_adapter(laundering_path)
            laundered = ""
        except SystemExit as e:
            laundered = str(e)
        check("replay refuses a submitted-tier cache and names the "
              "submitted route instead",
              "REFUSED" in laundered
              and "submitted-tier rows" in laundered
              and "p/f.feature:3" in laundered
              and "--adapter submitted" in laundered,
              laundered)

        def candidate_file(name, records) -> str:
            path = os.path.join(tmp, name + ".jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                if isinstance(records, str):
                    fh.write(records)
                else:
                    for record in records:
                        fh.write(json.dumps(record) + "\n")
            return path

        def candidate_refusal(path, release_ids=None) -> str:
            try:
                make_submitted_adapter(
                    path, release_ids or {"p/f.feature:3"})
            except SystemExit as exc:
                return str(exc)
            return ""

        submitted_path = candidate_file("submitted", [
            {
                "item_id": "p/f.feature:3", "adapter": "external-system",
                "produced_files": [{"file_path": "tests/T.php",
                                    "code": "<?php"}],
                "metadata": {
                    "driver_error": "external diagnostic",
                    "agent_stats": {"run_errors": ["external retry"]},
                },
            },
            {
                "item_id": "p/f.feature:4", "adapter": "external-system",
                "produced_files": [],
            },
        ])
        submitted = make_submitted_adapter(
            submitted_path,
            {"p/f.feature:3", "p/f.feature:4", "p/f.feature:5"})
        submitted_hit = submitted({"item_id": "p/f.feature:3"})
        submitted_default = submitted({"item_id": "p/f.feature:4"})
        submitted_miss = submitted({"item_id": "p/f.feature:5"})
        check("submitted candidates preserve hits, make absence an exact "
              "miss, and keep external error-shaped metadata nested",
              submitted.name == "submitted:external-system"
              and submitted.config == {
                  "candidates": submitted_path, "n_submitted": 2}
              and submitted_hit == {
                  "files": [{"file_path": "tests/T.php", "code": "<?php"}],
                  "metadata": {
                      "submitted": True,
                      "submitted_metadata": {
                          "driver_error": "external diagnostic",
                          "agent_stats": {
                              "run_errors": ["external retry"]},
                      },
                  },
              }
              and submitted_default == {
                  "files": [],
                  "metadata": {"submitted": True,
                               "submitted_metadata": {}},
              }
              and submitted_miss == {
                  "files": [], "metadata": {"submitted": False}},
              f"{submitted.name} {submitted_hit} {submitted_miss}")

        run_shaped = candidate_file("run-shaped", [{
            "item_id": "p/f.feature:3", "adapter": "external-system",
            "produced_files": [], "outcome": "passed",
        }])
        run_refusal = candidate_refusal(run_shaped)
        check("a run.jsonl-shaped extra key is refused by name and line",
              "REFUSED" in run_refusal and "unknown keys ['outcome']" in
              run_refusal and "line 1" in run_refusal, run_refusal)

        unknown_path = candidate_file("unknown-item", [{
            "item_id": "p/f.feature:404", "adapter": "external-system",
            "produced_files": [],
        }])
        unknown_refusal = candidate_refusal(unknown_path)
        check("a submitted item outside the admitted population is refused "
              "by name",
              "REFUSED" in unknown_refusal
              and "p/f.feature:404" in unknown_refusal
              and "not in the admitted population" in unknown_refusal,
              unknown_refusal)

        schema_cases = [
            ("empty", "\n", ("no candidate rows",)),
            ("non-object", "[]\n", ("line 1", "JSON object")),
            ("bad-json", "{\n", ("line 1", "valid JSON")),
            ("top-keys", [{
                "item_id": "p/f.feature:3", "adapter": "external-system",
                "outcome": "failed",
            }], ("missing keys ['produced_files']",
                 "unknown keys ['outcome']")),
            ("files-list", [{
                "item_id": "p/f.feature:3", "adapter": "external-system",
                "produced_files": {},
            }], ("produced_files must be a list",)),
            ("file-keys", [{
                "item_id": "p/f.feature:3", "adapter": "external-system",
                "produced_files": [{"file_path": "x", "content": "y"}],
            }], ("missing keys ['code']", "unknown keys ['content']")),
            ("file-types", [{
                "item_id": "p/f.feature:3", "adapter": "external-system",
                "produced_files": [{"file_path": "x", "code": 1}],
            }], ("file_path and code must be strings",)),
            ("metadata", [{
                "item_id": "p/f.feature:3", "adapter": "external-system",
                "produced_files": [], "metadata": [],
            }], ("metadata must be an object",)),
            ("blank-adapter", [{
                "item_id": "p/f.feature:3", "adapter": " ",
                "produced_files": [],
            }], ("adapter must be a nonempty string",)),
            ("duplicate", [
                {"item_id": "p/f.feature:3", "adapter": "external-system",
                 "produced_files": []},
                {"item_id": "p/f.feature:3", "adapter": "external-system",
                 "produced_files": []},
            ], ("duplicates item_id", "line 2")),
            ("mixed-adapter", [
                {"item_id": "p/f.feature:3", "adapter": "external-system",
                 "produced_files": []},
                {"item_id": "p/f.feature:4", "adapter": "another-system",
                 "produced_files": []},
            ], ("another-system", "earlier rows name 'external-system'")),
        ]
        schema_failures = []
        for label, records, needles in schema_cases:
            path = candidate_file("schema-" + label, records)
            message = candidate_refusal(
                path, {"p/f.feature:3", "p/f.feature:4"})
            missing = [needle for needle in needles if needle not in message]
            if missing or "REFUSED" not in message:
                schema_failures.append(
                    f"{label}: missing {missing}, message={message!r}")
        check("the submitted JSONL schema is closed and validated whole-file",
              not schema_failures, "; ".join(schema_failures))

    print("\n" + ("ALL PASS (fixtures)" if ok else "FAILURES (fixtures)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
