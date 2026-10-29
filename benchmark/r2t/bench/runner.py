"""S6 — run one adapter over the release and record raw outcomes.

v1 records outcomes, not metrics (SPEC §6): parse/compile status,
execution outcome, per-step results, wall time, and per-scenario
coverage.  Coverage is off by default because it costs 4.4x the runtime
(measured over a 100-item gold sweep: 19.1 s/item against 4.3 s without —
the "~8x" this file used to claim was never measured and was about double
the truth); `--coverage` turns it on, and it is worth turning on for any
sweep whose results might later be scored, because the behavioural metrics
are undefined without it and regenerating is far more expensive than
re-executing.

Two things exist here purely so that an evaluation can be RE-analysed
without being re-run — a sweep costs hours of container time and, for an
agent adapter, real money, so a metric that turns out to need one more
input must not force a second sweep.  `coverage_lines` keeps the
per-scenario coverage at line granularity rather than the per-file counts
a reader can no longer intersect with anything; `--keep-artifacts` writes
the solution, the full Behat log and the coverage to disk, keyed by the
same item-key the release uses for its gold records so the two join by
filename.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Optional

from ..core.gherkin import parse_feature_file
from .fixtures import FIXTURES
# Imported by NAME, not as the module: `harness` is the name of the Harness
# parameter half the functions in this file take.
from .harness import (SERVICES_FRAGMENT_NAME, Harness, Solution, fold_direct_calls,
                      fold_direct_calls_schema, fold_lines, fold_scenario_records)
from ..data.release import admit_pre_execution, task_view
from .repo import SubstrateTampered
from ..core.paths import BENCHMARK_ROOT, RELEASE_DIR


#: The root package (`r2t`), from `__package__` rather than `__name__` so
#: it is right when this module runs as `__main__` too.
_ROOT = __package__.rsplit(".", 1)[0]


def _agent_module(name: str):
    """One agent-owned module, by its name under `r2t`, or the refusal a
    checkout without the agent component gives.

    The seam between this file's benchmark half and the agent component.
    Wave O2 moved the agent-only half of the publication launcher to
    `agents/publication.py`, where its imports are plain; what stays here
    is the launcher the FIXTURE producers share with the agents
    (`run_publication_v3`, `construct_publication_run_plan`,
    `_RunShardLedger`, the lock, the receipts, the seal), which
    `bench/validate.py`, the merge, the ledger and the I2-I5 ledger
    self-tests run in the benchmark-only mirror.  Every agent branch of a
    shared function asks here -- for `agents.publication` itself, for the
    agent ledger's checkpoint and resume readers, for the Slice-3 cell
    check in `_check_campaign_flags` -- so a benchmark-only checkout
    refuses each of them by name instead of tracing back, and the import
    check's fact (b) sees no edge: `importlib` dispatch is outside it by
    definition, and the mirror's own check is the authority for what these
    sites reach.

    Only the NAMED module (or a package above it) being absent is "not
    shipped"; an import that fails inside a shipped module propagates as
    the bug it is.
    """
    import importlib
    dotted = f"{_ROOT}.{name}"
    try:
        return importlib.import_module(dotted)
    except ModuleNotFoundError as exc:
        if exc.name != dotted and not dotted.startswith(exc.name + "."):
            raise
        raise SystemExit(
            f"REFUSED: this step needs r2t.{name}, which is part of the agent "
            f"component this checkout does not ship (benchmark-only "
            f"distribution). No Docker, model, daemon, pool, or network "
            f"contact was made.") from exc


def _load_release(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _profile_for(args, harness: Harness):
    """The task profile this run's prompts are rendered from.

    Resolved from `--profile`, or from the boundary: `profile_<project>.yml`
    beside `--boundary`.  Loaded HERE rather than at module scope because
    only the adapters that talk to a model need one -- `gold`, `empty` and
    `stub` produce files without a prompt, and making them fail on a missing
    profile would turn the controls into the fragile part of the harness.

    The profile names its own boundary and is cross-checked against it at
    load, so the only thing left to verify is that it is the same PROJECT
    this run is scoring: a profile that describes another corpus would ask
    every model for the wrong artefact in the wrong language and record 422
    rows of the model failing.
    """
    from ..data.profile import load_profile, profile_path_for
    path = getattr(args, "profile", None) or profile_path_for(
        getattr(args, "boundary", None), harness.boundary.project)
    prof = load_profile(path)
    if prof.project != harness.boundary.project:
        raise SystemExit(
            f"REFUSED: profile {path} describes project {prof.project!r} but "
            f"this run is scored against boundary project "
            f"{harness.boundary.project!r}. The prompt and the harness would "
            f"be talking about two different repositories.")
    return prof


def build_adapter(args, harness: Harness):
    """This run's system under test, from the registry that lists them all.

    Still the single entry point — `cli.cmd_generate` and `run_adapter` both
    come through here — but the per-adapter construction lives in two
    tables, one `AdapterSpec` per name: `fixtures.FIXTURES` (bench) for the
    controls and the transports, consulted first, and `r2t.agents.registry`
    for the systems under test, consulted only when the name is not a
    fixture.  The consumer route therefore builds every fixture without the
    agent package, and a checkout that does not ship it refuses an agent arm
    by name instead of failing to import.  The tables are what make a SECOND
    agent a new row rather than a new branch in this function, and the
    branch they replaced is why that matters: everything a caller could know
    about an adapter had to be re-derived by reading the `if` that built it.

    What stays here is what belongs to the RUN rather than to the adapter: the
    replay label crosscheck (the cache's stamps against this run's flags),
    recording the spec's version on the built adapter so a row can say which
    revision of a named system produced it, and the confinement refusal —
    which is here BECAUSE this is the single entry point, and which was
    previously reachable only under `--campaign`.
    """
    name = args.adapter
    spec = FIXTURES.get(name)
    if spec is None:
        try:
            from ..agents.registry import get_spec
        except ImportError:
            raise SystemExit(
                f"REFUSED: agent arm {name!r} is not shipped in this "
                f"checkout (benchmark-only distribution); the fixtures are "
                f"{sorted(FIXTURES)}. Nothing was built, no container or "
                f"model contact was made.") from None
        # Refused before anything is constructed, and before `harness` is
        # touched: a typo must not spend a container, and it must not spend
        # a model call.
        spec = get_spec(name)
    # BEFORE `spec.build`, unlike the flag check this replaced.  That one ran
    # after, to keep a mistyped `--condition` being refused for being a
    # mistyped condition rather than for a missing flag; a host that has no
    # bubblewrap has no such ordering to preserve, because no flag can
    # contradict it and no adapter on this host can run whatever else the
    # command line says.  What refusing first therefore SAVES, stated exactly:
    # for an agent spec `spec.build` resolves the LLM config, loads the
    # profile, renders the command template and writes the agent seed
    # snapshot (a content-keyed copy of the readable tree under
    # `--artifacts/agent_seed`), and none of that is spent on a host that
    # cannot confine the launch.
    _require_agent_confinement(spec)
    adapter = spec.build(args, harness)
    # Additive, and on the CONFIG rather than on the stamp: the stamp's fields
    # are compared on resume, and adding one there would refuse every resume
    # into an existing run file (`_resume_set` compares a field whenever the
    # old row carries it).  Versioning the row is a separate change with its
    # own migration; versioning the object costs nothing and is already more
    # than the branch could say.
    config = getattr(adapter, "config", None)
    if isinstance(config, dict):
        config.setdefault("adapter_version", spec.version)
    if name == "replay":
        # After the adapter, because `make_replay_adapter` is what refuses a
        # cache that mixes generators, and that is the more basic complaint.
        _check_replay_labels(args, args.replay)
    return adapter


def _require_agent_confinement(spec) -> None:
    """An agent this harness runs is confined, so this host must be able to.

    WHAT THIS FUNCTION USED TO BE, AND WHY IT IS NOT THAT ANY MORE.  It was
    the `--sandbox-agent` check: `AdapterSpec.sandbox == "bwrap"` and no flag
    meant the agent would run as an ordinary host process beside the
    coordinator, which is how the wave5 algorand OpenHands cell was collected
    — all 362 preserved launches record a bubblewrap argv with every
    namespace unshared except the network, and three of its items fetched the
    upstream test file for the item they were being scored on.  That hole is
    closed, and closing it left the flag with exactly one valid setting:
    passing it was the only way to proceed and omitting it only chose an
    error message.  The flag is gone; `agents.registry` hands `sandbox=True`
    down for every agent spec unconditionally.

    WHAT IS LEFT IS THE HOST.  Confinement is now mandatory, so a host with
    no bubblewrap cannot run an agent at all, and that is a fact about the
    machine rather than about the command line — nothing the operator types
    can change it, and the thing they have to do instead is install a
    package.  Saying so here is worth a check because of WHEN it happens:
    `agents.sandbox.agent_sandbox_argv` already refuses (`NotConfined`), but
    it is reached from inside `run`, per item, after the workspace has been
    made and the repository copied into it.  This says it once, before the first
    item and before the seed snapshot, and names the package.

    `bwrap_available` and not `bwrap_probe`: the case this can state
    actionably is the executable being absent.  A bubblewrap that is present
    but cannot create a user namespace is what `bwrap_probe` measures by
    running `/bin/true` inside one, and `r2t doctor` reports it from there;
    repeating that here would spend two subprocesses on every single run to
    pre-empt a message bwrap itself gives.

    KEYED OFF THE SPEC, not off a list of adapter names: `AdapterSpec.sandbox`
    is the declaration `r2t.agents` already requires every agent to carry, so
    a third agent registered tomorrow is covered by the line that registers
    it rather than by somebody remembering this function exists.  A fixture
    transport declares no sandbox and is untouched — `gold` and `replay` read
    bytes off disk, launch nothing, and must not start demanding bubblewrap.

    Here rather than in `_run_stamp` because this is the single entry point
    every route comes through (`cli.cmd_generate` and `run_adapter` both).
    """
    if getattr(spec, "sandbox", None) != "bwrap":
        return
    from . import confine
    if confine.bwrap_available():
        return
    raise SystemExit(
        f"REFUSED: {spec.name!r} is an agent, an agent is launched confined "
        f"and nothing else, and bubblewrap is not installed on this host — "
        f"so there is no way to run it here. Install bubblewrap (Debian and "
        f"Ubuntu: `apt-get install bubblewrap`; Fedora and RHEL: `dnf "
        f"install bubblewrap`) and re-run; `r2t doctor` reports whether this "
        f"host can then create the namespace. No model call was made, no "
        f"container was started and no workspace was created.")


#: Row fields that say WHICH SYSTEM produced a cached generation.  A replay
#: re-serves those bytes, so the labels this run stamps them with have to be
#: the labels they were produced under.
_REPLAY_LABELS = ("condition", "model")


def _check_replay_labels(args, cache_path: str) -> None:
    """Refuse to relabel a generation cache as a different system.

    `make_replay_adapter` already refuses a cache that MIXES adapters, but
    nothing compared the cache's own stamps against this run's flags — so
    `--adapter replay --replay c2.jsonl --condition c3` produced a complete,
    internally consistent c3 run file out of c2 generations, and the only
    trace was `replayed_from` in the metadata. That is the cheapest possible
    way to manufacture a condition effect, and it is reachable by a typo.

    One pass over the file, at build time: this reads the same bytes the
    adapter just read rather than re-checking per item, and a refusal here
    costs nothing because no item has run yet.
    """
    want = {k: getattr(args, k, None) for k in _REPLAY_LABELS}
    want = {k: v for k, v in want.items() if v}
    if not want or not cache_path or not os.path.isfile(cache_path):
        return
    seen: dict[str, set] = {k: set() for k in want}
    with open(cache_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                # Not this function's finding: `load_cache` has already read
                # the same file, and refusing a run over a stray line here
                # would report the wrong fault.
                continue
            if not isinstance(row, dict):
                continue
            for k in want:
                # Scalars only, and never sorted across types: this is a guard,
                # and a guard that can raise on a weird cache row is one more
                # way to lose a shard.
                if isinstance(row.get(k), (str, int, float, bool)):
                    seen[k].add(row[k])
    # A cache row that carries no such field is not a conflict — generations
    # predating run stamping are unverifiable, not wrong.
    problems = [f"the cache was generated with {k}={sorted(v, key=repr)} but "
                f"this run labels its rows {k}={want[k]!r}"
                for k, v in seen.items() if v - {want[k]}]
    if problems:
        raise SystemExit(
            f"REFUSED: {cache_path} was not produced under the configuration "
            f"this run would stamp it with:\n  - " + "\n  - ".join(problems)
            + "\nReplay is a transport, not a relabelling: run with the "
              "labels the cache was generated under, or generate again.")


#: Outcomes that describe the harness or the transport failing rather than the
#: system under test producing a result.  Only these are retryable: re-running
#: an item because its result was disappointing is result-shopping.
#:
#: `harness_error` is in here for the same reason as `timeout`: it is an
#: exception in OUR code (see `_harness_error_row`), not an answer the system
#: gave, so re-running it is repairing the run rather than shopping for a
#: result.
_RETRYABLE_OUTCOMES = {"timeout", "scenario_not_found", "harness_error"}


def _harness_error_row(item_id: str, exc: BaseException) -> dict:
    """One item's crash, written down instead of ending the sweep.

    The traceback is kept — truncated to a tail, like `stdout_tail`, because
    this goes into a per-item row of a JSONL — because the whole value of
    turning a crash into a row is being able to fix the cause afterwards, and
    a bare exception message rarely says where it came from.  The stamp is
    applied by the caller, so the row carries the same provenance every other
    row does and the merge can bind it to the campaign.

    An exception that says the worker itself is unusable (`stops_worker`,
    PrestaShop's `SeededSchemaFault`) is repeated as `metadata.worker_stop`,
    which the cell launcher reads to stop that worker at once.
    """
    import traceback
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    metadata = {"harness_error": f"{type(exc).__name__}: {exc}",
                "traceback_tail": tb[-1500:]}
    if getattr(exc, "stops_worker", False):
        metadata["worker_stop"] = metadata["harness_error"]
    return {"item_id": item_id, "outcome": "harness_error", "metadata": metadata}


def _trials_of(args):
    """This run's trial budget in the WIRE vocabulary: 0, a count, or
    `"unlimited"`.

    One function, used by `build_adapter`, by the stamp and by the campaign
    crosscheck, because those values are compared with each other at merge
    time: normalising in three places is how one of them ends up writing
    `"unlimited"` while another writes `-1`, and the merge then refuses a
    campaign that was correct.

    `ValueError` becomes a refusal here rather than in
    `constants.parse_trials`, which is also argparse's `type=` and has to
    raise what argparse catches.  Everything on THIS path is a run about to
    be launched, where an unparseable flag must read like every other
    pre-flight refusal instead of like a traceback.
    """
    from ..core.constants import parse_trials
    try:
        return parse_trials(getattr(args, "trials", 0))
    except ValueError as e:
        raise SystemExit(f"REFUSED: {e}")


#: Stamp fields introduced AFTER runs were already on disk.
#:
#: THE PROBLEM THIS SOLVES.  `_run_stamp` is additive-only — a new field is
#: written by new runs and simply absent from old rows — and OUTSIDE a
#: campaign that is already handled: `_resume_set` compares a field only when
#: the old row HAS it, so an absent field is unverifiable rather than wrong.
#: Inside a campaign the rule is deliberately stricter: an absent field IS a
#: mismatch, because resuming an unstamped row would relabel an older,
#: differently-configured result as part of this campaign.
#:
#: That strictness is right for the fields that existed when the campaign
#: started and wrong for the ones that did not. Without this tuple, the day
#: `protocol_digest` was added every in-flight campaign would have refused to
#: resume — hours into a paid sweep, over a field the old rows could not
#: possibly have carried.
#:
#: SO THE RULE IS EXACTLY ONE-SIDED.  For a field named here:
#:
#:   * ABSENT in the old row -> grandfathered. Unverifiable, not wrong: the
#:     row predates the field, and nothing about it contradicts this run.
#:   * PRESENT and DIFFERENT -> still refused, exactly as before. A row that
#:     recorded `protocol_digest: abc` is not a row from a `def` protocol,
#:     and the leniency above must never grow into that.
#:
#: A field is added here ONCE, when it is introduced, and never removed: the
#: rows it grandfathers are permanent.
STAMP_OPTIONAL_FIELDS: tuple[str, ...] = (
    # WS1 (2026-08-02) — the protocol artifact and the citable identity.
    "dataset_version",
    "protocol_version",
    "protocol_digest",
    "protocol_deviations",
    "setting",
    "agent_timeout_seconds",
    "subset_id",
    "subset_digest",
    "adapter_version",
    "agent_system",
    "comparison_class",
    "harness_commit",
    "agent_version",
    # Slice 1 (2026-08-02) — the second scaffold's budget.
    "native_budget",
    # Reproducible v1 — publication runtime and custom-command disclosure.
    "agent_runtime_sha256",
    "agent_command_mode",
)


def _harness_commit() -> Optional[str]:
    """This checkout's short commit, or None — never a guess.

    `harness_version` says which SEMANTIC version of the executor produced a
    row; this says which BYTES did. They are different questions: a
    verdict-preserving refactor leaves the version alone and moves the commit,
    and when two archived sweeps disagree the commit is what makes the
    difference findable.

    Absent rather than `"unknown"` on any failure — no git, no repository, a
    tarball export — because `STAMP_OPTIONAL_FIELDS` gives an absent field a
    meaning ("this row predates the question") and a sentinel string would
    compare equal across two genuinely different checkouts.
    """
    try:
        import subprocess
        cp = subprocess.run(
            ["git", "-C", os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
             "rev-parse", "--short=7", "HEAD"],
            capture_output=True, text=True, timeout=10)
        out = (cp.stdout or "").strip()
        return out if cp.returncode == 0 and out else None
    except Exception:                                       # noqa: BLE001
        return None


def _spec_of(args):
    """This run's adapter spec, or None — never a raise, never a fixture.

    Fixture transports (gold, stripped-gold, empty, stub, replay) return None
    on purpose: a replayed row's `adapter` field keeps the GENERATOR's name so
    the row stays attributable to the system under test, and calling the
    transport a system would make two fields on one row answer "which system"
    differently.
    """
    name = getattr(args, "adapter", None)
    if not name or name in FIXTURES:
        return None
    try:
        from ..agents import registry as _reg
        return _reg.get_spec(name)
    # `get_spec` refuses unknown names by SystemExit, which `except Exception`
    # cannot catch; this helper's contract is best-effort-and-omit, and the
    # authoritative unknown-adapter refusal is `build_adapter`'s.
    except (Exception, SystemExit):                         # noqa: BLE001
        return None


def agent_system_of(args) -> Optional[str]:
    """WHICH SYSTEM this invocation is about, as the registry spells it.

    One resolver, three callers that must agree: the row stamp
    (`_identity_fields`), the campaign crosscheck (`_check_campaign_flags`)
    and the protocol's native-knob vocabulary (`cli._apply_protocol`). A
    second spelling anywhere would let a row, a campaign and a budget disagree
    about which system produced them, which is the whole failure this field
    exists to stop.

    THE REGISTRY WINS. `--agent-system` exists only on `r2t campaign`, which
    has no `--adapter` (a campaign names no system, its shards do); a run
    derives the name from the adapter it is actually about to build, so no
    flag can relabel a row. The declaration is read here only for the campaign
    case, and the two are compared where a campaign and a run meet
    (`_check_campaign_flags`).

    None when there is nothing to say: a fixture transport, an adapter the
    registry cannot resolve, or a subcommand with neither. Best-effort like
    the rest of the identity half — a run must not die because the registry
    could not be imported; it must leave the field absent, which reads as `?`.
    """
    spec = _spec_of(args)
    if spec is not None:
        return spec.name
    declared = getattr(args, "agent_system", None)
    return declared if declared else None


def _identity_fields(args) -> dict:
    """The WS1 identity half of the stamp: what this row can be CITED as.

    Everything here is best-effort and omitted on failure. A run must not die
    because the dataset manifest is missing or git is unavailable; it must run
    and leave the field absent, which the citation renders as `?`.
    """
    out: dict = {}
    try:
        from ..data.versions import component
        version = component("dataset").get("version")
        if version:
            out["dataset_version"] = str(version)
    except Exception:                                       # noqa: BLE001
        pass
    # WHICH ITEMS. Only when the file carries a provenance sidecar that still
    # matches its bytes — see `subsets.identify`. An ad-hoc slice has no
    # subset identity, and inventing one from the basename would put a
    # citable-looking label on rows measured over something else.
    try:
        from ..data.subsets import identify
        found = identify(getattr(args, "release", None) or "")
        if found:
            out["subset_id"] = found["subset_id"]
            out["subset_digest"] = found["subset_digest"]
    except Exception:                                       # noqa: BLE001
        pass
    # WHICH SYSTEM. `adapter` (already stamped) is the BUILT adapter's name
    # and carries the model (`openhands:deepseek`); these are the registry's
    # answer: the system, our configuration of it, and the population its rows
    # may be pooled with.
    #
    # `agent_version` is the older best-effort label for an ad-hoc run.  A
    # campaign instead carries `agent_runtime_sha256`, derived once from the
    # selected interpreter's exact locked environment before any paid item.
    try:
        from ..agents import registry as _reg
        # Fixture transports carry no system identity of their own: a replayed
        # row's `adapter` field keeps the GENERATOR's name on purpose (the row
        # stays attributable to the system under test, not to the transport),
        # and stamping agent_system="replay" beside it would make the two
        # fields on one row answer "which system" differently. `_spec_of`
        # holds that rule, and `agent_system_of` is built on the same helper,
        # so a row and a campaign crosscheck cannot disagree about it.
        spec = _spec_of(args)
        if spec is not None:
            out["agent_system"] = spec.name
            out["adapter_version"] = spec.qualified
            if spec.comparison_class:
                out["comparison_class"] = spec.comparison_class
            # A campaign probes its selected interpreter once, before any
            # paid item, and every row below carries that validated runtime's
            # digest.  Keep the older best-effort version label for ad-hoc
            # runs only; probing it again in every campaign shard would make
            # the immutable campaign identity cease to be the authority.
            if not getattr(args, "campaign", None):
                probed = _reg.agent_version(spec, args)
                if probed:
                    out["agent_version"] = probed
    # This block's contract is best-effort-and-omit, and the authoritative
    # unknown-adapter refusal is build_adapter's.
    except (Exception, SystemExit):                         # noqa: BLE001
        pass
    commit = _harness_commit()
    if commit:
        out["harness_commit"] = commit
    # WHICH RECIPE. Present only under `--protocol`: a run launched without
    # one did not follow a protocol, and a null here would read as "protocol
    # unset" where absence reads as "the question was not asked".
    for key in ("protocol_version", "protocol_digest"):
        value = getattr(args, key, None)
        if value is not None:
            out[key] = value
    # WHAT THE SYSTEM WAS GIVEN AT THE START -- `setting: cold_start`.
    #
    # Both protocol files say the setting is stamped on every row (v2's header,
    # v1's note that "nothing in a run row records it, which is why it is
    # written here and why v2 stamps it"), and until this it was not: the claim
    # lived only in a file a reader had to open, so a table could pool a
    # cold-start arm with a warm-context one and nothing in the rows would
    # disagree.  It comes from the protocol DOCUMENT rather than from a flag
    # because it is a claim about the task, not a knob -- there is nothing to
    # pass.
    #
    # Guarded by the digest: the row already asserts WHICH recipe it followed,
    # and a `setting` read out of some other document would be a second, softer
    # answer to the same question.  If the file on disk no longer digests to
    # what `_apply_protocol` computed, nothing is stamped -- absent, which
    # reads as `?`, rather than a claim from a recipe this run did not follow.
    if out.get("protocol_version") is not None:
        try:
            from ..agents import protocol as P
            doc = P.load(out["protocol_version"])
            if P.protocol_digest(doc) == out.get("protocol_digest"):
                out["setting"] = doc["setting"]
        except Exception:                                   # noqa: BLE001
            pass
        # THE PRIMARY BUDGET, as enforced.  protocol_v1 records that no
        # archived row carries the wall-clock envelope ("the one knob below
        # that cannot be re-derived from the artifacts. Protocol v2 stamps
        # it.") -- this is the stamp that makes that sentence true.  From
        # `args`, not the document: after `apply_defaults` the flag IS the
        # protocol's value unless the operator deviated, and a deviation is
        # refused under a campaign and recorded verbatim otherwise -- so what
        # belongs on the row is the envelope the run actually ran under.
        timeout = getattr(args, "agent_timeout", None)
        if timeout is not None:
            out["agent_timeout_seconds"] = int(timeout)
    # THE NATIVE BUDGET IN FORCE -- `{knob: value}` for the system that ran.
    #
    # `agent_timeout_seconds` is the only budget the protocol claims equal
    # across systems; `max_iterations` and `max_reflections` are native knobs
    # that mean different units of work, and a table holding both is unreadable
    # unless each row says which allowance it had. So this is the field a
    # cross-system reader looks at, and it must not be the field that is
    # missing on exactly the rows where it matters.
    #
    # STAMPED WITHOUT A PROTOCOL, unlike `setting` and the wall-clock envelope
    # above. Those are CLAIMS a recipe makes, so a run that followed no recipe
    # makes none. A native budget is not a claim: it is what the system was
    # actually run with, the same kind of fact as `max_iterations` in the base
    # stamp (which every row has always carried, protocol or not). An ad-hoc
    # aider probe at 1 reflection that stamped nothing here would be
    # indistinguishable from the protocol's 10.
    #
    # OMITTED when empty rather than stamped as `{}`: a system with no native
    # knobs, and a subcommand that carries none of them, both mean "the
    # question does not arise here", and absence is how this stamp says that.
    try:
        from ..agents import protocol as P
        budget = P.native_budget(args, out.get("agent_system"))
        if budget:
            out["native_budget"] = budget
    except Exception:                                       # noqa: BLE001
        pass
    devs = getattr(args, "protocol_deviations", None)
    if devs:
        # Verbatim, and only when non-empty. An ad-hoc probe is allowed to
        # deviate from its protocol; a row that deviated silently is not.
        out["protocol_deviations"] = list(devs)
    return out


def _run_stamp(args, adapter) -> dict:
    """What a row must carry to be attributable to a run configuration.

    Four run files already exist over the same 25 items with no record of the
    condition, cap, model or harness version that produced them, and the
    resume logic keys on `item_id` alone — so appending to an out file after
    changing any of that silently produces a set that is neither run.
    """
    from .validate import HARNESS_VERSION
    stamp = {
        "adapter": adapter.name,
        "condition": getattr(args, "condition", None),
        "model": getattr(args, "model", None),
        "coverage": bool(getattr(args, "coverage", False)),
        "repeats": getattr(args, "repeats", 1),
        "max_iterations": getattr(args, "max_iterations", None),
        "max_tokens": getattr(args, "max_tokens", None),
        "temperature": getattr(args, "temperature", None),
        # The two things that decide what the C3 arm actually IS, and neither
        # was recorded.  A shard relaunched after a crash without `--trials 5`
        # is a C2 run wearing C3's condition label, and a shard relaunched
        # under different confinement is a different experiment; both
        # produced rows indistinguishable from the first half's, so
        # `_resume_set` happily resumed into the other configuration and the
        # merged file was neither run.
        #
        # `parse_trials` rather than `int`, and the row therefore carries
        # `"unlimited"` for an unbounded run — a THIRD value, distinct from 0
        # (no channel) and from every count.  It has to be: the campaign
        # crosscheck compares this field with `trial_budget` by equality, and
        # a null or a 0 here would let an unbounded shard merge into a control
        # campaign or a counted one.
        "trials": _trials_of(args),
        # FROM THE ADAPTER, not from a flag, for the same reason
        # `prompt_digest` and `agent_command_mode` below are: the row should
        # say what the thing that ran was built as.  There is no longer a
        # flag to read anyway — `agents.registry` builds every agent spec
        # with `sandbox=True` and `make_agent_adapter` records that under
        # this key, while a fixture transport carries no such key and reads
        # False.  Those are exactly the two values the flag could produce on
        # a run that was allowed to start, so no existing row's value moves
        # and `_resume_set` has nothing new to compare.
        "sandboxed": bool((getattr(adapter, "config", None)
                           or {}).get("sandboxed")),
        # WHICH PROMPT this row was generated with.
        #
        # The prompt is an input, and until it became profile-driven the only
        # thing making rows comparable across runs was that the string was
        # hard-coded in a module nobody edited.  It is now a file that a
        # second project's operator is expected to copy and change, so the
        # run file has to carry the identity of the one that was used --
        # otherwise a merged set could hold rows generated from two different
        # prompts under one condition label, and nothing in it would look
        # wrong.  Taken from the adapter, which hashes the prompt it actually
        # renders; None for `gold`, `stripped-gold`, `empty`, `stub` and
        # `replay`, which produce files without a prompt.
        "prompt_digest": (getattr(adapter, "config", None)
                          or {}).get("prompt_digest"),
        "harness_version": HARNESS_VERSION,
    }
    # A submitted row makes no execution-channel claim.  `trials: 0` reads
    # "generated with no execution feedback", which is exactly what the
    # amendment says this pipeline cannot assert about bytes produced outside
    # it -- the producer may have had none, C3's channel, or an unbounded
    # private loop.  Absent, not 0: absence reads as "the question was not
    # asked", the same way the identity fields degrade.  No stamp-equality
    # path depends on the key being present -- submitted runs never resume
    # (`_refuse_submitted_output_path`) and never enter a campaign.
    if getattr(args, "adapter", None) == "submitted":
        del stamp["trials"]
    command_mode = (getattr(adapter, "config", None)
                    or {}).get("agent_command_mode")
    if command_mode:
        stamp["agent_command_mode"] = command_mode
    # The identity half (WS1): dataset, subset, system, harness bytes,
    # protocol. Every one of them is in STAMP_OPTIONAL_FIELDS, and every one
    # of them is OMITTED rather than nulled when it cannot be established.
    stamp.update(_identity_fields(args))
    spec = _spec_of(args)
    if spec is not None and spec.kind == "agent":
        # The generic CLI's completion cap belongs to single-shot adapters.
        # Match publication rows: native agents do not receive that cap, and
        # only the agent whose native knob is max_iterations owns that field.
        stamp["max_tokens"] = None
        stamp["max_iterations"] = stamp.get("native_budget", {}).get(
            "max_iterations")
    source_tag = getattr(args, "reference_source_tag", None)
    if source_tag is not None:
        from .mutation_run import sha256_file
        if adapter.name not in {"gold", "stripped-gold", "stub"}:
            raise SystemExit("REFUSED: reference derivation stamps require a benchmark control adapter")
        if not isinstance(source_tag, str) or not source_tag \
                or any(character.isspace() for character in source_tag):
            raise SystemExit("REFUSED: reference source tag must be one nonempty space-free tag")
        config = getattr(adapter, "config", None) or {}
        version = config.get("adapter_version")
        if type(version) is not int or version < 1:
            raise SystemExit("REFUSED: the built reference adapter has no actual version")
        control_policy = config.get("control_policy")
        if control_policy != getattr(args, "assertion_selection_policy", None):
            raise SystemExit("REFUSED: built control policy differs from the requested selection")
        # The unmutated gold run can precede the coverage-derived map. Record
        # its actual execution recipe here; collection adds the authenticated
        # asset index to the approved five-field mutation-workload preimage.
        stamp["reference_derivation"] = {
            "adapter": adapter.name, "adapter_version": version,
            "release_sha256": sha256_file(args.release),
            "control_policy": control_policy}
        stamp["reference_source_tag"] = source_tag
    visibility = (getattr(adapter, "config", None) or {}).get("visibility")
    if visibility is not None:
        stamp["visibility"] = visibility
    # Replay does no generation. Its generic CLI defaults cannot replace the
    # source agent's model, prompt, native budget or confinement claim. The
    # replay adapter has already required one homogeneous source stamp; only
    # recorded generation fields are overlaid, leaving fresh execution fields
    # (coverage, repeats and harness identity) here.
    replay_config = getattr(adapter, "config", None) or {}
    if replay_config.get("replay"):
        stamp.update(replay_config.get("generation_stamp") or {})
    # A labelled post-hoc sensitivity re-execution: its rows must never be
    # read as the primary observation (metrics.read_runs refuses mixed files).
    if getattr(args, "sensitivity", None) is not None:
        stamp["sensitivity"] = args.sensitivity
    # The campaign digest goes on the ROW, not only on the worker manifest.
    #
    # The manifest is written after the run and merely asserts which campaign
    # the rows belong to. A review reproduced the consequence: a row containing
    # nothing but `item_id` and `outcome` merged cleanly under a campaign with
    # a different model, image, seed, database, coverage flag and trial budget.
    # `_resume_set` compares a stamp field only when the field is PRESENT in
    # the old row, so an unstamped row is compatible with everything.
    campaign = getattr(args, "campaign", None)
    if campaign:
        from .campaign import campaign_digest
        doc = getattr(args, "_validated_campaign_document", None)
        if doc is None:
            with open(campaign, encoding="utf-8") as fh:
                doc = json.load(fh)
        elif getattr(args, "_validated_campaign_path", None) \
                != os.path.abspath(campaign):
            raise SystemExit(
                "REFUSED: validated campaign snapshot belongs to another path")
        # BEFORE the digest is taken, and long before an item runs: the
        # refusal is the whole point (see `_check_campaign_flags`).
        _check_campaign_flags(args, doc, campaign, adapter)
        if doc.get("agent_runtime_sha256") is not None:
            stamp["agent_runtime_sha256"] = doc["agent_runtime_sha256"]
        computed_digest = campaign_digest(doc)
        pinned_digest = getattr(args, "_validated_campaign_digest", None)
        if pinned_digest is not None and pinned_digest != computed_digest:
            raise SystemExit("REFUSED: validated campaign snapshot digest drifted")
        stamp["campaign_digest"] = pinned_digest or computed_digest
        stamp["shard"] = getattr(args, "shard", None)
        stamp["of"] = getattr(args, "of", None)
    return stamp


def _check_campaign_flags(args, campaign: dict, path: str, adapter) -> None:
    """Refuse a launch whose flags contradict the campaign it stamps rows with.

    The campaign fingerprint records the trial budget, the coverage flag, the
    model and K — and until now nothing compared them with the flags of the
    process that was about to stamp rows with that digest.  So a shard
    relaunched as `--campaign c3.json` but without `--trials 5` (or with the
    wrong `--of`) produced rows carrying a digest that asserts a configuration
    the run did not have, and the merge — which verifies that all shards agree
    on ONE digest — passed them, because they all agreed on the same lie.

    Refusing here rather than at merge time is the point: an agent sweep
    spends real money per item, and the merge only runs hours later, after
    every one of them has been paid for.
    """
    # Every comparison is guarded by a type check rather than a cast: this
    # runs BEFORE `campaign_digest` validates the fingerprint's shape, and a
    # malformed campaign file must reach that validation and its message
    # instead of dying here on a `ValueError` from `int("five")`.
    def _int(v):
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    def _budget(v):
        """A comparable trial budget: a count, or the unbounded sentinel.

        Same guard as `_int` and the same reason — a campaign whose
        `trial_budget` is neither must reach `campaign_digest`'s validation
        and its message rather than being reported here as a flag mismatch.
        The sentinel is a STRING, so it survives the JSON round-trip through
        the campaign file and compares equal to the value `_trials_of` puts on
        every row.
        """
        from ..core.constants import UNBOUNDED
        return v if v == UNBOUNDED else _int(v)

    problems = []
    trials = _trials_of(args)
    budget = _budget(campaign.get("trial_budget"))
    if budget is not None and budget != trials:
        problems.append(f"campaign trial_budget={budget}, but this run has "
                        f"--trials {trials}")
    coverage = bool(getattr(args, "coverage", False))
    if campaign.get("coverage") is not None \
            and bool(campaign["coverage"]) != coverage:
        problems.append(f"campaign coverage={bool(campaign['coverage'])}, but "
                        f"this run has coverage={coverage}")
    condition = campaign.get("condition")
    if "condition" in campaign \
            and condition != getattr(args, "condition", None):
        problems.append(f"campaign condition={condition!r}, but this run has "
                        f"--condition {getattr(args, 'condition', None)!r}")
    # A campaign that records no model (an agent whose model lives in the LLM
    # config, say) constrains nothing; one that names a model constrains
    # everything, because the model IS the system under test.
    model = campaign.get("model")
    if model is not None and model != getattr(args, "model", None):
        problems.append(f"campaign model={model!r}, but this run has --model "
                        f"{getattr(args, 'model', None)!r}")
    of = _int(getattr(args, "of", None))
    k = _int(campaign.get("k_workers"))
    if of and k is not None and k != of:
        problems.append(f"campaign k_workers={k}, but this run has --of {of}")
    from .campaign import POSITIONAL_SHARD_RULE, SHARD_RULE
    slice3_context = getattr(args, "_slice3_cell_context", None)
    expected_shard_rule = (POSITIONAL_SHARD_RULE
                           if slice3_context is not None else SHARD_RULE)
    if slice3_context is not None:
        validate_cell_capability = _agent_module("agents.slice3_eval").validate_cell_capability
        try:
            validate_cell_capability(
                slice3_context, expected_mode="run_shard")
        except ValueError as exc:
            problems.append(str(exc))
    if campaign.get("shard_rule") != expected_shard_rule:
        problems.append(
            f"campaign shard_rule={campaign.get('shard_rule')!r}, but this "
            f"invocation requires {expected_shard_rule!r}")
    # THE RECIPE.  A campaign that declares a protocol has bound it into its
    # digest; every row it stamps therefore asserts that recipe, and until this
    # check nothing made the run FOLLOW it — a shard launched without
    # `--protocol` produced rows asserting v2 while running the harness
    # defaults, and the merge could not see it because all shards asserted it
    # equally.  `cli._apply_protocol` is the only thing that puts this pair on
    # `args`, so "no --protocol" arrives here as a pair of Nones and is caught.
    #
    # Key presence distinguishes history from a current explicit null.  An
    # archived campaign written before the protocol pair existed constrains
    # nothing; a current campaign carrying both keys as null asserts that it
    # ran under no protocol and must refuse a protocol-stamped shard.
    for key in ("protocol_version", "protocol_digest"):
        if key not in campaign:
            continue
        want = campaign.get(key)
        got = getattr(args, key, None)
        if want != got:
            problems.append(
                f"campaign {key}={want!r}, but this run has {key}={got!r} "
                f"— launch it with `--protocol "
                f"{campaign.get('protocol_version') or 'N'}`")
    # WHICH SYSTEM. The digest makes two systems two campaigns; it does not
    # stop a shard of the other one from being LAUNCHED against this campaign,
    # and every shard of a mis-launched pair would carry the same digest, so
    # the merge could not see it either. Refused here, before item 1, for the
    # same reason as everything above it: an agent sweep spends real money per
    # item and the merge runs hours later.
    #
    # One-sided, like the rest: a campaign that names no system (every
    # archived one) constrains nothing. When it DOES name one, a fixture
    # adapter and an unresolvable one both arrive as None and are refused —
    # `gold` is not `aider`, and a row that cannot say which system produced
    # it must not be stamped with a campaign that asserts one.
    want_sys = campaign.get("agent_system")
    if want_sys is not None:
        got_sys = agent_system_of(args)
        if got_sys != want_sys:
            problems.append(
                f"campaign agent_system={want_sys!r}, but --adapter "
                f"{getattr(args, 'adapter', None)!r} resolves to "
                f"agent_system={got_sys!r} — an {want_sys} campaign's rows "
                f"are {want_sys}'s. A fixture transport and an adapter the "
                f"registry cannot resolve both name NO system, and a row that "
                f"cannot say which system produced it must not carry a "
                f"campaign that asserts one")
    # BUILT-IN SCAFFOLD.  This constrains every campaign run, including an
    # archived fingerprint which predates `agent_system`: the adapter still
    # says what is about to execute.
    #
    # THERE IS NO SANDBOX HALF ANY MORE.  It used to be here, comparing a
    # campaign's claim against `--sandbox-agent`, and being here was the bug:
    # this function runs only when `args.campaign` is set, so the plain
    # `r2t run --release` development route — the one the owner ruled
    # development uses — got no such refusal and launched the agent
    # unconfined.  The flag no longer exists: every agent spec is built with
    # `sandbox=True`, so a campaign has nothing left to disagree with.
    command_mode = (getattr(adapter, "config", None)
                    or {}).get("agent_command_mode")
    if command_mode == "custom_ad_hoc":
        problems.append(
            "this run uses a custom agent command, which is labelled "
            "custom_ad_hoc and cannot enter a publication campaign")
    if problems:
        raise SystemExit(
            f"REFUSED: this run's flags contradict the campaign it would stamp "
            f"its rows with ({path}):\n  - " + "\n  - ".join(problems)
            + "\nEvery row would carry a digest asserting a configuration this "
              "process does not have, and the merge cannot see that because "
              "all shards would assert it equally. Fix the flags, or make a "
              "new campaign with `r2t campaign`.")


def _resume_set(out_path: str, stamp: dict, retry_failed: bool,
                no_resume: bool) -> set[str]:
    """Which items are already done — and refuse to mix incompatible runs."""
    done: set[str] = set()
    conflicts: list[str] = []
    legacy = 0
    if not os.path.isfile(out_path):
        return done
    with open(out_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if "visibility" in row or "visibility" in stamp:
                if row.get("visibility") != stamp.get("visibility"):
                    raise SystemExit("REFUSED: source-view identity differs or is missing; use a fresh output")
            # Both directions: a sensitivity re-execution never resumes into,
            # or is resumed by, a run without the same label.
            if row.get("sensitivity") != stamp.get("sensitivity"):
                raise SystemExit("REFUSED: sensitivity label differs or is missing; use a fresh output")
            if "harness_version" not in row:
                legacy += 1
            # `harness_commit` names the bytes a row was produced by and is
            # provenance, not configuration (section 16): a resume across a
            # commit keeps each row's own commit.
            mismatched = sorted(k for k, v in stamp.items()
                                if k in row and row[k] != v
                                and k != "harness_commit")
            if "reference_derivation" in stamp or "reference_derivation" in row:
                mismatched += [key for key in ("reference_derivation", "reference_source_tag")
                               if key not in stamp or key not in row or stamp[key] != row[key]]
            # In CAMPAIGN mode an ABSENT field is a mismatch too. Outside it,
            # a missing field is only unverifiable; inside it, resuming an
            # unstamped row would relabel an older, differently-configured
            # result as part of this campaign — which is exactly how a merge
            # ends up internally consistent and provenance-false.
            #
            # ...except for the fields that did not EXIST when the old row was
            # written (`STAMP_OPTIONAL_FIELDS`). Their absence is
            # unverifiable-not-wrong even here: no row could have carried a
            # field the harness had not invented yet, and refusing on it would
            # kill a correct in-flight campaign hours into a paid sweep. A
            # PRESENT-and-different value still refuses, above, which is the
            # half that matters.
            if "campaign_digest" in stamp:
                mismatched += sorted(k for k in stamp if k not in row
                                     and k not in STAMP_OPTIONAL_FIELDS)
            if mismatched:
                conflicts.append(f"{row['item_id']}: {sorted(set(mismatched))}")
                continue
            # Supplied view evidence is checked even when this row will be retried.
            if row.get("visibility") is not None:
                from ..core.source_view import verify_recorded_view, ViewRefused
                try:
                    verify_recorded_view(row)
                except ViewRefused as exc:
                    raise SystemExit(f"REFUSED: run source-view evidence: {exc}") from exc
            if retry_failed and (
                    row.get("outcome") in _RETRYABLE_OUTCOMES
                    or (row.get("metadata") or {}).get("adapter_error")):
                continue
            done.add(row["item_id"])
    if conflicts and not no_resume:
        raise SystemExit(
            f"REFUSED: {out_path} holds {len(conflicts)} row(s) produced under "
            f"a different run configuration, e.g. {conflicts[0]}. Appending "
            f"would produce a file that is neither run. Use --out with a new "
            f"path, or --no-resume if you intend to mix them deliberately.")
    if legacy:
        print(f"  NOTE: {legacy} row(s) in {os.path.basename(out_path)} predate "
              f"run stamping, so their configuration cannot be verified.",
              flush=True)
    if no_resume:
        return set()
    return done


def item_key(item_id: str) -> str:
    """The release's own name for an item, without the `.json`.

    `release.build_release` names each gold record
    `sha1(item_id)[:16].json`, so reusing the derivation makes a run's
    artifacts join to its gold record by filename — and makes both safe as
    path components, which a raw item_id
    (`coreshop/features/domain/cart/x.feature:18`) is not.  Duplicated from
    release.py rather than imported because it is inlined there; `selftest`
    checks the two agree against the shipped manifest.
    """
    return hashlib.sha1(item_id.encode()).hexdigest()[:16]


def _safe_name(name: str) -> str:
    return name.replace(":", "_").replace("/", "_")


def _lines_by_file(units) -> dict:
    """`["src/X.php::L12", ...]` -> `{"src/X.php": [12, ...]}`.

    The recorder emits one string per covered line, which is about three
    times the bytes of the grouped form and has to be re-split by every
    reader before it can be intersected with anything.  Grouping here is
    lossless: `files` (the per-file COUNT the recorder also emits) is
    exactly the length of each list.
    """
    out: dict[str, list[int]] = {}
    for unit in units or []:
        path, sep, line = str(unit).rpartition("::L")
        if not sep or not line.isdigit():
            continue
        out.setdefault(path, []).append(int(line))
    return {p: sorted(set(v)) for p, v in sorted(out.items())}


def _fold_coverage(run: dict, representative_coverage: dict
                   ) -> tuple[Optional[dict], dict, list[str]]:
    """`(coverage_files, coverage_lines, coverage_mismatch)` over the matched records.

    One matched record -- every plain scenario -- is the identity: the
    recorder's own per-file counts beside its lines, and the mismatch
    witness comparing the two.  Several matched records -- a Scenario Outline
    -- union their lines (TARGET_INTERFACES_V2_SPEC section 4, V2-D3(a)): the
    API set is already the union over the same records (`fold_direct_calls`),
    and a region metric read from one Examples row under-measures every
    other row.  `coverage_files` is then the per-file size of the union, and
    the witness is taken PER RECORD before the union, because a malformed
    unit string dropped from one row would otherwise vanish into the union
    with no symptom.  A matched record without collected coverage
    contributes nothing; the representative's own coverage is what decides,
    as before, that the row collected at all.
    """
    matched, _rep = fold_scenario_records(
        run.get("records"),
        fold_lines(run.get("expected_line"), run.get("expected_lines")))
    collected = [r.get("coverage") for r in matched if r.get("coverage")]
    if len(collected) <= 1:
        files = representative_coverage.get("files")
        lines = _lines_by_file(representative_coverage.get("units"))
        return files, lines, _coverage_mismatch(files, lines)
    union: dict[str, set] = {}
    mismatch: set = set()
    for cov in collected:
        own = _lines_by_file(cov.get("units"))
        mismatch.update(_coverage_mismatch(cov.get("files"), own))
        for path, numbers in own.items():
            union.setdefault(path, set()).update(numbers)
    lines = {path: sorted(numbers) for path, numbers in sorted(union.items())}
    return {path: len(numbers) for path, numbers in lines.items()}, lines, sorted(mismatch)


def _coverage_mismatch(files, lines: dict) -> list[str]:
    """Files where the recorder's line COUNT and its line LIST disagree.

    Both come from the same PHP loop over `lineCoverage()`, so they cannot
    disagree unless a unit string was malformed and the regrouping above
    dropped it.  That failure is otherwise invisible — the record still
    reports `coverage_collected`, `coverage_files` still looks right, and
    every similarity computed from `coverage_lines` is merely *smaller* than
    it should be.  Recorded as a witness so a scoring pass can refuse the
    row instead of publishing a deflated number.
    """
    return sorted(f for f, n in (files or {}).items()
                  if n != len(lines.get(f, ())))


def _safe_rel(path: Optional[str]) -> Optional[str]:
    """A solution's own path, or None if it would escape the artifact dir."""
    rel = os.path.normpath((path or "").lstrip("/")).replace(os.sep, "/")
    if not rel or rel == "." or rel == ".." or rel.startswith("../"):
        return None
    return rel


def _write_artifacts(root: str, item: dict, adapter_name: str, produced: dict,
                     result: Optional[dict], rec: dict, stamp: dict) -> str:
    """Everything needed to re-analyse ONE item without re-running it.

        <root>/<adapter>/<item-key>/
            solution/…            the system's files at their own paths
            behat_services.yml    its DI fragment, if it supplied one
            stdout.log            the FULL Behat log, not the row's tail
            record.json           the run record as written to the run file
            coverage.json         line-granular coverage, when collected
            meta.json             what run produced this, and what happened

    The run file keeps a 2000-character tail of stdout because it is one
    row of a per-item JSONL; the interesting part of a failed run (the
    container compile error, the first PHP fatal) is at the top of the log
    and never survives that. `meta.stdout_complete` says which of the two
    landed here, because a truncated log that claims to be whole is worse
    than no log.
    """
    d = os.path.join(root, _safe_name(adapter_name), item_key(item["item_id"]))
    # Emptied, not merged into.  `--retry-failed` and `--no-resume` re-run
    # items, and a directory holding the new record next to the previous
    # run's solution and coverage is a set that is neither run — the same
    # failure mode `_resume_set` refuses for the run file.
    if os.path.isdir(d):
        import shutil
        shutil.rmtree(d)
    os.makedirs(d)

    refused_paths = []
    for f in produced.get("files") or []:
        rel = _safe_rel(f.get("file_path"))
        if rel is None:
            # The code is still in record.json's `produced_files`; what is
            # dropped is only the convenience copy, and dropping it silently
            # would misrepresent the solution.
            refused_paths.append(f.get("file_path"))
            continue
        if os.path.basename(rel) == SERVICES_FRAGMENT_NAME:
            dst = os.path.join(d, SERVICES_FRAGMENT_NAME)
        else:
            dst = os.path.join(d, "solution", rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(f.get("code") or "")

    runs = (result or {}).get("runs") or []
    complete = bool(runs) and all("stdout" in r for r in runs)
    if runs:
        logs = [r.get("stdout", r.get("stdout_tail") or "") for r in runs]
        text = logs[0] if len(logs) == 1 else "".join(
            f"=== run {i}/{len(logs)} ===\n{t}\n" for i, t in enumerate(logs, 1))
        with open(os.path.join(d, "stdout.log"), "w", encoding="utf-8") as fh:
            fh.write(text)

    # The run stamp is applied to the row by `run_adapter` AFTER this returns,
    # with the record winning any collision.  Repeated here so that
    # `record.json` is the row, not a version of it missing the condition and
    # model — the artifact tree has to be readable without the run file.
    with open(os.path.join(d, "record.json"), "w", encoding="utf-8") as fh:
        json.dump({**stamp, **rec}, fh, indent=1, sort_keys=True)

    if rec.get("coverage_collected"):
        with open(os.path.join(d, "coverage.json"), "w", encoding="utf-8") as fh:
            json.dump({"item_id": item["item_id"],
                       "files": rec.get("coverage_files") or {},
                       "lines": rec.get("coverage_lines") or {}},
                      fh, sort_keys=True)

    meta = {
        "item_id": item["item_id"],
        "item_key": item_key(item["item_id"]),
        "adapter": adapter_name,
        "condition": stamp.get("condition"),
        "model": stamp.get("model"),
        "harness_version": stamp.get("harness_version"),
        "outcome": rec.get("outcome"),
        "generation_seconds": rec.get("generation_seconds"),
        "execution_seconds": rec.get("execution_seconds"),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "coverage_requested": bool(rec.get("coverage_requested")),
        "coverage_collected": bool(rec.get("coverage_collected")),
        "stdout_complete": complete,
        "n_files": rec.get("n_files"),
        "solution_paths_not_written": refused_paths,
    }
    with open(os.path.join(d, "meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=1, sort_keys=True)
    return d


class _ExecutionLock:
    """One executor at a time, enforced, not assumed.

    Execution mutates ONE bind-mounted workspace: `clean_workspace` deletes
    every removable file, `_bench/run_record.jsonl` is deleted and re-read
    per run, `_bench/solution_index.json` and `services_item.yml` are
    rewritten per item, and `var/cache/test` is invalidated.  Two executors
    therefore delete each other's installed classes and read each other's
    records.  This is not hypothetical: two sweeps were once started 76
    seconds apart, and 26 of the 89 doubly-executed items (29%) came back
    with a DIFFERENT outcome for byte-identical input — the outcome label
    itself stopped being reproducible.  Nothing detected it, because the
    out file is opened append-only and resume reads it once at startup.
    """

    def __init__(self, root: str):
        self.path = os.path.join(root, ".r2t-exec.lock")
        self.fh = None

    def __enter__(self):
        self.fh = open(self.path, "w")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.fh.close()
            raise SystemExit(
                f"REFUSED: another execution holds {self.path}. Execution is "
                f"serial by construction — one workspace, one database, one "
                f"compiled container. Wait for it, or kill it first.")
        self.fh.write(f"{os.getpid()}\n")
        self.fh.flush()
        return self

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.fh, fcntl.LOCK_UN)
            self.fh.close()
        except Exception:                                  # noqa: BLE001
            pass


def _publication_execution_lock(harness_root: str, *, agent: bool):
    """Keep an agent lock beside, rather than inside, its exact seed tree."""
    root = os.path.dirname(harness_root) if agent else harness_root
    return _ExecutionLock(root)


def run_adapter(harness: Harness, args, artifacts: str, *, adapter=None) -> dict:
    with _ExecutionLock(harness.root):
        return _run_adapter_locked(
            harness, args, artifacts, adapter=adapter)


#: `--model` is in here with the relabelling flags, not the shard-shrinking
#: ones: this harness never invokes a model for submitted bytes, so a model
#: name on the flag would be stamped on every row as a claim about a
#: generation this run never saw.  The stamp writes `model: None` instead.
_SUBMITTED_REFUSED_OPTIONS = frozenset({
    "--condition", "--protocol", "--trials", "--replay", "--limit",
    "--item", "--shard", "--of", "--model", "--visibility-map",
})


def submitted_run_flags(args) -> None:
    """Refuse flags that could relabel or shrink a submitted denominator.

    Explicitness is captured by the CLI before worker defaults are applied.
    In particular, a worker may supply its own shard index as a runtime
    identity without turning the full-release submission into a shard.
    """
    if getattr(args, "adapter", None) != "submitted":
        if getattr(args, "candidates", None):
            raise SystemExit(
                "REFUSED: --candidates is read only by --adapter submitted; "
                "under any other adapter it would be silently ignored, and "
                "an ignored input file is a run that did not evaluate what "
                "the operator thinks it did. No Docker, daemon, pool, "
                "model, or network contact was made.")
        return
    explicit = set(getattr(args, "_submitted_explicit_options", ()) or ())
    if getattr(args, "visibility_map", None) is not None:
        explicit.add("--visibility-map")
    refused = sorted(explicit & _SUBMITTED_REFUSED_OPTIONS)
    if refused:
        reason = ("has no visibility-view verification join"
                  if "--visibility-map" in refused else
                  "fixes the submitted tier and the full-release denominator")
        raise SystemExit(
            f"REFUSED: --adapter submitted {reason}; remove {refused}. "
            "No Docker, daemon, "
            "pool, model, or network contact was made.")
    if not getattr(args, "candidates", None):
        raise SystemExit(
            "REFUSED: --adapter submitted requires --candidates FILE; no "
            "Docker, daemon, pool, model, or network contact was made.")

    # Resolve the same explicit-or-adjacent profile as the scoring harness,
    # before live worker validation. Until the submitted view join exists,
    # even a full-scope declaration would be an input this route ignores.
    from ..data.profile import load_profile, profile_path_for
    profile_path = getattr(args, "profile", None)
    boundary_path = getattr(args, "boundary", None)
    if not profile_path and boundary_path:
        from ..core.boundary import load_boundary
        profile_path = profile_path_for(
            boundary_path, load_boundary(boundary_path).project)
    if profile_path:
        profile = load_profile(profile_path)
        if profile.raw.get("visibility") is not None:
            raise SystemExit(
                "REFUSED: --adapter submitted cannot accept a profile with "
                f"a visibility block ({profile_path}) until its visibility-view "
                "verification join exists. No Docker, daemon, pool, model, "
                "or network contact was made.")


#: The projects the external-candidate submission amendment admits to the
#: submitted route: CoreShop (decision 3) and python-docx (decision 6).
#: `validate_submitted_project` holds the run to this literal, and `doctor`
#: reads it to know which projects get the submitted-route environment row.
SUBMITTED_ADMITTED_PROJECTS = ("coreshop", "python-docx")


def submitted_environment_proven(project: str,
                                 worker_spec_path: Optional[str]) -> bool:
    """Decision 7's stamp: was the scoring environment proven up?

    True iff the operator data root holds an accepted
    `r2t.project-environment/v1` record -- `state: "up"`,
    `gold_control.passed: true` -- for PROJECT, and this run's bound worker
    spec lies under that record's `workers_root`.  The containment join IS
    the record selection: pools are nonce-namespaced, so at most one saved
    record can contain the bound worker, and no flag chooses among them.

    False otherwise -- no configured data root, no saved record, a retired
    or unaccepted record, or a bound worker outside every saved pool --
    NEVER a refusal: this stamp replaced PR #195's unconditional bring-up
    refusal (amendment decision 7), and the run's own live-pool
    authentication of the bound worker is unchanged and no part of it.  The
    record's `docker_execution_authority` reference stays up-time evidence
    and is not re-compared here: one read of the saved record plus a path
    containment over already-known values, no re-hashing, no
    re-verification (`AGENTS.md`, Anti-OverDefense).
    """
    from ..toolkit.environment_lifecycle import _saved_records
    from ..core.paths import DATA_ROOT_ENV
    if not worker_spec_path or not os.environ.get(DATA_ROOT_ENV):
        return False
    worker = os.path.abspath(worker_spec_path)
    for _nonce, _path, record in _saved_records(project):
        pool = os.path.abspath(record["workers_root"])
        if worker.startswith(pool + os.sep):
            return (record["state"] == "up"
                    and record["gold_control"]["passed"] is True)
    return False


def _registered_release_item_ids(project: str) -> frozenset:
    """The item-id set of PROJECT's registered full release.

    `release/dataset_manifest.json` is the authority the rest of the tooling
    already reads (`doctor`, the retained-manifest reconstruction in this
    module's selftest): its project block names the released items file, and
    that file's ids ARE the denominator the submitted tier fixes.  Any
    failure to resolve them is a refusal, not a crash — a submitted run with
    an unverifiable denominator must not proceed to live contact.
    """
    release_root = RELEASE_DIR
    manifest_path = os.path.join(release_root, "dataset_manifest.json")
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            declaration = json.load(fh)["projects"][project]
        registered = frozenset(
            row["item_id"] for row in _load_release(
                os.path.join(release_root, declaration["items"])))
    except (KeyError, OSError, ValueError) as e:
        raise SystemExit(
            "REFUSED: cannot resolve the registered release for project "
            f"{project!r} from {manifest_path}: {e}. No Docker, daemon, "
            "pool, model, or network contact was made.") from e
    return registered


def validate_submitted_project(args, project: Optional[str],
                               items: Iterable[dict]) -> None:
    """Source-only admission of a submitted run's release inputs.

    Keep the approved external-submission route literal (CoreShop and
    python-docx, the amendment's two admitted projects), then hold the
    release rows to the identity the tier's denominator claim
    depends on.  The per-row project check mirrors the export-side check in
    `release.export_tasks`: a row from another project — or a row that does
    not say — fails closed.  The final pin compares the loaded item-id set
    against the project's registered full release, because a submitter who
    hands a subset release would otherwise choose their own denominator,
    which is exactly what `submitted_run_flags` exists to prevent.
    """
    if getattr(args, "adapter", None) != "submitted":
        return
    if project not in SUBMITTED_ADMITTED_PROJECTS:
        raise SystemExit(
            "REFUSED: --adapter submitted is approved only for the admitted "
            "projects 'coreshop' and 'python-docx'; got "
            f"{project!r}. No Docker, daemon, pool, model, or network "
            "contact was made.")
    rows = list(items)
    if not rows:
        raise SystemExit(
            "REFUSED: --release for a submitted run admitted no items; an "
            "empty release has no denominator to score against. No Docker, "
            "daemon, pool, model, or network contact was made.")
    foreign = next(
        (row for row in rows if row.get("project") != project), None)
    if foreign is not None:
        raise SystemExit(
            f"REFUSED: submitted release row {foreign.get('item_id')!r} "
            f"declares project {foreign.get('project')!r}, not {project!r}. "
            "No Docker, daemon, pool, model, or network contact was made.")
    registered = _registered_release_item_ids(project)
    loaded = {row["item_id"] for row in rows}
    if loaded != registered:
        raise SystemExit(
            f"REFUSED: --release does not match the registered {project} "
            f"release ({len(registered)} items): {len(registered - loaded)} "
            f"registered item(s) absent, {len(loaded - registered)} "
            "unregistered item(s) present. A submitted run's denominator is "
            "the registered full release, not the submitter's copy. No "
            "Docker, daemon, pool, model, or network contact was made.")


def _bind_submitted_population(args, items: Iterable[dict]) -> None:
    """Give the submitted adapter the exact population execution admitted."""
    if getattr(args, "adapter", None) == "submitted":
        args._submitted_admitted_item_ids = frozenset(
            item["item_id"] for item in items)


def _run_output_path(args, artifacts: str, adapter) -> str:
    """Resolve the ordinary run path after the adapter has its public name."""
    out_path = args.out or os.path.join(
        artifacts, "runs", f"{_safe_name(adapter.name)}.jsonl")
    if getattr(args, "of", None) and not args.out:
        out_path = os.path.join(
            artifacts, "runs",
            f"{_safe_name(adapter.name)}.shard{args.shard}.jsonl")
    return out_path


def _refuse_submitted_output_path(args, out_path: str) -> None:
    """A submitted evaluation always starts at a path that does not exist."""
    if getattr(args, "adapter", None) == "submitted" \
            and os.path.lexists(out_path):
        raise SystemExit(
            "REFUSED: submitted run output path already exists: "
            f"{out_path}. Use a new --out path; submitted runs do not resume "
            "or append. No Docker, daemon, pool, model, or network contact "
            "was made.")


def prepare_submitted_adapter(args, admitted_items: Iterable[dict], *,
                              project: Optional[str], artifacts: str):
    """Validate submitted bytes and their fresh output before live contact."""
    if getattr(args, "adapter", None) != "submitted":
        return None
    rows = list(admitted_items)
    validate_submitted_project(args, project, rows)
    _bind_submitted_population(args, rows)
    adapter = build_adapter(args, None)
    _refuse_submitted_output_path(
        args, _run_output_path(args, artifacts, adapter))
    return adapter


def _run_adapter_locked(harness: Harness, args, artifacts: str, *,
                        adapter=None) -> dict:
    items = _load_release(args.release)
    # An unknown --item is refused FIRST: it is a pure release-membership
    # fact, needs no harness or project, and must not be maskable by a
    # project's own pre-execution exclusion arithmetic.
    if args.item:
        want = set(args.item)
        missing = sorted(want - {item["item_id"] for item in items})
        if missing:
            raise SystemExit(
                "REFUSED: --item value(s) are not in --release "
                f"{args.release}: {', '.join(missing)}")
    validate_submitted_project(args, harness.boundary.project, items)
    items, _policy = admit_pre_execution(
        items, harness.boundary.project, getattr(args, "item", ()))
    _bind_submitted_population(args, items)
    if args.item:
        items = [i for i in items if i["item_id"] in want]
    # H4 — sharding comes BEFORE `--limit`.  The other order would make each
    # shard's contents depend on the limit, so `--limit 20 --of 4` would run
    # the first 20 items' shards rather than 20 items per worker, and two
    # campaigns with different limits would not be shards of the same set.
    shard, of = getattr(args, "shard", None), getattr(args, "of", None)
    if of:
        from .campaign import shard_of
        if shard is None or not 0 <= shard < of:
            raise SystemExit(f"REFUSED: --shard must be in 0..{of - 1}")
        items = [i for i in items if shard_of(i["item_id"], of) == shard]
    if args.limit:
        items = items[:args.limit]
    from ..go.context import preflight
    preflight(harness, items)
    if adapter is None:
        adapter = build_adapter(args, harness)

    out_path = _run_output_path(args, artifacts, adapter)
    # H5 — one out file per worker is derived in `_run_output_path` rather
    # than remembered.  A shared append-only out file is not merely untidy:
    # `_resume_set` reads it once at startup, so two shards appending to it
    # produce a file whose resume state was never true for either.
    _refuse_submitted_output_path(args, out_path)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    keep = getattr(args, "keep_artifacts", None)
    keep = os.path.abspath(keep) if keep else None

    stamp = _run_stamp(args, adapter)
    if getattr(args, "adapter", None) == "submitted":
        # Decision 7: the bring-up gate is a STAMP, not a refusal.  Every
        # submitted row says whether an accepted environment record covered
        # the worker that scored it; nothing refuses on proof-absence.
        stamp["environment_proven"] = submitted_environment_proven(
            harness.boundary.project, getattr(args, "worker", None))
    done = _resume_set(out_path, stamp,
                       retry_failed=getattr(args, "retry_failed", False),
                       no_resume=getattr(args, "no_resume", False))
    pending = [i for i in items if i["item_id"] not in done]

    counts: dict[str, int] = {}
    started = time.time()
    with open(out_path, "a", encoding="utf-8") as fh:
        for n, item in enumerate(pending, 1):
            # One item cannot end the shard.
            #
            # `run_one` guards the ADAPTER, so a model outage or an agent
            # driver crash is already a row. Everything else in it was
            # unguarded: a malformed solution, a container that will not
            # compile, an OSError from a full disk, a bug in this file. Any of
            # those killed the process and discarded every REMAINING item —
            # for a 100-item agent sweep, up to 99 items of generation that
            # were never paid for and now never will be, plus a shard the
            # merge refuses.  The exception becomes a row instead, in the same
            # out file, retryable by `--retry-failed` once the cause is fixed.
            try:
                rec = run_one(harness, adapter, item, coverage=args.coverage,
                              timeout=args.timeout, repeats=args.repeats,
                              keep_artifacts=keep, stamp=stamp)
            except KeyboardInterrupt:
                # An operator stopping the sweep is not a harness fault, and
                # swallowing it would make Ctrl-C take one item per press.
                raise
            except Exception as e:                          # noqa: BLE001
                rec = _harness_error_row(item["item_id"], e)
                print(f"  *** HARNESS ERROR on {item['item_id']}: "
                      f"{rec['metadata']['harness_error']} — recorded as a row "
                      f"and skipped; the shard continues. ***", flush=True)
            for key, value in stamp.items():
                rec.setdefault(key, value)
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            fh.flush()
            counts[rec["outcome"]] = counts.get(rec["outcome"], 0) + 1
            el = time.time() - started
            print(f"[{n}/{len(pending)}] {rec['item_id']} -> {rec['outcome']} "
                  f"({el/n:.1f}s/item)", flush=True)
    repro = _repro_check(harness, adapter, items, out_path,
                         getattr(args, "repro_check", 10),
                         coverage=args.coverage, timeout=args.timeout)

    # Leave the workspace as we found it.  Every run cleans BEFORE it
    # generates, so a leftover cannot affect a measurement — but the last
    # item's generated code sitting in the tree is confusing to anyone who
    # inspects the repo afterwards, and it is the kind of residue that
    # quietly becomes someone's evidence.
    from .repo import clean_workspace
    clean_workspace(harness.man, harness.boundary)
    harness.clear_registration()
    info = {"adapter": adapter.name, "out": out_path, "repro_check": repro,
            "n": len(pending), "outcomes": counts,
            "artifacts": keep,
            "shard": shard if of else None, "of": of,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z",
                                        time.localtime(started)),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "seconds": round(time.time() - started, 1)}
    config = getattr(adapter, "config", None) or {}
    if config.get("candidates"):
        info.update({"submitted": config["n_submitted"],
                     "release": len(items)})
    return info


#: Adapters whose output is a pure function of bytes already on disk.  Only
#: for these does re-running an item cost nothing but execution time.
_REPLAYABLE_ADAPTERS = (
    "gold", "stripped-gold", "empty", "stub", "replay")


def _repro_replayable(adapter) -> bool:
    """May this adapter's items be re-run for free, and without side effects?

    `replay` also arrives here under the NAME of whatever produced its cache
    (`make_replay_adapter` takes it so a replayed row stamps identically), so
    the name alone would skip the one case the check was designed for; its
    config says what it really is.
    """
    if getattr(adapter, "name", None) in _REPLAYABLE_ADAPTERS:
        return True
    config = getattr(adapter, "config", None) or {}
    return bool(config.get("replay") or config.get("candidates"))


def _repro_check(harness: Harness, adapter, items: list[dict], out_path: str,
                 n: int, coverage: bool, timeout: int, *,
                 feature_texts: Optional[Mapping[str, str]] = None) -> dict:
    """Re-execute a fixed subsample and refuse to trust a run that drifts.

    The input to an execution is fixed (for `replay`, byte-identical), so the
    same item must produce the same outcome twice.  When two executors once
    shared this workspace, 26 of 89 doubly-executed items (29%) came back with
    a DIFFERENT outcome for identical bytes — and nothing noticed, because the
    out file is append-only and resume reads it once.  This makes that class of
    corruption self-announcing instead of something a reviewer finds later.

    The subsample is the first `n` items in release order, so it is fixed
    rather than chosen after seeing the results.

    It re-invokes the ADAPTER, which is only free when the adapter is a
    lookup.  For an agent or a single-shot model it re-GENERATES: it spends
    model money a second time on `n` items, it is not a reproducibility check
    at all (a sampling model is not expected to answer twice the same way),
    and for the agent driver it re-enters a trajectory directory the driver
    refuses to reuse — so every sampled item came back different, and the run
    was branded "NOT trustworthy" by a check that had itself changed the
    input.  Skipped, loudly, rather than run against a system that generates.
    """
    if not _repro_replayable(adapter):
        name = getattr(adapter, "name", "?")
        why = (f"non-replayable adapter {name}: re-running would re-invoke "
               f"the system under test")
        print(f"  reproducibility check: SKIPPED — {why}. Re-execute this run "
              f"with `--adapter replay --replay <run file>` to check it for "
              f"free.", flush=True)
        return {"checked": 0, "skipped": why}
    if n <= 0:
        return {"checked": 0, "skipped": True}
    done = {}
    with open(out_path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                done[row["item_id"]] = row.get("outcome")
    sample = [i for i in items if i["item_id"] in done][:n]
    if not sample:
        return {"checked": 0, "skipped": True}
    drift = []
    for item in sample:
        relative = item["provenance"]["file_path"]
        text = None if feature_texts is None else feature_texts[relative]
        rec = run_one(harness, adapter, item, coverage=coverage, timeout=timeout,
                      feature_text=text)
        if rec["outcome"] != done[item["item_id"]]:
            drift.append({"item_id": item["item_id"],
                          "first": done[item["item_id"]],
                          "second": rec["outcome"]})
    out = {"checked": len(sample), "drift": drift,
           "reproducible": not drift}
    if drift:
        print(f"\n  *** REPRODUCIBILITY FAILURE: {len(drift)} of {len(sample)} "
              f"re-executed items changed outcome. This run file is NOT "
              f"trustworthy — something else is using the workspace. ***",
              flush=True)
        for d in drift[:5]:
            print(f"      {d['item_id']}: {d['first']} -> {d['second']}", flush=True)
    else:
        print(f"  reproducibility check: {len(sample)}/{len(sample)} identical",
              flush=True)
    return out


#: The adapters whose runs are gold runs (harness 25; specifications/
#: EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md section 3): they execute a
#: ground-truth closure, as is or with its assertions or step bodies emptied.
GOLD_RUN_ADAPTERS = frozenset({"gold", "stripped-gold", "stub"})


def is_gold_run_adapter(adapter) -> bool:
    """Whether this adapter's executions are gold runs (`Solution.gold_run`).

    The gold, stripped-gold and stub adapters' are, and an adapter whose
    builder says so (`req2test validate`'s ground-truth predictions set
    `config["gold_run"]`).  A replay adapter takes the name of the rows it
    re-serves, so a replay of gold rows is named `gold` too, and it is a
    candidate run: the decision reads the adapter this process built, never
    what a submission or a replayed row says.
    """
    config = getattr(adapter, "config", None) or {}
    return config.get("gold_run") is True or (
        getattr(adapter, "name", None) in GOLD_RUN_ADAPTERS
        and not config.get("replay"))


def run_one(harness: Harness, adapter, item: dict, coverage: bool = False,
            timeout: int = 600, repeats: int = 1,
            keep_artifacts: Optional[str] = None,
            stamp: Optional[dict] = None,
            feature_text: Optional[str] = None,
            after_prepare: Optional[Callable[[], None]] = None) -> dict:
    from ..go.context import preflight
    preflight(harness, [item])
    iid = item["item_id"]
    task = item.get("task") or "criterion_to_test"
    rel = item["provenance"]["file_path"]
    from ..java.algorand import runtime_feature_path
    runtime_rel = runtime_feature_path(item.get("project") or "", rel)
    if feature_text is None and runtime_rel != rel:
        with open(os.path.join(harness.root, runtime_rel),
                  encoding="utf-8") as handle:
            feature_text = handle.read()
    # `rel` remains the source identity carried by the item.  Only the bytes
    # are read from the composed runtime location.
    feature = parse_feature_file(os.path.join(harness.root, rel),
                                 text=feature_text)
    scenario = feature.scenario_at(item["provenance"]["line"])

    # The workspace is swept BEFORE generation, not only before execution.
    # A repo-reading agent that generates while the previous item's
    # installed closure — or its static index, or the compiled container
    # naming its classes — is still on disk can simply read it, which
    # reinstates exactly the retrieval confound repo-wide removal exists
    # to eliminate.
    harness.prepare_for_generation()
    if after_prepare is not None:
        after_prepare()

    # C3 (§3.9).  The adapter is handed a callable that executes THIS item's
    # scenario and nothing else — the item, the feature, the scenario, the
    # timeout and the coverage flag are all closed over here, where the
    # harness lives, so the agent's request has no field left to carry.  When
    # `--trials` is 0 the cell stays empty and the adapter takes exactly the
    # C2 path, which is what makes `k=0 ≡ C2` a structural claim rather than
    # a hope.
    cell = getattr(adapter, "trial_cell", None)
    if cell is not None and scenario is not None:
        def run_once(files: list, with_coverage: bool):
            sol = Solution.from_json({"files": files, "metadata": {}})
            res = harness.run_solution(feature, scenario, sol,
                                       coverage=with_coverage, timeout=timeout,
                                       task=task)
            return res, _record(iid, item, {"files": files}, 0.0, res,
                                coverage=with_coverage)

        cell["run_once"] = run_once

    t0 = time.time()
    try:
        produced = adapter(task_view(item))
    except _AggregateCapStopped:
        raise
    except Exception as e:                              # noqa: BLE001
        produced = {"files": [], "metadata": {"adapter_error": f"{type(e).__name__}: {e}"}}
    finally:
        if cell is not None:
            # Cleared so a later item cannot execute against the previous
            # item's scenario if binding is ever skipped.
            cell["run_once"] = None
    generation_seconds = time.time() - t0

    def attributed_substrate_violation(exc: SubstrateTampered,
                                       detected_at: str) -> tuple[dict, dict]:
        """Shape candidate-window tampering without trusting output shape."""
        report = exc.report
        violation = {key: list(report.get(key) or ())[:8]
                     for key in ("changed", "missing", "added")}
        if isinstance(produced, dict):
            safe_produced = dict(produced)
            raw_files = safe_produced.get("files")
            if not isinstance(raw_files, list):
                raw_files = []
            metadata = safe_produced.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {
                    "malformed_adapter_metadata": type(metadata).__name__,
                }
            else:
                metadata = dict(metadata)
                try:
                    json.dumps(metadata)
                except (TypeError, ValueError):
                    metadata = {
                        "malformed_adapter_metadata": "not JSON serialisable",
                    }
            files = []
            malformed_files = []
            for number, entry in enumerate(raw_files):
                if isinstance(entry, dict) \
                        and isinstance(entry.get("file_path"), str) \
                        and isinstance(entry.get("code"), str):
                    # Only the adapter contract enters the durable row.  An
                    # otherwise valid file may carry an arbitrary extra
                    # object; retaining it would make record.json fail to
                    # serialise after the substrate violation was already
                    # correctly attributed.
                    files.append({
                        "file_path": entry["file_path"],
                        "code": entry["code"],
                    })
                else:
                    malformed_files.append({
                        "index": number,
                        "type": type(entry).__name__,
                    })
            if malformed_files:
                metadata["malformed_adapter_files"] = {
                    "count": len(malformed_files),
                    "entries": malformed_files[:8],
                }
            safe_produced["files"] = files
        else:
            safe_produced = {"files": []}
            metadata = {
                "malformed_adapter_output": type(produced).__name__,
            }
        metadata["substrate_violation_attribution"] = {
            "window": "current_candidate_generation_or_trials",
            "detected_at": detected_at,
            "error": str(exc),
        }
        safe_produced["metadata"] = metadata
        # Shape this like Harness.run_solution's no-execution result.  The
        # authoritative verifier raised before any candidate file was
        # installed at the post-generation boundary.
        result = {
            "substrate_violation": violation,
            "written_files": [],
            "rejected_files": [],
            "feature_from_solution": False,
            "index_errors": {},
            "registered_contexts": None,
            "runs": [],
            "outcomes": [],
        }
        return safe_produced, result

    # The adapter controls both its return value and (for an agent) trial
    # execution.  Verify the retained substrate before parsing that untrusted
    # value or taking an early return: otherwise a malformed value can raise
    # first and make candidate-caused dirt look like a retryable harness bug.
    verify_substrate = getattr(harness, "verify_substrate", None)
    if callable(verify_substrate):
        try:
            verify_substrate()
        except SubstrateTampered as exc:
            safe_produced, result = attributed_substrate_violation(
                exc, "post_generation_before_output_parse")
            rec = _record(iid, item, safe_produced, generation_seconds,
                          result, coverage=coverage)
            if keep_artifacts:
                _write_artifacts(
                    keep_artifacts, item, getattr(adapter, "name", "?"),
                    safe_produced, result, rec, stamp or {})
            return rec

    solution = Solution.from_json(produced)
    solution.gold_run = is_gold_run_adapter(adapter)
    if scenario is None:
        rec = {"item_id": iid, "outcome": "scenario_not_found",
               "generation_seconds": generation_seconds,
               "metadata": produced.get("metadata", {})}
        if keep_artifacts:
            _write_artifacts(keep_artifacts, item, getattr(adapter, "name", "?"),
                             produced, None, rec, stamp or {})
        return rec

    # An empty solution is still EXECUTED: the scenario then runs with no glue
    # at all, which is the same must-fail leg §5 uses, and its outcome is the
    # floor every other outcome is read against.  Only the label is overridden.
    override = None
    if not solution.files:
        override = ("parse_error" if produced.get("metadata", {}).get("parse_error")
                    else "no_files_returned")

    try:
        from ..go.control_adapter import GoControlAdapter
        if isinstance(adapter, GoControlAdapter):
            result = adapter.run_control(harness, feature, scenario, solution,
                                         coverage=coverage, timeout=timeout,
                                         repeats=repeats, task=task,
                                         keep_stdout=bool(keep_artifacts))
        else:
            result = harness.run_solution(feature, scenario, solution,
                                          coverage=coverage, timeout=timeout,
                                          repeats=repeats, task=task,
                                          keep_stdout=bool(keep_artifacts))
    except SubstrateTampered as exc:
        # This catch is deliberately AT the final execution boundary, after
        # the adapter has generated (and, for C3, run its trials).  Tampering
        # found by prepare_for_generation() above predates this candidate and
        # still escapes to _run_adapter_locked as a retryable harness error.
        # At this boundary the current candidate is the only untrusted actor
        # that has run, so turning the exception into harness_error would
        # quarantine the wrong row and retry a candidate-caused result.
        produced, result = attributed_substrate_violation(
            exc, "authoritative_execution_boundary")
    except Exception as exc:
        # Generation has already completed. Keep its paid output and usage
        # even when authoritative execution cannot produce a result. The
        # outer fallback still owns failures before this boundary.
        rec = _harness_error_row(iid, exc)
        rec["metadata"] = {**(produced.get("metadata") or {}),
                           **rec["metadata"]}
        rec["produced_files"] = produced.get("files") or []
        rec["n_files"] = len(rec["produced_files"])
        rec["generation_seconds"] = round(generation_seconds, 2)
        rec["coverage_requested"] = coverage
        rec["coverage_collected"] = False
        if keep_artifacts:
            _write_artifacts(keep_artifacts, item, getattr(adapter, "name", "?"),
                             produced, None, rec, stamp or {})
        return rec
    rec = _record(iid, item, produced, generation_seconds, result,
                  override=override, coverage=coverage)
    if keep_artifacts:
        _write_artifacts(keep_artifacts, item, getattr(adapter, "name", "?"),
                         produced, result, rec, stamp or {})
    return rec


def _scenario_record(run: dict) -> Optional[dict]:
    """Repeat `RunResult.scenario`'s fold on a serialised run.

    The record file sits inside the bind-mounted workspace and the recorder
    appends to it at `@AfterScenario`, so a context supplied by the system
    under test can append a forged all-passed line from an earlier hook.
    `RunResult.outcome` selects by identity for exactly that reason — but the
    per-step numbers were read from `records[0]`, the unprotected slot, so
    every step-level figure (including the partial-credit measure) trusted
    whatever was written first.

    A `Scenario Outline` yields one record per Examples row, so the selection
    is a FOLD rather than a lookup, and it lives in `harness` so that this
    module, `RunResult` and `validate._thin` cannot drift apart — the last
    time two of them disagreed, the step numbers on a row described a
    different scenario from its outcome.
    """
    return fold_scenario_records(
        run.get("records"),
        fold_lines(run.get("expected_line"), run.get("expected_lines")))[1]


def _record(iid: str, item: dict, produced: dict, generation_seconds: float,
            result: dict, override: Optional[str] = None,
            coverage: bool = False) -> dict:
    runs = result["runs"]
    outcomes = [r["outcome"] for r in runs]
    # All-repeats-must-pass (SPEC §8, rule 4): with repeats > 1, disagreement
    # is not a pass — an assertion that held only sometimes did not hold.
    # The representative run is the first non-passing repeat (or the first
    # run when every repeat passed), and per_step/coverage/stdout/records
    # below are all read from that SAME representative, so a row's step
    # numbers can never describe a different repeat than its outcome — the
    # drift the Scenario Outline fold exists to prevent, applied to repeats.
    # Identity when repeats == 1, which is every archived row.
    rep = (next((r for r in runs if r["outcome"] != "passed"), runs[0])
           if runs else None)
    outcome = override or (rep["outcome"] if rep is not None else "no_run")
    index_errors = result.get("index_errors") or {}
    rejected = result.get("rejected_files") or []
    if index_errors and not override:
        outcome = "parse_or_compile_error"
    if rejected and not result.get("written_files"):
        outcome = "no_writable_files"
    # A submission that changed production code or the recorder during its own
    # execution has produced an unfalsifiable result, whatever Behat said: the
    # run may have been scored by a replaced recorder. It is voided here rather
    # than reported alongside a green outcome.
    if result.get("substrate_violation"):
        outcome = "substrate_violation"
    # `no_scenario_ran` covers everything from "the container did not
    # compile" to "the generated PHP threw before Behat reached a step".
    # For a system's run those are different findings, and §6 asks for
    # parse/compile status separately from execution outcome, so the
    # generated-code fatal is split out here.  Validation keeps the coarser
    # label: for gold, a fatal in restored code is a broken closure.
    if outcome == "no_scenario_ran" and runs:
        tail = rep.get("stdout_tail") or ""
        if "thrown in" in tail or "PHP Fatal error" in tail or "Parse error" in tail:
            outcome = "solution_error"

    per_step = []
    coverage_files = coverage_lines = coverage_mismatch = None
    coverage_collected = False
    rec = _scenario_record(rep) if runs else None
    if rec:
        per_step = [{"text": s["text"], "result": s["result"],
                     "seconds": s["seconds"],
                     "error": (s["exception"] or {}).get("message")}
                    for s in rec.get("steps", [])]
        cov = rec.get("coverage")
        if cov:
            coverage_files, coverage_lines, coverage_mismatch = _fold_coverage(rep, cov)
            coverage_collected = True

    # More records than the scenario could legitimately produce means
    # something wrote into the record file besides the one scenario we asked
    # for.  It is not necessarily an attack — but it is never normal, and it
    # must be visible.
    #
    # The budget is the number of lines a record may claim: one for a plain
    # scenario, the keyword line plus one per Examples row for an outline.
    # A flat `> 1` flagged every outline as an anomaly, which would have made
    # the flag meaningless on the corpora that have outlines.
    #
    # The budget is a UNION bound, not a tight one — an outline emits no
    # record for its keyword line, so it has one slot of slack and a single
    # forged extra record fits inside it without tripping this flag.  That is
    # the conservative direction on purpose: the flag is a visibility signal
    # and must never fire on a healthy row.  The defence against a forged
    # record is `fold_scenario_records`, which excludes any record whose line
    # is not one of these regardless of how many there are.
    n_records = len(rep.get("records") or []) if runs else 0
    n_expected = len(fold_lines(rep.get("expected_line"),
                                rep.get("expected_lines")) or []) if runs else 0
    substituted = bool(result.get("feature_from_solution"))
    if substituted and item.get("task") != "requirement_to_test":
        # install_solution refuses a .feature for this task, so reaching here
        # means the refusal was bypassed; do not report an execution outcome
        # for a scenario that is not the item's.
        outcome = "feature_substituted"

    return {
        "item_id": iid,
        "outcome": outcome,
        "feature_from_solution": substituted,
        "substrate_violation": result.get("substrate_violation"),
        "record_count": n_records,
        "record_count_anomaly": n_records > max(1, n_expected),
        "outcomes_all_runs": outcomes,
        # Non-null only on a timeout.  `survived` means the killed Behat is
        # still running and still appending to the record file the NEXT item
        # reads — the corruption the container-wide `pkill` used to cause and
        # then hide (defect 3, H7).
        "timeout_cleanup": next((r.get("timeout_cleanup") for r in runs
                                 if r.get("timeout_cleanup")), None),
        "generation_seconds": round(generation_seconds, 2),
        "execution_seconds": round(sum(r["wall_seconds"] for r in runs), 2),
        **({"resource_reset_seconds": round(sum(
            r.get("resource_reset_seconds", 0) for r in runs), 3)}
           if any("resource_reset_seconds" in r for r in runs) else {}),
        "n_files": len(produced.get("files") or []),
        # The system's actual output, kept so a run can be re-analysed
        # (or re-executed under an ablation) without paying for generation
        # again.
        "produced_files": produced.get("files") or [],
        "written_files": result.get("written_files"),
        "rejected_files": rejected,
        "registered_contexts": result.get("registered_contexts"),
        "index_errors": index_errors,
        # What the harness-25 corrections changed for this execution, on the
        # projects where each applies (specifications/EVALUATOR_CORRECTIONS_
        # 20261015_AMENDMENT.md section 3): the Go retained-test helpers
        # supplied, by gold file; the contexts a submission put in its suite
        # that harness 24 left out; the service ids autowired.  Empty, not
        # absent, when nothing changed.
        **{key: result[key] for key in ("supplied_helpers", "relisted_contexts",
                                        "autowired_services") if key in result},
        # A mutant crashed the Go test process: `failed`, disclosed by label.
        **({"crash": rep["crash"]} if runs and rep.get("crash") else {}),
        "per_step": per_step,
        "coverage_files": coverage_files,
        # Line granularity, because per-file counts cannot be intersected
        # with anything: two solutions that touch the same 40 lines of
        # `Order.php` and two that touch disjoint halves of it are
        # indistinguishable from the count alone.
        "coverage_lines": coverage_lines,
        # Union the required Examples records of this representative repeat
        # only. Per-step detail keeps its existing delegate and coverage is
        # the union over the matched records (`_fold_coverage`); missing API
        # evidence never changes the execution outcome.
        "direct_calls": (fold_direct_calls(
            rep.get("records"), rep.get("expected_line"),
            rep.get("expected_lines")) if rep is not None else None),
        "direct_calls_schema": (fold_direct_calls_schema(
            rep.get("records"), rep.get("expected_line"),
            rep.get("expected_lines")) if rep is not None else None),
        # Empty on every healthy row; non-empty means line data was lost on
        # the way from the recorder into this row, which deflates every
        # similarity computed from it without any other symptom.
        "coverage_mismatch": coverage_mismatch,
        # Requested-and-empty is a finding (the scenario ran but Xdebug was
        # not loaded, or nothing under src/ executed); not-requested is not,
        # and the two are indistinguishable from a null coverage field alone.
        "coverage_requested": coverage,
        "coverage_collected": coverage_collected,
        "exit_codes": [r["exit_code"] for r in runs],
        "stdout_tail": rep["stdout_tail"][-2000:] if runs else None,
        "metadata": produced.get("metadata", {}),
        "bench_meta": item.get("bench_meta"),
    }


def adapter_choices() -> list:
    """Every `--adapter` value this checkout can build, sorted.

    The registry's names -- the fixtures, `openai` and its alias, the shipped
    agents -- when the agent component is present, and `fixtures.FIXTURES`
    alone when it is not, which is how `run --adapter aider` in a
    benchmark-only checkout is refused at parse time rather than after a
    handler has run.
    """
    try:
        from ..agents.registry import known_names
    except ImportError:
        return sorted(FIXTURES)
    return known_names()


# ======================================================== result ledger I2
_PUBLICATION_ADAPTER_KINDS = {
    "empty": "empty",
    "gold": "gold",
    "stripped-gold": "stripped_gold",
    "stub": "stub",
}
_PUBLICATION_LOCK_SUFFIX = ".result-v3.lock"


def _publication_reserved_adapters() -> frozenset:
    """Every registered adapter name the v1 fixture gate refuses AS RESERVED.

    Reserved is not a second list to keep.  It is exactly "a fixture or a
    registered system, but not one of the four fixtures above", and the two
    tables are where adapters are registered -- so they are read here rather
    than restated.  It used to be a literal naming today's seven, and a
    literal is what a third agent falls out of: an arm the registry knows and
    this set does not is still refused, but as an UNKNOWN name, with the
    fixture menu on the message and nothing saying that the system the
    operator asked for exists and is simply not a v1 producer.  The two
    answers are not interchangeable to whoever reads the refusal -- one is a
    typo, the other is a routing mistake.

    Recomputed per call rather than pinned at import, so a spec registered
    afterwards -- which is how the selftest below drives a third arm through
    this gate -- is seen.  The import is function-local for the reason
    `build_adapter`'s is: the registry pulls the whole adapter chain behind
    it, and this gate runs before anything is built, on purpose.
    """
    try:
        from ..agents.registry import REGISTRY
    except ImportError:
        # No registry, nothing registered: only the fixtures that are not v1
        # producers stay reserved, and an unknown name gets the fixture
        # set's own refusal, which is the right one for a typo in a checkout
        # that ships only fixtures.
        registered = frozenset()
    else:
        registered = frozenset(REGISTRY)
    return (frozenset(FIXTURES) | registered) - frozenset(
        _PUBLICATION_ADAPTER_KINDS)


def publication_adapter_kind(args) -> str:
    """Close publication adapter admission before any expensive contact.

    This is the FIXTURE gate and it never moves: section 10 says result-ledger
    v1 never admits an agent, so EVERY registered agent stays reserved here
    even though `run --publication-v3 --adapter openhands` is admissible.
    That request does not reach this function at all -- it is routed to
    `agents.publication.agent_publication_adapter_kind` by the one explicit
    path section 3 names, which is the only place an agent name is admitted.
    """
    name = getattr(args, "adapter", None)
    if name in _PUBLICATION_ADAPTER_KINDS:
        return _PUBLICATION_ADAPTER_KINDS[name]
    if name in _publication_reserved_adapters():
        raise SystemExit(
            f"REFUSED: adapter {name!r} is reserved and cannot produce "
            "result-v3 evidence; no Docker, model, daemon, pool, or network "
            "contact was made.")
    raise SystemExit(
        f"REFUSED: adapter {name!r} is not in the closed result-v3 fixture "
        f"set {sorted(_PUBLICATION_ADAPTER_KINDS)}; no Docker, model, "
        "daemon, pool, or network contact was made.")


def is_agent_publication_request(argv_tail: Iterable[str]) -> bool:
    """Is this exactly section 3's `run --publication-v3 --adapter AGENT`?

    Answered from the TYPED tokens rather than a parsed namespace, because
    the answer decides which parser is built.  It is deliberately generous
    about everything except the two literals: a request that names an agent
    adapter alongside `--publication-v3` is ADMITTED TO THE AGENT GATE, which
    then applies section 3's complete refusal set to it.  Being generous here
    and exact there is what makes a malformed agent request produce section
    3's own message instead of the fixture set's.

    Without the agent producer there is no admitted agent kind, so no
    request can be one: False, exactly, and the fixture gate answers.
    """
    try:
        from ..confined import result_ledger_v2 as agent
    except ImportError:
        return False
    tokens = list(argv_tail)
    if "--publication-v3" not in tokens:
        return False
    for index, token in enumerate(tokens):
        if token == "--adapter" and index + 1 < len(tokens):
            value = tokens[index + 1]
        elif token.startswith("--adapter="):
            value = token[len("--adapter="):]
        else:
            continue
        if value in agent.ADMITTED_ADAPTER_KINDS:
            return True
    return False


def _publication_path(value: object, label: str, *, live: bool = True) -> str:
    from . import result_ledger as ledger
    return ledger.canonical_absolute_path(value, label, live=live)


def _publication_exact_path(value: object, expected: str, label: str) -> str:
    path = _publication_path(value, label, live=False)
    if path != expected:
        raise SystemExit(
            f"REFUSED: {label} {path!r} differs from authenticated path "
            f"{expected!r}; publication does not normalise path aliases.")
    return path


def publication_lock_path(result_path: str) -> str:
    from . import result_ledger as ledger
    if _PUBLICATION_LOCK_SUFFIX != ledger.PUBLICATION_LOCK_SUFFIX:
        raise ledger._refuse("publication result-lock suffix drifted")
    return _publication_path(
        result_path, "publication result path", live=False) \
        + ledger.PUBLICATION_LOCK_SUFFIX


class _PublicationResultLock:
    """Nonblocking OS ownership for one exact canonical result identity."""

    def __init__(self, result_path: str, *, create: bool = True):
        self.path = publication_lock_path(result_path)
        self.create = create
        self.fd = -1
        self.identity = None

    def __enter__(self):
        from . import result_ledger as ledger
        ledger._secure_directory_chain(self.path)
        parent = os.path.dirname(self.path)
        parent_fd = ledger._open_directory_nofollow(
            parent, "publication result-lock parent")
        created = False
        try:
            flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) \
                | getattr(os, "O_CLOEXEC", 0)
            if not self.create:
                self.fd = os.open(os.path.basename(self.path), flags,
                                  dir_fd=parent_fd)
            else:
                try:
                    self.fd = os.open(os.path.basename(self.path),
                                      flags | os.O_CREAT | os.O_EXCL, 0o600,
                                      dir_fd=parent_fd)
                    created = True
                    os.fchmod(self.fd, 0o600)
                    os.fsync(self.fd)
                    os.fsync(parent_fd)
                except FileExistsError:
                    self.fd = os.open(os.path.basename(self.path), flags,
                                      dir_fd=parent_fd)
        except OSError as exc:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1
            raise ledger._refuse(
                f"cannot open publication result lock {self.path}: {exc}") \
                from exc
        finally:
            os.close(parent_fd)
        try:
            leaf = ledger._trusted_leaf(
                self.path, "publication result lock")
            opened = os.fstat(self.fd)
            if ledger._stat_identity(leaf) != ledger._stat_identity(opened):
                raise ledger._refuse(
                    "publication result lock changed while it was opened")
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ledger._refuse(
                    f"another publication writer owns {self.path}") from exc
            leaf = ledger._trusted_leaf(
                self.path, "publication result lock")
            opened = os.fstat(self.fd)
            if ledger._stat_identity(leaf) != ledger._stat_identity(opened):
                raise ledger._refuse(
                    "publication result lock changed during acquisition")
            self.identity = ledger._stat_identity(opened)
            return self
        except BaseException:
            if self.fd >= 0:
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(self.fd)
                self.fd = -1
            # A newly-created lock deliberately persists.  Its exact path is
            # the stable identity every later contender must lock.
            del created
            raise

    def confirm(self) -> None:
        from . import result_ledger as ledger
        current = ledger._trusted_leaf(
            self.path, "publication result lock")
        opened = os.fstat(self.fd)
        if ledger._stat_identity(current) != self.identity \
                or ledger._stat_identity(opened) != self.identity:
            raise ledger._refuse(
                "publication result lock identity changed while owned")

    def __exit__(self, *exc):
        try:
            if self.fd >= 0:
                self.confirm()
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1


@dataclass
class _PublicationRunPlan:
    execution: dict
    plan: dict
    runtime: object
    context: object
    selected_items: list[dict]
    raw_by_path: dict[str, bytes]
    absent_paths: tuple[str, ...]
    strip_document: dict
    result_path: str
    checkpoint_path: str
    receipt_path: str
    worker_manifest_path: str

    @property
    def stamp(self) -> dict:
        return self.context.stamp

    @property
    def item_ids(self) -> list[str]:
        return self.context.item_ids


def _publication_raw_ref(reader, path: str, label: str) -> dict:
    from . import result_ledger as ledger
    path = _publication_path(os.path.abspath(path), label)
    raw = reader.read(path, label)
    return {"path": path, "file_sha256": ledger.raw_sha256(raw)}


def _publication_input(reader, role: str, logical_path: str,
                       path: str) -> dict:
    from . import result_ledger as ledger
    path = _publication_path(path, f"{role} input path")
    raw = reader.read(path, f"publication input {role}:{logical_path}")
    return {
        "role": role,
        "logical_path": logical_path,
        "path": path,
        "byte_length": len(raw),
        "file_sha256": ledger.raw_sha256(raw),
    }


def _publication_named_values(values: Mapping[str, object]) -> list[dict]:
    from . import result_ledger as ledger
    return [
        {"name": name,
         "value_json": ledger.canonical_json_bytes(values[name]).decode(
             "utf-8")}
        for name in sorted(values)
    ]


def _publication_selector(args, release_ids: list[str]) \
        -> tuple[dict, list[str]]:
    raw_requested = getattr(args, "item", None)
    requested = None
    if raw_requested is not None:
        if not isinstance(raw_requested, list) or not raw_requested \
                or any(not isinstance(value, str) or not value
                       for value in raw_requested):
            raise SystemExit(
                "REFUSED: publication --item values must be a nonempty list "
                "of nonempty item IDs.")
        if len(raw_requested) != len(set(raw_requested)):
            raise SystemExit(
                "REFUSED: publication --item repeats an item ID.")
        missing = sorted(set(raw_requested) - set(release_ids))
        if missing:
            raise SystemExit(
                f"REFUSED: publication --item IDs are absent from the exact "
                f"release: {missing}.")
        requested = sorted(raw_requested)
    limit = getattr(args, "limit", None)
    if limit is not None and (not isinstance(limit, int)
                              or isinstance(limit, bool) or limit <= 0):
        raise SystemExit(
            "REFUSED: publication --limit must be a positive integer.")
    wanted = None if requested is None else set(requested)
    selected = [item_id for item_id in release_ids
                if wanted is None or item_id in wanted]
    return {"limit": limit, "requested_item_ids": requested}, selected


def _publication_shard_ids(
        release_ids: list[str], selected_ids: list[str], selection: dict,
        shard: int, shard_count: int, *, slice3_context=None) -> list[str]:
    """The existing publication runner's one-shard assignment function."""
    from . import campaign

    if slice3_context is None:
        result = [item_id for item_id in selected_ids
                  if campaign.shard_of(item_id, shard_count) == shard]
        limit = selection["limit"]
        return result if limit is None else result[:limit]
    validate_cell_capability = _agent_module("agents.slice3_eval").validate_cell_capability
    try:
        context = validate_cell_capability(
            slice3_context, expected_mode="run_shard")
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if selection != {"limit": None, "requested_item_ids": None} \
            or selected_ids != release_ids \
            or release_ids != context["item_ids"]:
        raise SystemExit(
            "REFUSED: Slice-3 positional execution requires its complete "
            "frozen release and no secondary selector.")
    if shard != context["shard"] or shard_count != context["k_workers"]:
        raise SystemExit(
            "REFUSED: Slice-3 run shard/of differs from its capability.")
    return list(context["shard_item_ids"])


def _publication_manifest_object(document: dict, workspace: str,
                                 gold_root: str):
    from .repo import StripManifest
    manifest = StripManifest(
        repo_root=workspace,
        gold_root=(gold_root if document["gold_root"] == "."
                   else document["gold_root"]),
        moved=list(document["moved"]),
        moved_config=list(document["moved_config"]),
        patched=list(document["patched"]),
        installed=list(document["installed"]),
        boundary_version=document["boundary_version"],
        digests=dict(document["digests"]),
        substrate_roots=list(document["substrate_roots"]),
        substrate_volatile=list(document["substrate_volatile"]),
        bytecode_roots=list(document["bytecode_roots"]),
        build_roots=list(document["build_roots"]),
    )
    return manifest


#: Where the harness-owned price table is staged for a publication run.
#: Driver and transport helper instead execute from the authenticated backend
#: source package.  `verify_agent_adapter` closes all three against current
#: harness bytes.
AGENT_DEPLOYMENT_DIRECTORY = "agent-inputs"


def _agent_deployment_path(artifacts_root: str, source: str) -> str:
    return artifacts_root + "/" + AGENT_DEPLOYMENT_DIRECTORY + "/" \
        + os.path.basename(source)


def _publication_workspace_archive_files(
        raw: bytes, relative_paths: Iterable[str]) -> dict[str, bytes]:
    """Read exact regular files from an authenticated worker seed archive."""
    import io
    import tarfile

    from . import result_ledger as ledger

    wanted = {
        ledger._safe_relative(path, "worker seed archive member")
        for path in relative_paths
    }
    found: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                if member.name not in wanted:
                    continue
                if member.name in found:
                    raise ledger._refuse(
                        "worker seed archive repeats selected feature "
                        f"{member.name!r}")
                if not member.isfile():
                    raise ledger._refuse(
                        "worker seed archive selected feature is not a "
                        f"regular file: {member.name!r}")
                handle = archive.extractfile(member)
                if handle is None:
                    raise ledger._refuse(
                        "worker seed archive cannot open selected feature "
                        f"{member.name!r}")
                found[member.name] = handle.read()
    except ledger.ResultLedgerRefused:
        raise
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ledger._refuse(
            f"worker seed archive is not a readable tar archive: {exc}") \
            from exc
    missing = sorted(wanted - set(found))
    if missing:
        raise ledger._refuse(
            "authenticated worker seed archive omits checkpoint-selected "
            f"features: {missing}")
    return found


def construct_publication_run_plan(
        args, *, agent_admission=None,
        _verify_agent_workspace: bool = True,
        _checkpoint_feature_entries: Optional[
            Mapping[str, Mapping[str, object]]] = None) \
        -> _PublicationRunPlan:
    """Construct and self-verify the complete closed run plan, source-only.

    `agent_admission` is section 3's admitted request, and its presence is
    what selects the agent projection: it is produced only by
    `admit_agent_run` on the one explicit path, so a fixture request cannot
    reach the agent branches and an agent request cannot reach the fixture
    ones.
    """
    agent_kind = None
    if agent_admission is None:
        kind = publication_adapter_kind(args)
    else:
        kind = agent_kind = agent_admission["adapter_kind"]
    from . import campaign
    from . import result_ledger as ledger
    from . import worker
    from .validate import HARNESS_VERSION

    if getattr(args, "keep_artifacts", None) is not None:
        raise SystemExit(
            "REFUSED: --keep-artifacts is outside result-v3 receipt closure.")
    if bool(getattr(args, "no_resume", False)):
        raise SystemExit(
            "REFUSED: publication-v3 fixes --no-resume=false; a bound path "
            "is never extended as a fresh run.")
    if bool(getattr(args, "retry_failed", False)):
        raise SystemExit(
            "REFUSED: publication-v3 fixes --retry-failed=false; retries use "
            "a new attempt and output path.")
    for name in ("repeats", "timeout"):
        value = getattr(args, name, None)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise SystemExit(
                f"REFUSED: publication --{name} must be a positive integer.")
    repro_count = getattr(args, "repro_check", None)
    if not isinstance(repro_count, int) or isinstance(repro_count, bool) \
            or repro_count < 0:
        raise SystemExit(
            "REFUSED: publication --repro-check must be an integer >= 0.")
    # A REPRODUCIBILITY SAMPLE OVER AN AGENT IS A SECOND BILL, NOT A CHECK.
    #
    # `_repro_check` on the ordinary path already declines this, for reasons
    # spelled out in its docstring: the sample re-invokes the ADAPTER, which
    # costs nothing but time only when the adapter is a lookup, and for an
    # agent it re-GENERATES -- it spends model money a second time, and it
    # re-enters a trajectory directory the driver refuses to reuse, so every
    # sampled item comes back different.  `_publication_repro_check` had no
    # such guard.  With the default `--repro-check 10`, an agent shard
    # therefore finished, re-invoked the PAID agent on ten of its own items,
    # and was then refused whole for "publication reproducibility sample
    # drifted": money spent twice in order to throw the shard away.
    #
    # It is REFUSED here rather than skipped there because `repro_count` is
    # sealed into the run stamp and published.  A stamp reading
    # `repro_check_count: 10` next to a result that checked nothing is a
    # claim the run does not support, and this route fails closed on an
    # identity that does not say what it means.  Refusing costs the operator
    # one token before any Docker, model, daemon or network contact;
    # skipping would have cost a shard and left the record ambiguous.
    # Nothing downstream wanted the other answer either: the Slice-3 launch
    # observation already requires this stamp to read 0.
    #
    # Fixture publication is untouched.  `_PUBLICATION_ADAPTER_KINDS` is
    # exactly the four lookups, for which the sample is the free check it
    # was designed to be, so the gate is keyed to the agent projection
    # rather than applied to the whole route.
    if agent_kind is not None and repro_count > 0:
        raise SystemExit(
            "REFUSED: an agent publication run takes --repro-check 0; an "
            "agent does not replay, so the sample would re-invoke the paid "
            "system under test on an already-finished shard and then refuse "
            "it for drift. No Docker, model, daemon, pool, or network "
            "contact was made.")
    # THE SANDBOX PAIR THAT WAS HERE IS GONE, not relaxed.  It refused a
    # fixture publication carrying `--sandbox-agent` and an agent publication
    # without it; both were comparisons against a flag, and the flag is gone.
    # What it asserted is now structural: an agent spec declares the bwrap
    # sandbox and `agents.registry` builds it with `sandbox=True`, a fixture
    # transport declares none and launches nothing, and neither can be told
    # otherwise from a command line.  Keeping a comparison whose two sides
    # are both constants would only assert that this file still agrees with
    # itself.
    required_args = ("worker", "campaign", "worker_manifest", "out",
                     "release", "boundary", "gold", "artifacts")
    if agent_kind is not None:
        required_args += ("protocol", "llm_config", "agent_backend_runtime",
                          "agent_seed_manifest", "model")
    missing_args = [name for name in required_args
                    if not getattr(args, name, None)]
    if missing_args:
        raise SystemExit(
            f"REFUSED: publication-v3 run requires explicit bindings "
            f"{missing_args}; no Docker command was run.")

    reader = ledger._LiveReader()
    live_harness = ledger._stable_harness_identity(reader)
    live_harness["version"] = HARNESS_VERSION
    try:
        selected_static = worker.validate_worker_runtime_v3(
            args.worker, harness_version=HARNESS_VERSION,
            needs_database=None if agent_kind is not None else False)
        pool_paths = [entry["worker_spec_path"] for entry in
                      selected_static["binding"]["pool"]["workers"]]
        complete_pool = worker.validate_offline_worker_runtime_pool(pool_paths)
    except worker.WorkerRefused as exc:
        raise SystemExit(str(exc)) from exc
    index = selected_static["worker"].index
    if index >= len(complete_pool) \
            or complete_pool[index]["spec_path"] \
            != selected_static["spec_path"]:
        raise SystemExit(
            "REFUSED: selected worker is not its exact complete-pool member.")
    selected_static = complete_pool[index]
    # A resuming process adopts the checkpoint's recorded harness identity
    # (section 16.5, option B): the reconstructed execution and plan then
    # equal the checkpoint's, `_load_checkpoint`'s equalities hold, and the
    # version is still enforced by `publication_runtime_reference` against
    # the pool attestation validated at the live `HARNESS_VERSION` above.
    harness_identity = _recorded_publication_harness(
        selected_static["worker"].out_path)
    if harness_identity is None:
        harness_identity = live_harness
    else:
        ledger.disclose_harness_drift(harness_identity, live_harness)
    runtime_reference = worker.publication_runtime_reference(
        selected_static, harness_identity)
    runtime_context = ledger._verify_runtime(reader, runtime_reference)
    spec = runtime_context.worker

    result_path = _publication_exact_path(
        args.out, spec.out_path, "publication result path")
    _publication_exact_path(
        args.artifacts, spec.artifacts_root,
        "publication artifacts root")
    if getattr(args, "repo", None) != spec.workspace:
        raise SystemExit(
            "REFUSED: publication workspace differs from authenticated "
            "WorkerSpec.workspace.")
    if getattr(args, "container", None) != spec.container \
            or getattr(args, "workdir", None) != spec.workdir:
        raise SystemExit(
            "REFUSED: publication container/workdir differs from the "
            "authenticated WorkerSpec.")
    worker_manifest_path = _publication_path(
        args.worker_manifest, "publication WorkerManifest path", live=False)
    if args.worker_manifest != worker_manifest_path:
        raise SystemExit(
            "REFUSED: --worker-manifest must use its exact canonical absolute "
            "spelling in publication mode.")
    ledger._secure_directory_chain(worker_manifest_path)
    checkpoint_path = result_path + ledger.CHECKPOINT_SUFFIX
    receipt_path = result_path + ledger.RECEIPT_SUFFIX
    if worker_manifest_path in {
            result_path, checkpoint_path, receipt_path,
            publication_lock_path(result_path)}:
        raise SystemExit(
            "REFUSED: publication WorkerManifest path collides with a "
            "result/checkpoint/receipt/lock role; no Docker command was run.")
    for path, label in ((result_path, "result"),
                        (checkpoint_path, "checkpoint"),
                        (receipt_path, "receipt")):
        _publication_path(path, f"publication {label} path", live=False)
        ledger._secure_directory_chain(path)

    campaign_ref = _publication_raw_ref(
        reader, args.campaign, "generation campaign")
    campaign_raw = reader.raw_by_path[campaign_ref["path"]]
    campaign_document = ledger._parse_json_object(
        campaign_raw, "generation campaign")
    campaign_digest = campaign.campaign_digest(campaign_document)
    if campaign_document.get("schema") != campaign.GENERATION_CAMPAIGN_SCHEMA:
        raise SystemExit(
            "REFUSED: publication needs exact generation campaign v2.")
    if agent_kind is None:
        if campaign_document.get("model") is not None \
                or campaign_document.get("agent_system") is not None:
            raise SystemExit(
                "REFUSED: fixture publication campaign carries a model or "
                "agent identity.")
    else:
        # Section 3: "The campaign is executable r2t.generation-campaign/v2,
        # its selected agent_system equals the adapter, and its model equals
        # MODEL."  Checked here, before Docker or model contact, and again by
        # the semantic verifier over the frozen plan.
        if campaign_document.get("agent_system") != agent_kind:
            raise SystemExit(
                f"REFUSED: agent publication campaign agent_system "
                f"{campaign_document.get('agent_system')!r} is not the "
                f"admitted adapter {agent_kind!r}; no Docker or model contact "
                "was made.")
        if campaign_document.get("model") != getattr(args, "model", None):
            raise SystemExit(
                "REFUSED: agent publication campaign model differs from "
                "--model; no Docker or model contact was made.")
    # No adapter exists yet at this plan-construction boundary; the
    # command-mode half re-runs at `_run_stamp` with the real adapter.
    _check_campaign_flags(args, campaign_document, campaign_ref["path"], None)
    campaign_ref.update({
        "campaign_digest": campaign_digest,
        "semantic_digest": ledger.semantic_digest(campaign_document),
    })
    agent_runtime_path = campaign_ref["path"] + ".agent_runtime.json"
    agent_runtime_ref = _publication_raw_ref(
        reader, agent_runtime_path, "campaign agent runtime")
    agent_runtime_document = ledger._parse_json_object(
        reader.raw_by_path[agent_runtime_path], "campaign agent runtime")
    agent_runtime_ref["agent_runtime_sha256"] = (
        campaign.agent_runtime_digest(agent_runtime_document))

    release_ref = _publication_raw_ref(reader, args.release, "release")
    release_path = release_ref["path"]
    release_rows = ledger._json_lines(
        reader.raw_by_path[release_path], "publication release")
    release_ids = []
    for number, row in enumerate(release_rows):
        item_id = row.get("item_id") if isinstance(row, dict) else None
        if not isinstance(item_id, str) or not item_id:
            raise SystemExit(
                f"REFUSED: release row {number} has no nonempty item_id.")
        if item_id in release_ids:
            raise SystemExit(
                f"REFUSED: release repeats item ID {item_id!r}.")
        release_ids.append(item_id)
    selection, selected_ids = _publication_selector(args, release_ids)

    shard = getattr(args, "shard", None)
    shard_count = getattr(args, "of", None)
    if not isinstance(shard_count, int) or isinstance(shard_count, bool) \
            or shard_count <= 0:
        raise SystemExit(
            "REFUSED: publication --of must be a positive integer.")
    if not isinstance(shard, int) or isinstance(shard, bool) \
            or not 0 <= shard < shard_count:
        raise SystemExit(
            "REFUSED: publication --shard must be in the authenticated "
            "zero-based pool range.")
    if shard != spec.index or shard_count != len(complete_pool):
        raise SystemExit(
            "REFUSED: publication shard/of differs from authenticated worker "
            "index and complete pool.")
    slice3_context = getattr(args, "_slice3_cell_context", None)
    if slice3_context is None:
        effective_shard_rule = campaign.SHARD_RULE
    else:
        validate_cell_capability = _agent_module("agents.slice3_eval").validate_cell_capability
        try:
            slice3_context = validate_cell_capability(
                slice3_context, expected_mode="run_shard")
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        if shard != slice3_context["shard"] \
                or shard_count != slice3_context["k_workers"] \
                or agent_kind != slice3_context["agent_system"] \
                or getattr(args, "protocol_version", None) \
                != slice3_context["protocol_version"] \
                or getattr(args, "protocol_digest", None) \
                != slice3_context["protocol_digest"]:
            raise SystemExit(
                "REFUSED: Slice-3 run arguments differ from the one bound "
                "cell shard.")
        effective_shard_rule = campaign.POSITIONAL_SHARD_RULE
    selected_ids = _publication_shard_ids(
        release_ids, selected_ids, selection, shard, shard_count,
        slice3_context=slice3_context)
    row_by_id = {row["item_id"]: row for row in release_rows}
    selected_rows = [row_by_id[item_id] for item_id in selected_ids]

    boundary_ref = _publication_raw_ref(reader, args.boundary, "boundary")
    boundary_value = ledger._parse_yaml(
        reader.raw_by_path[boundary_ref["path"]], "boundary")
    if not isinstance(boundary_value, dict) \
            or not isinstance(boundary_value.get("project"), str):
        raise SystemExit("REFUSED: publication boundary has no project.")
    if slice3_context is not None \
            and boundary_value["project"] != slice3_context["project"]:
        raise SystemExit(
            "REFUSED: Slice-3 run boundary names another project.")
    from ..data.profile import profile_path_for
    resolved_profile = getattr(args, "profile", None) or profile_path_for(
        boundary_ref["path"], boundary_value["project"])
    profile_ref = _publication_raw_ref(
        reader, resolved_profile, "resolved profile")

    protocol_ref = None
    protocol_document = None
    if getattr(args, "protocol", None) is not None:
        from .protocol_file import path_for
        protocol_path = path_for(args.protocol)
        protocol_ref = _publication_raw_ref(
            reader, protocol_path, "protocol")
        protocol_document = ledger._parse_yaml(
            reader.raw_by_path[protocol_ref["path"]], "protocol")
    from .protocol_file import SLICE3_VERSIONS
    if agent_kind is not None and protocol_document is not None \
            and protocol_document.get("protocol_version") \
            in SLICE3_VERSIONS \
            and slice3_context is None:
        raise SystemExit(
            "REFUSED: Slice-3 protocol (v5-v8) agent publication requires "
            "the validated Slice-3 run_shard capability; use the Slice-3 "
            "operator path.")

    gold_root = _publication_path(args.gold, "publication gold root")
    strip_path = gold_root + "/strip_manifest.json"
    files = [_publication_input(
        reader, "harness_strip_manifest", "strip_manifest.json", strip_path)]
    feature_paths = set()
    feature_bindings = []
    from ..java.algorand import runtime_feature_path
    for row in selected_rows:
        provenance = row.get("provenance")
        if not isinstance(provenance, dict):
            raise SystemExit(
                f"REFUSED: release row {row['item_id']!r} has no provenance.")
        relative = ledger._safe_relative(
            provenance.get("file_path"), "release feature path")
        # A feature file can contain several selected scenarios.  The closed
        # input projection binds each byte stream once; repeating the same
        # (role, logical_path) would make the otherwise valid plan fail its
        # own uniqueness check.
        if relative in feature_paths:
            continue
        feature_paths.add(relative)
        runtime_relative = runtime_feature_path(
            boundary_value["project"], relative)
        target = ledger._contained_path(
            spec.workspace, runtime_relative,
            "publication harness feature")
        feature_bindings.append((relative, runtime_relative, target))

    recovered_feature_raw: dict[str, bytes] = {}
    checkpoint_features = _checkpoint_feature_entries
    archive_features: dict[str, bytes] = {}
    if checkpoint_features is not None:
        if set(checkpoint_features) != feature_paths:
            raise ledger._refuse(
                "checkpoint-selected feature membership differs from the "
                "current publication request")
        from . import seed as seed_module
        archive_path = (
            runtime_context.identity["seed_dir"] + "/"
            + seed_module.WORKSPACE_TAR)
        archive_raw = reader.raw_by_path.get(archive_path)
        if archive_raw is None:
            raise ledger._refuse(
                "authenticated worker seed archive was not retained by the "
                "runtime verifier")
        archive_features = _publication_workspace_archive_files(
            archive_raw,
            (runtime_relative for _logical, runtime_relative, _target
             in feature_bindings))

    for relative, runtime_relative, target in feature_bindings:
        checkpoint_entry = (
            None if checkpoint_features is None
            else checkpoint_features[relative])
        if checkpoint_entry is None:
            files.append(_publication_input(
                reader, "harness_feature", relative, target))
            continue
        # A retained substrate row can name a selected feature that the
        # previous item changed or removed. Recovery self-verifies the old
        # plan with bytes from the authenticated worker seed archive, while
        # leaving the dirty live target untouched. The alias exists only while
        # the plan verifier reads the feature entry; the archive itself stays
        # in the stable reader and is re-confirmed before this method returns.
        target = _publication_path(
            target, "recovered harness feature path", live=False)
        expected = {
            "role": "harness_feature",
            "logical_path": relative,
            "path": target,
            "byte_length": checkpoint_entry.get("byte_length"),
            "file_sha256": checkpoint_entry.get("file_sha256"),
        }
        if dict(checkpoint_entry) != expected:
            raise ledger._refuse(
                "checkpoint harness feature binding differs from the current "
                f"publication request: {relative}")
        raw = archive_features[runtime_relative]
        if not isinstance(expected["byte_length"], int) \
                or isinstance(expected["byte_length"], bool) \
                or expected["byte_length"] != len(raw) \
                or expected["file_sha256"] != ledger.raw_sha256(raw):
            raise ledger._refuse(
                "checkpoint harness feature differs from its authenticated "
                f"worker seed archive member: {relative}")
        if target in reader.raw_by_path:
            raise ledger._refuse(
                "recovered harness feature was opened before seed recovery: "
                f"{relative}")
        reader.raw_by_path[target] = raw
        recovered_feature_raw[target] = raw
        files.append(expected)

    public_configuration = {}
    # The profile is authoritatively loaded again by the semantic verifier;
    # this bounded parse only decides the closed coordinator role set.
    profile_value = ledger._parse_yaml(
        reader.raw_by_path[profile_ref["path"]], "resolved profile")
    if agent_kind and isinstance(profile_value, dict) and "visibility" in profile_value:
        raise ledger._refuse("publication source-view qualification is not yet admitted")
    framework = profile_value.get("framework") \
        if isinstance(profile_value, dict) else None
    if framework == "behat":
        alias_path = spec.artifacts_root + "/alias_table.json"
        files.append(_publication_input(
            reader, "harness_alias_table", "alias_table.json", alias_path))
        autowire_path = spec.artifacts_root + "/autowirable_types.json"
        if os.path.lexists(autowire_path):
            files.append(_publication_input(
                reader, "harness_autowirable_types",
                "autowirable_types.json", autowire_path))
            autowire_present = True
        else:
            reader.require_absent(
                autowire_path, "optional harness autowirable types")
            autowire_present = False
        public_configuration[
            "harness_autowirable_types_present"] = autowire_present
    elif framework not in ("behave", "cucumber", "cucumber_ruby"):
        raise SystemExit(
            f"REFUSED: publication profile framework {framework!r} has no "
            "admitted harness projection.")
    # `_build_publication_adapter` builds the stub and stripped-gold fixtures
    # from frozen in-memory bytes for these three frameworks only; any other
    # would fall through to the PHP fixture and measure a control that is
    # not the one its name says.  Cucumber's stub also needs the pinned
    # feature tree from disk, which this route does not read.
    if kind in {"stub", "stripped_gold"} \
            and framework not in ("behat", "behave", "cucumber_ruby"):
        raise SystemExit(
            f"REFUSED: publication fixture {getattr(args, 'adapter')!r} has "
            f"no frozen-bytes producer for framework {framework!r}; run that "
            "control without --publication-v3, where the fixture dispatches "
            "per stack. No Docker, pool or network contact was made.")

    all_release_ids = set(release_ids)
    agent_projection = None
    if agent_kind is not None:
        agent_projection = _agent_module(
            "agents.publication")._agent_publication_projection(
            reader, args, adapter_kind=agent_kind, workspace=spec.workspace,
            artifacts_root=spec.artifacts_root, result_path=result_path,
            protocol_document=protocol_document,
            verify_workspace=_verify_agent_workspace)
        if slice3_context is not None \
                and agent_projection["model_config"][
                    "aggregate_cost_guard"]["evaluation_plan_digest"] \
                != slice3_context["plan_digest"]:
            raise SystemExit(
                "REFUSED: Slice-3 model-config guard names another "
                "evaluation plan.")
        files.extend(agent_projection["files"])
        public_configuration.update(agent_projection["configuration"])
    elif kind == "gold":
        public_configuration["gold_root"] = gold_root
        manifest_path = os.path.dirname(release_path) + "/gold/manifest.json"
        files.append(_publication_input(
            reader, "release_gold_manifest", "gold/manifest.json",
            manifest_path))
        manifest = ledger._parse_json_object(
            reader.raw_by_path[manifest_path], "release gold manifest")
        if set(manifest) != all_release_ids:
            raise SystemExit(
                "REFUSED: release gold manifest membership differs from "
                "the exact release.")
        sources = set()
        for item_id in selected_ids:
            name = ledger._safe_relative(
                manifest.get(item_id), "release gold sidecar name")
            if "/" in name:
                raise SystemExit(
                    "REFUSED: release gold sidecar name is not a basename.")
            logical = "gold/" + name
            sidecar = os.path.dirname(release_path) + "/" + logical
            files.append(_publication_input(
                reader, "release_gold_record", logical, sidecar))
            record = ledger._parse_json_object(
                reader.raw_by_path[sidecar], "release gold record")
            if record.get("item_id") != item_id \
                    or not isinstance(record.get("files"), list):
                raise SystemExit(
                    "REFUSED: release gold record identity/closure is invalid.")
            for relative in record["files"]:
                sources.add(ledger._safe_relative(
                    relative, "release gold source"))
        for relative in sorted(sources):
            files.append(_publication_input(
                reader, "gold_source", relative,
                ledger._contained_path(gold_root, relative, "gold source")))
    elif kind in {"stripped_gold", "stub"}:
        if kind == "stripped_gold":
            public_configuration["gold_root"] = gold_root
        closures_path = spec.artifacts_root + "/closures.json"
        files.append(_publication_input(
            reader, "fixture_closures", "closures.json", closures_path))
        _closures, closures_by_id = ledger._closure_records(
            reader.raw_by_path[closures_path], "fixture closures")
        absent = sorted(set(selected_ids) - set(closures_by_id))
        if absent:
            raise SystemExit(
                f"REFUSED: fixture closures omit selected IDs: {absent}.")
        if kind == "stripped_gold":
            sources = {
                ledger._safe_relative(relative, "stripped-gold source")
                for item_id in selected_ids
                for relative in closures_by_id[item_id]["files"]
            }
            for relative in sorted(sources):
                files.append(_publication_input(
                    reader, "gold_source", relative,
                    ledger._contained_path(
                        gold_root, relative, "stripped-gold source")))

    files.sort(key=lambda item: (
        item["role"], item["logical_path"], item["path"]))
    stamp = {name: None for name in ledger.RUN_STAMP_NAMES}
    stamp.update({
        "adapter": getattr(args, "adapter"),
        "campaign_digest": campaign_digest,
        "condition": campaign_document["condition"],
        "coverage": campaign_document["coverage"],
        "execution_timeout_seconds": getattr(args, "timeout"),
        "harness_commit": (
            None if harness_identity["git_commit"] is None
            else harness_identity["git_commit"][:7]),
        "harness_version": harness_identity["version"],
        "keep_artifacts": None,
        "of": shard_count,
        "repeats": getattr(args, "repeats"),
        "repro_check_count": repro_count,
        "sandboxed": False,
        "shard": shard,
        "trials": campaign_document["trial_budget"],
        "protocol_digest": campaign_document["protocol_digest"],
        "protocol_version": campaign_document["protocol_version"],
    })
    if protocol_document is not None:
        stamp.update({
            "agent_timeout_seconds": protocol_document[
                "agent_timeout_seconds"],
            "max_iterations": protocol_document["max_iterations"],
            "setting": protocol_document["setting"],
            "temperature": protocol_document.get("temperature"),
        })
    secret_inputs: list[str] = []
    if agent_kind is not None:
        agentv2 = _agent_module("confined.result_ledger_v2")
        get_spec = _agent_module("agents.registry").get_spec
        prompt_profile = protocol_document["prompt_profile"]
        stamp.update({
            # The spec's own identity. A literal `@1` here would keep stamping
            # `@1` after the version a driver/preset/budget change is required
            # to increment had already moved, and the row would name a
            # configuration that did not produce it.
            "adapter_version": get_spec(agent_kind).qualified,
            "agent_system": agent_kind,
            "agent_version": _agent_module(
                "agents.publication")._agent_version_identity(
                    agent_kind, agent_projection["backend"]),
            "comparison_class": protocol_document["comparison_class"],
            "max_tokens": None,
            "model": getattr(args, "model"),
            "prompt_digest": prompt_profile["prompt_digest"][
                prompt_profile["arm_prompt_key"]],
            "sandboxed": True,
        })
        # Shared with the zero-provider-call probe: this is the actual row
        # projection, not a second mock spelling of the native budget.
        stamp.update(agentv2.agent_stamp_fields(
            agent_kind, protocol_document))
        secret_inputs = [agentv2.SECRET_CHANNEL]
    invocation = {
        "schema": ledger.RUN_INVOCATION_SCHEMA,
        "selection": selection,
        "effective_run_stamp": _publication_named_values(stamp),
        "adapter": {
            "kind": kind,
            "name": getattr(args, "adapter"),
            "public_configuration": _publication_named_values(
                public_configuration),
            "secret_inputs": secret_inputs,
            "files": files,
        },
        "resume": {
            "checkpoint_resume": True,
            "stale_running_suffix_adoption": True,
            "no_resume": False,
            "retry_failed": False,
        },
    }
    plan = {
        "schema": ledger.RUN_PLAN_SCHEMA,
        "campaign": campaign_ref,
        "campaign_agent_runtime": agent_runtime_ref,
        "release": release_ref,
        "boundary": boundary_ref,
        "profile": profile_ref,
        "protocol": protocol_ref,
        "worker_manifest_path": worker_manifest_path,
        "shard_index": shard,
        "shard_count": shard_count,
        "shard_rule": effective_shard_rule,
        "workset": {
            "item_count": len(selected_ids),
            "ordered_item_ids_digest": ledger.ordered_item_ids_digest(
                selected_ids),
        },
        "invocation": invocation,
        "invocation_digest": ledger.domain_digest(
            ledger.RUN_INVOCATION_SCHEMA, invocation),
        "digest": "0" * 64,
    }
    plan["digest"] = ledger.semantic_digest(plan)
    execution = {
        "attempt_id": campaign_document["attempt_id"],
        "runtime": runtime_reference,
    }
    if agent_kind is None:
        draft_probe = {
            "schema": ledger.CHECKPOINT_SCHEMA,
            "artifact_kind": "run_shard",
            "state": "draft",
            "execution": execution,
            "plan": plan,
            "result_prefix": {
                "path": result_path, "byte_length": 0, "row_count": 0,
                "file_sha256": ledger.raw_sha256(b""),
            },
            "reason": None,
            "digest": "0" * 64,
        }
        draft_probe["digest"] = ledger.semantic_digest(draft_probe)
        ledger.validate_checkpoint_schema(draft_probe)
    else:
        agentv2 = _agent_module("confined.result_ledger_v2")
        # Section 6's v2 checkpoint has no validation variant, so the draft
        # probe is built through the v2 builder, which closes its own schema.
        agentv2.build_checkpoint(
            execution=execution, plan=plan, state="draft",
            result_prefix={
                "path": result_path, "byte_length": 0, "row_count": 0,
                "file_sha256": ledger.raw_sha256(b"")},
            reason=None)
    context = ledger._verify_run_plan(reader, plan, runtime_context,
                                      agent_kind=agent_kind)
    if context.item_ids != selected_ids:
        raise ledger._refuse(
            "constructed publication workset does not self-replay")
    bundle_raw_by_path = dict(reader.raw_by_path)
    for target in recovered_feature_raw:
        del reader.raw_by_path[target]
    reader.confirm()
    return _PublicationRunPlan(
        execution=execution, plan=plan, runtime=runtime_context,
        context=context, selected_items=selected_rows,
        raw_by_path=bundle_raw_by_path,
        absent_paths=tuple(sorted(reader.absent_paths)),
        strip_document=copy.deepcopy(context.strip_document),
        result_path=result_path,
        checkpoint_path=checkpoint_path, receipt_path=receipt_path,
        worker_manifest_path=worker_manifest_path)


def _publication_file_entries(bundle: _PublicationRunPlan) \
        -> dict[tuple[str, str], dict]:
    return {
        (entry["role"], entry["logical_path"]): entry
        for entry in bundle.plan["invocation"]["adapter"]["files"]
    }


def _publication_bound_json(bundle: _PublicationRunPlan, entry: dict,
                            label: str):
    from . import result_ledger as ledger
    return ledger.loads_exact_json(
        bundle.raw_by_path[entry["path"]], label=label)


class _AggregateCapStopped(RuntimeError):
    """The current item was denied its next paid request by fd 6."""


def _build_publication_adapter(bundle: _PublicationRunPlan, args):
    """Build an admitted fixture that reads only the frozen in-memory bytes."""
    from .adapters import Adapter
    from . import result_ledger as ledger
    if bundle.context.agent_adapter is not None:
        return _agent_module("agents.publication")._AgentPublicationAdapter(
            bundle, args, secret=args._agent_publication_secret,
            launcher=getattr(args, "_agent_publication_launcher", None))
    entries = _publication_file_entries(bundle)
    adapter = bundle.plan["invocation"]["adapter"]
    kind = adapter["kind"]
    if kind == "empty":
        return Adapter("empty", lambda task: {"files": [], "metadata": {}})

    if kind == "gold":
        manifest_entry = entries[("release_gold_manifest",
                                  "gold/manifest.json")]
        manifest = _publication_bound_json(
            bundle, manifest_entry, "bound release gold manifest")
        records = {}
        for item_id in bundle.item_ids:
            logical = "gold/" + manifest[item_id]
            records[item_id] = _publication_bound_json(
                bundle, entries[("release_gold_record", logical)],
                "bound release gold record")
        source_texts = {
            logical: bundle.raw_by_path[entry["path"]].decode("utf-8")
            for (role, logical), entry in entries.items()
            if role == "gold_source"
        }

        def run_gold(task: dict) -> dict:
            gold = records.get(task.get("item_id"))
            if gold is None:
                return {"files": [],
                        "metadata": {"error": "no gold for item"}}
            output = [
                {"file_path": relative, "code": source_texts[relative]}
                for relative in gold["files"]
            ]
            if gold.get("di_fragment"):
                fragment = {"services": {}}
                for service_id, body in gold["di_fragment"].items():
                    value = {"class": body["class"]}
                    if body.get("arguments"):
                        value["arguments"] = body["arguments"]
                    if body.get("tags"):
                        value["tags"] = body["tags"]
                    fragment["services"][service_id] = value
                import yaml
                output.append({
                    "file_path": "behat_services.yml",
                    "code": yaml.safe_dump(fragment, sort_keys=False),
                })
            return {"files": output, "metadata": {"source": "gold"}}

        return Adapter("gold", run_gold, {"publication_plan":
                                           bundle.plan["digest"]})

    closures_entry = entries[("fixture_closures", "closures.json")]
    closures_value = _publication_bound_json(
        bundle, closures_entry, "bound fixture closures")
    closures = {row["item_id"]: row for row in closures_value}
    framework = bundle.context.profile.framework
    if kind == "stub":
        where: dict = {}
        if framework == "behave":
            from ..toolkit.stub_py import stub_solution
        elif framework == "cucumber_ruby":
            from ..toolkit.stub_rb import stub_solution
        else:
            from ..toolkit.stub import stub_solution
            from .repo import behat_project
            # WHERE a PHP stub context is written is per-project: its
            # namespace and directory have to fall inside the project's own
            # PSR-4 roots and inside the arm's removable prefix, or the stub
            # is a file the autoloader never loads.  The bundle's boundary is
            # the one already bound to this run; a boundary with no `behat:`
            # block is CoreShop's row, whose pair IS `stub.py`'s default.
            bp = behat_project(bundle.context.boundary)
            where = {"namespace": bp.stub_namespace, "dir_": bp.stub_dir}

        def run_stub(task: dict) -> dict:
            closure = closures.get(task.get("item_id"))
            if closure is None:
                return {"files": [], "metadata": {
                    "adapter_error": f"no closure for {task.get('item_id')}: "
                    "a stub cannot exclude retained steps without one"}}
            try:
                return stub_solution(task, closure, **where)
            except Exception as exc:                         # noqa: BLE001
                return {"files": [], "metadata": {
                    "adapter_error": f"{type(exc).__name__}: {exc}"}}

        return Adapter("stub", run_stub, {"publication_plan":
                                           bundle.plan["digest"]})

    if kind != "stripped_gold":
        raise ledger._refuse(
            f"publication adapter kind {kind!r} escaped admission")
    source_texts = {
        logical: bundle.raw_by_path[entry["path"]].decode("utf-8")
        for (role, logical), entry in entries.items()
        if role == "gold_source"
    }
    if framework == "behave":
        from ..toolkit.strip_py import StripRefused, stripped_solution
    elif framework == "cucumber_ruby":
        from ..toolkit.strip_rb import StripRefused, stripped_solution
    else:
        from ..toolkit.strip import StripRefused, stripped_solution
    gold_root = bundle.context.adapter_config["gold_root"]

    def run_stripped(task: dict) -> dict:
        item_id = task.get("item_id")
        closure = closures.get(item_id)
        if closure is None:
            return {"files": [], "metadata": {
                "adapter_error": f"no closure for {item_id}",
                "strip_refusal": True, "source": "stripped_gold",
                "stripped_gold": True, "item_id": item_id}}
        try:
            return stripped_solution(
                gold_root, closure, source_texts=source_texts)
        except StripRefused as exc:
            return {"files": [], "metadata": {
                "adapter_error": str(exc), "strip_refusal": True,
                "source": "stripped_gold", "stripped_gold": True,
                "item_id": item_id}}

    return Adapter("stripped-gold", run_stripped,
                   {"publication_plan": bundle.plan["digest"]})


def _publication_feature_texts(bundle: _PublicationRunPlan) -> dict[str, str]:
    return {
        logical: bundle.raw_by_path[entry["path"]].decode(
            "utf-8", errors="replace")
        for (role, logical), entry in _publication_file_entries(bundle).items()
        if role == "harness_feature"
    }


def _install_publication_harness_context(bundle: _PublicationRunPlan,
                                         args) -> None:
    boundary = copy.deepcopy(bundle.context.boundary)
    boundary.repo_root = bundle.runtime.worker.workspace
    strip_document = copy.deepcopy(bundle.strip_document)
    bundle.strip_document = strip_document
    manifest = _publication_manifest_object(
        strip_document, bundle.runtime.worker.workspace,
        strip_document["gold_root"])
    args._publication_harness_context = {
        "boundary": boundary,
        "manifest": manifest,
        "framework": bundle.context.profile.framework,
        "raw_by_path": bundle.raw_by_path,
        "artifacts_root": bundle.runtime.worker.artifacts_root,
        "autowirable_types_present": bool(
            bundle.context.adapter_config.get(
                "harness_autowirable_types_present", False)),
    }


def _publication_bundle_from_documents(execution: dict, plan: dict, *,
                                       agent_kind=None) \
        -> _PublicationRunPlan:
    """Rehydrate a frozen plan for lifecycle tests and checkpoint replay."""
    from . import result_ledger as ledger
    reader = ledger._LiveReader()
    runtime = ledger._verify_runtime(reader, execution["runtime"])
    context = ledger._verify_run_plan(
        reader, plan, runtime, agent_kind=agent_kind)
    reader.confirm()
    result_path = runtime.worker.out_path
    return _PublicationRunPlan(
        execution=copy.deepcopy(execution), plan=copy.deepcopy(plan),
        runtime=runtime, context=context,
        selected_items=copy.deepcopy(context.selected_rows),
        raw_by_path=dict(reader.raw_by_path),
        absent_paths=tuple(sorted(reader.absent_paths)),
        strip_document=copy.deepcopy(context.strip_document),
        result_path=result_path,
        checkpoint_path=result_path + ledger.CHECKPOINT_SUFFIX,
        receipt_path=result_path + ledger.RECEIPT_SUFFIX,
        worker_manifest_path=plan["worker_manifest_path"])


def _publication_document_bytes(document: dict) -> bytes:
    try:
        return (json.dumps(
            document, indent=1, sort_keys=True, ensure_ascii=True,
            allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        from . import result_ledger as ledger
        raise ledger._refuse(
            f"publication document is not exact JSON encodable: {exc}") \
            from exc


def _publication_result_binding(path: str, raw: bytes,
                                row_count: int) -> dict:
    from . import result_ledger as ledger
    return {
        "path": path,
        "byte_length": len(raw),
        "row_count": row_count,
        "file_sha256": ledger.raw_sha256(raw),
    }


def _publication_checkpoint_document(
        bundle: _PublicationRunPlan, state: str, result_prefix: dict,
        reason: Optional[str]) -> dict:
    from . import result_ledger as ledger
    if bundle.context.agent_adapter is not None:
        agent = _agent_module("confined.result_ledger_v2")
        return agent.build_checkpoint(
            execution=bundle.execution, plan=bundle.plan, state=state,
            result_prefix=result_prefix, reason=reason)
    document = {
        "schema": ledger.CHECKPOINT_SCHEMA,
        "artifact_kind": "run_shard",
        "state": state,
        "execution": bundle.execution,
        "plan": bundle.plan,
        "result_prefix": result_prefix,
        "reason": reason,
        "digest": "0" * 64,
    }
    document["digest"] = ledger.semantic_digest(document)
    ledger.validate_checkpoint_schema(document)
    return document


def _publication_reason(value: BaseException | str) -> str:
    text = str(value).replace("\x00", "?").strip()
    return (text or type(value).__name__)[:4096]


def _publication_substrate_stop(item_id: str, report: Mapping) -> dict:
    """Keep the attributed substrate report in the terminal diagnostic."""
    violation = {
        key: list(report.get(key) or ())
        for key in ("changed", "missing", "added")
    }
    reason = (
        f"substrate violation after {item_id}: "
        + json.dumps(
            violation, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False)
    )
    return {
        "kind": "substrate_violation",
        "terminal_reason": reason,
        "report": violation,
    }


class _PublicationAppendUncertain(RuntimeError):
    """Result bytes may be ahead; only stale-running adoption may decide."""


class _PublicationSubstrateTransitionUncertain(RuntimeError):
    """A durable substrate prefix must not be demoted after transition doubt."""


class _PublicationInjectedCrash(BaseException):
    """Deterministic hard-crash analogue; no cleanup transition may run."""


def _publication_fault(fault: Optional[Callable[[str], None]],
                       event: str) -> None:
    if fault is None:
        return
    try:
        fault(event)
    except BaseException as exc:
        raise _PublicationInjectedCrash(event) from exc


class _RunShardLedger:
    """Durable run-shard checkpoint/result state under a result lock."""

    _TRANSITIONS = {
        "draft": frozenset({"running", "failed"}),
        "running": frozenset({"running", "interrupted", "failed"}),
        "interrupted": frozenset({"running"}),
        "failed": frozenset(),
    }

    def __init__(
            self, bundle: _PublicationRunPlan, *,
            fault: Optional[Callable[[str], None]] = None,
            lock_confirm: Optional[Callable[[], None]] = None):
        self.bundle = bundle
        self.fault = fault
        self.lock_confirm = lock_confirm
        self.document: Optional[dict] = None
        self.pending_adoption: Optional[dict] = None
        self.created_draft = False

    def _event(self, event: str) -> None:
        _publication_fault(self.fault, event)

    def _confirm_lock(self) -> None:
        if self.lock_confirm is not None:
            self.lock_confirm()

    def _durably_confirm_result_binding(self, expected: dict) -> None:
        """Fsync and re-read the exact result bytes a checkpoint will claim."""
        from . import result_ledger as ledger
        if expected.get("path") != self.bundle.result_path:
            raise ledger._refuse(
                "checkpoint replacement claims another result path")
        raw = ledger.read_trusted_bytes(
            self.bundle.result_path, label="publication result")
        rows = ledger._json_lines(raw, "publication result")
        ledger._verify_row_sequence(
            rows, self.bundle.item_ids, stamp=self.bundle.stamp,
            allow_prefix=True)
        binding = _publication_result_binding(
            self.bundle.result_path, raw, len(rows))
        if binding != expected:
            raise ledger._refuse(
                "publication result changed before checkpoint replacement")
        before = ledger._trusted_leaf(
            self.bundle.result_path, "publication result")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_CLOEXEC", 0)
        fd = -1
        try:
            fd = os.open(self.bundle.result_path, flags)
            opened = os.fstat(fd)
            if ledger._stat_identity(before) != ledger._stat_identity(opened):
                raise ledger._refuse(
                    "publication result changed before checkpoint fsync")
            os.fsync(fd)
            synced = os.fstat(fd)
            if ledger._stat_identity(opened) \
                    != ledger._stat_identity(synced):
                raise ledger._refuse(
                    "publication result changed during checkpoint fsync")
        except OSError as exc:
            raise ledger._refuse(
                f"cannot fsync publication result before checkpoint: {exc}") \
                from exc
        finally:
            if fd >= 0:
                os.close(fd)
        if ledger.read_trusted_bytes(
                self.bundle.result_path, label="publication result") != raw:
            raise ledger._refuse(
                "publication result changed after checkpoint fsync")

    def _write_checkpoint(
            self, document: dict, *, create: bool,
            replace_guard: Optional[Callable[[], None]] = None) -> None:
        from . import result_ledger as ledger
        payload = _publication_document_bytes(document)
        self._confirm_lock()
        if create:
            if replace_guard is not None:
                raise ledger._refuse(
                    "a checkpoint creation cannot carry a replacement guard")
            def create_fault(event: str) -> None:
                if self.fault is not None:
                    self.fault(event)
                self._confirm_lock()
            ledger.durable_create_bytes_no_clobber(
                self.bundle.checkpoint_path, payload,
                label="result checkpoint", fault=create_fault)
        else:
            def guarded_fault(event: str) -> None:
                if self.fault is not None:
                    self.fault(event)
                self._confirm_lock()
                # The staged checkpoint is durable but not yet visible.
                # Recheck and fsync the exact result after any deterministic
                # fault/TOCTOU seam and immediately before replacement.
                if event == "result checkpoint:stage_fsync":
                    self._durably_confirm_result_binding(
                        document["result_prefix"])
                    if replace_guard is not None:
                        replace_guard()
            ledger.durable_replace_bytes(
                self.bundle.checkpoint_path, payload,
                label="result checkpoint", fault=guarded_fault)
        self._confirm_lock()
        self.document = document

    def _load_checkpoint(self, *, verify_plan_inputs: bool = True) -> dict:
        from . import result_ledger as ledger
        raw = ledger.read_trusted_bytes(
            self.bundle.checkpoint_path, label="result checkpoint")
        document = ledger.loads_exact_json(raw, label="result checkpoint")
        if not isinstance(document, dict):
            raise ledger._refuse("result checkpoint is not an object")
        # A fixture checkpoint decides itself; only another schema asks for
        # the agent producer, which refuses by name when it is not shipped.
        if document.get("schema") == ledger.CHECKPOINT_SCHEMA:
            ledger.validate_checkpoint_schema(document)
        else:
            _agent_module("confined.result_ledger_v2").validate_checkpoint_schema(
                document)
        if document.get("digest") != ledger.semantic_digest(document):
            raise ledger._refuse("result checkpoint digest does not recompute")
        # The I1 verifier closes runtime/plan/result grammar and all joins,
        # including a possible running suffix. It never contacts Docker.
        # The one false caller is the authenticated substrate-resume path:
        # its current workspace may differ at a selected feature left dirty
        # by the retained violation, so that caller has already rebuilt and
        # self-verified the exact same plan from the immutable worker seed.
        if verify_plan_inputs:
            ledger.verify_checkpoint(self.bundle.checkpoint_path)
        if document["execution"] != self.bundle.execution:
            raise ledger._refuse(
                "checkpoint execution differs from the reconstructed "
                "publication request")
        if document["plan"] != self.bundle.plan:
            raise ledger._refuse(
                "checkpoint plan differs from the reconstructed publication "
                "request")
        if document["result_prefix"]["path"] != self.bundle.result_path:
            raise ledger._refuse(
                "checkpoint result path differs from authenticated WorkerSpec")
        self.document = document
        return document

    def _ensure_empty_result(self) -> None:
        from . import result_ledger as ledger
        if os.path.lexists(self.bundle.result_path):
            raw = ledger.read_trusted_bytes(
                self.bundle.result_path, label="publication result")
            if raw != b"":
                raise ledger._refuse(
                    "draft publication result is not exact empty bytes")
            return
        self._event("initial:before_empty_result")
        self._confirm_lock()
        def empty_result_fault(event: str) -> None:
            if self.fault is not None:
                self.fault(event)
            self._confirm_lock()
        ledger.durable_create_bytes_no_clobber(
            self.bundle.result_path, b"", label="publication empty result",
            fault=empty_result_fault)
        self._confirm_lock()
        self._event("initial:after_empty_result")

    def inspect_existing(
            self, *, verify_plan_inputs: bool = True) -> Optional[dict]:
        """Validate retained checkpoint/result state without writing it."""
        from . import result_ledger as ledger
        checkpoint_exists = os.path.lexists(self.bundle.checkpoint_path)
        result_exists = os.path.lexists(self.bundle.result_path)
        manifest_exists = os.path.lexists(self.bundle.worker_manifest_path)
        if not checkpoint_exists:
            if result_exists:
                raise ledger._refuse(
                    "existing result without checkpoint is unbound diagnostic "
                    "evidence and cannot be upgraded")
            if manifest_exists:
                raise ledger._refuse(
                    "existing WorkerManifest without checkpoint burns this "
                    "publication path")
            return None

        document = self._load_checkpoint(
            verify_plan_inputs=verify_plan_inputs)
        state = document["state"]
        if state == "failed":
            # Terminal, and therefore an ANSWER rather than a refusal.  This
            # method is the read: `inspect_agent_publication_v3` classifies a
            # shard through it, and one shard's terminal failure must not
            # abort the coordinator's whole-descriptor preparation before it
            # can reuse the shards that did seal.  The terminal rule itself is
            # unchanged and is enforced where it belongs, on the writer:
            # `resolve` below refuses with the same words, `transition` has no
            # edge out of "failed", and `append`/`final_result` require a
            # running checkpoint.  Returning here also keeps this case's
            # validation depth exactly what it was -- the raise it replaces
            # skipped the result-prefix checks below in the same way.
            return document
        if state == "draft":
            if result_exists:
                raw = ledger.read_trusted_bytes(
                    self.bundle.result_path, label="publication result")
                if raw != b"":
                    raise ledger._refuse(
                        "draft publication result is not exact empty bytes")
            if manifest_exists:
                raise ledger._refuse(
                    "draft checkpoint cannot have a WorkerManifest")
            return document

        raw = ledger.read_trusted_bytes(
            self.bundle.result_path, label="publication result")
        prefix = document["result_prefix"]
        if len(raw) < prefix["byte_length"]:
            raise ledger._refuse(
                "publication result is shorter than committed checkpoint")
        committed = raw[:prefix["byte_length"]]
        if ledger.raw_sha256(committed) != prefix["file_sha256"]:
            raise ledger._refuse(
                "publication result committed prefix drifted")
        suffix = raw[prefix["byte_length"]:]
        if state != "running" and suffix:
            raise ledger._refuse(
                f"publication result has a suffix from {state} state")
        if state == "running" and suffix:
            rows = ledger._json_lines(raw, "stale running result")
            ledger._verify_row_sequence(
                rows, self.bundle.item_ids, stamp=self.bundle.stamp,
                allow_prefix=True)
            self.pending_adoption = _publication_result_binding(
                self.bundle.result_path, raw, len(rows))
        if manifest_exists \
                and (self.pending_adoption or document["result_prefix"])[
                    "row_count"] \
                != len(self.bundle.item_ids):
            raise ledger._refuse(
                "WorkerManifest exists before the frozen workset is complete")
        return document

    def resolve(self) -> dict:
        """Create draft or recover one existing exact checkpoint."""
        from . import result_ledger as ledger
        self.created_draft = False
        document = self.inspect_existing()
        if document is not None and document["state"] == "failed":
            # The writer boundary for the terminal rule that `inspect_existing`
            # now classifies instead of raising.  Every publication run reaches
            # this, so a terminally failed path is still unwritable and still
            # says so in the same words.
            raise ledger._refuse(
                "failed publication checkpoint is terminal; retry with a new "
                "attempt and output path")
        if document is None:
            empty = _publication_result_binding(
                self.bundle.result_path, b"", 0)
            draft = _publication_checkpoint_document(
                self.bundle, "draft", empty, None)
            self._event("initial:before_draft")
            self._write_checkpoint(draft, create=True)
            self.created_draft = True
            self._event("initial:after_draft")
            self._ensure_empty_result()
            return draft
        if document["state"] == "draft":
            self._ensure_empty_result()
        return document

    def _durable_adoption_binding(self) -> dict:
        """Revalidate and fsync the exact suffix about to be checkpointed."""
        from . import result_ledger as ledger
        if self.document is None or self.document["state"] != "running":
            raise ledger._refuse(
                "suffix adoption requires the stale running checkpoint")
        if os.path.lexists(self.bundle.receipt_path):
            raise ledger._refuse(
                "a stale running suffix cannot be adopted beside a receipt")
        raw = ledger.read_trusted_bytes(
            self.bundle.result_path, label="stale running result")
        prefix = self.document["result_prefix"]
        if len(raw) <= prefix["byte_length"]:
            raise ledger._refuse(
                "pending stale-running suffix disappeared before adoption")
        committed = raw[:prefix["byte_length"]]
        if ledger.raw_sha256(committed) != prefix["file_sha256"]:
            raise ledger._refuse(
                "publication result committed prefix drifted before adoption")
        rows = ledger._json_lines(raw, "stale running result")
        ledger._verify_row_sequence(
            rows, self.bundle.item_ids, stamp=self.bundle.stamp,
            allow_prefix=True)

        before = ledger._trusted_leaf(
            self.bundle.result_path, "stale running result")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_CLOEXEC", 0)
        fd = -1
        try:
            self._confirm_lock()
            fd = os.open(self.bundle.result_path, flags)
            opened = os.fstat(fd)
            if ledger._stat_identity(before) != ledger._stat_identity(opened):
                raise ledger._refuse(
                    "stale running result changed before adoption fsync")
            os.fsync(fd)
            synced = os.fstat(fd)
            if ledger._stat_identity(opened) \
                    != ledger._stat_identity(synced):
                raise ledger._refuse(
                    "stale running result changed during adoption fsync")
        except OSError as exc:
            raise ledger._refuse(
                f"cannot fsync stale running result before adoption: {exc}") \
                from exc
        finally:
            if fd >= 0:
                os.close(fd)
        confirmed = ledger.read_trusted_bytes(
            self.bundle.result_path, label="stale running result")
        if confirmed != raw:
            raise ledger._refuse(
                "stale running result changed after adoption fsync")
        return _publication_result_binding(
            self.bundle.result_path, confirmed, len(rows))

    def adopt_pending_suffix(self) -> None:
        """Advance over a prevalidated suffix only after live revalidation."""
        from . import result_ledger as ledger
        if self.pending_adoption is None:
            return
        if self.document is None or self.document["state"] != "running":
            raise ledger._refuse(
                "suffix adoption requires the stale running checkpoint")
        adoption = self._durable_adoption_binding()
        self._event("adoption:after_result_fsync")
        adoption = self._durable_adoption_binding()
        advanced = _publication_checkpoint_document(
            self.bundle, "running", adoption, None)
        def guard_adoption() -> None:
            if self._durable_adoption_binding() != adoption:
                raise ledger._refuse(
                    "stale running result changed before checkpoint commit")
        self._event("adoption:before_checkpoint")
        self._write_checkpoint(
            advanced, create=False,
            replace_guard=guard_adoption)
        self._event("adoption:after_checkpoint")
        self.pending_adoption = None

    def _synchronized_result(self) -> bytes:
        from . import result_ledger as ledger
        if self.document is None:
            raise ledger._refuse("publication checkpoint is not resolved")
        raw = ledger.read_trusted_bytes(
            self.bundle.result_path, label="publication result")
        prefix = self.document["result_prefix"]
        if len(raw) != prefix["byte_length"] \
                or ledger.raw_sha256(raw) != prefix["file_sha256"]:
            raise ledger._refuse(
                "publication result and checkpoint are not synchronized")
        rows = ledger._json_lines(raw, "publication result")
        if len(rows) != prefix["row_count"]:
            raise ledger._refuse(
                "publication result row count differs from checkpoint")
        ledger._verify_row_sequence(
            rows, self.bundle.item_ids, stamp=self.bundle.stamp,
            allow_prefix=True)
        return raw

    def transition(self, state: str, *, reason: Optional[str] = None) -> None:
        from . import result_ledger as ledger
        if self.document is None:
            raise ledger._refuse("publication checkpoint is not resolved")
        current = self.document["state"]
        if state not in self._TRANSITIONS.get(current, frozenset()):
            raise ledger._refuse(
                f"invalid publication transition {current} -> {state}")
        raw = self._synchronized_result()
        if state in {"draft", "running"}:
            if reason is not None:
                raise ledger._refuse(
                    f"publication state {state} cannot carry a reason")
        elif not isinstance(reason, str) or not reason.strip():
            raise ledger._refuse(
                f"publication state {state} requires a nonempty reason")
        prefix = _publication_result_binding(
            self.bundle.result_path, raw,
            self.document["result_prefix"]["row_count"])
        next_document = _publication_checkpoint_document(
            self.bundle, state, prefix, reason)
        self._event(f"transition:{current}:before:{state}")
        self._write_checkpoint(next_document, create=False)
        self._event(f"transition:{current}:after:{state}")

    def append(self, row: dict) -> None:
        from . import result_ledger as ledger
        if self.document is None or self.document["state"] != "running":
            raise ledger._refuse(
                "publication append requires a running checkpoint")
        raw = self._synchronized_result()
        ordinal = self.document["result_prefix"]["row_count"]
        if ordinal >= len(self.bundle.item_ids):
            raise ledger._refuse(
                "publication append would extend the frozen workset")
        ledger._verify_row_sequence(
            [row], [self.bundle.item_ids[ordinal]], stamp=self.bundle.stamp)
        try:
            payload = (json.dumps(
                row, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ledger._refuse(
                f"publication row is not finite JSON: {exc}") from exc
        before = ledger._trusted_leaf(
            self.bundle.result_path, "publication result")
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_CLOEXEC", 0)
        fd = -1
        write_started = False
        try:
            fd = os.open(self.bundle.result_path, flags)
            opened = os.fstat(fd)
            if ledger._stat_identity(before) != ledger._stat_identity(opened) \
                    or opened.st_size != len(raw):
                raise ledger._refuse(
                    "publication result changed before append")
            self._event("append:before_write")
            self._confirm_lock()
            write_started = True
            ledger._write_all(fd, payload, "publication result row")
            self._event("append:after_write")
            os.fsync(fd)
            self._event("append:after_result_fsync")
            self._confirm_lock()
        except BaseException as exc:
            if write_started:
                raise _PublicationAppendUncertain(str(exc)) from exc
            raise
        finally:
            if fd >= 0:
                os.close(fd)
        full = ledger.read_trusted_bytes(
            self.bundle.result_path, label="publication result")
        if full != raw + payload:
            raise _PublicationAppendUncertain(
                "publication result bytes differ after durable append")
        advanced = _publication_result_binding(
            self.bundle.result_path, full, ordinal + 1)
        next_document = _publication_checkpoint_document(
            self.bundle, "running", advanced, None)
        try:
            self._event("append:before_checkpoint")
            self._write_checkpoint(next_document, create=False)
            self._event("append:after_checkpoint")
        except BaseException as exc:
            # Result is intentionally ahead. Only the next stale-running
            # resolver may adopt it; never demote or truncate here.
            raise _PublicationAppendUncertain(str(exc)) from exc

    def final_result(self) -> tuple[dict, bytes, list[dict]]:
        from . import result_ledger as ledger
        if self.document is None or self.document["state"] != "running":
            state = None if self.document is None else self.document["state"]
            raise ledger._refuse(
                f"publication sealing requires running state, not {state!r}")
        raw = self._synchronized_result()
        rows = ledger._json_lines(raw, "complete publication result")
        ledger._verify_row_sequence(
            rows, self.bundle.item_ids, stamp=self.bundle.stamp)
        if len(rows) != len(self.bundle.item_ids):
            raise ledger._refuse(
                "cannot seal an incomplete frozen workset")
        return (_publication_result_binding(
            self.bundle.result_path, raw, len(rows)), raw, rows)


def _publication_prior_substrate_stop(
        state: _RunShardLedger) -> Optional[dict]:
    """Recover an attributed stop across interruption or append crash."""
    if state.document is None \
            or state.document["result_prefix"]["row_count"] == 0:
        return None
    from . import result_ledger as ledger
    rows = ledger._json_lines(
        state._synchronized_result(), "publication result")
    previous = rows[-1]
    if previous.get("outcome") != "substrate_violation":
        return None
    return _publication_substrate_stop(
        previous["item_id"], previous["substrate_violation"])


def _publication_interrupt_for_stop(
        state: _RunShardLedger, stop: Mapping[str, object]) -> None:
    """Persist the required stop or leave stale-running recovery authority."""
    try:
        state.transition("interrupted", reason=stop["terminal_reason"])
    except BaseException as exc:
        # The replacement may be either absent or already visible while the
        # in-memory document is still running. In both cases a generic failed
        # transition would destroy the only recoverable diagnostic prefix.
        raise _PublicationSubstrateTransitionUncertain(
            "substrate interruption checkpoint replacement is uncertain") \
            from exc


def _recorded_publication_harness(result_path: str) -> Optional[dict]:
    """The harness identity a bound checkpoint recorded, or None."""
    from . import result_ledger as ledger

    checkpoint_path = result_path + ledger.CHECKPOINT_SUFFIX
    if not os.path.lexists(checkpoint_path):
        return None
    document = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            checkpoint_path, label="publication resume checkpoint"),
        label="publication resume checkpoint")
    if not isinstance(document, dict):
        return None
    # A fixture checkpoint decides itself; only another schema asks for the
    # agent producer, which refuses by name when it is not shipped.
    if document.get("schema") == ledger.CHECKPOINT_SCHEMA:
        ledger.validate_checkpoint_schema(document)
    else:
        agent = _agent_module("confined.result_ledger_v2")
        if document.get("schema") != agent.CHECKPOINT_SCHEMA:
            return None
        agent.validate_checkpoint_schema(document)
    if document.get("digest") != ledger.semantic_digest(document):
        raise ledger._refuse(
            "publication resume checkpoint digest does not recompute")
    if document["result_prefix"]["path"] != result_path:
        return None
    return copy.deepcopy(
        document["execution"]["runtime"]["identity"]["harness"])


def _publication_substrate_resume_candidate(
        result_path: str) -> Optional[dict]:
    """Discover a retained substrate suffix without trusting it to mutate.

    This is deliberately only a discovery pass. The caller still rebuilds
    and self-verifies the complete current request, exact-compares that plan
    with the checkpoint, and authenticates any agent result chain before it
    may prefer the retained diagnostic or change checkpoint state.
    """
    from . import result_ledger as ledger

    checkpoint_path = result_path + ledger.CHECKPOINT_SUFFIX
    if not os.path.lexists(checkpoint_path) \
            or not os.path.lexists(result_path):
        return None
    checkpoint = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            checkpoint_path, label="substrate resume checkpoint"),
        label="substrate resume checkpoint")
    if not isinstance(checkpoint, dict):
        return None
    # A fixture checkpoint decides itself; only another schema asks for the
    # agent producer, which refuses by name when it is not shipped.
    if checkpoint.get("schema") == ledger.CHECKPOINT_SCHEMA:
        ledger.validate_checkpoint_schema(checkpoint)
    else:
        agent = _agent_module("confined.result_ledger_v2")
        if checkpoint.get("schema") != agent.CHECKPOINT_SCHEMA:
            return None
        agent.validate_checkpoint_schema(checkpoint)
    if checkpoint.get("digest") != ledger.semantic_digest(checkpoint):
        raise ledger._refuse(
            "substrate resume checkpoint digest does not recompute")
    if checkpoint["state"] not in {"running", "interrupted"} \
            or checkpoint["result_prefix"]["path"] != result_path:
        return None
    result_raw = ledger.read_trusted_bytes(
        result_path, label="substrate resume result")
    rows = ledger._json_lines(result_raw, "substrate resume result")
    if not rows or rows[-1].get("outcome") != "substrate_violation":
        return None
    report = rows[-1].get("substrate_violation")
    if not isinstance(report, dict):
        return None
    for name in ("changed", "missing", "added"):
        paths = report.get(name)
        if not isinstance(paths, list) \
                or any(not isinstance(path, str) for path in paths):
            return None

    features: dict[str, dict] = {}
    entries = checkpoint["plan"]["invocation"]["adapter"]["files"]
    for entry in entries:
        if entry.get("role") != "harness_feature":
            continue
        logical = ledger._safe_relative(
            entry.get("logical_path"),
            "checkpoint harness feature logical path")
        if logical in features:
            raise ledger._refuse(
                "substrate resume checkpoint repeats harness feature "
                f"{logical!r}")
        features[logical] = dict(entry)
    return {"checkpoint": checkpoint, "features": features,
            "report": {name: list(report[name])
                       for name in ("changed", "missing", "added")}}


def _publication_bound_substrate_stop(
        bundle: _PublicationRunPlan, secret: bytes, *, agent_mode: bool, args,
        live_validator: Callable[[], dict],
        lock_confirm: Callable[[], None]) -> Optional[dict]:
    """Authenticate a retained row before preferring its diagnostic."""
    from . import result_ledger as ledger

    result_path = bundle.result_path
    checkpoint_path = bundle.checkpoint_path
    if not os.path.lexists(checkpoint_path):
        return None
    state = _RunShardLedger(bundle, lock_confirm=lock_confirm)
    document = state.inspect_existing(verify_plan_inputs=False)
    if document is None \
            or document["state"] not in {"running", "interrupted"}:
        return None
    result_raw = ledger.read_trusted_bytes(
        result_path, label="substrate resume result")
    rows = ledger._json_lines(result_raw, "substrate resume result")
    binding = state.pending_adoption or document["result_prefix"]
    if len(rows) != binding["row_count"]:
        raise ledger._refuse(
            "substrate resume result row count differs from checkpoint")
    ledger._verify_row_sequence(
        rows, bundle.item_ids, stamp=bundle.stamp, allow_prefix=True)
    if not rows or rows[-1].get("outcome") != "substrate_violation":
        return None

    if agent_mode:
        agent = _agent_module("confined.result_ledger_v2")
        publication = _agent_module("agents.publication")

        def verify_chain(paths, item_index):
            chain = publication._verify_publication_agent_chain(
                bundle, paths, item_index, secret)
            if not ledger._same_json_value(chain["row"], rows[item_index]):
                raise ledger._refuse(
                    "substrate resume result differs from its agent evidence "
                    f"chain at row {item_index}")
            return chain["row_raw"]

        resumed = agent.resume_workset(
            result_path=result_path, item_ids=bundle.item_ids,
            result_raw=result_raw, verify_chain=verify_chain)
        if resumed["verified_rows"] != len(rows) \
                or resumed["pending_row"] is not None:
            raise ledger._refuse(
                "substrate resume has a pending agent chain beyond its "
                "durable result rows")
    stop = _publication_substrate_stop(
        rows[-1]["item_id"], rows[-1]["substrate_violation"])
    if state.pending_adoption is not None:
        # Plan equality and the full row chain are now authenticated.  Make
        # the recovered bundle authoritative for the production live-worker
        # callback immediately before it can authorize suffix adoption.
        args._publication_run_plan = bundle
        args._publication_protected_paths = publication_protected_paths(
            bundle)
        _publication_live_revalidate(bundle, live_validator)
        state.adopt_pending_suffix()
    if state.document["state"] == "running":
        _publication_interrupt_for_stop(state, stop)
    return stop


def _publication_live_revalidate(
        bundle: _PublicationRunPlan, live_validator: Callable[[], dict]) \
        -> dict:
    """Run the existing complete live gate and compare its selected identity."""
    from . import result_ledger as ledger
    from . import worker
    reader = ledger._LiveReader()
    # The frozen plan's recorded harness is the identity; the version is
    # enforced by the live gate and `publication_runtime_reference`, drift
    # of the commit/source pair is disclosed (section 16).
    ledger.disclose_harness_drift(
        bundle.runtime.harness, ledger._stable_harness_identity(reader))
    live = live_validator()
    if isinstance(live, dict) and "publication_runtime_reference" in live:
        # Source-only test seam. Production's CLI callback never returns this
        # key; it returns validate_live_worker_runtime's complete pool result.
        reference = live["publication_runtime_reference"]
    else:
        reference = worker.publication_runtime_reference(
            live, bundle.runtime.harness)
        pool_specs = live.get("pool_specs") if isinstance(live, dict) else None
        if pool_specs is None or len(pool_specs) \
                != bundle.plan["shard_count"]:
            raise ledger._refuse(
                "live runtime validation did not return the complete pool")
    if reference != bundle.execution["runtime"]:
        raise ledger._refuse(
            "live runtime identity differs from frozen execution identity")
    reader.confirm()
    return live


def publication_protected_paths(bundle: _PublicationRunPlan) -> tuple[str, ...]:
    """Paths one publication child protects during its live preflight."""
    protected = [
        bundle.checkpoint_path, bundle.receipt_path,
        publication_lock_path(bundle.result_path),
        bundle.worker_manifest_path,
        bundle.plan["campaign"]["path"],
        bundle.plan["campaign_agent_runtime"]["path"],
        bundle.plan["release"]["path"],
        bundle.plan["boundary"]["path"],
        bundle.plan["profile"]["path"],
    ]
    if bundle.plan["protocol"] is not None:
        protected.append(bundle.plan["protocol"]["path"])
    protected.extend(
        entry["path"]
        for entry in bundle.plan["invocation"]["adapter"]["files"]
        if entry["role"] != "harness_feature")
    return tuple(dict.fromkeys(protected))


def _publication_repro_check(harness: Harness, adapter,
                             bundle: _PublicationRunPlan, rows: list[dict],
                             args, feature_texts: Mapping[str, str]) -> dict:
    count = bundle.stamp["repro_check_count"]
    if count <= 0:
        return {"checked": 0, "skipped": True}
    outcomes = {row["item_id"]: row.get("outcome") for row in rows}
    sample = [item for item in bundle.selected_items
              if item["item_id"] in outcomes][:count]
    drift = []
    for item in sample:
        relative = item["provenance"]["file_path"]
        record = run_one(
            harness, adapter, item, coverage=bool(args.coverage),
            timeout=args.timeout, repeats=args.repeats,
            feature_text=feature_texts[relative])
        if record["outcome"] != outcomes[item["item_id"]]:
            drift.append({
                "item_id": item["item_id"],
                "first": outcomes[item["item_id"]],
                "second": record["outcome"],
            })
    return {"checked": len(sample), "drift": drift,
            "reproducible": not drift}


def _publication_verify_manifest(
        bundle: _PublicationRunPlan, result: dict) -> tuple[bytes, dict]:
    from . import result_ledger as ledger
    reader = ledger._LiveReader()
    raw = reader.read(
        bundle.worker_manifest_path, "publication WorkerManifest")
    reference = {
        "path": bundle.worker_manifest_path,
        "file_sha256": ledger.raw_sha256(raw),
    }
    ledger._verify_worker_manifest(
        reader, reference, bundle.plan, result, bundle.runtime,
        bundle.context)
    reader.confirm()
    return raw, reference


def _publication_worker_manifest(
        bundle: _PublicationRunPlan, *, started_at: str, finished_at: str,
        fault: Optional[Callable[[str], None]]) -> dict:
    from . import campaign
    from . import result_ledger as ledger
    if not os.path.lexists(bundle.worker_manifest_path):
        record = campaign.WorkerManifest(
            shard=bundle.runtime.worker.index,
            workspace=bundle.runtime.worker.workspace,
            container=bundle.runtime.worker.container,
            schema=bundle.runtime.worker.schema,
            credential=bundle.runtime.worker.credential,
            out_path=bundle.result_path,
            artifacts_root=bundle.runtime.worker.artifacts_root,
            started_at=started_at,
            finished_at=finished_at,
            campaign_digest=bundle.plan["campaign"]["campaign_digest"])
        _publication_fault(fault, "finalization:before_worker_manifest")
        campaign.write_worker_manifest(
            record, bundle.context.campaign, bundle.worker_manifest_path,
            durable_no_clobber=True)
        _publication_fault(fault, "finalization:after_worker_manifest")
    _raw, reference = _publication_verify_manifest(
        bundle, _publication_result_binding(
            bundle.result_path,
            ledger.read_trusted_bytes(
                bundle.result_path, label="publication result"),
            len(bundle.item_ids)))
    return reference


def _publication_seal(
        bundle: _PublicationRunPlan, ledger_state: _RunShardLedger,
        *, started_at: str, finished_at: str,
        live_validator: Callable[[], dict],
        fault: Optional[Callable[[str], None]],
        lock_confirm: Optional[Callable[[], None]] = None) -> dict:
    from . import result_ledger as ledger
    if bundle.context.agent_adapter is not None:
        return _agent_module("agents.publication")._publication_agent_seal(
            bundle, ledger_state, started_at=started_at,
            finished_at=finished_at, live_validator=live_validator,
            secret=getattr(bundle, "_agent_secret", b""), fault=fault,
            lock_confirm=lock_confirm)
    if lock_confirm is not None:
        lock_confirm()
    result, _raw, _rows = ledger_state.final_result()
    worker_manifest = _publication_worker_manifest(
        bundle, started_at=started_at, finished_at=finished_at, fault=fault)
    if lock_confirm is not None:
        lock_confirm()
    _publication_fault(fault, "finalization:before_live_revalidation")
    _publication_live_revalidate(bundle, live_validator)
    _publication_fault(fault, "finalization:after_live_revalidation")
    receipt = {
        "schema": ledger.RECEIPT_SCHEMA,
        "artifact_kind": "run_shard",
        "execution": bundle.execution,
        "plan": bundle.plan,
        "result": result,
        "worker_manifest": worker_manifest,
        "digest": "0" * 64,
    }
    receipt["digest"] = ledger.semantic_digest(receipt)
    ledger.validate_receipt_schema(receipt)
    _publication_fault(fault, "finalization:before_receipt_selfverify")
    ledger.verify_receipt_document(receipt, bundle.receipt_path)
    _publication_fault(fault, "finalization:after_receipt_selfverify")
    payload = _publication_document_bytes(receipt)
    _publication_fault(fault, "finalization:before_receipt_create")
    # Close a deterministic mutation window between construction and commit.
    ledger.verify_receipt_document(receipt, bundle.receipt_path)
    if lock_confirm is not None:
        lock_confirm()
    def durable_fault(event: str) -> None:
        _publication_fault(fault, event)
        if event == "result receipt:stage_fsync" \
                and lock_confirm is not None:
            lock_confirm()
    ledger.durable_create_bytes_no_clobber(
        bundle.receipt_path, payload, label="result receipt",
        fault=durable_fault)
    _publication_fault(fault, "finalization:after_receipt_create")
    return ledger.verify_receipt(bundle.receipt_path)


def _publication_existing_receipt(
        result_path: str, *,
        expected_artifact_kind: str = "run_shard") -> Optional[dict]:
    from . import result_ledger as ledger
    receipt_path = result_path + ledger.RECEIPT_SUFFIX
    if not os.path.lexists(receipt_path):
        return None
    # Presence is authoritative: any failure propagates and checkpoint
    # fallback is intentionally unreachable.
    try:
        receipt = ledger.verify_receipt(receipt_path)
    except ledger.ResultLedgerRefused as exc:
        raise SystemExit(str(exc)) from exc
    if receipt["artifact_kind"] != expected_artifact_kind:
        raise SystemExit(
            "REFUSED: result receipt artifact kind differs from the "
            f"requested producer: expected {expected_artifact_kind!r}, got "
            f"{receipt['artifact_kind']!r}")
    return receipt


def _publication_fsync_existing_receipt(receipt_path: str) -> None:
    """Finish a visible receipt's file/directory durability under its lock."""
    from . import result_ledger as ledger
    before = ledger._trusted_leaf(receipt_path, "result receipt")
    parent = os.path.dirname(receipt_path)
    parent_fd = ledger._open_directory_nofollow(
        parent, "result receipt parent")
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(os.path.basename(receipt_path), flags, dir_fd=parent_fd)
        opened = os.fstat(fd)
        if ledger._stat_identity(before) != ledger._stat_identity(opened):
            raise ledger._refuse(
                "result receipt changed before durability recovery")
        os.fsync(fd)
        synced = os.fstat(fd)
        current = os.stat(
            os.path.basename(receipt_path), dir_fd=parent_fd,
            follow_symlinks=False)
        if len({ledger._stat_identity(value) for value in (
                before, opened, synced, current)}) != 1:
            raise ledger._refuse(
                "result receipt changed during durability recovery")
        os.fsync(parent_fd)
    except OSError as exc:
        raise ledger._refuse(
            f"cannot complete existing receipt durability: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)
    after = ledger._trusted_leaf(receipt_path, "result receipt")
    if ledger._stat_identity(after) != ledger._stat_identity(before):
        raise ledger._refuse(
            "result receipt changed after durability recovery")


def _publication_existing_receipt_under_lock(
        result_path: str, *,
        expected_artifact_kind: str = "run_shard") -> Optional[dict]:
    """Verify, durably confirm, and reverify a receipt while owning its lock."""
    from . import result_ledger as ledger
    receipt = _publication_existing_receipt(
        result_path, expected_artifact_kind=expected_artifact_kind)
    if receipt is None:
        return None
    _publication_fsync_existing_receipt(
        result_path + ledger.RECEIPT_SUFFIX)
    if _publication_existing_receipt(
            result_path,
            expected_artifact_kind=expected_artifact_kind) != receipt:
        raise ledger._refuse(
            "result receipt changed across durability recovery")
    return receipt


def _publication_existing_receipt_matches(
        args, existing: dict, *, agent_admission) -> dict:
    """Accept a complete receipt only for the publication being requested.

    Receipt-first resume is idempotent for the SAME cell.  A receipt sealed
    by a DIFFERENT cell at the same authenticated result path publishes
    another workset, so returning it would answer this request with another
    cell's rows; that refuses and names both plans instead.  `_load_checkpoint`
    already holds this join for a partial shard; this closes it for a sealed
    one.
    """
    from . import result_ledger as ledger
    bundle = construct_publication_run_plan(
        args, agent_admission=agent_admission)
    document = ledger.loads_exact_json(
        ledger.read_trusted_bytes(
            existing["receipt_path"], label="result receipt"),
        label="result receipt")
    if document["execution"] != bundle.execution \
            or document["plan"] != bundle.plan:
        raise ledger._refuse(
            "result receipt publishes a different publication than the one "
            f"requested: receipt plan {document['plan']['digest']} of "
            f"attempt {document['execution']['attempt_id']}, requested plan "
            f"{bundle.plan['digest']} of attempt "
            f"{bundle.execution['attempt_id']}")
    return {"already_complete": True, **existing}

def _publication_resolve_existing_receipt(
        result_path: str, *,
        expected_artifact_kind: str = "run_shard") -> Optional[dict]:
    """Resolve a present receipt without creating any new evidence leaf.

    A compliant producer creates and owns the persistent result lock before a
    receipt can become visible.  Therefore a present receipt with an existing
    lock must be verified while owning that exact lock; an absent lock proves
    there is no compliant in-flight writer and permits a read-only check.
    """
    from . import result_ledger as ledger
    receipt_path = result_path + ledger.RECEIPT_SUFFIX
    if not os.path.lexists(receipt_path):
        return None
    lock_path = publication_lock_path(result_path)
    if not os.path.lexists(lock_path):
        receipt = _publication_existing_receipt(
            result_path, expected_artifact_kind=expected_artifact_kind)
        if not os.path.lexists(lock_path):
            return receipt
        # A lock appeared during verification.  Treat the receipt as owned by
        # that writer and resolve again only after acquiring its existing leaf.
    with _PublicationResultLock(result_path, create=False):
        return _publication_existing_receipt_under_lock(
            result_path, expected_artifact_kind=expected_artifact_kind)


def run_publication_v3(
        args, *, harness_factory: Callable[[], tuple],
        live_validator: Callable[[], dict],
        fault: Optional[Callable[[str], None]] = None,
        row_producer: Optional[Callable[[dict], dict]] = None,
        agent_admission: Optional[Mapping[str, object]] = None,
        agent_secret: bytes = b"", agent_launcher=None) -> dict:
    """Execute/resume/finalize one explicit run-shard publication."""
    if agent_admission is None:
        publication_adapter_kind(args)  # the first operation by contract
        publication = None
    else:
        publication = _agent_module("agents.publication")
        publication.agent_publication_adapter_kind(args)
    from . import result_ledger as ledger
    # The refusals planning and closing can raise: the ledger's, and the
    # agent producer's when this is an agent publication -- which is the
    # only case that asks for the agent component.
    planning_refusals: tuple = (ledger.ResultLedgerRefused,)
    if agent_admission is not None:
        agent_ledger = _agent_module("confined.result_ledger_v2")
        planning_refusals += (agent_ledger.ResultLedgerV2Refused,)
    if not getattr(args, "out", None):
        raise SystemExit(
            "REFUSED: run --publication-v3 requires an authenticated exact "
            "result path; no Docker command was run.")
    result_path = _publication_path(
        args.out, "publication result path", live=False)
    bound = any(os.path.lexists(path) for path in (
        result_path, result_path + ledger.CHECKPOINT_SUFFIX,
        result_path + ledger.RECEIPT_SUFFIX))
    if bound and (bool(getattr(args, "no_resume", False))
                  or bool(getattr(args, "retry_failed", False))):
        raise SystemExit(
            "REFUSED: --no-resume and --retry-failed cannot extend any "
            "result-v3-bound path.")
    existing = _publication_resolve_existing_receipt(result_path)
    if existing is not None:
        return _publication_existing_receipt_matches(
            args, existing, agent_admission=agent_admission)
    try:
        with _PublicationResultLock(result_path) as result_lock:
            # Receipt-first means first *under the result-owner lock*.  Bytes
            # made visible by an active writer are not complete until that
            # writer finishes the durable create and releases ownership.
            existing = _publication_existing_receipt_under_lock(result_path)
            if existing is not None:
                return _publication_existing_receipt_matches(
                    args, existing, agent_admission=agent_admission)
            candidate = _publication_substrate_resume_candidate(result_path)
            planning_error: Optional[BaseException] = None
            bundle = None
            try:
                bundle = construct_publication_run_plan(
                    args, agent_admission=agent_admission)
            except (SystemExit, *planning_refusals) as exc:
                if candidate is None:
                    raise
                planning_error = exc
            if candidate is not None and (
                    planning_error is not None
                    or bundle.execution != candidate["checkpoint"]["execution"]
                    or bundle.plan != candidate["checkpoint"]["plan"]):
                # The prior item may have changed or removed a selected
                # feature. Rebuild those exact checkpoint inputs from the
                # authenticated worker workspace archive common to agent and
                # fixture arms. Nothing is preferred or mutated until exact
                # plan/result comparison and any agent evidence-chain replay
                # have succeeded.
                resume_bundle = construct_publication_run_plan(
                    args, agent_admission=agent_admission,
                    _verify_agent_workspace=False,
                    _checkpoint_feature_entries=candidate["features"])
                stop = _publication_bound_substrate_stop(
                    resume_bundle, agent_secret,
                    agent_mode=agent_admission is not None, args=args,
                    live_validator=live_validator,
                    lock_confirm=result_lock.confirm)
                if stop is not None:
                    raise SubstrateTampered(stop["report"]) \
                        from planning_error
            if planning_error is not None:
                raise planning_error
            if bundle is None:
                raise ledger._refuse(
                    "publication planning produced no authenticated bundle")
            if agent_admission is not None:
                bundle._agent_secret = agent_secret
                args._agent_publication_secret = agent_secret
                args._agent_publication_launcher = agent_launcher
            if bundle.result_path != result_path:
                raise ledger._refuse(
                    "publication result path changed during planning")
            args._publication_run_plan = bundle
            args._publication_protected_paths = publication_protected_paths(
                bundle)
            state = _RunShardLedger(
                bundle, fault=fault, lock_confirm=result_lock.confirm)
            entered_running = False
            if agent_admission is None:
                state.resolve()
                entered_running = state.document["state"] == "running"
            _install_publication_harness_context(bundle, args)
            harness, boundary, manifest = harness_factory()
            if harness.root != bundle.runtime.worker.workspace \
                    or boundary.project != bundle.context.profile.project \
                    or manifest.gold_root != bundle.strip_document["gold_root"]:
                raise ledger._refuse(
                    "constructed harness differs from the frozen publication "
                    "bindings")

            def preserve_stale_substrate_stop() -> bool:
                """Do not let a live-gate failure demote an appended stop."""
                if not entered_running:
                    return False
                try:
                    stop = _publication_prior_substrate_stop(state)
                    if stop is None:
                        return False
                    _publication_interrupt_for_stop(state, stop)
                except BaseException:
                    # A pending suffix or uncertain replacement must remain
                    # stale running for the next authenticated owner.  The
                    # live-gate exception still propagates below.
                    return True
                return True

            try:
                _publication_live_revalidate(bundle, live_validator)
            except KeyboardInterrupt as exc:
                if not preserve_stale_substrate_stop() \
                        and state.document is not None \
                        and state.document["state"] == "running":
                    try:
                        state.transition(
                            "interrupted", reason=_publication_reason(exc))
                    except BaseException:
                        # A stale suffix is intentionally left running until
                        # a later owner can validate and adopt it.
                        pass
                raise
            except BaseException as exc:
                if not preserve_stale_substrate_stop() \
                        and state.document is not None \
                        and state.document["state"] == "running":
                    try:
                        state.transition(
                            "failed", reason=_publication_reason(exc))
                    except BaseException:
                        pass
                raise
            if agent_admission is not None:
                # Missing live execution authority cannot claim or burn an
                # agent evidence path. All authenticated inputs are already
                # frozen above; create the draft only after that authority
                # has revalidated.
                state.resolve()
                entered_running = state.document["state"] == "running"
            if agent_admission is None:
                state.adopt_pending_suffix()
                if state.document["state"] in {"draft", "interrupted"}:
                    state.transition("running")
            else:
                agent = _agent_module("confined.result_ledger_v2")
                if state.document["state"] == "draft":
                    if state.created_draft:
                        try:
                            agent.create_evidence_root(bundle.result_path)
                        except agent.ResultLedgerV2Refused as exc:
                            state.transition(
                                "failed", reason=_publication_reason(exc))
                            raise
                    else:
                        agent.create_or_accept_evidence_root(
                            bundle.result_path)
                else:
                    agent.verify_resume_evidence_root(
                        bundle.result_path, bundle.item_ids)
                result_raw = ledger.read_trusted_bytes(
                    bundle.result_path, label="agent publication result")

                def verify_chain(paths, item_index):
                    return publication._verify_publication_agent_chain(
                        bundle, paths, item_index, agent_secret)["row_raw"]

                resumed = agent.resume_workset(
                    result_path=bundle.result_path,
                    item_ids=bundle.item_ids, result_raw=result_raw,
                    verify_chain=verify_chain)
                state.adopt_pending_suffix()
                if state.document["state"] in {"draft", "interrupted"}:
                    state.transition("running")
                if resumed["pending_row"] is not None:
                    synchronized = ledger.read_trusted_bytes(
                        bundle.result_path, label="agent publication result")
                    appended = agent.append_pending_row(
                        bundle.result_path, resumed["pending_row"],
                        result_raw=synchronized)
                    state.pending_adoption = _publication_result_binding(
                        bundle.result_path, appended,
                        resumed["next_item_index"])
                    state.adopt_pending_suffix()

                # Section 4.1's immediately-before-first-launch moment.
                if state.document["result_prefix"]["row_count"] \
                        < len(bundle.item_ids):
                    info = bundle.context.agent_adapter
                    agent.verify_backend_source_runtime(info["backend"])
                    agent.reinventory_backend(info["backend"])
                    logical = agent.agent_logical_paths(info["adapter_kind"])
                    driver = info["files"][
                        ("agent_driver", logical["agent_driver"])]["path"]
                    agent.observe_backend_startup(
                        info["backend"], driver,
                        environment=agent.public_environment(
                            bundle.runtime.worker.workspace,
                            info["backend"]["root"]))

            adapter = _build_publication_adapter(bundle, args)
            features = _publication_feature_texts(bundle)
            started = time.time()
            started_at = time.strftime(
                "%Y-%m-%dT%H:%M:%S%z", time.localtime(started))
            counts: dict[str, int] = {}
            incomplete = None
            execution_lock = _publication_execution_lock(
                harness.root, agent=agent_admission is not None)
            with execution_lock:
                first = None
                try:
                    first = state.document["result_prefix"]["row_count"]
                    prior_substrate_stop = _publication_prior_substrate_stop(
                        state)
                    if prior_substrate_stop is not None \
                            and entered_running:
                        # A running checkpoint ending in a substrate row is
                        # the unfinished post-append transition.  Complete it
                        # before a suffix launch; a later invocation entering
                        # from interrupted may continue after operator cleanup.
                        _publication_interrupt_for_stop(
                            state, prior_substrate_stop)
                        incomplete = prior_substrate_stop
                    elif prior_substrate_stop is not None \
                            and first == len(bundle.item_ids):
                        verify_substrate = getattr(
                            harness, "verify_substrate", None)
                        if callable(verify_substrate):
                            try:
                                verify_substrate()
                            except SubstrateTampered:
                                _publication_interrupt_for_stop(
                                    state, prior_substrate_stop)
                                raise
                    # A row names the commit that produced it (section
                    # 16.5); the plan's stamp names the commit the shard was
                    # opened at, and the two differ after a resume across a
                    # merge.  One git call per process, not per item.
                    row_stamp = {**bundle.stamp,
                                 "harness_commit": _harness_commit()}
                    for number, item in enumerate(
                            (() if incomplete is not None else
                             bundle.selected_items[first:]), first + 1):
                        deferred_guard = (
                            agent_admission is not None
                            and prior_substrate_stop is not None
                            and row_producer is None)
                        if agent_admission is not None and not deferred_guard:
                            guard_snapshot = publication._agent_guard_snapshot(bundle)
                            if guard_snapshot is not None \
                                    and guard_snapshot["stopped"]:
                                reason = publication._aggregate_cap_reason(guard_snapshot)
                                state.transition(
                                    "interrupted",
                                    reason="aggregate guard stopped: " + reason)
                                incomplete = {
                                    "terminal_reason": reason,
                                    "guard": guard_snapshot,
                                }
                                break
                        try:
                            if row_producer is None:
                                relative = item["provenance"]["file_path"]

                                def after_prepare():
                                    if not deferred_guard:
                                        return
                                    snapshot = publication._agent_guard_snapshot(bundle)
                                    if snapshot is not None \
                                            and snapshot["stopped"]:
                                        raise _AggregateCapStopped(
                                            publication._aggregate_cap_reason(
                                                snapshot))

                                record = run_one(
                                    harness, adapter, item,
                                    coverage=bool(args.coverage),
                                    timeout=args.timeout,
                                    repeats=args.repeats,
                                    keep_artifacts=None, stamp=bundle.stamp,
                                    feature_text=features[relative],
                                    after_prepare=(after_prepare
                                                   if deferred_guard else None))
                            else:
                                record = row_producer(copy.deepcopy(item))
                        except _AggregateCapStopped:
                            guard_snapshot = publication._agent_guard_snapshot(bundle)
                            reason = publication._aggregate_cap_reason(guard_snapshot)
                            state.transition(
                                "interrupted",
                                reason="aggregate guard stopped: " + reason)
                            incomplete = {
                                "terminal_reason": reason,
                                "guard": guard_snapshot,
                            }
                            break
                        except SubstrateTampered as exc:
                            if prior_substrate_stop is None:
                                # Preserve the base publication behavior for
                                # preexisting dirt unrelated to an appended
                                # substrate row. #199 changes only recovery of
                                # the previous item's attributed stop.
                                record = _harness_error_row(
                                    item["item_id"], exc)
                            else:
                                # A resumed dirty workspace is the previous
                                # item's terminal substrate condition, not a
                                # row for an agent that was never launched.
                                _publication_interrupt_for_stop(
                                    state, prior_substrate_stop)
                                raise
                        except KeyboardInterrupt as exc:
                            state.transition(
                                "interrupted", reason=_publication_reason(exc))
                            raise
                        except Exception as exc:              # noqa: BLE001
                            record = _harness_error_row(
                                item["item_id"], exc)
                        for name, value in row_stamp.items():
                            record.setdefault(name, value)
                        if agent_admission is not None:
                            # Every publishable agent row, including a
                            # non-passing scientific result, closes one full
                            # immutable chain. A scenario/harness path that
                            # never launched the adapter is therefore a
                            # producer failure, not a row without evidence.
                            record = adapter.close_row(record)
                            if publication._native_evidence_required(
                                    adapter.name):
                                try:
                                    record = publication \
                                        ._verify_publication_agent_item_close(
                                            bundle, record, number - 1,
                                            agent_secret)
                                except planning_refusals as exc:
                                    evidence_stop = {
                                        "kind": "agent_item_evidence",
                                        "terminal_reason":
                                            _publication_reason(exc),
                                    }
                                    _publication_interrupt_for_stop(
                                        state, evidence_stop)
                                    incomplete = evidence_stop
                                    break
                        state.append(record)
                        prior_substrate_stop = None
                        substrate_stop = None
                        if record["outcome"] == "substrate_violation":
                            substrate_stop = _publication_substrate_stop(
                                record["item_id"],
                                record["substrate_violation"])
                            _publication_interrupt_for_stop(
                                state, substrate_stop)
                            incomplete = substrate_stop
                        counts[record["outcome"]] = (
                            counts.get(record["outcome"], 0) + 1)
                        elapsed = time.time() - started
                        print(
                            f"[{number}/{len(bundle.selected_items)}] "
                            f"{record['item_id']} -> {record['outcome']} "
                            f"({elapsed / max(1, number - first):.1f}s/item)",
                            flush=True)
                        if substrate_stop is not None:
                            break

                    if incomplete is None:
                        _binding, _result_raw, rows = state.final_result()
                        repro = _publication_repro_check(
                            harness, adapter, bundle, rows, args, features)
                        if repro.get("drift"):
                            raise ledger._refuse(
                                "publication reproducibility sample drifted")
                    elif incomplete.get("kind") == "substrate_violation":
                        repro = {
                            "checked": 0,
                            "skipped": "substrate violation retained workspace",
                        }
                    elif incomplete.get("kind") == "agent_item_evidence":
                        repro = {
                            "checked": 0,
                            "skipped": f"{adapter.name} item-close evidence "
                                       f"invalid",
                        }
                    else:
                        repro = {"checked": 0,
                                 "skipped": "aggregate cap stopped"}
                    if incomplete is None or incomplete.get("kind") not in {
                            "substrate_violation", "agent_item_evidence"}:
                        from .repo import clean_workspace
                        clean_workspace(harness.man, harness.boundary)
                        harness.clear_registration()
                        verify_substrate = getattr(
                            harness, "verify_substrate", None)
                        if callable(verify_substrate):
                            verify_substrate()
                    finished_at = time.strftime(
                        "%Y-%m-%dT%H:%M:%S%z")
                    if incomplete is None:
                        result_lock.confirm()
                        receipt = _publication_seal(
                            bundle, state, started_at=started_at,
                            finished_at=finished_at,
                            live_validator=live_validator, fault=fault,
                            lock_confirm=result_lock.confirm)
                    else:
                        receipt = None
                except _PublicationAppendUncertain:
                    # Preserve running. The next owner must validate/adopt the
                    # exact suffix; no transition may hide or truncate it.
                    raise
                except _PublicationSubstrateTransitionUncertain:
                    # The interrupted replacement may or may not be visible.
                    # Preserve stale running rather than demoting a durable
                    # diagnostic prefix to failed; the next owner replays it.
                    raise
                except _PublicationInjectedCrash:
                    raise
                except KeyboardInterrupt as exc:
                    if not os.path.lexists(bundle.receipt_path) \
                            and state.document is not None \
                            and state.document["state"] == "running":
                        try:
                            substrate_stop = None
                            if entered_running or (
                                    first is not None
                                    and state.document["result_prefix"][
                                        "row_count"] > first):
                                substrate_stop = \
                                    _publication_prior_substrate_stop(state)
                            if substrate_stop is None:
                                state.transition(
                                    "interrupted",
                                    reason=_publication_reason(exc))
                            else:
                                # A signal may land after append returned but
                                # before the outcome gate.  The durable row,
                                # not the later signal, owns the diagnostic.
                                _publication_interrupt_for_stop(
                                    state, substrate_stop)
                        except BaseException:
                            pass
                    raise
                except BaseException as exc:
                    if state.document is not None \
                            and state.document["state"] == "running":
                        try:
                            state.transition(
                                "failed", reason=_publication_reason(exc))
                        except BaseException:
                            # If result/checkpoint are not synchronized, the
                            # only safe persisted state is stale running.
                            pass
                    raise
            return {
                "adapter": adapter.name,
                "out": bundle.result_path,
                "n": len(bundle.selected_items),
                "complete": incomplete is None,
                "completed": state.document["result_prefix"]["row_count"],
                "missing": ([] if incomplete is None else
                            bundle.item_ids[
                                state.document["result_prefix"]["row_count"]:]),
                "terminal_reason": (None if incomplete is None else
                                    incomplete["terminal_reason"]),
                "outcomes": counts,
                "artifacts": None,
                "shard": bundle.plan["shard_index"],
                "of": bundle.plan["shard_count"],
                "started_at": started_at,
                "finished_at": finished_at,
                "seconds": round(time.time() - started, 1),
                "repro_check": repro,
                "receipt": receipt,
            }
    except planning_refusals as exc:
        raise SystemExit(str(exc)) from exc


def selftest() -> int:
    """The re-analysis plumbing, checked without a container.

    What is checked is the part that silently loses evidence: the coverage
    regrouping, the join key artifacts share with gold, and whether an
    artifact directory tells the truth about a truncated log.
    """
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    with tempfile.TemporaryDirectory() as root:
        release_path = os.path.join(root, "items.jsonl")
        with open(release_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "p/f.feature:1"}) + "\n")
        missing_args = type("Args", (), {
            "release": release_path,
            "item": ["p/f.feature:2"],
        })()
        try:
            _run_adapter_locked(None, missing_args, root)
            missing_refusal = ""
        except SystemExit as exc:
            missing_refusal = str(exc)
        check("an explicit --item absent from --release is refused before "
              "item execution",
              "REFUSED" in missing_refusal
              and "p/f.feature:2" in missing_refusal
              and release_path in missing_refusal,
              missing_refusal)

    units = ["src/A.php::L3", "src/A.php::L1", "src/B.php::L9", "src/A.php::L3"]
    lines = _lines_by_file(units)
    check("units regroup per file, sorted and deduplicated",
          lines == {"src/A.php": [1, 3], "src/B.php": [9]}, str(lines))
    check("a malformed unit is dropped, not guessed at",
          _lines_by_file(["src/A.php", "src/A.php::Lx", ""]) == {})
    check("the grouped form is smaller than the strings it replaces",
          len(json.dumps(lines)) < len(json.dumps(units)))
    check("a path containing a colon survives the split",
          _lines_by_file(["src/We:rd::L7"]) == {"src/We:rd": [7]},
          str(_lines_by_file(["src/We:rd::L7"])))
    check("a healthy coverage block has no mismatch",
          _coverage_mismatch({"src/A.php": 2, "src/B.php": 1}, lines) == [])
    check("dropping a unit is caught by the recorder's own per-file count",
          _coverage_mismatch({"src/A.php": 3, "src/B.php": 1}, lines)
          == ["src/A.php"])
    check("a file the recorder counted but sent no lines for is caught",
          _coverage_mismatch({"src/C.php": 4}, lines) == ["src/C.php"])

    # P0-3: a submission that edits production during its own execution must
    # not be able to produce a green row.
    viol = {"changed": ["src/CoreShop/Component/Order/Model/Order.php"],
            "missing": [], "added": []}
    green = {"runs": [{"outcome": "passed", "exit_code": 0, "wall_seconds": 1.0,
                       "records": [{"scenario_line": 3,
                                    "steps": [{"text": "x", "result": "passed",
                                               "seconds": 0.1,
                                               "exception": None}]}],
                       "expected_line": 3, "stdout_tail": ""}],
             "written_files": ["src/CoreShop/Behat/Context/Domain/X.php"],
             "rejected_files": [], "index_errors": {}}
    item0 = {"item_id": "p/f.feature:3", "task": "criterion_to_test"}
    ok_rec = _record("p/f.feature:3", item0, {"files": []}, 0.0, green)
    check("a clean execution still reports its real outcome",
          ok_rec["outcome"] == "passed" and ok_rec["substrate_violation"] is None)
    bad_rec = _record("p/f.feature:3", item0, {"files": []}, 0.0,
                      dict(green, substrate_violation=viol))
    check("a submission that changed production cannot report a pass",
          bad_rec["outcome"] == "substrate_violation")
    check("what changed is carried on the row, not just the label",
          bad_rec["substrate_violation"]["changed"] == viol["changed"])

    # The same integrity exception means two different things on the two
    # sides of generation.  Dirt present before the adapter starts belongs to
    # the worker and is retryable; dirt first observed at the authoritative
    # execution boundary belongs to the current candidate and must not be
    # retried away.  Exercise run_one itself so a future broad `except` cannot
    # silently collapse the distinction again.
    with tempfile.TemporaryDirectory(prefix="r2t-runner-attribution-") as root:
        feature_rel = "features/attribution.feature"
        os.makedirs(os.path.join(root, "features"))
        with open(os.path.join(root, feature_rel), "w", encoding="utf-8") as fh:
            fh.write("Feature: attribution\n\n"
                     "  Scenario: candidate\n"
                     "    Given a step\n")
        attributed_item = {
            "item_id": feature_rel + ":3",
            "task": "criterion_to_test",
            "provenance": {"file_path": feature_rel, "line": 3},
        }
        candidate_files = [{
            "file_path": "src/CoreShop/Behat/Context/Domain/Candidate.php",
            "code": "<?php final class Candidate {}",
        }]
        candidate_report = {
            "baseline": True,
            "changed": ["src/CoreShop/Component/Order/Model/Order.php"],
            "missing": [],
            "added": ["features/bootstrap/RetainedFixture.php"],
        }

        class CandidateTamperHarness:
            def __init__(self):
                self.root = root

            def prepare_for_generation(self):
                return None

            def run_solution(self, *_args, **_kwargs):
                raise SubstrateTampered(candidate_report)

        generated = {"files": candidate_files,
                     "metadata": {"candidate_marker": "preserved"}}
        candidate_rec = run_one(CandidateTamperHarness(),
                                lambda _task: generated, attributed_item)
        check("tampering found after the current candidate ran is attributed "
              "to that candidate, not called a harness error",
              candidate_rec["outcome"] == "substrate_violation"
              and candidate_rec["outcome"] not in _RETRYABLE_OUTCOMES,
              json.dumps(candidate_rec)[:300])
        check("the attributed row retains the candidate and bounded tamper "
              "evidence",
              candidate_rec["produced_files"] == candidate_files
              and candidate_rec["substrate_violation"]
              == {key: candidate_report[key]
                  for key in ("changed", "missing", "added")}
              and candidate_rec["metadata"]["candidate_marker"]
              == "preserved"
              and candidate_rec["metadata"]
              ["substrate_violation_attribution"]["detected_at"]
              == "authoritative_execution_boundary",
              json.dumps(candidate_rec)[:500])

        from ..go.runtime import RuntimeRefused
        from .validate import HARNESS_VERSION

        class FailedExecutionHarness(CandidateTamperHarness):
            def __init__(self, error):
                super().__init__()
                self.error = error

            def run_solution(self, *_args, **_kwargs):
                raise self.error

        class PaidCandidate:
            name = "preserved-fixture"

            def __init__(self):
                self.calls = 0

            def __call__(self, _task):
                self.calls += 1
                return {"files": candidate_files, "metadata": {
                    "agent_stats": {"llm_calls": 3, "prompt_tokens": 123},
                    "harness_error": "untrusted adapter diagnostic"}}

        for retain in (False, True):
            paid = PaidCandidate()
            kept = os.path.join(root, "failed-artifacts") if retain else None
            saved_stamp = {"model": "fixture", "harness_version": HARNESS_VERSION}
            failed = run_one(
                FailedExecutionHarness(RuntimeRefused("fixture native failure")),
                paid, attributed_item, coverage=True, keep_artifacts=kept,
                stamp=saved_stamp)
            check("execution failure retains paid candidate and usage without "
                  f"rerunning generation (artifacts={retain})",
                  paid.calls == 1 and failed["outcome"] == "harness_error"
                  and failed["produced_files"] == candidate_files
                  and failed["n_files"] == 1
                  and failed["metadata"]["agent_stats"]["llm_calls"] == 3
                  and failed["metadata"]["harness_error"]
                  == "RuntimeRefused: fixture native failure"
                  and "traceback_tail" in failed["metadata"]
                  and failed["coverage_requested"]
                  and not failed["coverage_collected"]
                  and "execution_seconds" not in failed
                  and "runs" not in failed)
            if retain:
                folder = os.path.join(kept, paid.name,
                                      item_key(attributed_item["item_id"]))
                with open(os.path.join(folder, "record.json")) as fh:
                    saved = json.load(fh)
                with open(os.path.join(folder, "meta.json")) as fh:
                    meta = json.load(fh)
                with open(os.path.join(folder, "solution",
                                       candidate_files[0]["file_path"])) as fh:
                    code = fh.read()
                check("failed execution artifacts retain exact candidate and "
                      "stamped row without claiming complete stdout",
                      code == candidate_files[0]["code"]
                      and saved == {**saved_stamp, **failed}
                      and not meta["stdout_complete"])
        for signal in (KeyboardInterrupt, SystemExit):
            propagated = False
            try:
                run_one(FailedExecutionHarness(signal()), PaidCandidate(),
                        attributed_item)
            except signal:
                propagated = True
            check(f"execution {signal.__name__} still propagates", propagated)

        # Harness 25: whether an execution is a gold run is decided by the
        # adapter this process built, and reaches the harness on the
        # solution (`Solution.gold_run`).
        from .fixtures import Adapter

        class GoldRunProbe(CandidateTamperHarness):
            def __init__(self):
                super().__init__()
                self.seen = []

            def run_solution(self, _feature, _scenario, solution, **_kwargs):
                self.seen.append(solution.gold_run)
                raise RuntimeRefused("probe")

        def answer(_task):
            return {"files": candidate_files, "metadata": {}}

        gold_run_cases = (
            (Adapter("gold", answer, {}), True),
            (Adapter("stripped-gold", answer, {}), True),
            (Adapter("stub", answer, {}), True),
            (Adapter("mutation-baseline", answer, {"gold_run": True}), True),
            (Adapter("gold", answer, {"replay": "c.jsonl"}), False),
            (Adapter("submitted:gold", answer, {}), False),
            (Adapter("mutation-baseline", answer, {}), False))
        probe = GoldRunProbe()
        for adapter, _gold in gold_run_cases:
            run_one(probe, adapter, attributed_item)
        check("[H25] the gold, stripped-gold and stub adapters, and one built "
              "as a gold run, execute gold runs; a replay of gold rows, a "
              "submission named after gold and any other adapter execute "
              "candidate runs",
              probe.seen == [gold for _adapter, gold in gold_run_cases]
              and [is_gold_run_adapter(adapter)
                   for adapter, _gold in gold_run_cases]
              == [gold for _adapter, gold in gold_run_cases],
              str(probe.seen))

        class MalformedTamperHarness(CandidateTamperHarness):
            def __init__(self):
                super().__init__()
                self.verify_calls = 0
                self.execution_called = False

            def verify_substrate(self):
                self.verify_calls += 1
                raise SubstrateTampered(candidate_report)

            def run_solution(self, *_args, **_kwargs):
                self.execution_called = True
                raise AssertionError("malformed output reached execution")

        malformed_harness = MalformedTamperHarness()
        malformed_artifacts = os.path.join(root, "malformed-artifacts")
        malformed_rec = run_one(
            malformed_harness,
            lambda _task: {"files": [
                               None,
                               {"file_path": "steps.py", "code": "pass\n",
                                "untrusted_extra": object()},
                           ],
                           "metadata": {"candidate_marker": "malformed"}},
            attributed_item, keep_artifacts=malformed_artifacts)
        check("post-generation verification attributes tampering before a "
              "malformed adapter result can become harness_error",
              malformed_rec["outcome"] == "substrate_violation"
              and malformed_rec["outcome"] not in _RETRYABLE_OUTCOMES
              and malformed_harness.verify_calls == 1
              and not malformed_harness.execution_called
              and malformed_rec["metadata"]
              ["substrate_violation_attribution"]["detected_at"]
              == "post_generation_before_output_parse"
              and malformed_rec["metadata"]["malformed_adapter_files"]
              ["count"] == 1
              and os.path.isfile(os.path.join(
                  malformed_artifacts, _safe_name("?"), item_key(
                      attributed_item["item_id"]), "record.json")),
              json.dumps(malformed_rec)[:500])

        adapter_called = False

        class PreexistingTamperHarness(CandidateTamperHarness):
            def prepare_for_generation(self):
                raise SubstrateTampered(candidate_report)

        def should_not_generate(_task):
            nonlocal adapter_called
            adapter_called = True
            return generated

        try:
            run_one(PreexistingTamperHarness(), should_not_generate,
                    attributed_item)
            preexisting_row = None
        except SubstrateTampered as exc:
            # This is the conversion `_run_adapter_locked` performs around
            # run_one; doing it here makes both halves independently visible.
            preexisting_row = _harness_error_row(
                attributed_item["item_id"], exc)
        check("preexisting substrate dirt escapes before generation and stays "
              "a retryable infrastructure error",
              not adapter_called and preexisting_row is not None
              and preexisting_row["outcome"] == "harness_error"
              and preexisting_row["outcome"] in _RETRYABLE_OUTCOMES,
              str(preexisting_row)[:300])

    # A Scenario Outline emits one record per Examples row.  Neither the
    # anomaly flag nor the per-step detail may treat that as tampering.
    def _row(line, result):
        return {"scenario_line": line,
                "steps": [{"text": f"L{line}", "result": result,
                           "seconds": 0.1, "exception": None}]}

    outline = {"runs": [{"outcome": "failed", "exit_code": 1,
                         "wall_seconds": 1.0,
                         "records": [_row(12, "passed"), _row(13, "failed")],
                         "expected_line": 6, "expected_lines": [6, 12, 13],
                         "stdout_tail": ""}],
               "written_files": ["src/CoreShop/Behat/Context/Domain/X.php"],
               "rejected_files": [], "index_errors": {}}
    out_rec = _record("p/f.feature:6", item0, {"files": []}, 0.0, outline)
    check("an outline's per-row records are not a record-count anomaly",
          out_rec["record_count"] == 2
          and out_rec["record_count_anomaly"] is False)
    check("the per-step detail describes the row that failed",
          [s["text"] for s in out_rec["per_step"]] == ["L13"],
          str(out_rec["per_step"]))
    forged = dict(outline, runs=[dict(outline["runs"][0], records=[
        _row(12, "passed"), _row(13, "failed"),
        _row(99, "passed"), _row(98, "passed")])])
    f_rec = _record("p/f.feature:6", item0, {"files": []}, 0.0, forged)
    check("records beyond what the scenario could produce are still flagged",
          f_rec["record_count"] == 4 and f_rec["record_count_anomaly"] is True)
    check("a forged record cannot supply the per-step detail",
          [s["text"] for s in f_rec["per_step"]] == ["L13"],
          str(f_rec["per_step"]))
    check("a plain scenario's second record is an anomaly, as before",
          _record("p/f.feature:3", item0, {"files": []}, 0.0,
                  dict(green, runs=[dict(green["runs"][0], records=[
                      _row(3, "passed"), _row(9, "passed")])])
                  )["record_count_anomaly"] is True)

    def direct_event(name, line):
        return {"callee_file": "src/product.py", "callee_line": line,
                "callee": f"Product.{name}",
                "caller_file": "features/steps/use.py", "accessor_binding": None}

    event_a, event_b = direct_event("a", 10), direct_event("b", 20)
    event_c, event_d = direct_event("c", 30), direct_event("d", 40)

    def api_execution(first, second, *, outcome="passed"):
        records = [dict(_row(12, "passed"), direct_calls=first,
                        direct_calls_schema="r2t.python_direct_calls/2",
                        coverage={"files": {"src/product.py": 1},
                                  "units": ["src/product.py::L11"]}),
                   dict(_row(13, "failed" if outcome == "failed" else "passed"),
                        direct_calls=second,
                        direct_calls_schema="r2t.python_direct_calls/2",
                        coverage={"files": {"src/product.py": 1},
                                  "units": ["src/product.py::L21"]})]
        return dict(outline["runs"][0], records=records, outcome=outcome,
                    exit_code=0 if outcome == "passed" else 1)

    def api_row(*runs):
        return _record("p/f.feature:6", item0, {"files": []}, 0.0,
                       dict(outline, runs=list(runs)))

    gold_execution = api_execution([event_a], [event_b])
    candidate_execution = api_execution([event_a], [event_c])
    gold_union = api_row(gold_execution)
    candidate_union = api_row(candidate_execution)
    check("gold and candidate item rows both preserve disjoint Examples "
          "calls through the same producer",
          gold_union["direct_calls"] == [event_a, event_b]
          and candidate_union["direct_calls"] == [event_a, event_c]
          and gold_union["direct_calls_schema"] == "r2t.python_direct_calls/2"
          and candidate_union["direct_calls_schema"] == "r2t.python_direct_calls/2")
    without_api = api_row(dict(gold_execution, records=[
        {key: value for key, value in record.items() if key != "direct_calls"}
        for record in gold_execution["records"]]))
    check("the API union changes no coverage, per-step, count, outcome, "
          "timing or other row field",
          {key: value for key, value in gold_union.items() if key != "direct_calls"}
          == {key: value for key, value in without_api.items() if key != "direct_calls"}
          and [step["text"] for step in gold_union["per_step"]] == ["L12"])
    check("an outline's coverage is the union of its Examples rows, with the "
          "per-file counts recomputed so the mismatch witness stays empty",
          gold_union["coverage_lines"] == {"src/product.py": [11, 21]}
          and gold_union["coverage_files"] == {"src/product.py": 2}
          and gold_union["coverage_mismatch"] == []
          and gold_union["coverage_collected"] is True)
    single = api_row(dict(gold_execution, records=gold_execution["records"][:1]))
    check("one matched record keeps the recorder's own counts beside its lines",
          single["coverage_lines"] == {"src/product.py": [11]}
          and single["coverage_files"] == {"src/product.py": 1}
          and single["coverage_mismatch"] == [])
    partial = api_row(dict(gold_execution, records=[
        gold_execution["records"][0],
        dict(gold_execution["records"][1], coverage=None)]))
    check("a matched record without collected coverage contributes no lines",
          partial["coverage_lines"] == {"src/product.py": [11]}
          and partial["coverage_files"] == {"src/product.py": 1})
    malformed = api_row(dict(gold_execution, records=[
        gold_execution["records"][0],
        dict(gold_execution["records"][1], coverage={
            "files": {"src/product.py": 2},
            "units": ["src/product.py::L21", "src/product.py::Lx"]})]))
    check("the mismatch witness is taken per record, so a malformed unit "
          "string in one Examples row still names its file after the union",
          malformed["coverage_mismatch"] == ["src/product.py"]
          and malformed["coverage_lines"] == {"src/product.py": [11, 21]})
    for label, execution, lines in (
            ("missing required record", dict(gold_execution,
                                              records=gold_execution["records"][:1]),
             {"src/product.py": [11]}),
            ("null required collection", api_execution([event_a], None),
             {"src/product.py": [11, 21]})):
        incomplete = api_row(execution)
        check(f"{label} emits API-unscored evidence while retaining "
              "the existing passed outcome and coverage",
              incomplete["direct_calls"] is None
              and incomplete["outcome"] == "passed"
              and incomplete["coverage_lines"] == lines)
    check("complete empty Examples lists emit measured-empty API evidence",
          api_row(api_execution([], []))["direct_calls"] == [])
    old_empty = api_execution([], [])
    old_empty["records"] = [
        {key: value for key, value in record.items() if key != "direct_calls_schema"}
        for record in old_empty["records"]]
    check("an old seeded collector's empty list retains no X1 schema claim",
          api_row(old_empty)["direct_calls"] == []
          and api_row(old_empty)["direct_calls_schema"] is None)
    other_repeat = api_execution([event_c], [event_d])
    failing_repeat = api_execution([event_c], [event_d], outcome="failed")
    check("API calls are never unioned across repeats: all-pass keeps "
          "the first repeat and a failure keeps its own repeat",
          api_row(gold_execution, other_repeat)["direct_calls"]
          == [event_a, event_b]
          and api_row(gold_execution, failing_repeat)["direct_calls"]
          == [event_c, event_d]
          and api_row(gold_execution, failing_repeat)["outcome"] == "failed")
    timed_out = dict(gold_execution, outcome="timeout", timed_out=True,
                     records=gold_execution["records"][:1], timeout_cleanup="killed")
    timeout_row = api_row(gold_execution, timed_out)
    check("an incomplete timed-out repeat withholds API without changing "
          "its timeout or cleanup verdict",
          timeout_row["direct_calls"] is None
          and timeout_row["outcome"] == "timeout"
          and timeout_row["timeout_cleanup"] == "killed")

    # All-repeats-must-pass (SPEC §8, rule 4).  With repeats > 1, a pass that
    # holds only sometimes is not a pass, and the row's detail must come from
    # the repeat that carried the verdict.
    flaky_run = dict(green["runs"][0], outcome="failed", exit_code=1,
                     stdout_tail="second repeat",
                     records=[{"scenario_line": 3,
                               "steps": [{"text": "y", "result": "failed",
                                          "seconds": 0.1, "exception": None}]}])
    flaky = dict(green, runs=[green["runs"][0], flaky_run])
    fl_rec = _record("p/f.feature:3", item0, {"files": []}, 0.0, flaky)
    check("repeats that disagree do not report a pass",
          fl_rec["outcome"] == "failed"
          and fl_rec["outcomes_all_runs"] == ["passed", "failed"])
    check("the per-step detail comes from the repeat that failed",
          [s["text"] for s in fl_rec["per_step"]] == ["y"]
          and fl_rec["stdout_tail"] == "second repeat",
          str(fl_rec["per_step"]))
    all_pass = dict(green, runs=[green["runs"][0],
                                 dict(green["runs"][0])])
    check("repeats that all pass still report the pass",
          _record("p/f.feature:3", item0, {"files": []}, 0.0,
                  all_pass)["outcome"] == "passed")

    check("a path that escapes the artifact directory is refused",
          _safe_rel("../../etc/passwd") is None
          and _safe_rel("/etc/passwd") == "etc/passwd"
          and _safe_rel("src/CoreShop/Behat/X.php") == "src/CoreShop/Behat/X.php")

    # The deleted manifests are independently retained by identity.  Rebuild
    # their exact bytes from the real release pools so a drift in `item_key`
    # or pool membership moves the digest instead of agreeing with a fixture
    # that was constructed by the same expression under test.
    benchmark_root = BENCHMARK_ROOT
    release_root = os.path.join(benchmark_root, "release")
    with open(os.path.join(release_root, "dataset_manifest.json"),
              encoding="utf-8") as fh:
        retained = json.load(fh)
    reconstructions = {}
    for project, block in retained["projects"].items():
        expected = block.get("gold_manifest_sha256")
        if expected is None:
            continue
        item_ids = [row["item_id"] for row in _load_release(
            os.path.join(release_root, block["items"]))]
        rendered = json.dumps(
            {iid: item_key(iid) + ".json" for iid in item_ids},
            indent=1, sort_keys=True).encode("utf-8")
        reconstructions[project] = {
            "actual": hashlib.sha256(rendered).hexdigest(),
            "expected": expected,
            "actual_n": len(item_ids),
            "expected_n": block["n_gold_sidecars"],
        }
    check("real release pools reconstruct every retained gold manifest "
          "identity",
          bool(reconstructions)
          and all(value["actual"] == value["expected"]
                  and value["actual_n"] == value["expected_n"]
                  for value in reconstructions.values()),
          json.dumps(reconstructions, sort_keys=True))

    produced = {"files": [
        {"file_path": "src/CoreShop/Behat/Context/Domain/X.php", "code": "<?php\n"},
        {"file_path": "behat_services.yml", "code": "services: {}\n"},
        {"file_path": "../escape.php", "code": "<?php\n"}]}
    item = {"item_id": "coreshop/features/domain/cart/x.feature:18"}
    rec = {"outcome": "passed", "coverage_requested": True,
           "coverage_collected": True, "coverage_files": {"src/A.php": 2},
           "coverage_lines": {"src/A.php": [1, 3]}}
    with tempfile.TemporaryDirectory() as root:
        d = _write_artifacts(root, item, "gold", produced,
                             {"runs": [{"stdout": "FULL LOG", "stdout_tail": "TAIL"}]},
                             rec, {"condition": "c2", "coverage": True})
        def read(*parts):
            with open(os.path.join(d, *parts), encoding="utf-8") as fh:
                return fh.read()
        check("the artifact directory is <adapter>/<gold key>",
              d == os.path.join(root, "gold", item_key(item["item_id"])), d)
        check("solution files keep their real relative paths",
              os.path.isfile(os.path.join(
                  d, "solution", "src/CoreShop/Behat/Context/Domain/X.php")))
        check("the DI fragment is separated from the solution",
              read("behat_services.yml") == "services: {}\n"
              and not os.path.isdir(os.path.join(d, "solution", "behat_services.yml")))
        meta = json.loads(read("meta.json"))
        check("an escaping path is refused and reported, not written",
              meta["solution_paths_not_written"] == ["../escape.php"], str(meta))
        check("stdout.log is the full log, not the row's tail",
              read("stdout.log") == "FULL LOG" and meta["stdout_complete"])
        check("coverage.json holds the line sets",
              json.loads(read("coverage.json"))["lines"] == {"src/A.php": [1, 3]})
        check("record.json is the run FILE's row — stamp included",
              json.loads(read("record.json"))["condition"] == "c2")

        # Re-running the same item must replace its directory, not merge
        # into it: this second run kept no stdout, collected no coverage and
        # produced no files.
        d2 = _write_artifacts(root, item, "gold", {"files": []},
                              {"runs": [{"stdout_tail": "TAIL"}]},
                              {"outcome": "failed"}, {})
        with open(os.path.join(d2, "meta.json"), encoding="utf-8") as fh:
            check("a tail-only log is filed as incomplete",
                  json.load(fh)["stdout_complete"] is False)
        check("a re-run replaces the item's artifacts rather than merging",
              d2 == d and not os.path.exists(os.path.join(d2, "coverage.json"))
              and not os.path.exists(os.path.join(d2, "solution")))

    # ------------------------------------------------------------------
    # The guards that have to hold BEFORE money is spent, and the one that
    # has to hold when an item blows up mid-sweep.  All pure functions, so
    # none of this needs a container, a release or an adapter that generates.
    from types import SimpleNamespace

    def fake_args(**over):
        base = dict(adapter="openhands", condition="c3", model="deepseek-chat",
                    coverage=False, repeats=1, max_iterations=30,
                    max_tokens=64000, temperature=0.0, trials=5,
                    campaign=None, shard=0, of=4,
                    artifacts=".", release="release/release.jsonl",
                    candidates=None)
        base.update(over)
        return SimpleNamespace(**base)

    def refuses(name, fn, *needles):
        try:
            fn()
        except SystemExit as e:
            miss = [x for x in needles if x not in str(e)]
            check(name, not miss, f"message lacks {miss}: {str(e)[:300]}")
        except Exception as e:                             # noqa: BLE001
            check(name, False, f"raised {type(e).__name__}: {e}")
        else:
            check(name, False, "did not refuse")

    for option in sorted(_SUBMITTED_REFUSED_OPTIONS):
        refuses(f"submitted runs refuse explicit {option} before contact",
                lambda value=option: submitted_run_flags(fake_args(
                    adapter="submitted",
                    _submitted_explicit_options={value})),
                "REFUSED", option,
                ("visibility-view verification join"
                 if option == "--visibility-map" else "full-release denominator"),
                "No Docker")
    try:
        submitted_run_flags(fake_args(
            adapter="submitted", condition=None, shard=3, of=None,
            candidates="fixture.jsonl",
            _submitted_explicit_options=frozenset()))
        injected_shard_allowed = True
    except SystemExit as exc:
        injected_shard_allowed = str(exc)
    check("a worker-injected shard identity does not shrink a submitted run",
          injected_shard_allowed is True, str(injected_shard_allowed))
    refuses("a submitted run without --candidates refuses before contact",
            lambda: submitted_run_flags(fake_args(
                adapter="submitted", condition=None,
                _submitted_explicit_options=frozenset())),
            "REFUSED", "--candidates", "no Docker")
    refuses("--candidates under a non-submitted adapter refuses instead of "
            "being silently ignored",
            lambda: submitted_run_flags(fake_args(
                candidates="fixture.jsonl")),
            "REFUSED", "--candidates", "silently ignored", "No Docker")

    # Exercise argparse itself: `--trials 0` equals the ordinary default, and
    # `--tri` is a supported abbreviation, so namespace values alone cannot
    # answer whether it was typed.  Worker binding happens after this capture
    # and must not make its injected shard look explicit.
    from .. import cli as cli_module
    from . import cli as bench_cli
    submitted_contact = {"worker": 0, "harness": 0}
    real_require_worker = bench_cli._require_bound_live_worker
    real_harness = bench_cli._harness
    try:
        bench_cli._require_bound_live_worker = lambda _args: (
            submitted_contact.__setitem__(
                "worker", submitted_contact["worker"] + 1))
        bench_cli._harness = lambda _args: submitted_contact.__setitem__(
            "harness", submitted_contact["harness"] + 1)
        try:
            bench_cli.cmd_run(SimpleNamespace(
                publication_v3=False, adapter="submitted",
                _submitted_explicit_options={"--limit"}))
            precontact_refusal = ""
        except SystemExit as exc:
            precontact_refusal = str(exc)
    finally:
        bench_cli._require_bound_live_worker = real_require_worker
        bench_cli._harness = real_harness
    check("the submitted flag gate is wired before worker and harness contact",
          "REFUSED" in precontact_refusal
          and submitted_contact == {"worker": 0, "harness": 0},
          f"message={precontact_refusal}, contact={submitted_contact}")

    # A labelled sensitivity re-execution: replay only, its own run file, and
    # only on a stack that defines the overlay.
    from unittest.mock import patch as _patch
    with tempfile.TemporaryDirectory(prefix="r2t-sensitivity-") as root:
        primary = os.path.join(root, "primary.jsonl")
        with open(primary, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1", "outcome": "not_passed"}) + "\n")
        contact = {"worker": 0}
        other_stack = SimpleNamespace()

        def sensitivity_run(adapter, out, label="webmock_world_v1"):
            return lambda: bench_cli.cmd_run(SimpleNamespace(
                publication_v3=False, adapter=adapter, sensitivity=label,
                out=out))

        with _patch.object(bench_cli, "_require_bound_live_worker",
                           lambda _args: contact.__setitem__("worker", contact["worker"] + 1)), \
                _patch.object(bench_cli, "_agent_model_readiness_boundary", lambda _args: None), \
                _patch.object(bench_cli, "_harness", lambda _args: (other_stack, None, None)):
            refuses("a sensitivity run refuses any adapter but replay, before contact",
                    sensitivity_run("codex", None), "--adapter replay")
            refuses("a sensitivity run refuses a run file holding unlabelled rows",
                    sensitivity_run("replay", primary), "own run file")
            check("both sensitivity refusals precede worker contact", contact["worker"] == 0)
            refuses("a sensitivity run refuses a stack without the overlay",
                    sensitivity_run("replay", os.path.join(root, "new.jsonl")),
                    "not defined for this project's stack")
            ruby_stack = SimpleNamespace(sensitivity="webmock_world_v1")
            with _patch.object(bench_cli, "_harness", lambda _args: (ruby_stack, None, None)):
                refuses("a label the project's stack does not define is refused",
                        sensitivity_run("replay", os.path.join(root, "new.jsonl"),
                                        "another_stack_label_v1"),
                        "not defined for this project's stack")
        with _patch.object(bench_cli, "_require_bound_live_worker",
                           lambda _args: contact.__setitem__("worker", contact["worker"] + 1)):
            for flag in ({"publication_v3": True}, {"campaign": "campaign.json"}):
                refuses(f"a sensitivity run is never a publication or campaign run ({sorted(flag)[0]})",
                        lambda flag=flag: bench_cli.cmd_run(SimpleNamespace(
                            **{"publication_v3": False, **flag}, adapter="replay",
                            sensitivity="webmock_world_v1", out=None)),
                        "never a publication or campaign run")
        labelled = os.path.join(root, "labelled.jsonl")
        with open(labelled, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1", "outcome": "passed",
                                 "sensitivity": "webmock_world_v1"}) + "\n")
        refuses("resuming a sensitivity run without its label is refused",
                lambda: _resume_set(labelled, {"model": "m"}, False, False),
                "sensitivity label differs")
        refuses("a sensitivity run never resumes into unlabelled rows",
                lambda: _resume_set(primary, {"sensitivity": "webmock_world_v1"}, False, False),
                "sensitivity label differs")
        check("a sensitivity run resumes its own labelled rows",
              _resume_set(labelled, {"sensitivity": "webmock_world_v1"}, False, False) == {"i1"})
    stamp_args = fake_args()
    stamp_args.sensitivity = "webmock_world_v1"
    check("a sensitivity run stamps its label on every row",
          _run_stamp(stamp_args, SimpleNamespace(name="replay", config={}))
          .get("sensitivity") == "webmock_world_v1"
          and "sensitivity" not in _run_stamp(fake_args(),
                                               SimpleNamespace(name="replay", config={})))
    corrected = {"supplied_helpers": {"internal/update/bdd_update_test.go": ["zipArchive"]},
                 "relisted_contexts": ["Sylius\\Behat\\Context\\Api\\Shop\\RegistrationContext"],
                 "autowired_services": ["app.cart"]}
    for key, value in corrected.items():
        check(f"a row carries the harness-25 field {key} its execution "
              "reported, empty when nothing changed, and a row of a project "
              "without the rule carries none",
              _record("p/f.feature:3", item0, {"files": []}, 0.0,
                      dict(green, **{key: value}))[key] == value
              and _record("p/f.feature:3", item0, {"files": []}, 0.0,
                          dict(green, **{key: type(value)()}))[key] == type(value)()
              and key not in ok_rec)

    # Exercise the flag gate with successfully loaded declarations. Profile
    # validation owns which prompt bytes make each declaration valid; adding
    # a visibility block to the ordinary frozen profile is not a valid one.
    # Check explicit and adjacent resolution independently of that contract.
    from unittest.mock import call, patch
    from ..data import profile as profile_module
    from ..data.profile import DEFAULT_PROFILE_PATH
    with tempfile.TemporaryDirectory(prefix="r2t-submitted-visibility-") as root:
        import shutil
        boundary_path = os.path.join(root, "boundary_coreshop.yml")
        shutil.copyfile(os.path.join(os.path.dirname(DEFAULT_PROFILE_PATH),
                                    "boundary_coreshop.yml"), boundary_path)
        profile_path = os.path.join(root, "profile_coreshop.yml")
        shutil.copyfile(DEFAULT_PROFILE_PATH, profile_path)
        selected_path = os.path.join(root, "profile_selected.yml")
        submitted_contact = {"worker": 0, "harness": 0}
        real_require_worker = bench_cli._require_bound_live_worker
        real_harness = bench_cli._harness
        try:
            bench_cli._require_bound_live_worker = lambda _args: (
                submitted_contact.__setitem__(
                    "worker", submitted_contact["worker"] + 1))
            bench_cli._harness = lambda _args: submitted_contact.__setitem__(
                "harness", submitted_contact["harness"] + 1)
            refuses("a submitted map input refuses before live contact",
                    lambda: bench_cli.cmd_run(SimpleNamespace(
                        publication_v3=False, adapter="submitted",
                        candidates="fixture.jsonl", visibility_map="map.json",
                        _submitted_explicit_options=frozenset())),
                    "--visibility-map", "verification join", "No Docker")
            for scope in ("full", "target_hidden", "all_hidden"):
                for explicit_profile in (True, False):
                    expected_path = (selected_path if explicit_profile
                                     else profile_path)
                    with patch.object(profile_module, "load_profile",
                                      return_value=SimpleNamespace(raw={
                                          "visibility": {"scope": scope,
                                                         "feedback": "final_only"}
                                      })) as loaded:
                        refuses(
                            f"submitted loaded {scope} declaration refuses "
                            f"before contact (explicit={explicit_profile})",
                            lambda explicit_profile=explicit_profile:
                                bench_cli.cmd_run(SimpleNamespace(
                                    publication_v3=False, adapter="submitted",
                                    candidates="fixture.jsonl",
                                    boundary=boundary_path,
                                    profile=(selected_path if explicit_profile
                                             else None),
                                    _submitted_explicit_options=frozenset())),
                            "visibility block", expected_path, "No Docker")
                        check(f"submitted {scope} resolves the selected profile "
                              f"(explicit={explicit_profile})",
                              loaded.call_args_list == [call(expected_path)])

            # When the checkout ships visibility profiles, exercise their
            # real frozen-prompt validation and the complete CLI path too.
            # These are the supported inputs the foundation adds; no test
            # invents a profile that its loader would reject first.
            import glob
            for shipped_path in sorted(glob.glob(os.path.join(
                    profile_module.CONFIG_DIR, "profile_*_visibility_*.yml"))):
                shipped = profile_module.load_profile(shipped_path)
                refuses(
                    f"submitted shipped {os.path.basename(shipped_path)} "
                    "refuses before contact",
                    lambda path=shipped_path, boundary=shipped.boundary_path:
                        cli_module.main([
                            "--boundary", boundary, "run", "--adapter",
                            "submitted", "--profile", path, "--candidates",
                            "fixture.jsonl", "--out", os.path.join(root, "run.jsonl")]),
                    "visibility block", shipped_path, "No Docker")
        finally:
            bench_cli._require_bound_live_worker = real_require_worker
            bench_cli._harness = real_harness
        check("visibility refusals make no worker or harness contact",
              submitted_contact == {"worker": 0, "harness": 0},
              str(submitted_contact))
        submitted_run_flags(fake_args(
            adapter="submitted", candidates="fixture.jsonl",
            boundary=boundary_path, profile=None))
        check("an ordinary adjacent profile remains admitted", True)

    # Decision 7 of the amendment: the bring-up gate is a STAMP, not a
    # refusal.  This lane REWRITES the one that stood here since #195, which
    # proved a fully valid invocation refused unconditionally.  The same
    # kind of fully valid submitted run now proceeds past that gate point
    # with NO environment record at all, and every row it writes says so;
    # the accepted / retired / unaccepted / foreign-pool record states each
    # fold to their specified stamp value.  Driven through the real
    # `_run_adapter_locked` with the fixture harness and `run_one`, exactly
    # as the 422-denominator lane below; the record fixtures go through the
    # lifecycle module's own writer, so the shape the stamp reads is the
    # shape `environment up` mints and `_load_record` accepts.
    import contextlib
    import io
    from . import repo as repo_module
    from ..toolkit.environment import PROJECTS as ENVIRONMENT_PROJECTS
    from ..toolkit.environment_lifecycle import _database_resources
    from ..toolkit.environment_lifecycle import _write_record as write_env_record
    from ..toolkit.environment_lifecycle import record_path as env_record_path

    class StampHarness:
        def __init__(self, root):
            self.root = root
            self.boundary = SimpleNamespace(project="coreshop")
            self.man = None

        def clear_registration(self):
            return None

    def fixture_environment_record(nonce, workers_root, *, state="up",
                                   passed=True):
        return {
            "schema": "r2t.project-environment/v1",
            "project": "coreshop", "nonce": nonce,
            "created_at": "2026-08-25T00:00:00Z", "state": state, "k": 1,
            "workers_root": workers_root, "workdir": "/var/www/html",
            "container_kind": "php",
            "image": {"tag": "coreshop_bench_img:base",
                      "id": "sha256:" + "a" * 64},
            "docker_execution_authority": {
                "path": "/private/authority.json",
                "file_sha256": "b" * 64, "digest": "c" * 64},
            "database": _database_resources(
                ENVIRONMENT_PROJECTS["coreshop"], nonce, 1),
            "gold_control": {
                "item": "coreshop/features/stamp.feature:1",
                "out": os.path.join(workers_root, "..",
                                    "gold-control.jsonl"),
                "outcome": "passed" if passed else "failed",
                "passed": passed},
        }

    def stamp_run_one(_harness, adapter, item, **_kwargs):
        produced = adapter(item)
        return {"item_id": item["item_id"],
                "outcome": ("passed" if produced["metadata"]["submitted"]
                            else "no_files_returned"),
                "metadata": produced["metadata"],
                "produced_files": produced["files"]}

    with tempfile.TemporaryDirectory(prefix="r2t-submitted-stamp-") as root:
        stamp_item_ids = [f"coreshop/features/stamp.feature:{n}"
                          for n in (1, 2, 3)]
        stamp_release = os.path.join(root, "release.jsonl")
        with open(stamp_release, "w", encoding="utf-8") as handle:
            for item_id in stamp_item_ids:
                handle.write(json.dumps({
                    "item_id": item_id, "project": "coreshop"}) + "\n")
        stamp_candidates = os.path.join(root, "candidates.jsonl")
        with open(stamp_candidates, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "item_id": stamp_item_ids[0],
                "produced_files": [{"file_path": "tests/T.php",
                                    "code": "<?php"}],
                "adapter": "external-system"}) + "\n")
        stamp_data_root = os.path.join(root, "data")
        pool = os.path.join(stamp_data_root, "projects", "coreshop",
                            "environments", "efix1", "workers")
        bound_worker = os.path.join(pool, "worker0.json")

        def stamp_rows(worker, out_name):
            args = fake_args(
                adapter="submitted", condition=None, model=None, trials=0,
                shard=0, of=None, release=stamp_release,
                candidates=stamp_candidates, artifacts=root,
                out=os.path.join(root, out_name), item=None, limit=None,
                keep_artifacts=None, no_resume=False, retry_failed=False,
                repro_check=0, timeout=1, worker=worker,
                _submitted_explicit_options=frozenset())
            with contextlib.redirect_stdout(io.StringIO()):
                _run_adapter_locked(StampHarness(root), args, root)
            with open(args.out, encoding="utf-8") as handle:
                return [json.loads(line) for line in handle if line.strip()]

        saved_data_root = os.environ.get("R2T_DATA_ROOT")
        real_run_one = globals()["run_one"]
        real_clean_workspace = repo_module.clean_workspace
        real_registered_ids = globals()["_registered_release_item_ids"]
        try:
            os.environ["R2T_DATA_ROOT"] = stamp_data_root
            globals()["run_one"] = stamp_run_one
            repo_module.clean_workspace = lambda _man, _boundary: []
            globals()["_registered_release_item_ids"] = (
                lambda _project: frozenset(stamp_item_ids))

            no_record_rows = stamp_rows(bound_worker, "no-record.jsonl")
            check("a fully valid submitted run with NO environment record "
                  "proceeds past the retired #195 gate point and stamps "
                  "every row environment_proven false",
                  len(no_record_rows) == 3
                  and all(row["environment_proven"] is False
                          for row in no_record_rows),
                  str([row.get("environment_proven")
                       for row in no_record_rows]))

            write_env_record(env_record_path("coreshop", "efix1"),
                             fixture_environment_record("efix1", pool))
            accepted_rows = stamp_rows(bound_worker, "accepted.jsonl")
            check("an accepted record whose pool contains the bound worker "
                  "stamps every row environment_proven true",
                  len(accepted_rows) == 3
                  and all(row["environment_proven"] is True
                          for row in accepted_rows),
                  str([row.get("environment_proven")
                       for row in accepted_rows]))

            outside_worker = os.path.join(root, "elsewhere", "worker0.json")
            outside_rows = stamp_rows(outside_worker, "outside.jsonl")
            check("a bound worker outside every saved pool stamps false, "
                  "never refuses",
                  all(row["environment_proven"] is False
                      for row in outside_rows),
                  str([row.get("environment_proven")
                       for row in outside_rows]))

            write_env_record(
                env_record_path("coreshop", "efix1"),
                fixture_environment_record("efix1", pool, passed=False))
            unaccepted_rows = stamp_rows(bound_worker, "unaccepted.jsonl")
            check("a record whose gold control did not pass stamps false",
                  all(row["environment_proven"] is False
                      for row in unaccepted_rows),
                  str([row.get("environment_proven")
                       for row in unaccepted_rows]))

            write_env_record(
                env_record_path("coreshop", "efix1"),
                fixture_environment_record("efix1", pool, state="down"))
            retired_rows = stamp_rows(bound_worker, "retired.jsonl")
            check("a retired (state 'down') record stamps false",
                  all(row["environment_proven"] is False
                      for row in retired_rows),
                  str([row.get("environment_proven")
                       for row in retired_rows]))
        finally:
            globals()["run_one"] = real_run_one
            repo_module.clean_workspace = real_clean_workspace
            globals()["_registered_release_item_ids"] = real_registered_ids
            if saved_data_root is None:
                os.environ.pop("R2T_DATA_ROOT", None)
            else:
                os.environ["R2T_DATA_ROOT"] = saved_data_root

    # Candidate validation, project admission and output-path freshness are
    # source-only gates.  Exercise them through cmd_run so the ordering with
    # worker/harness contact is part of the regression.
    with tempfile.TemporaryDirectory(
            prefix="r2t-submitted-precontact-") as root:
        submitted_release = os.path.join(root, "release.jsonl")
        submitted_candidates = os.path.join(root, "candidates.jsonl")
        with open(submitted_release, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "item_id": "known/item:1", "project": "coreshop"}) + "\n")
            handle.write(json.dumps({
                "item_id": "filtered/item:2", "project": "coreshop"}) + "\n")
        submitted_contact = {"worker": 0, "harness": 0}
        candidate_precontact_refusals = {}
        active_project = {"name": "coreshop"}
        real_require_worker = bench_cli._require_bound_live_worker
        real_harness = bench_cli._harness
        real_boundary = bench_cli._boundary
        from ..data import release as release_module
        real_admit_pre_execution = release_module.admit_pre_execution

        def submitted_cli_args():
            return SimpleNamespace(
                publication_v3=False, adapter="submitted",
                candidates=submitted_candidates, release=submitted_release,
                condition=None, _submitted_explicit_options=frozenset(),
                artifacts=root, out=None, item=None, shard=0, of=None)

        def fixture_admit(items, project, requested=()):
            rows = list(items)
            if project == "coreshop":
                rows = [row for row in rows
                        if row["item_id"] != "filtered/item:2"]
            return rows, {"fixture": True}

        # This lane is about the ORDERING of the other source-only gates
        # against live contact, so the gate that would fire first on a
        # fixture — the registered-release pin (tested below on the real
        # registered ids) — is fixtured out of the way here.  It is patched
        # on the IMPORTED module: under `python3 -m r2t.bench.runner` this file
        # runs as `__main__` while `cmd_run` re-imports `r2t.bench.runner`, so
        # this function's own globals are a different copy.
        from . import runner as runner_module
        real_registered_ids = runner_module._registered_release_item_ids
        try:
            runner_module._registered_release_item_ids = (
                lambda _project: frozenset({"known/item:1"}))
            bench_cli._require_bound_live_worker = lambda _args: (
                submitted_contact.__setitem__(
                    "worker", submitted_contact["worker"] + 1))
            bench_cli._harness = lambda _args: submitted_contact.__setitem__(
                "harness", submitted_contact["harness"] + 1)
            bench_cli._boundary = lambda _args: SimpleNamespace(
                project=active_project["name"])
            release_module.admit_pre_execution = fixture_admit
            invalid_candidates = {
                "not_admitted": {
                    "item_id": "filtered/item:2", "produced_files": [],
                    "adapter": "external-system",
                },
                "unknown_key": {
                    "item_id": "known/item:1", "produced_files": [],
                    "adapter": "external-system", "outcome": "passed",
                },
            }
            for label, candidate in invalid_candidates.items():
                with open(submitted_candidates, "w",
                          encoding="utf-8") as handle:
                    handle.write(json.dumps(candidate) + "\n")
                try:
                    bench_cli.cmd_run(submitted_cli_args())
                    candidate_precontact_refusals[label] = ""
                except SystemExit as exc:
                    candidate_precontact_refusals[label] = str(exc)

            active_project["name"] = "epubcheck"
            with open(submitted_candidates, "w",
                      encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "item_id": "known/item:1", "produced_files": [],
                    "adapter": "external-system",
                }) + "\n")
            try:
                bench_cli.cmd_run(submitted_cli_args())
                candidate_precontact_refusals["project"] = ""
            except SystemExit as exc:
                candidate_precontact_refusals["project"] = str(exc)

            active_project["name"] = "coreshop"
            runs_dir = os.path.join(root, "runs")
            os.makedirs(runs_dir)
            existing_out = os.path.join(
                runs_dir, "submitted_external-system.jsonl")
            with open(existing_out, "w", encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "item_id": "known/item:1",
                    "adapter": "submitted:external-system",
                    "produced_files": [{
                        "file_path": "tests/T.php", "code": "revision one",
                    }],
                }) + "\n")
            with open(submitted_candidates, "w",
                      encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "item_id": "known/item:1",
                    "adapter": "external-system",
                    "produced_files": [{
                        "file_path": "tests/T.php", "code": "revision two",
                    }],
                }) + "\n")
            try:
                bench_cli.cmd_run(submitted_cli_args())
                candidate_precontact_refusals["existing_output"] = ""
            except SystemExit as exc:
                candidate_precontact_refusals["existing_output"] = str(exc)
        finally:
            runner_module._registered_release_item_ids = real_registered_ids
            bench_cli._require_bound_live_worker = real_require_worker
            bench_cli._harness = real_harness
            bench_cli._boundary = real_boundary
            release_module.admit_pre_execution = real_admit_pre_execution
    check("submitted IDs are checked against the admitted population before "
          "live contact",
          "filtered/item:2" in candidate_precontact_refusals["not_admitted"]
          and "not in the admitted population" in
          candidate_precontact_refusals["not_admitted"]
          and "unknown keys ['outcome']" in candidate_precontact_refusals[
              "unknown_key"]
          and submitted_contact == {"worker": 0, "harness": 0},
          f"messages={candidate_precontact_refusals}, "
          f"contact={submitted_contact}")
    check("submitted evaluation is literally two-project — a third project "
          "refuses by name before live contact",
          "approved only for the admitted projects" in
          candidate_precontact_refusals["project"]
          and "'coreshop' and 'python-docx'" in
          candidate_precontact_refusals["project"]
          and "epubcheck" in candidate_precontact_refusals["project"]
          and submitted_contact == {"worker": 0, "harness": 0},
          f"messages={candidate_precontact_refusals}, "
          f"contact={submitted_contact}")
    check("a revised same-name submission refuses its resolved existing "
          "output before live contact",
          "output path already exists" in
          candidate_precontact_refusals["existing_output"]
          and "submitted_external-system.jsonl" in
          candidate_precontact_refusals["existing_output"]
          and submitted_contact == {"worker": 0, "harness": 0},
          f"messages={candidate_precontact_refusals}, "
          f"contact={submitted_contact}")

    # The release itself is a validated input, not merely a row source:
    # empty refuses, a row from another project refuses by name, and the
    # id set is pinned to the REGISTERED full release so a submitter cannot
    # hand a subset release and choose their own denominator — the exact
    # thing `submitted_run_flags` fixes on the flag side.
    submitted_release_args = fake_args(
        adapter="submitted", candidates="fixture.jsonl")
    refuses("a submitted run over an empty admitted release refuses before "
            "contact",
            lambda: validate_submitted_project(
                submitted_release_args, "coreshop", []),
            "REFUSED", "no denominator", "No Docker")
    refuses("a foreign-project release row is refused naming the row",
            lambda: validate_submitted_project(
                submitted_release_args, "coreshop",
                [{"item_id": "known/item:1", "project": "coreshop"},
                 {"item_id": "docx/item:2", "project": "python-docx"}]),
            "REFUSED", "docx/item:2", "python-docx", "No Docker")
    registered_rows = [
        {"item_id": item_id, "project": "coreshop"}
        for item_id in sorted(_registered_release_item_ids("coreshop"))]
    try:
        validate_submitted_project(
            submitted_release_args, "coreshop", registered_rows)
        full_release_admitted = True
    except SystemExit as exc:
        full_release_admitted = str(exc)
    check("the registered full release passes the identity pin",
          full_release_admitted is True, str(full_release_admitted))
    refuses("a subset release is refused by the registered-release pin",
            lambda: validate_submitted_project(
                submitted_release_args, "coreshop", registered_rows[:-1]),
            "REFUSED", "registered", "denominator", "No Docker")
    # The second admitted project (amendment decision 6): python-docx passes
    # the admission literal, and its registered-release pin resolves the
    # real 239-item release from `release/dataset_manifest.json`.
    docx_registered = _registered_release_item_ids("python-docx")
    docx_rows = [{"item_id": item_id, "project": "python-docx"}
                 for item_id in sorted(docx_registered)]
    try:
        validate_submitted_project(
            submitted_release_args, "python-docx", docx_rows)
        docx_admitted = True
    except SystemExit as exc:
        docx_admitted = str(exc)
    check("python-docx passes the admission literal and its registered "
          "239-item release resolves from the dataset manifest",
          docx_admitted is True and len(docx_registered) == 239,
          f"admitted={docx_admitted}, n={len(docx_registered)}")

    captured_cli = []
    real_cmd_run = bench_cli.cmd_run
    real_worker_spec = bench_cli._worker_spec
    try:
        bench_cli.cmd_run = lambda args: captured_cli.append(args) or 0
        cli_module.main([
            "run", "--adapter", "submitted", "--candidates", "fixture.jsonl",
            "--tri", "0",
        ])
        parsed_trials = captured_cli[-1]

        bench_cli._worker_spec = lambda _args: SimpleNamespace(
            index=3, workspace="/fixture/workspace", container="fixture-c3",
            workdir="/app", out_path=None)
        cli_module.main([
            "--worker", "fixture-worker.json", "run", "--adapter",
            "submitted", "--candidates", "fixture.jsonl",
        ])
        parsed_worker = captured_cli[-1]
    finally:
        bench_cli.cmd_run = real_cmd_run
        bench_cli._worker_spec = real_worker_spec
    check("the CLI records an explicit zero trial budget by occurrence",
          parsed_trials.trials == 0
          and parsed_trials._submitted_explicit_options == {"--trials"},
          str(parsed_trials._submitted_explicit_options))
    check("worker binding injects its shard after explicit-option capture",
          parsed_worker.shard == 3
          and "--shard" not in parsed_worker._submitted_explicit_options,
          f"shard={parsed_worker.shard}, "
          f"explicit={parsed_worker._submitted_explicit_options}")

    # Submitted bytes are inputs, just like replay bytes.  Pass their path to
    # the worker containment preflight so a candidate file cannot live below
    # the mutable workspace that is reset for an evaluation.
    from . import worker as worker_module
    candidate_inside_workspace = "/fixture/workspace/candidates.jsonl"
    captured_protected = []
    real_worker_spec = bench_cli._worker_spec
    real_stack_profile = bench_cli._stack_profile
    real_default_answers = worker_module.default_answer_paths
    real_validate_runtime = worker_module.validate_live_worker_runtime
    try:
        bench_cli._worker_spec = lambda _args: SimpleNamespace(index=0)
        bench_cli._stack_profile = lambda _args: SimpleNamespace(
            needs_database=False, project="python-docx")
        worker_module.default_answer_paths = lambda *_args: []
        worker_module.validate_live_worker_runtime = (
            lambda *pos, **_kw: captured_protected.extend(pos[4]) or {})
        bench_cli._require_bound_live_worker(SimpleNamespace(
            cmd="run", worker="fixture-worker.json", shard=0,
            worker_manifest=None, campaign=None, of=None,
            gold="/fixture/gold", artifacts="/fixture/artifacts",
            # The boundary/repo pair every parsed namespace carries: the
            # live worker validation reads the project's Behat row from it.
            boundary=bench_cli.DEFAULT_BOUNDARY, repo=None,
            profile=None, release="/fixture/release.jsonl",
            out="/fixture/out.jsonl", keep_artifacts=None, replay=None,
            candidates=candidate_inside_workspace, trajectory_dir=None,
            llm_config=None))
    finally:
        bench_cli._worker_spec = real_worker_spec
        bench_cli._stack_profile = real_stack_profile
        worker_module.default_answer_paths = real_default_answers
        worker_module.validate_live_worker_runtime = real_validate_runtime
    check("submitted candidate bytes enter worker containment preflight",
          candidate_inside_workspace in captured_protected,
          str(captured_protected))

    from ..java.algorand import load_exclusion_policy
    blocked_id = load_exclusion_policy()["item_ids"][0]
    with tempfile.TemporaryDirectory(prefix="r2t-runner-exclusion-") as root:
        release_path = os.path.join(root, "items.jsonl")
        with open(release_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": blocked_id}) + "\n")
        blocked_args = fake_args(
            adapter="not-a-real-adapter", release=release_path,
            item=(blocked_id,), limit=None, out=None, shard=None, of=None)
        blocked_harness = SimpleNamespace(
            boundary=SimpleNamespace(project="algorand-sdk"))
        try:
            _run_adapter_locked(blocked_harness, blocked_args, root)
        except SystemExit as exc:
            blocked_message = str(exc)
        else:
            blocked_message = ""
        check("a requested live-service item is refused before adapter "
              "construction",
              "needs_live_algod" in blocked_message
              and "unknown adapter" not in blocked_message,
              blocked_message)

    # The submitted adapter is still scored by the one normal item loop.  A
    # ten-row candidate file over a 422-item release therefore writes 412
    # measured empty answers, rather than choosing its own denominator.
    import contextlib
    import io
    from . import repo as repo_module, results as results_module
    with tempfile.TemporaryDirectory(prefix="r2t-runner-submitted-") as root:
        release_path = os.path.join(root, "items.jsonl")
        item_ids = [
            f"coreshop/features/submitted.feature:{number}"
            for number in range(1, 423)
        ]
        with open(release_path, "w", encoding="utf-8") as handle:
            for item_id in item_ids:
                handle.write(json.dumps({
                    "item_id": item_id, "project": "coreshop"}) + "\n")
        candidates_path = os.path.join(root, "candidates.jsonl")
        with open(candidates_path, "w", encoding="utf-8") as handle:
            for index, item_id in enumerate(item_ids[:10]):
                metadata = ({
                    "driver_error": "external diagnostic",
                    "agent_stats": {"run_errors": ["external retry"]},
                } if index == 0 else {})
                handle.write(json.dumps({
                    "item_id": item_id,
                    "produced_files": [{
                        "file_path": f"tests/T{index}.php", "code": "<?php"}],
                    "adapter": "external-system", "metadata": metadata,
                }) + "\n")

        class SubmittedHarness:
            def __init__(self):
                self.root = root
                self.boundary = SimpleNamespace(project="coreshop")
                self.man = None

            def clear_registration(self):
                return None

        submitted_args = fake_args(
            adapter="submitted", condition=None, model=None, trials=0,
            shard=3, of=None, release=release_path,
            candidates=candidates_path, artifacts=root,
            out=os.path.join(root, "submitted-run.jsonl"), item=None,
            limit=None, keep_artifacts=None, no_resume=False,
            retry_failed=False, repro_check=0, timeout=1,
            _submitted_explicit_options=frozenset())

        real_run_one = globals()["run_one"]
        real_clean_workspace = repo_module.clean_workspace
        real_registered_ids = globals()["_registered_release_item_ids"]

        def submitted_run_one(_harness, adapter, item, **_kwargs):
            produced = adapter(item)
            answered = produced["metadata"]["submitted"]
            return {
                "item_id": item["item_id"],
                "outcome": "passed" if answered else "no_files_returned",
                "metadata": produced["metadata"],
                "produced_files": produced["files"],
            }

        try:
            globals()["run_one"] = submitted_run_one
            repo_module.clean_workspace = lambda _man, _boundary: []
            globals()["_registered_release_item_ids"] = (
                lambda _project: frozenset(item_ids))
            with contextlib.redirect_stdout(io.StringIO()):
                submitted_info = _run_adapter_locked(
                    SubmittedHarness(), submitted_args, root)

            # A bare --out FILENAME resolves against the working directory
            # instead of dying in `os.makedirs("")`.  Chdir so "resolves
            # against the working directory" is what is actually exercised.
            bare_out_args = fake_args(
                adapter="submitted", condition=None, model=None, trials=0,
                shard=3, of=None, release=release_path,
                candidates=candidates_path, artifacts=root,
                out="bare-run.jsonl", item=None, limit=None,
                keep_artifacts=None, no_resume=False, retry_failed=False,
                repro_check=0, timeout=1,
                _submitted_explicit_options=frozenset())
            previous_cwd = os.getcwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    bare_out_info = _run_adapter_locked(
                        SubmittedHarness(), bare_out_args, root)
            finally:
                os.chdir(previous_cwd)
        finally:
            globals()["run_one"] = real_run_one
            repo_module.clean_workspace = real_clean_workspace
            globals()["_registered_release_item_ids"] = real_registered_ids

        with open(submitted_args.out, encoding="utf-8") as handle:
            submitted_rows = {
                row["item_id"]: row
                for row in (json.loads(line) for line in handle if line.strip())
            }
        submitted_ladder = results_module.ladder(submitted_rows)
        first_row = submitted_rows[item_ids[0]]
        check("a partial submission executes the full 422-item denominator",
              submitted_info["submitted"] == 10
              and submitted_info["release"] == 422
              and submitted_info["n"] == 422
              and len(submitted_rows) == 422
              and submitted_ladder["denominator"] == 422
              and submitted_info["outcomes"] == {
                  "passed": 10, "no_files_returned": 412},
              f"info={submitted_info}, ladder={submitted_ladder}")
        check("submitted rows carry their fixed tier and no protocol claim",
              submitted_args.condition == "submitted"
              and all(row.get("condition") == "submitted"
                      and "protocol_version" not in row
                      and "protocol_digest" not in row
                      for row in submitted_rows.values()))
        check("external error-shaped metadata stays in the denominator",
              first_row["metadata"] == {
                  "submitted": True,
                  "submitted_metadata": {
                      "driver_error": "external diagnostic",
                      "agent_stats": {"run_errors": ["external retry"]},
                  },
              }
              and results_module.infrastructure_marker(first_row) is None,
              str(first_row["metadata"]))
        check("a bare --out filename completes and lands in the working "
              "directory",
              bare_out_info["n"] == 422
              and os.path.isfile(os.path.join(root, "bare-run.jsonl")),
              str(bare_out_info))
        check("submitted rows claim no execution channel and no model -- "
              "`trials` absent, `model` null",
              all("trials" not in row and row.get("model") is None
                  for row in submitted_rows.values()),
              str({k: first_row.get(k) for k in ("trials", "model")}))

    fake_adapter = SimpleNamespace(
        name="openhands:deepseek",
        # An agent adapter is BUILT confined -- `agents.registry` passes
        # `sandbox=True` as a constant and `make_agent_adapter` records it
        # here -- and this is where `_run_stamp` reads the row's `sandboxed`
        # from, because there is no flag left to read.
        config={"agent_command_mode": "builtin", "sandboxed": True})
    fixture_adapter = SimpleNamespace(name="gold", config={})

    # -- the stamp says what the run WAS: its trial budget, and the
    #    confinement the thing that produced the rows was built with.
    stamp = _run_stamp(fake_args(), fake_adapter)
    check("the stamp records the trial budget and the confinement the "
          "adapter was built with",
          stamp["trials"] == 5 and stamp["sandboxed"] is True, str(stamp))
    check("a fixture transport launches nothing, carries no such config key "
          "and still stamps sandboxed=false -- the same value the flag used "
          "to produce for it",
          _run_stamp(fake_args(adapter="gold"),
                     fixture_adapter)["sandboxed"] is False)
    custom_adapter = SimpleNamespace(
        name="openhands:fixture",
        config={"agent_command_mode": "custom_ad_hoc"})
    check("a custom agent command is labelled ad hoc on every new row",
          _run_stamp(fake_args(), custom_adapter)["agent_command_mode"]
          == "custom_ad_hoc")
    check("a shard relaunched without --trials is no longer indistinguishable",
          _run_stamp(fake_args(trials=0), fake_adapter)["trials"] == 0)
    # The unbounded budget is a THIRD value on the row, not a null and not a
    # zero. The agent's executions are bounded by its iteration budget now
    # (`trials.py`), and a row that recorded that as 0 would be
    # indistinguishable from the C2-equivalent control, while a row that
    # recorded it as null would be indistinguishable from a row that predates
    # the field.
    # The sentinel itself is WIRE vocabulary and lives in `core.constants`
    # (`agents.trials` only re-exports it), so this name -- used by legs
    # scattered through the rest of this self-test -- needs no agent component
    # and no guard.
    from ..core.constants import UNBOUNDED
    for spelling in (UNBOUNDED, "UNLIMITED", " unlimited "):
        check(f"--trials {spelling!r} is stamped as the unbounded sentinel",
              _run_stamp(fake_args(trials=spelling),
                         fake_adapter)["trials"] == UNBOUNDED,
              str(_run_stamp(fake_args(trials=spelling), fake_adapter)["trials"]))
    check("an unbounded run is distinguishable from 0 and from a count",
          len({_run_stamp(fake_args(trials=t), fake_adapter)["trials"]
               for t in (0, 5, UNBOUNDED)}) == 3)

    # -- the identity half (WS1): what this row can be CITED as.  All three
    #    fields are the registry's answer (`_identity_fields` reaches it
    #    through `_spec_of`), so without the agent component there is no
    #    system to name and the fixture contrast has nothing to contrast with.
    try:
        from ..agents import registry as _reg_identity   # noqa: F401
    except ImportError:
        print("  [SKIP] the stamped-identity legs: `agent_system`, "
              "`adapter_version` and `comparison_class` come from the "
              "adapter registry, and this checkout has no agent component")
    else:
        check("the stamp names the SYSTEM and our configuration of it, not "
              "only the built adapter's label",
              stamp["agent_system"] == "openhands"
              and stamp["adapter_version"] == "openhands@2"
              and stamp["adapter"] == "openhands:deepseek", str(stamp))
        check("...and the population its rows may be pooled with",
              stamp["comparison_class"] == "fixed_model_scaffold", str(stamp))
        check("a CONTROL declares no comparison class -- a fixture's rows are "
              "not a system's rows",
              "comparison_class" not in _run_stamp(fake_args(adapter="gold"),
                                                   fake_adapter), str(stamp))
    # DERIVED from the manifest, not typed here.  This read `== "1.0"` until
    # the dataset moved to 1.1 (a second project shipped beside the frozen v1
    # files), and a literal would have made a documented, additive bump look
    # like a regression in a check that is not about WHICH version it is.  The
    # two properties that matter survive: the stamp READS `VERSIONS.yml`
    # rather than carrying its own copy, and it stamps a STRING — an unquoted
    # `1.1` in YAML parses as a float, and a float on a row is a citation
    # nobody can match against the manifest.
    from ..data.versions import component as _dataset_component
    _declared = str(_dataset_component("dataset")["version"])
    check("the dataset version is the manifest's, stamped as a string",
          stamp.get("dataset_version") == _declared
          and isinstance(stamp.get("dataset_version"), str),
          f"{stamp.get('dataset_version')!r} vs manifest {_declared!r}")
    # `harness_version` says WHICH SEMANTIC executor; `harness_commit` says
    # which bytes. Absent (not "unknown") outside a git checkout.
    check("harness_commit is a short commit or is ABSENT, never a sentinel",
          ("harness_commit" not in stamp
           or (isinstance(stamp["harness_commit"], str)
               and 7 <= len(stamp["harness_commit"]) <= 12)),
          str(stamp.get("harness_commit")))
    check("agent_version is a probed string or is ABSENT, never a guess",
          ("agent_version" not in stamp
           or (isinstance(stamp["agent_version"], str)
               and stamp["agent_version"].startswith("openhands-sdk@"))),
          str(stamp.get("agent_version")))
    # The subset identity binds only when the items file has a sidecar that
    # still matches its bytes; `release/release.jsonl` in the fixture has
    # neither, so nothing is stamped rather than a basename being invented.
    check("a run over an unidentifiable items file stamps NO subset -- a "
          "citable-looking label on unlabelled items is worse than a `?`",
          "subset_id" not in stamp and "subset_digest" not in stamp,
          str(stamp))
    real_subset = os.path.join(RELEASE_DIR, "eval100.jsonl")
    if os.path.isfile(real_subset):
        st_sub = _run_stamp(fake_args(release=real_subset), fake_adapter)
        check("...and the published subset DOES bind, by content",
              st_sub.get("subset_id") == "eval100"
              and len(st_sub.get("subset_digest") or "") == 16,
              str({k: st_sub.get(k) for k in ("subset_id", "subset_digest")}))
    check("no protocol field appears without --protocol: absence says 'this "
          "run followed no protocol', a null would say 'it lost the value'",
          not any(k in stamp for k in ("protocol_version", "protocol_digest",
                                       "protocol_deviations")), str(stamp))
    st_p = _run_stamp(fake_args(protocol_version=2,
                                protocol_digest="09d5fc7d2fd6a3ec",
                                protocol_deviations=["temperature: x"]),
                      fake_adapter)
    check("with a protocol, the version, the digest and any deviations are "
          "all on the row",
          st_p["protocol_version"] == 2
          and st_p["protocol_digest"] == "09d5fc7d2fd6a3ec"
          and st_p["protocol_deviations"] == ["temperature: x"], str(st_p))
    check("an EMPTY deviation list is absent, not an empty list -- a row that "
          "deviated in nothing should not carry the question",
          "protocol_deviations" not in _run_stamp(
              fake_args(protocol_version=2,
                        protocol_digest="09d5fc7d2fd6a3ec",
                        protocol_deviations=[]), fake_adapter))
    # THE SETTING IS STAMPED, not merely asserted in a file. Both protocol
    # files claim it is ("v2 stamps it"), and a claim in a document nobody
    # opens is how a cold-start arm and a warm-context arm end up in one
    # table with nothing in the rows to separate them.
    try:
        from ..agents import protocol as _P_setting     # noqa: F401
    except ImportError:
        print("  [SKIP] the stamped-setting legs: `setting` is read out of "
              "the protocol DOCUMENT, which is the agent component's, and "
              "this checkout does not ship it")
    else:
        check("a --protocol run carries the setting the recipe claims, read "
              "out of the protocol DOCUMENT rather than out of a flag",
              st_p.get("setting") == "cold_start", str(st_p.get("setting")))
        check("...and a protocol-less run stamps no setting at all -- it "
              "followed no recipe, so it makes no claim about what it was "
              "given",
              "setting" not in stamp, str(stamp.get("setting")))
        check("a row whose protocol_digest does not match the file on disk "
              "gets NO setting: a claim from a recipe this run did not follow "
              "is worse than a `?`",
              "setting" not in _run_stamp(
                  fake_args(protocol_version=2, protocol_digest="0" * 16),
                  fake_adapter))
    # THE PRIMARY BUDGET IS STAMPED under a protocol. protocol_v1 records
    # that no archived row carries the wall-clock envelope and says "Protocol
    # v2 stamps it" -- this pair of checks is what keeps that sentence true.
    check("a --protocol run stamps the wall-clock envelope it ran under",
          _run_stamp(fake_args(protocol_version=2,
                               protocol_digest="09d5fc7d2fd6a3ec",
                               agent_timeout=3600),
                     fake_adapter).get("agent_timeout_seconds") == 3600)
    check("...and a protocol-less run does not -- the flag existed, but no "
          "recipe asked for it to be citable",
          "agent_timeout_seconds" not in _run_stamp(
              fake_args(agent_timeout=3600), fake_adapter))
    # The stamp as it stood before WS1, written out as a literal: this is the
    # set every archived row on disk can be expected to carry, and the check
    # below is what makes "a new field must be grandfathered" mechanical
    # rather than a thing a reviewer has to remember.
    pre_ws1 = {"adapter", "condition", "model", "coverage", "repeats",
               "max_iterations", "max_tokens", "temperature", "trials",
               "sandboxed", "prompt_digest", "harness_version",
               "campaign_digest", "shard", "of"}
    check("every stamp field added since is registered in "
          "STAMP_OPTIONAL_FIELDS, or the day it lands every in-flight "
          "campaign refuses to resume",
          set(st_p) - pre_ws1 <= set(STAMP_OPTIONAL_FIELDS),
          str(sorted(set(st_p) - pre_ws1 - set(STAMP_OPTIONAL_FIELDS))))
    with tempfile.TemporaryDirectory() as root:
        from .campaign import (SHARD_RULE, campaign_digest,
                               campaign_fingerprint, generation_fingerprint)
        made: list[str] = []

        def campaign_file(**over) -> str:
            fp = dict(campaign_id="c3-sweep", k_workers=4,
                      shard_rule=SHARD_RULE, trial_budget=5, coverage=False,
                      condition="c3",
                      harness_version="v1", config_digest="cfg0123456789ab",
                      model="deepseek-chat",
                      protocol_version=None, protocol_digest=None,
                      container_image_digest="sha256:aa",
                      workspace_seed_digest="ws0123456789abcd",
                      database_dump_digest="db0123456789abcd")
            fp.update(over)
            p = os.path.join(root, f"campaign{len(made)}.json")
            made.append(p)
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(campaign_fingerprint(**fp), fh)
            return p

        cf = campaign_file()
        with open(cf, encoding="utf-8") as fh:
            digest = campaign_digest(json.load(fh))
        st = _run_stamp(fake_args(campaign=cf),
                        fake_adapter)
        check("a run whose flags match its campaign is stamped with its digest",
              st["campaign_digest"] == digest and st["shard"] == 0
              and st["of"] == 4, str(st.get("campaign_digest")))
        swap_cf = campaign_file()
        with open(swap_cf, encoding="utf-8") as fh:
            pinned_doc = json.load(fh)
        pinned_digest = campaign_digest(pinned_doc)
        pinned_args = fake_args(campaign=swap_cf)
        pinned_args._validated_campaign_document = pinned_doc
        pinned_args._validated_campaign_digest = pinned_digest
        pinned_args._validated_campaign_path = os.path.abspath(swap_cf)
        with open(swap_cf, "w", encoding="utf-8") as fh:
            json.dump(campaign_fingerprint(**{
                **pinned_doc, "container_image_digest": "sha256:changed"}),
                fh)
        pinned_stamp = _run_stamp(pinned_args, fake_adapter)
        check("a campaign path replacement after validation cannot change "
              "the row's pinned campaign identity",
              pinned_stamp["campaign_digest"] == pinned_digest)

        # Reproducible-v1 runtime identity is additive.  New v2 rows quote
        # the validated manifest digest, while a released row that predates
        # the field remains byte-for-byte untouched and resumable.
        runtime_fp = generation_fingerprint(
            campaign_id="runtime-sweep", k_workers=4,
            shard_rule=SHARD_RULE, trial_budget=5, condition="c3",
            coverage=False, harness_version="v1",
            config_digest="cfg0123456789ab", model="deepseek-chat",
            container_image_digest="sha256:aa",
            workspace_seed_digest="ws0123456789abcd",
            database_dump_digest="db0123456789abcd",
            protocol_version=None, protocol_digest=None, agent_system=None,
            attempt_id="runtime-attempt", harness_commit="a" * 40,
            harness_source_sha256="b" * 64,
            agent_runtime_sha256="c" * 64,
            network_semantics="fixture")
        runtime_cf = os.path.join(root, "runtime-campaign.json")
        with open(runtime_cf, "w", encoding="utf-8") as fh:
            json.dump(runtime_fp, fh)
        runtime_stamp = _run_stamp(
            fake_args(campaign=runtime_cf), fake_adapter)
        check("new campaign rows carry the validated runtime identity",
              runtime_stamp["agent_runtime_sha256"] == "c" * 64)
        released_path = os.path.join(root, "released-row.jsonl")
        released = dict(runtime_stamp, item_id="released", outcome="passed")
        released.pop("agent_runtime_sha256")
        released_before = dict(released)
        with open(released_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(released) + "\n")
        resumed = _resume_set(released_path, runtime_stamp,
                              retry_failed=False, no_resume=False)
        check("the additive runtime field does not restamp or invalidate a "
              "released row",
              resumed == {"released"} and released == released_before
              and "agent_runtime_sha256" not in released, str(released))
        refuses("a shard relaunched without --trials is refused before item 1",
                lambda: _run_stamp(fake_args(campaign=cf, trials=0),
                                   fake_adapter),
                "REFUSED", "trial_budget=5", "--trials 0")
        refuses("a coverage flag the campaign does not declare is refused",
                lambda: _run_stamp(fake_args(campaign=cf, coverage=True),
                                   fake_adapter),
                "REFUSED", "coverage")
        refuses("a condition the campaign does not declare is refused",
                lambda: _run_stamp(fake_args(campaign=cf, condition="c2"),
                                   fake_adapter),
                "REFUSED", "condition")
        refuses("an explicit null condition means control, not unconstrained",
                lambda: _run_stamp(fake_args(
                    campaign=campaign_file(condition=None), condition="c3"),
                    fake_adapter),
                "REFUSED", "condition=None")
        refuses("an explicit null protocol pair refuses a protocol run",
                lambda: _run_stamp(fake_args(
                    campaign=cf, protocol_version=2,
                    protocol_digest="09d5fc7d2fd6a3ec"), fake_adapter),
                "REFUSED", "protocol_version=None")
        refuses("a campaign shard rule this runner cannot implement refuses",
                lambda: _run_stamp(fake_args(
                    campaign=campaign_file(shard_rule="unknown-rule")),
                    fake_adapter),
                "REFUSED", "shard_rule")
        refuses("a model the campaign does not name is refused",
                lambda: _run_stamp(fake_args(campaign=cf, model="gpt-5"),
                                   fake_adapter),
                "REFUSED", "model", "deepseek-chat")
        refuses("a K the campaign was not provisioned for is refused",
                lambda: _run_stamp(fake_args(campaign=cf, of=3, shard=1),
                                   fake_adapter),
                "REFUSED", "k_workers=4", "--of 3")
        check("a campaign that names no model constrains nothing",
              _run_stamp(fake_args(campaign=campaign_file(model=None),
                                   model="anything"),
                         fake_adapter)["model"] == "anything")

        # -- WHICH SYSTEM, at launch (Slice 1).
        #
        # The merge half is `campaign._crosscheck_row`; this is the half that
        # fires before item 1, because the merge runs hours after the money is
        # spent. A campaign that names its system demands the run BE it; a
        # campaign that names none constrains nothing, which is what every
        # archived campaign is.
        try:
            from ..agents import registry as _reg_launch    # noqa: F401
        except ImportError:
            print("  [SKIP] the campaign agent_system legs: a campaign names "
                  "a system the REGISTRY resolves, and this checkout has no "
                  "agent component")
        else:
            oh_cf = campaign_file(agent_system="openhands")
            check("a shard whose adapter IS the campaign's system is stamped",
                  _run_stamp(fake_args(campaign=oh_cf),
                             fake_adapter)["agent_system"] == "openhands")
            # THE SOURCE-GREP THAT WAS HERE IS GONE.  It asserted that
            # `_check_campaign_flags` no longer mentions `--sandbox-agent`, which
            # was worth asserting while that flag existed somewhere else in the
            # package and could have been re-read here.  The flag exists nowhere
            # now, so the grep can no longer tell one state of this file from
            # another.  What it protected -- one confinement mechanism, on every
            # route -- is exercised where it lives: `agent_confinement_selftest`
            # section 3 builds every registered agent spec through
            # `build_adapter` and reads what the builder was handed.
            refuses("a custom command cannot enter a publication campaign",
                    lambda: _run_stamp(
                        fake_args(campaign=cf),
                        custom_adapter),
                    "REFUSED", "custom_ad_hoc", "publication campaign")
            refuses("a shard of another system is refused before item 1, not "
                    "discovered at merge",
                    lambda: _run_stamp(fake_args(campaign=oh_cf, adapter="aider"),
                                       fake_adapter),
                    "REFUSED", "agent_system='openhands'")
            refuses("...and so is a fixture transport: `gold` is not a system, "
                    "and a row that cannot say which system produced it must not "
                    "carry a campaign that asserts one",
                    lambda: _run_stamp(fake_args(campaign=oh_cf, adapter="gold"),
                                       fake_adapter),
                    "REFUSED", "agent_system='openhands'")
            check("a campaign that names no system constrains nothing -- every "
                  "archived campaign is one",
                  _run_stamp(fake_args(campaign=campaign_file(), adapter="gold"),
                             fake_adapter).get("agent_system") is None)
            check("agent_system_of reads the REGISTRY, so no flag can relabel a "
                  "row: a bare declaration is used only where there is no adapter "
                  "to derive it from (`r2t campaign`)",
                  agent_system_of(fake_args()) == "openhands"
                  and agent_system_of(fake_args(adapter="openhands",
                                                agent_system="aider"))
                  == "openhands"
                  and agent_system_of(SimpleNamespace(agent_system="aider"))
                  == "aider"
                  and agent_system_of(SimpleNamespace()) is None)

        # -- THE NATIVE BUDGET, on the row.
        #
        # 100 iterations and 10 reflections are not the same allowance, and a
        # cross-system table is unreadable unless each row says which it had.
        try:
            from ..agents import protocol as _P_budget      # noqa: F401
        except ImportError:
            print("  [SKIP] the native-budget legs: the native knob vocabulary "
                  "is the agent protocol's, and this checkout has no agent "
                  "component")
        else:
            for token_cap in (64000, 23):
                for name, expected_iterations, expected_budget in (
                        ("openhands", 100, {"max_iterations": 100}),
                        ("aider", None, {"max_reflections": 10})):
                    native_args = fake_args(
                        adapter=name, max_tokens=token_cap,
                        max_iterations=100, max_reflections=10)
                    native_adapter = SimpleNamespace(
                        name=name, config=fake_adapter.config)
                    native_stamp = _run_stamp(native_args, native_adapter)
                    check(f"{name} stamps only its effective native knobs "
                          f"with unrelated --max-tokens {token_cap}",
                          native_stamp["max_tokens"] is None
                          and native_stamp["max_iterations"]
                          == expected_iterations
                          and native_stamp["native_budget"] == expected_budget,
                          str({key: native_stamp.get(key) for key in
                               ("max_tokens", "max_iterations", "native_budget")}))
                prompt_stamp = _run_stamp(fake_args(
                    adapter="openai", max_tokens=token_cap, max_iterations=100),
                    SimpleNamespace(name="openai:deepseek", config={}))
                check(f"single-shot rows keep their completion budget {token_cap}",
                      prompt_stamp["max_tokens"] == token_cap
                      and prompt_stamp["max_iterations"] == 100
                      and "native_budget" not in prompt_stamp,
                      str({key: prompt_stamp.get(key) for key in
                           ("max_tokens", "max_iterations", "native_budget")}))
            nb = _run_stamp(fake_args(max_iterations=100), fake_adapter)
            check("an openhands row records its native budget as the value in "
                  "force",
                  nb["native_budget"] == {"max_iterations": 100},
                  str(nb.get("native_budget")))
            check("...and it is stamped WITHOUT a protocol: a native budget is "
                  "not a claim a recipe makes, it is what the system was run "
                  "with",
                  "protocol_version" not in nb and "native_budget" in nb)
            check("a fixture transport stamps no native budget -- with no "
                  "system there is no native vocabulary to record",
                  "native_budget" not in _run_stamp(fake_args(adapter="gold"),
                                                    fake_adapter))

        # -- the unbounded budget, end to end: campaign -> row stamp -> merge.
        #
        # The value has to survive both hops as ONE spelling, because the
        # merge compares them by equality. A campaign that recorded
        # "unlimited" against rows that recorded 0 (or -1, or null) would
        # refuse a correct run at merge time, hours after the money was spent;
        # a campaign that recorded 0 against unbounded rows would MERGE a
        # C2-equivalent control and an unbounded arm into one file.
        ucf = campaign_file(trial_budget=UNBOUNDED)
        ust = _run_stamp(fake_args(campaign=ucf, trials=UNBOUNDED),
                         fake_adapter)
        check("an unbounded campaign accepts an unbounded shard, and stamps it",
              ust["trials"] == UNBOUNDED and len(ust["campaign_digest"]) == 16,
              str(ust.get("trials")))
        with open(ucf, encoding="utf-8") as fh:
            ucamp = json.load(fh)
        from .campaign import _crosscheck_row
        check("and the merge crosscheck accepts that row",
              _crosscheck_row(ucamp, dict(ust, item_id="i0"), 0) == [],
              str(_crosscheck_row(ucamp, dict(ust, item_id="i0"), 0)))
        for wrong in (0, 5):
            problems = _crosscheck_row(
                ucamp, dict(ust, item_id="i0", trials=wrong), 0)
            check(f"a shard that ran --trials {wrong} cannot merge into an "
                  f"unbounded campaign", len(problems) == 1
                  and "unlimited" in problems[0], str(problems))
        check("nor can an unbounded row hide inside a counted campaign",
              len(_crosscheck_row(json.load(open(cf, encoding="utf-8")),
                                  dict(ust, item_id="i0"), 0)) == 1)
        refuses("a shard relaunched with --trials 5 under an unbounded "
                "campaign is refused before item 1",
                lambda: _run_stamp(fake_args(campaign=ucf, trials=5),
                                   fake_adapter),
                "REFUSED", "trial_budget=unlimited", "--trials 5")
        refuses("...and so is one relaunched with no budget at all",
                lambda: _run_stamp(fake_args(campaign=ucf, trials=0),
                                   fake_adapter),
                "REFUSED", "trial_budget=unlimited", "--trials 0")
        refuses("an unbounded shard under a COUNTED campaign is refused too",
                lambda: _run_stamp(fake_args(campaign=cf, trials=UNBOUNDED),
                                   fake_adapter),
                "REFUSED", "trial_budget=5", "--trials unlimited")

        # -- a generation cache cannot be replayed under another system's label.
        cache = os.path.join(root, "cache.jsonl")
        with open(cache, "w", encoding="utf-8") as fh:
            for i in range(3):
                fh.write(json.dumps({"item_id": f"i{i}", "condition": "c2",
                                     "model": "deepseek-chat",
                                     "produced_files": []}) + "\n")
        refuses("a c2 cache replayed under the c3 label is refused",
                lambda: _check_replay_labels(fake_args(condition="c3"), cache),
                "REFUSED", "condition", "c2")
        refuses("a cache from another model cannot be relabelled",
                lambda: _check_replay_labels(
                    fake_args(condition="c2", model="gpt-5"), cache),
                "REFUSED", "model")
        try:
            _check_replay_labels(fake_args(condition="c2"), cache)
            check("replaying under the labels the cache was generated with "
                  "is allowed", True)
        except SystemExit as e:
            check("replaying under the labels the cache was generated with "
                  "is allowed", False, str(e)[:200])
        legacy = os.path.join(root, "legacy.jsonl")
        with open(legacy, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i0", "produced_files": []}) + "\n")
        try:
            _check_replay_labels(fake_args(condition="c3"), legacy)
            check("an unstamped cache is unverifiable, not wrong", True)
        except SystemExit as e:
            check("an unstamped cache is unverifiable, not wrong", False,
                  str(e)[:200])

        # -- and a half-finished shard cannot be resumed into a different
        #    configuration now that the trial budget is on the row.
        half = os.path.join(root, "half.jsonl")
        with open(half, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(st, item_id="i0", outcome="failed")) + "\n")
        check("a matching shard resumes the item it already ran",
              _resume_set(half, st, retry_failed=False, no_resume=False)
              == {"i0"})
        refuses("a shard whose rows were produced at another trial budget is "
                "refused rather than appended to",
                lambda: _resume_set(half, _run_stamp(
                    fake_args(campaign=campaign_file(trial_budget=0),
                              trials=0),
                    fake_adapter), retry_failed=False, no_resume=False),
                "REFUSED", "different run configuration")
        # -- but not one whose rows were produced at another COMMIT (section
        #    16): the commit is provenance the row keeps, not configuration.
        #    Explicit values on both sides so the check is not vacuous in a
        #    checkout where `st` carries no commit at all.
        moved = os.path.join(root, "moved.jsonl")
        with open(moved, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(st, item_id="i1", outcome="failed",
                                     harness_commit="0000000")) + "\n")
        check("a shard whose rows were produced at another commit resumes, "
              "and its rows keep their own commit",
              _resume_set(moved, dict(st, harness_commit="1111111"),
                          retry_failed=False, no_resume=False) == {"i1"})

        # -- THE GRANDFATHER CLAUSE (STAMP_OPTIONAL_FIELDS).
        #
        # In campaign mode an absent field is normally a mismatch, which is
        # what stops an unstamped row being relabelled as part of this
        # campaign. But a field that did not EXIST when the old row was
        # written cannot be absent for that reason -- and refusing on it would
        # kill an in-flight campaign hours into a paid sweep, over a question
        # nobody had asked yet. So: absent is unverifiable, DIFFERENT is still
        # refused, and both halves are checked here because only having the
        # first one is how the leniency quietly becomes "anything resumes".
        old = os.path.join(root, "old.jsonl")
        aged = {k: v for k, v in st.items()
                if k not in STAMP_OPTIONAL_FIELDS}
        with open(old, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(aged, item_id="i0", outcome="failed"))
                     + "\n")
        check("a row written before the WS1 stamp fields existed still "
              "resumes under a campaign",
              _resume_set(old, st, retry_failed=False, no_resume=False)
              == {"i0"}, str(sorted(set(st) - set(aged))))
        check("...and the grandfathered set is not empty -- this check would "
              "pass vacuously if the stamp had gained nothing",
              set(st) - set(aged) != set(), str(sorted(st)))
        conflicting = os.path.join(root, "conflicting.jsonl")
        with open(conflicting, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(aged, item_id="i0", outcome="failed",
                                     adapter_version="openhands@99")) + "\n")
        refuses("a row that CARRIES a grandfathered field with a different "
                "value is still refused -- absence is leniency, disagreement "
                "is not",
                lambda: _resume_set(conflicting, dict(st,
                                                      adapter_version="openhands@1"),
                                    retry_failed=False, no_resume=False),
                "REFUSED", "different run configuration", "adapter_version")
        # Outside a campaign nothing changed at all: an absent field has
        # always been unverifiable there.
        check("outside a campaign the same aged row resumes as it always did",
              _resume_set(old, {k: v for k, v in st.items()
                                if k != "campaign_digest"},
                          retry_failed=False, no_resume=False) == {"i0"})

        # -- `--protocol`, end to end through the CLI's own wiring.
        #
        # Here rather than in a `cli` selftest because `cli` has none, and
        # because what is being checked is the STAMP: the whole point of the
        # flag is which fields end up on a row, and that is this module's
        # business. No agent, no container, no item runs -- `_apply_protocol`
        # is a pure function of an argv and a namespace, and `_run_stamp` is
        # what reads its answer.
        from .cli import _apply_protocol, _explicit_knobs

        def probe(argv, **over):
            """An args namespace as `main` would have it, protocol applied."""
            a = fake_args(**over)
            a.protocol = "2"
            a.cmd = "run"
            _apply_protocol(a, argv)
            return a

        # Defined above the guard, not inside it: the native-knob legs
        # further down call `probe` after the guard has ended.
        try:
            from ..agents import protocol as _P
            from ..agents.protocol import PINNED_DIGESTS
        except ImportError:
            print("  [SKIP] the --protocol legs: the recipes and their pinned "
                  "digests live in the agent component, which this checkout lacks")
        else:
            base_argv = ["run", "--adapter", "openhands", "--protocol", "2"]
            a = probe(base_argv, condition="c2", trials=0, max_iterations=99,
                      temperature=0.9, coverage=False, agent_timeout=60)
            check("a protocol's knobs become the DEFAULTS for the flags nobody "
                  "passed",
                  (a.condition, a.trials, a.max_iterations, a.agent_timeout,
                   a.temperature, a.repeats, a.coverage)
                  == ("c3", UNBOUNDED, 30, 3600, 0.0, 1, True), str(vars(a)))
            check("...and the run stamps which recipe it followed",
                  a.protocol_version == 2
                  and a.protocol_digest == PINNED_DIGESTS[2]
                  and _run_stamp(a, fake_adapter)["protocol_digest"]
                  == PINNED_DIGESTS[2], str(a.protocol_digest))
            check("no deviation is recorded when the run simply followed it",
                  a.protocol_deviations == []
                  and "protocol_deviations" not in _run_stamp(a, fake_adapter))
            check("...and end to end through the CLI the row carries the recipe's "
                  "setting too",
                  _run_stamp(a, fake_adapter).get("setting") == "cold_start",
                  str(_run_stamp(a, fake_adapter).get("setting")))

            check("an explicitly typed flag is seen as typed, and a defaulted one "
                  "is not",
                  _explicit_knobs(base_argv + ["--temperature", "0.9"])
                  == {"temperature"}
                  and _explicit_knobs(base_argv) == set(),
                  str(_explicit_knobs(base_argv + ["--temperature", "0.9"])))
            check("...including the store_true knob and the `=` spelling",
                  _explicit_knobs(base_argv + ["--coverage", "--trials=5"])
                  == {"coverage", "trials"},
                  str(_explicit_knobs(base_argv + ["--coverage", "--trials=5"])))

            dev_argv = base_argv + ["--temperature", "0.9"]
            b = probe(dev_argv, temperature=0.9)
            check("an ad-hoc probe MAY deviate -- and every row says so, verbatim",
                  b.protocol_deviations
                  == ["temperature (--temperature): protocol says 0.0, "
                      "flags say 0.9"]
                  and _run_stamp(b, fake_adapter)["protocol_deviations"]
                  == b.protocol_deviations, str(b.protocol_deviations))
            check("...while the knobs it did NOT contradict still come from the "
                  "protocol", b.max_iterations == 30 and b.coverage is True)
            refuses("the same deviation under --campaign is REFUSED before item 1 "
                    "-- a campaign run follows its protocol",
                    lambda: probe(dev_argv + ["--campaign", cf], temperature=0.9,
                                  campaign=cf),
                    "REFUSED", "deviates from protocol v2",
                    "temperature (--temperature)", "A campaign run follows")
            c = fake_args()
            c.protocol = None
            _apply_protocol(c, ["run", "--adapter", "openhands"])
            check("without --protocol nothing happens at all: no defaulting, and "
                  "not one protocol field on the row",
                  not hasattr(c, "protocol_digest")
                  and not any(k.startswith("protocol_")
                              for k in _run_stamp(c, fake_adapter)), str(vars(c)))
            d = fake_args()
            d.protocol = "999"
            # The list is DERIVED, not frozen: `protocol.known_versions()`
            # enumerates the directory, so adding a protocol file stays one
            # commit.  A literal here would have to be edited every time one
            # lands, and the version it went stale on is exactly the version the
            # message would then be lying about.
            _known = _P.known_versions()
            refuses("an unknown protocol version is refused in the house style, "
                    "with the list of the ones that exist",
                    lambda: _apply_protocol(d, ["run", "--protocol", "999"]),
                    "REFUSED", "no protocol version 999", str(_known))
            # ...and the derived list is a real enumeration, not an empty one that
            # would make the assertion above vacuous.
            check("the enumerated versions include both Slice-3 generations",
                  _known == sorted(_P.PINNED_DIGESTS)
                  and _P.SLICE3_VERSIONS <= set(_known), str(_known))

        try:
            from ..agents import protocol as _P_knobs       # noqa: F401
        except ImportError:
            print("  [SKIP] the native-knob legs: `_apply_protocol` applies "
                  "an agent recipe, and this checkout has no agent component")
        else:
            # -- THE NATIVE KNOBS, end to end through the same wiring.
            #
            # `protocol.KNOBS` is exactly seven and can never grow an eighth (v1
            # and v2 are immutable and carry no such key, so every `KNOBS` loop
            # would KeyError on them). A second system's budget therefore travels
            # by a SEPARATE mechanism, and the thing that has to be proved is that
            # the separate mechanism gets the SAME treatment: refused under a
            # campaign, recorded verbatim otherwise.
            def probe3(argv, **over):
                a = fake_args(**over)
                a.protocol = "3"
                a.cmd = "run"
                _apply_protocol(a, argv)
                return a

            aider_argv = ["run", "--adapter", "aider", "--protocol", "3"]
            n = probe3(aider_argv, adapter="aider", max_reflections=3)
            check("v3's native budget becomes the default for the flag "
                  "nobody passed -- aider's own 3 becomes the protocol's 10",
                  n.max_reflections == 10 and n.protocol_deviations == [],
                  str(n.max_reflections))
            check("...and the row records the budget it actually ran under",
                  _run_stamp(n, fake_adapter)["native_budget"]
                  == {"max_reflections": 10},
                  str(_run_stamp(n, fake_adapter).get("native_budget")))
            check("`--max-reflections` is seen as TYPED even at a value the "
                  "namespace already held -- the echo parser is the only "
                  "thing that can tell, and without it a protocol would "
                  "overwrite the operator",
                  _explicit_knobs(aider_argv + ["--max-reflections", "3"])
                  == {"max_reflections"},
                  str(_explicit_knobs(aider_argv
                                      + ["--max-reflections", "3"])))
            nd_argv = aider_argv + ["--max-reflections", "1"]
            m = probe3(nd_argv, adapter="aider", max_reflections=1)
            check("an ad-hoc probe MAY halve aider's only loop -- and every "
                  "row says so, verbatim",
                  m.protocol_deviations
                  == ["native_knobs.aider.max_reflections "
                      "(--max-reflections): protocol says 10, flags say 1"]
                  and _run_stamp(m, fake_adapter)["protocol_deviations"]
                  == m.protocol_deviations
                  and _run_stamp(m, fake_adapter)["native_budget"]
                  == {"max_reflections": 1}, str(m.protocol_deviations))
            refuses("the same deviation under --campaign is REFUSED before "
                    "item 1 -- a halved loop is exactly as incomparable as a "
                    "changed temperature",
                    lambda: probe3(nd_argv + ["--campaign", cf],
                                   adapter="aider", max_reflections=1,
                                   campaign=cf),
                    "REFUSED", "deviates from protocol v3",
                    "native_knobs.aider.max_reflections",
                    "A campaign run follows")
            check("an OPENHANDS run under v3 sees no native deviation of its "
                  "own: its native knob IS --max-iterations, reported once "
                  "under its own flag rather than twice under two names",
                  probe3(["run", "--adapter", "openhands", "--protocol", "3",
                          "--max-iterations", "7"],
                         max_iterations=7).protocol_deviations
                  == ["max_iterations (--max-iterations): protocol says 100, "
                      "flags say 7"])
            check("a run under v2 -- which pins nothing for aider -- deviates "
                  "in nothing native, whatever the flag says",
                  probe(["run", "--adapter", "aider", "--protocol", "2",
                         "--max-reflections", "1"],
                        adapter="aider",
                        max_reflections=1).protocol_deviations == [])

        # -- THE PROTOCOL PAIR IS ENFORCED, not merely fingerprinted.
        #
        # Hashing the recipe into the campaign digest makes two protocols
        # DIFFERENT; it does not make a shard FOLLOW the one its campaign
        # declares. Until this was checked, a campaign could assert
        # `protocol_version: 2` while every shard ran the harness defaults --
        # internally consistent, because all shards would assert it equally,
        # and false. Both ends are checked here: the launch refusal (before
        # item 1, before the money) and the merge crosscheck (for rows that
        # reached the file some other way).
        try:
            from ..agents.protocol import PINNED_DIGESTS
        except ImportError:
            print("  [SKIP] the protocol-pair enforcement legs: the pinned "
                  "digests are the agent protocol's, and this checkout has "
                  "no agent component")
        else:
            pcf = campaign_file(protocol_version=2,
                                protocol_digest=PINNED_DIGESTS[2])
            refuses("a campaign that DECLARES a protocol refuses a shard "
                    "launched without --protocol, before item 1",
                    lambda: _run_stamp(fake_args(campaign=pcf), fake_adapter),
                    "REFUSED", "campaign protocol_version=2",
                    "protocol_version=None", "--protocol 2")
            refuses("...and one launched under a DIFFERENT recipe",
                    lambda: _run_stamp(
                        fake_args(campaign=pcf, protocol_version=1,
                                  protocol_digest=PINNED_DIGESTS[1]),
                        fake_adapter),
                    "REFUSED", "campaign protocol_digest=",
                    PINNED_DIGESTS[2], PINNED_DIGESTS[1])
            pst = _run_stamp(fake_args(campaign=pcf, protocol_version=2,
                                       protocol_digest=PINNED_DIGESTS[2]),
                             fake_adapter)
            with open(pcf, encoding="utf-8") as fh:
                pcamp = json.load(fh)
            check("a shard that DID follow the campaign's recipe launches, "
                  "stamps the pair, and crosschecks clean at merge",
                  pst["protocol_version"] == 2
                  and pst["protocol_digest"] == PINNED_DIGESTS[2]
                  and _crosscheck_row(pcamp, dict(pst, item_id="i0"), 0) == [],
                  str(_crosscheck_row(pcamp, dict(pst, item_id="i0"), 0)))
            bare = {k: v for k, v in pst.items() if k != "protocol_version"}
            problems = _crosscheck_row(pcamp, dict(bare, item_id="i0"), 0)
            check("a merged row carrying NO protocol_version is REFUSED as "
                  "absent, not admitted as unknown -- an unstamped row is "
                  "compatible with every recipe",
                  len(problems) == 1
                  and "carries no 'protocol_version' at all" in problems[0],
                  str(problems))
            wrongp = _crosscheck_row(
                pcamp, dict(pst, item_id="i0", protocol_digest="0" * 16), 0)
            check("...and one carrying the WRONG digest is refused by value",
                  len(wrongp) == 1 and PINNED_DIGESTS[2] in wrongp[0],
                  str(wrongp))

        # THE GRANDFATHER HALF, which is what keeps the six archived campaign
        # sidecars mergeable: they do not carry the keys as `None`, they do not
        # carry them AT ALL. `campaign_fingerprint` defaults them in, so the
        # archived shape has to be built by deleting them.
        arch = campaign_file()
        with open(arch, encoding="utf-8") as fh:
            archdoc = json.load(fh)
        for k in ("protocol_version", "protocol_digest"):
            archdoc.pop(k, None)
        with open(arch, "w", encoding="utf-8") as fh:
            json.dump(archdoc, fh)
        arch_st = _run_stamp(fake_args(campaign=arch),
                             fake_adapter)
        arch_problems = _crosscheck_row(archdoc, dict(arch_st, item_id="i0"), 0)
        check("an archived-shape campaign with no protocol keys at all still "
              "launches a protocol-less shard AND still merges its rows",
              "protocol_version" not in archdoc
              and "protocol_version" not in arch_st
              and arch_problems == [], str(arch_problems))

    # -- the condition label is validated, and normalised before it is.
    #    Both the label vocabulary and the menu behind an unknown name are
    #    `agents.registry`'s (`_agent_flags`, `get_spec`), so without the
    #    agent component `build_adapter` never reaches either -- it refuses
    #    the arm by name first, which is the leg that runs instead.
    try:
        from ..agents import registry as _reg_flags        # noqa: F401
    except ImportError:
        refuses("an agent arm this checkout does not ship is refused by "
                "name, before anything is built",
                lambda: build_adapter(fake_args(), None),
                "REFUSED", "agent arm 'openhands' is not shipped",
                "Nothing was built")
    else:
        refuses("an unknown --condition is refused, not silently run as C2",
                lambda: build_adapter(fake_args(condition="c1_5"), None),
                "REFUSED", "unknown --condition")
        refuses("--condition C2 --trials 5 cannot slip past on its casing",
                lambda: build_adapter(fake_args(condition="C2", trials=5), None),
                "REFUSED", "--trials with --condition c2")
        refuses("--condition c3 without --trials is refused as a mislabelled C2",
                lambda: build_adapter(fake_args(condition="C3", trials=0), None),
                "REFUSED", "without --trials", "--trials unlimited")
        refuses("--condition c2 --trials unlimited is refused just as loudly",
                lambda: build_adapter(fake_args(condition="c2",
                                                trials=UNBOUNDED), None),
                "REFUSED", "--trials with --condition c2")
        refuses("a --trials value that is neither a count nor `unlimited` is "
                "refused, not read as 0",
                lambda: build_adapter(fake_args(condition="c3", trials="lots"),
                                      None),
                "unlimited")
        refuses("an unknown adapter is still refused",
                lambda: build_adapter(fake_args(adapter="hands"), None),
                "unknown adapter")

    # -- the v1 fixture gate RESERVES what the registry knows.
    #
    # The admitted half does not move: the four fixture names are still the
    # only ones that produce a v1 kind.  What moves is the other half of the
    # answer -- whether a name this gate refuses is refused as a system the
    # harness ships (reserved, route it to the agent gate) or as one it has
    # never heard of (a typo, here is the menu).  A third arm used to get the
    # second message.  Registering the spec is now the whole of what changes
    # that, which is what these three checks pin: the derivation moves, the
    # two shipped agents and their aliases do not, and an unregistered name
    # still gets the menu.
    try:
        from ..agents import registry as _reg3
        from ..agents.base import AdapterSpec as _Spec3
        from ..agents.publication import _native_evidence_required
    except ImportError:
        print("  [SKIP] the reserved-vs-admitted gate legs: they register a "
              "third arm in the agent adapter registry, and this checkout has "
              "no agent component")
    else:

        def gate_refusal(name):
            try:
                return publication_adapter_kind(SimpleNamespace(adapter=name))
            except SystemExit as exc:
                return str(exc)

        third3 = _Spec3(name="acme", version=1, kind="agent",
                        build=lambda args, harness: None,
                        trajectory_format="openhands.events/1", sandbox="bwrap",
                        comparison_class="fixed_model_scaffold")
        with _reg3.temporary_arm(third3):
            third_reserved = third3.name in _publication_reserved_adapters()
            third_gate = gate_refusal("acme")
            # The pin below, evaluated WITH the third arm registered as well as
            # after it is gone.  A census -- `== frozenset(<the six shipped
            # names>)` -- is exactly what a third arm breaks: it made the arm's
            # arrival a FAILURE of the gate that is supposed to route it.  What
            # this gate actually owes is containment (every shipped reserved name
            # stays reserved) and disjointness (no reserved name is also an
            # admitted fixture), and both survive an arm being added.
            reserved_with_third = _publication_reserved_adapters()
            fixtures_with_third = {n: gate_refusal(n)
                                   for n in _PUBLICATION_ADAPTER_KINDS}
            # The same third arm, once with and once without the second recorder
            # declared, is the only way to show the item-close dispatch reads the
            # SPEC rather than the name it happens to be looking at.
            third_plain_native = _native_evidence_required("acme")
            with _reg3.temporary_arm(_Spec3(
                    name="acme", version=1, kind="agent",
                    build=lambda args, harness: None,
                    trajectory_format="openhands.events/1", sandbox="bwrap",
                    comparison_class="fixed_model_scaffold",
                    native_manifest=_reg3.REGISTRY["aider"].native_manifest)):
                third_native = _native_evidence_required("acme")
        check("a third agent is RESERVED by the v1 fixture gate the moment its "
              "spec is registered, and is refused as a system this harness "
              "ships rather than as an unknown name",
              third_reserved and "is reserved and cannot produce" in third_gate
              and "acme" not in _publication_reserved_adapters(),
              f"reserved={third_reserved} refusal={third_gate!r}")
        shipped_reserved = frozenset({
            "replay", "submitted", "openai", "openhands", "aider", "llm"})
        fixtures = frozenset(_PUBLICATION_ADAPTER_KINDS)
        check("...while the shipped agents, the transports and the openai "
              "aliases stay reserved and the four fixtures stay admitted -- with "
              "the third arm registered and after it is gone, because what this "
              "gate owes is containment and disjointness, not a census",
              shipped_reserved <= reserved_with_third
              and shipped_reserved <= _publication_reserved_adapters()
              and not (reserved_with_third & fixtures)
              and not (_publication_reserved_adapters() & fixtures)
              and fixtures_with_third == _PUBLICATION_ADAPTER_KINDS
              and {n: gate_refusal(n) for n in _PUBLICATION_ADAPTER_KINDS}
              == _PUBLICATION_ADAPTER_KINDS,
              f"with_third={sorted(reserved_with_third)} "
              f"after={sorted(_publication_reserved_adapters())}")
        # ...and containment is not a weaker pin than the census it replaces.
        # The failure the census caught is an agent NAME reaching the fixture
        # gate as a fixture, and the only way that happens is the fixture set
        # growing to cover it -- so grow it, and watch the same gate that
        # REFUSES `aider` today hand back a fixture kind for it.
        _PUBLICATION_ADAPTER_KINDS["aider"] = "aider"
        try:
            leaked_reserved = _publication_reserved_adapters()
            leaked_gate = gate_refusal("aider")
        finally:
            del _PUBLICATION_ADAPTER_KINDS["aider"]
        check("...and the containment half is load-bearing: an agent the fixture "
              "set grew to cover stops being reserved and is ADMITTED here as a "
              "fixture, which is exactly the leak the pin refuses",
              leaked_gate == "aider"
              and not (shipped_reserved <= leaked_reserved)
              and "is reserved and cannot produce" in gate_refusal("aider"),
              f"leaked={leaked_gate!r}")
        check("...and a name no spec registers is still refused as unknown, "
              "with the fixture menu on the message",
              "not in the closed result-v3 fixture set" in gate_refusal("hands"),
              gate_refusal("hands"))

        # -- the per-item evidence chain is owed by the SPEC, not by a name.
        #
        # Behaviour-preserving for both shipped arms on purpose: aider@1 declares
        # a native manifest and keeps the per-item close, openhands@1 declares
        # none and keeps the seal-time verification it has always had.  Turning
        # it on for openhands would not change what a run REFUSES -- the seal
        # replays the same chain for every item of every agent -- but it would
        # change WHEN a shard stops, and that is a change to a live publication
        # run's failure mode, not a refactor.
        check("only a system whose spec declares a native manifest owes the "
              "per-item chain -- aider today, a third arm that declares one, and "
              "nothing else",
              _native_evidence_required("aider")
              and third_native
              and not _native_evidence_required("openhands")
              and not third_plain_native
              and not _native_evidence_required("gold")
              and not _native_evidence_required("nosuch"),
              f"aider={_native_evidence_required('aider')} "
              f"third_with={third_native} third_without={third_plain_native} "
              f"openhands={_native_evidence_required('openhands')}")

    # -- the reproducibility check never re-invokes a system that generates.
    check("only a lookup adapter is re-run for the reproducibility check",
          all(_repro_replayable(SimpleNamespace(name=n, config={}))
              for n in ("gold", "stripped-gold", "empty", "stub", "replay"))
          and not _repro_replayable(fake_adapter)
          and not _repro_replayable(SimpleNamespace(name="openai:x", config={})))
    check("a replay wearing its generator's name is still replayable",
          _repro_replayable(SimpleNamespace(name="openhands:deepseek",
                                            config={"replay": "cache.jsonl"})))
    check("submitted bytes are replayable by config, not by their free-text "
          "adapter name",
          _repro_replayable(SimpleNamespace(
              name="submitted:external-system",
              config={"candidates": "candidates.jsonl"}))
          and not _repro_replayable(SimpleNamespace(
              name="submitted:external-system", config={})))
    # Deliberately a path that does not exist: a gated check must return
    # before it reads the run file, let alone re-executes anything.
    gate = _repro_check(None, fake_adapter, [], "/nonexistent/run.jsonl",
                        10, coverage=False, timeout=1)
    check("an agent run's repro check is skipped, with the reason on the record",
          gate["checked"] == 0 and "non-replayable" in str(gate.get("skipped")),
          str(gate))
    # The publication route had no such gate, and its sample runs AFTER the
    # shard is complete: the default 10 re-invoked the paid agent on ten
    # finished items and then refused the shard for the drift it had just
    # caused.  Refused at plan time now, where it is still free.
    refuses("an agent publication run refuses a nonzero --repro-check before "
            "it can spend anything",
            lambda: construct_publication_run_plan(
                fake_args(adapter="aider", timeout=600, repro_check=10),
                agent_admission={"adapter_kind": "aider"}),
            "REFUSED", "--repro-check 0", "No Docker")
    refuses("...and a fixture publication keeps the free sample the check was "
            "designed for",
            lambda: construct_publication_run_plan(
                fake_args(adapter="gold", timeout=600, repro_check=10)),
            "requires explicit bindings")

    # -- one item's crash is a row, not the end of the shard.
    try:
        raise RuntimeError("the container went away")
    except RuntimeError as e:
        row = _harness_error_row("coreshop/features/domain/cart/x.feature:18", e)
    check("an unexpected exception becomes a row with the item's id",
          row["outcome"] == "harness_error"
          and row["item_id"].endswith("x.feature:18")
          and row["metadata"]["harness_error"]
          == "RuntimeError: the container went away", str(row)[:200])
    check("the traceback is kept, and bounded like every other row field",
          "runner.py" in row["metadata"]["traceback_tail"]
          and len(row["metadata"]["traceback_tail"]) <= 1500,
          str(len(row["metadata"]["traceback_tail"])))
    check("a harness error is retryable and a bad answer is not",
          "harness_error" in _RETRYABLE_OUTCOMES
          and not {"failed", "no_files_returned", "undefined_steps",
                   "parse_or_compile_error"} & _RETRYABLE_OUTCOMES,
          str(sorted(_RETRYABLE_OUTCOMES)))

    print("\n" + ("ALL PASS (runner)" if ok else "FAILURES (runner)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
