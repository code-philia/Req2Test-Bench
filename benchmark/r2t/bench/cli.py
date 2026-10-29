"""The benchmark's own verbs: `python3 -m r2t.bench.cli`, the consumer entry.

Every verb a benchmark consumer runs -- `docker-authority inspect`, `doctor`,
`bundle fetch`, `environment up`, `worker provision`, `tasks`, `run`,
`results` -- and the ones that operate the benchmark around them: campaigns'
shards and merges, mutation scoring, test quality.  `python3 -m r2t.cli`
composes this module with `toolkit.cli` (the extender's verbs) and, when the
checkout ships it, `agents.cli` (this study's own agent arms); this file
alone is the consumer's entry.

This module also holds the dispatcher every entry runs through (`dispatch`):
the global options, the argv scan that names the verb before any parser is
built, and the post-parse bindings.  Each component registers its verbs
through `register(verbs, request)`, and the persona tag on every verb's
help -- `[consumer]`, `[extender]`, `[operator]` -- is DERIVED from which
component registered it.

The shared helpers (`_harness`, `_boundary`, `_require_bound_live_worker`,
...) live here, and the other two components call them through this module
object, so a self-test that replaces `bench.cli._harness` replaces it for
every component's verb, as it did when all of them were one file.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import secrets
import shlex
import sys
from collections import namedtuple

from ..core.paths import project_path

#: The tag every verb registered by this component carries in `--help`.
PERSONA = "[consumer]"


#: The `r2t` package directory: the PHP data programs are under it.
PACKAGE_DIR = os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(PACKAGE_DIR)
DEFAULT_BOUNDARY = os.path.join(BENCHMARK, "config", "boundary_coreshop.yml")

# `--sample-seed` carries a value whether or not anything is sampled -- it is
# inert without `--sample` -- so a seed the operator actually typed can only
# be told from the parser's own default by comparing against it.
MUTATION_SAMPLE_SEED_DEFAULT = 20260731

# Set only by the two exact ``slice3_eval`` delegation seams.  They carry no
# scheduler state: campaign mode mints one identity and run mode authorizes
# one already-selected shard.  Ordinary ``r2t campaign``/``r2t run`` retain
# the historical SHA-1 assignment.
_SLICE3_CAMPAIGN_CONTEXT = None
_SLICE3_CELL_CONTEXT = None
_SLICE3_PREPARE_ONLY = False
_SLICE3_PREPARE_ENVIRON = None
# `run --adapter submitted` refuses --trials by OCCURRENCE, including the
# explicit spelling `--trials 0` that equals the ordinary parser default.
# Captured before a worker can inject its shard identity; normalised back to
# zero immediately after parsing so no downstream caller sees this sentinel.
_SUBMITTED_TRIALS_UNSET = object()

#: `--profile` is documented in one place because `run` and `generate` are
#: two halves of one sweep and must be given the same one: `generate` renders
#: the prompt and `run` executes what came back, so a generate/run pair with
#: different profiles produces rows whose prompt digest and whose harvest
#: policy disagree.
PROFILE_HELP = ("the task profile whose words the prompt is rendered from "
                "(default: profile_<project>.yml beside --boundary). It also "
                "decides which files count as a submission, so `generate` and "
                "`run` must be given the same one")
#: The same flag on the stack-bound verbs, where only ONE field of it is
#: read.  Spelled out separately because the FIELD differs, not the
#: resolution: omitted, these verbs fall back to `profile_<project>.yml`
#: beside the boundary exactly as `generate`/`run` do.  Every archived
#: CoreShop invocation stays byte-stable through that adjacency —
#: `profile_coreshop.yml` sits beside the default boundary declaring behat.
STACK_PROFILE_HELP = ("the task profile whose `framework:` decides which "
                      "stack runs this command (behat/behave) "
                      "(default: profile_<project>.yml beside --boundary). "
                      "Every CoreShop invocation omits it and gets Behat")
#: `--profile` on the three RUNTIME verbs (`seed`, `worker`, `quality`).
#:
#: The same file and the same resolution rule as `PROFILE_HELP`, read for a
#: different field: `runtime.needs_database`.  A separate string because the
#: prompt help would be actively misleading here — `worker provision` renders
#: no prompt, and an operator reading "the words the prompt is rendered from"
#: would reasonably conclude the flag does not matter to it.  (A third help
#: string, `STACK_PROFILE_HELP`, covers the five framework-dispatch verbs —
#: same flag, three distinct fields read, three honest descriptions.)
RUNTIME_PROFILE_HELP = (
    "the task profile whose `runtime:` block says what this project's stack "
    "needs (default: profile_<project>.yml beside --boundary). It decides "
    "whether a database is provisioned at all, and which pruning policy the "
    "seed is built under")
#: `--openhands-command` is kept as an alias rather than removed: it is in
#: operators' shell history and in this repository's own implementation
#: report, and a flag that starts erroring out is a flag that gets replaced by
#: a guess.  It shares the generic flag's dest, so both spellings reach the
#: adapter as the same value.
AGENT_COMMAND_HELP = ("agent adapters: shell command template to run instead "
                      "of the built-in driver; receives {task_file} "
                      "{workspace} {repo}. Custom commands are stamped as "
                      "ad hoc and are refused for a publication campaign. "
                      "(--openhands-command is a deprecated alias)")
#: `--protocol N` on `run` and `generate`.  One string, two subcommands, and
#: the wording matters as much as the mechanism: an operator has to be able to
#: tell from `--help` that a conflicting flag behaves DIFFERENTLY depending on
#: whether the run is part of a campaign.
PROTOCOL_HELP = (
    "run under protocol/protocol_vN.yml: its knobs become the DEFAULT for "
    "every flag you did not pass, and protocol_version + protocol_digest are "
    "stamped on every row. A flag you DID pass that contradicts the protocol "
    "is REFUSED under --campaign (a campaign run follows its protocol) and "
    "otherwise allowed and recorded verbatim as `protocol_deviations` (an "
    "ad-hoc probe may deviate; a comparable row may not). The PROJECT is "
    "compared the same way: a protocol carries one project's frozen prompt "
    "digests (current twins: v5 CoreShop, v6 python-docx), so "
    "a run whose profile names the other project is citing prompts it did not "
    "send. Without this flag nothing changes and no protocol field is stamped "
    "at all")
#: The per-agent loop budget flag on `run` and `generate`, one sentence at a
#: time from the arm's own record.  Two systems, two units of work, and the
#: help says so: the only budget this benchmark claims equal across systems
#: is the wall clock (`--agent-timeout`).
BUDGET_HELP = (
    "{name} adapters: cap on the agent's OWN loop per item, counted in "
    "`{kw}`. Defaults to {default} — what a run under NO protocol gets; a "
    "protocol may pin a different number and a run under one takes that "
    "unless you pass this flag, in which case the deviation is refused "
    "under --campaign and recorded on every row otherwise. NOT comparable "
    "with another agent's budget: the units are different work, which is "
    "why every row records `native_budget` per system")


def _agent_backends() -> tuple:
    """The registered agent arms, read live rather than listed.

    One function-local import for every consumer of the descriptor in this
    file: `cli` is `bench`, a checkout may physically lack the `agent`
    component, and the parser is built by EVERY verb (`--help` included).
    Live rather than cached because a self-test that registers a third arm
    registers it after import.
    """
    try:
        from ..agents.backends import AGENT_BACKENDS
    except ImportError:
        # No agent component, no arm, no budget flag: the fixture
        # verbs parse and run without one.
        return ()
    return tuple(AGENT_BACKENDS.values())


def _add_budget_flags(p) -> None:
    """Every registered agent's native loop budget, generated from the record.

    The flag, the dest a row's budget is read out of and the number a
    no-protocol run gets are three fields of one `AgentBackend`
    (`budget_flag` is DERIVED from `budget_kw`, so the driver's flag and the
    key the row is stamped with cannot drift).  Declared by hand, they were
    the same two flags written out on three parsers, which is how a third
    registered arm gets a driver, a spec and no way to say what its budget
    is — a complete run at whatever the driver defaults to, labelled as if
    it were the number we chose.
    """
    for backend in _agent_backends():
        p.add_argument(backend.budget_flag, type=int, dest=backend.budget_kw,
                       default=backend.budget_default,
                       help=BUDGET_HELP.format(name=backend.name,
                                               kw=backend.budget_kw,
                                               default=backend.budget_default))


DEFAULT_ARTIFACTS = project_path("coreshop", "artifacts")
DEFAULT_GOLD = project_path("coreshop", "gold")
DEFAULT_CONTAINER = "coreshop_bench_php"
DEFAULT_DB_CONTAINER = "coreshop_db"
DEFAULT_SEED = project_path("coreshop", "seed", "v1")
DEFAULT_WORKERS = project_path("coreshop", "workers")
DEFAULT_INTERNAL_NETWORK = "coreshop_bench_internal"
#: The root project release directory, which publishes its closure map.
DEFAULT_GOLD_DIR = os.path.join(BENCHMARK, "release")
BEHAT_CFG = "src/CoreShop/Behat/Resources/config"


def cmd_docker_authority(args) -> int:
    """Mint the sole initial Linux/current-user rootless authority schema."""
    from ..docker_authority import capture_authority
    document = capture_authority(
        docker_host=args.docker_host,
        docker_cli=args.docker_cli,
        out=os.path.abspath(args.out))
    print(json.dumps({"out": os.path.abspath(args.out),
                      "schema": document["schema"],
                      "digest": document["digest"]}, indent=1))
    return 0


def _trials(value: str):
    """`--trials`: a count, `0`, or `unlimited`.

    Not `type=int` any more, because the C3 arm's affordance is no longer
    rationed by a counter: a trial is a terminal tool call, so it already
    spends one of the agent's iterations and `--max-iterations` bounds
    executions natively — while a number in the prompt tells the agent its
    executions are scarce, which is a confound in the very behaviour the arm
    measures (`r2t/agents/trials.py`).  `0` still means the C2-equivalent control
    with no channel at all, and a count still rations, so both older
    configurations keep working exactly as they did.

    The parse lives in `constants.parse_trials` and is shared with the run
    path, so a value that argparse accepts is a value the stamp and the
    campaign fingerprint will spell identically.  `ArgumentTypeError` so the
    operator sees the real reason rather than argparse's "invalid _trials
    value".
    """
    from ..core.constants import parse_trials
    try:
        return parse_trials(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


def _boundary(args):
    from ..core.boundary import load_boundary
    return load_boundary(args.boundary, repo_root=args.repo)


def _behat_row(args):
    """The project's Behat row for the LIVE halves that read it.

    Which environment variable a worker's DSN is in, whether the DSN takes a
    query suffix, and whether the four `PIMCORE_INSTALL_*` variables belong
    beside it are per-project facts (`repo.BehatProject`), and the live
    worker inspection compares against them.  Read from the boundary the
    invocation already names, so a boundary with no `behat:` block is
    `CORESHOP_BEHAT` itself and every CoreShop pool is inspected against
    exactly what it was inspected against before.
    """
    from .repo import behat_project
    return behat_project(_boundary(args))


def _refuse_unbound_live_workload(workload: str, binding: str) -> None:
    """Close a live Docker producer until its workload schema is reviewed.

    Docker authority authenticates *which daemon* may be contacted.  It does
    not say which host inputs, mounts, image, or outputs belong to an
    anonymous/transient workload.  Treating authority as that missing binding
    would recreate the exact portability hole the authority work closes.
    """
    raise SystemExit(
        f"REFUSED: {workload} reaches Docker but has no reviewed {binding} "
        "workload binding. Docker authority alone is not workload binding; "
        "no Docker command was run.")


def _bound_container_image(container: str) -> str:
    """The immutable image ID of the operator-named container, or a refusal.

    The live extraction and population producers (`index`, `index-prod`,
    `mutants build`) run on three binding facts the argv already establishes:
    the boundary and profile pair, the container the operator named, and this
    ID -- resolved from the container's `{{.Image}}`, never from a mutable tag
    -- which each verb records in its own output (DOCKER_EXECUTION_AUTHORITY.md,
    2026-09-09 amendment).  A container whose image cannot be resolved to a
    `sha256:` ID is refused before the verb stages or runs anything.
    """
    from .worker import WorkerRefused, live_container_image_digest
    try:
        return live_container_image_digest(container)
    except WorkerRefused as exc:
        raise SystemExit(str(exc)) from exc


def _docx_v2_capability(args, action: str):
    """Return the one wrapper-bound DOCX capability, never ambient consent."""
    from ..toolkit.docx_v2_workload import capability_for
    return capability_for(args, action)


#: The DB-backed workloads that stay closed.  Every other database-backed
#: workload is open; `_refuse_unbound_database_runtime` says why.
_DATABASE_WORKLOADS_STILL_CLOSED = frozenset({
    "database-backed confinement certification",
})


def _refuse_unbound_database_runtime(needs_database: bool,
                                     workload: str) -> None:
    """Close the DB-backed workloads whose claims are still unbound.

    This closed every database-backed workload, for two stated reasons.  The
    first is now false; the second described the evidence rather than the
    enforcement.

    NO LONGER TRUE -- "does not authenticate the legacy template-container
    environment".  It did not, and a hand-recreated template could silently
    become the system under test; on the author host one already had.
    `--template-container` now has no default and refuses when absent, and the
    provision report records which container was read and which variable names
    came out of it.

    RE-EXAMINED -- "nor does it prove that `root@%` remains absent and every
    principal remains scoped to only its own schema".  That is about the
    RECORD, not the boundary.  `dbadmin.create_worker_principal` grants only
    ``ON `schema`.*``, then re-reads `SHOW GRANTS` and refuses any non-USAGE
    `ON *.*`.  `remove_wildcard_root` drops `root@%` only after confirming
    `root@localhost` survives, so the coordinator cannot lock itself out.
    `harden_database` refuses to harden a schema still holding
    `root@%`-definer objects.  The boundary is enforced and verified where it
    is applied.  Writing a durable record of that verification would mean
    versioning the schema that authorizes every live run -- including the
    no-database pools -- to produce a file nothing reads.

    So a pool's SQL boundary is demonstrated per-pool by `worker harden` and
    `worker probe`, which is where it can actually be falsified, rather than
    asserted by refusing the workload outright.  An operator who skips those
    has a pool whose isolation claim is Docker topology alone, and the remedy
    for that is to run them, not to close the workload for everyone.

    MUTATION AND TEST-QUALITY EXECUTION now leave the set on that same
    standard.  Their claims reach past the SQL boundary in three ways, and
    each one is falsifiable per-pool rather than asserted:

      * byte-exact production-source restore, by
        `mutation_run._require_pristine_substrate` and
        `Harness.verify_substrate`, which raise `SubstrateTampered` on any
        change, addition or deletion under the manifest's substrate roots;
      * a PID-scoped timeout kill, by H7 / `Harness._kill_behat`, which kills
        the subtree of exactly the Behat this call started and records whether
        it died;
      * per-execution schema-state reset, which had no falsifier at all --
        `Harness._run_solution` does filesystem hygiene only and the reset is
        performed by the retained Behat hooks, which nothing checked ran.
        `worker reset-probe` is that falsifier: two consecutive pair
        executions on one worker, markers written by the first, and a verdict
        that fails both when a marker crosses the boundary and when the probe
        can see nothing at all.

    So the duty is the same as for `harden`/`probe`: run `worker reset-probe`
    on the pool a campaign will use.  An operator who skips it has a pool
    whose reset claim is the hooks' reputation alone, and the remedy is to run
    it, not to close the workload for everyone.

    Still closed: confinement certification -- which is closed for every
    profile, not only database-backed ones, by the outer
    `_refuse_unbound_live_workload` in `cmd_confine`.
    """
    if needs_database and workload in _DATABASE_WORKLOADS_STILL_CLOSED:
        _refuse_unbound_live_workload(
            workload, "portable environment-and-database-isolation")

def _bind_data_defaults(args) -> None:
    """Bind lazy project defaults after argparse knows the active project."""
    import yaml

    path = getattr(args, "profile", None) or getattr(args, "boundary", None)
    project = "coreshop"
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            project = doc.get("project") or project
        except (OSError, yaml.YAMLError):
            # The command's real config loader reports the actionable error.
            pass
    replacements = (
        ("artifacts", DEFAULT_ARTIFACTS, ("artifacts",)),
        ("gold", DEFAULT_GOLD, ("gold",)),
        ("seed", DEFAULT_SEED, ("seed", "v1")),
        ("workers_root", DEFAULT_WORKERS, ("workers",)),
    )
    for attr, marker, parts in replacements:
        if getattr(args, attr, None) is marker:
            setattr(args, attr, project_path(project, *parts))


def _stack(args):
    """Which stack this invocation is against — the profile's `framework:`.

    Resolved by the ONE rule the rest of the file already documents —
    `--profile`, or `profile_<project>.yml` beside `--boundary` — because a
    second rule is a second answer.  While this function read `--profile`
    alone, `run --boundary config/boundary_python_docx.yml` with no profile
    (which `run --help` says resolves `profile_python_docx.yml`) routed down
    the behat branch and died opening CoreShop's `artifacts/alias_table.json`:
    the wrong harness, reported as a traceback rather than a refusal.

    Omitting `--profile` still means behat for every CoreShop invocation in
    this repository's runbooks, in the archived campaign logs and in the
    operator's shell history: each of them takes the default boundary, and
    `profile_coreshop.yml` sits beside it declaring `framework: behat`.  What
    keeps them byte-identical is that adjacency, not a hard-coded framework.
    A namespace carrying no boundary at all names no project to resolve
    against and keeps the historical answer.

    The profile is read for `framework:` alone here.  It is still the whole
    profile that gets loaded — digests verified, boundary cross-checked — for
    the same reason `run` loads it: a profile whose prompts have moved under
    it is not a profile this benchmark may act on, whichever field is being
    read out of it.
    """
    from ..stacks import DEFAULT_FRAMEWORK, for_framework
    if not getattr(args, "profile", None) \
            and not getattr(args, "boundary", None):
        return for_framework(DEFAULT_FRAMEWORK)
    return for_framework(_stack_profile(args).framework)


def _other_stack(args, verb_name):
    """This stack's own implementation of a verb, or None when it is behat's.

    The commands that use this are PHP-bound end to end — they run
    `analyze_php.php` inside the container, read `services.yml`, stage
    `mutate.php`, build PHP context classes — so dispatching them is a guard
    in front of a body, not a rewrite of one.  A `None` return means "carry
    on, this is the code that has always run", which is what keeps every
    CoreShop invocation byte-identical.
    """
    stack = _stack(args)
    if stack.FRAMEWORK == "behat":
        return None
    from ..stacks import verb
    return verb(stack, verb_name)


def _stack_profile(args):
    """The profile read for what a project's STACK needs, not for its prompt.

    Same resolution rule as `runner._profile_for` -- `--profile`, or
    `profile_<project>.yml` beside `--boundary` -- because a second file would
    be a second place for the two to disagree.  Its direct callers read
    `runtime.needs_database` (D6), which is the field the model never sees:
    the seed, the worker triple and the campaign fingerprint each behave
    differently for a stack that has no database, and having the operator
    remember a flag on all three is how one of them gets it wrong.  `_stack`
    reads `framework:` out of the same load, so which stack runs and what
    that stack needs can no longer be resolved from two different files.
    """
    from ..data.profile import load_profile, profile_path_for
    path = getattr(args, "profile", None) or profile_path_for(
        args.boundary, _boundary(args).project)
    return load_profile(path)


def _harness(args):
    """The harness, pointed at ONE workspace (H1).

    `--repo` used to reach only `load_boundary`, while every write resolved
    against `manifest.repo_root` — the path recorded when the tree was
    stripped.  Passing `--repo /worker/3` therefore classified paths against
    worker 3 and then installed, cleaned and executed in worker 0, which is
    defect 1 and the reason K-way could not work at all.  Both now come from
    one resolved value, and no second `--workspace` flag exists to disagree
    with it (review P2-2, decision D4).

    Routing to a stack happens HERE, at construction, because this is the one
    place a harness is made: `validate`, `runner` and `mutation_run` all take
    the harness as an argument and never name its class, so they are already
    duck-typed and need no branch of their own.

    The behat branch below is this function's own body, still in place,
    because S1 moves no logic — CoreShop's byte-stability is a property of
    that code not having moved.  A stack that lands later builds its harness
    through its own `make_harness`, and when behat's construction eventually
    joins it there this branch becomes one more call.
    """
    publication = getattr(args, "_publication_harness_context", None)
    if publication is not None:
        # The publication planner has already stable-read and semantically
        # verified this closed input set. Reopening one here would execute
        # bytes other than those the plan and final receipt bind.
        from . import result_ledger as ledger
        b = publication["boundary"]
        man = publication["manifest"]
        raw_by_path = publication["raw_by_path"]
        from .harness import DockerRunner
        runner = DockerRunner(args.container, workdir=args.workdir)
        if publication["framework"] == "behave":
            from ..stacks.behave import BehaveHarness
            return BehaveHarness(man, b, runner), b, man
        if publication["framework"] == "cucumber":
            from ..stacks.cucumber import CucumberHarness
            return CucumberHarness(man, b, runner), b, man
        if publication["framework"] == "cucumber_ruby":
            from ..stacks.cucumber_ruby import RubyHarness
            return RubyHarness(man, b, runner), b, man
        alias_path = publication["artifacts_root"] + "/alias_table.json"
        alias = ledger.loads_exact_json(
            raw_by_path[alias_path], label="bound harness alias table")
        auto = set()
        auto_path = publication["artifacts_root"] \
            + "/autowirable_types.json"
        if publication["autowirable_types_present"]:
            value = ledger.loads_exact_json(
                raw_by_path[auto_path],
                label="bound harness autowirable types")
            if not isinstance(value, list):
                raise SystemExit(
                    "REFUSED: bound harness autowirable types is not a list")
            auto = set(value)
        from .harness import Harness
        return Harness(man, b, runner, alias, auto), b, man
    other = _other_stack(args, "make_harness")
    if other is not None:
        return other(args)
    from ..core.boundary import load_boundary
    from .harness import DockerRunner, Harness
    from .repo import behat_project, load_manifest
    b = load_boundary(args.boundary, repo_root=args.repo)
    manifest_path = os.path.join(args.gold, "strip_manifest.json")
    if not os.path.isfile(manifest_path):      # pre-sanitise layout
        manifest_path = os.path.join(b.repo_root, "_bench", "strip_manifest.json")
    man = load_manifest(manifest_path)
    man.repo_root = os.path.abspath(b.repo_root)
    man.gold_root = os.path.abspath(args.gold)
    if not os.path.isdir(man.repo_root):
        raise SystemExit(f"REFUSED: no such workspace: {man.repo_root}")
    # Both files are read OFF a Symfony service container by `index`: which
    # class each service id wires, and which types the container can
    # autowire.  A project that wires no Behat services through Symfony has
    # neither, and `cmd_index` refuses to invent them rather than writing an
    # empty table that would read as a container that answered and knew
    # nothing -- so the row that has no services entry opens no file here.
    # The harness then resolves no aliases, which is what an absent service
    # container means; every project that HAS one still reads both, and a
    # missing file there is still the error it always was.
    alias: dict = {}
    auto: set = set()
    if behat_project(b).services_entry is not None:
        with open(os.path.join(args.artifacts, "alias_table.json"),
                  encoding="utf-8") as fh:
            alias = json.load(fh)
        with open(os.path.join(args.artifacts, "autowirable_types.json"),
                  encoding="utf-8") as fh:
            auto = set(json.load(fh))
    runner = DockerRunner(args.container, workdir=getattr(
        args, "workdir", None) or "/var/www/html")
    return Harness(man, b, runner, alias, auto), b, man


def _test_quality_worker_harness(args, spec_path, spec):
    """Construct both baseline and job harnesses against the selected worker."""
    wargs = argparse.Namespace(**vars(args))
    wargs.repo = spec.workspace
    wargs.container = spec.container
    wargs.workdir = spec.workdir
    if _stack(args).FRAMEWORK == "godog":
        # Go authenticates its workspace and execution artifacts against this
        # exact WorkerSpec. A global --worker or shared artifact path cannot
        # stand for every member of a test-quality pool.
        wargs.worker = spec_path
        wargs.artifacts = spec.artifacts_root
    return _harness(wargs)


def _derived_baseline(args, seed_dir: str) -> dict:
    """The seed's bytes for this stack's derived-state roots.

    What `Harness.restore_derived_state` puts back before every pair
    (`repo.DERIVED_STATE_ROOTS`; empty for a stack that declares none).  The
    three routes that execute pairs a mutant can poison -- `mutation-run`,
    `test-quality` and `worker reset-probe` -- read it from a seed they have
    already verified in the same command, so it is the content
    `workspace_seed_digest` binds, and attach it to every harness they build.
    """
    import tarfile
    from .repo import derived_state_roots
    from .seed import SeedRefused, derived_state_members
    framework = _stack(args).FRAMEWORK
    try:
        return derived_state_members(
            seed_dir, derived_state_roots(
                framework, behat=_behat_row(args) if framework == "behat" else None))
    except (SeedRefused, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    except (OSError, tarfile.TarError) as exc:
        raise SystemExit(f"REFUSED: cannot read the derived-state baseline "
                         f"from seed {seed_dir}: {exc}") from exc


def cmd_stamp_draw(args) -> int:
    """Record that a row is a repeat draw -- derived, checked, never typed.

    The operator supplies WHICH item, WHERE its discarded attempt was moved to,
    and WHY it was discarded.  Everything else -- the draw number, what the
    prior attempt scored, the digest of the evidence -- is read off disk, and
    the command refuses when the evidence does not support the claim: no prior
    row for that item, a prior row that PASSED, a prior row from another
    campaign.  See `r2t.bench.draws` for the field and both reason classes.

    It also refuses to break a merged campaign's `rows_digest` in silence --
    `--update-campaign-sidecar` carries that attestation forward and keeps the
    superseded digest on record.
    """
    from . import draws as D
    try:
        res = D.stamp_run(
            args.run, args.item, args.discarded, args.reason,
            evidence=args.evidence or [], dry_run=args.dry_run,
            update_campaign_sidecar=args.update_campaign_sidecar)
    except D.DrawRefusal as e:
        raise SystemExit(str(e))
    print(json.dumps(res, indent=1, sort_keys=True))
    side = res.get("campaign_sidecar")
    if side and not args.dry_run and res["changed"]:
        # Named on stdout as well as in the JSON: a digest that moved is the
        # kind of thing an operator has to be able to quote later.
        print(f"campaign sidecar carried forward: "
              f"{os.path.basename(side['path'])} rows_digest {side['was']} -> "
              f"{side['now']} (the superseded digest is kept in "
              f"`rows_digest_history` with the reason).")
    elif side and args.dry_run:
        print(f"NOTE: {os.path.basename(side['path'])} attests rows_digest "
              f"{side['was']} for this file; stamping will supersede it.")
    if args.dry_run:
        print("DRY RUN: nothing was written. Drop --dry-run to stamp.")
    elif not res["changed"]:
        print("no change: the row already carries exactly this stamp.")
    return 0


def cmd_report(args) -> int:
    from . import draws as D
    from .report import ReportRefusal, report
    if getattr(args, "publication_v3", False):
        return _report_publication_v3(args)
    non_vacuous_out = getattr(args, "non_vacuous_out", None)
    if non_vacuous_out is not None:
        # One run, one explicit summary: the file is the code-of-record
        # `report.non_vacuous` of exactly that pair, never a guess among
        # several runs or a discovered sidecar.
        if len(args.run) != 1 or len(args.test_quality or ()) != 1:
            raise SystemExit(
                "REFUSED: --non-vacuous-out writes one run's non-vacuous "
                "block; name exactly one --run and one --test-quality.")
        if os.path.lexists(non_vacuous_out):
            raise SystemExit(
                f"REFUSED: {non_vacuous_out} already exists.")
    reader = _reference_controls_reader(args)
    try:
        report(args.run, per_item=args.per_item, only=args.only or "",
               group_by=args.group_by or "",
               test_quality_paths=args.test_quality,
               release_paths=args.release,
               reference_controls_reader=reader)
    except D.DrawRefusal as e:
        # A malformed repeat-draw stamp can only come from a hand edit, and it
        # stops the read for the same reason a refusal does: absence means
        # "not known to be a repeat" everywhere in this file, so a stamp
        # nobody can parse must not quietly become a first draw.
        raise SystemExit(str(e))
    except ReportRefusal as e:
        # The message already starts `REFUSED:` and explains the harm; it is
        # raised before anything is printed, so the refusal is the whole
        # output rather than a footnote under a table nobody should have.
        raise SystemExit(str(e))
    if non_vacuous_out is not None:
        from . import report as REPORT
        from . import test_quality as TQ
        run_path, summary_path = args.run[0], args.test_quality[0]
        # Revalidated through the same reader the printed report used.
        bound = TQ.load_bound_test_quality(
            run_path, summary_path, reference_controls_reader=reader)
        # Over benchmark 2.0's population, as the printed report counts it.
        rows, bound, exclusions = REPORT.benchmark_population_rows(
            TQ.load_jsonl(run_path), bound)
        block = REPORT.non_vacuous(rows, bound)
        if exclusions is not None:
            block["population_exclusions"] = exclusions
        with open(non_vacuous_out, "x", encoding="utf-8") as handle:
            json.dump(block, handle, indent=1, sort_keys=True)
            handle.write("\n")
        print(f"non-vacuous block written: {non_vacuous_out}")
    return 0


def _jsonl_rows(path: str) -> list[dict]:
    """EVERY line of a run file, uncollapsed -- what `r2t.bench.draws` reads.

    `metrics.read_runs` keeps the last row per item; the lines it drops are the
    only on-disk trace of an item re-run IN PLACE, which is a repeat draw
    nobody had to remember to stamp.
    """
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _format_p_value(value: float) -> str:
    """Four decimals normally; scientific notation before they round to 0."""
    fixed = f"{value:.4f}"
    return f"{value:.3e}" if value > 0.0 and fixed == "0.0000" else fixed


def _compare_impl(args, clusters: dict | None = None) -> int:
    """Two runs, ONE fixed item set, and intervals that know about clusters.

    `results` produces one system's table; this produces the only comparison
    between two that is defensible here.  Everything it prints is
    cluster-aware because the items are not independent: 422 items share 142
    gold closures, so an interval computed over items counts observations the
    corpus never made (`release.closure_clusters`).  The item-level Wilson
    interval is printed too, carrying the label that says exactly what it
    ignores -- it is the number a reader would otherwise compute themselves,
    and printing it beside the cluster interval is how the gap is made
    visible rather than argued about.

    The denominator/inference refusals are:

      * not exactly two runs -- this is a paired test, not a leaderboard;
      * runs covering different item sets, which are NEVER intersected: the
        denominator is fixed before execution and a run that crashed on its
        hard items must not be re-scored on its easy ones.  `--items` names
        a denominator from a FILE instead, and then both runs must cover it
        in full -- that is a set pinned before the runs, not an intersection
        taken after them;
      * an item with no gold sidecar, whose correlation with the rest of the
        corpus is therefore unknown;
      * rows carrying two different `comparison_class` values, which are on
        record as measuring different things.
      * a released subset carrying `inference_valid: false`, or fewer than 20
        distinct closure clusters. Descriptive rates remain reportable; this
        command's interval and paired p-value do not.

    WHICH OUTCOME IS PAIRED IS A FLAG (`--metric`), AND IT HAS TO BE.  The
    contract's headline is `non_vacuous_pass_at_1`, not `pass_at_1`, and on a
    corpus where a do-nothing submission passes 239/239 the two are not
    variations on one number -- they can point in different directions with the
    same evidence.  Measured on the python-docx pair: both arms pass 32/32, the
    cluster bootstrap collapses onto a point in both, and McNemar reads
    b=0 c=0 p=1.0000, an exactly zero-information table; pair the NON-VACUOUS
    outcome of the same 32 items and the same two arms are 19/32 and 8/32,
    discordant 11-0, p=0.0010.  A comparison verb that could only express the
    first would leave the publishable number to be hand-assembled beside it,
    which is how a published figure and a reproducible one come apart.

    `--metric` rather than a bare `--non-vacuous` switch: the value NAMES the
    metric in the contract's own vocabulary and is printed in the header, so a
    pasted comparison says which of the two it is; a boolean's default is
    invisible in its own output.

    The non-vacuous mode adds refusals of its own, all loud, none ever
    degrading to functional pass:

      * a missing or stale test-quality summary on either side
        (`report.non_vacuous_view` -- the same rule `report` withholds the
        published rate under, reused rather than restated);
      * two different mutation ENGINES -- checked as the (name, VERSION) pair,
        and refused when either half is missing on either side.
        `r2t-mutate`'s eight PHP operators and `r2t-mutate-py`'s eight Python
        ones are neither the same operators nor comparably hard to kill, so a
        CoreShop arm and a python-docx arm have no common non-vacuity scale to
        be paired on -- and the items would differ anyway, which the
        denominator check above catches first for exactly one shape of that
        mistake and not for all of them.  The version is half of the identity
        rather than a label on it: `mutation.py` hashes it into every mutant
        id, `test_quality.run_slice` refuses when either half disagrees with
        the manifest, and a bump that adds an operator changes what
        `equivalent_to_reference` means over.
      * a missing or different `population_id`. Engine@version deliberately
        stays fixed between population v1 and v2, so it cannot substitute for
        the catalogue identity.
      * a different verdict basis, or two assertion-hard summaries bound to
        different hard-subset artifact digests.  Full-gold and hard-subset
        equivalence are different outcome vectors even over one population.
    """
    from . import draws as D
    from . import metrics as M
    from . import report as R
    from ..data import subsets as SS
    from ..data.release import cluster_stats, closure_clusters

    if len(args.run) != 2:
        raise SystemExit(
            f"REFUSED: compare takes exactly two --run files, "
            f"{len(args.run)} given. A paired test needs a pair; ranking N "
            f"systems by running this N-choose-2 times would need a "
            f"multiplicity correction this command does not apply.")
    path_a, path_b = args.run
    try:
        # Publication input is checked UNCOLLAPSED.  `read_runs` remains
        # last-row-wins for operational retry readers, but applying it first
        # here would silently move a comparison's denominator.
        raw_a, raw_b = _jsonl_rows(path_a), _jsonl_rows(path_b)
        R.check_unique_item_ids(raw_a, path_a)
        R.check_unique_item_ids(raw_b, path_b)
        # R4 item 7: the third publication entry point, gated like the other
        # two and BEFORE stdout.  A paired test over two projects at once
        # would pool them into one discordance count, which is the same
        # weighted average `check_single_project` refuses one level up -- and
        # there is no `--group-by` here to partition into, because a pair is
        # the unit.
        R.check_single_project(raw_a + raw_b)
        pure_submitted = R.check_single_tier(raw_a + raw_b)
        rows_a, rows_b = M.read_runs(path_a), M.read_runs(path_b)
    except FileNotFoundError as e:
        # The house rule results.py pins for itself: a missing run file
        # raises a NAMED refusal, never a traceback and never an empty table.
        raise SystemExit(f"REFUSED: no run file at {e.filename!r}. Both "
                         f"--run paths must exist; nothing is compared "
                         f"against an absence.")
    except R.ReportRefusal as e:
        raise SystemExit(str(e))
    # `check_single_tier` above refuses the MIXED case; two pure submitted
    # arms sail past it, and until this gate they ran the full bootstrap and
    # McNemar machinery.  That is a comparison the tier is barred from by
    # construction, not by power: neither arm declares a generation protocol,
    # so a paired test between them manufactures exactly the study comparison
    # the amendment closed (EXTERNAL_CANDIDATE_SUBMISSION_AMENDMENT.md,
    # decision 2 -- "labelled unattested and never compared").
    if pure_submitted:
        raise SystemExit(
            "REFUSED: submitted-tier rows are never compared "
            "(EXTERNAL_CANDIDATE_SUBMISSION_AMENDMENT.md decision 2): "
            "neither arm declares a generation protocol, so a paired test "
            "between them would manufacture a study comparison. Use `r2t "
            "report` for descriptive inspection of the submitted tier.")

    for path, rows in ((path_a, raw_a), (path_b, raw_b)):
        if os.path.lexists(str(path) + ".headroom.json"):
            from ..java import kapua_headroom as H
            try:
                H.load_run_projection(path)
            except (ValueError, OSError) as exc:
                raise SystemExit(str(exc)) from exc
            raise SystemExit("REFUSED: a headroom scoring view is descriptive-only; no interval or paired p-value")
        if any(str(row.get("subset_id", "")).startswith("headroom_") for row in rows):
            raise SystemExit("REFUSED: headroom runs have inference_valid:false, including without --items")
        from ..ruby import evaluation_selection as ruby_selection
        if any(row.get("subset_id") == ruby_selection.SUBSET_ID for row in rows):
            raise SystemExit("REFUSED: e-petitions implementation census is descriptive-only; no interval or paired p-value")

    # The denominator, resolved in exactly one of two ways.  With --items it
    # is that FILE -- a set named before either run existed -- and each run is
    # then required to cover it.  Without --items it is the runs' own item
    # set, which must therefore be identical in both.  What is never done is
    # the third thing: taking the intersection of two runs that disagree.
    if args.items:
        try:
            subset_identity = SS.identify_for_inference(args.items)
        except SS.SubsetRefused as exc:
            # Replay the subset construction before any statistic or stdout.
            # An edited declaration must not degrade into an ad-hoc input.
            raise SystemExit(str(exc))
        if subset_identity is not None \
                and (subset_identity.get("inference_valid") is False
                     or (subset_identity.get("allow_cluster_siblings") is True
                         and not (subset_identity.get("selection_unit") == "step_definition_set"
                                  and subset_identity.get("inference_unit") == "closure_file_set"))):
            raise SystemExit(
                f"REFUSED: {args.items} is released as a descriptive-only "
                f"subset with inference_valid: "
                f"{str(subset_identity.get('inference_valid')).lower()}"
                + (" and allow_cluster_siblings: true"
                   if subset_identity.get("allow_cluster_siblings") is True
                   else "")
                + ". `r2t report` can render descriptive rates, but `r2t "
                  "compare` will not produce a bootstrap interval or paired "
                  "p-value from this artifact.")
        pinned = sorted(set(M.load_items(args.items)))
        for path, rows in ((path_a, rows_a), (path_b, rows_b)):
            absent = sorted(set(pinned) - set(rows))
            if absent:
                raise SystemExit(
                    f"REFUSED: {len(absent)} of the {len(pinned)} item(s) in "
                    f"{args.items} have no row in {os.path.basename(path)} "
                    f"(e.g. {absent[0]}). The pinned set IS the denominator; "
                    f"an item that run never attempted is a missing "
                    f"measurement, and dropping it would score that run over "
                    f"a smaller corpus than its opponent.")
        ids = pinned
        denom_src = f"{args.items}, {len(ids)} items"
    elif set(rows_a) != set(rows_b):
        only_a = sorted(set(rows_a) - set(rows_b))
        only_b = sorted(set(rows_b) - set(rows_a))

        def _side(path, only):
            return (f"{len(only)} only in {os.path.basename(path)}"
                    + (f" (e.g. {only[0]})" if only else ""))
        raise SystemExit(
            f"REFUSED: the two runs cover different item sets "
            f"({len(rows_a)} vs {len(rows_b)} items). "
            f"{_side(path_a, only_a)}, {_side(path_b, only_b)}. They are not "
            f"intersected: the denominator is fixed before execution and "
            f"never moves afterwards, so the missing items are a result about "
            f"the run, not rows to drop. Pass --items ONLY if some file is the "
            f"set both runs were commissioned over and both cover it in full "
            f"-- a sweep over 422 items against a sweep over eval100 is that "
            f"case; a sweep that crashed on 12 items is not.")
    else:
        ids = sorted(rows_a)
        denom_src = "the runs themselves (identical item sets)"

    # Benchmark 2.0's listed instances are collected and counted in no
    # metric (BENCHMARK_V2_SPEC.md section 6), so they leave the pair too.
    from . import population as P
    try:
        blocks = [P.row_exclusions(raw_a), P.row_exclusions(raw_b)]
    except P.PopulationRefusal as e:
        raise SystemExit(str(e))
    left_out = {entry["item_id"]: entry for block in blocks if block
                for entry in block["excluded"] if entry["item_id"] in ids}
    if left_out:
        ids = [i for i in ids if i not in left_out]
        governing = next(block for block in blocks if block)
        left_out = dict(governing, count=len(left_out),
                        excluded=[left_out[i] for i in sorted(left_out)])

    try:
        # In publication mode the map is already derived from the recursively
        # verified compare-gold closure bytes; the directory is not reopened.
        cmap = closure_clusters(args.gold_dir) if clusters is None else clusters
        cls = M.comparison_class([rows_a[i] for i in ids]
                                 + [rows_b[i] for i in ids])
    except (FileNotFoundError, M.MetricsInputError) as e:
        raise SystemExit(str(e) if str(e).startswith("REFUSED:")
                         else f"REFUSED: {e}")
    unclustered = [i for i in ids if i not in cmap]
    if unclustered:
        raise SystemExit(
            f"REFUSED: {len(unclustered)} item(s) have no closure-cluster "
            f"entry under {args.gold_dir} (e.g. {unclustered[0]}), so their "
            f"closure -- and "
            f"with it their correlation with every other item -- is unknown. "
            f"Scoring them as clusters of their own would assume they are "
            f"independent, which is the assumption this command exists to "
            f"stop making.")

    metric = getattr(args, "metric", None) or "pass"
    # The default path is byte-for-byte what it always was: same vector, same
    # verb, same nouns.  Everything the non-vacuous mode adds is guarded on
    # `metric`, because a comparison already published must keep rendering the
    # way it was published.
    verb, noun, one = "passed", "passes", "pass"
    engines: dict = {}
    if metric == "pass":
        out_a = {i: rows_a[i].get("outcome") == "passed" for i in ids}
        out_b = {i: rows_b[i].get("outcome") == "passed" for i in ids}
    else:
        verb, noun, one = (R.NON_VACUOUS_DISPLAY,
                           f"{R.NON_VACUOUS_DISPLAY} passes",
                           f"{R.NON_VACUOUS_DISPLAY} pass")
        tq_paths = getattr(args, "test_quality", None)
        if tq_paths is not None and len(tq_paths) != 2:
            raise SystemExit(
                f"REFUSED: compare received {len(tq_paths)} explicit "
                "--test-quality summaries for two --run arms. Supply exactly "
                "two in A/B order, or omit both to use unique sidecars.")
        tq_paths = tq_paths or (None, None)
        try:
            view_a = R.non_vacuous_view(
                path_a, list(rows_a.values()), tq_paths[0])
            view_b = R.non_vacuous_view(
                path_b, list(rows_b.values()), tq_paths[1])
        except R.ReportRefusal as e:
            # LOUD, and never a fallback to functional pass: the whole reason
            # this mode exists is that the two metrics disagree.
            raise SystemExit(str(e))
        # ENGINE IDENTITY IS THE (name, version) PAIR, and it is checked as
        # one.  `mutation.py` puts `engine_version` inside every mutant id
        # hash, `test_quality.run_slice` refuses when EITHER half disagrees
        # with the manifest, and VERSIONS.yml lists the mutation harnesses as
        # versioned components because "a change here changes which mutants
        # exist and therefore what recall is measured over".  A version bump
        # that adds or retunes operators changes what
        # `equivalent_to_reference` MEANS, exactly as a PHP/Python swap does --
        # so checking the name alone would leave the header line below
        # asserting a property nobody verified.
        # R4 item 6, second leg.  A paired discordance count is only as
        # publishable as the two vectors it pairs, and the completeness
        # qualifier is now on both of them: an arm scored over a short gold
        # set, or one whose gold partly ended in the harness failing without
        # recorded consent, cannot be differenced against a complete arm and
        # called a result.  Refused rather than annotated, because the OUTPUT
        # of this verb is a single p-value that carries no room for a caveat.
        for side, view, path in (("A", view_a, path_a), ("B", view_b, path_b)):
            reasons = view["summary"].get("withheld_reasons") or []
            if reasons:
                raise SystemExit(
                    f"REFUSED: arm {side} ({os.path.basename(path)}) is not "
                    f"publication-ready non-vacuous evidence: "
                    f"{'; '.join(reasons)}. A paired {R.NON_VACUOUS_DISPLAY} "
                    f"comparison differences two vectors and prints one "
                    f"p-value; an arm measured over a smaller or degraded "
                    f"gold set is not on the same scale as one measured over "
                    f"the full one, and the difference would be read as the "
                    f"systems disagreeing. Rescore that arm, or compare "
                    f"`--metric pass`, which does not rest on gold.")
        engines = {"A": (view_a["engine"], view_a["engine_version"]),
                   "B": (view_b["engine"], view_b["engine_version"])}

        def _shown(pair) -> str:
            e, v = pair
            return f"{e or '(unnamed)'} {v or '(unversioned)'}"

        incomplete = [k for k, (e, v) in sorted(engines.items())
                      if not e or not v]
        if incomplete or len(set(engines.values())) != 1:
            raise SystemExit(
                f"REFUSED: a non-vacuous comparison needs ONE mutation engine, "
                f"named and versioned, and these summaries declare "
                f"A={_shown(engines['A'])}, B={_shown(engines['B'])}. A "
                f"verdict of `{R.NON_VACUOUS_VERDICT}` means the candidate "
                f"killed everything the reference killed IN THAT ENGINE's "
                f"operator set, and r2t-mutate's eight PHP operators are "
                f"neither the same operators as r2t-mutate-py's eight Python "
                f"ones nor comparably hard to kill. Pairing them would compare "
                f"two systems on two different scales and call the difference "
                f"a result. Compare arms of one project."
                + (" A VERSION is half of that identity, not a label on it: "
                   "`mutation.py` hashes engine_version into every mutant id "
                   "because two engines can produce the same replacement at "
                   "the same span by different rules, so one version's "
                   "operator population is not another's."
                   if not incomplete else "")
                + (f" ({', '.join(incomplete)} does not name both halves. An "
                   f"engine that is not fully identified is refused rather "
                   f"than assumed: a summary written before the column existed "
                   f"cannot say which population it is about, and assuming the "
                   f"other side's would be this command inventing the one fact "
                   f"it is checking.)" if incomplete else ""))
        population_ids = {"A": view_a.get("population_id"),
                          "B": view_b.get("population_id")}
        missing_population = [side for side, population_id
                              in sorted(population_ids.items())
                              if not population_id]
        if missing_population or len(set(population_ids.values())) != 1:
            raise SystemExit(
                f"REFUSED: a non-vacuous comparison needs ONE non-empty "
                f"population_id on both arms, and these summaries declare "
                f"A={population_ids['A']!r}, B={population_ids['B']!r}. "
                f"Engine name and version are not enough: population v1 and "
                f"v2 deliberately retain the same engine@version while their "
                f"operator catalogues differ. Rescore or bind the summaries "
                f"to one registered population before producing a paired "
                f"reference-equivalent p-value.")
        bases = {"A": view_a.get("verdict_basis"),
                 "B": view_b.get("verdict_basis")}
        if len(set(bases.values())) != 1:
            raise SystemExit(
                "REFUSED: the two non-vacuous arms use different verdict "
                f"bases (A={bases['A']!r}, B={bases['B']!r}). A legacy "
                "full-gold vector and C4's assertion-hard vector are "
                "different outcomes even when their engine/population ids "
                "match; rescore both arms under one basis.")
        if bases["A"] == "hard_subset":
            hard_digests = {
                "A": view_a.get("hard_subset_digest"),
                "B": view_b.get("hard_subset_digest"),
            }
            if not all(hard_digests.values()) \
                    or len(set(hard_digests.values())) != 1:
                raise SystemExit(
                    "REFUSED: assertion-hard comparison needs one non-empty "
                    "hard-subset artifact digest on both arms, and these "
                    f"summaries declare A={hard_digests['A']!r}, "
                    f"B={hard_digests['B']!r}.")
        out_a = {i: view_a["outcomes"][i] for i in ids}
        out_b = {i: view_b["outcomes"][i] for i in ids}
    sub = {i: cmap[i] for i in ids}
    st = cluster_stats(sub)
    n_clusters = st["effective_closure_cardinality"]

    # The function calls below enforce this independently; this preflight is
    # what keeps a redirected CLI table empty when the released subset is too
    # small for inference.  Descriptive reporting remains available through
    # `r2t report` and metrics.collapse_clusters.
    try:
        M.require_inference_clusters(
            out_a, sub,
            "cluster bootstrap and exact cluster-collapsed McNemar")
    except M.MetricsInputError as e:
        raise SystemExit(str(e))

    # BEFORE the first print, with every other refusal.  `D.summarise` refuses
    # on a malformed stamp, and `D.check_campaign_pair` refuses when a merged
    # run no longer hashes to what its campaign sidecar attests; a refusal
    # raised further down would go to stderr under a header block already
    # written to stdout, so a redirected comparison would look finished while
    # omitting the very disclosure being refused about.  Only `D.disclosure`,
    # which cannot refuse, prints below.
    try:
        redraws = {}
        for label, path in (("A", path_a), ("B", path_b)):
            D.check_campaign_pair(path)
            # Scoped to `ids`, the set this table is over: `--items` can pin a
            # subset, and a disclosure counted over the whole file would print
            # a denominator the table does not have and name an item the table
            # does not contain as included in it.
            redraws[label] = D.summarise(_jsonl_rows(path), items=ids)
    except D.DrawRefusal as e:
        raise SystemExit(str(e))

    print(f"items   : {len(ids)}  (fixed denominator: {denom_src})")
    if left_out:
        print("2.0 excluded: " + R.population_exclusions_text(left_out))
    print(f"clusters: {n_clusters} distinct gold closures "
          f"({st['items_in_closure_clusters']} of the items share one with a "
          f"sibling, largest {st['largest_closure_cluster']})")
    print(f"gold    : {args.gold_dir}")
    print("class   : " + (f"comparison_class={cls}" if cls else
                           "no row carries a comparison_class "
                           "(grandfathered-unknown on both sides)"))
    if metric != "pass":
        # Only in the new mode, so the published functional rendering is
        # untouched -- and unmissable in it, because a non-vacuity claim read
        # as a pass rate is a much bigger error than the reverse.
        print(f"metric  : non_vacuous_pass_at_1 -- "
              f"{R.NON_VACUOUS_DISPLAY}: a pass whose test kills everything "
              f"the reference kills on that item (stored verdict "
              f"{R.NON_VACUOUS_VERDICT!r}); a bare pass is NOT one")
        # Safe to say "both sides": the guard above refused unless the two
        # (name, version) pairs are identical AND both halves are named, so
        # this line reports what was checked rather than what was hoped.
        print(f"engine  : {engines['A'][0]} {engines['A'][1]} "
              f"(both sides, checked as a (name, version) pair; a mixed "
              f"engine or a version skew is refused)")
        print(f"population: {population_ids['A']} (both sides; mixed "
              f"population generations are refused)")
    # Before the intervals, because a re-drawn item is inside both of them.
    # One arm's second draw does not make the pair incomparable -- it makes the
    # pair asymmetric, and an asymmetry a reader cannot see is the one that
    # gets quoted.
    for label, summary in redraws.items():
        for line in D.disclosure(summary, indent=""):
            print(f"{label} {line}")
    print()
    widths = []
    for label, path, out in (("A", path_a, out_a), ("B", path_b, out_b)):
        k = sum(1 for v in out.values() if v)
        coll = M.collapse_clusters(out, sub)
        ck = sum(1 for v in coll.values() if v)
        lo, hi = M.cluster_bootstrap(out, sub)
        wlo, whi = M.wilson_interval(k, len(ids))
        # How the passes are distributed over closures is the whole reason
        # either interval is wider than the other, so it is measured here and
        # reported below rather than assumed.
        pass_clusters: dict[str, int] = {}
        for i, v in out.items():
            if v:
                pass_clusters[sub[i]] = pass_clusters.get(sub[i], 0) + 1
        widths.append({"label": label, "k": k, "degenerate": lo == hi,
                       "cluster": hi - lo, "wilson": whi - wlo,
                       "n_pass_clusters": len(pass_clusters),
                       "largest_pass_cluster": max(pass_clusters.values(),
                                                   default=0)})
        print(f"{label}  {path}")
        print(f"     {verb} {k}/{len(ids)} = {k / len(ids):.3f}   "
              f"clusters {verb} {ck}/{n_clusters} (all-pass rule)")
        # A boundary rate collapses the percentile bootstrap onto a point:
        # every resample redraws the same outcome. Said out loud, because
        # "95% CI [0.000, 0.000]" read as precision would be a lie.
        note = ("   DEGENERATE: every cluster scored the same, so every "
                "resample does too; the bootstrap cannot bound a boundary "
                "rate. Read the Wilson bound below."
                if lo == hi else "")
        print(f"     cluster bootstrap 95% CI  [{lo:.3f}, {hi:.3f}]{note}")
        print(f"     wilson 95% CI             [{wlo:.3f}, {whi:.3f}]  "
              f"({M.WILSON_LABEL})")
    mc = M.mcnemar_cluster_collapsed(out_a, out_b, sub)
    print()
    print("McNemar, exact, over clusters collapsed by the all-pass rule:")
    print(f"     b (A {verb}, B did not) = {mc['b']}   "
          f"c (B {verb}, A did not) = {mc['c']}   "
          f"discordant = {mc['b'] + mc['c']} of {mc['n_clusters']}")
    print(f"     p = {_format_p_value(mc['p'])}")
    print()
    print(f"The bootstrap resamples {n_clusters} clusters with replacement, "
          f"10000 times, seed {M.BOOTSTRAP_SEED} (sorted cluster order, so "
          f"the interval depends on the data and the seed alone).")
    print("A cluster is one gold closure file-set; per-item outcomes within "
          "one are correlated by construction. Clustering therefore widens "
          "the interval only where the passes CONCENTRATE behind a shared "
          "closure -- where each pass sits in a closure of its own, the two "
          "intervals see the same evidence and either can come out narrower. "
          "Which happened here is measured, not assumed:")
    # Never an unconditional claim about which interval is wider: the widths
    # are printed a few lines above and would contradict it the first time a
    # run's passes happened to be spread out (as, on the eval100 pair, they
    # are).
    for w in widths:
        cw, ww = w["cluster"], w["wilson"]
        if w["degenerate"]:
            verdict = ("the cluster bootstrap collapsed onto a point (see "
                       "above), so it has no width to compare")
        elif round(cw, 3) > round(ww, 3):
            verdict = (f"clustering WIDENS it: cluster width {cw:.3f} vs "
                       f"item-level {ww:.3f}")
        elif round(cw, 3) < round(ww, 3):
            verdict = (f"the ITEM-LEVEL interval is the wider one here: "
                       f"cluster width {cw:.3f} vs item-level {ww:.3f}")
        else:
            verdict = (f"the two are the same width to three decimals "
                       f"({cw:.3f})")
        if w["k"] == 0:
            why = (f"no item {verb}, so there is no {one} for a shared closure "
                   f"to concentrate")
        elif w["largest_pass_cluster"] <= 1:
            why = (f"the {w['k']} {noun} fall in {w['k']} distinct clusters, "
                   f"so no closure carries more than one of them")
        else:
            why = (f"the {w['k']} {noun} fall in {w['n_pass_clusters']} "
                   f"cluster(s), the largest carrying "
                   f"{w['largest_pass_cluster']} of them")
        print(f"     {w['label']}: {verdict} -- {why}.")
    return 0


#: Which publication-consumer options take a separate value token.  The
#: occurrence scan needs it so an option-shaped VALUE is never counted.
_PUBLICATION_CONSUMER_VALUE_OPTIONS = {
    "report": ("--publication-commit", "--publication-role", "--out", "--run",
               "--test-quality", "--only", "--group-by", "--release"),
    "results": ("--publication-commit", "--publication-role", "--out", "--run",
                "--gold", "--test-quality", "--prod-index", "--format",
                "--release"),
    "compare": ("--publication-commit", "--publication-role", "--out", "--run",
                "--gold-dir", "--items", "--metric", "--test-quality"),
}
#: (option, minimum, maximum) occurrences; `None` is unbounded.  Repeating a
#: singleton REFUSES rather than taking argparse's last value.
_PUBLICATION_CONSUMER_OCCURRENCES = {
    "report": (("--publication-v3", 1, 1), ("--publication-commit", 1, 1),
               ("--out", 1, 1), ("--run", 1, None), ("--per-item", 0, 1)),
    "results": (("--publication-v3", 1, 1), ("--publication-commit", 1, 1),
                ("--out", 1, 1), ("--run", 1, 1), ("--gold", 1, 1),
                ("--format", 0, 1)),
    "compare": (("--publication-v3", 1, 1), ("--publication-commit", 1, 1),
                ("--out", 1, 1), ("--run", 2, 2), ("--gold-dir", 1, 1),
                ("--metric", 0, 1)),
}


def _publication_parser_kwargs(command: str, publication: str | None) -> dict:
    """Publication parsers take exact spellings; default parsers are untouched.

    argparse resolves a unique PREFIX to its full option by default, and the
    occurrence scan below can only see the literal token that was typed.  The
    two together mean `--out A --ou B` passes the scan and argparse then hands
    the command B -- exactly the "argparse's last value" the grammar forbids,
    reached by spelling the repeat differently.  So the publication form of a
    consumer parses without abbreviation; an abbreviated spelling is then not
    a second occurrence of anything, it is not an option at all.
    """
    return {"allow_abbrev": False} if publication == command else {}


def _publication_consumer_scan(command: str, tail: list) -> None:
    """Count the exact option occurrences a publication request may carry."""
    value_options = set(_PUBLICATION_CONSUMER_VALUE_OPTIONS[command])
    counts: dict = {}
    index = 0
    while index < len(tail):
        token = tail[index]
        if not token.startswith("--"):
            index += 1
            continue
        name, separator, _value = token.partition("=")
        counts[name] = counts.get(name, 0) + 1
        index += 1 if separator or name not in value_options else 2
    for name, minimum, maximum in _PUBLICATION_CONSUMER_OCCURRENCES[command]:
        count = counts.get(name, 0)
        if count < minimum or (maximum is not None and count > maximum):
            bound = (f"exactly {minimum}" if minimum == maximum
                     else f"at least {minimum}" if maximum is None
                     else f"between {minimum} and {maximum}")
            raise SystemExit(
                f"REFUSED: {command} --publication-v3 takes {bound} "
                f"{name} occurrence(s), {count} given. A repeated singleton "
                f"is refused rather than resolved to its last value.")


def _cucumber_mutants_request(tail: list[str]) -> bool:
    """Expose release-review options only to an exact Java build/map argv."""
    actions = {"build", "map"}
    action = tail[0] if tail and tail[0] in actions else None
    if action is None and len(tail) >= 3 and tail[0] == "--profile" \
            and tail[2] in actions:
        action = tail[2]
    if action is None and len(tail) >= 2 \
            and tail[0].startswith("--profile=") and tail[1] in actions:
        action = tail[1]
    if action is None:
        return False
    profiles = []
    for index, token in enumerate(tail):
        if token == "--profile" and index + 1 < len(tail):
            profiles.append(tail[index + 1])
        elif token.startswith("--profile="):
            profiles.append(token.partition("=")[2])
    if len(profiles) != 1 or not profiles[0]:
        return False
    try:
        from ..data.profile import load_profile
        return load_profile(profiles[0]).framework == "cucumber"
    except (Exception, SystemExit):                       # malformed profile
        return False


def _add_reference_sensitivity_options(parser) -> None:
    """The labelled reference basis options `report` and `results` share.

    `test-quality` scores under the basis; `report` and `results` reopen a
    summary scored under it, which re-derives the same in-memory controls and
    so needs the same three options
    (specifications/SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md).
    `test-quality` declares its own `--sensitivity`, which also names the
    run-row labels.
    """
    parser.add_argument("--sensitivity", default=None,
                        choices=("sylius_stub_gate_waived_v1",),
                        help="with --reference-scope and --reference-controls, "
                             "in place of --reference-attestation: reopen a "
                             "summary scored under the labelled basis of a "
                             "reference whose stub gate failed "
                             "(specifications/SYLIUS_STUB_GATE_WAIVED_"
                             "SENSITIVITY_SPEC.md)")
    _add_reference_basis_consent_options(parser)


def _add_reference_basis_consent_options(parser) -> None:
    parser.add_argument("--allow-excluded-pairs", action="store_true",
                        help="with a labelled reference --sensitivity: the "
                             "recorded consent to the reference's section 5.1 "
                             "exclusions, which an attestation would "
                             "otherwise carry")
    parser.add_argument("--gold-disagreements", default=None, metavar="JSON",
                        help="with a labelled reference --sensitivity: "
                             "r2t.gold-disagreements/1 pairs the scoring "
                             "host's gold-agreement pilot did not kill; they "
                             "leave the full-gold kill set and the hard subset "
                             "and are listed, with the document's source and "
                             "SHA-256, in the controls and the summary")


def _sensitivity_arguments(args) -> dict | None:
    """The labelled reference basis keyword arguments, or None.

    Only a label of `reference_controls.SENSITIVITY_PROJECTS` names a
    reference basis; `webmock_world_v1` is a run-row label and is not one.
    `--allow-excluded-pairs` and `--gold-disagreements` mean something only
    under a reference basis, so either without one refuses rather than being
    silently ignored.
    """
    from . import reference_controls as RC
    sensitivity = getattr(args, "sensitivity", None)
    if sensitivity not in RC.SENSITIVITY_PROJECTS:
        if getattr(args, "allow_excluded_pairs", False) \
                or getattr(args, "gold_disagreements", None) is not None:
            raise SystemExit(
                "REFUSED: --allow-excluded-pairs and --gold-disagreements "
                "belong to a labelled reference --sensitivity basis.")
        return None
    path = getattr(args, "gold_disagreements", None)
    try:
        pairs, binding = (RC.load_gold_disagreements(path) if path is not None
                          else (frozenset(), None))
    except RC.ReferenceControlsRefused as exc:
        raise SystemExit(str(exc)) from exc
    return {"sensitivity": sensitivity,
            "allow_excluded_pairs": bool(getattr(args, "allow_excluded_pairs",
                                                 False)),
            "gold_disagreements": pairs,
            "gold_disagreements_binding": binding}


def _add_reference_controls_options(parser, *, go_control_plans=False) -> None:
    """Name the installed reference collection a v2 sidecar is scored under.

    One option per installed artifact, because nothing on disk indexes them:
    the attestation records digests, not paths, and inventing a directory
    convention here would be a new artifact contract rather than a way to
    read the existing one.  All of them together, or none: a v2 sidecar
    without its authenticated controls refuses.
    """
    parser.add_argument(
        "--reference-controls", metavar="DIR", default=None,
        help="the installed reference collection for ONE project: a "
             "directory holding full_gold/, stripped_gold/ and stub/, each a "
             "standalone mutation output. Required to score a "
             "single-observation (r2t.test-quality-summary/v2) sidecar; "
             "without it such a sidecar refuses rather than being scored "
             "against unauthenticated controls")
    parser.add_argument(
        "--reference-attestation", metavar="JSON", default=None,
        help="the minted reference-controls document for that collection")
    parser.add_argument(
        "--reference-validation", metavar="JSON", default=None,
        help="the reviewed native mutation-validation report the reference "
             "population is bound to")
    parser.add_argument(
        "--reference-manifest", metavar="JSON", default=None,
        help="the installed scored mutation manifest")
    parser.add_argument(
        "--reference-map", metavar="JSON", default=None,
        help="the installed mutation map")
    parser.add_argument(
        "--reference-release", metavar="JSONL", default=None,
        help="the installed release the reference population is registered "
             "against")
    parser.add_argument(
        "--reference-gold-baseline", metavar="JSONL", default=None,
        help="the installed gold baseline run the reference was collected "
             "over")
    parser.add_argument(
        "--reference-engine-source", metavar="FILE", default=None,
        help="the installed mutation applier the three roles name, when it "
             "is not resolvable from the tree")
    _add_evaluation_reference_sources(parser, consumer=True,
                                      go_control_plans=go_control_plans)
    _add_reference_sensitivity_options(parser)


def _reference_controls_reader(args):
    """The authenticated installed-controls callback a v2 summary needs.

    `None` when no reference is named, which leaves every v1 invocation
    byte-identical.  When one is named, the consumer never derives bundle
    authority for itself: it forwards this callback, and the callback is the
    only thing that opens the installed tree.
    """
    _refuse_unscoped_evaluation_sources(args)
    if getattr(args, "reference_scope", None) is not None and args.reference_controls is None:
        raise SystemExit("REFUSED: --reference-scope requires --reference-controls")
    sensitivity = _sensitivity_arguments(args)
    if args.reference_controls is None:
        if sensitivity is not None:
            raise SystemExit(
                "REFUSED: --sensitivity reopens a summary against "
                "--reference-scope and --reference-controls.")
        return None
    if sensitivity is not None and (
            getattr(args, "reference_scope", None) is None
            or getattr(args, "reference_attestation", None) is not None):
        raise SystemExit(
            "REFUSED: --sensitivity reopens a summary against "
            "--reference-scope and --reference-controls in place of "
            "--reference-attestation.")
    # Six sibling paths are as structurally required as `--reference-controls`
    # itself -- `load_native_reference_controls` takes all six as keyword-only
    # arguments with no default -- and argparse does not know it, because they
    # default to `None` so that every v1 invocation stays byte-identical.  An
    # omitted one therefore travelled as `None` into `os.lstat` and came back
    # as "installed ReferenceControls reader refused: lstat: path should be
    # string, bytes or os.PathLike, not NoneType", which names neither the
    # option nor the operator's mistake.  `cmd_test_quality` does not have
    # this shape: it resolves the same six from the verb's own asset options,
    # so the natural `results --reference-controls X --reference-attestation Y`
    # -- the exact form that works for `test-quality` -- was the failing one.
    #
    # Refuse all six by name, in ONE refusal, before the tree is opened; the
    # same rule and for the same reason as `cmd_test_quality`'s seven.
    missing_reference = [
        option for option, attr in (
            ("--reference-attestation", "reference_attestation"),
            ("--reference-validation", "reference_validation"),
            ("--reference-manifest", "reference_manifest"),
            ("--reference-map", "reference_map"),
            ("--reference-release", "reference_release"),
            ("--reference-gold-baseline", "reference_gold_baseline"))
        if getattr(args, attr, None) is None
        # A labelled basis is re-derived, never read from an attestation
        # (refused above).
        and not (sensitivity is not None and attr == "reference_attestation")]
    if missing_reference:
        raise SystemExit(
            f"REFUSED: --reference-controls names the installed three-role "
            f"tree; scoring against it also needs "
            f"{', '.join(missing_reference)}. The `test-quality` verb "
            f"resolves these from its own asset options; a consumer has no "
            f"asset options to resolve them from and must be told.")
    from . import reference_loader as RL
    from . import test_quality as TQ
    project = _boundary(args).project

    def read(_summary, _expected):
        if getattr(args, "reference_scope", None) is not None:
            from .evaluation_reference import load_evaluation_reference
            if args.reference_execution_release is None:
                raise SystemExit("REFUSED: evaluation reference requires --reference-execution-release")
            scoped = argparse.Namespace(**vars(args))
            scoped.mutation_validation = args.reference_validation
            scoped.manifest, scoped.map = args.reference_manifest, args.reference_map
            scoped.release = args.reference_execution_release
            scoped.map_release = args.reference_release
            scoped.gold_baseline = args.reference_gold_baseline
            if sensitivity is not None:
                from .evaluation_reference import \
                    load_evaluation_sensitivity_reference
                controls = load_evaluation_sensitivity_reference(
                    **_evaluation_reference_arguments(scoped),
                    **sensitivity)["controls"]
            else:
                controls = load_evaluation_reference(
                    **_evaluation_reference_arguments(scoped),
                    attestation_path=args.reference_attestation)["controls"]
        else:
            controls = RL.load_native_reference_controls(
                project, args.reference_controls,
                validation_path=args.reference_validation,
                manifest_path=args.reference_manifest,
                map_path=args.reference_map,
                release_path=args.reference_release,
                gold_baseline_path=args.reference_gold_baseline,
                attestation_path=args.reference_attestation,
                engine_source_path=args.reference_engine_source,
                validation_input_paths=_validation_input_paths(args))["controls"]
        # The scoring authority is sealed by `test_quality`, which owns the
        # private seal `load_bound_test_quality` re-checks.  This callback
        # supplies the ONE authenticated object and nothing else: the seal
        # derives the scoring view from these controls itself, so there is no
        # second object here that could disagree with them.  Reaching for the
        # module-private minter is deliberate -- it is the same call
        # `score_mutation` already makes below, and publishing a second public
        # name for it would only invite a caller to hand it a hand-built view.
        return TQ._seal_single_observation_scoring_authority(controls)

    return read


def _add_publication_consumer_options(parser, *, out: bool) -> None:
    """Register the publication-only grammar of section 2 on one command."""
    parser.add_argument(
        "--publication-v3", action="store_true",
        help="render this consumer over complete merged-run receipts and "
             "write a durable positive status beside the output")
    parser.add_argument(
        "--publication-commit", metavar="COMMIT",
        help="the one full 40-lowercase-hex reviewed commit whose blobs pin "
             "every named receipt's exact bytes")
    parser.add_argument(
        "--publication-role", action="append", metavar="ROLE_JSON",
        help="one closed {receipt_path, reviewed_path, role} JSON object; "
             "repeat once per exact role. Argument order has no authority")
    if out:
        parser.add_argument(
            "--out", metavar="ABS_PATH",
            help="canonical absolute output path; its status and lock leaves "
                 "are derived from it and never overwritten")


def _publication_status_note(out_path: str) -> None:
    from . import result_ledger as ledger
    # stderr only: stdout carries neither rendered bytes nor a second status.
    sys.stderr.write(
        f"publication-v3 status: {out_path}"
        f"{ledger.PUBLICATION_STATUS_SUFFIX}\n")


def _publication_render(call) -> str:
    """Produce the complete rendering in memory, with no stdout leak."""
    import contextlib
    import io
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        call()
    return buffer.getvalue()


def _report_publication_v3(args) -> int:
    from . import draws as D
    from . import population as P
    from . import report as RP
    from . import result_ledger as ledger
    if getattr(args, "non_vacuous_out", None) is not None:
        raise SystemExit(
            "REFUSED: report --publication-v3 refuses --non-vacuous-out. "
            "Version 1 makes no mutation claim.")
    if args.test_quality:
        raise SystemExit(
            "REFUSED: report --publication-v3 refuses --test-quality. The "
            "conventional sidecar is not opened either; version 1 makes no "
            "mutation claim.")
    if args.release:
        raise SystemExit(
            "REFUSED: report --publication-v3 refuses --release. Each "
            "publication role already supplies the exact verified frozen "
            "workset recorded in the durable status.")
    if args.only or args.group_by:
        raise SystemExit(
            "REFUSED: report --publication-v3 refuses --only and --group-by. "
            "Version 1 has no filtered or partitioned claim.")
    runs = list(args.run)

    def preflight():
        return ledger.publication_preflight(
            "report", args.publication_role or (),
            commit=args.publication_commit, run_paths=runs)

    try:
        roles = preflight()
        scopes = [P.publication_scope(role) for role in roles]
        ledger.publish_consumer_output(
            consumer="report", roles=roles,
            parameters={"per_item": bool(args.per_item)},
            commit=args.publication_commit, out_path=args.out,
            render=lambda: _publication_render(
                lambda: RP.publication_report(
                    runs, per_item=args.per_item,
                    population_scopes=scopes)),
            reclose=preflight)
    except ledger.ResultLedgerRefused as exc:
        raise SystemExit(str(exc)) from exc
    # The renderer runs inside the durable seam, so ITS refusals have to
    # arrive as the same named `REFUSED:` exit the default route produces --
    # the single-project gate, a duplicate run basename and an unreadable
    # repeat-draw stamp are refusals, not tracebacks.  These are exactly the
    # two types `cmd_report` catches.
    except (RP.ReportRefusal, D.DrawRefusal, P.PopulationRefusal) as exc:
        raise SystemExit(str(exc)) from exc
    _publication_status_note(args.out)
    return 0


def _results_publication_v3(args) -> int:
    from . import draws as D
    from . import population as P
    from . import results as R
    from . import result_ledger as ledger
    if args.test_quality or args.prod_index:
        raise SystemExit(
            "REFUSED: results --publication-v3 refuses --test-quality and "
            "--prod-index; their default lookups are not called either.")
    if args.infrastructure_exclusions:
        raise SystemExit(
            "REFUSED: results --publication-v3 refuses "
            "--infrastructure-exclusions; the strict publication workset "
            "admits no ratified exclusion.")
    if args.release:
        raise SystemExit(
            "REFUSED: results --publication-v3 refuses --release. The "
            "candidate role already supplies the exact verified frozen "
            "workset recorded in the durable status.")
    if not args.gold_run:
        raise SystemExit(
            "REFUSED: results --publication-v3 requires an explicit --gold "
            "run; the artifact-directory default is never resolved.")

    def preflight():
        return ledger.publication_preflight(
            "results", args.publication_role or (),
            commit=args.publication_commit, run_paths=[args.run],
            gold_path=args.gold_run)

    try:
        roles = preflight()
        boundary = _publication_boundary(roles[0])
        ledger.publish_consumer_output(
            consumer="results", roles=roles,
            parameters={"format": args.format},
            commit=args.publication_commit, out_path=args.out,
            render=lambda: R.render(
                R.publication_results(
                    args.run, gold_path=args.gold_run, boundary=boundary,
                    population_scope=P.publication_scope(roles[0])),
                args.format),
            reclose=preflight)
    except ledger.ResultLedgerRefused as exc:
        raise SystemExit(str(exc)) from exc
    # Same two types `cmd_results` catches, for the same reason.
    except (D.DrawRefusal, P.PopulationRefusal) as exc:
        raise SystemExit(str(exc)) from exc
    except R.ResultsInputError as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    _publication_status_note(args.out)
    return 0


def _publication_boundary(role):
    """The boundary the receipts bind, never the top-level parser default."""
    from ..core.boundary import load_boundary
    return load_boundary(role.substrate["boundary"]["path"])


def _compare_publication_v3(args) -> int:
    from . import result_ledger as ledger
    if args.items:
        raise SystemExit(
            "REFUSED: compare --publication-v3 refuses --items even when it "
            "names the same set. Version 1 has one scope authority: the "
            "receipts themselves.")
    if args.test_quality:
        raise SystemExit(
            "REFUSED: compare --publication-v3 refuses --test-quality.")
    metric = args.metric or "pass"
    if metric != "pass":
        raise SystemExit(
            f"REFUSED: compare --publication-v3 takes --metric pass, not "
            f"{metric!r}; every test-quality input is closed.")
    runs = list(args.run)

    def preflight():
        return ledger.publication_preflight(
            "compare", args.publication_role or (),
            commit=args.publication_commit, run_paths=runs)

    try:
        roles = preflight()
        clusters = ledger.publication_gold_clusters(
            roles[2], args.gold_dir, roles[0].item_ids)
        ledger.publish_consumer_output(
            consumer="compare", roles=roles,
            parameters={"metric": "pass", "gold_dir": args.gold_dir},
            commit=args.publication_commit, out_path=args.out,
            render=lambda: _publication_render(
                lambda: _compare_impl(args, clusters)),
            reclose=preflight)
    except ledger.ResultLedgerRefused as exc:
        raise SystemExit(str(exc)) from exc
    _publication_status_note(args.out)
    return 0


def cmd_compare(args) -> int:
    if getattr(args, "publication_v3", False):
        return _compare_publication_v3(args)
    return _compare_impl(args)


# `_compare_impl` is this command's body, so the contract documented there IS
# `compare`'s contract.  Restated by assignment rather than copied: splitting
# the publication route out of the verb must not quietly empty
# `help(cli.cmd_compare)`, which is part of the pre-I5 Python surface I5
# promises to leave alone.
cmd_compare.__doc__ = _compare_impl.__doc__


def cmd_results(args) -> int:
    """THE canonical results table -- one shape for every approach and agent.

    Deliberately thin.  Every default it resolves (the gold run and the
    production index from `--artifacts`, the test-quality summary from the
    sidecar convention `report` already uses) is resolved in `r2t.bench.results` and
    printed in the table's own provenance block, so a table produced here and
    a table produced from an analysis script are the same table -- and so
    every number in it can be recomputed from files the output names.

    The profile supplies two things rather than one: `api_scoring` says
    whether the api rows are measured at all, and `language` selects the
    production-index filename under the artifacts directory.
    """
    from . import draws as D
    from . import results as R
    if getattr(args, "publication_v3", False):
        return _results_publication_v3(args)
    prof = _stack_profile(args)
    try:
        res = R.results(args.run, gold_path=args.gold_run,
                        test_quality_path=args.test_quality,
                        reference_controls_reader=(
                            _reference_controls_reader(args)),
                        prod_index_path=args.prod_index,
                        boundary=_boundary(args), artifacts=args.artifacts,
                        api_scoring=prof.api_scoring,
                        language=prof.language,
                        release_path=args.release,
                        target_regions_path=args.target_regions,
                        items_path=args.items,
                        control_floors_path=args.control_floors,
                        cluster_source=args.clusters,
                        infrastructure_exclusions_path=(
                            args.infrastructure_exclusions))
        rendered = R.render(res, args.format)
    except D.DrawRefusal as e:
        raise SystemExit(str(e))
    except R.ResultsInputError as e:
        raise SystemExit(f"REFUSED: {e}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        # The rendering goes to the FILE or to stdout, never both: `--format
        # json --out x.json` has to leave stdout parseable, and a reader who
        # wants to see it can drop --out.
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(rendered)
    return 0


def cmd_tasks(args) -> int:
    """Export the admitted release questions without answer-bearing fields.

    `--contract` adds the other half of the exchange.  A task view says what
    to answer; it does not say where the answer is accepted, what a
    submission is recognised as on disk, or that CoreShop's contexts have a
    DI channel -- facts this study's own agent arms are handed in their
    prompt, and that an external submitter can otherwise find only by
    reading `config/profile_<project>.yml`.  One file per export, rendered
    from that same profile, or the one selected by `--profile`: see
    `release.task_contract`. This remains a source-only export.
    """
    from ..data.release import export_tasks
    try:
        count = export_tasks(args.release, args.out,
                             contract_path=args.contract,
                             profile_path=args.profile)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    print(f"wrote {count} tasks to {args.out}")
    if args.contract:
        print(f"wrote the answering contract to {args.contract}")
    return 0


def cmd_tier1b_verdict(args) -> int:
    """Reproduce CoreShop's byte-pinned Tier-1b published table."""
    from . import results as R

    wrapper = (args.coreshop_test_quality_wrapper
               if args.coreshop_test_quality_wrapper is not None
               else os.environ.get(R.LEGACY_PIN_ENV))
    verdict = R.legacy_pin_verdict(wrapper, artifacts=args.artifacts)
    fixture = os.path.relpath(R.LEGACY_FIXTURE, os.path.dirname(R.BENCHMARK))
    if verdict is True:
        print(f"[PASS] Tier-1b (PC8): rendered table byte-matches {fixture}")
        return 0
    print(f"[FAIL] Tier-1b (PC8): byte-match not established against {fixture}")
    print(verdict)
    return 1


def cmd_campaign_results(args) -> int:
    """Render canonical single-run results side by side for one campaign."""
    from . import campaign_table as C
    try:
        rendered = C.render(C.campaign_results(args.descriptor), args.format)
    except C.CampaignTableError as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(rendered)
    return 0


def cmd_doctor(args) -> int:
    """Report whether this host can run one project's benchmark workflow."""
    from ..toolkit import doctor as D
    report = D.doctor(
        project=args.project, agent=args.agent,
        llm_config=args.llm_config)
    print(D.render(report), end="")
    return 0 if report["ok"] else 1


def _generation_readiness_boundary(report: dict, *,
                                   coverage_enabled: bool,
                                   functional_only: bool) -> None:
    """State metric readiness and refuse before the paid generation call."""
    from ..toolkit import doctor as D
    from .campaign_table import NOT_SCORED_COVERAGE
    try:
        checks = [dict(row) for row in D.generation_readiness_checks(report)]
    except D.DoctorRefused as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    if not coverage_enabled:
        coverage = next(
            row for row in checks if row["name"] == D.COVERAGE_READINESS_ROW)
        if coverage["status"] == "pass":
            coverage["status"] = "fail"
            coverage["detail"] = (
                f"{NOT_SCORED_COVERAGE}: generation did not select "
                "--coverage")
    for row in checks:
        print(f"{row['status'].upper():4}  {row['name']}: {row['detail']}",
              file=sys.stderr, flush=True)
    failed = [row for row in checks if row["status"] == "fail"]
    if functional_only:
        print(
            "LIMITATION: --functional-only was selected; this launch does not "
            "require full mutation, coverage, and API-similarity readiness, "
            "and quality rows may remain unscored.",
            file=sys.stderr, flush=True)
        return
    if failed:
        detail = "; ".join(
            f"{row['name']}: {row['detail']}" for row in failed)
        raise SystemExit(
            "REFUSED: full metric readiness is unavailable before paid "
            f"generation: {detail}. Pass --functional-only only to accept a "
            "functional-only campaign.")


def _agent_model_readiness_boundary(args) -> None:
    """Prove an applicable agent history contract at the pre-paid boundary."""
    try:
        from ..agents.backends import AGENT_BACKENDS, OPENHANDS
        from ..agents.adapter import (agent_command_override,
                                      runs_openhands_driver,
                                      validate_agent_model_readiness)
    except ImportError:
        # No agent component, no arm on any driver, no contract to prove:
        # the fixture verbs pass through here on their way to a run.
        return
    from .adapters import resolve_llm_config
    adapter = getattr(args, "adapter", None)
    # Whoever RUNS THROUGH `openhands_driver.py`, not whoever is spelled
    # "openhands": a third agent registered on that driver has the same
    # reasoning-history failure mode and gets the same proof.
    if not runs_openhands_driver(adapter):
        return
    backend = AGENT_BACKENDS[adapter]
    config = resolve_llm_config(
        getattr(args, "llm_config", None), getattr(args, "model", None),
        require_credentials=False)
    command = getattr(args, "agent_command", None)
    if backend is OPENHANDS:
        # `--openhands-command` is ONE system's deprecated alias (it shares
        # `agent_command`'s dest; the second read is for hand-built
        # namespaces).  `agents.registry` refuses to let it point another
        # system's adapter at another binary, so reading it here for a
        # different agent would classify a built-in launch as custom and
        # refuse a proof that was available.
        command = command or getattr(args, "openhands_command", None)
    command_mode = ("custom_ad_hoc"
                    if agent_command_override(backend, command)
                    else "builtin")
    validate_agent_model_readiness(
        adapter, config, command_mode=command_mode)


def cmd_generate(args) -> int:
    """Phase 1 of a sweep: generate for every item, in parallel.

    Split out from `run` because the two phases have opposite constraints —
    generation is network-bound and shares nothing, execution needs the one
    workspace and the one database.  See r2t/bench/generate.py.
    """
    from .generate import generate_all
    from .runner import _load_release, _run_stamp, build_adapter
    from ..data.release import admit_pre_execution
    items = _load_release(args.release)
    boundary = _boundary(args)
    items, _policy = admit_pre_execution(
        items, boundary.project, getattr(args, "item", ()))
    if args.limit:
        items = items[:args.limit]
    h, b, man = _harness(args)
    from ..go.context import preflight
    preflight(h, items)
    adapter = build_adapter(args, h)
    stamp = _run_stamp(args, adapter)
    # Deliberately NO clean_workspace here.  Generation used to sweep the live
    # tree "so an agent cannot see the previous item's closure", but with the
    # frozen seed the agent never reads the live tree at all — and sweeping it
    # from the generation phase once deleted the files an execution running
    # concurrently had just installed.  Seed cleanliness is enforced where the
    # seed is built, which is the only place that can actually guarantee it.
    from ..toolkit import doctor as D
    from ..data.profile import profile_path_for
    readiness_profile = args.profile or profile_path_for(
        args.boundary, boundary.project)
    readiness = D.doctor(
        project=boundary.project, profile_path=readiness_profile)
    _generation_readiness_boundary(
        readiness, coverage_enabled=args.coverage,
        functional_only=args.functional_only)
    _agent_model_readiness_boundary(args)
    info = generate_all(adapter, items, args.out, workers=args.workers,
                        stamp=stamp, retry_failed=args.retry_failed)
    print(json.dumps(info, indent=1))
    return 0


def cmd_run(args) -> int:
    reference_tag = getattr(args, "reference_source_tag", None)
    if reference_tag is not None and (not isinstance(reference_tag, str) or not reference_tag
            or any(character.isspace() for character in reference_tag)):
        raise SystemExit("REFUSED: reference source tag must be one nonempty space-free tag")
    if reference_tag is not None and args.adapter not in {"gold", "stripped-gold", "stub"}:
        raise SystemExit("REFUSED: --reference-source-tag requires a benchmark control adapter")
    if getattr(args, "assertion_selection_policy", None) is not None \
            and args.adapter != "stripped-gold":
        raise SystemExit("REFUSED: --assertion-selection-policy requires --adapter stripped-gold")
    if getattr(args, "assertion_selection_policy", None) is not None and reference_tag is None:
        raise SystemExit("REFUSED: reviewed control selection requires --reference-source-tag")
    sensitivity = getattr(args, "sensitivity", None)
    if sensitivity is not None:
        # A labelled post-hoc sensitivity analysis re-executes saved
        # generations; its rows never share a file with unlabelled rows.
        if args.adapter != "replay":
            raise SystemExit("REFUSED: --sensitivity re-executes saved generations; "
                             "it requires --adapter replay")
        if getattr(args, "publication_v3", False) or getattr(args, "campaign", None):
            raise SystemExit("REFUSED: a sensitivity replay is never a publication or campaign run")
        out = getattr(args, "out", None)
        if out and os.path.isfile(out):
            with open(out, encoding="utf-8") as stream:
                labels = {json.loads(line).get("sensitivity") for line in stream if line.strip()}
            if labels - {sensitivity}:
                raise SystemExit(f"REFUSED: {out} holds rows not labelled {sensitivity!r}; "
                                 "a sensitivity replay writes to its own run file")
    if getattr(args, "publication_v3", False):
        if reference_tag is not None:
            raise SystemExit("REFUSED: --publication-v3 does not record --reference-source-tag; "
                             "use the ordinary control run for evaluation reference collection")
        from .runner import publication_adapter_kind, run_publication_v3
        tail = getattr(args, "_agent_publication_argv", None)
        if tail is not None:
            # Section 3: "Admission occurs only for explicit `run
            # --publication-v3 --adapter {openhands|aider}`."  The typed
            # tokens travel with the namespace because the occurrence
            # grammar is about what was TYPED -- a repeated singleton must
            # refuse rather than be resolved to argparse's last value.
            from ..agents.publication import run_agent_publication_v3
            info = run_agent_publication_v3(
                args, argv_tail=tail, environ=os.environ,
                harness_factory=lambda: _harness(args),
                live_validator=lambda: _require_bound_live_worker(args))
            _print_run_info(args, info)
            return 0
        # This gate is deliberately before worker/profile/harness resolution:
        # reserved adapters cannot trigger Docker, daemon, pool, model or
        # network contact merely by asking for publication.
        publication_adapter_kind(args)
        info = run_publication_v3(
            args, harness_factory=lambda: _harness(args),
            live_validator=lambda: _require_bound_live_worker(args))
        _print_run_info(args, info)
        return 0
    from .runner import prepare_submitted_adapter, submitted_run_flags
    submitted_run_flags(args)
    # PR #195's unconditional bring-up refusal stood here.  Decision 7 of
    # EXTERNAL_CANDIDATE_SUBMISSION_AMENDMENT.md replaced it with the
    # environment-proven stamp: a submitted run proceeds, and every result
    # row records whether an accepted `r2t.project-environment/v1` record
    # covered its bound worker (`runner.submitted_environment_proven`).
    from ..data.release import admit_pre_execution
    from .runner import _load_release, run_adapter
    submitted_adapter = None
    # Normal CLI namespaces always carry a release.  Keep the historical
    # diagnostic embedding used by the ledger selftest usable without making
    # it invent unrelated run inputs.
    if hasattr(args, "release"):
        # The row stamp below is best-effort, so a changed Kapua census would
        # otherwise run unlabelled; refuse it before any worker or model.
        from ..java import kapua_census as KC
        if KC.is_selection(args.release):
            try:
                KC.load_selection(args.release)
            except KC.SelectionRefused as exc:
                raise SystemExit(str(exc)) from exc
        boundary = _boundary(args)
        if reference_tag is not None:
            from . import evaluation_reference as ER, reference_workloads as RW
            role = {adapter: role for role, adapter in RW.ROLE_ADAPTERS.items()}[args.adapter]
            try:
                ER.validate_evaluation_control_policy(
                    project=boundary.project, role=role,
                    control_policy=getattr(args, "assertion_selection_policy", None))
            except ER.ReferenceControlsRefused as exc:
                raise SystemExit(str(exc)) from exc
        admitted_items, _policy = admit_pre_execution(
            _load_release(args.release), boundary.project,
            getattr(args, "item", ()))
        # Candidate shape, admitted-population membership and the fresh
        # resolved output path are source-only facts.  Settle all three before
        # live worker validation; execution reuses these exact parsed bytes.
        submitted_adapter = prepare_submitted_adapter(
            args, admitted_items, project=boundary.project,
            artifacts=getattr(args, "artifacts", "."))
    _agent_model_readiness_boundary(args)
    _require_bound_live_worker(args)
    h, _b, _man = _harness(args)
    if sensitivity is not None and getattr(h, "sensitivity", None) != sensitivity:
        raise SystemExit(f"REFUSED: --sensitivity {sensitivity} is not defined for this "
                         "project's stack")
    if submitted_adapter is None:
        info = run_adapter(h, args, artifacts=args.artifacts)
    else:
        info = run_adapter(
            h, args, artifacts=args.artifacts, adapter=submitted_adapter)
    if getattr(args, "worker_manifest", None):
        info["worker_manifest"] = _write_worker_manifest(args, info)
    _print_run_info(args, info)
    return 0


def _publication_finish_campaign_dir(args) -> "str | None":
    """Return the campaign directory only when the finish hint is usable."""
    campaign_path = getattr(args, "campaign", None)
    manifest_path = getattr(args, "worker_manifest", None)
    if campaign_path is None or manifest_path is None:
        return None
    from .finish import CAMPAIGN_NAME, MANIFEST_NAME
    campaign_path = os.path.abspath(campaign_path)
    if os.path.basename(campaign_path) != CAMPAIGN_NAME:
        return None
    campaign_dir = os.path.dirname(campaign_path)
    manifest_path = os.path.abspath(manifest_path)
    if os.path.dirname(manifest_path) != campaign_dir \
            or not MANIFEST_NAME.fullmatch(os.path.basename(manifest_path)):
        return None
    return campaign_dir


def _print_run_info(args, info: dict) -> None:
    """Print one JSON result, adding the next command for sealed shards."""
    finish_campaign_dir = (
        _publication_finish_campaign_dir(args)
        if getattr(args, "publication_v3", False) else None)
    finishable = (info.get("already_complete") is True
                  or info.get("complete") is True)
    if finish_campaign_dir and finishable:
        command = shlex.join([
            sys.executable, "-m", "r2t.cli", "finish",
            "--campaign", finish_campaign_dir])
        info["finish"] = f"PYTHONPATH={shlex.quote(BENCHMARK)} {command}"
    print(json.dumps(info, indent=1))


def _write_worker_manifest(args, info: dict) -> str:
    """Level 2 of the three-level metadata (§3.6), written by the shard itself.

    Written HERE rather than assembled afterwards by whoever runs the merge:
    the worker is the only party that knows what it actually used, and a
    manifest reconstructed from a shell history is a manifest that can be
    wrong without anybody noticing.
    """
    from .campaign import WorkerManifest, campaign_digest, write_worker_manifest
    if not getattr(args, "campaign", None):
        raise SystemExit(
            "REFUSED: --worker-manifest without --campaign. A worker manifest "
            "that names no campaign cannot be merged, because the merge's "
            "first check is that every shard shares one fingerprint (§3.7).")
    campaign = getattr(args, "_validated_campaign_document", None)
    if campaign is None:
        with open(args.campaign, encoding="utf-8") as fh:
            campaign = json.load(fh)
    elif getattr(args, "_validated_campaign_path", None) \
            != os.path.abspath(args.campaign):
        raise SystemExit(
            "REFUSED: validated campaign snapshot belongs to another path")
    spec = _worker_spec(args)
    if spec is None:
        raise SystemExit(
            "REFUSED: --worker-manifest without --worker. The schema and the "
            "credential identity are not command-line flags, and inventing "
            "them here would make the merge's disjointness check meaningless.")
    man = WorkerManifest(
        shard=spec.index,
        workspace=os.path.abspath(spec.workspace),
        container=spec.container,
        schema=spec.schema,
        credential=spec.credential,
        out_path=os.path.abspath(info["out"]),
        artifacts_root=os.path.abspath(
            info.get("artifacts") or spec.artifacts_root
            or os.path.join(args.artifacts, f"shard{spec.index}")),
        started_at=info.get("started_at"),
        finished_at=info.get("finished_at"),
        campaign_digest=(getattr(args, "_validated_campaign_digest", None)
                         or campaign_digest(campaign)))
    return write_worker_manifest(man, campaign, args.worker_manifest)


def _worker_spec(args):
    """The `(workspace, schema, container, credential)` this process is."""
    path = getattr(args, "worker", None)
    if not path:
        return None
    from .worker import WorkerRefused, load_worker_spec
    try:
        return load_worker_spec(path)
    except WorkerRefused as e:
        raise SystemExit(str(e)) from e


def _require_bound_live_worker(args) -> dict:
    """Authorize the persistent worker before live validation/evaluation."""
    from . import worker as W
    from .validate import HARNESS_VERSION
    run_publication = getattr(args, "_publication_run_plan", None)
    validation_publication = getattr(
        args, "_publication_validation_plan", None)
    if run_publication is not None and validation_publication is not None:
        raise SystemExit(
            "REFUSED: live worker request carries two publication plans; "
            "no Docker command was run.")
    publication = run_publication or validation_publication
    spec = (publication.runtime.worker if publication is not None
            else _worker_spec(args))
    if spec is None:
        raise SystemExit(
            "REFUSED: new live validation/evaluation requires --worker with "
            "exact r2t.worker-runtime/v3 evidence; no Docker command was run.")
    if getattr(args, "cmd", None) == "run" \
            and getattr(args, "shard", None) != spec.index:
        raise SystemExit(
            f"REFUSED: --shard {getattr(args, 'shard', None)} contradicts "
            f"authenticated worker index {spec.index}; no Docker command "
            "was run.")
    if getattr(args, "cmd", None) == "run" \
            and getattr(args, "worker_manifest", None) \
            and not getattr(args, "campaign", None):
        raise SystemExit(
            "REFUSED: --worker-manifest requires --campaign; no Docker "
            "command was run.")

    needs_database = (publication.context.profile.needs_database
                      if publication is not None else
                      _stack_profile(args).needs_database)
    _refuse_unbound_database_runtime(
        needs_database, "database-backed persistent validation/evaluation")

    expected_pool_size = (getattr(args, "of", None)
                          if getattr(args, "cmd", None) == "run" else
                          (len(publication.runtime.pool["workers"])
                           if validation_publication is not None else None))
    expected_runtime = None
    campaign_path = (getattr(args, "campaign", None)
                     if getattr(args, "cmd", None) == "run" else None)
    if campaign_path:
        from . import result_ledger as _ledger
        from .campaign import (
            GENERATION_CAMPAIGN_SCHEMA, agent_runtime_digest,
            campaign_digest, harness_commit_identity, harness_source_digest,
            probe_agent_runtime)
        if publication is not None:
            if os.path.abspath(campaign_path) \
                    != publication.context.campaign_path:
                raise SystemExit(
                    "REFUSED: publication campaign path changed after "
                    "planning; no Docker command was run.")
            campaign = publication.context.campaign
        else:
            try:
                with open(campaign_path, encoding="utf-8") as fh:
                    campaign = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                raise SystemExit(
                    f"REFUSED: cannot read campaign {campaign_path}: "
                    f"{exc}") from exc
        if not isinstance(campaign, dict):
            raise SystemExit("REFUSED: campaign fingerprint is not an object")
        validated_campaign_digest = campaign_digest(
            campaign)  # complete shape/semantic validation
        if campaign.get("schema") != GENERATION_CAMPAIGN_SCHEMA:
            raise SystemExit(
                "REFUSED: new live v3 execution requires exact "
                "r2t.generation-campaign/v2 identity; historical campaign "
                "bytes remain offline-only.")
        if publication is not None:
            current_config_digest = _ledger.raw_sha256(
                publication.raw_by_path[
                    publication.plan["boundary"]["path"]])[:16]
        else:
            with open(args.boundary, "rb") as boundary_fh:
                import hashlib
                current_config_digest = hashlib.sha256(
                    boundary_fh.read()).hexdigest()[:16]
        static_changed = []
        if campaign["config_digest"] != current_config_digest:
            static_changed.append("config_digest")
        # Section 16: the evaluator identity enforced here is the version;
        # the commit/source pair the campaign was minted at is disclosed.
        if campaign["harness_version"] != HARNESS_VERSION:
            static_changed.append("harness_version")
        _ledger.disclose_harness_drift(
            recorded={"git_commit": campaign["harness_commit"],
                      "source_sha256": campaign["harness_source_sha256"]},
            live={"git_commit": harness_commit_identity(),
                  "source_sha256": harness_source_digest()})
        runtime_path = campaign_path + ".agent_runtime.json"
        if publication is not None:
            saved_agent_runtime = publication.context.agent_runtime
            saved_runtime_digest = agent_runtime_digest(saved_agent_runtime)
        else:
            try:
                with open(runtime_path, encoding="utf-8") as runtime_fh:
                    saved_agent_runtime = json.load(runtime_fh)
                saved_runtime_digest = agent_runtime_digest(saved_agent_runtime)
            except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
                raise SystemExit(
                    f"REFUSED: cannot authenticate campaign agent runtime "
                    f"{runtime_path}: {exc}") from exc
        # Section 4.1 of the result-v3 agent producer amendment: a companion
        # that "is built from this selected backend, never by probing the
        # coordinator interpreter" cannot be re-probed here, because a probe
        # of THIS process would report a difference that says nothing about
        # the campaign.  The equality that replaces it is the backend join in
        # `result_ledger_v2.verify_agent_adapter`, which a publication plan
        # has already performed against the manifest the plan binds.
        #
        # THE DISCRIMINATOR IS THE COMPANION'S OWN BYTES, NOT THE CAMPAIGN'S
        # `agent_system`.  Section 4.1 puts `agent_backend_runtime_digest` in
        # a backend-built `agent_versions` and `probe_agent_runtime` cannot
        # emit it, so the member's presence says which document this is.
        # Keying on the system name instead would delete this live check for
        # every openhands and aider campaign ALREADY ON DISK -- probe-built,
        # every one of them, since no backend-built campaign could exist
        # before this amendment -- and section 10 leaves those unchanged
        # outside explicit agent publication mode.  For them the comparison
        # below is the only thing that refuses a coordinator whose agent
        # stack or proxy environment drifted, and it refuses before Docker
        # contact.
        saved_versions = (saved_agent_runtime.get("agent_versions")
                          if isinstance(saved_agent_runtime, dict) else None)
        if isinstance(saved_versions, dict) \
                and "agent_backend_runtime_digest" in saved_versions:
            current_runtime_digest = saved_runtime_digest
        else:
            # The re-probe mirrors campaign creation exactly: the selected
            # agent backend's interpreter under its exact requirements lock
            # when the campaign names one, the coordinator otherwise.  Any
            # other interpreter would report a difference that says nothing
            # about the campaign.
            probe_interpreter = sys.executable
            probe_lock = None
            if campaign.get("agent_system"):
                try:
                    from ..agents import get_spec
                    from ..agents.backends import AGENT_BACKENDS
                except ImportError:
                    raise SystemExit(
                        f"REFUSED: campaign names agent arm "
                        f"{campaign['agent_system']!r}, which this checkout "
                        f"does not ship (no agent component); no Docker "
                        f"command was run.")
                probe_spec = get_spec(campaign["agent_system"])
                if probe_spec.kind == "agent":
                    probe_backend = AGENT_BACKENDS[probe_spec.name]
                    probe_interpreter = probe_backend.python()
                    probe_lock = probe_backend.requirements_lock
            current_runtime_digest = agent_runtime_digest(probe_agent_runtime(
                interpreter=probe_interpreter,
                network_semantics=campaign["network_semantics"],
                agent_system=campaign.get("agent_system"),
                requirements_lock=probe_lock))
        if saved_runtime_digest != campaign["agent_runtime_sha256"]:
            static_changed.append("saved_agent_runtime_sha256")
        if current_runtime_digest != campaign["agent_runtime_sha256"]:
            static_changed.append("current_agent_runtime_sha256")
        if static_changed:
            raise SystemExit(
                "REFUSED: campaign static execution identity differs before "
                f"Docker contact; changed={static_changed}.")
        # Reuse the runner's complete flag/system/protocol comparison here,
        # before authority or worker inspection.  Running it only while the
        # row stamp is built is too late: the v3 gate has already contacted
        # Docker by then.
        from .runner import _check_campaign_flags
        # No adapter exists yet at this pre-Docker boundary; the
        # command-mode half of the comparison re-runs at `_run_stamp` with
        # the real adapter in hand.
        _check_campaign_flags(args, campaign, campaign_path, None)
        if getattr(args, "of", None) is None:
            raise SystemExit(
                "REFUSED: --campaign requires explicit --of equal to its "
                "authenticated worker pool; no Docker command was run.")
        if args.of != campaign["k_workers"]:
            raise SystemExit(
                f"REFUSED: campaign k_workers={campaign['k_workers']}, but "
                f"this run has --of {args.of}; no Docker command was run.")
        expected_pool_size = campaign["k_workers"]
        expected_runtime = {
            key: campaign.get(key)
            for key in ("harness_version", "container_image_digest",
                        "workspace_seed_digest", "database_dump_digest")
        }
        # Pin the exact validated snapshot.  Rows and the worker manifest must
        # not reopen a replaceable path after the pre-Docker runtime join and
        # then stamp a different campaign identity.
        args._validated_campaign_document = campaign
        args._validated_campaign_digest = validated_campaign_digest
        args._validated_campaign_path = os.path.abspath(campaign_path)

    protected = W.default_answer_paths(
        args.gold, args.artifacts, os.path.join(args.artifacts, "release"))
    protected.extend(filter(None, (
        args.gold,
        args.artifacts,
        getattr(args, "boundary", None),
        getattr(args, "profile", None),
    )))
    if getattr(args, "cmd", None) == "validate":
        protected.append(os.path.join(args.artifacts, args.out))
    else:
        protected.extend(filter(None, (
            getattr(args, "release", None),
            getattr(args, "out", None),
            getattr(args, "keep_artifacts", None),
            getattr(args, "campaign", None),
            (getattr(args, "campaign", None) + ".agent_runtime.json"
             if getattr(args, "campaign", None) else None),
            getattr(args, "worker_manifest", None),
            getattr(args, "replay", None),
            getattr(args, "candidates", None),
            getattr(args, "trajectory_dir", None),
            getattr(args, "llm_config", None),
        )))
    protected.extend(getattr(args, "_publication_protected_paths", ()))
    try:
        runtime = W.validate_live_worker_runtime(
            args.worker, spec, HARNESS_VERSION,
            needs_database, protected,
            expected_pool_size=expected_pool_size,
            expected_runtime=expected_runtime,
            behat=_behat_row(args), project=_stack_profile(args).project)
    except W.WorkerRefused as exc:
        raise SystemExit(str(exc)) from exc
    return runtime


def _worker_pool(args):
    """The complete saved pool and the subset selected for this action."""
    from . import worker as W
    try:
        workers = W.load_worker_pool(args.workers_root, args.k)
        needs_database = W.worker_pool_needs_database(workers)
    except W.WorkerRefused as e:
        raise SystemExit(str(e)) from e
    requested = set(args.only or ())
    unknown = sorted(requested - {w.index for w in workers})
    if unknown:
        raise SystemExit(
            f"REFUSED: --only names workers outside the saved 0.."
            f"{len(workers) - 1} pool: {unknown}")
    if getattr(args, "_workdir_explicit", False):
        disagree = [w.index for w in workers if w.workdir != args.workdir]
        if disagree:
            raise SystemExit(
                f"REFUSED: explicit --workdir {args.workdir!r} contradicts "
                f"saved worker spec(s) {disagree}; lifecycle actions use "
                "the manifests written by `worker plan`.")
    chosen = [w for w in workers if not requested or w.index in requested]
    return workers, chosen, needs_database


# ----------------------------------------------------------- release bundles
def _validation_input_paths(args):
    path = getattr(args, "validation_inputs", None)
    if path is None:
        return None
    from ..core.paths import data_root
    from ..data.evaluation_bundle import resolve_validation_inputs
    from ..data.bundle import BundleRefused
    root = getattr(args, "input_root", None) or data_root()
    try:
        return resolve_validation_inputs(path, root)
    except BundleRefused as exc:
        raise SystemExit(str(exc)) from exc


def _budgeted_sidecar_path(args):
    """The derived-map basis flag, admitted only where it is development.

    `HEADROOM_SUBSET_AND_BUDGETED_SAMPLE_SPEC.md` section 2: "in this program
    every budgeted row is a development row".  Neither mutation verb has a
    publication flag, so the one route on them that is welded to a reviewed,
    registered population is `--reference-scope`, whose collection scope pins
    the parent map's exact bytes.  Handed a derived map it would refuse on
    that pin, which reads as a corrupted scope rather than as what it is.
    """
    path = getattr(args, "budgeted_sidecar", None)
    if path is not None and getattr(args, "reference_scope", None) is not None:
        raise SystemExit(
            "REFUSED: --budgeted-sidecar is refused with --reference-scope. "
            "A budgeted population is a development basis -- "
            "HEADROOM_SUBSET_AND_BUDGETED_SAMPLE_SPEC.md section 2: \"in "
            "this program every budgeted row is a development row\" -- and a "
            "reviewed collection scope pins the parent map's own bytes as "
            "the population it approved.")
    return path


def _add_evaluation_reference_sources(parser, *, consumer=False,
                                      go_control_plans=True):
    parser.add_argument("--reference-scope", metavar="JSON",
                        help="approved precollection evaluation scope; no scoring-time narrowing")
    parser.add_argument("--validation-inputs", metavar="JSON",
                        help="complete native inputs.json location map")
    parser.add_argument("--input-root", metavar="DIR",
                        help="data root resolving native input locations (defaults to R2T_DATA_ROOT)")
    parser.add_argument("--reference-gold", metavar="DIR")
    parser.add_argument("--reference-release-gold", metavar="DIR")
    parser.add_argument("--reference-closures", metavar="JSON")
    parser.add_argument("--reference-feature-root", metavar="DIR")
    if go_control_plans:
        parser.add_argument("--reference-go-control-plans", metavar="DIR",
                            help="Coddy saved native control-plan tree for offline replay")
    parser.add_argument("--reference-task-binding", metavar="JSON")
    parser.add_argument("--reference-inputs", metavar="DIR")
    parser.add_argument("--reference-recipes", metavar="DIR")
    if consumer:
        parser.add_argument("--reference-execution-release", metavar="JSONL",
                            help="execution tasks; --reference-release remains the map release")
    else:
        parser.add_argument("--map-release", metavar="JSONL",
                            help="unchanged map authority, separate from --release execution tasks")


_DEVELOPMENT_REFERENCE_SOURCES = {
    "recipe_path": "reference_recipe", "gold_root": "reference_gold",
    "release_gold_root": "reference_release_gold", "closures_path": "reference_closures",
}


def _refuse_unscoped_evaluation_sources(args, *, development_reference=False):
    if getattr(args, "reference_scope", None) is not None:
        return
    permitted = (set(_DEVELOPMENT_REFERENCE_SOURCES.values()) | {"reference_feature_root"}
                 if development_reference and getattr(args, "reference_role", None)
                 and getattr(args, "budgeted_sidecar", None) else set())
    supplied = ["--" + name.replace("_", "-") for name in (
        "map_release", "reference_gold", "reference_release_gold",
        "reference_closures", "reference_feature_root", "reference_task_binding",
        "reference_go_control_plans",
        "reference_recipe", "reference_inputs", "reference_recipes", "reference_execution_release")
        if getattr(args, name, None) is not None and name not in permitted]
    if supplied:
        raise SystemExit("REFUSED: " + ", ".join(supplied) + " require --reference-scope")


def _development_reference_control(args, *, assets):
    """Source-authenticate a supported development baseline before runtime probes."""
    from .reference_workloads import validate_development_control_input
    if getattr(args, "budgeted_sidecar", None) is None:
        raise SystemExit("REFUSED: prospective development reference inputs require --budgeted-sidecar")
    if assets["asset_project"] == "kapua":
        from ..java import kapua_pilot as K
        try:
            if any(getattr(args, name, None) is not None for name in
                   (*_DEVELOPMENT_REFERENCE_SOURCES.values(), "reference_feature_root")):
                raise ValueError("Kapua pilot control sources come from its selection; explicit overrides are refused")
            if not K.is_pilot(args.release):
                raise ValueError("Kapua source replay requires the authenticated fixed pilot")
            return K.validate_control(args.candidate, args.release, assets["asset_index_sha256"],
                                      _canonical_reference_role(args.reference_role))
        except (ValueError, OSError) as exc:
            raise SystemExit("REFUSED: development reference source replay: " + str(exc)) from exc
    missing = ["--" + name.replace("_", "-")
               for name in _DEVELOPMENT_REFERENCE_SOURCES.values()
               if getattr(args, name, None) is None]
    if missing:
        raise SystemExit("REFUSED: development reference source replay requires " + ", ".join(missing))
    try:
        control = validate_development_control_input(
            project=assets["asset_project"],
            role=_canonical_reference_role(args.reference_role), run_path=args.candidate,
            execution_release_path=args.release,
            feature_root=getattr(args, "reference_feature_root", None),
            **{key: getattr(args, name) for key, name in _DEVELOPMENT_REFERENCE_SOURCES.items()})
        if control["recipe"]["asset_index_sha256"] != assets["asset_index_sha256"]:
            raise ValueError("reference recipe differs from the authenticated mutation assets")
    except (ValueError, OSError) as exc:
        raise SystemExit("REFUSED: development reference source replay: " + str(exc)) from exc
    return control


def _evaluation_protected_paths(args):
    return [os.path.abspath(value) for name in (
        "reference_scope", "map_release", "validation_inputs", "gold_baseline",
        "reference_gold", "reference_release_gold", "reference_closures",
        "reference_feature_root", "reference_task_binding", "reference_recipe",
        "reference_inputs", "reference_recipes", "reference_engine_source")
        if (value := getattr(args, name, None)) is not None]


def _evaluation_asset_arguments(args):
    fields = {"scope_path": "reference_scope", "validation_path": "mutation_validation",
              "manifest_path": "manifest", "map_path": "map",
              "execution_release_path": "release", "map_release_path": "map_release",
              "gold_baseline_path": "gold_baseline"}
    missing = ["--" + attr.replace("_", "-") for attr in fields.values()
               if getattr(args, attr, None) is None]
    if missing:
        raise SystemExit("REFUSED: evaluation scope requires " + ", ".join(missing))
    return {**{key: getattr(args, attr) for key, attr in fields.items()},
            "validation_input_paths": _validation_input_paths(args),
            "task_binding_path": getattr(args, "reference_task_binding", None)}


def _canonical_reference_role(value):
    from .reference_controls import IDENTITY_REFERENCE_ROLE
    roles = {identity: role for role, identity in IDENTITY_REFERENCE_ROLE.items()}
    if value not in roles:
        raise SystemExit("REFUSED: reference command requires --reference-role")
    return roles[value]


def _evaluation_reference_arguments(args, *, planning=False):
    """One explicit source contract for plan, collection, seal and reopening."""
    fields = {
        "scope_path": "reference_scope", "validation_path": "mutation_validation",
        "manifest_path": "manifest", "map_path": "map",
        "execution_release_path": "release", "map_release_path": "map_release",
        "gold_baseline_path": "gold_baseline", "gold_root": "reference_gold",
        "release_gold_root": "reference_release_gold",
        "closures_path": "reference_closures",
    }
    if planning:
        fields.update(candidate_path="candidate", recipe_path="reference_recipe",
                      source_tag="reference_source_tag")
    else:
        fields.update(reference_inputs_root="reference_inputs",
                      reference_recipes_root="reference_recipes",
                      reference_controls_root="reference_controls")
    missing = ["--" + attr.replace("_", "-") for attr in fields.values()
               if getattr(args, attr, None) is None]
    if missing:
        raise SystemExit("REFUSED: evaluation reference requires " + ", ".join(missing))
    values = {key: getattr(args, attr) for key, attr in fields.items()}
    values.update(validation_input_paths=_validation_input_paths(args),
                  task_binding_path=getattr(args, "reference_task_binding", None),
                  feature_root=getattr(args, "reference_feature_root", None),
                  go_control_plans_root=getattr(args, "reference_go_control_plans", None))
    if planning:
        values["role"] = _canonical_reference_role(getattr(args, "reference_role", None))
    else:
        values["engine_source_path"] = getattr(args, "reference_engine_source", None)
    return values


def _reference_report(result, *, action):
    collection = result["collection_scope"]
    report = {"action": action, "scope": collection["scope"],
              "declared_subset": collection["declared_subset"],
              "mutation_validation_sha256": collection["mutation_validation_sha256"]}
    if action == "plan":
        report.update(items=len(result["admitted_items"]),
                      pairs=len(result["expected_pairs"]),
                      map_release_items=result["assets"]["release_items"],
                      map_pairs=result["assets"]["map"]["n_pairs"],
                      catalog_mutants=result["assets"]["manifest"]["n"],
                      mapped_mutants=len(result["mutants"]),
                      generation=result["generation"])
    else:
        controls = result["controls"]
        report.update(reference_digest=controls["digest"],
                      pairs=controls["pairs"],
                      reference_observation_count=controls["reference_observation_count"])
    return report


def cmd_reference(args) -> int:
    from . import evaluation_reference as ER
    from .reference_controls import ReferenceControlsRefused
    from .reference_workloads import ReferenceWorkloadRefused
    from ..data.bundle import BundleRefused
    try:
        if args.action == "scope":
            options = _evaluation_asset_arguments(args)
            options["template_path"] = options.pop("scope_path")
            report = ER.instantiate_evaluation_scope(**options, out=args.out)
            print(json.dumps(report, indent=1, sort_keys=True))
            return 0
        if args.action == "recipe":
            from . import reference_workloads as RW
            from .fixtures import FIXTURES
            admitted = ER.admit_evaluation_scope(**_evaluation_asset_arguments(args))
            role = _canonical_reference_role(args.reference_role)
            ER.validate_evaluation_control_policy(
                project=admitted["project"], role=role,
                control_policy=args.assertion_selection_policy)
            adapter_version = FIXTURES[RW.ROLE_ADAPTERS[role]].version
            if admitted["project"] == "sylius" and role == "stub":
                from ..toolkit.stub import SYLIUS_ADAPTER_VERSION
                adapter_version = SYLIUS_ADAPTER_VERSION
            if admitted["project"] == "sylius" and role == "stripped_gold":
                adapter_version = 2
            report = RW.reference_recipe(
                role=role, adapter_version=adapter_version,
                release_sha256=admitted["collection_scope"]["scope"]["task_items_sha256"],
                asset_index_sha256=admitted["assets"]["asset_index_sha256"],
                control_policy=args.assertion_selection_policy)
            with open(args.out, "x", encoding="utf-8") as handle:
                json.dump(report, handle, sort_keys=True, indent=1)
                handle.write("\n")
            print(json.dumps(report, indent=1, sort_keys=True))
            return 0
        if args.action == "plan":
            result = ER.plan_reference_leg(**_evaluation_reference_arguments(args, planning=True))
        elif args.action == "seal":
            result = ER.seal_evaluation_reference(
                **_evaluation_reference_arguments(args), out=args.out,
                allow_excluded_pairs=args.allow_excluded_pairs,
                reference_basis=args.reference_basis)
        else:
            result = ER.load_evaluation_reference(
                **_evaluation_reference_arguments(args),
                attestation_path=args.reference_attestation)
        report = _reference_report(result, action=args.action)
        if args.action == "plan" and args.out is not None:
            with open(args.out, "x", encoding="utf-8") as handle:
                json.dump(report, handle, sort_keys=True, indent=1)
                handle.write("\n")
    except (ReferenceControlsRefused, ReferenceWorkloadRefused, BundleRefused,
            OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(report, indent=1, sort_keys=True))
    return 0


def cmd_bundle(args) -> int:
    from ..data import bundle as B
    from ..toolkit import algorand_bundle as A
    from ..toolkit import algorand_image as I

    try:
        if args.action == "measure-index":
            from ..data.evaluation_bundle import measure_evaluation_release
            report = measure_evaluation_release(
                archive=args.archive, manifest=args.manifest, out=args.out)
            print(json.dumps(report, indent=1, sort_keys=True))
            return 0
        # A private measured index applies only to the approved evaluation
        # layout. Old versions retain their existing release authority.
        release_index = getattr(args, "release_index", None)
        if release_index is not None:
            from ..data import evaluation_bundle as E
            if not E.is_evaluation_bundle(args.project, args.version):
                raise B.BundleRefused("REFUSED: --release-index requires an evaluation bundle")
            if args.action == "install":
                report = E.install_evaluation_bundle(
                    project=args.project, version=args.version, archive=args.archive,
                    release_index_path=release_index)
            elif args.action == "validate":
                from ..core.paths import data_root
                report = E.validate_evaluation_bundle(
                    project=args.project, version=args.version, root=data_root(),
                    release_index_path=release_index)
            elif args.action == "acquire-image" and args.project == "algorand-sdk":
                report = I.acquire_image(
                    project=args.project, docker_authority=args.docker_authority,
                    out=args.out, version=args.version, release_index_path=release_index)
            else:
                raise B.BundleRefused("REFUSED: private indexes are install/validate/native-image inputs")
            print(json.dumps(report, indent=1, sort_keys=True))
            return 0
        if args.action == "fetch":
            report = B.fetch_bundle(project=args.project,
                                    version=args.version)
        elif args.action == "install":
            report = B.install_bundle(
                project=args.project, version=args.version,
                archive=args.archive)
        elif args.action == "validate":
            report = B.validate_installed_bundle(
                project=args.project, version=args.version)
        elif args.action == "build-algorand":
            report = A.build_bundle(
                inputs_path=args.inputs, out=args.out, version=args.version)
        elif args.action == "acquire-image":
            # Identity comes only from the installed validated bundle under
            # R2T_DATA_ROOT; the command admits no digest, repository,
            # platform, or tag flag that could stand in for it.
            report = I.acquire_image(project=args.project,
                                     docker_authority=args.docker_authority,
                                     out=args.out, version=args.version)
        elif args.action == "verify-algorand-publication":
            report = I.verify_publication(
                version=args.version,
                source_manifest=args.source_manifest,
                docker_authority=args.docker_authority,
                out=args.out)
        else:
            from ..toolkit.bundle_build import build_bundle
            report = build_bundle(
                project=args.project, version=args.version,
                seed_dir=args.seed, gold_dir=args.gold,
                release_gold=args.release_gold,
                raw_manifest=args.raw_manifest,
                legacy_map=args.legacy_map,
                coverage_run=args.coverage_run,
                candidate_run=args.candidate_run,
                candidate_results=args.candidate_results,
                gold_results=args.gold_results, out=args.out,
                production_index=args.production_index,
                audit_attestation=args.audit_attestation,
                alias_table=args.alias_table,
                autowirable_types=args.autowirable_types,
                std_arm=args.std_arm,
                legacy_report=args.legacy_report,
                scoring_gold=args.scoring_gold,
                historical_release=args.historical_release,
                annotated_release=args.annotated_release,
                inputs_path=args.inputs)
    except (B.BundleRefused, A.AlgorandBundleRefused,
            I.ImageAcquisitionRefused) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(report, indent=1, sort_keys=True))
    return 0


# ------------------------------------------------------------------ K-way
def cmd_seed(args) -> int:
    """Build, verify or inspect the frozen (workspace, database) pair (§3.3)."""
    # The pruning policy and the database question both come off the profile,
    # so `seed build` for a second stack is a `--profile` away rather than a
    # branch here. An unknown framework is refused rather than seeded under
    # CoreShop's rules (`seed.rules_for`).
    prof = _stack_profile(args)
    from .dbadmin import MySQL
    from .repo import load_manifest
    from . import seed as S
    b = _boundary(args)
    rules = S.rules_for(prof.framework, prof.project)
    if args.action == "key":
        schema = args.schema if prof.needs_database else S.NO_DATABASE
        print(json.dumps(S.seed_key(b.repo_root, schema, rules=rules),
                         indent=1))
        return 0
    if args.action == "verify":
        rep = S.verify_seed(args.seed, b.repo_root)
        print(json.dumps(rep, indent=1))
        # Exit status is the only part of this a script reads. Returning 0 on
        # a corrupt seed made `seed verify && provision` a no-op guard.
        return 0 if rep["artifacts_ok"] else 1
    manifest_path = os.path.join(args.gold, "strip_manifest.json")
    man = None
    if os.path.isfile(manifest_path):
        man = load_manifest(manifest_path)
        man.repo_root = b.repo_root
        man.gold_root = os.path.abspath(args.gold)
    if not prof.needs_database:
        doc = S.build_seed(b.repo_root, b, args.seed, None, None,
                           manifest=man, force=args.force, rules=rules,
                           needs_database=False)
    else:
        with MySQL(container=args.db_container) as db:
            doc = S.build_seed(b.repo_root, b, args.seed, args.schema, db,
                               manifest=man, force=args.force, rules=rules)
    print(json.dumps({k: v for k, v in doc.items() if k != "cleanliness"},
                     indent=1))
    return 0


def _worker_process_args(profile):
    """Reap Ruby children and preserve stack-specific startup arguments."""
    from .prestashop_memory import go_memory_run_args
    if profile.framework == "cucumber_ruby":
        return ("--init",)
    if profile.project == "kapua":
        return ("--hostname", "kapua-worker", "--add-host", "kapua-worker:127.0.0.1")
    return go_memory_run_args(profile.project)


def _provision_workers(workers, provision_one, *, jobs):
    """Yield completed workers; drain started jobs on failure without refill."""
    if jobs < 1:
        raise SystemExit("REFUSED: worker provision --jobs must be at least 1")
    if jobs == 1:
        for worker in workers:
            yield worker, provision_one(worker)
        return
    from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

    remaining = iter(workers)
    failures = []
    with ThreadPoolExecutor(max_workers=min(jobs, len(workers))) as executor:
        pending = {}

        def submit_one():
            worker = next(remaining, None)
            if worker is not None:
                pending[executor.submit(provision_one, worker)] = worker

        for _ in range(min(jobs, len(workers))):
            submit_one()
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            completed = []
            for future in sorted(done, key=lambda job: pending[job].index):
                worker = pending.pop(future)
                try:
                    completed.append((worker, future.result()))
                except (Exception, SystemExit) as exc:
                    failures.append(exc)
            yield from completed
            if not failures:
                for _ in done:
                    submit_one()
    if failures:
        raise failures[0]


def cmd_worker(args) -> int:
    """Provision, check, probe and tear down the worker triples (§3.1, §3.2)."""
    from .dbadmin import MySQL
    from . import worker as W

    if args.action == "plan":
        from ..data.profile import config_stem
        prof = _stack_profile(args)
        prefix = args.prefix
        if prefix is None:
            # Native PrestaShop bootstrap adds test_ to its database name;
            # provisioning therefore requires the planned schema to carry it.
            prefix = ("test_prestashop" if prof.project == "prestashop"
                      else config_stem(prof.project))
        ws = W.plan_workers(args.workers_root, args.k,
                            runs_dir=args.runs_dir or None,
                            artifacts_dir=args.worker_artifacts or None,
                            name=args.name,
                            workdir=args.workdir,
                            prefix=prefix,
                            kind=args.container_kind,
                            needs_database=prof.needs_database)
        W.write_worker_pool(args.workers_root, ws)
        print(json.dumps({"workers": [w.to_json() for w in ws]}, indent=1))
        return 0

    ws, chosen, needs_db = _worker_pool(args)

    def behat_row():
        """The project's Behat row, for the LIVE halves that read it.

        A worker's baked database environment is per-project: which variable
        carries the DSN, whether the DSN takes a query suffix, and whether the
        four `PIMCORE_INSTALL_*` variables belong in the file at all.  Without
        this the row is defined and never reaches `worker.provision`, so a
        second Behat project would still be given CoreShop's variable and its
        application would read the committed `.env` instead.
        """
        return _behat_row(args)

    # A worker triple is a triple only where there IS a database (D6). The
    # saved manifests decide, once, and every action below reads the same
    # answer -- deriving it three times from three flags is how `provision`
    # skips the schema and `harden` then tries to narrow a grant on it.
    if (args.action == "provision"
            or (args.action == "preflight" and args.live)
            or args.action in ("probe", "reset-probe", "harden", "unharden")):
        _refuse_unbound_database_runtime(
            needs_db, f"database-backed worker {args.action}")
    image = getattr(args, "image", None) or W.DEFAULT_IMAGE
    answers = W.default_answer_paths(
        args.gold, args.artifacts, os.path.join(args.artifacts, "release"))
    # Validate the whole saved pool before selecting workers and before any
    # Docker, database, removal or workspace callback.  `--only` limits the
    # action; it cannot make a contradictory pool authoritative.
    W.preflight(ws, answers, live=False, needs_database=needs_db)

    def require_bound_admin_pool() -> dict:
        """Authenticate the already-provisioned v3 pool for live admin work."""
        selected = _worker_spec(args)
        if selected is None:
            raise SystemExit(
                "REFUSED: live worker administration requires global "
                "--worker with exact r2t.worker-runtime/v3 evidence; no "
                "Docker command was run.")
        if not chosen:
            raise SystemExit(
                "REFUSED: --only selects no member of the authenticated "
                "worker pool; no Docker command was run.")
        if selected.index >= len(ws) or selected != ws[selected.index]:
            raise SystemExit(
                "REFUSED: global --worker differs from the pool derived by "
                "the worker administration flags; no Docker command was run.")
        expected_path = os.path.abspath(os.path.join(
            args.workers_root, f"worker{selected.index}.json"))
        if os.path.abspath(args.worker) != expected_path:
            raise SystemExit(
                "REFUSED: global --worker is outside the exact "
                "--workers-root pool layout; no Docker command was run.")
        from .validate import HARNESS_VERSION
        try:
            static = W.validate_worker_runtime_v3(
                args.worker, expected_worker=selected,
                harness_version=HARNESS_VERSION,
                needs_database=needs_db)
            static_pool = static["binding"]["pool"]
            static_paths = tuple(
                entry["worker_spec_path"]
                for entry in static_pool["workers"])
            expected_paths = tuple(os.path.abspath(os.path.join(
                args.workers_root, f"worker{i}.json"))
                for i in range(args.k))
            if static_paths != expected_paths:
                raise W.WorkerRefused(
                    "REFUSED: administration flags differ from the static "
                    "authenticated v3 pool; no Docker command was run.")
            static_loaded = W.validate_offline_worker_runtime_pool(
                list(static_paths))
            if [item["worker"] for item in static_loaded] != ws:
                raise W.WorkerRefused(
                    "REFUSED: planned workers differ from the static "
                    "authenticated v3 pool; no Docker command was run.")
            expected_database = args.db_container if needs_db else None
            static_database = (
                static_pool["database"]["container_name"]
                if static_pool["database"] is not None else None)
            if static_database != expected_database:
                raise W.WorkerRefused(
                    "REFUSED: --db-container differs from the static "
                    "authenticated v3 pool; no Docker command was run.")
            if args.internal_network is not None \
                    and static_pool["network"]["name"] \
                    != args.internal_network:
                raise W.WorkerRefused(
                    "REFUSED: --internal-network differs from the static "
                    "authenticated v3 pool; no Docker command was run.")
            runtime = W.validate_live_worker_runtime(
                args.worker, selected, HARNESS_VERSION, needs_db, answers,
                expected_pool_size=args.k, behat=behat_row())
        except W.WorkerRefused as exc:
            raise SystemExit(str(exc)) from exc
        if list(runtime["pool_specs"]) != ws:
            raise SystemExit(
                "REFUSED: authenticated v3 pool differs from the complete "
                "pool derived by the administration flags.")
        pool = runtime["selected"]["binding"]["pool"]
        expected_database = args.db_container if needs_db else None
        observed_database = (pool["database"]["container_name"]
                             if pool["database"] is not None else None)
        if observed_database != expected_database:
            raise SystemExit(
                "REFUSED: --db-container differs from the authenticated v3 "
                "pool database container.")
        if args.internal_network is not None \
                and pool["network"]["name"] != args.internal_network:
            raise SystemExit(
                "REFUSED: --internal-network differs from the authenticated "
                "v3 pool network.")
        return runtime

    if args.action == "preflight":
        if args.live:
            require_bound_admin_pool()
        report = (W.preflight(
            chosen, answers, live=True, needs_database=needs_db,
            expected_indices=[w.index for w in chosen],
            behat=behat_row())
                  if args.live else
                  W.preflight(ws, answers, live=False,
                              needs_database=needs_db))
        print(json.dumps(report, indent=1))
        return 0

    if args.action == "provision":
        provision_jobs = getattr(args, "jobs", 1)
        if provision_jobs < 1:
            raise SystemExit("REFUSED: worker provision --jobs must be at least 1")
        if args.force:
            _refuse_unbound_live_workload(
                "worker provision --force cleanup", "lifecycle/cleanup")
        if args.only is not None:
            raise SystemExit(
                "REFUSED: worker provision must create the complete pool; "
                "--only cannot mint honest v3 pool bindings")
        if needs_db and not args.internal_network:
            raise SystemExit(
                "REFUSED: database-backed v3 workers require an explicit "
                "--internal-network and a dedicated database already "
                "exclusive to it")
        if not needs_db and args.internal_network:
            raise SystemExit(
                "REFUSED: a no-database v3 pool uses Docker network none; "
                "--internal-network would add an unbound peer route")
        from .. import docker_authority as DA
        from ..core import docker_cli as DC
        from .validate import HARNESS_VERSION
        # The framework question (whether the Kilo-era composer cache is a
        # required mount) is config, not pool state; the pool itself comes
        # from the saved manifests above.
        prof = _stack_profile(args)
        behat = behat_row()
        # The policy THIS invocation's project seeds under, for `provision`
        # to check the seed's own `rules_digest` against.  Both halves come
        # from the flags already given: the framework from the profile, the
        # project from the boundary.  A seed built for another project is the
        # one wrong pool that provisions, hardens and probes green.
        from .seed import rules_for
        seed_policy = rules_for(prof.framework, _boundary(args).project).digest()
        # Content-bearing host inputs are resolved before the first live
        # authority or network probe.  A missing Kilo-era cache must be a
        # portable configuration refusal with zero Docker contact.
        mounts = W.composer_mounts(
            required=bool(needs_db and prof.framework == "behat"),
            explicit=args.composer_cache)
        agent_jar = getattr(args, "direct_call_agent_jar", None)
        if agent_jar:
            from ..java import direct_calls as _dc
            try:
                mounts = mounts + (_dc.agent_jar_mount(agent_jar),)
            except _dc.DirectCallsRefused as exc:
                raise SystemExit(str(exc)) from exc
            print(f"direct-invocation agent jar {_dc.sha256_file(agent_jar)} "
                  f"{agent_jar} -> {_dc.AGENT_JAR_RUNTIME} (read-only)",
                  file=sys.stderr)
        seed_identity = W.verified_seed_identity(args.seed, needs_db)
        spec_paths = [
            os.path.abspath(os.path.join(
                args.workers_root, f"worker{w.index}.json"))
            for w in ws
        ]
        invalid_specs = [path for path in spec_paths
                         if os.path.islink(path) or not os.path.isfile(path)]
        if invalid_specs:
            raise SystemExit(
                "REFUSED: provision-time runtime evidence requires the exact "
                f"saved worker specs; run `worker plan` first: {invalid_specs}")
        evidence_paths = [
            path for spec_path in spec_paths
            for path in (W.binding_attestation_path(spec_path),
                         W.runtime_attestation_path(spec_path))
        ]
        collisions = [path for path in evidence_paths if os.path.lexists(path)]
        if collisions:
            raise SystemExit(
                "REFUSED: v3 binding/runtime evidence is immutable and already "
                f"exists; move the disposable pool to a fresh root: {collisions}")
        pool = W.build_execution_pool(
            ws, spec_paths,
            database_container=(args.db_container if needs_db else None),
            internal_network=(args.internal_network if needs_db else None))
        protected_evidence = [*spec_paths, *evidence_paths]
        W.preflight(ws, answers + protected_evidence, live=False,
                    needs_database=needs_db)
        _authority_doc, authority_ref = DC.authority_reference(live=True)
        # Quartz AUTO uses InetAddress.getLocalHost(); network-none containers
        # need their hostname explicitly bound to loopback. No peer route is added.
        extra = _worker_process_args(prof)
        if args.internal_network:
            # Informational: the one parseable stdout payload is the final
            # live preflight report below.
            print(json.dumps(W.validate_dedicated_database_network(
                args.db_container, args.internal_network), indent=1),
                  file=sys.stderr)
        network = args.internal_network if needs_db else "none"

        def _provision_one(worker):
            from contextlib import nullcontext
            # MySQL owns a mutable temporary credential-file path. Never
            # share that context between concurrently provisioned workers.
            database = (MySQL(container=args.db_container)
                        if needs_db else nullcontext(None))
            with database as db:
                return W.provision(
                    worker, args.seed, db, network=network,
                    image=image, force=args.force,
                    extra_run_args=extra, extra_mounts=mounts,
                    needs_database=needs_db,
                    template_container=getattr(args, "template_container", None),
                    overrides={} if not needs_db else None,
                    behat=behat, seed_policy=seed_policy)

        memory_observations = {}
        for w, rep in _provision_workers(ws, _provision_one, jobs=provision_jobs):
            if prof.project == "prestashop":
                memory_observations[w.index] = rep["memory_observation"]
            app_env = rep.get("app_env") or {}
            if app_env.get("template_container"):
                print(f"worker {w.index}: application environment "
                      f"{app_env['names']} from "
                      f"{app_env['template_container']}", file=sys.stderr)
            tables = rep["schema"].get("tables")
            print(f"worker {w.index}: "
                  + (f"{tables} tables, " if tables is not None
                     else f"{rep['schema']['declared']}, ")
                  + f"{rep['seconds']}s", file=sys.stderr, flush=True)
        if W.verified_seed_identity(args.seed, needs_db) != seed_identity:
            raise SystemExit("REFUSED: seed changed while the worker pool was provisioned")
        if W.build_execution_pool(
                ws, spec_paths,
                database_container=(args.db_container if needs_db else None),
                internal_network=(args.internal_network if needs_db else None)) != pool:
            raise SystemExit("REFUSED: saved worker specs changed during provisioning")
        # Provisioning and post-provision evidence capture are distinct
        # phases.  Revalidate the authority/fingerprint after all mutations
        # and before trusting the newly live pool.
        DC.reset_phase()
        bindings = W.capture_execution_bindings(pool, authority_ref)
        # Do not mint immutable evidence for a container whose actual mounts,
        # cache access mode, runtime environment, or answer containment fail.
        # The in-memory bindings already authenticate the pool; publication
        # happens only after this last live acceptance boundary succeeds.
        preflight_report = W.preflight(
            ws, answers + protected_evidence, live=True,
            needs_database=needs_db,
            expected_indices=[w.index for w in ws],
            behat=behat)
        # Every Go worker's enforced memory cap is checked before any
        # binding or runtime evidence is written, so a refusal mints none.
        from .prestashop_memory import capture_go_memory, go_memory_run_args
        if go_memory_run_args(prof.project):
            preflight_report["memory_observations"] = [
                {"worker": w.index, "at_attestation": capture_go_memory(w)} for w in ws]
        for w, spec_path, binding in zip(ws, spec_paths, bindings):
            binding_path = W.binding_attestation_path(spec_path)
            DA.write_evidence_no_clobber(binding_path, binding)
            memory = W.capture_prestashop_memory(w) if prof.project == "prestashop" else None
            if memory is not None:
                preflight_report.setdefault("memory_observations", []).append({
                    "worker": w.index, "before_initialization": memory_observations[w.index],
                    "at_attestation": memory})
            runtime_doc = W.build_worker_runtime_attestation(
                w, spec_path, seed_identity, HARNESS_VERSION,
                binding_path=binding_path,
                **({"memory_evidence": memory["memory"]} if memory is not None else {}))
            DA.write_evidence_no_clobber(
                W.runtime_attestation_path(spec_path), runtime_doc)
        # The one parseable stdout payload: the complete live preflight
        # report (RC3), untruncated.
        print(json.dumps(preflight_report, indent=1))
        return 0

    if not needs_db and args.action in ("probe", "reset-probe", "harden",
                                        "unharden", "teardown"):
        # `teardown` is here with the other three because its database half is
        # all it would do beyond removing the container -- which it still
        # does, below, with `db=None`.
        if args.action != "teardown":
            raise SystemExit(
                f"REFUSED: `worker {args.action}` is a database step and "
                "the saved worker manifests declare no database. "
                f"There is no schema to isolate and no `root@%` to remove; "
                f"running it would record an acceptance that cannot fail.")
        admin_runtime = require_bound_admin_pool()
        teardown_image = admin_runtime["selected"]["runtime"][
            "container_image_digest"]
        for w in chosen:
            print(w.index, json.dumps(W.teardown(
                w, None, keep_workspace=args.keep_workspace,
                image=teardown_image)))
        return 0

    if args.action == "probe":
        require_bound_admin_pool()
        sentinel = getattr(args, "sentinel_schema", None)
        if sentinel is not None:
            # A sentinel that is only a NAME is worse than none: MySQL denies
            # on privilege before it resolves the table, so an empty or absent
            # schema yields six genuine permission errors and a green verdict
            # that nothing could ever have falsified.
            with MySQL(container=args.db_container) as db:
                if sentinel not in db.schemas():
                    raise SystemExit(
                        f"REFUSED: sentinel schema {sentinel!r} does not "
                        "exist, so its denials would prove nothing.")
                if not db.table_bytes(sentinel):
                    raise SystemExit(
                        f"REFUSED: sentinel schema {sentinel!r} holds no "
                        "tables. A denial over an empty schema is "
                        "indistinguishable from a denial over data that was "
                        "never there.")
        out = []
        for w in chosen:
            victim = W.probe_victim_schema(ws, w, sentinel)
            out.append(W.probe_database(w, victim, behat=behat_row()))
        print(json.dumps(out, indent=1))
        return 0 if all(o["pass"] for o in out) else 1

    if args.action == "reset-probe":
        admin_runtime = require_bound_admin_pool()
        # This verb has no `--seed`: the pool's own authenticated runtime
        # names the seed every worker was provisioned from, and
        # `validate_worker_runtime_v3` has just re-verified its bytes.
        derived = _derived_baseline(
            args, admin_runtime["selected"]["runtime"]["seed_dir"])
        out = []
        for w in chosen:
            # One harness per worker, built the way `test-quality` builds one
            # per job: `_harness` reads `--repo`/`--container`/`--workdir`, and
            # a pool command must not leave those pointing at whichever worker
            # the global `--worker` happened to name.
            wargs = argparse.Namespace(**vars(args))
            wargs.repo = w.workspace
            wargs.container = w.container
            wargs.workdir = w.workdir
            harness, _wboundary, _manifest = _harness(wargs)
            if derived:
                harness.derived_baseline = derived
            try:
                out.append(W.reset_probe(w, harness))
            except W.WorkerRefused as exc:
                raise SystemExit(str(exc)) from exc
        print(json.dumps(out, indent=1))
        return 0 if all(o["pass"] for o in out) else 1

    if args.action == "harden":
        require_bound_admin_pool()
        with MySQL(container=args.db_container) as db:
            print(json.dumps(W.harden_database(chosen, db), indent=1))
        return 0

    if args.action == "unharden":
        require_bound_admin_pool()
        with MySQL(container=args.db_container) as db:
            print(json.dumps(db.restore_wildcard_root(), indent=1))
        return 0

    if args.action == "teardown":
        admin_runtime = require_bound_admin_pool()
        teardown_image = admin_runtime["selected"]["runtime"][
            "container_image_digest"]
        with MySQL(container=args.db_container) as db:
            for w in chosen:
                print(w.index, json.dumps(W.teardown(
                    w, db, keep_workspace=args.keep_workspace,
                    image=teardown_image)))
        return 0
    raise SystemExit(f"unknown worker action: {args.action}")


def cmd_environment(args) -> int:
    """Descriptor-driven project environment lifecycle (up/status/down).

    The composition lives in `r2t.toolkit.environment_lifecycle`; each worker step is
    an existing reviewed command surface invoked with an explicit argv, and
    `up` accepts only after the descriptor's gold control passes.
    """
    from ..toolkit import environment_lifecycle as EL
    if args.action == "up":
        return EL.up(args.project, k=args.k)
    if args.action == "status":
        return EL.status(args.project, nonce=args.nonce)
    if args.action == "down":
        return EL.down(args.project, nonce=args.nonce)
    raise SystemExit(f"unknown environment action: {args.action}")


def _publication_merge_sources(args):
    """Return the receipt-only publication input, refusing mixed authority."""
    if getattr(args, "manifest", None):
        raise SystemExit(
            "REFUSED: merge --publication-v3 accepts only explicit "
            "--source-receipt evidence, never --manifest.")
    return getattr(args, "source_receipt", None) or ()


def cmd_merge(args) -> int:
    """The strict merge of §3.7 — refuse, never repair."""
    if getattr(args, "publication_v3", False):
        from .campaign import merge_publication_v3
        info = merge_publication_v3(
            _publication_merge_sources(args),
            release_path=args.release, out_path=args.out,
            expected_shards=args.of)
        print(json.dumps(info, indent=1, sort_keys=True))
        return 0
    if getattr(args, "source_receipt", None):
        raise SystemExit(
            "REFUSED: --source-receipt is only accepted by explicit "
            "merge --publication-v3.")
    if not getattr(args, "manifest", None):
        raise SystemExit(
            "REFUSED: default merge requires --manifest once per shard.")
    from .campaign import merge_shards, write_merged
    from .runner import _load_release
    expected = [i["item_id"] for i in _load_release(args.release)]
    result = merge_shards(args.manifest, expected, args.of)
    out = write_merged(result, args.out)
    print(json.dumps({"out": out, "n": result["n"],
                      "campaign_digest": result["campaign_digest"],
                      "workers": len(result["workers"])}, indent=1))
    return 0


def cmd_finish(args) -> int:
    """Finish one complete result-v3 campaign into a run and table."""
    from .finish import finish_campaign
    print(json.dumps(finish_campaign(args.campaign), indent=1,
                     sort_keys=True))
    return 0


def cmd_verify_shard(args) -> int:
    """Re-attest one mutation shard against its own bytes. WRITES NOTHING.

    The verb review finding 8's third leg asks for: when a shard has been
    demoted to `failed` by something that has nothing to do with its rows, the
    operator needs evidence about which of the two happened before spending a
    rerun — and the alternative remedy, editing the sidecar by hand, must
    never be the one available. So this reports and does not repair.

    Exit 1 when the recorded TERMINAL state is not supported by the bytes,
    0 when it is, and 0 with `state_consistent_with_bytes: null` for a shard
    that is still running or interrupted, which is not a terminal claim to
    contradict.
    """
    from .mutation_run import MutationAborted, verify_shard
    try:
        report = verify_shard(args.out)
    except MutationAborted as e:
        raise SystemExit(str(e))
    print(json.dumps(report, indent=1, sort_keys=True))
    return 1 if report["state_consistent_with_bytes"] is False else 0


def cmd_verify_receipt(args) -> int:
    """Verify one result-ledger receipt recursively and write nothing."""
    from .result_ledger import ResultLedgerRefused, verify_receipt
    try:
        report = verify_receipt(args.receipt)
    except ResultLedgerRefused as exc:
        raise SystemExit(str(exc)) from exc
    # This is the only stdout on success, and it is reached only after the
    # verifier's final stable reread of the complete transitive evidence.
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


def cmd_campaign(args) -> int:
    """Level 1 of §3.6 — the fingerprint every shard must agree on.

    Emits `r2t.generation-campaign/v2` (plan §3, PR R3): the same recipe
    terms v1 carried, plus WHICH ATTEMPT this is, WHICH HARNESS BYTES will
    judge it, and the immutable runtime manifest the agent will run inside.
    v1 fingerprints stay readable and re-hashable; nothing writes one.
    """
    from .campaign import (AGENT_RUNTIME_SCHEMA, POSITIONAL_SHARD_RULE,
                                  SHARD_RULE,
                                  agent_runtime_digest, campaign_digest,
                                  generation_fingerprint,
                                  harness_commit_identity,
                                  harness_source_digest,
                                  probe_agent_runtime)
    from .validate import HARNESS_VERSION
    from . import seed as S
    interpreter = sys.executable
    requirements_lock = None
    llm_config = getattr(args, "llm_config", None)
    if args.agent_system:
        from ..agents import get_spec
        spec = get_spec(args.agent_system)
        if spec.kind != "agent":
            raise SystemExit(
                f"REFUSED: --agent-system {args.agent_system!r} is a "
                f"{spec.kind}, not an agent campaign system.")
        from ..agents.backends import AGENT_BACKENDS
        from .adapters import resolve_llm_config
        args.model = resolve_llm_config(
            llm_config, args.model,
            require_credentials=False)["model"]
        agent_backend = AGENT_BACKENDS[spec.name]
    elif llm_config:
        from .adapters import resolve_llm_config
        args.model = resolve_llm_config(
            llm_config, args.model,
            require_credentials=False)["model"]
    slice3_context = getattr(args, "_slice3_campaign_context", None)
    if slice3_context is None:
        campaign_shard_rule = SHARD_RULE
    else:
        from ..agents.slice3_eval import (validate_cell_capability,
                                  validate_cell_release)
        try:
            slice3_context = validate_cell_capability(
                slice3_context, expected_mode="campaign")
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        expected = {
            "k": slice3_context["k_workers"],
            "trials": "unlimited",
            "condition": "c3",
            "coverage": True,
            "model": "deepseek-v4-pro",
            "protocol_version": slice3_context["protocol_version"],
            "protocol_digest": slice3_context["protocol_digest"],
            "agent_system": slice3_context["agent_system"],
        }
        mismatch = {
            key: (want, getattr(args, key, None))
            for key, want in expected.items()
            if getattr(args, key, None) != want
        }
        if mismatch:
            raise SystemExit(
                "REFUSED: Slice-3 campaign flags differ from its frozen "
                f"cell: {mismatch}")
        if _boundary(args).project != slice3_context["project"]:
            raise SystemExit(
                "REFUSED: Slice-3 campaign boundary names another project")
        try:
            validate_cell_release(
                slice3_context, getattr(args, "release", None))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        campaign_shard_rule = POSITIONAL_SHARD_RULE
    # A CAMPAIGN IDENTITY IS MINTED ONCE.  Re-running this command over an
    # existing file would mint a SECOND attempt id and hand the operator a
    # different digest for what they think is the same campaign — every row
    # already stamped with the first would then refuse to merge. Refusing is
    # cheap; discovering it after a paid sweep is not.
    if os.path.lexists(args.out):
        raise SystemExit(
            f"REFUSED: {args.out} already exists. A campaign identity is "
            f"minted once and then reused by every shard: re-use this file, "
            f"or write the new attempt to a new path. (A re-run is a new "
            f"attempt and therefore a new identity, which is the point.)")
    doc = S.read_seed(args.seed) or {}
    with open(args.boundary, "rb") as fh:
        import hashlib
        config_digest = hashlib.sha256(fh.read()).hexdigest()[:16]
    # The RECIPE this campaign's shards must all have followed, bound into the
    # digest as an identity rather than as a document. `None` when the
    # campaign was created without `--protocol`, which is a different 16 hex
    # characters from any protocol -- "this campaign followed no protocol
    # file" is a fact, not a gap.
    protocol_version = protocol_digest = None
    if args.protocol is not None:
        from ..agents import protocol as P
        try:
            pdoc = P.load(args.protocol)
        except P.ProtocolError as e:
            raise SystemExit(f"REFUSED: {e}")
        protocol_version = pdoc["protocol_version"]
        protocol_digest = P.protocol_digest(pdoc)
    # WHAT THE AGENT RUNS INSIDE.  Probed rather than declared, except for
    # the network posture: that is an explicit factual disclosure supplied by
    # the operator, not an enforcement claim inferred from a retired gate
    # (the network publication controls are retired prospectively; recorded
    # campaigns keep the measured labels they were minted with).
    from ..confined import result_ledger_v2 as agent_v2
    # SECTION 4.1 OF THE RESULT-V3 AGENT PRODUCER AMENDMENT, BOUNDED BY
    # SECTION 10.  Campaign creation is the first of the four moments that
    # "re-inventory the same backend and require exact equality and repeat the
    # same direct startup observation", and the companion an agent campaign
    # carries "is built from this selected backend, never by probing the
    # coordinator interpreter".  That moment is what `--agent-backend-runtime`
    # selects, and BINDING THE BACKEND is what puts this command in it --
    # NOT the name in `--agent-system`.  Section 10 is why: "without explicit
    # agent publication mode, no ... campaign behavior ... changes", and
    # section 3 fixes that mode as `run --publication-v3 --adapter
    # {openhands|aider}`, which no `campaign` command line is ever in.
    #
    # Nothing is lost by scoping it this way, because the publication gate is
    # closed independently and totally: `verify_campaign_agent_runtime` (via
    # `verify_agent_adapter`) rebuilds this companion FROM the plan's backend
    # and requires whole-document equality, and the probe never emits
    # `agent_backend_runtime_digest` at all.  A probe-built companion is
    # therefore inadmissible at plan verification -- it can never authorize a
    # publication shard -- while the ordinary v1 sweep this repository runs
    # keeps working and keeps `runner._check_campaign_flags`' system
    # crosscheck, which dropping `--agent-system` would silently discard.
    #
    # The probe itself now interrogates the SELECTED interpreter in a
    # subprocess -- the agent backend's own python under its exact
    # requirements lock when `--agent-system` names one, the coordinator
    # otherwise -- so a probed agent campaign records the locked backend
    # environment it will actually run inside.  It is still a probe: it can
    # never stand in for the backend-built section 4.1 companion above.
    agent_kind = (args.agent_system
                  if args.agent_system in agent_v2.ADMITTED_ADAPTER_KINDS
                  else None)
    backend_runtime = getattr(args, "agent_backend_runtime", None)
    if backend_runtime is None:
        network_semantics = args.network_semantics
        if not network_semantics:
            raise SystemExit(
                "REFUSED: --network-semantics is a required factual runtime "
                "disclosure for a new campaign; the retired egress gate no "
                "longer supplies a measured default.")
        if args.agent_system:
            # Resolved only on the probe route: a campaign that BINDS a
            # backend below never starts this interpreter, and must not
            # demand the probe environment it will not use.
            interpreter = agent_backend.python()
            requirements_lock = agent_backend.requirements_lock
        runtime = probe_agent_runtime(
            interpreter=interpreter,
            network_semantics=network_semantics,
            agent_system=args.agent_system,
            requirements_lock=requirements_lock)
    else:
        if agent_kind is None:
            raise SystemExit(
                "REFUSED: --agent-backend-runtime binds an AGENT campaign's "
                f"selected backend, and --agent-system is {args.agent_system!r}"
                f", not one of {sorted(agent_v2.ADMITTED_ADAPTER_KINDS)}.")
        network_semantics = args.network_semantics or agent_v2.NETWORK_SEMANTICS
        if network_semantics != agent_v2.NETWORK_SEMANTICS:
            raise SystemExit(
                "REFUSED: an agent campaign's network_semantics is exactly "
                f"{agent_v2.NETWORK_SEMANTICS!r}, which is the value the run "
                f"gate joins; --network-semantics named {network_semantics!r}.")
        try:
            _backend, runtime = agent_v2.campaign_agent_runtime(
                backend_runtime, adapter_kind=agent_kind,
                workspace=os.path.dirname(os.path.abspath(args.out)))
        except agent_v2.ResultLedgerV2Refused as exc:
            raise SystemExit(str(exc)) from exc
    runtime_path = args.out + ".agent_runtime.json"
    if os.path.lexists(runtime_path):
        raise SystemExit(
            f"REFUSED: {runtime_path} already exists; an agent-runtime "
            f"manifest is immutable and is written once beside its campaign.")
    # ATTEMPT IDENTITY.  Minted per invocation unless the operator pins one,
    # because the failure this closes is two attempts of one recipe hashing
    # alike (review finding 20): deriving the id from the arguments would
    # reproduce exactly that.
    attempt_id = args.attempt_id or (
        f"{args.campaign_id}-"
        f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-"
        f"{secrets.token_hex(4)}")
    # A campaign that can authorize live shards is rooted in the same exact
    # v3 pool those shards will use.  Authority alone is not permission to
    # inspect a tag on an otherwise anonymous daemon.  The historical
    # `--allow-unresolved` design-only mode remains useful, but is now always
    # Docker-free and cannot pass a later live runtime join.
    from . import worker as W
    selected_worker = _worker_spec(args)
    if selected_worker is None:
        if not args.allow_unresolved:
            raise SystemExit(
                "REFUSED: an executable campaign requires global --worker "
                "with exact r2t.worker-runtime/v3 evidence. Docker authority "
                "alone is not workload binding; no Docker command was run.")
        image_digest = "unknown"
        workspace_seed_digest = doc.get("workspace_seed_digest")
        database_dump_digest = doc.get("database_dump_digest")
    else:
        needs_db = _stack_profile(args).needs_database
        _refuse_unbound_database_runtime(
            needs_db, "database-backed executable campaign creation")
        try:
            seed_identity = W.verified_seed_identity(args.seed, needs_db)
            selected_static = W.validate_worker_runtime_v3(
                args.worker, expected_worker=selected_worker,
                seed_dir=args.seed, harness_version=HARNESS_VERSION,
                needs_database=needs_db)
            runtime_identity = {
                "harness_version": HARNESS_VERSION,
                "container_image_digest": selected_static["runtime"][
                    "container_image_digest"],
                "workspace_seed_digest": seed_identity[
                    "workspace_seed_digest"],
                "database_dump_digest": seed_identity[
                    "database_dump_digest"],
            }
            protected = W.default_answer_paths(
                args.gold, args.artifacts,
                os.path.join(args.artifacts, "release"))
            protected.extend(filter(None, (
                args.seed, args.boundary, getattr(args, "profile", None),
                args.out, runtime_path,
            )))
            bound_runtime = W.validate_live_worker_runtime(
                args.worker, selected_worker, HARNESS_VERSION, needs_db,
                protected, expected_pool_size=args.k,
                expected_runtime=runtime_identity,
                behat=_behat_row(args), project=_stack_profile(args).project)
        except W.WorkerRefused as exc:
            raise SystemExit(str(exc)) from exc
        image_digest = _image_digest(args.image)
        bound_image_digest = bound_runtime["selected"]["runtime"][
            "container_image_digest"]
        if image_digest != bound_image_digest:
            raise SystemExit(
                f"REFUSED: --image resolves to {image_digest!r}, but the "
                "authenticated v3 pool runs "
                f"{bound_image_digest!r}.")
        workspace_seed_digest = seed_identity["workspace_seed_digest"]
        database_dump_digest = seed_identity["database_dump_digest"]
    fp = generation_fingerprint(
        attempt_id=attempt_id,
        harness_commit=harness_commit_identity(),
        harness_source_sha256=harness_source_digest(),
        agent_runtime_sha256=agent_runtime_digest(runtime),
        network_semantics=network_semantics,
        campaign_id=args.campaign_id,
        k_workers=args.k,
        shard_rule=campaign_shard_rule,
        trial_budget=args.trials,
        condition=args.condition,
        coverage=bool(args.coverage),
        harness_version=HARNESS_VERSION,
        config_digest=config_digest,
        model=args.model,
        container_image_digest=image_digest,
        workspace_seed_digest=workspace_seed_digest,
        database_dump_digest=database_dump_digest,
        protocol_version=protocol_version,
        protocol_digest=protocol_digest,
        # WHICH SYSTEM. `None` when the campaign does not say (every control
        # campaign, and every campaign written before the field existed),
        # which is a different 16 hex characters from any system that does.
        agent_system=args.agent_system)
    # Refuse a fingerprint that identifies nothing.
    #
    # `_image_digest` returns "unknown" when docker is unreachable, and a seed
    # directory that has never been built yields empty digests — so a campaign
    # could be created whose "identity" fields identified no image and no seed,
    # and every shard would then agree on that emptiness. A review created
    # exactly such a campaign.
    unresolved = sorted(k for k in ("container_image_digest",
                                    "workspace_seed_digest",
                                    "database_dump_digest", "harness_version",
                                    # v2: a campaign that cannot say which
                                    # commit produced it is reproducible only
                                    # by its source digest, and that is a
                                    # choice an operator makes explicitly.
                                    "harness_commit")
                        if not fp.get(k) or fp.get(k) == "unknown")
    if unresolved and not args.allow_unresolved:
        raise SystemExit(
            f"REFUSED: {unresolved} could not be resolved, so this campaign "
            f"would fingerprint nothing. Build the seed and make the image "
            f"readable, or pass --allow-unresolved if this campaign is "
            f"deliberately not reproducible.")
    # The seed must also be intact and current, not merely present.
    if args.seed and not args.allow_unresolved:
        from . import seed as _S
        v = _S.verify_seed(args.seed, _boundary(args).repo_root)
        if not v["artifacts_ok"]:
            raise SystemExit(
                f"REFUSED: the seed at {args.seed} does not match its own "
                f"recorded digests: {json.dumps(v)[:300]}")
        if v.get("stale"):
            print(f"  NOTE: the seed is STALE — its source tree has changed "
                  f"since it was built (source key now {v.get('source_key_now')}"
                  f"). The campaign records the seed's digests, so this is "
                  f"reproducible; it is simply not the current tree.")
    with open(runtime_path, "w", encoding="utf-8") as fh:
        json.dump(runtime, fh, indent=1, sort_keys=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(fp, fh, indent=1, sort_keys=True)
    print(json.dumps({"out": args.out, "digest": campaign_digest(fp),
                      "agent_runtime": runtime_path,
                      "agent_runtime_schema": AGENT_RUNTIME_SCHEMA,
                      "campaign": fp}, indent=1))
    return 0


def _image_digest(image: str) -> str:
    import subprocess
    from ..core.docker_cli import docker_command
    cp = subprocess.run(
        docker_command(["image", "inspect", image, "--format", "{{.Id}}"]),
        capture_output=True, text=True)
    return (cp.stdout or "").strip() or "unknown"


def cmd_confine(args) -> int:
    """Probe both namespaces from INSIDE them and refuse a vacuous pass."""
    _refuse_unbound_live_workload(
        "confinement certification",
        "agent-workspace-and-v3-evidence-containment")
    from . import confine as C
    from . import worker as W
    if not getattr(args, "agent", None):
        raise SystemExit(
            "REFUSED: --agent WORKSPACE is required. A confinement "
            "certificate that omits the agent namespace certifies the half "
            "that was never the problem; no Docker command was run.")
    selected = _worker_spec(args)
    if selected is None:
        raise SystemExit(
            "REFUSED: live confinement requires global --worker with exact "
            "r2t.worker-runtime/v3 evidence; no Docker command was run.")
    needs_db = _stack_profile(args).needs_database
    _refuse_unbound_database_runtime(
        needs_db, "database-backed confinement certification")
    answers = W.default_answer_paths(
        args.gold, args.artifacts, os.path.join(args.artifacts, "release"))
    from .validate import HARNESS_VERSION
    try:
        runtime = W.validate_live_worker_runtime(
            args.worker, selected, HARNESS_VERSION, needs_db, answers,
            expected_pool_size=args.k, behat=_behat_row(args),
            project=_stack_profile(args).project)
    except W.WorkerRefused as exc:
        raise SystemExit(str(exc)) from exc
    expected_paths = tuple(os.path.abspath(os.path.join(
        args.workers_root, f"worker{i}.json")) for i in range(args.k))
    if runtime["pool_paths"] != expected_paths:
        raise SystemExit(
            "REFUSED: --workers-root differs from the authenticated v3 pool "
            "layout; no confinement probe was run.")
    ws = list(runtime["pool_specs"])
    pool = runtime["selected"]["binding"]["pool"]
    observed_database = (pool["database"]["container_name"]
                         if pool["database"] is not None else None)
    if observed_database != (args.db_container if needs_db else None):
        raise SystemExit(
            "REFUSED: --db-container differs from the authenticated v3 pool; "
            "no confinement probe was run.")
    if args.only is not None \
            and any(index < 0 or index >= len(ws) for index in args.only):
        raise SystemExit(
            "REFUSED: --only names a worker outside the authenticated v3 "
            "pool; no confinement probe was run.")
    chosen = [w for w in ws if args.only is None or w.index in args.only]
    verdicts = []
    # Declared BEFORE probing, so a namespace that is never reached fails
    # instead of being silently absent from the certificate.
    expected = [f"executor[{w.index}]" for w in chosen]
    expected.append("agent")
    for w in chosen:
        others = [o.workspace for o in ws if o.index != w.index]
        spec = C.executor_spec(
            answers, others,
            db_host=(f"{args.db_container}:3306" if needs_db else None))
        # Named per worker: `certify` keys its report by namespace name, so
        # four workers all called "executor" would collapse into one entry and
        # three of the four probes would silently vanish from the record.
        spec.name = f"executor[{w.index}]"
        runner = w.runner()
        verdicts.append(C.verdict(spec, C.probe(
            spec, lambda script: (runner.run(script, timeout=300).stdout or ""))))
    spec = C.agent_spec(answers)
    # The BUILDER is agent code (`agents.sandbox`); the spec, the probe
    # and the certificate above are not.  Imported here, in the one verb
    # that probes a live agent namespace, so no consumer verb reaches it.
    from ..agents.sandbox import agent_sandbox_argv
    prefix = agent_sandbox_argv(args.agent)
    import subprocess

    def run_in_sandbox(script: str) -> str:
        cp = subprocess.run(prefix + ["/bin/sh", "-c", script],
                            capture_output=True, text=True, timeout=300)
        return cp.stdout or ""

    verdicts.append(C.verdict(spec, C.probe(spec, run_in_sandbox)))
    report = C.certify(verdicts, expected=expected)
    print(json.dumps(report, indent=1))
    return 0 if report["certified"] else 1


def run_slice3_mutation_job(context: dict, argv: list[str]) -> int:
    """Retired Slice-3 forward seam; saved evidence remains readable."""
    del context, argv
    raise SystemExit(
        "REFUSED: the direct Slice-3 mutation producer is retired; new live "
        "work requires the generic #203 test-quality authority")


def _validated_mutation_assets(args, *, paid_view_subset: bool,
                               compact_allowed: bool,
                               algorand_bundle_version: str = "1"):
    """Use the native report or the installed Slice-3 compact authority."""
    from ..data import mutation_attestation as A
    try:
        with open(args.mutation_validation, encoding="utf-8") as handle:
            schema = json.load(handle).get("schema")
    # `TypeError` because `test-quality` leaves `--mutation-validation`
    # optional: the peek can be handed None, and an absent or unnamed report
    # is not this function's refusal to make.  Falling through hands that
    # exact value to the native validator, which owns the message.
    except (AttributeError, OSError, TypeError, json.JSONDecodeError):
        schema = None
    if schema == "r2t.algorand-bundle-mutation-validation/1":
        if not compact_allowed or not paid_view_subset:
            raise A.MutationAssetRefused(
                "REFUSED: compact Algorand mutation authority is admitted "
                "only for a bound Slice-3 paid view")
        from ..toolkit import algorand_bundle
        try:
            return algorand_bundle.validate_installed_mutation_inputs(
                validation_path=args.mutation_validation,
                manifest_path=args.manifest, map_path=args.map,
                release_path=args.release,
                version=algorand_bundle_version)
        except algorand_bundle.AlgorandBundleRefused as exc:
            raise A.MutationAssetRefused(str(exc)) from exc
    locations = _validation_input_paths(args)
    return A.validate_campaign_asset_inputs(
        args.mutation_validation, manifest_path=args.manifest,
        map_path=args.map,
        release_path=(getattr(args, "map_release", None) or args.release),
        require_release_ready=True, paid_view_subset=paid_view_subset,
        budgeted_sidecar=_budgeted_sidecar_path(args),
        **({"input_paths": locations} if locations is not None else {}))



def _mutation_java_analysis_root(args, manifest, worker_roots):
    """Authenticate an explicitly separate compiler capture before live work."""
    root = getattr(args, "java_analysis_root", None)
    if root is None:
        return None
    from ..toolkit import mutation_java as JAVA
    recipe = manifest.get("analysis_recipe", {})
    if manifest.get("engine") != JAVA.ENGINE or recipe.get("schema") \
            != JAVA.MODULE_ANALYSIS_SCHEMA:
        raise SystemExit("REFUSED: --java-analysis-root requires a Kapua module-analysis manifest")
    root = os.path.abspath(root)
    try:
        JAVA.revalidate_analysis_inputs(root, recipe)
        for worker_root in worker_roots:
            JAVA.validate_module_analysis_sources(worker_root, recipe)
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    return root


def cmd_mutation_run(args) -> int:
    """Execute a slice of the mutant manifest against one candidate (§3.10)."""
    _refuse_unscoped_evaluation_sources(args, development_reference=True)
    # Read here as well as at asset validation because the `--reference-scope`
    # branch below never reaches it, and a flag that decides the population
    # must not be silently ignored on the one route that skips its reader.
    _budgeted_sidecar_path(args)
    if getattr(args, "reference_scope", None) is not None \
            and getattr(args, "reference_role", None) is None:
        raise SystemExit("REFUSED: --reference-scope collection requires --reference-role")
    if getattr(args, "gold_baseline", None) is not None \
            and getattr(args, "reference_scope", None) is None:
        raise SystemExit("REFUSED: mutation-run --gold-baseline requires --reference-scope")
    # THE REFERENCE DOOR.  The capability gate is the whole of this verb's
    # live-workload binding, and it is bound to the DOCX evidence workload --
    # which is one project's.  A reference observation (full gold,
    # assertion-stripped gold, stub control) has to be collectable once per
    # project, so `--reference-role` is the binding for every project
    # (owner ruling, 2026-09-01).  Nothing else about the sweep changes: the
    # complete authenticated pool, the frozen population, the substrate and
    # timeout rules are unchanged, and the reviewed DOCX wrapper stays valid
    # for its own recorded phases -- it is no longer the only route to a
    # python-docx leg, because one verified route for all three projects is
    # the point of this door.
    #
    # THE DECLARATION IS NOT TAKEN ON TRUST, which is what makes it
    # admissible as identity at all: a pair of these legs is directly
    # admissible as the release gold kill set
    # (`gold_killset.validate_observation_pair` allows the `full-gold` role),
    # so `--reference-role gold-anything` over hand-written bytes must not be
    # two words the operator typed.  `reference_generation_evidence` checks
    # the declared role against the `adapter` stamp `runner._run_stamp` wrote
    # on every row, and the observation against the release item set -- both
    # long before Docker.  What stays on the operator's word is
    # `--reference-source-tag`, which names a reviewed local tag; that is a
    # human gate, and it is recorded as identity rather than verified here.
    #
    # No mutual-exclusion guard against an active capability, for the reason
    # `cmd_test_quality` gives: `docx_v2_workload.bind_cli` compares the whole
    # argv against the approved one before any Docker command runs, so a
    # `--reference-role` spliced into a workload-bound invocation already
    # refuses there.
    reference_role = getattr(args, "reference_role", None)
    continuation_plan_path = getattr(args, "continuation_plan", None)
    if continuation_plan_path and (reference_role != "full-gold"
                                   or args.side != "gold"):
        raise SystemExit(
            "REFUSED: --continuation-plan requires --reference-role full-gold "
            "and --side gold.")
    if _docx_v2_capability(args, "mutation-run") is None \
            and reference_role is None:
        _refuse_unbound_live_workload(
            "mutation-run execution",
            "complete-pre-execution-and-result-publication")
    if reference_role is not None:
        # The exact v5 tag rule, enforced here rather than only at the mint:
        # `mutation_run._validate_campaign_identity` requires one non-empty,
        # space-free string, and an operator who typed a two-word tag should
        # lose an argv, not a preflight.
        source_tag = getattr(args, "reference_source_tag", None)
        if not isinstance(source_tag, str) or not source_tag \
                or any(character.isspace() for character in source_tag):
            raise SystemExit(
                f"REFUSED: --reference-role requires --reference-source-tag, "
                f"ONE non-empty, space-free reviewed local tag resolving to "
                f"the source commit these control bytes were frozen at; got "
                f"{source_tag!r}. Every leg of one project's reference "
                f"observation names the same tag, and it is campaign "
                f"identity.")
        # Role and side are one fact in the v5 identity, so read the
        # expectation off the same rule rather than restating it -- and read
        # it here, where the operator loses an argv instead of a preflight.
        expected_side = ("gold" if reference_role == "full-gold"
                         else "candidate")
        if args.side != expected_side:
            raise SystemExit(
                f"REFUSED: reference role {reference_role} is collected with "
                f"--side {expected_side}, not --side {args.side}.")
        # A reference observation is the COMPLETE population; a sample, a
        # prefix, or a pair plan is a partial one under three names.
        # `gold_killset.load_native_run` refuses a sampled observation when it
        # is read, which for CoreShop's 49,168 pairs is hours after the point
        # where the argv already said so.  The candidate file can be short
        # without naming any of them, which is why
        # `reference_generation_evidence` checks the item set itself.
        partial = [name for name, value in (
            ("--sample", args.sample),
            ("--sample-seed", (None
                               if args.sample_seed
                               == MUTATION_SAMPLE_SEED_DEFAULT
                               else args.sample_seed)),
            ("--mutant-limit", args.mutant_limit),
            ("--pair-plan", getattr(args, "pair_plan", None)))
            if value is not None]
        if partial:
            raise SystemExit(
                f"REFUSED: a reference observation is the complete unsampled "
                f"population, so --reference-role cannot be combined with "
                f"{', '.join(partial)}.")
    from ..data import mutation_attestation as A
    from . import worker as W
    from .mutation_run import (MutationAborted, binding_for,
                               build_campaign_identity, candidate_digest,
                               generation_evidence_for_run,
                               coordinator_cancellation,
                               expected_pairs_for_slice,
                               operator_profile_for,
                               prepare_standalone_output_directory,
                               reference_generation_evidence, run_slice,
                               runtime_applier_sha256,
                               sha256_file, substrate_baseline_digest)
    from .runner import _load_release
    evaluation_plan = None
    try:
        if getattr(args, "reference_scope", None) is not None:
            from .evaluation_reference import plan_reference_leg
            evaluation_plan = plan_reference_leg(
                **_evaluation_reference_arguments(args, planning=True))
            assets = evaluation_plan["assets"]
        else:
            assets = _validated_mutation_assets(
                args, paid_view_subset=False, compact_allowed=False,
                algorand_bundle_version=getattr(
                    args, "algorand_bundle_version", "1"))
    except (A.MutationAssetRefused, OSError, ValueError) as e:
        raise SystemExit(str(e))
    manifest = assets["manifest"]
    by_mutant = assets["map"]["by_mutant"]
    pair_plan_path = getattr(args, "pair_plan", None)
    pair_plan_sources = (getattr(args, "run1_campaign", None),
                         getattr(args, "hard_subset", None))
    if bool(pair_plan_path) != all(bool(value)
                                   for value in pair_plan_sources):
        raise SystemExit(
            "REFUSED: --pair-plan, --run1-campaign and --hard-subset must be "
            "supplied together.")
    if not pair_plan_path and any(pair_plan_sources):
        raise SystemExit(
            "REFUSED: --run1-campaign/--hard-subset are D4 execution inputs "
            "and require --pair-plan.")
    if pair_plan_path and (args.side != "candidate" or args.sample is not None
                           or args.mutant_limit is not None):
        raise SystemExit(
            "REFUSED: D4 --pair-plan is an unsampled candidate run 2; it "
            "cannot be combined with --side gold, --sample, or "
            "--mutant-limit.")
    try:
        operator_profile = operator_profile_for(manifest["operators"])
    except (KeyError, ValueError) as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    if os.path.islink(args.candidate) or not os.path.isfile(args.candidate):
        raise SystemExit(
            f"REFUSED: mutation candidate is not a regular file: "
            f"{args.candidate}")
    spec = _worker_spec(args)
    if spec is None:
        raise SystemExit(
            "REFUSED: publishable mutation-run requires global --worker. "
            "The worker spec supplies the workspace, container, schema, "
            "credential and env-file identities that must be preflighted and "
            "locked together; --repo/--container alone cannot prove database "
            "isolation.")
    reference_partition = None
    supplement_pending = None
    allocation_path = getattr(args, "reference_allocation", None)
    host_key = getattr(args, "reference_host", None)
    supplement_plan = getattr(args, "reference_supplement_plan", None)
    if allocation_path is not None or host_key is not None or supplement_plan is not None:
        from .mutation_run import load_reference_partition, load_reference_supplement
        if (not allocation_path or not host_key or args.reference_role != "full-gold"
                or args.side != "gold" or args.sample is not None or args.mutant_limit
                or getattr(args, "continuation_plan", None)):
            raise SystemExit("REFUSED: host partitions require an unsampled full-gold reference")
        if supplement_plan is None:
            reference_partition, allocated_workers = load_reference_partition(allocation_path, host_key)
        else:
            # Owner ruling 2026-09-30: a supplement host runs only its slot of
            # the frozen plan's pending pairs, bound to that plan.
            reference_partition, allocated_workers, supplement_pending = \
                load_reference_supplement(supplement_plan, allocation_path, host_key)
        if allocated_workers != (args.mutant_of or 1):
            raise SystemExit("REFUSED: local worker count differs from frozen host allocation")
    effective_of = args.mutant_of or 1
    effective_shard = args.mutant_shard if args.mutant_of else 0
    if effective_of < 1 or not 0 <= effective_shard < effective_of:
        raise SystemExit(
            f"REFUSED: --mutant-shard {effective_shard} is not a valid "
            f"zero-based shard of --mutant-of {effective_of}.")
    pool_entries = []
    for path in args.worker_pool:
        pool_args = argparse.Namespace(worker=path)
        pool_entries.append((path, _worker_spec(pool_args)))
    pool_entries.sort(key=lambda entry: entry[1].index)
    pool_paths = [entry[0] for entry in pool_entries]
    pool_specs = [entry[1] for entry in pool_entries]
    if len(pool_specs) != effective_of \
            or [worker.index for worker in pool_specs] \
            != list(range(effective_of)):
        raise SystemExit(
            f"REFUSED: --worker-pool must name the complete zero-based pool "
            f"0..{effective_of - 1}; got "
            f"{[worker.index for worker in pool_specs]}.")
    selected = pool_specs[effective_shard]
    if selected != spec:
        raise SystemExit(
            f"REFUSED: global --worker is worker {spec.index}, but shard "
            f"{effective_shard} is assigned to {selected.to_json()} in "
            "--worker-pool. Worker assignment is campaign identity.")
    needs_database = _stack_profile(args).needs_database
    _refuse_unbound_database_runtime(
        needs_database, "database-backed mutation execution")

    # Resolve the exact candidate population and generation class before the
    # first live runtime probe.  These are immutable workload inputs, so a bad
    # reference projection or D4 binding must not contact Docker first.
    files_by_item = {}
    candidate_ids = set()
    candidate_rows = []
    with open(args.candidate, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                row = json.loads(line)
                if row["item_id"] in candidate_ids:
                    raise SystemExit(
                        f"REFUSED: {args.candidate} has duplicate item_id "
                        f"{row['item_id']!r} at line {n}; campaign candidate "
                        "bytes must not depend on last-row-wins order.")
                candidate_ids.add(row["item_id"])
                files_by_item[row["item_id"]] = row.get("produced_files") or []
                candidate_rows.append(row)
    from ..toolkit import docx_v2_workload as DW
    reference_files = DW.reference_candidate_files(
        args.candidate, candidate_rows)
    development_control = None
    pilot_control = False
    if assets["asset_project"] == "kapua" and reference_role not in (None, "full-gold"):
        from ..java import kapua_pilot as K
        pilot_control = K.is_pilot(args.release)
    if evaluation_plan is None and reference_role is not None and (
            pilot_control or assets["asset_project"] == "prestashop"
            or any("reference_derivation" in row for row in candidate_rows)
            or getattr(args, "reference_recipe", None) is not None):
        development_control = _development_reference_control(args, assets=assets)
    if reference_files is not None:
        files_by_item = reference_files
    elif reference_role is not None:
        # THE SAME PASSED-ONLY PROJECTION THE DOCX WRAPPER TAKES -- the
        # same `TQ.passed_solutions` call, in the arm the wrapper does not
        # take.  `reference_candidate_files` returns the passed-only map, but
        # only while a DOCX evidence capability is active, and no door
        # invocation has one (`bind_cli` refuses an argv the workload did not
        # approve), so the two arms are exclusive rather than agreeing twice.
        # On this route it returns None, and without this branch member 4
        # would be digested over EVERY row while
        # `reference_controls._role_check` compares it against a workload
        # binding derived from the passed solutions.  The mismatch
        # would not surface until the collected leg was read back -- hours,
        # or days for CoreShop, after the sweep that produced it.
        #
        # Passed-only is also the right set on its own terms: §3.10 counts a
        # kill only where the control's own unmutated baseline passed, so a
        # row that failed its baseline has nothing to say about a mutant.
        # The completeness check above is unaffected -- it is taken over the
        # whole run, so the observation still has to cover every released
        # item; what narrows here is only which bytes execute.
        from . import test_quality as TQ
        files_by_item = TQ.passed_solutions(candidate_rows)
    # The release this campaign is bound to, and its digest, read HERE rather
    # than just before the mint (their old position, after the live
    # preflight) so that a reference leg's completeness is decided before
    # Docker.  `_load_release` is a plain read of bytes
    # `_validated_mutation_assets` has already authenticated by SHA-256, and
    # `sha256_file` hashes the same file the mint hashes.
    items_by_id = {i["item_id"]: i for i in _load_release(args.release)}
    map_release = getattr(args, "map_release", None) or args.release
    release_sha256 = sha256_file(map_release)
    pair_plan_binding = None
    planned_pairs = None
    if pair_plan_path:
        from . import test_quality as TQ
        try:
            pair_plan_binding = TQ.validate_d4_confirmation_plan(
                pair_plan_path, run1_campaign=args.run1_campaign,
                hard_subset_path=args.hard_subset,
                candidate_run_path=args.candidate, assets=assets,
                validation_path=args.mutation_validation,
                manifest_path=args.manifest, map_path=args.map,
                release_path=args.release)
        except (TQ.TestQualityRefused, OSError, ValueError) as exc:
            raise SystemExit(str(exc)) from exc
        if pair_plan_binding["timeout_seconds"] != args.timeout:
            raise SystemExit(
                "REFUSED: D4 run 2 timeout differs from run 1 "
                f"({args.timeout} != "
                f"{pair_plan_binding['timeout_seconds']}).")
        # `test-quality` run 1 scores PASSED rows only.  Preserve that exact
        # generated-test identity here; keeping failed rows in the digest
        # would make a byte-identical candidate look like a different one.
        files_by_item = pair_plan_binding["candidate_files"]

    # Only mutants at least one SCORED item covers, in manifest order so a
    # slice is a prefix and two slices of the same size are the same slice.
    eligible = [m for m in manifest["mutants"]
                if any(i in files_by_item for i in by_mutant.get(m["id"], []))]
    if args.sample:
        # A seeded sample, recorded, because the whole covered population is
        # 2,741 mutants / 49,553 pairs = 19.8 h at K=4 per candidate. §3.11
        # provides for sampling precisely so a gate can be affordable and
        # still say exactly which mutants it ran.
        import random
        random.Random(args.sample_seed).shuffle(eligible)
        eligible = sorted(eligible[:args.sample],
                          key=lambda m: (m["file"], m["start_line"], m["id"]))
    if pair_plan_binding is not None:
        partitions = TQ.shard_d4_confirmation_pairs(
            pair_plan_binding["pairs"], effective_of)
        empty = [number for number, values in enumerate(partitions)
                 if not values]
        if empty:
            raise SystemExit(
                "REFUSED: D4 pair plan has fewer independently applicable "
                f"mutant groups than --mutant-of {effective_of}; empty "
                f"shard(s) would be {empty}. Use fewer workers.")
        planned_pairs = partitions[effective_shard]
        planned_mutants = {mutant_id for _item_id, mutant_id in planned_pairs}
        eligible = [mutant for mutant in eligible
                    if mutant["id"] in planned_mutants]
        natural = expected_pairs_for_slice(eligible, by_mutant, files_by_item)
        outside = sorted(planned_pairs - natural)
        if outside:
            raise SystemExit(
                "REFUSED: D4 pair plan contains pair(s) outside the unchanged "
                f"candidate/map population, e.g. {outside[:3]}.")
    elif continuation_plan_path:
        from . import mutation_continuation as MC
        try:
            continuation_binding = MC.validate_plan(continuation_plan_path)
            if len(continuation_binding["partitions"]) != effective_of:
                raise MutationAborted(
                    "REFUSED: --mutant-of differs from continuation plan worker count")
            planned_pairs = set(continuation_binding["partitions"][effective_shard])
            natural = expected_pairs_for_slice(eligible, by_mutant, files_by_item)
            if not planned_pairs or not planned_pairs <= natural:
                raise MutationAborted(
                    "REFUSED: continuation shard is empty or outside the unchanged "
                    "candidate/map population")
        except (MutationAborted, OSError, ValueError) as exc:
            raise SystemExit(str(exc)) from exc
        planned_mutants = {mutant_id for _item_id, mutant_id in planned_pairs}
        eligible = [mutant for mutant in eligible
                    if mutant["id"] in planned_mutants]
    elif reference_partition is not None:
        from .mutation_run import reference_shard_pairs, reference_slot_indices
        slot_pairs = by_mutant if supplement_pending is None else supplement_pending
        if supplement_pending is not None:
            eligible = [m for m in eligible if supplement_pending.get(m["id"])]
        if reference_partition.get("pair_slots"):
            # A pair-slot supplement (full282 section 5, fourth supplement)
            # runs single pending pairs, possibly a few of many mutants.
            planned_pairs = reference_shard_pairs(
                {"mutants": eligible}, supplement_pending, reference_partition,
                effective_of)[effective_shard]
            planned_mutants = {mutant for _item, mutant in planned_pairs}
            eligible = [m for m in eligible if m["id"] in planned_mutants]
        else:
            slot = reference_slot_indices(
                [len(set(slot_pairs[m["id"]])) for m in eligible],
                reference_partition)[reference_partition["offset"] + effective_shard]
            eligible = [eligible[index] for index in slot]
        if supplement_pending is not None:
            if not reference_partition.get("pair_slots"):
                planned_pairs = {(item, m["id"]) for m in eligible
                                 for item in supplement_pending[m["id"]]}
            natural = expected_pairs_for_slice(eligible, by_mutant, files_by_item)
            if not planned_pairs or not planned_pairs <= natural:
                raise SystemExit(
                    "REFUSED: supplement shard is empty or outside the unchanged "
                    "candidate/map population")
    elif args.mutant_of:
        # Strided, not contiguous. Items-per-mutant is skewed (median 3, mean
        # 18.1, max 100), so contiguous blocks would hand one worker most of
        # the wide mutants and the wall would be that worker.
        eligible = eligible[args.mutant_shard::args.mutant_of]
    if args.mutant_limit:
        eligible = eligible[:args.mutant_limit]
    expected = (set(planned_pairs) if planned_pairs is not None
                else expected_pairs_for_slice(
                    eligible, by_mutant, files_by_item))
    # WHICH GENERATION ATTEMPT produced these candidate bytes (PR R3).  Read
    # from the candidate's own evidence — its v2 campaign sidecar, or the
    # registered legacy_exact_bytes entry the owner ruled on — and refused
    # when it has neither, because an unlabelled candidate is exactly the
    # state report §8.4 could not decide from.
    #
    # A REFERENCE LEG has exact submitted bytes and no generation attempt at
    # all, so there is nothing here to RESOLVE -- but the role the operator
    # declared is still checked against what the harness itself stamped on
    # every row, and the observation against the release it claims to cover.
    # Both of those refusals land here, still ahead of the live preflight
    # below that is this verb's first Docker contact.
    try:
        if evaluation_plan is not None:
            generation = dict(evaluation_plan["generation"])
            if files_by_item != evaluation_plan["files_by_item"]:
                raise MutationAborted("REFUSED: control inputs changed after reference planning")
        elif reference_role is not None:
            generation = reference_generation_evidence(
                role=reference_role,
                source_tag=args.reference_source_tag,
                candidate_rows=candidate_rows,
                release_item_ids=items_by_id,
                release_sha256=release_sha256,
                asset_index_sha256=assets["asset_index_sha256"], control=development_control)
        else:
            generation = generation_evidence_for_run(args.candidate,
                                                     candidate_rows)
    except MutationAborted as e:
        raise SystemExit(str(e))
    legacy = generation.pop("legacy_generation_evidence", None)
    if legacy is not None and candidate_digest(files_by_item) \
            != legacy["candidate_generated_tests_sha256"]:
        raise SystemExit(
            "REFUSED: registered legacy_exact_bytes generated-test identity "
            "differs from the passed-only candidate map; no Docker command "
            "was run.")
    # Other standalone shard processes may already be mutating their own
    # workers. Authenticate source bytes only on this shard's assigned worker;
    # the complete pool's runtime identity is still validated below.
    java_analysis_root = _mutation_java_analysis_root(
        args, manifest, [spec.workspace])
    answer_paths = W.default_answer_paths(
        args.gold, args.artifacts, os.path.join(args.artifacts, "release"))
    if java_analysis_root is not None:
        answer_paths.append(java_analysis_root)
    answer_paths.extend([
        args.candidate, args.manifest, args.map, args.release,
        args.mutation_validation, args.out,
        *pool_paths,
        *(W.runtime_attestation_path(path) for path in pool_paths),
        *(W.binding_attestation_path(path) for path in pool_paths),
        *(filter(None, (pair_plan_path, continuation_plan_path, *pair_plan_sources))),
    ])
    if allocation_path:
        answer_paths.append(allocation_path)
    continuation_containment = []
    if continuation_plan_path:
        answer_paths.extend(continuation_binding["protected_paths"])
        continuation_containment = continuation_binding.get("containment_paths", [])
    answer_paths.extend(getattr(args, "_publication_protected_paths", ()))
    if evaluation_plan is not None or development_control is not None:
        answer_paths.extend(_evaluation_protected_paths(args))
    if development_control is not None:
        answer_paths.extend(development_control.get("source_paths", {}).values())
    try:
        from .validate import HARNESS_VERSION
        W.preflight(pool_specs, answer_paths, containment_paths=continuation_containment, live=False,
                    needs_database=needs_database)
        runtime = W.validate_mutation_runtime(
            pool_paths, pool_specs, args.seed, HARNESS_VERSION,
            needs_database, project=assets["asset_project"])
        W.preflight(
            pool_specs, answer_paths,
            containment_paths=[*runtime["protected_evidence_paths"], *continuation_containment], live=True,
            needs_database=needs_database, behat=_behat_row(args))
    except W.WorkerRefused as e:
        raise SystemExit(str(e))
    resource_identities = [
        (field, getattr(spec, field))
        for field in W.resource_fields(needs_database)
        if getattr(spec, field)
    ]
    h, _b, _man = _harness(args)
    # `--seed` was verified against every worker's runtime just above.
    derived = _derived_baseline(args, args.seed)
    if derived:
        h.derived_baseline = derived
    # Which program materialises these mutants is decided by the MANIFEST's
    # engine, not by a flag and not by this file's stack: the ids hash the
    # engine, so the applier that can re-enumerate them is a property of the
    # population being executed.  CoreShop manifests name `r2t-mutate` and
    # resolve to exactly the php/mutate.php pair that produced every archived
    # row.
    engine_dir, applier = binding_for(manifest["engine"])
    stack = _stack(args)
    stack_dir = getattr(stack, "engine_dir", None)
    if stack_dir is not None and stack_dir != engine_dir:
        raise SystemExit(
            f"REFUSED: the manifest's mutants were minted by "
            f"{manifest.get('engine')!r} (applier in {engine_dir}), but "
            f"--profile routes mutation-run to the {stack.FRAMEWORK} stack "
            f"(engine dir {stack_dir}). One of them names the wrong "
            "project; no mutant was executed.")
    try:
        identity = build_campaign_identity(
            **generation,
            asset_index_sha256=assets["asset_index_sha256"],
            asset_project=assets["asset_project"],
            mutation_validation_sha256=assets["validation_sha256"],
            mutation_validation_class=assets["validation_class"],
            manifest_sha256=sha256_file(args.manifest),
            manifest_digest=manifest.get("digest"),
            map_sha256=sha256_file(args.map),
            release_sha256=release_sha256,
            candidate_run_sha256=sha256_file(args.candidate),
            candidate_generated_tests_sha256=candidate_digest(files_by_item),
            solution_generated_tests_sha256=candidate_digest(files_by_item),
            substrate_baseline_sha256=substrate_baseline_digest(h),
            worker_resources_sha256=runtime["worker_resources_sha256"],
            harness_version=runtime["harness_version"],
            container_image_digest=runtime["container_image_digest"],
            workspace_seed_digest=runtime["workspace_seed_digest"],
            database_dump_digest=runtime["database_dump_digest"],
            applier_sha256=runtime_applier_sha256(manifest["engine"], args.seed),
            expected_pairs=expected, engine=manifest["engine"],
            engine_version=manifest["engine_version"],
            parser=manifest["parser"], side=args.side,
            shard=effective_shard,
            of=effective_of, timeout=args.timeout, sample=args.sample,
            sample_seed=(args.sample_seed if args.sample is not None
                         else None),
            # Absent unless the assets carried a budgeted basis, so a
            # full-population leg's identity is exactly what it was.
            population_basis=assets.get("population_basis"),
            budgeted_sample_sha256=assets.get("budgeted_sample_sha256"),
            parent_map_sha256=assets.get("parent_map_sha256"))
        if reference_partition is not None:
            identity["reference_partition"] = reference_partition
        if continuation_plan_path:
            identity = MC.validate_identity(continuation_binding, identity)
        prepare_standalone_output_directory(
            args.out, identity)
        provenance = {
            "mutation_validation": os.path.abspath(args.mutation_validation),
            "manifest": os.path.abspath(args.manifest),
            "manifest_digest": manifest["digest"],
            "engine": manifest["engine"],
            "engine_version": manifest["engine_version"],
            "parser": manifest["parser"],
            "map": os.path.abspath(args.map),
            "candidate": os.path.abspath(args.candidate),
            "release": os.path.abspath(map_release),
            "seed": os.path.abspath(args.seed),
            "side": args.side,
            "sample": args.sample,
            "sample_seed": args.sample_seed,
            "mutant_shard": args.mutant_shard,
            "mutant_of": args.mutant_of,
            **({
                "d4_confirmation_plan": os.path.abspath(pair_plan_path),
                "d4_confirmation_plan_sha256": sha256_file(pair_plan_path),
                "d4_confirmation_plan_digest": pair_plan_binding[
                    "plan"]["digest"],
                "d4_run_1_campaign": os.path.abspath(args.run1_campaign),
                "d4_run_1_observation_id": pair_plan_binding[
                    "run_1_observation_id"],
                "d4_hard_subset": os.path.abspath(args.hard_subset),
                "d4_pair_shard_policy": TQ.D4_PAIR_SHARD_POLICY,
            } if pair_plan_binding is not None else {}),
            **({"continuation_plan": os.path.abspath(continuation_plan_path)}
               if continuation_plan_path else {}),
            "worker_resources": runtime["worker_resources"],
            "harness_version": runtime["harness_version"],
            "container_image_digest": runtime["container_image_digest"],
            "workspace_seed_digest": runtime["workspace_seed_digest"],
            "database_dump_digest": runtime["database_dump_digest"],
        }
        if development_control is not None:
            provenance["reference_control_sources"] = {
                **(development_control.get("source_paths") or
                   {key: os.path.abspath(getattr(args, name))
                    for key, name in _DEVELOPMENT_REFERENCE_SOURCES.items()}),
                "baseline_producer_tag": development_control["reference_source_tag"],
                "reference_freeze_tag": args.reference_source_tag,
            }
        with coordinator_cancellation() as cancel_event:
            run_options = {
                "timeout": args.timeout, "applier": applier,
                "operator_profile": operator_profile,
                "engine": manifest["engine"],
                "engine_version": manifest["engine_version"],
                "resume": getattr(args, "resume", False),
                "cancel_event": cancel_event,
                "resource_identities": resource_identities,
                "provenance": provenance,
            }
            if continuation_plan_path:
                run_options["continuation_plan_path"] = continuation_plan_path
            info = run_slice(
                h, eligible, items_by_id, files_by_item, by_mutant,
                engine_dir, args.out, identity=identity,
                manifest=manifest, planned_pairs=planned_pairs,
                java_analysis_root=java_analysis_root, **run_options)
    except MutationAborted as e:
        raise SystemExit(str(e))
    info["eligible_mutants"] = len(eligible)
    info["manifest_digest"] = manifest["digest"]
    print(json.dumps(info, indent=1))
    return 0


def cmd_recall(args) -> int:
    """Score a mutation slice — baseline-pass eligibility, macro average."""
    from ..data.mutation import (classify_outcome, nondeterministic_mutants,
                                 recall)
    from .mutation_run import (MutationAborted, candidate_digest, sha256_file,
                               validate_campaign_asset_claims,
                               validate_native_shards)
    result_paths = ([args.results] if isinstance(args.results, str)
                    else list(args.results))
    gold_result_paths = ([args.gold_results]
                         if isinstance(args.gold_results, str)
                         else list(args.gold_results))
    native_assets = None
    legacy_inputs = None
    if args.legacy_consistency:
        if len(result_paths) != 1 or len(gold_result_paths) != 1:
            raise SystemExit(
                "REFUSED: one legacy_consistency report binds one preserved "
                "candidate result and one gold result file, not shard lists.")
        from ..data import mutation_attestation as A
        try:
            legacy_inputs = A.load_validated_legacy_scoring_inputs(
                args.legacy_consistency, require_release_ready=True)
            report = legacy_inputs["report"]
            supplied_gold_baseline = args.gold_baseline or args.baseline
            for key, path in (
                    ("candidate_run", args.baseline),
                    ("gold_baseline", supplied_gold_baseline),
                    ("candidate_results", result_paths[0]),
                    ("gold_results", gold_result_paths[0])):
                wanted = report["inputs"][key]["sha256"]
                A.validate_preserved_file(
                    path, wanted, f"recall legacy {key}")
        except (A.MutationAssetRefused, OSError, ValueError, KeyError) as e:
            raise SystemExit(str(e))
        baseline_rows = legacy_inputs["candidate_run_rows"]
        gold_baseline_rows = legacy_inputs["gold_baseline_rows"]
        results = legacy_inputs["candidate_result_rows"]
        gold_result_rows = legacy_inputs["gold_result_rows"]
        evidence_class = "legacy_consistency"
    else:
        baseline_rows = []
        with open(args.baseline, encoding="utf-8") as fh:
            baseline_rows = [json.loads(line) for line in fh if line.strip()]
        from ..data import mutation_attestation as A
        from .mutation_run import validate_candidate_gold_campaign_pair
        try:
            candidate_campaign = validate_native_shards(
                result_paths, required_side="candidate",
                return_campaign=True)
            gold_campaign = validate_native_shards(
                gold_result_paths, required_side="gold",
                return_campaign=True)
            validate_candidate_gold_campaign_pair(
                candidate_campaign["campaign_identity"],
                gold_campaign["campaign_identity"])
            if not args.require_complete:
                raise MutationAborted(
                    "REFUSED: native recall requires --require-complete so "
                    "both candidate and gold are checked against the frozen "
                    "manifest/map population. Use test-quality "
                    "--allow-incomplete for an explicitly labelled "
                    "sensitivity analysis.")
            missing_assets = [name for name in (
                "mutation_validation", "manifest", "map", "release")
                if not getattr(args, name, None)]
            if missing_assets:
                raise MutationAborted(
                    f"REFUSED: native recall needs frozen asset input(s) "
                    f"{missing_assets} to prove its complete denominator.")
            # Slice-3 bound observations score a PAID VIEW of the population
            # the map was built over; every other native campaign hands that
            # population itself.  The durable image of the Slice-3 launch
            # former capability's durable image is the bound-job identity: a
            # v4 `mutation-run` campaign carrying its
            # minted observation_id.  Historical v1/v2/v3 and reference-
            # control v5 identities have no such field, so this is False for
            # every population-handing caller -- and the subset path itself
            # collapses to the strict default when the handed release is
            # byte-equal to the report's pinned population.
            bound_observation_pair = all(
                campaign["campaign_identity"].get("kind") == "mutation-run"
                and campaign["campaign_identity"].get("observation_id")
                is not None
                for campaign in (candidate_campaign, gold_campaign))
            native_assets = _validated_mutation_assets(
                args, paid_view_subset=bound_observation_pair,
                compact_allowed=bound_observation_pair,
                algorand_bundle_version=getattr(
                    args, "algorand_bundle_version", "1"))
            for campaign in (candidate_campaign, gold_campaign):
                validate_campaign_asset_claims(
                    campaign["campaign_identity"], native_assets,
                    validation_path=args.mutation_validation,
                    manifest_path=args.manifest, map_path=args.map,
                    release_path=args.release)
            results = candidate_campaign["rows"]
            gold_result_rows = gold_campaign["rows"]
        except (MutationAborted, A.MutationAssetRefused, OSError,
                ValueError) as e:
            raise SystemExit(str(e))
        evidence_class = "native"

    baseline = {}
    candidate_files = {}
    for number, row in enumerate(baseline_rows, 1):
        iid = row.get("item_id")
        if not isinstance(iid, str) or not iid or iid in baseline:
            raise SystemExit(
                f"REFUSED: {evidence_class} candidate baseline has missing "
                f"or duplicate item_id {iid!r} at row {number}.")
        baseline[iid] = row.get("outcome")
        candidate_files[iid] = row.get("produced_files") or []
    if evidence_class == "native":
        candidate_generated = candidate_digest(candidate_files)
        candidate_identity = candidate_campaign["campaign_identity"]
        candidate_binding_changes = sorted(key for key, wanted in {
            "candidate_run_sha256": sha256_file(args.baseline),
            "candidate_generated_tests_sha256": candidate_generated,
            "solution_generated_tests_sha256": candidate_generated,
        }.items() if candidate_identity.get(key) != wanted)
        if candidate_binding_changes:
            raise SystemExit(
                f"REFUSED: candidate native mutation shards differ from "
                f"their supplied baseline/generated-test bytes in field(s) "
                f"{candidate_binding_changes}.")
    # The POPULATION is production mutants. Rows for test-scaffolding mutants
    # are dropped here as well as excluded from new manifests, so a campaign
    # run before that exclusion existed still scores correctly.
    from ..core.boundary import PRODUCTION
    from ..data.mutation import normalise_path
    # Native campaigns already consume the PR-2-validated boundary-scored
    # manifest.  Applying the caller's global --boundary again would permit a
    # different policy to drop hard mutants from candidate, gold and the
    # reconstructed expectation together.  Only historical pre-boundary rows
    # retain the compatibility filter their legacy report explicitly audits.
    # That filter classifies by PRODUCTION alone and does NOT read
    # `behat.mutation_exclude`: the rows it filters are CoreShop's, whose
    # boundary declares no such row, and a project that did declare one would
    # keep rows its scored manifest excludes -- caught downstream, because the
    # population those rows are scored against is the scored manifest itself.
    b_ = (legacy_inputs["boundary"]
          if evidence_class == "legacy_consistency" else None)
    if b_ is not None:
        n_before = len(results)
        results = [r for r in results
                   if b_.classify(normalise_path(r.get("file", "")))
                   == PRODUCTION]
        n_non_production = n_before - len(results)
    else:
        n_non_production = 0
    # A gold KILL is not merely "gold's mutated run failed": §3.10 requires
    # the killer's own baseline to have passed, or a gold item that was
    # already broken would contribute mutants to the population that nothing
    # could have killed for the right reason.  Gold passes everywhere today,
    # which is exactly why deriving this naively would go unnoticed until the
    # day it does not.
    gold_baseline = {}
    src = (legacy_inputs["paths"]["gold_baseline"]
           if evidence_class == "legacy_consistency"
           else (args.gold_baseline or args.baseline))
    if evidence_class == "native":
        gold_baseline_rows = []
        with open(src, encoding="utf-8") as fh:
            gold_baseline_rows = [json.loads(line) for line in fh
                                  if line.strip()]
    gold_files = {}
    for number, row in enumerate(gold_baseline_rows, 1):
        iid = row.get("item_id")
        if not isinstance(iid, str) or not iid or iid in gold_baseline:
            raise SystemExit(
                f"REFUSED: {evidence_class} gold baseline has missing or "
                f"duplicate item_id {iid!r} at row {number}.")
        gold_baseline[iid] = row.get("outcome")
        gold_files[iid] = row.get("produced_files") or []
    if evidence_class == "native":
        gold_generated = candidate_digest(gold_files)
        gold_identity = gold_campaign["campaign_identity"]
        gold_binding_changes = sorted(key for key, wanted in {
            "candidate_run_sha256": sha256_file(src),
            "candidate_generated_tests_sha256": gold_generated,
            "solution_generated_tests_sha256": gold_generated,
        }.items() if gold_identity.get(key) != wanted)
        if gold_binding_changes:
            raise SystemExit(
                f"REFUSED: gold native mutation shards differ from their "
                f"supplied baseline/generated-test bytes in field(s) "
                f"{gold_binding_changes}.")
    # Validate the closed vocabulary even on a historical row later removed
    # by the compatibility boundary filter.  Unknown labels cannot silently
    # shrink gold's reference kill set.
    for row in gold_result_rows:
        classify_outcome(gold_baseline.get(row.get("item_id")),
                         row.get("outcome"))
    scored_gold_rows = gold_result_rows
    if b_ is not None:
        scored_gold_rows = [
            row for row in gold_result_rows
            if b_.classify(normalise_path(row.get("file", ""))) == PRODUCTION]
    from .test_quality import gold_infrastructure_pairs, gold_kill_sets
    gold_killed, ignored, gold_infrastructure = gold_kill_sets(
        scored_gold_rows, gold_baseline, baseline)
    # Ruling 2.6: the count and a PER-ITEM disclosure travel together wherever
    # the number appears, and this verb prints the number.
    gold_infrastructure_detail = gold_infrastructure_pairs(
        scored_gold_rows, gold_baseline, baseline)
    expected_pairs = None
    if args.require_complete or evidence_class == "legacy_consistency":
        # Derived from the SAMPLE, not from the results.
        #
        # Deriving it from the mutants that happen to appear would check
        # completeness only within the shards that ran — a shard that never
        # started, or whose out file was lost, would pass. That is the same
        # false comfort this flag exists to remove, so the expectation is
        # rebuilt from the manifest and the sample parameters the campaign
        # declared, exactly as `mutation-run` slices them.
        import random
        if evidence_class == "legacy_consistency":
            manifest = legacy_inputs["manifest"]
            by_mutant = legacy_inputs["map"]["by_mutant"]
            expected_pairs = set(legacy_inputs["expected_pairs"])
            expected_mutant_ids = {pair[1] for pair in expected_pairs}
            eligible = [
                mutant for mutant in manifest["mutants"]
                if mutant["id"] in expected_mutant_ids]
        elif not (args.manifest and args.map):
            raise SystemExit(
                "REFUSED: --require-complete needs --manifest and --map to "
                "rebuild what the campaign was supposed to execute.")
        elif native_assets is not None:
            manifest = native_assets["manifest"]
            by_mutant = native_assets["map"]["by_mutant"]
        else:
            with open(args.manifest, encoding="utf-8") as fh:
                manifest = json.load(fh)
            with open(args.map, encoding="utf-8") as fh:
                by_mutant = json.load(fh)["by_mutant"]
        if evidence_class != "legacy_consistency":
            eligible = [m for m in manifest["mutants"]
                        if any(i in baseline
                               for i in by_mutant.get(m["id"], []))]
            if args.sample:
                random.Random(args.sample_seed).shuffle(eligible)
                eligible = sorted(
                    eligible[:args.sample],
                    key=lambda m: (m["file"], m["start_line"], m["id"]))
            # The SAME production filter the results pass through above.  The
            # scored set drops test-scaffolding mutants (a manifest built
            # before the exclusion still carries them, e.g. TestBundle hooks
            # that every item covers), so an expectation built without the
            # filter demands pairs the scoring is defined to ignore — and the
            # completeness gate then refuses a campaign that is in fact
            # complete. Sampling happens BEFORE this filter because the
            # campaign sampled the unfiltered eligible list; filtering first
            # would rebuild a different sample.
            expected_pairs = {
                (i, m["id"]) for m in eligible
                if (b_ is None
                    or b_.classify(normalise_path(m["file"])) == PRODUCTION)
                for i in by_mutant.get(m["id"], []) if i in baseline}
        print(f"  completeness: expecting {len(expected_pairs)} (item, mutant) "
              f"executions over {len(eligible)} mutants")
        for label, rows in (("candidate", results),
                            ("gold", gold_result_rows)):
            pairs = [(row.get("item_id"), row.get("mutant_id"))
                     for row in rows
                     if (b_ is None or b_.classify(normalise_path(
                         row.get("file", ""))) == PRODUCTION)]
            if len(pairs) != len(set(pairs)) or set(pairs) != expected_pairs:
                raise SystemExit(
                    f"REFUSED: {label} mutation evidence is not the exact "
                    f"complete population: {len(expected_pairs-set(pairs))} "
                    f"missing and {len(set(pairs)-expected_pairs)} unexpected "
                    "pair(s), or duplicates are present.")
    # Harness 25 (correction D): a nondeterministic mutant's pairs leave G_i,
    # the candidate's rows and the completeness expectation before scoring.
    unscored = nondeterministic_mutants()
    gold_killed = {iid: mutants - unscored for iid, mutants in gold_killed.items()}
    results = [row for row in results if row.get("mutant_id") not in unscored]
    if expected_pairs is not None:
        expected_pairs = {pair for pair in expected_pairs
                          if pair[1] not in unscored}
    out = recall(baseline, results, gold_killed, expected_pairs=expected_pairs)
    out["gold_kills_ignored_ineligible_baseline"] = ignored
    out["gold_infrastructure_outcomes"] = gold_infrastructure
    out["gold_infrastructure_pairs"] = gold_infrastructure_detail
    out["rows_dropped_non_production"] = n_non_production
    out["mutation_evidence_class"] = evidence_class
    out["per_item"] = {k: v for k, v in sorted(out["per_item"].items())[:5]}
    print(json.dumps(out, indent=1, default=list))
    return 0


def _cmd_test_quality_slice3(args) -> int:
    """Score a published Slice-3 cell from its preserved mutation evidence.

    SLICE3_TEST_QUALITY_SPEC.md §2: run 1 (and run 2 where the D4 rule
    demanded one) already executed inside the frozen Java20 seam; what
    happens here is classification under the frozen hard-pair basis and the
    standard sidecar write.  No Docker, no worker pool, no execution.
    """
    from . import slice3_test_quality as S3Q
    from . import test_quality as TQ
    if not (args.slice3_observations and args.slice3_bundle):
        raise SystemExit(
            "REFUSED: the Slice-3 join needs both --slice3-observations "
            "and --slice3-bundle.")
    try:
        if not args.no_sidecar:
            existing = TQ.find_sidecar(args.run)
            if existing:
                raise SystemExit(
                    f"REFUSED: {args.run} already has test-quality sidecar "
                    f"{existing}; this command will not overwrite a "
                    "published binding. Preserve it and use a new candidate "
                    "run.")
        summary = S3Q.build_summary(
            args.run, observations_dir=args.slice3_observations,
            bundle_path=args.slice3_bundle)
        S3Q.print_summary(summary)
        if not args.no_sidecar:
            print(f"\nsidecar: {TQ.write_sidecar(summary, args.run)}")
    except (OSError, ValueError) as e:
        raise SystemExit(str(e))
    return 0


#: Every option that means something the single-observation policy does not
#: have: another gold source, another verdict denominator, a short campaign,
#: or a capped one.  `run_test_quality` refuses each of them anyway -- but
#: only after the worker preflight, and CoreShop's candidate sweep is days.
SINGLE_OBSERVATION_INCOMPATIBLE = (
    ("--gold-results", "gold_results"),
    ("--gold-results-attestation", "gold_results_attestation"),
    ("--hard-subset", "hard_subset"),
    ("--candidate-hard-rerun", "candidate_hard_rerun"),
    ("--candidate-hard-plan", "candidate_hard_plan"),
    ("--candidate-hard-plan-out", "candidate_hard_plan_out"),
    ("--allow-incomplete", "allow_incomplete"),
    ("--allow-degraded-gold", "allow_degraded_gold"),
    ("--compute-cap-seconds", "compute_cap_seconds"),
    ("--compute-cap-review-authority", "compute_cap_review_authority"),
    ("--gold-pair-plan", "gold_pair_plan"),
)


def _single_observation_execution(out_dir: str, *, resume: bool) -> dict:
    """Bind one scalar candidate observation; --resume recovers the root's.

    `run_test_quality` requires both fields and neither has a CLI surface:
    an observation identity is not something an operator types, and a second
    run that reused the first one's would make two physical observations
    indistinguishable.
    """
    from . import test_quality as TQ
    from .mutation_run import EXECUTION_POLICY_SCALAR_V1

    if not resume:
        return {"execution_policy": EXECUTION_POLICY_SCALAR_V1,
                "execution_observation_id": secrets.token_hex(16)}
    try:
        state = TQ._load_json_object(
            TQ._campaign_state_path(out_dir),
            "resumed reference-scored root campaign")
        plan = state.get("plan") if isinstance(state, dict) else None
        TQ._validate_campaign_state(state, plan)
        jobs = plan.get("jobs") if isinstance(plan, dict) else None
        first = (jobs[0].get("campaign_identity")
                 if isinstance(jobs, list) and jobs
                 and isinstance(jobs[0], dict) else None)
        saved = TQ._v4_execution_kwargs(first or {})
    except (TQ.TestQualityRefused, OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    if saved.get("execution_policy") != EXECUTION_POLICY_SCALAR_V1 \
            or not saved.get("observation_id"):
        raise SystemExit(
            "REFUSED: the root campaign in --out is not a resumable scalar "
            "single-observation candidate campaign; it names no scalar "
            "execution policy or no observation identity.")
    return {"execution_policy": EXECUTION_POLICY_SCALAR_V1,
            "execution_observation_id": saved["observation_id"]}


def cmd_test_quality(args, *, before_execute=None) -> int:
    """Per-solution anti-vacuity: is each PASS also a TEST? (§3.10)

    The corpus gate (`stub-accept` + `recall`) establishes that the benchmark
    can tell a test from a no-op.  This establishes it for the items a
    particular candidate actually passed, which is a different claim and the
    one a results table needs — the two eval100 passes both fall outside the
    sampled gate population, so the gate says nothing whatever about them.

    Everything here is assembly.  The population comes from `mutation`, the
    execution from `mutation_run.run_slice`, the scoring from
    `mutation.recall`; what this adds is that the right thing is now one
    command instead of a day of hand-driven shards.
    """
    sensitivity = getattr(args, "sensitivity", None)
    # A label of `reference_controls.SENSITIVITY_PROJECTS` names a basis of
    # the installed reference (SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md
    # section 5), not a harness overlay its run rows carry: the rows stay
    # unlabelled, so the run-label checks below see no label.
    reference_sensitivity = _sensitivity_arguments(args)
    if reference_sensitivity is not None:
        sensitivity = None
        if getattr(args, "reference_controls", None) is None \
                or getattr(args, "reference_scope", None) is None \
                or getattr(args, "reference_attestation", None) is not None \
                or not getattr(args, "development", False):
            raise SystemExit(
                "REFUSED: --sensitivity scores a --development candidate "
                "against --reference-scope/--reference-controls in place of "
                "--reference-attestation.")
    if sensitivity is not None:
        # E_PETITIONS_WEBMOCK_MUTATION_AMENDMENT.md: a labelled post-hoc
        # sensitivity is scored on the plain development route only, and
        # never as a publication or reference-scored campaign.  Gold is
        # observed in the campaign under the same overlay, never copied in.
        routes = [option for option, attr in (
            ("--gold-results", "gold_results"),
            ("--slice3-observations", "slice3_observations"),
            ("--slice3-bundle", "slice3_bundle"),
            ("--reference-controls", "reference_controls"),
            ("--kapua-reference-evidence", "kapua_reference_evidence"),
            ("--prestashop-reference-evidence",
             "prestashop_reference_evidence"),
            ("--compute-cap-seconds", "compute_cap_seconds"))
            if getattr(args, attr, None)]
        if not getattr(args, "development", False) or routes:
            raise SystemExit(
                "REFUSED: --sensitivity scores a labelled post-hoc "
                "sensitivity only on the plain --development route; "
                f"incompatible: {routes or ['missing --development']}")
    # getattr, not attribute access: docx/worker selftests drive this verb
    # with fixture namespaces that predate the two Slice-3 options.
    if getattr(args, "slice3_observations", None) \
            or getattr(args, "slice3_bundle", None):
        reference_options = ["--" + name.replace("_", "-")
                             for name, value in vars(args).items()
                             if value is not None and (name.startswith("reference_")
                                 or name in {"validation_inputs", "input_root", "map_release",
                                             "budgeted_sidecar", "prestashop_reference_evidence",
                                             "prestashop_task_items"})]
        if getattr(args, "candidate_pairs", "all") != "all":
            reference_options.append("--candidate-pairs")
        if reference_options:
            raise SystemExit("REFUSED: Slice-3 preserved scoring is incompatible with "
                             + ", ".join(reference_options))
        # SLICE3_TEST_QUALITY_SPEC.md §2: a Docker-free read-only join over
        # preserved Slice-3 evidence, not a live workload — the docx-v2
        # capability gate below guards only the live execution path.
        return _cmd_test_quality_slice3(args)
    kapua_evidence = getattr(args, "kapua_reference_evidence", None)
    prestashop_evidence = getattr(args, "prestashop_reference_evidence", None)
    if kapua_evidence is not None and prestashop_evidence is not None:
        raise SystemExit("REFUSED: name only one project's development reference evidence")
    if prestashop_evidence is not None:
        needed = ("prestashop_task_items", "budgeted_sidecar", "release")
        missing = ["--" + key.replace("_", "-") for key in needed
                   if not getattr(args, key, None)]
        if missing:
            raise SystemExit("REFUSED: --prestashop-reference-evidence requires " + ", ".join(missing))
        if getattr(args, "gold_pair_plan", None) is not None \
                or getattr(args, "candidate_pairs", "all") != "all":
            raise SystemExit("REFUSED: no PrestaShop amendment adopts --candidate-pairs "
                             "gold-killed or --gold-pair-plan; PrestaShop evidence scores "
                             "every pair")
        kapua_evidence = prestashop_evidence
    elif getattr(args, "prestashop_task_items", None) is not None:
        raise SystemExit("REFUSED: --prestashop-task-items requires --prestashop-reference-evidence")
    if kapua_evidence is not None:
        incompatible = ("gold_results", "gold_results_attestation", "reference_controls",
                        "reference_attestation", "reference_scope", "hard_subset",
                        "candidate_hard_rerun", "candidate_hard_plan", "candidate_hard_plan_out",
                        "compute_cap_seconds", "compute_cap_review_authority", "map_release")
        conflicts = [name for name in incompatible if getattr(args, name, None)]
        if not getattr(args, "development", False) or conflicts:
            raise SystemExit("REFUSED: project reference evidence requires ordinary --development "
                             "full-gold scoring; incompatible inputs: " + str(conflicts))
    reference_root = getattr(args, "reference_controls", None)
    reference_attestation = getattr(args, "reference_attestation", None)
    _refuse_unscoped_evaluation_sources(args)
    if getattr(args, "reference_scope", None) is not None and reference_root is None:
        raise SystemExit("REFUSED: evaluation scoring requires --reference-controls and --reference-attestation")
    if reference_sensitivity is None \
            and (reference_root is None) != (reference_attestation is None):
        raise SystemExit(
            "REFUSED: --reference-controls and --reference-attestation name "
            "the installed three-role tree and the attestation minted over "
            "it; neither establishes a reference without the other.")
    if reference_root is not None:
        # `--candidate-pairs` is not in this list: which scope a reference
        # admits depends on its basis, known only once it is loaded below.
        conflicting = [name for name, dest in
                       SINGLE_OBSERVATION_INCOMPATIBLE
                       if getattr(args, dest, None)]
        if conflicting:
            raise SystemExit(
                f"REFUSED: --reference-controls scores one candidate "
                f"observation against the installed reference, which is the "
                f"gold, any hard-subset denominator and the pair set; it "
                f"accepts no {conflicting}.")
    # THE DEVELOPMENT DOOR.  The capability gate is the whole of the live
    # producer's binding for this verb -- the returned capability is never
    # read again -- and it is bound to the DOCX evidence workload, which no
    # ordinary development run has.  `--development` opens the same execution
    # for a candidate the plain `run --release` route produced, and the run it
    # scores says so: `generation_evidence_for_run(development=True)` records
    # `development_unstamped`, which is unpublishable by class.
    #
    # No mutual-exclusion guard between the flag and an active capability, and
    # that is not an omission: `docx_v2_workload.bind_cli` compares
    # `tuple(argv)` against the approved argv before any Docker command runs,
    # so a `--development` spliced into a workload-bound invocation already
    # refuses there. A second check here would be justified by the first
    # rather than by a case that occurs.
    # THE REFERENCE DOOR, and the same one `cmd_mutation_run` opens for
    # collecting a leg.  The capability gate is this verb's whole live-workload
    # binding and it is bound to the DOCX evidence workload, which is one
    # project's; an installed three-role reference collection is the binding
    # for every other project.  It is a stronger one than the wrapper: the
    # attestation pins the population, the applier, the substrate baseline,
    # the image, the seed and the timeout, and the pool is held to all of them
    # below before a single mutant is applied.
    if _docx_v2_capability(args, "test-quality") is None \
            and not getattr(args, "development", False) \
            and reference_root is None:
        _refuse_unbound_live_workload(
            "test-quality execution",
            "complete-pre-execution-and-result-publication")
    # Seven more options are as structurally required as `--run`, and
    # argparse does not know it: the live path writes the campaign under
    # `--out`, iterates `--workers`, binds the scored population from
    # `--mutation-validation`, `--manifest` and `--map`, reads
    # `--gold-baseline` as the §3.10 reference, and provisions every worker
    # from `--seed`.  All seven lost `required=True` when the Slice-3 join
    # above arrived -- that join needs none of them -- and nothing replaced
    # it, so an omitted one travelled as `None` into `os.lstat`,
    # `os.path.join` and a `for` loop and ended in a TypeError, one launch at
    # a time.  `--mutation-validation` is the single partial exception:
    # `load_validated_saved_report` does refuse a non-`str` path, but it
    # names the role rather than the option the operator did not type.
    # Refuse all seven by name instead, here, before anything is read,
    # provisioned or written -- and in ONE refusal naming every one of them,
    # because an operator who omitted three should not need three launches to
    # find that out.
    #
    # `hasattr` first and only then `is None`: every real argv carries all
    # seven attributes because all seven are declared on the subparser, so an
    # omitted option IS `None` -- while the docx/worker/test_quality selftest
    # namespaces that predate an option leave its attribute off entirely and
    # stop at the seams they fake, which is what the `getattr(args, ...,
    # default)` calls below exist for too.
    missing = []
    for option, attr, why in (
            ("--out", "out",
             "the rows, the root campaign record and summary.json are "
             "written there"),
            ("--workers", "workers",
             "the candidate and gold slices are sharded across them"),
            ("--mutation-validation", "mutation_validation",
             "it is the release-ready report the other assets bind to"),
            ("--manifest", "manifest",
             "it is the scored mutant population itself"),
            ("--map", "map", "it says which mutants each item carries"),
            ("--gold-baseline", "gold_baseline",
             "it supplies both halves of the §3.10 reference"),
            ("--seed", "seed", "every worker spec is provisioned from it")):
        if hasattr(args, attr) and getattr(args, attr) is None:
            missing.append(f"{option} ({why})")
    if missing:
        raise SystemExit(
            f"REFUSED: test-quality execution needs {', '.join(missing)}.")
    from ..data import mutation_attestation as A
    from . import test_quality as TQ
    from . import worker as W
    from .mutation_run import (CAMPAIGN_IDENTITY_FIELDS_V2_ADDED,
                               MutationAborted, binding_for, candidate_digest,
                               coordinator_cancellation,
                               generation_evidence_for_run, run_slice,
                               operator_profile_for,
                               provenance_path, runtime_applier_sha256,
                               sha256_file,
                               substrate_baseline_digest,
                               validate_campaign_asset_claims,
                               validate_native_shards)
    from .runner import _load_release
    if os.path.lexists(str(args.run) + ".headroom.json") or os.path.basename(str(getattr(args, "release", None))).startswith("headroom_"):
        from ..java import kapua_headroom as H
        try:
            H.validate_candidate_workset(args.run, args.release)
        except (ValueError, OSError) as exc:
            raise SystemExit(str(exc)) from exc
    kapua_document = None
    kapua_expected = None
    if kapua_evidence is not None:
        if prestashop_evidence is not None:
            from . import prestashop_reference as KRef
        else:
            from ..java import kapua_reference as KRef
        try:
            kapua_document, kapua_expected = KRef.candidate_inputs(
                kapua_evidence, run_path=args.run,
                inputs={key: getattr(args, key) for key in KRef.ASSETS},
                gold_baseline=args.gold_baseline,
                **({"task_items": args.prestashop_task_items}
                   if prestashop_evidence is not None else {}))
        except (ValueError, OSError) as exc:
            raise SystemExit(str(exc)) from exc
        if not kapua_expected:
            print(json.dumps({"status": "unscored", "reason": "no passed candidate covering pairs",
                              "inference_valid": False, "mutation_score": None,
                              "campaign_created": False, "sidecar_created": False}, sort_keys=True))
            return 0
    if not args.no_sidecar:
        existing_sidecar = TQ.find_sidecar(args.run)
        if existing_sidecar:
            raise SystemExit(
                f"REFUSED: {args.run} already has test-quality sidecar "
                f"{existing_sidecar}; this command will not overwrite a "
                "published binding. Preserve it and use a new candidate run.")
    try:
        shard_policy = TQ.resolve_cli_shard_policy(
            args.out, getattr(args, "shard_policy", None),
            resume=getattr(args, "resume", False))
    except TQ.TestQualityRefused as e:
        raise SystemExit(str(e)) from e

    spec_entries = []
    for path in args.workers:
        if os.path.islink(path) or not os.path.isfile(path):
            raise SystemExit(
                f"REFUSED: worker spec is not a regular file: {path}")
        try:
            with open(path, encoding="utf-8") as fh:
                spec_entries.append(
                    (path, W.WorkerSpec.from_json(json.load(fh))))
        except (OSError, json.JSONDecodeError, W.WorkerRefused) as e:
            raise SystemExit(str(e))

    # ONE asset resolver for all three mutation verbs.  `mutation-run` and
    # `recall` already ask `_validated_mutation_assets`; this verb asked the
    # native validator directly, so the compact Slice-3 authority arrived
    # here as an unexplained native-report failure rather than as the one
    # refusal that names why it is closed.
    #
    # Both flags are False, and neither is a placeholder.  `recall` derives
    # its pair from the SHARD IDENTITIES it is scoring; this verb produces
    # those shards, so at this point no observation has been minted and
    # nothing in the argv can witness one.  Its only live doors -- the DOCX
    # evidence workload and `--development` -- hand the population document
    # itself, never a paid view of it.  So the native release-set strictness
    # stays exactly the `paid_view_subset=False` default the direct call
    # took, and the compact branch refuses here for the same reason it
    # refuses for `mutation-run`.
    try:
        assets = _validated_mutation_assets(
            args, paid_view_subset=False, compact_allowed=False)
    except (A.MutationAssetRefused, OSError, ValueError) as e:
        raise SystemExit(str(e))
    if assets["asset_project"] == "prestashop" \
            and assets.get("population_basis") == "budgeted_sample" \
            and prestashop_evidence is None:
        raise SystemExit(
            "REFUSED: PrestaShop B100 candidate work requires "
            "--prestashop-reference-evidence; an omitted reference must "
            "not schedule another gold observation.")
    manifest = assets["manifest"]
    by_mutant = assets["map"]["by_mutant"]
    gold_plan = gold_plan_binding = None
    if getattr(args, "gold_pair_plan", None) is not None:
        try:
            gold_plan, gold_plan_binding = TQ.load_gold_pair_plan(
                args.gold_pair_plan, manifest_digest=manifest.get("digest"))
        except (TQ.TestQualityRefused, OSError) as e:
            raise SystemExit(str(e))
    try:
        operator_profile = operator_profile_for(manifest["operators"])
    except (KeyError, ValueError) as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    # The engine the way `mutation-run` binds it: off the MANIFEST, through
    # `binding_for`, because the mutant ids hash the engine and only its own
    # applier can re-enumerate them.  This verb used to hard-code the PHP
    # pair here while its harness already routed through `--profile` — so a
    # docx cell staged `mutate.php` into a container with no `php` and every
    # apply died at rc 127, discovered only when the per-cell gate demanded
    # the sidecar this command could then not produce.
    try:
        engine_dir, applier = binding_for(manifest.get("engine"))
    except MutationAborted as e:
        raise SystemExit(str(e))
    # And the harness the SAME rows will run under, from `--profile`.  The
    # two resolve independently — engine from the manifest, stack from the
    # profile — so a mismatch here means the operator is pointing one
    # project's mutants at the other project's workspace.  Staging would
    # "succeed" and every apply would fail inside the container, hours in;
    # refusing on the two directory identities is free and immediate.
    stack_dir = getattr(_stack(args), "engine_dir", None)
    if stack_dir is not None and stack_dir != engine_dir:
        raise SystemExit(
            f"REFUSED: the manifest's mutants were minted by "
            f"{manifest.get('engine')!r} (applier in {engine_dir}), but "
            f"--profile routes this run to the {_stack(args).FRAMEWORK} "
            f"stack (engine dir {stack_dir}). One of the two names the "
            f"wrong project; staging that applier would fail every mutant "
            f"inside the container instead of failing here.")
    # No in-memory population rewrite is permitted here.  In particular the
    # historical 10,463-entry CoreShop catalogue must never be hashed and
    # labelled as if it were the 10,205-entry scored population.  PR-2 has
    # already proved that these exact bytes are the frozen scored manifest.
    n_non_production = assets["n_non_production_excluded"]

    reference = None
    single_observation_authority = None
    # Go workers run their seed-installed applier; the pool/reference join
    # below binds the reference to it, not to this checkout's builder.
    engine_source = (None if manifest.get("engine") == "r2t-mutate-go"
                     else os.path.join(engine_dir, applier.source))
    if reference_root is not None:
        from . import reference_loader as RL
        try:
            if reference_sensitivity is not None:
                from .evaluation_reference import \
                    load_evaluation_sensitivity_reference
                options = _evaluation_reference_arguments(args)
                if engine_source is not None:
                    options["engine_source_path"] = engine_source
                reference = load_evaluation_sensitivity_reference(
                    **options, **reference_sensitivity)
            elif getattr(args, "reference_scope", None) is not None:
                from .evaluation_reference import load_evaluation_reference
                options = _evaluation_reference_arguments(args)
                if engine_source is not None:
                    options["engine_source_path"] = engine_source
                reference = load_evaluation_reference(
                    **options, attestation_path=reference_attestation)
            else:
                reference = RL.load_native_reference_controls(
                    assets["asset_project"], reference_root,
                    validation_path=args.mutation_validation,
                    manifest_path=args.manifest, map_path=args.map,
                    release_path=args.release,
                    gold_baseline_path=args.gold_baseline,
                    attestation_path=reference_attestation,
                    engine_source_path=engine_source,
                    validation_input_paths=_validation_input_paths(args))
            single_observation_authority = \
                TQ._seal_single_observation_scoring_authority(
                    reference["controls"])
        except (RL.ReferenceControlsRefused, TQ.TestQualityRefused) as e:
            raise SystemExit(str(e))
        # GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md section 8: a full-gold-only
        # reference (FULL_GOLD_NV_LEAD_AMENDMENT.md section 5) scores
        # candidates on its sealed `G_i` only, and a hard-subset reference
        # on every pair.  `run_test_quality` refuses both mismatches too, but
        # only after the worker preflight below.
        full_gold_reference = getattr(
            single_observation_authority.sets, "reference_basis",
            "hard_subset") == "full_gold"
        gold_killed = (getattr(args, "candidate_pairs", "all")
                       == TQ.CANDIDATE_PAIRS_GOLD_KILLED)
        if full_gold_reference and not gold_killed:
            raise SystemExit(
                "REFUSED: the installed reference is full gold only; its "
                "candidates are scored on the pairs full gold kills. Pass "
                "--candidate-pairs gold-killed "
                "(FULL_GOLD_NV_LEAD_AMENDMENT.md section 5).")
        # The labelled stub-gate-waived basis adopts gold-killed for its
        # hard-subset reference (SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md
        # section 2): `H_i` lies inside `G_i`, which the scorer checks.
        if gold_killed and not full_gold_reference \
                and reference_sensitivity is None:
            raise SystemExit(
                "REFUSED: with --reference-controls, --candidate-pairs "
                "gold-killed is served only for a full-gold-only reference "
                "or a labelled reference --sensitivity basis; this "
                "reference's hard subset reads candidate outcomes on every "
                "pair (GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md section 7).")

    run_rows = TQ.load_jsonl(args.run)
    try:
        TQ.require_run_sensitivity(run_rows, sensitivity)
    except TQ.TestQualityRefused as e:
        raise SystemExit(str(e))
    gold_baseline_rows = TQ.load_jsonl(args.gold_baseline)
    gold_results = (TQ.load_jsonl(args.gold_results)
                    if args.gold_results else None)
    if bool(args.gold_results) != bool(getattr(
            args, "gold_results_attestation", None)):
        raise SystemExit(
            "REFUSED: --gold-results requires --gold-results-attestation, "
            "and an attestation without rows is invalid.")
    gold_results_attestation = None
    if args.gold_results_attestation:
        try:
            with open(args.gold_results_attestation, encoding="utf-8") as fh:
                gold_results_attestation = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            raise SystemExit(
                f"REFUSED: cannot read --gold-results-attestation: {e}")
    hard_path = getattr(args, "hard_subset", None)
    hard_rerun_paths = list(getattr(args, "candidate_hard_rerun", None) or [])
    hard_plan_path = getattr(args, "candidate_hard_plan", None)
    if hard_rerun_paths and not hard_path:
        raise SystemExit(
            "REFUSED: --candidate-hard-rerun requires --hard-subset; run 2 "
            "cannot define its own denominator. A hard subset may omit run 2 "
            "only when run 1 computes no D4 qualifying item.")
    if hard_rerun_paths and not hard_plan_path:
        raise SystemExit(
            "REFUSED: --candidate-hard-rerun requires --candidate-hard-plan; "
            "D4 run 2 must be produced from and rebound to the authenticated "
            "exact-pair plan derived from run 1.")
    if hard_plan_path and (not hard_rerun_paths or not hard_path
                           or not getattr(args, "resume", False)):
        raise SystemExit(
            "REFUSED: --candidate-hard-plan is a finalization input and "
            "requires --resume, --hard-subset, and at least one "
            "--candidate-hard-rerun.")
    hard_doc = None
    hard_rerun_rows = None
    hard_rerun_campaign = None
    hard_rerun_observation_id = None
    if hard_path:
        from ..toolkit.hard_subset import HardSubsetRefused, load as load_hard_subset
        try:
            hard_doc = load_hard_subset(hard_path, require_pin=True)
            if hard_rerun_paths:
                hard_rerun_campaign = validate_native_shards(
                    hard_rerun_paths, required_side="candidate",
                    return_campaign=True)
                hard_rerun_observation_id = \
                    TQ._hard_rerun_observation_id(hard_rerun_campaign)
                TQ.refuse_unpublishable_generation(
                    hard_rerun_campaign["campaign_identity"].get(
                        "generation_provenance_class"),
                    "the candidate hard rerun")
                validate_campaign_asset_claims(
                    hard_rerun_campaign["campaign_identity"], assets,
                    validation_path=args.mutation_validation,
                    manifest_path=args.manifest, map_path=args.map,
                    release_path=args.release)
                hard_rerun_rows = hard_rerun_campaign["rows"]
        except (HardSubsetRefused, TQ.TestQualityRefused, MutationAborted,
                A.MutationAssetRefused, OSError, ValueError) as e:
            raise SystemExit(str(e))
    if hard_plan_path:
        try:
            hard_plan_binding = TQ.validate_d4_confirmation_plan(
                hard_plan_path, run1_campaign=args.out,
                hard_subset_path=hard_path, candidate_run_path=args.run,
                assets=assets, validation_path=args.mutation_validation,
                manifest_path=args.manifest, map_path=args.map,
                release_path=args.release)
            if hard_plan_binding["timeout_seconds"] != args.timeout:
                raise TQ.TestQualityRefused(
                    "REFUSED: D4 finalization timeout differs from its "
                    "authenticated run-1 plan.")
            hard_rerun_sidecars = []
            for shard_path in hard_rerun_paths:
                with open(provenance_path(shard_path),
                          encoding="utf-8") as fh:
                    hard_rerun_sidecars.append(json.load(fh))
            TQ.validate_d4_confirmation_run_2_binding(
                rerun_campaign=hard_rerun_campaign,
                shard_sidecars=hard_rerun_sidecars,
                plan_binding=hard_plan_binding,
                plan_path=hard_plan_path, run1_campaign=args.out,
                hard_subset_path=hard_path)
        except (TQ.TestQualityRefused, MutationAborted, OSError,
                json.JSONDecodeError, ValueError) as e:
            raise SystemExit(str(e))

    needs_database = _stack_profile(args).needs_database
    _refuse_unbound_database_runtime(
        needs_database, "database-backed test-quality execution")
    spec_entries.sort(key=lambda entry: entry[1].index)
    spec_paths = [entry[0] for entry in spec_entries]
    specs = [entry[1] for entry in spec_entries]
    java_analysis_root = _mutation_java_analysis_root(
        args, manifest, [worker.workspace for worker in specs])
    answer_paths = W.default_answer_paths(
        args.gold, args.artifacts, os.path.join(args.artifacts, "release"))
    if java_analysis_root is not None:
        answer_paths.append(java_analysis_root)
    answer_paths.extend([
        args.run, args.gold_baseline, args.manifest, args.map, args.release,
        args.mutation_validation, args.out,
        *spec_paths,
        *(W.runtime_attestation_path(path) for path in spec_paths),
        *(W.binding_attestation_path(path) for path in spec_paths),
        *(filter(None, (args.gold_results,
                        args.gold_results_attestation, hard_path,
                        hard_plan_path, reference_root,
                        reference_attestation,
                        getattr(args, "gold_pair_plan", None),
                        getattr(args, "gold_disagreements", None)))),
        *hard_rerun_paths,
    ])
    if kapua_document is not None:
        answer_paths.extend(KRef.protected_paths(kapua_evidence, kapua_document))
    answer_paths.extend(getattr(args, "_publication_protected_paths", ()))
    if getattr(args, "reference_scope", None) is not None:
        answer_paths.extend(_evaluation_protected_paths(args))
    try:
        from .validate import HARNESS_VERSION
        W.preflight(specs, answer_paths, live=False,
                    needs_database=needs_database)
        runtime = W.validate_mutation_runtime(
            spec_paths, specs, args.seed, HARNESS_VERSION, needs_database,
            project=assets["asset_project"])
        W.preflight(
            specs, answer_paths,
            containment_paths=runtime["protected_evidence_paths"], live=True,
            needs_database=needs_database, behat=_behat_row(args))
    except W.WorkerRefused as e:
        raise SystemExit(str(e))
    # Read once from the `--seed` just verified, and shared read-only by every
    # job's harness below.
    derived = _derived_baseline(args, args.seed)
    try:
        applier_sha256 = runtime_applier_sha256(manifest.get("engine"), args.seed)
    except MutationAborted as e:
        raise SystemExit(str(e))
    # Jobs index this list by the validated zero-based worker id.  CLI order
    # is not identity and therefore cannot select another workspace.
    items_by_id = {i["item_id"]: i for i in _load_release(args.release)}

    # All shards in one campaign must interpret "pristine" against identical
    # immutable bytes.  Compute the recorded baseline identity before any
    # worker runs, and refuse a heterogeneous pool before creating --out.
    worker_baselines = []
    for spec_path, spec in spec_entries:
        worker_harness, _worker_boundary, _worker_manifest = (
            _test_quality_worker_harness(args, spec_path, spec))
        if sensitivity is not None \
                and getattr(worker_harness, "sensitivity", None) != sensitivity:
            raise SystemExit(
                f"REFUSED: --sensitivity {sensitivity} is defined only for "
                "the Ruby Cucumber stack")
        try:
            worker_baselines.append(substrate_baseline_digest(worker_harness))
        except MutationAborted as e:
            raise SystemExit(str(e))
    if len(set(worker_baselines)) != 1:
        raise SystemExit(
            "REFUSED: test-quality workers carry different immutable source "
            f"baselines: {sorted(set(worker_baselines))}. Reprovision them "
            "from one frozen workspace before running a campaign.")
    if reference is not None:
        # The v2 summary validator compares these same seven facts when the
        # campaign FINISHES. Comparing them here -- the first moment both the
        # runtime attestations and the pool's own baseline exist -- turns a
        # multi-day sweep against a pool the reference never ran on into an
        # immediate refusal.
        control_authority = reference["controls"]["authority"]
        pool_facts = {
            "harness_version": runtime["harness_version"],
            "container_image_digest": runtime["container_image_digest"],
            "workspace_seed_digest": runtime["workspace_seed_digest"],
            "database_dump_digest": runtime["database_dump_digest"],
            "applier_sha256": applier_sha256,
            "substrate_baseline_sha256": worker_baselines[0],
            "timeout_seconds": args.timeout,
        }
        changed = sorted(key for key, value in pool_facts.items()
                         if control_authority.get(key) != value)
        # A harness version VERSIONS.yml declares compatible with the
        # reference's recorded one, for this project, is not a difference.
        from ..data import versions
        if "harness_version" in changed \
                and versions.reference_harness_compatible(
                    reference["controls"]["population"]["asset_project"],
                    control_authority.get("harness_version"),
                    runtime["harness_version"]):
            changed.remove("harness_version")
        # Likewise an applier VERSIONS.yml accepts beside the recorded one.
        if "applier_sha256" in changed \
                and versions.reference_applier_accepted(
                    reference["controls"]["population"]["asset_project"],
                    control_authority.get("applier_sha256"), applier_sha256):
            changed.remove("applier_sha256")
        # And a seed (workspace and substrate, as one pair) VERSIONS.yml
        # accepts beside the recorded one.
        if set(versions.SEED_FIELDS) & set(changed) \
                and versions.reference_seed_accepted(
                    reference["controls"]["population"]["asset_project"],
                    control_authority, pool_facts):
            changed = [key for key in changed
                       if key not in versions.SEED_FIELDS]
        if changed:
            raise SystemExit(
                f"REFUSED: this worker pool differs from the installed "
                f"reference controls in field(s) {changed}. The three "
                f"reference observations were collected under the other "
                f"values, so a candidate executed here would be compared "
                f"against a reference it does not share an execution "
                f"environment with.")

    def execute(job):
        """One slice, on the worker that job belongs to.

        A fresh harness per job rather than one per worker: it is cheap (a
        boundary, a manifest and a docker handle), and it means the two sides
        cannot share a `expected_mutations` declaration by accident.
        """
        if before_execute is not None:
            before_execute(job)
        spec = specs[job["worker"]]
        h, _b, _man = _test_quality_worker_harness(
            args, spec_paths[job["worker"]], spec)
        if derived:
            h.derived_baseline = derived
        print(f"  [{job['side']} w{job['worker']}] {len(job['mutants'])} "
              f"mutant(s) -> {job['out']}", flush=True)
        return run_slice(h, job["mutants"], items_by_id, job["files_by_item"],
                         job["by_mutant"], engine_dir, job["out"],
                         timeout=args.timeout, provenance=job["provenance"],
                         identity=job["identity"], resume=job["resume"],
                         manifest=manifest,
                         java_analysis_root=java_analysis_root,
                         cancel_event=job["cancel_event"],
                         resources_locked=True,
                         # The manifest's own binding, exactly as
                         # `mutation-run` passes it: `run_slice` would
                         # otherwise default to the PHP applier and stage a
                         # program the docx container cannot even interpret.
                         applier=applier,
                         operator_profile=operator_profile,
                         # The manifest's own engine, so the rows and the
                         # summary that scores them cannot name two different
                         # ones -- `test_quality` refuses that anyway, and
                         # refusing after the campaign has run would be a
                         # refusal that cost hours.
                         engine=manifest.get("engine"),
                         engine_version=manifest.get("engine_version"))

    try:
        # `getattr` for the same reason the Slice-3 branch above uses it: the
        # docx/worker/test_quality selftests drive this verb with hand-built
        # namespaces that predate this option.
        generation = generation_evidence_for_run(
            args.run, run_rows,
            development=getattr(args, "development", False))
    except MutationAborted as e:
        raise SystemExit(str(e))
    generation.pop("legacy_generation_evidence", None)
    identity_inputs = {
        **generation,
        "asset_index_sha256": assets["asset_index_sha256"],
        "asset_project": assets["asset_project"],
        "mutation_validation_sha256": assets["validation_sha256"],
        "mutation_validation_class": assets["validation_class"],
        "manifest_sha256": sha256_file(args.manifest),
        "manifest_digest": manifest.get("digest"),
        "map_sha256": sha256_file(args.map),
        "release_sha256": sha256_file(getattr(args, "map_release", None) or args.release),
        "candidate_run_sha256": sha256_file(args.run),
        "candidate_generated_tests_sha256": candidate_digest(
            TQ.passed_solutions(run_rows)),
        "gold_baseline_sha256": sha256_file(args.gold_baseline),
        "gold_generated_tests_sha256": candidate_digest(
            TQ.gold_side(gold_baseline_rows,
                         TQ.passed_solutions(run_rows))[0]),
        "gold_results_sha256": (sha256_file(args.gold_results)
                                if args.gold_results else None),
        "gold_results_attestation_sha256": (
            sha256_file(args.gold_results_attestation)
            if args.gold_results_attestation else None),
        "applier_sha256": applier_sha256,
        "substrate_baseline_sha256": worker_baselines[0],
        "worker_resources_sha256": runtime["worker_resources_sha256"],
        "harness_version": runtime["harness_version"],
        "container_image_digest": runtime["container_image_digest"],
        "workspace_seed_digest": runtime["workspace_seed_digest"],
        "database_dump_digest": runtime["database_dump_digest"],
        "engine": manifest.get("engine"),
        "engine_version": manifest.get("engine_version"),
        "parser": manifest.get("parser"),
    }
    # Only when the assets carry it: a full-population campaign's identity
    # inputs are the exact dict they were.
    identity_inputs.update({
        key: assets[key] for key in
        ("population_basis", "budgeted_sample_sha256", "parent_map_sha256")
        if key in assets})
    if hard_rerun_campaign is not None:
        hard_identity = hard_rerun_campaign["campaign_identity"]
        expected_hard = {
            "asset_index_sha256": identity_inputs["asset_index_sha256"],
            "asset_project": identity_inputs["asset_project"],
            "mutation_validation_sha256": identity_inputs[
                "mutation_validation_sha256"],
            "mutation_validation_class": identity_inputs[
                "mutation_validation_class"],
            "manifest_sha256": identity_inputs["manifest_sha256"],
            "manifest_digest": identity_inputs["manifest_digest"],
            "map_sha256": identity_inputs["map_sha256"],
            "release_sha256": identity_inputs["release_sha256"],
            "candidate_run_sha256": identity_inputs["candidate_run_sha256"],
            "candidate_generated_tests_sha256": identity_inputs[
                "candidate_generated_tests_sha256"],
            "solution_generated_tests_sha256": identity_inputs[
                "candidate_generated_tests_sha256"],
            "substrate_baseline_sha256": identity_inputs[
                "substrate_baseline_sha256"],
            "applier_sha256": identity_inputs["applier_sha256"],
            "harness_version": identity_inputs["harness_version"],
            "container_image_digest": identity_inputs[
                "container_image_digest"],
            "workspace_seed_digest": identity_inputs[
                "workspace_seed_digest"],
            "database_dump_digest": identity_inputs[
                "database_dump_digest"],
            "engine": identity_inputs["engine"],
            "engine_version": identity_inputs["engine_version"],
            "parser": identity_inputs["parser"],
            "timeout_seconds": args.timeout,
            **{key: identity_inputs.get(key)
               for key in sorted(CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)},
        }
        changed = sorted(key for key, value in expected_hard.items()
                         if hard_identity.get(key) != value)
        if changed or hard_identity.get("kind") != "mutation-run" \
                or hard_identity.get("sample") is not None \
                or hard_identity.get("sample_seed") is not None:
            raise SystemExit(
                "REFUSED: --candidate-hard-rerun is not an unsampled "
                f"independent observation of this candidate; changed "
                f"field(s) {changed}.")
    single_observation_kwargs = {}
    if reference is not None:
        # `run_test_quality` does NOT self-validate a v2 summary, so this
        # closure is the only producer-side gate between the scored numbers
        # and the durable completion the campaign publishes.
        def reference_reader(_summary, _expected):
            return single_observation_authority

        def reference_final_validator(summary, summary_path):
            TQ._validate_native_summary_before_completion(
                summary, summary_path, args.run,
                reference_controls_reader=reference_reader)

        single_observation_kwargs = {
            "single_observation_authority": single_observation_authority,
            "final_summary_validator": reference_final_validator,
            **_single_observation_execution(
                args.out, resume=getattr(args, "resume", False)),
        }
    kapua_provenance = {}
    if kapua_document is not None:
        evidence_ref = (KRef._reference(kapua_evidence) if prestashop_evidence is not None
                        else KRef.G.reference(kapua_evidence))
        authenticated = KRef.selection(kapua_evidence, kapua_expected,
            {**identity_inputs, "gold_results_sha256": evidence_ref["sha256"],
             "gold_results_attestation_sha256": evidence_ref["sha256"],
             "timeout_seconds": args.timeout},
            **({"worker_resources": runtime["worker_resources"]}
               if prestashop_evidence is not None else {}))
        def kapua_final_validator(summary, summary_path):
            TQ._validate_native_summary_before_completion(summary, summary_path, args.run)
        kapua_provenance = {KRef.SUMMARY_KEY: evidence_ref["path"],
                            "reference_diagnostics": kapua_document["diagnostics"],
                            "inference_valid": False, "timeout_seconds": args.timeout}
        if gold_plan is None:
            identity_inputs.update({"gold_results_sha256": evidence_ref["sha256"],
                                    "gold_results_attestation_sha256": evidence_ref["sha256"]})
            single_observation_kwargs = {"authenticated_gold": authenticated,
                                         "final_summary_validator": kapua_final_validator}
            kapua_provenance.update({"gold_results_source": evidence_ref["path"],
                                     "gold_results_attestation": evidence_ref["path"]})
        else:
            # GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md section 4: gold is
            # observed again on this host, on exactly the evidence's
            # full-gold kills; the sealed rows only name those pairs.
            sealed, _binding = TQ._open_authenticated_gold_selection(authenticated)
            kills = {(row["item_id"], row["mutant_id"]) for row in sealed
                     if row["outcome"] == "failed"}
            if kills != set(kapua_expected) & gold_plan:
                raise SystemExit("REFUSED: --gold-pair-plan is not the reference evidence's "
                                 "full-gold kills on this candidate's pairs")
            single_observation_kwargs = {"final_summary_validator": kapua_final_validator}
        if prestashop_evidence is not None:
            kapua_provenance.update({"reference_method": "single_observation",
                                    "reference_observation_count": 1,
                                    "candidate_observation_count": 1,
                                    "prestashop_task_items": KRef._reference(args.prestashop_task_items)})
    resource_identities = []
    for spec in specs:
        for field in W.resource_fields(needs_database):
            value = getattr(spec, field)
            if value:
                resource_identities.append((field, value))
    try:
        with coordinator_cancellation() as cancel_event:
            summary = TQ.run_test_quality(
                run_rows=run_rows, gold_baseline_rows=gold_baseline_rows,
                manifest=manifest, by_mutant=by_mutant, out_dir=args.out,
                execute=execute, n_workers=len(specs), gold_results=gold_results,
                gold_results_attestation=gold_results_attestation,
                gold_results_attestation_path=(
                    args.gold_results_attestation),
                require_complete=not args.allow_incomplete,
                allow_degraded_gold=args.allow_degraded_gold,
                candidate_pairs=getattr(args, "candidate_pairs", "all"),
                gold_pair_plan=gold_plan,
                gold_pair_plan_binding=gold_plan_binding,
                identity_inputs=identity_inputs, timeout=args.timeout,
                resume=getattr(args, "resume", False),
                shard_policy=shard_policy,
                sensitivity=sensitivity,
                compute_cap_seconds=getattr(
                    args, "compute_cap_seconds", None),
                compute_cap_review_authority=(
                    getattr(args, "compute_cap_review_authority", None)),
                cancel_event=cancel_event,
                # One forked process per worker queue: slices are dominated by
                # interpreter-held hashing, which threads cannot overlap.
                worker_processes=True,
                resource_identities=resource_identities,
                worker_resources=runtime["worker_resources"],
                hard_subset_doc=hard_doc,
                hard_subset_path=hard_path,
                candidate_hard_rerun_rows=hard_rerun_rows,
                candidate_hard_rerun_paths=hard_rerun_paths,
                candidate_hard_rerun_observation_id=(
                    hard_rerun_observation_id),
                d4_confirmation_plan_out=getattr(
                    args, "candidate_hard_plan_out", None),
                **single_observation_kwargs,
                provenance={"run": os.path.abspath(args.run),
                            "gold_baseline": os.path.abspath(args.gold_baseline),
                            "manifest": os.path.abspath(args.manifest),
                            "map": os.path.abspath(args.map),
                            "release": os.path.abspath(args.release),
                            "mutation_validation": os.path.abspath(
                                args.mutation_validation),
                            "seed": os.path.abspath(args.seed),
                            "gold_results_source": (
                                os.path.abspath(args.gold_results)
                                if args.gold_results else None),
                            "gold_results_attestation": (
                                os.path.abspath(args.gold_results_attestation)
                                if args.gold_results_attestation else None),
                            "worker_resources": runtime[
                                "worker_resources"],
                            "manifest_digest": manifest.get("digest"),
                            "engine": manifest.get("engine"),
                            "engine_version": manifest.get("engine_version"),
                            "parser": manifest.get("parser"),
                            "shard_policy": shard_policy,
                            "mutants_non_production_excluded": n_non_production,
                            "workers_used": [os.path.abspath(p)
                                             for p in args.workers],
                            **kapua_provenance})
    except ValueError as e:
        # A REFUSED message is the product here; a traceback around it is not.
        raise SystemExit(str(e))
    if summary.get("schema") == TQ.D4_CONFIRMATION_PENDING_SCHEMA:
        print(json.dumps(summary, indent=1, sort_keys=True))
        print("\nD4 run 1 is complete and resumable. Execute the exact "
              "standalone run 2 with `mutation-run --pair-plan ...`, then "
              "repeat this command with --resume, --candidate-hard-plan, "
              "and one --candidate-hard-rerun per run-2 shard.")
        return 0
    TQ.print_summary(summary)
    if not args.no_sidecar:
        # Beside the run as well as in --out, because `report` reads the run
        # and a summary that only exists in a campaign directory is a summary
        # nobody will see again.
        try:
            print(f"\nsidecar: {TQ.write_sidecar(summary, args.run)}")
        except ValueError as e:
            raise SystemExit(str(e))
    print(f"summary: {os.path.join(args.out, TQ.SUMMARY)}")
    return 0


def cmd_mutation_bound(args) -> int:
    """Write a sound interval from a compute-capped test-quality campaign."""
    from . import mutation_bounds as B

    try:
        report = B.write_report(
            args.out,
            campaign_dir=args.campaign,
            run_path=args.run,
            gold_baseline_path=args.gold_baseline,
            mutation_validation_path=args.mutation_validation,
            manifest_path=args.manifest,
            map_path=args.map,
            release_path=args.release,
            cap_seconds=args.cap_seconds,
            cap_workers=args.cap_workers,
            cap_review_authority=args.cap_review_authority,
            thresholds=args.threshold or ("1.0",),
        )
    except (B.BoundRefused, OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps({
        "out": os.path.abspath(args.out),
        "schema": report["schema"],
        "state": report["state"],
        "publishable": report["publishable"],
        "denominator": report["denominator"],
        "reference_leg": report["reference_leg"],
        "threshold_bounds": report["threshold_bounds"],
    }, indent=1, sort_keys=True))
    return 0


def cmd_test_quality_bind(args) -> int:
    """Bind preserved legacy TQ evidence without rewriting its sidecar."""
    from . import test_quality as TQ
    try:
        wrapper = TQ.rebind_legacy_test_quality(
            args.run, args.summary, args.legacy_consistency, args.out,
            allow_degraded_gold=args.allow_degraded_gold)
    except ValueError as e:
        raise SystemExit(str(e))
    print(json.dumps({
        "out": os.path.abspath(args.out),
        "binding": wrapper["binding"],
        "gold_provenance_class": wrapper["gold_provenance_class"],
        # Ruling 2.6: the count and the per-item disclosure travel with the
        # number, so they are on the operator's screen at the moment the
        # wrapper that admits this evidence to publication is created.
        "gold_infrastructure_outcomes": wrapper[
            "gold_infrastructure_outcomes"],
        "gold_infrastructure_class": wrapper["gold_infrastructure_class"],
        "gold_infrastructure_pairs": wrapper["gold_infrastructure_pairs"],
        "allow_degraded_gold": wrapper["allow_degraded_gold"],
        "path_base": wrapper["path_base"],
        "legacy_rebinding": wrapper["legacy_rebinding"],
    }, indent=1, sort_keys=True))
    return 0


def cmd_mutants(args) -> int:
    """Enumerate the mutant population and pin it with a digest (§3.11)."""
    if getattr(args, "action", None) == "validate":
        from ..data import mutation_attestation as A
        from ..toolkit import mutation_audit as AUDIT
        from ..data import mutation as M
        from .mutation_run import binding_for

        def read_json(path, label):
            if not path:
                raise SystemExit(f"REFUSED: mutants validate needs --{label}")
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)

        raw_path = args.raw_manifest or args.manifest
        initial_inputs = [
            raw_path, args.manifest, args.map, args.coverage_run, args.release,
            args.asset_index, args.boundary, args.engine_source,
            args.candidate_run, args.gold_baseline, args.candidate_results,
            args.gold_results, args.audit_attestation,
            args.candidate_egress_attestation]
        if args.audit_root:
            audit_root = os.path.realpath(os.path.abspath(args.audit_root))
            output_real = os.path.realpath(os.path.abspath(args.out))
            try:
                output_inside_audit = (os.path.commonpath(
                    (audit_root, output_real)) == audit_root)
            except ValueError:
                output_inside_audit = False
            if output_inside_audit:
                raise SystemExit(
                    "REFUSED: --out must be outside --audit-root so writing "
                    "the evidence cannot change the audited workspace")
        try:
            out_fd = AUDIT.reserve_output(args.out, input_paths=initial_inputs)
        except A.MutationAssetRefused as exc:
            raise SystemExit(str(exc))

        engine_source = args.engine_source
        historical_engine_source = None
        repository_root = os.path.dirname(BENCHMARK)
        path_base = {
            "kind": "repository_root",
            "relative_to_report": os.path.relpath(
                repository_root,
                os.path.dirname(os.path.abspath(args.out))).replace(
                    os.sep, "/"),
        }

        def input_evidence():
            pairs = (
                ("raw_manifest", raw_path),
                ("manifest", args.manifest
                 if args.manifest != raw_path else None),
                ("map", args.map), ("coverage_run", args.coverage_run),
                ("release", args.release), ("asset_index", args.asset_index),
                ("boundary", args.boundary),
                ("engine_source", engine_source),
                ("candidate_run", args.candidate_run),
                ("candidate_egress_attestation",
                 args.candidate_egress_attestation),
                ("gold_baseline", args.gold_baseline),
                ("candidate_results", args.candidate_results),
                ("gold_results", args.gold_results),
                ("audit_attestation", args.audit_attestation))
            result = {}
            for key, path in pairs:
                if not path:
                    continue
                if key == "engine_source" \
                        and historical_engine_source is not None:
                    result[key] = {
                        "path": historical_engine_source["path"],
                        "sha256": historical_engine_source["sha256"],
                    }
                    continue
                absolute = os.path.abspath(path)
                try:
                    inside_repository = (os.path.commonpath(
                        (repository_root, absolute)) == repository_root)
                except ValueError:
                    inside_repository = False
                durable_path = (os.path.relpath(absolute, repository_root)
                                if inside_repository else absolute)
                item = {"path": durable_path.replace(os.sep, "/")}
                try:
                    item["sha256"] = A.sha256_file(path)
                except OSError as exc:
                    item["hash_error"] = str(exc)
                result[key] = item
            return result

        try:
            if args.require_release_ready and not args.asset_index:
                raise SystemExit(
                    "REFUSED: --require-release-ready needs --asset-index")
            if args.audit_attestation and not args.asset_index:
                raise SystemExit(
                    "REFUSED: --audit-attestation needs the frozen "
                    "--asset-index and --asset-project")
            if args.candidate_egress_attestation \
                    and not args.legacy_consistency:
                raise SystemExit(
                    "REFUSED: --candidate-egress-attestation is a preserved "
                    "legacy-run binding, not a native population input")
            for named_path in initial_inputs:
                if not named_path:
                    continue
                if os.path.islink(named_path) or not os.path.isfile(named_path):
                    raise SystemExit(
                        "REFUSED: validation inputs must be non-symlink "
                        f"regular files: {named_path}")

            index = None
            entry = None
            if args.asset_index:
                index = read_json(args.asset_index, "asset-index")
                A.validate_asset_index(index)
                if not args.asset_project:
                    raise SystemExit(
                        "REFUSED: --asset-index needs --asset-project")
                entry = index["projects"].get(args.asset_project)
                if entry is None:
                    raise SystemExit(
                        f"REFUSED: asset index has no project "
                        f"{args.asset_project!r}")

            if args.legacy_consistency:
                if args.require_release_ready:
                    raise SystemExit(
                        "REFUSED: legacy_consistency is explicitly non-native "
                        "and cannot satisfy --require-release-ready")
                needed = {
                    "raw-manifest (or --manifest)": raw_path,
                    "map": args.map,
                    "coverage-run": args.coverage_run,
                    "release": args.release,
                    "asset-index": args.asset_index,
                    "asset-project": args.asset_project,
                    "candidate-run": args.candidate_run,
                    "gold-baseline": args.gold_baseline,
                    "candidate-results": args.candidate_results,
                    "gold-results": args.gold_results,
                }
                missing = [name for name, path in needed.items() if not path]
                if missing:
                    raise SystemExit(
                        "REFUSED: --legacy-consistency needs "
                        + ", ".join("--" + name for name in missing))
                raw_manifest = read_json(raw_path, "raw-manifest")
                raw_facts = A.validate_manifest(raw_manifest)
                mapping = read_json(args.map, "map")
                release_ids = A.load_release_ids(args.release)
                coverage = A.coverage_from_rows(A.load_jsonl(
                    args.coverage_run))
                raw_map_facts = A.validate_map(
                    mapping, raw_manifest, release_ids=release_ids,
                    coverage_by_item=coverage, allow_legacy=True)
                role = entry["scored_population"]["role"]
                if role == "boundary_scored":
                    manifest = A.derive_boundary_scored_manifest(
                        raw_manifest, _boundary(args), args.boundary,
                        A.sha256_file(args.boundary))
                elif role == "raw_equals_scored":
                    manifest = A.derive_raw_equals_scored_manifest(
                        raw_manifest, _boundary(args), args.boundary,
                        A.sha256_file(args.boundary))
                else:
                    raise SystemExit(
                        f"REFUSED: unsupported indexed scored role {role!r}")
                if args.raw_manifest and args.manifest:
                    supplied_scored = read_json(args.manifest, "manifest")
                    if supplied_scored != manifest:
                        raise SystemExit(
                            "REFUSED: supplied scored manifest differs from "
                            "the explicit frozen-boundary derivation")
                manifest_facts = A.validate_manifest(
                    manifest, raw_manifest=(raw_manifest
                                            if manifest is not raw_manifest
                                            else None))
                strict_by, strict_uncovered = M.map_mutants_to_items(
                    manifest, coverage)
                strict_mapping = A.build_map_artifact(
                    manifest, strict_by, strict_uncovered,
                    coverage_sha256=A.sha256_file(args.coverage_run),
                    release_sha256=A.sha256_file(args.release))
                map_facts = A.validate_map(
                    strict_mapping, manifest, release_ids=release_ids,
                    coverage_by_item=coverage)
                candidate_run_rows = A.load_jsonl(args.candidate_run)
                evidence = A.legacy_consistency(
                    scored_manifest=manifest, mapping=mapping,
                    raw_manifest=(raw_manifest
                                  if raw_manifest["digest"]
                                  != manifest["digest"] else None),
                    release_ids=release_ids,
                    candidate_run_rows=candidate_run_rows,
                    gold_baseline_rows=A.load_jsonl(args.gold_baseline),
                    candidate_result_rows=A.load_jsonl(args.candidate_results),
                    gold_result_rows=A.load_jsonl(args.gold_results))
                agent_systems = {row.get("agent_system")
                                 for row in candidate_run_rows}
                needs_candidate_egress = (
                    args.asset_project == "coreshop"
                    and agent_systems == {"aider"})
                if needs_candidate_egress \
                        and not args.candidate_egress_attestation:
                    raise SystemExit(
                        "REFUSED: CoreShop+aider legacy validation needs "
                        "--candidate-egress-attestation")
                if args.candidate_egress_attestation:
                    from . import egress_attestation as EA
                    egress_document = read_json(
                        args.candidate_egress_attestation,
                        "candidate-egress-attestation")
                    egress_facts = EA.validate_attestation(egress_document)
                    if egress_facts["candidate_run_sha256"] \
                            != A.sha256_file(args.candidate_run):
                        raise SystemExit(
                            "REFUSED: candidate egress attestation names "
                            "another run")
                    n_candidate_items = len({row.get("item_id")
                                             for row in candidate_run_rows})
                    if egress_facts["n_items"] != n_candidate_items:
                        raise SystemExit(
                            "REFUSED: candidate egress attestation names "
                            "another item denominator")
            else:
                manifest = read_json(args.manifest, "manifest")
                raw_manifest = (read_json(args.raw_manifest, "raw-manifest")
                                if args.raw_manifest else manifest)
                mapping = read_json(args.map, "map")
                raw_facts = A.validate_manifest(raw_manifest)
                manifest_facts = A.validate_manifest(
                    manifest, raw_manifest=(raw_manifest
                                            if raw_manifest is not manifest
                                            else None))
                release_ids = (A.load_release_ids(args.release)
                               if args.release else None)
                coverage = (A.coverage_from_rows(A.load_jsonl(
                    args.coverage_run)) if args.coverage_run else None)
                map_facts = A.validate_map(
                    mapping, manifest, release_ids=release_ids,
                    coverage_by_item=coverage)
                raw_map_facts = None
                strict_mapping = mapping
                evidence = {"validation_class": "native"}

            audit_failure = None
            if args.audit_attestation:
                audit_document = read_json(
                    args.audit_attestation, "audit-attestation")
                audit = audit_document.get(
                    "materialisation_audit", audit_document)
            elif args.audit_root:
                audit = {"status": "pending_operator_audit"}
            else:
                audit = {
                    "status": "not_run",
                    "reason": "operator-gated disposable workspace required",
                    "expected_mutants": raw_manifest["n"],
                }

            index_facts = None
            if index is not None:
                if not (args.coverage_run and args.release):
                    raise SystemExit(
                        "REFUSED: frozen index binding needs "
                        "--coverage-run and --release")
                engine_dir, applier = binding_for(manifest["engine"])
                default_engine_source = os.path.join(
                    engine_dir, applier.source)
                engine_source = args.engine_source or default_engine_source
                if os.path.islink(engine_source) \
                        or not os.path.isfile(engine_source):
                    raise SystemExit(
                        "REFUSED: engine source must be a non-symlink "
                        f"regular file: {engine_source}")
                if args.engine_source is None:
                    logical_source = os.path.relpath(
                        default_engine_source,
                        repository_root).replace(os.sep, "/")
                    known_historical = A.legacy_engine_source_bindings().get(
                        logical_source)
                    if known_historical is not None \
                            and known_historical["sha256"] \
                            == entry["engine_source"]["sha256"]:
                        historical_engine_source = known_historical
                index_facts = A.validate_index_binding(
                    index, args.asset_project,
                    raw_manifest=raw_manifest, scored_manifest=manifest,
                    mapping=strict_mapping, boundary_path=args.boundary,
                    coverage_path=args.coverage_run,
                    release_path=args.release,
                    engine_source_path=engine_source,
                    historical_engine_source=historical_engine_source,
                    raw_manifest_path=raw_path,
                    audit_attestation=(audit if args.audit_attestation
                                       else None),
                    require_release_ready=args.require_release_ready)

            # Both in-image audits use isolated trees and one complete report.
            # Go selects existing workers from the authenticated owning pool.
            if args.audit_workers != 1 and not (
                    args.audit_root and raw_manifest["engine"] in {M.ENGINE, "r2t-mutate-go"}
                    and _worker_spec(args) is not None):
                reasons = []
                if not args.audit_root:
                    reasons.append("no --audit-root to copy")
                if raw_manifest["engine"] not in {M.ENGINE, "r2t-mutate-go"}:
                    reasons.append(
                        f"a {raw_manifest['engine']} population, which has "
                        "no in-image transport")
                if _worker_spec(args) is None:
                    reasons.append("no --worker binding")
                raise SystemExit(
                    "REFUSED: --audit-workers selects the in-image "
                    f"{M.ENGINE} audit or Go audit (k isolated trees); "
                    "this run has " + "; ".join(reasons))

            # Every structural and frozen-byte check above precedes mutation.
            # Once this starts, the reserved output guarantees success or
            # failure evidence cannot be hidden by an existing destination.
            if args.audit_root:
                try:
                    audit_kwargs = (
                        {"historical_engine_source": historical_engine_source}
                        if historical_engine_source is not None else
                        {"engine_source_path": engine_source})
                    # WHERE THE APPLIER RUNS.  Without `--worker` this is the
                    # host route it has always been, and a host without the
                    # interpreter refuses by name inside `audit_with_engine`.
                    # With it, the applier runs inside the pool's image with
                    # the disposable copy bind-mounted -- the same binding
                    # `mutants build` takes, and open on the same fact: the
                    # named container's IMMUTABLE image ID, resolved before
                    # any audit container starts (DOCKER_EXECUTION_AUTHORITY,
                    # 2026-09-09 amendment).
                    #
                    # ONLY for `r2t-mutate`.  The in-image transport is the
                    # Behat/PHP one; python-docx and Ruby populations audit on
                    # the host, and a `--worker` on their command line (one
                    # spec drives a whole session) must not turn their audit
                    # into a refusal -- nor spend a `docker inspect` deciding
                    # that.  The library keeps its own guard for a caller that
                    # is not this verb.
                    if raw_manifest["engine"] == M.ENGINE \
                            and _worker_spec(args) is not None:
                        from .harness import DockerRunner
                        audit_kwargs["expected_image_id"] = (
                            _bound_container_image(args.container))
                        audit_kwargs["runner"] = DockerRunner(
                            args.container, workdir=args.workdir)
                        audit_kwargs["workers"] = args.audit_workers
                    if raw_manifest["engine"] == "r2t-mutate-go":
                        from ..go.mutation_audit import audit_bound_pool
                        from .worker import WorkerRefused
                        from ..go.mutation_runtime import MutationRuntimeRefused
                        from .repo import SubstrateTampered
                        try:
                            audit = audit_bound_pool(
                                args, raw_manifest, audit_root=args.audit_root,
                                evidence_dir=args.out+".go-audit-evidence",
                                engine_source_path=engine_source)
                        except (WorkerRefused, MutationRuntimeRefused, SubstrateTampered) as exc:
                            raise A.MutationAssetRefused(str(exc)) from exc
                    else:
                        audit = AUDIT.audit_with_engine(
                            raw_manifest, args.audit_root, **audit_kwargs)
                except A.MaterialisationAuditRefused as exc:
                    audit = exc.report
                    audit_failure = str(exc)
            report = {
                "schema": "r2t.mutation-validation/1",
                "status": ("failed" if audit_failure else "valid"),
                "path_base": path_base,
                "raw_manifest": raw_facts,
                "scored_manifest": manifest_facts,
                "map": map_facts,
                "legacy_raw_map": raw_map_facts,
                "evidence": evidence,
                "asset_index": index_facts,
                "materialisation_audit": audit,
                "inputs": input_evidence(),
            }
        except (A.MutationAssetRefused, OSError, json.JSONDecodeError,
                ValueError, KeyError, TypeError, SystemExit) as exc:
            message = str(exc)
            if not message.startswith("REFUSED:"):
                message = "REFUSED: " + message
            failure = {
                "schema": "r2t.mutation-validation/1",
                "status": "refused",
                "path_base": path_base,
                "failure": message,
                "inputs": input_evidence(),
            }
            AUDIT.write_reserved_json(out_fd, failure)
            raise SystemExit(
                f"{message}; durable refusal evidence: {args.out}")
        AUDIT.write_reserved_json(out_fd, report)
        if audit_failure is not None:
            raise SystemExit(
                f"{audit_failure}; durable failure evidence: {args.out}")
        print(json.dumps({"out": args.out,
                          "manifest_digest": manifest["digest"],
                          "n": manifest["n"],
                          "map_pairs": map_facts["n_pairs"],
                          "validation_class":
                              evidence["validation_class"]}, indent=1))
        return 0

    other = _other_stack(args, "cmd_mutants")
    if other is not None:
        return other(args)
    import shutil
    import subprocess
    from .harness import DockerRunner
    from ..data import mutation as M
    from ..data import mutation_attestation as A
    from ..toolkit import mutation_audit as AUDIT
    from .repo import behat_project
    b = _boundary(args)
    if args.action == "map":
        try:
            out_fd = AUDIT.reserve_output(
                args.out, input_paths=(args.manifest, args.coverage_run,
                                       getattr(args, "release", None),
                                       args.boundary))
        except A.MutationAssetRefused as exc:
            raise SystemExit(str(exc))
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = json.load(fh)
        from .runner import _load_release
        cov = {}
        with open(args.coverage_run, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    row = json.loads(line)
                    if row.get("coverage_lines"):
                        if row["item_id"] in cov:
                            raise SystemExit(
                                "REFUSED: coverage run repeats item_id "
                                f"{row['item_id']!r}")
                        cov[row["item_id"]] = row["coverage_lines"]
        by_mutant, uncovered = M.map_mutants_to_items(manifest, cov)
        del _load_release
        if getattr(args, "release", None):
            release_ids = A.load_release_ids(args.release)
            bad_items = sorted(
                {item for items in by_mutant.values() for item in items}
                - release_ids)
            if bad_items:
                raise SystemExit(
                    f"REFUSED: coverage map names item IDs outside --release, "
                    f"e.g. {bad_items[:3]}")
            payload = A.build_map_artifact(
                manifest, by_mutant, uncovered,
                coverage_sha256=A.sha256_file(args.coverage_run),
                release_sha256=A.sha256_file(args.release))
            A.validate_map(payload, manifest, release_ids=release_ids,
                           coverage_by_item=cov)
        else:
            # Compatibility for exploratory calls. This shape is accepted only
            # by the explicitly limited legacy_consistency validator and
            # cannot become a canonical publishable map.
            payload = {"by_mutant": by_mutant, "uncovered": uncovered}
        AUDIT.write_reserved_json(out_fd, payload)
        covered = len(by_mutant)
        print(json.dumps({"out": args.out, "mutants": manifest["n"],
                          "covered": covered, "uncovered": len(uncovered),
                          "items_with_coverage": len(cov)}, indent=1))
        return 0

    image_id = _bound_container_image(args.container)
    print(f"image_id: {image_id}")
    operator_profile = getattr(args, "operator_profile", "v2")
    operators = (M.OPERATORS_V1 if operator_profile == "v1"
                 else M.OPERATORS)
    try:
        record_enumerator_rev = M.record_enumerator_revision(
            operator_profile,
            requested=getattr(args, "record_enumerator_rev", False))
        enumerator_identity = A.pinned_enumerator_identity(
            "r2t/php/mutate.php")
        expected_enumerator_rev = (
            enumerator_identity["enumerator_rev"]
            if record_enumerator_rev else None)
        # WHICH TREE IS THE POPULATION.  Both halves -- what the enumerator
        # walks and what the manifest keeps -- come from the boundary's
        # `behat.prod_paths` row, the same row the production index is built
        # over.  They were two CoreShop literals, and on a second Behat
        # project that meant enumerating `src/Sylius/**` and then excluding
        # all of it: keeps that match nothing exclude everything.  An
        # explicit `--path` still decides what is WALKED; it cannot widen
        # what is KEPT, because the manifest's keep roots are what
        # `_audit_roots` recomputes the audited source set from.
        #
        # Derived HERE, beside the other argv-decided facts, rather than
        # beside its two uses: a row that names no root can then refuse in a
        # line, instead of after an enumeration that is allowed 3600 s.
        behat = behat_project(b)
        population_exclusions = M.exclusions_for_prod_paths(behat.prod_paths)
        walked_paths = list(args.path or behat.prod_paths)
    except (ValueError, A.MutationAssetRefused) as exc:
        message = str(exc)
        raise SystemExit(message if message.startswith("REFUSED:")
                         else f"REFUSED: {message}") from exc
    scratch = os.path.join(b.repo_root, "var", "bench_mutate")
    scratch_created = False
    try:
        scratch = AUDIT.create_private_scratch(
            b.repo_root, os.path.join("var", "bench_mutate"))
        scratch_created = True
        AUDIT.stage_preserved_file(
            os.path.join(PACKAGE_DIR, "php", "mutate.php"),
            os.path.join(scratch, "mutate.php"),
            enumerator_identity["sha256"], label="PHP enumerator")
    except (OSError, A.MutationAssetRefused) as exc:
        if scratch_created:
            shutil.rmtree(scratch, ignore_errors=True)
        message = str(exc)
        raise SystemExit(message if message.startswith("REFUSED:")
                         else f"REFUSED: cannot stage PHP enumerator: "
                              f"{message}") from exc
    try:
        build_outputs = [args.out] + ([args.raw_out]
                                      if getattr(args, "raw_out", None)
                                      else [])
        build_fds = AUDIT.reserve_outputs(
            build_outputs, input_paths=(args.boundary,))
        out_fd = build_fds[0]
        raw_out_fd = build_fds[1] if len(build_fds) == 2 else None
    except A.MutationAssetRefused as exc:
        shutil.rmtree(scratch, ignore_errors=True)
        raise SystemExit(str(exc))
    runner = DockerRunner(args.container, workdir=args.workdir)
    cp = runner.run("php var/bench_mutate/mutate.php --root "
                    + runner.workdir + " "
                    + " ".join(f"--path {p}" for p in walked_paths)
                    + f" --operator-profile {operator_profile}"
                    + (" --record-enumerator-rev"
                       if record_enumerator_rev else "")
                    + " --out var/bench_mutate/raw.json", timeout=3600)
    produced = os.path.join(scratch, "raw.json")
    if cp.returncode != 0 or not os.path.isfile(produced):
        shutil.rmtree(scratch, ignore_errors=True)
        raise SystemExit(f"mutate.php failed (rc={cp.returncode}): "
                         f"{(cp.stderr or cp.stdout or '')[-800:]}")
    parser_identity = M.read_parser_version(
        os.path.join(b.repo_root, "composer.lock"))
    # The enumerator reports the installed package version; the manifest binds
    # the stronger lock identity including its dist reference.
    parser_report = parser_identity.split(" ", 1)[-1].split("@", 1)[0]
    try:
        envelope = A.load_enumerator_envelope(
            produced, expected_engine=M.ENGINE,
            expected_engine_version=M.ENGINE_VERSION,
            expected_parser_version=parser_report,
            expected_enumerator_rev=expected_enumerator_rev)
    except A.MutationAssetRefused as exc:
        shutil.rmtree(scratch, ignore_errors=True)
        raise SystemExit(str(exc))
    raw = envelope["mutants"]
    raw_manifest = M.build_manifest(
        raw, parser_version=parser_identity,
        operators=operators,
        exclusions=population_exclusions,
        n_invalid=envelope.get("n_invalid"),
        enumerator_rev=envelope.get("enumerator_rev"))
    # Only PRODUCTION code may be scored, and only the project's own product
    # code: a project may also DECLARE subtrees inside its production roots
    # that are not product code (`behat.mutation_exclude` -- tests, specs,
    # migrations, DI configuration, fixtures), which the boundary cannot
    # separate because it answers a question about the Behat glue. Both
    # leave the scored role; the immutable raw catalogue keeps every mutant
    # the engine produced, remains separately identified, and is named by
    # the derived manifest.
    #
    # `src/CoreShop/Bundle/TestBundle` sits under a production prefix but the
    # boundary classifies it RETAINED — it is the harness's own scaffolding,
    # kept precisely so every candidate can use it. Mutating it measures the
    # scaffolding: 258 of 10,463 mutants landed there, and because the stub
    # exercises the scaffolding like everything else, it "killed" 14 of them
    # with empty method bodies. That pushed the stub's measured recall to
    # 0.029 against a gate threshold of 0.02 — the anti-vacuity check failing
    # for a reason that had nothing to do with vacuity.
    manifest = A.derive_boundary_scored_manifest(
        raw_manifest, b, args.boundary, A.sha256_file(args.boundary),
        sample=args.sample, seed=args.seed)
    non_production = manifest["n_non_production_excluded"]
    # Of those, the ones the project DECLARED non-product inside its own
    # production roots (`behat.mutation_exclude`), rather than the ones the
    # boundary classified as glue.  Printed because it is the number an
    # operator checks the row by, and the two totals answer different
    # questions: on Sylius they are the same 31,297 of 43,670, because the
    # walk is confined to the production roots and the boundary classifies
    # nothing inside them as glue; on CoreShop this one is 0 while 258 rows
    # still leave by classification (`Bundle/TestBundle`).
    declared_non_product = manifest.get("n_mutation_excluded", 0)
    shutil.rmtree(scratch, ignore_errors=True)
    if os.path.isdir(scratch):
        runner.run("rm -rf var/bench_mutate")
    AUDIT.write_reserved_json(out_fd, manifest)
    raw_out = getattr(args, "raw_out", None)
    if raw_out:
        AUDIT.write_reserved_json(raw_out_fd, raw_manifest)
    print(json.dumps({"out": args.out, "n": manifest["n"],
                      "n_excluded": manifest["n_excluded"],
                      "n_non_production_excluded": non_production,
                      "n_mutation_excluded": declared_non_product,
                      "raw_n": raw_manifest["n"],
                      "raw_digest": raw_manifest["digest"],
                      "raw_out": raw_out,
                      "digest": manifest["digest"],
                      "engine": manifest["engine"],
                      "parser": manifest["parser"],
                      "image_id": image_id}, indent=1))
    return 0


#: What `dispatch` decides from the TYPED argv before any parser is built,
#: handed to every component's `register` and read again after parsing: the
#: whole argv, the verb it names (None when it names none), the tokens after
#: that verb and, for the one `run` shape that gets the two agent-input
#: options, that tail -- else None.
Request = namedtuple("Request",
                     "argv command tail agent_publication_tail")


class Verbs:
    """One component's handle on the subcommand table.

    `add_parser` is argparse's, with the component's persona tag written in
    front of the verb's help and description; `add_subparsers` opens a verb's
    own table under the same tag, so a nested verb (`worker plan`, `bundle
    fetch`) is tagged by the component that registered its parent.
    """

    def __init__(self, table, persona: str):
        self._table = table
        self._persona = persona

    def add_parser(self, name: str, **kwargs):
        for key in ("help", "description"):
            if key in kwargs:
                kwargs[key] = f"{self._persona} {kwargs[key]}"
        return self._table.add_parser(name, **kwargs)

    def add_subparsers(self, parser, **kwargs):
        return Verbs(parser.add_subparsers(**kwargs), self._persona)


def dispatch(argv, components: tuple, description: str, *,
             before_test_quality_execute=None) -> int:
    """Run one command line through the components' verbs.

    `components` are modules, each with `PERSONA` and `register(verbs,
    request)`, in menu order.  Everything else here -- the global options,
    the argv scan that names the verb before any parser exists, the
    post-parse bindings -- is what `main` did when the verbs were one file.
    """
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    global_value_options = {
        "--repo", "--boundary", "--artifacts", "--gold", "--container",
        "--worker", "--workdir", "--features", "--docker-authority",
    }
    command = None
    index = 0
    while index < len(effective_argv):
        token = effective_argv[index]
        if token in global_value_options:
            index += 2
            continue
        if any(token.startswith(option + "=")
               for option in global_value_options):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        command = token
        break
    # Section 3's one explicit path, decided from the TYPED tokens: it is the
    # only request that gets the two agent-input options at all, so every
    # other `run` keeps its byte-compatible parser and `--help`.  Asked only
    # for `run`: the answer needs the agent producer's admitted kinds, and
    # every other verb builds its parser without the agent component.
    agent_publication_tail = None
    if command == "run":
        from .runner import is_agent_publication_request
        if is_agent_publication_request(effective_argv[index + 1:]):
            agent_publication_tail = effective_argv[index + 1:]
    request = Request(effective_argv, command, effective_argv[index + 1:],
                      agent_publication_tail)

    ap = argparse.ArgumentParser(prog="r2t", description=description)
    ap.add_argument("--repo", default=None,
                    help="the workspace this process reads and writes "
                         "(default: the boundary config's own). It sets BOTH "
                         "the classification root and the write root; there is "
                         "deliberately no second --workspace flag to disagree "
                         "with it")
    ap.add_argument("--boundary", default=DEFAULT_BOUNDARY)
    ap.add_argument("--artifacts", default=DEFAULT_ARTIFACTS)
    ap.add_argument("--gold", default=DEFAULT_GOLD)
    ap.add_argument("--container", default=DEFAULT_CONTAINER)
    ap.add_argument("--worker", default=None, metavar="FILE",
                    help="a worker spec from `worker plan`. Sets --repo, "
                         "--container and --workdir together, and supplies "
                         "the schema and credential identity a worker "
                         "manifest needs")
    ap.add_argument("--workdir", default="/var/www/html",
                    help="where --repo is bind-mounted INSIDE --container. "
                         "Every worker is mounted at the default by "
                         "convention; the flag exists so that convention is "
                         "checkable rather than hard-coded")
    ap.add_argument("--features", default="features/domain")
    ap.add_argument(
        "--docker-authority", default=None, metavar="FILE",
        help="verified r2t.docker-execution-authority/v1 artifact. Required "
             "only when the selected verb reaches Docker; reporting and "
             "source-only verbs remain Docker-free")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for component in components:
        component.register(Verbs(sub, component.PERSONA), request)

    args = ap.parse_args(effective_argv)
    if getattr(args, "cmd", None) == "run":
        explicit = {
            name for name, value in (
                ("--condition", args.condition),
                ("--protocol", args.protocol),
                ("--trials", args.trials
                 if args.trials is not _SUBMITTED_TRIALS_UNSET else None),
                ("--replay", args.replay),
                ("--limit", args.limit),
                ("--item", args.item),
                ("--shard", args.shard),
                ("--of", args.of),
                # `--model` defaults to None and nothing writes it before
                # this capture, so a non-None value here IS the operator's
                # explicit flag -- the one that would assert a model this
                # harness never invoked for submitted bytes.
                ("--model", args.model),
            ) if value is not None
        }
        args._submitted_explicit_options = frozenset(explicit)
        if args.trials is _SUBMITTED_TRIALS_UNSET:
            args.trials = 0
    args._container_explicit = any(
        token == "--container" or token.startswith("--container=")
        for token in effective_argv)
    args._workdir_explicit = any(
        token == "--workdir" or token.startswith("--workdir=")
        for token in effective_argv)
    _bind_data_defaults(args)
    if agent_publication_tail is not None:
        args._agent_publication_argv = list(agent_publication_tail)
    if _SLICE3_CAMPAIGN_CONTEXT is not None:
        if args.cmd != "campaign":
            raise SystemExit(
                "REFUSED: Slice-3 campaign capability reached another verb")
        args._slice3_campaign_context = _SLICE3_CAMPAIGN_CONTEXT
    if _SLICE3_CELL_CONTEXT is not None:
        if args.cmd != "run" or not getattr(args, "publication_v3", False) \
                or agent_publication_tail is None:
            raise SystemExit(
                "REFUSED: Slice-3 cell capability requires the exact agent "
                "publication run path")
        args._slice3_cell_context = _SLICE3_CELL_CONTEXT
    from ..toolkit import docx_v2_workload
    if docx_v2_workload.has_active_capability():
        docx_v2_workload.bind_cli(args, effective_argv)
    from ..core.docker_cli import DockerEndpointRefused, configure
    try:
        if args.cmd == "docker-authority" and args.docker_authority is not None:
            raise DockerEndpointRefused(
                "REFUSED: docker-authority inspect takes --docker-host and "
                "--docker-cli; it does not consume an existing authority")
        configure(authority_path=args.docker_authority)
    except DockerEndpointRefused as e:
        raise SystemExit(str(e)) from e
    _apply_worker(args)
    _apply_protocol(args, effective_argv)
    if _SLICE3_PREPARE_ONLY:
        from ..agents.publication import prepare_agent_publication_v3
        return prepare_agent_publication_v3(
            args, argv_tail=args._agent_publication_argv,
            environ=_SLICE3_PREPARE_ENVIRON)
    try:
        if args.cmd == "test-quality" and before_test_quality_execute is not None:
            return cmd_test_quality(args, before_execute=before_test_quality_execute)
        return args.func(args)
    except DockerEndpointRefused as e:
        raise SystemExit(str(e)) from e


def main(argv=None) -> int:
    """`python3 -m r2t.bench.cli`: the consumer's verbs alone."""
    return dispatch(argv, (sys.modules[__name__],),
                    description=__doc__.split("\n")[0])


def register(verbs, request) -> None:
    """Every consumer verb, in the order `python3 -m r2t.cli` lists them."""
    # Keep parser-owned defaults and route choices joined to their source
    # modules.  Imported inside `register` like every other module reference
    # in this file, so importing the CLI itself remains cheap.  Both project
    # enums are derived from the reviewed dataset manifest, so adding a
    # project stays a data change; see doctor._manifest_projects.
    from ..toolkit.doctor import (
        MANIFEST_PROJECTS as MANIFEST_BUNDLE_PROJECTS,
        SUPPORTED_PROJECTS as CONSUMER_ROUTE_PROJECTS)
    from .mutation_run import REFERENCE_CONTROL_ROLES

    command, tail = request.command, request.tail
    # Keep the frozen consumer parser unchanged unless the native option is named.
    go_control_plans_cli = any(
        token == "--reference-go-control-plans"
        or token.startswith("--reference-go-control-plans=") for token in tail)
    agent_publication_tail = request.agent_publication_tail
    publication_merge_cli = command == "merge" and "--publication-v3" in tail
    # Section 10 bounds section 4.1's campaign-creation moment the same way
    # `run`'s agent-publication tail is bounded: the option that ENTERS that
    # moment exists only on a command line that TYPES it, so every
    # pre-amendment `campaign` keeps its byte-compatible parser and `--help`
    # -- including the abbreviations argparse resolved for it, which a
    # second `--agent-` option would turn into an error.
    campaign_backend_tail = (
        request.tail
        if command == "campaign"
        and any(token == "--agent-backend-runtime"
                or token.startswith("--agent-backend-runtime=")
                for token in request.tail)
        else None)
    # The three I5 consumers gain their publication grammar only when their
    # OWN token is present, so every default parser stays byte-compatible.
    publication_consumer_cli = (
        command if command in _PUBLICATION_CONSUMER_OCCURRENCES
        and "--publication-v3" in tail else None)
    if publication_consumer_cli is not None:
        _publication_consumer_scan(publication_consumer_cli, tail)
    java_mutants_cli = command == "mutants" and _cucumber_mutants_request(tail)
    # `--adapter` is closed at parse time to what THIS checkout can build, so
    # an agent arm a benchmark-only checkout does not ship is refused before
    # any handler runs, `--help` included.  Asked only for the two verbs
    # that take it: the answer reads the agent registry when it is present.
    adapter_choices = None
    if command in ("run", "generate"):
        from .runner import adapter_choices as _adapter_choices
        adapter_choices = _adapter_choices()


    p = verbs.add_parser(
        "docker-authority",
        help="inspect one explicit current-user rootless Docker "
             "authority")
    authority_sub = verbs.add_subparsers(p, dest="authority_action", required=True)
    p = authority_sub.add_parser(
        "inspect",
        help="run only the read-only version/info eligibility probes")
    p.add_argument("--docker-host", required=True, metavar="UNIX_SOCKET",
                   help="explicit URI-safe absolute local Unix socket")
    p.add_argument("--docker-cli", required=True, metavar="ABS_PATH",
                   help="exact absolute Docker CLI path to bind")
    p.add_argument("--out", required=True, metavar="ABS_PATH",
                   help="new owner-private authority JSON; never overwritten")
    p.set_defaults(func=cmd_docker_authority)

    p = verbs.add_parser(
        "doctor",
        help="read-only reference-host and project preflight")
    p.add_argument("--project", required=True, metavar="PROJECT",
                   choices=CONSUMER_ROUTE_PROJECTS,
                   help="project with a current consumer route: "
                        + ", ".join(CONSUMER_ROUTE_PROJECTS))
    p.add_argument("--agent", default=None, metavar="AGENT",
                   help="also check this supported agent environment and model")
    p.add_argument("--llm-config", default=None, metavar="ABS_FILE",
                   help="model configuration the campaign uses; keep it "
                        "outside the checkout, whose cleanliness the Docker "
                        "execution authority attests")
    p.set_defaults(func=cmd_doctor)

    p = verbs.add_parser(
        "report",
        help="report raw outcomes, test quality and cost for one or "
             "more runs",
        **_publication_parser_kwargs("report", publication_consumer_cli))
    p.add_argument("--run", action="append", required=True,
                   help="a run JSONL; repeat to compare (e.g. gold vs a model)")
    p.add_argument("--test-quality", action="append", default=None,
                   metavar="SUMMARY_JSON",
                   help="explicit binding-aware test-quality summary for the "
                        "corresponding --run; repeat once per run, in the "
                        "same order. Required for a validated legacy wrapper "
                        "that intentionally coexists with its preserved old "
                        "sidecar")
    _add_reference_controls_options(p, go_control_plans=go_control_plans_cli)
    p.add_argument("--non-vacuous-out", default=None, metavar="JSON",
                   help="also write the code-of-record non-vacuous block "
                        "(r2t.bench.report.non_vacuous) of the one --run and "
                        "its one --test-quality, revalidated through the same "
                        "reference reader, to this new file")
    p.add_argument("--release", action="append", default=None,
                   metavar="JSONL",
                   help="explicit validated planned workset for the "
                        "corresponding --run; repeat once per run in the same "
                        "order. Otherwise reporting resolves matching "
                        "row-stamped subset bytes, then a verified count-only "
                        "checkpoint, or labels genuinely unstamped output "
                        "unpinned")
    p.add_argument("--per-item", action="store_true")
    p.add_argument("--only", default=None,
                   help="with --per-item, show only this outcome")
    p.add_argument("--group-by", default=None, choices=("project",),
                   help="rows spanning more than one project are REFUSED "
                        "without this: a pooled rate over two projects is a "
                        "weighted average whose weights are how many items "
                        "each contributed. With it, each project gets a "
                        "complete report plus the preregistered equal-weight "
                        "functional-pass macro; no pooled rate or "
                        "cross-project reference-equivalent mean is produced")
    if publication_consumer_cli == "report":
        _add_publication_consumer_options(p, out=True)
    p.set_defaults(func=cmd_report)

    p = verbs.add_parser("compare",
                       help="two runs over ONE fixed item set: "
                            "cluster-aware "
                            "intervals and an exact paired test",
                       **_publication_parser_kwargs(
                           "compare", publication_consumer_cli))
    p.add_argument("--run", action="append", required=True,
                   help="a run JSONL; give it exactly twice (A then B)")
    p.add_argument("--gold-dir", default=DEFAULT_GOLD_DIR, metavar="DIR",
                   help="a project release directory containing "
                        "closure_clusters.json, or an installed bundle's "
                        f"gold directory (default: {DEFAULT_GOLD_DIR})")
    p.add_argument("--items", default=None, metavar="JSONL",
                   help="fix the denominator to this subset (e.g. "
                        "release/eval100.jsonl). Without it the denominator "
                        "is the runs' own item set, which must be identical "
                        "in both")
    p.add_argument("--metric", default="pass",
                   choices=("pass", "non_vacuous_pass"),
                   help="WHICH outcome is paired. `pass` is the functional "
                        "one and the default (unchanged rendering). "
                        "`non_vacuous_pass` pairs the metric the measurement "
                        "contract leads with: a pass whose test kills "
                        "everything the reference kills on that item, read "
                        "from the test-quality sidecar beside each run. It "
                        "REFUSES rather than degrading to `pass` when a "
                        "sidecar is missing or stale, or when the two arms "
                        "were scored by different mutation engines -- engine "
                        "identity being the (name, version) pair, either half "
                        "of which changes which mutants exist")
    p.add_argument("--test-quality", action="append", default=None,
                   metavar="SUMMARY_JSON",
                   help="explicit binding-aware test-quality summary for the "
                        "corresponding --run arm; supply exactly twice in A/B "
                        "order. This is how a validated legacy-rebinding "
                        "wrapper coexists with its preserved old sidecar")
    if publication_consumer_cli == "compare":
        _add_publication_consumer_options(p, out=True)
    p.set_defaults(func=cmd_compare)

    p = verbs.add_parser(
        "stamp-draw",
        help="record that a row is a REPEAT draw of its item, and "
             "why the prior attempt was discarded, from the evidence on disk")
    p.add_argument("--run", required=True, metavar="JSONL",
                   help="the run file holding the SURVIVING row (exactly one "
                        "line is rewritten; every other line is copied byte "
                        "for byte)")
    p.add_argument("--item", required=True, metavar="ITEM_ID",
                   help="the item that was drawn twice")
    p.add_argument("--discarded", required=True, metavar="JSONL",
                   help="the file the DISCARDED attempt(s) were moved into "
                        "(a quarantine sidecar, a pre-rerun backup). It is "
                        "the evidence: the draw number, what the prior "
                        "attempt scored and the campaign it belonged to are "
                        "all read from it, and the command refuses when it "
                        "holds no attempt at --item")
    p.add_argument("--reason", required=True,
                   choices=("benchmark_infrastructure", "candidate_caused"),
                   help="WHY the prior attempt was discarded, and the one "
                        "thing here that cannot be derived: "
                        "`benchmark_infrastructure` is the SPEC 8 rule 4 "
                        "re-run of OUR failure, declared ONLY when the "
                        "discarded attempt made no model call -- the "
                        "retained row stays the first candidate observation "
                        "and is disclosed as a restoration, not a redraw; "
                        "`candidate_caused` means the prior attempt failed "
                        "through the submission's own behaviour, so this row "
                        "is a second draw and every table containing it says "
                        "so")
    p.add_argument("--evidence", action="append", metavar="PATH",
                   help="a file or directory supporting --reason (a "
                        "quarantine README, a preserved trajectory). Hashed "
                        "into the stamp, so the declaration can be checked "
                        "later rather than taken on trust; repeatable")
    p.add_argument("--dry-run", action="store_true",
                   help="derive and print the stamp without writing it")
    p.add_argument("--update-campaign-sidecar", action="store_true",
                   help="carry `<run>.campaign.json`'s rows_digest forward "
                        "onto the stamped file, recording the superseded "
                        "digest and the reason in `rows_digest_history`. "
                        "REQUIRED when such a sidecar sits beside the run and "
                        "still describes it: stamping rewrites one line, "
                        "nothing re-verifies that digest at read time, and an "
                        "attestation left quietly false is worse than none")
    p.set_defaults(func=cmd_stamp_draw)

    p = verbs.add_parser("results",
                       help="THE canonical results table: the "
                            "failure ladder "
                            "over all instances, then mutation, coverage and "
                            "api quality over the passed ones",
                       **_publication_parser_kwargs(
                           "results", publication_consumer_cli))
    p.add_argument("--run", required=True,
                   help="the run JSONL to score (one; this command produces "
                        "ONE system's table, not a comparison)")
    p.add_argument("--release", default=None, metavar="JSONL",
                   help="explicit validated planned workset. It must reconcile "
                        "with every row-stamped population identity; otherwise "
                        "matching row-stamped subset bytes or a verified "
                        "count-only checkpoint are used, and a genuinely "
                        "unstamped development run is labelled unpinned")
    # `dest` because the top-level `--gold` is the gold TREE and this is the
    # gold RUN.  Same word for two objects is the confusion to design around,
    # so they land in different attributes and pointing this one at a
    # directory is refused by name rather than failing inside a JSON parser.
    p.add_argument("--gold", dest="gold_run", default=None, metavar="RUN",
                   help="gold's run JSONL, the upper bound coverage and api "
                        "are measured against (default: the gold sweep found "
                        "from the installed bundle's validated scoring_gold "
                        "role, else under <artifacts>/runs -- see "
                        "results.GOLD_RUN_NAMES; "
                        "whichever is used is printed in the table)")
    p.add_argument("--test-quality", default=None, metavar="SUMMARY_JSON",
                   help="a `test-quality` summary.json (default: the sidecar "
                        "beside --run, which is where `test-quality` writes "
                        "one). Without it the mutation rows print `not "
                        "scored`, never 0.0")
    _add_reference_controls_options(p, go_control_plans=go_control_plans_cli)
    p.add_argument("--prod-index", default=None, metavar="FILE",
                   help="the production method index api calls are joined "
                        "against (default: this language's filename under "
                        "<artifacts>; see core.constants.PROD_INDEX_NAMES; "
                        "pass this flag for an index stored elsewhere)")
    p.add_argument("--profile", default=None,
                   help="the task profile whose `api_scoring` capability "
                        "decides whether API similarity uses a production "
                        "method index or is not measured (default: "
                        "profile_<project>.yml beside --boundary)")
    # The section 6.2/6.3 secondary rows. Every one of them is OFF unless its
    # own input is given, and the canonical thirteen never move: these add a
    # labelled block below the table, they do not edit a row in it.
    p.add_argument("--target-regions", default=None, metavar="JSON",
                   help="a `target-regions` artifact (r2t.target-regions/1): "
                        "adds target-region recall and the reaches-target "
                        "rate below the canonical table")
    p.add_argument("--items", default=None, metavar="JSONL",
                   help="the release items file whose rows carry "
                        "`checked_interfaces`: adds the undisclosed-api row, "
                        "which scores `D_G \\ I` against `D_C \\ I`")
    p.add_argument("--control-floors", default=None, metavar="JSON",
                   help="a `control-floors` artifact (r2t.control-floors/1): "
                        "prints the measured floors -- what a sibling gold "
                        "test, assertion-stripped gold and a stub already "
                        "score -- as their own table below the rows")
    p.add_argument("--clusters", default=None, metavar="DIR",
                   help="a release directory holding closure_clusters.json: "
                        "attaches a cluster bootstrap 95%% CI to the "
                        "secondary rows (withheld below 20 clusters, as "
                        "`compare` withholds it)")
    p.add_argument("--infrastructure-exclusions", default=None, metavar="JSON",
                   help="the ratified-exclusions file `run_agent_cells.py "
                        "finalize --infrastructure-no-row` writes: missing "
                        "planned items whose attempt reached the agent and was "
                        "killed without a row, ratified by the owner as "
                        "infrastructure. They stay in missing_planned_ids and "
                        "are disclosed; when they are all that is missing the "
                        "canonical values are admitted "
                        "(REPORTING_POPULATION_COMPLETENESS_SPEC.md section 9)")
    p.add_argument("--format", default="text",
                   choices=("text", "json", "markdown", "markdown-legacy"),
                   help="text for reading, markdown to paste into a paper, "
                        "json for the same numbers as data (plus the "
                        "per-instance evidence the table does not print). "
                        "markdown-legacy emits the twelve-row payload ALONE, "
                        "with no provenance and no notes: it is the format to "
                        "diff a new rendering against a published one, and it "
                        "is pinned byte-for-byte in release/v1")
    p.add_argument("--out", default=None, metavar="FILE",
                   help="write the rendering here instead of stdout")
    # `results` reuses its existing --out; publication mode only makes it
    # mandatory, which the occurrence scan already required.
    if publication_consumer_cli == "results":
        _add_publication_consumer_options(p, out=False)
    p.set_defaults(func=cmd_results)

    p = verbs.add_parser(
        "tasks", help="export admitted benchmark questions as JSONL")
    p.add_argument("--release", default=os.path.join(
        BENCHMARK, "release", "items_v1.jsonl"), metavar="FILE",
        help="single-project task source JSONL (default: the CoreShop release)")
    p.add_argument("--out", required=True, metavar="FILE",
                   help="write the admitted task views as JSONL")
    p.add_argument("--profile", default=None, metavar="FILE",
                   help="profile for --contract's prompt base and placement "
                        "fields (default: config/profile_<project>.yml). "
                        "Validated against the task project; task rows "
                        "are unchanged")
    p.add_argument("--contract", default=None, metavar="FILE",
                   help="also write the answering contract as one JSON file: "
                        "the prompt this study's own agent arms receive, plus "
                        "where a submission is accepted and how it is "
                        "recognised. Rendered from "
                        "--profile or config/profile_<project>.yml; the "
                        "per-condition slots the arms fill are left open")
    p.set_defaults(func=cmd_tasks)

    if command == "tier1b-verdict":
        # This repository pins argparse's existing top-level choice
        # diagnostics. Like the source-closed `image` and
        # `java-reality-spike` routes above, expose this new parser only when
        # its own command token selected it, so unrelated errors stay stable.
        p = verbs.add_parser(
            "tier1b-verdict",
            help="reproduce CoreShop's Tier-1b byte-pinned published table")
        p.add_argument(
            "--coreshop-test-quality-wrapper", default=None, metavar="JSON",
            help="validated local wrapper produced by `test-quality-bind` "
                 "(default: $R2T_CORESHOP_TEST_QUALITY_WRAPPER)")
        p.set_defaults(func=cmd_tier1b_verdict)

    p = verbs.add_parser(
        "campaign-results",
        help="internal: render canonical results for a descriptor's "
             "cells side by side")
    p.add_argument("--descriptor", required=True, metavar="JSON_OR_YAML",
                   help="ordered campaign-cell descriptor")
    p.add_argument("--format", default="text",
                   choices=("text", "markdown", "json"))
    p.add_argument("--out", default=None, metavar="FILE",
                   help="write the rendering here instead of stdout")
    p.set_defaults(func=cmd_campaign_results)

    p = verbs.add_parser(
        "generate",
        help="generate adapter outputs for admitted release items")
    p.add_argument("--adapter", required=True, choices=adapter_choices,
                   metavar="ADAPTER")
    p.add_argument("--release", default=os.path.join(BENCHMARK, "release",
                                                     "items_v1.jsonl"))
    p.add_argument("--out", required=True)
    p.add_argument("--workers", type=int, default=8,
                   help="concurrent generations; execution stays serial")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--llm-config", default=None)
    p.add_argument("--max-tokens", type=int, default=64000)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--condition", default=None)
    p.add_argument("--profile", default=None, help=PROFILE_HELP)
    _add_budget_flags(p)
    p.add_argument("--agent-timeout", type=int, default=3600)
    p.add_argument("--agent-command", "--openhands-command", default=None,
                   dest="agent_command", help=AGENT_COMMAND_HELP)
    p.add_argument("--trajectory-dir", default=None)
    p.add_argument("--visibility-map", default=None,
                   help="reviewed target-body map for source-visibility generation")
    p.add_argument("--seed", default=DEFAULT_SEED,
                   help="qualified runtime seed for source-visibility generation")
    p.add_argument("--coverage", action="store_true",
                   help="recorded in the stamp so the cache matches the "
                        "execution it was generated for")
    p.add_argument(
        "--functional-only", action="store_true",
        help="explicitly accept generation without full metric readiness; "
             "the limitation is printed before launch")
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--retry-failed", action="store_true",
                   help="re-generate rows whose metadata records an adapter "
                        "or driver failure rather than a result; parse_error "
                        "and empty results are RESULTS and are never retried")
    p.add_argument("--protocol", default=None, metavar="N", help=PROTOCOL_HELP)
    p.set_defaults(func=cmd_generate)

    p = verbs.add_parser(
        "run",
        help="run one adapter on a bound worker; --publication-v3 is "
             "CLOSED outside no-database fixtures and openhands/aider agents",
        **({"allow_abbrev": False} if agent_publication_tail is not None
           else {}))
    p.add_argument(
        "--publication-v3", action="store_true",
        help="explicit result-v3 run-shard checkpoint/receipt lifecycle; "
             "admits empty/gold/stripped-gold/stub on no-database profiles and "
             "openhands/aider agents; every other adapter/profile combination "
             "is CLOSED")
    if agent_publication_tail is not None:
        # Section 3's two additionally required bindings.  They exist only on
        # this request, so no other `run` gains an option or a default.
        p.add_argument(
            "--agent-backend-runtime", default=None, metavar="ABS_PATH",
            help="verified r2t.agent-backend-runtime/v2 manifest for the "
                 "selected built-in backend")
        p.add_argument(
            "--agent-seed-manifest", default=None, metavar="ABS_PATH",
            help="verified r2t.agent-seed/v1 manifest whose snapshot this "
                 "worker's pre-agent workspace projection must equal")
    p.add_argument("--adapter", required=True, choices=adapter_choices,
                   metavar="ADAPTER")
    p.add_argument("--release", default=os.path.join(BENCHMARK, "release",
                                                     "items_v1.jsonl"))
    p.add_argument("--out", default=None)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--item", action="append", default=None)
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--coverage", action="store_true")
    p.add_argument("--keep-artifacts", default=None, metavar="DIR",
                   help="per-item evaluation artifacts (solution, full behat "
                        "log, record, coverage) under DIR/<adapter>/<item-key>; "
                        "the item-key is the release's gold filename, so the "
                        "two join. Off by default: measured at 316-382 KiB per "
                        "item for gold with coverage, whose 17-21 file closure "
                        "dominates (~145 MB for the 422-item release); a "
                        "system submitting one context file costs ~115 KiB an "
                        "item once its coverage is comparable to gold's")
    p.add_argument("--model", default=None)
    p.add_argument("--llm-config", default=None,
                   help="JSON with base_url/api_key/model; or use the "
                        "R2T_LLM_* environment variables")
    _add_budget_flags(p)
    p.add_argument("--agent-timeout", type=int, default=3600,
                   help="agent adapters: wall-clock cap per item")
    p.add_argument("--agent-command", "--openhands-command", default=None,
                   dest="agent_command", help=AGENT_COMMAND_HELP)
    p.add_argument("--condition", default=None,
                   help="evaluation condition this sweep belongs to; stamped "
                        "on every row and required to match on resume")
    p.add_argument("--profile", default=None, help=PROFILE_HELP)
    p.add_argument("--trajectory-dir", default=None,
                   help="agent adapters: where to persist trajectories "
                        "(default <artifacts>/trajectories); '' disables")
    p.add_argument("--visibility-map", default=None,
                   help="reviewed target-body map for source-visibility generation")
    p.add_argument("--seed", default=DEFAULT_SEED,
                   help="qualified runtime seed for source-visibility generation")
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-tokens", type=int, default=64000,
                   help="single-shot adapters: completion budget. Must cover\n"
                        "REASONING tokens too — a reasoning model shares one\n"
                        "budget between thinking and answer, and a cap that\n"
                        "truncates the answer is scored as the system failing.")
    p.add_argument("--no-resume", action="store_true",
                   help="ignore rows already in the out file (they are still "
                        "kept; the new rows are appended)")
    p.add_argument("--replay", default=None,
                   help="with --adapter replay: the generation cache to "
                        "re-execute, so a harness fix or a new metric does "
                        "not require paying for generation again")
    p.add_argument("--candidates", default=None,
                   help="with --adapter submitted: external candidate JSONL "
                        "to execute over the full admitted release")
    p.add_argument("--sensitivity", default=None,
                   choices=("webmock_world_v1",),
                   help="with --adapter replay: a labelled post-hoc sensitivity "
                        "re-execution; rows carry the label. webmock_world_v1: "
                        "e-petitions (specifications/E_PETITIONS_WEBMOCK_WORLD_"
                        "SENSITIVITY_SPEC.md). coddy_retained_helpers_v1 is "
                        "retired: harness 25 supplies the coddy-agent "
                        "retained-test helpers on every candidate execution "
                        "(specifications/EVALUATOR_CORRECTIONS_20261015_"
                        "AMENDMENT.md)")
    p.add_argument("--repro-check", type=int, default=10,
                   help="re-execute this many items at the end and refuse to "
                        "trust the run if any outcome changed (0 disables)")
    p.add_argument("--retry-failed", action="store_true",
                   help="re-run items whose recorded outcome was a harness or "
                        "transport failure rather than a result")
    p.add_argument("--shard", type=int, default=None,
                   help="this worker's index, 0-based (H4). Required, and "
                        "must equal the index the --worker evidence "
                        "authenticates, for every live run including a k=1 "
                        "diagnostic; omitting it is refused, not defaulted")
    p.add_argument("--of", type=int, default=None, metavar="K",
                   help="total workers. Assignment is sha1(item_id) %% K, so "
                        "it is content-based: adding one item to the release "
                        "does not re-shuffle which worker every other item "
                        "lands on")
    p.add_argument("--trials", type=_trials,
                   default=_SUBMITTED_TRIALS_UNSET, metavar="K",
                   help="C3: execution feedback over the agent's own "
                        "workspace. `unlimited` is the shipped arm — a trial "
                        "is a terminal tool call, so --max-iterations already "
                        "bounds how many an agent can make, and a second "
                        "counter only tells it the executions are scarce. A "
                        "count k rations them instead. 0 is C2 exactly — no "
                        "socket, no client, the same prompt")
    p.add_argument("--campaign", default=None, metavar="FILE",
                   help="the campaign fingerprint every shard must share (§3.6)")
    p.add_argument("--worker-manifest", default=None, metavar="FILE",
                   help="where this shard records what it used (§3.6 level 2); "
                        "requires --campaign and --worker")
    p.add_argument("--protocol", default=None, metavar="N", help=PROTOCOL_HELP)
    p.add_argument("--assertion-selection-policy",
                   choices=("r2t.reviewed-assertion-targets/1",),
                   help="approved replacement targets for stripped-gold controls")
    p.add_argument("--reference-source-tag", metavar="TAG",
                   help="record the actual control derivation/version and reviewed source for evaluation")
    p.set_defaults(func=cmd_run)

    # --------------------------------------------------- versioned data assets
    p = verbs.add_parser(
        "bundle",
        help="build, fetch or install one versioned project scoring bundle")
    bundle_sub = verbs.add_subparsers(p, dest="action", required=True)
    bp = bundle_sub.add_parser(
        "fetch",
        help="fetch the digest-pinned GitHub Release asset")
    bp.add_argument("--project", required=True,
                    choices=CONSUMER_ROUTE_PROJECTS)
    bp.add_argument("--version", required=True)
    bp.set_defaults(func=cmd_bundle)

    bp = bundle_sub.add_parser(
        "install", help="install a local archive against its reviewed release pin")
    bp.add_argument("--project", required=True,
                    choices=CONSUMER_ROUTE_PROJECTS)
    bp.add_argument("--version", required=True)
    bp.add_argument("--archive", required=True, metavar="FILE")
    bp.add_argument("--release-index", metavar="JSON",
                    help="complete private measured evaluation index, before publication")
    bp.set_defaults(func=cmd_bundle)

    bp = bundle_sub.add_parser(
        "validate", help="revalidate an installed bundle without fetching")
    bp.add_argument("--project", required=True,
                    choices=CONSUMER_ROUTE_PROJECTS)
    bp.add_argument("--version", required=True)
    bp.add_argument("--release-index", metavar="JSON")
    bp.set_defaults(func=cmd_bundle)

    bp = bundle_sub.add_parser("measure-index", help="measure a built evaluation archive for private installation")
    bp.add_argument("--archive", required=True)
    bp.add_argument("--manifest", required=True,
                    help="exact manifest sidecar emitted beside the built archive")
    bp.add_argument("--out", required=True, help="new private measured index file")
    bp.set_defaults(func=cmd_bundle)

    bp = bundle_sub.add_parser(
        "verify-algorand-publication",
        help="anonymously verify the fixed public Algorand v2 "
             "package and write its publication receipt")
    bp.add_argument(
        "--version", required=True, choices=("2",),
        help="explicit Algorand publication version")
    bp.add_argument(
        "--source-manifest", required=True, metavar="FILE",
        help="preserved raw source manifest bytes from the reviewed copy gate")
    bp.add_argument(
        "--out", required=True, metavar="FILE",
        help="absent absolute publication-receipt path; all package "
             "identities are fixed by the v2 specification")
    bp.set_defaults(func=cmd_bundle)

    bp = bundle_sub.add_parser(
        "acquire-image",
        help="pull the installed Algorand bundle's runtime image by "
             "registry digest, verify both OCI identities and the canonical "
             "qualification facts, and write one acquisition receipt")
    # Not derived, and not an incidental enum: this whole subcommand is the
    # Algorand image route.  Its version choices are Algorand bundle
    # versions and the identity it verifies comes from a runtime/oci-image
    # role no manifest-declared bundle carries, so a manifest project named
    # here would have nothing to acquire.
    bp.add_argument("--project", required=True, choices=("algorand-sdk",))
    bp.add_argument("--version", choices=("1", "2", "3", "4", "8"), default="1",
                    help="installed Algorand bundle version (default: 1)")
    bp.add_argument("--release-index", metavar="JSON",
                    help="private measured V8 index for prepublication image acquisition")
    bp.add_argument(
        "--out", required=True, metavar="FILE",
        help="absent absolute path for the acquisition receipt; the image "
             "identity comes only from the installed bundle's "
             "runtime/oci-image.json role under R2T_DATA_ROOT, and the "
             "global --docker-authority is required")
    bp.set_defaults(func=cmd_bundle)

    bp = bundle_sub.add_parser(
        "build-algorand",
        help="build a native Algorand bundle from approved "
             "inputs/evidence")
    bp.add_argument("--version", choices=("1", "2", "3", "4", "5", "8"),
                    default="1",
                    help="Algorand bundle version (default: 1)")
    bp.add_argument("--inputs", required=True,
                    help="closed native role and evidence descriptor")
    bp.add_argument("--out", required=True)
    bp.set_defaults(func=cmd_bundle)

    bp = bundle_sub.add_parser(
        "build",
        help="build the asset from preserved release evidence")
    bp.add_argument("--project", required=True,
                    choices=MANIFEST_BUNDLE_PROJECTS)
    bp.add_argument("--version", required=True)
    bp.add_argument("--inputs", help="closed evaluation-only build-input descriptor")
    bp.add_argument("--seed")
    bp.add_argument(
        "--gold",
        help="the removed-test gold tree used by the gold adapter")
    bp.add_argument(
        "--release-gold",
        help="the release gold manifest and per-item answer sidecars")
    bp.add_argument("--raw-manifest")
    bp.add_argument("--legacy-map")
    bp.add_argument(
        "--legacy-report",
        help="report minted by mutants validate --legacy-consistency over "
             "these inputs (defaults to the preserved project report)")
    bp.add_argument("--coverage-run")
    bp.add_argument("--candidate-run")
    bp.add_argument("--candidate-results")
    bp.add_argument("--gold-results")
    bp.add_argument("--production-index")
    bp.add_argument(
        "--historical-release", metavar="JSONL",
        help="preserved release bytes at another location; must match the "
             "selected legacy report's unchanged release digest")
    bp.add_argument(
        "--annotated-release", metavar="JSONL",
        help="annotated task companion, required exactly when the bundle "
             "declares annotated_release_items; historical tasks stay separate")
    bp.add_argument(
        "--scoring-gold",
        help="complete recollected gold run for the declared scoring_gold "
             "role; historical mutation and std-arm baselines stay separate")
    bp.add_argument("--audit-attestation")
    bp.add_argument("--alias-table")
    bp.add_argument("--autowirable-types")
    bp.add_argument(
        "--std-arm",
        help="the J3 ceremony's consumed-inputs shipping list, for an asset "
             "version whose dataset-manifest declaration ships the published "
             "eval100-std arm")
    bp.add_argument("--out", required=True)
    bp.set_defaults(func=cmd_bundle)

    p = verbs.add_parser("reference", help="plan, seal or authenticate evaluation reference controls")
    reference_sub = verbs.add_subparsers(p, dest="action", required=True)
    for action in ("scope", "recipe", "plan", "seal", "validate"):
        rp = reference_sub.add_parser(action)
        _add_evaluation_reference_sources(rp)
        for name in ("mutation-validation", "manifest", "map", "release", "gold-baseline"):
            rp.add_argument("--" + name, required=True)
        if action == "scope":
            rp.add_argument("--out", required=True, help="new instantiated scope; known pins and declaration remain unchanged")
        elif action == "recipe":
            rp.add_argument("--reference-role", required=True, choices=sorted(REFERENCE_CONTROL_ROLES))
            rp.add_argument("--assertion-selection-policy", choices=("r2t.reviewed-assertion-targets/1",))
            rp.add_argument("--out", required=True, help="new prospective five-field recipe")
        elif action == "plan":
            rp.add_argument("--candidate", required=True, help="actual unmutated control run JSONL")
            rp.add_argument("--reference-role", required=True, choices=sorted(REFERENCE_CONTROL_ROLES))
            rp.add_argument("--reference-source-tag", required=True)
            rp.add_argument("--reference-recipe", required=True)
            rp.add_argument("--out", help="new optional plan report; collection reuses its exact inputs")
        else:
            rp.add_argument("--reference-controls", required=True)
            rp.add_argument("--reference-engine-source", required=True)
            if action == "seal":
                rp.add_argument("--allow-excluded-pairs", action="store_true")
                rp.add_argument("--reference-basis", choices=("full_gold", "hard_subset"), default="hard_subset")
                rp.add_argument("--out", required=True)
            else:
                rp.add_argument("--reference-attestation", required=True)
        rp.set_defaults(func=cmd_reference)

    # ------------------------------------------------------------- K-way
    p = verbs.add_parser(
        "seed",
        help="frozen workspace/database pair; a database-backed build dumps "
             "the schema --schema names out of the container --db-container "
             "names")
    p.add_argument("action", choices=("build", "verify", "key"))
    p.add_argument("--seed", default=DEFAULT_SEED)
    p.add_argument("--schema", default="coreshop_bench")
    p.add_argument("--db-container", default=DEFAULT_DB_CONTAINER)
    p.add_argument("--force", action="store_true",
                   help="build over a seed at --seed whose key differs, "
                        "invalidating every worker provisioned from the old "
                        "one; without it a matching key is reused and a "
                        "differing one is refused")
    p.add_argument("--profile", default=None, help=RUNTIME_PROFILE_HELP)
    p.set_defaults(func=cmd_seed)


    p = verbs.add_parser(
        "worker",
        help="manage v3 workers; provision --force cleanup is CLOSED")
    worker_sub = verbs.add_subparsers(p, dest="action", required=True)

    def worker_locator(parser, *, only=True):
        parser.add_argument("--k", type=int, default=4)
        parser.add_argument("--workers-root", default=DEFAULT_WORKERS)
        if only:
            parser.add_argument("--only", type=int, action="append",
                                default=None, metavar="INDEX",
                                help="act on these workers only")
        parser.set_defaults(func=cmd_worker)

    wp = worker_sub.add_parser(
        "plan",
        help="derive and save the authoritative worker manifests")
    worker_locator(wp, only=False)
    wp.add_argument("--runs-dir", default=None)
    wp.add_argument("--worker-artifacts", default=None)
    # SUPPRESS keeps the parser-wide default from overwriting a value parsed
    # at either valid position.  The option lives here so the natural
    # `worker plan --workdir /work` placement works and no later lifecycle
    # verb accepts a new identity.
    wp.add_argument("--workdir", default=argparse.SUPPRESS,
                    help="container mount point saved in every worker spec")
    wp.add_argument("--profile", default=None, help=RUNTIME_PROFILE_HELP)
    wp.add_argument("--prefix", default=None, metavar="WORD",
                    help="project word in each derived worker identity")
    wp.add_argument("--name", default=None, metavar="WORD",
                    help="pool word in each derived worker identity")
    wp.add_argument("--container-kind", default="php", metavar="WORD",
                    help="the word in a worker's derived container name")

    wp = worker_sub.add_parser(
        "preflight", help="validate the saved worker pool")
    worker_locator(wp)
    wp.add_argument("--live", action="store_true",
                    help="also inspect each selected live container, which "
                         "is the half a name check cannot do")
    wp.add_argument("--db-container", default=DEFAULT_DB_CONTAINER)
    wp.add_argument("--internal-network", nargs="?",
                    const=DEFAULT_INTERNAL_NETWORK, default=None,
                    metavar="NAME")

    wp = worker_sub.add_parser(
        "provision",
        help="provision identities from saved worker manifests; "
             "--force cleanup is CLOSED")
    worker_locator(wp)
    wp.add_argument("--seed", default=DEFAULT_SEED)
    wp.add_argument("--jobs", type=int, default=1, metavar="N",
                    help="provision at most N workers concurrently (default: 1); "
                         "a failed worker stops further dispatch and preserves partial resources")
    wp.add_argument("--db-container", default=DEFAULT_DB_CONTAINER)
    wp.add_argument("--internal-network", nargs="?",
                    const=DEFAULT_INTERNAL_NETWORK, default=None,
                    metavar="NAME",
                    help="the pool's dedicated internal network; required "
                         "for a database-backed pool and refused without one")
    wp.add_argument(
        "--template-container", default=None, metavar="NAME",
        help="container whose application environment each database-backed "
             "worker inherits; required for a DB pool, with no default, "
             "because a hand-recreated template would otherwise silently "
             "become the system under test")
    wp.add_argument("--force", action="store_true",
                    help="CLOSED for provision: cleanup sidecar has no "
                         "reviewed lifecycle binding")
    # Defaulted to None and resolved in `cmd_worker` against
    # `worker.DEFAULT_IMAGE`, rather than repeating the image name here: two
    # literals of one image is two places for the coordinator and the worker
    # to disagree about what a campaign's `container_image_digest` describes.
    wp.add_argument("--image", default=None, metavar="IMAGE",
                    help="the container image a worker runs (default: the "
                         "CoreShop bench image). A second stack has its own; "
                         "see benchmark/docker/")
    wp.add_argument("--profile", default=None, help=RUNTIME_PROFILE_HELP)
    wp.add_argument(
        "--composer-cache", default=None, metavar="ABS_DIR",
        help="retained CoreShop input for database-backed provision: "
             "explicit existing read-only cache; no host-specific default")
    wp.add_argument(
        "--direct-call-agent-jar", default=None, metavar="ABS_FILE",
        help="the Java direct-invocation agent jar (API_DIRECT_INVOCATION_SPEC "
             "2.4), bound read-only into every worker at "
             "stacks.cucumber.AGENT_JAR_RUNTIME; its sha256 is printed so a "
             "run can be checked against it")

    wp = worker_sub.add_parser(
        "probe", help="probe saved workers' database isolation")
    worker_locator(wp)
    wp.add_argument(
        "--sentinel-schema", default=None, metavar="SCHEMA",
        help="schema this worker must not read; required at K=1, where the "
             "positional neighbour is the worker itself")
    wp.add_argument("--db-container", default=DEFAULT_DB_CONTAINER)
    wp.add_argument("--internal-network", nargs="?",
                    const=DEFAULT_INTERNAL_NETWORK, default=None,
                    metavar="NAME")

    wp = worker_sub.add_parser(
        "reset-probe",
        help="demonstrate per-execution schema reset on saved "
             "workers",
        description="demonstrate, from inside each worker "
                    "container, that state written by one pair execution is "
                    "not visible to the next. Two consecutive executions on "
                    "one worker with nothing between them; it passes only "
                    "when the purged markers are gone AND the control marker "
                    "the purges do not touch is still there, so a probe that "
                    "observes nothing cannot report a clean pool. Per pool, "
                    "per provisioned K: it is not a property of the project "
                    "and a re-provisioned pool repeats it.")
    worker_locator(wp)
    wp.add_argument("--db-container", default=DEFAULT_DB_CONTAINER)
    wp.add_argument("--internal-network", nargs="?",
                    const=DEFAULT_INTERNAL_NETWORK, default=None,
                    metavar="NAME")

    for action in ("harden", "unharden"):
        help_text = {
            "harden": "remove root@%% after verifying worker "
                      "principals and schema grants",
            "unharden": "restore the wildcard root@%% database "
                        "account",
        }[action]
        wp = worker_sub.add_parser(action, help=help_text)
        worker_locator(wp)
        wp.add_argument("--db-container", default=DEFAULT_DB_CONTAINER)
        wp.add_argument("--internal-network", nargs="?",
                        const=DEFAULT_INTERNAL_NETWORK, default=None,
                        metavar="NAME")

    wp = worker_sub.add_parser(
        "teardown",
        help="remove identities from saved worker manifests",
        description="remove identities from saved worker "
                    "manifests. Live administration, so it is refused "
                    "without the global --worker carrying exact "
                    "r2t.worker-runtime/v3 evidence for a member of this "
                    "pool -- the --workers-root/--k flags below select "
                    "WHICH members, they do not authorize the command.")
    worker_locator(wp)
    wp.add_argument("--db-container", default=DEFAULT_DB_CONTAINER)
    wp.add_argument("--internal-network", nargs="?",
                    const=DEFAULT_INTERNAL_NETWORK, default=None,
                    metavar="NAME")
    wp.add_argument("--keep-workspace", action="store_true")
    wp.add_argument("--image", default=None, metavar="IMAGE")

    if command == "environment":
        # Like `tier1b-verdict` above: this repository pins argparse's
        # existing top-level choice diagnostics (the result-ledger selftests
        # hash the unknown-option bytes), so a new verb is exposed only when
        # its own command token selected it and every unrelated diagnostic
        # keeps its exact bytes.
        from ..toolkit.environment import PROJECTS as ENVIRONMENT_PROJECTS
        p = verbs.add_parser(
            "environment",
            help="descriptor-driven project environment "
                 "lifecycle; up accepts only after its gold control passes")
        environment_sub = verbs.add_subparsers(p, dest="action", required=True)
        environment_projects = sorted(ENVIRONMENT_PROJECTS)

        ep = environment_sub.add_parser(
            "up",
            help="build the reviewed project image, provision "
                 "one fresh nonce-namespaced worker pool, and accept only "
                 "after the descriptor's gold-control row passes")
        ep.add_argument("--project", required=True,
                        choices=environment_projects)
        ep.add_argument("--k", type=int, default=None,
                        help="pool size (default: the released worker "
                             "plan's k)")
        ep.set_defaults(func=cmd_environment)

        ep = environment_sub.add_parser(
            "status",
            help="answer absent / live-and-bound / torn-down "
                 "for one saved environment record")
        ep.add_argument("--project", required=True,
                        choices=environment_projects)
        ep.add_argument("--nonce", default=None, metavar="NONCE",
                        help="which saved environment; required only when "
                             "several records exist")
        ep.set_defaults(func=cmd_environment)

        ep = environment_sub.add_parser(
            "down",
            help="tear down the saved record's authenticated "
                 "worker pool and directly owned resources, then retire "
                 "the record")
        ep.add_argument("--project", required=True,
                        choices=environment_projects)
        ep.add_argument("--nonce", default=None, metavar="NONCE",
                        help="which saved environment; required only when "
                             "several records exist")
        ep.set_defaults(func=cmd_environment)

    p = verbs.add_parser(
        "campaign",
        help="write a v3 campaign fingerprint; unresolved "
             "fingerprints cannot authorize live shards, and agent publication "
             "is CLOSED without --agent-backend-runtime")
    p.add_argument("--campaign-id", required=True)
    p.add_argument("--k", type=int, default=4)
    # The same parser as `run`'s, and that identity is the point: this value is
    # written into the campaign fingerprint and compared, by equality, with the
    # one every shard stamps on every row. Two spellings of "unbounded" would
    # refuse a correct merge hours after the sweep was paid for.
    p.add_argument("--trials", type=_trials, default=0, metavar="K",
                   help="the budget this campaign fingerprints: 0, a count, or "
                        "`unlimited`. Recorded as `trial_budget`, and a shard "
                        "launched with a different one is refused before its "
                        "first item")
    p.add_argument("--condition", default=None,
                   help="the experimental arm (c1.5/c2/c3) this campaign "
                        "fingerprints; None for the gold/stub controls. Bound "
                        "into the digest so two arms cannot share a campaign")
    # WHICH SYSTEM this campaign's shards run. Bound into the digest, so an
    # aider shard cannot merge into an openhands campaign — and enforced
    # before item 1 (`runner._check_campaign_flags`), not only at merge, since
    # an agent sweep is paid for per item and the merge runs hours later.
    #
    # A FLAG HERE AND NOWHERE ELSE. `run` has `--adapter`, from which the
    # registry gives the authoritative answer; a second flag there could only
    # relabel a row. `campaign` names no adapter (a campaign names no system,
    # its shards do), so this is the only place the claim can be made at all.
    # Section 4.1's campaign-creation moment, entered by BINDING a backend.
    # Optional, and its absence changes nothing: section 10 keeps campaign
    # behavior unchanged outside explicit agent publication mode, which no
    # `campaign` command line is ever in.  What the omission costs is exactly
    # publication -- the run gate rebuilds this companion from the plan's
    # backend and refuses a probed one.
    if campaign_backend_tail is not None:
        p.add_argument(
            "--agent-backend-runtime", default=None,
            dest="agent_backend_runtime", metavar="ABS_PATH",
            help="the r2t.agent-backend-runtime/v2 manifest an "
                 "openhands/aider campaign selects. Its tree is "
                 "re-inventoried and its interpreter started in probe mode "
                 "here, and the campaign's agent-runtime companion is built "
                 "FROM it. REQUIRED for a campaign that will authorize agent "
                 "publication; omitting it mints the unchanged probe-built "
                 "campaign, which the publication plan gate refuses")
    p.add_argument("--agent-system", default=None, dest="agent_system",
                   metavar="NAME",
                   help="the system under test this campaign fingerprints, as "
                        "the adapter registry spells it (e.g. openhands, "
                        "aider); omit for the gold/stub controls. Bound into "
                        "the digest, so a shard of another system can neither "
                        "be launched against this campaign nor merged into it")
    p.add_argument("--coverage", action="store_true")
    p.add_argument("--model", default=None)
    p.add_argument("--llm-config", default=None,
                   help="JSON with the campaign model identity; "
                        "R2T_LLM_MODEL takes precedence")
    # `cmd_campaign` reads `runtime.needs_database` off the stack profile, so
    # it needs the same escape hatch its seven siblings have.  Without it the
    # profile could only be resolved by ADJACENCY
    # (`profile_{config_stem(project)}.yml` beside `--boundary`), and a
    # project whose profile file is not spelled that way was unreachable:
    # `algorand-sdk` resolves to `profile_algorand_sdk.yml`, but its profile
    # is `profile_algorand.yml`, so every Algorand campaign refused with "no
    # task profile at …" and there was no operator-side spelling of it.  The
    # Java research-minimal path had already worked around the same gap by
    # hardcoding the name (`release_validation._profile_path`), which is what
    # made the mismatch invisible until a campaign was first attempted.
    p.add_argument("--profile", default=None, help=RUNTIME_PROFILE_HELP)
    from .worker import DEFAULT_IMAGE as DEFAULT_CORESHOP_IMAGE
    p.add_argument(
        "--image", default=DEFAULT_CORESHOP_IMAGE,
        help="image label to resolve only after v3 pool authorization; its "
             "immutable ID must equal the authenticated worker image")
    p.add_argument("--seed", default=DEFAULT_SEED)
    if _SLICE3_CAMPAIGN_CONTEXT is not None:
        p.add_argument(
            "--release", required=True, metavar="ABS_JSONL",
            help="exact frozen ordered Slice-3 cell release; available only "
                 "through the campaign-mint capability")
    p.add_argument("--out", required=True)
    # v2 (PR R3). WHICH ATTEMPT, and under what network posture.
    p.add_argument("--attempt-id", default=None, dest="attempt_id",
                   metavar="ID",
                   help="pin this attempt's identity instead of minting one. "
                        "A re-run under the same recipe is a NEW attempt and "
                        "gets a new id by default; that is what stops two "
                        "differently-contaminated attempts sharing a digest, "
                        "as the two Cell 3 attempts did")
    p.add_argument("--network-semantics", required=True,
                   dest="network_semantics", metavar="LABEL",
                   help="required factual disclosure of the network posture "
                        "this attempt ran under; it is recorded as runtime "
                        "identity, not as a confinement or publication-gate "
                        "claim")
    p.add_argument("--allow-unresolved", action="store_true",
                   help="with no --worker, allow unresolved image/seed "
                        "identities; the resulting Docker-free, "
                        "non-reproducible design artifact cannot authorize a "
                        "live shard")
    # The campaign's own `--protocol` binds the recipe's IDENTITY into the
    # digest every shard must agree on, so two sweeps that differ only in
    # their protocol file cannot merge into one result. It goes through the
    # same `_apply_protocol` as a run's, which is why a campaign created with
    # a contradicting flag is REFUSED rather than recorded: a campaign is the
    # comparability claim, so it has no ad-hoc mode.
    #
    # The help below promises the recipe is BINDING, and it is enforced in two
    # places rather than merely hashed: `runner._check_campaign_flags` refuses
    # a shard whose `--protocol` does not match, before item 1, and
    # `campaign.STAMP_CROSSCHECKS` refuses the row at merge. Hashing alone
    # would have made the promise false -- every shard would have asserted the
    # campaign's recipe equally, including the ones that never followed it.
    p.add_argument("--protocol", default=None, metavar="N",
                   help="record protocol/protocol_vN.yml's version and digest "
                        "in the fingerprint, so shards that followed a "
                        "different recipe cannot merge into this campaign "
                        "(and cannot be launched against it: a shard whose "
                        "--protocol disagrees is refused before item 1). "
                        "Omitted, the pair is null -- 'this campaign followed "
                        "no protocol file', which is a different digest from "
                        "any that did")
    p.set_defaults(func=cmd_campaign)

    p = verbs.add_parser(
        "verify-shard",
        help="re-attest one mutation shard against its own bytes "
             "(read-only)")
    p.add_argument("--out", required=True, metavar="ROWS",
                   help="the shard's rows file; its `.provenance.json` "
                        "sidecar is read beside it. Nothing is written: a "
                        "wrongly demoted shard is recovered by rerunning into "
                        "a NEW campaign directory, never by editing an "
                        "attestation")
    p.set_defaults(func=cmd_verify_shard)

    p = verbs.add_parser(
        "verify-receipt",
        help="verify one complete result-ledger receipt (read-only, "
             "offline)")
    p.add_argument(
        "--receipt", required=True, metavar="ABS_PATH",
        help="canonical absolute .result-ledger.json path; no Docker, daemon, "
             "pool, network, or file write is attempted")
    p.set_defaults(func=cmd_verify_receipt)

    p = verbs.add_parser(
        "merge", help="strictly merge K shards into one run")
    if publication_merge_cli:
        p.add_argument("--manifest", action="append",
                       help="a worker manifest; repeat once per shard")
        p.add_argument(
            "--publication-v3", action="store_true",
            help="publish a durable strict merged receipt from complete "
                 "source run-shard receipts")
        p.add_argument(
            "--source-receipt", action="append", metavar="ABS_PATH",
            help="canonical absolute complete run-shard receipt; repeat "
                 "exactly once per expected worker")
    else:
        # Byte-for-byte pre-I4 default parser contract: neither publication
        # option exists and argparse itself owns the required-manifest error.
        p.add_argument("--manifest", action="append", required=True,
                       help="a worker manifest; repeat once per shard")
    p.add_argument("--of", type=int, required=True)
    p.add_argument("--release", default=os.path.join(BENCHMARK, "release",
                                                     "items_v1.jsonl"))
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_merge)

    p = verbs.add_parser(
        "finish",
        help="merge one complete sealed result-v3 campaign and "
             "render results")
    p.add_argument(
        "--campaign", required=True, metavar="DIR",
        help="directory containing campaign.json and workerN.manifest.json")
    p.set_defaults(func=cmd_finish)

    p = verbs.add_parser(
        "confine",
        help="CLOSED pending agent/v3-evidence containment binding")
    p.add_argument("--k", type=int, default=4)
    p.add_argument("--workers-root", default=DEFAULT_WORKERS)
    p.add_argument("--db-container", default=DEFAULT_DB_CONTAINER)
    p.add_argument("--only", type=int, action="append", default=None)
    p.add_argument("--profile", default=None, help=RUNTIME_PROFILE_HELP)
    p.add_argument("--agent", default=None, metavar="WORKSPACE",
                   help="required workspace for the bwrap-sandboxed agent "
                        "filesystem, environment, and process probe")
    p.set_defaults(func=cmd_confine)

    p = verbs.add_parser(
        "mutants",
        help="mutant assets: build inside the named container (its immutable "
             "image ID is recorded), map, validate")
    p.add_argument("action", choices=("build", "map", "validate"))
    p.add_argument("--image-id", default=None,
                   help="Go build: immutable image ID of the exclusive analysis container")
    p.add_argument("--compile-workers", type=int, default=1,
                   help="Go build: concurrent disposable compilation views (1..32)")
    p.add_argument("--construction-timeout", type=int, default=1800,
                   help="Go build: static producer deadline in seconds; does not change test timeouts")
    p.add_argument("--path", action="append", default=None)
    p.add_argument("--out", required=True)
    p.add_argument("--manifest", default=None)
    p.add_argument("--raw-manifest", default=None,
                   help="preserved pre-boundary catalogue; validate uses it "
                        "to prove the scored population is a subset")
    p.add_argument("--raw-out", default=None,
                   help="build: also preserve the immutable pre-boundary "
                        "manifest at this path")
    p.add_argument("--map", default=None,
                   help="validate: mutant-to-release-item map")
    p.add_argument("--coverage-run", default=None,
                   help="a run JSONL whose rows carry coverage_lines")
    p.add_argument("--release", default=None,
                   help="map/validate: release JSONL defining legal item IDs; "
                        "supplying it makes map output identity-bearing")
    if java_mutants_cli:
        p.add_argument(
            "--approval", default=None,
            help="Java build/map: external phase=release approval for the "
                 "exact final release tree")
        p.add_argument(
            "--approved-digest", default=None,
            help="Java build/map: operator-approved semantic digest of "
                 "--approval")
    p.add_argument("--asset-index", default=None,
                   help="validate against a frozen r2t.mutation-assets/1 index")
    p.add_argument("--asset-project", default=None,
                   help="project key inside --asset-index")
    p.add_argument("--engine-source", default=None,
                   help="override engine source path for frozen-index binding")
    p.add_argument("--legacy-consistency", action="store_true",
                   help="validate preserved historical bytes and pair sets "
                        "without claiming missing native provenance")
    p.add_argument("--candidate-run", default=None)
    p.add_argument(
        "--candidate-egress-attestation", default=None,
        help="content-addressed strict-egress evidence for the exact "
             "candidate run; required by the preserved CoreShop+aider cell")
    p.add_argument("--gold-baseline", default=None)
    p.add_argument("--candidate-results", default=None)
    p.add_argument("--gold-results", default=None)
    p.add_argument("--audit-root", default=None,
                   help="run complete apply/parse/restore audit in an explicitly "
                        "marked disposable copy; never a live worker")
    p.add_argument("--audit-workers", type=int, default=1,
                   help="parallel in-image audit (default 1): Behat/PHP uses k "
                        "disposable sessions; Go uses the first k existing "
                        "workers in the authenticated owning pool")
    p.add_argument("--audit-attestation", default=None,
                   help="completed audit JSON to bind against the frozen index")
    p.add_argument("--require-release-ready", action="store_true",
                   help="refuse provisional assets that do not bind a complete "
                        "full-population materialisation audit")
    p.add_argument("--sample", type=int, default=None)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--record-enumerator-rev", action="store_true",
                   help="build: compatibility spelling; v2 always records "
                        "and verifies the current revision, while v1 rejects "
                        "this flag to preserve its historical object")
    p.add_argument("--operator-profile", choices=("v1", "v2"), default="v2",
                   help="build: enumerate the immutable shared-eight v1 "
                        "profile or the v2 default end to end")
    p.add_argument("--profile", default=None, help=STACK_PROFILE_HELP)
    p.set_defaults(func=cmd_mutants)

    p = verbs.add_parser(
        "mutation-run",
        help="CLOSED pending complete pre-execution/result binding")
    p.add_argument("--mutation-validation", required=True,
                   help="release-ready native validation report, or the "
                        "installed compact Algorand authority for a bound "
                        "Slice-3 job")
    p.add_argument("--algorand-bundle-version", choices=("1", "2", "3"),
                   default="1",
                   help="installed compact Algorand bundle version "
                        "(default: 1)")
    p.add_argument("--manifest", required=True)
    p.add_argument("--java-analysis-root", default=None, metavar="DIR",
                   help="Kapua only: immutable compiler capture authenticated by "
                        "the manifest recipe; worker production sources must "
                        "match, while worker runtime settings remain unchanged")
    p.add_argument("--seed", required=True,
                   help="verified content-addressed seed used by global "
                        "--worker; its provision-time runtime attestation, "
                        "live image ID and exact worker record enter the "
                        "campaign identity")
    p.add_argument("--worker-pool", nargs="+", required=True,
                   metavar="SPEC",
                   help="the complete ordered worker pool (one saved spec per "
                        "--mutant-of slot). Global --worker must equal this "
                        "shard's assigned record; the whole pool and its "
                        "runtime attestations enter every shard identity")
    p.add_argument("--side", choices=("candidate", "gold"),
                   default="candidate",
                   help="explicit comparison role stamped on every row; run "
                        "the reference sweep with --side gold so recall can "
                        "prove it did not compare two candidate campaigns")
    p.add_argument("--map", required=True, help="output of `mutants map`")
    p.add_argument("--budgeted-sidecar", default=None, metavar="JSON",
                   help="declare --map to be the DERIVED map of a budgeted "
                        "population and this its r2t.budgeted_sample/1 "
                        "sidecar. The validation report's map pin then names "
                        "the PARENT, and the derived map is admitted only as "
                        "the restriction the sidecar declares. A development "
                        "basis: refused with --reference-scope")
    p.add_argument("--candidate", required=True,
                   help="a run JSONL whose rows carry produced_files; the "
                        "candidate is scored on exactly those bytes, never "
                        "regenerated")
    p.add_argument("--release", default=os.path.join(BENCHMARK, "release",
                                                     "items_v1.jsonl"))
    p.add_argument("--mutant-limit", type=int, default=None,
                   help="run a PREFIX of the eligible mutants — a slice, "
                        "which is a pilot and not a gate result")
    p.add_argument("--sample", type=int, default=None,
                   help="run a seeded SAMPLE of the eligible mutants; the "
                        "sample size and seed belong in the write-up")
    p.add_argument("--sample-seed", type=int,
                   default=MUTATION_SAMPLE_SEED_DEFAULT)
    p.add_argument("--reference-role", choices=sorted(REFERENCE_CONTROL_ROLES),
                   default=None,
                   help="[operator] collect ONE leg of this project's "
                        "full-population reference observation from candidate "
                        "bytes that have exact submitted provenance and no "
                        "generation attempt. Declares which control these "
                        "bytes are, and is this verb's live-workload binding "
                        "for every project. The declaration is verified "
                        "against the harness's own per-row `adapter` stamp "
                        "(full-gold is gold, assertion-stripped-gold is "
                        "stripped-gold, stub-control is stub) and the run "
                        "must cover the complete release item set. "
                        "full-gold is collected with --side gold and the "
                        "other two with --side candidate; --sample, "
                        "--sample-seed, --mutant-limit "
                        "and --pair-plan are refused")
    p.add_argument("--reference-source-tag", default=None, metavar="TAG",
                   help="required with --reference-role: the reviewed, "
                        "space-free local tag resolving to the source commit "
                        "these control bytes were frozen or deterministically "
                        "derived under. Every leg of one reference "
                        "observation names the same tag, and it is identity")
    _add_evaluation_reference_sources(p)
    p.add_argument("--gold-baseline", metavar="JSONL",
                   help="full passing baseline required by --reference-scope")
    p.add_argument("--reference-recipe", metavar="JSON",
                   help="recorded control recipe for --reference-scope or source-authenticated "
                        "PrestaShop development --reference-role with --budgeted-sidecar")
    p.add_argument("--pair-plan", default=None, metavar="PLAN",
                   help="execute a D4 exact-pair plan derived by "
                        "test-quality --candidate-hard-plan-out. This "
                        "restricts executions at pair level while preserving "
                        "the complete candidate, map and population identity")
    p.add_argument("--continuation-plan", default=None, metavar="PLAN",
                   help="execute only unfinished pairs from an authenticated "
                        "full-gold continuation plan; requires --side gold and "
                        "the complete unchanged candidate and mutation assets")
    p.add_argument("--run1-campaign", default=None, metavar="DIR",
                   help="required with --pair-plan: the pending test-quality "
                        "run-1 root named by PLAN; its complete shards are "
                        "revalidated before any run-2 work")
    p.add_argument("--hard-subset", default=None, metavar="JSON",
                   help="required with --pair-plan: the exact population-"
                        "pinned hard subset named by PLAN")
    p.add_argument("--mutant-shard", type=int, default=0)
    p.add_argument("--reference-allocation", help="frozen full-gold host worker allocation JSON")
    p.add_argument("--reference-host", help="host key in --reference-allocation")
    p.add_argument("--reference-supplement-plan",
                   help="frozen supplement plan; run only this host's slot of its pending pairs")
    p.add_argument("--mutant-of", type=int, default=None, metavar="K",
                   help="split ordinary runs across K processes, strided; "
                        "D4 --pair-plan instead pair-balances complete mutant "
                        "groups by deterministic LPT")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--out", required=True)
    p.add_argument("--resume", action="store_true",
                   help="resume only when the existing rows and provenance "
                        "exactly match this content-bound mutation campaign; "
                        "the default requires a new output")
    # Harness-constructing, and it was the one such verb without the flag:
    # `_harness` routes on the profile's `framework:`, so a behave project's
    # mutation slice landed in the Behat branch and died looking for
    # `alias_table.json`. Which APPLIER runs is decided by the manifest's
    # engine, not by this — the two answer different questions and both have
    # to be right for a mutant to be executed at all.
    p.add_argument("--profile", default=None, help=STACK_PROFILE_HELP)
    p.set_defaults(func=cmd_mutation_run)

    p = verbs.add_parser(
        "recall", help="score a mutation slice (§3.10)")
    p.add_argument("--baseline", required=True,
                   help="the candidate's FINAL unmutated run; an item scores "
                        "only if its baseline passed")
    p.add_argument("--results", action="append", required=True,
                   help="a complete native mutation shard; repeat once per "
                        "shard. Historical merged rows require the explicit "
                        "--legacy-consistency report")
    p.add_argument("--gold-results", action="append", required=True,
                   help="gold's mutation rows; the population is items whose "
                        "gold killed set is non-empty. Repeat once per native "
                        "shard")
    p.add_argument("--legacy-consistency", default=None,
                   help="saved PR-2 legacy_consistency validation report "
                        "binding one historical --results and one historical "
                        "--gold-results file; never upgrades them to native")
    p.add_argument("--require-complete", action="store_true",
                   help="refuse to score unless every (item, mutant) the map "
                        "says a run should have covered is present. Needs "
                        "--map. A short file is a different denominator, not "
                        "a smaller measurement of the same one")
    p.add_argument("--map", default=None,
                   help="the `mutants map` output, for --require-complete")
    p.add_argument("--manifest", default=None,
                   help="the mutant manifest, for --require-complete")
    p.add_argument("--mutation-validation", default=None,
                   help="native recall: the release-ready full report or "
                        "bound Slice-3 compact Algorand authority")
    p.add_argument("--algorand-bundle-version", choices=("1", "2", "3"),
                   default="1",
                   help="installed compact Algorand bundle version "
                        "(default: 1)")
    p.add_argument("--release", default=None,
                   help="native recall: the frozen release JSONL bound by "
                        "--mutation-validation and the shard identities")
    p.add_argument("--sample", type=int, default=None,
                   help="the sample size the campaign used; with --sample-seed "
                        "this rebuilds exactly which mutants it should hold")
    p.add_argument("--sample-seed", type=int, default=20260731)
    p.add_argument("--gold-baseline", default=None,
                   help="gold's own unmutated run. A gold kill counts only "
                        "where gold's baseline passed; defaults to --baseline, "
                        "which is right only when scoring gold itself")
    p.set_defaults(func=cmd_recall)

    p = verbs.add_parser(
        "mutation-bound",
        help="sound recall intervals for an interrupted compute-capped "
             "test-quality campaign")
    p.add_argument("--campaign", required=True, metavar="DIR",
                   help="interrupted test-quality output directory; read "
                        "only, with its authenticated root plan and shards")
    p.add_argument("--run", required=True,
                   help="exact candidate run bound by the campaign")
    p.add_argument("--gold-baseline", required=True,
                   help="exact unmutated reference run bound by the campaign")
    p.add_argument("--mutation-validation", required=True,
                   help="release-ready native mutation-validation report "
                        "bound by every shard identity")
    p.add_argument("--manifest", required=True,
                   help="frozen scored mutant manifest named by the "
                        "mutation-validation report")
    p.add_argument("--map", required=True,
                   help="frozen mutant-to-item map named by the validation "
                        "report; used to reconstruct every planned pair")
    p.add_argument("--release", required=True,
                   help="frozen release JSONL named by the validation report")
    p.add_argument("--cap-seconds", type=int, required=True, metavar="N",
                   help="precommitted aggregate wall-clock cap in seconds; "
                        "recorded in the bound, never inferred from rows")
    p.add_argument("--cap-workers", type=int, required=True, metavar="K",
                   help="precommitted worker cap; must equal the root "
                        "campaign's authenticated worker-pool size")
    p.add_argument("--cap-review-authority", required=True, metavar="ID",
                   help="locally resolvable immutable authority "
                        "<repo-relative-path>@<40-lowercase-hex-commit>; "
                        "asserted against the root cap")
    p.add_argument("--threshold", action="append", default=None,
                   metavar="T",
                   help="positive recall threshold to bound in (0,1]; "
                        "repeat as needed (default: 1.0)")
    p.add_argument("--out", required=True,
                   help="new JSON report path outside --campaign; existing "
                        "files are never overwritten")
    p.set_defaults(func=cmd_mutation_bound)

    p = verbs.add_parser(
        "test-quality",
        help="CLOSED live producer; saved evidence remains "
             "inspectable")
    p.add_argument("--run", required=True,
                   help="the candidate sweep (a merged run JSONL). Only rows "
                        "whose outcome is `passed` are scored, and each is "
                        "scored on exactly the bytes its own produced_files "
                        "hold — nothing is regenerated")
    p.add_argument("--mutation-validation", default=None,
                   help="release-ready native r2t.mutation-validation/1 "
                        "report binding the exact scored manifest, map, "
                        "release, engine and completed materialisation audit")
    p.add_argument("--manifest", default=None,
                   help="the scored mutant manifest named by "
                        "--mutation-validation")
    p.add_argument("--java-analysis-root", default=None, metavar="DIR",
                   help="Kapua only: immutable compiler capture authenticated by "
                        "the manifest recipe; worker production sources must "
                        "match, while worker runtime settings remain unchanged")
    p.add_argument("--seed", default=None,
                   help="verified content-addressed seed used to provision "
                        "every --workers spec; provision-time runtime "
                        "attestations and live image IDs are mandatory")
    p.add_argument("--map", default=None, help="output of `mutants map`")
    p.add_argument("--budgeted-sidecar", default=None, metavar="JSON",
                   help="declare --map to be the DERIVED map of a budgeted "
                        "population and this its r2t.budgeted_sample/1 "
                        "sidecar, exactly as `mutation-run` takes it")
    p.add_argument("--kapua-reference-evidence", default=None, metavar="JSON",
                   help="reuse the fixed three original Kapua references on L/B100; "
                        "requires --development and schedules candidate work only")
    p.add_argument("--prestashop-reference-evidence", default=None, metavar="JSON",
                   help="reuse three authenticated single-observation PrestaShop B100 references; "
                        "requires --development and schedules candidate work only")
    p.add_argument("--prestashop-task-items", default=None, metavar="JSONL",
                   help="exact annotated generation sample for --prestashop-reference-evidence; "
                        "--release continues to name the original full map population")
    p.add_argument("--gold-baseline", default=None,
                   help="gold's UNMUTATED run. It supplies both halves of the "
                        "reference: the §3.10 eligibility rule's input (a "
                        "gold kill counts only where gold's baseline passed) "
                        "and the produced_files gold's side is executed from")
    p.add_argument("--gold-results", default=None,
                   help="precomputed gold mutation rows. Optional: without "
                        "it gold is executed over exactly the same (item, "
                        "mutant) pairs as the candidate. A short file is "
                        "refused unless --allow-incomplete is explicit and "
                        "native provenance attests its smaller pair set")
    p.add_argument("--gold-results-attestation", default=None,
                   help="required with --gold-results: either a current "
                        "complete native mutation shard bound to these exact "
                        "row bytes and per-row campaign stamps, or a saved "
                        "PR-2 mutation-validation report whose evidence is "
                        "explicitly legacy_consistency")
    p.add_argument("--workers", nargs="+", default=None, metavar="SPEC",
                   help="one or more worker specs from `worker plan`. The "
                        "candidate and gold slices are pair-balanced across "
                        "them and run in parallel; a "
                        "worker's own two slices run one after the other, "
                        "because its workspace is a mutex")
    p.add_argument(
        "--shard-policy", choices=(
            "r2t.balanced-pairs-lpt/1", "r2t.strided-mutants/1"),
        default=None,
        help="deterministic mutant assignment. New campaigns always use "
             "pair-count LPT. On --resume, omit this option to recover the "
             "saved policy, or name r2t.strided-mutants/1 as an assertion "
             "when resuming an older identity-matching v1 plan")
    p.add_argument("--release", default=os.path.join(BENCHMARK, "release",
                                                     "items_v1.jsonl"))
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--compute-cap-seconds", type=int, default=None,
                   metavar="N",
                   help="positive wall-clock cap frozen into the root plan "
                        "and every shard identity before worker dispatch")
    p.add_argument("--compute-cap-review-authority", default=None,
                   metavar="ID",
                   help="locally resolvable immutable review authority "
                        "<repo-relative-path>@<40-lowercase-hex-commit>; "
                        "required with --compute-cap-seconds")
    p.add_argument("--allow-incomplete", action="store_true",
                   help="allow an explicitly supplied --gold-results file to "
                        "be short. Planned candidate/gold shards remain "
                        "fail-closed and exact; this cannot launder a failed "
                        "worker into a complete campaign")
    p.add_argument("--allow-degraded-gold", action="store_true",
                   help="consent to scoring against gold rows that carry "
                        "infrastructure outcomes — the harness failing rather "
                        "than a mutant surviving. INDEPENDENT of "
                        "--allow-incomplete: a short file and a degraded file "
                        "are different states and neither flag implies the "
                        "other. The exact count and a per-item disclosure are "
                        "recorded in the summary and travel with every number "
                        "derived from it (owner ruling 2.6)")
    p.add_argument("--candidate-pairs", default="all",
                   choices=("all", "gold-killed"),
                   help="which pairs the candidate slice executes. "
                        "gold-killed: only the pairs gold kills, which leaves "
                        "per-item recall, verdicts and non-vacuous passes "
                        "unchanged and withholds candidate-only kills, "
                        "Jaccard and the excluded counts "
                        "(GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md). Needs gold's "
                        "kills first: precomputed gold, --gold-pair-plan, or "
                        "--reference-controls naming a full-gold-only "
                        "reference, which requires it, or scored under a "
                        "labelled reference --sensitivity")
    p.add_argument("--gold-pair-plan", default=None, metavar="JSON",
                   help="r2t.gold-pair-plan/1: the pairs an earlier gold "
                        "observation killed. Gold is observed again in this "
                        "campaign, and both slices execute only these pairs; "
                        "requires --candidate-pairs gold-killed. With "
                        "--kapua-reference-evidence it must be exactly that "
                        "evidence's full-gold kills")
    p.add_argument("--hard-subset", default=None,
                   help="population-pinned r2t.hard-subset/1 artifact. Makes "
                        "hard-subset recall the verdict basis; an absent/empty "
                        "item is not_scorable. Run 2 may be omitted only when "
                        "run 1 produces no D4 qualifier")
    p.add_argument("--candidate-hard-rerun", action="append", default=None,
                   metavar="SHARD",
                   help="one shard of the independently identified native "
                        "D4 run 2; requires --candidate-hard-plan. Its exact "
                        "pair union must be every complete hard set that run "
                        "1 killed literally-failed in full, and no "
                        "nonqualifying pair. Each shard must also match the "
                        "plan's deterministic K-worker allocation; repeat "
                        "for every shard")
    p.add_argument("--candidate-hard-plan-out", default=None, metavar="PLAN",
                   help="two-phase D4 producer: after complete run 1, derive "
                        "and write the authenticated exact-pair PLAN outside "
                        "--out, leaving the root resumable. Execute PLAN with "
                        "mutation-run --pair-plan, then repeat test-quality "
                        "with --resume and --candidate-hard-rerun. If run 1 "
                        "has no qualifier, no plan is written and scoring "
                        "finishes normally")
    p.add_argument("--candidate-hard-plan", default=None, metavar="PLAN",
                   help="finalization input: with --resume and "
                        "--candidate-hard-rerun, revalidate the exact PLAN "
                        "against the pending run-1 root and hard subset, and "
                        "require every standalone run-2 shard to bind it")
    p.add_argument("--no-sidecar", action="store_true",
                   help="do not write <run>.test_quality.json beside the run "
                        "(which is where `report` looks for it)")
    p.add_argument("--development", action="store_true",
                   help="score a candidate produced by the ordinary `run "
                        "--release` route, which carries no generation "
                        "campaign sidecar and no per-row campaign stamp. The "
                        "metric, the population and the pair set are "
                        "identical; what differs is that the candidate "
                        "cannot cite the attempt that produced it, so its "
                        "generation provenance is recorded as "
                        "`development_unstamped` and every publication "
                        "surface refuses that class. The mutation rows are "
                        "computed and rendered as withheld with the reason "
                        "named beside them")
    p.add_argument("--sensitivity", default=None,
                   choices=("webmock_world_v1", "sylius_stub_gate_waived_v1"),
                   help="webmock_world_v1, with --development on the Ruby "
                        "stack: score a labelled post-hoc sensitivity replay "
                        "(specifications/E_PETITIONS_WEBMOCK_MUTATION_"
                        "AMENDMENT.md). Every --run row must carry this "
                        "label; both slices load the same harness overlay, "
                        "and the label is bound into the root plan and the "
                        "summary. sylius_stub_gate_waived_v1, with "
                        "--development, --reference-scope and "
                        "--reference-controls in place of "
                        "--reference-attestation: score against the labelled "
                        "basis of a reference whose stub gate failed; the "
                        "gate is waived and recorded as a diagnostic, the run "
                        "rows carry no label, and the summary carries the "
                        "label and inference_valid false "
                        "(specifications/SYLIUS_STUB_GATE_WAIVED_"
                        "SENSITIVITY_SPEC.md)")
    _add_reference_basis_consent_options(p)
    p.add_argument("--reference-controls", default=None, metavar="DIR",
                   help="[operator] score this candidate against an INSTALLED "
                        "full-population reference collection instead of "
                        "executing gold: the directory holding full_gold/, "
                        "stripped_gold/ and stub/, each a standalone v2 "
                        "mutation output. Only candidate mutation jobs are "
                        "planned; the reference legs are projected from the "
                        "attestation. Requires --reference-attestation, and "
                        "is this verb's live-workload binding for a project "
                        "with no reviewed workload wrapper")
    p.add_argument("--reference-attestation", default=None, metavar="JSON",
                   help="required with --reference-controls: the minted "
                        "r2t.single-observation-reference-controls/1 document "
                        "for that tree. Its recorded section 5.1 exclusions "
                        "and its declared item subset, if it has one, narrow "
                        "the scored universe, and the pool must match the "
                        "execution identity it seals")
    _add_evaluation_reference_sources(p)
    p.add_argument("--slice3-observations", default=None, metavar="DIR",
                   help="Slice-3 (Java20) preserved observations directory: "
                        "six-gate-eligibility.json, the six control "
                        "observation directories and candidate_run*_<arm>. "
                        "With --slice3-bundle, scores the published "
                        "algorand-sdk cell named by --run from preserved "
                        "bytes alone -- no Docker, no execution "
                        "(SLICE3_TEST_QUALITY_SPEC.md §2)")
    p.add_argument("--slice3-bundle", default=None, metavar="BUNDLE",
                   help="the Slice-3 source bundle carrying the frozen "
                        "r2t.slice3-java20-execution-binding/1 document")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="candidate rows, gold rows and summary.json")
    p.add_argument("--resume", action="store_true",
                   help="resume identity-matching partial shards in --out; "
                        "the default requires a new or empty directory")
    # Same gap as `mutation-run`'s, one level up: this verb builds a harness
    # per worker for both sides of the comparison, so without the flag a
    # per-cell anti-vacuity run against a behave project cannot start.
    p.add_argument("--profile", default=None, help=STACK_PROFILE_HELP)
    p.set_defaults(func=cmd_test_quality)

    p = verbs.add_parser(
        "test-quality-bind",
        help="create a separate current binding for PR-2-validated "
             "legacy test-quality evidence; preserves the historical sidecar")
    p.add_argument("--run", required=True,
                   help="exact historical candidate run bytes")
    p.add_argument("--summary", required=True,
                   help="the unique preserved unbound sidecar discovered "
                        "beside --run")
    p.add_argument("--legacy-consistency", required=True,
                   help="PR-2 r2t.mutation-validation/1 report whose evidence "
                        "is explicitly legacy_consistency")
    p.add_argument("--out", required=True,
                   help="new wrapper path; must not be either automatically "
                        "discovered sidecar name")
    p.add_argument("--allow-degraded-gold", action="store_true",
                   help="record the operator's consent (owner ruling 2.6) to "
                        "publishing over preserved gold that carries "
                        "infrastructure outcomes. Legacy rows have no "
                        "`attempt` stamp and so can never claim degraded "
                        "NATIVE gold; they enter publication as this "
                        "recorded, disclosed tolerance, with the exact count "
                        "and the per-item list written into the wrapper. "
                        "Refused when the gold carries no such outcome")
    p.set_defaults(func=cmd_test_quality_bind)


#: The knobs `--protocol` can supply a default for, as a mini-parser: the
#: seven top-level ones plus the NATIVE ones a protocol pins per system --
#: the native half GENERATED from `AGENT_BACKENDS`, like the real flags, so
#: that a third arm's budget is echoed here the day its record lands.
#:
#: WHY A SECOND PARSER RATHER THAN THE REAL ONE.  `_apply_protocol` needs to
#: know which flags the operator TYPED, not which values ended up in the
#: namespace: a knob left at its harness default must take the protocol's
#: value, while the same value typed explicitly must be reported as a
#: deviation.  argparse offers no "was this passed" -- and the usual trick
#: (pre-seeding the namespace with a sentinel) does not survive subparsers on
#: 3.10, which re-apply their own defaults into a fresh namespace and copy the
#: lot back.  So we re-scan argv with a parser that knows only these knobs
#: and has no defaults at all: anything that comes back not-None was typed.
#:
#: No `type=` on any of them: this parser only answers PRESENCE, and a
#: conversion error here would be a second, differently-worded refusal for a
#: flag the real parser has already accepted.
def _explicit_parser():
    ep = argparse.ArgumentParser(add_help=False)
    ep.add_argument("--condition", default=None)
    ep.add_argument("--trials", default=None)
    ep.add_argument("--agent-timeout", dest="agent_timeout", default=None)
    ep.add_argument("--temperature", default=None)
    ep.add_argument("--repeats", default=None)
    ep.add_argument("--coverage", action="store_true", default=None)
    # THE NATIVE KNOBS, echoed for the same reason and read the same way, and
    # generated from the same records the real flags are.  A native budget has
    # a real default (aider's own 3), so the namespace can never answer "was
    # this typed" — only this re-scan can, and without it a `--protocol 3` run
    # would either overwrite the operator's 1 with the protocol's 10 or report
    # the protocol's own value as a deviation.  `--max-iterations` is BOTH a
    # top-level knob and OpenHands' native one — one flag, declared once, by
    # the loop that already has to declare it.
    for backend in _agent_backends():
        ep.add_argument(backend.budget_flag, dest=backend.budget_kw,
                        default=None)
    # Not a knob a protocol pins, but it decides WHICH native vocabulary the
    # knobs above are read in, and `r2t campaign` is where it is typed.
    ep.add_argument("--agent-system", dest="agent_system", default=None)
    return ep


def _protocol_module():
    """`agents.protocol`, or the refusal `--protocol` gives without it.

    Applying a recipe to a run is the agent half of the protocol (the file
    half, `bench.protocol_file`, ships with the benchmark); a checkout
    without the agent component can read a protocol but not follow one.
    """
    try:
        from ..agents import protocol
    except ImportError:
        raise SystemExit(
            "REFUSED: --protocol applies an agent recipe to a run, which "
            "needs the agent component; this checkout does not ship it.")
    return protocol


def _echoed_dests(P) -> tuple:
    """The arg dests `_explicit_knobs` reports on.

    DERIVED from the two places that define them (`protocol.KNOBS` and
    `protocol.NATIVE_KNOB_FLAGS`, read off the module `P`), not listed a
    third time: a hand-written literal falls behind the day a knob is added
    and then silently reports the new knob as "not typed", which is exactly
    how a protocol overwrites a flag the operator passed.
    """
    dests = [d for _k, d, _f in P.KNOBS]
    for knobs in P.NATIVE_KNOB_FLAGS.values():
        dests += [d for _k, d, _f in knobs if d]
    # Not a knob a protocol pins, but it selects which native vocabulary the
    # knobs above are read in, so an operator who typed it must be recorded as
    # having typed it.
    dests.append("agent_system")
    return tuple(dict.fromkeys(dests))


def _explicit_knobs(argv) -> set:
    """Which protocol knobs appear explicitly in `argv`."""
    if argv is None:
        argv = sys.argv[1:]
    ep = _explicit_parser()
    try:
        ns, _rest = ep.parse_known_args(list(argv))
    except SystemExit:
        # The REAL parser already accepted this argv, so reaching here means
        # the two disagree about how to read it -- and guessing either way is
        # worse than stopping. Guessing "nothing was explicit" would silently
        # overwrite a flag the operator typed; guessing "everything was"
        # would silently ignore the protocol.
        raise SystemExit(
            "REFUSED: --protocol could not determine which knobs you passed "
            "explicitly, so it can neither default them nor report them as "
            "deviations. Re-run without --protocol, or spell the knob flags "
            "in full (--condition/--trials/--max-iterations/--agent-timeout/"
            "--temperature/--repeats/--coverage/--max-reflections).")
    return {d for d in _echoed_dests(_protocol_module())
            if getattr(ns, d, None) is not None}


def _active_project(args) -> "str | None":
    """WHICH PROJECT this invocation's prompts are for -- or None when nothing
    in the invocation says.

    THE LABEL, NOT THE PROMPT.  A protocol copies one project's five frozen
    prompt digests, and `protocol.project_deviations` compares that project
    against this one; what is needed here is therefore an identity label, and
    reading one declarative field is the whole job.  `load_profile` stays the
    single AUTHORITY on the prompt BYTES -- it re-derives every digest on
    every load and the run performs it anyway (`runner._profile_for`) -- and
    it is deliberately not called here: this function must not become a
    second, weaker verifier, and it must not turn a drifted profile into a
    refusal that talks about protocols.

    TWO SOURCES, in the order a run resolves them.  `--profile` when it was
    passed, and otherwise the BOUNDARY, exactly as `runner._profile_for` and
    `cli._stack_profile` resolve it (`profile_<project>.yml` beside
    `--boundary`).  The boundary is a sound stand-in for the profile it
    resolves to because `_profile_for` REFUSES a profile whose project
    disagrees with the boundary's -- the two cannot diverge in a run that gets
    past it.  Falling back to "no --profile means CoreShop" instead would have
    left the hole this guard exists to close: `--boundary
    config/boundary_python_docx.yml` with no `--profile` is a docx run, and it
    would have sailed through `--protocol 3`.

    A SUBCOMMAND WITHOUT `--profile` ASSERTS NOTHING, which is the same rule
    `deviations` applies to a knob a subcommand does not have.  It matters
    here because `--boundary` is a GLOBAL flag with CoreShop's file as its
    default: `r2t campaign --protocol 4` would otherwise inherit a boundary
    nobody typed, decide the campaign was about CoreShop, and refuse the very
    docx campaign it was creating.  A campaign names no project (its shards
    do), so the question is not asked there -- and it is asked of every shard
    launched against that campaign, before item 1, beside the rest of
    `runner._check_campaign_flags`.

    NONE IS AN UNANSWERED QUESTION, not a matching answer: a file that cannot
    be read says nothing here rather than guessing, and the run refuses later
    for the better reason if the file is really broken.
    """
    import yaml
    if not hasattr(args, "profile"):
        return None
    path = getattr(args, "profile", None)
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception:                                   # noqa: BLE001
            return None
        project = doc.get("project") if isinstance(doc, dict) else None
        return project if isinstance(project, str) and project.strip() else None
    bpath = getattr(args, "boundary", None)
    if not bpath:
        return None
    try:
        from ..core.boundary import load_boundary
        return load_boundary(bpath).project or None
    except Exception:                                       # noqa: BLE001
        return None


def _apply_protocol(args, argv) -> None:
    """`--protocol N`: the recipe becomes the default, and deviations are
    refused or recorded depending on whether this row is meant to be
    comparable.

    WITHOUT THE FLAG THIS FUNCTION DOES NOTHING AT ALL. A run launched as it
    was yesterday behaves exactly as it did yesterday, and stamps no
    protocol field -- absent, not null. Absence is what says "this run
    followed no protocol"; a null would say "it followed one and the value
    was lost".

    WITH IT, the asymmetry between the two modes is the whole design:

      * under `--campaign` (and for `r2t campaign` itself, which WRITES the
        comparability claim), a deviation is REFUSED. A campaign exists to
        make its rows comparable with each other and with the rest of the
        arm, and a shard that quietly ran at a different temperature would be
        internally consistent and externally false -- the same failure
        `_check_campaign_flags` refuses one level down. It is refused BEFORE
        item 1, because the merge only runs hours after the money is spent.
      * without `--campaign`, a deviation is ALLOWED and recorded verbatim on
        every row as `protocol_deviations`. An ad-hoc probe is exactly the
        thing a protocol should not obstruct; what it must not do is come
        back looking like a protocol run.

    THREE THINGS ARE COMPARED, and all three feed that one decision: the seven
    top-level knobs, the native per-system ones, and the PROJECT whose frozen
    prompt digests the protocol copies (`_active_project` vs
    `prompt_profile.project`). The third is why v3 and v4 exist as twins --
    same recipe, one CoreShop's prompt identity and one python-docx's -- and
    without the comparison the twins would be decoration: nothing would stop a
    docx campaign from citing P3 and every row would look consistent.
    """
    version = getattr(args, "protocol", None)
    if version is None:
        if getattr(args, "adapter", None) in ("codex", "claude_code"):
            explicit = _explicit_knobs(argv)
            for dest, value in (("agent_timeout", 3600), ("temperature", None)):
                if dest not in explicit and hasattr(args, dest):
                    setattr(args, dest, value)
        return
    P = _protocol_module()
    try:
        doc = P.load(version)
    except P.ProtocolError as e:
        raise SystemExit(f"REFUSED: {e}")
    # CLASS BEFORE KNOBS: an adapter from the wrong comparison class is not a
    # deviation to record, it is a category error to refuse -- the rows would
    # each be internally consistent while citing a recipe for a population
    # they cannot be pooled with.
    # `campaign` has no --adapter (it names no system; its shards do), so the
    # lookup runs only when a name exists.  `get_spec` refuses unknown names
    # by SystemExit -- which `except Exception` cannot catch, and which once
    # made this very call refuse EVERY `campaign --protocol` with "unknown
    # adapter None" -- so it is caught explicitly: a class we could not look
    # up asserts nothing, and a genuinely unknown adapter is refused later by
    # build_adapter, where the refusal belongs.
    adapter_class = None
    _name = getattr(args, "adapter", None)
    if _name:
        try:
            from ..agents import registry as _reg
            adapter_class = getattr(_reg.get_spec(_name),
                                    "comparison_class", None)
        except (Exception, SystemExit):                     # noqa: BLE001
            adapter_class = None
    try:
        P.check_comparison_class(doc, adapter_class)
    except P.ProtocolError as e:
        raise SystemExit(f"REFUSED: {e}")
    explicit = _explicit_knobs(argv)
    # Defaults FIRST, deviations SECOND: `apply_defaults` skips every knob in
    # `explicit`, so what `deviations` then sees is what the operator asked
    # for rather than what was just written underneath them.
    P.apply_defaults(doc, args, explicit)
    # THE NATIVE KNOBS, one level down and by the same rules. Which vocabulary
    # they are read in depends on WHICH SYSTEM this invocation is about, and
    # `runner.agent_system_of` is the one resolver the row stamp and the
    # campaign crosscheck also use -- a second answer here would let a row's
    # `native_budget` and its campaign disagree about the system it belongs to.
    from .runner import agent_system_of
    system = agent_system_of(args)
    P.apply_native_defaults(doc, args, system, explicit)
    # ONE LIST, sorted once. The three kinds of deviation get identical
    # treatment -- refused under a campaign, recorded verbatim otherwise --
    # because a shard that quietly halved aider's only loop is exactly as
    # incomparable as one that ran at a different temperature, and a shard
    # that cited another project's frozen prompt digests is worse than both:
    # its rows would be internally consistent and name a prompt they never
    # sent. A protocol carries ONE project's five digests (current twins: v5
    # CoreShop, v6 python-docx), so WHICH project this invocation is about is
    # part of following the recipe.
    devs = sorted(P.deviations(doc, args)
                  + P.native_deviations(doc, args, system)
                  + P.project_deviations(doc, _active_project(args)))
    args.protocol_version = doc["protocol_version"]
    args.protocol_digest = P.protocol_digest(doc)
    args.protocol_deviations = devs
    comparable = bool(getattr(args, "campaign", None)) \
        or getattr(args, "cmd", None) == "campaign"
    if devs and comparable:
        raise SystemExit(
            f"REFUSED: this run deviates from protocol v{doc['protocol_version']} "
            f"({args.protocol_digest}) and it is part of a campaign, so its "
            f"rows are meant to be comparable:\n  - " + "\n  - ".join(devs)
            + f"\nA campaign run follows its protocol. Drop the conflicting "
              f"flag(s), point --protocol at the recipe this run actually "
              f"belongs to (a line above that names two projects names it "
              f"too), drop --campaign if this is an ad-hoc probe (the "
              f"deviations are then recorded on every row), or write a new "
              f"protocol file -- protocol_vN.yml is IMMUTABLE and a changed "
              f"knob is a new N.")
    if devs:
        print(f"  NOTE: this run deviates from protocol "
              f"v{doc['protocol_version']} ({args.protocol_digest}) in "
              f"{len(devs)} respect(s); every row records them verbatim as "
              f"`protocol_deviations`, and the run is NOT comparable with the "
              f"protocol's arm:\n    - " + "\n    - ".join(devs), flush=True)


def _apply_worker(args) -> None:
    """`--worker FILE` sets the workspace, the container and the mount point.

    One flag instead of four, because the four have to agree: a `--repo` from
    worker 3 with a `--container` from worker 0 executes worker 3's files in
    worker 0's schema, and every path involved exists in both, so nothing
    would notice until the outcomes stopped being reproducible.
    """
    spec = _worker_spec(args)
    if spec is None:
        return
    if getattr(args, "repo", None) and os.path.abspath(args.repo) != \
            os.path.abspath(spec.workspace):
        raise SystemExit(
            f"REFUSED: --repo {args.repo} contradicts worker "
            f"{spec.index}'s workspace {spec.workspace}.")
    if getattr(args, "_container_explicit", False) \
            and args.container != spec.container:
        raise SystemExit(
            f"REFUSED: --container {args.container} contradicts worker "
            f"{spec.index}'s container {spec.container}.")
    if getattr(args, "_workdir_explicit", False) \
            and args.workdir != spec.workdir:
        raise SystemExit(
            f"REFUSED: --workdir {args.workdir} contradicts worker "
            f"{spec.index}'s workdir {spec.workdir}.")
    args.repo = spec.workspace
    args.container = spec.container
    args.workdir = spec.workdir
    if getattr(args, "out", None) is None and spec.out_path:
        args.out = spec.out_path
    if getattr(args, "shard", None) is None:
        args.shard = spec.index



def selftest():
    """Exercise literal evaluation commands with synthetic execution leaves."""
    from contextlib import ExitStack, redirect_stdout, redirect_stderr
    from dataclasses import replace
    import io
    import json
    import os
    from pathlib import Path
    import shutil
    import tempfile
    from types import SimpleNamespace
    from unittest.mock import patch
    from . import cli as C, mutation_run as MR, test_quality as TQ, worker as W, runner as R
    from .fixtures import Adapter
    from . import evaluation_reference as ER
    from . import reference_controls as RC
    from .evaluation_reference_selftest import _rows, fixture_evaluation_inputs
    from ..data import bundle as B, evaluation_bundle as E, mutation_attestation as MA
    from ..toolkit.evaluation_bundle_selftest import fixture_evaluation_bundle_inputs

    from ..data.profile import load_profile
    for profile_name, expected in (
            ("e_petitions", ("--init",)),
            ("python_docx", ()),
            ("kapua", ("--hostname", "kapua-worker", "--add-host", "kapua-worker:127.0.0.1")),
            ("coddy_agent", ("--memory", "17179869184", "--memory-swap", "17179869184"))):
        profile = load_profile(str(Path(B.BENCHMARK) / f"config/profile_{profile_name}.yml"))
        assert C._worker_process_args(profile) == expected
    print("  [PASS] Ruby workers get an init reaper; coddy Go workers a 16 GiB/zero-swap cap; other stack arguments stay unchanged")
    # The Go cap is accepted only when the container enforces it: rootless
    # Docker drops an unenforceable limit with a warning, so an unbounded or
    # different effective limit refuses before any evidence is minted.
    from . import prestashop_memory as PM
    cap = str(PM.GO_MEMORY_POLICY["memory_bytes"])
    counters = "event low 0\nevent high 0\nevent max 0\nevent oom 0\nevent oom_kill 0\n"

    def go_probe(host, cgroup):
        fake = SimpleNamespace(container="ca_c27_g_go_0", runner=lambda docker_group=True: SimpleNamespace(
            run=lambda script, timeout: SimpleNamespace(returncode=0, stdout=cgroup, stderr="")))
        with patch.object(W, "_docker_json", return_value={"Id": "a" * 64, "HostConfig": host}):
            return PM.capture_go_memory(fake)
    enforced = {"Memory": int(cap), "MemorySwap": int(cap), "OomKillDisable": False}
    observed = go_probe(enforced, f"memory.max {cap}\nmemory.swap.max 0\n" + counters)
    assert observed["memory"]["effective_memory_bytes"] == int(cap)
    assert observed["memory"]["policy"]["projects"] == ["coddy-agent"]
    for host, cgroup in (
            (enforced, "memory.max max\nmemory.swap.max 0\n" + counters),          # dropped limit
            ({**enforced, "Memory": 0, "MemorySwap": 0}, f"memory.max {cap}\nmemory.swap.max 0\n" + counters),
            (enforced, f"memory.max {cap}\nmemory.swap.max {cap}\n" + counters),  # swap allowed
            (enforced, "memory.max 4294967296\nmemory.swap.max 0\n" + counters),
            ({**enforced, "OomKillDisable": True}, f"memory.max {cap}\nmemory.swap.max 0\n" + counters),
            (enforced, f"memory.max {cap}\nmemory.swap.max 0\n")):                # no OOM counters
        try:
            go_probe(host, cgroup)
        except W.WorkerRefused:
            pass
        else:
            raise AssertionError(f"Go memory cap accepted: {host} {cgroup!r}")
    assert PM.go_memory_run_args("kapua") == () and PM.go_memory_run_args("prestashop") == ()
    print("  [PASS] the coddy Go memory cap is accepted only when the container enforces 16 GiB with no swap")

    # The same helper supplies reset-probe, mutation-run and test-quality.
    # Exercise real project/profile resolution and seed tar reading: a
    # framework-only lookup wrongly requires Pimcore files in PrestaShop.
    import tarfile
    with tempfile.TemporaryDirectory(prefix="derived-baseline-") as temporary:
        seed = Path(temporary)
        archive = seed / "workspace.tar"
        with tarfile.open(archive, "w"):
            pass
        def derived_args(project):
            return SimpleNamespace(
                boundary=str(Path(B.BENCHMARK) / f"config/boundary_{project}.yml"),
                repo=temporary, profile=None)
        for project in ("prestashop", "sylius", "python_docx", "algorand", "e_petitions", "coddy_agent"):
            assert C._derived_baseline(derived_args(project), temporary) == {}, project
        try:
            C._derived_baseline(derived_args("coreshop"), temporary)
        except SystemExit as exc:
            assert "var/classes" in str(exc) and "nothing to restore" in str(exc)
        else:
            raise AssertionError("CoreShop accepted a seed without its derived classes")
        member = "var/classes/DataObject/CoreShopProduct.php"
        original = b"<?php // seeded product class\n"
        with tarfile.open(archive, "w") as tar:
            info = tarfile.TarInfo(member)
            info.size = len(original)
            tar.addfile(info, io.BytesIO(original))
        assert C._derived_baseline(derived_args("coreshop"), temporary) == {member: original}
        assert C._derived_baseline(derived_args("prestashop"), temporary) == {}
        assert C._derived_baseline(derived_args("coddy_agent"), temporary) == {}
    print("  [PASS] project-specific derived baseline preserves CoreShop requirements without imposing them on other projects")

    def invoke(argv, *, before_execute=None):
        output = io.StringIO()
        with redirect_stdout(output):
            result = (C.main(argv) if before_execute is None else C.dispatch(
                argv, (C,), description="execution gate fixture",
                before_test_quality_execute=before_execute))
        assert result == 0, (argv, output.getvalue())
        return output.getvalue()

    def refuses(argv, message):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            try:
                C.main(argv)
            except SystemExit as exc:
                assert message in str(exc), (message, str(exc))
            else:
                raise AssertionError(f"command was admitted: {argv}")

    def sources(paths, *, input_root=None):
        provenance = Path(paths["provenance"])
        options = {
            "reference-scope": provenance / "collection-scope.json",
            "mutation-validation": Path(paths["mutation_validation"]) / "report.json",
            "manifest": paths["scored_manifest"], "map": paths["mutation_map"],
            "release": paths["release_items"], "map-release": paths["map_release"],
            "gold-baseline": paths["gold_baseline"],
            "reference-gold": paths["gold"], "reference-release-gold": paths["release_gold"],
            "reference-closures": provenance / "reference-closures.json",
        }
        if paths.get("task_binding") is not None:
            options["reference-task-binding"] = paths["task_binding"]
        if input_root is not None:
            options.update({"validation-inputs": Path(paths["mutation_validation"]) / "inputs.json",
                            "input-root": input_root})
        return [value for name, path in options.items() for value in ("--" + name, str(path))]

    def reference_trees(paths):
        return ["--reference-inputs", paths["reference_inputs"],
                "--reference-recipes", str(Path(paths["provenance"]) / "reference-recipes"),
                "--reference-controls", paths["gold_results"]]

    for verb, tail in (("mutation-run", ["--mutation-validation", "fixture-report",
            "--manifest", "fixture-manifest", "--seed", "fixture-seed",
            "--worker-pool", "fixture-worker", "--map", "fixture-map",
            "--candidate", "fixture-candidate", "--out", "fixture-out"]),
            ("test-quality", ["--run", "fixture-run"])):
        with patch.object(C, "cmd_" + verb.replace("-", "_"), return_value=0) as command:
            invoke([verb, *tail, "--java-analysis-root", "fixture-compiler-capture"])
            assert command.call_args.args[0].java_analysis_root == "fixture-compiler-capture"
    try:
        C._mutation_java_analysis_root(SimpleNamespace(java_analysis_root="absent-root"),
                                       {"engine": "r2t-mutate-py"}, ["absent-worker"])
    except SystemExit as exc:
        assert "requires a Kapua module-analysis manifest" in str(exc)
    else:
        raise AssertionError("separate compiler root accepted for another engine")
    print("  [PASS] both mutation verbs admit the explicit compiler root; other engines refuse before file access")

    with patch.object(C, "_cmd_test_quality_slice3",
                      side_effect=AssertionError("mixed request reached historical scoring")):
        for flag in ("--reference-scope", "--reference-controls", "--reference-attestation",
                     "--reference-gold", "--validation-inputs", "--input-root", "--map-release"):
            refuses(["test-quality", "--run", "absent-private-run", "--slice3-bundle", "absent-slice3",
                     flag, "absent-reference-input"], "Slice-3 preserved scoring is incompatible")
    with patch.object(R, "run_publication_v3",
                      side_effect=AssertionError("unstamped request reached publication execution")):
        refuses(["run", "--adapter", "gold", "--publication-v3",
                 "--reference-source-tag", "fixture-reference"], "does not record --reference-source-tag")
        refuses(["run", "--adapter", "stripped-gold", "--publication-v3",
                 "--reference-source-tag", "fixture-reference", "--assertion-selection-policy",
                 "r2t.reviewed-assertion-targets/1"], "does not record --reference-source-tag")
    print("  [PASS] incompatible historical/publication dispatch refuses before evidence or runtime access")

    # specifications/SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md: the refusal
    # matrix of the labelled reference basis, before any input is opened.
    scoped_tq = ["test-quality", "--run", "absent-run",
                 "--reference-scope", "absent-scope",
                 "--reference-controls", "absent-controls"]
    labelled = ["--sensitivity", "sylius_stub_gate_waived_v1"]
    for argv in ([*scoped_tq, *labelled],
                 [*scoped_tq, *labelled, "--development",
                  "--reference-attestation", "absent-attestation"],
                 ["test-quality", "--run", "absent-run",
                  "--reference-controls", "absent-controls", *labelled,
                  "--development"]):
        refuses(argv, "--sensitivity scores a --development candidate")
    for stray in (["--allow-excluded-pairs"],
                  ["--gold-disagreements", "absent-disagreements"]):
        for verb in ("test-quality", "report"):
            refuses([verb, "--run", "absent-run", *stray],
                    "belong to a labelled reference --sensitivity basis")
        refuses(["test-quality", "--run", "absent-run", "--development",
                 "--sensitivity", "webmock_world_v1", *stray],
                "belong to a labelled reference --sensitivity basis")
    refuses(["report", "--run", "absent-run", *labelled],
            "--sensitivity reopens a summary")
    refuses(["report", "--run", "absent-run", "--reference-scope", "absent-scope",
             "--reference-controls", "absent-controls",
             "--reference-attestation", "absent-attestation", *labelled],
            "in place of --reference-attestation")
    refuses(["results", "--run", "absent-run", "--reference-controls",
             "absent-controls", *labelled], "in place of --reference-attestation")
    refuses(["report", "--run", "absent-a", "--run", "absent-b",
             "--non-vacuous-out", "absent-out"], "exactly one --run")
    print("  [PASS] --sensitivity, --allow-excluded-pairs and "
          "--gold-disagreements refuse every incomplete or stray combination "
          "on test-quality, report and results before reading an input")

    # THE BUDGETED DERIVED MAP (HEADROOM_SUBSET_AND_BUDGETED_SAMPLE_SPEC.md
    # section 2).  Both mutation verbs take the sidecar, and the one route
    # they have that is welded to a reviewed registered population refuses
    # it: a budgeted row is a development row.
    for verb in ("mutation-run", "test-quality"):
        surface = io.StringIO()
        try:
            with redirect_stdout(surface):
                C.main([verb, "--help"])
        except SystemExit:
            pass
        assert "--budgeted-sidecar" in surface.getvalue(), verb
    with patch.object(C, "_cmd_test_quality_slice3",
                      side_effect=AssertionError(
                          "a Slice-3 request with a sidecar reached scoring")):
        refuses(["test-quality", "--run", "absent-private-run",
                 "--slice3-observations", "absent-observations",
                 "--slice3-bundle", "absent-slice3",
                 "--budgeted-sidecar", "absent-sidecar"],
                "Slice-3 preserved scoring is incompatible with "
                "--budgeted-sidecar")
    with patch.object(C, "_validated_mutation_assets",
                      side_effect=AssertionError(
                          "welded budgeted request reached asset validation")):
        refuses(["mutation-run", "--mutation-validation", "absent-report",
                 "--manifest", "absent-manifest", "--seed", "absent-seed",
                 "--worker-pool", "absent-worker", "--map", "absent-map",
                 "--candidate", "absent-candidate", "--out", "absent-out",
                 "--reference-role", "full-gold",
                 "--reference-source-tag", "fixture-reference",
                 "--reference-scope", "absent-scope",
                 "--budgeted-sidecar", "absent-sidecar"],
                "--budgeted-sidecar is refused with --reference-scope")
    print("  [PASS] both mutation verbs take --budgeted-sidecar; a reviewed "
          "collection scope and the Slice-3 preserved route each refuse it "
          "by name, before any input is read")

    # Continuation is a separate authenticated full-gold route. Ordinary
    # partial selectors remain inadmissible even when a plan is supplied.
    continuation_command = ["mutation-run", "--mutation-validation", "absent-report",
        "--manifest", "absent-manifest", "--seed", "absent-seed",
        "--worker-pool", "absent-worker", "--map", "absent-map",
        "--candidate", "absent-candidate", "--out", "absent-out",
        "--continuation-plan", "absent-plan"]
    with patch.object(C, "_validated_mutation_assets",
                      side_effect=AssertionError("invalid continuation reached asset validation")):
        refuses(continuation_command, "requires --reference-role full-gold")
        refuses([*continuation_command, "--reference-role", "stub-control"],
                "requires --reference-role full-gold")
        for partial in (["--sample", "1"], ["--sample-seed", "7"],
                        ["--mutant-limit", "1"], ["--pair-plan", "absent-pair-plan"]):
            refuses([*continuation_command, "--reference-role", "full-gold",
                     "--reference-source-tag", "fixture-reviewed-reference",
                     "--side", "gold", *partial], "complete unsampled population")
    print("  [PASS] continuation requires full gold and never admits ordinary partial selectors")

    with tempfile.TemporaryDirectory(prefix="budgeted-cli-") as budgeted_root:
        from ..data import subsets as SUB
        from ..toolkit.subset_writer import write_budgeted_sample
        bd = Path(budgeted_root)
        # One item covering BOTH of the fixture's mutants, so B=1 is a real
        # restriction rather than the whole parent under another name.
        budgeted_fixture = fixture_evaluation_inputs(
            bd / "source",
            coverage_changes={"coverage_lines": {"src/app.py": [1, 2]}})
        role_paths = budgeted_fixture["role_sources"]
        budget_report = str(Path(role_paths["mutation_validation"])
                            / "report.json")
        parent_map = json.loads(
            Path(role_paths["mutation_map"]).read_text(encoding="utf-8"))
        draw = SUB.budgeted_sample(role_paths["map_release"],
                                   role_paths["mutation_map"],
                                   role_paths["scored_manifest"], 1, 20260911)
        derived_path, sidecar_path = write_budgeted_sample(
            draw, str(bd / "budgeted_sample"))
        assert draw["derived_map"]["n_pairs"] < parent_map["n_pairs"], (
            draw["derived_map"]["n_pairs"], parent_map["n_pairs"])
        campaign = dict(manifest_path=role_paths["scored_manifest"],
                        release_path=role_paths["map_release"],
                        require_release_ready=True)
        try:
            MA.validate_campaign_asset_inputs(
                budget_report, map_path=derived_path, **campaign)
            raise AssertionError("a derived map was admitted with no sidecar")
        except MA.MutationAssetRefused as exc:
            assert "campaign map input SHA-256" in str(exc), str(exc)
        budgeted_assets = MA.validate_campaign_asset_inputs(
            budget_report, map_path=derived_path,
            budgeted_sidecar=sidecar_path, **campaign)
        full_assets = MA.validate_campaign_asset_inputs(
            budget_report, map_path=role_paths["mutation_map"], **campaign)
        # What the leg will EXECUTE is the budget, not the population: this
        # is the pair set `mutation-run` slices out of `assets["map"]`.
        assert budgeted_assets["map"] == draw["derived_map"]
        assert budgeted_assets["map"] != full_assets["map"]
        assert budgeted_assets["population_basis"] == "budgeted_sample"
        assert budgeted_assets["budgeted_sample_sha256"] == MR.sha256_file(
            sidecar_path)
        assert budgeted_assets["parent_map_sha256"] == MR.sha256_file(
            role_paths["mutation_map"])
        assert set(full_assets) == set(budgeted_assets) - {
            "population_basis", "budgeted_sample_sha256", "parent_map_sha256"}
        # ...and the verbs' own asset resolver hands the flag down, which is
        # the only reason the leg ever sees the derived map.
        assert C._validated_mutation_assets(
            SimpleNamespace(mutation_validation=budget_report,
                            manifest=role_paths["scored_manifest"],
                            map=derived_path,
                            release=role_paths["map_release"],
                            budgeted_sidecar=sidecar_path),
            paid_view_subset=False, compact_allowed=False) == budgeted_assets
    print("  [PASS] a derived map refused by the campaign map pin is "
          "admitted with its sidecar, and the assets a leg runs are then the "
          "budget's own pairs")

    with patch.object(C, "_require_bound_live_worker",
                      side_effect=AssertionError("invalid control policy reached runtime admission")):
        for project, boundary_name in (("coreshop", "boundary_coreshop.yml"),
                                       ("algorand-sdk", "boundary_algorand.yml")):
            refuses(["--boundary", str(Path(B.BENCHMARK) / "config" / boundary_name),
                     "run", "--adapter", "stripped-gold", "--reference-source-tag", "fixture-reference",
                     "--release", "absent-release-before-policy-admission"],
                    "evaluation control policy")
        refuses(["--boundary", str(Path(B.BENCHMARK) / "config/boundary_python_docx.yml"),
                 "run", "--adapter", "stripped-gold", "--reference-source-tag", "fixture-reference",
                 "--assertion-selection-policy", "r2t.reviewed-assertion-targets/1",
                 "--release", "absent-release-before-policy-admission"],
                "evaluation control policy")
    print("  [PASS] prospective baseline policy refuses before release or runtime access")

    with tempfile.TemporaryDirectory(prefix="evaluation-cli-") as temporary:
        root = Path(temporary)
        for project in ("coreshop", "algorand-sdk"):
            policy_fixture = fixture_evaluation_inputs(root / ("recipe-" + project), project=project)
            recipe_path = root / (project + "-stripped-recipe.json")
            with policy_fixture["patch_context"]():
                command = ["reference", "recipe", *sources(policy_fixture["role_sources"]),
                           "--reference-role", "assertion-stripped-gold", "--out", str(recipe_path)]
                refuses(command, "evaluation control policy")
                assert not recipe_path.exists()
                recipe = json.loads(invoke([*command, "--assertion-selection-policy",
                                            "r2t.reviewed-assertion-targets/1"]))
                assert recipe["control_policy"] == "r2t.reviewed-assertion-targets/1"
        print("  [PASS] native CoreShop and Algorand recipe commands require the approved policy before output")
        fixture = fixture_evaluation_bundle_inputs(root / "source")
        paths = fixture["role_sources"]
        with fixture["patch_context"](), patch.dict(E.PROJECT_SCOPES,
                {"python-docx": fixture["project_scope"]}), patch.dict(os.environ,
                {"R2T_DATA_ROOT": str(root / "installed")}):
            common = sources(paths)
            stamp_args = SimpleNamespace(adapter="gold", release=paths["release_items"],
                reference_source_tag="fixture-reviewed-reference", assertion_selection_policy=None)
            adapter = Adapter("gold", lambda _item: {}, {"adapter_version": 1})
            stamp = R._run_stamp(stamp_args, adapter)
            assert stamp["reference_derivation"] == {
                "adapter": "gold", "adapter_version": 1,
                "release_sha256": MR.sha256_file(paths["release_items"]), "control_policy": None}
            assert stamp["reference_source_tag"] == "fixture-reviewed-reference"
            ordinary_args = SimpleNamespace(adapter="gold", release=paths["release_items"])
            ordinary = R._run_stamp(ordinary_args, adapter)
            assert "reference_derivation" not in ordinary and "reference_source_tag" not in ordinary
            for existing, requested in ((stamp, ordinary), (ordinary, stamp)):
                resumed = _rows(root / "resume.jsonl", [{"item_id": fixture["item_id"],
                                                         "outcome": "passed", **existing}])
                try:
                    R._resume_set(resumed, requested, retry_failed=False, no_resume=False)
                except SystemExit as exc:
                    assert "different run configuration" in str(exc)
                else:
                    raise AssertionError("reference derivation was silently added/dropped on resume")
            print("  [PASS] actual control version/task/policy/tag are recorded prospectively without restamping history")

            materialized_scope = root / "instantiated-scope.json"
            actual_scope = json.loads(invoke(["reference", "scope", *common, "--out", str(materialized_scope)]))
            assert actual_scope == json.loads(Path(fixture["common_args"]["scope_path"]).read_text())
            created_recipe = root / "full-gold.recipe.json"
            actual_recipe = json.loads(invoke(["reference", "recipe", *common,
                "--reference-role", "full-gold", "--out", str(created_recipe)]))
            assert actual_recipe["adapter_version"] == 1 and actual_recipe["control_policy"] is None
            assert set(actual_recipe) == {"adapter", "adapter_version", "release_sha256", "asset_index_sha256", "control_policy"}
            print("  [PASS] literal scope and recipe commands emit exact admitted inputs without fabricated pins")
            for role, spelling in (("full_gold", "full-gold"),
                    ("stripped_gold", "assertion-stripped-gold"), ("stub", "stub-control")):
                plan = json.loads(invoke(["reference", "plan", *common,
                    "--candidate", str(Path(paths["reference_inputs"]) / role / "run.jsonl"),
                    "--reference-role", spelling,
                    "--reference-source-tag", "fixture-reviewed-reference",
                    "--reference-recipe", str(Path(paths["provenance"]) / "reference-recipes" / (role + ".json"))]))
                assert plan["items"] == 1 and plan["pairs"] == 1
                assert plan["generation"]["reference_control_role"] == spelling
                assert plan["scope"]["task_items_sha256"] != plan["scope"]["map_release_sha256"]
            print("  [PASS] literal reference plan authenticates every role and separate task/map identities")
            refuses(["reference", "plan", *common,
                "--candidate", str(Path(paths["reference_inputs"]) / "stub/run.jsonl"),
                "--reference-role", "full-gold", "--reference-source-tag", "fixture-reviewed-reference",
                "--reference-recipe", str(Path(paths["provenance"]) / "reference-recipes/full_gold.json")],
                "reference derivation")
            sealed = root / "sealed.json"
            seal_command = ["reference", "seal", *common, *reference_trees(paths),
                            "--reference-engine-source", paths["engine_source"], "--out", str(sealed)]
            seal = json.loads(invoke(seal_command))
            assert seal["reference_digest"] == fixture["loaded"]["controls"]["digest"]
            refuses(seal_command, "already exists")
            validation = json.loads(invoke(["reference", "validate", *common, *reference_trees(paths),
                "--reference-engine-source", paths["engine_source"], "--reference-attestation", str(sealed)]))
            assert validation["reference_digest"] == seal["reference_digest"]
            print("  [PASS] literal seal/validate rederive controls and refuse overwriting an attestation")

            build = root / fixture["selected"]["asset"]
            refuses(["bundle", "build", "--project", "python-docx", "--version", E.RELEASE_TAG,
                     "--out", str(build), "--candidate-run", str(root / "absent-candidate")],
                    "incompatible inputs")
            assert not build.exists()
            built = json.loads(invoke(["bundle", "build", "--project", "python-docx",
                "--version", E.RELEASE_TAG, "--inputs", fixture["descriptor_path"], "--out", str(build)]))
            private_index = root / "private-index.json"
            measured = json.loads(invoke(["bundle", "measure-index", "--archive", str(build),
                "--manifest", built["manifest"], "--out", str(private_index)]))
            assert measured["asset"]["sha256"] == MR.sha256_file(str(build))
            shutil.move(root / "source", root / "producer-unavailable")
            installed = json.loads(invoke(["bundle", "install", "--project", "python-docx",
                "--version", E.RELEASE_TAG, "--archive", str(build), "--release-index", str(private_index)]))
            assert installed["release_ready"]
            moved = root / "relocated"
            shutil.move(root / "installed", moved)
            os.environ["R2T_DATA_ROOT"] = str(moved)
            validated = json.loads(invoke(["bundle", "validate", "--project", "python-docx",
                "--version", E.RELEASE_TAG, "--release-index", str(private_index)]))
            installed_paths = validated["role_paths"]
            invoke(["reference", "validate", *sources(installed_paths, input_root=moved),
                    *reference_trees(installed_paths), "--reference-engine-source", installed_paths["engine_source"],
                    "--reference-attestation", installed_paths["gold_results_attestation"]])
            print("  [PASS] literal build/measure/install/relocate/validate works without producer paths or candidates")

            # Use a new synthetic worker specification; it represents no live
            # pool. Only the physical execution/preflight leaves are replaced.
            private = root / "private-candidate"
            private.mkdir()
            worker = W.WorkerSpec(index=0, workspace=str(private / "workspace"),
                container="evaluation-cli-fixture", schema="", credential="",
                env_file=str(private / "worker.env"), workdir="/work")
            worker_file = private / "worker.json"
            worker_file.write_text(json.dumps(worker.to_json()))
            reference = ER.validate_evaluation_reference_inputs(
                project="python-docx", role_paths=installed_paths,
                scope=validated["manifest"]["scope"],
                validation_input_paths=validated["validation_input_paths"])
            authority = reference["controls"]["authority"]
            resources = [{"index": 0}]
            runtime = {**authority, "worker_resources": resources,
                       "worker_resources_sha256": MR.content_digest(resources),
                       "protected_evidence_paths": []}
            calls = []

            def execute(_h, mutants, items, files, mapping, _engine, out, *, identity, **kwargs):
                calls.append(identity)
                rows = [{"item_id": iid, "mutant_id": mutant["id"], "file": mutant["file"],
                         "operator": mutant["operator"], "outcome": "failed", "attempt": 1,
                         "retried_infrastructure": False, **MR.row_identity_stamp(identity)}
                        for mutant in mutants for iid in mapping[mutant["id"]] if iid in files]
                _rows(out, rows)
                for state in ("running", "complete"):
                    MR.write_shard_provenance(out, identity, state, provenance=kwargs.get("provenance"))
                return {"out": out, "rows": len(rows), "side": identity["side"]}

            run = _rows(private / "candidate.jsonl", [{"item_id": fixture["item_id"],
                "outcome": "passed", "produced_files": [{"file_path": "candidate.py", "code": "assert True\n"}]}])
            _engine_dir, real_applier = MR.binding_for("r2t-mutate-py")
            engine_dir = str(Path(installed_paths["engine_source"]).parent)
            fixture_applier = replace(real_applier, source=Path(installed_paths["engine_source"]).name)
            with ExitStack() as stack:
                stack.enter_context(patch.object(MR, "binding_for", return_value=(engine_dir, fixture_applier)))
                stack.enter_context(patch.object(C, "_stack_profile", return_value=SimpleNamespace(needs_database=False)))
                stack.enter_context(patch.object(C, "_stack", return_value=SimpleNamespace(engine_dir=engine_dir, FRAMEWORK="behave")))
                stack.enter_context(patch.object(C, "_harness", return_value=(SimpleNamespace(root=worker.workspace), None, None)))
                stack.enter_context(patch.object(W, "preflight", return_value={}))
                stack.enter_context(patch.object(W, "validate_mutation_runtime", return_value=runtime))
                stack.enter_context(patch.object(MR, "substrate_baseline_digest", return_value=authority["substrate_baseline_sha256"]))
                stack.enter_context(patch.object(MR, "run_slice", side_effect=execute))
                with patch.object(MR, "reference_generation_evidence",
                                  side_effect=AssertionError("old recipe inference used")):
                    reference_command = ["--worker", str(worker_file), "mutation-run",
                        *sources(installed_paths, input_root=moved),
                        "--profile", installed_paths["profile"],
                        "--candidate", str(Path(installed_paths["reference_inputs"]) / "full_gold/run.jsonl"),
                        "--reference-role", "full-gold", "--reference-source-tag", "fixture-reviewed-reference",
                        "--reference-recipe", str(Path(installed_paths["provenance"]) / "reference-recipes/full_gold.json"),
                        "--worker-pool", str(worker_file), "--seed", installed_paths["seed"],
                        "--side", "gold", "--timeout", str(authority["timeout_seconds"]),
                        "--out", str(private / "collected/full_gold/gold.w0.jsonl")]
                    sibling = replace(worker, index=1, workspace=str(private / "active-sibling"),
                                      container="evaluation-cli-sibling")
                    sibling_file = private / "worker1.json"
                    sibling_file.write_text(json.dumps(sibling.to_json()))
                    def own_sources_only(_args, _manifest, roots):
                        assert roots == [worker.workspace], "read an active sibling's source tree"
                        raise RuntimeError("assigned source root checked")
                    with patch.object(C, "_mutation_java_analysis_root", side_effect=own_sources_only):
                        try:
                            invoke([*reference_command, "--mutant-of", "2",
                                    "--worker-pool", str(worker_file), str(sibling_file)])
                        except RuntimeError as exc:
                            assert str(exc) == "assigned source root checked"
                        else:
                            raise AssertionError("standalone shard skipped compiler source admission")
                    invoke(reference_command)
                assert len(calls) == 1 and calls[0]["schema"] == MR.MUTATION_IDENTITY_SCHEMA_V5
                assert calls[0]["reference_control_role"] == "full-gold"
                assert calls[0]["release_sha256"] == MR.sha256_file(installed_paths["map_release"])
                assert "execution_policy" not in calls[0]
                # The continuation module authenticates parents and their
                # exact complement in its own self-test. Here exercise the
                # literal CLI wiring using this real full-release fixture.
                from . import mutation_continuation as MC
                pending = {(fixture["item_id"], mutant["id"])
                           for mutant in reference["assets"]["manifest"]["mutants"]
                           if fixture["item_id"] in reference["assets"]["map"]["by_mutant"].get(mutant["id"], [])}
                binding = {"partitions": [pending], "protected_paths": [],
                           "containment_paths": [str(private / "old-workspace")]}
                bound_calls = []
                def bind_continuation(bound, identity):
                    assert bound is binding
                    bound_calls.append(identity)
                    return identity
                with patch.object(MC, "validate_plan", return_value=binding), \
                        patch.object(MC, "validate_identity", side_effect=bind_continuation), \
                        patch.object(MR, "run_slice", return_value={}) as resumed:
                    invoke([*reference_command, "--continuation-plan", str(private / "plan.json"),
                            "--out", str(private / "continued/gold.w0.jsonl")])
                    assert len(bound_calls) == 1
                    for preflight_call in W.preflight.call_args_list[-2:]:
                        assert str(private / "old-workspace") in preflight_call.kwargs["containment_paths"]
                        assert str(private / "old-workspace") not in preflight_call.args[1]
                    assert resumed.call_args.kwargs["planned_pairs"] == pending
                    assert resumed.call_args.kwargs["continuation_plan_path"] == str(private / "plan.json")
                    resumed.reset_mock()
                    binding["partitions"] = [pending, pending]
                    refuses([*reference_command, "--continuation-plan", str(private / "plan.json")],
                            "worker count")
                    binding["partitions"] = [{("outside-item", "outside-mutant")}]
                    refuses([*reference_command, "--continuation-plan", str(private / "plan.json")],
                            "outside the unchanged candidate/map population")
                    resumed.assert_not_called()
                # Owner ruling 2026-09-30: a supplement host runs only its
                # slot of the frozen plan's pending pairs and names that plan.
                first = sorted(pending)[0]
                partition = {"allocation_sha256": "a" * 64, "host": "supplement", "offset": 0,
                             "total": 1, "supplement_plan_sha256": "b" * 64}
                plan_path = str(private / "supplement-plan.json")
                with patch.object(MR, "load_reference_supplement",
                                  return_value=(partition, 1, {first[1]: {first[0]}})) as loaded, \
                        patch.object(MR, "run_slice", return_value={}) as supplemented:
                    invoke([*reference_command, "--reference-allocation", "allocation.json",
                            "--reference-host", "supplement", "--reference-supplement-plan", plan_path,
                            "--out", str(private / "supplement/gold.w0.jsonl")])
                    assert loaded.call_args.args == (plan_path, "allocation.json", "supplement")
                    assert supplemented.call_args.kwargs["planned_pairs"] == {first}
                    assert supplemented.call_args.kwargs["identity"]["reference_partition"] == partition
                    refuses([*reference_command, "--reference-supplement-plan", plan_path],
                            "host partitions require")
                # Delegated 2026-09-30 (full282 section 5, fourth supplement):
                # a pair-slot plan deals single pairs, and the shard runs its own.
                dealt_pending = sorted(pending)[:3]
                dealt_by_mutant = {}
                for item, mutant in dealt_pending:
                    dealt_by_mutant.setdefault(mutant, set()).add(item)
                # This host holds slot 0 of two, so it runs a strict subset,
                # dealt by the same function the readers use on the whole manifest.
                paired = dict(partition, total=2, pair_slots=True)
                expected_dealt = MR.reference_shard_pairs(
                    reference["assets"]["manifest"], dealt_by_mutant, paired, 1)[0]
                assert expected_dealt and (expected_dealt < set(dealt_pending) or len(dealt_pending) == 1), \
                    (expected_dealt, dealt_pending)
                with patch.object(MR, "load_reference_supplement",
                                  return_value=(paired, 1, dealt_by_mutant)), \
                        patch.object(MR, "reference_shard_pairs", wraps=MR.reference_shard_pairs) as sharded, \
                        patch.object(MR, "run_slice", return_value={}) as dealt:
                    invoke([*reference_command, "--reference-allocation", "allocation.json",
                            "--reference-host", "supplement", "--reference-supplement-plan", plan_path,
                            "--out", str(private / "paired/gold.w0.jsonl")])
                    listed, _pending, used, workers = sharded.call_args.args
                    assert used == paired and workers == 1
                    assert [m["id"] for m in listed["mutants"]] == [
                        m["id"] for m in reference["assets"]["manifest"]["mutants"] if m["id"] in dealt_by_mutant]
                    assert dealt.call_args.kwargs["planned_pairs"] == expected_dealt
                    assert dealt.call_args.kwargs["identity"]["reference_partition"] == paired
                print("  [PASS] full-gold CLI routes authenticated pending pairs and refuses invalid shards")
                calls.clear()
                gated = []
                invoke(["test-quality", *sources(installed_paths, input_root=moved),
                    "--profile", installed_paths["profile"],
                    *reference_trees(installed_paths),
                    "--reference-attestation", installed_paths["gold_results_attestation"],
                    "--run", run, "--workers", str(worker_file), "--seed", installed_paths["seed"],
                    "--timeout", str(authority["timeout_seconds"]), "--out", str(private / "campaign"),
                    "--development"], before_execute=lambda job: gated.append(job["identity"]))
                assert gated == calls, "candidate hook did not see the exact executed jobs"
                # specifications/SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md, through
                # the literal verb: the labelled basis replaces the
                # attestation, and the pilot's disagreements document reaches
                # the loader and the summary with its source and digest.  The
                # label is bound to python-docx for this fixture only.
                disagreements_doc = private / "gold-disagreements.json"
                disagreements_doc.write_text(json.dumps({
                    "schema": RC.GOLD_DISAGREEMENTS_SCHEMA,
                    "source": "fixture host pilot", "pairs": []}))
                stack.enter_context(patch.dict(
                    RC.SENSITIVITY_PROJECTS,
                    {"sylius_stub_gate_waived_v1": "python-docx"}))
                sensitivity_loader = stack.enter_context(patch.object(
                    ER, "load_evaluation_sensitivity_reference",
                    wraps=ER.load_evaluation_sensitivity_reference))
                # A new candidate run: the eligible campaign above bound its
                # sidecar to `run`, and a binding is never overwritten.
                sensitivity_run = _rows(private / "sensitivity-candidate.jsonl",
                                        [json.loads(line) for line in
                                         Path(run).read_text().splitlines()])
                sensitivity_command = [
                    "test-quality", *sources(installed_paths, input_root=moved),
                    "--profile", installed_paths["profile"],
                    *reference_trees(installed_paths),
                    "--sensitivity", "sylius_stub_gate_waived_v1",
                    "--allow-excluded-pairs",
                    "--gold-disagreements", str(disagreements_doc),
                    "--run", sensitivity_run, "--workers", str(worker_file),
                    "--seed", installed_paths["seed"],
                    "--timeout", str(authority["timeout_seconds"]),
                    "--out", str(private / "sensitivity-campaign"),
                    "--development"]
                calls.clear()
                invoke(sensitivity_command)
                forwarded = sensitivity_loader.call_args.kwargs
                assert forwarded["sensitivity"] == "sylius_stub_gate_waived_v1"
                assert forwarded["allow_excluded_pairs"] is True
                assert forwarded["gold_disagreements"] == frozenset()
                assert forwarded["gold_disagreements_binding"] == {
                    "source": "fixture host pilot",
                    "sha256": MR.sha256_file(str(disagreements_doc))}
                assert calls and all(identity["side"] == "candidate"
                                     for identity in calls)
                sensitive = json.loads(
                    (private / "sensitivity-campaign/summary.json").read_text())
                assert sensitive["sensitivity"] == "sylius_stub_gate_waived_v1"
                assert sensitive["verdict_basis"] == "hard_subset"
                assert sensitive["inference_valid"] is False
                assert sensitive["reference_gold_disagreements"] == {
                    "source": "fixture host pilot",
                    "sha256": MR.sha256_file(str(disagreements_doc)),
                    "pairs": []}
                print("  [PASS] test-quality --sensitivity forwards the label, "
                      "the consent and the disagreements document (pairs, "
                      "source, SHA-256) to the loader and the summary")
                # `report` reopens that summary through the consumer reader:
                # the same three options re-derive the same controls, and
                # --non-vacuous-out writes the code-of-record block.
                report_reference = [
                    "--reference-scope", str(Path(installed_paths["provenance"]) / "collection-scope.json"),
                    "--reference-controls", installed_paths["gold_results"],
                    "--reference-validation", str(Path(installed_paths["mutation_validation"]) / "report.json"),
                    "--reference-manifest", installed_paths["scored_manifest"],
                    "--reference-map", installed_paths["mutation_map"],
                    "--reference-release", installed_paths["map_release"],
                    "--reference-execution-release", installed_paths["release_items"],
                    "--reference-gold-baseline", installed_paths["gold_baseline"],
                    "--reference-gold", installed_paths["gold"],
                    "--reference-release-gold", installed_paths["release_gold"],
                    "--reference-closures", str(Path(installed_paths["provenance"]) / "reference-closures.json"),
                    "--reference-inputs", installed_paths["reference_inputs"],
                    "--reference-recipes", str(Path(installed_paths["provenance"]) / "reference-recipes"),
                    "--reference-engine-source", installed_paths["engine_source"],
                    "--validation-inputs", str(Path(installed_paths["mutation_validation"]) / "inputs.json"),
                    "--input-root", str(moved),
                    *(["--reference-task-binding", installed_paths["task_binding"]]
                      if installed_paths.get("task_binding") is not None else [])]
                nv_path = private / "non_vacuous.json"
                report_command = [
                    "report", "--run", sensitivity_run,
                    # The binding sidecar test-quality wrote beside the run.
                    "--test-quality", str(private / "sensitivity-candidate.test_quality.json"),
                    *report_reference, "--sensitivity", "sylius_stub_gate_waived_v1",
                    "--allow-excluded-pairs",
                    "--gold-disagreements", str(disagreements_doc),
                    "--non-vacuous-out", str(nv_path)]
                refuses([arg for arg in report_command
                         if arg not in ("--sensitivity", "sylius_stub_gate_waived_v1",
                                        "--allow-excluded-pairs")
                         and arg != "--gold-disagreements"
                         and arg != str(disagreements_doc)],
                        "--reference-attestation")
                assert not nv_path.exists()
                printed = invoke(report_command)
                assert "sylius_stub_gate_waived_v1" in printed, printed[-800:]
                block = json.loads(nv_path.read_text())
                assert block["sensitivity"] == "sylius_stub_gate_waived_v1"
                assert block["publication_ready"] is False
                assert block["inference_valid"] is False
                assert block["non_vacuous_passes"] == sensitive["non_vacuous_passes"]
                refuses(report_command, "already exists")
                print("  [PASS] report reopens a sensitivity summary through "
                      "the consumer reader and writes its labelled "
                      "non_vacuous.json")
                # GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md through the literal
                # verb: the same labelled command with --candidate-pairs
                # gold-killed reaches the producer, the root plan and the
                # summary, and `report` reopens it with no new option.  This
                # fixture's one pair is a full-gold kill, so the slice is the
                # whole population; the narrowing is bench.test_quality's.
                gold_killed_run = _rows(
                    private / "gold-killed-candidate.jsonl",
                    [json.loads(line) for line in Path(run).read_text().splitlines()])
                gold_killed_command = [
                    gold_killed_run if arg == sensitivity_run else arg
                    for arg in sensitivity_command]
                gold_killed_command[gold_killed_command.index("--out") + 1] = \
                    str(private / "gold-killed-campaign")
                calls.clear()
                printed = invoke([*gold_killed_command,
                                  "--candidate-pairs", "gold-killed"])
                gold_killed = json.loads(
                    (private / "gold-killed-campaign/summary.json").read_text())
                gold_killed_root = json.loads(
                    (private / "gold-killed-campaign" / TQ.CAMPAIGN_STATE)
                    .read_text())["plan"]
                assert calls and all(identity["side"] == "candidate"
                                     for identity in calls)
                assert gold_killed["candidate_pair_scope"] == "gold-killed"
                assert gold_killed["withheld_measures"] == list(
                    TQ.SINGLE_OBSERVATION_GOLD_KILLED_WITHHELD)
                assert gold_killed["full_jaccard_macro"] is None
                assert gold_killed_root["candidate_pair_scope"]["scope"] == "gold-killed"
                for key in ("non_vacuous_passes", "recall_macro",
                            "hard_recall_macro", "full_recall_macro",
                            "verdicts", "sensitivity"):
                    assert gold_killed[key] == sensitive[key], key
                assert "candidate pairs: gold-killed only" in printed, printed[-800:]
                gold_killed_nv = private / "gold-killed-non_vacuous.json"
                gold_killed_report = [
                    gold_killed_run if arg == sensitivity_run else arg
                    for arg in report_command]
                gold_killed_report[gold_killed_report.index("--test-quality") + 1] = \
                    str(private / "gold-killed-candidate.test_quality.json")
                gold_killed_report[gold_killed_report.index("--non-vacuous-out") + 1] = \
                    str(gold_killed_nv)
                printed = invoke(gold_killed_report)
                assert "LABELLED POST-HOC SENSITIVITY sylius_stub_gate_waived_v1" \
                    in printed, printed[-800:]
                assert "candidate pairs: gold-killed only" in printed, printed[-800:]
                block = json.loads(gold_killed_nv.read_text())
                assert block["candidate_pair_scope"] == "gold-killed"
                assert block["sensitivity"] == "sylius_stub_gate_waived_v1"
                assert block["non_vacuous_passes"] == sensitive["non_vacuous_passes"]
                print("  [PASS] test-quality --candidate-pairs gold-killed binds "
                      "the scope into the root plan and summary, and report "
                      "reopens it, labelled and naming the scope")
                # VERSIONS.yml accepted_reference_appliers at the worker-pool
                # check: a pool whose applier differs from the one the
                # reference recorded refuses before any job runs, unless the
                # project's entry accepts it beside the recorded one; the
                # summary then records the pool's applier and validates.
                from ..data import versions as V
                later_applier = "f" * 64
                applier_run = _rows(private / "applier-candidate.jsonl",
                                    [json.loads(line) for line in
                                     Path(run).read_text().splitlines()])
                applier_command = [
                    "test-quality", *sources(installed_paths, input_root=moved),
                    "--profile", installed_paths["profile"],
                    *reference_trees(installed_paths),
                    "--reference-attestation", installed_paths["gold_results_attestation"],
                    "--run", applier_run, "--workers", str(worker_file),
                    "--seed", installed_paths["seed"],
                    "--timeout", str(authority["timeout_seconds"]),
                    "--out", str(private / "applier-campaign"), "--development"]
                with patch.object(MR, "runtime_applier_sha256",
                                  return_value=later_applier):
                    calls.clear()
                    refuses(applier_command, "field(s) ['applier_sha256']")
                    assert not calls
                    with patch.dict(V.component("harness"), {
                            "accepted_reference_appliers": {"python-docx": {
                                authority["applier_sha256"]: [later_applier]}}}):
                        invoke(applier_command)
                accepted = json.loads(
                    (private / "applier-campaign/summary.json").read_text())
                assert calls and all(identity["applier_sha256"] == later_applier
                                     for identity in calls)
                assert accepted["applier_sha256"] == later_applier
                print("  [PASS] a worker pool whose applier VERSIONS.yml accepts "
                      "beside the reference's recorded one scores and validates; "
                      "any other applier refuses before a job runs")
                # VERSIONS.yml accepted_reference_seeds at the same check: a
                # pool on another seed (workspace and substrate) refuses
                # before any job runs, unless the project's entry accepts
                # the pair, whole, beside the recorded one.
                later_seed = {"workspace_seed_digest": "e" * 64,
                              "substrate_baseline_sha256": "d" * 64}
                seed_entry = {"accepted_reference_seeds": {"python-docx": [{
                    "recorded": {key: authority[key] for key in V.SEED_FIELDS},
                    "accepted": [later_seed]}]}}
                seed_run = _rows(private / "seed-candidate.jsonl",
                                 [json.loads(line) for line in
                                  Path(run).read_text().splitlines()])
                seed_command = [
                    seed_run if arg == applier_run
                    else str(private / "seed-campaign")
                    if arg == str(private / "applier-campaign") else arg
                    for arg in applier_command]

                def seed_pool(workspace, substrate):
                    return (patch.object(W, "validate_mutation_runtime",
                                         return_value={
                                             **runtime,
                                             "workspace_seed_digest":
                                                 workspace}),
                            patch.object(MR, "substrate_baseline_digest",
                                         return_value=substrate))
                both = seed_pool(later_seed["workspace_seed_digest"],
                                 later_seed["substrate_baseline_sha256"])
                half = seed_pool(later_seed["workspace_seed_digest"],
                                 authority["substrate_baseline_sha256"])
                with both[0], both[1]:
                    calls.clear()
                    refuses(seed_command,
                            "field(s) ['substrate_baseline_sha256', "
                            "'workspace_seed_digest']")
                    with patch.dict(V.component("harness"), {
                            "accepted_reference_seeds": {"coreshop": seed_entry[
                                "accepted_reference_seeds"]["python-docx"]}}):
                        refuses(seed_command, "field(s) ['substrate_baseline_sha256', "
                                "'workspace_seed_digest']")
                    assert not calls
                with half[0], half[1], patch.dict(V.component("harness"), seed_entry):
                    refuses(seed_command, "field(s) ['workspace_seed_digest']")
                    assert not calls
                with both[0], both[1], patch.dict(V.component("harness"), seed_entry):
                    invoke(seed_command)
                seed_summary = json.loads(
                    (private / "seed-campaign/summary.json").read_text())
                assert calls and all(
                    identity[key] == later_seed[key]
                    for identity in calls for key in V.SEED_FIELDS)
                assert all(seed_summary[key] == later_seed[key]
                           for key in V.SEED_FIELDS)
                print("  [PASS] a worker pool on a seed VERSIONS.yml accepts, "
                      "workspace and substrate together, beside the "
                      "reference's recorded one scores and validates; one "
                      "field alone or another project's entry refuses before "
                      "a job runs")
            assert calls and all(identity["side"] == "candidate" for identity in calls)
            assert all("reference_control_role" not in identity for identity in calls)
            summary = json.loads((private / "campaign/summary.json").read_text())
            assert summary["release_sha256"] == MR.sha256_file(installed_paths["map_release"])
            assert summary["release_sha256"] != MR.sha256_file(installed_paths["release_items"])
            assert {row["side"] for row in summary["slices"]} == {"candidate"}
            print("  [PASS] literal installed test-quality executes only candidate jobs and retains map identity")
    # -- `_harness` opens the alias artifacts only where the ROW has them.
    #
    # `index` derives `alias_table.json` and `autowirable_types.json` from a
    # Symfony service container, and refuses to write either for a project
    # that has none (`services_entry: null`).  Opening them unconditionally
    # here made every command on such a row die on a file its own `index`
    # had declined to invent.  `_other_stack` is stood down because these two
    # boundaries are read for their behat ROW, not for stack routing -- which
    # file decides the framework is pinned in `r2t.stacks`.
    with tempfile.TemporaryDirectory(prefix="behat-rows-") as temporary:
        from .harness import Harness
        from .repo import StripManifest
        rows_root = Path(temporary)
        workspace = rows_root / "repo"
        (workspace / "_bench").mkdir(parents=True)
        gold = rows_root / "gold"
        gold.mkdir()
        artifacts = rows_root / "artifacts"
        artifacts.mkdir()
        StripManifest(repo_root=str(workspace), gold_root=str(gold)).save(
            str(gold / "strip_manifest.json"))
        context = "Tests\\Integration\\Behaviour\\Features\\Context\\CartContext"
        wired = "CoreShop\\Component\\Currency\\Repository\\CurrencyRepositoryInterface"
        index = {"files": {"CartContext.php": {"classes": [{
            "name": context, "kind": "class", "is_context": True,
            "constructor": [{"types": [wired], "has_default": False}]}]}}}
        nodi_boundary = rows_root / "boundary_prestashop.yml"
        nodi_boundary.write_text(
            "version: 1\n"
            "project: prestashop\n"
            "repo_root: " + str(workspace) + "\n"
            "removable:\n"
            "  - path: tests/Integration/Behaviour/Features/Context/Domain/\n"
            "retained:\n"
            "  - path: tests/Integration/Behaviour/bootstrap.php\n"
            "behat:\n"
            "  config_dir: tests/Integration/Behaviour\n"
            "  services_entry: null\n"
            "  hook_services: null\n"
            "  suites_entry: behat.yml\n"
            "  test_config: null\n"
            "  original_services_import: null\n"
            "  bench_services_import: null\n", encoding="utf-8")
        common = {"repo": str(workspace), "gold": str(gold),
                  "artifacts": str(artifacts), "container": "none",
                  "workdir": "/var/www/html", "profile": None}
        with patch.object(C, "_other_stack", return_value=None):
            nodi, nodi_row, _nodi_manifest = C._harness(SimpleNamespace(
                boundary=str(nodi_boundary), **common))
        assert nodi_row.project == "prestashop"
        assert nodi.behat.services_entry is None
        assert nodi.alias_table == {} and nodi.autowirable_types == set()
        assert not list(artifacts.iterdir()), "an artifact was invented"
        with patch.object(Harness, "invalidate_container", lambda self: None):
            registration = nodi.write_registration(index, {})
        assert registration["contexts"] == [context]
        assert registration["aliases"] == []

        (artifacts / "alias_table.json").write_text(
            json.dumps({wired: "coreshop.repository.currency"}),
            encoding="utf-8")
        (artifacts / "autowirable_types.json").write_text(
            json.dumps(["CoreShop\\Component\\Order\\Model\\OrderInterface"]),
            encoding="utf-8")
        coreshop_args = SimpleNamespace(
            boundary=str(Path(B.BENCHMARK) / "config/boundary_coreshop.yml"),
            **common)
        with patch.object(C, "_other_stack", return_value=None):
            coreshop, _coreshop_row, _coreshop_manifest = C._harness(
                coreshop_args)
        assert coreshop.behat.services_entry == "services.yml"
        assert coreshop.alias_table == {wired: "coreshop.repository.currency"}
        assert coreshop.autowirable_types == {
            "CoreShop\\Component\\Order\\Model\\OrderInterface"}
        with patch.object(Harness, "invalidate_container", lambda self: None):
            wired_registration = coreshop.write_registration(index, {})
        assert wired_registration["aliases"] == [wired]
        (artifacts / "alias_table.json").unlink()
        with patch.object(C, "_other_stack", return_value=None):
            try:
                C._harness(coreshop_args)
            except FileNotFoundError as exc:
                assert "alias_table.json" in str(exc)
            else:
                raise AssertionError(
                    "the CoreShop row stopped reading its alias table")
    print("  [PASS] the behat harness reads the alias artifacts for a row "
          "that has a service container and none for a row that has not")

    # -- `mutants build` walks and keeps the boundary's production roots ----
    #
    # Both halves used to be CoreShop literals here.  On a second Behat
    # project that enumerated `src/Sylius/**` and then excluded all of it,
    # because keeps that match nothing exclude everything -- an n=0 manifest
    # nothing downstream could mint an asset index from.  Both halves are
    # driven below: the argv the enumerator is handed, and the `exclusions`
    # the manifest is built with.  Stopping at the argv would test only half
    # of it, and the keep half is the half that decides what is SCORED.
    class BuildProbeStop(Exception):
        """Stops the verb AT `build_manifest`, holding the kwargs it got."""

    def drive_mutants_build(boundary_name, path=None, reach_manifest=False,
                            blank_roots=False):
        """Run `mutants build` against a fixture enumerator, and observe it."""
        from . import harness as _H, worker as _W
        from ..data import mutation as _M, mutation_attestation as _MA
        commands, manifest_kwargs = [], {}

        with tempfile.TemporaryDirectory(prefix="r2t-mutants-build-") as root:
            repository = os.path.join(root, "repo")
            os.makedirs(repository)

            class FixtureRunner:
                def __init__(self, container, workdir=None):
                    self.workdir = workdir

                def run(self, command, timeout=None):
                    commands.append(command)
                    if not reach_manifest:
                        return SimpleNamespace(returncode=1, stdout="",
                                               stderr="fixture: not executed")
                    # The verb reads the enumeration out of its own private
                    # scratch and refuses when the file is absent, so the
                    # fixture leaves one there.  Its CONTENT never matters:
                    # `load_enumerator_envelope` is patched below.
                    with open(os.path.join(repository, "var", "bench_mutate",
                                           "raw.json"), "w",
                              encoding="utf-8") as handle:
                        handle.write("{}")
                    return SimpleNamespace(returncode=0, stdout="", stderr="")

            def stop_at_manifest(*_positional, **kwargs):
                manifest_kwargs.update(kwargs)
                raise BuildProbeStop()

            build_args = SimpleNamespace(
                action="build", container="fixture-container",
                workdir="/var/www/html", repo=repository,
                boundary=str(Path(B.BENCHMARK) / "config" / boundary_name),
                profile=None, out=os.path.join(root, "population.json"),
                raw_out=None, path=path, sample=None, seed=None,
                operator_profile="v2", record_enumerator_rev=False)
            with ExitStack() as stack:
                stack.enter_context(patch.object(_H, "DockerRunner",
                                                 FixtureRunner))
                stack.enter_context(patch.object(
                    _W, "live_container_image_digest",
                    lambda *a, **k: "sha256:" + "0" * 64))
                if blank_roots:
                    # The REAL refusal, over the empty root tuple a
                    # `prod_paths: []` row produces.  (A row written with no
                    # YAML value never gets this far: `behat_project`
                    # refuses a null there.)
                    real_policy = _M.exclusions_for_prod_paths
                    stack.enter_context(patch.object(
                        _M, "exclusions_for_prod_paths",
                        lambda *a, **k: real_policy(())))
                if reach_manifest:
                    stack.enter_context(patch.object(
                        _MA, "load_enumerator_envelope",
                        lambda *a, **k: {"mutants": [], "n_invalid": None,
                                         "enumerator_rev": None}))
                    stack.enter_context(patch.object(
                        _M, "read_parser_version",
                        lambda *a, **k: "nikic/php-parser 5.0.0@fixture"))
                    stack.enter_context(patch.object(_M, "build_manifest",
                                                     stop_at_manifest))
                stack.enter_context(redirect_stdout(io.StringIO()))
                try:
                    C.cmd_mutants(build_args)
                except BuildProbeStop:
                    assert reach_manifest, "stopped at a manifest not asked for"
                except SystemExit as exc:
                    if blank_roots:
                        return (str(exc), commands)
                    assert not reach_manifest and "mutate.php failed" in str(exc), \
                        str(exc)
                else:
                    raise AssertionError("the fixture runner was not used")
        assert not blank_roots, "a row with no root was admitted"
        assert len(commands) == 1, commands
        argv = commands[0].split()
        return ([argv[index + 1] for index, token in enumerate(argv)
                 if token == "--path"], manifest_kwargs)

    from ..data import mutation as _MUTATION
    walked, kept = drive_mutants_build("boundary_coreshop.yml",
                                       reach_manifest=True)
    assert walked == ["src/CoreShop/Component", "src/CoreShop/Bundle"], walked
    assert kept["exclusions"] == _MUTATION.EXCLUDED_PREFIXES, kept
    print("  [PASS] `mutants build` still walks CoreShop's two production "
          "roots and keeps exactly EXCLUDED_PREFIXES, both now read from the "
          "row rather than written in the verb")
    walked, kept = drive_mutants_build("boundary_sylius.yml",
                                       reach_manifest=True)
    assert walked == ["src/Sylius/Component", "src/Sylius/Bundle",
                      "src/Sylius/Abstraction"], walked
    assert kept["exclusions"] == (
        "!src/Sylius/Component", "!src/Sylius/Bundle",
        "!src/Sylius/Abstraction", "vendor/", "var/"), kept
    print("  [PASS] a second Behat project's build walks ITS three production "
          "roots and keeps them, which the CoreShop literals never could")
    walked, _kept = drive_mutants_build("boundary_sylius.yml",
                                        path=["src/Sylius/Component"])
    assert walked == ["src/Sylius/Component"], walked
    print("  [PASS] an explicit --path still decides what is walked")
    refusal, ran = drive_mutants_build("boundary_sylius.yml",
                                       blank_roots=True)
    assert refusal.startswith("REFUSED: a mutation population needs at least "
                              "one production root"), refusal
    assert ran == [], ran
    print("  [PASS] a row that names no production root refuses in a line, "
          "before the enumeration the verb allows 3600 s for")

    # -- `mutants validate --audit-root` picks its applier transport -------
    #
    # A Behat/PHP audit runs the applier.  On a host with no `php` that used
    # to die inside `subprocess`; with `--worker` it runs inside the pool's
    # image instead.  Both are decided here, in the verb, from the argv.
    from ..toolkit import mutation_audit as AUDIT
    from ..data import mutation as MUT

    with tempfile.TemporaryDirectory(prefix="r2t-audit-transport-") as root:
        disposable = os.path.realpath(os.path.join(root, "copy"))
        os.makedirs(os.path.join(disposable, "src"))
        with open(os.path.join(disposable, "src", "Money.php"), "wb") as fh:
            fh.write(b"<?php\nreturn $a + $b;\n")
        os.makedirs(os.path.join(disposable, "vendor"))
        with open(os.path.join(disposable, "vendor", "autoload.php"), "w",
                  encoding="utf-8") as fh:
            fh.write("<?php\n")
        with open(os.path.join(disposable, "composer.lock"), "w",
                  encoding="utf-8") as fh:
            json.dump({"packages": [{
                "name": "nikic/php-parser", "version": "v5.3.1",
                "dist": {"reference": "0d1a1c1fixture"}}]}, fh)
        with open(os.path.join(disposable, MA.DISPOSABLE_MARKER), "w",
                  encoding="utf-8") as fh:
            fh.write(AUDIT.DISPOSABLE_MARKER_CONTENT)
        php_manifest = MUT.build_manifest(
            [{"file": "src/Money.php", "operator": "ArithmeticOperator",
              "start_line": 2, "start_col": 11,
              "original": "+", "mutated": "-"}],
            parser_version="nikic/php-parser v5.3.1@0d1a1c1fixture",
            operators=MUT.OPERATORS, exclusions=("!src", "vendor/"))
        by_mutant, uncovered = MUT.map_mutants_to_items(php_manifest, {})
        php_map = MA.build_map_artifact(
            php_manifest, by_mutant, uncovered,
            coverage_sha256="a" * 64, release_sha256="b" * 64)
        manifest_path = os.path.join(root, "population.json")
        map_path = os.path.join(root, "mutant_map.json")
        for path, document in ((manifest_path, php_manifest),
                               (map_path, php_map)):
            with open(path, "wb") as fh:
                fh.write(MA.canonical_bytes(document) + b"\n")

        def validate_argv(out_name, *extra):
            return ["mutants", "validate", "--manifest", manifest_path,
                    "--map", map_path, "--audit-root", disposable,
                    "--out", os.path.join(root, out_name), *extra]

        # `shutil` is stood in for so the refusal is the same on a host that
        # DOES have php as on the sprint hosts that do not.  It delegates
        # everything else to the real module: a stub with a hand-listed
        # surface makes a DELETED refusal fail on `AttributeError` somewhere
        # downstream instead of on the message this check is about.
        class PhplessShutil:
            which = staticmethod(lambda *a, **k: None)

            def __getattr__(self, name):
                return getattr(shutil, name)

        with patch.object(AUDIT, "shutil", PhplessShutil()):
            refuses(validate_argv("no-php.json"), "has no 'php' on PATH")
            refuses(validate_argv("no-php-2.json"),
                    "mutants validate --audit-root")
        print("  [PASS] a Behat/PHP audit on a host with no interpreter "
              "refuses by name, and names the worker binding instead of "
              "failing inside subprocess")

        bound_image = "sha256:" + "f" * 64
        seen = {}

        def capture_audit(manifest, audit_root, **kwargs):
            seen.update(kwargs)
            seen["audit_root"] = audit_root
            return {"status": "not_run", "reason": "fixture",
                    "expected_mutants": manifest["n"]}

        worker_spec = SimpleNamespace(
            index=0, workspace=disposable, container="sylius-pool-0",
            workdir="/work", out_path=None)
        with patch.object(C, "_worker_spec", lambda _args: worker_spec), \
                patch.object(C, "_bound_container_image",
                             lambda container: bound_image), \
                patch.object(AUDIT, "audit_with_engine", capture_audit):
            invoke(validate_argv("with-worker.json"))
        from .harness import DockerRunner as _DockerRunner
        bound_runner = seen.get("runner")
        assert seen["expected_image_id"] == bound_image, seen
        assert isinstance(bound_runner, _DockerRunner), type(bound_runner)
        assert bound_runner.container == "sylius-pool-0", bound_runner
        assert bound_runner.workdir == "/work", bound_runner
        assert seen["audit_root"] == disposable, seen
        assert seen["workers"] == 1, seen
        print("  [PASS] with a worker binding the verb hands the audit the "
              "pool's container, its workdir and the immutable image ID that "
              "container resolves to")

        # `--audit-workers` is the Java route's flag, and it means the same
        # thing: k disposable copies, one long-lived session container each.
        # It reaches the audit only where that transport exists.
        seen.clear()
        with patch.object(C, "_worker_spec", lambda _args: worker_spec), \
                patch.object(C, "_bound_container_image",
                             lambda container: bound_image), \
                patch.object(AUDIT, "audit_with_engine", capture_audit):
            invoke(validate_argv("k-way.json", "--audit-workers", "24"))
        assert seen["workers"] == 24, seen
        refuses(validate_argv("host-k-way.json", "--audit-workers", "24"),
                "--audit-workers selects the in-image r2t-mutate audit")
        refuses(validate_argv("host-k-way-2.json", "--audit-workers", "24"),
                "this run has no --worker binding")
        # ...and with no audit at all to spend it on.  This is the one place
        # the flag used to be accepted and ignored: the transport guard sat
        # inside `if args.audit_root:`.
        refuses(["mutants", "validate", "--manifest", manifest_path,
                 "--map", map_path, "--audit-workers", "24",
                 "--out", os.path.join(root, "no-audit-k-way.json")],
                "this run has no --audit-root to copy")
        print("  [PASS] --audit-workers reaches the in-image audit as its "
              "tree count, and on the host route -- or with no --audit-root "
              "at all -- is refused by name rather than accepted and ignored")

        # One worker spec drives a whole session, so a python-docx or Ruby
        # audit runs with `--worker` on the command line too.  Those stacks
        # have no in-image route: their audit must stay the host one, and
        # must not spend a `docker inspect` finding that out.
        from ..py import mutate as PY_MUTATE
        py_manifest = MUT.build_manifest(
            [{"file": "src/money.py", "operator": "ArithmeticOperator",
              "start_line": 1, "start_col": 8,
              "original": "+", "mutated": "-"}],
            parser_version=PY_MUTATE.parser_version(),
            operators=MUT.OPERATORS, exclusions=("!src",),
            engine=PY_MUTATE.ENGINE, engine_version=PY_MUTATE.ENGINE_VERSION)
        py_by_mutant, py_uncovered = MUT.map_mutants_to_items(py_manifest, {})
        py_manifest_path = os.path.join(root, "population_py.json")
        py_map_path = os.path.join(root, "mutant_map_py.json")
        for path, document in (
                (py_manifest_path, py_manifest),
                (py_map_path, MA.build_map_artifact(
                    py_manifest, py_by_mutant, py_uncovered,
                    coverage_sha256="c" * 64, release_sha256="d" * 64))):
            with open(path, "wb") as fh:
                fh.write(MA.canonical_bytes(document) + b"\n")
        seen.clear()
        inspected = []
        with patch.object(C, "_worker_spec", lambda _args: worker_spec), \
                patch.object(C, "_bound_container_image",
                             lambda container: inspected.append(container)), \
                patch.object(AUDIT, "audit_with_engine", capture_audit):
            invoke(["mutants", "validate", "--manifest", py_manifest_path,
                    "--map", py_map_path, "--audit-root", disposable,
                    "--out", os.path.join(root, "python-with-worker.json")])
        assert "runner" not in seen and "expected_image_id" not in seen, seen
        assert "workers" not in seen, seen
        assert inspected == [], inspected
        print("  [PASS] a non-PHP population with a worker on the command "
              "line still takes the host route, and no image is inspected "
              "to decide that")

        with patch.object(C, "_worker_spec", lambda _args: worker_spec), \
                patch.object(C, "_bound_container_image",
                             lambda container: bound_image):
            refuses(["mutants", "validate", "--manifest", py_manifest_path,
                     "--map", py_map_path, "--audit-root", disposable,
                     "--audit-workers", "24",
                     "--out", os.path.join(root, "python-k-way.json")],
                    "a r2t-mutate-py population, which has no in-image "
                    "transport")
        print("  [PASS] ...and a k-way walk of a population that has no "
              "in-image transport is refused by name too")

    print("ALL PASS (evaluation CLI)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
