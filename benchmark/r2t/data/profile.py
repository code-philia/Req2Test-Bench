"""S7 -- the TASK PROFILE: every project-specific word of the prompt, as data.

The benchmark's generation side was written against ONE repository and said
so in Python string constants: "All Behat test code has been removed from the
CoreShop repository", "PHP step-definition code",
`repo/src/CoreShop/Behat/`, a `behat_services.yml` DI channel, and a
readable-path tuple naming `composer.json`.  None of that is wrong for
CoreShop; all of it is wrong for the second project, and the only way to add
one was to edit the module that every already-published number was generated
with.  That is the worst possible place to require an edit: the prompt is an
INPUT, and a run file is only comparable with another run file if the input
did not move between them.

So the prompt is now assembled from a profile file that sits next to the
boundary it belongs to, and the CoreShop profile reproduces the shipped
prompt BYTE FOR BYTE (`prompt_digest` below, checked at load).  Adding
python+behave or java+cucumber is then a new pair of files, not a diff
against the file the CoreShop numbers came from.

WHY THE PROFILE AND THE BOUNDARY ARE ADJACENT.  They make claims about the
same tree and the claims have to agree.  The prompt tells the system where to
put its answer (`submission.acceptance_root`); the boundary decides what the
harness will ACCEPT.  When those two drifted apart in v0 the harness silently
discarded every file a compliant model wrote -- the model did as it was told
and scored `no_files_returned`.  `load_profile` therefore classifies the
acceptance root against the boundary the profile names and refuses to load
when it is not REMOVABLE, and does the same in reverse for the retained
carve-out the prompt promises is still there.  A prompt that cannot be obeyed
is a measurement of us, not of the system under test.

WHY THE DIGESTS ARE PER PROFILE.  There used to be one global
`_SYSTEM_PROMPT_SHA256` pinned in `adapters.selftest`.  With two projects
that constant becomes a claim that project 2's prompt equals project 1's,
which is false by construction -- so the first thing a second profile would
have forced is the deletion of the freeze that protects the first project's
published sweeps.  Each profile carries its own four digests instead
(single-shot plus the three agent conditions), verified every time it is
loaded, so a v2 project freezes v2 and CoreShop stays frozen against
CoreShop.

The rendering itself lives in `adapters.py`, not here: the prompt selftest
that reads the assembled artefact belongs with the code that assembles it,
and this module is the DATA plus the refusals.  `load_profile` reaches back
into `adapters` for the digest check through a function-local import, which
is also why that import is not at the top of the file.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field, replace
from typing import Optional

import yaml

from ..core.boundary import REMOVABLE, RETAINED, load_boundary

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(os.path.dirname(HERE), "config")

#: The profile the shipped v1 numbers were generated with.  Callers that pass
#: no profile get this one, so every entry point keeps working unchanged --
#: but nothing in the prompt path reads a CoreShop string any more, it reads
#: this file.
DEFAULT_PROFILE_PATH = os.path.join(CONFIG_DIR, "profile_coreshop.yml")

#: The four prompts a profile freezes.  `single_shot` is the system prompt of
#: the chat adapter (facts + JSON return contract); the other three are the
#: fully assembled agent prompts for the three agent conditions.  A profile
#: may freeze a fifth, `c2r`, the execution-enabled target-hidden prompt
#: (EXECUTION_ENABLED_TH_SENSITIVITY_SPEC.md section 4); it is not required
#: here, because only that study's variant profiles can render it.
PROMPT_KEYS = ("single_shot", "c1.5", "c2", "c3")

#: The placeholder that marks WHERE the wiring-channel fact belongs among the
#: environment facts.
#:
#: The DI bullet is the fourth of CoreShop's eight facts, and its position is
#: part of the frozen bytes -- so it cannot simply be appended when a project
#: has a wiring channel and dropped when it does not.  A profile with no
#: container (behave has none) either leaves the slot out or leaves it in and
#: has it dropped; a profile WITH a channel must contain the slot, because a
#: `wiring_channel` whose text is never emitted is a silently unused fact and
#: the prompt would then promise a delivery route the agent is never told
#: about.
WIRING_FACT_SLOT = "<wiring-channel>"

#: Release fields that identify what an item IS.  A profile that disagrees
#: with them is describing another corpus.
IDENTITY_FIELDS = ("project", "language", "framework")

#: The keys the optional `runtime:` block may carry, and their defaults.
#:
#: Closed rather than open, because the failure mode of an open one is silent:
#: `need_database: false` (one letter short) would leave `needs_database` at
#: its default True, and the operator would discover it when provisioning
#: created an empty MySQL schema for a library that has no database.  A typo
#: in a block whose whole purpose is to turn a provisioning step OFF has to be
#: a refusal.
RUNTIME_DEFAULTS = {"needs_database": True}

#: Whether this profile enables the API-similarity triple. Scoring also needs
#: a production-method index and recorded direct calls on both sides.
API_SCORING_METHOD_INDEX = "method_index"
API_SCORING_NONE = "none"
API_SCORING_MODES = frozenset(
    {API_SCORING_METHOD_INDEX, API_SCORING_NONE})

#: Fields interpolated into the prompt TEMPLATE -- the string that still has
#: `{task}` and `{instructions}` open when it is handed to `str.format`.
#: Checked for braces at load; see `_check_internal`.
_TEMPLATE_FIELDS = ("project_label", "language_label", "artefact_noun",
                    "removed_noun", "repo_dir", "acceptance_root",
                    "retained_note", "gherkin_suffix", "project_source_noun",
                    "retained_substrate", "client_interpreter", "runner_noun",
                    "trial_clause_runnable_entry")

#: Backtick-quoted tokens in `retained_note`, which is where a profile
#: promises the agent that something survived removal.  Cross-checked against
#: the boundary rather than trusted (see the module docstring).
_BACKTICKED = re.compile(r"`([^`]+)`")

#: The placeholders a C3 trial clause may use, and what fills each one.
#:
#: The clause is the ONE field that is a template rather than prose, so it is
#: the one field exempt from the no-braces rule in `_TEMPLATE_FIELDS` — and an
#: exemption without a check is how a profile ships a `{k}` nobody fills, which
#: is a `KeyError` in the middle of a paid sweep or, worse, a literal `{k}` in
#: the text sent to the model.
#:
#:   client       the trial client's path, known only once the socket exists
#:   k            the budget, in the BOUNDED form only
#:   interpreter  `trial.client_interpreter`, substituted by `trial_clause`
#:   runner       `trial.runner_noun`, likewise
_CLAUSE_PLACEHOLDERS = frozenset({"client", "k", "interpreter", "runner"})


class ProfileError(SystemExit):
    """A profile that cannot be trusted to describe this benchmark.

    `SystemExit` on purpose, and never caught per item: every problem this
    module reports is uniform across the whole release (a wrong acceptance
    root is wrong for item 1 and for item 422 alike), so failing at load is
    both correct and the cheapest possible moment -- an agent sweep spends
    real money per item and the alternative is discovering it afterwards.
    """


@dataclass(frozen=True)
class WiringChannel:
    """The out-of-band file a submission may use to wire its own classes.

    Nullable in the schema, and that is the whole point of it being here:
    CoreShop's contexts are Symfony services and a constructor argument that
    cannot be autowired needs an explicit `services:` fragment, while behave
    has no container at all.  Emitting CoreShop's DI bullet into a behave
    prompt would not merely be noise -- it would instruct the agent to
    produce a file the harness has nowhere to put.
    """

    name: str
    when_needed: str
    format: str
    auto_registration: str


#: The keys of the optional `guidance:` block, all required when it is present.
GUIDANCE_KEYS = ("id", "heading", "text")


@dataclass(frozen=True)
class Guidance:
    """A fixed block of method guidance appended to every agent prompt.

    The one place a profile may say something about HOW to work, which the
    base prompt deliberately does not (`prompt.agent_prompt_base`).  It exists
    for labelled intervention profiles: a byte copy of a shipped profile plus
    this block, whose agent prompts are then exactly the parent's followed by
    `prompt.guidance_block`.  Constant per profile and blind to the item, so it
    cannot carry per-item content; whether its wording stays within the
    agent's view is the specification's rule, checked when a profile is
    reviewed.

    `id` names the block for a reader of the file and is never rendered;
    `heading` and `text` are rendered verbatim.
    """

    id: str
    heading: str
    text: str


@dataclass(frozen=True)
class TaskProfile:
    """Everything the prompt says that is true of ONE project.

    Deliberately flat.  A profile is read in three places (the prompt
    renderer, the workspace seeder and the harvest) and every one of them
    wants one field, not a path through nested dictionaries; the YAML is
    grouped for a human reader and flattened on the way in.
    """

    # -- identity
    version: int
    project: str
    project_label: str
    language: str
    language_label: str
    framework: str
    api_scoring: str

    # -- the task statement
    artefact_noun: str
    gherkin_suffix: str
    removed_noun: str

    # -- where the answer goes, and how it is recognised on disk
    acceptance_root: Optional[str]
    example_path: str
    example_code: str
    placement_hint: str
    suffixes: tuple
    extra_names: tuple
    retained_note: str

    # -- the optional DI/registration channel
    wiring_channel: Optional[WiringChannel]

    # -- the agent's workspace
    repo_dir: str
    readable_paths: tuple

    # -- prose
    facts: tuple
    platform_blurb: str
    retained_substrate: str
    project_source_noun: str

    # -- the C3 trial client
    client_interpreter: str
    runner_noun: str

    # -- what C3's prompt says the agent may DO, in its two forms
    #
    # TWO forms because there are two things to say and only one of them
    # names a number.  The execution affordance is now bounded by the agent's
    # ITERATION budget (`trials.UNBOUNDED`, and the long WHY in that module's
    # docstring), so the shipped C3 arm renders the unbounded form; the
    # bounded form is what `--trials k` renders and is the wording every C3
    # sweep already on disk was generated with, kept byte-identical so those
    # rows stay attributable.
    #
    # The WORDING lives here, in the profile, rather than in the renderer, for
    # the same reason every other project-specific string does: choosing
    # between two clauses is logic and belongs in `prompt.trial_clause`,
    # while the sentences themselves are what this project says to a model and
    # belong in the file the digests are taken over.
    trial_clause_bounded: str
    trial_clause_unbounded: str
    # The `c2r` entry-point sentence (EXECUTION_ENABLED_TH_SENSITIVITY_SPEC.md
    # section 4.2), rendered after the runnable clause.  Only a project whose
    # own test command cannot run a Scenario in the view carries one; absent
    # everywhere else, so no other profile's bytes or prompts move.
    trial_clause_runnable_entry: Optional[str] = None

    # -- what the STACK needs in order to run at all (plan decision D6)
    #
    # Not a word of the prompt: this is the one field a profile carries that
    # the model never sees.  It lives here anyway because the profile is
    # already the per-project file every entry point resolves, and the
    # alternative -- a second project file, or a flag the operator has to
    # remember on every `worker provision` -- is how a python library ends up
    # provisioned with an empty MySQL schema and then refused for holding
    # fewer than 100 tables, which reads exactly like a broken seed.
    #
    # Defaulted to True, and DEFAULTED rather than required, so that every
    # profile written before the field existed keeps meaning what it meant:
    # CoreShop needs a database and says so by saying nothing.
    needs_database: bool = True

    # -- what the prompt DISCLOSES beyond the requirement (TARGET_INTERFACES_SPEC)
    #
    # A property of the profile, not of the item, and defaulted to False so
    # that every profile written before the field existed keeps rendering the
    # prompt it was frozen with.  When True, `prompt.build_user_prompt`
    # renders the item's `target_interfaces` list as one fixed block, and the
    # canonical fixture carries a list, so the four digests of a disclosing
    # profile differ from a non-disclosing twin's: the disclosure is frozen
    # by the same mechanism as every other word of the prompt.
    disclose_target_interfaces: bool = False
    #: The v2 disclosure (TARGET_INTERFACES_V2_SPEC section 5a): the product
    #: METHODS the scenario's action and check steps call, with their
    #: declarations.  A second flag rather than a second value of the first,
    #: because the two blocks are two disclosures with two shapes and a
    #: profile may carry either, both or neither.
    disclose_checked_interfaces: bool = False
    source_visibility: Optional[str] = None

    # -- method guidance appended to the agent prompt (`Guidance`)
    #
    # Defaulted to None for the same reason as the disclosure flags: every
    # profile written before the field existed renders nothing extra, so its
    # four frozen digests are the bytes they always were.
    guidance: Optional[Guidance] = None

    # -- provenance
    path: str = ""
    boundary_path: str = ""
    digest: str = ""
    prompt_digest: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
    acceptance_mode: str = "directory"

    def bullets(self) -> tuple:
        """The environment facts with the wiring slot resolved.

        Resolved HERE rather than at load time so the stored `facts` stay a
        faithful copy of the file -- `digest` covers the file's bytes and a
        reader comparing the two should not have to undo a substitution we
        made on the way in.
        """
        out = []
        for fact in self.facts:
            if fact == WIRING_FACT_SLOT:
                if self.wiring_channel is not None:
                    out.append(self.wiring_channel.auto_registration)
                continue                      # no channel: the fact is not true
            out.append(fact)
        return tuple(out)

    def acceptance_prefix(self) -> str:
        """`<repo_dir>/<acceptance_root>` -- what the prompt shows the agent."""
        if self.acceptance_mode == "item_path":
            raise ProfileError("REFUSED: item_path has no acceptance directory prefix")
        return f"{self.repo_dir}/{self.acceptance_root}"

    def harvest_suffixes(self) -> tuple:
        """Which files the harvest READS off the agent's workspace.

        The artefact's own suffixes plus the Gherkin one, deduplicated and in
        that order.  Two different questions, and this is the union of them:

        `submission.suffixes` is what a solution is MADE of.  The Gherkin
        suffix is here as well because the harvest's job is to see what the
        agent did, not to decide whether it counts -- that decision belongs
        to `map_files`, which classifies against the boundary and records a
        `.feature` the agent touched as `changed_outside_test_code`.  Drop it
        from the read and that edit becomes invisible rather than reported,
        and a `requirement_to_test` item (whose answer INCLUDES a `.feature`)
        would harvest to nothing at all.

        For CoreShop this is exactly `harvest`'s own historical default,
        which is what makes the parameterisation a no-op on the sweeps
        already on disk; `profile.selftest` pins that equality.
        """
        return tuple(dict.fromkeys(tuple(self.suffixes)
                                   + (self.gherkin_suffix,)))


# ------------------------------------------------------------------ loading
def _need(doc: dict, key: str, path: str, kind=None):
    if key not in doc or doc[key] is None:
        raise ProfileError(
            f"REFUSED: {path} has no `{key}`. A profile is the whole of what "
            f"the prompt knows about a project; a missing field would be "
            f"rendered as a hole in the text sent to the model.")
    val = doc[key]
    if kind is not None and not isinstance(val, kind):
        raise ProfileError(
            f"REFUSED: {path} field `{key}` is {type(val).__name__}, "
            f"expected {getattr(kind, '__name__', kind)}.")
    return val


def _need_str(doc: dict, key: str, path: str) -> str:
    val = _need(doc, key, path, str)
    if not val.strip():
        raise ProfileError(f"REFUSED: {path} field `{key}` is blank.")
    return val


def _need_list(doc: dict, key: str, path: str) -> tuple:
    val = _need(doc, key, path, list)
    bad = [v for v in val if not isinstance(v, str)]
    if bad:
        raise ProfileError(
            f"REFUSED: {path} field `{key}` contains non-string entries "
            f"{bad[:3]}.")
    return tuple(val)


def _runtime_of(doc: dict, path: str) -> dict:
    """The optional `runtime:` block, defaulted and closed (D6).

    Three refusals rather than a `.get` chain, and each of them is the same
    bug wearing a different hat: a `runtime` that is not a mapping, a key
    nobody reads, or a value that is not a boolean.  All three would leave
    `needs_database` at its default True, which is the ONE outcome that
    cannot be noticed by reading the file -- the profile says the stack has
    no database and the provisioner goes on creating one.

    Absent block means the CoreShop defaults, so nothing written before this
    existed has to change.
    """
    block = doc.get("runtime")
    if block is None:
        return dict(RUNTIME_DEFAULTS)
    if not isinstance(block, dict):
        raise ProfileError(
            f"REFUSED: {path} field `runtime` is {type(block).__name__}; it is "
            f"either a mapping of {sorted(RUNTIME_DEFAULTS)} or absent (absent "
            f"= the defaults {RUNTIME_DEFAULTS}).")
    unknown = sorted(k for k in block if k not in RUNTIME_DEFAULTS)
    if unknown:
        raise ProfileError(
            f"REFUSED: {path} `runtime` carries {unknown}, which nothing "
            f"reads. The known keys are {sorted(RUNTIME_DEFAULTS)}; a "
            f"misspelt one would leave the default in force and the profile "
            f"would be describing a stack that is not the one provisioned.")
    out = dict(RUNTIME_DEFAULTS)
    for key, default in RUNTIME_DEFAULTS.items():
        val = block.get(key, default)
        if not isinstance(val, type(default)):
            raise ProfileError(
                f"REFUSED: {path} `runtime.{key}` is {val!r} "
                f"({type(val).__name__}), expected "
                f"{type(default).__name__}. YAML reads `no` and `off` as "
                f"booleans but `\"false\"` as a string, and a truthy string is "
                f"how a stack that declares no database gets one anyway.")
        out[key] = val
    return out


def _boundary_path_for(profile_path: str, doc: dict) -> str:
    """The boundary a profile is cross-checked against.

    Resolved relative to the PROFILE's own directory and required to be a
    bare sibling name.  An absolute path or a `../` escape here would let a
    profile be validated against some other project's boundary while sitting
    next to the one it claims -- which is precisely the drift the adjacency
    exists to make impossible.
    """
    name = _need_str(doc, "boundary", profile_path)
    if os.path.isabs(name) or os.path.dirname(name):
        raise ProfileError(
            f"REFUSED: {profile_path} names its boundary as {name!r}. It must "
            f"be a bare filename sitting beside the profile, so the two "
            f"cannot drift apart or be pointed at different projects.")
    return os.path.join(os.path.dirname(os.path.abspath(profile_path)), name)


def _classify_probe(boundary, rel: str) -> str:
    """Classify a DIRECTORY the way a file inside it would be classified.

    `Boundary.classify` answers about paths, and a bare directory name misses
    its own prefix: `src/CoreShop/Behat/Context/Hook` does not start with
    `src/CoreShop/Behat/Context/Hook/`, so asking about the directory returns
    PRODUCTION for a tree that is plainly RETAINED.  Probing a synthetic file
    inside it asks the question the harness will actually ask.
    """
    rel = rel.rstrip("/")
    return boundary.classify(f"{rel}/__profile_probe__")


def load_profile(path: str = DEFAULT_PROFILE_PATH, *,
                 verify_digests: bool = True) -> TaskProfile:
    """Read a profile, cross-check it against its boundary, freeze its prompts.

    Three classes of refusal, and each one is a bug that has cost something:

    * a missing or mistyped field, because the renderer would otherwise
      interpolate `None` into the text sent to the model;
    * an acceptance root the boundary does not call REMOVABLE (or a retained
      carve-out it does not call RETAINED), because a prompt that tells the
      system to write where the harness refuses to accept is unobeyable, and
      that failure is recorded against the MODEL;
    * a prompt whose bytes no longer match the digests in the file, because
      every run already on disk was generated with the old bytes and a
      silently moved prompt makes them incomparable while still labelling
      them the same system.

    `verify_digests=False` exists for exactly one caller: the tool that
    computes the digests for a NEW profile, which cannot check what it is
    about to write.  It is not reachable from the CLI.
    """
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise ProfileError(
            f"REFUSED: no task profile at {path}. Every project the benchmark "
            f"runs needs one; pass --profile, or create "
            f"config/profile_<project>.yml beside its boundary.")
    with open(path, "rb") as fh:
        blob = fh.read()
    doc = yaml.safe_load(blob.decode("utf-8"))
    if not isinstance(doc, dict):
        raise ProfileError(f"REFUSED: {path} is not a YAML mapping.")

    task = _need(doc, "task", path, dict)
    sub = _need(doc, "submission", path, dict)
    ws = _need(doc, "workspace", path, dict)
    cond = _need(doc, "conditions", path, dict)
    trial = _need(doc, "trial", path, dict)

    wiring_doc = doc.get("wiring_channel")
    wiring = None
    if wiring_doc is not None:
        if not isinstance(wiring_doc, dict):
            raise ProfileError(
                f"REFUSED: {path} field `wiring_channel` is "
                f"{type(wiring_doc).__name__}; it is either a mapping or null "
                f"(null = this framework has no registration channel).")
        wiring = WiringChannel(
            name=_need_str(wiring_doc, "name", path),
            when_needed=_need_str(wiring_doc, "when_needed", path),
            format=_need_str(wiring_doc, "format", path),
            auto_registration=_need_str(wiring_doc, "auto_registration", path))

    runtime = _runtime_of(doc, path)

    facts = _need_list(doc, "facts", path)
    if wiring is not None and WIRING_FACT_SLOT not in facts:
        raise ProfileError(
            f"REFUSED: {path} declares a `wiring_channel` but its `facts` "
            f"list has no {WIRING_FACT_SLOT!r} slot, so the channel would be "
            f"offered in the collection contract and never explained in the "
            f"facts. Put the slot where the fact belongs.")

    acceptance_mode = sub.get("acceptance_mode", "directory")
    if acceptance_mode not in ("directory", "item_path"):
        raise ProfileError(f"REFUSED: {path} unknown submission.acceptance_mode")
    if acceptance_mode == "item_path" and "acceptance_root" in sub:
        raise ProfileError(f"REFUSED: {path} item_path must omit acceptance_root")

    prof = TaskProfile(
        version=_need(doc, "version", path, int),
        project=_need_str(doc, "project", path),
        project_label=_need_str(doc, "project_label", path),
        language=_need_str(doc, "language", path),
        language_label=_need_str(doc, "language_label", path),
        framework=_need_str(doc, "framework", path),
        api_scoring=_need_str(doc, "api_scoring", path),
        artefact_noun=_need_str(task, "artefact_noun", path),
        gherkin_suffix=_need_str(task, "gherkin_suffix", path),
        removed_noun=_need_str(task, "removed_noun", path),
        acceptance_mode=acceptance_mode,
        acceptance_root=(_need_str(sub, "acceptance_root", path)
                         if acceptance_mode == "directory" else None),
        example_path=_need_str(sub, "example_path", path),
        example_code=_need_str(sub, "example_code", path),
        # Defaulted rather than required: for most projects the placement
        # hint IS the acceptance root, and CoreShop is the exception only
        # because its prompt has always named the `Context/` subtree one
        # level down.
        placement_hint=str(sub.get("placement_hint")
                           or (_need_str(sub, "acceptance_root", path)
                               if acceptance_mode == "directory" else
                               "the exact item-specified glue path")),
        suffixes=_need_list(sub, "suffixes", path),
        extra_names=tuple(sub.get("extra_names") or ()),
        retained_note=str(sub.get("retained_note") or ""),
        wiring_channel=wiring,
        repo_dir=_need_str(ws, "repo_dir", path),
        readable_paths=_need_list(ws, "readable_paths", path),
        facts=facts,
        platform_blurb=_need_str(doc, "platform_blurb", path),
        retained_substrate=_need_str(cond, "retained_substrate", path),
        project_source_noun=_need_str(cond, "project_source_noun", path),
        client_interpreter=_need_str(trial, "client_interpreter", path),
        runner_noun=_need_str(trial, "runner_noun", path),
        trial_clause_bounded=_need_str(trial, "clause_bounded", path),
        trial_clause_unbounded=_need_str(trial, "clause_unbounded", path),
        trial_clause_runnable_entry=(
            _need_str(trial, "clause_runnable_entry", path)
            if "clause_runnable_entry" in trial else None),
        needs_database=runtime["needs_database"],
        disclose_target_interfaces=_disclosure_of(doc, path)["target_interfaces"],
        disclose_checked_interfaces=_disclosure_of(doc, path)["checked_interfaces"],
        source_visibility=_visibility_of(doc, path),
        guidance=_guidance_of(doc, path),
        path=path,
        boundary_path=_boundary_path_for(path, doc),
        # The FILE's bytes, not a canonicalised subset. Conservative on
        # purpose: this digest is mixed into the agent-seed cache key, and a
        # key that ignores a field would serve a stale seed after an edit
        # that turned out to matter after all.
        digest=hashlib.sha256(blob).hexdigest(),
        prompt_digest=dict(_need(doc, "prompt_digest", path, dict)),
        raw=doc)

    _check_against_boundary(prof)
    _check_internal(prof)
    if verify_digests:
        verify_prompt_digests(prof)
    return prof


def _visibility_of(doc: dict, path: str) -> Optional[str]:
    if "visibility" not in doc:
        return None
    value = doc["visibility"]
    if not isinstance(value, dict) or set(value) != {"scope", "feedback"}:
        raise ProfileError(f"REFUSED: {path}: invalid visibility declaration")
    if value["scope"] not in ("full", "target_hidden", "all_hidden") \
            or value["feedback"] != "final_only":
        raise ProfileError(f"REFUSED: {path}: unsupported visibility policy")
    if not any(_disclosure_of(doc, path).values()):
        raise ProfileError(f"REFUSED: {path}: source views require a "
                           f"target-interfaces or checked-interfaces disclosure")
    return value["scope"]


def refuse_source_view(profile, route: str) -> None:
    """Unintegrated routes fail before generation, for full/final_only too."""
    if getattr(profile, "source_visibility", None) is not None:
        raise ProfileError(f"REFUSED: {route} has no qualified per-item source-view route")


#: The disclosures a profile may declare, in the order they render.  Two:
#: the v1 type lists (TARGET_INTERFACES_SPEC) and the v2 checked methods
#: (TARGET_INTERFACES_V2_SPEC).  Anything else refuses -- the allowlist is
#: what stops a typo'd key from reading as "discloses nothing".
DISCLOSURE_KEYS = ("target_interfaces", "checked_interfaces")


def _disclosure_of(doc: dict, path: str) -> dict:
    """The optional `disclosure:` block, read as one bool per defined key.

    Absent means every key is False -- the profile renders exactly what it did
    before the block existed.  Present, it must be a mapping whose values are
    strict bools: a profile is what the prompt says, and "the profile
    discloses target interfaces" is a claim a reader must be able to check
    without inferring it from a truthy string.
    """
    block = doc.get("disclosure")
    if block is None:
        return {key: False for key in DISCLOSURE_KEYS}
    if not isinstance(block, dict):
        raise ProfileError(
            f"REFUSED: {path} field `disclosure` is {type(block).__name__}; "
            f"it is a mapping (or absent).")
    unknown = sorted(set(block) - set(DISCLOSURE_KEYS))
    if unknown:
        raise ProfileError(
            f"REFUSED: {path} `disclosure` names {unknown}; the only "
            f"disclosures this benchmark defines are "
            f"{list(DISCLOSURE_KEYS)}.")
    out = {}
    for key in DISCLOSURE_KEYS:
        val = block.get(key, False)
        if not isinstance(val, bool):
            raise ProfileError(
                f"REFUSED: {path} `disclosure.{key}` is "
                f"{type(val).__name__}, expected a bool.")
        out[key] = val
    return out


def _guidance_of(doc: dict, path: str) -> Optional[Guidance]:
    """The optional `guidance:` block, closed: exactly `GUIDANCE_KEYS`.

    Absent means no block, so the profile renders exactly what it did before
    the field existed.  Present, every key is a non-blank string -- a missing
    or misspelt `text` would otherwise render a heading over nothing -- and
    `heading` and `text` carry no brace: the block is appended to the prompt
    TEMPLATE, which is closed with `str.format` (the `_TEMPLATE_FIELDS` rule).
    """
    block = doc.get("guidance")
    if block is None:
        return None
    if not isinstance(block, dict):
        raise ProfileError(
            f"REFUSED: {path} field `guidance` is {type(block).__name__}; it "
            f"is a mapping of {list(GUIDANCE_KEYS)} (or absent).")
    if set(block) != set(GUIDANCE_KEYS):
        raise ProfileError(
            f"REFUSED: {path} `guidance` has keys {sorted(block)}; it has "
            f"exactly {list(GUIDANCE_KEYS)}.")
    for key in GUIDANCE_KEYS:
        val = block[key]
        if not isinstance(val, str) or not val.strip():
            raise ProfileError(
                f"REFUSED: {path} `guidance.{key}` is {val!r}; it is a "
                f"non-blank string.")
    for key in ("heading", "text"):
        if "{" in block[key] or "}" in block[key]:
            raise ProfileError(
                f"REFUSED: {path} `guidance.{key}` contains a brace. The block "
                f"is appended to the prompt TEMPLATE, which is closed with "
                f"str.format, so a brace here either crashes generation or "
                f"eats the text around it.")
    return Guidance(**{key: block[key] for key in GUIDANCE_KEYS})


def _check_against_boundary(prof: TaskProfile) -> None:
    """The claims the prompt makes about the tree, checked against the tree.

    This is why the profile names a boundary instead of standing alone.  The
    prompt's two structural promises are "write here" and "that one thing
    survived"; both are decided by the boundary, and both have been wrong
    before -- v0's boundary enumerated four Context subdirectories while the
    prompt said `Context/**`, so a model that wrote
    `Context/MyContext.php` had its answer classified as production and
    silently discarded.
    """
    if not os.path.isfile(prof.boundary_path):
        raise ProfileError(
            f"REFUSED: {prof.path} names boundary "
            f"{os.path.basename(prof.boundary_path)}, which does not exist "
            f"beside it. The profile's acceptance root is unverifiable "
            f"without it, and an unverifiable acceptance root is how a "
            f"compliant model's answer gets thrown away.")
    boundary = load_boundary(prof.boundary_path)
    if boundary.project != prof.project:
        raise ProfileError(
            f"REFUSED: {prof.path} is project {prof.project!r} but its "
            f"boundary {os.path.basename(prof.boundary_path)} is project "
            f"{boundary.project!r}. Two files describing two projects cannot "
            f"cross-check each other.")

    verdict = (_classify_probe(boundary, prof.acceptance_root)
               if prof.acceptance_mode == "directory" else REMOVABLE)
    if verdict != REMOVABLE:
        raise ProfileError(
            f"REFUSED: {prof.path} tells the system under test to write "
            f"under {prof.acceptance_root!r}, which the boundary classifies "
            f"as {verdict}. The harness only accepts REMOVABLE files, so "
            f"every file a compliant system wrote would be discarded and "
            f"recorded as the system producing nothing.")
    if boundary.classify(prof.example_path) != REMOVABLE:
        raise ProfileError(
            f"REFUSED: {prof.path} shows {prof.example_path!r} as the example "
            f"file path, which the boundary classifies as "
            f"{boundary.classify(prof.example_path)} rather than removable. "
            f"The example is the one path a single-shot system copies.")

    # The carve-out the prompt promises is still there. Named inside
    # `retained_note` in backticks, because that is how the sentence reads to
    # the agent ("`Context/Hook` is what remains") and re-stating it as a
    # separate field would let the sentence and the field disagree.
    #
    # Read BOTH ways round: CoreShop's note names a subtree of the acceptance
    # root (`Context/Hook`) while a behave project's names a sibling of it
    # (`features/environment.py`), and the sentence is right in both cases.
    # One of the readings has to classify RETAINED.
    for token in _BACKTICKED.findall(prof.retained_note):
        if " " in token:
            continue                          # prose, not a path
        candidates = [token]
        if prof.acceptance_mode == "directory" and not token.startswith(prof.acceptance_root):
            candidates.append(prof.acceptance_root.rstrip("/") + "/"
                              + token.lstrip("/"))
        verdicts = [(c, _classify_probe(boundary, c)) for c in candidates]
        if any(v == RETAINED for _c, v in verdicts):
            continue
        seen = ", ".join(f"{c!r} is {v}" for c, v in verdicts)
        raise ProfileError(
            f"REFUSED: {prof.path} promises the agent that `{token}` survived "
            f"removal, but the boundary says {seen}. Either the prompt is "
            f"lying to the agent about what it will find, or -- worse, if it "
            f"is removable -- the prompt is pointing at an answer.")


def _check_internal(prof: TaskProfile) -> None:
    """Consistency between the profile's own fields."""
    if prof.api_scoring not in API_SCORING_MODES:
        raise ProfileError(
            f"REFUSED: {prof.path} `api_scoring` is "
            f"{prof.api_scoring!r}; expected one of "
            f"{sorted(API_SCORING_MODES)}. `method_index` means the API "
            f"triple requires a production method index; `none` means the "
            f"project deliberately does not measure that metric.")
    if prof.acceptance_mode == "item_path":
        if (prof.project, prof.language, prof.framework) != ("coddy-agent", "go", "godog"):
            raise ProfileError("REFUSED: item_path requires coddy-agent/go/godog")
        if prof.acceptance_root is not None:
            raise ProfileError("REFUSED: item_path must omit acceptance_root")
    elif prof.acceptance_mode == "directory":
        if not prof.acceptance_root.endswith("/"):
            raise ProfileError(
                f"REFUSED: {prof.path} `submission.acceptance_root` must end in "
                f"'/' ({prof.acceptance_root!r}); it is a directory prefix and "
                f"the boundary's longest-prefix match treats a missing slash as "
                f"a different tree.")
        if not prof.example_path.startswith(prof.acceptance_root):
            raise ProfileError(
                f"REFUSED: {prof.path} example path {prof.example_path!r} is not "
                f"under the acceptance root {prof.acceptance_root!r}; the prompt "
                f"would show an example the harness rejects.")
    else:
        raise ProfileError("REFUSED: unknown submission.acceptance_mode")
    if not prof.gherkin_suffix.startswith("."):
        raise ProfileError(
            f"REFUSED: {prof.path} `task.gherkin_suffix` must be a file "
            f"suffix ({prof.gherkin_suffix!r}).")
    bad = [s for s in prof.suffixes if not s.startswith(".")]
    if bad:
        raise ProfileError(
            f"REFUSED: {prof.path} `submission.suffixes` entries {bad} are "
            f"not file suffixes.")
    if prof.wiring_channel is not None and (
            prof.wiring_channel.name not in prof.extra_names):
        # The harvest recognises a submission by suffix OR by exact name, and
        # the wiring fragment has neither the language's suffix nor a path
        # under the acceptance root. Left out of `extra_names` it is simply
        # invisible: the agent writes the file the prompt asked for and the
        # harness never sees it.
        raise ProfileError(
            f"REFUSED: {prof.path} offers `{prof.wiring_channel.name}` as its "
            f"wiring channel but does not list it in "
            f"`submission.extra_names`, so the harvest would never collect "
            f"it and the prompt would be promising a route that drops the "
            f"file on the floor.")
    # A brace in a field that lands in the prompt TEMPLATE is a live grenade.
    #
    # `agent_prompt_for` returns a template with `{task}` and `{instructions}`
    # still open and the caller closes it with `str.format`, so a stray `{` in
    # one of these fields is either a `KeyError` in the middle of a sweep or --
    # worse -- a silently eaten word. The fields NOT listed here
    # (`facts`, `platform_blurb`, `example_*`, `placement_hint`) arrive as
    # format ARGUMENTS and are never re-scanned, which is deliberate: a python
    # framework's own documentation is made of `{param}` placeholders and a
    # profile has to be able to quote it.
    for name in _TEMPLATE_FIELDS:
        val = getattr(prof, name)
        if val is None:     # item_path's acceptance root, an absent c2r entry
            continue
        if "{" in val or "}" in val:
            raise ProfileError(
                f"REFUSED: {prof.path} field `{name}` contains a brace "
                f"({val!r}). It is interpolated into the prompt TEMPLATE, "
                f"which is closed with str.format after the clauses are in, "
                f"so a brace here either crashes generation or eats the text "
                f"around it. Put brace-quoted prose in `facts`, which is "
                f"passed as an argument and never re-formatted.")
    if prof.wiring_channel is not None:
        for name in ("name", "when_needed", "format"):
            val = getattr(prof.wiring_channel, name)
            if "{" in val or "}" in val:
                raise ProfileError(
                    f"REFUSED: {prof.path} field `wiring_channel.{name}` "
                    f"contains a brace ({val!r}); it is interpolated into the "
                    f"prompt template. See `facts` for brace-quoted prose.")

    _check_trial_clauses(prof)

    missing = [k for k in PROMPT_KEYS if k not in prof.prompt_digest]
    if missing:
        raise ProfileError(
            f"REFUSED: {prof.path} `prompt_digest` is missing {missing}. All "
            f"four prompts are frozen or none of them is.")


def _clause_fields(text: str, path: str, which: str) -> set:
    """The `{placeholders}` a clause uses, or a refusal naming the bad one.

    `string.Formatter().parse` rather than a regex, because it is the same
    parser `str.format` will use on this string a moment later: a clause that
    parses here cannot fail to parse there, and an unbalanced brace is
    reported as the malformed template it is instead of surviving as text.
    """
    import string
    try:
        fields = {f for _lit, f, _spec, _conv
                  in string.Formatter().parse(text) if f is not None}
    except ValueError as e:
        raise ProfileError(
            f"REFUSED: {path} field `trial.{which}` is not a valid format "
            f"template ({e}). It is closed with str.format before it is put "
            f"into the prompt, so an unbalanced brace here is a crash in the "
            f"middle of a paid sweep.")
    unknown = sorted(f for f in fields if f not in _CLAUSE_PLACEHOLDERS)
    if unknown:
        raise ProfileError(
            f"REFUSED: {path} field `trial.{which}` uses placeholder(s) "
            f"{unknown}, and nothing fills them. The clause is closed with "
            f"str.format, so an unfilled placeholder is a KeyError per item; "
            f"the ones that ARE filled are "
            f"{sorted(_CLAUSE_PLACEHOLDERS)}.")
    return fields


def _check_trial_clauses(prof: TaskProfile) -> None:
    """The two C3 clauses, checked for the one thing each must and must not say.

    The unbounded clause states an affordance with NO count in it, and that is
    not a stylistic preference — it is the whole reason the two forms exist.
    A trial is a terminal tool call and already costs the agent an iteration,
    so `--max-iterations` bounds executions natively; the separate counter is
    gone (`trials.UNBOUNDED`).  What is left of it is the SENTENCE, and a
    sentence that tells an agent its executions are scarce invites it to hoard
    them and keep exploring — which is the exploration-paralysis behaviour the
    benchmark is trying to MEASURE.  A `{k}` surviving in the unbounded form
    would put a number back into the prompt of the arm that is supposed not to
    have one, and it would render as the string "unlimited" rather than as a
    count, so nothing downstream would look obviously wrong.
    """
    bounded = _clause_fields(prof.trial_clause_bounded, prof.path,
                             "clause_bounded")
    unbounded = _clause_fields(prof.trial_clause_unbounded, prof.path,
                               "clause_unbounded")
    if prof.source_visibility is not None:
        if bounded or unbounded:
            raise ProfileError(f"REFUSED: {prof.path}: final-only visibility has no trial affordance")
        return
    if "k" not in bounded:
        raise ProfileError(
            f"REFUSED: {prof.path} `trial.clause_bounded` never mentions "
            f"`{{k}}`, so `--trials 5` would promise the agent an execution "
            f"channel without saying it is capped at five — and the cap would "
            f"then be enforced by a socket the agent was never told about.")
    if "k" in unbounded:
        raise ProfileError(
            f"REFUSED: {prof.path} `trial.clause_unbounded` mentions `{{k}}`. "
            f"The unbounded form exists precisely so that no count reaches the "
            f"prompt; there is no number to put there, and the value that "
            f"would be interpolated is the word 'unlimited'.")
    for which, fields in (("clause_bounded", bounded),
                          ("clause_unbounded", unbounded)):
        if "client" not in fields:
            raise ProfileError(
                f"REFUSED: {prof.path} `trial.{which}` never mentions "
                f"`{{client}}`, so the clause offers the agent an execution "
                f"channel without naming the script that reaches it. The path "
                f"is only known once the socket exists, which is why it is a "
                f"placeholder and not prose.")


def verify_prompt_digests(prof: TaskProfile) -> None:
    """The freeze.

    A prompt is an INPUT.  Every run file on disk was generated with a
    particular one, and comparing rows across a change to it is comparing two
    different experiments under one label.  So the four prompts a profile can
    produce are hashed into the profile itself and re-derived on every load:
    if this refuses, the question is never "update the digest", it is "which
    sweep just became unattributable".

    The import is function-local because `adapters` imports THIS module at
    module scope -- the rendering lives there, next to the selftest that
    reads the assembled artefact, and the dependency only ever runs in this
    direction at call time.
    """
    from .prompt import prompt_digests
    # Every key the file freezes is verified, not only the four it must
    # carry: a fifth key nothing re-derived would be a digest by assertion.
    got = prompt_digests(prof)
    drifted = sorted(k for k in prof.prompt_digest
                     if got[k] != prof.prompt_digest[k])
    if drifted:
        detail = "\n  ".join(
            f"{k}: file says {prof.prompt_digest[k]}, renders as {got[k]}"
            for k in drifted)
        raise ProfileError(
            f"REFUSED: the prompts rendered from {prof.path} are not the "
            f"prompts it was frozen with:\n  {detail}\n"
            f"Every run generated with this profile used the frozen bytes. "
            f"Re-pinning makes those rows incomparable with anything "
            f"generated afterwards while they still carry the same labels; "
            f"if the change is intended, it is a NEW profile.")


def config_stem(project: str) -> str:
    """The file-name form of a project label.

    The corpus calls the second project `python-docx` -- that string is in
    every `item_id`, in `items.jsonl` and in the release, and it is not
    negotiable.  The config files beside it are `boundary_python_docx.yml`
    and `profile_python_docx.yml`, because that is the identifier form the
    rest of the tree uses.

    ONE deterministic mapping, applied in one place, rather than a lookup
    table or a two-candidate search: a search would silently pick whichever
    file happened to exist, which is precisely the profile/boundary drift the
    adjacency rule exists to prevent.  CoreShop's label has no punctuation, so
    for it this function is the identity and `profile_coreshop.yml` resolves
    exactly as it always has.
    """
    return re.sub(r"[^A-Za-z0-9]+", "_", project).strip("_")


#: The projects whose shipped profile file is NOT named for their label.
#: The Java project's label is `algorand-sdk`, but its profile is
#: `config/profile_algorand.yml`, and that path -- with the file's digest --
#: is what published bundles carry and what a release approval is checked
#: against, so the file cannot be renamed to agree.
#:
#: The exception is data, and it belongs here rather than at the call sites
#: because it was re-spelled at each of them (`doctor`, the Java release
#: validator) and MISSING from the one everything else resolves through:
#: `profile_path_for` derived `profile_algorand_sdk.yml`, which does not
#: exist, so an Algorand run or campaign refused with "no task profile at
#: ..." unless the operator named `--profile` by hand.  A fourth project adds
#: a file, not a fourth branch.
_PROFILE_STEM_EXCEPTIONS = {"algorand-sdk": "algorand"}


def profile_stem(project: str) -> str:
    """The file-name stem of a project's PROFILE.

    `config_stem` for every project whose profile is named for its label, and
    the recorded exception otherwise.  Kept apart from `config_stem` because
    that mapping is not only about file names -- `bundle` hands it to
    `plan_workers` as a container prefix -- and an exception made there would
    silently rename live worker containers.

    Only the profile needs this.  A profile NAMES its boundary in its own
    document (`_boundary_path_for`), so nothing downstream has to guess how
    the boundary file beside it is spelled.
    """
    return _PROFILE_STEM_EXCEPTIONS.get(project, config_stem(project))


def profile_path_for(boundary_path: Optional[str], project: str) -> str:
    """Where a project's profile lives when the operator did not say.

    Beside its boundary, named for the project the boundary declares.  Not a
    fixed `config/` path: `--boundary` may point anywhere, and resolving the
    profile somewhere else would reintroduce exactly the drift the adjacency
    prevents.
    """
    here = (os.path.dirname(os.path.abspath(boundary_path)) if boundary_path
            else CONFIG_DIR)
    return os.path.join(here, f"profile_{profile_stem(project)}.yml")


_DEFAULT: Optional[TaskProfile] = None


def default_profile() -> TaskProfile:
    """The CoreShop profile, loaded once.

    Every prompt-rendering entry point takes `profile=None` and falls back to
    this, so nothing outside the run path had to change and the v1 numbers
    keep their prompt.  Cached because loading verifies four prompt digests
    and the single-shot adapter renders per item.
    """
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = load_profile(DEFAULT_PROFILE_PATH)
    return _DEFAULT


def profile_for_item(prof: TaskProfile, item: dict) -> TaskProfile:
    """Resolve Kapua's submission package from the selected suite.

    Its test modules have different Maven compile classpaths. Generated glue
    belongs in the selected test module, whose existing dependencies provide
    that suite's production types. Other projects keep their static profile.
    The saved profile and its canonical prompt digests remain unchanged.
    """
    if prof.project != "kapua":
        return prof
    from ..java.kapua import FEATURE_SUITES
    feature = item.get("feature_file")
    if feature is None:
        provenance = item.get("provenance")
        feature = provenance.get("file_path") if isinstance(provenance, dict) else None
    try:
        suite = FEATURE_SUITES[feature]
    except (KeyError, TypeError):
        raise ProfileError(
            f"REFUSED: Kapua item has no admitted suite binding: {feature!r}") from None
    root = suite.generated_root
    return replace(prof, acceptance_root=root,
                   example_path=root + "GeneratedSteps.java",
                   example_code="package " + suite.generated_package + "; ...",
                   placement_hint=root + "...")


def check_item(prof: TaskProfile, item: dict) -> None:
    """Refuse an item this profile does not describe.

    The release stamps every item with `project`, `language` and `framework`,
    and until now nothing compared them with the prompt.  A CoreShop profile
    over a behave release would tell the model to write PHP into
    `src/CoreShop/Behat/`, harvest `.php`, and score every row as the model
    failing -- an entire sweep of zeros with a plausible-looking run file
    behind it.

    An item that carries no such field is unverifiable rather than wrong (the
    same rule `_check_replay_labels` uses for unstamped cache rows), so it
    passes.
    """
    bad = [(k, item.get(k)) for k in IDENTITY_FIELDS
           if item.get(k) is not None and item.get(k) != getattr(prof, k)]
    if bad:
        detail = ", ".join(f"{k}={v!r} (profile says "
                           f"{getattr(prof, k)!r})" for k, v in bad)
        raise ProfileError(
            f"REFUSED: item {item.get('item_id')!r} is {detail}. The profile "
            f"is what the prompt says; running it over another corpus asks "
            f"the model for the wrong artefact in the wrong language and "
            f"scores the answer against it.")

    if prof.acceptance_mode == "item_path":
        from ..go.context import ContextRefused, answer_paths
        from ..core.boundary import load_boundary
        try:
            answer_paths(item, boundary=load_boundary(prof.boundary_path),
                             project=prof.project)
        except ContextRefused as exc:
            raise ProfileError(str(exc)) from exc


# ------------------------------------------------------------------ selftest
def selftest() -> int:
    """The refusals, driven against real files rather than described.

    Every check here is a load that MUST fail: the value of a cross-check is
    entirely in whether it fires, and a validator nobody has watched refuse
    is a validator that may be reading the wrong field.
    """
    import shutil
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    prof = load_profile(DEFAULT_PROFILE_PATH)
    check("the shipped CoreShop profile loads and its prompts are frozen",
          prof.project == "coreshop" and prof.language == "php"
          and prof.framework == "behat"
          and prof.api_scoring == API_SCORING_METHOD_INDEX
          and set(prof.prompt_digest) == set(PROMPT_KEYS))
    kapua_profile = replace(prof, project="kapua")
    account_item = {"feature_file": "service/account/test/src/test/resources/features/AccountService.feature"}
    translator_item = {"feature_file": "translator/test/src/test/resources/features/translator.feature"}
    # Pick a real translator feature out of the pinned source map; its
    # generated package must compile in translator/test, never qa/common.
    from ..java.kapua import FEATURE_SUITES
    translator_item["feature_file"] = next(
        path for path in FEATURE_SUITES if path.startswith("translator/test/"))
    account_profile = profile_for_item(kapua_profile, account_item)
    translator_profile = profile_for_item(kapua_profile, translator_item)
    check("Kapua submission roots follow each selected test module's compile classpath",
          account_profile.acceptance_root.startswith("service/account/test/src/test/java/")
          and translator_profile.acceptance_root.startswith("translator/test/src/test/java/")
          and account_profile.acceptance_root.endswith("/r2t/generated/")
          and account_profile.example_path.startswith(account_profile.acceptance_root)
          and "org.eclipse.kapua.service.account.test.r2t.generated" in account_profile.example_code)
    check("per-item placement preserves the saved profile and every other project's identity",
          profile_for_item(prof, account_item) is prof
          and kapua_profile.acceptance_root == prof.acceptance_root
          and account_profile.prompt_digest == kapua_profile.prompt_digest)
    try:
        profile_for_item(kapua_profile, {"feature_file": "unbound.feature"})
        rejected_unknown = False
    except ProfileError:
        rejected_unknown = True
    check("an unknown Kapua suite cannot silently receive another module's placement",
          rejected_unknown)
    from .release import task_view
    released_routes = []
    for feature, suite in FEATURE_SUITES.items():
        released = task_view({"item_id": "kapua/" + feature + ":1",
                              "project": "kapua", "provenance": {"file_path": feature}})
        resolved = profile_for_item(kapua_profile, released)
        released_routes.append(
            "feature_file" not in released
            and resolved == profile_for_item(kapua_profile, {"feature_file": feature})
            and resolved.acceptance_root == suite.generated_root)
    check("actual released task views select every Kapua suite through provenance",
          len(released_routes) == len(FEATURE_SUITES) and all(released_routes))
    for invalid in ({}, {"provenance": None}, {"provenance": {"file_path": "unbound.feature"}}):
        try:
            profile_for_item(kapua_profile, task_view(invalid))
            refused = False
        except ProfileError:
            refused = True
        check("released tasks without an admitted feature still refuse", refused)
    check("it names its boundary as a sibling",
          os.path.dirname(prof.boundary_path) == os.path.dirname(prof.path)
          and os.path.isfile(prof.boundary_path), prof.boundary_path)
    check("the wiring channel is the name the harness routes on",
          prof.wiring_channel is not None
          and prof.wiring_channel.name in prof.extra_names,
          str(prof.extra_names))
    # The one place the profile and the PHP-side harness must agree by name:
    # `harness.install_solution` routes a file called this into the DI
    # fragment instead of onto disk, so a profile that renamed the channel
    # would offer the agent a file the harness would try to install as code.
    from ..bench.harness import SERVICES_FRAGMENT_NAME
    check("the CoreShop wiring channel is the harness's fragment name",
          prof.wiring_channel.name == SERVICES_FRAGMENT_NAME,
          f"{prof.wiring_channel.name} vs {SERVICES_FRAGMENT_NAME}")
    check("the wiring fact is rendered in place, not appended",
          prof.facts.index(WIRING_FACT_SLOT) == 3
          and prof.bullets()[3] == prof.wiring_channel.auto_registration,
          str(prof.facts.index(WIRING_FACT_SLOT)))
    # The parameterisation has to be a NO-OP on the runs already on disk, and
    # the harvest filter is the half of that which no prompt digest can see.
    # That the profile's filter still equals `agents.harvest.harvest`'s own
    # defaults is checked in `harvest`'s self-test, which owns the function
    # the claim is about; this file's self-test does not import an agent
    # module.
    check("the Gherkin suffix is read even though it is not the artefact",
          ".feature" in prof.harvest_suffixes()
          and ".feature" not in prof.suffixes)

    behave = os.path.join(CONFIG_DIR, "profile_behave_example.yml")
    check("a second, non-Symfony profile is shipped and loads",
          os.path.isfile(behave))
    if os.path.isfile(behave):
        bp = load_profile(behave)
        check("the behave profile carries no wiring channel at all",
              bp.wiring_channel is None and bp.framework == "behave"
              and bp.language == "python")
        check("and its harvest reads python, not PHP",
              bp.harvest_suffixes() == (".py", ".feature")
              and bp.extra_names == (), str(bp.harvest_suffixes()))
        check("dropping the channel drops the fact with it",
              WIRING_FACT_SLOT not in bp.bullets()
              and len(bp.bullets()) == len(bp.facts) - 1
              if WIRING_FACT_SLOT in bp.facts
              else WIRING_FACT_SLOT not in bp.bullets())
        check("a profile with no `runtime` block still needs a database",
              bp.needs_database is True)

    # -- the THIRD profile: python-docx, the first behave project with a real
    # repository behind it.  Everything below is a claim that would be
    # expensive to discover during a paid sweep.
    docx_path = os.path.join(CONFIG_DIR, "profile_python_docx.yml")
    check("the python-docx profile is shipped", os.path.isfile(docx_path))
    if os.path.isfile(docx_path):
        # Loading it IS the check: `load_profile` classifies the acceptance
        # root and every backticked token of `retained_note` against the
        # boundary, and re-derives all four prompt digests. It refuses if the
        # test_files carve-out is dropped (the note would then promise the
        # agent a directory that is removable, i.e. would point at an answer),
        # and it refuses if a word of the prose moves.
        dp = load_profile(docx_path)
        check("it is python+behave with no wiring channel and its prompts are "
              "frozen",
              dp.project == "python-docx" and dp.language == "python"
              and dp.framework == "behave" and dp.wiring_channel is None
              and dp.api_scoring == API_SCORING_METHOD_INDEX
              and set(dp.prompt_digest) == set(PROMPT_KEYS))
        check("it is the profile that declares the stack has NO database",
              dp.needs_database is False and prof.needs_database is True)
        # The promise the prompt makes about the fixtures, read back as the
        # boundary reads it. `load_profile` already refused if this were
        # false; asserting it here names WHICH claim the refusal protects, so
        # a future edit that weakened the check is visible as a passing test
        # that stopped being about anything.
        docx_boundary = load_boundary(dp.boundary_path)
        check("the prompt's fixture promise is the boundary's carve-out",
              "features/steps/test_files/" in dp.retained_note
              and docx_boundary.classify(
                  "features/steps/test_files/doc-default.docx") == RETAINED
              and docx_boundary.classify(
                  "features/steps/helpers.py") == REMOVABLE)
        check("and its harvest reads python, not PHP",
              dp.harvest_suffixes() == (".py", ".feature")
              and dp.extra_names == (), str(dp.harvest_suffixes()))
        check("no CoreShop profile digest is reachable from it",
              not (set(dp.prompt_digest.values())
                   & set(prof.prompt_digest.values())))
        # The BOUNDED c3 wording, frozen beside the unbounded one the arm
        # runs, so a `--trials k` docx run is an attributable configuration
        # rather than an unpinned variant. Pinned in the TEST as well as in
        # the file, because re-pinning the file must not also re-pin the check.
        from ..bench.adapters import CANONICAL_TRIALS
        from .prompt import prompt_digests as _pd
        _DOCX_C3_BOUNDED = (
            "c850167f2719ef1910134c8f00f395e3b5344c45775c4cea3590b4cf100cac71")
        bounded = _pd(dp, CANONICAL_TRIALS)
        check("the docx BOUNDED c3 rendering is frozen too",
              bounded["c3"] == _DOCX_C3_BOUNDED
              and bounded["c3"] != dp.prompt_digest["c3"],
              f"{bounded['c3']} != {_DOCX_C3_BOUNDED}")
        # The label the corpus uses carries a hyphen; the files beside it use
        # an underscore. One deterministic mapping, checked against the file
        # that is actually on disk -- a `run` with no `--profile` resolves
        # through here, and a mapping that missed would refuse every docx run.
        check("a hyphenated project label resolves to the shipped config file",
              config_stem("python-docx") == "python_docx"
              and config_stem("coreshop") == "coreshop"
              and os.path.abspath(profile_path_for(None, "python-docx"))
              == os.path.abspath(docx_path),
              profile_path_for(None, "python-docx"))

    # -- the FOURTH profile: epubcheck, java+cucumber.  It is frozen BEFORE
    # its first sweep rather than after one, so every check here is about the
    # file being loadable and self-consistent -- which is the whole of what
    # can be true of a profile whose stack (`stacks.for_framework("cucumber")`)
    # does not exist yet.
    epub_path = os.path.join(CONFIG_DIR, "profile_epubcheck.yml")
    check("the epubcheck profile is shipped", os.path.isfile(epub_path))
    if os.path.isfile(epub_path):
        # Loading IS the check, exactly as for docx: the acceptance root and
        # all five backticked tokens of `retained_note` are classified against
        # `boundary_epubcheck.yml`, and all four prompt digests are re-derived.
        from ..bench.adapters import CANONICAL_TRIALS as _EPUB_TRIALS
        from .prompt import prompt_digests as _epub_pd
        ep = load_profile(epub_path)
        check("it is java+cucumber with no wiring channel and its prompts are "
              "frozen",
              ep.project == "epubcheck" and ep.language == "java"
              and ep.framework == "cucumber" and ep.wiring_channel is None
              and set(ep.prompt_digest) == set(PROMPT_KEYS))
        check("it is the second profile to declare the stack has NO database",
              ep.needs_database is False)
        check("and its harvest reads java, not python or PHP",
              ep.harvest_suffixes() == (".java", ".feature")
              and ep.extra_names == (), str(ep.harvest_suffixes()))
        # Every shipped profile that has a real repository behind it, so a
        # copy-pasted digest block cannot survive here: three projects, four
        # prompts each, twelve distinct values.
        others = set()
        for sibling in ("profile_coreshop.yml", "profile_python_docx.yml"):
            others |= set(load_profile(
                os.path.join(CONFIG_DIR, sibling)).prompt_digest.values())
        check("no other project's profile digest is reachable from it",
              not (set(ep.prompt_digest.values()) & others),
              str(sorted(set(ep.prompt_digest.values()) & others)))
        # The two owner rulings the prompt DEPENDS on, read back as the
        # boundary reads them. `load_profile` already refused if the first
        # were false; asserting both here names WHICH claim the refusal
        # protects, and pins the one it cannot see.
        epub_boundary = load_boundary(ep.boundary_path)
        java = "src/test/java/org/w3c/epubcheck"
        check("R1.5's retained ParameterTypes.java is what the prompt promises "
              "the agent it will find",
              "`ParameterTypes.java`" in ep.retained_note
              and epub_boundary.classify(
                  f"{java}/test/ParameterTypes.java") == RETAINED)
        check("...and ruling 1 does NOT extend that to SharedParameterTypes: "
              "the prompt neither promises it nor may promise it",
              "SharedParameterTypes" not in ep.retained_note
              and epub_boundary.classify(
                  f"{java}/SharedParameterTypes.java") == REMOVABLE)
        # The BOUNDED c3 wording, frozen beside the unbounded one the arm will
        # run, so a `--trials k` epubcheck run is an attributable configuration
        # from its first day rather than an unpinned variant.
        _EPUB_C3_BOUNDED = (
            "dfe8d2b0100b50eda418f05900564439fe581c8a04684ed533eed7da2855c30c")
        epub_bounded = _epub_pd(ep, _EPUB_TRIALS)
        check("the epubcheck BOUNDED c3 rendering is frozen too",
              epub_bounded["c3"] == _EPUB_C3_BOUNDED
              and epub_bounded["c3"] != ep.prompt_digest["c3"],
              f"{epub_bounded['c3']} != {_EPUB_C3_BOUNDED}")
        check("an unpunctuated project label is its own config-file stem",
              config_stem("epubcheck") == "epubcheck"
              and os.path.abspath(profile_path_for(None, "epubcheck"))
              == os.path.abspath(epub_path),
              profile_path_for(None, "epubcheck"))
        # The profile loads, and the stack its `framework:` names answers
        # under ITS OWN name.  Both halves matter, and which half is which
        # changed at J5: before the cucumber stack landed, the second half
        # was that `for_framework` refused with the milestone in the
        # message; now that it exists, the thing that must stay true is the
        # one that was always the point — this profile is never routed to
        # another framework's harness.  Written both ways so that neither
        # J5 nor a later milestone has to edit the claim to keep it true.
        from ..stacks import for_framework
        try:
            stack = for_framework(ep.framework)
            check("this profile routes to the cucumber stack, and never to "
                  "another framework's harness",
                  getattr(stack, "FRAMEWORK", None) == ep.framework
                  and ep.framework == "cucumber",
                  str(getattr(stack, "FRAMEWORK", None)))
        except NotImplementedError as e:
            check("the not-yet-landed cucumber stack is refused, so this "
                  "profile cannot be run by accident",
                  "J5 (S4 harness)" in str(e) and "NOT done" in str(e),
                  str(e)[:120])

    # -- the ONE project whose profile file is not named for its label.
    # `algorand-sdk`'s profile is `profile_algorand.yml`, and every site that
    # needed to know that used to say so itself.  Asserted against the file
    # actually on disk in both directions: that the exception resolves it, and
    # that it applies to nothing else -- an exception that leaked would send a
    # CoreShop or python-docx run to the wrong prompt, which is the failure
    # mode a per-project branch has and a single mapping is supposed to end.
    algorand_path = os.path.join(CONFIG_DIR, "profile_algorand.yml")
    check("the label whose profile file is spelled differently resolves to "
          "the shipped file, and the other projects are untouched",
          profile_stem("algorand-sdk") == "algorand"
          and os.path.abspath(profile_path_for(None, "algorand-sdk"))
          == os.path.abspath(algorand_path)
          and os.path.isfile(algorand_path)
          and load_profile(algorand_path).project == "algorand-sdk"
          and all(profile_stem(name) == config_stem(name)
                  for name in ("coreshop", "python-docx", "epubcheck")),
          profile_path_for(None, "algorand-sdk"))

    from .prompt import prompt_digests as analysis_prompt_digests
    for project, stem in (("algorand-sdk", "algorand"), ("kapua", "kapua")):
        historical_path = os.path.join(CONFIG_DIR, f"profile_{stem}.yml")
        analysis_path = os.path.join(CONFIG_DIR,
                                     f"profile_{stem}_api_analysis.yml")
        ap = load_profile(analysis_path)
        historical = load_profile(historical_path)
        with open(historical_path, encoding="utf-8") as fh:
            historical_data = yaml.safe_load(fh)
        with open(analysis_path, encoding="utf-8") as fh:
            analysis_data = yaml.safe_load(fh)
        check(f"the explicit {project} analysis profile changes only API "
              "scoring and preserves every rendered prompt and the default",
              analysis_data == dict(historical_data,
                                    api_scoring=API_SCORING_METHOD_INDEX)
              and ap.api_scoring == API_SCORING_METHOD_INDEX
              and historical.api_scoring == API_SCORING_NONE
              and analysis_prompt_digests(ap)
                  == analysis_prompt_digests(historical)
              and analysis_prompt_digests(ap, CANONICAL_TRIALS)
                  == analysis_prompt_digests(historical, CANONICAL_TRIALS)
              and profile_path_for(None, project) == historical_path)
        if project == "kapua":
            check("Kapua API analysis preserves every admitted suite's "
                  "placement and rendered prompts",
                  all(replace(profile_for_item(ap, {"feature_file": feature}),
                              path=historical.path, digest=historical.digest,
                              raw=historical.raw,
                              api_scoring=API_SCORING_NONE)
                      == profile_for_item(historical, {"feature_file": feature})
                      and analysis_prompt_digests(
                          profile_for_item(ap, {"feature_file": feature}),
                          CANONICAL_TRIALS)
                      == analysis_prompt_digests(
                          profile_for_item(historical, {"feature_file": feature}),
                          CANONICAL_TRIALS)
                      for feature in FEATURE_SUITES))

    # -- the refusals.
    def mutate(fn, *, profile_name="profile_coreshop.yml") -> str:
        """A copy of the shipped pair with one thing changed."""
        d = tempfile.mkdtemp(prefix="r2t-profile-")
        for name in ("profile_coreshop.yml", "boundary_coreshop.yml"):
            shutil.copyfile(os.path.join(CONFIG_DIR, name),
                            os.path.join(d, name))
        p = os.path.join(d, profile_name)
        with open(p, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        fn(doc)
        with open(p, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True)
        return p

    def refuses(name, path, *needles):
        try:
            load_profile(path)
        except SystemExit as e:
            miss = [n for n in needles if n not in str(e)]
            check(name, not miss, f"message lacks {miss}: {str(e)[:300]}")
        except Exception as e:                             # noqa: BLE001
            check(name, False, f"raised {type(e).__name__}: {e}")
        else:
            check(name, False, "loaded without complaint")

    # A round-trip through safe_dump must itself still load, or every refusal
    # below would be testing the dumper rather than the validator.
    trip = mutate(lambda d: None)
    try:
        load_profile(trip)
        check("a re-serialised copy of the shipped profile still loads", True)
    except SystemExit as e:
        check("a re-serialised copy of the shipped profile still loads", False,
              str(e)[:300])

    def set_root(root):
        def fn(d):
            d["submission"]["acceptance_root"] = root
            d["submission"]["example_path"] = root + "X.php"
        return fn

    refuses("an acceptance root the boundary calls production is refused",
            mutate(set_root("src/CoreShop/Component/")),
            "REFUSED", "production", "discarded")
    refuses("an acceptance root the boundary RETAINS is refused too",
            mutate(set_root("src/CoreShop/Behat/Context/Hook/")),
            "REFUSED", "retained")
    refuses("a retained carve-out that is actually removable is refused",
            mutate(lambda d: d["submission"].__setitem__(
                "retained_note", "`Context/Domain` is what remains")),
            "REFUSED", "promises", "removable")
    refuses("a wiring channel missing from extra_names is refused",
            mutate(lambda d: d["submission"].__setitem__("extra_names", [])),
            "REFUSED", "extra_names", "floor")
    refuses("a wiring channel with no slot among the facts is refused",
            mutate(lambda d: d.__setitem__(
                "facts", [f for f in d["facts"] if f != WIRING_FACT_SLOT])),
            "REFUSED", "slot")
    refuses("a moved prompt is refused rather than silently re-pinned",
            mutate(lambda d: d.__setitem__(
                "platform_blurb", "some other platform")),
            "REFUSED", "frozen with", "incomparable")
    refuses("a missing digest is refused",
            mutate(lambda d: d["prompt_digest"].pop("c3")),
            "REFUSED", "prompt_digest", "c3")
    refuses("a boundary named by path rather than as a sibling is refused",
            mutate(lambda d: d.__setitem__(
                "boundary", "../config/boundary_coreshop.yml")),
            "REFUSED", "bare filename")
    refuses("a profile whose project differs from its boundary's is refused",
            mutate(lambda d: d.__setitem__("project", "notcoreshop")),
            "REFUSED", "cross-check")
    refuses("a missing field is refused, not rendered as a hole",
            mutate(lambda d: d["task"].pop("artefact_noun")),
            "REFUSED", "artefact_noun")
    refuses("an unknown api-scoring mode is refused rather than guessed",
            mutate(lambda d: d.__setitem__("api_scoring", "python_index")),
            "REFUSED", "api_scoring", "method_index", "none")
    refuses("an acceptance root without its trailing slash is refused",
            mutate(lambda d: d["submission"].__setitem__(
                "acceptance_root", "src/CoreShop/Behat")),
            "REFUSED", "longest-prefix")

    # -- the `runtime` block.  Every one of these would otherwise leave
    # `needs_database` at its default True, which is the one outcome a reader
    # of the file cannot see: the profile says the stack has no database and
    # the provisioner goes on creating one, loading an empty dump into it and
    # refusing the worker for holding fewer than 100 tables.
    refuses("a misspelt runtime key is refused, not ignored",
            mutate(lambda d: d.__setitem__(
                "runtime", {"need_database": False})),
            "REFUSED", "need_database", "nothing reads")
    refuses("a runtime block that is not a mapping is refused",
            mutate(lambda d: d.__setitem__("runtime", ["needs_database"])),
            "REFUSED", "runtime", "mapping")
    refuses("a string where a boolean belongs is refused",
            mutate(lambda d: d.__setitem__(
                "runtime", {"needs_database": "false"})),
            "REFUSED", "needs_database", "bool")
    # ... and the block that IS well formed loads, or the three refusals above
    # would be indistinguishable from a validator that refuses everything.
    ok_runtime = mutate(lambda d: d.__setitem__(
        "runtime", {"needs_database": True}))
    try:
        check("an explicit `needs_database: true` loads and means the default",
              load_profile(ok_runtime).needs_database is True)
    except SystemExit as e:
        check("an explicit `needs_database: true` loads and means the default",
              False, str(e)[:200])

    # -- the two C3 clause forms.  The unbounded one exists so that no COUNT
    # reaches the prompt: an execution costs the agent an iteration already,
    # and telling it the executions are scarce is telling it to hoard them,
    # which is the behaviour the benchmark measures rather than one it may
    # induce.  A `{k}` left in that form would render the literal word
    # "unlimited" into the sentence and nothing downstream would look wrong.
    check("the shipped profile carries both clause forms",
          "{k}" in prof.trial_clause_bounded
          and "{k}" not in prof.trial_clause_unbounded
          and "{client}" in prof.trial_clause_unbounded,
          repr(prof.trial_clause_unbounded))
    refuses("a `{k}` in the UNBOUNDED clause is refused",
            mutate(lambda d: d["trial"].__setitem__(
                "clause_unbounded", d["trial"]["clause_unbounded"]
                + " You may do this {k} times.")),
            "REFUSED", "clause_unbounded", "no count reaches the prompt")
    refuses("a bounded clause that never states the cap is refused",
            mutate(lambda d: d["trial"].__setitem__(
                "clause_bounded", d["trial"]["clause_unbounded"])),
            "REFUSED", "clause_bounded", "{k}")
    refuses("a clause with a placeholder nothing fills is refused",
            mutate(lambda d: d["trial"].__setitem__(
                "clause_unbounded",
                d["trial"]["clause_unbounded"] + " Ask {supervisor}.")),
            "REFUSED", "supervisor", "KeyError")
    refuses("a clause with an unbalanced brace is refused",
            mutate(lambda d: d["trial"].__setitem__(
                "clause_unbounded", d["trial"]["clause_unbounded"] + " {")),
            "REFUSED", "not a valid format template")
    refuses("a clause that names no client is refused",
            mutate(lambda d: d["trial"].__setitem__(
                "clause_unbounded", "You can run the scenario somehow.")),
            "REFUSED", "{client}")
    refuses("a missing clause form is refused, not defaulted",
            mutate(lambda d: d["trial"].pop("clause_unbounded")),
            "REFUSED", "clause_unbounded")

    # -- the optional `guidance:` block.  Each refusal is a block that would
    # otherwise reach the prompt malformed: a brace crashes or eats text in
    # `str.format`, and a missing or blank text renders a heading over nothing.
    good_guidance = {"id": "selftest_probe", "heading": "Before you finish",
                     "text": "Review the step definitions you wrote.\n"}
    for label, block, needles in (
            ("a guidance block that is not a mapping", "Review your work.",
             ("`guidance`", "mapping")),
            ("a guidance block missing a key",
             {k: v for k, v in good_guidance.items() if k != "id"},
             ("`guidance`", "exactly")),
            ("a guidance block with a key nothing reads",
             dict(good_guidance, scope="all_hidden"), ("`guidance`", "exactly")),
            ("a blank guidance text", dict(good_guidance, text="  \n"),
             ("guidance.text", "non-blank")),
            ("a guidance id that is not a string", dict(good_guidance, id=1),
             ("guidance.id", "non-blank")),
            ("a brace in the guidance text",
             dict(good_guidance, text="Check {value} exactly."),
             ("guidance.text", "brace")),
            ("a brace in the guidance heading",
             dict(good_guidance, heading="Before {you} finish"),
             ("guidance.heading", "brace"))):
        refuses(f"{label} is refused",
                mutate(lambda d, b=block: d.__setitem__("guidance", b)),
                "REFUSED", *needles)
    # A well-formed block moves the three agent prompts, so adding one to a
    # shipped profile is refused by the freeze: a block is a NEW profile.
    refuses("a guidance block added to a frozen profile is a moved prompt",
            mutate(lambda d: d.__setitem__("guidance", dict(good_guidance))),
            "REFUSED", "frozen with", "c2")

    # Minted the way a new profile is (loaded unverified, its four renderings
    # frozen, reloaded verified), a copy with a block loads, and it is its
    # parent plus the block: raw YAML equal but for `guidance` and
    # `prompt_digest`, the single-shot digest equal and every agent prompt the
    # parent's followed by `guidance_block`.  The same rule is then applied to
    # every shipped profile that carries a block.
    from .prompt import (canonical_prompt as _gcp, guidance_block as _ggb,
                         prompt_digests as _gpd)
    minted = mutate(lambda d: d.__setitem__("guidance", dict(good_guidance)))
    with open(minted, encoding="utf-8") as fh:
        minted_doc = yaml.safe_load(fh)
    minted_doc["prompt_digest"] = _gpd(load_profile(minted,
                                                    verify_digests=False))
    with open(minted, "w", encoding="utf-8") as fh:
        yaml.safe_dump(minted_doc, fh, sort_keys=False, allow_unicode=True)
    try:
        mp = load_profile(minted)
    except SystemExit as e:
        mp = None
        check("a copy with a guidance block loads once its digests are minted",
              False, str(e)[:300])

    def sans(doc, *keys):
        return {k: v for k, v in doc.items() if k not in keys}

    def parents_of(variant, pool):
        want = sans(variant.raw, "guidance", "prompt_digest")
        return [p for p in pool if p.guidance is None
                and sans(p.raw, "prompt_digest") == want]

    def parent_plus_block(variant, parent):
        return (variant.prompt_digest["single_shot"]
                == parent.prompt_digest["single_shot"]
                and all(_gcp(variant, k) == _gcp(parent, k) + _ggb(variant)
                        for k in ("c1.5", "c2", "c3")))

    import glob as _gg
    pool = [load_profile(p) for p in sorted(_gg.glob(
        os.path.join(CONFIG_DIR, "profile_*.yml")))]
    if mp is not None:
        check("a copy with a guidance block loads once its digests are minted, "
              "and it is the shipped profile plus the block",
              mp.guidance == Guidance(**good_guidance)
              and [p.path for p in parents_of(mp, pool)] == [prof.path]
              and parent_plus_block(mp, prof)
              and all(mp.prompt_digest[k] != prof.prompt_digest[k]
                      for k in ("c1.5", "c2", "c3")))
        check("...and a copy that also moved another word has no parent",
              not parents_of(replace(mp, raw=dict(
                  mp.raw, platform_blurb="another platform")), pool))
    variants = [p for p in pool if p.guidance is not None]
    orphans = [os.path.basename(v.path) for v in variants
               if not any(parent_plus_block(v, p) for p in parents_of(v, pool))]
    check(f"every shipped profile with a guidance block is a shipped profile "
          f"plus that block and nothing else ({len(variants)} at this commit)",
          not orphans, str(orphans))

    # -- and the item cross-check.
    good = {"item_id": "coreshop/f.feature:1", "project": "coreshop",
            "language": "php", "framework": "behat"}
    try:
        check_item(prof, good)
        check_item(prof, {"item_id": "x"})       # unstamped: unverifiable
        check("a matching item, and an unstamped one, are both accepted", True)
    except SystemExit as e:
        check("a matching item, and an unstamped one, are both accepted",
              False, str(e)[:200])
    for wrong in ({"language": "python"}, {"framework": "cucumber"},
                  {"project": "sylius"}):
        try:
            check_item(prof, dict(good, **wrong))
            fired = ""
        except SystemExit as e:
            fired = str(e)
        check(f"an item whose {list(wrong)[0]} disagrees with the profile is "
              f"refused", "REFUSED" in fired and list(wrong)[0] in fired,
              fired[:200])

    # -- the disclosing CoreShop twin (TARGET_INTERFACES_SPEC).  One variable
    # differs from `profile_coreshop.yml`: the `disclosure:` block.  Its
    # `single_shot` digest must therefore EQUAL the base's (the system message
    # is facts plus contract, untouched), while the three agent renderings
    # must DIFFER (the canonical task carries a list and the block renders).
    # Both directions are asserted: a twin whose agent digests still matched
    # would be a disclosure the freeze cannot see.
    ti_path = os.path.join(CONFIG_DIR, "profile_coreshop_target_interfaces.yml")
    check("the target-interfaces CoreShop profile is shipped", os.path.isfile(ti_path))
    if os.path.isfile(ti_path):
        ti = load_profile(ti_path)
        check("it discloses target interfaces and the base profile does not",
              ti.disclose_target_interfaces is True
              and prof.disclose_target_interfaces is False)
        check("its single_shot digest is the base profile's: the system "
              "message did not move",
              ti.prompt_digest["single_shot"] == prof.prompt_digest["single_shot"])
        check("its three agent digests all differ from the base profile's: "
              "the disclosure is frozen, not invisible",
              all(ti.prompt_digest[k] != prof.prompt_digest[k]
                  for k in ("c1.5", "c2", "c3")))
        check("every other word is the base profile's",
              ti.facts == prof.facts and ti.platform_blurb == prof.platform_blurb
              and ti.acceptance_root == prof.acceptance_root
              and ti.placement_hint == prof.placement_hint
              and ti.trial_clause_unbounded == prof.trial_clause_unbounded
              and ti.wiring_channel == prof.wiring_channel)
        # A disclosure the profile grammar does not define, or a non-bool
        # value, is refused rather than read as "true-ish".
        for label, bad in (("an unknown disclosure", {"disclosure": {"x": True}}),
                           ("a non-bool disclosure",
                            {"disclosure": {"target_interfaces": "yes"}}),
                           ("a non-mapping disclosure", {"disclosure": True})):
            doc = dict(ti.raw); doc.update(bad)
            try:
                _disclosure_of(doc, ti_path)
                check(f"{label} is refused", False)
            except ProfileError as e:
                check(f"{label} is refused", "REFUSED" in str(e))
        check("an absent disclosure block means no disclosure",
              _disclosure_of({}, ti_path)
              == {"target_interfaces": False, "checked_interfaces": False})

    # -- the v2 disclosure (TARGET_INTERFACES_V2_SPEC section 5a).  A SECOND
    # key beside the first, not a replacement: the shipped trio discloses
    # `checked_interfaces` and nothing else, which is what keeps every v1
    # profile's four digests where they were.  A `visibility:` block is
    # accepted under EITHER disclosure, and under neither it still refuses.
    ci_path = os.path.join(CONFIG_DIR,
                           "profile_coreshop_checked_interfaces_full.yml")
    check("the checked-interfaces CoreShop profile is shipped",
          os.path.isfile(ci_path))
    if os.path.isfile(ci_path):
        ci = load_profile(ci_path)
        v1 = load_profile(os.path.join(
            CONFIG_DIR, "profile_coreshop_visibility_full_v2.yml"))
        check("it discloses checked interfaces and NOT the v1 lists",
              ci.disclose_checked_interfaces is True
              and ci.disclose_target_interfaces is False
              and v1.disclose_checked_interfaces is False)
        check("a `visibility:` block is accepted under the v2 disclosure "
              "alone",
              ci.source_visibility == "full")
        check("its single_shot digest is the v1 twin's -- the system message "
              "carries no disclosure",
              ci.prompt_digest["single_shot"] == v1.prompt_digest["single_shot"])
        check("its three agent digests all differ from the v1 twin's: two "
              "disclosures are two prompts, and both are frozen",
              all(ci.prompt_digest[k] != v1.prompt_digest[k]
                  for k in ("c1.5", "c2", "c3")))
        check("every other word is the v1 twin's",
              ci.facts == v1.facts and ci.platform_blurb == v1.platform_blurb
              and ci.acceptance_root == v1.acceptance_root
              and ci.placement_hint == v1.placement_hint
              and ci.trial_clause_unbounded == v1.trial_clause_unbounded
              and ci.wiring_channel == v1.wiring_channel)
        check("a profile may disclose BOTH, which is a third prompt",
              _disclosure_of({"disclosure": {"target_interfaces": True,
                                             "checked_interfaces": True}},
                             ci_path)
              == {"target_interfaces": True, "checked_interfaces": True})
        for label, bad in (
                ("an unknown THIRD disclosure",
                 {"disclosure": {"checked_interfaces": True, "x": True}}),
                ("a non-bool v2 disclosure",
                 {"disclosure": {"checked_interfaces": "yes"}})):
            try:
                _disclosure_of(bad, ci_path)
                check(f"{label} is refused", False)
            except ProfileError as e:
                check(f"{label} is refused", "REFUSED" in str(e))
        # A visibility block with NO disclosure at all is still a refusal:
        # widening the rule to "either" must not have widened it to "any".
        try:
            _visibility_of({"visibility": {"scope": "full",
                                           "feedback": "final_only"}}, ci_path)
            check("a visibility block with neither disclosure is refused", False)
        except ProfileError as e:
            check("a visibility block with neither disclosure is refused",
                  "REFUSED" in str(e))
        # The whole shipped v2 family, loaded for real: each one is a
        # visibility profile, each discloses only the v2 key, and each
        # project's three scopes differ from one another.  The `_exec.yml`
        # variants are the c2r copies of the target_hidden members, not a
        # fourth scope; `data.prompt`'s self-test holds them to their parents.
        import glob as _cig
        family = sorted(path for path in _cig.glob(os.path.join(
            CONFIG_DIR, "profile_*_checked_interfaces_*.yml"))
            if not path.endswith("_exec.yml"))
        check("the v2 family is the eight projects' three scopes", len(family) == 24,
              str(len(family)))
        scopes = {}
        for path in family:
            prof2 = load_profile(path)
            scopes.setdefault(prof2.project, set()).add(prof2.source_visibility)
            check(f"{os.path.basename(path)} discloses only checked interfaces "
                  f"and names its scope",
                  prof2.disclose_checked_interfaces is True
                  and prof2.disclose_target_interfaces is False
                  and prof2.source_visibility is not None
                  and path.endswith(f"_{prof2.source_visibility}.yml"))
        check("every project carries all three scopes",
              all(v == {"full", "target_hidden", "all_hidden"}
                  for v in scopes.values()) and len(scopes) == 8,
              str({k: sorted(v) for k, v in scopes.items()}))
        presta = [load_profile(p) for p in family
                  if os.path.basename(p).startswith("profile_prestashop_")]
        check("PrestaShop's checked profiles keep the approved common projection "
              "and direct-FQCN final-only contract",
              len(presta) == 3
              and len({p.readable_paths for p in presta}) == 1
              and all(len(p.readable_paths) == 49
                      and "tests/Resources" not in p.readable_paths
                      and "tests/Resources/modules" not in p.readable_paths
                      and "tests/Resources/modules/ps_apiresources" not in p.readable_paths
                      and p.api_scoring == API_SCORING_METHOD_INDEX
                      and p.wiring_channel is None
                      and p.raw["visibility"]["feedback"] == "final_only" for p in presta))
        check("python-docx's v2 profiles score the API row (spec 6.2), which "
              "its v1 visibility profiles do not",
              all(load_profile(p).api_scoring == API_SCORING_METHOD_INDEX
                  for p in family if "python_docx" in p)
              and load_profile(os.path.join(
                  CONFIG_DIR, "profile_python_docx_visibility_full.yml"
              )).api_scoring == API_SCORING_NONE)

    # -- the freeze covers every key a file carries, the optional `c2r` one
    # included (EXECUTION_ENABLED_TH_SENSITIVITY_SPEC.md section 4.1): a
    # drifted c2r digest is refused at load, not first at a c2r launch.
    dx_exec = load_profile(os.path.join(
        CONFIG_DIR, "profile_python_docx_checked_interfaces_target_hidden_exec.yml"))
    for label, digests, named in (
            ("a drifted c2r digest", dict(dx_exec.prompt_digest, c2r="0" * 64),
             "c2r: file says " + "0" * 64),):
        try:
            verify_prompt_digests(replace(dx_exec, prompt_digest=digests))
            check(f"{label} is refused", False, "verified without complaint")
        except ProfileError as e:
            check(f"{label} is refused, by name", "REFUSED" in str(e)
                  and named in str(e), str(e)[:300])

    # -- the disclosing python-docx twin (spec D2): the same one-variable
    # relation to `profile_python_docx.yml`, asserted in both directions.
    dx_base_path = os.path.join(CONFIG_DIR, "profile_python_docx.yml")
    dx_ti_path = os.path.join(CONFIG_DIR, "profile_python_docx_target_interfaces.yml")
    check("the target-interfaces python-docx profile is shipped",
          os.path.isfile(dx_ti_path))
    if os.path.isfile(dx_ti_path) and os.path.isfile(dx_base_path):
        dx = load_profile(dx_base_path)
        dxt = load_profile(dx_ti_path)
        check("the docx twin discloses target interfaces and its base does not",
              dxt.disclose_target_interfaces is True
              and dx.disclose_target_interfaces is False)
        check("the docx twin's single_shot digest is its base's",
              dxt.prompt_digest["single_shot"] == dx.prompt_digest["single_shot"])
        check("the docx twin's three agent digests all differ from its base's",
              all(dxt.prompt_digest[k] != dx.prompt_digest[k]
                  for k in ("c1.5", "c2", "c3")))
        check("every other word of the docx twin is its base's",
              dxt.facts == dx.facts and dxt.platform_blurb == dx.platform_blurb
              and dxt.acceptance_root == dx.acceptance_root
              and dxt.placement_hint == dx.placement_hint
              and dxt.trial_clause_unbounded == dx.trial_clause_unbounded
              and dxt.wiring_channel == dx.wiring_channel
              and dxt.project == dx.project == "python-docx")

    print("\n" + ("ALL PASS (profile)" if ok else "FAILURES (profile)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
