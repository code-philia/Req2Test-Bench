"""The prompt renderer: what a system under test is told (SPEC S7).

Every project-specific fact the prompt states (Behat docblock annotations,
the DI registration the harness performs, the optional `behat_services.yml`
channel) is READ from a task profile (`profile.py`, `config/profile_<project>.yml`)
that sits beside the boundary it describes.  This module owns the SHAPE of
the prompt -- which sections exist, in what order, and which of them each
condition gets -- and the profile owns the words.  `profile.verify_prompt_digests`
freezes each project's four renderings byte for byte on every load, which is
why this module is the dataset contract's and depends on nothing but the
profile: `load_profile` reaches it, so it may reach nothing of the harness.

Cut out of `bench/adapters.py` in wave M5 (the LLM config, the single-shot
openai adapter and the repository ablation stayed there); every function
here is byte-for-byte what that module rendered.
"""
from __future__ import annotations

import json

from typing import Optional

from .profile import ProfileError, TaskProfile, default_profile
# The trial vocabulary, imported at module scope because the PROMPT depends on
# it: which C3 clause is rendered is decided by whether a budget was given, and
# that decision has to be made in one place with one spelling.  From
# `constants`, not `trials`: this module is benchmark code and `trials` is
# agent code, and the benchmark must import without it.
from ..core.constants import UNBOUNDED, SUBMITTED_CONDITION, is_unbounded


def _profile(profile: Optional[TaskProfile]) -> TaskProfile:
    """The profile, or CoreShop's.

    Every rendering entry point below takes `profile=None`, so a caller that
    predates the parameterisation keeps rendering exactly what it rendered
    before.  The fallback is a FUNCTION call rather than a module constant on
    purpose: importing this module must not read a YAML file off disk, or a
    missing config would break `python3 -c "from r2t import cli"` rather than
    the one command that actually needs a profile.
    """
    return profile if profile is not None else default_profile()


def environment_facts(profile: Optional[TaskProfile] = None) -> str:
    """The framework facts, with NO delivery contract attached.

    The split exists because the two halves answer different questions and
    only one of them is true in both conditions.  The facts (docblock
    annotations, the DI registration the harness performs, the
    `behat_services.yml` channel) are environment, and every system under
    test needs them.  How the work is DELIVERED is not: the single-shot
    adapter reads a JSON object out of a chat reply, while the agent's answer
    is whatever changed under the workspace repo, harvested off disk.

    Splicing the single-shot contract onto the agent prompt made every agent
    prompt END with "Return ONLY a JSON object", directly contradicting the
    "How your work is collected" section a few lines above it.  An agent that
    obeys the LAST instruction it was given writes nothing to disk, and the
    row scores `no_files_returned` -- a generation failure recorded against a
    model that did what we asked.

    The bullets come from `profile.bullets()`, which resolves the
    wiring-channel slot: a framework with no container emits neither the fact
    nor the collection-contract bullet that offers the channel, rather than
    telling a behave agent to return a Symfony `services:` block.
    """
    p = _profile(profile)
    return (
        f"You write executable {p.runner_noun} test code for "
        f"{p.platform_blurb}.\n"
        "\n"
        "All test code has been removed from the repository. Given one "
        f"Gherkin scenario, produce the {p.language_label} {p.artefact_noun} "
        "that makes exactly that scenario run and pass against the unmodified "
        "production code.\n"
        "\n"
        "Facts about the environment you cannot see:\n"
        "\n"
        + "".join(f"* {b}\n" for b in p.bullets()))


def return_contract(profile: Optional[TaskProfile] = None) -> str:
    """How a SINGLE-SHOT system delivers its answer.

    There is no disk to write to, so the files have to come back inside the
    reply.  This belongs to the `openai` adapter alone.  The example path and
    the example code body are the profile's, because a PHP `<?php ...` shown
    to a python system is an instruction to produce the wrong file.
    """
    p = _profile(profile)
    return ('Return ONLY a JSON object:\n'
            '\n'
            '{"files": [{"file_path": "' + p.example_path + '", "code": "'
            + p.example_code + '"}], "metadata": {"notes": "..."}}\n')


def system_prompt(profile: Optional[TaskProfile] = None) -> str:
    """Reassembled, and BYTE-IDENTICAL to the string the C1 sweep was sent.

    Those rows were generated against this exact prompt, and a prompt that
    drifts silently makes them incomparable with anything generated
    afterwards while still being labelled the same system.  The profile pins
    its sha256 as `prompt_digest.single_shot` for that reason -- the joiner
    below is the blank line that separates the last bullet from the contract,
    and nothing about this concatenation may be "tidied".
    """
    p = _profile(profile)
    return environment_facts(p) + "\n" + return_contract(p)


def build_user_prompt(task: dict, profile: Optional[TaskProfile] = None) -> str:
    """One item, as the system under test sees it.

    Also the single chokepoint every prompt goes through, which is why the
    profile/item cross-check lives here: `check_item` refuses an item whose
    (project, language, framework) the profile does not describe.  Running
    CoreShop's profile over a behave release would ask for PHP in
    `src/CoreShop/Behat/`, harvest `.php`, and record 422 rows of the model
    failing -- with a run file that looks entirely normal.
    """
    p = _profile(profile)
    from .profile import check_item
    check_item(p, task)
    req = task.get("requirement") or {}
    crit = task.get("criterion") or {}
    parts = [f"Feature: {req.get('feature_title') or ''}"]
    if req.get("narrative"):
        parts.append(req["narrative"])
    if req.get("background"):
        parts.append("\n" + req["background"])
    if task["task"] == "criterion_to_test":
        parts.append("\nThe scenario to implement:\n")
        parts.append(crit.get("gherkin") or "")
        parts.append(f"\nReturn the {p.artefact_noun} (and any helper it "
                     f"needs) that makes this scenario pass.")
    else:
        parts.append(f"\nWrite the Gherkin scenario(s) for this requirement "
                     f"AND the {p.artefact_noun} that makes them pass. Put the "
                     f"Gherkin in a file whose path ends in "
                     f"`{p.gherkin_suffix}`.")
    if p.disclose_target_interfaces:
        parts.append(target_interfaces_block(task, p))
    if p.disclose_checked_interfaces:
        parts.append(checked_interfaces_block(task, p))
    if p.acceptance_mode == "item_path":
        from ..go.context import answer_paths
        context = task["go_suite"]
        paths = ", ".join(f"`{p.repo_dir}/{path}`" for path in answer_paths(task))
        parts.append(
            f"\nReturn complete Go files at exactly these paths: {paths} "
            f"(item {task['item_id']}). "
            "This file list overrides the illustrative return-contract example. "
            "Every listed file is required and no other answer path is accepted.\n"
            f"Primary glue: `{context['glue_path']}`. "
            f"Package: `{context['package_name']}` in `{context['package_dir']}`.\n"
            f"Define `{context['test_name']}` with a Godog suite and initializer "
            "for this requirement. The harness owns the execution options.\n"
            f"Go build tags: {json.dumps(context['go_build_tags'])}.\n"
            f"Godog tag expression: {json.dumps(context['godog_tags'])}.")
    else:
        parts.append(f"\nRepository file to place code under: "
                     f"{p.placement_hint} (item {task['item_id']}).")
    return "\n".join(p2 for p2 in parts if p2 is not None)


def placement_row(profile: Optional[TaskProfile] = None) -> dict:
    """Where this project's answer goes, for a reader that is not a prompt.

    An agent driver runs inside the agent sandbox, which ro-binds this
    PACKAGE directory but not `config/` -- a sibling of it, of which one
    audited file (`pricing.yml`) is bound by name.  So a driver that has to
    name a write location can import this module and still not `load_profile`
    anything: there is no profile YAML to read.  It has to be handed one.  This is
    the row `adapter` puts in `task.json` beside the prompt, and it is built
    from the same three fields the prompt above renders: the artefact noun,
    the `placement_hint` sentence and the wiring bullet.  A driver can
    therefore only REPEAT where the agent was already told to write, rather
    than offer a second opinion about it.

    Paths are `repo_dir`-prefixed, because a driver's workspace is the parent
    of the repository and that is the form the collection contract's wiring
    bullet already uses.  `wiring_file` is None exactly where `bullets()`
    omits the bullet -- a framework with no service container has no wiring
    file, and naming one would ask for a file the harness has nowhere to put.

    `suffixes` and `extra_names` are the OTHER thing a driver cannot derive
    and must not guess: which files count as the agent's answer at all.  They
    are copied from `TaskProfile.harvest_suffixes()` and `.extra_names` --
    the identical pair `agents.adapter` hands `trials.final_harvest` -- read
    through those accessors rather than reassembled here, so a driver's view
    of "the agent has written something" and the harvest's view of "this is
    the submission" cannot drift apart.  The openhands driver filtered for
    `.php` or `behat_services.yml`, written as a literal, until this row
    carried them, and its `wrote_files` stat was therefore false on every
    non-PHP project.  Lists, not tuples: the row is read back out of JSON,
    and the row a caller holds should equal the row a driver loads.

    None of it is disclosure the prompt has not already made.  The artefact
    noun, the placement sentence and the wiring bullet are rendered above and
    in `environment_facts`; the two filters restate the language the prompt
    asks the agent to write, the Gherkin suffix it already names and that
    same wiring file.
    """
    p = _profile(profile)
    return {"artefact_noun": p.artefact_noun,
            "path": f"{p.repo_dir}/{p.placement_hint}",
            "wiring_file": (f"{p.repo_dir}/{p.wiring_channel.name}"
                            if p.wiring_channel is not None else None),
            "suffixes": list(p.harvest_suffixes()),
            "extra_names": list(p.extra_names)}


#: The heading the disclosed block opens with.  One string, used by the
#: renderer and read back by the selftest, so the two cannot drift apart.
TARGET_INTERFACES_HEADING = (
    "Target interfaces -- the production types through which this scenario's "
    "behaviour is exercised. They are declared in the repository; helpers, "
    "fixtures and test data are not listed.")

#: The two labelled lists (spec D1): the scenario's own surface, and what the
#: Background's steps add beyond it.  Fixed labels, fixed order.
TARGET_INTERFACES_BEHAVIOUR = "Behaviour (this scenario's steps):"
TARGET_INTERFACES_SETUP = "Setup (the Background's steps):"

#: What an EMPTY list renders under its label.  A value, not an omission: the
#: block is present under a disclosing profile whatever the lists hold, so a
#: reader of the prompt can tell "none identified" from "not disclosed".
TARGET_INTERFACES_NONE = "none identified"


def target_interfaces_block(task: dict, profile: TaskProfile) -> str:
    """The `target_interfaces` section of the user prompt (TARGET_INTERFACES_SPEC).

    Rendered ONLY when the profile discloses it, which is what makes the
    disclosure a frozen property of the profile rather than of the item: the
    canonical task carries a fixed list, so a disclosing profile's digests
    differ from a non-disclosing one's and `verify_prompt_digests` sees the
    change.  A profile that discloses and an item that carries no list is a
    refusal -- the prompt would promise a section the item cannot fill.

    Two labelled, sorted lists of fully-qualified names and nothing else: no
    methods, no counts, no per-step attribution.  The lists are sorted and
    made disjoint by the ITEM builder; repairing either here would hide a
    malformed item.
    """
    from .profile import ProfileError
    iid = task.get("item_id")
    lists = task.get("target_interfaces")
    if lists is None:
        raise ProfileError(
            f"REFUSED: {profile.path} discloses target interfaces but item "
            f"{iid!r} carries no `target_interfaces` field. The prompt would "
            f"promise a section the item cannot fill; release the item with "
            f"the field (empty lists are values) or run it under a profile "
            f"that does not disclose.")
    if not isinstance(lists, dict) or set(lists) != {"behaviour", "setup"}:
        raise ProfileError(
            f"REFUSED: item {iid!r} `target_interfaces` must be a mapping "
            f"with exactly the keys `behaviour` and `setup`, got "
            f"{sorted(lists) if isinstance(lists, dict) else type(lists).__name__}.")
    for key in ("behaviour", "setup"):
        names = lists[key]
        if not isinstance(names, list) or any(not isinstance(n, str) for n in names):
            raise ProfileError(
                f"REFUSED: item {iid!r} `target_interfaces.{key}` must be a "
                f"list of strings, got {type(names).__name__}.")
        if names != sorted(names) or len(set(names)) != len(names):
            raise ProfileError(
                f"REFUSED: item {iid!r} `target_interfaces.{key}` is not "
                f"sorted and deduplicated; the release builder owns that "
                f"order and the renderer will not repair it.")
    if set(lists["behaviour"]) & set(lists["setup"]):
        raise ProfileError(
            f"REFUSED: item {iid!r} names a type in both `target_interfaces` "
            f"lists; `setup` is what the Background adds BEYOND the "
            f"scenario's own surface.")

    def section(label, names):
        if not names:
            return f"{label} {TARGET_INTERFACES_NONE}"
        return label + "\n" + "\n".join(f"- {n}" for n in names)
    return ("\n" + TARGET_INTERFACES_HEADING + "\n"
            + section(TARGET_INTERFACES_BEHAVIOUR, lists["behaviour"]) + "\n"
            + section(TARGET_INTERFACES_SETUP, lists["setup"]))


#: The heading the v2 block opens with (TARGET_INTERFACES_V2_SPEC section 5a),
#: verbatim.  A separate constant from the v1 heading because the two blocks
#: are two disclosures, not two renderings of one: a v1 profile's four frozen
#: digests must not move when this string is written or changed.
CHECKED_INTERFACES_HEADING = (
    "Target interfaces -- the product methods this scenario's actions and "
    "checks call. They are declared in the repository; how to reach them "
    "(setup, fixtures, helpers, test data) is part of the task.")

#: What an EMPTY list renders, with its recorded reason in parentheses.  An
#: empty list is a VALUE (spec section 3.4), so the block is present under a
#: disclosing profile whatever the list holds and a reader of the prompt can
#: tell "none identified" from "not disclosed".
CHECKED_INTERFACES_NONE = "none identified"

#: The only reason an empty list may carry (spec section 3.4).  A tuple rather
#: than a bare string so the refusal below can name the vocabulary; the
#: derivation records exactly this token and nothing else.
CHECKED_INTERFACES_REASONS = ("no_action_or_check_call",)


def checked_interfaces_block(task: dict, profile: TaskProfile) -> str:
    """The `checked_interfaces` section of the user prompt (v2 spec section 5a).

    A PURE function of (task, profile), like its v1 twin: it holds no index
    and reads no source.  That is why each entry carries its own
    `declaration` text -- resolving a method key to the line it is declared on
    needs the pinned production index and the pinned source bytes, which is a
    mint-time input, not a prompt-time one (review B2).  The index, public and
    first-party checks the specification lists in section 5 are therefore
    DERIVATION refusals (section 8); what is left here is the shape, the
    order, and the empty-list/reason pairing.

    Entries are grouped for rendering on `key[0]`, the declaring type, in the
    stored order.  The derivation owns that order (sorted by the whole key and
    de-duplicated); repairing it here would hide a malformed item, exactly as
    the v1 renderer refuses to re-sort its lists.
    """
    from .profile import ProfileError
    iid = task.get("item_id")
    field = task.get("checked_interfaces")
    if field is None:
        raise ProfileError(
            f"REFUSED: {profile.path} discloses checked interfaces but item "
            f"{iid!r} carries no `checked_interfaces` field. The prompt would "
            f"promise a section the item cannot fill; release the item with "
            f"the field (an empty list with its reason is a value) or run it "
            f"under a profile that does not disclose.")
    if not isinstance(field, dict) or set(field) != {"checked", "empty_reason"}:
        raise ProfileError(
            f"REFUSED: item {iid!r} `checked_interfaces` must be a mapping "
            f"with exactly the keys `checked` and `empty_reason`, got "
            f"{sorted(field) if isinstance(field, dict) else type(field).__name__}.")
    entries = field["checked"]
    if not isinstance(entries, list):
        raise ProfileError(
            f"REFUSED: item {iid!r} `checked_interfaces.checked` must be a "
            f"list, got {type(entries).__name__}.")
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"key", "declaration"} \
                or not isinstance(entry.get("key"), list) \
                or not entry["key"] \
                or any(not isinstance(part, str) for part in entry["key"]) \
                or not isinstance(entry.get("declaration"), str) \
                or not entry["declaration"]:
            raise ProfileError(
                f"REFUSED: item {iid!r} `checked_interfaces.checked` entry "
                f"{entry!r} is not a mapping of a non-empty `key` list of "
                f"strings and a non-empty `declaration` string.")
    keys = [entry["key"] for entry in entries]
    if keys != sorted(keys) or any(a == b for a, b in zip(keys, keys[1:])):
        raise ProfileError(
            f"REFUSED: item {iid!r} `checked_interfaces.checked` is not "
            f"sorted by `key` and deduplicated; the derivation owns that "
            f"order and the renderer will not repair it.")
    reason = field["empty_reason"]
    if not entries and reason is None:
        raise ProfileError(
            f"REFUSED: item {iid!r} has an empty `checked_interfaces.checked` "
            f"and no `empty_reason`. An empty list is a value with a recorded "
            f"reason, never an omission.")
    if entries and reason is not None:
        raise ProfileError(
            f"REFUSED: item {iid!r} carries `empty_reason` {reason!r} beside "
            f"{len(entries)} checked interfaces; a reason describes an EMPTY "
            f"list and nothing else.")
    if reason is not None and reason not in CHECKED_INTERFACES_REASONS:
        raise ProfileError(
            f"REFUSED: item {iid!r} `checked_interfaces.empty_reason` is "
            f"{reason!r}; the only reason this benchmark defines is "
            f"{CHECKED_INTERFACES_REASONS[0]!r}.")

    if not entries:
        body = f"{CHECKED_INTERFACES_NONE} ({reason})"
    else:
        lines, current = [], None
        for entry in entries:
            if entry["key"][0] != current:
                current = entry["key"][0]
                lines.append(f"  {current}")
            lines.append(f"    - {entry['declaration']}")
        body = "\n".join(lines)
    return "\n" + CHECKED_INTERFACES_HEADING + "\n" + body


#: What an ANNOTATED COMPANION pool may add to a frozen task row, and the
#: renderer each addition is validated through.  One table, read by both
#: companion validators (`data.release.validate_annotated_release` and
#: `data.bundle._validate_annotated_release`), because a companion that the
#: release admits and the bundle refuses -- or the reverse -- is a pool that
#: exists on one side of the installation only.
ANNOTATION_BLOCKS = {"target_interfaces": target_interfaces_block,
                     "checked_interfaces": checked_interfaces_block}


def validate_annotation(row: dict, path: str) -> None:
    """Refuse a companion row whose annotation the prompt could not render.

    A companion exists to ADD a disclosure to frozen task bytes, so a row that
    adds none is refused -- with the v1 renderer's own message, because the v1
    field is still the one a companion without a v2 derivation carries.  Where
    a field IS present it goes through its own renderer, so the shape, order
    and reason rules are the prompt's, stated once.
    """
    from types import SimpleNamespace
    profile = SimpleNamespace(path=path)
    present = [key for key in ANNOTATION_BLOCKS if key in row]
    if not present:
        target_interfaces_block(row, profile)
        return
    for key in present:
        ANNOTATION_BLOCKS[key](row, profile)


# ------------------------------------------------------------- OpenHands
def guidance_block(profile: Optional[TaskProfile] = None) -> str:
    """The profile's `guidance` block as the agent reads it, or "".

    The empty string for every profile without the block, which is what keeps
    their prompts byte for byte.  With one, it is the last section of every
    agent prompt: the rendered prompt already ends in a blank line after the
    environment facts, so the heading follows that line exactly as every other
    section follows its predecessor.  The text's trailing newlines are
    normalised to one, so YAML's block-scalar chomping does not reach the
    bytes.
    """
    g = _profile(profile).guidance
    if g is None:
        return ""
    return g.heading + ":\n\n" + g.text.rstrip("\n") + "\n"


def agent_prompt_base(profile: Optional[TaskProfile] = None) -> str:
    """The one prompt every general-purpose agent gets.

    The conditions differ ONLY in `{repo_clause}` and `{trial_clause}` --
    what the agent can see and what it can do. Everything else is identical,
    because C1.5 -> C2 is meant to isolate repository access and C2 -> C3
    execution feedback, and neither isolates anything if the surrounding
    prose moves too.

    There is deliberately no advice about HOW to work. Whether an agent turns
    exploration into an attempt is part of what is being measured; an earlier
    version told it to "write a first version immediately" and "do NOT
    explore first", which measured the prompt rather than the agent.  The one
    exception is a profile's labelled `guidance` block, appended after
    everything else (`guidance_block`), so an intervention profile's prompt is
    its parent's prompt plus that block and nothing else moves.

    Two of the three collection bullets are structural and always emitted.
    The third -- the wiring channel -- is emitted only when the profile has
    one: offering a behave agent a Symfony `services:` block is not harmless
    filler, it is an instruction to produce a file the harness has nowhere to
    put, and the agent spends turns on it.
    """
    p = _profile(profile)
    if p.acceptance_mode == "item_path":
        collected = (
            "* Only the exact item-specified Go file set is accepted. "
            "Return every listed file, with helpers within that set.\n"
            "* Production code and retained support are never accepted as answers. "
            "Changes to any other path are discarded.\n")
        if p.retained_note:
            collected += f"* {p.retained_note}.\n"
    else:
        root = p.acceptance_prefix()
        # "create whatever path you need; `Context/Hook` is what remains." for a
        # project with a carve-out, and a plain full stop for one without.
        tail = f"; {p.retained_note}." if p.retained_note else "."
        collected = (
            f"* Only files under `{root}` are accepted. Repo-wide removal deleted "
            f"those directories, so create whatever path you need{tail}\n"
            f"* Production code is never accepted. Anything you change outside "
            f"`{root}` is discarded.\n")
    if p.wiring_channel is not None:
        w = p.wiring_channel
        collected += (f"* If {w.when_needed}, a file `{p.repo_dir}/{w.name}` "
                      f"is read as {w.format}.\n")
    return (
        f"All {p.removed_noun} has been removed from the {p.project_label} "
        f"repository. Write the {p.language_label} {p.artefact_noun} that "
        f"makes ONE scenario run and pass against the unmodified production "
        f"code.\n"
        "\n"
        "{task}\n"
        "\n"
        "How your work is collected:\n"
        + collected
        + "\n"
        "{repo_clause}\n"
        "\n"
        "{trial_clause}\n"
        "\n"
        "{instructions}\n"
        + guidance_block(p))


def repo_clause(condition: str, profile: Optional[TaskProfile] = None) -> str:
    """What the agent can SEE. The only difference between C1.5 and C2."""
    p = _profile(profile)
    if _agent_condition(condition) == "c1.5":
        return (f"`./{p.repo_dir}` is empty: there is no "
                f"{p.project_source_noun}, no other `{p.gherkin_suffix}` "
                f"file, and nothing to search.")
    return (f"The repository is in `./{p.repo_dir}`: production code, the "
            f"other `{p.gherkin_suffix}` files, and {p.retained_substrate}.")


def trial_clause(condition: str, profile: Optional[TaskProfile] = None,
                 trials=0) -> str:
    """What the agent can DO. The only difference between C2 and C3.

    The C3 clause is returned with `{client}` — and, in the bounded form,
    `{k}` — still unfilled: `agent_prompt_for` substitutes them, because the
    client's real path is only known once the trial socket exists (building
    the prompt before the channel and patching it afterwards is how C3 once
    shipped a prompt that said both "cannot run" and "may run").

    WHICH of the profile's two forms is rendered depends on one thing: whether
    a budget was given.  `--trials unlimited` renders a clause with no number
    in it at all, because there is no longer a number: a trial is a terminal
    tool call and already spends one of the agent's iterations, so
    `--max-iterations` bounds executions natively and a second counter bounds
    nothing (`trials.py`, "WHY THERE IS NO LONGER A SEPARATE EXECUTION
    BUDGET").  Deleting the count from the prompt is the point rather than a
    tidy-up: "You may do this 20 times" tells an agent its executions are
    scarce, scarce resources get hoarded, and hoarding-while-exploring is the
    behaviour this benchmark is measuring — a prompt that induces the finding
    is a confound in it.

    The wording of both forms is the PROFILE's (`trial.clause_bounded`,
    `trial.clause_unbounded`); the choice between them is this function's.
    `.replace` rather than `.format` for the two nouns, because `{client}` and
    `{k}` have to survive to the caller unfilled.

    `c2r` is C2 with a runnable workspace and no harness channel
    (EXECUTION_ENABLED_TH_SENSITIVITY_SPEC.md section 4): the C2 sentence made
    true, then the profile's entry-point sentence when it has one.  Only a
    target-hidden profile that freezes a `c2r` prompt renders it; every other
    profile's view has no runtime pack, so the sentence would be false there.
    """
    p = _profile(profile)
    cond = _agent_condition(condition)
    if cond == "c2r":
        if "c2r" not in p.prompt_digest or p.source_visibility != "target_hidden":
            raise ProfileError(
                f"REFUSED: {p.path} renders no c2r prompt: c2r is valid only "
                f"for a target-hidden profile that freezes `prompt_digest.c2r`.")
        return " ".join(s for s in (RUNNABLE_CLAUSE, p.trial_clause_runnable_entry)
                        if s)
    if cond != "c3":
        return "The scenario cannot be run from this workspace."
    tmpl = (p.trial_clause_unbounded if is_unbounded(trials)
            else p.trial_clause_bounded)
    return (tmpl.replace("{interpreter}", p.client_interpreter)
                .replace("{runner}", p.runner_noun))


#: The `c2r` trial clause, the same for every project (section 4.1).
RUNNABLE_CLAUSE = "The scenario can be run from this workspace."

#: Every benchmark-produced agent condition, lowercased. One set, so the
#: prompt builder and the seed builder cannot disagree about what exists.
#: `c2r` is the execution-enabled target-hidden sensitivity: a separate
#: label, never pooled with `c2`.
AGENT_CONDITIONS = ("c1.5", "c2", "c3", "c2r")

#: The separate, non-study tier used for externally produced candidates is
#: `constants.SUBMITTED_CONDITION`, imported above: deliberately absent from
#: ``AGENT_CONDITIONS``, because those labels describe the benchmark's own
#: reviewed generation protocols, while submitted bytes were produced under a
#: protocol this repository does not declare or review.


def _agent_condition(condition: str) -> str:
    """Normalise a condition label, or refuse it.

    Both of the callers used to fall back to C2 for anything unrecognised,
    which is the worst possible reading of a typo: `--condition c1_5` or
    `--condition C3 ` would have run the C2 prompt with the C2 seed and
    labelled every row with the condition the operator asked for.  The run file
    would then claim an ablation that was never performed, and nothing in it
    would look wrong.  A sweep is hours of agent time; failing at the first
    call is cheap by comparison.
    """
    # Lowercased, and nothing else. `condition` is also stamped verbatim on
    # every row and used verbatim as a trajectory directory name, so any
    # normalisation done HERE that is not done THERE buys a run whose prompt
    # and whose label disagree. Case folding predates this and stays; whitespace
    # is not silently eaten.
    cond = (condition or "").lower()
    if cond not in AGENT_CONDITIONS:
        raise ValueError(
            f"unknown agent condition {condition!r}; "
            f"valid conditions are {set(AGENT_CONDITIONS)}")
    return cond


def agent_prompt_for(condition: str, *, profile: Optional[TaskProfile] = None,
                     trials=0, client: str = "trial.py") -> str:
    """The prompt for one condition — same base, different affordances.

    `trials` is the WIRE value (`0`, a count, or `trials.UNBOUNDED`), passed
    through unnormalised so that this function renders exactly what the caller
    is about to run rather than its own idea of it.  `k=trials` is handed to
    `str.format` for both forms: the unbounded clause has no `{k}` to fill (a
    profile that put one there is refused at load), so the extra keyword is
    ignored and there is no second code path to keep in step.
    """
    p = _profile(profile)
    cond = _agent_condition(condition)
    trial = trial_clause(cond, p, trials)
    if cond == "c3":
        trial = trial.format(client=client, k=trials)
    return agent_prompt_base(p).replace(
        "{repo_clause}", repo_clause(cond, p)).replace("{trial_clause}", trial)


#: The item every profile's prompts are FROZEN over.
#:
#: A digest of the prompt template alone would not cover `build_user_prompt`,
#: and that function carries two project-specific strings of its own (where to
#: put the code, and the Gherkin file suffix).  Rendering a fixed fictional
#: item instead makes the freeze cover the whole assembled message, and the
#: fixture is a CONSTANT rather than a real release item so that the digest
#: depends on the profile and on nothing else.
CANONICAL_TASK = {
    "item_id": "canonical/example.feature:1",
    "task": "criterion_to_test",
    "requirement": {"feature_title": "Canonical feature",
                    "narrative": "Canonical narrative",
                    "background": "  Background:\n    Given a canonical "
                                  "precondition"},
    "criterion": {"gherkin": "  Scenario: canonical\n    Then it holds"},
    # Present on the fixture so that a profile which DISCLOSES target
    # interfaces renders the block over the canonical item and freezes it;
    # a profile that does not disclose never reads the key, so the four
    # digests of every profile shipped before this key existed are the
    # bytes they always were (`data.prompt.selftest` pins them literally).
    "target_interfaces": {
        "behaviour": ["Canonical\\Model\\ExampleInterface",
                      "Canonical\\Service\\ExampleRepositoryInterface"],
        "setup": ["Canonical\\Model\\CanonicalStoreInterface"]},
    # The v2 field, beside the v1 one rather than instead of it
    # (TARGET_INTERFACES_V2_SPEC review A1).  A profile that discloses only
    # `target_interfaces` never reads this key, so adding it moved none of the
    # four digests of the profiles shipped before it -- which the selftest
    # below asserts against the literal pins, not against the profiles.
    #
    # Two entries, one PHP-shaped key and one Python-shaped key, because the
    # rendering groups on `key[0]` and a one-entry fixture would freeze a
    # block that never exercises the grouping or the sort.
    "checked_interfaces": {
        "checked": [
            {"key": ["Canonical\\Model\\ExampleInterface", "getExample"],
             "declaration": "public function getExample(): string;"},
            {"key": ["canonical.example.Thing", "value"],
             "declaration": "(property getter)"},
        ],
        "empty_reason": None},
}

#: The client name the canonical C3 rendering uses. Fixed, because a digest
#: that moved with the workspace's temporary directory would freeze nothing.
CANONICAL_CLIENT = "trial.py"


def canonical_task(profile: TaskProfile) -> dict:
    """The old fixture stays byte-identical; only item_path uses Go context."""
    if profile.acceptance_mode != "item_path":
        return CANONICAL_TASK
    from ..go.context import canonical_item
    return dict(CANONICAL_TASK, **canonical_item())


def canonical_prompt(profile: TaskProfile, key: str, trials=UNBOUNDED) -> str:
    """One of the four prompts a profile freezes, fully assembled.

    `single_shot` is the chat adapter's system message; the other three are
    what an agent receives as its first user message.  Assembled the way the
    adapters assemble it -- `agent_prompt_for(...).format(...)`, never a
    re-implementation -- because a freeze over a lookalike string would go on
    passing while the shipped prompt drifted.

    `trials` defaults to UNBOUNDED because that is what the C3 arm runs now,
    and the frozen digest has to name the prompt that is actually sent.  It is
    a PARAMETER rather than a constant so the adapter can stamp each row with
    the digest of the FORM that row was generated under: a `--trials k` run
    stamps the bounded digest (the historical one) and an unlimited run stamps
    this one, so a run file cannot claim a clause it did not send.  Callers
    pass a form, not a count -- `CANONICAL_TRIALS` for bounded -- because the
    task fixture, the client name and the count are all held fixed on purpose:
    a digest that moved with `--trials` would freeze nothing and would match
    none of the four values in the profile.
    """
    if key == "single_shot":
        return system_prompt(profile)
    return agent_prompt_for(key, profile=profile, trials=trials,
                            client=CANONICAL_CLIENT).format(
        task=build_user_prompt(canonical_task(profile), profile),
        instructions=environment_facts(profile))


def prompt_digests(profile: TaskProfile, trials=UNBOUNDED) -> dict:
    """sha256 of each of the four, for `profile.prompt_digest`, and of every
    further prompt the profile freezes (`c2r`)."""
    import hashlib
    from .profile import PROMPT_KEYS
    keys = PROMPT_KEYS + tuple(k for k in profile.prompt_digest
                               if k not in PROMPT_KEYS)
    return {k: hashlib.sha256(
        canonical_prompt(profile, k, trials).encode("utf-8")).hexdigest()
        for k in keys}


def selftest() -> int:
    """The PROMPT, checked as an artefact rather than as code that builds one.

    Everything else in this codebase reads source or output; nothing read what
    is actually sent to the model. So C3 shipped with a prompt that said both
    "You CANNOT run the tests ... Read the repository instead" (inherited from
    C2) and "You may RUN the scenario against the real application" (appended
    for C3). All five C3 runs made zero trial requests and explored until their
    budget ran out — doing what the first sentence told them.

    A prompt is an input, and its claims have to match the affordances of the
    condition it describes. That is what these checks assert.
    """
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    import os
    # The bounded C3 budget is the adapter's constant (it is what a run is
    # given), read back here only to reproduce the bounded rendering.
    from ..bench.adapters import CANONICAL_TRIALS

    check("submitted is a separate tier, never a producer condition",
          AGENT_CONDITIONS == ("c1.5", "c2", "c3", "c2r")
          and SUBMITTED_CONDITION == "submitted"
          and SUBMITTED_CONDITION not in AGENT_CONDITIONS,
          f"agent={AGENT_CONDITIONS!r}, submitted={SUBMITTED_CONDITION!r}")

    task = {"item_id": "p/f.feature:3", "task": "criterion_to_test",
            "requirement": {"feature_title": "F", "narrative": "n",
                            "background": "  Background:\n    Given a"},
            "criterion": {"gherkin": "  Scenario: s\n    Then b"}}


    from .profile import (CONFIG_DIR, DEFAULT_PROFILE_PATH, PROMPT_KEYS,
                          load_profile)
    coreshop = load_profile(DEFAULT_PROFILE_PATH)

    def assembled(condition: str, prof=coreshop, trials=UNBOUNDED) -> str:
        # No appending. The trial offer is part of the prompt now; bolting it
        # on afterwards is how C3 came to say both "cannot run" and "may run".
        #
        # `environment_facts`, the same renderer the adapter fills in at
        # generation time. Substituting `system_prompt` here would have made
        # the test agree with itself and with nothing that ships.
        return agent_prompt_for(condition, profile=prof, trials=trials,
                                client="trial.py").format(
            task=build_user_prompt(task, prof),
            instructions=environment_facts(prof)).lower()

    # C3 has TWO renderings now and both ship: `--trials unlimited` (what the
    # arm runs) and `--trials k` (still supported, still frozen). Every
    # invariant below is checked over both, because "the prompts differ only
    # in the two clauses" and "no strategy coaching" are claims about what is
    # sent to a model, and either form can be the thing sent.
    c15, c2 = assembled("c1.5"), assembled("c2")
    c3, c3k = assembled("c3"), assembled("c3", trials=5)
    # `c2r` renders only on a target-hidden profile that freezes it, so it is
    # read off CoreShop's execution-enabled variant, over the canonical item
    # that profile's checked-interfaces disclosure needs, beside the C2
    # prompt of the same profile.
    from dataclasses import replace as _dc_replace
    coreshop_exec = load_profile(os.path.join(
        CONFIG_DIR, "profile_coreshop_checked_interfaces_target_hidden_exec.yml"))
    c2r = canonical_prompt(coreshop_exec, "c2r").lower()
    c2x = canonical_prompt(coreshop_exec, "c2").lower()

    # THE FREEZE. Four sweeps on disk (single-shot C1, and the three agent
    # arms) were generated with these exact bytes, and comparing their rows
    # against anything generated later is only meaningful if the input did not
    # move. Turning the prompt into a profile-driven renderer was a refactor of
    # the SOURCE and had to be a no-op on the VALUE, so the value is pinned by
    # hash rather than by eye.  If this fails, the question is not "update the
    # digest" but "which sweep is now unattributable".
    #
    # The pin lives in the PROFILE, one set of four per project, rather than as
    # one global constant here: with two projects a single constant asserts
    # that project 2's prompt equals project 1's, so the first thing a second
    # profile would force is deleting the freeze that protects the first.
    import hashlib as _hl
    rendered = prompt_digests(coreshop)
    for key in PROMPT_KEYS:
        check(f"the {key} prompt is byte-for-byte what CoreShop was run with",
              rendered[key] == coreshop.prompt_digest[key],
              f"renders {rendered[key]}, frozen as "
              f"{coreshop.prompt_digest.get(key)}")

    # THE THREE ARMS THAT MUST NOT HAVE MOVED, asserted against the literal
    # bytes rather than against the profile that could have been edited beside
    # the code.
    #
    # Removing the trial counter changed C3's clause and therefore C3's
    # digest, on purpose. It touched nothing else, and "touched nothing else"
    # is not a thing to take on trust: single-shot, C1.5 and C2 have published
    # numbers behind them, and a renderer refactor that quietly moved one of
    # them would make those rows incomparable while every label stayed the
    # same. Pinned here, in the test, so that re-pinning the profile cannot
    # also re-pin the check.
    _FROZEN_BEFORE_UNBOUNDED = {
        "coreshop": {
            "single_shot":
                "0cec12ed4a460043b31cac0d1c4b98a6a06f53c74a88cbf36850f62f4e8a2029",
            "c1.5":
                "c9891c9a61d416e79085400c0dd47fa61cb6375bc1e67e67a057739e520367bd",
            "c2":
                "6e1ed242d687dc4022f904786ed70e9a2dc66e4253c080391e52a144204d5e10",
            # The BOUNDED c3, i.e. what `--trials 5` renders today and what
            # every C3 sweep on disk was generated with. It is no longer the
            # profile's frozen `c3` — that is the unbounded form — but it is
            # still reachable and still has to be byte-identical, or those
            # rows lose their prompt.
            "c3_bounded":
                "ef53192e9050468f0200805953c531fd33c891669c5505b2336ff00496c66290",
        },
        "behave_example": {
            "single_shot":
                "64b9d21b031290b21892b37dffbb83a9a30dd535c474f2fdcdbb4046e20a52c4",
            "c1.5":
                "432cd34a5fd56bf6c58dceace61c4be98b78affb3b0a6c11c9e45e07808ce0f6",
            "c2":
                "d67b7c7ad82948cee013d781fd2e02fc5440c4baa2be014131dc02fa74663e94",
            "c3_bounded":
                "6ecf2073eca7c2df6b69ba570b07d3c3f971659dc74c2d1e6dfbfb7206b9290b",
        },
    }
    for key in ("single_shot", "c1.5", "c2"):
        want = _FROZEN_BEFORE_UNBOUNDED["coreshop"][key]
        check(f"removing the trial counter did NOT move the {key} prompt",
              rendered[key] == want, f"{rendered[key]} != {want}")
    bounded = prompt_digests(coreshop, CANONICAL_TRIALS)
    check("the BOUNDED c3 prompt is still the one the C3 sweeps were run with",
          bounded["c3"] == _FROZEN_BEFORE_UNBOUNDED["coreshop"]["c3_bounded"],
          f"{bounded['c3']} != "
          f"{_FROZEN_BEFORE_UNBOUNDED['coreshop']['c3_bounded']}")
    check("and the unbounded c3 is a DIFFERENT prompt, frozen as the new one",
          rendered["c3"] != bounded["c3"]
          and rendered["c3"] == coreshop.prompt_digest["c3"],
          f"{rendered['c3']} vs {bounded['c3']}")
    check("the other three are the same prompt at either budget — only the "
          "trial clause moved",
          all(bounded[k] == rendered[k] for k in ("single_shot", "c1.5", "c2")))
    # ... and the digests really do cover the item text, not just the template:
    # `build_user_prompt` carries two project-specific strings of its own and
    # only the criterion branch is on the canonical fixture's path.
    _REQUIREMENT_PROMPT_SHA256 = (
        "acbe8d7d13d8c7a8480e94e4a64f9495b6aebf5a414fbd16665c3c5e256af945")
    req_task = dict(CANONICAL_TASK, task="requirement_to_test")
    check("the requirement_to_test user prompt is frozen too",
          _hl.sha256(build_user_prompt(req_task, coreshop).encode(
              "utf-8")).hexdigest() == _REQUIREMENT_PROMPT_SHA256,
          _hl.sha256(build_user_prompt(req_task, coreshop).encode(
              "utf-8")).hexdigest())

    # THE TARGET-INTERFACES BLOCK (TARGET_INTERFACES_SPEC section 3.7).
    # Rendered under the disclosing profile and under no other; one fixed
    # heading, one sorted list, one fixed sentence for an empty list; and a
    # profile that discloses refuses an item that carries no list at all.
    from .profile import ProfileError
    ti = load_profile(os.path.join(CONFIG_DIR, "profile_coreshop_target_interfaces.yml"))
    base_render = build_user_prompt(CANONICAL_TASK, coreshop)
    ti_render = build_user_prompt(CANONICAL_TASK, ti)
    check("the base profile renders no target-interfaces block over the "
          "canonical task, so its digests could not have moved",
          TARGET_INTERFACES_HEADING not in base_render
          and "Canonical\\Model\\ExampleInterface" not in base_render)
    check("the disclosing profile renders the heading, the behaviour list, "
          "then the setup list, every name in order, before the placement line",
          ti_render.index(TARGET_INTERFACES_HEADING)
          < ti_render.index(TARGET_INTERFACES_BEHAVIOUR)
          < ti_render.index("- Canonical\\Model\\ExampleInterface")
          < ti_render.index("- Canonical\\Service\\ExampleRepositoryInterface")
          < ti_render.index(TARGET_INTERFACES_SETUP)
          < ti_render.index("- Canonical\\Model\\CanonicalStoreInterface")
          < ti_render.index("Repository file to place code under"))
    check("everything but the block is the base rendering",
          ti_render.replace(target_interfaces_block(CANONICAL_TASK, ti) + "\n", "")
          == base_render, repr(ti_render[-300:]))
    empty_task = dict(CANONICAL_TASK,
                      target_interfaces={"behaviour": [], "setup": []})
    empty_render = build_user_prompt(empty_task, ti)
    check("empty lists render their labels with the fixed sentence, under "
          "the heading, not an absent section",
          TARGET_INTERFACES_HEADING in empty_render
          and f"{TARGET_INTERFACES_BEHAVIOUR} {TARGET_INTERFACES_NONE}" in empty_render
          and f"{TARGET_INTERFACES_SETUP} {TARGET_INTERFACES_NONE}" in empty_render)
    li = lambda b, s: dict(CANONICAL_TASK, target_interfaces={"behaviour": b, "setup": s})
    for label, bad in (("no field at all", {k: v for k, v in CANONICAL_TASK.items()
                                             if k != "target_interfaces"}),
                       ("an unsorted list", li(["Z\\B", "A\\C"], [])),
                       ("a duplicated list", li(["A\\C", "A\\C"], [])),
                       ("a flat list instead of the two", dict(
                           CANONICAL_TASK, target_interfaces=["A\\C"])),
                       ("a missing key", dict(CANONICAL_TASK,
                                              target_interfaces={"behaviour": []})),
                       ("a type in both lists", li(["A\\C"], ["A\\C"]))):
        try:
            build_user_prompt(bad, ti)
            check(f"a disclosing profile refuses an item with {label}", False)
        except ProfileError as e:
            check(f"a disclosing profile refuses an item with {label}",
                  "REFUSED" in str(e))
    check("the base profile ignores the field entirely",
          build_user_prompt({k: v for k, v in CANONICAL_TASK.items()
                             if k != "target_interfaces"}, coreshop) == base_render)

    # THE CHECKED-INTERFACES BLOCK (TARGET_INTERFACES_V2_SPEC section 5a).
    #
    # The v2 field is a SECOND key on the canonical fixture, under a SECOND
    # disclosure flag.  Everything below is about the one property that makes
    # that safe: no profile written before the key existed renders it, so no
    # digest of theirs moved -- asserted above against the literal pins, and
    # here against the two profiles that carry a disclosure at all.
    import dataclasses as _dc
    check("neither the base profile nor the v1 disclosing twin renders the "
          "v2 heading over a canonical task that now carries the field",
          CHECKED_INTERFACES_HEADING not in base_render
          and CHECKED_INTERFACES_HEADING not in ti_render
          and "getExample" not in base_render and "getExample" not in ti_render)
    ci = load_profile(os.path.join(
        CONFIG_DIR, "profile_coreshop_checked_interfaces_full.yml"))
    ci_render = build_user_prompt(CANONICAL_TASK, ci)
    undisclosed = _dc.replace(ci, disclose_checked_interfaces=False)
    check("the v2 profile renders the heading, then each declaring type, then "
          "its declarations, in the stored order, before the placement line",
          ci_render.index(CHECKED_INTERFACES_HEADING)
          < ci_render.index("  Canonical\\Model\\ExampleInterface")
          < ci_render.index("    - public function getExample(): string;")
          < ci_render.index("  canonical.example.Thing")
          < ci_render.index("    - (property getter)")
          < ci_render.index("Repository file to place code under"))
    check("everything but the block is what the same profile renders with "
          "the disclosure off",
          ci_render.replace(checked_interfaces_block(CANONICAL_TASK, ci) + "\n", "")
          == build_user_prompt(CANONICAL_TASK, undisclosed),
          repr(ci_render[-300:]))
    both = build_user_prompt(CANONICAL_TASK,
                             _dc.replace(ci, disclose_target_interfaces=True))
    v1_block = target_interfaces_block(CANONICAL_TASK, ci)
    v2_block = checked_interfaces_block(CANONICAL_TASK, ci)
    check("a profile that discloses BOTH renders both blocks, v1 first, and "
          "nothing else -- that is legal, not a refusal",
          both.index(v1_block) < both.index(v2_block)
          and both.replace(v1_block + "\n", "").replace(v2_block + "\n", "")
          == build_user_prompt(CANONICAL_TASK, undisclosed),
          repr(both[-400:]))
    empty_v2 = dict(CANONICAL_TASK, checked_interfaces={
        "checked": [], "empty_reason": "no_action_or_check_call"})
    check("an empty list renders the fixed sentence WITH its reason, under "
          "the heading, not an absent section",
          f"{CHECKED_INTERFACES_NONE} (no_action_or_check_call)"
          in build_user_prompt(empty_v2, ci))
    ok_entry = {"key": ["A\\C", "m"], "declaration": "public function m();"}
    ci2 = lambda checked, reason=None: dict(
        CANONICAL_TASK, checked_interfaces={"checked": checked,
                                            "empty_reason": reason})
    for label, bad in (
            ("no field at all", {k: v for k, v in CANONICAL_TASK.items()
                                 if k != "checked_interfaces"}),
            ("the v1 shape", dict(CANONICAL_TASK, checked_interfaces={
                "behaviour": [], "setup": []})),
            ("a bare list", dict(CANONICAL_TASK, checked_interfaces=[ok_entry])),
            ("a missing key", dict(CANONICAL_TASK,
                                   checked_interfaces={"checked": []})),
            ("a bare string entry", ci2(["A\\C.m"])),
            ("an entry with no declaration", ci2([{"key": ["A\\C", "m"]}])),
            ("a non-string key component", ci2([
                {"key": ["A\\C", 3], "declaration": "d"}])),
            ("unsorted entries", ci2([
                {"key": ["Z\\B", "m"], "declaration": "d"}, ok_entry])),
            ("duplicated entries", ci2([ok_entry, dict(ok_entry)])),
            ("an empty list with no reason", ci2([])),
            ("a reason beside a populated list",
             ci2([ok_entry], "no_action_or_check_call")),
            ("an unknown reason", ci2([], "looked_empty_to_me"))):
        try:
            build_user_prompt(bad, ci)
            check(f"a v2 disclosing profile refuses an item with {label}", False)
        except ProfileError as e:
            check(f"a v2 disclosing profile refuses an item with {label}",
                  "REFUSED" in str(e))
    check("a profile that discloses neither ignores both fields entirely",
          build_user_prompt({k: v for k, v in CANONICAL_TASK.items()
                             if k not in ANNOTATION_BLOCKS}, coreshop)
          == base_render)

    sys_prompt = system_prompt(coreshop)
    check("the system prompt is still the facts plus the return contract",
          sys_prompt == environment_facts(coreshop) + "\n"
          + return_contract(coreshop))
    # The single-shot path has no disk to write to, so its prompt MUST end with
    # the schema line; that is the whole of how its answer gets back.
    check("the single-shot path still carries the JSON return contract",
          sys_prompt.rstrip().endswith(
              '"metadata": {"notes": "..."}}'), sys_prompt[-60:])

    # ... and the agent path must NOT. The agent's answer is the workspace
    # diff, which the prompt says a few lines earlier ("How your work is
    # collected"). Ending the same prompt with "Return ONLY a JSON object"
    # contradicted that, and an agent that obeys the last instruction it was
    # given writes nothing to disk and scores `no_files_returned` — a
    # generation failure recorded against a model that did as it was told.
    agent_prompts = (("c1.5", c15), ("c2", c2), ("c3", c3),
                     ("c3 --trials 5", c3k), ("c2r", c2r))
    for cond, text in agent_prompts:
        leaked = [w for w in ("json object", "return only") if w in text]
        check(f"{cond} does not ask the agent to return its files in chat",
              not leaked, str(leaked))

    # THE invariant: one prompt for every general-purpose agent, and the
    # conditions differ only in what the agent can see and what it can do.
    # C1.5 -> C2 isolates repository access and C2 -> C3 isolates execution
    # feedback; neither isolates anything if the surrounding prose also moves.
    def skeleton(text: str, prof=coreshop) -> str:
        clauses = [repo_clause(c, prof) for c in AGENT_CONDITIONS] + [
            trial_clause("c1.5", prof),
            trial_clause("c3", prof, 5).format(client="trial.py", k=5),
            trial_clause("c3", prof, UNBOUNDED).format(client="trial.py")]
        if "c2r" in prof.prompt_digest:
            clauses.append(trial_clause("c2r", prof))
        for clause in sorted(set(clauses), key=len, reverse=True):
            text = text.replace(clause.lower(), "<CLAUSE>")
        return text

    check("C1.5, C2 and C3 are the same prompt apart from the two clauses",
          skeleton(c15) == skeleton(c2) == skeleton(c3) == skeleton(c3k),
          f"c15!=c2: {skeleton(c15) != skeleton(c2)}, "
          f"c2!=c3: {skeleton(c2) != skeleton(c3)}, "
          f"c3!=c3k: {skeleton(c3) != skeleton(c3k)}")
    check("the prompts really are different once the clauses are in",
          len({c15, c2, c3, c3k}) == 4)
    # C2 -> C2R isolates a runnable workspace: on one profile, the trial
    # clause is the only difference.
    check("C2R is its profile's C2 prompt apart from the trial clause",
          skeleton(c2r, coreshop_exec) == skeleton(c2x, coreshop_exec)
          and c2r != c2x)
    check("C2R says the scenario can be run and names no trial client",
          "the scenario can be run from this workspace." in c2r
          and "cannot be run" not in c2r and "trial.py" not in c2r)
    for label, prof in (("a profile that freezes no c2r prompt", coreshop),
                        ("a c2r profile without a target-hidden view",
                         _dc_replace(coreshop_exec, source_visibility="full"))):
        try:
            canonical_prompt(prof, "c2r")
            check(f"c2r is refused for {label}", False)
        except ProfileError as e:
            check(f"c2r is refused for {label}", "REFUSED" in str(e))
    # Read off explicit copies, not off CoreShop's file, so the rendering is
    # checked apart from the sentence any one variant carries (below).
    entry = "`run-scenario <feature>:<line>` runs that Scenario."
    check("a profile's entry-point sentence follows the runnable clause, "
          "after one space, and a profile without one renders the clause alone",
          trial_clause("c2r", _dc_replace(
              coreshop_exec, trial_clause_runnable_entry=entry))
          == RUNNABLE_CLAUSE + " " + entry
          and trial_clause("c2r", _dc_replace(
              coreshop_exec, trial_clause_runnable_entry=None))
          == RUNNABLE_CLAUSE)

    # Affordances, stated truthfully.
    check("only C3 says the scenario can be run",
          "you can run the scenario" in c3 and "you can run the scenario" in c3k
          and "cannot be run" in c2 and "cannot be run" in c15)
    check("only C3 names a trial client",
          "trial.py" in c3 and "trial.py" in c3k
          and "trial.py" not in c2 and "trial.py" not in c15)
    check("only C1.5 says the repository is empty",
          "`./repo` is empty" in c15
          and "the repository is in `./repo`" in c2
          and "the repository is in `./repo`" in c3)

    # THE COUNT, and its absence.
    #
    # An execution is a terminal tool call and already costs the agent an
    # iteration, so `--max-iterations` bounds executions natively and the
    # separate counter is gone. What is left of it is the SENTENCE, and the
    # sentence is the part that could still bias the measurement: "You may do
    # this 20 times" tells an agent its executions are scarce, and an agent
    # that believes they are scarce hoards them and goes on exploring -- which
    # is the exploration-paralysis this benchmark is trying to observe rather
    # than a thing it may cause (97 of 100 agents in the last sweep submitted
    # nothing at all). So the unbounded prompt must carry NO count anywhere,
    # not merely no `{k}` in the clause.
    import re as _re
    trial_sentences = [s for s in _re.split(r"(?<=\.)\s+", c3)
                       if "trial.py" in s or "run the scenario" in s]
    check("the unbounded C3 prompt states the affordance",
          any("you can run the scenario" in s for s in trial_sentences)
          and "as often as you want" in c3, str(trial_sentences))
    check("...and states no number of runs, in any form",
          not _re.search(r"\b\d+\s+(times|runs|executions|attempts)\b", c3)
          and not _re.search(r"\byou may do this\s+\d", c3)
          and "unlimited" not in c3, str(trial_sentences))
    # Falsifiable: the BOUNDED form does still name its cap, so the check
    # above is reading the sentence rather than a prompt that never had one.
    check("the bounded C3 prompt still renders the count",
          "you may do this 5 times." in c3k
          and bool(_re.search(r"\b\d+\s+times\b", c3k)))
    # And the difference between the two is EXACTLY the count -- one clause,
    # one sentence, nothing else moved with it.
    check("bounded and unbounded C3 differ only in that one sentence",
          c3.replace("you may do this as often as you want.", "<COUNT>")
          == c3k.replace("you may do this 5 times.", "<COUNT>"))

    # No strategy coaching in any of them: an earlier version told the agent
    # to "write a first version immediately" and "do NOT explore first", which
    # measured the prompt instead of the agent.
    #
    # The unbounded clause is where this rule is easiest to break by accident:
    # having removed the cap, the tempting next sentence is "so run it early
    # and often", which is advice about HOW to work and would make the arm a
    # measurement of the prompt again.
    coaching = ("spend them like this", "do not explore", "work in a loop",
                "scores zero", "immediately", "in seconds", "your best attempt",
                "stop when", "do not read anything else", "early and often",
                "as soon as", "before you", "each time you")
    for cond, text in agent_prompts:
        found = [w for w in coaching if w in text]
        check(f"{cond} tells the agent WHAT, not HOW", not found, str(found))

    # A prompt must not assert a path the seed lacks.
    for cond, text in agent_prompts:
        check(f"{cond} does not assert a directory the seed lacks",
              "create whatever path you need" in text)

    # -- THE SECOND PROFILE, which is the whole point of the parameterisation.
    #
    # "The benchmark extends to other repos, languages and frameworks" was an
    # untested claim as long as the only way to test it was to write a second
    # project.  A profile with no repository behind it tests the half that is
    # actually in doubt: whether the renderer can produce a prompt for a
    # framework whose assumptions CoreShop's prose contradicts.  behave is the
    # sharpest case available -- no service container at all, so the DI channel
    # is not merely absent from the file, it must not be rendered.
    behave = load_profile(os.path.join(CONFIG_DIR,
                                       "profile_behave_example.yml"))
    behave_prompts = {k: canonical_prompt(behave, k) for k in PROMPT_KEYS}
    # Every noun that would betray a prompt written for the wrong project.
    # `behat` is in the list next to `behave` on purpose: they differ by two
    # letters and neither is a substring of the other, so a rendering that
    # leaked one into the other would be invisible to a reader.
    foreign = ("coreshop", "behat", "php", "symfony", "pimcore", "docblock",
               "webmozart", "autowir", "testbundle", "services:",
               "behat_services.yml", "sharedstorage", "@transform",
               "src/coreshop")
    for key, text in behave_prompts.items():
        low = text.lower()
        found = [w for w in foreign if w in low]
        check(f"the behave profile's {key} prompt has no CoreShop/PHP noun",
              not found, str(found))
    # ... and it is not clean because it is empty.  A renderer that dropped
    # everything it could not interpolate would pass the check above and be
    # worthless, so the parts that must survive are named.
    for key in ("c1.5", "c2", "c3"):
        low = behave_prompts[key].lower()
        check(f"the behave {key} prompt still states the task",
              "all behave test code has been removed" in low
              and "write the python step-definition code" in low
              and "makes one scenario run and pass" in low)
        check(f"the behave {key} prompt still states the collection contract",
              "how your work is collected" in low
              and "`repo/features/steps/`" in low
              and "production code is never accepted" in low)
        check(f"the behave {key} prompt still carries the framework facts",
              "facts about the environment you cannot see" in low
              and "@given" in low and "use_step_matcher" in low
              and "register_type" in low and "environment.py" in low
              and "context` object" in low and "plain `assert`" in low)
        # The DI bullet, specifically: the collection contract has exactly two
        # bullets rather than three, and no third one offering a wiring file.
        contract = behave_prompts[key].split("How your work is collected:\n")[1]
        contract = contract.split("\n\n")[0]
        check(f"the behave {key} prompt offers no wiring channel",
              len(contract.strip().split("\n")) == 2
              and "is read as" not in contract, repr(contract[:200]))
    check("the behave single-shot contract shows a python file, not a PHP one",
          '"file_path": "features/steps/cart_steps.py"'
          in behave_prompts["single_shot"]
          and "<?php" not in behave_prompts["single_shot"])
    # CoreShop, by contrast, must STILL offer it -- the check above has to be
    # falsifiable, and a renderer that dropped the bullet for everyone would
    # pass it while silently breaking the shipped prompt.
    check("CoreShop still offers its wiring channel",
          "`repo/behat_services.yml` is read as a symfony `services:` block"
          in c2)

    # -- THE ROW THE DRIVER IS HANDED says what the PROMPT says.
    #
    # `openhands_driver.forced_write_message` repeats the placement instead of
    # choosing one, and it can only stay a repetition if both readings come
    # off the same field.  The nudge used to carry
    # `repo/src/CoreShop/Behat/Context/Domain/<Name>Context.php` as a literal,
    # which on Sylius is outside the acceptance root and on Kapua is another
    # language's tree.
    for prof, rendered in ((coreshop, c2), (behave, behave_prompts["c2"])):
        row = placement_row(prof)
        stated = build_user_prompt(task, prof)
        check(f"the {prof.project} placement row is the place the prompt "
              f"states, under the repo directory the workspace has",
              row["path"] == f"{prof.repo_dir}/{prof.placement_hint}"
              and f"place code under: {prof.placement_hint} (item" in stated
              and row["artefact_noun"] == prof.artefact_noun,
              repr(row))
        check(f"...and it names a wiring file exactly where the collection "
              f"contract offers one ({prof.project})",
              (row["wiring_file"] is not None)
              == (prof.wiring_channel is not None)
              and (row["wiring_file"] is None
                   or (row["wiring_file"]
                       == f"{prof.repo_dir}/{prof.wiring_channel.name}"
                       and f"a file `{row['wiring_file']}` is read as"
                       in rendered)),
              repr(row["wiring_file"]))
    # Kapua resolves its submission package PER ITEM, and the row travels per
    # item for that reason: a static row would nudge every suite into the
    # account runner's package, which does not compile in the others.
    from .profile import profile_for_item
    from ..java.kapua import FEATURE_SUITES
    kapua = load_profile(os.path.join(CONFIG_DIR, "profile_kapua.yml"))
    translator = next(path for path in FEATURE_SUITES
                      if path.startswith("translator/test/"))
    per_item = placement_row(profile_for_item(kapua,
                                              {"feature_file": translator}))
    check("Kapua's placement row follows the selected suite rather than the "
          "profile's account-runner fallback",
          per_item["path"].startswith("repo/translator/test/src/test/java/")
          and per_item["path"] != placement_row(kapua)["path"]
          and per_item["wiring_file"] is None,
          repr(per_item))
    # -- ...AND THE HARVEST'S OWN FILTER, for every project this repository
    # ships.  The openhands driver decided "the agent has written something"
    # by looking for `.php` or `behat_services.yml`; the harvest decides it
    # with these two fields.  The row is where the driver gets them, so what
    # this asserts is that it gets the harvest's pair and not a copy that can
    # age: `harvest_suffixes()`/`extra_names` are read here through the same
    # accessors `agents.adapter` calls `final_harvest` with.
    import glob as _glob
    import json as _json
    shipped = sorted(_glob.glob(os.path.join(CONFIG_DIR, "profile_*.yml")))
    check("the loop below is not vacuous: every `profile_*.yml` in the "
          "config directory, 22 of them at this commit",
          len(shipped) >= 22, str(len(shipped)))
    for path in shipped:
        prof = load_profile(path)
        row = placement_row(prof)
        check(f"{os.path.basename(path)}: the row hands over the filter the "
              f"HARVEST uses, not a project-shaped guess",
              row.get("suffixes") == list(prof.harvest_suffixes())
              and row.get("extra_names") == list(prof.extra_names)
              and row.get("suffixes")
              == _json.loads(_json.dumps(row)).get("suffixes"),
              _json.dumps({k: row.get(k) for k in
                           ("suffixes", "extra_names")}))
    # -- THE GUIDANCE BLOCK, over every shipped profile.
    #
    # BEFORE is each file's frozen `prompt_digest`, written by the renderer
    # as it was when the profile was minted; AFTER is this renderer.  Loaded
    # unverified so that the comparison is this check rather than a side
    # effect of loading.  Then the property an intervention profile relies
    # on: in every agent condition, at both C3 budgets and for both task
    # kinds, the profile's prompt -- and that of a copy carrying another
    # block -- is its block-free prompt followed by `guidance_block`, which
    # is "" for a profile without one, and the single-shot system message
    # does not move.  The probe text ends in two newlines on purpose: the
    # block normalises YAML's chomping to one.
    import dataclasses as _gdc
    from .profile import Guidance
    probe = Guidance(id="selftest_probe", heading="Before you finish",
                     text="Review the step definitions you wrote.\n\n")

    def conditions(prof, trials, row):
        # Every agent condition the profile freezes: all of them but `c2r`,
        # which only the execution-enabled variants render.
        return {k: agent_prompt_for(k, profile=prof, trials=trials,
                                    client=CANONICAL_CLIENT).format(
            task=build_user_prompt(row, prof),
            instructions=environment_facts(prof))
            for k in AGENT_CONDITIONS if k in prof.prompt_digest}

    for path in shipped:
        prof = load_profile(path, verify_digests=False)
        bare = _gdc.replace(prof, guidance=None)
        variant = _gdc.replace(prof, guidance=probe)
        now = prompt_digests(prof)
        suffix, spacing = True, True
        # The Go item-path stack admits criterion items only.
        kinds = (("criterion_to_test",) if prof.acceptance_mode == "item_path"
                 else ("criterion_to_test", "requirement_to_test"))
        for trials in (UNBOUNDED, CANONICAL_TRIALS):
            for kind in kinds:
                row = dict(canonical_task(prof), task=kind)
                parent = conditions(bare, trials, row)
                for p in (prof, variant):
                    rendered = conditions(p, trials, row)
                    suffix = suffix and all(
                        rendered[k] == parent[k] + guidance_block(p)
                        for k in parent)
                spacing = spacing and all(
                    parent[k].endswith("\n\n")
                    and not parent[k].endswith("\n\n\n")
                    for k in parent)
        moved = prompt_digests(variant)
        check(f"{os.path.basename(path)}: renders its frozen digests; "
              f"every agent prompt is its block-free prompt plus its guidance "
              f"block (or another) after one blank line, and single-shot is "
              f"unchanged",
              now == prof.prompt_digest
              and set(PROMPT_KEYS) <= set(now)
              and suffix and spacing
              and system_prompt(variant) == system_prompt(bare)
              == system_prompt(prof)
              and moved["single_shot"] == now["single_shot"]
              and all(moved[k] != now[k] for k in now if k != "single_shot"),
              f"frozen={now == prof.prompt_digest} suffix={suffix} "
              f"spacing={spacing}")
    check("the block is its heading, a blank line and its text, which ends "
          "in exactly one newline",
          guidance_block(_gdc.replace(coreshop, guidance=probe))
          == "Before you finish:\n\nReview the step definitions you wrote.\n")

    # -- THE EXECUTION-ENABLED VARIANTS (EXECUTION_ENABLED_TH_SENSITIVITY_SPEC.md
    # sections 4.1 and 4.2), held to their target-hidden parents the way the
    # probe profiles are (`agents.protocol`): the same document apart from one
    # sentence of the visibility fact, the entry-point sentence where the
    # project's own tools cannot run one Scenario of the view, and the
    # digests; and a c2r prompt that is the parent's c2 prompt with exactly
    # the two replaced sentences, plus the entry-point sentence after the
    # first of them.  The header comment is the only other byte that differs,
    # and YAML drops it.  The sentences are literals here, so that an edit of
    # the renderer or of a profile cannot also move what they are held to.
    replaced = {
        "e-petitions": ("It is not a promised application runtime.",
                        "It is a provisioned application runtime for the code "
                        "in `./repo`.")}
    seven = ("It is not a provisioned application runtime; nothing here is "
             "executed by the harness.",
             "It is a provisioned application runtime for the code in "
             "`./repo`; nothing here is executed by the harness.")
    blind = "The scenario cannot be run from this workspace."
    runnable = "The scenario can be run from this workspace."
    behat_entry = ("`behat-scenario <feature file>:<line>` runs one Scenario "
                   "in this workspace.")
    behat = ("coreshop", "sylius", "prestashop")
    exec_paths = sorted(_glob.glob(os.path.join(
        CONFIG_DIR, "profile_*_checked_interfaces_target_hidden_exec.yml")))
    check("each of the eight projects ships one execution-enabled variant",
          len(exec_paths) == 8
          and len({load_profile(p).project for p in exec_paths}) == 8,
          str([os.path.basename(p) for p in exec_paths]))

    def sans(raw, *keys):
        return {k: v for k, v in raw.items() if k not in keys}

    for path in exec_paths:
        child = load_profile(path)
        parent = load_profile(path.replace("_exec.yml", ".yml"))
        old, new = replaced.get(child.project, seven)
        clause = runnable + (" " + behat_entry if child.project in behat else "")
        child_raw = dict(child.raw, trial=sans(child.raw["trial"],
                                               "clause_runnable_entry"))
        moved_facts = [i for i, (a, b) in enumerate(zip(parent.facts, child.facts))
                       if a != b]
        with open(path, encoding="utf-8") as fh:
            header = fh.read().split("\n", 2)[:2]
        parent_c2 = canonical_prompt(parent, "c2")
        check(f"{os.path.basename(path)} is its parent with one sentence of "
              f"the visibility fact replaced, its entry-point sentence if any, "
              f"and every digest re-frozen",
              sans(child_raw, "facts", "prompt_digest")
              == sans(parent.raw, "facts", "prompt_digest")
              and len(child.facts) == len(parent.facts)
              and len(moved_facts) == 1
              and parent.facts[moved_facts[0]].count(old) == 1
              and parent.facts[moved_facts[0]].replace(old, new)
              == child.facts[moved_facts[0]]
              and set(child.prompt_digest) == set(parent.prompt_digest) | {"c2r"}
              and all(child.prompt_digest[k] != parent.prompt_digest[k]
                      for k in parent.prompt_digest)
              and "EXECUTION_ENABLED_TH_SENSITIVITY_SPEC.md" in header[0],
              f"moved facts {moved_facts}")
        check(f"{os.path.basename(path)}: the c2r prompt is the parent's c2 "
              f"prompt with only the trial clause and that sentence replaced"
              + (", and the entry-point sentence after the clause"
                 if child.project in behat else ""),
              parent_c2.count(blind) == 1 and parent_c2.count(old) == 1
              and canonical_prompt(child, "c2r")
              == parent_c2.replace(blind, clause).replace(old, new))
    # Section 4.2: Behat's suite configuration and context registration are
    # removed test code, so only the three Behat projects need a command of
    # their own; the other five run one Scenario with their own tools.
    entries = {p.project: p.raw["trial"].get("clause_runnable_entry")
               for p in map(load_profile, exec_paths)}
    check("CoreShop, Sylius and PrestaShop carry the one entry-point "
          "sentence, and Algorand SDK, Kapua, python-docx, coddy-agent and "
          "e-petitions carry none",
          entries == {**dict.fromkeys(behat, behat_entry),
                      "algorand-sdk": None, "kapua": None, "python-docx": None,
                      "coddy-agent": None, "e-petitions": None}, str(entries))

    # Falsifiable, and the reason the loop above is not vacuous: the projects
    # really do disagree, so a row filled from ONE profile is wrong for the
    # others -- which is what the literal was.
    docx = load_profile(os.path.join(CONFIG_DIR, "profile_python_docx.yml"))
    kapua_row = placement_row(load_profile(
        os.path.join(CONFIG_DIR, "profile_kapua.yml")))
    check("the filters are per-project: CoreShop's is the `.php` pair the "
          "driver used to hard-code, Kapua's is Java's and python-docx's is "
          "Python's, and neither of those would see a `.php` file",
          placement_row(coreshop).get("suffixes") == [".php", ".feature"]
          and placement_row(coreshop).get("extra_names")
          == ["behat_services.yml"]
          and kapua_row.get("suffixes") == [".java", ".feature"]
          and placement_row(docx).get("suffixes") == [".py", ".feature"]
          and not any(sfx == ".php" for row in (kapua_row, placement_row(docx))
                      for sfx in row.get("suffixes") or ()),
          _json.dumps([placement_row(coreshop).get("suffixes"),
                       kapua_row.get("suffixes"),
                       placement_row(docx).get("suffixes")]))
    check("the two profiles disagree about every prompt they render",
          not (set(behave.prompt_digest.values())
               & set(coreshop.prompt_digest.values())))
    # The second profile is frozen the same way, and its three non-C3 prompts
    # must not have moved either: the parameterisation is only a no-op if it
    # is a no-op for both projects.
    behave_rendered = prompt_digests(behave)
    behave_bounded = prompt_digests(behave, CANONICAL_TRIALS)
    for key in ("single_shot", "c1.5", "c2"):
        want = _FROZEN_BEFORE_UNBOUNDED["behave_example"][key]
        check(f"the behave {key} prompt did not move either",
              behave_rendered[key] == want and behave_bounded[key] == want,
              f"{behave_rendered[key]} != {want}")
    check("the behave BOUNDED c3 is still its historical rendering",
          behave_bounded["c3"]
          == _FROZEN_BEFORE_UNBOUNDED["behave_example"]["c3_bounded"]
          and behave_rendered["c3"] == behave.prompt_digest["c3"]
          and behave_rendered["c3"] != behave_bounded["c3"],
          f"{behave_bounded['c3']} / {behave_rendered['c3']}")
    # ... and the clause the second project renders is unbounded in the same
    # way, from its own words: no count, and the framework's own runner noun.
    behave_c3 = canonical_prompt(behave, "c3")
    check("the behave unbounded clause names behave and no number",
          "prints behave's per-step results" in behave_c3
          and "as often as you want" in behave_c3
          and not _re.search(r"\b\d+\s+times\b", behave_c3))

    print("\n" + ("ALL PASS (prompt)" if ok else "FAILURES (prompt)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
