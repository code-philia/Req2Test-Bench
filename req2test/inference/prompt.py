"""The prompt of the leaderboard's runs with the runtime packs (its rows
without †), built from a task row.

`build_prompt(row)` reads only the fields of a `req2test tasks` row: the
requirement, its target interfaces and, for coddy-agent, the answer files
from `task` (the engine's task view the agents were given), and the rest
from `placement` and `environment`.  The text is the engine's `c2r` prompt
byte for byte (`r2t.data.prompt.agent_prompt_for("c2r")`), whose sha256
each profile pins as `prompt_digest.c2r`.
"""
from __future__ import annotations

import json

#: How a requirement's checked interfaces are introduced.
INTERFACES_HEADING = (
    "Target interfaces -- the product methods this scenario's actions and "
    "checks call. They are declared in the repository; how to reach them "
    "(setup, fixtures, helpers, test data) is part of the task.")


def build_prompt(row: dict) -> str:
    """The prompt for one task row."""
    env, pl = row["environment"], row["placement"]
    noun = pl["artefact_noun"]
    run = " ".join(s for s in ("The scenario can be run from this workspace.",
                               env["run"]) if s)
    return (
        f"All {env['removed']} has been removed from the {env['project']} "
        f"repository. Write the {env['language']} {noun} that makes ONE "
        f"scenario run and pass against the unmodified production code.\n"
        "\n"
        f"{_requirement(row)}\n"
        "\n"
        "How your work is collected:\n"
        + "".join(f"* {rule}\n" for rule in pl["rules"])
        + "\n"
        f"The repository is in `./repo`: production code, the other "
        f"`.feature` files, and {env['retained']}.\n"
        "\n"
        f"{run}\n"
        "\n"
        f"You write executable {env['framework']} test code for "
        f"{env['platform']}.\n"
        "\n"
        "All test code has been removed from the repository. Given one "
        f"Gherkin scenario, produce the {env['language']} {noun} that makes "
        "exactly that scenario run and pass against the unmodified "
        "production code.\n"
        "\n"
        "Facts about the environment you cannot see:\n"
        "\n"
        + "".join(f"* {fact}\n" for fact in env["facts"])
        + "\n")


def _requirement(row: dict) -> str:
    """The Feature, the Scenario, its target interfaces and where the
    answer goes."""
    req, task = row["task"]["requirement"], row["task"]
    pl, iid = row["placement"], row["instance_id"]
    parts = [f"Feature: {req.get('feature_title') or ''}"]
    if req.get("narrative"):
        parts.append(req["narrative"])
    if req.get("background"):
        parts.append("\n" + req["background"])
    parts += ["\nThe scenario to implement:\n",
              task["criterion"].get("gherkin") or "",
              f"\nReturn the {pl['artefact_noun']} (and any helper it needs) "
              f"that makes this scenario pass.",
              "\n" + INTERFACES_HEADING + "\n"
              + _interfaces(task["checked_interfaces"])]
    if pl["acceptance_mode"] == "item_path":
        suite = task["go_suite"]
        paths = ", ".join(f"`repo/{path}`" for path in task["files"])
        parts.append(
            f"\nReturn complete Go files at exactly these paths: {paths} "
            f"(item {iid}). "
            "This file list overrides the illustrative return-contract example. "
            "Every listed file is required and no other answer path is accepted.\n"
            f"Primary glue: `{suite['glue_path']}`. "
            f"Package: `{suite['package_name']}` in `{suite['package_dir']}`.\n"
            f"Define `{suite['test_name']}` with a Godog suite and initializer "
            "for this requirement. The harness owns the execution options.\n"
            f"Go build tags: {json.dumps(suite['go_build_tags'])}.\n"
            f"Godog tag expression: {json.dumps(suite['godog_tags'])}.")
    else:
        parts.append(f"\nRepository file to place code under: "
                     f"{pl['placement_hint']} (item {iid}).")
    return "\n".join(parts)


def _interfaces(field: dict) -> str:
    """The target interfaces grouped by declaring type, or "none
    identified" with the recorded reason."""
    entries = field["checked"]
    if not entries:
        return f"none identified ({field['empty_reason']})"
    lines, current = [], None
    for entry in entries:
        if entry["key"][0] != current:
            current = entry["key"][0]
            lines.append(f"  {current}")
        lines.append(f"    - {entry['declaration']}")
    return "\n".join(lines)
