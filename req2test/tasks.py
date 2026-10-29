"""`req2test tasks`: the task file a user's agent answers.

One JSON row per instance of a split and project, for the target-hidden (TH)
view:

* `requirement`: the Feature (title, narrative, Background) and the Scenario
  text, from the dataset row;
* `target_interfaces`: the paper's checked interfaces I^tar (empty with a
  reason when the scenario calls no production method directly);
* `placement`: where answers are accepted and what counts as one (the
  view profile's `submission` block resolved for the instance, through
  `r2t.data.prompt.placement_row`), with the collection `rules`;
* `environment`: what the agent cannot see in its workspace: the project,
  language and framework, what the view removed and retained, how to run a
  scenario there, and the profile's environment `facts`;
* `task`: the engine's task view of the item (`r2t.data.release.task_view`),
  which for coddy-agent holds the exact answer `files` and the Godog
  `go_suite` they define;
* `source_view`: the command that writes the agent-facing source tree of this
  instance and view (`req2test views materialize`); `./repo` in the rows is
  that tree;
* `benchmark_version`: the benchmark the row belongs to, "1.1"; a
  predictions row may repeat it;
* `runtime_setup`: the command that applies the project's runtime pack to the
  workspace before the agent starts (`req2test runtime setup`); the workspace
  is the directory that holds the view as `repo/`, the parent of
  `source_view`'s `DIR`.

A row holds the task, not a prompt: the agent's prompt is the agent's.  The
prompt the leaderboard's agents were given is built from these fields by
`req2test.inference.prompt`.

The profiles are the eight
`config/profile_<project>_checked_interfaces_target_hidden_exec.yml` profiles
of this clone's engine, each the kit's TH profile with the sentences about a
workspace without a runtime replaced.  Evaluation reads the kit's own files.

The engine item rows come from the kit's execution release.  Each instance's
profile is
resolved with `r2t.data.profile.profile_for_item`, as the study's agent
adapter resolved it: for Kapua the answer package is the generated-glue
package of the test module that runs the instance's feature (13 packages);
every other project keeps the view profile unchanged.
`--split full` is refused outside `layout.FULL_SPLIT_PROJECTS` (python-docx):
elsewhere the kit or the views lack part of the full population, and the
full split is data only.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import ENGINE_ROOT
from .execute import ensure_engine_path
from .layout import check_split, iter_jsonl, kit_inputs, load_kit
from .predictions import BENCHMARK_VERSIONS

DEFAULT_VERSION = "1.1"


def view_profile(kin, view: str, version: str = DEFAULT_VERSION) -> Path:
    """The `_exec` profile the tasks of `view` are read from."""
    if version not in BENCHMARK_VERSIONS:
        raise ValueError(f"unknown benchmark version {version!r}; expected "
                         f"one of {', '.join(BENCHMARK_VERSIONS)}")
    if view != "th":
        raise ValueError(f"benchmark {version} offers the th view only, "
                         f"not {view!r}")
    blind = Path(kin.view_profile("th"))
    return ENGINE_ROOT / "config" / f"{blind.stem}_exec.yml"


def collection_rules(profile) -> list:
    """The profile's collection rules, one per bullet, as the engine's
    prompt base states them (`r2t.data.prompt.agent_prompt_base`)."""
    from r2t.data.prompt import agent_prompt_base
    block = agent_prompt_base(profile).split("How your work is collected:\n", 1)[1]
    return [line[2:] for line in block.split("\n\n", 1)[0].splitlines()]


def environment(profile) -> dict:
    """What the agent cannot see in its workspace, from the profile."""
    return {"project": profile.project_label,
            "platform": profile.platform_blurb,
            "language": profile.language_label,
            "framework": profile.runner_noun,
            "removed": profile.removed_noun,
            "retained": profile.retained_substrate,
            "run": profile.trial_clause_runnable_entry,
            "facts": list(profile.bullets())}


def task_row(project: str, view: str, version: str, inst: dict,
             task: dict, profile) -> dict:
    """The row of dataset instance `inst`, from its engine task view and
    its resolved profile."""
    from r2t.data.prompt import placement_row
    iid = inst["instance_id"]
    placement = placement_row(profile)
    placement.update({"acceptance_mode": profile.acceptance_mode,
                      "acceptance_root": profile.acceptance_root,
                      "placement_hint": profile.placement_hint,
                      "rules": collection_rules(profile)})
    return {
        "instance_id": iid, "project": project, "view": view,
        "benchmark_version": version,
        "requirement": {"feature": inst["feature"],
                        "scenario": inst["scenario"]},
        "target_interfaces": inst.get("target_interfaces") or [],
        "target_interfaces_empty_reason":
            inst.get("target_interfaces_empty_reason"),
        "placement": placement,
        "environment": environment(profile),
        "task": task,
        "source_view": (f"req2test views materialize --project {project} "
                        f"--view {view} --instance {iid} --out DIR"),
        "runtime_setup": (f"req2test runtime setup --project {project} "
                          f"--instance {iid} --workspace WORKSPACE"),
    }


def task_rows(project: str, view: str = "th", split: str = "eval",
              version: str = DEFAULT_VERSION) -> list:
    ensure_engine_path()
    from r2t.data.profile import load_profile, profile_for_item
    from r2t.data.release import task_view
    from . import dataset
    from .layout import data_dir

    # `--split full` where the kit cannot execute all of it: data only.
    check_split(project, split)
    instances = list(dataset.iter_instances(split, project,
                                            data_dir=data_dir()))
    kit = load_kit(project)
    kin = kit_inputs(kit)
    items = {row["item_id"]: row for row in iter_jsonl(kin.release_items)}
    prof = load_profile(str(view_profile(kin, view, version)))
    rows = []
    for inst in instances:
        item = items.get(inst["instance_id"])
        if item is None:
            raise ValueError(f"kit {project} {kit.version} has no engine "
                             f"item for {inst['instance_id']}")
        task = task_view(item)
        # Kapua's answer package is the test module that runs this
        # instance's feature; every other project keeps `prof` itself.
        rows.append(task_row(project, view, version, inst, task,
                             profile_for_item(prof, task)))
    return rows


def export(project: str, view: str, out: str, split: str = "eval",
           version: str = DEFAULT_VERSION) -> int:
    rows = task_rows(project, view, split, version)
    with open(out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return len(rows)
