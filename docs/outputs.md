# Run outputs

The measures are defined in [metrics.md](metrics.md).

Every run lives under `$REQ2TEST_HOME/runs/<run-id>/` (default
`~/.req2test/runs/<run-id>/`). Values in the JSON files are fractions
(0 to 1), and `report.md` prints them as percentages.

## Run directory

| Path | Content |
|---|---|
| `summary.json` | The aggregate of every project in the run ([below](#summaryjson)) |
| `report.md` | The same for people ([below](#reportmd)) |
| `validate.json` | Written by `validate`: the installation check's verdict ([below](#validatejson)) |
| `subset.json` | Only in a SUBSET run: the selection (`--sample N` and its seed, or the `--instances` file) and each project's count |
| `split.json` | Only in a FULL-SPLIT run (`--split full`) |
| `<project>/th/instances.jsonl` | The scored instance rows ([below](#instancesjsonl)) |
| `<project>/th/exec.jsonl` | One execution row per instance. It records what the answer-handling rules ([agents.md](agents.md#what-the-harness-does-with-the-answer)) changed: `supplied_helpers`, `relisted_contexts` and `autowired_services` |
| `<project>/th/behaviour.json` | API F1 and coverage J of each instance |
| `<project>/th/mutation/w<k>.jsonl` | One row per mutant run: `instance_id`, `mutant_id`, `outcome` |
| `<project>/th/mutation.baseline.jsonl` | The unmutated baseline run of each passing test |

The other files in a project directory are caches and resume state.
`report` reads only `exec.jsonl`, `behaviour.json`, `mutation/`,
`mutation.done.json` and the installed kits.

## `instances.jsonl`

One row per instance of the project and view, fields in this order:

| Field | Type | Meaning |
|---|---|---|
| `instance_id` | string | The dataset's instance id |
| `project`, `view` | string | The project, and `th` |
| `outcome` | string | The first failing stage, or the pass: `generation_failure`, `compilation_failure`, `binding_failure`, `execution_failure`, `assertion_failure`, `pass`, `infrastructure_excluded` |
| `passed` | bool | `outcome == "pass"` |
| `api_f1` | number or null | API F1 of a pass in the kit's `I_api`, else null |
| `coverage_j` | number or null | Coverage Jaccard of a pass in the kit's `I_cov`, else null |
| `recall` | number or null | `n_killed / n_scored` of a pass with `mutation_status: scored`, else null |
| `kill_complete` | bool | The pass killed every scored pair of G_i (`n_scored > 0` and `n_killed == n_scored`) |
| `kill_complete_strict` | bool | `kill_complete` and no dropped pair |
| `kill_complete_95` | bool | A scored pass with `recall >= 0.95` |
| `mutation_status` | string | `not_run` (`--metrics exec`), `not_passed` (the test did not pass), `unscored` (a pass with no mutation row, for example because its baseline failed), `not_scorable` (every pair dropped, or an empty G_i) or `scored` |
| `mutation_baseline` | string or null | For a pass when mutation ran: the class of its unmutated baseline, `passed`, `failed` or `infrastructure` |
| `behaviour_status` | string | `measured`, or `not_run` when the run has no `behaviour.json` |
| `n_gt_kills` | int | \|G_i\|: the kit's ground-truth kills of the instance, minus its reference exclusions and the nondeterministic mutants ([metrics.md](metrics.md#per-instance-instancesjsonl)) |
| `n_scored` | int | \|G_i\| minus the dropped pairs (0 unless mutation scored the pass) |
| `n_killed`, `n_dropped` | int | Killed and dropped G_i pairs |
| `n_crash_kills` | int | Kills by a mutant-induced Go crash (coddy-agent) |
| `n_timeout_kills` | int | Kills by a candidate timeout (Kapua, PrestaShop, e-petitions) |
| `exclusion` | string or null | For `infrastructure_excluded`: `infrastructure` (the harness failed) or `outside_ladder` (an engine outcome outside the ladder) |
| `engine_outcome` | string or null | The engine's own outcome of the execution row, for example `passed`, `failed` or `no_writable_files` |
| `harness_version` | int or null | The engine harness version of the execution row |
| `rejected_files` | list of object | The prediction files the engine refused to write, as its execution row lists them: `{file_path, why}`, where `why` is for example `path_escape` or `not_test_code:<class>`. A rejected CoreShop or Sylius service definition adds `service_id`. Empty when none was rejected |

## `summary.json`

Schema `req2test.summary/1`:

| Key | Content |
|---|---|
| `schema`, `run_id` | `req2test.summary/1` and the run id |
| `headline` | `leaderboard`, the mode the report leads with |
| `benchmark_version` | The run's benchmark version, `1.1` |
| `population` | `benchmark_version`, `note`, `list` (the population file), `excluded_n` and `excluded` (`{instance_id: reason}`): the instances of the run that were scored and that no measure counts ([evaluation.md](evaluation.md#population)) |
| `modes` | `{"leaderboard": ..., "exact": ...}`, each `{mode, cells, mean}` (below) |
| `disclosures` | Per `"<project>/<view>"`: `infrastructure_excluded` (ids), `outside_ladder_excluded` (`{id: engine outcome}`), `unscored_passes`, `not_scorable_passes`, `baseline_failed`, `baseline_infrastructure` (ids), the counts `dropped_pairs`, `crash_kills`, `timeout_kills`, `kill_complete_with_dropped_pairs`, and `rejected_files` (`{instance_id: [rejected file]}`, the instances' `rejected_files` rows, only those with one) |
| `rules` | Per project, the kit's scoring rules: `family` (`single_observation` or `native`), `candidate_timeout` (`drop` or `kill`), `crash_kill`, `known_host_dependent` (mutant ids), and `nondeterministic_excluded`: the mutant ids of the engine's nondeterministic list that this kit's G_i lost ([metrics.md](metrics.md)) |
| `subset` | Only in a SUBSET run: `note` (the sentence the report prints) and the keys of `subset.json` |
| `full_split` | Only in a FULL-SPLIT run: `note` (the sentence the report prints) and the keys of `split.json` |
| `ci` | Only with `report --ci N`: `method`, `n_boot`, and `exact`: `{view: {metric: [low, high]}}` |

`modes.<mode>.cells["<project>/<view>"]` has `project`, `view`, `n` (instances
in the run), `census_n` (the project's eval instances in the population), `complete`
(`n == census_n`), `excluded`, `passes`, `kill_complete` (a count, null when
mutation was not run), `unscored_passes`, and the measures `pass_at_1`,
`kill_complete_at_1`, `api_f1`, `coverage_j`, `mutation_recall`. `exact` mode
adds `kill_complete_strict_at_1` and `kill_complete_95_at_1`. A measure that
was not run is null, never 0.

`modes.<mode>.mean[view][measure]` is `{value, projects, complete}`: the
equal-weight mean over the projects that have the measure, how many
contribute, and whether it is the 8-project mean (all eight projects present,
complete and contributing). `mean[view].complete` is true when every measure
is. Only a complete mean of a run that is neither SUBSET nor FULL-SPLIT is
comparable with the leaderboard.

## `report.md`

The report prints the run id, a SUBSET or FULL-SPLIT notice when it applies,
and a short reading guide. Then it prints one table per mode, `leaderboard`
first and then `exact`, with one row per project and the mean. A mean that
is not the complete 8-project mean carries its number of projects, for
example "(1 of 8 projects)". With `--ci N` it adds the 95% bootstrap
intervals. It ends with the disclosures per project (excluded instances,
unscored and not-scorable passes, dropped G_i pairs, crash and timeout
kills, rejected prediction files) and the scoring rules, with the
host-dependent mutants ([metrics.md](metrics.md#disclosures)).

## `validate.json`

Written by `req2test validate` (default run id `validate-<project>-<sample>`),
beside the outputs of a SUBSET run:

| Key | Content |
|---|---|
| `project`, `run_id`, `n` | The project, the run id and the sample size |
| `sample_seed`, `instances` | The seed string (`20261004:<project>`) and the sampled instance ids |
| `pass`, `kill_complete` | Counts over the sample |
| `api_f1_scored`, `api_f1_mean`, `api_f1_min` | API F1 over the sampled passes that have one |
| `coverage_j_scored`, `coverage_j_mean`, `coverage_j_min` | Coverage J likewise |
| `pairs` | `g_pairs` (planned G pairs of the passes), `g_pairs_with_rows` (run), `killed`, `survived`, `dropped`, `flip_rate` ((survived + dropped) / run, known host-dependent pairs included), `flips_not_known_host_dependent`, and `survived_by_mutant` / `dropped_by_mutant`: `{mutant_id: {n, instances, outcomes, known_host_dependent}}` |
| `flips_counted` | The flips the rule counts: survived plus dropped G pairs, not counting pairs of `known_host_dependent` mutants |
| `flip_tolerance` | 0.001 |
| `flips_allowed` | An integer: max(1, ⌊`flip_tolerance` × `g_pairs_with_rows`⌋) |
| `checks` | One boolean per condition of the verdict: `ground_truth_passes` (every sampled test passed and its mutation status is `scored` or `not_scorable`), `api_f1_mean_is_1`, `coverage_j_mean_at_least_0.99`, `flips_within_tolerance` (`flips_counted` ≤ `flips_allowed`) |
| `deviations` | One entry per instance with something to report: `{instance_id, level, causes, recall}`. `level` is the most severe of its causes: `deviation` (it breaks a check), `warning` (coverage J below 0.99 while the mean holds, or no scored G pair), `noise` (survived or dropped pairs while the flips are within the allowance), `known` (only pairs of `known_host_dependent` mutants). `causes` are short texts, for example `outcome assertion_failure`, `mutation unscored (mutation baseline failed)`, `1 G pair(s) survived: <mutant id>`, `coverage J 0.9390`. `recall` is the instance's recall or null |
| `ok` | True when every `checks` value is true: the verdict, exit 0. The rule is in [evaluation.md](evaluation.md#validate-an-installation) |
