# Evaluating predictions

Your system writes a predictions file, and `req2test evaluate` executes and
scores it. How to produce the tasks, workspaces and predictions is in
[agents.md](agents.md). The host requirements are in
[environments.md](environments.md#prerequisites).

## Splits

Evaluate the `eval` split (`--split eval`, the default). The `full` split is
data for analysis ([dataset.md](dataset.md#splits)). The one exception is
python-docx, whose kit and views cover all 239 of its `full` instances. Its
`full` split runs with `--metrics exec`, and the run is marked as a
FULL-SPLIT run that is not comparable with the leaderboard. For every other
project, `--split full` is refused.

## Population

Benchmark 1.1's measures count 2,037 of the 2,051 `eval` instances: CoreShop
328 of 334 and Sylius 311 of 319. The 14 instances left out are listed in
`benchmark/config/benchmark_2.0_population.yml`:

- three CoreShop instances whose target has no body to hide (`zero_body`);
- three CoreShop and eight Sylius instances whose ground-truth test already
  passes on the runnable TH view (`census_pass`), so the hidden target is
  not needed to pass them.

Generate and evaluate all 2,051 as usual. The 14 are scored into
`instances.jsonl` and left out of every measure. `summary.json` and
`report.md` name them.

## Predictions

One JSON object per line (`req2test.predictions/1`):

```json
{"instance_id": "python-docx/features/api-open-document.feature:13",
 "model_name_or_path": "my-system", "view": "th",
 "files": [{"path": "features/steps/api.py", "content": "..."}]}
```

- Paths are relative to the view root (the `repo/` directory) and must
  follow the task's `placement` rules
  ([agents.md](agents.md#collecting-the-answer)). A leading `repo/` is
  stripped with a warning.
- The engine writes only test code: the files that the project's
  boundary classifies as removable
  ([agents.md](agents.md#collecting-the-answer)). It rejects any other
  file, a `.feature` file and a path that leaves `repo/`. On coddy-agent
  it takes only the instance's exact `files`: an answer with another
  file, or without one of them, is not run. `evaluate` prints each
  rejected file with the reason, and `report.md` lists them.
- A missing row, an empty `files` list or `"status": "no_output"` is a
  generation failure. The instance is not executed and stays in the
  denominator. An instance whose files are all rejected is a generation
  failure too.

## Evaluate

```sh
req2test evaluate --predictions ~/r2t-work/predictions.jsonl --split eval \
  --project python-docx --run-id my-run
```

- Without `--project`, every project the predictions name is evaluated, one
  after the other.
- `--workers K` sets the worker pool size. The default per project is in
  [environments.md](environments.md#projects).
- `--metrics exec` skips mutation. It measures Pass@1, API F1 and coverage
  only, and reports KillComplete and Mutation R as `–`.
- `--instances FILE` (one instance id per line) or `--sample N [--seed S]`
  evaluates a subset. The run is marked as a SUBSET run, which is not
  comparable with the leaderboard. Use it to try a system cheaply.

For each project, `evaluate` brings up a pool of worker containers and runs
every test once against the full production code with coverage (600 s
timeout). It then computes API F1 and coverage, runs each passing test
against its mutants, and scores the run. The pool is retired at the end.
The rootless Docker daemon keeps running for the next run until
`req2test env stop-daemon`. The metrics are defined in
[metrics.md](metrics.md), and the outputs under
`~/.req2test/runs/<run-id>/` are listed in [outputs.md](outputs.md).

Rerunning the same command resumes the run. Finished instances and mutants
are not run again, and those that ended in an infrastructure error are.
SIGINT or SIGTERM stops a run cleanly. A run id holds one predictions file,
so use a new run id for another.

## Split a run over hosts

Each project can run on a different host. `req2test report` then scores
the merged run directory:

1. On each host, evaluate a different project with the same run id and the
   same predictions file:

   ```sh
   req2test evaluate --predictions preds.jsonl --project kapua --run-id run7        # host A
   req2test evaluate --predictions preds.jsonl --project coddy-agent --run-id run7  # host B
   ```

2. Copy each finished `runs/run7/<project>/` directory, intact, into one
   home's `runs/run7/`:

   ```sh
   mkdir -p ~/.req2test/runs/run7
   rsync -a hostA:.req2test/runs/run7/kapua ~/.req2test/runs/run7/
   rsync -a hostB:.req2test/runs/run7/coddy-agent ~/.req2test/runs/run7/
   ```

3. On that host, run `req2test report --run-id run7`. It writes
   `summary.json` and `report.md` over every project in the directory.

`report` needs no Docker, dataset or views. It needs the clone and the kit
of each project in the run (`req2test fetch --kits-only --project P`). It
refuses a project directory whose mutation stage did not finish, so copy
only finished projects. With fewer than eight projects, the means carry
their number of projects instead of being the 8-project mean.

## Cost

Execution runs each instance once. Mutation runs each passing test once
more unmutated, then once per mutant in its ground-truth kill set G_i.
Σ|G_i| is therefore the number of mutant executions if every test passed.

| Project | Eval instances | Σ\|G_i\| | One execution |
|---|---:|---:|---:|
| python-docx | 237 | 30,044 | 1 s |
| algorand-sdk | 111 | 7,504 | 6 s |
| kapua | 330 | 13,804 | 25 s |
| coddy-agent | 274 | 56,539 | 98 s |
| coreshop | 334 | 48,169 | 42 s |
| sylius | 319 | 66,823 | 95 s |
| prestashop | 348 | 10,097 | 115 s |
| e-petitions | 98 | 14,425 | 50 s |
| Total | 2,051 | 247,405 | |

The execution time is one ground-truth run with coverage on one worker.
Mutation executions are often shorter. A full configuration with mutation
costs on the order of 1,000 worker-hours, mostly on coddy-agent and Kapua.
`evaluate --metrics exec` takes minutes to hours per project.
`validate --sample 20` takes about 4 minutes on python-docx and up to about
70 minutes on the largest projects. Generating the tests is a separate cost
([agents.md](agents.md#cost-of-generation)).

## Validate an installation

```sh
req2test validate --project python-docx --sample 20
```

`validate` evaluates the ground-truth tests of a seeded sample of eval
instances (default 20) as predictions. It exits 0 and prints "OK, within
single-observation noise" when:

- every sampled ground-truth test passes, and so does its unmutated
  mutation baseline;
- the mean API F1 is 1.0 and the mean coverage J is at least 0.99;
- the survived or dropped mutant runs ("flips") are at most
  max(1, ⌊0.001 × G⌋), where G is the number of mutant runs. Runs of the
  mutants a kit marks as host-dependent are not counted
  ([metrics.md](metrics.md#disclosures)).

Otherwise it prints DEVIATIONS and exits 1. Each mutant is run once, so a
correct installation can show a few flips. The result is also written to
`runs/<run-id>/validate.json` ([outputs.md](outputs.md#validatejson)).

On a correct installation, `validate --sample 20` gives:

| Project | Ground-truth tests passing | Flips counted (allowed) | Verdict |
|---|---|---|---|
| python-docx | 20/20 | 0 (2) | OK |
| algorand-sdk | 20/20 | 0 (1) | OK |
| kapua | 20/20 | 0 (1) | OK |
| sylius | 20/20 | 0 (4) | OK |
| coddy-agent | 20/20 | 1 (3) | OK |
| e-petitions | 20/20 | 1 (2) | OK |
| coreshop | 20/20 | 0 (2) | OK |
| prestashop | 20/20 | 0 (1) | DEVIATIONS |

PrestaShop reports DEVIATIONS on a correct installation. The ground truth of
`product_management_shop_collection.feature:423` reaches API F1 0.9796, so
the mean API F1 is 0.9990.

## Troubleshooting

**`evaluate` refuses a dirty clone.** The engine records the clone's commit
and refuses untracked files. Move tasks, views and predictions out of the
clone (for example to `~/r2t-work`) or into its git-ignored `./work/`.

**`env up` says a directory "is writable or owned by another user".**
`$REQ2TEST_HOME` and every directory above it must be writable only by you.
Run `chmod go-w` on the directory it names.

**`env up` refuses the daemon's containerd image store.** Use a daemon with
the classic overlay2 store, or let `req2test` start its own
([environments.md](environments.md#prerequisites)).

**`env up` reports the kernel key quota.** Each rootless container uses
kernel keys. Retire finished pools, pass a lower `--workers`, or raise the
quota (`kernel.keys.maxkeys` and `kernel.keys.maxbytes`).

**Many timeouts or infrastructure errors.** The host is overloaded. Rerun
with a lower `--workers`. On Kapua, PrestaShop and e-petitions a timeout
counts as a kill, so an overloaded host changes the score.

**An instance ends as `harness_error` on every run.** Retire the
environment with `req2test env down --project P` and run the command again.

**`runtime preflight` exits 1.** It prints the cause. Most often the host
does not let bubblewrap create nested user namespaces
([agents.md](agents.md#runtime-packs)).

**A command warns that an installed kit is older than expected.** Run the
`req2test fetch --kits-only --project P` command it prints.

**PrestaShop ground-truth tests fail after November 2026.** Six PrestaShop
eval items contain dates that expire on 2026-12-01, and four more on
2026-12-31. The harness runs them on the host's clock, so after those dates
they can fail for the ground truth too. `env up` prints the affected counts.

**Errors.** A known error prints one line, `req2test: error: ...`, and exits
2. `req2test --debug <verb> ...` also prints the traceback.
