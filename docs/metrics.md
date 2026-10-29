# Metrics

The output files are listed in [outputs.md](outputs.md).

## Per instance (`instances.jsonl`)

Each instance gets one outcome on the outcome ladder: `generation_failure`,
`compilation_failure`, `binding_failure`, `execution_failure`,
`assertion_failure`, `pass`, or `infrastructure_excluded`. An instance is
excluded when the harness, not the test, failed, or when the engine reports an
outcome outside the ladder. Excluded instances leave the Pass@1 denominator,
and the report lists them.

Mutation scoring uses the kit's ground-truth kill set of the instance:

    G_i = the kit's pool pairs of i that the ground-truth test kills,
          minus the kit's reference exclusions,
          minus the pairs of the engine's nondeterministic mutants

A pool holds the mutants that the instance's ground-truth test covers. On
Kapua and PrestaShop it is a seeded sample of at most 100 of them, and an
instance with fewer covered mutants keeps all of them.

The nondeterministic mutants are the two CoreShop mutants listed in
[`benchmark/config/nondeterministic_mutants.yml`](../benchmark/config/nondeterministic_mutants.yml).
Whether a test kills them depends on a random draw (for example,
`96e02276fdb04ae5` is in random token generation). The mutation stage
therefore runs none of their pairs, and they are in no G_i.

On python-docx, a Scenario Outline's pool is built from the coverage of one
of its Examples rows.

A passing test is run against each mutant in G_i. Each result is a kill, a
survivor, or a dropped pair, by the project's rules (`mutation/rules.json` in
the kit):

| Projects | Kill | Candidate timeout | Infrastructure outcome |
|---|---|---|---|
| python-docx, Algorand SDK, CoreShop, Sylius | `failed` | dropped | dropped |
| coddy-agent | `failed`, including a mutant-induced Go crash | dropped | dropped |
| Kapua, PrestaShop, e-petitions | `failed` or `timeout` | kill | dropped |

- **Recall** = kills / (|G_i| − dropped).
- Every pair of G_i needs a result. `report` refuses an unfinished mutation
  stage until the run is resumed.
- **KillComplete**: the test passes and kills every scored pair of G_i
  (recall = 1).
- A pass with no mutation result (`unscored`) has no recall and is not
  kill-complete. Neither is a pass whose scored pairs are all dropped
  (`not_scorable`). A pass whose unmutated mutation baseline did not pass
  gets no mutation rows, and its `mutation_baseline` field says whether the
  baseline `failed` or hit `infrastructure`.
- Companions: strict KillComplete, where a pass with any dropped pair is
  kill-incomplete, and KillComplete at recall ≥ 0.95.

API F1 and coverage Jaccard compare the test's direct production calls and
covered lines with the ground-truth test's. They are defined for passing tests
only, on the instances whose ground truth has them (the kit's
`behaviour/I_api.json` and `I_cov.json`). A run with no such instance leaves
the measure empty.

## Per project and view, and the 8-project mean (`summary.json`)

Notation: N is the instances of the population (the 2,037 counted `eval`
instances, [evaluation.md](evaluation.md#population)), E the executed
instances (N minus the infrastructure-excluded ones), and P the passes. A
non-passing test scores 0 in every measure.

| Measure | `exact` mode | `leaderboard` mode (the headline) |
|---|---|---|
| Pass@1 | \|P\| / \|E\| | same |
| KillComplete@1 | KC / N | same |
| API F1 | Σ_P F1 / \|I_api ∩ E\| | mean F1 × passes with F1 / (\|I_api\| × \|E\| / N) |
| Coverage J | Σ_P J / \|I_cov ∩ E\| | mean J × \|P\| / (\|I_cov\| × \|E\| / N) |
| Mutation R | Σ_P recall / \|E\|, with an unscored pass as 0 | mean recall over scored passes × \|P\| / \|E\| |

- `leaderboard` mode is the leaderboard's aggregation. `exact` mode is
  printed beside it.
- The 8-project mean weights the eight projects equally. A value with fewer
  contributing projects, or with partial projects, is printed with its number
  of projects instead.
- A measure that was not run (no `behaviour.json` or no `mutation/` in the run)
  is empty, not 0.
- `req2test report --run-id R --ci N` adds 95% cluster-bootstrap intervals for
  `exact` mode. The bootstrap resamples feature files within each project,
  with N replicates.

## Disclosures

`report.md` lists, per project, what could affect a score: excluded
instances, unscored passes, dropped pairs, crash and timeout kills, and
rejected prediction files ([outputs.md](outputs.md#reportmd)).

Some mutants are marked host-dependent in their kit: Kapua
`42fa6d40e22a43a1`, PrestaShop `8e08150ac4bed473` and `856b05bc46ec63d9`,
and CoreShop `96e02276fdb04ae5`. Whether a test kills them can depend on the
worker's earlier executions. They stay in the score and are disclosed, and
only `validate` leaves them out of its flip count. CoreShop's
`96e02276fdb04ae5` is also nondeterministic, so it is in no G_i.
