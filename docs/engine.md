# The evaluation engine

`benchmark/` holds the execution engine. It provisions the worker
containers, writes a prediction into the instance's workspace, runs the
Scenario with coverage, applies mutants and classifies every outcome.
`req2test` drives it and scores what it records. Every execution and
mutation row records the engine's harness version (`harness_version`, 27).

## Pin and patches

`engine/UPSTREAM.json` pins the engine. It records the source commit, the
paths pruned from the source tree (`scripts/prune_engine.py`), the sha256 of
every scoring module and of the nondeterministic-mutant list
(`scoring_set`), and the patches applied on top, in order.
`req2test selftest --engine` fails when a scoring module differs from the
pin without a listed patch. How to change the engine is in
[CONTRIBUTING.md](../CONTRIBUTING.md#the-engine-is-a-vendored-snapshot).

| Patch | Files | What it does |
| --- | --- | --- |
| T1 | `config/nondeterministic_mutants.yml` | Comments only: the list's header. The parsed list is unchanged |
| P1 | `r2t/bench/worker.py`, `r2t/bench/prestashop_selftest.py` | A worker's container is used only once its entrypoint has started its command |

No patch changes a ground-truth mutation outcome, so the kits' references
are reused.

## Applier check

`scripts/check_applier.py` checks that the engine's mutant appliers write
the same bytes as the appliers that recorded the kits' ground-truth kills.
For every mutant of a kit's G_i, it applies the recipe to the kit's seed and
compares the sha256 of the mutated files. The script appliers (PHP, Python,
Ruby) run inside the kit's own image, offline. For Go and Java the engine
accepts only the exact byte splice of the mutant's descriptor, so the check
computes that splice on the kit seed. The reports are in
[`engine/applier_check/`](../engine/applier_check/).

| Project | Language | G mutants (files) | Result |
| --- | --- | ---: | --- |
| coreshop | PHP | 1,456 (387) | all equal |
| sylius | PHP | 1,923 (564) | all equal |
| prestashop | PHP | 2,530 (634) | all equal |
| python-docx | Python | 1,250 (66) | all equal |
| e-petitions | Ruby | 916 (94) | all equal |
| kapua | Java | 1,248 (266) | every descriptor splices on the seed |
| coddy-agent | Go | 4,950 (236) | every descriptor splices on the seed |
| algorand-sdk | Java | 1,531 (116) | every descriptor splices on the seed |

## Engine self-tests

`req2test selftest --engine` runs the engine self-tests of components `data`
and `bench` whose inputs this repository ships, then the scoring-set check.
`req2test.engine.SELFTEST_SKIPPED` lists the modules it leaves out and the
input each one lacks. It needs Go 1.25.0, JDK 17, Ruby 3.x and bubblewrap
with permission to create user namespaces, on `PATH`.
