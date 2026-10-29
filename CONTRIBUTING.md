# Contributing to Req2Test-Bench

Bug reports, documentation fixes and harness improvements are welcome. Open an
issue first for anything that changes how a run is scored, so the change can
be discussed before code is written.

## Layout

- `req2test/`: the `req2test` command and the dataset loader;
  `req2test/inference/` holds the leaderboard's prompt and an agent runner.
- `benchmark/`: the execution engine, a pinned snapshot
  ([docs/engine.md](docs/engine.md)).
- `engine/`: the engine's pin and patch list (`UPSTREAM.json`) and the
  applier-check reports.
- `docs/`: user documentation, with its figures in `docs/assets/`.
- `docker/`: a base image for agents that run in a container.
- `results/`: the leaderboard and its cells.
- `scripts/`: maintainer tools (the leaderboard builder, the applier check
  and the engine's prune list).
- `tests/`: the unit tests.

## Changes

- Work on a short-lived branch and open a pull request to `main`.
- Each pull request establishes one invariant. Include focused tests when
  behaviour changes.
- Before opening a pull request, run from the repository root:

  ```sh
  git diff --check
  python3 -m pip install pytest      # not a dependency of the package
  python3 -m pytest -q tests
  req2test selftest --engine
  ```

  `selftest --engine` needs JDK 17, Go 1.25.0, Ruby 3.x and bubblewrap
  ([docs/engine.md](docs/engine.md#engine-self-tests)). Say in the pull
  request what it printed.
- A change to a metric, a scoring rule, a timeout or the instance population
  changes what a number means. Describe it in the pull request and update
  [docs/metrics.md](docs/metrics.md) in the same pull request.

## The engine is a vendored snapshot

Do not edit files under `benchmark/` in place. An engine change is a listed
patch: add an entry to `patches` in `engine/UPSTREAM.json` (id, files,
sha256 before and after, reason) in the same pull request as the change.
Patches apply in list order. The scoring-set check fails on any scoring
module that differs from the pin without such an entry.

## Releases

The data releases are folders of the Hugging Face dataset repository. The
packers are `pack_kit`, `pack_views` and `pack_dataset` in `req2test.kits`,
and `pack_runtime` in `req2test.packs`. Each writes a release folder with
its `SHA256SUMS`, and the sha256 of that file is the release's pin in
`RELEASE_SUMS`. A changed release needs a new tag and a new pin.
`req2test views build --maintainer` rebuilds a project's view archives. It
needs the target-body maps and view repairs, which are not in this
repository.

## Never commit

- credentials, tokens, API keys or `.env` files;
- dataset, evaluation-kit or view bytes;
- experiment outputs: run directories, predictions, logs or trajectories.
