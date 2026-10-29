# Source views

A source view is the project as a system sees it while it writes a test. It
has the test implementations of all Scenarios removed. In the target-hidden
(TH) view, the bodies of the instance's target methods, and the helpers they
delegate behaviour to, are also replaced by placeholders that fail with an
"implementation hidden" error. Where hiding alone would stop the project
from building, the view carries small repairs (for example a stub file), so
that it builds and runs with the project's runtime pack
([agents.md](agents.md#runtime-packs)). The view also adds contract files
such as `TARGET_CONTRACTS.md`.

Every `eval` instance has a TH view, and so does every python-docx and
CoreShop instance of the `full` split.

## Materialize a view

```sh
req2test views materialize --project python-docx \
    --instance "python-docx/features/sct-section.feature:50" --out ~/r2t-work/ws/0001/repo
```

- `--out` must not exist. Put it outside the clone. The task rows call
  the view `./repo`, so the system's working directory is the parent of `--out`
  ([agents.md](agents.md#the-flow)).
- The command checks the written files against the view's recorded digest.
  On a mismatch it removes the view and exits non-zero.
- `--views-dir` defaults to `$REQ2TEST_HOME/views`, where `req2test fetch`
  installs the views. Materializing needs only the `zstd` command.

From Python: `req2test.views.materialize(project, view, instance_id, out_dir)`.

Give the system only the `--out` directory. The installed archives contain
the unhidden source ([agents.md](agents.md#what-the-system-may-and-may-not-see)).

## Archive set

Each project's views are one release, `views-<project>-v2.0`:

| File | Content |
|---|---|
| `views.json` | The inputs, archive sizes and digests |
| `manifests.jsonl` | One row per instance and view, with its digest |
| `base.tar.zst` | The project source shared by every view, with no body hidden |
| `th_overlays.tar.zst` | The per-instance overlays that hide the target bodies |

A TH view is the base with its overlay applied. Each view's digest equals
the one recorded for the view that the leaderboard's 1.1 rows worked in.
