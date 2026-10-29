# Dataset

The dataset is on the Hugging Face Hub as
[code-philia/Req2Test-Bench](https://huggingface.co/datasets/code-philia/Req2Test-Bench).
It loads with the `datasets` package:

```python
from datasets import load_dataset
eval_split = load_dataset("code-philia/Req2Test-Bench", split="eval")   # the 2,051 benchmark instances
full_split = load_dataset("code-philia/Req2Test-Bench", split="full")   # all 5,086, eval included
gt_tests = load_dataset("code-philia/Req2Test-Bench", "gt_tests", split="full")  # reference answers, not model input
```

The harness does not need `datasets`. `req2test fetch` installs the same rows
as JSONL from the release `dataset-v1.1`, under
`$REQ2TEST_HOME/data/dataset-v1.1/`. The release's `SCHEMA.md` has the same
tables as this page.

## Splits

| Split | Rows | Content |
| --- | ---: | --- |
| `eval` | 2,051 | The benchmark instances. The metrics count 2,037 of them ([population](evaluation.md#population)) |
| `full` | 5,086 | Every execution-validated instance, `eval` included. Data for analysis ([evaluation.md](evaluation.md#splits)) |
| `gt_tests` | 5,086 | The ground-truth test implementation of every instance, keyed by `instance_id` |

The `eval` rows are the `full` rows with `in_eval_split: true`, in the same
order. Rows are ordered by `project`, then by `instance_id`. The
ground-truth file contents are kept apart from the main rows because shared
step-definition files repeat across instances. The main rows list only
their paths (`gt_test_files`).

## Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `instance_id` | string | The item id: `<project>/<feature file path>:<Scenario line>`. Stable key across all project files. |
| `project` | string | One of `algorand-sdk`, `coddy-agent`, `coreshop`, `e-petitions`, `kapua`, `prestashop`, `python-docx`, `sylius`. |
| `language` | string | `go`, `java`, `php`, `python` or `ruby`. |
| `framework` | string | BDD runner: `godog`, `cucumber` (Java and Ruby), `behat` or `behave`. |
| `repo_url` | string | Upstream repository of the project snapshot that the test runs against (production code and test code). |
| `base_commit` | string | 40-character commit of `repo_url`: the pinned project snapshot. |
| `feature_repo_url`, `feature_commit` | string | Repository and commit holding the `.feature` file. Equal to `repo_url`/`base_commit` except for `algorand-sdk`, whose features live in `algorand/algorand-sdk-testing` while code and step definitions live in `algorand/java-algorand-sdk`. |
| `feature.file_path` | string | Path of the `.feature` file in `feature_repo_url` at `feature_commit`. |
| `feature.title` | string | Text after `Feature:`. |
| `feature.narrative` | string or null | Free-text Feature description as written (indentation kept). Null when the Feature has a title only. |
| `feature.background` | string or null | The Feature's `Background:` block as written, or null. Its Steps run before the Scenario's. |
| `scenario.title` | string | Text after `Scenario:` / `Scenario Outline:`. |
| `scenario.line` | int | 1-based line of the Scenario header in `feature.file_path`. |
| `scenario.kind` | string | `scenario` or `outline`. An Outline is one instance, and all its `Examples` rows are executed. |
| `scenario.tags` | list of string | Tags in effect for the Scenario (Feature and Scenario tags). |
| `scenario.gherkin` | string | Exact text of the Scenario from its header line through its last Step or Examples row, indentation kept, Examples tables included. Trailing blank and comment lines are dropped. Together with `feature.*` this is the Requirement r = <Feature, Scenario>. |
| `requirement_richness` | string | Benchmark label for the Feature description: `user_story` (As a / In order to / I want), `prose`, or `title_only`. |
| `target_interfaces` | list of object | The target interfaces: declarations of first-party public production methods that the ground-truth test calls directly from its When/Then Steps. Each object has `declaration` (source declaration text as shown to agents) and `key` (the method's identity, a list of strings whose form depends on the language: `[module, function]` for Python and Go, `[class, method]` for PHP, `[class, "name:(JVM descriptor)"]` for Java, `[class, "instance"/"class", method]` for Ruby). |
| `target_interfaces_empty_reason` | string or null | Null when `target_interfaces` is non-empty. `no_action_or_check_call` when the action and check Steps call no production method directly (such instances are part of the benchmark: 234 of the 2,051 evaluated). `not_identified: ...` for the 6 non-evaluated Algorand instances for which the checked interfaces were never computed. |
| `test_level` | string | `component`, `integration` or `system`. |
| `test_level_class` | string | The Step-Definition suite class the level was assigned from, e.g. `KP-UNIT`, `PS-BUS`, `SY-ADMIN`. |
| `in_eval_split` | bool | True for the 2,051 evaluated instances. |
| `gt_test_files` | list of string | Paths (relative to `repo_url` at `base_commit`) of the ground-truth Test Implementation: the validated project-local closure of the Step Definitions the runner bound and the helper classes they need. Shared testing infrastructure (hooks, base contexts, fixtures, test data, suite-wide Step Definitions) is excluded. |

The JSONL rows also carry `provenance`, which records where the build read
each field. No evaluation step reads it, and the parquet files leave it out.

## Ground-truth tests (`gt_tests`)

| Field | Type | Meaning |
| --- | --- | --- |
| `instance_id` | string | Joins to the main rows. |
| `files` | list of object | One `{path, content}` per entry of `gt_test_files`, same order. `content` is the file's full UTF-8 text at `base_commit`. |
| `di_fragment` | object, optional | CoreShop and Sylius only: the per-instance Symfony service definitions (service id -> class/arguments) that register the instance's Behat context classes. The parquet files hold it as JSON text, and as null for the other projects. |

## Counts

| Project | Language / framework | Full | Eval | Rows with target interfaces (all / eval) | Mean target interfaces (eval) | Mean GT files (eval) |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| algorand-sdk | Java, cucumber | 117 | 111 | 111 / 111 | 6.22 | 2.23 |
| coddy-agent | Go, godog | 282 | 274 | 220 / 214 | 3.33 | 2.51 |
| coreshop | PHP, behat | 422 | 334 | 417 / 329 | 3.94 | 13.76 |
| e-petitions | Ruby, cucumber | 119 | 98 | 13 / 13 | 0.16 | 3.96 |
| kapua | Java, cucumber | 605 | 330 | 583 / 318 | 9.52 | 1.50 |
| prestashop | PHP, behat | 1,352 | 348 | 1,342 / 346 | 13.80 | 8.24 |
| python-docx | Python, behave | 239 | 237 | 239 / 237 | 3.15 | 2.10 |
| sylius | PHP, behat | 1,950 | 319 | 1,252 / 249 | 1.86 | 3.36 |
| Total | | 5,086 | 2,051 | 4,177 / 1,817 | | 5.29 |

Test levels over all 5,086: 588 component, 2,066 integration, 2,432 system.
