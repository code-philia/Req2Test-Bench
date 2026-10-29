# Req2Test-Bench leaderboard

Means over the eight projects (equal weight), in percent, target-hidden view, aggregated by `req2test.aggregate` in `leaderboard` mode. A non-passing test counts as 0 in every column, and – marks a measure not available for every project. Benchmark 1.1 scores 2,037 of the 2,051 `eval` instances ([population](../docs/evaluation.md#population)). A run is comparable with this table when the system follows the generation protocol of `docs/agents.md` on the whole `eval` split.

| System | Model | Reasoning | Pass@1 | KillComplete@1 | API F1 | Coverage J | Mutation R |
|---|---|---|---:|---:|---:|---:|---:|
| Codex CLI‡ | DeepSeek-V4.1-Flash | high | 93.2 | 36.4 | 71.0 | 85.3 | 85.9 |
| Codex CLI | GPT-6.1 Sol | high | 87.2 | 35.5 | 64.9 | 77.6 | 79.4 |
| Codex CLI† | DeepSeek-V4.1-Flash | high | 82.8 | 33.8 | 64.2 | 75.9 | 76.3 |
| Claude Code† | Claude Sonnet 5.5 | high | 80.9 | 35.9 | 61.7 | 76.0 | 75.6 |
| Claude Code† | DeepSeek-V4.1-Flash | high | 80.5 | 34.4 | 62.0 | 73.2 | 73.3 |
| Codex CLI† | GPT-6 Sol | high | 73.5 | 31.3 | 54.2 | 65.3 | 66.1 |
| Codex CLI† | GPT-6 Luna | high | 66.2 | 28.3 | 49.9 | 59.6 | 60.6 |
| Codex CLI† | DeepSeek-V4.1-Flash | off | 57.6 | 23.6 | 41.9 | 53.1 | 53.4 |
| OpenHands† | DeepSeek-V4.1-Flash | off | 32.7 | 18.1 | 26.4 | 30.9 | 31.2 |
| Aider† | DeepSeek-V4.1-Flash | off | 9.7 | 4.5 | 6.6 | 8.0 | 8.5 |

† Results reported in the [paper](https://arxiv.org/abs/2610.36584), on the 2,051 eval instances, generated without the runtime packs, so the agent could not run the application.

‡ Algorand SDK, Kapua and 135 PrestaShop instances ran on DeepSeek's 17 October 2026 update of DeepSeek-V4.1-Flash.

## Data

- Every cell's counts and values are in `results/leaderboard.json`.
- Instance-set sizes for API F1 and coverage are in `req2test/data/i_sets.json`, and the three excluded attempts of the paper's runs in `req2test/data/attempt_exclusions.json`.
