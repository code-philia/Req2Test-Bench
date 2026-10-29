"""How the leaderboard's agents were run on the tasks.

`prompt` builds the prompt they were given from a `req2test tasks` row, and
`run_agent` runs a command-line agent on a task file and writes its
predictions.  Neither is part of the benchmark: an agent may use its own
prompt and driver (docs/agents.md).
"""
