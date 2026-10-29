"""The benchmark: the evaluator that scores a candidate test suite.

The runner, the fixture and submitted adapters, the campaign and worker
machinery, validation, metrics, results and reports, mutation scoring and
test quality.  Imports `core` and `stacks`; reaches the agent component only
through function-local, presence-guarded imports, so a checkout without
`agents/` still runs the consumer route.
"""
