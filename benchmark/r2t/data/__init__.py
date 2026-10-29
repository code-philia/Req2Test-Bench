"""The dataset contract: what a released benchmark IS, and how it is read.

The release vocabulary and readers, the installed-bundle fetch/validate,
subsets, the task profile and the prompt it freezes, the versions
registry, the mutant population and the mutation-asset validators.  The
modules here import `core` and nothing else at module level -- the checked
fact (c) of `core.components` -- and the few function-local edges their
code crosses into `bench` or `toolkit` are listed there in
`KNOWN_DATA_ROUTE_EDGES`.  Their self-tests are outside that fact: a
`core + data` checkout imports every module here and cannot self-test
them.  What WRITES these artifacts lives in `toolkit/` (`release_build`,
`bundle_build`, `subset_writer`, `mutation_audit`).
"""
