# `egress_fixtures/` — two trajectories the detector is read against

Two OpenHands-shaped attempt trees, written by `egress.py`'s own `_event`
and `_terminal` writers and committed here so that `egress.selftest()`'s
last three checks run on every machine.

They are **synthetic reconstructions**, not copies of archived evidence.
Nothing here was taken from a recorded run; the terminal commands and
observations were written by hand to carry the shape of what the archived
C1.5 attempts and C3 arms contain. They are fixtures, and citing them as
evidence of what an arm did would be false.

* `contaminated_c1_5/` — the 2026-08-01 C1.5 shape: a `curl` of a
  `raw.githubusercontent.com` source file, a `api.github.com` recursive
  tree enumeration, and the copy of the fetched file into the workspace.
  Four violations over two hosts.
* `clean_c3/` — a C3 attempt on the same project: `cat`, `grep` and a
  Behat run whose output is full of licence-header URLs
  (`coreshop.com/license`, `opensource.org/licenses/MIT`,
  `apache.org/licenses/LICENSE-2.0`). Zero violations — those headers are
  what a naive detector fires on, and this one must not.

Before this directory existed the same two claims were checked against
`/data2/binhang/coreshop_bench/artifacts/trajectories`, so they ran on one
host and printed `[SKIP]` everywhere else.
