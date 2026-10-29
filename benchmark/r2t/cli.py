"""One entry point for every stage of the CoreShop v1 benchmark.

    python3 -m r2t.cli index      S3a  static index + Behat-native step matching
    python3 -m r2t.cli index-prod      static index of PRODUCTION code
    python3 -m r2t.cli closures   S3   per-item ground-truth closures
    python3 -m r2t.cli strip      S4   build the stripped repo + gold tree
    python3 -m r2t.cli validate   S5   round-trip fail-then-pass gate
    python3 -m r2t.cli quality    S2   per-item quality fields
    python3 -m r2t.cli release    S7   apply the inclusion rule, write the set
    python3 -m r2t.cli run        S6   run one adapter over admitted items
    python3 -m r2t.cli report          read a run back (compare several)
    python3 -m r2t.cli results         THE canonical results table for a run
    python3 -m r2t.cli tier1b-verdict  check CoreShop's byte-pinned v1 table
    python3 -m r2t.cli doctor          read-only operator/environment preflight
    python3 -m r2t.cli compare         two runs, one fixed item set, with
                                       cluster-aware intervals and an exact
                                       paired test over closure clusters
    python3 -m r2t.cli stamp-draw     record, from the evidence on disk, that
                                      a row is a REPEAT draw of its item and
                                      why the prior attempt was discarded
    python3 -m r2t.cli provision-coreshop
                                      build the pinned CoreShop environment
                                      and a fresh verified seed

`index` and `closures` MUST run before `strip`: they read the test code
that stripping removes.  The command refuses to run them afterwards
rather than silently producing an empty index.
"""
# Stays at the package root although its component moved into a package:
# `python3 -m r2t.cli` is the invocation path pinned in this repository's
# documents, CI, bootstrap and approved workload records.  It is a composer:
# the verbs, the dispatcher and every handler live with their component.
from __future__ import annotations

import sys

from .bench import cli as bench
from .toolkit import cli as toolkit
try:
    from .agents import cli as agents
except ImportError:
    # The benchmark-only mirror ships no `agents/` component: its verbs are
    # not on the menu, and argparse names the ones that are.
    agents = None

#: The components whose verbs this entry registers, in menu order.  Each is a
#: module with `PERSONA` and `register(verbs, request)`.
COMPONENTS = tuple(m for m in (bench, toolkit, agents) if m is not None)


def main(argv=None) -> int:
    return bench.dispatch(argv, COMPONENTS,
                          description=__doc__.split("\n")[0])


if __name__ == "__main__":
    sys.exit(main())
