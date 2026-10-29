"""S4 — the pre-execution syntax gate: compile a solution, never import it.

The behave twin of the role `analyze_php.php` plays at run time for the PHP
stack: a solution whose files do not even parse must be recorded as
`parse_or_compile_error` — a different research signal from "the generated
test was wrong" — and it must be caught BEFORE behave runs, because behave's
own reaction to an unparseable step module is a framework abort whose stdout
looks exactly like an infrastructure failure.

Installed into `_bench/` by `strip_repo_behave`, so its hash is part of the
substrate baseline (the CoreShop precedent: `_bench/analyze_php.php` is under
the digest baseline and deliberately never refreshed).  Run in-container —
`python _bench/compile_check.py --path features/steps/x.py …` — with the
IMAGE's interpreter, because "does this parse" is a question about the python
that will execute it: the host runs 3.10 and the image 3.12, and 3.12 accepts
source 3.10 refuses (PEP 701 f-strings), so a host-side check would refuse
solutions the run would have accepted.

Three rules, each load-bearing:

* **`compile()`, never import.**  An import executes module-level code, and
  this program runs BEFORE the harness's execution boundary — a solution must
  not get a side-effect channel out of its own syntax check.  `compile()`
  parses and code-gens without running anything.
* **No bytecode.**  `compile()` returns the code object and writes nothing;
  `py_compile` was rejected because it drops a `.pyc` beside the solution,
  and compiled bytecode is exactly the state the purge hooks exist to sweep.
* **JSON on stdout, files and errors both.**  The caller
  (`BehaveHarness.index_paths`) mirrors the PHP analyzer's contract: an empty
  `errors` map means every file compiled, and a non-empty one routes the run
  to `parse_or_compile_error` through the same `runner._record` branch the
  PHP stack has always used.
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def check_paths(root: str, rel_paths: list) -> dict:
    files: dict = {}
    errors: dict = {}
    for rel in rel_paths:
        full = os.path.join(root, rel)
        try:
            with open(full, "rb") as fh:
                source = fh.read()
            # `compile` of the raw BYTES honours a PEP 263 coding cookie the
            # way the interpreter itself would; decoding here first would
            # check a file subtly different from the one behave will load.
            compile(source, rel, "exec")
        except SyntaxError as e:
            errors[rel] = f"SyntaxError: {e.msg} (line {e.lineno})"
        except ValueError as e:
            # A NUL byte in the source raises ValueError, not SyntaxError.
            errors[rel] = f"ValueError: {e}"
        except OSError as e:
            errors[rel] = f"{type(e).__name__}: {e}"
        else:
            files[rel] = {"compiled": True}
    return {"root": root, "files": files, "errors": errors}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--path", action="append", default=[])
    args = ap.parse_args(argv)
    json.dump(check_paths(args.root, args.path), sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
