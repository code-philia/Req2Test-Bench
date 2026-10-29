"""`req2test` command line.

Verbs: `fetch`, `tasks`, `views`, `runtime`, `env`, `evaluate`, `validate`,
`report` and `selftest --engine`.

A known error (`EnvError`, `KitError`, a `ValueError` or `RuntimeError` of a
stage, a missing file) prints one `req2test: error: ...` line, then any hint
lines the message carries, and exits 2; `req2test --debug VERB ...` prints
the traceback first and then the same lines.  Bare `req2test selftest` prints
how to run the engine's self-test and exits 0.
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback

VERBS = {
    "fetch": "download the dataset, evaluation kits, source views and "
             "runtime packs",
    "tasks": "write task JSONL for a split and project",
    "views": "materialize target-hidden (TH) source views",
    "runtime": "set up or check an attempt's application runtime",
    "env": "bring up a project's execution environment",
    "evaluate": "execute and score a predictions file",
    "validate": "validate an installation with ground-truth predictions",
    "report": "summarize an evaluation run",
    "selftest": "run self-tests (`--engine`: the vendored engine)",
}
#: Verbs that parse their own arguments.
OWN_PARSER = ("env",)
PROJECTS = ("algorand-sdk", "coddy-agent", "coreshop", "e-petitions",
            "kapua", "prestashop", "python-docx", "sylius")
#: Exit status of a known error (as argparse's usage errors).
ERROR_EXIT = 2
SELFTEST_HINT = (
    "req2test selftest: the self-test is the vendored engine's; run "
    "`req2test selftest --engine` from the clone. It needs JDK 17, Go "
    "1.25.0, Ruby 3.x and bubblewrap on PATH (docs/engine.md, \"Engine "
    "self-tests\").")


def _workers(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("--workers must be at least 1")
    return n


def _positive(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def _default_workers() -> str:
    """The per-project default pool sizes, as `req2test env up` uses them."""
    from .env import PROJECTS as DESCRIPTORS
    by_k: dict = {}
    for project in PROJECTS:
        by_k.setdefault(DESCRIPTORS[project]["k_default"], []).append(project)
    return "; ".join(f"{k} for {', '.join(names)}"
                     for k, names in sorted(by_k.items()))


SPLIT_HELP = ("eval (default) is the split the harness scores, with every "
              "metric. full runs for python-docx only, with --metrics exec "
              "(its kit and views hold all 239); for every other project it "
              "is data only and refused")
TASKS_SPLIT_HELP = ("eval (default) is the split the harness scores; full is "
                    "python-docx only (data only, and refused, for every "
                    "other project)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="req2test", description="Req2Test-Bench evaluation harness")
    parser.add_argument("--debug", action="store_true",
                        help="print the traceback of an error")
    verbs = parser.add_subparsers(dest="verb", metavar="VERB")
    verbs.required = True
    for verb, help_text in VERBS.items():
        # `env` parses its own arguments (req2test.env), --help included.
        sub = verbs.add_parser(verb, help=help_text, description=help_text,
                               add_help=verb not in OWN_PARSER)
        if verb not in OWN_PARSER:
            # Also accepted after the verb; SUPPRESS keeps the global value.
            sub.add_argument("--debug", action="store_true",
                             default=argparse.SUPPRESS,
                             help=argparse.SUPPRESS)
        if verb == "fetch":
            from . import kits
            kits.add_fetch_arguments(sub)
        if verb == "views":
            from . import views
            views.add_arguments(sub)
        if verb == "runtime":
            from . import packs
            packs.add_arguments(sub)
        if verb == "report":
            from . import report
            report.add_arguments(sub)
        if verb == "selftest":
            sub.add_argument(
                "--engine", action="store_true",
                help="run the vendored engine self-tests of components "
                     "data and bench whose inputs this repository ships "
                     "(req2test.engine.SELFTEST_SKIPPED lists the rest) and "
                     "check the scoring-set sha256s against "
                     "engine/UPSTREAM.json")
            sub.add_argument(
                "-j", "--jobs", type=int, default=None,
                help="parallel self-test modules (engine default when "
                     "omitted)")
        elif verb == "tasks":
            sub.add_argument("--split", choices=("eval", "full"),
                             default="eval", help=TASKS_SPLIT_HELP)
            sub.add_argument("--project", required=True, choices=PROJECTS)
            sub.add_argument("--view", default="th", choices=("th",),
                             help="th, the target-hidden view (the default)")
            sub.add_argument("--out", required=True, metavar="FILE")
        elif verb == "evaluate":
            sub.add_argument("--predictions", required=True, metavar="FILE",
                             help="predictions JSONL; file paths are "
                                  "relative to the repository root (a "
                                  "leading repo/ is removed, with a "
                                  "warning)")
            sub.add_argument("--split", choices=("eval", "full"),
                             default="eval", help=SPLIT_HELP)
            sub.add_argument("--project", default=None, choices=PROJECTS,
                             help="default: every project the predictions "
                                  "name (with --instances: the file names)")
            sub.add_argument("--view", default=None, choices=("th",),
                             help="th, the target-hidden view (the "
                                  "default)")
            sub.add_argument("--run-id", required=True)
            subset = sub.add_mutually_exclusive_group()
            subset.add_argument(
                "--instances", default=None, metavar="FILE",
                help="evaluate only these instances (one id per line): a "
                     "SUBSET run, not comparable to the leaderboard")
            subset.add_argument(
                "--sample", type=_positive, default=None, metavar="N",
                help="evaluate a seeded sample of N instances per project, "
                     "drawn as validate draws it: a SUBSET run, not "
                     "comparable to the leaderboard")
            sub.add_argument("--seed", type=int, default=None, metavar="S",
                             help="seed of --sample (default: validate's, "
                                  "20261004)")
            sub.add_argument("--workers", type=_workers, default=None,
                             help="parallel workers (default: the "
                                  "project's pool size, "
                                  + _default_workers() + ")")
            sub.add_argument("--metrics", choices=("exec", "all"),
                             default="all",
                             help="exec: Pass@1, API F1, coverage; all: "
                                  "also mutation (KillComplete)")
            sub.add_argument("--docker-host", default=None,
                             metavar="unix:///PATH",
                             help="an existing rootless daemon for `env up` "
                                  "(default: this home's own)")
        elif verb == "validate":
            sub.add_argument("--project", required=True, choices=PROJECTS)
            sub.add_argument("--sample", type=_positive, default=20)
            sub.add_argument("--run-id", default=None)
            sub.add_argument("--workers", type=_workers, default=None,
                             help="parallel workers (default: the "
                                  "project's pool size)")
            sub.add_argument("--docker-host", default=None,
                             metavar="unix:///PATH")
    return parser


def _print_summary(instances: list) -> None:
    """Counts per project/view, read off the scored instance rows.

    A cell without mutation (`--metrics exec`: every row `not_run`) prints
    KillComplete as not measured, as report.md does, never as 0 of N.
    """
    from .score import NOT_RUN
    cells: dict = {}
    for row in instances:
        cells.setdefault(f"{row['project']}/{row['view']}", []).append(row)
    for key, rows in sorted(cells.items()):
        passing = [r for r in rows if r["passed"]]
        api = [r["api_f1"] for r in passing if r["api_f1"] is not None]
        cov = [r["coverage_j"] for r in passing if r["coverage_j"] is not None]
        kc = ("– (mutation not measured)"
              if any(r.get("mutation_status") == NOT_RUN for r in rows) else
              f"{sum(1 for r in rows if r['kill_complete'])}/{len(rows)}")
        print(f"{key}: pass {len(passing)}/{len(rows)}, kill_complete {kc}, "
              f"API F1 (passing) {sum(api) / len(api) if api else '-'}, "
              f"coverage J (passing) {sum(cov) / len(cov) if cov else '-'}")


def _print_rejected(instances: list) -> None:
    """The prediction files the engine refused to write, per instance."""
    from .report import describe_rejected
    rows = [r for r in instances if r.get("rejected_files")]
    if not rows:
        return
    print(f"prediction files the engine rejected, with its reason, "
          f"{len(rows)} instance(s):")
    for r in rows:
        print(f"  {r['instance_id']}: "
              f"{describe_rejected(r['rejected_files']).replace('`', '')}")


def _daemon_note(docker_host) -> None:
    if not docker_host:
        print("note: this home's rootless Docker daemon keeps running for "
              "the next run; stop it with `req2test env stop-daemon`")


def _known_errors() -> tuple:
    from .env import EnvError
    from .kits import KitError
    return (EnvError, KitError, ValueError, RuntimeError, FileNotFoundError)


def report_error(exc: BaseException, debug: bool = False) -> int:
    """Print a known error as one `req2test: error:` line plus its hint
    lines (the rest of the message); with `--debug`, the traceback first."""
    if debug:
        traceback.print_exception(type(exc), exc, exc.__traceback__)
    text = str(exc).strip() or type(exc).__name__
    first, *rest = text.splitlines()
    print(f"req2test: error: {first}", file=sys.stderr)
    for line in rest:
        print(line, file=sys.stderr)
    return ERROR_EXIT


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    debug = bool(getattr(args, "debug", False))
    if args.verb in OWN_PARSER and "--debug" in extra:
        debug = True
        extra = [a for a in extra if a != "--debug"]
    if extra and args.verb not in OWN_PARSER:
        parser.error("unrecognized arguments: " + " ".join(extra))
    try:
        return _run(args, extra)
    except _known_errors() as exc:
        return report_error(exc, debug)


def _run(args, extra) -> int:
    if args.verb == "env":
        from . import env
        return env.main(extra)
    if args.verb == "report":
        from . import report
        return report.main(args)
    if args.verb == "fetch":
        from . import kits
        return kits.run_fetch(args)
    if args.verb == "views":
        from . import views
        return views.main(args)
    if args.verb == "runtime":
        from . import packs
        return packs.main(args)
    if args.verb == "selftest":
        if not args.engine:
            print(SELFTEST_HINT)
            return 0
        from . import engine
        return engine.selftest_engine(jobs=args.jobs)
    if args.verb == "tasks":
        from . import tasks
        n = tasks.export(args.project, args.view, args.out, args.split)
        print(f"wrote {n} task(s) to {args.out}")
        return 0
    if args.verb == "evaluate":
        from . import evaluate
        from .layout import run_root
        if args.seed is not None and args.sample is None:
            raise ValueError("--seed applies to --sample only")
        instances = (evaluate.read_instance_ids(args.instances)
                     if args.instances else None)
        result = evaluate.evaluate(
            args.predictions, run_id=args.run_id, split=args.split,
            project=args.project, view=args.view, workers=args.workers,
            metrics=args.metrics, instances=instances,
            instances_file=args.instances, sample=args.sample,
            seed=(evaluate.VALIDATE_SEED if args.seed is None
                  else args.seed),
            docker_host=args.docker_host)
        _print_summary(result["instances"])
        _print_rejected(result["instances"])
        from .report import FULL_SPLIT_NOTE, SUBSET_NOTE
        if result["summary"].get("full_split"):
            print(FULL_SPLIT_NOTE)
        if result["summary"].get("subset"):
            print(SUBSET_NOTE)
        print(f"wrote {run_root(args.run_id) / 'summary.json'} and "
              f"{run_root(args.run_id) / 'report.md'}")
        if result["pools"]:          # a run without a pool used no daemon
            _daemon_note(args.docker_host)
        return 0
    if args.verb == "validate":
        from . import evaluate
        result = evaluate.validate(args.project, sample=args.sample,
                                   run_id=args.run_id, workers=args.workers,
                                   docker_host=args.docker_host)
        print(json.dumps({k: v for k, v in result.items()
                          if k != "instances"}, indent=1))
        print("\n".join(evaluate.describe(result)))
        _daemon_note(args.docker_host)
        return 0 if result["ok"] else 1
    raise AssertionError(f"unhandled verb {args.verb!r}")


if __name__ == "__main__":
    sys.exit(main())
