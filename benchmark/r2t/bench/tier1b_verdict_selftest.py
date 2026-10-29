"""Network-free checks for the Tier-1b verdict CLI adapter."""
from __future__ import annotations

import contextlib
import io
import os

from .. import cli
from . import results as R


def _capture(argv: list[str]) -> tuple[int, str]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, output.getvalue()


def selftest() -> int:
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        ok = ok and bool(condition)
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))

    real_verdict = R.legacy_pin_verdict
    saved_wrapper = os.environ.pop(R.LEGACY_PIN_ENV, None)
    help_code, help_output = _capture(["tier1b-verdict", "--help"])
    os.environ[R.LEGACY_PIN_ENV] = "/fixture/ambient-wrapper.json"
    empty, empty_output = _capture([
        "--artifacts", "/fixture/artifacts", "tier1b-verdict",
        "--coreshop-test-quality-wrapper", "",
    ])
    os.environ.pop(R.LEGACY_PIN_ENV)
    calls = []
    outcomes = iter((
        True,
        "the rendering differs from the frozen payload:\n"
        "--- benchmark/release/v1/legacy_table_eval100_std.md\n"
        "+++ rendered\n"
        "@@ -1 +1 @@\n"
        "-| metric | published |\n"
        "+| metric | changed |\n",
    ))

    def fake_verdict(wrapper_path, *, artifacts=R.DEFAULT_ARTIFACTS,
                     **_unused):
        calls.append((wrapper_path, artifacts))
        return next(outcomes)

    R.legacy_pin_verdict = fake_verdict
    try:
        passed, pass_output = _capture([
            "--artifacts", "/fixture/artifacts", "tier1b-verdict",
            "--coreshop-test-quality-wrapper", "/fixture/wrapper.json",
        ])
        os.environ[R.LEGACY_PIN_ENV] = "/fixture/from-environment.json"
        failed, fail_output = _capture([
            "--artifacts", "/fixture/artifacts", "tier1b-verdict",
        ])
    finally:
        R.legacy_pin_verdict = real_verdict
        if saved_wrapper is None:
            os.environ.pop(R.LEGACY_PIN_ENV, None)
        else:
            os.environ[R.LEGACY_PIN_ENV] = saved_wrapper

    fixture = "benchmark/release/v1/legacy_table_eval100_std.md"
    check("the conditionally registered verdict parser exposes its own help",
          help_code == 0 and "usage: r2t tier1b-verdict" in help_output
          and "--coreshop-test-quality-wrapper" in help_output,
          repr((help_code, help_output)))
    check("the verdict verb delegates the explicit wrapper and artifacts to "
          "results.legacy_pin_verdict",
          calls[:1] == [("/fixture/wrapper.json", "/fixture/artifacts")],
          repr(calls))
    check("an explicitly empty wrapper overrides an ambient wrapper and "
          "reports the named unarmed failure",
          empty == 1 and "[FAIL] Tier-1b" in empty_output
          and "no test-quality wrapper supplied" in empty_output
          and "/fixture/ambient-wrapper.json" not in empty_output,
          repr((empty, empty_output)))
    check("a true PC8 verdict prints explicit PASS and exits zero",
          passed == 0 and "[PASS] Tier-1b" in pass_output
          and fixture in pass_output, repr((passed, pass_output)))
    check("the existing wrapper environment variable arms the same command",
          len(calls) == 2
          and calls[1] == ("/fixture/from-environment.json",
                           "/fixture/artifacts"), repr(calls))
    check("a failed PC8 verdict exits nonzero and preserves its useful diff",
          failed == 1 and "[FAIL] Tier-1b" in fail_output
          and fixture in fail_output
          and f"--- {fixture}" in fail_output
          and "+++ rendered" in fail_output
          and "-| metric | published |" in fail_output
          and "+| metric | changed |" in fail_output,
          repr((failed, fail_output)))

    print("\n" + ("ALL PASS (tier1b_verdict_selftest)" if ok
                   else "FAILURES (tier1b_verdict_selftest)"))
    return 0 if ok else 1
