"""Which stack a run is against, resolved from the profile's `framework:`.

One function, `for_framework`, and the refusals it makes.  Everything about
what a stack IS lives in `base.py` (the contract) and `behat.py` (the façade
over today's one implementation); this is the lookup the CLI dispatches on.

Two refusals, and they are different findings:

* an UNKNOWN framework is a typo or a profile from another benchmark, and the
  answer is "no such stack" with the list of the ones that exist;
* a KNOWN framework whose module has not landed yet is a `NotImplementedError`
  naming the milestone that lands it.  It is deliberately not a silent
  fallback to behat: a `behave` profile quietly measured through the PHP
  harness would fail in a hundred confusing ways, each of them looking like a
  finding about Python.

`DEFAULT_FRAMEWORK` is behat, and that is a compatibility rule rather than a
preference: every CoreShop invocation in this repository's history, in the
operator's shell history and in SPEC_C3_PARALLEL's runbooks passes no
`--profile` at all, and every one of them must keep producing byte-identical
commands.
"""
from __future__ import annotations

from types import ModuleType

from .base import (COVERAGE_FIELDS, DISPATCH_MEMBERS, ENGINE_MEMBERS,
                   RECORD_FIELDS, RECORD_SCHEMA, SCENARIO_RESULTS,
                   STEP_FIELDS, STEP_RESULTS, STEP_RESULTS_FOLDED,
                   StackRunner)

__all__ = ["COVERAGE_FIELDS", "DEFAULT_FRAMEWORK", "DISPATCH_MEMBERS",
           "ENGINE_MEMBERS", "KNOWN_FRAMEWORKS", "RECORD_FIELDS",
           "RECORD_SCHEMA", "SCENARIO_RESULTS", "STEP_FIELDS", "STEP_RESULTS",
           "STEP_RESULTS_FOLDED", "StackRunner", "for_framework", "selftest",
           "verb"]

#: `framework:` value -> the module inside this package that implements it.
#: A name here is a stack the benchmark KNOWS ABOUT; whether its module exists
#: yet is a separate question, answered by the import in `for_framework`.
KNOWN_FRAMEWORKS: dict[str, str] = {
    "behat": "behat",
    "behave": "behave",
    "cucumber": "cucumber",
    "cucumber_ruby": "cucumber_ruby",
    "godog": "godog",
}

#: The stack an invocation with no profile runs against — see the module
#: docstring.  CoreShop's byte-stability rests on this line.
DEFAULT_FRAMEWORK = "behat"

#: Which milestone lands each not-yet-existing stack, so the refusal says what
#: to do about itself instead of only that it happened.
_LANDS_IN: dict[str, str] = {
    "behave": "S3 (closure) and S4 (harness + recorder) of slice 1",
    "cucumber": "J5 (S4 harness) of the Java corpus expansion",
}


def for_framework(framework: str) -> ModuleType:
    """The stack module for a profile's `framework:`, or a refusal."""
    name = KNOWN_FRAMEWORKS.get(framework)
    if name is None:
        raise SystemExit(
            f"REFUSED: no stack for framework {framework!r}. This benchmark "
            f"knows {sorted(KNOWN_FRAMEWORKS)}; a profile naming another one "
            f"describes a project nothing here can strip, run or score.")
    from importlib import import_module
    try:
        module = import_module(f".{name}", __name__)
    except ModuleNotFoundError as e:
        # Only absence of the requested stack is an implementation milestone.
        # A stack that exists but has a missing transitive dependency is
        # broken and must retain its original import error; relabelling that
        # as "not implemented" would hide the defect as soon as cucumber.py
        # lands.
        if e.name != f"{__name__}.{name}":
            raise
        raise NotImplementedError(
            f"the {framework} stack is not implemented yet "
            f"({_LANDS_IN.get(framework, 'a later milestone')} lands it: "
            f"r2t/stacks/{name}.py). Falling back to {DEFAULT_FRAMEWORK} is "
            f"deliberately NOT done -- a {framework} project measured through "
            f"another framework's harness fails in ways that all look like "
            f"findings about the project. [{type(e).__name__}: {e}]") from None
    missing = [m for m in DISPATCH_MEMBERS if not hasattr(module, m)]
    if missing:
        raise SystemExit(
            f"REFUSED: r2t/stacks/{name}.py does not declare {missing}; the "
            f"CLI dispatches on those and would fail with an AttributeError "
            f"somewhere further in, wearing the name of whatever command the "
            f"operator ran.")
    if module.FRAMEWORK != framework:
        # The copy-paste failure this exists for: a new stack module derived
        # from `behat.py` that keeps `FRAMEWORK = "behat"` would be routed
        # here under its own name and then take the behat branch of every
        # dispatch in `cli.py` — i.e. run a Python project through the PHP
        # harness, which is the exact outcome the refusal above prevents.
        raise SystemExit(
            f"REFUSED: r2t/stacks/{name}.py calls itself "
            f"{module.FRAMEWORK!r} while it is registered as {framework!r}. "
            f"A stack that disagrees with its own name would be dispatched "
            f"as one framework and behave as another.")
    return module


def verb(stack: ModuleType, name: str):
    """One CLI verb of a stack, or a refusal naming what is missing.

    `getattr(stack, name)` would raise `AttributeError`, which reads as a bug
    in `r2t` rather than as "this stack has not implemented `closures` yet".
    The distinction matters most exactly when a stack is half-landed, which is
    the state slice 1 spends most of its time in.
    """
    fn = getattr(stack, name, None)
    if fn is None:
        raise NotImplementedError(
            f"the {stack.FRAMEWORK} stack has no `{name}` verb yet. It is "
            f"declared by `stacks.base` and implemented per stack; until it "
            f"lands, this command cannot run against a "
            f"{stack.FRAMEWORK} project.")
    return fn


# --------------------------------------------------------------- selftest
def selftest() -> int:
    """The façade IS the existing objects, and the record schema IS the code.

    Two claims, both of which are only worth anything if they are checked
    against the other files rather than against a copy of them here:

    * every member of `behat.MEMBERS` is the object it names, by `is`.  An
      equality check would pass for a wrapper that forwards, which is exactly
      the thing this package promises not to be;
    * `base.STEP_RESULTS` and the record's field lists are re-derived from
      `r2t/php/BenchRecorderHook.php` (which WRITES the records) and from
      `harness.record_outcome` (which READS them).  A vocabulary retyped into
      a constants file is a vocabulary that drifts.
    """
    import ast
    import inspect
    import os
    import re
    import textwrap

    from . import behat
    from ..bench import harness as _harness

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def resolve(dotted: str):
        """`r2t.bench.harness.Harness.install_solution` -> the object itself."""
        from importlib import import_module
        parts = dotted.split(".")
        obj = None
        for i in range(len(parts), 0, -1):
            try:
                obj = import_module(".".join(parts[:i]))
            except ImportError:
                continue
            for attr in parts[i:]:
                obj = getattr(obj, attr)
            return obj
        raise AssertionError(f"cannot resolve {dotted}")

    # ------------------------------------------------- the façade is a façade
    for member, dotted in behat.MEMBERS.items():
        have = getattr(behat, member, None)
        check(f"behat.{member} IS {dotted}", have is resolve(dotted),
              f"{have!r}")
    check("the seven seams of StackRunner are all present on the behat stack",
          all(hasattr(behat, s) for s in
              ("strip", "integrity_baseline", "extract_closure",
               "install_solution", "execute", "stub_solution",
               "mutant_population")))
    # The Protocol is `runtime_checkable`, so this is the contract itself
    # answering rather than a list of names retyped from it: a seam added to
    # `base.StackRunner` and forgotten here fails HERE, at the stack that is
    # supposed to implement it.
    check("...and the stack satisfies the StackRunner protocol itself",
          isinstance(behat, StackRunner))
    check("...and every one of them is in the identity table, so none can be "
          "quietly reimplemented later",
          {"strip", "integrity_baseline", "extract_closure",
           "install_solution", "execute", "stub_solution",
           "mutant_population"} <= set(behat.MEMBERS))
    # A façade that grew a function of its own would still pass the loop
    # above (it only walks MEMBERS), so the module's own namespace is the
    # thing checked here: nothing defined HERE, only names bound elsewhere.
    own = [n for n, v in vars(behat).items()
           if not n.startswith("_") and callable(v)
           and getattr(v, "__module__", None) == behat.__name__]
    check("the façade defines no function of its own -- zero logic movement",
          own == [], str(own))

    # ----------------------------------------------------- dispatch refusals
    check("the default framework is behat, so a CoreShop invocation with no "
          "profile is unchanged",
          DEFAULT_FRAMEWORK == "behat"
          and for_framework(DEFAULT_FRAMEWORK) is behat)
    try:
        mod = for_framework("cucumber")
        # J5 lands the module, and from then on this is the branch that runs:
        # the stack must say what it is rather than inherit behat's answer.
        # Written both ways, as the behave entry above it was, so that the
        # milestone that lands a stack does not have to edit the check that
        # protects the stacks that have not landed yet.
        check("a landed cucumber stack names itself",
              getattr(mod, "FRAMEWORK", None) == "cucumber",
              str(getattr(mod, "FRAMEWORK", None)))
    except NotImplementedError as e:
        message = str(e)
        check("the known-but-unlanded cucumber stack names its exact landing "
              "milestone and never falls back to behat",
              "J5 (S4 harness)" in message
              and "r2t/stacks/cucumber.py" in message
              and "NOT done" in message,
              message[:180])
    import importlib
    from unittest.mock import patch
    transitive = ModuleNotFoundError(
        "No module named 'stack_runtime_dependency'",
        name="stack_runtime_dependency")
    try:
        with patch.object(importlib, "import_module",
                          side_effect=transitive):
            for_framework("cucumber")
        transitive_reraised = False
    except ModuleNotFoundError as e:
        transitive_reraised = e is transitive
    check("a landed stack's missing transitive dependency is re-raised, not "
          "mislabelled as an unimplemented stack",
          transitive_reraised)
    try:
        mod = for_framework("behave")
        # Once S4 lands the module this is the branch that runs; the stack must
        # then say what it is rather than inherit behat's answer.
        check("a landed behave stack names itself",
              getattr(mod, "FRAMEWORK", None) == "behave",
              str(getattr(mod, "FRAMEWORK", None)))
    except NotImplementedError as e:
        check("a known-but-unlanded stack raises NotImplementedError naming "
              "the milestone, and never falls back to behat",
              "S4" in str(e) and "NOT done" in str(e), str(e)[:120])
    check("a stack declares everything the CLI dispatches on",
          all(hasattr(behat, m) for m in DISPATCH_MEMBERS))
    real_name = behat.FRAMEWORK
    try:
        behat.FRAMEWORK = "behave"
        for_framework("behat")
        check("a stack module that disagrees with its own registered name is "
              "refused", False, "accepted")
    except SystemExit as e:
        check("a stack module that disagrees with its own registered name is "
              "refused", "disagrees with its own name" in str(e))
    finally:
        behat.FRAMEWORK = real_name
    try:
        verb(behat, "cmd_nonexistent")
        check("a verb a stack has not implemented is refused, not "
              "AttributeError'd", False, "returned")
    except NotImplementedError as e:
        check("a verb a stack has not implemented is refused, not "
              "AttributeError'd", "has no `cmd_nonexistent` verb" in str(e))

    # --------------------------------------- one engine table, three stacks
    #
    # The uneven façade this replaces: behat declared all five engine members,
    # behave and cucumber only `engine_dir` and `applier`, so the name,
    # version and exclusion policy of two of the three engines had no
    # stack-side statement that anything could check.  Now every stack names
    # its engine and `mutation_run.engines()` is the one table saying what
    # that name binds to, so a façade that borrowed another engine's
    # directory, applier or exclusions fails HERE rather than at the mutant
    # id it would have minted.
    from ..bench import mutation_run as _mutation_run

    registry = _mutation_run.engines()
    claimed: dict[str, str] = {}
    landed: list[str] = []
    unlanded: list[str] = []
    for framework in sorted(KNOWN_FRAMEWORKS):
        # `for_framework` both ways, for the reason the behave check above is
        # written both ways: a framework registered before its module lands
        # is a state this file designs for (module docstring, and the
        # `NotImplementedError` check above names the milestone).  Letting it
        # out HERE would abort this module rather than report it, taking the
        # checks below and every later selftest module with it.
        try:
            module = for_framework(framework)
        except NotImplementedError:
            unlanded.append(framework)
            continue
        landed.append(framework)
        absent = [m for m in ENGINE_MEMBERS if not hasattr(module, m)]
        check(f"the {framework} stack declares every engine member",
              absent == [], str(absent))
        if absent:
            continue
        entry = registry.get(module.engine)
        check(f"...and names an engine the one table knows",
              entry is not None, f"{framework} claims {module.engine!r}")
        if entry is None:
            continue
        claimed.setdefault(module.engine, framework)
        # behat re-exports the `Applier` OBJECT; the other two re-export the
        # zero-argument factory their engine module exports, so that module
        # can be imported without `mutation_run` (see `base.ENGINE_MEMBERS`).
        # Resolve, then compare by VALUE: the factory mints a fresh Applier
        # per call, so `is` here would be a claim about caching rather than
        # about the two agreeing.
        bound = module.applier
        bound = bound() if callable(bound) else bound
        check(f"...and cannot disagree with it about {module.engine!r}'s "
              f"version, directory, applier or exclusions",
              (module.engine_version, module.engine_dir, bound,
               tuple(module.excluded_prefixes))
              == (entry.version, entry.engine_dir, entry.applier,
                  tuple(entry.excluded_prefixes)),
              f"{module.engine_version} {module.engine_dir} {bound}")
    check("every engine in the table belongs to exactly one stack and every "
          "stack to one engine, so a fourth language is one row plus one "
          "stack rather than an edit in four places",
          sorted(claimed.values()) == landed
          and (sorted(claimed) == sorted(registry) if not unlanded
               else set(claimed) <= set(registry)),
          f"{claimed} vs {sorted(registry)}"
          + (f" (unlanded {unlanded})" if unlanded else ""))

    # ------------------------------------------------------- the CLI routes
    #
    # Checked here rather than in `cli.py` (which has no selftest of its own)
    # because it is the same claim as the rest of this file: which stack runs
    # is decided in exactly one place, by the ONE rule the CLI documents --
    # `--profile`, or `profile_<project>.yml` beside `--boundary`.  A
    # namespace that names no boundary names no project to resolve against
    # and keeps behat, which is what every CoreShop invocation ever written
    # gets from that rule anyway: `profile_coreshop.yml` sits beside the
    # default boundary declaring it.
    import argparse
    import contextlib
    import io
    import shutil
    import tempfile

    from .. import cli as _cli
    from ..bench import cli as bench_cli
    from ..toolkit import cli as toolkit_cli

    config = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "config")
    verbs = ("cmd_index", "cmd_closures", "cmd_stub_accept", "cmd_mutants")
    bare = argparse.Namespace()
    check("a command with no --profile at all runs on the behat stack",
          bench_cli._stack(bare) is behat)
    check("...and so does one whose --profile is None",
          bench_cli._stack(argparse.Namespace(profile=None)) is behat)
    check("every stack-bound verb takes the behat path with no profile, so "
          "the CoreShop body is what runs",
          all(bench_cli._other_stack(bare, v) is None for v in verbs))
    coreshop = os.path.join(config, "profile_coreshop.yml")
    check("the real CoreShop profile resolves to the behat stack -- read out "
          "of the file, digests and all, not assumed",
          bench_cli._stack(argparse.Namespace(profile=coreshop)) is behat)
    coreshop_run = argparse.Namespace(
        boundary=os.path.join(config, "boundary_coreshop.yml"), repo=None,
        profile=None)
    check("...and so does the CoreShop BOUNDARY with no --profile at all, "
          "which is what every archived invocation actually types",
          bench_cli._stack(coreshop_run) is behat
          and bench_cli._other_stack(coreshop_run, "make_harness") is None)

    # A run that omits `--profile` is not a CoreShop run just because it is
    # silent: it is the run whose profile sits beside its OWN boundary, which
    # is what `run --help` promises.  Resolving that in `_stack_profile` but
    # not in `_stack` is what sent a python-docx `run --adapter gold` down
    # the behat branch to die opening CoreShop's `artifacts/alias_table.json`
    # -- the wrong harness, reported as a traceback rather than a refusal.
    behave_stack = for_framework("behave")
    docx_boundary = os.path.join(config, "boundary_python_docx.yml")
    docx_run = argparse.Namespace(boundary=docx_boundary, repo=None,
                                  profile=None)
    check("a run that omits --profile resolves the profile beside its OWN "
          "--boundary, so a python-docx boundary routes to behave",
          bench_cli._stack(docx_run) is behave_stack)
    check("...and the two resolvers now read ONE file: `_stack`'s framework "
          "and `_stack_profile`'s profile cannot name different projects",
          bench_cli._stack(docx_run).FRAMEWORK
          == bench_cli._stack_profile(docx_run).framework)
    # The routing seam itself, not just the resolver: `_harness` is the
    # function `run` reaches through, and the stand-in proves the handoff
    # happens without a container, a workspace or an artifacts tree.
    routed: list = []
    real_make_harness = behave_stack.make_harness
    try:
        behave_stack.make_harness = lambda a: (routed.append(a)
                                               or "behave-harness")
        made = bench_cli._harness(docx_run)
    except Exception as e:                                  # noqa: BLE001
        made = f"{type(e).__name__}: {e}"
    finally:
        behave_stack.make_harness = real_make_harness
    check("...so `_harness` hands that run to the behave stack's own "
          "make_harness rather than reading another project's artifacts",
          made == "behave-harness" and routed == [docx_run], str(made)[:120])

    # And when the documented default names a file that is not there, the
    # answer is that file's path.  The failure this replaces named
    # `alias_table.json` -- a file belonging to the project the operator did
    # not ask for, in a branch they did not choose.
    orphan_dir = tempfile.mkdtemp(prefix="r2t-stack-route-")
    try:
        orphan_boundary = os.path.join(orphan_dir,
                                       "boundary_python_docx.yml")
        shutil.copyfile(docx_boundary, orphan_boundary)
        expected = os.path.join(orphan_dir, "profile_python_docx.yml")
        try:
            bench_cli._harness(argparse.Namespace(
                boundary=orphan_boundary, repo=None, profile=None))
            refusal = "returned a harness"
        except SystemExit as e:
            refusal = str(e)
        except Exception as e:                              # noqa: BLE001
            refusal = f"{type(e).__name__}: {e}"
        check("a boundary with no profile beside it is REFUSED by the path "
              "it looked for, not routed to behat and crashed on a file "
              "belonging to another project",
              refusal.startswith("REFUSED:") and expected in refusal,
              refusal[:160])
    finally:
        shutil.rmtree(orphan_dir, ignore_errors=True)

    epubcheck = os.path.join(config, "profile_epubcheck.yml")

    def cli_help(argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            try:
                rc = _cli.main(argv)
            except SystemExit as exc:
                rc = exc.code
        return rc, output.getvalue()

    base_help = cli_help(["mutants", "--help"])
    java_help = cli_help([
        "mutants", "build", "--profile", epubcheck, "--help"])
    java_profile_first_help = cli_help([
        "mutants", "--profile", epubcheck, "map", "--help"])
    validate_help = cli_help([
        "mutants", "validate", "--profile", epubcheck, "--help"])
    review_flags = ("--approval", "--approved-digest")
    check("release-review grammar is isolated to both valid Cucumber "
          "build/map orderings",
          all(rc == 0 for rc, _text in (
              base_help, java_help, java_profile_first_help, validate_help))
          and all(flag not in base_help[1] and flag not in validate_help[1]
                  and flag in java_help[1]
                  and flag in java_profile_first_help[1]
                  for flag in review_flags))

    behave_profile = os.path.join(config, "profile_behave_example.yml")
    if os.path.isfile(behave_profile):
        from ..data.profile import load_profile
        check("the behave example profile routes AWAY from behat -- the field "
              "that decides is `framework:`, read out of a real file",
              load_profile(behave_profile).framework != behat.FRAMEWORK)
    else:
        print(f"  [SKIP] no {behave_profile}, so a real non-behat profile "
              f"could not be resolved")

    # That each stack-bound verb actually CONSULTS the stack — checked against
    # a stand-in rather than against `behave`, so that this stays a check
    # about dispatch after S3/S4 land a real behave module.  A verb missing
    # its guard would run the PHP body and raise AttributeError on the
    # Namespace instead of returning the stand-in's answer.
    import types

    stand_in = types.ModuleType("r2t.stacks._stand_in")
    stand_in.FRAMEWORK = "stand_in"
    called: list = []
    for v in verbs:
        def _made(v=v):
            def _verb(args):
                called.append(v)
                return 77
            return _verb
        setattr(stand_in, v, _made())
    real_stack = bench_cli._stack
    try:
        bench_cli._stack = lambda args: stand_in
        # Each call is guarded: a verb that LOST its dispatch would run the
        # PHP body against an empty Namespace and raise `AttributeError`, and
        # a check that let that escape would abort the selftest with a
        # traceback instead of naming the verb that regressed.
        rcs = []
        for v in verbs:
            holder = bench_cli if v == "cmd_mutants" else toolkit_cli
            try:
                rcs.append(getattr(holder, v)(argparse.Namespace()))
            except Exception as e:                          # noqa: BLE001
                rcs.append(f"{v}: {type(e).__name__}: {e}")
        check("every stack-bound verb hands off to the stack it resolved, and "
              "returns ITS exit code",
              rcs == [77] * len(verbs) and called == list(verbs),
              f"{rcs} {called}")
        try:
            del stand_in.cmd_mutants
            bench_cli.cmd_mutants(argparse.Namespace())
            check("a stack that has not implemented a verb refuses there, "
                  "rather than falling through to the PHP body", False,
                  "fell through")
        except NotImplementedError as e:
            check("a stack that has not implemented a verb refuses there, "
                  "rather than falling through to the PHP body",
                  "has no `cmd_mutants` verb" in str(e), str(e)[:80])

        # `manifest-baseline` is not a whole-verb handoff -- its body is
        # shared -- but WHOSE `integrity_baseline` takes the digests is the
        # same dispatch question, and the answer used to be "`repo`'s,
        # always".  That was invisible while both stacks ALIASED the seam to
        # `repo.baseline_substrate`; a stack whose seam refuses first (a pom
        # is a build script, and a digest cannot tell one that pins the run
        # from one that unpins it) would have had those refusals reachable
        # from nothing an operator can type.
        class _Manifest:
            digests: dict = {}

        taken: list = []

        def _integrity_baseline(manifest, boundary, manifest_path):
            taken.append(manifest_path)
            return {"files": 0, "had_baseline": False}

        stand_in.make_harness = lambda a: (None, object(), _Manifest())
        stand_in.integrity_baseline = _integrity_baseline
        baseline_args = argparse.Namespace(
            profile=None, verify_against=None, force=False, gold="/nowhere")
        # Redirected because the verb PRINTS what it recorded, and that
        # block belongs in an operator's terminal rather than in the middle
        # of a check listing -- and the capture is then asserted, so
        # "returned the stack's answer" includes "reported it".
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            rc = toolkit_cli.cmd_manifest_baseline(baseline_args)
        check("`manifest-baseline` takes the digests through the STACK's "
              "`integrity_baseline`, which is the only production entry "
              "point a stack has to refuse a tree before hashing it",
              rc == 0 and taken == ["/nowhere/strip_manifest.json"]
              and "had_baseline" in printed.getvalue(),
              f"{rc} {taken} {printed.getvalue()!r}")
        del stand_in.integrity_baseline
        try:
            toolkit_cli.cmd_manifest_baseline(baseline_args)
            check("...and a stack with no such seam refuses there rather "
                  "than falling back to the shared function", False,
                  "fell through")
        except NotImplementedError as e:
            check("...and a stack with no such seam refuses there rather "
                  "than falling back to the shared function",
                  "has no `integrity_baseline` verb" in str(e), str(e)[:80])
    finally:
        bench_cli._stack = real_stack
    check("...while behat's seam IS `repo.baseline_substrate`, so every "
          "CoreShop `manifest-baseline` still takes exactly the digests it "
          "always did",
          behat.integrity_baseline
          is resolve("r2t.bench.repo.baseline_substrate"))

    # ------------------------------------------- the vocabulary is DERIVED
    #
    # From the PHP recorder, which is the program that writes the values.
    php = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "php", "BenchRecorderHook.php")
    with open(php, encoding="utf-8") as fh:
        recorder = fh.read()
    names = re.search(r"\$names\s*=\s*\[(.*?)\];", recorder, re.S)
    recorded = tuple(m.group(1) for m in
                     re.finditer(r"=>\s*'([a-z_]+)'", names.group(1) if names
                                 else ""))
    check("the five step results are the recorder's own TestResult names, "
          "not a list retyped here",
          recorded == STEP_RESULTS, f"{recorded} vs {STEP_RESULTS}")

    # From the fold, which is the function that reads them.  It branches on
    # four of the five by name; `skipped` falls through to `not_passed`, and
    # that asymmetry is the thing worth pinning.
    tree = ast.parse(textwrap.dedent(inspect.getsource(_harness.record_outcome)))
    positioned = sorted(
        (n.lineno, n.col_offset, n.value) for cmp_ in ast.walk(tree)
        if isinstance(cmp_, ast.Compare)
        for n in cmp_.comparators
        if isinstance(n, ast.Constant) and isinstance(n.value, str))
    in_order = [v for _l, _c, v in positioned]
    compared = set(in_order)
    check("every step result the fold branches on is in the vocabulary",
          compared <= set(STEP_RESULTS) | {"no_steps_ran", "not_passed",
                                           "undefined_steps"},
          str(sorted(compared)))
    check("the fold names exactly the four it ranks, and `skipped` is "
          "deliberately not one of them",
          compared & set(STEP_RESULTS) == set(STEP_RESULTS_FOLDED)
          and "skipped" not in compared, str(sorted(compared)))
    # Read out of the SOURCE in the order the branches appear, so this says
    # something the membership check above does not: reordering the fold (a
    # failure outranking an undefined step, say) changes what an outline
    # scores, and would otherwise change it silently.
    check("the fold's precedence is the order documented here, taken from the "
          "branches themselves",
          [w for w in in_order if w in set(STEP_RESULTS)]
          == list(STEP_RESULTS_FOLDED), str(in_order))

    # The record's own field lists, from the same recorder.
    scenario_block = re.search(r"self::\$record\s*=\s*\[(.*?)\];", recorder, re.S)
    keys = set(re.findall(r"'([a-z_]+)'\s*=>", scenario_block.group(1)))
    keys |= set(re.findall(r"self::\$record\['([a-z_]+)'\]\s*=", recorder))
    # Plus its own collector identity, as behave's record carries: with the
    # per-step tag (TARGET_INTERFACES_V2_SPEC §4) the PHP recorder writes
    # `direct_calls_schema` too, because the harness version cannot attest
    # the event shape -- a new harness can execute an older seed whose
    # recorder is substrate.
    check("RECORD_FIELDS is exactly what the recorder writes per scenario",
          keys == set(RECORD_FIELDS) | {"direct_calls_schema"},
          f"{sorted(keys)} vs {sorted(RECORD_FIELDS)}")
    marker = re.search(r"DIRECT_CALLS_SCHEMA = '([^']+)'", recorder)
    check("...and the marker it stamps is one the fold carries -- a string "
          "only this file writes and only `fold_direct_calls_schema` reads, "
          "so a mismatch is an item silently unscored for API",
          marker is not None
          and marker.group(1) in _harness.DIRECT_CALLS_SCHEMAS,
          str(marker and marker.group(1)))
    step_block = re.search(r"self::\$record\['steps'\]\[\]\s*=\s*\[(.*?)\];",
                           recorder, re.S)
    step_keys = set(re.findall(r"'([a-z_]+)'\s*=>", step_block.group(1)))
    check("STEP_FIELDS is exactly what the recorder writes per step",
          step_keys == set(STEP_FIELDS),
          f"{sorted(step_keys)} vs {sorted(STEP_FIELDS)}")
    cov_block = re.search(r"return \['files' => \$files, 'units' => \$units\];",
                          recorder)
    check("COVERAGE_FIELDS is exactly what the recorder collects",
          cov_block is not None and set(COVERAGE_FIELDS) == {"files", "units"})
    check("the scenario verdict the recorder writes is one of the two "
          "documented values",
          set(re.findall(r"isPassed\(\) \? '([a-z-]+)' : '([a-z-]+)'",
                         recorder)) == {SCENARIO_RESULTS})

    # And the readers: the fields `runner._record` pulls out of a record must
    # be fields the schema declares, or a run row is reading something the
    # contract does not promise.
    from ..bench import runner as _runner
    reader = inspect.getsource(_runner._record)
    for field in ("steps", "coverage"):
        check(f"the run row reads `{field}` off the record by name, as "
              f"declared", f'rec.get("{field}"' in reader)
    from ..bench.harness import fold_direct_calls
    check("the run row obtains direct_calls through the shared Examples fold",
          _runner.fold_direct_calls is fold_direct_calls
          and 'record.get("direct_calls")' in inspect.getsource(fold_direct_calls))
    # The coverage halves are read by the fold helper `_record` delegates to
    # (`_fold_coverage`, the outline coverage union of TARGET_INTERFACES_V2
    # section 4), so the declared reader is the two sources together.
    coverage_reader = reader + inspect.getsource(_runner._fold_coverage)
    check("the coverage halves the run row reads are the declared ones",
          _runner._fold_coverage.__name__ in reader
          and all(f'.get("{k}")' in coverage_reader for k in COVERAGE_FIELDS))

    check("the record schema is versioned as a namespaced string",
          RECORD_SCHEMA == "r2t.record/1")

    print("\n" + ("ALL PASS (stacks)" if ok else "FAILURES (stacks)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
