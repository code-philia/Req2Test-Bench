"""Stub acceptance, done by BEHAVE'S OWN loader and registry (SPEC §3.10).

The in-container half of `r2t.toolkit.stub_py.acceptance`, and the twin of what the
coordinator runs against a PHP container for `r2t.toolkit.stub`.  The host half proves
the generated modules are valid Python carrying the patterns they were asked
for; only this half can prove the thing that actually matters — that behave
IMPORTS each module, that every step of the item then resolves to a definition
in it, and that no `AmbiguousStep` is raised on the way.

**One item at a time, and that is the whole design.**  behave raises
`AmbiguousStep` at REGISTRATION: `StepRegistry.add_step_definition` walks
`self.steps[step_type]` and raises as soon as an already-registered pattern
matches the new definition's own text.  The escape hatch beside it
(`same_step_definition`) requires the same pattern AND THE SAME
`FileLocation`, so it never applies to two different files.  Over the 239
python-docx criterion items the stub emits 1159 distinct (keyword, text) keys
of which 307 appear in more than one item — `Given a run` in nine — so a run
that installed every item's module at once would abort on the first shared
step and prove nothing about any of them.  Items are therefore installed and
imported ONE AT A TIME, exactly as they are used: a fresh registry, one module
in the step directory, load, ask, clear, next.

Two properties are checked that a "did it import" test would miss:

* **every step RESOLVES, through `find_step_definition`** — not "a definition
  exists with that pattern", but behave's own answer to behave's own
  question, per keyword, the way `match_steps.py` asks it;
* **and resolves ONLY to its own step** — the same question with a suffix
  appended must resolve to NOTHING.  `RegexMatcher.check_match` calls
  `regex.match`, which anchors at the start and not at the end, so an
  unanchored stub would answer for every longer step in the suite and the
  vacuous floor would be measuring something else entirely.  The anchoring
  comes from `use_step_matcher("re")` (`SimplifiedRegexMatcher` wraps the
  pattern in `^…$` itself); this is the check that it really did.

`--probe` additionally pins the four behave facts the generator's design
rests on, in the image, so that a behave upgrade that changed any of them
fails here instead of silently changing what a stub means.

Usage::

    python stub_accept.py --root /work --steps-dir features/steps \\
        --stubs stubs.json --out accept.json [--probe]

stubs.json = {"items": [{"item_id": ..., "module": "stub_<key>.py",
                         "code": "...", "steps": [{"keyword", "text"}]}]}
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import traceback

SCHEMA = "r2t.stubaccept/1"

#: What is appended to a step's text to prove the stub does not answer for it.
#: A suffix rather than a prefix because `regex.match` anchors at the start:
#: a prefix would fail for the wrong reason and the check would pass without
#: testing anything.
_OVERMATCH_SUFFIX = " zzz-r2t-overmatch-probe"


def _location(matcher):
    loc = matcher.location
    filename = getattr(loc, "filename", None)
    if filename is None:
        text = str(loc)
        filename, _, line = text.rpartition(":")
        return (str(filename).replace(os.sep, "/"),
                int(line) if line.isdigit() else 0)
    return (str(filename).replace(os.sep, "/"),
            int(getattr(loc, "line", 0) or 0))


def _definitions(registry) -> list:
    out = []
    for keyword in ("given", "when", "then", "step"):
        for m in registry.steps[keyword]:
            f, line = _location(m)
            out.append({"file": f, "line": line, "keyword": keyword,
                        "pattern": m.pattern,
                        "func": getattr(m.func, "__name__", None),
                        "matcher": getattr(m, "NAME", type(m).__name__)})
    return out


def _one_item(entry: dict, steps_dir: str, registry, model) -> dict:
    """Install one item's module, import it, ask behave about every step."""
    # A fresh directory AND a fresh registry.  Either one alone is not
    # isolation: a leftover module would be imported beside this one, and a
    # leftover registration would answer for it.
    if os.path.isdir(steps_dir):
        shutil.rmtree(steps_dir)
    os.makedirs(steps_dir)
    module_path = os.path.join(steps_dir, entry["module"])
    with open(module_path, "w", encoding="utf-8") as fh:
        fh.write(entry["code"])
    registry.clear()

    from behave.runner_util import load_step_modules
    from behave.step_registry import AmbiguousStep

    result = {"item_id": entry["item_id"], "module": entry["module"],
              "ambiguous": None, "load_error": None,
              "n_definitions": 0, "n_steps": len(entry["steps"]),
              "unresolved": [], "foreign": [], "overmatched": [],
              "matchers": []}
    try:
        load_step_modules([steps_dir])
    except AmbiguousStep as e:
        # The failure this whole design exists to avoid.  Recorded per item
        # rather than raised, so one bad item names itself instead of
        # stopping the corpus and hiding the other 238 answers.
        result["ambiguous"] = f"{type(e).__name__}: {e}"
        return result
    except Exception:                                        # noqa: BLE001
        result["load_error"] = traceback.format_exc()
        return result

    definitions = _definitions(registry)
    result["n_definitions"] = len(definitions)
    result["matchers"] = sorted({d["matcher"] for d in definitions})
    result["definitions"] = definitions
    ours = {d["file"] for d in definitions}

    for want in entry["steps"]:
        keyword = str(want["keyword"]).lower()
        text = want["text"]
        step = model.Step("<r2t>", 0, keyword.title(), keyword, text)
        found = registry.find_step_definition(step)
        if found is None:
            result["unresolved"].append([keyword, text])
            continue
        f, line = _location(found)
        if f not in ours or not f.endswith(entry["module"]):
            # Impossible while the directory holds one module, which is
            # exactly why it is checked: a leftover file would show up here
            # rather than as a silently passing acceptance.
            result["foreign"].append([keyword, text, f, line])
        longer = model.Step("<r2t>", 0, keyword.title(), keyword,
                            text + _OVERMATCH_SUFFIX)
        if registry.find_step_definition(longer) is not None:
            result["overmatched"].append([keyword, text])
    return result


# ------------------------------------------------------------------- probes
def _probes() -> dict:
    """The four behave facts the generator's design rests on, in the image.

    Each is a premise of `r2t.toolkit.stub_py`, and each would fail SILENTLY if a
    behave upgrade changed it: an unanchored pattern answers for longer steps,
    a pattern behave refuses raises at import for every item, and a registry
    that stopped raising `AmbiguousStep` would make the isolated install/import
    cycle look unnecessary right up until two definitions answered one step.
    """
    from behave.matchers import get_step_matcher_factory, make_step_matcher
    from behave.step_registry import AmbiguousStep, StepRegistry

    out: dict = {}
    factory = get_step_matcher_factory()

    def noop(context):
        pass

    # 1. `use_step_matcher("re")` selects the matcher that anchors for you.
    cls = factory.step_matcher_class_mapping.get("re")
    out["re_matcher_class"] = getattr(cls, "__name__", None)
    m = cls(noop, r"a\ run")
    out["re_wraps_pattern"] = m.pattern
    out["re_anchors_both_ends"] = bool(m.match("a run")) and \
        not m.match("a run with text")

    # 2. ...and refuses a pattern that already carries a marker, which is why
    #    the generator emits `re.escape(text)` and nothing else.
    try:
        cls(noop, r"a\ run$")
        out["re_refuses_own_markers"] = False
    except ValueError as e:
        out["re_refuses_own_markers"] = "begin/end-markers" in str(e)

    # 3. ...so a literal trailing `$` has to be spelled `\x24`, and that
    #    spelling still matches exactly one text.
    m24 = cls(noop, r"costs\ 5\x24")
    out["hex_escaped_dollar_matches"] = bool(m24.match("costs 5$")) and \
        not m24.match("costs 5$ more")

    # 4. AmbiguousStep fires at REGISTRATION, is keyword-scoped, and the
    #    same-location escape hatch does not save two different files.
    reg = StepRegistry()
    a = make_step_matcher(noop, r"a\ run", "given")
    a.location.filename = "features/steps/stub_a.py"
    reg.steps["given"].append(a)
    try:
        reg.add_step_definition("given", r"a\ run", noop)
        out["ambiguous_at_registration"] = False
    except AmbiguousStep:
        out["ambiguous_at_registration"] = True
    reg2 = StepRegistry()
    reg2.add_step_definition("given", r"a\ run", noop)
    try:
        reg2.add_step_definition("then", r"a\ run", noop)
        out["ambiguity_is_keyword_scoped"] = True
    except AmbiguousStep:
        out["ambiguity_is_keyword_scoped"] = False
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--steps-dir", dest="steps_dir", default="features/steps",
                    help="relative to --root; emptied before every item, so "
                         "it must be scratch and never the corpus's own")
    ap.add_argument("--stubs", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--probe", action="store_true",
                    help="also pin the behave facts the generator relies on")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    os.chdir(root)          # so behave's FileLocation is workspace-relative
    steps_dir = os.path.join(root, args.steps_dir)

    with open(args.stubs, encoding="utf-8") as fh:
        wanted = json.load(fh)

    import behave
    from behave import model
    from behave.step_registry import registry

    results = []
    for entry in wanted.get("items", []):
        results.append(_one_item(entry, steps_dir, registry, model))

    n_bad = sum(1 for r in results
                if r["ambiguous"] or r["load_error"] or r["unresolved"]
                or r["foreign"] or r["overmatched"])
    doc = {
        "schema": SCHEMA,
        "framework": "behave",
        # The evidence that this ran where it claims to have run.  The host
        # refuses a document whose `docker_env` is false: an acceptance run
        # against the operator's own behave says nothing about the run.
        "behave_version": behave.__version__,
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "docker_env": os.path.exists("/.dockerenv"),
        "root": root,
        "steps_dir": args.steps_dir,
        "n_items": len(results),
        "n_items_with_problems": n_bad,
        "n_definitions": sum(r["n_definitions"] for r in results),
        "n_steps": sum(r["n_steps"] for r in results),
        "results": results,
        "probes": _probes() if args.probe else None,
    }
    payload = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload)
    else:
        sys.stdout.write(payload)
    shutil.rmtree(steps_dir, ignore_errors=True)
    sys.stderr.write(
        "stub acceptance: %d items, %d definitions registered, %d steps "
        "asked, %d items with problems [behave %s, python %s]\n"
        % (len(results), doc["n_definitions"], doc["n_steps"], n_bad,
           doc["behave_version"], doc["python_version"]))
    return 0 if n_bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
