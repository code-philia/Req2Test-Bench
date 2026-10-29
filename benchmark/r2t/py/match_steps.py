"""Step -> step-definition matching, done by BEHAVE'S OWN registry.

The twin of `r2t/php/match_steps.php`, written under the same rule and for the
same reason.  Re-implementing behave's matching in the harness would be a
SECOND source of truth: python-docx's 467 definitions are `parse` patterns
(`a font having {color} highlighting`, `{count:d} runs`), `parse` compiles
them to regexes through a type registry that user code can extend at import
time, and any project may flip to `re` patterns mid-module with
`use_step_matcher("re")`.  A Python-side approximation of that would be right
until the day it was not, and the day it was not the benchmark would score a
scenario against glue behave never called.

So the matching happens HERE, inside `r2t_docx_img:base`, against the
installed behave: the same `load_step_modules` that a real run uses, the same
`StepRegistry`, the same `find_step_definition`, the same per-matcher
`match()`.  This program never compiles a pattern of its own.

Two behave facts are reproduced rather than assumed, and they are the two the
PHP twin had to state as well — with opposite answers, which is exactly why
they are stated:

* **behave matches PER KEYWORD.**  `find_step_definition` looks in
  `registry.steps[step.step_type]` and appends `registry.steps["step"]`;
  Behat's `RepositorySearchEngine` never consults the type at all.  So the
  input here is (keyword, text) PAIRS, and an `And`/`But` must already have
  been resolved to the concrete keyword it inherits (`pystep_index`).
* **behave takes the FIRST match; Behat raises on the second.**  behave
  raises `AmbiguousStep` at REGISTRATION when a new pattern matches an
  existing pattern's own text, but two patterns can both match a concrete
  step without either matching the other — 70 of python-docx's 1159 step
  texts are that case.  `find_step_definition` returns the first candidate in
  registration order, so that is the binding recorded, and every other
  candidate is recorded beside it as evidence rather than discarded.

Usage (mirrors match_steps.php):

    python match_steps.py --root /work --steps-dir features/steps \\
        --src src --steps _bench/steps.json --out _bench/matches.json

steps.json  = {"steps": [{"keyword": "given", "text": "a font"}, ...]}
matches.json = the `r2t.pymatches/1` document described in `_document`.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import traceback

#: `{name:Type}` in a `parse` pattern.  Used ONLY to ask "which of the types
#: this project registered does this pattern name", never to match a step:
#: the type names come from behave's live registry and the answer is
#: intersected with it, so a wrong reading of the braces can add nothing that
#: is not a registered type.  It exists because `register_type` is behave's
#: replacement for Behat's `@Transform`, the registry is global, and a pattern
#: in one module may therefore depend on a `register_type` call in another —
#: a code edge with no import behind it, which the closure would otherwise
#: miss.
_TYPED_FIELD = re.compile(r"\{[^{}:]*:([^{}]+)\}")

SCHEMA = "r2t.pymatches/1"


def _location(matcher) -> tuple[str, int]:
    loc = matcher.location
    filename = getattr(loc, "filename", None)
    if filename is None:                       # very old/odd behave
        text = str(loc)
        filename, _, line = text.rpartition(":")
        return (filename.replace(os.sep, "/"), int(line) if line.isdigit() else 0)
    return (str(filename).replace(os.sep, "/"), int(getattr(loc, "line", 0) or 0))


def _custom_type_names(pattern: str, registered: set) -> list:
    return sorted({t.strip() for t in _TYPED_FIELD.findall(pattern)}
                  & registered)


def _document(steps_dirs, definitions, matches, match_errors, registered,
              root, load_error=None) -> dict:
    import behave
    return {
        "schema": SCHEMA,
        "framework": "behave",
        # The evidence that this ran where it claims to have run.  The host
        # refuses a matches file whose `docker_env` is false: a matcher that
        # silently fell back to the operator's own interpreter would be
        # matching against whatever behave that machine happens to carry,
        # and the resulting closures would describe a run nobody will make.
        "behave_version": behave.__version__,
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "docker_env": os.path.exists("/.dockerenv"),
        "root": root,
        "steps_dirs": list(steps_dirs),
        "n_step_definitions": len(definitions),
        "custom_types": sorted(registered),
        "definitions": definitions,
        "matches": matches,
        "match_errors": match_errors,
        "load_error": load_error,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=".",
                    help="the workspace root; every path below is relative "
                         "to it and every path reported is too")
    ap.add_argument("--steps-dir", action="append", default=None,
                    help="a behave steps directory (repeatable). behave's own "
                         "PathManager puts each on sys.path, in order")
    ap.add_argument("--src", default=None,
                    help="a directory to put on sys.path BEFORE loading, for "
                         "projects whose step modules import the library "
                         "under test at module scope (python-docx does)")
    ap.add_argument("--steps", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    steps_dirs = args.steps_dir or ["features/steps"]
    os.chdir(root)          # so behave's FileLocation is workspace-relative

    if args.src:
        sys.path.insert(0, os.path.join(root, args.src))

    with open(args.steps, encoding="utf-8") as fh:
        wanted = json.load(fh)

    from behave import model
    from behave.matchers import ParseMatcher
    from behave.runner_util import load_step_modules
    from behave.step_registry import registry

    # A step module that raises at import time is a broken TREE, not a broken
    # step: every closure downstream would be missing whatever that module
    # registers, and silently.  Refuse, and say which module.
    try:
        load_step_modules([os.path.join(root, d) for d in steps_dirs])
    except Exception:                                        # noqa: BLE001
        doc = _document(steps_dirs, [], [], [], set(), root,
                        load_error=traceback.format_exc())
        _emit(doc, args.out)
        sys.stderr.write("REFUSED: a step module failed to load; see "
                         "load_error in the output document\n")
        return 3

    registered = set(getattr(ParseMatcher, "TYPE_REGISTRY", {}) or {})

    definitions = []
    seen_ids = {}
    for keyword in ("given", "when", "then", "step"):
        for m in registry.steps[keyword]:
            f, line = _location(m)
            entry = {"file": f, "line": line, "keyword": keyword,
                     "pattern": m.pattern,
                     "func": getattr(m.func, "__name__", None),
                     "matcher": getattr(m, "NAME", type(m).__name__),
                     "custom_types": _custom_type_names(m.pattern, registered)}
            seen_ids[id(m)] = entry
            definitions.append(entry)

    matches = []
    match_errors = []
    for want in wanted.get("steps", []):
        keyword = str(want["keyword"]).lower()
        text = want["text"]
        if keyword not in ("given", "when", "then"):
            # `step` is a DEFINITION keyword, never a step's own: a Gherkin
            # line is Given/When/Then after And/But resolution or it is not a
            # step behave will run.
            sys.stderr.write(f"REFUSED: step keyword {keyword!r} is not one "
                             f"of given/when/then (text: {text!r})\n")
            return 2
        step = model.Step("<r2t>", 0, keyword.title(), keyword, text)

        # Candidates exactly as `StepRegistry.find_step_definition` builds
        # them: the keyword's own list plus the keyword-agnostic `step` list.
        candidates = list(registry.steps[keyword]) + list(registry.steps["step"])
        hit_entries = []
        for cand in candidates:
            try:
                if cand.match(text):
                    hit_entries.append(seen_ids[id(cand)])
            except Exception as e:                           # noqa: BLE001
                match_errors.append({"pattern": cand.pattern,
                                     "text": text,
                                     "error": f"{type(e).__name__}: {e}"})

        chosen = registry.find_step_definition(step)
        chosen_entry = seen_ids.get(id(chosen)) if chosen is not None else None
        if chosen_entry is not None and hit_entries \
                and chosen_entry is not hit_entries[0]:
            # behave's own answer and the first candidate must be the same
            # object; if they ever are not, this program's model of the
            # registry is wrong and every closure built from it is suspect.
            match_errors.append({"pattern": chosen_entry["pattern"],
                                 "text": text,
                                 "error": "find_step_definition disagreed "
                                          "with the candidate order"})
        # `candidates` carries the WHOLE entry rather than a `file:line`
        # label: the closure extractor has to be able to prefer a RETAINED
        # provider over a removable twin of the same pattern, and it cannot do
        # that from a string it would have to re-join against `definitions`.
        matches.append({"keyword": keyword, "text": text,
                        "definition": chosen_entry,
                        "n_candidates": len(hit_entries),
                        "candidates": hit_entries})

    doc = _document(steps_dirs, definitions, matches, match_errors, registered,
                    root)
    _emit(doc, args.out)
    unmatched = sum(1 for m in matches if m["definition"] is None)
    sys.stderr.write(
        "matched %d (keyword, text) pairs against %d definitions "
        "[behave %s, python %s]: %d unmatched, %d ambiguous, %d errors\n"
        % (len(matches), len(definitions), doc["behave_version"],
           doc["python_version"], unmatched,
           sum(1 for m in matches if m["n_candidates"] > 1), len(match_errors)))
    return 0


def _emit(doc: dict, out) -> None:
    payload = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(payload)
    else:
        sys.stdout.write(payload)


if __name__ == "__main__":
    raise SystemExit(main())
