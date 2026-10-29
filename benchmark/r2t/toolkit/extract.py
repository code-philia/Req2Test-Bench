#!/usr/bin/env python3
"""Benchmark item extractor — requirement/criterion -> test generation.

Emits ONE JSONL record per benchmark item from a set of BDD projects.

TWO TASKS (both are emitted; `task` distinguishes them):

  criterion_to_test  — input: the Gherkin scenario (the acceptance
      criterion, authored by the project's own developers) plus its
      feature context. Output expected from the system under test:
      the STEP-DEFINITION code that makes it executable.
  requirement_to_test — input: the feature-level requirement (title,
      plus the authored narrative when one exists). Output expected:
      the Gherkin scenario(s) AND their step definitions.

REQUIREMENT RICHNESS is a first-class field, not an accident of the
corpus: BDD projects differ in how much requirement text they author
above the scenarios, and that variation supports the ablation "how
much does a user story actually help generation?".

  user_story  — "In order to ... / As a ... / I want|need ..."
  prose       — a free-text description under `Feature:`
  title_only  — the `Feature:` line and nothing else

Provenance is recorded per item (upstream URL, commit, commit date,
path, line, and the file's own last-touching commit) so that
contamination against a model's training cutoff can be analysed LATER
without re-extracting. No leakage policy is applied here by design.

Nothing in this module scores anything: it prepares inputs only.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from ..core.paths import BENCHMARK_ROOT, CONFIG_DIR

# Gherkin block keywords that terminate a narrative or a scenario body.
_BLOCK = re.compile(
    r"^\s*(Feature|Background|Scenario Outline|Scenario Template|Scenario"
    r"|Example|Examples|Scenarios|Rule)\s*:")
_FEATURE = re.compile(r"^\s*Feature\s*:\s*(.*)$")
_SCENARIO = re.compile(
    r"^\s*(Scenario Outline|Scenario Template|Scenario|Example)\s*:\s*(.*)$")
_BACKGROUND = re.compile(r"^\s*Background\s*:")
_EXAMPLES = re.compile(r"^\s*(Examples|Scenarios)\s*:")
_TAG = re.compile(r"^\s*@")
# "In order to / As a / I want|need" — the canonical Connextra-style story.
_STORY = re.compile(r"\b(in order to|as an?\b|i want|i need)\b", re.I)

LANGS = {
    ".php": ("php", "behat"),
    ".java": ("java", "cucumber"),
    ".py": ("python", "behave"),
}


def _git(repo, *args):
    """Best-effort git query; returns '' when the tree is not a repo."""
    try:
        r = subprocess.run(["git", *args], cwd=repo, capture_output=True,
                           text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def repo_provenance(repo):
    """Where this project came from — or a refusal, never a plausible guess.

    Every `git` command here runs with `cwd=repo`, and git WALKS UP: a
    checkout with no `.git` of its own answers with the enclosing repository's
    remote, HEAD and dates. That is not a missing answer, it is a wrong one
    wearing the shape of a right one, and it is already in the corpus — the
    python-pptx and algorand-sdk trees were unpacked inside a wrapper
    checkout, so 645 of the 2859 items in `items.jsonl` claim
    `code-philia/ReqEnhancement.git` as their upstream, carry that repo's
    commit, and have a null `file_date` because `git log -- <rel>` found
    nothing at that path. Contamination analysis reads exactly those fields.

    So the toplevel is checked before anything is recorded. Absence is
    tolerable and would have been recorded as nulls; mislabelling is not.
    """
    toplevel = _git(repo, "rev-parse", "--show-toplevel")
    if not toplevel or os.path.realpath(toplevel) != os.path.realpath(repo):
        raise SystemExit(
            f"REFUSED: {repo} is not the toplevel of a git repository "
            f"(toplevel: {toplevel or 'none'}). Provenance recorded from an "
            f"enclosing repo silently mislabels every item — 645 items in "
            f"items.jsonl carry the wrapper repo's URL because this check did "
            f"not exist. Re-clone the project with its own .git and "
            f"re-extract.")
    url = _git(repo, "config", "--get", "remote.origin.url")
    head = _git(repo, "rev-parse", "HEAD")
    when = _git(repo, "log", "-1", "--format=%cI")
    return {"repo_url": url or None,
            "commit": head or None,
            "commit_date": when or None}


def file_provenance(repo, rel):
    """The file's OWN last-touching commit — the timestamp that matters
    for contamination analysis (a scenario written after a model's
    cutoff cannot have been memorised)."""
    out = _git(repo, "log", "-1", "--format=%H|%cI", "--", rel)
    if "|" in out:
        commit, when = out.split("|", 1)
        return {"file_commit": commit, "file_date": when}
    return {"file_commit": None, "file_date": None}


def classify_richness(narrative):
    if not narrative or not narrative.strip():
        return "title_only"
    return "user_story" if _STORY.search(narrative) else "prose"


def parse_feature(text):
    """Parse one .feature file.

    Returns {title, narrative, background, scenarios:[{title, line,
    kind, gherkin}]}. Line numbers are 1-based and point at the
    scenario's own keyword line, matching the `path:line` item ids used
    elsewhere in this project.
    """
    lines = text.split("\n")
    title, narrative_lines = None, []
    feature_line = None
    for i, ln in enumerate(lines):
        m = _FEATURE.match(ln)
        if m:
            title = m.group(1).strip()
            feature_line = i
            break
    if feature_line is None:
        return None
    # narrative: everything between `Feature:` and the first block
    # keyword or tag line
    for ln in lines[feature_line + 1:]:
        if _BLOCK.match(ln) or _TAG.match(ln):
            break
        narrative_lines.append(ln)
    narrative = "\n".join(narrative_lines).strip("\n")

    def block_at(start):
        """Return a trimmed block plus its physical and retained stops.

        Trailing blank and comment-only lines are dropped. A
        commented-out scenario (`#  Scenario: ...`) does not match the
        block keywords, so without this it is swallowed into the
        PRECEDING live scenario and would be handed to the model as
        part of the criterion — observed in CoreShop's
        features/domain/currency/context.feature, whose disabled
        scenario is a known corpus defect.
        """
        out = [lines[start]]
        stop = len(lines)
        for index, ln in enumerate(lines[start + 1:], start + 1):
            if _BLOCK.match(ln) or _TAG.match(ln):
                stop = index
                break
            out.append(ln)
        while out and (not out[-1].strip()
                       or out[-1].lstrip().startswith("#")):
            out.pop()
        return "\n".join(out).rstrip(), stop, start + len(out)

    background = None
    scenarios = []
    for i, ln in enumerate(lines):
        if _BACKGROUND.match(ln) and background is None:
            background, _stop, _kept_stop = block_at(i)
            continue
        m = _SCENARIO.match(ln)
        if m:
            # An `Examples:`-bearing outline keeps its table: block_at
            # stops at `Examples:`, so re-extend through every table. Use
            # the physical stop index rather than the trimmed body length:
            # real suites commonly leave blank/comment lines before the
            # table, and trimming them must not move the source cursor.
            body, j, body_end = block_at(i)
            while j < len(lines):
                while j < len(lines) and (
                        not lines[j].strip()
                        or lines[j].lstrip().startswith("#")
                        or _TAG.match(lines[j])):
                    j += 1
                if j >= len(lines) or not _EXAMPLES.match(lines[j]):
                    break
                examples_start = j
                examples, j, next_body_end = block_at(examples_start)
                gap = lines[body_end:examples_start]
                body += "\n" + "\n".join([*gap, examples])
                body_end = next_body_end
            scenarios.append({
                "title": m.group(2).strip(),
                "line": i + 1,
                "kind": m.group(1).strip(),
                "gherkin": body,
            })
    return {"title": title, "narrative": narrative,
            "background": background, "scenarios": scenarios}


# Build outputs and dependency trees. `target/test-classes` in a Maven
# project is a verbatim COPY of `src/test/resources`: walking it doubled
# epubcheck (1041 scenarios counted twice) until this list existed.
_SKIP_DIRS = {".git", "node_modules", "vendor", "target", "build", "dist",
              "out", ".tox", ".venv", "venv", "__pycache__", ".gradle",
              ".mvn", "site-packages"}


def iter_feature_files(root, subdir=None):
    base = os.path.join(root, subdir) if subdir else root
    for dirpath, dirnames, files in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for f in sorted(files):
            if f.endswith(".feature"):
                yield os.path.join(dirpath, f)


def extract_project(name, root, subdir=None, language=None, framework=None):
    """All items for one project. Emits criterion_to_test items (one per
    scenario) and requirement_to_test items (one per feature)."""
    if not os.path.isdir(root):
        raise SystemExit(f"project {name}: {root} is not a directory")
    prov = repo_provenance(root)
    items, n_features, skipped = [], 0, []
    for path in iter_feature_files(root, subdir):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError as e:
            skipped.append((rel, str(e)))
            continue
        feat = parse_feature(text)
        if feat is None or not feat["scenarios"]:
            skipped.append((rel, "no Feature: header or no scenarios"))
            continue
        n_features += 1
        fprov = file_provenance(root, rel)
        richness = classify_richness(feat["narrative"])
        lang, fw = language, framework
        req = {
            "richness": richness,
            "feature_title": feat["title"],
            "narrative": feat["narrative"] or None,
            "background": feat["background"],
        }
        base_prov = dict(prov, file_path=rel, **fprov)

        for sc in feat["scenarios"]:
            items.append({
                "item_id": f"{name}/{rel}:{sc['line']}",
                "task": "criterion_to_test",
                "project": name,
                "language": lang,
                "framework": fw,
                "provenance": dict(base_prov, line=sc["line"]),
                "requirement": req,
                "criterion": {
                    "scenario_title": sc["title"],
                    "kind": sc["kind"],
                    "gherkin": sc["gherkin"],
                },
                "expected_output": ["step_definitions"],
            })
        items.append({
            "item_id": f"{name}/{rel}",
            "task": "requirement_to_test",
            "project": name,
            "language": lang,
            "framework": fw,
            "provenance": dict(base_prov, line=None),
            "requirement": req,
            "criterion": None,
            "reference_scenarios": [
                {"title": s["title"], "line": s["line"]}
                for s in feat["scenarios"]],
            "expected_output": ["gherkin", "step_definitions"],
        })
    return items, {"features": n_features, "skipped": skipped}


# ------------------------------------------------------------------ corpora

CORPORA_CONFIG = os.path.join(CONFIG_DIR, "corpora.yml")

# The five arguments `extract_project()` takes.  Everything else in a
# corpora.yml entry is IDENTITY (which upstream, which commit) — read by
# `verify_checkout`, never by the walk.
_PROJECT_FIELDS = ("name", "root", "subdir", "language", "framework")
_IDENTITY_FIELDS = ("upstream", "resolved_commit", "pinned_commit", "why")
# Optional, and enumerated rather than tolerated: an entry with a key nobody
# reads is a claim nobody checks.  algorand-sdk needs these because its
# Gherkin and its step definitions live in different repositories.
_OPTIONAL_FIELDS = ("step_definitions_upstream", "step_definitions_commit",
                    "step_definitions_root")

_SHA1 = re.compile(r"^[0-9a-f]{40}$")


def _refuse(path, why):
    raise SystemExit(f"REFUSED: {path}: {why}")


def load_corpora(path=CORPORA_CONFIG):
    """Read `config/corpora.yml`. The corpus list has one source: this file.

    Every check here is a refusal rather than a repair. A corpus file is the
    one place that says which tree a published item id came from; a typo in it
    is not a value to be defaulted, and a key nobody reads is a claim nobody
    checks. An absent file is refused the same way, by name, rather than
    silently answered with a different corpus.
    """
    if not os.path.isfile(path):
        _refuse(path, "does not exist; the corpus list has one source and "
                      "this is it")
    try:
        import yaml
    except ImportError:
        # The file exists, so the corpus it describes is the intended one.
        # Falling back to the literals here would silently extract a DIFFERENT
        # corpus than the one recorded beside them.
        _refuse(path, "exists but PyYAML is not importable, so the recorded "
                      "corpus cannot be read; install PyYAML (the rest of "
                      "this benchmark already requires it) or move the file "
                      "aside deliberately")
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    if not isinstance(doc, dict):
        _refuse(path, "top level is not a mapping")
    unknown = set(doc) - {"version", "projects", "evaluated_and_excluded"}
    if unknown:
        _refuse(path, f"unknown top-level key(s) {sorted(unknown)}")
    if doc.get("version") != 1:
        _refuse(path, f"unsupported version {doc.get('version')!r} (want 1)")
    projects = doc.get("projects")
    if not isinstance(projects, list) or not projects:
        _refuse(path, "`projects` must be a non-empty list")

    seen = set()
    for entry in projects:
        if not isinstance(entry, dict):
            _refuse(path, f"project entry is not a mapping: {entry!r}")
        name = entry.get("name")
        missing = [k for k in _PROJECT_FIELDS + _IDENTITY_FIELDS
                   if k not in entry]
        if missing:
            _refuse(path, f"project {name!r} is missing {missing}")
        extra = set(entry) - set(_PROJECT_FIELDS) - set(_IDENTITY_FIELDS) \
            - set(_OPTIONAL_FIELDS)
        if extra:
            _refuse(path, f"project {name!r} carries unknown key(s) "
                          f"{sorted(extra)} — add them to _OPTIONAL_FIELDS in "
                          f"r2t/toolkit/extract.py if they are meant to be read")
        if not isinstance(name, str) or not name:
            _refuse(path, f"project name must be a non-empty string: {name!r}")
        if name in seen:
            _refuse(path, f"duplicate project name {name!r}")
        seen.add(name)
        if not isinstance(entry["root"], str) or not entry["root"] \
                or os.path.isabs(entry["root"]):
            _refuse(path, f"project {name!r}: `root` must be relative to "
                          "R2T_DATA_ROOT")
        sub = entry["subdir"]
        if sub is not None and (not isinstance(sub, str) or not sub
                                or os.path.isabs(sub)):
            _refuse(path, f"project {name!r}: `subdir` must be null or a "
                          f"relative path")
        for key in ("language", "framework", "upstream", "why"):
            if not isinstance(entry[key], str) or not entry[key].strip():
                _refuse(path, f"project {name!r}: `{key}` must be a non-empty "
                              f"string")
        if not _SHA1.match(str(entry["resolved_commit"])):
            _refuse(path, f"project {name!r}: `resolved_commit` is not a "
                          f"40-character sha: {entry['resolved_commit']!r}")
        pin = entry["pinned_commit"]
        if pin is not None and not _SHA1.match(str(pin)):
            _refuse(path, f"project {name!r}: `pinned_commit` must be null or "
                          f"a 40-character sha: {pin!r}")
        # The step-definitions trio gets the same treatment as the fields
        # above, for the same reason: it is recorded IDENTITY. An unchecked
        # `step_definitions_commit` is a sha-shaped string nobody ever
        # compared to a checkout — precisely the "written down, therefore
        # true" habit this file was built to break. All three or none: a
        # commit without an upstream names nothing, and an upstream without
        # a commit dates nothing.
        present = [k for k in _OPTIONAL_FIELDS if k in entry]
        if present and len(present) != len(_OPTIONAL_FIELDS):
            _refuse(path, f"project {name!r}: carries {sorted(present)} but "
                          f"not {sorted(set(_OPTIONAL_FIELDS) - set(present))}"
                          f" — record the step definitions' upstream, commit "
                          f"and root together or not at all")
        if present:
            if not _SHA1.match(str(entry["step_definitions_commit"])):
                _refuse(path, f"project {name!r}: `step_definitions_commit` "
                              f"is not a 40-character sha: "
                              f"{entry['step_definitions_commit']!r}")
            up = entry["step_definitions_upstream"]
            if not isinstance(up, str) or not up.strip():
                _refuse(path, f"project {name!r}: `step_definitions_upstream` "
                              f"must be a non-empty string")
            sroot = entry["step_definitions_root"]
            if not isinstance(sroot, str) or not sroot or os.path.isabs(sroot):
                _refuse(path, f"project {name!r}: `step_definitions_root` "
                              f"must be relative to R2T_DATA_ROOT: {sroot!r}")

    excluded = doc.get("evaluated_and_excluded") or []
    if not isinstance(excluded, list):
        _refuse(path, "`evaluated_and_excluded` must be a list")
    for entry in excluded:
        if not isinstance(entry, dict) or not entry.get("name"):
            _refuse(path, f"excluded entry needs a name: {entry!r}")
        if not str(entry.get("reason") or "").strip():
            _refuse(path, f"excluded project {entry['name']!r} has no reason "
                          f"— dropping a project silently is the thing this "
                          f"section exists to prevent")
        if entry["name"] in seen:
            _refuse(path, f"project {entry['name']!r} is both extracted and "
                          f"excluded")
    doc["evaluated_and_excluded"] = excluded
    return doc


def corpus_entries():
    """The corpus as recorded — full entries from config/corpora.yml."""
    doc = load_corpora()
    entries = [dict(p) for p in doc["projects"]]
    from r2t.core.paths import resolve_config_path
    for entry in entries:
        entry["root"] = os.fspath(resolve_config_path(entry["root"]))
        if entry.get("step_definitions_root"):
            entry["step_definitions_root"] = os.fspath(
                resolve_config_path(entry["step_definitions_root"]))
    return entries


def default_projects():
    """The corpora currently on this machine, as `extract_project` wants
    them. `subdir` narrows the walk to the suite under study (CoreShop's
    domain suite is the one the pilot instrumented)."""
    return [{k: e[k] for k in _PROJECT_FIELDS} for e in corpus_entries()]


def require_roots(projects):
    """Every recorded root must be on this machine. Absent is a REFUSAL.

    This used to print `ABSENT` and carry on, which meant a missing tree
    produced an `items.jsonl` quietly short one whole project while every
    count downstream — README's scale table, SPEC's pipeline row, the
    related-work item total — went on claiming it. That is the shape of
    silent repair the corpus file exists to end: a root that is not there
    means this is not the machine `corpora.yml` describes, so say which
    ones and stop. `--project` is the way to extract a subset on purpose.
    """
    missing = [(p["name"], p["root"]) for p in projects
               if not os.path.isdir(p["root"])]
    if missing:
        listing = "\n".join(f"    {n}: {r}" for n, r in missing)
        raise SystemExit(
            f"REFUSED: {len(missing)} recorded corpus root(s) are not on "
            f"this machine:\n{listing}\n  Extracting without them would "
            f"write an items.jsonl that is missing whole projects while "
            f"every headline count still claims them. Clone the missing "
            f"tree(s) at the commit config/corpora.yml records, or pass "
            f"--project to extract a subset deliberately.")


def verify_checkout(entry):
    """Does the tree agree with what the corpus file says it is?

    Returns notes to print; RAISES when the disagreement would mislabel
    items. The distinction is the point: an upstream mismatch means every
    `repo_url` this project emits is a lie, and a moved PIN means item ids
    that other artifacts already reference are about to be re-minted —
    neither is recoverable by defaulting. An unpinned project that has moved
    is expected (it tracks its default branch), so it is a note, and the note
    says the file now needs updating.
    """
    notes, root, name = [], entry["root"], entry["name"]
    if not entry.get("upstream"):
        return notes
    url = _git(root, "config", "--get", "remote.origin.url")
    if url != entry["upstream"]:
        raise SystemExit(
            f"REFUSED: {name}: {root} has origin {url or 'none'!r}, but "
            f"config/corpora.yml records {entry['upstream']!r}. Every item's "
            f"`repo_url` is read from that remote, so extracting here would "
            f"label {name} with the wrong upstream — the exact defect that "
            f"cost 645 items their provenance.")
    head = _git(root, "rev-parse", "HEAD")
    pin = entry.get("pinned_commit")
    if pin and head != pin:
        raise SystemExit(
            f"REFUSED: {name}: {root} is at {head or 'unknown'}, but "
            f"config/corpora.yml pins {pin}. The pin exists because artifacts "
            f"already reference this project's item ids; re-check out the "
            f"pinned commit, or change the pin deliberately and re-run the "
            f"byte-identity gate.")
    if not pin and head and head != entry.get("resolved_commit"):
        notes.append(
            f"  note: {name} is at {head[:7]}, corpora.yml records "
            f"{str(entry.get('resolved_commit'))[:7]} — items are being "
            f"re-minted; update `resolved_commit` after this run")
    return notes


def selftest():
    """Parser checks on hand-written fixtures (no repo access)."""
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    story = """Feature: Add a table
  In order to fulfill a requirement for a table
  As a developer using python-docx
  I need the ability to add a table

  Scenario: Access a table
     Given a document containing a table
      Then I can access the table
"""
    f = parse_feature(story)
    check("user-story narrative parsed", f["title"] == "Add a table")
    check("richness=user_story",
          classify_richness(f["narrative"]) == "user_story")
    check("one scenario, line 6",
          len(f["scenarios"]) == 1 and f["scenarios"][0]["line"] == 6,
          str(f["scenarios"]))
    check("scenario body kept whole",
          "Then I can access the table" in f["scenarios"][0]["gherkin"])

    bare = """@domain @cart
Feature: Adding a new Product

  Background:
    Given the site operates on a store in "Austria"

  Scenario: Test one
    Given a thing
  Scenario: Test two
    Given another
"""
    f = parse_feature(bare)
    check("richness=title_only",
          classify_richness(f["narrative"]) == "title_only",
          repr(f["narrative"]))
    check("background captured", "Austria" in (f["background"] or ""))
    check("two scenarios", len(f["scenarios"]) == 2)
    check("background not counted as scenario",
          all("Austria" not in s["gherkin"] for s in f["scenarios"]))

    prose = """Feature: EPUB checks

  Checks conformance to the specification:
    http://example.org/spec

  Scenario: A check
    Given a file
"""
    f = parse_feature(prose)
    check("richness=prose", classify_richness(f["narrative"]) == "prose",
          repr(f["narrative"]))

    outline = """Feature: F

  Scenario Outline: Templated
    Given <a>

    # The physical gap must not hide the Examples block.
    @positive
    Examples:
      | a |
      | 1 |

    @more
    Scenarios:
      | a |
      | 2 |

  @next
  Scenario: Next
    Given the next scenario
"""
    f = parse_feature(outline)
    check("outline kind recorded",
          f["scenarios"][0]["kind"] == "Scenario Outline")
    check("Examples table retained in the outline body",
          "| 1 |" in f["scenarios"][0]["gherkin"]
          and "Scenarios:" in f["scenarios"][0]["gherkin"]
          and "| 2 |" in f["scenarios"][0]["gherkin"],
          f["scenarios"][0]["gherkin"])
    check("internal blank, comment, and tag lines are retained",
          "\n\n    # The physical gap" in f["scenarios"][0]["gherkin"]
          and "@positive" in f["scenarios"][0]["gherkin"]
          and "@more" in f["scenarios"][0]["gherkin"],
          f["scenarios"][0]["gherkin"])
    check("the next scenario's tag is not retained by the outline",
          len(f["scenarios"]) == 2
          and "@next" not in f["scenarios"][0]["gherkin"],
          f["scenarios"][0]["gherkin"])

    # Regression: a commented-out scenario must neither become an item
    # nor contaminate the live scenario above it (CoreShop
    # currency/context.feature, a known corpus defect).
    disabled = """Feature: Currency

  Scenario: Site should be using currency "USD"
    Then the site should be using currency "USD"

#  Scenario: Customer comes from Country "USA"
#    And I am in country "USA"
"""
    f = parse_feature(disabled)
    check("commented-out scenario is not an item", len(f["scenarios"]) == 1,
          str([s["title"] for s in f["scenarios"]]))
    check("commented-out scenario does not contaminate the live one",
          "#" not in f["scenarios"][0]["gherkin"],
          f["scenarios"][0]["gherkin"])

    check("no Feature: header -> None", parse_feature("Scenario: x") is None)

    # Provenance must be REFUSED rather than inherited from an enclosing
    # repository. These use real `git` on throwaway trees, because the whole
    # defect is a behaviour of `git` (it walks up) rather than of this file.
    import tempfile

    def refused(path):
        try:
            repo_provenance(path)
            return False
        except SystemExit as e:
            return str(e).startswith("REFUSED:")

    def accepted(path):
        try:
            return repo_provenance(path)
        except SystemExit:
            return None

    with tempfile.TemporaryDirectory() as tmp:
        plain = os.path.join(tmp, "no_git")
        os.makedirs(plain)
        # Only meaningful if the temporary directory is not itself inside a
        # checkout; say so rather than reporting a pass this run did not earn.
        if _git(tmp, "rev-parse", "--show-toplevel"):
            print("  [SKIP] no-.git case: the temp dir is inside a repository")
        else:
            check("a tree with no .git anywhere above it is refused",
                  refused(plain))

        top = os.path.join(tmp, "repo")
        os.makedirs(top)
        made = subprocess.run(["git", "init", "-q", top], capture_output=True,
                              text=True).returncode == 0
        check("git is available to build the fixture repository", made)
        if made:
            prov = accepted(top)
            check("a tree that IS its own git toplevel is accepted",
                  prov is not None and set(prov) == {"repo_url", "commit",
                                                     "commit_date"}, str(prov))
            nested = os.path.join(top, "vendored", "python-pptx")
            os.makedirs(nested)
            check("a SUBDIR of a git repo is refused, not labelled with it",
                  refused(nested))

    # ---------------------------------------------------------- corpora.yml
    # The corpus is DATA now.  These checks bind the file to the code that
    # reads it and to the trees it describes: a config that disagrees with
    # the CHECKOUT is the 645-item provenance defect coming back wearing a
    # nicer URL.  The corpus list has one source — an absent file is refused
    # by name, not silently answered with a different corpus.
    with tempfile.TemporaryDirectory() as _tmp:
        missing = os.path.join(_tmp, "corpora.yml")
        msg = None
        try:
            load_corpora(missing)
        except SystemExit as exc:
            msg = str(exc)
        check("a missing corpora.yml is refused by name",
              msg is not None and msg.startswith(f"REFUSED: {missing}"),
              repr(msg))

    try:
        import yaml as _yaml
    except ImportError:
        _yaml = None
    if _yaml is None:
        print("  [SKIP] corpora.yml checks: PyYAML is not importable")
    elif not os.path.isfile(CORPORA_CONFIG):
        print(f"  [SKIP] corpora.yml checks: {CORPORA_CONFIG} is absent")
    else:
        doc = load_corpora()
        names = [p["name"] for p in doc["projects"]]
        check("corpora.yml loads and validates", isinstance(doc, dict))
        check("kedro is not extracted", "kedro" not in names, str(names))
        excluded = {e["name"]: e for e in doc["evaluated_and_excluded"]}
        check("kedro is recorded as evaluated-and-excluded, with a reason",
              "kedro" in excluded
              and len(excluded["kedro"]["reason"].split()) > 20,
              str(sorted(excluded)))
        by_name = {p["name"]: p for p in doc["projects"]}
        check("python-docx is pinned at the commit its items came from",
              by_name["python-docx"]["pinned_commit"]
              == "e45454602b53e8e572b179ccf1c91093ec9f4ed7"
              and by_name["python-docx"]["upstream"]
              == "https://github.com/python-openxml/python-docx.git",
              str(by_name.get("python-docx")))
        # The fixed layout subsumes the old no-scratch-tree assertion: a
        # portable `projects/<name>/source` root cannot spell the scratch
        # checkout.  `require_roots` remains the operator gate that refuses
        # until the external checkout exists.
        check("every corpus root uses the fixed data-root layout",
              all(p["root"] == f"projects/{p['name']}/source"
                  for p in doc["projects"]),
              str({p["name"]: p["root"] for p in doc["projects"]}))
        check("epubcheck is pinned at its slice-3 extraction commit",
              by_name["epubcheck"]["pinned_commit"]
              == "82b174ec319ea3e6c9d2488f84155fa4a9171fc2",
              str(by_name["epubcheck"]))

        # Refusals.  Each fixture is a real corpus file with ONE thing wrong.
        def loads(mutate):
            base = {
                "version": 1,
                "projects": [{"name": "p", "root": "projects/p/source",
                              "subdir": None,
                              "language": "python", "framework": "behave",
                              "upstream": "https://example.invalid/p.git",
                              "resolved_commit": "0" * 40,
                              "pinned_commit": None, "why": "fixture"}],
                "evaluated_and_excluded": [{"name": "dropped",
                                            "reason": "fixture"}]}
            mutate(base)
            with tempfile.TemporaryDirectory() as td:
                path = os.path.join(td, "corpora.yml")
                with open(path, "w", encoding="utf-8") as fh:
                    _yaml.safe_dump(base, fh)
                try:
                    load_corpora(path)
                    return None
                except SystemExit as exc:
                    return str(exc)

        check("a well-formed fixture is accepted",
              loads(lambda d: None) is None)
        for label, mutate in (
                ("an unsupported version",
                 lambda d: d.update(version=2)),
                ("an unknown top-level key",
                 lambda d: d.update(corpora=[])),
                ("a duplicate project name",
                 lambda d: d["projects"].append(dict(d["projects"][0]))),
                ("a missing identity field",
                 lambda d: d["projects"][0].pop("upstream")),
                ("an unread extra key",
                 lambda d: d["projects"][0].update(mirror="yes")),
                ("an absolute root",
                 lambda d: d["projects"][0].update(root="/tmp/p")),
                ("a truncated commit",
                 lambda d: d["projects"][0].update(resolved_commit="0" * 7)),
                ("a project that is both extracted and excluded",
                 lambda d: d["evaluated_and_excluded"].append(
                     {"name": "p", "reason": "fixture"})),
                ("an exclusion with no reason",
                 lambda d: d["evaluated_and_excluded"][0].update(reason=" ")),
                ("a step-definitions commit that is not a sha",
                 lambda d: d["projects"][0].update(
                     step_definitions_upstream="https://example.invalid/s.git",
                     step_definitions_commit="main",
                    step_definitions_root="projects/s/source")),
                ("an absolute step-definitions root",
                 lambda d: d["projects"][0].update(
                     step_definitions_upstream="https://example.invalid/s.git",
                     step_definitions_commit="1" * 40,
                     step_definitions_root="/tmp/s")),
                ("half a step-definitions record",
                 lambda d: d["projects"][0].update(
                     step_definitions_commit="1" * 40)),
        ):
            msg = loads(mutate)
            check(f"corpora.yml with {label} is refused",
                  msg is not None and msg.startswith("REFUSED:"), repr(msg))

    # ----------------------------------------------- the documented scale
    # The headline counts, bound to the file they describe. This is the one
    # thing the adversarial review of this milestone caught: SPEC's pipeline
    # row went on describing an items.jsonl that no longer existed. A number
    # in prose goes stale in silence — the only way it stays true is if
    # something recomputes it. SPEC's S1 row is the one document that states
    # these counts; README's copies went with the one-home-per-fact rule.
    _here = BENCHMARK_ROOT
    _items = os.path.join(_here, "items.jsonl")

    def _doc(name):
        path = os.path.join(_here, name)
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    spec = _doc("SPEC.md")
    if not os.path.isfile(_items):
        print("  [SKIP] documented-scale checks: items.jsonl is absent")
    else:
        crit = req = 0
        incomplete_outlines = []
        seen_projects = set()
        with open(_items, encoding="utf-8") as fh:
            for line in fh:
                it = json.loads(line)
                seen_projects.add(it["project"])
                if it["task"] == "criterion_to_test":
                    crit += 1
                    criterion = it.get("criterion") or {}
                    if criterion.get("kind") in (
                            "Scenario Outline", "Scenario Template") \
                            and not any(_EXAMPLES.match(line) for line in
                                        criterion.get("gherkin", "").splitlines()):
                        incomplete_outlines.append(it["item_id"])
                elif it["task"] == "requirement_to_test":
                    req += 1

        check("every stored outline includes its Examples table",
              not incomplete_outlines, str(incomplete_outlines[:10]))

        if spec is None:
            print("  [SKIP] SPEC pipeline-row check: SPEC.md is absent")
        else:
            s = re.search(r"S1 extract items \| `items\.jsonl` \(([\d,]+) "
                          r"criterion \+ ([\d,]+) requirement, (\d+) projects",
                          spec)
            check("SPEC's S1 pipeline row describes the CURRENT items.jsonl",
                  s is not None
                  and [int(x.replace(",", "")) for x in s.groups()]
                  == [crit, req, len(seen_projects)],
                  f"spec={s and s.groups()} "
                  f"data={crit}/{req}/{len(seen_projects)}")

    # A recorded root that is not on disk. The old behaviour (print ABSENT,
    # keep going) is the one repair this file cannot afford, because its
    # output is silent: a short items.jsonl looks exactly like a full one.
    with tempfile.TemporaryDirectory() as tmp:
        here = {"name": "here", "root": tmp}
        gone = {"name": "gone", "root": os.path.join(tmp, "not-cloned")}
        alsogone = {"name": "alsogone", "root": os.path.join(tmp, "neither")}

        def roots_refused(ps):
            try:
                require_roots(ps)
                return None
            except SystemExit as exc:
                return str(exc)

        check("a corpus whose roots all exist is accepted",
              roots_refused([here]) is None)
        msg = roots_refused([here, gone])
        check("an ABSENT recorded root is refused, not skipped",
              msg is not None and msg.startswith("REFUSED:"), repr(msg))
        msg = roots_refused([gone, here, alsogone])
        check("the refusal names EVERY missing project, not just the first",
              msg is not None and "gone:" in msg and "alsogone:" in msg
              and "--project" in msg, repr(msg))

    # The checkout cross-check, against real `git` on a throwaway repo: the
    # whole point is what git ANSWERS, so a mocked remote would prove nothing.
    with tempfile.TemporaryDirectory() as tmp:
        repo = os.path.join(tmp, "proj")
        os.makedirs(repo)
        url = "https://example.invalid/proj.git"
        built = subprocess.run(["git", "init", "-q", repo],
                               capture_output=True).returncode == 0
        if built:
            open(os.path.join(repo, "f.txt"), "w").write("x\n")
            for cmd in (["git", "add", "f.txt"],
                        ["git", "-c", "user.email=r2t@example.invalid",
                         "-c", "user.name=r2t", "commit", "-q", "-m", "init"],
                        ["git", "remote", "add", "origin", url]):
                subprocess.run(cmd, cwd=repo, capture_output=True)
        head = _git(repo, "rev-parse", "HEAD")
        check("git is available to build the checkout fixture",
              built and bool(head))
        if built and head:
            entry = {"name": "proj", "root": repo, "subdir": None,
                     "language": "python", "framework": "behave",
                     "upstream": url, "resolved_commit": head,
                     "pinned_commit": head, "why": "fixture"}

            def rejects(e):
                try:
                    verify_checkout(e)
                    return False
                except SystemExit as exc:
                    return str(exc).startswith("REFUSED:")

            check("a checkout matching the corpus file verifies silently",
                  verify_checkout(entry) == [])
            other = "https://example.invalid/other.git"
            check("a checkout whose origin is not the recorded upstream is "
                  "refused", rejects(dict(entry, upstream=other)))
            check("a PINNED project whose HEAD has moved is refused",
                  rejects(dict(entry, pinned_commit="a" * 40)))
            drifted = verify_checkout(
                dict(entry, pinned_commit=None, resolved_commit="a" * 40))
            check("an UNPINNED project whose HEAD has moved is a note",
                  len(drifted) == 1 and "re-minted" in drifted[0],
                  str(drifted))

    print("\n" + ("ALL PASS (parser + richness classifier + corpora)" if ok
                  else "FAILURES"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=os.path.join(
        BENCHMARK_ROOT, "items.jsonl"))
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--project", action="append", default=None,
                    help="restrict to named project(s)")
    args = ap.parse_args()
    if args.selftest:
        raise SystemExit(selftest())

    projects = corpus_entries()
    if args.project:
        want = set(args.project)
        projects = [p for p in projects if p["name"] in want]
        missing = want - {p["name"] for p in projects}
        if missing:
            raise SystemExit(f"unknown project(s): {sorted(missing)}")

    require_roots(projects)

    all_items, report = [], []
    for p in projects:
        for note in verify_checkout(p):
            print(note)
        items, stats = extract_project(
            p["name"], p["root"], p["subdir"], p["language"], p["framework"])
        crit = sum(1 for i in items if i["task"] == "criterion_to_test")
        req = sum(1 for i in items if i["task"] == "requirement_to_test")
        all_items.extend(items)
        report.append((p["name"], p["language"], stats["features"], crit, req))
        for rel, why in stats["skipped"][:3]:
            print(f"  note: {p['name']}/{rel} skipped -- {why}")

    # A duplicate item_id means the same scenario was reached by two
    # paths (a build-output copy, a vendored tree). Refuse rather than
    # silently double-count: every headline number below derives from
    # this file.
    seen, dupes = set(), []
    for it in all_items:
        if it["item_id"] in seen:
            dupes.append(it["item_id"])
        seen.add(it["item_id"])
    if dupes:
        raise SystemExit(
            f"REFUSED: {len(dupes)} duplicate item_id(s), e.g. "
            f"{dupes[:3]} — a copy of the suite is being walked twice; "
            f"add its directory to _SKIP_DIRS")

    # Near-duplicate guard: identical scenario TEXT under different
    # paths is legitimate (parameterised suites reuse phrasing), so this
    # only warns.
    bodies = {}
    for it in all_items:
        if it["task"] == "criterion_to_test":
            bodies.setdefault(it["criterion"]["gherkin"], []).append(
                it["item_id"])
    repeated = {k: v for k, v in bodies.items() if len(v) > 1}
    if repeated:
        n = sum(len(v) - 1 for v in repeated.values())
        print(f"  note: {n} criterion item(s) share scenario text with "
              f"another item ({len(repeated)} distinct bodies) — legitimate "
              f"for parameterised suites, but check before scoring")

    with open(args.out, "w", encoding="utf-8") as fh:
        for it in all_items:
            fh.write(json.dumps(it, sort_keys=True) + "\n")

    print(f"\n{'project':<16}{'lang':<10}{'features':>9}"
          f"{'criterion':>11}{'requirement':>13}")
    for name, lang, nf, c, r in report:
        print(f"{name:<16}{lang:<10}{nf:>9}{c:>11}{r:>13}")
    tc = sum(r[3] for r in report)
    tr = sum(r[4] for r in report)
    print(f"{'TOTAL':<16}{'':<10}{sum(r[2] for r in report):>9}"
          f"{tc:>11}{tr:>13}")

    rich = {}
    for it in all_items:
        if it["task"] == "criterion_to_test":
            rich[it["requirement"]["richness"]] = rich.get(
                it["requirement"]["richness"], 0) + 1
    print("\ncriterion items by requirement richness (the ablation axis):")
    for k in ("user_story", "prose", "title_only"):
        print(f"  {k:<12}{rich.get(k, 0):>6}")
    print(f"\nwrote {len(all_items)} items -> {args.out}")


if __name__ == "__main__":
    main()
