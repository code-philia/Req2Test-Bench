"""S3 — `r2t index` for the behave stack: what a step IS, before it is matched.

`cli.cmd_index` for CoreShop runs two PHP programs in a container and writes
four artifacts.  This is the behave arm of the same verb, and it does three
things the PHP arm does not have to:

**1. It resolves And/But/`*` to a CONCRETE keyword.**  Behat's
`RepositorySearchEngine::searchDefinition` never consults the step type, so
`match_steps.php` matches on TEXT alone and the keyword is decoration.  behave
does the opposite: `StepRegistry.find_step_definition` looks only in
`registry.steps[step.step_type]` (plus the keyword-agnostic `step` list), so
`Given a font` and `Then a font` are different questions.  A Gherkin `And`
carries no type of its own, and behave's parser resolves it — line for line,
reproduced in `resolve_block_keywords` below — from the previous step of the SAME
statement, falling back to the last Background step and raising when there is
neither.  Matching before that resolution would silently look in the wrong
keyword list.

**2. It substitutes the Examples row before matching.**  124 of python-docx's
239 criterion items are Scenario Outlines with 535 Examples rows between them,
and an outline's step text is a TEMPLATE: `Given a font having <color>
highlighting` matches nothing at all, while its three substituted forms match
one definition each.  behave builds one real Scenario per row
(`ScenarioOutlineBuilder.render_template`) and runs it, so the honest question
to ask the registry is the row's, not the template's — 693 of the 1159
distinct (keyword, text) pairs this corpus asks about exist only after
substitution.

**3. It runs the matcher in the IMAGE, against a READ-ONLY workspace.**  The
PHP arm writes its programs into the repository's own `_bench/` and execs into
a long-lived container.  There is no long-lived container before S4, and the
python-docx corpus is a pinned clone whose bytes are a gate (`S0`: the 306
extracted items must re-derive byte-identically), so nothing is written into
it: the repository is bind-mounted `:ro`, and the matcher, its input and its
output live in a scratch directory mounted beside it.

What comes out: `py_index.json` (the static index, host-side — see
`py/analyze_py.py`), `steps.json` (the (keyword, text) pairs, substituted),
and `matches.json` (behave's own answers, from inside the image).
`closure_py` reads all three.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional

from ..core.gherkin import Block, Feature, parse_feature_file
from ..py import analyze_py

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The execution image, `docker/python_docx/Dockerfile`.  An env var rather
#: than a CLI flag so that no shared parser gains an option in a milestone
#: that touches four files; the default is the built tag and the override is
#: for an operator testing a rebuilt one.
DEFAULT_IMAGE = os.environ.get("R2T_BEHAVE_IMAGE", "r2t_docx_img:base")
#: Since 2026-09-09 `index` no longer reads this: its matcher runs in the
#: image of the container `--container` names (`DOCKER_EXECUTION_AUTHORITY.md`).
#: The mutation enumerator's defaults (`mutation_py`) and the closed S5 gate
#: still do.

#: Where the workspace is mounted inside that image — its `WORKDIR`, and the
#: `src` half of its `PYTHONPATH`.  Matching it here means the matcher's
#: `sys.path` is the run's `sys.path`.
CONTAINER_ROOT = "/work"

#: Where the matcher, its input and its output live: a HOST scratch directory,
#: mounted read-write beside a read-only workspace.  See the module docstring.
CONTAINER_SCRATCH = "/r2t"

#: The directory whose modules a step definition may import by bare name, and
#: which behave itself puts on `sys.path` before loading them.  `src` is
#: python-docx's; it is the same string the image bakes into `PYTHONPATH` and
#: the same one `repo.BEHAVE_SUBSTRATE_ROOTS` hashes.
DEFAULT_SRC = os.environ.get("R2T_BEHAVE_SRC", "src")

#: `DockerRunner` wraps every `docker exec` in `sg docker -c` so that an
#: operator freshly added to the group does not have to log out first.  A
#: one-shot `docker run` has the same problem, so it gets the same wrapper,
#: and the same escape hatch for a machine where `sg` is not what runs docker.
DOCKER_GROUP = os.environ.get("R2T_DOCKER_GROUP", "1") not in ("0", "no", "")


class StepResolutionError(RuntimeError):
    """A Gherkin file behave's own parser would refuse.

    Raised rather than defaulted: an `And` with nothing before it has no
    keyword, and guessing `Given` would put the question to the wrong third
    of the registry — the wrong answer, silently, for exactly the steps whose
    author already got something wrong.
    """


@dataclass(frozen=True)
class StepRef:
    """One step OCCURRENCE, as behave will see it when the scenario runs.

    For a plain scenario there is one of these per Gherkin step line.  For a
    Scenario Outline there is one per (Examples data row × step line), because
    that is what behave executes: `ScenarioOutlineBuilder` makes a real
    Scenario out of every row and the row's values are already substituted
    into the step name by the time the registry is asked anything.

    `example_line` is the DATA ROW's line, which is also the line the
    recorder stamps its per-row record with (`stacks.base`, `harness.
    fold_scenario_records`).  `source_line` stays the template's, so an
    unmatched step can still be pointed at.
    """
    keyword: str                    # effective, lower-case: given|when|then
    text: str                       # after Examples substitution
    origin: str                     # "background" | "scenario"
    source_line: int
    raw_keyword: str                # as written: Given / And / But / *
    raw_text: str                   # before substitution
    example_line: Optional[int] = None
    example_row: Optional[int] = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.keyword, self.text)


# ------------------------------------------------------- keyword resolution
#: The keywords that carry no type of their own.  `*` is here for behave's
#: reason rather than Gherkin's: `behave.i18n.languages["en"]` lists `"* "`
#: under EVERY step type, and `Parser.parse_step` iterates
#: ("given", "when", "then", "and", "but") — so a `*` with no predecessor
#: matches the `given` entry first and IS a Given, while a `*` with one
#: inherits (`if kw.startswith("*") and self.last_step_type`).
_INHERITS = {"And", "But"}
_STAR = "*"


def resolve_block_keywords(steps: list, last_background_type: Optional[str],
                           where: str) -> list[str]:
    """behave's `Parser.parse_step` keyword inheritance, one statement's worth.

    Reproduced rather than reused because `gherkin.Step.resolved` answers a
    different question: it seeds `last_concrete = "Given"`, so a leading `And`
    silently becomes a Given.  behave instead reaches for
    `_select_last_background_step_type()` — the type of the LAST BACKGROUND
    STEP, which for a `When`-ending Background is a When — and raises
    `ParserError` when there is no Background either.  CoreShop has no
    leading-`And` scenario and neither does python-docx, so this changes no
    number today; it is written because the difference is invisible in the
    output and would be a wrong keyword list, not a crash.
    """
    out: list[str] = []
    last = last_background_type
    for st in steps:
        kw = st.keyword
        if kw == _STAR:
            step_type = last or "Given"
            last = step_type
        elif kw in _INHERITS:
            if last is None:
                raise StepResolutionError(
                    f"{where}:{st.line}: `{kw}` has no previous "
                    f"Given/When/Then step and no Background to inherit one "
                    f"from; behave's parser raises here and so does this")
            step_type = last
        else:
            step_type = kw
            last = kw
        out.append(step_type.lower())
    return out


def effective_steps(feature: Feature, scenario: Block
                    ) -> list[tuple[str, Block, object]]:
    """`(effective keyword, origin, step)` for the Background then the scenario.

    The Background's steps are part of the item: behave runs them before the
    scenario and the scenario cannot pass without their definitions, which is
    the same rule `closure.bind_steps` applies to Behat.
    """
    out: list[tuple[str, str, object]] = []
    bg_last: Optional[str] = None
    if feature.background is not None and feature.background.steps:
        kws = resolve_block_keywords(feature.background.steps, None,
                                     f"{feature.path} Background")
        out += [(k, "background", s)
                for k, s in zip(kws, feature.background.steps)]
        bg_last = kws[-1].title()
    kws = resolve_block_keywords(
        scenario.steps, bg_last, f"{feature.path} {scenario.kind}")
    out += [(k, "scenario", s) for k, s in zip(kws, scenario.steps)]
    return out


# ---------------------------------------------------------- Examples tables
# A Gherkin table row is split by the RUNNER that will execute it, and the
# runners this benchmark drives do not agree. The disagreement is invisible on
# a well-formed row and decides the split on a row that carries trailing prose
# after its final `|`, so the dialect is an explicit argument rather than a
# default anyone can drift into.  See `_cells` for the two rules and
# the explicit dialect constants below for who selects which.
BEHAVE_DIALECT = "behave"
CUCUMBER_DIALECT = "cucumber"
BEHAT_DIALECT = "behat"
_DIALECTS = (BEHAVE_DIALECT, CUCUMBER_DIALECT, BEHAT_DIALECT)


def _cells(line: str, *, dialect: str = BEHAVE_DIALECT) -> list[str]:
    """One Gherkin table row's cells, under the runner's own split rule.

    `behave` (`Parser.action_table`):

        cells = [cell.replace("\\\\|", "|").strip()
                 for cell in re.split(r"(?<!\\\\)\\|", line[1:-1])]

    written out here because a cell value is what gets substituted into a
    step, and a cell split that disagreed with behave's would produce step
    texts that match nothing while behave's match fine.  `line[1:-1]` drops
    one character from each end, which assumes the row ENDS in `|`.

    cucumber-JVM (`GherkinLine.getTableCells`) appends a cell only when it
    reaches a closing `|`, so a segment after the final `|` is never a cell.
    On `| a | b | c | (note)` behave yields four cells (the last `(note`) and
    cucumber yields three.  EPUBCheck ships exactly that shape at
    `src/test/resources/unit-tests/url-fragment.feature:61-62`, and the live
    dry-run capture settles it: cucumber emitted pickles for all eight rows of
    the outline at line 48, so on the Java arm three is the true count.

    Behat follows its own Lexer::CELL_PATTERN / scanTableRow: backslash
    pairs before a pipe do not escape that delimiter, and doubled backslashes
    inside a cell are decoded after escaped pipes.

    The behave rule stays the default and is byte-identical to what it always
    was; the python-docx archives were derived under it.
    """
    import re
    s = line.strip()
    if dialect == BEHAVE_DIALECT:
        return [c.replace("\\|", "|").strip()
                for c in re.split(r"(?<!\\)\|", s[1:-1])]
    if dialect == BEHAT_DIALECT:
        # Behat's Lexer::CELL_PATTERN splits at a pipe preceded by an
        # even number of backslashes. The backslashes remain in the cell;
        # scanTableRow then unescapes pipes and doubled backslashes, in that
        # order. Like cucumber, it ignores prose after the closing pipe.
        pipes = [m.end() - 1 for m in re.finditer(r"(?<!\\)(?:\\\\)*\|", s)]
        return [s[a + 1:b].replace("\\|", "|").replace("\\\\", "\\").strip()
                for a, b in zip(pipes, pipes[1:])]
    if dialect != CUCUMBER_DIALECT:
        raise StepResolutionError(f"unknown Gherkin table dialect {dialect!r}")
    # Cells live strictly BETWEEN delimiters: drop the segment before the
    # first `|` and the unterminated segment after the last one.
    return [c.replace("\\|", "|").strip()
            for c in re.split(r"(?<!\\)\|", s)[1:-1]]


def examples_rows(feature: Feature, scenario: Block, *,
                  dialect: str = BEHAVE_DIALECT) -> list[tuple[int, dict]]:
    """`(data-row line, {heading: value})` for every Examples row, in order.

    `Block.examples_lines` gives 0-based half-open spans that include the
    `Examples:` keyword line and the table's heading row; within a span the
    first `|` line is the headings and the rest are cases.  An outline with
    several Examples blocks contributes all of their rows, which is what
    behave does (`ScenarioOutline.scenarios` iterates every `Examples`).

    `dialect` picks the row split (see `_cells`); it defaults to behave, and
    the cucumber-JVM callers on the Java arm pass it explicitly.
    """
    if dialect not in _DIALECTS:
        raise StepResolutionError(f"unknown Gherkin table dialect {dialect!r}")
    rows: list[tuple[int, dict]] = []
    for start, end in scenario.examples_lines:
        headings: Optional[list[str]] = None
        for i in range(max(0, start), min(end, len(feature.lines))):
            ln = feature.lines[i]
            if not ln.lstrip().startswith("|"):
                continue
            cells = _cells(ln, dialect=dialect)
            if headings is None:
                headings = cells
                continue
            if len(cells) != len(headings):
                # behave raises ParserError("Malformed table") here, and a
                # zip() would instead drop a column and substitute nothing
                # into the steps that used it.
                raise StepResolutionError(
                    f"{feature.path}:{i + 1}: Examples row has "
                    f"{len(cells)} cells for {len(headings)} headings")
            rows.append((i + 1, dict(zip(headings, cells))))
    return rows


def render_template(text: str, row: dict) -> str:
    """behave's `ScenarioOutlineBuilder.render_template`, for a step name.

    Verbatim in behaviour: bail out when the text holds no `<`…`>` at all,
    then a plain `str.replace` of `<heading>` per column in heading order.
    No regex, no escaping, no recursion — a value that itself looks like a
    placeholder IS substituted, because behave's `safe_values` guard is
    hard-coded to False in 1.3.3.
    """
    if not ("<" in text and ">" in text):
        return text
    for name, value in row.items():
        text = text.replace(f"<{name}>", value)
    return text


def item_steps(feature: Feature, scenario: Block) -> list[StepRef]:
    """Every step occurrence of one item, ready to be matched."""
    base = effective_steps(feature, scenario)
    if not scenario.kind.startswith(("Scenario Outline", "Scenario Template")):
        return [StepRef(keyword=k, text=s.text, origin=o, source_line=s.line,
                        raw_keyword=s.keyword, raw_text=s.text)
                for k, o, s in base]
    out: list[StepRef] = []
    for idx, (line, row) in enumerate(examples_rows(feature, scenario)):
        for k, o, s in base:
            out.append(StepRef(keyword=k, text=render_template(s.text, row),
                               origin=o, source_line=s.line,
                               raw_keyword=s.keyword, raw_text=s.text,
                               example_line=line, example_row=idx))
    return out


# ------------------------------------------------------------- item walking
def walk_features(repo_root: str, features_rel: str, project: str,
                  item_path: Optional[Callable[[str], str]] = None,
                  ) -> list[tuple[str, Feature, Block]]:
    """`(item_id, feature, scenario)` for every scenario under `features_rel`.

    The same walk `cli.cmd_index`/`cmd_closures` do for CoreShop, in the same
    sorted order, producing the same `<project>/<rel>:<line>` identity — so an
    item id here is the item id `items.jsonl` already carries.  `item_path`
    changes only that identity when a composed workspace relocated a feature;
    the parsed Feature keeps its runtime path.
    """
    out: list[tuple[str, Feature, Block]] = []
    root = os.path.join(repo_root, features_rel)
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for f in sorted(files):
            if not f.endswith(".feature"):
                continue
            path = os.path.join(dirpath, f)
            rel = os.path.relpath(path, repo_root).replace(os.sep, "/")
            feat = parse_feature_file(path)
            item_rel = item_path(rel) if item_path is not None else rel
            for sc in feat.scenarios:
                out.append((f"{project}/{item_rel}:{sc.line}", feat, sc))
    return out


def distinct_pairs(items: dict) -> list[dict]:
    """The (keyword, text) questions to ask the registry, sorted.

    Sorted and de-duplicated because the matcher's cost is one `match()` per
    (pair × definition) — 1159 × 467 for python-docx — and because a sorted
    input makes `matches.json` a file two runs can be diffed on.
    """
    pairs = {r.key for refs in items.values() for r in refs}
    return [{"keyword": k, "text": t} for k, t in sorted(pairs)]


# ------------------------------------------------------------ the container
def _docker(argv: list[str]) -> list[str]:
    """Wrap a full legacy Docker argv through the shared endpoint selector."""
    from ..core.docker_cli import docker_command
    if not argv or argv[0] != "docker":
        raise ValueError("Docker argv must begin with the docker executable")
    return docker_command(argv[1:], docker_group=DOCKER_GROUP,
                          executable=argv[0])


def run_matcher(repo_root: str, steps_dirs: list, src: Optional[str],
                pairs: list, *, image: str,
                timeout: int = 1800) -> dict:
    """Run `py/match_steps.py` inside `image` and return its document.

    The workspace goes in READ-ONLY.  That is not caution about the container,
    it is the S0 gate: python-docx is a clone pinned at `e454546` whose 306
    extracted items must re-derive byte-identically, and a matcher that left a
    `_bench/` behind (which is what the PHP arm does, deliberately, in a
    working application) would change the tree the corpus is defined over.

    The container also gets `--network none`: this matcher has no network
    dependency, so giving it a network route would serve no purpose.
    """
    scratch = tempfile.mkdtemp(prefix="r2t_pymatch_")
    try:
        shutil.copyfile(os.path.join(HERE, "py", "match_steps.py"),
                        os.path.join(scratch, "match_steps.py"))
        with open(os.path.join(scratch, "steps.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"steps": pairs}, fh, indent=1, ensure_ascii=False)
        inner = ["python", f"{CONTAINER_SCRATCH}/match_steps.py",
                 "--root", CONTAINER_ROOT,
                 "--steps", f"{CONTAINER_SCRATCH}/steps.json",
                 "--out", f"{CONTAINER_SCRATCH}/matches.json"]
        for d in steps_dirs:
            inner += ["--steps-dir", d]
        if src:
            inner += ["--src", src]
        argv = ["docker", "run", "--rm", "--network", "none",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", f"{os.path.abspath(repo_root)}:{CONTAINER_ROOT}:ro",
                "-v", f"{scratch}:{CONTAINER_SCRATCH}",
                "-w", CONTAINER_ROOT, image] + inner
        cp = subprocess.run(_docker(argv), capture_output=True, text=True,
                            timeout=timeout)
        if cp.stderr.strip():
            print("  " + cp.stderr.strip().replace("\n", "\n  "))
        out = os.path.join(scratch, "matches.json")
        if cp.returncode != 0 or not os.path.isfile(out):
            raise SystemExit(
                f"REFUSED: the in-container matcher exited {cp.returncode}. "
                f"Nothing downstream may be built from a partial match table "
                f"-- an unmatched step and an unRUN step are the same empty "
                f"list, and only one of them is a finding.\n"
                f"{cp.stdout[-2000:]}\n{cp.stderr[-2000:]}")
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# --------------------------------------------------------------- cross-check
def crosscheck(index: dict, matches: dict) -> list[str]:
    """Everything that must be true before a closure may be built. Refusals.

    Each one is a way for the pipeline to produce closures that look fine and
    are wrong, which is the only kind worth a check:

    * a matcher that did not run in a container matched against whatever
      behave the operator's machine carries;
    * a step module that failed to load registers nothing, so every step it
      answers comes back unmatched — indistinguishable from a step nobody
      wrote;
    * a definition in a file the static index does not know is a definition
      whose file the closure cannot restore;
    * a registry location the source census does not contain means the two
      disagree about what exists, and the closure is built from the census.
    """
    problems: list[str] = []
    if matches.get("load_error"):
        problems.append("a step module failed to load inside the image")
    if not matches.get("docker_env"):
        problems.append(
            "the matcher did not run inside a container (`/.dockerenv` "
            "absent): its behave is not the run's behave")
    if index["errors"]:
        problems.append(f"{len(index['errors'])} indexed module(s) do not "
                        f"parse: {sorted(index['errors'])[:3]}")
    if matches.get("match_errors"):
        problems.append(f"{len(matches['match_errors'])} pattern(s) raised "
                        f"while matching")

    known = set(index["files"])
    source = analyze_py.step_definition_locations(index)
    for d in matches.get("definitions", []):
        if d["file"] not in known:
            problems.append(f"definition in an unindexed file: "
                            f"{d['file']}:{d['line']}")
        elif (d["file"], d["line"]) not in source:
            problems.append(f"registry location absent from the source "
                            f"census: {d['file']}:{d['line']}")
    return problems


# -------------------------------------------------------------- the CLI verb
def index_paths_for(boundary) -> list[str]:
    """The trees to index: the boundary's own test code, python files only.

    Read out of the boundary rather than hard-coded so that "what is test
    code" has one answer per project and it is the one the stripper uses.
    For python-docx that is `features/steps` (removable) and
    `features/environment.py` (retained); `features/steps/test_files`
    (retained) contributes nothing because 53 `.docx` fixtures hold no
    Python.
    """
    out: list[str] = []
    for p in list(boundary.removable_prefixes()) + list(
            boundary.retained_prefixes()):
        p = p.rstrip("/")
        full = os.path.join(boundary.repo_root, p)
        if os.path.isfile(full) and p.endswith(".py"):
            out.append(p)
        elif os.path.isdir(full):
            for dirpath, dirnames, files in os.walk(full):
                dirnames[:] = [d for d in dirnames if d != "__pycache__"]
                if any(f.endswith(".py") for f in files):
                    out.append(p)
                    break
    return sorted(set(out))


def steps_dirs_for(repo_root: str, features_rel: str) -> list[str]:
    """behave's step directories: `<base_dir>/steps`, and it must exist.

    behave's own discovery (`Runner.setup_paths`) walks upward looking for a
    directory containing `steps/`; naming it here rather than re-implementing
    that walk keeps the artifact honest about which directory was loaded.
    """
    rel = f"{features_rel.rstrip('/')}/steps"
    if not os.path.isdir(os.path.join(repo_root, rel)):
        raise SystemExit(
            f"REFUSED: no `{rel}` under {repo_root}. behave discovers step "
            f"definitions by importing every module in the `steps/` directory "
            f"beside the features; without one there is nothing to index.")
    return [rel]


def cmd_index(args) -> int:
    """`r2t index --profile config/profile_python_docx.yml --features features`

    The behave arm of `cli.cmd_index`, reached through `cli._other_stack`.

    The matcher runs in the IMAGE of the container the operator named
    (`--container`), resolved to its immutable ID before anything is indexed,
    and `matches.json` records that ID beside the matcher's own provenance:
    the registry that answered is the one the run's behave will consult.
    """
    from ..bench.cli import _bound_container_image
    from ..core.boundary import load_boundary
    image = _bound_container_image(args.container)
    print(f"image_id: {image}")
    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    features = features_rel(args, b)
    from .cli import _refuse_existing_artifacts
    _refuse_existing_artifacts(
        args.artifacts, ("py_index.json", "steps.json", "matches.json"))
    os.makedirs(args.artifacts, exist_ok=True)

    paths = index_paths_for(b)
    steps_dirs = steps_dirs_for(b.repo_root, features)
    index = analyze_py.build_index(b.repo_root, paths)
    print(f"indexed {index['counts']['files']} python files under "
          f"{', '.join(paths)}: {index['counts']['step_definitions']} step "
          f"decorators, {index['counts']['register_types']} registered types, "
          f"{index['counts']['errors']} parse errors")

    items = {}
    for item_id, feat, sc in walk_features(b.repo_root, features,
                                          b.project):
        items[item_id] = item_steps(feat, sc)
    pairs = distinct_pairs(items)
    n_rows = sum(1 for refs in items.values() for r in refs
                 if r.example_line is not None)
    print(f"collected {len(items)} scenarios / {len(pairs)} distinct "
          f"(keyword, text) pairs ({n_rows} of the occurrences come from "
          f"Examples rows)")

    src = DEFAULT_SRC if os.path.isdir(
        os.path.join(b.repo_root, DEFAULT_SRC)) else None
    matches = run_matcher(b.repo_root, steps_dirs, src, pairs, image=image)
    matches["matcher_sha256"] = _matcher_digest()
    matches["image_id"] = image

    problems = crosscheck(index, matches)
    unmatched = [m for m in matches["matches"] if m["definition"] is None]

    with open(os.path.join(args.artifacts, "py_index.json"), "w",
              encoding="utf-8") as fh:
        json.dump(index, fh, indent=1, sort_keys=True)
    with open(os.path.join(args.artifacts, "steps.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"steps": pairs}, fh, indent=1, ensure_ascii=False)
    with open(os.path.join(args.artifacts, "matches.json"), "w",
              encoding="utf-8") as fh:
        json.dump(matches, fh, indent=1, sort_keys=True, ensure_ascii=False)

    print(f"matched in-container: behave {matches['behave_version']}, python "
          f"{matches['python_version']} ({matches['python_executable']}), "
          f"{matches['n_step_definitions']} definitions")
    print(f"  unmatched pairs: {len(unmatched)}")
    print(f"  pairs with more than one candidate: "
          f"{sum(1 for m in matches['matches'] if m['n_candidates'] > 1)}")
    if problems:
        for p in problems:
            print(f"  PROBLEM: {p}")
        raise SystemExit(
            f"REFUSED: {len(problems)} cross-check problem(s) between the "
            f"static index and behave's registry. The artifacts were written "
            f"so the disagreement can be read, but no closure may be built "
            f"from them.")
    return 0


def features_rel(args, boundary) -> str:
    """`--features`, refusing CoreShop's default when it names nothing here.

    The flag's default is `features/domain`, which is CoreShop's tree and is
    what every CoreShop runbook relies on; python-docx keeps its features at
    `features`.  Silently correcting the flag would make the artifacts depend
    on a guess, so the refusal names the value to pass.
    """
    rel = getattr(args, "features", None) or "features"
    if not os.path.isdir(os.path.join(boundary.repo_root, rel)):
        raise SystemExit(
            f"REFUSED: `--features {rel}` names no directory under "
            f"{boundary.repo_root}. The default is CoreShop's tree; this "
            f"project keeps its `.feature` files elsewhere -- for "
            f"{boundary.project} pass `--features features`.")
    return rel.rstrip("/")


def _matcher_digest() -> str:
    import hashlib
    with open(os.path.join(HERE, "py", "match_steps.py"), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# ----------------------------------------------------------------- selftest
def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    # ------------------------------------------------- keyword inheritance
    src = """Feature: F

  Background:
    Given a store
    When the clock ticks

  Scenario: Inherits from the previous step
    Given a font
    And a paragraph
    Then it is bold
    But not italic

  Scenario: Leads with And, so it inherits the BACKGROUND's last step
    And a second font
    Then it is bold

  Scenario: A star with a predecessor inherits it
    Then it is bold
    * it is also red
"""
    feat = parse_feature_file("m.feature", src)
    kws = [k for k, _o, _s in effective_steps(feat, feat.scenarios[0])]
    check("Background steps come first and keep their own keywords",
          kws[:2] == ["given", "when"], str(kws))
    check("`And` inherits the previous concrete keyword, `But` too",
          kws[2:] == ["given", "given", "then", "then"], str(kws))
    kws2 = [k for k, _o, _s in effective_steps(feat, feat.scenarios[1])]
    check("a leading `And` inherits the LAST BACKGROUND step's type -- a When "
          "here, which `gherkin.Step.resolved` would have called a Given",
          kws2[-2:] == ["when", "then"], str(kws2))
    check("...and `gherkin.Step.resolved` really does disagree, so this is "
          "not a distinction without a difference",
          feat.scenarios[1].steps[0].resolved == "Given")
    kws3 = [k for k, _o, _s in effective_steps(feat, feat.scenarios[2])]
    check("`*` inherits the step before it", kws3[-2:] == ["then", "then"],
          str(kws3))

    lonely = parse_feature_file("n.feature", """Feature: F

  Scenario: And with nothing before it
    And a font
""")
    try:
        effective_steps(lonely, lonely.scenarios[0])
        check("an `And` with no predecessor and no Background is REFUSED, "
              "never defaulted to Given", False, "accepted")
    except StepResolutionError as e:
        check("an `And` with no predecessor and no Background is REFUSED, "
              "never defaulted to Given", "no previous" in str(e))
    star = parse_feature_file("o.feature", """Feature: F

  Scenario: Star with nothing before it
    * a font
""")
    check("a leading `*` is a Given -- behave's en keyword table lists `* ` "
          "under every type and `parse_step` tries `given` first",
          [k for k, _o, _s in effective_steps(star, star.scenarios[0])]
          == ["given"])

    # --------------------------------------------------- Examples handling
    outline = parse_feature_file("p.feature", """Feature: F

  Scenario Outline: Get highlight color
    Given a font having <color> highlighting\x20
     Then font.highlight_color is <value>

    Examples: values
      | color        | value        |
      | no           | None         |
      | bright green | BRIGHT_GREEN |
      | a \\| b       | PIPE         |
""")
    sc = outline.scenarios[0]
    rows = examples_rows(outline, sc)
    check("every Examples DATA row is found, and the heading row is not one "
          "of them", len(rows) == 3, str(rows))
    check("a row's line is the row's own, so a record can be joined to it",
          [ln for ln, _r in rows] == [9, 10, 11], str([ln for ln, _r in rows]))
    check("an escaped pipe is one cell value, the way behave unescapes it",
          rows[2][1]["color"] == "a | b", str(rows[2][1]))

    # ------------------------------------------- the two table-split dialects
    # EPUBCheck ships trailing prose after the final `|` at
    # src/test/resources/unit-tests/url-fragment.feature:61-62.  behave's
    # `line[1:-1]` turns that prose into a fourth cell; cucumber-JVM's
    # `GherkinLine.getTableCells` never emits it, and the live dry run agrees
    # with cucumber (it produced pickles for all eight rows of that outline).
    trailing = '      | "*id"            | invalid  | "*id" | (not an NCName)'
    plain = "      | color | value |"
    check("cucumber-JVM drops the segment after the final `|`, so the row "
          "has as many cells as the table has headings",
          _cells(trailing, dialect=CUCUMBER_DIALECT)
          == ['"*id"', "invalid", '"*id"'],
          str(_cells(trailing, dialect=CUCUMBER_DIALECT)))
    check("behave keeps its historical answer on that same row -- a fourth "
          "cell, the prose with its last character chopped off",
          _cells(trailing, dialect=BEHAVE_DIALECT)
          == ['"*id"', "invalid", '"*id"', "(not an NCName"],
          str(_cells(trailing, dialect=BEHAVE_DIALECT)))
    check("behave is still the DEFAULT, byte-identical to what the python-docx "
          "archives were derived under",
          _cells(trailing) == _cells(trailing, dialect=BEHAVE_DIALECT)
          and _cells(plain) == ["color", "value"], str(_cells(plain)))
    check("on a well-formed row the two dialects cannot be told apart, which "
          "is why the disagreement went unseen until EPUBCheck",
          _cells(plain, dialect=CUCUMBER_DIALECT)
          == _cells(plain, dialect=BEHAVE_DIALECT))
    check("an escaped pipe survives the cucumber split too",
          _cells(r"| a \| b | PIPE |", dialect=CUCUMBER_DIALECT)
          == ["a | b", "PIPE"],
          str(_cells(r"| a \| b | PIPE |", dialect=CUCUMBER_DIALECT)))
    behat_row = r"| a \| b | path\\| literal\n | (ignored)"
    check("Behat unescapes pipes/backslashes and splits after paired backslashes",
          _cells(behat_row, dialect=BEHAT_DIALECT)
          == ["a | b", "path\\", r"literal\n"],
          str(_cells(behat_row, dialect=BEHAT_DIALECT)))

    trailing_outline = parse_feature_file("u.feature", """Feature: F

  Scenario Outline: SVG shorthand fragment <fragment>
    Given <fragment> is a <validity> SVG fragment

    Examples: Shorthand fragments
      | fragment | validity | id    |
      | "id"     | valid    | "id"  |
      | "*id"    | invalid  | "*id" | (not an NCName)
""")
    tsc = trailing_outline.scenarios[0]
    trows = examples_rows(trailing_outline, tsc, dialect=CUCUMBER_DIALECT)
    check("under cucumber the outline yields BOTH data rows, at their own "
          "lines, which is what the dry run's pickles are joined on",
          [ln for ln, _r in trows] == [8, 9], str(trows))
    check("...and the trailing prose is not a value of any heading",
          trows[1][1] == {"fragment": '"*id"', "validity": "invalid",
                          "id": '"*id"'}, str(trows[1][1]))
    try:
        examples_rows(trailing_outline, tsc, dialect=BEHAVE_DIALECT)
        check("behave still REFUSES that row as a malformed table", False,
              "no refusal")
    except StepResolutionError as exc:
        check("behave still REFUSES that row as a malformed table -- its "
              "answer is preserved, not silently corrected",
              "4 cells for 3 headings" in str(exc), str(exc))
    for bad in ("gherkin", "", None):
        try:
            _cells(plain, dialect=bad)
            check(f"an unknown dialect {bad!r} is refused", False, "accepted")
        except StepResolutionError:
            check(f"an unknown dialect {bad!r} is refused", True)

    refs = item_steps(outline, sc)
    check("an outline yields one occurrence per (row x step)",
          len(refs) == 6, str(len(refs)))
    check("the placeholder is substituted and the trailing whitespace of the "
          "source line is already gone -- behave strips a step name after its "
          "keyword, and so does `gherkin._parse_steps`",
          refs[0].text == "a font having no highlighting", repr(refs[0].text))
    check("...and the raw template is kept beside it",
          refs[0].raw_text == "a font having <color> highlighting",
          repr(refs[0].raw_text))
    check("each occurrence carries its Examples row line",
          sorted({r.example_line for r in refs}) == [9, 10, 11],
          str(sorted({r.example_line for r in refs})))
    check("no substituted text keeps a placeholder",
          not any("<" in r.text and ">" in r.text for r in refs))
    check("the distinct questions are (keyword, text) PAIRS, so a Given and a "
          "Then of the same text are two",
          distinct_pairs({"i": [
              StepRef("given", "a font", "scenario", 1, "Given", "a font"),
              StepRef("then", "a font", "scenario", 2, "Then", "a font"),
              StepRef("given", "a font", "scenario", 3, "Given", "a font")]})
          == [{"keyword": "given", "text": "a font"},
              {"keyword": "then", "text": "a font"}])

    plain = parse_feature_file("q.feature", """Feature: F

  Scenario: Plain
    Given a font
""")
    pr = item_steps(plain, plain.scenarios[0])
    check("a plain scenario's occurrences carry no Examples line",
          len(pr) == 1 and pr[0].example_line is None)

    # ------------------------------------------------------- the cross-check
    index = {"files": {"features/steps/a.py": {
        "steps": [{"keyword": "given", "pattern": "a font", "func": "f",
                   "line": 3, "registry_line": 3, "def_line": 4}],
        "dynamic_steps": []}}, "errors": {}}
    good = {"docker_env": True, "load_error": None, "match_errors": [],
            "definitions": [{"file": "features/steps/a.py", "line": 3}],
            "matches": []}
    check("a clean pair of censuses raises nothing",
          crosscheck(index, good) == [], str(crosscheck(index, good)))
    check("a matcher that did not run in a container is refused",
          any("did not run inside a container" in p
              for p in crosscheck(index, dict(good, docker_env=False))))
    check("a definition in a file the index does not know is refused",
          any("unindexed file" in p for p in crosscheck(
              index, dict(good, definitions=[{"file": "x.py", "line": 1}]))))
    check("a registry location the source census lacks is refused",
          any("absent from the source census" in p for p in crosscheck(
              index, dict(good, definitions=[
                  {"file": "features/steps/a.py", "line": 99}]))))
    check("a step module that failed to load is refused",
          any("failed to load" in p
              for p in crosscheck(index, dict(good, load_error="boom"))))
    check("an unparseable indexed module is refused",
          any("do not parse" in p for p in crosscheck(
              dict(index, errors={"features/steps/b.py": "SyntaxError"}),
              good)))

    # ------------------------------------------- the matcher is not a regex
    #
    # The `match_steps.php:2-19` rule, checked against the python twin's own
    # bytes rather than restated: the program must reach behave's registry,
    # and must not compile a pattern of its own.
    with open(os.path.join(HERE, "py", "match_steps.py"), encoding="utf-8") \
            as fh:
        matcher_src = fh.read()
    for needle in ("load_step_modules", "registry.find_step_definition",
                   "registry.steps[keyword]"):
        check(f"the matcher goes through behave's own `{needle}`",
              needle in matcher_src)
    compiles = [ln.strip() for ln in matcher_src.splitlines()
                if "re.compile" in ln]
    check("the matcher compiles exactly ONE regex of its own, and it is the "
          "typed-field reader rather than a step pattern -- the "
          "match_steps.php:2-19 rule, checked against the bytes",
          len(compiles) == 1 and compiles[0].startswith("_TYPED_FIELD"),
          str(compiles))

    print("\n" + ("ALL PASS (pystep_index)" if ok else "FAILURES (pystep_index)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
