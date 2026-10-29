"""Gherkin parsing for the requirement-to-test benchmark.

`r2t/toolkit/extract.py` parses features well enough to emit ITEMS (title,
line, raw block text).  Executing an item needs more: the step list as
Behat sees it (keyword resolution for And/But, multiline arguments), the
tags that decide suite membership, and the ability to write a STANDALONE
`.feature` file that contains exactly one scenario plus the Background it
cannot run without.

Everything here is line-oriented and lossless: `standalone_feature()`
reproduces original source lines verbatim rather than re-rendering them,
so a system under test never sees a normalised paraphrase of the
criterion it was given.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

_FEATURE = re.compile(r"^\s*Feature\s*:\s*(.*)$")
_BACKGROUND = re.compile(r"^\s*Background\s*:\s*(.*)$")
_SCENARIO = re.compile(
    r"^\s*(Scenario Outline|Scenario Template|Scenario|Example)\s*:\s*(.*)$")
_EXAMPLES = re.compile(r"^\s*(Examples|Scenarios)\s*:\s*(.*)$")
_TAGLINE = re.compile(r"^\s*@\S")
_STEP = re.compile(r"^\s*(Given|When|Then|And|But|\*)\s+(.*)$")
_PYSTRING = re.compile(r'^\s*("""|\'\'\')\s*$')
_TABLE_ROW = re.compile(r"^\s*\|")
_COMMENT = re.compile(r"^\s*#")
_BLOCK_START = re.compile(
    r"^\s*(Feature|Background|Scenario Outline|Scenario Template|Scenario"
    r"|Example|Examples|Scenarios|Rule)\s*:")

#: Keywords that do not carry their own semantics; they inherit the
#: previous concrete keyword.  Behat resolves these the same way.
_INHERITING = {"And", "But", "*"}


@dataclass
class Step:
    keyword: str            # as written: Given/When/Then/And/But/*
    resolved: str           # Given/When/Then after And/But resolution
    text: str
    line: int               # 1-based
    end_line: int           # last line of the step incl. its argument
    arg_kind: Optional[str] = None      # None | "table" | "pystring"

    @property
    def source_span(self) -> tuple[int, int]:
        return (self.line, self.end_line)


@dataclass
class Block:
    """A Background or a Scenario/Scenario Outline."""
    kind: str               # "Background" | "Scenario" | "Scenario Outline" | ...
    title: str
    line: int               # line of the keyword itself (1-based)
    tag_line: Optional[int]  # first line of the tag block above it, if any
    end_line: int           # last source line belonging to this block
    tags: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    examples_lines: list[tuple[int, int]] = field(default_factory=list)

    @property
    def start_line(self) -> int:
        return self.tag_line if self.tag_line is not None else self.line


@dataclass
class Feature:
    path: str
    title: Optional[str]
    line: Optional[int]
    tags: list[str]
    tag_line: Optional[int]
    narrative: str
    background: Optional[Block]
    scenarios: list[Block]
    lines: list[str]

    def scenario_at(self, line: int) -> Optional[Block]:
        for s in self.scenarios:
            if s.line == line:
                return s
        return None


def _tags_on(line: str) -> list[str]:
    return re.findall(r"@[^\s@]+", line)


def _collect_tag_block(lines: list[str], idx: int, *,
                       allow_tag_gaps: bool = False) -> tuple[list[str], Optional[int]]:
    """Tags attached to a block, with the project's measured gap semantics.

    Kapua's native Gherkin parser associates tags across blanks and comments.
    Existing projects retain their established contiguous-tag interpretation.
    """
    tags: list[str] = []
    first: Optional[int] = None
    j = idx - 1
    while j >= 0:
        if _TAGLINE.match(lines[j]):
            tags = _tags_on(lines[j]) + tags
            first = j
        elif not (allow_tag_gaps and (
                not lines[j].strip() or _COMMENT.match(lines[j]))):
            break
        j -= 1
    return tags, (first + 1 if first is not None else None)


def _parse_steps(lines: list[str], start: int, end: int) -> list[Step]:
    """Steps between 0-based [start, end) — comments are NOT steps."""
    steps: list[Step] = []
    last_concrete = "Given"
    i = start
    while i < end:
        ln = lines[i]
        if _COMMENT.match(ln):
            i += 1
            continue
        m = _STEP.match(ln)
        if not m:
            i += 1
            continue
        keyword, text = m.group(1), m.group(2).strip()
        resolved = keyword if keyword not in _INHERITING else last_concrete
        if keyword not in _INHERITING:
            last_concrete = keyword
        j = i + 1
        arg_kind = None
        # A PyString or a table immediately following belongs to the step.
        while j < end and not lines[j].strip():
            break
        if j < end and _PYSTRING.match(lines[j]):
            arg_kind = "pystring"
            fence = lines[j].strip()
            j += 1
            while j < end and lines[j].strip() != fence:
                j += 1
            j += 1
        elif j < end and _TABLE_ROW.match(lines[j]):
            arg_kind = "table"
            while j < end and _TABLE_ROW.match(lines[j]):
                j += 1
        steps.append(Step(keyword=keyword, resolved=resolved, text=text,
                          line=i + 1, end_line=j, arg_kind=arg_kind))
        i = j
    return steps


def parse_feature_file(path: str, text: Optional[str] = None, *,
                       allow_tag_gaps: bool = False) -> Feature:
    if text is None:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    lines = text.split("\n")

    feature_idx = None
    title = None
    for i, ln in enumerate(lines):
        m = _FEATURE.match(ln)
        if m:
            feature_idx, title = i, m.group(1).strip()
            break

    ftags, ftag_line = ([], None)
    if feature_idx is not None:
        ftags, ftag_line = _collect_tag_block(
            lines, feature_idx, allow_tag_gaps=allow_tag_gaps)

    # Every structural line, so a block's extent is "up to the next one".
    starts: list[tuple[int, str]] = []
    for i, ln in enumerate(lines):
        if _BLOCK_START.match(ln):
            starts.append((i, ln))

    narrative_lines: list[str] = []
    if feature_idx is not None:
        for ln in lines[feature_idx + 1:]:
            if _BLOCK_START.match(ln) or _TAGLINE.match(ln):
                break
            narrative_lines.append(ln)
    narrative = "\n".join(narrative_lines).strip("\n")

    background: Optional[Block] = None
    scenarios: list[Block] = []

    for pos, (i, ln) in enumerate(starts):
        nxt = starts[pos + 1][0] if pos + 1 < len(starts) else len(lines)
        # A scenario's own extent stops at the next structural line, but
        # its Examples tables belong to it.
        bgm = _BACKGROUND.match(ln)
        if bgm:
            blk = Block(kind="Background", title=bgm.group(1).strip(),
                        line=i + 1, tag_line=None, end_line=nxt)
            blk.steps = _parse_steps(lines, i + 1, nxt)
            if background is None:
                background = blk
            continue
        m = _SCENARIO.match(ln)
        if not m:
            continue
        tags, tag_line = _collect_tag_block(lines, i, allow_tag_gaps=allow_tag_gaps)
        blk = Block(kind=m.group(1).strip(), title=m.group(2).strip(),
                    line=i + 1, tag_line=tag_line, end_line=nxt, tags=tags)
        blk.steps = _parse_steps(lines, i + 1, nxt)
        # Absorb any Examples blocks that directly follow.
        k = pos + 1
        while k < len(starts) and _EXAMPLES.match(starts[k][1]):
            ex_start = starts[k][0]
            ex_end = starts[k + 1][0] if k + 1 < len(starts) else len(lines)
            blk.examples_lines.append((ex_start, ex_end))
            blk.end_line = ex_end
            k += 1
        scenarios.append(blk)

    return Feature(path=path, title=title,
                   line=(feature_idx + 1) if feature_idx is not None else None,
                   tags=ftags, tag_line=ftag_line, narrative=narrative,
                   background=background, scenarios=scenarios, lines=lines)


def _trim(block_lines: list[str]) -> list[str]:
    """Drop trailing blank lines.  Tags are handled by `_extent`, upstream.

    A trailing tag line is not trimmed away here on purpose: by the time a
    slice reaches this function it must already be only its own block's
    lines, so a tag surviving to the end is a SOURCE that ends on dangling
    tags, and silently deleting it would hide that.  `_extent` is what stops
    the next block's tags entering the slice at all.
    """
    while block_lines and not block_lines[-1].strip():
        block_lines.pop()
    return block_lines


def _extent(feature: Feature, block: Block) -> int:
    """0-based slice end for `block`: its own lines, never the next block's tags.

    `Block.end_line` runs to the next STRUCTURAL line (`Scenario:`,
    `Examples:`, `Background:`), and a tag line is NOT structural — so a
    verbatim slice to `end_line` carries the tag block belonging to whatever
    comes next.  `Block.start_line` is already the honest left edge of a
    block (`tag_line` when it has tags, else the keyword line), so clamping
    to the next block's `start_line` keeps every leaked tag out of the slice
    rather than cleaning it up afterwards.

    Left unclamped those tags are silent corruption in both
    `standalone_feature` slices.  After a Background they duplicate the
    scenario's own tag line.  After the scenario itself they are an orphan
    at EOF, and Gherkin then refuses the WHOLE file --

        (N:0): unexpected end of file, expected: #TagLine, #ScenarioLine,
               #Comment, #Empty

    -- so no scenario runs, both validation legs report `no_scenario_ran`,
    and the item is excluded `missing_scenario` for a property of its
    NEIGHBOUR rather than of itself.  That is what excluded 38 of the 59
    Algorand N=3 candidates (PROVENANCE A19/A20, RECONCILIATION 2026-08-11).
    """
    later = [other.start_line for other in feature.scenarios
             if other.start_line > block.line]
    if feature.background is not None \
            and feature.background.start_line > block.line:
        later.append(feature.background.start_line)
    end = min([block.end_line] + [start - 1 for start in later])
    # The clamp above cannot reach one shape: a source whose LAST block is
    # followed by tags that annotate nothing.  There is no next block to
    # clamp to, so those tags would reach EOF and cost the whole file for
    # the same reason.  A tag can only survive to the end of an already
    # clamped slice in that case, so retreating over it here stays exact.
    # Zero occurrences across the 143 corpus feature files; the invariant
    # "the emitted feature is parse-safe" should not depend on that.
    while end > block.line and (not feature.lines[end - 1].strip()
                                or _TAGLINE.match(feature.lines[end - 1])):
        end -= 1
    return end


def standalone_feature(feature: Feature, scenario: Block,
                       keep_tags: bool = True, *,
                       prerequisite_tag: str | None = None,
                       allow_tag_gaps: bool = False) -> str:
    """A `.feature` file holding the selected scenario and its prerequisites.

    Contains the feature header (tags + `Feature:` + narrative), the
    Background when one exists — the scenario cannot run without it —
    and the scenario itself with its own tags and `Examples:` tables.
    Lines are copied verbatim from the source. When a project's runner
    declares a prerequisite tag, copy the matching prerequisite scenarios
    before the selected item, including their original tag lines. Kapua's
    setup hooks depend on those tags; they are not Background steps.

    The result is EOF-clean whatever the source tag layout is: `_extent`
    clamps both copied slices to the next block's `start_line`, so the
    following scenario's tags never enter the file and it cannot end on an
    orphan tag that makes Gherkin refuse it.  Whether an item is runnable is
    therefore a property of the item, not of whichever scenario happens to
    sit after it in the source file.
    """
    if allow_tag_gaps:
        # Callers may have parsed the item through the shared legacy path.
        # Recover native tags from the exact same source and scenario line.
        feature = parse_feature_file(feature.path, "\n".join(feature.lines),
                                     allow_tag_gaps=True)
        scenario = feature.scenario_at(scenario.line)
        if scenario is None:
            raise ValueError("selected scenario is absent from its source feature")
    out: list[str] = []
    if keep_tags and feature.tags:
        out.append(" ".join(feature.tags))
    out.append(f"Feature: {feature.title or ''}".rstrip())
    if feature.narrative.strip():
        out.extend(feature.narrative.split("\n"))
    out.append("")

    if feature.background is not None:
        bg = feature.background
        out.extend(_trim(feature.lines[bg.line - 1:_extent(feature, bg)]))
        out.append("")

    if prerequisite_tag is not None:
        for prerequisite in feature.scenarios:
            if prerequisite.line == scenario.line \
                    or prerequisite_tag not in prerequisite.tags:
                continue
            out.extend(_trim(feature.lines[
                prerequisite.start_line - 1:_extent(feature, prerequisite)]))
            out.append("")

    sc_lines = feature.lines[scenario.line - 1:_extent(feature, scenario)]
    if keep_tags and scenario.tags:
        out.append("  " + " ".join(scenario.tags))
    out.extend(_trim(list(sc_lines)))
    out.append("")
    return "\n".join(out)


def live_step_count(scenario: Block, background: Optional[Block] = None,
                    include_background: bool = False) -> int:
    n = len(scenario.steps)
    if include_background and background is not None:
        n += len(background.steps)
    return n


def is_commented_out(scenario: Block) -> bool:
    """A scenario whose body has no live steps at all.

    Note what this does and does not catch.  A scenario whose `Scenario:`
    line is ITSELF commented out never becomes a Block, so it cannot
    reach here — that is what CoreShop's currency/context.feature:21,25
    look like, and the extractor drops them earlier.  This rule is for the
    other shape: a live heading over a body whose steps are all commented
    out.  On CoreShop domain it fires zero times; it is kept because SPEC
    §7.4 asks for it and the ART expansion corpora are not this clean.
    """
    return not scenario.steps


def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    src = '''@domain @cart
Feature: Cart totals

  As a shopper
  I want totals

  Background:
    Given the site operates on a store in "Austria"
    And there is a product "T-Shirt"

  @wip
  Scenario: Add a product
    Given I add the product "T-Shirt" to my cart
    And the cart should contain:
      | product | qty |
      | T-Shirt | 1   |
    Then the total should be "2400"

  Scenario Outline: Templated
    When I add <n> products
    Then the total is <total>

    Examples:
      | n | total |
      | 1 | 2400  |

  Scenario: Disabled on purpose
#    Given nothing
'''
    f = parse_feature_file("mem.feature", src)
    check("feature tags", f.tags == ["@domain", "@cart"], str(f.tags))
    check("narrative kept", "As a shopper" in f.narrative)
    check("background steps", f.background is not None
          and len(f.background.steps) == 2)
    check("three scenarios", len(f.scenarios) == 3,
          str([s.title for s in f.scenarios]))

    sc = f.scenarios[0]
    check("scenario tags", sc.tags == ["@wip"], str(sc.tags))
    check("3 steps in first scenario", len(sc.steps) == 3,
          str([s.text for s in sc.steps]))
    check("And resolves to Given",
          sc.steps[1].resolved == "Given" and sc.steps[1].keyword == "And")
    check("table arg attached", sc.steps[1].arg_kind == "table")
    check("Then resolves to Then", sc.steps[2].resolved == "Then")

    out = f.scenarios[1]
    check("outline kind", out.kind == "Scenario Outline", out.kind)
    check("examples retained", "| 1 | 2400  |" in standalone_feature(f, out),
          standalone_feature(f, out))

    dis = f.scenarios[2]
    check("commented-out scenario has no live steps", is_commented_out(dis))

    sa = standalone_feature(f, sc)
    check("standalone has background", 'store in "Austria"' in sa)
    check("standalone has only its own scenario",
          "Templated" not in sa and "Disabled" not in sa, sa)
    check("standalone keeps feature tags", sa.startswith("@domain @cart"))
    check("standalone keeps scenario tags", "@wip" in sa)
    check("standalone verbatim step text",
          'Given I add the product "T-Shirt" to my cart' in sa)

    # A scenario directly followed by another with no blank line.
    tight = """Feature: F
  Scenario: A
    Given a
  Scenario: B
    Given b
"""
    f2 = parse_feature_file("t.feature", tight)
    check("tight scenarios split", len(f2.scenarios) == 2
          and len(f2.scenarios[0].steps) == 1, str(f2.scenarios))

    # ---- the orphan tag line: the emitted file must be EOF-clean --------
    # Red fixture, the exact shape of the Algorand `_bench_item.feature`
    # retained at restore-attempt-1 (`d51b6e67…`): an outline with an
    # Examples table, followed by a TAGGED scenario.  Before the `_trim`
    # fix the emitted bytes ended `  @unit.indexer.rekey` + EOF and Gherkin
    # refused the whole file, so nothing ran.
    orphan = """@unit
Feature: Indexer Client v2 Responses

  Background:
    Given a client

  @unit.indexer
  Scenario Outline: SearchForAssets response
    Given mock http responses in "<jsonfiles>"
    Examples:
      | jsonfiles              |
      | searchForAssets_0.json |

  @unit.indexer.rekey
  Scenario Outline: SearchForTransactions response, rekey-to
    Given mock http responses in "<jsonfiles>"
    Examples:
      | jsonfiles                    |
      | searchForTransactions_1.json |
"""
    f3 = parse_feature_file("orphan.feature", orphan)
    first, second = f3.scenarios[0], f3.scenarios[1]

    # ANTI-VACUITY: the fixture must really carry the shape under test --
    # a following scenario whose tag line falls inside the first
    # scenario's verbatim extent.  If this ever stops holding, the checks
    # below would pass for the wrong reason.
    raw = f3.lines[first.line - 1:first.end_line]
    check("orphan fixture is loaded: next scenario's tag is inside the slice",
          any(_TAGLINE.match(ln) for ln in raw)
          and second.tags == ["@unit.indexer.rekey"], str(raw[-3:]))
    raw_bg = f3.lines[f3.background.line - 1:f3.background.end_line]
    check("orphan fixture is loaded: a tag also trails the Background",
          any(_TAGLINE.match(ln) for ln in raw_bg), str(raw_bg))

    emitted = standalone_feature(f3, first)
    body = [ln for ln in emitted.split("\n") if ln.strip()]
    check("emitted feature does not end on a tag line",
          not _TAGLINE.match(body[-1]), repr(body[-1]))
    check("emitted feature ends on the Examples row it should",
          body[-1].strip() == "| searchForAssets_0.json |", repr(body[-1]))
    check("the next scenario's tag never reaches the emitted file",
          "@unit.indexer.rekey" not in emitted, emitted)
    check("the next scenario's body never reaches the emitted file",
          "rekey-to" not in emitted and "searchForTransactions_1" not in emitted)
    check("the item's own tag and steps survive",
          "@unit.indexer" in emitted and "SearchForAssets response" in emitted
          and "| searchForAssets_0.json |" in emitted)
    check("the Background survives the same trim",
          "Given a client" in emitted)
    check("emitted feature is newline-terminated", emitted.endswith("\n"))

    # The other half of the rule: a tag that annotates an `Examples:` table
    # sits BEFORE a structural line, so it is never last and must survive.
    tagged_examples = """Feature: F

  Scenario Outline: X
    Given <a>
    @slow
    Examples:
      | a |
      | 1 |

  @next
  Scenario: Y
    Given b
"""
    f4 = parse_feature_file("te.feature", tagged_examples)
    em4 = standalone_feature(f4, f4.scenarios[0])
    check("a tag on an Examples block is kept", "@slow" in em4, em4)
    check("the following scenario's tag is still dropped",
          "@next" not in em4, em4)

    # The shape the clamp alone cannot reach: the LAST block is followed by
    # tags annotating nothing, so there is no next `start_line` to clamp to.
    # Absent from all 143 corpus feature files; pinned because the invariant
    # "the emitted feature is parse-safe" must not rest on that.
    f5 = parse_feature_file(
        "d.feature", "Feature: F\n\n  Scenario: A\n    Given a\n\n  @dangling\n")
    em5 = standalone_feature(f5, f5.scenarios[0])
    body5 = [ln for ln in em5.split("\n") if ln.strip()]
    check("a source ending on dangling tags still emits a parse-safe file",
          not _TAGLINE.match(body5[-1]) and "@dangling" not in em5, em5)
    check("and it keeps the scenario it was asked for",
          "Scenario: A" in em5 and "Given a" in em5, em5)

    setup_source = '''@env_none
Feature: Account service

  @setup
  @KapuaProperties("locator.class.impl=org.eclipse.kapua.qa.common.MockedLocator")
  Scenario: Initialize test environment
    Given Init Security Context

  @account
  Scenario: Create an account
    When I create an account
    Then the account exists

  @teardown
  Scenario: Stop test environment
    Given Close Security Context
'''
    setup_feature = parse_feature_file("AccountService.feature", setup_source)
    setup_item = setup_feature.scenarios[1]
    with_setup = standalone_feature(
        setup_feature, setup_item, prerequisite_tag="@setup")
    parsed_setup = parse_feature_file("_bench_item.feature", with_setup)
    check("project prerequisite precedes the selected item",
          [s.title for s in parsed_setup.scenarios]
          == ["Initialize test environment", "Create an account"])
    setup = setup_feature.scenarios[0]
    setup_bytes = "\n".join(setup_feature.lines[
        setup.start_line - 1:_extent(setup_feature, setup)])
    check("prerequisite tag lines and body survive verbatim",
          setup_bytes in with_setup and parsed_setup.tags == ["@env_none"]
          and parsed_setup.scenarios[0].tags == setup.tags)
    check("prerequisite selection does not copy teardown",
          "@teardown" not in with_setup
          and "Close Security Context" not in with_setup)
    check("existing synthesis remains one scenario without a project quirk",
          len(parse_feature_file("single.feature", standalone_feature(
              setup_feature, setup_item)).scenarios) == 1)
    check("selecting the setup scenario does not duplicate it",
          len(parse_feature_file("setup.feature", standalone_feature(
              setup_feature, setup, prerequisite_tag="@setup")).scenarios) == 1)

    # The pinned Account feature separates @account/@env_none from Feature
    # with a blank line. Dropping @env_none makes its native runner run zero
    # tests. Also cover comments/gaps around setup and the following item.
    gapped = setup_source.replace("@env_none\nFeature:",
                                  "@account\n@env_none\n\nFeature:")
    gapped = gapped.replace("  @setup\n", "  @setup\n  # setup hook\n\n")
    gapped = gapped.replace("  @teardown\n", "  @teardown\n\n")
    legacy = parse_feature_file("gapped.feature", gapped)
    native = parse_feature_file("gapped.feature", gapped, allow_tag_gaps=True)
    emitted = standalone_feature(legacy, legacy.scenarios[1],
                                 prerequisite_tag="@setup", allow_tag_gaps=True)
    recovered = parse_feature_file("emitted.feature", emitted, allow_tag_gaps=True)
    check("Kapua keeps native tags across blank and comment lines",
          native.tags == ["@account", "@env_none"]
          and "@setup" in native.scenarios[0].tags
          and native.scenarios[2].tags == ["@teardown"])
    check("Kapua synthesis recovers feature tags and exactly the prerequisite",
          recovered.tags == native.tags
          and [s.title for s in recovered.scenarios] == [
              "Initialize test environment", "Create an account"]
          and recovered.scenarios[0].tags == native.scenarios[0].tags
          and recovered.scenarios[1].tags == ["@account"]
          and "@teardown" not in emitted, emitted)
    check("without setup, the native environment tag still selects the item",
          parse_feature_file("without.feature", standalone_feature(
              legacy, legacy.scenarios[1], allow_tag_gaps=True)).tags == native.tags)
    check("other projects retain contiguous-tag parsing and synthesis",
          legacy.tags == [] and "@env_none" not in standalone_feature(
              legacy, legacy.scenarios[1]))

    print("\n" + ("ALL PASS (gherkin)" if ok else "FAILURES (gherkin)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
