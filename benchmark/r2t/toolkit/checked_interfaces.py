"""Checked interfaces -- the product methods an item's actions and checks call.

TARGET_INTERFACES_V2_SPEC.md sections 3, 8 and 9, implementation step 2.  For
one item the list is the first-party PUBLIC production methods that the
reference test called DIRECTLY from its own action and check steps, read off
the gold run's per-step call attribution:

  * **which step made the call** is the recorder's `step` field -- the 0-based
    index into the row's `per_step` list, the Background's steps first, `null`
    for a call a hook made between two steps (`py/bench_environment.py`, and
    its four sibling recorders).  Nothing here re-derives it;
  * **what the step IS** is decided here and only here, from the released
    item's own Gherkin: `core/gherkin.Step.resolved` resolves And/But, and
    `toolkit/quality._ORACLE` -- the same regex that already produces
    `bench_meta.n_oracle_steps` -- decides a check.  The oracle rule is
    keyword-independent on purpose: 14 CoreShop items write their assertions
    as `Given`, and a keyword-only rule would call those items empty;
  * **what a call CREDITS** is `bench/metrics.direct_methods`'s rule, per
    role rather than per row: the callee's file classifies production, the
    caller's classifies removable, the identity is the index join (Python's
    declaration line and its accessor bindings, PHP's attribute-span rule,
    Ruby's bindings, Java's descriptor), and the method is public.  The
    module's own self-test holds the union of the per-role sets to
    `direct_methods`' set on the same row, so the two can never drift.

`checked` is the union of the action and the check sets minus the
constructors attributed to check steps -- a check step builds its expected
value (`Inches(1)`), and that construction is not the interface under check.
A constructor an ACTION step called stays: the exclusion is about the role,
not about the name.  On the pinned python-docx gold run 12 items call a
constructor from a check step and 8 of them lose the entry; the other 4 call
the same constructor from an action step too.

An empty list is a value with a reason (`no_action_or_check_call`), never an
exclusion, and the summary enumerates what produced each one.

REFUSALS (section 9, as the review trimmed it).  Naming the item every time:
a row that predates the per-step field (`harness_version` < 18, or an event
without `step`); a row whose outcome is not `passed`; a row whose `per_step`
length is not the item's Background plus scenario step count; an action or
check call whose callee is production and whose caller is removable but which
the pinned index does not know (every such callee is named).  The verb takes
the index, boundary and release as arguments and records their digests, which
is their identity -- there is no separate identity clause.

    python3 -m r2t.cli checked-interfaces --gold gold.jsonl --index prod.json \\
        --boundary config/boundary_<project>.yml --items items.jsonl \\
        --source-root <pinned source> --out checked_interfaces.json
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import statistics
import subprocess
from dataclasses import dataclass
from typing import Optional

from ..bench.metrics import (Accessor, Method, _norm, direct_record_issue,
                             load_prod_index, read_runs,
                             refuse_stale_python_index)
from ..core.boundary import PRODUCTION, REMOVABLE, Boundary, load_boundary
from ..core.gherkin import Block, parse_feature_file
from .quality import _ORACLE

SCHEMA = "r2t.checked-interfaces/1"

#: The harness version that first stamped `step` on every direct-call event
#: (TARGET_INTERFACES_V2_SPEC section 4).  A row below it carries calls whose
#: step is unknown, and guessing one would invent the attribution this whole
#: derivation is.
#:
#: This is MASTER's 18.  The mutation-evaluation-collection-v1.1 line also
#: minted an 18, cut from H12, whose rows have no `step` -- so the number
#: alone does not separate them.  It does not have to: the per-event check in
#: `_check_row` refuses any row whose call events lack `step`, whatever it is
#: stamped.  The gate stays at 18 because master-18 rows are exactly what the
#: checked-interfaces v2 lanes collect.
STEP_TAG_HARNESS_VERSION = 18

#: The single reason an empty list carries (section 3.4).
EMPTY_NO_ACTION_OR_CHECK_CALL = "no_action_or_check_call"

#: Why an item's list came out empty.  `only_unjoined_calls` is the public
#: filter, not the index: an action or check call the index does not know at
#: all is a REFUSAL, so the only way a direct call can reach this bucket is by
#: being a non-public method the index does know.
CAUSE_NO_CALL = "no_production_call"
CAUSE_ONLY_CONSTRUCTORS = "only_constructors_in_check_steps"
CAUSE_ONLY_UNJOINED = "only_unjoined_calls"

#: Every spelling of a constructor across the five stacks.  Java's key name
#: carries its descriptor (`<init>:(I)V`), so the test is on the part before
#: the colon; Ruby's key is (owner, kind, name) and Python's accessors end in
#: `.setter`/`.deleter`, so the test is always on the key's LAST component.
CONSTRUCTORS = frozenset({"__init__", "__new__", "__construct", "<init>",
                          "initialize"})

#: The roles a step can have.  `hook` is not a step: it is what an event
#: carries when the recorder saw it between two steps.
ROLES = ("action", "check", "context", "background", "hook")

#: A PHP signature's first line: the modifiers, then `function`.  The index
#: starts an attributed method on its `#[...]` line, so the span's first line
#: is not always the signature.
_PHP_SIGNATURE = re.compile(
    r"^(?:(?:final|abstract|public|protected|private|static|readonly)\s+)*"
    r"function\b")

_JAVA_PRIMITIVES = {"B": "byte", "C": "char", "D": "double", "F": "float",
                    "I": "int", "J": "long", "S": "short", "Z": "boolean",
                    "V": "void"}


class CheckedInterfacesRefused(RuntimeError):
    """A gold row, item or source tree cannot support the derivation.

    Raised rather than dropping the item: a missing attribution is not an
    empty list, and section 9 requires the item to be named.
    """


# --------------------------------------------------------------------------
# steps

def _parse_background(item: dict) -> list:
    """The item's Background steps, from the text the release row carries."""
    text = item["requirement"].get("background")
    if not text:
        return []
    feature = parse_feature_file("<background>", text=text)
    if feature.background is None:
        raise CheckedInterfacesRefused(
            f"{item['item_id']}: requirement.background carries text that "
            f"parses to no Background block")
    return feature.background.steps


def _parse_scenario(item: dict) -> Block:
    """The item's own scenario, from `criterion.gherkin` (keyword lines and all)."""
    scenarios = parse_feature_file(
        "<criterion>", text=item["criterion"]["gherkin"]).scenarios
    if len(scenarios) != 1:
        raise CheckedInterfacesRefused(
            f"{item['item_id']}: criterion.gherkin parses to "
            f"{len(scenarios)} scenarios, not one")
    return scenarios[0]


def step_roles(item: dict) -> list[str]:
    """One role per step, in the order the recorder's `step` indexes them.

    Background first (never counted, whatever its keyword), then the
    scenario's own steps: a check is a `Then` or an oracle match, an action
    is a `When` that is not a check, everything else is context.  The counts
    are held to `bench_meta`'s own record of the same parse, because a
    Background that does not reproduce shifts every index by its own length
    and would silently re-attribute the whole item.
    """
    background = _parse_background(item)
    scenario = _parse_scenario(item)
    meta = item["bench_meta"]
    if (len(background) != meta["live_background_step_count"]
            or len(scenario.steps) != meta["live_step_count"]):
        raise CheckedInterfacesRefused(
            f"{item['item_id']}: the released Gherkin parses to "
            f"{len(background)} Background and {len(scenario.steps)} scenario "
            f"steps, but bench_meta records "
            f"{meta['live_background_step_count']} and "
            f"{meta['live_step_count']}")
    roles = ["background"] * len(background)
    for step in scenario.steps:
        check = step.resolved == "Then" or bool(_ORACLE.search(step.text))
        roles.append("check" if check
                     else ("action" if step.resolved == "When" else "context"))
    return roles


# --------------------------------------------------------------------------
# crediting one event

@dataclass(frozen=True)
class Credited:
    """One index entry a call event resolved to, with the file that declares it."""
    rel: str
    obj: object            # Method | Accessor

    @property
    def key(self) -> tuple:
        return self.obj.key

    @property
    def span(self) -> tuple[int, int]:
        """The declaring lines this entry covers, for the leakage figure."""
        if isinstance(self.obj, Accessor):
            return (self.obj.declaring_line, self.obj.declaring_line)
        low = self.obj.decl if self.obj.decl is not None else self.obj.start
        return (min(low, self.obj.start), self.obj.end)


def _credit(event: dict, boundary: Boundary, index, ruby: bool,
            item_id: str) -> Optional[tuple]:
    """`direct_methods`' rule for ONE event: (kind, payload) or None.

    `None` is an event the metric ignores entirely and counts nowhere --
    production calling production, the retained substrate, a caller with no
    source file.  `("credited", [Credited, ...])` is a public index entry,
    `("unjoined", callee)` an index entry the definition excludes because it
    is not public, and `("unmapped", callee)` a direct call the index does
    not know.  Held to `direct_methods` by this module's self-test.
    """
    callee = event["callee"]
    if event["callee_file"] is None:
        return None
    callee_file = _norm(event["callee_file"])
    java = callee_file.endswith(".java")
    name = callee.split(":", 1)[0] if java else callee
    name = name.rsplit(".", 1)[-1]
    if not ruby and name.startswith("<") and not (java and name == "<init>"):
        return None
    caller_file = event["caller_file"]
    if boundary.classify(callee_file) != PRODUCTION:
        return None
    if not isinstance(caller_file, str) \
            or boundary.classify(_norm(caller_file)) != REMOVABLE:
        return None

    def resolved(entries: list) -> tuple:
        public = [e for e in entries if e.obj.public]
        return ("credited", public) if public else ("unjoined", callee)

    if ruby:
        binding = event["ruby_binding"]
        identity = (tuple(binding[k] for k in
                          ("declaring_file", "declaring_line", "owner",
                           "method_kind", "method_name"))
                    if binding else None)
        method = index.ruby_bindings.get(identity)
        if method is None:
            return ("unmapped", callee)
        return resolved([Credited(_norm(binding["declaring_file"]), method)])

    binding = event.get("accessor_binding") if callee_file.endswith(".py") else None
    if binding is not None:
        try:
            declaring_file = _norm(binding["declaring_file"])
            identity = (declaring_file, binding["declaring_line"],
                        binding["owner"], binding["attribute"],
                        binding["access_kind"])
        except (KeyError, TypeError):
            # `direct_methods` withholds the whole row's API set on this;
            # here it is the item's refusal, because an incomplete binding is
            # not an empty measured set.
            raise CheckedInterfacesRefused(
                f"{item_id}: accessor binding evidence for {callee} is "
                f"incomplete, so the call cannot be attributed")
        accessor = index.accessors.get(identity)
        if boundary.classify(declaring_file) != PRODUCTION:
            return None
        if accessor is None:
            return ("unmapped", callee)
        return resolved([Credited(declaring_file, accessor)])

    line = event["callee_line"]
    methods = index.get(callee_file, ())
    if java:
        exact = [m for m in methods if m.descriptor is not None
                 and f"{m.fqcn}.{m.name}:{m.descriptor}" == callee]
    else:
        exact = [m for m in methods
                 if (m.decl if m.decl is not None else m.start) == line]
    if exact:
        return resolved([Credited(callee_file, m) for m in exact])
    if not java and "<locals>" in callee:
        enclosing = [m for m in methods if m.start <= line <= m.end]
        if not enclosing:
            return ("unmapped", callee)
        fold = max(enclosing, key=lambda m: m.start)
        return resolved([Credited(callee_file, fold)])
    if callee_file.endswith(".php"):
        spanning = [m for m in methods if m.start <= line <= m.end]
        if not spanning:
            return ("unmapped", callee)
        hit = max(spanning, key=lambda m: m.start)
        return resolved([Credited(callee_file, hit)])
    return ("unmapped", callee)


# --------------------------------------------------------------------------
# declarations

def _read_source(source_root: str, rel: str, item_id: str) -> list[str]:
    path = os.path.join(source_root, rel)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().split("\n")
    except OSError as exc:
        raise CheckedInterfacesRefused(
            f"{item_id}: the pinned source root has no readable {rel} "
            f"({exc.strerror}); the declaration cannot be read") from exc


def _logical(lines: list[str], start: int, stops: str, comments: tuple,
             *, include_stop: bool) -> Optional[str]:
    """Physical lines from `start`, joined to the first `stops` char at depth 0.

    An empty `stops` means "until the brackets balance at the end of a line",
    which is what a declaration with no terminator (a Python class-body
    attribute, a Ruby `def`) needs.

    Comments are dropped (quote-aware, so a `#` inside a string literal is
    kept) because python-docx writes its generated attribute declarations as
    `id: int = RequiredAttribute(  # pyright: ignore[...]` across two lines,
    and a naive join would bury the rest of the declaration behind a `#`.
    Returns None when the source runs out before the terminator.
    """
    out: list[str] = []
    depth = 0
    quote = ""
    for raw in lines[start:]:
        i = 0
        piece: list[str] = []
        while i < len(raw):
            ch = raw[i]
            if quote:
                piece.append(ch)
                if ch == "\\":
                    if i + 1 < len(raw):
                        piece.append(raw[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
                i += 1
                continue
            if ch in "\"'":
                quote = ch
                piece.append(ch)
                i += 1
                continue
            if any(raw.startswith(token, i) for token in comments):
                break
            # The terminator is tested BEFORE the bracket counter, because a
            # `{` is both PHP's body opener and a bracket.
            if depth == 0 and ch in stops:
                if include_stop:
                    piece.append(ch)
                out.append("".join(piece))
                return " ".join(" ".join(out).split())
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            piece.append(ch)
            i += 1
        out.append("".join(piece))
        if not stops and depth == 0:
            return " ".join(" ".join(out).split())
    return None


def _python_declaration(lines: list[str], method: Method, rel: str,
                        item_id: str) -> str:
    """`def name(...):`, from the first `def` at or after the declaration line.

    The declaration line is the first decorator where there is one, which is
    what the call event reports; `start` is the first body statement, so the
    `def` is strictly between them.
    """
    low = (method.decl if method.decl is not None else method.start) - 1
    for i in range(max(low, 0), max(method.start, low + 1)):
        if i >= len(lines):
            break
        stripped = lines[i].lstrip()
        if stripped.startswith("def ") or stripped.startswith("async def "):
            text = _logical(lines, i, ":", ("#",), include_stop=True)
            if text is not None:
                return text
            break
    raise CheckedInterfacesRefused(
        f"{item_id}: {rel} has no complete `def` signature for "
        f"{method.fqcn}.{method.name} at line {method.decl or method.start}")


def _accessor_declaration(lines: list[str], accessor: Accessor, rel: str,
                          item_id: str) -> str:
    """The class-body statement that installs a generated accessor.

    A schema-2 accessor has no `def` of its own: `id: int =
    RequiredAttribute("w:id", ST_DecimalNumber)` IS the declaration, and it is
    what a reader of the source sees.
    """
    i = accessor.declaring_line - 1
    if 0 <= i < len(lines):
        text = _logical(lines, i, "", ("#",), include_stop=False)
        if text:
            return text
    raise CheckedInterfacesRefused(
        f"{item_id}: {rel} has no declaration for {accessor.fqcn}."
        f"{accessor.attribute} at line {accessor.declaring_line}")


def _php_declaration(lines: list[str], method: Method, rel: str,
                     item_id: str) -> str:
    """The `function` signature, without its attributes and docblock.

    The PHP index starts an attributed method on its `#[...]` line, so the
    span's first line is not always the signature; the first line that opens
    with the modifiers and `function` is.  The body's `{` (or an abstract
    declaration's `;`) ends it and is not part of it.
    """
    for i in range(method.start - 1, min(method.end, len(lines))):
        if i < 0:
            continue
        if _PHP_SIGNATURE.match(lines[i].lstrip()):
            text = _logical(lines, i, "{;", ("//", "#"), include_stop=False)
            if text is not None:
                return text
            break
    raise CheckedInterfacesRefused(
        f"{item_id}: {rel} has no complete `function` signature for "
        f"{method.fqcn}::{method.name} at line {method.start}")


def _ruby_declaration(lines: list[str], method: Method, rel: str,
                      item_id: str) -> str:
    """The `def` line.  Ruby signatures are one line in every indexed corpus."""
    i = (method.decl if method.decl is not None else method.start) - 1
    if 0 <= i < len(lines):
        text = _logical(lines, i, "", ("#",), include_stop=False)
        if text:
            return text
    raise CheckedInterfacesRefused(
        f"{item_id}: {rel} has no `def` line for {method.fqcn}#{method.name} "
        f"at line {method.decl or method.start}")


def _go_declaration(lines: list[str], method: Method, rel: str,
                    item_id: str) -> str:
    """The `func` signature, up to but not including the body's brace."""
    i = (method.decl if method.decl is not None else method.start) - 1
    if 0 <= i < len(lines):
        text = _logical(lines, i, "{", ("//",), include_stop=False)
        if text:
            return text
    raise CheckedInterfacesRefused(
        f"{item_id}: {rel} has no `func` signature for {method.fqcn}."
        f"{method.name} at line {method.decl or method.start}")


def _java_type(descriptor: str, i: int) -> tuple[str, int]:
    arrays = 0
    while i < len(descriptor) and descriptor[i] == "[":
        arrays += 1
        i += 1
    if i >= len(descriptor):
        raise ValueError(descriptor)
    char = descriptor[i]
    if char == "L":
        end = descriptor.index(";", i)
        name = descriptor[i + 1:end].replace("/", ".").replace("$", ".")
        i = end + 1
    elif char in _JAVA_PRIMITIVES:
        name = _JAVA_PRIMITIVES[char]
        i += 1
    else:
        raise ValueError(descriptor)
    return name + "[]" * arrays, i


def java_declaration(key: tuple) -> str:
    """`ReturnType name(ParamType, ...)`, reconstructed from the JVM descriptor.

    The Java index carries no source line -- the agent records the binary
    identity -- so the descriptor IS the declaration's source here.  Binary
    names become source names (`/` and the nest separator `$` both become
    `.`), which is how the declaration reads in the file.
    """
    name, _, descriptor = key[-1].partition(":")
    try:
        close = descriptor.index(")")
        if not descriptor.startswith("("):
            raise ValueError(descriptor)
        params, i = [], 1
        while i < close:
            param, i = _java_type(descriptor, i)
            params.append(param)
        if i != close:
            raise ValueError(descriptor)
        ret, i = _java_type(descriptor, close + 1)
        if i != len(descriptor):
            raise ValueError(descriptor)
    except ValueError as exc:
        raise CheckedInterfacesRefused(
            f"{key[0]}.{key[-1]}: the recorded descriptor is not a JVM method "
            f"descriptor") from exc
    return f"{ret} {name}({', '.join(params)})"


def _prefix(entry: Credited, properties: frozenset) -> str:
    """`(property getter|setter|deleter) `, or nothing."""
    if isinstance(entry.obj, Accessor):
        return {"get": "(property getter) ", "set": "(property setter) ",
                "delete": "(property deleter) "}[entry.obj.access_kind]
    name = entry.key[-1]
    if name.endswith(".setter"):
        return "(property setter) "
    if name.endswith(".deleter"):
        return "(property deleter) "
    if (entry.rel, entry.obj.fqcn, name) in properties:
        return "(property getter) "
    return ""


def declaration(entry: Credited, source_root: str, properties: frozenset,
                cache: dict, item_id: str) -> str:
    """One whitespace-normalised declaration line for one credited entry."""
    if entry.rel.endswith(".java"):
        return java_declaration(entry.key)
    if entry.rel not in cache:
        cache[entry.rel] = _read_source(source_root, entry.rel, item_id)
    lines = cache[entry.rel]
    if isinstance(entry.obj, Accessor):
        text = _accessor_declaration(lines, entry.obj, entry.rel, item_id)
    elif entry.rel.endswith(".py"):
        text = _python_declaration(lines, entry.obj, entry.rel, item_id)
    elif entry.rel.endswith(".php"):
        text = _php_declaration(lines, entry.obj, entry.rel, item_id)
    elif entry.rel.endswith(".rb"):
        text = _ruby_declaration(lines, entry.obj, entry.rel, item_id)
    elif entry.rel.endswith(".go"):
        text = _go_declaration(lines, entry.obj, entry.rel, item_id)
    else:
        raise CheckedInterfacesRefused(
            f"{item_id}: no declaration rule for {entry.rel}")
    return _prefix(entry, properties) + text


# --------------------------------------------------------------------------
# inputs

def property_flags(index_path: str) -> frozenset:
    """{(relative file, class, method name)} the index marks a property.

    `load_prod_index` keeps the four fields the metric is defined over and
    drops this one; the prefix `(property getter)` is a rendering fact, so it
    is read here rather than added to `Method`.
    """
    with open(index_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    files = doc.get("files") if isinstance(doc, dict) and "files" in doc else doc
    flags = set()
    for rel, entry in files.items():
        classes = entry.get("classes") if isinstance(entry, dict) else entry
        for cls in classes or []:
            for method in cls.get("methods") or []:
                if method.get("property"):
                    flags.add((_norm(rel), cls["name"], method["name"]))
    return frozenset(flags)


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def source_commit(source_root: str) -> Optional[str]:
    """The source root's git HEAD, or None when it is not a git checkout.

    The pinned corpora are exported trees as often as they are clones, so the
    absence of a commit is a fact about the input and not a failure.
    """
    try:
        done = subprocess.run(["git", "-C", source_root, "rev-parse", "HEAD"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              check=False)
    except OSError:
        return None
    if done.returncode != 0:
        return None
    return done.stdout.decode().strip() or None


def load_items(path: str) -> list[dict]:
    items = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


# --------------------------------------------------------------------------
# derivation

def _check_row(item_id: str, row: Optional[dict], roles: list[str],
               index) -> None:
    if row is None:
        raise CheckedInterfacesRefused(
            f"{item_id}: the gold file carries no row for this released item")
    version = row.get("harness_version")
    if not isinstance(version, int) or version < STEP_TAG_HARNESS_VERSION:
        raise CheckedInterfacesRefused(
            f"{item_id}: harness_version {version} predates the per-step call "
            f"attribution (>= {STEP_TAG_HARNESS_VERSION} required)")
    if row.get("outcome") != "passed":
        raise CheckedInterfacesRefused(
            f"{item_id}: the gold outcome is {row.get('outcome')!r}, not "
            f"'passed'; a list derived from a run that did not pass is not "
            f"what the reference test checks")
    events = row.get("direct_calls")
    if events is None:
        raise CheckedInterfacesRefused(
            f"{item_id}: the gold row collected no direct calls")
    issue = direct_record_issue(row, index)
    if issue is not None:
        raise CheckedInterfacesRefused(
            f"{item_id}: the gold row's call events are {issue}")
    missing = sum(1 for event in events if "step" not in event)
    if missing:
        raise CheckedInterfacesRefused(
            f"{item_id}: {missing} of {len(events)} call events carry no "
            f"'step'; the row predates the per-step attribution")
    per_step = row.get("per_step") or []
    if len(per_step) != len(roles):
        raise CheckedInterfacesRefused(
            f"{item_id}: the gold row records {len(per_step)} steps but the "
            f"released Gherkin has {len(roles)}")
    for event in events:
        step = event["step"]
        if step is not None and (type(step) is not int
                                 or not 0 <= step < len(roles)):
            raise CheckedInterfacesRefused(
                f"{item_id}: a call event names step {step!r}, which is not "
                f"one of this item's {len(roles)} steps")


def _item_detail(item: dict, row: dict, roles: list[str], boundary: Boundary,
                 index, ruby: bool) -> dict:
    """Per-role credited entries, unjoined and unmapped callees, for one item."""
    credited = {role: {} for role in ROLES}     # role -> {key: Credited}
    unmapped = {role: set() for role in ROLES}
    unjoined = {role: set() for role in ROLES}
    item_id = item["item_id"]
    for event in row["direct_calls"]:
        step = event["step"]
        role = "hook" if step is None else roles[step]
        verdict = _credit(event, boundary, index, ruby, item_id)
        if verdict is None:
            continue
        kind, payload = verdict
        if kind == "credited":
            for entry in payload:
                credited[role].setdefault(entry.key, entry)
        elif kind == "unmapped":
            unmapped[role].add(payload)
        else:
            unjoined[role].add(payload)
    named = sorted(unmapped["action"] | unmapped["check"])
    if named:
        raise CheckedInterfacesRefused(
            f"{item_id}: {len(named)} call(s) from an action or check step "
            f"name a production method the index does not know: "
            f"{', '.join(named)}")
    return {"credited": credited, "unmapped": unmapped, "unjoined": unjoined}


def _checked_keys(credited: dict) -> tuple[set, set]:
    """(checked keys, constructor keys the check-step rule excluded)."""
    action = set(credited["action"])
    check = set(credited["check"])
    excluded = {key for key in check
                if key[-1].split(":", 1)[0] in CONSTRUCTORS} - action
    return (action | check) - excluded, excluded


def _cause(detail: dict, excluded: set) -> str:
    if excluded:
        return CAUSE_ONLY_CONSTRUCTORS
    if detail["unjoined"]["action"] or detail["unjoined"]["check"]:
        return CAUSE_ONLY_UNJOINED
    return CAUSE_NO_CALL


def derive(gold: str, index: str, boundary: str, items: str,
           source_root: str) -> dict:
    """The whole artifact: one `checked_interfaces` object per released item."""
    bound = load_boundary(boundary)
    prod_index = load_prod_index(index)
    refuse_stale_python_index(prod_index, index)
    properties = property_flags(index)
    ruby = getattr(prod_index, "schema", None) == "r2t.rb_prod_index/1"
    rows = read_runs(gold)
    released = load_items(items)
    cache: dict[str, list[str]] = {}

    out_items: dict[str, dict] = {}
    out_detail: dict[str, dict] = {}
    facts: list[dict] = []
    for item in released:
        item_id = item["item_id"]
        roles = step_roles(item)
        row = rows.get(item_id)
        _check_row(item_id, row, roles, prod_index)
        detail = _item_detail(item, row, roles, bound, prod_index, ruby)
        credited = detail["credited"]
        checked, excluded = _checked_keys(credited)
        entries = []
        for key in sorted(checked):
            entry = credited["action"].get(key) or credited["check"][key]
            entries.append({"key": [str(part) for part in key],
                            "declaration": declaration(
                                entry, source_root, properties, cache, item_id)})
        out_items[item_id] = {
            "checked": entries,
            "empty_reason": None if entries else EMPTY_NO_ACTION_OR_CHECK_CALL}
        out_detail[item_id] = {
            "action": [list(key) for key in sorted(credited["action"])],
            "check": [list(key) for key in sorted(credited["check"])],
            "context_calls": len(credited["context"]),
            "background_calls": len(credited["background"]),
            "constructors_excluded": [list(key) for key in sorted(excluded)],
            "unmapped": sorted(set().union(*detail["unmapped"].values())),
        }
        facts.append(_facts(item, row, bound, credited, checked, excluded,
                            detail))

    return {
        "schema": SCHEMA,
        "project": bound.project,
        "inputs": {
            "gold_rows_sha256": _sha256(gold),
            "index_sha256": _sha256(index),
            "boundary_sha256": _sha256(boundary),
            "items_sha256": _sha256(items),
            "source_root": source_root,
            "source_commit": source_commit(source_root),
        },
        "items": out_items,
        "detail": out_detail,
        "summary": summary(facts),
    }


def write(doc: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
        fh.write("\n")


# --------------------------------------------------------------------------
# summary (section 8)

def _facts(item: dict, row: dict, boundary: Boundary, credited: dict,
           checked: set, excluded: set, detail: dict) -> dict:
    """The per-item numbers the release summary aggregates.

    `disclosed_share` is the share of the gold run's OWN direct API set that
    the list hands over, and `covered_inside` the share of gold's covered
    production lines that lie inside a disclosed method's index span -- the
    leakage figure, and the one that says how much of the coverage row the
    list gives away.  Both are None where their denominator is empty, which
    is a state of the item, not a zero.
    """
    gold_api = set().union(*[set(credited[role]) for role in ROLES])
    spans: dict[str, list[tuple[int, int]]] = {}
    for key in checked:
        entry = credited["action"].get(key) or credited["check"][key]
        spans.setdefault(entry.rel, []).append(entry.span)
    covered = inside = 0
    for rel, lines in (row.get("coverage_lines") or {}).items():
        rel = _norm(rel)
        if boundary.classify(rel) != PRODUCTION:
            continue
        covered += len(lines)
        ranges = spans.get(rel, ())
        inside += sum(1 for line in lines
                      if any(low <= int(line) <= high for low, high in ranges))
    return {
        "item_id": item["item_id"],
        "size": len(checked),
        "n_oracle_steps": item["bench_meta"]["n_oracle_steps"],
        "action_empty": not credited["action"],
        "check_empty": not credited["check"],
        "constructor_in_check": any(
            key[-1].split(":", 1)[0] in CONSTRUCTORS for key in credited["check"]),
        "constructor_excluded": bool(excluded),
        "cause": None if checked else _cause(detail, excluded),
        "unmapped_by_role": {role: len(detail["unmapped"][role])
                             for role in ROLES},
        "disclosed_share": (len(checked & gold_api) / len(gold_api)
                            if gold_api else None),
        "undisclosed_api_empty": not (gold_api - checked),
        "covered_inside": (inside / covered) if covered else None,
    }


def _bucket(n_oracle_steps: int) -> str:
    return "1" if n_oracle_steps <= 1 else ("2-3" if n_oracle_steps <= 3 else "4+")


def _dist(sizes) -> dict:
    """Lower median, nearest-rank p90 and max -- all values that occur."""
    sizes = sorted(sizes)
    n = len(sizes)
    if not n:
        return {}
    return {"median": sizes[(n - 1) // 2],
            "p90": sizes[max(0, -(-9 * n // 10) - 1)],
            "max": sizes[-1]}


def _median(values) -> Optional[float]:
    values = sorted(v for v in values if v is not None)
    return statistics.median_low(values) if values else None


def summary(facts: list[dict]) -> dict:
    """The per-project figures section 8 requires of every derivation."""
    empties = [f for f in facts if not f["size"]]
    shares = [f["disclosed_share"] for f in facts]
    covered = [f["covered_inside"] for f in facts]
    buckets = {}
    for label in ("1", "2-3", "4+"):
        sizes = [f["size"] for f in facts if _bucket(f["n_oracle_steps"]) == label]
        buckets[label] = {"items": len(sizes), **_dist(sizes)}
    return {
        "n_items": len(facts),
        "size": _dist(f["size"] for f in facts),
        "size_by_oracle_steps": buckets,
        "empty": {
            "items": len(empties),
            "causes": {cause: sum(1 for f in empties if f["cause"] == cause)
                       for cause in (CAUSE_NO_CALL, CAUSE_ONLY_CONSTRUCTORS,
                                     CAUSE_ONLY_UNJOINED)}},
        "action_empty": sum(1 for f in facts if f["action_empty"]),
        "check_empty": sum(1 for f in facts if f["check_empty"]),
        "constructor_in_check_items": sum(1 for f in facts
                                          if f["constructor_in_check"]),
        "constructor_excluded_items": sum(1 for f in facts
                                          if f["constructor_excluded"]),
        "disclosed_share_of_gold_api": {
            "median": _median(shares),
            "items": sum(1 for s in shares if s is not None),
            "undefined": sum(1 for s in shares if s is None)},
        "items_with_empty_undisclosed_api": sum(
            1 for f in facts if f["undisclosed_api_empty"]),
        "unmapped_by_role": {
            role: sum(f["unmapped_by_role"][role] for f in facts)
            for role in ROLES},
        "coverage_inside_disclosed": {
            "median": _median(covered),
            "items": sum(1 for c in covered if c is not None),
            "undefined": sum(1 for c in covered if c is None)},
    }


# ------------------------------------------------------------------ selftest
def selftest() -> int:
    """Fixtures for the rules, and the one identity that keeps them honest.

    The union of the per-role credited sets IS `direct_methods`' set: this
    module re-walks the metric's join per role, and a divergence would
    silently disclose (or hide) methods the API rows score.
    """
    import tempfile

    from ..bench.metrics import direct_methods

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refused(name, fn, *needles):
        try:
            fn()
        except CheckedInterfacesRefused as exc:
            check(name, all(n in str(exc) for n in needles), str(exc))
            return
        check(name, False, "no refusal")

    source = {"src/shop/cart.py": [
        "class Cart:",                                        # 1
        "",
        "    def __init__(self, store):",                     # 3
        "        self.store = store",
        "",
        "    def add(self,",                                  # 6
        "            item: str,   # what to add",
        "            qty: int = 1) -> None:",
        "        self._n = qty",
        "",
        "    @property",                                      # 11
        "    def total(self) -> int:",
        "        return self._n",
        "",
        "    @total.setter",                                  # 15
        "    def total(self, value: int) -> None:",
        "        self._n = value",
        "",
        "    def _hidden(self):",                             # 19
        "        return 1",
        "",
        "    label: str = Attribute(  # pyright: ignore[reportAssignmentType]",  # 22
        '        "w:label", ST_String',
        "    )",
        ""]}
    index_doc = {"schema": "r2t.py_prod_index/2", "files": {
        "src/shop/cart.py": {"classes": [{
            "name": "shop.cart.Cart", "kind": "class",
            "methods": [
                {"name": "__init__", "decl": 3, "start": 4, "end": 4,
                 "public": True, "property": False},
                {"name": "add", "decl": 6, "start": 9, "end": 9,
                 "public": True, "property": False},
                {"name": "total", "decl": 11, "start": 13, "end": 13,
                 "public": True, "property": True},
                {"name": "total.setter", "decl": 15, "start": 17, "end": 17,
                 "public": True, "property": True},
                {"name": "_hidden", "decl": 19, "start": 20, "end": 20,
                 "public": False, "property": False}],
            "accessors": [{"declaring_line": 22, "attribute": "label",
                           "access_kind": "get", "public": True}]}]}}}
    boundary_doc = ("version: 1\nproject: shop\nrepo_root: src\n"
                    "removable:\n  - path: features/steps/\n    why: glue\n"
                    "retained: []\nremovable_config: []\nretained_contexts: []\n")

    def event(callee, line, step, caller="features/steps/shop.py",
              callee_file="src/shop/cart.py", binding=None):
        return {"callee": callee, "callee_file": callee_file,
                "callee_line": line, "caller_file": caller,
                "accessor_binding": binding, "step": step}

    def item(item_id, gherkin, background=None, bg_steps=0, oracle=1):
        return {"item_id": item_id, "project": "shop",
                "criterion": {"gherkin": gherkin},
                "requirement": {"background": background},
                "bench_meta": {"n_oracle_steps": oracle,
                               "live_background_step_count": bg_steps,
                               "live_step_count": gherkin.count("\n") - 1}}

    def row(item_id, events, n_steps, outcome="passed", version=18):
        return {"item_id": item_id, "harness_version": version,
                "outcome": outcome, "record_count": 1,
                "direct_calls_schema": "r2t.python_direct_calls/3",
                "direct_calls": events,
                "coverage_lines": {"src/shop/cart.py": [4, 9, 13, 20]},
                "per_step": [{"text": f"s{i}"} for i in range(n_steps)]}

    # One item per rule.  `two` writes its assertion as a Given, which the
    # oracle rule must still call a check.
    one = item("shop/f.feature:3",
               "  Scenario: set the total\n"
               "    Given a cart\n"
               "     When I set the total\n"
               "     Then the total is 2\n")
    two = item("shop/f.feature:9",
               "  Scenario: constructors\n"
               "    Given a cart\n"
               "     When I add an item\n"
               "      And the cart should hold it\n",
               background="  Background:\n    Given a store\n", bg_steps=1)
    three = item("shop/f.feature:20",
                 "  Scenario: nothing checked\n"
                 "    Given a cart\n"
                 "     Then it is fine\n")
    four = item("shop/f.feature:26",
                "  Scenario: a constructor in both roles\n"
                "     When I build a cart\n"
                "     Then a fresh cart is equal to it\n", oracle=2)
    five = item("shop/f.feature:32",
                "  Scenario: only an expected value\n"
                "    Given a cart\n"
                "     Then a fresh cart exists\n", oracle=4)
    six = item("shop/f.feature:38",
               "  Scenario: only a private call\n"
               "     When I poke the cart\n", oracle=0)
    items_rows = [one, two, three, four, five, six]
    gold_rows = [
        row(one["item_id"], [
            event("Cart.__init__", 3, 0),
            event("Cart.total.setter", 15, 1),
            event("Cart.total", 11, 2),
            event("Cart._hidden", 19, 2),
            event("Cart.label", 22, 2, binding={
                "declaring_file": "src/shop/cart.py", "declaring_line": 22,
                "owner": "shop.cart.Cart", "attribute": "label",
                "access_kind": "get"}),
            event("Cart.add", 6, None)], 3),
        row(two["item_id"], [
            event("Cart.__init__", 3, 3),
            event("Cart.add", 6, 2),
            event("Cart.add", 6, 0)], 4),
        row(three["item_id"], [
            event("Cart.add", 6, 0),
            event("Cart.total", 11, 1, caller="src/shop/other.py")], 2),
        row(four["item_id"], [
            event("Cart.__init__", 3, 0),
            event("Cart.__init__", 3, 1)], 2),
        row(five["item_id"], [event("Cart.__init__", 3, 1)], 2),
        row(six["item_id"], [event("Cart._hidden", 19, 0)], 1),
    ]

    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "src", "shop"))
        for rel, lines in source.items():
            with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
        paths = {}
        for name, payload in (("index.json", index_doc),):
            paths[name] = os.path.join(root, name)
            with open(paths[name], "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
        paths["boundary.yml"] = os.path.join(root, "boundary.yml")
        with open(paths["boundary.yml"], "w", encoding="utf-8") as fh:
            fh.write(boundary_doc)

        def write_jsonl(name, rows_):
            paths[name] = os.path.join(root, name)
            with open(paths[name], "w", encoding="utf-8") as fh:
                for obj in rows_:
                    fh.write(json.dumps(obj) + "\n")
            return paths[name]

        write_jsonl("items.jsonl", items_rows)
        write_jsonl("gold.jsonl", gold_rows)

        def run(gold="gold.jsonl", items_name="items.jsonl"):
            return derive(gold=paths[gold], index=paths["index.json"],
                          boundary=paths["boundary.yml"],
                          items=paths[items_name], source_root=root)

        doc = run()
        got = doc["items"][one["item_id"]]
        keys = [tuple(e["key"]) for e in got["checked"]]
        check("a When step's call is an action and a Then step's a check; the "
              "list is their union, sorted by key",
              keys == [("shop.cart.Cart", "label"),
                       ("shop.cart.Cart", "total"),
                       ("shop.cart.Cart", "total.setter")], str(keys))
        check("a non-public method the index knows is credited to nobody",
              ("shop.cart.Cart", "_hidden") not in keys)
        check("a call a hook made between steps carries no step and is not "
              "credited",
              ("shop.cart.Cart", "add") not in keys)
        check("a constructor called from a context step is not in the list "
              "either -- only action and check steps count",
              ("shop.cart.Cart", "__init__") not in keys)
        declarations = {tuple(e["key"]): e["declaration"] for e in got["checked"]}
        check("a multi-line Python signature joins to one line without its "
              "comment, and a property getter/setter says which it is",
              declarations[("shop.cart.Cart", "total")]
              == "(property getter) def total(self) -> int:"
              and declarations[("shop.cart.Cart", "total.setter")]
              == "(property setter) def total(self, value: int) -> None:",
              str(declarations))
        check("a generated accessor renders its class-body declaration, "
              "joined across lines and without the pyright comment",
              declarations[("shop.cart.Cart", "label")]
              == '(property getter) label: str = Attribute( "w:label", ST_String )',
              declarations[("shop.cart.Cart", "label")])
        detail = doc["detail"][one["item_id"]]
        check("the detail counts context and background calls without naming "
              "them, and names none as unmapped",
              detail["context_calls"] == 1 and detail["background_calls"] == 0
              and detail["unmapped"] == [], str(detail))

        two_got = doc["items"][two["item_id"]]
        two_detail = doc["detail"][two["item_id"]]
        check("a step whose text matches the oracle rule IS a check step "
              "whatever its keyword, and its constructor is excluded",
              [tuple(e["key"]) for e in two_got["checked"]]
              == [("shop.cart.Cart", "add")]
              and two_detail["check"] == [["shop.cart.Cart", "__init__"]]
              and two_detail["constructors_excluded"]
              == [["shop.cart.Cart", "__init__"]], str(two_detail))
        check("a Background step's call is never counted, whatever its keyword",
              two_detail["background_calls"] == 1
              and two_detail["action"] == [["shop.cart.Cart", "add"]],
              str(two_detail))

        four_detail = doc["detail"][four["item_id"]]
        check("a constructor an ACTION step also called stays in the list: "
              "the exclusion is about the role, not the name",
              [tuple(e["key"]) for e in doc["items"][four["item_id"]]["checked"]]
              == [("shop.cart.Cart", "__init__")]
              and four_detail["constructors_excluded"] == [],
              str(four_detail))

        three_got = doc["items"][three["item_id"]]
        check("an item whose action and check steps called nothing is an "
              "empty list with its reason, not an exclusion",
              three_got["checked"] == []
              and three_got["empty_reason"] == EMPTY_NO_ACTION_OR_CHECK_CALL,
              str(three_got))
        check("a non-empty list carries no reason",
              got["empty_reason"] is None)

        # THE identity: the per-role walk is the metric's own join.
        boundary_obj = load_boundary(paths["boundary.yml"])
        index_obj = load_prod_index(paths["index.json"])
        same = True
        for item_row, released in zip(gold_rows, items_rows):
            roles = step_roles(released)
            per_role = _item_detail(released, item_row, roles, boundary_obj,
                                    index_obj, False)["credited"]
            union = set().union(*[set(per_role[r]) for r in ROLES])
            same = same and union == direct_methods(item_row, boundary_obj,
                                                    index_obj)[0]
        check("the union of the per-role credited sets is exactly "
              "`direct_methods`' set on the same row", same)

        summary_got = doc["summary"]
        # The whole block at once: every figure section 8 asks for, over six
        # items built to hit each of them.  `only_unjoined_calls` is reachable
        # only through a non-public callee, because an action or check call
        # the index does not know refuses the derivation instead.
        expected = {
            "n_items": 6,
            "size": {"median": 0, "p90": 3, "max": 3},
            "size_by_oracle_steps": {
                "1": {"items": 4, "median": 0, "p90": 3, "max": 3},
                "2-3": {"items": 1, "median": 1, "p90": 1, "max": 1},
                "4+": {"items": 1, "median": 0, "p90": 0, "max": 0}},
            "empty": {"items": 3, "causes": {CAUSE_NO_CALL: 1,
                                             CAUSE_ONLY_CONSTRUCTORS: 1,
                                             CAUSE_ONLY_UNJOINED: 1}},
            "action_empty": 3,
            "check_empty": 2,
            "constructor_in_check_items": 3,
            "constructor_excluded_items": 2,
            "disclosed_share_of_gold_api": {"median": 0.5, "items": 5,
                                            "undefined": 1},
            "items_with_empty_undisclosed_api": 2,
            "unmapped_by_role": {role: 0 for role in ROLES},
            "coverage_inside_disclosed": {"median": 0.0, "items": 6,
                                          "undefined": 0},
        }
        check("the summary reports every section 8 figure: the size "
              "distribution and its oracle-step buckets, the empties by "
              "cause, both constructor counts, the disclosed share of gold's "
              "own API set, the items with nothing undisclosed left, the "
              "unmapped counts by role, and the coverage inside disclosed "
              "methods",
              summary_got == expected,
              json.dumps(summary_got, sort_keys=True))

        check("the inputs carry each argument's digest and the source root as "
              "given, with no commit for a tree that is not a checkout",
              doc["inputs"]["index_sha256"] == _sha256(paths["index.json"])
              and doc["inputs"]["source_root"] == root
              and doc["inputs"]["source_commit"] is None
              and doc["schema"] == SCHEMA and doc["project"] == "shop")

        first, second = os.path.join(root, "a.json"), os.path.join(root, "b.json")
        write(run(), first)
        write(run(), second)
        with open(first, "rb") as fa, open(second, "rb") as fb:
            check("re-derivation from the same inputs is byte-identical",
                  fa.read() == fb.read())

        # Refusals (section 9), each naming the item.
        stale = json.loads(json.dumps(gold_rows[0]))
        stale["harness_version"] = 17
        write_jsonl("stale.jsonl", [stale] + gold_rows[1:])
        refused("a row that predates the per-step field is refused by name",
                lambda: run(gold="stale.jsonl"), one["item_id"], "17")

        untagged = json.loads(json.dumps(gold_rows[0]))
        for ev in untagged["direct_calls"]:
            ev.pop("step")
        write_jsonl("untagged.jsonl", [untagged] + gold_rows[1:])
        refused("a row whose events carry no 'step' is refused by name",
                lambda: run(gold="untagged.jsonl"), one["item_id"], "'step'")

        failed = json.loads(json.dumps(gold_rows[0]))
        failed["outcome"] = "failed"
        write_jsonl("failed.jsonl", [failed] + gold_rows[1:])
        refused("a gold row that did not pass is refused by name",
                lambda: run(gold="failed.jsonl"), one["item_id"], "'failed'")

        short = json.loads(json.dumps(gold_rows[0]))
        short["per_step"] = short["per_step"][:2]
        write_jsonl("short.jsonl", [short] + gold_rows[1:])
        refused("a row whose step count is not Background plus scenario is "
                "refused by name",
                lambda: run(gold="short.jsonl"), one["item_id"], "2 steps")

        unknown = json.loads(json.dumps(gold_rows[0]))
        unknown["direct_calls"].append(event("Cart.ghost", 999, 2))
        write_jsonl("unknown.jsonl", [unknown] + gold_rows[1:])
        refused("an action or check call the index does not know is refused, "
                "naming the item and every unmapped callee",
                lambda: run(gold="unknown.jsonl"),
                one["item_id"], "Cart.ghost")

        # The same unmapped call from a CONTEXT step is counted, not refused.
        counted = json.loads(json.dumps(gold_rows[0]))
        counted["direct_calls"].append(event("Cart.ghost", 999, 0))
        write_jsonl("counted.jsonl", [counted] + gold_rows[1:])
        counted_doc = run(gold="counted.jsonl")
        check("an unmapped call from a context step is counted by role, not "
              "refused",
              counted_doc["detail"][one["item_id"]]["unmapped"] == ["Cart.ghost"]
              and counted_doc["summary"]["unmapped_by_role"]["context"] == 1,
              json.dumps(counted_doc["summary"]["unmapped_by_role"]))

        write_jsonl("missing.jsonl", gold_rows[1:])
        refused("a released item with no gold row is refused by name",
                lambda: run(gold="missing.jsonl"), one["item_id"])

        shifted = json.loads(json.dumps(items_rows))
        shifted[1]["requirement"]["background"] = None
        write_jsonl("shifted.jsonl", shifted)
        refused("a released item whose Background text does not reproduce its "
                "recorded step count is refused, because every step index "
                "would shift",
                lambda: run(items_name="shifted.jsonl"), two["item_id"])

        os.remove(os.path.join(root, "src", "shop", "cart.py"))
        refused("a declaration the pinned source root cannot supply is "
                "refused, not left blank",
                run, one["item_id"], "cart.py")

    # The four other stacks' declaration rules, on their own snippets.
    php = ["    #[Attribute]", "    public function total(", "        int $n",
           "    ): int {", "        return $n;", "    }"]
    check("PHP drops the attribute line and stops before the body brace, "
          "keeping the visibility keyword",
          _php_declaration(php, Method("C", "total", 1, 6, True), "a.php", "i")
          == "public function total( int $n ): int",
          _php_declaration(php, Method("C", "total", 1, 6, True), "a.php", "i"))
    rb = ["  def total(n) # count", "    n", "  end"]
    check("Ruby renders the def line without its comment",
          _ruby_declaration(rb, Method("C", "total", 1, 3, True, decl=1),
                            "a.rb", "i") == "def total(n)")
    go = ["func (c *Cart) Total(m map[string]int) (int, error) {", "\treturn 0, nil", "}"]
    check("Go renders the func signature up to the body brace",
          _go_declaration(go, Method("C", "Total", 1, 3, True), "a.go", "i")
          == "func (c *Cart) Total(m map[string]int) (int, error)")
    check("Java reconstructs the declaration from the JVM descriptor, with "
          "source type names and array suffixes",
          java_declaration(("com.a.Client",
                            "executeCall:([Ljava/lang/String;ILjava/util/Map$Entry;)"
                            "Lcom/a/Response;"))
          == "com.a.Response executeCall(java.lang.String[], int, "
             "java.util.Map.Entry)",
          java_declaration(("com.a.Client",
                            "executeCall:([Ljava/lang/String;ILjava/util/Map$Entry;)"
                            "Lcom/a/Response;")))
    check("a Java constructor keeps its recorded name",
          java_declaration(("com.a.Client", "<init>:(I)V"))
          == "void <init>(int)")
    refused("a descriptor that is not a JVM method descriptor is refused",
            lambda: java_declaration(("com.a.Client", "x:(Q)V")), "descriptor")

    print("ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
