"""Read and validate persisted agent trajectory evidence.

This module owns the non-network part of the former post-run egress pass:
trajectory discovery, event parsing, row-to-disk count reconciliation, native
manifest verification, and credential redaction utilities.  It does not infer
which hosts an agent contacted and it does not decide whether a run may be
published.

The validation boundary is deliberately modest.  It catches evidence that is
absent, unreadable, shorter than the row says, or inconsistent with an agent's
preserved native manifest.  It assumes a cooperating operator and does not try
to prove that a larger directory is an adversarially faithful superset of the
one originally scored.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Iterable, Optional


_REDACTED = "[REDACTED]"
_MIN_SECRET_LEN = 8
SNIPPET_MAX = 200

_SECRET_PATTERNS = (
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"), _REDACTED),
    (re.compile(r"(?i)\b(authorization|api[_\-]?key|apikey|access[_\-]?token|"
                r"auth[_\-]?token|token|secret|password|passwd)\b"
                r"(\s*[:=]\s*)[\"']?[^\s\"',;&)]+"),
     r"\1\2" + _REDACTED),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"),
     "Bearer " + _REDACTED),
    (re.compile(r"(?i)([?&](?:api[_\-]?key|access[_\-]?token|token|key|sig|"
                r"signature)=)[^&\s\"']+"),
     r"\1" + _REDACTED),
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"),
     "://" + _REDACTED + "@"),
)

_KNOWN_SIDECARS = ("base_state.json", "TASKS.json")
_NATIVE_MANIFEST = "native_manifest.json"


def redact(text: str, secrets: Iterable = ()) -> str:
    """Return text with known and conventional credential shapes scrubbed.

    Literal secrets are replaced first, longest first.  Short strings are not
    treated as secrets because replacing ordinary substrings would corrupt the
    evidence being preserved.
    """
    if not isinstance(text, str):
        return ""
    for needle in sorted({str(value) for value in secrets
                          if value and len(str(value)) >= _MIN_SECRET_LEN},
                         key=len, reverse=True):
        text = text.replace(needle, _REDACTED)
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _native_contract(system) -> Optional[tuple]:
    """Return the native-manifest contract owed by an agent system."""
    if not system:
        return None
    try:
        from ..agents.registry import REGISTRY
    except ImportError:
        # `egress._native_contract`'s rule: a fixture owes no contract, and
        # an agent arm this checkout does not ship is refused by name.
        from .fixtures import FIXTURES
        if system in FIXTURES:
            return None
        raise SystemExit(
            f"REFUSED: the run names agent system {system!r}, whose native "
            f"trajectory contract is agent-owned; this checkout does not "
            f"ship the agent component, so its trajectories cannot be "
            f"validated here.")
    spec = REGISTRY.get(system)
    if spec is None or not getattr(spec, "native_manifest", None):
        return None
    return spec.native_manifest, spec.qualified


def _event_files(directory: str) -> list:
    """Every persisted ``event-*.json`` below a directory, stably ordered."""
    found = []
    if not os.path.isdir(directory):
        return found
    for dirpath, dirnames, names in os.walk(directory):
        dirnames[:] = sorted(dirnames)
        for name in sorted(names):
            if name.startswith("event-") and name.endswith(".json"):
                found.append(os.path.join(dirpath, name))
    return sorted(found)


def _conversation_events(attempt_dir: str, conversation: str) -> int:
    """Count events under one safely named conversation directory."""
    if (not conversation or conversation in (".", "..")
            or "/" in conversation or os.sep in conversation
            or (os.altsep and os.altsep in conversation)):
        return 0
    return len(_event_files(os.path.join(attempt_dir, conversation)))


def _unrecognized_files(directory: str) -> list:
    """Record-like files not handled by the normalized event reader.

    These names remain useful evidence for a human or agent-specific validator,
    but their mere presence is no longer a publication or smoke-gate failure.
    """
    out = []
    if not os.path.isdir(directory):
        return out
    for dirpath, dirnames, names in os.walk(directory):
        dirnames[:] = sorted(dirnames)
        for name in sorted(names):
            if not (name.endswith(".json") or name.endswith(".jsonl")):
                continue
            if name.startswith("event-") and name.endswith(".json"):
                continue
            if name in _KNOWN_SIDECARS:
                continue
            out.append(os.path.relpath(os.path.join(dirpath, name), directory))
    return out


def _recount_events(directory: str) -> int:
    """Count ``*.json`` directly inside directories named ``events``."""
    if not os.path.isdir(directory):
        return 0
    if os.path.basename(os.path.normpath(directory)) == "events":
        roots = [directory]
    else:
        roots = []
        for dirpath, dirnames, _names in os.walk(directory):
            dirnames[:] = sorted(dirnames)
            if os.path.basename(dirpath) == "events":
                roots.append(dirpath)
    total = 0
    for events in roots:
        try:
            names = os.listdir(events)
        except OSError:
            continue
        total += sum(1 for name in names if name.endswith(".json"))
    return total


def _observation_text(observation) -> str:
    """Flatten the text-bearing fields of a normalized observation."""
    if not isinstance(observation, dict):
        return ""
    parts = []
    content = observation.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
            elif isinstance(block, str):
                parts.append(block)
    elif isinstance(content, str):
        parts.append(content)
    for key in ("output", "stdout", "stderr", "text", "command"):
        if isinstance(observation.get(key), str):
            parts.append(observation[key])
    return "\n".join(parts)


def _snippet(text: str, start: int, end: int) -> str:
    """A whitespace-folded window no longer than ``SNIPPET_MAX``."""
    span = max(end - start, 0)
    pad = max((SNIPPET_MAX - span) // 2, 0)
    lo = max(start - pad, 0)
    hi = min(max(end, start) + pad, len(text))
    head = "..." if lo > 0 else ""
    tail = "..." if hi < len(text) else ""
    window = " ".join(text[lo:hi].split())
    budget = SNIPPET_MAX - len(head) - len(tail)
    return head + window[:max(budget, 0)] + tail


def validate_trajectory(directory: str) -> dict:
    """Read one attempt and verify its normalized and native evidence.

    Parsing errors are returned, never skipped.  Native artifacts declared by
    a valid manifest are removed from the unrecognized inventory after their
    bytes and counts have been verified by ``r2t.agents.scanners``.
    """
    directory = os.path.abspath(directory)
    report = {
        "dir": directory,
        "present": os.path.isdir(directory),
        "n_events": 0,
        "n_parsed": 0,
        "parsed": False,
        "recount": _recount_events(directory),
        "unrecognized": _unrecognized_files(directory),
        "conversations": [],
        "errors": [],
    }
    paths = _event_files(directory)
    report["n_events"] = len(paths)
    events = []
    conversations = set()
    for path in paths:
        relative = os.path.relpath(path, directory)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            report["errors"].append(
                {"event": relative,
                 "error": f"{type(exc).__name__}: {exc}"})
            continue
        if not isinstance(data, dict):
            report["errors"].append(
                {"event": relative, "error": "event is not an object"})
            continue
        parts = relative.split(os.sep)
        conversation = parts[0] if len(parts) > 2 else ""
        if conversation:
            conversations.add(conversation)
        events.append(data)
    report["conversations"] = sorted(conversations)
    report["n_parsed"] = len(events)
    report["parsed"] = bool(events) and not report["errors"]

    if os.path.isfile(os.path.join(directory, _NATIVE_MANIFEST)):
        from ..agents import scanners
        native = scanners.verify(directory, events)
        if native is not None:
            declared = set(native.get("declared") or ())
            report["unrecognized"] = [
                name for name in report["unrecognized"]
                if name not in declared
            ]
            report["native"] = {
                "agent_system": native.get("agent_system"),
                "counts": native.get("counts"),
                "declared": sorted(declared),
                "termination": native.get("termination"),
                "problems": list(native.get("problems") or ()),
            }
    return report


def item_key(item_id: str) -> str:
    """The stable trajectory-directory key for an item."""
    return hashlib.sha1(item_id.encode()).hexdigest()[:16]


def _attempt_dirs(parent: str, key: str) -> list:
    """Return ``<key>`` and ``<key>.rN`` directories in attempt order."""
    found = []
    if not os.path.isdir(parent):
        return found
    base = os.path.join(parent, key)
    if os.path.isdir(base):
        found.append((1, base))
    try:
        names = os.listdir(parent)
    except OSError:
        return [path for _, path in sorted(found)]
    for name in names:
        match = re.fullmatch(re.escape(key) + r"\.r(\d+)", name)
        if match and os.path.isdir(os.path.join(parent, name)):
            found.append((int(match.group(1)), os.path.join(parent, name)))
    return [path for _, path in sorted(found)]


def trajectory_dirs(item_id: str, trajectory_root: str,
                    condition: Optional[str] = None,
                    recorded: Optional[str] = None) -> list:
    """Discover conventional attempts plus the directory named by the row."""
    parents = [trajectory_root]
    if condition and os.path.isdir(os.path.join(trajectory_root, condition)):
        parents.append(os.path.join(trajectory_root, condition))
    elif not condition and os.path.isdir(trajectory_root):
        for name in sorted(os.listdir(trajectory_root)):
            path = os.path.join(trajectory_root, name)
            if os.path.isdir(path):
                parents.append(path)
    key = item_key(item_id)
    out, seen = [], set()
    for parent in parents:
        for path in _attempt_dirs(parent, key):
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                out.append(path)
    if recorded and os.path.isdir(recorded):
        recorded_key = os.path.basename(recorded).split(".r")[0]
        for path in _attempt_dirs(os.path.dirname(recorded), recorded_key):
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                out.append(path)
    return out


def _rows(run_jsonl: str) -> list:
    """Return ``(line_number, raw_line, parsed_or_none)`` for a run file."""
    out = []
    with open(run_jsonl, "r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                out.append((number, line, json.loads(line)))
            except ValueError:
                out.append((number, line, None))
    return out


def validate_run(run_jsonl: str, trajectory_root: str,
                 condition: Optional[str] = None) -> dict:
    """Return evidence-validation results keyed by ``item_id``.

    A result is intact when event files can be read, the independent on-disk
    recount agrees, the disk has at least the number of events recorded on the
    row, and any required native manifest reconciles.  Extra events and
    unrecognized side files are reported but do not make the result fail.
    """
    trajectory_root = os.path.abspath(trajectory_root)
    results = {}
    cache = {}
    for number, _line, row in _rows(run_jsonl):
        if not isinstance(row, dict) or not row.get("item_id"):
            continue
        item_id = row["item_id"]
        summary = ((row.get("metadata") or {}).get("trajectory") or {}) \
            if isinstance(row.get("metadata"), dict) else {}
        summary = summary if isinstance(summary, dict) else {}
        recorded = summary.get("dir")
        row_condition = condition or row.get("condition")
        entry = results.setdefault(item_id, {
            "item_id": item_id,
            "condition": row_condition,
            "rows": 0,
            "lines": [],
            "attempts": [],
            "recorded": [],
            "no_trajectory": True,
            "unrecognized": [],
            "unreadable": [],
            "n_events": 0,
            "trajectory_intact": False,
            "trajectory_problems": [],
            "native_problems": [],
            "intact": False,
            "problems": [],
        })
        entry["rows"] += 1
        entry["lines"].append(number)
        if recorded and isinstance(summary.get("n_events"), int):
            entry["recorded"].append({
                "dir": recorded,
                "real": os.path.realpath(recorded),
                "n_events": summary["n_events"],
                "line": number,
            })
        for directory in trajectory_dirs(item_id, trajectory_root,
                                         row_condition, recorded):
            real = os.path.realpath(directory)
            if any(attempt["real"] == real for attempt in entry["attempts"]):
                continue
            if real not in cache:
                cache[real] = validate_trajectory(directory)
            report = cache[real]
            attempt = {
                "dir": directory,
                "real": real,
                "n_events": report["n_events"],
                "n_parsed": report["n_parsed"],
                "parsed": report["parsed"],
                "recount": report["recount"],
                "conversations": report["conversations"],
                "unrecognized": list(report["unrecognized"]),
                "errors": list(report["errors"]),
            }
            row_system = row.get("agent_system") or row.get("adapter")
            if "native" in report:
                native = dict(report["native"])
                native["problems"] = list(native.get("problems") or ())
                claimed = native.get("agent_system")
                if row_system and claimed and claimed != row_system:
                    native["problems"].append(
                        f"the native manifest claims agent system {claimed!r} "
                        f"and the run row claims {row_system!r} -- the two "
                        "records disagree about whose evidence this is")
                attempt["native"] = native
            else:
                required = _native_contract(row_system)
                if required is not None:
                    schema, qualified = required
                    attempt["native"] = {
                        "agent_system": None,
                        "counts": {},
                        "declared": [],
                        "termination": None,
                        "missing": True,
                        "problems": [
                            f"the run row claims {row_system!r}, and "
                            f"{qualified}'s contract requires every attempt "
                            f"to carry a native manifest ({schema}); "
                            f"{_NATIVE_MANIFEST} is not there, so the "
                            "framework's own record cannot be reconciled "
                            "against the normalized events"
                        ],
                    }
            entry["attempts"].append(attempt)
            if report["n_events"] > 0:
                entry["no_trajectory"] = False
    for entry in results.values():
        for attempt in entry["attempts"]:
            entry["n_events"] += attempt["n_events"]
            for error in attempt["errors"]:
                entry["unreadable"].append(dict(error, dir=attempt["dir"]))
            for name in attempt["unrecognized"]:
                entry["unrecognized"].append(os.path.join(attempt["dir"], name))
        _reconcile(entry)
    return results


def _reconcile(entry: dict) -> None:
    """Set ``intact`` and ``problems`` from plain evidence conservation.

    This is not an adversarial identity check.  In particular it does not use
    conversation inventories to prove a larger attempt is a true superset and
    it does not reject an explicit absent/present mismatch.  Those defenses
    belonged to the retired publication gate.
    """
    trajectory_problems = []
    native_problems = []
    if entry["no_trajectory"]:
        trajectory_problems.append(
            "no attempt directory on disk holds an event file")
    for attempt in entry["attempts"]:
        where = attempt["dir"]
        if attempt["n_events"] == 0:
            trajectory_problems.append(
                f"{where}: present but holds no event file")
        if attempt["errors"]:
            trajectory_problems.append(
                f"{where}: {len(attempt['errors'])} event file(s) could not "
                "be read")
        if attempt["recount"] != attempt["n_events"]:
            trajectory_problems.append(
                f"{where}: the adapter's rule counts {attempt['recount']} "
                f"events, this validation read {attempt['n_events']}")
        for problem in (attempt.get("native") or {}).get("problems") or ():
            native_problems.append(f"{where}: {problem}")
    by_real = {attempt["real"]: attempt for attempt in entry["attempts"]}
    for record in entry["recorded"]:
        attempt = by_real.get(record["real"])
        if attempt is None:
            trajectory_problems.append(
                f"row line {record['line']} was scored against "
                f"{record['dir']} ({record['n_events']} events) and this "
                "validation did not read that directory")
        elif attempt["n_events"] < record["n_events"]:
            trajectory_problems.append(
                f"{record['dir']}: the run row recorded "
                f"{record['n_events']} events, {attempt['n_events']} are on "
                "disk -- the scored evidence is incomplete")
    entry["trajectory_problems"] = trajectory_problems
    entry["trajectory_intact"] = not trajectory_problems
    entry["native_problems"] = native_problems
    entry["problems"] = trajectory_problems + native_problems
    entry["intact"] = not entry["problems"]


def selftest() -> int:
    """Exercise parsing, discovery, redaction, and plain reconciliation."""
    import shutil
    import tempfile

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        ok = ok and bool(condition)
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))

    secret = "sk-validation-fixture-0123456789"
    cleaned = redact(f"Authorization: Bearer {secret}", [secret])
    check("redact removes a known key without echoing it",
          secret not in cleaned and _REDACTED in cleaned)
    flattened = _observation_text(
        {"content": [{"text": "one"}, "two"], "stderr": "three"})
    check("observation text preserves all supported text blocks",
          flattened == "one\ntwo\nthree", repr(flattened))
    check("snippets respect their declared bound",
          len(_snippet("x" * 500, 250, 251)) <= SNIPPET_MAX)

    root = tempfile.mkdtemp(prefix="r2t-trajectory-validation-")
    try:
        item = "project/features/example.feature:1"
        attempt = os.path.join(root, "c3", item_key(item))
        events = os.path.join(attempt, "conv", "events")
        os.makedirs(events)
        for index in (1, 2):
            with open(os.path.join(events, f"event-{index:05d}-x.json"),
                      "w", encoding="utf-8") as handle:
                json.dump({"id": str(index), "kind": "MessageEvent"}, handle)
        with open(os.path.join(attempt, "notes.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write('{"note": "reported, not gated"}\n')

        report = validate_trajectory(attempt)
        check("trajectory events parse and recount exactly",
              report["parsed"] and report["n_parsed"] == 2
              and report["recount"] == report["n_events"] == 2,
              json.dumps(report, default=str))
        check("unrecognized records remain visible",
              report["unrecognized"] == ["notes.jsonl"],
              repr(report["unrecognized"]))
        check("conversation event discovery rejects path-like names",
              _conversation_events(attempt, "conv") == 2
              and _conversation_events(attempt, "../conv") == 0)

        # The rows below name a system so `validate_run` resolves a native
        # contract for it; which system is not what they are about.  Without
        # the agent component there is no arm to name and naming one is
        # refused, so they run on a fixture and the refusal itself is the
        # leg that runs instead.
        try:
            from ..agents.registry import REGISTRY         # noqa: F401
        except ImportError:
            row_adapter = "gold"
            refusal = ""
            try:
                _native_contract("openhands")
            except SystemExit as exc:
                refusal = str(exc)
            check("an agent arm this checkout does not ship is refused by "
                  "name, and a fixture owes no contract",
                  "'openhands'" in refusal and "agent component" in refusal
                  and _native_contract(row_adapter) is None, refusal)
        else:
            row_adapter = "openhands"

        run = os.path.join(root, "run.jsonl")
        row = {"item_id": item, "condition": "c3", "adapter": row_adapter,
               "metadata": {"trajectory": {
                   "dir": attempt, "present": True, "n_events": 2,
                   "conversations": ["conv"]}}}
        with open(run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
        result = validate_run(run, root)[item]
        check("a coherent row is intact despite an unrelated side record",
              result["intact"] and result["unrecognized"],
              json.dumps(result["problems"]))

        os.remove(os.path.join(events, "event-00002-x.json"))
        result = validate_run(run, root)[item]
        check("a row whose recorded event count shrank is not intact",
              not result["intact"]
              and any("incomplete" in problem for problem in result["problems"]),
              json.dumps(result["problems"]))

        malformed_event = os.path.join(events, "event-00002-x.json")
        with open(malformed_event, "w", encoding="utf-8") as handle:
            handle.write("{not-json")
        result = validate_run(run, root)[item]
        check("an unreadable event makes plain trajectory evidence not intact",
              not result["trajectory_intact"] and result["unreadable"],
              json.dumps(result["trajectory_problems"]))

        with open(malformed_event, "w", encoding="utf-8") as handle:
            json.dump({"id": "2", "kind": "MessageEvent"}, handle)
        recount_only = os.path.join(events, "side-record.json")
        with open(recount_only, "w", encoding="utf-8") as handle:
            json.dump({"side": True}, handle)
        result = validate_run(run, root)[item]
        check("an on-disk recount mismatch makes the trajectory not intact",
              not result["trajectory_intact"]
              and any("adapter's rule counts" in problem
                      for problem in result["trajectory_problems"]),
              json.dumps(result["trajectory_problems"]))
        os.remove(recount_only)

        for index in (2, 3):
            with open(os.path.join(events, f"event-{index:05d}-x.json"),
                      "w", encoding="utf-8") as handle:
                json.dump({"id": str(index), "kind": "MessageEvent"}, handle)
        result = validate_run(run, root)[item]
        check("extra events do not invoke the retired superset defense",
              result["intact"] and result["n_events"] == 3,
              json.dumps(result["problems"]))

        empty_item = "project/features/empty.feature:2"
        empty_attempt = os.path.join(root, "c3", item_key(empty_item))
        os.makedirs(empty_attempt)
        empty_run = os.path.join(root, "empty.jsonl")
        with open(empty_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "item_id": empty_item,
                "condition": "c3",
                "adapter": row_adapter,
                "metadata": {"trajectory": {
                    "dir": empty_attempt, "present": True, "n_events": 0,
                    "conversations": [],
                }},
            }) + "\n")
        empty_result = validate_run(empty_run, root)[empty_item]
        check("an empty recorded attempt makes trajectory evidence not intact",
              not empty_result["trajectory_intact"]
              and empty_result["no_trajectory"],
              json.dumps(empty_result["trajectory_problems"]))

        retry = attempt + ".r2"
        os.makedirs(retry)
        check("attempt discovery orders the base before retries",
              trajectory_dirs(item, root, "c3") == [attempt, retry],
              repr(trajectory_dirs(item, root, "c3")))
    finally:
        shutil.rmtree(root, ignore_errors=True)

    print("\n" + ("ALL PASS (trajectory_validation)" if ok
                  else "FAILURES (trajectory_validation)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
