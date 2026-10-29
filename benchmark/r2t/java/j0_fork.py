"""Source-only validator for one J0 fork-safe Cucumber JSONL stream.

The authority is the closed ``r2t.java-j0-cucumber-fork/1`` grammar in
``benchmark/J0_JVM_TIMING_PROTOCOL.md``.  This module only authenticates raw
fork bytes and returns their header, events, footer, and file SHA-256.  It does
not project a canonical union, fold statuses into ``r2t.record/1``, publish
evidence, or execute Java, Maven, Docker, or a network client.
"""
from __future__ import annotations

import copy
import sys
from typing import Any, Callable

from . import j0


SCHEMA = "r2t.java-j0-cucumber-fork/1"
ADAPTER_BY_PROJECT = {
    "algorand-sdk": "cucumber-6.6.0/r2t-1",
    "epubcheck": "cucumber-7.8.0/r2t-1",
}
STATUSES = {
    "unknown", "skipped", "pending", "undefined",
    "ambiguous", "failed", "passed", "unused",
}
HOOK_TYPES = {"before", "after", "before_step", "after_step"}

_HEADER_KEYS = {
    "adapter", "invocation_id", "invocation_manifest_sha256", "project",
    "projection_manifest_sha256", "recorder_class_sha256", "schema",
    "surefire_context_id", "type",
}
_CASE_KEYS = {"case_column", "case_line", "name", "pickle_steps", "uri"}
_PICKLE_STEP_KEYS = {"column", "keyword", "line", "ordinal", "text"}
_EVENT_KEYS = {
    "case_started": {"case", "case_ref", "event", "seq", "type"},
    "step_finished": {
        "case_ref", "code_location", "error", "event",
        "execution_ordinal", "hook_type", "pickle_step_ordinal", "seq",
        "status", "type",
    },
    "case_finished": {
        "case_ref", "error", "event", "seq", "status", "type",
    },
}
_FOOTER_KEYS = {
    "case_finished_count", "case_started_count", "event_count",
    "events_sha256", "header_sha256", "schema", "step_finished_count",
    "type",
}


class J0ForkError(j0.J0Error):
    """A controlled refusal of raw fork evidence."""


def _closed(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise J0ForkError(f"{where}: expected object")
    actual = set(value)
    if actual != keys:
        raise J0ForkError(
            f"{where}: closed schema mismatch; "
            f"missing={sorted(keys - actual)!r}, unknown={sorted(actual - keys)!r}")
    return value


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise J0ForkError(f"{where}: expected string")
    return value


def _integer(value: Any, where: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise J0ForkError(f"{where}: expected integer >= {minimum}")
    return value


def _hex64(value: Any, where: str) -> str:
    if not isinstance(value, str) or j0.HEX64.fullmatch(value) is None:
        raise J0ForkError(f"{where}: expected lowercase 64-hex")
    return value


def _validate_header(value: Any) -> dict[str, Any]:
    header = _closed(value, _HEADER_KEYS, "header")
    if header["type"] != "header" or header["schema"] != SCHEMA:
        raise J0ForkError("header: wrong type or schema")
    project = header["project"]
    if not isinstance(project, str) or project not in ADAPTER_BY_PROJECT:
        raise J0ForkError("header.project: unknown project")
    if header["adapter"] != ADAPTER_BY_PROJECT[project]:
        raise J0ForkError("header.adapter: wrong adapter for project")
    for key in (
        "invocation_id", "invocation_manifest_sha256",
        "projection_manifest_sha256", "recorder_class_sha256",
    ):
        _hex64(header[key], f"header.{key}")
    context = header["surefire_context_id"]
    if context is not None:
        _hex64(context, "header.surefire_context_id")
    return header


def _validate_pickle_steps(value: Any, where: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise J0ForkError(f"{where}: expected array")
    steps: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        step = _closed(item, _PICKLE_STEP_KEYS, f"{where}[{index}]")
        _integer(step["line"], f"{where}[{index}].line", minimum=1)
        _integer(step["column"], f"{where}[{index}].column", minimum=1)
        if _integer(step["ordinal"], f"{where}[{index}].ordinal") != index:
            raise J0ForkError(f"{where}[{index}].ordinal: not its list index")
        _string(step["keyword"], f"{where}[{index}].keyword")
        _string(step["text"], f"{where}[{index}].text")
        steps.append(step)
    return steps


def _validate_case(value: Any, where: str) -> dict[str, Any]:
    case = _closed(value, _CASE_KEYS, where)
    _integer(case["case_line"], f"{where}.case_line", minimum=1)
    _integer(case["case_column"], f"{where}.case_column", minimum=1)
    _string(case["name"], f"{where}.name")
    j0.validate_posix_path(case["uri"], where=f"{where}.uri")
    _validate_pickle_steps(case["pickle_steps"], f"{where}.pickle_steps")
    return case


def _case_ref(case: dict[str, Any]) -> str:
    return j0._sha256(
        b"r2t-j0-raw-case/1\0"
        + j0.canonical_json_bytes(case, terminal_lf=False))


def _validate_error(value: Any, where: str) -> None:
    if value is None:
        return
    error = _closed(value, {"class", "message"}, where)
    _string(error["class"], f"{where}.class")
    if error["message"] is not None:
        _string(error["message"], f"{where}.message")


def _validate_location(value: Any, where: str) -> None:
    location = _closed(value, {"line", "path"}, where)
    _integer(location["line"], f"{where}.line", minimum=1)
    j0.validate_posix_path(location["path"], where=f"{where}.path")


def _validate_status(value: Any, where: str) -> None:
    if not isinstance(value, str) or value not in STATUSES:
        raise J0ForkError(f"{where}: unknown Cucumber status")


def _canonical_lines(raw: bytes) -> tuple[list[Any], list[bytes]]:
    if not isinstance(raw, bytes):
        raise J0ForkError("fork: expected bytes")
    if not raw.endswith(b"\n"):
        raise J0ForkError("fork: missing terminal LF")
    bodies = raw.split(b"\n")[:-1]
    if len(bodies) < 2 or any(not body for body in bodies):
        raise J0ForkError("fork: expected nonempty header and footer lines")
    lines = [body + b"\n" for body in bodies]
    values = [
        j0.load_canonical_json_bytes(line, where=f"fork line {index + 1}")
        for index, line in enumerate(lines)
    ]
    return values, lines


def validate_fork_bytes(raw: bytes) -> dict[str, Any]:
    """Validate and return the raw facts from one complete fork stream."""
    values, lines = _canonical_lines(raw)
    header = _validate_header(values[0])
    footer = _closed(values[-1], _FOOTER_KEYS, "footer")
    if footer["type"] != "footer" or footer["schema"] != SCHEMA:
        raise J0ForkError("footer: wrong type or schema")

    events: list[dict[str, Any]] = []
    active: dict[str, dict[str, Any]] = {}
    finished: set[str] = set()
    next_execution_ordinal: dict[str, int] = {}
    observed_counts = {name: 0 for name in _EVENT_KEYS}

    for index, value in enumerate(values[1:-1]):
        where = f"events[{index}]"
        if not isinstance(value, dict):
            raise J0ForkError(f"{where}: expected object")
        event_name = value.get("event")
        if not isinstance(event_name, str) or event_name not in _EVENT_KEYS:
            raise J0ForkError(f"{where}.event: unknown event variant")
        event = _closed(value, _EVENT_KEYS[event_name], where)
        if event["type"] != "event":
            raise J0ForkError(f"{where}.type: expected event")
        if _integer(event["seq"], f"{where}.seq") != index:
            raise J0ForkError(f"{where}.seq: expected contiguous value {index}")
        case_ref = _hex64(event["case_ref"], f"{where}.case_ref")

        if event_name == "case_started":
            case = _validate_case(event["case"], f"{where}.case")
            if case_ref != _case_ref(case):
                raise J0ForkError(f"{where}.case_ref: wrong raw-case domain hash")
            if case_ref in active or case_ref in finished:
                raise J0ForkError(f"{where}: duplicate case start")
            active[case_ref] = case
            next_execution_ordinal[case_ref] = 0
        elif event_name == "step_finished":
            if case_ref not in active:
                raise J0ForkError(f"{where}: step outside active case lifecycle")
            execution = _integer(
                event["execution_ordinal"], f"{where}.execution_ordinal")
            if execution != next_execution_ordinal[case_ref]:
                raise J0ForkError(
                    f"{where}.execution_ordinal: not next TestCase position")
            next_execution_ordinal[case_ref] += 1

            hook = event["hook_type"]
            pickle_ordinal = event["pickle_step_ordinal"]
            if (hook is None) == (pickle_ordinal is None):
                raise J0ForkError(
                    f"{where}: exactly one hook/pickle identity is required")
            if hook is not None:
                if not isinstance(hook, str) or hook not in HOOK_TYPES:
                    raise J0ForkError(f"{where}.hook_type: unknown hook type")
            else:
                ordinal = _integer(
                    pickle_ordinal, f"{where}.pickle_step_ordinal")
                if ordinal >= len(active[case_ref]["pickle_steps"]):
                    raise J0ForkError(
                        f"{where}.pickle_step_ordinal: outside case steps")

            _validate_status(event["status"], f"{where}.status")
            _validate_error(event["error"], f"{where}.error")
            undefined_pickle = hook is None and event["status"] == "undefined"
            if undefined_pickle:
                if event["code_location"] is not None:
                    raise J0ForkError(
                        f"{where}.code_location: undefined pickle requires null")
            else:
                if event["code_location"] is None:
                    raise J0ForkError(
                        f"{where}.code_location: location is required")
                _validate_location(
                    event["code_location"], f"{where}.code_location")
        else:
            if case_ref not in active:
                raise J0ForkError(f"{where}: finish outside active case lifecycle")
            _validate_status(event["status"], f"{where}.status")
            _validate_error(event["error"], f"{where}.error")
            del active[case_ref]
            del next_execution_ordinal[case_ref]
            finished.add(case_ref)

        observed_counts[event_name] += 1
        events.append(event)

    if active:
        raise J0ForkError("fork: missing case finish")

    count_fields = {
        "case_started": "case_started_count",
        "step_finished": "step_finished_count",
        "case_finished": "case_finished_count",
    }
    for event_name, field in count_fields.items():
        claimed = _integer(footer[field], f"footer.{field}")
        if claimed != observed_counts[event_name]:
            raise J0ForkError(f"footer.{field}: does not match events")
    event_count = _integer(footer["event_count"], "footer.event_count")
    claimed_sum = sum(footer[field] for field in count_fields.values())
    if event_count != len(events) or event_count != claimed_sum:
        raise J0ForkError("footer.event_count: count sum does not match events")

    header_sha256 = _hex64(footer["header_sha256"], "footer.header_sha256")
    events_sha256 = _hex64(footer["events_sha256"], "footer.events_sha256")
    if header_sha256 != j0._sha256(lines[0]):
        raise J0ForkError("footer.header_sha256: digest mismatch")
    if events_sha256 != j0._sha256(b"".join(lines[1:-1])):
        raise J0ForkError("footer.events_sha256: digest mismatch")

    return {
        "events": events,
        "footer": footer,
        "fork_sha256": j0._sha256(raw),
        "header": header,
    }


def selftest() -> int:
    """Source-only mutation probes for the closed fork grammar."""
    ok = True

    def check(name: str, condition: Any) -> None:
        nonlocal ok
        passed = bool(condition)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed

    def refused(callable_: Callable[[], Any]) -> bool:
        try:
            callable_()
        except j0.J0Error:
            return True
        return False

    def digest(label: str) -> str:
        return j0._sha256(label.encode("ascii"))

    def literal_case_ref(value: dict[str, Any]) -> str:
        return j0._sha256(
            b"r2t-j0-raw-case/1\0"
            + j0.canonical_json_bytes(value, terminal_lf=False))

    def resequence(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for index, event in enumerate(events):
            event["seq"] = index
        return events

    def rebind_case(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        case_ref = literal_case_ref(events[0]["case"])
        for event in events:
            event["case_ref"] = case_ref
        return events

    def seal_lines(
        header: dict[str, Any],
        event_lines: list[bytes],
        counts: dict[str, int],
        footer_changes: dict[str, Any] | None = None,
    ) -> bytes:
        header_line = j0.canonical_json_bytes(header)
        footer = {
            "case_finished_count": counts["case_finished"],
            "case_started_count": counts["case_started"],
            "event_count": sum(counts.values()),
            "events_sha256": j0._sha256(b"".join(event_lines)),
            "header_sha256": j0._sha256(header_line),
            "schema": SCHEMA,
            "step_finished_count": counts["step_finished"],
            "type": "footer",
        }
        if footer_changes:
            footer.update(footer_changes)
        return header_line + b"".join(event_lines) + j0.canonical_json_bytes(footer)

    def seal(
        header: dict[str, Any],
        events: list[dict[str, Any]],
        footer_changes: dict[str, Any] | None = None,
    ) -> bytes:
        counts = {name: 0 for name in _EVENT_KEYS}
        for event in events:
            counts[event["event"]] += 1
        return seal_lines(
            header,
            [j0.canonical_json_bytes(event) for event in events],
            counts,
            footer_changes,
        )

    check("schema name has an independent literal oracle",
          SCHEMA == "r2t.java-j0-cucumber-fork/1")
    check("project/adapter pairs have an independent literal oracle",
          ADAPTER_BY_PROJECT == {
              "algorand-sdk": "cucumber-6.6.0/r2t-1",
              "epubcheck": "cucumber-7.8.0/r2t-1",
          })
    check("status vocabulary has an independent literal oracle",
          STATUSES == {
              "unknown", "skipped", "pending", "undefined",
              "ambiguous", "failed", "passed", "unused",
          })
    check("hook vocabulary has an independent literal oracle",
          HOOK_TYPES == {"before", "after", "before_step", "after_step"})
    check("event variants have an independent literal oracle",
          set(_EVENT_KEYS) == {
              "case_started", "step_finished", "case_finished"})

    header = {
        "adapter": ADAPTER_BY_PROJECT["epubcheck"],
        "invocation_id": digest("invocation"),
        "invocation_manifest_sha256": digest("invocation-manifest"),
        "project": "epubcheck",
        "projection_manifest_sha256": digest("projection"),
        "recorder_class_sha256": digest("recorder-class"),
        "schema": SCHEMA,
        "surefire_context_id": digest("surefire-context"),
        "type": "header",
    }
    case = {
        "case_column": 3,
        "case_line": 7,
        "name": "empty strings remain ordinary strings",
        "pickle_steps": [
            {"column": 5, "keyword": "Given ", "line": 8,
             "ordinal": 0, "text": "a book"},
            {"column": 5, "keyword": "Then ", "line": 9,
             "ordinal": 1, "text": "it validates"},
        ],
        "uri": "src/test/resources/features/book.feature",
    }
    case_ref = literal_case_ref(case)
    check("raw-case identity uses the independent literal domain prefix",
          _case_ref(case) == case_ref)
    events = [
        {"case": case, "case_ref": case_ref, "event": "case_started",
         "seq": 0, "type": "event"},
        {"case_ref": case_ref,
         "code_location": {"line": 12, "path": "src/test/java/Hooks.java"},
         "error": None, "event": "step_finished", "execution_ordinal": 0,
         "hook_type": "before", "pickle_step_ordinal": None, "seq": 1,
         "status": "passed", "type": "event"},
        {"case_ref": case_ref,
         "code_location": {"line": 21, "path": "src/test/java/Steps.java"},
         "error": {"class": "", "message": None},
         "event": "step_finished", "execution_ordinal": 1,
         "hook_type": None, "pickle_step_ordinal": 0, "seq": 2,
         "status": "passed", "type": "event"},
        {"case_ref": case_ref, "code_location": None, "error": None,
         "event": "step_finished", "execution_ordinal": 2,
         "hook_type": None, "pickle_step_ordinal": 1, "seq": 3,
         "status": "undefined", "type": "event"},
        {"case_ref": case_ref,
         "code_location": {"line": 18, "path": "src/test/java/Hooks.java"},
         "error": None, "event": "step_finished", "execution_ordinal": 3,
         "hook_type": "after", "pickle_step_ordinal": None, "seq": 4,
         "status": "passed", "type": "event"},
        {"case_ref": case_ref,
         "error": {"class": "io.cucumber.Error", "message": "undefined"},
         "event": "case_finished", "seq": 5, "status": "failed",
         "type": "event"},
    ]
    clean = seal(header, events)
    facts = validate_fork_bytes(clean)
    check("clean multi-event vector returns only authenticated raw facts",
          facts["header"] == header and facts["events"] == events
          and facts["footer"]["event_count"] == 6
          and facts["fork_sha256"] == j0._sha256(clean)
          and set(facts) == {"header", "events", "footer", "fork_sha256"})

    direct_header = copy.deepcopy(header)
    direct_header["surefire_context_id"] = None
    zero = seal(direct_header, [])
    zero_facts = validate_fork_bytes(zero)
    check("zero-event direct fork is valid and hashes empty event bytes",
          zero_facts["events"] == []
          and zero_facts["footer"]["events_sha256"] == j0._sha256(b""))

    unknown = copy.deepcopy(events)
    unknown[1]["foreign"] = False
    check("unknown event key is refused after footer rehash",
          refused(lambda: validate_fork_bytes(seal(header, unknown))))
    missing = copy.deepcopy(events)
    del missing[1]["error"]
    check("missing event key is refused after footer rehash",
          refused(lambda: validate_fork_bytes(seal(header, missing))))
    canonical_event_lines = [j0.canonical_json_bytes(event) for event in events]
    duplicate_line = canonical_event_lines[1][:-2] + b',"type":"event"}\n'
    duplicate_lines = list(canonical_event_lines)
    duplicate_lines[1] = duplicate_line
    counts = {"case_started": 1, "step_finished": 4, "case_finished": 1}
    duplicate_raw = seal_lines(header, duplicate_lines, counts)
    check("duplicate JSON key is refused with matching raw event digest",
          refused(lambda: validate_fork_bytes(duplicate_raw)))

    unknown_event_name = copy.deepcopy(events)
    unknown_event_name[1]["event"] = "case_progressed"
    unknown_event_raw = seal_lines(
        header,
        [j0.canonical_json_bytes(event) for event in unknown_event_name],
        counts,
    )
    check("unknown event name is refused with matching raw event digest",
          refused(lambda: validate_fork_bytes(unknown_event_raw)))

    foreign_header = copy.deepcopy(header)
    foreign_header["foreign"] = None
    foreign_case = copy.deepcopy(events)
    foreign_case[0]["case"]["foreign"] = None
    foreign_pickle = copy.deepcopy(events)
    foreign_pickle[0]["case"]["pickle_steps"][0]["foreign"] = None
    foreign_location = copy.deepcopy(events)
    foreign_location[1]["code_location"]["foreign"] = None
    foreign_error = copy.deepcopy(events)
    foreign_error[-1]["error"]["foreign"] = None
    closed_object_probes = (
        ("header", seal(foreign_header, events)),
        ("footer", seal(header, events, {"foreign": None})),
        ("case", seal(header, rebind_case(foreign_case))),
        ("pickle-step", seal(header, rebind_case(foreign_pickle))),
        ("code-location", seal(header, foreign_location)),
        ("error", seal(header, foreign_error)),
    )
    for label, probe_raw in closed_object_probes:
        check(f"foreign key in {label} object is refused after full rehash",
              refused(lambda raw=probe_raw: validate_fork_bytes(raw)))

    bad_case_line = copy.deepcopy(events)
    bad_case_line[0]["case"]["case_line"] = 0
    bad_pickle_line = copy.deepcopy(events)
    bad_pickle_line[0]["case"]["pickle_steps"][0]["line"] = 0
    bad_pickle_text = copy.deepcopy(events)
    bad_pickle_text[0]["case"]["pickle_steps"][0]["text"] = 7
    single_step_events = resequence([
        copy.deepcopy(events[0]), copy.deepcopy(events[1]),
        copy.deepcopy(events[-1]),
    ])
    core_field_probes = [
        ("header.type", seal({**header, "type": "event"}, events)),
        ("header.schema", seal({**header, "schema": "foreign/1"}, events)),
        ("footer.type", seal(header, events, {"type": "header"})),
        ("footer.schema", seal(header, events, {"schema": "foreign/1"})),
        ("case.case_line", seal(header, rebind_case(bad_case_line))),
        ("pickle-step.line", seal(header, rebind_case(bad_pickle_line))),
        ("pickle-step.text", seal(header, rebind_case(bad_pickle_text))),
    ]
    for field in (
        "case_started_count", "step_finished_count", "case_finished_count",
    ):
        core_field_probes.append(
            (f"footer.{field}", seal(header, single_step_events, {field: True})))
    for label, probe_raw in core_field_probes:
        check(f"core field {label} is validated after independent reseal",
              refused(lambda raw=probe_raw: validate_fork_bytes(raw)))

    spaced_lines = list(canonical_event_lines)
    spaced_lines[1] = spaced_lines[1].replace(b',"error":', b', "error":', 1)
    check("noncanonical line is refused with matching raw event digest",
          refused(lambda: validate_fork_bytes(
              seal_lines(header, spaced_lines, counts))))
    crlf_header_line = j0.canonical_json_bytes(header)[:-1] + b"\r\n"
    crlf_event_lines = [line[:-1] + b"\r\n" for line in canonical_event_lines]
    crlf_footer = {
        "case_finished_count": 1,
        "case_started_count": 1,
        "event_count": 6,
        "events_sha256": j0._sha256(b"".join(crlf_event_lines)),
        "header_sha256": j0._sha256(crlf_header_line),
        "schema": "r2t.java-j0-cucumber-fork/1",
        "step_finished_count": 4,
        "type": "footer",
    }
    crlf_raw = crlf_header_line + b"".join(crlf_event_lines) \
        + j0.canonical_json_bytes(crlf_footer)[:-1] + b"\r\n"
    check("CRLF framing refuses even when its raw-line digests are recomputed",
          refused(lambda: validate_fork_bytes(crlf_raw)))
    check("trailing bytes after the terminal fork are refused",
          refused(lambda: validate_fork_bytes(clean + b"trailing"))
          and refused(lambda: validate_fork_bytes(clean + b"\n")))

    noncontiguous = copy.deepcopy(events)
    noncontiguous[2]["seq"] = 7
    check("noncontiguous event seq is refused after footer rehash",
          refused(lambda: validate_fork_bytes(seal(header, noncontiguous))))
    weakened = copy.deepcopy(events)
    weak_ref = j0._sha256(j0.canonical_json_bytes(case, terminal_lf=False))
    for event in weakened:
        event["case_ref"] = weak_ref
    check("case_ref without the raw-case domain is refused after footer rehash",
          refused(lambda: validate_fork_bytes(seal(header, weakened))))

    duplicate_start = copy.deepcopy(events)
    duplicate_start.insert(1, copy.deepcopy(duplicate_start[0]))
    resequence(duplicate_start)
    missing_start = resequence(copy.deepcopy(events[1:]))
    duplicate_finish = copy.deepcopy(events)
    duplicate_finish.append(copy.deepcopy(duplicate_finish[-1]))
    resequence(duplicate_finish)
    missing_finish = copy.deepcopy(events[:-1])
    check("duplicate case start is refused after count and digest rehash",
          refused(lambda: validate_fork_bytes(seal(header, duplicate_start))))
    check("missing case start is refused after count and digest rehash",
          refused(lambda: validate_fork_bytes(seal(header, missing_start))))
    check("duplicate case finish is refused after count and digest rehash",
          refused(lambda: validate_fork_bytes(seal(header, duplicate_finish))))
    check("missing case finish is refused after count and digest rehash",
          refused(lambda: validate_fork_bytes(seal(header, missing_finish))))

    both_step_kinds = copy.deepcopy(events)
    both_step_kinds[1]["pickle_step_ordinal"] = 0
    neither_step_kind = copy.deepcopy(events)
    neither_step_kind[1]["hook_type"] = None
    bad_pickle_index = copy.deepcopy(events)
    bad_pickle_index[2]["pickle_step_ordinal"] = 2
    check("hook/pickle XOR is exact after event digest rehash",
          refused(lambda: validate_fork_bytes(seal(header, both_step_kinds)))
          and refused(lambda: validate_fork_bytes(seal(header, neither_step_kind))))
    check("pickle ordinal must index the started case after digest rehash",
          refused(lambda: validate_fork_bytes(seal(header, bad_pickle_index))))
    bad_execution = copy.deepcopy(events)
    bad_execution[2]["execution_ordinal"] = 2
    check("execution ordinal follows per-case event-bus order",
          refused(lambda: validate_fork_bytes(seal(header, bad_execution))))

    count_bypass = {
        "case_started_count": 2,
        "case_finished_count": 0,
        "event_count": 6,
    }
    check("self-consistent footer count sum cannot bypass observed counts",
          refused(lambda: validate_fork_bytes(
              seal(header, events, count_bypass))))
    check("wrong header digest is refused",
          refused(lambda: validate_fork_bytes(seal(
              header, events, {"header_sha256": digest("wrong-header")}))))
    check("wrong events digest is refused",
          refused(lambda: validate_fork_bytes(seal(
              header, events, {"events_sha256": digest("wrong-events")}))))

    footerless = b"".join(clean.splitlines(keepends=True)[:-1])
    check("footerless stream is refused",
          refused(lambda: validate_fork_bytes(footerless)))
    check("a canonical event after the footer is refused",
          refused(lambda: validate_fork_bytes(clean + canonical_event_lines[0])))

    wrong_adapter = copy.deepcopy(header)
    wrong_adapter["adapter"] = "cucumber-8.0.0/r2t-1"
    mismatched_project = copy.deepcopy(header)
    mismatched_project["project"] = "algorand-sdk"
    wrong_project = copy.deepcopy(header)
    wrong_project["project"] = "cores"
    check("unknown adapter is refused after header digest rehash",
          refused(lambda: validate_fork_bytes(seal(wrong_adapter, events))))
    check("project/adapter pairing is exact after header digest rehash",
          refused(lambda: validate_fork_bytes(seal(mismatched_project, events))))
    check("unknown project is refused after header digest rehash",
          refused(lambda: validate_fork_bytes(seal(wrong_project, events))))
    wrong_status = copy.deepcopy(events)
    wrong_status[1]["status"] = "successful"
    check("status vocabulary is closed after event digest rehash",
          refused(lambda: validate_fork_bytes(seal(header, wrong_status))))
    wrong_type = copy.deepcopy(events)
    wrong_type[1]["type"] = "step"
    bool_seq = copy.deepcopy(events)
    bool_seq[1]["seq"] = True
    check("event discriminator and integer JSON types are exact",
          refused(lambda: validate_fork_bytes(seal(header, wrong_type)))
          and refused(lambda: validate_fork_bytes(seal(header, bool_seq))))

    malformed_case = copy.deepcopy(events)
    malformed_case[0]["case"]["pickle_steps"][1]["ordinal"] = 0
    malformed_ref = literal_case_ref(malformed_case[0]["case"])
    for event in malformed_case:
        event["case_ref"] = malformed_ref
    check("pickle step shape and list ordinal are exact after full rehash",
          refused(lambda: validate_fork_bytes(seal(header, malformed_case))))
    wrong_case_name = copy.deepcopy(events)
    wrong_case_name[0]["case"]["name"] = 7
    wrong_pickle_keyword = copy.deepcopy(events)
    wrong_pickle_keyword[0]["case"]["pickle_steps"][0]["keyword"] = 7
    check("case name and pickle keyword remain strings after full rehash",
          refused(lambda: validate_fork_bytes(seal(
              header, rebind_case(wrong_case_name))))
          and refused(lambda: validate_fork_bytes(seal(
              header, rebind_case(wrong_pickle_keyword)))))
    bad_case_path = copy.deepcopy(events)
    bad_case_path[0]["case"]["uri"] = "/absolute.feature"
    bad_path_ref = literal_case_ref(bad_case_path[0]["case"])
    for event in bad_case_path:
        event["case_ref"] = bad_path_ref
    check("case URI uses the protocol relative POSIX path rule",
          refused(lambda: validate_fork_bytes(seal(header, bad_case_path))))

    bad_location = copy.deepcopy(events)
    bad_location[1]["code_location"]["path"] = "../Hooks.java"
    zero_location_line = copy.deepcopy(events)
    zero_location_line[1]["code_location"]["line"] = 0
    missing_location = copy.deepcopy(events)
    missing_location[1]["code_location"] = None
    located_undefined = copy.deepcopy(events)
    located_undefined[3]["code_location"] = {
        "line": 1, "path": "src/test/java/Foreign.java"}
    check("code location shape/path and undefined nullability are exact",
          refused(lambda: validate_fork_bytes(seal(header, bad_location)))
          and refused(lambda: validate_fork_bytes(seal(header, zero_location_line)))
          and refused(lambda: validate_fork_bytes(seal(header, missing_location)))
          and refused(lambda: validate_fork_bytes(seal(header, located_undefined))))
    bad_error = copy.deepcopy(events)
    bad_error[-1]["error"]["message"] = 7
    bad_error_class = copy.deepcopy(events)
    bad_error_class[-1]["error"]["class"] = 7
    check("error shape and message type are exact after event digest rehash",
          refused(lambda: validate_fork_bytes(seal(header, bad_error)))
          and refused(lambda: validate_fork_bytes(seal(header, bad_error_class))))

    status_vectors_valid = True
    for status in sorted(STATUSES):
        status_events = copy.deepcopy(events)
        status_events[2]["status"] = status
        status_events[2]["code_location"] = (
            None if status == "undefined"
            else {"line": 21, "path": "src/test/java/Steps.java"})
        try:
            validate_fork_bytes(seal(header, status_events))
        except j0.J0Error:
            status_vectors_valid = False
    check("all eight protocol status values remain admissible evidence",
          status_vectors_valid)

    for key in (
        "invocation_id", "invocation_manifest_sha256",
        "projection_manifest_sha256", "recorder_class_sha256",
    ):
        bad_hex_header = copy.deepcopy(header)
        bad_hex_header[key] = "A" * 64
        check(f"header.{key} independently requires lowercase 64-hex",
              refused(lambda value=bad_hex_header: validate_fork_bytes(
                  seal(value, events))))
    check("non-null Surefire context independently requires lowercase 64-hex",
          refused(lambda: validate_fork_bytes(
              seal({**header, "surefire_context_id": 7}, events))))
    check("validator accepts bytes only",
          refused(lambda: validate_fork_bytes(bytearray(clean))))

    print("\n" + ("ALL PASS (java.j0_fork)" if ok
                   else "FAILURES (java.j0_fork)"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(selftest())
