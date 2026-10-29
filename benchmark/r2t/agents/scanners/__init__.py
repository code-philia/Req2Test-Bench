"""The native-manifest contract: an agent's own record, independently checked.

WHY THIS PACKAGE EXISTS.  Rev 1 of the aider design had the driver synthesize
a normalized event stream and the validation pass verify the driver's own
output —
circular: a buggy driver that drops a native record still passes every counter
it wrote itself.  The fix (plan D8b) is a
SECOND, independent recorder: the agent framework's own artifacts — for aider,
the chat markdown and the analytics event log — preserved immutably beside the
normalized stream and DECLARED in a manifest, so that a validation pass which
wrote neither can reconcile the two records of one run.  A mismatch means the
evidence is not intact.

THE MANIFEST (`native_manifest.json`, at the top of the attempt directory):

    {"schema": "r2t.native_manifest/1",
     "agent_system": "aider",
     "files": [{"name": "aider.chat.history.md", "role": "chat_log",
                "sha256": "...", "bytes": 470},
               {"name": "aider_events.jsonl", "role": "analytics_log",
                "sha256": "...", "bytes": 964}],
     "counts": {"llm_calls_main": 3, "test_failures": 2, "edits": 1,
                "reflection_cap_hit": false}}

`files` are the native artifacts, hashed AS PRESERVED (the driver redacts
credentials before hashing, so the later adapter-side redaction pass finds
nothing to rewrite and the hashes stay true).  `counts` are derived from the
NATIVE artifacts alone — never from the driver's own bookkeeping — and only
quantities the native stream can actually witness are in the vocabulary.  That
restriction is finding F5 of the A1 battery (docs/AIDER_A1_VERIFICATION.md)
and it reshapes what "reconcile" may mean:

  llm_calls_main      the number of `message_send` events in the analytics
                      log.  Aider emits one per MAIN-LOOP model call and NONE
                      for its chat-history summarizer (the event is raised
                      only from `calculate_and_show_tokens_and_cost`), so the
                      normalized stream — which accounts EVERY call the
                      litellm callback saw, summarizer included — must carry
                      AT LEAST this many llm-call events.  A floor, not an
                      equality: demanding equality would refuse every correct
                      run whose history grew long enough to summarize.  The
                      count itself is also recounted here from the declared
                      analytics bytes, and THAT comparison is exact — a
                      manifest that misstates its own file is lying about the
                      one thing only it asserts.
  test_failures       occurrences of aider's "Attempt to fix test errors?"
                      gate in the chat log — a PASSING --auto-test run leaves
                      no native trace at all (F5), so failed runs are the only
                      reconcilable test quantity.  Exactly equal to the
                      normalized autotest events whose exit code is non-zero.
  edits               DISTINCT file paths in the chat log's "Applied edit to"
                      lines.  Distinct, because aider prints the line once per
                      path per turn while `Coder.aider_edited_files` — the
                      driver's independent source — is a cumulative set; both
                      derive from the same per-turn `edited` lists, so the
                      distinct counts agree exactly (verified at the 0.86.2
                      pin: base_coder.py:1588 vs :2334).  Exactly equal to the
                      normalized file-edit events.
  reflection_cap_hit  whether the chat log carries "reflections allowed,
                      stopping.".  Declared, NOT reconciled: it is a boolean
                      about aider's own loop and no independent normalized
                      record of it exists.

REFUSE-DON'T-REPAIR.  A manifest that is unreadable, mis-shaped, of an unknown
schema, or naming an agent no scanner here knows is a validation problem.  A
declared file that is missing, or whose bytes no longer match their declared
sha256, is a conservation failure: the evidence the row was scored with is not
the evidence on disk.  Declared file names are validated before they are joined
onto a path, so a manifest cannot point validation at somebody else's file.

An attempt directory with no manifest is not touched by this package.  Whether
one is required is declared by the agent registry and enforced by
``trajectory_validation.validate_run``.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Iterable, Optional

#: The manifest's file name, at the top of the attempt directory.
NATIVE_MANIFEST = "native_manifest.json"

#: Bump when a FIELD changes meaning.  An unknown schema string is refused,
#: never guessed at: a future manifest format read under today's rules would
#: verify claims it does not make.
MANIFEST_SCHEMA = "r2t.native_manifest/1"


def _scanner_for(agent_system: Optional[str]):
    """The per-agent reconcile module, or None.

    Function-local import so that loading this package does not load every
    agent's scanner, and so a broken scanner costs the agents that use it
    rather than the package.  The registry is deliberately a literal: an
    agent system is admitted here by a code change, reviewed, never by a
    string in a file the run itself wrote.
    """
    if agent_system == "aider":
        from . import aider
        return aider
    return None


#: The schema of the `termination` block an attempt cut short by the
#: wall-clock envelope carries (`r2t.confined.terminate`).  Read here rather than
#: imported so that reading an archived run still does not construct the
#: adapter chain; the two are pinned equal by `terminate.selftest`.
TERMINATION_SCHEMA = "r2t.termination/1"

#: A selftest sentinel meaning "leave this key out entirely", so that a
#: fixture can distinguish a key set to None from a key that is not there.
_ABSENT = object()


def read_termination(manifest: dict) -> tuple:
    """`(declaration, problems)` for a manifest's optional `termination` key.

    ABSENT means the run finished — that is what every manifest written
    before this key existed means, and it must keep meaning it, so absence is
    never a problem.  PRESENT means the attempt was cut short, and then the
    block has to be able to say so: a declaration that cannot name its reason,
    or that claims the run was `complete` after all, is a manifest
    contradicting itself, and a validator that shrugged at that would accept
    the one shape a driver could use to launder a partial run into a whole
    one.
    """
    if "termination" not in manifest:
        return None, []
    doc = manifest.get("termination")
    if not isinstance(doc, dict):
        return None, [f"{NATIVE_MANIFEST} declares a termination that is not "
                      f"an object: {doc!r:.120}"]
    problems = []
    if doc.get("schema") != TERMINATION_SCHEMA:
        problems.append(
            f"{NATIVE_MANIFEST}'s termination declares schema "
            f"{doc.get('schema')!r}, and this validator reads only "
            f"{TERMINATION_SCHEMA!r}")
    if not isinstance(doc.get("reason"), str) or not doc["reason"]:
        problems.append(
            f"{NATIVE_MANIFEST} says this attempt was terminated but names "
            "no reason -- a partial run that cannot say why it is partial is "
            "not an account of anything")
    if doc.get("complete") is not False:
        problems.append(
            f"{NATIVE_MANIFEST}'s termination says complete="
            f"{doc.get('complete')!r}; a terminated attempt is by "
            "construction incomplete, and a manifest may not claim otherwise")
    if not isinstance(doc.get("preserved_by"), str) or not doc["preserved_by"]:
        problems.append(
            f"{NATIVE_MANIFEST}'s termination does not say WHO preserved the "
            "evidence -- the driver's main thread and its watchdog take "
            "snapshots of different quality and a reader must be able to "
            "tell them apart")
    return doc, problems


def _safe_name(name) -> bool:
    """Is this declared file name a plain name under the attempt directory?

    The manifest is data written inside the run, and its names are joined
    onto paths.  Anything that could walk out of the attempt — a separator, a
    `..`, an absolute path — is refused, for the same reason the trajectory
    validator's
    `_conversation_events` refuses them: a row must not be able to have
    somebody else's bytes answer for its own.
    """
    return (isinstance(name, str) and bool(name)
            and name not in (".", "..")
            and "/" not in name and "\\" not in name
            and os.sep not in name
            and not (os.altsep and os.altsep in name))


def read_manifest(directory: str) -> tuple:
    """`(manifest, problem)` — exactly one of the two is None.

    A missing file returns `(None, None)`: absence is the archived case and
    is not a problem.  Everything else that is not a well-shaped manifest of
    the known schema is a PROBLEM string, because a half-read manifest that
    still granted exemptions would be a repair.
    """
    path = os.path.join(directory, NATIVE_MANIFEST)
    if not os.path.isfile(path):
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError) as exc:
        return None, (f"{NATIVE_MANIFEST} could not be read: "
                      f"{type(exc).__name__}: {exc}")
    if not isinstance(doc, dict):
        return None, f"{NATIVE_MANIFEST} is not an object"
    if doc.get("schema") != MANIFEST_SCHEMA:
        return None, (f"{NATIVE_MANIFEST} declares schema "
                      f"{doc.get('schema')!r}, and this validator reads only "
                      f"{MANIFEST_SCHEMA!r}")
    if not isinstance(doc.get("files"), list) or not doc["files"]:
        return None, f"{NATIVE_MANIFEST} declares no files"
    if not isinstance(doc.get("counts"), dict):
        return None, f"{NATIVE_MANIFEST} declares no counts"
    return doc, None


def verify(directory: str, events: list, secrets: Iterable = (),
           sweep=None) -> Optional[dict]:
    """Verify one attempt directory's native manifest against what is there.

    ``events`` are the attempt's parsed normalized events.  This package checks
    the declared native bytes and reconciles native counts; host detection and
    raw network sweeps are outside its own contract — the retained LEGACY
    gate may inject its raw-byte ``sweep`` (`egress._raw_sweep`) and the
    ``secrets`` it redacts; the prospective path injects neither.

    Returns None when the directory carries no manifest (the archived path:
    the caller then changes nothing), else:

        {"agent_system": ..., "counts": {...},
         "declared": [names exempt from the unrecognized inventory],
         "problems": [strings -- each means the evidence is not intact],
         "hits": [...], "errors": [...],
         "exempt": [...]}   # from the injected sweep; all empty when the
                            # caller supplies none

    ``declared`` is empty whenever the manifest itself could not be trusted, so
    a bad manifest exempts nothing from the reported unrecognized inventory and
    carries its own validation problem.
    """
    manifest, problem = read_manifest(directory)
    if manifest is None and problem is None:
        return None
    out = {"agent_system": None, "counts": {}, "declared": [],
           "termination": None, "problems": [], "hits": [], "errors": [],
           "exempt": []}
    if problem is not None:
        out["problems"].append(problem)
        return out
    out["agent_system"] = manifest.get("agent_system")
    out["counts"] = dict(manifest["counts"])
    out["termination"], termination_problems = read_termination(manifest)
    out["problems"].extend(termination_problems)

    scanner = _scanner_for(manifest.get("agent_system"))
    if scanner is None:
        out["problems"].append(
            f"{NATIVE_MANIFEST} names agent system "
            f"{manifest.get('agent_system')!r}, which no scanner here reads "
            "-- its native files cannot be verified, so they are not "
            "exempted either")
        return out

    # The file inventory: existence and identity, before anything else reads
    # the bytes.  Only files that pass every check land in `declared`; the
    # manifest itself is exempt because it IS the account.
    declared = [NATIVE_MANIFEST]
    present: list = []
    by_role: dict = {}
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or not _safe_name(entry.get("name")):
            out["problems"].append(
                f"{NATIVE_MANIFEST} declares a file under an unusable name: "
                f"{entry!r:.120}")
            continue
        name = entry["name"]
        declared.append(name)
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            out["problems"].append(
                f"declared native file {name} is missing -- the evidence the "
                "manifest accounts for is not on disk")
            continue
        try:
            with open(path, "rb") as handle:
                blob = handle.read()
        except OSError as exc:
            out["problems"].append(
                f"declared native file {name} could not be read: "
                f"{type(exc).__name__}: {exc}")
            continue
        digest = hashlib.sha256(blob).hexdigest()
        if entry.get("sha256") != digest:
            out["problems"].append(
                f"native file {name} does not match its declared sha256 -- "
                "the bytes on disk are not the bytes the run preserved")
            continue
        if isinstance(entry.get("bytes"), int) and entry["bytes"] != len(blob):
            out["problems"].append(
                f"native file {name} is {len(blob)} bytes, declared "
                f"{entry['bytes']}")
            continue
        present.append(name)
        role = entry.get("role")
        if isinstance(role, str) and role:
            by_role.setdefault(role, name)
    # Exemption is granted for every SAFELY NAMED declared file, present or
    # not: a missing declared file is already a fatal problem above, and
    # leaving its name in the unrecognized inventory as well would report one
    # absence twice under two vocabularies.
    out["declared"] = declared

    # The raw-byte sweep over what is actually there, with the LEGACY
    # gate's own detectors — run only when the caller injects one.  The
    # prospective validation path (`trajectory_validation`) supplies none:
    # host inference is retired for new runs.  Hits come back kind "raw":
    # capped at SUSPECT, never a violation — a URL in a chat transcript is
    # the model TALKING about a host, and aider has no tool that could have
    # fetched it.
    if sweep is not None:
        hits, errors, exempt = sweep(directory, present, "native-file",
                                     secrets)
        out["hits"] = hits
        out["errors"] = errors
        out["exempt"] = exempt


    # The counts, reconciled by the agent's own scanner under the F5-aware
    # rules the module docstring states.
    out["problems"].extend(
        scanner.reconcile(directory, manifest, events, by_role))
    return out


# ------------------------------------------------------------------ selftest

def selftest() -> int:
    """Exercise native identity, native counts, and registry dispatch."""
    import shutil
    import tempfile

    from ...bench import trajectory_validation as validation

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        ok = ok and bool(condition)
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))

    def sha(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def write(directory: str, name: str, text: str) -> str:
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, name), "w", encoding="utf-8") as fh:
            fh.write(text)
        return text

    def event(directory: str, index: int, payload: dict) -> None:
        events = os.path.join(directory, "conv", "events")
        os.makedirs(events, exist_ok=True)
        with open(os.path.join(events, f"event-{index:05d}-aaaa.json"),
                  "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

    def attempt(root: str, item: str, *, n_msg: int = 2,
                counts: Optional[dict] = None,
                schema: str = MANIFEST_SCHEMA, agent: str = "aider",
                termination=None) -> str:
        directory = os.path.join(root, validation.item_key(item))
        chat = ("# aider chat started\n\n"
                "> Attempt to fix test errors? (Y)es/(N)o [Yes]: y\n"
                "Applied edit to repo/src/x.py\n")
        analytics = ('{"event": "message_send", "properties": {}}\n'
                     '{"event": "message_send", "properties": {}}\n')
        write(directory, "aider.chat.history.md", chat)
        write(directory, "aider_events.jsonl", analytics)
        index = 1
        for number in range(n_msg):
            event(directory, index,
                  {"id": f"call-{number}", "kind": "MessageEvent",
                   "source": "agent", "llm_call": {"sequence": number + 1}})
            index += 1
        event(directory, index,
              {"id": "test", "kind": "ActionEvent", "source": "agent",
               "tool_name": "autotest", "exit_code": 1,
               "action": {"kind": "AutotestAction",
                          "command": "python3 trial.py"}})
        index += 1
        event(directory, index,
              {"id": "edit", "kind": "ActionEvent", "source": "agent",
               "tool_name": "file_edit",
               "action": {"kind": "FileEditAction",
                          "path": "repo/src/x.py"}})
        manifest = {
            "schema": schema,
            "agent_system": agent,
            "files": [
                {"name": "aider.chat.history.md", "role": "chat_log",
                 "sha256": sha(chat), "bytes": len(chat.encode())},
                {"name": "aider_events.jsonl", "role": "analytics_log",
                 "sha256": sha(analytics),
                 "bytes": len(analytics.encode())},
            ],
            "counts": counts or {
                "llm_calls_main": 2,
                "test_failures": 1,
                "edits": 1,
                "reflection_cap_hit": False,
            },
        }
        if termination is not None:
            manifest["termination"] = termination
        write(directory, NATIVE_MANIFEST, json.dumps(manifest))
        return directory

    def result_for(root: str, item: str, adapter: str = "aider") -> dict:
        run = os.path.join(root, f"run-{validation.item_key(item)}.jsonl")
        with open(run, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": item, "condition": "c3",
                                 "adapter": adapter}) + "\n")
        return validation.validate_run(run, root)[item]

    def reasons(result: dict) -> str:
        return json.dumps(result["problems"])

    counts = {"llm_calls_main": 2, "test_failures": 1, "edits": 1,
              "reflection_cap_hit": False}
    root = tempfile.mkdtemp(prefix="r2t-scanners-")
    try:
        item = "project/features/native.feature:1"
        attempt(root, item)
        result = result_for(root, item)
        check("a coherent native manifest validates",
              result["intact"], reasons(result))
        native = result["attempts"][0]["native"]
        check("declared native files are accounted rather than unrecognized",
              result["unrecognized"] == []
              and native["agent_system"] == "aider",
              json.dumps(result))

        item = "project/features/dropped.feature:2"
        attempt(root, item, n_msg=1)
        result = result_for(root, item)
        check("a dropped normalized main-loop call is detected",
              not result["intact"]
              and any("fewer" in problem and "analytics" in problem
                      for problem in result["problems"]), reasons(result))

        item = "project/features/summarized.feature:3"
        attempt(root, item, n_msg=5)
        result = result_for(root, item)
        check("normalized summarizer calls may exceed the native floor",
              result["intact"], reasons(result))

        item = "project/features/liar.feature:4"
        attempt(root, item, n_msg=3,
                counts=dict(counts, llm_calls_main=3))
        result = result_for(root, item)
        check("a manifest that misstates its native analytics is detected",
              not result["intact"]
              and any("recount" in problem for problem in result["problems"]),
              reasons(result))

        item = "project/features/missing.feature:5"
        directory = attempt(root, item)
        os.remove(os.path.join(directory, "aider.chat.history.md"))
        result = result_for(root, item)
        check("a missing declared native file is detected",
              not result["intact"]
              and any("missing" in problem for problem in result["problems"]),
              reasons(result))

        item = "project/features/tampered.feature:6"
        directory = attempt(root, item)
        with open(os.path.join(directory, "aider.chat.history.md"), "a",
                  encoding="utf-8") as fh:
            fh.write("changed after preservation\n")
        result = result_for(root, item)
        check("changed native bytes fail their declared digest",
              not result["intact"]
              and any("sha256" in problem for problem in result["problems"]),
              reasons(result))

        item = "project/features/schema.feature:7"
        attempt(root, item, schema="r2t.native_manifest/999")
        result = result_for(root, item)
        check("an unknown native-manifest schema is not guessed",
              not result["intact"]
              and any("schema" in problem for problem in result["problems"]),
              reasons(result))

        item = "project/features/agent.feature:8"
        attempt(root, item, agent="unknown-agent")
        result = result_for(root, item)
        check("an unknown native scanner is reported",
              not result["intact"]
              and any("no scanner" in problem for problem in result["problems"]),
              reasons(result))

        check("native file names cannot escape the attempt directory",
              not _safe_name("../elsewhere") and not _safe_name("a/b")
              and _safe_name("aider.chat.history.md"))

        termination = {"schema": TERMINATION_SCHEMA,
                       "reason": "envelope_expired", "complete": False,
                       "preserved_by": "main"}
        item = "project/features/terminated.feature:9"
        attempt(root, item, termination=termination)
        result = result_for(root, item)
        check("a well-declared partial attempt remains valid and visible",
              result["intact"]
              and result["attempts"][0]["native"]["termination"]["reason"]
              == "envelope_expired", reasons(result))

        item = "project/features/badtermination.feature:10"
        attempt(root, item, termination=dict(termination, complete=True))
        result = result_for(root, item)
        check("a contradictory termination declaration is detected",
              not result["intact"]
              and any("incomplete" in problem for problem in result["problems"]),
              reasons(result))

        item = "project/features/crossed.feature:11"
        attempt(root, item)
        result = result_for(root, item, adapter="openhands")
        check("row and manifest agent identities must agree",
              not result["intact"]
              and any("openhands" in problem and "aider" in problem
                      for problem in result["problems"]), reasons(result))

        item = "project/features/stray.feature:12"
        directory = attempt(root, item)
        write(directory, "session.jsonl", '{"note": "extra"}\n')
        result = result_for(root, item)
        check("an extra record is reported but is no longer an egress gate",
              result["intact"]
              and any(name.endswith("session.jsonl")
                      for name in result["unrecognized"]),
              json.dumps(result))

        item = "project/features/nomanifest.feature:13"
        directory = os.path.join(root, validation.item_key(item))
        event(directory, 1,
              {"id": "call", "kind": "MessageEvent", "source": "agent",
               "llm_call": {"sequence": 1}})
        try:
            # The two legs below read each arm's native contract off the
            # registry; a checkout without the agent component refuses an
            # agent arm's rows by name instead (`_native_contract`).
            from ..registry import REGISTRY  # noqa: F401
        except ImportError:
            print("  [SKIP] aider's registry contract requires a native "
                  "manifest / a system with no native contract keeps the "
                  "manifest-less path: the registry (agent component) is "
                  "not shipped in this checkout")
        else:
            result = result_for(root, item)
            check("aider's registry contract requires a native manifest",
                  not result["intact"]
                  and any(NATIVE_MANIFEST in problem and "aider@2" in problem
                          for problem in result["problems"]),
                  reasons(result))
            result = result_for(root, item, adapter="openhands")
            check("a system with no native contract keeps the manifest-less "
                  "path",
                  result["intact"]
                  and all("native" not in attempt
                          for attempt in result["attempts"]),
                  reasons(result))

        check("verify returns None when no manifest exists",
              verify(os.path.join(root, "absent"), []) is None)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    print("\n" + ("ALL PASS (agents.scanners)" if ok
                  else "FAILURES (agents.scanners)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
