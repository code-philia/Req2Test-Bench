"""The Java direct-invocation collector: the agent jar, its output, and the index.

`benchmark/API_DIRECT_INVOCATION_SPEC.md` section 2.4 makes the Java collector a
javaagent, because JaCoCo records no caller.  This module is the host side of
that agent:

* **the build** -- `build_agent_jar` compiles the sources under
  `direct_call_agent/` with the JDK the caller names, targeting release 11
  (the Algorand image is Temurin 11), bundles ASM 9.6 from the pinned jar the
  image already bakes under `/opt/m2` (`ASM_JAR_SHA256`), and writes a
  DETERMINISTIC jar: sorted entries, fixed timestamps, fixed modes.  Two builds
  from the same compiler give the same bytes, which is what lets the jar's
  SHA-256 be pinned beside a run's evaluator identity (section 7) and checked
  rather than trusted.
* **the option** -- `agent_option` is the one JVM argument the harness passes
  through surefire's `${r2t.agent.argline}` (section 2.4): the jar's runtime
  path and the ABSOLUTE output path, so the fork's working directory -- a
  per-project quirk -- never decides where the file lands.
* **the output** -- `read_direct_calls` reads `target/r2t-direct-calls.json`
  after the fork exits and returns the section 2.5 list: unique
  `{callee_file, callee_line, callee, caller_file}` objects sorted by that
  tuple, null before any string.  It refuses a file of another schema and a
  file that reports a class the agent failed to instrument, because a missed
  class is a silently smaller set and the loud version is right.
* **the index** -- `JavaMethodIndex` (in the same jar) reads
  `target/classes` with ASM into the envelope `bench.metrics.load_prod_index`
  already reads plus a `descriptor` per method; `cross_check_index` compares
  it with JaCoCo's own method inventory from a `jacoco.xml`, which is section
  2.4's cross-check.

Nothing here runs a JVM or Docker unless asked to build; the selftest is
network-free and JDK-free.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
import zipfile
from typing import Optional

#: Where the agent's sources live, package-relative, and the files that ARE the agent.
AGENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "direct_call_agent")
AGENT_SOURCES: tuple[str, ...] = (
    "r2t/directcalls/DirectCallAgent.java",
    "r2t/directcalls/DirectCallRecorder.java",
    "r2t/directcalls/Json.java",
    "r2t/directcalls/JavaMethodIndex.java",
)
#: The recorder-semantics fixture project (section 8's in-container fixtures
#: that need no SDK class), compiled and run by `scripts/gate_java_direct_calls.py`.
FIXTURE_DIR = os.path.join(AGENT_DIR, "fixtures")

AGENT_JAR_NAME = "r2t-direct-calls-agent.jar"
PREMAIN_CLASS = "r2t.directcalls.DirectCallAgent"
INDEX_MAIN_CLASS = "r2t.directcalls.JavaMethodIndex"

#: The class-file release the agent is compiled for: the image's JDK.
JAVA_RELEASE = "11"

#: The one third-party input, and its identity.  `/opt/m2` in the Algorand
#: image holds this exact file (JaCoCo 0.8.11 depends on it), and the host
#: Maven cache the reference build reads holds a byte-identical copy.
ASM_COORDINATE = "org.ow2.asm:asm:9.6"
ASM_JAR_REL = "org/ow2/asm/asm/9.6/asm-9.6.jar"
ASM_JAR_SHA256 = "3c6fac2424db3d4a853b669f4e3d1d9c3c552235e19a319673f887083c2303a1"

#: Where the fork finds the agent INSIDE the container, whichever route puts
#: it there (the owner's ruling of 2026-09-06: a read-only bind mount added at
#: worker provisioning).  Named here, beside the option that spells it, so the
#: harness that names the path and the provisioning that mounts it cannot
#: disagree about it.
AGENT_JAR_RUNTIME = "/opt/r2t/r2t-direct-calls-agent.jar"

#: The agent's output, workspace-relative.  Under `target/`, a BUILD root that
#: lies under no substrate root (`repo.CUCUMBER_SUBSTRATE_ROOTS`), exactly as
#: JaCoCo's two outputs do, so `verify_substrate` can never report it `added`.
OUTPUT_REL = "target/r2t-direct-calls.json"
#: `/2` since every event carries `step`.  The jar is mounted read-only at a
#: fixed runtime path, so the harness version cannot attest which recorder
#: wrote a dump; the dump says so itself and a `/1` file is refused here.
OUTPUT_SCHEMA = "r2t.java-direct-calls/2"
INDEX_SCHEMA = "r2t.java_prod_index/1"

#: The record entry's keys, section 2.5, in tuple order.  `step` is the
#: 0-based index of the executing step in the record's `steps` list, or None
#: for a call made outside any step (a hook, glue construction)
#: (TARGET_INTERFACES_V2_SPEC.md section 4).
EVENT_FIELDS: tuple[str, ...] = ("callee_file", "callee_line", "callee",
                                 "caller_file", "step")

#: The shape every Java gold row collected before the step tag carries.
#: `canonical_events` validates already-collected shards as well as fresh
#: agent output, and refusing those retroactively would discard collected
#: evidence, so both shapes are accepted and each event keeps its own keys.
LEGACY_EVENT_FIELDS: tuple[str, ...] = EVENT_FIELDS[:-1]

#: The jar's manifest, byte for byte.  CRLF because the JAR specification
#: writes it so; the blank line terminates the main section.
MANIFEST = ("Manifest-Version: 1.0\r\n"
            f"Premain-Class: {PREMAIN_CLASS}\r\n"
            f"Main-Class: {INDEX_MAIN_CLASS}\r\n"
            "Can-Redefine-Classes: false\r\n"
            "Can-Retransform-Classes: false\r\n"
            "\r\n")

#: Every zip entry's timestamp (the format's epoch) and mode.
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_ZIP_MODE = 0o644 << 16

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CALLEE = re.compile(r"[^\s:]+\.(<init>|[^\s.:<>]+):\(.*\).+\Z")


class DirectCallsRefused(RuntimeError):
    """The agent's inputs or its output are not what the harness can use."""


def _refuse(message: str) -> DirectCallsRefused:
    return DirectCallsRefused("REFUSED: " + message)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ------------------------------------------------------------------ the option

def agent_option(jar_runtime_path: str, output_abs: str) -> str:
    """The exact `-javaagent` option, for surefire's `${r2t.agent.argline}`.

    Both paths must be absolute and free of whitespace, because the option
    travels as ONE JVM argument through a Maven `-D` and surefire's late
    `argLine` substitution, neither of which quotes.
    """
    for label, path in (("agent jar", jar_runtime_path), ("output", output_abs)):
        if not path.startswith("/") or any(c.isspace() for c in path) \
                or "," in path:
            raise _refuse(f"the {label} path {path!r} must be absolute and "
                          f"carry no whitespace or comma: it rides in one "
                          f"unquoted JVM argument")
    return f"-javaagent:{jar_runtime_path}={output_abs}"


def agent_jar_mount(host_path: str) -> tuple[str, str]:
    """The read-only bind of the agent jar, as `worker.provision` spells a mount.

    `(host, "<runtime>:ro")`, the shape `composer_mounts` already returns,
    so the jar rides through the same `extra_mounts` argument and lands in
    the same `mounts_of` report.  Refuses anything but one canonical regular
    file: a symlink or a directory would mount something other than the
    bytes whose digest a run records.
    """
    if not isinstance(host_path, str) or not host_path \
            or any(c in host_path for c in "\x00\r\n,:") \
            or not os.path.isabs(host_path) \
            or os.path.normpath(host_path) != host_path:
        raise _refuse(f"agent jar path must be one normalized absolute path "
                      f"without ',' or ':': {host_path!r}")
    if os.path.islink(host_path) or not os.path.isfile(host_path) \
            or os.path.realpath(host_path) != host_path:
        raise _refuse(f"agent jar is not a canonical regular file: {host_path}")
    return (host_path, AGENT_JAR_RUNTIME + ":ro")


# ------------------------------------------------------------------- the build

def compile_agent(javac: str, asm_jar: str, classes_dir: str) -> None:
    """javac the four sources at release 11, warnings as errors."""
    sources = [os.path.join(AGENT_DIR, rel) for rel in AGENT_SOURCES]
    for path in sources:
        if not os.path.isfile(path):
            raise _refuse(f"agent source missing: {path}")
    argv = [javac, "--release", JAVA_RELEASE, "-Xlint:all", "-Werror",
            "-encoding", "UTF-8", "-cp", asm_jar, "-d", classes_dir] + sources
    cp = subprocess.run(argv, capture_output=True, text=True)
    if cp.returncode != 0:
        raise _refuse("javac failed:\n" + (cp.stderr or cp.stdout)[-3000:])


def _asm_entries(asm_jar: str) -> list[tuple[str, bytes]]:
    """ASM's classes, and only its classes: no manifest, no module descriptor."""
    with zipfile.ZipFile(asm_jar) as zf:
        return sorted(
            (info.filename, zf.read(info))
            for info in zf.infolist()
            if info.filename.startswith("org/objectweb/asm/")
            and info.filename.endswith(".class"))


def _class_entries(classes_dir: str) -> list[tuple[str, bytes]]:
    out = []
    for dirpath, _dirs, files in os.walk(classes_dir):
        for name in files:
            if name.endswith(".class"):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, classes_dir).replace(os.sep, "/")
                with open(full, "rb") as fh:
                    out.append((rel, fh.read()))
    return sorted(out)


def write_deterministic_jar(entries: list[tuple[str, bytes]], out_path: str,
                            manifest: str = MANIFEST) -> str:
    """Write `entries` (sorted, manifest first) as a jar whose bytes depend on nothing else."""
    names = [name for name, _ in entries]
    if len(set(names)) != len(names):
        raise _refuse("duplicate jar entries: "
                      + ", ".join(sorted({n for n in names if names.count(n) > 1})))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in [("META-INF/MANIFEST.MF", manifest.encode("utf-8"))] \
                + sorted(entries):
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = _ZIP_MODE
            info.create_system = 3
            # Per entry: the ZipFile-level level does not reach a ZipInfo write.
            zf.writestr(info, data, compresslevel=9)
    raw = buffer.getvalue()
    tmp = out_path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(raw)
    os.replace(tmp, out_path)
    return hashlib.sha256(raw).hexdigest()


def build_agent_jar(javac: str, asm_jar: str, out_path: str) -> str:
    """Compile and package the agent; return the jar's SHA-256.

    `asm_jar` must be the pinned ASM 9.6 (`ASM_JAR_SHA256`): the agent's
    bundled copy has to be the bytes the image's JaCoCo already carries, so
    that the jar's identity is a function of this repository's sources and
    one named coordinate.
    """
    actual = sha256_file(asm_jar)
    if actual != ASM_JAR_SHA256:
        raise _refuse(f"{asm_jar} is not {ASM_COORDINATE}: sha256 {actual}, "
                      f"expected {ASM_JAR_SHA256}")
    with tempfile.TemporaryDirectory(prefix="r2t-agent-build-") as tmp:
        classes = os.path.join(tmp, "classes")
        os.makedirs(classes)
        compile_agent(javac, asm_jar, classes)
        entries = _class_entries(classes) + _asm_entries(asm_jar)
    return write_deterministic_jar(entries, out_path)


# ------------------------------------------------------------------ the output

def _null_first(value: Optional[str]) -> tuple[int, str]:
    return (0, "") if value is None else (1, value)


def event_sort_key(event: dict) -> tuple:
    step = event.get("step")
    return (_null_first(event["callee_file"]),
            _null_first(None if event["callee_line"] is None
                        else str(event["callee_line"])),
            event["callee"], _null_first(event["caller_file"]),
            # Null before any index, as the other three components are.
            (step is not None, step or 0))


def canonical_events(events: list) -> list[dict]:
    """Validate section 2.5's shape and return the unique, sorted list.

    Both shapes are accepted: an event with `step` (what the agent writes
    now) and one without (what every Java gold shard collected before it
    carries).  Each event keeps the keys it arrived with, so validating a
    collected shard never rewrites it.
    """
    if not isinstance(events, list):
        raise _refuse(f"direct_calls must be a list, got {type(events).__name__}")
    seen: dict[tuple, dict] = {}
    for i, event in enumerate(events):
        fields = (EVENT_FIELDS if isinstance(event, dict) and "step" in event
                  else LEGACY_EVENT_FIELDS)
        if not isinstance(event, dict) or tuple(sorted(event)) != tuple(sorted(fields)):
            raise _refuse(f"event {i} does not carry exactly {list(EVENT_FIELDS)} "
                          f"(or {list(LEGACY_EVENT_FIELDS)}, collected before "
                          f"the step tag): {event!r}")
        step = event.get("step")
        if step is not None and (type(step) is not int or step < 0):
            raise _refuse(f"event {i}: step must be null or a 0-based step "
                          f"index, got {step!r}")
        if event["callee_line"] is not None:
            raise _refuse(f"event {i}: a Java event carries no callee_line, got "
                          f"{event['callee_line']!r}")
        if not isinstance(event["callee"], str) or not _CALLEE.match(event["callee"]):
            raise _refuse(f"event {i}: callee must be "
                          f"<binary class>.<name>:<descriptor>, got "
                          f"{event['callee']!r}")
        for key in ("callee_file", "caller_file"):
            value = event[key]
            if value is not None and (not isinstance(value, str)
                                      or value.startswith("/") or not value):
                raise _refuse(f"event {i}: {key} must be null or a "
                              f"repo-relative path, got {value!r}")
        seen[event_sort_key(event)] = {k: event[k] for k in fields}
    return [seen[k] for k in sorted(seen)]


def parse_direct_calls(text: str, *, label: str = OUTPUT_REL) -> list[dict]:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise _refuse(f"{label} is not JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema") != OUTPUT_SCHEMA:
        raise _refuse(f"{label} does not carry schema {OUTPUT_SCHEMA!r}: "
                      f"{str(doc)[:120]}")
    failures = doc.get("transform_failures")
    if failures:
        # A class the agent could not instrument is a class whose every
        # activation is missing from the set, with nothing in the record to
        # say so.  That is a harness fault, and the loud version is right.
        raise _refuse(f"the agent failed to instrument {len(failures)} "
                      f"class(es); the run's direct_calls would be silently "
                      f"incomplete: {failures[:5]}")
    if "events" not in doc:
        raise _refuse(f"{label} carries no events list")
    return canonical_events(doc["events"])


def read_direct_calls(path: str) -> Optional[list[dict]]:
    """The record's `direct_calls`: the canonical list, or None when no file exists.

    None rather than [] when the file is absent, for the reason `_coverage`
    returns None rather than an empty block: an agent that did not run and an
    agent that ran over a scenario touching no production method are
    different findings.  The agent writes the file from a shutdown hook even
    when it recorded nothing, so `[]` is what the second case reads.
    """
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return parse_direct_calls(fh.read(), label=path)


# ------------------------------------------------------------------- the index

def callee_key(binary_class: str, name: str, descriptor: str) -> str:
    """The join key, spelled as the agent spells `callee`."""
    return f"{binary_class}.{name}:{descriptor}"


def load_index(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or doc.get("schema") != INDEX_SCHEMA:
        raise _refuse(f"{path} does not carry schema {INDEX_SCHEMA!r}")
    return doc


def index_methods(doc: dict) -> dict[str, tuple[str, dict]]:
    """`callee key -> (file, method)` over an index document."""
    out: dict[str, tuple[str, dict]] = {}
    for rel, entry in doc["files"].items():
        for cls in entry["classes"]:
            for method in cls["methods"]:
                key = callee_key(cls["name"], method["name"], method["descriptor"])
                if key in out:
                    raise _refuse(f"index key {key} declared twice")
                out[key] = (rel, method)
    return out



def merge_module_indexes(documents: list[dict]) -> dict:
    """Join source-qualified module indexes without overwriting any authority."""
    files = {}
    classes = set()
    skipped_generated = {}
    carries_generated = False
    counts = {key: 0 for key in ("files", "classes", "methods", "public_methods")}
    if not documents:
        raise _refuse("no module production indexes")
    for document in documents:
        root = document.get("root")
        if document.get("schema") != INDEX_SCHEMA or document.get("language") != "java":
            raise _refuse("module index has an unknown schema or language")
        if not isinstance(root, str) or not root or root in (".", "..") \
                or os.path.isabs(root) or os.path.normpath(root) != root or root.startswith("../"):
            raise _refuse("module index has no normalized source root")
        if "skipped_generated" in document:
            carries_generated = True
            generated = document["skipped_generated"]
            if not isinstance(generated, dict) or not root.endswith("src/main/java"):
                raise _refuse("module generated exclusions lack their source root")
            generated_root = root[:-len("src/main/java")] + "target/generated-sources/annotations/"
            for binary, path in generated.items():
                if not isinstance(binary, str) or not binary \
                        or not isinstance(path, str) or not path.startswith(generated_root) \
                        or os.path.normpath(path) != path or not path.endswith(".java"):
                    raise _refuse("generated exclusion is outside its module annotation sources")
                if binary in classes:
                    raise _refuse(f"module indexes declare class {binary} twice")
                classes.add(binary)
                skipped_generated[binary] = path
        actual_counts = {key: 0 for key in counts}
        for path, entry in document["files"].items():
            if not path.startswith(root + "/") or os.path.normpath(path) != path:
                raise _refuse(f"module index file {path} is outside source root {root}")
            actual_counts["files"] += 1
            actual_counts["classes"] += len(entry["classes"])
            for cls in entry["classes"]:
                actual_counts["methods"] += len(cls["methods"])
                actual_counts["public_methods"] += sum(bool(method["public"]) for method in cls["methods"])
        if document.get("counts") != actual_counts:
            raise _refuse("module index counts differ from its complete contents")
        for path, entry in document["files"].items():
            if path in files:
                raise _refuse(f"module indexes declare source file {path} twice")
            files[path] = entry
            counts["files"] += 1
            for cls in entry["classes"]:
                if cls["name"] in classes:
                    raise _refuse(f"module indexes declare class {cls['name']} twice")
                classes.add(cls["name"])
                counts["classes"] += 1
                counts["methods"] += len(cls["methods"])
                counts["public_methods"] += sum(bool(method["public"])
                    for method in cls["methods"])
    merged = {"schema": INDEX_SCHEMA, "language": "java", "root": ".",
              "counts": counts, "files": dict(sorted(files.items()))}
    if carries_generated:
        merged["skipped_generated"] = dict(sorted(skipped_generated.items()))
    index_methods(merged)
    return merged


def jacoco_method_inventory(xml_text: str) -> set[str]:
    """JaCoCo's methods as callee keys, minus what the agent never reports.

    `<clinit>` is excluded by section 2.2; `lambda$...` bodies are synthetic
    methods JaCoCo deliberately keeps (its `SyntheticFilter` exempts them for
    line coverage) and the agent deliberately skips.
    """
    import xml.etree.ElementTree as ET

    keys: set[str] = set()
    for cls in ET.fromstring(xml_text).iter("class"):
        binary = (cls.get("name") or "").replace("/", ".")
        for method in cls.findall("method"):
            name = method.get("name") or ""
            if name == "<clinit>" or name.startswith("lambda$"):
                continue
            keys.add(callee_key(binary, name, method.get("desc") or ""))
    return keys


def cross_check_index(doc: dict, jacoco_xml: str) -> dict:
    """Section 2.4's cross-check: the index against JaCoCo's method inventory.

    `jacoco_only` is the finding that matters -- a method JaCoCo can see and
    the index does not know is a method the agent would report as unmapped.
    `index_only` lists methods JaCoCo dropped whole (its filters remove, for
    example, a private empty no-argument constructor) and is reported so a
    reader can confirm every one of them is a filter and not an omission.
    """
    index = set(index_methods(doc))
    jacoco = jacoco_method_inventory(jacoco_xml)
    generated = {key for key in jacoco
                 if key.split(":", 1)[0].rsplit(".", 1)[0]
                 in doc.get("skipped_generated", {})}
    comparable = jacoco - generated
    verdict = {"common": len(index & comparable),
               "index_only": sorted(index - comparable),
               "jacoco_only": sorted(comparable - index)}
    if "skipped_generated" in doc:
        verdict["excluded_generated"] = sorted(generated)
    return verdict


# ---------------------------------------------------------------- selftest

def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refused(fn):
        try:
            fn()
        except DirectCallsRefused as exc:
            return str(exc).startswith("REFUSED: ")
        return False

    from ..bench import repo as _repo

    # -- the constants the harness leans on
    check("the four agent sources exist where the build reads them",
          all(os.path.isfile(os.path.join(AGENT_DIR, rel)) for rel in AGENT_SOURCES))
    check("the fixture project exists, with production, glue and jar halves",
          all(os.path.isdir(os.path.join(FIXTURE_DIR, half))
              for half in ("main", "test", "third")))
    check("the output lies under the build root and under NO substrate root, "
          "so verify_substrate can never report it added",
          any(OUTPUT_REL.startswith(b + "/") for b in _repo.CUCUMBER_BUILD_ROOTS)
          and not any(OUTPUT_REL == r or OUTPUT_REL.startswith(r + "/")
                      for r in _repo.CUCUMBER_SUBSTRATE_ROOTS))
    check("the ASM pin is one lower-case sha256 and names the coordinate the "
          "image bakes", _SHA256.match(ASM_JAR_SHA256) is not None
          and ASM_JAR_REL.startswith("org/ow2/asm/asm/9.6/"))
    check("the manifest declares the premain class and the index main class, "
          "CRLF-terminated with the blank line the JAR spec requires",
          MANIFEST.startswith("Manifest-Version: 1.0\r\n")
          and f"Premain-Class: {PREMAIN_CLASS}\r\n" in MANIFEST
          and f"Main-Class: {INDEX_MAIN_CLASS}\r\n" in MANIFEST
          and MANIFEST.endswith("\r\n\r\n"))
    check("the -javaagent option is jar=output, one argument, no spaces",
          agent_option("/opt/r2t/agent.jar", "/work/target/r2t-direct-calls.json")
          == "-javaagent:/opt/r2t/agent.jar=/work/target/r2t-direct-calls.json")
    check("a relative or space-carrying path is refused: it rides in one "
          "unquoted JVM argument",
          refused(lambda: agent_option("agent.jar", "/work/out.json"))
          and refused(lambda: agent_option("/opt/a.jar", "/work/my out.json")))
    with tempfile.TemporaryDirectory() as tmp:
        jar = os.path.join(tmp, "agent.jar")
        with open(jar, "wb") as fh:
            fh.write(b"PK")
        link = os.path.join(tmp, "link.jar")
        os.symlink(jar, link)
        check("the jar mount is the read-only bind at the runtime path, in "
              "the shape worker.provision takes",
              agent_jar_mount(jar) == (jar, AGENT_JAR_RUNTIME + ":ro")
              and AGENT_JAR_RUNTIME.startswith("/opt/"))
        check("a symlink, a directory, a missing file, a relative path and a "
              "path carrying a mount separator are refused",
              refused(lambda: agent_jar_mount(link))
              and refused(lambda: agent_jar_mount(tmp))
              and refused(lambda: agent_jar_mount(os.path.join(tmp, "no.jar")))
              and refused(lambda: agent_jar_mount("agent.jar"))
              and refused(lambda: agent_jar_mount(os.path.join(tmp, "a:b.jar"))))

    # -- the output, section 2.5
    good = {"schema": OUTPUT_SCHEMA, "activations": 3, "transform_failures": [],
            "events": [
                {"callee_file": "src/main/java/fx/prod/Prod.java",
                 "callee_line": None, "callee": "fx.prod.Prod.b:()I",
                 "caller_file": "src/main/java/fx/prod/Prod.java", "step": 1},
                {"callee_file": "src/main/java/fx/prod/Prod.java",
                 "callee_line": None, "callee": "fx.prod.Prod.b:()I",
                 "caller_file": None, "step": 0},
                {"callee_file": "src/main/java/fx/prod/Prod.java",
                 "callee_line": None, "callee": "fx.prod.Prod.a:()I",
                 "caller_file": "src/test/java/fx/glue/Steps.java", "step": 2},
                {"callee_file": "src/main/java/fx/prod/Prod.java",
                 "callee_line": None, "callee": "fx.prod.Prod.a:()I",
                 "caller_file": "src/test/java/fx/glue/Steps.java", "step": 2},
                # The same call from another step is another event; the API
                # scorer collapses them again.
                {"callee_file": "src/main/java/fx/prod/Prod.java",
                 "callee_line": None, "callee": "fx.prod.Prod.a:()I",
                 "caller_file": "src/test/java/fx/glue/Steps.java", "step": None},
                {"callee_file": None, "callee_line": None,
                 "callee": "fx.prod.NoDebug.<init>:()V", "caller_file": None,
                 "step": None}]}
    events = parse_direct_calls(json.dumps(good))
    check("events are unique and sorted by (callee_file, callee_line, callee, "
          "caller_file, step) with null before any string and before any step",
          [(e["callee_file"], e["callee"], e["caller_file"], e["step"])
           for e in events] == [
              (None, "fx.prod.NoDebug.<init>:()V", None, None),
              ("src/main/java/fx/prod/Prod.java", "fx.prod.Prod.a:()I",
               "src/test/java/fx/glue/Steps.java", None),
              ("src/main/java/fx/prod/Prod.java", "fx.prod.Prod.a:()I",
               "src/test/java/fx/glue/Steps.java", 2),
              ("src/main/java/fx/prod/Prod.java", "fx.prod.Prod.b:()I", None, 0),
              ("src/main/java/fx/prod/Prod.java", "fx.prod.Prod.b:()I",
               "src/main/java/fx/prod/Prod.java", 1)], str(events))
    check("every event carries exactly the five keys, callee_line null",
          all(tuple(e) == EVENT_FIELDS and e["callee_line"] is None for e in events))
    # Java gold collected before the step tag has four-key events, and
    # `canonical_events` validates those shards as well as fresh agent
    # output: refusing them retroactively would discard collected evidence.
    legacy = [{k: v for k, v in event.items() if k != "step"}
              for event in good["events"]]
    legacy_events = canonical_events(legacy)
    check("a collected four-key shard still validates, keeps its own keys, "
          "and de-duplicates as it always did",
          len(legacy_events) == 4
          and all(tuple(e) == LEGACY_EVENT_FIELDS for e in legacy_events))
    check("an event carrying a negative or non-integer step is refused",
          refused(lambda: canonical_events([dict(good["events"][0], step=-1)]))
          and refused(lambda: canonical_events([dict(good["events"][0],
                                                     step="0")])))
    check("another schema is refused -- including the pre-step-tag recorder, "
          "whose dump a v2 harness must not read as complete",
          refused(lambda: parse_direct_calls(json.dumps(dict(good, schema="x/9"))))
          and refused(lambda: parse_direct_calls(json.dumps(
              dict(good, schema="r2t.java-direct-calls/1")))))
    check("a transform failure is a refusal, not a smaller set",
          refused(lambda: parse_direct_calls(json.dumps(dict(
              good, transform_failures=["com/x/Y: java.lang.RuntimeException"])))))
    check("an event with a missing key, an absolute path, or a callee_line is refused",
          refused(lambda: canonical_events([{"callee": "a.B.c:()V"}]))
          and refused(lambda: canonical_events([dict(good["events"][0], extra=1)]))
          and refused(lambda: canonical_events([dict(good["events"][0],
                                                     caller_file="/abs/X.java")]))
          and refused(lambda: canonical_events([dict(good["events"][0],
                                                     callee_line=12)])))
    check("a callee without a descriptor is refused -- the Java identity "
          "includes it (section 2.3)",
          refused(lambda: canonical_events([dict(good["events"][0],
                                                 callee="fx.prod.Prod.b")])))
    check("an empty events list reads as [] (collected, nothing called), and "
          "no file reads as None (not collected)",
          parse_direct_calls(json.dumps(dict(good, events=[]))) == []
          and read_direct_calls(os.path.join(tempfile.gettempdir(),
                                             "r2t-no-such-direct-calls.json")) is None)

    # -- the index and its cross-check
    index = {"schema": INDEX_SCHEMA, "language": "java", "root": "src/main/java",
             "files": {"src/main/java/fx/prod/Prod.java": {"classes": [
                 {"name": "fx.prod.Prod", "methods": [
                     {"name": "a", "descriptor": "()I", "public": True,
                      "static": True, "abstract": False, "start": 9, "end": 9},
                     {"name": "<init>", "descriptor": "()V", "public": False,
                      "static": False, "abstract": False, "start": 4, "end": 4}]},
                 {"name": "fx.prod.Prod$1", "methods": [
                     {"name": "run", "descriptor": "()V", "public": True,
                      "static": False, "abstract": False, "start": 20, "end": 21}]}]}}}
    jacoco = """<report name="fx"><package name="fx/prod">
      <class name="fx/prod/Prod" sourcefilename="Prod.java">
        <method name="&lt;clinit&gt;" desc="()V" line="3"/>
        <method name="a" desc="()I" line="9"/>
        <method name="lambda$a$0" desc="()I" line="9"/>
        <method name="b" desc="()I" line="12"/>
      </class>
      <class name="fx/prod/Prod$1" sourcefilename="Prod.java">
        <method name="run" desc="()V" line="20"/>
      </class></package></report>"""
    verdict = cross_check_index(index, jacoco)
    check("the cross-check ignores <clinit> and lambda bodies, keys nested "
          "classes by binary name, and reports each side's residue",
          verdict == {"common": 2, "index_only": ["fx.prod.Prod.<init>:()V"],
                      "jacoco_only": ["fx.prod.Prod.b:()I"]}, str(verdict))
    check("the index envelope is the one bench.metrics.load_prod_index reads",
          {m.name for ms in __import__(
              "r2t.bench.metrics", fromlist=["load_prod_index"]).load_prod_index(
              _write_temp(json.dumps(index))).values() for m in ms}
          == {"a", "<init>", "run"})
    check("a duplicate key in an index is refused",
          refused(lambda: index_methods({"files": {"f": {"classes": [
              {"name": "A", "methods": [{"name": "m", "descriptor": "()V"},
                                        {"name": "m", "descriptor": "()V"}]}]}}})))

    # -- the jar writer
    entries = [("fx/B.class", b"\xca\xfe\xba\xbe\x00\x00"),
               ("fx/A.class", b"\xca\xfe\xba\xbe\x00\x01")]
    with tempfile.TemporaryDirectory() as tmp:
        one = write_deterministic_jar(entries, os.path.join(tmp, "one.jar"))
        two = write_deterministic_jar(list(reversed(entries)),
                                      os.path.join(tmp, "two.jar"))
        with open(os.path.join(tmp, "one.jar"), "rb") as fh:
            raw = fh.read()
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            stamps = {info.date_time for info in zf.infolist()}
            manifest = zf.read("META-INF/MANIFEST.MF").decode("utf-8")
        check("the same entries in any order give byte-identical jars",
              one == two and one == hashlib.sha256(raw).hexdigest())
        check("the manifest is the first entry and the rest are sorted, all "
              "stamped at the zip epoch",
              names == ["META-INF/MANIFEST.MF", "fx/A.class", "fx/B.class"]
              and stamps == {_ZIP_TIME} and manifest == MANIFEST, str(names))
        check("a duplicate entry is refused rather than shadowed",
              refused(lambda: write_deterministic_jar(
                  entries + [("fx/A.class", b"")], os.path.join(tmp, "dup.jar"))))

    print("ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


def _write_temp(text: str) -> str:
    fd, path = tempfile.mkstemp(prefix="r2t-direct-calls-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


if __name__ == "__main__":
    raise SystemExit(selftest())
