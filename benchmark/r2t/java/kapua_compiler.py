"""Read-only authentication of Kapua's development compiler capture.

The caller supplies the reviewed staging receipt SHA. Native evidence, when
provided, must already have passed ``kapua_runtime.load_capture``. This loader
adds compiler/source joins; it does not grant release admission or run tools.
Original raw-log and response-file whitespace hashes were not recorded. Raw
argument/project facts are reparsed against the bound capture, and retained
copies must agree; this does not retroactively authenticate original log bytes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import tarfile
import xml.etree.ElementTree as ET

from . import kapua as K
from .kapua_runtime import _sha256_stream
from ..core.boundary import PRODUCTION
from ..toolkit import mutation_java as M

BUNDLE = "var/bench_java_analysis/m2/"
MAVEN_FLAGS = ["mvn", "-o", "-B", "-Pconsole", "-Dmaven.repo.local=/opt/m2",
               "-DskipTests", "-Dcheckstyle.skip=true", "-Dmaven.buildNumber.skip=true",
               "-Dgwt.compiler.skip=true", "-Dgwt.jvm=/opt/java/openjdk8/bin/java"]


def require(ok, reason):
    if not ok:
        raise ValueError("REFUSED: Kapua compiler " + reason)


class Files:
    """Hash each retained regular file once during one admission call."""
    def __init__(self):
        self.hashes = {}

    def path(self, path):
        path = Path(path).absolute()
        require(path.resolve() == path and path.is_file(),
                "missing, symlinked or nonregular input: " + str(path))
        return path

    def sha(self, path):
        path = self.path(path)
        if path not in self.hashes:
            with path.open("rb") as handle:
                self.hashes[path] = _sha256_stream(handle)
        return self.hashes[path]

    def check(self, path, digest):
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                and self.sha(path) == digest, "input hash differs: " + str(path))
        return self.path(path)

    def document(self, path, digest=None):
        path = self.check(path, digest) if digest is not None else self.path(path)
        return json.loads(path.read_bytes())


def relative(value):
    require(isinstance(value, str) and value and not value.startswith("/")
            and str(PurePosixPath(value)) == value
            and ".." not in PurePosixPath(value).parts, "nonrelative input path")
    return value


def tree_hashes(root, files):
    root = Path(root)
    require(root.is_dir() and root.resolve() == root.absolute(), "missing owner tree")
    return {str(path.relative_to(root)): files.sha(path)
            for path in sorted(root.rglob("*")) if path.is_file() or path.is_symlink()}


def source_census(source_root, boundary, files):
    require(boundary.project == "kapua", "wrong source boundary project")
    root = Path(source_root)
    inventory = {}
    for path in root.rglob("*.java"):
        rel = str(path.relative_to(root))
        if "/src/main/java/" in rel and not {"target", ".git"}.intersection(path.relative_to(root).parts) \
                and boundary.classify(rel) == PRODUCTION:
            inventory[rel] = files.sha(path)
    roots = {name.split("/src/main/java/", 1)[0] + "/src/main/java" for name in inventory}
    require(len(inventory) == 3686 and len(roots) == 138, "production census is not 138 roots/3686 files")
    return inventory


def option(argv, *names):
    result = []
    for index, value in enumerate(argv):
        for name in names:
            if value == name:
                require(index + 1 < len(argv), "compiler option has no value")
                result.append(argv[index + 1])
            elif value.startswith(name + "="):
                result.append(value[len(name) + 1:])
    return result


def ordered_path(value):
    """The observed javac spelling permits one trailing path separator."""
    parts = value.split(":")
    if parts[-1:] == [""]:
        parts.pop()
    require(bool(parts) and all(parts), "empty compiler path element")
    return parts


def docker_command(phase):
    argv = phase["argv"]
    require(argv[:1] and argv.count("--host") == 1, "phase lacks one Docker authority endpoint")
    return argv[argv.index("--host") + 2:]


def phases(document, root, files, authority=None):
    rows = document["phases"]
    require(rows and len({p["name"] for p in rows}) == len(rows), "phase names repeat")
    authority = authority or rows[0]["authority_reference"]
    for row in rows:
        require(row["returncode"] == 0 and row.get("finished_at")
                and not row.get("timed_out") and row["authority_reference"] == authority,
                "phase failed, unfinished or changed authority: " + row["name"])
        if "log" in row:
            require(Path(row["log"]) == Path(root) / relative(row["name"]) / "output.log",
                    "phase log belongs to another capture")
            files.path(row["log"])
            require(files.document(Path(row["log"]).with_name("argv.json")) == row["argv"],
                    "retained phase argv differs")
    return {p["name"]: p for p in rows}, authority


def verify_worker_sources(repo_root, original, files):
    for rel, digest in original.items():
        files.check(Path(repo_root) / relative(rel), digest)


def native_join(native, capture, authority):
    """``native`` has already passed the native loader, including its files."""
    require(native["build"]["image_id"] == capture["image_id"]
            and native["build"]["receipt"]["sha256"] == capture["build_receipt_sha256"]
            and native["source"]["commit"] == capture["source_commit"]
            and native["source"]["archive_sha256"] == capture["source_archive_sha256"]
            and native["authority"]["reference"] == authority,
            "native/compiler build, image, source or authority differs")


def compiler_binding(row, raw_root, native_root, toolchains, files):
    require(len(row["javac_invocations"]) == 1, "owning compiler invocation is not unique")
    invocation = row["javac_invocations"][0]
    directory = relative(invocation["directory"])
    prefix = "target/full-production-capture/"
    require(directory.startswith(prefix), "compiler raw directory differs")
    raw = raw_root / directory[len(prefix):]
    for path in raw.iterdir():
        files.check(native_root / directory / path.name, files.sha(path))
    argv = [value.decode() for value in (raw / "argv.nul").read_bytes().split(b"\0") if value]
    require(argv == invocation["argv"], "raw compiler argv differs")
    expanded, argfile = [], 0
    for value in argv:
        if value.startswith("@"):
            expanded.extend(shlex.split((raw / f"argfile-{argfile}").read_text()))
            argfile += 1
        else:
            expanded.append(value)
    require(expanded == invocation["expanded_argv"], "raw compiler response arguments differ")
    require(int((raw / "exit-code.txt").read_text()) == invocation["returncode"] == 0,
            "actual javac failed")
    executable = (raw / "executable.txt").read_text().strip()
    java_home = str(PurePosixPath(executable).parent.parent)
    require(java_home in toolchains and executable == java_home + "/bin/javac"
            and executable == invocation["real_javac"], "compiler executable differs")
    toolchain = toolchains[java_home]
    require((raw / "version.txt").read_text().strip() == invocation["javac_version"]
            == toolchain["parser"].split(" [", 1)[0], "actual compiler version differs")
    digest, recorded_executable = (raw / "executable.sha256").read_text().split()
    require(digest == toolchain["compiler_executable_sha256"] and recorded_executable == executable,
            "actual compiler bytes differ")
    owner = "/work/" + row["module"] + "/target/classes"
    require(option(expanded, "-d") == [owner], "compiler output is not its owner")
    classpath = option(expanded, "-classpath", "-cp", "--class-path")
    require(len(classpath) == 1 and ordered_path(classpath[0]) == row["compile_classpath"],
            "actual ordered compiler classpath differs")
    module_options = option(expanded, "--module-path", "-p")
    require(len(module_options) <= 1 and (ordered_path(module_options[0]) if module_options else [])
            == row["module_path"], "actual compiler module path differs")
    require(option(expanded, "-encoding") == ["UTF-8"], "compiler encoding is not explicit UTF-8")
    source, target, release = option(expanded, "-source"), option(expanded, "-target"), option(expanded, "--release")
    require((source, target, release) == (invocation["source"], invocation["target"], invocation["release"])
            and ((len(source) == len(target) == 1 and not release)
                 or (not source and not target and len(release) == 1)), "compiler language options differ")
    cwd = (raw / "cwd.txt").read_text().strip()
    require(cwd == "/work/" + row["module"], "unexpected compiler working directory")
    inputs = [posixpath.normpath(value if value.startswith("/") else posixpath.join(cwd, value))
              for value in expanded if not value.startswith("-") and value.endswith(".java")]
    original = {"/work/" + rel for rel in row["source_files"]}
    generated = "/work/" + row["module"] + "/target/generated-sources/"
    require(inputs == invocation["original_and_generated_source_inputs"]
            and {v for v in inputs if not v.startswith(generated)} == original,
            "actual original compiler source participation differs")
    for value in inputs:
        require(value in original or value.startswith(generated), "foreign generated source input")
        files.path(native_root / value.removeprefix("/work/"))
    return {**toolchain, "encoding": "UTF-8", "source": source[0] if source else None,
            "target": target[0] if target else None, "release": release[0] if release else None}


def load_module_authority(staging_root, *, binding_path, expected_receipt_sha256,
                          source_root, boundary, native_capture=None, repo_roots=()):
    """Authenticate the full compiler context; never modify supplied roots.

    ``native_capture`` is an optional *already authenticated* return value of
    ``kapua_runtime.load_capture``. Its raw artifacts are deliberately not read
    twice here. The caller owns release/admission decisions.
    """
    files = Files()
    root, source = Path(staging_root).absolute(), Path(source_root).absolute()
    require(root.resolve() == root and source.resolve() == source, "noncanonical source/staging root")
    receipt = files.document(root / "receipt.json", expected_receipt_sha256)
    require(receipt["state"] == "development_module_authority_staged_not_enumerated"
            and receipt["source_commit"] == K.SOURCE_COMMIT, "staging state/source differs")
    binding_path = files.check(binding_path, receipt["binding_sha256"])
    binding = files.document(binding_path)
    for path, digest in binding["inputs"].items():
        files.check(path, digest)
    for name, digest in binding["preparation_files"].items():
        files.check(binding_path.parent / relative(name), digest)
    workspace = root / "workspace"
    recipe = files.document(root / "module-analysis-recipe.json", receipt["authority_sha256"])
    M.validate_analysis_recipe(recipe, str(workspace))
    require(recipe["digest"] == receipt["authority_digest"], "staged composite digest differs")
    original = source_census(source, boundary, files)
    captured_root = Path(binding["capture"])
    capture = files.document(captured_root / "receipt.json", receipt["capture_receipt_sha256"])
    require(capture["state"] == "full_production_capture_raw_complete_pending_authority_authentication"
            and capture["finished_at"] and capture["cleanup_returncode"] == 0
            and capture["source_commit"] == K.SOURCE_COMMIT
            and capture["image_id"] == receipt["image_id"], "compiler capture state/image differs")
    raw_rows = files.document(captured_root / "module-captures.json", capture["module_captures_sha256"])
    require(len(raw_rows) == len(recipe["modules"]) == capture["module_count"] == receipt["module_count"] == 138,
            "compiler module census differs")
    require(sum(len(r["source_files"]) for r in raw_rows) == capture["source_count"]
            == receipt["source_count"] == 3686, "compiler source count differs")
    captured_original = {rel: digest for row in raw_rows for rel, digest in row["original_source_sha256"].items()}
    require(captured_original == original, "original production membership/bytes differ")
    archive = files.check(binding["source_archive"], capture["source_archive_sha256"])
    with tarfile.open(archive) as stream:
        archived = {}
        for member in stream:
            if member.name in original or member.name.endswith("pom.xml"):
                require(member.isfile() and member.name not in archived, "original archive member differs")
                with stream.extractfile(member) as handle:
                    archived[member.name] = _sha256_stream(handle)
    require({name: archived.get(name) for name in original} == original, "pinned archive production bytes differ")
    for name, digest in archived.items():
        files.check(source / relative(name), digest)
        files.check(workspace / relative(name), digest)
    build_path = files.check(capture["build_receipt"], capture["build_receipt_sha256"])
    build = files.document(build_path)
    require(build["state"] == "expanded_image_built_not_captured" and build["finished_at"]
            and all(build[key] == capture[key] for key in
                    ("image_id", "source_commit", "source_archive_sha256", "inputs_sha256", "authority_checkout")),
            "build/compiler capture identity differs")
    capture_phases, authority = phases(capture, captured_root, files)
    build_phases, _ = phases(build, build_path.parent, files, authority)
    inspected = files.document(build_phases["inspect"]["log"])
    require(len(inspected) == 1 and inspected[0]["Id"] == capture["image_id"]
            and inspected[0]["Os"] == "linux" and inspected[0]["Architecture"] == "amd64",
            "actual image inspection differs")
    authority_doc = files.document(authority["path"], authority["file_sha256"])
    require(authority_doc["digest"] == authority["digest"], "capture authority document differs")
    create = docker_command(capture_phases["create"])
    require(create[:3] == ["run", "--detach", "--name"], "compiler container command differs")
    require(create[4:] == ["--network", "none", "--hostname", "kapua-worker", "--add-host",
            "kapua-worker:127.0.0.1", "--mount", f"type=bind,source={captured_root / 'workspace'},target=/work",
            "--workdir", "/work", capture["image_id"], "tail", "-f", "/dev/null"]
            and Path(capture_phases["create"]["log"]).read_text().strip() == capture["container_id"]
            and docker_command(capture_phases["cleanup"]) == ["rm", "-f", capture["container_id"]],
            "compiler source/image/network/cleanup binding differs")
    expected_phases = {"create", "cache-hygiene", "toolchains", "external-cache-manifest",
                       "offline-full-install", "export-compile-inputs", "cleanup"}
    expected_phases.update(f"module-{index:03d}-{suffix}" for index in range(len(raw_rows))
                           for suffix in ("clear", "compile"))
    require(set(capture_phases) == expected_phases, "capture phase membership differs")
    prefix = ["exec", "--workdir", "/work", capture["container_id"]]
    require(docker_command(capture_phases["cache-hygiene"]) == prefix +
            ["test", "!", "-e", "/opt/m2/org/eclipse/kapua"], "pre-install cache hygiene differs")
    install = docker_command(capture_phases["offline-full-install"])
    expected = prefix + MAVEN_FLAGS + ["install", "-pl"]
    require(install[:len(expected)] == expected and len(install) == len(expected) + 2
            and install[-1] == "-am" and {row["module"] for row in raw_rows}
            <= set(install[-2].split(",")), "complete offline owning-module install differs")
    observation_path = files.check(binding["toolchain_receipt"], receipt["toolchain_receipt_sha256"])
    observation = files.document(observation_path)
    require(observation["state"] == "image_toolchain_observations_passed"
            and observation["capture_receipt_sha256"] == files.sha(captured_root / "receipt.json")
            and observation["build_receipt_sha256"] == capture["build_receipt_sha256"]
            and observation["image_id"] == capture["image_id"]
            and observation["source_commit"] == K.SOURCE_COMMIT, "toolchain observation identity differs")
    tool_phases, _ = phases(observation, observation_path.parent, files, authority)
    toolchains = {}
    for tool in observation["toolchains"]:
        selector = Path(tool["java_home"]).name
        require(selector in {"openjdk", "openjdk8"} and tool["java_home"] not in toolchains,
                "unexpected/repeated toolchain")
        raw = "\n".join(files.path(observation_path.parent / selector / name).read_text()
                        for name in ("stdout.log", "stderr.log"))
        require(tool == {"java_home": "/opt/java/" + selector, "parser": M.parse_toolchain_probe(raw),
                         **M.parse_toolchain_hash_probe(raw)}, "raw toolchain observation differs")
        command = docker_command(tool_phases[selector])
        require(command[:4] == ["run", "--pull", "never", "--name"]
                and command[5:-2] == ["--network", "none", "--read-only", "--workdir", "/work",
                                     "--entrypoint", "sh", capture["image_id"]]
                and command[-2] == "-c", "toolchain probe uses another image/network")
        toolchains[tool["java_home"]] = tool
    require(set(toolchains) == {"/opt/java/openjdk", "/opt/java/openjdk8"}, "missing toolchain")
    artifact_hashes = {}
    for line in files.path(captured_root / "capture/compile-inputs.sha256").read_text().splitlines():
        digest, origin = line.split(None, 1)
        origin = origin.strip()
        require(origin.startswith("/opt/m2/") and origin not in artifact_hashes, "repeated/foreign artifact origin")
        artifact_hashes[origin] = digest
    with tarfile.open(files.check(captured_root / "capture/compile-inputs.tar", capture["capture_archive_sha256"])) as stream:
        seen = set()
        for member in stream:
            origin = "/opt/m2/" + relative(member.name)
            require(member.isfile() and origin in artifact_hashes and origin not in seen, "compiler archive membership differs")
            with stream.extractfile(member) as handle:
                require(_sha256_stream(handle) == artifact_hashes[origin], "compiler archive bytes differ")
            files.check(workspace / BUNDLE / member.name, artifact_hashes[origin])
            seen.add(origin)
    require(seen == set(artifact_hashes) and len(seen) == capture["compile_input_count"]
            == receipt["artifact_count"], "compiler artifact set differs")
    by_module = {row["module"]: row for row in recipe["modules"]}
    require(len(by_module) == len(raw_rows) and {row["module"] for row in raw_rows} == set(by_module), "compiler owners differ")
    origins = files.document(root / "origin-map.json")
    require([row["module"] for row in origins] == [row["module"] for row in recipe["modules"]], "origin-map row order differs")
    origin_map = {row["module"]: row for row in origins}
    participation = files.document(root / "source-class-participation.json",
            binding["preparation_files"]["capture-consistency.json"])
    require(participation["capture_receipt_sha256"] == files.sha(captured_root / "receipt.json")
            and participation["module_captures_sha256"] == capture["module_captures_sha256"],
            "source/class participation belongs to another capture")
    evidence = {row["module"]: row for row in participation["modules"]}
    require(len(evidence) == len(participation["modules"]) and set(evidence) == set(by_module),
            "source/class participation owners differ")
    used = set()
    for index, row in enumerate(raw_rows):
        module = relative(row["module"])
        owned = by_module[module]
        require(row["source_root"] == module + "/src/main/java"
                and owned["source_root"] == row["source_root"] and owned["source_files"] == row["source_files"]
                and set(row["original_source_sha256"]) == set(row["source_files"]), "owning source membership differs")
        files.check(captured_root / "workspace" / module / "pom.xml", row["pom_sha256"])
        require(row["pom_sha256"] == archived[module + "/pom.xml"], "owning POM differs from original archive")
        raw_xml = files.path(captured_root / "workspace" / relative(row["raw_project_xml"]))
        files.check(captured_root / "capture" / f"{index:03d}" / "project.xml", files.sha(raw_xml))
        xml = ET.fromstring(raw_xml.read_bytes())
        require(xml.findtext("basedir") == "/work/" + module and xml.findtext("outputDirectory") == "/work/" + module + "/target/classes"
                and [v.text for v in xml.findall("compileClasspathElements/entry")] == row["compile_classpath"]
                and {k: xml.findtext(k) for k in row["effective"]} == row["effective"], "raw Maven owning context differs")
        phase = capture_phases[f"module-{index:03d}-compile"]
        runtime = f"/work/target/full-production-capture/{index:03d}"
        require(docker_command(phase) == ["exec", "--workdir", "/work", "--env", "R2T_CAPTURE_DIR=" + runtime,
                capture["container_id"], *MAVEN_FLAGS, "-Dmaven.ext.class.path=/opt/r2t/maven-capture.jar",
                "-Dr2t.capture.directory=" + runtime, "compile", "-pl", module]
                and docker_command(capture_phases[f"module-{index:03d}-clear"]) == ["exec", "--workdir", "/work",
                    capture["container_id"], "rm", "-rf", "--", "/work/" + module + "/target"], "actual owning compile/clear command differs")
        require("BUILD SUCCESS" in Path(phase["log"]).read_text(), "owning Maven success log is absent")
        compiler = compiler_binding(row, captured_root / "capture", captured_root / "workspace", toolchains, files)
        require(owned["compiler"] == compiler, "recipe compiler differs from actual javac")
        owner = module + "/target/classes"
        outputs = {relative(item["path"]): item["sha256"] for item in row["output_tree_files"]}
        require(len(outputs) == len(row["output_tree_files"]) and outputs
                and tree_hashes(captured_root / "workspace" / owner, files) == outputs
                and tree_hashes(workspace / owner, files) == outputs, "owning output bytes/membership differ")
        generated = {}
        for item in evidence[module]["generated_sources"]:
            rel = relative(item["path"])
            require(rel.startswith(module + "/target/generated-sources/") and rel not in generated,
                    "generated source ownership differs")
            files.check(captured_root / "workspace" / rel, item["sha256"])
            files.check(workspace / rel, item["sha256"])
            generated[rel] = item["sha256"]
        emitted = evidence[module]["classes"]
        require(len({item["output"] for item in emitted}) == len(emitted)
                and {item["output"] for item in emitted}
                == {owner + "/" + rel for rel in outputs if rel.endswith(".class")},
                "source/class participation output membership differs")
        for item in emitted:
            rel = relative(item["output"])
            require(item["sha256"] == outputs[rel.removeprefix(owner + "/")]
                    and len(item["source_candidates"]) == 1
                    and ((item["source_kind"] == "original" and item["source_candidates"][0] in row["source_files"])
                         or (item["source_kind"] == "generated" and item["source_candidates"][0] in generated)),
                    "original/generated class ownership differs")
        for key, actual in (("classpath", row["compile_classpath"]), ("module_path", row["module_path"])):
            expected = []
            for value in actual:
                if value == "/work/" + owner:
                    expected.append(owner)
                else:
                    require(value in artifact_hashes, "uncaptured compiler dependency")
                    used.add(value)
                    expected.append(BUNDLE + value.removeprefix("/opt/m2/"))
            require(expected == [entry["path"] for entry in owned["recipe"][key]]
                    and origin_map[module][key] == [list(pair) for pair in zip(actual, expected)], "per-module ordered recipe origins differ")
        verify_worker_sources(captured_root / "workspace", row["original_source_sha256"], files)
    require(used == set(artifact_hashes), "compiler export is not exact dependency union")
    if native_capture is not None:
        native_join(native_capture, capture, authority)
    for repo_root in repo_roots:
        verify_worker_sources(repo_root, original, files)
    return {"root": str(root), "workspace": str(workspace), "analysis_recipe": recipe,
            "image_id": capture["image_id"]}


def selftest():
    """Compact source-only refusal checks; the real 138-root capture is external."""
    import copy
    import tempfile
    from ..core import boundary as B

    checks = []

    def check(name, operation, refused=False):
        try:
            result = operation()
            ok = not refused and result is not False
        except ValueError:
            ok = refused
        checks.append(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")

    with tempfile.TemporaryDirectory(prefix="kapua-compiler-") as scratch:
        root = Path(scratch)
        source = root / "subject/a/src/main/java/A.java"
        source.parent.mkdir(parents=True)
        source.write_text("class A {}\n")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        original = {"a/src/main/java/A.java": digest}
        check("worker original bytes accepted without writes", lambda:
              verify_worker_sources(root / "subject", original, Files()))
        source.write_text("class A { int changed; }\n")
        check("changed worker production source refused", lambda:
              verify_worker_sources(root / "subject", original, Files()), True)
        check("wrong reviewed receipt hash refused", lambda: Files().check(source, "0" * 64), True)
        check("non-Kapua boundary refused", lambda:
              source_census(root / "subject", B.Boundary(1, "other", str(root)), Files()), True)
        check("partial production census refused", lambda:
              source_census(root / "subject", B.Boundary(1, "kapua", str(root)), Files()), True)
        check("one trailing classpath separator accepted", lambda:
              ordered_path("/work/a/target/classes:/opt/m2/dep.jar:")
              == ["/work/a/target/classes", "/opt/m2/dep.jar"])
        check("interior empty classpath refused", lambda: ordered_path("a::b:"), True)
        capture = {"image_id": "sha256:image", "build_receipt_sha256": "build",
                   "source_commit": K.SOURCE_COMMIT, "source_archive_sha256": "archive"}
        authority = {"digest": "authority"}
        native = {"build": {"image_id": capture["image_id"], "receipt": {"sha256": "build"}},
                  "source": {"commit": K.SOURCE_COMMIT, "archive_sha256": "archive"},
                  "authority": {"reference": authority}}
        check("authenticated native/compiler identity join", lambda: native_join(native, capture, authority))
        for field in capture:
            wrong = dict(capture, **{field: "other"})
            check("different native " + field + " refused", lambda wrong=wrong:
                  native_join(native, wrong, authority), True)
        check("different native daemon authority refused", lambda:
              native_join(native, capture, {"digest": "other"}), True)
        raw = root / "capture/000/javac.fixture"
        mirrored = root / "native/target/full-production-capture/000/javac.fixture"
        raw.mkdir(parents=True)
        mirrored.mkdir(parents=True)
        java_home = "/opt/java/openjdk"
        compiler_sha = "1" * 64
        tool = {"java_home": java_home, "parser": "javac 17.0.17 [Fixture; runtime=17.0.17]",
                "runtime_executable_sha256": "2" * 64, "compiler_executable_sha256": compiler_sha,
                "tools_jar_sha256": None}
        args = ["-d", "/work/a/target/classes", "-classpath", "/work/a/target/classes:/opt/m2/dep.jar:",
                "-encoding", "UTF-8", "-source", "1.8", "-target", "1.8", "/work/a/src/main/java/A.java"]
        payloads = {"argv.nul": b"@/work/arguments\0", "argfile-0": shlex.join(args).encode(),
                    "exit-code.txt": b"0\n", "cwd.txt": b"/work/a\n",
                    "executable.txt": (java_home + "/bin/javac\n").encode(),
                    "version.txt": b"javac 17.0.17\n",
                    "executable.sha256": (compiler_sha + "  " + java_home + "/bin/javac\n").encode()}
        for name, value in payloads.items():
            (raw / name).write_bytes(value)
            (mirrored / name).write_bytes(value)
        path = root / "native/a/src/main/java/A.java"
        path.parent.mkdir(parents=True)
        path.write_text("class A {}")
        invocation = {"directory": "target/full-production-capture/000/javac.fixture",
                      "argv": ["@/work/arguments"], "expanded_argv": args,
                      "original_and_generated_source_inputs": ["/work/a/src/main/java/A.java"],
                      "returncode": 0, "real_javac": java_home + "/bin/javac",
                      "javac_version": "javac 17.0.17", "source": ["1.8"], "target": ["1.8"], "release": []}
        row = {"module": "a", "source_files": ["a/src/main/java/A.java"],
               "compile_classpath": ["/work/a/target/classes", "/opt/m2/dep.jar"],
               "module_path": [], "javac_invocations": [invocation]}
        def verify(value):
            return compiler_binding(value, root / "capture", root / "native", {java_home: tool}, Files())
        check("raw response/source/executable joins accepted", lambda: verify(row)["source"] == "1.8")
        changed = copy.deepcopy(row)
        changed["compile_classpath"].reverse()
        check("reordered owning compiler classpath refused", lambda: verify(changed), True)
        changed = copy.deepcopy(row)
        changed["source_files"].append("a/src/main/java/Absent.java")
        check("uncompiled original source refused", lambda: verify(changed), True)
        changed = copy.deepcopy(row)
        changed["javac_invocations"][0]["target"] = ["11"]
        check("changed captured language level refused", lambda: verify(changed), True)
        (raw / "exit-code.txt").write_text("1\n")
        (mirrored / "exit-code.txt").write_text("1\n")
        check("actual compiler failure refused", lambda: verify(row), True)
    return 0 if all(checks) else 1
