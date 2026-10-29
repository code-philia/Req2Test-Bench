"""Kapua native runtime evidence, separate from the legacy Java image chain.

These are development capture checks, not release admission. Every claim is
recomputed from original source and retained native artifacts; live consumers
also bind the captured image and daemon to their selected worker.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from . import kapua as K

SCHEMA = "r2t.kapua-runtime-capture/1"


def require(ok, reason):
    if not ok:
        raise ValueError("REFUSED: Kapua runtime " + reason)


def source_inventory(root):
    root = Path(root)
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file() and not {"target", ".git"}.intersection(
                path.relative_to(root).parts)}


def source_census(root):
    native = K.feature_items(str(root), scaffolding=True)
    candidate_ids = {row[0] for row in K.feature_items(str(root))}
    expected = [dict(feature=i.removeprefix("kapua/").rsplit(":", 1)[0],
                     line=scenario.line, name=scenario.title,
                     step_count=len(scenario.steps),
                     setup_or_teardown=i not in candidate_ids)
                for i, _feature, scenario in native]
    partition = {
        "native_pickle_ids": sorted(i.removeprefix("kapua/") for i, _, _ in native),
        "candidate_ids": sorted(candidate_ids),
        "scaffold_ids": sorted(i for i, _, _ in native if i not in candidate_ids),
    }
    return expected, partition


def compare_native(document, suite, expected):
    actual, statuses, features = Counter(), Counter(), set()
    for feature in document:
        uri = feature["uri"]
        if uri.startswith("classpath:"):
            uri = suite.module + "/src/test/resources/" + uri[len("classpath:"):].lstrip("/")
        elif uri.startswith("file:/work/"):
            uri = uri[len("file:/work/"):]
        elif uri.startswith("/work/"):
            uri = uri[len("/work/"):]
        features.add(uri)
        for case in feature.get("elements", []):
            if case.get("type") != "scenario":
                continue
            actual[(uri, case["line"], case["name"], len(case.get("steps", [])))] += 1
            statuses.update(step.get("result", {}).get("status", "<missing>")
                            for step in case.get("steps", []))
    wanted = Counter((row["feature"], row["line"], row["name"], row["step_count"])
                     for row in expected)
    require(bool(wanted) and actual == wanted, "native source scenario identities differ")
    require(features == set(suite.features), "native feature membership differs")
    return {"scenario_count": sum(actual.values()),
            "step_status_counts": dict(statuses),
            "pickle_ids": sorted(f"{uri}:{line}" for uri, line, _, _ in actual.elements())}


def selected_xml(raw, target, count):
    tree = ET.fromstring(raw)
    require(tree.tag == "testsuite" and tree.get("name") == target,
            "wrong selected Surefire runner")
    require(int(tree.get("tests", "0")) == count
            and len(tree.findall("testcase")) == count,
            "Surefire does not contain exact native census")
    props = {}
    for node in tree.iter("property"):
        key = node.get("name")
        if key in {"java.class.path", "surefire.test.class.path"}:
            require(key not in props, "repeated Surefire classpath property")
            props[key] = node.get("value")
    cp = props.get("java.class.path")
    require(bool(cp) and cp == props.get("surefire.test.class.path"),
            "actual JVM/test classpaths disagree")
    return cp, dict(tree.attrib)


def triplet_agreement(rows):
    require(len(rows) == 3, "missing native triplet")
    ordinary, dry, stripped = rows
    require([row["stripped"] for row in rows] == [False, False, True]
            and [row["dry_run"] for row in rows] == [False, True, True],
            "triplet modes differ")
    def identity(entry):
        return (entry["path"], entry["kind"], entry["origin"],
                entry.get("source_root"), entry.get("role"))
    baseline = ordinary["classpath"]
    require(all([identity(entry) for entry in row["classpath"]]
                == [identity(entry) for entry in baseline] for row in rows),
            "ordered module/classpath origins differ")
    for index, entry in enumerate(baseline):
        if entry["kind"] != "jar":
            continue
        require(entry["sha256"] == dry["classpath"][index]["sha256"],
                "pinned ordinary/dry JAR bytes changed")
        if entry["origin"] == "external":
            require(entry["sha256"] == stripped["classpath"][index]["sha256"],
                    "external JAR bytes changed across source states")
    return {"target": ordinary["target"], "runs": [row["name"] for row in rows],
            "ordered_origins": [dict(path=e["path"], kind=e["kind"], origin=e["origin"],
                                     source_root=e.get("source_root"), role=e.get("role"))
                                for e in baseline],
            "cross_state_first_party_hash_rule":
                "record each actual archive; equality is not required"}


def _sha256_stream(handle):
    """Hash retained file and archive streams on supported Python versions."""
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1 << 20), b""):
        digest.update(chunk)
    return digest.hexdigest()


class CaptureFiles:
    """Authenticate retained files once, including large executable archives."""
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.checked = {}

    def path(self, ref):
        require(isinstance(ref, dict) and set(ref) == {"path", "bytes", "sha256"},
                "malformed artifact reference")
        rel = ref["path"]
        require(isinstance(rel, str) and rel and not Path(rel).is_absolute()
                and ".." not in Path(rel).parts, "nonrelative artifact reference")
        path = self.root / rel
        require(path.is_file() and not path.is_symlink()
                and path.resolve().is_relative_to(self.root), "missing or foreign artifact")
        require(rel not in self.checked or self.checked[rel] == ref,
                "conflicting artifact references")
        if rel not in self.checked:
            with path.open("rb") as handle:
                digest = _sha256_stream(handle)
            require(path.stat().st_size == ref["bytes"] and digest == ref["sha256"],
                    "artifact bytes differ: " + rel)
            self.checked[rel] = dict(ref)
        return path

    def document(self, ref):
        return json.loads(self.path(ref).read_bytes())

    def verify_refs(self, value):
        if isinstance(value, dict):
            if set(value) == {"path", "bytes", "sha256"}:
                self.path(value)
            else:
                for child in value.values():
                    self.verify_refs(child)
        elif isinstance(value, list):
            for child in value:
                self.verify_refs(child)


def validate_live_runtime(capture, runtime):
    selected = runtime.get("selected") or {}
    live = selected.get("runtime") or {}
    daemon = (selected.get("authority") or {}).get("daemon") or {}
    require(live.get("container_image_digest") == capture["build"]["image_id"]
            and live.get("docker_execution_authority") == capture["authority"]["reference"]
            and daemon.get("fingerprint_sha256") == capture["authority"]["daemon_fingerprint"],
            "live worker differs from captured image or daemon")



def phase_command(phase):
    argv = phase["argv"]
    require(argv[:1] and argv.count("--host") == 1, "Docker phase has no exact authority prefix")
    return argv[argv.index("--host") + 2:]


def require_exec(phase, workspace, command=None):
    actual = phase_command(phase)
    prefix = ["exec", "--workdir", "/work", workspace["container_id"]]
    require(actual[:4] == prefix and (command is None or actual[4:] == command),
            "Docker exec is not bound to the selected source workspace")


def _captured_installed_sources(installed):
    """Admit the recorded runner-only capture and the later per-step capture."""
    from ..stacks import cucumber as C
    runners = [variant.runner_rel for variant in C.runner_variants_for("kapua")]
    current = list(C.installed_sources_for("kapua"))
    require(installed == runners or installed == current,
            "captured installed source membership differs")
    return installed


def _verify_captured_runner_sources(root, rels, recorded):
    """Check retained harness-owned sources against the capture's own hashes.

    Native capture selects upstream runners. Its unused R2TBench runners and
    step-tag listeners may predate the current candidate recipe; their recorded
    bytes remain evidence of that historical workspace, not authority for a
    live candidate.
    """
    for rel in rels:
        path = Path(root) / rel
        require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()
                == recorded[rel],
                "retained generated runner differs from captured substrate")


def load_capture(root, *, source_root, boundary, runtime=None):
    """Recompute a complete native capture; optionally bind its live worker.

    The returned capture remains development evidence. Release and complete
    compiler-population admission are separate consumers and separate gates.
    """
    from . import research_minimal as R, closure_java as J
    from ..stacks import cucumber as C
    from ..stacks.cucumber import records_from_json
    import tarfile

    files = CaptureFiles(root)
    capture = json.loads((files.root / "receipt.json").read_bytes())
    require(capture.get("schema") == SCHEMA and capture.get("status") == "complete"
            and capture.get("error") is None and capture.get("finished_at"),
            "capture did not complete")
    files.verify_refs(capture)
    source = capture["source"]
    require(source["commit"] == K.SOURCE_COMMIT and boundary.project == "kapua",
            "source/project differs")
    from ..core.boundary import load_boundary
    captured_boundary = load_boundary(str(files.path(source["boundary"])),
                                      repo_root=str(source_root))
    require(captured_boundary.raw == boundary.raw, "boundary differs")
    expected, partition = source_census(source_root)
    require(len(expected) == 688 and len(partition["candidate_ids"]) == 624
            and files.document(source["partition"]) == partition,
            "native/candidate/scaffolding partition differs")
    census = files.document(source["census"])
    require(census["source_commit"] == source["commit"]
            and Counter(json.dumps(row, sort_keys=True) for row in census["scenarios"])
            == Counter(json.dumps(row, sort_keys=True) for row in expected),
            "source census differs")
    build = files.document(capture["build"]["receipt"])
    inputs = files.document(capture["build"]["inputs"])
    image_id = capture["build"]["image_id"]
    inspected = files.document(capture["build"]["inspect"])
    require(build["state"] == "expanded_image_built_not_captured"
            and build["image_id"] == image_id
            and build["inputs_sha256"] == capture["build"]["inputs"]["sha256"]
            and build["source_commit"] == inputs["source_commit"] == source["commit"]
            and build["source_archive_sha256"] == inputs["source_archive_sha256"]
            == source["archive_sha256"]
            and len(inspected) == 1 and inspected[0]["Id"] == image_id
            and inspected[0]["Os"] == "linux" and inspected[0]["Architecture"] == "amd64",
            "build/image/source chain differs")
    authority = capture["authority"]
    authority_document = files.document(authority["document"])
    require(authority["document"]["sha256"] == authority["reference"]["file_sha256"]
            and authority_document["digest"] == authority["reference"]["digest"]
            and authority_document["daemon"]["fingerprint_sha256"]
            == authority["daemon_fingerprint"], "authority document differs")
    if runtime is not None:
        validate_live_runtime(capture, runtime)
    plans = R.reality_runs("kapua")
    rows, phases, workspaces = capture["runs"], capture["phases"], capture["workspaces"]
    require([row["name"] for row in rows] == [plan.name for plan in plans],
            "native leg set or order differs")
    require([row["kind"] for row in workspaces] == ["pinned", "stripped"]
            and len({row["path"] for row in workspaces}) == 2
            and len({row["container_id"] for row in workspaces}) == 2,
            "original/stripped workspaces are not distinct")
    source_files = source_inventory(source_root)
    by_kind = {row["kind"]: row for row in workspaces}
    phase_by_label = {phase["label"]: phase for phase in phases}
    require(len(phase_by_label) == len(phases), "phase labels repeat")
    directory_cache = {}
    for workspace in workspaces:
        kind = workspace["kind"]
        create = phase_by_label[kind + "-create"]
        require(phase_command(create) == ["run", "--pull", "never", "--detach", "--name",
                workspace["container_name"], "--network", "none", "--hostname", "kapua-worker",
                "--add-host", "kapua-worker:127.0.0.1", "--mount",
                f"type=bind,source={workspace['path']},target=/work", "--workdir", "/work",
                image_id, "tail", "-f", "/dev/null"]
                and create["returncode"] == 0
                and files.path(create["stdout"]).read_text().strip() == workspace["container_id"],
                "native container source/image/network binding differs")
        require(files.document(workspace["original_source_files"]) == source_files,
                "original attribution source differs from runtime archive")
        before = files.document(workspace["substrate_before"])
        require(files.document(workspace["substrate_after"]) == before,
                "source substrate changed during native capture")
        if kind == "pinned":
            require(workspace["strip_manifest"] is None and before == source_files,
                    "original source state differs")
        else:
            strip = files.document(workspace["strip_manifest"])
            moved = strip["moved"]
            require(len(moved) == 24 and len(set(moved)) == 24
                    and all(path not in before and path in source_files
                            and boundary.classify(path) == "removable" for path in moved),
                    "stripped source state differs")
            # Before step attribution, the preserved capture installed only
            # runners. Authenticate its own supported membership and hashes;
            # live workers still require the current runner/listener recipe.
            installed = _captured_installed_sources(strip["installed"])
            require(strip["moved_config"] == [] and strip["patched"] == ["pom.xml"]
                    and strip["installed"] == installed
                    and set(before) == (set(source_files) - set(moved)) | set(installed)
                    and all(before[path] == digest for path, digest in source_files.items()
                            if path not in set(moved) | {"pom.xml"}),
                    "stripped preparation changed other original source")
            _verify_captured_runner_sources(
                files.root / kind / "workspace", installed, before)
            require(before["pom.xml"] == hashlib.sha256(C._kapua_pom_with_agent(
                        (Path(source_root) / "pom.xml").read_text()).encode()).hexdigest(),
                    "stripped POM bytes differ")
            substrate = files.document(workspace["substrate_verification"])
            require(substrate["baseline"] and not any(substrate[key]
                    for key in ("changed", "missing", "added")),
                    "stripped substrate verification failed")
        for field, suffix in (("install_phase", "install"), ("cleanup_phase", "cleanup"),
                              ("absence_phase", "absence")):
            phase = phases[workspace[field]]
            require(phase["label"] == kind + "-" + suffix
                    and phase["returncode"] == 0 and not phase["timed_out"],
                    "workspace installation/cleanup failed")
        require_exec(phases[workspace["install_phase"]], workspace)
        require(phase_command(phases[workspace["cleanup_phase"]])
                == ["rm", "-f", workspace["container_name"]]
                and phase_command(phases[workspace["absence_phase"]])
                == ["ps", "-aq", "--no-trunc", "--filter",
                    "name=^/" + workspace["container_name"] + "$"],
                "cleanup targets another native container")
        require(not files.path(phases[workspace["absence_phase"]]["stdout"]).read_bytes().strip(),
                "native container absence is not proven")
        jar_inputs = files.document(workspace["classpath_jar_inputs"])
        with tarfile.open(files.path(workspace["classpath_jar_archive"])) as archive:
            members = archive.getmembers()
            require(len(members) == len(jar_inputs)
                    and {member.name for member in members} == set(jar_inputs)
                    and all(member.isfile() for member in members),
                    "native JAR archive membership differs")
            for member in members:
                with archive.extractfile(member) as handle:
                    require(_sha256_stream(handle)
                            == jar_inputs[member.name], "native JAR archive bytes differ")
    type_index = J.build_type_index(str(source_root), J.test_source_roots("kapua"))
    for row, plan in zip(rows, plans):
        suite = next(suite for suite in K.SUITES
                     if suite.runner_package + "." + suite.upstream_runner_class == plan.target)
        require(row["target"] == plan.target and row["module"] == suite.module
                and row["workspace_kind"] == plan.workspace_kind
                and row["dry_run"] == plan.dry_run and row["stripped"] == plan.stripped
                and row["maven_argv"] == list(plan.maven_argv), "native plan differs")
        workspace = by_kind[plan.workspace_kind]
        phase = phases[row["phase"]]
        require_exec(phase, workspace, list(plan.maven_argv))
        require(phase["label"] == plan.name and phase["returncode"] == row["returncode"]
                == (R.stripped_dry_run_exit("kapua") if plan.stripped else 0)
                and not phase["timed_out"] and phase["stdout"] == row["stdout"]
                and phase["stderr"] == row["stderr"]
                and phase["argv"][-len(plan.maven_argv):] == list(plan.maven_argv),
                "actual native command or outcome differs")
        clear = phases[row["phase"] - 1]
        require(clear["label"] == plan.name + "-clear" and clear["returncode"] == 0
                and not clear["timed_out"], "fresh native report cleanup is missing")
        require_exec(clear, workspace, ["rm", "-rf", "--", "/tmp/kapua-liquibase",
            f"/work/{suite.module}/target/surefire-reports",
            f"/work/{suite.module}/target/r2t-cucumber.json",
            f"/work/{suite.module}/target/r2t-cucumber-dry-run.json",
            f"/work/{suite.module}/target/jacoco.exec"])
        raw = files.path(row["raw_json"]).read_bytes()
        document = json.loads(raw)
        wanted = [record for record in expected if record["feature"] in suite.features]
        observation = compare_native(document, suite, wanted)
        require(files.document(row["observation"]) == observation, "native observation differs")
        folded_raw = files.path(row["folded_jsonl"]).read_bytes()
        folded, voids = records_from_json(document)
        require(not voids and [json.loads(line) for line in folded_raw.splitlines()] == folded,
                "native raw/folded evidence differs")
        xml_raw = files.path(row["selected_surefire_xml"]).read_bytes()
        cp, attrs = selected_xml(xml_raw, plan.target, len(wanted))
        require(row["surefire_attributes"] == attrs and row["classpath_properties"]
                == {"java.class.path": cp, "surefire.test.class.path": cp},
                "selected native XML properties differ")
        workspace = by_kind[plan.workspace_kind]
        mapping = files.path(workspace["code_source_map"]).read_text()
        require(mapping == K.code_source_map(str(source_root), boundary), "source map differs")
        verification = K.verify_code_source_classpath(str(source_root), suite, cp, mapping)
        require(row["classpath_verification"] == verification, "native classpath origins differ")
        paths = (cp[:-1] if cp.endswith(":") else cp).split(":")
        require([entry["path"] for entry in row["classpath"]] == paths,
                "ordered native classpath differs")
        mapped = {entry["code_source"]: entry for entry in verification["verified_origins"]}
        hash_phase = phases[row["classpath_hash_phase"]]
        jars = [path for path in paths if path.endswith(".jar")]
        require(hash_phase["label"] == plan.name + "-classpath-hashes"
                and hash_phase["returncode"] == 0, "native JAR hash phase failed")
        require_exec(hash_phase, workspace, ["sha256sum", "--", *jars])
        hashes = {}
        for line in files.path(hash_phase["stdout"]).read_text().splitlines():
            digest, path = line.split(None, 1)
            path = path.lstrip(" *")
            require(path not in hashes, "native JAR hash record repeats")
            hashes[path] = digest
        require(set(hashes) == set(jars), "native JAR hash membership differs")
        jar_inputs = files.document(workspace["classpath_jar_inputs"])
        for entry in row["classpath"]:
            path = entry["path"]
            require(entry["origin"] == ("reactor" if path in mapped else "external")
                    and entry["kind"] == ("jar" if path.endswith(".jar") else "directory"),
                    "native classpath kind/origin differs")
            if path in mapped:
                require(all(entry[key] == mapped[path][key] for key in ("source_root", "role")),
                        "native classpath source mapping differs")
            if entry["kind"] == "jar":
                require(entry["archive_member"] == path.lstrip("/")
                        and jar_inputs.get(entry["archive_member"]) == entry["sha256"]
                        == hashes[path],
                        "native classpath archive differs")
            else:
                key = (plan.workspace_kind, path)
                if key not in directory_cache:
                    directory = files.root / plan.workspace_kind / "workspace" / path.removeprefix("/work/")
                    directory_cache[key] = (directory.is_dir(), {
                        str(item.relative_to(directory)): hashlib.sha256(item.read_bytes()).hexdigest()
                        for item in sorted(directory.rglob("*")) if item.is_file()})
                require((entry["exists"], entry["files"]) == directory_cache[key],
                        "native output directory differs from retained class bytes")
        artifacts = {"cucumber.json": raw, "cucumber.records.jsonl": folded_raw,
                     "surefire/TEST-" + plan.target + ".xml": xml_raw}
        facts = R._artifact_facts(R.CommandResult(tuple(plan.maven_argv), row["returncode"],
                                  artifacts=artifacts), plan, observation["pickle_ids"],
                                  boundary, type_index, "kapua")
        require(files.document(row["artifact_facts"]) == facts, "derived native facts differ")
    for phase in phases:
        require(phase["authority_reference"] == authority["reference"]
                and phase["daemon_fingerprint"] == authority["daemon_fingerprint"]
                and not phase["timed_out"] and phase["finished_at"],
                "phase authority or completion differs")
    require(capture["classpath_agreement"] == [triplet_agreement(rows[i:i+3])
            for i in range(0, len(rows), 3)], "triplet agreement differs")
    return capture
