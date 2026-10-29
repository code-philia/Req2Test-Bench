"""Reviewed development-release binding for Kapua's module population.

The native and owning-compiler captures have different jobs. Native evidence
proves the original/stripped suite contract; compiler evidence preserves every
production module, including modules absent from native test classpaths. Neither
capture is a release approval. The external approval binds the final release
bytes and both captures before a live worker can consume their analysis recipe.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from . import kapua_runtime as KR

APPROVAL_SCHEMA = "r2t.kapua-development-population-approval/2"
MANIFEST_SCHEMA = "r2t.kapua-development-release-manifest/1"


def require(ok, reason):
    if not ok:
        raise ValueError("REFUSED: Kapua population " + reason)


def release_file_manifest(root):
    """Use the shared file/tree framing without claiming a legacy image chain."""
    from .release_validation import _release_file_manifest
    document, tree = _release_file_manifest(str(root))
    return {"schema": MANIFEST_SCHEMA, "project": "kapua",
            "files": document["files"], "tree_sha256": tree}


def load_approval(path, digest):
    from .. import docker_authority as D
    require(path is not None and digest is not None,
            "external reviewed release approval is absent")
    path = D.canonical_absolute_path(path, "Kapua population approval")
    D.assert_trusted_file(path, label="Kapua population approval")
    document = D.loads_exact_json(Path(path).read_bytes(), label="Kapua population approval")
    require(isinstance(document, dict) and set(document) == {
            "schema", "project", "route", "release_manifest_sha256",
            "release_tree_sha256", "source_root", "boundary", "native_capture",
            "compiler_capture", "gold_coverage", "digest"}
            and document["schema"] == APPROVAL_SCHEMA
            and document["project"] == "kapua" and document["route"] == "development",
            "approval schema/project/route differs")
    require(document["digest"] == digest == D.semantic_digest(document, domain=APPROVAL_SCHEMA),
            "approval digest is stale or is not the reviewed digest")
    from ..toolkit import mutation_java as MJ
    for key in ("release_manifest_sha256", "release_tree_sha256"):
        require(MJ._is_sha256(document[key]), "approval lacks exact " + key)
    for name, keys in (("boundary", {"path", "sha256"}),
                       ("native_capture", {"root", "receipt_sha256"}),
                       ("compiler_capture", {"root", "binding_path", "receipt_sha256"}),
                       ("gold_coverage", {"receipt_path", "receipt_sha256"})):
        ref = document[name]
        require(isinstance(ref, dict) and set(ref) == keys,
                "approval has malformed " + name)
        for key, value in ref.items():
            if key.endswith("sha256"):
                require(MJ._is_sha256(value), "approval has no exact " + name + " digest")
            else:
                D.canonical_absolute_path(value, "Kapua " + name + " " + key)
    D.canonical_absolute_path(document["source_root"], "Kapua original source")
    return document


def measured_release(release_root):
    """Authenticate assembled release bytes without asserting human approval."""
    from ..toolkit import mutation_java as MJ
    from ..bench import result_ledger as L
    root = Path(release_root).absolute()
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root,
            "release root is not canonical")
    manifest_path = root.parent / "release-manifest.json"
    document, raw = MJ._json_object(str(manifest_path), "Kapua release manifest")
    actual = release_file_manifest(root)
    require(set(document) == set(actual) | {"released_item_ids"}
            and all(document[key] == value for key, value in actual.items()),
            "release files differ from the assembled manifest/tree")
    refs = {ref["path"]: ref for ref in document["files"]}
    require("items.jsonl" in refs and "control-artifacts/closures.json" in refs,
            "release lacks item or closure records")
    items_path = root / "items.jsonl"
    items_raw = MJ._regular_bytes(str(items_path), "Kapua release items",
                                  maximum=MJ._MAX_AUTHORITY_JSON)
    rows = L._json_lines(items_raw, "Kapua release items")
    ids = [row.get("item_id") for row in rows]
    require(ids and all(isinstance(i, str) and i.startswith("kapua/") for i in ids)
            and len(ids) == len(set(ids)) and document["released_item_ids"] == ids,
            "release item membership or order differs")
    closures = json.loads((root / "control-artifacts/closures.json").read_bytes())
    require(isinstance(closures, list) and all(isinstance(row, dict) for row in closures),
            "closure ledger has another shape")
    closure_ids = [row.get("item_id") for row in closures]
    require(all(isinstance(i, str) for i in closure_ids)
            and len(closure_ids) == len(set(closure_ids)) and set(ids) <= set(closure_ids),
            "release items lack unique closure records")
    by_id = {row["item_id"]: row for row in closures}
    require(all(by_id[i].get("admitted") is True and by_id[i].get("files") for i in ids),
            "release contains an unadmitted or empty closure")
    return {"root": str(root), "manifest_path": str(manifest_path),
            "items_path": str(items_path), "released_item_ids": set(ids), "item_rows": rows,
            "items_sha256": refs["items.jsonl"]["sha256"],
            "closures_sha256": refs["control-artifacts/closures.json"]["sha256"],
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "tree_sha256": document["tree_sha256"]}


def validate_release(release_root, *, approval_path, approved_digest):
    """Require external review before mutation entrypoints consume the release."""
    approval = load_approval(approval_path, approved_digest)
    release = measured_release(release_root)
    require(release["manifest_sha256"] == approval["release_manifest_sha256"]
            and release["tree_sha256"] == approval["release_tree_sha256"],
            "release files differ from the reviewed manifest/tree")
    return {**release, "approval": approval}


def load_gold_coverage(coverage_run, release, *, boundary_path):
    """Consume only the completed ordinary-gold receipt in this approval."""
    from . import kapua_gold_coverage as G
    approved = release["approval"]
    require(os.path.abspath(boundary_path) == approved["boundary"]["path"],
            "coverage boundary differs from final review")
    ref = approved["gold_coverage"]
    return G.load_coverage(ref["receipt_path"], ref["receipt_sha256"],
                           coverage_run=coverage_run, release=release,
                           approved=approved)


def load_population_authority(release_root, *, repo_roots, runtime,
                              approval_path, approved_digest):
    """Bind reviewed release bytes to actual native/compile evidence and workers."""
    from ..toolkit import mutation_java as MJ
    from ..core.boundary import load_boundary
    from . import kapua_compiler as KC
    release = validate_release(release_root, approval_path=approval_path,
                               approved_digest=approved_digest)
    approved = release["approval"]
    boundary_ref = approved["boundary"]
    raw = Path(boundary_ref["path"]).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == boundary_ref["sha256"],
            "reviewed boundary changed")
    boundary = load_boundary(boundary_ref["path"], repo_root=approved["source_root"])
    native_ref = approved["native_capture"]
    raw = MJ._regular_bytes(os.path.join(native_ref["root"], "receipt.json"),
                            "Kapua native receipt", maximum=MJ._MAX_AUTHORITY_JSON)
    require(hashlib.sha256(raw).hexdigest() == native_ref["receipt_sha256"],
            "native receipt differs from final review")
    require(isinstance(runtime, dict) and isinstance(runtime.get("selected"), dict),
            "population has no validated live worker")
    capture = KR.load_capture(native_ref["root"], source_root=approved["source_root"],
                              boundary=boundary, runtime=runtime)
    _, partition = KR.source_census(approved["source_root"])
    require(release["released_item_ids"] <= set(partition["candidate_ids"]),
            "release includes a setup/teardown or unadmitted native item")
    roots = list(repo_roots)
    require(bool(roots), "population has no worker source roots")
    ref = approved["compiler_capture"]
    compiler = KC.load_module_authority(ref["root"], binding_path=ref["binding_path"],
        expected_receipt_sha256=ref["receipt_sha256"], source_root=approved["source_root"],
        boundary=boundary, native_capture=capture, repo_roots=roots)
    return {**compiler, "release": release}


def stage_population_analysis(repo_roots, authority):
    """Copy captured compiler inputs into authenticated workers, without replacing files.

    Original production sources are readers only. Existing exact outputs and
    dependency copies are reusable; another byte sequence refuses and remains
    available for diagnosis. The excluded bundle keeps Maven-relative layout.
    """
    from ..toolkit import mutation_java as MJ
    recipe = authority["analysis_recipe"]
    source = authority["workspace"]
    MJ.validate_analysis_recipe(recipe, source)
    roots = [Path(root).absolute() for root in repo_roots]
    require(bool(roots), "analysis staging has no worker roots")
    entries = {}
    for row in recipe["modules"]:
        for key in ("classpath", "module_path"):
            for entry in row["recipe"][key]:
                entries[entry["path"]] = (key, entry)
    # Verify every worker source before the first write to any worker.
    for root in roots:
        require(root.is_dir() and root.resolve() == root, "worker root is not canonical")
        for row in recipe["modules"]:
            entry, = row["recipe"]["sourcepath"]
            require(MJ._input_content(str(root), entry["path"], "sourcepath")
                    == (entry["kind"], entry["sha256"]), "worker production source differs")
    for root in roots:
        for rel, (key, entry) in sorted(entries.items()):
            destination = root / rel
            if not os.path.lexists(destination):
                parent = root
                for part in Path(rel).parts[:-1]:
                    parent = parent / part
                    if os.path.lexists(parent):
                        require(parent.is_dir() and not parent.is_symlink(),
                                "analysis parent is not a directory")
                    else:
                        parent.mkdir(mode=0o700)
                MJ._copy_analysis_entry(source, entry, str(destination), key)
            require(MJ._input_content(str(root), rel, key,
                        allow_kapua_absent_manifest_classpath=True)
                    == (entry["kind"], entry["sha256"]), "existing analysis input differs: " + rel)
        MJ.validate_analysis_recipe(recipe, str(root))
    return recipe


def selftest():
    import copy
    import tempfile
    from .. import docker_authority as D
    from ..toolkit import mutation_java as MJ
    failures = []
    from . import research_minimal as R
    assert MJ._RELEVANT_REALITY_RUNS["kapua"] == tuple(
        run.name for run in R.reality_runs("kapua") if not run.stripped)
    assert "kapua" not in R.PROJECTS

    def refused(label, call):
        try:
            call()
        except (ValueError, RuntimeError):
            return
        failures.append(label)

    with tempfile.TemporaryDirectory(prefix="kapua_population_") as scratch:
        base = Path(scratch)
        root = base / "release"
        (root / "control-artifacts").mkdir(parents=True)
        items = [{"item_id": "kapua/features/Example.feature:3"},
                 {"item_id": "kapua/features/Example.feature:7"}]
        closures = [{"item_id": row["item_id"], "admitted": True,
                     "files": ["example/test-steps/Steps.java"]} for row in items]
        (root / "items.jsonl").write_text("".join(json.dumps(row) + "\n" for row in items))
        (root / "control-artifacts/closures.json").write_text(json.dumps(closures))
        document = release_file_manifest(root)
        document["released_item_ids"] = [row["item_id"] for row in items]
        manifest = base / "release-manifest.json"
        manifest.write_text(json.dumps(document))
        approval = {
            "schema": APPROVAL_SCHEMA, "project": "kapua", "route": "development",
            "release_manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "release_tree_sha256": document["tree_sha256"], "source_root": str(base / "source"),
            "boundary": {"path": str(base / "boundary.yml"), "sha256": "a" * 64},
            "native_capture": {"root": str(base / "native"), "receipt_sha256": "b" * 64},
            "compiler_capture": {"root": str(base / "compiler"),
                "binding_path": str(base / "binding.json"), "receipt_sha256": "c" * 64},
            "gold_coverage": {"receipt_path": str(base / "gold/receipt.json"),
                              "receipt_sha256": "e" * 64},
            "digest": "0" * 64}
        approval["digest"] = D.semantic_digest(approval, domain=APPROVAL_SCHEMA)
        approval_path = base / "approval.json"
        approval_path.write_text(json.dumps(approval))
        def load():
            return validate_release(str(root), approval_path=str(approval_path),
                                    approved_digest=approval["digest"])
        legacy = copy.deepcopy(approval)
        legacy["schema"] = "r2t.kapua-development-population-approval/1"
        legacy.pop("gold_coverage")
        legacy["digest"] = D.semantic_digest(legacy, domain=legacy["schema"])
        approval_path.write_text(json.dumps(legacy))
        refused("legacy approval without gold accepted", lambda: load_approval(
            str(approval_path), legacy["digest"]))
        approval_path.write_text(json.dumps(approval))
        checked = load()
        assert [r["item_id"] for r in checked["item_rows"]] == document["released_item_ids"]
        refused("missing review accepted", lambda: validate_release(str(root),
                approval_path=None, approved_digest=None))
        changed = copy.deepcopy(approval)
        changed["compiler_capture"]["receipt_sha256"] = "d" * 64
        approval_path.write_text(json.dumps(changed))
        refused("changed capture approval accepted", load)
        approval_path.write_text(json.dumps(approval))
        original = (root / "items.jsonl").read_bytes()
        (root / "items.jsonl").write_bytes(b"\n".join(reversed(original.splitlines())) + b"\n")
        refused("changed item order accepted", load)
        (root / "items.jsonl").write_bytes(original)
        path = root / "control-artifacts/closures.json"
        original_closures = path.read_bytes()
        path.write_text("[]")
        refused("changed closure evidence accepted", load)
        path.write_bytes(original_closures)
        (root / "extra.txt").write_text("undeclared")
        refused("unreviewed release file accepted", load)
        (root / "extra.txt").unlink()
        # Even a correctly re-bound file manifest must match its declared item order.
        document["released_item_ids"].reverse()
        manifest.write_text(json.dumps(document))
        approval["release_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        approval["digest"] = D.semantic_digest(approval, domain=APPROVAL_SCHEMA)
        approval_path.write_text(json.dumps(approval))
        refused("false manifest item order accepted", load)

        # One real recipe and fresh worker prove copying plus conflicting-output refusal.
        source, worker = base / "captured", base / "worker"
        rel = "example/src/main/java"
        for directory in (source / rel, worker / rel, source / "example/target/classes"):
            directory.mkdir(parents=True)
        for directory in (source, worker):
            (directory / rel / "Example.java").write_text("class Example {}\n")
        (source / "example/target/classes/Example.class").write_bytes(b"retained fixture output")
        compiler = {"java_home": "/opt/java/openjdk", "parser": "javac 17.0.17",
            "runtime_executable_sha256": "a" * 64, "compiler_executable_sha256": "b" * 64,
            "tools_jar_sha256": None, "encoding": "UTF-8", "source": "1.8",
            "target": "1.8", "release": None}
        child = MJ.make_module_analysis_child_recipe(str(source), "example",
                    classpath=["example/target/classes"])
        recipe = MJ.make_module_analysis_recipe(str(source), [{"module": "example",
            "source_root": rel, "source_files": [rel + "/Example.java"],
            "compiler": compiler, "recipe": child}])
        authority = {"workspace": str(source), "analysis_recipe": recipe}
        assert stage_population_analysis([str(worker)], authority) == recipe
        assert stage_population_analysis([str(worker)], authority) == recipe
        output = worker / "example/target/classes/Example.class"
        output.write_bytes(b"different observed output")
        refused("conflicting worker output overwritten", lambda:
                stage_population_analysis([str(worker)], authority))
        assert output.read_bytes() == b"different observed output"
        (worker / rel / "Example.java").write_text("class Changed {}\n")
        refused("changed worker source accepted", lambda:
                stage_population_analysis([str(worker)], authority))
    if failures:
        print("FAIL: " + "; ".join(failures))
        return 1
    print("PASS: Kapua reviewed release, capture bindings, item order and worker staging")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
