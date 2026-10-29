#!/usr/bin/env python3
"""V-applier: does master's mutant applier write the bytes the paper's did?

Audience: maintainers checking a project's evaluation kit against the vendored
engine (harness plan A.3 item 4). Offline: no model calls, no network inside
the container, nothing written outside ``--work`` and ``--out``.

For every ground-truth-killed mutant of a kit (the mutants of G_i: pool pairs
with ``gold_outcome == killed``, minus ``reference_excluded``), the check
applies the mutant recipe to the kit's seed with the applier the paper's
scoring used and with this repository's applier, and compares the sha256 of
the two mutated files.

    # 1. Where the research checkout is: verify the pinned applier identities
    #    and write the paper appliers for the kit host.
    python3 scripts/check_applier.py sources --research R --write DIR

    # 2. Where the kit and a Docker daemon are (DOCKER_HOST is honoured):
    python3 scripts/check_applier.py run --project coreshop --kit KIT \\
        --paper-applier DIR/coreshop/mutate.php --work W --out report.json

Two kinds of engine, as the engine itself applies them:

- Script appliers (PHP ``mutate.php``, Python ``mutate.py``, Ruby
  ``mutate.rb``) produce the mutated bytes. Both versions run inside the kit's
  own image, with the argument vector ``bench.mutation_run.apply_mutant``
  builds, except that ``--out`` names a file outside the read-only workspace.
- Splice engines (Go ``r2t-mutate-go``, Java ``r2t-mutate-java``). The engine
  refuses any applier output other than the exact byte splice of the
  descriptor (``go/mutation_copy.apply_mutation``,
  ``bench/mutation_run.apply_mutant``), so the mutated bytes are that splice,
  computed here on the seed. No applier is run on this route: the report
  marks both applier rows not run (``appliers_run: false``), checks that every
  descriptor splices on the seed, and compares applier identities (Go: the copy
  the seed installs, which is what workers run). Its verdict reads "equal" only
  when the two applier sources are the same or the ``PAPER`` row records a
  reviewed diff; otherwise it reads "unreviewed_diff".

Both kinds also compare each output with the descriptor's own byte splice of
the seed file, so a difference names which side moved.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time

REPO_ROOT = Path(__file__).resolve().parents[1]
ENGINE_DIR = REPO_ROOT / "benchmark" / "r2t"
SCHEMA = "req2test.applier-check/1"

#: Engine name -> (applier path under benchmark/r2t, interpreter, kind).
ENGINES = {
    "r2t-mutate": ("php/mutate.php", "php", "script"),
    "r2t-mutate-py": ("py/mutate.py", "python3", "script"),
    "r2t-mutate-rb": ("ruby/mutate.rb", "ruby", "script"),
    "r2t-mutate-java": ("java/Mutate.java", "java", "splice"),
    "r2t-mutate-go": ("go/mutate.go", "go", "splice"),
}

#: The applier of the paper's scoring per project (harness plan A.3's table):
#: the research tags its references were collected at and its candidates were
#: scored at, and the sha256 of the applier at each of them. `sources`
#: re-derives every row from git; `run` checks a supplied file against it.
PAPER = {
    "coreshop": {
        "engine": "r2t-mutate",
        "applier_sha256": "0da1838b156531c307d34e3eb77537e32e953e4d9b61f43f09291cc6e88a4e8c",
        "refs": [
            ("mutation-evaluation-collection-v1.1", "4a2782b4311cd2198de2c8412989f617ba17f138", "references"),
            ("mutation-evaluation-collection-v1.1.2", "4998a89c979b9afc65fe033e3d586d2e525fd473", "candidate scoring"),
            ("mutation-evaluation-collection-v1.1.2-pq1-20260927", "a2cff2894ee9c8da24745a598f06d1894517f17b",
             "candidate scoring"),
        ],
    },
    "sylius": {
        "engine": "r2t-mutate",
        "applier_sha256": "3c9321e13c4675c6e7591ecc6491054cfc0c1a9af934732d12bbdffe6879d215",
        "refs": [
            ("sylius_mutation_full-gold-results_v1", "0c345bfab4b29fadbd08f897792929f0b8da9d6e", "references"),
            ("sylius319-stub-gate-waived-gold-killed-h21-v1-20260928", "987e6d4e96bf6ad270e9a76d0544d2fa0bbd6595",
             "candidate scoring"),
        ],
    },
    "prestashop": {
        "engine": "r2t-mutate",
        "applier_sha256": "3c9321e13c4675c6e7591ecc6491054cfc0c1a9af934732d12bbdffe6879d215",
        "refs": [
            ("onb-prestashop-continuation-h23-20260923", "c9692025f1489d54a04af1fe2185807545349b48", "references"),
            ("codex-psh-scoring-r2-20260927", "97030f222970a8844f1c022aed4440374fe9d1c1", "candidate scoring"),
        ],
    },
    "python-docx": {
        "engine": "r2t-mutate-py",
        "applier_sha256": "87ee207f49917442fec94da7ff9fcb19154ffaaa70fb9b2f162cb2d3a2b8b69f",
        "refs": [
            ("mutation-evaluation-collection-v1", "0ebd5496209776c8159960b01208c20f24e682b3", "references"),
            ("codex-luna-cells-h1-20260925", "5a9169144f09de285ee5a26fed56ea135cf9257b", "candidate scoring"),
        ],
    },
    "e-petitions": {
        "engine": "r2t-mutate-rb",
        "applier_sha256": "0a1ade79caf3a32b6dd10a1f8db9d659bd09cfb8580e22102f8458c10add2922",
        "refs": [
            ("e-petitions_mutation_full-gold-results_v1", "47b9933cc2e86e1473b8182a66b747cac4a783a3",
             "references (harness 21)"),
            ("epet-task-revision-r2-20260928", "d5df64c325d1c4c884527f74c7fd21d629f33086", "candidate scoring"),
        ],
    },
    "kapua": {
        "engine": "r2t-mutate-java",
        "applier_sha256": "1b9dce7bbc6a2a3d3a97b76ecfab7999d60a430e839632daec7d86e23bee8824",
        "refs": [
            ("kapua-census330-mutation-r1-20260927", "b59a81cb26d57813fe6662c3fa0ed499cc321ef9", "references"),
            ("kapua-census330-candidates-r2-20260927", "3f5f28eb273c3b79ea91cd30a24ab5c6e1c54f8c",
             "candidate scoring"),
            ("kapua-census330-candidates-r3-20260928", "ccbd50e9c961c0b5aa295ab20cfaa9981e12ef56",
             "candidate scoring (replacement view)"),
        ],
    },
    "algorand-sdk": {
        "engine": "r2t-mutate-java",
        "applier_sha256": "0ade84feea4bcf864aa52de46db5fde3237f56b9de04a401af41ca28563e31f6",
        # Splice engines do not run the applier, so a source difference needs
        # a reviewed diff before the verdict can read "equal".
        "reviewed_diff": (
            "Mutate.java 0ebd5496 -> 21f1cb23 only adds the optional --source-level/--target-level/"
            "--release-level flags and passes them to javac when given. Algorand's manifest carries "
            "a single r2t.java-analysis-recipe/1 authority, for which "
            "toolkit/mutation_java.py:1410-1415 (analysis_binding_for_path) returns compiler_argv [], "
            "so the flags are never passed and the applier runs its legacy path; the engine pins the "
            "bytes to the exact splice either way."),
        "refs": [
            ("mutation-evaluation-collection-v1", "0ebd5496209776c8159960b01208c20f24e682b3",
             "references and candidate scoring"),
        ],
    },
    "coddy-agent": {
        "engine": "r2t-mutate-go",
        # Go workers run the mutate.go their seed installs; this is the
        # applier_sha256 of the sealed reference authority, and the copy in
        # the research tree at these tags is only the catalogue builder.
        "applier_sha256": "d89899e35b314c836b3ba073ffd11d3f80cdd69d99f870c78e8395c3a4b4862b",
        "seed_applier": "_bench/go/support/mutate.go",
        "refs": [
            ("coddy-agent-fullgold-attempt4-v1-20260929", "7c1f4e3fc21dbbdf033c217b97ec02291ff8f86e",
             "references; route-B candidate scoring"),
            ("coddy-agent-fullgold-attempt4-supplement-v4-20260930", "f6e7f5648f22df10c0ce6390d9b166423a902f75",
             "references (supplement); route-B candidate scoring"),
        ],
    },
}

#: The ordered v1 operator list (`data/mutation.py` OPERATORS_V1); any other
#: manifest of a profile-taking engine is v2, as `operator_profile_for` reads.
OPERATORS_V1 = ("ConditionalBoundary", "NegateConditional", "Increment", "ArithmeticOperator",
                "TrueValue", "FalseValue", "ReturnValue", "MethodCallRemoval")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_maybe_zst(path: Path) -> bytes:
    if path.suffix == ".zst":
        return subprocess.run(["zstd", "-dc", str(path)], check=True, capture_output=True).stdout
    return path.read_bytes()


# ------------------------------------------------------------------ sources

def git_show(research: Path, commit: str, rel: str):
    done = subprocess.run(["git", "-C", str(research), "show", f"{commit}:{rel}"], capture_output=True)
    return done.stdout if done.returncode == 0 else None


def cmd_sources(args) -> int:
    """Re-derive every PAPER row from the research checkout; optionally write the appliers."""
    research = Path(args.research)
    problems = []
    for project, row in PAPER.items():
        if args.project and project not in args.project:
            continue
        rel = "benchmark/r2t/" + ENGINES[row["engine"]][0]
        master = (ENGINE_DIR / ENGINES[row["engine"]][0]).read_bytes()
        print(f"{project}: master {rel} {sha256_bytes(master)}")
        paper = None
        for tag, commit, role in row["refs"]:
            resolved = subprocess.run(["git", "-C", str(research), "rev-parse", f"{tag}^{{commit}}"],
                                      capture_output=True, text=True).stdout.strip()
            raw = git_show(research, commit, rel)
            digest = sha256_bytes(raw) if raw is not None else None
            print(f"  {role:38} {tag} {commit[:8]} applier {digest}")
            if resolved != commit:
                problems.append(f"{project}: tag {tag} is {resolved or 'absent'}, not {commit}")
            if "seed_applier" not in row and digest != row["applier_sha256"]:
                problems.append(f"{project}: {tag} applier {digest} is not {row['applier_sha256']}")
            if paper is None and raw is not None and digest == row["applier_sha256"]:
                paper = raw
        if args.write and paper is not None:
            out = Path(args.write) / project / Path(rel).name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(paper)
            print(f"  wrote {out}")
    for problem in problems:
        print("PROBLEM: " + problem)
    return 1 if problems else 0


# ---------------------------------------------------------------------- kit

def load_kit(kit: Path):
    meta = json.loads((kit / "kit.json").read_text())
    manifest = json.loads(read_maybe_zst(kit / "mutation" / "manifest.json.zst"))
    excluded = set()
    for line in (kit / "mutation" / "reference_excluded.jsonl").read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            excluded.add((row["item_id"], row["mutant_id"]))
    pairs = killed = 0
    g_mutants = set()
    for line in read_maybe_zst(kit / "mutation" / "pools.jsonl.zst").decode().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        pairs += 1
        if row["gold_outcome"] == "killed":
            killed += 1
            if (row["item_id"], row["mutant_id"]) not in excluded:
                g_mutants.add(row["mutant_id"])
    recipes = {m["id"]: m for m in manifest["mutants"]}
    missing = sorted(g_mutants - set(recipes))
    if missing:
        raise SystemExit(f"REFUSED: {len(missing)} G mutants have no recipe in the manifest, e.g. {missing[:3]}")
    return meta, manifest, {"pairs": pairs, "gt_killed_pairs": killed}, [recipes[m] for m in sorted(g_mutants)]


def seed_tar(kit: Path, meta: dict, override=None) -> Path:
    if override:
        return Path(override)
    seed = meta["exec_env"]["seed"]
    if seed.get("workspace"):
        return kit / seed["workspace"]
    return kit / seed["dir"] / "workspace.tar"


def extract_members(tar_path: Path, names) -> dict:
    """The bytes of `names` (workspace-relative) from a seed workspace tar."""
    wanted, found = set(names), {}
    with tarfile.open(tar_path, "r:*") as archive:
        for member in archive:
            name = member.name[2:] if member.name.startswith("./") else member.name
            if name in wanted and member.isfile():
                found[name] = archive.extractfile(member).read()
    return found


def operator_profile(engine: str, manifest: dict) -> str:
    if engine == "r2t-mutate-rb":
        return "v2"  # mutate.rb takes only v2
    return "v1" if tuple(manifest.get("operators") or ()) == OPERATORS_V1 else "v2"


def descriptor_splice(raw: bytes, m: dict, *, inclusive_end: bool):
    """The descriptor's own byte splice of `raw`, or None if its span is not there.

    Byte coordinates, 1-based. Script descriptors are spliced at the start
    for len(original) bytes, as the appliers do; splice engines use the
    inclusive physical end too, as `apply_mutant`'s Java check and
    `toolkit.mutation_go.splice` do.
    """
    starts = [0] + [i + 1 for i, b in enumerate(raw) if b == 10]

    def offset(line, col):
        if line < 1 or line > len(starts) or col < 1:
            return None
        return starts[line - 1] + col - 1

    start = offset(int(m["start_line"]), int(m["start_col"]))
    original = m["original"].encode("utf-8")
    if start is None:
        return None
    end = start + len(original)
    if inclusive_end:
        last = offset(int(m["end_line"]), int(m["end_col"]))
        if last is None or last + 1 != end:
            return None
    if end > len(raw) or raw[start:end] != original:
        return None
    return raw[:start] + m["mutated"].encode("utf-8") + raw[end:]


# --------------------------------------------------------------- execution

def docker(*argv, **kwargs):
    return subprocess.run(["docker", *argv], **kwargs)


def ensure_image(kit: Path, image: dict) -> str:
    digest = image["config_digest"]
    if docker("image", "inspect", digest, capture_output=True).returncode != 0:
        print(f"loading {image['file']} ...", flush=True)
        zstd = subprocess.Popen(["zstd", "-dc", str(kit / image["file"])], stdout=subprocess.PIPE)
        loaded = docker("load", stdin=zstd.stdout, capture_output=True, text=True)
        zstd.stdout.close()
        if zstd.wait() != 0 or loaded.returncode != 0:
            raise SystemExit(f"REFUSED: docker load of {image['file']} failed: {loaded.stderr[-400:]}")
    found = docker("image", "inspect", "--format", "{{.Id}}", digest, capture_output=True, text=True)
    if found.returncode != 0 or found.stdout.strip() != digest:
        raise SystemExit(f"REFUSED: image {digest} is not in this daemon by its config digest "
                         "(a classic overlay2 image store reports it as .Id)")
    return digest


def extract_workspace(tar_path: Path, dest: Path) -> str:
    """Extract the seed once; the marker holds the tar's sha256."""
    digest = sha256_file(tar_path)
    marker = dest.with_name(dest.name + ".sha256")
    if not (dest.is_dir() and marker.is_file() and marker.read_text().strip() == digest):
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        subprocess.run(["tar", "-xf", str(tar_path), "-C", str(dest)], check=True)
        marker.write_text(digest + "\n")
    return digest


def run_script(args, project, kit, meta, manifest, recipes, appliers) -> dict:
    engine = manifest["engine"]
    rel_applier, interpreter, _kind = ENGINES[engine]
    work = Path(args.work).resolve() / project
    work.mkdir(parents=True, exist_ok=True)
    tar_path = seed_tar(kit, meta, args.seed_tar)
    tar_sha = extract_workspace(tar_path, work / "ws")
    image = ensure_image(kit, meta["exec_env"]["images"][0])
    workdir = meta["exec_env"]["worker"]["workdir"]
    name = Path(rel_applier).name
    for label, raw in appliers.items():
        (work / "appliers" / label).mkdir(parents=True, exist_ok=True)
        (work / "appliers" / label / name).write_bytes(raw)
        out = work / "out" / label
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
    profile = operator_profile(engine, manifest)
    container = f"r2tb-applier-{project}-{os.getpid()}"
    started = docker("run", "-d", "--rm", "--network", "none", "--user", "0:0", "--entrypoint", "sleep",
                     "--name", container,
                     "-v", f"{work / 'ws'}:{workdir}:ro",
                     "-v", f"{work / 'appliers'}:/r2tb/appliers:ro",
                     "-v", f"{work / 'out'}:/r2tb/out",
                     image, "infinity", capture_output=True, text=True)
    if started.returncode != 0:
        raise SystemExit(f"REFUSED: could not start the check container: {started.stderr[-400:]}")
    try:
        version = docker("exec", container, interpreter, "--version", capture_output=True, text=True)
        interpreter_version = (version.stdout or version.stderr).strip().splitlines()[0]

        def apply(job):
            m, label = job
            argv = [interpreter, f"/r2tb/appliers/{label}/{name}", "--root", workdir,
                    "--operator-profile", profile, "--apply-file", m["file"],
                    "--start-line", str(int(m["start_line"])), "--start-col", str(int(m["start_col"])),
                    "--operator", m["operator"], "--original", m["original"], "--mutated", m["mutated"],
                    "--out", f"/r2tb/out/{label}/{m['id']}"]
            done = docker("exec", container, *argv, capture_output=True, text=True)
            produced = work / "out" / label / m["id"]
            return m["id"], label, done.returncode, (done.stderr or done.stdout or "")[-300:], \
                (sha256_file(produced) if done.returncode == 0 and produced.is_file() else None)

        jobs = [(m, label) for m in recipes for label in appliers]
        outcomes = {}
        began = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            for n, (mid, label, rc, tail, digest) in enumerate(pool.map(apply, jobs), 1):
                outcomes[(mid, label)] = (rc, tail, digest)
                if n % 500 == 0:
                    print(f"  {n}/{len(jobs)} applications, {time.monotonic() - began:.0f} s", flush=True)
    finally:
        docker("rm", "-f", container, capture_output=True)
    originals = {}
    for m in recipes:
        if m["file"] not in originals:
            path = work / "ws" / m["file"]
            originals[m["file"]] = path.read_bytes() if path.is_file() else None
    expected = {m["id"]: (descriptor_splice(originals[m["file"]], m, inclusive_end=False)
                          if originals[m["file"]] is not None else None) for m in recipes}
    rows = []
    for m in recipes:
        row = {"mutant_id": m["id"], "file": m["file"], "operator": m["operator"],
               "splice_sha256": sha256_bytes(expected[m["id"]]) if expected[m["id"]] is not None else None}
        for label in appliers:
            rc, tail, digest = outcomes[(m["id"], label)]
            row[label] = {"rc": rc, "sha256": digest, **({"stderr_tail": tail} if rc else {})}
        rows.append(row)
    environment = {"seed_tar": str(tar_path), "seed_tar_sha256": tar_sha, "image_config_digest": image,
                   "workdir": workdir, "interpreter": interpreter_version, "operator_profile": profile}
    return {"environment": environment, "rows": rows}


def run_splice(args, project, kit, meta, manifest, recipes, appliers) -> dict:
    tar_path = seed_tar(kit, meta, args.seed_tar)
    files = extract_members(tar_path, {m["file"] for m in recipes} | (
        {PAPER[project]["seed_applier"]} if "seed_applier" in PAPER[project] else set()))
    rows = []
    for m in recipes:
        raw = files.get(m["file"])
        mutated = descriptor_splice(raw, m, inclusive_end=True) if raw is not None else None
        digest = sha256_bytes(mutated) if mutated is not None else None
        # The engine admits only this splice from either applier version; no
        # applier runs here, so the applier rows hold no measurement.
        rows.append({"mutant_id": m["id"], "file": m["file"], "operator": m["operator"],
                     "splice_sha256": digest,
                     **{label: {"rc": None, "sha256": None} for label in appliers}})
    environment = {"seed_tar": str(tar_path), "seed_tar_sha256": sha256_file(tar_path)}
    if "seed_applier" in PAPER[project]:
        installed = files.get(PAPER[project]["seed_applier"])
        environment["seed_applier"] = {"path": PAPER[project]["seed_applier"],
                                       "sha256": sha256_bytes(installed) if installed is not None else None,
                                       "identity_constants": go_identity(installed)}
    return {"environment": environment, "rows": rows}


def go_identity(raw):
    """ENGINE, ENGINE_VERSION, ENUMERATOR_REV of a Go applier, as `applier_sha256` reads them."""
    if raw is None:
        return None
    text = raw.decode("utf-8", "replace")
    return {name: (re.search('^const ' + name + ' = "([^"]*)"$', text, re.M) or [None, None])[1]
            for name in ("ENGINE", "ENGINE_VERSION", "ENUMERATOR_REV")}


def cmd_run(args) -> int:
    project = args.project
    row = PAPER[project]
    kit = Path(args.kit)
    meta, manifest, counts, recipes = load_kit(kit)
    engine = manifest["engine"]
    if engine != row["engine"] or meta.get("project") != project:
        raise SystemExit(f"REFUSED: kit is {meta.get('project')}/{engine}, not {project}/{row['engine']}")
    rel_applier, _interpreter, kind = ENGINES[engine]
    master = (ENGINE_DIR / rel_applier).read_bytes()
    if args.limit:
        recipes = recipes[:args.limit]
    appliers = {"master": master}
    paper_source = None
    if kind == "script":
        paper = Path(args.paper_applier).read_bytes() if args.paper_applier else None
        if paper is None or sha256_bytes(paper) != row["applier_sha256"]:
            raise SystemExit(f"REFUSED: --paper-applier must be the paper's applier {row['applier_sha256']}")
        appliers = {"paper": paper, "master": master}
        paper_source = sha256_bytes(paper)
        result = run_script(args, project, kit, meta, manifest, recipes, appliers)
    else:
        appliers = {"paper": None, "master": master}
        result = run_splice(args, project, kit, meta, manifest, recipes, appliers)
    rows = result["rows"]
    labels = ("paper", "master")

    def count(pred):
        return sum(1 for r in rows if pred(r))
    applied_both = lambda r: all(r[label]["rc"] == 0 and r[label]["sha256"] for label in labels)
    if kind == "script":
        summary = {
            "g_mutants": len(rows),
            "applied_by_both": count(applied_both),
            "equal_sha256": count(lambda r: applied_both(r) and r["paper"]["sha256"] == r["master"]["sha256"]),
            "differ_sha256": count(lambda r: applied_both(r) and r["paper"]["sha256"] != r["master"]["sha256"]),
            "refused_by_paper_only": count(lambda r: r["paper"]["rc"] != 0 and r["master"]["rc"] == 0),
            "refused_by_master_only": count(lambda r: r["paper"]["rc"] == 0 and r["master"]["rc"] != 0),
            "refused_by_both": count(lambda r: r["paper"]["rc"] != 0 and r["master"]["rc"] != 0),
            "output_is_descriptor_splice": count(
                lambda r: applied_both(r) and r["master"]["sha256"] == r["splice_sha256"]),
        }
        ok = lambda r: applied_both(r) and r["paper"]["sha256"] == r["master"]["sha256"]
    else:
        summary = {
            "g_mutants": len(rows),
            "splices_on_seed": count(lambda r: r["splice_sha256"] is not None),
            "splice_refused": count(lambda r: r["splice_sha256"] is None),
        }
        ok = lambda r: r["splice_sha256"] is not None
    seed_applier = result["environment"].get("seed_applier")
    master_applier = {"path": "benchmark/r2t/" + rel_applier, "sha256": sha256_bytes(master)}
    identity_ok = True
    if seed_applier is not None:
        # Workers run the seed's copy (`go.mutation_runtime.seed_applier`);
        # master admits it when its identity constants are master's own.
        constants_ok = seed_applier["identity_constants"] == go_identity(master)
        identity_ok = seed_applier["sha256"] == row["applier_sha256"] and constants_ok
        master_applier = {"runtime": "the kit seed's " + seed_applier["path"],
                          "sha256": seed_applier["sha256"],
                          "identity_constants_match_master": constants_ok,
                          "catalogue_builder": master_applier}
    same_source = row["applier_sha256"] == master_applier["sha256"]
    bytes_ok = count(ok) == len(rows) and identity_ok
    if kind == "splice" and bytes_ok and not same_source and not row.get("reviewed_diff"):
        verdict = "unreviewed_diff"
    else:
        verdict = "equal" if bytes_ok else "differs"
    passed = verdict == "equal"
    report = {
        "schema": SCHEMA,
        "project": project,
        "engine": engine,
        "kind": kind,
        "appliers_run": kind == "script",
        "kit": {"path": str(kit), "kit_version": meta.get("kit_version"),
                "manifest_digest": manifest.get("digest"), **counts,
                "g_files": len({r["file"] for r in rows}), "limit": args.limit or None},
        "appliers": {
            "paper": {"sha256": row["applier_sha256"], "refs": [
                {"tag": t, "commit": c, "role": role} for t, c, role in row["refs"]],
                **({"supplied_file_sha256": paper_source} if paper_source else {})},
            "master": master_applier,
            "same_source": same_source,
            **({"reviewed_diff": row["reviewed_diff"]} if row.get("reviewed_diff") else {}),
        },
        "environment": result["environment"],
        "summary": summary,
        "verdict": verdict,
        "exceptions": [r for r in rows if not ok(r)],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": os.uname().nodename,
    }
    Path(args.out).write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    if args.rows:
        with open(args.rows, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
    print(json.dumps({"project": project, "verdict": report["verdict"], **summary}))
    return 0 if passed else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    verbs = parser.add_subparsers(dest="verb", required=True)
    s = verbs.add_parser("sources", help="verify the pinned paper appliers in a research checkout")
    s.add_argument("--research", required=True)
    s.add_argument("--project", action="append")
    s.add_argument("--write", help="write each paper applier to DIR/<project>/<file>")
    r = verbs.add_parser("run", help="apply every G mutant with both appliers and compare")
    r.add_argument("--project", required=True, choices=sorted(PAPER))
    r.add_argument("--kit", required=True)
    r.add_argument("--paper-applier", help="the paper's applier file (script engines)")
    r.add_argument("--seed-tar", help="seed workspace tar (default: the kit's exec seed)")
    r.add_argument("--work", default=os.path.join(os.environ.get("REQ2TEST_HOME", os.path.expanduser("~/.req2test")),
                                                  "applier-check"),
                   help="scratch directory, outside the worktree (default: $REQ2TEST_HOME/applier-check)")
    r.add_argument("--out", required=True, help="report JSON")
    r.add_argument("--rows", help="also write one JSONL row per G mutant")
    r.add_argument("--jobs", type=int, default=16)
    r.add_argument("--limit", type=int, default=0, help="check only the first N G mutants (smoke)")
    args = parser.parse_args(argv)
    return cmd_sources(args) if args.verb == "sources" else cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
