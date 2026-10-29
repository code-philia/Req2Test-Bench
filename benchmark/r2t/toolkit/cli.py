"""The extender's verbs: what BUILDS a benchmark from a repository.

`index`, `closures`, `index-prod`, `strip`, `sanitise`, `validate`,
`quality`, `release`, `manifest-baseline`, `stub-accept`, and the
environment builders `image`, `java-reality-spike`, `provision-coreshop`
and `provision-sylius`.
Registered into `python3 -m r2t.cli` by the composer at `r2t/cli.py`; not an
entry point of its own.  The handlers moved here whole from `r2t/cli.py` and
call the shared helpers through `bench_cli`, the module object, so a
self-test's replacement of one is seen here too.
"""
from __future__ import annotations

import json
import os

from ..bench import cli as bench_cli
from ..bench.repo import CORESHOP_BEHAT
from ..core.constants import PROD_INDEX_NAMES
# Constants only, and `ast`-only underneath: importing the Python
# production indexer here costs nothing and lets `--path`'s help name
# the default it would actually use.
from ..py.prod_index import PY_PROD_PATHS

#: The tag every verb registered by this component carries in `--help`.
PERSONA = "[extender]"



def cmd_image(args) -> int:
    """Run one independently gated EPUBCheck image-production phase."""
    from .epubcheck_image import (EPUBCheckImageRefused,
                                  produce_epubcheck_image)
    authority = args.docker_authority
    if not isinstance(authority, str) or not os.path.isabs(authority) \
            or os.path.normpath(authority) != authority:
        raise SystemExit(
            "REFUSED: image production requires --docker-authority as one "
            "normalized absolute path")
    if not os.path.isabs(args.out) or os.path.normpath(args.out) != args.out:
        raise SystemExit(
            "REFUSED: image production requires --out as one normalized "
            "absolute absent directory")
    try:
        result = produce_epubcheck_image(phase=args.phase, out=args.out)
    except EPUBCheckImageRefused as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, sort_keys=True, indent=1))
    return 0


def cmd_java_reality_spike(args) -> int:
    """Capture the separately gated EPUBCheck suite and closure fixtures."""
    from .epubcheck_reality import (EPUBCheckRealityRefused,
                                    capture_epubcheck_reality)
    authority = args.docker_authority
    if not isinstance(authority, str) or not os.path.isabs(authority) \
            or os.path.normpath(authority) != authority:
        raise SystemExit(
            "REFUSED: java reality spike requires --docker-authority as one "
            "normalized absolute path")
    if not os.path.isabs(args.image_transcript) \
            or os.path.normpath(args.image_transcript) != args.image_transcript:
        raise SystemExit(
            "REFUSED: java reality spike requires --image-transcript as one "
            "normalized absolute path")
    if not os.path.isabs(args.out) or os.path.normpath(args.out) != args.out:
        raise SystemExit(
            "REFUSED: java reality spike requires --out as one normalized "
            "absolute absent directory")
    try:
        result = capture_epubcheck_reality(
            image_transcript=args.image_transcript, out=args.out)
    except EPUBCheckRealityRefused as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, sort_keys=True, indent=1))
    return 0


#: What the PHP `index` body writes under `--artifacts`.
INDEX_ARTIFACTS = ("php_index.json", "matches.json", "steps.json",
                   "alias_table.json", "alias_table_ambiguous.json",
                   "autowirable_types.json", "autowirable_named.json")


def _refuse_existing_artifacts(artifacts: str, names) -> None:
    """A live producer never replaces an artifact that is already there.

    `--artifacts` defaults to the canonical data root's project directory,
    where `php_prod_index.json` is the bundle's byte-pinned production index
    and `matches.json` is the extraction the release was built from.  A
    re-derivation that lands on those paths would silently replace pinned
    inputs (the same rule `mutation_audit.reserve_output` applies to every
    mutation artifact), so an occupied destination is refused before anything
    is written.
    """
    present = [name for name in names
               if os.path.lexists(os.path.join(artifacts, name))]
    if present:
        raise SystemExit(
            f"REFUSED: {', '.join(present)} already exist(s) under "
            f"{artifacts}; a re-derivation never replaces an artifact in "
            f"place. Pass --artifacts naming a fresh directory.")


def _config_root(repo: str, gold: str, bp) -> str:
    """The Behat config tree — in the repo before stripping, gold after.

    Probed through the services entry, or the suites entry for a project
    that has no services file at all: either way it is a file the strip
    moves, which is the question being asked.
    """
    probe = bp.services_entry or bp.suites_entry
    if os.path.isfile(os.path.join(repo, bp.config_dir, probe)):
        return repo
    return gold


def cmd_index(args) -> int:
    """Static PHP index + step matching, both done inside the container."""
    other = bench_cli._other_stack(args, "cmd_index")
    if other is not None:
        return other(args)
    from ..bench.harness import DockerRunner
    from ..bench.repo import behat_project
    b = bench_cli._boundary(args)
    bp = behat_project(b)
    if not os.path.isdir(os.path.join(b.repo_root, bp.index_guard)):
        raise SystemExit("REFUSED: the repo is already stripped; index before strip")

    image_id = bench_cli._bound_container_image(args.container)
    print(f"image_id: {image_id}")
    _refuse_existing_artifacts(args.artifacts, INDEX_ARTIFACTS)
    os.makedirs(args.artifacts, exist_ok=True)
    runner = DockerRunner(args.container, workdir=args.workdir)
    bench = os.path.join(b.repo_root, "_bench")
    os.makedirs(bench, exist_ok=True)
    for f in ("analyze_php.php", "match_steps.php"):
        src = os.path.join(bench_cli.PACKAGE_DIR, "php", f)
        with open(src, encoding="utf-8") as r, \
                open(os.path.join(bench, f), "w", encoding="utf-8") as w:
            w.write(r.read())

    paths = " ".join(f"--path {p}" for p in bp.index_paths)
    cp = runner.run(f"php _bench/analyze_php.php --root {runner.workdir} {paths} "
                    f"--out _bench/php_index.json")
    print(cp.stderr.strip() or cp.stdout.strip())

    from ..core.gherkin import parse_feature_file
    texts, per_item = set(), {}
    root = os.path.join(b.repo_root, args.features)
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = sorted(dirnames)
        for f in sorted(files):
            if not f.endswith(".feature"):
                continue
            path = os.path.join(dirpath, f)
            rel = os.path.relpath(path, b.repo_root).replace(os.sep, "/")
            feat = parse_feature_file(path, allow_tag_gaps=b.project == "prestashop")
            bg = [s.text for s in feat.background.steps] if feat.background else []
            for sc in feat.scenarios:
                steps = bg + [s.text for s in sc.steps]
                per_item[f"{b.project}/{rel}:{sc.line}"] = steps
                texts.update(steps)
    with open(os.path.join(bench, "steps.json"), "w", encoding="utf-8") as fh:
        json.dump({"steps": sorted(texts)}, fh)
    print(f"collected {len(per_item)} scenarios / {len(texts)} distinct step texts")

    cp = runner.run("php _bench/match_steps.php --index _bench/php_index.json "
                    "--steps _bench/steps.json --out _bench/matches.json")
    print(cp.stderr.strip() or cp.stdout.strip())

    import shutil
    for f in ("php_index.json", "steps.json"):
        shutil.copyfile(os.path.join(bench, f), os.path.join(args.artifacts, f))
    # The binding this run was made under travels with the matches, so a
    # closure built from them names the image whose Behat answered.  The
    # artifacts copy is the matcher's document plus `image_id`, re-encoded
    # by Python (indent 1, sorted keys); the PHP bytes stay in `_bench/`.
    with open(os.path.join(bench, "matches.json"), encoding="utf-8") as fh:
        matches = json.load(fh)
    matches["image_id"] = image_id
    with open(os.path.join(args.artifacts, "matches.json"), "w", encoding="utf-8") as fh:
        json.dump(matches, fh, indent=1, sort_keys=True, ensure_ascii=False)

    if bp.services_entry is None:
        # Both artifacts below are read OFF the container's service
        # container: which type each service id wires, and which types it
        # can autowire. A project that wires no services through Symfony
        # has neither, and inventing an empty alias table would read as a
        # container that answered and knew nothing.
        print(f"{b.project} declares no Behat service wiring: no alias "
              f"table, no autowirable types")
        return 0

    from .behat_wiring import alias_table, load_services
    with open(os.path.join(args.artifacts, "php_index.json"), encoding="utf-8") as fh:
        idx = json.load(fh)
    services = load_services(os.path.join(b.repo_root, bp.config_dir,
                                          bp.services_entry))
    ua, multi = alias_table(services, idx)
    with open(os.path.join(args.artifacts, "alias_table.json"), "w", encoding="utf-8") as fh:
        json.dump(ua, fh, indent=1, sort_keys=True)
    with open(os.path.join(args.artifacts, "alias_table_ambiguous.json"), "w",
              encoding="utf-8") as fh:
        json.dump({k: sorted(v) for k, v in multi.items() if len(v) > 1}, fh,
                  indent=1, sort_keys=True)
    print(f"alias table: {len(ua)} unambiguous, "
          f"{sum(1 for v in multi.values() if len(v) > 1)} ambiguous")

    cp = runner.run(f"bin/console debug:autowiring --all --env={bp.app_env} "
                    f"--no-ansi")
    types = _parse_autowirable(cp.stdout)
    with open(os.path.join(args.artifacts, "autowirable_types.json"), "w",
              encoding="utf-8") as fh:
        json.dump(types["bare"], fh, indent=0)
    with open(os.path.join(args.artifacts, "autowirable_named.json"), "w",
              encoding="utf-8") as fh:
        json.dump(types["named"], fh, indent=1)
    print(f"container can autowire {len(types['bare'])} bare types and "
          f"{sum(len(v) for v in types['named'].values())} "
          f"parameter-name-specific aliases")
    return 0


#: What production code is, for indexing purposes: the component library and
#: the bundles that wire it into Pimcore.  `src/CoreShop/Behat` is test code
#: and is covered by `index`.
#:
#: The ROW rather than a second literal (`repo.CORESHOP_BEHAT.prod_paths`):
#: `--path`'s help text names this default and `cmd_index_prod` uses the
#: boundary's own, and two copies of one tuple could only ever disagree.
PROD_PATHS = CORESHOP_BEHAT.prod_paths

#: Where `index-prod` puts the analyzer and its output while it runs.
#:
#: NOT `_bench/`, the obvious place: `_bench` is a SUBSTRATE_ROOT, so any file
#: appearing there that is not in SUBSTRATE_VOLATILE is reported as `added` by
#: `verify_substrate` — which aborts the next item as tampering.  `var/` is
#: outside the hashed roots, so this stage cannot disturb a baseline even if
#: it is interrupted before its cleanup.
PROD_SCRATCH = "var/bench_index"


def _index_prod_python(args) -> int:
    """`index-prod` for a Python project -- `ast`, on the host, no container.

    The PHP half of this verb has to reach a container: `analyze_php.php`
    needs nikic/php-parser out of the project's own `vendor/`, so it is a live
    Docker workload bound to the named container's immutable image ID.
    Python ships its parser, so none of that applies here -- this reads files
    and writes one JSON file, which is why `index-prod` dispatches on the
    stack's LANGUAGE before reaching the PHP body.
    """
    from ..py.prod_index import build_prod_index
    from ..core.paths import project_path
    b = bench_cli._boundary(args)
    # `--artifacts` is a TOP-LEVEL global whose default is CoreShop's
    # canonical artifacts directory, and nothing cross-checks it against the
    # project the boundary names.  Before this verb had a Python branch it
    # could not write anywhere at all, so the mismatch was unreachable; now
    # `index-prod --boundary config/boundary_python_docx.yml` with no
    # `--artifacts` would drop a Python index into CoreShop's tree beside the
    # sha-pinned php_prod_index.json.  Refuse rather than write there.
    expected = project_path(b.project, "artifacts")
    if os.path.abspath(args.artifacts) != os.path.abspath(expected):
        raise SystemExit(
            f"REFUSED: --artifacts {args.artifacts!r} is not the artifacts "
            f"directory of the project this boundary names ({b.project!r}); "
            f"expected {expected!r}. Pass --artifacts explicitly, or omit it "
            f"only when the boundary's project owns the default.")
    _refuse_existing_artifacts(args.artifacts, (PROD_INDEX_NAMES["python"],))
    os.makedirs(args.artifacts, exist_ok=True)
    paths = list(args.path or PY_PROD_PATHS)
    doc = build_prod_index(b.repo_root, paths)
    dst = os.path.join(args.artifacts, PROD_INDEX_NAMES["python"])
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)

    c = doc["counts"]
    print(f"{c['files']} files, {c['classes']} classes, {c['methods']} "
          f"methods ({c['public_methods']} public, {c['properties']} "
          f"properties), {c['errors']} errors -> {dst}")
    print(f"  {os.path.getsize(dst) / 1e6:.1f} MB")
    # Loud, because the consequence is quiet: a file that did not parse
    # contributes no methods, so every line covered in it joins to nothing
    # and BOTH sides of the comparison shrink by the same invisible amount.
    for rel, why in sorted(doc["errors"].items()):
        print(f"  UNPARSED {rel}: {why}")
    return 0


def _index_prod_ruby(args) -> int:
    """Ruby's source-only Ripper producer runs in the bound immutable image."""
    from .prod_index_rb import build_prod_index
    from ..core.paths import project_path
    b = bench_cli._boundary(args)
    expected = project_path(b.project, "artifacts")
    if os.path.abspath(args.artifacts) != os.path.abspath(expected):
        raise SystemExit(f"REFUSED: --artifacts must name {b.project!r}'s artifacts directory: {expected}")
    image = bench_cli._bound_container_image(args.container)
    _refuse_existing_artifacts(args.artifacts, (PROD_INDEX_NAMES["ruby"],))
    doc = build_prod_index(b.repo_root, args.path, image=image)
    from ..bench.metrics import load_prod_index
    # Validate the same bytes scoring consumes before admitting the artifact.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="r2t-ruby-index-check-") as scratch:
        check_path = os.path.join(scratch, "index.json")
        with open(check_path, "w", encoding="utf-8") as stream:
            json.dump(doc, stream)
        load_prod_index(check_path)
    os.makedirs(args.artifacts, exist_ok=True)
    dst = os.path.join(args.artifacts, PROD_INDEX_NAMES["ruby"])
    with open(dst, "x", encoding="utf-8") as stream:
        json.dump(doc, stream, indent=1, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"out": dst, "image_id": image, **doc["counts"]}, sort_keys=True))
    for entry in doc["unsupported"]:
        print(f"UNSUPPORTED {entry['file']}:{entry['line']}: {entry['reason']}")
    return 0


def cmd_index_prod(args) -> int:
    """Static index of production code — per-class method spans.

    `index` records a method only when it carries a Behat annotation, so
    nothing said which production method a recorded CALL EVENT names.  That
    mapping -- a callee's file and declaration line to a public production
    method -- is what turns a run's `direct_calls` into a comparable set of
    API calls, so it is indexed separately here.

    PHP/Python production code is never removed, so their indexes remain
    valid against the stripped tree. Go needs the complete original source
    and explicit witnessed closures to derive each selected-glue context.
    The PHP analyzer also leaves no trace: installed `_bench/analyze_php.php`
    is under the digest baseline and is
    deliberately NOT refreshed, because doing so would silently invalidate the
    substrate every run verifies.

    A PYTHON project is indexed on the host instead -- see
    `_index_prod_python`.  Dispatched on the stack's LANGUAGE rather than
    through `_other_stack`, because the two implementations differ by which
    parser they can reach and not by which framework runs the tests: `ast` is
    the answer for any Python project whatever its runner, and routing it
    through the stack registry would need a verb in `stacks/behave.py` that
    has nothing to do with behave.  A PHP project reaches the body below,
    which runs `analyze_php.php` inside the named container and records that
    container's immutable image ID. Go uses its qualified static producer
    before runnable-stack dispatch. Other languages are refused by name;
    Java's production index is staged by its
    operator under `PROD_INDEX_NAMES["java"]` instead.
    """
    # Static Go indexing is available before the complete Godog execution
    # stack is registered. Keep the other languages on their existing route.
    if any(getattr(args, key, None) is not None
           for key in ("profile", "closures", "image_id")):
        profile = bench_cli._stack_profile(args)
        if profile.language == "go":
            from ..go.prod_index_cli import cmd_index_prod as go_index_prod
            from ..go.context import ContextRefused
            from ..go.prod_index import GoIndexRefused
            try:
                return go_index_prod(args, profile)
            except (GoIndexRefused, ContextRefused, OSError, ValueError) as error:
                raise SystemExit(str(error)) from error
    language = bench_cli._stack(args).LANGUAGE
    if language == "python":
        return _index_prod_python(args)
    if language == "ruby":
        return _index_prod_ruby(args)
    if language != "php":
        raise SystemExit(
            f"REFUSED: index-prod has no production analyzer for LANGUAGE "
            f"{language!r}: its non-Python body is `analyze_php.php` inside "
            f"the named container. A Java operator stages the direct-call "
            f"index under {PROD_INDEX_NAMES['java']!r} instead "
            f"(core.constants.PROD_INDEX_NAMES).")
    import shutil
    import time as _time
    from ..bench.harness import DockerRunner
    from ..bench.repo import behat_project
    b = bench_cli._boundary(args)
    image_id = bench_cli._bound_container_image(args.container)
    print(f"image_id: {image_id}")
    _refuse_existing_artifacts(args.artifacts, (PROD_INDEX_NAMES["php"],))
    os.makedirs(args.artifacts, exist_ok=True)
    scratch = os.path.join(b.repo_root, PROD_SCRATCH)
    os.makedirs(scratch, exist_ok=True)
    shutil.copyfile(os.path.join(bench_cli.PACKAGE_DIR, "php", "analyze_php.php"),
                    os.path.join(scratch, "analyze_php.php"))

    runner = DockerRunner(args.container, workdir=args.workdir)
    paths = list(args.path or behat_project(b).prod_paths)
    started = _time.time()
    cp = runner.run(f"php {PROD_SCRATCH}/analyze_php.php --root {runner.workdir} "
                    + " ".join(f"--path {p}" for p in paths)
                    + f" --out {PROD_SCRATCH}/{PROD_INDEX_NAMES['php']}",
                    timeout=1800)
    wall = _time.time() - started
    print(cp.stderr.strip() or cp.stdout.strip())

    produced = os.path.join(scratch, PROD_INDEX_NAMES["php"])
    if cp.returncode != 0 or not os.path.isfile(produced):
        shutil.rmtree(scratch, ignore_errors=True)
        raise SystemExit(f"analyzer failed (rc={cp.returncode})")
    dst = os.path.join(args.artifacts, PROD_INDEX_NAMES["php"])
    shutil.copyfile(produced, dst)
    shutil.rmtree(scratch, ignore_errors=True)
    if os.path.isdir(scratch):
        # The analyzer runs as root inside the container, so its output can
        # outlive a host-side rmtree if `var/` was ever chowned.
        runner.run(f"rm -rf {PROD_SCRATCH}")

    with open(dst, encoding="utf-8") as fh:
        idx = json.load(fh)
    classes = sum(len(f["classes"]) for f in idx["files"].values())
    methods = sum(len(c.get("methods") or [])
                  for f in idx["files"].values() for c in f["classes"])
    print(f"{len(idx['files'])} files, {classes} classes, {methods} methods, "
          f"{len(idx['errors'])} errors -> {dst}")
    print(f"  {os.path.getsize(dst)/1e6:.1f} MB, {wall:.1f}s wall")

    # The stage's own proof that it left no trace: a leftover under a hashed
    # root would abort the next item as tampering, and finding that out here
    # is much cheaper than finding it out mid-sweep.
    manifest_path = os.path.join(args.gold, "strip_manifest.json")
    if os.path.isfile(manifest_path):
        from ..bench.repo import load_manifest, verify_substrate
        rep = verify_substrate(load_manifest(manifest_path), b)
        print(f"  substrate after: {len(rep['changed'])} changed, "
              f"{len(rep['missing'])} missing, {len(rep['added'])} added")
    return 0


def _parse_autowirable(text: str) -> dict:
    """`debug:autowiring` output -> what the container can resolve.

    Two kinds of entry, and the difference matters: a BARE type resolves
    for any parameter name, while a NAMED alias (`FactoryInterface
    $productFactory`) resolves only for that exact parameter name.  An
    earlier version captured bare types only, which made the
    autowirability figure in SPEC §4.1 unreproducible from the shipped
    artifacts and hid the fact that most CoreShop factories and
    repositories are wired by parameter NAME.
    """
    import re
    bare, named = set(), {}
    for ln in text.splitlines():
        s = ln.strip()
        m = re.match(r"^([A-Za-z_\\][\w\\]*)(?:\s+\$(\w+))?(\s+-\s+alias:.*)?$", s)
        if not m or "\\" not in m.group(1):
            continue
        if m.group(2):
            named.setdefault(m.group(1), set()).add(m.group(2))
        else:
            bare.add(m.group(1))
    return {"bare": sorted(bare),
            "named": {k: sorted(v) for k, v in sorted(named.items())}}


def cmd_closures(args) -> int:
    other = bench_cli._other_stack(args, "cmd_closures")
    if other is not None:
        return other(args)
    from .behat_suites import SUITE_MAP_NAME
    from .closure import load_extractor
    from ..bench.repo import behat_project
    from ..core.gherkin import parse_feature_file
    b = bench_cli._boundary(args)
    bp = behat_project(b)
    cfg_root = _config_root(b.repo_root, args.gold, bp)
    ex = load_extractor(
        os.path.join(args.artifacts, "php_index.json"),
        os.path.join(args.artifacts, "matches.json"),
        args.boundary,
        # None for a project with no Symfony wiring: its suites name their
        # contexts by class, so there is nothing for the extractor to
        # resolve an id through.
        services_entry=(None if bp.services_entry is None else
                        os.path.join(cfg_root, bp.config_dir,
                                     bp.services_entry)),
        suites_entry=os.path.join(cfg_root, bp.config_dir, bp.suites_entry),
        repo_root=b.repo_root,
        # Written by the strip, from the tree that still had every suite
        # file. Absent before a strip, and absent for a project that is not
        # suite-scoped -- `load_extractor` builds the map itself then.
        suite_map_path=os.path.join(args.gold, SUITE_MAP_NAME))
    if ex.registered_classes:
        print(f"registered context universe: {len(ex.registered_classes)} classes")

    out = []
    root = os.path.join(b.repo_root, args.features)
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = sorted(dirnames)
        for f in sorted(files):
            if not f.endswith(".feature"):
                continue
            path = os.path.join(dirpath, f)
            rel = os.path.relpath(path, b.repo_root).replace(os.sep, "/")
            feat = parse_feature_file(path, allow_tag_gaps=b.project == "prestashop")
            for sc in feat.scenarios:
                out.append(ex.closure_for(f"{b.project}/{rel}:{sc.line}",
                                          feat, sc).to_json())
    dst = os.path.join(args.artifacts, "closures.json")
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)

    import statistics
    sizes = [len(c["files"]) for c in out]
    print(f"{len(out)} items -> {dst}")
    print(f"  closure files: min {min(sizes)} median "
          f"{statistics.median(sizes):.0f} max {max(sizes)}")
    print(f"  unmatched steps: {sum(c['counts']['steps_unmatched'] for c in out)}")
    print(f"  answered entirely by retained code: "
          f"{sum(1 for c in out if c['answered_entirely_by_retained'])}")
    probs = sum(1 for c in out if c["problems"])
    print(f"  items with extractor problems: {probs}")
    return 0


def cmd_strip(args) -> int:
    # Dispatched like index/closures: `repo.strip_repo` refuses any tree
    # that is not CoreShop, so a behave project's strip is a different body,
    # not a parameterisation of this one.  No profile still means behat.
    other = bench_cli._other_stack(args, "cmd_strip")
    if other is not None:
        return other(args)
    from ..bench.repo import strip_repo
    b = bench_cli._boundary(args)
    man = strip_repo(b, args.gold, os.path.join(bench_cli.PACKAGE_DIR, "php"), dry_run=args.dry_run)
    print(f"{'would move' if args.dry_run else 'moved'} {len(man.moved)} test-code "
          f"files and {len(man.moved_config)} config files -> {args.gold}")
    if not args.dry_run:
        print(f"patched: {man.patched}")
        print(f"installed: {man.installed}")
    return 0


def cmd_sanitise(args) -> int:
    """Remove the answer's other copies (git history, extraction artifacts,
    compiled container) from an already-stripped repo."""
    if args.dump_autoload:
        bench_cli._refuse_unbound_live_workload(
            "sanitise --dump-autoload", "transient preprocessing")
    from ..bench.harness import DockerRunner
    from ..bench.repo import sanitise_repo
    b = bench_cli._boundary(args)
    moved = sanitise_repo(b.repo_root, args.gold)
    if args.dump_autoload:
        # Composer's optimised classmap still maps every removed class to
        # its (now absent) path — 134 CoreShop\Behat context entries.  A
        # regenerated classmap drops them; PSR-4 fallback still resolves
        # whatever a system under test writes.
        cp = DockerRunner(args.container, workdir=args.workdir).run(
            "composer dump-autoload -o --no-interaction")
        moved.append(f"composer dump-autoload -o (rc={cp.returncode})")
    for m in moved:
        print(" ", m)
    print(f"{len(moved)} sanitisation actions")
    return 0


def cmd_validate(args) -> int:
    if getattr(args, "publication_v3", False):
        from ..bench.validate import run_publication_v3
        info = run_publication_v3(
            args, harness_factory=lambda: bench_cli._harness(args),
            live_validator=lambda: bench_cli._require_bound_live_worker(args))
        print(json.dumps(info, indent=1))
        return 0
    from ..data.release import admit_pre_execution
    boundary = bench_cli._boundary(args)
    with open(os.path.join(args.artifacts, "closures.json"), encoding="utf-8") as fh:
        closures = json.load(fh)
    closures, _policy = admit_pre_execution(
        closures, boundary.project, getattr(args, "item", ()))
    bench_cli._require_bound_live_worker(args)
    from ..bench.runner import _ExecutionLock
    from ..bench.validate import summarise, validate_all
    with _ExecutionLock(boundary.repo_root):
        h, _b, _man = bench_cli._harness(args)
        if args.limit:
            closures = closures[:args.limit]
        if args.item:
            closures = [c for c in closures if c["item_id"] in set(args.item)]
        out = os.path.join(args.artifacts, args.out)
        validate_all(h, args.gold, closures, out, repeats=args.repeats,
                     timeout=args.timeout, resume=not args.no_resume)
    print(json.dumps(summarise(out), indent=1))
    return 0


def cmd_interfaces(args) -> int:
    """The declared interaction surface, per item (TARGET_INTERFACES_SPEC)."""
    other = bench_cli._other_stack(args, "cmd_interfaces")
    if other is not None:
        return other(args)
    from .interfaces import extract_all, load_extractor, summary, write_interfaces
    ex = load_extractor(os.path.join(args.artifacts, "php_index.json"),
                        os.path.join(args.artifacts, "php_prod_index.json"),
                        args.boundary)
    with open(os.path.join(args.artifacts, "closures.json"), encoding="utf-8") as fh:
        closures = json.load(fh)
    items = extract_all(closures, ex)
    dst = os.path.join(args.artifacts, "interfaces.json")
    write_interfaces(items, dst)
    print(json.dumps(dict(summary(items), wrote=dst), indent=1))
    return 0


def cmd_checked_interfaces(args) -> int:
    """The product methods an item's actions and checks call (V2 spec §3, §8).

    Every input is an argument and the artifact records each one's digest,
    which is its identity -- unlike `interfaces`, which reads the artifacts
    directory by convention, this verb reads a gold run, a pinned index and a
    released item pool that do not have to live together.
    """
    from ..bench.metrics import MetricsInputError
    from .checked_interfaces import CheckedInterfacesRefused, derive, write
    try:
        doc = derive(gold=args.gold, index=args.index, boundary=args.boundary,
                     items=args.items, source_root=args.source_root)
    except (CheckedInterfacesRefused, MetricsInputError) as exc:
        # A stale Python production index is the metric's own refusal and is
        # this verb's too: it would map every callee unmapped.
        raise SystemExit(f"REFUSED: {exc}") from exc
    write(doc, args.out)
    print(json.dumps(dict(doc["summary"], wrote=args.out),
                     indent=1, sort_keys=True))
    return 0


def cmd_quality(args) -> int:
    from .quality import build, dependencies_for
    b = bench_cli._boundary(args)
    # Which dependencies an item can HAVE is a property of the stack, not of
    # the scenario: `["database"]` unconditionally is right for CoreShop and
    # is a false claim about a library that has none (D6).
    n = build(b, args.items, os.path.join(args.artifacts, "closures.json"),
              os.path.join(args.artifacts, "quality.json"), args.v8,
              gold_root=args.gold,
              deps=dependencies_for(bench_cli._stack_profile(args).framework))
    print(f"wrote quality fields for {n} items")
    return 0


def cmd_release(args) -> int:
    from .release_build import build_release
    # The declared interaction surface exists for behat, behave and the
    # reviewed cucumber_ruby/Go mappings. Java cucumber remains withheld in v1
    # (TARGET_INTERFACES_SPEC D4) and releases without the field.
    interfaces_path = (os.path.join(args.artifacts, "interfaces.json")
                       if bench_cli._stack_profile(args).framework
                       in ("behat", "behave", "cucumber_ruby", "godog") else None)
    # The v2 list (TARGET_INTERFACES_V2_SPEC section 5) is NOT gated on the
    # framework: it is recorded by the harness rather than read out of a
    # per-stack index, so Java cucumber carries it like every other stack.
    # It is an explicit path because the `checked-interfaces` derivation reads
    # gold rows, not the extraction artifacts this verb is pointed at.
    project = bench_cli._boundary(args).project
    dispositions = None
    if getattr(args, "item_dispositions", None):
        dispositions = _load_item_dispositions(args.item_dispositions,
                                               args.items, project)
    info = build_release(args.artifacts, args.items, args.out,
                         min_live_steps=args.min_live_steps,
                         project=project,
                         items_name=args.items_name,
                         interfaces_path=interfaces_path,
                         checked_interfaces_path=getattr(
                             args, "checked_interfaces", None),
                         item_dispositions=dispositions)
    print(json.dumps(info, indent=1))
    return 0


def _load_item_dispositions(path: str, items_path: str,
                            project: str) -> dict:
    """An operator's named exclusions, `{item_id: {stage, reasons}}`.

    `build_release` already takes this mapping and writes every non-released
    item into `exclusions.csv` and `summary.json`'s reasons, which is what
    keeps a project's omissions (a suite that cannot run in the harness) in
    the release's own record instead of in the operator's memory.  Every key
    must name an item of THIS project in the pool: `build_release` skips the
    other projects' items before it consults the mapping (the default pool
    holds five projects), so a disposition for any other id would be
    silently unused, and a typo'd exclusion is an item released by accident.
    The shape is checked here, where the operator's file is read, so a
    malformed entry names the file rather than surfacing as a build error.
    """
    from ..data.subsets import SubsetRefused, read_items
    try:
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"REFUSED: cannot read {path}: {exc}") from exc
    if not isinstance(document, dict) or not document:
        raise SystemExit(
            f"REFUSED: {path} is not a non-empty JSON object mapping item ids "
            "to {\"stage\": ..., \"reasons\": [...]}")
    for iid, decision in document.items():
        if not isinstance(decision, dict) \
                or set(decision) != {"stage", "reasons"} \
                or not isinstance(decision["stage"], str) \
                or not decision["stage"] \
                or not isinstance(decision["reasons"], list) \
                or any(not isinstance(reason, str) or not reason
                       for reason in decision["reasons"]):
            raise SystemExit(
                f"REFUSED: {path}: malformed disposition for {iid!r}; each "
                "entry is {\"stage\": <str>, \"reasons\": [<str>, ...]}")
    try:
        pool = {iid for iid, line in read_items(items_path)
                if json.loads(line).get("project") == project}
    except SubsetRefused as exc:
        raise SystemExit(str(exc)) from exc
    unknown = sorted(set(document) - pool)
    if unknown:
        raise SystemExit(
            f"REFUSED: {len(unknown)} disposition(s) name no {project!r} item "
            f"of {items_path} (e.g. {unknown[0]!r}); a disposition nothing "
            "consumes is an exclusion that never happened")
    return document


def cmd_provision_coreshop(args) -> int:
    """Build the one pinned CoreShop environment recipe."""
    from ..core.paths import data_root
    from .provision_coreshop import ProvisionRefused, provision
    try:
        report = provision(args.data_root or data_root())
    except ProvisionRefused as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(report, indent=1))
    return 0


def cmd_provision_sylius(args) -> int:
    """Build the one pinned Sylius API-arm environment recipe."""
    from ..core.paths import data_root
    from .provision_sylius import ProvisionRefused, provision
    try:
        report = provision(args.data_root or data_root(),
                           stop_after_install=args.stop_after_install,
                           resume_seed=args.resume_seed)
    except ProvisionRefused as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(report, indent=1))
    return 0


def cmd_stub_accept(args) -> int:
    """§3.10's stub acceptance: the corpus half here, the PHP half in the
    container."""
    other = bench_cli._other_stack(args, "cmd_stub_accept")
    if other is not None:
        return other(args)
    from .stub import acceptance
    info = acceptance(args.release, args.closures or os.path.join(
        args.artifacts, "closures.json"))
    print(json.dumps(info, indent=1))
    return 0


def cmd_manifest_baseline(args) -> int:
    """Record the current tree's digests as the integrity baseline.

    A solution's PHP executes as root on a read-write bind mount of the
    repository, so it can rewrite the recorder that scores it, the retained
    hook that isolates the database, or production code — and nothing would
    notice.  This writes the digests that make such a change detectable.

    It asserts nothing about whether the tree is currently clean.  That has
    to be established separately; for CoreShop the check is a diff of the
    production sources against an independent copy of the same checkout, and
    `--verify-against` performs it.

    The digests are taken through the STACK's `integrity_baseline` seam, not
    through `repo.baseline_substrate` directly.  For behat and behave those
    are the same object, so every CoreShop and python-docx invocation is
    unchanged byte for byte.  For a stack where one of the hashed files is a
    BUILD SCRIPT they are not: `stacks.cucumber.integrity_baseline` reads
    `pom.xml` BEFORE its bytes become the definition of "unchanged" and
    refuses a surefire configuration that unpins the exit-code witness, a
    pom carrying no coverage recipe, or a workspace with no harness runner.
    This verb is the only production entry point to baselining, so calling
    the shared function from here left all three refusals reachable from
    nothing but that module's own selftest.
    """
    from ..bench.repo import verify_substrate
    from ..stacks import verb as stack_verb
    stack = bench_cli._stack(args)
    if stack.FRAMEWORK == "godog":
        # A fresh Go seed precedes its worker and native closure census.
        # Baseline the preserved strip copy without constructing a runtime.
        b, man = stack.baseline_inputs(args)
    else:
        _h, b, man = bench_cli._harness(args)
    # Resolved BEFORE the tree work below: a stack that cannot baseline at
    # all should say so before `--verify-against` walks two checkouts.
    take_baseline = stack_verb(stack, "integrity_baseline")
    manifest_path = os.path.join(args.gold, "strip_manifest.json")

    if args.verify_against:
        import filecmp
        if stack.FRAMEWORK == "godog":
            from ..go.prod_index import GO_PROD_PATHS
            roots = GO_PROD_PATHS
        else:
            roots = ("src",)
        diff = []
        for path in roots:
            other = os.path.join(args.verify_against, path)
            mine = os.path.join(man.repo_root, path)
            if not os.path.isdir(other):
                raise SystemExit(f"no such tree: {other}")
            diff.extend(_diff_trees(mine, other, b))
            if stack.FRAMEWORK == "godog":
                # The first baseline must also detect production removed
                # from the disposable copy, including an entire source root.
                diff.extend(_diff_trees(other, mine, b))
        if stack.FRAMEWORK == "godog":
            diff = sorted(set(diff))
        print(f"production files differing from {args.verify_against}: "
              f"{len(diff)}")
        for rel in diff[:20]:
            print(f"  {rel}")
        if diff and not args.force:
            raise SystemExit(
                "REFUSED: the tree differs from the reference copy, so it is "
                "not a safe baseline. Investigate first, or pass --force if "
                "the differences are understood and intended.")
        del filecmp

    if man.digests and not args.force:
        report = verify_substrate(man, b)
        if report["changed"] or report["missing"] or report["added"]:
            raise SystemExit(
                "REFUSED: a baseline already exists and the tree no longer "
                "matches it. Re-baselining now would launder whatever changed "
                f"({len(report['changed'])} changed, "
                f"{len(report['missing'])} missing, {len(report['added'])} "
                "added). Investigate first, then pass --force.")

    info = take_baseline(man, b, manifest_path)
    print(json.dumps(info, indent=1))
    return 0


def _diff_trees(mine: str, other: str, boundary) -> list:
    """Production files that differ between two copies of the same checkout."""
    from ..core.boundary import PRODUCTION
    out = []
    for dirpath, dirnames, names in os.walk(mine):
        dirnames[:] = sorted(dirnames)
        for n in sorted(names):
            full = os.path.join(dirpath, n)
            rel = os.path.relpath(full, os.path.dirname(mine))
            rel = rel.replace(os.sep, "/")
            if boundary.classify(rel) != PRODUCTION:
                continue
            twin = os.path.join(other, os.path.relpath(full, mine))
            if not os.path.isfile(twin):
                out.append(f"{rel} (absent in reference)")
                continue
            with open(full, "rb") as a, open(twin, "rb") as b_fh:
                if a.read() != b_fh.read():
                    out.append(rel)
    return out


def cmd_target_regions(args) -> int:
    """Resolve a reviewed target body map to its per-item covered-line sets."""
    from ..core.source_view import ViewRefused
    from ..data.profile import load_profile
    from .source_views import java_tools_from_environment
    from .target_regions import resolve_regions, write_regions
    profile = load_profile(args.profile)
    try:
        # The same launch input every other Java-map consumer takes: the map
        # names `.java` bodies, whose spans only a compiler can give.
        tools = java_tools_from_environment() if profile.project in ('algorand-sdk', 'kapua') else {}
        if profile.project == 'coddy-agent':
            from ..bench.runner import _load_release
            from .source_views import go_tools_for_release
            if not args.release or not args.go_scratch:
                raise ViewRefused('Go target regions require --release and --go-scratch')
            tools = go_tools_for_release(_load_release(args.release),
                                         args.go_scratch, go=args.go)
        document = resolve_regions(
            map_path=args.map, source_root=args.source_root,
            readable_paths=tuple(profile.readable_paths),
            project=profile.project, **tools)
    except ViewRefused as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    write_regions(document, args.out)
    print(json.dumps({"out": args.out, **document["summary"],
                      "map_file_sha256": document["map_file_sha256"],
                      "source_files_digest": document["source_files_digest"]},
                     sort_keys=True, indent=1))
    return 0


def cmd_control_floors(args) -> int:
    """Measure what a wrong-but-plausible test already scores, from run rows."""
    from ..bench import metrics as M
    from .control_floors import (FloorsInputError, control_floors,
                                 write_floors)
    boundary = bench_cli._boundary(args)

    def rows(paths):
        out = {}
        for path in paths or ():
            for item_id, row in M.read_runs(path).items():
                out[item_id] = row
        return out

    controls = {role: rows(paths) for role, paths in
                (("assertion_stripped_gold", args.stripped),
                 ("stub", args.stub)) if paths}
    try:
        document = control_floors(
            project=boundary.project, gold_rows=rows(args.gold),
            boundary=boundary,
            prod_index=(M.load_prod_index(args.prod_index)
                        if args.prod_index else None),
            regions=(M.load_target_regions(args.target_regions)
                     if args.target_regions else None),
            controls=controls)
    except (FloorsInputError, M.MetricsInputError) as exc:
        message = str(exc)
        raise SystemExit(message if message.startswith("REFUSED: ")
                         else f"REFUSED: {message}") from exc
    write_floors(document, args.out)
    print(json.dumps({"out": args.out, **document["floors"]},
                     sort_keys=True, indent=1, default=str))
    return 0


def register(verbs, request) -> None:
    """Every extender verb, in the order `python3 -m r2t.cli` lists them."""
    from ..data.release import DEFAULT_ITEMS_NAME
    command = request.command


    if command == "image":
        # Like the publication-only merge grammar below, add this stopped
        # route only when it is the selected command.  The repository freezes
        # argparse's legacy help/error bytes, including the top-level choice
        # list, so an independently gated producer must not rewrite those
        # diagnostics for every unrelated command.
        p = verbs.add_parser(
            "image",
            help="CLOSED by source gates: authority-bound executor-"
                 "image producer")
        image_sub = verbs.add_subparsers(p, dest="image_project", required=True)
        p = image_sub.add_parser(
            "epubcheck",
            help="CLOSED by source gates: run one authority-bound "
                 "EPUBCheck image phase")
        p.add_argument("--phase", required=True,
                       choices=("base-pull", "discovery", "canonical"))
        p.add_argument("--out", required=True, metavar="ABSENT_ABS_DIR")
        p.set_defaults(func=cmd_image)

    if command == "java-reality-spike":
        # Kept conditional for the same frozen-help reason as `image`: this
        # source-closed operator route must not rewrite unrelated CLI bytes.
        p = verbs.add_parser(
            "java-reality-spike",
            help="CLOSED by source gates: authority-bound Java "
                 "reality capture")
        reality_sub = verbs.add_subparsers(
            p, dest="reality_project", required=True)
        p = reality_sub.add_parser(
            "epubcheck",
            help="CLOSED by source gates: capture one authority-bound "
                 "EPUBCheck reality spike")
        p.add_argument("--image-transcript", required=True,
                       metavar="APPROVED_ABS_FILE")
        p.add_argument("--out", required=True, metavar="ABSENT_ABS_DIR")
        p.set_defaults(func=cmd_java_reality_spike)

    # `index`, `closures`, `strip`, `stub-accept` and `mutants` are the five
    # verbs whose bodies are bound to one stack's language, so they are the
    # five that take `--profile` for its `framework:` alone.  Omitting it
    # means behat, which is what every CoreShop runbook does.
    p = verbs.add_parser(
        "index",
        help="static step index and framework-registry matching inside the "
             "container --container names, which must run the project's own "
             "image (its immutable image ID is recorded)")
    p.add_argument("--profile", default=None, help=bench_cli.STACK_PROFILE_HELP)
    p.add_argument("--source-root", default=None,
                   help="Original clean pinned source clone for Go bootstrap/closure verification")
    p.set_defaults(func=cmd_index)
    p = verbs.add_parser(
        "closures",
        help="extract source-file closures for criterion-to-test "
             "items")
    p.add_argument("--profile", default=None, help=bench_cli.STACK_PROFILE_HELP)
    p.add_argument("--source-root", default=None,
                   help="Original clean pinned source clone for Go bootstrap/closure verification")
    p.set_defaults(func=cmd_closures)
    p = verbs.add_parser(
        "interfaces",
        help="extract each item's declared interaction surface "
             "(target_interfaces) from the closure and the index")
    p.add_argument("--profile", default=None, help=bench_cli.STACK_PROFILE_HELP)
    p.add_argument("--source-root", default=None,
                   help="Go: original clean pinned source clone for declared-type attribution")
    p.add_argument("--image-id", default=None,
                   help="Go: qualified immutable image ID of the exclusive analysis container")
    p.set_defaults(func=cmd_interfaces)

    p = verbs.add_parser(
        "checked-interfaces",
        help="derive each item's checked interfaces -- the product methods "
             "its action and check steps called in the gold run -- from the "
             "per-step call attribution and the pinned production index")
    p.add_argument("--gold", required=True,
                   help="gold run rows (JSONL), harness version >= 18")
    p.add_argument("--index", required=True,
                   help="the project's pinned production method index")
    p.add_argument("--boundary", required=True,
                   help="config/boundary_<project>.yml")
    p.add_argument("--items", required=True,
                   help="the released item pool (JSONL)")
    p.add_argument("--source-root", required=True,
                   help="the pinned production source checkout the "
                        "declarations are read from")
    p.add_argument("--out", required=True, help="output JSON path")
    p.set_defaults(func=cmd_checked_interfaces)

    p = verbs.add_parser(
        "index-prod",
        # `result_ledger_v2_selftest` pins the ORDERED COMMAND TUPLE it parses
        # out of argparse's invalid-choice diagnostic, not the help strings:
        # adding or removing a verb changes that pin and must be reviewed
        # there, while a help line is free to say what is true today.  (An
        # earlier revision of this comment described a sha256 over `--help`;
        # help bytes have not been hashed since the tuple pin replaced it.)
        # `--path` below is only shown by `index-prod --help`.
        help="PHP: analyzer inside the named container (its immutable "
             "image ID is recorded); Python: host AST; Ruby: source-only Ripper in the bound image; "
             "Go: qualified image, explicit witnessed closures and original source")
    p.add_argument("--path", action="append", default=None,
                   help=f"repo-relative tree to index (default: "
                        f"{' '.join(PROD_PATHS)} for PHP, "
                        f"{' '.join(PY_PROD_PATHS)} for Python, app lib for Ruby)")
    p.add_argument("--profile", default=None, help=bench_cli.STACK_PROFILE_HELP)
    p.add_argument("--closures", default=None,
                   help="Go: explicit complete witnessed closures.json input")
    p.add_argument("--image-id", default=None,
                   help="Go: qualified immutable image ID of the named analysis container")
    p.set_defaults(func=cmd_index_prod)

    p = verbs.add_parser(
        "strip",
        help="move benchmark answer files out of the workspace into "
             "gold")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--profile", default=None, help=bench_cli.STACK_PROFILE_HELP)
    p.set_defaults(func=cmd_strip)

    p = verbs.add_parser(
        "sanitise",
        help="remove remaining answer copies from an already-stripped "
             "workspace; --dump-autoload is CLOSED")
    p.add_argument("--dump-autoload", action="store_true",
                   help="CLOSED pending preprocessing binding: also "
                        "regenerate Composer's classmap in the container")
    p.set_defaults(func=cmd_sanitise)

    p = verbs.add_parser(
        "validate",
        help="admit only items that fail without and pass with the "
             "reference solution")
    p.add_argument(
        "--publication-v3", action="store_true",
        help="explicit result-v3 validation checkpoint/receipt lifecycle")
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--item", action="append", default=None)
    p.add_argument("--out", default="validation.jsonl")
    p.add_argument("--no-resume", action="store_true")
    # Harness-constructing (`_harness` routes on the profile's framework);
    # omitting it keeps every CoreShop validation invocation byte-stable.
    p.add_argument("--profile", default=None, help=bench_cli.STACK_PROFILE_HELP)
    p.set_defaults(func=cmd_validate)

    p = verbs.add_parser(
        "quality",
        help="compute per-item quality and dependency fields")
    p.add_argument("--items", default=os.path.join(bench_cli.BENCHMARK, "items.jsonl"))
    p.add_argument("--v8", default=None,
                   help="optional scenario_statistics.csv from the research "
                        "analysis; omitted, quality is computed without its "
                        "post-hoc annotations")
    p.add_argument("--profile", default=None, help=bench_cli.RUNTIME_PROFILE_HELP)
    p.set_defaults(func=cmd_quality)

    p = verbs.add_parser(
        "release",
        help="build the admitted release from extraction and "
             "validation artifacts")
    p.add_argument("--items", default=os.path.join(bench_cli.BENCHMARK, "items.jsonl"))
    p.add_argument("--out", default=os.path.join(bench_cli.BENCHMARK, "release"))
    p.add_argument("--min-live-steps", type=int, default=3)
    p.add_argument("--checked-interfaces", default=None, metavar="JSON",
                   help="a `checked-interfaces` derivation output "
                        "(r2t.checked-interfaces/1); its per-item "
                        "{checked, empty_reason} object is copied onto every "
                        "released row as `checked_interfaces` "
                        "(TARGET_INTERFACES_V2_SPEC). Every framework, "
                        "Java cucumber included")
    p.add_argument("--item-dispositions", default=None, metavar="JSON",
                   help="operator-named exclusions, a JSON object of "
                        "item_id -> {\"stage\": ..., \"reasons\": [...]}; "
                        "every non-released stage lands in exclusions.csv "
                        "and summary.json with its reasons")
    # The pool's file NAME, not its path: `--out release/python-docx` writes a
    # second project's pool beside v1's, and calling it `items_v1.jsonl` too
    # would put two different pools under one name that `VERSIONS.yml` pins
    # by content. Defaults to v1's, so every CoreShop invocation is unchanged.
    p.add_argument("--items-name", default=DEFAULT_ITEMS_NAME,
                   metavar="NAME",
                   help="basename of the pool file written under --out "
                        f"(default {DEFAULT_ITEMS_NAME})")
    p.set_defaults(func=cmd_release)

    p = verbs.add_parser(
        "manifest-baseline",
        help="record the current workspace's integrity baseline")
    p.add_argument("--verify-against", default=None,
                   help="an independent copy of the same checkout; production "
                        "sources are diffed against it before baselining")
    p.add_argument("--force", action="store_true")
    # Harness-constructing, so it dispatches on `framework:` too — without
    # the flag a behave tree would be baselined through the behat branch,
    # which starts by reading a PHP alias table that does not exist.
    p.add_argument("--profile", default=None, help=bench_cli.STACK_PROFILE_HELP)
    p.set_defaults(func=cmd_manifest_baseline)

    p = verbs.add_parser(
        "provision-coreshop",
        help="LEGACY, not a current execution route: build the pinned "
             "CoreShop image and seed")
    p.add_argument(
        "--data-root", default=None,
        help="fixed benchmark data layout root (default: R2T_DATA_ROOT)")
    p.set_defaults(func=cmd_provision_coreshop)

    p = verbs.add_parser(
        "provision-sylius",
        help="build the pinned Sylius API-arm image, installed tree and "
             "seed")
    p.add_argument(
        "--data-root", default=None,
        help="fixed benchmark data layout root (default: R2T_DATA_ROOT)")
    # `index`, `index-prod` and `closures` read the Api contexts the strip
    # removes, so the recipe can stop with the installed tree up and finish
    # after the operator has taken them.
    stage = p.add_mutually_exclusive_group()
    stage.add_argument(
        "--stop-after-install", action="store_true",
        help="stop with the installed build tree and the setup container "
             "running, before the strip and the seed")
    stage.add_argument(
        "--resume-seed", action="store_true",
        help="strip, seed and start the template container over the tree "
             "--stop-after-install left")
    p.set_defaults(func=cmd_provision_sylius)

    p = verbs.add_parser(
        "stub-accept",
        help="§3.10 stub acceptance over a corpus")
    p.add_argument("--release", default=os.path.join(bench_cli.BENCHMARK, "release",
                                                     "items_v1.jsonl"))
    p.add_argument("--closures", default=None)
    p.add_argument("--profile", default=None, help=bench_cli.STACK_PROFILE_HELP)
    p.set_defaults(func=cmd_stub_accept)

    p = verbs.add_parser(
        "target-regions",
        help="resolve a reviewed target body map to the per-item production "
             "LINES the target-region rows are measured over")
    p.add_argument("--map", required=True, metavar="JSON",
                   help="the reviewed target body map "
                        "(maps/<project>/target_body_map.json or target-map.json)")
    p.add_argument("--source-root", required=True, metavar="DIR",
                   help="the pinned source seed the map names; its inventory "
                        "must reproduce the map's source_files_digest, since "
                        "other bytes give other line numbers")
    p.add_argument("--profile", required=True, metavar="FILE",
                   help="the project profile supplying the project and the "
                        "workspace readable_paths the seed is inventoried over")
    p.add_argument("--out", required=True, metavar="JSON")
    p.add_argument("--release", help="selected Go release with per-item suite contexts")
    p.add_argument("--go", help="absolute qualified Go executable; defaults to R2T_SOURCE_VIEW_GO")
    p.add_argument("--go-scratch", help="absolute trusted Go scratch outside the source seed")
    p.set_defaults(func=cmd_target_regions)

    p = verbs.add_parser(
        "control-floors",
        help="measure the behavioural floors -- what sibling gold, "
             "assertion-stripped gold and a stub already score -- offline "
             "from existing run rows")
    p.add_argument("--gold", action="append", required=True, metavar="JSONL",
                   help="a gold run JSONL; repeat for a sharded gold run")
    p.add_argument("--stripped", action="append", default=None,
                   metavar="JSONL",
                   help="an assertion-stripped gold run JSONL; repeatable")
    p.add_argument("--stub", action="append", default=None, metavar="JSONL",
                   help="a stub run JSONL; repeatable")
    p.add_argument("--prod-index", default=None, metavar="FILE",
                   help="the production method index; without it the API "
                        "floors are absent rather than 0.0")
    p.add_argument("--target-regions", default=None, metavar="JSON",
                   help="a `target-regions` artifact; without it the "
                        "target-region floors are absent rather than 0.0")
    p.add_argument("--out", required=True, metavar="JSON")
    p.set_defaults(func=cmd_control_floors)
