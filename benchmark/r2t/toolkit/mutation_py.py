"""S5 — the behave/Python mutant population: the engine wired to the manifest.

`r2t.data.mutation` already owns everything that decides what a mutant IS once an
enumerator has spoken — the id hash, the canonical sort, the exclusion policy,
the digest — and S1 made every one of those a PARAMETER with the PHP value as
its default.  This module is what supplies the second set of arguments.  It
holds no arithmetic of its own: the population is built by
`mutation.build_manifest`, the recall by `mutation.recall`, and a bug fixed in
either is fixed for both stacks at once.

What is genuinely python-specific, and therefore here:

* **the engine's identity** — `r2t-mutate-py` / `1.0`, taken from
  `r2t/py/mutate.py` rather than re-typed, because `mutation.mutant_id` hashes
  both fields and a copy that drifted would mint ids for a population no
  enumerator produced;
* **where the parser version comes from** — PHP reads `nikic/php-parser` out
  of the tree's own `composer.lock`; Python's parser IS the interpreter, so
  the version is the one running the enumerator.  Which is why enumeration
  happens INSIDE `r2t_docx_img:base`, the same image the applier will run in,
  and why the image is probed independently and the two answers compared: an
  enumerator that reported a parser it was not running under would produce a
  manifest whose digest no rerun could reproduce;
* **the keep root** — `!src`, because python-docx is a src-layout project and
  `src/` is the whole of the code under test.  `vendor/` and `var/` are named
  beside it for the same reason `mutation.EXCLUDED_PREFIXES` names them under
  a keep root that already excludes them: they are the two trees that would
  dominate the count if they ever became reachable, and a redundant exclusion
  costs nothing while a missing one costs a population;
* **the applier's staging** — `var/bench_mutate/mutate.py`, run by `python3`.
  `var/`, never `_bench/`: `_bench` is a hashed substrate root and a stray
  file there aborts the next item as tampering.

One shared assumption was checked rather than inherited.  `mutation.map_
mutants_to_items` attributes a mutant to the items covering `(file,
start_line)`, which is right for Xdebug because it credits a statement to the
line it starts on.  coverage.py was asked the same question in the image, and
gives the same answer: a `return (` spanning four lines reports the `return`
line as executed along with the rest, so the 970 `ReturnValue` mutants — 44%
of this population, and the ones whose regions are multi-line — join to
coverage rather than dropping out of it as uncovered.  Had it reported only
the inner lines, nearly half the population would have been silently
unreachable and the recall denominator would have been wrong with nothing
saying so.

The read-only mount is not caution about the container, it is the S0 gate:
python-docx is a clone pinned at `e454546` whose 306 extracted items must
re-derive byte-identically, so the enumeration writes nothing into it — the
same rule `pystep_index.run_matcher` follows, and the same scratch-beside-the-
workspace shape.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Iterable, Optional

from ..data import mutation as M
from ..py import mutate as _mutate
from .pystep_index import (CONTAINER_ROOT, CONTAINER_SCRATCH, DEFAULT_IMAGE,
                           _docker)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The engine's own constants, imported rather than repeated.  `mutant_id`
#: hashes both, so two spellings of them would be two id spaces.
ENGINE = _mutate.ENGINE
ENGINE_VERSION = _mutate.ENGINE_VERSION

#: Where this repository keeps the python enumerator/applier program, for
#: `mutation_run.install_applier`.
PY_ENGINE_DIR = os.path.join(HERE, "py")

#: The trees to enumerate when the caller names none.  A src-layout project's
#: whole library; the boundary then has the last word (see `production_only`).
DEFAULT_PATHS: tuple[str, ...] = ("src",)
OFFLINE_DOCKER_RUN: tuple[str, ...] = (
    "docker", "run", "--rm", "--pull=never", "--network", "none")

#: The exclusion policy, in `mutation.is_excluded`'s vocabulary: an entry
#: beginning with `!` is a KEEP root and a path matching none of them is
#: excluded.  See the module docstring for why the two plain entries are here
#: even though the keep root already excludes them.
EXCLUDED_PREFIXES: tuple[str, ...] = ("!src", "vendor/", "var/")


def applier():
    """The python applier, as `mutation_run.Applier` describes one.

    Built on demand rather than at import so that this module can be read (and
    selftested) without pulling in the harness, which `mutation_run` imports at
    module scope for the PHP path.
    """
    from ..bench.mutation_run import Applier
    return Applier(source="mutate.py", rel="var/bench_mutate/mutate.py",
                   interpreter="python3")


# --------------------------------------------------------------- the image
def probe_parser_version(image: str = DEFAULT_IMAGE, timeout: int = 300) -> str:
    """Ask the IMAGE which interpreter it runs, in `mutate.parser_version`'s
    spelling.

    A second, independent witness to the one field the manifest cannot check
    for itself.  `mutation.load_raw` deliberately refuses to trust an
    enumerator's envelope about the engine; the parser deserves the same
    treatment, and here it can have it cheaply because the image is one
    `docker run` away.
    """
    argv = [*OFFLINE_DOCKER_RUN, image,
            "python", "-c",
            "import platform;print(platform.python_implementation().lower(),"
            "platform.python_version())"]
    cp = subprocess.run(_docker(argv), capture_output=True, text=True,
                        timeout=timeout)
    if cp.returncode != 0 or not cp.stdout.strip():
        raise SystemExit(
            f"REFUSED: could not read the interpreter version out of {image} "
            f"(rc={cp.returncode}). Without it the manifest cannot name the "
            f"parser that produced its spans, which is the one property "
            f"§3.11 asks a manifest to have.\n{cp.stderr[-800:]}")
    return cp.stdout.strip()


def enumerate_in_image(repo_root: str, paths: Iterable[str],
                       image: str = DEFAULT_IMAGE, timeout: int = 1800, *,
                       record_enumerator_rev: bool = False,
                       operator_profile: str = "v2",
                       expected_enumerator_sha256: Optional[str] = None) -> dict:
    """Run `py/mutate.py --path ...` inside `image`, return its document.

    The workspace goes in READ-ONLY and the program, like its output, lives in
    a host scratch directory mounted beside it.
    """
    if operator_profile not in {"v1", "v2"}:
        raise ValueError(
            f"unknown operator profile {operator_profile!r}; expected v1 or v2")
    if record_enumerator_rev and expected_enumerator_sha256 is None:
        raise ValueError(
            "recording enumerator provenance requires the pinned staged "
            "producer SHA-256")
    paths = list(paths)
    scratch = tempfile.mkdtemp(prefix="r2t_pymutate_")
    try:
        source = os.path.join(PY_ENGINE_DIR, "mutate.py")
        staged = os.path.join(scratch, "mutate.py")
        if expected_enumerator_sha256 is None:
            # Non-production diagnostic gates predate the current-enumerator
            # registry.  Canonical builders always pass the authority digest
            # below; retaining this path keeps those explicitly exploratory
            # probes usable without weakening production.
            shutil.copyfile(source, staged)
        else:
            from ..data import mutation_attestation as A
            from . import mutation_audit as AUDIT
            AUDIT.stage_preserved_file(
                source, staged, expected_enumerator_sha256,
                label="Python enumerator")
        inner = ["python", f"{CONTAINER_SCRATCH}/mutate.py",
                 "--root", CONTAINER_ROOT,
                 "--out", f"{CONTAINER_SCRATCH}/raw.json",
                 "--operator-profile", operator_profile]
        for p in paths:
            inner += ["--path", p]
        if record_enumerator_rev:
            inner.append("--record-enumerator-rev")
        argv = [*OFFLINE_DOCKER_RUN,
                "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", f"{os.path.abspath(repo_root)}:{CONTAINER_ROOT}:ro",
                "-v", f"{scratch}:{CONTAINER_SCRATCH}",
                "-w", CONTAINER_ROOT, image] + inner
        cp = subprocess.run(_docker(argv), capture_output=True, text=True,
                            timeout=timeout)
        if cp.stderr.strip():
            print("  " + cp.stderr.strip().replace("\n", "\n  "))
        out = os.path.join(scratch, "raw.json")
        if cp.returncode != 0 or not os.path.isfile(out):
            raise SystemExit(
                f"REFUSED: the in-container enumerator exited "
                f"{cp.returncode}. A partial population is not a smaller "
                f"measurement of the same thing -- it is a different "
                f"denominator.\n{cp.stdout[-2000:]}\n{cp.stderr[-2000:]}")
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# ------------------------------------------------------------- the population
def production_only(raw: list, boundary) -> tuple[list, int]:
    """Drop every mutant the BOUNDARY does not call production, and count.

    The CoreShop arm learned this the expensive way and the lesson is not
    PHP's: `src/CoreShop/Bundle/TestBundle` sits under a production prefix but
    the boundary classifies it RETAINED — it is the harness's own scaffolding
    — and 258 mutants in it pushed the measured stub recall from 0.015 to
    0.029 against a gate threshold of 0.02.  The keep root and the boundary
    answer different questions ("what is the library" and "what survives
    stripping"), and only the second one knows about scaffolding, so both are
    asked.
    """
    from ..core.boundary import PRODUCTION
    kept = [m for m in raw
            if boundary.classify(M.normalise_path(m["file"])) == PRODUCTION]
    return (kept, len(raw) - len(kept))


def build_population(raw: list, *, parser_version: str,
                     operators: Iterable[str] = M.OPERATORS,
                     exclusions: Iterable[str] = EXCLUDED_PREFIXES,
                     sample: Optional[int] = None, seed=None,
                     n_invalid: Optional[int] = None,
                     enumerator_rev: Optional[str] = None) -> dict:
    """This stack's `mutant_population` seam: `mutation.build_manifest`, with
    the python engine's identity and keep root.

    Every argument that decides what a mutant IS is passed explicitly, so that
    a reader of the call knows the population without reading this module's
    defaults, and so that the PHP defaults can never be inherited by accident.
    """
    return M.build_manifest(raw, parser_version=parser_version,
                            operators=operators, exclusions=exclusions,
                            engine=ENGINE, engine_version=ENGINE_VERSION,
                            sample=sample, seed=seed,
                            n_invalid=n_invalid,
                            enumerator_rev=enumerator_rev)


def population_for(doc: dict, boundary, boundary_name: str, *,
                   sample: Optional[int] = None, seed=None,
                   operators: Iterable[str] = M.OPERATORS,
                   ) -> tuple[dict, int]:
    """`(manifest, n_non_production)` — the whole population, in one place.

    The CLI verb and `scripts/gate_s5_vacuity.py` both go through here, and
    that is the point rather than tidiness: a gate that certified a digest
    the shipped manifest does not carry would be certifying a different
    population under the same name.  The boundary filter and the two fields
    that record it are inside the digest, exactly as the CoreShop arm records
    them — which is why `boundary_name` is an argument and not read off the
    object: it goes into the manifest, so it has to be the file the operator
    actually passed rather than a label reconstructed from a project name.
    """
    raw = load_raw_doc(doc)
    kept, non_production = production_only(raw, boundary)
    manifest = build_population(kept, parser_version=doc["parser"],
                                operators=operators,
                                sample=sample, seed=seed,
                                n_invalid=doc.get("n_invalid"),
                                enumerator_rev=doc.get("enumerator_rev"))
    manifest["exclusions"] = list(manifest.get("exclusions") or ()) + [
        f"non-production by {boundary_name}"]
    manifest["n_non_production_excluded"] = non_production
    manifest["digest"] = M.manifest_digest(manifest)
    return (manifest, non_production)


def load_raw(path: str) -> list:
    """`mutation.load_raw` under THIS engine's identity.

    The refusal follows the parameter, not the constant: reading a PHP
    envelope here, or a python one on the CoreShop path, mints ids that hash
    the wrong engine and silently pools two populations.
    """
    return M.load_raw(path, engine=ENGINE, engine_version=ENGINE_VERSION)


# ---------------------------------------------------------------- the CLI verb
def cmd_mutants(args) -> int:
    """`r2t mutants build|map --profile config/profile_python_docx.yml`

    The behave arm of `cli.cmd_mutants`, reached through `cli._other_stack`.
    """
    from ..core.boundary import load_boundary
    from ..data import mutation_attestation as A
    from . import mutation_audit as AUDIT
    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))

    if args.action == "map":
        try:
            out_fd = AUDIT.reserve_output(
                args.out, input_paths=(args.manifest, args.coverage_run,
                                       getattr(args, "release", None),
                                       args.boundary))
        except A.MutationAssetRefused as exc:
            raise SystemExit(str(exc))
        # The join of a manifest against a completed coverage sweep is
        # arithmetic in `r2t.data.mutation` and is the same for both stacks; what
        # is dispatched is only WHERE the two files come from.  The PHP arm's
        # body lives inside `cli.cmd_mutants` and moving it would change the
        # bytes of every CoreShop invocation, so it is called rather than
        # shared (S1's no-logic-movement rule).
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = json.load(fh)
        if manifest.get("engine") != ENGINE:
            raise SystemExit(
                f"REFUSED: {args.manifest} was built by "
                f"{manifest.get('engine')!r}, not {ENGINE!r}. Its mutant ids "
                f"hash the other engine, so a map built from it would name "
                f"mutants this stack cannot apply.")
        cov = {}
        with open(args.coverage_run, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    row = json.loads(line)
                    if row.get("coverage_lines"):
                        if row["item_id"] in cov:
                            raise SystemExit(
                                "REFUSED: coverage run repeats item_id "
                                f"{row['item_id']!r}")
                        cov[row["item_id"]] = row["coverage_lines"]
        by_mutant, uncovered = M.map_mutants_to_items(manifest, cov)
        if getattr(args, "release", None):
            release_ids = A.load_release_ids(args.release)
            bad_items = sorted(
                {item for items in by_mutant.values() for item in items}
                - release_ids)
            if bad_items:
                raise SystemExit(
                    f"REFUSED: coverage map names item IDs outside --release, "
                    f"e.g. {bad_items[:3]}")
            payload = A.build_map_artifact(
                manifest, by_mutant, uncovered,
                coverage_sha256=A.sha256_file(args.coverage_run),
                release_sha256=A.sha256_file(args.release))
            A.validate_map(payload, manifest, release_ids=release_ids,
                           coverage_by_item=cov)
        else:
            payload = {"by_mutant": by_mutant, "uncovered": uncovered}
        AUDIT.write_reserved_json(out_fd, payload)
        print(json.dumps({"out": args.out, "mutants": manifest["n"],
                          "covered": len(by_mutant),
                          "uncovered": len(uncovered),
                          "items_with_coverage": len(cov)}, indent=1))
        return 0

    from ..bench.cli import _bound_container_image, _docx_v2_capability
    capability = _docx_v2_capability(args, "mutants-build")
    if capability is None:
        # No reviewed wrapper is active: the population is bound to the
        # named container's immutable image ID, resolved before anything
        # is staged or reserved, and printed with the build summary.  When
        # a wrapper IS active the image comes from its recorded runtime,
        # exactly as before.
        bound_image = _bound_container_image(args.container)
        print(f"image_id: {bound_image}")

    operator_profile = getattr(args, "operator_profile", "v2")
    operators = (M.OPERATORS_V1 if operator_profile == "v1"
                 else M.OPERATORS)
    try:
        record_enumerator_rev = M.record_enumerator_revision(
            operator_profile,
            requested=getattr(args, "record_enumerator_rev", False))
        enumerator_identity = A.pinned_enumerator_identity(
            "r2t/py/mutate.py")
        expected_enumerator_rev = (
            enumerator_identity["enumerator_rev"]
            if record_enumerator_rev else None)
    except (ValueError, A.MutationAssetRefused) as exc:
        message = str(exc)
        raise SystemExit(message if message.startswith("REFUSED:")
                         else f"REFUSED: {message}") from exc
    try:
        build_outputs = [args.out] + ([args.raw_out]
                                      if getattr(args, "raw_out", None)
                                      else [])
        build_fds = AUDIT.reserve_outputs(
            build_outputs, input_paths=(args.boundary,))
        out_fd = build_fds[0]
        raw_out_fd = build_fds[1] if len(build_fds) == 2 else None
    except A.MutationAssetRefused as exc:
        raise SystemExit(str(exc))
    image = capability.image_id if capability is not None else bound_image
    paths = list(args.path or DEFAULT_PATHS)
    doc = enumerate_in_image(
        b.repo_root, paths, image=image,
        record_enumerator_rev=record_enumerator_rev,
        operator_profile=operator_profile,
        expected_enumerator_sha256=enumerator_identity["sha256"])
    probed = probe_parser_version(image)
    try:
        doc = A.validate_enumerator_envelope(
            doc, expected_engine=ENGINE,
            expected_engine_version=ENGINE_VERSION,
            expected_parser_version=probed,
            expected_enumerator_rev=expected_enumerator_rev)
    except A.MutationAssetRefused as exc:
        # Keep the per-file witness visible as well as the fail-closed summary.
        errors = doc.get("errors") if isinstance(doc, dict) else None
        if isinstance(errors, dict):
            for rel, why in sorted(errors.items()):
                print(f"  PROBLEM: {rel}: {why}")
        raise SystemExit(str(exc))

    manifest, non_production = population_for(
        doc, b, os.path.basename(args.boundary),
        sample=args.sample, seed=args.seed, operators=operators)
    if getattr(args, "raw_out", None):
        # This stack's frozen Slice 1 population has an explicit zero-row
        # boundary derivation, so raw and scored bytes are intentionally the
        # same identity.  The validator reclassifies every row before it will
        # accept that equality.
        if non_production:
            raise SystemExit(
                "REFUSED: --raw-out cannot name the boundary-filtered "
                "manifest when non-production mutants were excluded")
    AUDIT.write_reserved_json(out_fd, manifest)
    if getattr(args, "raw_out", None):
        AUDIT.write_reserved_json(raw_out_fd, manifest)

    per_operator: dict = {}
    for m in manifest["mutants"]:
        per_operator[m["operator"]] = per_operator.get(m["operator"], 0) + 1
    summary = {"out": args.out, "n": manifest["n"],
               "n_excluded": manifest["n_excluded"],
               "n_non_production_excluded": non_production,
               "files": doc["files"],
               "digest": manifest["digest"],
               "engine": manifest["engine"],
               "parser": manifest["parser"],
               "per_operator": dict(sorted(per_operator.items()))}
    if capability is None:
        summary["image_id"] = image
    print(json.dumps(summary, indent=1))
    return 0


def load_raw_doc(doc: dict) -> list:
    """The mutant array out of an in-memory enumerator envelope.

    The file-reading path is `load_raw`; this is the same contract for a
    document that never touched the disk, and it makes the SAME engine check,
    because "the enumerator I just ran" is exactly as capable of being the
    wrong program as one whose output was written to a file.
    """
    for key, ours in (("engine", ENGINE), ("engine_version", ENGINE_VERSION)):
        theirs = doc.get(key)
        if theirs is not None and theirs != ours:
            raise SystemExit(
                f"REFUSED: the enumerator reports {key}={theirs!r} but this "
                f"stack identifies mutants as {ours!r}. Every mutant id "
                f"hashes {key}, so the two disagree about what a mutant IS.")
    mutants = doc.get("mutants")
    if not isinstance(mutants, list):
        raise SystemExit("REFUSED: the enumerator envelope carries no "
                         "'mutants' array.")
    if "n_invalid" in doc:
        n_invalid = doc["n_invalid"]
        if not isinstance(n_invalid, int) or isinstance(n_invalid, bool) \
                or n_invalid <= 0:
            raise SystemExit("REFUSED: enumerator.n_invalid must be a "
                             "positive integer when present (omit zero).")
    if "enumerator_rev" in doc \
            and (not isinstance(doc["enumerator_rev"], str)
                 or not doc["enumerator_rev"].strip()):
        raise SystemExit("REFUSED: enumerator.enumerator_rev must be a "
                         "non-empty string.")
    return mutants


# ----------------------------------------------------------------- selftest
def selftest() -> int:
    import tempfile
    from ..data import mutation_attestation as A

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def raises(fn, needle=""):
        try:
            fn()
        except (SystemExit, ValueError) as e:
            return needle in str(e)
        except Exception:                                    # noqa: BLE001
            return False
        return False

    # -- identity ----------------------------------------------------------
    check("the engine is the enumerator's own constant, not a copy of it",
          ENGINE is _mutate.ENGINE and ENGINE_VERSION is _mutate.ENGINE_VERSION
          and ENGINE == "r2t-mutate-py")
    check("...and it is NOT the PHP engine, so the two id spaces are disjoint",
          ENGINE != M.ENGINE)
    check("the Python producer revision matches the single current registry "
          "pin",
          A.pinned_enumerator_revision("r2t/py/mutate.py")
          == _mutate.ENUMERATOR_REV)
    current_envelope = {
        "engine": ENGINE, "engine_version": ENGINE_VERSION,
        "parser": "fixture-parser", "files": 1, "errors": {},
        "mutants": [], "enumerator_rev": _mutate.ENUMERATOR_REV,
    }
    check("the Python producer path requires its requested revision and "
          "exact envelope",
          A.validate_enumerator_envelope(
              current_envelope, expected_engine=ENGINE,
              expected_engine_version=ENGINE_VERSION,
              expected_parser_version="fixture-parser",
              expected_enumerator_rev=_mutate.ENUMERATOR_REV)
          is current_envelope
          and raises(lambda: A.validate_enumerator_envelope(
              {key: value for key, value in current_envelope.items()
               if key != "enumerator_rev"}, expected_engine=ENGINE,
              expected_engine_version=ENGINE_VERSION,
              expected_enumerator_rev=_mutate.ENUMERATOR_REV), "expected"))
    check("a revision-bearing image enumeration cannot stage unchecked "
          "producer bytes",
          raises(lambda: enumerate_in_image(
              "/not/reached", (), record_enumerator_rev=True),
                 "pinned staged producer SHA-256"))
    check("every population container forbids pulls and container networking",
          OFFLINE_DOCKER_RUN == (
              "docker", "run", "--rm", "--pull=never",
              "--network", "none"))

    # The eleven names are the v2 vocabulary; the enumerator must implement
    # exactly them and no more.  Derived from the engine's own tables rather
    # than from a list retyped here, so an operator added to `mutate.py`
    # without being declared fails this check.
    implemented = (
        {"ConditionalBoundary", "NegateConditional", "ArithmeticOperator",
         "Increment", "TrueValue", "FalseValue", "ReturnValue",
         "MethodCallRemoval", "LogicalConnector", "RemoveNegation",
         "ConstantReplacement"})
    fixture_ops = {m["operator"] for m in _mutate.enumerate_file(
        "f.py", _mutate._FIXTURE.encode("utf-8"), _mutate._FIXTURE)}
    check("the enumerator implements exactly r2t.data.mutation's v2 operators",
          fixture_ops == set(M.OPERATORS) == implemented,
          f"{sorted(fixture_ops)}")
    check("the immutable v1 profile is the exact ordered prefix of v2",
          M.OPERATORS[:len(M.OPERATORS_V1)] == M.OPERATORS_V1
          and len(M.OPERATORS_V1) == 8 and len(M.OPERATORS) == 11)

    # -- the keep root -----------------------------------------------------
    check("a src-layout library is inside the keep root",
          not M.is_excluded("src/docx/text/font.py", EXCLUDED_PREFIXES))
    check("the behave suite is NOT: it is the answer, not the code under test",
          M.is_excluded("features/steps/font.py", EXCLUDED_PREFIXES)
          and M.is_excluded("features/environment.py", EXCLUDED_PREFIXES))
    check("neither is the project's own unit-test tree, nor its packaging",
          M.is_excluded("tests/test_api.py", EXCLUDED_PREFIXES)
          and M.is_excluded("pyproject.toml", EXCLUDED_PREFIXES))
    check("vendor/ and var/ are excluded, and a directory merely NAMED like "
          "them is not",
          M.is_excluded("vendor/x/y.py", EXCLUDED_PREFIXES)
          and M.is_excluded("var/cache/x.py", EXCLUDED_PREFIXES)
          and not M.is_excluded("src/variables.py", EXCLUDED_PREFIXES))

    # -- the manifest ------------------------------------------------------
    raw = [
        {"file": "src/docx/text/font.py", "operator": "NegateConditional",
         "start_line": 12, "start_col": 8, "original": "==", "mutated": "!="},
        {"file": "src/docx/text/font.py", "operator": "ReturnValue",
         "start_line": 20, "start_col": 9, "original": "return x",
         "mutated": "return None"},
        {"file": "features/steps/font.py", "operator": "TrueValue",
         "start_line": 3, "start_col": 1, "original": "True",
         "mutated": "False"},
    ]
    man = build_population(raw, parser_version="cpython 3.12.13")
    check("the manifest declares THIS engine in its header",
          man["engine"] == ENGINE and man["engine_version"] == ENGINE_VERSION)
    check("...and the answer half of the tree is excluded and COUNTED",
          man["n"] == 2 and man["n_excluded"] == 1,
          f"n={man['n']} excluded={man['n_excluded']}")
    check("every id hashes the python engine, so no id can collide with a "
          "PHP one for the same span",
          all(m["id"] == M.mutant_id(m["file"], m["operator"], m["start_line"],
                                     m["start_col"], m["original"],
                                     m["mutated"], engine=ENGINE,
                                     engine_version=ENGINE_VERSION)
              for m in man["mutants"])
          and {m["id"] for m in man["mutants"]}.isdisjoint(
              {M.mutant_id(m["file"], m["operator"], m["start_line"],
                           m["start_col"], m["original"], m["mutated"])
               for m in man["mutants"]}))
    check("the digest reproduces over the same input",
          build_population(list(raw),
                           parser_version="cpython 3.12.13")["digest"]
          == man["digest"])
    check("a different interpreter is a different manifest -- the parser "
          "decides the spans",
          build_population(raw, parser_version="cpython 3.11.9")["digest"]
          != man["digest"])
    revised = build_population(
        raw, parser_version="cpython 3.12.13", n_invalid=4,
        enumerator_rev=_mutate.ENUMERATOR_REV)
    check("validity metadata crosses the Python population seam",
          revised["n_invalid"] == 4
          and revised["enumerator_rev"] == _mutate.ENUMERATOR_REV
          and revised["digest"] != man["digest"])

    # -- the cross-engine refusal, both directions -------------------------
    with tempfile.TemporaryDirectory() as d:
        php_env = os.path.join(d, "php.json")
        with open(php_env, "w", encoding="utf-8") as fh:
            json.dump({"engine": M.ENGINE, "engine_version": M.ENGINE_VERSION,
                       "mutants": raw}, fh)
        py_env = os.path.join(d, "py.json")
        with open(py_env, "w", encoding="utf-8") as fh:
            json.dump({"engine": ENGINE, "engine_version": ENGINE_VERSION,
                       "mutants": raw}, fh)
        check("a PHP envelope is REFUSED under the python identity",
              raises(lambda: load_raw(php_env), "what a mutant IS"))
        check("...and a python envelope under the PHP one -- the check is "
              "symmetric, not a one-way allowance",
              raises(lambda: M.load_raw(py_env), "what a mutant IS"))
        check("a python envelope loads under its own identity",
              load_raw(py_env) == raw)
        check("the in-memory form makes the same check",
              load_raw_doc({"engine": ENGINE, "mutants": raw}) == raw
              and raises(lambda: load_raw_doc(
                  {"engine": M.ENGINE, "mutants": raw}), "what a mutant IS"))
        check("an envelope with no mutant array is refused, not stack-traced",
              raises(lambda: load_raw_doc({"engine": ENGINE}), "no 'mutants'"))
        check("optional enumerator metadata is fail-closed",
              load_raw_doc({"engine": ENGINE, "mutants": raw,
                            "n_invalid": 1,
                            "enumerator_rev": _mutate.ENUMERATOR_REV}) == raw
              and raises(lambda: load_raw_doc(
                  {"engine": ENGINE, "mutants": raw, "n_invalid": 0}),
                         "omit zero")
              and raises(lambda: load_raw_doc(
                  {"engine": ENGINE, "mutants": raw,
                   "enumerator_rev": " "}), "non-empty"))

    # -- the applier -------------------------------------------------------
    ap = applier()
    check("the applier is staged under var/, never under _bench/ (a stray "
          "file in a hashed substrate root aborts the next item as tampering)",
          ap.rel.startswith("var/") and "_bench" not in ap.rel, ap.rel)
    check("it is the SAME program the enumerator is -- one program, two "
          "modes, so 'mutant M' cannot mean two things",
          ap.source == "mutate.py"
          and os.path.isfile(os.path.join(PY_ENGINE_DIR, ap.source)))
    check("and it is run by python, not by php", ap.interpreter == "python3")

    # -- the boundary filter -----------------------------------------------
    config = os.path.join(os.path.dirname(HERE), "config",
                          "boundary_python_docx.yml")
    if os.path.isfile(config):
        from ..core.boundary import load_boundary
        b = load_boundary(config)
        kept, dropped = production_only(raw, b)
        check("the boundary drops what the keep root would have kept only by "
              "accident, and says how many",
              [m["file"] for m in kept] == ["src/docx/text/font.py"] * 2
              and dropped == 1, f"kept={len(kept)} dropped={dropped}")

        # The one manifest builder both the CLI verb and the S5 gate go
        # through.  A gate that computed the population its own way would
        # certify a digest the shipped file does not carry — the same class
        # of mistake as two engines sharing an id space, one level up.
        doc = {"engine": ENGINE, "engine_version": ENGINE_VERSION,
               "parser": "cpython 3.12.13", "mutants": raw}
        full, n_np = population_for(doc, b, "boundary_python_docx.yml")
        check("population_for records the boundary filter INSIDE the digest",
              n_np == 1 and full["n_non_production_excluded"] == 1
              and "non-production by boundary_python_docx.yml"
              in full["exclusions"]
              and full["digest"] == M.manifest_digest(full), str(full["n"]))
        check("...so it is NOT the digest of the same mutants without it",
              full["digest"] != man["digest"] and full["n"] == man["n"])
        again, _ = population_for(doc, b, "boundary_python_docx.yml")
        check("...and it reproduces over the same document",
              again["digest"] == full["digest"])
        v1, _ = population_for(
            doc, b, "boundary_python_docx.yml", operators=M.OPERATORS_V1)
        check("an explicit v1 producer document constructs an ordinary v1 "
              "manifest without post-hoc row filtering",
              v1["operators"] == list(M.OPERATORS_V1)
              and v1["mutants"] == full["mutants"]
              and v1["digest"] != full["digest"])
    else:
        print(f"  [SKIP] no {config}, so the boundary filter could not be "
              f"checked against the real config")

    print("\n" + ("ALL PASS (mutation_py)" if ok else "FAILURES (mutation_py)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
