"""The frozen (workspace, database) pair every worker is provisioned from.

SPEC_C3_PARALLEL §3.3.  A worker is a triple — workspace, schema, container —
and the first two have to come from somewhere that is cheap to copy and
provably the same for everyone.  Copying the LIVE pair is neither: the live
schema is 393.4 MB across 252 tables, of which **325.6 MB is `versions` and
59.1 MB is `messenger_messages`**, and neither is touched by the per-scenario
purges; the remainder is 8.70 MB in 2,526 rows.  `var/versions` was 221 MB in
21,979 files.  So the seed is *pruned*, and pruning is a policy that has to be
recorded rather than remembered.

**Nothing is destroyed to build it.**  The obvious construction — `TRUNCATE`
the two tables, then `mysqldump` — destroys the schema every existing result
was measured against in order to produce a copy of it.  Dumping the same
schema twice instead, once skipping those tables and once with `--no-data`,
yields exactly the pruned pair and leaves the source untouched.

**Identity is content-based** (review P2-5).  The key covers every file that
goes into the workspace *and* the pruning rules themselves, so changing a
source file, adding an excluded path or emptying one more table all
invalidate it.  The database half has no cheap pre-image — there is no way to
digest "the rows MySQL would dump" without dumping them — so it is identified
by the digest of the dump it produced, and this module says so rather than
implying a guarantee it cannot make.

**A seed containing removable files is an ANSWER**, not a workspace, and is
refused: every worker provisioned from it would start each item with the gold
solution already on disk.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tarfile
import time
from typing import Optional

from dataclasses import dataclass

from ..core.boundary import REMOVABLE, Boundary
# The sentinel a seed records where a dump would be, imported rather than
# repeated: `campaign` is where the value becomes part of an identity and a
# second literal of it is a second thing to keep in step.
from .campaign import NO_DATABASE
from .repo import (BEHAVE_SUBSTRATE_VOLATILE, GO_SUBSTRATE_VOLATILE,
                   BENCH_DIR, StripManifest, RUBY_SUBSTRATE_VOLATILE,
                   SUBSTRATE_VOLATILE, verify_substrate)
from ..core.paths import BENCHMARK_ROOT

#: Emptied in the dump: kept as tables so the schema is complete, kept
#: row-free because nothing the benchmark executes reads them.  `versions`
#: holds Pimcore's object-revision history and `messenger_messages` its async
#: queue; the per-scenario purges touch neither, so they only ever grow.
PRUNE_TABLES = ("versions", "messenger_messages")

#: Dropped from the workspace: the on-disk half of the same history, plus
#: everything that is a cache of something else.  `var/cache` in particular
#: MUST be dropped — a copied compiled container names the previous item's
#: context classes, which is both a stale service graph and a small answer
#: key.
PRUNE_PATHS = ("var/versions",)
EXCLUDE_PATHS = ("var/cache", "var/log", "var/tmp", "var/recyclebin",
                 "var/bench_index", ".r2t-exec.lock", ".git")

#: The directories that must still EXIST after pruning, empty.  Pimcore
#: creates them on demand, but a missing `var/versions` turns the first write
#: into a permissions question rather than a benchmark result.
KEEP_EMPTY = ("var/versions", "var/cache", "var/log", "var/tmp",
              "var/recyclebin")

#: CoreShop paths omitted from the frozen workspace seed.
#:
#: This is deliberately distinct from `repo.SUBSTRATE_VOLATILE`: seed
#: omissions are hashed into existing seed and campaign identities, while
#: substrate volatility answers which runtime rewrites count as tampering.
#: Expanding the latter must not silently re-key historical seeds.
CORESHOP_SEED_VOLATILE = frozenset({
    f"{BENCH_DIR}/services_item.yml",
    f"{BENCH_DIR}/item.feature",
    f"{BENCH_DIR}/run_record.jsonl",
    f"{BENCH_DIR}/solution_index.json",
})

SEED_MANIFEST = "seed.json"
WORKSPACE_TAR = "workspace.tar"
DATABASE_SQL = "database.sql"

#: The mtime every EXTRACTED workspace file is stamped with.  The tar writer
#: sets `info.mtime = 0` so the archive's bytes -- and therefore
#: `workspace_seed_digest`, which the evidence chains pin -- do not move with
#: the clock.  That is right for the ARCHIVE and wrong for the TREE:
#: maven-resources copies a resource only when the destination's mtime is
#: strictly older than the source's, a destination that does not exist reports
#: mtime 0, and `0 < 0` is false -- so a workspace unpacked at epoch gets its
#: `target/test-classes/**` resource directories created and left EMPTY while
#: the build log still announces the count it meant to copy.  Any glue that
#: reads a fixture through `getResourceAsStream` then fails on a resource that
#: is present in the tree, which is a harness fault wearing an item's clothes.
#:
#: Measured, not reasoned: on an untouched algorand workspace Maven logged
#: `Copying 258 resources` and wrote ZERO files; with one file touched it
#: logged the same line and wrote exactly that one.  `selftest` pins both
#: directions with that discriminant.
#:
#: A FIXED PAST constant rather than the clock, for two reasons.  It keeps
#: unpacking deterministic -- two workspaces from one seed are the same
#: workspace, mtimes included.  And it preserves the warm build: sources older
#: than a previously compiled `target/classes` are what lets the compiler skip
#: main recompilation between items, which stamping "now" would silently undo.
#: The value only has to be non-zero for maven's comparison; 2001-09-09 is the
#: usual round Unix second and carries no other meaning.
WORKSPACE_MTIME_NS = 1_000_000_000_000_000_000

#: Bumped when the meaning of a seed changes, so an old directory is refused
#: rather than silently reused under new rules.
SEED_FORMAT = 1

#: The prefix that turns an anchored exclusion rule into a NAME rule.
#:
#: `var/cache` means "that directory"; `**/__pycache__` means "every directory
#: called that, at any depth", which is the only shape that catches CPython's
#: droppings — they appear beside whatever was imported, and the tree decides
#: where that is.  Deliberately folded into the SAME list rather than added as
#: a seventh key of the hashed policy: `rules_digest` is pinned by the
#: campaign digest vector and the frozen CoreShop seed key, and a new key
#: would move both for every project including the one that does not use it.
NAME_RULE = "**/"

#: python+behave's pruning policy (D3/D6).
#:
#: `features/_scratch` is behave's own scratch directory — the retained
#: environment hook creates it and a scenario that SAVES a document writes
#: there.  Seeding one worker's leftovers into every other worker is exactly
#: the shared-state failure K-way execution exists to remove, so it is
#: excluded and recreated empty.
#:
#: `**/__pycache__` is the rule that needs the name form.  A `.pyc` in the
#: seed is a compiled copy of whatever was imported when the seed was taken,
#: handed to every worker, and stale from the moment the source moves.
BEHAVE_EXCLUDE_PATHS = ("features/_scratch", ".r2t-exec.lock", ".git",
                        f"{NAME_RULE}__pycache__")
BEHAVE_KEEP_EMPTY = ("features/_scratch",)

#: Java+Cucumber's pruning policy (J3).
#:
#: Maven's `target` tree is generated output and may appear at the repository
#: root or below any module.  The name rule excludes that exact path component
#: without catching source directories such as `retarget`.
CUCUMBER_EXCLUDE_PATHS = (".r2t-exec.lock", ".git",
                          f"{NAME_RULE}target")


#: Go caches and compiler temporaries live outside the workspace. Git answers
#: and the live execution lock are excluded; retained package helpers remain.
GO_EXCLUDE_PATHS = (".r2t-exec.lock", ".git")


class SeedRefused(RuntimeError):
    pass


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _canon(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class SeedRules:
    """The pruning policy, as DATA rather than as five module constants.

    The constants above are CoreShop's answer, and they are still the
    defaults, so every caller that does not name a policy gets exactly the
    one every seed on disk was built under.  What changes is that a second
    stack can now HAVE an answer: python+behave prunes a scratch directory
    and compiled bytecode and empties no tables at all, and expressing that
    by editing the constants would silently re-key CoreShop's seed.

    `recreate` is the mirror image of `volatile` — a file is written back on
    unpack precisely because it was left out of the tar as per-item state —
    and it is deliberately NOT part of the hashed policy below: hashing both
    halves of one fact would state it twice, and `selftest` checks instead
    that every recreated path is a declared volatile one.
    """

    prune_tables: tuple = PRUNE_TABLES
    prune_paths: tuple = PRUNE_PATHS
    exclude_paths: tuple = EXCLUDE_PATHS
    keep_empty: tuple = KEEP_EMPTY
    volatile: frozenset = CORESHOP_SEED_VOLATILE
    recreate: tuple = ((f"{BENCH_DIR}/services_item.yml", "services: {}\n"),)
    seed_format: int = SEED_FORMAT

    def digest(self) -> str:
        """The pruning POLICY, hashed.

        Without this the key answers "are these the same bytes?" and not
        "were these bytes produced under the same rules?" — and the second
        question is the one that matters when the rules change and the
        sources do not.

        THE SHAPE OF THIS DOCUMENT IS FROZEN.  Under the defaults it must
        hash to what it hashed before the policy became data, because the
        CoreShop seed on disk records that digest and the campaign digest
        vector is taken over a fingerprint that carries it.  A rule that
        needs a new KIND of expression is spelled inside an existing list
        (see `NAME_RULE`), never as a seventh key.
        """
        return hashlib.sha256(_canon({
            "format": self.seed_format,
            "prune_tables": sorted(self.prune_tables),
            "prune_paths": sorted(self.prune_paths),
            "exclude_paths": sorted(self.exclude_paths),
            "keep_empty": sorted(self.keep_empty),
            "volatile": sorted(self.volatile),
        })).hexdigest()[:16]

    def excluded(self, rel: str) -> bool:
        """Is this path (or directory) kept out of the seed?"""
        if rel in self.volatile:
            return True
        parts = rel.split("/")
        for rule in tuple(self.prune_paths) + tuple(self.exclude_paths):
            if rule.startswith(NAME_RULE):
                if rule[len(NAME_RULE):] in parts:
                    return True
            elif rel == rule or rel.startswith(rule + "/"):
                return True
        return False

    def to_manifest(self) -> dict:
        """The policy as the seed manifest records it, so a reader — and
        `verify_seed` — can reconstruct it without being told."""
        return {"prune_tables": list(self.prune_tables),
                "prune_paths": list(self.prune_paths),
                "exclude_paths": list(self.exclude_paths),
                "keep_empty": list(self.keep_empty),
                "volatile": sorted(self.volatile),
                "recreate": [list(pair) for pair in self.recreate]}

    @classmethod
    def from_manifest(cls, doc: Optional[dict]) -> "SeedRules":
        """Recover the policy a seed was built under, from the seed itself.

        Every key defaults to CoreShop's, which is what makes the seed
        already on disk — written before `keep_empty`, `volatile` and
        `recreate` were recorded — reconstruct to exactly the policy it was
        built under and re-derive exactly its own `rules_digest`.  Anything
        else would make a staleness check report a seed as stale because the
        CODE moved, which is the one answer that check must never give.
        """
        d = doc or {}
        return cls(
            prune_tables=tuple(d.get("prune_tables", PRUNE_TABLES)),
            prune_paths=tuple(d.get("prune_paths", PRUNE_PATHS)),
            exclude_paths=tuple(d.get("exclude_paths", EXCLUDE_PATHS)),
            keep_empty=tuple(d.get("keep_empty", KEEP_EMPTY)),
            volatile=frozenset(d.get("volatile", CORESHOP_SEED_VOLATILE)),
            recreate=tuple(tuple(pair) for pair in d["recreate"])
            if "recreate" in d else cls.recreate,
            seed_format=d.get("format", SEED_FORMAT))


#: CoreShop's, and the default everywhere `rules` is not passed.
DEFAULT_RULES = SeedRules()

#: python+behave's.  No tables to empty (there is no database), no history
#: tree to prune, and the two things a behave run leaves behind instead:
#: a scratch directory and compiled bytecode.  `recreate` is empty because
#: a behave workspace has no per-item file to put back — the recorder writes
#: `_bench/run_record.jsonl` when it runs, and a placeholder there would be a
#: file the substrate baseline never saw.
BEHAVE_RULES = SeedRules(prune_tables=(), prune_paths=(),
                         exclude_paths=BEHAVE_EXCLUDE_PATHS,
                         keep_empty=BEHAVE_KEEP_EMPTY,
                         volatile=BEHAVE_SUBSTRATE_VOLATILE,
                         recreate=())

#: Java+Cucumber's.  It has no database, no retained empty generated trees,
#: and no per-item state to recreate in a fresh worker.
CUCUMBER_RULES = SeedRules(prune_tables=(), prune_paths=(),
                           exclude_paths=CUCUMBER_EXCLUDE_PATHS,
                           keep_empty=(), volatile=frozenset(), recreate=())

#: Go has no database or in-workspace generated state to recreate. The
#: exported record is omitted without introducing an empty placeholder.
GO_RULES = SeedRules(prune_tables=(), prune_paths=(),
                     exclude_paths=GO_EXCLUDE_PATHS, keep_empty=(),
                     volatile=GO_SUBSTRATE_VOLATILE, recreate=())

#: Sylius's, and the one row that separates it from CoreShop's.
#:
#: `DEFAULT_RULES` empties `versions` and `messenger_messages` after the
#: dump, because a Pimcore checkout accumulates both and neither is
#: purged per scenario.  Sylius's installed schema has 83 tables and
#: NEITHER of those names is among them, and `dbadmin.MySQL.dump` runs
#: `mysqldump --no-data <db> <those tables>` -- which fails outright on a
#: table that does not exist.  So the tables are not "left alone here as a
#: simplification"; they do not exist, and naming them would abort the
#: seed build.
#:
#: `var/versions` is Pimcore's on-disk half of the same history and is
#: absent for the same reason, and `keep_empty` keeps only the two
#: directories Symfony writes into.  Everything else -- what is excluded
#: from the tar, what is volatile, what is written back on unpack -- is
#: CoreShop's, because a Symfony checkout under Behat leaves behind
#: exactly the same things.
SYLIUS_RULES = SeedRules(prune_tables=(), prune_paths=(),
                         exclude_paths=EXCLUDE_PATHS,
                         keep_empty=("var/cache", "var/log"),
                         volatile=CORESHOP_SEED_VOLATILE)


# PostgreSQL is private to each Ruby image, outside the seeded workspace.
# This policy has no external database dump (route A), not a database-free app.
# The image helper restores npm dependencies after materialization; Rails
# rebuilds assets during boot. No generated directory is an input exemption.
RUBY_RULES = SeedRules(
    prune_tables=(), prune_paths=(),
    exclude_paths=(
        ".git", ".r2t-exec.lock", ".bundle", "node_modules",
        "app/assets/builds", "public/assets", "log", "tmp", "coverage",
        "storage",
    ),
    keep_empty=("app/assets/builds", "log", "tmp"),
    volatile=RUBY_SUBSTRATE_VOLATILE, recreate=(), seed_format=1,
)

#: Which policy a stack gets, keyed by the profile's `framework`.
#:
#: A CLOSED mapping that refuses an unknown framework rather than falling back
#: to CoreShop's: a stack whose pruning policy nobody has written would
#: otherwise be seeded under rules chosen for Pimcore — emptying tables it
#: does not have, keeping `var/versions` it does not have, and not pruning the
#: bytecode it does.
RULES_BY_FRAMEWORK = {"behat": DEFAULT_RULES, "behave": BEHAVE_RULES,
                      "cucumber": CUCUMBER_RULES,
                      "cucumber_ruby": RUBY_RULES, "godog": GO_RULES}

#: ...and the PROJECTS inside a framework that answer differently.
#:
#: A row, not a second framework: Sylius runs Behat exactly as CoreShop
#: does, and what differs is its database and its `var/` tree.  Keyed by
#: project so that adding one cannot move `DEFAULT_RULES.digest()`, which
#: the frozen CoreShop seed key and the campaign digest vector pin.
# Native PrestaShop table/resource restore inputs under var/r2t-db-dumps
# remain seeded; only regenerated caches/logs and answer history are omitted.
PRESTASHOP_RULES = SeedRules(
    prune_tables=(), prune_paths=(),
    exclude_paths=("var/cache", "var/log", "var/logs", ".r2t-exec.lock", ".git"),
    keep_empty=("var/cache", "var/log", "var/logs"),
    volatile=CORESHOP_SEED_VOLATILE)
RULES_BY_PROJECT = {"sylius": SYLIUS_RULES, "prestashop": PRESTASHOP_RULES}


def rules_for(framework: str, project: Optional[str] = None) -> SeedRules:
    """The pruning policy for one stack, narrowed by project when it has one.

    The framework is still CLOSED -- an unknown one is refused rather than
    seeded under CoreShop's rules -- and the project row is consulted
    inside it, so a project nobody has written a row for gets its
    framework's policy and says so in `rules_digest`.
    """
    if framework not in RULES_BY_FRAMEWORK:
        raise SeedRefused(
            f"REFUSED: no seed pruning policy for framework {framework!r}. "
            f"The known ones are {sorted(RULES_BY_FRAMEWORK)}; a stack seeded "
            f"under another framework's rules prunes the wrong things and "
            f"records a `rules_digest` that says it did not.")
    if project in RULES_BY_PROJECT:
        return RULES_BY_PROJECT[project]
    return RULES_BY_FRAMEWORK[framework]


def rules_digest(rules: SeedRules = DEFAULT_RULES) -> str:
    """Back-compatible spelling of `rules.digest()`."""
    return rules.digest()


def workspace_files(root: str, rules: SeedRules = DEFAULT_RULES) -> list[str]:
    """Every path the seed will carry, in a fixed order.

    Sorted at every level rather than trusting `os.walk`: the file list feeds
    both the tar and the content key, and a key that depended on readdir order
    would differ between two byte-identical trees.
    """
    out: list[str] = []
    for dirpath, dirnames, names in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(
            d for d in dirnames
            if not rules.excluded(f"{rel_dir}/{d}" if rel_dir else d))
        for n in sorted(names):
            rel = f"{rel_dir}/{n}" if rel_dir else n
            if rules.excluded(rel):
                continue
            full = os.path.join(dirpath, n)
            if os.path.islink(full) or not os.path.isfile(full):
                # A symlink in the seed would be resolved differently in every
                # worker's workspace, so it is dropped and reported rather
                # than followed.
                continue
            out.append(rel)
    # Globally sorted, not merely per-directory: `os.walk` yields a
    # directory's own files before its subdirectories, so the natural order
    # is deterministic but not sorted, and "sorted" is the property that is
    # cheap to state and cheap to check.
    return sorted(out)


def workspace_inputs_digest(root: str, files: Optional[list[str]] = None,
                            rules: SeedRules = DEFAULT_RULES) -> dict:
    """sha256 over "<rel>\\0<sha256>\\n" for every seeded file.

    This IS "every source input" in review P2-5's sense: change one byte of
    one file and the key changes, so a seed can never outlive the tree it was
    taken from without saying so.

    `files` is passed in by `build_seed` so that the key and the tar describe
    the SAME scan.  Scanning twice let the two disagree, and the first real
    build did exactly that: the manifest recorded 84,398 files while the tar
    held 84,399, i.e. a seed whose stated identity did not describe its own
    contents.
    """
    h = hashlib.sha256()
    n_bytes = 0
    files = workspace_files(root, rules) if files is None else files
    for rel in files:
        full = os.path.join(root, rel)
        n_bytes += os.path.getsize(full)
        h.update(rel.encode())
        h.update(b"\0")
        h.update(_sha256_file(full).encode())
        h.update(b"\n")
    return {"digest": h.hexdigest(), "n_files": len(files), "bytes": n_bytes}


def seed_key(root: str, schema: str, files: Optional[list[str]] = None,
             rules: SeedRules = DEFAULT_RULES) -> dict:
    """The content-addressed identity of a would-be seed, before building it.

    `schema` is `NO_DATABASE` for a stack that has none, which is a different
    16 characters from any schema name AND from `None` — a seed built with no
    database and one built before anybody recorded the database must not be
    the same seed.
    """
    inputs = workspace_inputs_digest(root, files, rules)
    rules_d = rules.digest()
    key = hashlib.sha256(_canon({
        "workspace_inputs": inputs["digest"], "rules": rules_d,
        "source_schema": schema})).hexdigest()[:16]
    return {"seed_key": key, "rules_digest": rules_d,
            "workspace_inputs_digest": inputs["digest"],
            "n_files": inputs["n_files"], "workspace_bytes": inputs["bytes"],
            "source_schema": schema}


def assert_clean(root: str, boundary: Boundary,
                 manifest: Optional[StripManifest] = None,
                 rules: SeedRules = DEFAULT_RULES) -> dict:
    """Refuse to freeze a tree that is not the tree the benchmark measures.

    Two separate refusals, and both have already happened once to this
    project.  A REMOVABLE file present in the tree is a solution — the agent
    seed once captured a graded item's own generated answer and handed every
    agent a worked example of what it was being asked to produce.  A substrate
    that no longer matches its baseline is a tree something has edited, and
    freezing it would propagate that edit into every worker for the life of
    the campaign.
    """
    leaked = [rel for rel in workspace_files(root, rules)
              if boundary.classify(rel) == REMOVABLE]
    if leaked:
        raise SeedRefused(
            f"REFUSED to seed from {root}: it holds {len(leaked)} removable "
            f"file(s), which are ANSWERS: {leaked[:5]}. Sweep the workspace "
            f"and make sure no execution is in flight.")
    report: dict = {"removable_files": 0}
    if manifest is not None:
        sub = verify_substrate(manifest, boundary)
        if sub["baseline"] and (sub["changed"] or sub["missing"] or sub["added"]):
            raise SeedRefused(
                f"REFUSED to seed from {root}: its substrate no longer matches "
                f"the recorded baseline ({len(sub['changed'])} changed, "
                f"{len(sub['missing'])} missing, {len(sub['added'])} added). "
                f"Freezing it would copy whatever changed into every worker.")
        report["substrate"] = {k: len(v) for k, v in sub.items()
                               if isinstance(v, list)}
        report["substrate_baseline"] = sub["baseline"]
    return report


def _tar_workspace(root: str, files: list[str], out_path: str,
                   keep_empty: tuple = KEEP_EMPTY,
                   resource_directories: Optional[dict] = None) -> dict:
    """Build into a temporary file and rename, never write in place.

    A crash halfway through leaves `workspace.tar.part`, which nothing reads,
    instead of a truncated `workspace.tar` that untars into a workspace
    missing whichever files came last.
    """
    tmp = out_path + ".part"
    with tarfile.open(tmp, "w", format=tarfile.GNU_FORMAT) as tar:
        directories = dict.fromkeys(keep_empty, 0o755)
        directories.update(resource_directories or {})
        for rel, mode in directories.items():
            info = tarfile.TarInfo(rel)
            info.type = tarfile.DIRTYPE
            info.mode = mode
            info.mtime = 0
            tar.addfile(info)
        for rel in files:
            full = os.path.join(root, rel)
            info = tar.gettarinfo(full, arcname=rel)
            # Timestamps and ownership are normalised so that two seeds taken
            # from the same bytes are the same seed.  Without it the tar
            # digest changes every time the tree is merely touched, and the
            # digest is what the campaign fingerprint pins.
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with open(full, "rb") as fh:
                tar.addfile(info, fh)
    os.replace(tmp, out_path)
    return {"path": out_path, "bytes": os.path.getsize(out_path),
            "n_files": len(files), "digest": _sha256_file(out_path)}


def build_seed(root: str, boundary: Boundary, out_dir: str, schema: str,
               db, manifest: Optional[StripManifest] = None,
               force: bool = False, rules: SeedRules = DEFAULT_RULES,
               needs_database: bool = True) -> dict:
    """Freeze the pair, once, and record what it is made of.

    `needs_database=False` makes it a pair of one (D6).  The workspace half is
    unchanged; the database half becomes a DECLARATION — `database_dump_digest
    = "no_database"` — rather than a missing key, because that value is hashed
    into the campaign fingerprint and "this stack has no database" must be a
    different campaign from "nobody recorded the database".

    The declaration is refused when it does not match its arguments.  A caller
    that says "no database" and hands over a schema name is describing two
    different stacks, and the seed would then record a source schema that
    nothing was dumped from.
    """
    if not needs_database:
        if db is not None or (schema not in (None, "", NO_DATABASE)):
            raise SeedRefused(
                f"REFUSED: build_seed(needs_database=False) was given "
                f"schema={schema!r} and db={type(db).__name__ if db else None}. "
                f"A stack with no database has no schema to name and nothing "
                f"to dump; recording one would attribute the seed to a "
                f"database it never read.")
        schema = NO_DATABASE
    elif schema == NO_DATABASE:
        raise SeedRefused(
            f"REFUSED: {NO_DATABASE!r} is the sentinel for a stack that has "
            f"no database; it cannot also be the name of one.")
    resource_directories = None
    resource_baseline_digest = None
    if boundary.project == "prestashop":
        if manifest is None:
            raise SeedRefused("PrestaShop requires a strip manifest with native resource inputs")
        from .prestashop_resources import verify_entry
        verify_entry(manifest)
        resource_baseline_digest = hashlib.sha256(
            _canon(manifest.prestashop_resources)).hexdigest()
        resource_directories = {rel: entry["mode"] for rel, entry in
                                manifest.prestashop_resources["entries"].items()
                                if entry["kind"] == "directory"}
    key = seed_key(root, schema, rules=rules)
    existing = read_seed(out_dir)
    if existing and not force:
        if resource_baseline_digest is not None and existing.get("prestashop_resources_digest") != resource_baseline_digest:
            raise SeedRefused("PrestaShop seed has a different native resource baseline; use a new seed directory")
        if existing.get("seed_key") == key["seed_key"]:
            return {**existing, "reused": True}
        raise SeedRefused(
            f"REFUSED: {out_dir} already holds a seed with key "
            f"{existing.get('seed_key')}, and the sources now hash to "
            f"{key['seed_key']}. A seed is content-addressed on purpose — "
            f"build the new one somewhere else, or pass --force if you mean "
            f"to invalidate every worker provisioned from the old one.")

    clean = assert_clean(root, boundary, manifest, rules)
    os.makedirs(out_dir, exist_ok=True)
    started = time.time()
    # ONE scan feeds the key, the tar and the stability check.  `seed_key`
    # above scanned separately, and on the first real build the tree gained a
    # file between the two — producing a manifest whose recorded identity did
    # not describe its own tar.  The seed is what every worker in a campaign
    # is provisioned from, so "probably the same tree" is not good enough.
    files = workspace_files(root, rules)
    key = seed_key(root, schema, files, rules)
    ws = _tar_workspace(root, files, os.path.join(out_dir, WORKSPACE_TAR),
                        rules.keep_empty, resource_directories)
    after = seed_key(root, schema, workspace_files(root, rules), rules)
    if after["seed_key"] != key["seed_key"]:
        os.remove(ws["path"])
        raise SeedRefused(
            f"REFUSED: {root} changed while it was being frozen "
            f"({key['n_files']} -> {after['n_files']} files, key "
            f"{key['seed_key']} -> {after['seed_key']}). The tar would be a "
            f"mixture of two trees. Stop everything that writes there and "
            f"build again.")
    if needs_database:
        dump = db.dump(schema, os.path.join(out_dir, DATABASE_SQL),
                       empty_tables=rules.prune_tables)
        dump["digest"] = _sha256_file(dump["path"])
    else:
        # No file is written, and that is the point: `verify_seed` must not
        # go looking for `database.sql` and `provision` must not load one.
        # The `declared` key is what both of them read, so "there is no
        # database" is a fact in the manifest rather than the absence of one.
        dump = {"declared": NO_DATABASE, "digest": NO_DATABASE,
                "path": None, "bytes": 0}

    doc = {
        "format": SEED_FORMAT,
        **key,
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "built_from": os.path.abspath(root),
        "build_seconds": round(time.time() - started, 1),
        "needs_database": needs_database,
        **rules.to_manifest(),
        "workspace": ws,
        "database": dump,
        "cleanliness": clean,
        **({"prestashop_resources_digest": resource_baseline_digest}
           if resource_baseline_digest is not None else {}),
        # The two fields §3.6's campaign fingerprint pins, named the same way
        # there so a reader can join them without guessing.
        "workspace_seed_digest": ws["digest"],
        "database_dump_digest": dump["digest"],
    }
    tmp = os.path.join(out_dir, SEED_MANIFEST + ".part")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
    os.replace(tmp, os.path.join(out_dir, SEED_MANIFEST))
    return doc


def read_seed(seed_dir: str) -> Optional[dict]:
    path = os.path.join(seed_dir, SEED_MANIFEST)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def verify_seed(seed_dir: str, source_root: Optional[str] = None) -> dict:
    """Do the artifacts still hash to what the manifest says, and is it stale?

    Two different questions.  The first is corruption — a half-copied tar, a
    dump truncated by a full disk.  The second is staleness: the sources have
    moved on and every worker provisioned from this seed is now running an
    older tree than the one the repository holds.  Both are silent otherwise.

    **`needs_database` is a DELIBERATE widening of this report** (D6), stated
    here because it is the one field that makes `r2t seed verify` print a
    line it did not print before — for every seed, CoreShop's archived one
    included.  Three reasons it is the right trade, and none of them is
    "the null-DB branch happened to need it":

    * it is what `worker.provision` cross-checks its own claim against, so a
      seed built with a dump can never be provisioned as if it had none.  The
      field is load-bearing, not decoration.
    * it is reported for EVERY seed rather than only for the seeds that
      declare it, because a key that appears only sometimes is a key every
      caller reads with a default of its own — and defaults that live in two
      places are how the answer starts depending on who asked.
    * it is the EFFECTIVE value, not the declaration: a manifest written
      before the key existed reads as True, which is exactly what provision
      will do with it.  Reporting `None` there would describe the manifest
      accurately and the behaviour wrongly.

    Nothing hashes this report — a seed's identity is its manifest, not the
    verification of it — so no pin moves.  It is still a change to a
    command's output, and the selftest pins the report's exact field set so
    the next one cannot arrive without somebody deciding it should.
    """
    doc = read_seed(seed_dir)
    if doc is None:
        raise SeedRefused(f"REFUSED: no seed at {seed_dir}")
    out = {"seed_key": doc["seed_key"], "format": doc.get("format"),
           "artifacts_ok": True, "stale": None,
           "needs_database": doc.get("needs_database", True)}
    for name, sub in (("workspace", WORKSPACE_TAR), ("database", DATABASE_SQL)):
        half = doc.get(name) or {}
        path = os.path.join(seed_dir, sub)
        want = half.get("digest")
        # A DECLARED absence is verified by reading the declaration, not by
        # hashing a file that was never written. Fail-closed all the same: the
        # declaration must be the exact sentinel and there must be no file
        # sitting there contradicting it, because a `database.sql` beside a
        # manifest that says there is no database is a seed nobody can
        # attribute.
        if half.get("declared") == NO_DATABASE:
            stray = os.path.isfile(path)
            out[name] = {"path": path, "expected": NO_DATABASE,
                         "actual": NO_DATABASE if not stray else "a file",
                         "declared": NO_DATABASE, "ok": not stray}
            out["artifacts_ok"] = out["artifacts_ok"] and out[name]["ok"]
            continue
        got = _sha256_file(path) if os.path.isfile(path) else None
        out[name] = {"path": path, "expected": want, "actual": got,
                     "ok": bool(want) and want == got}
        out["artifacts_ok"] = out["artifacts_ok"] and out[name]["ok"]
    if doc.get("format") != SEED_FORMAT:
        out["artifacts_ok"] = False
        out["format_mismatch"] = f"{doc.get('format')} != {SEED_FORMAT}"
    if source_root:
        # Under the policy THIS seed was built with, read back off the seed
        # itself. Re-deriving under the module defaults would report every
        # non-CoreShop seed as stale the moment a second stack existed, and
        # "stale" is the one verdict that must mean the sources moved.
        rules = SeedRules.from_manifest(doc)
        now = seed_key(source_root, doc["source_schema"], rules=rules)
        out["stale"] = now["seed_key"] != doc["seed_key"]
        out["source_key_now"] = now["seed_key"]
        out["rules_changed"] = now["rules_digest"] != doc["rules_digest"]
    return out


def unpack_workspace(seed_dir: str, dest: str, force: bool = False) -> dict:
    """Materialise one worker's workspace from the tar.

    Refuses a non-empty destination unless `force`: silently untarring over an
    existing workspace merges two trees, and the result is a workspace that is
    neither seed nor whatever was there — the same "set that is neither run"
    failure the run files refuse.
    """
    doc = read_seed(seed_dir)
    if doc is None:
        raise SeedRefused(f"REFUSED: no seed at {seed_dir}")
    if os.path.isdir(dest) and os.listdir(dest):
        if not force:
            raise SeedRefused(
                f"REFUSED: {dest} is not empty. Untarring over it would "
                f"produce a workspace that is neither the seed nor what was "
                f"there. Remove it first, or pass force=True.")
        shutil.rmtree(dest)
    os.makedirs(dest, exist_ok=True)
    tar_path = os.path.join(seed_dir, WORKSPACE_TAR)
    started = time.time()
    with tarfile.open(tar_path, "r") as tar:
        for info in tar:
            # The tar is built by this module, but it is also the thing a
            # worker's whole filesystem comes from, so it is checked rather
            # than trusted: one `../` member would write outside the worker.
            name = os.path.normpath(info.name).replace(os.sep, "/")
            if name.startswith("..") or name.startswith("/"):
                raise SeedRefused(f"REFUSED: seed tar escapes its root: "
                                  f"{info.name!r}")
            if not (info.isfile() or info.isdir()):
                raise SeedRefused(f"REFUSED: seed tar holds a non-regular "
                                  f"member: {info.name!r}")
        tar.extractall(dest)  # noqa: S202 -- every member checked above
    # The volatile files a run expects to exist but the seed deliberately
    # does not carry.  Read off the seed's own manifest, so a workspace is
    # never handed a placeholder belonging to another stack: writing
    # CoreShop's `_bench/services_item.yml` into a behave workspace would put
    # a Symfony DI fragment inside a hashed substrate root that the baseline
    # never saw, and the first item would abort as tampering.
    rules = SeedRules.from_manifest(doc)
    for rel, content in rules.recreate:
        full = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(content)
    # Publication evidence requires the complete worker workspace to be
    # current-UID owned and non-writable by peers.  Archive modes do not cover
    # implicit parent directories, the destination root, or recreated paths,
    # so normalise the finished tree once while preserving bytes and execute
    # bits.
    entries = [dest]
    for dirpath, dirnames, filenames in os.walk(dest):
        entries.extend(os.path.join(dirpath, name)
                       for name in dirnames + filenames)
    for full in entries:
        info = os.lstat(full)
        if info.st_uid != os.geteuid() or not (
                stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise SeedRefused(
                f"REFUSED: extracted workspace entry is not a current-UID "
                f"owned regular file or directory: {full}")
        os.chmod(full, stat.S_IMODE(info.st_mode) & ~0o022)
    stamped = _stamp_workspace_mtimes(dest)
    return {"dest": dest, "seconds": round(time.time() - started, 1),
            "seed_key": doc["seed_key"],
            "recreated": [rel for rel, _ in rules.recreate],
            "mtime_stamped": stamped}


def derived_state_members(seed_dir: str, roots: tuple) -> dict:
    """The seed's own bytes for every workspace file under `roots`.

    The baseline `repo.restore_derived_state` puts back before every pair
    (`repo.DERIVED_STATE_ROOTS`).  Read from the tar itself rather than from
    any worker, because the tar is what `workspace_seed_digest` binds into the
    campaign identity: every caller verifies the seed in the same command
    before it gets here, and a worker's own copy is exactly the thing that
    drifts.  CoreShop's is 106 files, 920,567 bytes.

    Refused when a declared root has no member at all.  A restore over an
    empty baseline restores nothing, which is the defect wearing a fix.
    """
    if not roots:
        return {}
    members: dict = {}
    with tarfile.open(os.path.join(seed_dir, WORKSPACE_TAR), "r") as tar:
        for info in tar:
            name = os.path.normpath(info.name).replace(os.sep, "/")
            if not any(name.startswith(root + "/") for root in roots):
                continue
            if info.isdir():
                continue
            if not info.isfile():
                raise SeedRefused(f"REFUSED: seed tar holds a non-regular "
                                  f"member: {info.name!r}")
            members[name] = tar.extractfile(info).read()
    empty = [root for root in roots
             if not any(rel.startswith(root + "/") for rel in members)]
    if empty:
        raise SeedRefused(
            f"REFUSED: the seed at {seed_dir} carries no file under the "
            f"derived-state root(s) {empty}, so there is nothing to restore "
            f"them to between pairs.")
    return members


def _stamp_workspace_mtimes(dest: str) -> int:
    """Give every unpacked path a non-zero, fixed mtime; return the count.

    The tar's own `mtime = 0` is what keeps the archive byte-stable, and this
    undoes it on the TREE only -- see `WORKSPACE_MTIME_NS`.  Nothing in this
    system hashes a workspace mtime (every digest and every substrate baseline
    is over content), so this moves no identity: the seed's bytes, its
    `seed_key`, `workspace.digest` and `workspace_seed_digest` are untouched.

    Directories are stamped too and stamped LAST per level, because writing a
    file inside a directory bumps that directory's own mtime.
    """
    count = 0
    times = (WORKSPACE_MTIME_NS, WORKSPACE_MTIME_NS)
    for dirpath, dirnames, filenames in os.walk(dest, topdown=False):
        for name in filenames:
            full = os.path.join(dirpath, name)
            if not os.path.islink(full):
                os.utime(full, ns=times)
                count += 1
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if not os.path.islink(full):
                os.utime(full, ns=times)
                count += 1
    os.utime(dest, ns=times)
    return count


def selftest() -> int:
    """The parts that need neither a database nor 800 MB of CoreShop."""
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refused(fn):
        try:
            fn()
            return False
        except SeedRefused:
            return True

    here = BENCHMARK_ROOT
    from ..core.boundary import load_boundary

    with tempfile.TemporaryDirectory() as root:
        def write(rel, text="x"):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        write("src/CoreShop/Component/Order/Model/Order.php", "<?php // prod")
        write("composer.json", "{}")
        write("var/versions/object/1/1.psf", "history")
        write("var/cache/test/BehatKernelTestDebugContainer.php", "stale")
        write("var/log/test.log", "noise")
        write("config/reference.php", "<?php // framework-generated\n")
        write(f"{BENCH_DIR}/retained_services.yml", "services: {}\n")
        write(f"{BENCH_DIR}/run_record.jsonl", "{}\n")
        write(f"{BENCH_DIR}/item.feature", "Feature: x\n")

        files = workspace_files(root)
        check("history, caches and logs are pruned out of the workspace",
              not any(f.startswith(("var/versions/", "var/cache/", "var/log/"))
                      for f in files), str(files))
        check("the volatile per-item files are not seeded",
              f"{BENCH_DIR}/run_record.jsonl" not in files
              and f"{BENCH_DIR}/item.feature" not in files, str(files))
        check("runtime substrate classification does not change the frozen "
              "seed file set",
              "config/reference.php" in files, str(files))
        check("production code and the retained substrate are seeded",
              "composer.json" in files
              and "src/CoreShop/Component/Order/Model/Order.php" in files
              and f"{BENCH_DIR}/retained_services.yml" in files)
        check("the file list is sorted, so the key does not depend on readdir",
              files == sorted(files), str(files))

        b = load_boundary(os.path.join(here, "config", "boundary_coreshop.yml"),
                          repo_root=root)
        key1 = seed_key(root, "coreshop_bench")
        check("a clean tree is accepted", assert_clean(root, b)["removable_files"] == 0)

        # An answer in the tree is the failure this refusal exists for.
        write("src/CoreShop/Behat/Context/Domain/CartContext.php", "<?php // ANSWER")
        check("a removable file in the seed source is refused as an answer",
              refused(lambda: assert_clean(root, b)))
        os.remove(os.path.join(root,
                               "src/CoreShop/Behat/Context/Domain/CartContext.php"))

        # Content addressing: the key must move when a source moves.
        check("the key is stable for an unchanged tree",
              seed_key(root, "coreshop_bench")["seed_key"] == key1["seed_key"])
        write("src/CoreShop/Component/Order/Model/Order.php", "<?php // edited")
        key2 = seed_key(root, "coreshop_bench")
        check("editing one source file changes the key",
              key2["seed_key"] != key1["seed_key"])
        check("pointing at a different source schema changes the key",
              seed_key(root, "coreshop_bench_3")["seed_key"] != key2["seed_key"])
        check("the pruning RULES are part of the key, not just the bytes",
              key2["rules_digest"] == rules_digest()
              and hashlib.sha256(_canon({"workspace_inputs":
                                         key2["workspace_inputs_digest"],
                                         "rules": "different",
                                         "source_schema": "coreshop_bench"})
                                 ).hexdigest()[:16] != key2["seed_key"])
        check("a file the tree does not have cannot be in the digest",
              workspace_inputs_digest(root)["n_files"] == len(workspace_files(root)))

        # tar + unpack round trip.
        with tempfile.TemporaryDirectory() as seed_dir:
            ws = _tar_workspace(root, workspace_files(root),
                                os.path.join(seed_dir, WORKSPACE_TAR))
            doc = {"format": SEED_FORMAT, "seed_key": key2["seed_key"],
                   "source_schema": "coreshop_bench",
                   "rules_digest": key2["rules_digest"], "workspace": ws,
                   "database": {"digest": None}}
            with open(os.path.join(seed_dir, SEED_MANIFEST), "w",
                      encoding="utf-8") as fh:
                json.dump(doc, fh)
            with tempfile.TemporaryDirectory() as dest:
                info = unpack_workspace(seed_dir, dest, force=True)
                got = workspace_files(dest)
                check("the unpacked workspace holds exactly the seeded files",
                      got == workspace_files(root), str(set(got) ^
                                                       set(workspace_files(root))))
                check("the pruned directories exist but are empty",
                      os.path.isdir(os.path.join(dest, "var/versions"))
                      and not os.listdir(os.path.join(dest, "var/versions")))
                check("services_item.yml is recreated, not seeded",
                      open(os.path.join(dest, BENCH_DIR, "services_item.yml"),
                           encoding="utf-8").read() == "services: {}\n")
                check("unpacking reports the seed it came from",
                      info["seed_key"] == key2["seed_key"])

                # ---- the extracted tree's mtimes -------------------------
                # The archive stays at epoch (below); the TREE must not,
                # because maven-resources copies a resource only when the
                # destination is strictly older than the source and a
                # destination that does not exist reports 0.  Measured on the
                # algorand workspace: untouched, Maven logged `Copying 258
                # resources` and wrote ZERO files; with one file touched it
                # logged the same line and wrote exactly that one.  The
                # selftest cannot run Maven, so what it pins is the property
                # that discriminates the two -- see WORKSPACE_MTIME_NS and
                # req2test_wave5_20260811/DEFECT_B_DERIVATION.md §5.
                stamped = []
                for dirpath, dirnames, filenames in os.walk(dest):
                    for name in filenames + dirnames:
                        stamped.append(os.stat(
                            os.path.join(dirpath, name)).st_mtime_ns)
                check("every unpacked path carries the fixed non-zero mtime, "
                      "so maven-resources performs its copies instead of "
                      "silently creating empty resource directories",
                      stamped
                      and all(v == WORKSPACE_MTIME_NS for v in stamped),
                      str(sorted(set(stamped))[:4]))
                check("the recreated volatile files are stamped too, not "
                      "left on the clock -- unpacking one seed twice gives "
                      "the same tree, mtimes included",
                      os.stat(os.path.join(dest, BENCH_DIR,
                                           "services_item.yml")).st_mtime_ns
                      == WORKSPACE_MTIME_NS)
                check("the stamp is reported, so a caller can see it ran",
                      info["mtime_stamped"] == len(stamped), str(info))
                check("the stamp is in the PAST, which is what keeps a warm "
                      "target/classes warm between items: stamping `now` "
                      "would silently invalidate every compiled main class",
                      WORKSPACE_MTIME_NS < time.time_ns())

                # ANTI-VACUITY: with the stamp neutered the tree comes out at
                # epoch -- the exact state the empty `target/test-classes`
                # was measured in -- and both checks above go red.
                real_stamp = globals()["_stamp_workspace_mtimes"]
                globals()["_stamp_workspace_mtimes"] = lambda _dest: 0
                try:
                    with tempfile.TemporaryDirectory() as unstamped:
                        unpack_workspace(seed_dir, unstamped, force=True)
                        raw = [os.stat(os.path.join(dp, n)).st_mtime_ns
                               for dp, dn, fn in os.walk(unstamped)
                               for n in fn
                               if n != "services_item.yml"]
                        check("anti-vacuity: without the stamp the tar's own "
                              "`mtime = 0` reaches the tree, which is the "
                              "state the resource copy was measured to skip",
                              raw and all(v == 0 for v in raw),
                              str(sorted(set(raw))[:4]))
                finally:
                    globals()["_stamp_workspace_mtimes"] = real_stamp

                with open(os.path.join(dest, "extra.txt"), "w") as fh:
                    fh.write("x")
                check("untarring over a non-empty workspace is refused",
                      refused(lambda: unpack_workspace(seed_dir, dest)))

            # A supported source checkout can be group-writable (0664), and
            # tar extraction otherwise reapplies that mode after creation.
            # The permissive umask also reaches implicit and recreated paths.
            with tempfile.TemporaryDirectory() as mode_root:
                mode_source = os.path.join(mode_root, "source")
                mode_seed = os.path.join(mode_root, "seed")
                mode_dest = os.path.join(mode_root, "workspace")
                os.makedirs(mode_source)
                os.makedirs(mode_seed)
                feature = os.path.join(mode_source, "features", "item.feature")
                runner = os.path.join(mode_source, "bin", "runner")
                os.makedirs(os.path.dirname(feature))
                os.makedirs(os.path.dirname(runner))
                feature_bytes = b"Feature: peer writable fixture\n"
                runner_bytes = b"#!/bin/sh\nexit 0\n"
                with open(feature, "wb") as fh:
                    fh.write(feature_bytes)
                with open(runner, "wb") as fh:
                    fh.write(runner_bytes)
                os.chmod(feature, 0o664)
                os.chmod(runner, 0o775)
                mode_tar = os.path.join(mode_seed, WORKSPACE_TAR)
                mode_ws = _tar_workspace(
                    mode_source, ["bin/runner", "features/item.feature"],
                    mode_tar, keep_empty=("retained-empty",))
                with open(os.path.join(mode_seed, SEED_MANIFEST), "w",
                          encoding="utf-8") as fh:
                    json.dump({
                        "format": SEED_FORMAT,
                        "seed_key": "mode-fixture",
                        "source_schema": "coreshop_bench",
                        "rules_digest": rules_digest(),
                        "workspace": mode_ws,
                        "database": {"digest": None},
                        "keep_empty": ["retained-empty"],
                        "recreate": [["recreated/state.txt", "state\n"]],
                    }, fh)
                with tarfile.open(mode_tar) as tar:
                    archived_modes = {
                        member.name: member.mode for member in tar}
                saved_umask = os.umask(0o002)
                try:
                    os.makedirs(mode_dest, mode=0o777)
                    unpack_workspace(mode_seed, mode_dest, force=True)
                finally:
                    os.umask(saved_umask)
                extracted_feature = os.path.join(
                    mode_dest, "features", "item.feature")
                extracted_runner = os.path.join(mode_dest, "bin", "runner")
                extracted_entries = [mode_dest]
                for dirpath, dirnames, filenames in os.walk(mode_dest):
                    extracted_entries.extend(
                        os.path.join(dirpath, name)
                        for name in dirnames + filenames)
                extracted_stats = [os.lstat(path)
                                   for path in extracted_entries]
                check("a 0664 archive member and permissive umask leave no "
                      "peer-writable workspace entry",
                      archived_modes["features/item.feature"] == 0o664
                      and all(info.st_uid == os.geteuid()
                              and not stat.S_IMODE(info.st_mode) & 0o022
                              for info in extracted_stats))
                check("the normalised tree includes implicit, retained-empty "
                      "and recreated paths",
                      all(os.path.isdir(os.path.join(mode_dest, path))
                          for path in ("features", "bin", "retained-empty",
                                       "recreated"))
                      and not os.listdir(os.path.join(
                          mode_dest, "retained-empty"))
                      and os.path.isfile(os.path.join(
                          mode_dest, "recreated", "state.txt")))
                with open(extracted_feature, "rb") as fh:
                    extracted_feature_bytes = fh.read()
                with open(extracted_runner, "rb") as fh:
                    extracted_runner_bytes = fh.read()
                check("mode normalisation preserves execute bits and file "
                      "bytes",
                      archived_modes["bin/runner"] == 0o775
                      and stat.S_IMODE(os.stat(extracted_runner).st_mode)
                      == 0o755
                      and extracted_feature_bytes == feature_bytes
                      and extracted_runner_bytes == runner_bytes)

            # ---- and the ARCHIVE, which must NOT move ---------------------
            # The evidence chains pin `workspace_seed_digest`, so the fix is
            # scoped to extraction: the tar writer keeps `info.mtime = 0` and
            # the seed's identity is untouched by any of the above.
            with tarfile.open(os.path.join(seed_dir, WORKSPACE_TAR)) as tar:
                member_mtimes = {member.mtime for member in tar}
            check("the tar members are still written at epoch, so the "
                  "archive's bytes -- and workspace_seed_digest with them -- "
                  "do not move when the extraction changes",
                  member_mtimes == {0}, str(sorted(member_mtimes)[:4]))
            check("re-taring the same tree after an unpack reproduces the "
                  "same digest, so the seed's identity is stamp-independent",
                  _tar_workspace(root, workspace_files(root),
                                 os.path.join(seed_dir, "stamp_check.tar"))[
                                     "digest"] == ws["digest"])

            check("a tar built twice from the same bytes is byte-identical",
                  _tar_workspace(root, workspace_files(root),
                                 os.path.join(seed_dir, "again.tar"))["digest"]
                  == ws["digest"])

            # A tree that changes while it is being frozen must be refused,
            # not averaged.  Simulated by making the scan return a different
            # answer the second time, which is exactly what a stray write
            # during the tar does.
            class _NoDB:
                def dump(self, *a, **k):
                    raise AssertionError("the dump must never be reached")

            write("docs/throwaway.md", "written by something else")
            real_tar = globals()["_tar_workspace"]

            def tar_then_change(where, files, out, *a, **kw):
                info = real_tar(where, files, out, *a, **kw)
                os.remove(os.path.join(where, "docs/throwaway.md"))
                return info

            globals()["_tar_workspace"] = tar_then_change
            try:
                with tempfile.TemporaryDirectory() as unstable:
                    check("a tree that changes while it is frozen is refused",
                          refused(lambda: build_seed(root, b, unstable,
                                                     "coreshop_bench", _NoDB())))
                    check("the half-built tar is not left behind",
                          not os.path.isfile(os.path.join(unstable,
                                                          WORKSPACE_TAR)))
            finally:
                globals()["_tar_workspace"] = real_tar

            v = verify_seed(seed_dir, source_root=root)
            check("verify recomputes the tar digest",
                  v["workspace"]["ok"] and not v["stale"], json.dumps(v)[:200])

            # ---- the report's SHAPE, pinned, not just its verdicts --------
            #
            # D6 added `needs_database` to this report, and that changed what
            # `r2t seed verify` prints for every seed on disk — the archived
            # CoreShop one included, whose manifest predates the key and
            # therefore reads as the effective True.  The addition was worth
            # making (provision cross-checks that field); it is recorded in
            # `verify_seed`'s own prose and pinned HERE, because the next
            # field to arrive silently would change a command's output with
            # nobody having decided it should.  If this fails, the question
            # is not "what is the new set" — it is "who added a field, and is
            # the operator reading this output expecting it".
            check("the verify report carries exactly the fields it is "
                  "documented to carry, D6's included",
                  set(v) == {"seed_key", "format", "artifacts_ok", "stale",
                             "needs_database", "workspace", "database",
                             "source_key_now", "rules_changed"},
                  str(sorted(v)))
            check("and without a source root it drops exactly the two "
                  "staleness fields, no more",
                  set(verify_seed(seed_dir))
                  == set(v) - {"source_key_now", "rules_changed"})
            check("a manifest written before the field existed reports the "
                  "value provision will ACT on, not a declaration it never "
                  "made",
                  "needs_database" not in read_seed(seed_dir)
                  and v["needs_database"] is True)
            write("composer.json", '{"changed": true}')
            v2 = verify_seed(seed_dir, source_root=root)
            check("a source change makes the seed report itself STALE",
                  v2["stale"] is True and v2["workspace"]["ok"])
            with open(os.path.join(seed_dir, WORKSPACE_TAR), "ab") as fh:
                fh.write(b"corruption")
            check("a corrupted tar fails verification",
                  not verify_seed(seed_dir)["artifacts_ok"])

    # ---- the policy is data now, and CoreShop's must not have moved --------
    #
    # `rules_digest` is inside every CoreShop seed key on disk, and the seed
    # key is inside the campaign fingerprint the archived manifests re-hash.
    # Everything above would still pass if the hashed document had gained a
    # key, or if a default had changed: nothing there compares the digest with
    # a LITERAL. This does. If it fails, the answer is never to re-pin it --
    # it means the seed at /data2/binhang/coreshop_bench/seed/v1 no longer
    # identifies itself and every campaign built on it stopped verifying.
    _FROZEN_RULES_DIGEST = "6f28900b8f71453c"
    check("the CoreShop pruning policy still hashes to its pinned digest",
          DEFAULT_RULES.digest() == _FROZEN_RULES_DIGEST
          and rules_digest() == _FROZEN_RULES_DIGEST,
          f"{DEFAULT_RULES.digest()} != {_FROZEN_RULES_DIGEST}")
    check("a seed manifest predating the volatile field reconstructs the "
          "frozen CoreShop omissions",
          SeedRules.from_manifest({}).volatile == CORESHOP_SEED_VOLATILE)
    check("the frozen seed omissions remain runtime-volatile while the "
          "generated reference is classification-only",
          DEFAULT_RULES.volatile < SUBSTRATE_VOLATILE
          and SUBSTRATE_VOLATILE - DEFAULT_RULES.volatile
          == frozenset({"config/reference.php"}))
    check("the hashed policy document is still exactly six keys",
          set(json.loads(_canon({
              "format": 1, "prune_tables": [], "prune_paths": [],
              "exclude_paths": [], "keep_empty": [], "volatile": []}))) ==
          {"format", "prune_tables", "prune_paths", "exclude_paths",
           "keep_empty", "volatile"})
    check("a second stack has a DIFFERENT policy, not a copy of the first",
          BEHAVE_RULES.digest() != DEFAULT_RULES.digest()
          and BEHAVE_RULES.prune_tables == ())
    _FROZEN_BEHAVE_RULES_DIGEST = "48836f0af0530eab"
    check("the Behave pruning policy still hashes to its pinned digest",
          BEHAVE_RULES.digest() == _FROZEN_BEHAVE_RULES_DIGEST,
          f"{BEHAVE_RULES.digest()} != {_FROZEN_BEHAVE_RULES_DIGEST}")
    check("an unknown framework is refused a policy rather than given "
          "CoreShop's",
          rules_for("behat") is DEFAULT_RULES
          and rules_for("behave") is BEHAVE_RULES
          and rules_for("cucumber") is CUCUMBER_RULES
          and rules_for("cucumber_ruby") is RUBY_RULES
          and refused(lambda: rules_for("unknown")))
    # Sylius's row, and the one number it must not move.
    #
    # `mysqldump --no-data <db> versions messenger_messages` FAILS on a
    # schema that has neither table, and Sylius's 83 do not -- so an empty
    # `prune_tables` is what makes its seed buildable at all, and the
    # CoreShop digest beside it is what says the row did not reach the
    # policy every archived seed was built under.
    check("a project row is consulted inside its framework, not instead of "
          "it",
          rules_for("behat", "sylius") is SYLIUS_RULES
          and rules_for("behat", "coreshop") is DEFAULT_RULES
          and rules_for("behat") is DEFAULT_RULES
          and rules_for("behat", "some-new-behat-project") is DEFAULT_RULES
          and refused(lambda: rules_for("unknown", "sylius")))
    check("Sylius empties NO table -- its schema has neither of the two "
          "CoreShop's policy names, and `mysqldump` fails on a missing one",
          SYLIUS_RULES.prune_tables == () and SYLIUS_RULES.prune_paths == ()
          and set(DEFAULT_RULES.prune_tables)
          == {"versions", "messenger_messages"})
    check("...so it is a DIFFERENT policy, which `_FROZEN_RULES_DIGEST` "
          "above is what keeps out of CoreShop's",
          SYLIUS_RULES.digest() != DEFAULT_RULES.digest(),
          f"{DEFAULT_RULES.digest()} / {SYLIUS_RULES.digest()}")
    # The recreate/volatile pairing, which is the one fact the hashed document
    # deliberately does NOT state twice.  A file put back on unpack that was
    # never declared volatile is a file the substrate baseline never saw, and
    # the first item would abort as tampering.
    for label, rr in (("coreshop", DEFAULT_RULES), ("behave", BEHAVE_RULES),
                      ("cucumber", CUCUMBER_RULES), ("sylius", SYLIUS_RULES),
                      ("ruby", RUBY_RULES)):
        undeclared = [rel for rel, _ in rr.recreate if rel not in rr.volatile]
        check(f"every file the {label} policy recreates is a declared "
              f"volatile one", not undeclared, str(undeclared))

    # Real workspace selection: preserve reference helpers, fixtures, source
    # assets and locks while omitting state a prior Ruby process generated.
    with tempfile.TemporaryDirectory() as root:
        retained = (
            "app/models/petition.rb", "app/views/pages/home.html.erb",
            "app/assets/stylesheets/application.scss", "public/robots.txt",
            "features/support/paths.rb", "spec/fixtures/vcr/search.yml",
            "spec/support/constituency_api.rb", "spec/factories.rb",
            "Gemfile.lock", "package-lock.json", "_bench/bench_recorder.rb",
        )
        generated = (
            "node_modules/esbuild/bin/esbuild", ".bundle/config", ".git/config",
            "app/assets/builds/.keep", "public/assets/application.css",
            "log/test.log", "tmp/cache/bootsnap/x", "coverage/index.html",
            "storage/upload", "_bench/run_record.jsonl", "_bench/item.feature",
        )
        for rel in retained + generated:
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("fixture\n")
        check("Ruby seeds preserve inputs and omit runtime dependency/output state",
              set(workspace_files(root, RUBY_RULES)) == set(retained))
        check("Ruby seed rules preserve empty build/log/tmp directories only",
              RUBY_RULES.keep_empty == ("app/assets/builds", "log", "tmp")
              and not RUBY_RULES.recreate and not RUBY_RULES.prune_tables)

    # ---- Java+Cucumber: source-only input, generated Maven output omitted ---
    with tempfile.TemporaryDirectory() as root:
        def write(rel, text="x"):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        write("pom.xml", "<project/>\n")
        write(".mvn/wrapper/maven-wrapper.properties", "distributionUrl=x\n")
        write("src/main/java/example/App.java", "class App {}\n")
        write("src/test/java/example/steps/CartSteps.java",
              "class CartSteps {}\n")
        write("src/test/resources/features/cart.feature", "Feature: cart\n")
        write("src/test/resources/fixtures/cart.json", "{}\n")
        write("target/classes/example/App.class", "generated")
        write("module/target/surefire-reports/test.txt", "generated")
        write("retarget/TargetName.java", "class TargetName {}\n")
        write("module/target-output/report.txt", "retained")
        write(".git/config", "generated")
        write(".r2t-exec.lock", "generated")

        files = workspace_files(root, CUCUMBER_RULES)
        check("root and nested Maven target trees are not seeded",
              not any(part == "target" for rel in files
                      for part in rel.split("/")), str(files))
        anchored_target_mutant = SeedRules(
            prune_tables=(), prune_paths=(),
            exclude_paths=(".r2t-exec.lock", ".git", "target"),
            keep_empty=(), volatile=frozenset(), recreate=())
        mutant_files = workspace_files(root, anchored_target_mutant)
        check("J3 mutation probe kills anchored-only target exclusion",
              "target/classes/example/App.class" not in mutant_files
              and "module/target/surefire-reports/test.txt" in mutant_files
              and "module/target/surefire-reports/test.txt" not in files,
              str(mutant_files))
        check("J3 mutation probe kills overbroad target-name exclusion",
              "retarget/TargetName.java" in files
              and "module/target-output/report.txt" in files, str(files))
        check("the Maven descriptor and wrapper are seeded",
              "pom.xml" in files
              and ".mvn/wrapper/maven-wrapper.properties" in files,
              str(files))
        check("Java sources, Cucumber glue, and resource fixtures are seeded",
              {"src/main/java/example/App.java",
               "src/test/java/example/steps/CartSteps.java",
               "src/test/resources/features/cart.feature",
               "src/test/resources/fixtures/cart.json"}.issubset(files),
              str(files))
        check("root Git metadata and the execution lock are not seeded",
              ".git/config" not in files and ".r2t-exec.lock" not in files,
              str(files))

        inputs1 = workspace_inputs_digest(root, rules=CUCUMBER_RULES)
        key1 = seed_key(root, NO_DATABASE, rules=CUCUMBER_RULES)
        write("target/classes/example/App.class", "changed generated output")
        write("module/submodule/target/new-report.txt", "new generated output")
        inputs2 = workspace_inputs_digest(root, rules=CUCUMBER_RULES)
        key2 = seed_key(root, NO_DATABASE, rules=CUCUMBER_RULES)
        check("changes and additions under target leave the workspace digest "
              "and seed key unchanged",
              inputs2 == inputs1 and key2 == key1,
              f"{inputs1} / {inputs2} / {key1} / {key2}")
        write("src/main/java/example/App.java", "class App { int changed; }\n")
        inputs3 = workspace_inputs_digest(root, rules=CUCUMBER_RULES)
        key3 = seed_key(root, NO_DATABASE, rules=CUCUMBER_RULES)
        check("an included Java edit changes the workspace digest and seed key",
              inputs3["digest"] != inputs2["digest"]
              and key3["seed_key"] != key2["seed_key"])

        roundtrip = SeedRules.from_manifest(CUCUMBER_RULES.to_manifest())
        check("the Cucumber pruning policy round-trips through a seed manifest",
              roundtrip == CUCUMBER_RULES
              and roundtrip.digest() == CUCUMBER_RULES.digest())
        check("the Cucumber policy has no database pruning or mutable state",
              CUCUMBER_RULES.prune_tables == ()
              and CUCUMBER_RULES.prune_paths == ()
              and CUCUMBER_RULES.keep_empty == ()
              and CUCUMBER_RULES.volatile == frozenset()
              and CUCUMBER_RULES.recreate == ())

    # ---- the name rule, and the null-database branch -----------------------
    with tempfile.TemporaryDirectory() as root:
        def write(rel, text="x"):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        write("src/docx/__init__.py", "VERSION = 1\n")
        write("src/docx/__pycache__/__init__.cpython-312.pyc", "\x00")
        write("features/environment.py", "def before_all(c): pass\n")
        write("features/steps/test_files/doc-default.docx", "PK")
        write("features/_scratch/test_out.docx", "leftover")
        write("pyproject.toml", "[project]\n")
        write(f"{BENCH_DIR}/run_record.jsonl", "{}\n")

        files = workspace_files(root, BEHAVE_RULES)
        check("`**/__pycache__` prunes bytecode wherever it appears, which an "
              "anchored path rule cannot do",
              not any(f"/{'__pycache__'}/" in f for f in files)
              and "src/docx/__init__.py" in files, str(files))
        check("the scratch directory is not seeded — one worker's leftovers "
              "are not every worker's starting state",
              not any(f.startswith("features/_scratch/") for f in files))
        check("the fixtures ARE seeded: they are what the scenarios read",
              "features/steps/test_files/doc-default.docx" in files)
        check("the recorder's per-item output is volatile, not seeded",
              f"{BENCH_DIR}/run_record.jsonl" not in files)
        check("CoreShop's policy does NOT prune bytecode — the rule is the "
              "behave policy's, not a global change",
              any("__pycache__" in f for f in workspace_files(root)))

        b = load_boundary(os.path.join(here, "config",
                                       "boundary_python_docx.yml"),
                          repo_root=root)

        class _NeverDB:
            def dump(self, *a, **k):
                raise AssertionError("a stack with no database must not dump")

        with tempfile.TemporaryDirectory() as seed_dir:
            doc = build_seed(root, b, seed_dir, None, None,
                             rules=BEHAVE_RULES, needs_database=False)
            check("a seed with no database records the DECLARED sentinel, not "
                  "a missing key",
                  doc["database_dump_digest"] == NO_DATABASE
                  and doc["database"]["declared"] == NO_DATABASE
                  and doc["needs_database"] is False, json.dumps(doc)[:300])
            check("no database.sql is written",
                  not os.path.isfile(os.path.join(seed_dir, DATABASE_SQL)))
            check("the seed still verifies, by reading the declaration",
                  verify_seed(seed_dir)["artifacts_ok"])
            # The report's `needs_database` is LOAD-BEARING, and this is what
            # binds it: provision reads that field and nothing else to decide
            # whether the two halves of a worker agree about the stack.  The
            # refusal lands before any container or schema exists, so the
            # check costs no docker.
            from .worker import WorkerRefused, plan_workers, provision
            spec = plan_workers(os.path.join(root, "workers"), 1,
                                prefix="docx", kind="py",
                                needs_database=False)[0]
            try:
                provision(spec, seed_dir, None, needs_database=True)
                why = "provisioned it anyway"
            except WorkerRefused as exc:
                why = str(exc)
            check("provisioning a database-less seed as if it had one is "
                  "refused by reading that field",
                  "was built without a database" in why, why[:200])
            check("its identity is not the identity of a seed built with a "
                  "database from the same tree",
                  doc["seed_key"] != seed_key(root, "some_schema",
                                              rules=BEHAVE_RULES)["seed_key"])
            # Fail closed: a dump sitting beside a manifest that says there is
            # no database is a seed nobody can attribute.
            with open(os.path.join(seed_dir, DATABASE_SQL), "w") as fh:
                fh.write("-- a dump that should not be here\n")
            check("a stray dump beside the declaration FAILS verification",
                  not verify_seed(seed_dir)["artifacts_ok"])
            os.remove(os.path.join(seed_dir, DATABASE_SQL))
            check("staleness is judged under the policy the seed records, not "
                  "the module default",
                  verify_seed(seed_dir, source_root=root)["stale"] is False)
            with tempfile.TemporaryDirectory() as dest:
                info = unpack_workspace(seed_dir, dest, force=True)
                check("nothing is recreated in a behave workspace — no "
                      "Symfony fragment lands in a hashed substrate root",
                      info["recreated"] == []
                      and not os.path.exists(
                          os.path.join(dest, BENCH_DIR, "services_item.yml")))
                check("and the scratch directory is there, empty",
                      os.path.isdir(os.path.join(dest, "features/_scratch"))
                      and not os.listdir(
                          os.path.join(dest, "features/_scratch")))

        # The two directions of the declaration, both refused when they
        # disagree with their arguments.
        with tempfile.TemporaryDirectory() as seed_dir:
            check("declaring no database while naming a schema is refused",
                  refused(lambda: build_seed(root, b, seed_dir, "docx_bench",
                                             None, rules=BEHAVE_RULES,
                                             needs_database=False)))
            check("declaring no database while handing over a connection is "
                  "refused",
                  refused(lambda: build_seed(root, b, seed_dir, None,
                                             _NeverDB(), rules=BEHAVE_RULES,
                                             needs_database=False)))
            check("and the sentinel cannot be used as a schema NAME",
                  refused(lambda: build_seed(root, b, seed_dir, NO_DATABASE,
                                             _NeverDB(), rules=BEHAVE_RULES,
                                             needs_database=True)))

    # A real archive round trip proves that distributed Go helper files and
    # embed resources survive while execution state and answers cannot leak.
    with tempfile.TemporaryDirectory() as task_dir:
        root = os.path.join(task_dir, "work")
        os.makedirs(root)
        kept = {"go.mod": "module fixture\n", "go.sum": "module sum\n",
                "internal/agent/agent.go": "package agent\n",
                "internal/agent/agent_test.go": "package agent\n",
                "internal/agent/prompt.md": "embedded instructions\n",
                "features/agent.feature": "Feature: agent\n",
                "_bench/go/support/helper.go": "trusted helper\n"}
        for rel, content in {**kept, ".git/HEAD": "answer history",
                             ".r2t-exec.lock": "locked",
                             "_bench/run_record.jsonl": "old record"}.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        answer = "internal/agent/bdd_agent_test.go"
        b = Boundary(1, "go-fixture", root,
                     removable=[(answer, "answer")],
                     retained=[("internal/agent/agent_test.go", "helper")])
        seed_dir = os.path.join(task_dir, "seed")
        doc = build_seed(root, b, seed_dir, None, None,
                         rules=rules_for("godog"), needs_database=False)
        dest = os.path.join(task_dir, "unpacked")
        unpack_workspace(seed_dir, dest)
        observed = {}
        for rel in workspace_files(dest, GO_RULES):
            with open(os.path.join(dest, rel), encoding="utf-8") as fh:
                observed[rel] = fh.read()
        check("Go seed round trip keeps protected helpers and embed bytes",
              observed == kept and verify_seed(seed_dir)["artifacts_ok"])
        check("Go seed excludes Git, lock and prior output without placeholders",
              all(not os.path.exists(os.path.join(dest, rel))
                  for rel in (".git", ".r2t-exec.lock", "_bench/run_record.jsonl")))
        check("Go seed has the existing no-database identity",
              doc["database_dump_digest"] == NO_DATABASE
              and doc["needs_database"] is False
              and not os.path.exists(os.path.join(seed_dir, DATABASE_SQL)))
        with open(os.path.join(root, answer), "w", encoding="utf-8") as fh:
            fh.write("package agent\n")
        answer_refused = False
        try:
            build_seed(root, b, os.path.join(task_dir, "answer-seed"), None,
                       None, rules=GO_RULES, needs_database=False)
        except SeedRefused:
            answer_refused = True
        check("a Go seed containing distributed answer glue is refused",
              answer_refused)

    # The derived-state baseline (v1.1) is the tar's own bytes for the
    # declared roots, and nothing else.
    from .repo import DERIVED_STATE_ROOTS
    with tempfile.TemporaryDirectory() as root:
        tree = {"var/classes/DataObject/P.php": b"<?php class P {}\n",
                "var/classes/definition_P.php": b"<?php return [];\n",
                "var/classesque/not-a-member.php": b"<?php\n",
                "src/P.php": b"<?php // production source\n"}
        for rel, data in tree.items():
            full = os.path.join(root, "tree", rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(data)
        seed_dir = os.path.join(root, "seed")
        os.makedirs(seed_dir)
        _tar_workspace(os.path.join(root, "tree"), sorted(tree),
                       os.path.join(seed_dir, WORKSPACE_TAR))
        members = derived_state_members(seed_dir, DERIVED_STATE_ROOTS)
        check("the derived baseline is exactly the tar's files under the "
              "declared roots, byte for byte -- not a sibling that shares a "
              "prefix, not production source",
              members == {rel: data for rel, data in tree.items()
                          if rel.startswith("var/classes/")}, str(members))
        check("a stack that declares no roots reads nothing",
              derived_state_members(seed_dir, ()) == {})
        check("a declared root the seed carries nothing under is refused, "
              "because restoring to nothing restores nothing",
              refused(lambda: derived_state_members(
                  seed_dir, ("var/classes", "var/generated"))))
        linked_dir = os.path.join(root, "linked")
        os.makedirs(linked_dir)
        with tarfile.open(os.path.join(linked_dir, WORKSPACE_TAR), "w") as tar:
            info = tarfile.TarInfo("var/classes/DataObject/P.php")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
        check("a non-regular member under a root is refused, not read",
              refused(lambda: derived_state_members(linked_dir,
                                                    DERIVED_STATE_ROOTS)))

    print("\n" + ("ALL PASS (seed)" if ok else "FAILURES (seed)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
