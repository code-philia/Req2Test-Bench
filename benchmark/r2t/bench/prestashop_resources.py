"""Seed-exact native resource lifecycle; PRESTASHOP_RUNTIME_RESOURCE_RESET_SPEC.

Only PrestaShop uses this policy. Inputs live beside gold, outside the worker;
post-execution comparison never exempts an immutable sibling or blesses new bytes.

The worker's database gets the same care for its seeded TABLES
(specifications/BENCHMARK_V2_SPEC.md section 8.1, harness 26): see
`ensure_seeded_schema` and `retained_hook_database_fault`.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from typing import Optional

NAME = "prestashop_resources"
_NATIVE = ("tests/Resources/img", "tests/Resources/download", "tests/Resources/modules")
_LOCALE = re.compile(r"[a-z]{2}(?:-[A-Z]{2})?")
_SHOP = re.compile(r"config/themes/[^/]+/shop[0-9]*\.json")
#: Upload fixtures that Behat steps hand to PrestaShop's uploaders, which may
#: move or delete them (spec section "Consumed upload fixtures"). An execution
#: that changes nothing immutable but these is restored from the bytes verified
#: at its own entry and reported as `fixture_consumed`, an infrastructure
#: outcome; any other change still stops the campaign.
FIXTURES = "tests/Resources/dummyFile"


class ResourceResetError(RuntimeError):
    """A resource input or restoration is invalid; the worker must stop."""


def selected(rel: str) -> bool:
    if rel == "robots.txt" or _SHOP.fullmatch(rel):
        return True
    if any(rel == p or rel.startswith(p + "/") for p in _NATIVE):
        return True
    parts = rel.split("/")
    return (len(parts) >= 2 and parts[0] in ("mails", "translations")
            and _LOCALE.fullmatch(parts[1]) is not None)


def _safe_parent(root: str, rel: str) -> None:
    """Never walk through a link while inspecting or restoring resources."""
    path = root
    for part in rel.split("/")[:-1]:
        path = os.path.join(path, part)
        if os.path.lexists(path) and (os.path.islink(path) or not os.path.isdir(path)):
            raise ResourceResetError(f"Resource parent is not a directory: {path}")


def _children(root: str, rel: str) -> list[str]:
    _safe_parent(root, rel + "/child")
    path = os.path.join(root, rel)
    if not os.path.exists(path):
        return []
    return sorted(os.listdir(path))


def roots(root: str) -> list[str]:
    paths = list(_NATIVE) + ["robots.txt"]
    for parent in ("mails", "translations"):
        paths.extend(f"{parent}/{name}" for name in _children(root, parent)
                     if _LOCALE.fullmatch(name))
    for theme in _children(root, "config/themes"):
        parent = f"config/themes/{theme}"
        # Theme entries outside the generated shop-settings shape remain
        # immutable. A changed directory link is refused rather than followed.
        if os.path.isdir(os.path.join(root, parent)) or os.path.islink(os.path.join(root, parent)):
            paths.extend(f"{parent}/{name}" for name in _children(root, parent)
                         if _SHOP.fullmatch(f"{parent}/{name}"))
    return sorted(paths)


def _entry(path: str) -> dict:
    st = os.lstat(path)
    value = {"mode": stat.S_IMODE(st.st_mode)}
    if stat.S_ISLNK(st.st_mode):
        value.update(kind="link", target=os.readlink(path))
    elif stat.S_ISDIR(st.st_mode):
        value.update(kind="directory")
    elif stat.S_ISREG(st.st_mode):
        from .repo import _sha256
        value.update(kind="file", sha256=_sha256(path))
    else:
        raise ResourceResetError(f"Unsupported native resource file: {path}")
    return value


def inventory(root: str) -> dict:
    entries = {}

    def visit(rel):
        _safe_parent(root, rel)
        path = os.path.join(root, rel)
        if not os.path.lexists(path):
            return
        value = entries[rel] = _entry(path)
        if value["kind"] == "directory":
            for child in sorted(os.listdir(path)):
                visit(rel + "/" + child)

    for rel in roots(root):
        visit(rel)
    return entries


def _copy_entries(source: str, target: str, entries: dict) -> None:
    for rel, value in sorted(entries.items(), key=lambda pair: (pair[0].count("/"), pair[0])):
        _safe_parent(target, rel)
        path = os.path.join(target, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if value["kind"] == "directory":
            os.makedirs(path, exist_ok=True)
        elif value["kind"] == "link":
            os.symlink(value["target"], path)
        else:
            shutil.copyfile(os.path.join(source, rel), path, follow_symlinks=False)
            os.chmod(path, value["mode"])
    # Apply directory modes last, so a read-only fixture can contain children.
    for rel, value in sorted(entries.items(), reverse=True):
        if value["kind"] == "directory":
            os.chmod(os.path.join(target, rel), value["mode"])


def capture(manifest) -> None:
    source = os.path.abspath(manifest.repo_root)
    target = os.path.join(os.path.abspath(manifest.gold_root), NAME)
    if os.path.commonpath([source, target]) == source:
        raise ResourceResetError("Native resource baseline must live outside the worker")
    os.makedirs(target, exist_ok=False)
    entries = inventory(source)
    # Match unpack_workspace before recording the seed baseline. Native
    # installers often produce 666/777 resources; workers remove peer writes.
    for rel, entry in entries.items():
        if entry["kind"] != "link":
            entry["mode"] &= ~0o022
            os.chmod(os.path.join(source, rel), entry["mode"])
    _copy_entries(source, target, entries)
    manifest.prestashop_resources = {"schema": 1, "entries": entries}
    verify_inputs(manifest, bind_digests=False)


def verify_inputs(manifest, *, bind_digests: bool = True) -> dict:
    baseline = manifest.prestashop_resources
    if not baseline or baseline.get("schema") != 1 or not isinstance(baseline.get("entries"), dict):
        raise ResourceResetError("PrestaShop requires a fresh strip with native resource inputs")
    entries = baseline["entries"]
    if any(not selected(rel) or rel.startswith("/") or ".." in rel.split("/") for rel in entries):
        raise ResourceResetError("Native resource baseline contains a path outside the closed scope")
    target = os.path.join(os.path.abspath(manifest.gold_root), NAME)
    if os.path.commonpath([os.path.abspath(manifest.repo_root), target]) == os.path.abspath(manifest.repo_root):
        raise ResourceResetError("Native resource baseline must live outside the worker")
    if inventory(target) != entries:
        raise ResourceResetError("Protected native resource baseline changed")
    if bind_digests:
        if not manifest.digests:
            raise ResourceResetError("Native resource baseline requires substrate digests")
        for rel, entry in entries.items():
            if entry["kind"] == "file" and manifest.digests.get(rel) != entry["sha256"]:
                raise ResourceResetError(f"Resource is not bound to the strip baseline: {rel}")
    return entries


def verify_entry(manifest) -> None:
    entries = verify_inputs(manifest)
    if inventory(manifest.repo_root) != entries:
        raise ResourceResetError("Native resource state differs from its seed on execution entry")


def restore(manifest) -> None:
    entries = verify_inputs(manifest)
    root = manifest.repo_root
    # The iterator never follows a resource symlink. Unlinking the selected
    # node itself leaves any external target untouched.
    for rel in roots(root):
        _safe_parent(root, rel)
        path = os.path.join(root, rel)
        if os.path.islink(path) or os.path.isfile(path):
            os.unlink(path)
        elif os.path.isdir(path):
            # Native fixtures may contain read-only directories. They are
            # session-owned, selected resources, and are immediately replaced.
            for directory, dirs, _ in os.walk(path, followlinks=False):
                os.chmod(directory, os.stat(directory).st_mode | stat.S_IWUSR)
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(directory, d))]
            shutil.rmtree(path)
    _copy_entries(os.path.join(manifest.gold_root, NAME), root, entries)
    verify_entry(manifest)


def post_execute(harness) -> None:
    """Compare immutable bytes before erasing any native state transition."""
    from .repo import SubstrateTampered, compare_substrate_inventory, substrate_digests
    man = harness.man
    verify_inputs(man)
    # Inventory validates all resource ancestors before the substrate walk;
    # this also refuses a replaced parent link without reading its target.
    inventory(man.repo_root)
    current = substrate_digests(man.repo_root, harness.boundary,
                                man.roots(), man.volatile(), skip=selected)
    report = compare_substrate_inventory(
        {r: d for r, d in man.digests.items() if r not in man.volatile() and not selected(r)},
        current, harness.expected_mutations)
    if any(report[k] for k in ("changed", "missing", "added")):
        consumed = _restore_fixtures(man.repo_root, report,
                                     getattr(harness, "fixture_snapshot", None))
        if consumed is None:
            raise SubstrateTampered(report)
        harness.fixture_consumed = consumed
    restore(man)
    harness.verify_substrate()


def snapshot_fixtures(root: str) -> dict:
    """The upload fixtures' bytes and modes, read right after the entry check."""
    base = os.path.join(root, FIXTURES)
    snapshot: dict = {}
    if os.path.islink(base) or not os.path.isdir(base):
        return snapshot
    for directory, dirs, files in os.walk(base, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(directory, d))]
        for name in files:
            path = os.path.join(directory, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            with open(path, "rb") as fh:
                snapshot[os.path.relpath(path, root)] = (
                    fh.read(), stat.S_IMODE(os.lstat(path).st_mode))
    return snapshot


def _restore_fixtures(root: str, report: dict, snapshot) -> "list[str] | None":
    """Restore consumed upload fixtures; None when anything else changed."""
    paths = sorted({p for k in ("changed", "missing", "added") for p in report[k]})
    if not snapshot or not paths \
            or any(not p.startswith(FIXTURES + "/") for p in paths) \
            or any(p not in snapshot for p in report["changed"] + report["missing"]):
        return None
    # Judge every node before touching any, so a refusal keeps its evidence.
    for rel in paths:
        _safe_parent(root, rel)
        path = os.path.join(root, rel)
        if os.path.lexists(path) and not os.path.islink(path) \
                and not os.path.isfile(path):
            return None
    for rel in paths:
        path = os.path.join(root, rel)
        if os.path.lexists(path):
            os.unlink(path)
    for rel in report["changed"] + report["missing"]:
        data, mode = snapshot[rel]
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "xb") as fh:
            fh.write(data)
        os.chmod(path, mode)
    return paths


# ------------------------------------------------------- seeded schema health
#
# BENCHMARK_V2_SPEC.md section 8.1.  The retained `@restore-all-tables-before-
# feature` hook (`Tests\Resources\DatabaseDump::restoreAllTables`) restores
# only the tables `SHOW TABLES` lists, so a table a killed restore dropped
# between its DROP and its CREATE is never recreated.  On 2026-10-16 that left
# one evaluation worker without `ps_lang` for about 12 hours: every later item
# failed in the retained BeforeSuite hook before any step ran, and 66 rows read
# as ordinary `no_scenario_ran`.  So the harness compares the worker's tables
# with the seeded table list before every execution and after a killed or
# timed-out one, restores the native full dump when one is missing, and stops
# the worker when that does not bring it back.

#: The native restore inputs every PrestaShop workspace carries (the template's
#: `composer create-test-db` dumps; `prestashop_worker_init.php` copies them
#: into the container's private /tmp for the retained DatabaseDump hooks).
DUMPS = "var/r2t-db-dumps"
_TABLE = re.compile(r"ps_[A-Za-z0-9_]+")
_SCHEMA_SECONDS = 120
#: The full dump is the whole seeded database; a slow host takes minutes,
#: and a host under heavy I/O took 1,249 s into an empty schema and 2,109 s
#: over a loaded one, so this is only a guard against a restore that hangs.
_RESTORE_SECONDS = 7200


class SeededSchemaFault(ResourceResetError):
    """The worker's schema lacks a seeded table and could not be restored.

    `stops_worker` reaches the item's `harness_error` row as
    `metadata.worker_stop` (`runner._harness_error_row`), and the cell
    launcher stops the worker at once rather than after a streak.
    """
    stops_worker = True


class RetainedHookDatabaseFault(RuntimeError):
    """A retained BeforeSuite hook threw a database exception: the run
    measured nothing, so its row is infrastructure (`harness_error`) and a
    worker fault, not the submission's `no_scenario_ran`."""


#: The schema program, run inside the worker container with the worker's own
#: DSN and sent on stdin, so it never becomes a workspace file the substrate
#: check would see.  `check` lists the schema's tables.  `restore DUMP` first
#: loads the native full dump with the mysql client, as
#: `Tests\Resources\DatabaseDump::restore` does, but through a mode-0600
#: defaults file instead of a password argument.  It prints one JSON line; a
#: PDO error is reported by class and code only, because its message can carry
#: connection details.
_SCHEMA_PHP = r"""<?php
declare(strict_types=1);
$out = ['action' => $argv[1] ?? ''];
$cnf = null;
try {
    $dsn = parse_url((string) getenv('DATABASE_URL'));
    if (!is_array($dsn) || ($dsn['scheme'] ?? '') !== 'mysql') {
        throw new RuntimeException('no MySQL DATABASE_URL');
    }
    $schema = rawurldecode(ltrim($dsn['path'] ?? '', '/'));
    $host = $dsn['host'] ?? '';
    $port = (int) ($dsn['port'] ?? 3306);
    $user = rawurldecode($dsn['user'] ?? '');
    $pass = rawurldecode($dsn['pass'] ?? '');
    $out['schema'] = $schema;
    if ($out['action'] === 'restore') {
        $dump = $argv[2] ?? '';
        if (!is_file($dump)) {
            throw new RuntimeException('no full dump at ' . $dump);
        }
        $cnf = tempnam(sys_get_temp_dir(), 'r2t-schema-');
        if ($cnf === false || file_put_contents(
                $cnf, "[client]\nuser=$user\npassword=$pass\nhost=$host\nport=$port\n") === false) {
            throw new RuntimeException('cannot write the client defaults file');
        }
        $process = proc_open(['mysql', '--defaults-extra-file=' . $cnf, $schema],
            [0 => ['file', $dump, 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            throw new RuntimeException('cannot start mysql');
        }
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        $out['restore_exit'] = proc_close($process);
        $out['restore_stderr'] = substr(trim($stderr), 0, 300);
    }
    $db = new PDO(sprintf('mysql:host=%s;port=%d;dbname=%s', $host, $port, $schema), $user, $pass,
                  [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $query = $db->prepare('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?');
    $query->execute([$schema]);
    $out['tables'] = $query->fetchAll(PDO::FETCH_COLUMN);
} catch (Throwable $error) {
    $out['error'] = get_class($error) . ($error instanceof PDOException
        ? ' ' . $error->getCode() : ': ' . $error->getMessage());
} finally {
    if (is_string($cnf)) {
        @unlink($cnf);
    }
}
echo json_encode($out), "\n";
"""


def seeded_dump(root: str) -> tuple[str, list[str]]:
    """The native full dump and the seeded table list of a workspace.

    The seeded tables are the `*.md5` restore inputs of `DUMPS`
    (`ps_dump_<schema>_<version>_<table>.md5`, 244 in the 2026-10-16
    incident); the full dump is the one `<prefix>.sql` whose prefix every
    checksum file carries.  A table's own `<prefix>_<table>.sql` never
    qualifies: no other table is named `<table>_ps_...`.
    """
    try:
        names = os.listdir(os.path.join(root, DUMPS))
    except OSError:
        raise SeededSchemaFault(
            f"no native restore inputs at {DUMPS}, so the seeded table list "
            "is unknown; this worker must stop") from None
    checksums = sorted(n for n in names if n.endswith(".md5"))
    wholes = [n[:-len(".sql")] for n in names if n.endswith(".sql") and checksums
              and all(c.startswith(n[:-len(".sql")] + "_ps_") for c in checksums)]
    tables = ([c[len(wholes[0]) + 1:-len(".md5")] for c in checksums]
              if len(wholes) == 1 else [])
    if not tables or not all(_TABLE.fullmatch(t) for t in tables):
        raise SeededSchemaFault(
            f"{DUMPS} holds {len(checksums)} table checksum(s) and "
            f"{len(wholes)} full dump(s) that name them all; the seeded table "
            "list is unknown, so this worker must stop")
    return f"{DUMPS}/{wholes[0]}.sql", tables


def _schema(runner, *args: str, timeout: int) -> dict:
    """Run `_SCHEMA_PHP` with `args` in the worker; refuse an unreadable answer."""
    try:
        cp = runner.run("php -- " + " ".join(shlex.quote(a) for a in args),
                        env={"XDEBUG_MODE": "off"}, timeout=timeout,
                        input=_SCHEMA_PHP)
    except subprocess.TimeoutExpired:
        raise SeededSchemaFault(
            f"the worker's schema {args[0]} did not finish within {timeout} s; "
            "this worker must stop") from None
    lines = (cp.stdout or "").strip().splitlines()
    try:
        doc = json.loads(lines[-1]) if lines else None
    except ValueError:
        doc = None
    if not isinstance(doc, dict) or doc.get("error") \
            or not isinstance(doc.get("tables"), list):
        why = (doc.get("error") if isinstance(doc, dict) and doc.get("error")
               else f"exit {cp.returncode}, no table list")
        raise SeededSchemaFault(
            f"the worker's schema could not be read ({args[0]}: {why}); "
            "this worker must stop")
    return doc


def ensure_seeded_schema(harness, when: str) -> list:
    """Check the worker's tables against the seeded list; restore or stop.

    Returns the seeded tables the full dump restored (empty when none was
    missing).  Raises `SeededSchemaFault` when the schema cannot be read, or
    when a seeded table is still missing after the restore.  Tables beyond
    the seeded list are not this check's business.
    """
    dump, seeded = seeded_dump(harness.man.repo_root)
    present = _schema(harness.runner, "check", timeout=_SCHEMA_SECONDS)["tables"]
    missing = sorted(set(seeded) - set(present))
    if not missing:
        return []
    named = ", ".join(missing[:8]) + (", ..." if len(missing) > 8 else "")
    print(f"r2t: the worker's schema lacks {len(missing)} of {len(seeded)} "
          f"seeded tables {when} ({named}); restoring the full dump {dump}",
          file=sys.stderr, flush=True)
    doc = _schema(harness.runner, "restore", harness.runner.in_container(dump),
                  timeout=_RESTORE_SECONDS)
    still = sorted(set(seeded) - set(doc["tables"]))
    if doc.get("restore_exit") != 0 or still:
        raise SeededSchemaFault(
            f"the worker's schema lacked seeded tables {when} ({named}), and "
            f"the full dump did not restore them (mysql exit "
            f"{doc.get('restore_exit')!r}: {doc.get('restore_stderr') or '-'}; "
            f"still missing: {', '.join(still[:8]) or 'none'}); this worker "
            "must stop")
    print(f"r2t: the full dump restored {named}; all {len(seeded)} seeded "
          "tables are present", file=sys.stderr, flush=True)
    return missing


#: Behat's pretty output of a hook that threw:
#:     ┌─ @BeforeSuite # Tests\...\CommonFeatureContext::prepare()
#:     │
#:     ╳  Table 'test_prestashop_rr_2.ps_lang' doesn't exist<br />... (PrestaShopDatabaseException)
#:     │
_BEFORE_SUITE = re.compile(r"┌─ @BeforeSuite # (?P<callee>[A-Za-z_\\][\w\\]*)::(?P<method>\w+)\(\)$")
_THROWN = re.compile(r"\((?P<cls>[A-Za-z_\\][\w\\]*)\)$")
#: The database layers a PrestaShop hook reaches: the legacy `Db` class,
#: PDO underneath it, and Doctrine DBAL on the Symfony side.
_DATABASE_EXCEPTIONS = ("PrestaShopDatabaseException", "PDOException")
_DATABASE_NAMESPACES = ("Doctrine\\DBAL\\",)


def retained_hook_database_fault(harness, stdout: str) -> Optional[str]:
    """The first database exception a RETAINED BeforeSuite hook threw, or None.

    A hook is retained when its class's PSR-4 path is retained under the
    boundary (CommonFeatureContext, the recorder); a submission's own hook
    throwing stays the submission's outcome.
    """
    from ..core.boundary import RETAINED
    from .repo import _class_path_guess
    lines = [line.strip() for line in (stdout or "").splitlines()]
    for at, line in enumerate(lines):
        hook = _BEFORE_SUITE.match(line)
        if hook is None:
            continue
        path = _class_path_guess(hook["callee"], harness.behat.psr4)
        if path is None or harness.boundary.classify(path) != RETAINED:
            continue
        thrown = []
        for follow in lines[at + 1:]:
            if follow.startswith("╳"):
                thrown.append(follow[1:].strip())
            elif not follow.startswith("│"):
                break
        exception = _THROWN.search(thrown[-1]) if thrown else None
        if exception is None:
            continue
        cls = exception["cls"].lstrip("\\")
        if cls in _DATABASE_EXCEPTIONS or cls.startswith(_DATABASE_NAMESPACES):
            message = re.sub(r"\s+", " ", " ".join(thrown))[:400]
            return (f"database exception in the retained BeforeSuite hook "
                    f"{hook['callee']}::{hook['method']}(): {message}")
    return None


def selftest() -> int:
    import json  # bound here too: the seed materializer below re-imports it
    import subprocess
    import tempfile
    from pathlib import Path
    from unittest import mock
    from ..core.boundary import Boundary
    from .harness import Harness
    from .repo import StripManifest, SubstrateTampered, baseline_substrate, load_manifest

    failures = []

    def check(label, condition):
        if not condition:
            failures.append(label)
            print("FAIL:", label)

    def refuses(call, kind=ResourceResetError):
        try:
            call()
        except kind:
            return True
        return False

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp, "worker")
        gold = Path(temp, "gold")
        root.mkdir()
        gold.mkdir()

        def write(rel, content):
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)

        original = {
            "src/Protected.php": "<?php // production",
            "config/themes/seeded/shop.json": '{"name":"empty-id seed"}',
            "config/themes/hummingbird/shop1.json": '{"name":"seed"}',
            "config/themes/hummingbird/theme.json": '{"template":"immutable"}',
            "tests/Resources/img/c/fr.jpg": "French fixture",
            "tests/Resources/download/example.txt": "download",
            "tests/Resources/modules/example/example.php": "<?php // native fixture",
            "mails/en/account.html": "original mail",
            "mails/themes/classic/theme.yml": "immutable template",
            "translations/fr-FR/catalog.xlf": "installed catalogue",
            "translations/fr-FR.zip": "immutable archive",
            "translations/default/messages.xlf": "immutable default",
            "tests/Resources/dummyFile/dummy_zip.zip": "upload fixture",
            "tests/Resources/dummyFile/app_icon.png": "icon fixture",
        }
        for rel, content in original.items():
            write(rel, content)
        os.chmod(root / "tests/Resources/download/example.txt", 0o444)
        os.chmod(root / "config/themes/seeded/shop.json", 0o444)
        write("config/themes/linked/theme.json", "immutable")
        os.symlink("../seeded/shop.json", root / "config/themes/linked/shop.json")
        os.symlink("example.txt", root / "tests/Resources/download/link")
        # The native restore inputs: a full dump and three tables, two of
        # whose names share a prefix (ps_lang, ps_lang_shop).
        seeded = ["ps_configuration", "ps_lang", "ps_lang_shop"]
        write(f"{DUMPS}/ps_dump_test_seed_9.3.0.sql", "-- full dump")
        for table in seeded:
            write(f"{DUMPS}/ps_dump_test_seed_9.3.0_{table}.sql", "-- table dump")
            write(f"{DUMPS}/ps_dump_test_seed_9.3.0_{table}.md5", "123456")
        (root / DUMPS / "ps_backup_test_img").mkdir()
        context = "tests/Integration/Behaviour/Features/Context/"
        boundary = Boundary(version=1, project="prestashop", repo_root=str(root),
                            removable=[(context, "")],
                            retained=[(context + "CommonFeatureContext.php", ""),
                                      ("tests/Integration/Behaviour/Bench/", "")],
                            raw={"behat": {"psr4": {"Tests\\": "tests/"}}})
        man = StripManifest(repo_root=str(root), gold_root=str(gold),
                            substrate_roots=["src", "config", "tests", "mails", "translations", "robots.txt"])
        capture(man)
        baseline_substrate(man, boundary, str(gold / "strip_manifest.json"))
        check("baseline metadata round trip", load_manifest(str(gold / "strip_manifest.json")).prestashop_resources == man.prestashop_resources)

        class Runner:
            """Behat and the worker's database, faked; `tables` is the live schema."""
            workdir = "/fixture"
            action = None
            seen = 0

            def __init__(self):
                self.tables = set(seeded) | {"ps_not_seeded"}
                self.restore_leaves = set()   # tables a broken restore does not bring back
                self.schema_error = None
                self.schema_calls = []        # (argv, behat runs so far, kwargs)

            def in_container(self, rel):
                return self.workdir + "/" + rel

            def run(self, command, **kwargs):
                if command.startswith("php -- "):
                    argv = shlex.split(command)[2:]
                    self.schema_calls.append((argv, self.seen, kwargs))
                    doc = {"action": argv[0], "schema": "test_fixture"}
                    if self.schema_error:
                        doc["error"] = self.schema_error
                    else:
                        if argv[0] == "restore":
                            self.tables |= set(seeded) - self.restore_leaves
                            doc.update(restore_exit=0, restore_stderr="")
                        doc["tables"] = sorted(self.tables)
                    return subprocess.CompletedProcess(command, 0, json.dumps(doc) + "\n", "")
                if "vendor/bin/behat" in command:
                    self.seen += 1
                    stdout = self.action()
                    if isinstance(stdout, str):
                        return subprocess.CompletedProcess(command, 1, stdout, "")
                return subprocess.CompletedProcess(command, 0, "", "")

        runner = Runner()
        harness = Harness(man, boundary, runner)

        def mutate_resources():
            check("each execution starts with exact resources", inventory(str(root)) == man.prestashop_resources["entries"])
            write("config/themes/hummingbird/shop2.json", "new shop")
            write("config/themes/hummingbird/shop.json", "empty shop ID")
            (root / "config/themes/seeded/shop.json").unlink()
            write("config/themes/seeded/shop.json", "modified seed")
            (root / "config/themes/linked/shop.json").unlink()
            write("config/themes/linked/shop.json", "replaced link")
            (root / "tests/Resources/img/c/fr.jpg").unlink()
            write("mails/en/account.html", "edited mail")
            write("translations/fr-FR/catalog.xlf", "edited catalogue")
            write("robots.txt", "regenerated robots")
            write("tests/Resources/modules/new/module.php", "<?php // installed test module")

        runner.action = mutate_resources
        results = [harness.execute() for _ in range(2)]
        check("consecutive executions reset all resources", runner.seen == 2 and inventory(str(root)) == man.prestashop_resources["entries"])
        check("baseline absence restored", not (root / "robots.txt").exists() and not (root / "config/themes/hummingbird/shop2.json").exists())
        check("empty shop absence restored", not (root / "config/themes/hummingbird/shop.json").exists())
        check("empty shop seed bytes and mode restored",
              (root / "config/themes/seeded/shop.json").read_text() == original["config/themes/seeded/shop.json"]
              and stat.S_IMODE((root / "config/themes/seeded/shop.json").stat().st_mode) == 0o444)
        check("empty shop seed link restored", os.readlink(root / "config/themes/linked/shop.json") == "../seeded/shop.json")
        check("resource mode and link restored", stat.S_IMODE((root / "tests/Resources/download/example.txt").stat().st_mode) == 0o444 and os.readlink(root / "tests/Resources/download/link") == "example.txt")
        check("reset overhead separately recorded", all(r.resource_reset_seconds is not None and "resource_reset_seconds" in r.to_json() for r in results))
        from .validate import _thin
        check("T4 summaries retain separate reset overhead", all(_thin(r.to_json())["resource_reset_seconds"] == r.to_json()["resource_reset_seconds"] for r in results))
        without_reset = results[0].to_json()
        del without_reset["resource_reset_seconds"]
        check("other project summaries stay unchanged", "resource_reset_seconds" not in _thin(without_reset))
        from .runner import _record
        row = _record("fixture", {}, {}, 0, {"runs": [r.to_json() for r in results]})
        check("result rows aggregate reset overhead separately", row["resource_reset_seconds"] == round(sum(r.to_json()["resource_reset_seconds"] for r in results), 3) and row["execution_seconds"] == round(sum(r.to_json()["wall_seconds"] for r in results), 2))
        check("other project result rows stay unchanged", "resource_reset_seconds" not in _record("fixture", {}, {}, 0, {"runs": [without_reset]}))

        fixture = "tests/Resources/dummyFile/"

        def consume_fixtures():
            mutate_resources()
            (root / (fixture + "dummy_zip.zip")).unlink()
            write(fixture + "app_icon.png", "moved and rewritten")
            write(fixture + "copy.zip", "left behind")

        runner.action = consume_fixtures
        consumed = harness.execute()
        check("consumed upload fixtures are restored and reported, not raised",
              consumed.outcome == "fixture_consumed"
              and consumed.fixture_consumed == [fixture + "app_icon.png", fixture + "copy.zip",
                                                fixture + "dummy_zip.zip"]
              and consumed.to_json()["fixture_consumed"] == consumed.fixture_consumed
              and all((root / (fixture + n)).read_text() == original[fixture + n]
                      for n in ("dummy_zip.zip", "app_icon.png"))
              and not (root / (fixture + "copy.zip")).exists()
              and inventory(str(root)) == man.prestashop_resources["entries"])
        from ..data.mutation import classify_outcome
        check("a consumed-fixture run is infrastructure, never a kill or a survivor",
              classify_outcome("passed", consumed.outcome) == "infrastructure")
        runner.action = mutate_resources
        clean = harness.execute()
        check("the next execution starts from the restored fixtures and reports none",
              clean.fixture_consumed is None and "fixture_consumed" not in clean.to_json())
        runner.action = lambda: (consume_fixtures(), write("src/Protected.php", "tampered"))
        check("consumed fixtures beside any other change still stop the campaign",
              refuses(harness.execute, SubstrateTampered))
        check("...keeping the evidence: nothing was restored",
              not (root / (fixture + "dummy_zip.zip")).exists())
        write("src/Protected.php", original["src/Protected.php"])
        for n in ("dummy_zip.zip", "app_icon.png"):
            write(fixture + n, original[fixture + n])
        (root / (fixture + "copy.zip")).unlink()
        restore(man)

        for rel in ("src/Protected.php", "mails/themes/classic/theme.yml", "translations/fr-FR.zip", "translations/default/messages.xlf", "config/themes/hummingbird/theme.json"):
            runner.action = lambda rel=rel: (mutate_resources(), write(rel, "tampered"))
            check("immutable edit refused: " + rel, refuses(harness.execute, SubstrateTampered))
            check("immutable failure preserves evidence before reset", (root / "config/themes/hummingbird/shop2.json").exists())
            write(rel, original[rel])
            restore(man)

        for rel in ("config/themes/hummingbird/shopx.json",
                    "config/themes/hummingbird/shop-1.json",
                    "config/themes/hummingbird/shop.json.bak",
                    "config/themes/hummingbird/nested/shop.json"):
            runner.action = lambda rel=rel: (mutate_resources(), write(rel, "unexpected"))
            check("immutable sibling addition refused: " + rel, refuses(harness.execute, SubstrateTampered))
            check("empty shop evidence retained on source violation", (root / "config/themes/hummingbird/shop.json").exists())
            (root / rel).unlink()
            if "/nested/" in rel:
                (root / "config/themes/hummingbird/nested").rmdir()
            restore(man)

        snapshot = gold / NAME / "mails/en/account.html"
        snapshot.write_text("bad input")
        check("gold input tampering refused", refuses(harness.execute))
        snapshot.write_text(original["mails/en/account.html"])
        write("mails/en/account.html", "stale worker")
        check("dirty entry refused rather than silently repaired", refuses(harness.execute))
        restore(man)

        external = Path(temp, "external")
        external.mkdir()
        (external / "untouched").write_text("outside")
        runner.action = lambda: (shutil.rmtree(root / "mails/en"), os.symlink(external, root / "mails/en"))
        harness.execute()
        check("changed resource link never followed", (external / "untouched").read_text() == "outside" and not (root / "mails/en").is_symlink())
        saved_themes = root / "config/themes"
        saved_themes.rename(root / "config/saved-themes")
        os.symlink(external, saved_themes)
        check("changed parent link refuses restoration", refuses(lambda: restore(man)))
        saved_themes.unlink()
        (root / "config/saved-themes").rename(saved_themes)

        def timeout_action():
            mutate_resources()
            raise subprocess.TimeoutExpired("behat", 600)

        runner.action = timeout_action
        with mock.patch.object(harness, "_kill_behat", return_value="killed") as kill:
            result = harness.execute()
            check("timeout stops process before exact restoration", kill.call_count == 1 and result.timed_out and inventory(str(root)) == man.prestashop_resources["entries"])
        with mock.patch.object(harness, "_kill_behat", return_value="survived"):
            check("surviving timed-out process prevents reset", refuses(harness.execute))
            check("survivor resource evidence retained", (root / "config/themes/hummingbird/shop2.json").exists())
        restore(man)
        with mock.patch.object(harness, "_kill_behat",
                               return_value="cleanup_failed:TimeoutExpired"):
            try:
                harness.execute()
            except ResourceResetError as error:
                check("the stop failure retains the cleanup reason for diagnosis",
                      "cleanup_failed:TimeoutExpired" in str(error))
            else:
                check("unconfirmed cleanup refuses resource reset", False)
        restore(man)
        runner.action = mutate_resources
        with mock.patch(__name__ + ".restore", side_effect=OSError("reset failed")):
            check("reset failure cannot return a run", refuses(harness.execute, OSError))
        restore(man)
        runner.action = lambda: (_ for _ in ()).throw(ValueError("execution failure"))
        with mock.patch.object(harness, "_kill_behat", return_value="killed"):
            check("exceptional execution keeps original exception after safe reset", refuses(harness.execute, ValueError))

        # Seeded schema health (BENCHMARK_V2_SPEC section 8.1, harness 26),
        # against a synthetic missing table in the faked database.
        import contextlib
        import io
        from .results import infrastructure_marker
        from .runner import _harness_error_row
        restore(man)
        full_dump = runner.in_container(f"{DUMPS}/ps_dump_test_seed_9.3.0.sql")
        check("the seeded tables are the dump's *.md5 inputs, and the full dump is the one every checksum names",
              seeded_dump(str(root)) == (f"{DUMPS}/ps_dump_test_seed_9.3.0.sql", seeded))

        def observed(action):
            """One execution: (result or exception, schema calls, stderr)."""
            runner.action, runner.schema_calls = action, []
            log = io.StringIO()
            with contextlib.redirect_stderr(log), \
                    mock.patch.object(harness, "_kill_behat", return_value="killed"):
                try:
                    outcome = harness.execute()
                except Exception as error:      # noqa: BLE001 -- the test reads it
                    outcome = error
            calls = [(argv, at) for argv, at, _kwargs in runner.schema_calls]
            check("every schema call sends the program on stdin with xdebug off",
                  all(kwargs.get("input") == _SCHEMA_PHP and kwargs.get("env") == {"XDEBUG_MODE": "off"}
                      for _argv, _at, kwargs in runner.schema_calls))
            return outcome, calls, log.getvalue()

        before = runner.seen
        result, calls, log = observed(lambda: None)
        check("a healthy schema: one check, before Behat, and no restore",
              result.outcome == "no_scenario_ran" and calls == [(["check"], before)] and not log)

        runner.tables.discard("ps_lang")
        before = runner.seen
        result, calls, log = observed(lambda: None)
        check("a missing seeded table restores the full dump before Behat runs",
              calls == [(["check"], before), (["restore", full_dump], before)]
              and runner.seen == before + 1 and "ps_lang" in runner.tables
              and result.outcome == "no_scenario_ran"
              and "lacks 1 of 3 seeded tables before this execution (ps_lang)" in log
              and "all 3 seeded tables are present" in log)

        runner.tables.discard("ps_lang")
        runner.restore_leaves = {"ps_lang"}
        before = runner.seen
        fault, calls, _log = observed(lambda: None)
        row = _harness_error_row("item", fault) if isinstance(fault, Exception) else {"metadata": {}}
        check("a table the full dump does not bring back stops the worker before Behat runs",
              isinstance(fault, SeededSchemaFault) and fault.stops_worker and runner.seen == before
              and "still missing: ps_lang" in str(fault) and "this worker must stop" in str(fault)
              and calls == [(["check"], before), (["restore", full_dump], before)])
        check("...as an infrastructure row that asks the launcher to stop the worker",
              infrastructure_marker(row) == "harness_error"
              and row["metadata"].get("worker_stop") == row["metadata"]["harness_error"]
              and row["metadata"]["harness_error"].startswith("SeededSchemaFault: "))
        runner.restore_leaves = set()
        runner.tables.add("ps_lang")

        runner.schema_error = "PDOException 2002"
        fault, _calls, _log = observed(lambda: None)
        check("a schema that cannot be read stops the worker too",
              isinstance(fault, SeededSchemaFault) and "PDOException 2002" in str(fault) and runner.seen == before)
        runner.schema_error = None

        def killed_inside_a_table_restore():
            runner.tables.discard("ps_lang")
            raise subprocess.TimeoutExpired("behat", 600)

        before = runner.seen
        result, calls, log = observed(killed_inside_a_table_restore)
        check("a killed execution's dropped table is restored right after the kill",
              result.timed_out and result.outcome == "timeout" and "ps_lang" in runner.tables
              and calls == [(["check"], before), (["check"], before + 1), (["restore", full_dump], before + 1)]
              and "after a killed or timed-out execution (ps_lang)" in log)

        before = runner.seen
        result, calls, _log = observed(lambda: runner.tables.discard("ps_lang_shop"))
        check("an execution that ends normally is not checked after, only before",
              calls == [(["check"], before)] and "ps_lang_shop" not in runner.tables)
        result, calls, _log = observed(lambda: None)
        check("...so the next execution's entry check restores what it dropped",
              calls == [(["check"], before + 1), (["restore", full_dump], before + 1)]
              and "ps_lang_shop" in runner.tables)

        # The failed hook exactly as Behat printed it on worker 2 (2026-10-16).
        hook = ("┌─ @BeforeSuite # Tests\\Integration\\Behaviour\\Features\\Context\\{}::prepare()\n"
                "│\n"
                "╳  Table 'test_prestashop_rr_2.ps_lang' doesn't exist<br /><br /><pre>SELECT l.*, ls.`id_shop`\n"
                "╳  \t\t\t\tFROM `ps_lang` l\n"
                "╳  \t\t\t\tLEFT JOIN `ps_lang_shop` ls ON (l.id_lang = ls.id_lang)</pre> ({})\n"
                "│\n\n"
                "@restore-all-tables-before-feature @full-ux-discount-test-free-gift\n"
                "Feature: Full UX discount test\n\n"
                "--- Failed hooks:\n\n"
                "    BeforeSuite \"bench\" # Tests\\Integration\\Behaviour\\Features\\Context\\{}::prepare()\n\n"
                "1 scenario (1 skipped)\n33 steps (33 skipped)\n")

        def failing_hook(owner="CommonFeatureContext", thrown="PrestaShopDatabaseException", drop=None):
            def action():
                if drop:
                    runner.tables.discard(drop)
                mutate_resources()
                return hook.format(owner, thrown, owner)
            return action

        before = runner.seen
        fault, calls, _log = observed(failing_hook(drop="ps_lang"))
        row = _harness_error_row("item", fault) if isinstance(fault, Exception) else {"metadata": {}}
        check("a database exception in a retained BeforeSuite hook is a worker fault, not no_scenario_ran",
              isinstance(fault, RetainedHookDatabaseFault)
              and "CommonFeatureContext::prepare()" in str(fault)
              and "Table 'test_prestashop_rr_2.ps_lang' doesn't exist" in str(fault)
              and "(PrestaShopDatabaseException)" in str(fault)
              and infrastructure_marker(row) == "harness_error" and "worker_stop" not in row["metadata"])
        check("...after the resource reset and a schema repair for the next execution",
              inventory(str(root)) == man.prestashop_resources["entries"] and "ps_lang" in runner.tables
              and calls == [(["check"], before), (["check"], before + 1), (["restore", full_dump], before + 1)])
        result, _calls, _log = observed(failing_hook(owner="Domain\\CandidateFeatureContext"))
        check("the submission's own BeforeSuite hook throwing stays the submission's outcome",
              not isinstance(result, Exception) and result.outcome == "no_scenario_ran")
        result, _calls, _log = observed(failing_hook(thrown="RuntimeException"))
        check("a retained hook's non-database exception stays an ordinary outcome",
              not isinstance(result, Exception) and result.outcome == "no_scenario_ran")
        check("Doctrine DBAL exceptions are database exceptions too",
              retained_hook_database_fault(harness, hook.format(
                  "CommonFeatureContext", "Doctrine\\DBAL\\Exception\\ConnectionException",
                  "CommonFeatureContext")) is not None)

        # Under an applied mutant the hook's exception can be the mutant's own
        # (prepare() boots the shop through production code): a mutation pair
        # keeps harness 25's no_scenario_ran, which mutation_run retries once
        # and then excludes as infrastructure. The entry check still runs.
        import hashlib
        mutated = b"<?php // a mutant on the hook's path"
        (root / "src/Protected.php").write_bytes(mutated)
        harness.expected_mutations = {"src/Protected.php": hashlib.sha256(mutated).hexdigest()}
        before = runner.seen
        result, calls, _log = observed(failing_hook())
        check("under an applied mutant a retained hook's database exception stays no_scenario_ran",
              not isinstance(result, Exception) and result.outcome == "no_scenario_ran"
              and calls == [(["check"], before)])
        write("src/Protected.php", original["src/Protected.php"])
        harness.expected_mutations = {}

        with tempfile.TemporaryDirectory() as other:
            check("no restore inputs: the seeded list is unknown and the worker stops",
                  refuses(lambda: seeded_dump(other), SeededSchemaFault))
            Path(other, DUMPS).mkdir(parents=True)
            Path(other, DUMPS, "ps_dump_a_1.0_ps_lang.md5").write_text("1")
            check("checksums without the full dump that names them all: the worker stops",
                  refuses(lambda: seeded_dump(other), SeededSchemaFault))
        man.prestashop_resources = None
        check("legacy seed without baseline refuses", refuses(harness.execute))
    # Exercise the actual seed materializer: native 666/777 modes and empty
    # fixture directories must survive as exactly the recorded worker state.
    with tempfile.TemporaryDirectory() as temp:
        from .seed import build_seed, unpack_workspace, PRESTASHOP_RULES, SeedRefused, SEED_MANIFEST
        import json
        root = Path(temp, "source")
        gold = Path(temp, "gold")
        root.mkdir()
        gold.mkdir()
        image = root / "tests/Resources/img/c/fr.jpg"
        image.parent.mkdir(parents=True)
        image.write_text("French placeholder")
        os.chmod(image, 0o666)
        os.chmod(image.parent, 0o777)
        empty = root / "tests/Resources/download/empty"
        empty.mkdir(parents=True)
        os.chmod(empty, 0o750)
        boundary = Boundary(version=1, project="prestashop", repo_root=str(root))
        man = StripManifest(repo_root=str(root), gold_root=str(gold), substrate_roots=["tests", "config", "mails", "translations", "robots.txt"])
        capture(man)
        baseline_substrate(man, boundary, str(gold / "strip_manifest.json"))

        class Database:
            def dump(self, schema, path, **kwargs):
                Path(path).write_text("fixture database")
                return {"path": path, "bytes": 16}

        seed = str(Path(temp, "seed"))
        build_seed(str(root), boundary, seed, "test_fixture", Database(), manifest=man, rules=PRESTASHOP_RULES)
        destination = str(Path(temp, "worker"))
        unpack_workspace(seed, destination)
        man.repo_root = destination
        verify_entry(man)
        check("seed round trip preserves normalized resource modes and empty dirs", inventory(destination) == man.prestashop_resources["entries"] and stat.S_IMODE((Path(destination) / "tests/Resources/img/c/fr.jpg").stat().st_mode) == 0o644 and stat.S_IMODE((Path(destination) / "tests/Resources/download/empty").stat().st_mode) == 0o750)
        man.repo_root = str(root)
        seed_manifest = Path(seed, SEED_MANIFEST)
        doc = json.loads(seed_manifest.read_text())
        changed_source = Path(temp, "changed-source")
        changed_gold = Path(temp, "changed-gold")
        shutil.copytree(root, changed_source)
        changed_gold.mkdir()
        os.chmod(changed_source / "tests/Resources/download/empty", 0o700)
        changed_boundary = Boundary(version=1, project="prestashop", repo_root=str(changed_source))
        changed_man = StripManifest(repo_root=str(changed_source), gold_root=str(changed_gold), substrate_roots=man.substrate_roots)
        capture(changed_man)
        baseline_substrate(changed_man, changed_boundary, str(changed_gold / "strip_manifest.json"))
        check("same-byte seed with different directory metadata refuses reuse", refuses(lambda: build_seed(str(changed_source), changed_boundary, seed, "test_fixture", Database(), manifest=changed_man, rules=PRESTASHOP_RULES), SeedRefused))
        del doc["prestashop_resources_digest"]
        seed_manifest.write_text(json.dumps(doc))
        check("old same-byte seed cannot bypass the new baseline", refuses(lambda: build_seed(str(root), boundary, seed, "test_fixture", Database(), manifest=man, rules=PRESTASHOP_RULES), SeedRefused))
    print(("FAIL " + str(len(failures)) if failures else "PASS") + " (prestashop_resources)")
    return bool(failures)


if __name__ == "__main__":
    from r2t.bench.prestashop_resources import selftest as imported_selftest
    raise SystemExit(imported_selftest())
