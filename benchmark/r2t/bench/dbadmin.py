"""MySQL administration for K-way execution, without publishing credentials.

SPEC_C3_PARALLEL §3.2 and H8.  Two facts about the benchmark's database made
"isolation" an assertion rather than a boundary, and both are fixed here:

* **`root@%` was the only non-system principal.**  Submitted PHP connects as
  it — the DSN is in the execution container's environment — so `SHOW
  DATABASES` returned all six schemas and a `SELECT` against a neighbouring
  worker's schema would have succeeded.  Schema separation is not an
  isolation boundary while one principal holds every schema.
* **Secrets travelled in `argv`.**  `docker exec -e KEY=value` puts the value
  into the host's process arguments, where any user on the machine can read it
  out of `/proc` for as long as the exec runs.  So can `mysql -proot`.

Everything here therefore passes credentials on **stdin only**: the password
is written into a mode-0600 defaults file inside the database container and
referenced by path, and every statement that contains a password (`CREATE
USER … IDENTIFIED BY …`) is piped rather than argued.  The only thing that
ever appears in a command line is a *name*.

Run stamps record the principal's NAME (`bench_3`), never the DSN.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import subprocess
from dataclasses import dataclass
from typing import Optional

#: Schemas MySQL ships and that every principal can see.  `SHOW DATABASES`
#: returning exactly one schema is NOT the isolation check (review P1-4) —
#: these are normally visible and their visibility proves nothing either way.
SYSTEM_SCHEMAS = frozenset({"information_schema", "performance_schema",
                            "mysql", "sys"})
DEFAULT_ROOT_PASSWORD = "root"

#: A worker principal's name.  Constrained because it is interpolated into
#: SQL: MySQL has no placeholder syntax for an account name, so the only
#: defence is refusing anything that is not a plain identifier.
_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,30}$")


class DatabaseRefused(RuntimeError):
    """An administrative action that would remove an isolation boundary."""


def _ident(name: str, what: str) -> str:
    if not _IDENT.match(name or ""):
        raise DatabaseRefused(
            f"REFUSED: {what} {name!r} is not a plain identifier. It would be "
            f"interpolated into SQL, and MySQL has no placeholder for an "
            f"account or schema name.")
    return name


def new_password(nbytes: int = 24) -> str:
    """A worker password, generated rather than configured.

    `secrets`, not `random`: this value is the only thing standing between one
    worker's submitted PHP and another worker's schema, and a reproducible
    password would be worth exactly nothing.  It is never written to a run
    stamp, a log line or a command line — only into a mode-0600 env file the
    coordinator owns and the container reads at `docker run`.
    """
    return secrets.token_urlsafe(nbytes)


@dataclass
class MySQL:
    """Administrative access to the benchmark's MySQL, over `docker exec`.

    The coordinator reaches the server by executing *inside* the database
    container, so it connects over the container's own loopback and is
    matched by `root@localhost`.  That is what makes removing `root@%`
    workable: the admin route survives it and the worker route — TCP from a
    neighbouring container — does not.
    """

    container: str = "coreshop_db"
    user: str = "root"
    password: str = DEFAULT_ROOT_PASSWORD
    docker_group: bool = True
    _cnf: Optional[str] = None

    # ------------------------------------------------------------- plumbing
    def _docker(self, argv: list[str], stdin: Optional[str] = None,
                stdout_path: Optional[str] = None,
                timeout: int = 1800) -> subprocess.CompletedProcess:
        from ..core.docker_cli import docker_command
        cmd = docker_command(argv, docker_group=self.docker_group)
        if stdout_path:
            with open(stdout_path, "wb") as out:
                return subprocess.run(cmd, input=(stdin or "").encode(),
                                      stdout=out, stderr=subprocess.PIPE,
                                      timeout=timeout)
        return subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                              timeout=timeout)

    def _defaults_file(self) -> str:
        """Write the credential into the container, on stdin, mode 0600.

        `umask 077` before the redirect rather than a `chmod` after it: the
        file exists between the two, and inside a container shared with
        submitted code that window is the whole problem.
        """
        if self._cnf:
            return self._cnf
        # Provisioning threads have the same PID but independent context
        # lifetimes. One context must never remove another's credential.
        path = f"/tmp/.r2t-admin-{os.getpid()}-{secrets.token_hex(8)}.cnf"
        body = (f"[client]\nuser={self.user}\npassword={self.password}\n"
                f"[mysqldump]\nuser={self.user}\npassword={self.password}\n")
        cp = self._docker(["exec", "-i", self.container, "sh", "-c",
                           f"umask 077 && cat > {shlex.quote(path)}"],
                          stdin=body, timeout=60)
        if cp.returncode != 0:
            raise DatabaseRefused(
                f"could not install the admin credential in {self.container}: "
                f"{(cp.stderr or '')[-400:]}")
        self._cnf = path
        return path

    def close(self) -> None:
        if self._cnf:
            self._docker(["exec", self.container, "rm", "-f", self._cnf],
                         timeout=60)
            self._cnf = None

    def __enter__(self) -> "MySQL":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -------------------------------------------------------------- queries
    def sql(self, statements: str, database: Optional[str] = None,
            timeout: int = 600) -> subprocess.CompletedProcess:
        """Run SQL supplied on STDIN.

        Never `-e "…"`: a `CREATE USER … IDENTIFIED BY 'pw'` passed that way
        publishes the worker password to every process listing on the host for
        as long as the statement runs.
        """
        cnf = self._defaults_file()
        argv = ["exec", "-i", self.container, "mysql",
                f"--defaults-extra-file={cnf}", "--batch", "--raw",
                "--skip-column-names"]
        if database:
            argv.append(_ident(database, "schema"))
        return self._docker(argv, stdin=statements, timeout=timeout)

    def query(self, statement: str, database: Optional[str] = None) -> list[list[str]]:
        cp = self.sql(statement, database=database)
        if cp.returncode != 0:
            raise DatabaseRefused(f"query failed: {(cp.stderr or '')[-400:]}")
        return [ln.split("\t") for ln in (cp.stdout or "").splitlines() if ln]

    def schemas(self) -> list[str]:
        return sorted(r[0] for r in self.query("SHOW DATABASES;"))

    def principals(self) -> list[tuple[str, str]]:
        return sorted((r[0], r[1]) for r in
                      self.query("SELECT user, host FROM mysql.user;"))

    def table_bytes(self, database: str) -> dict[str, int]:
        rows = self.query(
            "SELECT table_name, COALESCE(data_length+index_length,0) "
            "FROM information_schema.tables WHERE table_schema="
            f"'{_ident(database, 'schema')}';")
        return {r[0]: int(r[1]) for r in rows}

    def buffer_pool_bytes(self) -> int:
        rows = self.query("SELECT @@innodb_buffer_pool_size;")
        return int(rows[0][0]) if rows else 0

    def resident_pages(self, database: str) -> dict:
        """What the pruned schema actually keeps resident (§3.4).

        v2 sized an 8 GB buffer pool against the ~400 MB *live* schema while
        claiming an 8.7 MB pruned seed.  The K limit and the pool size are
        deferred until this is measured, so the measurement has to exist
        before the decision does.
        """
        rows = self.query(
            "SELECT COUNT(*), COALESCE(SUM(compressed_size),0) "
            "FROM information_schema.innodb_buffer_page "
            f"WHERE table_name LIKE '`{_ident(database, 'schema')}`%';")
        pages = int(rows[0][0]) if rows else 0
        return {"schema": database, "pages": pages,
                "page_bytes": pages * 16384,
                "buffer_pool_bytes": self.buffer_pool_bytes()}

    # ------------------------------------------------------------- schemas
    def create_schema(self, name: str) -> None:
        self.sql(f"CREATE DATABASE IF NOT EXISTS `{_ident(name, 'schema')}` "
                 f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")

    def drop_schema(self, name: str) -> None:
        name = _ident(name, "schema")
        if name in SYSTEM_SCHEMAS:
            raise DatabaseRefused(f"REFUSED: {name} is a system schema")
        self.sql(f"DROP DATABASE IF EXISTS `{name}`;")

    #: `DEFINER=\`x\`@\`y\`` on a view, trigger, routine or event.
    _DEFINER = re.compile(r"DEFINER=`[^`]*`@`[^`]*`\s*")

    def dump(self, database: str, out_path: str,
             empty_tables: tuple = (), timeout: int = 3600,
             invoker_security: bool = True) -> dict:
        """A schema dump with named tables kept but emptied (§3.3).

        The obvious construction — `TRUNCATE` then dump — destroys the live
        schema to produce a copy of it.  Dumping the same schema twice, once
        skipping those tables and once with `--no-data`, produces exactly the
        pruned pair without touching the source at all.  That matters because
        the source is the tree every existing result was measured against.

        **`invoker_security` is an isolation property, not tidiness.**  Pimcore
        materialises one `object_<class>` VIEW per DataObject class, and
        `mysqldump` writes them out as
        ``DEFINER=`root`@`%` SQL SECURITY DEFINER`` — 37 of them in this
        schema.  Two consequences, both measured here:

        * Removing `root@%` (§3.2) then breaks every one of them.  A worker's
          first `SELECT` through `object_cs_order` fails, every scenario dies
          in `@BeforeScenario`, and all 100 items score `no_scenario_ran` —
          which reads exactly like the system under test failing.  Restoring
          `root@%` with a DELIBERATELY WRONG password fixed it, which is what
          identified the definer rather than the credential.
        * Worse, a `SQL SECURITY DEFINER` view owned by a superuser is a hole
          that per-schema grants cannot close: whoever can name the view reads
          through it with the definer's privileges. Rewriting to
          `SQL SECURITY INVOKER` makes every view obey the worker's own
          grants, which is the boundary §3.2 asks for.
        """
        database = _ident(database, "schema")
        empty = [_ident(t, "table") for t in empty_tables]
        cnf = self._defaults_file()
        common = [f"--defaults-extra-file={cnf}", "--single-transaction",
                  "--no-tablespaces", "--skip-lock-tables", "--hex-blob",
                  "--set-gtid-purged=OFF", "--routines", "--events",
                  "--triggers", "--default-character-set=utf8mb4"]
        tmp = out_path + ".part"
        with open(tmp, "wb"):
            pass
        parts = [
            common + [f"--ignore-table={database}.{t}" for t in empty]
            + [database],
            (common + ["--no-data", "--skip-triggers", database] + empty)
            if empty else None,
        ]
        for argv in parts:
            if argv is None:
                continue
            piece = tmp + ".piece"
            cp = self._docker(["exec", self.container, "mysqldump", *argv],
                              stdout_path=piece, timeout=timeout)
            if cp.returncode != 0:
                os.remove(piece)
                raise DatabaseRefused(
                    f"mysqldump failed: {(cp.stderr or b'')[-400:]!r}")
            with open(tmp, "ab") as dst, open(piece, "rb") as src:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    dst.write(chunk)
            os.remove(piece)
        rewritten = 0
        if invoker_security:
            rewritten = self._rewrite_definers(tmp)
        os.replace(tmp, out_path)
        return {"path": out_path, "bytes": os.path.getsize(out_path),
                "emptied": empty, "definers_removed": rewritten,
                "security": "invoker" if invoker_security else "definer"}

    @classmethod
    def _rewrite_definers(cls, path: str) -> int:
        """Drop every `DEFINER=` clause and force invoker security.

        Refuses rather than half-rewrites: a dump that still names an account
        which the hardening step is about to remove produces a schema whose
        views work today and fail the moment `root@%` goes, and the failure
        is attributed to the system under test.
        """
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            text = fh.read()
        before = len(cls._DEFINER.findall(text))
        text = cls._DEFINER.sub("", text)
        text = text.replace("SQL SECURITY DEFINER", "SQL SECURITY INVOKER")
        left = cls._DEFINER.findall(text)
        if left or "SQL SECURITY DEFINER" in text:
            raise DatabaseRefused(
                f"REFUSED: {len(left)} DEFINER clause(s) survived the rewrite, "
                f"so the seed would carry objects owned by an account the "
                f"workers must not have: {left[:3]}")
        with open(path, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(text)
        return before

    #: Separates the generated statements.  A view definition containing this
    #: would corrupt the split, so `rewrite_views_to_invoker` checks for it
    #: rather than assuming.
    _VIEW_SEP = "@@@R2T_VIEW_END@@@"

    def rewrite_views_to_invoker(self, database: str,
                                 backup_path: Optional[str] = None) -> dict:
        """Make an EXISTING schema's views obey the querying user's grants.

        `seed.build_seed` fixes this for every schema provisioned from the
        seed, but a schema that predates the seed still holds
        ``DEFINER=`root`@`%` SQL SECURITY DEFINER`` views — 37 of them here —
        and those are the reason removing `root@%` broke every item.  They are
        also the hole itself: whoever can name such a view reads through it
        with the definer's privileges, which is precisely what a per-schema
        grant is supposed to prevent.

        Reversible: `backup_path` receives the original `SHOW CREATE VIEW`
        statements before anything is changed, so the previous state can be
        restored by loading that file.
        """
        # The body is transported BASE64-encoded, and this is not fastidiousness.
        # `mysql --batch --raw` writes values verbatim, so a view definition —
        # which is multi-line and full of tabs — arrives split across what the
        # tab/newline parser reads as several rows. The first attempt did
        # exactly that: 37 `CREATE OR REPLACE` statements were built from
        # fragments, every one of them was accepted by MySQL as a *different*
        # view, and the schema was left unchanged while the code reported
        # success. Base64 has neither character, and MySQL's own line wrapping
        # is stripped, so one view is one line.
        db = _ident(database, "schema")
        rows = self.query(
            "SELECT table_name, security_type, "
            "REPLACE(REPLACE(TO_BASE64(view_definition), '\\n', ''), '\\r', '') "
            "FROM information_schema.views "
            f"WHERE table_schema='{db}' ORDER BY table_name;")
        import base64
        entries = []
        for row in rows:
            if len(row) < 3:
                raise DatabaseRefused(
                    f"REFUSED: unparseable information_schema row for {db}: "
                    f"{row!r}")
            body = base64.b64decode(row[2]).decode("utf-8", "surrogateescape")
            if not body.strip():
                raise DatabaseRefused(
                    f"REFUSED: view {db}.{row[0]} came back with an empty "
                    f"definition; rewriting it would destroy the view.")
            entries.append((row[0].strip(), row[1].strip(), body))

        if backup_path:
            with open(backup_path, "w", encoding="utf-8") as fh:
                for name, sec, body in entries:
                    fh.write(f"-- {name} (was SQL SECURITY {sec})\n"
                             f"CREATE OR REPLACE SQL SECURITY {sec} VIEW "
                             f"`{db}`.`{name}` AS {body};\n")

        changed, skipped = [], []
        for name, sec, body in entries:
            if sec != "DEFINER":
                skipped.append(name)
                continue
            cp = self.sql(f"CREATE OR REPLACE SQL SECURITY INVOKER VIEW "
                          f"`{db}`.`{name}` AS {body};")
            if cp.returncode != 0:
                raise DatabaseRefused(
                    f"rewriting view {db}.{name} failed: "
                    f"{(cp.stderr or '')[-300:]}")
            changed.append(name)
        left = self.query(
            "SELECT COUNT(*) FROM information_schema.views WHERE "
            f"table_schema='{db}' AND security_type='DEFINER';")
        if left and int(left[0][0]):
            raise DatabaseRefused(
                f"REFUSED: {left[0][0]} view(s) in {db} are still SQL SECURITY "
                f"DEFINER after the rewrite.")
        return {"schema": db, "rewritten": len(changed),
                "already_invoker": len(skipped), "backup": backup_path,
                "views": changed}

    def definer_accounts(self, database: str) -> dict:
        """Which accounts own the schema's views, routines and triggers.

        Read before dropping an account, because dropping the definer of a
        `SQL SECURITY DEFINER` view breaks every query through it — and the
        error names the *querying* user, so the cause is invisible.
        """
        out: dict = {}
        db = _ident(database, "schema")
        for kind, sql in (
            ("view", "SELECT definer, table_name FROM information_schema.views "
                     f"WHERE table_schema='{db}'"),
            ("routine", "SELECT definer, routine_name FROM "
                        f"information_schema.routines WHERE routine_schema='{db}'"),
            ("trigger", "SELECT definer, trigger_name FROM "
                        f"information_schema.triggers WHERE trigger_schema='{db}'"),
        ):
            for row in self.query(sql + ";"):
                if len(row) >= 2:
                    out.setdefault(row[0], []).append(f"{kind}:{row[1]}")
        return out

    def load(self, database: str, sql_path: str, timeout: int = 3600) -> None:
        database = _ident(database, "schema")
        self.create_schema(database)
        cnf = self._defaults_file()
        from ..core.docker_cli import docker_command
        cmd = docker_command(
            ["exec", "-i", self.container, "mysql",
             f"--defaults-extra-file={cnf}", database],
            docker_group=self.docker_group)
        with open(sql_path, "rb") as src:
            cp = subprocess.run(cmd, stdin=src, capture_output=True,
                                timeout=timeout)
        if cp.returncode != 0:
            raise DatabaseRefused(
                f"loading {sql_path} into {database} failed: "
                f"{(cp.stderr or b'')[-400:]!r}")

    # ---------------------------------------------------------- principals
    def create_worker_principal(self, user: str, password: str,
                                schema: str) -> dict:
        """One principal, one schema, and nothing else.

        `GRANT ALL ON <schema>.*` and not `ON *.*`: the worker needs to create
        and drop Pimcore's per-scenario class tables inside its own schema and
        must be unable to name any other.  No `GRANT … WITH GRANT OPTION`, so
        a worker cannot widen itself.
        """
        user = _ident(user, "principal")
        schema = _ident(schema, "schema")
        pw = password.replace("\\", "\\\\").replace("'", "\\'")
        self.sql(
            f"DROP USER IF EXISTS '{user}'@'%';\n"
            f"CREATE USER '{user}'@'%' IDENTIFIED BY '{pw}';\n"
            f"GRANT ALL PRIVILEGES ON `{schema}`.* TO '{user}'@'%';\n"
            f"FLUSH PRIVILEGES;\n")
        granted = [r[0] for r in self.query(f"SHOW GRANTS FOR '{user}'@'%';")]
        wrong = [g for g in granted
                 if "ON *.*" in g and "USAGE" not in g]
        if wrong:
            raise DatabaseRefused(
                f"REFUSED: {user} ended up with a server-wide grant: {wrong}")
        return {"user": user, "schema": schema, "grants": granted}

    def drop_principal(self, user: str) -> None:
        self.sql(f"DROP USER IF EXISTS '{_ident(user, 'principal')}'@'%';")

    def remove_wildcard_root(self) -> dict:
        """Take `root@%` away, which is the actual boundary (§3.2).

        Refused unless `root@localhost` still exists: that is the account this
        class itself uses (it executes inside the database container, so it
        connects over loopback), and dropping the wildcard without it would
        lock the coordinator out of its own database.

        Reversible on purpose — `restore_wildcard_root` exists — because a
        change that cannot be undone is one nobody dares make.
        """
        before = self.principals()
        if (self.user, "localhost") not in before:
            raise DatabaseRefused(
                f"REFUSED: {self.user}@localhost does not exist, so dropping "
                f"root@% would lock the coordinator out of its own database.")
        self.sql("DROP USER IF EXISTS 'root'@'%'; FLUSH PRIVILEGES;")
        after = self.principals()
        return {"removed": [p for p in before if p not in after],
                "principals_now": after}

    def restore_wildcard_root(self, password: str = "root") -> dict:
        pw = password.replace("\\", "\\\\").replace("'", "\\'")
        self.sql(f"CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '{pw}';\n"
                 f"GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT "
                 f"OPTION;\nFLUSH PRIVILEGES;\n")
        return {"principals_now": self.principals()}


#: The slot `db_probe_php` renders the project's DSN variable name into.  A
#: NAME, not a value: the DSN itself never leaves the container's environment.
_DSN_ENV_SLOT = "R2T_PROBE_DSN_ENV"

#: The slots the project's victim-table names go into.  Neither is a prefix
#: of the other, so the two substitutions cannot eat each other.
_TABLE_SLOT = "R2T_PROBE_TABLE"
_SECOND_TABLE_SLOT = "R2T_PROBE_SECOND_TABLE"

#: The adversarial acceptance of §3.2, as PHP, because it has to run from
#: INSIDE the worker container using the credential that container was given.
#: Inspecting grants from the coordinator proves nothing about what the
#: container can reach: the grant table and the network path are different
#: questions, and only the second one is the boundary.  Rendered by
#: `db_probe_php`, never written out as it stands.
_DB_PROBE_PHP = r"""<?php
// GENERATED by r2t.bench.dbadmin -- the adversarial database probe of
// SPEC_C3_PARALLEL 3.2.  Run inside a WORKER container, with that worker's
// own DSN, against a schema it must not be able to touch.
$dsn = getenv('R2T_PROBE_DSN_ENV');
$victim = $argv[1] ?? '';
$out = ['dsn_present' => (bool)$dsn, 'victim' => $victim, 'checks' => []];
if (!$dsn) { echo json_encode($out); exit(2); }
$p = parse_url($dsn);
$user = $p['user'] ?? ''; $pass = $p['pass'] ?? '';
$host = $p['host'] ?? ''; $port = $p['port'] ?? 3306;
$mine = ltrim($p['path'] ?? '', '/');
$out['principal'] = $user;
$out['own_schema'] = $mine;

function attempt(array &$out, string $name, callable $fn): void {
    try { $fn(); $out['checks'][$name] = ['denied' => false, 'error' => null]; }
    catch (Throwable $e) { $out['checks'][$name] =
        ['denied' => true, 'error' => substr($e->getMessage(), 0, 200)]; }
}

// The control: the worker must be able to use its OWN schema, or the probe is
// measuring a broken container rather than a boundary.
attempt($out, 'own_schema_select', function () use ($user,$pass,$host,$port,$mine) {
    $c = new PDO("mysql:host=$host;port=$port;dbname=$mine", $user, $pass,
                 [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $c->query('SELECT 1')->fetchAll();
});
if ($victim !== '') {
    attempt($out, 'victim_connect', function () use ($user,$pass,$host,$port,$victim) {
        new PDO("mysql:host=$host;port=$port;dbname=$victim", $user, $pass,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    });
    foreach ([['victim_select', "SELECT 1 FROM `$victim`.`R2T_PROBE_SECOND_TABLE` LIMIT 1"],
              ['victim_select_any', "SELECT COUNT(*) FROM `$victim`.`R2T_PROBE_TABLE`"],
              ['victim_insert', "INSERT INTO `$victim`.`R2T_PROBE_TABLE` (id) VALUES (0)"],
              ['victim_drop',   "DROP TABLE `$victim`.`R2T_PROBE_TABLE`"]] as [$name,$sql]) {
        attempt($out, $name, function () use ($user,$pass,$host,$port,$mine,$sql) {
            $c = new PDO("mysql:host=$host;port=$port;dbname=$mine", $user, $pass,
                         [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $c->query($sql);
        });
    }
}
// The wildcard admin must be unreachable over TCP from here.
foreach (['root' => 'root'] as $u => $pw) {
    attempt($out, "admin_connect_$u", function () use ($u,$pw,$host,$port) {
        new PDO("mysql:host=$host;port=$port", $u, $pw,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    });
}
$rows = [];
try {
    $c = new PDO("mysql:host=$host;port=$port;dbname=$mine", $user, $pass,
                 [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    foreach ($c->query('SHOW DATABASES') as $r) { $rows[] = $r[0]; }
} catch (Throwable $e) { $rows = ['error: ' . $e->getMessage()]; }
$out['visible_schemas'] = $rows;
echo json_encode($out);
"""


def db_probe_php(behat=None) -> str:
    """The §3.2 probe, reading the DSN variable and tables THIS project has.

    The probe runs inside the worker container and reads its DSN out of the
    environment `write_env_file` wrote, and which variable that is belongs to
    the project's row (`repo.BehatProject`): CoreShop's workers carry
    `PIMCORE_TEST_DB_DSN`, Sylius's carry `DATABASE_URL`.  With the name
    fixed, a Sylius probe found no DSN, exited 2, and reported an isolation
    failure that was only a variable it was not looking at.

    The victim tables are the row's for a smaller but real reason.  A
    correctly hardened pool denies on PRIVILEGE, before MySQL resolves the
    name, so a Pimcore table name against a Sylius neighbour still passes.
    A BROKEN pool is where it matters: there the query gets as far as the
    name, answers 1146 "base table not found" instead of 1044/1142, and
    `probe_report` calls that `denials_without_a_permission_error` -- a
    correct refusal to pass, attached to the wrong cause.

    `behat=None` is CoreShop's, so the probe every existing caller renders is
    byte-identical to the one it rendered before.
    """
    from .repo import CORESHOP_BEHAT
    row = behat or CORESHOP_BEHAT
    names = tuple(row.probe_table)
    return (_DB_PROBE_PHP
            .replace(_DSN_ENV_SLOT, row.db_dsn_env)
            .replace(_SECOND_TABLE_SLOT, names[1] if len(names) > 1
                     else names[0])
            .replace(_TABLE_SLOT, names[0]))


#: Every check the probe must report as denied for the boundary to hold.
#: `own_schema_select` is deliberately absent — it must SUCCEED, and a probe
#: where everything is denied is a broken container, not a secure one.
REQUIRED_DENIED = ("victim_connect", "victim_select", "victim_select_any",
                   "victim_insert", "victim_drop", "admin_connect_root")

#: MySQL's own vocabulary for "you may not", and the only evidence that counts
#: as a denial.
#:
#: The probe marks a check denied whenever the statement threw, which is not
#: the same thing: `Base table or view not found` throws too, so a victim
#: schema that merely lacked the table being probed produced a clean
#: certificate for a boundary nobody had tested. A review demonstrated exactly
#: that with a synthetic report in which every "denial" was a missing table.
_DENIAL_MARKERS = ("1044", "1045", "1142", "1143", "1227", "1370",
                   "28000", "42000", "access denied", "command denied")


def probe_report(doc: dict) -> dict:
    """Turn the probe's JSON into a verdict, and refuse the vacuous pass.

    `SHOW DATABASES` returning one schema is NOT the check (review P1-4):
    system schemas are normally visible, and a principal that can see nothing
    at all is usually a container that cannot connect.  So the control is
    checked first: if the worker cannot reach its OWN schema, the probe
    failed, whatever the denials say.
    """
    checks = doc.get("checks") or {}
    control = checks.get("own_schema_select") or {}
    if control.get("denied", True):
        return {"pass": False, "why": "the worker cannot reach its own "
                                      "schema, so nothing here is evidence",
                "control": control, "checks": checks}
    missing = [c for c in REQUIRED_DENIED if c not in checks]
    allowed = [c for c in REQUIRED_DENIED
               if c in checks and not checks[c].get("denied")]
    # A denial has to be a PERMISSION error. Anything else — a missing table,
    # a typo in the probe, an unreachable host — is the check not having run.
    unproven = []
    for name in REQUIRED_DENIED:
        entry = checks.get(name) or {}
        if not entry.get("denied"):
            continue
        text = str(entry.get("error") or "").lower()
        if not any(m in text for m in _DENIAL_MARKERS):
            unproven.append({"check": name,
                             "error": str(entry.get("error"))[:120]})
    non_system = sorted(s for s in (doc.get("visible_schemas") or [])
                        if s not in SYSTEM_SCHEMAS)
    return {"pass": not allowed and not missing and not unproven,
            "reachable_from_worker": allowed,
            "checks_not_run": missing,
            # Denied, but not for a reason that proves anything.
            "denials_without_a_permission_error": unproven,
            "principal": doc.get("principal"),
            "own_schema": doc.get("own_schema"),
            # Reported, never asserted on: see the docstring.
            "non_system_schemas_visible": non_system,
            "checks": checks}


def selftest() -> int:
    """Everything that does not need a database — which is the parsing,
    the refusals and the probe's verdict logic."""
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
        except DatabaseRefused:
            return True

    check("a schema name that is not an identifier is refused",
          refused(lambda: _ident("coreshop`; DROP DATABASE x; --", "schema")))
    check("an empty principal is refused", refused(lambda: _ident("", "p")))
    check("a plain identifier is accepted",
          _ident("coreshop_bench_3", "schema") == "coreshop_bench_3")
    check("dropping a system schema is refused",
          refused(lambda: MySQL().drop_schema("mysql")))
    check("passwords are generated, not configured",
          new_password() != new_password() and len(new_password()) >= 24)

    from concurrent.futures import ThreadPoolExecutor
    import threading
    from unittest.mock import patch

    files = {}
    calls = []
    file_lock = threading.Lock()
    credentials_ready = threading.Barrier(2)
    first_closed = threading.Event()
    fixture_passwords = ("fixture-first-password", "fixture-second-password")

    def credential_transport(_db, argv, stdin=None, **_kwargs):
        with file_lock:
            calls.append(list(argv))
            if argv[-2:-1] == ["-c"]:
                assert argv[-1].startswith("umask 077 && cat > ")
                files[shlex.split(argv[-1])[-1]] = stdin
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[2:4] == ["rm", "-f"]:
                files.pop(argv[-1], None)
                return subprocess.CompletedProcess(argv, 0, "", "")
            selected = [arg.split("=", 1)[1] for arg in argv
                        if arg.startswith("--defaults-extra-file=")]
            if len(selected) != 1 or selected[0] not in files:
                return subprocess.CompletedProcess(argv, 1, "", "credential file missing")
            assert _db.password in files[selected[0]]
            return subprocess.CompletedProcess(argv, 0, "1\n", "")

    def concurrent_admin(index):
        with MySQL(password=fixture_passwords[index]) as db:
            assert db.query("SELECT 1;") == [["1"]]
            path = db._cnf
            credentials_ready.wait(timeout=5)
            if index == 0:
                db.close()
                first_closed.set()
            else:
                assert first_closed.wait(timeout=5)
                assert db.query("SELECT 1;") == [["1"]]
            return path

    with patch.object(MySQL, "_docker", credential_transport):
        with ThreadPoolExecutor(max_workers=2) as executor:
            credential_paths = list(executor.map(concurrent_admin, range(2)))
    check("concurrent admin contexts retain independent credentials and cleanup",
          len(set(credential_paths)) == 2 and not files)
    check("concurrent admin credentials still travel only through private stdin files",
          all(password not in " ".join(argv)
              for argv in calls for password in fixture_passwords))

    # The probe verdict, over hand-written documents.
    denied = {"denied": True,
              "error": "SQLSTATE[42000]: 1142 SELECT command denied to user"}
    allowed_c = {"denied": False, "error": None}
    good = {"principal": "bench_3", "own_schema": "coreshop_bench_3",
            "visible_schemas": ["information_schema", "coreshop_bench_3"],
            "checks": {"own_schema_select": allowed_c,
                       **{c: dict(denied) for c in REQUIRED_DENIED}}}
    check("a worker that reaches only its own schema passes",
          probe_report(good)["pass"], json.dumps(probe_report(good))[:200])

    leaky = json.loads(json.dumps(good))
    leaky["checks"]["victim_select"] = allowed_c
    check("a worker that can read a neighbour's schema fails",
          not probe_report(leaky)["pass"]
          and probe_report(leaky)["reachable_from_worker"] == ["victim_select"])

    rooted = json.loads(json.dumps(good))
    rooted["checks"]["admin_connect_root"] = allowed_c
    check("a worker that can still connect as root@% fails",
          not probe_report(rooted)["pass"])

    broken = json.loads(json.dumps(good))
    broken["checks"]["own_schema_select"] = dict(denied)
    check("a container that cannot reach its OWN schema is not a pass",
          not probe_report(broken)["pass"]
          and "own schema" in probe_report(broken)["why"])

    partial = json.loads(json.dumps(good))
    del partial["checks"]["victim_drop"]
    check("a probe that skipped a required check is not a pass",
          not probe_report(partial)["pass"]
          and probe_report(partial)["checks_not_run"] == ["victim_drop"])

    many = json.loads(json.dumps(good))
    many["visible_schemas"] = ["information_schema", "mysql", "sys",
                               "performance_schema", "coreshop_bench_3",
                               "coreshop_bench_0"]
    check("schema VISIBILITY alone never decides the verdict",
          probe_report(many)["pass"]
          and probe_report(many)["non_system_schemas_visible"]
          == ["coreshop_bench_0", "coreshop_bench_3"])

    check("the probe's own control is not in the required-denied set",
          "own_schema_select" not in REQUIRED_DENIED)
    check("opening a neighbour's schema at all is a required denial",
          "victim_connect" in REQUIRED_DENIED)

    # A denial that is really a missing table proves nothing.
    wrong_reason = json.loads(json.dumps(good))
    wrong_reason["checks"]["victim_select"] = {
        "denied": True,
        "error": "SQLSTATE[42S02]: Base table or view not found: 1146"}
    rep = probe_report(wrong_reason)
    check("a 'denial' that is really a missing table does NOT pass",
          not rep["pass"]
          and rep["denials_without_a_permission_error"][0]["check"]
          == "victim_select", json.dumps(rep)[:220])
    check("a denial naming a real permission error does pass",
          probe_report(good)["pass"])
    coreshop_probe = db_probe_php()
    check("the probe is PHP that reads the DSN from the environment, and "
          "the project that names no row still reads PIMCORE_TEST_DB_DSN",
          "getenv('PIMCORE_TEST_DB_DSN')" in coreshop_probe
          and "$argv[1]" in coreshop_probe
          and _DSN_ENV_SLOT not in coreshop_probe)
    from dataclasses import replace as _replace
    from .repo import CORESHOP_BEHAT
    sylius_probe = db_probe_php(
        _replace(CORESHOP_BEHAT, db_dsn_env="DATABASE_URL",
                 db_dsn_suffix="?charset=utf8mb4", db_install_vars=False))
    check("...and a project whose row names DATABASE_URL gets a probe that "
          "reads DATABASE_URL -- the rest of the probe unchanged",
          "getenv('DATABASE_URL')" in sylius_probe
          and "PIMCORE" not in sylius_probe
          and sylius_probe.replace("getenv('DATABASE_URL')", "X")
          == coreshop_probe.replace("getenv('PIMCORE_TEST_DB_DSN')", "X"))
    # The CoreShop probe is the ONE §3.2 acceptance in production use, so
    # what is pinned is its bytes and not a property of them: the table
    # names became a row in the same change, and a probe that silently
    # started asking `objects` where it asked `users` would be a different
    # acceptance under the same name.
    import hashlib
    check("CoreShop's rendered probe is byte-for-byte the one it was before "
          "the DSN variable and the victim tables became rows",
          hashlib.sha256(coreshop_probe.encode("utf-8")).hexdigest()[:16]
          == "0014f57dec92517a")
    check("CoreShop's probe still names its two victim tables where it named "
          "them: `users` for the plain SELECT, `objects` for the other three",
          coreshop_probe.count("`$victim`.`users`") == 1
          and coreshop_probe.count("`$victim`.`objects`") == 3
          and _TABLE_SLOT not in coreshop_probe
          and _SECOND_TABLE_SLOT not in coreshop_probe)
    one_name = db_probe_php(_replace(CORESHOP_BEHAT,
                                     probe_table=("sylius_channel",)))
    check("a project whose row names ONE table uses it for all four victim "
          "checks, and no Pimcore table survives into its probe",
          one_name.count("`$victim`.`sylius_channel`") == 4
          and "objects" not in one_name and "`users`" not in one_name
          and _SECOND_TABLE_SLOT not in one_name)

    # A dump that carries `DEFINER=root@%` is a dump that breaks the moment
    # `root@%` is removed — and a `SQL SECURITY DEFINER` view owned by a
    # superuser reads through the very grant boundary §3.2 sets up.
    import tempfile
    dump = (
        "CREATE TABLE `t` (`id` int);\n"
        "/*!50001 CREATE ALGORITHM=UNDEFINED */\n"
        "/*!50013 DEFINER=`root`@`%` SQL SECURITY DEFINER */\n"
        "/*!50001 VIEW `object_cs_order` AS SELECT 1 */;\n"
        "/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ "
        "/*!50003 TRIGGER `t_ai` AFTER INSERT ON `t` FOR EACH ROW BEGIN END */;;\n")
    with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as fh:
        fh.write(dump)
        path = fh.name
    n = MySQL._rewrite_definers(path)
    with open(path, encoding="utf-8") as fh:
        rewritten = fh.read()
    os.remove(path)
    check("every DEFINER clause is removed from a dump",
          n == 2 and "DEFINER=" not in rewritten, f"{n}: {rewritten[:200]}")
    check("views become SQL SECURITY INVOKER, so they obey the WORKER's grants",
          "SQL SECURITY INVOKER" in rewritten
          and "SQL SECURITY DEFINER" not in rewritten)
    check("the rest of the dump is untouched",
          "CREATE TABLE `t` (`id` int);" in rewritten
          and "object_cs_order" in rewritten and "t_ai" in rewritten)

    print("\n" + ("ALL PASS (dbadmin)" if ok else "FAILURES (dbadmin)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
