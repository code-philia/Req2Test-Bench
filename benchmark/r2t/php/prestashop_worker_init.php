<?php
/** Prepare this worker's native restore inputs before runtime attestation. */
declare(strict_types=1);

function prestashopRestoreName(string $name, string $sourceSchema, string $schema, string $version): string
{
    $prefix = 'ps_dump_' . $sourceSchema . '_' . $version;
    if ($name === $prefix . '.sql'
        || preg_match('/^' . preg_quote($prefix, '/') . '_ps_[A-Za-z0-9_]+\.(sql|md5)$/D', $name)) {
        return 'ps_dump_' . $schema . '_' . $version . substr($name, strlen($prefix));
    }
    return $name;
}

/** Restore the source-tracked module link omitted by regular-file seed archives. */
function prestashopRestoreNativeModuleLinks(string $root): void
{
    $root = realpath($root);
    if ($root === false) {
        throw new RuntimeException('Missing worker root');
    }
    $target = $root . '/modules/ps_apiresources';
    if (!is_dir($target) || realpath($target) !== $target) {
        throw new RuntimeException('Missing real workspace API resources module');
    }
    // Both originate from PrestaShop's tracked tests/Resources module link:
    // the fixture itself and ResourceResetter's preserved native backup.
    $parents = [
        $root . '/tests/Resources/modules',
        $root . '/var/r2t-db-dumps/ps_backup_test_modules',
    ];
    $relative = '../../../modules/ps_apiresources';
    foreach ($parents as $parent) {
        if (!is_dir($parent) || realpath($parent) !== $parent) {
            throw new RuntimeException('Missing real native module directory');
        }
        $link = $parent . '/ps_apiresources';
        if (is_link($link)) {
            if (readlink($link) !== $relative) {
                throw new RuntimeException('Native module link differs from pinned source');
            }
        } elseif (file_exists($link)) {
            throw new RuntimeException('Native module link replaced by another entry');
        }
    }
    foreach ($parents as $parent) {
        $link = $parent . '/ps_apiresources';
        if (!is_link($link) && !symlink($relative, $link)) {
            throw new RuntimeException('Cannot restore native module link');
        }
    }
}

function prestashopCopyRestoreInputs(string $source, string $target, string $sourceSchema, string $schema, string $version): int
{
    foreach (['ps_backup_test_img', 'ps_backup_test_download', 'ps_backup_test_modules'] as $directory) {
        if (!is_dir($source . '/' . $directory)) {
            throw new RuntimeException('Missing native resource backup');
        }
    }
    $whole = 'ps_dump_' . $sourceSchema . '_' . $version . '.sql';
    if (!is_file($source . '/' . $whole)) {
        throw new RuntimeException('Missing native database dump');
    }
    $copy = function (string $from, string $to) use (&$copy): void {
        if (is_link($from)) {
            if (!symlink(readlink($from), $to)) {
                throw new RuntimeException('Cannot copy resource symlink');
            }
        } elseif (is_dir($from)) {
            if (!is_dir($to) && !mkdir($to, 0755, true)) {
                throw new RuntimeException('Cannot copy resource directory');
            }
            foreach (new DirectoryIterator($from) as $entry) {
                if (!$entry->isDot()) {
                    $copy($entry->getPathname(), $to . '/' . $entry->getFilename());
                }
            }
        } elseif (!copy($from, $to)) {
            throw new RuntimeException('Cannot copy native restore input');
        }
    };
    $tables = 0;
    foreach (new DirectoryIterator($source) as $entry) {
        if ($entry->isDot()) {
            continue;
        }
        $name = $entry->getFilename();
        $renamed = prestashopRestoreName($name, $sourceSchema, $schema, $version);
        if (str_ends_with($name, '.md5')) {
            if (!is_file(substr($entry->getPathname(), 0, -4) . '.sql')) {
                throw new RuntimeException('Missing paired native table dump');
            }
            ++$tables;
        }
        $copy($entry->getPathname(), $target . '/' . $renamed);
    }
    if ($tables === 0) {
        throw new RuntimeException('Missing native table restore inputs');
    }
    return $tables;
}

function prestashopWorkerInit(array $args): array
{
    [$sourceSchema, $schema, $principal] = array_slice($args, 1);
    $root = getcwd();
    $dsn = parse_url((string) getenv('DATABASE_URL'));
    if (!is_array($dsn) || ($dsn['scheme'] ?? '') !== 'mysql'
        || rawurldecode(ltrim($dsn['path'] ?? '', '/')) !== $schema
        || rawurldecode($dsn['user'] ?? '') !== $principal
        || !str_starts_with($schema, 'test_')) {
        throw new RuntimeException('Worker DSN identity mismatch');
    }
    // Generated configuration has its own $dsn/$schema locals.
    $parameters = (static function (string $path): array {
        return require $path;
    })($root . '/app/config/parameters.php')['parameters'];
    if ('test_' . $parameters['database_name'] !== $schema
        || $parameters['database_user'] !== $principal
        || $parameters['database_host'] !== $dsn['host']
        || (int) $parameters['database_port'] !== (int) ($dsn['port'] ?? 3306)
        || $parameters['database_password'] !== rawurldecode($dsn['pass'] ?? '')) {
        throw new RuntimeException('Application parameters differ from worker DSN');
    }
    $db = new PDO(sprintf('mysql:host=%s;port=%d;dbname=%s',
        $parameters['database_host'], $parameters['database_port'], $schema),
        $parameters['database_user'], $parameters['database_password'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $observed = $db->query('SELECT DATABASE(), CURRENT_USER()')->fetch(PDO::FETCH_NUM);
    if ($observed[0] !== $schema || explode('@', $observed[1])[0] !== $principal) {
        throw new RuntimeException('Live database identity mismatch');
    }
    if (sys_get_temp_dir() !== '/tmp') {
        throw new RuntimeException('Runtime temporary files must stay outside workspace');
    }
    require_once $root . '/src/Core/Version.php';
    prestashopRestoreNativeModuleLinks($root);
    $tables = prestashopCopyRestoreInputs($root . '/var/r2t-db-dumps', '/tmp',
        $sourceSchema, $schema, \PrestaShop\PrestaShop\Core\Version::VERSION);
    return ['schema' => $schema, 'principal' => $principal, 'tables' => $tables,
            'private_tmp' => true];
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    try {
        if (count($argv) !== 4) {
            throw new RuntimeException('Expected source schema, worker schema and principal');
        }
        echo json_encode(prestashopWorkerInit($argv)) . "\n";
    } catch (Throwable $error) {
        // Messages from PDO can carry credentials. The caller only needs failure.
        fwrite(STDERR, 'PrestaShop worker initialization failed: ' . get_class($error) . "\n");
        exit(1);
    }
}
