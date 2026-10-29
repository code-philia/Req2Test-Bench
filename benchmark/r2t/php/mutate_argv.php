<?php
/**
 * Run the staged mutation engine under an argument vector read from a file.
 *
 * WHY THIS EXISTS.  The in-image materialisation audit runs `mutate.php`
 * inside the pool's container, so every argument it passes becomes a Docker
 * argument -- and `r2t.core.docker_cli.docker_argv`, the owner's execution
 * authority, refuses an EMPTY argv token.  A mutant descriptor carries the
 * ORIGINAL and MUTATED source text, and a deletion-shaped operator mutates
 * text to the empty string: `RemoveNegation` deletes a unary `!`, so
 * `--mutated ''` is an empty token and the authority refuses it.  Live proof
 * (track S, Sylius pool, 2026-09-10): the audit walked 182 mutants and died
 * on the 183rd, the first `RemoveNegation`, with `REFUSED: Docker argv
 * contains an invalid token`.  All 930 of that population's RemoveNegation
 * rows would have died the same way.
 *
 * Two things could not move.  `mutate.php`'s bytes are the `engine_source`
 * sha256 bound in CoreShop's frozen asset index and in every validation
 * report, so the engine cannot learn a new calling convention; and the
 * Docker authority is the owner's, so its argv rule is not relaxed for one
 * caller.  This shim is the third option: the audit writes the argument
 * vector as JSON INSIDE the disposable copy it already mounts, and the only
 * Docker arguments left are two constant, path-shaped tokens.  No mutant's
 * text is ever a container argument.
 *
 * WHAT IT DOES NOT DO.  It does not interpret the vector, know an operator,
 * or touch the tree.  It replaces `$argv` with the vector the audit wrote and
 * requires the engine staged beside it -- so `mutate.php` sees exactly the
 * command line the HOST route would have handed it, and the two routes stay
 * one protocol.
 *
 *   php mutate_argv.php <descriptor path>
 *
 *   {"schema": "r2t.mutation-applier-argv/1",
 *    "argv": ["/work/var/bench_mutate/mutate.php", "--root", "/work",
 *             "--apply-file", "src/A.php", "--original", "!", "--mutated", ""]}
 *
 * The vector IS `$argv` and is installed verbatim, element 0 included: PHP's
 * `$argv[0]` is the SCRIPT, not the interpreter, and `mutate.php` opens with
 * `array_slice($argv, 1)` to drop it.  A vector that still carried "php"
 * would leave the script path in argument position, and the engine would
 * exit 2 on `unknown argument /work/var/bench_mutate/mutate.php`.
 */
declare(strict_types=1);

/**
 * The argument vector one descriptor names, or a refusal on stderr.
 *
 * Everything is checked before the engine is reached, because a descriptor
 * that is half-read is a command line nobody wrote: a truncated JSON write
 * would otherwise become a SHORTER argv, and a short argv is a different
 * mutant (or an enumeration) rather than an error.  Density and string-ness
 * are checked for the same reason and not as input hygiene: `json_decode`
 * with `true` turns a sparse or keyed JSON object into an associative PHP
 * array, which the engine's POSITIONAL loop would walk as some other
 * command line rather than reject.
 */
function r2t_audit_argument_vector(string $path): array
{
    if ($path === '') {
        fwrite(STDERR, "mutate_argv.php needs one descriptor path\n");
        exit(2);
    }
    $raw = @file_get_contents($path);
    if ($raw === false) {
        fwrite(STDERR, "cannot read argv descriptor {$path}\n");
        exit(2);
    }
    $document = json_decode($raw, true);
    if (!is_array($document)
        || ($document['schema'] ?? null) !== 'r2t.mutation-applier-argv/1') {
        fwrite(STDERR, "argv descriptor {$path} is not "
            . "r2t.mutation-applier-argv/1\n");
        exit(2);
    }
    $vector = $document['argv'] ?? null;
    if (!is_array($vector) || $vector === []
        || array_keys($vector) !== range(0, count($vector) - 1)) {
        fwrite(STDERR, "argv descriptor {$path} has no argument vector\n");
        exit(2);
    }
    foreach ($vector as $value) {
        if (!is_string($value)) {
            fwrite(STDERR, "argv descriptor {$path} has a non-string "
                . "argument\n");
            exit(2);
        }
    }
    return $vector;
}

$argv = r2t_audit_argument_vector($argv[1] ?? '');
$argc = count($argv);
$_SERVER['argv'] = $argv;
$_SERVER['argc'] = $argc;
require __DIR__ . '/mutate.php';
