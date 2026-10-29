<?php
/**
 * Deterministic mutant enumerator and applier for the requirement-to-test
 * benchmark's mutation campaign (SPEC_C3_PARALLEL.md S3.11).
 *
 * S3.11 exists because v2 conflated covered *lines* with *mutants*: a line
 * yields zero, one or several mutants, so 151,180 (line, item) pairs were
 * never (mutant, item) executions.  Fixing that needs an enumerator whose
 * output IS the population -- named engine, named version, named operators,
 * named exclusions, and a manifest digest that a rerun over the same tree
 * reproduces byte for byte.
 *
 * DETERMINISM IS THE REQUIREMENT, not a nicety.  The campaign metadata carries
 * a digest of this file's output; if the digest moves the campaign is no
 * longer reproducible and every mutation number computed from it is
 * unfalsifiable.  Two orderings are therefore pinned by hand:
 *   * the file list is sorted, because RecursiveDirectoryIterator returns
 *     readdir order, which is inode order on ext4 -- stable on one machine and
 *     different on a restored copy of the same tree;
 *   * per file, mutants are sorted by (start byte, end byte, operator) after
 *     collection, so the result does not depend on the AST walk order at all.
 * Everything else here (token scan, operator maps) is already a pure function
 * of the file bytes.
 *
 * Enumeration and application share one script. The code that says "mutant M
 * exists here" and the code that materialises M must not be able to disagree about
 * what M is: --apply-file re-enumerates the single file it is about to rewrite
 * and REFUSES unless the requested record appears in that fresh enumeration,
 * byte-identical.  A file edited between enumeration and application then
 * fails loudly instead of scoring some other mutation under M's identifier.
 *
 * This script assigns NO identifiers.  The Python side owns the id scheme, so
 * that the id can outlive a change in traversal here.
 *
 * OPERATOR PROFILES.  r2t.mutation.OPERATORS_V1 is the immutable shared-eight
 * Slice 1 profile.  The v2 default appends LogicalConnector (&& <-> || and
 * and <-> or), RemoveNegation (delete unary !), and ConstantReplacement
 * (integer literal n -> decimal n+1).  Deliberate exclusions are UOI
 * insertion, string literals, general statement deletion, and bitwise,
 * argument and exception mutation.  Exact/partial mappings to PIT, Infection
 * and the classical names are documented in benchmark/MUTATION_OPERATOR_MAPPING_V2.md.
 * The shared eight retain their historical @codeCoverageIgnore suppression.
 * The appended three traverse the production AST irrespective of coverage
 * annotations: coverage policy is not a mutation-ignore directive, and any
 * execution-trivial row is for the later hard-subset screen to remove.
 *
 * ENUMERATE
 *   php mutate.php --root /var/www/html \
 *       --path src/CoreShop/Component [--path ...] --out var/manifest.json \
 *       [--operator-profile v1|v2]
 *   v2 is the default.  Explicit v1 runs only the frozen shared traversal and
 *   retains the historical envelope shape; it is a producer profile, not a
 *   post-hoc filter over rows emitted under a different population.
 *
 *   {
 *     "engine": "r2t-mutate", "engine_version": "1.0",
 *     "parser": "v5.7.0",              // nikic/php-parser, from composer
 *     "files": 412,                    // files enumerated (post-exclusions)
 *     "errors": {"<rel path>": "<parse error>"},
 *     "n_invalid": 2,                  // optional; omitted when zero
 *     "enumerator_rev": "...",        // opt-in; omitted for legacy/v1
 *     "mutants": [
 *       {"file": "<rel path>", "start_line": 42, "start_col": 17,
 *        "end_line": 42, "end_col": 17,          // inclusive, 1-based, BYTES
 *        "operator": "NegateConditional",
 *        "original": "<", "mutated": ">="}
 *     ]
 *   }
 *
 *   original/mutated are the exact source bytes of the mutated region before
 *   and after, so a consumer can reconstruct the mutant without a PHP parser.
 *   The region is the smallest one that changes -- the operator token, the
 *   literal, or the whole statement -- never the enclosing expression, because
 *   an enclosing-expression `original` would have to be re-printed and a
 *   pretty-printer round trip is not byte-identical to the source it read.
 *
 * PARSE ONLY
 *   php mutate.php --root DIR --path REL --parse-only [--out FILE]
 *   Uses the same file admission and parser checks as enumeration, without
 *   enumerating or reparsing sibling candidates. Returns parser/files/errors
 *   evidence with no mutants field; this is not a population manifest.
 *
 * APPLY
 *   php mutate.php --root /var/www/html --apply-file <rel> \
 *       --start-line N --start-col N --operator OP \
 *       --original TEXT --mutated TEXT --out <rel>
 *
 * Exit codes: 0 ok, 2 usage, 3 output failure, 4 REFUSED (integrity).
 */

declare(strict_types=1);

use PhpParser\Node;
use PhpParser\ParserFactory;

$autoload = null;
$autoloadCandidates = [__DIR__ . '/../../../vendor/autoload.php',
                       '/var/www/html/vendor/autoload.php'];
$configuredAutoload = getenv('R2T_PHP_AUTOLOAD');
if (is_string($configuredAutoload) && $configuredAutoload !== '') {
    array_unshift($autoloadCandidates, $configuredAutoload);
}
foreach ($autoloadCandidates as $cand) {
    if (is_file($cand)) {
        $autoload = $cand;
        break;
    }
}
if ($autoload === null) {
    fwrite(STDERR, "cannot find vendor/autoload.php\n");
    exit(2);
}
require $autoload;

const ENGINE = 'r2t-mutate';
const ENGINE_VERSION = '1.0';
// Implementation provenance, deliberately absent from legacy/v1 envelopes.
// A v2 caller opts in with --record-enumerator-rev; recording it in a v1
// manifest would rewrite the identity of an already published population.
const ENUMERATOR_REV = 'r2t-mutate/m3-operators-v2-1';

/** Keep the token positions produced by the installed parser's own lexer. */
function mutation_parser(): PhpParser\Parser
{
    if (method_exists(PhpParser\Parser::class, 'getTokens')) {
        return (new ParserFactory())->createForNewestSupportedVersion();
    }
    // PrestaShop's locked parser 4 exposes token_get_all-shaped tokens on
    // its lexer. Use the same attributes as its newest-version factory.
    $lexer = new PhpParser\Lexer\Emulative(['usedAttributes' => [
        'comments', 'startLine', 'endLine', 'startTokenPos', 'endTokenPos',
        'startFilePos', 'endFilePos',
    ]]);
    return new class($lexer) extends PhpParser\Parser\Php7 {
        public function getTokens(): array
        {
            $tokens = [];
            $pos = 0;
            foreach ($this->lexer->getTokens() as $token) {
                $text = is_array($token) ? $token[1] : $token;
                $tokens[] = (object) ['text' => $text, 'pos' => $pos];
                $pos += strlen($text);
            }
            return $tokens;
        }
    };
}

function refuse(string $msg): void
{
    fwrite(STDERR, 'REFUSED: ' . $msg . "\n");
    exit(4);
}

/* ------------------------------------------------------------------ *
 * Arguments
 * ------------------------------------------------------------------ */

$opts = [
    'root' => null, 'paths' => [], 'out' => null,
    'apply_file' => null, 'start_line' => null, 'start_col' => null,
    'operator' => null, 'original' => null, 'mutated' => null,
    'operator_profile' => 'v2',
    'record_enumerator_rev' => false,
    'validity_probe' => false,
    'parse_only' => false,
];
$argvv = array_slice($argv, 1);
for ($i = 0; $i < count($argvv); $i++) {
    // Every value-taking flag reads $argvv[++$i]; a trailing flag with no
    // value would silently pass null through to the integrity check below,
    // so a missing value is a usage error here rather than a confusing
    // "position not found" refusal three hundred lines later.
    $needsValue = in_array($argvv[$i], [
        '--root', '--path', '--out', '--apply-file', '--start-line',
        '--start-col', '--operator', '--original', '--mutated',
        '--operator-profile',
    ], true);
    if ($needsValue && !array_key_exists($i + 1, $argvv)) {
        fwrite(STDERR, "argument {$argvv[$i]} needs a value\n");
        exit(2);
    }
    switch ($argvv[$i]) {
        case '--root': $opts['root'] = $argvv[++$i]; break;
        case '--path': $opts['paths'][] = $argvv[++$i]; break;
        case '--out': $opts['out'] = $argvv[++$i]; break;
        case '--apply-file': $opts['apply_file'] = $argvv[++$i]; break;
        case '--start-line': $opts['start_line'] = (int) $argvv[++$i]; break;
        case '--start-col': $opts['start_col'] = (int) $argvv[++$i]; break;
        case '--operator': $opts['operator'] = $argvv[++$i]; break;
        case '--original': $opts['original'] = $argvv[++$i]; break;
        case '--mutated': $opts['mutated'] = $argvv[++$i]; break;
        case '--operator-profile': $opts['operator_profile'] = $argvv[++$i]; break;
        case '--record-enumerator-rev': $opts['record_enumerator_rev'] = true; break;
        case '--parse-only': $opts['parse_only'] = true; break;
        case '--validity-probe': $opts['validity_probe'] = true; break;
        default:
            fwrite(STDERR, "unknown argument {$argvv[$i]}\n");
            exit(2);
    }
}
if ($opts['parse_only'] && ($opts['apply_file'] !== null || $opts['validity_probe'])) {
    fwrite(STDERR, "--parse-only takes neither --apply-file nor --validity-probe\n");
    exit(2);
}
if (!in_array($opts['operator_profile'], ['v1', 'v2'], true)) {
    fwrite(STDERR, "--operator-profile must be v1 or v2\n");
    exit(2);
}
if ($opts['root'] === null) {
    fwrite(STDERR, "usage: mutate.php --root DIR --path REL [--path REL ...] [--out FILE]\n"
        . "       mutate.php --root DIR --apply-file REL --start-line N --start-col N \\\n"
        . "           --operator OP --original TEXT --mutated TEXT --out REL\n");
    exit(2);
}
$root = rtrim($opts['root'], '/');
if (!is_dir($root)) {
    fwrite(STDERR, "root is not a directory: {$root}\n");
    exit(2);
}

/** --out and --apply-file are documented as root-relative; absolute still works. */
function resolve_path(string $root, string $p): string
{
    return (strlen($p) > 0 && $p[0] === '/') ? $p : $root . '/' . ltrim($p, '/');
}

/* ------------------------------------------------------------------ *
 * Engine identity
 * ------------------------------------------------------------------ */

/**
 * The manifest names the parser version because operator coverage is a
 * function of it: php-parser gained enum, readonly and first-class-callable
 * node types across 4.x->5.x, and a manifest that does not say which version
 * produced it cannot be checked against a rerun on a different image.
 *
 * $root's OWN vendor tree is consulted first.  Composer's InstalledVersions
 * describes whichever autoloader this script loaded, which is pinned to
 * /var/www/html above and has nothing to do with --root: asking it first meant
 * `--root` a tree with no vendor/ at all still reported a confident version
 * number for a parser in a different tree.  r2t.mutation is explicit that the
 * parser version is "a property of the tree being mutated, not of this
 * repository", so the tree being mutated is asked first.
 */
function parser_version(string $root): string
{
    $inst = $root . '/vendor/composer/installed.json';
    if (is_file($inst)) {
        $data = json_decode((string) file_get_contents($inst), true);
        $pkgs = $data['packages'] ?? (is_array($data) ? $data : []);
        if (is_array($pkgs)) {
            foreach ($pkgs as $p) {
                if (is_array($p) && ($p['name'] ?? null) === 'nikic/php-parser'
                    && (string) ($p['version'] ?? '') !== '') {
                    return (string) $p['version'];
                }
            }
        }
    }
    // Fallback: the parser that is actually running.  True of this run, but
    // not attributable to $root -- see the note above.
    if (class_exists('\Composer\InstalledVersions')) {
        try {
            $v = \Composer\InstalledVersions::getPrettyVersion('nikic/php-parser');
            if (is_string($v) && $v !== '') {
                return $v;
            }
        } catch (Throwable $e) {
            // fall through
        }
    }
    return '';
}

/* ------------------------------------------------------------------ *
 * Source geometry
 * ------------------------------------------------------------------ */

/** Byte offset of the start of each line; index 0 is line 1. */
function line_starts(string $code): array
{
    $starts = [0];
    $len = strlen($code);
    for ($i = 0; $i < $len; $i++) {
        if ($code[$i] === "\n") {
            $starts[] = $i + 1;
        }
    }
    return $starts;
}

/**
 * Columns are 1-based BYTE offsets within the line, not characters.  A
 * character column would need the file's encoding to be known and would make
 * the apply-side offset arithmetic depend on mb_* configuration; the manifest
 * is a machine artefact, so bytes are the honest unit.
 */
function pos_to_linecol(array $starts, int $pos): array
{
    $lo = 0;
    $hi = count($starts) - 1;
    while ($lo < $hi) {
        $mid = intdiv($lo + $hi + 1, 2);
        if ($starts[$mid] <= $pos) {
            $lo = $mid;
        } else {
            $hi = $mid - 1;
        }
    }
    return [$lo + 1, $pos - $starts[$lo] + 1];
}

function linecol_to_pos(array $starts, int $line, int $col): ?int
{
    if ($line < 1 || $line > count($starts) || $col < 1) {
        return null;
    }
    return $starts[$line - 1] + ($col - 1);
}

/* ------------------------------------------------------------------ *
 * Exclusions (S3.11; repeated in the manifest by the Python side)
 * ------------------------------------------------------------------ */

/**
 * A generated file's mutants are noise: nobody maintains a test for generated
 * code, so every one of them is born unkillable and inflates the denominator.
 * Only the head of the file is scanned because that is where the banner is,
 * and because "@generated" appearing in a docblock 900 lines down is a comment
 * about something else.
 */
function is_generated(string $code): bool
{
    $head = '';
    $offset = 0;
    for ($n = 0; $n < 40; $n++) {
        $nl = strpos($code, "\n", $offset);
        if ($nl === false) {
            $head .= substr($code, $offset);
            break;
        }
        $head .= substr($code, $offset, $nl - $offset + 1);
        $offset = $nl + 1;
    }
    return strpos($head, '@generated') !== false || strpos($head, 'GENERATED by') !== false;
}

/**
 * Line ranges between @codeCoverageIgnoreStart and ...End, inclusive of both
 * marker lines, matching PHPUnit.  An unterminated Start runs to end of file
 * -- PHPUnit does the same, and treating it as "no exclusion" would put back
 * exactly the mutants the author declared untestable.
 */
function ignore_ranges(string $code): array
{
    // MUST split on "\n" alone, exactly as line_starts() and php-parser do.
    // preg_split('/\R/') also breaks on a bare \r, \v, \f or \x85, so a single
    // form-feed byte inside a string literal shifted every subsequent line
    // number by one and the ignore range was then applied to the wrong lines:
    // mutants outside a @codeCoverageIgnore block were dropped and mutants
    // inside one were admitted, silently, in a file that parsed cleanly.
    $lines = explode("\n", $code);
    $ranges = [];
    $depth = 0;
    $open = 0;
    foreach ($lines as $i => $line) {
        if (strpos($line, '@codeCoverageIgnoreStart') !== false) {
            if ($depth === 0) {
                $open = $i + 1;
            }
            $depth++;
        } elseif (strpos($line, '@codeCoverageIgnoreEnd') !== false) {
            if ($depth > 0) {
                $depth--;
                if ($depth === 0) {
                    $ranges[] = [$open, $i + 1];
                }
            }
        }
    }
    if ($depth > 0) {
        $ranges[] = [$open, count($lines)];
    }
    return $ranges;
}

function in_ignored(array $ranges, int $line): bool
{
    foreach ($ranges as [$a, $b]) {
        if ($line >= $a && $line <= $b) {
            return true;
        }
    }
    return false;
}

/** Bare @codeCoverageIgnore -- \b fails against "...IgnoreStart", so Start/End do not match. */
function doc_says_ignore(?Node $node): bool
{
    if ($node === null) {
        return false;
    }
    $doc = $node->getDocComment();
    if ($doc === null) {
        return false;
    }
    return (bool) preg_match('/@codeCoverageIgnore\b/', $doc->getText());
}

/* ------------------------------------------------------------------ *
 * Operator tables
 * ------------------------------------------------------------------ */

/**
 * Node class -> [operator name, source texts the operator token may take,
 *                replacement text].
 *
 * A relational node appears in TWO tables on purpose: `<` yields both
 * ConditionalBoundary (`<=`) and NegateConditional (`>=`) at the same byte
 * position.  They are different mutants -- an off-by-one guard kills the first
 * and not always the second -- which is precisely why (file, line, col) alone
 * is not a mutant identity and the record carries the operator.
 */
function conditional_boundary_map(): array
{
    return [
        Node\Expr\BinaryOp\Smaller::class => [['<'], '<='],
        Node\Expr\BinaryOp\SmallerOrEqual::class => [['<='], '<'],
        Node\Expr\BinaryOp\Greater::class => [['>'], '>='],
        Node\Expr\BinaryOp\GreaterOrEqual::class => [['>='], '>'],
    ];
}

function negate_conditional_map(): array
{
    return [
        // `<>` is the legacy spelling of `!=`; the token text is kept as
        // `original` so the apply-side byte comparison matches the file.
        Node\Expr\BinaryOp\Equal::class => [['=='], '!='],
        Node\Expr\BinaryOp\NotEqual::class => [['!=', '<>'], '=='],
        Node\Expr\BinaryOp\Identical::class => [['==='], '!=='],
        Node\Expr\BinaryOp\NotIdentical::class => [['!=='], '==='],
        Node\Expr\BinaryOp\Smaller::class => [['<'], '>='],
        Node\Expr\BinaryOp\GreaterOrEqual::class => [['>='], '<'],
        Node\Expr\BinaryOp\Greater::class => [['>'], '<='],
        Node\Expr\BinaryOp\SmallerOrEqual::class => [['<='], '>'],
    ];
}

/**
 * Binary arithmetic only.  Unary minus is excluded because `-$x` -> `+$x` is a
 * no-op for every numeric type PHP has, and `+=`/`-=` are excluded because the
 * spec names the binary operators and a compound-assignment mutant is a
 * different operator that would have to be declared in the manifest.
 *
 * `%` -> `*` is present because r2t.mutation declares it as part of the
 * ArithmeticOperator set ("+ -> -, * -> /, % -> *, and their inverses").  It
 * was missing here, so every `%` in the tree was silently absent from a
 * population the manifest claimed to enumerate -- exactly the undeclared
 * shrinkage S3.11 exists to prevent.
 */
function arithmetic_map(): array
{
    return [
        Node\Expr\BinaryOp\Plus::class => [['+'], '-'],
        Node\Expr\BinaryOp\Minus::class => [['-'], '+'],
        Node\Expr\BinaryOp\Mul::class => [['*'], '/'],
        Node\Expr\BinaryOp\Div::class => [['/'], '*'],
        Node\Expr\BinaryOp\Mod::class => [['%'], '*'],
    ];
}

function increment_map(): array
{
    return [
        Node\Expr\PostInc::class => [['++'], '--'],
        Node\Expr\PreInc::class => [['++'], '--'],
        Node\Expr\PostDec::class => [['--'], '++'],
        Node\Expr\PreDec::class => [['--'], '++'],
    ];
}

function logical_connector_map(): array
{
    return [
        Node\Expr\BinaryOp\BooleanAnd::class => [['&&'], '||'],
        Node\Expr\BinaryOp\BooleanOr::class => [['||'], '&&'],
        Node\Expr\BinaryOp\LogicalAnd::class => [['and'], 'or'],
        Node\Expr\BinaryOp\LogicalOr::class => [['or'], 'and'],
    ];
}

/** Preserve the ordinary all-upper/title/lower spelling of a PHP keyword. */
function mutate_keyword_case(string $written, string $lowerReplacement): string
{
    if ($written === strtoupper($written)) {
        return strtoupper($lowerReplacement);
    }
    if ($written !== strtolower($written)) {
        return ucfirst($lowerReplacement);
    }
    return $lowerReplacement;
}

/**
 * A `return <expr>;` may become `return null;` only where null is actually a
 * legal return value.  Mutating `public function foo(): int` to `return null;`
 * produces a mutant that dies on a TypeError in every single execution --
 * killed by construction, by nothing the candidate wrote.  Those mutants
 * inflate both numerator and denominator and make gold and stub look closer
 * together than they are, so they are never enumerated.
 */
function return_type_allows_null(?Node $type): bool
{
    if ($type === null) {
        return true;                                   // no declared type
    }
    if ($type instanceof Node\NullableType) {
        return true;
    }
    if ($type instanceof Node\UnionType) {
        foreach ($type->types as $t) {
            if (return_type_allows_null($t)) {
                return true;
            }
        }
        return false;
    }
    if ($type instanceof Node\IntersectionType) {
        return false;                                  // A&B never admits null
    }
    if ($type instanceof Node\Identifier) {
        $n = strtolower($type->toString());
        return $n === 'mixed' || $n === 'null';
    }
    if ($type instanceof Node\Name) {
        return strtolower($type->toString()) === 'null';
    }
    return false;
}

/* ------------------------------------------------------------------ *
 * Enumeration
 * ------------------------------------------------------------------ */

/** First token in [$from,$to] whose text is one of $wanted, with its byte offset. */
function find_op_token(array $tokens, int $from, int $to, array $wanted): ?array
{
    $n = count($tokens);
    for ($i = max(0, $from); $i <= $to && $i < $n; $i++) {
        $written = $tokens[$i]->text;
        foreach ($wanted as $candidate) {
            $matches = $written === $candidate
                || (ctype_alpha($candidate)
                    && strcasecmp($written, $candidate) === 0);
            if ($matches) {
                return [$tokens[$i]->pos, $written];
            }
        }
    }
    return null;
}

/**
 * Enumerate every mutant in one already-read, already-parsed file.
 *
 * $ast/$tokens must come from the same parse of $code: the token offsets are
 * used to locate operator tokens that the AST does not carry a position for
 * (a BinaryOp node spans left..right, not the `<` between them).
 */
function enumerate_file(
    string $relpath,
    string $code,
    array $ast,
    array $tokens,
    string $operatorProfile = 'v2'
): array
{
    if (!in_array($operatorProfile, ['v1', 'v2'], true)) {
        refuse("unknown operator profile {$operatorProfile}; expected v1 or v2");
    }
    $starts = line_starts($code);
    $ignored = ignore_ranges($code);
    $out = [];

    $cb = conditional_boundary_map();
    $nc = negate_conditional_map();
    $ar = arithmetic_map();
    $inc = increment_map();
    $logical = logical_connector_map();

    $emit = function (
        string $operator,
        int $startPos,
        int $endPos,
        string $mutated,
        bool $honourCoverage = true
    )
        use ($relpath, $code, $starts, $ignored, &$out): void {
        [$sl, $sc] = pos_to_linecol($starts, $startPos);
        if ($honourCoverage && in_ignored($ignored, $sl)) {
            return;
        }
        [$el, $ec] = pos_to_linecol($starts, $endPos);
        $original = substr($code, $startPos, $endPos - $startPos + 1);
        if ($original === $mutated) {
            return;                                    // identity is not a mutant
        }
        $out[] = [
            'file' => $relpath,
            'start_line' => $sl, 'start_col' => $sc,
            'end_line' => $el, 'end_col' => $ec,
            'operator' => $operator,
            'original' => $original,
            'mutated' => $mutated,
            '_pos' => $startPos, '_end' => $endPos,   // stripped after sorting
        ];
    };

    $binary = function (
        Node\Expr\BinaryOp $node,
        array $spec,
        string $operator,
        bool $honourCoverage = true
    )
        use ($tokens, $relpath, $emit): void {
        [$wanted, $replacement] = $spec;
        $hit = find_op_token(
            $tokens,
            $node->left->getEndTokenPos() + 1,
            $node->right->getStartTokenPos() - 1,
            $wanted
        );
        if ($hit === null) {
            // Unreachable for well-formed source: the parser produced this
            // node, so the token is between its operands.  Refusing rather
            // than skipping keeps a parser upgrade that changes token
            // splitting from silently shrinking the mutant population.
            refuse(sprintf(
                '%s:%d operator token %s not found between operands (%s)',
                $relpath, $node->getStartLine(), implode('|', $wanted), get_class($node)
            ));
        }
        [$pos, $text] = $hit;
        if ($operator === 'LogicalConnector' && ctype_alpha($text)) {
            $replacement = mutate_keyword_case($text, $replacement);
        }
        $emit(
            $operator,
            $pos,
            $pos + strlen($text) - 1,
            $replacement,
            $honourCoverage
        );
    };

    // Explicit recursive walk (rather than NodeTraverser) so that the return
    // type of the enclosing function-like is available at each `return`, and
    // so that a @codeCoverageIgnore docblock prunes the whole subtree instead
    // of only the node it is attached to.
    $walk = function ($node, ?Node $retType)
        use (&$walk, $emit, $binary, $cb, $nc, $ar, $inc, $tokens, $relpath): void {
        if (is_array($node)) {
            foreach ($node as $child) {
                $walk($child, $retType);
            }
            return;
        }
        if (!$node instanceof Node) {
            return;
        }
        if (doc_says_ignore($node)) {
            return;
        }

        if ($node instanceof Node\FunctionLike) {
            $retType = $node->getReturnType();
        }

        $cls = get_class($node);

        if ($node instanceof Node\Expr\BinaryOp) {
            if (isset($cb[$cls])) {
                $binary($node, $cb[$cls], 'ConditionalBoundary');
            }
            if (isset($nc[$cls])) {
                $binary($node, $nc[$cls], 'NegateConditional');
            }
            if (isset($ar[$cls])) {
                $binary($node, $ar[$cls], 'ArithmeticOperator');
            }
        } elseif (isset($inc[$cls])) {
            /** @var Node\Expr\PostInc|Node\Expr\PreInc|Node\Expr\PostDec|Node\Expr\PreDec $node */
            [$wanted, $replacement] = $inc[$cls];
            $post = $node instanceof Node\Expr\PostInc || $node instanceof Node\Expr\PostDec;
            $from = $post ? $node->var->getEndTokenPos() + 1 : $node->getStartTokenPos();
            $to = $post ? $node->getEndTokenPos() : $node->var->getStartTokenPos() - 1;
            $hit = find_op_token($tokens, $from, $to, $wanted);
            if ($hit === null) {
                refuse(sprintf('%s:%d increment token not found (%s)', $relpath, $node->getStartLine(), $cls));
            }
            [$pos, $text] = $hit;
            $emit('Increment', $pos, $pos + strlen($text) - 1, $replacement);
        } elseif ($node instanceof Node\Expr\ConstFetch) {
            $name = strtolower($node->name->toString());
            if ($name === 'true' || $name === 'false') {
                // Source case and any leading `\` are preserved so that the
                // mutant is a one-token edit and `original` is byte-identical
                // to the file: `\TRUE` -> `\FALSE`, not `false`.
                $emit(
                    $name === 'true' ? 'TrueValue' : 'FalseValue',
                    $node->name->getStartFilePos(),
                    $node->name->getEndFilePos(),
                    mutate_bool_literal_text($node, $name)
                );
            }
        } elseif ($node instanceof Node\Stmt\Return_) {
            $expr = $node->expr;
            $isNullLiteral = $expr instanceof Node\Expr\ConstFetch
                && strtolower($expr->name->toString()) === 'null';
            if ($expr !== null && !$isNullLiteral && return_type_allows_null($retType)) {
                $emit('ReturnValue', $node->getStartFilePos(), $node->getEndFilePos(), 'return null;');
            }
        } elseif ($node instanceof Node\Stmt\Expression) {
            $e = $node->expr;
            // An expression statement discards its value by definition, so a
            // method call in this position is exactly the "value unused" case
            // the spec names.  A call whose result is assigned, returned or
            // passed on is NOT an expression statement and is left alone --
            // deleting it would leave an undefined variable, i.e. a mutant
            // killed by a PHP notice rather than by the behaviour under test.
            //
            // The replacement is `;`, not the empty string, because the spec
            // writes the operator as `$o->m($a); -> ;` and because a
            // braceless body -- `if ($x) $o->log();` -- has exactly one
            // statement slot: deleting the bytes outright leaves `if ($x)`
            // dangling and the mutant does not parse.  With `;` the slot is
            // filled by an empty statement, which is a no-op everywhere a
            // deletion would have been and legal everywhere it would not.
            if ($e instanceof Node\Expr\MethodCall
                || $e instanceof Node\Expr\NullsafeMethodCall
                || $e instanceof Node\Expr\StaticCall) {
                $emit('MethodCallRemoval', $node->getStartFilePos(), $node->getEndFilePos(), ';');
            }
        }

        foreach ($node->getSubNodeNames() as $sub) {
            $walk($node->$sub, $retType);
        }
    };

    $walk($ast, null);

    // The appended families deliberately do not consume PHPUnit coverage
    // annotations as mutation ignores.  A separate traversal is also a
    // compatibility proof: none of the shared-v1 walk above moved for v2.
    $walkV2 = function ($node)
        use (&$walkV2, $emit, $binary, $logical, $tokens, $relpath): void {
        if (is_array($node)) {
            foreach ($node as $child) {
                $walkV2($child);
            }
            return;
        }
        if (!$node instanceof Node) {
            return;
        }
        $cls = get_class($node);
        if ($node instanceof Node\Expr\BinaryOp && isset($logical[$cls])) {
            $binary($node, $logical[$cls], 'LogicalConnector', false);
        } elseif ($node instanceof Node\Expr\BooleanNot) {
            $hit = find_op_token(
                $tokens,
                $node->getStartTokenPos(),
                $node->expr->getStartTokenPos() - 1,
                ['!']
            );
            if ($hit === null) {
                refuse(sprintf(
                    '%s:%d RemoveNegation token ! not found before operand',
                    $relpath, $node->getStartLine()
                ));
            }
            [$pos, $text] = $hit;
            $emit(
                'RemoveNegation', $pos, $pos + strlen($text) - 1, '', false
            );
        } elseif ($node instanceof Node\Scalar\Int_
            || $node instanceof Node\Scalar\LNumber) {
            $emit(
                'ConstantReplacement',
                $node->getStartFilePos(),
                $node->getEndFilePos(),
                (string) ($node->value + 1),
                false
            );
        }
        foreach ($node->getSubNodeNames() as $sub) {
            $walkV2($node->$sub);
        }
    };
    if ($operatorProfile === 'v2') {
        $walkV2($ast);
    }

    // Canonical order, independent of the walk above: byte position, then
    // operator name for the several mutants a single token yields.  usort is
    // stable in PHP 8, and the comparator is total, so the order is a pure
    // function of the file bytes.
    usort($out, function (array $a, array $b): int {
        return [$a['_pos'], $a['_end'], $a['operator']] <=> [$b['_pos'], $b['_end'], $b['operator']];
    });
    foreach ($out as &$m) {
        unset($m['_pos'], $m['_end']);
    }
    unset($m);

    return $out;
}

/** `true` -> `false` keeping the source's case style and any leading `\`. */
function mutate_bool_literal_text(Node\Expr\ConstFetch $node, string $lower): string
{
    $written = $node->name->toString();
    $prefix = '';
    if ($node->name instanceof Node\Name\FullyQualified || strncmp($written, '\\', 1) === 0) {
        $prefix = '\\';
        $written = ltrim($written, '\\');
    }
    $target = $lower === 'true' ? 'false' : 'true';
    if ($written === strtoupper($written)) {
        $target = strtoupper($target);
    } elseif ($written !== strtolower($written)) {
        $target = ucfirst($target);
    }
    return $prefix . $target;
}

/** Candidate-reparse the rows from an already parsed original file. */
function parse_valid_mutants(
    PhpParser\Parser $parser,
    string $relpath,
    string $code,
    array $mutants
): array {
    $starts = line_starts($code);
    $valid = [];
    $nInvalid = 0;
    foreach ($mutants as $mutant) {
        $offset = linecol_to_pos($starts, $mutant['start_line'], $mutant['start_col']);
        $original = $mutant['original'];
        if ($offset === null || substr($code, $offset, strlen($original)) !== $original) {
            // A bad span is an enumerator defect, not an ordinary invalid
            // candidate.  Refuse it rather than hiding it in n_invalid.
            refuse(sprintf(
                '%s:%d:%d enumerated original bytes do not match the source',
                $relpath, $mutant['start_line'], $mutant['start_col']
            ));
        }
        $candidate = substr_replace($code, $mutant['mutated'], $offset, strlen($original));
        try {
            $candidateAst = $parser->parse($candidate);
        } catch (PhpParser\Error $e) {
            $nInvalid++;
            continue;
        }
        if ($candidateAst === null) {
            $nInvalid++;
            continue;
        }
        $valid[] = $mutant;
    }
    return [$valid, $nInvalid];
}

/**
 * Parse, enumerate and candidate-reparse one file.
 * Returns [mutants, n_invalid, error|null, skipped].
 */
function process_file(
    PhpParser\Parser $parser,
    string $relpath,
    string $abspath,
    bool $validateCandidates = true,
    string $operatorProfile = 'v2',
    bool $parseOnly = false
): array
{
    $code = file_get_contents($abspath);
    if ($code === false) {
        return [[], 0, 'cannot read file', false];
    }
    if (is_generated($code)) {
        return [[], 0, null, true];
    }
    // `original` is raw source bytes and the manifest is UTF-8 JSON, so a file
    // with a non-UTF-8 byte in any mutable region makes json_encode fail for
    // the WHOLE run: one Latin-1 string literal anywhere in the tree used to
    // abort enumeration with exit 3, no manifest, and no clue which file did
    // it.  Recorded per file instead, on the same "recorded, never dropped"
    // terms as a parse error, so the population change has a witness.
    if (preg_match('//u', $code) !== 1) {
        return [[], 0, 'file is not valid UTF-8; its source bytes cannot be carried in a UTF-8 manifest', false];
    }
    try {
        $ast = $parser->parse($code);
    } catch (Throwable $e) {
        // Recorded, never dropped: a file that stops parsing after a refactor
        // would otherwise remove its mutants from the population and move the
        // recall denominator without anything saying so.
        return [[], 0, $e->getMessage(), false];
    }
    if ($ast === null) {
        return [[], 0, 'parser returned null', false];
    }
    if ($parseOnly) {
        return [[], 0, null, false];
    }
    $enumerated = enumerate_file(
        $relpath, $code, $ast, $parser->getTokens(), $operatorProfile
    );
    if ($validateCandidates) {
        [$valid, $nInvalid] = parse_valid_mutants($parser, $relpath, $code, $enumerated);
        return [$valid, $nInvalid, null, false];
    }
    return [$enumerated, 0, null, false];
}

/** Every .php file under $rel, sorted, with vendor/ and var/ pruned. */
function collect_files(string $root, string $rel, array &$errors): array
{
    $abs = $root . '/' . trim($rel, '/');
    if (is_file($abs)) {
        // A directory --path is filtered to *.php; a file --path was not, so
        // `--path composer.json` was parsed as PHP, produced one big InlineHTML
        // node, no mutants and no error, and still incremented `files` -- the
        // one number in the envelope that claims to count enumerated .php
        // files.  Refusing it as an error keeps that count meaning what the
        // header says it means.
        if (strtolower(pathinfo($abs, PATHINFO_EXTENSION)) !== 'php') {
            $errors[$rel] = 'not a .php file';
            return [];
        }
        return [$abs];
    }
    if (!is_dir($abs)) {
        $errors[$rel] = 'not found';
        return [];
    }
    $todo = [];
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($it as $f) {
        if (!$f->isFile() || strtolower($f->getExtension()) !== 'php') {
            continue;
        }
        $todo[] = $f->getPathname();
    }
    sort($todo);   // see the determinism note in the file header
    return $todo;
}

/**
 * vendor/ is third-party code the benchmark does not test and var/ is scratch;
 * mutants in either are unkillable by construction.  Matched on path segments
 * so that a legitimate directory called "varnish" or a class named
 * "VendorController" is not swept up.
 */
function is_excluded_path(string $relpath): bool
{
    foreach (explode('/', $relpath) as $seg) {
        if ($seg === 'vendor' || $seg === 'var') {
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------ *
 * Mode: APPLY
 * ------------------------------------------------------------------ */

if ($opts['validity_probe']) {
    if ($opts['paths'] || $opts['apply_file'] !== null) {
        fwrite(STDERR, "--validity-probe takes neither --path nor --apply-file\n");
        exit(2);
    }
    $parser = mutation_parser();
    $code = "<?php\n\$value = 1;\n";
    $base = [
        'file' => 'probe.php', 'start_line' => 2, 'start_col' => 10,
        'end_line' => 2, 'end_col' => 10,
        'operator' => 'ValidityProbe', 'original' => '1',
    ];
    [$valid, $nInvalid] = parse_valid_mutants($parser, 'probe.php', $code, [
        $base + ['mutated' => '2'],
        $base + ['mutated' => '('],
    ]);
    echo json_encode(['kept' => count($valid), 'n_invalid' => $nInvalid]) . "\n";
    exit(count($valid) === 1 && $nInvalid === 1 ? 0 : 1);
}

if ($opts['apply_file'] !== null) {
    foreach (['start_line', 'start_col', 'operator', 'original', 'mutated', 'out'] as $req) {
        if ($opts[$req] === null) {
            fwrite(STDERR, "apply mode needs --" . str_replace('_', '-', $req) . "\n");
            exit(2);
        }
    }
    if ($opts['paths']) {
        fwrite(STDERR, "--path is meaningless in apply mode\n");
        exit(2);
    }
    $rel = ltrim($opts['apply_file'], '/');
    // The enumerator prunes vendor/ and var/ before it ever parses; apply mode
    // checked the @generated exclusion but not this one, so the applier would
    // cheerfully materialise a mutant in vendor/ that no enumeration can
    // produce.  That is precisely the disagreement "two modes, one script"
    // claims to make impossible, so it is refused on the same terms.
    if (is_excluded_path($rel)) {
        refuse("{$rel} is under an excluded vendor/ or var/ path; no mutant of it is in the manifest");
    }
    $abs = $root . '/' . $rel;
    if (!is_file($abs)) {
        refuse("apply target does not exist: {$rel}");
    }
    $code = file_get_contents($abs);
    if ($code === false) {
        refuse("cannot read {$rel}");
    }

    $parser = mutation_parser();
    // Population construction reparses every row once.  During a campaign,
    // reparse only the requested row below; reparsing every sibling mutant in
    // this file for every application would multiply the one-time gate cost.
    [$mutants, $_nInvalid, $err, $skipped] = process_file(
        $parser, $rel, $abs, false, $opts['operator_profile']
    );
    if ($err !== null) {
        refuse("{$rel} does not parse now ({$err}); it did when the manifest was built");
    }
    if ($skipped) {
        refuse("{$rel} is excluded as generated; no mutant of it is in the manifest");
    }

    // The whole point of one script with two modes: the requested record must
    // still be produced by the enumerator, field for field.  A file edited
    // since enumeration fails here instead of scoring a different mutation
    // under the recorded identifier.
    $match = null;
    foreach ($mutants as $m) {
        if ($m['start_line'] === $opts['start_line']
            && $m['start_col'] === $opts['start_col']
            && $m['operator'] === $opts['operator']
            && $m['original'] === $opts['original']
            && $m['mutated'] === $opts['mutated']) {
            $match = $m;
            break;
        }
    }
    if ($match === null) {
        // Deliberately does not guess which side is wrong: either the file
        // moved under the manifest, or the caller invented a record.  Both are
        // "do not score this run", and a message that picked one would be a
        // guess printed as a fact.
        refuse(sprintf(
            'enumerating %s now yields no mutant %s at %d:%d with this original/mutated text'
            . ' -- the file has changed since the manifest was built, or the record is not from it',
            $rel, $opts['operator'], $opts['start_line'], $opts['start_col']
        ));
    }
    [$validMatch, $_invalidMatch] = parse_valid_mutants(
        $parser, $rel, $code, [$match]
    );
    if (!$validMatch) {
        refuse("the requested mutant no longer parses in {$rel}; an invalid candidate cannot belong to a manifest");
    }

    $starts = line_starts($code);
    $off = linecol_to_pos($starts, $match['start_line'], $match['start_col']);
    if ($off === null) {
        refuse("position {$match['start_line']}:{$match['start_col']} is outside {$rel}");
    }
    // Belt and braces over the enumerator agreement above: compare the bytes
    // themselves, because that is the invariant the score depends on.
    $len = strlen($opts['original']);
    if (substr($code, $off, $len) !== $opts['original']) {
        refuse(sprintf(
            'source at %s:%d:%d is not byte-identical to --original',
            $rel, $match['start_line'], $match['start_col']
        ));
    }

    $mutatedCode = substr_replace($code, $opts['mutated'], $off, $len);
    $outAbs = resolve_path($root, $opts['out']);
    $dir = dirname($outAbs);
    if (!is_dir($dir) && !@mkdir($dir, 0777, true) && !is_dir($dir)) {
        fwrite(STDERR, "cannot create output directory {$dir}\n");
        exit(3);
    }
    if (file_put_contents($outAbs, $mutatedCode) === false) {
        fwrite(STDERR, "cannot write {$outAbs}\n");
        exit(3);
    }
    fwrite(STDERR, sprintf(
        "applied %s at %s:%d:%d (%d -> %d bytes) -> %s\n",
        $opts['operator'], $rel, $match['start_line'], $match['start_col'],
        strlen($code), strlen($mutatedCode), $outAbs
    ));
    exit(0);
}

/* ------------------------------------------------------------------ *
 * Mode: ENUMERATE
 * ------------------------------------------------------------------ */

if (!$opts['paths']) {
    fwrite(STDERR, "usage: mutate.php --root DIR --path REL [--path REL ...] [--out FILE]\n");
    exit(2);
}

$pv = parser_version($root);
if ($pv === '') {
    // Without the exact parser version the manifest digest is not comparable
    // across images, which is the one property S3.11 asks the manifest to have.
    refuse('cannot determine nikic/php-parser version; the manifest would not be reproducible');
}

$parser = mutation_parser();

$errors = [];
$mutants = [];
$nfiles = 0;
$nInvalid = 0;
$seen = [];

foreach ($opts['paths'] as $rel) {
    foreach (collect_files($root, $rel, $errors) as $abspath) {
        $relpath = ltrim(substr($abspath, strlen($root)), '/');
        if (is_excluded_path($relpath)) {
            continue;
        }
        // Two overlapping --path arguments must not double-count a file: the
        // manifest would then carry the same mutant twice and every rate
        // computed from it would be wrong in a way no digest check catches.
        if (isset($seen[$relpath])) {
            continue;
        }
        $seen[$relpath] = true;

        [$fileMutants, $fileInvalid, $err, $skipped] = process_file(
            $parser, $relpath, $abspath, true, $opts['operator_profile'],
            $opts['parse_only']
        );
        if ($err !== null) {
            $errors[$relpath] = $err;
            continue;
        }
        if ($skipped) {
            continue;
        }
        $nfiles++;
        $nInvalid += $fileInvalid;
        foreach ($fileMutants as $m) {
            $mutants[] = $m;
        }
    }
}

// Files were visited in sorted order per --path, but --path arguments are
// taken in the order given, so a caller that lists paths differently would get
// a different manifest.  Sorting the whole list makes the manifest a function
// of the file set alone.
usort($mutants, function (array $a, array $b): int {
    return [$a['file'], $a['start_line'], $a['start_col'], $a['end_line'], $a['end_col'], $a['operator']]
        <=> [$b['file'], $b['start_line'], $b['start_col'], $b['end_line'], $b['end_col'], $b['operator']];
});
ksort($errors);

$doc = [
    'engine' => ENGINE,
    'engine_version' => ENGINE_VERSION,
    'parser' => $pv,
    'files' => $nfiles,
    // (object) because json_encode renders an EMPTY assoc array as `[]`, not
    // `{}`: a clean run emitted `"errors": []` and readers that treat it as a
    // mapping broke on exactly the good case.
    'errors' => (object) $errors,
    'mutants' => $mutants,
];
if ($opts['parse_only']) {
    unset($doc['mutants']);
}
// Omit zero so optional validity metadata has one canonical representation.
// A v1 manifest is reconstructed from shared rows under the named v1 profile;
// this v2-default envelope itself is not misrepresented as historical bytes.
if ($nInvalid > 0) {
    $doc['n_invalid'] = $nInvalid;
}
if ($opts['record_enumerator_rev']) {
    $doc['enumerator_rev'] = ENUMERATOR_REV;
}
$json = json_encode($doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if ($json === false) {
    fwrite(STDERR, 'json_encode failed: ' . json_last_error_msg() . "\n");
    exit(3);
}
if ($opts['out'] !== null) {
    $outAbs = resolve_path($root, $opts['out']);
    $dir = dirname($outAbs);
    if (!is_dir($dir) && !@mkdir($dir, 0777, true) && !is_dir($dir)) {
        fwrite(STDERR, "cannot create output directory {$dir}\n");
        exit(3);
    }
    if (file_put_contents($outAbs, $json) === false) {
        fwrite(STDERR, "cannot write {$outAbs}\n");
        exit(3);
    }
    fwrite(STDERR, sprintf(
        "%s %d mutants over %d files, %d errors -> %s\n",
        $opts['parse_only'] ? 'parse-only:' : 'enumerated',
        count($mutants), $nfiles, count($errors), $outAbs
    ));
} else {
    echo $json;
}
