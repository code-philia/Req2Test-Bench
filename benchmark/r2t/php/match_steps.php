<?php
/**
 * Step -> step-definition matching, done by BEHAT'S OWN matcher.
 *
 * Re-implementing Behat's pattern matching in Python would be a second
 * source of truth: CoreShop mixes regex patterns (`@Given /^…$/`, 973 of
 * them) with turnip patterns (`@Given I am logged in as :email`, 204),
 * and turnip's transformation to a regex is a four-step rewrite whose
 * PCRE output Python's `re` does not always accept.  So the matching
 * runs here, inside the container, against the installed
 * behat/behat — the same PatternTransformer, the same policies in the
 * same priority order (regex 60 before turnip 50), the same preg_match.
 *
 * Behat matches a step against EVERY definition regardless of its
 * Given/When/Then keyword (RepositorySearchEngine::searchDefinition
 * never consults the type) and treats two matching definitions as an
 * AmbiguousMatchException, so both facts are reproduced here: no keyword
 * filter, and every match is returned rather than the first.
 *
 * Usage:
 *   php match_steps.php --index php_index.json --steps steps.json --out matches.json
 *
 * steps.json = {"steps": ["step text", ...], "extra_args": ["...", ...]}
 * matches.json = {
 *   "steps":      {"<text>": [{file,class,method,kind,pattern,captures:[…]}]},
 *   "transforms": {"<arg>":  [{file,class,method,pattern}]},
 *   "regex_errors": {"<pattern>": "message"}
 * }
 */

declare(strict_types=1);

use Behat\Behat\Definition\Pattern\PatternTransformer;
use Behat\Behat\Definition\Pattern\Policy\RegexPatternPolicy;
use Behat\Behat\Definition\Pattern\Policy\TurnipPatternPolicy;

$autoload = null;
foreach ([__DIR__ . '/../../../vendor/autoload.php', '/var/www/html/vendor/autoload.php'] as $cand) {
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

$opts = ['index' => null, 'steps' => null, 'out' => null];
$argvv = array_slice($argv, 1);
for ($i = 0; $i < count($argvv); $i++) {
    switch ($argvv[$i]) {
        case '--index': $opts['index'] = $argvv[++$i]; break;
        case '--steps': $opts['steps'] = $argvv[++$i]; break;
        case '--out':   $opts['out'] = $argvv[++$i]; break;
        default:
            fwrite(STDERR, "unknown argument {$argvv[$i]}\n");
            exit(2);
    }
}
foreach (['index', 'steps'] as $k) {
    if ($opts[$k] === null || !is_file($opts[$k])) {
        fwrite(STDERR, "--$k must point at an existing file\n");
        exit(2);
    }
}

$index = json_decode((string) file_get_contents($opts['index']), true, 512, JSON_THROW_ON_ERROR);
$input = json_decode((string) file_get_contents($opts['steps']), true, 512, JSON_THROW_ON_ERROR);

$transformer = new PatternTransformer();
// Behat sorts pattern policies by descending priority: regex (60) is
// tried before turnip (50).  Turnip's supportsPattern() always returns
// true, so getting this order wrong would route every regex pattern
// through the turnip rewriter.
$transformer->registerPatternPolicy(new RegexPatternPolicy());
$transformer->registerPatternPolicy(new TurnipPatternPolicy());

$stepDefs = [];
$transformDefs = [];
foreach ($index['files'] as $path => $finfo) {
    foreach ($finfo['classes'] as $c) {
        foreach ($c['steps'] as $s) {
            $stepDefs[] = [
                'file' => $path, 'class' => $c['name'], 'method' => $s['method'],
                'kind' => $s['kind'], 'pattern' => $s['pattern'], 'line' => $s['line'],
            ];
        }
        foreach ($c['transforms'] as $t) {
            $transformDefs[] = [
                'file' => $path, 'class' => $c['name'], 'method' => $t['method'],
                'pattern' => $t['pattern'], 'line' => $t['line'],
            ];
        }
    }
}

$regexErrors = [];

/** @return string|null the compiled regex, or null when the pattern is unusable */
function compile(PatternTransformer $transformer, string $pattern, array &$regexErrors): ?string
{
    static $cache = [];
    if (array_key_exists($pattern, $cache)) {
        return $cache[$pattern];
    }
    try {
        $regex = $transformer->transformPatternToRegex($pattern);
    } catch (Throwable $e) {
        $regexErrors[$pattern] = $e->getMessage();
        return $cache[$pattern] = null;
    }
    return $cache[$pattern] = $regex;
}

$stepsOut = [];
$argsToProbe = [];
foreach (array_unique($input['steps'] ?? []) as $text) {
    $matches = [];
    foreach ($stepDefs as $def) {
        $regex = compile($transformer, $def['pattern'], $regexErrors);
        if ($regex === null) {
            continue;
        }
        $m = [];
        if (@preg_match($regex, $text, $m) !== 1) {
            continue;
        }
        // Behat passes capture groups (index >= 1) as the step arguments;
        // named groups appear twice in $m, so key on integer offsets.
        $captures = [];
        foreach ($m as $k => $v) {
            if (is_int($k) && $k > 0) {
                $captures[] = $v;
            }
        }
        foreach ($captures as $c) {
            if (is_string($c)) {
                $argsToProbe[$c] = true;
            }
        }
        $matches[] = $def + ['captures' => $captures];
    }
    $stepsOut[$text] = $matches;
}

foreach ($input['extra_args'] ?? [] as $a) {
    $argsToProbe[(string) $a] = true;
}

$transformsOut = [];
foreach (array_keys($argsToProbe) as $arg) {
    $hits = [];
    foreach ($transformDefs as $def) {
        $regex = compile($transformer, $def['pattern'], $regexErrors);
        if ($regex === null) {
            continue;
        }
        if (@preg_match($regex, (string) $arg) === 1) {
            $hits[] = $def;
        }
    }
    if ($hits) {
        $transformsOut[(string) $arg] = $hits;
    }
}

$doc = [
    'n_step_definitions' => count($stepDefs),
    'n_transform_definitions' => count($transformDefs),
    'steps' => $stepsOut,
    'transforms' => $transformsOut,
    'regex_errors' => $regexErrors,
];
$json = json_encode($doc, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
if ($json === false) {
    fwrite(STDERR, 'json_encode failed: ' . json_last_error_msg() . "\n");
    exit(3);
}
if ($opts['out'] !== null) {
    file_put_contents($opts['out'], $json);
    fwrite(STDERR, sprintf("matched %d step texts against %d definitions (%d regex errors) -> %s\n",
        count($stepsOut), count($stepDefs), count($regexErrors), $opts['out']));
} else {
    echo $json;
}
