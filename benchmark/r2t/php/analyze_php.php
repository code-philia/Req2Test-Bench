<?php
/**
 * Static index of PHP test code, for the requirement-to-test benchmark's
 * closure extractor (SPEC.md S3).
 *
 * Regexes cannot compute a dependency closure over PHP: name resolution
 * depends on `use` aliases, relative namespaces and imported function
 * scope.  This uses nikic/php-parser (already vendored by CoreShop) with
 * the NameResolver visitor, so every class reference this emits is a
 * fully-qualified name that PHP itself would resolve to.
 *
 * Emits ONE JSON document (not JSONL) so the Python side can load it in
 * one read:
 *
 *   {
 *     "root": "/var/www/html",
 *     "files": {
 *        "<relative path>": {
 *           "namespace": "CoreShop\\Behat\\Context\\Domain",
 *           "uses": {"Assert": "Webmozart\\Assert\\Assert", ...},
 *           "classes": [{
 *              "name": "CoreShop\\Behat\\Context\\Domain\\CartContext",
 *              "kind": "class|interface|trait|enum",
 *              "abstract": false,
 *              "extends": [...], "implements": [...], "traits": [...],
 *              "is_context": true,               // implements Behat Context
 *              "constructor": [{"name":"cartContext","type":"...","promoted":true}],
 *              "methods": [{"name":"addProduct","start":42,"end":57,
 *                           "public":true,"static":false,"abstract":false}],
 *              "steps": [{"method":"...","kind":"Given|When|Then",
 *                         "pattern":"/^.../", "line": 42}],
 *              "transforms": [{"method":"...","pattern":"...","line":13,
 *                              "return_type":"...",
 *                              "params":[{"name":"...","type":"..."}]}]
 *           }],
 *           "refs": ["FQCN", ...]      // every class this file references
 *        }
 *     },
 *     "errors": {"<path>": "parse error ..."}
 *   }
 *
 * Usage:
 *   php analyze_php.php --root /var/www/html --path src/CoreShop/Behat \
 *       --path src/CoreShop/Bundle/TestBundle --out /var/www/html/_bench/php_index.json
 */

declare(strict_types=1);

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;

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
$composerLoader = require $autoload;

$opts = ['root' => null, 'paths' => [], 'out' => null];
$argvv = array_slice($argv, 1);
for ($i = 0; $i < count($argvv); $i++) {
    switch ($argvv[$i]) {
        case '--root': $opts['root'] = $argvv[++$i]; break;
        case '--path': $opts['paths'][] = $argvv[++$i]; break;
        case '--out': $opts['out'] = $argvv[++$i]; break;
        default:
            fwrite(STDERR, "unknown argument {$argvv[$i]}\n");
            exit(2);
    }
}
if ($opts['root'] === null || !$opts['paths']) {
    fwrite(STDERR, "usage: analyze_php.php --root DIR --path REL [--path REL ...] [--out FILE]\n");
    exit(2);
}

const BEHAT_CONTEXT = 'Behat\\Behat\\Context\\Context';

/** Collects every fully-qualified class name a file mentions. */
final class RefCollector extends NodeVisitorAbstract
{
    /** @var array<string,true> */
    public array $refs = [];

    public function enterNode(Node $node)
    {
        if ($node instanceof Node\Name\FullyQualified) {
            $this->refs[$node->toString()] = true;
        }
        return null;
    }
}

/**
 * Collects every `$this-><name>` one method body mentions
 * (TARGET_INTERFACES_SPEC section 3.2, T3).
 *
 * The declared type of a collaborator is already in `constructor[]` (a
 * promoted parameter) or `properties[]`; what was missing is WHICH of them
 * a given step method touches.  Without that, a scenario's declared surface
 * is a property of its context class rather than of the scenario.  Dynamic
 * `$this->$name` is deliberately skipped: the name is not statically known.
 */
final class ThisPropCollector extends NodeVisitorAbstract
{
    /** @var array<string,true> */
    public array $props = [];

    public function enterNode(Node $node)
    {
        if ($node instanceof Node\Expr\PropertyFetch
                && $node->var instanceof Node\Expr\Variable
                && $node->var->name === 'this'
                && $node->name instanceof Node\Identifier) {
            $this->props[$node->name->toString()] = true;
        }
        return null;
    }
}

/**
 * Every fully-qualified class name one method BODY references, sorted
 * (TARGET_INTERFACES_SPEC section 3.2, T5): `new X(`, `X::CONST`, static
 * calls, `instanceof`, `catch (X $e)`, closure parameter types, and the
 * `@var X` docblock a CoreShop step puts on a local it fills from a
 * generically typed factory.  The per-method analogue of the file-level
 * `refs` -- and unlike that edge it cannot pick up another method's names.
 */
function body_refs(Node\Stmt\ClassMethod $m): array
{
    if ($m->stmts === null) {
        return [];
    }
    $traverser = new NodeTraverser();
    $collector = new RefCollector();
    $traverser->addVisitor($collector);
    $traverser->traverse($m->stmts);
    $refs = $collector->refs;
    // `@var Type $x` on a statement inside the body: the type is a NAME the
    // resolver never saw, so resolve it by hand against the file's imports.
    foreach ($m->stmts as $stmt) {
        foreach (docblock_var_types($stmt) as $t) {
            $refs[$t] = true;
        }
    }
    $out = array_keys($refs);
    sort($out);
    return $out;
}

/** Fully-qualified `@var` types of one statement's docblock (and nested). */
function docblock_var_types(Node $node): array
{
    $use_map = $GLOBALS['use_map'] ?? [];
    $current_namespace = $GLOBALS['current_namespace'] ?? '';
    $out = [];
    $stack = [$node];
    while ($stack) {
        $n = array_pop($stack);
        $doc = $n->getDocComment();
        if ($doc !== null && preg_match_all('/@var\s+([\\\\\w|?]+)/', $doc->getText(), $mm)) {
            foreach ($mm[1] as $raw) {
                foreach (explode('|', ltrim($raw, '?')) as $part) {
                    $part = trim($part);
                    if ($part === '' || in_array(strtolower($part), ['null', 'string', 'int', 'bool', 'float', 'array', 'mixed', 'object', 'callable', 'iterable', 'self', 'static'], true)) {
                        continue;
                    }
                    if ($part[0] === '\\') {
                        $out[] = ltrim($part, '\\');
                        continue;
                    }
                    $head = explode('\\', $part)[0];
                    if (isset($use_map[$head])) {
                        $out[] = $use_map[$head] . substr($part, strlen($head));
                    } elseif ($current_namespace !== '') {
                        $out[] = $current_namespace . '\\' . $part;
                    } else {
                        $out[] = $part;
                    }
                }
            }
        }
        foreach ($n->getSubNodeNames() as $name) {
            $sub = $n->$name;
            if ($sub instanceof Node) {
                $stack[] = $sub;
            } elseif (is_array($sub)) {
                foreach ($sub as $s) {
                    if ($s instanceof Node) {
                        $stack[] = $s;
                    }
                }
            }
        }
    }
    return $out;
}

/** Collects every `$this-><name>(` method call one method body makes. */
final class ThisCallCollector extends NodeVisitorAbstract
{
    /** @var array<string,true> */
    public array $calls = [];

    public function enterNode(Node $node)
    {
        if ($node instanceof Node\Expr\MethodCall
                && $node->var instanceof Node\Expr\Variable
                && $node->var->name === 'this'
                && $node->name instanceof Node\Identifier) {
            $this->calls[$node->name->toString()] = true;
        }
        return null;
    }
}

/** The same-object methods one method body calls, sorted (spec T6). */
function this_calls(Node\Stmt\ClassMethod $m): array
{
    if ($m->stmts === null) {
        return [];
    }
    $traverser = new NodeTraverser();
    $collector = new ThisCallCollector();
    $traverser->addVisitor($collector);
    $traverser->traverse($m->stmts);
    $out = array_keys($collector->calls);
    sort($out);
    return $out;
}

/** The `$this->` fields one method body actually references, sorted. */
function this_props(Node\Stmt\ClassMethod $m): array
{
    if ($m->stmts === null) {
        return [];              // abstract / interface method: no body
    }
    $traverser = new NodeTraverser();
    $collector = new ThisPropCollector();
    $traverser->addVisitor($collector);
    $traverser->traverse($m->stmts);
    $out = array_keys($collector->props);
    sort($out);
    return $out;
}

/**
 * Docblock annotations Behat understands.  CoreShop uses the docblock
 * style exclusively (`@Given /^regex$/`); PHP-8 attributes (#[Given])
 * are also read here so the extractor keeps working if upstream migrates.
 */
function parse_annotations(?string $doc): array
{
    $steps = [];
    $transforms = [];
    if ($doc === null) {
        return [$steps, $transforms];
    }
    foreach (preg_split('/\R/', $doc) as $line) {
        $line = preg_replace('/^\s*\*\s?/', '', $line);
        if (!preg_match('/^\s*@(Given|When|Then|Transform)\b\s*(.*)$/', $line, $m)) {
            continue;
        }
        $kind = $m[1];
        $pattern = rtrim($m[2]);
        if ($kind === 'Transform') {
            $transforms[] = $pattern;
        } else {
            $steps[] = [$kind, $pattern];
        }
    }
    return [$steps, $transforms];
}

function type_to_strings(?Node $type): array
{
    if ($type === null) {
        return [];
    }
    if ($type instanceof Node\NullableType) {
        return type_to_strings($type->type);
    }
    if ($type instanceof Node\UnionType || $type instanceof Node\IntersectionType) {
        $out = [];
        foreach ($type->types as $t) {
            $out = array_merge($out, type_to_strings($t));
        }
        return $out;
    }
    if ($type instanceof Node\Identifier) {
        return [$type->toString()];
    }
    if ($type instanceof Node\Name) {
        return [$type->toString()];
    }
    return [];
}

$parser = (new ParserFactory())->createForNewestSupportedVersion();

$files = [];
$errors = [];

$root = rtrim($opts['root'], '/');
foreach ($opts['paths'] as $rel) {
    $abs = $root . '/' . trim($rel, '/');
    if (!is_dir($abs)) {
        if (is_file($abs)) {
            $todo = [$abs];
        } else {
            $errors[$rel] = 'not found';
            continue;
        }
    } else {
        $todo = [];
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->isFile() && strtolower($f->getExtension()) === 'php') {
                $todo[] = $f->getPathname();
            }
        }
    }
    sort($todo);

    foreach ($todo as $abspath) {
        $relpath = ltrim(substr($abspath, strlen($root)), '/');
        $code = file_get_contents($abspath);
        try {
            $ast = $parser->parse($code);
        } catch (Throwable $e) {
            $errors[$relpath] = $e->getMessage();
            continue;
        }
        if ($ast === null) {
            $errors[$relpath] = 'parser returned null';
            continue;
        }

        // NameResolver rewrites every Name into a FullyQualified one,
        // which is what makes `refs` trustworthy.
        $traverser = new NodeTraverser();
        $traverser->addVisitor(new NameResolver(null, ['preserveOriginalNames' => false]));
        $refs = new RefCollector();
        $traverser->addVisitor($refs);
        $ast = $traverser->traverse($ast);

        $entry = [
            'namespace' => null,
            'uses' => [],
            'classes' => [],
            'refs' => [],
        ];

        $walk = function (array $nodes, ?string $ns) use (&$walk, &$entry) {
            foreach ($nodes as $node) {
                if ($node instanceof Node\Stmt\Namespace_) {
                    $ns = $node->name ? $node->name->toString() : null;
                    $entry['namespace'] = $ns;
                    $walk($node->stmts, $ns);
                    continue;
                }
                if ($node instanceof Node\Stmt\Use_ || $node instanceof Node\Stmt\GroupUse) {
                    $prefix = $node instanceof Node\Stmt\GroupUse ? $node->prefix->toString() . '\\' : '';
                    foreach ($node->uses as $u) {
                        $fq = $prefix . $u->name->toString();
                        $alias = $u->getAlias()->toString();
                        $entry['uses'][$alias] = $fq;
                    }
                    continue;
                }
                if ($node instanceof Node\Stmt\ClassLike) {
                    $name = $node->name ? $node->name->toString() : null;
                    if ($name === null) {
                        continue;   // anonymous class
                    }
                    $fqcn = $ns ? $ns . '\\' . $name : $name;
                    // For `@var` resolution inside this class's method bodies.
                    $GLOBALS['use_map'] = $entry['uses'];
                    $GLOBALS['current_namespace'] = (string) $ns;

                    $kind = 'class';
                    if ($node instanceof Node\Stmt\Interface_) {
                        $kind = 'interface';
                    } elseif ($node instanceof Node\Stmt\Trait_) {
                        $kind = 'trait';
                    } elseif ($node instanceof Node\Stmt\Enum_) {
                        $kind = 'enum';
                    }

                    $extends = [];
                    if ($node instanceof Node\Stmt\Class_ && $node->extends !== null) {
                        $extends[] = $node->extends->toString();
                    }
                    if ($node instanceof Node\Stmt\Interface_) {
                        foreach ($node->extends as $e) {
                            $extends[] = $e->toString();
                        }
                    }
                    $implements = [];
                    if ($node instanceof Node\Stmt\Class_) {
                        foreach ($node->implements as $i) {
                            $implements[] = $i->toString();
                        }
                    }
                    if ($node instanceof Node\Stmt\Enum_) {
                        foreach ($node->implements as $i) {
                            $implements[] = $i->toString();
                        }
                    }
                    $traits = [];
                    foreach ($node->stmts as $st) {
                        if ($st instanceof Node\Stmt\TraitUse) {
                            foreach ($st->traits as $t) {
                                $traits[] = $t->toString();
                            }
                        }
                    }

                    $steps = [];
                    $transforms = [];
                    $ctor = [];
                    $methods = [];
                    $properties = [];
                    foreach ($node->stmts as $st) {
                        if ($st instanceof Node\Stmt\Property) {
                            // Declared (non-promoted) fields, with their
                            // declared types, so a `$this->x` reference in a
                            // step method resolves whether `x` was promoted
                            // in the constructor or declared on the class.
                            foreach ($st->props as $pp) {
                                $properties[] = [
                                    'name' => $pp->name->toString(),
                                    'types' => type_to_strings($st->type),
                                    'static' => $st->isStatic(),
                                ];
                            }
                            continue;
                        }
                        if (!$st instanceof Node\Stmt\ClassMethod) {
                            continue;
                        }
                        $mname = $st->name->toString();
                        // Every method, annotated or not.  `steps` and
                        // `transforms` below record only the Behat-annotated
                        // ones, so there was no way to ask which method a
                        // given production line belongs to — which is what
                        // an API-call comparison between two solutions needs.
                        // Spans come from the node itself: `end` is the
                        // method's closing brace, so an abstract or interface
                        // method is a one-or-two-line span, not a zero-length
                        // one.
                        $surfaceParams = [];
                        foreach ($st->params as $p) {
                            $surfaceParams[] = [
                                'name' => $p->var instanceof Node\Expr\Variable && is_string($p->var->name)
                                    ? $p->var->name : null,
                                'types' => type_to_strings($p->type),
                            ];
                        }
                        $methods[] = [
                            'name' => $mname,
                            'start' => $st->getStartLine(),
                            'end' => $st->getEndLine(),
                            'public' => $st->isPublic(),
                            'static' => $st->isStatic(),
                            'abstract' => $st->isAbstract(),
                            // The method's own declared surface (TARGET_INTERFACES_SPEC
                            // section 3.2): what a step that delegates here inherits.
                            'params' => $surfaceParams,
                            'return_types' => type_to_strings($st->getReturnType()),
                            'this_props' => this_props($st),
                            'body_refs' => body_refs($st),
                            'this_calls' => this_calls($st),
                        ];
                        if (strtolower($mname) === '__construct') {
                            foreach ($st->params as $p) {
                                $ctor[] = [
                                    'name' => $p->var instanceof Node\Expr\Variable && is_string($p->var->name)
                                        ? $p->var->name : null,
                                    'types' => type_to_strings($p->type),
                                    'promoted' => $p->flags !== 0,
                                    'has_default' => $p->default !== null,
                                    'variadic' => $p->variadic,
                                ];
                            }
                        }
                        $doc = $st->getDocComment();
                        [$s, $t] = parse_annotations($doc ? $doc->getText() : null);
                        // PHP-8 attribute form, kept for forward compatibility.
                        foreach ($st->attrGroups as $group) {
                            foreach ($group->attrs as $attr) {
                                $an = $attr->name->toString();
                                $short = substr($an, (int) strrpos($an, '\\') + 1);
                                if (in_array($short, ['Given', 'When', 'Then', 'Transform'], true)) {
                                    $arg = null;
                                    if (isset($attr->args[0]) && $attr->args[0]->value instanceof Node\Scalar\String_) {
                                        $arg = $attr->args[0]->value->value;
                                    }
                                    if ($short === 'Transform') {
                                        $t[] = (string) $arg;
                                    } else {
                                        $s[] = [$short, (string) $arg];
                                    }
                                }
                            }
                        }
                        $params = [];
                        foreach ($st->params as $p) {
                            $params[] = [
                                'name' => $p->var instanceof Node\Expr\Variable && is_string($p->var->name)
                                    ? $p->var->name : null,
                                'types' => type_to_strings($p->type),
                            ];
                        }
                        $returns = type_to_strings($st->getReturnType());
                        $fields = this_props($st);
                        $bodyRefs = body_refs($st);
                        $thisCalls = this_calls($st);
                        foreach ($s as [$k, $pattern]) {
                            $steps[] = [
                                'method' => $mname,
                                'kind' => $k,
                                'pattern' => $pattern,
                                'line' => $st->getStartLine(),
                                'params' => $params,
                                'return_types' => $returns,
                                'this_props' => $fields,
                                'body_refs' => $bodyRefs,
                                'this_calls' => $thisCalls,
                            ];
                        }
                        foreach ($t as $pattern) {
                            $transforms[] = [
                                'method' => $mname,
                                'pattern' => $pattern,
                                'line' => $st->getStartLine(),
                                'params' => $params,
                                'return_types' => $returns,
                                'this_props' => $fields,
                                'body_refs' => $bodyRefs,
                                'this_calls' => $thisCalls,
                            ];
                        }
                    }

                    $entry['classes'][] = [
                        'name' => $fqcn,
                        'kind' => $kind,
                        'abstract' => $node instanceof Node\Stmt\Class_ ? $node->isAbstract() : false,
                        'extends' => $extends,
                        'implements' => $implements,
                        'traits' => $traits,
                        'is_context' => in_array(BEHAT_CONTEXT, $implements, true),
                        'constructor' => $ctor,
                        'properties' => $properties,
                        'methods' => $methods,
                        'steps' => $steps,
                        'transforms' => $transforms,
                        'line' => $node->getStartLine(),
                    ];
                    continue;
                }
                // Anything else: recurse into nested statement lists if any.
                if (property_exists($node, 'stmts') && is_array($node->stmts)) {
                    $walk($node->stmts, $ns);
                }
            }
        };
        $walk($ast, null);

        $entry['refs'] = array_values(array_keys($refs->refs));
        sort($entry['refs']);
        $files[$relpath] = $entry;
    }
}

// Context implementation is inherited. A submitted child often extends a
// retained parent outside --path; ask Composer where that parent lives, then
// parse its declaration without autoloading/executing the parent or child.
// Ancestor metadata is private to this check, never added to the emitted files.
$parentTypes = [];
foreach ($files as $entry) {
    foreach ($entry['classes'] as $class) {
        $parentTypes[$class['name']] = array_merge($class['extends'], $class['implements']);
    }
}
$contextTypes = [];
$readParentFiles = [];
$finder = new \PhpParser\NodeFinder();
$isContext = function (string $name) use (&$isContext, &$parentTypes, &$contextTypes,
                                         &$readParentFiles, $finder, $parser, $composerLoader): bool {
    if ($name === BEHAT_CONTEXT) {
        return true;
    }
    if (array_key_exists($name, $contextTypes)) {
        return $contextTypes[$name];
    }
    $contextTypes[$name] = false;
    if (!array_key_exists($name, $parentTypes)) {
        $parentTypes[$name] = [];
        $path = $composerLoader->findFile($name);
        if ($path !== false && !isset($readParentFiles[$path])) {
            $readParentFiles[$path] = true;
            $ast = $parser->parse(file_get_contents($path));
            $resolver = new NodeTraverser();
            $resolver->addVisitor(new NameResolver());
            $ast = $resolver->traverse($ast ?? []);
            foreach ($finder->findInstanceOf($ast, Node\Stmt\ClassLike::class) as $parent) {
                if ($parent->name === null) {
                    continue;
                }
                $fqcn = isset($parent->namespacedName)
                    ? $parent->namespacedName->toString() : $parent->name->toString();
                $edges = [];
                if ($parent instanceof Node\Stmt\Class_ && $parent->extends !== null) {
                    $edges[] = $parent->extends->toString();
                } elseif ($parent instanceof Node\Stmt\Interface_) {
                    foreach ($parent->extends as $interface) {
                        $edges[] = $interface->toString();
                    }
                }
                if ($parent instanceof Node\Stmt\Class_ || $parent instanceof Node\Stmt\Enum_) {
                    foreach ($parent->implements as $interface) {
                        $edges[] = $interface->toString();
                    }
                }
                $parentTypes[$fqcn] = $edges;
            }
        }
    }
    foreach ($parentTypes[$name] as $parent) {
        if ($isContext($parent)) {
            return $contextTypes[$name] = true;
        }
    }
    return false;
};
foreach ($files as &$entry) {
    foreach ($entry['classes'] as &$class) {
        if ($class['kind'] === 'class') {
            $class['is_context'] = $isContext($class['name']);
        }
    }
    unset($class);
}
unset($entry);

// Cast because json_encode renders an EMPTY assoc array as `[]`, not `{}`:
// a run in which every input file failed to parse emitted `"files": []`, and
// every reader that treats it as a mapping broke on that one case.
$doc = ['root' => $root, 'files' => (object) $files, 'errors' => (object) $errors];
$json = json_encode($doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if ($json === false) {
    fwrite(STDERR, 'json_encode failed: ' . json_last_error_msg() . "\n");
    exit(3);
}
if ($opts['out'] !== null) {
    file_put_contents($opts['out'], $json);
    fwrite(STDERR, sprintf("indexed %d files, %d errors -> %s\n", count($files), count($errors), $opts['out']));
} else {
    echo $json;
}
