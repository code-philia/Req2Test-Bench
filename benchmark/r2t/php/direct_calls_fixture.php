<?php
/**
 * In-container fixture for the PHP direct-invocation collector
 * (API_DIRECT_INVOCATION_SPEC §8, CoreShop operator gate).
 *
 * Run inside a provisioned CoreShop worker under `XDEBUG_MODE=trace` (or
 * `coverage,trace`), with the workspace root and, optionally, the pinned
 * production index as arguments:
 *
 *     XDEBUG_MODE=trace php /tmp/direct_calls_fixture.php /var/www/html /tmp/php_prod_index.json
 *
 * The recorder class is loaded from
 * `<root>/src/CoreShop/Behat/Bench/BenchRecorderHook.php` through the
 * workspace's Composer autoloader, so the class under test is the installed
 * one.  Nothing is written under the workspace: the synthetic production and
 * test files live under a temporary root of their own, which is the `$root`
 * the reducer is given for them.
 *
 * Four questions are decided, each by a real xdebug trace reduced by the
 * recorder's own `directCallsFromTrace`:
 *
 *  1. Reflection identity — a trait method, an inherited method and an
 *     attribute-decorated method called on a class resolve to the DECLARING
 *     file, and the attributed method's reflected line is reported beside
 *     the index start so the §2.3 span rule can be read off.  The same is
 *     then asked of three real production methods of the workspace,
 *     against the pinned index passed as the optional second argument.
 *  2. The caller rule — a test context calls production `A`, which calls
 *     production `B`: `A` carries the context file as caller, `B` carries
 *     `A`'s own file, and no tuple credits `B` to the context.
 *  3. The per-step tag (TARGET_INTERFACES_V2_SPEC §4) — a context that
 *     brackets its calls with the recorder's own `stepBegin`/`stepEnd`
 *     markers, as the step hooks do, produces events tagged with the step
 *     index; a call made between steps is tagged `null`, the same call from
 *     two steps is two events, and neither marker is ever itself an event.
 *  4. Generated-class crediting (§3.3, V2-D1(a)) — a class under a
 *     generated root that overrides a first-party method, or implements a
 *     first-party interface's, is credited to that contract method's own
 *     file and line with the generated method named in `generated_callee`;
 *     a generated method with no first-party contract is dropped and
 *     counted.
 *
 * Prints one `[PASS]`/`[FAIL]` line per check and a final JSON line with
 * every measured value; exits 1 if any check failed.
 */

declare(strict_types=1);

$root = $argv[1] ?? getcwd();
$indexPath = $argv[2] ?? null;
$autoload = $root . '/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "no Composer autoloader at $autoload\n");
    exit(2);
}
require $autoload;

use CoreShop\Behat\Bench\BenchRecorderHook;

if (!in_array('trace', (array) xdebug_info('mode'), true)) {
    fwrite(STDERR, "xdebug trace mode is not active; run under XDEBUG_MODE=trace\n");
    exit(2);
}
// The provisioned ini starts a request-scoped trace; the recorder's
// `@BeforeSuite` stops it and prepares the process, so do the same here.
BenchRecorderHook::prepareTracing();

$failures = 0;
$report = [];
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    echo '  [' . ($ok ? 'PASS' : 'FAIL') . '] ' . $name . ($ok || $detail === '' ? '' : ' -- ' . $detail) . "\n";
    if (!$ok) {
        $failures++;
    }
}

// --------------------------------------------------------------- fixture tree
$fx = sys_get_temp_dir() . '/r2t-direct-fixture-' . getmypid();
@mkdir($fx . '/src/Prod', 0777, true);
@mkdir($fx . '/test', 0777, true);
@mkdir($fx . '/vendor', 0777, true);
// One of the recorder's own generated roots, so the credit rule fires on
// this tree exactly as it does on a workspace's `var/classes`.
@mkdir($fx . '/var/classes/Generated', 0777, true);
$files = [
    'src/Prod/FixtureTrait.php' => <<<'PHP'
<?php
namespace R2tFixture\Prod;
trait FixtureTrait
{
    public function traitMethod(): string
    {
        return 'trait';
    }
}
PHP,
    'src/Prod/FixtureParent.php' => <<<'PHP'
<?php
namespace R2tFixture\Prod;
class FixtureParent
{
    public function inheritedMethod(): string
    {
        return 'parent';
    }
}
PHP,
    'src/Prod/FixtureChild.php' => <<<'PHP'
<?php
namespace R2tFixture\Prod;
#[\Attribute]
final class FixtureAttr
{
}
class FixtureChild extends FixtureParent implements \Countable, \IteratorAggregate
{
    use FixtureTrait;

    #[FixtureAttr]
    public function attributedMethod(): string
    {
        return 'attributed';
    }

    public static function staticMethod(): string
    {
        return 'static';
    }

    public function count(): int
    {
        return 3;
    }

    public function getIterator(): \Iterator
    {
        return new \ArrayIterator([1, 2, 3]);
    }

    public function withClosure(): int
    {
        $f = function (): int { return 1; };
        return $f();
    }
}
PHP,
    'src/Prod/A.php' => <<<'PHP'
<?php
namespace R2tFixture\Prod;
class A
{
    public function a(): string
    {
        return (new B())->b();
    }
}
PHP,
    'src/Prod/B.php' => <<<'PHP'
<?php
namespace R2tFixture\Prod;
class B
{
    public function __construct()
    {
    }

    public function b(): string
    {
        return 'b';
    }
}
PHP,
    // The generated-class case, in the shape CoreShop has it: the interface
    // declares the getter, the first-party model class does NOT (Pimcore
    // generates it), and the generated DataObject declares it itself.
    'src/Prod/OrderInterface.php' => <<<'PHP'
<?php
namespace R2tFixture\Prod;
interface OrderInterface
{
    public function getPaymentState(): ?string;
}
PHP,
    'src/Prod/OrderModel.php' => <<<'PHP'
<?php
namespace R2tFixture\Prod;
abstract class OrderModel implements OrderInterface
{
    public function getStore(): string
    {
        return 'store';
    }

    public function getTotal(): int
    {
        return 7;
    }
}
PHP,
    'var/classes/Generated/GeneratedOrder.php' => <<<'PHP'
<?php
namespace R2tFixture\Generated;
class GeneratedOrder extends \R2tFixture\Prod\OrderModel
{
    public function getPaymentState(): ?string
    {
        return 'paid';
    }

    public function getStore(): string
    {
        return 'generated';
    }

    public function getGeneratedOnly(): string
    {
        return 'only here';
    }
}
PHP,
    'vendor/FixtureLib.php' => <<<'PHP'
<?php
namespace R2tFixture\Vendor;
use R2tFixture\Prod\B;
class FixtureLib
{
    public function l(): string
    {
        return (new B())->b();
    }
}
PHP,
    'test/FixtureContext.php' => <<<'PHP'
<?php
namespace R2tFixture\Test;
use R2tFixture\Prod\A;
use R2tFixture\Prod\FixtureChild;
final class FixtureContext
{
    public function run(): array
    {
        $c = new FixtureChild();
        $out = [];
        $out[] = $c->traitMethod();
        $out[] = $c->inheritedMethod();
        $out[] = $c->attributedMethod();
        $out[] = FixtureChild::staticMethod();
        $out[] = count($c);
        foreach ($c as $v) {
            $out[] = $v;
        }
        $out[] = $c->withClosure();
        $out[] = (new A())->a();
        $out[] = (new \R2tFixture\Vendor\FixtureLib())->l();
        return $out;
    }

    /**
     * One scenario's worth of steps, bracketed the way the recorder's own
     * step hooks bracket them: three steps (a Background step, a When and a
     * Then) and one call made between steps.
     */
    public function runSteps(): array
    {
        $g = new \R2tFixture\Generated\GeneratedOrder();
        $out = [];
        \CoreShop\Behat\Bench\BenchRecorderHook::stepBegin();
        $out[] = $g->getTotal();
        \CoreShop\Behat\Bench\BenchRecorderHook::stepEnd();
        \CoreShop\Behat\Bench\BenchRecorderHook::stepBegin();
        $out[] = (new A())->a();
        $out[] = $g->getTotal();
        \CoreShop\Behat\Bench\BenchRecorderHook::stepEnd();
        \CoreShop\Behat\Bench\BenchRecorderHook::stepBegin();
        $out[] = $g->getPaymentState();
        $out[] = $g->getStore();
        $out[] = $g->getGeneratedOnly();
        \CoreShop\Behat\Bench\BenchRecorderHook::stepEnd();
        $out[] = $g->getTotal();
        return $out;
    }
}
PHP,
];
foreach ($files as $rel => $code) {
    file_put_contents($fx . '/' . $rel, $code . "\n");
}
foreach (array_keys($files) as $rel) {
    require $fx . '/' . $rel;
}
$ctx = new R2tFixture\Test\FixtureContext();

// ------------------------------------------------------------- synthetic trace
// The recorder filters the trace to call sites under <cwd>/src/; this
// fixture's trees live elsewhere, so it names its own: the synthetic src/
// and test/ (not its vendor/).
xdebug_set_filter(XDEBUG_FILTER_TRACING, XDEBUG_PATH_INCLUDE, [$fx . '/src/', $fx . '/test/']);
$traceBase = $fx . '/trace';
$trace = xdebug_start_trace($traceBase, XDEBUG_TRACE_COMPUTERIZED);
check('a per-scenario trace starts once the request-scoped one is stopped', is_string($trace), var_export($trace, true));
$ctx->run();
xdebug_stop_trace();

$diag = [];
$calls = BenchRecorderHook::directCallsFromTrace($trace, $fx, $diag);
$report['synthetic'] = ['calls' => $calls, 'diag' => $diag];
$byName = [];
foreach ($calls as $c) {
    $byName[$c['callee']][] = $c;
}
$one = static function (string $name) use ($byName): ?array {
    return isset($byName[$name]) && count($byName[$name]) === 1 ? $byName[$name][0] : null;
};

// 1. reflection identity, on the synthetic tree
$t = $one('R2tFixture\Prod\FixtureChild->traitMethod');
check('a trait method called on the using class resolves to the TRAIT file',
      $t !== null && $t['callee_file'] === 'src/Prod/FixtureTrait.php' && $t['callee_line'] === 5,
      json_encode($t));
$p = $one('R2tFixture\Prod\FixtureParent->inheritedMethod');
check('an inherited method is traced under, and resolves to, the PARENT file',
      $p !== null && $p['callee_file'] === 'src/Prod/FixtureParent.php' && $p['callee_line'] === 5,
      json_encode($p ?? $byName));
$a = $one('R2tFixture\Prod\FixtureChild->attributedMethod');
// The attribute sits on line 11 of FixtureChild.php, the `function` line is 12.
$childSrc = file($fx . '/src/Prod/FixtureChild.php');
$attrLine = 1 + array_search("    #[FixtureAttr]\n", $childSrc, true);
check('an attribute-decorated method resolves to its own file',
      $a !== null && $a['callee_file'] === 'src/Prod/FixtureChild.php', json_encode($a));
$report['attributed_reflected_line'] = $a['callee_line'] ?? null;
$report['attributed_attribute_line'] = $attrLine;
$report['attributed_function_line'] = $attrLine + 1;
check('...and its reflected line is the `function` line, one below the `#[...]` line (reported, not required)',
      $a !== null && $a['callee_line'] === $attrLine + 1, json_encode(['attr_line' => $attrLine] + ($a ?? [])));
$s = $one('R2tFixture\Prod\FixtureChild::staticMethod');
check('a static call is a `Class::method` name and resolves like any other', $s !== null, json_encode($byName));
$cnt = $one('R2tFixture\Prod\FixtureChild->count');
check('count() on a Countable credits the method with the calling file as caller',
      $cnt !== null && $cnt['caller_file'] === 'test/FixtureContext.php', json_encode($cnt));
$it = $one('R2tFixture\Prod\FixtureChild->getIterator');
check('foreach over an IteratorAggregate credits getIterator with the calling file as caller',
      $it !== null && $it['caller_file'] === 'test/FixtureContext.php', json_encode($it));
$closureTuples = array_filter($calls, static fn ($c) => str_contains($c['callee'], '{closure'));
check('a closure is never a tuple', $closureTuples === [], json_encode(array_values($closureTuples)));
check('...and its class-scoped trace name is counted as resolving to no method',
      ($diag['unresolved_names'] ?? 0) >= 1
      && array_filter(array_keys($diag['unresolved_top'] ?? []), static fn ($n) => str_contains($n, '{closure')) !== [],
      json_encode($diag['unresolved_top'] ?? null));
// Five keys since the per-step tag: this trace runs no step markers at all,
// so every call in it was made outside a step and carries a null one.
check('every tuple carries a repo-relative path, an int line, and the five keys in order',
      $calls !== [] && array_reduce($calls, static fn ($ok, $c) => $ok
          && array_keys($c) === ['callee_file', 'callee_line', 'callee', 'caller_file', 'step']
          && !str_starts_with($c['callee_file'], '/') && !str_starts_with($c['caller_file'], '/')
          && is_int($c['callee_line']) && $c['step'] === null, true),
      json_encode($calls[0] ?? null));
check('a trace with no step markers reports none',
      ($diag['step_markers'] ?? null) === 0, json_encode($diag['step_markers'] ?? null));
$sorted = $calls;
usort($sorted, static fn ($x, $y) => [$x['callee_file'], $x['callee_line'], $x['callee'], $x['caller_file']]
    <=> [$y['callee_file'], $y['callee_line'], $y['callee'], $y['caller_file']]);
check('the list is sorted by (callee_file, callee_line, callee, caller_file)', $sorted === $calls);
check('the internal ArrayIterator constructor is not a tuple and not an unresolved name',
      !isset($byName['ArrayIterator->__construct'])
      && !isset($diag['unresolved_top']['ArrayIterator->__construct']));

// 2. the caller rule
$aa = $one('R2tFixture\Prod\A->a');
$bb = $byName['R2tFixture\Prod\B->b'] ?? [];
check('A, called by the context, carries the context file as caller_file',
      $aa !== null && $aa['caller_file'] === 'test/FixtureContext.php', json_encode($aa));
check('B, called only by A, carries A\'s own file as caller_file',
      count($bb) === 1 && $bb[0]['caller_file'] === 'src/Prod/A.php', json_encode($bb));
check('no tuple credits B to the context',
      array_filter($bb, static fn ($c) => $c['caller_file'] === 'test/FixtureContext.php') === []);
$bc = $one('R2tFixture\Prod\B->__construct');
check('B\'s constructor, called by A, likewise carries A as caller',
      $bc !== null && $bc['caller_file'] === 'src/Prod/A.php', json_encode($bc));
$lib = $one('R2tFixture\Vendor\FixtureLib->l');
check('a vendor method called by the context is traced (src/ call site) and then fenced as a vendor callee',
      $lib === null && ($diag['fenced_events']['vendor'] ?? 0) >= 1, json_encode($diag['fenced_events'] ?? null));
check('B called from a VENDOR call site is not in the trace at all (the call-site filter), so B\'s only tuple is A\'s',
      count($bb) === 1);

// ------------------------------------------- 3 + 4: steps, and generated
// A second synthetic trace over the same tree, this one bracketed by the
// markers the step hooks call.  Nothing about the markers is special-cased
// by the fixture: they are ordinary calls made from the context file, and
// the reducer is the only thing that knows what they mean.
xdebug_set_filter(XDEBUG_FILTER_TRACING, XDEBUG_PATH_INCLUDE, [$fx . '/src/', $fx . '/test/']);
$trace3 = xdebug_start_trace($fx . '/trace3', XDEBUG_TRACE_COMPUTERIZED);
$ctx->runSteps();
xdebug_stop_trace();
$diag3 = [];
$calls3 = BenchRecorderHook::directCallsFromTrace($trace3, $fx, $diag3);
$report['stepped'] = ['calls' => $calls3, 'diag' => $diag3];
$named = static function (string $name) use ($calls3): array {
    return array_values(array_filter($calls3, static fn ($c) => $c['callee'] === $name));
};

check('the three step markers are counted, and neither marker is ever an event',
      ($diag3['step_markers'] ?? null) === 3
      && $named('CoreShop\Behat\Bench\BenchRecorderHook::stepBegin') === []
      && $named('CoreShop\Behat\Bench\BenchRecorderHook::stepEnd') === []
      && !isset($diag3['unresolved_top']['CoreShop\Behat\Bench\BenchRecorderHook::stepBegin']),
      json_encode([$diag3['step_markers'] ?? null, $diag3['unresolved_top'] ?? null]));
$totals = $named('R2tFixture\Prod\OrderModel->getTotal');
check('the same call from two steps, and once outside every step, is three '
      . 'events differing only in `step`, null first',
      array_column($totals, 'step') === [null, 0, 1]
      && count(array_unique(array_column($totals, 'caller_file'))) === 1,
      json_encode($totals));
$deep = $named('R2tFixture\Prod\B->b');
check('a call made deeper in the stack carries the step the test was in, '
      . 'not a step of its own',
      count($deep) === 1 && $deep[0]['step'] === 1
      && $deep[0]['caller_file'] === 'src/Prod/A.php', json_encode($deep));
$pay = $named('R2tFixture\Prod\OrderInterface->getPaymentState');
$payLine = (new ReflectionMethod('R2tFixture\Prod\OrderInterface', 'getPaymentState'))->getStartLine();
check('a generated method that implements a first-party INTERFACE method is '
      . 'credited to the interface, at the interface\'s own file and line',
      count($pay) === 1 && $pay[0]['callee_file'] === 'src/Prod/OrderInterface.php'
      && $pay[0]['callee_line'] === $payLine
      && $pay[0]['generated_callee'] === 'R2tFixture\Generated\GeneratedOrder->getPaymentState'
      && $pay[0]['caller_file'] === 'test/FixtureContext.php' && $pay[0]['step'] === 2
      && array_keys($pay[0]) === ['callee_file', 'callee_line', 'callee', 'caller_file',
                                  'generated_callee', 'step'],
      json_encode($pay));
$store = $named('R2tFixture\Prod\OrderModel->getStore');
$storeLine = (new ReflectionMethod('R2tFixture\Prod\OrderModel', 'getStore'))->getStartLine();
check('a generated OVERRIDE is credited to the nearest first-party '
      . 'declaration, the parent class, not to an interface',
      count($store) === 1 && $store[0]['callee_file'] === 'src/Prod/OrderModel.php'
      && $store[0]['callee_line'] === $storeLine && $store[0]['step'] === 2
      && $store[0]['generated_callee'] === 'R2tFixture\Generated\GeneratedOrder->getStore',
      json_encode($store));
check('a generated method with no first-party contract is dropped, counted '
      . 'as uncredited, and still counted by the production fence',
      $named('R2tFixture\Generated\GeneratedOrder->getGeneratedOnly') === []
      && ($diag3['generated_uncredited']['R2tFixture\Generated\GeneratedOrder->getGeneratedOnly'] ?? 0) === 1
      && ($diag3['fenced_events']['var/classes'] ?? 0) === 1,
      json_encode([$diag3['generated_uncredited'] ?? null, $diag3['fenced_events'] ?? null]));
check('...and the two credited calls are counted as credited, by name, and '
      . 'not as fenced',
      ($diag3['generated_credited'] ?? []) === [
          'R2tFixture\Generated\GeneratedOrder->getPaymentState' => 1,
          'R2tFixture\Generated\GeneratedOrder->getStore' => 1],
      json_encode($diag3['generated_credited'] ?? null));
check('an inherited first-party method needs no credit: it is traced under '
      . 'its declaring class and kept as an ordinary event',
      count($totals) === 3 && array_reduce($totals, static fn ($ok, $c) => $ok
          && !array_key_exists('generated_callee', $c), true), json_encode($totals));

// ------------------------------------------------------------ real production
$real = [];
$realChecks = [
    // [class, method, why]
    ['CoreShop\Component\Pimcore\PriorityQueue', 'getIterator', 'attribute-decorated (#[ReturnTypeWillChange]); executed by 81 of 100 gold items'],
    ['CoreShop\Component\Pimcore\SplPriorityQueue', 'insert', 'attribute-decorated; executed by 87 of 100 gold items'],
    ['CoreShop\Component\Store\Model\Store', 'setCurrency', 'trait method (CurrencyAwareTrait) flattened into Store'],
    ['CoreShop\Component\Core\Cart\Rule\Condition\CarriersConditionChecker', 'isValid', 'inherited from the abstract Order\Cart\Rule\Condition\AbstractConditionChecker'],
];
$index = null;
if ($indexPath !== null && is_file($indexPath)) {
    $index = json_decode((string) file_get_contents($indexPath), true);
}
foreach ($realChecks as [$class, $method, $why]) {
    $row = ['class' => $class, 'method' => $method, 'why' => $why];
    try {
        $m = new ReflectionMethod($class, $method);
        $row['reflected_file'] = ltrim(str_replace($root, '', (string) $m->getFileName()), '/');
        $row['reflected_line'] = $m->getStartLine();
        $row['declaring_class'] = $m->getDeclaringClass()->getName();
    } catch (Throwable $e) {
        $row['error'] = $e->getMessage();
    }
    if ($index !== null && isset($row['reflected_file'])) {
        $entry = $index['files'][$row['reflected_file']] ?? null;
        foreach ((array) ($entry['classes'] ?? []) as $cls) {
            foreach ((array) ($cls['methods'] ?? []) as $im) {
                if ($im['name'] === $method) {
                    $row['index_class'] = $cls['name'];
                    $row['index_start'] = $im['start'];
                    $row['index_end'] = $im['end'];
                    $row['index_line_at_start'] = trim((string) (file($root . '/' . $row['reflected_file'])[$im['start'] - 1] ?? ''));
                }
            }
        }
        $inSpan = isset($row['index_start']) && $row['reflected_line'] >= $row['index_start'] && $row['reflected_line'] <= $row['index_end'];
        check("$class::$method reflects into the declaring file and inside the index span for that method ($why)",
              $inSpan, json_encode($row));
    } else {
        check("$class::$method reflects to a file and line ($why)", isset($row['reflected_line']), json_encode($row));
    }
    $real[] = $row;
}
$report['real'] = $real;

// A real trace of the attributed method, reduced against the workspace root:
// the tuple's line is the reflected line, which the §2.3 span rule joins.
$q = new CoreShop\Component\Pimcore\PriorityQueue();
$q->insert('x', 1);
// The call site of the foreach below is this script, so the filter names
// this script's directory for the second trace.
xdebug_set_filter(XDEBUG_FILTER_TRACING, XDEBUG_PATH_INCLUDE, [rtrim(dirname(__FILE__), '/') . '/']);
$trace2 = xdebug_start_trace($fx . '/trace2', XDEBUG_TRACE_COMPUTERIZED);
foreach ($q as $_) {
}
xdebug_stop_trace();
$diag2 = [];
$calls2 = BenchRecorderHook::directCallsFromTrace($trace2, $root, $diag2);
$git = array_values(array_filter($calls2, static fn ($c) => str_ends_with($c['callee'], '->getIterator')
    && $c['callee_file'] === 'src/CoreShop/Component/Pimcore/PriorityQueue.php'));
check('a real foreach over PriorityQueue yields a getIterator tuple in the production file with this script as caller',
      count($git) === 1 && $git[0]['callee_line'] === ($real[0]['reflected_line'] ?? -1),
      json_encode($git));
$report['real_trace'] = ['calls' => $calls2, 'diag' => $diag2];

// ------------------------------------------------------------------ cleanup
foreach (array_keys($files) as $rel) {
    @unlink($fx . '/' . $rel);
}
@unlink($trace);
@unlink($trace2);
@unlink($trace3);
@rmdir($fx . '/src/Prod');
@rmdir($fx . '/src');
@rmdir($fx . '/test');
@rmdir($fx . '/vendor');
@rmdir($fx . '/var/classes/Generated');
@rmdir($fx . '/var/classes');
@rmdir($fx . '/var');
@rmdir($fx);
$report['failures'] = $failures;
echo json_encode($report, JSON_UNESCAPED_SLASHES) . "\n";
exit($failures === 0 ? 0 : 1);
