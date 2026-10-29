<?php
/**
 * Per-run outcome recorder for the requirement-to-test benchmark (SPEC §6).
 *
 * Behat's own formatters answer "did it pass"; the benchmark has to record
 * rather more per run — the per-step results (so a partial pass is
 * distinguishable from an undefined-step run), wall time, and per-scenario
 * line coverage.  Coverage is collected only when BENCH_COVERAGE=1 because
 * it costs roughly 8x the runtime; it is recorded now, though unused in v1,
 * because it is the input any later anti-vacuity metric needs and re-running
 * every item later to get it would be far more expensive than paying for it
 * once (SPEC §6).
 *
 * Beside the coverage block every record carries `direct_calls`
 * (API_DIRECT_INVOCATION_SPEC §2.4-§2.5): the unique (callee file, callee
 * declaration line, callee name, caller file, step) tuples of every
 * production method activation in the scenario's window, read out of an
 * xdebug function trace that brackets the scenario exactly as the coverage
 * collector does.
 * The trace rides on the same `XDEBUG_MODE` the harness already sets for a
 * coverage invocation (`coverage,trace`), is written under the container's
 * temporary directory — outside every substrate root, for the reason the
 * harness keeps its own pid file there — and is deleted once reduced.  The
 * field is `null` when no trace ran, `[]` when one ran and saw no production
 * activation; the removable test, the public test and the index join are
 * applied at scoring, on the host, never here.  The trace is filtered to
 * calls made from files under `src/`, which every direct call is.
 *
 * Every event names the STEP that made it (TARGET_INTERFACES_V2_SPEC §4):
 * `step` is the 0-based index of the executing step in this record's
 * `steps` list -- the Background's steps first, then the scenario's own,
 * which is the order `@AfterStep` appends them in -- or `null` for a call
 * made outside any step (a hook, glue construction).  The step is part of
 * the event's identity, so the same call from two steps is two events; the
 * API scorer collapses them again.  Which steps are actions or checks is
 * decided later, in Python, from the feature text: this recorder decides
 * nothing about that.  The index is read out of the trace itself, from the
 * `stepBegin`/`stepEnd` markers the step hooks call.
 *
 * A call into a class the framework GENERATES (Pimcore's DataObjects under
 * `var/classes`, a Doctrine proxy under `var/cache`) is credited to the
 * nearest first-party contract method it implements, and carries the
 * generated method's own name in `generated_callee` (§3.3, V2-D1(a)).
 * Without that the call is invisible: its declaring file is under no
 * production root, and the pinned index -- built over the project's own
 * source -- knows nothing about it.
 *
 * `direct_calls_schema` names the event shape this recorder wrote, because
 * the harness version cannot: a new harness can execute an older seed whose
 * recorder is substrate.  It is null exactly when `direct_calls` is.
 *
 * This class is HARNESS code that lives inside the repository under test so
 * Composer's `CoreShop\Behat\ -> src/CoreShop/Behat/` PSR-4 rule autoloads
 * it.  It defines no step and no transform, so it can never answer any part
 * of a scenario.
 */

declare(strict_types=1);

namespace CoreShop\Behat\Bench;

use Behat\Behat\Context\Context;
use Behat\Behat\Hook\Scope\AfterScenarioScope;
use Behat\Behat\Hook\Scope\AfterStepScope;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use Behat\Behat\Hook\Scope\BeforeStepScope;
use SebastianBergmann\CodeCoverage\CodeCoverage;
use SebastianBergmann\CodeCoverage\Driver\Selector;
use SebastianBergmann\CodeCoverage\Filter;

final class BenchRecorderHook implements Context
{
    /**
     * The shape of the events in `direct_calls`, recorded beside them.
     *
     * `/1` is the first PHP marker at all: the per-step tag arrived with it,
     * so a row that carries it carries `step` on every event.
     */
    public const DIRECT_CALLS_SCHEMA = 'r2t.php_direct_calls/1';

    /**
     * Where this project's framework GENERATES product classes, relative to
     * the workspace root.  A callee declared there is credited to the
     * first-party contract method it implements rather than dropped
     * (TARGET_INTERFACES_V2_SPEC §3.3); the literal is CoreShop's, and
     * `repo.recorder_source` rewrites it for a project whose `behat:` block
     * declares other roots.
     *
     * @var list<string>
     */
    private static array $generatedRoots = ['var/classes', 'var/cache'];

    private static ?CodeCoverage $cov = null;
    private static string $root = '';
    private static string $out = '';
    private static array $record = [];
    private static float $scenarioStart = 0.0;
    private static float $stepStart = 0.0;
    private static bool $covRunning = false;

    /** The trace file xdebug reported for the running scenario, or null. */
    private static ?string $traceFile = null;
    private static float $traceStart = 0.0;
    private static int $traceSeq = 0;
    private static bool $traceWarned = false;
    /**
     * `Class->method` name -> [declaring file, start line] or null when the
     * name resolves to no method.  Classes do not change within one Behat
     * process, so a name resolved for one scenario is resolved for all.
     *
     * @var array<string, array{0: string, 1: int}|null>
     */
    private static array $resolved = [];
    /**
     * The same, for a "<root>\0<generated name>" key: the contract method
     * it is credited to as [declaring file, start line, contract name], or
     * null when the generated class has no first-party ancestor declaring
     * that method.
     * Beside `$resolved` and for its reason -- reflection over an ancestry
     * is the expensive half of the reduction, and classes do not change
     * within one Behat process.
     *
     * @var array<string, array{0: string, 1: int, 2: string}|null>
     */
    private static array $credited = [];

    /** @BeforeSuite */
    public static function bootRecorder(): void
    {
        self::$root = (string) getcwd();
        self::$out = getenv('BENCH_RECORD_PATH') ?: (self::$root . '/_bench/run_record.jsonl');
        @mkdir(dirname(self::$out), 0777, true);

        if (getenv('BENCH_COVERAGE') === '1') {
            try {
                $filter = new Filter();
                $filter->includeDirectory(self::$root . '/src');
                self::$cov = new CodeCoverage((new Selector())->forLineCoverage($filter), $filter);
            } catch (\Throwable $e) {
                fwrite(STDERR, '[BenchRecorderHook] coverage unavailable: ' . $e->getMessage() . "\n");
                self::$cov = null;
            }
            self::prepareTracing();
        }
    }

    /**
     * Make the process ready for per-scenario traces, once.
     *
     * Two facts of the provisioned image, measured rather than assumed:
     * its ini sets `xdebug.start_with_request=yes`, so a mode that includes
     * `trace` starts one request-scoped trace at process start and every
     * `xdebug_start_trace()` after that fails with "Function trace already
     * started"; and it sets `xdebug.collect_params=On`, which would write
     * every argument of every call into a trace that only needs names.
     * The harness suppresses the request-scoped trace on its command line
     * (`-d xdebug.start_with_request=no`); should one be running anyway it
     * is stopped here and discarded.  Parameter collection and per-record
     * compression are switched off for this process -- process-local
     * settings; the provisioned ini file is untouched.  The call-site
     * filter is not set here: it costs on every call while armed, so
     * `startTrace` arms it for the scenario window and `stopTrace` removes
     * it.  A container runs one Behat at a time, so a trace file left by a
     * process that never reached `@AfterScenario` (a timeout kill, a fatal)
     * belongs to nobody and is swept here.  The diag file is started afresh
     * for this process before anything is written to it: the first line a
     * process may write is the request trace it had to stop, and that line
     * is what the gate's suppression check reads.
     */
    public static function prepareTracing(): void
    {
        @file_put_contents(self::diagPath(), '');
        if (!function_exists('xdebug_info')) {
            return;
        }
        $modes = (array) @xdebug_info('mode');
        if (!in_array('trace', $modes, true)) {
            return;
        }
        $auto = @xdebug_stop_trace();
        if (is_string($auto) && $auto !== '') {
            $bytes = @filesize($auto);
            @unlink($auto);
            self::diag(['event' => 'request_trace_stopped', 'file' => $auto,
                        'bytes' => $bytes === false ? null : $bytes]);
        }
        if (ini_get('xdebug.collect_params') !== '0') {
            ini_set('xdebug.collect_params', '0');
        }
        // xdebug flushes the trace after every record, so its gzip output is
        // LARGER than the plain text and costs about five times the write
        // time (measured: 9.0 s against 1.7 s for 600k records).
        if (ini_get('xdebug.use_compression') !== '0') {
            ini_set('xdebug.use_compression', '0');
        }
        foreach (glob(sys_get_temp_dir() . '/r2t-direct-[0-9]*') ?: [] as $stale) {
            @unlink($stale);
        }
    }

    /** @BeforeScenario */
    public function startScenario(BeforeScenarioScope $scope): void
    {
        $feature = $scope->getFeature();
        self::$scenarioStart = microtime(true);
        self::$record = [
            'feature_file' => ltrim(str_replace(self::$root, '', (string) $feature->getFile()), '/'),
            'feature_title' => $feature->getTitle(),
            'scenario_title' => $scope->getScenario()->getTitle(),
            'scenario_line' => $scope->getScenario()->getLine(),
            'suite' => $scope->getSuite()->getName(),
            'steps' => [],
            'direct_calls' => null,
        ];
        if (self::$cov !== null) {
            self::$cov->start(self::$record['feature_file'] . ':' . self::$record['scenario_line']);
            self::$covRunning = true;
            self::startTrace();
        }
    }

    /** @BeforeStep */
    public function startStep(BeforeStepScope $scope): void
    {
        self::stepBegin();
        self::$stepStart = microtime(true);
    }

    /**
     * The step boundary, as the trace itself sees it.
     *
     * Empty on purpose: the CALL is the signal.  This file lives under the
     * workspace's trace root, so xdebug's call-site filter records these two
     * activations like any other, and `directCallsFromTrace` reads the k-th
     * `stepBegin` as step k -- the same k `@AfterStep` appends to `steps`,
     * Background steps included.  The alternative, a trace window per step,
     * arms and disarms xdebug's filter on every step and pays for it on
     * every call in between.
     *
     * Public and static because the hook that calls them is neither the
     * only caller (the fixture drives them too) nor an instance the trace
     * can reach.
     */
    public static function stepBegin(): void
    {
    }

    public static function stepEnd(): void
    {
    }

    /**
     * Behat's TestResult codes are 0/10/20/30/99, not 0..4
     * (Testwork\Tester\Result\TestResult).  They are recorded as names because "undefined" versus
     * "failed" is exactly the distinction the SPEC §5 must-fail leg needs:
     * a run where every step is undefined means the removal worked, whereas
     * a failing assertion means the glue ran and disagreed.
     *
     * @AfterStep
     */
    public function stopStep(AfterStepScope $scope): void
    {
        $result = $scope->getTestResult();
        $code = $result->getResultCode();
        $names = [0 => 'passed', 10 => 'skipped', 20 => 'pending', 30 => 'undefined', 99 => 'failed'];
        $step = $scope->getStep();

        $exception = null;
        if (method_exists($result, 'getException') && $result->getException() !== null) {
            $e = $result->getException();
            $exception = [
                'class' => $e::class,
                'message' => mb_substr((string) $e->getMessage(), 0, 4000),
            ];
        }

        self::$record['steps'][] = [
            'line' => $step->getLine(),
            'keyword' => trim($step->getKeyword()),
            'text' => $step->getText(),
            'result' => $names[$code] ?? ('code' . $code),
            'seconds' => round(microtime(true) - self::$stepStart, 4),
            'exception' => $exception,
        ];
        self::stepEnd();
    }

    /** @AfterScenario */
    public function stopScenario(AfterScenarioScope $scope): void
    {
        $direct = null;
        if (self::$covRunning && self::$cov !== null) {
            $trace = self::stopTrace();
            self::$cov->stop();
            self::$covRunning = false;
            self::$record['coverage'] = $this->collectCoverage();
            self::$cov->clear();
            if ($trace !== null) {
                $direct = self::reduceTrace($trace);
            }
        }
        self::$record['direct_calls'] = $direct;
        // Null exactly when `direct_calls` is: the marker attests the shape
        // of the events this recorder wrote, and a scenario that collected
        // none has no shape to attest.
        self::$record['direct_calls_schema'] = $direct === null ? null : self::DIRECT_CALLS_SCHEMA;
        self::$record['seconds'] = round(microtime(true) - self::$scenarioStart, 4);
        self::$record['scenario_result'] = $scope->getTestResult()->isPassed() ? 'passed' : 'not-passed';

        $fh = fopen(self::$out, 'a');
        if ($fh !== false) {
            fwrite($fh, json_encode(self::$record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
            fclose($fh);
        }
        self::$record = [];
    }

    /** @return array{files: array<string,int>, units: list<string>} */
    private function collectCoverage(): array
    {
        $files = [];
        $units = [];
        $src = self::$root . '/src';
        foreach (self::$cov->getData()->lineCoverage() as $file => $lines) {
            if (strncmp($file, $src, strlen($src)) !== 0) {
                continue;
            }
            $rel = ltrim(str_replace(self::$root, '', $file), '/');
            $n = 0;
            foreach ($lines as $line => $tests) {
                if (!empty($tests)) {
                    $units[] = $rel . '::L' . $line;
                    $n++;
                }
            }
            if ($n > 0) {
                $files[$rel] = $n;
            }
        }

        return ['files' => $files, 'units' => $units];
    }

    // ------------------------------------------------------------ the trace

    /**
     * Start the function trace for the scenario that has just begun.
     *
     * Only when xdebug's active mode includes `trace`: `xdebug_start_trace`
     * under any other mode warns and starts nothing, and the harness sets
     * `coverage,trace` on exactly the invocations that collect coverage.  A
     * coverage run whose xdebug cannot trace records `direct_calls: null`
     * and says so once on stderr, the way an unavailable coverage driver
     * does.
     */
    private static function startTrace(): void
    {
        self::$traceFile = null;
        $modes = function_exists('xdebug_info') ? (array) @xdebug_info('mode') : [];
        if (!in_array('trace', $modes, true)) {
            if (!self::$traceWarned) {
                self::diag(['event' => 'unavailable', 'why' => 'xdebug trace mode is not active']);
                self::$traceWarned = true;
            }

            return;
        }
        // Under the temporary directory, never under the workspace: `_bench/`
        // is a substrate root and a trace beside the record would be reported
        // `added` by the substrate check.  xdebug appends its own suffix to
        // the base name and reports the name it actually opened.
        $base = sys_get_temp_dir() . '/r2t-direct-' . getmypid() . '-' . (++self::$traceSeq);
        // Trace only calls MADE FROM files under the workspace's src/ (the
        // filter tests the call-site file, measured): every direct call has
        // a removable, hence src/, call site, and every production call made
        // by production or retained code is kept too.  What drops out is the
        // framework calling itself and the framework calling production --
        // events no boundary can ever classify direct -- which is most of
        // the trace by volume.  Armed for the scenario window only: xdebug
        // evaluates the filter on every call while it is set, trace or no
        // trace, and the retained setup hooks run outside the window.
        xdebug_set_filter(XDEBUG_FILTER_TRACING, XDEBUG_PATH_INCLUDE, [self::$root . '/src/']);
        self::$traceStart = microtime(true);
        $file = xdebug_start_trace($base, XDEBUG_TRACE_COMPUTERIZED);
        if (!is_string($file) || $file === '') {
            xdebug_set_filter(XDEBUG_FILTER_TRACING, XDEBUG_FILTER_NONE, []);
            if (!self::$traceWarned) {
                self::diag(['event' => 'unavailable', 'why' => 'xdebug_start_trace started no trace']);
                self::$traceWarned = true;
            }

            return;
        }
        self::$traceFile = $file;
    }

    /** Stop the running trace and return its file, or null if none ran. */
    private static function stopTrace(): ?string
    {
        if (self::$traceFile === null) {
            return null;
        }
        xdebug_stop_trace();
        xdebug_set_filter(XDEBUG_FILTER_TRACING, XDEBUG_FILTER_NONE, []);
        $file = self::$traceFile;
        self::$traceFile = null;

        return $file;
    }

    /**
     * Reduce one scenario's trace to its `direct_calls` list, delete the
     * trace, and append the reduction's diagnostics to the diag file — one
     * line per scenario carrying what the operator gate reports (§8): trace
     * size and time, the names that resolved to no method, and the events
     * the production-root fence dropped by callee directory with their
     * callers under `src/`.
     *
     * @return list<array{callee_file: string, callee_line: int, callee: string, caller_file: string}>
     */
    private static function reduceTrace(string $trace): array
    {
        $traceSeconds = microtime(true) - self::$traceStart;
        $bytes = @filesize($trace);
        $t0 = microtime(true);
        $diag = [];
        $calls = self::directCallsFromTrace($trace, self::$root, $diag);
        @unlink($trace);
        self::diag([
            'event' => 'scenario',
            'scenario' => self::$record['feature_file'] . ':' . self::$record['scenario_line'],
            'trace_bytes' => $bytes === false ? null : $bytes,
            'trace_seconds' => round($traceSeconds, 4),
            'reduce_seconds' => round(microtime(true) - $t0, 4),
        ] + $diag);

        return $calls;
    }

    /**
     * Append one diagnostic line to `<tmp>/r2t-direct-diag.jsonl`.
     *
     * A file, and not stderr, for a measured reason: the harness appends
     * stderr to the Behat log it classifies, keeps a 4000-character tail of
     * that log, and reads `PHP Fatal error` and the DI markers out of it --
     * a diagnostic that named an unresolved `...ParseException->__construct`
     * or merely pushed a fatal out of the tail would change an outcome.  The
     * file lives beside the traces, outside every substrate root, is never
     * read by the harness, holds one process's lines (`prepareTracing`
     * starts it afresh), and is what the §8 gate collects after each item.
     */
    private static function diagPath(): string
    {
        return sys_get_temp_dir() . '/r2t-direct-diag.jsonl';
    }

    private static function diag(array $line): void
    {
        $fh = @fopen(self::diagPath(), 'a');
        if ($fh !== false) {
            fwrite($fh, json_encode($line, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
            fclose($fh);
        }
    }

    /**
     * The unique production call events of one computerized xdebug trace.
     *
     * An entry record of that format carries the nesting level, the function
     * name, whether the function is user-defined, and the file and line of
     * the CALL SITE; the caller's file is therefore the record's own filename
     * field, and no ancestor record is consulted (§2.4).  Only entries that
     * name a user-defined method — `Class->method` or `Class::method` — are
     * activations this definition knows: plain functions, includes, closures
     * and internal functions are dropped.  The callee's declaring file is
     * not in the trace; it is resolved once per distinct name through
     * reflection, whose file and start line are the method body's — the
     * trait's file for a trait method, the parent's for an inherited one —
     * and the production-root fence is applied to THAT file: an event is
     * kept only when it lies under `$root/src`.  A name that resolves to no
     * method is dropped and counted.  What remains is reduced to unique
     * (callee file, callee line, callee name, caller file, step) tuples with
     * repo-relative paths, sorted by that tuple.
     *
     * The step comes from the trace as well: the k-th `stepBegin` marker
     * opens step k and `stepEnd` closes it, so a call made between steps
     * carries `null`.  Both markers are skipped entirely — never counted,
     * never resolved, never emitted — because the marker is itself an
     * activation inside the trace root and would otherwise be an event.
     * The step is part of the key the events are aggregated under, so the
     * same call from two steps survives as two events.
     *
     * A callee declared under one of the project's generated roots is not
     * dropped but CREDITED to the nearest first-party method it implements
     * (§3.3): the emitted event names the contract's file, line and method,
     * and the generated method in `generated_callee`.  A generated method
     * with no such ancestor is dropped and counted separately.
     *
     * Public and static so an in-container fixture can run it over a trace
     * of its own, against a root of its own.
     *
     * @param array<string, mixed> $diag  receives the reduction's counts
     * @return list<array{callee_file: string, callee_line: int, callee: string, caller_file: string, step: int|null}>
     */
    public static function directCallsFromTrace(string $trace, string $root, ?array &$diag = null): array
    {
        $root = rtrim($root, '/');
        $underCalleeRoots = static function (string $file) use ($root): bool {
            return strncmp($file, $root . '/src/', strlen($root . '/src/')) === 0;
        };
        $stepBegin = self::class . '::stepBegin';
        $stepEnd = self::class . '::stepEnd';
        $step = null;                // the step the trace is inside, or none
        $steps = 0;                  // how many `stepBegin` markers it held
        $entries = 0;
        $methodEvents = 0;
        $pairs = [];                 // "name\0caller file\0step" -> event count

        // gzopen reads a plain file as well as a compressed one, and xdebug
        // compresses its output when built with zlib.
        $fh = function_exists('gzopen') ? gzopen($trace, 'rb') : fopen($trace, 'rb');
        if ($fh === false) {
            throw new \RuntimeException('cannot open trace ' . $trace);
        }
        $gets = function_exists('gzgets') ? 'gzgets' : 'fgets';
        while (($line = $gets($fh)) !== false) {
            // Records start with the nesting level; the header, the
            // TRACE START/END markers and the closing memory line do not.
            if ($line === '' || $line[0] < '0' || $line[0] > '9') {
                continue;
            }
            $f = explode("\t", $line, 11);
            if (!isset($f[9]) || $f[2] !== '0') {
                continue;            // an exit or return record
            }
            $entries++;
            if ($f[6] !== '1') {
                continue;            // an internal function
            }
            $name = $f[5];
            if ($name === $stepBegin) {
                $step = $steps++;    // the k-th marker opens step k
                continue;
            }
            if ($name === $stepEnd) {
                $step = null;
                continue;
            }
            if (strpos($name, '->') === false && strpos($name, '::') === false) {
                continue;            // a plain function, an include, {main}
            }
            $methodEvents++;
            $key = $name . "\0" . $f[8] . "\0" . ($step === null ? '' : $step);
            $pairs[$key] = ($pairs[$key] ?? 0) + 1;
        }
        (function_exists('gzclose') ? 'gzclose' : 'fclose')($fh);

        $unresolved = [];            // name -> events
        $fenced = [];                // callee top-level directory -> events
        $fencedSrcCallers = [];      // directory -> caller under src/ -> events
        $credited = [];              // generated name -> events credited
        $uncredited = [];            // generated name -> events with no contract
        $kept = 0;
        $tuples = [];
        foreach ($pairs as $key => $count) {
            [$name, $callerAbs, $atStep] = explode("\0", $key, 3);
            $step = $atStep === '' ? null : (int) $atStep;
            if (!array_key_exists($name, self::$resolved)) {
                self::$resolved[$name] = self::resolve($name);
            }
            $where = self::$resolved[$name];
            if ($where === null) {
                $unresolved[$name] = ($unresolved[$name] ?? 0) + $count;
                continue;
            }
            [$file, $startLine] = $where;
            $caller = ltrim(str_replace($root, '', $callerAbs), '/');
            $generated = null;
            if (!$underCalleeRoots($file)) {
                $isGenerated = self::underGeneratedRoots($file, $root);
                $contract = $isGenerated
                    ? self::creditGenerated($name, $underCalleeRoots, $root) : null;
                if ($contract === null) {
                    if ($isGenerated) {
                        $uncredited[$name] = ($uncredited[$name] ?? 0) + $count;
                    }
                    $dir = self::topLevelDirectory($file, $root);
                    $fenced[$dir] = ($fenced[$dir] ?? 0) + $count;
                    if (strncmp($caller, 'src/', 4) === 0) {
                        $fencedSrcCallers[$dir][$caller] = ($fencedSrcCallers[$dir][$caller] ?? 0) + $count;
                    }
                    continue;
                }
                // ONE credit per generated call: the contract method is what
                // the event now names, and the generated method it came
                // through is kept beside it as evidence.
                $credited[$name] = ($credited[$name] ?? 0) + $count;
                $generated = $name;
                [$file, $startLine, $name] = $contract;
            }
            $kept += $count;
            $rel = ltrim(str_replace($root, '', $file), '/');
            $event = [
                'callee_file' => $rel,
                'callee_line' => $startLine,
                'callee' => $name,
                'caller_file' => $caller,
            ];
            if ($generated !== null) {
                $event['generated_callee'] = $generated;
            }
            $event['step'] = $step;
            $tuples[$rel . "\0" . $startLine . "\0" . $name . "\0" . $caller
                    . "\0" . (string) $generated . "\0" . $atStep] = $event;
        }
        $calls = array_values($tuples);
        usort($calls, static function (array $a, array $b): int {
            return strcmp($a['callee_file'], $b['callee_file'])
                ?: $a['callee_line'] <=> $b['callee_line']
                ?: strcmp($a['callee'], $b['callee'])
                ?: strcmp($a['caller_file'], $b['caller_file'])
                // A call outside any step sorts first, as the Python
                // recorder's own event order does.
                ?: ($a['step'] !== null) <=> ($b['step'] !== null)
                ?: ($a['step'] ?? 0) <=> ($b['step'] ?? 0)
                ?: strcmp($a['generated_callee'] ?? '', $b['generated_callee'] ?? '');
        });

        arsort($unresolved);
        arsort($credited);
        arsort($uncredited);
        ksort($fenced);
        foreach ($fencedSrcCallers as &$callers) {
            arsort($callers);
        }
        unset($callers);
        ksort($fencedSrcCallers);
        $diag = [
            'entries' => $entries,
            'method_events' => $methodEvents,
            'distinct_pairs' => count($pairs),
            'unresolved_events' => array_sum($unresolved),
            'unresolved_names' => count($unresolved),
            'unresolved_top' => array_slice($unresolved, 0, 20, true),
            'fenced_events' => $fenced,
            'fenced_src_callers' => $fencedSrcCallers,
            // Zero on a scenario that ran steps is the symptom of a recorder
            // installed outside the project's trace roots: the markers are
            // then filtered out and every event carries a null step.
            'step_markers' => $steps,
            'generated_credited' => array_slice($credited, 0, 20, true),
            'generated_uncredited' => array_slice($uncredited, 0, 20, true),
            'production_events' => $kept,
            'unique_tuples' => count($calls),
        ];

        return $calls;
    }

    /**
     * The declaring file and start line of the method a trace name denotes,
     * or null when it denotes none.
     *
     * @return array{0: string, 1: int}|null
     */
    private static function resolve(string $name): ?array
    {
        $at = strpos($name, '->');
        if ($at === false) {
            $at = strpos($name, '::');
        }
        $class = substr($name, 0, $at);
        $method = substr($name, $at + 2);
        if ($class === '' || $method === '' || !class_exists($class, false) && !trait_exists($class, false)
                && !interface_exists($class, false) && !enum_exists($class, false)) {
            return null;
        }
        try {
            $m = new \ReflectionMethod($class, $method);
        } catch (\ReflectionException $e) {
            return null;
        }
        $file = $m->getFileName();
        $line = $m->getStartLine();
        if ($file === false || $line === false) {
            return null;             // an internal method
        }

        return [$file, $line];
    }

    /** Whether a declaring file lies under one of this project's generated roots. */
    private static function underGeneratedRoots(string $file, string $root): bool
    {
        foreach (self::$generatedRoots as $generated) {
            $prefix = $root . '/' . trim($generated, '/') . '/';
            if (strncmp($file, $prefix, strlen($prefix)) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * The first-party contract method a generated method implements, as
     * [declaring file, start line, contract name], or null when there is
     * none (TARGET_INTERFACES_V2_SPEC §3.3, owner ruling V2-D1(a)).
     *
     * The ancestry is walked NEAREST FIRST — the parent chain, then the
     * class's interfaces in `getInterfaceNames()` order — and the first
     * ancestor that DECLARES a method of that name itself, in a file under
     * a callee root, is the credit.  Nearest first because the nearest
     * declaration is the one a tester would write against: CoreShop's
     * `CoreShopOrder extends Core\Model\Order` declares `getPaymentState`
     * itself while `Order` does not, so the credit is the interface's, and
     * a generated override of a method the parent class DOES declare is
     * credited to that class.  Exactly one credit, never a set: the event
     * is one call.
     *
     * Cached per (root, name), not per name: unlike a declaring file, a
     * credit depends on which roots are first-party, and the fixture
     * reduces two traces against two different roots in one process.
     *
     * @param callable(string): bool $underCalleeRoots
     * @return array{0: string, 1: int, 2: string}|null
     */
    private static function creditGenerated(string $name, callable $underCalleeRoots,
                                            string $root): ?array
    {
        $cache = $root . "\0" . $name;
        if (array_key_exists($cache, self::$credited)) {
            return self::$credited[$cache];
        }
        self::$credited[$cache] = null;
        $at = strpos($name, '->');
        $separator = '->';
        if ($at === false) {
            $at = strpos($name, '::');
            $separator = '::';
        }
        $class = substr($name, 0, (int) $at);
        $method = substr($name, (int) $at + 2);
        if (!class_exists($class, false)) {
            return null;             // an interface or trait generates nothing
        }
        try {
            $reflected = new \ReflectionClass($class);
        } catch (\ReflectionException $e) {
            return null;
        }
        $ancestors = [];
        for ($parent = $reflected->getParentClass(); $parent !== false; $parent = $parent->getParentClass()) {
            $ancestors[] = $parent->getName();
        }
        foreach ($reflected->getInterfaceNames() as $interface) {
            $ancestors[] = $interface;
        }
        foreach ($ancestors as $ancestor) {
            try {
                $m = new \ReflectionMethod($ancestor, $method);
            } catch (\ReflectionException $e) {
                continue;
            }
            if ($m->getDeclaringClass()->getName() !== $ancestor) {
                continue;            // inherited, not declared here
            }
            $file = $m->getFileName();
            $line = $m->getStartLine();
            if ($file === false || $line === false || !$underCalleeRoots($file)) {
                continue;
            }
            self::$credited[$cache] = [$file, $line, $ancestor . $separator . $method];
            break;
        }

        return self::$credited[$cache];
    }

    /** `var/classes` or `var/cache` for a generated file, else the first path component, else `outside-root`. */
    private static function topLevelDirectory(string $file, string $root): string
    {
        if (strncmp($file, $root . '/', strlen($root) + 1) !== 0) {
            return 'outside-root';
        }
        $parts = explode('/', substr($file, strlen($root) + 1), 3);
        if ($parts[0] === 'var' && isset($parts[1])) {
            return 'var/' . $parts[1];
        }

        return $parts[0];
    }
}
