"""Go source-entry and native-block measurement in the existing execution copy.

The complete runtime remains gated until actual-project qualification. These
helpers plan/reconstruct the single trusted finalization; they own no process,
container, retry, or independent execution deadline.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from ..core.boundary import PRODUCTION
from .execution import COPY_ROOT
from .prod_index import GO_PROD_PATHS
from .registry import checked_plan as checked_interposition, planner_command as interposition_command, support_files

PLANNER = '_bench/go/support/measurement.go'
RECORDER = '_bench/go/measure/recorder.go'
HELPER = '_bench/go/support/measurement_harness.go'
#: `/2` stamps every entry with the step that made it. The marker moves with
#: the shape: a new harness can execute an older seed whose recorder is
#: substrate, so the harness version cannot attest it.
SCHEMA = 'r2t.go-measurement/2'
WINDOW = 'selected-parent-process-through-M.Run-cleanup'


class MeasurementRefused(ValueError):
    pass


def _require(value, why):
    if not value:
        raise MeasurementRefused(why)


def _production(path, boundary):
    return (isinstance(path, str) and path.endswith('.go') and not path.endswith('_test.go')
            and any(path.startswith(root + '/') for root in GO_PROD_PATHS)
            and boundary.classify(path) == PRODUCTION)


def runtime_helper(*, control=False):
    if control:
        from .controls import helper_source
        source = helper_source()
    else:
        source = support_files()['_bench/go/support/harness.go']
    marker = b'"event": "interposed", "test": t.Name()'
    _require(source.count(b'import (') == source.count(marker) == 1,
             'native runtime helper extension points changed')
    source = source.replace(b'import (', b'import (\n r2tmeasure "R2T_MEASUREMENT_IMPORT"', 1)
    source = source.replace(marker, marker + b', "measurement_pid": os.Getpid()', 1)
    # The harness registers godog's step hooks either way; only a measured run
    # has a recorder to receive the step, so the binding lives here.
    return source + (b'\nfunc init() { r2tSetStep = r2tmeasure.SetStep }\n'
                     b'func TestMain(m *testing.M) { r2tmeasure.FinalizeAndExit(m.Run()) }\n')


def initial_files(*, control=False):
    directory = Path(__file__).with_name('support')
    return {PLANNER: (directory / 'measurement.go').read_bytes(),
            RECORDER: (directory / 'measurement_recorder.go').read_bytes(),
            HELPER: runtime_helper(control=control)}


def planner_command(context, *, runtime_diagnostics=False):
    argv = interposition_command(context, helper_path=HELPER, runtime_diagnostics=runtime_diagnostics)
    argv[2] = './' + PLANNER
    argv.insert(2, '-p=1')
    return argv


def checked_plan(raw, *, context, original, expected_inventory, boundary, helper_template):
    """Reconstruct measured source against independently held current inputs."""
    try:
        plan = json.loads(raw)
        module = plan['module_path']
        _require(isinstance(module, str) and module and not any(c.isspace() for c in module)
                 and all(p not in ('', '.', '..') for p in module.split('/')),
                 'invalid compiled module identity')
        imported = module + '/_bench/go/measure'
        _require(plan['recorder_import'] == imported, 'recorder import differs from compiled module')
        template = helper_template.replace(b'R2T_MEASUREMENT_IMPORT', imported.encode())
        mapping, transforms = checked_interposition(json.dumps(plan['interposition']), context,
                                                    original, helper_template=template)
        files = plan['production_files']
        _require(isinstance(files, list) and files == sorted(set(files)) and files,
                 'missing or duplicate compiled production inventory')
        _require([row['file'] for row in plan['production_plans']] == files,
                 'partial production measurement plan')
        _require(plan['coverage_order'] == 'native-original-coverage-before-api-entry-hooks',
                 'measurement instrumentation order differs')
        for row in plan['production_plans']:
            path = row['file']
            _require(_production(path, boundary) and path in expected_inventory,
                     'measurement source escapes compiled original production fence')
            source = row['original_source'].encode('utf-8')
            _require(hashlib.sha256(source).hexdigest() == row['original_sha256'] == expected_inventory[path],
                     'measurement source differs from independently verified bytes')
            native = row['native_covered_source'].encode('utf-8')
            _require(native.startswith(f'//line {COPY_ROOT}/{path}:1:1\n'.encode()),
                     'native coverage lost original source positions')
            counter, hook = row['counter_name'], row['hook_name']
            _require(all(isinstance(name, str) and re.fullmatch(r'[A-Za-z_]\w*', name)
                         for name in (counter, hook)), 'invalid generated Go identifier')
            previous = -1
            edits, counter_edits = row['edits'], row['counter_edits']
            for edit in edits:
                start, end = edit['Start'], edit['End']
                _require(type(start) is int and type(end) is int and previous <= start <= end <= len(native),
                         'overlapping or invalid measurement edit')
                _require(isinstance(edit['Text'], str) and '\n' not in edit['Text'],
                         'measurement edit moves source lines')
                previous = end
            _require([e for e in edits if e['End'] > e['Start']] == counter_edits,
                     'only native increments may be replaced')
            for edit in counter_edits:
                before = native[edit['Start']:edit['End']].decode('utf-8')
                match = re.fullmatch(r'_cover_atomic_\.AddUint32\((&' + re.escape(counter)
                                     + r'\.Count\[\d+\]), 1\)', before)
                _require(match is not None and edit['Text'] == hook + '.Hit(' + match[1] + ')',
                         'native counter replacement changed its target')
            _require(len(edits) == len(row['declarations']) + 1 + len(counter_edits),
                     'missing or duplicate production API entry')
            rebuilt = native
            for edit in reversed(edits):
                rebuilt = rebuilt[:edit['Start']] + edit['Text'].encode('utf-8') + rebuilt[edit['End']:]
            rebuilt += row['suffix'].encode('utf-8')
            _require(rebuilt.decode('utf-8') == row['transformed_source']
                     and rebuilt.count(b'\n') == native.count(b'\n') + 2,
                     'measurement transformation does not reconstruct')
            marker = b'\nvar ' + counter.encode() + b' = struct'
            offset = native.rfind(marker)
            _require(offset >= 0 and native[offset:] in rebuilt,
                     'native coverage counter metadata changed')
            transforms[path] = rebuilt
        return mapping, transforms, plan
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise MeasurementRefused('malformed Go measurement preparation plan') from error


def project(capture, witness, *, coverage=True):
    """Return shared records plus a diagnostic; incomplete channels stay null.

    Native status/Outline identity is decoded independently before this call.
    Every actual row receives the same measured parent-process set. A failed
    collector does not change its native scenario outcome or fabricate a set.
    """
    records = deepcopy(witness.records)
    if not coverage:
        return records, None
    diagnostic = None
    direct, covered = None, None
    try:
        _require(capture.measurement is not None and capture.measurement_owner is not None
                 and capture.measurement_plan is not None, 'measurement finalization missing')
        document = json.loads(capture.measurement)
        _require(document['schema'] == SCHEMA and document['complete'] is True
                 and document['window'] == WINDOW and not document['failures'],
                 'measurement finalization failed or incomplete')
        pid = document['pid']
        _require(type(pid) is int and pid > 0 and capture.measurement_owner == f'{pid}\n'.encode(),
                 'measurement parent claim differs')
        native_start = json.loads(capture.native.splitlines()[0])
        _require(native_start['measurement_pid'] == pid
                 and document['exit'] == capture.completed.returncode,
                 'measurement parent/exit differs from native execution')
        plan = capture.measurement_plan
        declarations = {(p['file'], d['Line']): d
                        for p in plan['production_plans'] for d in p['declarations']}
        events = document['direct_calls']
        keys = {'callee_file', 'callee_line', 'callee', 'caller_file', 'step'}
        _require(isinstance(events, list), 'API event set is unavailable')
        # `step` indexes the record's own step list, so the same entry made
        # from two steps is two events; null is an entry made outside any
        # step. Every record of this process runs the same Background and
        # scenario steps, so one length bounds them all.
        steps = len(records[0]['steps'])
        identity = lambda e: (e['callee_file'], e['callee_line'], e['callee'],
                              (0, '') if e['caller_file'] is None else (1, e['caller_file']),
                              (0, 0) if e['step'] is None else (1, e['step']))
        for event in events:
            _require(isinstance(event, dict) and set(event) == keys,
                     'invalid common API event fields')
            _require(isinstance(event['callee_file'], str) and type(event['callee_line']) is int
                     and event['callee_line'] > 0 and isinstance(event['callee'], str),
                     'invalid API declaration coordinates')
            _require(event['step'] is None or (type(event['step']) is int
                                               and 0 <= event['step'] < steps),
                     'API event names no step of its own record')
            declaration = declarations.get((event['callee_file'], event['callee_line']))
            _require(declaration and declaration['Name'] == event['callee']
                     and (event['caller_file'] is None or isinstance(event['caller_file'], str)),
                     'API event lacks its original declaration identity')
        _require(events == sorted(events, key=identity) and len({identity(e) for e in events}) == len(events),
                 'API events are not a deterministic unique set')
        counters = document['coverage']
        _require(isinstance(counters, list) and [r['File'] for r in counters] == plan['production_files'],
                 'coverage file set differs from the compiled production plan')
        sources = {p['file']: p['original_source'].encode('utf-8').splitlines()
                   for p in plan['production_plans']}
        by_file = {}
        for row in counters:
            counts, positions, statements = row['Counts'], row['Positions'], row['Statements']
            _require(isinstance(counts, list) and len(positions) == 3 * len(counts)
                     and len(statements) == len(counts), 'partial native coverage counters')
            lines = set()
            for index, count in enumerate(counts):
                start, end, columns = positions[3*index:3*index+3]
                _require(type(count) is int and 0 <= count < 2**32
                         and all(type(n) is int for n in (start, end, columns))
                         and 1 <= start <= end <= len(sources[row['File']])
                         and 0 < (columns & 65535) <= len(sources[row['File']][start-1]) + 1
                         and 0 < (columns >> 16) <= len(sources[row['File']][end-1]) + 1,
                         'coverage block lost original physical positions')
                if count:
                    # Shared line units expand the original native source block;
                    # continuation-line mutation tokens keep their own coordinates.
                    lines.update(range(start, end + 1))
            if lines:
                by_file[row['File']] = lines
        direct = events
        covered = {'files': {path: len(lines) for path, lines in sorted(by_file.items())},
                   'units': sorted(f'{path}::L{line}' for path, lines in by_file.items() for line in lines)}
    except (MeasurementRefused, KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        diagnostic = str(error)
    for row in records:
        row.update(coverage=deepcopy(covered), direct_calls=deepcopy(direct),
                   measurement_window=WINDOW)
    return records, diagnostic
