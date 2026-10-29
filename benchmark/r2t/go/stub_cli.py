"""Go stub acceptance through the existing coordinator-owned control runner.

Every selected stub must run successfully. Mutation recall remains the separate
shared anti-vacuity gate; this command collects no API/coverage or scored rows.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..bench import cli as bench_cli
from ..bench.harness import Solution
from ..bench.runner import _ExecutionLock
from ..bench.validate import HARNESS_VERSION
from ..bench.worker import validate_live_worker_runtime
from ..core.gherkin import parse_feature_file
from .control_adapter import make_stub_adapter
from .controls import registrations
from .execution import COMMAND_TIMEOUT
from .registry import _require, source_selection
from .workspace import load_worker_workspace


def cmd_stub_accept(args) -> int:
    """Check the release's Go criterion stubs on one authenticated worker."""
    from ..stacks.godog import GodogHarness

    profile = bench_cli._stack_profile(args)
    _require((profile.project, profile.language, profile.framework) ==
             ('coddy-agent', 'go', 'godog'), 'Go stub acceptance requires the coddy-agent profile')
    manifest, boundary, runner, inventory, bound = load_worker_workspace(args)
    _require(boundary.project == profile.project, 'Go stub acceptance boundary differs from profile')
    closures_path = Path(args.closures or Path(args.artifacts) / 'closures.json').resolve()
    closures = json.loads(closures_path.read_text(encoding='utf-8'))
    harness = GodogHarness(manifest, boundary, runner, closures, original_inventory=inventory)
    by_id = {closure['item_id']: closure for closure in closures}
    with open(args.release, encoding='utf-8') as stream:
        items = [item for line in stream if line.strip() for item in [json.loads(line)]
                 if item.get('project') == profile.project and item.get('task') == 'criterion_to_test']
    _require(items and len({item['item_id'] for item in items}) == len(items),
             'Go stub acceptance needs nonempty unique criterion items')
    selected = []
    definitions = 0
    for item in items:
        harness.check_context(item)
        closure = by_id[item['item_id']]
        _require(not closure.get('problems'), 'Go stub acceptance refuses a blocked gold closure')
        definitions += len(registrations(closure))
        context = closure['go_suite']
        feature_path = Path(harness.root) / context['feature_path']
        _require(feature_path.resolve().is_relative_to(Path(harness.root)),
                 'Go stub acceptance feature escapes its worker')
        # Reuse the native selector's exact header/Examples validation before
        # the live boundary, then the shared feature object expected by runtime.
        source_selection(context, feature_path.read_text(encoding='utf-8'))
        feature = parse_feature_file(str(feature_path))
        scenario = feature.scenario_at(context['scenario_line'])
        _require(scenario is not None, 'Go stub acceptance selected header is absent')
        selected.append((item, feature, scenario))
    adapter = make_stub_adapter(str(closures_path), harness=harness)
    results = []
    violations = []
    with _ExecutionLock(harness.root):
        harness.verify_substrate()
        live = validate_live_worker_runtime(args.worker, bound['worker'], HARNESS_VERSION,
            needs_database=False, answer_paths=tuple(filter(None, (args.gold, args.artifacts, args.boundary,
                getattr(args, 'profile', None), args.release, str(closures_path)))),
            expected_runtime={key: bound['runtime'][key] for key in (
                'harness_version', 'container_image_digest', 'workspace_seed_digest', 'database_dump_digest')})
        runner.container = live['selected']['binding']['container']['id']
        for item, feature, scenario in selected:
            harness.prepare_for_generation()
            produced = adapter(item)
            result = adapter.run_control(harness, feature, scenario, Solution.from_json(produced),
                coverage=False, timeout=COMMAND_TIMEOUT, repeats=1, task='criterion_to_test', keep_stdout=True)
            results.append({'item_id': item['item_id'], 'result': result})
            if (result['outcomes'] != ['passed'] or result['substrate_violation']
                    or result['rejected_files'] or result['index_errors']):
                violations.append(item['item_id'] + ': stub did not pass')
    print(json.dumps({'items': len(items), 'items_refused': len(violations),
        'definitions_emitted': definitions, 'closures': str(closures_path),
        'violations': violations, 'results': results}, indent=1))
    if violations:
        raise SystemExit('REFUSED: Go stub acceptance failed:\n  ' + '\n  '.join(violations))
    return 0
