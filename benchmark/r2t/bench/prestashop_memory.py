"""Approved PrestaShop memory policy, observed through the bound native worker.

Counters are diagnostics; they never change mutation outcomes or retry rules.
"""
from __future__ import annotations

import json
import os
import re

PRESTASHOP_MEMORY_POLICY = {
    "schema": "r2t.prestashop-memory-policy/1",
    "memory_bytes": 4294967296,
    "swap_bytes": 0,
}


def _refuse(message):
    from .worker import WorkerRefused
    return WorkerRefused("REFUSED: " + message)


def _validate_worker_memory(memory, *, container_id=None):
    fields = {"policy", "container_id", "configured_memory_bytes",
              "configured_memory_swap_bytes", "oom_kill_disabled",
              "effective_memory_bytes", "effective_swap_bytes"}
    if not isinstance(memory, dict) or set(memory) != fields \
            or memory.get("policy") != PRESTASHOP_MEMORY_POLICY:
        raise _refuse("worker memory policy is not approved PrestaShop 4 GiB/zero swap")
    policy = memory["policy"]
    if type(policy.get("memory_bytes")) is not int or type(policy.get("swap_bytes")) is not int:
        raise _refuse("worker memory policy limits must be integers")
    limits = {"configured_memory_bytes": 4294967296,
              "configured_memory_swap_bytes": 4294967296,
              "effective_memory_bytes": 4294967296,
              "effective_swap_bytes": 0}
    if any(type(memory[key]) is not int or memory[key] != value
           for key, value in limits.items()) or memory["oom_kill_disabled"] is not False:
        raise _refuse("worker memory enforcement differs from its approved policy")
    if not isinstance(memory["container_id"], str) \
            or re.fullmatch(r"[0-9a-f]{64}", memory["container_id"]) is None:
        raise _refuse("worker memory evidence has no exact container identity")
    if container_id is not None and memory["container_id"] != container_id:
        raise _refuse("memory evidence belongs to another bound container")
    return dict(PRESTASHOP_MEMORY_POLICY)


_MEMORY_QUERY = r'''set -eu
for name in memory.max memory.swap.max; do
  [ -r "/sys/fs/cgroup/$name" ] || exit 3
  IFS= read -r value < "/sys/fs/cgroup/$name"
  printf '%s %s\n' "$name" "$value"
done
[ -r /sys/fs/cgroup/memory.events ] || exit 3
while read -r name value; do printf 'event %s %s\n' "$name" "$value"; done < /sys/fs/cgroup/memory.events
'''


def _observe_memory(worker, label, *, docker_group=True):
    """Configured HostConfig plus effective cgroup limits and counters; execute no application."""
    from . import worker as W
    inspected = W._docker_json(
        ["inspect", worker.container, "--format", "{{json .}}"],
        label, docker_group=docker_group)
    host = inspected.get("HostConfig") or {}
    cp = worker.runner(docker_group=docker_group).run(_MEMORY_QUERY, timeout=30)
    if cp.returncode != 0:
        raise _refuse("cannot observe effective worker cgroup memory limits")
    limits, events = {}, {}
    try:
        for line in (cp.stdout or "").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in {"memory.max", "memory.swap.max"}:
                if parts[0] in limits or not parts[1].isdigit():
                    raise ValueError("duplicate or unbounded limit")
                limits[parts[0]] = int(parts[1])
            elif len(parts) == 3 and parts[0] == "event" \
                    and re.fullmatch(r"[a-z_]+", parts[1]) and parts[2].isdigit():
                if parts[1] in events:
                    raise ValueError("duplicate memory counter")
                events[parts[1]] = int(parts[2])
            else:
                raise ValueError("unknown cgroup response")
        if set(limits) != {"memory.max", "memory.swap.max"} \
                or not {"oom", "oom_kill"} <= set(events):
            raise ValueError("incomplete memory response")
    except (ValueError, TypeError) as exc:
        raise _refuse("missing or invalid effective worker memory evidence") from exc
    disabled = host.get("OomKillDisable")
    if disabled is not None and disabled is not False:
        raise _refuse("worker OOM killer must remain enabled")
    return inspected, host, limits, events


def capture_prestashop_memory(worker, *, docker_group=True):
    """Read configured/effective limits and counters; execute no application."""
    inspected, host, limits, events = _observe_memory(
        worker, "PrestaShop memory container", docker_group=docker_group)
    memory = {"policy": dict(PRESTASHOP_MEMORY_POLICY),
              "container_id": inspected.get("Id"),
              "configured_memory_bytes": host.get("Memory"),
              "configured_memory_swap_bytes": host.get("MemorySwap"),
              "oom_kill_disabled": False,
              "effective_memory_bytes": limits["memory.max"],
              "effective_swap_bytes": limits["memory.swap.max"]}
    _validate_worker_memory(memory)
    return {"memory": memory, "oom_counters": events}


# Coddy-agent Go workers (owner, 2026-09-29): a mutant that allocates without
# bound must die inside its own container, not exhaust a shared host.  The
# kill is the section-2 out-of-memory infrastructure case; no outcome rule
# changes.  Rootless Docker drops an unenforceable limit with only a warning,
# so the effective cgroup limit is checked, not just the requested one.
GO_MEMORY_POLICY = {
    "schema": "r2t.go-memory-policy/1",
    "projects": ["coddy-agent"],
    "memory_bytes": 17179869184,
    "swap_bytes": 0,
}


def go_memory_run_args(project):
    """Container arguments of the Go memory policy for PROJECT, or none."""
    if project not in GO_MEMORY_POLICY["projects"]:
        return ()
    limit = str(GO_MEMORY_POLICY["memory_bytes"])
    return ("--memory", limit, "--memory-swap", limit)


def capture_go_memory(worker, *, docker_group=True):
    """Refuse a Go worker whose enforced limit is not the approved 16 GiB/zero swap."""
    inspected, host, limits, events = _observe_memory(
        worker, "Go memory container", docker_group=docker_group)
    limit = GO_MEMORY_POLICY["memory_bytes"]
    observed = {"configured_memory_bytes": host.get("Memory"),
                "configured_memory_swap_bytes": host.get("MemorySwap"),
                "effective_memory_bytes": limits["memory.max"],
                "effective_swap_bytes": limits["memory.swap.max"]}
    if observed != {"configured_memory_bytes": limit, "configured_memory_swap_bytes": limit,
                    "effective_memory_bytes": limit, "effective_swap_bytes": 0}:
        raise _refuse("Go worker memory enforcement differs from its approved policy: "
                      + json.dumps(observed, sort_keys=True))
    return {"memory": {"policy": dict(GO_MEMORY_POLICY), "container_id": inspected.get("Id"),
                       "oom_kill_disabled": False, **observed},
            "oom_counters": events}


def normalized_worker_memory_policy(resources):
    """Compare policy from exact runtime bytes, independently of worker placement."""
    from . import worker as W
    if not isinstance(resources, list) or not resources:
        raise _refuse("memory comparison needs bound worker resources")
    with W._seed_verification_scope():
        policies = []
        for resource in resources:
            path = resource["runtime_attestation"]
            if W._sha256_regular_file(path, "memory runtime") != resource["runtime_attestation_sha256"]:
                raise _refuse("memory runtime attestation bytes changed")
            with open(path, encoding="utf-8") as handle:
                attestation = json.load(handle)
            version = W.worker_runtime_version(attestation)
            if version in {"v3", "v4"}:
                checked = W.validate_worker_runtime_v3(resource["worker_spec"])
                if checked["runtime_path"] != os.path.realpath(path) or checked["runtime"] != attestation:
                    raise _refuse("memory evidence differs from its bound worker")
            elif version not in {"v1", "v2"}:
                raise _refuse("unsupported worker memory evidence")
            policies.append(_validate_worker_memory(attestation["memory"])
                            if version == "v4" else None)
        if any(policy != policies[0] for policy in policies[1:]):
            raise _refuse("worker pool has mixed memory policies")
        return policies[0]


def require_prestashop_memory(loaded):
    """New collection requires capped evidence; operator plans own concurrency."""
    from . import worker as W
    if not loaded:
        raise _refuse("new PrestaShop collection requires a memory-bound worker pool")
    for item in loaded:
        if W.worker_runtime_version(item["runtime"]) != "v4":
            raise _refuse("new PrestaShop collection requires memory-bound runtime v4")
        _validate_worker_memory(item["runtime"]["memory"], container_id=item["binding"]["container"]["id"])


def selftest():
    """No Docker: real shell/file observations and native shape/prospective gates."""
    import copy
    from pathlib import Path
    import subprocess
    import tempfile
    from unittest.mock import patch
    from . import worker as W
    from .. import docker_authority as A
    from ..core.ledger_primitives import validate_json_schema

    def refuses(callback):
        try:
            callback()
        except W.WorkerRefused:
            return True
        return False

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / 'memory.max').write_text('4294967296\n')
        (root / 'memory.swap.max').write_text('0\n')
        (root / 'memory.events').write_text('low 0\nhigh 0\nmax 2\noom 1\noom_kill 1\n')
        class LocalShell:
            def run(self, command, timeout):
                command = command.replace('/sys/fs/cgroup/', str(root) + '/')
                return subprocess.run(['/bin/sh', '-c', command], capture_output=True,
                                      text=True, timeout=timeout, env={'PATH': '/nonexistent'})
        worker = W.WorkerSpec(0, str(root / 'work'), 'memory-fixture', '', '',
                             str(root / 'env'), '/work', str(root / 'out'), str(root / 'artifacts'))
        configured = {'Id': 'c' * 64, 'HostConfig': {'Memory': 4294967296,
                       'MemorySwap': 4294967296, 'OomKillDisable': False}}
        with patch.object(W, '_docker_json', return_value=configured), \
                patch.object(W.WorkerSpec, 'runner', return_value=LocalShell()):
            observed = capture_prestashop_memory(worker)
            assert observed['oom_counters']['oom_kill'] == 1
            assert observed['memory']['effective_swap_bytes'] == 0
            configured['HostConfig']['Memory'] = 0
            assert refuses(lambda: capture_prestashop_memory(worker))
            configured['HostConfig']['Memory'] = 4294967296
            (root / 'memory.max').write_text('max\n')
            assert refuses(lambda: capture_prestashop_memory(worker))
            (root / 'memory.max').write_text('4294967296\n')
            (root / 'memory.swap.max').write_text('4294967296\n')
            assert refuses(lambda: capture_prestashop_memory(worker))
            (root / 'memory.swap.max').write_text('0\n')
            configured['HostConfig']['OomKillDisable'] = True
            assert refuses(lambda: capture_prestashop_memory(worker))
            configured['HostConfig']['OomKillDisable'] = False
            (root / 'memory.events').unlink()
            assert refuses(lambda: capture_prestashop_memory(worker))

        memory = observed['memory']
        for field in ['configured_memory_bytes', 'configured_memory_swap_bytes',
                      'effective_memory_bytes', 'effective_swap_bytes']:
            invalid = copy.deepcopy(memory); invalid[field] = 1
            assert refuses(lambda: _validate_worker_memory(invalid))
        invalid = copy.deepcopy(memory); invalid['policy']['swap_bytes'] = False
        assert refuses(lambda: _validate_worker_memory(invalid))
        assert refuses(lambda: _validate_worker_memory(memory, container_id='d' * 64))

        spec_path = root / 'worker0.json'; spec_path.write_text(json.dumps(worker.to_json()))
        spec_sha = W._sha256_regular_file(str(spec_path), 'fixture')
        ref = {'path': str(root / 'binding.json'), 'file_sha256': 'a' * 64, 'digest': 'b' * 64}
        binding = {'worker_index': 0, 'worker_spec_sha256': spec_sha, 'authority': ref,
                   'pool': {'workers': [{'worker_spec_path': str(spec_path),
                      'worker_spec_sha256': spec_sha, 'container_name': worker.container}]},
                   'container': {'name': worker.container, 'id': 'c' * 64, 'image_id': 'sha256:' + 'd' * 64}}
        seed = {'seed_dir': str(root / 'seed'), 'seed_manifest_sha256': 'e' * 64,
                'seed_key': 'fixture', 'workspace_seed_digest': 'f' * 64,
                'database_dump_digest': 'no_database', 'needs_database': False}
        with patch.object(A, 'evidence_reference', return_value=(binding, ref)):
            old = W.build_worker_runtime_attestation(worker, str(spec_path), seed, 21,
                                                    binding_path=ref['path'])
            new = W.build_worker_runtime_attestation(worker, str(spec_path), seed, 21,
                binding_path=ref['path'], memory_evidence=memory)
        assert W.worker_runtime_version(old) == 'v3' and 'memory' not in old
        assert W.worker_runtime_version(new) == 'v4'
        validate_json_schema(old, 'r2t.worker-runtime/v3', label='old runtime')
        validate_json_schema(new, 'r2t.worker-runtime/v4', label='capped runtime')
        loaded = [{'worker': worker, 'spec_path': str(spec_path), 'runtime': old,
                   'binding': {**binding, 'pool': {'workers': [{'worker_spec_path': str(spec_path)}]}}}]
        live_calls = []
        def pool(_paths, *, live):
            if live:
                live_calls.append(True)
                raise AssertionError('uncapped new collection contacted Docker')
            return loaded
        with patch.object(W, 'validate_worker_runtime_v3', return_value=loaded[0]), \
                patch.object(W, '_authority_bound_runtime_attestations', side_effect=pool):
            assert refuses(lambda: W.validate_mutation_runtime([str(spec_path)], [worker],
                seed['seed_dir'], 21, False, project='prestashop'))
            assert refuses(lambda: W.validate_live_worker_runtime(str(spec_path), worker,
                21, False, project='prestashop'))
            from types import SimpleNamespace
            assert refuses(lambda: W.validate_live_worker_runtime(str(spec_path), worker,
                21, False, behat=SimpleNamespace(worker_init='prestashop')))
        assert not live_calls
        loaded[0]['runtime'] = new
        require_prestashop_memory(loaded)  # A K1 consumer/qualification pool still has the same per-worker policy.
    print('  [PASS] PrestaShop memory: configured/effective limits, minimal shell, v3/v4 schemas and no-contact collection gates')
    return 0


if __name__ == '__main__':
    raise SystemExit(selftest())
