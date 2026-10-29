"""Read Go's original inventory from its already authenticated worker seed."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile

from ..bench import seed
from .execution import _path
from .registry import _require


def seed_inventory(runtime):
    """Bind the bytes read here to existing v3 identities, never to a live scan.

    The caller first authenticates runtime with validate_worker_runtime_v3.
    Reading the archive into immutable bytes keeps the member inventory tied
    to the same archive digest even if its pathname is subsequently replaced.
    Go's reviewed seed policy recreates no files after extraction.
    """
    root = Path(runtime['seed_dir'])
    manifest = (root / seed.SEED_MANIFEST).read_bytes()
    _require(hashlib.sha256(manifest).hexdigest() == runtime['seed_manifest_sha256'],
             'Go seed manifest changed after worker validation')
    document = json.loads(manifest)
    _require(seed.SeedRules.from_manifest(document) == seed.GO_RULES
             and document['rules_digest'] == seed.GO_RULES.digest(),
             'worker seed does not use the reviewed Go rules')
    raw = (root / seed.WORKSPACE_TAR).read_bytes()
    _require(hashlib.sha256(raw).hexdigest() == runtime['workspace_seed_digest'],
             'Go seed archive changed after worker validation')
    inventory = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            path = _path(member.name)
            _require(member.isfile() or member.isdir(),
                     'Go seed archive requires regular files and directories')
            if member.isdir():
                continue
            _require(path not in inventory, 'duplicate Go seed archive file')
            with archive.extractfile(member) as source:
                inventory[path] = hashlib.sha256(source.read()).hexdigest()
    return inventory


def load_worker_workspace(args):
    """Return manifest/boundary/runner/seed/runtime before closures exist.

    This is host-only authentication. A caller that will execute must also use
    the existing live worker validation before any container operation.
    """
    from ..bench import repo
    from ..bench.harness import DockerRunner
    from ..bench.validate import HARNESS_VERSION
    from ..bench.worker import validate_worker_runtime_v3
    from ..core.boundary import load_boundary

    _require(getattr(args, 'worker', None), 'Go operation requires a bound --worker')
    bound = validate_worker_runtime_v3(args.worker, needs_database=False,
                                      harness_version=HARNESS_VERSION)
    worker = bound['worker']
    boundary = load_boundary(args.boundary, repo_root=getattr(args, 'repo', None))
    root = Path(boundary.repo_root).resolve()
    _require(root == Path(worker.workspace).resolve()
             and args.container == worker.container
             and args.workdir == worker.workdir == '/work',
             'Go workspace/container/workdir differs from the bound worker')
    _require(root.is_dir(), 'Go worker workspace does not exist')
    artifacts = Path(args.artifacts).resolve()
    _require(artifacts == Path(worker.artifacts_root).resolve(),
             'Go artifacts must belong to the bound worker')
    gold = Path(args.gold).resolve()
    manifest_path = gold / 'strip_manifest.json'
    _require(manifest_path.is_file(), 'Go operation requires its preserved strip manifest')
    manifest = repo.load_manifest(str(manifest_path))
    manifest.repo_root, manifest.gold_root = str(root), str(gold)
    return (manifest, boundary, DockerRunner(worker.container, workdir=worker.workdir),
            seed_inventory(bound['runtime']), bound)
