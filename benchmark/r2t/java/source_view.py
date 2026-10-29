"""JDK syntax inventory for the shared source-view builder; no subject execution.

The foundation owns BodyRef/BodyEdit, selection normalization and application.
This backend deliberately does not resolve JVM descriptors or admit a project.
"""
from __future__ import annotations

import atexit
import base64
from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import tempfile

from ..toolkit.mutation_java import compile_engine, sanitised_java_env


@dataclass(frozen=True)
class JavaSourceInventory:
    declarations: tuple[dict, ...]
    bodies: tuple
    contract_only_reasons: tuple[str, ...]


@lru_cache(maxsize=None)
def _compiler(java: str, javac: str):
    from ..core.source_view import ViewRefused

    if not Path(java).is_absolute() or not Path(javac).is_absolute():
        raise ViewRefused('Java source views require explicit absolute java/javac paths')
    directory = tempfile.TemporaryDirectory(prefix='r2t_java_source_view_')
    try:
        _, tools_jar = compile_engine(directory.name,
            source=str(Path(__file__).with_name('SourceView.java')), javac=javac)
    except (OSError, RuntimeError) as exc:
        directory.cleanup()
        raise ViewRefused(f'cannot compile Java source-view helper: {exc}') from exc
    atexit.register(directory.cleanup)
    # JDK 8 keeps the compiler API in tools.jar; newer JDKs expose jdk.compiler.
    import os
    classpath = directory.name
    if tools_jar:
        classpath += os.pathsep + tools_jar
    return [java, '-cp', classpath, 'SourceView']


def _inspect(sources: dict[str, bytes], *, java: str, javac: str, parse_only=False):
    from ..core.source_view import ViewRefused

    requests = []
    for path, raw in sources.items():
        try:
            raw.decode('utf-8')
        except UnicodeError as exc:
            raise ViewRefused(f'{path}: Java source must be UTF-8') from exc
        requests.append(base64.b64encode(raw) + b'\n')
    paths = list(sources)
    rows = []
    # Bound helper memory while amortizing JVM startup over actual files.
    for offset in range(0, len(requests), 100):
        batch = requests[offset:offset + 100]
        try:
            result = subprocess.run(
                [*_compiler(java, javac), 'parse' if parse_only else 'inventory'],
                input=b''.join(batch), capture_output=True, env=sanitised_java_env())
        except OSError as exc:
            raise ViewRefused(f'cannot launch Java source parser: {exc}') from exc
        if result.returncode:
            raise ViewRefused('Java source parsing failed: ' +
                              result.stderr.decode('utf-8', errors='replace'))
        found = [json.loads(line) for line in result.stdout.splitlines()]
        if len(found) != len(batch):
            raise ViewRefused('Java source parser did not return every requested file')
        for path, row in zip(paths[offset:offset + 100], found):
            if row.get('error'):
                raise ViewRefused(f'{path}: {row["error"]}')
        rows.extend(found)
    return rows


def source_inventories(sources: dict[str, bytes], *, java: str, javac: str) -> dict[str, JavaSourceInventory]:
    """Inventory supplied subject files in bounded JVM batches, independently of maps.

    Declaration start/end positions are UTF-8 byte offsets in original source;
    J2 can join attributed declarations there. IDs use syntactic parameter
    types, not erased JVM descriptors; colliding callable signatures append
    their declared type parameters and bounds. Contract-only reasons require the
    shared builder's reviewed omission and common supplement before admission.
    """
    from ..core.source_view import BodyEdit, BodyRef

    inventories = {}
    for path, row in zip(sources, _inspect(sources, java=java, javac=javac)):
        edits = tuple(BodyEdit(BodyRef(path, e['declaration_id'], e['kind'],
                                       e['start_byte'], e['end_byte']),
                               e['replacement'].encode('utf-8'))
                      for e in row['bodies'])
        inventories[path] = JavaSourceInventory(
            tuple(row['declarations']), edits, tuple(row['contract_only_reasons']))
    return inventories


def source_inventory(path: str, raw: bytes, *, java: str, javac: str) -> JavaSourceInventory:
    return source_inventories({path: raw}, java=java, javac=javac)[path]


def source_bodies(path: str, raw: bytes, *, java: str, javac: str) -> tuple:
    """Shared dispatcher seam: callable bodies AND executable initializers.

    Nested bodies remain in the inventory. The shared builder already removes
    contained edits when an enclosing body is selected; do not flatten this
    inventory into only outer methods or the union of item target selections.
    """
    from ..core.source_view import ViewRefused

    result = source_inventory(path, raw, java=java, javac=javac)
    if result.contract_only_reasons:
        raise ViewRefused(f'{path}: use reviewed contract_only omission: ' +
                          '; '.join(result.contract_only_reasons))
    return result.bodies


def parse_source(path: str, raw: bytes, *, java: str, javac: str) -> None:
    """Parse transformed bytes only: never analyze, generate or load subject code."""
    parse_sources({path: raw}, java=java, javac=javac)


def parse_sources(sources: dict[str, bytes], *, java: str, javac: str) -> None:
    """Parse every transformed file in bounded batches without attribution."""
    _inspect(sources, java=java, javac=javac, parse_only=True)
