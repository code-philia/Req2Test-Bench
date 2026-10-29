"""Resolve a reviewed target body map to the COVERED LINES a metric can read.

`TARGET_INTERFACES_V2_SPEC` section 6.2 measures recall of gold's covered
lines inside the item's reviewed target bodies.  The maps carry
`{path, declaration_id, kind}` and nothing else: the spans are resolved at
view-preparation time (`toolkit.source_views`) into `BodyRef.start_byte` /
`end_byte` against the pinned source seed, i.e. BYTE offsets, while coverage
is line-keyed.  This module is the one place that crosses that gap.

It is a toolkit verb rather than a metrics function on purpose.  Resolving
the spans needs the language body parsers (`ast` for Python, tree-sitter for
PHP, a compiler for Java); `bench/metrics.py` must stay a consumer of the
artifact this writes, or the consumer route and the self-test's process
budget acquire a parser dependency for a secondary row.

The artifact binds itself to the inputs a reader would have to re-derive it
from: the map's own schema and file digest, and the seed identity the map
names.  Those three are the reason a consumer can say the line numbers mean
what the map says -- a different source seed silently shifts every one of
them -- and they are recorded rather than recomputed downstream.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..bench.metrics import TARGET_REGIONS_SCHEMA as SCHEMA
from ..core.ledger_primitives import loads_exact_json
from ..core.source_view import (
    ViewRefused, _source_bytes, qualify_source_seed,
)
from .source_views import MAP_SCHEMAS, source_bodies


def _line_starts(raw: bytes) -> list[int]:
    """Byte offset of every line's first byte, 1-based line `n` at index n-1."""
    starts = [0]
    for line in raw.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    return starts


def span_lines(raw: bytes, starts: list[int], start: int, end: int) -> set[int]:
    """The 1-based lines a body span actually occupies.

    A line counts when the span holds a NON-WHITESPACE byte of it.  That rule
    is what keeps the declaration line out of the region: a Python body span
    begins just after the `def ...:` colon and a PHP one just after the `{`,
    so both open with that line's newline and nothing else.  The declaration
    line matters here because coverage records it once at import (or class
    load) for every item in the project, so counting it would put a line
    every sibling covers into the region it is supposed to discriminate.
    A one-line body (`def f(self): return 1`) keeps its line, because there
    the span does hold `return 1`.
    """
    lines = set()
    for index in range(len(starts) - 1):
        first, last = starts[index], starts[index + 1]
        if last <= start:
            continue
        if first >= end:
            break
        if raw[max(first, start):min(last, end)].strip():
            lines.add(index + 1)
    return lines


def resolve_regions(*, map_path: str, source_root: str,
                    readable_paths: tuple[str, ...], project: str,
                    java: str | None = None, javac: str | None = None,
                    go: str | None = None, go_contexts: dict | None = None,
                    go_scratch: str | None = None) -> dict:
    """The `r2t.target-regions/1` artifact for one reviewed map.

    Bound to the seed the map names: the inventory of `source_root` under
    `readable_paths` must reproduce the map's `source_files_digest`, and each
    file's bytes are re-verified against that inventory as they are read
    (`_source_bytes`).  A map resolved against a different tree would still
    find most declarations and would silently return other line numbers, so
    the mismatch is a refusal here rather than a caveat downstream.
    """
    raw_map = Path(map_path).read_bytes()
    doc = loads_exact_json(raw_map, label="target body map")
    # Both map schemas, from the one table `toolkit.source_views` reads, so
    # the two readers cannot drift apart on which maps exist.  The v2 revision
    # renamed the item's interface annotation; regions come from `bodies`,
    # which that revision did not touch.
    if doc.get("schema") not in MAP_SCHEMAS:
        raise ViewRefused(
            f"{map_path}: expected one of {', '.join(sorted(MAP_SCHEMAS))}, "
            f"got {doc.get('schema')!r}")
    if doc.get("project") != project:
        raise ViewRefused(
            f"{map_path}: map project {doc.get('project')!r} is not {project!r}")
    seed = qualify_source_seed(root=source_root, project=project,
                               runtime_seed_digest=doc["runtime_seed_digest"],
                               readable_paths=readable_paths)
    if seed.files_digest != doc["source_files_digest"]:
        raise ViewRefused(
            f"{source_root} is not the source seed this map names: inventory "
            f"digest {seed.files_digest} against the map's "
            f"{doc['source_files_digest']}. The map's declarations resolve to "
            f"byte spans in THOSE bytes; another tree yields other line "
            f"numbers for the same declaration.")
    if project == "coddy-agent":
        from ..go.source_view import _context
        from .source_views import _outside_go_scratch
        if not isinstance(go_contexts, dict) or not go_contexts:
            raise ViewRefused('Go target regions require released per-item suite contexts')
        go_contexts = {iid: _context(context) for iid, context in go_contexts.items()}
        _outside_go_scratch(go_scratch, source_root)
    records = {record.path: record for record in seed.files}
    parsed: dict[str, tuple] = {}
    texts: dict[str, tuple[bytes, list[int]]] = {}
    items: dict[str, dict[str, list[int]]] = {}
    for item in doc["items"]:
        item_id = item["item_id"]
        if item_id in items:
            raise ViewRefused(f"duplicate map item: {item_id}")
        context = None
        if project == "coddy-agent":
            context = go_contexts.get(item_id)
            if context is None:
                raise ViewRefused(f'map item lacks its released Go context: {item_id}')
        region: dict[str, set[int]] = {}
        for body in item["bodies"]:
            path = body["path"]
            if path not in records:
                raise ViewRefused(
                    f"{item_id}: target body path is outside the seed: {path}")
            if path.endswith('.go'):
                # Re-resolve for this item's build tags; a path-only cache can
                # wrongly admit a file inactive in a later suite.
                raw = _source_bytes(seed, records[path])
                texts[path] = (raw, _line_starts(raw))
                resolved = source_bodies(path, raw, go=go, go_context=context,
                                         go_scratch=go_scratch)
            else:
                if path not in parsed:
                    raw = _source_bytes(seed, records[path])
                    texts[path] = (raw, _line_starts(raw))
                    parsed[path] = source_bodies(path, raw, java=java, javac=javac)
                resolved = parsed[path]
            matches = [edit for edit in resolved
                       if edit.body.declaration_id == body["declaration_id"]
                       and edit.body.kind == body["kind"]]
            if len(matches) != 1:
                raise ViewRefused(
                    f"{item_id}: no unique concrete body: {path}: "
                    f"{body['declaration_id']} ({body['kind']})")
            raw, starts = texts[path]
            ref = matches[0].body
            region.setdefault(path, set()).update(
                span_lines(raw, starts, ref.start_byte, ref.end_byte))
        items[item_id] = {path: sorted(lines)
                          for path, lines in sorted(region.items()) if lines}
    empty = sorted(iid for iid, region in items.items() if not region)
    return {
        "schema": SCHEMA,
        "project": project,
        "map_schema": doc["schema"],
        "map_file_sha256": hashlib.sha256(raw_map).hexdigest(),
        "source_files_digest": doc["source_files_digest"],
        "runtime_seed_digest": doc["runtime_seed_digest"],
        "summary": {
            "n_items": len(items),
            "n_items_without_region": len(empty),
            "items_without_region": empty,
            "n_region_lines": sum(len(lines) for region in items.values()
                                  for lines in region.values()),
            "n_region_files": len({path for region in items.values()
                                   for path in region}),
        },
        "items": items,
    }


def write_regions(document: dict, out: str) -> str:
    with open(out, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=1, sort_keys=True)
        stream.write("\n")
    return out


# --------------------------------------------------------------------------
# selftest

def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    import tempfile
    from .. import __file__ as package_file
    from ..bench import metrics as M

    examples = Path(package_file).resolve().parents[1] / "examples/source_views"
    document = resolve_regions(
        map_path=str(examples / "map.json"),
        source_root=str(examples / "source"),
        readable_paths=("src",), project="python-docx")
    check("the shipped example map resolves against its own source",
          document["schema"] == SCHEMA and document["items"], str(document))
    region = document["items"]["fixture/generated.feature:3"]
    raw = (examples / "source/src/api.py").read_bytes().decode()
    lines = raw.splitlines()
    body = region["src/api.py"]
    check("the resolved region is the body's lines",
          body and all(lines[n - 1].strip() for n in body), str(region))
    check("the declaration line is NOT in the region -- coverage records it "
          "at import for every item, so it discriminates nothing",
          not any(lines[n - 1].lstrip().startswith("def ") for n in body),
          "\n".join(f"{n}: {lines[n - 1]}" for n in body))

    # The v2 map revision renamed only the item's interface annotation
    # (`target_interfaces` -> `checked_interfaces`).  Regions are resolved
    # from `bodies` alone, which it did not touch, so the same declarations
    # must give the same lines -- and until the verb accepts the schema, the
    # section 6.2 rows cannot be produced from a v2 map at all.
    v2_path = examples / "map.v2.json"
    v2 = resolve_regions(map_path=str(v2_path),
                         source_root=str(examples / "source"),
                         readable_paths=("src",), project="python-docx")
    check("a v2 target body map resolves to the same regions as its v1 twin",
          v2["items"] == document["items"], str(v2["items"]))
    check("the artifact records the map's OWN schema and file digest",
          v2["map_schema"] == "r2t.target-body-map/v2"
          and v2["map_file_sha256"] == hashlib.sha256(
              v2_path.read_bytes()).hexdigest(),
          f'{v2["map_schema"]} {v2["map_file_sha256"]}')

    with tempfile.TemporaryDirectory() as scratch:
        out = write_regions(document, str(Path(scratch) / "regions.json"))
        loaded = M.load_target_regions(out)
        check("the artifact round-trips into the metric's line sets",
              loaded["fixture/generated.feature:3"]["src/api.py"] == set(body))
        # A map resolved against the wrong tree finds the same declarations
        # and returns different line numbers, so the seed binding is the
        # whole guarantee: it must refuse, not caveat.
        other = Path(scratch) / "source"
        other.mkdir()
        (other / "src").mkdir()
        (other / "src/api.py").write_text("# shifted\n" + raw)
        try:
            resolve_regions(map_path=str(examples / "map.json"),
                            source_root=str(other), readable_paths=("src",),
                            project="python-docx")
            check("a different source tree refuses", False, "no exception")
        except ViewRefused as exc:
            check("a source tree that is not the map's seed REFUSES rather "
                  "than returning shifted line numbers",
                  "is not the source seed this map names" in str(exc),
                  str(exc))
        try:
            resolve_regions(map_path=str(examples / "map.json"),
                            source_root=str(examples / "source"),
                            readable_paths=("src",), project="coreshop")
            check("a map read for another project refuses", False,
                  "no exception")
        except ViewRefused as exc:
            check("a map read under another project's name refuses",
                  "is not 'coreshop'" in str(exc), str(exc))

    # The verb's Java branch.  A `.java` body span comes from a compiler, so
    # a Java map resolves only when the CLI hands `resolve_regions` the JDK --
    # the same launch input every other Java-map consumer already takes.
    import io
    import os
    from contextlib import redirect_stdout
    from types import SimpleNamespace

    java_home = os.environ.get("JAVA_HOME")
    if not (java_home and Path(java_home, "bin/javac").exists()):
        print("  [SKIP] the Java branch of `target-regions`: JAVA_HOME names "
              "no javac, so a Java body map could not be resolved")
    else:
        from . import cli
        prefix = "src/main/java/com/algorand/algosdk/"
        java_source = (b"package com.algorand.algosdk;\n"
                       b"public class Fixture {\n"
                       b"    public int value(int x) {\n"
                       b"        int y = x + 42;\n"
                       b"        return y;\n"
                       b"    }\n"
                       b"}\n")
        readable = ("src", "pom.xml")
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            tree = root / "source"
            (tree / prefix).mkdir(parents=True)
            (tree / prefix / "Fixture.java").write_bytes(java_source)
            (tree / "pom.xml").write_bytes(b"<project/>\n")
            seed = qualify_source_seed(root=str(tree), project="algorand-sdk",
                                       runtime_seed_digest="a" * 64,
                                       readable_paths=readable)
            java_map = root / "map.json"
            java_map.write_text(json.dumps({
                "schema": "r2t.target-body-map/v1", "project": "algorand-sdk",
                "runtime_seed_digest": "a" * 64,
                "source_files_digest": seed.files_digest,
                "items": [{"item_id": "fixture/java.feature:1", "bodies": [
                    {"path": prefix + "Fixture.java", "kind": "method",
                     "declaration_id":
                         "com.algorand.algosdk.Fixture#value(int)"}]}]}))
            # The falsifier: this is the call the verb used to make.  Without
            # java/javac the very same map refuses, so what the CLI route
            # below exercises is the Java parser and not Python's.
            try:
                resolve_regions(map_path=str(java_map), source_root=str(tree),
                                readable_paths=readable, project="algorand-sdk")
                check("a Java map resolved without java/javac refuses", False,
                      "no exception")
            except ViewRefused as exc:
                check("a Java body map resolved without java/javac REFUSES, "
                      "so the CLI route below is the Java branch",
                      "explicit absolute java/javac paths" in str(exc), str(exc))
            out = str(root / "java-regions.json")
            profile_path = str(Path(package_file).resolve().parents[1]
                               / "config"
                               / "profile_algorand_visibility_target_hidden.yml")
            try:
                with redirect_stdout(io.StringIO()):
                    code = cli.cmd_target_regions(SimpleNamespace(
                        map=str(java_map), source_root=str(tree),
                        profile=profile_path, out=out))
                java_regions = json.loads(Path(out).read_text())["items"]
            except SystemExit as exc:
                # A refusal here is this check's failure, not the run's.
                code, java_regions = 1, {"exit": str(exc)}
            check("`target-regions` resolves a Java body map with the JDK "
                  "JAVA_HOME names, like every other Java-map consumer",
                  code == 0
                  and java_regions.get("fixture/java.feature:1", {}).get(
                      prefix + "Fixture.java") == [3, 4, 5, 6],
                  str(java_regions))

    # Real Go spans through the CLI, with a second item's different tags.
    import shutil
    from . import cli
    from ..go.source_view_selftest import context
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        tree = root / 'source'
        for directory in ('cmd', 'internal', 'external', 'features'):
            (tree / directory).mkdir(parents=True)
        (tree / 'go.mod').write_text('module fixture\n')
        (tree / 'go.sum').write_text('')
        path = 'internal/api.go'
        (tree / path).write_text('//go:build http\n\npackage p\nfunc API() {\n    secret()\n}\n')
        seed = qualify_source_seed(root=str(tree), project='coddy-agent',
                                   runtime_seed_digest='a' * 64,
                                   readable_paths=('cmd', 'internal', 'external', 'features', 'go.mod', 'go.sum'))
        item = {'item_id': 'fixture/go.feature:3', 'bodies': [
            {'path': path, 'kind': 'function', 'declaration_id': 'p#API'}]}
        mapping = {'schema': 'r2t.target-body-map/v2', 'project': 'coddy-agent',
                   'runtime_seed_digest': 'a' * 64, 'source_files_digest': seed.files_digest,
                   'items': [item]}
        map_path = root / 'map.json'
        map_path.write_text(json.dumps(mapping))
        release = root / 'items.jsonl'
        release.write_text(json.dumps({'item_id': item['item_id'],
                                       'go_suite': context(['http'])}) + '\n')
        args = SimpleNamespace(map=str(map_path), source_root=str(tree),
            profile=str(Path(package_file).resolve().parents[1] / 'config' /
                        'profile_coddy_agent_checked_interfaces_target_hidden.yml'),
            out=str(root / 'regions.json'), release=str(release),
            go=shutil.which('go'), go_scratch=str(root / 'trusted-scratch'))
        with redirect_stdout(io.StringIO()):
            code = cli.cmd_target_regions(args)
        regions = json.loads(Path(args.out).read_text())['items']
        check('Go CLI resolves real tagged body spans using released context',
              code == 0 and regions[item['item_id']][path] == [4, 5, 6], str(regions))
        mapping['items'].append({**item, 'item_id': 'fixture/go.feature:9'})
        map_path.write_text(json.dumps(mapping))
        with release.open('a') as stream:
            stream.write(json.dumps({'item_id': 'fixture/go.feature:9',
                                     'go_suite': context()}) + '\n')
        try:
            cli.cmd_target_regions(args)
            check('later Go suite cannot reuse an earlier active-file resolution', False)
        except SystemExit as exc:
            check('later Go suite cannot reuse an earlier active-file resolution',
                  'inactive' in str(exc), str(exc))
        args.release = None
        try:
            cli.cmd_target_regions(args)
            check('Go CLI requires released contexts', False)
        except SystemExit as exc:
            check('Go CLI requires released contexts', '--release' in str(exc), str(exc))

    # The span-to-line rule itself, on the two shapes that decide it.
    source = (b"class C:\n    def one(self): return 1\n\n"
              b"    def two(self):\n        x = 2\n        return x\n")
    starts = _line_starts(source)
    one = source.index(b"return 1") - 1
    check("a one-line body keeps its declaration line, because the span "
          "holds that line's code",
          span_lines(source, starts, one, one + len(b" return 1\n")) == {2},
          str(span_lines(source, starts, one, one + len(b" return 1\n"))))
    two = source.index(b"\n        x = 2")
    check("a suite body starts at its first statement, not at `def`",
          span_lines(source, starts, two, len(source)) == {5, 6},
          str(span_lines(source, starts, two, len(source))))

    print("ALL PASS (target_regions)" if ok else "FAILURES (target_regions)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
