"""Compiler-attributed declared interactions for approved Java/Cucumber inputs.

Registry locations select original methods. T1/T2, referenced field types (T3),
explicit body type uses (T5), and closure-local removable helper calls (T6)
produce the existing type-level interfaces artifact. Production calls never
expand the surface. J1 remains the owner of source-body IDs and replacement.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

from ..core.boundary import PRODUCTION, REMOVABLE
from .interfaces import (
    EMPTY_NO_DECLARATION, EMPTY_NO_MEMBER, InterfacesError, ItemInterfaces,
    extract_all, summary, write_interfaces,
)
from .mutation_java import compile_engine, sanitised_java_env

ATTRIBUTION_SCHEMA = "r2t.java-attribution/1"
JAVA_SOURCE = Path(__file__).resolve().parents[1] / "java" / "AttributeInterfaces.java"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def attribute_sources(source_root, source_paths, *, java, javac,
                      classpath=(), sourcepath=(), output_root, release=8,
                      production_paths=()) -> dict:
    """Attribute original source without generating or executing subject code.

    Both JDK executables and ordered dependency paths are explicit coordinator
    inputs. ``output_root`` must be absent; diagnostic output survives refusal.
    The per-source identities are consumed by the extractor's freshness check.
    """
    root, out = Path(source_root).resolve(), Path(output_root).absolute()
    if not Path(java).is_absolute() or not Path(javac).is_absolute():
        raise InterfacesError("REFUSED: Java attribution needs explicit absolute java/javac paths")
    if isinstance(release, bool) or release not in (8, 17):
        raise InterfacesError("REFUSED: Java attribution supports only release 8 or 17")
    paths = list(source_paths)
    if not paths or len(paths) != len(set(paths)):
        raise InterfacesError("REFUSED: original Java source inventory is empty or duplicated")
    paths = sorted(paths)
    if any(Path(p).is_absolute() or '..' in Path(p).parts or not p.endswith('.java') for p in paths):
        raise InterfacesError("REFUSED: Java source inventory needs relative .java paths")
    production_paths = list(production_paths)
    if len(production_paths) != len(set(production_paths)) \
            or production_paths != sorted(production_paths):
        raise InterfacesError(
            "REFUSED: production Java authority is duplicated or unordered")
    if set(paths) & set(production_paths):
        raise InterfacesError(
            "REFUSED: compiler and production-authority inventories overlap")
    if any(Path(p).is_absolute() or '..' in Path(p).parts
           or not p.endswith('.java') for p in production_paths):
        raise InterfacesError(
            "REFUSED: production Java authority needs relative .java paths")
    source_files, production_source_files = [], []
    try:
        for path in paths:
            raw = (root / path).read_bytes()
            source_files.append({'path': path, 'sha256': _sha(raw), 'bytes': len(raw)})
        for path in production_paths:
            raw = (root / path).read_bytes()
            production_source_files.append(
                {'path': path, 'sha256': _sha(raw), 'bytes': len(raw)})
        out.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise InterfacesError(f"REFUSED: Java attribution input/output: {exc}") from exc
    deps = [str(Path(p).resolve()) for p in classpath]
    source_roots = [str(Path(p).resolve()) for p in sourcepath]
    for path in deps:
        if not Path(path).is_file():
            raise InterfacesError(f"REFUSED: missing Java classpath input: {path}")
    for path in source_roots:
        if not Path(path).is_dir():
            raise InterfacesError(f"REFUSED: missing Java sourcepath input: {path}")
    file_list = out / 'sources.txt'
    file_list.write_text(''.join(p + '\n' for p in paths), encoding='utf-8')
    classes = out / 'helper-classes'
    try:
        _, tools_jar = compile_engine(str(classes), source=str(JAVA_SOURCE), javac=str(javac))
        helper_cp = str(classes) + (os.pathsep + tools_jar if tools_jar else '')
        # Empty path strings mean cwd to javac; use an explicit absent directory.
        argv = [str(java), '-XX:-UsePerfData', '-cp', helper_cp, 'AttributeInterfaces',
                str(root), os.pathsep.join(deps) or str(out / 'empty-classpath'),
                os.pathsep.join(source_roots) or str(out / 'empty-sourcepath'), str(file_list)]
        if release != 8:
            argv.append(str(release))
        run = subprocess.run(argv, capture_output=True, env=sanitised_java_env())
    except (OSError, RuntimeError) as exc:
        raise InterfacesError(f"REFUSED: Java attribution helper: {exc}") from exc
    (out / 'stdout.jsonl').write_bytes(run.stdout)
    (out / 'stderr.txt').write_bytes(run.stderr)
    if run.returncode:
        raise InterfacesError("REFUSED: unresolved Java attribution: " +
                              run.stderr.decode('utf-8', errors='replace')[-6000:])
    try:
        records = [json.loads(line) for line in run.stdout.splitlines()]
        metadata = records.pop(0)
        if metadata.get('record') != 'metadata':
            raise ValueError('missing compiler metadata')
    except (ValueError, IndexError) as exc:
        raise InterfacesError("REFUSED: malformed Java attribution helper output") from exc
    recipe_level = ({'source_level': '8'} if release == 8
                    else {'release': str(release)})
    doc = {'schema': ATTRIBUTION_SCHEMA, 'source_root': str(root),
           'source_files': source_files, 'declarations': records,
           'methods': [r for r in records if r['kind'] in ('method', 'constructor')],
           'recipe': {'java': str(java), 'javac': str(javac), **recipe_level,
                      'classpath': [{'path': p, 'sha256': _sha(Path(p).read_bytes())} for p in deps],
                      'sourcepath': source_roots, 'module_path': [], 'processing': 'disabled',
                      'helper_sha256': _sha(JAVA_SOURCE.read_bytes()), 'argv': argv,
                      'java_runtime_version': metadata['java_runtime_version'],
                      'java_vendor': metadata['java_vendor']}}
    if production_source_files:
        doc['production_source_files'] = production_source_files
    (out / 'attribution.json').write_text(json.dumps(doc, sort_keys=True, indent=1) + '\n')
    return doc


class JavaInterfaceExtractor:
    def __init__(self, attribution: dict, prod_index: dict, boundary):
        if attribution.get('schema') != ATTRIBUTION_SCHEMA:
            raise InterfacesError("REFUSED: expected compiler-attributed Java source")
        self.boundary = boundary
        self.methods = {}
        self.locations = {}
        root = Path(attribution['source_root'])
        for record in [*attribution['source_files'],
                       *attribution.get('production_source_files', [])]:
            try:
                current = (root / record['path']).read_bytes()
            except OSError as exc:
                raise InterfacesError(f"REFUSED: missing attributed source {record['path']}") from exc
            if _sha(current) != record['sha256']:
                raise InterfacesError(f"REFUSED: stale attributed source {record['path']}")
        for method in attribution['methods']:
            if method['key'] in self.methods:
                raise InterfacesError(f"REFUSED: duplicate attributed member {method['key']}")
            self.methods[method['key']] = method
            self.locations.setdefault(method['registry_location'], []).append(method)
        declared, declared_paths = {}, {}
        for path, file in prod_index['files'].items():
            for cls in file.get('classes', []):
                declared[cls['name']] = path
                declared_paths.setdefault(cls['name'], set()).add(path)
        # Types are normalized by javac, not by splitting a binary name.
        self.first_party = set()
        production_records = attribution.get('production_source_files')
        if production_records is None:
            for record in attribution['declarations']:
                if record['kind'] != 'type':
                    continue
                name = record['top_level_name']
                path = declared.get(name)
                if path == record['path'] \
                        and boundary.classify(record['path']) == PRODUCTION:
                    self.first_party.add(name)
        else:
            if boundary.project != 'kapua' or not production_records:
                raise InterfacesError(
                    "REFUSED: detached production authority is Kapua-only")
            authority = {record['path'] for record in production_records}
            if len(authority) != len(production_records) \
                    or any(boundary.classify(path) != PRODUCTION
                           or path not in prod_index['files'] for path in authority):
                raise InterfacesError(
                    "REFUSED: detached Kapua production authority differs "
                    "from its production index/boundary")
            candidates = set()
            for method in attribution['methods']:
                for edge in ('declared_types', 'field_types',
                             'explicit_types'):
                    candidates.update(method[edge])
            for name in candidates:
                paths = declared_paths.get(name)
                if not paths:
                    continue
                if len(paths) != 1:
                    raise InterfacesError(
                        f"REFUSED: production type {name} has multiple "
                        "original declarations")
                path = next(iter(paths))
                if boundary.classify(path) != PRODUCTION:
                    continue
                if path not in authority:
                    raise InterfacesError(
                        f"REFUSED: production type {name} is outside the "
                        "selected original authority")
                self.first_party.add(name)

    def _surface(self, start: dict, files: set[str]):
        found, seen, witnesses = set(), set(), []
        todo = [start['key']]
        while todo:
            key = todo.pop()
            if key in seen:
                continue
            seen.add(key)
            method = self.methods[key]
            for edge in ('declared_types', 'field_types', 'explicit_types'):
                found.update(method[edge])
            witnesses.append({'key': key, 'path': method['path'],
                              'start_byte': method['start_byte'], 'end_byte': method['end_byte']})
            for callee in method['calls']:
                path = method['call_sources'].get(callee)
                if path not in files or self.boundary.classify(path) != REMOVABLE:
                    continue
                if callee in method['implicit_calls']:
                    continue  # no source helper body; construction type is already T5
                if callee not in self.methods:
                    raise InterfacesError(f"REFUSED: unresolved closure helper {callee} in {path}")
                todo.append(callee)
        return found, witnesses

    def for_item(self, closure: dict) -> ItemInterfaces:
        item = ItemInterfaces(closure['item_id'], closure['feature_file'], closure['scenario_line'])
        groups = {'scenario': set(), 'background': set()}
        seen = set()
        files = set(closure['files'])
        for step in closure.get('steps', []):
            if step.get('side') != REMOVABLE:
                continue
            origin = step.get('origin')
            definition = step.get('definition') or {}
            path, location = definition.get('file'), step.get('location')
            if origin not in groups or path not in files or self.boundary.classify(path) != REMOVABLE:
                raise InterfacesError(f"REFUSED: invalid registry binding for {item.item_id}: {location}")
            matches = [m for m in self.locations.get(location, []) if m['path'] == path]
            if len(matches) != 1:
                raise InterfacesError(f"REFUSED: no unique attributed registry member {location} in {path}")
            method = matches[0]
            key = (origin, method['key'])
            if key in seen:
                continue
            seen.add(key)
            surface, witnesses = self._surface(method, files)
            groups[origin].update(surface)
            item.members.append({'location': location, 'file': path, 'origin': origin,
                                 'key': method['key'], 'declarations': witnesses})
        scenario, background = groups['scenario'], groups['background']
        item.candidates = {'behaviour': sorted(scenario), 'setup': sorted(background - scenario)}
        item.behaviour = sorted(scenario & self.first_party)
        item.setup = sorted((background & self.first_party) - set(item.behaviour))
        if not item.behaviour:
            item.empty_reason = (EMPTY_NO_DECLARATION if any(m['origin'] == 'scenario' for m in item.members)
                                 else EMPTY_NO_MEMBER)
        return item


def annotated_rows(original_bytes: bytes, annotations: dict) -> bytes:
    """Insert only the annotation field; never reserialize historical fields."""
    output, ids = [], []
    for line in original_bytes.splitlines(keepends=True):
        if not line.strip():
            output.append(line)
            continue
        try:
            row = json.loads(line)
            iid = row['item_id']
            annotation = annotations[iid]
        except (ValueError, KeyError, TypeError) as exc:
            raise InterfacesError('REFUSED: task row or its annotation is missing/malformed') from exc
        if iid in ids or 'target_interfaces' in row:
            raise InterfacesError(f'REFUSED: duplicate or already annotated item {iid}')
        if not isinstance(annotation, dict) or set(annotation) != {'behaviour', 'setup'}:
            raise InterfacesError(f'REFUSED: malformed target_interfaces for {iid}')
        for values in annotation.values():
            if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values) \
                    or values != sorted(set(values)):
                raise InterfacesError(f'REFUSED: annotation is not a sorted unique type list for {iid}')
        if set(annotation['behaviour']) & set(annotation['setup']):
            raise InterfacesError(f'REFUSED: overlapping annotation origins for {iid}')
        end = len(line.rstrip(b' \t\r\n')) - 1
        if line[end:end + 1] != b'}':
            raise InterfacesError(f'REFUSED: task is not a JSON object for {iid}')
        addition = json.dumps(annotation, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        output.append(line[:end] + b',"target_interfaces":' + addition + line[end:])
        ids.append(iid)
    if set(ids) != set(annotations):
        raise InterfacesError('REFUSED: annotations do not cover exactly the ordered task population')
    return b''.join(output)


KAPUA_CLASSPATH_SCHEMA = "r2t.kapua-interface-classpaths/1"


def kapua_interface_partitions(source_root, source_paths, closures, prod_index,
                               boundary, envelope):
    """Select original sources using each item's measured native suite recipe.

    Directory outputs are validated as the exact suite's two leading entries.
    Attribution consumes original sources and the exported dependency JARs;
    compiler runs sharing identical native classpaths may share one partition.
    No dependency union is formed across differing suite classpaths.
    """
    from ..java import kapua

    source_paths = list(source_paths)
    if boundary.project != "kapua" or not isinstance(envelope, dict) \
            or envelope.get("schema") != KAPUA_CLASSPATH_SCHEMA \
            or envelope.get("source_commit") != kapua.SOURCE_COMMIT:
        raise InterfacesError("REFUSED: expected pinned Kapua suite classpaths")
    if len(source_paths) != len(set(source_paths)) \
            or source_paths != sorted(source_paths):
        raise InterfacesError(
            "REFUSED: Kapua original source input is duplicated or unordered")
    suites = {suite.runner_package + "." + suite.upstream_runner_class: suite
              for suite in kapua.SUITES}
    rows = envelope["suites"]
    names = [row["runner"] for row in rows]
    if names != list(suites):
        raise InterfacesError(
            "REFUSED: Kapua classpaths must cover the 17 native runners "
            "in pinned order")
    root = Path(source_root).resolve()
    mapping = kapua.code_source_map(str(root), boundary)
    groups, by_runner, checked_jars = {}, {}, {}
    for row in rows:
        captures = row["native_classpaths"]
        if set(captures) != {"ordinary", "dry", "stripped_dry"} \
                or len(set(captures.values())) != 1:
            raise InterfacesError("REFUSED: Kapua runner triplet classpaths differ")
        native = captures["ordinary"]
        try:
            verified = kapua.verify_code_source_classpath(
                str(root), suites[row["runner"]], native, mapping)
        except ValueError as exc:
            raise InterfacesError("REFUSED: " + str(exc)) from exc
        entries = (native[:-1] if native.endswith(":") else native).split(":")
        jars = row["jars"]
        if [entry["origin"] for entry in jars] != entries[2:]:
            raise InterfacesError("REFUSED: exported JAR order differs from the native classpath")
        dependencies = []
        for entry in jars:
            path = Path(entry["path"])
            if not path.is_absolute() or not path.is_file():
                raise InterfacesError("REFUSED: missing exported Kapua dependency JAR")
            absolute = str(path.resolve())
            if absolute not in checked_jars:
                checked_jars[absolute] = _sha(path.read_bytes())
            if checked_jars[absolute] != entry["sha256"]:
                raise InterfacesError("REFUSED: exported Kapua JAR differs from its captured identity")
            dependencies.append(absolute)
        identity = [(entry["origin"], entry["sha256"]) for entry in jars]
        if native in groups:
            group = groups[native]
            if group["jar_identities"] != identity:
                raise InterfacesError("REFUSED: one native classpath names inconsistent JAR bytes")
        else:
            origins = verified["verified_origins"]
            production_roots = {entry["source_root"] for entry in origins
                                if entry["role"] == "production"}
            production = {path for path in prod_index["files"]
                          if boundary.classify(path) == PRODUCTION
                          and any(path.startswith(prefix + "/") for prefix in production_roots)}
            group = {"native_classpath": native, "jar_identities": identity,
                     "classpath": dependencies, "sources": set(),
                     "production_sources": production, "closures": [],
                     "runners": [], "sourcepath": []}
            groups[native] = group
        group["runners"].append(row["runner"])
        by_runner[row["runner"]] = group
    seen = set()
    for closure in closures:
        iid = closure["item_id"]
        if iid in seen or closure["feature_file"] not in kapua.FEATURE_SUITES:
            raise InterfacesError("REFUSED: duplicate or unadmitted Kapua interface item")
        seen.add(iid)
        suite = kapua.FEATURE_SUITES[closure["feature_file"]]
        group = by_runner[suite.runner_package + "." + suite.upstream_runner_class]
        group["closures"].append(closure)
        group["sources"].update(closure["files"])
    partitions = []
    for group in groups.values():
        if not group["closures"]:
            continue
        if any(boundary.classify(path) != REMOVABLE
               for path in group["sources"]):
            raise InterfacesError(
                "REFUSED: Kapua compiler inventory is not closure-removable")
        if not (group["sources"] | group["production_sources"]) \
                <= set(source_paths):
            raise InterfacesError(
                "REFUSED: Kapua attribution inventory omits selected "
                "production or closure sources")
        group["sources"] = sorted(group["sources"])
        group["production_sources"] = sorted(group["production_sources"])
        partitions.append(group)
    return partitions


def attribute_kapua(source_root, source_paths, closures, prod_index, boundary,
                    envelope, *, java, javac, sourcepath, output_root):
    """Run exact compiler partitions and merge only final per-item interfaces."""
    partitions = kapua_interface_partitions(source_root, source_paths, closures,
                                            prod_index, boundary, envelope)
    if sourcepath:
        raise InterfacesError(
            "REFUSED: Kapua attribution requires an explicit empty sourcepath")
    out = Path(output_root).absolute()
    out.mkdir(parents=True, exist_ok=False)
    selected, recipes = {}, []
    for i, partition in enumerate(partitions):
        attribution = attribute_sources(source_root, partition["sources"], java=java, javac=javac,
            classpath=partition["classpath"], sourcepath=(), release=17,
            production_paths=partition["production_sources"],
            output_root=out / f"partition-{i:02d}")
        ex = JavaInterfaceExtractor(attribution, prod_index, boundary)
        for item in extract_all(partition["closures"], ex):
            selected[item.item_id] = item
        recipes.append({"partition": i, "runners": partition["runners"],
            "native_classpath": partition["native_classpath"],
            "jar_identities": partition["jar_identities"],
            "sources": partition["sources"],
            "production_sources": partition["production_sources"],
            "attribution_recipe": attribution["recipe"],
            "items": [closure["item_id"] for closure in partition["closures"]]})
    (out / "suite-partitions.json").write_text(json.dumps({
        "schema": KAPUA_CLASSPATH_SCHEMA, "partitions": recipes}, indent=2) + "\n")
    return [selected[closure["item_id"]] for closure in closures]


def main(argv=None):
    """Produce interfaces and an annotation-only companion from pinned inputs."""
    import argparse
    from ..core.boundary import load_boundary
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ('source-root', 'source-files', 'classpath', 'java', 'javac',
                 'items', 'closures', 'production-index', 'boundary', 'out'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--sourcepath', action='append', default=[])
    args = parser.parse_args(argv)
    out = Path(args.out).absolute()
    try:
        raw = Path(args.items).read_bytes()
        ids = [json.loads(line)['item_id'] for line in raw.splitlines() if line.strip()]
        closures = json.loads(Path(args.closures).read_bytes())
        by_id = {c['item_id']: c for c in closures}
        if len(by_id) != len(closures) or len(ids) != len(set(ids)) or any(i not in by_id for i in ids):
            raise InterfacesError('REFUSED: duplicate or missing selected closure')
        selected = [by_id[i] for i in ids]
        boundary = load_boundary(args.boundary, repo_root=args.source_root)
        production = json.loads(Path(args.production_index).read_bytes())
        sources = json.loads(Path(args.source_files).read_bytes())
        classpath = json.loads(Path(args.classpath).read_bytes())
        if boundary.project == 'kapua':
            extracted = attribute_kapua(args.source_root, sources, selected, production, boundary,
                classpath, java=args.java, javac=args.javac, sourcepath=args.sourcepath, output_root=out)
        else:
            attribution = attribute_sources(args.source_root, sources,
                java=args.java, javac=args.javac, classpath=classpath,
                sourcepath=args.sourcepath, output_root=out)
            ex = JavaInterfaceExtractor(attribution, production, boundary)
            extracted = extract_all(selected, ex)
        annotations = {i.item_id: {'behaviour': i.behaviour, 'setup': i.setup} for i in extracted}
        companion = annotated_rows(raw, annotations)
        write_interfaces(extracted, str(out / 'interfaces.json'))
        (out / 'items.annotated.jsonl').write_bytes(companion)
    except (InterfacesError, OSError, ValueError) as exc:
        parser.exit(2, str(exc) + '\n')
    print(json.dumps(dict(summary(extracted), out=str(out)), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
