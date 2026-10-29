"""Write a drawn subset and its provenance sidecar.

The two write-only functions of `data/subsets.py` (wave M5).  The sampler
and every reader stay there: `verify_release_subsets` proves a published
sidecar by re-running the sampler, so the sampler is a reader's tool; only
the bytes-to-disk step is a builder's.
"""
from __future__ import annotations

import json
import os


def write_subset(subset: dict, out_path: str) -> tuple[str, str]:
    """Write `<out>.jsonl` and `<out>.provenance.json`. No timestamps.

    Nothing here records WHEN it ran: a timestamp would make two draws of
    the same subset differ, and the point of this module is that they do
    not.
    """
    base = out_path[:-6] if out_path.endswith(".jsonl") else out_path
    parent = os.path.dirname(os.path.abspath(base))
    os.makedirs(parent, exist_ok=True)
    items_out = base + ".jsonl"
    prov_out = base + ".provenance.json"
    if subset["provenance"].get("schema") == "r2t.headroom_subset/1":
        _write_headroom_context(subset, items_out)
    if subset["provenance"].get("schema") == "r2t.step-definition-census/1":
        _write_census_context(subset, items_out)
    with open(items_out, "w", encoding="utf-8") as fh:
        fh.write("".join(subset["lines"]))
    write_provenance(prov_out, subset["provenance"])
    return items_out, prov_out


def _write_census_context(subset: dict, items_out: str) -> None:
    """Ship the census's native inputs; existing producer bytes never change."""
    from ..data import subsets as S
    from ..data.step_definition_census import census
    context = subset['replay_context']
    expected = census(context['items'], context['closures'])
    if expected['provenance'] != subset['provenance'] or expected['lines'] != subset['lines']:
        raise S._refuse('implementation census inputs changed before writing')
    files = {}
    for key in ('items', 'closures'):
        path = context[key]
        name = os.path.basename(path)
        if name in files or name == S.CLOSURE_MAP_NAME:
            raise S._refuse('implementation census input basenames collide')
        with open(path, 'rb') as handle:
            files[name] = handle.read()
    files[S.CLOSURE_MAP_NAME] = (json.dumps(context['clusters'], sort_keys=True,
                                           indent=1)+'\n').encode('utf-8')
    parent = os.path.dirname(os.path.abspath(items_out))
    if os.path.basename(items_out) in files:
        raise S._refuse('implementation census output would overwrite a replay input')
    outputs = {items_out: ''.join(subset['lines']).encode('utf-8')}
    provenance_out = os.path.splitext(items_out)[0] + '.provenance.json'
    for target, raw in outputs.items():
        if os.path.exists(target):
            with open(target, 'rb') as handle:
                if handle.read() != raw:
                    raise S._refuse(f'implementation census would replace existing subset {target}')
    if os.path.exists(provenance_out):
        with open(provenance_out, encoding='utf-8') as handle:
            if json.load(handle) != subset['provenance']:
                raise S._refuse(f'implementation census would replace existing provenance {provenance_out}')
    # Validate all collisions before creating anything. Existing cluster-map
    # formatting is immaterial; its partition is pinned by the reader.
    pending = []
    for name, raw in files.items():
        target = os.path.join(parent, name)
        if os.path.exists(target):
            with open(target, 'rb') as handle:
                old = handle.read()
            same = (json.loads(old) == context['clusters']
                    if name == S.CLOSURE_MAP_NAME else old == raw)
            if not same:
                raise S._refuse(f'implementation census would overwrite different input {target}')
        else:
            pending.append((target, raw))
    for target, raw in pending:
        with open(target, 'xb') as handle:
            handle.write(raw)


def _write_headroom_context(subset: dict, items_out: str) -> None:
    """Preserve the inputs W4 names by basename; never overwrite another input."""
    from ..data import subsets as S
    def read_bytes(path):
        with open(path, "rb") as handle:
            return handle.read()

    context = subset["replay_context"]
    source, boundary = context["items"], context["boundary"]
    parent = os.path.dirname(os.path.abspath(items_out))
    files = {os.path.basename(source): read_bytes(source),
             os.path.basename(S.headroom_boundary_path(items_out)): read_bytes(boundary)}
    # A census with /2 provenance also needs its original pool and closure map.
    # Plain level1 inputs remain supported by W4; Kapua additionally proves the
    # current census and its K7 pool through the gold-projection parent.
    identity = S.identify_for_inference(source)
    if identity and identity.get("sidecar"):
        provenance_path = identity["sidecar"]
        with open(provenance_path, encoding="utf-8") as handle:
            provenance = json.load(handle)
        if provenance.get("schema") == S.SCHEMA:
            source_root = os.path.dirname(source)
            pool = os.path.join(source_root, provenance["source_items"])
            files[os.path.basename(provenance_path)] = read_bytes(provenance_path)
            files[os.path.basename(pool)] = read_bytes(pool)
            clusters = os.path.join(source_root, S.CLOSURE_MAP_NAME)
            files[S.CLOSURE_MAP_NAME] = (read_bytes(clusters) if os.path.isfile(clusters)
                else (json.dumps(S._closure_clusters(source_root), sort_keys=True) + "\n").encode())
    for name, raw in files.items():
        target = os.path.join(parent, name)
        if target == os.path.abspath(items_out):
            raise S.SubsetRefused("REFUSED: headroom output would replace its census")
        if os.path.lexists(target) and (os.path.islink(target) or not os.path.isfile(target)
                                      or read_bytes(target) != raw):
            raise S.SubsetRefused("REFUSED: headroom replay context already differs: " + target)
    for name, raw in files.items():
        target = os.path.join(parent, name)
        if not os.path.exists(target):
            with open(target, "xb") as handle:
                handle.write(raw)


def write_provenance(path: str, document: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=1, sort_keys=True)
        fh.write("\n")


def write_budgeted_sample(sample: dict, out_path: str) -> tuple[str, str]:
    """Write `<out>.map.json` and `<out>.json`. No timestamps.

    Two files, because two different readers need them: every leg of the
    project runs `mutation-run --map` on the DERIVED MAP, and the sidecar is
    what says that map is a budgeted draw of a named parent.
    """
    base = out_path[:-5] if out_path.endswith(".json") else out_path
    parent = os.path.dirname(os.path.abspath(base))
    os.makedirs(parent, exist_ok=True)
    map_out = base + ".map.json"
    sidecar_out = base + ".json"
    write_provenance(map_out, sample["derived_map"])
    write_provenance(sidecar_out, sample["sidecar"])
    return map_out, sidecar_out
