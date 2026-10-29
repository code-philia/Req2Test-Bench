"""Go interfaces CLI on the existing exclusive source-analysis transport."""
import json
import os
from pathlib import Path
import re
import tempfile

from ..bench import cli as bench_cli
from ..core.paths import project_path
from ..toolkit.interfaces import InterfacesError, extract_all, summary, write_interfaces
from .context import ContextTable
from .interfaces import GoInterfaceExtractor
from .interfaces_attribution import partitions
from .prod_index import _compilation_view, _removables
from .prod_index_cli import IndexTransport, _publish_index
from .prod_index_entry import source_inventory


class InterfacesTransport(IndexTransport):
    def _payload_files(self):
        return ('prod_index.py','context.py','prod_index_entry.py',
                'interfaces_attribution.py','interfaces.go','interfaces_entry.py')

    def _entry_module(self):
        return 'r2t.go.interfaces_entry'


def cmd_interfaces(args):
    profile = bench_cli._stack_profile(args)
    boundary = bench_cli._boundary(args)
    if (profile.project,profile.language,profile.framework) != ('coddy-agent','go','godog') \
            or boundary.project != profile.project \
            or Path(args.boundary).resolve() != Path(profile.boundary_path).resolve():
        raise InterfacesError('REFUSED: Go interfaces requires the coddy-agent profile/boundary')
    image = getattr(args,'image_id',None)
    if not isinstance(image,str) or not re.fullmatch('sha256:[0-9a-f]{64}',image) \
            or not getattr(args,'_container_explicit',False):
        raise InterfacesError('REFUSED: explicit exclusive analysis container and immutable image required')
    source = Path(getattr(args,'source_root',None) or project_path(profile.project,'source')).resolve()
    artifacts = Path(args.artifacts).resolve()
    if artifacts.is_relative_to(source) or source.is_relative_to(artifacts):
        raise InterfacesError('REFUSED: Go interfaces artifacts and original source must be disjoint')
    closures = json.loads((artifacts/'closures.json').read_text())
    prod_index = json.loads((artifacts/'go_prod_index.json').read_text())
    ContextTable(closures,boundary=boundary,project=profile.project)
    _, contexts = partitions(closures,prod_index)
    if prod_index.get('image_id') != image or Path(prod_index['root']).resolve() != source:
        raise InterfacesError('REFUSED: Go production index has a different original source/image')
    removable = sorted(_removables(source,[p for p,_ in boundary.removable],[r['go_suite'] for r in contexts]))
    attribution_path,output = artifacts/'go_interface_attribution.json',artifacts/'interfaces.json'
    if any(os.path.lexists(p) for p in (attribution_path,output)):
        raise InterfacesError('REFUSED: Go interface outputs already exist')
    inventory = source_inventory(source)
    with tempfile.TemporaryDirectory(prefix='go-interface-source-') as directory:
        scratch = Path(directory).resolve()
        if scratch.is_relative_to(source) or source.is_relative_to(scratch):
            raise InterfacesError('REFUSED: Go interface temporary source must be disjoint')
        snapshot = scratch/'source'; _compilation_view(source,snapshot,set())
        if source_inventory(snapshot) != inventory or source_inventory(source) != inventory:
            raise InterfacesError('REFUSED: Go interface source changed while snapshotting')
        request = {'original_root':str(source),'inventory':inventory,'contexts':[r['go_suite'] for r in contexts],
                   'closures':closures,'prod_index':prod_index,'removable_paths':removable,'image_id':image}
        attribution = InterfacesTransport(args.container,image).run(snapshot,request)
    extractor = GoInterfaceExtractor(attribution,prod_index,boundary,closures)
    items = extract_all(closures,extractor)
    # Both products are fully reconstructed before either becomes visible.
    with tempfile.TemporaryDirectory(prefix='.go-interfaces-',dir=artifacts) as directory:
        staged = Path(directory)/'interfaces.json'; write_interfaces(items,str(staged))
        _publish_index(attribution_path,attribution)
        os.link(staged,output)
    print(json.dumps(dict(summary(items),wrote=str(output)),indent=1))
    return 0
