"""Stdlib-only image entry for original Go declared-type attribution."""
import json
from pathlib import Path
import subprocess
import sys

from .interfaces_attribution import attribute_sources
from .prod_index_entry import source_inventory


def main(request_path):
    request = json.loads(Path(request_path).read_text())
    root = '/r2t-go/run/work'
    expected = request['inventory']
    if source_inventory(root) != expected:
        raise ValueError('staged original Go interface source differs')
    names = ['GOVERSION','GOOS','GOARCH','CGO_ENABLED','GOTOOLCHAIN','GOPROXY','GOWORK','GOFLAGS','GOMODCACHE']
    observed = json.loads(subprocess.check_output(['/usr/local/go/bin/go','env','-json',*names]))
    if observed != {'GOVERSION':'go1.25.0','GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'1','GOTOOLCHAIN':'local',
                    'GOPROXY':'off','GOWORK':'off','GOFLAGS':'-mod=readonly','GOMODCACHE':'/opt/r2t-go/pkg/mod'}:
        raise ValueError('unqualified Go interface analysis image')
    try:
        result = attribute_sources(root,request['closures'],request['prod_index'],go='/usr/local/go/bin/go',
                    go_scratch='/r2t-go/run/interfaces-support',removable_paths=request['removable_paths'])
    finally:
        if source_inventory(root) != expected:
            raise ValueError('original Go interface source changed during attribution')
    result['source_root'] = result['root'] = request['original_root']
    result['image_id'] = request['image_id']
    print(json.dumps(result,sort_keys=True))


if __name__ == '__main__':
    main(sys.argv[1])
