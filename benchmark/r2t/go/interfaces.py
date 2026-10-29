"""Approved Go declared-type surface, using the shared interfaces artifact."""
from __future__ import annotations

from collections import deque

from ..core.boundary import PRODUCTION, REMOVABLE
from ..toolkit.interfaces import (EMPTY_NO_DECLARATION, EMPTY_NO_MEMBER,
                                  InterfacesError, ItemInterfaces)
from .interfaces_attribution import SCHEMA, handler_identity, member_key, partitions
from .prod_index import GoIndexRefused
from .prod_index_entry import source_inventory


class GoInterfaceExtractor:
    def __init__(self, attribution, prod_index, boundary, closures):
        try:
            groups, contexts = partitions(closures, prod_index)
        except (GoIndexRefused, ValueError, KeyError, TypeError) as exc:
            raise InterfacesError('REFUSED: '+str(exc)) from exc
        if attribution.get('schema') != SCHEMA or attribution.get('contexts') != contexts \
                or len(attribution.get('partitions', [])) != len(groups):
            raise InterfacesError('REFUSED: Go attribution differs from exact closure/index contexts')
        if source_inventory(attribution['source_root']) != attribution['source_inventory']:
            raise InterfacesError('REFUSED: stale original Go attribution source')
        for fact in attribution['partitions']:
            for path, digest in fact['source_files'].items():
                if attribution['source_inventory'].get(path) != {'sha256': digest}:
                    raise InterfacesError('REFUSED: compiled Go source differs from original attribution')
        self.boundary = boundary
        self.entries = {}
        for context in contexts:
            c = context['go_suite']; group = groups[context['partition']]
            fact = attribution['partitions'][context['partition']]
            if fact['compiled_package_name'] != c['package_name'] \
                    or fact.get('bound_native_handlers') != len(group['handlers']):
                raise InterfacesError('REFUSED: wrong compiled Go package/handler count')
            first_party = set()
            for path in context['files']:
                if boundary.classify(path) != PRODUCTION:
                    continue
                for cls in prod_index['files'][path].get('classes', []):
                    if cls.get('kind') == 'type' and cls.get('decl'):
                        first_party.add((cls['name'],path,cls['decl']))
            members, spans = {}, {}
            for member in fact['members']:
                identity = member['identity']
                key = member_key(identity)
                physical = (identity['file'],identity['start_byte'],identity['end_byte'])
                if key in members or physical in spans or identity['file'] not in context['answer_files']:
                    raise InterfacesError('REFUSED: duplicate/outside Go member declaration')
                members[key] = member; spans[physical] = key
            self.entries[c['feature_path'],c['scenario_line']] = (c, context['answer_files'], members, spans, first_party)

    def _surface(self, start, files, members, spans, first_party):
        found, eligible, seen, witnesses = set(), set(), set(), []
        todo = deque([start])
        while todo:
            key = todo.popleft()
            if key in seen:
                continue
            seen.add(key); member = members[key]
            for row in member['explicit_type_uses']:
                if not row['type_parameter']:
                    found.add(row['name'])
                    if (row['name'],row['file'],row['line']) in first_party:
                        eligible.add(row['name'])
            for field in member['selected_fields']:
                for row in field['named_constituents']:
                    if not row['type_parameter']:
                        found.add(row['name'])
                        if (row['name'],row['file'],row['line']) in first_party:
                            eligible.add(row['name'])
            witnesses.append(handler_identity(member['identity']))
            for call in member['calls']:
                target = call.get('declaration')
                if target is None or target['file'] not in files \
                        or self.boundary.classify(target['file']) != REMOVABLE:
                    continue
                physical = target['file'],target['start_byte'],target['end_byte']
                if physical not in spans:
                    raise InterfacesError('REFUSED: unresolved removable Go helper declaration')
                todo.append(spans[physical])
        return found, eligible, witnesses

    def for_item(self, closure):
        item = ItemInterfaces(closure['item_id'],closure['feature_file'],closure['scenario_line'])
        try:
            context, files, members, spans, first_party = self.entries[item.feature_file,item.scenario_line]
        except KeyError as exc:
            raise InterfacesError('REFUSED: missing exact Go attribution context') from exc
        if closure.get('go_suite') != context or sorted(closure['files']) != files:
            raise InterfacesError('REFUSED: Go closure context/answer paths changed')
        groups = {'scenario':set(),'background':set()}; filtered = {'scenario':set(),'background':set()}; seen = set()
        for step in closure.get('steps', []):
            if step.get('side') != REMOVABLE:
                continue
            origin = step.get('origin')
            try:
                handler = handler_identity(step['definition']['go']['handler'])
                key = member_key(handler)
            except (KeyError,TypeError,GoIndexRefused) as exc:
                raise InterfacesError('REFUSED: missing exact native Go handler') from exc
            if origin not in groups or handler['file'] not in files \
                    or self.boundary.classify(handler['file']) != REMOVABLE or key not in members:
                raise InterfacesError('REFUSED: stale or outside native Go handler')
            if (origin,key) in seen:
                continue
            seen.add((origin,key))
            surface,eligible,witnesses = self._surface(key,set(files),members,spans,first_party)
            groups[origin].update(surface); filtered[origin].update(eligible)
            item.members.append({'file':handler['file'],'origin':origin,'handler':handler,'declarations':witnesses})
        scenario,background = groups['scenario'],groups['background']
        item.candidates = {'behaviour':sorted(scenario),'setup':sorted(background-scenario)}
        item.behaviour = sorted(filtered['scenario'])
        item.setup = sorted(filtered['background']-filtered['scenario'])
        if not item.behaviour:
            item.empty_reason = EMPTY_NO_DECLARATION if any(m['origin']=='scenario' for m in item.members) else EMPTY_NO_MEMBER
        return item
