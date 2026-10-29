"""CoreShop's Behat DI + suite wiring, read as data.

The benchmark synthesises its own per-item suite (SPEC.md §4, decision
D2), which means it must first understand the wiring it is replacing:

* `Resources/config/services/**.yml` — service id -> class + constructor
  arguments.  Contexts are Symfony services here, not plain classes, so
  the closure extractor cannot see their dependencies from PHP alone.
* `Resources/config/suites/**.yml` — which contexts each suite loads and
  the tag filter that selects its scenarios.

It also derives the **autowiring alias table**: CoreShop wires most
context arguments by service id (`@coreshop.repository.currency`), which
plain `autowire: true` cannot resolve.  Aggregating every removed
context's (parameter type -> service id) pair over the whole corpus gives
a type->service map that is a property of the *substrate*, not of any one
item, so publishing it with the harness leaks nothing about a given
scenario's answer while letting an autowired registration resolve.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml


class _TolerantLoader(yaml.SafeLoader):
    """Symfony YAML uses tags PyYAML has never heard of.

    `!tagged_iterator`, `!service`, `!php/const` and friends appear inside
    argument lists.  They are irrelevant to the wiring questions asked
    here, so they are preserved as an opaque marker rather than crashing
    the parse.
    """


def _unknown(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {"__tag__": tag_suffix, "value": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {"__tag__": tag_suffix, "value": loader.construct_sequence(node)}
    return {"__tag__": tag_suffix, "value": loader.construct_mapping(node)}


_TolerantLoader.add_multi_constructor("!", _unknown)


@dataclass
class ServiceDef:
    id: str
    file: str
    cls: Optional[str] = None
    arguments: list[Any] = field(default_factory=list)
    tags: list[Any] = field(default_factory=list)
    alias_of: Optional[str] = None      # `id: '@other'` shorthand
    raw: Any = None

    @property
    def is_alias(self) -> bool:
        return self.alias_of is not None


@dataclass
class SuiteDef:
    name: str
    file: str
    contexts: list[str] = field(default_factory=list)
    tag_filter: Optional[str] = None
    paths: list[str] = field(default_factory=list)


def _load(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return yaml.load(fh, Loader=_TolerantLoader) or {}


def _resolve_import(base_file: str, resource: str) -> str:
    return os.path.normpath(os.path.join(os.path.dirname(base_file), resource))


def load_services(entry: str) -> dict[str, ServiceDef]:
    """All service definitions reachable from `entry`, following imports.

    A `.php` entry is a Symfony CONFIGURATOR rather than YAML and is read
    by `behat_wiring_php`, which answers into these same dataclasses.  The
    dispatch is here, on the entry's suffix, so every caller -- the closure
    extractor, `cmd_index`'s alias table, the strip -- stays stack-blind.
    """
    if entry.endswith(".php"):
        from .behat_wiring_php import load_services_php
        return load_services_php(entry)
    out: dict[str, ServiceDef] = {}
    seen: set[str] = set()
    stack = [os.path.abspath(entry)]
    while stack:
        path = stack.pop()
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        doc = _load(path)
        if not isinstance(doc, dict):
            continue
        for imp in doc.get("imports") or []:
            res = imp.get("resource") if isinstance(imp, dict) else imp
            if isinstance(res, str):
                stack.append(_resolve_import(path, res))
        services = doc.get("services")
        if not isinstance(services, dict):
            continue
        for sid, body in services.items():
            if sid.startswith("_"):          # _defaults, _instanceof
                continue
            if isinstance(body, str):
                out[sid] = ServiceDef(id=sid, file=path,
                                      alias_of=body.lstrip("@"), raw=body)
                continue
            if body is None:
                out[sid] = ServiceDef(id=sid, file=path,
                                      cls=sid if "\\" in sid else None, raw=body)
                continue
            if not isinstance(body, dict):
                continue
            cls = body.get("class")
            if cls is None and "\\" in sid:
                cls = sid                    # FQCN-as-id shorthand
            alias = body.get("alias")
            args = body.get("arguments") or []
            if isinstance(args, dict):       # named arguments
                args = list(args.values())
            out[sid] = ServiceDef(id=sid, file=path, cls=cls,
                                  arguments=list(args),
                                  tags=list(body.get("tags") or []),
                                  alias_of=(alias.lstrip("@")
                                            if isinstance(alias, str) else None),
                                  raw=body)
    return out


def load_suites(entry: str) -> dict[str, SuiteDef]:
    """All Behat suites reachable from `entry` (suites.yml).

    A `.php` entry is a Behat 4 `Behat\\Config\\Config` chain; see
    `load_services` for why the dispatch lives on the suffix.
    """
    if entry.endswith(".php"):
        from .behat_wiring_php import load_suites_php
        return load_suites_php(entry)
    out: dict[str, SuiteDef] = {}
    seen: set[str] = set()
    stack = [os.path.abspath(entry)]
    while stack:
        path = stack.pop()
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        doc = _load(path)
        if not isinstance(doc, dict):
            continue
        for imp in doc.get("imports") or []:
            res = imp.get("resource") if isinstance(imp, dict) else imp
            if isinstance(res, str):
                stack.append(_resolve_import(path, res))
        for profile, pbody in doc.items():
            if profile == "imports" or not isinstance(pbody, dict):
                continue
            suites = pbody.get("suites")
            if not isinstance(suites, dict):
                continue
            for name, sbody in suites.items():
                if not isinstance(sbody, dict):
                    continue
                filters = sbody.get("filters") or {}
                out[name] = SuiteDef(
                    name=name, file=path,
                    contexts=[c if isinstance(c, str) else next(iter(c))
                              for c in (sbody.get("contexts") or [])],
                    tag_filter=filters.get("tags") if isinstance(filters, dict) else None,
                    paths=list(sbody.get("paths") or []),
                )
    return out


def class_to_service(services: dict[str, ServiceDef]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for sid, sd in services.items():
        if sd.cls:
            out.setdefault(sd.cls, []).append(sid)
    return out


def resolve_context_ref(ref: str, services: dict[str, ServiceDef]) -> Optional[str]:
    """A suite `contexts:` entry is either a service id or a bare FQCN."""
    sd = services.get(ref)
    hops = 0
    while sd is not None and sd.is_alias and hops < 10:
        sd = services.get(sd.alias_of or "")
        hops += 1
    if sd is not None and sd.cls:
        return sd.cls
    if "\\" in ref:
        return ref
    return None


_ARG_SERVICE = re.compile(r"^@\??(.+)$")


def alias_table(services: dict[str, ServiceDef],
                php_index: dict) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Type -> service id, derived from how the substrate wires itself.

    Returns (unambiguous map, full multimap).  A type that CoreShop wires
    to two different services is left out of the unambiguous map: nothing
    can be inferred there and guessing would silently mis-wire.
    """
    by_class: dict[str, dict] = {}
    for finfo in php_index["files"].values():
        for c in finfo["classes"]:
            by_class[c["name"]] = c

    multi: dict[str, set[str]] = {}
    for sd in services.values():
        if not sd.cls or not sd.arguments:
            continue
        cinfo = by_class.get(sd.cls)
        if cinfo is None or not cinfo.get("constructor"):
            continue
        params = cinfo["constructor"]
        for i, arg in enumerate(sd.arguments):
            if i >= len(params) or not isinstance(arg, str):
                continue
            m = _ARG_SERVICE.match(arg)
            if not m:
                continue
            target = m.group(1)
            types = [t for t in params[i]["types"] if "\\" in t or t[:1].isupper()]
            for t in types:
                if t in ("string", "int", "float", "bool", "array", "iterable",
                         "mixed", "callable", "object"):
                    continue
                multi.setdefault(t.lstrip("\\"), set()).add(target)
    unambiguous = {t: next(iter(s)) for t, s in multi.items() if len(s) == 1}
    return unambiguous, multi


def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    import tempfile
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "services.yml"), "w") as fh:
        fh.write("""imports:
    - { resource: services/contexts.yml }

services:
    _defaults:
        public: true
    coreshop.behat.shared_storage: '@CoreShop\\Bundle\\TestBundle\\Service\\SharedStorageInterface'
    CoreShop\\Behat\\Service\\Index\\RelationalIndexExtension:
        tags:
            - { name: coreshop.index.extension }
""")
    os.makedirs(os.path.join(d, "services"), exist_ok=True)
    with open(os.path.join(d, "services", "contexts.yml"), "w") as fh:
        fh.write("""services:
    coreshop.behat.context.domain.cart:
        class: CoreShop\\Behat\\Context\\Domain\\CartContext
        arguments:
            - '@coreshop.context.cart'
        tags:
            - { name: fob.context_service }
    weird:
        class: CoreShop\\Behat\\Weird
        arguments: !tagged_iterator coreshop.thing
""")
    svc = load_services(os.path.join(d, "services.yml"))
    check("imports followed", "coreshop.behat.context.domain.cart" in svc,
          str(sorted(svc)))
    check("alias shorthand read",
          svc["coreshop.behat.shared_storage"].alias_of
          == "CoreShop\\Bundle\\TestBundle\\Service\\SharedStorageInterface")
    check("FQCN-as-id gets a class",
          svc["CoreShop\\Behat\\Service\\Index\\RelationalIndexExtension"].cls
          == "CoreShop\\Behat\\Service\\Index\\RelationalIndexExtension")
    check("unknown yaml tag survives", "weird" in svc)
    check("class->service index",
          class_to_service(svc)["CoreShop\\Behat\\Context\\Domain\\CartContext"]
          == ["coreshop.behat.context.domain.cart"])
    check("service-id context ref resolves",
          resolve_context_ref("coreshop.behat.context.domain.cart", svc)
          == "CoreShop\\Behat\\Context\\Domain\\CartContext")
    check("bare FQCN context ref resolves",
          resolve_context_ref("CoreShop\\Behat\\Nope\\X", svc)
          == "CoreShop\\Behat\\Nope\\X")

    with open(os.path.join(d, "suites.yml"), "w") as fh:
        fh.write("""imports:
    - suites/domain.yml
""")
    os.makedirs(os.path.join(d, "suites"), exist_ok=True)
    with open(os.path.join(d, "suites", "domain.yml"), "w") as fh:
        fh.write("""default:
    suites:
        domain_cart:
            contexts:
                - coreshop.behat.context.domain.cart
                - CoreShop\\Bundle\\TestBundle\\Context\\Hook\\DoctrineORMContext
            filters:
                tags: "@domain&&@cart"
""")
    suites = load_suites(os.path.join(d, "suites.yml"))
    check("suite loaded", "domain_cart" in suites, str(sorted(suites)))
    check("suite contexts", len(suites["domain_cart"].contexts) == 2)
    check("suite tag filter", suites["domain_cart"].tag_filter == "@domain&&@cart")

    idx = {"files": {"x.php": {"classes": [{
        "name": "CoreShop\\Behat\\Context\\Domain\\CartContext",
        "constructor": [{"name": "cartContext",
                         "types": ["CoreShop\\Component\\Order\\Context\\CartContextInterface"]}],
    }]}}}
    ua, multi = alias_table(svc, idx)
    check("alias table derived",
          ua.get("CoreShop\\Component\\Order\\Context\\CartContextInterface")
          == "coreshop.context.cart", str(ua))

    print("\n" + ("ALL PASS (behat_wiring)" if ok else "FAILURES (behat_wiring)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
