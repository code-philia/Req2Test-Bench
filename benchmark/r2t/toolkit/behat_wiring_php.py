"""Sylius's Behat wiring — Symfony PHP configurators and Behat 4 PHP
config, read as data.

`behat_wiring.py` reads CoreShop's YAML.  Sylius spells the same two facts
in PHP: `Resources/config/services.php` is a Symfony *configurator* closure
(`$services->set('id', Cls::class)->args([service('x'), '%p%'])`) and
`Resources/config/suites.php` is a Behat 4 `Behat\\Config\\Config` chain
(`(new Suite('api_x', [...]))->withContexts(...)->withFilter(new
TagFilter('@x&&@api'))`).  Nothing about the QUESTIONS changes — which
service registers which class with which arguments, and which contexts and
tag filter each suite carries — so this module answers them into the SAME
`ServiceDef` / `SuiteDef` dataclasses, and `closure.py`, `cmd_index`'s
alias table and `resolve_context_ref` work unchanged.

READ, NOT EXECUTED.  Evaluating the configurator would need PHP, Symfony's
container and Behat's config classes on the host, which is a container
round trip for a question that is answered by the file's own text.  So
this is a small scanner: comments stripped, statements split at `;`,
method chains matched with balanced parentheses, string literals and
`Cls::class` references resolved through each file's `use` table.  The
shapes it has to read are the ones the corpus contains (measured over
Sylius's 233 config files: `->set` with one or two arguments, `->alias`,
`->args([...])` whose elements are `service('id')`, `service(Cls::class)`,
either with `->nullOnInvalid()`, a `'literal'`, a `'%parameter%'` or a
number, and `->tag('name', [...])`); anything else is kept as its raw
text rather than guessed at, which is what an argument list is FOR here —
`alias_table` reads `@id` references and ignores the rest.
"""
from __future__ import annotations

import glob
import os
import re
from typing import Optional

from .behat_wiring import ServiceDef, SuiteDef

#: The two invalidation suffixes Symfony's configurator spells on a service
#: reference, both meaning "may be absent" — which is `@?id` in YAML.
_OPTIONAL = ("->nullOnInvalid()", "->ignoreOnInvalid()")

_USE = re.compile(r"^\s*use\s+(?!function\s|const\s)([^;]+);", re.M)
_IMPORT_CALL = re.compile(r"->import\s*\(")
_NEW_SUITE = re.compile(r"new\s+Suite\s*\(")
_TAG_FILTER = re.compile(r"new\s+TagFilter\s*\(\s*'([^']*)'")
_CHAIN = re.compile(r"\s*->\s*(\w+)\s*\(")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def strip_php_comments(text: str) -> str:
    """`//`, `#` and `/* */` comments blanked, newlines and offsets kept.

    Offsets are preserved so a caller can still map a match back to the
    line it came from (`repo._removable_import_lines` edits the RAW file
    by line number after finding its imports here).
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    break
                j += 1
            out.append(text[i:min(j + 1, n)])
            i = j + 1
            continue
        if c == "/" and text[i + 1:i + 2] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "#" and text[i + 1:i + 2] != "[":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "/" and text[i + 1:i + 2] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _match_paren(text: str, i: int) -> int:
    """Index of the bracket closing the one at `i`, strings skipped."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    closing = pairs[text[i]]
    depth = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    break
                j += 1
            i = j + 1
            continue
        if c in pairs:
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                if c != closing:
                    raise ValueError(f"unbalanced brackets at offset {i}")
                return i
        i += 1
    raise ValueError("unbalanced brackets")


def _split_top(text: str, sep: str = ",") -> list:
    """Split at `sep` outside strings and brackets; empty parts dropped."""
    parts, start, depth = [], 0, 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    break
                j += 1
            i = j + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return [p for p in parts if p.strip()]


def _statements(text: str) -> list:
    """The file's top-level statements, split at `;` outside brackets."""
    return _split_top(text, ";")


def _chain_root(stmt: str, arrow: int) -> str:
    """What the `->` at `arrow` hangs off: `$services`, `parameters`, ...

    Needed because a configurator writes a service and a container PARAMETER
    with the SAME `->set('id', Cls::class)`, distinguished only by the
    receiver -- `$services` / `$container->services()` against `$parameters` /
    `$container->parameters()` -- and both live in one `return static function
    (...) { ... };`, which `_statements` cannot split (its `;` are inside the
    braces).  Reading every `->set(` in the file therefore merged the two
    namespaces into one dict, where the winner of a collision was decided by
    file order; Sylius's `services/pages/admin/account.php` has exactly that
    collision on `sylius.behat.page.admin.reset_password`.

    A `->set(...)->args(...)->set(...)` continuation keeps walking back to the
    head that decides the kind; `services()` and `parameters()` stop the walk
    because they ARE the kind.
    """
    while arrow >= 0:
        i = arrow - 1
        while i >= 0 and stmt[i].isspace():
            i -= 1
        if i < 0:
            return ""
        if stmt[i] != ")":
            end = i + 1
            while i >= 0 and (stmt[i].isalnum() or stmt[i] in "_$"):
                i -= 1
            return stmt[i + 1:end]
        depth, j = 0, i
        while j >= 0:
            if stmt[j] == ")":
                depth += 1
            elif stmt[j] == "(":
                depth -= 1
                if depth == 0:
                    break
            j -= 1
        if j < 0:
            return ""
        k = j - 1
        while k >= 0 and stmt[k].isspace():
            k -= 1
        end = k + 1
        while k >= 0 and (stmt[k].isalnum() or stmt[k] in "_$"):
            k -= 1
        name = stmt[k + 1:end]
        if name in ("services", "parameters"):
            return name
        while k >= 0 and stmt[k].isspace():
            k -= 1
        if k >= 1 and stmt[k - 1] == "-" and stmt[k] == ">":
            arrow = k - 1
            continue
        return name
    return ""


#: Chain roots that make a `->set(...)` a container parameter, not a service.
_PARAMETER_ROOTS = ("parameters", "$parameters")


def _calls(stmt: str) -> list:
    """`[(method name, raw argument text, chain root)]` for one `->a()->b()`."""
    out = []
    for m in re.finditer(r"->\s*(\w+)\s*\(", stmt):
        try:
            close = _match_paren(stmt, m.end() - 1)
        except ValueError:
            continue
        out.append((m.group(1), stmt[m.end():close],
                    _chain_root(stmt, m.start())))
    return out


def use_table(text: str) -> dict:
    """`local alias -> FQCN` for every `use X\\Y [as Z];` in the file."""
    table = {}
    for m in _USE.finditer(text):
        for clause in m.group(1).split(","):
            clause = clause.strip()
            if not clause:
                continue
            parts = clause.split()
            fqcn = parts[0].lstrip("\\")
            alias = (parts[2] if len(parts) >= 3 and parts[1].lower() == "as"
                     else fqcn.rsplit("\\", 1)[-1])
            table[alias] = fqcn
    return table


def resolve_class(name: str, uses: dict) -> str:
    """A PHP class reference as written -> the FQCN it names."""
    name = name.strip().lstrip("\\")
    head, sep, rest = name.partition("\\")
    if head in uses:
        return uses[head] + (sep + rest if sep else "")
    return name


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1].replace("\\'", "'").replace("\\\\", "\\")
    return text


def _literal_or_class(text: str, uses: dict) -> str:
    """`'an.id'` -> `an.id`; `Cls::class` -> the FQCN; anything else raw."""
    text = text.strip()
    if text[:1] in "'\"":
        return _unquote(text)
    if text.endswith("::class"):
        return resolve_class(text[:-len("::class")], uses)
    return text


# ------------------------------------------------------------- imports
def _import_resources(text: str) -> list:
    """Every resource string a file's `->import(...)` calls name."""
    out = []
    for m in _IMPORT_CALL.finditer(text):
        close = _match_paren(text, m.end() - 1)
        raw = text[m.end():close].strip()
        if raw.startswith("["):
            raw = raw[1:_match_paren(raw, 0)]
        for part in _split_top(raw, ","):
            part = part.strip()
            if part[:1] in "'\"":
                out.append(_unquote(part))
    return out


def resolve_import(base_file: str, resource: str) -> list:
    """A resource, relative to the importing file -> the paths it names.

    A glob (`services/elements/**/*.php`) expands, sorted, to what is on
    disk now; anything else is one path, which may or may not exist.
    """
    target = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(base_file)), resource))
    if any(ch in resource for ch in "*?["):
        return sorted(glob.glob(target, recursive=True))
    return [target]


def reachable_php_files(entry: str) -> list:
    """Every configurator file reachable from `entry`, in import order."""
    out, seen = [], set()
    queue = [os.path.abspath(entry)]
    while queue:
        path = queue.pop(0)
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        out.append(path)
        text = strip_php_comments(_read(path))
        for resource in _import_resources(text):
            queue.extend(resolve_import(path, resource))
    return out


# ------------------------------------------------------------ services
def _arg_value(element: str, uses: dict):
    """One `->args([...])` element in `ServiceDef.arguments` vocabulary.

    `@id` for a service reference and `@?id` for an optional one, the same
    two spellings the YAML reader produces, so `alias_table` and
    `closure._service_class` read a PHP project's arguments unchanged.  A
    shape this scanner does not model (a nested array, `param()`,
    `tagged_iterator()`, an expression) is kept as its raw text: it is not
    a service reference, and inventing a structure for it would be a
    second, silent parse.
    """
    element = element.strip()
    for suffix in _OPTIONAL:
        if element.endswith(suffix):
            inner = _arg_value(element[:-len(suffix)], uses)
            return "@?" + inner[1:] if isinstance(inner, str) \
                and inner.startswith("@") else inner
    if element.startswith("service(") and element.endswith(")"):
        return "@" + _literal_or_class(element[len("service("):-1], uses)
    if element[:1] in "'\"":
        return _unquote(element)
    if element.endswith("::class"):
        return resolve_class(element[:-len("::class")], uses)
    return element


def _parse_args(raw: str, uses: dict) -> list:
    raw = raw.strip()
    if raw.startswith("["):
        raw = raw[1:_match_paren(raw, 0)]
    return [_arg_value(e, uses) for e in _split_top(raw, ",")]


def _parse_tag(raw: str, uses: dict) -> dict:
    """`->tag('name', ['k' => 'v'])` in the YAML reader's tag vocabulary."""
    parts = _split_top(raw, ",")
    if not parts:
        return {}
    tag = {"name": _literal_or_class(parts[0], uses)}
    if len(parts) > 1:
        body = parts[1].strip()
        if body.startswith("["):
            body = body[1:_match_paren(body, 0)]
        for pair in _split_top(body, ","):
            key, sep, value = pair.partition("=>")
            if sep:
                tag[_unquote(key)] = _literal_or_class(value, uses)
    return tag


def load_services_php(entry: str) -> dict:
    """All service definitions reachable from a PHP configurator entry."""
    out: dict = {}
    for path in reachable_php_files(entry):
        text = strip_php_comments(_read(path))
        uses = use_table(text)
        for stmt in _statements(text):
            if "->set(" not in stmt and "->alias(" not in stmt:
                continue
            current: Optional[ServiceDef] = None
            for name, raw, root in _calls(stmt):
                if name == "set":
                    if root in _PARAMETER_ROOTS:
                        # A container parameter. It is not a service, it has
                        # no class, and nothing downstream may resolve a
                        # context reference to it.
                        current = None
                        continue
                    args = _split_top(raw, ",")
                    if not args:
                        continue
                    sid = _literal_or_class(args[0], uses)
                    cls = (_literal_or_class(args[1], uses) if len(args) > 1
                           else (sid if "\\" in sid else None))
                    current = ServiceDef(id=sid, file=path, cls=cls,
                                         raw=stmt.strip())
                    out[sid] = current
                elif name == "alias":
                    args = _split_top(raw, ",")
                    if len(args) < 2:
                        continue
                    aid = _literal_or_class(args[0], uses)
                    out[aid] = ServiceDef(
                        id=aid, file=path,
                        alias_of=_literal_or_class(args[1], uses).lstrip("@?"),
                        raw=stmt.strip())
                    current = None
                elif current is None:
                    continue
                elif name == "args":
                    current.arguments = _parse_args(raw, uses)
                elif name == "tag":
                    current.tags.append(_parse_tag(raw, uses))
    return out


# -------------------------------------------------------------- suites
def _suites_in(text: str, uses: dict) -> list:
    """`[(name, contexts, tag filter, paths)]` for one Behat 4 config file."""
    found = []
    for m in _NEW_SUITE.finditer(text):
        open_paren = m.end() - 1
        close = _match_paren(text, open_paren)
        args = _split_top(text[open_paren + 1:close], ",")
        if not args:
            continue
        name = _literal_or_class(args[0], uses)

        # `(new Suite(...))->withContexts(...)`: the chain hangs off the
        # WRAPPING parenthesis, not off `new Suite(...)` itself.
        before = m.start() - 1
        while before >= 0 and text[before].isspace():
            before -= 1
        pos = close
        if before >= 0 and text[before] == "(":
            pos = _match_paren(text, before)

        contexts: list = []
        tag_filter = None
        paths: list = []
        i = pos + 1
        while True:
            call = _CHAIN.match(text, i)
            if call is None:
                break
            arg_open = call.end() - 1
            arg_close = _match_paren(text, arg_open)
            raw = text[arg_open + 1:arg_close]
            if call.group(1) == "withContexts":
                contexts += [_literal_or_class(a, uses)
                             for a in _split_top(raw, ",")]
            elif call.group(1) == "withFilter":
                hit = _TAG_FILTER.search(raw)
                if hit is not None:
                    tag_filter = hit.group(1)
            elif call.group(1) == "withPaths":
                body = raw.strip()
                if body.startswith("["):
                    body = body[1:_match_paren(body, 0)]
                paths += [_unquote(a) for a in _split_top(body, ",")]
            i = arg_close + 1
        found.append((name, contexts, tag_filter, paths))
    return found


def load_suites_php(entry: str) -> dict:
    """All Behat suites reachable from a Behat 4 PHP config entry."""
    out: dict = {}
    for path in reachable_php_files(entry):
        text = strip_php_comments(_read(path))
        uses = use_table(text)
        for name, contexts, tag_filter, paths in _suites_in(text, uses):
            out[name] = SuiteDef(name=name, file=path, contexts=contexts,
                                 tag_filter=tag_filter, paths=paths)
    return out


#: The corpus this module's optional live leg reads when it is present.
SYLIUS_CORPUS = "/data2/binhang/r2t_onb_sylius/projects/sylius/source"


def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    import tempfile

    with tempfile.TemporaryDirectory() as root:
        def write(rel, text):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        # A configurator tree in miniature: an import, a glob import, an id
        # with a class, an FQCN-as-id, an alias, a `service()` argument, an
        # optional one, a parameter, a literal and a tag.
        write("services.php", """<?php
/* a licence header with a ; in it; and a (paren */
declare(strict_types=1);

use Symfony\\Component\\DependencyInjection\\Loader\\Configurator\\ContainerConfigurator;
use function Symfony\\Component\\DependencyInjection\\Loader\\Configurator\\service;

return static function (ContainerConfigurator $container) {
    $container->import('services/contexts.php');
    $container->import('services/elements/**/*.php');
};
""")
        write("services/contexts.php", """<?php
declare(strict_types=1);

use Demo\\Behat\\Context\\Api\\ShopContext;
use Demo\\Behat\\Context\\Setup\\AddressContext;
use Demo\\Behat\\Service\\SharedStorage;
use Demo\\Behat\\Service\\SharedStorageInterface;
use Symfony\\Component\\DependencyInjection\\Loader\\Configurator\\ContainerConfigurator;
use function Symfony\\Component\\DependencyInjection\\Loader\\Configurator\\service;

return static function (ContainerConfigurator $container) {
    $services = $container->services();

    $services->defaults()->public();

    $services
        ->set('demo.behat.context.setup.address', AddressContext::class)
        ->args([
            service('demo.repository.address'),   // a comment
            '%demo.locale%',
            service('session.factory')->nullOnInvalid(),
            'literal',
        ])
        ->tag('fob.context_service', ['priority' => 10])
    ;

    $services->set('demo.behat.context.api.shop', ShopContext::class);

    $services->set(SharedStorage::class);

    $services->alias(SharedStorageInterface::class, 'demo.behat.shared_storage');

    // Container PARAMETERS: the same `->set('id', ...)` spelling, a different
    // namespace, and here deliberately AFTER the service of the same id.
    $parameters = $container->parameters();
    $parameters->set('demo.locale', 'en_US');
    $parameters->set('demo.behat.context.api.shop', 'a.parameter.value');
};
""")
        write("services/elements/one.php", """<?php
use Demo\\Behat\\Element\\CartElement;
use Symfony\\Component\\DependencyInjection\\Loader\\Configurator\\ContainerConfigurator;

return static function (ContainerConfigurator $container) {
    $container->services()->set('demo.behat.element.cart', CartElement::class);
    $container->parameters()->set('demo.behat.element.cart.class', CartElement::class);
};
""")

        svc = load_services_php(os.path.join(root, "services.php"))
        check("a plain import is followed",
              "demo.behat.context.setup.address" in svc, str(sorted(svc)))
        check("a `**/*.php` glob import is followed",
              "demo.behat.element.cart" in svc, str(sorted(svc)))
        setup = svc["demo.behat.context.setup.address"]
        check("`->set('id', Cls::class)` resolves the class through `use`",
              setup.cls == "Demo\\Behat\\Context\\Setup\\AddressContext",
              str(setup.cls))
        check("`->args([...])` reads a service reference as `@id`, an "
              "optional one as `@?id`, a parameter and a literal as "
              "themselves",
              setup.arguments == ["@demo.repository.address", "%demo.locale%",
                                  "@?session.factory", "literal"],
              str(setup.arguments))
        check("a trailing `//` comment inside an argument list is not an "
              "argument", len(setup.arguments) == 4, str(setup.arguments))
        check("`->tag('name', [...])` reads as the YAML reader's tag shape",
              setup.tags == [{"name": "fob.context_service", "priority": "10"}],
              str(setup.tags))
        check("`->set(Cls::class)` is an FQCN-as-id and gets that class",
              svc["Demo\\Behat\\Service\\SharedStorage"].cls
              == "Demo\\Behat\\Service\\SharedStorage")
        alias = svc["Demo\\Behat\\Service\\SharedStorageInterface"]
        check("`->alias(A::class, 'b')` is an alias to `b`",
              alias.is_alias and alias.alias_of == "demo.behat.shared_storage",
              str(alias))
        check("a licence header's `;` and `(` do not split a statement or "
              "unbalance a chain",
              svc["demo.behat.context.api.shop"].cls
              == "Demo\\Behat\\Context\\Api\\ShopContext")
        check("a container PARAMETER is not a service definition, in either "
              "the `$parameters->set` or the `parameters()->set` spelling",
              "demo.locale" not in svc
              and "demo.behat.element.cart.class" not in svc, str(sorted(svc)))
        check("...and an id used for both keeps its SERVICE, whichever came "
              "last in the file",
              svc["demo.behat.context.api.shop"].cls
              == "Demo\\Behat\\Context\\Api\\ShopContext",
              str(svc["demo.behat.context.api.shop"]))

        from .behat_wiring import class_to_service, resolve_context_ref
        check("the shared class->service index reads a PHP project",
              class_to_service(svc)["Demo\\Behat\\Context\\Api\\ShopContext"]
              == ["demo.behat.context.api.shop"])
        check("the shared context-ref resolver reads a PHP service id",
              resolve_context_ref("demo.behat.context.api.shop", svc)
              == "Demo\\Behat\\Context\\Api\\ShopContext")

        # Behat 4 suites: an import list, an `id` context, a `Cls::class`
        # context reached through an aliased `use`, and one TagFilter.
        write("suites.php", """<?php
use Behat\\Config\\Config;

return (new Config())
    ->import([
        'suites/api.php',
    ])
;
""")
        write("suites/api.php", """<?php
use Behat\\Config\\Config;

return (new Config())
    ->import(['api/address_book.php'])
;
""")
        write("suites/api/address_book.php", """<?php
use Behat\\Config\\Config;
use Behat\\Config\\Filter\\TagFilter;
use Behat\\Config\\Profile;
use Behat\\Config\\Suite;
use Demo\\Behat\\Context\\Setup\\AddressContext as SetupAddressContext;

return (new Config())
    ->withProfile(
        (new Profile('default'))
        ->withSuite(
            (new Suite('api_address_book', [
            'javascript' => false,
        ]))
            ->withContexts(
                'demo.behat.context.setup.address',
                SetupAddressContext::class,
            )
            ->withContexts(
                'demo.behat.context.api.shop',
            )
            ->withPaths(['%paths.base%/features'])
            ->withFilter(new TagFilter('@address_book&&@api')),
        ),
    )
;
""")
        suites = load_suites_php(os.path.join(root, "suites.php"))
        check("a nested `->import([...])` list is followed",
              list(suites) == ["api_address_book"], str(sorted(suites)))
        s = suites["api_address_book"]
        check("every `->withContexts(...)` call contributes, in suite order",
              s.contexts == ["demo.behat.context.setup.address",
                             "Demo\\Behat\\Context\\Setup\\AddressContext",
                             "demo.behat.context.api.shop"],
              str(s.contexts))
        check("an aliased `use` resolves a `Cls::class` context reference",
              s.contexts[1] == "Demo\\Behat\\Context\\Setup\\AddressContext")
        check("the TagFilter is the suite's tag filter",
              s.tag_filter == "@address_book&&@api", str(s.tag_filter))
        check("`->withPaths([...])` is read",
              s.paths == ["%paths.base%/features"], str(s.paths))

        # The dispatch that makes every existing caller stack-blind.
        from . import behat_wiring
        check("`behat_wiring.load_services` dispatches on the entry's suffix",
              behat_wiring.load_services(os.path.join(root, "services.php"))
              .keys() == svc.keys())
        check("`behat_wiring.load_suites` does the same",
              list(behat_wiring.load_suites(os.path.join(root, "suites.php")))
              == ["api_address_book"])

    # -- the live leg: the corpus itself, when this host has it.
    cfg = os.path.join(SYLIUS_CORPUS, "src/Sylius/Behat/Resources/config")
    if not os.path.isdir(cfg):
        print(f"  [note] {SYLIUS_CORPUS} is not present; the corpus leg is "
              f"skipped (the fixture leg above is the portable one)")
    else:
        suites = load_suites_php(os.path.join(cfg, "suites.php"))
        api = {n: s for n, s in suites.items() if n.startswith("api_")}
        check("the corpus's 69 API suites all parse",
              len(api) == 69, str(len(api)))
        check("...each with exactly one `@<feature>&&@api` tag filter",
              all(s.tag_filter and s.tag_filter.endswith("&&@api")
                  for s in api.values()),
              str(sorted(n for n, s in api.items()
                         if not (s.tag_filter or "").endswith("&&@api"))[:4]))
        check("...and a non-empty context list",
              all(s.contexts for s in api.values()))
        services = load_services_php(os.path.join(cfg, "services.php"))
        contexts = [sid for sid, sd in services.items()
                    if sd.cls and "\\Context\\" in sd.cls]
        check("the corpus's context service definitions parse (>= 250)",
              len(contexts) >= 250, str(len(contexts)))
        check("...out of a whole configurator tree, not one file (>= 480 "
              "definitions over >= 60 files)",
              len(services) >= 480
              and len({sd.file for sd in services.values()}) >= 60,
              f"{len(services)} defs / "
              f"{len({sd.file for sd in services.values()})} files")
        check("the corpus's 128 container parameters are NOT among them",
              "sylius.behat.notification_checker.admin.class_map"
              not in services
              and "sylius.behat.clock.date_file" not in services,
              str([sid for sid in services
                   if sid.startswith("sylius.behat.notification_checker.")]))
        check("a known corpus definition reads with its arguments",
              services["sylius.behat.context.hook.doctrine_orm"].arguments
              == ["@doctrine.orm.entity_manager"],
              str(services.get("sylius.behat.context.hook.doctrine_orm")))
        check("a corpus `->nullOnInvalid()` argument reads as `@?id`",
              "@?session.factory"
              in services["sylius.behat.admin_security"].arguments,
              str(services["sylius.behat.admin_security"].arguments))

    print("\n" + ("ALL PASS (behat_wiring_php)" if ok
                  else "FAILURES (behat_wiring_php)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
