"""A Symfony project's PRODUCTION wiring, read as a static service graph.

`IMPLEMENTATION_VISIBILITY_SPEC.md` §2.2 requires the delegation edges of a
visibility map to be resolved "using static source and reviewed wiring",
with "the actual binding evidence (inheritance, trait resolution, service
alias/tag/registry, static call, or reviewed dynamic dispatch)" recorded per
edge (§2.1).  CoreShop's map does that by citing
`Resources/config/services*.yml` line ranges and `DependencyInjection/
Compiler/*Pass.php`, because CoreShop wires production in Symfony YAML.

Sylius does not.  On the pinned 2.3 tree every production service is a PHP
*configurator* closure -- `$services->set('id', Cls::class)->args([service(
'other'), '%locale%'])`, `->alias(Iface::class, 'id')`, `->decorate('other')`
-- so CoreShop's method does not transfer and a YAML loader answers nothing.
This module answers the SAME question over all three spellings Symfony
accepts, so a lane can cite `services/fixtures_factories.php:120` the way
CoreShop cites `services.yml:36-42`:

* PHP `ContainerConfigurator` closures (`Resources/config/**.php`)
* XML service containers (`<container><services><service id= class=>`)
* YAML `services:` blocks

`behat_wiring_php` already reads the configurator form for Sylius's *Behat*
config, into `behat_wiring`'s `ServiceDef`.  Its scanner primitives --
comment stripping, balanced-bracket matching, top-level splitting, the `use`
table, the chain-root walk that keeps `$parameters->set` out of the service
namespace -- are imported here rather than copied.  What is new is (a) the
other two formats, (b) per-call source lines, because the line IS the
evidence, and (c) `delegates()`, which is the question a map draft asks.

READ, NOT EXECUTED, and NOT A CONTAINER.  Compiling the container would need
PHP, the vendor tree and every bundle extension; the questions here are
answered by the files' own text.  The consequence is stated rather than
hidden: this graph knows what the configuration *says*, not what a compiler
pass later rewrites, and a compiler pass is exactly the second wiring
channel CoreShop's map cites.  Passes are NOT read here; a lane that needs
one still reads `DependencyInjection/Compiler/*Pass.php` by hand.

REFUSAL, NOT GUESSWORK.  The configurator vocabulary is open-ended.  Every
construct this module has a rule for is named in `_STRUCTURAL`, `_NO_EFFECT`
and `_ARG_FUNCTIONS` below; anything else is recorded in `graph["refusals"]`
by name, with its file and line, and contributes no edge.  A file that is
not service wiring at all (a `<constraint-mapping>`, a `doctrine` mapping, a
framework `app/*.yml`) is *skipped*, which is a different fact and is
counted separately -- calling it a refusal would drown the real ones.

`delegates()` proposes; it never decides.  §2.2 keeps the delegation
boundary a reviewed judgment: generic repositories, factories and
serialization primitives stay readable unless they implement the tested
behavior.  A hop-1 edge from this module is evidence for that judgment and
is not itself one.
"""
from __future__ import annotations

import os
import re
from typing import Iterable, Optional
from xml.etree import ElementTree

import yaml

from .behat_wiring import _TolerantLoader
from .behat_wiring_php import (_PARAMETER_ROOTS, _chain_root, _match_paren,
                               _unquote, resolve_class, strip_php_comments,
                               use_table)

#: The graph schema this module writes.
SCHEMA = "r2t.di-graph/1"

#: The corpus the optional live leg of `selftest` reads when present.
SYLIUS_CORPUS = "/data2/binhang/r2t_onb_sylius/projects/sylius/source"
SYLIUS_PROD_INDEX = "/data2/binhang/r2t_onb_sylius/artifacts/php_prod_index.json"
#: `boundary_sylius.yml`'s `behat.prod_paths` row.
SYLIUS_PROD_PATHS = ("src/Sylius/Component", "src/Sylius/Bundle",
                     "src/Sylius/Abstraction")

# --------------------------------------------------------------------------
# The closed sets.  A construct outside them refuses BY NAME.
# --------------------------------------------------------------------------

#: Chain methods that change the graph.
_STRUCTURAL = frozenset((
    "set", "alias", "args", "arg", "class", "decorate", "parent", "factory",
    "call", "load", "exclude", "defaults"))

#: Chain methods that are recognised and provably irrelevant to delegation:
#: they set visibility, laziness, tags or deprecation, none of which binds a
#: collaborator.  Listed rather than ignored by default, so that a method
#: that DOES bind one (`bind`, `property`, `configurator`, `instanceof`)
#: falls through to a refusal instead of being silently dropped.
_NO_EFFECT = frozenset((
    "tag", "public", "private", "abstract", "lazy", "share", "shared",
    "deprecate", "autoconfigure", "synthetic", "file",
    "nullOnInvalid", "ignoreOnInvalid"))

#: Chain methods that turn autowiring on for what follows.
_AUTOWIRE = frozenset(("autowire",))

#: Container-level methods.
_CONTAINER = frozenset(("services", "parameters", "import", "extension",
                        "withPath", "when", "env"))

#: Argument functions with a rule.  The value is the token kind produced.
_ARG_FUNCTIONS = {
    "service": "ref",
    "service_closure": "ref",
    "inline_service": "inline",
    "tagged_iterator": "tagged",
    "tagged_locator": "tagged",
    "service_locator": "collection",
    "iterator": "collection",
    "param": "param",
    "abstract_arg": "opaque",
    "expr": "opaque",
    "env": "opaque",
}

#: `->nullOnInvalid()` / `->ignoreOnInvalid()`: "may be absent", `@?id` in the
#: vocabulary `behat_wiring` established and this module keeps.
_OPTIONAL_SUFFIX = ("->nullOnInvalid()", "->ignoreOnInvalid()")

_CALL_RE = re.compile(r"->\s*(\w+)\s*\(")


# --------------------------------------------------------------------- util
def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _spans(text: str, sep: str = ",") -> list:
    """`[(start, end)]` of the parts of `text` split at top-level `sep`.

    `behat_wiring_php._split_top` answers the same question without the
    offsets.  Offsets are the point here: a delegation edge is only worth
    anything with the file and line that states it.
    """
    out, start, depth = [], 0, 0
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
            out.append((start, i))
            start = i + 1
        i += 1
    out.append((start, n))
    return [(a, b) for a, b in out if text[a:b].strip()]


# ------------------------------------------------------------- config roots
def config_roots(repo_root: str,
                 prod_paths: Iterable[str] = SYLIUS_PROD_PATHS) -> list:
    """Every `Resources/config` directory under the boundary's prod paths.

    The default: the boundary's own `behat.prod_paths` row decides what is
    production, so the wiring that is production wiring is the wiring that
    lives under it.  `src/Sylius/Behat/Resources/config` is therefore NOT a
    production root -- it is the glue, and `behat_wiring_php` reads it.
    """
    roots = []
    for rel in prod_paths:
        base = os.path.join(repo_root, rel)
        for dirpath, dirnames, _files in os.walk(base):
            dirnames.sort()
            if (os.path.basename(dirpath) == "config"
                    and os.path.basename(os.path.dirname(dirpath))
                    == "Resources"):
                roots.append(dirpath)
                dirnames[:] = []          # its subtree belongs to this root
    return sorted(roots)


def _config_files(roots: Iterable[str]) -> list:
    out = []
    for root in roots:
        for dirpath, dirnames, files in os.walk(root):
            dirnames.sort()
            for name in sorted(files):
                if name.rsplit(".", 1)[-1] in ("php", "xml", "yml", "yaml"):
                    out.append(os.path.join(dirpath, name))
    return out


# --------------------------------------------------------------- the graph
class _Graph:
    """Accumulator with the bookkeeping every reader shares."""

    def __init__(self, repo_root: str):
        self.repo_root = os.path.abspath(repo_root)
        self.services: dict = {}
        self.aliases: dict = {}
        self.refusals: list = []
        self.skipped: list = []
        self.parsed: dict = {}            # rel file -> definitions from it

    def rel(self, path: str) -> str:
        return os.path.relpath(os.path.abspath(path), self.repo_root)

    def refuse(self, path: str, line: int, construct: str, reason: str):
        self.refusals.append({"file": self.rel(path), "line": line,
                              "construct": construct, "reason": reason})

    def skip(self, path: str, reason: str):
        self.skipped.append({"file": self.rel(path), "reason": reason})

    def define(self, sid: str, record: dict, path: str):
        self.services[sid] = record
        rel = self.rel(path)
        self.parsed[rel] = self.parsed.get(rel, 0) + 1

    def note_alias(self, alias: str, target: str, path: str):
        self.aliases[alias] = target
        rel = self.rel(path)
        self.parsed[rel] = self.parsed.get(rel, 0) + 1


def _autowire_types(services: dict, aliases: dict) -> dict:
    """`FQCN -> service id`, Symfony's own by-type binding rule.

    A type is bound to a service when an alias is NAMED for the type
    (`->alias(MoneyFormatterInterface::class, 'sylius.formatter.money')`) or
    when a service's id IS its class.  Nothing else in a configurator binds
    a type, so nothing else is inferred here.
    """
    out = {}
    for sid, record in services.items():
        if record.get("class") and sid == record["class"]:
            out[sid] = sid
    for alias, target in aliases.items():
        if "\\" in alias:
            out[alias] = target
    return out


def build_graph(repo_root: str,
                roots: Optional[Iterable[str]] = None,
                prod_paths: Iterable[str] = SYLIUS_PROD_PATHS,
                index: Optional[dict] = None) -> dict:
    """The static service graph of `repo_root`'s production wiring."""
    if roots is None:
        roots = config_roots(repo_root, prod_paths)
    roots = list(roots)
    g = _Graph(repo_root)
    for path in _config_files(roots):
        suffix = path.rsplit(".", 1)[-1]
        if suffix == "php":
            _read_php(g, path, index)
        elif suffix == "xml":
            _read_xml(g, path)
        else:
            _read_yaml(g, path)
    return {"schema": SCHEMA,
            "root": g.repo_root,
            "config_roots": [g.rel(r) for r in roots],
            "services": g.services,
            "aliases": g.aliases,
            "autowire_types": _autowire_types(g.services, g.aliases),
            "definitions_per_file": g.parsed,
            "refusals": g.refusals,
            "skipped": g.skipped}


# ------------------------------------------------------------ PHP arguments
def _arg_token(raw: str, uses: dict, path: str, line: int, g: _Graph):
    """One configurator argument in this module's reference vocabulary.

    `@id` a service reference, `@?id` an optional one, `#Fqcn` an inline
    service (a real collaborator, spelled anonymously), `!tagged:name` a
    tagged registry (NAMED and left unexpanded -- expanding it would decide
    a delegation boundary this module is not allowed to decide), `%p%` a
    container parameter, a list for a nested array, and a plain string for
    a literal or a `Cls::class`.
    """
    raw = raw.strip()
    for suffix in _OPTIONAL_SUFFIX:
        if raw.endswith(suffix):
            inner = _arg_token(raw[:-len(suffix)], uses, path, line, g)
            if isinstance(inner, str) and inner.startswith("@"):
                return "@?" + inner[1:]
            return inner
    if raw.startswith("[") and raw.endswith("]"):
        body = raw[1:_match_paren(raw, 0)]
        return [_arg_token(body[a:b], uses, path, line, g)
                for a, b in _spans(body, ",")]
    if "=>" in raw and not raw[:1] in "'\"":
        # a named or keyed argument: `'$currency' => service('x')`
        _key, _sep, value = raw.partition("=>")
        return _arg_token(value, uses, path, line, g)
    call = re.match(r"([A-Za-z_]\w*)\s*\(", raw)
    if call is not None and raw.endswith(")"):
        name = call.group(1)
        inner = raw[call.end():_match_paren(raw, call.end() - 1)]
        kind = _ARG_FUNCTIONS.get(name)
        if kind is None:
            g.refuse(path, line, name + "()",
                     "argument function outside the closed set; the argument "
                     "contributes no edge rather than a guessed one")
            return "!refused:" + name
        if kind == "ref":
            return "@" + _php_literal(inner, uses)
        if kind == "inline":
            return "#" + _php_literal(inner, uses)
        if kind == "tagged":
            return "!tagged:" + _php_literal(inner, uses)
        if kind == "collection":
            return [_arg_token(inner[a:b], uses, path, line, g)
                    for a, b in _spans(inner, ",")]
        if kind == "param":
            return "%" + _php_literal(inner, uses) + "%"
        return "!" + name
    return _php_literal(raw, uses)


def _php_literal(raw: str, uses: dict) -> str:
    raw = raw.strip()
    if raw[:1] in "'\"":
        return _unquote(raw)
    if raw.endswith("::class"):
        return resolve_class(raw[:-len("::class")], uses)
    return raw


def _parse_php_args(raw: str, uses: dict, path: str, line: int,
                    g: _Graph) -> list:
    raw = raw.strip()
    if raw.startswith("["):
        raw = raw[1:_match_paren(raw, 0)]
    return [_arg_token(raw[a:b], uses, path, line, g)
            for a, b in _spans(raw, ",")]


# -------------------------------------------------------------- PHP reader
def _read_php(g: _Graph, path: str, index: Optional[dict]):
    raw = _read(path)
    text = strip_php_comments(raw)
    if "->services()" not in text and "$services" not in text:
        g.skip(path, "no `$container->services()` block: not service wiring")
        return
    uses = use_table(text)
    current: Optional[dict] = None
    mode = "none"                  # "service" | "defaults" | "none"
    defaults_autowire = False
    consumed = 0
    for m in _CALL_RE.finditer(text):
        if m.start() < consumed:
            continue               # inside an argument list already read
        name = m.group(1)
        try:
            close = _match_paren(text, m.end() - 1)
        except ValueError:
            g.refuse(path, _line_of(text, m.start()), "->" + name + "(",
                     "unbalanced brackets")
            continue
        body = text[m.end():close]
        line = _line_of(text, m.start())
        root = _chain_root(text, m.start())

        if name in _CONTAINER:
            continue
        if name in _NO_EFFECT:
            continue
        if name in _AUTOWIRE:
            if mode == "defaults":
                defaults_autowire = True
            elif current is not None:
                current["autowire"] = True
            continue
        if name not in _STRUCTURAL:
            g.refuse(path, line, "->" + name + "(",
                     "configurator method outside the closed set")
            current = None
            mode = "none"
            continue

        if name == "set":
            if root in _PARAMETER_ROOTS:
                current, mode = None, "none"
                continue
            parts = [body[a:b] for a, b in _spans(body, ",")]
            if not parts:
                continue
            sid = _php_literal(parts[0], uses)
            cls = (_php_literal(parts[1], uses) if len(parts) > 1
                   else (sid if "\\" in sid else None))
            current = {"class": cls, "arguments": [], "file": g.rel(path),
                       "line": line, "arg_line": line}
            if defaults_autowire:
                current["autowire"] = True
            mode = "service"
            g.define(sid, current, path)
            continue
        if name == "defaults":
            current, mode = None, "defaults"
            continue
        if name == "alias":
            parts = [body[a:b] for a, b in _spans(body, ",")]
            if len(parts) >= 2:
                g.note_alias(_php_literal(parts[0], uses),
                             _php_literal(parts[1], uses).lstrip("@?"), path)
            current, mode = None, "none"
            continue
        if name == "load":
            parts = [body[a:b] for a, b in _spans(body, ",")]
            if len(parts) >= 2:
                _expand_load(g, path, line, _php_literal(parts[0], uses),
                             _php_literal(parts[1], uses), index,
                             defaults_autowire)
            current, mode = None, "none"
            continue

        if current is None:
            continue
        if name == "args":
            current["arguments"] = _parse_php_args(body, uses, path, line, g)
            current["arg_line"] = line
            consumed = close
        elif name == "arg":
            parts = _spans(body, ",")
            if len(parts) >= 2:
                a, b = parts[1]
                current["arguments"].append(
                    _arg_token(body[a:b], uses, path, line, g))
                current["arg_line"] = line
            consumed = close
        elif name == "class":
            current["class"] = _php_literal(body, uses)
        elif name == "decorate":
            parts = _spans(body, ",")
            if parts:
                a, b = parts[0]
                current["decorates"] = _php_literal(body[a:b], uses)
                current["decorate_line"] = line
            consumed = close
        elif name == "parent":
            current["parent"] = _php_literal(body, uses)
        elif name == "factory":
            current["factory"] = _parse_php_args(body, uses, path, line, g)
            current["factory_line"] = line
            consumed = close
        elif name == "call":
            parts = _spans(body, ",")
            if parts:
                a, b = parts[0]
                method = _php_literal(body[a:b], uses)
                call_args = (_parse_php_args(
                    body[parts[1][0]:parts[1][1]], uses, path, line, g)
                    if len(parts) > 1 else [])
                current.setdefault("calls", []).append(
                    {"method": method, "arguments": call_args, "line": line})
            consumed = close
        elif name == "exclude":
            consumed = close


def _expand_load(g: _Graph, path: str, line: int, prefix: str, directory: str,
                 index: Optional[dict], autowire: bool):
    """`->load('Ns\\', '../src/')`: one service per class, id = FQCN.

    PSR-4 by construction: the directory IS the namespace prefix's root, so
    a file's path below it spells the rest of its name.  The production
    index decides which of those files actually declares that class -- with
    no index there is nothing to check the mapping against, so the
    registration is refused by name rather than assumed.
    """
    base = os.path.normpath(os.path.join(os.path.dirname(path), directory))
    if index is None:
        g.refuse(path, line, "->load()",
                 "no production index: a PSR-4 expansion cannot be checked "
                 "against the classes the directory actually declares")
        return
    prefix = prefix.rstrip("\\") + "\\"
    for rel, entry in sorted(index.get("files", {}).items()):
        full = os.path.normpath(os.path.join(g.repo_root, rel))
        if not full.startswith(base + os.sep):
            continue
        suffix = full[len(base) + 1:-len(".php")].replace(os.sep, "\\")
        expected = prefix + suffix
        for cls in entry.get("classes", []):
            if cls.get("name") != expected or cls.get("kind") != "class":
                continue
            record = {"class": expected, "arguments": [], "file": g.rel(path),
                      "line": line, "arg_line": line, "load": True}
            if autowire:
                record["autowire"] = True
            g.define(expected, record, path)


# -------------------------------------------------------------- XML reader
def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_arg(node, path: str, text: str, g: _Graph):
    kind = node.get("type")
    if kind in ("service", "service_closure"):
        token = "@" + (node.get("id") or "")
        if node.get("on-invalid") in ("null", "ignore"):
            token = "@?" + token[1:]
        return token
    if kind in ("collection", "iterator", "service_locator"):
        return [_xml_arg(child, path, text, g) for child in node
                if _xml_local(child.tag) == "argument"]
    if kind in ("tagged_iterator", "tagged_locator", "tagged"):
        return "!tagged:" + (node.get("tag") or "")
    if kind in ("expression", "abstract", "constant", "binary", "string",
                "closure"):
        return "!" + kind
    if kind is None:
        return (node.text or "").strip()
    g.refuse(path, _line_of(text, text.find('type="%s"' % kind)),
             '<argument type="%s">' % kind,
             "argument type outside the closed set")
    return "!refused:" + kind


def _read_xml(g: _Graph, path: str):
    text = _read(path)
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        g.refuse(path, 1, "<xml>", "not well-formed: %s" % exc)
        return
    if _xml_local(root.tag) != "container":
        g.skip(path, "<%s> root: not a service container"
               % _xml_local(root.tag))
        return
    blocks = [c for c in root if _xml_local(c.tag) == "services"]
    if not blocks:
        g.skip(path, "<container> with no <services> block")
        return
    for block in blocks:
        for node in block:
            local = _xml_local(node.tag)
            if local == "defaults":
                continue
            if local != "service":
                g.refuse(path, _line_of(text, text.find("<" + local)),
                         "<%s>" % local, "service-block element outside the "
                         "closed set")
                continue
            sid = node.get("id")
            if not sid:
                continue
            line = _line_of(text, text.find('id="%s"' % sid))
            if node.get("alias"):
                g.note_alias(sid, node.get("alias"), path)
                continue
            record = {"class": node.get("class") or (sid if "\\" in sid
                                                     else None),
                      "arguments": [], "file": g.rel(path), "line": line,
                      "arg_line": line}
            if node.get("autowire") == "true":
                record["autowire"] = True
            if node.get("decorates"):
                record["decorates"] = node.get("decorates")
                record["decorate_line"] = line
            if node.get("parent"):
                record["parent"] = node.get("parent")
            for child in node:
                child_local = _xml_local(child.tag)
                if child_local == "argument":
                    record["arguments"].append(_xml_arg(child, path, text, g))
                elif child_local == "call":
                    record.setdefault("calls", []).append(
                        {"method": child.get("method"),
                         "arguments": [_xml_arg(a, path, text, g)
                                       for a in child
                                       if _xml_local(a.tag) == "argument"],
                         "line": line})
                elif child_local not in ("tag", "deprecated",
                                         "autowiring-type"):
                    g.refuse(path, line, "<service><%s>" % child_local,
                             "service child element outside the closed set")
            g.define(sid, record, path)


# ------------------------------------------------------------- YAML reader
def _yaml_arg(value, path: str, g: _Graph, line: int):
    if isinstance(value, str):
        if value.startswith("@?"):
            return "@?" + value[2:]
        if value.startswith("@@"):
            return value[1:]
        if value.startswith("@"):
            return "@" + value[1:]
        return value
    if isinstance(value, list):
        return [_yaml_arg(v, path, g, line) for v in value]
    if isinstance(value, dict):
        tag = value.get("__tag__")
        if tag in ("tagged_iterator", "tagged_locator", "tagged"):
            inner = value.get("value")
            if isinstance(inner, dict):
                inner = inner.get("tag")
            return "!tagged:" + str(inner)
        if tag == "service":
            return "!inline_service"
        if tag is not None:
            g.refuse(path, line, "!" + str(tag),
                     "YAML argument tag outside the closed set")
            return "!refused:" + str(tag)
        return [_yaml_arg(v, path, g, line) for v in value.values()]
    return value


def _read_yaml(g: _Graph, path: str):
    text = _read(path)
    try:
        doc = yaml.load(text, Loader=_TolerantLoader) or {}
    except yaml.YAMLError as exc:
        if re.search(r"(?m)^services:", text) is None:
            g.skip(path, "no top-level `services:` key (and not plain YAML: "
                         "Symfony workflow/state-machine documents key their "
                         "places and transitions with structures PyYAML "
                         "cannot hash)")
            return
        g.refuse(path, 1, "yaml", "not loadable: %s" % exc)
        return
    if not isinstance(doc, dict) or "services" not in doc:
        g.skip(path, "no top-level `services:` key: not service wiring")
        return
    block = doc.get("services") or {}
    if not isinstance(block, dict):
        g.refuse(path, 1, "services:",
                 "`services:` is a %s, not a mapping" % type(block).__name__)
        return
    for sid, body in block.items():
        if sid in ("_defaults", "_instanceof"):
            continue
        line = _line_of(text, text.find("\n" + " " * 4 + str(sid) + ":") + 1)
        if isinstance(body, str):
            g.note_alias(sid, body.lstrip("@"), path)
            continue
        if body is None:
            body = {}
        if not isinstance(body, dict):
            g.refuse(path, line, "services.%s" % sid,
                     "definition is a %s" % type(body).__name__)
            continue
        if "alias" in body:
            g.note_alias(sid, str(body["alias"]).lstrip("@"), path)
            continue
        if "resource" in body:
            g.refuse(path, line, "resource:",
                     "a directory registration; the PSR-4 expansion of a "
                     "YAML `resource:` is not in the closed set")
            continue
        record = {"class": body.get("class") or (sid if "\\" in sid else None),
                  "arguments": [_yaml_arg(v, path, g, line)
                                for v in _yaml_args(body.get("arguments"))],
                  "file": g.rel(path), "line": line, "arg_line": line}
        if body.get("autowire") is True:
            record["autowire"] = True
        if body.get("decorates"):
            record["decorates"] = str(body["decorates"])
            record["decorate_line"] = line
        if body.get("parent"):
            record["parent"] = str(body["parent"])
        for key in body:
            if key not in ("class", "arguments", "autowire", "autoconfigure",
                           "decorates", "decoration_priority",
                           "decoration_inner_name", "parent", "tags",
                           "public", "shared", "lazy", "abstract", "calls",
                           "factory", "deprecated", "synthetic"):
                g.refuse(path, line, "services.%s.%s" % (sid, key),
                         "definition key outside the closed set")
        g.define(sid, record, path)


def _yaml_args(value) -> list:
    if value is None:
        return []
    if isinstance(value, dict):
        return list(value.values())
    if isinstance(value, list):
        return value
    return [value]


# -------------------------------------------------------------- delegation
def resolve_alias(graph: dict, sid: str, seen: Optional[set] = None) -> str:
    seen = seen or set()
    while sid in graph["aliases"] and sid not in seen:
        seen.add(sid)
        sid = graph["aliases"][sid]
    return sid


def _class_of(graph: dict, sid: str) -> Optional[str]:
    target = resolve_alias(graph, sid)
    record = graph["services"].get(target)
    return record.get("class") if record else None


def services_of_class(graph: dict, fqcn: str) -> list:
    return sorted(sid for sid, r in graph["services"].items()
                  if r.get("class") == fqcn)


def _index_classes(index: Optional[dict]) -> dict:
    if not index:
        return {}
    out = {}
    for rel, entry in index.get("files", {}).items():
        for cls in entry.get("classes", []):
            out[cls["name"]] = dict(cls, __path__=rel)
    return out


def _edges_for(graph: dict, sid: str, classes: dict) -> list:
    """The hop-1 edges one service definition states."""
    record = graph["services"][sid]
    file_, line = record["file"], record.get("arg_line", record["line"])
    out = []

    def ref(token, via, at):
        target = token.lstrip("@?")
        if target == ".inner":
            inner = record.get("decorates")
            if inner is None:
                return
            out.append({"to_class": _class_of(graph, inner),
                        "via": "decorate:.inner -> " + inner,
                        "evidence": {"file": file_,
                                     "line": record.get("decorate_line", at)}})
            return
        out.append({"to_class": _class_of(graph, target),
                    "via": via + ":" + target,
                    "evidence": {"file": file_, "line": at}})

    def walk(tokens, via, at):
        for token in tokens:
            if isinstance(token, list):
                walk(token, via, at)
            elif isinstance(token, str) and token.startswith("@"):
                ref(token, via, at)
            elif isinstance(token, str) and token.startswith("#"):
                out.append({"to_class": token[1:], "via": "inline_service",
                            "evidence": {"file": file_, "line": at}})

    walk(record.get("arguments", []), "service-id", line)
    for call in record.get("calls", []):
        walk(call.get("arguments", []),
             "call:" + str(call.get("method")), call.get("line", line))
    walk(record.get("factory", []), "factory", record.get("factory_line", line))
    if record.get("parent"):
        out.append({"to_class": _class_of(graph, record["parent"]),
                    "via": "parent:" + record["parent"],
                    "evidence": {"file": file_, "line": record["line"]}})

    # Autowiring by constructor type, only where the definition asks for it.
    if record.get("autowire") and not record.get("arguments"):
        cls = classes.get(record.get("class") or "")
        for param in (cls or {}).get("constructor", []):
            for type_ in param.get("types", []):
                bound = graph["autowire_types"].get(type_)
                if bound is not None:
                    out.append({"to_class": _class_of(graph, bound),
                                "via": "constructor-type:" + type_
                                       + " -> " + bound,
                                "evidence": {"file": file_,
                                             "line": record["line"]}})
                elif classes.get(type_, {}).get("kind") == "class":
                    out.append({"to_class": type_,
                                "via": "constructor-type:" + type_,
                                "evidence": {"file": file_,
                                             "line": record["line"]}})
                else:
                    out.append({"to_class": None,
                                "via": "constructor-type:" + type_
                                       + " (unbound)",
                                "evidence": {"file": file_,
                                             "line": record["line"]}})
    return out


def delegates(graph: dict, fqcn: str, hops: int = 1,
              index: Optional[dict] = None) -> list:
    """The classes `fqcn` delegates to, with the wiring that says so.

    One record per edge: `{to_class, via, evidence: {file, line}}`.  A
    `to_class` of `None` means the binding is named in `via` but resolves
    outside the scanned configuration -- a third-party or application-level
    service.  §2.2 wants exactly that recorded as an explicit stopping
    point, so it is an answer here and not an omission.

    A class with no service definition gets an empty list: nothing in the
    container wires it, which for a static utility or a `new`-ed
    collaborator is the true answer.  Following its call sites instead
    would be the transitive source walk §2.1 forbids below a principal.
    """
    classes = _index_classes(index)
    seen_class = {fqcn}
    seen_edge: set = set()
    frontier = [fqcn]
    out: list = []
    for _hop in range(max(1, hops)):
        nxt = []
        for cls in frontier:
            for sid in services_of_class(graph, cls):
                for edge in _edges_for(graph, sid, classes):
                    key = (edge["to_class"], edge["via"],
                           edge["evidence"]["file"], edge["evidence"]["line"])
                    if key in seen_edge:
                        continue
                    seen_edge.add(key)
                    out.append(edge)
                    target = edge["to_class"]
                    if target and target not in seen_class:
                        seen_class.add(target)
                        nxt.append(target)
        frontier = nxt
        if not frontier:
            break
    return out


def report(graph: dict) -> dict:
    """Counts a review lane can read without loading the whole graph."""
    per_format: dict = {}
    for rel, count in graph.get("definitions_per_file", {}).items():
        suffix = rel.rsplit(".", 1)[-1]
        per_format[suffix] = per_format.get(suffix, 0) + count
    files = graph.get("definitions_per_file", {})
    reasons: dict = {}
    for row in graph["refusals"]:
        reasons[row["construct"]] = reasons.get(row["construct"], 0) + 1
    skipped: dict = {}
    for row in graph["skipped"]:
        skipped[row["reason"]] = skipped.get(row["reason"], 0) + 1
    return {"services": len(graph["services"]),
            "definitions_per_format": per_format,
            "aliases": len(graph["aliases"]),
            "autowire_types": len(graph["autowire_types"]),
            "definition_files": len(files),
            "refusals": len(graph["refusals"]),
            "refusals_by_construct": reasons,
            "unparsed_files": sorted({r["file"] for r in graph["refusals"]}),
            "skipped_by_reason": skipped}


# ---------------------------------------------------------------- selftest
def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    import json
    import tempfile

    with tempfile.TemporaryDirectory() as root:
        def write(rel, text):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        # --- the PHP configurator, in the shapes the Sylius corpus uses ---
        write("src/Demo/Bundle/ShopBundle/Resources/config/services.php",
              """<?php
/* a licence header with a ; in it; and a (paren */
declare(strict_types=1);

namespace Symfony\\Component\\DependencyInjection\\Loader\\Configurator;

use Demo\\Bundle\\ShopBundle\\Formatter\\MoneyFormatter;
use Demo\\Bundle\\ShopBundle\\Formatter\\MoneyFormatterInterface;
use Demo\\Bundle\\ShopBundle\\Fixture\\AdminUserExampleFactory;
use Demo\\Bundle\\ShopBundle\\Api\\IriConverter;
use Demo\\Bundle\\ShopBundle\\Api\\Inner;

return static function (ContainerConfigurator $container) {
    $services = $container->services();
    $parameters = $container->parameters();

    $parameters->set('demo.locale', 'en_US');

    $services->set('demo.formatter.money', MoneyFormatter::class);
    $services->alias(MoneyFormatterInterface::class, 'demo.formatter.money');

    $services
        ->set('demo.fixture.example_factory.admin_user',
              AdminUserExampleFactory::class)
        ->args([
            service('demo.factory.admin_user'),
            '%demo.locale%',
            service('demo.uploader.image')->nullOnInvalid(),
            'a literal',
            tagged_iterator('demo.thing'),
            inline_service(Inner::class),
            service('third_party.filesystem'),
        ])
        ->tag('demo.fixture')
    ;

    $services
        ->set('demo.api.iri_converter', IriConverter::class)
        ->decorate('demo.api.inner_converter', null, 64)
        ->args([service('.inner'), service('demo.formatter.money')])
    ;

    $services
        ->set('demo.api.inner_converter', Inner::class)
        ->call('setFormatter', [service('demo.formatter.money')])
    ;

    $services->set('demo.factory.admin_user', 'Demo\\\\Bundle\\\\ShopBundle\\\\Fixture\\\\AdminUserFactory');
};
""")

        # --- the same questions in XML ---
        write("src/Demo/Bundle/ShopBundle/Resources/config/xml_services.xml",
              """<?xml version="1.0" encoding="UTF-8"?>
<container xmlns="http://symfony.com/schema/dic/services">
    <services>
        <service id="demo.uploader.image" class="Demo\\Bundle\\ShopBundle\\Uploader\\ImageUploader">
            <argument type="service" id="demo.formatter.money"/>
            <tag name="demo.uploader"/>
        </service>
        <service id="demo.alias.uploader" alias="demo.uploader.image"/>
    </services>
</container>
""")
        # ...and an XML file under the same root that is NOT service wiring.
        write("src/Demo/Bundle/ShopBundle/Resources/config/validation/Money.xml",
              """<?xml version="1.0" encoding="UTF-8"?>
<constraint-mapping xmlns="http://symfony.com/schema/dic/constraint-mapping">
    <class name="Demo\\Bundle\\ShopBundle\\Model\\Money"/>
</constraint-mapping>
""")

        # --- and in YAML, including the alias shorthand ---
        write("src/Demo/Bundle/ShopBundle/Resources/config/yaml_services.yaml",
              """services:
    _defaults:
        public: true

    demo.checker.deletion:
        class: Demo\\Bundle\\ShopBundle\\Checker\\DeletionChecker
        arguments:
            - '@demo.uploader.image'
            - '%demo.locale%'

    Demo\\Bundle\\ShopBundle\\Checker\\DeletionCheckerInterface: '@demo.checker.deletion'
""")

        # --- a directory registration, for the `load()` expansion ---
        write("src/Demo/Bundle/ShopBundle/Resources/config/loaded.php",
              """<?php
namespace Symfony\\Component\\DependencyInjection\\Loader\\Configurator;

return static function (ContainerConfigurator $container) {
    $services = $container->services();
    $services->defaults()->autowire();
    $services->load('Demo\\\\Bundle\\\\ShopBundle\\\\Processor\\\\', '../../Processor/');
};
""")

        # --- one construct outside the closed set ---
        write("src/Demo/Bundle/ShopBundle/Resources/config/odd.php",
              """<?php
namespace Symfony\\Component\\DependencyInjection\\Loader\\Configurator;

use Demo\\Bundle\\ShopBundle\\Odd\\Widget;

return static function (ContainerConfigurator $container) {
    $services = $container->services();
    $services->set('demo.odd.widget', Widget::class)
        ->property('collaborator', service('demo.formatter.money'));
    $services->set('demo.odd.other', Widget::class)
        ->args([shipping_calculator('demo.formatter.money')]);
};
""")

        index = {"files": {
            "src/Demo/Bundle/ShopBundle/Processor/PersistProcessor.php": {
                "classes": [{
                    "name": "Demo\\Bundle\\ShopBundle\\Processor"
                            "\\PersistProcessor",
                    "kind": "class",
                    "constructor": [
                        {"name": "formatter",
                         "types": ["Demo\\Bundle\\ShopBundle\\Formatter"
                                   "\\MoneyFormatterInterface"]},
                        {"name": "clock",
                         "types": ["Demo\\Bundle\\ShopBundle\\Clock"]},
                        {"name": "logger",
                         "types": ["Psr\\Log\\LoggerInterface"]}]}]},
            "src/Demo/Bundle/ShopBundle/Clock.php": {
                "classes": [{"name": "Demo\\Bundle\\ShopBundle\\Clock",
                             "kind": "class", "constructor": []}]}}}

        roots = config_roots(root, ["src/Demo"])
        check("`Resources/config` under the prod paths is the default root",
              [os.path.relpath(r, root) for r in roots]
              == ["src/Demo/Bundle/ShopBundle/Resources/config"], str(roots))

        g = build_graph(root, prod_paths=["src/Demo"], index=index)
        svc, aliases = g["services"], g["aliases"]

        check("the graph carries its schema", g["schema"] == SCHEMA)

        # -- format 1: the PHP configurator
        admin = svc.get("demo.fixture.example_factory.admin_user")
        check("PHP: `->set('id', Cls::class)` resolves the class through `use`",
              admin and admin["class"] == "Demo\\Bundle\\ShopBundle\\Fixture"
                                          "\\AdminUserExampleFactory",
              str(admin))
        check("PHP: `->args([...])` reads service refs, an optional ref, a "
              "parameter, a literal, a tagged registry and an inline service",
              admin["arguments"] == ["@demo.factory.admin_user",
                                     "%demo.locale%",
                                     "@?demo.uploader.image",
                                     "a literal",
                                     "!tagged:demo.thing",
                                     "#Demo\\Bundle\\ShopBundle\\Api\\Inner",
                                     "@third_party.filesystem"],
              str(admin["arguments"]))
        check("PHP: the definition's line is the `->set(` line, and the "
              "argument list states its own",
              admin["line"] == 23 and admin["arg_line"] == 25,
              f"{admin['line']}/{admin['arg_line']}")
        check("PHP: a container PARAMETER is not a service",
              "demo.locale" not in svc, str(sorted(svc)))
        check("PHP: `->decorate('other')` is recorded, so `service('.inner')` "
              "has something to resolve to",
              svc["demo.api.iri_converter"]["decorates"]
              == "demo.api.inner_converter",
              str(svc["demo.api.iri_converter"]))

        # -- format 2: XML
        check("XML: a `<service id class>` with a `<argument type=\"service\">`"
              " parses", svc["demo.uploader.image"]["arguments"]
              == ["@demo.formatter.money"],
              str(svc.get("demo.uploader.image")))
        check("XML: a non-container root is SKIPPED, not refused",
              any(r["file"].endswith("validation/Money.xml")
                  for r in g["skipped"])
              and not any(r["file"].endswith("validation/Money.xml")
                          for r in g["refusals"]),
              str(g["skipped"]))

        # -- format 3: YAML
        check("YAML: a `services:` block with `@id` arguments parses",
              svc["demo.checker.deletion"]["arguments"]
              == ["@demo.uploader.image", "%demo.locale%"],
              str(svc.get("demo.checker.deletion")))

        # -- aliasing, in all three spellings
        check("aliasing: PHP `->alias(Iface::class, 'id')`, XML "
              "`<service alias=>` and the YAML `Iface: '@id'` shorthand all "
              "land in one table",
              aliases.get("Demo\\Bundle\\ShopBundle\\Formatter"
                          "\\MoneyFormatterInterface") == "demo.formatter.money"
              and aliases.get("demo.alias.uploader") == "demo.uploader.image"
              and aliases.get("Demo\\Bundle\\ShopBundle\\Checker"
                              "\\DeletionCheckerInterface")
              == "demo.checker.deletion",
              str(aliases))
        check("an interface alias becomes an autowirable type",
              g["autowire_types"].get(
                  "Demo\\Bundle\\ShopBundle\\Formatter\\MoneyFormatterInterface")
              == "demo.formatter.money", str(g["autowire_types"]))

        # -- `load()` expansion
        loaded = svc.get("Demo\\Bundle\\ShopBundle\\Processor\\PersistProcessor")
        check("`->load(prefix, dir)` registers one service per PSR-4 class the "
              "index declares under that directory, id = FQCN",
              loaded is not None and loaded.get("load") is True
              and loaded["class"] == "Demo\\Bundle\\ShopBundle\\Processor"
                                     "\\PersistProcessor",
              str(loaded))
        check("...and only for a class the index actually declares there",
              "Demo\\Bundle\\ShopBundle\\Processor\\Missing" not in svc)
        check("...carrying the `defaults()->autowire()` of its own file",
              loaded.get("autowire") is True, str(loaded))

        # -- refusal, by name
        refusals = {r["construct"] for r in g["refusals"]}
        check("a configurator method outside the closed set refuses BY NAME",
              "->property(" in refusals, str(sorted(refusals)))
        check("...and so does an argument function outside it",
              "shipping_calculator()" in refusals, str(sorted(refusals)))
        check("the refused argument is marked rather than guessed",
              svc["demo.odd.other"]["arguments"]
              == ["!refused:shipping_calculator"],
              str(svc["demo.odd.other"]))
        check("the refusal names its file and line",
              all(r["file"].endswith("odd.php") and r["line"] > 0
                  for r in g["refusals"]), str(g["refusals"]))
        check("the report lists the unparsed file once",
              report(g)["unparsed_files"]
              == ["src/Demo/Bundle/ShopBundle/Resources/config/odd.php"],
              str(report(g)["unparsed_files"]))

        # -- delegation
        edges = delegates(g, "Demo\\Bundle\\ShopBundle\\Fixture"
                             "\\AdminUserExampleFactory", index=index)
        by_class = {e["to_class"]: e for e in edges}
        check("hop 1: an argument service id becomes an edge to its class",
              by_class.get("Demo\\Bundle\\ShopBundle\\Uploader\\ImageUploader",
                           {}).get("via") == "service-id:demo.uploader.image",
              str(edges))
        check("hop 1: an inline service is an edge to the class it names",
              by_class.get("Demo\\Bundle\\ShopBundle\\Api\\Inner", {}).get("via")
              == "inline_service", str(edges))
        check("hop 1: a service id defined nowhere in the scanned roots is an "
              "edge with a null class -- the stopping point, stated",
              any(e["to_class"] is None
                  and e["via"] == "service-id:third_party.filesystem"
                  for e in edges), str(edges))
        check("hop 1: the tagged registry contributes NO edge (naming it is "
              "this module's job; expanding it is the lane's)",
              not any("tagged" in e["via"] for e in edges), str(edges))
        check("each edge cites the file and line that states it",
              all(e["evidence"]["file"].endswith("services.php")
                  and e["evidence"]["line"] == 25
                  for e in edges
                  if e["via"].startswith(("service-id", "inline"))),
              str(edges))

        check("`->call('setX', [service('y')])` is setter injection and an "
              "edge, with the method in the `via`",
              any(e["via"] == "call:setFormatter:demo.formatter.money"
                  and e["to_class"] == "Demo\\Bundle\\ShopBundle\\Formatter"
                                       "\\MoneyFormatter"
                  for e in delegates(g, "Demo\\Bundle\\ShopBundle\\Api"
                                        "\\Inner")),
              str(delegates(g, "Demo\\Bundle\\ShopBundle\\Api\\Inner")))

        inner = delegates(g, "Demo\\Bundle\\ShopBundle\\Api\\IriConverter")
        check("`service('.inner')` resolves through `->decorate(...)` to the "
              "decorated service's class",
              any(e["via"] == "decorate:.inner -> demo.api.inner_converter"
                  and e["to_class"] == "Demo\\Bundle\\ShopBundle\\Api\\Inner"
                  for e in inner), str(inner))

        auto = delegates(g, "Demo\\Bundle\\ShopBundle\\Processor"
                            "\\PersistProcessor", index=index)
        vias = {e["via"]: e["to_class"] for e in auto}
        check("autowiring: an interface constructor type resolves through the "
              "alias table to the bound service's class",
              vias.get("constructor-type:Demo\\Bundle\\ShopBundle\\Formatter"
                       "\\MoneyFormatterInterface -> demo.formatter.money")
              == "Demo\\Bundle\\ShopBundle\\Formatter\\MoneyFormatter",
              str(auto))
        check("autowiring: a concrete first-party constructor type is its own "
              "edge", vias.get("constructor-type:Demo\\Bundle\\ShopBundle"
                               "\\Clock")
              == "Demo\\Bundle\\ShopBundle\\Clock", str(auto))
        check("autowiring: a type with no binding is recorded as unbound, not "
              "resolved to an arbitrary implementor",
              vias.get("constructor-type:Psr\\Log\\LoggerInterface (unbound)",
                       "sentinel") is None, str(auto))
        check("a class the container never wires has no delegates",
              delegates(g, "Demo\\Bundle\\ShopBundle\\Model\\Money") == [],
              "a static utility is not a delegation edge")

        check("hops=2 follows the graph one step further",
              any(e["via"].startswith("service-id:demo.formatter.money")
                  for e in delegates(
                      g, "Demo\\Bundle\\ShopBundle\\Fixture"
                         "\\AdminUserExampleFactory", hops=2, index=index)),
              "the uploader's own argument")

        check("the graph is JSON-serialisable",
              isinstance(json.dumps(g), str))

    # -- the live leg: the corpus itself, when this host has it.
    if not os.path.isdir(SYLIUS_CORPUS):
        print(f"  [note] {SYLIUS_CORPUS} is not present; the corpus leg is "
              f"skipped (the fixture leg above is the portable one)")
    else:
        graph = build_graph(SYLIUS_CORPUS)
        rep = report(graph)
        check("the corpus's production wiring parses (>= 1400 services)",
              rep["services"] >= 1400, str(rep["services"]))
        check("...all but eight definitions from PHP configurators, which is "
              "why CoreShop's YAML walk does not transfer: the whole tree "
              "holds four XML and four YAML service definitions, and they "
              "are two spellings of the same two `tests/` fixtures",
              rep["definitions_per_format"].get("php", 0) >= 1600
              and rep["definitions_per_format"].get("xml") == 4
              and rep["definitions_per_format"].get("yaml") == 4
              and "yml" not in rep["definitions_per_format"],
              str(rep["definitions_per_format"]))
        check("...and not one `.yml` file in the tree is service wiring: "
              "every one of them is framework, workflow or resource config",
              all(not r["file"].endswith(".yml")
                  for r in graph["services"].values()),
              str([r["file"] for r in graph["services"].values()
                   if r["file"].endswith(".yml")][:3]))
        check("...and no construct of the corpus is refused: the closed sets "
              "cover the wiring this tree actually contains",
              graph["refusals"] == [], str(graph["refusals"][:3]))
        check("...and every corpus definition that carries no class names a "
              "`->parent()` to inherit one from, so no class is lost to a "
              "parse miss",
              all(r.get("parent") for r in graph["services"].values()
                  if not r.get("class")),
              str([sid for sid, r in graph["services"].items()
                   if not r.get("class") and not r.get("parent")][:4]))
        check("the corpus's seven `->call()` setter injections read as "
              "service references",
              sorted(c["arguments"][0] for r in graph["services"].values()
                     for c in r.get("calls", []))
              == ["@ux.live_component.live_responder"] * 7,
              str([c for r in graph["services"].values()
                   for c in r.get("calls", [])][:2]))
        check("a known corpus definition reads with its arguments and line",
              graph["services"]["sylius.formatter.money"]["class"]
              == "Sylius\\Bundle\\MoneyBundle\\Formatter\\MoneyFormatter",
              str(graph["services"].get("sylius.formatter.money")))
        check("a corpus `->alias(Iface::class, 'id')` is an autowirable type",
              graph["autowire_types"].get(
                  "Sylius\\Bundle\\MoneyBundle\\Formatter"
                  "\\MoneyFormatterInterface") == "sylius.formatter.money")
        edges = delegates(graph, "Sylius\\Bundle\\CoreBundle\\Fixture\\Factory"
                                 "\\AdminUserExampleFactory")
        check("the first of T8's proposed principals has its four hop-1 "
              "delegates (the fifth argument is a container parameter), each "
              "citing the configurator line that states it",
              len(edges) == 4
              and all(e["evidence"]["file"].endswith(
                  "services/fixtures_factories.php")
                  and e["evidence"]["line"] == 121 for e in edges),
              str(edges))
        check("...and three of the four stop outside the scanned wiring: "
              "`sylius.factory.*` is registered by SyliusResourceBundle's "
              "compiler pass and `file_locator` is Symfony's own, neither of "
              "which this module reads",
              sorted(e["via"] for e in edges if e["to_class"] is None)
              == ["service-id:file_locator",
                  "service-id:sylius.factory.admin_user",
                  "service-id:sylius.factory.avatar_image"], str(edges))

    print("\n" + ("ALL PASS (di_walk_php)" if ok else "FAILURES (di_walk_php)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
