"""Live-frame checks for Python xmlchemy accessor recording, without a corpus.

The coordinator supports Python 3.10; the execution image uses 3.12 and owns
`co_qualname`. These fixtures pass actual function `__qualname__` values to
the recorder's event method while profiling real calls and closure cells.
The complete installed hook remains a pinned-interpreter operator gate.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace

from . import bench_environment as recorder


_FACTORY_SOURCE = '''
class Meta(type):
    def __new__(meta, name, bases, namespace):
        cls = super().__new__(meta, name, bases, namespace)
        for name, descriptor in namespace.items():
            if isinstance(descriptor, Descriptor):
                descriptor._element_cls = cls
                descriptor._prop_name = name
                installed = name + "_lst" if descriptor.many else name
                setter = descriptor._setter if descriptor.writable else None
                setattr(cls, installed, property(descriptor._getter, setter))
                if descriptor.many:
                    delattr(cls, name)
        return cls

class Descriptor:
    many = False
    writable = False
    def __init__(self, tag):
        self.tag = tag
    @property
    def _getter(self):
        def get_value(obj):
            return obj.values[self._prop_name]
        return get_value
    @property
    def _setter(self):
        def set_value(obj, value):
            obj.values[self._prop_name] = value
        return set_value

class OneAndOnlyOne(Descriptor):
    pass
class OptionalAttribute(Descriptor):
    writable = True
class ZeroOrMore(Descriptor):
    many = True
'''

_MODEL_SOURCE = '''
class Element(metaclass=Meta):
    def __init__(self, **values):
        self.values = values

class Inline(Element):
    graphic: object = OneAndOnlyOne("graphic")
class Graphic(Element):
    graphicData = OneAndOnlyOne("graphicData")
class GraphicData(Element):
    pic = OneAndOnlyOne("pic")
class Picture(Element):
    blipFill = OneAndOnlyOne("blipFill")
class BlipFill(Element):
    blip = OneAndOnlyOne("blip")
class Blip(Element):
    embed = OptionalAttribute("embed")
    link = OptionalAttribute("link")
    _private = OptionalAttribute("private")
class Inherited(Blip):
    pass
class Override(Blip):
    embed = OptionalAttribute("different")
class Repeating(Element):
    p = ZeroOrMore("p")
class Ordinary(Element):
    def method(self):
        return self.values["value"]
    @property
    def value(self):
        return self.method()
class Transparent:
    def __get__(self, obj, owner):
        return obj.method()
class Wrapped(Ordinary):
    forwarded = Transparent()

def production_read(obj):
    return obj.embed
'''


def selftest() -> int:
    failures = 0

    def check(name, ok, details=""):
        nonlocal failures
        failures += not bool(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              + (f" -- {details}" if not ok and details else ""))

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        module_names = ("docx.oxml.xmlchemy", "binding_fixture")
        saved = {name: sys.modules.get(name) for name in module_names}
        try:
            def module(name, rel, source, supplied=None):
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")
                result = ModuleType(name)
                result.__file__ = str(path)
                result.__dict__.update(supplied or {})
                sys.modules[name] = result
                exec(compile(source, str(path), "exec"), result.__dict__)
                return result

            factory = module(module_names[0], "src/docx/oxml/xmlchemy.py", _FACTORY_SOURCE)
            models = module(module_names[1], "src/binding_fixture.py", _MODEL_SOURCE,
                            {name: getattr(factory, name) for name in
                             ("Meta", "OneAndOnlyOne", "OptionalAttribute", "ZeroOrMore")})
            names = {}
            for cls in vars(models).values():
                if not isinstance(cls, type):
                    continue
                for member in vars(cls).values():
                    functions = ((member.fget, member.fset, member.fdel)
                                 if isinstance(member, property) else (member,))
                    for function in functions:
                        if hasattr(function, "__code__"):
                            names[function.__code__] = function.__qualname__

            def capture(code, *, caller="features/steps/access.py", values=None):
                context = SimpleNamespace(_bench_direct=recorder._DirectCalls(str(root)))
                namespace = dict(vars(models), **(values or {}))
                operation = compile(code, str(root / caller), "exec")
                previous = sys.getprofile()

                def profile(frame, event, arg):
                    if event == "call":
                        context._bench_direct.record(
                            frame, names.get(frame.f_code, frame.f_code.co_name))

                sys.setprofile(profile)
                try:
                    exec(operation, namespace)
                finally:
                    sys.setprofile(previous)
                return context

            blip = models.Blip(embed="rId1", link="rId2", _private="hidden")
            inline = models.Inline(graphic=models.Graphic(
                graphicData=models.GraphicData(pic=models.Picture(
                    blipFill=models.BlipFill(blip=blip)))))
            context = capture("result = inline.graphic.graphicData.pic.blipFill.blip.embed",
                              values={"inline": inline})
            events = recorder._uninstall(context)
            bindings = [event["accessor_binding"] for event in events
                        if event["accessor_binding"] is not None]
            check("six actual accessor activations retain six declaring bindings",
                  {(b["owner"], b["attribute"], b["access_kind"]) for b in bindings}
                  == {(f"binding_fixture.{owner}", attribute, "get") for owner, attribute in
                      (("Inline", "graphic"), ("Graphic", "graphicData"),
                       ("GraphicData", "pic"), ("Picture", "blipFill"),
                       ("BlipFill", "blip"), ("Blip", "embed"))}, str(bindings))
            check("binding source lines name assignments, while callee evidence stays factory code",
                  all(b["declaring_file"] == "src/binding_fixture.py"
                      and _MODEL_SOURCE.splitlines()[b["declaring_line"] - 1].strip()
                          .startswith(b["attribute"])
                      for b in bindings)
                  and all(event["callee_file"] == "src/docx/oxml/xmlchemy.py"
                          and event["caller_file"] == "features/steps/access.py"
                          for event in events), str(events))
            check("shared factory code has distinct closed-over descriptor instances",
                  models.Blip.embed.fget.__code__ is models.Blip.link.fget.__code__
                  and models.Blip.embed.fget.__closure__[0].cell_contents
                      is not models.Blip.link.fget.__closure__[0].cell_contents)
            events = recorder._uninstall(capture(
                "a = obj.embed; b = obj.link; obj.embed = 'changed'; c = obj._private",
                values={"obj": blip}))
            check("shared getter code, setters and private properties stay distinct",
                  {(e["accessor_binding"]["attribute"], e["accessor_binding"]["access_kind"])
                   for e in events} == {("embed", "get"), ("embed", "set"),
                                         ("link", "get"), ("_private", "get")}, str(events))
            inherited = recorder._uninstall(capture("value = obj.embed", values={
                "obj": models.Inherited(embed="base")}))
            overridden = recorder._uninstall(capture("value = obj.embed", values={
                "obj": models.Override(embed="override")}))
            check("inheritance uses the installed base owner; overrides use the new declaration",
                  inherited[0]["accessor_binding"]["owner"] == "binding_fixture.Blip"
                  and overridden[0]["accessor_binding"]["owner"] == "binding_fixture.Override")
            repeated = recorder._uninstall(capture("value = obj.p_lst", values={
                "obj": models.Repeating(p=[1, 2])}))
            binding = repeated[0]["accessor_binding"]
            check("list properties name the installed _lst attribute and original assignment",
                  binding["attribute"] == "p_lst"
                  and _MODEL_SOURCE.splitlines()[binding["declaring_line"] - 1].strip()
                      .startswith("p = ZeroOrMore"), str(binding))
            ordinary = recorder._uninstall(capture("a = obj.value; b = obj.forwarded", values={
                "obj": models.Wrapped(value=1)}))
            check("ordinary calls retain explicit null binding and descriptor frames stay transparent",
                  ordinary and all(e["accessor_binding"] is None for e in ordinary)
                  and any(e["callee"] == "Ordinary.method"
                          and e["caller_file"] == "features/steps/access.py" for e in ordinary)
                  and all("__get__" not in e["callee"] for e in ordinary), str(ordinary))
            production = recorder._uninstall(capture("production_read(obj)", values={"obj": blip}))
            retained = recorder._uninstall(capture("value = obj.embed", caller="features/fixtures/keep.py",
                                                   values={"obj": blip}))
            check("the recorder retains production and retained callers without applying a boundary",
                  any(e["accessor_binding"] is not None
                      and e["caller_file"] == "src/binding_fixture.py" for e in production)
                  and retained[0]["caller_file"] == "features/fixtures/keep.py")

            detached = models.Blip.embed.fget
            saved_property = models.Blip.embed
            del models.Blip.embed
            try:
                unresolved = capture("result = detached(obj)", values={"detached": detached, "obj": blip})
                class CapturedOutput(io.StringIO):
                    flushed = False
                    def flush(self):
                        self.flushed = True
                        super().flush()

                output = CapturedOutput()
                original_stdout = sys.__stdout__
                try:
                    sys.__stdout__ = output
                    missing = recorder._uninstall(unresolved)
                finally:
                    sys.__stdout__ = original_stdout
                diagnostic = json.loads(output.getvalue().split(" ", 1)[1])
                check("an unresolved accessor withholds API and flushes raw evidence to the timeout-retained stream",
                      missing is None and output.flushed and len(diagnostic["errors"]) == 1
                      and diagnostic["direct_calls_raw"] == unresolved._bench_direct.events()
                      and diagnostic["errors"][0]["event"]["callee"] == detached.__qualname__
                      and "0 installed properties" in diagnostic["errors"][0]["reason"],
                      output.getvalue())
            finally:
                models.Blip.embed = saved_property

            # Per-step attribution (TARGET_INTERFACES_V2_SPEC section 4): the
            # hooks set the executing step's index by identity in the list
            # `before_scenario` captured, the event carries it, and a call
            # made between steps carries null.
            check("every event carries a `step` and an idle recorder stamps null",
                  all(e["step"] is None for e in ordinary + production + retained)
                  and set(ordinary[0]) == {"callee_file", "callee_line", "callee",
                                           "caller_file", "accessor_binding", "step"},
                  str(ordinary[:1]))
            first, second = object(), object()
            stepped = SimpleNamespace(_bench_direct=recorder._DirectCalls(str(root)),
                                      _bench_steps=[first, second])
            recorder.before_step(stepped, second)
            tagged_index = stepped._bench_direct.step
            recorder.after_step(stepped, second)
            cleared_index = stepped._bench_direct.step
            recorder.before_step(stepped, object())
            unknown_index = stepped._bench_direct.step
            check("before_step finds the step by identity and after_step clears it",
                  tagged_index == 1 and cleared_index is None and unknown_index is None)
            nested_scenario = SimpleNamespace(_bench_direct=recorder._DirectCalls(str(root)),
                                              _bench_steps=[first, second])
            recorder.before_step(nested_scenario, second)
            recorder.before_step(nested_scenario, object())      # execute_steps() child
            inner_index = nested_scenario._bench_direct.step
            recorder.after_step(nested_scenario, object())
            restored_index = nested_scenario._bench_direct.step
            recorder.after_step(nested_scenario, second)
            check("a step executed inside another (execute_steps) carries null and "
                  "the outer step's index is restored when it finishes",
                  inner_index is None and restored_index == 1
                  and nested_scenario._bench_direct.step is None)
            live = capture("a = obj.value", values={"obj": models.Wrapped(value=1)})
            live._bench_steps = [first, second]
            recorder.before_step(live, first)
            sys.setprofile(lambda frame, event, arg: (
                live._bench_direct.record(frame, names.get(frame.f_code, frame.f_code.co_name))
                if event == "call" else None))
            try:
                exec(compile("c = obj.value", str(root / "features/steps/access.py"), "exec"),
                     dict(vars(models), obj=models.Wrapped(value=4)))
            finally:
                sys.setprofile(None)
            recorder.after_step(live, first)
            stamped = recorder._uninstall(live)
            check("the same call from two steps is two events, keyed by step, "
                  "sorted null first",
                  [e["step"] for e in stamped if e["callee"] == "Ordinary.value"] == [None, 0]
                  and live._bench_direct.step is None,
                  str(stamped))
            scenario = SimpleNamespace(status="passed", line=4)
            off = recorder.build_record(scenario, [], 0.0, None, None)
            empty = recorder.build_record(scenario, [], 0.0, {"files": {}, "units": []}, [])
            refused = recorder.build_record(scenario, [], 0.0, {"files": {}, "units": []}, None,
                                             direct_calls_schema=recorder.DIRECT_CALLS_SCHEMA)
            check("empty new recordings identify their recorder; collection-off stays unknown",
                  empty["direct_calls_schema"] == "r2t.python_direct_calls/3"
                  and off["direct_calls_schema"] is None
                  and refused["direct_calls_schema"] == "r2t.python_direct_calls/3"
                  and refused["direct_calls"] is None
                  and empty["scenario_result"] == refused["scenario_result"] == "passed")
        finally:
            for name, original in saved.items():
                if original is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = original
    print("ALL PASS (accessor recorder)" if not failures else f"FAILURES: {failures}")
    return int(bool(failures))
