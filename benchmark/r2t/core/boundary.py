"""The test/production boundary, as data (SPEC.md §3.1, decision D1).

Classification is longest-prefix: `retained` wins over `removable` so a
file inside a removable directory can be pulled back out by name (the
CoreShop tree needs exactly that — `Behat/Service/` is half glue and half
infrastructure).  Anything matching neither list is production and is
never touched.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import yaml
from .paths import BENCHMARK_ROOT

REMOVABLE = "removable"
RETAINED = "retained"
PRODUCTION = "production"


@dataclass
class Boundary:
    version: int
    project: str
    repo_root: str
    removable: list[tuple[str, str]] = field(default_factory=list)
    retained: list[tuple[str, str]] = field(default_factory=list)
    removable_config: list[str] = field(default_factory=list)
    retained_contexts: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def classify(self, rel_path: str) -> str:
        rel = rel_path.replace(os.sep, "/").lstrip("./")
        best, verdict = -1, PRODUCTION
        for prefix, _ in self.retained:
            if _matches(rel, prefix) and len(prefix) > best:
                best, verdict = len(prefix), RETAINED
        for prefix, _ in self.removable:
            if _matches(rel, prefix) and len(prefix) > best:
                best, verdict = len(prefix), REMOVABLE
        return verdict

    def is_test_code(self, rel_path: str) -> bool:
        return self.classify(rel_path) in (REMOVABLE, RETAINED)

    def removable_prefixes(self) -> list[str]:
        return [p for p, _ in self.removable]

    def retained_prefixes(self) -> list[str]:
        return [p for p, _ in self.retained]


def _matches(rel: str, prefix: str) -> bool:
    if prefix.endswith("/"):
        return rel.startswith(prefix)
    return rel == prefix or rel.startswith(prefix + "/")


def load_boundary(path: str, repo_root: Optional[str] = None) -> Boundary:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    def pairs(key):
        return [(e["path"].replace(os.sep, "/"), e.get("why", ""))
                for e in (doc.get(key) or [])]

    # `removable_config` is folded into the removable prefixes so that
    # ONE function decides what may be written, deleted or restored.  When
    # it was a second list, a restore that consulted only `classify()`
    # brought the removed suite and services YAML back into the stripped
    # repo — the wiring half of the answer, silently.
    config_removable = [(p.replace(os.sep, "/"), "DI/suite configuration, "
                         "synthesised per item (decision D2)")
                        for p in (doc.get("removable_config") or [])]

    from .paths import resolve_config_path

    return Boundary(
        version=doc["version"],
        project=doc["project"],
        repo_root=(repo_root if repo_root is not None
                   else resolve_config_path(doc["repo_root"])),
        removable=pairs("removable") + config_removable,
        retained=pairs("retained"),
        removable_config=list(doc.get("removable_config") or []),
        retained_contexts=list(doc.get("retained_contexts") or []),
        raw=doc,
    )


def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    here = BENCHMARK_ROOT
    b = load_boundary(os.path.join(here, "config", "boundary_coreshop.yml"))

    cases = {
        "src/CoreShop/Behat/Context/Domain/CartContext.php": REMOVABLE,
        "src/CoreShop/Behat/Context/Setup/StoreContext.php": REMOVABLE,
        "src/CoreShop/Behat/Context/Transform/CartContext.php": REMOVABLE,
        "src/CoreShop/Behat/Context/Hook/PimcoreSetupContext.php": RETAINED,
        "src/CoreShop/Behat/Model/Car.php": RETAINED,
        "src/CoreShop/Behat/Service/Setup.php": RETAINED,
        "src/CoreShop/Behat/Service/Index/RelationalIndexExtension.php": RETAINED,
        "src/CoreShop/Behat/Service/SampleCountryContext.php": REMOVABLE,
        "src/CoreShop/Behat/Service/Tracking/ConfigResolver.php": REMOVABLE,
        "src/CoreShop/Behat/Page/Frontend/HomePage.php": REMOVABLE,
        "src/CoreShop/Behat/Context/MyOwnContext.php": REMOVABLE,
        "src/CoreShop/Behat/Resources/config/services/contexts/hook.yml": RETAINED,
        "src/CoreShop/Behat/Bench/BenchRecorderHook.php": RETAINED,
        "src/CoreShop/Bundle/TestBundle/Context/Setup/ClassContext.php": RETAINED,
        "src/CoreShop/Component/Order/Model/Order.php": PRODUCTION,
        "src/CoreShop/Bundle/CoreBundle/CoreShopCoreBundle.php": PRODUCTION,
        "vendor/behat/behat/src/Behat/Behat/Context/Context.php": PRODUCTION,
        "features/domain/cart/cart_item_taxes.feature": PRODUCTION,
    }
    for path, want in cases.items():
        got = b.classify(path)
        check(f"{path} -> {want}", got == want, f"got {got}")

    check("retained beats removable on the same subtree",
          b.classify("src/CoreShop/Behat/Service/Setup.php") == RETAINED
          and b.classify("src/CoreShop/Behat/Service/StoreContextSetter.php") == REMOVABLE)
    check("prefix must respect directory boundaries",
          b.classify("src/CoreShop/Behatx/Thing.php") == PRODUCTION,
          b.classify("src/CoreShop/Behatx/Thing.php"))
    check("a model following the prompt can write where it was told",
          b.classify("src/CoreShop/Behat/Context/Domain/NewContext.php") == REMOVABLE)
    check("harness code is not writable by a solution",
          b.classify("src/CoreShop/Behat/Bench/BenchRecorderHook.php") == RETAINED)
    check("retained context list non-empty", len(b.retained_contexts) >= 9)
    check("removed DI/suite config classifies as removable",
          b.classify("src/CoreShop/Behat/Resources/config/services.yml") == REMOVABLE
          and b.classify("src/CoreShop/Behat/Resources/config/suites/domain/cart.yml") == REMOVABLE,
          b.classify("src/CoreShop/Behat/Resources/config/services.yml"))
    check("retained hook wiring survives inside a removed config tree",
          b.classify("src/CoreShop/Behat/Resources/config/services/contexts/hook.yml")
          == RETAINED)

    # ---- python-docx: the carve-out that decides whether the corpus exists --
    #
    # 53 binary fixtures sit inside `features/steps/`, which is the directory
    # a behave system under test must regenerate.  Removing them with the code
    # would not make the task harder, it would make every item impossible: a
    # `.docx` a scenario OPENS is an input, not glue, and a run stripped of it
    # fails for a reason that has nothing to do with test generation.
    #
    # These four cases are what "the carve-out is in force" means, and they
    # fail LOUDLY if it is ever dropped: the first two are the two classes the
    # carve-out separates, the third is the directory itself (written without
    # a trailing slash on purpose -- `classify` matches a bare prefix against
    # the path AND against `prefix + "/"`, so the entry covers the directory
    # and everything under it), and the fourth is the one file the decision
    # deliberately leaves REMOVABLE, because recreating the helper that turns
    # a fixture name into a path IS part of the task.
    d = load_boundary(os.path.join(here, "config", "boundary_python_docx.yml"))
    docx_cases = {
        "features/steps/document.py": REMOVABLE,
        "features/steps/helpers.py": REMOVABLE,
        "features/steps/test_files/doc-default.docx": RETAINED,
        "features/steps/test_files": RETAINED,
        "features/steps/test_files/subdir/monty-truth.png": RETAINED,
        "features/environment.py": RETAINED,
        "features/doc-add-table.feature": PRODUCTION,
        "src/docx/document.py": PRODUCTION,
        "pyproject.toml": PRODUCTION,
        # Directory-boundary respect, the same check CoreShop gets: a sibling
        # whose name merely STARTS with the retained prefix is not inside it.
        "features/steps/test_files_extra/x.docx": REMOVABLE,
    }
    for path, want in docx_cases.items():
        got = d.classify(path)
        check(f"[docx] {path} -> {want}", got == want, f"got {got}")
    check("[docx] the fixtures are carved out of the very prefix that is "
          "removable, by longest-prefix match and nothing else",
          len("features/steps/test_files") > len("features/steps/")
          and d.classify("features/steps/test_files/lena.gif") == RETAINED
          and d.classify("features/steps/lena.gif") == REMOVABLE)
    check("[docx] behave has no wiring to remove and says so with empty lists",
          d.removable_config == [] and d.retained_contexts == [])

    # ---- epubcheck: the boundary that could NOT be one broad prefix --------
    #
    # Cucumber-JVM's glue path is the runner's package and everything under
    # it, so the obvious shape is "`org/w3c/epubcheck/` is removable, with
    # exceptions".  That shape is unwritable here: `url/URLUtilsTest.java` is
    # a plain JUnit test inside the glue package, and this grammar can pull a
    # file back to RETAINED but never to PRODUCTION.  The table below is that
    # argument as cases -- three broad glue prefixes, two named files, and the
    # unit test that must stay untouched between them.
    e = load_boundary(os.path.join(here, "config", "boundary_epubcheck.yml"))
    java = "src/test/java/org/w3c/epubcheck"
    res = "src/test/resources"
    epub_cases = {
        # the eight step/hook-annotated glue classes, one per removable entry
        f"{java}/container/FilenameCheckerSteps.java": REMOVABLE,
        f"{java}/test/AssertionSteps.java": REMOVABLE,
        f"{java}/test/CLISteps.java": REMOVABLE,
        f"{java}/util/microsyntax/ViewportSteps.java": REMOVABLE,
        f"{java}/url/URLFragmentSteps.java": REMOVABLE,
        # owner ruling 1: single-consumer `{multimap}` registration, glue
        f"{java}/SharedParameterTypes.java": REMOVABLE,
        # owner ruling R1.5: retained, hashed, not candidate-editable
        f"{java}/test/ParameterTypes.java": RETAINED,
        f"{java}/test/EPUBCheckConfiguration.java": RETAINED,
        f"{java}/test/TestEnvironment.java": RETAINED,
        f"{java}/test/MessageInfo.java": RETAINED,
        f"{java}/test/TestReport.java": RETAINED,
        f"{java}/RunCucumberTest.java": RETAINED,
        f"{java}/DebugCucumberTest.java": RETAINED,
        # the JUnit-only tree falls through, INCLUDING the one file that sits
        # inside the glue package beside a removable Steps class
        f"{java}/url/URLUtilsTest.java": PRODUCTION,
        "src/test/java/com/adobe/epubcheck/vocab/VocabTest.java": PRODUCTION,
        "src/test/java/org/idpf/epubcheck/util/css/CssParserTest.java": PRODUCTION,
        # owner ruling 2: fixtures retained, criteria production, runner
        # configuration removable
        f"{res}/epub3/05-package-document/files/package-title-valid.opf": RETAINED,
        f"{res}/epub3/05-package-document/files": RETAINED,
        f"{res}/epub2/files/x.epub": RETAINED,
        f"{res}/css/samples.css": RETAINED,
        f"{res}/epub3/test-files-unused/video-valid.xhtml": RETAINED,
        f"{res}/opf-peeker/uniqueId.opf": RETAINED,
        f"{res}/stress/mimetype": RETAINED,
        f"{res}/epub3/05-package-document/package-document.feature": PRODUCTION,
        f"{res}/cli/cli.feature": PRODUCTION,
        f"{res}/cucumber.properties": REMOVABLE,
        "src/main/java/com/adobe/epubcheck/api/EpubCheck.java": PRODUCTION,
        "pom.xml": PRODUCTION,
    }
    for path, want in epub_cases.items():
        got = e.classify(path)
        check(f"[epubcheck] {path} -> {want}", got == want, f"got {got}")
    check("[epubcheck] the acceptance root is the whole glue package, so a "
          "class the prompt asked for is accepted under a name nobody "
          "enumerated",
          e.classify(f"{java}/test/MyOwnSteps.java") == REMOVABLE
          and e.classify(f"{java}/container/MyOwnSteps.java") == REMOVABLE)
    check("[epubcheck] a fixture directory does not shadow the .feature file "
          "beside it -- the criterion text is production, the data is not",
          e.classify(f"{res}/cli/files/valid.epub") == RETAINED
          and e.classify(f"{res}/cli/cli.feature") == PRODUCTION)
    check("[epubcheck] prefix must respect directory boundaries, so a "
          "sibling merely STARTING with a fixture root is not inside it",
          e.classify(f"{res}/stress-extra/x") == PRODUCTION
          and e.classify(f"{java}/test/ParameterTypesExtra.java") == REMOVABLE,
          e.classify(f"{res}/stress-extra/x"))
    check("[epubcheck] cucumber has no suite to synthesise contexts into and "
          "says so with an empty list, but it DOES have one runtime "
          "configuration file to remove",
          e.retained_contexts == []
          and e.removable_config == ["src/test/resources/cucumber.properties"],
          str(e.removable_config))

    print("\n" + ("ALL PASS (boundary)" if ok else "FAILURES (boundary)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
