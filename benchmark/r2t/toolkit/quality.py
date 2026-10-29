"""S2 — per-item quality fields, recorded at extraction, applied at release.

The v8 analyser already computes `suitable`, `has_expected_behavior` and
step counts for every CoreShop scenario, and its `(feature_file, line)`
key joins to `item_id` exactly (545/545).  Those columns are carried
through here rather than recomputed.

Three fields are computed HERE instead, because the v8 versions cannot be
used as-is for this benchmark:

* **live step counts.**  The v8 Gherkin reader drops every `#` line
  before it counts anything, so it has no notion of a commented-out step
  or scenario and cannot express SPEC §7.4 or §7.5.
* **oracle.**  v8's `has_expected_behavior` is a keyword regex over body
  steps.  CoreShop writes many assertions as `Given`/`And` steps whose
  text contains "should", so a keyword-only reading under-counts.  The
  rule here is the UNION of the two readings — a step that resolves to
  `Then`, or a step whose text states an expectation whatever its
  keyword — and v8's answer is recorded alongside so the two can be
  compared rather than conflated.  On CoreShop domain they agree exactly
  (541 with an oracle, 4 without).
* **dependency profile.**  v8's static profile is a bag-of-substrings
  over the feature PATH, which labels `cart_link.feature` as
  `browser_ui` because the filename contains "link".  Here the profile is
  read off the closure and the suite: every CoreShop domain scenario
  needs the database, none of them needs a browser (the domain profile
  loads no Mink extension at all), and anything that does touch Mink is
  detected from the closure's own imports.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Optional

from ..core.boundary import Boundary
from ..core.gherkin import is_commented_out, parse_feature_file
from ..java.algorand import runtime_feature_path

#: Keyword-independent oracle test.  An assertion in CoreShop is a step
#: that states an expected outcome, whatever keyword introduces it.
_ORACLE = re.compile(
    r"\b(should|must|expect(?:ed|s)?|has to be|is expected)\b", re.I)

_MINK = re.compile(r"Behat\\Mink|Mink\\Session|MinkContext")
#: A URL in a licence header is not a network dependency — CoreShop puts
#: `https://www.coreshop.com` at the top of every file, which made a naive
#: `https?://` scan label 530 of 545 items `network`.  Only real client
#: usage counts.
_NETWORK = re.compile(
    r"GuzzleHttp|Symfony\\(?:Contracts|Component)\\HttpClient"
    r"|curl_init|HttpClientInterface|Psr\\Http\\Client")

#: The python equivalents.  Same rule as above, and the same honest limit:
#: an IMPORT is required, so a bare URL in a docstring and a bare module name
#: in prose are both ignored — but the scan is text, not AST, so `import
#: socket` written inside a comment or a docstring counts.  That is the same
#: looseness the two PHP patterns have, kept deliberately: the labels select
#: which items may run without a database or a browser, and an item wrongly
#: labelled `network` is one item not measured, while one wrongly labelled
#: clean is a measurement taken against a dependency nobody provisioned.
_PY_BROWSER = re.compile(
    r"\bfrom\s+selenium\b|\bimport\s+selenium\b|\bsplinter\b"
    r"|\bplaywright\b|\bwebdriver\b")
_PY_NETWORK = re.compile(
    r"\bimport\s+requests\b|\bfrom\s+requests\b|\bimport\s+httpx\b"
    r"|\bfrom\s+urllib\b|\bimport\s+urllib\b|\bhttp\.client\b"
    r"|\bimport\s+socket\b")
_JAVA_BROWSER = re.compile(r"\borg\.openqa\.selenium\b|\bplaywright\b")
_JAVA_NETWORK = re.compile(
    r"\bjava\.net\b|\bokhttp3\b|\borg\.apache\.http\b")

_RUBY_BROWSER = re.compile(
    r"\bselenium-webdriver\b|\bcapybara/cuprite\b|\bSelenium::WebDriver\b")
_RUBY_NETWORK = re.compile(
    r"\bnet/http\b|\bNet::HTTP\b|\bwebmock\b|\bWebMock\b|\bvcr\b|\bVCR\b")


# These label source capabilities, including loopback HTTP fixtures; they do
# not change the worker's network-none policy. Quoted exact imports avoid
# treating URLs or net/http/httptest alone as a network-client dependency.
_GO_BROWSER = re.compile(r"node_modules/vitest/vitest\.mjs")
_GO_NETWORK = re.compile(r'"(?:net|net/http)"')


@dataclass(frozen=True)
class DependencyRules:
    """How an item's `dependency_profile` is read off its closure.

    Three things, and the FIRST is the one this exists for.  `base` was the
    literal `["database"]` — true of CoreShop because every domain scenario
    boots Pimcore against MySQL, and false of python-docx, where a scenario
    opens a `.docx` with lxml and asserts about the object graph.  Left as a
    constant it would publish `dependency_profile: ["database"]` on 239 items
    belonging to a library that has no database, which is a claim about the
    corpus rather than a measurement of it.

    The two regexes are here rather than at module scope for the ordinary
    reason a second language needs its own: `Behat\\Mink` does not appear in
    Python and `import requests` does not appear in PHP, so a shared pattern
    would answer False for every item of whichever project it was not written
    for -- silently, and looking exactly like a clean profile.
    """

    base: tuple = ("database",)
    browser: re.Pattern = _MINK
    network: re.Pattern = _NETWORK


#: CoreShop's, and the default everywhere `deps` is not passed: `["database"]`
#: unconditionally, because Pimcore + MySQL is not optional for any of its
#: domain scenarios.
PHP_DEPENDENCIES = DependencyRules()

#: python+behave's.  The empty base is the whole point (D6): python-docx
#: needs no database, no browser and no network, and an item that touches one
#: of the last two says so through its own closure's imports.
BEHAVE_DEPENDENCIES = DependencyRules(base=(), browser=_PY_BROWSER,
                                      network=_PY_NETWORK)
CUCUMBER_DEPENDENCIES = DependencyRules(
    base=(), browser=_JAVA_BROWSER, network=_JAVA_NETWORK)
GO_DEPENDENCIES = DependencyRules(
    base=(), browser=_GO_BROWSER, network=_GO_NETWORK)

# Route A supplies each worker's PostgreSQL inside the image. Empty base
# means no external database provisioning; the project profile records this.
RUBY_DEPENDENCIES = DependencyRules(
    base=(), browser=_RUBY_BROWSER, network=_RUBY_NETWORK)

#: Closed, and refusing an unknown framework rather than defaulting: a stack
#: read under CoreShop's rules would be stamped "database" for a library that
#: has none, and nothing downstream distinguishes a stamped fact from a
#: measured one.
DEPENDENCIES_BY_FRAMEWORK = {"behat": PHP_DEPENDENCIES,
                             "behave": BEHAVE_DEPENDENCIES,
                             "cucumber": CUCUMBER_DEPENDENCIES,
                             "cucumber_ruby": RUBY_DEPENDENCIES,
                             "godog": GO_DEPENDENCIES}


def dependencies_for(framework: str) -> DependencyRules:
    try:
        return DEPENDENCIES_BY_FRAMEWORK[framework]
    except KeyError:
        raise SystemExit(
            f"REFUSED: no dependency-profile rules for framework "
            f"{framework!r}. The known ones are "
            f"{sorted(DEPENDENCIES_BY_FRAMEWORK)}; reading a stack under "
            f"another framework's rules records dependencies it does not have "
            f"and misses the ones it does.") from None


def _v8_rows(path: str, project: str) -> dict[str, dict]:
    if not path or not os.path.isfile(path):
        return {}
    out = {}
    with open(path, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if not row.get("feature_file") or not row.get("line"):
                continue
            if row.get("full_name", "").split("/")[0].lower() != project:
                continue
            out[f"{project}/{row['feature_file']}:{row['line']}"] = row
    return out


def tag_filter_matches(expr: Optional[str], tags: list[str]) -> bool:
    """Behat's tag filter language: `,` is OR, `&&` is AND, `~` negates."""
    if not expr:
        return True
    have = {t.lstrip("@") for t in tags}
    for conjunct in expr.split("&&"):
        ok = False
        for token in conjunct.split(","):
            token = token.strip()
            if not token:
                continue
            neg = token.startswith("~")
            name = token.lstrip("~@")
            if (name in have) != neg:
                ok = True
                break
        if not ok:
            return False
    return True


def upstream_selected(tags: list[str], profile_filter: Optional[str],
                      suite_filters: list[Optional[str]]) -> bool:
    """Would CoreShop's own CI ever have run this scenario?

    Behat AND-s the profile filter with each suite's filter, so a scenario
    runs only if some suite accepts it AND the profile does.  24 of the 545
    domain scenarios satisfy neither (14 files lack `@domain`, one is
    `@wip`): their step definitions have never been executed upstream, so a
    gold closure that fails for them is evidence about the SCENARIO, not
    about the closure extractor.  Recording this keeps the two apart.
    """
    if not tag_filter_matches(profile_filter, tags):
        return False
    return any(tag_filter_matches(f, tags) for f in suite_filters)


def _signature(feature, scenario) -> str:
    """A hash of the steps a scenario actually runs.

    CoreShop has 13 groups of byte-identical scenarios (26 items), some of
    them stale pre-refactor copies.  They are not excluded — they are real
    scenarios in the repository — but per-item outcomes on them are
    correlated, so anything computing a variance over items needs to know.
    """
    bg = [s.text for s in (feature.background.steps if feature.background else [])]
    body = [s.text for s in scenario.steps]
    return hashlib.sha1("\n".join(bg + ["--"] + body).encode()).hexdigest()[:12]


def item_quality(feature, scenario, closure: Optional[dict],
                 selection: Optional[tuple] = None,
                 *code_roots: str,
                 deps: DependencyRules = PHP_DEPENDENCIES) -> dict:
    body = scenario.steps
    bg = feature.background.steps if feature.background else []
    oracle_steps = [s.text for s in body if _ORACLE.search(s.text)
                    or s.resolved == "Then"]

    browser = False
    network = False
    for rel in (closure or {}).get("files", []) or []:
        # After stripping, closure files live in the gold tree, not the
        # repo; look in both so this stays correct in either state.
        path = next((os.path.join(r, rel) for r in code_roots
                     if os.path.isfile(os.path.join(r, rel))), None)
        if path is None:
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        if deps.browser.search(text):
            browser = True
        if deps.network.search(text):
            network = True

    # CoreShop's `["database"]` is still the default and still unconditional
    # (Pimcore + MySQL is not optional for a domain scenario); a stack that
    # needs none of the three starts empty and earns each entry from its own
    # closure.
    profile = list(deps.base)
    if browser:
        profile.append("browser")
    if network:
        profile.append("network")

    return {
        "live_step_count": len(body),
        "signature": _signature(feature, scenario),
        "upstream_selected": (None if selection is None else upstream_selected(
            feature.tags + scenario.tags, selection[0], selection[1])),
        "live_background_step_count": len(bg),
        "live_effective_step_count": len(body) + len(bg),
        "commented_out": is_commented_out(scenario),
        "has_oracle": bool(oracle_steps),
        "n_oracle_steps": len(oracle_steps),
        "tags": feature.tags + scenario.tags,
        "is_outline": scenario.kind.startswith("Scenario Outline"),
        "dependency_profile": profile,
        "closure_files": len((closure or {}).get("files", []) or []),
        "closure_contexts": len((closure or {}).get("context_classes", []) or []),
        "steps_removable": (closure or {}).get("counts", {}).get("steps_removable"),
        "steps_retained": (closure or {}).get("counts", {}).get("steps_retained"),
        "steps_unmatched": (closure or {}).get("counts", {}).get("steps_unmatched"),
        "answered_entirely_by_retained":
            (closure or {}).get("answered_entirely_by_retained"),
    }


def _upstream_selection(config_root: str) -> Optional[tuple]:
    """(profile tag filter, per-suite tag filters) from the ORIGINAL config."""
    import yaml as _yaml

    from .behat_wiring import load_suites
    prof = os.path.join(config_root, "src/CoreShop/Behat/Resources/config",
                        "profiles/default.yml")
    suites = os.path.join(config_root, "src/CoreShop/Behat/Resources/config",
                          "suites.yml")
    if not (os.path.isfile(prof) and os.path.isfile(suites)):
        return None
    with open(prof, encoding="utf-8") as fh:
        doc = _yaml.safe_load(fh) or {}
    pf = (((doc.get("default") or {}).get("gherkin") or {})
          .get("filters") or {}).get("tags")
    # Select by the FILE a suite is declared in, not by a `domain_` name
    # prefix: CoreShop has one domain suite (`product_quantity_price_rules`)
    # that does not follow the naming convention, and a prefix test
    # silently mislabelled its scenario as never-run-upstream.
    filters = [s.tag_filter for s in load_suites(suites).values()
               if "/suites/domain/" in s.file.replace(os.sep, "/")]
    return (pf, filters)


def build(boundary: Boundary, items_path: str, closures_path: str,
          out_path: str, v8_csv: Optional[str] = None,
          gold_root: Optional[str] = None,
          deps: DependencyRules = PHP_DEPENDENCIES) -> int:
    with open(closures_path, encoding="utf-8") as fh:
        closures = {c["item_id"]: c for c in json.load(fh)}
    v8 = _v8_rows(v8_csv or "", boundary.project)
    selection = None
    for root in (boundary.repo_root, gold_root):
        if root:
            selection = selection or _upstream_selection(root)

    features: dict = {}
    out = {}
    with open(items_path, encoding="utf-8") as fh:
        for line in fh:
            item = json.loads(line)
            if item["project"] != boundary.project:
                continue
            if item["task"] != "criterion_to_test":
                continue
            rel = item["provenance"]["file_path"]
            runtime_rel = runtime_feature_path(boundary.project, rel)
            path = os.path.join(boundary.repo_root, runtime_rel)
            if not os.path.isfile(path):
                continue
            feat = features.get(rel)
            if feat is None:
                feat = features[rel] = parse_feature_file(
                    path, allow_tag_gaps=boundary.project in {"kapua", "prestashop"})
            sc = feat.scenario_at(item["provenance"]["line"])
            if sc is None:
                continue
            q = item_quality(feat, sc, closures.get(item["item_id"]), selection,
                             boundary.repo_root,
                             *([gold_root] if gold_root else []),
                             deps=deps)
            row = v8.get(item["item_id"])
            if row:
                q["v8"] = {k: row.get(k) for k in (
                    "suitable", "has_expected_behavior", "step_count",
                    "background_step_count", "effective_step_count",
                    "step_definition_coverage", "step_definition_covered",
                    "testing_level", "tags")}
            out[item["item_id"]] = q

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    return len(out)


# ------------------------------------------------------------------ selftest
def selftest() -> int:
    """The dependency profile, which is the one field here that is a CLAIM.

    Step counts and the oracle rule are read off the Gherkin and are checked
    by `gherkin.selftest`; the profile is different in kind, because it is
    partly asserted rather than measured — `["database"]` was a constant, true
    of CoreShop and untrue of the second project.  A constant that is right
    for one corpus and wrong for the next fails silently: the field is present,
    plausible, and describes a database the library does not have.
    """
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    with tempfile.TemporaryDirectory() as root:
        feature_path = os.path.join(root, "doc-add-table.feature")
        with open(feature_path, "w", encoding="utf-8") as fh:
            fh.write("Feature: add a table\n"
                     "  Scenario: add a 2x2 table\n"
                     "    Given a document with no tables\n"
                     "    When I add a 2x2 table\n"
                     "    Then the document should have one table\n")
        feat = parse_feature_file(feature_path)
        sc = feat.scenario_at(2)

        def closure_over(name: str, body: str) -> dict:
            with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
                fh.write(body)
            return {"files": [name]}

        plain = closure_over(
            "table.py",
            "from behave import given, then\n"
            "from docx import Document\n"
            "@given('a document with no tables')\n"
            "def step_impl(context):\n"
            "    context.document = Document()\n")

        php = item_quality(feat, sc, plain, None, root)
        py = item_quality(feat, sc, plain, None, root, deps=BEHAVE_DEPENDENCIES)
        check("CoreShop's reading is unchanged: every item needs the database",
              php["dependency_profile"] == ["database"])
        check("a python library's reading starts from nothing and stays there",
              py["dependency_profile"] == [], str(py["dependency_profile"]))
        check("everything else about the item is the same measurement",
              {k: v for k, v in php.items() if k != "dependency_profile"}
              == {k: v for k, v in py.items() if k != "dependency_profile"})
        check("and the item is still measured, not emptied",
              py["live_step_count"] == 3 and py["has_oracle"] is True)

        # The regexes have to FIRE, or an empty profile would mean "we looked
        # and found nothing" and "we looked with the wrong language's pattern"
        # at the same time.
        netty = closure_over("net.py", "import requests\n"
                                       "from behave import given\n")
        browsy = closure_over("web.py", "from selenium import webdriver\n")
        check("a python closure that really does use the network says so",
              item_quality(feat, sc, netty, None, root,
                           deps=BEHAVE_DEPENDENCIES)["dependency_profile"]
              == ["network"])
        check("...and one that drives a browser says so",
              item_quality(feat, sc, browsy, None, root,
                           deps=BEHAVE_DEPENDENCIES)["dependency_profile"]
              == ["browser"])
        check("CoreShop's PHP patterns find neither in python source — which "
              "is exactly why the rules are per stack",
              item_quality(feat, sc, netty, None, root)["dependency_profile"]
              == ["database"])
        for label, source, wanted in (
                ("HTTP client", 'import "net/http"', ["network"]),
                ("listener", 'import "net"', ["network"]),
                ("Vitest", 'exec.Command("node", "node_modules/vitest/vitest.mjs")',
                 ["browser"]),
                ("URL comment", '// https://example.invalid', []),
                ("httptest alone", 'import "net/http/httptest"', [])):
            closure = closure_over("bdd_go_test.go", source)
            result = item_quality(feat, sc, closure, None, root,
                                  deps=dependencies_for("godog"))
            check("Go dependency label for " + label,
                  result["dependency_profile"] == wanted,
                  str(result["dependency_profile"]))
        # ... and the reverse, so neither pattern is merely permissive.
        mink = closure_over("MinkContext.php",
                            "<?php use Behat\\Mink\\Session;\n")
        guzzle = closure_over("Http.php", "<?php use GuzzleHttp\\Client;\n")
        check("the PHP patterns still fire on PHP",
              item_quality(feat, sc, mink, None, root)["dependency_profile"]
              == ["database", "browser"]
              and item_quality(feat, sc, guzzle, None,
                               root)["dependency_profile"]
              == ["database", "network"])
        check("and the python patterns do not fire on PHP",
              item_quality(feat, sc, mink, None, root,
                           deps=BEHAVE_DEPENDENCIES)["dependency_profile"] == [])

        java = closure_over(
            "NetworkSteps.java",
            "import java.net.HttpURLConnection;\n"
            "import org.openqa.selenium.WebDriver;\n")
        check("the Cucumber rules start without a database and detect Java "
              "browser/network imports",
              item_quality(feat, sc, java, None, root,
                           deps=CUCUMBER_DEPENDENCIES)["dependency_profile"]
              == ["browser", "network"])

        ruby = closure_over(
            "browser_steps.rb",
            "require 'selenium-webdriver'\nrequire 'capybara/cuprite'\n"
            "require 'net/http'\nrequire 'webmock'\nrequire 'vcr'\n")
        check("Ruby dependencies detect browser/network clients without an external DB",
              item_quality(feat, sc, ruby, None, root,
                           deps=RUBY_DEPENDENCIES)["dependency_profile"]
              == ["browser", "network"])
        ruby_local = closure_over("local_steps.rb", "expect(2 + 2).to eq(4)\n")
        check("plain Ruby steps have no browser or external-network dependency",
              item_quality(feat, sc, ruby_local, None, root,
                           deps=RUBY_DEPENDENCIES)["dependency_profile"] == [])

        source_rel = "features/unit/offline.feature"
        runtime_rel = runtime_feature_path("algorand-sdk", source_rel)
        runtime_path = os.path.join(root, runtime_rel)
        os.makedirs(os.path.dirname(runtime_path), exist_ok=True)
        with open(runtime_path, "w", encoding="utf-8") as fh:
            fh.write("Feature: offline\n  Scenario: mapped\n"
                     "    Then the result should be available\n")
        items_path = os.path.join(root, "items.jsonl")
        with open(items_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "item_id": "algorand-sdk/features/unit/offline.feature:2",
                "project": "algorand-sdk", "task": "criterion_to_test",
                "provenance": {"file_path": source_rel, "line": 2},
            }) + "\n")
        closures_path = os.path.join(root, "closures.json")
        with open(closures_path, "w", encoding="utf-8") as fh:
            json.dump([], fh)
        quality_path = os.path.join(root, "quality.json")

        class AlgorandBoundary:
            project = "algorand-sdk"
            repo_root = root

        mapped_count = build(
            AlgorandBoundary(), items_path, closures_path, quality_path,
            deps=CUCUMBER_DEPENDENCIES)
        with open(quality_path, encoding="utf-8") as fh:
            mapped_quality = json.load(fh)
        check("quality reads an Algorand source identity from its composed "
              "runtime path",
              mapped_count == 1
              and "algorand-sdk/features/unit/offline.feature:2"
              in mapped_quality)

        # Kapua's native Account.feature separates its feature tags from
        # Feature: with a blank line. Quality must retain that selection.
        with open(feature_path, "w", encoding="utf-8") as fh:
            fh.write("@account\n@env_none\n\nFeature: User Account Service\n"
                     "  Scenario: Handle account creation\n"
                     "    Given a valid account\n"
                     "    Then the account should be created\n")
        with open(items_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "item_id": "kapua/doc-add-table.feature:5",
                "project": "kapua", "task": "criterion_to_test",
                "provenance": {"file_path": "doc-add-table.feature", "line": 5},
            }) + "\n")

        class KapuaBoundary:
            project = "kapua"
            repo_root = root

        kapua_count = build(
            KapuaBoundary(), items_path, closures_path, quality_path,
            deps=CUCUMBER_DEPENDENCIES)
        with open(quality_path, encoding="utf-8") as fh:
            kapua_quality = json.load(fh)
        check("quality retains Kapua native feature tags across blank lines",
              kapua_count == 1
              and kapua_quality["kapua/doc-add-table.feature:5"]["tags"]
              == ["@account", "@env_none"], str(kapua_quality))

    check("an unknown framework is refused rather than read under CoreShop's "
          "rules",
          dependencies_for("behat") is PHP_DEPENDENCIES
          and dependencies_for("behave") is BEHAVE_DEPENDENCIES
          and dependencies_for("cucumber") is CUCUMBER_DEPENDENCIES
          and dependencies_for("cucumber_ruby") is RUBY_DEPENDENCIES
          and _refuses(lambda: dependencies_for("unknown")))

    print("\n" + ("ALL PASS (quality)" if ok else "FAILURES (quality)"))
    return 0 if ok else 1


def _refuses(fn) -> bool:
    try:
        fn()
        return False
    except SystemExit:
        return True


if __name__ == "__main__":
    raise SystemExit(selftest())
