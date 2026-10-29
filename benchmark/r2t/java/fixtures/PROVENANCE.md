# `r2t/java/fixtures/` — where every byte in this directory came from

Fixtures under this directory are read by `r2t.java.closure_java.selftest`,
which runs with no container, no JVM and no network.  Each entry below states
the SOURCE, the RETRIEVAL DATE and the TRANSFORMATION applied, because a
witness whose provenance is not written down is not a witness — it is a number
somebody typed.

`closure_java.selftest` refuses when a file in this directory has no `##`
entry here, so a fixture cannot be added without saying where it came from.

---

## `cucumber_dry_run_epubcheck.json`

- **Kind**: SYNTHESIZED (not imported).  Written at this commit.
- **Format source**: `/data2/binhang/temp/ReqEnhancement_ours/ReqEnhancement/
  data/repos/with_tests/metasfresh/backend/de.metas.cucumber/target/cucumber.json`
  — real `io.cucumber` json-plugin output, read 2026-08-08.  Its member sets
  are the ones reproduced here, key for key:

      feature   uri elements id keyword line name tags description
      element   type keyword line name steps (+ id tags description
                start_timestamp on a scenario; a background carries neither)
      step      keyword line name match result (+ rows for a data table)
      result    status (+ duration, error_message)
      match     location (+ arguments)

  The `location` shape is that file's own: `fully.qualified.Class.method(
  fully.qualified.ParamTypes)`, and `rows` is its `[{"cells": [...]}]`.
  `start_timestamp` is deliberately NOT reproduced: it is optional, and a
  fabricated wall-clock in a checked-in fixture is a fact nobody measured.
- **Content source**: the scenarios, step texts, line numbers and step-
  definition signatures are epubcheck's own, at the commit `config/corpora.yml`
  pins (`82b174ec`), read 2026-08-08 from
  `/data2/binhang/req2test_corpora/epubcheck`:
  `src/test/resources/localization/localization.feature` (Background plus the
  scenarios at lines 11 and 16) and
  `src/test/resources/epub3/F-viewport-meta-tag/viewport-syntax.feature` (the
  first two Examples rows of the outline at line 7).  The four localization
  signatures are ART's own reading of the same registry
  (`art_step_definition_map_epubcheck.json`); the three `ViewportSteps` ones
  are read off `src/test/java/org/w3c/epubcheck/util/microsyntax/
  ViewportSteps.java`, which the ART map does not cover.
- **Transformation**: a dry run was never executed — D2a is the source half,
  and the live dry run is D2b.  This file states what cucumber 7.8.0 writes
  under `cucumber.execution.dry-run=true`: every bound step carries its
  `match.location` with `result.status = "passed"`, because a dry run builds
  every match and invokes nothing.  The feature `uri`s use the `classpath:`
  scheme epubcheck's `@CucumberOptions(features = "classpath:")` produces.
- **ONE DELIBERATE DEPARTURE, disclosed rather than repaired**: every `passed`
  step here carries `"duration": 0`, and cucumber never writes that value —
  `JsonFormatter.createResultMap` puts `duration` only when
  `!Result.getDuration().isZero()` (`javap -c`, offsets 55-84), so a real run
  writes a non-zero nanosecond count or omits the key.  A fabricated timing is
  a fact nobody measured, for the same reason `start_timestamp` is absent; the
  zero is here so that the parser's OPTIONAL `duration` member is exercised by
  a fixture at all.  Nothing in `closure_java` reads it.
- **Why it is here**: it is the format the parser is held to.  A real dry run
  replaces it as EVIDENCE at D2b; it does not replace it as a FIXTURE, because
  a parser test that needs a JVM is a parser test nobody runs.

## `cucumber_dry_run_epubcheck_stripped.json`

- **Kind**: SYNTHESIZED (not imported).  Written at this commit.
- **Source**: the same two localization scenarios as the file above, with the
  removable glue removed — which is what a strip does to this tree.
- **Transformation**: the steps `ExecutionSteps` and `AssertionSteps` answered
  become `"match": {}` — cucumber replaces a missing definition with an
  `UndefinedPickleStepDefinitionMatch`, which carries a `NoStepDefinition`
  (`getLocation()` is null) AND `Collections.emptyList()` arguments, so
  `JsonFormatter.createMatchMap` writes neither `location` nor `arguments` for
  them.  Their two statuses are NOT the same: the FIRST removable step of each
  scenario is `"undefined"`, and the one after it is `"skipped"`, because
  `TestStep.run` returns `ExecutionMode.SKIP` as soon as a step's result is not
  `PASSED`, `ExecutionMode.next` makes SKIP absorbing, and `SKIP.execute`
  returns `SKIPPED` without ever consulting the match.  A stripped tree
  therefore emits a LOCATIONLESS `skipped` step, which is why `_validate_step`
  exempts `skipped` from both directions of its location check — and why
  `_validate_skip_order` constrains it by POSITION instead: both `skipped`
  steps here sit directly behind an `undefined` one, which is the cause a
  genuine skip has to have, and the cause a forged one cannot supply.  The two
  Background steps and the reporting-locale step keep their locations, because
  `boundary_epubcheck.yml` RETAINS `TestEnvironment` and
  `EPUBCheckConfiguration`.  (Every cucumber fact in this bullet was read with
  `javap -c` over `~/.m2/repository/io/cucumber/cucumber-core/7.8.0/
  cucumber-core-7.8.0.jar`, the version epubcheck's `pom.xml` pins.)  The
  `"duration": 0` departure disclosed for the file above applies here too, on
  the FIVE step objects that kept their locations — counted as the json
  plugin EMITS them, which is the count `grep -c '"location":'` returns.
  Those five are three DISTINCT source steps: the Background pair is emitted
  once per scenario (2 x 2 = 4), plus the second scenario's own
  reporting-locale step.  The two counts differ because of that repetition —
  the same repetition that makes `parse_dry_run` pair elements positionally —
  and neither of them is four.
- **Why it is here**: it pins the shape of the stripped-tree question, and it
  pins the fact that for this corpus that question is not "every step is
  undefined".  Nine annotated methods survive a strip by owner ruling, so the
  gate `unstripped_bindings` implements is the honest one: no step of any
  pickle is answered by a REMOVABLE file.

## `art_step_definition_map_epubcheck.json`

- **Kind**: IMPORTED.
- **Source**: `/data2/binhang/temp/ReqEnhancement_ours/ReqEnhancement/data/
  scenario_data/epubcheck/scenario_step_definition_map.json`
- **Retrieved**: 2026-08-08.
- **Produced by**: ART (`utils/scenario_collector.py`), which ran cucumber
  once per scenario (`-Dcucumber.features=<path>
  -Dcucumber.filter.name=<title> -Dcucumber.plugin=pretty,summary`) and parsed
  the `pretty` plugin's own `# <signature>` comment lines.  It is therefore an
  INDEPENDENT reading of the same registry this module reads out of the `json`
  plugin — a witness, not a second copy of our own answer.
- **Transformation**: (1) wrapped in a `{"schema", "provenance", "scenarios"}`
  object so the provenance travels with the bytes; (2) `scenario_path` → `uri`
  with ART's `epubcheck/` prefix stripped, so the path is the repo-relative one
  this repository's boundary and item ids use; (3) `scenario_title` → `title`
  and `scenario_title_line_number` → `line`; (4) sorted by `(uri, line)`.  No
  scenario, no step and no signature was added, dropped or edited.
- **KNOWN INCOMPLETENESS, not repaired here**: the map covers **948 of the
  1041 scenarios** the pinned checkout holds, and the gap has TWO halves.
  This entry used to state only the first, which reads as "44 whole files"
  and is not what the bytes say.  Every count below is re-derived from the
  checkout at `82b174ec` with this repository's own
  `r2t.gherkin.parse_feature_file`, keyed by the `(uri, line)` pair the map
  itself is keyed by — no number here is dictated.

  1. **Five feature files the map never ran at all** (52 scenarios):
     `cli/cli.feature`, `epub3/A-unsupported/unsupported.feature`,
     `epub3/C-structural-semantics/structural-semantics.feature`,
     `epub3/F-viewport-meta-tag/viewport-syntax.feature` and
     `unit-tests/url-fragment.feature` — and with them the three glue classes
     `CLISteps`, `ViewportSteps` and `URLFragmentSteps`.

     The map therefore names **seven of the checkout's ten step-declaring
     classes, and 27 distinct signatures**.  Ten, because
     `grep -rlE '^\s*@(Given|When|Then|And|But)\(' src/test/java/org/w3c/
     epubcheck` at `82b174ec` hits ten files: the eight REMOVABLE glue
     classes `boundary_epubcheck.yml` counts, plus the two RETAINED ones
     (`EPUBCheckConfiguration`, `TestEnvironment`) whose leak that file
     discloses.  Seven, because the map names five of the removable eight
     (`FilenameCheckerSteps`, `AssertionSteps`, `ExecutionSteps`,
     `JSONReportAssertionSteps`, `XMLReportAssertionSteps`) and both retained
     ones.  This entry said "seven of the eight", which no reading can make
     true — seven named plus the three missing is ten, and the eight is the
     boundary's count of removable glue, of which the map names five.  The
     seven and the 27 are re-derived from the map's own bytes in
     `closure_java.selftest`, so they cannot drift.  The eight is
     `gate_s2_boundary_epubcheck.REMOVABLE_CENSUS` minus
     `SharedParameterTypes.java` (which declares a `@ParameterType`, not a
     step) and `cucumber.properties`.  The ten is the grep above and nothing
     re-derives it yet; run it before trusting it against a moved pin.

  2. **Forty-one scenarios INSIDE the 44 files it did run.**  Those 44 files
     hold 989 scenarios; the map has 948.  The cause is in the producer named
     above, and each kind is a different line of it:

     - **21 `Example:`-keyword scenarios** — 21 of the 23 scenarios of
       `epub3/D-vocabularies/vocabularies.feature` (lines 20, 26, 37, 42, 47,
       52, 57, 67, …); its two `Scenario:`-keyword ones ARE in the map, which
       is what makes this a keyword gap rather than a missing file.  Gherkin
       treats `Example:` as a synonym of `Scenario:`, but ART's own extractor
       recognises two keywords and no others
       (`utils/scenario_collector.py:204-207`), so these were never asked
       about.
     - **17 scenarios sharing a title with another scenario of the same
       file** — e.g. `epub2/opf-package-document.feature:67,75,81`, three
       scenarios all titled "the unique identifier must not be empty".  The
       selector is `-Dcucumber.filter.name=^<escaped title>$`
       (`scenario_collector.py:473`) and the parser returns nothing unless
       the console says exactly `1 Scenarios (1 passed)` (`:419`), so a title
       that selects two or three scenarios drops ALL of them.  None of the 17
       is in the map under any line.
     - **3 `Scenario Outline`s whose title carries a `<placeholder>`** —
       `epub3/04-ocf/filename-checker.feature:9,21,53`, which are also the
       only three outlines anywhere in the 44 files (its other five
       scenarios are in the map).  `filter.name` matches the SUBSTITUTED
       pickle names, so `^…<filename>…$` selects nothing and the same
       `1 Scenarios` guard drops them.

  `compare_to_gt` handles all 93 correctly — they land in `uncovered`, never
  in `agreed` — so this is a disclosure defect rather than a code defect.  It
  is written down because the ≥99% agreement gate at D2b reads over a
  denominator of 948, and a reader of the old sentence would have taken that
  for "every scenario of 44 files".


## `art_api_index_epubcheck.json`

- **Kind**: IMPORTED.
- **Source**: `/data2/binhang/temp/ReqEnhancement_ours/ReqEnhancement/data/
  project_api_index/epubcheck.json`
- **Retrieved**: 2026-08-08.
- **Produced by**: ART (`collect_project_api_index.py`) over
  `data/repos/with_tests/epubcheck/src/main/java`, with the tree-sitter query
  `(method_declaration name: (identifier) @name body: (block) @body)` and its
  constructor equivalent.
- **Transformation**: wrapped in a `{"schema", "provenance", "api_index"}`
  object; ART's own `project_name`, `language`, `source_dir`, `generated_at`
  and `total_apis` carried into `provenance.art` unchanged.  The 923
  `api_index` entries are byte-identical to the source.
- **Why it is here**: it is the witness for the defect this module fixes.  Two
  of its entries — `main` and `testisISO8601Date` — resolve to
  `com.adobe.epubcheck.util.DateParserTest`, a `main`-method test class
  upstream keeps under `src/main/java`.  The leak is pinned as DATA, so
  `drop_test_classes` is tested against the real bytes that carried it rather
  than against a hand-written imitation of them.

## `cucumber_6_11_kapua_ordinary.json`

- Kind: captured native Cucumber 6.11.0 JSON, excerpted on 2026-09-09.
- Source: `/srv/r2t/binhang/r2t_onb_kapua/cucumber-contract-attempt1/ordinary/native-test/reports/service/account/test/target/r2t-contract-ordinary.json`; full raw SHA256 `b0923913b2d16234b2ba8eaf4fe76ea0c09ed6cf0b62d81930747ab318c61dbb`.
- Corpus: eclipse-kapua/kapua commit
  `15c3c1e2c44f4a71885e2a16ed8c100c59e15091`.
- Development image config ID:
  `sha256:b0084fa24ff63f208a3dcbf29ea13a6c79944ceaf7eccb3433505e4f1f24ac81`.
  This is local runtime qualification evidence, not a canonical result.
- Capture: offline native `RunAccountUnitTest`, `ordinary` leg;
  driver SHA256 `16fdb50b959d56d6bd5d49cb1c0d4610deba67b2ec12b37fb56631bbf1886aeb`.
  The retained receipt records source, build and authority identities and actual exits.
- Transformation: keep only the scenario elements at source lines 22 and 25;
  preserve every field and value of those elements and their feature, including
  actual durations and timestamps; reserialize JSON with one-space indentation.
  No outcome or location was synthesized.
- Purpose: hold the version-specific status/location parser to real bound and
  missing-step output. Full captures retain all 22 source scenario identities.

## `cucumber_6_11_kapua_dry.json`

- Kind: captured native Cucumber 6.11.0 JSON, excerpted on 2026-09-09.
- Source: `/srv/r2t/binhang/r2t_onb_kapua/cucumber-contract-attempt1/dry/native-test/reports/service/account/test/target/r2t-contract-dry.json`; full raw SHA256 `94a8852dcb670d15a133f2d1e2f622bb29487e1ee40576778aaef9d5d0bcb1b8`.
- Corpus: eclipse-kapua/kapua commit
  `15c3c1e2c44f4a71885e2a16ed8c100c59e15091`.
- Development image config ID:
  `sha256:b0084fa24ff63f208a3dcbf29ea13a6c79944ceaf7eccb3433505e4f1f24ac81`.
  This is local runtime qualification evidence, not a canonical result.
- Capture: offline native `RunAccountUnitTest`, `dry` leg;
  driver SHA256 `16fdb50b959d56d6bd5d49cb1c0d4610deba67b2ec12b37fb56631bbf1886aeb`.
  The retained receipt records source, build and authority identities and actual exits.
- Transformation: keep only the scenario elements at source lines 22 and 25;
  preserve every field and value of those elements and their feature, including
  actual durations and timestamps; reserialize JSON with one-space indentation.
  No outcome or location was synthesized.
- Purpose: hold the version-specific status/location parser to real bound and
  missing-step output. Full captures retain all 22 source scenario identities.

## `cucumber_6_11_kapua_stripped_dry.json`

- Kind: captured native Cucumber 6.11.0 JSON, excerpted on 2026-09-09.
- Source: `/srv/r2t/binhang/r2t_onb_kapua/cucumber-contract-attempt1/stripped-dry/native-test/reports/service/account/test/target/r2t-contract-stripped-dry.json`; full raw SHA256 `d815f39eabc8c210bee2c5a9dfcae4a0db80a5f73d7024be12afb7beea61dbc4`.
- Corpus: eclipse-kapua/kapua commit
  `15c3c1e2c44f4a71885e2a16ed8c100c59e15091`.
- Development image config ID:
  `sha256:b0084fa24ff63f208a3dcbf29ea13a6c79944ceaf7eccb3433505e4f1f24ac81`.
  This is local runtime qualification evidence, not a canonical result.
- Capture: offline native `RunAccountUnitTest`, `stripped-dry` leg;
  driver SHA256 `16fdb50b959d56d6bd5d49cb1c0d4610deba67b2ec12b37fb56631bbf1886aeb`.
  The retained receipt records source, build and authority identities and actual exits.
- Transformation: keep only the scenario elements at source lines 22 and 25;
  preserve every field and value of those elements and their feature, including
  actual durations and timestamps; reserialize JSON with one-space indentation.
  No outcome or location was synthesized.
- Purpose: hold the version-specific status/location parser to real bound and
  missing-step output. Full captures retain all 22 source scenario identities.
