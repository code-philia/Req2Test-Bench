"""Every module selftest, in one command: `python3 -m r2t.selftest`.

These are the checks that need no container, no database and no stripped
repository — parsing, classification, wiring and closure logic against
hand-written fixtures.  Everything that needs the environment is checked
by the round-trip gate instead, which is the honest place for it.
"""
# Stays at the package root although its component moved into a package:
# `python3 -m r2t.selftest` is the invocation path pinned in this
# repository's documents, CI, bootstrap and approved workload records.
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

# Module level is safe in this direction only: `components` imports
# `selftest.MODULES` inside its functions, never at import time.
from .core import components

MODULES = ("core.paths",
           # The spellings two components share, and the component table
           # with the import direction it implies -- first, because every
           # module below is filed in that table and checked against it.
           "core.constants", "core.components", "core.source_view_selftest",
           "docker_authority", "core.docker_cli", "core.gherkin",
           "core.boundary", "go.context", "go.coddy", "go.mutation_copy_selftest", "go.mutation_runtime_selftest", "go.mutation_audit_selftest", "go.execution_selftest", "go.workspace_selftest", "go.runtime_selftest", "data.profile",
           # The corpus walk that writes `items.jsonl` (S1), ahead of the
           # modules below that read the items it emits.
           "toolkit.extract", "toolkit.behat_wiring",
           # The second Behat project's two halves of the same two questions
           # (`onb` track S): Sylius spells its DI and its suites in PHP
           # rather than YAML, so `behat_wiring_php` answers them into
           # `behat_wiring`'s own dataclasses, and `behat_suites` is the tag
           # evaluator + suite map that decides WHICH of two twin
           # definitions (Api or Ui) a step binds to.  Immediately after
           # `behat_wiring` because each is checked against it -- the
           # dispatch is on the entry's suffix and the shapes have to be
           # the same object -- and before `closure`, which is the reader
           # both of them exist for.
           "toolkit.behat_wiring_php", "toolkit.behat_suites",
           # The same corpus's PRODUCTION wiring, which is a different
           # question and a different tree: `behat_wiring_php` reads the
           # glue's `Resources/config`, `di_walk_php` reads every bundle's,
           # in all three formats Symfony accepts, and answers the delegation
           # question `IMPLEMENTATION_VISIBILITY_SPEC` section 2.2 asks of a
           # visibility map.  Directly after, because it imports that
           # module's scanner primitives rather than copying them.
           "toolkit.di_walk_php",
           "toolkit.closure",
           # The declared interaction surface (TARGET_INTERFACES_SPEC): read
           # off the closure's bindings and the index's declared types, so
           # after both.  Its own fixtures are in-memory; the real extraction
           # needs the index the analyzer extension writes.
           "toolkit.interfaces",
           # Its behave twin: the same artifact shape, read off the closure's
           # bindings and an `ast` pass over the bound step functions.
           "toolkit.interfaces_py", "toolkit.source_views_selftest",
           # The body-span-to-covered-line resolver, immediately after the
           # module whose body resolution it reuses, and the offline floors
           # it feeds (TARGET_INTERFACES_V2_SPEC 6.2/6.3).
           "toolkit.target_regions", "toolkit.control_floors",
           "java.source_view_selftest",
           "toolkit.source_views_java_selftest", "ruby.source_view", "go.source_view_selftest",
           "go.prod_index_selftest", "go.prod_index_cli_selftest", "go.registry_selftest", "go.interpose_selftest",
           "go.interfaces_selftest", "go.interfaces_cli_selftest", "go.mutation_cli_selftest", "go.measurement_selftest",
           "go.scaffold_selftest", "go.capture_selftest",
           "go.closure_plan_selftest", "go.bootstrap_selftest", "go.index_cli_selftest",
           "go.controls_selftest", "go.stub_cli_selftest", "go.assertion_strip_selftest",
           "agents.source_views_selftest",
           "agents.source_view_all_selftest",
           # Approved Java rule, checked with compiler-attributed local fixtures.
           "toolkit.interfaces_java_selftest",
           # The stack seam: which (language, framework) pair a run is
           # against, and the record schema both stacks' recorders write.
           # Before `harness` because it is the contract `harness` is one
           # implementation of -- and because its checks are about IDENTITY
           # (the Behat façade IS the existing objects) and about the step
           # vocabulary being derived from the recorder rather than retyped,
           # both of which are cheaper to read before the harness's own.
           "stacks",
           # The behave stack's index half (S3).  After `closure` and
           # `stacks` because it is the second implementation of the first
           # and is dispatched by the second: `py.analyze_py` is the static
           # index Python's own parser gives for free, `pystep_index` is what
           # a step IS before it is matched (And/But resolved behave's way,
           # Examples rows substituted), and `closure_py` is `closure.py`'s
           # computation minus the DI edge, over `ItemClosure`/`StepBinding`
           # themselves rather than over copies of them.  None of the three
           # needs a container to check: the matching that does is checked by
           # `pystep_index` against the matcher's own bytes, and for real by
           # the S3 gate.
           "py.analyze_py", "py.prod_index", "toolkit.pystep_index", "toolkit.closure_py",
           # The cucumber stack's index half (S3), and the THIRD implementation
           # of the one closure.  Here rather than beside the other `java.`
           # entries because what it has to be read against is `closure` and
           # `closure_py` -- it subclasses their `ItemClosure`/`StepBinding`
           # and is held to `closure_py.GOLD_SIDECAR_FIELDS` by identity, so a
           # divergence shows up as a failure two lines after the twin it
           # diverged from.  Its subject is what cucumber's OWN registry
           # answered: a dry run's json, parsed, never a regex over glue.
           # Registering it opens no Java stack -- nothing here runs cucumber,
           # Maven, Docker or a JVM, and the live dry run is D2b's.
           "java.closure_java",
           # The tree under measurement: which roots the substrate guard
           # hashes, and the bytecode sweep that keeps a python stack from
           # aborting itself on its own `__pycache__`.  Unregistered until it
           # had a selftest, which is also when it stopped being one
           # project's constants and became per-stack data.
           "bench.repo", "bench.prestashop_resources", "bench.prestashop_memory",
           # Per-item quality, and specifically the `dependency_profile` --
           # the one field here that is partly ASSERTED rather than measured.
           # It was the literal `["database"]`, true of CoreShop and untrue of
           # a library that has none, and a wrong constant in that field looks
           # exactly like a right one.
           "toolkit.quality",
           # `validate` sits with these two: the three of them read the same
           # record file, and the Scenario Outline fold is the reason they
           # must agree about which record a run's numbers come from.
           "bench.harness", "bench.runner", "bench.validate", "bench.metrics", "bench.generate",
           # The v2 target-interface derivation, here rather than beside
           # `toolkit.interfaces` because what it has to be read against is
           # `bench.metrics`: it re-walks `direct_methods`' index join PER
           # STEP ROLE, and its own check is that the union of the per-role
           # sets is that function's set on the same row.  It also reads
           # `toolkit.quality`'s oracle rule and `core.gherkin`'s keyword
           # resolution, both of which ran above.
           "toolkit.checked_interfaces",
           # SPEC_C3_PARALLEL — K-way execution, the C3 protocol, and the
           # gates that block publishing a C3 number.
           "bench.adapters",
           # The prompt renderer (wave M5), cut out of `adapters` because
           # `load_profile` re-freezes its four digests on every load.
           "data.prompt",
           # The agent half of the adapters (wave O2): the readiness probe
           # and the end-to-end stub-agent construction legs, beside the
           # prompt legs they were split from.
           "agents.adapter",
           # The controls and the transports, and the runner's refusal of an
           # agent arm a checkout does not ship.
           "bench.fixtures", "bench.seed", "bench.worker", "bench.prestashop_selftest", "bench.result_ledger",
           # Explicit I2 producer lifecycle: source-only closed projections,
           # crash windows, lock ownership, resume/adoption and no-clobber.
           "bench.result_ledger_i2_selftest",
           # I3 adds the validation-only projection and lifecycle while the
           # default diagnostic validate route remains byte-compatible.
           "bench.result_ledger_i3_selftest",
           # I4 recursively closes run-shard sources into a durable merged
           # result/sidecar/receipt tuple without opening any consumer.
           "bench.result_ledger_i4_selftest",
           # One-command completion discovers only colocated sealed shards,
           # reuses I4's strict merge, and renders the canonical table.
           "bench.finish_selftest",
           # I5 opens the first three consumers behind one shared preflight:
           # explicit merged-run roles pinned to one reviewed commit, and a
           # positive status created only after the complete output.
           "bench.result_ledger_i5_selftest",
           # The agent-producer amendment: ledger/checkpoint v2, the closed
           # agent evidence chain, and the transport boundary that records
           # what actually went out.  Immediately after I5 because I5's
           # section 9 vectors are now preflighted over receipts THIS
           # module's producer surfaces build -- the literal v2 fixture
           # constructor is gone, so a shape disagreement between the two
           # goes red rather than staying invisible.
           "agents.result_ledger_v2_selftest", "confined.agent_wire_transport",
           # D2's one noncanonical observation: closed workload/intent bytes,
           # consumed-before-spawn ordering, and an SDK-blocked Bubblewrap
           # child whose fd-6 peer is already closed.  Temporary fixtures
           # only; no provider, Docker, canonical result, or retained root.
           "agents.agent_d2_launch_observation_selftest",
           "bench.dbadmin", "toolkit.provision_coreshop", "toolkit.provision_sylius",
           "toolkit.provision_prestashop", "bench.campaign", "agents.harvest", "agents.trials",
           "toolkit.stub", "toolkit.strip", "data.mutation", "bench.mutation_batch",
           "data.mutation_attestation",
           # The writer half of `mutation_attestation` (wave M5): the audit,
           # the producer discipline and the validation-report builders.
           "toolkit.mutation_audit",
           # The one writer that MINTS an `r2t.mutation-assets/1` entry, for
           # Java and for Behat/PHP alike.  Registered beside the audit
           # because the completed audit is the evidence it refuses to mint
           # an index without.
           "toolkit.mutation_asset_index",
           "toolkit.coreshop_mutation_map_selftest",
           "toolkit.coreshop_mutation_authority_selftest",
           "toolkit.coreshop_evaluation_inputs_selftest",
           "bench.mutation_run",
           "bench.mutation_continuation",
           "bench.prestashop_continuation_selftest",
           "bench.prestashop_continuation_packet",
           "bench.mutation_distribution",
           # Sound fallback for a compute-capped reference leg.  It is next
           # to mutation_run because it authenticates that producer's native
           # rows and sidecars before applying the candidate-partition
           # envelope; it never treats a short shard as a smaller score.
           "bench.mutation_bounds",
           # Population-v2's gold oracle is an artifact builder rather than
           # a campaign runner.  It still belongs beside mutation_run: its
           # only admissible inputs are two complete native gold campaigns,
           # and its output is their failed-only intersection plus every
           # observed flip.
           "toolkit.gold_killset", "toolkit.hard_subset",
           "bench.evaluation_reference_selftest",
           "bench.cli",
           # The N=1 sibling of those two, kept beside them because it is the
           # same derivation from different evidence: one full-gold, one
           # assertion-stripped-gold and one stub observation instead of two
           # gold campaigns, and section 5.1's uniform exclusion instead of a
           # flip set.  Temporary fixtures only; it starts no worker.
           "bench.reference_controls",
           # The from-disk half of the same artifact, and only that: it
           # derives the three adapter workload bindings the scope bridge
           # cannot derive for itself, then hands the tree to the preserved
           # reader above.  After `reference_controls` because every refusal
           # it produces is one of that module's, and because its own probes
           # are what the preserved reader does NOT settle -- the role set,
           # the derived bindings, and the installed applier.
           "bench.reference_loader",
           # The portable reader of the delivered Sylius319 continuation
           # aggregates, through the preserved reader above.
           "bench.reference_pair_continuation_selftest",
           "toolkit.assertion_selection", "bench.reference_workloads",
           "bench.prestashop_reference_selftest",
           "toolkit.anti_vacuity",
           # The retained DOCX bridge is source-only here: its selftest proves
           # exact workload binding and closed ordinary producers without
           # configuring Docker or creating a retained output.
           "toolkit.docx_v2_workload",
           "bench.test_quality",
           # The offline selector of the harness-25 corrections reads the
           # harness's own rules (harness, go.sensitivity) over saved rows.
           "bench.evaluator_corrections",
           "bench.mutation_startup_recovery",
           # Issue #225's project-neutral admission/orchestration boundary.
           # Its adapter is synthetic and its executor writes only temporary
           # native evidence through the existing mutation writers.
           "bench.live_test_quality", "bench.confine", "toolkit.doctor",
           # The retained non-network half of the former post-run pass:
           # trajectory discovery, counts, native manifests, redaction.
           "bench.trajectory_validation",
           # The RETIRED gate's own classifiers stay registered: recorded
           # egress attestations and sealed agent evidence still validate
           # byte-identically through them (legacy path only).
           "egress", "bench.egress_attestation", "agents.egress_proxy_selftest",
           # The ChatGPT account route's forwarder, and the claim that its
           # token never enters the sandbox, checked in a real namespace.
           "agents.chatgpt_account_selftest",
           # Its request-shape probe's checks, through that forwarder against a
           # stand-in backend (FRONTIER_ARMS_20261015_AMENDMENT.md section 8).
           "agents.codex_shape_probe",
           # The behave stack's anti-vacuity half (S5).  After `stub` and
           # `mutation` because each is the second implementation of one of
           # them and is checked against it: `stub_py` keys on the (keyword,
           # text) PAIR because behave matches per keyword and emits patterns
           # behave's own `re` matcher anchors, `py.mutate` is the one
           # enumerate+apply program (the mutate.php rule) whose operator
           # names are `mutation.OPERATORS` mirrored, and `mutation_py` is
           # what hands the python engine's identity and keep root to
           # `mutation.build_manifest` rather than to a copy of it.  What
           # needs the image -- 239 isolated install/import cycles through
           # behave's registry, and apply/revert against a real tree -- is
           # `py/stub_accept.py` under `scripts/gate_s5_vacuity.py`, and that
           # driver now refuses for every stack before any Docker contact, so
           # nothing has run it since (`stub_py.CONTAINER_HALF_NOTE`, which
           # `stub_java.selftest` holds to the gate's own bytes).
           "toolkit.stub_py", "toolkit.strip_py", "py.mutate", "toolkit.mutation_go_selftest", "toolkit.mutation_py",
           # Track D's v2-from-birth Java mutation producer and its binding.
           # Its selftest covers the envelope/applier plus the final-release,
           # exact-classpath and strict-gold population/map authority seams.
           "toolkit.mutation_java",
           # J0 Phase A is source-only: exact Git/archive identities, the
           # hermetic Algorand composer, pinned Gherkin AST adapters, census,
           # scalar/Examples selection and lossless slicing.  Registration
           # here does not open Maven/Docker/timing or claim a Java result.
           "java.compose_algorand", "java.j0",
           # J0 Phase B's inert controller seam: exact N=3 blocked order,
           # per-cell process counts/timeouts, attempt-0001 layout, no-retry
           # resume decisions and durable no-clobber evidence publication.
           # It has deliberately no CLI or process/network backend; adding it
           # cannot execute Maven, Docker or Java or resolve the still-open
           # Phase-B qualification and host gates.
           "java.j0_timing",
           # Raw Phase-B fork evidence is independently closed before union
           # projection: canonical JSONL framing, project/adapter authority,
           # case/step identity and lifecycle, and footer counts/digests.  The
           # validator is pure bytes-to-facts and cannot run or publish J0.
           "java.j0_fork",
           # Research-minimal Java phase/release producers use fake runners
           # here; no Docker, Maven, registry, or JVM is contacted.
           "java.research_minimal_selftest",
           "java.kapua_compiler", "java.kapua_population", "java.kapua_gold_coverage", "java.kapua_pilot", "java.kapua_census", "java.kapua_census_mutation", "java.kapua_headroom", "java.kapua_reference",
           "java.kapua_development_release",
           "java.research_minimal_oci_selftest",
           # The seam a second system under test lands on: the adapter
           # registry, and the vocabulary an agent's accounting record is
           # allowed to use.  Both are about COMPARABILITY rather than about
           # any one system -- a second agent that builds differently or
           # names its tokens differently produces a ladder that cannot be
           # added to the first one's, and neither failure is visible in a
           # run file.
           "agents", "confined.agent_stats",
           # The seam that keeps the second agent's driver honest:
           # `agents.scanners` is the native-manifest contract -- independent
           # trajectory validation reconciles aider's OWN artifacts against
           # the driver's normalized stream, so a driver bug that drops a
           # record is a validation failure rather than a smaller number.
           "agents.scanners",
           # ...and EVERY AGENT DRIVER, derived rather than listed
           # (`components.agent_driver_modules`): a driver is the one file an
           # arm adds under this package, and an arm whose driver is not
           # registered here is a driver nothing runs.  Both are run end to
           # end against a MOCKED agent -- aider against a mocked litellm
           # (the D8 call sequence, the F1 late-callback drain, the
           # outcome-keyed autotest wrapper over every verified reply shape,
           # and redaction proven in the events AND the preserved native
           # bytes), openhands against a mocked SDK (the ordinary path pinned
           # unchanged and the terminated one proven to write what the
           # SIGKILL used to destroy).  No API spend; the mock is the point.
           *components.agent_driver_modules(),
           # What a driver is allowed to do when the wall-clock envelope
           # expires.  After the drivers because it is the seam BETWEEN them
           # and the adapter, and it is registered at all because A5 cell 1
           # proved the alternative: `subprocess.run(timeout=)` SIGKILLed
           # seven rows before either driver had written its trajectory, its
           # native manifest or its accounting record, the then-current
           # strict egress gate refused the campaign, and $9.82 became a lower
           # bound with a biased gap.  Its selftest REPRODUCES that -- a mock
           # driver
           # through the real adapter, hard-killed, leaving an empty attempt
           # directory -- and then fixes it on the same fixture, so the
           # defect can never be re-argued from memory.
           "confined.terminate",
           # ONE INVARIANT ACROSS EVERY MODULE THAT CAN START AN AGENT:
           # `--unshare-net`.  After `confine`, `adapters`, `runner`, `agents`
           # and the v2 ledger, because it is a claim about the SET of
           # sandbox argvs they build between them rather than about any one
           # of them -- it takes a census of every construction in the
           # package and requires each to be classified, so the next launch
           # path added anywhere cannot go nine days and a whole campaign
           # without confinement the way #121's did.
           "agents.agent_confinement_selftest",
           # The two builders that census classifies as launches, in
           # the one module that now holds both: the development
           # route's bwrap wrapper and section 3.2's policy.
           "agents.sandbox", "agents.visibility_mounts_selftest",
           # The c2r runtime pack: its identity, admission, attempt setup and
           # run log, the adapter hook that binds it, one real launch of a
           # nested runtime through the first builder above, and the
           # launcher's runtime preflight (gate G-host) through the same
           # builder, refused where the runner cannot run.
           "agents.runtime_pack_selftest",
           # Gate G-rows: whether a c2r cell's first finished rows ran
           # anything past the runtime's sandbox setup.
           "agents.run_health",
           # What the development-route launch lets the agent SEE: the
           # driver's harness files and no fixture, no private model
           # configuration (AGENT_VIEW_HARDENING_AMENDMENT), checked in a
           # real namespace the adapter builds.
           "agents.agent_view_selftest",
           # The release's own arithmetic -- the inclusion rule's tallies and,
           # since the cluster statistics, the effective sample size the whole
           # corpus is really drawn from.  It was unregistered until then
           # because it had no selftest to run.
           "data.release",
           # The writer half of `release` (wave M5): the inclusion rule, the
           # dataset manifest and the RI1-RI6 release-integrity checks.
           "toolkit.release_build",
           "data.bundle",
           "data.visibility_release",
           # The writer half of `bundle` (wave M5): the build-then-validate
           # checks live with the builder.
           "toolkit.bundle_build",
           "toolkit.evaluation_bundle_selftest",
           "toolkit.environment", "toolkit.algorand_bundle",
           "toolkit.algorand_bundle_inputs_selftest",
           "toolkit.coreshop_preparation",
           # The host half of the CoreShop direct-invocation gate
           # (`scripts/gate_php_direct.py`): the index join with the span
           # rule, the caller split and the sibling F1 the gate reports, on
           # synthetic rows.  Its container half is the operator gate itself.
           "toolkit.php_direct_gate_selftest",
           "toolkit.java_direct_gate_selftest",
           "toolkit.validate_cli_selftest",
           # Fresh-host registry-by-digest acquisition of the Algorand
           # runtime image, driven by the installed bundle's oci-image.json
           # role.  A fake daemon/registry stands in here; no live Docker,
           # network, or registry is contacted.
           "toolkit.algorand_image",
           # Which items a published number was measured on, and the record
           # that says how they were chosen.  Registered here because its
           # last check reads `release/` and refuses when a published subset
           # has no sidecar, or a sidecar that no longer matches it.
           "data.subsets",
           # Per-instance cost accounting.  One entry, not three: the price
           # arithmetic, the driver's stats assembly and report.py's
           # aggregation are one measurement passing through three files, and
           # `pricing.selftest` checks them together -- a driver that records
           # tokens nobody can price, or a summary that silently drops the
           # rows carrying no stats, is a failure of the whole chain rather
           # than of any one module in it.
           "confined.pricing",
           # The frozen four-cell/Java20 plan and its zero-provider-call
           # operator gates.
           "agents.slice3_eval", "agents.evaluation_execution_selftest",
           "agents.evaluation_execution_v3_selftest",
           "agents.evaluation_execution_v3_agent_selftest",
           "agents.evaluation_execution_v3_attempt_selftest",
           "agents.evaluation_execution_v3_lineage_selftest",
           # The recipe a run was launched under, as a file with a digest.
           # After `subsets` (which answers WHICH ITEMS) and before
           # `versions` (which cross-checks the manifest entry that pins these
           # two files by sha256): a protocol is the third leg of what a
           # published number can be cited as, beside the dataset and the
           # harness, and its own selftest pins the digests the manifest then
           # has to agree with.
           "agents.protocol",
           # The artifact manifest.  Not a measurement -- it cross-checks
           # `VERSIONS.yml` against the constants and the dataset bytes it
           # claims to describe, so that a component version bumped in code
           # and forgotten in the manifest is a failing check rather than a
           # stale line nobody reads.
           "data.versions",
           # The canonical results table.  Registered last because it is
           # downstream of nearly everything above -- it reads the ladder out
           # of a run file, the Jaccard out of `test_quality`, and coverage
           # and api out of `metrics` -- so a failure here after those pass is
           # a failure of the TABLE rather than of any measurement in it.
           "bench.results", "bench.tier1b_verdict_selftest", "bench.campaign_table",
           # The behave stack's execution half (S4): the recorder's status
           # mapping against behave 1.3.3's full probed vocabulary, the
           # r2t.record/1 shape, the no-`--strict` invocation pin, the
           # reuse-by-identity table (install_solution/verify_substrate ARE
           # the PHP harness's), the fail-leg construction, and the strip's
           # recorder swap.  APPENDED after `results` rather than threaded
           # into the curated order above because two milestone branches add
           # modules to this tuple in parallel and integration merges
           # appends; `results`' own comment still holds for everything
           # upstream of the table.
           "stacks.behave", "py.accessor_recorder_selftest",
           # The cucumber stack (J5), whose recorder is cucumber's own JSON
           # formatter rather than a hook this benchmark installs: the
           # status vocabulary and the two joins the document's shape forces
           # (a Background element belongs to the scenario after it, a hook
           # that did not pass is a step), the ambiguous-and-void rulings,
           # the outline's per-row identity, and the per-project argv
           # quirks.  Immediately after `stacks.behave` because it is the
           # same kind of claim about the same schema, and appended for the
           # same reason that one was.
           "stacks.cucumber",
           # That stack's direct-invocation collector (API_DIRECT_INVOCATION_SPEC
           # section 2.4): the agent jar's deterministic build, the
           # `-javaagent` option the harness passes, the section 2.5 record
           # shape read back from the agent's output, and the ASM index's
           # cross-check against JaCoCo's inventory.  Beside the stack that
           # folds it; JDK-free and Docker-free, like everything here.
           "java.direct_calls",
           # That stack's anti-vacuity half (J6), immediately after it for
           # the reason `stub_py` sits immediately after `stub`: it is the
           # third implementation of one idea and is checked against the
           # first two.  Its two departures are cucumber's and Java's rather
           # than taste -- the key is the step TEXT (a definition answers a
           # step whatever keyword registered it, read out of the pinned
           # checkout's own bytes) and a method must declare the trailing
           # parameter a DocString or DataTable step supplies, because Java
           # has no optional parameters to absorb one with.  What needs the
           # image -- javac, and cucumber's own glue loader registering
           # every expression -- is run by NOTHING today:
           # `benchmark/scripts/gate_s5_vacuity.py` refuses for every stack
           # before any Docker contact and is behave-bound underneath, so
           # the cucumber arm lands with the reviewed gate workload binding
           # (`benchmark/J0_DOCKER_AUTHORITY_AMENDMENT.md`).  That is the
           # module's `CONTAINER_HALF_NOTE`, and its own selftest reads the
           # gate's bytes rather than trusting this comment.
           "toolkit.stub_java",
           # ...and its de-saturation half, beside it as `strip_py` sits
           # beside `stub_py`.  The rule that decides which definitions are
           # assertions is `strip.py`'s own function, reused by identity;
           # what this module owns is the one thing Java does not hand over
           # for free -- where a method body starts and stops, without a
           # parser on this side of the container. Every ambiguity a
           # keyword-free declaration grammar creates (an overload, a
           # javadoc that quotes the signature, a non-void assertion whose
           # emptied body would not compile) is a refusal, and the table of
           # them is the test.
           "toolkit.strip_java",
           # The S6 sweep: `validate` over K workers, resumable.  Appended
           # for the same reason `stacks.behave` was — parallel milestone
           # branches add modules here and integration merges appends — and
           # it belongs after `validate` in any order, because it produces no
           # verdict of its own: it decides which verdicts a RESUME may
           # trust, hands one worker to one thread, and refuses when the
           # host rather than the corpus is what is failing.
           "toolkit.sweep",
           # The A4 smoke gate's checks (slice 1 integration step 2): what a
           # PRODUCED aider run must prove before campaigns -- native evidence
           # reconciliation, litellm_callback stats with a
           # cache split, priced rows, the native_budget stamp, no .aider*
           # leak, key hygiene and the F2-amended host ban.  Registered so
           # the gate that stands between mocks and money is itself under
           # test: each MUST is broken exactly one way on fixtures and must
           # be caught by exactly the check that owns it.
           "agents.smoke",
           # Is a row a FIRST observation of its item, or a re-draw of one?
           # Registered because A5 cell 4 shipped the answer in prose: an item
           # whose first attempt failed through the CANDIDATE's own behaviour
           # was re-run, passed, and printed exactly like a first-draw pass in
           # every command that reads a run. The field, its two reason classes
           # and the refusals that stop a stamp being invented are checked
           # here; who PRINTS it is checked in `report` below.
           "bench.draws",
           # The reading half of a run file, at last under test in its own
           # right. `pricing` already exercises its cost aggregation, but the
           # non-vacuity half -- the vector behind `non_vacuous_pass_at_1`,
           # and the missing/stale refusals that must fire before a comparison
           # is drawn from it -- had no home, and it is the input `cli
           # compare --metric non_vacuous_pass` pairs. Last, because its end-
           # to-end checks drive that verb through `cli` and therefore sit
           # downstream of nearly everything above.
           "bench.report",
           # The image definitions, as source.  Appended rather than filed
           # beside `docker_authority`/`docker_cli` because those two are
           # about the DAEMON and this one is about a Dockerfile's bytes, and
           # because what it checks them against -- `stacks.cucumber`'s
           # repository path and JDK major -- is registered far below them.
           # The drift it exists to catch is silent in both directions: an
           # image that baked its offline repository somewhere else fails
           # every item as a `container_error`, and one built on the wrong
           # JDK major fails nothing at all while changing which compiler
           # judged the submission.
           "toolkit.images",
           # The authority-bound EPUBCheck image producer.  Separate from
           # `images` because that module remains source-only/pure while this
           # suite drives the stopped three-phase controller through a fake
           # Docker adapter and the sole Java helper through loopback HTTP.
           # No Docker daemon, registry, Central, or canonical output is used.
           "toolkit.epubcheck_image_selftest",
           # The later reality-spike capture remains source-closed. Its test
           # uses private fixture workspaces and a fake Docker runner to hold
           # exact offline argv, raw artifacts, timing fold and closure gate;
           # it opens no Docker, Maven, JVM or socket.
           "toolkit.epubcheck_reality_selftest",
           # The Slice-3 test-quality join (SLICE3_TEST_QUALITY_SPEC.md §2):
           # the Docker-free scorer for the two published algorand-sdk cells
           # and the §2.5 validator acceptance path.  Appended, like
           # `stacks.behave`, because parallel branches add modules here and
           # integration merges appends; it belongs after `test_quality` and
           # `slice3_eval` in any order, being the join of the two.
           "bench.slice3_test_quality",
           # The consumer lifecycle over `environment`'s #181 descriptors:
           # `up`'s composition order and its gold-control acceptance gate,
           # the fresh-nonce/dirty-root refusals, the three `status` answers
           # (absent / live-and-bound / torn down, with a broken pool
           # distinguished from an absent one), and a `down` scoped to
           # exactly its own record's pool.  Every live step is a
           # monkeypatched seam here — no Docker, daemon, image build or
           # container is touched.  Appended, like `stacks.behave`, because
           # parallel branches add modules to this tuple and integration
           # merges appends; it belongs after `environment`, `worker` and
           # `doctor` in any order, being a composition of the three.
           "toolkit.environment_lifecycle",
           "stacks.cucumber_ruby", "ruby.e_petitions", "ruby.evaluation_selection", "data.sylius_selection", "toolkit.rbstep_index", "toolkit.closure_rb", "toolkit.stub_rb", "toolkit.strip_rb", "toolkit.mutation_rb", "toolkit.prod_index_rb", "toolkit.interfaces_rb")


#: `components.COMPONENT` is the one partition of these modules -- which of
#: `core`, `data`, `bench`, `toolkit` and `agent` each belongs to -- and
#: `components.component_modules` is what `--component` runs.  It is not
#: restated here: that table is checked against the files on disk, so a
#: second copy in this file could only disagree with it.  `MODULES` above
#: stays the single ordered reading of the whole battery and is not
#: partitioned: its order and its commentary are a designed artifact, and
#: splitting the tuple would cost the narration to save nothing.


#: Modules whose checks are timing envelopes or a fixed port rather than pure
#: logic: a neighbouring child on the same core makes them fail without
#: anything being wrong.  They run one at a time after the parallel set
#: instead of having their envelopes widened -- the envelope IS the check, so
#: widening it deletes what the module measures.
SERIAL = (
    # `terminate.py:964-975` -- a 19 s envelope around a real launch.
    "confined.terminate",
    # `epubcheck_image_selftest.py:2835-2837` -- a 7 s envelope.
    "toolkit.epubcheck_image_selftest",
    # `test_quality.py:11499-11838` -- scheduling windows.
    "bench.test_quality",
    # `egress_proxy_selftest.py:72-84` -- re-binds one fixed port.
    "agents.egress_proxy_selftest",
)

#: This checkout's `benchmark/` directory, which is what a child has to import
#: `r2t` from: a run of THIS runner must check THIS tree, never whichever
#: `r2t` an inherited `PYTHONPATH` happens to name first.
BENCHMARK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: `--component distribution` names no row of the component table: it is the
#: opt-in that runs the benchmark-only mirror's own falsifier,
#: `scripts/build_distribution.py --check`.  That builds a git repository and
#: runs a nested battery inside it, so no component gate runs it implicitly;
#: master and release/export pull requests ask for it by name.
DISTRIBUTION = "distribution"


def _child_command(name: str) -> list:
    """One module's selftest, as its own interpreter's exit status.

    `os.umask` is set by the CHILD rather than asked of the operator: several
    modules assert owner-private modes on files they create, and a group
    writable inherited umask fails them for a reason that has nothing to do
    with the change under review.
    """
    # `-u`: the child's stdout is a file, so a buffered child would flush its
    # `[PASS]` lines AFTER the unbuffered traceback that ended the run and the
    # log would read out of execution order.
    return [sys.executable, "-u", "-c",
            "import os, sys\n"
            "os.umask(0o022)\n"
            f"import r2t.{name} as m\n"
            "raise SystemExit(m.selftest())\n"]


def _child_env(module_tmp: str) -> dict:
    env = dict(os.environ)
    inherited = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (BENCHMARK + os.pathsep + inherited
                         if inherited else BENCHMARK)
    # Without this, every child races the others writing the shared
    # `__pycache__` inside the checkout -- the one place a self-test run must
    # not touch.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["TMPDIR"] = module_tmp
    return env


def _spawn(name: str, run_root: str) -> tuple:
    module_tmp = os.path.join(run_root, name)
    os.makedirs(module_tmp, mode=0o700, exist_ok=True)
    # A file rather than a pipe: the parent prints in `MODULES` order, so it
    # is not reading while the child writes, and a pipe would deadlock the
    # moment a module's output outgrew the buffer.
    log = open(os.path.join(run_root, name + ".log"), "w+b")
    proc = subprocess.Popen(
        _child_command(name), env=_child_env(module_tmp),
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    return proc, log, time.monotonic()


def _run_group(modules: tuple, jobs: int, run_root: str, seconds: dict,
               failures: list) -> None:
    """Run `modules`, at most `jobs` at once, printing in `MODULES` order."""
    pending, running, finished, emitted = list(modules), {}, {}, 0
    while emitted < len(modules):
        while pending and len(running) < jobs:
            name = pending.pop(0)
            running[name] = _spawn(name, run_root)
        for name, (proc, log, started) in list(running.items()):
            if proc.poll() is None:
                continue
            log.seek(0)
            finished[name] = (proc.returncode, log.read(),
                              time.monotonic() - started)
            log.close()
            del running[name]
        while emitted < len(modules) and modules[emitted] in finished:
            name = modules[emitted]
            code, output, elapsed = finished.pop(name)
            seconds[name] = elapsed
            emitted += 1
            print(f"--- r2t.{name} ---")
            sys.stdout.flush()
            sys.stdout.buffer.write(output)
            sys.stdout.buffer.flush()
            if code < 0:
                print(f"[FAIL] r2t.{name} killed by signal {-code}")
            elif code != 0:
                print(f"[FAIL] r2t.{name} exited {code}")
            if code != 0:
                failures.append(name)
            sys.stdout.flush()
        if running and emitted < len(modules):
            time.sleep(0.02)


#: What `--changed` compares against when the flag is given no reference:
#: the base an ordinary pull request is opened against.
DEFAULT_CHANGED_REF = "origin/master"


def changed_paths(ref: str) -> list:
    """The merge-base diff `ref...HEAD`, as repo-relative paths.

    The same three-dot form the whitespace check uses, so the two gates read
    the same change: what this branch did, not what master did meanwhile.
    """
    root = os.path.dirname(BENCHMARK)
    done = subprocess.run(
        ["git", "-C", root, "diff", "--name-only", f"{ref}...HEAD"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(
            f"REFUSED: `git diff --name-only {ref}...HEAD` failed in {root}: "
            + (done.stderr.strip() or f"exit {done.returncode}"))
    return [line for line in done.stdout.splitlines() if line]


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    component, changed, only, keep = "all", None, [], False
    jobs = min(8, max(1, (os.cpu_count() or 2) // 2))
    while argv:
        flag = argv.pop(0)
        if flag == "--component":
            if not argv:
                raise SystemExit("REFUSED: --component needs a component "
                                 "name; choose from "
                                 f"{', '.join(components.COMPONENTS)}, all "
                                 f"or {DISTRIBUTION}")
            component = argv.pop(0)
        elif flag == "--changed":
            # The reference is optional, so a following `-j` is a flag and
            # not a ref: only a bare word is taken as the base.
            changed = (argv.pop(0) if argv and not argv[0].startswith("-")
                       else DEFAULT_CHANGED_REF)
        elif flag == "--only":
            if not argv:
                raise SystemExit("REFUSED: --only needs a module name")
            only.append(argv.pop(0))
        elif flag == "-j":
            if not argv:
                raise SystemExit("REFUSED: -j needs a worker count")
            count = argv.pop(0)
            if not count.isdigit() or int(count) < 1:
                raise SystemExit(
                    f"REFUSED: -j takes a positive integer, not {count!r}")
            jobs = int(count)
        elif flag == "--keep":
            keep = True
        else:
            raise SystemExit(
                f"REFUSED: unexpected argument(s): {' '.join([flag, *argv])}")
    if changed is not None and component != "all":
        raise SystemExit(
            f"REFUSED: --component {component} and --changed {changed} name "
            f"two different selections; pass one")
    if component == DISTRIBUTION:
        # One script, not a module selection: it builds the benchmark-only
        # mirror and runs its own battery inside it, so `--only` and `-j`
        # have nothing here to select or parallelise.
        if only:
            raise SystemExit(
                f"REFUSED: --component {DISTRIBUTION} runs one script, not "
                f"modules; --only {' '.join(only)} selects nothing")
        return subprocess.call(
            [sys.executable,
             os.path.join(BENCHMARK, "scripts", "build_distribution.py"),
             "--check"],
            stdin=subprocess.DEVNULL)
    if changed is None:
        modules = components.component_modules(component)
        label = "" if component == "all" else f"component {component}"
    else:
        paths = changed_paths(changed)
        selection = components.changed_selection(paths)
        modules = tuple(selection)
        label = f"--changed {changed}"
        print(f"--changed {changed}: {len(paths)} changed path(s), "
              f"{len(modules)} module(s) selected")
        for name, why in selection.items():
            print(f"  {name}: {why}")
        if not modules:
            # Two different empty selections, and neither may be described
            # as the other: nothing differed from the base at all, or every
            # path that did matched a `CHANGE_MAP` row that selects no
            # module.  Those rows are not all prose: the paper tables and the
            # req2test front end have gates of their own, so each matched
            # row prints its reason, which names that gate.  Both exit 0
            # having run nothing, which is the point.
            if not paths:
                print("  (no path differs from " + changed + ")")
            else:
                print("  (every changed path matched a row that selects no "
                      "self-test module:)")
                rows = {components.change_rule(path) for path in paths}
                for row in components.CHANGE_MAP:
                    if row in rows:
                        print(f"  - {row[2]}")
        print()
    if only:
        wanted = set(only)
        for name in only:
            if name not in set(MODULES):
                raise SystemExit(
                    f"REFUSED: {name!r} is not a registered module")
        modules = tuple(m for m in modules if m in wanted)
        # An empty selection would otherwise print `ALL PASS (0 modules)` and
        # exit 0: a green gate that ran nothing.  `--changed` on a diff the
        # map selects no module for is the one selection allowed to be empty,
        # and it is empty for a reason it just printed.
        if not modules:
            raise SystemExit(
                f"REFUSED: --only {' '.join(only)} selects no module"
                + ("" if not label else f" in {label}"))
    # At `-j 1` there is no neighbour to disturb a timing envelope, so the
    # serial lane is not separated and the whole battery reads in `MODULES`
    # order exactly as the single-process runner did.
    if jobs == 1:
        groups = [(modules, 1)]
    else:
        groups = [(tuple(m for m in modules if m not in SERIAL), jobs)]
        serial = tuple(m for m in modules if m in SERIAL)
        if serial:
            groups.append((serial, 1))
    # The run root is always a directory this run creates, so removing it
    # removes only what this run put there: `$R2T_SELFTEST_TMP` is an operator
    # scratch directory that usually holds other things too.
    given = os.environ.get("R2T_SELFTEST_TMP")
    run_root = (os.path.join(given, f"run-{os.getpid()}") if given
                else os.path.join(os.path.expanduser("~"), ".cache",
                                  "r2t-selftest", str(os.getpid())))
    os.makedirs(run_root, mode=0o700, exist_ok=True)
    seconds, failures, started = {}, [], time.monotonic()
    try:
        for group, width in groups:
            _run_group(group, width, run_root, seconds, failures)
    finally:
        if not keep:
            shutil.rmtree(run_root)
    wall = time.monotonic() - started
    print()
    if failures:
        print(f"FAILURES in: {', '.join(failures)}")
    else:
        print(f"ALL PASS ({len(modules)} modules"
              + (f", {label}" if label else "") + ")")
    slowest = sorted(seconds.items(), key=lambda row: -row[1])[:10]
    print(f"{wall:.1f} s wall, -j {jobs}; slowest: "
          + ", ".join(f"{name} {value:.1f}" for name, value in slowest))
    if keep:
        print(f"kept: {run_root}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
