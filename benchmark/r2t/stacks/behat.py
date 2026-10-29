"""The Behat/PHP stack — a FAÇADE, and nothing else.

Every name below is bound to an object that already exists somewhere else in
`r2t`.  There is no wrapper, no `self`, no re-implementation and no "small
adaptation": `behat.execute is harness.Harness.execute` is true with the `is`
operator, and this package's selftest asserts exactly that for every member of
`MEMBERS`.

Why a façade and not an extraction.  CoreShop's published numbers are a
property of these functions' bytes — the archived campaign digests re-hash,
the frozen 12-row payload renders byte-for-byte, the mutant manifest rebuilds
to `03f4017d…`.  Moving code to make it "shared" would put every one of those
pins at the mercy of a refactor whose only benefit is that a second stack has
not been written yet.  So the second stack is written against the CONTRACT
(`stacks/base.py`), the first stack is described by a table of re-exports, and
the day some behaviour is genuinely common it moves once, with both callers in
front of us.

What this file is FOR, then: it is the answer to "where is the Behat stack?",
which before it existed was "spread across harness.py, repo.py, closure.py,
stub.py, mutation.py and eleven branches of cli.py, and you find out by
reading them".
"""
from __future__ import annotations

from ..toolkit import closure as _closure
from ..bench import harness as _harness
from ..data import mutation as _mutation
from ..bench import mutation_run as _mutation_run
from ..bench import repo as _repo
from ..toolkit import strip as _assertion_strip
from ..toolkit import stub as _stub

#: The value of `framework:` in `config/profile_coreshop.yml`, and the key the
#: CLI dispatches on.
FRAMEWORK = "behat"

#: The language this stack measures, for the same reason: a profile's
#: `language:` and its `framework:` are checked against each other at load.
LANGUAGE = "php"

# --------------------------------------------------------------- the seven
#
# `stacks.base.StackRunner`, member for member, in the order a project passes
# through them.  Each is the existing object; see the module docstring.

#: `repo.strip_repo` — the answer out of the clone and into `gold/`.
strip = _repo.strip_repo

#: `repo.baseline_substrate` — hash the substrate roots so that a submission
#: rewriting production code during its own run is a `substrate_violation`
#: rather than a better score.
integrity_baseline = _repo.baseline_substrate

#: `closure.load_extractor` — builds the extractor whose `closure_for(item,
#: feature, scenario)` is one item's gold closure.  The extractor object, not
#: a function per item, because it holds the PHP index, the step-match table
#: and the registered-context universe, and rebuilding those per item is the
#: difference between minutes and hours.
extract_closure = _closure.load_extractor

#: `Harness.install_solution`, unbound: the harness is per-workspace state
#: (manifest, boundary, container handle), so the seam is its method and the
#: façade names the function rather than any one bound instance.
install_solution = _harness.Harness.install_solution

#: `Harness.execute`, unbound — one scenario, in the container, folded over
#: `r2t.record/1`.
execute = _harness.Harness.execute

#: `stub.stub_solution` — the anti-vacuity control: every step defined, every
#: body empty.  The /3 corpus gate requires its measured HARD recall to be
#: exactly zero; its deliberately high scenario pass rate is diagnostic only.
stub_solution = _stub.stub_solution

#: Candidate-blind de-saturation control: gold with Then-only bodies emptied.
#: It is an additive fixture seam rather than one of ``StackRunner``'s seven
#: historical operations, so existing stack dispatch remains byte-compatible.
stripped_solution = _assertion_strip.stripped_solution
make_strip_adapter = _assertion_strip.make_strip_adapter

#: `mutation.build_manifest` — validate, exclude, identify, sort, sample, then
#: digest.  Called with this stack's engine, operators and exclusions, which
#: are its defaults.
mutant_population = _mutation.build_manifest

# ------------------------------------------------- the objects those live on
#
# Re-exported because a caller that has the stack should not have to know
# which module inside it to import from — that knowledge is exactly what the
# façade exists to hold.

Harness = _harness.Harness
DockerRunner = _harness.DockerRunner
Solution = _harness.Solution

#: The recorder's own fold, and the outcome of one record: shared with every
#: stack rather than re-derived, because "what does this record say happened"
#: must not have two answers.
record_outcome = _harness.record_outcome
fold_scenario_records = _harness.fold_scenario_records

#: The reference solution, assembled from a gold closure.
gold_solution = _harness.gold_solution

#: `repo.verify_substrate` / `repo.clean_workspace` — the integrity check at
#: the execution boundary, and the between-items reset.
verify_substrate = _repo.verify_substrate
clean_workspace = _repo.clean_workspace

#: Where this stack's recorder writes, repo-relative.
record_rel = _harness.RECORD_REL

# --------------------------------------------------------- mutation engine
#
# The values that make `mutation`/`mutation_run`'s parameters mean "CoreShop"
# — the pieces a second engine replaces one for one.  `stacks.base` names the
# set (`ENGINE_MEMBERS`) and every stack declares all of it; what each name
# binds to is `mutation_run.engines()`, and the selftest holds the two to
# each other.

#: `r2t-mutate` / `1.0`.  Inside every mutant id, so it is identity and not a
#: label.
engine = _mutation.ENGINE
engine_version = _mutation.ENGINE_VERSION

#: The keep-roots-and-drops policy the population is defined over.
excluded_prefixes = _mutation.EXCLUDED_PREFIXES

#: How the applier is staged and invoked: `php var/bench_mutate/mutate.php`.
applier = _mutation_run.PHP_APPLIER

#: Where `mutate.php` (enumerator AND applier — one program, so a mutant
#: cannot mean one thing at manifest time and another at execution time)
#: lives in this repository.
engine_dir = _mutation_run.PHP_ENGINE_DIR


#: Every façade member, and the dotted path of the object it must BE.  The
#: selftest walks this with `is`; a member that starts wrapping something
#: instead of re-exporting it fails here, which is the whole enforcement
#: mechanism of "façade, and nothing else".
MEMBERS: dict[str, str] = {
    # the seven
    "strip": "r2t.bench.repo.strip_repo",
    "integrity_baseline": "r2t.bench.repo.baseline_substrate",
    "extract_closure": "r2t.toolkit.closure.load_extractor",
    "install_solution": "r2t.bench.harness.Harness.install_solution",
    "execute": "r2t.bench.harness.Harness.execute",
    "stub_solution": "r2t.toolkit.stub.stub_solution",
    "stripped_solution": "r2t.toolkit.strip.stripped_solution",
    "make_strip_adapter": "r2t.toolkit.strip.make_strip_adapter",
    "mutant_population": "r2t.data.mutation.build_manifest",
    # the objects they live on
    "Harness": "r2t.bench.harness.Harness",
    "DockerRunner": "r2t.bench.harness.DockerRunner",
    "Solution": "r2t.bench.harness.Solution",
    "record_outcome": "r2t.bench.harness.record_outcome",
    "fold_scenario_records": "r2t.bench.harness.fold_scenario_records",
    "gold_solution": "r2t.bench.harness.gold_solution",
    "verify_substrate": "r2t.bench.repo.verify_substrate",
    "clean_workspace": "r2t.bench.repo.clean_workspace",
    "record_rel": "r2t.bench.harness.RECORD_REL",
    # the mutation engine
    "engine": "r2t.data.mutation.ENGINE",
    "engine_version": "r2t.data.mutation.ENGINE_VERSION",
    "excluded_prefixes": "r2t.data.mutation.EXCLUDED_PREFIXES",
    "applier": "r2t.bench.mutation_run.PHP_APPLIER",
    "engine_dir": "r2t.bench.mutation_run.PHP_ENGINE_DIR",
}
