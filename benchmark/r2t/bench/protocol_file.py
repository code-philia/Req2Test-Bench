"""The protocol FILE: resolution, loading, total validation and the digest.

A protocol (`benchmark/protocol/protocol_vN.yml`) is the recipe a run was
launched under, as a file with a digest -- dataset, and immutable.  This
module is the half of `agents/protocol.py` that only READS that file: which
versions exist, how a version resolves to a path, the total validation every
load performs, the canonical digest, and the pins that make a version an
identity.  Benchmark-owned because the consumer route reads protocol files
without ever applying one: the algorand bundle's validator checks the
bundled recipe against the reviewed file, `results` digests the recipe a row
cites, and `versions` cross-checks the pins against the manifest.  Applying
a recipe to a run -- knobs, native budgets, deviations -- is the agent half,
and `agents/protocol.py` imports every name below back so its readers keep
their spelling.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Optional

from ..core.paths import PROTOCOL_DIR


#: The schema every protocol file declares.  One string, checked by equality:
#: a file that does not say what it is cannot be read as what we hope it is.
SCHEMA = "r2t.protocol/1"


#: `protocol_vN.yml`, and nothing else, is a protocol file.  Named as a
#: pattern so `known_versions` can enumerate the directory instead of a list
#: somebody has to remember to extend.
_NAME_RE = re.compile(r"^protocol_v(\d+)\.yml$")


#: Top-level keys every protocol file must carry, with the type each must
#: have.  `bool` before `int` matters nowhere here because no key admits
#: both -- and `coverage` is checked as a strict bool for the same reason
#: `campaign._validate_fingerprint` refuses a bool trial budget: `1` and
#: `True` hash differently and mean the same thing to a reader.
_REQUIRED: tuple[tuple[str, Any], ...] = (
    ("schema", str),
    ("protocol_version", int),
    ("reconstructed", bool),
    ("condition", str),
    ("max_iterations", int),
    ("agent_timeout_seconds", int),
    ("temperature", float),
    ("repeats", int),
    ("coverage", bool),
    ("setting", str),
    ("comparison_class", str),
    ("prompt_profile", dict),
)


#: Keys `prompt_profile` must carry.  `prompt_digest` is checked for shape
#: rather than for value: the AUTHORITY on what a prompt renders to is
#: `profile.verify_prompt_digests`, which re-derives it from the bytes, and a
#: second authority here would be a second thing to keep in step.
_PROFILE_REQUIRED = ("path", "arm_prompt_key", "prompt_digest")


#: Keys `network_policy` must carry WHEN PRESENT.  Every shipped file today
#: preserves the historical policy it was written under; the approved
#: network-free successor recipes (awaiting their version numbers under the
#: owner's renumbering) omit it prospectively.  The gate fields are
#: deliberately NOT in this tuple: v1 records `egress_gate_at_publication`
#: (the fail-open gate its numbers were cleared under) and v2 records
#: `egress_gate_required` (the fail-closed gate it demands), and requiring
#: both of a file would force each to make a claim it has no business
#: making.  At least one is required when the map exists.
_NETWORK_REQUIRED = ("method", "allowlist")


#: `(path, mtime) -> parsed document`, for the same reason `pricing` and
#: `versions` cache: the selftest and a run both read the same file more than
#: once, and re-parsing a frozen file is pure cost.
_CACHE: dict[tuple, dict] = {}


#: Every version whose file carries the closed Slice-3 `model_request`.
#: Two GENERATIONS live here.  v5/v6 froze deepseek-v4-flash with thinking
#: enabled; v7/v8 are their twins under the owner's 2026-08-12 ruling
#: (deepseek-v4-pro, thinking OFF).  The older pair is kept loadable and
#: pinned -- a protocol file is immutable, so a changed request is a NEW
#: file -- and nothing was ever generated under it.
SLICE3_VERSIONS = frozenset({5, 6, 7, 8})


#: The pair this benchmark actually runs.  Anything that opens a paid path
#: names THIS set; anything that merely validates a document that claims to
#: be Slice-3 names `SLICE3_VERSIONS`.
SLICE3_CURRENT_VERSIONS = frozenset({7, 8})

# Reviewed development recipes; these do not open Slice-3 or publication.
# 33-44 name deepseek-v4-flash; 94-107 are codex@2's checked-interfaces
# recipes (CODEX_CHECKED_INTERFACES_V2_SPEC.md) and name deepseek-flash;
# 108-121 are their twins naming gpt-6-luna
# (CODEX_CHECKED_INTERFACES_V2_GPT6_LUNA_AMENDMENT.md); PrestaShop's 122-123
# name deepseek-flash and their twins 124-125 gpt-6-luna
# (CODEX_CHECKED_INTERFACES_V2_PRESTASHOP_AMENDMENT.md); e-petitions task
# revision r2's 128-129 name deepseek-flash and their twins 130-131
# gpt-6-luna (specifications/E_PETITIONS_ENVIRONMENT_CORRECTION_AMENDMENT.md);
# 132-147 are the gpt-6-sol twins of the Luna census recipes 108-119,
# 124-125 and 130-131, in that order
# (CODEX_CHECKED_INTERFACES_V2_GPT6_SOL_AMENDMENT.md; 148-149 are unused);
# the solution probe's 150-173 name deepseek-flash, 178-209 gpt-6-luna and
# 210-229, the twins of the Sol census recipes 132/133/136/137, gpt-6-sol
# (specifications/SOLUTION_PROBE_SPEC.md; 174-177 are reserved, not minted);
# its PrestaShop transfer check's 230-231, twins of 124, name gpt-6-luna
# (that specification's section 18.2; 232-233 are reserved, not minted);
# the reasoning-off ablation's 270-272 and 340-352, twins of the
# deepseek-flash census recipes 94-105, 122-123 and 128-129, name
# deepseek-flash (specifications/CODEX_DEEPSEEK_REASONING_OFF_ABLATION_SPEC.md);
# the RQ4 decomposition retry pilot's 280-295, twins of the python-docx
# and CoreShop census recipes 94-97 and 108-111, name their twins' models:
# 280-283 and 288-291 deepseek-flash, 284-287 and 292-295 gpt-6-luna
# (../experiments/rq4-pilots-20261001/PILOT_SPEC.md).
# Its wave 2 (../experiments/rq4-pilots-20261001/PILOT_SPEC_WAVE2.md) adds
# the level pilot's L arm 296-299, twins of 94, 96, 108 and 110 (its C arm
# reruns 280, 282, 284 and 286), and the decomposition extension's R0
# 304-312 and R1 313-321, twins of 98-101, 104-105 and 116-118, each
# naming its twin's model: 296-297, 304-309 and 313-318 deepseek-flash,
# 298-299, 310-312 and 319-321 gpt-6-luna. 300-303 are not minted.
# Its wave 3 (../experiments/rq4-pilots-20261001/PILOT_SPEC_WAVE3.md, pilot
# E) adds 322-327, twins of the Luna target_hidden census recipes 108 and
# 112, all naming gpt-6-luna: C 322-323, T1 324-325 and E 326-327.
# Its pilot P1 (../experiments/rq4-pilots-20261001/PILOT_SPEC_P1.md) adds
# Rcov 332-335 and Rctl 336-339, copies of the R1 recipes 294, 295, 319 and
# 320 (CoreShop and Kapua, gpt-6-luna) that change only protocol_version
# and notes; its R0 arm reruns 286, 287, 310 and 311.
# 385-400 are the gpt-6.1-sol twins of the GPT-6 Sol census recipes 132-147,
# in that order (specifications/FRONTIER_ARMS_20261015_AMENDMENT.md section 2).
# The execution-enabled target-hidden sensitivity's c2r recipes
# (specifications/EXECUTION_ENABLED_TH_SENSITIVITY_SPEC.md section 6) name
# their blind twins' models: 401-408, the twins of 94, 96, 98, 100, 102, 104,
# 122 and 128, deepseek-flash.
# Benchmark 2.0's protocols for new arms (specifications/BENCHMARK_V2_SPEC.md
# section 9, PR 6; 409-416 stay reserved for Claude Code x Opus 5.5): the
# re-run baseline cells 417 and 418 of section 5.4, the twins of 403 and 405
# with the rebuilt Algorand SDK and Kapua packs, name deepseek-flash; 419-426,
# the twins of 401, 402, 417, 404, 418, 406, 407 and 408, name gpt-6.1-sol.
# 427-434, the GPT-6.1 Sol re-run on the v1.1 packs, twins of 419-426
# (specifications/BENCHMARK_V2_RUNTIME_PATH_AMENDMENT.md section 5), name
# gpt-6.1-sol.
# The model is keyed by version, like `SLICE3_CLOSED_REQUESTS`, so a new
# model is a new file and never widens what an older one may say.
CODEX_MODELS = {
    **{version: "deepseek-v4-flash" for version in range(33, 45)},
    **{version: "deepseek-flash" for version in range(94, 108)},
    **{version: "gpt-6-luna" for version in range(108, 122)},
    122: "deepseek-flash", 123: "deepseek-flash",
    124: "gpt-6-luna", 125: "gpt-6-luna",
    128: "deepseek-flash", 129: "deepseek-flash",
    130: "gpt-6-luna", 131: "gpt-6-luna",
    **{version: "gpt-6-sol" for version in range(132, 148)},
    **{version: "deepseek-flash" for version in range(150, 174)},
    **{version: "gpt-6-luna" for version in range(178, 210)},
    **{version: "gpt-6-sol" for version in range(210, 230)},
    230: "gpt-6-luna", 231: "gpt-6-luna",
    **{version: "deepseek-flash" for version in range(270, 273)},
    **{version: "deepseek-flash" for version in (280, 281, 282, 283, 288, 289, 290, 291)},
    **{version: "gpt-6-luna" for version in (284, 285, 286, 287, 292, 293, 294, 295)},
    **{version: "deepseek-flash" for version in (296, 297, *range(304, 310), *range(313, 319))},
    **{version: "gpt-6-luna" for version in (298, 299, 310, 311, 312, 319, 320, 321)},
    **{version: "gpt-6-luna" for version in range(322, 328)},
    **{version: "gpt-6-luna" for version in range(332, 340)},
    **{version: "deepseek-flash" for version in range(340, 353)},
    **{version: "gpt-6.1-sol" for version in range(385, 401)},
    **{version: "deepseek-flash" for version in range(401, 409)},
    417: "deepseek-flash", 418: "deepseek-flash",
    **{version: "gpt-6.1-sol" for version in range(419, 427)},
    **{version: "gpt-6.1-sol" for version in range(427, 435)},
}
CODEX_VERSIONS = frozenset(CODEX_MODELS)

#: The Codex recipes whose request names a reasoning effort other than
#: `high`, keyed by version like `CODEX_MODELS`; every other Codex version
#: requests `high`, so no existing file or pin moves.  A value must be one
#: the driver admits (`confined.codex_driver.EFFORTS`, each effort level
#: listed by the pinned catalog for every Codex model); the `agents.protocol`
#: self-test binds the three.  206-209 are the solution probe's R arm
#: (specifications/SOLUTION_PROBE_SPEC.md section 4).  270-272 and 340-352
#: are the reasoning-off ablation's `none`, DeepSeek's switch that turns
#: thinking off
#: (specifications/CODEX_DEEPSEEK_REASONING_OFF_ABLATION_SPEC.md section 4).
CODEX_REASONING: dict = {**{version: "max" for version in range(206, 210)},
                         **{version: "none" for version in range(270, 273)},
                         **{version: "none" for version in range(340, 353)}}


def codex_model_request(version: int) -> dict:
    """The closed native Responses request Codex recipe `version` carries."""
    return {
        "schema": "r2t.protocol-model-request/1",
        "model": CODEX_MODELS[version],
        "wire_api": "responses",
        "reasoning_effort": CODEX_REASONING.get(version, "high"),
        "omitted_parameters": ["temperature", "top_p"],
    }


# Claude Code's checked-interfaces recipes (CLAUDE_CODE_AGENT_ADMISSION_SPEC.md):
# each DeepSeek recipe is the twin of a codex@2 deepseek-flash recipe -- 250-261
# of 94-105, 262-263 of PrestaShop's 122-123, 264-265 of e-petitions r2's
# 128-129 -- with the Claude Code budget knob and a native Anthropic Messages
# request. Keyed by version like `CODEX_MODELS`, so a new model is a new file.
CLAUDE_CODE_TWINS = {**{250 + offset: 94 + offset for offset in range(12)},
                     262: 122, 263: 123, 264: 128, 265: 129}
#: The Claude Sonnet 5.5 arm (specifications/CLAUDE_CODE_SONNET_5_5_AMENDMENT.md
#: section 2): 353-368, each the twin of the Claude Code DeepSeek recipe 103
#: versions below it, with only protocol_version, model_request.model and
#: notes changed.
CLAUDE_CODE_SONNET_TWINS = {353 + offset: 250 + offset for offset in range(16)}
CLAUDE_CODE_SONNET_MODEL = "claude-sonnet-5-5"
#: The Claude Opus 5.5 arm (specifications/FRONTIER_ARMS_20261015_AMENDMENT.md
#: section 2): 369-384, each the twin of the Sonnet 5.5 recipe 16 versions
#: below it, with only protocol_version, model_request.model and notes changed.
CLAUDE_CODE_OPUS_TWINS = {369 + offset: 353 + offset for offset in range(16)}
CLAUDE_CODE_OPUS_MODEL = "claude-opus-5-5"
CLAUDE_CODE_MODELS = {**{version: CODEX_MODELS[twin]
                         for version, twin in CLAUDE_CODE_TWINS.items()},
                      **{version: CLAUDE_CODE_SONNET_MODEL
                         for version in CLAUDE_CODE_SONNET_TWINS},
                      **{version: CLAUDE_CODE_OPUS_MODEL
                         for version in CLAUDE_CODE_OPUS_TWINS}}
CLAUDE_CODE_VERSIONS = frozenset(CLAUDE_CODE_MODELS)


def claude_code_model_request(version: int) -> dict:
    """The closed native Messages request Claude Code recipe `version` carries."""
    return {
        "schema": "r2t.protocol-model-request/1",
        "model": CLAUDE_CODE_MODELS[version],
        "wire_api": "anthropic_messages",
        "reasoning_effort": "high",
        "omitted_parameters": ["temperature", "top_p"],
    }

#: One closed request per generation, keyed by the versions that carry it.
#: Written as data rather than as a branch so that adding a third generation
#: cannot quietly widen what an older version is allowed to say.
SLICE3_CLOSED_REQUESTS: dict = {
    frozenset({5, 6}): {
        "schema": "r2t.protocol-model-request/1",
        "model": "deepseek-v4-flash",
        "extra_body": {"thinking": {"type": "enabled"}},
        "reasoning_effort": "high",
        "omitted_parameters": ["temperature", "top_p"],
    },
    frozenset({7, 8}): {
        "schema": "r2t.protocol-model-request/1",
        "model": "deepseek-v4-pro",
        "extra_body": {"thinking": {"type": "disabled"}},
        "reasoning_effort": None,
        "omitted_parameters": ["temperature", "top_p"],
    },
}


class ProtocolError(ValueError):
    """A missing, malformed or self-contradictory protocol file.

    A dedicated class rather than `SystemExit` because this module is also
    read by the selftest and by `results`, and a check that wants to assert
    "this document is refused" should not have to catch the exception the
    whole process exits on.  `cli` turns it into a REFUSED line.
    """


def known_versions(directory: Optional[str] = None) -> list[int]:
    """Every `protocol_vN.yml` on disk, by N, sorted.

    Enumerated rather than listed in a constant so that adding a protocol
    file is one commit, not two -- and so the refusal below can never name a
    version the directory does not actually hold.
    """
    directory = directory or PROTOCOL_DIR
    out = []
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    for name in names:
        m = _NAME_RE.match(name)
        if m:
            out.append(int(m.group(1)))
    return sorted(out)


def path_for(version_or_path, directory: Optional[str] = None) -> str:
    """`2` or `"2"` -> `<protocol>/protocol_v2.yml`; a path stays a path.

    Both spellings because `--protocol 2` is what an operator types and a
    selftest needs to point at a doctored copy in a temp directory without
    installing it into the repository.
    """
    directory = directory or PROTOCOL_DIR
    text = str(version_or_path)
    if text.isdigit():
        version = int(text)
        known = known_versions(directory)
        if version not in known:
            raise ProtocolError(
                f"no protocol version {version}; known versions: "
                f"{known or 'none'}. A protocol file is IMMUTABLE -- a "
                f"changed knob is a new protocol_vN.yml, so a version this "
                f"directory does not hold is a version nothing was ever run "
                f"under.")
        return os.path.join(directory, f"protocol_v{version}.yml")
    return text


def load(version_or_path, directory: Optional[str] = None) -> dict:
    """Parse and TOTALLY validate one protocol file.

    Returns the document as parsed, unmodified: nothing here defaults a
    missing key, because a protocol whose knob was defaulted on the way in is
    a protocol whose digest describes this loader rather than the file.
    """
    path = path_for(version_or_path, directory)
    try:
        key = (os.path.abspath(path), os.path.getmtime(path))
    except OSError as e:
        raise ProtocolError(f"no protocol file at {path}: {e}") from e
    doc = _CACHE.get(key)
    if doc is None:
        import yaml
        try:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as e:
            raise ProtocolError(f"{path} is unreadable: {e}") from e
        validate(doc, path)
    # A load BY VERSION NUMBER is a claim about a NAMED, immutable recipe, so
    # it is held to the pin: an edited protocol_vN.yml would otherwise yield a
    # perfectly self-consistent run whose rows carry a digest nothing else has
    # ever heard of, and nobody would look, because every check the run itself
    # performs would agree with the file it just read.  A load by explicit
    # PATH is exempt on purpose -- that is how a draft or a doctored copy is
    # examined at all.
    #
    # The pin runs on CACHE HITS too, and before anything is cached: the
    # cache key is (path, mtime), not (path, mtime, load mode), so a prior
    # path-load of the same file must not launder a later version-load past
    # the pin.  And an UNPINNED version number refuses outright -- the
    # immutability guarantee is only as total as this dict, so a version
    # someone forgot to pin must not load with no identity check at all.
    if isinstance(version_or_path, int) or (
            isinstance(version_or_path, str) and version_or_path.isdigit()):
        version = int(version_or_path)
        pinned = PINNED_DIGESTS.get(version)
        if pinned is None:
            raise ProtocolError(
                f"protocol version {version} has no pinned digest in "
                f"PINNED_DIGESTS. Pin it (and VERSIONS.yml) in the commit "
                f"that adds the file, or load it by explicit path while it "
                f"is still a draft.")
        computed = protocol_digest(doc)
        if computed != pinned:
            raise ProtocolError(
                f"protocol_v{version}.yml no longer digests to its pinned "
                f"identity: pinned {pinned}, computed {computed}. The file "
                f"is IMMUTABLE -- restore it, or write the change as a new "
                f"protocol_v{version + 1}.yml and pin that.")
    _CACHE[key] = doc
    return doc


def validate(doc: Any, path: str = "<protocol>") -> None:
    """Every key, every type, every cross-field rule -- or a refusal.

    Total on purpose.  This runs once per sweep, before an item is executed
    and before an agent is paid for, so the cost of being exhaustive is zero
    and the cost of being lenient is a run whose rows claim a digest for a
    document nobody checked.
    """
    if not isinstance(doc, dict):
        raise ProtocolError(f"{path} is not a mapping")
    codex = doc.get("protocol_version") in CODEX_VERSIONS
    claude_code = doc.get("protocol_version") in CLAUDE_CODE_VERSIONS
    native_cli = codex or claude_code
    if doc.get("protocol_version") in SLICE3_VERSIONS or native_cli:
        present_sampling = [name for name in ("temperature", "top_p")
                            if name in doc]
        if present_sampling:
            raise ProtocolError(
                f"{path}: Slice-3, Codex and Claude Code protocols omit sampling "
                f"members entirely; found {present_sampling}")
    for key, typ in _REQUIRED:
        if key not in doc:
            if (key == "temperature" and (
                    doc.get("protocol_version") in SLICE3_VERSIONS or native_cli)) \
                    or (key == "max_iterations" and native_cli):
                continue
            raise ProtocolError(
                f"{path} has no {key!r}; a protocol states every knob it "
                f"pins, because an absent knob reads as 'the harness default' "
                f"to a machine and as 'unimportant' to a reader")
        value = doc[key]
        # bool is a subclass of int: `coverage: 1` and `repeats: true` would
        # both pass a naive isinstance check and both mean nothing.
        if typ is bool and not isinstance(value, bool):
            raise ProtocolError(f"{path}: {key} must be true or false, "
                                f"got {value!r}")
        if typ is int and (isinstance(value, bool)
                           or not isinstance(value, int)):
            raise ProtocolError(f"{path}: {key} must be an integer, "
                                f"got {value!r}")
        if typ is float and (isinstance(value, bool)
                             or not isinstance(value, (int, float))):
            raise ProtocolError(f"{path}: {key} must be a number, "
                                f"got {value!r}")
        if typ is str and (not isinstance(value, str) or not value.strip()):
            raise ProtocolError(f"{path}: {key} must be a non-empty string, "
                                f"got {value!r}")
        if typ is dict and not isinstance(value, dict):
            raise ProtocolError(f"{path}: {key} must be a mapping, "
                                f"got {value!r}")
    if doc["schema"] != SCHEMA:
        raise ProtocolError(f"{path}: schema is {doc['schema']!r}, "
                            f"expected {SCHEMA!r}")
    if doc["protocol_version"] < 1:
        raise ProtocolError(f"{path}: protocol_version must be >= 1, "
                            f"got {doc['protocol_version']!r}")
    # `trials` is the one knob with three legal shapes, and it is checked
    # against the SAME vocabulary the stamp and the campaign fingerprint use.
    # A protocol spelling it `-1` or `"unlimted"` would default a run into a
    # budget nothing else in the harness can compare.
    from ..core.constants import UNBOUNDED
    budget = doc.get("trials")
    if budget != UNBOUNDED and (isinstance(budget, bool)
                                or not isinstance(budget, int)
                                or budget < 0):
        raise ProtocolError(
            f"{path}: trials must be 0 (no execution channel), a positive "
            f"count, or {UNBOUNDED!r} -- got {budget!r}")
    if doc.get("temperature") is not None and doc["temperature"] < 0:
        raise ProtocolError(f"{path}: temperature must be >= 0, "
                            f"got {doc['temperature']!r}")
    if doc["repeats"] < 1:
        raise ProtocolError(f"{path}: repeats must be >= 1, "
                            f"got {doc['repeats']!r}")
    if "max_iterations" in doc and doc["max_iterations"] < 1:
        raise ProtocolError(f"{path}: max_iterations must be >= 1, "
                            f"got {doc['max_iterations']!r}")
    if doc["agent_timeout_seconds"] < 1:
        raise ProtocolError(f"{path}: agent_timeout_seconds must be >= 1, "
                            f"got {doc['agent_timeout_seconds']!r}")

    # v5/v6 carry one deliberately closed request contract.  It is an
    # explicit version set: older files remain byte-compatible and an unknown
    # future version does not inherit Slice-3 semantics by numeric accident.
    if doc["protocol_version"] in SLICE3_VERSIONS:
        request = doc.get("model_request")
        expected = next(
            value for versions, value in SLICE3_CLOSED_REQUESTS.items()
            if doc["protocol_version"] in versions)
        if request != expected:
            raise ProtocolError(
                f"{path}: model_request must equal the closed Slice-3 "
                f"{expected['model']} request {expected!r}; got {request!r}")

    if codex:
        expected = codex_model_request(doc["protocol_version"])
        if doc.get("model_request") != expected:
            raise ProtocolError(
                f"{path}: Codex model_request differs from the reviewed "
                f"{expected['model']} recipe")
        if doc.get("native_knobs") != {"codex": {"max_model_calls": 200}}:
            raise ProtocolError(f"{path}: Codex recipes require max_model_calls 200")
        if "max_iterations" in doc:
            raise ProtocolError(f"{path}: Codex does not declare OpenHands max_iterations")

    if claude_code:
        expected = claude_code_model_request(doc["protocol_version"])
        if doc.get("model_request") != expected:
            raise ProtocolError(
                f"{path}: Claude Code model_request differs from the reviewed "
                f"{expected['model']} recipe")
        if doc.get("native_knobs") != {"claude_code": {"max_provider_requests": 200}}:
            raise ProtocolError(
                f"{path}: Claude Code recipes require max_provider_requests 200")
        if "max_iterations" in doc:
            raise ProtocolError(
                f"{path}: Claude Code does not declare OpenHands max_iterations")

    # ---- the native knobs, and the v3+ cross-field rule --------------------
    #
    # SHAPE FIRST, for any version that carries the key at all (v2 does).  A
    # native knob is read by `native_deviations` and stamped on every row as
    # `native_budget`, so a nested structure or a null here would reach a row
    # as a budget nobody can compare -- and `campaign._validate_fingerprint`
    # refuses non-scalars for the identical reason one level up.
    native = doc.get("native_knobs")
    if native is not None:
        if not isinstance(native, dict) or not native:
            raise ProtocolError(
                f"{path}: native_knobs must be a non-empty mapping of "
                f"agent_system -> knob -> value, got {native!r}")
        for system, knobs in sorted(native.items()):
            if not isinstance(system, str) or not system.strip():
                raise ProtocolError(f"{path}: native_knobs is keyed by "
                                    f"agent_system; {system!r} is not a name")
            if not isinstance(knobs, dict) or not knobs:
                raise ProtocolError(
                    f"{path}: native_knobs.{system} must be a non-empty "
                    f"mapping of knob -> value, got {knobs!r}")
            bad = sorted(k for k, v in knobs.items()
                         if not isinstance(k, str)
                         or not isinstance(v, (str, int, float))
                         or isinstance(v, bool))
            if bad:
                raise ProtocolError(
                    f"{path}: native_knobs.{system} entries {bad} are not "
                    f"scalar knob values; a native budget is stamped on every "
                    f"row and has to be comparable by equality")
    # THE CROSS-FIELD RULE, from v3 onwards.  `max_iterations` is an OpenHands
    # concept that predates `native_knobs` and therefore lives in TWO places:
    # the top-level key `KNOBS` compares against `--max-iterations`, and the
    # per-system map a second system's budget has to live in.  Two places for
    # one number is tolerable only while something makes them agree; a file
    # where they disagreed would pin one budget for the flag and another for
    # the record, and both would look authoritative.
    #
    # IT BINDS ON THE OPENHANDS BLOCK, NOT ON THE VERSION.  It used to be
    # unconditional from v3, which made "declare openhands.max_iterations" a
    # duty of EVERY future protocol file -- so a protocol pinning a third
    # agent's budget and nothing else could not be written at all, and the
    # only way to write one was to name a budget for a system the file was
    # not about.  What the rule actually protects is the ONE knob that is
    # written twice; a file that writes it once, in the per-system map where
    # every other budget lives, is not the failure this guards.
    #
    # v3+ only, still.  v1 has no `native_knobs` at all and v2 happens to
    # satisfy the rule; both are IMMUTABLE, so applying a rule they were not
    # written under could only ever strand them.  The version is the honest
    # place to bind a rule that came later.
    if doc["protocol_version"] >= 3:
        if not isinstance(native, dict) or not native:
            raise ProtocolError(
                f"{path}: a protocol from v3 onwards must record "
                f"`native_knobs` -- the budgets it pins per system. The "
                f"wall-clock envelope is the only budget that crosses "
                f"systems; everything else has to be named per system or it "
                f"is being claimed equal by silence.")
        # An openhands arm is what makes the knob exist twice, so it is what
        # the equality binds on.  Without one, what a v3+ file still owes is
        # "at least one system with at least one budget", and that is already
        # total: the check immediately above refuses an empty `native_knobs`,
        # and the shape pass refuses any system whose knob map is empty or
        # not a mapping.  Restating it here would be a third guard whose only
        # justification is the first two.
        oh = native.get("openhands")
        if oh is not None:
            # `oh` is a non-empty mapping by the shape pass above, so an
            # openhands arm that is present is an arm that can be read.
            if "max_iterations" not in oh:
                raise ProtocolError(
                    f"{path}: native_knobs names no openhands.max_iterations,"
                    f" but the top-level `max_iterations: "
                    f"{doc['max_iterations']!r}` IS that knob (a single-shot "
                    f"model has no iterations). Record it in both places, or "
                    f"the top-level pin names a budget for nothing.")
            if oh["max_iterations"] != doc["max_iterations"]:
                raise ProtocolError(
                    f"{path}: max_iterations is {doc['max_iterations']!r} at "
                    f"the top level and {oh['max_iterations']!r} in "
                    f"native_knobs.openhands. They are the same knob written "
                    f"twice: the top-level one is what `--max-iterations` is "
                    f"compared against, the native one is what a row records "
                    f"and a cross-system reader trusts. A file where they "
                    f"disagree pins two budgets and looks authoritative about "
                    f"both.")

    prof = doc["prompt_profile"]
    missing = [k for k in _PROFILE_REQUIRED if k not in prof]
    if missing:
        raise ProtocolError(f"{path}: prompt_profile has no {missing}")
    digests = prof["prompt_digest"]
    if not isinstance(digests, dict) or not digests:
        raise ProtocolError(f"{path}: prompt_profile.prompt_digest must be a "
                            f"non-empty mapping of arm -> sha256")
    bad = sorted(k for k, v in digests.items()
                 if not isinstance(v, str) or len(v) != 64
                 or any(c not in "0123456789abcdef" for c in v))
    if bad:
        raise ProtocolError(f"{path}: prompt_profile.prompt_digest entries "
                            f"{bad} are not sha256 hex")
    if prof["arm_prompt_key"] not in digests:
        raise ProtocolError(
            f"{path}: arm_prompt_key {prof['arm_prompt_key']!r} names no "
            f"digest; known: {sorted(digests)}")
    # The execution-enabled target-hidden recipes
    # (EXECUTION_ENABLED_TH_SENSITIVITY_SPEC.md section 6): a `c2r` file pins
    # the runtime pack its launch binds -- its prompt profile's project and
    # the pack's manifest digest, which the adapter compares with the
    # installed pack -- and no other file names one.
    if (doc["condition"] == "c2r") != ("runtime_pack" in doc):
        raise ProtocolError(
            f"{path}: `runtime_pack` belongs to every c2r recipe and to no "
            f"other; condition is {doc['condition']!r}")
    if "runtime_pack" in doc:
        pack = doc["runtime_pack"]
        if not isinstance(pack, dict) \
                or set(pack) != {"project", "manifest_sha256"}:
            raise ProtocolError(
                f"{path}: runtime_pack must be a mapping of exactly `project` "
                f"and `manifest_sha256`, got {pack!r}")
        if pack["project"] != prof.get("project"):
            raise ProtocolError(
                f"{path}: runtime_pack project {pack['project']!r} is not the "
                f"prompt profile's project {prof.get('project')!r}")
        digest = pack["manifest_sha256"]
        if not isinstance(digest, str) or len(digest) != 64 \
                or any(c not in "0123456789abcdef" for c in digest):
            raise ProtocolError(
                f"{path}: runtime_pack manifest_sha256 {digest!r} is not "
                f"sha256 hex")

    # Optional prospectively, but total whenever carried.  The old files keep
    # the field and their pinned identities; an optional field with a malformed
    # value is not the same thing as an absent field.
    if "network_policy" in doc:
        net = doc["network_policy"]
        if not isinstance(net, dict):
            raise ProtocolError(f"{path}: network_policy must be a mapping, "
                                f"got {net!r}")
        missing = [k for k in _NETWORK_REQUIRED if k not in net]
        if missing:
            raise ProtocolError(f"{path}: network_policy has no {missing}")
        gates = [k for k in ("egress_gate_at_publication",
                             "egress_gate_required") if k in net]
        if not gates:
            raise ProtocolError(
                f"{path}: network_policy names no egress gate. A retrospective "
                f"protocol records `egress_gate_at_publication` (the gate its "
                f"numbers were originally cleared under); a forward one "
                f"records `egress_gate_required`. Silence about the gate is "
                f"the one thing a network policy may not say.")
        for k in gates:
            if isinstance(net[k], bool) or not isinstance(net[k], int) \
                    or net[k] < 1:
                raise ProtocolError(
                    f"{path}: network_policy.{k} must be a gate version >= 1, "
                    f"got {net[k]!r}")
    if doc["reconstructed"] and "reconstructed_note" not in doc:
        raise ProtocolError(
            f"{path}: reconstructed is true but there is no "
            f"`reconstructed_note`. A recipe written after the run it "
            f"describes has to say when it was written and what it was read "
            f"back from, or the label is decoration.")


def _canonical(doc: dict) -> str:
    """The bytes the digest is taken over.

    Same spelling as `campaign._canonical` -- sorted keys, no whitespace --
    and for the same reason: two processes on two machines have to agree
    about the bytes, and `json.dumps`'s defaults do not.
    """
    return json.dumps(doc, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def protocol_digest(doc: dict) -> str:
    """sha256 over the canonical JSON of the WHOLE document, first 16 hex.

    The whole document, prose included.  A subtler rule -- digest only the
    knobs -- would let a protocol's explanation of what a knob MEANS change
    without the identity changing, and the explanation is the part a reader
    relies on.  Truncated to 16 for the same reason `campaign_digest` is:
    it is quoted in citations and refusals, and 64 bits is not a collision
    risk over the handful of protocols a benchmark ever has.
    """
    return hashlib.sha256(_canonical(doc).encode("utf-8")).hexdigest()[:16]


#: The digests of the shipped protocol files, computed once and pinned.
#:
#: Pinning is CORRECT here, unlike for a file under active edit, precisely
#: because the files are immutable: a knob change is a new `protocol_vN.yml`,
#: never an edit, so a change to any of these digests means somebody edited
#: a recipe that archived rows already cite.  The answer on that day is never
#: to re-pin -- it is to restore the file and add a v5.
#:
#: Project-specific twins have separate identities because rendered prompts
#: are part of the recipe.  A new twin adds a file and a pin; it never edits an
#: identity that existing evidence may cite.
PINNED_DIGESTS: dict = {
    54: "2d9b329927d50214",  # e-petitions checked full, OpenHands 200
    55: "6f557d6af81b9288",  # e-petitions checked target_hidden, OpenHands 200
    56: "60d74371290a0637",  # e-petitions checked all_hidden, OpenHands 200
    1: "68f477b3e4e761b5",
    2: "09d5fc7d2fd6a3ec",
    3: "e6ea6d2471996861",
    4: "bda1d9bcb1852e92",
    5: "b9f0f18741ecc5fa",
    6: "e1547acaebd159c8",
    # v7/v8 are v5/v6's twins under the 2026-08-12 model ruling: everything
    # identical but the closed request (deepseek-v4-pro, thinking OFF).  The
    # older pair keeps its pin rather than being edited, which is what makes
    # the q-freeze artifacts that cite it still readable.
    7: "397e2bc40a91ea8d",
    8: "e630da9f0d0ac2d2",
    # v9/v10 are the network-control retirement's prospective successors to
    # P3/P4 -- CoreShop and python-docx, carrying NO `network_policy` at all.
    # They reached master numbered 5 and 6; the owner renumbered them here
    # (2026-08-14) because this lineage's v5/v6 are cited by sealed evidence
    # and a protocol number, like a protocol file, is an identity rather than
    # a label.  Nothing else about the two documents moved.
    9: "41cada04be7e95b2",
    10: "647e879f5da8c4e8",
    # v11 is v9's CoreShop sensitivity successor.  The version creates the
    # new identity; the only experimental recipe change is the symmetric
    # per-item agent timeout, 3,600 -> 1,200 seconds.
    11: "2a9b7094af39c4af",
    # v12 is the generic Algorand twin of P9/P10: the same recipe with
    # Algorand's frozen prompt identity and no closed Slice-3 model request.
    12: "c660e70c9f3ff3a7",
    # v13 is v9's target-interfaces twin (TARGET_INTERFACES_SPEC): the same
    # recipe under `setting: target_interfaces`, carrying the disclosing
    # CoreShop profile's frozen prompt identity.
    13: "a87c287722778363",
    # v14 is v10's target-interfaces twin for python-docx (TARGET_INTERFACES_SPEC,
    # owner ruling D2): the same recipe under `setting: target_interfaces`,
    # carrying the disclosing python-docx profile's frozen prompt identity.
    14: "74307966090965cd",
    15: "ebc782561f3eee9c",
    16: "bf6eead997eb4dd8",
    17: "dba775c5649ef253",
    18: "917439069cba4840",
    19: "8bf159433b7d5303",
    20: "ec575fc62d1e5803",
    27: "e97dbd3848658b41",
    28: "cf0cbfe946ae7fad",
    29: "ff0bbaf9e18252e2",
    # Prospective CoreShop write-path correction; old recipe pins remain frozen.
    30: "40e1925a3a49e363",
    31: "7c6c724913e31ad5",
    32: "692b922bdebe68ee",
    33: "82d5ea391721a540",
    34: "2fe0b96d293c4cc5",
    35: "75db01e91d46e480",
    36: "1d979564303c2a1a",
    37: "78ac99c761e1179d",
    38: "566ad49efa7811e0",
    39: "5b54a0a6d0677405",
    40: "278f9d6e54c70b40",
    41: "34f658c44190e5ff",
    42: "238e5a2e35d250ad",
    43: "bd05ec2d311c0267",
    44: "18587c0872cad7cf",
    # v45-v47 are Sylius's final-only visibility trio (onboarding sprint
    # 2026-09 track S, S_sylius.md T8), on the v27-v29 aider/OpenHands shape
    # (not the Codex arm of v33-v44): full, target_hidden, all_hidden. Model
    # selection stays a separate run input, per v27-v29 and per section
    # 10.2's own `--llm-config` mechanism -- it is not a protocol key.
    45: "44f5ecbba6504593",
    46: "60768308125c0e5f",
    47: "8264d1a0f3fed796",
    # PrestaShop checked-interface visibility qualification protocols.
    48: "613f8560812899da",
    49: "b64f622ee6739128",
    50: "2cbb71e8d83cab26",
    # Kapua final-only visibility recipes; actual map/runtime gates remain separate.
    51: "4ff79ffae09cec55",
    52: "5bf49c8c1d317f92",
    53: "b711b0defde02576",
    # v57 is Go's ordinary full-source C3 twin of P9/P10/P12.
    57: "1eb3f1ff7c221271",
    # v58-v75 are the checked-interfaces (v2) family: three final-only
    # visibility recipes per project under `setting:
    # checked_interfaces_{full,target_hidden,all_hidden}`
    # (TARGET_INTERFACES_V2_SPEC sections 5, 5a and 7).  Ruling 17(b)
    # already reserves 58-60 for coddy-agent; 61-75 are the V track's
    # proposal, pending the sprint marshal's allocation.
    58: "b64a9fae6e499774",  # coddy-agent target_hidden
    59: "5ccd2def047702f7",  # coddy-agent all_hidden
    60: "70e1104abf394f71",  # coddy-agent full
    61: "2b75cb827110034d",  # python-docx full
    62: "9f1bd6608414fee1",  # python-docx target_hidden
    63: "59d970719dcfe2e3",  # python-docx all_hidden
    64: "a7e0195413fce0f4",  # CoreShop full
    65: "8776aec2609525f6",  # CoreShop target_hidden
    66: "5e99cc49f9ee1d01",  # CoreShop all_hidden
    67: "146bdc4a51c79006",  # Sylius full
    68: "dfc6d294ba58ff85",  # Sylius target_hidden
    69: "d14af0afe08699a5",  # Sylius all_hidden
    70: "29b3a1420bd4caf1",  # Algorand full
    71: "603c9cf192bafedb",  # Algorand target_hidden
    72: "fefeceb7d7e7572c",  # Algorand all_hidden
    73: "8baadb797c7ba580",  # Kapua full
    74: "f273deebeb5bac04",  # Kapua target_hidden
    75: "951acbfd512c1a4c",  # Kapua all_hidden
    # v76-v93 are the SAME eighteen checked-interfaces recipes at an
    # OpenHands budget of 200 (owner ruling R7, 2026-09-16: the 100-call
    # recipes ended many rows at the cap with no test written).  New
    # FILES, because v58-v75 are immutable and keep their 100; the four
    # prompt digests are copied unchanged, since a budget renders into no
    # prompt.  The numbers are a proposal pending the sprint marshal's
    # allocation.
    76: "a7c018bcefe79378",  # python-docx full (v61 at 200)
    77: "35477b45e0d82d0e",  # python-docx target_hidden (v62 at 200)
    78: "164655e3ff0bbda1",  # python-docx all_hidden (v63 at 200)
    79: "3e3b46e59aba8221",  # CoreShop full (v64 at 200)
    80: "062e43349a655be8",  # CoreShop target_hidden (v65 at 200)
    81: "659d42d0c2d4422e",  # CoreShop all_hidden (v66 at 200)
    82: "7d78fe041daa4689",  # Algorand full (v70 at 200)
    83: "efbce7e80ec62493",  # Algorand target_hidden (v71 at 200)
    84: "7b708c26545f72f2",  # Algorand all_hidden (v72 at 200)
    85: "502e779a7d8b79c5",  # Sylius full (v67 at 200)
    86: "a0062dcce8682a66",  # Sylius target_hidden (v68 at 200)
    87: "a59befee4b9dd2d9",  # Sylius all_hidden (v69 at 200)
    88: "6c692286e81c9c56",  # Kapua full (v73 at 200)
    89: "0859673ad469d659",  # Kapua target_hidden (v74 at 200)
    90: "0f0b1c56926acb88",  # Kapua all_hidden (v75 at 200)
    91: "73d26efb04bae586",  # coddy-agent target_hidden (v58 at 200)
    92: "3604dd543e5a7790",  # coddy-agent all_hidden (v59 at 200)
    93: "bfcc3329ec453072",  # coddy-agent full (v60 at 200)
    # v94-v107 are codex@2 on the checked-interfaces cells
    # (CODEX_CHECKED_INTERFACES_V2_SPEC.md): each sibling's setting, prompt
    # identity and visibility with the Codex shape of v39-v44 and a
    # deepseek-flash request.
    94: "1c786c558256902a",  # python-docx target_hidden (v77's input)
    95: "c89c7a5105add41c",  # python-docx all_hidden (v78's input)
    96: "ff4dc9fbcd32cb66",  # CoreShop target_hidden (v80's input)
    97: "1906b8f454df4e77",  # CoreShop all_hidden (v81's input)
    98: "df9fa8824deb7a55",  # Algorand target_hidden (v83's input)
    99: "e8c313ceb6f5294c",  # Algorand all_hidden (v84's input)
    100: "fb1b234e65721542",  # Sylius target_hidden (v86's input)
    101: "b67857dcd7a75b39",  # Sylius all_hidden (v87's input)
    102: "740a4f5702ac361f",  # Kapua target_hidden (v89's input)
    103: "8157d55d9d9e577f",  # Kapua all_hidden (v90's input)
    104: "f1c47035d2a5b477",  # coddy-agent target_hidden (v91's input)
    105: "ea65dfd7d7a9eddb",  # coddy-agent all_hidden (v92's input)
    106: "94f089f65cfed7ec",  # e-petitions target_hidden (v55's input)
    107: "2b217878058be620",  # e-petitions all_hidden (v56's input)
    # v108-v121 are v94-v107's twins for the GPT-6 Luna arm
    # (CODEX_CHECKED_INTERFACES_V2_GPT6_LUNA_AMENDMENT.md): only
    # protocol_version, the requested model and the notes differ.
    108: "a7adbb165f29ef40",  # python-docx target_hidden (v94's twin)
    109: "76bf807ca99fdfe0",  # python-docx all_hidden (v95's twin)
    110: "f91e23d48fea1840",  # CoreShop target_hidden (v96's twin)
    111: "b8631142f9cdfabf",  # CoreShop all_hidden (v97's twin)
    112: "c3eb783a2432545c",  # Algorand target_hidden (v98's twin)
    113: "c18973dd7460e1ba",  # Algorand all_hidden (v99's twin)
    114: "95e37a30cff2eabd",  # Sylius target_hidden (v100's twin)
    115: "f3344a19c39b9c5b",  # Sylius all_hidden (v101's twin)
    116: "4ce8a0e9ac50f823",  # Kapua target_hidden (v102's twin)
    117: "aca78f3a00090e97",  # Kapua all_hidden (v103's twin)
    118: "0438ef111663292a",  # coddy-agent target_hidden (v104's twin)
    119: "e30a2c56638859f5",  # coddy-agent all_hidden (v105's twin)
    120: "d26435b5ca966adc",  # e-petitions target_hidden (v106's twin)
    121: "70b02ef91eaa7d19",  # e-petitions all_hidden (v107's twin)
    # v122-v125 add PrestaShop to both codex@2 model arms
    # (CODEX_CHECKED_INTERFACES_V2_PRESTASHOP_AMENDMENT.md): v122/v123 take
    # v49/v50's setting, prompt identity and visibility with the deepseek-flash
    # request of v94-v107, and v124/v125 are their gpt-6-luna twins.
    122: "a53bc8de39d23bc8",  # PrestaShop target_hidden (v49's input)
    123: "03e2041a324e9541",  # PrestaShop all_hidden (v50's input)
    124: "b782717fe2106f11",  # PrestaShop target_hidden (v122's twin)
    125: "deba88bed1261494",  # PrestaShop all_hidden (v123's twin)
    # v126-v131 are e-petitions task revision r2 (owner decision 2026-09-28,
    # specifications/E_PETITIONS_ENVIRONMENT_CORRECTION_AMENDMENT.md: WebMock's
    # Cucumber World moves into retained support). Each is its r1 file with
    # only protocol_version and notes changed: v126/v127 of the aider/OpenHands
    # v55/v56, v128/v129 of the codex@2 v106/v107 (baseline siblings
    # v126/v127), v130/v131 of the never-run Luna v120/v121 (twins of
    # v128/v129). The notes cite the amendment and name the r2 map, seed and
    # source digests.
    126: "3a636978a937d1cc",  # e-petitions r2 target_hidden (v55's recipe)
    127: "051ccc2b4cefd6f8",  # e-petitions r2 all_hidden (v56's recipe)
    128: "1c555b57e384dbda",  # e-petitions r2 target_hidden (v106's recipe)
    129: "24a69524e4a8cafa",  # e-petitions r2 all_hidden (v107's recipe)
    130: "042177bb31c12d18",  # e-petitions r2 target_hidden (v128's twin)
    131: "1b4b8f0166710679",  # e-petitions r2 all_hidden (v129's twin)
    # v132-v147 are the GPT-6 Sol arm's twins of the Luna census recipes
    # (CODEX_CHECKED_INTERFACES_V2_GPT6_SOL_AMENDMENT.md): v132-v143 of
    # v108-v119, v144/v145 of v124/v125 and v146/v147 of v130/v131. Only
    # protocol_version, the requested model (gpt-6-sol) and the notes differ.
    132: "bd9333fc0a15da5a",  # python-docx target_hidden (v108's twin)
    133: "5231c1b35716d690",  # python-docx all_hidden (v109's twin)
    134: "03819173174f657d",  # CoreShop target_hidden (v110's twin)
    135: "3ca07fe2d29b6611",  # CoreShop all_hidden (v111's twin)
    136: "471f30b896f17fec",  # Algorand target_hidden (v112's twin)
    137: "4c9bcf77586b4241",  # Algorand all_hidden (v113's twin)
    138: "c8ba4505717e9b3f",  # Sylius target_hidden (v114's twin)
    139: "d33567c7eadaddeb",  # Sylius all_hidden (v115's twin)
    140: "d0a29a143af96b6d",  # Kapua target_hidden (v116's twin)
    141: "3d3dcb62650f516a",  # Kapua all_hidden (v117's twin)
    142: "e638c6ff8ee61977",  # coddy-agent target_hidden (v118's twin)
    143: "23dc932fb798b9f6",  # coddy-agent all_hidden (v119's twin)
    144: "aea9ba6ab3609863",  # PrestaShop target_hidden (v124's twin)
    145: "01171323eaa2b65d",  # PrestaShop all_hidden (v125's twin)
    146: "2a763a5cd7cea4e9",  # e-petitions r2 target_hidden (v130's twin)
    147: "a06f0343b7ee4cff",  # e-petitions r2 all_hidden (v131's twin)
    # v150-v173 and v178-v209 are the solution probe's arms
    # (specifications/SOLUTION_PROBE_SPEC.md sections 4, 5 and 10.3), in
    # blocks of four: python-docx target_hidden and all_hidden, then Algorand
    # target_hidden and all_hidden. Each is the census recipe of its model,
    # project and setting (the twin) with only what its arm changes: a
    # control (C0, C0p) only protocol_version and notes, a prompt arm (Obj,
    # C1, T1-T3) also prompt_profile, which names a probe profile, and R also
    # model_request (reasoning effort max). 174-177, DeepSeek R, are reserved
    # and not minted.
    150: "9ce5727c62a608fd",  # C0 deepseek-flash python-docx target_hidden (v94's twin)
    151: "2169bf84ad172c1f",  # C0 deepseek-flash python-docx all_hidden (v95's twin)
    152: "a707166953d9f772",  # C0 deepseek-flash Algorand SDK target_hidden (v98's twin)
    153: "23715b211b9b9553",  # C0 deepseek-flash Algorand SDK all_hidden (v99's twin)
    154: "dda4415249471499",  # C0p deepseek-flash python-docx target_hidden (v94's twin)
    155: "6cbe61a4ded1749d",  # C0p deepseek-flash python-docx all_hidden (v95's twin)
    156: "9263db2dc074d243",  # C0p deepseek-flash Algorand SDK target_hidden (v98's twin)
    157: "f66bbe5577de6e96",  # C0p deepseek-flash Algorand SDK all_hidden (v99's twin)
    158: "bdf43bc0dd3b420b",  # C1 deepseek-flash python-docx target_hidden (v94's twin)
    159: "ff40a89e8ca693bf",  # C1 deepseek-flash python-docx all_hidden (v95's twin)
    160: "802fb43eb88bb69d",  # C1 deepseek-flash Algorand SDK target_hidden (v98's twin)
    161: "a80e35bd8524c266",  # C1 deepseek-flash Algorand SDK all_hidden (v99's twin)
    162: "a7d186063698d42e",  # T1 deepseek-flash python-docx target_hidden (v94's twin)
    163: "9d5a59d185f0af8b",  # T1 deepseek-flash python-docx all_hidden (v95's twin)
    164: "7ff199be16448400",  # T1 deepseek-flash Algorand SDK target_hidden (v98's twin)
    165: "b9cbbf3d33f1c42d",  # T1 deepseek-flash Algorand SDK all_hidden (v99's twin)
    166: "113698780459de39",  # T2 deepseek-flash python-docx target_hidden (v94's twin)
    167: "dea79e5fa61d5377",  # T2 deepseek-flash python-docx all_hidden (v95's twin)
    168: "b0146f831a723fad",  # T2 deepseek-flash Algorand SDK target_hidden (v98's twin)
    169: "49b103a8d2fbd65c",  # T2 deepseek-flash Algorand SDK all_hidden (v99's twin)
    170: "21b3147042efd646",  # T3 deepseek-flash python-docx target_hidden (v94's twin)
    171: "caa427db403ece67",  # T3 deepseek-flash python-docx all_hidden (v95's twin)
    172: "d039855f4f193dff",  # T3 deepseek-flash Algorand SDK target_hidden (v98's twin)
    173: "a1a547353a28dbc1",  # T3 deepseek-flash Algorand SDK all_hidden (v99's twin)
    178: "b31bfb93ff1f69cf",  # C0 gpt-6-luna python-docx target_hidden (v108's twin)
    179: "270bea32788464ca",  # C0 gpt-6-luna python-docx all_hidden (v109's twin)
    180: "cff47586b51d5a33",  # C0 gpt-6-luna Algorand SDK target_hidden (v112's twin)
    181: "fbbcdeaf0a93c2f3",  # C0 gpt-6-luna Algorand SDK all_hidden (v113's twin)
    182: "e2711a2bc21dffb0",  # C0p gpt-6-luna python-docx target_hidden (v108's twin)
    183: "1a7520dadba003cd",  # C0p gpt-6-luna python-docx all_hidden (v109's twin)
    184: "be5d5931d15b7606",  # C0p gpt-6-luna Algorand SDK target_hidden (v112's twin)
    185: "bb5e4f12851f33ae",  # C0p gpt-6-luna Algorand SDK all_hidden (v113's twin)
    186: "cc93b10667f4531e",  # Obj gpt-6-luna python-docx target_hidden (v108's twin)
    187: "5bc8eaf3999e5787",  # Obj gpt-6-luna python-docx all_hidden (v109's twin)
    188: "bbc23919a3b27b5e",  # Obj gpt-6-luna Algorand SDK target_hidden (v112's twin)
    189: "d3f1f68bb3a75bdd",  # Obj gpt-6-luna Algorand SDK all_hidden (v113's twin)
    190: "902ca99c8ec32e0b",  # C1 gpt-6-luna python-docx target_hidden (v108's twin)
    191: "6f34eef5ba924b48",  # C1 gpt-6-luna python-docx all_hidden (v109's twin)
    192: "6b7d66efa9e4e462",  # C1 gpt-6-luna Algorand SDK target_hidden (v112's twin)
    193: "45bb08c2f18930da",  # C1 gpt-6-luna Algorand SDK all_hidden (v113's twin)
    194: "63181b983b092b8b",  # T1 gpt-6-luna python-docx target_hidden (v108's twin)
    195: "3991e1f91dfc3eb4",  # T1 gpt-6-luna python-docx all_hidden (v109's twin)
    196: "c993fab38715ddc9",  # T1 gpt-6-luna Algorand SDK target_hidden (v112's twin)
    197: "40b9c692ee28efae",  # T1 gpt-6-luna Algorand SDK all_hidden (v113's twin)
    198: "328dfa5e19f2b2dc",  # T2 gpt-6-luna python-docx target_hidden (v108's twin)
    199: "9584708a757fbbfd",  # T2 gpt-6-luna python-docx all_hidden (v109's twin)
    200: "2a4e703907418081",  # T2 gpt-6-luna Algorand SDK target_hidden (v112's twin)
    201: "7cddd2f1b7562568",  # T2 gpt-6-luna Algorand SDK all_hidden (v113's twin)
    202: "4798bd74e3ce78e7",  # T3 gpt-6-luna python-docx target_hidden (v108's twin)
    203: "b87dbdf51b3e7e54",  # T3 gpt-6-luna python-docx all_hidden (v109's twin)
    204: "03207a61026a1a21",  # T3 gpt-6-luna Algorand SDK target_hidden (v112's twin)
    205: "de41b0b23530dafb",  # T3 gpt-6-luna Algorand SDK all_hidden (v113's twin)
    206: "f0f322a82fe94336",  # R gpt-6-luna python-docx target_hidden (v108's twin)
    207: "cc1269777897f74c",  # R gpt-6-luna python-docx all_hidden (v109's twin)
    208: "1e7364966d3b0380",  # R gpt-6-luna Algorand SDK target_hidden (v112's twin)
    209: "74e233b9b0f8894a",  # R gpt-6-luna Algorand SDK all_hidden (v113's twin)
    # v210-v229 are the solution probe's GPT-6 Sol arms (PR-2,
    # specifications/SOLUTION_PROBE_SPEC.md sections 5 and 10.4), in the same
    # blocks of four. Each twins the Sol census recipe of its project and
    # setting (v132, v133, v136, v137) and changes only protocol_version and
    # notes, and for a prompt arm also prompt_profile, which names the arm's
    # probe profile shared with DeepSeek and Luna.
    210: "500d6c3d9d8483d9",  # C0 gpt-6-sol python-docx target_hidden (v132's twin)
    211: "ebedb7411ebc10b4",  # C0 gpt-6-sol python-docx all_hidden (v133's twin)
    212: "b5797a1c1f4227ab",  # C0 gpt-6-sol Algorand SDK target_hidden (v136's twin)
    213: "b831f0ffc1342354",  # C0 gpt-6-sol Algorand SDK all_hidden (v137's twin)
    214: "673a1df86a2bf78a",  # C1 gpt-6-sol python-docx target_hidden (v132's twin)
    215: "ac3e0f3c611a8aa5",  # C1 gpt-6-sol python-docx all_hidden (v133's twin)
    216: "7643d0637854ff5a",  # C1 gpt-6-sol Algorand SDK target_hidden (v136's twin)
    217: "aeb5fa3764a7249f",  # C1 gpt-6-sol Algorand SDK all_hidden (v137's twin)
    218: "6e311fa408bedb63",  # T1 gpt-6-sol python-docx target_hidden (v132's twin)
    219: "a586806b7dbd9573",  # T1 gpt-6-sol python-docx all_hidden (v133's twin)
    220: "8d7478e46ac3da92",  # T1 gpt-6-sol Algorand SDK target_hidden (v136's twin)
    221: "3387966f705d46f7",  # T1 gpt-6-sol Algorand SDK all_hidden (v137's twin)
    222: "861cfc9ef87b86e7",  # T2 gpt-6-sol python-docx target_hidden (v132's twin)
    223: "28462fab17942971",  # T2 gpt-6-sol python-docx all_hidden (v133's twin)
    224: "65441a85ff260b35",  # T2 gpt-6-sol Algorand SDK target_hidden (v136's twin)
    225: "eb21510df2546793",  # T2 gpt-6-sol Algorand SDK all_hidden (v137's twin)
    226: "4c9bf75fcf07d1b0",  # T3 gpt-6-sol python-docx target_hidden (v132's twin)
    227: "b79977f89f15eb0a",  # T3 gpt-6-sol python-docx all_hidden (v133's twin)
    228: "9d5b61ec033e8cb3",  # T3 gpt-6-sol Algorand SDK target_hidden (v136's twin)
    229: "7d44705e8c95a8b2",  # T3 gpt-6-sol Algorand SDK all_hidden (v137's twin)
    # v230-v231 are the solution probe's PrestaShop transfer check
    # (specifications/SOLUTION_PROBE_SPEC.md section 18.2, the dated amendment
    # that re-opens it as a post-freeze exploratory pilot): GPT-6 Luna,
    # target_hidden only, both twins of the PrestaShop census recipe v124.
    # v230 changes only protocol_version and notes; v231 also prompt_profile,
    # which names PrestaShop's T1 probe profile. 232-233 (T2, T3) are
    # reserved and not minted.
    230: "4de3d5f5cfaf9c6c",  # C0 gpt-6-luna PrestaShop target_hidden (v124's twin)
    231: "9da1bde38bff830d",  # T1 gpt-6-luna PrestaShop target_hidden (v124's twin)
    # v250-v265 are claude_code@1 on the checked-interfaces cells
    # (CLAUDE_CODE_AGENT_ADMISSION_SPEC.md), each the twin of a codex@2
    # deepseek-flash recipe (`CLAUDE_CODE_TWINS`) with only protocol_version,
    # native_knobs, model_request and notes changed.
    250: "e4a517109bf050e7",  # Claude Code python-docx target_hidden (v94's twin)
    251: "b64d19a73652c056",  # Claude Code python-docx all_hidden (v95's twin)
    252: "471e04a759e5d427",  # Claude Code CoreShop target_hidden (v96's twin)
    253: "a1622f1974abcaaa",  # Claude Code CoreShop all_hidden (v97's twin)
    254: "505f47175b50053e",  # Claude Code Algorand SDK target_hidden (v98's twin)
    255: "9f38dee8d0a61c50",  # Claude Code Algorand SDK all_hidden (v99's twin)
    256: "77667d20e5b5c2d2",  # Claude Code Sylius target_hidden (v100's twin)
    257: "273d97cf253b3003",  # Claude Code Sylius all_hidden (v101's twin)
    258: "eaaf399c8d9eaa26",  # Claude Code Kapua target_hidden (v102's twin)
    259: "8d5c4d2d11c63168",  # Claude Code Kapua all_hidden (v103's twin)
    260: "a1f94a431b12f649",  # Claude Code coddy-agent target_hidden (v104's twin)
    261: "ce4a753ebde29a2c",  # Claude Code coddy-agent all_hidden (v105's twin)
    262: "b96b2a18aebcada0",  # Claude Code PrestaShop target_hidden (v122's twin)
    263: "2c6c7ccddda20f4c",  # Claude Code PrestaShop all_hidden (v123's twin)
    264: "7be878b7cfd10ed0",  # Claude Code e-petitions r2 target_hidden (v128's twin)
    265: "f7fbeb2a32c64cd2",  # Claude Code e-petitions r2 all_hidden (v129's twin)
    # v270-v272 are the reasoning-off ablation
    # (specifications/CODEX_DEEPSEEK_REASONING_OFF_ABLATION_SPEC.md): each is
    # the deepseek-flash target_hidden census recipe of its project (the twin)
    # with only protocol_version, notes and model_request (reasoning effort
    # none) changed.
    270: "9cd98e10789ebee6",  # none deepseek-flash python-docx target_hidden (v94's twin)
    271: "b33f4915abd1ef26",  # none deepseek-flash CoreShop target_hidden (v96's twin)
    272: "bb6d101f27e021d1",  # none deepseek-flash Algorand SDK target_hidden (v98's twin)
    # v280-v295 are the RQ4 decomposition retry pilot
    # (../experiments/rq4-pilots-20261001/PILOT_SPEC.md, an exploratory
    # experiment of the paper, not a benchmark cell): each is the Codex
    # census recipe of its model, project and setting (the twin). The R0
    # twins 280-287 change only protocol_version and notes; the R1 twins
    # 288-295 also prompt_profile, which names the twin's profile plus
    # guidance block rq4_pilot_r1_v1 (`config/profile_*_pilot_r1_*.yml`).
    280: "a2f4897255fbe735",  # R0 deepseek-flash python-docx target_hidden (v94's twin)
    281: "78d7415d7c802207",  # R0 deepseek-flash python-docx all_hidden (v95's twin)
    282: "83ffd00a10453ba0",  # R0 deepseek-flash CoreShop target_hidden (v96's twin)
    283: "a47621ddfe9a41c4",  # R0 deepseek-flash CoreShop all_hidden (v97's twin)
    284: "4687e9376b7ee9a5",  # R0 gpt-6-luna python-docx target_hidden (v108's twin)
    285: "a4d37acd7bd8c4b3",  # R0 gpt-6-luna python-docx all_hidden (v109's twin)
    286: "be21d2e61f20afd9",  # R0 gpt-6-luna CoreShop target_hidden (v110's twin)
    287: "7fbdfbee32da6298",  # R0 gpt-6-luna CoreShop all_hidden (v111's twin)
    288: "0d6480a650e1dce2",  # R1 deepseek-flash python-docx target_hidden (v94's twin)
    289: "6afa76a014b9e995",  # R1 deepseek-flash python-docx all_hidden (v95's twin)
    290: "eb91297525dfb268",  # R1 deepseek-flash CoreShop target_hidden (v96's twin)
    291: "b7906660c17e4538",  # R1 deepseek-flash CoreShop all_hidden (v97's twin)
    292: "2d4c67fae1678254",  # R1 gpt-6-luna python-docx target_hidden (v108's twin)
    293: "1b778630aa9917ed",  # R1 gpt-6-luna python-docx all_hidden (v109's twin)
    294: "a07bb47e184024b7",  # R1 gpt-6-luna CoreShop target_hidden (v110's twin)
    295: "285b6bf9ffc21eb2",  # R1 gpt-6-luna CoreShop all_hidden (v111's twin)
    # v296-v299 and v304-v321 are wave 2 of the RQ4 pilots
    # (../experiments/rq4-pilots-20261001/PILOT_SPEC_WAVE2.md): census twins
    # again. The level pilot's L twins 296-299 change only protocol_version
    # and notes (the level block is the experiment's supplement); the
    # decomposition extension's R0 304-312 likewise, and its R1 313-321 also
    # prompt_profile (`config/profile_*_pilot_r1_*.yml`, guidance block
    # rq4_pilot_r1_v1). 300-303 are not minted.
    296: "7b21c0e95298c362",  # L deepseek-flash python-docx target_hidden (v94's twin)
    297: "f1b9b327a9ec96a7",  # L deepseek-flash CoreShop target_hidden (v96's twin)
    298: "6744e294a18cb5e9",  # L gpt-6-luna python-docx target_hidden (v108's twin)
    299: "f8d38df18c4345e3",  # L gpt-6-luna CoreShop target_hidden (v110's twin)
    304: "71d165a798e063a3",  # R0 deepseek-flash Algorand SDK target_hidden (v98's twin)
    305: "4a8e4752f4e18f1b",  # R0 deepseek-flash Algorand SDK all_hidden (v99's twin)
    306: "4b4a9de099ca757f",  # R0 deepseek-flash Sylius target_hidden (v100's twin)
    307: "dbac479cdaf29590",  # R0 deepseek-flash Sylius all_hidden (v101's twin)
    308: "7c533589764113d0",  # R0 deepseek-flash coddy-agent target_hidden (v104's twin)
    309: "554b586dae34750d",  # R0 deepseek-flash coddy-agent all_hidden (v105's twin)
    310: "179c3c8f38001bee",  # R0 gpt-6-luna Kapua target_hidden (v116's twin)
    311: "be4395805eb87ef6",  # R0 gpt-6-luna Kapua all_hidden (v117's twin)
    312: "93e6d92ea5e64211",  # R0 gpt-6-luna coddy-agent target_hidden (v118's twin)
    313: "8cc5c62016e791fb",  # R1 deepseek-flash Algorand SDK target_hidden (v98's twin)
    314: "b98a0c2ff39ccdbf",  # R1 deepseek-flash Algorand SDK all_hidden (v99's twin)
    315: "ed307b523902a411",  # R1 deepseek-flash Sylius target_hidden (v100's twin)
    316: "7b078fd377919985",  # R1 deepseek-flash Sylius all_hidden (v101's twin)
    317: "c32493a965b2c49b",  # R1 deepseek-flash coddy-agent target_hidden (v104's twin)
    318: "874613d1cda82ccc",  # R1 deepseek-flash coddy-agent all_hidden (v105's twin)
    319: "4932566264fff240",  # R1 gpt-6-luna Kapua target_hidden (v116's twin)
    320: "15c66077825a569f",  # R1 gpt-6-luna Kapua all_hidden (v117's twin)
    321: "2f59d66baf194b19",  # R1 gpt-6-luna coddy-agent target_hidden (v118's twin)
    # v322-v327 are wave 3 of the RQ4 pilots, pilot E
    # (../experiments/rq4-pilots-20261001/PILOT_SPEC_WAVE3.md): twins of the
    # Luna target_hidden census recipes 108 and 112. C 322-323 and E 326-327
    # change only protocol_version and notes (E's per-item block is the
    # experiment's supplement); T1 324-325 also prompt_profile, which is the
    # one the solution probe's T1 recipes 194 and 196 name
    # (`config/profile_*_probe_t1_target_hidden.yml`, guidance block
    # probe_t1_v1).
    322: "e9fff8bfff71593c",  # C gpt-6-luna python-docx target_hidden (v108's twin)
    323: "a5b1b9a74613b6be",  # C gpt-6-luna Algorand SDK target_hidden (v112's twin)
    324: "8751eaf37ef8ddf7",  # T1 gpt-6-luna python-docx target_hidden (v108's twin)
    325: "78c0c354c65c6e76",  # T1 gpt-6-luna Algorand SDK target_hidden (v112's twin)
    326: "6166a8ca5ffdc321",  # E gpt-6-luna python-docx target_hidden (v108's twin)
    327: "2a585d8cf60e701d",  # E gpt-6-luna Algorand SDK target_hidden (v112's twin)
    # v332-v339 are pilot P1 of the RQ4 pilots
    # (../experiments/rq4-pilots-20261001/PILOT_SPEC_P1.md): Rcov 332-335 and
    # Rctl 336-339 copy the R1 recipes 294, 295, 319 and 320, changing only
    # protocol_version and notes, so each names its R1 recipe's profile and
    # digests. Which Scenarios the per-item reference section shows is the
    # experiment's supplement, outside these files.
    332: "9377069a1f8c5c68",  # Rcov gpt-6-luna CoreShop target_hidden (v294's copy)
    333: "7d0a4f969a0e603c",  # Rcov gpt-6-luna CoreShop all_hidden (v295's copy)
    334: "31ab55344ef0498b",  # Rcov gpt-6-luna Kapua target_hidden (v319's copy)
    335: "05db31bb48e00228",  # Rcov gpt-6-luna Kapua all_hidden (v320's copy)
    336: "e6095753434c837b",  # Rctl gpt-6-luna CoreShop target_hidden (v294's copy)
    337: "22f45d743d2af156",  # Rctl gpt-6-luna CoreShop all_hidden (v295's copy)
    338: "f3b01768f39db083",  # Rctl gpt-6-luna Kapua target_hidden (v319's copy)
    339: "8b287071fe94b0fa",  # Rctl gpt-6-luna Kapua all_hidden (v320's copy)
    # v340-v352 extend the reasoning-off ablation to the other thirteen cells
    # of the codex@2 deepseek-flash census
    # (specifications/CODEX_DEEPSEEK_REASONING_OFF_ABLATION_SPEC.md): each is
    # the deepseek-flash census recipe of its project and setting (the twin)
    # with only protocol_version, notes and model_request (reasoning effort
    # none) changed, as v270-v272 are.
    340: "6887d2d4be982f86",  # none deepseek-flash python-docx all_hidden (v95's twin)
    341: "e419e8baa96ac9e1",  # none deepseek-flash CoreShop all_hidden (v97's twin)
    342: "ea59e710a5748fb6",  # none deepseek-flash Algorand SDK all_hidden (v99's twin)
    343: "57a862549bd16055",  # none deepseek-flash Sylius target_hidden (v100's twin)
    344: "ab644fbf53e45ea2",  # none deepseek-flash Sylius all_hidden (v101's twin)
    345: "8d445d1175b64c42",  # none deepseek-flash Kapua target_hidden (v102's twin)
    346: "314ec6960bb0b62f",  # none deepseek-flash Kapua all_hidden (v103's twin)
    347: "5430181af63b69cc",  # none deepseek-flash coddy-agent target_hidden (v104's twin)
    348: "392eefc075602ba8",  # none deepseek-flash coddy-agent all_hidden (v105's twin)
    349: "ba81317de537fee9",  # none deepseek-flash PrestaShop target_hidden (v122's twin)
    350: "d9dc320ad2e490f5",  # none deepseek-flash PrestaShop all_hidden (v123's twin)
    351: "9578083edf0a9257",  # none deepseek-flash e-petitions r2 target_hidden (v128's twin)
    352: "31874ee4c3246a0c",  # none deepseek-flash e-petitions r2 all_hidden (v129's twin)
    # v353-v368 are claude_code@1 with claude-sonnet-5-5
    # (specifications/CLAUDE_CODE_SONNET_5_5_AMENDMENT.md section 2): each is the
    # Claude Code DeepSeek recipe of its project and setting (the twin, 250-265)
    # with only protocol_version, model_request.model and notes changed.
    353: "15e0e28e7e87e390",  # Claude Code sonnet-5-5 python-docx target_hidden (v250's twin)
    354: "2445e47844e31bae",  # Claude Code sonnet-5-5 python-docx all_hidden (v251's twin)
    355: "4f39201e427c376e",  # Claude Code sonnet-5-5 CoreShop target_hidden (v252's twin)
    356: "9180f1022e55530a",  # Claude Code sonnet-5-5 CoreShop all_hidden (v253's twin)
    357: "f45356efd6d2aba9",  # Claude Code sonnet-5-5 Algorand SDK target_hidden (v254's twin)
    358: "c3a9c6ed33aad06d",  # Claude Code sonnet-5-5 Algorand SDK all_hidden (v255's twin)
    359: "76262522352452f4",  # Claude Code sonnet-5-5 Sylius target_hidden (v256's twin)
    360: "7adcf7a1115756b3",  # Claude Code sonnet-5-5 Sylius all_hidden (v257's twin)
    361: "c9ec95ceed4ec7e6",  # Claude Code sonnet-5-5 Kapua target_hidden (v258's twin)
    362: "2df055a820971b05",  # Claude Code sonnet-5-5 Kapua all_hidden (v259's twin)
    363: "13679e7ed7cb85e0",  # Claude Code sonnet-5-5 coddy-agent target_hidden (v260's twin)
    364: "8ad1936b73ccced6",  # Claude Code sonnet-5-5 coddy-agent all_hidden (v261's twin)
    365: "7f40726a94d7a5c8",  # Claude Code sonnet-5-5 PrestaShop target_hidden (v262's twin)
    366: "b17927b2e494e396",  # Claude Code sonnet-5-5 PrestaShop all_hidden (v263's twin)
    367: "e051f15ba85deef5",  # Claude Code sonnet-5-5 e-petitions r2 target_hidden (v264's twin)
    368: "b63e7920f34efa52",  # Claude Code sonnet-5-5 e-petitions r2 all_hidden (v265's twin)
    # v369-v384 are claude_code@1 with claude-opus-5-5 and v385-v400 codex@2 with
    # gpt-6.1-sol (specifications/FRONTIER_ARMS_20261015_AMENDMENT.md section 2):
    # each is its Sonnet 5.5 twin (353-368) or GPT-6 Sol twin (132-147) with only
    # protocol_version, model_request.model and notes changed.
    369: "8b949d3deb732c24",  # Claude Code opus-5-5 python-docx target_hidden (v353's twin)
    370: "067d995479811fcf",  # Claude Code opus-5-5 python-docx all_hidden (v354's twin)
    371: "8feacbddce456727",  # Claude Code opus-5-5 CoreShop target_hidden (v355's twin)
    372: "e74dcbddd0723ca6",  # Claude Code opus-5-5 CoreShop all_hidden (v356's twin)
    373: "5d550bdf6129c6b7",  # Claude Code opus-5-5 Algorand SDK target_hidden (v357's twin)
    374: "386232c883230e5e",  # Claude Code opus-5-5 Algorand SDK all_hidden (v358's twin)
    375: "fe9dcab0de46ae79",  # Claude Code opus-5-5 Sylius target_hidden (v359's twin)
    376: "d6e67f604e55fc88",  # Claude Code opus-5-5 Sylius all_hidden (v360's twin)
    377: "62f9968487687abb",  # Claude Code opus-5-5 Kapua target_hidden (v361's twin)
    378: "b8bb4a115e0e8309",  # Claude Code opus-5-5 Kapua all_hidden (v362's twin)
    379: "5a85655af41ace52",  # Claude Code opus-5-5 coddy-agent target_hidden (v363's twin)
    380: "384ef7c62bf1b1ad",  # Claude Code opus-5-5 coddy-agent all_hidden (v364's twin)
    381: "1e7ddab71bc6cc6c",  # Claude Code opus-5-5 PrestaShop target_hidden (v365's twin)
    382: "86e36d38416c33c9",  # Claude Code opus-5-5 PrestaShop all_hidden (v366's twin)
    383: "a029a8665909f8be",  # Claude Code opus-5-5 e-petitions r2 target_hidden (v367's twin)
    384: "2d575707e12f917f",  # Claude Code opus-5-5 e-petitions r2 all_hidden (v368's twin)
    385: "671caaeb2c11a887",  # gpt-6.1-sol python-docx target_hidden (v132's twin)
    386: "c9a2c724b6ee84b3",  # gpt-6.1-sol python-docx all_hidden (v133's twin)
    387: "7a1b37f5f0ce9a1d",  # gpt-6.1-sol CoreShop target_hidden (v134's twin)
    388: "fd364d3201247d79",  # gpt-6.1-sol CoreShop all_hidden (v135's twin)
    389: "6b96b22338f2639e",  # gpt-6.1-sol Algorand SDK target_hidden (v136's twin)
    390: "1b36674ccd5c90ed",  # gpt-6.1-sol Algorand SDK all_hidden (v137's twin)
    391: "961d246e5d9dd3a7",  # gpt-6.1-sol Sylius target_hidden (v138's twin)
    392: "cd43e8cfc6860dfc",  # gpt-6.1-sol Sylius all_hidden (v139's twin)
    393: "98921a36d324364a",  # gpt-6.1-sol Kapua target_hidden (v140's twin)
    394: "34b34c7fb37b090c",  # gpt-6.1-sol Kapua all_hidden (v141's twin)
    395: "5e90c83c0c48d0a2",  # gpt-6.1-sol coddy-agent target_hidden (v142's twin)
    396: "5c9f451936639108",  # gpt-6.1-sol coddy-agent all_hidden (v143's twin)
    397: "caa68bf68754d01b",  # gpt-6.1-sol PrestaShop target_hidden (v144's twin)
    398: "902bf36d33c8d675",  # gpt-6.1-sol PrestaShop all_hidden (v145's twin)
    399: "b8a8414b80fd2237",  # gpt-6.1-sol e-petitions r2 target_hidden (v146's twin)
    400: "577b8bc53f8e6556",  # gpt-6.1-sol e-petitions r2 all_hidden (v147's twin)
    # v401-v408 are the execution-enabled target-hidden sensitivity's c2r
    # recipes (specifications/EXECUTION_ENABLED_TH_SENSITIVITY_SPEC.md section
    # 6): each is its blind twin with only protocol_version, condition, the
    # variant prompt profile (its five digests, arm key c2r), runtime_pack and
    # notes changed.
    401: "20e9790fde631afd",  # c2r deepseek-flash python-docx target_hidden (v94's twin)
    402: "ed9887cebb0735c4",  # c2r deepseek-flash CoreShop target_hidden (v96's twin)
    403: "328a201aae25aa47",  # c2r deepseek-flash Algorand SDK target_hidden (v98's twin)
    404: "aafb841a338e66e2",  # c2r deepseek-flash Sylius target_hidden (v100's twin)
    405: "78703a94750b1197",  # c2r deepseek-flash Kapua target_hidden (v102's twin)
    406: "53a6aed289d444eb",  # c2r deepseek-flash coddy-agent target_hidden (v104's twin)
    407: "f2a0a8e6fb08e333",  # c2r deepseek-flash PrestaShop target_hidden (v122's twin)
    408: "e6fef5a50ed5e8f6",  # c2r deepseek-flash e-petitions r2 target_hidden (v128's twin)
    # v417-v426 are benchmark 2.0's protocols for new arms
    # (specifications/BENCHMARK_V2_SPEC.md section 9, PR 6): the re-run
    # baseline cells of section 5.4, each its c2r twin with only
    # protocol_version, runtime_pack (the rebuilt pack) and notes changed,
    # and the GPT-6.1 Sol arm, each its 2.0 baseline twin with only
    # protocol_version, model_request.model, runtime_pack (the scrubbed
    # pack, where the twin pins the unscrubbed one) and notes changed.
    417: "5c8fbff85b1e02cc",  # c2r deepseek-flash Algorand SDK target_hidden, 2.0 re-run baseline (v403's twin)
    418: "29022b46416e9ae9",  # c2r deepseek-flash Kapua target_hidden, 2.0 re-run baseline (v405's twin)
    419: "c9452d2f89ccc77e",  # c2r gpt-6.1-sol python-docx target_hidden, 2.0 (v401's twin)
    420: "db553d917eaedced",  # c2r gpt-6.1-sol CoreShop target_hidden, 2.0 (v402's twin)
    421: "92a6704c3a192cc3",  # c2r gpt-6.1-sol Algorand SDK target_hidden, 2.0 (v417's twin)
    422: "55ee1af2408befee",  # c2r gpt-6.1-sol Sylius target_hidden, 2.0 (v404's twin)
    423: "26753073f33e4cca",  # c2r gpt-6.1-sol Kapua target_hidden, 2.0 (v418's twin)
    424: "d021885d9ec4bbd8",  # c2r gpt-6.1-sol coddy-agent target_hidden, 2.0 (v406's twin)
    425: "ea25616db359f0aa",  # c2r gpt-6.1-sol PrestaShop target_hidden, 2.0 (v407's twin)
    426: "5ae9adb036d4351e",  # c2r gpt-6.1-sol e-petitions r2 target_hidden, 2.0 (v408's twin)
    # v427-v434 are the GPT-6.1 Sol re-run
    # (specifications/BENCHMARK_V2_RUNTIME_PATH_AMENDMENT.md section 5): each
    # is the withdrawn cell 419-426 with only protocol_version, runtime_pack
    # (the project's v1.1 pack) and notes changed.
    427: "23929477c351b7b9",  # c2r gpt-6.1-sol python-docx target_hidden, 2.0 re-run, pack v1.1 (v419's twin)
    428: "e4f73a07ddbd3430",  # c2r gpt-6.1-sol CoreShop target_hidden, 2.0 re-run, pack v1.1 (v420's twin)
    429: "eb4da56077d4d365",  # c2r gpt-6.1-sol Algorand SDK target_hidden, 2.0 re-run, pack v1.1 (v421's twin)
    430: "3dc4cefc5d030889",  # c2r gpt-6.1-sol Sylius target_hidden, 2.0 re-run, pack v1.1 (v422's twin)
    431: "e9d82cb9d44121bd",  # c2r gpt-6.1-sol Kapua target_hidden, 2.0 re-run, pack v1.1 (v423's twin)
    432: "5cb935a8b9ef95d9",  # c2r gpt-6.1-sol coddy-agent target_hidden, 2.0 re-run, pack v1.1 (v424's twin)
    433: "003e9c0064ae1c0f",  # c2r gpt-6.1-sol PrestaShop target_hidden, 2.0 re-run, pack v1.1 (v425's twin)
    434: "29863bcd4bba1511",  # c2r gpt-6.1-sol e-petitions r2 target_hidden, 2.0 re-run, pack v1.1 (v426's twin)
}


def protocol_for_project(project: Optional[str],
                         directory: Optional[str] = None) -> list[int]:
    """Which shipped protocols carry THIS project's frozen prompt digests.

    Derived from the files on disk, never from a table: a second list of
    "which protocol belongs to which project" is a second thing to keep in
    step, and the answer is already written in every file's
    `prompt_profile.project`.  Sorted, and `[]` for a project no protocol
    names -- which is the honest answer while a third stack has a profile but
    no recipe yet.

    A file that will not load is SKIPPED rather than fatal: this function
    exists to make a refusal more useful, and a refusal that itself refused
    would be worse than one that says less.
    """
    if not project:
        return []
    out = []
    for version in known_versions(directory):
        try:
            doc = load(version, directory)
        except ProtocolError:
            continue
        prof = doc.get("prompt_profile")
        if isinstance(prof, dict) and prof.get("project") == project:
            out.append(version)
    return out


def project_deviations(protocol: dict,
                       project: Optional[str]) -> list[str]:
    """One string when the run's PROJECT is not the protocol's, else `[]`.

    THE THIRD KIND OF DEVIATION, and the only one that is not about a knob.
    A protocol copies ONE project's five frozen prompt digests
    (`prompt_profile`), because the prompt template is rendered against a
    project's profile and every rendered byte is that project's.  So a sweep
    over python-docx launched with `--protocol 3` would stamp CoreShop's
    prompt identity on every row while having sent python-docx's bytes -- a
    citation that is wrong in the one field citations exist to pin down, and
    wrong in a way no knob comparison can see.

    Reported here, ACTED ON by `cli._apply_protocol`, exactly like the other
    two lists: refused under `--campaign` (a comparable row may not cite a
    prompt it did not use), recorded verbatim on every row otherwise (an
    ad-hoc probe may, as long as it says so).  Sharing that mechanism is
    deliberate -- a parallel refusal would be a second place for the
    refuse-or-record decision to be made, and the two would drift.

    SILENCE ON EITHER SIDE ASSERTS NOTHING, the same rule
    `check_comparison_class` follows.  v1 and v2 name no project: they were
    written before the key existed and they are IMMUTABLE, so holding them to
    a rule written after them could only strand them.  And a caller that
    could not resolve WHICH project this invocation is about passes None --
    an unanswered question, not a matching answer.

    The message names the right file, because "this is the wrong protocol" is
    only half of what an operator at 2am needs.
    """
    prof = protocol.get("prompt_profile")
    declared = prof.get("project") if isinstance(prof, dict) else None
    if not declared or not project or declared == project:
        return []
    siblings = [v for v in protocol_for_project(project)
                if v != protocol.get("protocol_version")]
    where = (f"protocol_v{siblings[0]}.yml carries {project}'s"
             if len(siblings) == 1 else
             (f"protocols {siblings} carry {project}'s" if siblings else
              f"no protocol file carries {project}'s -- a project without a "
              f"recipe has nothing to be cited under yet"))
    return [f"prompt_profile.project (--profile): protocol says {declared!r}, "
            f"this run's prompts render from {project!r}, so its rows would "
            f"cite prompt digests they did not use; {where}"]
