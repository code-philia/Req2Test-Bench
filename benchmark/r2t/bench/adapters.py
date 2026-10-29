"""S7 — system-under-test adapters.

The gap in ART this benchmark exists to close: ART evaluates one method,
so its generation is welded to its executor.  Here anything that maps

    task  ->  {files: [{file_path, code}], metadata}

can be evaluated.  An adapter is a callable with that signature plus a
name (`fixtures.Adapter`).  The controls and the transports -- gold, empty,
stub, stripped-gold, replay, submitted -- are built in `fixtures.py`; the
systems under test are built here:

  openai   any OpenAI-compatible chat endpoint (DeepSeek v4 Pro is one),
           configured by file or environment, never by a committed key.
  openhands  drives an OpenHands agent (openhands-ai 1.x, SDK) over a COPY
           of the stripped repository, so the agent can READ the codebase
           while it writes. The answer is whatever changed under the
           removable tree, not whatever the agent says it did.  Built in
           `agents/adapter.py` since wave O2, from the prompts rendered
           here; this module imports without the agent component.

The prompt itself -- what the model is told, rendered from the task
profile (`r2t/data/profile.py`, `config/profile_<project>.yml`) -- lives in
`prompt.py` since wave M5: `load_profile` verifies every project's four
prompt digests on every load, so the renderer is part of the dataset
contract and this module only fills it in.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from typing import Optional

from ..core.paths import agent_python

from .fixtures import Adapter
from ..data.profile import TaskProfile
# The prompt renderer moved to `prompt.py` in wave M5; the two entry points
# the single-shot adapter fills in, and the condition normaliser the
# repository ablation shares with it, are imported back from there.
# `terminate`, the envelope-expiry contract, is imported where the envelope
# expires (`agents.adapter._run_agent`, `agents.adapter.make_agent_adapter`).
from ..data.prompt import _agent_condition, _profile, build_user_prompt, system_prompt
from ..core.paths import CONFIG_DIR


# ------------------------------------------------------------ LLM adapter
def resolve_llm_config(path: Optional[str],
                       explicit_model: Optional[str] = None, *,
                       require_credentials: bool = True) -> dict:
    """Resolve credentials and model once, refusing an explicit conflict."""
    cfg = {}
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            cfg = json.load(fh)
    for key, env in (("base_url", "R2T_LLM_BASE_URL"),
                     ("api_key", "R2T_LLM_API_KEY"),
                     ("model", "R2T_LLM_MODEL")):
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    configured_model = cfg.get("model")
    if explicit_model and configured_model \
            and explicit_model != configured_model:
        raise SystemExit(
            f"REFUSED: --model {explicit_model!r} conflicts with the "
            f"configured model {configured_model!r}. Use one model identity "
            f"for execution, campaign provenance and result rows.")
    if explicit_model:
        cfg["model"] = explicit_model
    # A ChatGPT account configuration's credential is its account's Codex
    # login file (`agents.chatgpt_account`, which validates the rest), and a
    # Claude subscription's its token file (`agents.claude_account`).
    credential = {"chatgpt_account": "chatgpt_auth_file",
                  "claude_subscription": "claude_token_file"}.get(
        cfg.get("access_route"), "api_key")
    required = (("base_url", credential, "model")
                if require_credentials else ("model",))
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        raise SystemExit(
            f"LLM adapter needs {missing}: pass --llm-config FILE or set "
            f"R2T_LLM_BASE_URL / R2T_LLM_API_KEY / R2T_LLM_MODEL")
    return cfg


_JSON_BLOCK = re.compile(r"\{.*\}", re.S)


_VALID_ESCAPE = set('"\\/bfnrtu')


def _repair_php_escapes(text: str) -> str:
    """Double the backslashes a model left bare inside a JSON string.

    The adapter contract asks for PHP SOURCE inside a JSON string, and PHP
    is made of backslashes: every namespace is `CoreShop\\Behat\\Context`.
    JSON requires each to be doubled, and a model that forgets produces
    `Invalid \\escape` — not a wrong test, a wrong quoting convention we
    imposed.  Measured on a 100-item sweep: 10 of 100 responses failed this
    way with `finish_reason: stop`, i.e. the model finished cleanly and we
    threw the answer away.

    Only backslashes that cannot begin a valid JSON escape are doubled, so
    a correctly-escaped response is left byte-identical.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n and text[i + 1] not in _VALID_ESCAPE:
            out.append("\\\\")
        else:
            out.append(c)
        i += 1
    return "".join(out)


def parse_model_output(text: str) -> dict:
    """Model output -> the adapter contract, tolerantly.

    A refusal to parse is itself a measurement (`parse_error`), so this
    never raises: the run harness records it as the outcome.  But a failure
    caused by OUR encoding choice is not a measurement of the system, so
    one repair pass runs before giving up, and whether it was needed is
    recorded (`repaired_escapes`) rather than hidden.
    """
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned)

    def _attempt(raw: str):
        try:
            return json.loads(raw), None
        except json.JSONDecodeError as e:
            m = _JSON_BLOCK.search(raw)
            if not m:
                return None, f"no JSON object: {e}"
            try:
                return json.loads(m.group(0)), None
            except json.JSONDecodeError as e2:
                return None, str(e2)

    doc, err = _attempt(cleaned)
    repaired = False
    if doc is None:
        doc, err2 = _attempt(_repair_php_escapes(cleaned))
        repaired = doc is not None
        err = err if doc is None else None
    if doc is None:
        return {"files": [], "metadata": {"parse_error": err,
                                          "raw_tail": text[-800:],
                                          "raw": text}}
    files = []
    for f in doc.get("files") or []:
        if isinstance(f, dict) and f.get("file_path") and f.get("code") is not None:
            files.append({"file_path": f["file_path"], "code": f["code"]})
    meta = doc.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {"notes": str(meta)}
    if repaired:
        meta["repaired_escapes"] = True
    if not files:
        meta.setdefault("parse_error", "no files in the JSON object")
        meta.setdefault("raw_tail", text[-800:])
    return {"files": files, "metadata": meta}


def make_openai_adapter(config_path: Optional[str] = None,
                        model: Optional[str] = None,
                        temperature: float = 0.0,
                        max_tokens: int = 64000,
                        retries: int = 4,
                        timeout: int = 900,
                        profile: Optional[TaskProfile] = None,
                        resolved_config: Optional[dict] = None) -> Adapter:
    """Single-shot generation over an OpenAI-compatible endpoint.

    `max_tokens` has to cover REASONING tokens, not just the answer.  On a
    reasoning model the two share one budget: a measured sweep at
    max_tokens=16000 returned `completion_tokens: 16001` with
    `reasoning_tokens: 13314` — the model thought for 13k tokens and its
    visible answer was then cut mid-string, which the harness scored as the
    system failing to produce output.  It did not fail; the cap did.  That
    was 12 of 100 items, so the default is now high enough that the cap is
    not what decides the result.

    A truncated reply is also RETRIED, which it previously was not: the
    retry loop only caught transport exceptions, and a cut-off reply is a
    perfectly successful HTTP 200 whose body does not parse.
    """
    import urllib.error
    import urllib.request

    cfg = (dict(resolved_config) if resolved_config is not None
           else resolve_llm_config(config_path, model))
    prof = _profile(profile)
    from ..data.profile import refuse_source_view
    refuse_source_view(prof, "single-shot adapter")
    # The canonical system prompt identifies the saved profile on the run
    # stamp. Kapua resolves a suite-specific submission path per item and
    # records that actual system prompt's digest in the item metadata.
    sys_prompt = system_prompt(prof)

    def run(task: dict) -> dict:
        from ..data.profile import profile_for_item
        item_prof = profile_for_item(prof, task)
        item_sys_prompt = (system_prompt(item_prof)
                           if item_prof is not prof else sys_prompt)
        url = cfg["base_url"].rstrip("/") + "/chat/completions"
        last = None
        cap = max_tokens
        for attempt in range(retries):
            payload = {
                "model": cfg["model"],
                "temperature": temperature,
                "max_tokens": cap,
                "messages": [
                    {"role": "system", "content": item_sys_prompt},
                    {"role": "user", "content": build_user_prompt(task, item_prof)},
                ],
            }
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode(), method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {cfg['api_key']}"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    doc = json.loads(resp.read().decode("utf-8", "replace"))
                choice = (doc.get("choices") or [{}])[0]
                text = choice["message"]["content"]
                usage = doc.get("usage") or {}
                finish = choice.get("finish_reason")
                out = parse_model_output(text)
                out["metadata"].update({
                    "model": cfg["model"], "usage": usage,
                    "attempt": attempt + 1, "finish_reason": finish,
                    "max_tokens": cap, "response_chars": len(text or "")})
                if item_prof is not prof:
                    out["metadata"]["system_prompt_digest"] = _hl.sha256(
                        item_sys_prompt.encode("utf-8")).hexdigest()
                # Distinguish "the model produced malformed JSON" from "we cut
                # it off": only the latter is worth spending another call on,
                # and it is recorded either way so the run file can tell them
                # apart without re-deriving it from token counts.
                truncated = (finish == "length"
                             or usage.get("completion_tokens", 0) >= cap)
                if out["metadata"].get("parse_error") and truncated:
                    out["metadata"]["truncated"] = True
                    last = f"truncated at {cap} tokens"
                    cap = min(cap * 2, 128000)
                    continue
                return out
            except Exception as e:                    # noqa: BLE001
                last = f"{type(e).__name__}: {e}"
                time.sleep(min(30, 2 ** attempt))
        return {"files": [], "metadata": {"error": last, "model": cfg["model"],
                                          "attempts_exhausted": retries}}

    import hashlib as _hl
    return Adapter(f"openai:{cfg['model']}", run,
                   {"model": cfg["model"], "profile": prof.path,
                    "prompt_digest": _hl.sha256(
                        sys_prompt.encode("utf-8")).hexdigest()})


def agent_repo_paths(condition: str,
                     profile: Optional[TaskProfile] = None) -> tuple:
    """What each condition's agent may read (SPEC_C3_PARALLEL §2.1).

    **C1.5 is the masked-repository arm**, and it exists because v1's claim
    that "C1->C2 isolates repository access" is false: C1 is single-shot
    while C2 is multi-turn with shell tools, context accumulation, its own
    stopping policy, a different effective token budget and a forced-write
    turn.  Five things differ, so their difference measures none of them.
    C1.5 is the same agent, the same tools and the same budget with an EMPTY
    repository, so C1.5->C2 differs in exactly one thing and is the
    repository-access ablation.

    Refuses an unknown label rather than serving C2's paths for it: this is
    the function that decides whether the agent gets a repository at all, so
    a silent fallback here turns a mistyped C1.5 run into a C2 run wearing
    C1.5's name -- the one confusion that would invalidate the ablation the
    arm exists to make.
    """
    if _agent_condition(condition) == "c1.5":
        return ()
    return tuple(_profile(profile).readable_paths)

#: The budget the BOUNDED canonical C3 rendering names.
#:
#: Still 5, and still fixed for the same reason as the client name — but no
#: longer the default `canonical_prompt` renders. The shipped C3 arm is
#: unbounded (see `trial_clause`), so `prompt_digest.c3` freezes the unbounded
#: wording and this constant is what reproduces the BOUNDED wording: rendered
#: with it, the c3 prompt is byte-for-byte the one the C3 sweeps on disk were
#: generated with, which `selftest` asserts against the digest the profiles
#: used to carry. A `--trials k` run is therefore still a frozen, attributable
#: configuration rather than an unpinned variant.
CANONICAL_TRIALS = 5


#: What a redacted secret is replaced with.  A fixed-width marker rather than
#: deletion, so a reader of a trajectory can see that something WAS there.
_REDACTED = "[REDACTED]"

#: Below this length a "secret" is more likely to be a substring of ordinary
#: text than a credential, and blanket-replacing it would corrupt the
#: trajectory it is supposed to protect.
_MIN_SECRET_LEN = 8


def selftest() -> int:
    """The LLM config, the repository ablation and the output parser; the
    prompt itself is `prompt.selftest`'s subject."""
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    llm_env = {k: os.environ.pop(k, None) for k in (
        "R2T_LLM_BASE_URL", "R2T_LLM_API_KEY", "R2T_LLM_MODEL")}
    try:
        with tempfile.TemporaryDirectory() as config_dir:
            config_path = os.path.join(config_dir, "llm_config.json")
            with open(config_path, "w", encoding="utf-8") as fh:
                json.dump({"base_url": "http://model.invalid/v1",
                           "api_key": "fixture-key", "model": "model-a"}, fh)
            cfg = resolve_llm_config(config_path)
            check("the configured model resolves as the execution identity",
                  cfg["model"] == "model-a", str(cfg))
            try:
                resolve_llm_config(config_path, "model-b")
                conflict = ""
            except SystemExit as exc:
                conflict = str(exc)
            check("a conflicting explicit model refuses before execution",
                  "conflicts" in conflict and "model-a" in conflict,
                  conflict)
    finally:
        for key, value in llm_env.items():
            if value is not None:
                os.environ[key] = value

    # The two profiles the ablation below is checked against; the prompts
    # themselves are `prompt.selftest`'s subject.
    from ..data.profile import DEFAULT_PROFILE_PATH, load_profile
    from ..data.prompt import agent_prompt_for
    coreshop = load_profile(DEFAULT_PROFILE_PATH)
    behave = load_profile(os.path.join(CONFIG_DIR,
                                       "profile_behave_example.yml"))
    # The C1.5/C2 ablation is profile-driven now, so it has to hold for a
    # profile that is not CoreShop's as well.
    check("the second profile keeps the C1.5-vs-C2 repository ablation",
          agent_repo_paths("c1.5", behave) == ()
          and agent_repo_paths("c2", behave) == agent_repo_paths("c3", behave)
          and agent_repo_paths("c2", behave) != agent_repo_paths("c2", coreshop)
          and len(agent_repo_paths("c2", behave)) > 0)

    # An unrecognised condition is a MISTAKE, and both of these used to answer
    # it with C2 — the prompt builder AND the seed builder. `--condition c1_5`
    # would then have run C2's prompt over C2's repository and stamped every
    # row `c1_5`: a run file asserting an ablation that was never performed.
    for bad in ("c1_5", "C4", "c1.5 ", "", None):
        for fname, fn in (("agent_prompt_for", agent_prompt_for),
                          ("agent_repo_paths", agent_repo_paths)):
            try:
                fn(bad)
                raised = ""
            except ValueError as e:
                raised = str(e)
            check(f"{fname}({bad!r}) is refused, not read as c2",
                  "valid conditions" in raised and repr(bad) in raised, raised)
    # ... and every label that IS valid still works, case included, because a
    # refusal that also refused `C3` would be its own outage.
    for good in ("c1.5", "c2", "c3", "C3"):
        try:
            agent_prompt_for(good)
            agent_repo_paths(good)
            accepted = True
        except ValueError as e:
            accepted = str(e)
        check(f"{good!r} is still a valid condition", accepted is True,
              str(accepted))
    check("C1.5 is the arm with no repository, and C2/C3 the arm with one",
          agent_repo_paths("c1.5") == ()
          and agent_repo_paths("c2") == agent_repo_paths("c3")
          and len(agent_repo_paths("c2")) > 0)

    # The seed each condition is given must match what its prompt claims.

    # Escaping: the PHP the model must return lives inside a JSON string.
    doc = parse_model_output('{"files": [{"file_path": "a.php", '
                             '"code": "<?php namespace CoreShop\\Behat;"}]}')
    check("a bare PHP namespace backslash is repaired, not scored as a failure",
          doc["files"] and "CoreShop" in doc["files"][0]["code"])

    print("\n" + ("ALL PASS (adapters)" if ok else "FAILURES (adapters)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
