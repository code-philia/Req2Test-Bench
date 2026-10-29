"""Confinement for the two namespaces that run code we did not write.

The threat model is not hypothetical, it is the state of the benchmark as
measured:

* **The agent is a host process.**  It runs as the coordinator's own user,
  with `gold/` readable at mode 775 beside it, the generation caches readable,
  and `closures.json` readable.  Nothing stops it reading the answer to the
  item it is being scored on; nothing would record that it had.
* **Submitted code is root inside the executor**, on a read-write bind mount,
  with `disable_functions` empty.  §2.5 measured that `gold/` is *not*
  currently mounted there — but v1's plan to share it read-only across
  workers would have *introduced* that exposure, and the code could then have
  returned an answer through the permitted stdout/exception channel.

Two things this module refuses to do.  It does not call trajectory auditing
confinement: auditing detects some violations after the fact, and after the
fact is after the score.  And it does not report a boundary as held unless a
probe **executed inside that namespace** failed to cross it — a mount list
read by the coordinator says what Docker was asked for, not what the process
can reach.

`certify()` aggregates the evidence.  It returns a verdict, and every property
that is declared but not enforced here is listed by name in `unenforced`, so a
result can never quietly inherit the word "confined" for a boundary nobody
built.

WHAT IS HERE AND WHAT IS NOT.  This module declares both namespaces, probes
them and certifies the answers, and it reports whether this host can create a
namespace at all (`bwrap_available`, `bwrap_probe`) -- the two questions the
benchmark's own consumer route asks.  BUILDING the agent's sandbox is agent
code and lives in `r2t.agents.sandbox`: the consumer route never launches an
agent, so nothing here imports it.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from ..docker_authority import AMBIENT_DOCKER_KEYS

#: A docker network created `--internal` has no route off the host, so a
#: container attached only to it cannot reach the internet — enforced by the
#: kernel's routing table rather than by an environment variable a process is
#: free to ignore.  The database container is attached to it as well, which is
#: the executor's only legitimate correspondent.
INTERNAL_NETWORK = "coreshop_bench_internal"

class NotConfined(RuntimeError):
    pass


@dataclass
class NamespaceSpec:
    """What must be true of a namespace, stated before it is probed.

    Written down as data because "we confined the agent" is not a claim
    anybody can check, while "these eleven paths were unreadable and this
    host was unreachable, probed from inside" is.
    """

    name: str
    #: Paths that must NOT be readable from inside.  The answer, in all its
    #: copies.
    forbidden_paths: list[str] = field(default_factory=list)
    #: Hosts that must NOT be reachable.  Egress.
    forbidden_hosts: list[str] = field(default_factory=list)
    #: The one host that must remain reachable, so a total failure to reach
    #: anything is not mistaken for a boundary.
    control_host: Optional[str] = None
    #: Environment variable NAMES that must be absent inside.  Values are
    #: never read or printed.
    forbidden_env: list[str] = field(default_factory=list)
    #: Exact host-client paths that must not remain executable after broader
    #: interpreter/library binds (notably /usr) are masked in the agent.
    forbidden_executables: list[str] = field(default_factory=list)
    #: Properties this module declares but cannot enforce here.
    unenforced: list[str] = field(default_factory=list)


#: Environment that would hand a namespace the coordinator's own keys.
COORDINATOR_ENV = tuple(dict.fromkeys((
    "R2T_LLM_API_KEY", "R2T_LLM_BASE_URL", "AWS_SECRET_ACCESS_KEY",
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", *AMBIENT_DOCKER_KEYS,
)))

#: Paths that must be unreachable from an EXECUTOR.  The DSN is legitimately
#: in its environment — that is what it executes against — so the executor's
#: forbidden-env list is shorter than the agent's.
_DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")


def _authority_confinement_paths() -> tuple[list[str], list[str]]:
    """Return ordinary forbidden paths and exact clients to mask/probe."""
    from ..core import docker_cli as D
    all_paths = list(D.authority_protected_paths())
    clients = list(D.selected_client_paths())
    ordinary = [path for path in all_paths if path not in clients]
    return ordinary, clients


def executor_spec(answer_paths: list[str], other_workspaces: list[str],
                  db_host: Optional[str] = "coreshop_db:3306") -> NamespaceSpec:
    """The executor reaches its own database and nothing else.

    `db_host` is the control, not a permission: the executor MUST be able to
    open it, and a probe where even that fails is a container that cannot
    connect to anything — which would otherwise be indistinguishable from an
    egress boundary that works.
    """
    authority_paths, _clients = _authority_confinement_paths()
    return NamespaceSpec(
        name="executor",
        forbidden_paths=list(answer_paths) + list(other_workspaces)
        + list(_DOCKER_SOCKETS) + authority_paths,
        forbidden_hosts=["1.1.1.1:443", "8.8.8.8:53", "example.com:443"],
        control_host=db_host,
        forbidden_env=list(COORDINATOR_ENV),
        unenforced=[],
    )


def agent_spec(answer_paths: list[str]) -> NamespaceSpec:
    authority_paths, clients = _authority_confinement_paths()
    return NamespaceSpec(
        name="agent",
        forbidden_paths=list(answer_paths) + list(_DOCKER_SOCKETS)
        + authority_paths,
        # The agent gets the key by a mechanism it cannot enumerate — the
        # driver pops it out of its own environment before starting the
        # agent — so the NAME being absent inside is the checkable property.
        forbidden_env=[e for e in COORDINATOR_ENV if e != "R2T_LLM_BASE_URL"],
        forbidden_executables=clients,
    )


# --------------------------------------------------------------- probes
#: One POSIX shell script, so that the same questions are asked of a container
#: and of a sandboxed host process.  It reports; it does not decide.
#:
#: The reachability test is deliberately not `/dev/tcp`: that is a bash
#: feature and the executor's shell is BusyBox `ash`, where every host would
#: have come back unreachable — which reads exactly like perfect egress
#: confinement.  Three mechanisms are tried in turn and the one that worked is
#: reported, so a namespace with none of them is a BROKEN probe rather than a
#: clean result.
#:
#: `bash` is detected with `command -v`, not with `$BASH_VERSION`: the probe is
#: invoked through `/bin/sh`, so the variable is unset even where bash exists,
#: and the bwrap-sandboxed agent namespace duly reported "no way to open a
#: socket" while `/usr/bin/bash` sat inside it.
PROBE_SH = r"""
set -u
_method=none
if command -v nc >/dev/null 2>&1; then _method=nc
elif command -v python3 >/dev/null 2>&1; then _method=python3
elif command -v php >/dev/null 2>&1; then _method=php
elif command -v bash >/dev/null 2>&1; then _method=devtcp
fi
_connect() {
  case "$_method" in
    nc) nc -z -w 3 "$1" "$2" >/dev/null 2>&1 ;;
    python3) python3 -c 'import socket,sys
socket.create_connection((sys.argv[1], int(sys.argv[2])), 3).close()' "$1" "$2" >/dev/null 2>&1 ;;
    php) php -r 'exit(@fsockopen($argv[1],(int)$argv[2],$e,$s,3)?0:1);' "$1" "$2" >/dev/null 2>&1 ;;
    devtcp) bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$1" "$2" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
printf '{'
printf '"paths":{'
first=1
for p in %(paths)s; do
  [ $first -eq 1 ] || printf ','
  first=0
  if [ -r "$p" ]; then st=readable; elif [ -e "$p" ]; then st=present; else st=absent; fi
  printf '"%%s":"%%s"' "$p" "$st"
done
printf '},"env":{'
first=1
for k in %(env)s; do
  [ $first -eq 1 ] || printf ','
  first=0
  v=$(eval "printf '%%s' \"\${$k:-}\"")
  if [ -n "$v" ]; then printf '"%%s":true' "$k"; else printf '"%%s":false' "$k"; fi
done
printf '},"executables":{'
first=1
for p in %(executables)s; do
  [ $first -eq 1 ] || printf ','
  first=0
  if [ -x "$p" ]; then printf '"%%s":true' "$p";
  else printf '"%%s":false' "$p"; fi
done
printf '},"hosts":{'
first=1
for hp in %(hosts)s; do
  [ $first -eq 1 ] || printf ','
  first=0
  h=${hp%%:*}; pt=${hp##*:}
  if _connect "$h" "$pt"; then printf '"%%s":true' "$hp";
  else printf '"%%s":false' "$hp"; fi
done
printf '},"connect_method":"%%s"' "$_method"
printf ',"pids":%%s' "$(ls /proc 2>/dev/null | grep -c '^[0-9]*$' || echo 0)"
printf '}\n'
"""


def build_probe(spec: NamespaceSpec) -> str:
    hosts = list(spec.forbidden_hosts) + (
        [spec.control_host] if spec.control_host else [])
    return PROBE_SH % {
        "paths": " ".join(shlex.quote(p) for p in spec.forbidden_paths),
        "env": " ".join(shlex.quote(e) for e in spec.forbidden_env),
        "executables": " ".join(
            shlex.quote(p) for p in spec.forbidden_executables),
        "hosts": " ".join(shlex.quote(h) for h in hosts),
    }


def probe(spec: NamespaceSpec, run: Callable[[str], str]) -> dict:
    """Ask the namespace about itself, from inside it.

    `run` executes a shell script *there* and returns its stdout — a
    `DockerRunner.run` for a container, a `bwrap` invocation for a sandboxed
    host process.  One probe, two namespaces, so a boundary cannot be checked
    thoroughly in one and loosely in the other.
    """
    raw = run(build_probe(spec))
    start = raw.find("{")
    if start < 0:
        raise NotConfined(
            f"the {spec.name} probe produced no JSON, so nothing about that "
            f"namespace has been established: {raw[-400:]!r}")
    return json.loads(raw[start:])


def verdict(spec: NamespaceSpec, doc: dict) -> dict:
    """Turn one probe's answers into a pass or a named list of failures.

    A host-bearing spec whose shell has no supported TCP client would report
    every host unreachable, which would read as perfect executor egress
    confinement.  That is why `control_host` exists: when one is declared and
    it is NOT reachable, the probe is treated as broken rather than as a pass.
    A spec that declares no hosts makes no network claim, so the availability
    of a TCP client has no bearing on its verdict.
    """
    expected_fields = {"paths", "env", "executables", "hosts",
                       "connect_method", "pids"}
    failures = []
    if not isinstance(doc, dict):
        failures.append("the probe result is not a JSON object")
        doc = {}

    missing_fields = sorted(expected_fields - set(doc))
    unexpected_fields = sorted(set(doc) - expected_fields)
    if missing_fields:
        failures.append(f"probe fields missing: {missing_fields}")
    if unexpected_fields:
        failures.append(f"unexpected probe fields: {unexpected_fields}")

    dimensions = {}
    for field_name in ("paths", "env", "executables", "hosts"):
        value = doc.get(field_name)
        if not isinstance(value, dict):
            failures.append(f"probe field {field_name} is not an object")
            value = {}
        dimensions[field_name] = value
    paths = dimensions["paths"]
    env = dimensions["env"]
    executables = dimensions["executables"]
    hosts = dimensions["hosts"]

    expected_keys = {
        "paths": set(spec.forbidden_paths),
        "env": set(spec.forbidden_env),
        "executables": set(spec.forbidden_executables),
        "hosts": set(spec.forbidden_hosts)
        | ({spec.control_host} if spec.control_host is not None else set()),
    }
    for field_name, values in dimensions.items():
        missing = sorted(expected_keys[field_name] - set(values))
        unexpected = sorted(set(values) - expected_keys[field_name])
        if missing:
            failures.append(
                f"probe field {field_name} is missing declared keys: {missing}")
        if unexpected:
            failures.append(
                f"probe field {field_name} has unexpected keys: {unexpected}")

    invalid_paths = sorted(
        path for path, state in paths.items()
        if state not in ("absent", "present", "readable"))
    invalid_env = sorted(key for key, present in env.items()
                         if type(present) is not bool)
    invalid_executables = sorted(
        path for path, executable in executables.items()
        if type(executable) is not bool)
    invalid_hosts = sorted(host for host, reachable in hosts.items()
                           if type(reachable) is not bool)
    if invalid_paths:
        failures.append(f"invalid path states for: {invalid_paths}")
    if invalid_env:
        failures.append(f"non-boolean environment answers for: {invalid_env}")
    if invalid_executables:
        failures.append(
            f"non-boolean executable answers for: {invalid_executables}")
    if invalid_hosts:
        failures.append(f"non-boolean host answers for: {invalid_hosts}")

    method = doc.get("connect_method")
    if method not in {"none", "nc", "python3", "php", "devtcp"}:
        failures.append("probe field connect_method is missing or invalid")
    pids = doc.get("pids")
    if type(pids) is not int or pids < 0:
        failures.append(
            "probe field pids is missing or not a nonnegative integer")

    readable = sorted(p for p, st in paths.items() if st == "readable")
    present = sorted(p for p, st in paths.items()
                     if st == "present" and p not in readable)
    leaked_env = sorted(k for k, v in env.items() if v)
    exposed_clients = sorted(
        path for path in spec.forbidden_executables
        if executables.get(path) is True)
    reachable = sorted(h for h in spec.forbidden_hosts if hosts.get(h))
    control_ok = True
    if spec.control_host is not None:
        control_ok = bool(hosts.get(spec.control_host))
    if ((spec.forbidden_hosts or spec.control_host is not None)
            and method == "none"):
        failures.append(
            "the namespace has no way to open a TCP connection at all "
            "(no nc, python3, php, or bash), so every 'unreachable' below "
            "is an absent tool rather than a boundary")
    if readable:
        failures.append(f"readable answer-bearing paths: {readable}")
    if present:
        failures.append(f"paths that exist but are unreadable — a mount that "
                        f"should not be there at all: {present}")
    if leaked_env:
        failures.append(f"coordinator environment present: {leaked_env}")
    if exposed_clients:
        failures.append(
            f"selected Docker client remains executable: {exposed_clients}")
    if reachable:
        failures.append(f"egress to {reachable}")
    if not control_ok:
        failures.append(
            f"the control host {spec.control_host} was unreachable too, so "
            f"the egress result is not evidence — the probe could not open a "
            f"socket at all")
    return {"namespace": spec.name, "pass": not failures,
            "failures": failures, "unenforced": list(spec.unenforced),
            "n_paths_checked": len(paths), "pids_visible": pids,
            "connect_method": method,
            "control_host_reachable": control_ok if spec.control_host else None}


def certify(verdicts: list[dict], expected: Optional[Iterable[str]] = None) -> dict:
    """The aggregate certificate — fail closed on what was NOT probed.

    A namespace with an unenforced property is NOT certified, however clean
    its probe.  `unenforced` exists so that "we did not build this" survives
    into the result file instead of being remembered by whoever wrote the
    code.

    `expected` is the fix for the hole a review found: the first version
    declared success when none of the namespaces it *happened to receive* had
    failed, so `certify([])` returned `certified: true` — a green certificate
    for probing nothing — and `confine --k 4` without `--agent` issued one
    that omitted the single most security-sensitive namespace.  A
    certification now names, in advance, the namespaces it must see, and an
    absent one fails exactly like a breached one.
    """
    seen = {v["namespace"] for v in verdicts}
    failing = [v for v in verdicts if not v["pass"]]
    unenforced = sorted({u for v in verdicts for u in v.get("unenforced") or []})
    missing = sorted(set(expected or ()) - seen)
    unexpected = sorted(seen - set(expected)) if expected is not None else []
    if expected is None and not verdicts:
        # No expectation AND no evidence: there is nothing here to certify.
        missing = ["<nothing was probed>"]
    return {
        "certified": (not failing and not unenforced and not missing
                      and not unexpected),
        "namespaces": {v["namespace"]: v for v in verdicts},
        "failing": [v["namespace"] for v in failing],
        "not_probed": missing,
        "unexpected": unexpected,
        "unenforced": unenforced,
    }


# ------------------------------------------------------- executor plumbing
def _docker(argv: list[str], docker_group: bool = True,
            timeout: int = 300) -> subprocess.CompletedProcess:
    from ..core.docker_cli import docker_command
    cmd = docker_command(argv, docker_group=docker_group)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def ensure_internal_network(name: str = INTERNAL_NETWORK,
                            attach: tuple = ("coreshop_db",),
                            docker_group: bool = True) -> dict:
    """An egress-free network the executor can still reach the database on.

    This is the one confinement property that can be enforced without
    touching the host's firewall: `--internal` removes the network's route to
    the outside, and attaching the database container to it as a SECOND
    network keeps the executor's only legitimate correspondent reachable
    without giving the database's own clients a new path.
    """
    cp = _docker(["network", "inspect", name, "--format", "{{.Internal}}"],
                 docker_group=docker_group)
    if cp.returncode != 0:
        created = _docker(["network", "create", "--internal", name],
                          docker_group=docker_group)
        if created.returncode != 0:
            raise NotConfined(f"could not create {name}: "
                              f"{(created.stderr or '')[-300:]}")
    elif (cp.stdout or "").strip() != "true":
        raise NotConfined(
            f"REFUSED: the network {name} already exists and is NOT internal, "
            f"so attaching a worker to it would not confine anything. Remove "
            f"it, or use a different name.")
    attached = []
    for container in attach:
        cp = _docker(["network", "connect", name, container],
                     docker_group=docker_group)
        # "already exists in network" is the steady state, not an error.
        ok = cp.returncode == 0 or "already exists" in (cp.stderr or "")
        attached.append({"container": container, "ok": ok,
                         "error": None if ok else (cp.stderr or "")[-200:]})
    return {"network": name, "internal": True, "attached": attached}


def bwrap_available() -> bool:
    from shutil import which
    return which("bwrap") is not None


def bwrap_probe() -> dict:
    """Report whether bubblewrap can create the namespace agents need.

    Finding the executable is not enough: hosts with user namespaces disabled
    have a perfectly ordinary ``bwrap --version`` and refuse the first real
    invocation.  The probe creates a short-lived PID namespace and runs
    ``/bin/true`` inside it; it neither binds benchmark data nor changes the
    host.
    """
    if not bwrap_available():
        return {"usable": False, "version": None,
                "error": "bwrap is not installed"}
    try:
        version = subprocess.run(
            ["bwrap", "--version"], capture_output=True, text=True,
            timeout=10)
        attempted = subprocess.run(
            ["bwrap", "--ro-bind", "/", "/", "--unshare-pid",
             "--new-session", "/bin/true"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"usable": False, "version": None, "error": str(e)}
    version_text = (version.stdout or version.stderr or "").strip() or None
    error = (attempted.stderr or attempted.stdout or "").strip()
    return {"usable": attempted.returncode == 0, "version": version_text,
            "error": error[-400:] if attempted.returncode else ""}


def selftest() -> int:
    """The verdict logic and the certificate, without a container.

    What is deliberately NOT selftested is whether a real namespace holds:
    that is what the probes are for, and asserting it here from the
    coordinator's side would be exactly the mistake §3.12 names.
    """
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    spec = executor_spec(["/gold", "/artifacts/closures.json"],
                         ["/workers/worker1/app"])
    script = build_probe(spec)
    check("the probe asks about every forbidden path by name",
          all(p in script for p in spec.forbidden_paths))
    check("the probe asks about the docker socket",
          "/var/run/docker.sock" in script)
    check("the probe reads env NAMES, never values, into its output",
          '"%s":true' in script and "printf '%s' \\\"\\${$k:-}\\\"" in script)
    check("all Docker client selector names are stripped from untrusted "
          "namespaces",
          set(AMBIENT_DOCKER_KEYS) <= set(COORDINATOR_ENV))
    empty = NamespaceSpec(name="empty")
    empty_doc = probe(empty, lambda probe_script: subprocess.run(
        ["/bin/sh", "-c", probe_script], capture_output=True, text=True,
        check=True).stdout)
    check("an empty probe dimension stays empty instead of probing an empty name",
          empty_doc["paths"] == {} and empty_doc["env"] == {}
          and empty_doc["hosts"] == {})

    clean = {"paths": {p: "absent" for p in spec.forbidden_paths},
             "env": {e: False for e in spec.forbidden_env},
             "executables": {
                 p: False for p in spec.forbidden_executables},
             "hosts": {**{h: False for h in spec.forbidden_hosts},
                       spec.control_host: True},
             "connect_method": "nc", "pids": 3}
    check("a namespace that reaches nothing forbidden passes",
          verdict(spec, clean)["pass"], str(verdict(spec, clean)["failures"]))

    leaky = json.loads(json.dumps(clean))
    leaky["paths"]["/gold"] = "readable"
    check("a readable gold tree fails",
          not verdict(spec, leaky)["pass"]
          and "/gold" in verdict(spec, leaky)["failures"][0])

    mounted = json.loads(json.dumps(clean))
    mounted["paths"]["/artifacts/closures.json"] = "present"
    check("a forbidden path that merely EXISTS also fails",
          not verdict(spec, mounted)["pass"])

    keyed = json.loads(json.dumps(clean))
    keyed["env"]["R2T_LLM_API_KEY"] = True
    check("the coordinator's api key present inside fails",
          not verdict(spec, keyed)["pass"])

    out = json.loads(json.dumps(clean))
    out["hosts"]["1.1.1.1:443"] = True
    check("egress to an arbitrary host fails",
          not verdict(spec, out)["pass"])

    noshell = json.loads(json.dumps(clean))
    noshell["connect_method"] = "none"
    noshell["hosts"] = {h: False for h in noshell["hosts"]}
    check("a namespace with no way to open a socket is a BROKEN probe",
          not verdict(spec, noshell)["pass"]
          and "absent tool" in " ".join(verdict(spec, noshell)["failures"]))

    aspec = agent_spec(["/gold"])
    aclean = {"paths": {"/gold": "absent",
                        **{s: "absent" for s in _DOCKER_SOCKETS}},
              "env": {e: False for e in aspec.forbidden_env},
              "executables": {
                  p: False for p in aspec.forbidden_executables},
              "hosts": {}, "connect_method": "none", "pids": 3}
    check("the agent certificate declares no outbound-host property",
          not aspec.forbidden_hosts and aspec.control_host is None
          and not aspec.unenforced)

    check("a host-free agent spec needs no TCP client to clear its probe",
          verdict(aspec, aclean)["pass"],
          str(verdict(aspec, aclean)["failures"]))

    missing_path = json.loads(json.dumps(aclean))
    del missing_path["paths"]["/gold"]
    check("an omitted declared path makes the agent probe BROKEN",
          not verdict(aspec, missing_path)["pass"]
          and "/gold" in " ".join(verdict(aspec, missing_path)["failures"]))

    missing_env = json.loads(json.dumps(aclean))
    missing_env_key = aspec.forbidden_env[0]
    del missing_env["env"][missing_env_key]
    check("an omitted declared environment name makes the probe BROKEN",
          not verdict(aspec, missing_env)["pass"]
          and missing_env_key in " ".join(
              verdict(aspec, missing_env)["failures"]))

    missing_pids = json.loads(json.dumps(aclean))
    del missing_pids["pids"]
    check("an omitted process count makes the agent probe BROKEN",
          not verdict(aspec, missing_pids)["pass"]
          and "pids" in " ".join(verdict(aspec, missing_pids)["failures"]))

    malformed = json.loads(json.dumps(clean))
    malformed["paths"]["/gold"] = []
    malformed["env"][spec.forbidden_env[0]] = "false"
    malformed["hosts"][spec.forbidden_hosts[0]] = 0
    malformed["connect_method"] = "curl"
    malformed["pids"] = True
    malformed_failures = " ".join(verdict(spec, malformed)["failures"])
    check("invalid probe answer types cannot produce a certificate",
          not verdict(spec, malformed)["pass"]
          and all(field in malformed_failures for field in (
              "/gold", spec.forbidden_env[0], spec.forbidden_hosts[0],
              "connect_method", "pids")))

    cert = certify([verdict(spec, clean), verdict(aspec, aclean)],
                   expected=["executor", "agent"])
    check("clean executor and agent probes produce a certification",
          cert["certified"] and not cert["unenforced"], json.dumps(cert)[:300])
    check("a fully-enforced namespace certifies when it is the one expected",
          certify([verdict(spec, clean)], expected=["executor"])["certified"])
    check("one failing namespace is named in the certification",
          certify([verdict(spec, leaky)], expected=["executor"])["failing"]
          == ["executor"])
    # The hole a review found: certifying nothing used to pass.
    check("certifying NOTHING is refused, not passed",
          not certify([])["certified"]
          and certify([])["not_probed"] == ["<nothing was probed>"])
    check("a namespace that was expected but not probed fails",
          not certify([verdict(spec, clean)],
                      expected=["executor", "agent"])["certified"]
          and certify([verdict(spec, clean)],
                      expected=["executor", "agent"])["not_probed"] == ["agent"])
    check("a namespace nobody expected is refused rather than absorbed",
          not certify([verdict(spec, clean)], expected=["agent"])["certified"]
          and certify([verdict(spec, clean)],
                      expected=["agent"])["unexpected"] == ["executor"])

    bwrap = bwrap_probe()
    check("bubblewrap can create a process namespace",
          bwrap["usable"], bwrap.get("error") or "bubblewrap is unusable")
    print("\n" + ("ALL PASS (confine)" if ok else "FAILURES (confine)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
