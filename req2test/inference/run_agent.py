"""Run a command-line agent on exported tasks and write its predictions.

    export DEEPSEEK_API_KEY=...
    python3 -m req2test.inference.run_agent --agent codex \\
        --model deepseek/deepseek-flash \\
        --tasks ~/r2t-work/tasks.jsonl -o ~/r2t-work/codex-deepseek

writes `~/r2t-work/codex-deepseek/predictions.jsonl` with Codex CLI and
DeepSeek-V4.1-Flash at high reasoning effort, as in the leaderboard's first
row. Any other
command-line agent that reads the prompt on standard input runs with its own
command line after `--`, for example

    python3 -m req2test.inference.run_agent --tasks ~/r2t-work/tasks.jsonl \\
        -o ~/r2t-work/my-agent --env MY_API_KEY --allow api.example.com -- my-agent

For each task, `--workers` at a time, it materializes the instance's source
view into a new workspace `<output-dir>/workspaces/<NNNN>/repo`, sets up the
runtime pack there, runs the agent from the workspace in a bubblewrap sandbox
with the task's prompt (`req2test.inference.prompt`) on standard input, and
appends one row to `<output-dir>/predictions.jsonl` for the files the agent
created or changed under `repo/`. An agent that exits non-zero, for example on a provider error,
gets no row. A rerun skips the instances already in the predictions and retries
the others from a new workspace. Once the row is written, the workspace and
the attempt's runtime state `<NNNN>.rt`, which hold builds and caches of up to
some hundred MB, are removed. The agent's output `<NNNN>.log` and
`<NNNN>.runs.jsonl`, the commands it ran through the runtime pack, stay. An
attempt without a row keeps its workspace until a rerun retries it.

The sandbox holds the host's system directories read-only, the workspace and the
runtime pack's binds, an empty home directory and `/tmp`, and the agent's
installation read-only: its directory on `PATH`, or the directory above it if
that is a `bin` directory (for example an npm prefix, which holds node and the
package), and the directory its executable resolves to. Add what else the
agent needs, such as a configuration file, with `--ro-bind` or `--bind`, and
pass environment variables such as API keys with `--env`. None of these binds
may hold your home directory, `$REQ2TEST_HOME`, the output directory or this
clone, which the agent must not see: keep the agent installed outside them.

As in the leaderboard's runs, the agent's shell is bash and it sees none of
the host's project toolchains (`req2test.inference.toolset`). It reaches only
the endpoints `--allow` names, through `HTTPS_PROXY`, which it must honour,
and one on this host's loopback, such as a local model server, at its own
address (`req2test.inference.egress`). `--agent codex` needs no `--allow`: it
reaches its provider through a relay that holds the API key and stops Codex at
its 201st LLM call. With `--docker IMAGE` the agent runs in a container of
IMAGE instead (docker/agent.Dockerfile is a base), to which `--bind`,
`--ro-bind` and `--env` apply. See docs/agents.md for the sandbox's
requirements and the generation protocol.
"""

import argparse
import hashlib
import http.client
import http.server
import json
import os
import posixpath
import shlex
import shutil
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from req2test import ENGINE_ROOT, REPO_ROOT, kits, packs, views
from req2test.execute import ensure_engine_path
from req2test.inference import egress, toolset
from req2test.inference.prompt import build_prompt

#: Where the agent's network directory, with `egress.py` and the proxy's
#: socket (and for `--agent codex`, its catalog and its relay's socket),
#: appears in the sandbox.
NET = "/tmp/.r2t-net"
#: The agent's proxy, and what it does not apply to: the sandbox's loopback.
PROXY_ENV = {name: f"http://127.0.0.1:{egress.PROXY_PORT}"
             for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")}
PROXY_ENV.update({name: "localhost,127.0.0.1" for name in ("NO_PROXY", "no_proxy")})

#: The protocol's budget of LLM calls per generation (docs/agents.md).
CALLS = 200
#: The providers `--agent codex` can use, as `--model PROVIDER/MODEL` with the
#: leaderboard's MODEL on each.
CODEX_PROVIDERS = {"deepseek": ("DeepSeek", "https://api.deepseek.com", "DEEPSEEK_API_KEY",
                                "deepseek-flash")}
#: The Codex model catalog of the leaderboard's runs, byte for byte (its
#: harness's `config/codex_models.json`): each model's instructions, tools
#: and context window.  Codex runs a model it has no entry for with generic
#: ones, and names every model of the catalog in its `spawn_agent` tool, so
#: all of it is part of what the model is sent.  Each attempt gets a copy in
#: its network directory.
CODEX_CATALOG = Path(__file__).resolve().parent.parent / "data" / "codex_models.json"


def codex(model: str) -> list:
    """Codex CLI's command line for `--model PROVIDER/MODEL`, as the
    leaderboard ran it: the model's catalog entry, no web search,
    multi-agent, apps, memories or hooks, no user configuration, and the
    provider through the relay (`Relay`), which holds the API key."""
    provider, _, name = model.partition("/")
    settings = ["model_reasoning_effort=high", f"model_provider={provider}",
                f'model_providers.{provider}={{name="{CODEX_PROVIDERS[provider][0]}", '
                f'base_url="http://127.0.0.1:{egress.RELAY_PORT}", wire_api="responses", '
                "requires_openai_auth=false}",
                f'model_catalog_json="{NET}/{CODEX_CATALOG.name}"', 'web_search="disabled"',
                "features.multi_agent=false", "features.apps=false",
                "features.memories=false", "features.hooks=false"]
    return (["codex", "exec", "--ephemeral", "--ignore-user-config", "--ignore-rules",
             "--model", name] + [arg for s in settings for arg in ("-c", s)]
            + ["--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check", "-"])


class Relay(socketserver.ThreadingUnixStreamServer):
    """`--agent codex`'s way to its model provider, on the unix socket
    `path`, which the bridge serves at `127.0.0.1:egress.RELAY_PORT`: each
    `POST /responses` goes on to the provider at `url` with the API `key`.
    The call after the `cap`-th gets 429 and sets `capped`, at which the
    agent is stopped, as the leaderboard's harness did.  `calls` counts the
    calls passed on."""
    daemon_threads = True

    def __init__(self, path: str, url: str, key: str, cap: int):
        super().__init__(path, _Call)
        self.url, self.key, self.cap = urlsplit(url), key, cap
        self.calls, self.capped, self.lock = 0, threading.Event(), threading.Lock()


class Proxy(socketserver.ThreadingUnixStreamServer):
    """The agent's CONNECT proxy (`egress.tunnel`) on the unix socket `path`,
    which tunnels to the `(host, port)` endpoints in `allow`.  What it
    refuses or cannot reach is appended to `notes`, complete once
    `server_close` has waited for the tunnels, which end with the agent."""
    request_queue_size = 64

    def __init__(self, path: str, allow: set):
        self.notes = []
        super().__init__(path, lambda conn, _, server: egress.tunnel(conn, allow, server.notes))

    def handle_error(self, request, client_address) -> None:
        if not isinstance(sys.exc_info()[1], OSError):     # not the agent hanging up
            super().handle_error(request, client_address)


class _Call(http.server.BaseHTTPRequestHandler):
    """One call through the `Relay`, its response passed back as it comes."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        pass

    def answer(self, status: int, message: str) -> None:
        body = json.dumps({"error": {"message": message}}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.answer(403, "only POST /responses is available")

    def do_POST(self) -> None:
        relay = self.server
        if self.path != "/responses":
            return self.answer(403, "only POST /responses is available")
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with relay.lock:
            if relay.calls >= relay.cap:
                relay.capped.set()
                return self.answer(429, f"the budget of {relay.cap} LLM calls is spent")
            relay.calls += 1
        url = relay.url
        conn = (http.client.HTTPSConnection if url.scheme == "https" else
                http.client.HTTPConnection)(url.hostname, url.port, timeout=300)
        try:
            conn.request("POST", url.path.rstrip("/") + "/responses", body, {
                "Authorization": f"Bearer {relay.key}",
                "Content-Type": "application/json", "Accept": "text/event-stream"})
            response = conn.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            conn.close()
            return self.answer(502, f"could not reach the provider: {exc}")
        try:
            self.send_response(response.status)
            self.send_header("Content-Type", response.getheader("Content-Type", ""))
            self.send_header("Connection", "close")
            self.end_headers()
            while chunk := response.read1(65536):
                self.wfile.write(chunk)
                self.wfile.flush()
        except (OSError, http.client.HTTPException):
            pass    # the agent or the provider closed the stream
        finally:
            conn.close()


def removable(project: str):
    """Whether a file of `project`, by its path under `repo/`, is test code
    that scoring takes: what the project's boundary classifies as removable.
    That holds the placement's `acceptance_root` and, on Kapua and Algorand
    SDK, reaches beyond it."""
    ensure_engine_path()
    from r2t.core.boundary import REMOVABLE, load_boundary
    # The engine's copy, which the project's views were cut by.
    name = posixpath.basename(views.recipe_inputs(project).provenance["boundary"])
    boundary = load_boundary(str(ENGINE_ROOT / "config" / name))
    return lambda rel: boundary.classify(rel) == REMOVABLE


def answers(pl: dict, rel: str, removable) -> bool:
    """Whether the file `rel`, under `repo/`, is part of the answer, as the
    leaderboard's runs collected it: named in the row's placement
    `extra_names`, or with one of its `suffixes` where `removable` (the
    project's `removable`) holds."""
    if posixpath.basename(rel) in pl["extra_names"]:
        return True
    return rel.endswith(tuple(pl["suffixes"])) and removable(rel)


def snapshot(repo: Path, pl: dict, removable) -> dict:
    """The hashes of the files under `repo` that `answers` takes, and of the
    feature files; none if the agent replaced `repo` with a link."""
    if repo.is_symlink() or not repo.is_dir():
        return {}
    hashes = {}
    for p in repo.rglob("*"):
        rel = p.relative_to(repo).as_posix()
        if ((answers(pl, rel, removable) or rel.endswith(".feature"))
                and p.is_file() and not p.is_symlink()):
            hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return hashes


def prediction(task: dict, repo: Path, before: dict, model: str, removable) -> dict:
    """The files the agent created or changed under `repo/` that are part of
    the answer (`answers`), and the view's feature files it changed
    (docs/agents.md, "Collecting the answer")."""
    pl = task["placement"]
    after, files = snapshot(repo, pl, removable), []
    for rel in sorted(after):
        if after[rel] == before.get(rel):
            continue
        if not answers(pl, rel, removable) and rel not in before:
            continue    # a feature file a build copied, not one the agent edited
        try:
            files.append({"path": rel, "content": (repo / rel).read_text(encoding="utf-8")})
        except UnicodeDecodeError:
            continue
    return {"instance_id": task["instance_id"], "model_name_or_path": model,
            "view": task["view"], "files": files}


def remove(path: Path) -> None:
    """Remove an earlier attempt's directory, read-only directories included."""
    if path.exists():
        subprocess.run(["chmod", "-R", "u+rwX", str(path)])
        shutil.rmtree(path)


def predicted(out: Path) -> set:
    """The instances that the predictions file `out` has rows for.  A run
    stopped while appending a row leaves it cut off: the row is dropped, so
    that its instance runs again and the next row starts a line."""
    if not out.exists():
        return set()
    rows = out.read_text()
    if rows and not rows.endswith("\n"):
        rows = rows[:rows.rfind("\n") + 1]
        out.write_text(rows)
    return {json.loads(line)["instance_id"] for line in rows.splitlines() if line.strip()}


def tidy(ws: Path) -> None:
    """Remove the attempt's workspace `ws` and its runtime state `<ws>.rt`,
    but keep the state's record of the commands the agent ran through the
    pack, as `<ws>.runs.jsonl`.  The agent could write the state, so the
    record is read without following a link, and only if it is a regular
    file, as the engine's `collect_runs` reads it."""
    rt = Path(f"{ws}.rt")
    try:
        fd = os.open(rt / "runs.jsonl", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        fd = None
    if fd is not None:
        with os.fdopen(fd, "rb") as f:
            if stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                Path(f"{ws}.runs.jsonl").write_bytes(f.read())
    remove(rt)
    remove(ws)


def bridge_start(path_prepend: str, forwards: list, relay: bool = False) -> str:
    """bash that starts the network bridge (`egress.bridge`, forwarding the
    loopback ports `forwards`, and serving the `Relay` if `relay`) with the
    python3 on PATH without the pack's wrappers (`path_prepend`), as
    `launcher` finds an interpreter."""
    rest = shlex.quote(path_prepend + ":")
    bridge = shlex.join([f"{NET}/egress.py", "--socket", f"{NET}/proxy.sock"]
                        + [f"--forward={port}" for port in forwards]
                        + ([f"--relay={NET}/relay.sock"] if relay else []))
    return (f'p=$(PATH=${{PATH#{rest}}} command -v python3) || '
            '{ echo "run_agent: no python3 for the network bridge" >&2; exit 125; }; '
            f'"$p" -I {bridge} || exit 125; ')


def launcher(path_prepend: str) -> str:
    """bash that starts the agent, `"$@"`, with the interpreter its
    `#!/usr/bin/env NAME` line names found on PATH without the pack's
    wrappers (`path_prepend`).  A pack wraps some interpreters (node for
    e-petitions, python3 for python-docx) to run them in its own sandbox,
    which cannot see the agent's installation.  The agent's PATH stays as it
    is, so the commands it runs still go through the pack."""
    rest = shlex.quote(path_prepend + ":")
    return ('if a=$(command -v -- "$1"); then '
            "l=$(head -c 256 -- \"$a\" 2>/dev/null | tr -d '\\0' | head -n 1); "
            "case $l in '#!/usr/bin/env '*) i=${l#'#!/usr/bin/env '}; "
            f'i=$(PATH=${{PATH#{rest}}} command -v -- "${{i%% *}}") '
            '&& shift && set -- "$i" "$a" "$@";; esac; fi; exec "$@"')


def installation(exe: str) -> list:
    """The agent's installation, which the sandbox binds read-only: the
    agent's directory on PATH, or the one above it if that is a `bin`
    directory (for example an npm prefix, which holds node and the package)
    other than / and your home, and the directory its executable resolves
    to."""
    bindir = os.path.dirname(exe)
    prefix = os.path.dirname(bindir)
    if os.path.basename(bindir) not in ("bin", ".bin") or prefix in ("/", os.path.expanduser("~")):
        prefix = bindir
    return [prefix, os.path.dirname(os.path.realpath(exe))]


def codex_paths(image: str = None) -> list:
    """The directories that the Codex on PATH, or in `image`, puts on its
    commands' PATH: `codex-path` beside its native binary, which holds a
    ripgrep.  The leaderboard's Codex had none."""
    script = ('p=$(readlink -f "$(command -v codex)") && d=${p%/bin/*} && for x in '
              '"$d"/codex-path "$d"/node_modules/@openai/codex-*/vendor/*/codex-path; '
              'do [ -d "$x" ] && echo "$x"; done; true')
    sh = (["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", image]
          if image else ["sh"])
    return subprocess.run(sh + ["-c", script], capture_output=True, text=True).stdout.split()


def sandbox(setup: dict, args, command: list, net: str, start: str, hide: list) -> tuple:
    """bwrap's command line for the agent, with the network directory `net`,
    the start script `start` (`bridge_start`, `launcher`) and the directories
    `hide` emptied (`codex_paths`), and the agent's environment, which bwrap
    passes on.  The environment keeps the values of `--env`, such as API keys,
    out of the command line, which every user of the host can read."""
    home = os.path.expanduser("~")
    argv = packs.bwrap_base(bwrap=shutil.which("bwrap")) + ["--tmpfs", home]
    exe = shutil.which(command[0])
    for flag, paths in (("--ro-bind", installation(exe) + args.ro_bind),
                        ("--bind", args.bind)):
        for path in paths:
            path = os.path.realpath(os.path.expanduser(path))
            argv += [flag, path, path]
    for bind in setup["binds"]:
        argv += ["--bind" if bind["writable"] else "--ro-bind",
                 bind["source"], bind["target"]]
    for link in setup["home_links"]:
        argv += ["--symlink", link["target"], os.path.join(home, link["name"])]
    argv += ["--ro-bind", net, NET]
    # The leaderboard's tool set: no toolchain, ripgrep, lxml or behave of
    # the host's, and none of Codex's own ripgrep.
    argv += toolset.masks() + toolset.directory_masks(hide)
    argv += ["--chdir", setup["workspace"]]
    env = {"PATH": f"{setup['path_prepend']}:{os.path.dirname(exe)}:{packs.PREFLIGHT_PATH}",
           "HOME": home, "SHELL": toolset.SHELL}
    env.update((name, os.environ[name]) for name in args.env)
    env.update(PROXY_ENV)
    return argv + ["bash", "-c", start, "bash", os.path.realpath(exe)] + command[1:], env


def wait(proc: subprocess.Popen, prompt: bytes, timeout: int, capped=None) -> str:
    """Give `proc` the prompt on standard input and wait until it exits,
    `timeout` seconds pass or `capped` is set; return how it ended.  The
    prompt is written on a thread of its own: an agent may read it late, or
    only part of it, and a pipe holds less than a long prompt."""
    def give():
        try:
            with proc.stdin:
                proc.stdin.write(prompt)
        except OSError:     # it ended without reading all of it
            pass
    threading.Thread(target=give, daemon=True).start()
    end = time.monotonic() + timeout
    while True:
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        if capped is not None and capped.is_set():
            return "stopped at the budget"
        if proc.returncode is not None:
            return f"exit {proc.returncode}"
        if time.monotonic() >= end:
            return "timed out"


def run(argv: list, prompt: bytes, log, timeout: int, capped=None, env: dict = None,
        name: str = None) -> str:
    """Run `argv` with `prompt` on standard input and the environment `env`,
    and return how it ended (`wait`).  What still runs then is killed: for a
    container `name`, by `docker kill`."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=log,
                            stderr=subprocess.STDOUT, env=env)
    status = wait(proc, prompt, timeout, capped)
    if proc.returncode is None:
        if name:
            subprocess.run(["docker", "kill", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        else:
            proc.kill()
        proc.wait()
    return status


def container(setup: dict, args, command: list, name: str, user: list,
              net: str, start: str, hide: list) -> list:
    """`docker run` of the agent's image with the attempt's runtime: the
    `docker_args`, an empty home directory at the path of yours with the
    pack's home links in it, and the network, as in the sandbox, and the
    user's binds and variables.  `user` is `packs.docker_user()`; `start` and
    `hide` are as in `sandbox`, `hide` in the image.  The `docker run` client
    gets SIGTERM if this process dies, and forwards it to the container,
    which `--rm` then removes."""
    home = os.path.expanduser("~")
    # --init: the agent is not the container's PID 1, which ignores the
    # SIGTERM that `docker run` forwards.
    argv = (["setpriv", "--pdeathsig", "TERM", "--", "docker", "run", "--rm", "-i",
             "--init", "--name", name, "--network", "none", "-v", f"{net}:{NET}:ro"]
            + setup["docker_args"] + user
            # exec: Docker mounts a tmpfs noexec, the sandbox's home is not.
            + ["--tmpfs", f"{home}:exec", "-e", f"HOME={home}",
               "-e", f"SHELL={toolset.SHELL}"]
            + [arg for path in hide for arg in ("--tmpfs", f"{path}:ro")])
    for flag, paths in ((":ro", args.ro_bind), ("", args.bind)):
        for path in paths:
            path = os.path.realpath(os.path.expanduser(path))
            argv += ["-v", f"{path}:{path}{flag}"]
    for var in args.env:
        argv += ["-e", var]
    for var, value in PROXY_ENV.items():
        argv += ["-e", f"{var}={value}"]
    links = "".join(f'ln -sfn {shlex.quote(link["target"])} '
                    f'"$HOME"/{shlex.quote(link["name"])} && '
                    for link in setup["home_links"])
    return (argv + [args.docker] + packs.unprivileged(user)
            + ["bash", "-c", links + start, "bash"] + command)


def endpoints(texts: list) -> tuple:
    """The endpoints that the `--allow` values `texts` name, as a set of
    (host, port), and the loopback ports among them, which the bridge
    forwards into the sandbox, each once."""
    allow = set()
    for text in texts:
        host, port = egress.endpoint(text)
        allow.add(("127.0.0.1" if host == "localhost" else host, port))
    return allow, sorted(port for host, port in allow if host == "127.0.0.1")


def main() -> int:
    ap = argparse.ArgumentParser(prog="python3 -m req2test.inference.run_agent",
                                 description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent", choices=["codex"],
                    help="a built-in agent, run with --model; or give the agent's command after --")
    ap.add_argument("--model", metavar="PROVIDER/MODEL",
                    help=f"the built-in agent's model; providers: {', '.join(CODEX_PROVIDERS)}")
    ap.add_argument("--tasks", required=True, help="a `req2test tasks` file")
    ap.add_argument("-o", "--output-dir", required=True,
                    help="writes predictions.jsonl and workspaces/ here")
    ap.add_argument("--limit", type=int, help="run only the first N tasks")
    ap.add_argument("--workers", type=int, default=1,
                    help="tasks to run at once (default 1)")
    ap.add_argument("--docker", metavar="IMAGE",
                    help="run the agent in a container of IMAGE instead of a "
                         "bubblewrap sandbox")
    ap.add_argument("--model-name",
                    help="the rows' model_name_or_path (default: the output directory's name)")
    ap.add_argument("--timeout", type=int, default=3600,
                    help="wall-clock seconds per generation (default 3600)")
    ap.add_argument("--bind", action="append", default=[], metavar="PATH",
                    help="host path the agent may write, at the same path")
    ap.add_argument("--ro-bind", action="append", default=[], metavar="PATH",
                    help="host path the agent may read, at the same path")
    ap.add_argument("--env", action="append", default=[], metavar="NAME",
                    help="environment variable to pass into the sandbox")
    ap.add_argument("--allow", action="append", default=[], metavar="HOST[:PORT]",
                    help="an endpoint the agent may reach, such as its model provider's "
                         "API (port 443 if not given); the agent reaches nothing else")
    ap.add_argument("command", nargs=argparse.REMAINDER,
                    help="-- the agent's command line, which reads the prompt on standard input")
    args = ap.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.agent:
        if command:
            ap.error("give either --agent or a command after --, not both")
        provider, _, name = (args.model or "").partition("/")
        if provider not in CODEX_PROVIDERS:
            ap.error(f"--agent codex needs --model PROVIDER/MODEL, "
                     f"with PROVIDER one of {', '.join(CODEX_PROVIDERS)}")
        if name != CODEX_PROVIDERS[provider][3]:
            ap.error(f"--agent codex runs the leaderboard's {provider}/"
                     f"{CODEX_PROVIDERS[provider][3]}; give another model's agent "
                     "command after --")
        command = codex(args.model)
        key = CODEX_PROVIDERS[provider][2]
        if not os.environ.get(key):
            ap.error(f"export {key} first")
    elif not command:
        ap.error("give --agent and --model, or the agent's command after --")
    elif not args.allow:
        ap.error("name the endpoints the agent may reach, such as its model "
                 "provider's API, with --allow HOST[:PORT]")
    try:
        allow, forwards = endpoints(args.allow)
    except ValueError as exc:
        ap.error(f"--allow: {exc}")
    for name in args.env:
        if name not in os.environ:
            ap.error(f"--env {name}: export {name} first")
    if args.docker:
        for tool in ("docker", "setpriv"):
            if shutil.which(tool) is None:
                ap.error(f"{tool} is not on PATH")
        try:
            user = packs.docker_user()
        except ValueError as exc:
            ap.error(str(exc))
    else:
        for tool in ("bwrap", command[0]):
            if shutil.which(tool) is None:
                ap.error(f"{tool} is not on PATH")
    if args.workers < 1:
        ap.error("--workers must be at least 1")
    outdir = Path(args.output_dir).expanduser().absolute()
    # Nothing bound for the agent may hold what it must not see (docs/agents.md).
    hidden = [("REQ2TEST_HOME", kits.req2test_home()), ("the output directory", outdir),
              ("this clone", REPO_ROOT), ("your home directory", os.path.expanduser("~"))]
    binds = ([("--ro-bind", path) for path in args.ro_bind]
             + [("--bind", path) for path in args.bind])
    if not args.docker:
        binds += [("its installation", path)
                  for path in installation(shutil.which(command[0]))]
    for what, path in binds:
        path = Path(os.path.realpath(os.path.expanduser(path)))
        for name, root in hidden:
            root = Path(os.path.realpath(root))
            if path == root or path in root.parents:
                ap.error(f"the agent would see {name} ({root}) through {what} {path}")

    hide = codex_paths(args.docker) if args.agent else []
    tasks = [json.loads(line) for line in open(os.path.expanduser(args.tasks))]
    tests = {project: removable(project) for project in {t["project"] for t in tasks}}
    model_name = args.model_name or outdir.name
    out = outdir / "predictions.jsonl"
    done = predicted(out)
    root = outdir / "workspaces"
    root.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    def say(line: str) -> None:
        with lock:
            print(line, file=sys.stderr, flush=True)

    def attempt(n: int, task: dict) -> bool:
        iid = task["instance_id"]
        ws = root / f"{n:04d}"
        remove(ws)
        remove(Path(f"{ws}.rt"))
        views.materialize(task["project"], task["view"], iid, ws / "repo")
        setup = packs.setup_attempt(task["project"], iid, ws)
        before = snapshot(ws / "repo", task["placement"], tests[task["project"]])
        say(f"[{n}] {iid}")
        prompt = build_prompt(task).encode()
        # The network directory: the proxy's socket, and egress.py for the
        # bridge.  Under /tmp, as a unix socket's path must be short.
        net = tempfile.mkdtemp(prefix="r2t-net-", dir="/tmp")
        shutil.copy(egress.__file__, net)
        relay = capped = None
        if args.agent:
            shutil.copy(CODEX_CATALOG, net)
            _, url, key, _ = CODEX_PROVIDERS[args.model.partition("/")[0]]
            relay = Relay(f"{net}/relay.sock", url, os.environ[key], CALLS)
            capped = relay.capped
            threading.Thread(target=relay.serve_forever, daemon=True).start()
        proxy = Proxy(f"{net}/proxy.sock", allow)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        start = (bridge_start(setup["path_prepend"], forwards, bool(relay))
                 + launcher(setup["path_prepend"]))
        try:
            with open(f"{ws}.log", "wb") as log:
                if args.docker:
                    name = f"r2t-agent-{os.getpid()}-{n:04d}"
                    status = run(container(setup, args, command, name, user, net, start, hide),
                                 prompt, log, args.timeout, capped, name=name)
                else:
                    argv, env = sandbox(setup, args, command, net, start, hide)
                    status = run(argv, prompt, log, args.timeout, capped, env=env)
        finally:
            proxy.shutdown()
            proxy.server_close()
            if relay:
                relay.shutdown()
                relay.server_close()
            shutil.rmtree(net)
        calls = f" after {relay.calls} LLM call(s)" if relay else ""
        counts = ", ".join(f"{note} ({k}x)" if k > 1 else note
                           for note, k in Counter(proxy.notes).items())
        with open(f"{ws}.log", "a") as log:
            log.write(f"\nrun_agent: {status}{calls}\n")
            if counts:
                log.write(f"run_agent: the agent's network {counts}\n")
        if counts:
            say(f"[{n}] network: {counts}")
        if status not in ("exit 0", "timed out", "stopped at the budget"):
            say(f"[{n}] {status}{calls}, no prediction; see {ws}.log")
            return False
        row = prediction(task, ws / "repo", before, model_name, tests[task["project"]])
        with lock, out.open("a") as f:
            f.write(json.dumps(row) + "\n")
        tidy(ws)
        say(f"[{n}] {status}{calls}, {len(row['files'])} file(s); log {ws}.log")
        return True

    todo = [(n, task) for n, task in enumerate(tasks[:args.limit])
            if task["instance_id"] not in done]
    if len(todo) < len(tasks[:args.limit]):
        say(f"{len(tasks[:args.limit]) - len(todo)} instance(s) already have a "
            f"prediction in {out}; skipping them")
    with ThreadPoolExecutor(args.workers) as pool:
        failed = list(pool.map(lambda nt: attempt(*nt), todo)).count(False)
    if failed:
        print(f"{failed} instance(s) got no prediction; rerun to retry them", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
