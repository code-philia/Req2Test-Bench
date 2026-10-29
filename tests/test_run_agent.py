"""`req2test.inference.run_agent`: each agent sandbox has its own network,
which reaches the allowed endpoints and nothing else.

A runtime pack starts the project's services on fixed loopback ports (MySQL
on 3306, PostgreSQL on 5432), so attempts that run at once, or a service
already on the host, must not share one loopback.  The sandbox tests need
bubblewrap.
"""
import http.client
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

import pytest
from kitfixture import bwrap_usable

from req2test import packs
from req2test.inference import egress, run_agent, toolset

needs_sandbox = pytest.mark.skipif(not bwrap_usable("--unshare-net"),
                                   reason="needs bubblewrap")


def _echo_server() -> tuple:
    """A server on this host's loopback that sends back what it gets, and
    its threads."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    threads = []

    def echo(conn):
        with conn:
            while data := conn.recv(65536):
                conn.sendall(data)

    def accept():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            threads.append(threading.Thread(target=echo, args=(conn,)))
            threads[-1].start()

    threads.append(threading.Thread(target=accept))
    threads[0].start()
    return server, threads


#: Run in the sandbox: the allowed endpoint through the proxy and at its
#: forwarded port, with more data than a socket buffer holds; a refused one;
#: and a direct connection.
CLIENT = r"""
import socket, sys
port, data = int(sys.argv[1]), bytes(range(256)) * 1200

def head(s):
    h = b""
    while b"\r\n\r\n" not in h:
        h += s.recv(1)
    return h.split(b"\r\n")[0].decode()

def echoed(s):
    s.sendall(data)
    got = b""
    while len(got) < len(data):
        got += s.recv(65536)
    return got == data

s = socket.create_connection(("127.0.0.1", 3128))
s.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n" % port)
print("proxy", head(s), echoed(s))
print("forward", echoed(socket.create_connection(("127.0.0.1", port))))
s = socket.create_connection(("127.0.0.1", 3128))
s.sendall(b"CONNECT example.org:443 HTTP/1.1\r\n\r\n")
print("other", head(s))
try:
    socket.create_connection(("1.1.1.1", 443), timeout=5)
    print("direct connected")
except OSError:
    print("direct none")
"""


@needs_sandbox
def test_the_sandbox_reaches_the_allowed_endpoint_alone():
    echo, threads = _echo_server()
    port = echo.getsockname()[1]
    # A unix socket's path must be short; pytest's tmp_path can be too long.
    net = tempfile.mkdtemp(prefix="r2t-net-", dir="/tmp")
    shutil.copy(egress.__file__, net)
    proxy = run_agent.Proxy(f"{net}/proxy.sock", {("127.0.0.1", port)})
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    try:
        out = subprocess.run(
            ["bwrap", "--die-with-parent", "--unshare-pid", "--unshare-net",
             "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
             "--tmpfs", "/tmp", "--ro-bind", net, run_agent.NET, "bash", "-c",
             f'{sys.executable} -I {run_agent.NET}/egress.py --socket '
             f'{run_agent.NET}/proxy.sock --forward {port} && '
             f'{sys.executable} -I -c "$0" {port}', CLIENT],
            capture_output=True, text=True, timeout=60)
    finally:
        proxy.shutdown()
        proxy.server_close()
        echo.shutdown(socket.SHUT_RDWR)    # wakes its accept(), as close() does not
        echo.close()
        for thread in threads:
            thread.join()
        shutil.rmtree(net)
    assert out.stdout.splitlines() == [
        "proxy HTTP/1.1 200 Connection established True", "forward True",
        "other HTTP/1.1 403 Forbidden", "direct none"], out.stderr
    assert proxy.notes == ["refused example.org:443"]


@pytest.mark.parametrize("text, endpoint", [
    ("api.deepseek.com", ("api.deepseek.com", 443)),
    ("API.example.com:8443", ("api.example.com", 8443)),
    ("127.0.0.1:8000", ("127.0.0.1", 8000)),
    ("[::1]:8000", ("::1", 8000))])
def test_an_allowed_endpoint(text, endpoint):
    assert egress.endpoint(text) == endpoint


def test_another_agent_names_the_endpoints_it_may_reach(tmp_path):
    out = subprocess.run(
        [sys.executable, "-m", "req2test.inference.run_agent", "--tasks",
         str(tmp_path / "tasks.jsonl"), "-o", str(tmp_path / "out"), "--", "true"],
        capture_output=True, text=True)
    assert out.returncode == 2 and "--allow HOST[:PORT]" in out.stderr


def test_an_unset_variable_is_an_error(tmp_path):
    # Not passed on, it would leave the agent without its key, and an agent
    # that exits 0 without one leaves rows a rerun skips.
    env = {k: v for k, v in os.environ.items() if k != "R2T_UNSET_KEY"}
    out = subprocess.run(
        [sys.executable, "-m", "req2test.inference.run_agent", "--tasks",
         str(tmp_path / "tasks.jsonl"), "-o", str(tmp_path / "out"), "--env",
         "R2T_UNSET_KEY", "--allow", "api.example.com", "--", "true"],
        capture_output=True, text=True, env=env)
    assert out.returncode == 2 and "export R2T_UNSET_KEY first" in out.stderr


def test_codex_runs_as_the_leaderboard_ran_it(tmp_path):
    command = run_agent.codex("deepseek/deepseek-flash")
    assert {"--ephemeral", "--ignore-user-config", "--ignore-rules"} <= set(command)
    settings = [command[i + 1] for i, arg in enumerate(command) if arg == "-c"]
    assert f'model_catalog_json="{run_agent.NET}/codex_models.json"' in settings
    assert 'web_search="disabled"' in settings and "features.hooks=false" in settings
    # The provider through the relay, which holds the key: Codex has none.
    assert ('model_providers.deepseek={name="DeepSeek", base_url="http://127.0.0.1:3129", '
            'wire_api="responses", requires_openai_auth=false}') in settings
    catalog = json.loads(run_agent.CODEX_CATALOG.read_text())
    assert "deepseek-flash" in [m["slug"] for m in catalog["models"]]
    # A model without the leaderboard's catalog entry would run with Codex's
    # generic instructions and tools.
    out = subprocess.run(
        [sys.executable, "-m", "req2test.inference.run_agent", "--agent", "codex",
         "--model", "deepseek/deepseek-chat", "--tasks", str(tmp_path / "tasks.jsonl"),
         "-o", str(tmp_path / "out")],
        capture_output=True, text=True, env={**os.environ, "DEEPSEEK_API_KEY": "x"})
    assert out.returncode == 2 and "runs the leaderboard's deepseek/deepseek-flash" in out.stderr


class _Provider(http.server.ThreadingHTTPServer):
    """A model provider on this host's loopback that records each call and
    streams back its body in two pieces."""
    daemon_threads = True

    def __init__(self):
        self.calls = []

        class Call(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(handler):
                body = handler.rfile.read(int(handler.headers["Content-Length"]))
                self.calls.append((handler.path, handler.headers["Authorization"], body))
                handler.send_response(200)
                handler.send_header("Content-Type", "text/event-stream")
                handler.send_header("Transfer-Encoding", "chunked")
                handler.end_headers()
                for piece in (b"data: ", body):
                    handler.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
                handler.wfile.write(b"0\r\n\r\n")

        super().__init__(("127.0.0.1", 0), Call)
        threading.Thread(target=self.serve_forever, daemon=True).start()


def _post(path: str, body: bytes, method: str = "POST") -> tuple:
    """A call to the relay's unix socket: the status and the body."""
    conn = http.client.HTTPConnection("relay")
    conn.sock = socket.socket(socket.AF_UNIX)
    conn.sock.connect(path)
    conn.request(method, "/responses", body)
    response = conn.getresponse()
    return response.status, response.read()


def test_the_relay_holds_the_key_and_refuses_calls_past_the_budget():
    provider = _Provider()
    net = tempfile.mkdtemp(prefix="r2t-net-", dir="/tmp")
    relay = run_agent.Relay(f"{net}/relay.sock", "http://127.0.0.1:%d/v1"
                            % provider.server_port, "sk-host", 2)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    try:
        assert _post(f"{net}/relay.sock", b"", "GET")[0] == 403
        assert _post(f"{net}/relay.sock", b'{"n": 1}') == (200, b'data: {"n": 1}')
        assert _post(f"{net}/relay.sock", b'{"n": 2}') == (200, b'data: {"n": 2}')
        assert not relay.capped.is_set()
        status, body = _post(f"{net}/relay.sock", b'{"n": 3}')
    finally:
        relay.shutdown()
        relay.server_close()
        provider.shutdown()
        shutil.rmtree(net)
    assert status == 429 and b"budget of 2 LLM calls" in body
    assert relay.capped.is_set() and relay.calls == 2
    assert provider.calls == [("/v1/responses", "Bearer sk-host", b'{"n": %d}' % n)
                              for n in (1, 2)]


#: Run in the sandbox as the agent: calls through the relay until one is
#: refused, then waits, as an agent that would go on.
CALLER = r"""
import http.client, sys, time
while True:
    conn = http.client.HTTPConnection("127.0.0.1", 3129)
    conn.request("POST", "/responses", b"{}")
    response = conn.getresponse()
    print(response.status, response.read().decode(), flush=True)
    if response.status != 200:
        time.sleep(60)
"""


def test_a_prompt_longer_than_a_pipe_reaches_an_agent_that_reads_it_late(tmp_path):
    with open(tmp_path / "log", "wb") as log:
        status = run_agent.run(["sh", "-c", "sleep 2; wc -c"], b"x" * 300_000, log, 30)
    assert status == "exit 0"
    assert (tmp_path / "log").read_text().split() == ["300000"]


@needs_sandbox
def test_the_agent_is_stopped_at_the_budget(tmp_path):
    provider = _Provider()
    net = tempfile.mkdtemp(prefix="r2t-net-", dir="/tmp")
    shutil.copy(egress.__file__, net)
    relay = run_agent.Relay(f"{net}/relay.sock", "http://127.0.0.1:%d"
                            % provider.server_port, "sk-host", 3)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    argv = ["bwrap", "--die-with-parent", "--unshare-pid", "--unshare-net",
            "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
            "--tmpfs", "/tmp", "--ro-bind", net, run_agent.NET, "bash", "-c",
            f"{sys.executable} -I {run_agent.NET}/egress.py --socket "
            f"{run_agent.NET}/proxy.sock --relay {run_agent.NET}/relay.sock && "
            f'{sys.executable} -I -c "$0"', CALLER]
    started = time.monotonic()
    try:
        with open(tmp_path / "log", "wb") as log:
            status = run_agent.run(argv, b"", log, 60, relay.capped)
    finally:
        relay.shutdown()
        relay.server_close()
        provider.shutdown()
        shutil.rmtree(net)
    assert status == "stopped at the budget" and time.monotonic() - started < 30
    assert (tmp_path / "log").read_text().splitlines()[:4] == ["200 data: {}"] * 3 + [
        '429 {"error": {"message": "the budget of 3 LLM calls is spent"}}']
    assert relay.calls == 3 and len(provider.calls) == 3


def _installed(exe):
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    return str(exe)


def test_the_agent_installation_is_a_prefix_only_above_a_bin_directory(tmp_path):
    assert (run_agent.installation(_installed(tmp_path / "npm" / "bin" / "agent"))
            == [str(tmp_path / "npm"), str(tmp_path / "npm" / "bin")])
    assert (run_agent.installation(_installed(tmp_path / "work" / "agents" / "agent"))
            == [str(tmp_path / "work" / "agents")] * 2)


def test_nothing_bound_for_the_agent_holds_what_it_must_not_see(tmp_path):
    (tmp_path / "tasks.jsonl").write_text("")
    (tmp_path / "me").mkdir()

    def run(*argv):
        return subprocess.run(
            [sys.executable, "-m", "req2test.inference.run_agent", "--tasks",
             str(tmp_path / "tasks.jsonl"), "--allow", "api.example.com", *argv],
            capture_output=True, text=True,
            env={**os.environ, "REQ2TEST_HOME": str(tmp_path / "home"),
                 "HOME": str(tmp_path / "me")})

    # Installed beside the output directory, as work/bin/agent: the sandbox
    # binds work/, the parent of the agent's directory.
    beside = _installed(tmp_path / "work" / "bin" / "agent")
    out = run("-o", str(tmp_path / "work" / "out"), "--", beside)
    assert out.returncode == 2
    assert (f"the output directory ({os.path.realpath(tmp_path / 'work' / 'out')}) "
            f"through its installation {os.path.realpath(tmp_path / 'work')}") in out.stderr
    out = run("-o", str(tmp_path / "out"), "--ro-bind", str(tmp_path), "--", beside)
    assert out.returncode == 2 and "would see REQ2TEST_HOME" in out.stderr
    out = run("-o", str(tmp_path / "out"), "--", _installed(tmp_path / "me" / "x" / "agent"))
    assert out.returncode == 0, out.stderr
    out = run("-o", str(tmp_path / "out"), "--", _installed(tmp_path / "me" / "agent"))
    assert out.returncode == 2 and "would see your home directory" in out.stderr
    apart = _installed(tmp_path / "tools" / "bin" / "agent")
    out = run("-o", str(tmp_path / "work" / "out"), "--", apart)
    assert out.returncode == 0, out.stderr


def test_a_loopback_endpoint_named_twice_is_forwarded_once():
    allow, forwards = run_agent.endpoints(
        ["localhost:8000", "127.0.0.1:8000", "api.example.com"])
    assert allow == {("127.0.0.1", 8000), ("api.example.com", 443)}
    assert forwards == [8000]


def test_a_rerun_drops_a_cut_off_row(tmp_path):
    out = tmp_path / "predictions.jsonl"
    assert run_agent.predicted(out) == set()
    out.write_text('{"instance_id": "a"}\n{"instance_id": "b", "fi')
    assert run_agent.predicted(out) == {"a"}
    assert out.read_text() == '{"instance_id": "a"}\n'


@needs_sandbox
def test_a_rerun_says_which_instances_it_skips(tmp_path):
    # A rerun into an output directory that holds every task's row runs
    # nothing, and says so rather than exiting without a word.
    (tmp_path / "tasks.jsonl").write_text(
        json.dumps({"instance_id": "a", "project": "python-docx"}) + "\n")
    out = tmp_path / "out" / "predictions.jsonl"
    out.parent.mkdir()
    out.write_text('{"instance_id": "a"}\n')
    run = subprocess.run(
        [sys.executable, "-m", "req2test.inference.run_agent", "--tasks",
         str(tmp_path / "tasks.jsonl"), "-o", str(out.parent), "--allow",
         "api.example.com", "--", "true"],
        capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert f"1 instance(s) already have a prediction in {out}; skipping them" in run.stderr


def test_an_attempt_with_a_row_keeps_its_log_and_record_of_runs(tmp_path):
    ws = tmp_path / "0000"
    (ws / "repo" / "target").mkdir(parents=True)
    (ws / "repo" / "target" / "x").write_text("build")
    (ws / "repo" / "target").chmod(0o555)
    (tmp_path / "0000.log").write_text("agent output")
    (tmp_path / "0000.rt" / "gocache").mkdir(parents=True)
    (tmp_path / "0000.rt" / "gocache" / "x").write_text("cache")
    (tmp_path / "0000.rt" / "gocache").chmod(0o555)
    (tmp_path / "0000.rt" / "runs.jsonl").write_text('{"tool": "go"}\n')
    run_agent.tidy(ws)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["0000.log", "0000.runs.jsonl"]
    assert (tmp_path / "0000.runs.jsonl").read_text() == '{"tool": "go"}\n'


def test_an_attempt_does_not_follow_a_link_in_its_runtime_state(tmp_path):
    ws = tmp_path / "0000"
    (ws / "repo").mkdir(parents=True)
    (tmp_path / "0000.rt").mkdir()
    (tmp_path / "host-file").write_text("not the agent's")
    (tmp_path / "0000.rt" / "runs.jsonl").symlink_to(tmp_path / "host-file")
    run_agent.tidy(ws)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["host-file"]


def test_the_answer_is_the_test_code_scoring_takes(tmp_path):
    pl = {"acceptance_root": "features/steps/", "suffixes": [".py", ".feature"],
          "extra_names": ["behat_services.yml"]}
    task = {"instance_id": "p/a.feature:1", "view": "c2", "placement": pl}
    # The project's boundary: test code under features/steps/ and shared/.
    removable = lambda rel: rel.startswith(("features/steps/", "shared/"))  # noqa: E731
    repo = tmp_path / "ws" / "repo"
    for rel in ("features/a.feature", "features/b.feature", "setup.py"):
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text("view\n")
    before = run_agent.snapshot(repo, pl, removable)
    for rel in ("features/steps/a_steps.py",      # the answer
                "shared/helpers.py",              # test code beyond the acceptance root
                "features/a.feature",             # an edit of the view's feature file
                "behat_services.yml",             # the wiring file
                "setup.py",                       # production code
                "target/features/b.feature",      # a build's copy
                "var/cache/Container.py",         # a cache the tests wrote
                "repo/features/steps/a_steps.py"):  # a tree inside the tree
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text("agent\n")
    row = run_agent.prediction(task, repo, before, "m", removable)
    assert [f["path"] for f in row["files"]] == [
        "behat_services.yml", "features/a.feature", "features/steps/a_steps.py",
        "shared/helpers.py"]
    # An agent that replaces repo/ with a link to a host directory submits nothing.
    shutil.move(repo, tmp_path / "elsewhere")
    repo.symlink_to(tmp_path / "elsewhere")
    assert run_agent.prediction(task, repo, before, "m", removable)["files"] == []


def test_the_agent_sandbox_has_its_own_network_and_workspace(tmp_path, monkeypatch):
    ws = str(tmp_path / "out" / "workspaces" / "0000")
    setup = {"binds": [{"source": ws, "target": ws, "writable": True}],
             "home_links": [], "workspace": ws, "path_prepend": "/r2t-rt/bin"}
    args = type("Args", (), {"ro_bind": [], "bind": [], "env": ["R2T_TEST_KEY"],
                             "agent": None})()
    exe = tmp_path / "bin" / "agent"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("R2T_TEST_KEY", "sk-not-in-argv")
    argv, env = run_agent.sandbox(setup, args, [str(exe)], "/tmp/r2t-net-x", "START", [])
    assert "--unshare-net" in argv
    i = argv.index("/tmp/r2t-net-x")
    assert argv[i - 1:i + 2] == ["--ro-bind", "/tmp/r2t-net-x", run_agent.NET]
    # Keys go in the environment: every user of the host can read argv.
    assert env["R2T_TEST_KEY"] == "sk-not-in-argv" and "sk-not-in-argv" not in argv
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:3128" and env["HOME"] == os.path.expanduser("~")
    # The tool set's shell.  No account files, as in the leaderboard's
    # sandbox: Codex, which takes its shell from /etc/passwd, then runs bash.
    assert env["SHELL"] == "/bin/bash"
    assert not {"/etc/passwd", "/etc/group"} & set(argv)
    assert argv[-5:] == ["bash", "-c", "START", "bash", str(exe)]


@needs_sandbox
def test_the_sandbox_hides_the_hosts_toolchains(tmp_path, monkeypatch):
    # A stand-in for the host's system: a toolchain directory, a masked name
    # with a version and a link to it, a link into the toolchain directory,
    # a longer name, and lxml in a system package directory.
    usr = tmp_path / "usr"
    tools, jdk = usr / "bin", usr / "lib" / "jvm" / "jdk" / "bin"
    packages = usr / "lib" / "python3" / "dist-packages"
    for directory in (tools, jdk, packages / "lxml"):
        directory.mkdir(parents=True)
    for tool in (jdk / "fixturejava", tools / "fixtureruby3.2", tools / "fixturerubocop"):
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o755)
    (tools / "fixtureruby").symlink_to("fixtureruby3.2")
    (tools / "fixturejava").symlink_to("../lib/jvm/jdk/bin/fixturejava")
    (packages / "lxml" / "__init__.py").write_text("")
    (packages / "lxml" / "etree.py").write_text("")
    monkeypatch.setattr(toolset, "MASKED_TOOLS", ("fixtureruby", "fixturejava"))
    monkeypatch.setattr(toolset, "TOOL_DIRECTORIES", (str(tools),))
    monkeypatch.setattr(toolset, "MASKED_TOOLCHAIN_DIRECTORIES", (str(usr / "lib" / "jvm"),))
    monkeypatch.setattr(toolset, "MASKED_PACKAGE_DIRECTORIES", (str(packages),))
    monkeypatch.setattr(toolset, "SYSTEM_ROOTS", (f"{usr}/",))
    argv = ["bwrap", "--die-with-parent", "--unshare-net", "--ro-bind", "/", "/",
            "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
            "--ro-bind", str(tmp_path), str(tmp_path)]
    masks = toolset.masks()
    # The link into the masked directory dangles, so it gets no mask, which
    # bwrap could not make; the link to a masked name needs none.
    assert masks == ["--tmpfs", str(usr / "lib" / "jvm"), "--remount-ro", str(usr / "lib" / "jvm"),
                     "--tmpfs", str(packages / "lxml"), "--remount-ro", str(packages / "lxml"),
                     "--ro-bind", "/dev/null", str(tools / "fixtureruby3.2")]
    script = ('for t in fixtureruby3.2 fixtureruby fixturejava fixturerubocop; do '
              '"$t" 2>/dev/null; echo "$t $?"; done; '
              f'{sys.executable} -I -S -c "import sys; sys.path.insert(0, \'{packages}\'); '
              'import lxml.etree" 2>/dev/null; echo "lxml.etree $?"')
    out = subprocess.run(argv + masks + ["bash", "-c", script], capture_output=True,
                         text=True, env={"PATH": f"{tools}:/usr/bin:/bin"})
    assert out.returncode == 0, out.stderr
    assert out.stdout.splitlines() == ["fixtureruby3.2 126", "fixtureruby 126",
                                       "fixturejava 127", "fixturerubocop 0",
                                       "lxml.etree 1"]


def test_codex_keeps_no_ripgrep_of_its_own(tmp_path, monkeypatch):
    # Installed with npm: bin/codex links to the package's codex.js, and the
    # native binary and its codex-path come in a platform package.
    npm = tmp_path / "npm"
    package = npm / "lib" / "node_modules" / "@openai" / "codex"
    rg = (package / "node_modules" / "@openai" / "codex-linux-x64" / "vendor"
          / "x86_64-unknown-linux-musl" / "codex-path")
    rg.mkdir(parents=True)
    (npm / "bin").mkdir()
    (npm / "bin" / "codex").symlink_to(_installed(package / "bin" / "codex.js"))
    monkeypatch.setenv("PATH", f"{npm / 'bin'}:/usr/bin:/bin")
    assert run_agent.codex_paths() == [str(rg)]
    # The native binary on its own, with codex-path beside its bin/.
    native = tmp_path / "opt" / "codex"
    (native / "codex-path").mkdir(parents=True)
    _installed(native / "bin" / "codex")
    monkeypatch.setenv("PATH", f"{native / 'bin'}:/usr/bin:/bin")
    assert run_agent.codex_paths() == [str(native / "codex-path")]


@pytest.mark.parametrize("shebang, ran", [
    ("#!/usr/bin/env tool-interp", "agent's"),   # never the pack's wrapper
    ("#!/usr/bin/env tool-interp -u", "agent's"),
    ("#!/bin/sh", "own")])
def test_the_agent_starts_with_its_own_interpreter(tmp_path, shebang, ran):
    pack, agent = tmp_path / "pack", tmp_path / "agent"
    for d, who in ((pack, "pack's"), (agent, "agent's")):
        d.mkdir()
        (d / "tool-interp").write_text(f'#!/bin/sh\necho "{who} $1 $2"\n')
        (d / "tool-interp").chmod(0o755)
    script = agent / "the-agent"
    script.write_text(f"{shebang}\necho \"own $1\"\n")
    script.chmod(0o755)
    out = subprocess.run(
        ["bash", "-c", run_agent.launcher(str(pack)), "bash", "the-agent", "x"],
        capture_output=True, text=True,
        env={"PATH": f"{pack}:{agent}:/usr/bin:/bin"}).stdout
    assert out == (f"{ran} {script} x\n" if ran == "agent's" else "own x\n")


@pytest.mark.parametrize("user", [[], ["--user", "5:5"]])
def test_the_agent_container_has_the_attempt_runtime_and_a_home(tmp_path,
                                                                 user):
    ws = str(tmp_path / "out" / "workspaces" / "0000")
    setup = {"docker_args": ["-v", f"{ws}:{ws}", "-w", ws],
             "path_prepend": "/r2t-rt/bin",
             "home_links": [{"name": ".m2", "target": "/r2t-rt/home/.m2"}]}
    args = type("Args", (), {"ro_bind": [str(tmp_path / "agent")], "bind": [],
                             "env": ["KEY"], "docker": "my-agent", "agent": None})()
    argv = run_agent.container(setup, args, ["agent", "--yes"], "r2t-agent-1",
                               user, "/tmp/r2t-net-x", "START", ["/opt/codex/codex-path"])
    agent, home = str(tmp_path / "agent"), os.path.expanduser("~")
    # An empty home at your home's path, as in the sandbox, so that a
    # configuration directory bound from it is where the agent looks.  The
    # tool set's shell, and no ripgrep of Codex's own.
    proxies = [arg for name, value in run_agent.PROXY_ENV.items()
               for arg in ("-e", f"{name}={value}")]
    assert argv == [
        "setpriv", "--pdeathsig", "TERM", "--",
        "docker", "run", "--rm", "-i", "--init", "--name", "r2t-agent-1",
        "--network", "none", "-v", f"/tmp/r2t-net-x:{run_agent.NET}:ro",
        "-v", f"{ws}:{ws}", "-w", ws, *user,
        "--tmpfs", f"{home}:exec", "-e", f"HOME={home}", "-e", "SHELL=/bin/bash",
        "--tmpfs", "/opt/codex/codex-path:ro",
        "-v", f"{agent}:{agent}:ro", "-e", "KEY", *proxies, "my-agent",
        *packs.unprivileged(user),
        "bash", "-c", 'ln -sfn /r2t-rt/home/.m2 "$HOME"/.m2 && START', "bash",
        "agent", "--yes"]


@pytest.mark.parametrize("capped, ended", [(False, "timed out"),
                                           (True, "stopped at the budget")])
def test_a_container_past_its_time_is_killed_by_name(tmp_path, monkeypatch,
                                                     capped, ended):
    # A stand-in `docker` that records its arguments: `run` outlives the
    # timeout, and `kill` ends it, as `docker kill` ends the container.
    calls, pid = tmp_path / "calls", tmp_path / "pid"
    docker = tmp_path / "bin" / "docker"
    docker.parent.mkdir()
    docker.write_text(f'#!/bin/sh\necho "$@" >> {calls}\n'
                      f'if [ "$1" = run ]; then echo $$ > {pid}; exec sleep 30; fi\n'
                      f'kill "$(cat {pid})"\n')
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{docker.parent}:{os.environ['PATH']}")
    with open(tmp_path / "log", "wb") as log:
        budget = threading.Event()
        if capped:
            budget.set()
        status = run_agent.run(["docker", "run", "r2t-agent-7"], b"", log, 1, budget,
                               name="r2t-agent-7")
    assert status == ended
    assert calls.read_text().splitlines() == ["run r2t-agent-7",
                                              "kill r2t-agent-7"]
