"""The agent's network: only the endpoints `run_agent --allow` names.

The agent's network namespace has nothing but its own loopback (bubblewrap's
`--unshare-net`, Docker's `--network none`).  Two halves connect it to the
allowed endpoints, as in the leaderboard's runs:

* `tunnel`, which `run_agent.Proxy` serves outside the sandbox, is an HTTP
  `CONNECT` proxy on a unix socket.  It opens a tunnel to an allowed
  `host:port` and refuses every other target.  It never terminates TLS, so it
  sees no request.
* `bridge`, inside the sandbox, listens on `127.0.0.1:PROXY_PORT` for the
  agent's `HTTPS_PROXY` and passes each connection to that unix socket,
  which, as a file, crosses the network namespace.  An allowed endpoint on
  the host's loopback, such as a local model server, is also forwarded at
  its own port, so the agent reaches it at the address it has on the host.

For `--agent codex` the bridge also serves the unix socket of
`run_agent.Relay` at `127.0.0.1:RELAY_PORT`.

This file is run as a script inside the sandbox, so it imports only what a
minimal Python has (Debian's python3-minimal has no `socketserver`).
"""
import argparse
import os
import select
import selectors
import socket
import sys
import threading

#: The agent's proxy port on its own loopback.
PROXY_PORT = 3128
#: Where `--agent codex` reaches its relay on its own loopback.
RELAY_PORT = 3129
CONNECT_TIMEOUT = 10.0


def _send_all(dst: socket.socket, data: memoryview) -> None:
    """Write every byte to a non-blocking socket, waiting while its buffer
    is full (`sendall` gives up there, which cut large requests short)."""
    while data:
        try:
            data = data[dst.send(data):]
        except (BlockingIOError, InterruptedError):
            select.select([], [dst], [])


def _pump(a: socket.socket, b: socket.socket) -> None:
    """Forward bytes both ways until either side closes.  No idle timeout:
    a model can take long for its first byte."""
    sel = selectors.DefaultSelector()
    for src, dst in ((a, b), (b, a)):
        src.setblocking(False)
        sel.register(src, selectors.EVENT_READ, dst)
    try:
        while True:
            for key, _ in sel.select():
                try:
                    data = key.fileobj.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return
                if not data:
                    return
                try:
                    _send_all(key.data, memoryview(data))
                except OSError:
                    return
    finally:
        sel.close()


def _head(conn: socket.socket) -> bytes:
    """A request's or response's head, up to its blank line."""
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > 8192:
            raise ValueError("head too large")
        chunk = conn.recv(4096)
        if not chunk:
            raise ValueError("closed before the end of the head")
        data += chunk
    return data


def endpoint(text: str) -> tuple:
    """`(host, port)` from `HOST[:PORT]`, the port 443 by default."""
    host, sep, port = text.rpartition(":")
    if not sep or host.endswith(":"):
        host, port = text, "443"
    host = host.strip("[]").lower()
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"not HOST[:PORT]: {text!r}")
    return host, int(port)


def tunnel(conn: socket.socket, allow: set, notes: list) -> None:
    """Answer one connection to the proxy: tunnel to the `(host, port)` in
    `allow` that its CONNECT names, or refuse it.  What it refuses or cannot
    reach is appended to `notes`."""
    conn.settimeout(CONNECT_TIMEOUT)
    try:
        line = _head(conn).split(b"\r\n", 1)[0].decode("latin-1").split()
        if len(line) != 3 or line[0] != "CONNECT":
            notes.append(f"refused a request that is not CONNECT: {' '.join(line)[:80]}")
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        target = endpoint(line[1])
    except (ValueError, OSError):
        return
    if target not in allow:
        notes.append("refused %s:%d" % target)
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        return
    try:
        upstream = socket.create_connection(target, timeout=CONNECT_TIMEOUT)
    except OSError as exc:
        notes.append("could not reach %s:%d: %s" % (*target, exc))
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        return
    try:
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        _pump(conn, upstream)
    finally:
        upstream.close()


def _forward(conn: socket.socket, path: str, target: bytes) -> None:
    """Pass `conn` to the unix socket, through a tunnel to `target` if any."""
    with conn, socket.socket(socket.AF_UNIX) as up:
        try:
            up.connect(path)
            if target:
                up.sendall(b"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target))
                if b" 200 " not in _head(up).split(b"\r\n", 1)[0]:
                    return
            _pump(conn, up)
        except (OSError, ValueError):
            pass


def bridge(path: str, forwards: list, relay: str = "") -> None:
    """Listen on `127.0.0.1:PROXY_PORT` and on `127.0.0.1:F` for each F in
    `forwards`, for the proxy's unix socket `path`, and on
    `127.0.0.1:RELAY_PORT` for the relay's unix socket `relay` if given.
    Then serve in the background, so that the caller goes on once every
    port listens."""
    routes = [(PROXY_PORT, path, b"")] + [(f, path, b"127.0.0.1:%d" % f) for f in forwards]
    if relay:
        routes.append((RELAY_PORT, relay, b""))
    listeners = {}
    for p, to, target in routes:
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", p))
        sock.listen(64)
        listeners[sock] = (to, target)
    if os.fork():
        os._exit(0)
    os.setsid()
    sel = selectors.DefaultSelector()
    for sock, route in listeners.items():
        sel.register(sock, selectors.EVENT_READ, route)
    while True:
        for key, _ in sel.select():
            conn, _ = key.fileobj.accept()
            threading.Thread(target=_forward, args=(conn, *key.data), daemon=True).start()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="the sandbox's half of the agent's network")
    ap.add_argument("--socket", required=True)
    ap.add_argument("--forward", type=int, action="append", default=[])
    ap.add_argument("--relay", default="")
    args = ap.parse_args()
    try:
        bridge(args.socket, args.forward, args.relay)
    except OSError as exc:
        sys.exit(f"run_agent: the network bridge failed: {exc}")
