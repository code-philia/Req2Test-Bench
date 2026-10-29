"""One verified Docker execution authority for every benchmark subprocess.

All Docker leaves converge here.  Building a Docker argv is therefore a live
operation: it lazily loads and revalidates the explicit authority artifact,
derives the exact client and Unix endpoint from it, and gives the command a
fresh empty client configuration.  There is no default daemon and no ``sg``
fallback.  Report/source-only commands never call this module's command
builder, so they remain Docker-free even when no authority was configured.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import tempfile
import threading
from typing import Iterable, Mapping, Optional

from .. import docker_authority as _A


DockerEndpointRefused = _A.DockerAuthorityRefused
AMBIENT_DOCKER_ENDPOINT_KEYS = _A.AMBIENT_DOCKER_KEYS


@dataclass(frozen=True)
class DockerExecution:
    authority_path: Optional[str] = None


_selection = DockerExecution()
_document: Optional[dict] = None
_reference: Optional[dict] = None
_phase_validated = False
_client_config: Optional[tempfile.TemporaryDirectory] = None
_state_lock = threading.RLock()


def _clear_configs() -> None:
    global _client_config
    with _state_lock:
        if _client_config is not None:
            _client_config.cleanup()
            _client_config = None


def configure(*, authority_path: Optional[str] = None,
              environ: Optional[Mapping[str, str]] = None) -> DockerExecution:
    """Record a path lazily; source-only commands do not consume it.

    ``environ`` is retained for deterministic callers but intentionally not
    inspected here.  Ambient Docker state is rejected only when a Docker path
    is actually reached, preserving Docker-free reporting behavior.
    """
    del environ
    if authority_path is not None:
        if not isinstance(authority_path, str) or not authority_path:
            raise DockerEndpointRefused(
                "REFUSED: --docker-authority must name one evidence file")
        authority_path = os.path.abspath(authority_path)
        _A.canonical_absolute_path(authority_path, "Docker authority path")
    global _selection, _document, _reference, _phase_validated
    with _state_lock:
        _clear_configs()
        _selection = DockerExecution(authority_path=authority_path)
        _document = None
        _reference = None
        _phase_validated = False
        return _selection


def endpoint() -> DockerExecution:
    """Compatibility name for the immutable process-wide authority selection."""
    return _selection


def configured_authority_path() -> Optional[str]:
    return _selection.authority_path


def _require_path() -> str:
    if _selection.authority_path is None:
        raise DockerEndpointRefused(
            "REFUSED: live Docker execution requires --docker-authority; "
            "the default/shared daemon and bare socket routes are not "
            "execution authority; no Docker command was run")
    return _selection.authority_path


def begin_phase() -> tuple[dict, dict]:
    """Revalidate authority once at a new process/workload phase.

    Every CLI/gate entry calls ``configure`` and therefore begins a phase.
    A coordinator that deliberately starts another phase in the same process
    calls ``reset_phase`` first.  One phase may issue concurrent Docker
    subprocesses; the lock makes their common revalidation/config proof
    linearizable.
    """
    global _document, _reference, _phase_validated
    with _state_lock:
        if not _phase_validated:
            path = _require_path()
            _document, _reference = _A.authority_reference(path, live=True)
            _phase_validated = True
        assert _document is not None and _reference is not None
        return _document, _reference


def reset_phase() -> None:
    """Force the next Docker boundary to repeat every live authority proof."""
    global _phase_validated
    with _state_lock:
        _phase_validated = False
        _clear_configs()


def authority_reference(*, live: bool = False) -> tuple[dict, dict]:
    """Return the exact configured authority and evidence reference."""
    global _document, _reference
    if live:
        return begin_phase()
    with _state_lock:
        if _document is None or _reference is None:
            path = _require_path()
            _document, _reference = _A.authority_reference(path, live=False)
        return _document, _reference


def require_authority_reference(expected: object, *, live: bool = False) -> dict:
    document, actual = authority_reference(live=live)
    if expected != actual:
        raise DockerEndpointRefused(
            "REFUSED: workload evidence names a different Docker authority; "
            "no Docker command was run")
    return document


def _new_client_config() -> str:
    global _client_config
    with _state_lock:
        if _client_config is None:
            _client_config = tempfile.TemporaryDirectory(
                prefix="r2t-docker-client.")
            os.chmod(_client_config.name, 0o700)
        if os.listdir(_client_config.name):
            raise DockerEndpointRefused(
                "REFUSED: isolated Docker client configuration is not empty")
        return _client_config.name


def docker_argv(argv: Iterable[str], *, executable: str = "docker",
                environ: Optional[Mapping[str, str]] = None) -> list[str]:
    """Return exact authority-derived Docker argv for one live command."""
    _A.refuse_ambient_docker()
    if environ is not None:
        _A.refuse_ambient_docker(environ)
    with _state_lock:
        document, _reference_value = begin_phase()
        parts = list(argv)
        if any(not isinstance(value, str) or not value or "\x00" in value
               for value in parts):
            raise DockerEndpointRefused(
                "REFUSED: Docker argv contains an invalid token")
        selected = document["client"]["selected_executable"]
        if executable not in {"docker", selected}:
            raise DockerEndpointRefused(
                "REFUSED: Docker executable must be the exact client bound by "
                "--docker-authority")
        config = _new_client_config()
        return [selected, "--config", config, "--host",
                document["endpoint"]["address"], *parts]


def docker_command(argv: Iterable[str], *, docker_group: bool = True,
                   executable: str = "docker",
                   environ: Optional[Mapping[str, str]] = None) -> list[str]:
    """Return an unwrapped exact-client command; ``sg docker`` is forbidden."""
    del docker_group
    return docker_argv(argv, executable=executable, environ=environ)


def selected_socket_path() -> str:
    document, _reference_value = authority_reference(live=False)
    return document["adapter"]["selected_socket_path"]


def authority_protected_paths() -> tuple[str, ...]:
    """Host objects that submitted code must never receive as bind mounts.

    Workload-specific spec/binding/runtime files are added by their callers.
    This process-wide portion is derivable solely from the selected authority
    and includes both spellings of every deliberately dereferenced object plus
    the reviewed verifier source.
    """
    if configured_authority_path() is None:
        return ()
    document, reference = authority_reference(live=False)
    paths = (
        reference["path"],
        document["adapter"]["selected_socket_path"],
        document["adapter"]["resolved_socket_path"],
        document["daemon"]["docker_root_dir"],
        document["adapter"]["docker_root_resolved_path"],
        document["client"]["selected_executable"],
        document["client"]["resolved_executable"],
        os.path.abspath(_A.__file__),
    )
    return tuple(dict.fromkeys(paths))


def selected_client_paths() -> tuple[str, ...]:
    """Exact selected/resolved client spellings for sandbox masking."""
    if configured_authority_path() is None:
        return ()
    document, _reference_value = authority_reference(live=False)
    return tuple(dict.fromkeys((
        document["client"]["selected_executable"],
        document["client"]["resolved_executable"],
    )))


def endpoint_selection_identity() -> str:
    """Historical helper: new evidence uses full authority references."""
    if _selection.authority_path is None:
        return "legacy-default"
    document, _reference_value = authority_reference(live=False)
    return document["endpoint"]["selection_identity"]


def valid_endpoint_selection(value: object) -> bool:
    """Recognize only persisted v2 route spellings; never authorize them."""
    if value == "legacy-default":
        return True
    if not isinstance(value, str) or not value.startswith("host:unix://"):
        return False
    path = value[len("host:unix://"):]
    # Preserve the exact v2 producer grammar.  Authority v1 deliberately
    # narrows Unix paths to URI-unambiguous characters, but a historical v2
    # route was allowed to contain spaces, %, ?, or #.  It remains readable
    # offline and remains non-authorizing regardless of spelling.
    return bool(path and os.path.isabs(path)
                and os.path.normpath(path) == path
                and "\x00" not in path and "\r" not in path
                and "\n" not in path)


def add_cli_arguments(parser) -> None:
    parser.add_argument(
        "--docker-authority", default=None, metavar="FILE",
        help="verified r2t.docker-execution-authority/v1 artifact required "
             "before this gate reaches Docker")


def configure_from_args(args, *, verify_socket: bool = True) -> DockerExecution:
    del verify_socket
    return configure(authority_path=getattr(args, "docker_authority", None))


def _install_test_authority(document: dict, reference: dict) -> None:
    """Source-only selftest seam; production never calls this."""
    global _selection, _document, _reference, _phase_validated
    with _state_lock:
        _clear_configs()
        _selection = DockerExecution(authority_path=reference["path"])
        _document = document
        _reference = reference
        _phase_validated = True


def selftest() -> int:
    import stat
    from unittest.mock import patch

    failures = []

    def check(name, condition):
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}")
        if not condition:
            failures.append(name)

    def refused(fn) -> bool:
        try:
            fn()
        except DockerEndpointRefused:
            return True
        return False

    configure()
    check("missing authority fails closed only at Docker boundary",
          refused(lambda: docker_command(["ps"], environ={})))
    # Configuration itself remains inert for a reporting command.
    configure(authority_path="relative-authority.json",
              environ={"DOCKER_HOST": "secret-not-read"})
    check("authority path is normalized without loading/contacting Docker",
          configured_authority_path() == os.path.abspath(
              "relative-authority.json"))

    document = _A._fixture_authority()
    reference = {"path": "/private/authority.json",
                 "file_sha256": "a" * 64, "digest": document["digest"]}
    _install_test_authority(document, reference)
    argv = docker_command(["run", "--rm", "image"], environ={})
    check("Docker argv derives exact client, empty config and explicit host",
          argv[0] == document["client"]["selected_executable"]
          and argv[1] == "--config" and os.path.isdir(argv[2])
          and os.listdir(argv[2]) == []
          and argv[3:5] == ["--host", document["endpoint"]["address"]]
          and argv[5:] == ["run", "--rm", "image"])
    check("sg/group wrapping is never emitted", argv[0] != "sg")
    _clear_configs()
    with tempfile.TemporaryDirectory(prefix="docker-cli-tmp.") as config_root, \
            patch.dict(os.environ, {"TMPDIR": config_root}), \
            patch.object(tempfile, "tempdir", None):
        try:
            configured = docker_command(["info"], environ={})
            cfg = configured[2]
            facts = os.stat(cfg)
            check("workload client config honors TMPDIR without changing authority or permissions",
                  os.path.dirname(cfg) == config_root and os.listdir(cfg) == []
                  and stat.S_IMODE(facts.st_mode) == 0o700 and facts.st_uid == os.geteuid()
                  and configured == [document["client"]["selected_executable"], "--config", cfg,
                                     "--host", document["endpoint"]["address"], "info"])
            with open(os.path.join(cfg, "config.json"), "w") as handle:
                handle.write("{}")
            check("configured workload client directory still refuses nonempty contents",
                  refused(lambda: docker_command(["info"], environ={})))
        finally:
            _clear_configs()
        check("configured workload client directory is removed on reset", not os.path.exists(cfg))
    check("custom Docker executable refuses",
          refused(lambda: docker_argv(["info"], executable="/tmp/docker",
                                      environ={})))
    check("ambient selectors refuse without reading values",
          all(refused(lambda name=name: docker_argv(
              ["info"], environ={name: "credential-shaped-secret"}))
              for name in AMBIENT_DOCKER_ENDPOINT_KEYS))
    check("exact authority reference is enforced",
          require_authority_reference(reference) is document
          and refused(lambda: require_authority_reference(
              {**reference, "digest": "0" * 64})))
    check("authority confinement protects the daemon data root",
          document["daemon"]["docker_root_dir"]
          in authority_protected_paths())
    check("historical v2 route parser is strict and non-authorizing",
          valid_endpoint_selection("legacy-default")
          and valid_endpoint_selection(
              "host:unix:///run/user/1001/r2t/docker.sock")
          and not valid_endpoint_selection("host:tcp://localhost:2375")
          and valid_endpoint_selection("host:unix:///tmp/a?b")
          and not valid_endpoint_selection("host:unix:///tmp/a/../b"))
    real_authority_reference = _A.authority_reference
    phase_calls = []

    def fixture_authority_reference(path, *, live=False):
        phase_calls.append((path, live))
        return document, reference

    _A.authority_reference = fixture_authority_reference
    try:
        configure(authority_path=reference["path"])
        docker_argv(["ps"], environ={})
        docker_argv(["info"], environ={})
        reset_phase()
        docker_argv(["version"], environ={})
    finally:
        _A.authority_reference = real_authority_reference
    check("authority is revalidated once per explicit command phase",
          phase_calls == [(reference["path"], True),
                          (reference["path"], True)])
    configure()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(selftest())
