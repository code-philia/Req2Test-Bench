"""Engine patch P1: a worker's container is used only once its entrypoint
has started its command, `tail -f /dev/null`.  e-petitions' entrypoint
starts PostgreSQL first, and a command run at once found it not yet
listening, or still starting up."""
import subprocess
import time
from types import SimpleNamespace

import pytest
from kitfixture import bwrap_usable

from req2test.execute import ensure_engine_path

ensure_engine_path()
from r2t.bench import worker as W  # noqa: E402


def test_the_wait_runs_in_the_container_and_refuses_one_that_stopped(monkeypatch):
    calls = []

    def docker(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(W, "_docker", docker)
    W.wait_for_command("w0", docker_group=False, timeout=5)
    [(argv, kwargs)] = calls
    assert argv == ["exec", "w0", "sh", "-c", W._REACHES_COMMAND, "sh", "5"]
    assert kwargs == {"docker_group": False, "timeout": 65}

    stopped = SimpleNamespace(returncode=1, stdout="",
                              stderr="Error response from daemon: container w0 is not running")
    monkeypatch.setattr(W, "_docker", lambda argv, **kwargs: stopped)
    with pytest.raises(W.WorkerRefused, match="is not running"):
        W.wait_for_command("w0", timeout=5)

    def hangs(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(W, "_docker", hangs)
    with pytest.raises(W.WorkerRefused, match="within 5s"):
        W.wait_for_command("w0", timeout=5)


def reaches(command: str, seconds: int) -> tuple:
    """The script's exit status and time, run in a PID namespace of its own
    after `command` is started in the background."""
    start = time.monotonic()
    done = subprocess.run(
        ["bwrap", "--die-with-parent", "--unshare-pid", "--dev-bind", "/", "/",
         "--proc", "/proc", "sh", "-c", f'{command} & sh -c "$0" sh {seconds}',
         W._REACHES_COMMAND], capture_output=True, text=True, timeout=60)
    return done.returncode, time.monotonic() - start


@pytest.mark.skipif(not bwrap_usable("--unshare-pid"), reason="needs bubblewrap")
def test_the_script_waits_for_the_command_wherever_it_runs():
    # An entrypoint that prepares for two seconds, then execs the command.
    status, seconds = reaches("sh -c 'sleep 2; exec tail -f /dev/null'", 30)
    assert status == 0 and 2 <= seconds < 15
    # The command under an init, as with --init or tini.
    assert reaches("sh -c 'tail -f /dev/null; true'", 30)[0] == 0
    # An entrypoint that never gets there.
    status, seconds = reaches("sleep 30", 2)
    assert status == 1 and seconds < 15
