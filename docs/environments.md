# Execution environments

Every test runs in a pool of worker containers under a rootless Docker
daemon. `evaluate` and `validate` bring the pool up and retire it
themselves. `req2test env` does the same by hand.

## Prerequisites

- Linux x86_64 with cgroup v2, and the memory controller delegated to your
  user session (`cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers`
  lists `memory`). The coddy-agent and PrestaShop pools need it for their
  memory caps.
- Rootless Docker for the current user: `dockerd-rootless.sh`,
  `rootlesskit`, `slirp4netns`, `newuidmap`/`newgidmap`, and subordinate ID
  ranges for your user in `/etc/subuid` and `/etc/subgid`. A daemon you
  name with `--docker-host` must use the classic overlay2 image store, not
  the containerd store. By default `req2test` starts its own daemon, which
  does.
- A systemd user session (`systemctl --user` works), with lingering enabled.
  Without one, start a rootless daemon yourself and pass `--docker-host`.
- `docker` (the CLI), `git`, `zstd`, `tar`, and Python 3.10+ with `venv`
  (`apt install python3-venv` on Debian and Ubuntu).
- A git clone of this repository, not a source archive, installed with
  `pip install -e .` in a virtual environment. It must stay clean, untracked
  files included, because the engine records its commit.
- `$REQ2TEST_HOME` (default `~/.req2test`) and every directory above it
  writable only by you or root.
- Disk: about 0.2–1.2 GB per project once installed, plus its Docker images.
- On the host where your system generates tests: bubblewrap, allowed to
  create nested user namespaces, for the runtime packs
  ([agents.md](agents.md#runtime-packs)); and for `run_agent`, `python3`
  in the system directories, which runs its network bridge in the sandbox.

Evaluation needs no JDK, Go or bubblewrap. Those are only for the engine
self-tests ([engine.md](engine.md#engine-self-tests)).

## Commands

```sh
req2test env up --project P [--workers K] [--docker-host unix:///PATH]
req2test env status --project P
req2test env down --project P [--nonce N | --all]
req2test env stop-daemon
```

- `env up` loads the kit's images, starts the project's database if it has
  one, provisions K workers and runs a ground-truth test on each of them.
  If a step fails, the environment is recorded as `failed` and the error
  names the `env down` command that retires it.
- `env down` removes a pool. With more than one live pool for the project,
  name it with `--nonce`, or retire them all with `--all`.
- `env stop-daemon` stops this home's own Docker daemon. Its loaded images
  stay on disk for the next start.

From Python:

```python
from req2test import env
handle = env.up(kit, workers=4, run_dir=run_dir)   # EnvHandle
argv = handle.global_args(i)    # engine global options for a run on worker i
env.down(handle)
```

## Layout under `$REQ2TEST_HOME` (default `~/.req2test`)

```
data/, kits/, views/, runtime-packs/    installed by `req2test fetch`
docker/                                 this home's rootless Docker daemon
engine/                                 the kits' inputs, staged for the engine
envs/<project>/<nonce>/                 one environment: env.json, logs, workers
runs/<run-id>/                          evaluation runs (outputs.md)
```

## Projects

| Project | Database | Memory cap | Default K |
| --- | --- | --- | ---: |
| python-docx | none | none | 16 |
| algorand-sdk | none | none | 16 |
| kapua | none | none | 28 |
| coddy-agent | none | 16 GiB, no swap | 40 |
| coreshop | MySQL 8.4.10 | none | 24 |
| sylius | MySQL 8.4.10 | none | 16 |
| prestashop | MySQL 8.0 | 4 GiB, no swap | 24 |
| e-petitions | none | none | 24 |

The default pool sizes are for a 64-CPU host. On a smaller host, pass a
lower `--workers`. Kapua's load is about 3.3 CPUs per worker. An overloaded
host can time tests out, and on Kapua, PrestaShop and e-petitions a mutant
run that times out counts as a kill ([metrics.md](metrics.md)).
