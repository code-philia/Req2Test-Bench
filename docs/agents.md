# Running your own system

This page covers running your own system on the tasks. Read the part for
your system:

- **A command-line agent.** `run_agent` runs it for you
  ([below](#your-own-command-line-agent)).
- **Any other system.** Your own code runs [the flow](#the-flow), with the
  project's [runtime pack](#runtime-packs) in its sandbox, and
  [collects the answer](#collecting-the-answer).

Either way, `req2test evaluate` scores the files the system writes
([evaluation.md](evaluation.md)), and the result is comparable with the
leaderboard when the system keeps to
[the generation protocol](#the-generation-protocol).

## Your own command-line agent

`req2test.inference.run_agent` runs any command-line agent that reads its
prompt on standard input. Give the command that starts the agent after `--`,
for example the path of its start script:

```sh
export DEEPSEEK_API_KEY=<your key>
python3 -m req2test.inference.run_agent --tasks ~/r2t-work/tasks.jsonl -o ~/r2t-work/my-agent \
  --env DEEPSEEK_API_KEY --allow api.deepseek.com -- ~/my-agent/run.sh
```

For a Python agent with its code, `agent.py`, and its virtual environment,
`.venv`, in `~/my-agent`, the script can be:

```sh
#!/bin/sh
here=$(dirname "$(readlink -f "$0")")
exec "$here/.venv/bin/python" "$here/agent.py" --model deepseek-flash --max-steps 50
```

Its last line sets the agent's own options. `agent.py` reads the prompt with
`sys.stdin.read()`. The script names the environment's Python because a bare
`python3` in the sandbox is the project's or the system's, without the
agent's packages. Make it executable with `chmod +x ~/my-agent/run.sh`.

For each task, `run_agent` makes a workspace
`~/r2t-work/my-agent/workspaces/<NNNN>` with the project in `repo/`, and
runs the command there as given, with the prompt on standard input. When the
agent exits, or is stopped after an hour (`--timeout`), it adds a row with
the files the agent created or changed under `repo/` to
`~/r2t-work/my-agent/predictions.jsonl`.

- The rows' `model_name_or_path` is the output directory's name, or
  `--model-name`.
- The agent's output is in `workspaces/<NNNN>.log`.
- An agent that exits non-zero gets no row and keeps its workspace.
- Running the same command again skips the tasks that have a row and
  retries the others. Give a new run a new output directory, and run one
  `run_agent` at a time per output directory.

These commands run Codex CLI with GPT-6.1 Sol, Claude Code with Claude
Sonnet 5.5, and OpenCode with DeepSeek-V4.1-Flash, with the API key exported
in the variable that `--env` names:

```sh
python3 -m req2test.inference.run_agent --tasks ~/r2t-work/tasks.jsonl -o ~/r2t-work/codex-sol \
  --env CODEX_API_KEY --allow api.openai.com \
  -- codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox --model gpt-6.1-sol
python3 -m req2test.inference.run_agent --tasks ~/r2t-work/tasks.jsonl -o ~/r2t-work/claude-sonnet \
  --env ANTHROPIC_API_KEY --allow api.anthropic.com \
  -- claude -p --dangerously-skip-permissions --model claude-sonnet-5-5
python3 -m req2test.inference.run_agent --tasks ~/r2t-work/tasks.jsonl -o ~/r2t-work/opencode-flash \
  --env DEEPSEEK_API_KEY --allow api.deepseek.com \
  -- opencode run --auto --model deepseek/deepseek-flash
```

Their flags `--dangerously-bypass-approvals-and-sandbox`,
`--dangerously-skip-permissions` and `--auto` let them run commands and edit
files without asking. The sandbox confines them instead. OpenCode takes the
provider in `--model`, while Codex calls OpenAI and Claude Code calls
Anthropic unless you configure another provider. For Codex with
DeepSeek-V4.1-Flash, use `--agent codex`. The commands were checked with
Codex CLI 0.161.0, Claude Code 2.1.312 and OpenCode 1.19.0. Codex CLI
0.153.4, the leaderboard's version, lacks GPT-6.1 Sol's settings.

Besides the workspace, the sandbox gives the agent only the following:

- **Its program.** The command must be on `PATH` or given by its path. The
  sandbox can read the command's directory, or the one above it if that is
  a `bin` directory, such as an npm or virtual-environment prefix. The
  agent's home directory is empty. Give it other files it reads with
  `--ro-bind PATH` and places it writes with `--bind PATH`, at the same
  path. A virtual environment made from a Python under your home, such as
  conda's or pyenv's, needs that Python too, for example
  `--ro-bind ~/anaconda3`.
- **Its key.** `--env NAME` passes the environment variable `NAME`.
- **Its model provider.** `--allow HOST[:PORT]` names an endpoint the agent
  may reach, on port 443 unless you give one. The agent reaches it through
  `HTTPS_PROXY`, so it must honour that variable, and the endpoint must use
  HTTPS. An endpoint on this host, such as `--allow 127.0.0.1:8000`, is
  reached at the same address, over HTTP too. For a plain-HTTP server on
  another machine, forward its port here, for example with
  `ssh -N -L 8000:localhost:8000 gpu-host`, and allow `127.0.0.1:8000`.
  Every other host is refused, and the log names it.
- **The prompt on standard input.** For an agent that takes the prompt as
  an argument, put a small script in the directory of the agent's program
  and give the script after `--`:

  ```sh
  #!/bin/sh
  exec my-agent --message "$(cat)"
  ```

  `-- sh -c 'my-agent --message "$(cat)"'` does not work, because the
  sandbox then reads `sh` but not your agent.

The prompt is the one that
[req2test/inference/prompt.py](../req2test/inference/prompt.py) builds,
which the leaderboard's runs used when their agent could run the project's
code (its rows without †). To give your agent a prompt of your own, follow
[the flow](#the-flow) with your own code. A run comparable with the
leaderboard keeps to [the generation protocol](#the-generation-protocol),
whose budget of 200 LLM calls `run_agent` counts only for `--agent codex`.
`--docker IMAGE` runs the agent in a Docker container
([below](#agents-in-containers)), and `--help` lists all the options.

## The flow

`run_agent` runs these steps for a command-line agent. A system with its own
driver runs them itself.

1. **Tasks.** Export one row per instance:

   ```sh
   mkdir -p ~/r2t-work
   req2test tasks --split eval --project python-docx --out ~/r2t-work/tasks.jsonl
   ```

   A row holds the `instance_id`, the `requirement` (Feature and Scenario),
   the `target_interfaces`, the `placement` of the answer
   ([below](#collecting-the-answer)), the `environment` the system cannot
   see ([below](#the-environment)), the `task` (the requirement and target
   interfaces as the leaderboard's agents were given them, and on
   coddy-agent the exact answer `files` and the Godog `go_suite` they
   define), and the `source_view` and `runtime_setup` commands of steps 2
   and 3. It holds no prompt, because the prompt is part of your system.
   `build_prompt(row)` in `req2test/inference/prompt.py` builds the
   leaderboard's.

2. **View.** Write the instance's source view into a new workspace. The rows
   call the view `./repo`, so the workspace is its parent directory, and
   `--out` must not exist yet:

   ```sh
   req2test views materialize --project python-docx \
     --instance python-docx/features/api-open-document.feature:13 \
     --out ~/r2t-work/ws/0000/repo
   ```

   The view is the project with the test implementations of all Scenarios
   removed and the target bodies replaced by placeholders
   ([views.md](views.md)).

3. **Runtime.** Apply the project's runtime pack to the workspace
   ([below](#runtime-packs)):

   ```sh
   req2test runtime setup --project python-docx \
     --instance python-docx/features/api-open-document.feature:13 \
     --workspace ~/r2t-work/ws/0000
   ```

4. **Generate.** Start the system in the workspace with a prompt made from
   the row. It writes its Step Definitions and helpers in `repo/`, where the
   row's `placement` says.

5. **Collect.** Turn what the system wrote into one predictions row per
   instance ([below](#collecting-the-answer)), then run `req2test evaluate`.

## Runtime packs

The workspace is runnable: the system can build the project and run its code
and tests there. A project's runtime pack holds its interpreters, build
tools, dependencies and services, such as MySQL or PostgreSQL, and runs them
in a nested bubblewrap sandbox of its own. The hidden target bodies fail
with an "implementation hidden" error, so nothing the system runs reaches
the complete implementation.

`req2test fetch` installs the packs (about 3.4 GB of downloads and 13 GB
unpacked for all eight projects). The host needs bubblewrap and must let it
create nested user namespaces. Check once per project and host that the
pack runs where the workspaces will be:

```sh
mkdir -p ~/r2t-work/ws
req2test runtime preflight --project python-docx --workspace-root ~/r2t-work/ws
```

It runs the project's version command, such as `python3 --version`, through
the pack in a throwaway attempt, prints a JSON record, and exits 1 when the
pack cannot run there.

`run_agent` does the rest. A sandbox of your own must do the following:

1. Before the system starts on an instance, run `runtime setup` (step 3 of
   [the flow](#the-flow)). It prints JSON: `binds` (`source`, `target`,
   `writable`), `path_prepend`, `home_links` (`name`, `target`),
   `runtime_pack`, and `docker_args`, the same binds as `docker run` options
   ([below](#agents-in-containers)).
2. Make each bind, read-only unless `writable`, and put `path_prepend` first
   on `PATH`. In the system's home directory, make each `home_links` entry a
   link called `name` to `target`. Keep the workspace at the absolute path
   given to `runtime setup`: a mount elsewhere, such as
   `-v <workspace>:/workspace`, makes every pack command fail.
3. Provide `bash`, `bwrap`, a writable `/tmp` and nested user namespaces, and
   a loopback network of the sandbox's own. The CoreShop, PrestaShop and
   Sylius packs start MySQL on `127.0.0.1:3306`, and the e-petitions pack
   PostgreSQL on `127.0.0.1:5432`, so attempts that share the host's network
   collide with each other and with a database on the host.
4. Let the network reach the model provider and nothing else
   ([the generation protocol](#the-generation-protocol)), in particular not
   the upstream repositories ([below](#what-the-system-may-and-may-not-see)).
5. Start a system whose launcher begins with `#!/usr/bin/env node` or
   `#!/usr/bin/env python3`, as Codex CLI's does, with its own interpreter
   rather than through `PATH`. The e-petitions pack wraps `node`, and the
   python-docx pack `python3`, to run them in the pack's own sandbox, which
   cannot see the system's installation.

To check your sandbox, set up a throwaway attempt with `runtime setup`,
start your sandbox on it, and run the `probe` command that
`runtime preflight` printed from `repo/`. It must exit 0.

### Agents in containers

A system can also run in a Docker container. Its image needs bash and
bubblewrap besides the system, and python3 for `run_agent`'s network bridge.
[docker/agent.Dockerfile](../docker/agent.Dockerfile) is a Debian base to
install a system on. `runtime preflight --docker IMAGE` checks the pack in a
container of that image:

```sh
docker build -t r2t-agent-base -f docker/agent.Dockerfile docker
req2test runtime preflight --project python-docx --workspace-root ~/r2t-work/ws \
  --docker r2t-agent-base
```

`run_agent --docker IMAGE` runs its agent in such a container, for example
`--docker my-agent` with an image built `FROM r2t-agent-base`. To start one
yourself, put the `docker_args` that `runtime setup` printed before the
image name. They mount the binds at the same paths, start in the workspace,
and set `PATH` to the pack's wrappers followed by Docker's default `PATH`,
so install the system on that default `PATH`. They also turn off Docker's
system-call filter, AppArmor profile and masked `/proc` paths
(`--security-opt seccomp=unconfined`, `apparmor=unconfined` and
`systempaths=unconfined`), which the pack's runner needs to make its own
sandbox. In addition:

- Make the `home_links` links in the container's home directory.
- A login shell (`bash -l`, which some systems run their commands in)
  resets `PATH` from `/etc/profile`. The base image's
  `/etc/profile.d/r2t-rt.sh` puts the pack's wrappers back, and an image of
  your own needs the same.
- On a rootful Docker daemon, pass `--user "$(id -u):$(id -g)"`, so that the
  files the system writes in the workspace stay yours. On a rootless daemon
  the container's root is already you, but the packs' PostgreSQL and MySQL
  refuse to run as root. There, start the system as your IDs in a user
  namespace of its own by putting
  `bwrap --unshare-user --uid "$(id -u)" --gid "$(id -g)" --dev-bind / / --`
  before its command. Its files are still yours on the host.

## The environment

A row's `environment` holds what the system cannot see in its workspace:

| Field | Meaning |
|---|---|
| `project`, `platform` | The project's name, and the platform with its language and framework versions |
| `language`, `framework` | The answer's language and its BDD framework, for example `PHP` and `Behat` |
| `removed` | What the view removed, for example `Behat test code` |
| `retained` | What test code the view keeps besides the production code and the other `.feature` files |
| `run` | A sentence naming the command that runs one Scenario in the workspace, or `null` where the project's own tools do |
| `facts` | Facts about the framework, the harness and the workspace, one sentence or short paragraph each |

## Collecting the answer

The answer is the files the system created or changed under `repo/`, with
paths relative to `repo/`, such as `features/steps/api.py`. Take the
`before` snapshot after `runtime setup`, so that the files `runtime setup`
writes do not count as the system's. The row's `placement` says where to
write and which suffixes the answer has:

| Field | Meaning |
|---|---|
| `acceptance_mode` | `directory`: files under `acceptance_root` are accepted. `item_path` (coddy-agent): only the exact file paths in `task.files` are accepted |
| `acceptance_root` | The directory, relative to `repo/`, under which answer files are accepted (`null` for `item_path`). For Kapua it depends on the instance |
| `path`, `placement_hint` | Where to put the answer, relative to the workspace and to `repo/` |
| `rules` | The collection rules, one bullet each: what is accepted, what is discarded, and the wiring file where there is one |
| `suffixes` | The suffixes of the answer's files: the project's language, plus `.feature`. A feature file of the view that the system changed is collected wherever it is, so that the edit is reported |
| `extra_names` | Extra file names that count as part of the answer. CoreShop and Sylius: `behat_services.yml`, which registers the answer's Behat contexts |
| `wiring_file` | That wiring file's path relative to the workspace, or `null` |
| `artefact_noun` | What the answer is called, for example `step-definition code` |

Scoring keeps the files that the project's boundary
(`benchmark/config/boundary_*.yml`) classifies as removable test code, and
the wiring file, and discards the rest, such as the caches and build output
that a test run leaves. The removable test code holds the `acceptance_root`
and, on Kapua and Algorand SDK, reaches beyond it, for example to the
upstream step modules. On Kapua, write where the `placement` says: a file in
another test module's package is accepted but not run, so the Scenario's
steps stay undefined.

`run_agent` collects the answer with two functions of
`req2test.inference.run_agent`, which a driver of your own can import or
adapt: `snapshot(repo, placement, removable(project))` after
`runtime setup`, and `prediction(task, repo, before, model, removable(project))`
once the system has ended. `removable(project)` tells which files are
removable test code, and the leaderboard's runs collected all of them.

### What the harness does with the answer

The harness keeps what the prompts promise:

- **coddy-agent.** Some retained unit tests call helpers that were declared
  only in removed files. Each such helper that the answer does not declare
  is copied from the ground truth into the execution copy.
- **PrestaShop and Sylius.** A Behat context class the answer returns joins
  the item's suite, also when an upstream suite uses its class name, unless
  an earlier returned class already defines one of its step patterns. A
  step it defines twice with a retained context is a binding failure.
- **CoreShop and Sylius.** Every returned class is registered as a public,
  autowired and autoconfigured service.

Each execution row records what this changed
([outputs.md](outputs.md#run-directory)).

## What the system may and may not see

Give the system only its workspace, the runtime's binds and its prompt.
Never expose:

- `$REQ2TEST_HOME/kits/`, `$REQ2TEST_HOME/views/` and `$REQ2TEST_HOME/data/`,
  which hold the full project, the unhidden source and the ground-truth
  tests
- `$REQ2TEST_HOME/runtime-packs/`, except through the binds that
  `runtime setup` prints
- this clone, earlier run directories, and the upstream repositories named
  by the dataset's `repo_url`, which contain the developers' tests

A bind for the agent's own files must not hold any of these either.
`run_agent` refuses to start when the agent's installation, a `--bind` or a
`--ro-bind` holds `$REQ2TEST_HOME`, the output directory, this clone or
your home directory.

## The generation protocol

A run is comparable with the leaderboard only when the system follows this
protocol on the whole `eval` split:

- **Input.** Each generation receives a prompt made from its task row: the
  requirement, the target interfaces, the placement and the environment.
  The prompt is part of the system and may be its own, but it gives no
  information about the instance beyond the row and the workspace. The
  leaderboard's prompt (`build_prompt(row)`) gives no advice on how to work
  and does not tell the agent to run, check or iterate on its tests.
- **One scored generation per instance.** A generation is re-run only when a
  provider-side limit or the benchmark's environment interrupted it, never
  because of its outcome. Do not submit an interrupted generation as a
  failure.
- **No evaluator feedback.** The system may inspect the view and run the
  project's code and tests, but the harness returns no execution feedback.
  Only the final files are evaluated, once.
- **Sandbox.** A bubblewrap sandbox with the runtime pack's binds and
  loopback, whose network reaches only the model provider, with a 3,600 s
  wall-clock limit per generation.
- **Tool set.** The system's shell is bash. Outside the runtime pack it
  reaches no project toolchain (Go, PHP, Ruby, a JDK, Maven or Gradle), no
  ripgrep and no Python that can import lxml or run behave, so what it can
  run does not depend on the host. `run_agent` hides these host tools in
  its bubblewrap sandbox, and for `--agent codex` also the ripgrep that
  Codex installs beside itself. Like the leaderboard's sandbox, it gives the
  system no `/etc/passwd`, so Codex, which takes its shell from that file
  rather than from `SHELL`, runs bash.
- **Budget.** At most 200 LLM calls. Each agent uses its native mechanisms
  for repository inspection, file editing and command execution.
  `run_agent --agent codex` stops Codex at its 201st call, as the
  leaderboard's harness did, and scores what it wrote by then. A system
  given after `--` must keep to the budget itself.
- **Population.** All 2,051 `eval` instances are generated and evaluated
  ([population](evaluation.md#population)).

The leaderboard's configurations used Codex CLI 0.153.4 with
DeepSeek-V4.1-Flash and 0.159.0 with GPT-6.1 Sol. The paper's rows used
OpenHands (openhands-sdk 1.34.0), Aider 0.86.2, Codex CLI 0.153.4 (0.157.1
for GPT-6 Sol) and Claude Code (2.1.274 with DeepSeek-V4.1-Flash, 2.1.292
with Claude Sonnet 5.5).

A system that differs, for example one that gets more calls, is a different
configuration. Report it as such.

## Cost of generation

Cost and resources per generation of the paper's runs. Costs are list prices
from recorded token counts. The time and LLM calls of Aider and OpenHands
cover the six and five projects that record them.

| | Aider | OpenHands | Claude Code | Claude Code | Codex CLI | Codex CLI | Codex CLI | Codex CLI |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Model, reasoning | DS, off | DS, off | DS, high | Sonnet, high | DS, off | DS, high | Luna, high | Sol, high |
| $ per generation | 0.061 | 0.187 | 0.158 | 0.680 | 0.121 | 0.236 | 0.039 | 1.16 |
| $ per kill-complete test | 1.56 | 1.21 | 0.49 | 1.99 | 0.55 | 0.74 | 0.15 | 3.92 |
| Time (minutes) | 2.0 | 5.7 | 6.2 | 2.7 | 4.1 | 8.7 | 3.2 | 3.1 |
| LLM calls | 2.0 | 137.8 | 88.9 | 22.3 | 96.6 | 102.4 | 23.6 | 16.8 |

DS is DeepSeek-V4.1-Flash, Sonnet is Claude Sonnet 5.5, Luna and Sol are
GPT-6 Luna and GPT-6 Sol. A configuration is 2,051 generations.
