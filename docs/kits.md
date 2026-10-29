# Evaluation kits, releases and `req2test fetch`

The dataset, the evaluation kits, the source views and the runtime packs
are release folders of the Hugging Face dataset repository
[code-philia/Req2Test-Bench](https://huggingface.co/datasets/code-philia/Req2Test-Bench),
one folder per release under `releases/<tag>/`. None of them is in this git
repository. They total about 7.2 GB, and the
[dataset card](https://huggingface.co/datasets/code-philia/Req2Test-Bench#release-files)
gives the size of each kind.

## Releases

| Release | Content |
| --- | --- |
| `dataset-v1.1` | The task rows and ground-truth tests ([dataset.md](dataset.md)) |
| `kit-<project>-v<version>` | The project's evaluation kit ([below](#what-a-kit-holds)) |
| `kit-shared-v1.0` | The MySQL 8.4.10 image that the CoreShop and Sylius kits use |
| `views-<project>-v2.0` | The project's target-hidden source views ([views.md](views.md)) |
| `runtime-<project>-v1.1` | The project's runtime pack ([agents.md](agents.md#runtime-packs)) |

The releases hold benchmark inputs only. Run logs, trajectories and
generated tests are not in them.

## What a kit holds

`req2test fetch` installs each kit under
`$REQ2TEST_HOME/kits/<project>/<version>/`:

- `kit.json`: the kit's header, with every file's sha256;
- `exec/`: the worker Docker image, the project seed and the ground-truth
  execution data;
- `behaviour/`: the ground-truth run and the instance lists that API F1 and
  coverage use;
- `mutation/`: the mutants, each instance's pool with its ground-truth
  outcomes, and the scoring rules (`rules.json`).

The PrestaShop seed, mutation archive and views contain the
`app/config/parameters.php` of a throwaway local test install (a generated
API key and cookie secrets, database login root/root). The workspace needs
it to start, and it grants access to nothing outside the container.

## `req2test fetch`

```sh
req2test fetch --split eval --project python-docx
```

Without `--project`, `fetch` installs all eight projects. Every file is
checked against a sha256 pinned in the harness, and a mismatch is refused.
An installed kit or view is never overwritten. No account or token is
needed.

| Option | Meaning |
| --- | --- |
| `--split full` | also install the `full` split's rows |
| `--dataset-only`, `--kits-only`, `--views-only`, `--packs-only` | fetch only that part (default: all four) |
| `--endpoint URL` | a Hugging Face mirror (default `$HF_ENDPOINT`, else `https://huggingface.co`) |
| `--download-only DIR` | download and check into `DIR`, install nothing |
| `--from-dir DIR` | install from `DIR`, with no network |
| `-j N` | parallel downloads (default 4) |

## Hosts without Internet access

1. On a connected host, download what one project needs, or every release
   with the Hugging Face CLI:

   ```sh
   req2test fetch --split eval --project python-docx --download-only DIR
   ```

   ```sh
   hf download code-philia/Req2Test-Bench --repo-type dataset --revision 0dfb049d5c9bfd0d8c98d23c22af7d02ee6865a3 --include "releases/*" --local-dir DIR
   ```

   From the clone's root, also download the harness's Python dependencies
   as wheels: `python3 -m pip download -d WHEELS . setuptools`. Use the same
   Python version as the offline host.
2. Copy `DIR`, `WHEELS` and a clone of this repository to the offline host,
   for example with `rsync -a`.
3. On the offline host, install the harness and the data:

   ```sh
   python3 -m venv .venv && . .venv/bin/activate
   python3 -m pip install --no-index --find-links WHEELS -e .
   req2test fetch --split eval --project python-docx --from-dir DIR
   ```
