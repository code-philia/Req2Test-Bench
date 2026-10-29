# Notices

The Req2Test-Bench harness, its tooling and the benchmark metadata in this
repository are released under the MIT License ([LICENSE](LICENSE)).

## Upstream projects

Task content is derived from the upstream projects below and remains under
their licences. That content is the requirements (Gherkin features), the
source snapshots and source views, the ground-truth tests, the mutants, and
the evaluation kits built from them. The dataset and the kits record the
pinned commit of every snapshot.

| Project in the benchmark | Upstream repository | Pinned commit | Licence |
|---|---|---|---|
| python-docx | [python-openxml/python-docx](https://github.com/python-openxml/python-docx) | `e45454602b53` | MIT |
| algorand-sdk | [algorand/java-algorand-sdk](https://github.com/algorand/java-algorand-sdk) (code) and [algorand/algorand-sdk-testing](https://github.com/algorand/algorand-sdk-testing) (features) | `4e38dadc4eec` / `7c67284b5267` | MIT / MIT |
| coddy-agent | [coddy-project/coddy-agent](https://github.com/coddy-project/coddy-agent) | `5fadd23573ba` | MIT |
| e-petitions | [alphagov/e-petitions](https://github.com/alphagov/e-petitions) | `8968fc9c24a2` | MIT |
| sylius | [Sylius/Sylius](https://github.com/Sylius/Sylius) | `70cf6ca686ec` | MIT |
| kapua | [eclipse-kapua/kapua](https://github.com/eclipse-kapua/kapua) | `15c3c1e2c44f` | EPL-2.0 |
| prestashop | [PrestaShop/PrestaShop](https://github.com/PrestaShop/PrestaShop) | `2961c63ece3c` | OSL-3.0 (core), AFL-3.0 (modules) |
| coreshop | [coreshop/CoreShop](https://github.com/coreshop/CoreShop) | `05bf7af946c9` | CoreShop Commercial License (CCL), with Pimcore under the Pimcore Open Core License (POCL). See [CoreShop](#coreshop) |

The licence of each upstream project is the one stated in its repository at
the pinned commit. Dependencies that a project installs (Composer, Maven, Go,
Ruby and Python packages) are under their own licences.

## CoreShop

CoreShop content is included in this release. CoreShop at the pinned
commit is under the [CoreShop Commercial License (CCL)](https://github.com/coreshop/CoreShop/blob/05bf7af946c919896d0807e4f0c7af37f446653b/LICENSE.md),
and Pimcore, which CoreShop requires (pimcore/pimcore v12.3.9 in the
Composer lock of the image recipe), is under the
[Pimcore Open Core License (POCL)](https://github.com/pimcore/pimcore/blob/355ac351e1a672e92246b2cd54763bfa59158cb4/LICENSE.md).
Neither is an open-source licence. Those terms govern that content, not the
MIT License of this repository.

The CoreShop content is the CoreShop kit, views, runtime pack and
ground-truth tests in the data releases, and the requirement text of its
items in `benchmark/items.jsonl` and `benchmark/release/eval100.jsonl` in
this repository. The CoreShop image in the kit was built with a patch that
disables Pimcore's product-key validation, so that CoreShop runs offline.

## Docker images

The evaluation kits contain Docker images. They include an operating system
and third-party packages (language runtimes, database servers, build tools
and project dependencies), each under its own licence.

## Runtime packs

The runtime packs contain an operating system userland and third-party
packages (language runtimes, build tools, MySQL and PostgreSQL servers and
project dependencies), each under its own licence. The CoreShop runtime pack
contains CoreShop and Pimcore, under the licences given in
[CoreShop](#coreshop).

## Codex model catalog

`req2test/data/codex_models.json` is the Codex model catalog of the
leaderboard's Codex runs. The model instructions in it are Codex CLI's own,
from [openai/codex](https://github.com/openai/codex), under the Apache
License 2.0.

## Evaluation engine

`benchmark/` is the benchmark's execution engine, released under the MIT
License. Its test fixtures that come from upstream projects keep their own
licence files where they have one.
