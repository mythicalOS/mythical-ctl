# mythical-ctl

The installer and lifecycle CLI for the **mythicalOS** family of local-first containers.

One command installs a product, keeps its configuration in a predictable place, and manages it
afterwards — `install`, `start`, `stop`, `recreate`, `status`, `uninstall`. It is deliberately
**product-agnostic**: everything specific to a product (image reference, ports, volumes,
environment) arrives from a manifest that product ships, never from logic baked in here.

```sh
curl -fsSL https://get.mythicalos.ai | bash          # choose interactively
curl -fsSL https://get.mythicalos.ai/brokkr | bash   # a specific product
```

> **Status: pre-launch.** The product images are not published yet. The command surface below is
> specified but not implemented — this repository currently carries the project scaffolding, its
> licence and community files, and CI. Until the images are public, any install attempt reports
> that the product has not launched yet rather than failing with a registry error.

## Why it exists

Installing several products should not mean learning several installers. Before this existed, each
product carried its own install script with its own conventions — different volume names, different
environment variables, different ideas about where configuration lives. A user who installed two of
them met two different models, and the shared parts drifted apart with every change.

`mythical-ctl` is the common half, written once: container-runtime preflight, the `~/.mythical/`
layout, reading and validating configuration, volume and bind lifecycle, and the lifecycle verbs.
Products contribute a manifest describing themselves, and nothing more.

## One place for everything you edit

```
~/.mythical/
  mythical.conf        host-only configuration and bootstrap secrets — never mounted
  <product>.conf       per-product settings — mounted into that product's container
  bin/                 this CLI, and its siblings
  <product>/           generated artifacts, owned by the installer
  transcripts/ logs/   product data
```

Nothing is scattered across your home directory: every file you are expected to read or edit is
in there.

**It is not the whole install, though.** Product state — and each product's own secrets store —
lives in named container volumes, and the containers, images and shared network live in your
container runtime. None of that is in this directory. So:

- **Copying `~/.mythical/` is not a backup.** The data and the runtime secrets are not in it. Use
  `mythical-ctl` to back up, so the volumes are included.
- **Deleting `~/.mythical/` is not an uninstall.** The containers keep running. Use
  `mythical-ctl uninstall`.

**Your data is never collateral.** The installer creates what is missing and reads what already
exists. It does not overwrite a configuration file you have edited, and it does not delete
transcripts, logs, or any directory you bound — re-installing on a machine that has been in use
for a year is safe.

## Siblings

The `mythical-` prefix is a namespace, not just a name. `bin/` is structured so that focused
companion binaries can live alongside this one rather than accreting into it — the CLI should stay
small enough to read.

## Requirements

**Bash** and a container runtime. Nothing else — no language runtime is required to install a
product, which is why this is written in shell.

(Bash specifically, not POSIX `sh`: the CLI uses `set -o pipefail` and other bash features. Bash
is present by default on macOS and every mainstream Linux distribution; where it is not — Alpine,
some minimal images — it is a one-package install.)

## Open core

`mythical-ctl` is open source under **Apache-2.0**, and so are the products it installs. What you
get from this repository is the whole installer: there is no reduced "community edition" of it, and
no feature here is withheld from the open-source build.

The commercial side of mythicalOS is a **separate, private, hosted service** — it is not a
restricted version of anything in this repository, and nothing here calls into it. Running the
open-source products, including running them for other people as a paid hosted offering of your
own, is permitted by Apache-2.0 and is not something this project asks you to license separately.

Contributions are welcome anywhere in this repository. See [CONTRIBUTING.md](CONTRIBUTING.md) —
we use DCO sign-off, not a CLA.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
