# mythical-ctl

The installer and lifecycle CLI for the **mythicalOS** family of local-first containers.

> **Status: scaffolding — the lifecycle commands are not implemented yet.** `mythical-ctl` today
> answers `--version` and `--help` and nothing else. What is built and tested is the foundation the
> verbs will stand on: the `~/.mythical/` layout and its ownership rules, a single atomic
> fail-closed state ledger, a family operation lock, the two-config-file layer with its
> non-executing parser, and a hermetic test harness. Everything below describing
> `install`/`start`/`stop` is the **design**, not shipped behaviour — read it as what this is for,
> not what it does today. The products themselves are not published yet either.
>
> The install command below **does** work — but it is served by
> [get.mythicalos.ai](https://get.mythicalos.ai), which installs product containers directly; it
> does not yet download or use `mythical-ctl`. Until a product's image publishes it will tell you
> so and install nothing.

It is designed to be **product-agnostic**: everything specific to a product (image reference,
ports, volumes, environment) will arrive from a manifest that product ships, never from logic baked
in here. One command will install a product, keep its configuration in a predictable place, and
manage it afterwards — `install`, `start`, `stop`, `recreate`, `status`, `uninstall`.

```sh
# fetch, CHECK, run — deliberately not a one-liner (see below).
# Subshell: without it, a failed download would exit your shell.
# Explicit gates, not `set -e`: errexit is suppressed inside a subshell used
# in an if/&&/|| context, so it cannot be relied on here.
(
  tmp=$(mktemp) || exit 1
  trap 'rm -f "$tmp"' EXIT

  # BOTH gates: curl must succeed AND the status must be exactly 200
  code=$(curl -fsS --proto '=https' --max-redirs 0 \
              -o "$tmp" -w '%{http_code}' \
              https://get.mythicalos.ai/brokkr) \
    || { echo "download failed — refusing to run it"; exit 1; }
  [ "$code" = 200 ] || { echo "unexpected HTTP $code — refusing to run it"; exit 1; }

  bash "$tmp"
)
```

## Why it exists

Installing several products should not mean learning several installers. Before this existed, each
product carried its own install script with its own conventions — different volume names, different
environment variables, different ideas about where configuration lives. A user who installed two of
them met two different models, and the shared parts drifted apart with every change.

`mythical-ctl` is that common half, written once: container-runtime preflight, the `~/.mythical/`
layout, reading and validating configuration, volume and bind lifecycle, and the lifecycle verbs.
Products contribute a manifest describing themselves, and nothing more. That is the **design** — of
it, the layout and the configuration layer are built and tested today; the preflight, the volume and
bind lifecycle and the verbs are not (see the status note at the top).

## One place for everything you edit

The planned layout — the ownership rules below are implemented (`lib/layout.sh`), the mounting is
not, because nothing here mounts anything yet:

```
~/.mythical/
  mythical.conf        host-only configuration and bootstrap secrets — to be never mounted
  <product>.conf       per-product settings — to be mounted into that product's container
  bin/                 this CLI, and its siblings
  <product>/           generated artifacts, owned by the installer
  .state/              lock + ledger, owned by the installer — not an editing surface
  transcripts/ logs/   product data
```

Both files are `KEY=value` text. They are **never** executed — `mythical-ctl` parses them with a
strict non-executing reader that allowlists keys and validates values by type, so a line like
`KEY=$(...)` is refused rather than run. That reader is built and tested today.

The **split between the two files** is the design, not shipped behaviour, for the same reason as
everything else above: `mythical.conf` is to stay host-only and never be mounted into any container;
`<product>.conf` is to be the only file a product can see or write; and the code that eventually
launches a container is to build its arguments without reading any value out of it. None of that is
enforced here yet, because nothing in this repository mounts a file or launches a container — those
obligations belong to the code that does, and this repository does not yet contain it. The format
itself is specified in [`docs/CONFIG-FORMAT.md`](docs/CONFIG-FORMAT.md).

Nothing is scattered across your home directory: every file you are expected to read or edit is
in there.

**It is not the whole install, though.** Product state — and each product's own secrets store —
lives in named container volumes, and the containers, images and shared network live in your
container runtime. None of that is in this directory. So:

- **Copying `~/.mythical/` is not a backup.** The data and the runtime secrets are not in it — a
  complete backup has to include the named volumes as well. (There is no backup command; the
  documented volume-aware procedure will ship with the lifecycle commands.)
- **Deleting `~/.mythical/` is not an uninstall.** The containers keep running.

**Your data must never be collateral — that is the rule the installer is being built to.** It will
create what is missing and read what already exists; it will not overwrite a configuration file you
have edited, and it will not delete transcripts, logs, or any directory you bound, so re-installing
on a machine that has been in use for a year is meant to be safe. Today this is enforced only where
there is code to enforce it: `mi_zone` classifies every path into an ownership class, the layout
helper creates missing directories and touches nothing else, and the config layer is additive by
construction — it appends a key that is absent, refuses to change one that is already set to
something else, and leaves every other byte, comment and blank line exactly as it found them.
**Do not read it as a guarantee over your data yet** — nothing here touches a transcript or a log at
all. The only files it writes are the two configuration files and its own bookkeeping under `.state/`
(the operation lock and the state ledger), which is the installer's, not an editing surface.

## Siblings

The `mythical-` prefix is a namespace, not just a name. `bin/` is structured so that focused
companion binaries can live alongside this one rather than accreting into it — the CLI should stay
small enough to read.

## Requirements

**To run the CLI as it stands:** bash, and nothing else. It answers `--version` and `--help`, and its
library layer needs only bash builtins, the usual POSIX text tools, and `sha256sum` or `shasum -a 256`.

**A container runtime** is required by the lifecycle verbs, which are not implemented yet — so it is a
requirement of the design, not of this release. It is listed here because it is the reason this is
written in shell at all: no language runtime is required to install a product.

**To install**, you additionally need **`curl`** and **`mktemp`** — the sequence above downloads the
bootstrap to a temp file and checks its HTTP status before executing anything, rather than piping a
response straight into a shell.

**What is verified, and what is not.** The bootstrap installs each product image **pinned by
content digest** (`@sha256:…`), which the container runtime checks on pull: if the bytes are not the
bytes that were pinned, the pull fails and the installer **stops rather than installing
unverified bytes**. A product with no published digest yet is reported as not launched and is not
installed. The bootstrap script *itself* is authenticated by TLS to a known origin, not by a
separate signature — that is a deliberate, stated limit of this model, not an oversight.

### Why this is not a one-liner

`curl … | bash` cannot reject a redirect. Without `-L`, curl does not *follow* a redirect — but
it does not fail on one either: `-f` acts on 4xx and 5xx, so a `3xx` response is transferred
like any other and **its body goes straight into your shell**. Anyone who controls a redirect
controls that body. `--max-redirs 0` bounds following, not status handling.

Downloading first makes the status checkable before anything executes. It is one extra line,
and it is the difference between "we verify everything" and "we verify everything after the
first thing already ran".

`wget` is not supported here either: no flag constrains every hop of a redirect chain, so an
`https → http → https` chain is undetectable.

(Bash specifically, not POSIX `sh`: the CLI uses `set -o pipefail` and other bash features. Bash
is present by default on macOS and every mainstream Linux distribution; where it is not — Alpine,
some minimal images — it is a one-package install.)

## Development

The test runner is vendored as a git submodule, so **clone with submodules** — a plain `git clone`
leaves `vendor/bats-core/` empty and the unit tests cannot run:

```sh
git clone --recurse-submodules https://github.com/mythicalOS/mythical-ctl.git
# already cloned without it:
git submodule update --init
```

The checks CI runs, which you can run identically:

```sh
shellcheck -x bin/* lib/*.sh tests/*.sh tests/harness/* tools/*.sh  # lint (zero findings expected)
./tests/smoke.sh                                                    # entrypoint smoke
vendor/bats-core/bin/bats tests/unit                                # unit tests

# and the same smoke suite against the artifact a release actually publishes
tools/bundle.sh dist/mythical-ctl
shellcheck dist/mythical-ctl
MCTL_BIN="$PWD/dist/mythical-ctl" ./tests/smoke.sh
```

`lib/` holds the shipped shell libraries; `tests/harness/` holds test-only helpers — a fake
container runtime and filesystem-snapshot assertions — which shipped code never sources.

A release does **not** publish `bin/mythical-ctl` as it sits here. `tools/bundle.sh` inlines
`lib/*.sh` into the entrypoint's `mctl:modules` region and publishes a single self-contained file,
because the installed layout is exactly one file — one artifact, one digest, one attestation, and
no directory beside the installed CLI for it to source code out of on every later run. The bundle
is byte-reproducible from a given tree, so a published checksum is one anyone can re-derive.

## Licence and the paid tier

`mythical-ctl` is open source under **Apache-2.0**, and so are the products it installs, as they
are published. No part of the installer is withheld from the open-source build: there is no reduced
"community edition" of it, and no feature here is withheld from the open-source build.

The commercial side of mythicalOS is a **separate, private, hosted service** — it is not a
restricted version of anything in this repository, and nothing here calls into it. Running the
open-source products, including running them for other people as a paid hosted offering of your
own, is permitted by Apache-2.0 and is not something this project asks you to license separately.

Contributions are welcome anywhere in this repository. See [CONTRIBUTING.md](CONTRIBUTING.md) —
we use DCO sign-off, not a CLA.

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The licence covers the code, not the
names and branding — see [`TRADEMARK.md`](TRADEMARK.md).
