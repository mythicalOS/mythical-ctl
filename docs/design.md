# mythical-ctl — design and behaviour

The reference detail behind the [README](../README.md): the layout and its ownership rules, the
config-file model, the authenticated-document trust chain, exactly what backup/uninstall/status do,
and why the install sequence is deliberately not a one-liner.

`mythical-ctl` is **product-agnostic** by design: everything specific to a product — image reference,
ports, volumes, environment — arrives from a manifest that product ships, never from logic baked in
here. Products contribute a manifest describing themselves, and nothing more.

## One place for everything you edit

The layout is implemented in `lib/layout.sh`; the CLI mounts each product's configuration and volumes
into its container per that product's manifest.

```
~/.mythical/
  mythical.conf        host-only configuration and bootstrap secrets — never mounted
  <product>.conf       per-product settings — mounted into that product's container
  bin/                 this CLI, and its siblings
  <product>/           generated artifacts, owned by the installer
    cli.toml           that product's host-side tool config — yours, host-only, never mounted
  .state/              lock + ledger, owned by the installer — not an editing surface
  transcripts/ logs/   product data
```

Nothing is scattered across your home directory: every file you are expected to read or edit is here.

### The two config files are text, and never executed

Both `.conf` files are `KEY=value` text, parsed by a strict **non-executing** reader that allowlists
keys and validates values by type — a line like `KEY=$(...)` is refused, not run. That reader is
built and tested today.

The **split** between the two files is the design (not all of it shipped behaviour yet):
`mythical.conf` is host-only and never mounted into any container; `<product>.conf` is the only file
a product can see or write; and the code that launches a container builds its arguments without
reading any value out of it. That is enforced at the one launch path the verbs walk — the mount,
publish, and secret-injection rules live at the single place a container is created, so no caller can
express an unsafe launch. The format itself is specified in
[`CONFIG-FORMAT.md`](CONFIG-FORMAT.md).

### The host-tool slot

`<product>/cli.toml` is the one leaf inside an installer-managed product directory that the installer
does **not** own. It is where a product's *host-side* tool — a CLI that runs beside this one rather
than inside the product's container — keeps its own configuration, including host-only credentials.
It is yours: mode 0600, owned by you, never mounted into any container by name (which is why such a
credential does not belong in `<product>.conf`, which *is* mounted read-write). Three product names
are excluded — `bin`, `logs`, `transcripts` — because those directories already mean something else
here. `mythical-ctl` never creates, modifies, removes, or parses `cli.toml`; the one thing that reads
its bytes is `backup`, which copies the whole directory — so treat a backup as secret material.
Full detail, including the limit on the never-mounted guarantee, is in
[`CONFIG-FORMAT.md`](CONFIG-FORMAT.md).

## The authenticated-document layer

Beyond the two config files, the lifecycle commands call on a more privileged authenticated-document
layer: a family index, a family policy index, and each product's manifest, chained back to a single
authenticated root, plus a small bounded reader for a product's own version out of its `/detect`
response. That contract — the grammar, the trust model, and exactly which keys a manifest may and may
not declare — is published in [`DOCUMENT-FORMAT.md`](DOCUMENT-FORMAT.md) for product authors and index
publishers who need it without reading this repository's source.

## Your data is never collateral

The installer creates what is missing and reads what already exists; it will not overwrite a
configuration file you have edited, and it will not delete transcripts, logs, or any directory you
bound. Today this is enforced where there is code to enforce it: `mi_zone` classifies every path into
an ownership class, the layout helper creates missing directories and touches nothing else, and the
config layer is additive by construction — it appends an absent key, refuses to change one already
set to something else, and leaves every other byte, comment, and blank line exactly as found. Do not
read it as a blanket guarantee over your data yet — nothing here touches a transcript or a log at all.

Product state — and each product's own secrets store — lives in named container volumes, and the
containers, images, and shared network live in your container runtime. None of that is in
`~/.mythical/`. So:

- **Copying `~/.mythical/` is not a backup.** The data and runtime secrets are not in it. A complete
  backup has to include the named volumes — that is what `mythical-ctl backup` is for (and `restore`
  puts them back).
  - **It covers exactly what this tool installed.** Backup walks the installer state ledger and
    captures the volumes recorded there — a volume enters coverage only by having been created through
    this tool's install path. A product that installed itself by its own installer holds volumes this
    ledger has never heard of, and they are **silently absent** from the backup. Use that product's
    own backup verb for its data.
- **`uninstall --purge` destroys named volumes, and asks first.** A plain `uninstall` keeps every
  volume and says so per volume; `--purge` removes them. Both the product- and family-scoped forms
  list what they are about to remove — each volume by name, with its role and whether its contents can
  be rebuilt — then require an explicit confirmation. A bare newline, EOF, or closed stdin all refuse,
  so a purge cannot be carried by an empty pipe. The listing comes before anything is removed.
  - **A volume whose data class is unknown is treated as unrecoverable.** A role is declared
    unregenerable in the family policy index (`<product>.precious_role`); a product's own manifest
    cannot make that claim about itself. Where no declaration exists, `status` and `--purge` report the
    volume as unregenerable rather than safe to delete.
- **`status` reports volumes, not just containers** — presence, role, data class, and whether this
  installation created them. Deliberately not size: the host cannot read a named volume's contents and
  the runtime reports no size, so any number would be invented — and `status` starts nothing.
- **Deleting `~/.mythical/` is not an uninstall.** The containers keep running.

## What is verified, and what is not

The bootstrap installs each product image **pinned by content digest** (`@sha256:…`), which the
container runtime checks on pull: if the bytes are not the bytes that were pinned, the pull fails and
the installer stops rather than install unverified bytes. A product with no published digest yet is
reported as not launched and is not installed. The bootstrap script *itself* is authenticated by TLS
to a known origin, not by a separate signature — a deliberate, stated limit of this model.

## Why this is not a one-liner

`curl … | bash` cannot reject a redirect. Without `-L`, curl does not *follow* a redirect — but it
does not fail on one either: `-f` acts on 4xx and 5xx, so a `3xx` response is transferred like any
other and **its body goes straight into your shell**. Anyone who controls a redirect controls that
body. `--max-redirs 0` bounds following, not status handling.

Downloading first makes the status checkable before anything executes. It is one extra line, and it
is the difference between "we verify everything" and "we verify everything after the first thing
already ran". `wget` is not supported either: no flag constrains every hop of a redirect chain, so an
`https → http → https` chain is undetectable.

(Bash specifically, not POSIX `sh`: the CLI uses `set -o pipefail` and other bash features. Bash is
present by default on macOS and every mainstream Linux distribution; where it is not — Alpine, some
minimal images — it is a one-package install.)

## Development

`lib/` holds the shipped shell libraries; `tests/harness/` holds test-only helpers (a fake container
runtime and filesystem-snapshot assertions) that shipped code never sources. Tests are hermetic, so a
green suite proves logic, not Docker behaviour.

A release does **not** publish `bin/mythical-ctl` as it sits in the tree. `tools/bundle.sh` inlines
`lib/*.sh` into the entrypoint's `mctl:modules` region and publishes a single self-contained file,
because the installed layout is exactly one file — one artifact, one digest, one attestation. The
bundle is byte-reproducible from a given tree, so a published checksum is one anyone can re-derive:

```sh
tools/bundle.sh dist/mythical-ctl
shellcheck dist/mythical-ctl
MCTL_BIN="$PWD/dist/mythical-ctl" ./tests/smoke.sh
```

## Siblings

The `mythical-` prefix is a namespace, not just a name. `bin/` is structured so that focused companion
binaries can live alongside this one rather than accreting into it — the CLI should stay small enough
to read.
