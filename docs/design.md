# mythical-ctl — design and behaviour

The reference detail behind the [README](../README.md): the layout and its ownership rules, the
config-file model, the authenticated-document trust chain, exactly what backup/uninstall/status do,
and what a published release is held to.

`mythical-ctl` is **product-agnostic** by design: everything specific to a product — image reference,
ports, volumes, environment — arrives from a manifest that product ships, never from logic baked in
here. Products contribute a manifest describing themselves, and nothing more.

## One place for everything you edit

The layout is implemented in the `layout` package; the CLI mounts each product's configuration and
volumes into its container per that product's manifest.

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

**The product images** are **pinned by content digest** (`@sha256:…`), which the container runtime
checks on pull: if the bytes are not the bytes that were pinned, the pull fails and the installer
stops rather than install unverified bytes. A product with no published digest yet is reported as
not launched and is not installed.

**The CLI itself** is verified by you, once, before you first run it — see the section below. That
is the honest boundary of this model: nothing inside a downloaded binary can establish that the
binary is the right one, so the check has to happen outside it, against a digest published beside
it and a provenance attestation signed by the workflow that built it.

## What you download, and how you check it

A release publishes four static binaries — `mythical-ctl_{darwin,linux}_{amd64,arm64}` — and a
`SHA256SUMS` file naming each one's digest. **Verify the digest before the first execution.** The
version string is not the integrity guarantee: anyone can print a version. The digest is
content-addressed, and every binary additionally carries a signed build-provenance attestation
tying those exact bytes to the workflow run and commit that produced them.

That is also why the artifacts are built reproducibly (below): a published checksum is only worth
something if a stranger can re-derive it from the source rather than take it on trust.

## Development

The CLI is one Go module. `internal/` holds a package per module — layout, conf, trust, engine,
runtime, verbs and the rest — with tests beside the code they test. The engine tests run against a
hermetic fake rather than a daemon, so a green suite proves logic, not Docker behaviour;
`bash check.sh acceptance` re-measures those behaviours against a real daemon and is opt-in.

Every check the Go tree gets lives in `check.sh`, which CI and a person run identically — spelling
the commands out in a workflow as well guarantees the two drift, and the direction is always the
same: the release lane ends up laxer than the pull-request lane. CI adds the checks that are not
Go: shellcheck over the four remaining scripts, an executable-bit check on the same four, a gate on
what may appear in a public tree, and the smoke script twice.

```sh
bash check.sh go        # gofmt, build, vet, the reference-boundary gate, the whole test suite
bash check.sh parity    # every test of the retired bash suite is still accounted for
bash check.sh release   # build the published matrix twice, require identical bytes
./tests/smoke.sh        # the CLI contract, against a binary it builds (or MCTL_BIN=<path>)
```

`check.sh release` is the reproducibility claim being exercised rather than asserted: it builds
all four artifacts, then builds them again from a copy of the source at a different absolute path
with a cold build cache, and requires every byte to match. `tools/release-verify` grades the
result from the FILES rather than from the commands that made them.

`check.sh parity` is the evidence that retiring the previous shell implementation lost nothing:
`tests/parity-manifest.tsv` records all 1,178 tests of the suite that specified it, and the audit
requires each one to be claimed exactly once by a `PORTED:` or argued `N/A:` inventory line in the
Go tree, with every `PORTED` target resolving to a test that really runs.

## Siblings

The `mythical-` prefix is a namespace, not just a name. `bin/` is structured so that focused companion
binaries can live alongside this one rather than accreting into it — the CLI should stay small enough
to read.
