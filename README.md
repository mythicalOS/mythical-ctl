<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.svg">
    <img src=".github/assets/logo-light.svg" alt="mythicalOS" width="84" height="84">
  </picture>
</p>

<h1 align="center">mythical-ctl</h1>

<p align="center">
  <strong>One installer and lifecycle CLI for the mythicalOS family of local-first containers — a single static binary, no runtime required.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache_2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/built_with-Go-00ADD8.svg?logo=go&logoColor=white" alt="Go">
  <a href="https://mythicalos.ai"><img src="https://img.shields.io/badge/part_of-mythicalOS-0F6B66.svg" alt="Part of mythicalOS"></a>
</p>

---

Installing several products shouldn't mean learning several installers. `mythical-ctl` is the common
half, written once: container preflight, a predictable `~/.mythical/` layout, config, volume/bind
lifecycle, and the lifecycle verbs. Everything product-specific — image, ports, volumes, environment —
arrives from a **manifest the product ships**, never from logic baked in here.

One command installs a product and manages it afterwards:

```
install · start · stop · restart · recreate · status · uninstall · state repair
migrate-storage · backup · restore
```

> **Status:** the lifecycle verbs and data movement are implemented, on top of the `~/.mythical/`
> layout, a non-executing config parser, an authenticated-document trust chain, and a hermetic test
> harness. The products themselves aren't published yet — so installing one whose image hasn't
> shipped reports that it hasn't launched and creates nothing (a recognised state, not a failure).

## Install

`mythical-ctl` is a single static binary. Download the one for your platform from the
[releases](https://github.com/mythicalOS/mythical-ctl/releases), **check its digest against the
published `SHA256SUMS` before you run it**, then put it on your `PATH`:

```sh
ver=v0.0.0            # the release you want
plat=darwin_arm64     # darwin_amd64 · darwin_arm64 · linux_amd64 · linux_arm64
base="https://github.com/mythicalOS/mythical-ctl/releases/download/$ver"

curl -fsSL --proto '=https' -o mythical-ctl  "$base/mythical-ctl_$plat"
curl -fsSL --proto '=https' -o SHA256SUMS    "$base/SHA256SUMS"

# Verify BEFORE the first execution. Compare the digest of what you downloaded
# against the line for that artifact; anything but a match, stop.
shasum -a 256 mythical-ctl | awk '{print $1}'      # sha256sum on Linux
grep "mythical-ctl_$plat\$" SHA256SUMS

chmod +x mythical-ctl && mv mythical-ctl /usr/local/bin/
```

The version string is not the integrity guarantee — the digest is. Every published binary also
carries a signed GitHub build-provenance attestation, so `gh attestation verify mythical-ctl
--repo mythicalOS/mythical-ctl` will tell you which workflow run, from which commit, produced
exactly those bytes. [get.mythicalos.ai](https://get.mythicalos.ai) serves a pinned release
artifact from here, so a product's own getting-started page can hand you the same bytes.

Product images are pinned by content digest (`@sha256:…`) and verified by the container runtime on
pull; if the bytes don't match, the install stops rather than run unverified bytes.

**Requirements:** a container runtime (rootful Docker Engine 28+ or Docker Desktop); nothing
else — the CLI is a static binary with no language runtime and no shared-library dependency.

## Your data is never collateral

The installer creates what's missing and reads what's there — it won't overwrite a config you edited
or delete a transcript, log, or bound directory. Config writes are additive by construction. Note
that **copying `~/.mythical/` is not a backup** — product data and runtime secrets live in named
volumes; use `mythical-ctl backup` (and `restore`) for those.

The layout, ownership zones, config-file model, the authenticated-document trust chain, and the exact
backup/uninstall/status semantics are documented in **[`docs/design.md`](docs/design.md)**; the config
and trust-chain contracts are in [`docs/CONFIG-FORMAT.md`](docs/CONFIG-FORMAT.md) and
[`docs/DOCUMENT-FORMAT.md`](docs/DOCUMENT-FORMAT.md).

## Develop

Every check this tree gets lives in one script, run identically by CI and by a person:

```sh
bash check.sh go        # gofmt, build, vet, the reference-boundary gate, the whole test suite
bash check.sh parity    # every test of the retired bash suite is still accounted for
bash check.sh release   # build the published matrix twice, require identical bytes
bash check.sh           # all three
./tests/smoke.sh        # CLI contract, against a binary it builds (or MCTL_BIN=<path>)
```

Tests are hermetic (a fake container engine) — a green suite proves logic, not Docker behaviour;
`bash check.sh acceptance` re-measures the daemon behaviours against a real one, and is opt-in.
A release publishes four static binaries plus `SHA256SUMS`, byte-reproducible from the tree. See
[`docs/design.md`](docs/design.md#development) for what the release lane checks.

## License

**Apache-2.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE); the licence covers the code, not the
mythicalOS name and marks ([TRADEMARK.md](TRADEMARK.md)). The installer and the products it installs
are open and stay open — there is no reduced community edition. The commercial side of mythicalOS is
a separate, private, hosted service; nothing here calls into it, and running the open-source products
(including for others, as a paid offering of your own) is permitted by Apache-2.0. Contributions
welcome under a DCO sign-off, no CLA — see [CONTRIBUTING.md](CONTRIBUTING.md).
