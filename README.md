<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.svg">
    <img src=".github/assets/logo-light.svg" alt="mythicalOS" width="84" height="84">
  </picture>
</p>

<h1 align="center">mythical-ctl</h1>

<p align="center">
  <strong>One installer and lifecycle CLI for the mythicalOS family of local-first containers — pure bash, no runtime required.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache_2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/shell-bash-4EAA25.svg?logo=gnubash&logoColor=white" alt="bash">
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

The bootstrap below is served by [get.mythicalos.ai](https://get.mythicalos.ai). It downloads to a
temp file and **checks the HTTP status before executing anything** — deliberately not a
`curl … | bash` one-liner, because that form can't reject a redirect into your shell. The full
reasoning is in [`docs/design.md`](docs/design.md#why-this-is-not-a-one-liner).

```sh
(
  tmp=$(mktemp) || exit 1
  trap 'rm -f "$tmp"' EXIT
  code=$(curl -fsS --proto '=https' --max-redirs 0 -o "$tmp" -w '%{http_code}' \
              https://get.mythicalos.ai/brokkr) \
    || { echo "download failed — refusing to run it"; exit 1; }
  [ "$code" = 200 ] || { echo "unexpected HTTP $code — refusing to run it"; exit 1; }
  bash "$tmp"
)
```

Product images are pinned by content digest (`@sha256:…`) and verified by the container runtime on
pull; if the bytes don't match, the install stops rather than run unverified bytes.

**Requirements:** bash. The lifecycle verbs additionally need a container runtime (rootful Docker
Engine 28+ or Docker Desktop); installing needs `curl` and `mktemp`.

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

The test runner is a git submodule — **clone with submodules**, or the unit tests can't run:

```sh
git clone --recurse-submodules https://github.com/mythicalOS/mythical-ctl.git
# already cloned: git submodule update --init
```

```sh
shellcheck -x bin/* lib/*.sh tests/*.sh tests/harness/* tools/*.sh   # lint
./tests/smoke.sh                                                     # entrypoint smoke
vendor/bats-core/bin/bats tests/unit                                 # unit tests
```

Tests are hermetic (a fake container runtime) — a green suite proves logic, not Docker behaviour. A
release publishes a single bundled file (`tools/bundle.sh`), byte-reproducible from the tree. See
[`docs/design.md`](docs/design.md#development) for the release-artifact check.

## License

**Apache-2.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE); the licence covers the code, not the
mythicalOS name and marks ([TRADEMARK.md](TRADEMARK.md)). The installer and the products it installs
are open and stay open — there is no reduced community edition. The commercial side of mythicalOS is
a separate, private, hosted service; nothing here calls into it, and running the open-source products
(including for others, as a paid offering of your own) is permitted by Apache-2.0. Contributions
welcome under a DCO sign-off, no CLA — see [CONTRIBUTING.md](CONTRIBUTING.md).
