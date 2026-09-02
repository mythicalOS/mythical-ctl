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

It runs in a subshell, so a failed check stops it and stops it there — nothing below a failure
runs, and `set -e` cannot take your own shell with it. It also does its work in a private
directory of its own, for the reason spelled out inside:

```sh
(
  set -e
  ver=v0.0.0            # the release you want

  # The platform is DERIVED, not chosen. All four artifacts have valid published
  # digests, so a leftover choice from a copy-paste verifies perfectly and then
  # installs a binary that cannot run on this machine — over a working one.
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64)              plat=darwin_arm64 ;;
    Darwin/x86_64)             plat=darwin_amd64 ;;
    Linux/x86_64)              plat=linux_amd64  ;;
    Linux/aarch64|Linux/arm64) plat=linux_arm64  ;;
    *) echo "no published binary for $(uname -s)/$(uname -m)"; exit 1 ;;
  esac

  # A PRIVATE DIRECTORY, not the one you happen to be standing in. Everything below
  # refers to files by NAME, and between verifying a name and installing what it
  # points at, anyone who can write that directory can swap it — a window `sudo`
  # widens while it prompts you for a password. mktemp -d is mode 0700 and yours, so
  # there is nobody left to swap anything. It also stops `curl -O` from silently
  # overwriting files you already had.
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cd "$tmp"

  base="https://github.com/mythicalOS/mythical-ctl/releases/download/$ver"

  curl -fsSL --proto '=https' -O "$base/mythical-ctl_$plat"
  curl -fsSL --proto '=https' -O "$base/SHA256SUMS"

  # VERIFY BEFORE THE FIRST EXECUTION, and let the tool do the comparing — printing
  # two digests side by side and leaving you to eyeball them is not verification.
  # Pulling the one line out first is deliberate: `-c` over the whole file would try
  # to check three artifacts you did not download and fail for the wrong reason.
  grep " mythical-ctl_$plat\$" SHA256SUMS > expected.sha256
  [ -s expected.sha256 ] || { echo "no digest published for mythical-ctl_$plat"; exit 1; }
  shasum -a 256 -c expected.sha256      # sha256sum -c expected.sha256 on Linux

  # install(1), not `mv`: within one filesystem `mv` is a RENAME, so even under
  # sudo the installed file keeps the downloading user's ownership and mode —
  # leaving a root-PATH executable that one unprivileged account can rewrite
  # afterwards, which is exactly the guarantee the digest above was for.
  # install COPIES, so the new file is root's, at the mode named here.
  sudo install -m 0755 "mythical-ctl_$plat" /usr/local/bin/mythical-ctl
)
```

If you have the GitHub CLI, one more check goes further than the digest — it says which workflow
run, from which commit, produced exactly those bytes:

```sh
gh attestation verify /usr/local/bin/mythical-ctl --repo mythicalOS/mythical-ctl
```

It takes a **file path**, not a command name, so that line checks the file that is already
installed — run it *after* the block.

To check *before* installing instead, edit the block above rather than running anything separately:
add `gh attestation verify "mythical-ctl_$plat" --repo mythicalOS/mythical-ctl` as the line
immediately above `sudo install`. It has to go **inside**, because `$plat` and the downloaded file
exist only there — the subshell's trap deletes the temporary directory as it exits, so the same
command run afterwards would resolve `$plat` to nothing and check a file that is not there.

The two forms are not interchangeable. Run the `/usr/local/bin/...` one *before* installing and it
attests **whatever was already there**: a green result about bytes you are not about to run, which
is the one direction a verification step must never fail in.

The version string is not the integrity guarantee — the digest is; anyone can print a version.
[get.mythicalos.ai](https://get.mythicalos.ai) serves a pinned release artifact from here, so a
product's own getting-started page can hand you the same bytes.

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

Every check the Go tree gets lives in one script, run identically by CI and by a person:

```sh
bash check.sh go         # gofmt, build, vet, the reference-boundary gate, the whole test suite
bash check.sh boundary   # the reference-boundary gate on its own
bash check.sh parity     # every test of the retired suite is still accounted for
bash check.sh release    # build the published matrix twice, require identical bytes
bash check.sh selfcheck  # prove the graders above cannot be neutered by the environment
bash check.sh            # all of them
./tests/smoke.sh        # CLI contract, against a binary it builds (or MCTL_BIN=<path>)
```

`selfcheck` deserves a word, because it is unusual. A grader is run by `go run`, and `go run`
honours the environment it inherits — so an inherited `GOFLAGS`, `go env` file or workspace could
make a stage build its grader, run something else instead, and print OK having checked nothing.
Each script now fixes its own Go environment, and `selfcheck` proves it: it re-runs the stages under
each hostile channel and requires both a zero exit **and** the grader's own verdict line, because
"did not report success" is equally satisfied by a guard that breaks everything.

CI runs those, and a few things that are not Go: `shellcheck -x check.sh tests/*.sh tools/*.sh`,
an executable-bit check on the same four scripts, the smoke script twice (once on its own default
path, once against a stamped release artifact), and a gate on what may appear in a public tree.

Tests are hermetic (a fake container engine) — a green suite proves logic, not Docker behaviour;
`bash check.sh acceptance` re-measures the daemon behaviours against a real one, and is opt-in.
`parity` is the load-bearing one: the suite that specified the retired implementation is gone, so
its 1,201 tests survive as a digest-pinned manifest, and each must be claimed exactly once by a
`PORTED:` or argued `N/A:` line — with every `PORTED` target declared, listed, **and observed to
run**, not merely named.
A release publishes four static binaries plus `SHA256SUMS`, byte-reproducible from the tree. See
[`docs/design.md`](docs/design.md#development) for what the release lane checks.

## License

**Apache-2.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE); the licence covers the code, not the
mythicalOS name and marks ([TRADEMARK.md](TRADEMARK.md)). The installer and the products it installs
are open and stay open — there is no reduced community edition. The commercial side of mythicalOS is
a separate, private, hosted service; nothing here calls into it, and running the open-source products
(including for others, as a paid offering of your own) is permitted by Apache-2.0. Contributions
welcome under a DCO sign-off, no CLA — see [CONTRIBUTING.md](CONTRIBUTING.md).
