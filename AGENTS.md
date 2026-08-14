# AGENTS.md — mythical-ctl

The product-agnostic **installer and lifecycle CLI** for the mythicalOS family — pure bash (no
language runtime required to install a product). Product specifics arrive from authenticated
manifests, never from logic baked in here. `README.md` carries the model: the `~/.mythical/`
layout and ownership zones, the non-executing config parser, the authenticated-document trust
chain, and why the install sequence is deliberately not a one-liner.

## Authority & precedence

Repository orientation, not a role contract. If a role, playbook, or system prompt governs your
session, that contract is authoritative and supersedes anything here — including the commands.
This file grants no edit, run, commit, push, or release permission.

## Layout

| Path | What it is |
|------|-----------|
| `bin/mythical-ctl` | The entrypoint. **Not the shipped artifact** — releases bundle it (below). |
| `lib/*.sh` | The shipped shell libraries, sourced by the entrypoint in dev layout. |
| `tests/unit/` + `tests/harness/` | bats unit tests + test-only helpers (fake container runtime, filesystem-snapshot assertions). **Shipped code never sources anything under `tests/`.** |
| `tests/smoke.sh` | Entrypoint smoke — also run against the bundled artifact. |
| `tools/bundle.sh` | Builds the release artifact: inlines `lib/*.sh` into the entrypoint's `mctl:modules` region → one self-contained, byte-reproducible file. |
| `vendor/bats-core/` | The test runner, vendored as a **git submodule** — clone with `--recurse-submodules` or `git submodule update --init`, or unit tests cannot run. |
| `docs/` | `CONFIG-FORMAT.md`, `DOCUMENT-FORMAT.md` — the published config and trust-chain contracts. |

## Commands

Run only if your active role permits command execution.

- Lint (zero findings expected): `shellcheck -x bin/* lib/*.sh tests/*.sh tests/harness/* tools/*.sh`
- Smoke: `./tests/smoke.sh`
- Unit tests: `vendor/bats-core/bin/bats tests/unit`
- Release-artifact check: `tools/bundle.sh dist/mythical-ctl && shellcheck dist/mythical-ctl &&
  MCTL_BIN="$PWD/dist/mythical-ctl" ./tests/smoke.sh`

Tests are hermetic (fake container runtime) — none of them touch a real Docker daemon. Report
skipped or failing checks exactly.

## Boundaries & gotchas

- **The config reader never executes config.** `KEY=value` files are parsed by a strict
  non-executing reader with key allowlists and typed validation — never "simplify" a code path
  to `source` a config file, and never widen what a mounted `<product>.conf` may contain
  (`mythical.conf` stays host-only and unmounted).
- **Data is never collateral.** `mi_zone` classifies every path into an ownership class; config
  writes are additive by construction (append absent keys, refuse to change set ones, preserve
  every other byte). Any new write path must fit those zones.
- **The host-tool slot is user-owned.** `~/.mythical/<product>/cli.toml` is carved out of the
  installer-managed product directory for a product's *host-side* tool, and it holds host-only
  credentials. Never create, read, write, chmod or delete it — and never remove a product directory
  wholesale: a reaper deletes the artifacts it created by name, or skips every `user-owned` entry.
  `docs/CONFIG-FORMAT.md` is the contract.
- **Container launches go through the one launch path** — mount, publish, and secret-injection
  rules live at the single place a container is created, so no caller can express an unsafe
  launch. Do not add a second `docker run` site.
- **Bash, not POSIX sh** (`set -o pipefail` and other bashisms are relied on); the library layer
  needs only bash builtins + POSIX text tools + `sha256sum`/`shasum -a 256`.
- The bundle is byte-reproducible from a given tree — keep it that way (no timestamps,
  environment leakage, or nondeterminism in `tools/bundle.sh` output).
- This repo is consumed as a pinned submodule by a private downstream workspace: land and push
  on `main` here first, then the consumer bumps its pin.
