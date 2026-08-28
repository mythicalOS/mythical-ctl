# AGENTS.md — mythical-ctl

The product-agnostic **installer and lifecycle CLI** for the mythicalOS family — a single
static binary (no language runtime required to install a product). Product specifics arrive
from authenticated manifests, never from logic baked in here. `README.md` carries the model: the
`~/.mythical/` layout and ownership zones, the non-executing config parser, the
authenticated-document trust chain, and how a downloaded release is verified before it is run.

## Authority & precedence

Repository orientation, not a role contract. If a role, playbook, or system prompt governs your
session, that contract is authoritative and supersedes anything here — including the commands.
This file grants no edit, run, commit, push, or release permission.

## Layout

| Path | What it is |
|------|-----------|
| `cmd/mythical-ctl/` | The entrypoint: argument parsing, verb dispatch, exit codes. |
| `internal/*` | One package per module — layout, conf, trust, engine, runtime, verbs, and the rest. Tests live beside the code they test, hermetically (a fake container engine, no daemon). |
| `check.sh` | **Every check the GO TREE gets, in one place** — the `go`, `parity` and `release` lanes. CI and a person run the same script; see its header for why the release lane is a stage in it rather than a second list of commands. CI adds what is not Go: shellcheck, the executable-bit check, the public-safety gate, and two smoke runs. |
| `tests/smoke.sh` | Transport-level CLI smoke — exit codes, the `--version` line, `-v` as its twin, usage errors staying off stdout. Run against a built binary (`MCTL_BIN`), or with nothing set, in which case it builds one. |
| `tests/parity-manifest.tsv` | The retired bash suite's 1,178 test names, in committed form. `check.sh parity` proves every one of them is still accounted for by a `PORTED:`/`N/A:` inventory line in the Go tree. **Do not hand-edit it** — it is pinned by content digest in `tools/parity-audit`. |
| `tools/` | `build-release.sh` + `release-verify` (the published artifacts and their grading), `parity-audit`, `boundary-gate`. |
| `docs/` | `CONFIG-FORMAT.md`, `DOCUMENT-FORMAT.md` — the published config and trust-chain contracts. `RECOVERY.md`, `design.md`. |

## Commands

Run only if your active role permits command execution.

- The three lanes CI's `go` job runs: `bash check.sh` (individually: `go`, `parity`, `release`).
  It is not quite everything CI runs — the shellcheck lint, the executable-bit check, the
  public-safety hygiene gate and the two smoke runs are separate workflow steps, below.
- Just the Go lane: `bash check.sh go` — package-count floors, gofmt, build, vet, the
  reference-boundary gate, and the full test suite
- Smoke: `./tests/smoke.sh` (builds what it tests), or `MCTL_BIN=<binary> ./tests/smoke.sh`
- Lint the four remaining scripts: `shellcheck -x check.sh tests/*.sh tools/*.sh`
- Real daemon (opt-in, NOT in CI, needs Docker running): `bash check.sh acceptance`

`check.sh go`'s tests are hermetic (a fake container engine) — none of them touch a real
Docker daemon, so a green suite proves logic, not daemon behaviour. Report skipped or failing
checks exactly.

## Boundaries & gotchas

- **The config reader never executes config.** `KEY=value` files are parsed by a strict
  non-executing reader with key allowlists and typed validation — never "simplify" a code path
  to `source` a config file, and never widen what a mounted `<product>.conf` may contain
  (`mythical.conf` stays host-only and unmounted).
- **Data is never collateral.** `layout.ZoneOf` classifies every path into an ownership class (the
  published contract in `docs/CONFIG-FORMAT.md` still calls it by its original name); config
  writes are additive by construction (append absent keys, refuse to change set ones, preserve
  every other byte). Any new write path must fit those zones.
- **The host-tool slot is user-owned.** `~/.mythical/<product>/cli.toml` is carved out of the
  installer-managed product directory for a product's *host-side* tool, and it holds host-only
  credentials. Never create, modify, chmod, delete or parse it — and never remove a product
  directory wholesale: a reaper deletes the artifacts it created by name, or skips every
  `user-owned` entry. `backup` is the one path that reads its bytes (it copies the whole tree), so a
  backup is secret material. `docs/CONFIG-FORMAT.md` is the contract.
- **Container launches go through the one launch path** — mount, publish, and secret-injection
  rules live at the single place a container is created, so no caller can express an unsafe
  launch. Do not add a second `docker run` site.
- **The published artifacts are byte-reproducible from a given tree** — keep it that way. No
  timestamps, no build-environment leakage, no VCS stamp: `tools/build-release.sh` carries the
  flags and the reason for each, and `check.sh release` builds the whole matrix twice (the
  second time from a different absolute path with a cold cache) and requires identical bytes.
- **The parity evidence is not ordinary text.** `tests/parity-manifest.tsv`, the `PORTED:` /
  `N/A:` inventory comments, and `tools/parity-audit` are the record that retiring the bash
  implementation lost nothing. They are the one place bats paths legitimately still appear.
- This repo is consumed as a pinned submodule by a private downstream workspace: land and push
  on `main` here first, then the consumer bumps its pin.
